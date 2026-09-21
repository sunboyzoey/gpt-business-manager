"""One refresh-grant attempt for the exact sold member; never log provider data.

The account operation lease serializes cooperating writers. SQL predicates also
fence credential, membership and workspace changes. A durable, credential-free
attempt journal prevents replaying a refresh token after an uncertain response.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any
import uuid

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from core.db import (
    GptBusinessAccountModel as Source,
    GptBusinessChildMembershipModel as Membership,
    GptPlanAccountModel as Account,
    GptPlanAccountOperationLeaseModel as Lease,
)


_JOURNAL = "nv_sold_quota_refresh"
_OPERATION = "nv_sold_quota_refresh"
_CHILD_FIELDS = ("email", "business_parent_id", "codex_access_token", "codex_refresh_token",
                 "codex_id_token", "codex_session_token", "codex_rt_acquired_at", "extra_json")
_PARENT_FIELDS = ("email", "business_parent_id", "source_pool", "source_account_id", "chatgpt_account_id")
_SOURCE_FIELDS = ("email", "cookie_blob")
_MEMBER_FIELDS = ("business_account_id", "pro_account_id", "email", "source", "seat_type",
                  "remote_user_id", "remote_invite_id", "invited_at", "created_at", "ended_at",
                  "sale_status", "sold_at", "nv_remote_card_id", "nv_remote_order_id",
                  "nv_listed_at", "nv_listing_confirmed_at", "operation_id")
_REJECTED = frozenset({"invalid_grant", "refresh_token_reused", "refresh_token_invalidated",
                       "invalid_refresh_token", "token_revoked", "access_denied"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _result(code: str = "", status: int | None = None, *, refreshed: bool = False) -> dict:
    return {"ok": not code, "refreshed": refreshed, "error_code": code, "http_status": status}


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


class _Changed(Exception):
    pass


def _token(value: Any) -> str:
    # OAuth bearer values must be nonempty strings with no header/control chars.
    return value if (isinstance(value, str) and 0 < len(value) <= 32768
                     and all(33 <= ord(character) <= 126 for character in value)) else ""


def _identity(token: str) -> tuple[str, str, str]:
    from platforms.chatgpt.status_probe import _decode_jwt_payload
    from services.nv_sold_quota import _email, _identifier

    payload = _decode_jwt_payload(token)
    auth, profile = payload.get("https://api.openai.com/auth"), payload.get("https://api.openai.com/profile")
    auth = auth if isinstance(auth, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    return (_email(profile.get("email") or payload.get("email")),
            _identifier(auth.get("chatgpt_user_id") or auth.get("user_id")),
            _identifier(auth.get("chatgpt_account_id")))


def _begin(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _state(session: Session, cap: Any, job: dict, evidence: dict) -> dict:
    from services.nv_sold_quota import _date, _email, _identifier

    child, parent, source, member = (
        session.get(Account, job["child_id"]), session.get(Account, job["parent_account_id"]),
        session.get(Source, job["source_account_id"]), session.get(Membership, job["membership_id"]),
    )
    if any(row is None for row in (child, parent, source, member)):
        raise _Changed()
    identity = _identity(str(child.codex_access_token or "").strip())
    _, source_workspace, _ = cap._business()._business_cookie_at_team(source.cookie_blob)
    known_workspaces = {_identifier(value) for value in (source_workspace, parent.chatgpt_account_id)
                        if _identifier(value)}
    if (not all(identity) or identity[:2] != (_email(job["email"]), _identifier(job["remote_user_id"]))
            or known_workspaces != {identity[2]} or child.business_parent_id != source.id
            or _email(child.email) != identity[0] or member.ended_at is not None
            or member.business_account_id != source.id or member.pro_account_id != child.id
            or _email(member.email) != identity[0] or member.remote_user_id != identity[1]
            or member.source != "pool" or parent.source_pool != "gpt_business"
            or parent.source_account_id != source.id or parent.business_parent_id is not None
            or _email(parent.email) != _email(job.get("parent_email"))
            or _email(source.email) != _email(job.get("parent_email"))
            or (member.nv_remote_card_id and member.nv_remote_card_id != evidence["nv_remote_card_id"])
            or (member.sold_at is not None and _aware(member.sold_at) != _date(evidence["sold_at"]))):
        raise _Changed()
    context = job.get("context") if isinstance(job.get("context"), dict) else {}
    invited = context.get("membership_invited_at")
    if invited and _date(invited) != _aware(member.invited_at):
        raise _Changed()
    try:
        extra = json.loads(child.extra_json or "{}")
    except Exception:
        raise _Changed() from None
    if not isinstance(extra, dict):
        raise _Changed()
    return {"child": {key: getattr(child, key) for key in _CHILD_FIELDS},
            "parent": {key: getattr(parent, key) for key in _PARENT_FIELDS},
            "source": {key: getattr(source, key) for key in _SOURCE_FIELDS},
            "member": {key: getattr(member, key) for key in _MEMBER_FIELDS},
            "identity": identity, "extra": extra}


def _predicates(model: Any, values: dict) -> list:
    return [getattr(model, key) == value for key, value in values.items()]


def _same_attempt(current: dict, observed: dict) -> bool:
    """Allow incidental metadata writes without discarding a rotated token.

    `_state` already verifies the source cookie resolves to the same workspace.
    The exact pending journal, including its unique attempt id, must survive.
    """
    if (current["identity"] != observed["identity"] or current["parent"] != observed["parent"]
            or current["member"] != observed["member"]
            or current["extra"].get(_JOURNAL) != observed["extra"].get(_JOURNAL)):
        return False
    return all(
        all(value == current[group].get(key) for key, value in observed[group].items() if key != ignored)
        for group, ignored in (("child", "extra_json"), ("source", "cookie_blob"))
    )


def _write(session: Session, job: dict, owner: str, observed: dict, values: dict) -> None:
    guards = [select(model.id).where(model.id == job[key], *_predicates(model, observed[name])).exists()
              for model, key, name in ((Membership, "membership_id", "member"),
                                       (Account, "parent_account_id", "parent"),
                                       (Source, "source_account_id", "source"))]
    guards.append(select(Lease.account_id).where(
        Lease.account_id == job["child_id"], Lease.token == owner,
        Lease.operation == _OPERATION, Lease.expires_at > _now(),
    ).exists())
    written = session.exec(update(Account).where(
        Account.id == job["child_id"], *_predicates(Account, observed["child"]), *guards,
    ).values(**values).execution_options(synchronize_session=False))
    if written.rowcount != 1:
        raise _Changed()
    session.commit()


def _journal_result(extra: dict, fingerprint: str) -> dict | None:
    from services.nv_sold_quota import _date

    journal = extra.get(_JOURNAL)
    if not isinstance(journal, dict) or journal.get("refresh_fingerprint") != fingerprint:
        return None
    state = journal.get("state")
    if state == "blocked":
        return _result("refresh_rejected")
    if state in {"pending", "unconfirmed"}:
        return _result("refresh_unconfirmed")
    if state == "cooldown":
        retry = _date(journal.get("next_retry"))
        if retry is None or retry > _now():
            rate = journal.get("error_code") == "refresh_rate_limited"
            return _result("refresh_rate_limited" if rate else "refresh_http_error", 429 if rate else None)
    elif state != "success":
        return _result("refresh_unconfirmed")
    return None


def _post(refresh_token: str, proxy: str) -> tuple[dict, dict, int]:
    """Exactly one refresh-grant POST; no login, fallback, retry or raw logging."""
    from curl_cffi import requests as cffi_requests
    from platforms.chatgpt.constants import OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI, OAUTH_TOKEN_URL

    response = None
    try:
        response = cffi_requests.post(
            OAUTH_TOKEN_URL, headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data={"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI,
                  "grant_type": "refresh_token", "refresh_token": refresh_token},
            proxies={"http": proxy, "https": proxy} if proxy else None,
            timeout=20, impersonate="chrome120", allow_redirects=False,
        )
        status = response.status_code
        if type(status) is not int or not 100 <= status <= 599:
            return _result("refresh_invalid_response"), {}, 0
        content = response.content
        data = {}
        if isinstance(content, bytes) and len(content) <= 512 * 1024:
            try:
                value = response.json()
                data = value if isinstance(value, dict) else {}
            except Exception:
                pass
        if status == 200:
            return _result(status=200), data, 0
        if status == 429:
            raw_retry = response.headers.get("Retry-After", "")
            retry = int(raw_retry) if isinstance(raw_retry, str) and re.fullmatch(r"[0-9]{1,6}", raw_retry) else 60
            return _result("refresh_rate_limited", 429), {}, max(60, min(retry, 3600))
        # An upstream may have rotated the RT before a gateway/server failed.
        # A 5xx response therefore cannot authorize replaying this token.
        if status >= 500:
            return _result("refresh_unconfirmed", status), {}, 0
        error = data.get("error")
        codes = [data.get("code"), error]
        if isinstance(error, dict):
            codes.extend((error.get("code"), error.get("type")))
        rejected = status in (400, 401, 403) and any(isinstance(code, str) and code in _REJECTED for code in codes)
        if rejected or status in (401, 403):
            return _result("refresh_rejected", status), {}, 0
        return _result("refresh_http_error", status), {}, 60
    except Exception as exc:
        timeout = isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower()
        return _result("refresh_timeout" if timeout else "refresh_connection_error"), {}, 0
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def refresh_sold_access_token(job: dict, evidence: dict, expected_fingerprint: str) -> dict:
    """Repair only the 401 token observed by the caller, returning no credentials."""
    from services import nv_automation_capabilities as cap
    from services import nv_sold_quota as quota

    if (quota.sold_quota_error(job, evidence) is None or not isinstance(expected_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) is None):
        return _result("identity_changed")
    plans, owner = cap._plans(), ""
    try:
        try:
            owner = plans._claim_plan_operation(job["child_id"], _OPERATION)
        except Exception as exc:
            return _result("refresh_busy" if getattr(exc, "status_code", None) == 409 else "refresh_persist_failed")
        try:
            member = cap._member(job, require_remote=True)
            access, _, live_fingerprint = quota._credentials(cap, job, member)
            with Session(plans.engine) as session:
                _begin(session)
                observed = _state(session, cap, job, evidence)
                if str(observed["child"]["codex_access_token"] or "").strip() != access:
                    raise _Changed()
                if live_fingerprint != expected_fingerprint:
                    return _result()
                refresh = _token(str(observed["child"]["codex_refresh_token"] or "").strip())
                if not refresh:
                    return _result("refresh_missing")
                fingerprint = _fingerprint(refresh)
                prior = _journal_result(observed["extra"], fingerprint)
                if prior is not None:
                    return prior
                extra = {**observed["extra"], _JOURNAL: {"state": "pending", "refresh_fingerprint": fingerprint,
                                                          "attempt_id": uuid.uuid4().hex,
                                                          "updated_at": _now().isoformat()}}
                serialized = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
                _write(session, job, owner, observed, {"extra_json": serialized})
                observed["extra"] = extra
                observed["child"]["extra_json"] = serialized
        except (_Changed, quota._IdentityError, HTTPException):
            return _result("identity_changed")
        except Exception:
            return _result("refresh_persist_failed")

        # Persisted pending is a fence even if resolution/transport crashes.
        try:
            outcome, data, cooldown = _post(refresh, plans._resolve_proxy(None))
        except Exception:
            outcome, data, cooldown = _result("refresh_unconfirmed"), {}, 0
        values: dict[str, Any] = {}
        if outcome["ok"]:
            access = _token(data.get("access_token"))
            rotated = _token(data.get("refresh_token")) if "refresh_token" in data else refresh
            identity_token = _token(data.get("id_token")) if "id_token" in data else ""
            if (data.get("error") is not None or not access or not rotated
                    or ("id_token" in data and not identity_token)):
                outcome = _result("refresh_invalid_response", 200)
            elif (_identity(access) != observed["identity"]
                  or (identity_token and _identity(identity_token) != observed["identity"])):
                outcome = _result("identity_changed", 200)
            else:
                values = {"codex_access_token": access, "codex_refresh_token": rotated, "updated_at": _now()}
                if identity_token:
                    values["codex_id_token"] = identity_token
        journal = None
        if not outcome["ok"]:
            state = "blocked" if outcome["error_code"] == "refresh_rejected" else "unconfirmed"
            journal = {"state": "cooldown" if cooldown else state, "refresh_fingerprint": fingerprint,
                       "attempt_id": observed["extra"][_JOURNAL]["attempt_id"],
                       "updated_at": _now().isoformat()}
            if cooldown:
                journal.update(error_code=outcome["error_code"], next_retry=(_now() + timedelta(seconds=cooldown)).isoformat())
        try:
            # Recheck the facade as well as SQL fences; no mother-health gate.
            cap._member(job, require_remote=True)
            with Session(plans.engine) as session:
                _begin(session)
                current = _state(session, cap, job, evidence)
                if not _same_attempt(current, observed):
                    raise _Changed()
                extra = dict(current["extra"])
                if journal is None:
                    extra.pop(_JOURNAL, None)
                else:
                    extra[_JOURNAL] = journal
                values["extra_json"] = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
                # Fence the current metadata/cookie snapshot in the write itself.
                _write(session, job, owner, current, values)
        except (_Changed, HTTPException):
            return _result("identity_changed")
        except Exception:
            return _result("refresh_persist_failed")
        return _result(status=200, refreshed=True) if outcome["ok"] else outcome
    except Exception:
        return _result("refresh_unconfirmed")
    finally:
        if owner:
            try:
                plans._release_plan_operation(job["child_id"], owner)
            except Exception:
                # Never expose SQL parameters; the durable lease can expire.
                pass
