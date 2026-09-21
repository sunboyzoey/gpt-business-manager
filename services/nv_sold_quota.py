"""Read-only usage observations for a confirmed NV or manual sale.

This display snapshot never changes membership, sale, pricing or release state.
Saved ATs are tried first. Only a 401 may refresh via RT once. If that RT is
rejected, the caller schedules the separately fenced OAuth recovery stage.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from typing import Any


_SCHEMA = "nv_sold_quota_v1"
_MAX_WINDOW_SECONDS = 366 * 86400
_IDENTITY_KEYS = ("child_id", "membership_id", "email", "remote_user_id")
_ERRORS = {
    "identity_mismatch": "账号或工作区身份未通过核对，未查询额度",
    "identity_changed": "查询期间账号身份或凭证已变化，请重新检查",
    "account_deactivated": "OpenAI 已明确停用该子号，等待核对并清理关联",
    "missing_credentials": "账号缺少已保存的访问凭证，无法查询额度",
    "credential_invalid": "账号访问凭证未通过验证（HTTP 401）",
    "credential_invalid_after_refresh": "AT 更新后额度接口仍返回 HTTP 401，已停止本轮刷新",
    "refresh_busy": "账号正在执行其他操作，待下次检查刷新 AT",
    "refresh_missing": "缺少 RT，无法刷新 AT；请手动获取 RT",
    "refresh_rejected": "RT 刷新被拒绝，已进入自动重新获取 RT",
    "refresh_timeout": "刷新 AT 超时，结果未确认；已停止重复使用同一 RT",
    "refresh_connection_error": "刷新 AT 连接失败，结果未确认；已停止重复使用同一 RT",
    "refresh_unconfirmed": "上次刷新 AT 结果未确认；请核对或手动重新获取 RT",
    "refresh_rate_limited": "刷新 AT 请求受限，稍后检查时再试",
    "refresh_http_error": "刷新 AT 接口返回异常，稍后检查时再试",
    "refresh_invalid_response": "刷新 AT 返回的凭证无效或身份不符，请手动核对",
    "refresh_persist_failed": "新凭证未能安全保存；请手动核对，未继续查询",
    "forbidden": "额度接口拒绝访问（HTTP 403）",
    "rate_limited": "额度接口请求受限（HTTP 429）",
    "http_error": "额度接口返回异常状态",
    "timeout": "额度查询超时",
    "connection_error": "额度接口连接失败",
    "invalid_response": "额度接口未返回有效、完整的限额窗口",
    "query_error": "额度查询失败，请稍后重新检查",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _date(value: Any) -> datetime | None:
    if not isinstance(value, (str, datetime)) or (isinstance(value, str) and len(value) > 80):
        return None
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.year < 2020:
            return None
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _identifier(value: Any) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else ""


def _email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip().casefold()
    return value if len(value) <= 320 and re.fullmatch(r"[^\s@]+@[^\s@]+", value) else ""


def _number(value: Any, maximum: int = 100) -> int | float | None:
    if type(value) not in (int, float) or not 0 <= value <= maximum or not math.isfinite(value):
        return None
    return int(value) if value == int(value) else value


def _http_status(value: Any) -> int | None:
    return value if type(value) is int and 100 <= value <= 599 else None


def _error_message(code: str, status: int | None) -> str:
    if code == "http_error" and status is not None:
        return f"额度接口返回 HTTP {status}"
    return _ERRORS[code]


def normalize_sold_quota(value: Any, job: dict | None = None) -> dict | None:
    """Allowlist a usage snapshot and bind it to one member and sale cycle."""
    if not isinstance(value, dict) or value.get("schema") != _SCHEMA:
        return None
    child, membership = value.get("child_id"), value.get("membership_id")
    email, remote = _email(value.get("email")), _identifier(value.get("remote_user_id"))
    card = _identifier(value.get("nv_remote_card_id"))
    context = job.get("context") if isinstance(job, dict) and isinstance(job.get("context"), dict) else {}
    manual_sale = context.get("manual_sale") is True or context.get("sale_source") == "manual"
    sold, checked = _date(value.get("sold_at")), _date(value.get("checked_at"))
    if (type(child) is not int or child <= 0 or type(membership) is not int or membership <= 0
            or not email or not remote or (not card and not manual_sale) or sold is None or checked is None
            or checked > _now() + timedelta(minutes=10) or sold > checked + timedelta(minutes=10)):
        return None
    clean = dict(schema=_SCHEMA, child_id=child, membership_id=membership, email=email,
                 remote_user_id=remote, sold_at=sold.isoformat(), nv_remote_card_id=card,
                 checked_at=checked.isoformat())
    if value.get("at_refreshed") is True:
        clean["at_refreshed"] = True
    if job is not None:
        if not isinstance(job, dict) or any(
            (_email(job.get(key)) if key == "email" else job.get(key)) != clean[key]
            for key in _IDENTITY_KEYS
        ):
            return None
        if context.get("sold_at") and _date(context["sold_at"]) != sold:
            return None
        if context.get("nv_remote_card_id") and context["nv_remote_card_id"] != card:
            return None
    status, http = value.get("status"), _http_status(value.get("http_status"))
    if value.get("http_status") is not None and http is None:
        return None
    if status == "error":
        code = value.get("error_code")
        if not isinstance(code, str) or code not in _ERRORS:
            return None
        return {**clean, "status": "error", "remaining_percent": None, "windows": [],
                "error_code": code, "error": _error_message(code, http), "http_status": http}
    if status != "ok" or http != 200:
        return None
    windows = value.get("windows")
    if not isinstance(windows, list) or not 1 <= len(windows) <= 2:
        return None
    normalized, seen = [], set()
    for window in windows:
        if not isinstance(window, dict):
            return None
        key, seconds = window.get("key"), window.get("window_seconds")
        remaining = _number(window.get("remaining_percent"))
        reset = _date(window.get("reset_at"))
        if (key not in ("primary", "secondary") or key in seen
                or type(seconds) is not int or not 0 < seconds <= _MAX_WINDOW_SECONDS
                or remaining is None or (window.get("reset_at") is not None and reset is None)
                or (reset is not None and reset > checked + timedelta(seconds=_MAX_WINDOW_SECONDS))):
            return None
        seen.add(key)
        normalized.append(dict(key=key, window_seconds=seconds, remaining_percent=remaining,
                               reset_at=reset.isoformat() if reset is not None else None))
    minimum = min(window["remaining_percent"] for window in normalized)
    if _number(value.get("remaining_percent")) != minimum:
        return None
    return {**clean, "status": "ok", "remaining_percent": minimum, "windows": normalized,
            "error_code": "", "error": "", "http_status": 200}


def sold_quota_error(job: dict, evidence: dict, code: str = "query_error",
                     http_status: int | None = None) -> dict | None:
    """Build a safe error without copying provider text, credentials or payloads."""
    if not isinstance(job, dict) or not isinstance(evidence, dict) or evidence.get("status") != "sold":
        return None
    # The caller supplies this turn's identity-checked sale proof. Never infer a
    # sale merely from a previous job context or from the quota response.
    sold = _date(evidence.get("sold_at"))
    if sold is None or sold > _now() + timedelta(minutes=10):
        return None
    if any(key in evidence and evidence[key] != job.get(key) for key in _IDENTITY_KEYS):
        return None
    code = code if isinstance(code, str) and code in _ERRORS else "query_error"
    return normalize_sold_quota({
        "schema": _SCHEMA, **{key: job.get(key) for key in _IDENTITY_KEYS},
        "sold_at": sold.isoformat(), "nv_remote_card_id": evidence.get("nv_remote_card_id"),
        "checked_at": _now().isoformat(), "status": "error", "error_code": code,
        "http_status": _http_status(http_status),
    }, job)


def _usage_windows(payload: Any, checked: datetime) -> list[dict] | None:
    if not isinstance(payload, dict) or payload.get("error") is not None:
        return None
    rate = payload.get("rate_limit")
    if not isinstance(rate, dict) or not {"primary_window", "secondary_window"} <= set(rate):
        return None
    windows = []
    for key in ("primary", "secondary"):
        window = rate[f"{key}_window"]
        if window is None:  # Explicit absence, including accounts with no 5h window.
            continue
        if not isinstance(window, dict):
            return None
        seconds, used = window.get("limit_window_seconds"), _number(window.get("used_percent"))
        if type(seconds) is not int or not 0 < seconds <= _MAX_WINDOW_SECONDS or used is None:
            return None
        reset = None
        raw_reset, raw_after = window.get("reset_at"), window.get("reset_after_seconds")
        if raw_reset is not None:
            timestamp = _number(raw_reset, 253402300799)
            if timestamp is None:
                return None
            try:
                reset = datetime.fromtimestamp(timestamp, timezone.utc)
            except (ValueError, OverflowError, OSError):
                return None
            if reset.year < 2020 or reset > checked + timedelta(seconds=_MAX_WINDOW_SECONDS):
                return None
        if raw_after is not None:
            after = _number(raw_after, _MAX_WINDOW_SECONDS)
            if after is None:
                return None
            if reset is None:
                reset = checked + timedelta(seconds=after)
        windows.append(dict(key=key, window_seconds=seconds,
                            remaining_percent=_number(100 - used),
                            reset_at=reset.isoformat() if reset is not None else None))
    return windows or None


class _IdentityError(Exception):
    def __init__(self, code: str = "identity_mismatch") -> None:
        self.code = code


_DEAD_RESULT_KEY = "_sold_quota_deactivation"
_DEAD_IDENTITY_KEYS = ("id", "version", "step", "parent_account_id", "source_account_id",
                       "parent_email", "child_id", "membership_id", "email", "remote_user_id", "seat_type")
_DEAD_MEMBER_KEYS = (*_IDENTITY_KEYS, "seat_type", "membership_invited_at", "oauth_acquired_at",
                     "oauth_credential_version")


@dataclass(frozen=True)
class SoldQuotaDeactivationProof:
    """Only in-process evidence; neither credentials nor their hashes are persisted."""
    identity: tuple = field(repr=False)
    binding: str = field(repr=False)
    evidence: dict = field(repr=False)
    sale: dict = field(repr=False)


class SoldQuotaDeactivated(Exception):
    def __init__(self, observation: dict, proof: SoldQuotaDeactivationProof):
        super().__init__("OpenAI 已明确停用该子号")
        self.observation, self.proof = observation, proof


class StaleSoldQuotaDeactivation(ValueError):
    """Reject just this scan member; other sale observations remain valid."""


def _deactivation_binding(session, cap, job, evidence):
    # Reuse the refresh grant's canonical identity fence, without acquiring a
    # grant or mutating anything. No mother credential is sent to the usage GET.
    from core.db import GptPlanAccountModel
    from services.nv_sold_token_refresh import _state, _aware
    state = _state(session, cap, job, evidence)
    child = session.get(GptPlanAccountModel, job["child_id"])
    member, account = state["member"], state["child"]
    context = job.get("context") or {}
    invited = _date(context.get("membership_invited_at") or context.get("oauth_membership_invited_at"))
    if (invited is None or invited != _aware(member["invited_at"])
            or member["seat_type"] != job.get("seat_type")
            or _email(job.get("email")) == _email(job.get("parent_email"))
            or any(context.get(key) and _date(context[key]) != invited
                   for key in ("membership_invited_at", "oauth_membership_invited_at"))):
        raise _IdentityError("identity_changed")
    current_member = dict(child_id=job["child_id"], membership_id=job["membership_id"],
        email=_email(member["email"]), remote_user_id=member["remote_user_id"], seat_type=member["seat_type"],
        membership_invited_at=invited.isoformat(),
        oauth_acquired_at=_aware(account["codex_rt_acquired_at"]).isoformat() if account["codex_rt_acquired_at"] else "",
        oauth_credential_version=hashlib.sha256(json.dumps([account[key] for key in
            ("codex_access_token", "codex_refresh_token", "codex_id_token", "codex_session_token")]).encode()).hexdigest())
    binding = {"member": {key: member[key] for key in ("business_account_id", "pro_account_id", "email", "source",
        "seat_type", "remote_user_id", "remote_invite_id", "invited_at", "created_at", "ended_at", "operation_id")},
        "credentials": current_member["oauth_credential_version"], "acquired_at": current_member["oauth_acquired_at"],
        "last_login_at": _aware(child.last_login_at), "workspace": state["identity"], "parent": state["parent"]}
    return hashlib.sha256(json.dumps(binding, sort_keys=True, default=str).encode()).hexdigest(), current_member


def validate_sold_deactivation(session, job, result):
    """Fence the usage response again inside finish_scan's result transaction."""
    from services import nv_automation_capabilities as cap
    from services.nv_dead_child_cleanup import normalize_deactivation_evidence, recovered_after
    from core.db import GptPlanAccountModel
    proof = result.get(_DEAD_RESULT_KEY)
    message = "停用额度结果已失效：当前子号、成员周期或凭据已变化，未清理"
    try:
        values = result.get("updates") or {}
        additions = values.get("context") or {}
        current = {key: getattr(job, key) for key in _DEAD_IDENTITY_KEYS}
        current["context"] = json.loads(job.context_json or "{}")
        if (type(proof) is not SoldQuotaDeactivationProof
                or proof.identity != tuple(current.get(key) for key in _DEAD_IDENTITY_KEYS)
                or result.get("outcome") != "failed" or result.get("next_step", job.step) != job.step
                or additions.get("child_deactivation") != proof.evidence
                or normalize_deactivation_evidence(proof.evidence, current) is None
                or current["context"].get("child_deactivation") not in (None, proof.evidence)
                or any(key in values and values[key] != current[key] for key in (*_IDENTITY_KEYS, "seat_type"))
                or any(key in additions and additions[key] != current["context"].get(key)
                       for key in ("membership_invited_at", "oauth_membership_invited_at"))
                or any(additions.get(key) != proof.sale.get(key) for key in ("sold_at", "nv_remote_card_id"))):
            raise ValueError(message)
        binding, _ = _deactivation_binding(session, cap, current, proof.sale)
        child = session.get(GptPlanAccountModel, job.child_id)
        if binding != proof.binding or recovered_after(child, proof.evidence["observed_at"]):
            raise ValueError(message)
    except Exception:
        raise StaleSoldQuotaDeactivation(message) from None


def _credentials(cap: Any, job: dict, member: dict) -> tuple[str, str, str]:
    from core.db import GptBusinessAccountModel, GptPlanAccountModel
    from platforms.chatgpt.status_probe import _decode_jwt_payload

    if (member.get("ended_at") or any(member.get(key) != job.get(key) for key in _IDENTITY_KEYS)):
        raise _IdentityError()
    plans = cap._plans()
    with cap.Session(plans.engine) as session:
        child = session.get(GptPlanAccountModel, job["child_id"])
        source = session.get(GptBusinessAccountModel, cap._positive(job.get("source_account_id")))
        parent = session.get(GptPlanAccountModel, cap._positive(job.get("parent_account_id")))
        if child is None or source is None or parent is None:
            raise _IdentityError()
        token = str(child.codex_access_token or "").strip()
        if not token:
            raise _IdentityError("missing_credentials")
        payload = _decode_jwt_payload(token)
        auth, profile = payload.get("https://api.openai.com/auth"), payload.get("https://api.openai.com/profile")
        auth, profile = auth if isinstance(auth, dict) else {}, profile if isinstance(profile, dict) else {}
        workspace = _identifier(auth.get("chatgpt_account_id"))
        token_email = _email(profile.get("email") or payload.get("email"))
        token_user = _identifier(auth.get("chatgpt_user_id") or auth.get("user_id"))
        _, source_workspace, _ = cap._business()._business_cookie_at_team(source.cookie_blob)
        known_workspaces = {_identifier(value) for value in (source_workspace, parent.chatgpt_account_id) if _identifier(value)}
        if (token_email != _email(job.get("email")) or not workspace
                or token_user != _identifier(member.get("remote_user_id"))
                or known_workspaces != {workspace} or child.business_parent_id != source.id
                or _email(child.email) != _email(job.get("email"))):
            raise _IdentityError()
        return token, workspace, hashlib.sha256(token.encode()).hexdigest()


def query_sold_quota(job: dict, evidence: dict) -> dict | None:
    """Query one sold member; on 401 only, refresh and retry the GET once."""
    baseline = sold_quota_error(job, evidence)
    if baseline is None:
        return None
    from services import nv_automation_capabilities as cap
    refreshed = False

    def failed(code: str, status: int | None = None) -> dict:
        return {**baseline, "error_code": code, "error": _error_message(code, status),
                "http_status": status, "checked_at": _now().isoformat(),
                **({"at_refreshed": True} if refreshed else {})}

    try:
        member = cap._member(job, require_remote=True)
        token, workspace, fingerprint = _credentials(cap, job, member)
    except _IdentityError as exc:
        return failed(exc.code)
    except Exception:
        return failed("identity_mismatch")
    for attempt in range(2):
        try:
            status, payload = cap._read_tier_usage(token, workspace, cap._plans()._resolve_proxy(None))
        except Exception as exc:
            kind = type(exc).__name__.casefold()
            return failed("timeout" if isinstance(exc, TimeoutError) or "timeout" in kind else "connection_error")
        checked = _now()
        try:
            current = cap._member(job, require_remote=True)
            _, current_workspace, current_fingerprint = _credentials(cap, job, current)
            if (current_workspace != workspace or current_fingerprint != fingerprint
                    or any(current.get(key) != member.get(key) for key in _DEAD_MEMBER_KEYS)):
                return failed("identity_changed")
        except Exception:
            return failed("identity_changed")
        status = _http_status(status)
        error = payload.get("error") if isinstance(payload, dict) else None
        if (status is not None and status != 200 and isinstance(error, dict)
                and isinstance(error.get("code"), str)
                and error["code"] in {"account_deactivated", "account_deleted", "user_deactivated"}):
            # Only a typed response to this exact child's saved bearer can
            # create cleanup evidence. A display error_code cannot do so.
            from services.nv_dead_child_cleanup import make_deactivation_evidence, normalize_deactivation_evidence
            proof_evidence = make_deactivation_evidence(job, observed_at=checked)
            previous = (job.get("context") or {}).get("child_deactivation")
            if previous is not None:
                proof_evidence = normalize_deactivation_evidence(previous, job)
            try:
                if proof_evidence is None:
                    raise _IdentityError()
                with cap.Session(cap._plans().engine) as session:
                    binding, canonical_member = _deactivation_binding(session, cap, job, evidence)
                if any(canonical_member.get(key) != current.get(key) for key in _DEAD_MEMBER_KEYS):
                    raise _IdentityError()
            except Exception:
                return failed("identity_changed", status)
            proof = SoldQuotaDeactivationProof(tuple(job.get(key) for key in _DEAD_IDENTITY_KEYS),
                binding, proof_evidence, {key: evidence[key] for key in ("status", "sold_at", "nv_remote_card_id")})
            raise SoldQuotaDeactivated(failed("account_deactivated", status), proof)
        if status != 401:
            break
        if attempt == 1:
            return failed("credential_invalid_after_refresh", 401)
        # This helper takes the same durable per-account lease as interactive
        # OAuth, journals one refresh grant and saves rotated credentials before
        # returning. No resolver that can launch a browser is used here.
        from services.nv_sold_token_refresh import refresh_sold_access_token
        try:
            repair = refresh_sold_access_token(job, evidence, fingerprint)
        except Exception:
            return failed("refresh_unconfirmed")
        if not isinstance(repair, dict) or repair.get("ok") is not True:
            code = repair.get("error_code") if isinstance(repair, dict) else "refresh_unconfirmed"
            return failed(code if isinstance(code, str) and code in _ERRORS else "refresh_unconfirmed",
                          _http_status(repair.get("http_status")) if isinstance(repair, dict) else None)
        refreshed = repair.get("refreshed") is True
        try:
            current = cap._member(job, require_remote=True)
            new_token, new_workspace, new_fingerprint = _credentials(cap, job, current)
            if (new_workspace != workspace or any(current.get(key) != member.get(key)
                    for key in (*_IDENTITY_KEYS, "seat_type", "membership_invited_at"))):
                return failed("identity_changed")
            token, fingerprint = new_token, new_fingerprint
            member = current
        except Exception:
            return failed("identity_changed")
    if status != 200:
        code = {401: "credential_invalid", 403: "forbidden", 429: "rate_limited"}.get(status, "http_error")
        return failed(code if status is not None else "invalid_response", status)
    windows = _usage_windows(payload, checked)
    if windows is None:
        return failed("invalid_response", 200)
    result = normalize_sold_quota({
        **baseline, "status": "ok", "checked_at": checked.isoformat(), "http_status": 200,
        "windows": windows, "remaining_percent": min(window["remaining_percent"] for window in windows),
        **({"at_refreshed": True} if refreshed else {}),
    }, job)
    return result if result is not None else failed("invalid_response", 200)
