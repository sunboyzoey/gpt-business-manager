"""BUSINESS mother session checks; never invite, remove, or replay a mutation.

``cookie_expires_at`` in the legacy schema is the *AT* expiry.  A browser
session's expiry is only recorded from the authenticated session response.
Health is bound to the exact saved cookie, so a late 401 cannot poison a newer
login.  All public errors are fixed strings, never remote response bodies.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, select

from core.db import (
    GptBusinessAccountModel as Mother,
    GptBusinessAllocationLeaseModel as Lease,
    GptPlanAccountModel as Plan,
    GptPlanAccountOperationLeaseModel as OperationLease,
    ChatGptSecurityOperationLeaseModel as SecurityLease,
)

KEY = "business_session_health_v1"
CHECK_TTL = 300
HTTP_TIMEOUT = 12
RECOVERY_TTL = 360
RETRY_SECONDS = 600
_RECOVERY_REASONS = {
    "credentials_missing": "母号没有已确认配置的 ChatGPT 密码，请人工登录更新 Cookie",
    "email_verification_required": "母号登录要求额外邮箱验证，请人工登录更新 Cookie",
    "mfa_unavailable": "母号登录所需的已保存 2FA 凭据不可用，请人工登录",
    "login_failed": "母号登录恢复未完成，请稍后重试或人工登录",
    "timeout": "母号登录恢复达到时间上限，请稍后重试",
    "rate_limited": "母号登录被限流，请暂停尝试并人工核对",
    "wrong_identity": "无法确认原母号的邮箱、工作区和用户身份，请人工登录正确工作区",
    "cleanup_failed": "登录恢复进程退出尚未确认，请等待租约到期后人工核对",
}
_TEAM = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_COOKIE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_SESSION_NAMES = (
    "__Secure-next-auth.session-token", "next-auth.session-token",
    "__Secure-authjs.session-token", "authjs.session-token", "__session",
)
_TEAM_PLANS = {"team", "business", "chatgptteamplan", "chatgptbusinessplan"}
_LABELS = {
    "valid": "目标 BUSINESS 工作区访问正常",
    "unchecked": "尚未检查当前会话，请点击检查会话",
    "expired": "AT 已到期或即将到期，请检查会话以尝试自动刷新",
    "missing": "缺少 BUSINESS 登录凭证，请先登录母号",
    "invalid": "登录会话已失效，请重新登录母号后检查会话",
    "unauthorized": "AT 已被远端拒绝（HTTP 401），请检查会话以尝试刷新，或重新登录母号",
    "blocked": "访问被拒绝（HTTP 403），可能是权限或网络防护问题，不能判定 Cookie 过期",
    "error": "会话检查失败，无法确认有效性；请稍后重试",
    "wrong_identity": "会话身份或工作区与母号不符，请重新登录并选择正确的 BUSINESS 工作区",
    "busy": "该母号正在检查或刷新会话，请稍后重试",
    "deactivated": "母号已被明确标记停用，自动轮询已停止，请人工处理",
}


def _now():
    return datetime.now(timezone.utc)


def _date(value):
    try:
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        if isinstance(value, str) and value.strip():
            return _date(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, TypeError, OverflowError):
        pass
    return None


def _iso(value):
    parsed = _date(value)
    return parsed.isoformat() if parsed else ""


def _extra(value):
    try:
        result = json.loads(value or "{}")
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def _fingerprint(value):
    return hashlib.sha256(str(value or "").encode()).hexdigest()


def _cookies(blob):
    # Use the same semicolon format as the actual BUSINESS request path.
    result = {}
    for part in str(blob or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and _COOKIE_NAME.fullmatch(name) and _safe_value(value):
            result[name] = value
    return result


def _safe_value(value):
    return (isinstance(value, str) and 0 < len(value) <= 32768
            and all(32 <= ord(c) < 127 and c not in ";\r\n" for c in value))


def _has_session(cookies):
    return any(name == base or name.startswith(base + ".")
               for name in cookies for base in _SESSION_NAMES)


def _claims(at):
    try:
        if not _safe_value(at):
            return {}
        parts = at.split(".")
        if len(parts) != 3:
            return {}
        result = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError, UnicodeError):
        return {}


def _identity(at):
    claims = _claims(at)
    auth = claims.get("https://api.openai.com/auth") or {}
    profile = claims.get("https://api.openai.com/profile") or {}
    if not isinstance(auth, dict) or not isinstance(profile, dict):
        return {}, None
    expiry = None
    try:
        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            expiry = datetime.fromtimestamp(exp, timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return {
        "email": str(profile.get("email") or claims.get("email") or "").strip().lower(),
        "user": str(auth.get("chatgpt_user_id") or auth.get("user_id") or ""),
        "team": str(auth.get("chatgpt_account_id") or ""),
        "plan": str(auth.get("chatgpt_plan_type") or "").lower(),
    }, expiry


def _saved_health(mother):
    raw = _extra(mother.extra_json).get(KEY)
    raw = raw if isinstance(raw, dict) else {}
    checked = _date(raw.get("checked_at"))
    updated = _date(mother.cookie_updated_at)
    if (raw.get("fingerprint") != _fingerprint(mother.cookie_blob)
            or (checked and updated and updated > checked)):
        return {}
    return raw


def public_health(mother):
    """Local-only, credential-free DTO; listing a page never hits OpenAI."""
    cookies = _cookies(mother.cookie_blob)
    at = cookies.get("oai-access-token", "")
    identity, expiry = _identity(at)
    raw = _saved_health(mother)
    state = raw.get("status") if raw.get("status") in _LABELS else "unchecked"
    if mother.dangerous:
        state = "deactivated"
    elif not at:
        state = "missing"
    elif (not expiry or not _TEAM.fullmatch(identity.get("team", ""))
          or identity.get("plan") not in _TEAM_PLANS):
        state = "wrong_identity"
    elif expiry <= _now() + timedelta(seconds=60) and state not in {"invalid", "unauthorized", "wrong_identity", "blocked", "error"}:
        state = "expired"
    elif state == "valid" and (not _date(raw.get("checked_at")) or
                              _date(raw.get("checked_at")) + timedelta(seconds=CHECK_TTL) <= _now()):
        state = "unchecked"
    code = raw.get("http_status")
    result = {
        "status": state,
        "message": _LABELS[state],
        "checked_at": _iso(raw.get("checked_at")),
        "access_token_expires_at": _iso(expiry),
        "session_expires_at": _iso(raw.get("session_expires_at")),
        "cookie_updated_at": _iso(mother.cookie_updated_at),
        "refreshed_at": _iso(raw.get("refreshed_at")),
        "can_refresh": _has_session(cookies),
        "http_status": code if isinstance(code, int) and not isinstance(code, bool) and 100 <= code <= 599 else None,
    }
    recovery = raw.get("recovery") if isinstance(raw.get("recovery"), dict) else {}
    reason = recovery.get("reason")
    if reason in _RECOVERY_REASONS:
        result.update(recovery_reason=reason, recovery_message=_RECOVERY_REASONS[reason],
                      retry_at=_iso(recovery.get("retry_at")), retryable=recovery.get("retryable") is True)
    return result


@dataclass(frozen=True)
class _Snapshot:
    source_id: int
    plan_id: int
    email: str
    source_created: str
    plan_created: str
    blob: str
    plan_blob: str
    cookie_updated: str
    team: str
    user: str
    plan_cookie_updated: str
    plan_team: str
    plan_user: str
    plan_checked: str


def _engine():
    # Resolve lazily: the BUSINESS module is the owner of mother credentials.
    from api import gpt_business
    return gpt_business.engine


def _bound(session, source_id, *, lock=False):
    mother_query = select(Mother).where(Mother.id == int(source_id))
    if lock:
        mother_query = mother_query.with_for_update()
    mother = session.exec(mother_query).first()
    if mother is None:
        return None, None
    plan_query = select(Plan).where(
        Plan.source_pool == "gpt_business", Plan.source_account_id == int(source_id),
        Plan.business_parent_id.is_(None),
    )
    if lock:
        plan_query = plan_query.with_for_update()
    rows = session.exec(plan_query).all()
    if len(rows) != 1 or str(rows[0].email).strip().lower() != str(mother.email).strip().lower():
        return mother, None
    return mother, rows[0]


def _eligible(mother, plan):
    from api.gpt_plans import _catalog_category, _canonical_member_plan
    return bool(mother and plan and mother.enabled and plan.enabled
                and not mother.dangerous and not plan.dangerous
                and _catalog_category(plan) == "member"
                and _canonical_member_plan(plan.plan_type) == "team"
                and str(mother.refund_status or "") not in {"refunded_pending_credit", "refund_credited"}
                and str(plan.refund_status or "") not in {"refunded_pending_credit", "refund_credited"})


def _capture(mother, plan):
    identity, _ = _identity(_cookies(mother.cookie_blob).get("oai-access-token", ""))
    return _Snapshot(int(mother.id), int(plan.id), str(mother.email).strip().lower(),
                     _iso(mother.created_at), _iso(plan.created_at), str(mother.cookie_blob or ""),
                     str(plan.cookie_blob or ""), _iso(mother.cookie_updated_at),
                     identity.get("team", ""), identity.get("user", ""),
                     _iso(plan.cookie_updated_at), str(plan.chatgpt_account_id or ""),
                     str(plan.chatgpt_user_id or ""), _iso(plan.plan_checked_at))


def _same(snapshot, mother, plan):
    return bool(_eligible(mother, plan) and _capture(mother, plan) == snapshot)


def _begin(session):
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _lease_key(source_id):
    # Separate from parent mutation lease: callers may already own parent:<id>.
    # This serializes *only* session renewal; final writes also CAS the cookie.
    return f"business-session:{int(source_id)}"


def _release(source_id, token):
    with Session(_engine()) as session:
        session.exec(delete(Lease).where(Lease.resource_key == _lease_key(source_id), Lease.owner_token == token))
        session.commit()


def _persist(snapshot, token, *, status, http_status=None, blob=None, session_expires_at=None, refreshed=False,
             automation=False, recovery=None, deactivated=False):
    try:
        return _persist_atomic(snapshot, token, status=status, http_status=http_status,
                               blob=blob, session_expires_at=session_expires_at, refreshed=refreshed,
                               automation=automation, recovery=recovery, deactivated=deactivated)
    except SQLAlchemyError:
        # SQL exceptions can embed bound Cookie parameters; never let them
        # reach task logs or HTTP error serializers.
        raise HTTPException(503, "会话结果保存失败，未确认刷新完成，请稍后检查") from None


def _persist_atomic(snapshot, token, *, status, http_status=None, blob=None, session_expires_at=None, refreshed=False,
                    automation=False, recovery=None, deactivated=False):
    with Session(_engine()) as session:
        _begin(session)
        mother, plan = _bound(session, snapshot.source_id, lock=True)
        lease = session.get(Lease, _lease_key(snapshot.source_id))
        if (not _same(snapshot, mother, plan) or not lease or lease.owner_token != token
                or (_date(lease.expires_at) or _now()) <= _now()):
            raise HTTPException(409, "检查期间母号 Cookie 或绑定已更新，已丢弃旧结果，请重新检查")
        if automation and not _automation_leases_current(session, snapshot, token):
            raise HTTPException(409, "母号登录恢复租约已变化，已丢弃旧结果")
        now = _now()
        extra = _extra(mother.extra_json)
        previous = _saved_health(mother)
        health = {
            "fingerprint": _fingerprint(blob if blob is not None else snapshot.blob),
            "status": status, "http_status": http_status, "checked_at": _iso(now),
            "session_expires_at": _iso(session_expires_at) or _iso(previous.get("session_expires_at")),
            "refreshed_at": _iso(now) if refreshed else _iso(previous.get("refreshed_at")),
        }
        if recovery is not None:
            health["recovery"] = recovery
        extra[KEY] = health
        # Repair old rows that saved an AT but lost (or retained an older)
        # cookie_expires_at value. This column has always meant AT expiry.
        _, expiry = _identity(_cookies(blob if blob is not None else snapshot.blob).get("oai-access-token", ""))
        fields = {"extra_json": json.dumps(extra, ensure_ascii=False), "cookie_expires_at": expiry}
        if blob is not None:
            fields.update(cookie_blob=blob, cookie_expires_at=expiry, cookie_updated_at=now, updated_at=now)
        if deactivated:
            fields.update(dangerous=True, dangerous_detected_at=now, updated_at=now)
        # Conditional SQL protects other processes as well as threads.
        changed = session.exec(update(Mother).where(
            Mother.id == snapshot.source_id, Mother.cookie_blob == snapshot.blob,
            Mother.extra_json == mother.extra_json,
            Mother.email == mother.email, Mother.created_at == mother.created_at,
            Mother.cookie_updated_at == mother.cookie_updated_at,
            Mother.enabled.is_(True), Mother.dangerous.is_(False),
            Mother.refund_status == mother.refund_status,
        ).values(**fields))
        if changed.rowcount != 1:
            raise HTTPException(409, "母号会话已变化，请重新检查")
        if blob is not None or deactivated:
            plan_fields = ({"cookie_blob": blob, "cookie_updated_at": now, "cookie_expires_at": expiry,
                            "updated_at": now} if blob is not None else {})
            if deactivated:
                plan_fields.update(dangerous=True, dangerous_detected_at=now, updated_at=now)
            changed = session.exec(update(Plan).where(
                Plan.id == snapshot.plan_id, Plan.cookie_blob == snapshot.plan_blob,
                Plan.source_pool == "gpt_business", Plan.source_account_id == snapshot.source_id,
                Plan.email == plan.email, Plan.created_at == plan.created_at,
                Plan.business_parent_id.is_(None), Plan.enabled.is_(True), Plan.dangerous.is_(False),
                Plan.catalog_category == plan.catalog_category, Plan.plan_type == plan.plan_type,
                Plan.refund_status == plan.refund_status,
                Plan.cookie_updated_at == plan.cookie_updated_at,
                Plan.chatgpt_account_id == plan.chatgpt_account_id, Plan.chatgpt_user_id == plan.chatgpt_user_id,
                Plan.plan_checked_at == plan.plan_checked_at,
            ).values(**plan_fields))
            if changed.rowcount != 1:
                raise HTTPException(409, "套餐母号会话已更新，请重新检查")
        session.commit()
        session.expire_all()
        return public_health(session.get(Mother, snapshot.source_id))


def _request(url, *, headers, proxy, params=None):
    """Fixed origin, bounded GET only. No redirects or automatic retries."""
    from curl_cffi import requests
    with requests.Session(impersonate="chrome131", trust_env=False) as client:
        response = client.get(url, headers=headers, params=params,
                              proxies={"http": proxy, "https": proxy} if proxy else {},
                              timeout=HTTP_TIMEOUT, allow_redirects=False)
        if len(response.content) > 512 * 1024:
            return int(response.status_code), None, {}
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = None
        # Cookie values remain private; only exact chatgpt.com cookies are used.
        renewed = {}
        for cookie in response.cookies.jar:
            if str(cookie.domain or "").lstrip(".") != "chatgpt.com":
                continue
            name, value = str(cookie.name), str(cookie.value or "")
            if _COOKIE_NAME.fullmatch(name) and (not value or _safe_value(value)):
                renewed[name] = value
        return int(response.status_code), body, renewed


def _probe(at, team, proxy):
    if not _TEAM.fullmatch(team):
        return "wrong_identity", None
    status, body, _ = _request(
        f"https://chatgpt.com/backend-api/accounts/{team}/users",
        headers={"Authorization": f"Bearer {at}", "chatgpt-account-id": team,
                 "Accept": "application/json", "Referer": "https://chatgpt.com/"},
        params={"limit": 1, "offset": 0}, proxy=proxy,
    )
    if status == 200 and isinstance(body, dict) and isinstance(body.get("items"), list) and not body.get("error"):
        return "valid", status
    return {401: "unauthorized", 403: "blocked"}.get(status, "error"), status


def check_session(source_id, *, force=False):
    """Check a bound mother, renew AT once if necessary, then test the new AT.

    Forced/manual checks also validate the browser session if one is saved.
    Automatic preflights use a five-minute successful check cache. Legacy
    BUSINESS-only rows are not enrolled implicitly.
    """
    token = uuid.uuid4().hex
    try:
        with Session(_engine()) as session:
            _begin(session)
            mother, plan = _bound(session, source_id)
            if plan is None:
                return None
            if not _eligible(mother, plan):
                raise HTTPException(409, "该 BUSINESS 母号已停用、Dead 或已进入已退款列表")
            current = public_health(mother)
            if not force and current["status"] == "valid":
                return current
            key = _lease_key(source_id)
            existing = session.get(Lease, key)
            if existing and (_date(existing.expires_at) or _now()) > _now():
                raise HTTPException(409, {"code": "business_session_busy", "message": _LABELS["busy"]})
            if existing:
                session.delete(existing)
                session.flush()
            snapshot = _capture(mother, plan)
            session.add(Lease(resource_key=key, job_id=key, owner_token=token,
                              expires_at=_now() + timedelta(seconds=90)))
            session.commit()
    except IntegrityError:
        raise HTTPException(409, {"code": "business_session_busy", "message": _LABELS["busy"]}) from None

    try:
        from core.config_store import config_store
        proxy = str(config_store.get("default_proxy", "") or "").strip()
        cookies = _cookies(snapshot.blob)
        at = cookies.get("oai-access-token", "")
        identity, expiry = _identity(at)
        if identity.get("email") and identity["email"] != snapshot.email:
            return _persist(snapshot, token, status="wrong_identity")
        if identity.get("plan") not in _TEAM_PLANS:
            return _persist(snapshot, token, status="missing" if not at else "wrong_identity")
        if not _TEAM.fullmatch(snapshot.team):
            return _persist(snapshot, token, status="missing" if not at else "wrong_identity")
        state, http_status = "expired", None
        if not (force and _has_session(cookies)) and expiry and expiry > _now() + timedelta(seconds=60):
            state, http_status = _probe(at, snapshot.team, proxy)
            if state != "unauthorized":
                return _persist(snapshot, token, status=state, http_status=http_status)
        if not _has_session(cookies):
            return _persist(snapshot, token, status=state, http_status=http_status)

        # Never send our synthetic AT cookie to the session service.
        outbound = {k: v for k, v in cookies.items() if k != "oai-access-token"}
        status, body, renewed = _request(
            "https://chatgpt.com/api/auth/session",
            headers={"Cookie": "; ".join(f"{k}={v}" for k, v in outbound.items()),
                     "Accept": "application/json", "Referer": "https://chatgpt.com/",
                     "chatgpt-account-id": snapshot.team}, proxy=proxy,
        )
        if status == 401 or (status == 200 and isinstance(body, dict) and not body.get("accessToken")):
            return _persist(snapshot, token, status="invalid", http_status=status)
        if status != 200 or not isinstance(body, dict):
            return _persist(snapshot, token, status="blocked" if status == 403 else "error", http_status=status)
        new_at = body.get("accessToken")
        new_identity, new_expiry = _identity(new_at)
        if (not new_identity.get("email") or new_identity["email"] != snapshot.email
                or new_identity.get("team") != snapshot.team
                or (snapshot.user and new_identity.get("user") != snapshot.user)
                or new_identity.get("plan") not in _TEAM_PLANS
                or not new_expiry or new_expiry <= _now() + timedelta(seconds=60)):
            return _persist(snapshot, token, status="wrong_identity", http_status=status)
        # Replace rotating chunk families, not just a single .0 fragment.
        for base in _SESSION_NAMES:
            if any(k == base or k.startswith(base + ".") for k in renewed):
                for k in list(cookies):
                    if k == base or k.startswith(base + "."):
                        cookies.pop(k)
        for name, value in renewed.items():
            if value:
                cookies[name] = value
            else:
                cookies.pop(name, None)
        cookies["oai-access-token"] = new_at
        new_blob = "; ".join(f"{k}={v}" for k, v in cookies.items())
        session_expiry = _date(body.get("expires"))
        # Save renewed cookies before the probe: a failed probe must not discard
        # a session cookie that the server may already have rotated.
        _persist(snapshot, token, status="unchecked", blob=new_blob,
                 session_expires_at=session_expiry, refreshed=True)
        with Session(_engine()) as session:
            mother, plan = _bound(session, source_id)
            if not _eligible(mother, plan) or mother.cookie_blob != new_blob:
                raise HTTPException(409, "刷新后母号会话已变化，请重新检查")
            snapshot = _capture(mother, plan)
        state, status = _probe(new_at, snapshot.team, proxy)
        return _persist(snapshot, token, status=state, http_status=status)
    except HTTPException:
        raise
    except Exception:
        # A timeout, HTML challenge, or transport failure is not expiry proof.
        return _persist(snapshot, token, status="error")
    finally:
        _release(source_id, token)


def ensure_session(source_id):
    health = check_session(source_id)
    if health is not None and health["status"] != "valid":
        raise HTTPException(409, {
            "code": "business_session_unavailable", "message": health["message"],
            "session_health": health,
        })
    return health


def _automation_error(health=None, *, busy=False, dead=False, retryable=True):
    # Only locally produced health DTOs enter this public error boundary.
    health = health or {"status": "missing", "message": _LABELS["missing"]}
    code = "business_mother_deactivated" if dead else "business_session_busy" if busy else "business_session_unavailable"
    message = (_LABELS["deactivated"] if dead else _LABELS["busy"] if busy
               else health.get("recovery_message") or health.get("message") or _LABELS["error"])
    detail = {"code": code, "message": message, "session_health": health,
              "retryable": False if dead else bool(retryable)}
    if health.get("retry_at"):
        detail["retry_at"] = health["retry_at"]
    return HTTPException(409, detail)


def _automation_leases_current(session, snapshot, token):
    rows = ((session.get(Lease, _lease_key(snapshot.source_id)), "owner_token"),
            (session.get(OperationLease, snapshot.plan_id), "token"),
            (session.get(SecurityLease, snapshot.email), "owner_token"))
    return all(row and getattr(row, field) == token and (_date(row.expires_at) or _now()) > _now()
               for row, field in rows)


def _claim_automation(source_id):
    token = uuid.uuid4().hex
    with Session(_engine()) as session:
        _begin(session)
        mother, plan = _bound(session, source_id, lock=True)
        current = public_health(mother) if mother else None
        if mother and (mother.dangerous or (plan and plan.dangerous)):
            raise _automation_error(current, dead=True)
        if not _eligible(mother, plan):
            raise _automation_error(current, retryable=False)
        snapshot = _capture(mother, plan)
        if current["status"] == "valid":
            return None, None, current
        rows = (session.get(Lease, _lease_key(source_id)), session.get(OperationLease, snapshot.plan_id),
                session.get(SecurityLease, snapshot.email))
        if any(row and (_date(row.expires_at) or _now()) > _now() for row in rows):
            raise _automation_error(current, busy=True)
        for row in rows:
            if row:
                session.delete(row)
        session.flush()
        until = _now() + timedelta(seconds=RECOVERY_TTL)
        key = _lease_key(source_id)
        session.add(Lease(resource_key=key, job_id=key, owner_token=token, expires_at=until))
        session.add(OperationLease(account_id=snapshot.plan_id, operation="login", token=token, expires_at=until))
        session.add(SecurityLease(email=snapshot.email, owner_token=token, expires_at=until))
        session.commit()
        return snapshot, token, current


def _release_automation(snapshot, token):
    with Session(_engine()) as session:
        session.exec(delete(Lease).where(Lease.resource_key == _lease_key(snapshot.source_id), Lease.owner_token == token))
        session.exec(delete(OperationLease).where(OperationLease.account_id == snapshot.plan_id, OperationLease.token == token))
        session.exec(delete(SecurityLease).where(SecurityLease.email == snapshot.email, SecurityLease.owner_token == token))
        session.commit()


def _recover_login(snapshot, *, proxy, browser_mode):
    from services.business_session_recovery import recover_password_session
    return recover_password_session(snapshot.email, proxy=proxy, browser_mode=browser_mode)


def ensure_session_for_automation(source_id, *, emit=None, browser_mode="headless"):
    """Restore one mother before automation; never replay a failed mutation.

    Only an exact existing-account password login is supported. No credential
    configuration, registration, email-OTP fallback, SMS purchase or deletion.
    A failed attempt is bound to the saved cookie and backed off for ten minutes.
    """
    snapshot = token = None
    current = None
    release = True
    def report(message):
        if callable(emit):
            try:
                emit(message)
            except Exception:
                pass
    try:
        if browser_mode not in {"headless", "headed"}:
            raise _automation_error(retryable=False)
        with Session(_engine()) as session:
            mother, plan = _bound(session, source_id)
            current = public_health(mother) if mother else None
            if mother and (mother.dangerous or (plan and plan.dangerous)):
                raise _automation_error(current, dead=True)
            if not _eligible(mother, plan):
                raise _automation_error(current, retryable=False)
            captured = _capture(mother, plan)
            if ((captured.plan_team and captured.plan_team != captured.team)
                    or (captured.plan_user and captured.plan_user != captured.user)):
                current = {**current, "status": "wrong_identity", "message": _LABELS["wrong_identity"]}
                raise _automation_error(current, retryable=False)
            if current["status"] == "valid":
                return current
            retry_at = _date(current.get("retry_at"))
            if retry_at and retry_at > _now():
                raise _automation_error(current, retryable=current.get("retryable", True))
        report("正在检查并尝试续期母号 Cookie")
        current = check_session(source_id, force=True)
        if current and current["status"] == "valid":
            return current
        snapshot, token, current = _claim_automation(source_id)
        if snapshot is None:
            return current
        reason, retryable = "login_failed", True
        if current["status"] in {"invalid", "unauthorized", "expired", "missing"}:
            # A clean login may choose a different workspace: never guess which
            # original identity to overwrite when its stable binding is absent.
            bound = (bool(_TEAM.fullmatch(snapshot.team)) and bool(snapshot.user)
                     and (not snapshot.plan_team or snapshot.plan_team == snapshot.team)
                     and (not snapshot.plan_user or snapshot.plan_user == snapshot.user))
            if bound:
                from core.config_store import config_store
                proxy = str(config_store.get("default_proxy", "") or "").strip()
                report("母号 Cookie 已失效，正在用已配置密码与 2FA 尝试一次登录恢复")
                try:
                    result = _recover_login(snapshot, proxy=proxy, browser_mode=browser_mode)
                except Exception:
                    result = {"status": "unavailable", "reason": "login_failed"}
                result = result if isinstance(result, dict) else {}
                if (result.get("status") == "deactivated" and result.get("evidence") == "trusted_auth_error_page"
                        and result.get("email_confirmed") is True and result.get("email_submitted") is True):
                    current = _persist(snapshot, token, status="deactivated", automation=True, deactivated=True)
                    report(_LABELS["deactivated"])
                    raise _automation_error(current, dead=True)
                reason = result.get("reason") if result.get("reason") in _RECOVERY_REASONS else "login_failed"
                if result.get("status") == "valid":
                    blob = str(result.get("cookie_blob") or "")
                    cookies = _cookies(blob)
                    identity, expiry = _identity(cookies.get("oai-access-token", ""))
                    if (len(blob) <= 256 * 1024 and _has_session(cookies) and identity.get("email") == snapshot.email
                            and identity.get("team") == snapshot.team and identity.get("user") == snapshot.user
                            and identity.get("plan") in _TEAM_PLANS and expiry and expiry > _now() + timedelta(seconds=60)):
                        try:
                            state, status = _probe(cookies["oai-access-token"], snapshot.team, proxy)
                        except Exception:
                            state, status = "error", None
                        if state == "valid":
                            normalized_blob = "; ".join(f"{name}={value}" for name, value in cookies.items())
                            current = _persist(snapshot, token, status="valid", blob=normalized_blob, http_status=status,
                                               session_expires_at=result.get("session_expires_at"), refreshed=True,
                                               automation=True)
                            report("母号登录与目标 BUSINESS 工作区验证成功，已同步更新 Cookie")
                            return current
                    else:
                        reason = "wrong_identity"
                retryable = reason not in {"credentials_missing", "email_verification_required", "mfa_unavailable", "wrong_identity", "rate_limited", "cleanup_failed"}
                if reason == "cleanup_failed":
                    # Unconfirmed descendants must remain fenced by TTL; do not
                    # permit another login while the old browser may still act.
                    release = False
            else:
                reason, retryable = "wrong_identity", False
        elif current["status"] == "wrong_identity":
            reason, retryable = "wrong_identity", False
        retry = {"reason": reason, "retryable": retryable, "retry_at": _iso(_now() + timedelta(seconds=RETRY_SECONDS))}
        current = _persist(snapshot, token, status=current["status"], http_status=current.get("http_status"),
                           automation=True, recovery=retry)
        raise _automation_error(current, retryable=retryable)
    except HTTPException as exc:
        if isinstance(exc.detail, dict) and exc.detail.get("code") in {
                "business_session_unavailable", "business_session_busy", "business_mother_deactivated"}:
            if "session_health" in exc.detail:
                raise
            raise _automation_error(current, busy=exc.detail.get("code") == "business_session_busy") from None
        raise _automation_error(current, busy=exc.status_code == 409) from None
    except (IntegrityError, SQLAlchemyError):
        raise _automation_error(current, busy=True) from None
    except Exception:
        raise _automation_error(current) from None
    finally:
        if snapshot is not None and token and release:
            try:
                _release_automation(snapshot, token)
            except Exception:
                # Lease TTL is the safe fallback; SQL exceptions can contain
                # secret parameters and must never replace the public error.
                pass


def note_unauthorized(at, team, *, request_started_at=None):
    """Observe a real 401 without changing its return/compensation semantics."""
    if not at or not team:
        return
    with Session(_engine()) as session:
        _begin(session)
        rows = session.exec(select(Mother).join(Plan, Plan.source_account_id == Mother.id).where(
            Plan.source_pool == "gpt_business", Plan.business_parent_id.is_(None),
        )).all()
        for mother in rows:
            cookies = _cookies(mother.cookie_blob)
            identity, _ = _identity(cookies.get("oai-access-token", ""))
            if cookies.get("oai-access-token") != at or identity.get("team") != team:
                continue
            extra = _extra(mother.extra_json)
            prior = _saved_health(mother)
            started = _date(request_started_at)
            if started and any(value and value > started for value in (
                _date(mother.cookie_updated_at), _date(prior.get("checked_at")),
            )):
                # A newer login/check wins even when OpenAI returned the same
                # still-current AT while rotating only the browser cookies.
                continue
            extra[KEY] = {**prior, "fingerprint": _fingerprint(mother.cookie_blob),
                          "status": "unauthorized", "http_status": 401, "checked_at": _iso(_now())}
            session.exec(update(Mother).where(
                Mother.id == mother.id, Mother.cookie_blob == mother.cookie_blob,
                Mother.extra_json == mother.extra_json,
            ).values(extra_json=json.dumps(extra, ensure_ascii=False)))
        session.commit()
