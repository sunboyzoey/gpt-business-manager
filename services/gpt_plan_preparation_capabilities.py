"""Bounded ordinary-account preparation; all public values are credential-free.

One account lease covers Cookie inspection, one login and one security action.
Browser authentication/enrollment remains owned by the existing ChatGPT helpers.
Cookie health proves only the instant recorded in ``cookie_checked_at``; an AT
expiry is never presented as the browser session's expiry.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import HTTPException
from sqlmodel import Session, select, func

from core.db import GptPlanAccountModel, GptBusinessChildMembershipModel, GptPlanAccountOperationLeaseModel

_OPERATION = "account_preparation"
_COOKIE_OPERATIONS = frozenset({_OPERATION, "business_invite", "business_allocation", "business_replace"})
_SESSION_URL = "https://chatgpt.com/api/auth/session"
_PROTECTED_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
_SESSION_NAMES = ("__Secure-next-auth.session-token", "__Secure-authjs.session-token")
_DEAD_CODES = {"account_deactivated", "user_deactivated"}
# Recent completed registration can resume without another HTTP session probe.
# This is intentionally not a long-lived claim that the remote session is valid.
_FRESH_PREPARATION_TTL = timedelta(hours=24)
_HTTP_PREPARATION_TTL = timedelta(minutes=10)
_REGISTRATION_SECURITY_WINDOW = timedelta(hours=1)
_PREPARATION_RECEIPT_KEY = "invite_preparation_receipt_v1"
_LABELS = {
    "account_busy": "账号已有其他操作，尚未启动准备",
    "account_unavailable": "账号已不属于健康、未使用的普通账号池",
    "identity_changed": "账号身份、归属或操作租约已变化，已停止准备",
    "cookie_changed": "保存的会话已被其他操作更新，未覆盖新会话",
    "cookie_missing": "没有可检查的浏览器 Session Cookie",
    "cookie_expired": "浏览器会话已失效；这不表示账号未注册或已停用",
    "cookie_blocked": "会话检查被拒绝或需要人工验证",
    "cookie_network_error": "会话检查发生网络异常，未判定账号停用",
    "cookie_service_unavailable": "会话服务暂时不可用，未判定账号停用",
    "cookie_unknown": "会话响应未提供足够的身份及受保护接口证据",
    "identity_mismatch": "远端登录身份与目标账号不一致",
    "account_deactivated": "远端明确返回账号停用代码",
    "login_failed": "注册或登录未完成，需要检查登录阶段",
    "login_deactivation_unconfirmed": "登录页提示账号可能已停用；缺少准确远端错误代码，等待人工核验",
    "login_not_verified": "登录没有通过精确账号身份及受保护会话核验",
    "registration_failed": "密码注册未完成，保留原子号与已保存凭据，等待自动重试",
    "gmail_source_exhausted": "注册服务明确返回 user_already_exists；已自动关闭该 Gmail 母号，等待改用其他可用母号",
    "gmail_source_block_failed": "已确认 user_already_exists，但 Gmail 母号停用状态尚未保存，将自动重试保存并停止当前账号准备",
    "security_unavailable": "账号安全凭据不可读或状态不可安全恢复",
    "security_failed": "密码与 Authenticator 准备未完成，保留现有凭据等待核对",
    "security_not_confirmed": "密码或 Authenticator 尚未达到已确认就绪状态",
    "cookie_not_saved": "认证完成但没有可保存的浏览器 Session Cookie",
    "preparation_failed": "账号准备发生异常，已停止且未自动重试",
    "checkpoint_failed": "准备进度无法持久保存，已停止后续操作",
}


def _plans():
    from api import gpt_plans
    return gpt_plans


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _date(value: Any) -> datetime | None:
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _iso(value: Any) -> str:
    parsed = _date(value)
    return parsed.isoformat() if parsed else ""


def _email(value: Any) -> str:
    return str(value or "").strip().casefold()


class _Stopped(Exception):
    def __init__(self, code: str):
        self.code = code if code in _LABELS else "preparation_failed"
        super().__init__(_LABELS[self.code])


def _result(stage: str, code: str = "", **fields: Any) -> dict:
    return {
        "ok": not bool(code), "stage": stage, "error": _LABELS.get(code, ""),
        "error_code": code, "retryable": code in {"account_busy", "cookie_network_error", "cookie_service_unavailable"}, "dead": False,
        "cookie_saved": False, "cookie_health": "unknown", "cookie_checked_at": "",
        "cookie_expires_at": "", "registered_at": "", "registered_verified": False,
        "security_confirmed": False, **fields,
    }


def security_confirmed(status: Any) -> bool:
    """Strict completion, not merely permission to retry a staged TOTP seed."""
    return isinstance(status, dict) and (
        status.get("credentials_readable") is True
        and status.get("has_password") is True
        and status.get("has_totp") is True
        and status.get("password_state") == "configured"
        and status.get("mfa_state") == "enabled"
    )


def _security_status(email: str) -> dict:
    from services.chatgpt_security_store import get_chatgpt_security_status
    return get_chatgpt_security_status(email)


def _fresh_secrets(email: str) -> list[str] | None:
    """Private redaction material; ``None`` means diagnostics must use fixed text."""
    try:
        from services.chatgpt_security_store import get_chatgpt_security_secrets
        values = get_chatgpt_security_secrets(email)
        return [str(values.get(key) or "") for key in ("password", "totp_secret")] + [
            str(value) for value in (values.get("recovery_codes") or [])
        ]
    except Exception:
        return None


def _owned(account_id: int, token: str, expected_email: str = "", *, expected_cookie: str | None = None,
           operation: str = _OPERATION):
    """Revalidate the normal candidate policy and exact lease before every write."""
    if operation not in _COOKIE_OPERATIONS:
        raise _Stopped("identity_changed")
    plans = _plans()
    from api.gpt_business import _is_business_child_candidate
    with Session(plans.engine) as session:
        if not plans._plan_operation_is_current(session, account_id, token, operation):
            raise _Stopped("identity_changed")
        account = session.get(GptPlanAccountModel, account_id)
        if account is None or (expected_email and _email(account.email) != expected_email):
            raise _Stopped("identity_changed")
        if not _is_business_child_candidate(account):
            raise _Stopped("account_unavailable")
        # Preparation is only for never-assigned inventory, including email-level
        # history. The current lease is deliberately not treated as a conflict.
        membership = session.exec(select(GptBusinessChildMembershipModel.id).where(
            (GptBusinessChildMembershipModel.pro_account_id == account_id)
            | (func.lower(func.trim(GptBusinessChildMembershipModel.email)) == _email(account.email))
        )).first()
        if membership is not None:
            raise _Stopped("account_unavailable")
        if expected_cookie is not None and str(account.cookie_blob or "") != expected_cookie:
            raise _Stopped("cookie_changed")
        return account


def _save(account_id: int, token: str, expected_email: str, expected_cookie: str,
          *, operation: str = _OPERATION, expected_extra_json: str | None = None, **values: Any) -> None:
    plans = _plans()
    expected = _owned(account_id, token, expected_email, expected_cookie=expected_cookie, operation=operation)
    if expected_extra_json is not None and expected.extra_json != expected_extra_json:
        raise _Stopped("identity_changed")
    from sqlalchemy import update
    with Session(plans.engine) as session:
        if not plans._plan_operation_is_current(session, account_id, token, operation):
            raise _Stopped("identity_changed")
        lease_exists = select(GptPlanAccountOperationLeaseModel.account_id).where(
            GptPlanAccountOperationLeaseModel.account_id == account_id,
            GptPlanAccountOperationLeaseModel.token == token,
            GptPlanAccountOperationLeaseModel.operation == operation,
            GptPlanAccountOperationLeaseModel.expires_at > _now(),
        ).exists()
        no_membership = ~select(GptBusinessChildMembershipModel.id).where(
            (GptBusinessChildMembershipModel.pro_account_id == account_id)
            | (func.lower(func.trim(GptBusinessChildMembershipModel.email)) == expected_email)
        ).exists()
        result = session.execute(update(GptPlanAccountModel).where(
            GptPlanAccountModel.id == account_id,
            GptPlanAccountModel.email == expected.email,
            GptPlanAccountModel.cookie_blob == expected_cookie,
            lease_exists, no_membership,
            GptPlanAccountModel.business_parent_id.is_(None),
            GptPlanAccountModel.enabled == True,  # noqa: E712
            GptPlanAccountModel.dangerous == False,  # noqa: E712
            GptPlanAccountModel.policy_warning == False,  # noqa: E712
            *[getattr(GptPlanAccountModel, key) == getattr(expected, key) for key in (
                "refund_status", "pending_alerts_json", "extra_json", "is_pro",
                "plan_type", "catalog_category", "source_pool",
            )],
        ).values(**values, updated_at=_now()))
        if result.rowcount != 1:
            raise _Stopped("identity_changed")
        session.commit()


def _cookies(blob: Any) -> dict[str, str]:
    from platforms.chatgpt.account_security import _parse_cookie_payload
    return {name: value for name, value in _parse_cookie_payload(blob).items()
            if re.fullmatch(r"[A-Za-z0-9_\-.]+", name)
            and isinstance(value, str) and 0 < len(value) <= 32768
            and all(32 <= ord(c) < 127 and c not in ";\r\n" for c in value)}


def _has_session(cookies: dict) -> bool:
    from platforms.chatgpt.account_security import _has_session_cookie
    return _has_session_cookie(cookies)


def _cookie_digest(blob: Any) -> str:
    return hashlib.sha256(json.dumps(_cookies(blob), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _ready_receipt(account: Any, status: dict, authenticated_at: Any, *, proof_kind: str = "browser") -> dict | None:
    """Bind browser (24h) or HTTP (10m) identity proof to its final local state."""
    at = _date(authenticated_at)
    login_at = _date(account.last_login_at)
    cookie_at = _date(account.cookie_updated_at)
    password_at, mfa_at = _date(status.get("password_updated_at")), _date(status.get("mfa_updated_at"))
    if not isinstance(proof_kind, str) or proof_kind not in {"browser", "http"}:
        return None
    ttl = _FRESH_PREPARATION_TTL if proof_kind == "browser" else _HTTP_PREPARATION_TTL
    if (not at or not timedelta(0) <= _now() - at <= ttl
            or (proof_kind == "browser" and (not login_at or abs(at - login_at) > timedelta(seconds=1)))
            or _email(status.get("email")) != _email(account.email)
            or not security_confirmed(status)
            or not password_at or not mfa_at or not cookie_at
            or not _has_session(_cookies(account.cookie_blob))):
        return None
    if (any(value > _now() for value in (login_at, cookie_at, password_at, mfa_at) if value is not None)
            or cookie_at < max(at, password_at, mfa_at) - timedelta(seconds=1)):
        return None
    return {"account_id": account.id, "email": _email(account.email), "proof_kind": proof_kind,
            "authenticated_at": _iso(at), "last_login_at": _iso(login_at),
            "cookie_sha256": _cookie_digest(account.cookie_blob),
            "cookie_updated_at": _iso(account.cookie_updated_at),
            "password_updated_at": _iso(status.get("password_updated_at")),
            "mfa_updated_at": _iso(status.get("mfa_updated_at"))}


def _fresh_preparation_evidence(account: Any, status: dict) -> dict | None:
    """Read narrowly bound proof for a recently authenticated, prepared child.

    Older failed tasks did not persist a dedicated preparation receipt. Their
    alias registration, exact plan binding, same-login plan snapshot and newly
    completed security timestamps jointly provide that receipt. Imported email
    shells, a Cookie alone, or a UI's previous success flags are insufficient.
    The source's *production* block deliberately does not invalidate a child
    which already completed registration. Explicit Cookie checks never use this.
    """
    email = _email(account.email)
    if (not security_confirmed(status) or _email(status.get("email")) != email
            or str(account.last_login_error or "")
            or not _has_session(_cookies(account.cookie_blob))):
        return None
    now = _now()
    expiry = _date(account.cookie_expires_at)
    if expiry is not None and expiry <= now:
        return None
    try:
        metadata = json.loads(account.extra_json or "{}")
    except (TypeError, ValueError):
        return None
    if not isinstance(metadata, dict):
        return None
    receipt = metadata.get(_PREPARATION_RECEIPT_KEY)
    if _PREPARATION_RECEIPT_KEY in metadata and not isinstance(receipt, dict):
        return None
    if isinstance(receipt, dict):
        if type(receipt.get("account_id")) is not int:
            return None
        expected = _ready_receipt(account, status, receipt.get("authenticated_at"), proof_kind=receipt.get("proof_kind"))
        if expected is not None and receipt == expected:
            return _result("cookie_check", cookie_saved=True, cookie_health="valid",
                           cookie_checked_at=receipt["authenticated_at"], cookie_expires_at=_iso(expiry),
                           registered_at=receipt["authenticated_at"], registered_verified=True,
                           security_confirmed=True, fresh_preparation_reused=True,
                           preparation_proof_kind=receipt["proof_kind"])
        # A changed receipt must not silently fall back to weaker legacy proof.
        return None
    if str(account.mail_provider or "").casefold() != "gmail":
        return None
    login_at, plan_at, cookie_at, password_at, mfa_at = (
        _date(value) for value in (account.last_login_at, account.plan_checked_at,
            account.cookie_updated_at, status.get("password_updated_at"), status.get("mfa_updated_at"))
    )
    if not all((login_at, plan_at, cookie_at, password_at, mfa_at)):
        return None
    if (not timedelta(0) <= now - login_at <= _FRESH_PREPARATION_TTL
            or abs(plan_at - login_at) > timedelta(seconds=1)
            or any(not login_at - timedelta(seconds=1) <= value <= login_at + _REGISTRATION_SECURITY_WINDOW
                   for value in (password_at, mfa_at))
            or cookie_at < max(login_at, password_at, mfa_at) - timedelta(seconds=1)
            or any(value > now for value in (plan_at, cookie_at, password_at, mfa_at))):
        return None
    try:
        alias_id, source_id = metadata.get("gmail_alias_id"), metadata.get("gmail_source_id")
        if type(alias_id) is not int or alias_id <= 0 or type(source_id) is not int or source_id <= 0:
            return None
        from services.gmail_store import GmailAlias
        with Session(_plans().engine) as session:
            alias = session.get(GmailAlias, alias_id)
            if (alias is None or alias.gpt_plan_account_id != account.id
                    or alias.source_id != source_id or _email(alias.email) != email
                    or alias.registration_stage == "source_exhausted"):
                return None
            registered_at = _date(alias.registered_at)
            if (registered_at is None or registered_at > now
                    or abs(registered_at - login_at) > timedelta(minutes=1)):
                return None
    except Exception:
        # Missing legacy tables or invalid metadata cannot waive normal checks.
        return None
    return _result("cookie_check", cookie_saved=True, cookie_health="valid",
                   cookie_checked_at=_iso(login_at), cookie_expires_at=_iso(expiry),
                   registered_at=_iso(registered_at), registered_verified=True,
                   security_confirmed=True, fresh_preparation_reused=True, preparation_proof_kind="browser")


def _blob(cookies: dict) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def _merge_cookies(original: dict, renewed: dict) -> dict:
    result = dict(original)
    for base in _SESSION_NAMES:
        if any(name == base or name.startswith(base + ".") for name in renewed):
            result = {name: value for name, value in result.items()
                      if not (name == base or name.startswith(base + "."))}
    for name, value in renewed.items():
        result.pop(name, None)
        if value:
            result.update(_cookies({name: value}))
    return result


def _request(url: str, **kwargs: Any):
    # Shared bounded GET transport: fixed origin, no redirect, no auto retry.
    from services.business_session_health import _request as request
    return request(url, **kwargs)


def _remote_code(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    for item in (error if isinstance(error, dict) else {}, body):
        for key in ("code", "error_code"):
            if isinstance(item.get(key), str) and item[key] in _DEAD_CODES:
                return "account_deactivated"
    return ""


def _check_owned_cookie(account_id: int, token: str, email: str, proxy: str,
                        *, operation: str = _OPERATION) -> dict:
    """Inspect and CAS-refresh a Cookie under an already held allowed lease."""
    account = _owned(account_id, token, email, operation=operation)
    original = str(account.cookie_blob or "")
    cookies = _cookies(original)
    checked = _iso(_now())
    def failed(code, health="unknown", **fields):
        _owned(account_id, token, email, expected_cookie=original, operation=operation)
        return _result("cookie_check", code, cookie_health=health, cookie_checked_at=checked, **fields)
    if not _has_session(cookies):
        return failed("cookie_missing", "missing")
    outbound = {key: value for key, value in cookies.items() if key != "oai-access-token"}
    try:
        status, body, renewed = _request(_SESSION_URL, headers={
            "Cookie": _blob(outbound), "Accept": "application/json", "Referer": "https://chatgpt.com/",
        }, proxy=proxy)
        user = body.get("user") if isinstance(body, dict) and isinstance(body.get("user"), dict) else {}
        if user.get("email") and _email(user["email"]) != email:
            return failed("identity_mismatch", "wrong_identity")
        if _remote_code(body):
            return failed("account_deactivated", "dead", dead=True)
        if status == 401 or (status == 200 and isinstance(body, dict) and not body.get("accessToken")):
            return failed("cookie_expired", "expired")
        if status == 403:
            return failed("cookie_blocked", "blocked")
        if 500 <= status <= 599:
            return failed("cookie_service_unavailable", "network_error")
        if status != 200 or not isinstance(body, dict) or body.get("error"):
            return failed("cookie_unknown")
        if _email(user.get("email")) != email:
            return failed("identity_mismatch", "wrong_identity")
        at = body.get("accessToken")
        if not isinstance(at, str) or not at or any(c in at for c in "\r\n"):
            return failed("cookie_unknown")
        merged = _merge_cookies(outbound, renewed)
        headers = {"Authorization": f"Bearer {at}", "Cookie": _blob(merged),
                   "Accept": "application/json", "Referer": "https://chatgpt.com/"}
        _owned(account_id, token, email, expected_cookie=original, operation=operation)
        status, protected, refreshed = _request(_PROTECTED_URL, headers=headers, proxy=proxy)
        if _remote_code(protected):
            return failed("account_deactivated", "dead", dead=True)
        if status == 401:
            return failed("cookie_expired", "expired")
        if status == 403:
            return failed("cookie_blocked", "blocked")
        if 500 <= status <= 599:
            return failed("cookie_service_unavailable", "network_error")
        if status != 200 or not isinstance(protected, dict) or protected.get("error"):
            return failed("cookie_unknown")
        if not isinstance(protected.get("accounts"), dict) or not protected["accounts"]:
            return failed("cookie_unknown")
        merged = _merge_cookies(merged, refreshed)
        merged["oai-access-token"] = at
        if not _has_session(merged):
            return failed("cookie_not_saved", "missing")
        expiry = _date(body.get("expires"))
        if expiry is not None and expiry <= _now():
            return failed("cookie_expired", "expired")
        _save(account_id, token, email, original, cookie_blob=_blob(merged),
              cookie_updated_at=_now(), cookie_expires_at=expiry, last_login_error="", operation=operation)
        return _result("cookie_check", cookie_saved=True, cookie_health="valid",
                       cookie_checked_at=checked, cookie_expires_at=_iso(expiry),
                       registered_at=checked, registered_verified=True)
    except _Stopped:
        raise
    except Exception:
        return failed("cookie_network_error", "network_error")


def _login(account_id: int, token: str, email: str, settings: dict, proxy: str, emit: Callable,
           checkpoint: Callable | None = None, *, prepare_security: bool = False, operation: str = _OPERATION) -> dict:
    """Run the live post-login continuation before the login owner closes its page.

    The callback's private outcome is authoritative: the legacy login helper can
    swallow callback exceptions and still return ``ok=True``. Neither its stale
    pre-callback Cookie snapshot nor its public ``action_result`` is a writeback
    source. Only the callback saves registration Cookie, then security owns any
    later Cookie produced while configuring 2FA in that same browser.
    """
    from platforms.chatgpt import gpt_pro_login as login
    from platforms.chatgpt.account_security import _session_identity_with_retry, _collect_page_cookies
    from services.business_invite_login_diagnostics import make_prelogin_logger, classify_prelogin_failure, STAGE_LABELS
    account = _owned(account_id, token, email, operation=operation)
    original = str(account.cookie_blob or "")
    status = _security_status(email)
    managed = status.get("has_totp") is True or status.get("mfa_state") in {"pending", "enabled", "unmanaged"}
    mailbox, mailbox_account = (None, None) if managed else login.build_mailbox_for_account(
        _plans()._account_mail_snapshot(account), proxy=proxy)
    if mailbox is not None:
        from core.gmail_mailbox import GmailMailbox
        if isinstance(mailbox, GmailMailbox):
            # Gmail emits only fixed transport classifications, never mail
            # contents or OTPs. Show reconnect progress on the owning task.
            mailbox._log_fn = emit
    checkpoint = checkpoint if callable(checkpoint) else lambda _stage, _details: None
    callback_started = False
    callback_outcome: dict | None = None
    callback_stage = "login"
    registration: dict[str, Any] = {}
    unsubmitted_password_evidence = None

    def gmail_source_exhausted(result, *, registration_result=False):
        if (str(getattr(account, "mail_provider", "") or "").strip().casefold() != "gmail"
                or getattr(result, "ok", False) is True or callback_started):
            return False
        if registration_result:
            return getattr(result, "error_code", "") == "user_already_exists"
        failure = login.normalize_login_failure(getattr(result, "login_failure", None))
        return bool(failure and failure["code"] == "login_existing_account_context"
                    and getattr(result, "stage", "") == failure["stage"])

    def exhausted_result():
        try:
            from services.gmail_registration import block_source_for_plan
            _owned(account_id, token, email, operation=operation)
            block_source_for_plan(account_id, email, token)
        except _Stopped:
            raise
        except Exception:
            return _result("login", "gmail_source_block_failed", retryable=True)
        return _result("login", "gmail_source_exhausted", retryable=False,
                       source_error_code="user_already_exists")

    def record(stage: str, details: dict):
        nonlocal callback_stage
        callback_stage = stage
        try:
            checkpoint(stage, details)
        except Exception:
            raise _Stopped("checkpoint_failed") from None

    def summary():
        outcome = callback_outcome or _result(callback_stage, "login_not_verified", **registration)
        # The browser helper may log this object; never return the live page,
        # Cookie, private closure state, or newly generated credentials.
        return {"ok": outcome["ok"], "error": outcome["error"]}

    def continue_on_page(page, result):
        nonlocal callback_started, callback_outcome, registration
        if callback_started:
            return summary()  # Never repeat setup even when a hook is replayed.
        callback_started = True
        try:
            _owned(account_id, token, email, expected_cookie=original, operation=operation)
            if getattr(result, "ok", False) is not True or _email(getattr(result, "email", "")) != email:
                emit("登录结果未通过目标账号核验，未继续保存会话或设置安全凭据")
                raise _Stopped("login_not_verified")
            identity = _session_identity_with_retry(page, emit)
            if not (identity.get("authenticated") is True
                    and identity.get("status") == 200
                    and identity.get("backend_status") == 200
                    and _email(identity.get("email")) == email):
                # Only bounded HTTP codes and locally computed booleans may be
                # logged; response bodies/errors can contain private credentials.
                def http_code(key):
                    value = identity.get(key)
                    return str(value) if type(value) is int and 100 <= value <= 599 else "未取得"
                emit("登录会话核验未通过："
                     f"会话接口={http_code('status')}，受保护接口={http_code('backend_status')}，"
                     f"目标邮箱匹配={'是' if _email(identity.get('email')) == email else '否'}，"
                     f"页面来源可信={'否' if identity.get('origin_untrusted') is True else '未发现异常'}；"
                     "保留当前账号，未发送邀请")
                raise _Stopped("login_not_verified")
            proved_at = _iso(_now())
            registration = {"registered_verified": True, "registered_at": proved_at}
            # The identity probe can itself rotate a session. Read the live jar
            # after that probe, never result.cookies captured before this hook.
            cookie_map = _cookies(_collect_page_cookies(page))
            if not _has_session(cookie_map):
                raise _Stopped("cookie_not_saved")
            _save(account_id, token, email, original, operation=operation, cookie_blob=_blob(cookie_map),
                  cookie_updated_at=_now(), cookie_expires_at=None, last_login_at=_date(proved_at),
                  last_login_error="", last_used=_now(),
                  plan_type=str(getattr(result, "plan_type", "") or ""), plan_checked_at=_date(proved_at),
                  chatgpt_user_id=str(getattr(result, "user_id", "") or ""),
                  chatgpt_account_id=str(getattr(result, "account_id", "") or ""))
            registration.update(cookie_saved=True, cookie_health="valid",
                                cookie_checked_at=proved_at, cookie_expires_at="")
            record("login", _result("login", **registration))
            callback_outcome = _result("login", **registration)
            if prepare_security:
                # This checkpoint is durable before any credential mutation. The
                # same account lease remains held throughout the borrowed page.
                record("security", dict(registration))
                if not security_confirmed(_security_status(email)):
                    emit("注册/登录及 Cookie 已保存，复用当前浏览器设置 2FA；启用成功后直接进入邀请")
                    secured = _setup_security(account_id, token, email, settings, proxy, record,
                        page=page, operation=operation,
                        verified_unsubmitted_password=(getattr(result, "unsubmitted_password_evidence", None)
                                                       or unsubmitted_password_evidence))
                    callback_outcome = {**secured, **registration}
                else:
                    callback_outcome = _result("security", **registration)
        except _Stopped as exc:
            callback_outcome = _result(callback_stage, exc.code, **registration)
        except Exception:
            callback_outcome = _result(callback_stage, "preparation_failed", **registration)
        return summary()

    try:
        from services.gpt_plan_password_registration import (
            should_register, register_in_session, needs_saved_password_login, login_saved_password_in_session,
        )
        result = None
        if needs_saved_password_login(status):
            emit(("使用已保存密码恢复登录；登录成功后在当前窗口继续设置 2FA"
                  if status.get("password_state") == "configured" else
                  "恢复上次未完成的密码登录；登录成功后在当前窗口继续设置 2FA"))
            record("login", {"browser_used": True})
            result = login_saved_password_in_session(email=email, proxy=proxy,
                headless=settings.get("browser_mode", "headless") != "headed",
                assert_owned=lambda: _owned(account_id, token, email, operation=operation),
                on_authenticated=continue_on_page,
                emit=make_prelogin_logger(lambda message: emit(message.replace("[邀请前登录]", "[账号准备]")), account_id))
            if gmail_source_exhausted(result):
                return exhausted_result()
            if getattr(result, "email_session_recovery", False) is True:
                emit("当前账号仅提供邮箱验证码登录，先恢复会话再读取密码设置状态")
                result = None
        elif should_register(account, status):
            emit("开始密码注册，邮箱验证后直接在当前窗口设置 2FA")
            result = register_in_session(
                email=email, mailbox=mailbox, mailbox_account=mailbox_account,
                proxy=proxy, headless=settings.get("browser_mode", "headless") != "headed",
                assert_owned=lambda: _owned(account_id, token, email, operation=operation),
                on_authenticated=continue_on_page, emit=emit,
                browser_started=lambda: record("login", {"browser_used": True}),
            )
            if gmail_source_exhausted(result, registration_result=True):
                return exhausted_result()
            if getattr(result, "existing_account", False) is True:
                unsubmitted_password_evidence = getattr(result, "unsubmitted_password_evidence", None)
                emit("该邮箱已有 GPT 账号，使用现有登录流程恢复会话")
                result = None
            elif not callback_started and getattr(result, "ok", False) is not True:
                return _result("login", "registration_failed", retryable=True,
                               error=result.error or _LABELS["registration_failed"])
        if result is None:
            record("login", {"browser_used": True})
            result = login.login_with_account_auth(
                email=email, mailbox=mailbox, mailbox_account=mailbox_account,
                headless=settings.get("browser_mode", "headless") != "headed", proxy=proxy,
                # The login owner closes its page in finally, AFTER this synchronous
                # hook completes. Security closes only browsers that it creates.
                otp_timeout=180, keep_browser_open=False, is_signup=False,
                post_login_action=continue_on_page, log_fn=make_prelogin_logger(
                    lambda message: emit(message.replace("[邀请前登录]", "[账号准备]")), account_id),
            )
    except Exception:
        if callback_outcome is not None and callback_outcome["ok"] is False:
            return callback_outcome
        return _result(callback_stage, "preparation_failed", **registration)
    if callback_outcome is not None and callback_outcome["ok"] is False:
        return callback_outcome
    if callback_started:
        if (callback_outcome is None or getattr(result, "ok", False) is not True
                or _email(getattr(result, "email", "")) != email):
            return _result(callback_stage, "login_not_verified", **registration)
        # No write occurs here: a new password/2FA may have revoked the original
        # login Cookie. The security result has already persisted its final jar.
        return callback_outcome
    if getattr(result, "ok", False) is not True:
        if gmail_source_exhausted(result):
            return exhausted_result()
        # A bare legacy stage can be inferred from page prose, so it remains
        # non-authoritative.  The browser adapter's closed login_failure DTO is
        # different: normalize_login_failure verifies every field and emits
        # remote_dead only after the page exposes the exact
        # account_deactivated code.  Preserve that typed proof so the NV owner
        # can quarantine this uninvited candidate and select another one.
        login_failure = login.normalize_login_failure(getattr(result, "login_failure", None))
        if (login_failure and login_failure["code"] == "account_deactivated"
                and login_failure["remote_dead"] is True
                and getattr(result, "stage", "") == login_failure["stage"]):
            return _result("login", "account_deactivated", dead=True)
        if getattr(result, "stage", "") in _DEAD_CODES:
            return _result("login", "login_deactivation_unconfirmed")
        fresh = _fresh_secrets(email)
        if fresh is None:
            return _result("login", "login_failed")
        diagnostic = classify_prelogin_failure(
            getattr(result, "stage", ""), getattr(result, "error", ""),
            login_failure=getattr(result, "login_failure", None),
            known_secrets=[*fresh, account.password, account.client_id,
                           account.refresh_token, original, proxy,
                           str(getattr(result, "access_token", "") or ""),
                           str(getattr(result, "session_token", "") or ""),
                           *list(_cookies(getattr(result, "cookies", {})).values())],
        )
        failure_stage = diagnostic["failure_stage"]
        return _result("login", "login_failed", retryable=diagnostic["retryable"],
                       failure_stage=failure_stage,
                       **({"login_failure": diagnostic["login_failure"]} if diagnostic.get("login_failure") else {}),
                       error=f"{STAGE_LABELS[failure_stage]}：{diagnostic['failure_reason']}")
    return _result("login", "login_not_verified")


def _setup_security(account_id: int, token: str, email: str, settings: dict, proxy: str, checkpoint: Callable,
                    *, page: Any = None, operation: str = _OPERATION,
                    verified_unsubmitted_password: Any = None) -> dict:
    from core.base_platform import RegisterConfig
    from core.config_store import config_store
    from platforms.chatgpt.plugin import ChatGPTPlatform
    from services.chatgpt_security_progress import normalize_security_progress, STAGE_LABELS
    account = _owned(account_id, token, email, operation=operation)
    original = str(account.cookie_blob or "")
    platform_account, _secrets = _plans()._plan_security_platform_account(account, require_setup_capability=True)
    latest = None
    checkpoint_failed = False
    def progress(value):
        nonlocal latest, checkpoint_failed
        fresh = _fresh_secrets(email)
        supplied = dict(value) if isinstance(value, dict) else {}
        supplied["reason"] = _plans()._redact_text(
            supplied.get("reason") or "", *_secrets, *(fresh or []), proxy,
        ) if fresh is not None else ""
        clean = normalize_security_progress(supplied)
        if clean:
            clean["reason"] = clean["reason"] or STAGE_LABELS[clean["stage"]]
            latest = clean
            try:
                _owned(account_id, token, email, operation=operation)
                checkpoint("security", {"security_progress": clean})
            except Exception:
                checkpoint_failed = True
                raise _Stopped("checkpoint_failed") from None
    platform = ChatGPTPlatform(config=RegisterConfig(
        executor_type=settings.get("browser_mode", "headless"), proxy=proxy or None,
        extra=dict(config_store.get_all()),
    ))
    result = platform.execute_action("setup_security", platform_account, {
        "browser_mode": settings.get("browser_mode", "headless"),
        "_log_fn": lambda _message: None, "_progress_fn": progress,
        "_confirmation_mode": "in_session",
        **({"_verified_unsubmitted_password": verified_unsubmitted_password}
           if verified_unsubmitted_password is not None else {}),
        **({"_browser_page": page} if page is not None else {}),
    })
    if isinstance(result, dict):
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        security = data.get("security") if isinstance(data.get("security"), dict) else {}
        if isinstance(security.get("security_progress"), dict):
            progress(security["security_progress"])
    _owned(account_id, token, email, expected_cookie=original, operation=operation)
    if checkpoint_failed:
        raise _Stopped("checkpoint_failed")
    if not isinstance(result, dict) or result.get("ok") is not True:
        retry = (latest or {}).get("task_retry") or {}
        reason = f"{STAGE_LABELS[latest['stage']]}：{latest['reason']}" if latest else _LABELS["security_failed"]
        return _result("security", "security_failed", security_progress=latest,
                       error=reason,
                       retryable=retry.get("strategy") in {"safe_resume", "verify_existing"})
    patch = result.get("account_extra_patch") or {}
    refreshed = _cookies(patch.get("cookies")) if isinstance(patch, dict) else {}
    if refreshed:
        merged = _merge_cookies(_cookies(original), refreshed)
        if not _has_session(merged):
            raise _Stopped("cookie_not_saved")
        _save(account_id, token, email, original, operation=operation, cookie_blob=_blob(merged),
              cookie_updated_at=_now(), cookie_expires_at=None)
    return _result("security", security_progress=latest)


def _run_impl(account_id: int, settings: dict | None, emit: Callable | None, checkpoint: Callable | None, *, check_only: bool,
         worker_token: str = "", operation: str = _OPERATION) -> dict:
    settings = dict(settings or {})
    emit = emit if callable(emit) else lambda _message: None
    checkpoint = checkpoint if callable(checkpoint) else lambda _stage, _details: None
    token, email, stage = "", "", "cookie_check"
    owns_lease = not bool(worker_token)
    browser_used = False
    authenticated_this_run = False
    evidence: dict[str, Any] = {}
    def record(next_stage: str, details: dict):
        nonlocal stage, browser_used
        if details.get("browser_used") is True:
            browser_used = True
        stage = next_stage
        try:
            checkpoint(next_stage, details)
        except Exception:
            raise _Stopped("checkpoint_failed") from None
    try:
        if type(account_id) is not int or account_id <= 0:
            raise _Stopped("account_unavailable")
        if settings.get("browser_mode", "headless") not in {"headed", "headless"}:
            raise _Stopped("preparation_failed")
        expected_email = ""
        if "_expected_email" in settings:
            raw_email = settings["_expected_email"]
            if (not isinstance(raw_email, str) or any(char in raw_email for char in "\r\n")
                    or len(raw_email) > 320
                    or not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+", raw_email.strip())):
                raise _Stopped("identity_changed")
            expected_email = _email(raw_email)
        if operation not in _COOKIE_OPERATIONS or (owns_lease and operation != _OPERATION):
            raise _Stopped("identity_changed")
        token = worker_token or _plans()._claim_plan_operation(account_id, _OPERATION)
        # Private runtime checkpoint only: never part of a result or log DTO.
        record(stage, {"account_operation_token": token})
        account = _owned(account_id, token, expected_email=expected_email, operation=operation)
        email = _email(account.email)
        proxy = _plans()._resolve_proxy(settings.get("proxy"))
        status = _security_status(email) if not check_only else {}
        checked = _fresh_preparation_evidence(account, status) if not check_only else None
        if checked is None:
            checked = _check_owned_cookie(account_id, token, email, proxy, operation=operation)
        else:
            # Fence the receipt against a concurrent identity/Cookie mutation.
            _owned(account_id, token, email, expected_cookie=str(account.cookie_blob or ""), operation=operation)
            emit("已注册且密码、2FA 已完成，复用已保存的准备结果；不重复检查会话或注册")
        evidence = {key: checked[key] for key in (
            "cookie_saved", "cookie_health", "cookie_checked_at", "cookie_expires_at",
            "registered_at", "registered_verified",
        )}
        record(stage, checked)
        if check_only:
            return checked
        if checked["dead"]:
            account = _owned(account_id, token, email, operation=operation)
            _save(account_id, token, email, str(account.cookie_blob or ""), operation=operation,
                  dangerous=True, dangerous_detected_at=_now())
            return checked
        status = _security_status(email)
        if status.get("credentials_readable") is not True:
            return _result(stage, "security_unavailable", **evidence)
        security_handled_in_login = False
        from services.gpt_plan_password_registration import needs_saved_password_login
        recover_password = needs_saved_password_login(status)
        if not checked["ok"] or recover_password:
            if not checked["ok"] and checked["cookie_health"] not in {"missing", "expired"}:
                return checked
            if status.get("mfa_state") in {"pending", "enabled", "unmanaged"} and (
                    status.get("has_totp") is not True or status.get("has_password") is not True):
                return _result("login", "security_unavailable", **evidence)
            record("login", {})
            emit("正在确认账号注册及登录状态")
            security_handled_in_login = not security_confirmed(status)
            logged = _login(account_id, token, email, settings, proxy, emit,
                            checkpoint=record, prepare_security=security_handled_in_login, operation=operation)
            # Preserve the callback's durable registration proof even if a
            # later security action/checkpoint failed. Never regress a fused
            # security failure to a generic login stage or invoke it twice.
            evidence.update({key: logged[key] for key in (
                "cookie_saved", "cookie_health", "cookie_checked_at", "cookie_expires_at",
                "registered_at", "registered_verified",
            )})
            record(logged["stage"], logged)
            if not logged["ok"]:
                if logged["dead"]:
                    account = _owned(account_id, token, email, operation=operation)
                    _save(account_id, token, email, str(account.cookie_blob or ""), operation=operation,
                          dangerous=True, dangerous_detected_at=_now())
                return logged
            authenticated_this_run = True
        if not security_handled_in_login and not security_confirmed(status):
            record("security", {**evidence, "browser_used": True})
            secured = _setup_security(account_id, token, email, settings, proxy, record, operation=operation)
            if not secured["ok"]:
                return {**secured, **evidence}
        account = _owned(account_id, token, email, operation=operation)
        prepared_cookie = str(account.cookie_blob or "")
        record("verify", dict(evidence))
        status = _security_status(email)
        if not security_confirmed(status):
            return _result("verify", "security_not_confirmed", **evidence)
        # Login already proved the target identity in its browser; security
        # enrollment saved its final Cookie under the same lease. A second HTTP
        # probe adds no enrollment proof and can be rejected by a different
        # transport after successful 2FA. Keep only local persistence/ownership
        # checks here. Existing accounts still receive their initial probe.
        account = _owned(account_id, token, email, expected_cookie=prepared_cookie, operation=operation)
        if not _has_session(_cookies(prepared_cookie)):
            return _result("verify", "cookie_not_saved", **{**evidence,
                           "security_confirmed": True, "cookie_saved": False, "cookie_health": "missing"})
        expiry = _date(account.cookie_expires_at)
        if expiry is not None and expiry <= _now():
            return _result("verify", "cookie_expired", **{**evidence,
                           "security_confirmed": True, "cookie_health": "expired"})
        status = _security_status(email)
        if not security_confirmed(status):
            return _result("verify", "security_not_confirmed", **evidence)
        proof_kind = ("browser" if authenticated_this_run else
                      checked.get("preparation_proof_kind", "http"))
        # Reuse preserves the original evidence timestamp; it never renews TTL.
        proof_time = evidence.get("cookie_checked_at")
        receipt = _ready_receipt(account, status, proof_time, proof_kind=proof_kind)
        if receipt is not None:
            metadata = json.loads(account.extra_json or "{}")
            if not isinstance(metadata, dict):
                raise _Stopped("identity_changed")
            if metadata.get(_PREPARATION_RECEIPT_KEY) != receipt:
                metadata[_PREPARATION_RECEIPT_KEY] = receipt
                _save(account_id, token, email, prepared_cookie, operation=operation,
                      expected_extra_json=account.extra_json,
                      extra_json=json.dumps(metadata, ensure_ascii=False, separators=(",", ":")))
        result = _result("ready", **{**evidence, "cookie_saved": True,
                         "cookie_expires_at": _iso(expiry), "security_confirmed": True,
                         "browser_used": browser_used})
        record("ready", result)
        emit("账号已完成注册身份确认及密码、Authenticator 2FA 准备")
        return result
    except _Stopped as exc:
        return _result(stage, exc.code, **evidence)
    except HTTPException as exc:
        return _result(stage, "account_busy" if exc.status_code == 409 and not token else "preparation_failed", **evidence)
    except Exception:
        return _result(stage, "preparation_failed", **evidence)
    finally:
        if token and owns_lease:
            try:
                _plans()._release_plan_operation(account_id, token)
            except Exception:
                # The runtime's private token checkpoint permits exact-token
                # cleanup after this process exits; never expose a DB exception.
                pass



def _run(account_id, settings, emit, checkpoint, *, check_only, worker_token="", operation=_OPERATION):
    browser_used = False
    observer = checkpoint if callable(checkpoint) else lambda _stage, _details: None
    def record(stage, details):
        nonlocal browser_used
        browser_used = browser_used or details.get("browser_used") is True
        observer(stage, details)
    result = _run_impl(account_id, settings, emit, record, check_only=check_only,
                       worker_token=worker_token, operation=operation)
    return {**result, "browser_used": browser_used}


def prepare_for_invite(account_id: int, *, worker_token: str, expected_email: str,
                       expected_operation: str = "business_invite", settings: dict | None = None,
                       emit: Callable | None = None, checkpoint: Callable | None = None) -> dict:
    """Use the caller's exact child lease; never acquire or release its ownership."""
    if (not isinstance(worker_token, str) or not worker_token
            or expected_operation not in _COOKIE_OPERATIONS - {_OPERATION}
            or not isinstance(expected_email, str) or not expected_email.strip()):
        return _result("cookie_check", "identity_changed", browser_used=False)
    return _run(account_id, {**(settings or {}), "_expected_email": expected_email}, emit, checkpoint,
                check_only=False, worker_token=worker_token, operation=expected_operation)

def prepare_account(account_id: int, settings: dict, emit: Callable[[str], None], checkpoint: Callable[[str, dict], None]) -> dict:
    """Prepare one candidate once. No invitation, OAuth, sale, or retry loop."""
    return _run(account_id, settings, emit, checkpoint, check_only=False)


def check_account_cookie(account_id: int, settings: dict | None = None, emit: Callable | None = None, checkpoint: Callable | None = None) -> dict:
    """Check only; never authenticate, enroll MFA, clear Cookie, or mark Dead."""
    return _run(account_id, settings, emit, checkpoint, check_only=True)
