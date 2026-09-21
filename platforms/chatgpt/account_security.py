"""Post-registration ChatGPT password and authenticator-MFA setup.

The public ChatGPT settings UI is intentionally treated as a semantic state
machine.  OpenAI does not publish stable DOM selectors for that UI, so every
remote transition is verified before local state is advanced.  Passwords,
TOTP seeds and one-time codes must never be returned in action results or
written to logs.
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.parse
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional


CHATGPT_HOME = "https://chatgpt.com/"
ACCOUNT_DEACTIVATED_LOGIN_ERROR = "OpenAI 已明确停用或删除此账号（account_deactivated）"
_AUTHENTICATION_PAGE_ERROR = "OpenAI 登录页面报告身份验证错误，尚未完成登录"
_UNSUBMITTED_PASSWORD_PREFIX = "首次密码尚未提交；"
_UNSUBMITTED_PASSWORD_ERRORS = {
    "无法打开 ChatGPT 账户安全与登录设置", "未找到添加密码入口",
    "已点击密码设置入口，但等待后未出现验证页或可填写的密码表单",
}


class AccountDeactivatedLoginError(RuntimeError):
    """Only raised after an explicit code on the trusted, visible auth page."""

    def __init__(self) -> None:
        super().__init__(ACCOUNT_DEACTIVATED_LOGIN_ERROR)


@dataclass(frozen=True)
class VerifiedUnsubmittedPasswordEvidence:
    """Internal audited handoff, never accepted from JSON or saved as credentials.

    Registration may pass this process-local object only when its driver
    explicitly observed no password submission. Its version fields describe
    the caller's original staged candidate, never a newly read replacement.
    """

    email: str
    security_updated_at: str
    password_updated_at: str
    mfa_updated_at: str


_SETTINGS_URLS = {
    "account": (
        "https://chatgpt.com/#settings/Account",
        "https://chatgpt.com/#settings/account",
    ),
    "security": (
        "https://chatgpt.com/#settings/Security",
        "https://chatgpt.com/#settings/security",
    ),
}
_MFA_TERMS = (
    "multi-factor authentication",
    "multifactor authentication",
    "two-factor authentication",
    "two factor authentication",
    "双重身份验证",
    "多重身份验证",
    "双因素认证",
    "多因素身份验证",
    "多因素身份驗證",
    "两步验证",
)
_AUTHENTICATOR_TERMS = (
    "authenticator app",
    "authentication app",
    "authenticator application",
    "身份验证器应用",
    "验证器应用",
    "身份验证应用",
)
_SECURITY_LOCK_STRIPES = tuple(threading.RLock() for _ in range(64))
_SECURITY_DB_LEASE_SECONDS = 15 * 60
_SECURITY_LEASE_OWNER: ContextVar[tuple[str, str] | None] = ContextVar("chatgpt_security_lease_owner", default=None)
_SETTINGS_SECTION_TIMEOUT_SECONDS = 12.0
_SESSION_COOKIE_BASES = (
    "__Secure-next-auth.session-token",
    "__Secure-authjs.session-token",
)
_SECURITY_PROGRESS: ContextVar[Any] = ContextVar("chatgpt_security_progress", default=None)


class _SecurityProgress:
    """Per-invocation diagnostics, never credentials or remote state truth."""

    def __init__(self, email: str, callback: Any = None, *, confirmation_mode: str = "independent") -> None:
        self.email = email
        self.callback = callback
        self.confirmation_mode = confirmation_mode
        self.value: dict[str, Any] = {}
        self.submission_started = False
        self.totp_activation_started = False
        self.totp_submission_started = False
        self.initial_state_known = False
        self.credentials_readable = False
        self.prior_state_safe = False
        self.password_saved = False
        self.totp_saved = False
        self.must_verify_existing = False
        self.failure_kind = ""
        self.retry_blocker = ""
        self.unsubmitted_candidate = False
        self.known_secrets: tuple[str, ...] = ()

    def remember_secrets(self, *values: str) -> None:
        self.known_secrets = tuple(dict.fromkeys((*self.known_secrets, *(str(v) for v in values if v))))

    def capture_initial_state(self, status: dict[str, Any], *, password_saved: bool,
                              totp_saved: bool, must_verify_first: bool) -> None:
        self.initial_state_known = True
        self.credentials_readable = status.get("credentials_readable") is True
        self.password_saved = password_saved
        self.totp_saved = totp_saved
        self.must_verify_existing = must_verify_first
        password_state = str(status.get("password_state") or "")
        mfa_state = str(status.get("mfa_state") or "")
        self.prior_state_safe = bool(
            status.get("credentials_readable") is True
            and not status.get("has_totp")
            and mfa_state in {"not_configured", "disabled"}
            and ((not status.get("has_password") and password_state == "not_configured")
                 or (status.get("has_password") is True and password_state == "configured"))
        )

    def task_retry(self, result: Any) -> dict[str, str]:
        from services.chatgpt_security_progress import TASK_RETRY_TRANSIENT_REASONS

        def manual(code: str) -> dict[str, str]:
            return {"strategy": "manual", "reason_code": code}

        if self.retry_blocker:
            return manual(self.retry_blocker)
        if not self.initial_state_known:
            return manual("insufficient_evidence")
        if self.failure_kind not in TASK_RETRY_TRANSIENT_REASONS:
            return manual("unknown_failure")
        # A retry must still possess the exact durable credential and enter an
        # existing verification-only branch before any reset/enrollment action.
        password_recheck = bool(
            self.password_saved and result.has_password
            and result.password_state in {"unknown", "pending"}
            and (self.must_verify_existing or self.submission_started)
            and (result.mfa_state not in {"pending", "enabled", "unmanaged"}
                 or (self.totp_saved and result.has_totp))
        )
        totp_recheck = bool(
            self.password_saved and self.totp_saved and result.has_password and result.has_totp
            and result.mfa_state == "pending"
            and result.password_state in {"configured", "unknown", "pending"}
        )
        # Admission only permits the existing read-only remote-state gate.
        # It must prove the same account and disabled Authenticator before any
        # new enrollment; an enabled/unknown row without a seed still stops.
        pending_totp_inspection = bool(
            self.credentials_readable and self.password_saved and result.has_password
            and result.password_state == "configured" and result.mfa_state == "pending"
            and not self.totp_saved and not result.has_totp and not self.totp_submission_started
        )
        # A password mutation earlier in this invocation is no longer unknown
        # after independent exact-account login proved it. Preserve the audit
        # marker, but do not let it turn an unopened MFA settings panel into an
        # uncertain enrollment. No activation/submission may have started.
        confirmed_password_settings_retry = bool(
            self.credentials_readable and self.password_saved and result.has_password
            and result.password_state == "configured"
            and result.mfa_state in {"disabled", "not_configured"}
            and self.value.get("stage") == "totp_settings"
            and "password_verify" in self.value.get("completed_stages", [])
            and not self.totp_saved and not result.has_totp
            and not self.totp_activation_started and not self.totp_submission_started
        )
        if password_recheck or totp_recheck or pending_totp_inspection or confirmed_password_settings_retry:
            return {"strategy": "verify_existing", "reason_code": self.failure_kind}
        if self.submission_started or self.totp_activation_started or self.totp_submission_started:
            return manual("remote_change_unverified")
        if not self.prior_state_safe and not self.unsubmitted_candidate:
            return manual("untracked_prior_state")
        return {"strategy": "safe_resume", "reason_code": self.failure_kind}

    def emit(self, stage: str | None = None, *, status: str = "running",
             code: str = "", reason: str = "", retry_mode: str = "none",
             retry_attempt: int = 0, retry_limit: int = 0) -> None:
        from services.chatgpt_security_progress import normalize_security_progress

        stage = stage or self.value.get("stage") or "session_check"
        if status in {"running", "completed"}:
            self.failure_kind = ""
        completed = list(self.value.get("completed_stages") or [])
        if status == "completed" and stage not in completed:
            completed.append(stage)
        value = normalize_security_progress({
            "stage": stage, "status": status, "code": code or stage,
            "reason": _safe_error(reason, 1000, known_secrets=self.known_secrets), "retry_mode": retry_mode,
            "retry_attempt": retry_attempt, "retry_limit": retry_limit,
            "completed_stages": completed,
        })
        if value is None:
            return
        self.value = value
        if callable(self.callback):
            try:
                self.callback({**value, "completed_stages": list(value["completed_stages"])})
            except Exception:
                # Observers cannot alter authentication or cancel cleanup.
                pass

    def finish(self, result: Any) -> None:
        if result.ok:
            self.emit("done", status="completed", code="security_complete",
                      reason="安全设置已完成并确认")
        elif self.value.get("status") not in {"failed", "review"}:
            stage = self.value.get("stage", "session_check")
            uncertain = ((stage in {"password_submit", "password_verify"}
                          and result.password_state in {"pending", "unknown"})
                         or (stage in {"totp_settings", "totp_verify"}
                             and result.mfa_state == "pending"))
            self.emit(stage, status="review" if uncertain else "failed",
                      code="password_verification_required" if uncertain and stage.startswith("password") else "security_failed",
                      reason=_safe_error(result.error, 1000, known_secrets=self.known_secrets) or (
                          ("远端结果未确认；保留现有凭据，下次只核对当前会话，不自动重设密码或重绑 2FA"
                           if self.confirmation_mode == "in_session" else
                           "远端结果未确认；再次操作须先独立验证，不自动重设密码或重绑 2FA")
                          if uncertain else "该安全设置子步骤未完成，未返回具体原因"),
                      retry_mode="verify_first" if uncertain else "manual")
        result.security_progress = self.snapshot()
        if not result.ok:
            # Only the canonical workflow's final result grants permission.
            # A streamed substep failure is not a completed security task.
            self.value["task_retry"] = self.task_retry(result)
            result.security_progress = self.snapshot()
            if callable(self.callback):
                try:
                    self.callback(self.snapshot())
                except Exception:
                    pass

    def snapshot(self) -> dict[str, Any]:
        result = {**self.value, "completed_stages": list(self.value.get("completed_stages") or [])}
        if "task_retry" in result:
            result["task_retry"] = dict(result["task_retry"])
        return result


def _emit_security_progress(stage: str | None = None, **values: Any) -> None:
    tracker = _SECURITY_PROGRESS.get()
    if tracker is not None:
        tracker.emit(stage, **values)


def _security_progress_snapshot() -> dict[str, Any]:
    tracker = _SECURITY_PROGRESS.get()
    return tracker.snapshot() if tracker is not None else {}


def _mark_password_submission() -> None:
    """Persist uncertainty *before* the remote mutation, including crash windows."""
    tracker = _SECURITY_PROGRESS.get()
    if tracker is None:
        return
    from services.chatgpt_security_store import update_chatgpt_security_state

    in_session = tracker.confirmation_mode == "in_session"
    update_chatgpt_security_state(
        tracker.email, password_state="pending" if in_session else "unknown",
        last_error=("密码提交即将发出，结果尚未确认；保留原密码，下次先核对当前会话"
                    if in_session else "密码提交即将发出，结果尚未确认；再次操作必须先干净登录验证"),
    )
    tracker.submission_started = True
    tracker.emit("password_submit", reason=("正在提交新密码并等待当前页面确认"
                 if in_session else "正在提交新密码；提交结果须用全新浏览器验证"),
                 retry_mode="verify_first")


def _mark_totp_activation() -> None:
    """Close the pre-seed crash window before even attempting the enable click."""
    tracker = _SECURITY_PROGRESS.get()
    if tracker is None:
        return
    from services.chatgpt_security_store import update_chatgpt_security_state

    update_chatgpt_security_state(
        tracker.email, mfa_state="pending",
        last_error="Authenticator 启用入口即将尝试，结果尚未确认；缺少原密钥时须先核对远端状态，不能直接重绑",
    )
    tracker.totp_activation_started = True


def _record_security_retry_failure(kind: str, page: Any = None) -> None:
    """Called only by explicit failed operations, never by log/error matching."""
    tracker = _SECURITY_PROGRESS.get()
    if tracker is None:
        return
    if kind in {"credentials_missing", "identity_mismatch", "auth_rejected", "configuration_required", "insufficient_evidence"}:
        tracker.retry_blocker = kind
        tracker.failure_kind = ""
        return
    if page is not None:
        # Page text may only veto an otherwise explicit transient diagnosis.
        # It can never grant permission, and is never retained or logged.
        try:
            if not _trusted_openai_action_url(str(page.url or "")):
                tracker.failure_kind = ""
                return
            text = _visible_text(page, 8000).lower()
            if re.search(r"incorrect password|invalid password|wrong password|密码错误|密码不正确|密码无效|account_deactivated|account_deleted|account.{0,30}(?:suspended|deactivated)|access denied|forbidden|\b(?:401|403)\b", text):
                tracker.retry_blocker = "auth_rejected"
                tracker.failure_kind = ""
                return
        except Exception:
            tracker.failure_kind = ""
            return
    tracker.failure_kind = kind


def _record_security_network_failure(exc: Exception, page: Any = None) -> None:
    """Use known exception types, not words such as 'timeout' in raw errors."""
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and not isinstance(status, bool) and status in {401, 403}:
        _record_security_retry_failure("auth_rejected")
        return
    # Text is allowed only to veto, never to turn an unknown exception into a
    # retryable one. Some transports omit a structured response on HTTP errors.
    if re.search(r"\b(?:401|403)\b|incorrect password|invalid password|wrong password|密码错误|密码不正确|account_deactivated|account_deleted", str(exc), re.I):
        _record_security_retry_failure("auth_rejected")
        return
    classes = {(cls.__module__, cls.__name__) for cls in type(exc).__mro__}
    known_network = bool(classes & {
        ("builtins", "TimeoutError"), ("builtins", "ConnectionError"),
        ("requests.exceptions", "Timeout"), ("requests.exceptions", "ConnectionError"),
        ("httpx", "TimeoutException"), ("httpx", "NetworkError"),
    })
    if known_network:
        _record_security_retry_failure("network_temporary", page)


def _security_workflow_lock(email: str) -> threading.RLock:
    normalized = _normalise_email(email)
    return _SECURITY_LOCK_STRIPES[hash(normalized) % len(_SECURITY_LOCK_STRIPES)]


def _safe_error(
    value: object,
    limit: int = 300,
    *,
    known_secrets: tuple[str, ...] = (),
) -> str:
    """Keep a useful error without accidentally persisting a credential."""
    text = str(value or "").strip()
    for secret in sorted(
        (str(item) for item in known_secrets if str(item or "")),
        key=len,
        reverse=True,
    ):
        text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"otpauth://\S+", "[TOTP URI 已隐藏]", text, flags=re.I)
    text = re.sub(r"(?i)(secret|password|totp|code)\s*[:=]\s*\S+", r"\1=[已隐藏]", text)
    text = re.sub(
        r"(?i)\b(https?://)([^\s/@:]+):([^\s/@]+)@",
        r"\1[认证信息已隐藏]@",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+", "Bearer [已隐藏]", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "[令牌已隐藏]",
        text,
    )
    return text[:limit]


def _log_safely(log: Callable[[str], None], message: str) -> None:
    try:
        log(_safe_error(message, 600))
    except Exception:
        pass


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalise_email(value: object) -> str:
    return str(value or "").strip().lower()


def _parse_cookie_payload(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            str(k): str(v)
            for k, v in value.items()
            if str(k).strip() and v is not None and str(v)
        }
    raw = str(value or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return _parse_cookie_payload(parsed)
    except Exception:
        pass
    cookies: dict[str, str] = {}
    for piece in raw.split(";"):
        if "=" not in piece:
            continue
        name, val = piece.split("=", 1)
        name = name.strip()
        if name:
            cookies[name] = val.strip()
    return cookies


def _session_cookie_from_map(cookies: dict[str, str]) -> str:
    """Return a complete NextAuth/Auth.js token, including chunked cookies."""
    for base in _SESSION_COOKIE_BASES:
        direct = str(cookies.get(base) or "")
        if direct:
            return direct
        chunks: list[tuple[int, str]] = []
        prefix = f"{base}."
        for name, value in cookies.items():
            suffix = str(name).removeprefix(prefix)
            if str(name).startswith(prefix) and suffix.isdigit() and str(value or ""):
                chunks.append((int(suffix), str(value)))
        if chunks:
            chunks.sort(key=lambda item: item[0])
            # Require a contiguous sequence; a partial JWT/JWE is not usable
            # and must never be persisted as a complete session token.
            if [index for index, _ in chunks] == list(range(len(chunks))):
                return "".join(value for _, value in chunks)
    return ""


def _has_session_cookie(cookies: dict[str, str]) -> bool:
    return bool(_session_cookie_from_map(cookies))


def _collect_page_cookies(page: Any) -> dict[str, str]:
    try:
        values = page.cookies() or []
    except Exception:
        return {}
    if isinstance(values, dict):
        return _parse_cookie_payload(values)
    if not isinstance(values, (list, tuple)):
        return {}
    output: dict[str, str] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        if name and value:
            output[name] = value
    return output


def _inject_cookies(page: Any, cookies: dict[str, str]) -> int:
    injected = 0
    for name, value in cookies.items():
        if not name or not value:
            continue
        cookie: dict[str, Any] = {
            "name": name,
            "value": value,
            "path": "/",
            "secure": True,
        }
        if name.startswith("__Host-"):
            # A __Host- cookie is invalid when a Domain attribute is present.
            # Omitting Domain lets Chromium bind it to the currently-open
            # chatgpt.com host.  ``hostOnly`` is a cookie response property,
            # not a valid Network.setCookie input.
            pass
        else:
            cookie["domain"] = "chatgpt.com"
        try:
            page.set.cookies(cookie)
            injected += 1
        except Exception:
            continue
    return injected


def _auth_login_page_error(page: Any) -> str:
    """Read fixed error categories, never page text, request IDs or credentials.

    HTTP failures and an absent session are not account-deactivation proof.
    Only a visible error on the exact authentication origin can supply it.
    """
    try:
        value = page.run_js(
            r"""
            const url = new URL(String(location.href || ''));
            if (url.protocol !== 'https:' || url.hostname !== 'auth.openai.com' ||
                (url.port && url.port !== '443')) return '';
            const visible = el => {
              if (!el) return false;
              const rect = el.getBoundingClientRect();
              const style = getComputedStyle(el);
              return rect.width > 0 && rect.height > 0 &&
                style.display !== 'none' && style.visibility !== 'hidden';
            };
            const body = document.body;
            if (!body || !visible(body)) return 'unreadable';
            const text = String(body.innerText || '').slice(0, 16000);
            const headings = [...document.querySelectorAll('h1,h2,[role="heading"]')]
              .filter(visible).map(el => String(el.innerText || '').trim());
            const alerts = [...document.querySelectorAll(
              '[role="alert"],.error,[data-testid*="error" i]'
            )].filter(visible).map(el => String(el.innerText || '')).join(' ');
            const errorHeading = headings.some(value =>
              /^(?:authentication error|authentication failed|identity verification error|error|身份验证错误|身份驗證錯誤|认证错误|認證錯誤)$/i.test(value));
            // Do not mistake an email address or a longer identifier for an
            // error code, even on a genuine authentication-error page.
            const deactivated = /(?:^|\s|[(\[（:：])(?:account_deactivated|account_deleted|access_deactivated)(?=$|\s|[)\]）])/i;
            if (deactivated.test(text) && (errorHeading || deactivated.test(alerts) ||
                /(?:error\s*code|错误代码|錯誤代碼)\s*[:：]\s*(?:account_deactivated|account_deleted|access_deactivated)(?=$|\s|[)\]）])/i.test(text))) {
              return 'account_deactivated';
            }
            if (errorHeading || /invalid|incorrect|expired|rejected|failed|error|无效|错误|过期|不正确|拒绝|失败/i.test(alerts)) {
              return 'authentication_error';
            }
            return '';
            """,
            timeout=3,
        )
        return value if isinstance(value, str) and value in {
            "", "account_deactivated", "authentication_error", "unreadable"
        } else "unreadable"
    except Exception:
        # A failed DOM read cannot prove either deactivation or MFA success.
        return "unreadable"


def _raise_for_auth_login_page_error(page: Any) -> bool:
    """Raise a fixed safe error, or say whether the page was readable."""
    error = _auth_login_page_error(page)
    if error == "account_deactivated":
        raise AccountDeactivatedLoginError()
    if error == "authentication_error":
        raise RuntimeError(_AUTHENTICATION_PAGE_ERROR)
    return error != "unreadable"


def _session_identity(page: Any) -> dict:
    try:
        result = page.run_js(
            """
            return (async () => {
              try {
                if (location.protocol !== 'https:' || location.hostname !== 'chatgpt.com' ||
                    (location.port && location.port !== '443')) {
                  return {ok:false, authenticated:false, origin_untrusted:true};
                }
                const response = await fetch('/api/auth/session', {
                  credentials: 'include', cache: 'no-store'
                });
                let body = null;
                try { body = await response.json(); } catch (_) {}
                const accessToken = String(body?.accessToken || '');
                const accountId = String(body?.account?.id || '');
                let backendOk = false;
                let backendStatus = 0;
                let backendReadError = false;
                let backendReadRetryable = false;
                if (response.ok && accessToken) {
                  const headers = {Authorization: `Bearer ${accessToken}`};
                  if (accountId) headers['chatgpt-account-id'] = accountId;
                  try {
                    const backend = await fetch(
                      '/backend-api/accounts/check/v4-2023-04-27',
                      {credentials: 'include', cache: 'no-store', headers}
                    );
                    backendStatus = Number(backend.status || 0);
                    backendOk = backend.ok;
                  } catch (error) {
                    backendReadError = true;
                    backendReadRetryable = ['AbortError', 'TimeoutError', 'TypeError']
                      .includes(String(error?.name || ''));
                  }
                }
                return {
                  ok: response.ok,
                  status: response.status,
                  email: body?.user?.email || '',
                  account_id: accountId,
                  has_access_token: Boolean(accessToken),
                  backend_status: backendStatus,
                  ...(backendReadError ? {error:'protected session read failed',
                    read_retryable:backendReadRetryable} : {}),
                  // /api/auth/session can retain a revoked access token.  A
                  // protected backend request is the durable proof that the
                  // browser can still perform account-security mutations.
                  authenticated: Boolean(accessToken) && backendOk,
                };
              } catch (error) {
                return {ok: false, error: String(error), read_retryable:
                  ['AbortError', 'TimeoutError', 'TypeError'].includes(String(error?.name || ''))};
              }
            })();
            """
        )
        return result if isinstance(result, dict) else {
            "ok": False, "error": "会话读取未返回可核验结果", "read_retryable": False,
        }
    except Exception as exc:
        classes = {(cls.__module__, cls.__name__) for cls in type(exc).__mro__}
        retryable = isinstance(exc, (TimeoutError, ConnectionError)) or any(
            module.startswith("DrissionPage") and name in {
                "ContextLostError", "PageDisconnectedError", "WaitTimeoutError", "BrowserConnectError",
            } for module, name in classes)
        return {"ok": False, "error": _safe_error(exc), "read_retryable": retryable}


def _session_probe_transient(identity: dict) -> bool:
    """Transport failure is not evidence that an existing session expired."""
    if identity.get("origin_untrusted") is True:
        return False
    if identity.get("authenticated") is True:
        return not _normalise_email(identity.get("email"))
    statuses = (identity.get("status"), identity.get("backend_status"))
    if any(type(status) is int and (status in {408, 429} or 500 <= status <= 599) for status in statuses):
        return True
    return bool(identity.get("error") or identity.get("status") == 0
                or (identity.get("has_access_token") is True and identity.get("backend_status", 0) == 0))


def _session_identity_with_retry(page: Any, log: Callable[[str], None]) -> dict:
    """At most three reads in the same browser; never log in or clear cookies."""
    for attempt in range(3):
        identity = _session_identity(page)
        if not _session_probe_transient(identity):
            return identity
        if attempt < 2:
            reason = f"登录会话读取暂未确认，保留当前浏览器只读重核（第 {attempt + 1}/2 次）"
            _emit_security_progress(status="retrying", code="session_read_retry", reason=reason,
                                    retry_mode="auto_local", retry_attempt=attempt + 1, retry_limit=2)
            _log_safely(log, "[账号安全] " + reason)
            time.sleep(0.75 * (attempt + 1))
    missing_identity = identity.get("authenticated") is True and not _normalise_email(identity.get("email"))
    unknown_read_error = bool(identity.get("error") and identity.get("read_retryable") is not True)
    _record_security_retry_failure("insufficient_evidence" if missing_identity or unknown_read_error else "network_temporary")
    reason = ("登录会话仍缺少可核验的账号邮箱，已完成两次只读重核；未继续修改账号安全设置" if missing_identity
              else "登录会话读取异常原因尚未确认，已完成两次只读重核；未继续修改账号安全设置" if unknown_read_error
              else "登录会话读取暂未确认，已完成两次只读重核；保留当前凭据，稍后重试")
    _emit_security_progress(status="failed", code="session_read_failed", reason=reason, retry_mode="verify_first")
    return identity


def _unsubmitted_password_candidate(status: dict, *, verified_evidence=None, email: str = "") -> bool:
    """Recognize our pre-submit handoff; legacy ambiguous pending rows still verify."""
    error = str(status.get("last_error") or "")
    verified = False
    if type(verified_evidence) is VerifiedUnsubmittedPasswordEvidence:
        fields = {"updated_at": verified_evidence.security_updated_at,
                  "password_updated_at": verified_evidence.password_updated_at,
                  "mfa_updated_at": verified_evidence.mfa_updated_at}
        verified = bool(_normalise_email(email) and _normalise_email(email) == verified_evidence.email
                        and all(type(value) is str and value == status.get(key) for key, value in fields.items()))
        try:
            for key, value in fields.items():
                # A never-started MFA row has an exact empty timestamp.
                if key == "mfa_updated_at" and value == "":
                    continue
                stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    verified = False
        except (ValueError, TypeError, AttributeError):
            verified = False
    return bool(status.get("credentials_readable") is True and status.get("has_password") is True
                and status.get("password_state") == "pending"
                and status.get("mfa_state") in {"not_configured", "disabled"}
                and status.get("has_totp") is False and status.get("has_recovery_codes") is False
                and (verified if verified_evidence is not None else (
                    error in _UNSUBMITTED_PASSWORD_ERRORS or error.startswith(_UNSUBMITTED_PASSWORD_PREFIX)))
                and not any(marker in error for marker in ("密码已提交", "密码提交")))


def _visible_text(page: Any, limit: int = 8000) -> str:
    try:
        text = page.run_js(
            "return (document.body && document.body.innerText || '').slice(0, arguments[0]);",
            int(limit),
        )
        return str(text or "")
    except Exception:
        return ""


def _click_text(page: Any, terms: tuple[str, ...], *, dialog_only: bool = False) -> bool:
    """Click a visible semantic control; exact text wins over substring."""
    try:
        return bool(
            page.run_js(
                """
                const options = arguments[0] || {};
                const terms = (options.terms || []).map(
                  x => String(x).trim().toLowerCase()
                );
                const dialogOnly = Boolean(options.dialogOnly);
                const visibleDialogs = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
                      const s = getComputedStyle(el);
                      const r = el.getBoundingClientRect();
                      return r.width > 0 && r.height > 0 &&
                        s.display !== 'none' && s.visibility !== 'hidden';
                    });
                // Nested enrollment dialogs are appended after the Settings
                // shell.  Operate on the top-most visible dialog.
                const root = dialogOnly
                  ? visibleDialogs[visibleDialogs.length - 1]
                  : document;
                if (!root) return false;
                const visible = (el) => {
                  const r = el.getBoundingClientRect();
                  const s = getComputedStyle(el);
                  return r.width > 0 && r.height > 0 && s.display !== 'none' &&
                    s.visibility !== 'hidden' && !el.disabled;
                };
                const candidates = [...root.querySelectorAll(
                  'button,[role="button"],[role="tab"],[role="menuitem"],a'
                )].filter(visible);
                const label = (el) => String(
                  el.innerText || el.textContent || el.getAttribute('aria-label') ||
                  el.getAttribute('title') || ''
                ).trim().toLowerCase();
                for (const exact of [true, false]) {
                  for (const el of candidates) {
                    const text = label(el);
                    if (!text) continue;
                    const hit = terms.some(term => exact ? text === term : text.includes(term));
                    if (hit) { el.click(); return true; }
                  }
                }
                return false;
                """,
                {
                    "terms": list(terms),
                    "dialogOnly": bool(dialog_only),
                },
            )
        )
    except Exception:
        return False


def _open_settings_shell(page: Any) -> bool:
    """Open Settings using the profile menu when a hash route did not do it."""
    try:
        clicked = bool(
            page.run_js(
                """
                const visible = (el) => {
                  const r = el.getBoundingClientRect();
                  return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
                };
                const selectors = [
                  '[data-testid*="profile-button" i]',
                  '[data-testid*="account-menu" i]',
                  'button[aria-label*="profile" i]',
                  'button[aria-label*="account" i]',
                  'button[aria-label*="个人" i]',
                  'button[aria-label*="账户" i]'
                ];
                for (const selector of selectors) {
                  const el = [...document.querySelectorAll(selector)].find(visible);
                  if (el) { el.click(); return true; }
                }
                return false;
                """
            )
        )
    except Exception:
        clicked = False
    if not clicked:
        return False
    time.sleep(0.8)
    if not _click_text(page, ("settings", "设置", "preferences", "偏好设置")):
        return False
    time.sleep(1.2)
    return True


def _section_is_visible(page: Any, section: str) -> bool:
    text = _visible_text(page, 10000).lower()
    if section == "security":
        if any(term in text for term in _MFA_TERMS) or "passkey" in text or "通行密钥" in text:
            return True

        # Password setup now lives in the Security panel.  Accounts that have
        # not established a password yet can render the panel's title and
        # password row before (or, for some account variants, without) the MFA
        # row.  Treat that combination as positive proof that the requested
        # panel is open instead of reporting a false navigation failure.
        security_titles = (
            "account security and login",
            "security and login",
            "账户安全与登录",
            "帳戶安全與登入",
        )
        password_rows = (
            "add or update password",
            "add password",
            "update password",
            "password 添加",
            "password add",
            "密码 添加",
            "密碼 新增",
            "添加密码",
            "更新密码",
            "新增密碼",
            "更新密碼",
        )
        return any(term in text for term in security_titles) and any(
            term in text for term in password_rows
        )
    return any(
        term in text
        for term in (
            "add or update password",
            "add password",
            "update password",
            "添加或更新密码",
            "添加密码",
            "更新密码",
        )
    )


def _wait_for_settings_section(
    page: Any,
    section: str,
    *,
    timeout: float = _SETTINGS_SECTION_TIMEOUT_SECONDS,
) -> bool:
    """Wait for the lazy Settings panel instead of sampling it once.

    The current ChatGPT shell opens the settings dialog before its Security
    content is rendered.  On proxied BUSINESS children that gap is commonly
    several seconds, so a fixed 1-2 second sleep produces a false navigation
    failure even though the authenticated page finishes loading normally.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        _raise_for_auth_login_page_error(page)
        if _section_is_visible(page, section):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.35)


def _open_settings_section(page: Any, section: str) -> bool:
    section = "security" if section == "security" else "account"
    # A retry may already be on the loaded panel; do not navigate away from it.
    if _section_is_visible(page, section):
        return True
    for attempt, url in enumerate(_SETTINGS_URLS[section]):
        if attempt:
            _emit_security_progress(status="retrying", code="password_settings_retry",
                                    reason="设置面板尚未加载，正在重新核对设置入口；未提交密码或启用 2FA",
                                    retry_mode="auto_local", retry_attempt=attempt, retry_limit=2)
        try:
            page.get(url, timeout=30)
        except Exception as exc:
            _record_security_network_failure(exc)
            if _section_is_visible(page, section):
                return True
            continue
        if _wait_for_settings_section(page, section):
            return True
        terms = ("security", "安全") if section == "security" else ("account", "账户", "账号")
        if _click_text(page, terms, dialog_only=True):
            if _wait_for_settings_section(page, section):
                return True

    try:
        page.get(CHATGPT_HOME, timeout=30)
        time.sleep(1.5)
    except Exception as exc:
        _record_security_network_failure(exc)
        return False
    if not _open_settings_shell(page):
        return False
    terms = ("security", "安全") if section == "security" else ("account", "账户", "账号")
    _click_text(page, terms, dialog_only=True)
    return _wait_for_settings_section(page, section)


def _click_password_setting(page: Any) -> bool:
    """Open the password row in both the current Security UI and old UI."""
    try:
        clicked = page.run_js(
            r"""
            return (() => {
              const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0 &&
                  style.display !== 'none' && style.visibility !== 'hidden';
              });
              const root = dialogs[dialogs.length - 1] || document;
              const visible = (el) => {
                if (!el || el.disabled) return false;
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0 &&
                  style.display !== 'none' && style.visibility !== 'hidden';
              };
              const direct = root.querySelector('[data-testid="password-setting"]');
              if (visible(direct)) { direct.click(); return true; }
              const candidates = [...root.querySelectorAll(
                'button,[role="button"],a,div[tabindex="0"]'
              )].filter(visible);
              const norm = (value) => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
              const target = candidates.find(el => {
                const text = norm(el.innerText || el.textContent || el.getAttribute('aria-label'));
                return (text.includes('password') || text.includes('密码') || text.includes('密碼')) &&
                  (/\badd\b|\bupdate\b|添加|更新/.test(text));
              });
              if (!target) return false;
              target.click();
              return true;
            })();
            """
        )
        if clicked:
            return True
    except Exception:
        pass
    return _click_text(
        page,
        (
            "add or update password",
            "add password",
            "添加或更新密码",
            "添加密码",
        ),
        dialog_only=True,
    ) or _click_text(
        page,
        (
            "add or update password",
            "add password",
            "添加或更新密码",
            "添加密码",
        ),
    )


def _inspect_mfa_row(
    page: Any, *, click_enable: bool = False, authenticator_only: bool = False
) -> str:
    """Return enabled/disabled/clicked/unknown without exposing page text."""
    try:
        value = page.run_js(
            r"""
            const options = arguments[0] || {};
            const clickEnable = Boolean(options.clickEnable);
            const authenticatorOnly = Boolean(options.authenticatorOnly);
            const mfaTerms = options.terms || [];
            const norm = (v) => String(v || '').replace(/\s+/g, ' ').trim().toLowerCase();
            const visible = (el) => {
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              if (!(r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden')) return false;
              if (authenticatorOnly) {
                for (let node = el; node && node.nodeType !== 9; node = node.parentElement) {
                  const style = getComputedStyle(node);
                  if (node.hidden || node.getAttribute('aria-hidden') === 'true' ||
                      style.display === 'none' || style.visibility === 'hidden') return false;
                }
              }
              return true;
            };
            const scopeDialogs = [...document.querySelectorAll('[role="dialog"]')].filter(visible);
            const scope = scopeDialogs[scopeDialogs.length - 1] || document;
            // Current Security has two independent switches.  Select the
            // Authenticator control explicitly so SMS can never be enabled by
            // a broad MFA-row match.
            const directControls = [...scope.querySelectorAll(
              '[data-testid="mfa-authenticator-toggle"],button[role="switch"][aria-label*="authenticator" i],[role="switch"][aria-label*="authenticator" i]'
            )].filter(visible);
            if (authenticatorOnly && directControls.length > 1) return 'unknown';
            const direct = directControls[0];
            if (direct) {
              const checked = direct.getAttribute('aria-checked');
              if (authenticatorOnly && (direct.indeterminate === true ||
                  (checked !== null && !['true', 'false'].includes(checked)))) return 'unknown';
              if (authenticatorOnly && ['true', 'false'].includes(checked) &&
                  typeof direct.checked === 'boolean' && direct.checked !== (checked === 'true')) return 'unknown';
              if (checked === 'true' || direct.checked === true) return 'enabled';
              if (checked === 'false' || direct.checked === false) {
                if (clickEnable) {
                  if (direct.disabled || direct.getAttribute('aria-disabled') === 'true') return 'unknown';
                  direct.click(); return 'clicked';
                }
                return 'disabled';
              }
              if (authenticatorOnly) return 'unknown';
            }
            if (authenticatorOnly) {
              // Recovery without the original seed must never infer the
              // Authenticator state from a generic MFA panel or its SMS switch.
              const isAuthenticator = value => /authenticator|authentication app|身份验证器|身分驗證器|验证器应用|驗證器應用/.test(norm(value));
              const hasOtherFactor = value => /\bsms\b|text message|phone number|passkey|短信|簡訊|手机号|手機號|通行密钥|通行金鑰/.test(norm(value));
              const labels = [...scope.querySelectorAll('div,section,li,tr,span,p,label')]
                .filter(visible)
                .filter(el => isAuthenticator(el.innerText) && norm(el.innerText).length < 600)
                .sort((a, b) => norm(a.innerText).length - norm(b.innerText).length);
              const rows = [];
              for (const label of labels) {
                let row = label;
                for (let depth = 0; row && row !== scope && depth < 5; depth += 1, row = row.parentElement) {
                  if (!visible(row) || norm(row.innerText).length >= 600 || hasOtherFactor(row.innerText)) break;
                  const controls = [...row.querySelectorAll('button,[role="button"],[role="switch"],input[type="checkbox"]')].filter(visible);
                  if (!controls.length) continue;
                  // More than one control cannot safely be attributed to this label.
                  if (controls.length !== 1) break;
                  if (!rows.some(item => item.control === controls[0])) rows.push({row, control: controls[0]});
                  break;
                }
              }
              if (rows.length !== 1) return 'unknown';
              const {control} = rows[0];
              const checked = control.getAttribute('aria-checked');
              if (control.indeterminate === true ||
                  (checked !== null && !['true', 'false'].includes(checked))) return 'unknown';
              if (['true', 'false'].includes(checked) && typeof control.checked === 'boolean' &&
                  control.checked !== (checked === 'true')) return 'unknown';
              let state = 'unknown';
              if (checked === 'true' || control.checked === true) state = 'enabled';
              else if (checked === 'false' || control.checked === false) state = 'disabled';
              else {
                const label = norm(control.innerText || control.getAttribute('aria-label') || control.title);
                if (/^(?:disable|turn off|remove|停用|关闭|移除)$/.test(label)) state = 'enabled';
                else if (/^(?:enable|turn on|set up|setup|启用|开启|设置)$/.test(label)) state = 'disabled';
              }
              if (state === 'disabled' && clickEnable) {
                if (control.disabled || control.getAttribute('aria-disabled') === 'true') return 'unknown';
                control.click(); return 'clicked';
              }
              return state;
            }
            const nodes = [...scope.querySelectorAll('div,section,li,tr')]
              .filter(visible)
              .map(el => ({el, text: norm(el.innerText)}))
              .filter(x => x.text.length < 1200 && mfaTerms.some(t => x.text.includes(t)))
              .sort((a, b) => a.text.length - b.text.length);
            if (!nodes.length) return 'unknown';
            let row = nodes[0].el;
            // The shortest hit is often only the label.  Climb to the
            // smallest visible ancestor that also owns the action/status.
            for (let depth = 0; row && row !== scope && depth < 7; depth += 1) {
              const hasControl = Boolean(row.querySelector(
                'button,[role="button"],[role="switch"],input[type="checkbox"]'
              ));
              const statusText = norm(row.innerText);
              if (hasControl || /\benabled\b|not enabled|disabled|已启用|未启用|已关闭/.test(statusText)) {
                break;
              }
              row = row.parentElement;
            }
            if (!row) return 'unknown';
            const buttons = [...row.querySelectorAll('button,[role="button"]')].filter(visible);
            const switches = [...row.querySelectorAll('[role="switch"],input[type="checkbox"]')]
              .filter(visible);
            for (const control of switches) {
              const checked = control.getAttribute('aria-checked');
              if (checked === 'true' || control.checked === true) return 'enabled';
              if (checked === 'false' || control.checked === false) {
                if (clickEnable) { control.click(); return 'clicked'; }
                return 'disabled';
              }
            }
            for (const button of buttons) {
              const text = norm(button.innerText || button.getAttribute('aria-label') || button.title);
              if (/disable|turn off|remove|停用|关闭|移除/.test(text)) return 'enabled';
            }
            const rowText = norm(row.innerText);
            if (/\benabled\b|已启用|开启中/.test(rowText) && !/not enabled|未启用/.test(rowText)) {
              return 'enabled';
            }
            for (const button of buttons) {
              const text = norm(button.innerText || button.getAttribute('aria-label') || button.title);
              if (/enable|turn on|set up|setup|启用|开启|设置/.test(text)) {
                if (clickEnable) { button.click(); return 'clicked'; }
                return 'disabled';
              }
            }
            return /not enabled|disabled|未启用|已关闭/.test(rowText) ? 'disabled' : 'unknown';
            """,
            {
                "clickEnable": bool(click_enable),
                "authenticatorOnly": bool(authenticator_only),
                "terms": list(_MFA_TERMS),
            },
        )
        return str(value or "unknown")
    except Exception:
        return "unknown"


def _choose_authenticator(page: Any, *, verify_identity: Optional[Callable[[], bool]] = None) -> bool:
    deadline = time.monotonic() + 20.0
    while True:
        challenge = _totp_setup_identity_probe(page) if callable(verify_identity) else {}
        if challenge.get("kind") in {"identity_mismatch", "untrusted", "email", "password", "authenticator"}:
            # A recognized challenge has priority over stale settings or
            # chooser controls. The callback rechecks the expected identity.
            return verify_identity()
        state = (_totp_enrollment_probe(page, action="choose")
                 if not callable(verify_identity) or challenge else {})
        if state.get("enrollment_visible") or state.get("authenticator_clicked"):
            # A successful choice hands off immediately to the enrollment
            # wait; this loop never clicks that option a second time.
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.4, remaining))


_TOTP_SETUP_IDENTITY_JS = r"""
const options = arguments[0] || {};
const expected = String(options.email || '').trim().toLowerCase();
const state = {kind:'unknown', password_switch_clicked:false, workspace_clicked:false};
const url = new URL(location.href);
if (url.protocol !== 'https:' || !['auth.openai.com','chatgpt.com'].includes(url.hostname) ||
    (url.port && url.port !== '443') || url.username || url.password) {state.kind='untrusted'; return state;}
if (url.hostname !== 'auth.openai.com') return state;
const visible = el => {
  if (!el || !el.isConnected) return false;
  for (let node = el; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (node.hidden || node.hasAttribute('inert') || node.getAttribute('aria-hidden') === 'true' ||
        style.display === 'none' || /hidden|collapse/.test(style.visibility) || style.opacity === '0') return false;
  }
  const box = el.getBoundingClientRect(); return box.width > 0 && box.height > 0;
};
const fields = [...document.querySelectorAll('input')].filter(visible);
const namedEmails = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"]')]
  .map(el => String(el.value || '').trim().toLowerCase()).filter(value => value.includes('@'));
if (expected && namedEmails.some(value => value !== expected)) {state.kind='identity_mismatch'; return state;}
const route = url.pathname.replace(/\/+$/, '') || '/';
const hasCode = fields.some(el => el.getAttribute('autocomplete') === 'one-time-code' ||
  el.getAttribute('name') === 'code' || el.getAttribute('inputmode') === 'numeric');
if (['/email-verification','/log-in/code'].includes(route) && hasCode) state.kind='email';
else if (['/log-in/password','/password'].includes(route) &&
         fields.some(el => el.getAttribute('type') === 'password' && el.getAttribute('autocomplete') !== 'new-password')) state.kind='password';
else if (['/log-in/mfa','/log-in/totp','/mfa','/mfa/totp'].includes(route) && hasCode) state.kind='authenticator';
else if (route === '/workspace') state.kind='workspace';
if (state.kind === 'workspace' && options.action === 'select_workspace' && expected && options.account_id) {
  const accountId = String(options.account_id);
  const pending = window.__chatgptSecurityWorkspaceChoiceV1;
  if (pending) {state.workspace_clicked = pending.accountId === accountId; return state;}
  const choices = [...document.querySelectorAll('form button,form input[type="submit"],[role="button"]')]
    .filter(visible).filter(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true')
    .filter(el => {
      const ids = ['value','data-account-id','data-workspace-id'].map(attr => el.getAttribute(attr)).filter(Boolean);
      return ids.length > 0 && ids.every(id => id === accountId);
    });
  if (choices.length === 1) {
    window.__chatgptSecurityWorkspaceChoiceV1 = {accountId};
    choices[0].click(); state.workspace_clicked=true;
  }
}
if (state.kind === 'email' && options.action === 'switch_password' && expected) {
  const norm = value => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const choices = [...document.querySelectorAll('a,button,[role="button"]')].filter(visible)
    .filter(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true')
    .filter(el => /^(?:continue with password|use your password|use password|sign in with password|使用密码继续|使用密码|改用密码)$/.test(
      norm(el.innerText || el.getAttribute('aria-label'))))
    .filter(el => {
      const href = el.getAttribute('href'); if (!href) return el.tagName !== 'A';
      try {const next = new URL(href, url); return next.origin === url.origin &&
        ['/log-in/password','/password'].includes(next.pathname.replace(/\/+$/, ''));} catch (_) {return false;}
    });
  if (choices.length === 1) {choices[0].click(); state.password_switch_clicked=true;}
}
return state;
"""


def _totp_setup_identity_probe(page: Any, *, email: str = "", action: str = "inspect", account_id: str = "") -> dict[str, Any]:
    try:
        value = page.run_js(_TOTP_SETUP_IDENTITY_JS, {"email": email, "action": action, "account_id": account_id})
        return value if isinstance(value, dict) else {}
    except Exception:
        # Enable commonly navigates to auth.openai.com and briefly destroys the
        # old execution context. Wait for a readable state without echoing DOM.
        return {}


def _verify_totp_setup_identity(page: Any, *, email: str, password: str,
                                initiating_identity: dict[str, Any],
                                email_code_provider: Optional[Callable[..., str]] = None,
                                email_baseline_ready: bool = False,
                                log: Optional[Callable[[str], None]] = None) -> bool:
    """Complete the existing Enable flow's step-up challenge, never reset/login.

    A confirmed same-account session immediately before Enable is required.
    The only password action submits the already saved password; no navigation
    to a new login flow, password reset, repeated Enable, or MFA rebinding occurs.
    """
    from platforms.chatgpt.drission_rt_acquirer import _try_password_login

    def fail(reason: str, kind: str = "controls_unavailable") -> None:
        _record_security_retry_failure(kind)
        _emit_security_progress("totp_identity", status="review", code="totp_identity_verification_failed",
                                reason=reason, retry_mode="verify_first")
        raise RuntimeError(reason)

    if (not isinstance(initiating_identity, dict) or initiating_identity.get("authenticated") is not True
            or _normalise_email(initiating_identity.get("email")) != _normalise_email(email)):
        fail("2FA 启用前的目标账号身份未确认，未提交身份验证", "identity_mismatch")
    _emit_security_progress("totp_identity", code="totp_identity_verification_required",
                            reason="启用 2FA 前需要再次验证身份，正在使用原密码或本次新邮件验证码；不会重发启用或改密码")
    _log_safely(log, "[账号安全] Authenticator 启用已进入身份再验证，不是绑定入口缺失")
    deadline = time.monotonic() + 60.0
    switched = password_submitted = email_submitted = workspace_clicked = False
    def continue_workspace() -> bool:
        nonlocal workspace_clicked
        if workspace_clicked:
            return True
        original_account = str(initiating_identity.get("account_id") or "").strip()
        if not original_account:
            fail("身份验证需要选择工作空间，但启用前没有可精确匹配的工作空间身份，未盲选")
        selected = _totp_setup_identity_probe(page, email=email, action="select_workspace", account_id=original_account)
        if not selected.get("workspace_clicked"):
            return False
        workspace_clicked = True
        _log_safely(log, "[账号安全] 已选择启用前同一个工作空间，等待身份验证回跳；未切换其他工作空间")
        return True
    while time.monotonic() < deadline:
        state = _totp_setup_identity_probe(page, email=email)
        if not state:
            time.sleep(0.4)
            continue
        kind = state.get("kind")
        if kind == "identity_mismatch":
            fail("2FA 身份验证页面账号与目标账号不一致，已停止", "identity_mismatch")
        if kind == "untrusted":
            fail("2FA 身份验证页面已离开可信地址，未提交或读取凭据", "identity_mismatch")
        if kind == "authenticator":
            fail("2FA 启用前要求原 Authenticator 动态码，不能用新密钥猜测或重新绑定", "credentials_missing")
        if kind == "workspace":
            if not (password_submitted or email_submitted):
                fail("尚未确认本次身份验证凭据已提交，未操作工作空间选择")
            continue_workspace()
            time.sleep(0.4)
            continue
        try:
            if not _raise_for_auth_login_page_error(page):
                time.sleep(0.4)
                continue
        except AccountDeactivatedLoginError:
            _record_security_retry_failure("auth_rejected")
            _emit_security_progress("totp_identity", status="failed", code="account_deactivated",
                                    reason=ACCOUNT_DEACTIVATED_LOGIN_ERROR, retry_mode="none")
            raise
        except Exception as exc:
            if type(exc).__name__ in {"ContextLostError", "PageDisconnectedError", "ElementLostError"}:
                time.sleep(0.4)
                continue
            fail("2FA 身份验证页面报告错误，未再次提交凭据", "auth_rejected")
        if kind == "email" and password and not switched and not password_submitted and not email_submitted:
            choice = _totp_setup_identity_probe(page, email=email, action="switch_password")
            switched = bool(choice.get("password_switch_clicked"))
            if switched:
                _log_safely(log, "[账号安全] 已选择使用原密码完成 2FA 启用前身份验证")
                time.sleep(0.4)
                continue
        if kind == "password" and not password_submitted and not email_submitted:
            if not password:
                fail("2FA 身份验证要求原密码，但本地没有可读密码", "credentials_missing")
            diagnostic: dict[str, Any] = {}
            submitted = _try_password_login(page, password, lambda _message: None,
                                             diagnostic_fn=diagnostic.update)
            if not submitted or diagnostic.get("code") != "password_login_submitted":
                fail("2FA 身份验证的原密码提交未确认，未重复提交")
            password_submitted = True
            _log_safely(log, "[账号安全] 原密码已提交，等待身份验证实际通过；密码未修改")
        elif kind == "email" and not email_submitted and (not switched or password_submitted):
            if not callable(email_code_provider) or email_baseline_ready is not True:
                fail("2FA 身份验证要求邮箱验证码，但没有启用前的新邮件基线；未读取或重发验证码", "configuration_required")
            try:
                code = str(email_code_provider(email=email, timeout=120, prepare=False, exclude_codes=set()) or "").strip()
            except Exception:
                fail("2FA 身份验证的新邮件验证码暂不可用，未重复提交", "mail_wait_temporary")
            if not re.fullmatch(r"\d{6}", code):
                fail("2FA 身份验证未取得有效的新邮件验证码", "mail_wait_temporary")
            # Recheck the exact factor after the potentially slow mailbox read.
            if _totp_setup_identity_probe(page, email=email).get("kind") != "email":
                fail("等待邮件期间身份验证页面已变化，未向其他验证方式填写验证码")
            def email_challenge_active(current: Any) -> bool:
                read_deadline = time.monotonic() + 45.0
                while time.monotonic() < read_deadline:
                    current_state = _totp_setup_identity_probe(current, email=email)
                    current_kind = current_state.get("kind")
                    if current_kind in {"untrusted", "identity_mismatch"}:
                        fail("邮箱验证期间目标身份或可信地址发生变化，已停止", "identity_mismatch")
                    if current_kind == "authenticator":
                        fail("邮箱验证后要求原 Authenticator 动态码，未用新密钥或邮箱码继续", "credentials_missing")
                    if current_kind == "email":
                        return True
                    if current_kind == "workspace":
                        continue_workspace()
                        time.sleep(0.25)
                        continue
                    if current_state and _totp_enrollment_probe(current).get("enrollment_visible"):
                        return False
                    # A lost execution context or different factor is not a
                    # passed OTP. Never let the generic helper click while
                    # the page identity/factor cannot be read confidently.
                    time.sleep(0.25)
                fail("邮箱验证后的页面状态暂不可读，未将页面变化认定为验证成功")
            submitted, error_kind = _submit_password_verification_code(page, code,
                challenge_active=email_challenge_active)
            code = ""
            if not submitted:
                if error_kind in {"invalid", "expired", "rate_limited"}:
                    fail("2FA 身份验证的邮箱验证码被拒绝或已过期，未再次提交", "auth_rejected")
                fail("2FA 身份验证的邮箱验证码尚未通过，未再次提交")
            email_submitted = True
            deadline = time.monotonic() + 30.0
        # An action result or transient context loss cannot establish success.
        enrollment = _totp_enrollment_probe(page, action="choose")
        if enrollment.get("enrollment_visible") or enrollment.get("authenticator_clicked"):
            if not (password_submitted or email_submitted):
                fail("2FA 身份验证页面已变化，但本次没有已提交的验证凭据，未继续绑定")
            _emit_security_progress("totp_identity", status="completed", code="totp_identity_verified",
                                    reason="本次身份验证已提交并进入 Authenticator 设置界面；原密码保持不变")
            return True
        time.sleep(0.4)
    fail("2FA 启用前身份验证等待超时，尚未进入绑定界面；未再次启用或修改原密码")


# This script never returns page text, QR bytes or input contents other than
# provenance-approved enrollment candidates. Diagnostics strip candidates too.
_TOTP_ENROLLMENT_JS = r"""
const originUrl = new URL(location.href);
if (originUrl.protocol !== 'https:' || !['chatgpt.com','auth.openai.com'].includes(originUrl.hostname) ||
    (originUrl.port && originUrl.port !== '443') || originUrl.username || originUrl.password) return {};
const action = String((arguments[0] || {}).action || 'inspect');
const norm = value => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
const visible = el => {
  if (!el || !el.isConnected) return false;
  for (let node = el; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (node.hidden || node.hasAttribute('inert') || node.getAttribute('aria-hidden') === 'true' ||
        (node.tagName === 'DIALOG' && !node.hasAttribute('open')) ||
        style.display === 'none' || /hidden|collapse/.test(style.visibility) ||
        style.opacity === '0') return false;
  }
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
};
const text = el => typeof el.innerText === 'string' ? el.innerText : String(el.textContent || '');
const auth = /authenticator|authentication app|身份验证器|验证器应用|身份验证应用|身分驗證器|驗證器應用/i;
const scan = /qr\s*code|scan.{0,45}code|二维码|二維碼|扫描.{0,15}码|掃描.{0,15}碼/i;
const manual = /can['’]?t scan|cannot scan|unable to scan|enter manually|manual setup|show (?:the )?(?:setup |secret )?key|view (?:the )?(?:setup |secret )?key|无法扫描|無法掃描|手动输入|手動輸入|手动设置|手動設定|显示.{0,8}密钥|顯示.{0,8}金鑰/i;
const keyLabel = /^(?:(?:your |the )?(?:setup key|secret key|manual (?:setup )?key|authentication key)|设置密钥|设置密匙|密钥|密匙|手动(?:设置)?密钥|身份验证密钥|設定金鑰|金鑰|手動(?:設定)?金鑰)\s*[:：]?$/i;
const keyInstruction = /^(?:enter|copy|use) (?:this |the )?(?:setup |secret )?(?:key|code)\b.{0,90}(?:authenticator|authentication app)|^(?:在|将|將).{0,40}(?:验证器|驗證器).{0,30}(?:输入|輸入|密钥|金鑰)/i;
const isKeyLabel = value => value.length <= 180 && (keyLabel.test(norm(value)) || keyInstruction.test(norm(value)));
const controls = scope => [...scope.querySelectorAll('button,[role="button"],a,[role="radio"]')].filter(visible);
const controlText = el => norm(text(el) || el.getAttribute('aria-label') || el.getAttribute('title'));
const enabled = el => !el.disabled && el.getAttribute('aria-disabled') !== 'true';
const labels = scope => [...scope.querySelectorAll('label,div,span,p,dt,strong')]
  .filter(visible).filter(el => isKeyLabel(text(el)));
const title = scope => {
  const headings = [...scope.querySelectorAll('h1,h2,h3,h4,[role="heading"]')].filter(visible);
  const named = String(scope.getAttribute('aria-labelledby') || '').split(/\s+/)
    .map(id => document.getElementById(id)).filter(el => el && scope.contains(el) && visible(el));
  return norm([scope.getAttribute('aria-label') || '', ...named.map(text), ...headings.map(text)].join(' '));
};
const isEnrollment = scope => {
  if (scope.closest('[data-message-author-role],[data-testid^="conversation-turn"]')) return false;
  const heading = title(scope);
  if (/recovery codes?|backup codes?|password|text message|sms|恢复码|恢复代码|备用代码|密码|短信|復原碼|備用碼|密碼/.test(heading)) return false;
  const value = norm(text(scope));
  if (!auth.test(heading + ' ' + value)) return false;
  return scan.test(value) || controls(scope).some(el => manual.test(controlText(el))) ||
    labels(scope).length > 0 || (auth.test(heading) && /set up|setup|enable|activate|设置|設定|启用|啟用/.test(heading));
};
const dialogs = [...document.querySelectorAll('[role="dialog"],dialog,[role="alertdialog"]')].filter(visible);
let scope = dialogs[dialogs.length - 1] || null;
// Never fall back to the document body: settings, chat content and stale
// dialogs can contain unrelated Base32-looking strings or old setup keys.
if (!scope) {
  const regions = [...document.querySelectorAll('form,section,[data-testid*="authenticator" i]')]
    .filter(visible).filter(el => auth.test(title(el))).filter(isEnrollment);
  const innermost = regions.filter(el => !regions.some(other => other !== el && el.contains(other)));
  if (innermost.length === 1) scope = innermost[0];
}
const state = {enrollment_visible:false, manual_available:false, manual_disabled:false,
  manual_clicked:false, authenticator_clicked:false, qr_visible:false, otp_input_visible:false,
  unrelated_dialog:false, loading:false, candidate_overflow:false, candidates:[]};
if (!scope) return state;
state.enrollment_visible = isEnrollment(scope);
state.unrelated_dialog = Boolean(dialogs.length && !state.enrollment_visible);
if (!state.enrollment_visible) {
  const heading = title(scope);
  const chooser = /(?:choose|select|add|set up|setup).{0,40}(?:authentication|verification|multi.factor|two.factor|method)|authentication methods?|multi.factor authentication|two.factor authentication|选择.{0,20}(?:验证|方式)|選擇.{0,20}(?:驗證|方式)|添加.{0,20}验证|新增.{0,20}驗證|多重身份验证|双重身份验证|多因素身份驗證/.test(heading) &&
    !/recovery|backup|password|text message|sms|恢复|备用|密码|短信|復原|備用|密碼/.test(heading);
  if (action === 'choose' && dialogs.length && chooser) {
    const options = controls(scope).filter(el => enabled(el) &&
      !['switch', 'checkbox'].includes(el.getAttribute('role')) &&
      el.getAttribute('data-testid') !== 'mfa-authenticator-toggle' &&
      (el.tagName !== 'A' || !el.getAttribute('href') || String(el.getAttribute('href')).startsWith('#')) &&
      /^(?:use |choose |select )?(?:an? )?(?:authenticator app(?:lication)?|authentication app|身份验证器应用|验证器应用|身份验证应用|身分驗證器應用程式)(?:\s*[（(].*[)）])?$/.test(controlText(el)));
    if (options.length === 1) { options[0].click(); state.authenticator_clicked = true; }
  }
  return state;
}
// A nested popup must not contribute candidates or action controls to its
// parent enrollment dialog (including one hidden via an ancestor).
const owned = el => visible(el) && (!dialogs.length || el.closest('[role="dialog"],dialog,[role="alertdialog"]') === scope);
const manualControls = controls(scope).filter(owned).filter(el => manual.test(controlText(el)) &&
  !/disable|turn off|remove|confirm|verify|submit|关闭|停用|移除|确认|验证|提交/.test(controlText(el)) &&
  (el.tagName !== 'A' || !el.getAttribute('href') || String(el.getAttribute('href')).startsWith('#')));
state.manual_available = manualControls.some(enabled);
state.manual_disabled = manualControls.some(el => !enabled(el));
state.qr_visible = scan.test(text(scope)) && [...scope.querySelectorAll('canvas,svg,img')].some(owned);
state.otp_input_visible = [...scope.querySelectorAll('input[autocomplete="one-time-code"],input[inputmode="numeric"],input[maxlength="6"]')].some(owned);
state.loading = scope.getAttribute('aria-busy') === 'true' ||
  [...scope.querySelectorAll('[role="progressbar"],[aria-busy="true"]')].some(owned);
const add = (kind, value) => {
  if (!value || String(value).length > 1200) return;
  if (state.candidates.length >= 80) { state.candidate_overflow = true; return; }
  state.candidates.push({kind, value:String(value)});
};
for (const el of scope.querySelectorAll('[data-secret]')) {
  if (owned(el)) add('plain', el.getAttribute('data-secret'));
}
for (const el of scope.querySelectorAll('input[readonly],code,pre')) {
  if (owned(el)) add('plain', el.value || text(el));
}
for (const el of scope.querySelectorAll('a,img,[data-uri]')) {
  if (!owned(el)) continue;
  // Read every supported URI attribute independently; an ordinary href must
  // not hide an explicit data-uri on the same visible element.
  for (const attr of ['href','src','data-uri']) {
    const value = el.getAttribute(attr);
    if (/^otpauth:\/\//i.test(String(value || '').trim())) add('uri', value);
  }
}
const addField = el => {
  if (!el || !scope.contains(el) || !owned(el) || !el.matches('div,span,p,dd,input,code,pre')) return;
  add('plain', el.value || text(el));
};
// Plain div/span text is accepted only through an explicit setup-key label.
// There is deliberately no whole-dialog Base32 regex search.
for (const el of scope.querySelectorAll('div,span,p,input,[aria-labelledby]')) {
  if (!owned(el)) continue;
  if (isKeyLabel(el.getAttribute('aria-label') || '')) addField(el);
  const ids = String(el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
  if (ids.some(id => {
    const label = document.getElementById(id);
    return label && scope.contains(label) && owned(label) && isKeyLabel(text(label));
  })) addField(el);
}
for (const label of labels(scope).filter(owned)) {
  const target = label.getAttribute('for');
  if (target) addField(document.getElementById(target));
  addField(label.nextElementSibling);
  // Common wrappers put the label inside a small heading div, with the key
  // as the next sibling of that wrapper. Climb only through label-only text.
  const parent = label.parentElement;
  if (parent && parent !== scope && norm(text(parent)) === norm(text(label))) addField(parent.nextElementSibling);
}
// Also accept a single, explicitly labelled field: "Setup key: ABCD ...".
for (const el of scope.querySelectorAll('div,span,p')) {
  if (!owned(el) || text(el).length > 320) continue;
  const match = text(el).trim().match(/^([^:：\n]{1,90})\s*[:：]\s*([A-Z2-7=\s-]+)$/i);
  if (match && isKeyLabel(match[1])) add('plain', match[2]);
}
const candidateNowVisible = state.candidates.some(candidate => {
  if (candidate.kind === 'uri') return true;
  const value = candidate.value.replace(/[\s-]+/g, '').replace(/=+$/, '');
  return /^[A-Z2-7]{16,128}$/i.test(value);
});
if (action === 'reveal' && !candidateNowVisible && manualControls.filter(enabled).length === 1) {
  manualControls.filter(enabled)[0].click(); state.manual_clicked = true;
}
return state;
"""


def _totp_enrollment_probe(page: Any, *, action: str = "inspect") -> dict[str, Any]:
    try:
        value = page.run_js(_TOTP_ENROLLMENT_JS, {"action": action})
        return value if isinstance(value, dict) else {}
    except Exception:
        # Browser errors can embed source/DOM data; never forward that text.
        return {}


def _totp_enrollment_secrets(state: dict[str, Any]) -> set[str]:
    if not state.get("enrollment_visible"):
        return set()
    candidates = state.get("candidates", [])
    secrets: set[str] = set()
    for candidate in candidates if isinstance(candidates, list) else []:
        if not isinstance(candidate, dict):
            continue
        value = str(candidate.get("value") or "")
        # A single URI field may contain multiple otpauth values. Validate
        # all of them so first-match parsing cannot hide conflicting seeds.
        uris = re.findall(r"otpauth://[^\s\"'<>]+", value, flags=re.I)
        for item in uris or [value]:
            secret = _candidate_to_totp_secret(item, allow_plain=candidate.get("kind") == "plain")
            if secret:
                secrets.add(secret)
    return secrets


def _totp_enrollment_diagnostics(page: Any) -> dict[str, bool]:
    state = _totp_enrollment_probe(page)
    secrets = _totp_enrollment_secrets(state)
    ambiguous = len(secrets) > 1 or bool(state.get("candidate_overflow"))
    result = {key: bool(state.get(key)) for key in (
        "enrollment_visible", "manual_available", "manual_disabled", "qr_visible",
        "otp_input_visible", "unrelated_dialog", "loading",
    )}
    result.update(secret_found=len(secrets) == 1 and not ambiguous, ambiguous=ambiguous)
    return result


def _normalise_totp_secret(value: object) -> str:
    secret = re.sub(r"[\s-]+", "", str(value or "")).upper().rstrip("=")
    if not 16 <= len(secret) <= 128 or not re.fullmatch(r"[A-Z2-7]+", secret):
        return ""
    try:
        base64.b32decode(secret + "=" * ((-len(secret)) % 8), casefold=True)
    except Exception:
        return ""
    return secret


def _candidate_to_totp_secret(value: object, *, allow_plain: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for match in re.finditer(r"otpauth://[^\s\"'<>]+", text, flags=re.I):
        try:
            parsed = urllib.parse.urlparse(match.group(0))
            raw = urllib.parse.parse_qs(parsed.query).get("secret", [""])[0]
            secret = _normalise_totp_secret(urllib.parse.unquote(raw))
            if secret:
                return secret
        except Exception:
            continue
    # Never mine arbitrary text or QR image bytes for Base32-looking runs.
    # Plain Base32 is accepted only from a provenance-approved DOM field
    # (readonly input, code/pre, or data-secret).  This still permits the rare
    # valid all-letter seed without mistaking English UI copy for a secret.
    if not allow_plain or re.match(r"^(?:data|blob|https?):", text, flags=re.I):
        return ""
    return _normalise_totp_secret(text)


def _extract_totp_secret(page: Any) -> str:
    state = _totp_enrollment_probe(page)
    secrets = _totp_enrollment_secrets(state)
    return next(iter(secrets)) if len(secrets) == 1 and not state.get("candidate_overflow") else ""


def _reveal_manual_totp_secret(page: Any, emit: Optional[Callable[[str], None]] = None) -> str:
    deadline = time.monotonic() + 20.0
    clicked = False
    reported: set[str] = set()

    def report(key: str, message: str) -> None:
        if key not in reported:
            reported.add(key)
            if emit is not None:
                emit(message)

    report("waiting", "等待身份验证器设置界面及手动密钥加载（最多20秒）")
    state: dict[str, Any] = {}
    while True:
        state = _totp_enrollment_probe(page)
        secrets = _totp_enrollment_secrets(state)
        if len(secrets) > 1 or state.get("candidate_overflow"):
            report("ambiguous", "身份验证器设置出现多个不同密钥候选或候选过多，已停止提取，避免绑定错误密钥")
            return ""
        if len(secrets) == 1:
            report("found", "已从当前可见身份验证器设置界面读取并校验唯一手动密钥")
            return next(iter(secrets))
        if state.get("enrollment_visible"):
            report("enrollment", "已确认当前可见身份验证器设置界面，正在检查手动密钥入口")
        if state.get("manual_available") and not clicked:
            revealed = _totp_enrollment_probe(page, action="reveal")
            clicked = bool(revealed.get("manual_clicked"))
            if clicked:
                report("clicked", "已点击手动显示密钥入口，等待密钥实际出现")
        if state.get("manual_disabled") and not state.get("manual_available"):
            report("disabled", "手动密钥入口暂不可用，继续等待界面完成加载")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.4, remaining))
    if state.get("qr_visible") and not state.get("manual_available") and not clicked:
        report("timeout", "身份验证器设置仅显示二维码，手动密钥入口不存在或不可用；无法读取可保存的密钥")
    elif clicked:
        report("timeout", "手动显示入口已点击，但20秒内未出现可校验的唯一密钥")
    elif state.get("unrelated_dialog"):
        report("timeout", "当前弹窗不是身份验证器设置界面，未读取其他弹窗中的密钥候选")
    elif state.get("enrollment_visible"):
        report("timeout", "身份验证器设置界面已出现，但20秒内未找到可读取的手动密钥")
    else:
        report("timeout", "20秒内未出现可识别的身份验证器设置界面")
    return ""


def _fill_totp_and_submit(page: Any, code: str) -> bool:
    try:
        return bool(
            page.run_js(
                """
                return (async () => {
                  const code = String(arguments[0]);
                  const startUrl = String(location.href || '');
                  let roots = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
                    const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0;
                  });
                  let root = roots[roots.length - 1] || document;
                  const visible = (el) => {
                    const r = el.getBoundingClientRect();
                    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
                  };
                  const fields = [...root.querySelectorAll(
                    'input[autocomplete="one-time-code"],input[name*="code" i],input[name*="otp" i],input[inputmode="numeric"],input[maxlength="6"]'
                  )].filter(visible);
                  if (!fields.length) return false;
                  const setValue = (el, value) => {
                    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                    setter.call(el, value);
                    el.dispatchEvent(new Event('input', {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                  };
                  if (fields.length >= 6 && fields.slice(0, 6).every(x => Number(x.maxLength || 1) <= 1)) {
                    fields.slice(0, 6).forEach((el, i) => setValue(el, code[i] || ''));
                  } else {
                    setValue(fields[0], code);
                  }
                  // React enables the submit button on a later render.  Wait
                  // two animation frames instead of claiming success before
                  // the button was actually clickable.
                  await new Promise(resolve => requestAnimationFrame(
                    () => requestAnimationFrame(resolve)
                  ));
                  roots = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
                    const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0;
                  });
                  root = roots[roots.length - 1] || document;
                  const buttons = [...root.querySelectorAll('button,[role="button"]')].filter(visible);
                  const terms = /verify|confirm|continue|next|finish|done|验证|确认|继续|下一步|完成/i;
                  const submit = buttons.find(el => !el.disabled && terms.test(
                    el.innerText || el.textContent || el.getAttribute('aria-label') || ''
                  )) || [...root.querySelectorAll('button[type="submit"]')]
                    .find(el => visible(el) && !el.disabled);
                  if (!submit) {
                    // Some six-box components submit automatically once the
                    // final digit is entered and render no confirm button.
                    // Give their network/render cycle enough time to finish.
                    for (let attempt = 0; attempt < 20; attempt += 1) {
                      await new Promise(resolve => setTimeout(resolve, 100));
                      const currentDialogs = [...document.querySelectorAll('[role="dialog"]')]
                        .filter(el => {
                          const r = el.getBoundingClientRect();
                          return r.width > 0 && r.height > 0;
                        });
                      const currentRoot = currentDialogs[currentDialogs.length - 1] || document;
                      const remaining = [...currentRoot.querySelectorAll(
                        'input[autocomplete="one-time-code"],input[name*="code" i],input[name*="otp" i],input[inputmode="numeric"],input[maxlength="6"]'
                      )].filter(visible);
                      if (!remaining.length || String(location.href || '') !== startUrl) return true;
                      const errorText = [...currentRoot.querySelectorAll('[role="alert"],[class*="error" i]')]
                        .filter(visible).map(el => el.innerText || el.textContent || '').join(' ');
                      if (/invalid|incorrect|expired|error|无效|错误|过期|不正确/i.test(errorText)) return false;
                    }
                    return false;
                  }
                  submit.click();
                  return true;
                })();
                """,
                code,
            )
        )
    except Exception:
        return False


def _mfa_activation_status(page: Any) -> str:
    """Return success/error/pending for the current TOTP enrollment.

    The ordinary ChatGPT Authenticator flow now closes the enrollment modal
    after a success toast and does not display recovery codes.  Keep this
    probe deliberately narrow so an unrelated notification cannot be treated
    as proof that MFA was enabled.
    """
    try:
        value = page.run_js(
            r"""
            const visible = (el) => {
              if (!el) return false;
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              return r.width > 0 && r.height > 0 &&
                s.display !== 'none' && s.visibility !== 'hidden';
            };
            const successToast = document.querySelector(
              '[data-testid="totp-mfa-activation-success"]'
            );
            if (visible(successToast)) return 'success';
            const toggle = document.querySelector(
              '[data-testid="mfa-authenticator-toggle"]'
            );
            if (visible(toggle) && toggle.getAttribute('aria-checked') === 'true') {
              return 'success';
            }
            const modal = document.querySelector('[data-testid="modal-enroll-totp"]');
            const scope = visible(modal) ? modal : document;
            const errors = [...scope.querySelectorAll(
              '[role="alert"],[class*="error" i],[aria-live="assertive"]'
            )].filter(visible).map(el => String(el.innerText || el.textContent || ''))
              .join(' ').toLowerCase();
            if (/invalid|incorrect|expired|failed|error|无效|错误|过期|失败|不正确/.test(errors)) {
              return 'error';
            }
            return 'pending';
            """
        )
        return str(value or "pending")
    except Exception:
        return "pending"


def _current_totp(secret: str) -> str:
    remaining = 30 - (time.time() % 30)
    if remaining < 8:
        time.sleep(remaining + 0.4)
    from platforms.kiro_github.totp import generate_totp

    return generate_totp(secret)


def is_authenticator_challenge(page: Any) -> bool:
    """Detect a sign-in TOTP challenge without confusing it with email OTP."""
    try:
        value = page.run_js(
            r"""
            const url = String(location.href || '').toLowerCase();
            const visible = (el) => {
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              return r.width > 0 && r.height > 0 && s.display !== 'none' &&
                s.visibility !== 'hidden';
            };
            const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(visible);
            const root = dialogs[dialogs.length - 1] ||
              document.body || document.documentElement || document;
            const text = String(root.innerText || '').toLowerCase();
            const routeHit = /\/mfa|\/totp|authenticator/.test(url);
            const textHit = /authenticator app|authentication app|two.factor|multi.factor|身份验证器|验证器应用|双重身份验证|多重身份验证|双因素认证/.test(text);
            const broadCodeInput = [...root.querySelectorAll(
              'input[autocomplete="one-time-code"],input[name*="totp" i],input[name*="mfa" i],input[name*="code" i],input[inputmode="numeric"],input[maxlength="6"]'
            )].some(visible);
            const emailPrompt = /check your email|sent (a )?code to|查看.*邮箱|验证码.*邮箱|已向.*邮箱.*发送|邮箱.*收到.*验证码/.test(text);
            const authenticatorCodePrompt = /enter.{0,40}code.{0,40}(authenticator|authentication) app|code.{0,30}from.{0,30}(authenticator|authentication) app|(authenticator|authentication) app.{0,40}code|输入.{0,30}(身份验证器|验证器应用).{0,30}(代码|验证码)/.test(text);
            // The email-code page can carry a generic "Multi-factor"
            // heading and an "Authenticator app" alternative-method button.
            // Those labels do not turn its visible mailbox OTP input into a
            // TOTP challenge.  Only an explicit Authenticator-code prompt may
            // override the mailbox wording.
            if (emailPrompt && !authenticatorCodePrompt) return false;
            return broadCodeInput && (routeHit || textHit);
            """
        )
        return bool(value)
    except Exception:
        return False


def choose_authenticator_login_method(page: Any) -> bool:
    """Choose Authenticator when login first presents an MFA method picker."""
    try:
        is_picker = bool(
            page.run_js(
                r"""
                const url = String(location.href || '').toLowerCase();
                const visible = (el) => {
                  const r = el.getBoundingClientRect();
                  const s = getComputedStyle(el);
                  return r.width > 0 && r.height > 0 && s.display !== 'none' &&
                    s.visibility !== 'hidden';
                };
                const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(visible);
                const root = dialogs[dialogs.length - 1] ||
                  document.body || document.documentElement || document;
                const text = String(root.innerText || '').toLowerCase();
                const hasCode = [...root.querySelectorAll(
                  'input[autocomplete="one-time-code"],input[name*="totp" i],input[name*="mfa" i],input[inputmode="numeric"]'
                )].some(visible);
                const hasAuthenticator = /authenticator app|authentication app|身份验证器应用|验证器应用|身份验证应用/.test(text);
                const hasMfaContext = /\/mfa|two.factor|multi.factor|choose.*method|选择.*验证|双重身份验证|多重身份验证/.test(url + ' ' + text);
                return !hasCode && hasAuthenticator && hasMfaContext;
                """
            )
        )
    except Exception:
        return False
    if not is_picker:
        return False
    return _click_text(page, _AUTHENTICATOR_TERMS, dialog_only=True) or _click_text(
        page,
        _AUTHENTICATOR_TERMS,
    )


def _is_email_verification_challenge(page: Any) -> bool:
    """Return whether login is waiting for a mailbox OTP after password."""
    try:
        return bool(
            page.run_js(
                r"""
                const url = String(location.href || '').toLowerCase();
                const visible = (el) => {
                  const r = el.getBoundingClientRect();
                  const s = getComputedStyle(el);
                  return r.width > 0 && r.height > 0 &&
                    s.display !== 'none' && s.visibility !== 'hidden';
                };
                const hasCode = [...document.querySelectorAll(
                  'input[autocomplete="one-time-code"],input[name="code"],input[inputmode="numeric"],input[maxlength="1"]'
                )].some(visible);
                return hasCode && (
                  url.includes('/email-verification') ||
                  url.includes('/log-in/code')
                );
                """
            )
        )
    except Exception:
        return False


def complete_authenticator_challenge(
    page: Any,
    totp_secret: str,
    log_fn: Optional[Callable[[str], None]] = None,
    *,
    timeout: int = 15,
) -> bool:
    """Complete an MFA challenge during a later login.

    Returns ``False`` when the current page is not an authenticator challenge;
    returns ``True`` only after submitting TOTP and the challenge visibly
    disappearing.  A
    missing secret is an explicit error because silently waiting would make
    every OAuth/login job look hung after automatic MFA enrollment.
    """
    _raise_for_auth_login_page_error(page)
    if not is_authenticator_challenge(page):
        return False
    log = log_fn if callable(log_fn) else (lambda _message: None)
    secret = _normalise_totp_secret(totp_secret)
    if not secret:
        raise RuntimeError("账号要求 Authenticator 2FA，但本地没有可用的 TOTP 密钥")

    _log_safely(log, "[账号安全] 检测到 Authenticator 2FA 登录校验")
    previous_code = ""
    for attempt in range(2):
        _raise_for_auth_login_page_error(page)
        code = _current_totp(secret)
        if previous_code and code == previous_code:
            # A rejected TOTP must not be submitted twice.  Wait until the
            # counter advances, even when the first verification returned
            # unusually quickly.
            deadline = time.time() + 35
            while code == previous_code and time.time() < deadline:
                time.sleep(0.5)
                code = _current_totp(secret)
            if code == previous_code:
                raise RuntimeError("Authenticator 2FA 未进入新的验证码时间窗")
        previous_code = code
        _raise_for_auth_login_page_error(page)
        submitted = _fill_totp_and_submit(page, code)
        _raise_for_auth_login_page_error(page)
        if not submitted:
            time.sleep(0.8)
            if is_authenticator_challenge(page):
                _record_security_retry_failure("controls_unavailable", page)
                raise RuntimeError("Authenticator 2FA 页面缺少验证码输入或确认控件")
            # A route can disappear because another navigation won a race.
            # Without a confirmed fill/submit this helper has no TOTP proof;
            # leave callback validation to the outer OAuth state machine.
            return False
        deadline = time.time() + max(3, int(timeout))
        while time.time() < deadline:
            page_readable = _raise_for_auth_login_page_error(page)
            if not is_authenticator_challenge(page) and page_readable:
                # Losing the input can also mean an error page replaced it.
                # Recheck after the DOM probe before publishing MFA success.
                if not _raise_for_auth_login_page_error(page):
                    time.sleep(0.5)
                    continue
                _log_safely(log, "[账号安全] Authenticator 2FA 登录校验通过")
                return True
            time.sleep(0.5)
        if attempt == 0:
            _log_safely(log, "[账号安全] 首个 TOTP 未通过，跨时间窗后重试一次")
    raise RuntimeError("Authenticator 2FA 验证码被拒绝或页面未继续")


def _password_submission_status(page: Any) -> str:
    """Return success/error/pending without returning potentially sensitive UI text."""
    try:
        value = page.run_js(
            r"""
            const visible = (el) => {
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              return r.width > 0 && r.height > 0 && s.visibility !== 'hidden';
            };
            const text = [...document.querySelectorAll(
              '[role="alert"],[aria-live],.error,[class*="error" i],.toast,[class*="toast" i]'
            )].filter(visible).map(el => String(el.innerText || el.textContent || ''))
              .join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
            if (/password.{0,40}(updated|saved|set|changed|success)|密码.{0,30}(已更新|已保存|设置成功|修改成功)/i.test(text)) {
              return 'success';
            }
            if (/error|failed|invalid|incorrect|unable|错误|失败|无效|不正确/i.test(text)) {
              return 'error';
            }
            return 'pending';
            """
        )
        return str(value or "pending")
    except Exception:
        return "pending"


def _fill_and_submit_new_password_form(
    page: Any,
    password: str,
    log_fn: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """Fill one unambiguous new-password form and submit it safely.

    The live auth page is React controlled. Assigning ``input.value`` for all
    password fields made the DOM look filled while React still considered the
    form empty, leaving Continue inert. On a real ChromiumPage we therefore
    use native input, keep both fields in one form, and click only that form's
    enabled submit control. Tiny legacy page adapters retain a strictly
    form-scoped JavaScript fallback.
    """
    log = log_fn if callable(log_fn) else (lambda _message: None)
    current_url = str(getattr(page, "url", "") or "").strip()
    if not _trusted_openai_action_url(current_url):
        return False, "密码页面不是可信 OpenAI HTTPS 地址，已停止填写"
    if not password:
        return False, "本地没有可用于设置的密码"

    try:
        from platforms.chatgpt.drission_register import _element_is_interactable
    except Exception:
        _element_is_interactable = lambda element: bool(element)  # type: ignore[assignment]

    finder = getattr(page, "eles", None)
    native_fields: Optional[list[Any]] = None
    if callable(finder):
        try:
            raw_fields = finder("css:input[type='password']", timeout=0.8)
            native_fields = list(raw_fields or [])
        except TypeError:
            # unittest.mock.Mock and older tiny adapters can expose a callable
            # attribute that is not an iterable element collection.
            native_fields = None
        except Exception:
            return False, "无法读取密码设置表单"

    if native_fields is not None:
        fields = [field for field in native_fields if _element_is_interactable(field)]
        if not fields:
            _record_security_retry_failure("controls_unavailable", page)
            return False, "添加密码入口未提供可填写的密码表单"
        try:
            shape = page.run_js(
                r"""
                const fields = Array.from(arguments);
                const visible = (el) => {
                  if (!el || el.disabled || el.readOnly || el.closest('[inert]')) return false;
                  if (el.getAttribute('aria-hidden') === 'true') return false;
                  const r = el.getBoundingClientRect();
                  const s = getComputedStyle(el);
                  return r.width > 0 && r.height > 0 &&
                    s.display !== 'none' && s.visibility !== 'hidden';
                };
                const form = fields[0]?.closest('form');
                if (!form || fields.some((field) => field.closest('form') !== form)) {
                  return {ok: false, reason: 'different_forms'};
                }
                const formFields = [...form.querySelectorAll('input[type="password"]')]
                  .filter(visible);
                const descriptors = formFields.map((field) =>
                  `${field.name || ''} ${field.autocomplete || ''} ${field.id || ''}`.toLowerCase()
                );
                return {
                  ok: formFields.length === 2 && fields.length === 2,
                  count: formFields.length,
                  currentRequired: descriptors.some((value) => /current-password|current_password|currentpassword/.test(value)),
                  hasNew: descriptors.some((value) => /new-password|new_password|newpassword/.test(value)),
                  hasConfirm: descriptors.some((value) => /confirm|repeat|retype/.test(value)),
                };
                """,
                *fields,
            )
        except Exception:
            return False, "无法核对密码设置表单结构"
        if not isinstance(shape, dict) or not shape.get("ok"):
            if isinstance(shape, dict) and shape.get("currentRequired"):
                return False, "页面要求当前密码，未自动覆盖已有密码"
            return False, "密码设置表单结构不明确，已停止自动提交"
        if shape.get("currentRequired"):
            return False, "页面要求当前密码，未自动覆盖已有密码"
        if not shape.get("hasNew") or not shape.get("hasConfirm"):
            return False, "未能明确区分新密码与确认密码字段，已停止自动提交"

        _log_safely(log, "[账号安全] 已确认同一表单内的新密码与确认密码字段")

        def native_fill(element: Any) -> bool:
            try:
                if not _element_is_interactable(element):
                    return False
                element.click()
                try:
                    element.clear(by_js=False)
                except TypeError:
                    element.clear()
                except Exception:
                    try:
                        element.clear()
                    except Exception:
                        pass
                try:
                    element.input(password, clear=False)
                except TypeError:
                    element.input(password)
                time.sleep(0.35)
                actual = element.property("value")
                accepted = str(actual or "") == password
                actual = ""
                return accepted
            except Exception:
                return False

        if not native_fill(fields[0]):
            return False, "新密码输入未被页面接受"

        # React may replace the second input after the first field changes.
        try:
            refreshed = list(finder("css:input[type='password']", timeout=0.8) or [])
            fields = [field for field in refreshed if _element_is_interactable(field)]
        except Exception:
            return False, "填写新密码后表单已变化，已停止提交"
        if len(fields) != 2 or not native_fill(fields[1]):
            return False, "确认密码输入未被页面接受"
        try:
            retained_values = [str(field.property("value") or "") for field in fields]
            retained = all(value == password for value in retained_values)
            retained_values = []
        except Exception:
            retained = False
        if not retained:
            return False, "密码表单在提交前未保留两次一致输入"
        _log_safely(log, "[账号安全] 密码表单已通过原生输入完成填写")

        marker = "account-security-new-password-submit"
        readiness = "missing"
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                result = page.run_js(
                    r"""
                    const fields = Array.from(arguments).slice(0, -1);
                    const marker = String(arguments[arguments.length - 1]);
                    document.querySelectorAll(`[data-codex-security-submit="${marker}"]`)
                      .forEach((el) => el.removeAttribute('data-codex-security-submit'));
                    const form = fields[0]?.closest('form');
                    if (!form || fields.some((field) => field.closest('form') !== form)) {
                      return 'form_changed';
                    }
                    const visible = (el) => {
                      if (!el || el.closest('[inert]')) return false;
                      if (el.getAttribute('aria-hidden') === 'true') return false;
                      const r = el.getBoundingClientRect();
                      const s = getComputedStyle(el);
                      return r.width > 0 && r.height > 0 &&
                        s.display !== 'none' && s.visibility !== 'hidden' &&
                        s.pointerEvents !== 'none' && Number(s.opacity || 1) > 0;
                    };
                    const controls = [...form.querySelectorAll(
                      'button, input[type="submit"], [role="button"]'
                    )].filter(visible);
                    const label = (el) => String(
                      el.innerText || el.value || el.textContent || el.getAttribute('aria-label') || ''
                    ).trim().toLowerCase();
                    const exact = new Set([
                      'continue', 'save', 'confirm', 'set password',
                      '继续', '保存', '确认', '设置密码', '更改密码'
                    ]);
                    const submit = controls.find((el) => el.type === 'submit') ||
                      controls.find((el) => exact.has(label(el)));
                    if (!submit) return 'missing';
                    if (!form.checkValidity()) return 'invalid';
                    if (submit.disabled || submit.getAttribute('aria-disabled') === 'true') {
                      return 'disabled';
                    }
                    submit.setAttribute('data-codex-security-submit', marker);
                    return 'ready';
                    """,
                    *fields,
                    marker,
                )
                readiness = str(result or "missing")
            except Exception:
                readiness = "missing"
            if readiness == "ready":
                break
            if readiness in {"form_changed", "invalid"}:
                break
            time.sleep(0.35)
        if readiness == "form_changed":
            return False, "填写后密码表单发生变化，未执行提交"
        if readiness == "invalid":
            return False, "OpenAI 页面判定新密码表单未通过校验"
        if readiness == "disabled":
            return False, "密码已填写，但确认按钮仍不可用"
        if readiness != "ready":
            return False, "密码已填写，但同一表单内没有可用的确认按钮"
        try:
            submit = page.ele(
                f'css:[data-codex-security-submit="{marker}"]',
                timeout=1,
            )
        except Exception:
            submit = None
        if not submit or not _element_is_interactable(submit):
            return False, "密码确认按钮在提交前已失效"
        _mark_password_submission()
        try:
            submit.click()
        except Exception:
            return False, "密码确认按钮点击失败"
        _log_safely(log, "[账号安全] 密码提交已发出，等待独立登录复核")
        return True, ""

    # Strict compatibility path for legacy adapters without ``eles``. Real
    # ChromiumPage never reaches this branch, so normal operation does not send
    # a credential through JavaScript.
    _mark_password_submission()
    try:
        result = page.run_js(
            r"""
            return (() => {
              const password = String(arguments[0]);
              const visible = (el) => {
                if (!el || el.disabled || el.readOnly || el.closest('[inert]')) return false;
                if (el.getAttribute('aria-hidden') === 'true') return false;
                const r = el.getBoundingClientRect();
                const s = getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                  s.display !== 'none' && s.visibility !== 'hidden';
              };
              const fields = [...document.querySelectorAll('input[type="password"]')]
                .filter(visible);
              if (fields.length !== 2) return {filled: false, ambiguous: true};
              const form = fields[0].closest('form');
              if (!form || fields.some((field) => field.closest('form') !== form)) {
                return {filled: false, ambiguous: true};
              }
              if (fields.some((field) => /current-password|current_password|currentpassword/i.test(
                `${field.name || ''} ${field.autocomplete || ''} ${field.id || ''}`
              ))) return {filled: false, current_required: true};
              const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
              if (!setter) return {filled: false};
              fields.forEach((field) => {
                setter.call(field, password);
                field.dispatchEvent(new Event('input', {bubbles: true}));
                field.dispatchEvent(new Event('change', {bubbles: true}));
              });
              const controls = [...form.querySelectorAll(
                'button, input[type="submit"], [role="button"]'
              )].filter(visible);
              const label = (el) => String(
                el.innerText || el.value || el.textContent || el.getAttribute('aria-label') || ''
              ).trim().toLowerCase();
              const exact = new Set([
                'continue', 'save', 'confirm', 'set password',
                '继续', '保存', '确认', '设置密码', '更改密码'
              ]);
              const submit = controls.find((el) => el.type === 'submit') ||
                controls.find((el) => exact.has(label(el)));
              if (!submit || submit.disabled || submit.getAttribute('aria-disabled') === 'true') {
                return {filled: true, submitted: false};
              }
              submit.click();
              return {filled: true, submitted: true};
            })();
            """,
            password,
        )
    except Exception as exc:
        return False, _safe_error(exc, known_secrets=(password,))
    if not isinstance(result, dict) or not result.get("filled"):
        if isinstance(result, dict) and result.get("current_required"):
            return False, "页面要求当前密码，未自动覆盖已有密码"
        return False, "添加密码入口未提供明确的新密码表单"
    if not result.get("submitted"):
        return False, "密码已填写，但确认按钮不可用"
    return True, ""


def _password_code_error_kind(page: Any) -> str:
    """Classify a visible password-verification error without exposing text."""
    try:
        value = page.run_js(
            r"""
            const visible = (el) => {
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              return r.width > 0 && r.height > 0 &&
                s.display !== 'none' && s.visibility !== 'hidden';
            };
            const text = [...document.querySelectorAll(
              '[role="alert"],[aria-live],.error,[class*="error" i]'
            )].filter(visible).map(el => String(el.innerText || el.textContent || ''))
              .join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
            if (!text) return '';
            if (/too many|rate limit|try again later|\u8fc7\u4e8e\u9891\u7e41|\u7a0d\u540e\u91cd\u8bd5/.test(text)) {
              return 'rate_limited';
            }
            if (/expired|\u5df2\u8fc7\u671f|\u8fc7\u671f/.test(text)) return 'expired';
            if (/invalid|incorrect|wrong code|does not match|\u65e0\u6548|\u4e0d\u6b63\u786e|\u9519\u8bef/.test(text)) {
              return 'invalid';
            }
            return '';
            """
        )
        return str(value or "")
    except Exception:
        return ""


def _fill_password_verification_code(page: Any, code: str) -> bool:
    """Fill the password-reset OTP with native events when it uses split boxes.

    The registration helper's JavaScript fallback is retained for single-box
    variants.  Password management currently uses six one-character React
    inputs on some deployments; native per-box input is required there so the
    submit button observes the same state a real keyboard would create.
    """
    normalized = str(code or "").strip()
    if not re.fullmatch(r"\d{6}", normalized):
        return False

    try:
        from platforms.chatgpt.drission_register import (
            _element_is_interactable,
            _fill_verification_code,
        )

        split_fields: list[Any] = []
        finder = getattr(page, "eles", None)
        if callable(finder):
            for selector in (
                'css:input[maxlength="1"]',
                'css:input[inputmode="numeric"][maxlength="1"]',
            ):
                try:
                    split_fields = [
                        field
                        for field in list(finder(selector, timeout=0.5) or [])
                        if _element_is_interactable(field)
                    ]
                except Exception:
                    split_fields = []
                if len(split_fields) >= len(normalized):
                    break

        if len(split_fields) >= len(normalized):
            for field, digit in zip(split_fields, normalized):
                try:
                    field.click()
                    try:
                        field.clear(by_js=False)
                    except TypeError:
                        field.clear()
                    except Exception:
                        pass
                    try:
                        field.input(digit, clear=False)
                    except TypeError:
                        field.input(digit)
                except Exception:
                    return False
            try:
                return all(
                    str(field.property("value") or "") == digit
                    for field, digit in zip(split_fields, normalized)
                )
            except Exception:
                # Native input completed without an exception.  The route and
                # submit-state checks below remain the final proof.
                return True

        return bool(_fill_verification_code(page, normalized))
    except Exception:
        return False


def _click_password_code_submit(page: Any) -> str:
    """Click the verification form submit and report only safe control state."""
    try:
        value = page.run_js(
            r"""
            return (() => {
              const visible = (el) => {
                const r = el.getBoundingClientRect();
                const s = getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                  s.display !== 'none' && s.visibility !== 'hidden';
              };
              const inputs = [...document.querySelectorAll(
                'input[autocomplete="one-time-code"],input[name="code"],input[inputmode="numeric"],input[maxlength="1"]'
              )].filter(visible);
              const input = inputs[0];
              if (!input) return 'missing_input';
              const form = input.closest('form');
              if (!form) return 'missing_form';
              const buttons = [...form.querySelectorAll(
                'button[type="submit"],input[type="submit"],button,[role="button"]'
              )].filter(visible);
              const label = (el) => String(
                el.innerText || el.value || el.textContent || el.getAttribute('aria-label') || ''
              ).trim().toLowerCase();
              const button = buttons.find(el => [
                'continue','verify','confirm','next','\u7ee7\u7eed','\u9a8c\u8bc1','\u786e\u8ba4','\u4e0b\u4e00\u6b65'
              ].includes(label(el))) || buttons.find(el => el.type === 'submit');
              if (button) {
                if (button.disabled || button.getAttribute('aria-disabled') === 'true') {
                  return 'disabled';
                }
                button.click();
                return 'clicked';
              }
              if (typeof form.requestSubmit === 'function' && form.checkValidity()) {
                form.requestSubmit();
                return 'submitted';
              }
              return 'missing_submit';
            })();
            """
        )
        return str(value or "missing_submit")
    except Exception:
        return "missing_submit"


def _submit_password_verification_code(
    page: Any,
    code: str,
    *,
    timeout: float = 25.0,
    challenge_active: Optional[Callable[[Any], bool]] = None,
) -> tuple[bool, str]:
    """Submit one mailbox OTP and verify that its challenge advances.

    OAuth can move from email OTP directly to TOTP, which also has a visible
    code input. Its caller supplies the narrower email-challenge predicate so
    we never mistake the next factor for a failed email OTP or submit twice.
    """
    from platforms.chatgpt.drission_register import _registration_state

    def still_waiting() -> bool:
        if challenge_active is not None:
            return bool(challenge_active(page))
        return _registration_state(page) == "verification"

    if not _fill_password_verification_code(page, code):
        return False, "input_missing"

    # Some variants auto-submit the sixth digit.  Give that route precedence
    # before touching a possibly re-rendering Continue button.
    auto_deadline = time.monotonic() + 2.5
    while time.monotonic() < auto_deadline:
        if not still_waiting():
            return True, ""
        error_kind = _password_code_error_kind(page)
        if error_kind:
            return False, error_kind
        time.sleep(0.25)

    submit_state = ""
    submit_deadline = time.monotonic() + 6.0
    while time.monotonic() < submit_deadline:
        if not still_waiting():
            return True, ""
        error_kind = _password_code_error_kind(page)
        if error_kind:
            return False, error_kind
        submit_state = _click_password_code_submit(page)
        if submit_state in {"clicked", "submitted"}:
            break
        time.sleep(0.3)
    if submit_state not in {"clicked", "submitted"}:
        return False, "submit_unavailable"

    transition_deadline = time.monotonic() + max(1.0, float(timeout))
    while time.monotonic() < transition_deadline:
        if not still_waiting():
            return True, ""
        error_kind = _password_code_error_kind(page)
        if error_kind:
            return False, error_kind
        time.sleep(0.35)
    return False, "transition_timeout"


def _extract_recovery_codes(page: Any) -> tuple[bool, list[str]]:
    """Return (recovery-screen-visible, codes) from the top-most dialog."""
    try:
        result = page.run_js(
            r"""
            const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
              const r = el.getBoundingClientRect();
              return r.width > 0 && r.height > 0;
            });
            const root = dialogs[dialogs.length - 1] || document;
            const text = String(root.innerText || root.textContent || '');
            const present = /recovery codes?|backup codes?|恢复代码|恢复码|备用代码|备用码/i.test(text);
            if (!present) return {present: false, values: []};
            const values = [...root.querySelectorAll('code,pre,input[readonly],li')]
              .map(el => String(el.value || el.innerText || el.textContent || ''))
              .filter(Boolean).slice(0, 80);
            return {present: true, values};
            """
        )
    except Exception:
        return False, []
    if not isinstance(result, dict) or not result.get("present"):
        return False, []
    codes: list[str] = []
    seen: set[str] = set()
    pattern = re.compile(
        r"(?<![A-Za-z0-9])(?=[A-Za-z0-9-]{8,32}(?![A-Za-z0-9-]))"
        r"(?=[A-Za-z0-9-]*[A-Za-z])(?=[A-Za-z0-9-]*\d)"
        r"(?:[A-Za-z0-9]{8,24}|[A-Za-z0-9]{4,10}(?:-[A-Za-z0-9]{4,10}){1,3})"
        r"(?![A-Za-z0-9])"
    )
    for value in result.get("values") or []:
        for match in pattern.finditer(str(value or "")):
            code = match.group(0).strip()
            if code and code not in seen:
                codes.append(code)
                seen.add(code)
    return True, codes


def _acknowledge_recovery_codes(page: Any) -> None:
    """Acknowledge a saved recovery-code screen without exposing its text."""
    try:
        page.run_js(
            """
            const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(el => {
              const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0;
            });
            const root = dialogs[dialogs.length - 1] || document;
            const checkbox = [...root.querySelectorAll(
              'input[type="checkbox"],[role="checkbox"]'
            )].find(el => {
              const r = el.getBoundingClientRect();
              return r.width > 0 && r.height > 0 &&
                el.checked !== true && el.getAttribute('aria-checked') !== 'true';
            });
            if (checkbox) checkbox.click();
            """
        )
    except Exception:
        pass


def _wait_for_recovery_codes(page: Any, timeout: float = 6.0) -> tuple[bool, list[str]]:
    """Return codes only after two consecutive identical non-empty snapshots."""
    deadline = time.time() + max(0.0, float(timeout))
    screen_seen = False
    previous: tuple[str, ...] | None = None
    stable_snapshots = 0
    while True:
        present, codes = _extract_recovery_codes(page)
        if present:
            screen_seen = True
            snapshot = tuple(str(code) for code in codes if str(code or ""))
            if snapshot:
                if snapshot == previous:
                    stable_snapshots += 1
                else:
                    previous = snapshot
                    stable_snapshots = 1
                if stable_snapshots >= 2:
                    return True, list(snapshot)
            else:
                previous = None
                stable_snapshots = 0
        else:
            previous = None
            stable_snapshots = 0
        if time.time() >= deadline:
            return screen_seen, []
        time.sleep(0.25)


def _trusted_openai_action_url(value: object) -> bool:
    """Accept only HTTPS action links controlled by OpenAI/ChatGPT."""
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
    except (TypeError, ValueError):
        return False
    host = str(parsed.hostname or "").lower().rstrip(".")
    trusted_host = (
        host in {"openai.com", "chatgpt.com"}
        or host.endswith(".openai.com")
        or host.endswith(".chatgpt.com")
    )
    return (
        parsed.scheme.lower() == "https"
        and trusted_host
        and parsed.username is None
        and parsed.password is None
    )


def _reauthenticate_with_password(
    page: Any,
    target_email: str,
    password: str,
    totp_secret: str,
    log: Callable[[str], None],
    *,
    prefer_personal_workspace: bool = False,
    email_code_provider: Optional[Callable[..., str]] = None,
) -> tuple[bool, str, bool]:
    """Restore an expired ChatGPT session with password and any required MFA.

    Returns ``(authenticated, safe_error, totp_was_verified)``.  The last flag
    lets a pending seed be promoted only after both a real MFA challenge and an
    exact post-login identity check have succeeded.
    """
    if not password:
        return False, "本地没有可用于重新登录的已保存密码", False
    safe_log = lambda message: _log_safely(log, str(message or ""))
    email_code_baseline_ready = False
    if callable(email_code_provider):
        try:
            email_code_provider(
                email=target_email,
                timeout=1,
                prepare=True,
                exclude_codes=set(),
            )
            email_code_baseline_ready = True
        except Exception:
            # Password/TOTP login does not always require a mailbox challenge.
            # A transient mailbox failure must not block that ordinary route;
            # if OpenAI does request email verification below, fail closed
            # rather than accepting a code without a fresh message baseline.
            safe_log(
                "[账号安全] 暂时无法建立邮箱验证码基线；"
                "若本次登录追加邮箱校验将安全停止"
            )
    try:
        from platforms.chatgpt.drission_rt_acquirer import (
            _PASSWORD_INPUT_SELECTORS,
            _SWITCH_TO_PASSWORD_SELECTORS,
            _try_password_login,
            _try_selectors,
        )
        from platforms.chatgpt.drission_register import _has_existing_account_auth_error
        from platforms.chatgpt.gpt_pro_login import (
            _click_continue,
            _email_entry_state,
            _fill_email_react,
            _find_email_input,
            _gen_random_birthday,
            _gen_random_name,
            _handle_workspace_chooser,
            _on_workspace_chooser,
            _open_login_modal,
            _submit_about_you_with_retry,
            _wait_page_ready,
        )
        from platforms.chatgpt.password_login_transition import (
            snapshot as _login_transition_snapshot,
            guarded_continue as _guarded_email_continue,
        )
        error_reasons = {
            "network": "登录页面报告网络连接错误；尚未提交密码",
            "captcha": "登录页面要求人工安全验证；未自动处理验证挑战",
            "rate_limited": "登录页面提示尝试过于频繁；已停止继续提交",
            "auth_rejected": "登录页面明确拒绝当前账号；尚未提交密码",
            "invalid_email": "登录页面提示邮箱无效；已停止继续提交",
            "unknown": "登录页面显示错误，但未提供可确认的错误类型；尚未提交密码",
        }

        def navigation_error(state: dict[str, Any]) -> str:
            _raise_for_auth_login_page_error(page)
            page_error = state.get("error")
            reason = error_reasons.get(page_error, "")
            if state.get("page_kind") == "untrusted":
                page_error = "untrusted"
                reason = "登录页面已离开受信任的 OpenAI 登录地址；未填写或提交密码"
            if reason:
                safe_log(f"[账号安全] {reason}")
                _emit_security_progress(status="failed", code="password_login_page_error",
                                        reason=reason, retry_mode="manual")
                _record_security_retry_failure(
                    "auth_rejected" if page_error == "auth_rejected"
                    else "configuration_required" if page_error in {"invalid_email", "captcha", "untrusted"}
                    else "network_temporary" if page_error == "network" else "controls_unavailable",
                    page,
                )
            return reason

        page.get(CHATGPT_HOME, timeout=30)
        time.sleep(1.0)
        initial_error = navigation_error(_login_transition_snapshot(page))
        if initial_error:
            return False, initial_error, False
        safe_log("[账号安全] 打开独立登录页面，准备确认账号邮箱；尚未提交密码")
        if not _open_login_modal(page, safe_log, attempts=4):
            _record_security_retry_failure("controls_unavailable", page)
            return False, "会话失效且无法打开 ChatGPT 登录表单", False
        opened_error = navigation_error(_login_transition_snapshot(page))
        if opened_error:
            return False, opened_error, False
        email_box = _find_email_input(page, timeout=8)
        email_entry_state = _email_entry_state(page)
        if email_box is None and email_entry_state not in {
            "otp",
            "password",
            "advanced",
        }:
            _record_security_retry_failure("controls_unavailable", page)
            return False, "会话失效且登录页没有邮箱输入框", False
        if email_box is not None:
            _wait_page_ready(page, timeout=8, min_wait=0.5)
            email_filled = _fill_email_react(
                page,
                email_box,
                target_email,
                safe_log,
                retries=3,
                settle=0.5,
            )
            email_entry_state = _email_entry_state(page)
            filled_error = navigation_error(_login_transition_snapshot(page))
            if filled_error:
                return False, filled_error, False
            if not email_filled and email_entry_state not in {
                "otp",
                "password",
                "advanced",
            }:
                _record_security_retry_failure("controls_unavailable", page)
                return False, "会话失效且登录页未能可靠填写账号邮箱", False
            if email_filled and email_entry_state in {"email", "unknown"}:
                if not _click_continue(page):
                    # React can replace the email form while the click helper is
                    # resolving its control.  Re-read the semantic route before
                    # declaring failure; never submit the email a second time once
                    # OTP/password/a later page is observable.
                    email_entry_state = _email_entry_state(page)
                    if email_entry_state not in {"otp", "password", "advanced"}:
                        _record_security_retry_failure("controls_unavailable", page)
                        return False, "会话失效且登录页无法提交账号邮箱", False
                else:
                    safe_log("[账号安全] 已点击首次邮箱继续，等待页面实际跳转；尚未提交密码")
        if email_entry_state in {"otp", "password", "advanced"}:
            safe_log(
                "[账号安全] 邮箱输入阶段已进入后续登录页面，"
                "未重复填写或提交邮箱"
            )

        # An email submit can open a second email/identity-provider page.
        # Observe the current page, not just a password selector. A guarded
        # email continuation is bounded and may never restart the deadline or
        # run after any later authentication stage has already been observed.
        route_deadline = time.time() + 75
        password_input = None
        next_email_advance_at = time.time() + 10
        email_advance_attempts = 0
        later_route_seen = email_entry_state in {"otp", "password", "advanced"}
        next_switch_at = 0.0
        switch_attempts = 0
        last_diagnostic = None
        next_diagnostic_at = 0.0
        route = "unknown"
        page_state: dict[str, Any] = {}
        route_labels = {
            "email": "邮箱输入或登录中转页",
            "otp": "邮箱验证码页（等待明确的密码登录入口）",
            "password": "密码输入页",
            "authenticator": "Authenticator 动态码页",
            "advanced": "后续登录页面",
            "unknown": "尚未识别的页面",
        }
        ready_labels = {
            "loading": "加载中", "interactive": "页面已解析", "complete": "加载完成",
            "unknown": "加载状态未知",
        }
        while time.time() < route_deadline:
            email_entry_state = _email_entry_state(page)
            page_state = _login_transition_snapshot(page)
            observed_route = {"email_otp": "otp"}.get(page_state.get("route"), page_state.get("route"))
            # Either independent reader seeing a later stage is sufficient to
            # prohibit another email submit. Neither reader proves login.
            route = next((item for item in ("authenticator", "advanced", "password", "otp")
                          if item in {email_entry_state, observed_route}),
                         observed_route if observed_route in {"email", "unknown"} else email_entry_state)
            later_route_seen = later_route_seen or route in {"otp", "password", "advanced", "authenticator"}
            page_error = page_state.get("error", "")
            detected_error = navigation_error(page_state)
            if detected_error:
                return False, detected_error, False
            diagnostic = (route, page_error, page_state.get("ready_state"),
                          page_state.get("busy"), page_state.get("email_count"),
                          page_state.get("password_count"), page_state.get("continue_count"))
            now = time.time()
            if diagnostic != last_diagnostic or now >= next_diagnostic_at:
                # Every fragment comes from a fixed label or bounded count;
                # do not log URLs, form values, DOM text or browser exceptions.
                def count_label(key: str) -> str:
                    value = page_state.get(key)
                    return str(value) if type(value) is int and 0 <= value <= 100 else "未知"
                reason = (
                    f"当前为{route_labels.get(route, route_labels['unknown'])}；"
                    + ("页面状态读取暂时失败" if page_error == "unreadable"
                       else ready_labels.get(page_state.get("ready_state"), "加载状态未知"))
                    + f"；邮箱框 {count_label('email_count')}，密码框 {count_label('password_count')}"
                    + ("；页面操作正在处理中" if page_state.get("busy") is True else "")
                    + "；尚未提交密码"
                )
                safe_log(f"[账号安全] {reason}")
                _emit_security_progress(code="password_login_email_transition" if route == "email"
                                        else "password_login_route_uncertain",
                                        reason=reason, retry_mode="none",
                                        retry_attempt=email_advance_attempts,
                                        retry_limit=2 if email_advance_attempts else 0)
                last_diagnostic = diagnostic
                next_diagnostic_at = now + 15
            if route == "authenticator":
                reason = ("登录页面要求 Authenticator，但本地没有原密钥；尚未提交密码"
                          if not totp_secret else "页面已进入 Authenticator 验证，但本次尚无密码提交证据")
                _record_security_retry_failure("credentials_missing" if not totp_secret else "controls_unavailable")
                return False, reason, False
            if route == "advanced":
                # ``advanced`` is only an anti-resubmission signal.  Even an
                # authenticated landing page cannot prove that this invocation
                # submitted the candidate password, so never promote it to a
                # configured password here.
                identity = _session_identity(page)
                if identity.get("authenticated"):
                    if _normalise_email(identity.get("email")) != _normalise_email(target_email):
                        _record_security_retry_failure("identity_mismatch")
                        return False, "页面进入后续登录阶段，但账号身份与目标账号不一致", False
                    _record_security_retry_failure("controls_unavailable", page)
                    return False, "页面已进入后续登录阶段，但本次没有可核验的密码提交证据", False
            password_input, _ = _try_selectors(
                page,
                _PASSWORD_INPUT_SELECTORS,
                per_timeout=0.35,
            )
            if password_input is not None:
                break
            now = time.time()
            if now >= route_deadline:
                break
            if (not later_route_seen and page_state.get("route") == "email"
                    and page_state.get("ready_state") == "complete"
                    and page_state.get("busy") is False and page_state.get("email_count") == 1
                    and not page_error and email_advance_attempts < 2 and now >= next_email_advance_at):
                email_advance_attempts += 1
                # Count attempts, including refused/raced clicks; a changing
                # DOM must not grant an unlimited retry budget.
                next_email_advance_at = now + 10
                reason = f"仍停在邮箱输入或登录中转页，正在核对邮箱并继续（补充推进 {email_advance_attempts}/2）"
                safe_log(f"[账号安全] {reason}")
                _emit_security_progress(status="retrying", code="password_login_email_transition",
                                        reason=reason, retry_mode="auto_local",
                                        retry_attempt=email_advance_attempts, retry_limit=2)
                email_box = _find_email_input(page, timeout=min(2, max(0.1, route_deadline - time.time())))
                if email_box is None:
                    continue
                filled = _fill_email_react(page, email_box, target_email, safe_log, retries=3, settle=0.5)
                after = _login_transition_snapshot(page)
                after_error = navigation_error(after)
                if after_error:
                    return False, after_error, False
                after_legacy = _email_entry_state(page)
                if (after.get("route") in {"email_otp", "password", "authenticator", "advanced"}
                        or after_legacy in {"otp", "password", "advanced"}):
                    later_route_seen = True
                    safe_log("[账号安全] 邮箱确认期间页面已进入后续阶段，未再次点击邮箱继续")
                    continue
                if not filled:
                    reason = "登录邮箱中转页的邮箱填写未通过回读确认，未点击继续；尚未提交密码"
                    _emit_security_progress(status="failed", code="password_login_email_transition_failed",
                                            reason=reason, retry_mode="verify_first")
                    _record_security_retry_failure("controls_unavailable", page)
                    return False, reason, False
                if time.time() >= route_deadline:
                    break
                click_result = _guarded_email_continue(page, target_email)
                next_email_advance_at = time.time() + 10
                if click_result == "clicked":
                    safe_log("[账号安全] 已核对唯一邮箱表单并点击继续，等待实际跳转；尚未提交密码")
                elif click_result == "error":
                    reason = "登录邮箱继续操作发生错误或返回结果无法确认，已停止再次提交；尚未提交密码"
                    _emit_security_progress(status="failed", code="password_login_email_transition_failed",
                                            reason=reason, retry_mode="verify_first")
                    _record_security_retry_failure("controls_unavailable", page)
                    return False, reason, False
                else:
                    safe_log("[账号安全] 邮箱继续未执行：页面已变化、尚未就绪或无法安全确认唯一控件；继续观察，不强制点击")
                continue
            # A password-method switch is also a page action, not proof of a
            # transition; throttle it and never retry it indefinitely.
            if now >= next_switch_at and switch_attempts < 2:
                next_switch_at = time.time() + 3
                switch, _ = _try_selectors(page, _SWITCH_TO_PASSWORD_SELECTORS, per_timeout=0.15)
                switched = False
                if switch is not None:
                    switch_attempts += 1
                    next_switch_at = time.time() + 10
                    try:
                        switch.click()
                        switched = True
                    except Exception:
                        pass
                elif _click_text(
                    page,
                    (
                        "使用密码继续",
                        "使用密码",
                        "改用密码",
                        "输入密码",
                        "continue with password",
                        "use your password",
                        "use password",
                        "sign in with password",
                    ),
                ):
                    switch_attempts += 1
                    next_switch_at = time.time() + 10
                    switched = True
                if switched:
                    safe_log("[账号安全] 已点击明确的密码登录入口，等待密码输入框")
                    time.sleep(0.8)
                    continue
            time.sleep(0.3)
        if password_input is None:
            reason = (
                "登录邮箱仍未完成跳转，等待期限内没有出现密码输入页；尚未提交密码"
                if route == "email" else
                "登录页面停在邮箱验证码页，等待期限内未出现密码登录入口；未用邮箱验证码替代密码核验"
                if route == "otp" else
                "登录页面状态一直无法读取，无法确认密码入口；尚未提交密码"
                if page_state.get("error") == "unreadable" else
                "登录页面在75秒等待期限内未出现可确认的密码输入页；尚未提交密码"
            )
            _emit_security_progress(status="failed", code="password_login_email_transition_failed"
                                    if route == "email" else "password_login_route_missing",
                                    reason=reason, retry_mode="verify_first")
            _record_security_retry_failure("controls_unavailable", page)
            return False, reason, False
        password_diagnostic: dict[str, Any] = {}

        def on_password_diagnostic(value: dict[str, Any]) -> None:
            password_diagnostic.update(value)
            _emit_security_progress(
                status=value["status"], code=value["code"], reason=value["reason"],
                retry_mode="auto_local" if value["status"] == "retrying" else "verify_first",
                retry_attempt=value["retry_attempt"], retry_limit=value["retry_limit"],
            )

        _raise_for_auth_login_page_error(page)
        password_login_started = _try_password_login(
            page,
            password,
            safe_log,
            diagnostic_fn=on_password_diagnostic,
        )
        if not password_login_started:
            if password_diagnostic.get("code") in {
                "password_login_input_missing", "password_login_input_failed",
                "password_login_submit_missing",
                "password_login_input_stale", "password_login_submit_stale",
            }:
                _record_security_retry_failure("controls_unavailable", page)
            return False, password_diagnostic.get("reason") or "密码验证登录未能完成密码填写或提交", False
        if password_diagnostic.get("code") != "password_login_submitted":
            # A route transition can race a stale DOM operation.  It is useful
            # for deciding what page to observe next, but it cannot prove that
            # this invocation actually submitted the saved candidate password.
            # Fail closed so an existing browser session or unrelated redirect
            # can never promote an unverified candidate to ``configured``.
            _record_security_retry_failure("controls_unavailable")
            _emit_security_progress(
                status="review",
                code="password_login_submission_unverified",
                reason="密码登录页面已变化，但本次密码提交没有可核验凭据",
                retry_mode="verify_first",
            )
            return False, "密码登录页面已变化，但本次密码提交没有可核验凭据", False

        deadline = time.time() + 45
        totp_verified = False
        email_otp_verified = False
        workspace_selection_started = False
        profile_completion_attempted = False
        while time.time() < deadline:
            _raise_for_auth_login_page_error(page)
            # A password-first registration can be interrupted after the
            # password was accepted but before its /about-you profile was
            # submitted.  A later clean password login then returns to that
            # exact page.  Treat it as a resumable registration checkpoint;
            # otherwise this loop waits for an identity that OpenAI will not
            # create until the profile form is completed.
            try:
                current = urllib.parse.urlsplit(str(getattr(page, "url", "") or ""))
                on_about_you = (
                    current.scheme.lower() == "https"
                    and str(current.hostname or "").lower().rstrip(".") == "auth.openai.com"
                    and current.port in (None, 443)
                    and current.username is None
                    and current.password is None
                    and re.match(r"^/about-you(?:/|$)", current.path or "") is not None
                )
            except (TypeError, ValueError):
                on_about_you = False
            if on_about_you:
                if _has_existing_account_auth_error(page):
                    # The password login itself has already been submitted.
                    # Some partially-created accounts return an explicit
                    # user_already_exists error on their stale /about-you
                    # continuation even though the existing-account session
                    # is now valid.  Leave that signup continuation and accept
                    # it only after the normal exact identity probe succeeds.
                    safe_log("[账号安全] 密码已通过，旧注册资料页已失效，正在转入现有账号会话")
                    try:
                        try:
                            page.get(CHATGPT_HOME, timeout=30, retry=0)
                        except TypeError:
                            page.get(CHATGPT_HOME, timeout=30)
                    except Exception as exc:
                        _record_security_network_failure(exc, page)
                    time.sleep(1.0)
                    existing_identity = _session_identity(page)
                    if existing_identity.get("authenticated"):
                        if _normalise_email(existing_identity.get("email")) != _normalise_email(target_email):
                            _record_security_retry_failure("identity_mismatch")
                            return False, "现有账号会话身份与目标账号不一致", totp_verified
                        return True, "", totp_verified
                    return False, "密码已通过，但旧注册资料页失效且现有账号会话尚未建立", totp_verified
                if profile_completion_attempted:
                    return False, "密码已通过，但账号资料页面自动补全后仍未继续", totp_verified
                profile_completion_attempted = True
                safe_log("[账号安全] 密码已通过，正在自动补全中断的账号资料")
                _emit_security_progress(
                    "password_verify", status="retrying", code="password_login_profile_resume",
                    reason="密码已通过，正在自动补全中断的账号资料",
                    retry_mode="auto_local", retry_attempt=1, retry_limit=1,
                )
                if not _submit_about_you_with_retry(
                    page, _gen_random_name(), _gen_random_birthday(), safe_log,
                    allow_existing_login_context=True,
                ):
                    _record_security_retry_failure("controls_unavailable", page)
                    return False, "密码已通过，但账号资料页面自动补全失败", totp_verified
                # Profile submission can lead to a workspace chooser before
                # the authenticated session becomes readable.
                deadline = max(deadline, time.time() + 45)
                continue
            # Multi-workspace accounts can land on this chooser immediately
            # after the Authenticator challenge.  Handle it inside the loop:
            # waiting until this helper returns would otherwise deadlock the
            # outer login flow for the full authentication timeout.
            if _on_workspace_chooser(page):
                if not workspace_selection_started:
                    workspace_selection_started = _handle_workspace_chooser(
                        page,
                        safe_log,
                        prefer_personal=prefer_personal_workspace,
                    )
                    if workspace_selection_started:
                        # A successful click is not proof that navigation has
                        # committed.  Keep one bounded transition window, but do
                        # not click another workspace row while the first action
                        # may still be in flight.
                        deadline = max(deadline, time.time() + 45)
                time.sleep(0.75)
                continue
            if choose_authenticator_login_method(page):
                time.sleep(0.4)
            if is_authenticator_challenge(page):
                if not totp_secret:
                    _record_security_retry_failure("credentials_missing")
                    return False, "重新登录要求 Authenticator，但本地没有对应密钥", False
                if not complete_authenticator_challenge(
                    page,
                    totp_secret,
                    safe_log,
                    timeout=min(20, max(1, int(deadline - time.time()))),
                ):
                    return False, "重新登录的 Authenticator 验证未通过", False
                totp_verified = True
            if (
                not email_otp_verified
                and not is_authenticator_challenge(page)
                and _is_email_verification_challenge(page)
            ):
                if not callable(email_code_provider) or not email_code_baseline_ready:
                    return (
                        False,
                        "密码已通过，但 OpenAI 还要求邮箱验证码，当前账号没有可用的新邮件基线",
                        False,
                    )
                safe_log("[账号安全] 密码已提交，OpenAI 要求再验证一次邮箱验证码")
                email_code = ""
                try:
                    email_code = str(
                        email_code_provider(
                            email=target_email,
                            timeout=120,
                            prepare=False,
                            exclude_codes=set(),
                        )
                        or ""
                    ).strip()
                    if not re.fullmatch(r"\d{6}", email_code):
                        if not email_code:
                            _record_security_retry_failure("mail_wait_temporary", page)
                        return False, "未能从邮箱取得密码登录后的六位验证码", False
                    # Mail delivery is allowed to take longer than the normal
                    # password/TOTP route.  Give the browser a fresh transition
                    # window after the blocking mailbox poll returns.
                    deadline = max(deadline, time.time() + 45)
                    submitted, submit_error = _submit_password_verification_code(
                        page,
                        email_code,
                        timeout=min(20, max(1, int(deadline - time.time()))),
                    )
                except Exception as exc:
                    _record_security_network_failure(exc, page)
                    return False, "密码登录后的邮箱验证码处理失败", False
                finally:
                    email_code = ""
                if not submitted:
                    if submit_error in {"input_missing", "submit_unavailable", "transition_timeout"}:
                        _record_security_retry_failure("controls_unavailable", page)
                    safe_reason = {
                        "input_missing": "验证码输入框不可用",
                        "submit_unavailable": "验证码确认按钮不可用",
                        "invalid": "验证码被拒绝",
                        "expired": "验证码已过期",
                        "rate_limited": "验证尝试过于频繁",
                        "transition_timeout": "验证后页面未继续",
                    }.get(submit_error, "验证未完成")
                    return False, f"密码登录后的邮箱{safe_reason}", False
                email_otp_verified = True
                safe_log("[账号安全] 密码登录后的邮箱验证已通过")
                continue
            _raise_for_auth_login_page_error(page)
            identity = _session_identity(page)
            _raise_for_auth_login_page_error(page)
            if identity.get("authenticated"):
                actual_email = _normalise_email(identity.get("email"))
                if actual_email != _normalise_email(target_email):
                    _record_security_retry_failure("identity_mismatch")
                    return False, "重新登录后的账号身份与目标账号不一致", False
                return True, "", totp_verified
            # A protected-session 401 while the auth SPA is still navigating is
            # not a password/TOTP rejection.  Explicit page/form diagnostics
            # above retain the authority to mark a real credential rejection.
            time.sleep(0.5)
        _raise_for_auth_login_page_error(page)
        if workspace_selection_started and _on_workspace_chooser(page):
            _record_security_retry_failure("controls_unavailable", page)
            _emit_security_progress(status="review", code="password_login_timeout",
                                    reason="已选择工作空间，但等待登录跳转超时", retry_mode="verify_first")
            return False, "已选择 ChatGPT 工作区，但等待登录跳转超时", totp_verified
        _emit_security_progress(status="review", code="password_login_timeout",
                                reason="密码验证登录已提交，但等待远端认证结果超时", retry_mode="verify_first")
        _record_security_retry_failure("controls_unavailable", page)
        return False, "使用已保存密码重新登录超时", False
    except AccountDeactivatedLoginError:
        _emit_security_progress(status="failed", code="account_deactivated",
                                reason=ACCOUNT_DEACTIVATED_LOGIN_ERROR, retry_mode="manual")
        _record_security_retry_failure("auth_rejected")
        return False, ACCOUNT_DEACTIVATED_LOGIN_ERROR, False
    except Exception as exc:
        _emit_security_progress(status="failed", code="password_login_route_failed",
                                reason="密码验证登录的页面导航或网络操作失败，尚未完成身份验证", retry_mode="verify_first")
        _record_security_network_failure(exc, page)
        return (
            False,
            _safe_error(
                exc,
                known_secrets=(password, totp_secret),
            )
            or "使用已保存密码重新登录失败",
            False,
        )


def _verify_totp_with_fresh_login(
    target_email: str,
    password: str,
    totp_secret: str,
    proxy: str,
    headless: bool,
    log: Callable[[str], None],
    email_code_provider: Optional[Callable[..., str]] = None,
) -> tuple[bool, dict[str, str], str]:
    """Independently prove that both the password and new TOTP are active."""
    page = None
    try:
        from platforms.chatgpt.drission_register import create_browser

        page = create_browser(proxy=proxy or "", headless=headless)
        if page is None:
            return False, {}, "无法启动独立 2FA 复核浏览器"
        authenticated, error, totp_verified = _reauthenticate_with_password(
            page,
            target_email,
            password,
            totp_secret,
            log,
            email_code_provider=email_code_provider,
        )
        identity = _session_identity(page) if authenticated else {}
        if not (
            authenticated
            and totp_verified
            and identity.get("authenticated")
            and _normalise_email(identity.get("email"))
            == _normalise_email(target_email)
        ):
            return False, {}, error or "全新登录未出现或未通过 Authenticator 校验"
        return True, _collect_page_cookies(page), ""
    except Exception as exc:
        _record_security_network_failure(exc, page)
        return (
            False,
            {},
            _safe_error(exc, known_secrets=(password, totp_secret)),
        )
    finally:
        if page is not None:
            try:
                page.quit(force=True)
            except TypeError:
                try:
                    page.quit()
                except Exception:
                    pass
            except Exception:
                pass


def _open_login_verified_session(
    target_email: str,
    password: str,
    totp_secret: str,
    proxy: str,
    headless: bool,
    log: Callable[[str], None],
    email_code_provider: Optional[Callable[..., str]] = None,
) -> tuple[Any, bool, str]:
    """Create a cookie-clean browser and authenticate the exact identity."""
    page = None
    try:
        from platforms.chatgpt.drission_register import create_browser

        page = create_browser(proxy=proxy or "", headless=headless)
        if page is None:
            return None, False, "无法启动独立登录浏览器"
        authenticated, error, totp_verified = _reauthenticate_with_password(
            page,
            target_email,
            password,
            totp_secret,
            log,
            email_code_provider=email_code_provider,
        )
        identity = _session_identity(page) if authenticated else {}
        if not (
            authenticated
            and identity.get("authenticated")
            and _normalise_email(identity.get("email"))
            == _normalise_email(target_email)
        ):
            raise RuntimeError(error or "全新浏览器未能登录目标账号")
        return page, bool(totp_verified), ""
    except Exception as exc:
        _record_security_network_failure(exc, page)
        if page is not None:
            try:
                page.quit(force=True)
            except TypeError:
                try:
                    page.quit()
                except Exception:
                    pass
            except Exception:
                pass
        return (
            None,
            False,
            _safe_error(exc, known_secrets=(password, totp_secret)),
        )


def _open_email_otp_verified_session(
    target_email: str,
    email_code_provider: Callable[..., str],
    proxy: str,
    headless: bool,
    log: Callable[[str], None],
) -> tuple[Any, str]:
    """Create a clean, exact-identity session through a fresh email OTP.

    This recovery path is reserved for accounts whose locally staged password
    has *not* been proven against OpenAI and which do not have managed MFA.
    Reuse the raw OTP implementation here rather than the public auth
    dispatcher: the latter consults the security store again and can route a
    half-configured account back into this recovery decision.

    A successful OTP login proves only the browser session and account
    identity.  It must never promote the staged password to ``configured``;
    the caller still has to submit and independently verify that password.
    """
    if not callable(email_code_provider):
        _record_security_retry_failure("configuration_required")
        return None, "会话已失效，且该账号没有可用的邮箱验证码读取器"

    safe_log = lambda message: _log_safely(log, str(message or ""))
    page_holder: dict[str, Any] = {}

    try:
        # Take the mailbox snapshot before the login form sends a new code, so
        # a registration/password-reset OTP can never be reused accidentally.
        email_code_provider(
            email=target_email,
            timeout=1,
            prepare=True,
            exclude_codes=set(),
        )
    except Exception as exc:
        _record_security_network_failure(exc)
        return None, "无法建立登录验证码邮件基线"

    def otp_callback() -> str:
        try:
            value = str(
                email_code_provider(
                    email=target_email,
                    timeout=180,
                    prepare=False,
                    exclude_codes=set(),
                )
                or ""
            ).strip()
            if not value:
                _record_security_retry_failure("mail_wait_temporary")
            return value
        except Exception as exc:
            _record_security_network_failure(exc)
            # Mail-provider exceptions may contain credentials or response
            # payloads.  Do not propagate them into durable task logs.
            raise RuntimeError("未能从邮箱取得登录验证码") from None

    def capture_verified_page(page: Any, _result: Any) -> dict[str, Any]:
        page_holder["page"] = page
        identity = _session_identity_with_retry(page, log)
        actual_email = _normalise_email(identity.get("email"))
        if not identity.get("authenticated"):
            # A fresh OTP was already accepted at this point.  A protected
            # endpoint 401/403 can still be a delayed/revoked access token; it
            # is not evidence that the mailbox credential itself was rejected.
            # Keep this as a bounded session/control retry rather than poisoning
            # later attempts with the permanent password/TOTP blocker.
            if identity.get("origin_untrusted") is True:
                _record_security_retry_failure("identity_mismatch")
            elif not _session_probe_transient(identity):
                _record_security_retry_failure("controls_unavailable")
            return {
                "ok": False,
                "error": (
                    "邮箱验证码登录后受保护会话复核失败"
                    f"（Session HTTP {int(identity.get('status') or 0)}，"
                    f"账号接口 HTTP {int(identity.get('backend_status') or 0)}）"
                ),
            }
        if not actual_email:
            _record_security_retry_failure("insufficient_evidence")
            return {"ok": False, "error": "邮箱验证码登录后的会话未返回可核验的账号邮箱"}
        if actual_email != _normalise_email(target_email):
            _record_security_retry_failure("identity_mismatch")
            return {"ok": False, "error": "邮箱验证码登录后的账号身份不一致"}
        return {"ok": True}

    try:
        from platforms.chatgpt.gpt_pro_login import _login_with_email_otp

        result = _login_with_email_otp(
            target_email,
            otp_callback=otp_callback,
            headless=headless,
            proxy=proxy or "",
            log_fn=safe_log,
            keep_browser_open=True,
            is_signup=False,
            post_login_action=capture_verified_page,
        )
        page = page_holder.get("page")
        action_result = (
            result.action_result
            if isinstance(getattr(result, "action_result", None), dict)
            else {}
        )
        if result.ok and page is not None and action_result.get("ok") is True:
            return page, ""

        if page is not None:
            try:
                page.quit(force=True)
            except TypeError:
                try:
                    page.quit()
                except Exception:
                    pass
            except Exception:
                pass
        error = (
            action_result.get("error")
            or getattr(result, "error", "")
            or "邮箱验证码登录未能恢复有效会话"
        )
        from platforms.chatgpt.gpt_pro_login import normalize_login_failure, login_failure_reason
        failure = normalize_login_failure(getattr(result, "login_failure", None))
        if failure is not None:
            if failure["remote_dead"] is True:
                _emit_security_progress(status="failed", code="account_deactivated",
                                        reason=ACCOUNT_DEACTIVATED_LOGIN_ERROR, retry_mode="manual")
                _record_security_retry_failure("auth_rejected")
                return None, ACCOUNT_DEACTIVATED_LOGIN_ERROR
            if failure["retryable"] is True:
                reason_code = ("network_temporary" if failure["code"] in {
                    "session_read_failed", "session_http_transient", "login_transport_unavailable", "login_rate_limited",
                    "session_request_timeout", "session_network_failed", "session_browser_timeout",
                    "session_browser_disconnected",
                } else "controls_unavailable")
                _record_security_retry_failure(reason_code)
                _emit_security_progress(status="failed", code=failure["code"],
                                        reason=login_failure_reason(failure) + "；保留已有密码与 2FA，稍后核对再继续",
                                        retry_mode="verify_first")
            elif failure["code"] in {"session_identity_mismatch", "session_origin_untrusted", "login_origin_untrusted"}:
                _record_security_retry_failure("identity_mismatch")
            elif failure["code"] == "login_auth_rejected":
                _record_security_retry_failure("auth_rejected")
            else:
                _record_security_retry_failure("insufficient_evidence")
            if failure["retryable"] is False:
                _emit_security_progress(status="failed", code=failure["code"],
                                        reason=login_failure_reason(failure), retry_mode="manual")
        if (getattr(result, "stage", "") == "fill_email"
                and error == "邮箱输入框填写未通过回读确认，未提交登录"):
            _record_security_retry_failure("controls_unavailable")
        return None, _safe_error(error)
    except Exception as exc:
        _record_security_network_failure(exc)
        page = page_holder.get("page")
        if page is not None:
            try:
                page.quit(force=True)
            except TypeError:
                try:
                    page.quit()
                except Exception:
                    pass
            except Exception:
                pass
        return None, _safe_error(exc)


def _open_password_verified_session(
    target_email: str,
    password: str,
    proxy: str,
    headless: bool,
    log: Callable[[str], None],
    email_code_provider: Optional[Callable[..., str]] = None,
) -> tuple[Any, str]:
    """Create a fresh browser and prove the newly submitted password."""
    page, _totp_verified, error = _open_login_verified_session(
        target_email,
        password,
        "",
        proxy,
        headless,
        log,
        email_code_provider=email_code_provider,
    )
    return page, error


def _complete_password_setup(
    page: Any,
    password: str,
    target_email: str,
    password_link_provider: Optional[Callable[..., str]] = None,
    password_code_provider: Optional[Callable[..., str]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    *,
    confirmation_mode: str = "independent",
) -> tuple[str, str]:
    """Best-effort fallback for passwordless registration variants."""
    log = log_fn if callable(log_fn) else (lambda _message: None)
    _emit_security_progress("password_settings", reason="正在打开账户密码设置")
    # Password management moved from Account to "Security / Account security
    # and login" in the current ChatGPT settings shell.  The Security route
    # remains backward-compatible with older builds that also exposed MFA.
    if not _open_settings_section(page, "security"):
        _record_security_retry_failure("controls_unavailable", page)
        return "unknown", "无法打开 ChatGPT 账户安全与登录设置"

    # A password OTP must reject every message that existed before the
    # password row was clicked.  Ask the process-local mailbox adapter to take
    # that snapshot now; it retains no credentials in the account payload.
    if callable(password_code_provider):
        try:
            password_code_provider(
                email=target_email,
                timeout=1,
                prepare=True,
                exclude_codes=set(),
            )
        except Exception as exc:
            _record_security_network_failure(exc)
            return "unknown", "无法建立密码验证码邮件基线"
    clicked = _click_password_setting(page)
    if not clicked:
        text = _visible_text(page, 5000).lower()
        if "update password" in text or "更新密码" in text:
            return "unknown", "账号已有密码，但当前流程无法验证密码是否与本地一致"
        _record_security_retry_failure("controls_unavailable", page)
        return "failed", "未找到添加密码入口"
    _emit_security_progress("password_settings", status="completed", reason="已打开密码设置入口")
    # Add Password starts a cross-origin re-authentication.  Do not sample the
    # URL only once: on a slower connection the settings page can remain
    # visible briefly before auth.openai.com commits the navigation.
    current_url = ""
    text = ""
    transition_deadline = time.time() + 12
    transition_observed = False
    while time.time() < transition_deadline:
        time.sleep(0.35)
        text = _visible_text(page, 5000).lower()
        try:
            current_url = str(getattr(page, "url", "") or "").lower()
        except Exception:
            current_url = ""
        try:
            password_fields_visible = bool(
                page.run_js(
                    r"""
                    const visible = (el) => {
                      const r = el.getBoundingClientRect();
                      const s = getComputedStyle(el);
                      return r.width > 0 && r.height > 0 &&
                        s.display !== 'none' && s.visibility !== 'hidden';
                    };
                    return [...document.querySelectorAll('input[type="password"]')]
                      .some(visible);
                    """
                )
            )
        except Exception:
            password_fields_visible = False
        if (
            "/email-verification" in current_url
            or "/log-in/code" in current_url
            or "/reset-password/" in current_url
            or password_fields_visible
            or any(
                term in text
                for term in (
                    "check your email",
                    "email sent",
                    "查看您的邮箱",
                    "检查你的收件箱",
                    "邮件已发送",
                )
            )
        ):
            transition_observed = True
            break

    if not transition_observed:
        _record_security_retry_failure("controls_unavailable", page)
        return "link_required", "已点击密码设置入口，但等待后未出现验证页或可填写的密码表单"

    # Current UI: Password -> email-verification (six-digit OTP) -> password
    # form.  This is different from the older email action-link flow below.
    if "/email-verification" in current_url or "/log-in/code" in current_url:
        _emit_security_progress("password_email", reason="正在验证密码设置邮件")
        if not callable(password_code_provider):
            return "code_required", "OpenAI 要求邮箱验证码后才能设置密码"
        excluded_codes: set[str] = set()
        failure_kind = ""
        verified = False
        for code_attempt in range(2):
            email_code = ""
            try:
                email_code = str(
                    password_code_provider(
                        email=target_email,
                        timeout=120,
                        prepare=False,
                        exclude_codes=set(excluded_codes),
                    )
                    or ""
                ).strip()
                if not re.fullmatch(r"\d{6}", email_code):
                    if not email_code:
                        _record_security_retry_failure("mail_wait_temporary", page)
                    return "code_required", "邮箱未返回有效的六位密码设置验证码"
                _log_safely(
                    log,
                    "[账号安全] 已取得密码设置验证码，正在提交"
                    + (f"（第 {code_attempt + 1}/2 次）" if code_attempt else ""),
                )
                verified, failure_kind = _submit_password_verification_code(
                    page,
                    email_code,
                )
                if verified:
                    break
                excluded_codes.add(email_code)
            except Exception as exc:
                _record_security_network_failure(exc, page)
                return "code_required", "未能从邮箱取得密码设置验证码"
            finally:
                # Do not retain even a short-lived OTP in local variables
                # longer than this transition requires.
                email_code = ""

            if code_attempt == 0 and failure_kind != "rate_limited":
                try:
                    password_code_provider(
                        email=target_email,
                        timeout=1,
                        prepare=True,
                        exclude_codes=set(excluded_codes),
                    )
                except Exception:
                    return "code_required", "重新发送前无法建立新的验证码邮件基线"
                resent = _click_text(
                    page,
                    (
                        "resend code",
                        "send again",
                        "resend",
                        "重新发送验证码",
                        "重新发送",
                        "再发一次",
                    ),
                )
                if resent:
                    _emit_security_progress("password_email", status="retrying", code="password_email_retry",
                                            reason="密码设置邮件验证码未完成跳转，已重新发送并安全重试一次",
                                            retry_mode="auto_local", retry_attempt=1, retry_limit=1)
                    _log_safely(
                        log,
                        "[账号安全] 首次密码验证码未完成页面跳转，已重新发送并安全重试一次",
                    )
                    time.sleep(0.8)
                    continue
            break

        if not verified:
            if failure_kind in {"input_missing", "submit_unavailable", "transition_timeout"}:
                _record_security_retry_failure("controls_unavailable", page)
            failure_messages = {
                "input_missing": "密码设置验证码页面没有可交互的输入框",
                "submit_unavailable": "密码设置验证码已填写，但确认按钮不可用",
                "invalid": "密码设置验证码被 OpenAI 页面拒绝",
                "expired": "密码设置验证码已过期",
                "rate_limited": "密码设置验证码尝试过于频繁，请稍后重试",
                "transition_timeout": "密码设置验证码提交后页面未进入下一步",
            }
            return "code_required", failure_messages.get(
                failure_kind,
                "密码设置验证码未通过或页面未进入下一步",
            )

        _emit_security_progress("password_email", status="completed", reason="密码设置邮件验证码已通过")
        text = _visible_text(page, 5000).lower()
    elif any(
        term in text
        for term in (
            "check your email",
            "email sent",
            "查看您的邮箱",
            "检查你的收件箱",
            "邮件已发送",
        )
    ):
        _emit_security_progress("password_email", reason="正在验证密码设置邮件链接")
        if not callable(password_link_provider):
            return "link_required", "OpenAI 要求通过邮件中的链接完成密码设置"
        try:
            action_url = str(
                password_link_provider(email=target_email, timeout=120) or ""
            ).strip()
        except Exception:
            return "link_required", "未能从邮箱取得 OpenAI 密码设置链接"
        if not _trusted_openai_action_url(action_url):
            return "link_required", "邮箱返回的密码设置链接不是可信 OpenAI HTTPS 地址"
        try:
            page.get(action_url, timeout=30)
            time.sleep(1.0)
        except Exception:
            return "link_required", "无法打开 OpenAI 密码设置链接"
        if not _trusted_openai_action_url(getattr(page, "url", "")):
            return "link_required", "密码设置链接跳转到了非 OpenAI 地址，已停止填写密码"
        _emit_security_progress("password_email", status="completed", reason="已打开可信密码设置邮件链接")
    _emit_security_progress("password_submit", reason="正在填写新密码表单")
    # A success banner that predates this submission cannot prove acceptance
    # of this exact password. Only this private mode can use an in-page result.
    in_session = confirmation_mode == "in_session"
    prior_success = in_session and _password_submission_status(page) == "success"
    submitted, submit_error = _fill_and_submit_new_password_form(
        page,
        password,
        log,
    )
    if not submitted:
        tracker = _SECURITY_PROGRESS.get()
        if tracker is not None and tracker.submission_started:
            if in_session:
                return "pending", "密码提交已尝试，但当前页面未确认结果；已保留原密码，未启动其他登录"
            return "unknown", "密码提交已尝试，但未能确认请求结果，必须先独立登录验证"
        if "当前密码" in submit_error:
            return "unknown", submit_error
        if "未提供" in submit_error or "结构不明确" in submit_error:
            return "link_required", submit_error
        return "failed", submit_error or "密码表单提交失败"
    _emit_security_progress("password_submit", status="completed", reason="密码提交已发出；尚未确认密码可用")
    deadline = time.time() + 8
    while time.time() < deadline:
        state = _password_submission_status(page)
        if state == "error":
            return "failed", "OpenAI 页面拒绝了密码设置"
        if state == "success":
            if in_session:
                if not prior_success and _trusted_openai_action_url(getattr(page, "url", "")):
                    return "configured", ""
                time.sleep(0.3)
                continue
            # A toast or the old browser session only proves that the UI
            # accepted the click. The caller must still prove this exact
            # password with a fresh cookie-free login before persisting it as
            # configured or starting MFA enrollment.
            return "unknown", "密码已提交，等待全新浏览器登录复核"
        prior_success = False
        time.sleep(0.3)
    if in_session:
        return "pending", "密码已提交，但当前页面没有返回明确成功结果；已保留原密码，未启动其他登录"
    return "unknown", "密码已提交，但页面没有返回明确结果，等待全新浏览器登录复核"


@dataclass
class ChatGptSecuritySetupResult:
    ok: bool
    email: str
    password_state: str = "unknown"
    mfa_state: str = "unknown"
    has_password: bool = False
    has_totp: bool = False
    error: str = ""
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    security_progress: dict[str, Any] = field(default_factory=_security_progress_snapshot)

    def safe_dict(self) -> dict:
        from services.chatgpt_security_progress import normalize_security_progress
        return {
            "ok": self.ok,
            "email": self.email,
            "password_state": self.password_state,
            "mfa_state": self.mfa_state,
            "has_password": self.has_password,
            "has_totp": self.has_totp,
            "error": _safe_error(self.error),
            "security_progress": normalize_security_progress(self.security_progress),
        }


def _confirm_pending_totp_disabled(page: Any, email: str, log: Callable[[str], None]) -> None:
    """Read-only recovery gate for an enrollment interrupted before seed save.

    A persisted ``pending`` marker is not proof of enabled MFA. Equally, a
    successful password login is not proof that MFA is disabled. Require both
    an exact authenticated identity and an explicitly disabled settings row,
    twice, before allowing the existing enrollment path to run again. This
    helper never clicks enable, disables MFA, or clears the durable marker.
    """
    target = _normalise_email(email)
    _emit_security_progress(
        "totp_settings", reason="上次启用结果待确认且未保存密钥，正在只读核对远端 2FA 状态",
        retry_mode="verify_first",
    )
    _log_safely(log, "[账号安全] 2FA 启用结果待确认；先核对远端状态，不直接重新绑定")
    for attempt in range(2):
        identity = _session_identity(page)
        if (identity.get("authenticated") is not True
                or _normalise_email(identity.get("email")) != target):
            _record_security_retry_failure("identity_mismatch")
            raise RuntimeError("无法确认当前登录账号身份，未重新绑定 Authenticator")
        if is_authenticator_challenge(page):
            _record_security_retry_failure("credentials_missing")
            raise RuntimeError("当前页面要求 Authenticator 动态码，但本地没有原密钥；未重新绑定")
        state = _inspect_mfa_row(page, authenticator_only=True)
        if state == "enabled":
            _record_security_retry_failure("credentials_missing")
            raise RuntimeError("远端已启用 Authenticator，但本地没有原密钥；需人工恢复，未关闭或重新绑定")
        if state != "disabled":
            _record_security_retry_failure("credentials_missing")
            raise RuntimeError("远端 Authenticator 状态尚未确认；未清除待确认状态，也未重新绑定")
        if attempt == 0:
            time.sleep(0.4)
    _log_safely(log, "[账号安全] 已核对同一账号的 Authenticator 明确未启用，可以继续设置；保留原密码")


def _require_in_session_identity(identity: dict, email: str) -> None:
    """Require the exact protected account without starting authentication."""
    if (identity.get("authenticated") is not True
            or identity.get("status") != 200 or identity.get("backend_status") != 200
            or identity.get("origin_untrusted") is True
            or _normalise_email(identity.get("email")) != email):
        if identity.get("email") and _normalise_email(identity["email"]) != email:
            _record_security_retry_failure("identity_mismatch")
        raise RuntimeError("当前会话未通过目标账号及受保护接口核对；已保留原凭据，未启动其他登录")


def _fresh_in_session_identity(page: Any, email: str, log: Callable[[str], None]) -> dict:
    """Wait briefly for a just-authenticated browser session to propagate.

    The registration/login continuation has already proved this exact account
    immediately before entering security setup. OpenAI can nevertheless make
    the protected account endpoint return a short-lived 401/403 while the new
    session is propagating. Re-read only; never log in, clear cookies, or
    mutate security until the complete identity proof is available again.
    """
    target = _normalise_email(email)
    last: dict = {}
    for attempt in range(5):
        last = _session_identity_with_retry(page, log)
        observed = _normalise_email(last.get("email"))
        if observed and observed != target:
            _require_in_session_identity(last, target)
        if (last.get("authenticated") is True
                and last.get("status") == 200
                and last.get("backend_status") == 200
                and last.get("origin_untrusted") is not True
                and observed == target):
            return last
        if last.get("origin_untrusted") is True:
            break
        if attempt < 4:
            _log_safely(
                log,
                f"[账号安全] 新登录会话尚未在受保护接口生效，"
                f"保留当前浏览器第 {attempt + 1}/4 次只读重核",
            )
            time.sleep(1.0 + attempt * 0.5)
    _require_in_session_identity(last, target)
    return last


def _in_session_authenticator_state(page: Any, email: str, log: Callable[[str], None]) -> str:
    """Read the named Authenticator row in the same authenticated browser."""
    # Immediately after registration the Settings shell can remain bound to a
    # partial account bootstrap: its title/password row renders while the exact
    # Authenticator control never appears in that document. Polling the same
    # DOM cannot recover it, so reload once and reopen Security in this same
    # authenticated browser. Never infer state from a generic MFA/SMS row.
    for load_attempt in range(2):
        if not _open_settings_section(page, "security"):
            _record_security_retry_failure("controls_unavailable", page)
            return "unknown"
        _fresh_in_session_identity(page, email, log)
        state = "unknown"
        for attempt in range(12):
            state = _inspect_mfa_row(page, authenticator_only=True)
            if state != "unknown":
                return state
            if attempt < 11:
                time.sleep(0.5)
        if load_attempt == 0:
            _log_safely(log, "[账号安全] Authenticator 控件尚未加载，刷新当前会话后重新打开 Security")
            try:
                page.refresh()
            except Exception:
                break
            time.sleep(0.8)
    _record_security_retry_failure("controls_unavailable", page)
    return "unknown"


def _guard_pending_totp_recovery(email: str, snapshot: dict[str, Any], password: str, seed: str) -> None:
    """Fence recovery against a replaced credential or an expired worker lease."""
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets, get_chatgpt_security_status, renew_chatgpt_security_lease,
    )
    owner = _SECURITY_LEASE_OWNER.get()
    if (owner is None or owner[0] != email or not renew_chatgpt_security_lease(
            email, owner[1], ttl_seconds=_SECURITY_DB_LEASE_SECONDS)):
        raise RuntimeError("安全设置任务的执行权已变化，未继续启用或替换 Authenticator 密钥")
    current = get_chatgpt_security_status(email)
    fields = ("updated_at", "password_updated_at", "mfa_updated_at", "password_state", "mfa_state")
    if (current.get("mfa_state") != "pending" or current.get("has_recovery_codes")
            or any(current.get(key) != snapshot.get(key) for key in fields)):
        raise RuntimeError("原待确认安全记录已变化，未继续启用或替换 Authenticator 密钥")
    material = get_chatgpt_security_secrets(email)
    if material.get("password") != password or material.get("totp_secret") != seed:
        raise RuntimeError("原待确认凭据已变化，未继续启用或替换 Authenticator 密钥")


def _confirm_in_session_pending_totp_disabled(
    page: Any, email: str, log: Callable[[str], None], snapshot: dict[str, Any], password: str, seed: str,
) -> None:
    """Permit unfinished enrollment only after two exact, protected disabled reads."""
    for attempt in range(2):
        _guard_pending_totp_recovery(email, snapshot, password, seed)
        _fresh_in_session_identity(page, email, log)
        if _inspect_mfa_row(page, authenticator_only=True) != "disabled":
            raise RuntimeError("Authenticator 状态在恢复前发生变化；已保留原密钥，未继续启用")
        _guard_pending_totp_recovery(email, snapshot, password, seed)
        if attempt == 0:
            time.sleep(0.4)
    _log_safely(log, "[账号安全] 同一账号已两次确认 Authenticator 尚未启用，自动继续未完成的设置")


def _confirm_in_session_totp_enabled(
    page: Any, email: str, log: Callable[[str], None], *, attempts: int = 2,
) -> bool:
    """Require durable post-reload evidence before recording MFA as enabled."""
    for attempt in range(max(1, int(attempts))):
        try:
            page.refresh()
        except Exception:
            return False
        time.sleep(0.8 if attempt == 0 else 0.4)
        if _in_session_authenticator_state(page, email, log) != "enabled":
            return False
    return True


def _configure_registered_account_security_unlocked(
    *,
    email: str,
    password: str,
    password_set_proven: bool,
    cookies: object = None,
    session_token: str = "",
    proxy: str = "",
    headless: bool = True,
    enable_totp: bool = True,
    log_fn: Optional[Callable[[str], None]] = None,
    page: Any = None,
    page_factory: Optional[Callable[[], Any]] = None,
    password_link_provider: Optional[Callable[..., str]] = None,
    password_code_provider: Optional[Callable[..., str]] = None,
    progress_fn: Optional[Callable[[dict[str, Any]], None]] = None,
    verified_unsubmitted_password: VerifiedUnsubmittedPasswordEvidence | None = None,
    confirmation_mode: str = "independent",
) -> ChatGptSecuritySetupResult:
    """Ensure a newly-created ChatGPT account has a known password and TOTP.

    The TOTP seed is persisted as ``pending`` *before* the first code is
    submitted.  This ordering prevents an interrupted process from enabling
    MFA remotely while losing the only copy of the seed.

    ``in_session`` is an internal preparation policy: the caller owns initial
    authentication, while this function confirms mutations in that same
    session and never opens a second browser for password or MFA verification.
    """
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets,
        get_chatgpt_security_status,
        stage_chatgpt_password,
        stage_chatgpt_recovery_codes,
        stage_chatgpt_totp,
        update_chatgpt_security_state,
    )

    if not isinstance(confirmation_mode, str) or confirmation_mode not in {"independent", "in_session"}:
        raise ValueError("账号安全确认模式无效")
    in_session = confirmation_mode == "in_session"
    if in_session:
        password_set_proven = password_set_proven is True
    caller_proven_password = password if password_set_proven is True else ""
    target_email = _normalise_email(email)
    log = log_fn if callable(log_fn) else (lambda _message: None)
    password_state = "configured" if password_set_proven else "pending"
    mfa_state = "unknown"
    owns_page = False
    working_page = page
    _emit_security_progress("session_check", reason="正在检查登录会话与目标账号身份")

    if not target_email or not password:
        _record_security_retry_failure("configuration_required")
        error = "账号邮箱或待设置密码为空"
        if target_email:
            update_chatgpt_security_state(target_email, password_state="failed", last_error=error)
        return ChatGptSecuritySetupResult(False, target_email, "failed", "unknown", error=error)

    # Preserve a previously verified password.  Manual retries may receive a
    # stale legacy AccountModel password; replacing the known-good encrypted
    # value before even validating the browser identity could lock the user
    # out.  Brand-new/pending accounts are staged before the remote mutation
    # so the generated password survives a crash.
    preexisting_status = get_chatgpt_security_status(target_email)
    if (type(verified_unsubmitted_password) is VerifiedUnsubmittedPasswordEvidence
            and not _unsubmitted_password_candidate(
                preexisting_status, verified_evidence=verified_unsubmitted_password, email=target_email)):
        _record_security_retry_failure("insufficient_evidence")
        error = "未提交密码的原核验证据已变化，未启动登录或修改安全设置；请重新核对当前记录"
        return ChatGptSecuritySetupResult(
            False, target_email, str(preexisting_status.get("password_state") or "unknown"),
            str(preexisting_status.get("mfa_state") or "unknown"),
            preexisting_status.get("has_password") is True, preexisting_status.get("has_totp") is True, error,
        )
    preexisting_password = ""
    preexisting_totp_secret = ""
    if preexisting_status.get("has_password"):
        preexisting_secrets = get_chatgpt_security_secrets(target_email)
        preexisting_password = str(preexisting_secrets.get("password") or "")
        preexisting_totp_secret = str(preexisting_secrets.get("totp_secret") or "")
    if preexisting_password:
        password = preexisting_password
        if in_session:
            # Registration evidence belongs to the exact submitted password,
            # never a different candidate recovered from the encrypted store.
            password_set_proven = bool(caller_proven_password and caller_proven_password == password)
        password_state = str(
            preexisting_status.get("password_state") or password_state or "pending"
        )
        _log_safely(log, "[账号安全] 已保留先前安全保存的注册密码")
    else:
        stage_chatgpt_password(target_email, password, state=password_state)
        _log_safely(log, "[账号安全] 注册密码已安全保存")
    preexisting_password_state = str(
        preexisting_status.get("password_state") or ""
    ).strip().lower()
    from services.chatgpt_security_recovery import can_inspect_pending_totp
    pending_seed_inspection = bool(
        preexisting_password and can_inspect_pending_totp(preexisting_status)
    )
    if pending_seed_inspection:
        # A TOTP recovery is not a password reset. The encrypted store has
        # already recorded independent verification of this exact password.
        # Session identity is still rechecked below before opening settings.
        password_set_proven = True
        password_state = "configured"
    tracker = _SECURITY_PROGRESS.get()
    if tracker is not None:
        tracker.remember_secrets(password, preexisting_totp_secret)
    # Pending ciphertext alone can be a never-submitted registration candidate.
    # Unknown (or an older pending row with explicit submission evidence) must
    # never fall back from inconclusive verification to another remote reset.
    must_verify_first = bool(preexisting_password and (
        preexisting_password_state == "unknown"
        or (preexisting_password_state == "pending" and (
            bool(preexisting_totp_secret) or any(
                marker in str(preexisting_status.get("last_error") or "")
                for marker in ("密码已提交", "密码提交")
            )
        ))
    ))
    if in_session and password_set_proven:
        must_verify_first = False
    if must_verify_first:
        password_set_proven = False
    if tracker is not None:
        tracker.capture_initial_state(
            preexisting_status, password_saved=bool(password),
            totp_saved=bool(preexisting_totp_secret), must_verify_first=must_verify_first,
        )
        tracker.unsubmitted_candidate = _unsubmitted_password_candidate(
            preexisting_status, verified_evidence=verified_unsubmitted_password, email=target_email)
    if (enable_totp and not preexisting_totp_secret
            and preexisting_status.get("mfa_state") in {"enabled", "unmanaged"}):
        _record_security_retry_failure("credentials_missing")
        error = "账号已记录启用 Authenticator，但本地没有原密钥；需补充原密钥或恢复凭据后继续"
        update_chatgpt_security_state(target_email, last_error=error)
        return ChatGptSecuritySetupResult(
            False, target_email, password_state, str(preexisting_status["mfa_state"]),
            bool(preexisting_status.get("has_password")), False, error,
        )
    staged_password_probe_eligible = bool(
        preexisting_password
        and not password_set_proven
        and not _unsubmitted_password_candidate(
            preexisting_status, verified_evidence=verified_unsubmitted_password, email=target_email)
        and preexisting_password_state
        in {"pending", "unknown", "code_required", "link_required", "failed"}
    )
    staged_password_probe_attempted = False

    cookie_map = _parse_cookie_payload(cookies)
    if session_token and not _has_session_cookie(cookie_map):
        # OpenAI has used both NextAuth and Auth.js cookie names.  A bare
        # session_token does not tell us which deployment produced it, so make
        # it available under both names; the server reads only its active name.
        cookie_map["__Secure-next-auth.session-token"] = str(session_token)
        cookie_map["__Secure-authjs.session-token"] = str(session_token)

    if not enable_totp and password_set_proven and not in_session:
        update_chatgpt_security_state(target_email, password_state="configured", mfa_state="disabled")
        return ChatGptSecuritySetupResult(True, target_email, "configured", "disabled", True, False)

    if preexisting_password and preexisting_password_state == "configured":
        # Durable independent verification of the original encrypted password
        # wins over a stale call-site flag. A usable Cookie is not a reason to
        # reset that password again; the identity/session and MFA checks below
        # still run, and an expired session logs in with this exact password.
        # Keep this below the caller-proven fast path: persisted state alone
        # must never bypass the current session/identity verification.
        password_set_proven = True
        password_state = "configured"

    try:
        if working_page is None:
            _emit_security_progress("session_check", code="browser_init_started",
                                    reason="正在启动独立浏览器并连接调试通道，尚未开始账号安全修改")
            try:
                if page_factory is not None:
                    working_page = page_factory()
                else:
                    from platforms.chatgpt.drission_register import create_browser

                    working_page = create_browser(proxy=proxy or "", headless=headless)
            except Exception as exc:
                from core.browser_startup import BrowserInitializationError
                if isinstance(exc, BrowserInitializationError):
                    clean = exc.retryable is True and exc.cleanup_complete is True
                    blocked = "remote_change_unverified" if not exc.cleanup_complete else "configuration_required"
                    _record_security_retry_failure("network_temporary" if clean else blocked)
                    if not clean and tracker is not None:
                        tracker.retry_blocker = blocked
                    _emit_security_progress("session_check", status="failed" if clean or exc.cleanup_complete else "review",
                        code="browser_init_failed" if clean else "browser_init_cleanup_pending" if not exc.cleanup_complete else "security_failed",
                        reason="浏览器初始化失败，尚未开始账号会话或安全修改" if clean else
                               "浏览器初始化失败且旧进程清理未确认，保留安全状态等待核对" if not exc.cleanup_complete else
                               "浏览器启动配置不可用，保留安全状态等待修复配置",
                        retry_mode="verify_first")
                raise
            if working_page is None:
                raise RuntimeError("无法启动安全设置浏览器")
            owns_page = True
            _emit_security_progress("session_check", reason="浏览器已启动，正在核验当前登录账号与安全状态")
            try:
                working_page.get(CHATGPT_HOME, timeout=30)
            except Exception:
                pass
            injected = _inject_cookies(working_page, cookie_map) if cookie_map else 0
            if cookie_map and injected <= 0:
                _log_safely(log, "[账号安全] Session Cookie 注入失败，将按账号安全状态恢复登录")
            try:
                working_page.get(CHATGPT_HOME, timeout=30)
            except Exception as exc:
                _record_security_network_failure(exc)
                raise
            time.sleep(1.5)

        identity = (_fresh_in_session_identity(working_page, target_email, log)
                    if in_session else _session_identity_with_retry(working_page, log))
        if in_session:
            _require_in_session_identity(identity, target_email)
        if _session_probe_transient(identity):
            raise RuntimeError("登录会话读取暂未确认，已保留现有凭据，未启动新的邮箱登录")
        if not identity.get("authenticated"):
            # This first probe validates only the injected/cached browser
            # session.  A 401/403 here commonly means that the saved Cookie or
            # access token expired; it is not evidence that the account's
            # password, TOTP, or mailbox authentication was rejected.  The
            # credential-specific recovery helpers below record
            # ``auth_rejected`` when an actual password/TOTP/login challenge is
            # explicitly rejected.
            _log_safely(
                log,
                "[账号安全] 当前会话复核未通过："
                f"Session HTTP {int(identity.get('status') or 0)}，"
                f"账号接口 HTTP {int(identity.get('backend_status') or 0)}",
            )
            login_secrets = get_chatgpt_security_secrets(target_email)
            login_password = str(login_secrets.get("password") or password or "")
            login_totp_secret = str(login_secrets.get("totp_secret") or "")
            login_status = get_chatgpt_security_status(target_email)
            effective_password_state = str(
                login_status.get("password_state") or password_state or "unknown"
            ).strip().lower()
            effective_mfa_state = str(
                login_status.get("mfa_state") or "not_configured"
            ).strip().lower()
            managed_mfa = bool(login_totp_secret) or effective_mfa_state in {
                "pending",
                "enabled",
                "unmanaged",
            }

            recovered_with_proven_password = False
            totp_verified = False
            verified_page = None
            login_error = ""
            if effective_password_state == "configured":
                _emit_security_progress("password_verify", reason="正在用独立浏览器验证已保存密码", retry_mode="verify_first")
                _log_safely(
                    log,
                    "[账号安全] 会话已失效，正在使用已确认密码重新登录",
                )
                verified_page, totp_verified, login_error = _open_login_verified_session(
                    target_email,
                    login_password,
                    login_totp_secret,
                    proxy,
                    headless,
                    log,
                    email_code_provider=password_code_provider,
                )
                recovered_with_proven_password = verified_page is not None
            elif (login_totp_secret and staged_password_probe_eligible
                  and effective_password_state in {"pending", "unknown"}):
                staged_password_probe_attempted = True
                _emit_security_progress("password_verify", reason="正在用已保存密码和原 Authenticator 密钥独立核验，不重新绑定", retry_mode="verify_first")
                verified_page, totp_verified, login_error = _open_login_verified_session(
                    target_email, login_password, login_totp_secret, proxy,
                    headless, log, email_code_provider=password_code_provider,
                )
                recovered_with_proven_password = verified_page is not None
                if not recovered_with_proven_password:
                    raise RuntimeError("已保存密码与原 2FA 核验未通过，未重设密码或重新绑定"
                                       + (f"：{login_error}" if login_error else ""))
            elif managed_mfa:
                _emit_security_progress("password_verify", status="review", code="password_verification_required",
                                        reason="账号疑似已有 2FA，但缺少可安全复核的本地凭据；未降级邮箱登录或重新绑定",
                                        retry_mode="verify_first")
                raise RuntimeError(
                    "账号已有或疑似已有 Authenticator 2FA，但本地密码尚未完成远端验证；"
                    "为防锁号，未降级到邮箱验证码登录"
                )
            elif staged_password_probe_eligible:
                staged_password_probe_attempted = True
                _emit_security_progress("password_verify", reason="正在先验证上次保存的候选密码", retry_mode="verify_first")
                _log_safely(
                    log,
                    "[账号安全] 检测到上次已保存但未确认的密码，先执行干净登录验证",
                )
                verified_page, totp_verified, login_error = _open_login_verified_session(
                    target_email,
                    login_password,
                    "",
                    proxy,
                    headless,
                    log,
                    email_code_provider=password_code_provider,
                )
                recovered_with_proven_password = verified_page is not None
                if not recovered_with_proven_password:
                    if must_verify_first:
                        raise RuntimeError(
                            "先前密码提交结果未确认；干净登录复核失败，已停止重设密码和 2FA 操作"
                            + (f"：{login_error}" if login_error else "")
                        )
                    _emit_security_progress("session_check", reason="候选密码尚未提交，正在恢复首次设置所需会话")
                    _log_safely(
                        log,
                        "[账号安全] 候选密码尚未验证，改用邮箱验证码恢复会话并继续密码设置",
                    )
                    verified_page, login_error = _open_email_otp_verified_session(
                        target_email,
                        password_code_provider,
                        proxy,
                        headless,
                        log,
                    )
            else:
                _log_safely(
                    log,
                    "[账号安全] 本地密码尚未确认，正在使用邮箱验证码恢复登录会话",
                )
                verified_page, login_error = _open_email_otp_verified_session(
                    target_email,
                    password_code_provider,
                    proxy,
                    headless,
                    log,
                )
            if verified_page is None:
                raise RuntimeError(login_error or "注册会话已失效，重新登录失败")
            if owns_page and working_page is not None:
                try:
                    working_page.quit(force=True)
                except TypeError:
                    try:
                        working_page.quit()
                    except Exception:
                        pass
                except Exception:
                    pass
            working_page = verified_page
            owns_page = True
            identity = _session_identity_with_retry(working_page, log)
            if _session_probe_transient(identity):
                raise RuntimeError("登录后的会话读取暂未确认，已保留现有凭据")
            if recovered_with_proven_password:
                _emit_security_progress("password_verify", status="completed", reason="已通过独立密码登录及目标账号身份核对")
                password = login_password
                # A successful exact-identity password login is stronger proof
                # than a transient Settings success banner: this password is
                # usable now.  Email OTP recovery intentionally does not enter
                # this branch; it proves the session, not the staged password.
                password_set_proven = True
                password_state = "configured"
                update_chatgpt_security_state(
                    target_email,
                    password_state="configured",
                    mfa_state="enabled" if totp_verified else None,
                    last_error="",
                )
            else:
                password_set_proven = False
                password_state = effective_password_state or "pending"
                _log_safely(
                    log,
                    "[账号安全] 邮箱验证码登录完成；候选密码仍待远端设置与验证",
                )
        actual_email = _normalise_email(identity.get("email"))
        if not identity.get("authenticated"):
            raise RuntimeError("注册会话已失效，无法进入账号安全设置")
        if actual_email != target_email:
            _record_security_retry_failure("identity_mismatch")
            raise RuntimeError("当前浏览器登录账号与待设置账号不一致")
        _log_safely(log, "[账号安全] 已核对当前 ChatGPT 登录账号")
        _emit_security_progress("session_check", status="completed", reason="已核对当前 ChatGPT 登录账号身份")

        if in_session and not password_set_proven and (must_verify_first or staged_password_probe_eligible):
            # An interrupted submission must not turn into another reset, nor
            # into an independent password login under this policy.
            error = "先前密码提交结果尚未确认；保留原密码待恢复，未重设密码或启动其他登录"
            update_chatgpt_security_state(target_email, password_state="pending", last_error=error)
            _emit_security_progress("password_verify", status="review", code="password_verification_required",
                                    reason=error, retry_mode="verify_first")
            return ChatGptSecuritySetupResult(
                False, target_email, "pending", str(preexisting_status.get("mfa_state") or "unknown"),
                True, bool(preexisting_totp_secret), error, _collect_page_cookies(working_page),
            )

        # A retry can arrive with a still-valid Cookie even though the previous
        # password mutation completed remotely after its UI confirmation timed
        # out.  Prove the staged password in a clean browser before issuing a
        # second reset.  Merely having ciphertext is never treated as proof.
        if (
            not password_set_proven
            and staged_password_probe_eligible
            and not staged_password_probe_attempted
        ):
            staged_password_probe_attempted = True
            _emit_security_progress("password_verify", reason="正在先验证上次保存的候选密码", retry_mode="verify_first")
            if not preexisting_totp_secret and str(preexisting_status.get("mfa_state") or "") in {"pending", "enabled", "unmanaged"}:
                _emit_security_progress("password_verify", status="review", code="password_verification_required",
                                        reason="账号疑似已有 2FA，但本地缺少原 Authenticator 密钥；未重设密码或重新绑定",
                                        retry_mode="verify_first")
                raise RuntimeError("账号已有或疑似已有 Authenticator 2FA，但本地缺少原密钥；为防锁号未重设密码或重新绑定")
            _log_safely(
                log,
                "[账号安全] 检测到上次已保存但未确认的密码，先执行干净登录验证",
            )
            verified_page, _totp_verified, verification_error = (
                _open_login_verified_session(
                    target_email,
                    password,
                    preexisting_totp_secret,
                    proxy,
                    headless,
                    log,
                    email_code_provider=password_code_provider,
                )
            )
            if verified_page is not None:
                if owns_page and working_page is not None:
                    try:
                        working_page.quit(force=True)
                    except TypeError:
                        try:
                            working_page.quit()
                        except Exception:
                            pass
                    except Exception:
                        pass
                working_page = verified_page
                owns_page = True
                password_set_proven = True
                password_state = "configured"
                update_chatgpt_security_state(
                    target_email,
                    password_state="configured",
                    mfa_state="enabled" if _totp_verified else None,
                    last_error="",
                )
                _log_safely(log, "[账号安全] 已保存密码已通过干净登录复核")
                _emit_security_progress("password_verify", status="completed", reason="已通过独立密码登录及目标账号身份核对")
            else:
                if must_verify_first:
                    raise RuntimeError(
                        "先前密码提交结果未确认；干净登录复核失败，已停止重设密码和 2FA 操作"
                        + (f"：{verification_error}" if verification_error else "")
                    )
                _log_safely(
                    log,
                    "[账号安全] 从未确认提交的候选密码无法登录，继续首次密码设置",
                )

        if not password_set_proven:
            _emit_security_progress("password_settings", reason="正在打开账户设置补设首次密码")
            _log_safely(log, "[账号安全] 注册阶段未确认密码，正在打开账户设置补设密码")
            password_state, password_error = _complete_password_setup(
                working_page,
                password,
                target_email,
                password_link_provider=password_link_provider,
                password_code_provider=password_code_provider,
                log_fn=log,
                **({"confirmation_mode": confirmation_mode} if in_session else {}),
            )
            tracker = _SECURITY_PROGRESS.get()
            if (password_state == "unknown"
                    and not str(password_error or "").startswith(("密码已提交", "密码提交已尝试"))
                    and tracker is not None and not tracker.submission_started):
                # An unavailable Settings panel/mailbox before the mutation is
                # not an unknown password *submission*. Keep first setup possible.
                password_state = "pending"
            if (
                not in_session and password_state == "unknown"
                and str(password_error or "").startswith(("密码已提交", "密码提交已尝试"))
            ):
                _emit_security_progress("password_verify", reason="密码提交结果待确认，正在用全新浏览器验证", retry_mode="verify_first")
                _log_safely(log, "[账号安全] 页面未返回密码提示，正在用全新登录复核")
                verified_page, verification_error = _open_password_verified_session(
                    target_email,
                    password,
                    proxy,
                    headless,
                    log,
                    email_code_provider=password_code_provider,
                )
                if verified_page is not None:
                    if owns_page and working_page is not None:
                        try:
                            working_page.quit(force=True)
                        except TypeError:
                            try:
                                working_page.quit()
                            except Exception:
                                pass
                        except Exception:
                            pass
                    working_page = verified_page
                    owns_page = True
                    password_state = "configured"
                    password_error = ""
                    _emit_security_progress("password_verify", status="completed", reason="已通过独立密码登录及目标账号身份核对")
                elif verification_error:
                    password_error = (
                        f"{password_error}；全新登录复核失败：{verification_error}"
                    )
            if in_session and password_state == "unknown":
                password_state = "pending"
            update_chatgpt_security_state(
                target_email,
                password_state=password_state,
                last_error=password_error,
            )
            if password_state != "configured":
                raise RuntimeError(password_error or "密码设置结果无法确认")
            if in_session:
                _emit_security_progress("password_verify", status="completed", reason="当前页面已确认密码设置成功")
            _log_safely(log, "[账号安全] ChatGPT 密码设置完成")
        else:
            password_state = "configured"
            update_chatgpt_security_state(target_email, password_state="configured", last_error="")

        if not enable_totp:
            mfa_state = "disabled"
            update_chatgpt_security_state(target_email, mfa_state=mfa_state, last_error="")
            return ChatGptSecuritySetupResult(
                True,
                target_email,
                password_state,
                mfa_state,
                True,
                False,
                cookies=_collect_page_cookies(working_page),
            )

        _log_safely(log, "[账号安全] 正在打开 Security 并启用 Authenticator 2FA")
        _emit_security_progress("totp_settings", reason="正在检查 Authenticator 2FA 设置，已有密钥不会自动重绑")
        existing = get_chatgpt_security_secrets(target_email)
        existing_status = get_chatgpt_security_status(target_email)
        pending_recovery_snapshot = None
        pending_recovery_seed = ""
        if in_session and str(existing_status.get("mfa_state") or "") == "pending":
            _emit_security_progress("totp_verify", reason="正在当前会话核对上次 Authenticator 启用结果，不重复绑定",
                                    retry_mode="verify_first")
            current = _in_session_authenticator_state(working_page, target_email, log)
            if current == "enabled" and existing.get("totp_secret"):
                update_chatgpt_security_state(target_email, mfa_state="enabled", last_error="")
                _emit_security_progress("totp_verify", status="completed", reason="当前同身份会话已确认 Authenticator 启用")
                return ChatGptSecuritySetupResult(
                    True, target_email, password_state, "enabled", True, True,
                    cookies=_collect_page_cookies(working_page),
                )
            if (current == "disabled" and existing.get("totp_secret")
                    and not existing_status.get("has_recovery_codes")
                    and preexisting_status.get("mfa_state") != "enabled"):
                # A saved candidate does not mean activation succeeded.  The
                # original failed submission can leave the remote switch off.
                # Confirm that exact account twice before continuing enrollment;
                # never disable a factor or clear an uncertain remote state.
                pending_recovery_snapshot = existing_status
                pending_recovery_seed = str(existing["totp_secret"])
                _confirm_in_session_pending_totp_disabled(
                    working_page, target_email, log, pending_recovery_snapshot, password, pending_recovery_seed,
                )
                _emit_security_progress("totp_settings", reason="已确认 Authenticator 尚未启用，自动继续完成设置",
                                        retry_mode="auto_local")
            else:
                error = ("当前会话显示 Authenticator 已启用，但本地缺少原密钥；保留待确认状态，未重新绑定"
                         if current == "enabled" else
                         "当前会话未确认上次 Authenticator 已启用；保留原密钥与待确认状态，未重新绑定")
                update_chatgpt_security_state(target_email, mfa_state="pending", last_error=error)
                return ChatGptSecuritySetupResult(
                    False, target_email, password_state, "pending", True, bool(existing.get("totp_secret")),
                    error, _collect_page_cookies(working_page),
                )
        inspect_missing_seed = bool(
            pending_seed_inspection and can_inspect_pending_totp(existing_status)
            and existing.get("password") == password and not existing.get("totp_secret")
        )
        if str(existing_status.get("mfa_state") or "") in {"pending", "unmanaged"} and not existing.get("totp_secret"):
            if not inspect_missing_seed:
                _record_security_retry_failure("credentials_missing")
                raise RuntimeError("Authenticator 启用结果待确认且缺少可核验的原凭据，已停止自动重新绑定")
        if (not in_session and existing.get("totp_secret")
                and str(existing_status.get("mfa_state") or "") == "pending"):
            _emit_security_progress("totp_verify", reason="正在用原暂存 Authenticator 密钥进行全新登录核验，不重复绑定", retry_mode="verify_first")
            verified, verified_cookies, verify_error = _verify_totp_with_fresh_login(
                target_email, password, str(existing["totp_secret"]), proxy,
                headless, log, email_code_provider=password_code_provider,
            )
            if not verified:
                error = "原暂存 Authenticator 密钥尚未通过真实挑战核验，未重新绑定" + (f"：{verify_error}" if verify_error else "")
                update_chatgpt_security_state(target_email, mfa_state="pending", last_error=error)
                # Keep an exact password-submit diagnostic from the nested
                # login, if present; otherwise explain the missing MFA proof.
                tracker = _SECURITY_PROGRESS.get()
                if tracker is None or tracker.value.get("status") not in {"failed", "review"}:
                    _emit_security_progress("totp_verify", status="review", code="totp_verification_required",
                                            reason=_safe_error(error, known_secrets=(password, str(existing["totp_secret"]))), retry_mode="verify_first")
                return ChatGptSecuritySetupResult(False, target_email, password_state, "pending",
                                                 True, True, error, _collect_page_cookies(working_page))
            update_chatgpt_security_state(target_email, mfa_state="enabled", last_error="")
            _emit_security_progress("totp_verify", status="completed", reason="原暂存 Authenticator 密钥已通过真实挑战及目标账号身份核验")
            return ChatGptSecuritySetupResult(True, target_email, password_state, "enabled",
                                             True, True, cookies=verified_cookies)
        if not in_session and not _open_settings_section(working_page, "security"):
            _record_security_retry_failure("controls_unavailable", working_page)
            raise RuntimeError("无法打开 ChatGPT Security 设置")

        if inspect_missing_seed:
            _confirm_pending_totp_disabled(working_page, target_email, log)
            # Keep the pending marker across the entire recovery until the new
            # seed is safely persisted and real verification succeeds. A crash
            # or another failed reveal must never make an uncertain enrollment
            # look disabled. The following normal path rechecks the row again.

        current = (
            _in_session_authenticator_state(working_page, target_email, log) if in_session else
            _inspect_mfa_row(working_page, authenticator_only=True)
            if inspect_missing_seed else _inspect_mfa_row(working_page)
        )
        if current == "enabled":
            if (
                existing.get("totp_secret")
                and str(existing_status.get("mfa_state") or "") == "enabled"
            ):
                update_chatgpt_security_state(target_email, mfa_state="enabled", last_error="")
                _emit_security_progress("totp_verify", status="completed", reason="已核对已管理的 Authenticator 2FA 仍为启用状态")
                return ChatGptSecuritySetupResult(
                    True,
                    target_email,
                    password_state,
                    "enabled",
                    True,
                    True,
                    cookies=_collect_page_cookies(working_page),
                )
            if existing.get("totp_secret"):
                error = (
                    "远端已启用 2FA，但本地暂存密钥尚未通过一次全新登录验证；"
                    "为防保存错误密钥，状态保持待确认"
                )
                update_chatgpt_security_state(
                    target_email,
                    mfa_state="pending",
                    last_error=error,
                )
                return ChatGptSecuritySetupResult(
                    False,
                    target_email,
                    password_state,
                    "pending",
                    True,
                    True,
                    error,
                    _collect_page_cookies(working_page),
                )
            error = "远端已启用 2FA，但本地没有该 Authenticator 密钥；为防锁号未自动重绑"
            _record_security_retry_failure("credentials_missing")
            update_chatgpt_security_state(target_email, mfa_state="unmanaged", last_error=error)
            return ChatGptSecuritySetupResult(False, target_email, password_state, "unmanaged", True, False, error)

        if (
            in_session
            and current == "disabled"
            and existing.get("totp_secret")
            and str(existing_status.get("mfa_state") or "") == "enabled"
            and not existing_status.get("has_recovery_codes")
        ):
            # Repair a prior optimistic same-page success only after the exact
            # authenticated account now proves that the remote factor is off.
            error = "远端已明确确认 Authenticator 未启用；已自动修正本地误判并继续完成设置"
            update_chatgpt_security_state(
                target_email,
                mfa_state="pending",
                last_error=error,
            )
            existing_status = get_chatgpt_security_status(target_email)
            pending_recovery_snapshot = existing_status
            pending_recovery_seed = str(existing["totp_secret"])
            _confirm_in_session_pending_totp_disabled(
                working_page,
                target_email,
                log,
                pending_recovery_snapshot,
                password,
                pending_recovery_seed,
            )
            _emit_security_progress(
                "totp_settings",
                reason="已确认原 2FA 成功记录为误判，自动继续完成 Authenticator 设置",
                retry_mode="auto_local",
            )

        # Never overwrite the only known key for a remotely-proven MFA setup.
        # A transient selector/UI mismatch must not turn a usable account into
        # one whose authenticator secret is permanently lost.
        if (
            existing.get("totp_secret")
            and str(existing_status.get("mfa_state") or "") == "enabled"
        ):
            error = "本地已有已启用的 2FA 密钥，但远端状态未能确认；为防锁号未自动重绑"
            update_chatgpt_security_state(target_email, last_error=error)
            return ChatGptSecuritySetupResult(
                False,
                target_email,
                password_state,
                "enabled",
                True,
                True,
                error,
                _collect_page_cookies(working_page),
            )
        if current != "disabled":
            raise RuntimeError("无法明确判断 Authenticator 2FA 是否已关闭，未执行绑定")

        activation_identity = _session_identity(working_page)
        if in_session:
            _require_in_session_identity(activation_identity, target_email)
        if (not activation_identity.get("authenticated")
                or _normalise_email(activation_identity.get("email")) != target_email):
            _record_security_retry_failure("identity_mismatch")
            raise RuntimeError("启用 Authenticator 前的目标账号身份复核失败，未点击启用")
        setup_email_baseline_ready = False
        if callable(password_code_provider):
            try:
                baseline = password_code_provider(email=target_email, timeout=1, prepare=True, exclude_codes=set())
                setup_email_baseline_ready = bool(isinstance(baseline, dict)
                    and baseline.get("baseline_ready") is True and baseline.get("strict") is True)
            except Exception:
                _log_safely(log, "[账号安全] 启用前邮件基线暂不可用；若页面提供原密码验证则使用原密码，否则安全停止")
        if pending_recovery_snapshot is not None:
            _guard_pending_totp_recovery(target_email, pending_recovery_snapshot, password, pending_recovery_seed)
        _mark_totp_activation()
        if pending_recovery_snapshot is not None:
            # This checkpoint is our own write; protect its resulting version
            # throughout the remote enrollment and until the new key is saved.
            pending_recovery_snapshot = get_chatgpt_security_status(target_email)
            _guard_pending_totp_recovery(target_email, pending_recovery_snapshot, password, pending_recovery_seed)
        clicked = (
            _inspect_mfa_row(working_page, click_enable=True, authenticator_only=True)
            if inspect_missing_seed or pending_recovery_snapshot is not None
            else _inspect_mfa_row(working_page, click_enable=True)
        )
        if clicked != "clicked":
            _record_security_retry_failure("controls_unavailable", working_page)
            _emit_security_progress("totp_settings", status="review", code="totp_activation_entry_missing",
                                    reason="未找到 Authenticator 2FA 启用入口", retry_mode="verify_first")
            raise RuntimeError("未找到 Authenticator 2FA 启用入口")
        time.sleep(1.0)
        if not _choose_authenticator(working_page, verify_identity=lambda: _verify_totp_setup_identity(
            working_page, email=target_email, password=password, initiating_identity=activation_identity,
            email_code_provider=password_code_provider, email_baseline_ready=setup_email_baseline_ready, log=log,
        )):
            _record_security_retry_failure("controls_unavailable", working_page)
            _emit_security_progress("totp_settings", status="review", code="totp_authenticator_entry_missing",
                                    reason="未找到 Authenticator App 绑定入口", retry_mode="verify_first")
            raise RuntimeError("未找到 Authenticator App 绑定入口")
        time.sleep(1.0)

        def enrollment_log(message: str) -> None:
            _log_safely(log, f"[账号安全] {message}")
            _emit_security_progress("totp_settings", reason=message, retry_mode="verify_first")

        secret = _reveal_manual_totp_secret(working_page, emit=enrollment_log)
        if not secret:
            diagnostics = _totp_enrollment_diagnostics(working_page)
            if diagnostics.get("ambiguous"):
                reason = "出现多个不同的密钥候选或候选过多，无法安全确定 Authenticator 密钥"
            elif diagnostics.get("qr_visible") and not diagnostics.get("manual_available"):
                reason = "仅显示二维码，手动密钥入口不存在或不可用"
            elif diagnostics.get("unrelated_dialog"):
                reason = "当前弹窗不是 Authenticator 设置界面，未读取其他弹窗内容"
            elif not diagnostics.get("enrollment_visible"):
                reason = "等待20秒后仍未出现可确认的 Authenticator 设置界面"
            else:
                reason = "Authenticator 设置界面已出现，但等待20秒后仍未读取到可安全保存的手动密钥"
            raise RuntimeError(f"{reason}；未提交动态码，启用结果仍待确认")
        tracker = _SECURITY_PROGRESS.get()
        if tracker is not None:
            tracker.remember_secrets(secret)

        # Crash-safe ordering: save the only seed before enabling it remotely.
        if pending_recovery_snapshot is not None:
            _guard_pending_totp_recovery(target_email, pending_recovery_snapshot, password, pending_recovery_seed)
        stage_chatgpt_totp(target_email, secret, state="pending")
        if pending_recovery_snapshot is not None:
            pending_recovery_snapshot = get_chatgpt_security_status(target_email)
            pending_recovery_seed = secret
        if tracker is not None:
            tracker.totp_saved = True
        mfa_state = "pending"
        _emit_security_progress("totp_settings", status="completed", reason="Authenticator 密钥已安全暂存，尚待验证生效")
        _emit_security_progress("totp_verify", reason="正在提交 Authenticator 验证码并核对远端启用状态", retry_mode="verify_first")
        _log_safely(log, "[账号安全] Authenticator 密钥已加密暂存，正在校验一次性验证码")

        code = _current_totp(secret)
        if pending_recovery_snapshot is not None:
            _guard_pending_totp_recovery(target_email, pending_recovery_snapshot, password, pending_recovery_seed)
        if tracker is not None:
            tracker.totp_submission_started = True
        totp_submitted = _fill_totp_and_submit(working_page, code)
        if in_session and totp_submitted is not True:
            _record_security_retry_failure("controls_unavailable", working_page)
            raise RuntimeError("Authenticator 动态码提交未确认；已保留原密钥，未重新绑定或启动其他登录")
        if not totp_submitted:
            time.sleep(0.8)
            if is_authenticator_challenge(working_page):
                _record_security_retry_failure("controls_unavailable", working_page)
                raise RuntimeError("未找到 Authenticator 验证码输入或确认控件")
        activation_deadline = time.time() + 15
        activation_state = "pending"
        while time.time() < activation_deadline:
            activation_state = _mfa_activation_status(working_page)
            if activation_state in {"success", "error"}:
                break
            time.sleep(0.35)
        if activation_state == "error":
            _record_security_retry_failure("auth_rejected")
            raise RuntimeError("Authenticator 验证码被 OpenAI 页面拒绝")

        # Older variants exposed recovery codes here; the current ordinary
        # Authenticator flow only shows a success toast and closes the modal.
        # Persist recovery material when it is actually present, but never
        # fail a remotely verified TOTP enrollment merely because this
        # optional screen does not exist.
        recovery_visible, recovery_codes = _extract_recovery_codes(working_page)
        if recovery_visible:
            recovery_visible, recovery_codes = _wait_for_recovery_codes(
                working_page,
                timeout=3.0,
            )
            if not recovery_codes:
                raise RuntimeError("恢复代码未形成两次稳定快照，未确认或启用本地状态")
            stage_chatgpt_recovery_codes(target_email, recovery_codes)
            _acknowledge_recovery_codes(working_page)
            _log_safely(log, "[账号安全] 2FA 恢复代码已稳定读取并加密保存")

        if in_session:
            # A success toast or checked toggle may be optimistic.  Close the
            # dialog and require the exact account's Authenticator row to
            # survive two full reloads in the same registration session.
            _click_text(working_page, ("done", "continue", "finish", "完成", "继续"), dialog_only=True)
            settings_confirmed = _confirm_in_session_totp_enabled(
                working_page, target_email, log,
            )
            if not settings_confirmed:
                error = "Authenticator 动态码已提交，但刷新安全设置页后未确认启用；已保留原密钥与待确认状态"
                update_chatgpt_security_state(target_email, mfa_state="pending", last_error=error)
                return ChatGptSecuritySetupResult(
                    False, target_email, password_state, "pending", True, True,
                    error, _collect_page_cookies(working_page),
                )
            update_chatgpt_security_state(target_email, mfa_state="enabled", last_error="")
            _log_safely(log, "[账号安全] 当前会话已确认 Authenticator 2FA 设置成功")
            _emit_security_progress("totp_verify", status="completed", reason="当前会话已确认 Authenticator 2FA 设置成功")
            return ChatGptSecuritySetupResult(
                True, target_email, password_state, "enabled", True, True,
                cookies=_collect_page_cookies(working_page),
            )

        # Complete the enrollment dialog and then independently re-open the
        # Security panel to verify the durable remote state.
        _click_text(working_page, ("done", "continue", "finish", "完成", "继续"), dialog_only=True)
        time.sleep(0.8)
        settings_confirmed = bool(
            _open_settings_section(working_page, "security")
            and _inspect_mfa_row(working_page) == "enabled"
        )
        verified_cookies: dict[str, str] = {}
        if not settings_confirmed:
            # Enabling MFA can revoke the access token used to open Settings.
            # The strongest available proof is therefore a completely fresh
            # password login that actually presents and passes the TOTP
            # challenge with the candidate seed.
            _log_safely(log, "[账号安全] 设置页复核不可用，正在执行全新登录复核 2FA")
            verified, verified_cookies, verify_error = _verify_totp_with_fresh_login(
                target_email,
                password,
                secret,
                proxy,
                headless,
                log,
                email_code_provider=password_code_provider,
            )
            if not verified:
                error = (
                    "Authenticator 验证码已提交，但全新登录复核未通过"
                    + (f"：{verify_error}" if verify_error else "")
                )
                # Keep the candidate key as pending.  If the remote
                # confirmation succeeded but both probes failed, this remains
                # the only key capable of completing a later reconciliation.
                update_chatgpt_security_state(
                    target_email,
                    mfa_state="pending",
                    last_error=error,
                )
                return ChatGptSecuritySetupResult(
                    False,
                    target_email,
                    password_state,
                    "pending",
                    True,
                    True,
                    error,
                    _collect_page_cookies(working_page),
                )

        mfa_state = "enabled"
        update_chatgpt_security_state(target_email, mfa_state=mfa_state, last_error="")
        _log_safely(log, "[账号安全] Authenticator 2FA 已启用并完成远端复核")
        _emit_security_progress("totp_verify", status="completed", reason="Authenticator 2FA 已启用并完成远端复核")
        return ChatGptSecuritySetupResult(
            True,
            target_email,
            password_state,
            mfa_state,
            True,
            True,
            cookies=verified_cookies or _collect_page_cookies(working_page),
        )
    except Exception as exc:
        if isinstance(exc, AccountDeactivatedLoginError):
            _emit_security_progress(status="failed", code="account_deactivated",
                                    reason=ACCOUNT_DEACTIVATED_LOGIN_ERROR, retry_mode="manual")
            _record_security_retry_failure("auth_rejected")
        error = _safe_error(
            exc,
            known_secrets=(
                password,
                preexisting_totp_secret,
                str(locals().get("secret") or ""),
                session_token,
            ),
        )
        status = get_chatgpt_security_status(target_email)
        # Keep the last durable, remotely-proven state.  A transient UI or
        # network failure must never downgrade an already enabled MFA record.
        password_state = str(status.get("password_state") or password_state or "unknown")
        mfa_state = str(status.get("mfa_state") or mfa_state or "unknown")
        tracker = _SECURITY_PROGRESS.get()
        durable_error = error
        if (tracker is not None and (tracker.prior_state_safe or tracker.unsubmitted_candidate)
                and not tracker.must_verify_existing and not tracker.submission_started
                and not tracker.totp_activation_started and not tracker.totp_submission_started
                and password_state == "pending" and mfa_state in {"not_configured", "disabled"}
                and not status.get("has_totp") and not status.get("has_recovery_codes")):
            durable_error = _UNSUBMITTED_PASSWORD_PREFIX + error
        update_chatgpt_security_state(
            target_email,
            password_state=password_state,
            mfa_state=mfa_state,
            last_error=durable_error,
        )
        _log_safely(log, f"[账号安全] 设置未完成：{error}")
        return ChatGptSecuritySetupResult(
            False,
            target_email,
            password_state,
            mfa_state,
            bool(status.get("has_password")),
            bool(status.get("has_totp")),
            error,
            _collect_page_cookies(working_page) if working_page is not None else {},
        )
    finally:
        if owns_page and working_page is not None:
            try:
                working_page.quit(force=True)
            except TypeError:
                try:
                    working_page.quit()
                except Exception:
                    pass
            except Exception:
                pass


def configure_registered_account_security(**kwargs: Any) -> ChatGptSecuritySetupResult:
    """Report bounded sub-step diagnostics while preserving the existing result API."""
    tracker = _SecurityProgress(_normalise_email(kwargs.get("email")), kwargs.pop("progress_fn", None),
                                confirmation_mode=kwargs.get("confirmation_mode", "independent"))
    tracker.remember_secrets(str(kwargs.get("password") or ""), str(kwargs.get("session_token") or ""))
    token = _SECURITY_PROGRESS.set(tracker)
    try:
        tracker.emit("session_check", reason="正在准备账号安全检查")
        result = _configure_registered_account_security_locked(**kwargs)
        tracker.finish(result)
        return result
    finally:
        _SECURITY_PROGRESS.reset(token)


def _configure_registered_account_security_locked(**kwargs: Any) -> ChatGptSecuritySetupResult:
    """Serialize password/MFA mutations per identity and across processes."""
    email = str(kwargs.get("email") or "")
    with _security_workflow_lock(email):
        lease_token = ""
        try:
            from services.chatgpt_security_store import (
                acquire_chatgpt_security_lease,
                get_chatgpt_security_status,
                release_chatgpt_security_lease,
            )

            lease_token = str(
                acquire_chatgpt_security_lease(
                    email,
                    ttl_seconds=_SECURITY_DB_LEASE_SECONDS,
                )
                or ""
            )
            if not lease_token:
                _emit_security_progress("session_check", status="failed", code="security_busy",
                                        reason="该账号的安全设置正由另一个进程处理，请稍后重试", retry_mode="manual")
                normalized_email = _normalise_email(email)
                status = get_chatgpt_security_status(normalized_email)
                return ChatGptSecuritySetupResult(
                    False,
                    normalized_email,
                    str(status.get("password_state") or "unknown"),
                    str(status.get("mfa_state") or "unknown"),
                    bool(status.get("has_password")),
                    bool(status.get("has_totp")),
                    "该账号的安全设置正在由另一个进程处理，请稍后重试",
                )
            owner_context = _SECURITY_LEASE_OWNER.set((_normalise_email(email), lease_token))
            try:
                return _configure_registered_account_security_unlocked(**kwargs)
            finally:
                _SECURITY_LEASE_OWNER.reset(owner_context)
        except Exception as exc:
            # Key/storage failures can happen before the browser try/finally is
            # entered.  Preserve fail-soft registration semantics and never
            # echo a credential in the action result.
            return ChatGptSecuritySetupResult(
                False,
                _normalise_email(email),
                "unknown",
                "unknown",
                False,
                False,
                _safe_error(
                    exc,
                    known_secrets=(
                        str(kwargs.get("password") or ""),
                        str(kwargs.get("session_token") or ""),
                    ),
                ),
            )
        finally:
            if lease_token:
                try:
                    release_chatgpt_security_lease(email, lease_token)
                except Exception:
                    # The finite lease remains the crash/release-failure escape
                    # hatch.  Never mask the real workflow result here.
                    pass


def finalize_registered_platform_account(
    account: Any,
    *,
    config: Optional[dict] = None,
    proxy: str = "",
    browser_mode: str = "protocol",
    log_fn: Optional[Callable[[str], None]] = None,
) -> Any:
    """Fail-soft bridge used by the generic ChatGPT registration plugin."""
    if account is None or str(getattr(account, "platform", "")) != "chatgpt":
        return account
    # BUSINESS OAuth persists an intermediate PENDING_RT row from inside the
    # registration method.  It therefore finalizes security before that first
    # save.  Outer registration wrappers may still call this bridge; keep the
    # marker process-local (never in Account.extra/DB) and make that call a
    # no-op so the newly enabled MFA is not enrolled twice.
    if bool(getattr(account, "_chatgpt_security_finalized", False)):
        return account
    extra = getattr(account, "extra", None)
    if not isinstance(extra, dict):
        extra = {}
        account.extra = extra
    cfg = dict(config or {})
    enabled = _as_bool(cfg.get("chatgpt_security_after_register"), True)
    password_proven = _as_bool(extra.get("password_set_proven"), False)
    source = str(extra.get("chatgpt_token_source") or "register").strip().lower()

    # A login fallback may return an existing account.  Do not silently mutate
    # its security settings under a task advertised as registration.
    if source == "login" and not bool(getattr(account, "_gmail_registration_owned", False)):
        extra["chatgpt_security"] = {
            "password_state": "unknown",
            "mfa_state": "not_attempted_existing_account",
            "has_password": bool(getattr(account, "password", "")),
            "has_totp": False,
            "error": "检测为已有账号登录，未自动修改安全设置",
        }
        setattr(account, "_chatgpt_security_finalized", True)
        return account

    # This is intentionally one atomic user-facing choice: when disabled, do
    # not set or persist either a ChatGPT password or an Authenticator secret.
    # In particular, keep this short-circuit ahead of the shared configurator,
    # because that function stages the password before it opens a browser.
    if not enabled:
        extra["chatgpt_security"] = ChatGptSecuritySetupResult(
            True,
            _normalise_email(getattr(account, "email", "")),
            password_state="not_configured",
            mfa_state="disabled",
            has_password=False,
            has_totp=False,
        ).safe_dict()
        setattr(account, "_chatgpt_security_finalized", True)
        if callable(log_fn):
            _log_safely(
                log_fn,
                "[账号安全] 已关闭注册后密码与 Authenticator 2FA 设置，已全部跳过",
            )
        return account

    result = configure_registered_account_security(
        email=str(getattr(account, "email", "") or ""),
        password=str(getattr(account, "password", "") or ""),
        password_set_proven=password_proven,
        cookies=extra.get("cookies"),
        session_token=str(extra.get("session_token") or ""),
        proxy=proxy or "",
        headless=str(browser_mode or "protocol").lower() != "headed",
        enable_totp=True,
        log_fn=log_fn,
        password_link_provider=(
            cfg.get("_chatgpt_password_link_provider")
            if callable(cfg.get("_chatgpt_password_link_provider"))
            else None
        ),
        password_code_provider=(
            cfg.get("_chatgpt_password_code_provider")
            if callable(cfg.get("_chatgpt_password_code_provider"))
            else None
        ),
    )
    extra["chatgpt_security"] = result.safe_dict()
    if result.cookies:
        extra["cookies"] = json.dumps(result.cookies, ensure_ascii=False)
        refreshed_session = _session_cookie_from_map(result.cookies)
        if refreshed_session:
            extra["session_token"] = refreshed_session
    if result.ok and result.password_state == "configured":
        extra["password_set_proven"] = True
    setattr(account, "_chatgpt_security_finalized", True)
    return account
