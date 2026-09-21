"""Credential-free, bounded diagnostics shared by security tasks and NV UI."""
from __future__ import annotations

import re
from typing import Any


STAGE_LABELS = {
    "session_check": "检查登录会话",
    "password_settings": "打开密码设置",
    "password_email": "验证密码设置邮件",
    "password_submit": "提交新密码",
    "password_verify": "新浏览器验证密码",
    "totp_identity": "启用 2FA 前验证身份",
    "totp_settings": "设置 Authenticator 2FA",
    "totp_verify": "验证 2FA 已生效",
    "done": "安全设置完成",
}
STATUSES = {"running", "retrying", "completed", "failed", "review"}
RETRY_MODES = {"none", "auto_local", "manual", "verify_first"}
CODES = set(STAGE_LABELS) | {
    "account_deactivated",
    "session_read_retry", "session_read_failed", "login_recovery_failed", "password_settings_retry",
    "session_request_timeout", "session_network_failed", "session_browser_timeout",
    "session_context_lost", "session_browser_disconnected",
    "session_read_unconfirmed", "session_http_transient", "session_http_rejected", "session_http_unconfirmed",
    "session_empty", "session_invalid", "session_identity_missing", "session_token_missing", "session_state_error",
    "session_identity_mismatch", "session_origin_untrusted", "login_page_unready", "login_transport_unavailable",
    "login_rate_limited", "login_page_challenge", "login_page_unconfirmed", "login_origin_untrusted", "login_auth_rejected",
    "security_busy", "security_failed", "security_complete",
    "browser_init_started", "browser_init_failed", "browser_init_timeout", "browser_init_cleanup_pending",
    "password_verification_required", "password_verification_failed",
    "password_login_input_missing", "password_login_input_failed", "password_login_input_stale",
    "password_login_input_retry",
    "password_login_submit_missing", "password_login_submit_failed", "password_login_submit_stale",
    "password_login_route_uncertain", "password_login_route_advanced", "password_login_submitted",
    "password_login_route_missing", "password_login_route_failed", "password_login_timeout",
    "password_login_email_transition", "password_login_email_transition_failed",
    "password_login_page_error",
    "password_email_retry", "totp_verification_required",
    "totp_activation_entry_missing", "totp_authenticator_entry_missing",
    "totp_identity_verification_required", "totp_identity_verification_failed", "totp_identity_verified",
}
TASK_RETRY_TRANSIENT_REASONS = {"controls_unavailable", "mail_wait_temporary", "network_temporary"}
TASK_RETRY_MANUAL_REASONS = {
    "insufficient_evidence", "remote_change_unverified", "credentials_missing",
    "identity_mismatch", "auth_rejected", "configuration_required",
    "unknown_failure", "untracked_prior_state",
}


def normalize_task_retry(value: Any) -> dict[str, str] | None:
    """Normalize an explicit terminal instruction; never infer retry permission."""
    fallback = {"strategy": "manual", "reason_code": "insufficient_evidence"}
    if value is None:
        return None
    if not isinstance(value, dict):
        return fallback
    strategy, reason = value.get("strategy"), value.get("reason_code")
    if not isinstance(strategy, str) or not isinstance(reason, str):
        return fallback
    if strategy in {"safe_resume", "verify_existing"} and reason in TASK_RETRY_TRANSIENT_REASONS:
        return {"strategy": strategy, "reason_code": reason}
    if strategy == "safe_resume" and reason == "no_remote_attempt":
        # NV reconciliation proved the durable pre-mutation marker was never
        # set. This is an orchestrator decision, not a browser error heuristic.
        return {"strategy": strategy, "reason_code": reason}
    if strategy == "manual" and reason in TASK_RETRY_MANUAL_REASONS:
        return {"strategy": strategy, "reason_code": reason}
    return fallback


def _safe_reason(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = re.sub(r"(?i)bearer\s+[^\s,;]+", "Bearer [已隐藏]", value)
    text = re.sub(r"eyJ[A-Za-z0-9_-]{15,}(?:\.[A-Za-z0-9_-]+){1,2}", "[凭证已隐藏]", text)
    text = re.sub(
        r"(?i)\b(?:proxy-)?authorization\s*['\"]?\s*[:=：]\s*['\"]?(?:basic|bearer)\s+[^\s,;}\]'\"]+['\"]?",
        "Authorization=[已隐藏]", text,
    )
    text = re.sub(
        r"(?i)\b(?:[a-z][\w-]*[_-](?:secret|seed)|(?:totp|authenticator|mfa|2fa)(?:secret|seed))\b"
        r"\s*['\"]?\s*[:=：]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        "安全密钥=[已隐藏]", text,
    )
    text = re.sub(
        r"(?i)((?:password|passwd|secret|totp|otp|cookie|authorization|access_token|refresh_token|id_token|api[_-]?key)\s*['\"]?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)",
        r"\1[已隐藏]", text,
    )
    text = re.sub(r"https?://[^\s]+", "[链接已隐藏]", text)
    text = re.sub(r"(?i)\b(?:set-cookie|cookie|cookies)\b\s*['\"]?\s*[:=：][^\r\n]+", "Cookie=[已隐藏]", text)
    text = re.sub(r"(?<!\d)\d{6}(?!\d)", "[验证码已隐藏]", text)
    return text[:1000]


def normalize_security_progress(value: Any) -> dict[str, Any] | None:
    """Discard credential fields; callers also redact their known secret values."""
    if not isinstance(value, dict) or not isinstance(value.get("stage"), str) or value["stage"] not in STAGE_LABELS:
        return None
    status = value.get("status")
    retry_mode = value.get("retry_mode")
    code = value.get("code")
    def count(key: str) -> int:
        item = value.get(key)
        return min(2, max(0, item)) if isinstance(item, int) and not isinstance(item, bool) else 0
    completed = value.get("completed_stages")
    completed = completed if isinstance(completed, list) else []
    result = {
        "stage": value["stage"],
        "status": status if isinstance(status, str) and status in STATUSES else "review",
        "code": code if isinstance(code, str) and code in CODES else "",
        "reason": _safe_reason(value.get("reason")),
        "retry_mode": retry_mode if isinstance(retry_mode, str) and retry_mode in RETRY_MODES else "verify_first",
        "retry_attempt": count("retry_attempt"),
        "retry_limit": count("retry_limit"),
        "completed_stages": list(dict.fromkeys(item for item in completed if isinstance(item, str) and item in STAGE_LABELS)),
    }
    # Missing metadata is deliberately not upgraded. Old data and intermediate
    # diagnostics carry no task-level authorization; consumers default manual.
    if isinstance(status, str) and status in {"failed", "review"} and "task_retry" in value:
        result["task_retry"] = normalize_task_retry(value["task_retry"]) or {
            "strategy": "manual", "reason_code": "insufficient_evidence",
        }
    return result
