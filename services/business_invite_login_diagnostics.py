"""Credential-free diagnostics for failures before a BUSINESS invite request.

This module performs no I/O. Retry permission is deliberately narrower than
"login failed": callers must also prove that no invite request was sent.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable


FAILURE_STAGES = {
    "init", "open_login_page", "fill_email", "wait_otp_page", "fetch_otp",
    "about_you", "wait_landing", "extract_session", "password_totp_login",
    "security_state_unavailable", "security_credentials_unavailable",
    "security_credentials_incomplete", "account_deactivated", "post_login_action",
    "done", "configuration", "unknown", "login_transport",
}
STAGE_LABELS = {
    "init": "准备登录浏览器", "open_login_page": "打开登录页面",
    "fill_email": "填写账号邮箱", "wait_otp_page": "等待邮箱验证码页面",
    "fetch_otp": "等待并验证邮箱验证码", "about_you": "处理账号资料页面",
    "wait_landing": "等待进入 ChatGPT", "extract_session": "提取已登录会话",
    "password_totp_login": "密码与 Authenticator 登录",
    "login_transport": "连接登录服务",
    "security_state_unavailable": "读取账号安全状态",
    "security_credentials_unavailable": "读取账号安全凭据",
    "security_credentials_incomplete": "检查账号安全凭据",
    "account_deactivated": "账号已停用", "post_login_action": "登录后动作",
    "done": "登录完成", "configuration": "检查登录配置", "unknown": "登录阶段未确认",
}
_RETRY_STAGES = {"init", "open_login_page", "fill_email", "wait_otp_page", "fetch_otp",
                 "about_you", "wait_landing", "extract_session", "password_totp_login", "login_transport"}
_MFA_NAMES = {"two-factor", "two factor", "authenticator", "totp", "2fa", "mfa"}
_PERMANENT = (
    "invalid_grant", "invalid_client", "invalid credentials", "incorrect password",
    "invalid_credentials", "invalid_password", "incorrect_password", "invalid_otp", "invalid_totp",
    "auth_rejected", "auth_error", "authentication_error", "authentication_failed",
    "challenge_failed", "challenge_required",
    "wrong password", "invalid password", "authentication failed", "unauthorized", "forbidden",
    "credentials unavailable", "credentials missing", "credentials required", "missing credentials",
    "two-factor", "two factor", "operation lock", "access denied",
    "account_deactivated", "account_deleted", "access_deactivated", "disabled",
    "suspended", "banned", "authenticator", "totp", "2fa", "mfa",
    "security_credentials", "security_state", "lease", "claim", "busy",
    "密码错误", "密码不正确", "凭据", "配置", "缺少", "未提供", "无法解密",
    "账号不存在", "账号已停用", "账号已被停用", "账号已禁用", "账号已被禁用",
    "账号已封禁", "账户已停用", "被封", "身份与目标", "身份不一致",
    "验证码错误", "验证码不正确", "验证码无效", "非法 otp", "invalid otp",
    "invalid code", "incorrect code", "wrong otp", "otp rejected", "totp rejected",
    "invalid totp", "incorrect otp", "incorrect totp", "authentication rejected",
    "password rejected", "otp invalid", "totp invalid", "otp failed", "totp failed",
    "没有原密钥", "没有密钥", "密钥不完整", "密钥不存在", "密钥缺失", "missing seed", "seed missing",
    "密钥为空", "原密钥未保存", "seed not found", "totp secret not found",
    "未完成 2fa 校验", "验证未通过", "认证结果", "登录结果未确认", "登录结果未知",
    "authentication result", "authentication outcome", "身份验证结果", "验证码被拒绝",
    "登录状态未知", "登录状态不明", "结果无法确认", "认证状态未确认",
    "租约", "正在执行", "操作占用", "不支持",
    "浏览器清理未确认", "浏览器启动配置错误",
)
_TRANSIENT = (
    "timeout", "timed out", "time out", "超时", "连接重置", "连接中断", "暂时不可用",
    "connection reset", "connection refused", "connection aborted", "connection closed",
    "network error", "network is unreachable", "err_connection", "err_network",
    "err_name_not_resolved", "temporary failure", "temporarily unavailable",
    "bad gateway", "service unavailable", "gateway timeout",
    "元素对象已失效", "stale element", "elementlosterror",
)
_TEMPORARY_PAGES = {
    "open_login_page": ("找不到登录按钮", "无法打开登录表单", "登录页面未就绪"),
    "fill_email": ("找不到邮箱输入框", "找不到/点不到", "未找到邮箱输入框", "邮箱输入框未出现",
                   "邮箱输入框填写未通过回读确认"),
    "wait_otp_page": ("未跳转到 otp 页", "未进入验证码页", "等待验证码页面失败"),
    "fetch_otp": ("未收到验证码", "未获取到验证码", "未取得验证码"),
    "wait_landing": ("未跳转到 chatgpt.com", "未能进入 chatgpt 主页"),
}


def browser_start_failure(reason: Any) -> bool:
    """Recognize only local startup diagnostics, not a remote auth rejection.

    The legacy DrissionPage signature is kept for an identity-fenced recovery
    migration. New launches emit a fixed phrase only after owned cleanup.
    """
    if not isinstance(reason, str) or _hard_failure(reason.casefold(), managed=True):
        return False
    if "本地浏览器启动暂时失败，已清理本次启动进程" in reason:
        return True
    return bool("浏览器连接失败。" in reason and "ChromiumOptions" in reason
                and re.search(r"(?:127\.0\.0\.1|localhost):(?:\d{1,5}|\[验证码已隐藏\]|\[调试端口\])", reason))


def safe_prelogin_reason(value: Any, *, known_secrets: Iterable[str] = ()) -> str:
    """Redact exact known values before generic patterns; never stringify DTOs."""
    if not isinstance(value, str):
        return "登录失败，未返回可识别的具体原因"
    text = value.strip()
    for secret in sorted({item for item in known_secrets if isinstance(item, str) and item}, key=len, reverse=True):
        text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"otpauth://\S+|https?://[^\s\"'<>]+", "[链接已隐藏]", text, flags=re.I)
    text = re.sub(r"(?i)\bbearer\s+[^\s,;]+", "Bearer [已隐藏]", text)
    text = re.sub(r"(?i)\b(?:proxy-)?authorization\s*['\"]?\s*[:=：]\s*(?:basic|bearer)\s+[^\s,;}\]]+",
                  "Authorization=[已隐藏]", text)
    text = re.sub(
        r"(?i)\b(?:[a-z][\w-]*[_-](?:secret|seed)|(?:totp|authenticator|mfa|2fa)(?:secret|seed))\b"
        r"\s*['\"]?\s*[:=：]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        "安全密钥=[已隐藏]", text,
    )
    text = re.sub(r"(?<![\w-])[\w-]{2,}\.[\w-]{2,}\.[\w-]{8,}(?![\w-])", "[令牌已隐藏]", text)
    text = re.sub(
        r"(?i)\b(password|passwd|secret|totp|otp|code|client[_ -]?(?:id|secret)|"
        r"(?:access|refresh|session|id)[_ -]?token|api[_ -]?key|authorization|rt)\b"
        r"\s*['\"]?\s*[:=：]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        lambda m: f"{m.group(1)}=[已隐藏]", text,
    )
    text = re.sub(r"(?i)\b(?:set-cookie|cookie|cookies)\b\s*['\"]?\s*[:=：][^\r\n]+", "Cookie=[已隐藏]", text)
    text = re.sub(r"(?i)\b(?:sk-|rt-)[A-Za-z0-9_-]{12,}", "[凭据已隐藏]", text)
    # A local CDP port is not an email OTP. Do not mislabel it as one.
    text = re.sub(r"\b(127\.0\.0\.1|localhost):(?:\d{1,5}|\[验证码已隐藏\])",
                  r"\1:[调试端口]", text)
    text = re.sub(r"(?<!\d)\d{4,8}(?!\d)", "[验证码已隐藏]", text)
    text = re.sub(r"未跳转到\s*OTP\s*页", "等待邮箱验证码页面超时", text, flags=re.I)
    text = re.sub(r"\s*[（(]当前\s*URL\s*[:：]\s*\[链接已隐藏\][）)]?", "", text, flags=re.I)
    return text[:700] or "登录失败，未返回可识别的具体原因"


def _retryable(stage: str, reason: str) -> bool:
    if stage not in _RETRY_STAGES:
        return False
    lowered = reason.casefold()
    if _hard_failure(lowered, managed=stage == "password_totp_login"):
        return False
    if stage == "init" and browser_start_failure(reason):
        return True
    if stage == "password_totp_login":
        # This source stage already proved both encrypted credentials exist.
        # Merely mentioning Authenticator is not a rejection. A generic login
        # timeout still lacks evidence of a transport or control failure.
        return bool(
            any(marker in lowered for marker in _TRANSIENT if marker not in {
                "timeout", "timed out", "time out", "超时", "暂时不可用", "temporary failure", "temporarily unavailable",
            })
            or "网络连接错误" in lowered
            or re.search(r"(?:network|connection|request|browser|page|element|control|selector|locator|input)[^\n]{0,48}(?:timeout|timed out|time out)", lowered)
            or re.search(r"(?:网络|连接|请求|浏览器|页面|控件|元素|输入框|按钮)[^\n]{0,24}(?:超时|失效)", lowered)
        )
    return bool(any(marker in lowered for marker in _TRANSIENT)
                or any(marker in lowered for marker in _TEMPORARY_PAGES.get(stage, ())))


def _hard_failure(reason: str, *, managed: bool = False) -> bool:
    return bool(any(marker in reason for marker in _PERMANENT if not (managed and marker in _MFA_NAMES))
                or re.search(r"(?<!\d)(?:401|403)(?!\d)", reason))


def classify_prelogin_failure(stage: Any, reason: Any, *, known_secrets: Iterable[str] = (),
                             login_failure: Any = None) -> dict[str, Any]:
    """Classify source evidence, never infer success or invitation state."""
    normalized_stage = stage if isinstance(stage, str) and stage in FAILURE_STAGES else "unknown"
    safe_reason = safe_prelogin_reason(reason, known_secrets=known_secrets)
    if login_failure is not None:
        from platforms.chatgpt.gpt_pro_login import login_failure_reason, normalize_login_failure
        typed = normalize_login_failure(login_failure)
        if typed is None or typed["stage"] != normalized_stage:
            return {"failure_stage": normalized_stage, "failure_reason": safe_reason, "retryable": False}
        return {"failure_stage": normalized_stage, "failure_reason": login_failure_reason(typed),
                "retryable": typed["retryable"] is True and not _hard_failure(safe_reason.casefold()),
                "login_failure": typed}
    return {"failure_stage": normalized_stage, "failure_reason": safe_reason,
            "retryable": _retryable(normalized_stage, safe_reason)}


def normalize_prelogin_failure(value: Any) -> dict[str, Any] | None:
    """Consume only the exact pre-invite failure envelope and strict booleans."""
    if (not isinstance(value, dict) or value.get("code") != "business_child_prelogin_failed"
            or value.get("remote_invite_sent") is not False):
        return None
    result = classify_prelogin_failure(value.get("failure_stage"), value.get("failure_reason"),
                                      login_failure=value.get("login_failure"))
    result["retryable"] = bool(value.get("retryable") is True and result["retryable"])
    result["remote_invite_sent"] = False
    return result


def prelogin_exception_stage(reason: Any) -> str:
    """No authoritative login result means no retry, even for an unknown timeout."""
    lowered = reason.casefold() if isinstance(reason, str) else ""
    return "configuration" if any(marker in lowered for marker in (
        "配置", "缺少", "凭据", "无法解密", "mailbox is required", "invalid_client", "invalid_grant",
    )) else "unknown"


def classify_prelogin_exception(exc: Exception, *, remote_invite_sent: bool,
                               known_secrets: Iterable[str] = ()) -> dict[str, Any]:
    """Classify typed transport failure only at an explicit no-invite boundary.

    Raw exception text can veto retry, but never grant it. Return fixed reasons
    for recognized transports; preserve safe diagnostics for everything else.
    """
    if type(exc).__module__ == "core.browser_startup" and type(exc).__name__ == "BrowserInitializationError":
        safe_reason = safe_prelogin_reason(str(exc), known_secrets=known_secrets)
        result = classify_prelogin_failure("init", safe_reason)
        result["retryable"] = bool(remote_invite_sent is False and getattr(exc, "retryable", False) is True
                                   and getattr(exc, "cleanup_complete", False) is True and result["retryable"])
        return result
    detail = getattr(exc, "detail", None)
    if isinstance(detail, dict):
        reason = detail.get("error") or detail.get("message") or "登录前检查失败"
        code = detail.get("code")
    else:
        reason = detail if isinstance(detail, str) else str(exc)
        code = None
    safe_reason = safe_prelogin_reason(reason, known_secrets=known_secrets)
    rejected = _hard_failure(safe_reason.casefold(), managed=True) or (
        isinstance(code, str) and _hard_failure(code.casefold(), managed=True)
    )
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    transient_http = type(status) is int and status in {408, 429, 502, 503, 504}
    classes = {(cls.__module__, cls.__name__) for cls in type(exc).__mro__}
    typed_network = bool(classes & {
        ("builtins", "TimeoutError"), ("builtins", "ConnectionError"),
        ("requests.exceptions", "Timeout"), ("requests.exceptions", "ConnectionError"),
        ("httpx", "TimeoutException"), ("httpx", "NetworkError"),
    })
    if (remote_invite_sent is False and not rejected
            and (transient_http or status is None and typed_network)):
        fixed_reason = (f"登录请求返回 HTTP {status}，服务暂时不可用；尚未发送 BUSINESS 邀请"
                        if transient_http else "登录网络连接暂时不可用；尚未发送 BUSINESS 邀请")
        return classify_prelogin_failure("login_transport", fixed_reason)
    result = classify_prelogin_failure(prelogin_exception_stage(safe_reason), safe_reason)
    result["retryable"] = False
    return result


def make_prelogin_logger(callback: Any, child_id: int) -> Callable[[Any], None]:
    """Project known browser log markers to fixed phrases, never forward raw logs."""
    last_stage = ""
    input_mismatch_logged = False
    markers = (
        ("[GPT PRO 登录] 1/5", "open_login_page"),
        ("[GPT PRO 登录] 2/5", "fill_email"),
        ("[GPT PRO 登录] 3/5", "wait_otp_page"),
        ("[GPT PRO 登录] 4/5", "fetch_otp"),
        ("[GPT PRO 登录] 5/5", "wait_landing"),
        ("[GPT PRO 登录] 等 /about-you", "about_you"),
        ("[GPT PRO 登录] 检测到已管理的 Authenticator 2FA", "password_totp_login"),
        ("[账号安全] 密码已通过，正在自动补全中断的账号资料", "about_you"),
        ("[账号安全] 密码已通过，旧注册资料页已失效，正在转入现有账号会话", "about_you"),
        ("[GPT PRO 登录] ✅ 完成:", "done"),
        ("[GPT PRO 登录] 浏览器已创建", "init"),
    )

    def log(message: Any) -> None:
        nonlocal last_stage, input_mismatch_logged
        if not callable(callback) or not isinstance(message, str):
            return
        if (message.startswith("[GPT PRO 登录] ⚠ 邮箱填后又空/不符")
                and "__noinput__" in message and not input_mismatch_logged):
            input_mismatch_logged = True
            try:
                callback(f"[邀请前登录] 子号 #{int(child_id)}：邮箱输入框定位与回读不一致，尚未确认邮箱填写成功")
            except Exception:
                pass
            return
        for prefix, stage in markers:
            if message.startswith(prefix):
                if last_stage != stage:
                    last_stage = stage
                    try:
                        callback(f"[邀请前登录] 子号 #{int(child_id)}：{STAGE_LABELS[stage]}")
                    except Exception:
                        pass
                return
    return log
