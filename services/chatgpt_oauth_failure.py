"""Credential-free OAuth failure evidence; retry flags never authorize spending.

Only controlled browser boundaries may create retryable evidence. Unknown errors
must not be classified by matching their text. A caller must separately enforce
its retry limit, account ownership and any SMS spending authorization.
"""
from __future__ import annotations

from typing import Any


_CATALOG = {
    "browser_start_failed": ("browser", "OAuth 浏览器未能启动"),
    "browser_timeout": ("browser", "OAuth 浏览器等待页面推进超时"),
    "oauth_cancelled": ("browser", "OAuth 已主动停止"),
    "control_timeout": ("login", "OAuth 页面控件等待超时"),
    "password_page_timeout": ("login", "OAuth 密码已提交，但密码登录页未推进，未确认登录成功"),
    "sms_timeout": ("add_phone", "手机号已进入短信验证，但等待验证码超时"),
    "sms_rejected": ("add_phone", "OpenAI 明确拒绝了手机号或短信验证码"),
    "sms_phone_rejected": ("add_phone", "OpenAI 明确提示手机号无效或不支持"),
    "sms_account_restricted": ("add_phone", "OpenAI 限制了账号或手机号验证次数，需稍后处理"),
    "sms_code_rejected": ("add_phone", "OpenAI 明确拒绝了本次短信验证码"),
    "sms_number_request_failed": ("add_phone", "接码取号网络请求异常，号码分配或扣费结果未确认"),
    "sms_number_http_502": ("add_phone", "接码取号请求返回 HTTP 502，号码分配或扣费结果未确认"),
    "sms_no_inventory": ("add_phone", "短信服务商没有可用号码库存"),
    "sms_balance_insufficient": ("add_phone", "接码平台余额不足，充值并确认余额后可恢复"),
    "sms_configuration_error": ("add_phone", "短信服务配置、账户余额或权限不满足要求"),
    "phone_verification_not_authorized": ("add_phone", "本次 OAuth 未授权手机号验证，已停止且未申请短信号码"),
    "sms_cancelled": ("add_phone", "短信服务商已取消本次号码激活"),
    "sms_provider_error": ("add_phone", "短信服务或验证页面结果未确认，不能判定为拒收"),
    "password_rejected": ("login", "OpenAI 明确拒绝了登录密码"),
    "account_deactivated": ("login", "OpenAI 已确认该账号已停用"),
    "callback_invalid": ("callback", "已收到 OAuth 回调，但授权码或 state 校验未通过"),
    "exchange_failed": ("exchange", "OAuth 授权兑换未确认成功，不得自动重新授权"),
    "partial_credentials": ("persistence", "OAuth 未取得完整凭证，不得自动重新授权"),
    "oauth_unknown": ("unknown", "OAuth 结果未确认，请查看原始失败日志并人工核对"),
}
_RETRY_CODES = frozenset({"browser_timeout", "control_timeout", "password_page_timeout", "sms_timeout", "phone_verification_not_authorized"})
_BOOL_FIELDS = ("retryable", "callback_received", "exchange_started", "charge_possible", "terminal")
_FIELDS = frozenset({"code", "stage", "reason", *_BOOL_FIELDS})


def normalize_oauth_failure(value: Any) -> dict[str, Any] | None:
    """Validate the complete closed DTO. Missing/extra/ambiguous data fails closed."""
    if not isinstance(value, dict) or set(value) != _FIELDS:
        return None
    code = value.get("code")
    if not isinstance(code, str) or code not in _CATALOG:
        return None
    stage, reason = _CATALOG[code]
    if value.get("stage") != stage or value.get("reason") != reason:
        return None
    if any(type(value.get(key)) is not bool for key in _BOOL_FIELDS):
        return None
    if value["exchange_started"] and not value["callback_received"]:
        return None
    if code == "callback_invalid" and not value["callback_received"]:
        return None
    if code in {"exchange_failed", "partial_credentials"} and not value["exchange_started"]:
        return None
    if value["retryable"] and (
        code not in _RETRY_CODES or not value["terminal"]
        or value["callback_received"] or value["exchange_started"]
    ):
        return None
    if code in {"sms_timeout", "sms_number_http_502", "sms_number_request_failed"} and not value["charge_possible"]:
        return None
    return {key: value[key] for key in ("code", "stage", "reason", *_BOOL_FIELDS)}


class OAuthAttemptFailure(RuntimeError):
    """A fixed reason plus monotonic, credential-free attempt evidence."""

    def __init__(self, code: str, *, callback_received: bool = False,
                 exchange_started: bool = False, charge_possible: bool = False,
                 terminal: bool = True):
        if code not in _CATALOG or any(type(v) is not bool for v in (
            callback_received, exchange_started, charge_possible, terminal,
        )):
            raise ValueError("invalid OAuth failure evidence")
        stage, reason = _CATALOG[code]
        self.oauth_failure = {
            "code": code, "stage": stage, "reason": reason,
            "retryable": False, "callback_received": callback_received,
            "exchange_started": exchange_started, "charge_possible": charge_possible,
            "terminal": terminal,
        }
        self.set_attempt_evidence(terminal=terminal)
        super().__init__(reason)

    def set_attempt_evidence(self, *, callback_received: bool = False,
                             exchange_started: bool = False, charge_possible: bool = False,
                             terminal: bool | None = None) -> None:
        """Never downgrade observed callback/exchange/possible-charge evidence."""
        if any(type(v) is not bool for v in (callback_received, exchange_started, charge_possible)):
            raise ValueError("invalid OAuth failure evidence")
        value = dict(self.oauth_failure)
        for key, flag in (("callback_received", callback_received),
                          ("exchange_started", exchange_started), ("charge_possible", charge_possible)):
            value[key] = value[key] or flag
        if terminal is not None:
            if type(terminal) is not bool:
                raise ValueError("invalid OAuth terminal evidence")
            value["terminal"] = terminal
        value["retryable"] = (value["code"] in _RETRY_CODES and value["terminal"]
                              and not value["callback_received"] and not value["exchange_started"])
        normalized = normalize_oauth_failure(value)
        if normalized is None:
            raise ValueError("inconsistent OAuth failure evidence")
        self.oauth_failure = normalized
