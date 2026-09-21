"""NV-only bounded reauthorization policy; no credentials or network calls.

The browser DTO describes what happened. This policy decides whether a *new*
OAuth transaction may be attempted after that worker has terminated. It does
not replay an authorization code or authorize overwriting a saved credential.
"""
from datetime import datetime, timezone
import re

from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure


RECOVERABLE_CODES = frozenset({
    "browser_start_failed", "browser_timeout", "control_timeout", "password_page_timeout",
    "sms_timeout", "sms_rejected", "sms_phone_rejected", "sms_code_rejected",
    "sms_number_request_failed", "sms_number_http_502", "sms_no_inventory",
    "sms_cancelled", "phone_verification_not_authorized", "sms_balance_insufficient",
    "sms_provider_error", "exchange_failed", "partial_credentials", "oauth_unknown",
})
HARD_FAILURE_CODES = frozenset({
    "sms_configuration_error", "sms_account_restricted", "password_rejected",
    "account_deactivated", "callback_invalid", "oauth_cancelled",
})
HARD_POLICY_REASONS = {
    "identity_mismatch": "账号或成员身份不一致",
    "auth_rejected": "账号登录被拒绝",
    "credentials_missing": "缺少必要登录凭证",
    "remote_change_unverified": "账号归属或凭证已变化，不能重放旧任务",
}


def _hard_policy(context):
    policy = context.get("task_retry")
    return (HARD_POLICY_REASONS.get(policy.get("reason_code"))
            if isinstance(policy, dict) and policy.get("strategy") == "manual" else None)


def _time(value):
    if not isinstance(value, str) or not value or len(value) > 80:
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.astimezone(timezone.utc) if date.tzinfo is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def recoverable_failure(value):
    failure = normalize_oauth_failure(value)
    return bool(failure and failure["terminal"] is True
                and failure["code"] in RECOVERABLE_CODES
                and (failure["code"] in {"exchange_failed", "partial_credentials"}
                     or not failure["callback_received"] and not failure["exchange_started"]))


def _attempt_evidence_valid(context):
    if not isinstance(context, dict) or context.get("oauth_reconcile_only") is True or _hard_policy(context):
        return False
    started = _time(context.get("oauth_started_at"))
    count = context.get("oauth_execution_attempts")
    return bool(started and started <= datetime.now(timezone.utc)
                and started == _time(context.get("oauth_failure_started_at"))
                and type(count) is int and count >= 1
                and (context.get("oauth_attempted") is True or (
                    context.get("oauth_attempted") is False and context.get("oauth_retry_ready") is True)))


def recovery_evidence_valid(context):
    return bool(_attempt_evidence_valid(context)
                and recoverable_failure(context.get("oauth_failure"))
                and (context["oauth_failure"]["code"] != "sms_provider_error"
                     or provider_recovery_evidence_valid(context)))


def provider_recovery_evidence_valid(context):
    """A closed pre-callback provider attempt permits bounded fresh inspection.

    The failure remains an unconfirmed provider/page result. Only the exact
    terminal DTO and frozen attempt/cycle identity qualify, including the
    retry-ready state produced after inspecting that failed attempt. The caller
    must first reconcile complete saved credentials, confirm the current cycle
    under the account lease, and enforce the execution and SMS spending limits.
    """
    if not _attempt_evidence_valid(context):
        return False
    ready = context.get("oauth_retry_ready")
    if context.get("oauth_attempted") is True and ready is not None and ready is not False:
        return False
    invited = _time(context.get("oauth_membership_invited_at"))
    started = _time(context.get("oauth_started_at"))
    if invited is None or started is None or invited > started:
        return False
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    return bool(failure and failure["code"] == "sms_provider_error"
                and failure["terminal"] is True
                and not failure["callback_received"] and not failure["exchange_started"])


def manual_provider_recovery_evidence_valid(context):
    """Retain eligibility for an explicit one-use grant on the original failure."""
    return bool(provider_recovery_evidence_valid(context)
                and context.get("oauth_attempted") is True
                and context.get("oauth_retry_ready") is not True)


def retry_problem(context, *, max_executions, phone_allowed, allow_extra_execution=False,
                  allow_manual_provider_error=False, allow_unknown_failure=False):
    if not isinstance(context, dict):
        return "unconfirmed_evidence", "本次 RT 执行终态或账号记录不完整，暂不能重新授权"
    if _hard_policy(context):
        return "permanent_failure", _hard_policy(context)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if failure and failure["code"] in HARD_FAILURE_CODES:
        return "permanent_failure", failure["reason"]
    unknown_recovery = bool(
        allow_unknown_failure is True
        and failure is not None
        and failure["code"] == "oauth_unknown"
        and failure["terminal"] is True
        and failure["callback_received"] is False
        and failure["exchange_started"] is False
        and _attempt_evidence_valid(context)
    )
    if not (recovery_evidence_valid(context) or unknown_recovery
            or allow_manual_provider_error is True and manual_provider_recovery_evidence_valid(context)):
        return "unconfirmed_evidence", "本次 RT 执行终态或账号记录不完整，暂不能重新授权"
    if type(max_executions) is not int or not 1 <= max_executions <= 5:
        return "unconfirmed_evidence", "本任务 RT 次数上限无法确认"
    # A closed unknown login-route failure gets one bounded automatic attempt
    # beyond the normal budget. The extra-attempt counter is consumed by the
    # worker before launch; subsequent unknown failures remain capped.
    unknown_extra = bool(unknown_recovery and context.get("oauth_unknown_auto_retry_count", 0) == 0)
    if context["oauth_execution_attempts"] >= max_executions and allow_extra_execution is not True and not unknown_extra:
        return "execution_limit", "RT 自动重试次数已用完，可手动重新获取一次"
    if (failure["charge_possible"] or failure["code"] in {
            "phone_verification_not_authorized", "sms_balance_insufficient",
            "sms_provider_error"}) and phone_allowed is not True:
        return "phone_cost_not_authorized", "未授权额外接码费用，已暂停重新获取 RT"
    return None


def classify_legacy_number_request(context, messages):
    """Read-only projection of exact old getNumber failures, never error guessing.

    A failed rental response may still have allocated/charged a number. Preserve
    charge_possible and require the normal spending authorization before retry.
    Mixed rental/page/poll failures are deliberately not reclassified.
    """
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if (not failure or failure["code"] != "sms_provider_error" or not failure["terminal"]
            or failure["callback_received"] or failure["exchange_started"]):
        return context
    bodies = [re.sub(r"^\s*(?:\[\d{2}:\d{2}:\d{2}\]\s*){0,2}", "", str(line)).strip()
              for line in messages]
    found = False
    for body in bodies:
        match = re.fullmatch(r"\[smsbower \d{1,6}/\d{1,2}/\d{1,2}\] 取号失败: (\S+)", body)
        if match:
            if match[1] != "REQUEST_FAILED":
                return context
            found = True
        elif any(marker in body for marker in ("取号成功", "取号异常", "手机号输入框命中", "已点击 add-phone", "等 SMS", "收到 SMS",
                                               "getStatus", "OpenAI 明确拒收", "phone OTP", "短信验证码被拒", "短信验证页面超时")):
            return context
    if not found:
        return context
    refined = OAuthAttemptFailure("sms_number_request_failed", charge_possible=True).oauth_failure
    return {**context, "oauth_failure": refined, "oauth_failure_detail": refined["reason"]}
