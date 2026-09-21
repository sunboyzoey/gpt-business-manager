"""Read-only compatibility for the old, precisely diagnosed password-page stall.

Only refine an already closed pre-callback attempt. This is not a retry grant:
the normal current-member, credential, execution-budget and fee gates still run.
Unknown failures and incomplete logs remain unknown; no production rows are
rewritten when displaying or previewing recovery.
"""
from __future__ import annotations

import json
import math
import re
import time

from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure
from services.nv_oauth_sms_history import _message, _timestamp


LEGACY_REASON = (
    "密码登录后仍停在 /log-in/password · 页面无报错元素"
    "(见上方 [diag] 可见文本/截图判断是密码错/验证/captcha)"
)
_START = "RT 任务已启动"
_SUBMIT = "[routing] 密码验证登录已填写密码并提交，等待远端验证"
_FAIL = "✗ OAuth 失败: " + LEGACY_REASON
_MAX_LOGS = 500
_READ_ONLY = {
    "RT 原始失败原因：" + LEGACY_REASON + "；先核对是否已保存凭证，再判断能否安全重试",
    "正在核对本次 RT 落库与工作区成员状态，不重新授权或覆盖 RT",
    "本次 RT 执行终态或账号记录不完整，暂不能重新授权；获取 RT 未完成：" + LEGACY_REASON,
    "开始核对：获取 RT", "已请求核对远端结果",
    "已进入一键串行处理；本批仅授权一次，先核对原结果再继续",
}


def historical_password_page_context(session, job):
    """Project exact old evidence, preserving actual attempts and possible cost."""
    from sqlmodel import select
    from services.nv_automation_store import NvAutomationLog
    from services.nv_oauth_legacy import _contradictory, _unreliable_timeout_evidence

    with session.no_autoflush:
        try:
            context = json.loads(job.context_json or "{}")
        except (ValueError, TypeError):
            return {}
        if not isinstance(context, dict):
            return {}
        failure = normalize_oauth_failure(context.get("oauth_failure"))
        started = _timestamp(context.get("oauth_started_at"))
        invited = _timestamp(context.get("oauth_membership_invited_at"))
        count = context.get("oauth_execution_attempts")
        if (job.step != "oauth" or not failure or failure["code"] != "oauth_unknown"
                or not failure["terminal"] or failure["callback_received"] or failure["exchange_started"]
                or context.get("oauth_failure_detail") != LEGACY_REASON
                or context.get("oauth_attempted") is not True
                or context.get("oauth_reconcile_only") is True
                or context.get("oauth_retry_ready") not in (None, False)
                or type(count) is not int or count < 1 or not started or not invited
                or not invited <= started <= time.time()
                or started != _timestamp(context.get("oauth_failure_started_at"))):
            return context
        rows = session.exec(select(NvAutomationLog).where(
            NvAutomationLog.job_id == job.id, NvAutomationLog.step == "oauth",
            NvAutomationLog.created_at >= started,
        ).order_by(NvAutomationLog.id).limit(_MAX_LOGS + 1)).all()
        if not rows or len(rows) > _MAX_LOGS:
            return context
        now = time.time()
        if any(not isinstance(row.created_at, (int, float)) or not math.isfinite(row.created_at)
               or not started <= row.created_at <= now for row in rows):
            return context
        bodies = [_message(row.message) for row in rows]
        if any(body is None for body in bodies):
            return context
        if any(bodies.count(marker) != 1 for marker in (_START, _SUBMIT, _FAIL)):
            return context
        first, submit, final = (bodies.index(marker) for marker in (_START, _SUBMIT, _FAIL))
        if first != 0 or not first < submit < final or not 0 <= rows[first].created_at - started <= 10:
            return context
        if any(rows[i].created_at > rows[i + 1].created_at for i in range(len(rows) - 1)):
            return context
        between = bodies[submit + 1:final]
        if not any(body == "[diag password_submit_stuck] url=[链接已隐藏]" for body in between):
            return context
        if not any(re.fullmatch(r"\[diag password_submit_stuck\] html_len=[1-9][0-9]*", body) for body in between):
            return context
        # Full-episode audit: contradictory outcomes, another OAuth, or any
        # post-failure work other than known read-only reconciliation veto it.
        for index, body in enumerate(bodies):
            if index == final:
                continue
            if index > final:
                if body not in _READ_ONLY:
                    return context
                continue
            if (_contradictory(body) or _unreliable_timeout_evidence(body) or any(word in body for word in (
                    "account_deactivated", "account_deleted", "密码错误", "密码不正确", "拒绝", "验证码无效",
                    "取号成功", "收到 SMS", "开始 token", "兑换", "OAuth 失败", "OAuth 成功",
                )) or re.search(r"\b(?:wrong|incorrect|invalid)\s+(?:email\s+or\s+)?password\b", body, re.I)):
                return context
        projected = OAuthAttemptFailure(
            "password_page_timeout", terminal=True,
            charge_possible=failure["charge_possible"],
        ).oauth_failure
        return {**context, "oauth_failure": projected}
