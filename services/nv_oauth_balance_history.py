"""Read-only refinement of a terminal legacy SMS configuration failure.

An exact, complete NO_BALANCE attempt refines the recorded provider phase only.
It does not check today's balance, authorize a retry, or change any job state.
"""
from __future__ import annotations

import json
import math
import re
import time

from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure
from services.nv_oauth_sms_history import (
    _CONFIGURATION, _COUNTRY_START, _NORMAL_START, _START,
    _WAIT_CALLBACK, _message, _other_outcome, _timestamp,
)


_MAX_LOGS = 20000
_REASON = "短信服务配置、账户余额或权限不满足要求"
_FAILURE = "✗ OAuth 失败: " + _REASON
_NUMBER_FAILURE = re.compile(r"\[smsbower ([0-9]+)/1/([1-9]|10)\] 取号失败: NO_BALANCE")
_GLOBAL_STOP = "[smsbower] NO_BALANCE 属账号级问题, 终止全部尝试"
_SUMMARY = re.compile(r"\[smsbower\] 全部国家轮换结束: ([0-9]+)=NO_BALANCE")
_PHONE_START = re.compile(
    r"\[smsbower\] add_phone 启动 \(service=[A-Za-z0-9_-]+, countries=\[([0-9]+(?:,[0-9]+)*)\],"
    r" maxPrice=(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+), attempts_per_country=([1-9]|10)"
    r"(?:, 短信等待上限=(?:[1-9][0-9]{0,3})秒)?\)"
)
_LOCAL_CLEANUP = re.compile(
    r"\[DrissionPage cleanup\] 目录=/[A-Za-z0-9_./-]+, 总数=[0-9]+, 删除=[0-9]+, "
    r"活跃跳过=[0-9]+, 新目录跳过=[0-9]+, 失败=0"
)
_READ_ONLY = frozenset({
    "开始核对：获取 RT",
    "正在核对本次 RT 落库与工作区成员状态，不重新授权或覆盖 RT",
    "已请求核对远端结果",
    "已进入一键串行处理；本批仅授权一次，先核对原结果再继续",
    "执行结果证据不足，未自动重新获取 RT",
    "OAuth 失败证据需先核对后才能重新授权",
    "授权结果或邀请周期证据不足，不能自动重新获取 RT；获取 RT 未完成：" + _REASON,
    "RT 原始失败原因：" + _REASON + "；先核对是否已保存凭证，再判断能否安全重试",
    _REASON,
})


def _sequence(entries: list[tuple[float, str]], started: float, email: str) -> bool:
    starts = [i for i, (_, message) in enumerate(entries) if message == _START]
    numbers = [i for i, (_, message) in enumerate(entries) if _NUMBER_FAILURE.fullmatch(message)]
    stops = [i for i, (_, message) in enumerate(entries) if message == _GLOBAL_STOP]
    summaries = [i for i, (_, message) in enumerate(entries) if _SUMMARY.fullmatch(message)]
    failures = [i for i, (_, message) in enumerate(entries) if message == _FAILURE]
    if any(len(indices) != 1 for indices in (starts, numbers, stops, summaries, failures)):
        return False
    start, number, stop, summary, failure = (indices[0] for indices in (starts, numbers, stops, summaries, failures))
    if not start < number < stop < summary < failure or not 0 <= entries[start][0] - started <= 10:
        return False
    country, maximum = _NUMBER_FAILURE.fullmatch(entries[number][1]).groups()
    if _SUMMARY.fullmatch(entries[summary][1]).group(1) != country:
        return False
    phone_start = None
    configured_countries = None
    country_start = None
    wrappers = set()
    for index, (_, message) in enumerate(entries):
        if index in {start, number, stop, summary, failure}:
            continue
        if index > failure:
            if message not in _READ_ONLY:
                return False
            continue
        config = _PHONE_START.fullmatch(message)
        injected = _CONFIGURATION.fullmatch(message)
        country_marker = _COUNTRY_START.fullmatch(message)
        wrapper = ("step" if message == _NORMAL_START else
                   "launch" if message in {f"OAuth 启动: {email} (proxy=有)", f"OAuth 启动: {email} (proxy=无)"} else None)
        if config:
            if not start < index < number or phone_start is not None or country_start is not None:
                return False
            phone_start = (config.group(1).split(","), int(config.group(2)))
        elif injected:
            if not start < index < number or configured_countries is not None or phone_start is not None:
                return False
            configured_countries = injected.group(1).split(",")
        elif country_marker:
            if not start < index < number or country_start is not None:
                return False
            position, count, marker_country = country_marker.groups()
            if position != "1" or marker_country != country:
                return False
            country_start = int(count)
        elif wrapper:
            if (not start < index < number or wrapper in wrappers or phone_start is not None
                    or (wrapper == "step" and "launch" in wrappers)):
                return False
            wrappers.add(wrapper)
        elif message == "[smsbower] " + _REASON:
            if not summary < index < failure or "reason" in wrappers:
                return False
            wrappers.add("reason")
        elif message in {"[smsbower] 使用自定义 base_url: [链接已隐藏]", "[smsbower] 使用自定义接码服务地址"}:
            if not start < index < number or phone_start is not None or "base_url" in wrappers:
                return False
            wrappers.add("base_url")
        elif message == _WAIT_CALLBACK:
            if not start < index < number or "wait_callback" in wrappers:
                return False
            wrappers.add("wait_callback")
        elif _LOCAL_CLEANUP.fullmatch(message):
            if not start < index < number or "local_cleanup" in wrappers:
                return False
            wrappers.add("local_cleanup")
        elif message == "[DrissionPage] 临时 profile 暂未清理: invalid_path":
            # This is not teardown evidence; the saved terminal flag is required.
            if not summary < index < failure or "cleanup" in wrappers:
                return False
            wrappers.add("cleanup")
        elif ("smsbower" in message.lower() or _other_outcome(message)
              or re.search(r"NO_BALANCE|BAD_KEY|NO_NUMBERS|ACCESS_NUMBER|短信|手机号|号码|接码|"
                           r"\b(?:sms|activation|getnumber|setstatus)\b",
                           message, re.IGNORECASE)):
            return False
    for countries in (configured_countries, phone_start[0] if phone_start else None):
        if countries is not None and (countries[0] != country or len(set(countries)) != len(countries)
                                      or country_start is not None and country_start != len(countries)):
            return False
    if phone_start is not None and (phone_start[1] != int(maximum)
                                   or configured_countries is not None and phone_start[0] != configured_countries):
        return False
    return True


def historical_sms_balance_failure(session, job) -> dict | None:
    """Inspect only the caller's current job and complete logs, without flushing.

    None means incomplete, contradictory, stale or ineligible evidence. A fixed
    failure DTO is diagnostic evidence, never a retry grant or a counter reset.
    """
    try:
        with session.no_autoflush:
            return _historical_sms_balance_failure(session, job)
    except Exception:
        return None


def _historical_sms_balance_failure(session, job) -> dict | None:
    if (getattr(job, "step", None) != "oauth" or not isinstance(job.id, str) or not job.id
            or getattr(job, "status", None) not in {"failed", "review"}
            or getattr(job, "worker_token", None) or getattr(job, "worker_pid", None)):
        return None
    email = getattr(job, "email", None)
    if not isinstance(email, str) or not email or _message(email) != email or " " in email:
        return None
    context = json.loads(job.context_json)
    if not isinstance(context, dict) or context.get("oauth_attempted") is not True:
        return None
    count = context.get("oauth_execution_attempts")
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if (type(count) is not int or count < 1 or failure is None
            or failure["code"] != "sms_configuration_error" or failure["terminal"] is not True
            or failure["retryable"] is not False or failure["callback_received"] is not False
            or failure["exchange_started"] is not False):
        return None
    started = _timestamp(context.get("oauth_started_at"))
    failed = _timestamp(context.get("oauth_failure_started_at"))
    invited = _timestamp(context.get("oauth_membership_invited_at"))
    now = time.time()
    if started is None or failed != started or invited is None or not invited <= started <= now:
        return None
    # Importing the diagnostic alone must not initialize the application DB.
    from sqlmodel import select
    from services.nv_automation_store import NvAutomationLog

    logs = session.exec(select(NvAutomationLog).where(NvAutomationLog.job_id == job.id)
                        .order_by(NvAutomationLog.created_at, NvAutomationLog.id)
                        .limit(_MAX_LOGS + 1)).all()
    if not logs or len(logs) > _MAX_LOGS:
        return None
    entries = []
    for log in logs:
        stamp, message = log.created_at, _message(log.message)
        if (type(stamp) not in (int, float) or not math.isfinite(stamp)
                or not 0 < stamp <= now or message is None):
            return None
        if stamp >= started:
            if log.step != "oauth":
                return None
            entries.append((stamp, message))
    if not _sequence(entries, started, email):
        return None
    return OAuthAttemptFailure("sms_balance_insufficient", charge_possible=failure["charge_possible"], terminal=True).oauth_failure
