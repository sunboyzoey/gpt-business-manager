"""Read-only refinement of an already terminal, historical SMS provider error.

This does not authorize another OAuth or infer browser teardown from logs. The
caller owns the current job transaction and must independently enforce manual
authority, identity, credentials, fees and the actual execution limit.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import json
import math
import re
import time
import unicodedata

from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure


_MAX_LOGS = 20000
_START = "RT 任务已启动"
_REASON = "短信服务或验证页面结果未确认，不能判定为拒收"
_FAILURE = "✗ OAuth 失败: " + _REASON
_CLOCK = re.compile(r"^\[(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\] *")
_NUMBER_FAILURE = re.compile(r"\[smsbower ([0-9]+)/([1-9]|10)/([1-9]|10)\] 取号失败: HTTP_502")
_COUNTRY_FAILURE = re.compile(r"\[smsbower\] 国家 ([0-9]+) 失败 \(HTTP_502, 试了 ([1-9]|10) 次\), 进入下一国家")
_SUMMARY = re.compile(r"\[smsbower\] 全部国家轮换结束: ([0-9]+=HTTP_502(?:, [0-9]+=HTTP_502)*)")
_COUNTRY_START = re.compile(r"\[smsbower\] >>> 国家 ([1-9][0-9]*)/([1-9][0-9]*): ([0-9]+)")
_PHONE_START = re.compile(
    r"\[smsbower\] add_phone 启动 \(service=[A-Za-z0-9_-]+, countries=\[([0-9]+(?:,[0-9]+)*)\],"
    r" maxPrice=(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+), attempts_per_country=([1-9]|10)\)"
)
_CONFIGURATION = re.compile(r"已注入 smsbower 配置 \(countries=([0-9]+(?:,[0-9]+)*), service=[A-Za-z0-9_-]+\)")
_NORMAL_START = "步骤 1/1：邀请阶段已完成登录，直接开始 Codex OAuth"
_WAIT_CALLBACK = "[DrissionPage] 5/5 等 OAuth 完成 → callback"
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
_REFRESH = frozenset({
    "[smsbower] 刷新 /add-phone 页面 (清掉上次拒收号的 React state)",
    "[smsbower] 刷新完成, 输入框已就绪",
})


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value or len(value) > 64 or value != value.strip():
        return None
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        stamp = parsed.timestamp()
        return stamp if math.isfinite(stamp) and stamp > 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _message(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value):
        return None
    message = value.strip()
    for _ in range(2):
        match = _CLOCK.match(message)
        if not match:
            break
        message = message[match.end():].strip()
    # Reject invalid clocks and a third wrapper rather than treating them as
    # opaque prose. Bracketed provider/DrissionPage tags are not clocks.
    if not message or re.match(r"^\[[^\]]*:", message):
        return None
    return message


def _other_outcome(message: str) -> bool:
    """Only ordinary pre-result navigation may remain outside the SMS grammar."""
    from services.nv_oauth_legacy import _contradictory

    return (_contradictory(message)
            or _START in message
            or any(marker in message for marker in (
                "失败", "异常", "拒绝", "拒收", "超时", "取消", "未配置", "取到号码", "取号成功",
                "等待短信", "等待 SMS", "等 SMS", "短信验证码", "号码已分配", "开始执行：获取 RT",
            ))
            or bool(re.search(
                r"callback|exchange|authorization\s+code|oauth/token|gets?tatus|poll|"
                r"\b(?:error|failed|timeout|cancelled|rejected)\b|"
                r"(?:OAuth|RT).{0,16}(?:开始|启动|重启)|(?:开始|启动|重启).{0,16}(?:OAuth|RT)",
                message, re.IGNORECASE,
            )))


def _sequence(entries: list[tuple[float, str]], started: float, email: str) -> bool:
    starts = [index for index, (_, message) in enumerate(entries) if message == _START]
    summaries = [index for index, (_, message) in enumerate(entries) if _SUMMARY.fullmatch(message)]
    failures = [index for index, (_, message) in enumerate(entries) if message == _FAILURE]
    if len(starts) != 1 or len(summaries) != 1 or len(failures) != 1:
        return False
    start, summary, failure = starts[0], summaries[0], failures[0]
    if not start < summary < failure or not 0 <= entries[start][0] - started <= 10:
        return False
    country_results = _SUMMARY.fullmatch(entries[summary][1]).group(1).split(", ")
    countries = [part.split("=", 1)[0] for part in country_results]
    if len(set(countries)) != len(countries):
        return False
    attempts: dict[str, list[tuple[int, int]]] = defaultdict(list)
    endings: dict[str, int] = {}
    phone_start = None
    configured_countries = None
    seen_country_starts = set()
    wrappers = set()
    for index, (_, message) in enumerate(entries):
        if index in {start, summary, failure}:
            continue
        if index > failure:
            if message not in _READ_ONLY:
                return False
            continue
        number = _NUMBER_FAILURE.fullmatch(message)
        ending = _COUNTRY_FAILURE.fullmatch(message)
        country_start = _COUNTRY_START.fullmatch(message)
        config = _PHONE_START.fullmatch(message)
        injected = _CONFIGURATION.fullmatch(message)
        wrapper = ("step" if message == _NORMAL_START else
                   "launch" if message in {f"OAuth 启动: {email} (proxy=有)", f"OAuth 启动: {email} (proxy=无)"} else None)
        if number:
            country, attempt, maximum = number.group(1), int(number.group(2)), int(number.group(3))
            if not start < index < summary or country in endings or attempt > maximum:
                return False
            attempts[country].append((attempt, maximum))
        elif ending:
            country, maximum = ending.group(1), int(ending.group(2))
            if not start < index < summary or not attempts.get(country) or country in endings:
                return False
            endings[country] = maximum
        elif config:
            if not start < index < summary or phone_start is not None or attempts:
                return False
            phone_start = (config.group(1).split(","), int(config.group(2)))
        elif injected:
            if not start < index < summary or configured_countries is not None or attempts:
                return False
            configured_countries = injected.group(1).split(",")
        elif wrapper:
            if not start < index < summary or attempts or wrapper in wrappers or (wrapper == "step" and "launch" in wrappers):
                return False
            wrappers.add(wrapper)
        elif country_start:
            country_index, count, country = int(country_start.group(1)), int(country_start.group(2)), country_start.group(3)
            if (not start < index < summary or country in seen_country_starts or country in attempts
                    or count != len(countries) or not 1 <= country_index <= count
                    or country != countries[country_index - 1]):
                return False
            seen_country_starts.add(country)
        elif message == "[smsbower] " + _REASON:
            if not summary < index < failure:
                return False
        elif message == "[smsbower] 使用自定义 base_url: [链接已隐藏]":
            if not start < index < summary or attempts or "base_url" in wrappers:
                return False
            wrappers.add("base_url")
        elif message == _WAIT_CALLBACK:
            if not start < index < summary or "wait_callback" in wrappers:
                return False
            wrappers.add("wait_callback")
        elif message == "[DrissionPage] 临时 profile 暂未清理: invalid_path":
            # Profile cleanup is not browser teardown. The saved structured
            # terminal flag, never this line, proves the old browser ended.
            if not summary < index < failure:
                return False
        elif message in _REFRESH:
            if not start < index < summary or not attempts:
                return False
        elif "smsbower" in message.lower() or _other_outcome(message):
            return False
    if set(attempts) != set(countries):
        return False
    if phone_start is not None and phone_start[0] != countries:
        return False
    if configured_countries is not None and configured_countries != countries:
        return False
    for country, actual in attempts.items():
        maximum = actual[0][1]
        if (actual != [(attempt, maximum) for attempt in range(1, maximum + 1)]
                or endings.get(country, maximum) != maximum
                or (phone_start is not None and phone_start[1] != maximum)):
            return False
    return True


def historical_sms_502_failure(session, job) -> dict | None:
    """Inspect the caller's current ORM job and full logs without any writes.

    None means unknown/ineligible. A returned closed failure DTO only refines
    the provider phase; it is not a retry grant and never resets any counter.
    """
    try:
        # Include ORM attribute refreshes, not just the explicit log SELECT:
        # even an expired caller-owned job may not flush unrelated mutations.
        with session.no_autoflush:
            return _historical_sms_502_failure(session, job)
    except Exception:
        return None


def _historical_sms_502_failure(session, job) -> dict | None:
    try:
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
                or failure["code"] != "sms_provider_error" or failure["terminal"] is not True
                or failure["retryable"] is not False or failure["callback_received"] is not False
                or failure["exchange_started"] is not False or failure["charge_possible"] is not True):
            return None
        started = _timestamp(context.get("oauth_started_at"))
        failed = _timestamp(context.get("oauth_failure_started_at"))
        invited = _timestamp(context.get("oauth_membership_invited_at"))
        now = time.time()
        if started is None or failed != started or invited is None or not invited <= started <= now:
            return None
        # Importing this diagnostic alone must not initialize the application
        # database. Reuse the caller's session and never flush pending writes.
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
                # A different stage cannot supply OAuth evidence or silently
                # hide a later callback/success behind a changed step label.
                if log.step != "oauth":
                    return None
                entries.append((stamp, message))
        if not _sequence(entries, started, email):
            return None
        return OAuthAttemptFailure("sms_number_http_502", charge_possible=True, terminal=True).oauth_failure
    except Exception:
        # Missing schema, incomplete history or malformed data never become
        # permission to spend money on a new number allocation.
        return None
