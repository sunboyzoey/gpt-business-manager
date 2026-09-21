"""Read-only, narrowly scoped recovery of one historical SMS timeout outcome.

This is diagnostic extraction, never permission to retry. Historical logs do
not prove browser teardown and can never establish a terminal retry outcome.
No schema initialization, task execution or database writes occur here.
"""
from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timezone


_START = "RT 任务已启动"
_RECONCILE = "正在核对本次 RT 落库与工作区成员状态，不重新授权或覆盖 RT"
_TIMEOUT = "[smsbower] 等 SMS 超时"
_FAILURE_PREFIX = "✗ OAuth 失败: add_phone: OpenAI 要求手机号验证"
_CLOCK_PREFIX = re.compile(r"^\[(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\]\s*")
_MAX_LOGS = 20000


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        stamp = parsed.timestamp()
        return stamp if math.isfinite(stamp) and stamp > 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _message(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        return None
    clean = value.strip()
    # Two timestamp wrappers are possible when canonical task logs are relayed.
    for _ in range(2):
        clean = _CLOCK_PREFIX.sub("", clean, count=1).strip()
    return clean


def _contradictory(message: str) -> bool:
    """Recognize observed results, not routine 'waiting for callback' logs."""
    return any(marker in message for marker in (
        "拿到 authorization code", "换到 RT", "已进入 OAuth 回调", "已收到 OAuth 回调",
        "OAuth callback 校验", "OAuth 授权兑换", "OAuth 兑换", "凭证已保存", "已成功保存凭证",
        "RT 获取成功", "获取 RT 成功", "OAuth 成功", "OAuth 已成功", "OAuth 已完成",
        "callback received", "exchange started", "credentials saved",
    )) or bool(re.search(r"(?:^|[✓✅])\s*(?:OAuth|RT|凭证).*(?:成功|保存完成)", message))


def _unreliable_timeout_evidence(message: str, *, generic_terminal: bool = False) -> bool:
    """Old polling code also printed 'timeout' after cancellation/read errors."""
    if generic_terminal:
        # This precise legacy catch-all summary was printed even for a plain
        # SMS timeout. It is not an observed rejection event. Ignore only the
        # catch-all phrase, never an independent explicit rejection log.
        message = re.sub(r"全部拒收\s*/\s*无库存", "", message)
    if any(marker in message for marker in (
        "取消", "拒收", "拒绝", "查询异常", "查询失败", "查询超时", "读取未确认", "读取异常", "读取失败",
        "关闭浏览器异常", "关闭浏览器失败", "浏览器关闭异常", "浏览器关闭失败", "浏览器未关闭",
        "退出浏览器异常", "退出浏览器失败",
    )):
        return True
    return bool(re.search(
        r"cancel(?:led|ed|lation)?|reject(?:ed|ion)?|getstatus.{0,50}(?:异常|失败|error|failed|timeout)"
        r"|(?:browser|chromium|drission).{0,30}(?:close|quit).{0,30}(?:error|fail|timeout)",
        message, re.IGNORECASE,
    ))


def oauth_legacy_failure_evidence(job: dict) -> dict | None:
    """Return fixed, credential-free evidence only for an unambiguous old timeout.

    Identity and the entire checkpoint context must match the durable row.
    Anything missing, stale, contradictory, or unreadable fails closed.
    """
    if not isinstance(job, dict) or job.get("step") != "oauth":
        return None
    identifier = job.get("id")
    context = job.get("context")
    if not isinstance(identifier, str) or not identifier or not isinstance(context, dict):
        return None
    if any(type(job.get(key)) is not int or job[key] <= 0
           for key in ("parent_account_id", "child_id", "membership_id")):
        return None
    if not isinstance(job.get("email"), str) or not job["email"].strip():
        return None
    started = _timestamp(context.get("oauth_started_at"))
    invited = _timestamp(context.get("oauth_membership_invited_at"))
    now = time.time()
    if started is None or invited is None or not invited <= started <= now:
        return None
    try:
        # Deliberately lazy: importing this helper must not load the application
        # database, initialize schema, or start any scheduler.
        from sqlmodel import Session, select
        from services import nv_automation_store as store
        from services.chatgpt_oauth_failure import OAuthAttemptFailure

        with Session(store.engine) as session:
            row = session.get(store.NvAutomationJob, identifier)
            if row is None or row.step != "oauth":
                return None
            if any(getattr(row, key) != job[key]
                   for key in ("parent_account_id", "child_id", "membership_id")):
                return None
            if row.email.strip().casefold() != job["email"].strip().casefold():
                return None
            if json.loads(row.context_json) != context:
                return None
            for optional in ("source_account_id", "parent_email", "remote_user_id", "seat_type", "worker_token", "version"):
                if optional in job and job[optional] != getattr(row, optional):
                    return None
            worker_started = row.step_started_at
            if (type(worker_started) not in (int, float) or not math.isfinite(worker_started)
                    or not started <= worker_started <= now):
                return None
            logs = session.exec(select(store.NvAutomationLog).where(
                store.NvAutomationLog.job_id == identifier,
                store.NvAutomationLog.step == "oauth",
            ).order_by(store.NvAutomationLog.created_at, store.NvAutomationLog.id).limit(_MAX_LOGS + 1)).all()
            if not logs or len(logs) > _MAX_LOGS:
                return None
            entries: list[tuple[float, str]] = []
            for log in logs:
                stamp = log.created_at
                message = _message(log.message)
                if (type(stamp) not in (int, float) or not math.isfinite(stamp)
                        or stamp <= 0 or stamp > now or message is None):
                    return None
                entries.append((stamp, message))
            current = [(stamp, message) for stamp, message in entries if stamp >= started]
            if any(_START in message and message != _START for _, message in current):
                return None
            starts = [index for index, (_, message) in enumerate(current) if message == _START]
            timeouts = [index for index, (_, message) in enumerate(current) if message == _TIMEOUT]
            failures = [index for index, (_, message) in enumerate(current) if "OAuth 失败" in message]
            if len(starts) != 1 or len(timeouts) != 1 or len(failures) != 1:
                return None
            start_index, timeout_index, failure_index = starts[0], timeouts[0], failures[0]
            if not (start_index < timeout_index < failure_index):
                return None
            if not 0 <= current[start_index][0] - started <= 10:
                return None
            failed_message = current[failure_index][1]
            if not failed_message.startswith(_FAILURE_PREFIX):
                return None
            # Require a boundary after the complete controlled phrase; similar
            # prose ('要求手机号验证成功') must not count as this terminal event.
            suffix = failed_message[len(_FAILURE_PREFIX):]
            if suffix and suffix[0] not in " ,，:：;；(（":
                return None
            if any(_contradictory(message) or _unreliable_timeout_evidence(message, generic_terminal=index == failure_index)
                   for index, (_, message) in enumerate(current)):
                return None
            return {
                # A task failure line is not proof its browser was closed.
                # No trustworthy teardown-success marker existed in this log
                # format; even apparent later 'browser closed' text cannot
                # manufacture terminal evidence or authorize another OAuth.
                "oauth_failure": OAuthAttemptFailure("sms_timeout", charge_possible=True, terminal=False).oauth_failure,
                "execution_attempts": sum(message == _START for _, message in entries),
                "reconciliation_attempts": sum(message == _RECONCILE and stamp < worker_started
                                               for stamp, message in entries),
            }
    except Exception:
        # DB unavailable, schema absent, malformed JSON, or any evidence read
        # failure is unknown, never grounds for launching another OAuth.
        return None
