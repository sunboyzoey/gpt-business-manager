"""Shared SMS waiting policy. Pure config reads; no provider or database access."""
from __future__ import annotations

from typing import Any, Callable


DEFAULT_SMS_TIMEOUT_SECONDS = 180
MIN_SMS_TIMEOUT_SECONDS = 60
MAX_SMS_TIMEOUT_SECONDS = 300


def resolve_sms_timeout(config: Any = None) -> int:
    """Prefer the UI setting, then the legacy provider setting, then 180 s.

    Blank, boolean, malformed and non-positive values are not settings. A valid
    positive integer is bounded to 60–300 s consistently for all OAuth paths.
    """
    for key in ("chatgpt_add_phone_sms_timeout", "smsbower_otp_timeout_seconds"):
        try:
            raw = config.get(key) if config is not None else None
            if isinstance(raw, bool) or raw is None:
                continue
            value = int(str(raw).strip())
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
        if value > 0:
            return max(MIN_SMS_TIMEOUT_SECONDS, min(MAX_SMS_TIMEOUT_SECONDS, value))
    return DEFAULT_SMS_TIMEOUT_SECONDS


class SmsWaitProgress:
    """Rate-limited elapsed-time logs without phone/activation/OTP information."""

    def __init__(self, timeout: int, log: Callable[[str], Any], *,
                 clock: Callable[[], float], prefix: str = "") -> None:
        self.timeout = timeout
        self._log = log
        self._clock = clock
        self._prefix = prefix
        self._started = clock()
        self._last_reported = -15
        self.report()

    def remaining(self) -> float:
        return max(0.0, self.timeout - max(0.0, self._clock() - self._started))

    def report(self, *, force: bool = False) -> None:
        elapsed = max(0, int(self._clock() - self._started))
        if elapsed == self._last_reported:
            return
        if force or elapsed - self._last_reported >= 15:
            self._last_reported = elapsed
            self._log(f"{self._prefix}等待短信：已等待 {elapsed} / {self.timeout} 秒")
