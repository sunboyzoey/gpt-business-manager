"""Read-only SMS balance polling, independent of registration/NV workers.

Only ``getBalance`` is called. Credentials, endpoint URLs and raw provider
errors never enter the public snapshot. The cache is local to this process.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import threading
import time
from urllib.parse import urlsplit

from core.config_store import config_store
from platforms.chatgpt.smsbower_client import (
    DEFAULT_BASE_URL,
    SmsbowerClient,
    SmsbowerError,
)


POLL_INTERVAL_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 15
LOW_BALANCE_THRESHOLD = Decimal("0.50")
RECHARGE_URL = "https://grizzlysms.com/profile/pay"


def _provider(base_url: str) -> tuple[str, str | None]:
    """Grizzly balances use USD since 2025-09-01; other hosts are unverified.

    https://grizzlysms.com/blog/important-update-all-grizzly-sms-prices-and-balances-are-switching-to-usd
    """
    try:
        hostname = (urlsplit(base_url).hostname or "").lower()
    except ValueError:
        hostname = ""
    if hostname in {"grizzlysms.com", "api.grizzlysms.com"}:
        return "Grizzly SMS", "USD"
    if hostname in {"smsbower.page", "smsbower.app"}:
        return "SMSBower", None
    return "自定义接码平台", None


def _timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, SmsbowerError):
        if exc.code == "BAD_KEY":
            return "接码平台 API Key 无效，请检查配置"
        if exc.code == "BANNED":
            return "接码平台账号不可用，请检查账号状态"
    return "接码余额查询失败，将自动重试"


class SmsBalanceMonitor:
    def __init__(self, *, config_loader=None, client_factory=None,
                 interval_seconds=POLL_INTERVAL_SECONDS,
                 clock=None, monotonic=None):
        self._config_loader = config_loader or config_store.get_all
        self._client_factory = client_factory or SmsbowerClient
        self._interval = max(1, int(interval_seconds))
        self._clock = clock or time.time
        self._monotonic = monotonic or time.monotonic
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._settings = None
        self._fingerprint = None
        self._config_error = None
        self._balance = None
        self._last_success_at = None
        self._last_success_monotonic = None
        self._checked_at = None
        self._error = None
        self._refreshing = False
        self._next_check_at = None
        self._next_due = 0.0

    def _sync_config_locked(self):
        try:
            values = self._config_loader()
            settings = (
                str(values.get("smsbower_api_key", "") or "").strip(),
                str(values.get("smsbower_base_url", "") or "").strip() or DEFAULT_BASE_URL,
                str(values.get("smsbower_proxy", "") or "").strip(),
            )
            fingerprint = hashlib.sha256(json.dumps(settings).encode()).digest()
            self._config_error = None
        except Exception:
            settings = None
            fingerprint = None
            self._config_error = "读取接码配置失败，将自动重试"
        if fingerprint != self._fingerprint:
            self._settings = settings
            self._fingerprint = fingerprint
            self._balance = None
            self._last_success_at = None
            self._last_success_monotonic = None
            self._checked_at = None
            self._error = None
            self._next_due = 0.0
            self._next_check_at = self._clock() if settings and settings[0] else None
            self._wake.set()

    def snapshot(self) -> dict:
        """Read cached results; no remote request is performed by this method."""
        with self._lock:
            self._sync_config_locked()
            configured = bool(self._settings and self._settings[0])
            provider, currency = _provider(self._settings[1] if self._settings else DEFAULT_BASE_URL)
            stale = (
                self._balance is None
                or bool(self._error or self._config_error)
                or self._last_success_monotonic is None
                or self._monotonic() - self._last_success_monotonic >= self._interval * 2
            )
            return {
                "configured": configured,
                "provider": provider,
                "currency": currency,
                "balance": format(self._balance, "f") if self._balance is not None else None,
                "threshold": format(LOW_BALANCE_THRESHOLD, ".2f"),
                "low_balance": (
                    self._balance < LOW_BALANCE_THRESHOLD
                    if self._balance is not None and currency == "USD" else None
                ),
                "last_success_at": _timestamp(self._last_success_at),
                "checked_at": _timestamp(self._checked_at),
                "error": self._config_error or self._error,
                "stale": stale,
                "refreshing": self._refreshing,
                "next_check_at": _timestamp(self._next_check_at),
                "poll_interval_seconds": self._interval,
                "recharge_url": RECHARGE_URL,
            }

    def tick(self) -> bool:
        """Run one due check. Single-flight even when called concurrently."""
        with self._lock:
            self._sync_config_locked()
            if (self._refreshing or not self._settings or not self._settings[0]
                    or self._monotonic() < self._next_due):
                return False
            api_key, base_url, proxy = self._settings
            fingerprint = self._fingerprint
            self._refreshing = True
            self._next_check_at = None
        balance = None
        error = None
        try:
            client = self._client_factory(
                api_key=api_key, base_url=base_url, proxy=proxy or None,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            raw_balance = client.balance()
            try:
                if isinstance(raw_balance, bool):
                    raise ValueError("invalid balance")
                balance = Decimal(str(raw_balance))
                if not balance.is_finite() or balance < 0:
                    raise ValueError("invalid balance")
            except (InvalidOperation, ValueError):
                balance = None
                error = "接码平台返回的余额无效，将自动重试"
        except Exception as exc:
            error = _safe_error(exc)
        finally:
            with self._lock:
                # A response from the old API key/host/proxy must never appear
                # as the balance of the newly selected account.
                self._sync_config_locked()
                self._refreshing = False
                if fingerprint == self._fingerprint:
                    now = self._clock()
                    monotonic_now = self._monotonic()
                    self._checked_at = now
                    self._error = error
                    self._next_due = monotonic_now + self._interval
                    self._next_check_at = now + self._interval
                    if balance is not None:
                        self._balance = balance
                        self._last_success_at = now
                        self._last_success_monotonic = monotonic_now
        return True

    def _loop(self):
        while not self._stop.is_set():
            self.tick()
            self._wake.wait(timeout=5)
            self._wake.clear()

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, name="sms-balance-monitor", daemon=True,
            )
            self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=1)


sms_balance_monitor = SmsBalanceMonitor()
