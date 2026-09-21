"""Read-only balance prerequisite for recovering a proven NO_BALANCE failure.

refresh() is called only outside SQLite write transactions. problem() performs
no network I/O, and accepts only recent results for the current SMS settings.
Neither method allocates a number or grants permission to spend.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import threading
import time


STALE_REASON = "接码余额尚未完成本次核验，请稍后重新恢复"
LOW_REASON = "接码余额不足以覆盖当前单号价格上限，请充值后重新恢复"
CONFIG_REASON = "接码配置或单号价格上限无效，请检查配置后恢复"


class OAuthBalanceGate:
    def __init__(self, *, config_loader=None, client_factory=None, clock=None):
        self._config_loader = config_loader
        self._client_factory = client_factory
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._fingerprint = None
        self._checked_at = None
        self._problem = STALE_REASON
        self._refreshing = False

    def _config(self):
        from platforms.chatgpt.smsbower_client import DEFAULT_BASE_URL, DEFAULT_MAX_PRICE
        if self._config_loader is None:
            from core.config_store import config_store
            loader = config_store.get_all
        else:
            loader = self._config_loader
        try:
            values = loader()
            settings = tuple(str(values.get(key) or default).strip() or default for key, default in (
                ("smsbower_api_key", ""), ("smsbower_base_url", DEFAULT_BASE_URL),
                ("smsbower_proxy", ""), ("smsbower_max_price", DEFAULT_MAX_PRICE),
            ))
            ceiling = Decimal(settings[3])
            if not settings[0] or not ceiling.is_finite() or ceiling <= 0:
                return None
            fingerprint = hashlib.sha256(json.dumps(settings).encode()).digest()
            return settings, ceiling, fingerprint
        except Exception:
            return None

    def problem(self):
        """Cache-only predicate, including a fresh configuration fingerprint."""
        config = self._config()
        if config is None:
            return CONFIG_REASON
        with self._lock:
            if (config[2] != self._fingerprint or self._checked_at is None
                    or not 0 <= self._clock() - self._checked_at < 60):
                return STALE_REASON
            return self._problem

    def refresh(self, *, force=False):
        """Only getBalance; concurrent refreshes cannot reuse an old success."""
        config = self._config()
        if config is None:
            return CONFIG_REASON
        settings, ceiling, fingerprint = config
        with self._lock:
            if self._refreshing:
                return STALE_REASON
            if (not force and fingerprint == self._fingerprint and self._checked_at is not None
                    and 0 <= self._clock() - self._checked_at < 60):
                return self._problem
            self._refreshing = True
            self._fingerprint, self._checked_at, self._problem = fingerprint, None, STALE_REASON
        problem = STALE_REASON
        try:
            from platforms.chatgpt.smsbower_client import SmsbowerClient
            client = (self._client_factory or SmsbowerClient)(
                api_key=settings[0], base_url=settings[1], proxy=settings[2] or None, timeout=15,
            )
            raw = client.balance()
            if isinstance(raw, bool):
                raise ValueError("invalid balance")
            balance = Decimal(str(raw))
            if not balance.is_finite() or balance < 0:
                raise ValueError("invalid balance")
            problem = None if balance >= ceiling else LOW_REASON
        except Exception as exc:
            # No endpoint, key, provider body or exception text may reach a job.
            from platforms.chatgpt.smsbower_client import SmsbowerError
            problem = (CONFIG_REASON if isinstance(exc, SmsbowerError)
                       and exc.code in {"BAD_KEY", "BANNED"} else "接码余额读取失败，未启动新的 RT，请稍后恢复")
        finally:
            current = self._config()
            with self._lock:
                self._refreshing = False
                if current is not None and current[2] == fingerprint:
                    self._fingerprint, self._checked_at, self._problem = fingerprint, self._clock(), problem
        return self.problem()


oauth_balance_gate = OAuthBalanceGate()
