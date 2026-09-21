"""Manual proxy selection and persistent connectivity checks.

Enabled is a user's choice; a successful check must never re-enable a proxy.
A separate table adds check state safely to existing standalone installations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import threading
from typing import Optional
from urllib.parse import urlsplit
from uuid import uuid4

from sqlmodel import Field, SQLModel, Session, select

from .db import ProxyModel, engine
from .proxy_utils import coerce_proxy_url


class ProxyHealth(SQLModel, table=True):
    __tablename__ = "registration_proxy_health"

    proxy_id: int = Field(primary_key=True)
    url_fingerprint: str
    last_check_ok: bool = False
    last_check_at: datetime
    last_check_error: str = ""
    latency_ms: int = 0


def init_proxy_health(db_engine=None) -> None:
    ProxyHealth.__table__.create(db_engine or engine, checkfirst=True)


def validate_proxy_url(value: str) -> str:
    """Validate without including credentials or untrusted input in errors."""
    try:
        url = coerce_proxy_url(value)
        parts = urlsplit(url or "")
        if (
            parts.scheme not in {"http", "https", "socks5", "socks5h"}
            or not parts.hostname
            or parts.port is None
            or not 1 <= parts.port <= 65535
            or parts.query
            or parts.fragment
            or parts.path not in {"", "/"}
            or any(char.isspace() for char in str(url))
        ):
            raise ValueError
        return str(url)
    except (TypeError, ValueError):
        raise ValueError("代理格式无效，请填写 http(s) 或 socks5 代理地址和端口") from None


def _fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def proxy_health_fields(proxy: ProxyModel, health: ProxyHealth | None) -> dict:
    current = health is not None and health.url_fingerprint == _fingerprint(proxy.url)
    checked_ok = bool(health.last_check_ok) if current else None
    return {
        "last_check_ok": checked_ok,
        "last_check_at": health.last_check_at if current else None,
        "last_check_error": health.last_check_error if current else "",
        "latency_ms": health.latency_ms if current else 0,
        "is_usable": bool(proxy.is_active and checked_ok),
    }


def safe_check_error(probe: dict) -> str:
    if probe.get("ok"):
        return ""
    try:
        status = int(probe.get("csrf_status") or probe.get("home_status") or probe.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    if 100 <= status <= 599:
        return f"ChatGPT 预检未通过（HTTP {status}）"
    return "代理连接失败，请检查地址、认证信息及网络"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProxyPool:
    def __init__(self):
        self._index = 0
        self._lock = threading.Lock()
        self._check_lock = threading.Lock()
        self._check_status = {
            "job_id": "", "running": False, "total": 0, "completed": 0,
            "ok": 0, "fail": 0, "results": [], "error": "",
            "started_at": None, "finished_at": None,
        }

    def get_next(self, region: str = "") -> Optional[str]:
        """Round-robin over enabled proxies whose latest check passed."""
        with Session(engine) as session:
            query = select(ProxyModel, ProxyHealth).join(
                ProxyHealth, ProxyHealth.proxy_id == ProxyModel.id
            ).where(ProxyModel.is_active == True, ProxyHealth.last_check_ok == True)
            if region:
                query = query.where(ProxyModel.region == region)
            proxies = [p for p, health in session.exec(query).all() if proxy_health_fields(p, health)["is_usable"]]
            if not proxies:
                return None
            proxies.sort(key=lambda p: p.success_count / max(p.success_count + p.fail_count, 1), reverse=True)
            with self._lock:
                idx = self._index % len(proxies)
                self._index += 1
            return proxies[idx].url

    def record_check(self, url: str, probe: dict, proxy_id: int | None = None) -> bool:
        """Persist only if the same proxy still exists, without changing enabled."""
        with Session(engine) as session:
            proxy = session.get(ProxyModel, proxy_id) if proxy_id else None
            if proxy_id is None:
                proxy = session.exec(select(ProxyModel).where(ProxyModel.url == url)).first()
            if proxy is None or proxy.url != url:
                return False
            now = _utcnow()
            ok = bool(probe.get("ok"))
            proxy.last_checked = now
            if ok:
                proxy.success_count += 1
            else:
                proxy.fail_count += 1
            health = session.get(ProxyHealth, proxy.id)
            if health is None:
                health = ProxyHealth(proxy_id=proxy.id, url_fingerprint=_fingerprint(url), last_check_at=now)
            health.url_fingerprint = _fingerprint(url)
            health.last_check_ok = ok
            health.last_check_at = now
            health.last_check_error = safe_check_error(probe)
            try:
                health.latency_ms = max(0, int(probe.get("latency") or 0))
            except (ValueError, TypeError):
                health.latency_ms = 0
            session.add(proxy)
            session.add(health)
            session.commit()
            return True

    def report_success(self, url: str, proxy_id: int | None = None) -> None:
        self.record_check(url, {"ok": True}, proxy_id)

    def report_fail(self, url: str, proxy_id: int | None = None) -> None:
        self.record_check(url, {"ok": False}, proxy_id)

    def get_check_status(self) -> dict:
        with self._check_lock:
            return {**self._check_status, "results": [dict(item) for item in self._check_status["results"]]}

    def prepare_check(self) -> dict:
        """Reserve one job synchronously so repeated requests do not overlap."""
        with self._check_lock:
            if self._check_status["running"]:
                return {"started": False, **self._check_status}
            with Session(engine) as session:
                total = len(session.exec(select(ProxyModel.id)).all())
            self._check_status = {
                "job_id": uuid4().hex, "running": True, "total": total, "completed": 0,
                "ok": 0, "fail": 0, "results": [], "error": "",
                "started_at": _utcnow(), "finished_at": None,
            }
            return {"started": True, **self._check_status}

    def check_all(self, job_id: str = "") -> dict:
        """Check each proxy and publish actual progress until the job completes."""
        if not job_id:
            status = self.prepare_check()
            if not status["started"]:
                return self.get_check_status()
            job_id = status["job_id"]
        with self._check_lock:
            if job_id != self._check_status["job_id"] or not self._check_status["running"]:
                return {**self._check_status}
        try:
            from services.proxy_pool import probe_chatgpt_protocol_proxy
            with Session(engine) as session:
                proxies = session.exec(select(ProxyModel)).all()
            with self._check_lock:
                self._check_status["total"] = len(proxies)
            for proxy in proxies:
                try:
                    validate_proxy_url(proxy.url)
                    probe = probe_chatgpt_protocol_proxy(proxy.url, timeout=8, cache_ttl=0)
                except Exception:
                    # Exceptions frequently contain user:password proxy URLs.
                    probe = {"ok": False}
                self.record_check(proxy.url, probe, proxy.id)
                ok = bool(probe.get("ok"))
                detail = {"id": proxy.id, "ok": ok, "error": safe_check_error(probe)}
                with self._check_lock:
                    self._check_status["completed"] += 1
                    self._check_status["ok" if ok else "fail"] += 1
                    self._check_status["results"].append(detail)
        except Exception:
            with self._check_lock:
                self._check_status["error"] = "检测任务未完成，请重试"
        finally:
            with self._check_lock:
                self._check_status["running"] = False
                self._check_status["finished_at"] = _utcnow()
        return self.get_check_status()


proxy_pool = ProxyPool()
