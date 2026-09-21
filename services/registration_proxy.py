"""Resolve registration proxy keys against current checked manager state.

Public options never contain proxy URLs with credentials. Resolving a saved key
always checks eligibility again and never switches nodes or falls back to direct.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlmodel import Session, select

from core import proxy_pool as manual_pool
from core.db import ProxyModel
from core.proxy_pool import ProxyHealth, proxy_health_fields, validate_proxy_url


UNAVAILABLE_MESSAGE = "所选代理已删除、停用或检测未通过，请在代理管理中检测后重新选择"


def _manual_label(proxy: ProxyModel, url: str) -> str:
    parts = urlsplit(url)
    host = str(parts.hostname or "")
    if ":" in host:
        host = f"[{host}]"
    region = f" · {proxy.region}" if proxy.region else ""
    return f"#{proxy.id} {parts.scheme}://{host}:{parts.port}{region}"


def _manual_options() -> list[dict]:
    items = []
    with Session(manual_pool.engine) as session:
        for proxy, health in session.exec(select(ProxyModel, ProxyHealth).join(
            ProxyHealth, ProxyHealth.proxy_id == ProxyModel.id
        ).where(ProxyModel.is_active == True, ProxyHealth.last_check_ok == True)).all():
            fields = proxy_health_fields(proxy, health)
            if not fields["is_usable"]:
                continue
            try:
                url = validate_proxy_url(proxy.url)
            except ValueError:
                continue
            items.append({
                "key": f"manual:{proxy.id}", "kind": "manual", "proxy_id": proxy.id,
                "label": _manual_label(proxy, url), "region": proxy.region,
                "latency_ms": fields["latency_ms"], "last_check_at": fields["last_check_at"],
                "url": url,
            })
    return items


def _subscription_options() -> list[dict]:
    from services import proxy_pool

    # A listener can change after subscription replacement. Only the current
    # name/address pair can be resolved, and the last completed result wins.
    current_nodes = {str(node.get("name") or ""): node for node in proxy_pool.get_nodes()}
    generic = proxy_pool.get_test_status()
    protocol = proxy_pool.get_chatgpt_protocol_test_status()
    if generic.get("running") or protocol.get("running"):
        return []
    sources = [(generic, proxy_pool.get_pool()), (protocol, protocol.get("pool") or [])]
    latest: dict[str, tuple[float, dict | None]] = {}
    for status, pool in sources:
        checked_at = float(status.get("updated_at") or 0)
        passed = {str(item.get("name") or ""): item for item in pool}
        results = {str(item.get("name") or ""): item for item in (status.get("results") or [])}
        for name in set(passed) | set(results):
            if name in latest and latest[name][0] > checked_at:
                continue
            result = results.get(name)
            candidate = passed.get(name)
            if result and result.get("status") != "ok":
                candidate = None
            latest[name] = (checked_at, candidate)

    items = []
    for name, (checked_at, item) in latest.items():
        node = current_nodes.get(name)
        if not item or not node or not name:
            continue
        addr = str(item.get("addr") or "").strip()
        if not addr or addr != str(node.get("addr") or "").strip():
            continue
        try:
            url = validate_proxy_url(addr)
        except ValueError:
            continue
        region = str(item.get("region") or "")
        items.append({
            "key": f"subscription:{name}", "kind": "subscription", "proxy_node": name,
            "label": f"{name}" + (f" · {region}" if region else ""),
            "region": region, "latency_ms": int(item.get("latency") or 0),
            "last_check_at": datetime.fromtimestamp(checked_at, timezone.utc) if checked_at else None,
            "url": url,
        })
    return sorted(items, key=lambda item: (item["latency_ms"], item["label"]))


def list_registration_proxy_options() -> dict:
    items = [{key: value for key, value in item.items() if key != "url"}
             for item in _manual_options() + _subscription_options()]
    return {"items": items, "total": len(items)}


def resolve_registration_proxy(key: str) -> dict:
    """Resolve only the saved key; raises a credential-free ValueError."""
    key = str(key or "").strip()
    if key.startswith("manual:"):
        items = _manual_options()
    elif key.startswith("subscription:"):
        items = _subscription_options()
    else:
        raise ValueError(UNAVAILABLE_MESSAGE)
    for item in items:
        if item["key"] == key:
            return dict(item)
    raise ValueError(UNAVAILABLE_MESSAGE)
