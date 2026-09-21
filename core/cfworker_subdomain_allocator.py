"""CF Worker 二级域名分配与配额控制。"""

from __future__ import annotations

import random
import re
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from core.db import CFWorkerSubdomainModel, engine

_allocator_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_domain(domain: Any) -> str:
    value = str(domain or "").strip().lower()
    if value.startswith("@"):
        value = value[1:]
    return value.strip(".")


def _normalize_label(value: Any) -> str:
    text = str(value or "").strip().lower().strip(".")
    text = re.sub(r"[^a-z0-9-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text


def _normalize_strategy(value: Any) -> str:
    strategy = str(value or "").strip().lower()
    if strategy in {"counter", "random"}:
        return strategy
    return "counter"


def _parse_limit(value: Any, default: int = 100) -> int:
    try:
        parsed = int(str(value or "").strip() or default)
    except (TypeError, ValueError):
        parsed = default
    return max(parsed, 1)


def _build_counter_label(rows: list[CFWorkerSubdomainModel], prefix: str) -> str:
    max_index = 0
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    for row in rows:
        match = pattern.match(row.subdomain_label or "")
        if not match:
            continue
        max_index = max(max_index, int(match.group(1)))
    return f"{prefix}-{max_index + 1:04d}"


def _build_random_label(rows: list[CFWorkerSubdomainModel], prefix: str) -> str:
    existing = {row.subdomain_label for row in rows}
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(50):
        suffix = "".join(random.choices(alphabet, k=6))
        label = f"{prefix}-{suffix}"
        if label not in existing:
            return label
    return _build_counter_label(rows, prefix)


def _make_label(
    rows: list[CFWorkerSubdomainModel],
    *,
    prefix: str,
    strategy: str,
) -> str:
    if strategy == "random":
        return _build_random_label(rows, prefix)
    return _build_counter_label(rows, prefix)


def _serialize(row: CFWorkerSubdomainModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "root_domain": row.root_domain,
        "subdomain_label": row.subdomain_label,
        "full_domain": row.full_domain,
        "max_accounts": row.max_accounts,
        "used_count": row.used_count,
        "inflight_count": row.inflight_count,
    }


def reserve_subdomain(
    root_domain: str,
    *,
    prefix: Any = "",
    strategy: Any = "counter",
    max_accounts: Any = 100,
) -> dict[str, Any]:
    root = _normalize_domain(root_domain)
    if not root:
        raise RuntimeError("未提供可用的根域名")

    label_prefix = _normalize_label(prefix) or "acc"
    label_strategy = _normalize_strategy(strategy)
    limit = _parse_limit(max_accounts)

    with _allocator_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(CFWorkerSubdomainModel)
                .where(CFWorkerSubdomainModel.root_domain == root)
                .where(CFWorkerSubdomainModel.enabled == True)  # noqa: E712
                .order_by(CFWorkerSubdomainModel.id)
            ).all()

            target: Optional[CFWorkerSubdomainModel] = None
            for row in rows:
                capacity = max(int(row.max_accounts or 0), 1)
                if int(row.used_count or 0) + int(row.inflight_count or 0) < capacity:
                    target = row
                    break

            if target is None:
                label = _make_label(rows, prefix=label_prefix, strategy=label_strategy)
                target = CFWorkerSubdomainModel(
                    root_domain=root,
                    subdomain_label=label,
                    full_domain=f"{label}.{root}",
                    max_accounts=limit,
                    used_count=0,
                    inflight_count=0,
                    enabled=True,
                )
                session.add(target)
                session.commit()
                session.refresh(target)

            target.inflight_count = int(target.inflight_count or 0) + 1
            target.updated_at = _utcnow()
            session.add(target)
            session.commit()
            session.refresh(target)
            return _serialize(target)


def finalize_reservation(reservation_id: Any) -> None:
    try:
        rid = int(reservation_id)
    except (TypeError, ValueError):
        return
    if rid <= 0:
        return

    with _allocator_lock:
        with Session(engine) as session:
            row = session.get(CFWorkerSubdomainModel, rid)
            if not row:
                return
            row.inflight_count = max(int(row.inflight_count or 0) - 1, 0)
            row.used_count = int(row.used_count or 0) + 1
            row.updated_at = _utcnow()
            session.add(row)
            session.commit()


def release_reservation(reservation_id: Any) -> None:
    try:
        rid = int(reservation_id)
    except (TypeError, ValueError):
        return
    if rid <= 0:
        return

    with _allocator_lock:
        with Session(engine) as session:
            row = session.get(CFWorkerSubdomainModel, rid)
            if not row:
                return
            row.inflight_count = max(int(row.inflight_count or 0) - 1, 0)
            row.updated_at = _utcnow()
            session.add(row)
            session.commit()


def release_used_slot(extra: dict | None = None) -> None:
    meta = extra or {}
    try:
        rid = int(meta.get("cfworker_subdomain_id") or 0)
    except (TypeError, ValueError):
        rid = 0

    if rid <= 0:
        return

    with _allocator_lock:
        with Session(engine) as session:
            row = session.get(CFWorkerSubdomainModel, rid)
            if not row:
                return
            row.used_count = max(int(row.used_count or 0) - 1, 0)
            row.updated_at = _utcnow()
            session.add(row)
            session.commit()
