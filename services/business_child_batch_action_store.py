"""Durable snapshots for BUSINESS child batch actions.

Snapshots contain frozen local identities and progress only. Account passwords,
cookies, tokens and remote response bodies remain in their canonical stores.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlmodel import Field, Session, SQLModel, select

from core.db import engine

_initialized = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BusinessChildBatchActionTask(SQLModel, table=True):
    __tablename__ = "business_child_batch_action_tasks"

    task_id: str = Field(primary_key=True)
    action: str = Field(index=True)
    status: str = Field(default="running", index=True)
    payload_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    finished_at: datetime | None = None


def init_tables() -> None:
    global _initialized
    SQLModel.metadata.create_all(engine, tables=[BusinessChildBatchActionTask.__table__])
    _initialized = True


def _ensure_tables() -> None:
    if not _initialized:
        init_tables()


def save(task: dict[str, Any]) -> None:
    _ensure_tables()
    task_id = str(task.get("task_id") or "").strip()
    action = str(task.get("action") or "").strip()
    if not task_id or action not in {"setup_security", "oauth", "leave_workspace"}:
        return
    payload = json.dumps(task, ensure_ascii=False, separators=(",", ":"))
    status = str(task.get("status") or "running")
    now = _utcnow()
    with Session(engine) as session:
        row = session.get(BusinessChildBatchActionTask, task_id)
        if row is None:
            row = BusinessChildBatchActionTask(task_id=task_id, action=action)
        row.action = action
        row.status = status
        row.payload_json = payload
        row.updated_at = now
        row.finished_at = now if status in {"done", "failed"} else None
        session.add(row)
        session.commit()


def load(task_id: str) -> dict[str, Any] | None:
    _ensure_tables()
    with Session(engine) as session:
        row = session.get(BusinessChildBatchActionTask, str(task_id or ""))
        if row is None:
            return None
        try:
            value = json.loads(row.payload_json or "{}")
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, dict) else None


def unfinished() -> list[dict[str, Any]]:
    _ensure_tables()
    with Session(engine) as session:
        rows = list(session.exec(
            select(BusinessChildBatchActionTask)
            .where(BusinessChildBatchActionTask.status.in_(("pending", "running")))
            .order_by(BusinessChildBatchActionTask.created_at)
        ).all())
    result: list[dict[str, Any]] = []
    for row in rows:
        try:
            value = json.loads(row.payload_json or "{}")
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            result.append(value)
    return result
