"""Durable, credential-free snapshots for prepared BUSINESS batch invitations."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlmodel import Field, Session, SQLModel, select

from core.db import engine

_initialized = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PreparedBatchInviteTask(SQLModel, table=True):
    __tablename__ = "prepared_business_batch_invite_tasks"

    task_id: str = Field(primary_key=True)
    account_id: int = Field(index=True)
    status: str = Field(default="running", index=True)
    phase: str = Field(default="prepare", index=True)
    payload_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    finished_at: datetime | None = None


def init_tables() -> None:
    global _initialized
    SQLModel.metadata.create_all(engine, tables=[PreparedBatchInviteTask.__table__])
    _initialized = True


def _ensure_tables() -> None:
    if not _initialized:
        init_tables()


def save(task: dict[str, Any]) -> None:
    _ensure_tables()
    if str(task.get("workflow") or "") != "prepare_then_batch":
        return
    task_id = str(task.get("task_id") or "").strip()
    mothers = task.get("mothers") if isinstance(task.get("mothers"), list) else []
    account_id = int((mothers[0] if mothers else {}).get("account_id") or 0)
    if not task_id or account_id <= 0:
        return
    # The task contains only local ids, emails, proxy reference keys, progress,
    # and sanitized logs. Browser cookies, passwords, API keys and RTs live in
    # their established encrypted/account stores and never enter this snapshot.
    payload = json.dumps(task, ensure_ascii=False, separators=(",", ":"))
    status = str(task.get("status") or "running")
    phase = str(task.get("phase") or "prepare")
    now = _utcnow()
    with Session(engine) as session:
        row = session.get(PreparedBatchInviteTask, task_id)
        if row is None:
            row = PreparedBatchInviteTask(task_id=task_id, account_id=account_id)
        row.account_id = account_id
        row.status = status
        row.phase = phase
        row.payload_json = payload
        row.updated_at = now
        row.finished_at = now if status in {"done", "failed"} else None
        session.add(row)
        session.commit()


def load(task_id: str) -> dict[str, Any] | None:
    _ensure_tables()
    with Session(engine) as session:
        row = session.get(PreparedBatchInviteTask, str(task_id or ""))
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
            select(PreparedBatchInviteTask)
            .where(PreparedBatchInviteTask.status.in_(("pending", "running")))
            .order_by(PreparedBatchInviteTask.created_at)
        ).all())
    result: list[dict[str, Any]] = []
    for row in rows:
        try:
            value = json.loads(row.payload_json or "{}")
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("workflow") == "prepare_then_batch":
            result.append(value)
    return result
