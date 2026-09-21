"""Read-only execution counts for explicitly bounded historical OAuth recovery.

Unlike failure evidence, these counts do not assert that a browser closed or
that an authorization exchange never occurred. Recovery is a separate, once-
only authorization and still needs fresh identity/credential checks and the
canonical account lease before starting anything.
"""
from __future__ import annotations

import json
import re
from datetime import datetime


def historical_oauth_execution_count(job: dict) -> int | None:
    from sqlmodel import Session, select
    from services import nv_automation_store as store

    try:
        context = job["context"]
        started = datetime.fromisoformat(context["oauth_started_at"].replace("Z", "+00:00"))
        if started.tzinfo is None:
            return None
        with Session(store.engine) as session:
            row = session.get(store.NvAutomationJob, job["id"])
            if row is None or row.step != "oauth" or row.status != "running":
                return None
            if not job.get("worker_token") or row.worker_token != job["worker_token"]:
                return None
            if any(getattr(row, key) != job.get(key) for key in (
                "parent_account_id", "source_account_id", "child_id", "membership_id", "email",
            )) or json.loads(row.context_json) != context:
                return None
            entries = session.exec(select(store.NvAutomationLog).where(
                store.NvAutomationLog.job_id == row.id,
                store.NvAutomationLog.step == "oauth",
            ).order_by(store.NvAutomationLog.created_at, store.NvAutomationLog.id).limit(20001)).all()
            if not entries or len(entries) > 20000:
                return None
            starts = []
            for entry in entries:
                message = entry.message.strip()
                for _ in range(2):
                    message = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s*", "", message).strip()
                if "RT 任务已启动" in message:
                    if message != "RT 任务已启动":
                        return None
                    starts.append(entry.created_at)
            # A complete log must contain exactly one launch at the frozen
            # latest attempt boundary, with no later unidentified launch.
            recent = [stamp for stamp in starts if stamp >= started.timestamp()]
            if len(recent) != 1 or not 0 <= recent[0] - started.timestamp() <= 10:
                return None
            return len(starts)
    except Exception:
        return None
