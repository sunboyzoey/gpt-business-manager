"""定时注册任务 API"""

import json
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlmodel import Session, select, func, col

from core.db import engine, ScheduledJobModel, TaskQueueModel

router = APIRouter(prefix="/scheduled", tags=["scheduled"])

# ── 平台级并发锁 ──
_platform_locks: Dict[str, threading.Lock] = {}
_platform_locks_guard = threading.Lock()


def get_platform_lock(platform: str) -> threading.Lock:
    with _platform_locks_guard:
        if platform not in _platform_locks:
            _platform_locks[platform] = threading.Lock()
        return _platform_locks[platform]


def is_platform_busy(platform: str) -> bool:
    lock = get_platform_lock(platform)
    acquired = lock.acquire(blocking=False)
    if acquired:
        lock.release()
        return False
    return True


def _utcnow():
    return datetime.now(timezone.utc)


# ── 请求模型 ──

class ScheduledJobCreate(BaseModel):
    name: str = ""
    platform: str
    cron_hour: int = 9
    cron_minute: int = 0
    count: int = 1
    concurrency: int = 1
    mail_provider: str = "outlook"
    proxy: str = ""
    config_json: str = "{}"
    enabled: bool = True


class ScheduledJobUpdate(BaseModel):
    name: Optional[str] = None
    cron_hour: Optional[int] = None
    cron_minute: Optional[int] = None
    count: Optional[int] = None
    concurrency: Optional[int] = None
    mail_provider: Optional[str] = None
    proxy: Optional[str] = None
    config_json: Optional[str] = None
    enabled: Optional[bool] = None


# ── 计算下次执行时间 ──

def calc_next_run(hour: int, minute: int) -> datetime:
    now = _utcnow()
    today_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if today_run <= now:
        return today_run + timedelta(days=1)
    return today_run


# ── CRUD ──

@router.get("/jobs")
def list_jobs():
    with Session(engine) as s:
        jobs = s.exec(select(ScheduledJobModel).order_by(col(ScheduledJobModel.id).desc())).all()
        return [_serialize_job(j) for j in jobs]


@router.post("/jobs")
def create_job(body: ScheduledJobCreate):
    with Session(engine) as s:
        job = ScheduledJobModel(
            name=body.name or f"{body.platform} 定时注册",
            platform=body.platform,
            cron_hour=body.cron_hour,
            cron_minute=body.cron_minute,
            count=body.count,
            concurrency=body.concurrency,
            mail_provider=body.mail_provider,
            proxy=body.proxy,
            config_json=body.config_json,
            enabled=body.enabled,
            next_run_at=calc_next_run(body.cron_hour, body.cron_minute),
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        s.add(job)
        s.commit()
        s.refresh(job)
        return _serialize_job(job)


@router.put("/jobs/{job_id}")
def update_job(job_id: int, body: ScheduledJobUpdate):
    with Session(engine) as s:
        job = s.get(ScheduledJobModel, job_id)
        if not job:
            return {"detail": "不存在"}
        for field in ("name", "cron_hour", "cron_minute", "count", "concurrency",
                       "mail_provider", "proxy", "config_json", "enabled"):
            val = getattr(body, field, None)
            if val is not None:
                setattr(job, field, val)
        job.next_run_at = calc_next_run(job.cron_hour, job.cron_minute)
        job.updated_at = _utcnow()
        s.add(job)
        s.commit()
        s.refresh(job)
        return _serialize_job(job)


@router.delete("/jobs/{job_id}")
def delete_job(job_id: int):
    with Session(engine) as s:
        job = s.get(ScheduledJobModel, job_id)
        if job:
            s.delete(job)
            s.commit()
    return {"ok": True}


@router.post("/jobs/{job_id}/toggle")
def toggle_job(job_id: int):
    with Session(engine) as s:
        job = s.get(ScheduledJobModel, job_id)
        if not job:
            return {"detail": "不存在"}
        job.enabled = not job.enabled
        if job.enabled:
            job.next_run_at = calc_next_run(job.cron_hour, job.cron_minute)
        job.updated_at = _utcnow()
        s.add(job)
        s.commit()
        return {"enabled": job.enabled}


@router.post("/jobs/{job_id}/run-now")
def run_job_now(job_id: int):
    """手动立即执行一次定时任务"""
    with Session(engine) as s:
        job = s.get(ScheduledJobModel, job_id)
        if not job:
            return {"ok": False, "error": "不存在"}

    if is_platform_busy(job.platform):
        return {"ok": False, "error": f"{job.platform} 有任务正在运行，请等待完成"}

    task_id = _execute_job(job)
    return {"ok": True, "task_id": task_id}


@router.get("/jobs/status")
def jobs_status():
    """获取所有平台的运行状态"""
    platforms = ["chatgpt", "grok", "trae", "kiro", "openblocklabs"]
    result = {}
    for p in platforms:
        result[p] = {"busy": is_platform_busy(p)}
    return result


# ── 任务历史 ──

@router.get("/history")
def task_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    platform: Optional[str] = Query(None),
):
    with Session(engine) as s:
        query = select(TaskQueueModel)
        if platform:
            query = query.where(TaskQueueModel.platform == platform)
        total = s.exec(select(func.count()).select_from(query.subquery())).one()
        items = s.exec(
            query.order_by(col(TaskQueueModel.id).desc())
            .offset((page - 1) * page_size).limit(page_size)
        ).all()
        return {
            "total": total,
            "items": [_serialize_task(t) for t in items],
        }


# ── 执行器 ──

def _execute_job(job: ScheduledJobModel) -> str:
    """从 ScheduledJob 创建并执行注册任务"""
    from api.tasks import enqueue_register_task, RegisterTaskRequest

    extra = {}
    try:
        extra = json.loads(job.config_json or "{}")
    except Exception:
        pass
    extra["mail_provider"] = job.mail_provider

    req = RegisterTaskRequest(
        platform=job.platform,
        count=job.count,
        concurrency=job.concurrency,
        proxy=job.proxy or None,
        executor_type="protocol",
        captcha_solver=extra.get("captcha_solver", "yescaptcha"),
        extra=extra,
    )

    task_id = enqueue_register_task(req, source="scheduled")

    # 持久化到 task_queue
    with Session(engine) as s:
        record = TaskQueueModel(
            job_id=job.id,
            task_id=task_id,
            platform=job.platform,
            source="scheduled",
            status="running",
            total=job.count,
            config_json=json.dumps(extra, ensure_ascii=False),
            created_at=_utcnow(),
            updated_at=_utcnow(),
            started_at=_utcnow(),
        )
        s.add(record)
        s.commit()

    return task_id


def check_and_run_scheduled_jobs():
    """由 Scheduler 调用：检查到期的定时任务并执行"""
    now = _utcnow()
    with Session(engine) as s:
        jobs = s.exec(
            select(ScheduledJobModel)
            .where(ScheduledJobModel.enabled == True)
            .where(ScheduledJobModel.next_run_at <= now)
        ).all()

        for job in jobs:
            if is_platform_busy(job.platform):
                continue

            try:
                task_id = _execute_job(job)
                job.last_run_at = now
                job.next_run_at = calc_next_run(job.cron_hour, job.cron_minute)
                job.updated_at = now
                s.add(job)
                print(f"[Scheduler] 定时任务触发: {job.name} → {task_id}")
            except Exception as e:
                print(f"[Scheduler] 定时任务失败: {job.name} → {e}")

        s.commit()


# ── 序列化 ──

def _serialize_job(job: ScheduledJobModel) -> Dict[str, Any]:
    return {
        "id": job.id,
        "name": job.name,
        "platform": job.platform,
        "cron_hour": job.cron_hour,
        "cron_minute": job.cron_minute,
        "cron_display": f"{job.cron_hour:02d}:{job.cron_minute:02d}",
        "count": job.count,
        "concurrency": job.concurrency,
        "mail_provider": job.mail_provider,
        "proxy": job.proxy,
        "config_json": job.config_json,
        "enabled": job.enabled,
        "last_run_at": job.last_run_at.isoformat() if job.last_run_at else "",
        "next_run_at": job.next_run_at.isoformat() if job.next_run_at else "",
        "created_at": job.created_at.isoformat() if job.created_at else "",
    }


def _serialize_task(t: TaskQueueModel) -> Dict[str, Any]:
    return {
        "id": t.id,
        "task_id": t.task_id,
        "job_id": t.job_id,
        "platform": t.platform,
        "source": t.source,
        "status": t.status,
        "total": t.total,
        "success": t.success,
        "failed": t.failed,
        "progress": t.progress,
        "error": t.error,
        "created_at": t.created_at.isoformat() if t.created_at else "",
        "started_at": t.started_at.isoformat() if t.started_at else "",
        "finished_at": t.finished_at.isoformat() if t.finished_at else "",
    }
