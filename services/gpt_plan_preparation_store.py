"""Durable preparation inventory and bounded queue; never stores credentials.

An account stays in gpt_plan_accounts. Only verified readiness changes its view.
No network/browser operations are performed while a database transaction is held.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import socket
import time
import uuid
from zoneinfo import ZoneInfo

from sqlalchemy import inspect, text
from sqlmodel import Field, Session, SQLModel, func, select

from core.db import GptPlanAccountModel, engine

DEFAULTS = dict(enabled=False, interval_minutes=5, batch_size=5, target_ready=20,
                mail_provider="icloud", browser_mode="headless", max_attempts=3)
STAGES = dict(cookie_check="检查登录会话", login="登录 / 首次注册", security="设置密码与 2FA",
              verify="核验准备结果", ready="准备完成")
STATUS_LABELS = dict(pending="等待准备", running="准备中", retry="等待重试", review="需要人工处理",
                     failed="准备失败", completed="已完成", dead="账号已停用", cancelled="已取消", ready="已就绪")
BUSY = ("pending", "running", "retry")
BULK_RETRY_LIMIT = 100


class GptPlanPreparationModel(SQLModel, table=True):
    __tablename__ = "gpt_plan_preparations"
    account_id: int = Field(primary_key=True)
    state: str = Field(default="pending", index=True)
    stage: str = "cookie_check"
    job_id: str = ""
    registered_at: float = 0
    ready_at: float = 0
    cookie_saved: bool = False
    cookie_health: str = "unknown"
    cookie_checked_at: float = 0
    cookie_expires_at: float = 0
    error: str = ""
    updated_at: float = Field(default_factory=time.time)


class PreparationSettings(SQLModel, table=True):
    __tablename__ = "gpt_plan_preparation_settings"
    id: int = Field(default=1, primary_key=True)
    payload_json: str = "{}"
    next_run_at: float = 0
    last_error: str = ""


class PreparationJob(SQLModel, table=True):
    __tablename__ = "gpt_plan_preparation_jobs"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    account_id: int = Field(index=True)
    email: str = ""
    kind: str = "prepare"
    status: str = Field(default="pending", index=True)
    stage: str = "cookie_check"
    attempts: int = 0
    max_attempts: int = 3
    automatic: bool = False
    browser_mode: str = "headless"
    next_retry_at: float = 0
    error: str = ""
    error_code: str = ""
    security_progress_json: str = "{}"
    worker_token: str = ""
    account_operation_token: str = ""
    worker_pid: int = 0
    worker_host: str = ""
    heartbeat_at: float = 0
    started_at: float = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    finished_at: float = 0


class PreparationAttempt(SQLModel, table=True):
    __tablename__ = "gpt_plan_preparation_attempts"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    job_id: str = Field(index=True)
    started_at: float = Field(default_factory=time.time, index=True)


class PreparationLog(SQLModel, table=True):
    __tablename__ = "gpt_plan_preparation_logs"
    id: int | None = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    at: float = Field(default_factory=time.time)
    message: str = ""


def init_tables():
    SQLModel.metadata.create_all(engine, tables=[model.__table__ for model in (
        GptPlanPreparationModel, PreparationSettings, PreparationJob, PreparationAttempt, PreparationLog)])


def _exists(session, name="gpt_plan_preparations"):
    return inspect(session.connection()).has_table(name)


def preparation_ready_ids(session):
    if not _exists(session):
        return set()
    from api.gpt_business import _is_business_child_candidate, _business_child_has_completed_history
    from core.db import GptBusinessChildMembershipModel
    active_emails = {str(value).strip().casefold() for value in session.exec(
        select(GptBusinessChildMembershipModel.email).where(GptBusinessChildMembershipModel.ended_at.is_(None))).all()}
    accounts = session.exec(select(GptPlanAccountModel).join(
        GptPlanPreparationModel, GptPlanPreparationModel.account_id == GptPlanAccountModel.id
    ).where(GptPlanPreparationModel.state == "ready")).all()
    return {account.id for account in accounts if _ordinary(account) and _is_business_child_candidate(account)
            and account.email.strip().casefold() not in active_emails
            and not _business_child_has_completed_history(session, child_id=account.id, email=account.email)
            and _security_ready_now(account.email)}


def _security_ready_now(email):
    from services.chatgpt_security_store import get_chatgpt_security_status
    try:
        status = get_chatgpt_security_status(email)
    except Exception:
        return False
    return (status.get("credentials_readable") is True and status.get("has_password") is True
            and status.get("has_totp") is True and status.get("password_state") == "configured"
            and status.get("mfa_state") == "enabled")


def preparation_busy_ids(session):
    if not _exists(session):
        return set()
    return set(session.exec(select(GptPlanPreparationModel.account_id).where(GptPlanPreparationModel.state.in_(BUSY))).all())


@contextmanager
def _write():
    with Session(engine) as session:
        if engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise


def _settings(session):
    row = session.get(PreparationSettings, 1)
    saved = json.loads(row.payload_json) if row else {}
    # Older rows may retain removed settings. Reading never migrates the row,
    # and only currently supported keys may reach a worker or public response.
    return {key: saved.get(key, default) for key, default in DEFAULTS.items()}


def get_settings():
    with Session(engine) as session:
        if not _exists(session, "gpt_plan_preparation_settings"):
            return dict(DEFAULTS)
        return _settings(session)


def is_enabled():
    return get_settings()["enabled"] is True


def _queue_busy(session):
    return session.exec(select(PreparationJob.id).where(
        PreparationJob.status.in_(BUSY),
    ).limit(1)).first() is not None


def _schedule_after_queue_change(session, now):
    """Persist a fresh idle interval only after the last queued task ends.

    Called inside the same write transaction as enqueue/finish/cancellation.
    A retry (including one whose due time is in the future) still owns the
    current queue, as does a Cookie check. No batch or worker is discarded.
    """
    session.flush()
    settings = _settings(session)
    config = session.get(PreparationSettings, 1) or PreparationSettings()
    config.next_run_at = (
        now + settings["interval_minutes"] * 60
        if settings["enabled"] and not _queue_busy(session) else 0
    )
    session.add(config)


def _idle_next_run_at(config, settings, latest_finish, now):
    interval = settings["interval_minutes"] * 60
    return max(config.next_run_at if config else 0,
               latest_finish + interval if latest_finish else 0) or now + interval


def save_settings(values):
    values = dict(values)
    # Cached clients may still submit this obsolete setting. It no longer
    # constrains execution and is never persisted by a subsequent settings save.
    values.pop("daily_limit", None)
    if set(values) - set(DEFAULTS):
        raise ValueError("包含未知准备设置")
    merged = {**get_settings(), **values}
    if type(merged["enabled"]) is not bool:
        raise ValueError("自动准备开关必须是布尔值")
    for key, low, high in (("interval_minutes", 1, 1440), ("batch_size", 1, 100),
                           ("target_ready", 1, 10000), ("max_attempts", 1, 5)):
        if type(merged[key]) is not int or not low <= merged[key] <= high:
            raise ValueError(f"{key} 必须在 {low}–{high} 之间")
    if merged["mail_provider"] not in {"auto", "icloud", "outlook", "gmail"}:
        raise ValueError("邮箱类型无效")
    if merged["browser_mode"] not in {"headed", "headless"}:
        raise ValueError("浏览器模式无效")
    with _write() as session:
        row = session.get(PreparationSettings, 1) or PreparationSettings()
        row.payload_json = json.dumps(merged)
        row.next_run_at = (
            time.time() + merged["interval_minutes"] * 60
            if merged["enabled"] and not _queue_busy(session) else 0
        )
        row.last_error = ""
        session.add(row)
    return merged


def _epoch(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, float(value))
    try:
        return max(0, datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except (ValueError, TypeError):
        return 0


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else ""


def _safe(value):
    # Capabilities redact exact secrets before calling the durable boundary.
    from api.gpt_plans import _sanitize_member_task_text
    return _sanitize_member_task_text(str(value or ""))[:1500]


def _log(session, job, message):
    session.add(PreparationLog(job_id=job.id, message=_safe(message)))


def _ordinary(account):
    return (account is not None and str(account.plan_type or "").lower() in {"", "free", "chatgptfreeplan"}
            and account.catalog_category != "refunded" and account.business_parent_id is None
            and account.source_pool != "gpt_business")


def _gmail_preparation_allowed(session, account):
    """A retired source cannot create new identities; existing children survive."""
    if account is None or str(account.mail_provider or "").lower() != "gmail":
        return True
    from services.gmail_store import GmailAlias, GmailSource
    if not _exists(session, GmailAlias.__tablename__) or not _exists(session, GmailSource.__tablename__):
        return True
    alias = session.exec(select(GmailAlias).where(
        GmailAlias.email == str(account.email or "").strip().lower())).first()
    if alias is None:
        return True
    if alias.registration_stage == "source_exhausted":
        return False
    from services.gmail_registration import _has_registered_identity
    if alias.registered_at or alias.registered_account_id or _has_registered_identity(None, account):
        return True
    from services.gmail_production_policy import can_start
    return can_start(session, alias, session.get(GmailSource, alias.source_id))


def _inventory(session):
    ids = preparation_ready_ids(session)
    rows = session.exec(select(GptPlanPreparationModel, GptPlanAccountModel)
                        .join(GptPlanAccountModel, GptPlanAccountModel.id == GptPlanPreparationModel.account_id)
                        .where(GptPlanPreparationModel.state == "ready")).all()
    return [(prep, account) for prep, account in rows if account.id in ids]


def _today_start():
    return datetime.now(ZoneInfo("Asia/Shanghai")).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def _today_attempts(session):
    return len(session.exec(select(PreparationAttempt.id).where(PreparationAttempt.started_at >= _today_start())).all())


def enqueue(count, *, automatic=False, browser_mode=None, due_only=False):
    if type(count) is not int or not 1 <= count <= 100:
        raise ValueError("每次准备数量须为 1–100")
    if browser_mode is not None and browser_mode not in {"headed", "headless"}:
        raise ValueError("浏览器模式无效")
    from api.gpt_business import (_regular_business_child_candidate_query, _is_business_child_candidate,
                                 _business_child_matches_candidate_mail_provider)
    now = time.time()
    with _write() as session:
        settings = _settings(session)
        config = session.get(PreparationSettings, 1) or PreparationSettings()
        if automatic and not settings["enabled"]:
            return {"ok": True, "queued": 0, "message": "尚未到自动检查时间"}
        active = session.exec(select(PreparationJob).where(PreparationJob.status.in_(BUSY))).all()
        if active:
            if automatic:
                config.next_run_at = 0
                session.add(config)
                return {"ok": True, "queued": 0, "message": "当前准备或 Cookie 检查队列尚未完成，完成后再开始定时间隔"}
            # This check and every job insert share the queue's write lock, so
            # two manual clicks cannot both observe an empty queue and append.
            # Cookie checks count too, exactly as the public BUSY counters do.
            raise ValueError("已有准备或 Cookie 检查任务等待或正在执行，请等待当前队列完成")
        if automatic:
            interval = settings["interval_minutes"] * 60
            # Legacy schedules may have been set while the previous queue was
            # still running. A read of its durable final completion establishes
            # the same idle floor after upgrades or a dispatcher restart.
            latest_finish = session.exec(select(func.max(PreparationJob.finished_at)).where(
                PreparationJob.status.not_in(BUSY),
            )).one() or 0
            config.next_run_at = _idle_next_run_at(config, settings, latest_finish, now)
            session.add(config)
            if due_only and config.next_run_at > now:
                return {"ok": True, "queued": 0, "message": "尚未到自动检查时间"}
            # Empty stock/target already met also waits a full interval before
            # the next check, rather than scanning on every dispatcher tick.
            config.next_run_at = now + interval
            count = min(count, max(0, settings["target_ready"] - len(_inventory(session))))
        old_ids = set(session.exec(select(GptPlanPreparationModel.account_id)).all())
        # Prior failures are retried as the same durable job, never freshly
        # enqueued to evade a retry limit or an uncertain password/MFA result.
        query = _regular_business_child_candidate_query(session).order_by(GptPlanAccountModel.id)
        candidates = session.exec(query).all() if count else []
        picked = []
        for account in candidates:
            if account.id in old_ids or not _is_business_child_candidate(account):
                continue
            if not _gmail_preparation_allowed(session, account):
                continue
            if not _business_child_matches_candidate_mail_provider(account, settings["mail_provider"]):
                continue
            picked.append(account)
            if len(picked) >= count:
                break
        for account in picked:
            job = PreparationJob(account_id=account.id, email=account.email, automatic=automatic,
                                 max_attempts=settings["max_attempts"], browser_mode=browser_mode or settings["browser_mode"])
            session.add(job)
            session.add(GptPlanPreparationModel(account_id=account.id, job_id=job.id))
            _log(session, job, "已加入准备队列；依次验证登录、密码和 2FA，成功后进入准备号池")
        if picked:
            _schedule_after_queue_change(session, now)
        return {"ok": True, "queued": len(picked), "message": f"已加入 {len(picked)} 个准备任务" if picked else "没有可加入的普通账号，或已达到准备库存目标"}


def enqueue_cookie_check(account_id):
    with _write() as session:
        prep = session.get(GptPlanPreparationModel, account_id)
        account = session.get(GptPlanAccountModel, account_id)
        if not prep or not account or not _ordinary(account):
            raise ValueError("准备账号不存在，或已不在普通 / 准备池")
        if session.exec(select(PreparationJob.id).where(PreparationJob.account_id == account_id, PreparationJob.status.in_(BUSY))).first():
            raise ValueError("该账号已有进行中的准备或检查任务")
        job = PreparationJob(account_id=account_id, email=account.email, kind="check_cookie", max_attempts=1,
                             browser_mode=_settings(session)["browser_mode"])
        session.add(job)
        _log(session, job, "已安排 Cookie 远端只读检查；401 不等同于账号停用")
        _schedule_after_queue_change(session, time.time())
        return {"ok": True, "job_id": job.id}


def claim_next():
    now = time.time()
    with _write() as session:
        settings = _settings(session)
        # One preparation browser globally, including multiple server processes.
        if session.exec(select(PreparationJob.id).where(PreparationJob.status == "running")).first():
            return None
        jobs = session.exec(select(PreparationJob).where(PreparationJob.status.in_(("pending", "retry")),
                                                       PreparationJob.next_retry_at <= now).order_by(PreparationJob.updated_at)).all()
        cancelled = False
        for job in jobs:
            if job.automatic and not settings["enabled"]:
                continue
            account = session.get(GptPlanAccountModel, job.account_id)
            account_email = str(account.email or "").strip().casefold() if account else ""
            if (not _ordinary(account) or not account_email
                    or account_email != str(job.email or "").strip().casefold()
                    or job.kind == "prepare" and not _gmail_preparation_allowed(session, account)):
                job.status, job.error, job.finished_at = "cancelled", "账号已删除、变更或离开普通池，未执行准备", now
                prep = session.get(GptPlanPreparationModel, job.account_id)
                if prep and prep.job_id == job.id:
                    prep.state, prep.error = "cancelled", job.error
                    session.add(prep)
                session.add(job)
                cancelled = True
                continue
            job.status, job.worker_token = "running", uuid.uuid4().hex
            job.started_at = job.heartbeat_at = job.updated_at = now
            job.worker_host, job.worker_pid = socket.gethostname(), 0
            job.attempts += 1
            job.error = ""
            job.finished_at = 0
            if job.kind == "prepare":
                session.add(PreparationAttempt(job_id=job.id, started_at=now))
                prep = session.get(GptPlanPreparationModel, job.account_id)
                prep.state, prep.updated_at = "running", now
                session.add(prep)
            session.add(job)
            _log(session, job, f"开始第 {job.attempts}/{job.max_attempts} 次处理")
            _schedule_after_queue_change(session, now)
            return {"id": job.id, "account_id": job.account_id, "token": job.worker_token, "kind": job.kind,
                    "settings": {**settings, "browser_mode": job.browser_mode}}
        if cancelled:
            _schedule_after_queue_change(session, now)
    return None


def heartbeat(job_id, token, pid=0):
    with _write() as session:
        job = session.get(PreparationJob, job_id)
        if not job or job.worker_token != token or job.status != "running":
            return False
        job.heartbeat_at = time.time()
        if pid:
            job.worker_pid = pid
        session.add(job)
        return True


def append_log(job_id, token, message):
    with _write() as session:
        job = session.get(PreparationJob, job_id)
        if job and job.worker_token == token and job.status == "running":
            _log(session, job, message)


def _metadata(prep, details):
    registered_at = _epoch(details.get("registered_at"))
    if registered_at and not prep.registered_at:
        prep.registered_at = registered_at
    for field in ("cookie_checked_at", "cookie_expires_at"):
        if field in details:
            setattr(prep, field, _epoch(details[field]))
    if type(details.get("cookie_saved")) is bool:
        prep.cookie_saved = details["cookie_saved"]
    if details.get("cookie_health") in {"valid", "expired", "dead", "unknown", "error", "missing", "blocked", "wrong_identity", "network_error"}:
        prep.cookie_health = details["cookie_health"]


def checkpoint(job_id, token, stage, details=None):
    if stage not in STAGES:
        return
    details = details or {}
    from services.chatgpt_security_progress import normalize_security_progress
    with _write() as session:
        job = session.get(PreparationJob, job_id)
        if not job or job.worker_token != token or job.status != "running":
            raise RuntimeError("准备任务已不属于当前执行者")
        if stage != job.stage:
            _log(session, job, STAGES[stage])
        job.stage, job.updated_at = stage, time.time()
        if isinstance(details.get("account_operation_token"), str):
            job.account_operation_token = details["account_operation_token"]
        progress = normalize_security_progress(details.get("security_progress"))
        if progress:
            progress["reason"] = _safe(progress.get("reason", ""))
            job.security_progress_json = json.dumps(progress, ensure_ascii=False)
        prep = session.get(GptPlanPreparationModel, job.account_id)
        if prep:
            _metadata(prep, details)
            if job.kind == "prepare":
                prep.stage, prep.updated_at = stage, time.time()
            session.add(prep)
        session.add(job)


def finish(job_id, token, result):
    now = time.time()
    with _write() as session:
        job = session.get(PreparationJob, job_id)
        if not job or job.worker_token != token or job.status != "running":
            return False
        prep = session.get(GptPlanPreparationModel, job.account_id)
        account = session.get(GptPlanAccountModel, job.account_id)
        account_email = str(account.email or "").strip().casefold() if account else ""
        if (not prep or not account_email or account_email != str(job.email or "").strip().casefold()
                or not _ordinary(account)):
            job.status, job.error = "cancelled", "账号身份或归属已变化，未迁移到准备池"
            if prep and prep.job_id == job.id:
                prep.state, prep.error, prep.updated_at = "cancelled", job.error, now
                session.add(prep)
        else:
            _metadata(prep, result)
            ok = result.get("ok") is True
            if job.kind == "prepare" and ok:
                from services.chatgpt_security_store import get_chatgpt_security_status
                try:
                    security = get_chatgpt_security_status(account.email)
                except Exception:
                    security = {}
                from api.gpt_business import _is_business_child_candidate
                ok = (ok and result.get("registered_verified") is True and result.get("security_confirmed") is True
                      and result.get("cookie_saved") is True and bool(account.cookie_blob)
                      and result.get("cookie_health") == "valid" and security.get("credentials_readable") is True
                      and security.get("has_password") is True and security.get("has_totp") is True
                      and security.get("password_state") == "configured" and security.get("mfa_state") == "enabled"
                      and _is_business_child_candidate(account))
            if ok:
                job.status, job.error = "completed", ""
                if job.kind == "prepare":
                    prep.state, prep.stage, prep.ready_at = "ready", "ready", now
                    job.stage = "ready"
                    prep.registered_at = prep.registered_at or now
                _log(session, job, "密码、2FA 与登录身份均已确认，已迁移到准备号池" if job.kind == "prepare" else "Cookie 远端检查完成")
            else:
                job.error = _safe(result.get("error")) or "尚未取得完整注册、密码、2FA 与会话证据，未迁移到准备号池"
                job.error_code = str(result.get("error_code") or "verification_incomplete")[:100]
                if result.get("dead") is True:
                    job.status = "dead"
                    # Only the capability's exact remote deactivation-code
                    # evidence may mark an account. Generic HTTP 401 cannot.
                    account.dangerous = True
                    account.dangerous_detected_at = datetime.now(timezone.utc)
                    session.add(account)
                elif result.get("retryable") is True and job.attempts < job.max_attempts:
                    job.status = "retry"
                    job.next_retry_at = now + min(1800, 60 * (2 ** (job.attempts - 1)))
                elif (job.error_code == "gmail_source_exhausted"
                      and result.get("source_error_code") == "user_already_exists"):
                    job.status = "failed"
                else:
                    job.status = "failed" if result.get("retryable") is True else "review"
                if job.kind == "prepare" or result.get("dead") is True:
                    prep.state = job.status
                _log(session, job, job.error + ("；已安排自动重试" if job.status == "retry" else ""))
            prep.error, prep.updated_at = job.error, now
            session.add(prep)
        job.updated_at, job.finished_at, job.worker_token = now, now, ""
        job.worker_pid = 0
        from core.db import GptPlanAccountOperationLeaseModel
        lease = session.get(GptPlanAccountOperationLeaseModel, job.account_id)
        if (lease and job.account_operation_token and lease.token == job.account_operation_token
                and lease.operation == "account_preparation"):
            session.delete(lease)
        session.add(job)
        _schedule_after_queue_change(session, now)
        return True


def interrupt_job(job_id, token):
    # A crashed password/TOTP mutation is not blindly replayed by a restart.
    from core.db import GptPlanAccountOperationLeaseModel
    with _write() as session:
        job = session.get(PreparationJob, job_id)
        if not job or job.worker_token != token or job.status != "running":
            return False
        lease = session.get(GptPlanAccountOperationLeaseModel, job.account_id)
        if (lease and job.account_operation_token and lease.token == job.account_operation_token
                and lease.operation == "account_preparation"):
            session.delete(lease)
    return finish(job_id, token, {"ok": False, "error_code": "worker_interrupted",
                                 "error": "准备进程中断，已保留步骤和凭据；请重试，系统会先核验已有结果", "retryable": False})


def recover_stale(alive):
    with Session(engine) as session:
        jobs = session.exec(select(PreparationJob).where(PreparationJob.status == "running")).all()
    for job in jobs:
        if job.worker_host != socket.gethostname():
            continue
        if time.time() - job.heartbeat_at <= 90:
            continue
        if job.worker_pid and alive(job.worker_pid):
            continue
        interrupt_job(job.id, job.worker_token)


class _RetryIneligible(ValueError):
    """Only fixed, public eligibility reasons may become per-item skips."""


def _retry_job_locked(session, job, *, browser_mode=None):
    """Requeue one existing job under the caller's transaction and safety guards."""
    from api.gpt_business import _is_business_child_candidate, _business_child_has_completed_history
    from core.db import GptBusinessChildMembershipModel, GptPlanAccountOperationLeaseModel
    if not job or job.status not in {"failed", "review", "retry"}:
        raise _RetryIneligible("仅失败、待人工处理或等待重试的任务可以继续")
    if job.error_code == "gmail_source_exhausted":
        raise _RetryIneligible("该 Gmail 母号已停止新号生产，不能重新注册原子号；后续任务将改选其他母号")
    account = session.get(GptPlanAccountModel, job.account_id)
    if account is None:
        raise _RetryIneligible("账号已删除，未重新执行")
    email = str(account.email or "").strip().casefold()
    if not email or email != str(job.email or "").strip().casefold():
        raise _RetryIneligible("账号邮箱身份已变化，未重新执行")
    if not _ordinary(account) or not _is_business_child_candidate(account):
        raise _RetryIneligible("账号已非健康、未使用的普通账号，未重新执行")
    if job.kind == "prepare" and not _gmail_preparation_allowed(session, account):
        raise _RetryIneligible("该 Gmail 母号已停止新号生产，后续任务将改选其他可用母号")
    prep = session.get(GptPlanPreparationModel, job.account_id)
    if not prep or (job.kind == "prepare" and prep.job_id != job.id):
        raise _RetryIneligible("准备记录已缺失或属于更新任务，未重新执行旧任务")
    if prep.state == "dead":
        raise _RetryIneligible("准备账号已标记停用，未重新执行")
    membership = session.exec(select(GptBusinessChildMembershipModel.id).where(
        GptBusinessChildMembershipModel.ended_at.is_(None),
        (GptBusinessChildMembershipModel.pro_account_id == job.account_id)
        | (func.lower(func.trim(GptBusinessChildMembershipModel.email)) == email),
    ).limit(1)).first()
    if membership is not None:
        raise _RetryIneligible("账号已有当前 BUSINESS 归属，未重新执行")
    if _business_child_has_completed_history(session, child_id=job.account_id, email=email):
        raise _RetryIneligible("账号已有历史 BUSINESS 归属，不再作为未使用普通账号准备")
    if session.exec(select(PreparationJob.id).where(
        PreparationJob.account_id == job.account_id, PreparationJob.id != job.id,
        PreparationJob.status.in_(BUSY),
    ).limit(1)).first():
        raise _RetryIneligible("该账号已有其他准备或 Cookie 检查任务，不能重复执行")
    now = time.time()
    if session.exec(select(GptPlanAccountOperationLeaseModel.account_id).where(
        GptPlanAccountOperationLeaseModel.account_id == job.account_id,
        GptPlanAccountOperationLeaseModel.expires_at > datetime.fromtimestamp(now, timezone.utc),
    ).limit(1)).first() is not None:
        raise _RetryIneligible("账号正被其他操作占用，未抢占操作租约")
    job.status, job.next_retry_at, job.updated_at = "pending", 0, now
    job.automatic = False
    if browser_mode is not None:
        job.browser_mode = browser_mode
    # Explicit authority adds only one opportunity when exhausted. Attempts,
    # saved stage, progress and encrypted credentials are never reset here.
    job.max_attempts = max(job.max_attempts, job.attempts + 1)
    if job.kind == "prepare":
        prep.state = "pending"
        session.add(prep)
    session.add(job)
    _log(session, job, "人工请求继续；先核验已保存步骤，不重复设置已完成的密码与 2FA")
    _schedule_after_queue_change(session, now)


def retry_job(job_id):
    with _write() as session:
        _retry_job_locked(session, session.get(PreparationJob, job_id))
    return {"ok": True}


def retry_failed_jobs(*, browser_mode=None):
    """Requeue at most one fixed snapshot of 100 failed preparation jobs."""
    if browser_mode is not None and (not isinstance(browser_mode, str) or browser_mode not in {"headed", "headless"}):
        raise ValueError("浏览器模式无效")
    with _write() as session:
        predicates = (PreparationJob.kind == "prepare", PreparationJob.status.in_(("failed", "review")))
        total = session.exec(select(func.count()).select_from(PreparationJob).where(*predicates)).one()
        selected = session.exec(select(PreparationJob).where(*predicates)
                                .order_by(PreparationJob.updated_at, PreparationJob.id)
                                .limit(BULK_RETRY_LIMIT)).all()
        items = []
        queued = 0
        reviewed_at = time.time()
        for job in selected:
            try:
                _retry_job_locked(session, job, browser_mode=browser_mode)
            except _RetryIneligible as exc:
                # Explicitly reviewed skips rotate behind unexamined history,
                # otherwise 100 permanently ineligible old rows starve the
                # remaining failures forever. Only audit time/log changes.
                job.updated_at = reviewed_at
                session.add(job)
                _log(session, job, "本次人工批量重试已跳过：" + str(exc))
                items.append(dict(id=job.id, email=job.email, status="skipped", reason=str(exc)))
            else:
                queued += 1
                items.append(dict(id=job.id, email=job.email, status="queued",
                                  reason="已加入现有串行队列；保留单账号重试次数限制"))
        skipped, remaining = len(selected) - queued, max(0, total - len(selected))
        message = f"已加入 {queued} 项，跳过 {skipped} 项；还有 {remaining} 项未纳入本次"
        message += "。入队不等于立即执行：按现有队列串行处理，保留单账号重试次数限制"
        return dict(ok=True, queued=queued, skipped=skipped, remaining=remaining, items=items, message=message)


def _public_job(job):
    return {"id": job.id, "account_id": job.account_id, "email": job.email, "kind": job.kind,
            "status": job.status, "status_label": STATUS_LABELS.get(job.status, job.status), "stage": job.stage,
            "stage_label": STAGES.get(job.stage, job.stage), "attempts": job.attempts, "max_attempts": job.max_attempts,
            "error": job.error, "error_code": job.error_code, "security_progress": json.loads(job.security_progress_json),
            **{key: _iso(getattr(job, key)) for key in ("created_at", "updated_at", "finished_at", "next_retry_at")}}


def list_jobs(page=1, page_size=10, status=None, keyword=None):
    with Session(engine) as session:
        if not _exists(session, "gpt_plan_preparation_jobs"):
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        query = select(PreparationJob)
        if status:
            query = query.where(PreparationJob.status == status)
        if keyword:
            query = query.where(PreparationJob.email.contains(keyword))
        rows = session.exec(query.order_by(PreparationJob.updated_at.desc())).all()
        return {"items": [_public_job(j) for j in rows[(page-1)*page_size:page*page_size]], "total": len(rows), "page": page, "page_size": page_size}


def get_job(job_id):
    with Session(engine) as session:
        if not _exists(session, "gpt_plan_preparation_jobs"):
            return None
        job = session.get(PreparationJob, job_id)
        if not job:
            return None
        logs = session.exec(select(PreparationLog).where(PreparationLog.job_id == job_id).order_by(PreparationLog.id.desc()).limit(500)).all()
        return {**_public_job(job), "logs": [{"at": _iso(log.at), "message": log.message} for log in reversed(logs)]}


def list_accounts(page=1, page_size=10, keyword=None):
    from services.chatgpt_security_store import get_chatgpt_security_status
    with Session(engine) as session:
        if not _exists(session):
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        rows = [(prep, account) for prep, account in _inventory(session) if not keyword or keyword.casefold() in account.email.casefold()]
        rows.sort(key=lambda pair: pair[0].ready_at, reverse=True)
        items = []
        for prep, account in rows[(page-1)*page_size:page*page_size]:
            status = get_chatgpt_security_status(account.email)
            items.append({"account_id": account.id, "email": account.email, "mail_provider": account.mail_provider,
                          "note": account.note, "state": prep.state, "stage": prep.stage, "stage_label": STAGES.get(prep.stage, prep.stage),
                          "has_password": status["has_password"], "has_totp": status["has_totp"], "error": prep.error,
                          "cookie_saved": bool(account.cookie_blob), "cookie_health": prep.cookie_health,
                          **{key: _iso(getattr(prep, key)) for key in ("ready_at", "registered_at", "cookie_checked_at", "cookie_expires_at")}})
        return {"items": items, "total": len(rows), "page": page, "page_size": page_size}


def snapshot():
    with Session(engine) as session:
        if not _exists(session, "gpt_plan_preparation_settings"):
            return {"settings": dict(DEFAULTS), "counts": {key: 0 for key in ("ready", "pending", "running", "retry", "failed", "review", "retryable_prepare", "today_ready", "today_attempts")},
                    "runtime": {"next_run_at": "", "last_error": "", "schedule_state": "disabled", "queue_busy": False}}
        settings = _settings(session)
        config = session.get(PreparationSettings, 1)
        jobs = session.exec(select(PreparationJob)).all()
        counts = {state: sum(j.status == state for j in jobs) for state in ("pending", "running", "retry", "failed", "review")}
        counts.update(retryable_prepare=sum(j.kind == "prepare" and j.status in {"failed", "review"} for j in jobs),
                      ready=len(_inventory(session)), today_ready=sum(j.kind == "prepare" and j.status == "completed" and j.finished_at >= _today_start() for j in jobs),
                      today_attempts=_today_attempts(session))
        queue_busy = any(j.status in BUSY for j in jobs)
        schedule_state = "disabled" if not settings["enabled"] else "waiting_queue" if queue_busy else "waiting_interval"
        latest_finish = max((j.finished_at for j in jobs if j.status not in BUSY), default=0)
        next_run_at = _idle_next_run_at(config, settings, latest_finish, time.time()) if schedule_state == "waiting_interval" else 0
        return {"settings": settings, "counts": counts,
                "runtime": {"next_run_at": _iso(next_run_at), "last_error": config.last_error if config else "",
                            "schedule_state": schedule_state, "queue_busy": queue_busy}}


def worker_job(job_id, token):
    with Session(engine) as session:
        job = session.get(PreparationJob, job_id)
        if not job or job.worker_token != token or job.status != "running":
            return None
        return {"id": job.id, "account_id": job.account_id, "kind": job.kind,
                "settings": {**_settings(session), "browser_mode": job.browser_mode, "_expected_email": job.email}}
