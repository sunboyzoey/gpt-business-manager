"""Durable, secret-free job API for Gmail app-password provisioning.

Only encrypted pending results are retained. Browser/network effects belong to
workers; this module fences every source write and never launches a thread.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import os
import secrets
from typing import Optional
from uuid import uuid4

from sqlalchemy import inspect, or_, update
from sqlmodel import Field, Session, SQLModel, select

from services import gmail_store as store

LEASE_SECONDS = 600
MAX_AUTOMATIC_ATTEMPTS = 3

_MESSAGES = {
    "queued": "等待自动配置 Gmail 收件授权",
    "running": "正在配置 Gmail 收件授权",
    "verified": "Gmail 收件授权已验证并保存",
    "already_ready": "已有有效收件授权，无需重复生成",
    "source_disabled": "母号已停用，未继续配置收件授权",
    "source_busy": "母号正在进行其他验证，收件授权任务将稍后自动继续",
    "source_changed": "母号资料或收件授权已更新，本次结果未覆盖最新配置",
    "credentials_missing": "母号缺少可用的登录资料，尚未开始生成应用密码",
    "create_result_unknown": "Google 可能已生成应用密码，但结果未保存；已停止重复生成，请核对 Google 应用密码记录",
    "credential_persist_failed": "Google 应用密码生成结果未能保存；已停止重复生成，请核对 Google 应用密码记录",
    "app_passwords_unavailable": "此 Google 账号暂不支持应用密码，请检查两步验证及账号策略",
    "app_name_already_exists": "Google 已存在本次任务的应用密码名称，未再次生成",
    "account_mismatch": "Google 登录身份与当前 Gmail 母号不一致，未继续生成",
    "account_identity_unconfirmed": "尚未确认 Google 登录身份，未继续生成",
    "captcha_required": "Google 要求人机验证，自动配置暂时停止",
    "device_verification_required": "Google 要求设备确认，自动配置暂时停止",
    "totp_required": "Google 要求 Authenticator 验证，但未取得有效验证资料",
    "totp_rejected": "Google 未接受 Authenticator 验证，请检查已保存的两步验证资料",
    "invalid_password": "Google 登录密码验证失败，尚未生成应用密码",
    "password_changed": "Google 登录密码已变化，请更新母号登录资料",
    "recovery_rejected": "Google 未接受辅助邮箱验证，尚未生成应用密码",
    "invalid_email": "Google 未接受母号邮箱，尚未生成应用密码",
    "account_disabled": "Google 账号当前不可用，尚未生成应用密码",
    "unsafe_browser": "Google 未接受当前浏览器环境，尚未生成应用密码",
    "invalid_credentials": "母号登录资料不完整，尚未生成应用密码",
    "invalid_proxy": "母号代理配置无效，尚未开始配置",
    "invalid_app_name": "应用密码任务名称无效，尚未开始生成",
    "missing_persistence_callbacks": "应用密码保存回调不可用，尚未开始生成",
    "unsupported_app_password_page": "Google 应用密码页面暂不受支持，尚未生成新密码",
    "unexpected_page": "未识别到可安全操作的 Google 页面，尚未生成新密码",
    "create_guard_failed": "创建前身份或任务校验未通过，未重复提交",
    "gmail_not_ready": "Gmail 页面尚未就绪，将稍后重试",
    "provision_timeout": "自动配置等待超时，将稍后重试",
    "network_timeout": "连接 Google 或 Gmail 超时，将稍后重试",
    "navigation_error": "Google 页面跳转暂时失败，将稍后重试",
    "browser_closed": "验证浏览器已关闭，可重新继续本次任务",
    "browser_init_failed": "验证浏览器启动失败，可重新继续本次任务",
    "browser_cleanup_failed": "验证浏览器清理未完成，本次授权状态以持久记录为准",
    "provision_failed": "自动配置未完成，请查看当前失败阶段后重试",
    "cancelled": "本次自动配置已停止",
    "interrupted": "上次任务中断，将从已保存的阶段继续",
    "imap_timeout": "已保存应用密码，Gmail 收件验证超时，将只重试收件验证",
    "imap_network_error": "已保存应用密码，Gmail 收件连接失败，将只重试收件验证",
    "imap_auth_failed": "已保存应用密码，但 Gmail 未接受收件授权；不会重新生成密码",
    "imap_authentication_failed": "已保存应用密码，但 Gmail 未接受收件授权；不会重新生成密码",
    "imap_tls_error": "已保存应用密码，但无法建立安全的 Gmail TLS 连接，请检查网络或代理设置",
    "imap_imap_error": "已保存应用密码，但 Gmail 收信请求未完成，可继续验证已保存的授权",
    "imap_invalid_proxy": "已保存应用密码，但母号代理配置无效，请更新代理后继续验证",
    "imap_invalid_source": "Gmail 收件验证的母号地址无效，尚未启用收件授权",
    "imap_invalid_credentials": "已保存的 Gmail 收件授权格式无效，尚未启用收件授权",
    "imap_mailbox_unavailable": "已保存应用密码，但 Gmail 未提供可读取的邮箱文件夹",
    "authentication_failed": "Gmail 未接受收件授权；已保存的密码未丢弃",
    "auth_required": "Gmail 收件授权验证失败；已保存的密码未丢弃",
    "crypto_error": "应用密码加密或解密暂不可用，请检查服务凭证密钥",
    "failed": "自动配置未完成，未覆盖已有收件授权",
}
_TRANSIENT = {"source_busy", "gmail_not_ready", "provision_timeout", "network_timeout", "navigation_error", "browser_closed",
              "browser_init_failed", "imap_timeout", "imap_network_error", "interrupted"}
_NEEDS_USER = {"create_result_unknown", "credential_persist_failed", "app_passwords_unavailable", "app_name_already_exists",
               "account_mismatch", "captcha_required", "device_verification_required", "account_disabled"}
_STAGES = {"queued", "browser", "email", "password", "totp", "recovery", "inbox", "identity", "app_passwords",
           "before_create", "create_started", "credential_saved", "imap", "completed", "failed", "interrupted", "needs_user"}
_STAGE_ALIASES = {"account": "identity", "app_password": "app_passwords", "creating": "create_started"}


class GmailAppPasswordJob(SQLModel, table=True):
    __tablename__ = "gmail_app_password_jobs"
    id: str = Field(default_factory=lambda: uuid4().hex, primary_key=True)
    source_id: int = Field(foreign_key="gmail_sources.id", index=True)
    active_source_key: Optional[str] = Field(default=None, sa_column_kwargs={"unique": True})
    email: str
    source_revision: int
    status: str = "queued"
    stage: str = "queued"
    error_code: str = "queued"
    mode: str = "create"
    pending_ciphertext: str = ""
    create_started_at: Optional[datetime] = None
    attempts: int = 0
    automatic_attempts: int = 0
    next_retry_at: Optional[datetime] = None
    worker_token: str = ""
    worker_pid: int = 0
    worker_started_at: float = 0
    lease_expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=store.utcnow)
    updated_at: datetime = Field(default_factory=store.utcnow)


@dataclass(frozen=True)
class AppPasswordJobSnapshot:
    job_id: str
    source_id: int
    email: str
    revision: int
    worker_token: str = field(repr=False)
    proxy_url: str
    verification: store.VerificationSnapshot = field(repr=False)
    has_pending_password: bool = False


def init_tables(engine_override=None):
    SQLModel.metadata.create_all(engine_override if engine_override is not None else store.engine,
                                 tables=[GmailAppPasswordJob.__table__])


def _available():
    return GmailAppPasswordJob.__tablename__ in inspect(store.engine).get_table_names()


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def _public(job):
    uncertain = bool(job.create_started_at and not job.pending_ciphertext)
    can_retry = job.status in {"failed", "interrupted", "needs_user"} and not uncertain
    return {"id": job.id, "source_id": job.source_id, "email": job.email, "status": job.status,
            "stage": job.stage, "message": _MESSAGES.get(job.error_code, _MESSAGES["failed"]),
            "error_code": job.error_code if job.error_code in _MESSAGES else "failed", "can_retry": can_retry,
            "has_pending_password": bool(job.pending_ciphertext), "attempts": job.attempts,
            "next_retry_at": job.next_retry_at, "created_at": job.created_at, "updated_at": job.updated_at}


def _lock(session):
    session.execute(update(GmailAppPasswordJob).where(GmailAppPasswordJob.id == "").values(stage="queued"))


def _job(session, job_id):
    job = session.get(GmailAppPasswordJob, str(job_id))
    if job is None:
        raise store.GmailStoreError("app_password_job_not_found", "未找到 Gmail 收件授权任务", 404)
    return job


def _clear_worker(job):
    job.worker_token, job.worker_pid, job.worker_started_at = "", 0, 0
    job.lease_expires_at = None


def _source_current(source, snapshot):
    return bool(source and source.enabled and source.id == snapshot.source_id and source.email == snapshot.email
                and source.credential_revision == snapshot.revision
                and source.app_password_ciphertext == snapshot.verification.app_password_ciphertext)


def _owned(session, snapshot):
    job = _job(session, snapshot.job_id)
    if (job.status != "running" or not snapshot.worker_token or job.worker_token != snapshot.worker_token
            or job.source_id != snapshot.source_id or job.source_revision != snapshot.revision
            or _aware(job.lease_expires_at) is None or _aware(job.lease_expires_at) <= store.utcnow()):
        raise store.GmailStoreError("app_password_lease_changed", "收件授权任务已变化，旧任务未覆盖当前状态", 409)
    return job


def _retry_locked(session, job, source):
    if not source.enabled:
        raise store.GmailStoreError("source_disabled", _MESSAGES["source_disabled"], 409)
    if job.status == "running" or job.status == "queued":
        return job
    if job.create_started_at and not job.pending_ciphertext:
        raise store.GmailStoreError("create_result_unknown", _MESSAGES["create_result_unknown"], 409)
    if source.app_password_ciphertext and source.app_password_ciphertext != job.pending_ciphertext:
        raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
    if job.email != source.email:
        raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
    job.source_revision = source.credential_revision
    job.status, job.stage, job.error_code = "queued", "queued", "queued"
    job.automatic_attempts, job.next_retry_at = 0, None
    job.active_source_key = str(source.id)
    job.updated_at = store.utcnow()
    _clear_worker(job)
    session.add(job)
    return job


def begin(source_id: int) -> dict:
    with Session(store.engine) as session:
        _lock(session)
        source = store._source(session, source_id)
        if not source.enabled:
            raise store.GmailStoreError("source_disabled", _MESSAGES["source_disabled"], 409)
        active = session.exec(select(GmailAppPasswordJob).where(GmailAppPasswordJob.active_source_key == str(source_id))).first()
        ready = bool(source.app_password_ciphertext and source.receive_verified)
        if active and ready and active.status != "running":
            active.active_source_key = None
            active.status, active.stage, active.error_code = "succeeded", "completed", "already_ready"
            active.updated_at = store.utcnow()
            session.add(active)
            session.commit()
            return _public(active)
        if active:
            if active.status not in {"running", "queued"} and not (active.create_started_at and not active.pending_ciphertext):
                _retry_locked(session, active, source)
            session.add(active)
            session.commit()
            return _public(active)
        if ready:
            previous = session.exec(select(GmailAppPasswordJob).where(GmailAppPasswordJob.source_id == source_id,
                GmailAppPasswordJob.status == "succeeded").order_by(GmailAppPasswordJob.created_at.desc())).first()
            if previous:
                return _public(previous)
        if not ready and not source.app_password_ciphertext and not source.login_password_ciphertext:
            raise store.GmailStoreError("credentials_missing", _MESSAGES["credentials_missing"], 409)
        job = GmailAppPasswordJob(source_id=source.id, email=source.email, source_revision=source.credential_revision,
            active_source_key=None if ready else str(source.id),
            pending_ciphertext=source.app_password_ciphertext if not ready else "",
            mode="verify_existing" if source.app_password_ciphertext else "create",
            status="succeeded" if ready else "queued", stage="completed" if ready else "queued",
            error_code="already_ready" if ready else "queued")
        session.add(job)
        session.commit()
        return _public(job)


def begin_inline(source_id: int) -> AppPasswordJobSnapshot:
    """Claim a new setup job inside an already authenticated import flow.

    The durable running lease is written before Google is allowed to create a
    password, so the background worker cannot race this browser. Existing
    active work is never replaced.
    """
    with Session(store.engine) as session:
        _lock(session)
        source = store._source(session, source_id)
        if not source.enabled:
            raise store.GmailStoreError("source_disabled", _MESSAGES["source_disabled"], 409)
        active = session.exec(select(GmailAppPasswordJob).where(
            GmailAppPasswordJob.active_source_key == str(source_id))).first()
        if active is not None:
            raise store.GmailStoreError("source_busy", _MESSAGES["source_busy"], 409)
        if source.app_password_ciphertext and source.receive_verified:
            raise store.GmailStoreError("already_ready", _MESSAGES["already_ready"], 409)
        now = store.utcnow()
        token = secrets.token_urlsafe(24)
        verification = store.VerificationSnapshot(
            source.id, source.email, source.credential_revision, source.enabled,
            source.proxy_url, source.login_password_ciphertext, source.totp_secret_ciphertext,
            source.verification_url_ciphertext, source.app_password_ciphertext, source.recovery_email,
        )
        job = GmailAppPasswordJob(
            source_id=source.id, email=source.email, source_revision=source.credential_revision,
            active_source_key=str(source.id), pending_ciphertext=source.app_password_ciphertext,
            mode="verify_existing" if source.app_password_ciphertext else "create",
            status="running", stage="imap" if source.app_password_ciphertext else "browser",
            error_code="running", worker_token=token, worker_pid=os.getpid(),
            lease_expires_at=now + timedelta(seconds=LEASE_SECONDS), attempts=1,
            automatic_attempts=1, updated_at=now,
        )
        try:
            import psutil
            job.worker_started_at = psutil.Process(job.worker_pid).create_time()
        except Exception:
            job.worker_started_at = 0
        session.add(job)
        session.commit()
        return AppPasswordJobSnapshot(job.id, source.id, source.email, source.credential_revision,
                                      token, source.proxy_url, verification,
                                      bool(source.app_password_ciphertext))


def get_job(job_id):
    if not _available():
        raise store.GmailStoreError("app_password_job_not_found", "未找到 Gmail 收件授权任务", 404)
    with Session(store.engine) as session:
        return _public(_job(session, job_id))


def list_jobs(source_id=None):
    if not _available():
        return []
    with Session(store.engine) as session:
        query = select(GmailAppPasswordJob)
        if source_id is not None:
            query = query.where(GmailAppPasswordJob.source_id == source_id)
        return [_public(job) for job in session.exec(query.order_by(GmailAppPasswordJob.created_at.desc()).limit(100)).all()]


def latest_for_source(source_id):
    rows = list_jobs(source_id)
    return rows[0] if rows else None


def latest_jobs_by_source():
    """One latest public job per source, without the history-list limit."""
    if not _available():
        return []
    with Session(store.engine) as session:
        rows = session.exec(select(GmailAppPasswordJob).order_by(
            GmailAppPasswordJob.created_at.desc(), GmailAppPasswordJob.id.desc())).all()
        latest = {}
        for row in rows:
            if row.source_id not in latest:
                latest[row.source_id] = _public(row)
        return list(latest.values())


def retry(job_id):
    with Session(store.engine) as session:
        _lock(session)
        job = _job(session, job_id)
        if job.status == "succeeded":
            return _public(job)
        _retry_locked(session, job, store._source(session, job.source_id))
        session.add(job)
        session.commit()
        return _public(job)


def _due(job, now):
    return (job.status == "queued" or (job.status in {"failed", "interrupted"}
        and job.automatic_attempts < MAX_AUTOMATIC_ATTEMPTS and job.next_retry_at is not None
        and _aware(job.next_retry_at) <= now))


def list_queued(limit=50):
    if not _available():
        return []
    with Session(store.engine) as session:
        rows = session.exec(select(GmailAppPasswordJob).where(or_(GmailAppPasswordJob.status == "queued",
            (GmailAppPasswordJob.status.in_(("failed", "interrupted")))
            & (GmailAppPasswordJob.automatic_attempts < MAX_AUTOMATIC_ATTEMPTS)
            & (GmailAppPasswordJob.next_retry_at <= store.utcnow())))
            .order_by(GmailAppPasswordJob.created_at).limit(max(1, min(int(limit), 100)))).all()
        return [_public(job) for job in rows]


def claim(job_id):
    with Session(store.engine) as session:
        _lock(session)
        job = _job(session, job_id)
        if not _due(job, store.utcnow()):
            return None
        source = store._source(session, job.source_id)
        if not source.enabled or source.credential_revision != job.source_revision or source.email != job.email:
            job.status, job.stage = "failed", "failed"
            job.error_code = "source_disabled" if not source.enabled else "source_changed"
            job.next_retry_at = None
            session.add(job)
            session.commit()
            return None
        if job.create_started_at and not job.pending_ciphertext:
            job.status, job.stage, job.error_code = "needs_user", "needs_user", "create_result_unknown"
            job.next_retry_at = None
            session.add(job)
            session.commit()
            return None
        now = store.utcnow()
        verification = store.VerificationSnapshot(source.id, source.email, source.credential_revision, source.enabled,
            source.proxy_url, source.login_password_ciphertext, source.totp_secret_ciphertext,
            source.verification_url_ciphertext, source.app_password_ciphertext, source.recovery_email)
        job.status, job.stage, job.error_code = "running", "imap" if job.pending_ciphertext else "browser", "running"
        job.worker_token, job.worker_pid = secrets.token_urlsafe(24), os.getpid()
        try:
            import psutil
            job.worker_started_at = psutil.Process(job.worker_pid).create_time()
        except Exception:
            job.worker_started_at = 0
        job.lease_expires_at, job.updated_at = now + timedelta(seconds=LEASE_SECONDS), now
        job.attempts += 1
        job.automatic_attempts += 1
        job.next_retry_at = None
        session.add(job)
        session.commit()
        return AppPasswordJobSnapshot(job.id, source.id, source.email, source.credential_revision,
                                      job.worker_token, source.proxy_url, verification, bool(job.pending_ciphertext))


def is_current(snapshot):
    try:
        with Session(store.engine) as session:
            _owned(session, snapshot)
            return _source_current(session.get(store.GmailSource, snapshot.source_id), snapshot)
    except Exception:
        return False


def heartbeat(snapshot, stage=None):
    try:
        with Session(store.engine) as session:
            _lock(session)
            job = _owned(session, snapshot)
            if not _source_current(session.get(store.GmailSource, snapshot.source_id), snapshot):
                return False
            job.updated_at = store.utcnow()
            job.lease_expires_at = store.utcnow() + timedelta(seconds=LEASE_SECONDS)
            stage = _STAGE_ALIASES.get(stage, stage) if isinstance(stage, str) else None
            if stage == "create_started" and job.create_started_at and not job.pending_ciphertext:
                job.stage = stage
            if stage in _STAGES and stage not in {"create_started", "credential_saved", "completed"}:
                job.stage = stage
            session.add(job)
            session.commit()
            return True
    except store.GmailStoreError:
        return False


def before_create(snapshot):
    with Session(store.engine) as session:
        _lock(session)
        job = _owned(session, snapshot)
        source = store._source(session, snapshot.source_id)
        if not _source_current(source, snapshot) or source.app_password_ciphertext:
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
        if job.pending_ciphertext or job.create_started_at:
            raise store.GmailStoreError("create_result_unknown", _MESSAGES["create_result_unknown"], 409)
        # Acquire a real source-row write fence as well as the job lease. This
        # keeps revision validation atomic on engines other than SQLite too.
        checked = session.execute(update(store.GmailSource).where(
            store.GmailSource.id == snapshot.source_id,
            store.GmailSource.email == snapshot.email,
            store.GmailSource.enabled.is_(True),
            store.GmailSource.credential_revision == snapshot.revision,
            store.GmailSource.app_password_ciphertext == snapshot.verification.app_password_ciphertext
        ).values(updated_at=store.GmailSource.updated_at))
        if checked.rowcount != 1:
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
        job.create_started_at, job.updated_at = store.utcnow(), store.utcnow()
        job.stage = "create_started"
        job.lease_expires_at = store.utcnow() + timedelta(seconds=LEASE_SECONDS)
        session.add(job)
        session.commit()


def save_created(snapshot, password):
    # Encrypt before entering the short DB transaction; the input is never put
    # into errors, logs, DTOs, or the source row before IMAP has confirmed it.
    normalized = store.normalize_app_password(password)
    ciphertext = store._encrypt(snapshot.email, normalized)
    with Session(store.engine) as session:
        _lock(session)
        job = _owned(session, snapshot)
        if not job.create_started_at or job.pending_ciphertext:
            raise store.GmailStoreError("app_password_result_changed", "应用密码结果不属于当前创建阶段，未覆盖已有结果", 409)
        job.pending_ciphertext, job.stage, job.updated_at = ciphertext, "credential_saved", store.utcnow()
        job.lease_expires_at = store.utcnow() + timedelta(seconds=LEASE_SECONDS)
        session.add(job)
        session.commit()
        # Even a concurrent edit must not lose an already-created remote secret.
        # It remains encrypted in this job, but is never attached over that edit.
        source = store._source(session, snapshot.source_id)
        if not _source_current(source, snapshot):
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)


def verification_password(snapshot):
    from core.gmail_crypto import decrypt_gmail_password
    with Session(store.engine) as session:
        job = _owned(session, snapshot)
        if not _source_current(session.get(store.GmailSource, snapshot.source_id), snapshot):
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
        if not job.pending_ciphertext:
            raise store.GmailStoreError("credentials_missing", _MESSAGES["credentials_missing"], 409)
        try:
            return decrypt_gmail_password(snapshot.email, job.pending_ciphertext)
        except Exception:
            raise store.GmailStoreError("crypto_error", _MESSAGES["crypto_error"], 503) from None


def finish_success(snapshot):
    with Session(store.engine) as session:
        _lock(session)
        job = _owned(session, snapshot)
        source = store._source(session, snapshot.source_id)
        if not _source_current(source, snapshot):
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
        if not job.pending_ciphertext:
            raise store.GmailStoreError("credentials_missing", _MESSAGES["credentials_missing"], 409)
        now = store.utcnow()
        changed = session.execute(update(store.GmailSource).where(store.GmailSource.id == snapshot.source_id,
            store.GmailSource.credential_revision == snapshot.revision, store.GmailSource.enabled.is_(True),
            store.GmailSource.app_password_ciphertext == snapshot.verification.app_password_ciphertext).values(
                app_password_ciphertext=job.pending_ciphertext, receive_verified=True,
                credential_revision=store.GmailSource.credential_revision + 1, status="ok", last_error="",
                last_checked_at=now, usability_status="usable", usability_method="imap",
                usability_checked_at=now, usability_error="", updated_at=now))
        if changed.rowcount != 1:
            raise store.GmailStoreError("source_changed", _MESSAGES["source_changed"], 409)
        job.status, job.stage, job.error_code = "succeeded", "completed", "verified"
        job.active_source_key, job.next_retry_at = None, None
        job.updated_at = now
        _clear_worker(job)
        session.add(job)
        session.commit()
        return _public(job)


def finish_failure(snapshot, code="failed"):
    with Session(store.engine) as session:
        _lock(session)
        job = _owned(session, snapshot)
        source = session.get(store.GmailSource, snapshot.source_id)
        safe = code if isinstance(code, str) and code in _MESSAGES else "failed"
        if not _source_current(source, snapshot):
            safe = "source_disabled" if source is not None and not source.enabled else "source_changed"
        uncertain = bool(job.create_started_at and not job.pending_ciphertext)
        if uncertain:
            safe = "credential_persist_failed" if safe == "credential_persist_failed" else "create_result_unknown"
        job.status = "needs_user" if uncertain or safe in _NEEDS_USER else "failed"
        job.stage = "needs_user" if job.status == "needs_user" else job.stage
        job.error_code, job.updated_at = safe, store.utcnow()
        job.next_retry_at = (store.utcnow() + timedelta(seconds=30 * max(1, job.automatic_attempts))
            if job.status == "failed" and safe in _TRANSIENT and job.automatic_attempts < MAX_AUTOMATIC_ATTEMPTS else None)
        _clear_worker(job)
        session.add(job)
        session.commit()
        return _public(job)


def _worker_dead(job):
    if job.worker_pid <= 0:
        return True
    try:
        import psutil
        process = psutil.Process(job.worker_pid)
        return bool(job.worker_started_at and abs(process.create_time() - job.worker_started_at) > 0.01)
    except ProcessLookupError:
        return True
    except Exception as exc:
        try:
            import psutil
            if isinstance(exc, psutil.NoSuchProcess):
                return True
        except ImportError:
            pass
        return False


def recover():
    if not _available():
        return {"recovered": 0, "needs_user": 0}
    counts = {"recovered": 0, "needs_user": 0}
    with Session(store.engine) as session:
        _lock(session)
        for job in session.exec(select(GmailAppPasswordJob).where(GmailAppPasswordJob.status == "running")).all():
            if _aware(job.lease_expires_at) and _aware(job.lease_expires_at) > store.utcnow() and not _worker_dead(job):
                continue
            uncertain = bool(job.create_started_at and not job.pending_ciphertext)
            job.status, job.stage = ("needs_user", "needs_user") if uncertain else ("interrupted", "imap" if job.pending_ciphertext else "interrupted")
            job.error_code = "create_result_unknown" if uncertain else "interrupted"
            job.next_retry_at = store.utcnow() if not uncertain and job.automatic_attempts < MAX_AUTOMATIC_ATTEMPTS else None
            job.updated_at = store.utcnow()
            _clear_worker(job)
            session.add(job)
            counts["needs_user" if uncertain else "recovered"] += 1
        session.commit()
    return counts
