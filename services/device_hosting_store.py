"""Independent, credential-free CPA/SUB hosting queue. No import-time DB writes."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import socket
import time
import uuid

from sqlalchemy import func, inspect, or_, text
from sqlmodel import Field, Session, SQLModel, select

from core.db import (GptBusinessAccountModel, GptBusinessAutomationPolicyModel, GptBusinessChildMembershipModel,
                     GptPlanAccountModel, GptPlanAccountOperationLeaseModel, engine, resolve_business_delivery_binding)

STEPS = ("check", "select", "invite", "oauth", "upload", "verify")
STEP_LABELS = dict(check="检查现有子号", select="检查可用账号", invite="邀请子号", oauth="获取 RT", upload="上传设备", verify="核验设备结果")
STATUS_LABELS = dict(pending="等待执行", running="执行中", waiting="等待条件", retry="等待重试", review="需要人工核对",
                     failed="执行失败", paused="已暂停", completed="已完成", cancelled="已取消")
TERMINAL = ("completed", "cancelled")
BROWSER_STEPS = ("invite", "oauth")
MUTATION_STEPS = ("invite", "oauth", "upload")
MAX_CONCURRENT = 3
BROWSER_CONCURRENT = 2
HARD_CONCURRENT_LIMIT = 10
MAX_ATTEMPTS = 3
CONTEXT_BOOL = {f"{step}_{suffix}" for step in MUTATION_STEPS for suffix in ("attempted", "confirmed")} | {"oauth_terminal_failed"}
CONTEXT_INT = {"candidate_child_id"}
CONTEXT_OBJECT = {"invite_failure", "invite_preflight_failure", "oauth_failure"}
MANUAL_OAUTH_CODES = frozenset({"browser_start_failed", "browser_timeout", "control_timeout", "password_rejected",
                               "phone_verification_not_authorized"})
INVITE_PREFLIGHT_CODES = frozenset({"invite_cooldown_active", "invite_quota_exhausted", "no_invitable_seat",
    "seat_type_unknown", "derived_seat_type_changed", "business_parent_busy", "gpt_pro_account_busy"})
CONTEXT_TEXT = {"candidate_email", "invite_started_at", "oauth_started_at", "upload_started_at", "remote_id", "membership_invited_at",
                "remote_user_id", "remote_invite_id", "verification_reason", "canonical_operation_id", "canonical_task_id",
                "presence_status", "quota_status", "verified_at", "credential_fingerprint", "oauth_failure_started_at"}


class DeviceHostingSettings(SQLModel, table=True):
    __tablename__ = "device_hosting_settings"
    device_ref: str = Field(primary_key=True)
    enabled: bool = False
    interval_seconds: int = 300
    next_run_at: float = 0
    revision: int = 0
    last_error: str = ""
    device_epoch: str = ""
    discovery_token: str = ""
    discovery_revision: int = 0
    heartbeat_at: float = 0
    worker_pid: int = 0
    worker_host: str = ""


class DeviceHostingMother(SQLModel, table=True):
    __tablename__ = "device_hosting_mothers"
    id: str = Field(primary_key=True)
    device_ref: str = Field(index=True)
    source_account_id: int = Field(index=True)
    payload_json: str = "{}"
    updated_at: float = 0


class DeviceHostingJob(SQLModel, table=True):
    __tablename__ = "device_hosting_jobs"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    identity_key: str = Field(index=True, unique=True)
    device_ref: str = Field(index=True)
    parent_account_id: int = Field(index=True)
    source_account_id: int = Field(index=True)
    parent_email: str
    child_id: int = Field(default=0, index=True)
    email: str = ""
    membership_id: int = 0
    seat_type: str = "default"
    kind: str = "existing"
    binding_revision: int = 0
    device_epoch: str = ""
    status: str = Field(default="pending", index=True)
    recheck_generation: str = ""
    step: str = "check"
    context_json: str = "{}"
    attempts: int = 0
    step_attempts: int = 0
    max_attempts: int = MAX_ATTEMPTS
    reconcile_attempts: int = 0
    reconcile_requested: bool = False
    pause_requested: bool = False
    error: str = ""
    next_run_at: float = 0
    worker_token: str = ""
    worker_pid: int = 0
    worker_host: str = ""
    heartbeat_at: float = 0
    version: int = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    completed_at: float = 0


class DeviceHostingStep(SQLModel, table=True):
    __tablename__ = "device_hosting_steps"
    id: int | None = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    step: str
    attempt: int
    reconcile: bool = False
    status: str = "running"
    error: str = ""
    started_at: float = Field(default_factory=time.time)
    finished_at: float = 0


class DeviceHostingLog(SQLModel, table=True):
    __tablename__ = "device_hosting_logs"
    id: int | None = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    step: str
    message: str
    created_at: float = Field(default_factory=time.time)


def init_tables():
    SQLModel.metadata.create_all(engine, tables=[model.__table__ for model in
        (DeviceHostingSettings, DeviceHostingMother, DeviceHostingJob, DeviceHostingStep, DeviceHostingLog)])


def _exists(session):
    return inspect(session.connection()).has_table(DeviceHostingSettings.__tablename__)


@contextmanager
def _write():
    with Session(engine) as session:
        if engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        else:
            # Serialize global resource admission, including an empty queue.
            session.execute(text("LOCK TABLE device_hosting_settings IN EXCLUSIVE MODE"))
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise


def _device(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:cpa|sub2api):[1-9][0-9]{0,9}", value):
        raise ValueError("设备标识无效")
    if int(value.split(":")[1]) > 2_147_483_647:
        raise ValueError("设备标识无效")
    return value


def _int(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 2_147_483_647:
        raise ValueError("账号或版本标识无效")
    return value


def _email(value, *, optional=False):
    if optional and value in (None, ""):
        return ""
    if not isinstance(value, str) or len(value) > 320 or not re.fullmatch(r"[^\s@]+@[^\s@]+", value.strip()):
        raise ValueError("账号邮箱标识无效")
    return value.strip().casefold()


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else ""


def safe_message(value):
    from api.gpt_plans import _sanitize_member_task_text
    message = _sanitize_member_task_text(str(value or ""))
    message = re.sub(r"(?i)(password|passwd|cookie|api[_ -]?key|totp[_ -]?secret|密钥|密码)\s*[:=：]\s*[^\s,;]+",
                     r"\1=[redacted]", message)
    return message[:1500]


def _settings(row, device_ref):
    return dict(device_ref=device_ref, enabled=bool(row.enabled) if row else False,
                interval_seconds=row.interval_seconds if row else 300,
                next_run_at=_iso(row.next_run_at) if row else "", revision=row.revision if row else 0,
                last_error=row.last_error if row else "", device_epoch=row.device_epoch if row else "")


def _current_device_epoch(device_ref):
    # Local configuration only; never probes a device. A replacement endpoint
    # must be explicitly enabled again rather than inheriting an old queue.
    from api.delivery_devices import _device_epoch
    provider, identity = _device(device_ref).split(":")
    return _device_epoch(provider, int(identity))


def get_settings(device_ref):
    device_ref = _device(device_ref)
    with Session(engine) as session:
        row = session.get(DeviceHostingSettings, device_ref) if _exists(session) else None
        return _settings(row, device_ref)


def save_settings(device_ref, enabled, interval_seconds=300):
    device_ref = _device(device_ref)
    if type(enabled) is not bool or type(interval_seconds) is not int or not 60 <= interval_seconds <= 3600:
        raise ValueError("托管开关须为布尔值，检查间隔须为 60–3600 秒")
    epoch = _current_device_epoch(device_ref) if enabled else ""
    with _write() as session:
        row = session.get(DeviceHostingSettings, device_ref) or DeviceHostingSettings(device_ref=device_ref)
        row.enabled, row.interval_seconds = enabled, interval_seconds
        if enabled:
            row.device_epoch = epoch
        row.revision += 1
        row.next_run_at = time.time() if enabled else 0
        session.add(row)
        return _settings(row, device_ref)


def list_settings(enabled_only=False):
    with Session(engine) as session:
        if not _exists(session):
            return []
        query = select(DeviceHostingSettings).order_by(DeviceHostingSettings.device_ref)
        if enabled_only:
            query = query.where(DeviceHostingSettings.enabled.is_(True))
        return [_settings(row, row.device_ref) for row in session.exec(query).all()]


def request_dispatch(device_ref):
    device_ref = _device(device_ref)
    with _write() as session:
        row = session.get(DeviceHostingSettings, device_ref)
        if not row or not row.enabled:
            raise ValueError("请先启用该设备托管")
        row.next_run_at = time.time()
        session.add(row)
    return {"ok": True, "message": "已请求托管检查；任务按母号串行执行"}


def _active_workers(session):
    return session.exec(select(DeviceHostingJob).where(DeviceHostingJob.worker_token != "")).all()


def has_active_workers(device_ref=None, source_account_id=None, *, session=None):
    if device_ref is not None:
        device_ref = _device(device_ref)
    if session is None:
        with Session(engine) as current:
            return has_active_workers(device_ref, source_account_id, session=current)
    if not _exists(session):
        return False
    query = select(DeviceHostingJob.id).where(DeviceHostingJob.worker_token != "")
    if device_ref is not None:
        query = query.where(DeviceHostingJob.device_ref == device_ref)
    if source_account_id is not None:
        query = query.where(DeviceHostingJob.source_account_id == _int(source_account_id, 1))
    return session.exec(query.limit(1)).first() is not None


def forget_device(device_ref, *, session=None):
    device_ref = _device(device_ref)
    if session is None:
        with Session(engine) as check:
            if not _exists(check):
                return False
        with _write() as current:
            return forget_device(device_ref, session=current)
    if not _exists(session):
        return False
    if has_active_workers(device_ref, session=session):
        raise RuntimeError("设备仍有执行中的托管任务")
    row = session.get(DeviceHostingSettings, device_ref)
    if row:
        row.enabled, row.next_run_at, row.discovery_token = False, 0, ""
        row.revision += 1
        session.add(row)
    for job in session.exec(select(DeviceHostingJob).where(DeviceHostingJob.device_ref == device_ref,
                                                          DeviceHostingJob.status.not_in(TERMINAL))).all():
        job.status, job.error = "cancelled", "设备已删除；保留托管步骤与历史，不再执行"
        job.updated_at = job.completed_at = time.time()
        session.add(job)
        _log(session, job, job.error)
    return True


def mother_is_hosted(source_account_id, *, session=None):
    source_account_id = _int(source_account_id, 1)
    if session is None:
        with Session(engine) as current:
            return mother_is_hosted(source_account_id, session=current)
    if not _exists(session):
        return False
    if has_active_workers(source_account_id=source_account_id, session=session):
        return True
    policy = session.get(GptBusinessAutomationPolicyModel, source_account_id)
    provider, target = resolve_business_delivery_binding(policy)
    settings = session.get(DeviceHostingSettings, f"{provider}:{target}") if provider and target else None
    return bool(settings and settings.enabled)


def _binding_problem(session, job):
    settings = session.get(DeviceHostingSettings, job.device_ref)
    if not settings or not settings.device_epoch or settings.device_epoch != job.device_epoch:
        return "设备连接版本已变化，请重新核对并开启托管"
    try:
        if _current_device_epoch(job.device_ref) != job.device_epoch:
            return "设备连接版本已变化，请重新核对并开启托管"
    except Exception:
        return "设备连接不可用，任务已停止"
    policy = session.get(GptBusinessAutomationPolicyModel, job.source_account_id)
    provider, target = resolve_business_delivery_binding(policy)
    if not policy or f"{provider}:{target}" != job.device_ref or policy.revision != job.binding_revision or policy.auto_rotation_enabled:
        return "母号设备绑定已变化，任务已停止；请核对原有步骤"
    source = session.get(GptBusinessAccountModel, job.source_account_id)
    parent = session.get(GptPlanAccountModel, job.parent_account_id)
    from services.device_hosting_capabilities import _parent_reason
    if (not source or not parent or parent.source_pool != "gpt_business" or parent.source_account_id != job.source_account_id
            or str(source.email).strip().casefold() != job.parent_email or str(parent.email).strip().casefold() != job.parent_email
            or not source.enabled or source.dangerous or not parent.enabled or parent.dangerous
            or _parent_reason(parent, source)):
        return "母号身份或可用状态已变化，任务已停止"
    return ""


def _mother(value):
    source_id = _int(value.get("source_account_id"), 1)
    return {"id": source_id, "source_account_id": source_id,
            "parent_account_id": _int(value.get("parent_account_id", 0)),
            "parent_email": _email(value.get("parent_email", value.get("email")), optional=True),
            "email": _email(value.get("parent_email", value.get("email")), optional=True),
            "note": safe_message(value.get("note", "")), "can_run": value.get("can_run") is True,
            "state": safe_message(value.get("state", "")), "reason": safe_message(value.get("reason", "")),
            "next_check_at": str(value.get("next_check_at") or "")[:50],
            "active_child_count": _int(value.get("active_child_count", 0)),
            "available_seats": value.get("available_seats") if type(value.get("available_seats")) is int else None,
            "binding_revision": _int(value.get("binding_revision", 0)),
            "device_epoch": str(value.get("device_epoch") or "")[:128]}


def _candidate(value, device_ref):
    step = value.get("step", "check")
    kind = str(value.get("kind", "existing"))
    if step not in STEPS or kind not in {"existing", "existing_child", "fill", "vacancy"}:
        raise ValueError("托管候选类型或步骤无效")
    child_id = _int(value.get("child_id", 0))
    membership = _int(value.get("membership_id", 0))
    email = _email(value.get("email", ""), optional=child_id == 0)
    if child_id and not membership:
        raise ValueError("已有子号缺少唯一成员关系")
    seat = value.get("seat_type", "default")
    if seat not in {"default", "prolite"}:
        raise ValueError("席位类型无效")
    epoch = value.get("device_epoch")
    if not isinstance(epoch, str) or not epoch or len(epoch) > 128:
        raise ValueError("设备版本证据缺失")
    generation = value.get("recheck_generation", "")
    if not isinstance(generation, str) or (generation and not re.fullmatch(r"[a-f0-9]{64}", generation)):
        raise ValueError("设备缺失快照版本证据无效")
    status = value.get("status", "pending")
    if status not in {"pending", "review"}:
        raise ValueError("托管初始状态无效")
    error = safe_message(value.get("error")) if status == "review" else ""
    if status == "review" and (not child_id or not error):
        raise ValueError("待核对子号缺少身份或原因")
    return dict(device_ref=device_ref, parent_account_id=_int(value.get("parent_account_id"), 1),
                source_account_id=_int(value.get("source_account_id"), 1), parent_email=_email(value.get("parent_email")),
                child_id=child_id, email=email, membership_id=membership, seat_type=seat, kind=kind,
                binding_revision=_int(value.get("binding_revision")), device_epoch=epoch, step=step, recheck_generation=generation,
                status=status, error=error)


def _uncertain(job):
    context = json.loads(job.context_json)
    return (any(context.get(f"{step}_attempted") and not context.get(f"{step}_confirmed") for step in MUTATION_STEPS)
            or (job.reconcile_requested and job.step in MUTATION_STEPS))


def _retire_changed_binding(session, job, now):
    if job.worker_token or job.status in TERMINAL:
        return
    policy = session.get(GptBusinessAutomationPolicyModel, job.source_account_id)
    provider, identity = resolve_business_delivery_binding(policy)
    try:
        epoch = _current_device_epoch(job.device_ref)
    except Exception:
        epoch = ""
    if policy and f"{provider}:{identity}" == job.device_ref and policy.revision == job.binding_revision and epoch == job.device_epoch:
        return
    if _uncertain(job):
        reason = "母号绑定或设备已变化，但旧目标操作结果未确认；请先人工核对旧目标，不重新提交"
        if job.status == "review" and job.error == reason:
            return
        job.status, job.error = "review", reason
    else:
        job.status, job.error = "cancelled", "母号绑定或设备已变化；旧任务无未确认副作用，已取消并保留步骤历史"
        job.completed_at, job.next_run_at = now, 0
    job.updated_at, job.version = now, job.version + 1
    session.add(job)
    _log(session, job, job.error)


def sync_discovery(device_ref, result, *, token=None):
    device_ref = _device(device_ref)
    mothers = [_mother(value) for value in result.get("mothers", [])]
    candidates = [_candidate(value, device_ref) for value in result.get("candidates", [])]
    if len(mothers) > 500 or len(candidates) > 1000:
        raise ValueError("单次托管发现数量超出范围")
    now = time.time()
    with _write() as session:
        settings = session.get(DeviceHostingSettings, device_ref)
        if not settings or not settings.enabled:
            return {"ok": True, "created": 0}
        if token is not None and (settings.discovery_token != token or settings.discovery_revision != settings.revision):
            return {"ok": False, "created": 0}
        for old in session.exec(select(DeviceHostingMother).where(DeviceHostingMother.device_ref == device_ref)).all():
            session.delete(old)
        session.flush()
        for value in mothers:
            session.add(DeviceHostingMother(id=f"{device_ref}:{value['source_account_id']}", device_ref=device_ref,
                        source_account_id=value["source_account_id"], payload_json=json.dumps(value, ensure_ascii=False), updated_at=now))
        created = 0
        for value in candidates:
            # One open vacancy per mother/seat. Existing members are fixed by
            # their persistent membership, never duplicated after completion.
            existing = session.exec(select(DeviceHostingJob).where(
                                DeviceHostingJob.source_account_id == value["source_account_id"])).all()
            for old in existing:
                _retire_changed_binding(session, old, now)
            if value["child_id"]:
                same = [job for job in existing if job.child_id == value["child_id"] and job.membership_id == value["membership_id"]]
                def blocks(job):
                    if job.status not in TERMINAL or (job.status == "cancelled" and _uncertain(job)):
                        return True
                    same_target = (job.device_ref == device_ref and job.device_epoch == value["device_epoch"]
                                   and job.binding_revision == value["binding_revision"])
                    return (job.status == "completed" and same_target
                            and (not value["recheck_generation"] or job.recheck_generation == value["recheck_generation"]))
                if any(blocks(job) for job in same):
                    continue
                key = f"{device_ref}:{value['source_account_id']}:{value['membership_id']}:{value['child_id']}:{uuid.uuid4().hex}"
            else:
                if any(job.status not in TERMINAL and (job.child_id == 0 or job.seat_type == value["seat_type"]) for job in existing):
                    continue
                key = f"{device_ref}:{value['source_account_id']}:{value['seat_type']}:{uuid.uuid4().hex}"
            job = DeviceHostingJob(**value, identity_key=hashlib.sha256(key.encode()).hexdigest(), created_at=now, updated_at=now)
            if _binding_problem(session, job):
                continue
            session.add(job)
            session.flush()
            for skipped in STEPS[:STEPS.index(job.step)]:
                session.add(DeviceHostingStep(job_id=job.id, step=skipped, attempt=0, status="skipped", started_at=now, finished_at=now))
            _log(session, job, job.error or "已加入独立设备托管队列；不会删除或自动更换旧子号")
            created += 1
        settings.next_run_at, settings.last_error = now + settings.interval_seconds, ""
        session.add(settings)
        return {"ok": True, "created": created}


def claim_discovery():
    now = time.time()
    with _write() as session:
        scans = session.exec(select(DeviceHostingSettings).where(DeviceHostingSettings.discovery_token != "")).all()
        if len(scans) + len(_active_workers(session)) >= min(MAX_CONCURRENT, HARD_CONCURRENT_LIMIT):
            return None
        rows = session.exec(select(DeviceHostingSettings).where(DeviceHostingSettings.enabled.is_(True),
                    DeviceHostingSettings.next_run_at <= now, DeviceHostingSettings.discovery_token == "")
                    .order_by(DeviceHostingSettings.next_run_at, DeviceHostingSettings.device_ref)).all()
        if not rows:
            return None
        row = rows[0]
        try:
            current_epoch = _current_device_epoch(row.device_ref)
        except Exception:
            current_epoch = ""
        if not row.device_epoch or current_epoch != row.device_epoch:
            row.enabled, row.next_run_at = False, 0
            row.last_error = "设备已删除或连接配置已变化，请核对后重新开启托管"
            row.revision += 1
            session.add(row)
            return None
        row.discovery_token, row.discovery_revision = uuid.uuid4().hex, row.revision
        row.heartbeat_at, row.worker_host, row.worker_pid = now, socket.gethostname(), 0
        row.next_run_at = now + row.interval_seconds
        session.add(row)
        return dict(device_ref=row.device_ref, token=row.discovery_token)


def discovery_heartbeat(device_ref, token, pid=0):
    with _write() as session:
        row = session.get(DeviceHostingSettings, device_ref)
        if not row or not token or row.discovery_token != token:
            return False
        row.heartbeat_at = time.time()
        if pid:
            row.worker_pid = pid
        session.add(row)
        return True


def finish_discovery(device_ref, token, error=""):
    with _write() as session:
        row = session.get(DeviceHostingSettings, device_ref)
        if not row or not token or row.discovery_token != token:
            return False
        row.discovery_token, row.worker_pid = "", 0
        row.last_error = safe_message(error)
        session.add(row)
        return True


def _log(session, job, message):
    # Capabilities emit only sanitized public reasons, never raw browser output.
    session.add(DeviceHostingLog(job_id=job.id, step=job.step, message=safe_message(message)))


def _public(job, action_problem=""):
    context = json.loads(job.context_json)
    result = {key: getattr(job, key) for key in ("id", "device_ref", "parent_account_id", "source_account_id", "parent_email",
                "child_id", "email", "membership_id", "seat_type", "kind", "binding_revision", "device_epoch", "status",
                "step", "attempts", "step_attempts", "max_attempts", "error", "version")} | {
        "status_label": STATUS_LABELS.get(job.status, job.status), "step_label": STEP_LABELS.get(job.step, job.step),
        "paused": job.pause_requested or job.status == "paused", "can_pause": job.status not in (*TERMINAL, "paused") and not job.pause_requested,
        "can_resume": job.status == "paused", "can_retry": job.status in {"review", "failed", "retry"},
        **{key: _iso(getattr(job, key)) for key in ("next_run_at", "created_at", "updated_at", "completed_at")}}
    result["email"] = job.email or context.get("candidate_email", "")
    result["action_blocked_reason"] = action_problem
    result["retry_mode"] = "reconcile" if job.reconcile_requested else "execute"
    result["retry_reason"] = ("请先在子号操作中人工处理；此处仅核对已保存结果，不重新邀请、获取 RT 或上传"
                              if job.reconcile_requested else "人工重试将继续当前步骤，仍遵守账号身份和共享租约检查")
    if action_problem:
        result["can_retry"] = result["can_resume"] = False
    return result


def _worker(job):
    return {**_public(job), "email": job.email, "context": json.loads(job.context_json), "worker_token": job.worker_token,
            "operation_id": f"device-hosting-{job.id}", "reconcile_requested": job.reconcile_requested}


def _recheck_local_invite_quota_waits(session, now):
    """Expire only proven local-quota sleeps; never shorten remote cooldowns.

    Older queued rows may retain a deadline calculated under a previous quota
    window. Waking their preflight check is safe only with the closed evidence
    that no invite was sent. Current capability checks still own admission.
    """
    candidates = session.exec(select(DeviceHostingJob).where(
        DeviceHostingJob.step == "invite", DeviceHostingJob.status == "waiting",
        DeviceHostingJob.next_run_at > now, DeviceHostingJob.worker_token == "",
        DeviceHostingJob.worker_pid == 0, DeviceHostingJob.pause_requested == False,
        DeviceHostingJob.reconcile_requested == False,
    )).all()
    for job in candidates:
        try:
            context = json.loads(job.context_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(context, dict):
            continue
        preflight = context.get("invite_preflight_failure")
        if (not isinstance(preflight, dict) or set(preflight) != {"code", "remote_invite_sent"}
                or preflight.get("code") != "invite_quota_exhausted"
                or preflight.get("remote_invite_sent") is not False
                or context.get("invite_attempted") is not False
                or context.get("invite_started_at") or context.get("invite_confirmed")
                or context.get("canonical_operation_id") != f"device-hosting-{job.id}"
                or job.child_id or job.membership_id
                or type(job.updated_at) not in {int, float}
                or not math.isfinite(job.updated_at) or not 0 < job.updated_at <= now):
            continue
        settings = session.get(DeviceHostingSettings, job.device_ref)
        source = session.get(GptBusinessAccountModel, job.source_account_id)
        if not settings or not settings.enabled or source is None:
            continue
        if session.exec(select(GptBusinessChildMembershipModel.id).where(
                GptBusinessChildMembershipModel.operation_id == context["canonical_operation_id"]).limit(1)).first() is not None:
            continue
        until = source.invite_cooldown_until
        if until is not None:
            until = until if until.tzinfo is not None else until.replace(tzinfo=timezone.utc)
            if until.timestamp() > now:
                continue
        deadline = max(now, job.updated_at + 300)
        if job.next_run_at <= deadline:
            continue
        job.next_run_at = deadline
        job.version += 1
        session.add(job)
        _log(session, job, "本地邀请额度等待已改为定期重新核验；仍需重新检查当前额度、席位及邀请冷却")


def claim_next():
    now = time.time()
    with _write() as session:
        active = _active_workers(session)
        scans = session.exec(select(func.count()).select_from(DeviceHostingSettings)
                             .where(DeviceHostingSettings.discovery_token != "")).one()
        if len(active) + scans >= min(MAX_CONCURRENT, HARD_CONCURRENT_LIMIT):
            return None
        _recheck_local_invite_quota_waits(session, now)
        source_ids = {job.source_account_id for job in active}
        browsers = sum(job.step in BROWSER_STEPS for job in active)
        query = select(DeviceHostingJob).where(DeviceHostingJob.status.in_(("pending", "waiting", "retry")),
                 DeviceHostingJob.next_run_at <= now).order_by(DeviceHostingJob.updated_at, DeviceHostingJob.id)
        for job in session.exec(query).all():
            settings = session.get(DeviceHostingSettings, job.device_ref)
            if not settings or not settings.enabled or job.source_account_id in source_ids:
                continue
            problem = _binding_problem(session, job)
            if problem:
                _retire_changed_binding(session, job, now)
                if job.status == "cancelled":
                    continue
                if _uncertain(job) and "旧目标操作结果未确认" in job.error:
                    continue
                job.status, job.error, job.updated_at = "review", problem, now
                session.add(job)
                _log(session, job, problem)
                continue
            if job.step in BROWSER_STEPS and browsers >= BROWSER_CONCURRENT:
                continue
            if job.pause_requested:
                job.status = "paused"
                session.add(job)
                continue
            if (job.reconcile_requested and job.reconcile_attempts >= MAX_ATTEMPTS) or (not job.reconcile_requested and job.step_attempts >= job.max_attempts):
                job.status, job.error = "review", "本步骤已达到重试上限，请人工核对后继续"
                session.add(job)
                continue
            job.status, job.worker_token = "running", uuid.uuid4().hex
            job.worker_host, job.worker_pid = socket.gethostname(), 0
            job.heartbeat_at = job.updated_at = now
            job.version += 1
            job.attempts += 1
            if job.reconcile_requested:
                job.reconcile_attempts += 1
            else:
                job.step_attempts += 1
            session.add(job)
            session.add(DeviceHostingStep(job_id=job.id, step=job.step, attempt=job.attempts,
                                           reconcile=job.reconcile_requested, started_at=now))
            _log(session, job, ("核对上次执行结果：" if job.reconcile_requested else "开始：") + STEP_LABELS[job.step])
            return _worker(job)
    return None


def _owned(session, job_id, token):
    job = session.get(DeviceHostingJob, job_id)
    if not token or not job or job.worker_token != token or job.status != "running":
        raise RuntimeError("托管任务已不属于当前执行者")
    return job


def worker_job(job_id, token):
    with Session(engine) as session:
        job = _owned(session, job_id, token)
        if _binding_problem(session, job):
            raise RuntimeError("母号设备绑定或身份已变化")
        return _worker(job)


def heartbeat(job_id, token, pid=0):
    with _write() as session:
        try:
            job = _owned(session, job_id, token)
        except RuntimeError:
            return False
        job.heartbeat_at = time.time()
        if pid:
            job.worker_pid = pid
        session.add(job)
        return True


def append_log(job_id, token, message):
    with _write() as session:
        job = _owned(session, job_id, token)
        _log(session, job, message)


def _updates(job, values, session=None):
    if not isinstance(values, dict) or set(values) - {"child_id", "email", "membership_id", "seat_type", "context"}:
        raise ValueError("托管检查点包含未允许字段")
    child = _int(values.get("child_id", job.child_id))
    email = _email(values.get("email", job.email), optional=child == 0)
    membership = _int(values.get("membership_id", job.membership_id))
    seat = values.get("seat_type", job.seat_type)
    if seat not in {"default", "prolite"} or (seat != job.seat_type and (job.child_id or not child or not membership)):
        raise ValueError("已确认席位身份不可更改")
    if (job.child_id and child != job.child_id) or (job.email and email != job.email) or (job.membership_id and membership != job.membership_id):
        raise ValueError("托管任务账号身份不可更改")
    context = values.get("context", {})
    if not isinstance(context, dict) or set(context) - CONTEXT_BOOL - CONTEXT_TEXT - CONTEXT_INT - CONTEXT_OBJECT:
        raise ValueError("托管上下文包含未允许字段")
    prior = json.loads(job.context_json)
    context = dict(context)
    failure = None
    if "invite_failure" in context:
        from services.business_invite_login_diagnostics import normalize_prelogin_failure
        failure = normalize_prelogin_failure(context["invite_failure"])
        if not failure:
            raise ValueError("邀请前失败证据无效")
        context["invite_failure"] = {"code": "business_child_prelogin_failed", **failure}
    preflight = context.get("invite_preflight_failure")
    if "invite_preflight_failure" in context:
        if (not isinstance(preflight, dict) or set(preflight) != {"code", "remote_invite_sent"}
                or preflight.get("code") not in INVITE_PREFLIGHT_CODES or preflight.get("remote_invite_sent") is not False):
            raise ValueError("邀请前条件阻断证据无效")
    if any(key in context for key in ("oauth_failure", "oauth_terminal_failed", "oauth_failure_started_at")):
        from services.chatgpt_oauth_failure import normalize_oauth_failure
        from services.device_hosting_capabilities import _date
        oauth_failure = normalize_oauth_failure(context.get("oauth_failure"))
        started = _date(prior.get("oauth_started_at"))
        if (job.step != "oauth" or prior.get("oauth_attempted") is not True or prior.get("oauth_confirmed")
                or context.get("oauth_terminal_failed") is not True or not oauth_failure or oauth_failure["terminal"] is not True
                or started is None or started > datetime.now(timezone.utc)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", str(context.get("canonical_task_id") or ""))
                or ("oauth_failure_started_at" in context and context["oauth_failure_started_at"] != prior.get("oauth_started_at"))):
            raise ValueError("OAuth 明确终态失败证据不完整")
        context["oauth_failure"] = oauth_failure
        context["oauth_failure_started_at"] = prior["oauth_started_at"]
    rearm = bool(
        job.step == "invite" and not child and not membership and not prior.get("invite_confirmed")
        and prior.get("invite_attempted") is True and context.get("invite_attempted") is False
        and context.get("invite_started_at") == "" and ((failure and failure["retryable"] is True) or preflight)
        and prior.get("canonical_operation_id") == f"device-hosting-{job.id}"
        and session is not None
    )
    if rearm and session.exec(select(GptBusinessChildMembershipModel.id).where(
            GptBusinessChildMembershipModel.operation_id == prior["canonical_operation_id"]).limit(1)).first() is not None:
        rearm = False
    for key, value in context.items():
        if key in CONTEXT_BOOL:
            if type(value) is not bool or (prior.get(key) is True and value is not True and not (key == "invite_attempted" and rearm)):
                raise ValueError("已记录的副作用证据不可清除")
        elif key in CONTEXT_OBJECT:
            continue
        elif key in CONTEXT_INT:
            _int(value, 1)
        elif key == "candidate_email":
            _email(value)
        elif key == "credential_fingerprint":
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError("凭据版本证据无效")
        elif not isinstance(value, str) or len(value) > 1000:
            raise ValueError("托管上下文字段无效")
    job.child_id, job.email, job.membership_id, job.seat_type = child, email, membership, seat
    job.context_json = json.dumps({**prior, **{k: safe_message(v) if k in CONTEXT_TEXT else v for k, v in context.items()}}, ensure_ascii=False)
    if rearm:
        job.reconcile_requested = False


def checkpoint(job_id, token, values):
    with _write() as session:
        job = _owned(session, job_id, token)
        if _binding_problem(session, job):
            raise RuntimeError("母号设备绑定或身份已变化")
        _updates(job, values, session)
        job.updated_at, job.version = time.time(), job.version + 1
        session.add(job)
        return True


def _close_step(session, job, status, error, now):
    row = session.exec(select(DeviceHostingStep).where(DeviceHostingStep.job_id == job.id, DeviceHostingStep.status == "running")
                       .order_by(DeviceHostingStep.id.desc())).first()
    if row:
        row.status, row.error, row.finished_at = status, error, now
        session.add(row)


def _completion_problem(session, job):
    """Fence a remote success against current canonical state in this write transaction.

    No second remote call, credential DTO, or lease stealing. An in-progress
    canonical operation prevents completion even before it updates membership.
    """
    from services.device_hosting_capabilities import _credential_fingerprint, _date, _nv_reason, _protected_membership

    context = json.loads(job.context_json)
    verified = _date(context.get("verified_at"))
    cycle = _date(context.get("membership_invited_at"))
    now = datetime.now(timezone.utc)
    if (context.get("presence_status") != "confirmed" or context.get("quota_status") != "valid"
            or not str(context.get("remote_id") or "").strip() or verified is None or cycle is None
            or not cycle <= verified <= now):
        return "最终设备存在、额度或邀请周期证据不完整，请重新核对"
    if not inspect(session.connection()).has_table(GptPlanAccountOperationLeaseModel.__tablename__):
        return "共享账号操作租约表不可用，无法确认最终状态"
    for account_id in (job.parent_account_id, job.child_id):
        lease = session.get(GptPlanAccountOperationLeaseModel, account_id)
        if lease and (_date(lease.expires_at) is None or _date(lease.expires_at) > now):
            return "母号或子号仍有其他操作正在执行，请稍后重新核对设备结果"
    member = session.get(GptBusinessChildMembershipModel, job.membership_id)
    child = session.get(GptPlanAccountModel, job.child_id)
    if (not member or not child or member.ended_at is not None or member.source != "pool"
            or member.business_account_id != job.source_account_id or member.pro_account_id != job.child_id
            or child.business_parent_id != job.source_account_id or not job.email
            or str(child.email).strip().casefold() != job.email or str(member.email).strip().casefold() != job.email
            or _date(member.invited_at) != cycle or member.seat_type != job.seat_type
            or member.intent_remote_started or str(member.end_reason or "").startswith("pending:")
            or not child.enabled or child.dangerous or child.policy_warning or str(child.refund_status or "")
            or child.catalog_category == "refunded"):
        return "子号成员身份、邀请周期或账号状态已变化，未记为完成"
    if _protected_membership(member):
        return "子号已有上架或售出保护记录，未记为完成"
    problem = _nv_reason(session, job.parent_account_id, job.source_account_id, job.child_id, job.membership_id)
    if problem:
        return problem
    duplicates = session.exec(select(GptBusinessChildMembershipModel.id).where(
        GptBusinessChildMembershipModel.ended_at.is_(None),
        or_(GptBusinessChildMembershipModel.pro_account_id == job.child_id,
            func.lower(func.trim(GptBusinessChildMembershipModel.email)) == job.email))).all()
    if duplicates != [job.membership_id]:
        return "子号存在重复归属记录，未记为完成"
    acquired = _date(child.codex_rt_acquired_at)
    if (not all(str(getattr(child, key) or "").strip() for key in ("codex_access_token", "codex_refresh_token", "codex_id_token"))
            or acquired is None or not cycle <= acquired <= verified
            or context.get("credential_fingerprint") != _credential_fingerprint(child)):
        return "子号凭据或凭据版本已变化，请重新核对设备结果"
    try:
        extra = json.loads(child.extra_json or "{}")
    except (ValueError, TypeError):
        return "子号设备关联记录格式无效，未记为完成"
    if not isinstance(extra, dict):
        return "子号设备关联记录格式无效，未记为完成"
    provider, target = job.device_ref.split(":")
    remote_id = context["remote_id"]
    if provider == "cpa":
        linked = (extra.get("cpa_synced") is True and str(extra.get("cpa_synced_to_id") or "") == target
                  and str(extra.get("cpa_auth_name") or "") == remote_id
                  and remote_id == f"{child.email.strip()}.json"
                  and not any(extra.get(key) for key in ("cpa_sync_pending", "cpa_sync_compensation_pending",
                                                        "cpa_disabled", "cpa_monitor_suppressed")))
    else:
        linked = (str(extra.get("sub2api_device_id") or "") == target
                  and str(extra.get("sub2api_remote_account_id") or "") == remote_id
                  and not extra.get("sub2api_remote_missing") and not extra.get("sub2api_sync_pending"))
    return "" if linked else "子号的当前设备关联已变化，请重新核对设备结果"


def _manual_oauth_retry_allowed(session, job):
    """An explicit click may rearm only an exact non-spending terminal attempt."""
    from services.chatgpt_oauth_failure import normalize_oauth_failure
    from services.device_hosting_capabilities import _date, _nv_reason, _protected_membership
    context = json.loads(job.context_json)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    started, cycle = _date(context.get("oauth_started_at")), _date(context.get("membership_invited_at"))
    if (job.step != "oauth" or job.worker_token or job.status not in {"review", "failed", "retry"}
            or context.get("oauth_attempted") is not True or context.get("oauth_confirmed")
            or context.get("oauth_terminal_failed") is not True or not failure or failure["code"] not in MANUAL_OAUTH_CODES
            or not failure["terminal"] or failure["callback_received"] or failure["exchange_started"] or failure["charge_possible"]
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", str(context.get("canonical_task_id") or ""))
            or started is None or cycle is None or not cycle <= started <= datetime.now(timezone.utc)
            or context.get("oauth_failure_started_at") != context.get("oauth_started_at")):
        return False
    if not inspect(session.connection()).has_table(GptPlanAccountOperationLeaseModel.__tablename__):
        return False
    for account_id in (job.parent_account_id, job.child_id):
        lease = session.get(GptPlanAccountOperationLeaseModel, account_id)
        if lease and (_date(lease.expires_at) is None or _date(lease.expires_at) > datetime.now(timezone.utc)):
            return False
    child = session.get(GptPlanAccountModel, job.child_id)
    member = session.get(GptBusinessChildMembershipModel, job.membership_id)
    if (not child or not member or member.ended_at is not None or member.source != "pool"
            or member.business_account_id != job.source_account_id or member.pro_account_id != job.child_id
            or child.business_parent_id != job.source_account_id or not job.email
            or str(child.email).strip().casefold() != job.email or str(member.email).strip().casefold() != job.email
            or _date(member.invited_at) != cycle or member.seat_type != job.seat_type or member.intent_remote_started
            or str(member.end_reason or "").startswith("pending:") or _protected_membership(member)
            or not child.enabled or child.dangerous or child.policy_warning or str(child.refund_status or "")
            or child.catalog_category == "refunded"
            or any(str(getattr(child, key) or "").strip() for key in ("codex_access_token", "codex_refresh_token", "codex_id_token"))):
        return False
    if _nv_reason(session, job.parent_account_id, job.source_account_id, job.child_id, job.membership_id):
        return False
    duplicates = session.exec(select(GptBusinessChildMembershipModel.id).where(GptBusinessChildMembershipModel.ended_at.is_(None),
        or_(GptBusinessChildMembershipModel.pro_account_id == job.child_id,
            func.lower(func.trim(GptBusinessChildMembershipModel.email)) == job.email))).all()
    return duplicates == [job.membership_id]


def _retry_public(session, job, problem=""):
    result = _public(job, problem)
    if not problem and _manual_oauth_retry_allowed(session, job):
        result.update(retry_mode="execute", retry_reason="本次 OAuth 已明确失败且未回调、兑换或收费；人工重试可重新获取 RT，不申请短信号码")
    return result


def finish_step(job_id, token, result):
    now = time.time()
    with _write() as session:
        job = _owned(session, job_id, token)
        outcome = result.get("outcome")
        if outcome not in {"advance", "wait", "retry", "review", "failed"}:
            raise ValueError("托管步骤结果无效")
        _updates(job, result.get("updates", {}), session)
        problem = _binding_problem(session, job)
        if not problem and outcome == "advance" and result.get("next_step") == "completed":
            problem = _completion_problem(session, job)
        error = problem or safe_message(result.get("error"))
        if problem:
            outcome = "review"
        old_step = job.step
        if outcome == "advance":
            next_step = result.get("next_step")
            if next_step == "completed":
                if old_step != "verify":
                    raise ValueError("只有远端核验步骤可完成托管任务")
                job.status, job.completed_at = "completed", now
            elif next_step in STEPS and STEPS.index(next_step) > STEPS.index(old_step):
                for skipped in STEPS[STEPS.index(old_step) + 1:STEPS.index(next_step)]:
                    session.add(DeviceHostingStep(job_id=job.id, step=skipped, attempt=0, status="skipped", started_at=now, finished_at=now))
                job.step, job.status = next_step, "pending"
            else:
                raise ValueError("托管步骤不能回退或重复提交")
            job.step_attempts, job.reconcile_attempts, job.max_attempts = 0, 0, MAX_ATTEMPTS
            job.reconcile_requested, job.next_run_at = False, 0
        elif outcome in {"wait", "retry"}:
            delay = result.get("delay", 60)
            if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not 1 <= delay <= 604800:
                raise ValueError("托管等待时间无效")
            job.status = "waiting" if outcome == "wait" else "retry"
            job.next_run_at = now + delay
            if outcome == "wait":
                # A quota/cooldown wait is not a failed network execution.
                if job.reconcile_requested:
                    job.reconcile_attempts = max(0, job.reconcile_attempts - 1)
                else:
                    job.step_attempts = max(0, job.step_attempts - 1)
            context = json.loads(job.context_json)
            if old_step in MUTATION_STEPS and context.get(f"{old_step}_attempted"):
                job.reconcile_requested = True
            if outcome == "retry" and ((job.reconcile_requested and job.reconcile_attempts >= MAX_ATTEMPTS)
                                        or (not job.reconcile_requested and job.step_attempts >= job.max_attempts)):
                job.status = "failed"
        else:
            job.status = outcome
            if old_step in MUTATION_STEPS and json.loads(job.context_json).get(f"{old_step}_attempted") is True:
                job.reconcile_requested = True
        if job.pause_requested and job.status not in TERMINAL:
            job.status = "paused"
        job.error, job.updated_at, job.version = error, now, job.version + 1
        _close_step(session, job, "completed" if outcome == "advance" else job.status, error, now)
        job.worker_token, job.worker_pid = "", 0
        session.add(job)
        _log(session, job, error or STATUS_LABELS[job.status])
        return True


def mark_interrupted(job_id, token, reason="步骤执行中断；先核对已有结果，不重复提交"):
    with _write() as session:
        try:
            job = _owned(session, job_id, token)
        except RuntimeError:
            return False
        now = time.time()
        job.reconcile_requested = True
        job.status = "paused" if job.pause_requested else "retry"
        if job.reconcile_attempts >= MAX_ATTEMPTS:
            job.status = "review"
        job.next_run_at, job.error, job.updated_at = now + 60, safe_message(reason), now
        _close_step(session, job, "interrupted", job.error, now)
        _log(session, job, job.error)
        job.worker_token, job.worker_pid = "", 0
        job.version += 1
        session.add(job)
        return True


def recover_stale(alive):
    with Session(engine) as session:
        if not _exists(session):
            return
        jobs = _active_workers(session)
        scans = session.exec(select(DeviceHostingSettings).where(DeviceHostingSettings.discovery_token != "")).all()
    now = time.time()
    for job in jobs:
        if job.worker_host == socket.gethostname() and now - job.heartbeat_at > 90 and not (job.worker_pid and alive(job.worker_pid)):
            mark_interrupted(job.id, job.worker_token)
    for row in scans:
        if row.worker_host == socket.gethostname() and now - row.heartbeat_at > 90 and not (row.worker_pid and alive(row.worker_pid)):
            finish_discovery(row.device_ref, row.discovery_token, "托管发现进程中断，将在下次检查时重试")


def job_action(device_ref, job_id, action):
    device_ref = _device(device_ref)
    if action not in {"retry", "pause", "resume"}:
        raise ValueError("任务操作无效")
    with _write() as session:
        job = session.get(DeviceHostingJob, job_id)
        if not job or job.device_ref != device_ref:
            raise KeyError("托管任务不存在")
        if job.status in TERMINAL:
            raise RuntimeError("已完成或取消的任务不可重新执行")
        if action == "pause":
            job.pause_requested = True
            if job.status != "running":
                job.status = "paused"
        else:
            if (action == "resume" and job.status != "paused") or (action == "retry" and job.status not in {"failed", "review", "retry"}):
                raise RuntimeError("当前任务状态不支持此操作")
            problem = _binding_problem(session, job)
            if problem:
                raise RuntimeError(problem)
            manual_oauth = action == "retry" and _manual_oauth_retry_allowed(session, job)
            if manual_oauth:
                context = json.loads(job.context_json)
                for key in ("oauth_terminal_failed", "oauth_failure", "canonical_task_id", "oauth_failure_started_at"):
                    context.pop(key, None)
                context.update(oauth_attempted=False, oauth_started_at="")
                job.context_json = json.dumps(context, ensure_ascii=False)
                job.reconcile_requested = False
                _log(session, job, "人工授权重新获取 RT：上一轮已明确终态且无回调、兑换或收费；旧失败授权已消费，不申请短信号码")
            job.pause_requested, job.status, job.next_run_at = False, "pending", 0
            if job.reconcile_requested:
                job.reconcile_attempts = max(0, job.reconcile_attempts - 1)
            job.max_attempts = max(job.max_attempts, job.step_attempts + 1)
        job.updated_at, job.version = time.time(), job.version + 1
        session.add(job)
        _log(session, job, {"pause": "已请求暂停；已执行的步骤不会撤销", "retry": "人工请求重试；先核对不确定结果", "resume": "人工请求继续托管任务"}[action])
        return {"ok": True, "job": _retry_public(session, job, _binding_problem(session, job))}


def list_jobs(device_ref, parent_account_id=None, scope="current", page=1, page_size=10):
    device_ref = _device(device_ref)
    if scope not in {"current", "history", "all"} or type(page) is not int or page < 1 or type(page_size) is not int or not 1 <= page_size <= 100:
        raise ValueError("任务列表参数无效")
    with Session(engine) as session:
        if not _exists(session):
            return dict(items=[], total=0, page=page, page_size=page_size)
        filters = [DeviceHostingJob.device_ref == device_ref]
        if parent_account_id is not None:
            filters.append(DeviceHostingJob.parent_account_id == _int(parent_account_id, 1))
        if scope != "all":
            filters.append(DeviceHostingJob.status.in_(TERMINAL) if scope == "history" else DeviceHostingJob.status.not_in(TERMINAL))
        total = session.exec(select(func.count()).select_from(DeviceHostingJob).where(*filters)).one()
        jobs = session.exec(select(DeviceHostingJob).where(*filters).order_by(DeviceHostingJob.created_at.desc(), DeviceHostingJob.id.desc())
                            .offset((page - 1) * page_size).limit(page_size)).all()
        histories = session.exec(select(DeviceHostingStep).where(DeviceHostingStep.job_id.in_([job.id for job in jobs]))
                                 .order_by(DeviceHostingStep.id)).all() if jobs else []
        problems = {}
        for job in jobs:
            key = (job.parent_account_id, job.source_account_id, job.parent_email, job.device_epoch, job.binding_revision)
            if key not in problems:
                problems[key] = _binding_problem(session, job)
        return dict(items=[{**_retry_public(session, job, problems[(job.parent_account_id, job.source_account_id, job.parent_email, job.device_epoch, job.binding_revision)]),
                           "steps": _step_summary([row for row in histories if row.job_id == job.id])}
                           for job in jobs], total=total, page=page, page_size=page_size)


def _step_summary(history):
    steps = []
    for name in STEPS:
        matching = [row for row in history if row.step == name]
        last = matching[-1] if matching else None
        steps.append(dict(step=name, label=STEP_LABELS[name], status=last.status if last else "pending",
                          attempts=sum(row.attempt > 0 for row in matching), error=last.error if last else "",
                          started_at=_iso(matching[0].started_at) if matching else "", finished_at=_iso(last.finished_at) if last else ""))
    return steps


def get_job(device_ref, job_id):
    device_ref = _device(device_ref)
    with Session(engine) as session:
        job = session.get(DeviceHostingJob, job_id) if _exists(session) else None
        if not job or job.device_ref != device_ref:
            raise KeyError("托管任务不存在")
        history = session.exec(select(DeviceHostingStep).where(DeviceHostingStep.job_id == job_id).order_by(DeviceHostingStep.id)).all()
        logs = session.exec(select(DeviceHostingLog).where(DeviceHostingLog.job_id == job_id).order_by(DeviceHostingLog.id)).all()
        return {**_retry_public(session, job, _binding_problem(session, job)), "steps": _step_summary(history),
                "step_history": [dict(id=row.id, step=row.step, attempt=row.attempt, reconcile=row.reconcile, status=row.status,
                                      error=row.error, started_at=_iso(row.started_at), finished_at=_iso(row.finished_at)) for row in history],
                "logs": [dict(id=row.id, step=row.step, message=row.message, created_at=_iso(row.created_at)) for row in logs]}


def overview(device_ref, mothers=None):
    device_ref = _device(device_ref)
    with Session(engine) as session:
        present = _exists(session)
        settings = session.get(DeviceHostingSettings, device_ref) if present else None
        jobs = session.exec(select(DeviceHostingJob).where(DeviceHostingJob.device_ref == device_ref)).all() if present else []
        if mothers is None:
            mothers = [json.loads(row.payload_json) for row in session.exec(select(DeviceHostingMother).where(
                       DeviceHostingMother.device_ref == device_ref)).all()] if present else []
        mothers = [_mother(value) for value in mothers]
        for mother in mothers:
            own = [job for job in jobs if job.source_account_id == mother["source_account_id"]]
            active = [job for job in own if job.status not in TERMINAL]
            active.sort(key=lambda job: (not bool(job.worker_token), -job.updated_at, job.id))
            current = active[0] if active else None
            mother.update(active_job_count=len(active), current_job_id=current.id if current else None,
                          current_step=current.step if current else None,
                          counts={status: sum(job.status == status for job in own) for status in STATUS_LABELS})
            if current and current.worker_token:
                mother.update(state="running", reason=current.error or "当前步骤执行中", next_check_at="")
            elif not settings or not settings.enabled:
                mother.update(state="disabled", reason="设备托管未开启；绑定仅保存管理关系", next_check_at="")
            elif current:
                mother.update(state=current.status, reason=current.error or STATUS_LABELS[current.status],
                              next_check_at=_iso(current.next_run_at), can_run=current.status in {"pending", "waiting", "retry"})
        return dict(settings=_settings(settings, device_ref), mothers=mothers,
                    counts={status: sum(job.status == status for job in jobs) for status in STATUS_LABELS})
