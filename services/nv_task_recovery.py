"""Automatic recovery admission and credential-free next-action presentation.

Recovery never grants a blind replay: canonical capabilities still own remote
verification, account leases and mutations. Isolation is per task, not a global
pause, and does not free a mother's occupied seat or manufacture an order.
"""
from datetime import datetime, timezone
import os
import re
import socket
import time
import uuid

from sqlalchemy import inspect
from sqlmodel import func, or_, select

from core.db import (
    ChatGptAccountSecurityModel as Security, ChatGptSecurityOperationLeaseModel as SecurityLease,
    GptPlanAccountModel as Account, GptPlanAccountOperationLeaseModel as AccountLease,
    GptBusinessAccountModel as Mother, GptBusinessChildMembershipModel as Membership,
)
from services import nv_automation_store as store
from services.chatgpt_security_progress import normalize_task_retry


def _tables(session):
    if "nv_recovery_tables" not in session.info:
        session.info["nv_recovery_tables"] = set(inspect(session.connection()).get_table_names())
    return session.info["nv_recovery_tables"]


def _date(value):
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _security_target_status(session, job, settings, *, browser=False, manual=False):
    """Shared current ownership/lease gates; no retry inference here."""
    statuses = {"failed", "review", "retry"} if manual else ({"failed", "review"} if browser else {"failed"})
    if (session is None or job.step != "security" or job.status not in statuses
            or job.worker_token or job.worker_pid or job.pause_requested
            or not store._enabled_for(job, settings)
            or (not browser and not manual and job.attempts >= min(3, store._job_max_attempts(job)))):
        return None
    models = (Account, Mother, Membership, Security, AccountLease, SecurityLease)
    if any(model.__tablename__ not in _tables(session) for model in models):
        return None
    context = store._decode(job.context_json)
    started = _date(context.get("security_started_at"))
    if started is None or not started.timestamp() <= job.updated_at <= time.time() + 5:
        return None
    parent, mother = session.get(Account, job.parent_account_id), session.get(Mother, job.source_account_id)
    child, member = session.get(Account, job.child_id), session.get(Membership, job.membership_id)
    email = lambda value: str(value or "").strip().lower()
    if (parent is None or mother is None or child is None or member is None
            or parent.source_pool != "gpt_business" or parent.source_account_id != mother.id
            or parent.business_parent_id is not None or child.business_parent_id != mother.id
            or email(parent.email) != email(job.parent_email) or email(mother.email) != email(job.parent_email)
            or email(child.email) != email(job.email) or email(member.email) != email(job.email)
            or email(child.email) == email(parent.email)
            or member.business_account_id != mother.id or member.pro_account_id != child.id
            or member.ended_at is not None or member.source != "pool"
            or any(not row.enabled or row.dangerous for row in (parent, mother, child))
            or child.policy_warning or parent.policy_warning
            or any(str(row.refund_status or "") in {"refunded", "refunded_pending_credit", "refund_credited"}
                   for row in (parent, mother, child))
            or parent.catalog_category == "refunded" or child.catalog_category == "refunded"
            or member.sale_status != "unlisted" or member.sold_at or member.nv_listed_at
            or member.nv_listing_confirmed_at or member.nv_remote_card_id or member.nv_remote_order_id
            or member.intent_remote_started or member.end_reason or member.replacement_pro_account_id
            or str(member.intent_payload_json or "{}").strip() not in {"", "{}"}
            or member.seat_type != job.seat_type
            or job.remote_user_id and job.remote_user_id != member.remote_user_id):
        return None
    invited = _date(member.invited_at)
    if (invited is None or invited > started
            or any(context.get(key) and _date(context[key]) != invited
                   for key in ("membership_invited_at", "oauth_membership_invited_at"))
            or any(context.get(key) for key in ("publish_attempted", "publish_started_at", "existing_listing", "sold_at"))):
        return None
    if session.exec(select(Membership.id).where(Membership.ended_at == None,
            or_(Membership.pro_account_id == child.id,
                func.lower(func.trim(Membership.email)) == email(child.email)))).all() != [member.id]:
        return None
    now = datetime.now(timezone.utc)
    for model, identifiers in ((AccountLease, (parent.id, child.id)),
                               (SecurityLease, (email(parent.email), email(child.email)))):
        for identifier in identifiers:
            lease = session.get(model, identifier)
            if lease is not None and (_date(lease.expires_at) is None or _date(lease.expires_at) > now):
                return None
    if session.exec(select(store.NvAutomationJob.id).where(store.NvAutomationJob.id != job.id,
            or_(store.NvAutomationJob.child_id == child.id, store.NvAutomationJob.membership_id == member.id),
            or_(store.NvAutomationJob.worker_token != "", store.NvAutomationJob.worker_pid != 0,
                store.NvAutomationJob.status == "running"))).first():
        return None
    row = session.get(Security, email(child.email))
    if (row is None or _date(row.updated_at) is None
            or not manual and _date(row.updated_at).timestamp() > job.updated_at + 5):
        return None
    from services.chatgpt_security_store import _status
    return _status(row, email(child.email))


def _manual_security_status(session, job, settings, *, automatic=False):
    """Local-only permission check; never infer permission from a reset marker."""
    from services.nv_security_recovery import manual_security_retry_problem, normalize_security_retry, normalize_security_recovery
    context = store._decode(job.context_json)
    grant = normalize_security_retry(context.get("security_retry"), job)
    if job.status in {"pending", "running"}:
        return None, "一次手动安全核验已排队或正在执行，不能并发启动"
    if automatic and job.attempts >= min(3, store._job_max_attempts(job)):
        return None, "原安全阶段自动重试次数已用尽，可明确手动追加一次核验许可；历史次数不重置"
    old_browser_grant = normalize_security_recovery(context.get("security_recovery"), job)
    if automatic and any(value and value["phase"] == "queued" for value in (grant, old_browser_grant)):
        return None, "此前安全核验许可尚未消费，不能自动重复创建许可"
    if context.get("security_retry") is not None and grant is None:
        return None, "已保存的手动安全核验许可无效，需先核对原记录"
    if job.worker_host not in {"", socket.gethostname()}:
        return None, "原安全任务执行设备未确认，不能在另一设备重复启动"
    status = _security_target_status(session, job, settings, manual=True)
    if status is None:
        return None, "当前任务、成员或账号操作租约未允许安全核验；请先恢复调度并等待原操作结束"
    problem = manual_security_retry_problem(context, status)
    if problem:
        return None, problem
    # Preserve the existing strong no-submit proof for its legacy family.
    # A broad retry grant must not make its missing/contradictory logs harmless
    # or turn an old random candidate into an independent password login.
    from services.nv_legacy_security_login import is_legacy_pre_password_failure, retry_instruction
    if is_legacy_pre_password_failure(context) and retry_instruction(session, job, status) is None:
        return None, "旧首次密码的未提交证据已变化，需先核对原任务记录"
    task = re.fullmatch(r"gpt_plan_business_child_setup_security_(\d+)_(\d+)_(\d{13})_[a-f0-9]{8}",
                        context["canonical_task_id"])
    if (not task or int(task[1]) != job.parent_account_id or int(task[2]) != job.child_id
            or abs(int(task[3]) / 1000 - _date(context["security_started_at"]).timestamp()) > 30):
        return None, "原安全任务与当前账号或执行周期不一致，不能重复启动"
    if context.get("security_attempted") is not False:
        return None, "原安全任务的终态交接尚未确认，不能重复启动"
    from api.tasks import _task_store
    task_id = context["canonical_task_id"]
    if _task_store.exists(task_id):
        try:
            snapshot = _task_store.snapshot(task_id)
        except (KeyError, RuntimeError):
            return None, "原安全任务状态正在变化，请稍后核对"
        from services.chatgpt_security_progress import normalize_security_progress
        actual = normalize_security_progress((snapshot.get("meta") or {}).get("security_progress"))
        expected = normalize_security_progress(context.get("security_progress"))
        comparable = lambda value: {key: item for key, item in value.items() if key not in {"status", "task_retry"}}
        if (snapshot.get("status") != "failed" or not actual or not expected
                or comparable(actual) != comparable(expected)
                or manual_security_retry_problem({**context, "security_progress": actual}, status)):
            return None, "原安全任务仍在执行或终态证据不一致，未重复启动"
    if not _security_worker_absent(job.id):
        return None, "原安全任务进程尚未确认结束，未重复启动"
    return status, ""


def security_manual_retry_status(session, job, settings):
    """Authoritative, credential-free UI/API eligibility for explicit retry."""
    from services.nv_security_recovery import security_has_history
    if job.step != "security" or not security_has_history(store._decode(job.context_json)):
        return {"available": False, "reason": "当前任务没有可重新核验的安全设置记录"}
    status, reason = _manual_security_status(session, job, settings)
    return {"available": status is not None, "reason": reason}


def security_automatic_retry_status(session, job, settings):
    """Read-only admission shared by each automatic tick and batch snapshot."""
    status, reason = _manual_security_status(session, job, settings, automatic=True)
    return {"available": status is not None, "reason": reason}


def queue_manual_security_retry(session, job, settings, request_id=None):
    """The explicit action owns this transaction; normal checkpoints cannot mint.

    A second click while this exact grant is queued/running is a no-op. A new
    click after a closed failure is a new, independently recorded permission;
    it never deletes the old browser-recovery proof or resets job attempts.
    """
    return _queue_security_retry(session, job, settings, request_id=request_id, automatic=False)


def queue_automatic_security_retry(session, job, settings, request_id=None):
    """Spend only the original stage budget; never create a manual allowance."""
    return _queue_security_retry(session, job, settings, request_id=request_id, automatic=True)


def _queue_security_retry(session, job, settings, *, request_id=None, automatic=False):
    from services.nv_security_recovery import (
        normalize_security_retry, SECURITY_MANUAL_RETRY_REASON, SECURITY_STAGE_RETRY_REASON,
    )
    context = store._decode(job.context_json)
    previous = normalize_security_retry(context.get("security_retry"), job)
    if (previous and job.status in {"pending", "running"}
            and (request_id is None or request_id == previous["request_id"])):
        return False
    if previous and request_id is not None and previous["request_id"] == request_id:
        raise RuntimeError("本次手动安全核验许可已处理，未重复启动")
    status, reason = _manual_security_status(session, job, settings, automatic=automatic)
    if status is None:
        raise RuntimeError(reason)
    if automatic and not context.get("security_retry") and not context.get("security_recovery"):
        from services.nv_legacy_security_login import retry_instruction
        legacy_instruction = retry_instruction(session, job, status)
        if legacy_instruction is not None:
            context.update(task_retry=legacy_instruction, security_attempted=False)
            job.context_json = store._json(context)
            job.status, job.reconcile_requested, job.next_run_at = "pending", False, time.time()
            job.updated_at, job.version = time.time(), job.version + 1
            job.error = "旧登录阶段已确认未进入密码或 2FA 修改，按原剩余次数重试；先核验同一账号会话"
            store._log(session, job, job.error)
            session.add(job)
            return True
    member = session.get(Membership, job.membership_id)
    now = datetime.now(timezone.utc)
    grant = normalize_security_retry(dict(kind="security_stage_retry_v1" if automatic else "security_manual_retry_v1",
        request_id=request_id or ("stage-security-" if automatic else "manual-security-") + uuid.uuid4().hex,
        sequence=(previous["sequence"] if previous else 0) + 1, phase="queued", job_id=job.id,
        email=job.email.strip().casefold(), parent_account_id=job.parent_account_id,
        source_account_id=job.source_account_id, child_id=job.child_id, membership_id=job.membership_id,
        remote_user_id=job.remote_user_id, membership_invited_at=_date(member.invited_at).isoformat(),
        source_task_id=context["canonical_task_id"], source_started_at=context["security_started_at"],
        admitted_at=now.isoformat(), started_at="", security_updated_at=status["updated_at"],
        credential_state=status["password_state"], mfa_state=status["mfa_state"],
        has_totp=status["has_totp"], has_recovery_codes=status["has_recovery_codes"], prior_attempts=job.attempts), job)
    if grant is None:
        raise RuntimeError("原安全任务或当前成员周期无法生成有效手动核验许可")
    context["security_retry"] = grant
    context["task_retry"] = {"strategy": "verify_existing", "reason_code": "controls_unavailable"}
    # security_attempted already false is a terminal handoff, not a claim that
    # no historical remote attempt occurred. Keep all source diagnostics.
    job.context_json = store._json(context)
    job.status, job.reconcile_requested, job.next_run_at = "pending", False, time.time()
    job.error = SECURITY_STAGE_RETRY_REASON if automatic else SECURITY_MANUAL_RETRY_REASON
    job.updated_at, job.version = time.time(), job.version + 1
    store._log(session, job, job.error + f"；{'自动' if automatic else '手动'}许可第 {grant['sequence']} 次")
    session.add(job)
    return True


def security_retry_instruction(session, job, settings):
    """Project current stage admission, retaining exact legacy compatibility."""
    if security_automatic_retry_status(session, job, settings)["available"]:
        return {"strategy": "verify_existing", "reason_code": "controls_unavailable"}
    return _legacy_security_retry_instruction(session, job, settings)


def _legacy_security_retry_instruction(session, job, settings):
    context = store._decode(job.context_json)
    if context.get("security_retry") or context.get("security_recovery"):
        return None
    status = _security_target_status(session, job, settings)
    if status is None:
        return None
    from services.nv_security_recovery import security_recovery_retry
    instruction = security_recovery_retry(store._decode(job.context_json), status)
    if instruction is not None:
        return instruction
    from services.nv_legacy_security_login import retry_instruction
    instruction = retry_instruction(session, job, status)
    return instruction if instruction is not None and _security_worker_absent(job.id) else None


def _security_worker_absent(job_id):
    """Inspect only process ownership, never expose argv or signal a process."""
    import psutil
    try:
        for process in psutil.process_iter(["pid", "name", "cmdline", "uids"]):
            info = process.info
            if info["pid"] == os.getpid():
                continue
            uids = info.get("uids")
            if uids is not None and uids.real != os.getuid():
                continue
            argv = info.get("cmdline")
            if argv is None and "python" in str(info.get("name") or "").lower():
                return False
            argv = argv or []
            if "services.nv_automation" in argv and "--job" in argv:
                index = argv.index("--job") + 1
                if index >= len(argv) or argv[index] == job_id:
                    return False
        return True
    except (psutil.Error, OSError):
        return False


def security_browser_recovery_admission(session, job, settings):
    """One independent recovery budget for a closed pre-session interruption."""
    context = store._decode(job.context_json)
    if (context.get("security_recovery") or job.worker_host not in {"", socket.gethostname()}
            or job.attempts >= min(3, store._job_max_attempts(job))):
        return None
    status = _security_target_status(session, job, settings, browser=True)
    if status is None:
        return None
    from services.nv_security_recovery import browser_security_recovery_retry, normalize_security_recovery
    if browser_security_recovery_retry(context, status) is None:
        return None
    from api.tasks import _task_store
    task_id = context.get("canonical_task_id")
    if _task_store.exists(task_id):
        try:
            source = _task_store.snapshot(task_id)
        except (KeyError, RuntimeError):
            return None
        if source.get("status") != "failed":
            return None
        from services.chatgpt_security_progress import normalize_security_progress
        actual = normalize_security_progress((source.get("meta") or {}).get("security_progress"))
        expected = normalize_security_progress(context.get("security_progress"))
        if actual != expected:
            return None
    if not _security_worker_absent(job.id):
        return None
    progress = context.get("security_progress") or {}
    if progress.get("code") == "security_failed" and job.updated_at - _date(context["security_started_at"]).timestamp() < 20 * 60:
        return None
    proof = dict(kind="browser_init_verify_v1", attempts=1, phase="queued", job_id=job.id,
        email=job.email.strip().casefold(), parent_account_id=job.parent_account_id,
        source_account_id=job.source_account_id, child_id=job.child_id, membership_id=job.membership_id,
        source_task_id=task_id, source_started_at=context["security_started_at"],
        admitted_at=datetime.now(timezone.utc).isoformat(), started_at="",
        security_updated_at=status["updated_at"], credential_state=status["password_state"],
        mfa_state=status["mfa_state"], has_totp=status["has_totp"], has_recovery_codes=status["has_recovery_codes"])
    return normalize_security_recovery(proof, job)


def enqueue_security_recovery():
    """Each enabled tick adopts eligible historical failures once, without I/O."""
    queued = []
    with store.transaction() as session:
        if store.NvAutomationSettings.__tablename__ not in _tables(session):
            return queued
        config = store._settings_row(session)
        settings = store._settings(config)
        if not settings["enabled"] or config.scan_token:
            return queued
        for job in session.exec(select(store.NvAutomationJob).where(
                store.NvAutomationJob.step == "security", store.NvAutomationJob.status.in_(["failed", "review"]))).all():
            if security_automatic_retry_status(session, job, settings)["available"]:
                if queue_automatic_security_retry(session, job, settings):
                    queued.append(job.id)
                continue
            # Historical narrow paths keep their original evidence and budget;
            # broad retries above always carry a versioned one-use grant.
            instruction = _legacy_security_retry_instruction(session, job, settings)
            browser_recovery = security_browser_recovery_admission(session, job, settings) if instruction is None else None
            if instruction is None and browser_recovery is None:
                continue
            context = store._decode(job.context_json)
            if browser_recovery is not None:
                context["security_recovery"] = browser_recovery
                instruction = {"strategy": "verify_existing", "reason_code": "network_temporary"}
            context.update(task_retry=instruction, security_attempted=False)
            job.context_json = store._json(context)
            job.status, job.reconcile_requested = "pending", False
            job.next_run_at = job.updated_at = time.time()
            job.version += 1
            job.error = "已排队自动核验 2FA 状态；确认未启用后继续设置，已有密钥不重绑"
            if (context.get("security_progress") or {}).get("stage") == "session_check":
                job.error = "旧登录阶段已确认未进入密码或 2FA 修改，按原剩余次数重试；先核验同一账号会话"
            if browser_recovery is not None:
                job.error = "旧浏览器任务已结束，已排队一次受限安全核验；保留原密码与 2FA，不重置历史次数"
            store._log(session, job, job.error)
            session.add(job)
            queued.append(job.id)
    return queued


def _message(value):
    value = store.safe_message(value)
    for suffix in ("；请人工核对，未自动重试", "；需要人工处理后重试", "；需要人工核对"):
        value = value.replace(suffix, "")
    return value.strip(" ；")


def public_plan(session, job, settings):
    """Describe the actual scheduler decision; never claim a queued side effect."""
    if (job.status in store.TERMINAL_STATUSES or job.step == "renew"
            or store.manual_exit_requested_at(job) is not None):
        return None
    def plan(mode, label, reason, next_at=None):
        return dict(mode=mode, label=label, reason=_message(reason), next_retry_at=next_at)
    if job.status == "running":
        from services.nv_security_recovery import normalize_security_retry
        grant = normalize_security_retry(store._decode(job.context_json).get("security_retry"), job)
        if job.step == "security" and grant and grant["phase"] == "started":
            if grant["kind"] == "security_stage_retry_v1":
                return plan("verify", "原安全阶段重试进行中", "按原剩余次数执行安全设置；先验证原密码和 2FA，不重复设置已完成项")
            return plan("verify", "手动安全核验进行中", "本次只使用一个手动许可；保留原密码和 2FA，正在核对同一账号及远端状态")
        return None
    if job.pause_requested or job.status == "paused" or not store._enabled_for(job, settings):
        return plan("wait", "已暂停", "自动售号关闭、母号暂停或已移出管理，不自动启动")
    context = store._oauth_context_for_retry(session, job)
    if job.step == "security":
        from services.nv_security_recovery import normalize_security_retry, SECURITY_MANUAL_RETRY_REASON, SECURITY_STAGE_RETRY_REASON
        grant = normalize_security_retry(context.get("security_retry"), job)
        if grant and job.status == "pending" and grant["phase"] == "queued":
            if grant["kind"] == "security_stage_retry_v1":
                return plan("verify", "原安全阶段重试已排队", SECURITY_STAGE_RETRY_REASON, store._iso(job.next_run_at))
            return plan("verify", "手动安全核验已排队", SECURITY_MANUAL_RETRY_REASON, store._iso(job.next_run_at))
        if job.status == "pending" and job.reconcile_requested:
            return plan("verify", "只读安全核对已排队", "仅核对已保存的安全状态和原任务结果，不启动新的设置", store._iso(job.next_run_at))
    if job.step == "dead_cleanup":
        if job.status in {"review", "failed"}:
            proof = context.get("dead_child_cleanup") or {}
            blocked = store._retry_batch_skip_reason(job, settings, automatic=True, session=session)
            return plan("isolated", "清理已隔离", blocked or job.error) if blocked or not proof.get("submitted_at") else plan(
                "verify", "仅核验移除结果", job.error)
        return plan("replace", "停用清理后补号", job.error, store._iso(job.next_run_at))
    if job.status not in {"failed", "review", "retry", "pending"}:
        return None
    instruction = normalize_task_retry(context.get("task_retry"))
    if job.status == "pending":
        stage_mode = store._stage_retry_mode(job)
        if stage_mode is not None:
            verify = bool(job.reconcile_requested or stage_mode == "reconcile")
            return plan("verify" if verify else "retry", "原阶段核对已排队" if verify else "原阶段重试已排队",
                        job.error or "等待原阶段执行资源", store._iso(job.next_run_at))
        if instruction and instruction["strategy"] in {"safe_resume", "verify_existing"}:
            return plan("verify" if instruction["strategy"] == "verify_existing" else "retry",
                        "自动核验已排队" if instruction["strategy"] == "verify_existing" else "自动重试已排队",
                        job.error or "等待执行资源", store._iso(job.next_run_at))
        return None
    if (job.status == "retry" and not job.reconcile_requested and job.step in {"security", "oauth"}
            and (not instruction or instruction["strategy"] not in {"safe_resume", "verify_existing"})):
        return plan("isolated", "已隔离", "原重试记录缺少安全恢复依据，未启动新操作")
    if session is not None and security_retry_instruction(session, job, settings):
        return plan("verify", "等待自动核验", "下次调度重试原安全阶段，先核对当前账号及原密码与 2FA，已完成项不重复设置")
    if session is not None and job.step == "security" and job.status in {"failed", "review"}:
        permission = security_manual_retry_status(session, job, settings)
        if permission["available"]:
            return plan("isolated", "等待手动安全核验", "当前安全设置尚未完成；可明确手动重试一次，先核对远端状态；不自动重新绑定 2FA")
        if context.get("security_recovery") or context.get("security_retry"):
            return plan("isolated", "安全核验已隔离", permission["reason"])
    reason = store._retry_batch_skip_reason(job, settings, automatic=True, session=session)
    if reason:
        # These gates are actually rechecked by the scheduler when the shared
        # balance/fee setting changes. A missing password/key/configuration is
        # not promised an automatic resume without a verified recovery path.
        waiting = any(word in reason for word in ("余额", "费用", "未开启"))
        return plan("wait" if waiting else "isolated", "等待条件恢复" if waiting else "已隔离",
                    reason.removeprefix("当前任务需要人工处理："))
    stage_mode = store._stage_retry_mode(job)
    verify = (stage_mode == "reconcile" if stage_mode is not None else (
        job.step in store.WAIT_STEPS or job.status == "review"
        or instruction and instruction["strategy"] == "verify_existing"
        or context.get(f"{job.step}_attempted") is True))
    return plan("verify" if verify else "retry", "自动核验" if verify else "自动重试",
                job.error or "等待下一轮自动恢复", store._iso(job.next_run_at) if job.status == "retry" else None)
