"""Admission and local completion fences for unsold, deactivated NV children.

This module never sends requests. Only a closed, structured security/OAuth
failure can admit an existing task; ordinary 401s and free-form job errors are
not proof. The canonical mother capability performs the separate cleanup step.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import time
import uuid

from sqlalchemy import inspect
from sqlalchemy.orm import object_session
from sqlmodel import Session, select, func, or_

from core.db import (GptPlanAccountModel as Account, GptBusinessAccountModel as Mother,
                     GptBusinessChildMembershipModel as Membership,
                     GptPlanAccountOperationLeaseModel as AccountLease,
                     ChatGptSecurityOperationLeaseModel as SecurityLease)
from services import nv_automation_store as store
from services.chatgpt_oauth_failure import normalize_oauth_failure
from services.chatgpt_security_progress import normalize_security_progress

KEY = "dead_child_cleanup"
REASON = "OpenAI 已明确停用或删除此账号（account_deactivated）"
COMPLETE_REASON = "停用子号已清理，旧任务已结束；母号将按席位与邀请额度重新补号"
PHASES = {"queued", "checking", "removing", "submitted", "verifying", "complete"}
IDENTITY_KEYS = ("parent_account_id", "source_account_id", "child_id", "membership_id", "email")
SOURCE_STEPS = {"invite", "security", "oauth", "publish", "renew", "wait_sale", "wait_warranty", "leave"}
DEACTIVATION_KEY = "child_deactivation"
_DEACTIVATION_FIELDS = {"code", "job_id", *IDENTITY_KEYS, "step", "observed_at", "membership_invited_at"}
FROZEN_KEYS = (*IDENTITY_KEYS, "code", "original_step", "remote_user_id", "remote_invite_id",
               "invited_at", "evidence_at", "operation_id", "sale_history", "account_history")
SALE_CONTEXT_KEYS = ("publish_attempted", "publish_started_at", "publish_confirmed", "publish_baseline",
    "nv_publish_started", "nv_publish_confirmed", "nv_listing_started_at", "nv_listed_at", "nv_listing_confirmed_at",
    "nv_remote_card_id", "nv_remote_order_id", "nv_card_id", "nv_order_id", "sold_at", "sale_confirmed",
    "sale_verified_at", "warranty_until", "leave_attempted", "leave_target", "left_at", "existing_listing",
    "nv_refund", "team5x_warranty", "price_yuan", "warranty_hours")
SALE_MEMBER_KEYS = ("sale_status", "sold_at", "nv_listed_at", "nv_listing_confirmed_at", "nv_remote_card_id",
                    "nv_remote_order_id", "nv_team5x_warranty_until", "warranty_hours")
ACCOUNT_HISTORY_KEYS = ("plan_type", "catalog_category", "is_pro", "subscribed_at", "pro_expires_at",
    "refund_status", "refund_detected_at", "refund_credited_at", "human_review_requested_at", "refund_rejected_at",
    "refund_manual_at")


def account_history(child):
    return {key: (_date(value).isoformat() if isinstance(value, datetime) else value)
            for key in ACCOUNT_HISTORY_KEYS if (value := getattr(child, key, None)) is not None}


def sale_history_fingerprint(session, job, member):
    """Freeze sales facts, including the separate ledger, without copying secrets."""
    context = job.get("context", {}) if isinstance(job, dict) else store._decode(job.context_json)
    get = job.get if isinstance(job, dict) else lambda key: getattr(job, key, None)
    history = {
        "context": {key: context.get(key) for key in SALE_CONTEXT_KEYS},
        "member": {key: getattr(member, key, None) for key in SALE_MEMBER_KEYS},
    }
    if inspect(session.connection()).has_table("nv_sale_orders"):
        from services.nv_order_history import NvSaleOrder
        rows = session.exec(select(NvSaleOrder).where(or_(
            NvSaleOrder.job_id == get("id"), NvSaleOrder.membership_id == member.id,
            NvSaleOrder.child_id == get("child_id"), func.lower(func.trim(NvSaleOrder.email)) == _email(get("email")),
        )).order_by(NvSaleOrder.id)).all()
        history["orders"] = [row.model_dump() for row in rows]
    return hashlib.sha256(json.dumps(history, sort_keys=True, default=str).encode()).hexdigest()


def _date(value):
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _email(value):
    return str(value or "").strip().lower()


def normalize_deactivation_evidence(value, job):
    """Accept a typed child result bound to one task and invitation cycle."""
    if not isinstance(value, dict) or set(value) != _DEACTIVATION_FIELDS:
        return None
    get = job.get if isinstance(job, dict) else lambda key: getattr(job, key, None)
    context = (get("context") or {}) if isinstance(job, dict) else store._decode(job.context_json)
    if (value.get("code") != "account_deactivated" or value.get("job_id") != get("id")
            or value.get("step") not in SOURCE_STEPS or value.get("step") != get("step")
            or any(type(value.get(key)) is not int or value[key] <= 0 or value[key] != get(key)
                   for key in IDENTITY_KEYS if key != "email")
            or not isinstance(value.get("email"), str) or value["email"] != _email(get("email"))
            or not re.fullmatch(r"[^\s@]+@[^\s@]+", value["email"])
            or value["email"] == _email(get("parent_email"))):
        return None
    times = []
    for key in ("observed_at", "membership_invited_at"):
        stamp = value.get(key)
        parsed = _date(stamp)
        if not isinstance(stamp, str) or parsed is None or parsed.isoformat() != stamp:
            return None
        times.append(parsed)
    observed, invited = times
    if not invited <= observed <= datetime.now(timezone.utc):
        return None
    if not any(context.get(key) for key in ("membership_invited_at", "oauth_membership_invited_at")):
        return None
    if any(context.get(key) and _date(context[key]) != invited
           for key in ("membership_invited_at", "oauth_membership_invited_at")):
        return None
    return dict(value)


def make_deactivation_evidence(job, *, observed_at=None):
    """The caller must first verify the remote typed error belongs to this child."""
    get = job.get if isinstance(job, dict) else lambda key: getattr(job, key, None)
    context = (get("context") or {}) if isinstance(job, dict) else store._decode(job.context_json)
    invited = _date(context.get("membership_invited_at") or context.get("oauth_membership_invited_at"))
    observed = _date(observed_at) if observed_at is not None else datetime.now(timezone.utc)
    if invited is None or observed is None:
        return None
    return normalize_deactivation_evidence({
        "code": "account_deactivated", "job_id": get("id"),
        **{key: get(key) for key in IDENTITY_KEYS}, "step": get("step"),
        "observed_at": observed.isoformat(), "membership_invited_at": invited.isoformat(),
    }, job)


def recovered_after(child, evidence_at):
    """A successful later authentication invalidates historical deactivation."""
    floor = _date(evidence_at)
    return floor is None or any(value is not None and value > floor for value in
        (_date(child.last_login_at), _date(child.codex_rt_acquired_at)))


def _dead_marker_recovery_target(session, current):
    state = store._decode(current.context_json).get(KEY)
    if (current.step != "dead_cleanup" or not isinstance(state, dict)
            or state.get("code") != "account_deactivated" or state.get("phase") not in PHASES
            or any(getattr(current, key) != state.get(key) for key in IDENTITY_KEYS)):
        return None
    evidence = _date(state.get("evidence_at"))
    if evidence is None or evidence.isoformat() != state.get("evidence_at") or evidence > datetime.now(timezone.utc):
        return None
    original = current.model_copy(update={"step": state.get("original_step"), "status": "failed",
                                          "updated_at": evidence.timestamp()})
    if terminal_failure(original, evidence_session=session) is None:
        return None
    child, member = session.get(Account, current.child_id), session.get(Membership, current.membership_id)
    parent, mother = session.get(Account, current.parent_account_id), session.get(Mother, current.source_account_id)
    if (child is None or member is None or parent is None or mother is None
            or parent.source_pool != "gpt_business" or parent.source_account_id != mother.id
            or parent.business_parent_id is not None or not parent.enabled or not mother.enabled
            or parent.dangerous or mother.dangerous or _email(child.email) == _email(parent.email)
            or _email(parent.email) != _email(current.parent_email) or _email(mother.email) != _email(current.parent_email)
            or any(str(a.refund_status or "") in {"refunded", "refunded_pending_credit", "refund_credited"} for a in (parent, mother))
            or not state.get("sale_history") or state.get("account_history") is None
            or child.dangerous is not False or _email(child.email) != state["email"]
            or child.business_parent_id != (None if member.ended_at else state["source_account_id"])
            or recovered_after(child, evidence) or account_history(child) != state["account_history"]
            or sale_history_fingerprint(session, current, member) != state["sale_history"]):
        return None
    frozen = frozen_identity(current, member, started=evidence)
    if frozen is None or any(frozen[key] != state.get(key) for key in (*IDENTITY_KEYS,
            "remote_user_id", "remote_invite_id", "invited_at")):
        return None
    extra = store._decode(child.extra_json)
    if (extra.get("nv_account_deactivated") != {"job_id": current.id, "detected_at": state["evidence_at"]}
            or extra.get("dead_login_review_recovered_at")):
        return None
    for model, identifiers in ((AccountLease, (child.id, parent.id)),
                               (SecurityLease, (_email(child.email), _email(parent.email)))):
        for identifier in identifiers:
            lease = session.get(model, identifier)
            if lease is not None and (_date(lease.expires_at) is None or _date(lease.expires_at) > datetime.now(timezone.utc)):
                return None
    return child, state


def dead_marker_recovery_eligible(session, job):
    """Read-only retry projection for the exact old mailbox overwrite error."""
    if (job.status not in {"review", "failed"} or job.worker_token or job.worker_pid or job.pause_requested
            or job.error not in {"停用子号的账号状态或母号绑定已变化",
                                 "停用子号的账号状态或母号绑定已变化 ；请人工核对，未自动重试"}):
        return False
    return _dead_marker_recovery_target(session, job) is not None


def restore_confirmed_dead_marker(job, state):
    """Restore only an owned cleanup's confirmed flag, never its remote phase."""
    with store.transaction() as session:
        current = session.get(store.NvAutomationJob, job.get("id"))
        if (current is None or current.status != "running" or not current.worker_token
                or current.worker_token != job.get("worker_token")
                or store._decode(current.context_json).get(KEY) != state):
            return False
        target = _dead_marker_recovery_target(session, current)
        if target is None:
            return False
        child, state = target
        child.dangerous = True
        child.dangerous_detected_at = child.dangerous_detected_at or _date(state["evidence_at"])
        child.updated_at = datetime.now(timezone.utc)
        session.add(child)
        return True


def _legacy_security_task_failure(job, context, started, *, evidence_session=None):
    """Read only the original canonical task; arbitrary job errors are insufficient."""
    task_id = context.get("security_task_id")
    task = re.fullmatch(r"gpt_plan_business_child_setup_security_(\d+)_(\d+)_(\d{13})_[a-f0-9]{8}",
                        str(task_id or ""))
    if (not task or task_id != context.get("canonical_task_id")
            or int(task[1]) != job.parent_account_id or int(task[2]) != job.child_id
            or abs(int(task[3]) / 1000 - started.timestamp()) > 30):
        return False
    from api.tasks import _task_store
    if not _task_store.exists(task_id):
        # NV workers keep their canonical source tasks in process memory. Once
        # that process exits, only its job/step/time-bound forwarded logs survive.
        # Require both exact typed source lines and the matching terminal DTO.
        progress = normalize_security_progress(context.get("security_progress"))
        legacy_error = "account_deactivated: 账号已被停用或删除"
        session = evidence_session if evidence_session is not None else object_session(job)
        if (session is None or progress is None or progress["status"] != "failed"
                or progress["code"] != "security_failed" or progress["reason"] != legacy_error):
            return False
        rows = session.exec(select(store.NvAutomationLog).where(
            store.NvAutomationLog.job_id == job.id, store.NvAutomationLog.step == "security",
            store.NvAutomationLog.created_at >= started.timestamp(),
            store.NvAutomationLog.created_at <= job.updated_at + 5,
        ).order_by(store.NvAutomationLog.created_at, store.NvAutomationLog.id)).all()
        if not rows or len(rows) > 20000:
            return False
        expected = {
            "✗ 检测到 account_deactivated(账号已停用/删除), 停止重试",
            "✗ 账号已被停用或删除 (account_deactivated), 终止登录",
        }
        observed = set()
        for row in rows:
            message = str(row.message)
            for _ in range(2):
                message = re.sub(r"^\[(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\] *", "", message, count=1)
            message = message.removeprefix("[GPT PRO 登录] ")
            if message in expected:
                observed.add(message)
            if message in {"密码与 Authenticator 2FA 设置完成", "密码与 Authenticator 2FA 已确认"}:
                return False
        return observed == expected
    try:
        snapshot = _task_store.snapshot(task_id)
    except (KeyError, RuntimeError):
        return False
    meta = snapshot.get("meta") or {}
    if (snapshot.get("id") != task_id or snapshot.get("status") != "failed"
            or snapshot.get("source") != "gpt_plan_business_child_security"
            or any(meta.get(key) != expected for key, expected in (
                ("account_id", job.parent_account_id), ("child_id", job.child_id),
                ("membership_id", job.membership_id), ("email", job.email)))
            or type(snapshot.get("updated_at")) not in (int, float)
            or not started.timestamp() <= snapshot["updated_at"] <= job.updated_at + 5):
        return False
    progress = normalize_security_progress(meta.get("security_progress"))
    explicit = (progress is not None and progress["status"] == "failed"
                and progress["code"] == "account_deactivated")
    # An exact canonical error envelope recovers this old typed-result adapter
    # bug; substring searches of job errors or unrelated logs are never used.
    legacy_error = "account_deactivated: 账号已被停用或删除"
    legacy = (snapshot.get("error") == legacy_error and snapshot.get("errors") == [legacy_error]
              and progress is not None and progress["status"] == "failed"
              and progress["code"] == "security_failed" and progress["reason"] == legacy_error)
    return explicit or legacy


def _unsold_unpublished(job, member):
    context = store._decode(job.context_json)
    keys = ("publish_attempted", "publish_started_at", "publish_confirmed", "nv_publish_started",
            "nv_publish_confirmed", "nv_listing_started_at", "nv_listed_at", "nv_listing_confirmed_at",
            "nv_remote_card_id", "nv_remote_order_id", "nv_card_id", "nv_order_id", "sold_at",
            "sale_confirmed", "sale_verified_at", "warranty_until", "leave_attempted", "left_at")
    return bool(not any(context.get(key) for key in keys)
                and not context.get("existing_listing")
                and member.sale_status == "unlisted" and not member.sold_at
                and not member.nv_listed_at and not member.nv_listing_confirmed_at
                and not member.nv_remote_card_id and not member.nv_remote_order_id)


def terminal_failure(job, *, evidence_session=None):
    """Return the original failed execution start, never infer from error text."""
    if job.step not in SOURCE_STEPS or job.status not in {"failed", "review", "retry", "waiting", "pending"}:
        return None
    context = store._decode(job.context_json)
    evidence = normalize_deactivation_evidence(context.get(DEACTIVATION_KEY), job)
    if evidence is not None:
        return _date(evidence["observed_at"])
    if job.step not in {"security", "oauth"} or job.status not in {"failed", "review"}:
        return None
    started = _date(context.get(job.step + "_started_at"))
    if started is None or not started.timestamp() <= job.updated_at <= time.time() + 5:
        return None
    if job.step == "security":
        progress = normalize_security_progress(context.get("security_progress"))
        task = context.get("security_task_id")
        # Compatibility for the old progress normalizer, which retained the
        # fixed deactivation reason but mapped its code to security_failed.
        explicit = bool(progress and (progress["code"] == "account_deactivated"
                        or progress["code"] == "security_failed" and progress["reason"] == REASON))
        if _legacy_security_task_failure(job, context, started, evidence_session=evidence_session):
            return started
        if (not explicit or progress["status"] != "failed" or progress["retry_mode"] != "manual"
                or not isinstance(task, str) or not task
                or task != context.get("canonical_task_id")):
            return None
    else:
        failure = normalize_oauth_failure(context.get("oauth_failure"))
        if (not failure or failure["code"] != "account_deactivated" or not failure["terminal"]
                or _date(context.get("oauth_failure_started_at")) != started
                or type(context.get("oauth_execution_attempts")) is not int
                or context["oauth_execution_attempts"] < 1):
            return None
    return started


def frozen_identity(job, member, *, started):
    """Require the same current membership cycle as the failed execution."""
    context = store._decode(job.context_json)
    invited = _date(member.invited_at)
    if (member.source != "pool"
            or member.business_account_id != job.source_account_id
            or member.pro_account_id != job.child_id or _email(member.email) != _email(job.email)
            or invited is None or invited > started
            or (job.remote_user_id and job.remote_user_id != member.remote_user_id)
            or member.seat_type != job.seat_type or member.seat_type not in {"default", "prolite"}
            or not (member.remote_user_id or member.remote_invite_id)):
        return None
    for key in ("membership_invited_at", "oauth_membership_invited_at"):
        if context.get(key) not in (None, "") and _date(context[key]) != invited:
            return None
    return {**{key: getattr(job, key) for key in IDENTITY_KEYS},
            "code": "account_deactivated", "original_step": job.step,
            "remote_user_id": member.remote_user_id, "remote_invite_id": member.remote_invite_id,
            "invited_at": invited.isoformat(), "evidence_at": datetime.fromtimestamp(job.updated_at, timezone.utc).isoformat(),
            "operation_id": str(uuid.uuid4()), "phase": "queued"}


def enqueue():
    """Each enabled dispatcher tick also admits old terminal failures once."""
    queued = []
    with store.transaction() as session:
        config = store._settings_row(session)
        settings = store._settings(config)
        if not settings["enabled"] or config.scan_token:
            return queued
        schema = inspect(session.connection())
        if any(not schema.has_table(model.__tablename__) for model in (Account, Mother, Membership, AccountLease, SecurityLease)):
            return queued
        jobs = session.exec(select(store.NvAutomationJob).where(
            store.NvAutomationJob.status.in_(["failed", "review", "retry", "waiting", "pending"]),
            store.NvAutomationJob.step.in_(SOURCE_STEPS))).all()
        for job in jobs:
            if (job.parent_account_id not in settings["mother_ids"]
                    or job.parent_account_id in settings["paused_mother_ids"] or job.pause_requested
                    or job.worker_token or job.worker_pid
                    or store._mother_dead_reason(session, job.parent_account_id, job.source_account_id)):
                continue
            started = terminal_failure(job)
            if started is None:
                continue
            parent, mother = session.get(Account, job.parent_account_id), session.get(Mother, job.source_account_id)
            child, member = session.get(Account, job.child_id), session.get(Membership, job.membership_id)
            if (parent is None or mother is None or child is None or member is None
                    or parent.source_pool != "gpt_business" or parent.source_account_id != mother.id
                    or parent.business_parent_id is not None or not parent.enabled or not mother.enabled
                    or _email(parent.email) != _email(job.parent_email) or _email(mother.email) != _email(job.parent_email)
                    or (member.ended_at is None and child.business_parent_id != mother.id)
                    or (member.ended_at is not None and child.business_parent_id is not None)
                    or _email(child.email) != _email(job.email)
                    or _email(child.email) == _email(parent.email)
                    or any(str(a.refund_status or "") in {"refunded", "refunded_pending_credit", "refund_credited"}
                           for a in (parent, mother)) or parent.catalog_category == "refunded"):
                continue
            # A later successful login/OAuth can supersede an old failed
            # attempt (for example after an appeal). Do not retire a recovered
            # account using a historical task that has not yet been reconciled.
            context = store._decode(job.context_json)
            explicit = normalize_deactivation_evidence(context.get(DEACTIVATION_KEY), job)
            observed = _date(explicit["observed_at"]) if explicit else datetime.fromtimestamp(job.updated_at, timezone.utc)
            if recovered_after(child, observed):
                continue
            frozen = frozen_identity(job, member, started=started)
            if frozen is None:
                continue
            if session.exec(select(Membership.id).where(Membership.ended_at == None, or_(
                    Membership.pro_account_id == child.id, func.lower(func.trim(Membership.email)) == _email(child.email),
            ))).all() != ([] if member.ended_at is not None else [member.id]):
                continue
            now = datetime.now(timezone.utc)
            occupied = False
            for model, identifiers in ((AccountLease, (parent.id, child.id)),
                                       (SecurityLease, (_email(parent.email), _email(child.email)))):
                for identifier in identifiers:
                    lease = session.get(model, identifier)
                    if lease is not None and (_date(lease.expires_at) is None or _date(lease.expires_at) > now):
                        occupied = True
            if occupied or session.exec(select(store.NvAutomationJob.id).where(
                store.NvAutomationJob.id != job.id,
                or_(store.NvAutomationJob.child_id == child.id, store.NvAutomationJob.membership_id == member.id),
                or_(store.NvAutomationJob.status == "running", store.NvAutomationJob.worker_token != "",
                    store.NvAutomationJob.worker_pid != 0),
            )).first():
                continue
            frozen["evidence_at"] = observed.isoformat()
            frozen["sale_history"] = sale_history_fingerprint(session, job, member)
            frozen["account_history"] = account_history(child)
            # Preserve original failed-step diagnostics in the old task. The
            # separate phase cannot restart security/OAuth or issue an invite.
            context[KEY] = frozen
            context["oauth_retry_ready"] = False
            # This is a new, separately guarded cleanup stage. The failed
            # security/OAuth stage's retry policy must not gate its execution.
            context.pop("task_retry", None)
            child.dangerous = True
            child.dangerous_detected_at = child.dangerous_detected_at or datetime.now(timezone.utc)
            child.updated_at = datetime.now(timezone.utc)
            extra = store._decode(child.extra_json)
            extra["nv_account_deactivated"] = {"job_id": job.id, "detected_at": frozen["evidence_at"]}
            child.extra_json = store._json(extra)
            job.context_json = store._json(context)
            # Invitation jobs initially have no member user ID. A later
            # accepted-invite snapshot may populate it in this SAME immutable
            # membership cycle. Freeze that known identity before cleanup;
            # a different previously known user ID was rejected above.
            job.remote_user_id = frozen["remote_user_id"]
            job.step, job.status, job.attempts = "dead_cleanup", "pending", 0
            job.reconcile_requested, job.operation_id = False, ""
            job.error = "已确认子号停用，等待清理旧邀请或成员；不会重试原号"
            job.next_run_at = job.updated_at = time.time()
            job.version += 1
            session.add(child)
            session.add(job)
            store._log(session, job, job.error)
            queued.append(job.id)
    return queued


def validate_checkpoint(job, previous, incoming):
    if (job.step != "dead_cleanup" or not isinstance(previous, dict) or not isinstance(incoming, dict)
            or incoming.get("phase") not in PHASES
            or any(incoming.get(key) != previous.get(key) for key in FROZEN_KEYS)
            or incoming.get("code") != "account_deactivated"):
        raise ValueError("停用子号清理检查点身份已变化")
    from services.nv_exit_recovery import normalize_leave_preflight
    no_request = normalize_leave_preflight(incoming.get("preflight_failure"))
    proven_preflight = bool(previous.get("phase") == "submitted" and incoming.get("phase") == "queued"
                            and no_request is not None and no_request["remote_mutation_started"] is False)
    for key in ("submitted_at", "confirmed_at"):
        if incoming.get(key) and _date(incoming[key]) is None:
            raise ValueError("停用子号清理时间无效")
        if previous.get(key) and incoming.get(key) != previous[key] and not (
                key == "submitted_at" and not incoming.get(key) and proven_preflight):
            raise ValueError("不能覆盖已提交的停用清理证据")
    return incoming


def finish_locked(session, job):
    """The worker must prove remote cleanup, then the local cycle must agree."""
    proof = store._decode(job.context_json).get(KEY)
    if (job.step != "dead_cleanup" or not isinstance(proof, dict) or proof.get("phase") != "complete"
            or proof.get("code") != "account_deactivated" or _date(proof.get("confirmed_at")) is None
            or any(getattr(job, key) != proof.get(key) for key in IDENTITY_KEYS)):
        raise RuntimeError("停用子号尚未确认清理完成")
    member = session.get(Membership, proof["membership_id"])
    if (member is None or member.ended_at is None or member.business_account_id != proof["source_account_id"]
            or _email(member.email) != _email(proof["email"]) or member.source != "pool"
            or member.pro_account_id not in (None, proof["child_id"])
            or member.remote_user_id != proof["remote_user_id"] or member.remote_invite_id != proof["remote_invite_id"]
            or _date(member.invited_at) != _date(proof["invited_at"])
            or (proof.get("sale_history") and sale_history_fingerprint(session, job, member) != proof["sale_history"])
            or (not proof.get("sale_history") and not _unsold_unpublished(job, member))):
        raise RuntimeError("停用子号的归属结束记录尚未确认")
    child = session.get(Account, proof["child_id"])
    if child is not None:
        raise RuntimeError("停用子号本地删除尚未确认，未释放补号任务")
    if session.exec(select(Account.id).where(func.lower(func.trim(Account.email)) == _email(proof["email"]))).first() is not None:
        raise RuntimeError("停用子号邮箱已存在新的本地身份，未复用旧清理结果")
    job.worker_token, job.worker_pid = "", 0
    store._cancel_deleted_child(session, job, COMPLETE_REASON)


def public_state(job):
    proof = store._decode(job.context_json).get(KEY)
    if job.step != "dead_cleanup" or not isinstance(proof, dict) or proof.get("phase") not in PHASES:
        return None
    return {"phase": proof["phase"], "original_step": proof.get("original_step"),
            "reason": store.safe_message(job.error)}
