"""Durable Gmail alias ownership for NV's invitation preparation.

Only identities and stage evidence cross this bridge. Mailbox credentials and
the browser/account-operation lease stay with their existing owners.
"""
from __future__ import annotations

import json
from datetime import timezone

from sqlalchemy import func, inspect, or_, update
from sqlmodel import Session, select

from core.db import (AccountModel, GptBusinessChildMembershipModel, GptPlanAccountModel,
                     GptPlanAccountOperationLeaseModel)
from services import gmail_store as store


def _value(job, key, default=None):
    return job.get(key, default) if isinstance(job, dict) else getattr(job, key, default)


def _has_table(session, model):
    return inspect(session.connection()).has_table(model.__tablename__)


def _job_model():
    from services.nv_automation_store import NvAutomationJob
    return NvAutomationJob


def owner_active(session, alias) -> bool:
    """Paused/review jobs retain their exact alias; terminal or deleted jobs do not."""
    if not alias.production_job_id:
        return False
    model = _job_model()
    # Missing lifecycle tables are not evidence that a persisted owner ended.
    if not _has_table(session, model):
        return True
    job = session.get(model, alias.production_job_id)
    plan = session.get(GptPlanAccountModel, job.child_id) if job and job.child_id else None
    return bool(job and job.status not in {"completed", "cancelled"}
                and job.child_id and job.child_id == alias.gpt_plan_account_id
                and job.active_child_key == str(job.child_id)
                and str(job.email or "").strip().lower() == alias.email
                and plan is not None and str(plan.email or "").strip().lower() == alias.email)


def _mark_deactivated(session, alias):
    """An immutable alias must never lose confirmed GPT deactivation evidence."""
    alias.registration_status = "failed"
    alias.registration_stage = "account_deactivated"
    alias.registration_error = "GPT 已明确停用此子号，已停止注册和自动售号，不再重复选择"
    alias.registration_lease_token = ""
    alias.registration_lease_expires_at = None
    alias.registration_retry_at = None
    alias.registration_updated_at = store.utcnow()
    session.add(alias)


def quarantine_deactivated(session, alias) -> bool:
    """Persist exact dead-candidate evidence before a purged plan can be rebuilt.

    Include the current job: its active email is cleared before plan deletion,
    and a later candidate overwrites its single dead-candidate checkpoint. The
    alias tombstone therefore outlives both records, without requiring a new
    plan merely to preserve the rejected email.
    """
    if alias.registration_stage == "account_deactivated":
        return True
    model = _job_model()
    if not _has_table(session, model):
        return False
    contexts = session.exec(select(model.context_json).where(
        func.lower(model.context_json).contains(alias.email.lower()))).all()
    for raw in contexts:
        try:
            context = json.loads(raw or "{}")
        except (TypeError, ValueError):
            continue
        evidence = context.get("invite_dead_candidate") if isinstance(context, dict) else None
        if (isinstance(evidence, dict) and evidence.get("confirmed_dead") is True
                and evidence.get("remote_invite_sent") is False
                and type(evidence.get("child_id")) is int and evidence["child_id"] > 0
                and str(evidence.get("email") or "").strip().lower() == alias.email):
            _mark_deactivated(session, alias)
            return True
    return False


def recover_owner(session, alias) -> bool:
    """Release a ended owner's claim without scheduling an unsolicited signup."""
    if not alias.production_job_id:
        return False
    if owner_active(session, alias):
        return True
    if alias.registration_stage == "source_exhausted":
        alias.production_job_id = ""
        session.add(alias)
        return False
    if quarantine_deactivated(session, alias):
        alias.production_job_id = ""
        session.add(alias)
        return False
    from services import gmail_registration as registration
    account, plan = registration._existing(session, alias)
    previous_stage = alias.registration_stage
    registered = registration._sync(session, alias, account, plan)
    alias.production_job_id = ""
    alias.registration_lease_token = ""
    alias.registration_lease_expires_at = None
    alias.registration_retry_at = None
    if registered:
        if previous_stage != "registered":
            alias.registration_stage = "security_paused"
            alias.registration_error = "自动售号任务已结束，已注册账号的后续设置已暂停"
    else:
        alias.registration_status = "paused"
        alias.registration_stage = "production_paused"
        alias.registration_error = "自动售号任务已结束；再次选择此子号时将核对已有注册状态"
    alias.registration_updated_at = store.utcnow()
    session.add(alias)
    return False


def release_owner(session, job_id) -> int:
    """Lazily release only ownership whose durable NV reservation has ended."""
    count = 0
    for alias in session.exec(select(store.GmailAlias).where(
            store.GmailAlias.production_job_id == str(job_id))).all():
        if not recover_owner(session, alias):
            count += 1
    return count


def _historically_used(session, alias, plan, job_id):
    if _has_table(session, GptBusinessChildMembershipModel):
        clauses = [func.lower(GptBusinessChildMembershipModel.email) == alias.email]
        if plan:
            clauses.append(GptBusinessChildMembershipModel.pro_account_id == plan.id)
        if session.exec(select(GptBusinessChildMembershipModel.id).where(or_(*clauses))).first() is not None:
            return True
    from services.nv_order_history import NvSaleOrder
    if _has_table(session, NvSaleOrder):
        clauses = [func.lower(NvSaleOrder.email) == alias.email]
        if plan:
            clauses.append(NvSaleOrder.child_id == plan.id)
        if session.exec(select(NvSaleOrder.id).where(or_(*clauses))).first() is not None:
            return True
    model = _job_model()
    clauses = [func.lower(model.email) == alias.email]
    if plan:
        clauses.append(model.child_id == plan.id)
    for previous in session.exec(select(model).where(model.id != job_id, or_(*clauses))).all():
        if previous.active_child_key or previous.membership_id or previous.remote_user_id:
            return True
        try:
            context = json.loads(previous.context_json or "{}")
        except (TypeError, ValueError):
            return True
        if not isinstance(context, dict) or context.get("invite_attempted") or context.get("invite_confirmed"):
            return True
    return False


def _healthy_shell(session, plan):
    if plan is None:
        return True
    if (not plan.enabled or plan.dangerous or plan.policy_warning or plan.is_pro
            or plan.refund_status or plan.business_parent_id or plan.business_invited_at
            or plan.subscribed_at or plan.pro_expires_at or plan.payment_card_last4
            or plan.catalog_category not in {"", "regular"}
            or plan.source_state not in {"", "regular", "never_logged"}
            or plan.plan_type not in {"", "free"}):
        return False
    if _has_table(session, GptPlanAccountOperationLeaseModel):
        lease = session.get(GptPlanAccountOperationLeaseModel, plan.id)
        if lease and lease.expires_at.replace(tzinfo=timezone.utc) > store.utcnow():
            return False
    return True


def allocate_candidate(session, nv_job, excluded_ids=None, *, _generate=True):
    """Allocate in the caller's NV transaction; caller binds child_id before commit.

    The alias CAS also fences manual registration. No remote work or nested
    transaction is opened here, so the alias and NV child reservation commit
    together or are both rolled back.
    """
    from services import gmail_registration as registration
    from services.gmail_production_policy import can_start
    job_id = str(_value(nv_job, "id", "") or "")
    if not job_id or _value(nv_job, "status") in {"completed", "cancelled"}:
        raise store.GmailStoreError("invalid_production_job", "自动售号任务身份无效", 409)
    excluded = set(excluded_ids or ())
    session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
    rows = session.exec(select(store.GmailAlias, store.GmailSource).join(store.GmailSource,
        store.GmailAlias.source_id == store.GmailSource.id).order_by(store.GmailAlias.id)).all()
    for alias, source in rows:
        if quarantine_deactivated(session, alias):
            if alias.production_job_id and not owner_active(session, alias):
                alias.production_job_id = ""
                session.add(alias)
            continue
        if alias.production_job_id:
            if owner_active(session, alias):
                if alias.production_job_id == job_id:
                    return {"child_id": alias.gpt_plan_account_id, "email": alias.email,
                            "context": {"gmail_production_alias_id": alias.id,
                                        "gmail_production_source_id": alias.source_id}}
                continue
            recover_owner(session, alias)
        if (not registration._ready(source) or not can_start(session, alias, source) or alias.registration_lease_token
                or alias.registration_status not in {"unregistered", "paused"}
                or alias.registration_status == "paused" and alias.registration_stage != "production_paused"
                or alias.registration_retry_at is not None):
            continue
        account, plan = registration._existing(session, alias)
        if (registration._has_registered_identity(account, plan)
                or plan is not None and plan.id in excluded
                or not _healthy_shell(session, plan)
                or _historically_used(session, alias, plan, job_id)):
            continue
        claimed = session.execute(update(store.GmailAlias).where(
            store.GmailAlias.id == alias.id, store.GmailAlias.production_job_id == "",
            store.GmailAlias.registration_lease_token == "",
            store.GmailAlias.registration_status.in_(("unregistered", "paused"))).values(
                production_job_id=job_id, registration_status="reserved", registration_stage="selected",
                registration_error="", registration_retry_at=None, registration_updated_at=store.utcnow()))
        if claimed.rowcount != 1:
            continue
        if plan is None:
            plan = GptPlanAccountModel(email=alias.email, mail_provider="gmail", mail_access_type="imap",
                                       catalog_category="regular", source_state="regular")
        try:
            extra = json.loads(plan.extra_json or "{}")
        except (TypeError, ValueError):
            extra = {}
        extra = extra if isinstance(extra, dict) else {}
        extra.update(mail_provider="gmail", gmail_source_id=alias.source_id, gmail_alias_id=alias.id)
        plan.extra_json = json.dumps(extra, ensure_ascii=False)
        plan.mail_provider, plan.mail_access_type = "gmail", "imap"
        session.add(plan)
        session.flush()
        alias.production_job_id = job_id
        alias.gpt_plan_account_id = plan.id
        session.add(alias)
        return {"child_id": plan.id, "email": alias.email,
                "context": {"gmail_production_alias_id": alias.id,
                            "gmail_production_source_id": alias.source_id}}
    if _generate:
        for source in session.exec(select(store.GmailSource).order_by(store.GmailSource.id)).all():
            if not registration._ready(source) or source.production_blocked:
                continue
            try:
                store.generate_aliases_in_session(session, source.id, count=1, prefix="child")
            except store.GmailStoreError as exc:
                if exc.code in {"source_alias_limit", "source_production_blocked", "source_disabled", "source_unverified"}:
                    continue
                raise
            return allocate_candidate(session, nv_job, excluded_ids, _generate=False)
    return None


def _context(job):
    value = _value(job, "context")
    if value is None:
        try:
            value = json.loads(_value(job, "context_json", "{}") or "{}")
        except (TypeError, ValueError):
            value = {}
    return value if isinstance(value, dict) else {}


def _owned_alias(session, job, *, final=False):
    job_id = str(_value(job, "id", "") or "")
    if not job_id:
        return None
    session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
    alias = session.exec(select(store.GmailAlias).where(store.GmailAlias.production_job_id == job_id)).first()
    if alias is None:
        if _context(job).get("gmail_production_alias_id"):
            raise store.GmailStoreError("stale_production", "Gmail 自动售号子号归属已变化", 409)
        return None
    saved_job = session.get(_job_model(), job_id)
    token = _value(job, "worker_token", "")
    if (not owner_active(session, alias) or not saved_job or saved_job.status != "running"
            or not isinstance(token, str) or not token or saved_job.worker_token != token
            or alias.gpt_plan_account_id != _value(job, "child_id")
            or alias.email != str(_value(job, "email", "") or "").strip().lower()
            or any(_context(owner).get("gmail_production_alias_id") != alias.id
                   or _context(owner).get("gmail_production_source_id") != alias.source_id
                   for owner in (job, saved_job))):
        raise store.GmailStoreError("stale_production", "Gmail 自动售号子号归属已变化", 409)
    # Each stage callback precedes further browser work. A pause must stop the
    # next stage, while the matching running worker may still record evidence
    # already saved by the last browser action through complete_preparation.
    if not final and saved_job.pause_requested:
        raise store.GmailStoreError("production_paused", "自动售号任务已请求暂停，已停止后续注册与安全设置", 409)
    if not final and not _source_ready(session, alias):
        raise store.GmailStoreError("receive_not_ready", "Gmail 母号已停用或收件授权不可用，等待恢复后继续", 409)
    return alias


def _source_ready(session, alias):
    from services import gmail_registration as registration
    return registration._ready(session.get(store.GmailSource, alias.source_id))


def _record_preparation(job, stage, details, *, final=False):
    from services import gmail_registration as registration
    details = details if isinstance(details, dict) else {}
    with Session(store.engine) as session:
        if not _has_table(session, store.GmailAlias):
            return {}
        alias = _owned_alias(session, job, final=final)
        if alias is None:
            return {}
        if alias.registration_stage == "source_exhausted":
            if final:
                return store._alias_dto(alias)
            raise store.GmailStoreError("source_production_blocked", "此 Gmail 母号已停止新号生产，自动改选其他母号", 409)
        if final and (details.get("ok") is False
                      and details.get("error_code") == "gmail_source_exhausted"
                      and details.get("source_error_code") == "user_already_exists"):
            from services.gmail_production_policy import mark_source_exhausted
            mark_source_exhausted(session, alias)
            session.commit()
            return store._alias_dto(alias)
        confirmed_dead = (details.get("dead") is True
                          and details.get("error_code") == "account_deactivated")
        if final and confirmed_dead:
            _mark_deactivated(session, alias)
            session.commit()
            return store._alias_dto(alias)
        if alias.registration_stage == "account_deactivated":
            raise store.GmailStoreError("account_deactivated", "GPT 子号已明确停用，不能继续注册或邀请", 409)
        account, plan = registration._existing(session, alias)
        registered = registration._sync(session, alias, account, plan)
        complete = (details.get("ok") is True and details.get("registered_verified") is True
                    and details.get("security_confirmed") is True)
        if final and complete and not registered:
            raise store.GmailStoreError("production_registration_unverified", "尚未保存 Gmail 子号的注册身份依据", 409)
        if registered:
            alias.registration_stage = "registered" if complete else ("security_pending" if final else "security")
            alias.registration_error = "" if not final or complete else "已注册，密码或 2FA 尚未完成，由自动售号任务继续"
        else:
            alias.registration_status = "retry_pending" if final else "registering"
            alias.registration_stage = "resume_login" if final else "verification" if stage == "verification" else "registering"
            alias.registration_error = "注册或登录确认尚未完成，由自动售号任务继续" if final else ""
        # The NV lifecycle exclusively schedules production retries.
        alias.registration_retry_at = None
        alias.registration_updated_at = store.utcnow()
        session.add(alias)
        session.commit()
        return store._alias_dto(alias)


def mark_preparation(job, stage, details=None):
    return _record_preparation(job, stage, details)


def complete_preparation(job, result):
    return _record_preparation(job, "ready", result, final=True)


def candidate_rejection(job):
    """Read durable policy before opening a browser, including crash recovery."""
    from services.gmail_production_policy import within_alias_limit
    context = _context(job)
    if not context.get("gmail_production_alias_id"):
        return False
    with Session(store.engine) as session:
        alias = session.get(store.GmailAlias, context["gmail_production_alias_id"])
        if (not alias or alias.production_job_id != _value(job, "id")
                or alias.gpt_plan_account_id != _value(job, "child_id")
                or alias.email != _value(job, "email")):
            return False
        source = session.get(store.GmailSource, alias.source_id)
        return bool(source and (source.production_blocked or not within_alias_limit(session, alias)))
