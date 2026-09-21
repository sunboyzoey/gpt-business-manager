"""Journaled renewal of an existing, unsold 5X inventory card.

The journal is the mutation fence: after ``submitted_at`` is written, recovery
only reads NV. Frozen listing terms change together with the membership, after
the same inventory card proves the exact requested deadline.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fastapi import HTTPException
import socket
import time
import uuid

from sqlalchemy import Column, String, inspect
from sqlmodel import Field, Session, SQLModel, select

from core.db import (GptBusinessAccountModel as Mother,
                     GptBusinessChildMembershipModel as Membership,
                     GptPlanAccountModel as Account)
from services import nv_automation_store as store
from services import nv_automation_capabilities as caps
from services import nexusvault as nv
from services import nv_listing_renewal_remote as remote
from services.nv_listing_warranty import _normalize_hours, normalize_team5x_warranty


class RenewalStateError(RuntimeError):
    """A credential-free local identity or lifecycle diagnostic."""


class NvListingRenewal(SQLModel, table=True):
    __tablename__ = "nv_listing_renewals"
    id: str = Field(primary_key=True)
    request_id: str = Field(index=True, unique=True)
    job_id: str = Field(index=True)
    origin: str = "manual"
    status: str = Field(default="queued", index=True)
    active_key: str | None = Field(default=None, sa_column=Column(String, unique=True))
    requested_version: int = 0
    old_until: str
    new_until: str = ""
    card_id: str = ""
    remote_card_id: str = ""
    price_yuan: str = ""
    identity_json: str = "{}"
    error: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    submitted_at: float = 0
    confirmed_at: float = 0


def _date(value):
    return caps._date(value)


def _deadline(context):
    frozen = context.get("team5x_warranty")
    basis = context.get("existing_listing")
    value = frozen.get("until") if isinstance(frozen, dict) and frozen.get("mode") == "until" else None
    return _date(value or (basis.get("nv_team5x_warranty_until") if isinstance(basis, dict) else None))


def _has_table(session):
    return inspect(session.connection()).has_table(NvListingRenewal.__tablename__)


def _latest(session, job_id):
    return session.exec(select(NvListingRenewal).where(NvListingRenewal.job_id == job_id)
                        .order_by(NvListingRenewal.created_at.desc(), NvListingRenewal.id.desc())).first()


def _identity(job, member):
    context = store._decode(job.context_json)
    return {**{key: getattr(job, key) for key in (
        "parent_account_id", "source_account_id", "parent_email", "child_id",
        "email", "membership_id", "remote_user_id", "seat_type",
    )}, "invited_at": caps._iso(_date(member.invited_at)),
        "listed_at": caps._iso(_date(member.nv_listed_at)),
        "confirmed_at": caps._iso(_date(member.nv_listing_confirmed_at)),
        "card_id": member.nv_remote_card_id,
        "listing_cycle_id": context.get("listing_cycle_id", "")}


def _member_locked(session, job, *, require_health=True):
    """Repeat the immutable local identity check inside every write fence."""
    tables = inspect(session.connection())
    if any(not tables.has_table(model.__tablename__) for model in (Account, Mother, Membership)):
        raise RenewalStateError("无法核对当前母号与子号归属，未提交续期")
    parent = session.get(Account, job.parent_account_id)
    mother = session.get(Mother, job.source_account_id)
    child = session.get(Account, job.child_id)
    member = session.get(Membership, job.membership_id)
    email = caps._email
    if (parent is None or mother is None or child is None or member is None
            or parent.source_pool != "gpt_business" or parent.source_account_id != mother.id
            or parent.business_parent_id is not None
            or email(parent.email) != email(job.parent_email) or email(mother.email) != email(job.parent_email)
            or member.business_account_id != mother.id or member.pro_account_id != child.id
            or child.business_parent_id != mother.id or member.source != "pool"
            or member.ended_at is not None or not email(job.email)
            or email(child.email) != email(job.email) or email(member.email) != email(job.email)
            or not caps._identifier(job.remote_user_id) or member.remote_user_id != job.remote_user_id
            or member.seat_type != "prolite" or job.seat_type != "prolite"):
        raise RenewalStateError("续期的母号、子号或席位归属已变化")
    if require_health:
        if store._mother_dead_reason(session, job.parent_account_id, job.source_account_id):
            raise RenewalStateError(store.DEAD_MOTHER_REASON)
        if (not parent.enabled or not mother.enabled or not child.enabled or child.dangerous
                or parent.policy_warning or mother.policy_warning or child.policy_warning):
            raise RenewalStateError("母号或子号已停用或存在告警，不能续期")
        if (any(str(account.refund_status or "").strip() in {
                "refunded", "refunded_pending_credit", "refund_credited"}
                for account in (parent, mother, child))
                or any(str(account.catalog_category or "").strip() == "refunded"
                       for account in (parent, child))):
            raise RenewalStateError("母号或子号已经退款，不能续期")
    context = store._decode(job.context_json)
    listed = _date(context.get("nv_listed_at"))
    basis = context.get("existing_listing")
    # Newly invited children freeze their membership cycle during OAuth;
    # adopted listings instead carry membership_invited_at. Accept either
    # historic proof, but never let a valid fallback hide conflicting or
    # malformed evidence (or invent proof from today's membership row).
    invited_evidence = [context.get("membership_invited_at"),
                        context.get("oauth_membership_invited_at")]
    if isinstance(basis, dict):
        listed = listed or _date(basis.get("nv_listed_at"))
        invited_evidence.append(basis.get("membership_invited_at"))
    invited_dates = [_date(value) for value in invited_evidence if value is not None and value != ""]
    invited = _date(member.invited_at)
    if not invited_dates or invited is None or any(value != invited for value in invited_dates):
        raise RenewalStateError("本次上架缺少一致的邀请周期证据，未提交续期")
    frozen_card = context.get("nv_remote_card_id") or (basis.get("nv_remote_card_id") if isinstance(basis, dict) else "")
    if (not listed
            or listed != _date(member.nv_listed_at) or not member.nv_listing_confirmed_at
            or not frozen_card or frozen_card != member.nv_remote_card_id
            or _deadline(context) is None or _deadline(context) != _date(member.nv_team5x_warranty_until)):
        raise RenewalStateError("本次上架的成员周期、卡片或冻结截止已变化")
    return member


def _eligible(session, job, settings, *, allow_running=False, require_expired=True):
    if job is None:
        raise KeyError("子号任务不存在")
    if (job.parent_account_id not in settings.get("mother_ids", [])
            or job.parent_account_id in settings.get("paused_mother_ids", [])):
        raise RenewalStateError("母号未管理或已暂停，不能续期")
    if (job.step not in {"wait_sale", "renew"} or job.status in {"completed", "cancelled", "paused"}
            or job.pause_requested or (not allow_running and (job.worker_token or job.worker_pid or job.status == "running"))):
        raise RenewalStateError("当前任务状态不支持续期，请先等待原任务结束")
    member = _member_locked(session, job)
    context = store._decode(job.context_json)
    if member.sale_status != "listed" or member.sold_at or context.get("sold_at") or context.get("sale_confirmed"):
        raise RenewalStateError("账号已售出或尚未确认上架，不能续期")
    if require_expired and _deadline(context) > caps._now():
        raise RenewalStateError("本次上架尚未到期，不能续期")
    _normalize_hours(settings.get("team5x_warranty_hours"))
    return member


def public_status(job, session=None):
    """Project server evidence conservatively; never initialize missing tables."""
    context = store._decode(job.context_json)
    deadline = _deadline(context)
    if job.seat_type != "prolite" and deadline is None:
        return None
    base = dict(status="unknown", can_renew=False, readback_only=False, reason="上架状态尚未完成核对",
                last_renewed_at=None, renewal_count=0, expires_at=caps._iso(deadline) or None)
    if session is None:
        with Session(store.engine) as local:
            return public_status(job, session=local)
    if not _has_table(session):
        return base
    rows = session.exec(select(NvListingRenewal).where(NvListingRenewal.job_id == job.id)
                        .order_by(NvListingRenewal.created_at.desc(), NvListingRenewal.id.desc())).all()
    confirmed = [row for row in rows if row.status == "confirmed"]
    base["renewal_count"] = len(confirmed)
    base["last_renewed_at"] = store._iso(max((row.confirmed_at for row in confirmed), default=0))
    settings = store._settings(session.get(store.NvAutomationSettings, 1))
    if context.get("sold_at") or context.get("sale_confirmed"):
        return {**base, "status": "sold", "reason": "账号已售出"}
    latest = rows[0] if rows else None
    confirmed_recovery = bool(latest and latest.status == "confirmed" and job.step == "renew")
    if latest and (latest.status in {"queued", "submitted", "review"} or confirmed_recovery):
        base["readback_only"] = bool(latest.submitted_at or confirmed_recovery)
        status = "review" if (latest.status == "review" or job.status in {"review", "failed"}
                              or base["readback_only"] and job.status == "paused") else "renewing"
        if latest.status == "queued" and latest.origin == "auto" and (
                settings.get("enabled") is not True or settings.get("team5x_auto_renew") is not True):
            status = "failed"
        base.update(status=status, reason=latest.error or ("仅核对此次续期结果，不会重复提交" if status == "review" else "续期已排队或正在处理"))
        if status == "failed":
            base["reason"] = "自动续期已关闭，可手动请求续期"
        if status in {"review", "failed"} or (latest.status == "queued" and not (
                job.worker_token or job.worker_pid or job.status == "running")):
            try:
                if latest.submitted_at:
                    _member_locked(session, job, require_health=False)
                    if job.worker_token or job.worker_pid or job.status == "running":
                        raise RenewalStateError("正在核对")
                else:
                    _eligible(session, job, settings)
                base["can_renew"] = True
            except (RuntimeError, ValueError, KeyError):
                pass
        return base
    if latest and latest.status == "rejected":
        base.update(status="failed", reason=latest.error or "上次续期未完成，可手动重试")
    else:
        if job.status in {"review", "failed"}:
            return {**base, "reason": store.safe_message(job.error) or "最新 NV 状态核对失败，不能确认仍在售"}
        synced = _date(context.get("nv_last_synced_at"))
        freshness = max(120, min(3600, 2 * int(settings.get("scan_interval_seconds", 300))))
        if deadline is None or synced is None or not 0 <= (caps._now() - synced).total_seconds() <= freshness:
            return base
        try:
            member = _member_locked(session, job, require_health=False)
            if (job.step != "wait_sale" or job.status in {"completed", "cancelled"}
                    or member.sale_status != "listed" or member.sold_at):
                raise RenewalStateError("当前任务或成员状态已变化，不能确认仍在售")
        except (RuntimeError, ValueError, KeyError) as error:
            return {**base, "reason": str(error)}
        base.update(status="expired" if deadline <= caps._now() else "listed", reason="")
    try:
        _eligible(session, job, settings)
        base["can_renew"] = True
    except (RuntimeError, ValueError, KeyError) as error:
        if base["status"] != "listed":
            base["reason"] = str(error)
    return base


def _queue(session, job, request_id, settings, *, automatic):
    current = session.exec(select(NvListingRenewal).where(NvListingRenewal.active_key == str(job.id))).first()
    if current is None and job.step == "renew":
        latest = _latest(session, job.id)
        if latest and latest.status == "confirmed":
            current = latest
    if current:
        if not automatic:
            if job.worker_token or job.worker_pid or job.status == "running":
                return current
            readonly = bool(current.submitted_at or current.status == "confirmed")
            if readonly:
                _member_locked(session, job, require_health=False)
            else:
                _eligible(session, job, settings)
                if current.origin != "manual":
                    current.origin, current.updated_at = "manual", time.time()
                    session.add(current)
            # A failed launcher or process death before POST can leave the
            # journal queued while the owning task is review/failed. Reuse it.
            if job.status not in {"pending", "retry"} or job.reconcile_requested != readonly:
                job.step, job.status = "renew", "pending"
                job.reconcile_requested, job.next_run_at = readonly, time.time()
                job.pause_requested, job.error = False, ""
                job.version += 1
                job.updated_at = time.time()
                session.add(job)
        return current
    member = _eligible(session, job, settings)
    if automatic and (settings.get("enabled") is not True or settings.get("team5x_auto_renew") is not True):
        raise RenewalStateError("自动续期未开启")
    now = time.time()
    row = NvListingRenewal(id=request_id, request_id=request_id, job_id=job.id,
        active_key=str(job.id), origin="auto" if automatic else "manual", requested_version=job.version,
        old_until=caps._iso(_deadline(store._decode(job.context_json))),
        remote_card_id=member.nv_remote_card_id, identity_json=store._json(_identity(job, member)),
        created_at=now, updated_at=now)
    session.add(row)
    job.step, job.status, job.next_run_at = "renew", "pending", now
    job.reconcile_requested, job.error = False, ""
    job.version += 1
    job.updated_at = now
    session.add(job)
    store._log(session, job, "自动续期已排队" if automatic else "手动续期已排队")
    return row


def request(job_id, version, request_id, automatic=False):
    try:
        identifier = str(uuid.UUID(request_id)) if isinstance(request_id, str) else ""
    except (ValueError, AttributeError):
        identifier = ""
    if not identifier or identifier != request_id.lower():
        raise ValueError("续期请求编号必须是有效 UUID")
    if type(version) is not int or not 0 <= version <= 9007199254740991:
        raise ValueError("任务版本无效，请刷新后重试")
    with store.transaction() as session:
        job = session.get(store.NvAutomationJob, str(job_id))
        if job is None:
            raise KeyError("子号任务不存在")
        replay = session.get(NvListingRenewal, identifier)
        if replay:
            if replay.job_id != job.id:
                raise RenewalStateError("续期请求编号已用于其他任务")
            latest = _latest(session, job.id)
            if (latest and latest.id == replay.id and latest.status in {"queued", "submitted", "review", "confirmed"}
                    and job.step == "renew" and job.status in {"review", "failed", "paused"}):
                _queue(session, job, identifier, store._settings(store._settings_row(session)), automatic=automatic)
        else:
            if job.version != version:
                raise RenewalStateError("任务状态已更新，请刷新后重试")
            settings = store._settings(store._settings_row(session))
            _queue(session, job, identifier, settings, automatic=automatic)
        session.flush()
        result = store._public(job)
    return result


def claim():
    """Share worker capacity, mother execution locks, and scan exclusion."""
    with Session(store.engine) as probe:
        if not _has_table(probe):
            return None
    with store.transaction() as session:
        configuration = store._settings_row(session)
        settings = store._settings(configuration)
        if configuration.scan_token:
            return None
        running = session.exec(select(store.NvAutomationJob).where(store._occupied_worker_clause())).all()
        if len(running) >= min(10, settings["max_concurrent"]):
            return None
        parents = {row.parent_account_id for row in running}
        now = time.time()
        rows = session.exec(select(store.NvAutomationJob).where(
            store.NvAutomationJob.step == "renew", store.NvAutomationJob.status.in_(["pending", "retry"]),
            store.NvAutomationJob.next_run_at <= now).order_by(store.NvAutomationJob.next_run_at)).all()
        for job in rows:
            journal = _latest(session, job.id)
            if not journal or journal.status == "rejected" or job.parent_account_id in parents:
                continue
            readback_only = bool(journal.submitted_at or journal.status == "confirmed")
            if job.worker_token or job.worker_pid:
                continue
            if not readback_only and (job.parent_account_id not in settings["mother_ids"]
                    or job.parent_account_id in settings["paused_mother_ids"] or job.pause_requested
                    or store._mother_dead_reason(session, job.parent_account_id, job.source_account_id)):
                continue
            if not readback_only and journal.origin == "auto" and (
                    settings.get("enabled") is not True or settings.get("team5x_auto_renew") is not True):
                continue
            if session.exec(select(store.NvAutomationJob.id).where(
                    store.NvAutomationJob.active_parent_key == str(job.parent_account_id),
                    store.NvAutomationJob.id != job.id)).first():
                continue
            job.reconcile_requested = bool(job.reconcile_requested or journal.submitted_at or journal.status == "confirmed")
            job.active_parent_key = str(job.parent_account_id)
            job.status, job.worker_token = "running", uuid.uuid4().hex
            job.worker_pid, job.worker_host = 0, socket.gethostname()
            job.heartbeat_at = job.step_started_at = job.updated_at = now
            job.attempts += 1
            job.version += 1
            job.operation_id = uuid.uuid4().hex
            session.add(job)
            session.add(store.NvAutomationStep(id=job.operation_id, job_id=job.id, step="renew", attempts=job.attempts))
            store._log(session, job, "开始核对续期结果" if job.reconcile_requested else "开始续期前核对")
            return store._worker(job, settings)
    return None


def enqueue_automatic():
    """One local enqueue per old deadline; failures never create retry loops."""
    with Session(store.engine) as probe:
        if not _has_table(probe):
            return 0
    count = 0
    with store.transaction() as session:
        settings = store._settings(store._settings_row(session))
        if settings.get("enabled") is not True or settings.get("team5x_auto_renew") is not True:
            return 0
        jobs = session.exec(select(store.NvAutomationJob).where(
            store.NvAutomationJob.step == "wait_sale", store.NvAutomationJob.seat_type == "prolite",
            store.NvAutomationJob.status == "waiting")).all()
        for job in jobs:
            state = public_status(job, session=session)
            if not state or state["status"] != "expired" or not state["can_renew"]:
                continue
            old = _deadline(store._decode(job.context_json))
            history = session.exec(select(NvListingRenewal).where(NvListingRenewal.job_id == job.id)).all()
            if any(_date(row.old_until) == old for row in history):
                continue
            _queue(session, job, str(uuid.uuid4()), settings, automatic=True)
            count += 1
    return count


def _stop(job, journal_id, error, *, rejected=False):
    with store.transaction() as session:
        current = store._owned(session, job["id"], job["worker_token"])
        row = session.get(NvListingRenewal, journal_id)
        if row is None or row.job_id != current.id:
            raise RenewalStateError("续期请求记录已变化")
        if row.status == "confirmed":
            row.error, row.updated_at = error, time.time()
            session.add(row)
            return {"outcome": "review", "error": "续期截止已确认，后续出售状态待核对：" + error}
        row.status = "rejected" if rejected else "review"
        row.error, row.updated_at = error, time.time()
        if rejected:
            row.active_key = None
        session.add(row)
    return {"outcome": "failed" if rejected else "review", "error": error}


def _inventory(job, snapshot, journal=None):
    if snapshot.inventory_complete is not True:
        raise RenewalStateError("NV 库存未完整读取，续期结果待核对")
    email = caps._email(job["email"])
    cards = [row for row in snapshot.inventory_records if caps._email(row.email) == email]
    if len(cards) != 1:
        raise RenewalStateError("NV 未返回唯一原库存卡片，续期结果待核对")
    card = cards[0]
    if not caps._identifier(card.inventory_card_id):
        raise RenewalStateError("NV 未确认原库存账号 ID，未提交续期")
    if journal is not None and card.inventory_card_id != journal.card_id:
        raise RenewalStateError("NV 库存账号已变化，未确认续期")
    if caps._email(job["email"]) in {caps._email(value) for value in snapshot.unconfirmed_sold_emails}:
        raise RenewalStateError("NV 出售状态尚未确认，续期待核对")
    return card


def _readback(job, journal, snapshot):
    """Verify the exact deadline and same native card before the trusted write."""
    card = _inventory(job, snapshot, journal)
    deadline = _date(journal.new_until)
    if deadline is None or _date(card.team5x_warranty_until) != deadline:
        raise RenewalStateError("NV 尚未确认本次续期目标截止，保留原截止等待核对")
    price_cents = card.pool_price_cents if card.status == "sold" else card.price_cents
    if type(price_cents) is not int or Decimal(price_cents) / 100 != Decimal(journal.price_yuan):
        raise RenewalStateError("NV 续期后价格与提交记录不一致，等待核对")
    if card.status == "available":
        if (card.health_status != "healthy" or card.archived is not False or card.sold_at is not None
                or getattr(card, "fallback_pool_only", None) is not False):
            raise RenewalStateError("NV 续期卡片当前不可售，等待核对")
        # Cycle matching still checks all original IDs, original first-listing
        # time and any sale conflicts. Only the separately proven new deadline
        # is projected back for this immutable-old-terms validation.
        projected = replace(snapshot, inventory_records=tuple(
            replace(row, team5x_warranty_until=_date(journal.old_until)) if row is card else row
            for row in snapshot.inventory_records))
        evidence = caps._cycle_evidence(job, projected)
        if evidence["status"] != "available" or evidence["nv_remote_card_id"] != journal.remote_card_id:
            raise RenewalStateError("NV 原卡片身份无法确认，等待核对")
        return
    if card.status != "sold":
        raise RenewalStateError("NV 续期后卡片状态未知，等待核对")
    # A sale racing the POST must carry this request's exact new terms, a
    # timestamp after submission, and a fully corroborated card/order identity.
    floor = _date(store._decode(journal.identity_json).get("listed_at"))
    sold = [row for row in snapshot.sold_records if caps._email(row.email) == caps._email(job["email"])
            and _date(row.sold_at) is not None and _date(row.sold_at) >= floor]
    times = {_date(row.sold_at) for row in sold}
    orders = {caps._identifier(row.remote_order_id) for row in sold}
    submitted = datetime.fromtimestamp(journal.submitted_at, timezone.utc)
    if (not sold or len(times) != 1 or len(orders) != 1 or "" in orders
            or not submitted <= next(iter(times)) <= min(caps._now(), deadline)
            or _date(card.sold_at) != next(iter(times))
            or any(_date(row.team5x_warranty_until) != deadline for row in sold)):
        raise RenewalStateError("续期期间出售的时间、订单或新截止未完整匹配，等待核对")
    identity = caps._cycle_card_identity(job, snapshot, caps._email(job["email"]), floor, sold)
    valid_ids = {journal.remote_card_id, journal.card_id}
    if identity:
        if identity["inventory_card_id"] != journal.card_id:
            raise RenewalStateError("续期出售记录关联到其他库存账号")
        valid_ids.add(identity["order_card_id"])
    if (caps._identifier(card.remote_card_id) not in valid_ids
            or any(caps._identifier(row.remote_card_id) not in valid_ids for row in sold)
            or (card.remote_order_id and caps._identifier(card.remote_order_id) not in orders)):
        raise RenewalStateError("续期出售记录的原卡片或订单身份不一致")


def execute(job, emit, checkpoint, reconcile=False):
    """Perform at most one POST; an existing submission is read-back only."""
    with Session(store.engine) as session:
        journal = _latest(session, job["id"])
        if journal is None:
            return {"outcome": "review", "error": "缺少续期请求记录，未发送请求"}
        session.expunge(journal)
    try:
        caps._member(job, require_remote=True)
        if journal.status == "confirmed":
            return caps._reconcile_nv(job, nv.fetch_sales_snapshot(include_inventory=True))
        if journal.status == "rejected":
            return {"outcome": "failed", "error": journal.error or "上次续期已明确失败，请重新提交人工请求"}
        if not journal.submitted_at:
            snapshot = nv.fetch_sales_snapshot(include_inventory=True)
            evidence = caps._cycle_evidence(job, snapshot)
            if evidence["status"] == "sold":
                # Sale won the race before our POST: preserve original terms
                # and let the existing sale lifecycle consume the evidence.
                _stop(job, journal.id, "续期前已确认售出，未发送续期", rejected=True)
                return caps._reconcile_nv(job, snapshot)
            card = _inventory(job, snapshot)
            if (evidence["status"] != "available" or evidence["nv_remote_card_id"] != journal.remote_card_id
                    or card.status != "available" or card.health_status != "healthy" or card.archived is not False
                    or getattr(card, "fallback_pool_only", None) is not False
                    or card.sold_at is not None or _date(card.team5x_warranty_until) != _date(journal.old_until)
                    or type(card.price_cents) is not int or not 1 <= card.price_cents <= 99999999):
                raise RenewalStateError("NV 原卡片未确认到期未售、健康及当前价格，未提交续期")
            # Parent action policy applies only to a new mutation, after the
            # read-only sale preflight and immediately before its write fence.
            caps._assert_parent(job, require_action=True)
            with store.transaction() as session:
                current = store._owned(session, job["id"], job["worker_token"])
                row = session.get(NvListingRenewal, journal.id)
                settings = store._settings(store._settings_row(session))
                member = _eligible(session, current, settings, allow_running=True)
                if (row is None or row.status not in {"queued", "review"} or row.submitted_at
                        or _identity(current, member) != store._decode(row.identity_json)
                        or _date(row.old_until) != _deadline(store._decode(current.context_json))):
                    raise RenewalStateError("续期身份或提交记录已变化，未重复提交")
                if row.origin == "auto" and (settings.get("enabled") is not True or settings.get("team5x_auto_renew") is not True):
                    raise RenewalStateError("自动续期已关闭，未提交续期")
                now = caps._now()
                terms = normalize_team5x_warranty({"mode": "until", "until":
                    (now + timedelta(hours=_normalize_hours(settings.get("team5x_warranty_hours")))).isoformat()}, now=now)
                row.new_until, row.card_id = terms["until"], card.inventory_card_id
                row.price_yuan = f"{Decimal(card.price_cents) / 100:.2f}"
                row.status, row.submitted_at, row.updated_at = "submitted", now.timestamp(), time.time()
                session.add(row)
                session.flush()
                journal = NvListingRenewal.model_validate(row.model_dump())
            emit("已记录原卡片续期请求，提交后将核对 NV 实际截止")
            try:
                remote.renew_existing_card(inventory_card_id=journal.card_id,
                    price_yuan=journal.price_yuan, warranty_until=journal.new_until)
            except (remote.RenewalRejected, remote.RenewalValidationError, remote.RenewalConfigurationError) as error:
                return _stop(job, journal.id, store.safe_message(error), rejected=True)
            except Exception:
                # Even unexpected exceptions can occur after sending bytes.
                # The durable marker permanently forbids another POST.
                emit("续期提交结果尚未确认，正在只读核对原卡片")
        snapshot = nv.fetch_sales_snapshot(include_inventory=True)
        _readback(job, journal, snapshot)
        with store.transaction() as session:
            current = store._owned(session, job["id"], job["worker_token"])
            row = session.get(NvListingRenewal, journal.id)
            member = _member_locked(session, current, require_health=False)
            if (row is None or row.status not in {"submitted", "review"} or not row.submitted_at
                    or row.new_until != journal.new_until or row.card_id != journal.card_id
                    or _identity(current, member) != store._decode(row.identity_json)
                    or member.sale_status != "listed" or member.sold_at
                    or _date(member.nv_team5x_warranty_until) != _date(row.old_until)):
                raise RenewalStateError("续期核对后本地周期已变化，未写回新截止")
            context = store._decode(current.context_json)
            context["team5x_warranty"] = {"mode": "until", "until": row.new_until}
            if isinstance(context.get("existing_listing"), dict):
                context["existing_listing"] = {**context["existing_listing"], "nv_team5x_warranty_until": row.new_until}
            context["nv_last_synced_at"] = caps._iso(caps._now())
            # This narrow, proven renewal path is the only intentional bypass
            # of the generic checkpoint's immutable-warranty protection.
            current.context_json = store._json(context)
            current.version += 1
            current.updated_at = time.time()
            member.nv_team5x_warranty_until = _date(row.new_until)
            member.nv_last_synced_at = caps._now()
            member.updated_at = caps._now()
            row.status, row.active_key, row.error = "confirmed", None, ""
            row.confirmed_at = row.updated_at = time.time()
            session.add(current)
            session.add(member)
            session.add(row)
            job["context"] = context
        emit("已核对原卡片续期截止，继续核对出售状态")
        return caps._reconcile_nv(job, snapshot)
    except Exception as error:
        if isinstance(error, (RenewalStateError, remote.RenewalError)):
            detail = store.safe_message(error)
        elif isinstance(error, HTTPException):
            detail = store.safe_message(f"HTTP {error.status_code}：{error.detail}")
        else:
            detail = f"续期核对暂时失败（{type(error).__name__}）"
        return _stop(job, journal.id, f"{detail}；未重复发送请求")
