"""Durable, explicitly requested repricing of *existing* unsold NV listings.

This worker never invites, authenticates, lists, sells or removes accounts. It
uses the same journalled single-card operation as the manual price editor. A
batch freezes the changed tier prices and exact local listing identities. Each
item is independent; an uncertain PATCH is read back, never blindly replayed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import socket
import threading
import time
import uuid

from fastapi import HTTPException
from sqlmodel import Field, Session, SQLModel, func, select

from services import nv_automation_store as store
from services.nv_tier_policy import TIERS, TIER_LABELS, job_policy, price_for_tier

ACTIVE = ("queued", "running")
TERMINAL = ("completed", "paused")
ITEM_DONE = ("succeeded", "failed", "skipped", "review")
_thread_lock = threading.Lock()
_thread = None
_stop = threading.Event()
_wake = threading.Event()


class NvPriceBatch(SQLModel, table=True):
    __tablename__ = "nv_price_batches"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    request_id: str = Field(index=True, unique=True)
    requested_prices_json: str = "{}"
    prices_json: str = "{}"
    status: str = Field(default="queued", index=True)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    owner_token: str = ""
    owner_pid: int = 0
    owner_host: str = ""


class NvPriceBatchItem(SQLModel, table=True):
    __tablename__ = "nv_price_batch_items"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    batch_id: str = Field(index=True)
    ordinal: int = 0
    job_id: str = Field(index=True)
    email: str = ""
    parent_account_id: int = 0
    parent_email: str = ""
    policy_tier: str = "unknown"
    price_yuan: str = ""
    guard_json: str = "{}"
    status: str = Field(default="queued", index=True)
    mode: str = "edit"
    message: str = "等待串行处理"
    logs_json: str = "[]"
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class NvPriceBatchNotice(SQLModel, table=True):
    """UI acknowledgement of one exact batch version; never worker state."""
    __tablename__ = "nv_price_batch_notices"
    batch_id: str = Field(primary_key=True)
    batch_updated_at: float
    dismissed_at: float = Field(default_factory=time.time)


def init_tables():
    SQLModel.metadata.create_all(store.engine, tables=[
        NvPriceBatch.__table__, NvPriceBatchItem.__table__, NvPriceBatchNotice.__table__,
    ])


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _context(job):
    return store._decode(job.context_json)


def _identity(job):
    return {key: getattr(job, key) for key in (
        "id", "parent_account_id", "source_account_id", "child_id", "membership_id",
        "email", "remote_user_id", "seat_type",
    )}


def _fingerprint(ctx):
    # Exclude routine scan timestamps/versions, but never overlook an intervening
    # manual price edit, a changed listing cycle or a different remote card.
    fields = ("price_yuan", "nv_price_override", "nv_price_confirmed", "nv_price_sale_unverified",
              "listing_cycle_id", "nv_listing_started_at", "nv_listed_at", "publish_started_at",
              "nv_remote_card_id", "nv_card_id", "existing_listing", "publish_attempted",
              "publish_confirmed")
    return hashlib.sha256(store._json({key: ctx.get(key) for key in fields}).encode()).hexdigest()


def _guard(job, tier, item_id):
    return dict(identity=_identity(job), tier=tier, fingerprint=_fingerprint(_context(job)), batch_item_id=item_id)


def _listed(job, ctx):
    return (job.step == "wait_sale" and job.status not in store.TERMINAL_STATUSES
            and bool(ctx.get("publish_attempted") or ctx.get("existing_listing"))
            and not ctx.get("sold_at") and not ctx.get("sale_confirmed"))


def validate_guard(job, guard):
    """Also called inside single-card CAS, immediately before its PATCH journal."""
    ctx = _context(job)
    if _identity(job) != guard.get("identity"):
        raise HTTPException(409, "账号或本次上架身份已变化，已跳过批量改价")
    if not _listed(job, ctx):
        raise HTTPException(409, "账号已非本次待售上架状态，已跳过批量改价")
    if job.worker_token or job.status == "running":
        raise HTTPException(409, "账号任务正在执行，已跳过批量改价")
    if job_policy(job, ctx)[0] != guard.get("tier"):
        raise HTTPException(409, "账号价格档位已变化或待核验，已跳过批量改价")
    pending = ctx.get("nv_price_edit") or {}
    if pending and pending.get("batch_item_id") != guard.get("batch_item_id"):
        raise HTTPException(409, "账号已有另一项待核对改价，未覆盖原操作")
    if _fingerprint(ctx) != guard.get("fingerprint"):
        raise HTTPException(409, "账号价格或上架记录在保存后已被修改，未覆盖人工改价")


def _log(item, message):
    item.updated_at = time.time()
    item.message = store.safe_message(message)
    try:
        import json
        logs = json.loads(item.logs_json)
    except (ValueError, TypeError):
        logs = []
    if not isinstance(logs, list):
        logs = []
    logs.append(dict(at=_iso(item.updated_at), message=item.message))
    item.logs_json = store._json(logs[-40:])


def _public(session, batch, *, rows=None, notices=None):
    import json
    if rows is None:
        rows = session.exec(select(NvPriceBatchItem).where(NvPriceBatchItem.batch_id == batch.id)
                            .order_by(NvPriceBatchItem.ordinal, NvPriceBatchItem.id)).all()
    notice = (session.get(NvPriceBatchNotice, batch.id) if notices is None else notices.get(batch.id))
    counts = {key: sum(row.status == key for row in rows) for key in ITEM_DONE}
    processed = sum(counts.values())
    items = [dict(id=row.id, job_id=row.job_id, email=row.email,
                  parent_account_id=row.parent_account_id, parent_email=row.parent_email,
                  policy_tier=row.policy_tier,
                  policy_tier_label=TIER_LABELS.get(row.policy_tier, "普通席位 · 5 小时限制待核验"),
                  price_yuan=row.price_yuan or None, status=row.status, message=row.message,
                  logs=json.loads(row.logs_json), updated_at=_iso(row.updated_at)) for row in rows]
    return dict(id=batch.id, status=batch.status, prices=store._decode(batch.prices_json),
                created_at=_iso(batch.created_at), updated_at=_iso(batch.updated_at), total=len(rows),
                notice_dismissed=bool(batch.status in TERMINAL and notice
                                      and notice.batch_updated_at == batch.updated_at),
                processed=processed, progress=(round(processed * 100 / len(rows)) if rows else 100),
                **counts, items=items)


def get_batch(batch_id=None):
    with Session(store.engine) as session:
        batch = (session.get(NvPriceBatch, batch_id) if batch_id else session.exec(
            select(NvPriceBatch).order_by(NvPriceBatch.created_at.desc(), NvPriceBatch.id.desc()).limit(1)).first())
        if batch is None:
            return None
        return _public(session, batch)


def list_batches(page=1, page_size=10):
    """Read a bounded history page, including active and acknowledged batches."""
    if (type(page) is not int or page < 1 or type(page_size) is not int
            or not 1 <= page_size <= 100):
        raise HTTPException(422, "批量改价分页参数无效")
    with Session(store.engine) as session:
        total = session.exec(select(func.count()).select_from(NvPriceBatch)).one()
        result = dict(items=[], total=total, page=page, page_size=page_size)
        offset = (page - 1) * page_size
        if offset >= total:
            return result
        batches = session.exec(select(NvPriceBatch).order_by(
            NvPriceBatch.created_at.desc(), NvPriceBatch.id.desc(),
        ).offset(offset).limit(page_size)).all()
        ids = [batch.id for batch in batches]
        # Exactly two bulk child queries, independent of the number of batches.
        # Never load items or acknowledgements for other history pages.
        rows = session.exec(select(NvPriceBatchItem).where(NvPriceBatchItem.batch_id.in_(ids))
                            .order_by(NvPriceBatchItem.ordinal, NvPriceBatchItem.id)).all()
        notices = {notice.batch_id: notice for notice in session.exec(
            select(NvPriceBatchNotice).where(NvPriceBatchNotice.batch_id.in_(ids))).all()}
        grouped = {batch_id: [] for batch_id in ids}
        for row in rows:
            grouped[row.batch_id].append(row)
        result["items"] = [_public(session, batch, rows=grouped[batch.id], notices=notices)
                           for batch in batches]
        return result


def dismiss_batch(batch_id, expected_updated_at):
    """Acknowledge only the exact terminal version, without changing the batch."""
    try:
        if not isinstance(expected_updated_at, str) or not 1 <= len(expected_updated_at) <= 64:
            raise ValueError
        version = datetime.fromisoformat(expected_updated_at)
        if version.tzinfo is None or version.utcoffset() is None:
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        raise HTTPException(422, "批量改价提醒版本无效") from None
    with store.transaction() as session:
        # SQLite's BEGIN IMMEDIATE and row locking on other engines serialize
        # the version check with worker updates and concurrent acknowledgements.
        batch = session.exec(select(NvPriceBatch).where(NvPriceBatch.id == batch_id)
                             .with_for_update()).first()
        if batch is None:
            raise HTTPException(404, "批量改价记录不存在")
        if batch.status not in TERMINAL:
            raise HTTPException(409, "批量改价仍在处理中，不能关闭进度提醒")
        # Compare the exact public representation, then retain the original DB
        # float. Parsing the ISO back to a float can lose its sub-microsecond bits.
        if expected_updated_at != _iso(batch.updated_at):
            raise HTTPException(409, "批量改价记录已更新，请刷新后再关闭提醒")
        notice = session.get(NvPriceBatchNotice, batch.id)
        if notice is None:
            notice = NvPriceBatchNotice(batch_id=batch.id, batch_updated_at=batch.updated_at)
            session.add(notice)
        elif notice.batch_updated_at != batch.updated_at:
            notice.batch_updated_at = batch.updated_at
            notice.dismissed_at = time.time()
            session.add(notice)
        session.flush()
        return _public(session, batch, notices={batch.id: notice})


def create_batch_locked(session, before_settings, after_settings, request_id, expected_prices=None):
    """Save settings and freeze their existing-listing targets in ONE transaction.

    Caller owns store.transaction(). Raising on an active/conflicting batch also
    rolls the settings save back. No remote query or side effect is performed.
    """
    prices = {tier: store._normalized_price(price_for_tier(after_settings, tier) or "") for tier in TIERS}
    request_id = str(request_id or uuid.uuid4().hex)
    if len(request_id) > 120:
        raise HTTPException(422, "批量改价请求标识过长")
    old = session.exec(select(NvPriceBatch).where(NvPriceBatch.request_id == request_id)).first()
    if old:
        if store._decode(old.requested_prices_json) != prices:
            raise HTTPException(409, "本次保存标识已用于不同价格，请重新打开设置")
        # Internal transaction signal: the original save already committed.
        # Returning its batch must not reapply stale settings over later edits.
        return {**_public(session, old), "replayed": True}
    if expected_prices is not None:
        if not isinstance(expected_prices, dict) or set(expected_prices) != set(TIERS):
            raise HTTPException(422, "批量改价缺少完整的原默认价格，请重新打开设置")
        expected = {tier: store._normalized_price(expected_prices[tier] or "") for tier in TIERS}
        before = {tier: store._normalized_price(price_for_tier(before_settings, tier) or "") for tier in TIERS}
        if expected != before:
            raise HTTPException(409, "默认价格已在其他页面更新，请重新打开设置确认改价范围")
    changed = {tier: price for tier, price in prices.items() if price and
               price != store._normalized_price(price_for_tier(before_settings, tier) or "")}
    if not changed:
        return None
    active = session.exec(select(NvPriceBatch).where(NvPriceBatch.status.in_(ACTIVE))).first()
    if active:
        raise HTTPException(409, "已有批量改价正在处理，请完成后再保存新的同步价格")
    try:
        batch_id = str(uuid.UUID(request_id))
    except ValueError:
        batch_id = str(uuid.uuid4())
    batch = NvPriceBatch(id=batch_id, request_id=request_id, requested_prices_json=store._json(prices),
                         prices_json=store._json(changed))
    session.add(batch)
    session.flush()
    jobs = session.exec(select(store.NvAutomationJob).where(
        store.NvAutomationJob.step == "wait_sale",
        store.NvAutomationJob.status.notin_(store.TERMINAL_STATUSES)
    ).order_by(store.NvAutomationJob.created_at, store.NvAutomationJob.id)).all()
    ordinal = 0
    for job in jobs:
        ctx = _context(job)
        if not _listed(job, ctx):
            continue
        tier, _ = job_policy(job, ctx)
        if tier not in changed and tier != "unknown":
            continue
        # Unknown ordinary tiers matter only if an ordinary default changed;
        # a known seat is still not evidence of a confirmed pricing tier.
        if tier == "unknown" and not ((job.seat_type == "prolite" and "prolite" in changed)
                or (job.seat_type != "prolite" and any(key.startswith("default_") for key in changed))):
            continue
        item = NvPriceBatchItem(batch_id=batch.id, ordinal=ordinal, job_id=job.id, email=job.email,
            parent_account_id=job.parent_account_id, parent_email=job.parent_email,
            policy_tier=tier, price_yuan=changed.get(tier, ""))
        ordinal += 1
        item.guard_json = store._json(_guard(job, tier, item.id))
        reason = ("价格档位尚未核验，未猜测普通席位是否有 5 小时限制" if tier == "unknown" else
                  "账号已有待核对改价，未覆盖原操作" if ctx.get("nv_price_edit") else
                  "账号任务正在执行，已跳过批量改价" if job.worker_token or job.status == "running" else "")
        if reason:
            item.status = "skipped"
            _log(item, reason)
        else:
            _log(item, f"等待串行处理：本次目标价格 ¥{item.price_yuan}")
        session.add(item)
    session.flush()
    pending = session.exec(select(NvPriceBatchItem.id).where(
        NvPriceBatchItem.batch_id == batch.id, NvPriceBatchItem.status == "queued")).first()
    if not pending:
        batch.status = "completed"
        session.add(batch)
        session.flush()
    return _public(session, batch)


def _set_item(item_id, status, message):
    with store.transaction() as session:
        item = session.get(NvPriceBatchItem, item_id)
        if item is None:
            return
        item.status = status
        _log(item, message)
        session.add(item)
        batch = session.get(NvPriceBatch, item.batch_id)
        if batch:
            batch.updated_at = item.updated_at
            session.add(batch)


def progress(item_id, message):
    """Known phase text only; credentials and provider bodies are not accepted."""
    _set_item(item_id, "running", message)


def _run_item(item_id):
    from services import nv_automation_pricing as pricing
    with store.transaction() as session:
        item = session.get(NvPriceBatchItem, item_id)
        if item is None or item.status != "queued":
            return
        item.status = "running"
        _log(item, "正在核验账号身份、待售状态和价格档位" if item.mode == "edit" else
             "上次执行被中断，仅读取原卡片价格核对，不重复发送改价")
        session.add(item)
        guard, job_id, price = store._decode(item.guard_json), item.job_id, item.price_yuan
        mode = item.mode
    try:
        with Session(store.engine) as session:
            job = session.get(store.NvAutomationJob, job_id)
            if job is None:
                raise HTTPException(404, "账号任务已删除，未发送改价")
            validate_guard(job, guard)
            ctx = _context(job)
            pending = ctx.get("nv_price_edit") or {}
            if mode == "reconcile" and pending.get("batch_item_id") != item_id:
                raise HTTPException(409, "找不到本次中断改价的原始记录；未重复发送改价，请人工核对")
            version = job.version
        result = pricing.update_job_price(job_id, price, version, batch_guard=guard)
        if result.get("ok") is not True:
            raise RuntimeError("改价尚未确认成功")
        _set_item(item_id, "succeeded", f"NV 在售价格已读回确认：¥{price}")
    except Exception as exc:
        with Session(store.engine) as session:
            job = session.get(store.NvAutomationJob, job_id)
            ctx = _context(job) if job else {}
            journal = ctx.get("nv_price_edit") or {}
            confirmed = ctx.get("nv_price_confirmed") or {}
        if (confirmed.get("batch_item_id") == item_id and confirmed.get("price_yuan") == price
                and not journal):
            # The remote read-back may have committed successfully before an
            # unrelated response/progress error. Durable proof wins; no PATCH.
            status, message = "succeeded", f"已恢复本次远端读回成功记录：¥{price}；未重复发送改价"
        elif journal.get("batch_item_id") == item_id:
            status = "review"
            message = "本次改价结果待核对，未自动重发；可从该子号的价格操作核对原改价"
        elif isinstance(exc, HTTPException) and exc.status_code in {404, 409}:
            status, message = "skipped", str(exc.detail)
        else:
            status, message = "failed", (str(exc.detail) if isinstance(exc, HTTPException) else "批量改价执行失败，请查看该子号价格状态后重试")
        _set_item(item_id, status, message)


def _owner_alive(batch):
    if not batch.owner_pid or batch.owner_host != socket.gethostname():
        return False if not batch.owner_pid else None
    try:
        os.kill(batch.owner_pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return None


def recover_interrupted_batches():
    """Resume only untouched queued work; never replay an interrupted mutation."""
    with store.transaction() as session:
        batches = session.exec(select(NvPriceBatch).where(NvPriceBatch.status == "running")).all()
        for batch in batches:
            alive = _owner_alive(batch)
            if alive is not False:
                continue
            items = session.exec(select(NvPriceBatchItem).where(
                NvPriceBatchItem.batch_id == batch.id, NvPriceBatchItem.status == "running")).all()
            for item in items:
                job = session.get(store.NvAutomationJob, item.job_id)
                ctx = _context(job) if job else {}
                confirmed, journal = ctx.get("nv_price_confirmed") or {}, ctx.get("nv_price_edit") or {}
                if (confirmed.get("batch_item_id") == item.id and confirmed.get("price_yuan") == item.price_yuan
                        and not journal):
                    item.status = "succeeded"
                    _log(item, f"已恢复本次远端读回成功记录：¥{item.price_yuan}")
                elif journal.get("batch_item_id") == item.id:
                    item.status, item.mode = "queued", "reconcile"
                    _log(item, "服务重启后仅读取原改价结果，不重复发送改价")
                else:
                    item.status = "review"
                    _log(item, "执行被中断且结果未确认；未重复发送改价，请查看该子号的价格状态")
                session.add(item)
            batch.status = "queued"
            batch.owner_pid, batch.owner_host, batch.owner_token = 0, "", ""
            batch.updated_at = time.time()
            session.add(batch)


def run_batch(batch_id):
    token = uuid.uuid4().hex
    with store.transaction() as session:
        batch = session.get(NvPriceBatch, batch_id)
        if batch is None or batch.status != "queued":
            return
        batch.status, batch.owner_token = "running", token
        batch.owner_pid, batch.owner_host = os.getpid(), socket.gethostname()
        batch.updated_at = time.time()
        session.add(batch)
    try:
        while not _stop.is_set():
            with Session(store.engine) as session:
                batch = session.get(NvPriceBatch, batch_id)
                if batch is None or batch.owner_token != token:
                    return
                item_id = session.exec(select(NvPriceBatchItem.id).where(
                    NvPriceBatchItem.batch_id == batch_id, NvPriceBatchItem.status == "queued"
                ).order_by(NvPriceBatchItem.ordinal).limit(1)).first()
            if item_id is None:
                break
            _run_item(item_id)
    finally:
        with store.transaction() as session:
            batch = session.get(NvPriceBatch, batch_id)
            if batch is not None and batch.owner_token == token:
                interrupted = session.exec(select(NvPriceBatchItem).where(
                    NvPriceBatchItem.batch_id == batch_id, NvPriceBatchItem.status == "running")).all()
                for item in interrupted:
                    item.status = "review"
                    _log(item, "执行中断，结果尚未确认；本批次已暂停，请从该子号价格操作核对，未自动重发")
                    session.add(item)
                pending = session.exec(select(NvPriceBatchItem.id).where(
                    NvPriceBatchItem.batch_id == batch_id, NvPriceBatchItem.status.in_(ACTIVE))).first()
                batch.status = "paused" if interrupted else "queued" if pending else "completed"
                batch.owner_pid, batch.owner_host, batch.owner_token = 0, "", ""
                batch.updated_at = time.time()
                session.add(batch)


def _loop():
    recovery_pending = True
    while not _stop.is_set():
        try:
            if recovery_pending:
                recover_interrupted_batches()
                recovery_pending = False
            with Session(store.engine) as session:
                batch_id = session.exec(select(NvPriceBatch.id).where(NvPriceBatch.status == "queued")
                                         .order_by(NvPriceBatch.created_at).limit(1)).first()
            if batch_id:
                run_batch(batch_id)
                continue
        except Exception:
            # Keep the journal/queue intact on a DB/service failure. No network
            # operation is repeated here; interrupted running items need proof.
            pass
        _wake.wait(2)
        _wake.clear()


def start_worker():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _stop.clear()
            _thread = threading.Thread(target=_loop, name="nv-price-batches", daemon=True)
            _thread.start()
        _wake.set()


def stop_worker():
    _stop.set()
    _wake.set()
    if _thread and _thread is not threading.current_thread():
        _thread.join(timeout=2)
