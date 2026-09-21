"""Explicit per-child listing prices, separate from immutable sale receipts.

Reads never alter prices. An explicit remote edit is journalled before its one
PATCH; unknown outcomes can only be read back, never automatically replayed.
No schema change: journal and per-job override use existing durable context.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from threading import Lock
from types import SimpleNamespace
import time
import uuid

from fastapi import HTTPException
from sqlmodel import Session, select

from services import nv_automation_store as store, nexusvault
from services.nv_tier_policy import (
    TIER_LABELS, exit_delay_for_tier, job_exit_delay, job_policy, price_for_tier,
)

_cache_lock = Lock()
_edit_lock = Lock()
_cache = {}
PLANS = (
    ("default_5h", "default", "team", "team_all"),
    ("default_no_5h", "default", "team", "team_all"),
    ("prolite", "prolite", "business_pro_5x", "prolite"),
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _money(cents):
    return f"{cents // 100}.{cents % 100:02d}" if type(cents) is int and cents > 0 else None


def _remote():
    from services import nv_pricing_remote
    return nv_pricing_remote


def _read_cached(name, callback, refresh):
    # A changed web-session account must never inherit another seller's cache.
    from core.config_store import config_store
    fingerprint = hashlib.sha256(str(config_store.get(nexusvault.SALES_SESSION_COOKIE_CONFIG, "")).encode()).hexdigest()
    key = (name, fingerprint)
    with _cache_lock:
        old = _cache.get(key)
        if not refresh and old and time.monotonic() - old[0] < 60:
            return deepcopy(old[1]), ""
    try:
        result = callback()
    except nexusvault.NexusVaultError as exc:
        return None, str(exc)
    except Exception:
        return None, "NV 价格读取失败，请稍后刷新"
    with _cache_lock:
        if len(_cache) > 8:
            _cache.clear()
        _cache[key] = (time.monotonic(), deepcopy(result))
    return result, ""


def _price_state(job, settings, cards=None, inventory_error=""):
    ctx = store._decode(job.context_json)
    # Classification must already be bound to this exact child/membership.
    # A pricing GET never writes evidence, starts a probe or guesses "no 5h"
    # from absent inventory quota. The normal NV reconciliation persists it.
    policy_tier, label = job_policy(job, ctx)
    edit = ctx.get("nv_price_edit") or {}
    confirmed = ctx.get("nv_price_confirmed") or {}
    published = bool(ctx.get("publish_attempted") or ctx.get("existing_listing"))
    sold = bool(ctx.get("sold_at") or ctx.get("sale_confirmed") or job.step in {"wait_warranty", "leave", "done"})
    price, source = None, "unknown"
    if published:
        price = confirmed.get("price_yuan") or ctx.get("price_yuan")
        source = "frozen" if price else "unknown"
    else:
        price = ctx.get("nv_price_override") or price_for_tier(settings, policy_tier)
        source = "override" if ctx.get("nv_price_override") else "default" if price else "unknown"
    available = []
    identity_conflict = False
    if cards is not None and published and not sold:
        matches = [c for c in cards if c["email"] == job.email.strip().casefold()]
        available = [c for c in matches if c["status"] == "available"] if len(matches) == 1 else []
        frozen_ids = {str(value) for value in (confirmed.get("card_id"), ctx.get("nv_remote_card_id"),
                      (ctx.get("existing_listing") or {}).get("nv_remote_card_id")) if value}
        identity_conflict = bool(available and frozen_ids and frozen_ids != {str(available[0]["id"])})
        if identity_conflict:
            available = []
        if available and _money(available[0]["price_cents"]):
            price, source = _money(available[0]["price_cents"]), "remote"
    reason = ""
    if job.status in store.TERMINAL_STATUSES or sold:
        reason = "已出售或任务已结束，不能修改成交价格"
    elif not job.child_id or not job.email:
        reason = "尚未选择子号"
    elif job.worker_token or job.status == "running":
        reason = "子号任务正在执行，请步骤结束后改价"
    elif job.seat_type not in {"default", "prolite"}:
        reason = "席位类型尚未确认"
    elif published and not edit and job.step != "wait_sale":
        reason = "上架结果尚未确认，请先核对上架状态"
    elif published and not edit and (inventory_error or not available):
        reason = inventory_error or ("NV 卡片与本次上架身份不一致，请先核对" if identity_conflict else "NV 未找到唯一在售卡片，请刷新价格或先核对出库状态")
    if edit and job.status not in store.TERMINAL_STATUSES and not sold:
        reason = "上次改价结果待核对；只读取原卡片价格，不重复发送改价"
    return dict(job_id=job.id, version=job.version, price_yuan=price or None,
                policy_tier=policy_tier, label=label, policy_tier_label=label,
                auto_exit_delay_hours=job_exit_delay(job, settings, ctx),
                source=source, editable=not reason or bool(edit and not sold and job.status not in store.TERMINAL_STATUSES),
                reason=reason, pending=bool(edit), pending_price_yuan=edit.get("price_yuan"))


def pricing_snapshot(refresh=False):
    market, market_error = _read_cached("market", _remote().read_market, refresh)
    inventory, inventory_error = _read_cached("inventory", _remote().read_inventory_prices, refresh)
    settings = store.get_settings()
    remote_plans = {p["plan"]: p for p in (market or {}).get("plans", [])}
    items = []
    for tier, seat, plan, market_scope in PLANS:
        info = remote_plans.get(plan, {})
        items.append(dict(seat_type=seat, plan_name="TEAM" if seat == "default" else "Business Pro 5X",
                          policy_tier=tier, label=TIER_LABELS[tier], policy_tier_label=TIER_LABELS[tier],
                          market_scope=market_scope,
                          min_price_yuan=_money(info.get("min_cents")),
                          max_price_yuan=_money(info.get("max_cents")),
                          market_count=info.get("inventory_token_count"), sold_count=None,
                          my_price_yuan=price_for_tier(settings, tier),
                          auto_exit_delay_hours=exit_delay_for_tier(settings, tier, seat)))
    with Session(store.engine) as session:
        jobs = session.exec(select(store.NvAutomationJob).where(
            store.NvAutomationJob.status.notin_(store.TERMINAL_STATUSES)
        ).order_by(store.NvAutomationJob.created_at.desc()).limit(500)).all()
        rows = [_price_state(job, settings, (inventory or {}).get("cards"), inventory_error) for job in jobs]
    return dict(currency="CNY", checked_at=(market or {}).get("fetched_at"),
                market_updated_at=(market or {}).get("updated_at"),
                error=market_error, inventory_error=inventory_error, items=items, jobs=rows)


def _job(session, job_id, version=None):
    row = session.get(store.NvAutomationJob, job_id)
    if row is None:
        raise HTTPException(404, "子号任务不存在")
    if version is not None and row.version != version:
        raise HTTPException(409, "子号状态已变化，请刷新价格后重试")
    return row


def _validate_local(job):
    from services import nv_automation_capabilities as cap
    # Canonical ownership verifier, without starting a browser or touching NV.
    if job.membership_id:
        cap._member(store._worker(job))
    else:
        cap._assert_parent(store._worker(job))
        with Session(cap._plans().engine) as session:
            child = session.get(cap.GptPlanAccountModel, job.child_id)
            if child is None or child.email.strip().casefold() != job.email.strip().casefold():
                raise HTTPException(409, "待上架子号已删除或身份已变化")


def _available_card(job):
    from services import nv_automation_capabilities as cap
    snapshot = nexusvault.fetch_sales_snapshot(include_inventory=True)
    evidence = cap._cycle_evidence(store._worker(job), snapshot)
    if evidence.get("status") != "available":
        raise HTTPException(409, "NV 已确认出售，不能修改历史成交价格")
    matches = [r for r in snapshot.inventory_records if r.email == job.email.strip().casefold()]
    if len(matches) != 1 or not matches[0].inventory_card_id:
        raise HTTPException(409, "NV 未返回本次上架的唯一库存编号，未改价")
    return matches[0].inventory_card_id


def _read_exact_card(job, card_id):
    result = _remote().read_inventory_prices()
    matches = [c for c in result["cards"] if c["email"] == job.email.strip().casefold()]
    if len(matches) != 1 or matches[0]["id"] != card_id:
        raise HTTPException(409, "NV 卡片身份已变化或记录不唯一，未确认改价")
    return matches[0]


def _journal_finish(job_id, operation_id, *, confirmed=None, message="", sale_ambiguous=False):
    with store.transaction() as session:
        job = _job(session, job_id)
        ctx = store._decode(job.context_json)
        edit = ctx.get("nv_price_edit") or {}
        if edit.get("id") != operation_id or job.status in store.TERMINAL_STATUSES:
            raise HTTPException(409, "改价任务归属已变化，请刷新后人工核对")
        if confirmed:
            ctx["nv_price_confirmed"] = confirmed
        if sale_ambiguous:
            ctx["nv_price_sale_unverified"] = True
        ctx.pop("nv_price_edit", None)
        job.context_json = store._json(ctx)
        job.status = edit["previous_status"]
        job.error = edit["previous_error"]
        job.updated_at = time.time()
        job.version += 1
        session.add(job)
        store._log(session, job, message)
        with _cache_lock:
            _cache.clear()
        return _price_state(job, store._settings(store._settings_row(session)))


def _reconcile_edit(job, edit, *, accept_current=False):
    card = _read_exact_card(job, edit["card_id"])
    if card["status"] != "available":
        # A sale wins the race: never rewrite a receipt or resend PATCH.
        _journal_finish(job.id, edit["id"], sale_ambiguous=True, message="改价期间 NV 已非在售，成交金额待核对，未按新旧价格猜测收入；等待出库检查")
        raise HTTPException(409, "卡片已非在售，已结束改价核对；未改写历史价格，请检查 NV 成交记录")
    actual_price = _money(card["price_cents"])
    if not actual_price or (not accept_current and actual_price != edit["price_yuan"]):
        raise HTTPException(409, "NV 尚未返回目标价格，未重复发送改价；请到 NV 核对原操作")
    proof = dict(price_yuan=actual_price, card_id=edit["card_id"],
                 confirmed_at=_now(), listing_started_at=edit["listing_started_at"])
    if edit.get("batch_item_id"):
        proof["batch_item_id"] = edit["batch_item_id"]
    item = _journal_finish(job.id, edit["id"], confirmed=proof,
                           message=f"NV 当前价格已读回确认：¥{actual_price}（仅本子号）")
    item.update(source="remote", editable=True, reason="")
    return dict(ok=True, item=item, message=("已采用 NV 当前价格，解除改价待核对；未重复发送改价"
                                            if accept_current else "NV 价格已更新并读回确认"))


def reconcile_job_price(job_id, version):
    """Explicit operator acceptance of the exact card's current remote price.

    Allows an interrupted or rejected edit to stop blocking its lifecycle
    without asserting the PATCH succeeded and without issuing another PATCH.
    """
    if not _edit_lock.acquire(blocking=False):
        raise HTTPException(409, "已有改价正在处理，请稍后重试")
    try:
        with Session(store.engine) as session:
            job = _job(session, job_id, version)
            _validate_local(job)
            edit = store._decode(job.context_json).get("nv_price_edit")
            if not edit:
                raise HTTPException(409, "没有待核对的改价，请刷新价格")
            return _reconcile_under_lease(job, edit, accept_current=True)
    except nexusvault.NexusVaultError as exc:
        raise HTTPException(502, str(exc)) from None
    finally:
        _edit_lock.release()


def _reconcile_under_lease(job, edit, *, accept_current=False):
    from api import gpt_plans as plans
    lease = plans._claim_plan_operation(job.child_id, "nexusvault_price")
    try:
        return _reconcile_edit(job, edit, accept_current=accept_current)
    finally:
        plans._release_plan_operation(job.child_id, lease)


def update_job_price(job_id, price_yuan, version, *, batch_guard=None):
    price = store._normalized_price(price_yuan)
    if not price:
        raise HTTPException(422, "请输入大于 0 的价格")
    # Process-local serialization prevents duplicate HTTP requests; durable
    # journal + version CAS also fence other processes and restarts.
    if not _edit_lock.acquire(blocking=False):
        raise HTTPException(409, "已有改价正在处理，请稍后重试")
    try:
        return _update_job_price(job_id, price, version, batch_guard=batch_guard)
    except nexusvault.NexusVaultError as exc:
        raise HTTPException(502, str(exc)) from None
    finally:
        _edit_lock.release()


def _update_job_price(job_id, price, version, *, batch_guard=None):
    with Session(store.engine) as session:
        job = _job(session, job_id, version)
        if batch_guard is not None:
            from services.nv_price_batch import validate_guard
            validate_guard(job, batch_guard)
        _validate_local(job)
        ctx = store._decode(job.context_json)
        pending = ctx.get("nv_price_edit")
        if pending:
            if price != pending["price_yuan"]:
                raise HTTPException(409, "请先核对上次目标价格，不得覆盖未确认的改价")
            return _reconcile_under_lease(job, pending)
        state = _price_state(job, store.get_settings())
        published = bool(ctx.get("publish_attempted") or ctx.get("existing_listing"))
        if not published:
            if not state["editable"]:
                raise HTTPException(409, state["reason"])
        elif (job.step != "wait_sale" or job.status in store.TERMINAL_STATUSES
              or job.worker_token or job.status == "running" or ctx.get("sold_at") or ctx.get("sale_confirmed")):
            raise HTTPException(409, "当前不是可改价的待售状态，请先完成正在执行的任务或上架核对")
    if not published:
        with store.transaction() as session:
            job = _job(session, job_id, version)
            _validate_local(job)
            if batch_guard is not None:
                validate_guard(job, batch_guard)
            ctx = store._decode(job.context_json)
            if job.worker_token or job.status == "running" or ctx.get("publish_attempted"):
                raise HTTPException(409, "子号已开始执行或上架，请刷新后重试")
            ctx["nv_price_override"] = price
            job.context_json = store._json(ctx)
            job.updated_at, job.version = time.time(), job.version + 1
            session.add(job)
            store._log(session, job, f"单号定价已保存：¥{price}；仅用于该子号下次首次上架")
            return dict(ok=True, item=_price_state(job, store._settings(store._settings_row(session))), message="单号定价已保存")
    if batch_guard is not None:
        from services.nv_price_batch import progress
        progress(batch_guard["batch_item_id"], "正在核对 NV 唯一卡片身份及远端是否仍在售")
    card_id = _available_card(job)
    before = _read_exact_card(job, card_id)
    if before["status"] != "available":
        raise HTTPException(409, "NV 卡片已非在售，未改价")
    from api import gpt_plans as plans
    child_id = job.child_id
    lease = plans._claim_plan_operation(child_id, "nexusvault_price")
    operation_id = uuid.uuid4().hex
    try:
        with store.transaction() as session:
            job = _job(session, job_id, version)
            _validate_local(job)
            if batch_guard is not None:
                validate_guard(job, batch_guard)
            if job.worker_token or job.status == "running":
                raise HTTPException(409, "子号已开始执行，请稍后重试")
            ctx = store._decode(job.context_json)
            ctx["nv_price_edit"] = dict(id=operation_id, card_id=card_id, price_yuan=price,
                 previous_status=job.status, previous_error=job.error, started_at=_now(),
                 listing_started_at=store._public_listed_at(job, ctx))
            if batch_guard is not None:
                ctx["nv_price_edit"]["batch_item_id"] = batch_guard["batch_item_id"]
            job.context_json = store._json(ctx)
            job.status, job.error = "paused", "正在核对 NV 改价结果；未确认前不会重复改价"
            job.updated_at, job.version = time.time(), job.version + 1
            session.add(job)
            store._log(session, job, f"用户请求 NV 单号改价：¥{price}；已保存原卡片身份与单次请求记录")
            target = SimpleNamespace(id=job.id, email=job.email)
            edit = dict(ctx["nv_price_edit"])
        # The journal deliberately remains on timeout/error/crash. Subsequent
        # clicks reconcile only the exact original target, never replay it.
        if batch_guard is not None:
            progress(batch_guard["batch_item_id"], f"已保存本次改价记录，正在请求 NV 修改为 ¥{price}")
        _remote().edit_card_price(card_id, price)
        if batch_guard is not None:
            progress(batch_guard["batch_item_id"], "改价请求已返回，正在重新读取原卡片价格确认结果")
        return _reconcile_edit(target, edit)
    finally:
        plans._release_plan_operation(child_id, lease)
