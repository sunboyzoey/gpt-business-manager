"""Unlimited BUSINESS invitation audit ledger.

Invitation rows remain durable idempotency fences around the remote mutation,
but no local rolling-window allowance can reject a new invitation. Confirmed
rows are also the source for per-day and lifetime success counters.
"""
from datetime import timezone
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlmodel import select

from core.db import (
    GptBusinessAccountModel as Mother,
    GptBusinessRotationReservationModel as Reservation,
)

TYPES = ("default", "prolite")
ACTIONS = ("invite", "pro_refund_burn")
DAY_TIMEZONE = ZoneInfo("Asia/Shanghai")
UNLIMITED_REMAINING = 2_147_483_647


def aware(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def iso(value):
    return aware(value).isoformat() if value is not None else ""


def normalize_type(value):
    value = str(value or "").strip().lower()
    if value not in TYPES:
        raise HTTPException(400, "邀请席位类型必须为 default 或 prolite")
    return value


def quota_rows(session, parent_id):
    return list(session.exec(select(Reservation).where(
        Reservation.business_account_id == int(parent_id),
        Reservation.action.in_(ACTIONS),
    )).all())


def _row_type(row):
    return row.seat_type if row.seat_type in TYPES else "legacy"


def _success_counts(rows, now):
    local_day = aware(now).astimezone(DAY_TIMEZONE).date()
    result = {key: {"today": 0, "total": 0, "reserved": 0}
              for key in (*TYPES, "legacy")}
    for row in rows:
        kind = _row_type(row)
        if row.state == "reserved":
            result[kind]["reserved"] += 1
            continue
        if row.state != "consumed":
            continue
        result[kind]["total"] += 1
        confirmed_at = aware(row.resolved_at or row.reserved_at)
        if confirmed_at is not None and confirmed_at.astimezone(DAY_TIMEZONE).date() == local_day:
            result[kind]["today"] += 1
    return result


def _bucket(kind, counts, now, *, legacy_today=0, legacy_total=0, legacy_reserved=0):
    own = counts[kind]
    return {
        "seat_type": kind,
        "mode": "unlimited_audit",
        "limited": False,
        "limit": None,
        "window_hours": None,
        "window_started_at": "",
        "window_ends_at": "",
        "reset_at": "",
        "next_available_at": "",
        "earliest_recovery_at": "",
        "recovery_schedule": [],
        "cycle_state": "unlimited",
        "used": own["total"] + legacy_total,
        "effective_used": own["total"] + legacy_total,
        "consumed_used": own["total"] + legacy_total,
        "reserved": own["reserved"] + legacy_reserved,
        "remaining": UNLIMITED_REMAINING,
        "today_success_count": own["today"] + legacy_today,
        "total_success_count": own["total"] + legacy_total,
        "typed_today_success_count": own["today"],
        "typed_total_success_count": own["total"],
        "legacy_shared_used": legacy_total,
        "legacy_shared_reserved": legacy_reserved,
        "legacy_shared_reset_at": "",
        "snapshot_at": iso(now),
        "day_timezone": str(DAY_TIMEZONE),
    }


def snapshot(session, parent_id, now, seat_type=None):
    parent = session.get(Mother, int(parent_id))
    if parent is None:
        raise HTTPException(404, "BUSINESS 母号不存在")
    kind = normalize_type(seat_type) if seat_type is not None else None
    counts = _success_counts(quota_rows(session, parent_id), now)
    legacy = counts["legacy"]
    by_type = {key: _bucket(key, counts, now) for key in TYPES}
    if kind is not None:
        return by_type[kind]
    today = sum(counts[key]["today"] for key in (*TYPES, "legacy"))
    total = sum(counts[key]["total"] for key in (*TYPES, "legacy"))
    reserved = sum(counts[key]["reserved"] for key in (*TYPES, "legacy"))
    return {
        "mode": "unlimited_audit",
        "limited": False,
        "limit": None,
        "window_hours": None,
        "window_started_at": "",
        "window_ends_at": "",
        "reset_at": "",
        "next_available_at": "",
        "earliest_recovery_at": "",
        "recovery_schedule": [],
        "cycle_state": "unlimited",
        "used": total,
        "effective_used": total,
        "consumed_used": total,
        "reserved": reserved,
        "remaining": UNLIMITED_REMAINING,
        "today_success_count": today,
        "total_success_count": total,
        "legacy_shared_used": legacy["total"],
        "legacy_shared_reserved": legacy["reserved"],
        "legacy_shared_reset_at": "",
        "snapshot_at": iso(now),
        "day_timezone": str(DAY_TIMEZONE),
        "by_type": by_type,
        "aggregate_only": True,
    }


def initialize_locked(session, parent, rows, now):
    if not parent.invite_quota_typed_initialized:
        parent.invite_quota_typed_initialized = True
        session.add(parent)
        session.flush()


def sync_legacy_mirror(session, parent, now):
    """Clear obsolete admission counters while preserving audit rows."""
    parent.invite_quota_used = 0
    parent.invite_quota_window_started_at = None
    for kind in (*TYPES, "legacy"):
        setattr(parent, f"invite_quota_{kind}_used", 0)
        setattr(parent, f"invite_quota_{kind}_window_started_at", None)
    parent.updated_at = now
    session.add(parent)


def normalize_locked(session, parent, now, keep_slot_ids=None):
    initialize_locked(session, parent, quota_rows(session, int(parent.id)), now)
    sync_legacy_mirror(session, parent, now)
    session.flush()


def exhausted_detail(quota, required):
    return {
        "code": "invite_limit_removed",
        "message": "本项目不再设置本地邀请次数限制",
        "required": max(1, int(required or 1)),
        "remaining": UNLIMITED_REMAINING,
        "reset_at": "",
        "invite_quota": quota,
    }


def _binding(row, parent_id, action, seat_type):
    if row.business_account_id != parent_id or row.action != action:
        raise HTTPException(409, "邀请操作绑定不一致")
    if seat_type is not None and row.seat_type != seat_type:
        raise HTTPException(409, {"code": "invite_seat_type_mismatch",
                                  "message": "邀请操作的席位类型不可更改",
                                  "seat_type": row.seat_type})


def reserve_locked(session, parent, operation_id, slot_ids, action, now, seat_type):
    kind = normalize_type(seat_type)
    normalize_locked(session, parent, now)
    existing = {slot: session.get(Reservation, slot) for slot in slot_ids.values()}
    for row in existing.values():
        if row is None:
            continue
        _binding(row, int(parent.id), action, kind)
        if row.state not in {"reserved", "consumed", "released"}:
            raise HTTPException(409, "邀请操作状态异常，拒绝重试")
        if row.state != "released":
            raise HTTPException(409, {"code": "invite_operation_already_started",
                                      "message": "该邀请操作已发起或已完成，不能重复发送；新的邀请请使用新操作",
                                      "operation_id": operation_id,
                                      "affected_targets": sum(item is not None for item in existing.values())})
    for slot, row in existing.items():
        if row is None:
            row = Reservation(operation_id=slot, business_account_id=int(parent.id),
                              action=action, seat_type=kind, created_at=now)
        row.state = "reserved"
        row.reserved_at = now
        row.resolved_at = None
        row.resolution_reason = ""
        row.updated_at = now
        session.add(row)
    session.flush()
    return {"ok": True, "operation_id": operation_id, "slot_ids": slot_ids,
            "invite_quota": snapshot(session, int(parent.id), now, kind)}


def consume_locked(session, parent, slot_ids, action, now, seat_type=None):
    explicit = normalize_type(seat_type) if seat_type is not None else None
    normalize_locked(session, parent, now, set(slot_ids.values()))
    existing = {slot: session.get(Reservation, slot) for slot in slot_ids.values()}
    missing_type = explicit or "default"
    touched = set()
    increment = 0
    for slot, row in existing.items():
        if row is not None:
            _binding(row, int(parent.id), action, explicit)
            if row.state == "consumed":
                touched.add(_row_type(row))
                continue
            if row.state == "released":
                raise HTTPException(409, "邀请操作已明确释放，重试前必须重新预留")
            if row.state != "reserved":
                raise HTTPException(409, "邀请操作状态异常")
        else:
            row = Reservation(operation_id=slot, business_account_id=int(parent.id),
                              action=action, seat_type=missing_type,
                              reserved_at=now, created_at=now)
        touched.add(_row_type(row))
        row.state = "consumed"
        row.resolved_at = now
        row.resolution_reason = "server_confirmed_invite"
        row.updated_at = now
        session.add(row)
        increment += 1
    session.flush()
    return_type = next(iter(touched)) if len(touched) == 1 and "legacy" not in touched else explicit
    return {"ok": True, "consumed": increment,
            "invite_quota": snapshot(session, int(parent.id), now, return_type)}


def release_locked(session, parent, slot_ids, action, reason, now, seat_type=None):
    explicit = normalize_type(seat_type) if seat_type is not None else None
    normalize_locked(session, parent, now)
    touched = set()
    for slot in slot_ids.values():
        row = session.get(Reservation, slot)
        if row is None:
            continue
        _binding(row, int(parent.id), action, explicit)
        touched.add(_row_type(row))
        if row.state == "consumed":
            continue
        row.state = "released"
        row.resolved_at = now
        row.resolution_reason = str(reason or "remote_definite_noop")[:300]
        row.updated_at = now
        session.add(row)
    session.flush()
    return_type = next(iter(touched)) if len(touched) == 1 and "legacy" not in touched else explicit
    return_type = return_type or "default"
    return {"ok": True, "invite_quota": snapshot(session, int(parent.id), now, return_type)}
