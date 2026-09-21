"""Apply explicit NV workspace-deactivation evidence to one exact live mother.

No HTTP, account login, credential changes or membership/sale mutations happen
here. The caller must first match the complete NV snapshot; this second fence
rechecks the durable job, membership and listing inside the write transaction.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from core.db import (GptBusinessAccountModel as Mother,
                     GptBusinessChildMembershipModel as Membership,
                     GptPlanAccountModel as Account)
from services import business_session_health as health
from services import nv_automation_store as store


KEY = "nv_workspace_deactivation_v1"
REASON = "NV 明确报告当前工作区停用（HTTP 402），已停止该母号自动任务"
_INVALID = "NV 工作区停用证据与当前任务、母号或上架周期不一致，未标记母号"
_FIELDS = {"workspace_deactivated", "email", "remote_card_id", "listed_at", "checked_at"}
_JOB_FIELDS = ("id", "parent_account_id", "source_account_id", "parent_email", "child_id",
               "email", "membership_id", "remote_user_id", "seat_type", "step", "status",
               "version", "operation_id", "worker_token")
_CYCLE_FIELDS = ("existing_listing", "nv_listed_at", "nv_listing_confirmed_at",
                 "publish_started_at", "nv_remote_card_id", "nv_remote_order_id", "sold_at",
                 "membership_invited_at", "leave_attempted", "left_at")


def _now():
    return datetime.now(timezone.utc)


def _date(value):
    try:
        value = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _email(value):
    return value.strip().lower() if isinstance(value, str) else ""


def _id(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value) else ""


def _proof(evidence, now):
    if not isinstance(evidence, dict) or set(evidence) != _FIELDS or evidence.get("workspace_deactivated") is not True:
        raise ValueError(_INVALID)
    email = _email(evidence["email"])
    card = _id(evidence["remote_card_id"])
    listed, checked = _date(evidence["listed_at"]), _date(evidence["checked_at"])
    if (not re.fullmatch(r"[^\s@]{1,200}@[^\s@]{1,119}", email) or not card
            or listed is None or checked is None or not listed <= checked <= now):
        raise ValueError(_INVALID)
    return dict(workspace_deactivated=True, email=email, remote_card_id=card,
                listed_at=listed.isoformat(), checked_at=checked.isoformat())


def _locked(session, model, identifier):
    return session.exec(select(model).where(model.id == identifier).with_for_update()).first()


def _validate(session, supplied, proof, now):
    if not isinstance(supplied, dict) or not _id(supplied.get("id")):
        raise ValueError(_INVALID)
    for key in ("parent_account_id", "source_account_id", "child_id", "membership_id"):
        if type(supplied.get(key)) is not int or supplied[key] <= 0:
            raise ValueError(_INVALID)
    if type(supplied.get("version")) is not int or supplied["version"] < 0:
        raise ValueError(_INVALID)
    job = _locked(session, store.NvAutomationJob, supplied["id"])
    if (job is None or any(key not in supplied or supplied[key] != getattr(job, key) for key in _JOB_FIELDS)
            or job.pause_requested or job.step not in {"publish", "renew", "wait_sale", "wait_warranty", "leave"}
            or job.status not in {"running", "waiting", "review", "failed"}
            or (job.status == "running" and not job.worker_token)
            or (job.status != "running" and (job.worker_token or job.worker_pid))):
        raise ValueError(_INVALID)
    context = store._decode(job.context_json)
    supplied_context = supplied.get("context")
    if (not isinstance(supplied_context, dict)
            or any(supplied_context.get(key) != context.get(key) for key in _CYCLE_FIELDS)):
        raise ValueError(_INVALID)
    basis = context.get("existing_listing") or {}
    if not isinstance(basis, dict):
        raise ValueError(_INVALID)
    floor = _date(basis.get("nv_listed_at") or context.get("nv_listed_at") or context.get("publish_started_at"))
    listed = _date(proof["listed_at"])
    if (floor != listed or _email(job.email) != proof["email"]
            or not _id(job.remote_user_id) or context.get("left_at") or context.get("leave_attempted")):
        raise ValueError(_INVALID)

    parent = _locked(session, Account, job.parent_account_id)
    source = _locked(session, Mother, job.source_account_id)
    child = _locked(session, Account, job.child_id)
    member = _locked(session, Membership, job.membership_id)
    if (parent is None or source is None or child is None or member is None
            or parent.id == child.id or parent.source_pool != "gpt_business"
            or parent.source_account_id != source.id or parent.business_parent_id is not None
            or _email(parent.email) != _email(job.parent_email)
            or _email(source.email) != _email(job.parent_email)
            or _email(child.email) != proof["email"] or _email(child.email) == _email(parent.email)
            or child.business_parent_id != source.id or member.business_account_id != source.id
            or member.pro_account_id != child.id or _email(member.email) != proof["email"]
            or member.remote_user_id != job.remote_user_id or member.source != "pool"
            or member.ended_at is not None or member.intent_remote_started
            or member.sale_status not in {"listed", "sold", "refunded", "partial_refund"}
            or member.seat_type != job.seat_type or member.seat_type not in {"default", "prolite"}
            or _date(member.invited_at) is None or _date(member.invited_at) > listed
            or _date(member.nv_listed_at) != listed
            or _date(member.nv_listing_confirmed_at) is None
            or not listed <= _date(member.nv_listing_confirmed_at) <= now
            or member.nv_remote_card_id != proof["remote_card_id"]):
        raise ValueError(_INVALID)
    # The same child cannot have two current memberships, including an old
    # email-only row. No ambiguity is resolved by taking the first match.
    live = session.exec(select(Membership.id).where(Membership.ended_at.is_(None), or_(
        Membership.pro_account_id == child.id,
        func.lower(func.trim(Membership.email)) == proof["email"],
    )).with_for_update()).all()
    if live != [member.id]:
        raise ValueError(_INVALID)
    for frozen in (context, basis):
        for key in ("nv_remote_card_id", "nv_remote_order_id"):
            if frozen.get(key) and frozen[key] != getattr(member, key):
                raise ValueError(_INVALID)
        for key, expected in (("sold_at", member.sold_at), ("membership_invited_at", member.invited_at),
                              ("nv_listed_at", member.nv_listed_at),
                              ("nv_listing_confirmed_at", member.nv_listing_confirmed_at)):
            if frozen.get(key) and _date(frozen[key]) != _date(expected):
                raise ValueError(_INVALID)
    return job, parent, source


def mark_deactivated_mother(job, evidence):
    """Mark both authoritative mothers atomically, or raise a fixed ValueError.

    ``job`` is an owned worker/scan DTO including its unchanged version and
    context. ``evidence`` is exactly the five-field, credential-free dictionary
    emitted after complete-snapshot matching by the NV capability. Its checked
    time comes from NV's explicit workspace-deactivation observation, not now.
    The result and log never include credentials or remote response text.
    """
    now = _now()
    proof = _proof(evidence, now)
    try:
        with store.transaction() as session:
            current, parent, source = _validate(session, job, proof, now)
            already = parent.dangerous is True and source.dangerous is True
            provenance = dict(reason=REASON, http_status=402, source="nexusvault",
                job_id=current.id, parent_account_id=parent.id, source_account_id=source.id,
                child_id=current.child_id, membership_id=current.membership_id,
                recorded_at=now.isoformat(), **proof)
            changed = False
            for row in (parent, source):
                extra = store._decode(row.extra_json)
                previous = extra.get(KEY)
                # Exact replay is a no-op. Preserve the first detection and
                # prior same-mother evidence instead of moving its audit clock.
                same = (row.dangerous is True and isinstance(previous, dict)
                        and all(previous.get(key) == value for key, value in proof.items()))
                if same:
                    continue
                old_health = extra.get(health.KEY)
                old_health = old_health if isinstance(old_health, dict) else {}
                extra[health.KEY] = {**old_health, "fingerprint": health._fingerprint(row.cookie_blob),
                    "status": "deactivated", "http_status": 402, "checked_at": now.isoformat()}
                extra[KEY] = provenance
                row.extra_json = store._json(extra)
                row.dangerous = True
                row.dangerous_detected_at = row.dangerous_detected_at or now
                row.updated_at = now
                session.add(row)
                changed = True
            if changed:
                store._log(session, current, REASON + "；未删除成员、修改订单或取消远端邀请")
            return dict(marked=changed, already_marked=already, parent_account_id=parent.id,
                        source_account_id=source.id, status="deactivated")
    except SQLAlchemyError:
        # Bound SQL parameters can include private extra data. Never leak them
        # through the canonical task logger or a remote error serializer.
        raise ValueError("NV 工作区停用标记保存失败，未确认更新母号") from None
