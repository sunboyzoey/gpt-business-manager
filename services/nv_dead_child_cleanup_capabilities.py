"""Exact, pre-sale dead-child release using the canonical mother capability.

This adapter never invites, authorizes OAuth, uploads credentials or writes NV.
An ambiguous submitted removal may only be read back, never replayed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import uuid
from typing import Callable

from fastapi import HTTPException
from sqlmodel import Session, func, select

from core.db import GptBusinessChildMembershipModel as Membership, GptPlanAccountModel as Account
from services import nexusvault
from services import nv_automation_capabilities as cap
from services import nv_dead_child_cleanup as policy


_PHASES = {"queued", "checking", "removing", "submitted", "verifying", "complete"}
_IDENTITY_KEYS = ("parent_account_id", "source_account_id", "child_id", "membership_id", "email")
_LISTING_KEYS = (
    "publish_attempted", "publish_confirmed", "publish_started_at", "publish_baseline",
    "nv_publish_started", "nv_publish_confirmed", "nv_listing_started_at", "nv_listed_at",
    "nv_listing_confirmed_at", "nv_remote_card_id", "nv_remote_order_id", "nv_card_id",
    "nv_order_id", "nv_card_identity", "existing_listing", "sold_at", "warranty_until",
    "left_at", "leave_attempted", "leave_target", "team5x_warranty",
)
_MEMBER_LISTING_KEYS = (
    "nv_listed_at", "nv_listing_confirmed_at", "nv_remote_card_id", "nv_remote_order_id",
    "sold_at", "nv_team5x_warranty_until",
)


def _date(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def _state(job):
    context = cap._context(job)
    state = context.get("dead_child_cleanup")
    if not isinstance(state, dict):
        raise ValueError("缺少停用子号清理证据")
    state = dict(state)
    if (job.get("step") != "dead_cleanup" or state.get("code") != "account_deactivated"
            or state.get("original_step") not in policy.SOURCE_STEPS
            or state.get("phase") not in _PHASES):
        raise ValueError("停用子号清理阶段或明确停用证据无效")
    for key in _IDENTITY_KEYS:
        value = state.get(key)
        if key != "email" and (type(value) is not int or value <= 0):
            raise ValueError("停用子号清理身份无效")
        if value != job.get(key):
            raise ValueError("停用子号清理对象已变化")
    email = state["email"]
    if (not isinstance(email, str) or email != cap._email(email)
            or not re.fullmatch(r"[^\s@]+@[^\s@]+", email)
            or email == cap._email(job.get("parent_email"))):
        raise ValueError("停用子号邮箱或母子身份无效")
    for key in ("remote_user_id", "remote_invite_id"):
        value = state.get(key)
        if not isinstance(value, str) or value and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value):
            raise ValueError("停用子号远端身份格式无效")
    if not (state["remote_user_id"] or state["remote_invite_id"]):
        raise ValueError("停用子号没有可核对的成员或邀请身份")
    if state["remote_user_id"] != str(job.get("remote_user_id") or ""):
        raise ValueError("停用子号的冻结成员身份已变化")
    try:
        operation_id = state["operation_id"]
        if not isinstance(operation_id, str) or str(uuid.UUID(operation_id)).replace("-", "") != operation_id.replace("-", ""):
            raise ValueError
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("停用子号清理操作编号无效") from None
    invited, evidence = _date(state.get("invited_at")), _date(state.get("evidence_at"))
    if invited is None or evidence is None or not invited <= evidence <= cap._now():
        raise ValueError("停用子号清理的邀请周期或停用时间无效")
    if state.get("sale_history") is not None and not re.fullmatch(r"[0-9a-f]{64}", str(state["sale_history"])):
        raise ValueError("停用子号的销售历史快照无效")
    if not state.get("sale_history") and any(context.get(key) for key in _LISTING_KEYS):
        raise ValueError("账号存在上架、成交或退出证据，不能按未售停用子号清理")
    for key in ("submitted_at", "confirmed_at"):
        if state.get(key) and (_date(state[key]) is None or not evidence <= _date(state[key]) <= cap._now()):
            raise ValueError("停用子号清理时间证据无效")
    if state["phase"] in {"submitted", "verifying", "complete"} and not state.get("submitted_at"):
        # Remote absence can complete without sending a delete. The completion
        # checkpoint uses confirmed_at alone in that explicitly no-write case.
        if state["phase"] != "complete" or not state.get("confirmed_at"):
            raise ValueError("停用子号缺少原移除提交时间，不能重放请求")
    return state


def _validate_local(job, state):
    """Return ended only after checking the original row, not an email lookup."""
    cap._assert_parent(job, require_action=True)
    from services import nv_automation_store as store
    settings = store.get_settings()
    if (settings.get("enabled") is not True
            or state["parent_account_id"] not in settings.get("mother_ids", [])
            or state["parent_account_id"] in settings.get("paused_mother_ids", [])):
        raise ValueError("母号自动售号已暂停或已移出管理，未执行停用子号清理")
    with Session(cap._plans().engine) as session:
        member = session.get(Membership, state["membership_id"])
        child = session.get(Account, state["child_id"])
        if (member is None or member.business_account_id != state["source_account_id"]
                or cap._email(member.email) != state["email"] or member.source != "pool"
                or _date(member.invited_at) != _date(state["invited_at"])
                or str(member.remote_user_id or "") != state["remote_user_id"]
                or str(member.remote_invite_id or "") != state["remote_invite_id"]):
            raise ValueError("停用子号的原成员归属或邀请周期已变化，未清理其他成员")
        if state.get("sale_history"):
            if policy.sale_history_fingerprint(session, job, member) != state["sale_history"]:
                raise ValueError("停用清理期间上架、成交或退款历史已变化，需重新核对，未改写订单")
        elif str(member.sale_status or "") != "unlisted" or any(getattr(member, key, None) for key in _MEMBER_LISTING_KEYS):
            raise ValueError("停用子号已有上架或成交记录，不能执行未售清理")
        ended = member.ended_at is not None
        if child is None:
            if not ended or member.pro_account_id is not None:
                raise ValueError("停用子号本地身份缺失且退出尚未确认")
            if session.exec(select(Account.id).where(func.lower(func.trim(Account.email)) == state["email"])).first() is not None:
                raise ValueError("原停用子号邮箱已有新的本地账号，不能复用旧清理结果")
        elif (member.pro_account_id != state["child_id"] or cap._email(child.email) != state["email"]
                or (not ended and child.business_parent_id != state["source_account_id"])
                or (ended and child.business_parent_id is not None)):
            raise ValueError("停用子号的账号状态或母号绑定已变化")
        if child is not None:
            if state.get("account_history") is not None and policy.account_history(child) != state["account_history"]:
                raise ValueError("停用清理期间本地套餐或退款记录已变化，未删除账号或改写历史")
            if policy.recovered_after(child, state["evidence_at"]):
                raise ValueError("停用证据之后账号已有成功登录或新 RT，旧清理已停止")
            extra = policy.store._decode(child.extra_json)
            if any(extra.get(key) for key in ("cpa_synced", "cpa_device_id", "cpa_auth_name", "cpa_sync_pending",
                    "cpa_cleanup_pending", "sub2api_synced", "sub2api_device_id", "sub2api_remote_account_id",
                    "sub2api_sync_pending", "delivery_replacement_pending", "business_device_binding")):
                raise ValueError("停用子号仍有设备远端关联，须由该设备的精确清理能力确认释放后继续")
        if not ended and (member.intent_remote_started or str(member.end_reason or "").startswith("pending:")):
            if str(member.operation_id or "") != state["operation_id"] or not state.get("submitted_at"):
                raise ValueError("该成员已有其他未完成移除操作，未重复提交")
        if child is not None and child.dangerous is not True:
            # Older mailbox workers could overwrite this flag using a stale
            # pre-enqueue snapshot. Keep the normal guard; restore it only from
            # the exact durable cleanup task plus its still-current child marker.
            if (not policy.store._decode(child.extra_json).get("nv_account_deactivated")
                    or not policy.restore_confirmed_dead_marker(job, state)):
                raise ValueError("停用子号的账号状态或母号绑定已变化")
        return ended


def _checkpoint(job, phase, checkpoint, **fields):
    state = {**_state(job), **fields, "phase": phase}
    cap._checkpoint(job, {"context": {"dead_child_cleanup": state}}, checkpoint)
    return state


def _nv_absence():
    # The complete snapshot adapter raises when any sold-order page failed.
    snapshot = nexusvault.fetch_sales_snapshot(include_inventory=True)
    if not isinstance(snapshot, nexusvault.NexusVaultSalesSnapshot) or snapshot.inventory_complete is not True:
        raise ValueError("NV 库存和出库记录未完整读取，未执行停用子号移除")
    return snapshot


def _assert_no_nv_record(state, snapshot):
    if any(cap._email(row.email) == state["email"] for row in snapshot.inventory_records):
        raise ValueError("NV 仍有该停用子号的在售库存；尚无已验证的下架能力，保留清理任务等待先下架，未移除母号成员")
    if (state["email"] in {cap._email(value) for value in snapshot.unconfirmed_sold_emails}
            or not state.get("sale_history") and any(cap._email(row.email) == state["email"] for row in snapshot.sold_records)):
        raise ValueError("NV 已有该邮箱的库存、成交或待确认记录，需先核对售卖状态；未移除")


def _workspace_state(state):
    workspace = cap._business().workspace_members(state["source_account_id"])
    if (not isinstance(workspace, dict) or workspace.get("fresh") is not True
            or workspace.get("cached") is not False or workspace.get("ok") is not True
            or any(not isinstance(workspace.get(key), list) for key in ("members", "invites", "membership_conflicts"))
            or any(not isinstance(row, dict) for key in ("members", "invites", "membership_conflicts") for row in workspace[key])):
        raise ValueError("母号未返回完整实时成员与邀请结果，不能确认子号已移除")
    if any(cap._email(row.get("email")) == state["email"] for row in workspace["membership_conflicts"]):
        raise ValueError("停用子号远端记录与本地写回冲突，不能确认移除")
    matches = []
    for key, kind, identity in (("members", "member", "user_id"), ("invites", "invite", "invite_id")):
        frozen = state["remote_user_id" if kind == "member" else "remote_invite_id"]
        for row in workspace[key]:
            email, remote = cap._email(row.get("email")), str(row.get(identity) or "")
            if email == state["email"] or frozen and remote == frozen:
                if email != state["email"] or not frozen or remote != frozen:
                    raise ValueError("远端成员或邀请身份已变化，未对其他账号执行移除")
                if str(row.get("role") or "").lower() in {"owner", "admin", "primary-owner"}:
                    raise ValueError("目标远端成员是母号或管理员，未执行自动清理")
                matches.append(kind)
    if not matches:
        return "absent"
    expected = "member" if state["remote_user_id"] else "invite"
    if matches != [expected]:
        raise ValueError("远端停用子号不唯一或已改变成员类型，未执行移除")
    return expected


def _complete(job, state, checkpoint):
    if not _validate_local(job, state):
        raise ValueError("远端已无该子号，但本地原成员退出尚未确认")
    with Session(cap._plans().engine) as session:
        child_exists = session.get(Account, state["child_id"]) is not None
    if child_exists:
        # Canonical membership removal uses best-effort local deletion. Resume
        # that exact local finalizer if it was blocked, never replay remote DELETE.
        result = cap._business()._purge_released_dead_business_child_best_effort(
            state["child_id"], parent_id=state["source_account_id"], email=state["email"],
            expected_deactivated_at=_date(state["evidence_at"]),
        )
        if not isinstance(result, dict) or not (result.get("deleted") is True or result.get("reason") == "account_missing"):
            return _retry("远端关联已释放，本地账号删除尚未确认；保留清理任务，稍后仅重试本地清理", delay=300)
    _validate_local(job, state)
    with Session(cap._plans().engine) as session:
        if session.get(Account, state["child_id"]) is not None:
            return _retry("本地删除尚未落库，保留原清理任务等待核对", delay=300)
    _checkpoint(job, "complete", checkpoint,
        confirmed_at=state.get("confirmed_at") or cap._iso(cap._now()))
    return cap._result("cancelled", error="停用子号已清理，等待母号重新补号")


def _retry(error="读取暂时失败，稍后核对停用子号清理状态；不会重复移除", *, delay=60):
    return cap._result("retry", error=error, delay=delay)


def execute(job: dict, emit: Callable, checkpoint: Callable, reconcile: bool = False) -> dict:
    """Clean exactly one unlisted dead child; the scheduler owns replacement."""
    job = {**job, "context": cap._context(job)}
    try:
        state = _state(job)
        _validate_local(job, state)
        submitted = bool(state.get("submitted_at"))
        if not submitted and state["phase"] != "complete":
            state = _checkpoint(job, "checking", checkpoint)
        cap._log(emit, "正在核对停用子号身份及 NV 库存、销售历史")
        try:
            snapshot = _nv_absence()
        except nexusvault.NexusVaultError:
            return _retry("NV 库存/出库记录暂未读到，尚未移除；稍后自动重试", delay=300)
        _assert_no_nv_record(state, snapshot)
        from services.business_session_health import check_session, ensure_session_for_automation
        from services.nv_exit_recovery import BusinessExitPreflightError, CODES
        try:
            cap._log(emit, "正在检查母号会话，失效时复用母号登录恢复能力")
            # The automation helper may trust a saved valid health marker.
            # Refresh that marker first, so a newly expired Cookie cannot make
            # the membership reader return stale cache before recovery runs.
            check_session(state["source_account_id"], force=True)
            ensure_session_for_automation(state["source_account_id"], emit=emit,
                browser_mode=cap._settings(job).get("browser_mode", "headless"))
        except HTTPException as exc:
            if isinstance(exc.detail, dict) and exc.detail.get("code") in CODES:
                failure = BusinessExitPreflightError(exc.detail)
                if not failure.failure["retryable"]:
                    return cap._review(failure.failure["message"])
                return _retry(failure.failure["message"], delay=300)
            raise
        remote = _workspace_state(state)
        ended = _validate_local(job, state)
        if remote == "absent":
            cap._log(emit, "已确认原子号在母号远端不存在，核对本地退出流水")
            return _complete(job, state, checkpoint)
        if ended:
            return cap._review("本地原成员已结束，但远端仍存在；未自动删除新的成员周期")
        if submitted or state["phase"] == "complete":
            return cap._review("原移除请求结果仍未确认，子号仍在母号；仅回读核对，未重复提交移除")
        # Even a worker explicitly marked as reconcile may start the queued
        # request only if the durable state proves no earlier submission.
        state = _checkpoint(job, "removing", checkpoint)
        _validate_local(job, state)
        plans = cap._plans()
        target = {
            **{key: state[key] for key in _IDENTITY_KEYS},
            "parent_email": cap._email(job["parent_email"]), "source": "pool",
            "user_id": state["remote_user_id"], "invite_id": state["remote_invite_id"],
            "operation_id": state["operation_id"], "kind": remote, "invited_at": state["invited_at"],
        }
        body = plans.GptPlanBusinessChildRemoveRequest(
            membership_id=state["membership_id"], operation_id=state["operation_id"], confirm_remove=True,
        )
        body._batch_expected_target = target
        state = _checkpoint(job, "submitted", checkpoint, submitted_at=cap._iso(cap._now()))
        cap._log(emit, "正在调用母号移除停用子号" if remote == "member" else "正在调用母号撤销停用子号邀请")
        try:
            # Return values are not completion proof. The canonical owner
            # performs remove/revoke and persists the exact membership history.
            plans.member_business_remove(state["parent_account_id"], body)
        except BusinessExitPreflightError as exc:
            # This typed error is raised before the canonical source mutation.
            _checkpoint(job, "queued", checkpoint, submitted_at="", preflight_failure={
                **exc.failure, "retry_at": cap._iso(cap._now() + timedelta(seconds=300)),
            })
            return (_retry(exc.failure["message"], delay=300) if exc.failure["retryable"]
                    else cap._review(exc.failure["message"]))
        except Exception:
            cap._log(emit, "移除接口结果尚未确认，开始回读原成员；不会重复发送请求")
        state = _checkpoint(job, "verifying", checkpoint)
        remote = _workspace_state(state)
        if remote != "absent":
            return cap._review("移除后远端仍存在原子号，未确认成功；停止本号，不重复移除")
        result = _complete(job, state, checkpoint)
        cap._log(emit, "停用子号远端移除与本地退出均已确认，母号交回正常补号调度")
        return result
    except ValueError as exc:
        return cap._review(str(exc))
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if exc.status_code in {408, 429, 502, 503, 504} or detail.get("code") in {
            "business_parent_automation_busy", "gpt_pro_account_busy", "business_workspace_refresh_fenced",
        }:
            return _retry()
        return cap._review(cap._safe_error(exc))
    except (TimeoutError, ConnectionError):
        return _retry()
    except Exception as exc:
        # Do not reflect a raw provider/DB exception containing credentials.
        return cap._review(f"停用子号清理未能确认（{type(exc).__name__}）；原任务与成员记录已保留")
