"""Narrow, additive device hosting adapters; no legacy rotation or deletion.

Discovery is local-only. Canonical account capabilities own invitation, OAuth
and upload leases. Durable task checkpoints and binding/endpoint fences are
required around every action. Interrupted mutations are only reconciled.
"""
from __future__ import annotations

import json
import re
import hashlib
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import func, inspect, or_
from sqlmodel import Session, select
from fastapi import HTTPException

from core.db import (engine, GptPlanAccountModel, GptBusinessAccountModel,
                     GptBusinessChildMembershipModel, GptBusinessAutomationPolicyModel,
                     resolve_business_delivery_binding)
from services.business_invite_wait import cooldown_wait_seconds


def _plans():
    from api import gpt_plans
    return gpt_plans


def _business():
    from api import gpt_business
    return gpt_business


def _devices():
    from api import delivery_devices
    return delivery_devices


def _operations():
    from api import gpt_plan_operations
    return gpt_plan_operations


def current_device_epoch(device_ref: str) -> str:
    device = _devices()._delivery_binding_device(device_ref)
    return _devices()._device_epoch(device["provider"], device["provider_id"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _date(value: Any) -> datetime | None:
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _email(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if len(text) <= 320 and re.fullmatch(r"[^\s@]+@[^\s@]+", text) else ""


def _id(value: Any) -> int:
    return value if type(value) is int and value > 0 else 0


def _context(job: dict) -> dict:
    return job.get("context") if isinstance(job.get("context"), dict) else {}


def _result(outcome: str, next_step: str = "", error: str = "", *, delay: int = 0, updates: dict | None = None) -> dict:
    return {"outcome": outcome, "next_step": next_step, "error": error,
            "delay": delay, "updates": updates or {}}


class HostingStopped(RuntimeError):
    """Only fixed credential-free messages cross the adapter boundary."""


def _checkpoint(job: dict, payload: dict, checkpoint: Callable | None) -> None:
    if not callable(checkpoint) or checkpoint(payload) is not True:
        raise HostingStopped("托管检查点或任务租约未确认，停止后续动作")
    for key, value in payload.items():
        job[key] = {**_context(job), **value} if key == "context" else value


def _nv_reason(session: Session, parent_id: int, source_id: int, child_id: int = 0, membership_id: int = 0) -> str:
    from services.nv_automation_store import NvAutomationSettings, NvAutomationJob
    tables = inspect(session.connection())
    if tables.has_table(NvAutomationSettings.__tablename__):
        settings = session.get(NvAutomationSettings, 1)
        payload = json.loads(settings.payload_json or "{}") if settings else {}
        if payload.get("enabled") is True and parent_id in payload.get("mother_ids", []):
            return "母号已由自动售号管理，设备托管不抢占"
    if tables.has_table(NvAutomationJob.__tablename__):
        clauses = [NvAutomationJob.parent_account_id == parent_id, NvAutomationJob.source_account_id == source_id]
        if child_id:
            clauses.append(NvAutomationJob.child_id == child_id)
        if membership_id:
            clauses.append(NvAutomationJob.membership_id == membership_id)
        active = session.exec(select(NvAutomationJob.id).where(
            or_(*clauses), NvAutomationJob.status.notin_(["completed", "cancelled"]),
        ).limit(1)).first()
        if active is not None:
            return "母号或子号仍有未结束的自动售号任务，设备托管不抢占"
    return ""


def _parent_reason(parent: Any, source: Any) -> str:
    if (parent is None or source is None or parent.source_pool != "gpt_business"
            or parent.source_account_id != source.id or parent.business_parent_id is not None
            or not _email(parent.email) or _email(parent.email) != _email(source.email)):
        return "母号套餐目录或来源身份未确认"
    refunded = {"refunded", "refunded_pending_credit", "refund_credited"}
    if (not parent.enabled or not source.enabled or parent.dangerous or source.dangerous
            or parent.policy_warning or str(parent.refund_status or "") in refunded or str(source.refund_status or "") in refunded
            or str(parent.catalog_category or "") == "refunded"):
        return "母号已停用、告警或退款，不执行托管"
    return ""


def _protected_membership(row: Any) -> bool:
    return bool(row and (row.sale_status != "unlisted" or row.sold_at or row.nv_listed_at
        or row.nv_listing_confirmed_at or row.nv_remote_card_id or row.nv_remote_order_id))


def _credential_fingerprint(child: Any) -> str:
    values = [str(getattr(child, key, "") or "").strip() for key in (
        "codex_access_token", "codex_refresh_token", "codex_id_token")]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _member(job: dict) -> dict:
    with Session(engine) as session:
        member = session.get(GptBusinessChildMembershipModel, _id(job.get("membership_id")))
        child = session.get(GptPlanAccountModel, _id(job.get("child_id")))
        invited = _date(getattr(member, "invited_at", None))
        if (member is None or child is None or member.ended_at is not None or member.source != "pool"
                or member.business_account_id != job.get("source_account_id")
                or member.pro_account_id != child.id or child.business_parent_id != member.business_account_id
                or not _email(job.get("email")) or _email(child.email) != _email(job.get("email"))
                or _email(member.email) != _email(job.get("email")) or invited is None
                or member.intent_remote_started or str(member.end_reason or "").startswith("pending:")
                or not child.enabled or child.dangerous or child.policy_warning or str(child.refund_status or "")
                or str(child.catalog_category or "") == "refunded"):
            raise HostingStopped("子号成员身份、邀请周期或账号状态已变化")
        if _context(job).get("membership_invited_at") and _date(_context(job)["membership_invited_at"]) != invited:
            raise HostingStopped("子号已不属于本次邀请周期")
        if _protected_membership(member):
            raise HostingStopped("子号有上架或售出保护记录，不用于设备托管")
        reason = _nv_reason(session, job["parent_account_id"], job["source_account_id"], child.id, member.id)
        if reason:
            raise HostingStopped(reason)
        duplicates = session.exec(select(GptBusinessChildMembershipModel.id).where(
            GptBusinessChildMembershipModel.ended_at.is_(None),
            or_(GptBusinessChildMembershipModel.pro_account_id == child.id,
                func.lower(func.trim(GptBusinessChildMembershipModel.email)) == _email(member.email)),
        )).all()
        if duplicates != [member.id]:
            raise HostingStopped("子号存在重复归属记录，需要人工核对")
        try:
            extra = json.loads(child.extra_json or "{}")
        except (ValueError, TypeError):
            raise HostingStopped("子号设备关联记录格式无效，需要人工核对") from None
        if not isinstance(extra, dict):
            raise HostingStopped("子号设备关联记录格式无效，需要人工核对")
        acquired = _date(child.codex_rt_acquired_at)
        credentials = [child.codex_access_token, child.codex_refresh_token, child.codex_id_token]
        return {"membership_invited_at": invited.isoformat(), "remote_user_id": str(member.remote_user_id or ""),
                "remote_invite_id": str(member.remote_invite_id or ""), "seat_type": member.seat_type,
                "has_rt": bool(str(child.codex_refresh_token or "").strip()),
                "has_any_credentials": any(bool(str(value or "").strip()) for value in credentials),
                "oauth_complete": bool(all(str(value or "").strip() for value in credentials)
                    and acquired and invited <= acquired <= datetime.now(timezone.utc)),
                "oauth_acquired_at": acquired.isoformat() if acquired else "", "extra": extra,
                "cpa_expected_auth_name": f"{str(child.email).strip()}.json",
                "credential_fingerprint": _credential_fingerprint(child)}


def _guard(job: dict, checkpoint: Callable) -> bool:
    _checkpoint(job, {}, checkpoint)
    device = _devices()._delivery_binding_device(job.get("device_ref", ""))
    if device.get("state") != "configured" or device.get("device_ref") != job.get("device_ref"):
        raise HostingStopped("目标设备未配置、已停用或身份变化")
    if not _devices()._device_epoch_is_current(device["provider"], device["provider_id"], job.get("device_epoch", "")):
        raise HostingStopped("目标设备配置已变化，需要人工核对")
    with Session(engine) as session:
        parent = session.get(GptPlanAccountModel, _id(job.get("parent_account_id")))
        source = session.get(GptBusinessAccountModel, _id(job.get("source_account_id")))
        reason = _parent_reason(parent, source)
        if reason or _email(getattr(parent, "email", "")) != _email(job.get("parent_email")):
            raise HostingStopped(reason or "母号邮箱身份变化")
        policy = session.get(GptBusinessAutomationPolicyModel, source.id)
        binding = resolve_business_delivery_binding(policy)
        if (policy is None or type(job.get("binding_revision")) is not int
                or policy.revision != job["binding_revision"] or binding != (device["provider"], device["provider_id"])
                or policy.auto_rotation_enabled):
            raise HostingStopped("母号设备绑定版本已变化或存在旧轮换授权")
        reason = _nv_reason(session, parent.id, source.id, _id(job.get("child_id")), _id(job.get("membership_id")))
        if reason:
            raise HostingStopped(reason)
    if _id(job.get("membership_id")):
        _member(job)
    return True


def _missing_generation(session: Session, candidate: dict) -> str:
    """A newer, complete local inventory may reopen a completed exact member.

    Never use a missing/failed snapshot or an older device incarnation as
    evidence of deletion. This is discovery only; upload still reads remotely.
    """
    from core.db import DeliveryDeviceMonitorStateModel, DeliveryDeviceAccountSnapshotModel
    from services.device_hosting_store import DeviceHostingJob
    tables = inspect(session.connection())
    if not all(tables.has_table(model.__tablename__) for model in (
            DeviceHostingJob, DeliveryDeviceMonitorStateModel, DeliveryDeviceAccountSnapshotModel)):
        return ""
    completed = session.exec(select(DeviceHostingJob).where(
        DeviceHostingJob.device_ref == candidate["device_ref"],
        DeviceHostingJob.device_epoch == candidate["device_epoch"],
        DeviceHostingJob.binding_revision == candidate["binding_revision"],
        DeviceHostingJob.membership_id == candidate["membership_id"],
        DeviceHostingJob.child_id == candidate["child_id"],
        DeviceHostingJob.status == "completed",
    ).order_by(DeviceHostingJob.updated_at.desc())).first()
    if completed is None:
        return ""
    try:
        context = json.loads(completed.context_json or "{}")
    except (ValueError, TypeError):
        return ""
    if not isinstance(context, dict):
        return ""
    verified = _date(context.get("verified_at"))
    state = session.get(DeliveryDeviceMonitorStateModel, candidate["device_ref"])
    refreshed = _date(getattr(state, "refreshed_at", None))
    if (state is None or state.refresh_error or not verified or not refreshed or refreshed <= verified
            or context.get("presence_status") != "confirmed" or context.get("quota_status") != "valid"):
        return ""
    rows = session.exec(select(DeliveryDeviceAccountSnapshotModel).where(
        DeliveryDeviceAccountSnapshotModel.device_key == candidate["device_ref"],
    )).all()
    if len(rows) != state.account_count or not context.get("remote_id"):
        return ""
    for row in rows:
        try:
            payload = json.loads(row.payload_json or "{}")
        except (ValueError, TypeError):
            return ""
        if (not isinstance(payload, dict) or _date(row.checked_at) != refreshed
                or _email(payload.get("email")) == candidate["email"]
                or row.remote_id == context["remote_id"]):
            return ""
    evidence = f"{candidate['device_epoch']}:{candidate['membership_id']}:{refreshed.isoformat()}"
    return hashlib.sha256(evidence.encode()).hexdigest()


def discover(device_ref: str) -> dict:
    """Return all bound mothers, including blocked rows, using local state only."""
    snapshot = _devices().delivery_device_business_bindings(device_ref)
    device = snapshot["device"]
    try:
        epoch = _devices()._device_epoch(device["provider"], device["provider_id"])
    except Exception:
        epoch = ""
    mothers, candidates = [], []
    with Session(engine) as session:
        for binding in snapshot["bindings"]:
            parent_id, source_id = _id(binding.get("plan_account_id")), _id(binding.get("parent_id"))
            parent = session.get(GptPlanAccountModel, parent_id) if parent_id else None
            source = session.get(GptBusinessAccountModel, source_id) if source_id else None
            reason = _parent_reason(parent, source)
            if not reason:
                reason = _nv_reason(session, parent_id, source_id)
            if not reason and (not epoch or device.get("state") != "configured"):
                reason = "设备未配置或已停用"
            if not reason and binding.get("eligible") is not True:
                reason = "母号登录状态或绑定资格尚未确认"
            policy = session.get(GptBusinessAutomationPolicyModel, source_id) if source_id else None
            if not reason and bool(getattr(policy, "auto_rotation_enabled", False)):
                reason = "母号存在旧设备轮换授权，不能并行托管"
            members = session.exec(select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.business_account_id == source_id,
                GptBusinessChildMembershipModel.ended_at.is_(None),
            ).order_by(GptBusinessChildMembershipModel.id)).all() if source_id else []
            seats = _plans()._business_invitable_seat_count(source) if source else 0
            typed = _plans()._exact_business_typed_available_counts(_plans()._safe_business_seat_summary(source) or {}) if source else None
            fill_seat = next((kind for kind in ("default", "prolite") if typed and typed.get(kind, 0) > 0), "")
            quota = _plans()._business_invite_quota_for_source(session, source_id) if source else {}
            from core.business_invite_policy import invitable_counts_by_type
            eligible_seats = invitable_counts_by_type(typed, quota)
            fill_seat = next((kind for kind in ("default", "prolite") if eligible_seats[kind] > 0), "")
            cooldown = _business()._business_invite_cooldown_from_parent(source) if source else {}
            available = min(max(0, int(seats)), sum(eligible_seats.values()))
            invite_reason = reason or ("邀请失败冷却中" if cooldown.get("active") else "席位类型尚未精确确认" if seats > 0 and not typed else "" if available else "等待可用席位或邀请额度")
            base = dict(device_ref=device["device_ref"], parent_account_id=parent_id, source_account_id=source_id,
                parent_email=_email(binding.get("email")), binding_revision=int(binding.get("policy_revision") or 0), device_epoch=epoch)
            mothers.append({**base, "id": parent_id, "plan_account_id": parent_id or None, "email": base["parent_email"],
                "note": str(binding.get("note") or "")[:500], "can_run": not reason, "state": "blocked" if reason else "ready" if available else "waiting",
                "reason": reason or invite_reason, "next_check_at": cooldown.get("resume_at") or quota.get("next_available_at") or "",
                "available_seats": available, "active_child_count": len(members)})
            if reason:
                continue
            for member in members:
                if member.seat_type not in {"default", "prolite"} or not _id(member.pro_account_id) or not _email(member.email):
                    mothers[-1]["reason"] = mothers[-1]["reason"] or "部分成员缺少可确认的邮箱、本地账号或席位类型，需要人工核对"
                    continue
                candidate = {**base, "child_id": _id(member.pro_account_id), "email": _email(member.email),
                    "membership_id": member.id, "seat_type": member.seat_type, "step": "check", "kind": "existing_child",
                    "context": {"membership_invited_at": (_date(member.invited_at).isoformat() if _date(member.invited_at) else "")}}
                try:
                    _member(candidate)
                except HostingStopped as exc:
                    candidate.update(status="review", error=str(exc))
                generation = _missing_generation(session, candidate)
                if generation:
                    candidate["recheck_generation"] = generation
                candidates.append(candidate)
            if not invite_reason:
                candidates.append({**base, "child_id": 0, "email": "", "membership_id": 0, "seat_type": fill_seat,
                                   "step": "select", "kind": "fill"})
    return {"device_ref": device["device_ref"], "mothers": mothers, "candidates": candidates}


def _invited(job: dict) -> dict | None:
    operation = _context(job).get("canonical_operation_id") or job.get("operation_id")
    if not operation:
        return None
    with Session(engine) as session:
        rows = session.exec(select(GptBusinessChildMembershipModel).where(
            GptBusinessChildMembershipModel.operation_id == operation,
            GptBusinessChildMembershipModel.business_account_id == job["source_account_id"],
            GptBusinessChildMembershipModel.ended_at.is_(None),
        )).all()
        if len(rows) != 1:
            return None
        row = rows[0]
        proposed = {**job, "child_id": _id(row.pro_account_id), "email": _email(row.email), "membership_id": row.id}
    member = _member(proposed)
    return {"child_id": proposed["child_id"], "email": proposed["email"], "membership_id": proposed["membership_id"],
            "seat_type": member["seat_type"], "context": {"invite_confirmed": True, "membership_invited_at": member["membership_invited_at"]}}


_INVITE_PREFLIGHT_CODES = frozenset({"invite_cooldown_active", "invite_quota_exhausted", "no_invitable_seat",
    "seat_type_unknown", "derived_seat_type_changed", "business_parent_busy", "gpt_pro_account_busy"})


def _invite_local_wait(job: dict) -> str:
    with Session(engine) as session:
        source = session.get(GptBusinessAccountModel, job["source_account_id"])
        if source is None:
            raise HostingStopped("母号来源已变化")
        if _business()._business_invite_cooldown_from_parent(source).get("active"):
            return "母号邀请冷却尚未结束，等待后重新检查；尚未发送邀请"
        quota = _plans()._business_invite_quota_for_source(session, source.id)
        if int(quota.get("remaining") or 0) <= 0:
            return "母号邀请额度暂未恢复，等待后重新检查；尚未发送邀请"
        typed = _plans()._exact_business_typed_available_counts(_plans()._safe_business_seat_summary(source) or {})
        if not typed or not any(typed.get(kind, 0) > 0 for kind in ("default", "prolite")):
            return "母号暂无可确认类型的空位，等待后重新检查；尚未发送邀请"
        from core.business_invite_policy import invitable_counts_by_type
        if not any(invitable_counts_by_type(typed, quota).values()):
            return "有空位的席位类型邀请额度暂未恢复，等待后重新检查；尚未发送邀请"
    return ""


def _invite_wait_seconds(job: dict, detail=None) -> int:
    if isinstance(detail, dict) and detail.get("code") != "invite_cooldown_active":
        return 300
    cooldown = detail.get("invite_cooldown") if isinstance(detail, dict) else None
    if not isinstance(cooldown, dict):
        with Session(engine) as session:
            source = session.get(GptBusinessAccountModel, job["source_account_id"])
            cooldown = _business()._business_invite_cooldown_from_parent(source) if source else {}
    return cooldown_wait_seconds(cooldown, default=300)


def _invite(job: dict, emit: Callable, checkpoint: Callable, reconcile: bool) -> dict:
    if reconcile or _context(job).get("invite_attempted"):
        saved = _invited(job)
        return _result("advance", "oauth", updates=saved) if saved else _result("review", error="此前邀请结果尚未确认，不重复邀请")
    waiting = _invite_local_wait(job)
    if waiting:
        return _result("wait", delay=_invite_wait_seconds(job), error=waiting)
    operation = job.get("operation_id") or f"device-hosting-{job.get('id', '')}"
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,160}", operation):
        raise HostingStopped("托管邀请缺少稳定操作编号")
    _checkpoint(job, {"context": {"invite_attempted": True, "invite_started_at": _now(), "canonical_operation_id": operation}}, checkpoint)
    body = _plans().GptPlanBusinessChildInviteRequest(operation_id=operation, candidate_mail_provider="auto")
    body._state_guard = lambda: _guard(job, checkpoint)

    def selected(child_id: int, email: str):
        _guard(job, checkpoint)
        with Session(engine) as session:
            child = session.get(GptPlanAccountModel, child_id)
            if child is None or _email(child.email) != _email(email) or not _email(email):
                raise HostingStopped("邀请候选身份未确认")
        _checkpoint(job, {"context": {"candidate_child_id": child_id, "candidate_email": _email(email)}}, checkpoint)
        emit("已记录本次候选账号，开始核验登录状态")
        return True

    body._selection_observer = selected
    emit("调用母号能力，优先选择准备号，不足时补充普通号")
    def prelogin_progress(line):
        from services.business_invite_login_diagnostics import STAGE_LABELS
        if not isinstance(line, str):
            return
        # The canonical source already projects browser logs. Keep this outer
        # boundary closed as well so future source diagnostics cannot leak.
        match = re.fullmatch(r"\[邀请前登录\] 子号 #\d+：(.+)", line)
        if match and match.group(1) in {*STAGE_LABELS.values(), "邮箱输入框定位与回读不一致，尚未确认邮箱填写成功"}:
            emit(f"邀请前登录：{match.group(1)}")
    body._log_fn = prelogin_progress
    try:
        result = _plans().member_business_invite(job["parent_account_id"], body)
    except HTTPException as exc:
        from services.business_invite_login_diagnostics import normalize_prelogin_failure
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if exc.status_code == 409 and detail.get("code") in _INVITE_PREFLIGHT_CODES:
            _guard(job, checkpoint)
            if _invited(job) is not None:
                return _result("review", error="邀请前等待证据与已有邀请流水冲突，不重复邀请")
            cleared = {"context": {"invite_attempted": False, "invite_started_at": "",
                "invite_preflight_failure": {"code": detail["code"], "remote_invite_sent": False}}}
            _checkpoint(job, cleared, checkpoint)
            return _result("wait", delay=_invite_wait_seconds(job, detail), error="母号席位、额度、冷却或共享租约暂未就绪，已确认未发送邀请，等待预计恢复时间后重新检查", updates=cleared)
        failure = normalize_prelogin_failure(exc.detail)
        if failure is None:
            raise
        _guard(job, checkpoint)
        if _invited(job) is not None:
            return _result("review", error="登录失败证据与已存在邀请流水冲突，不重复邀请")
        cleared = {"context": {"invite_failure": {"code": "business_child_prelogin_failed", **failure}}}
        if failure["retryable"]:
            cleared["context"].update(invite_attempted=False, invite_started_at="")
        _checkpoint(job, cleared, checkpoint)
        reason = f"邀请前登录失败，已确认未发送 BUSINESS 邀请：{failure['failure_reason']}"
        emit(reason)
        return _result("retry" if failure["retryable"] else "review", delay=60 if failure["retryable"] else 0,
                       error=reason, updates=cleared)
    _guard(job, checkpoint)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("persistence_confirmed") is not True:
        return _result("review", error="邀请结果或本地归属未同时确认，不重复邀请")
    saved = _invited(job)
    return _result("advance", "oauth", updates=saved) if saved else _result("review", error="邀请后未找到唯一归属流水，需要人工核对")


def _oauth(job: dict, emit: Callable, checkpoint: Callable, reconcile: bool) -> dict:
    member = _member(job)
    target = {key: job[key] for key in ("parent_account_id", "source_account_id", "parent_email", "child_id", "email", "membership_id")}
    target.update({key: member[key] for key in ("membership_invited_at", "remote_user_id", "remote_invite_id")})
    if member["oauth_complete"]:
        floor = _context(job).get("oauth_started_at") or member["membership_invited_at"]
        result = _plans()._reconcile_persisted_business_child_oauth(target, acquired_after=floor)
        _guard(job, checkpoint)
        if result.get("verified") is True:
            return _result("advance", "upload", updates={"context": {"oauth_confirmed": True}})
        if result.get("retryable") is True:
            return _result("retry", delay=60, error="已有 RT 的成员身份读取暂未完成，仅重试只读核验，不重新获取 RT")
        return _result("review", error="已有 RT 的本次成员身份尚未确认，不重新获取 RT")
    if reconcile or _context(job).get("oauth_attempted") or member["has_any_credentials"]:
        return _result("review", error="已有或此前获取的 RT 结果待核对，不自动重新获取")
    emit("子号尚无 RT，调用现有成员认证能力；不额外执行密码或 2FA 设置")

    def before_start():
        _guard(job, checkpoint)
        if _member(job)["has_any_credentials"]:
            raise HostingStopped("其他操作已保存凭据，停止重复获取 RT")
        _checkpoint(job, {"context": {"oauth_attempted": True, "oauth_started_at": _now(),
                                      "membership_invited_at": member["membership_invited_at"]}}, checkpoint)

    # Raw browser logs may contain credentials. Only fixed stage markers leave this adapter.
    last_marker = ""
    def progress(line):
        nonlocal last_marker
        for marker, message in (("[DrissionPage] 1/5", "正在打开 OAuth 授权页"),
                ("[DrissionPage] 2/5", "正在核验并填写子号邮箱"),
                ("[DrissionPage] 3/5", "正在完成子号登录验证"),
                ("[DrissionPage] 4/5", "正在检查邮箱验证与已有 Authenticator"),
                ("[DrissionPage] 5/5", "正在校验 OAuth 回调并获取 RT")):
            if isinstance(line, str) and line.lstrip().startswith(marker) and marker != last_marker:
                last_marker = marker
                emit(message)
                break
    snapshot = _plans()._run_business_child_oauth_with_lease(target, emit=progress,
        before_start=before_start, allow_phone_verification=False, expected_invited_at=member["membership_invited_at"])
    _guard(job, checkpoint)
    if snapshot.get("status") != "done":
        from services.chatgpt_oauth_failure import normalize_oauth_failure
        failure = normalize_oauth_failure(snapshot.get("oauth_failure"))
        if failure:
            task_id = snapshot.get("task_id")
            if (snapshot.get("status") == "failed" and failure["terminal"]
                    and _context(job).get("oauth_attempted") is True
                    and isinstance(task_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", task_id)):
                _checkpoint(job, {"context": {"canonical_task_id": task_id,
                    "oauth_terminal_failed": True, "oauth_failure": failure}}, checkpoint)
            return _result("review", error=f"子号 RT 获取未完成：{failure['reason']}；不自动重新获取 RT")
        return _result("review", error="子号 RT 获取未确认完成，需要人工核对；未授权额外接码")
    return _oauth(job, emit, checkpoint, True)


def _remote(job: dict, checkpoint: Callable) -> dict:
    from services import delivery_device_monitor as monitor
    _guard(job, checkpoint)
    snapshot = monitor.refresh_device_pro_inventory(job["device_ref"], before_persist=lambda: _guard(job, checkpoint))
    _guard(job, checkpoint)
    if snapshot.get("ok") is not True or snapshot.get("device_ref") != job["device_ref"] or not isinstance(snapshot.get("accounts"), list):
        return {"presence_status": "unknown", "quota_status": "unknown"}
    member = _member(job)
    provider, target = job["device_ref"].split(":", 1)
    identity = (member["cpa_expected_auth_name"] if provider == "cpa" else
                _context(job).get("remote_id") or (member["extra"].get("sub2api_remote_account_id")
                    if str(member["extra"].get("sub2api_device_id") or "") == target else ""))
    if identity and any(isinstance(row, dict) and str(row.get("remote_id") or "") == str(identity)
            and _email(row.get("email")) != _email(job["email"]) for row in snapshot["accounts"]):
        return {"presence_status": "identity_changed", "quota_status": "unknown"}
    rows = [row for row in snapshot["accounts"] if isinstance(row, dict) and _email(row.get("email")) == _email(job["email"])]
    if not rows:
        return {"presence_status": "missing", "quota_status": "unknown"}
    if len(rows) != 1:
        return {"presence_status": "ambiguous", "quota_status": "unknown"}
    row = rows[0]
    remote_id = str(row.get("remote_id") or "")
    expected = _context(job).get("remote_id")
    if not remote_id or (expected and expected != remote_id):
        return {"presence_status": "identity_changed", "quota_status": "unknown"}
    if provider == "cpa" and remote_id != member["cpa_expected_auth_name"]:
        return {"presence_status": "identity_changed", "quota_status": "unknown"}
    quota = "valid" if row.get("quota_checked") is True and row.get("usage_status") == "ok" else "unknown"
    if row.get("disabled") is True or row.get("schedulable") is False:
        quota = "disabled"
    elif row.get("quota_http_status") == 401 or row.get("quota_error_code") == "401" or row.get("account_issue") is True:
        quota = "unauthorized"
    elif row.get("error") or row.get("usage_status") == "error":
        quota = "error"
    elif row.get("limit_reached") is True:
        quota = "exhausted"
    return {"presence_status": "confirmed", "quota_status": quota, "remote_id": remote_id, "verified_at": _now()}


def _verify(job: dict, checkpoint: Callable) -> dict:
    before = _member(job)
    evidence = _remote(job, checkpoint)
    updates = {"context": evidence}
    if evidence["presence_status"] == "confirmed" and evidence["quota_status"] == "valid":
        member = _member(job)
        extra = member["extra"]
        if before["credential_fingerprint"] != member["credential_fingerprint"]:
            return _result("retry", delay=60, error="核验期间本地凭据版本发生变化，仅重新读取核验，不重复上传", updates=updates)
        provider, target = job["device_ref"].split(":", 1)
        linked = (extra.get("cpa_synced") is True and str(extra.get("cpa_synced_to_id")) == target
                  and str(extra.get("cpa_auth_name") or "") == evidence["remote_id"]
                  and not any(extra.get(key) for key in ("cpa_sync_pending", "cpa_sync_compensation_pending", "cpa_disabled", "cpa_monitor_suppressed"))) if provider == "cpa" else (
            str(extra.get("sub2api_device_id")) == target
            and str(extra.get("sub2api_remote_account_id") or "") == evidence["remote_id"]
            and not extra.get("sub2api_remote_missing") and not extra.get("sub2api_sync_pending"))
        if not linked:
            return _result("review", error="远端账号已存在，但本次本地设备归属尚未确认，不重复上传或推定完成", updates=updates)
        if not member["oauth_complete"]:
            return _result("review", error="远端核验后本次成员凭据已变化，不能确认完成", updates=updates)
        updates["context"]["credential_fingerprint"] = member["credential_fingerprint"]
        if _context(job).get("upload_attempted") is True:
            updates["context"]["upload_confirmed"] = True
        return _result("advance", "completed" if job.get("step") == "verify" else "verify", updates=updates)
    if evidence["quota_status"] in {"unauthorized", "disabled", "exhausted"}:
        return _result("failed", error="远端凭据存在但认证、启用状态或额度核验未通过；不会删除或自动换号", updates=updates)
    if evidence["presence_status"] == "unknown" or (evidence["presence_status"] == "confirmed" and evidence["quota_status"] in {"unknown", "error"}):
        return _result("retry", delay=60, error="远端只读核验暂未完成，仅重试读取；不重复获取 RT 或上传", updates=updates)
    return _result("review", error="远端账号存在性或额度尚未确认，不标记健康完成、不重复上传", updates=updates)


def _upload(job: dict, emit: Callable, checkpoint: Callable, reconcile: bool) -> dict:
    if reconcile or _context(job).get("upload_attempted"):
        return _verify(job, checkpoint)
    member = _member(job)
    if not member["oauth_complete"]:
        return _result("review", error="没有本次邀请周期可确认的完整 RT，不执行上传")
    operations = _operations()
    lease = operations._claim_gpt_pro_account_operation(job["child_id"], "device_hosting_upload", allow_managed_business_child=True)
    try:
        _guard(job, checkpoint)
        status, _ = _business()._remote_child_membership_status(job["source_account_id"], job["email"])
        _guard(job, checkpoint)
        if status != "member":
            return _result("review", error="上传前未确认子号仍是本母号的远端成员")
        extra = _member(job)["extra"]
        provider, provider_id = job["device_ref"].split(":", 1)
        cpa_id = extra.get("cpa_synced_to_id") or extra.get("cpa_device_id")
        sub_id = extra.get("sub2api_device_id")
        if (cpa_id and (provider != "cpa" or str(cpa_id) != provider_id)) or (sub_id and (provider != "sub2api" or str(sub_id) != provider_id)):
            return _result("review", error="子号已有其他设备关联，托管不执行迁移或覆盖")
        evidence = _remote(job, checkpoint)
        if evidence["presence_status"] == "confirmed":
            _checkpoint(job, {"context": evidence}, checkpoint)
            return _verify(job, checkpoint)
        if evidence["presence_status"] != "missing":
            if evidence["presence_status"] == "unknown":
                return _result("retry", delay=60, error="上传前远端读取暂未完成，仅重试核验，不发送上传请求")
            return _result("review", error="上传前无法唯一确认远端身份，不发送上传请求")
        _checkpoint(job, {"context": {"upload_attempted": True, "upload_started_at": _now()}}, checkpoint)
        emit("调用现有子号上传能力，仅同步到本任务绑定设备，不迁移或删除账号")
        kwargs = dict(expected_business_parent_id=job["source_account_id"], operation_token=lease,
                      delivery_guard=lambda: _guard(job, checkpoint), allow_credential_reauth=False)
        try:
            if provider == "cpa":
                result = operations.sync_account_to_cpa(job["child_id"], int(provider_id), allow_destructive_recovery=False, **kwargs)
            else:
                result = operations.sync_account_to_sub2api(job["child_id"], int(provider_id), **kwargs)
        except HTTPException:
            # A failed write response is not permission to send it again. Read
            # exact presence/quota so a known 401 is surfaced as failed.
            return _verify(job, checkpoint)
        _guard(job, checkpoint)
        if not isinstance(result, dict) or result.get("ok") is not True:
            return _result("review", error="上传结果未确认，保留检查点，不重复上传")
        return _result("advance", "verify", updates={"context": {"upload_confirmed": True}})
    finally:
        operations._release_gpt_pro_account_operation(job["child_id"], lease)


def _run(job: dict, emit: Callable, checkpoint: Callable, reconcile: bool) -> dict:
    try:
        _guard(job, checkpoint)
        step = job.get("step")
        if step == "select":
            with Session(engine) as session:
                rows = _plans()._plan_business_candidate_records(session, job["source_account_id"], candidate_mail_provider="auto")
            return _result("advance", "invite") if rows else _result("wait", error="准备号与普通池暂无可用候选", delay=300)
        if step == "check":
            member = _member(job)
            return _result("advance", "oauth", updates={"context": {"membership_invited_at": member["membership_invited_at"]}})
        if step == "invite":
            return _invite(job, emit, checkpoint, reconcile)
        if step == "oauth":
            return _oauth(job, emit, checkpoint, reconcile)
        if step == "upload":
            return _upload(job, emit, checkpoint, reconcile)
        if step == "verify":
            return _verify(job, checkpoint)
        return _result("review", error="托管任务阶段未识别，未执行账号操作")
    except HostingStopped as exc:
        return _result("review", error=str(exc))
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if (exc.status_code == 409 and detail.get("code") == "gpt_pro_account_busy"
                and job.get("step") in {"oauth", "upload"}
                and not _context(job).get(f"{job['step']}_attempted") and not reconcile):
            return _result("wait", delay=60, error="子号正在执行其他操作；尚未启动本步骤，等待共享租约释放")
        return _result("review", error="托管步骤结果尚未确认，已保留检查点，不自动重放账号操作")
    except Exception:
        # Provider/browser exceptions may contain secrets or whole responses.
        return _result("review", error="托管步骤执行结果未确认，已保留原检查点；请核对，不自动重放")


def execute_step(job: dict, emit: Callable, checkpoint: Callable) -> dict:
    return _run(job, emit, checkpoint, False)


def reconcile_step(job: dict, emit: Callable, checkpoint: Callable) -> dict:
    return _run(job, emit, checkpoint, True)
