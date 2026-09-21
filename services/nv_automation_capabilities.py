"""Narrow, fail-closed adapters for the durable NV sales lifecycle.

The runner owns scheduling and durable job/lease state.  This module owns no
background loop, never retries a remote mutation, and never exposes account
credentials.  Existing GPT Plans capabilities remain the mutation owners.
"""
from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from fastapi import HTTPException
from sqlmodel import Session, func, or_, select

from core.business_invite_policy import BUSINESS_INVITE_WINDOW_HOURS
from core.business_invite_mail_provider import resolve_candidate_mail_provider
from core.db import (
    GptBusinessAccountModel,
    GptBusinessAutomationPolicyModel,
    GptBusinessChildMembershipModel,
    GptBusinessInviteOperationModel,
    GptPlanAccountModel,
)
from services import nexusvault
from services.business_invite_login_diagnostics import normalize_prelogin_failure
from services.nv_invite_progress import normalize_invite_progress
from services.business_invite_wait import cooldown_wait_seconds
from services.chatgpt_security_progress import normalize_security_progress, normalize_task_retry
from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure
from services.nv_oauth_manual_recovery import (
    manual_sms_recovery_granted,
    legacy_unknown_manual_recovery_granted,
)
from services.nv_oauth_retry_policy import recoverable_failure, retry_problem, HARD_FAILURE_CODES
from services.nv_auto_exit_policy import auto_exit_at, normalize_auto_exit_delay_hours
from services.nv_account_tier import (
    TIER_LABELS, make_quota_tier, normalize_quota_tier, nv_windows, usage_windows,
)


def _manual_oauth_recovery_granted(context: dict) -> bool:
    return manual_sms_recovery_granted(context) or legacy_unknown_manual_recovery_granted(context)


def _plans():
    # Keep the durable runner importable without loading API/task machinery.
    from api import gpt_plans
    return gpt_plans


def _business():
    from api import gpt_business
    return gpt_business


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _date(value: Any) -> datetime | None:
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value or "").replace("Z", "+00:00")
        )
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value is not None else ""


def _email(value: Any) -> str:
    value = str(value or "").strip().casefold()
    if len(value) > 320 or not re.fullmatch(r"[^\s@]+@[^\s@]+", value):
        return ""
    return value


def _identifier(value: Any) -> str:
    # IDs are not free-form log messages.  In particular, reject credential
    # assignment/URL-shaped strings even when a remote payload calls it an ID.
    value = str(value or "").strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else ""


def _positive(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _context(job: dict) -> dict:
    return dict(job.get("context")) if isinstance(job.get("context"), dict) else {}


def _settings(job: dict) -> dict:
    return job.get("settings") if isinstance(job.get("settings"), dict) else {}


def _live_exit_settings(job: dict | None = None, context: dict | None = None) -> tuple[bool, float | None]:
    """Release timing is live policy, never the job's frozen listing settings."""
    from services import nv_automation_store as store
    settings = store.get_settings()
    if job is None:
        return (settings.get("auto_exit") is True,
                normalize_auto_exit_delay_hours(settings.get("auto_exit_delay_hours", 2)))
    from services.nv_tier_policy import exit_delay_for_tier
    from services.nv_job_exit_policy import exit_delay_override, manual_exit_authorized
    # Fresh NV evidence augments the frozen job context, rather than dropping
    # the per-order override merely because the NV payload has no private keys.
    merged = {**_context(job), **(context or {})}
    override = exit_delay_override(job, merged)
    enabled = settings.get("auto_exit") is True or manual_exit_authorized(job, merged, now=_now().timestamp())
    if override is not None:
        return enabled, override
    proof = normalize_quota_tier(merged.get("quota_tier"), job, now=_now())
    return (enabled, exit_delay_for_tier(
        settings, proof["tier"] if proof else "unknown", seat_type=job.get("seat_type", ""),
    ))


def _exit_wait_result(warranty_until: Any, confirmed: dict, *, emit: Callable | None = None,
                      check_enabled: bool = True, job: dict | None = None) -> dict | None:
    enabled, delay_hours = _live_exit_settings(job, confirmed)
    if delay_hours is None:
        return _result("wait", next_step="wait_warranty", delay=60,
            error="普通席位的 5 小时限制尚未核验，暂不能确定自动退出时间；等待 NV 额度证据更新",
            updates={"context": confirmed})
    deadline = auto_exit_at(warranty_until, delay_hours)
    if deadline is None:
        return _review("真实质保截止时间无法确认，不能安排自动退出")
    from services.nv_job_exit_policy import manual_sale_early_exit_authorized
    context = {**_context(job or {}), **confirmed}
    if manual_sale_early_exit_authorized(job, context, now=_now().timestamp()):
        # Only the durable, cycle-bound explicit request bypasses the manual
        # sale's countdown. Merely marking it sold still waits normally.
        return None
    remaining = (deadline - _now()).total_seconds()
    if remaining > 0:
        if emit is not None:
            _log(emit, f"尚未到自动退出时间：质保截止后需再等 {delay_hours:g} 小时，预计 {_iso(deadline)}；手动退出不受此限制")
        return _result("wait", next_step="wait_warranty", delay=math.ceil(remaining), updates={"context": confirmed})
    if check_enabled and not enabled:
        return _result("wait", next_step="wait_warranty", delay=60,
            error=f"质保结束已满 {delay_hours:g} 小时，自动退出开关未开启", updates={"context": confirmed})
    return None


def _safe_error(exc: Any) -> str:
    if isinstance(exc, HTTPException):
        return f"HTTP {exc.status_code}：{_plans()._business_child_batch_action_error(exc)}"[:480]
    if isinstance(exc, (nexusvault.NexusVaultConfigurationError, nexusvault.NexusVaultRequestError)):
        return _plans()._sanitize_member_task_text(str(exc))[:480]
    # Validation failures from the BUSINESS facade are deterministic and do
    # not contain credentials. Preserve their short, sanitized reason so an
    # operator can repair the exact binding instead of seeing only the opaque
    # exception class (which otherwise looks like a transient remote failure).
    if isinstance(exc, ValueError):
        detail = _plans()._sanitize_member_task_text(str(exc)).strip()
        return (f"参数校验失败：{detail}" if detail else "参数校验失败")[:480]
    if isinstance(exc, RuntimeError):
        detail = _plans()._sanitize_member_task_text(str(exc)).strip()
        # These messages are emitted by our own fixed OAuth guards and contain
        # no provider payload. Preserve them so an automatic quota repair shows
        # why startup was rejected instead of only exposing ``RuntimeError``.
        if detail.startswith(("RT 任务未能安全启动", "BUSINESS 子号凭证修复租约已失效")):
            return detail[:480]
    # Arbitrary exceptions can include OAuth URLs, cookies or provider secrets.
    return f"操作未能确认（{type(exc).__name__}）"


def _log(emit: Callable, message: str) -> None:
    emit(_plans()._sanitize_member_task_text(message))


def _result(outcome: str, *, next_step: str = "", error: str = "", delay: int = 0, updates: dict | None = None) -> dict:
    result: dict[str, Any] = {"outcome": outcome}
    if next_step:
        result["next_step"] = next_step
    if error:
        result["error"] = _plans()._sanitize_member_task_text(error)[:500]
    if delay:
        result["delay_seconds"] = max(1, min(int(delay), 172800))
    if updates:
        result["updates"] = updates
    return result


def _review(message: str) -> dict:
    return _result("review", error=f"{message} ；请人工核对，未自动重试")


def _child_deactivation_result(job: dict, exc) -> dict | None:
    """Route only a typed failure for the exact child, never mother/HTTP text."""
    detail = exc.detail if isinstance(exc, HTTPException) and isinstance(exc.detail, dict) else {}
    explicit = (detail.get("code") in {"account_deactivated", "account_deleted", "user_deactivated"}
                and type(detail.get("child_id")) is int and detail["child_id"] == job.get("child_id")
                and detail.get("email") == _email(job.get("email")))
    if isinstance(exc, OAuthAttemptFailure) and job.get("step") == "oauth":
        failure = normalize_oauth_failure(exc.oauth_failure)
        explicit = bool(failure and failure["code"] == "account_deactivated" and failure["terminal"])
    if not explicit:
        return None
    from services.nv_dead_child_cleanup import make_deactivation_evidence, DEACTIVATION_KEY
    proof = make_deactivation_evidence(job)
    if proof is None:
        return _review("远端明确报告子号停用，但本次成员周期证据不完整；未删除，等待身份核对")
    return _result("failed", error="OpenAI 已明确停用该子号，等待清理关联后重新补号",
                   updates={"context": {DEACTIVATION_KEY: proof}})


def _prelogin_failure(detail: Any) -> dict[str, Any] | None:
    normalized = normalize_prelogin_failure(detail)
    if normalized is None:
        return None
    return {"code": "business_child_prelogin_failed", **normalized}


def _mother_identity_reason(parent: Any, source: Any) -> str:
    if (parent is None or parent.source_pool != "gpt_business"
            or parent.business_parent_id is not None
            or _plans()._canonical_member_plan(parent.plan_type) != "team"):
        return "账号不是 GPT 套餐目录中的 BUSINESS 母号"
    if (source is None or parent.source_account_id != source.id
            or not _email(parent.email) or _email(source.email) != _email(parent.email)):
        return "母号来源绑定已变化"
    return ""


def _mother_action_reason(parent: Any, source: Any) -> str:
    if any(str(value or "") in {"refunded", "refunded_pending_credit", "refund_credited"}
           for value in (parent.refund_status, source.refund_status)) or _plans()._catalog_category(parent) == "refunded":
        return "母号已经退款，不能执行账号变更"
    if parent.dangerous or source.dangerous:
        return "母号已标记 Dead，不能执行账号变更"
    if not parent.enabled or not source.enabled:
        return "母号已停用，不能执行账号变更"
    from services.device_hosting_store import mother_is_hosted
    with Session(_plans().engine) as session:
        if mother_is_hosted(int(source.id), session=session):
            return "母号正在由 CPA/SUB 设备托管，请先暂停设备托管后再由 NV 管理"
    return ""


def _mother_revenue_cap(session: Session, parent_id: int, settings: dict, seat_types: list[str]) -> dict:
    """Return received NV revenue and cap state for one mother.

    Only receipts confirmed by the immutable sales ledger are counted.  Orders
    still inside warranty (or with an unknown amount) deliberately contribute
    zero, so a pending sale cannot stop rotation prematurely.
    """
    from services import nv_order_history as history
    from services.nv_revenue_cap import evaluate_caps
    totals = {"default": 0, "prolite": 0}
    try:
        orders = session.exec(select(history.NvSaleOrder).where(
            history.NvSaleOrder.parent_account_id == int(parent_id))).all()
    except Exception:
        orders = []
    now = _now()
    for order in orders:
        tier = str(order.seat_type or "").strip().lower()
        if tier not in totals:
            continue
        receipt = history._receipt(order, now)
        if receipt.get("status") == "received" and isinstance(receipt.get("revenue_cents"), int):
            totals[tier] += max(0, int(receipt["revenue_cents"]))
    return evaluate_caps(totals, seat_types, settings)


def _assert_parent(job: dict, *, require_action: bool = False) -> None:
    plans = _plans()
    with Session(plans.engine) as session:
        parent = session.get(GptPlanAccountModel, _positive(job.get("parent_account_id")))
        source = session.get(GptBusinessAccountModel, _positive(job.get("source_account_id")))
        if (
            parent is None or source is None
            or parent.source_pool != "gpt_business"
            or parent.business_parent_id is not None
            or parent.source_account_id != source.id
            or _email(parent.email) != _email(job.get("parent_email"))
            or _email(source.email) != _email(job.get("parent_email"))
            or not _email(job.get("parent_email"))
        ):
            raise HTTPException(409, "自动售号母号绑定已变化")
        if require_action:
            reason = _mother_identity_reason(parent, source) or _mother_action_reason(parent, source)
            policy = session.get(GptBusinessAutomationPolicyModel, int(source.id))
            if reason or bool(getattr(policy, "auto_rotation_enabled", False)):
                raise HTTPException(409, reason or "母号启用了旧设备自动轮换，不能并行执行账号变更")
    if require_action:
        binding, _ = plans._business_child_facade_binding(
            int(job["parent_account_id"]), require_action=True,
        )
        if binding.source_account_id != job["source_account_id"] or binding.normalized_email != _email(job["parent_email"]):
            raise HTTPException(409, "自动售号母号绑定已变化")


def _member(job: dict, *, allow_ended: bool = False, require_remote: bool = False) -> dict:
    """Read immutable identity only; NV monitoring has no mother health gate."""
    plans = _plans()
    _assert_parent(job)
    with Session(plans.engine) as session:
        row = session.get(GptBusinessChildMembershipModel, _positive(job.get("membership_id")))
        child = session.get(GptPlanAccountModel, _positive(job.get("child_id")))
        if (
            row is None or child is None
            or row.business_account_id != _positive(job.get("source_account_id"))
            or row.pro_account_id != _positive(job.get("child_id"))
            or _email(row.email) != _email(job.get("email"))
            or _email(child.email) != _email(job.get("email"))
            or not _email(job.get("email"))
            or _email(job.get("email")) == _email(job.get("parent_email"))
            or str(row.source or "") != "pool"
            or (row.ended_at is not None and not allow_ended)
            or (row.ended_at is None and child.business_parent_id != row.business_account_id)
        ):
            raise HTTPException(409, "自动售号成员身份或归属已变化")
        remote = _identifier(row.remote_user_id)
        frozen_remote = _identifier(job.get("remote_user_id"))
        if (frozen_remote and remote != frozen_remote) or (require_remote and not remote):
            raise HTTPException(409, "自动售号远端成员身份已变化或尚未加入空间")
        original_invite = _identifier(_context(job).get("existing_invite_id"))
        if original_invite and not remote and _identifier(row.remote_invite_id) != original_invite:
            raise HTTPException(409, "已有成员的远端邀请身份已变化")
        original_invited_at = _context(job).get("membership_invited_at")
        if _context(job).get("existing_member") is True and original_invited_at and original_invited_at != _iso(_date(row.invited_at)):
            raise HTTPException(409, "已有成员的邀请周期已变化")
        return {
            "membership_id": int(row.id),
            "child_id": int(child.id),
            "email": _email(row.email),
            "remote_user_id": remote,
            "remote_invite_id": _identifier(row.remote_invite_id),
            "seat_type": plans._safe_business_child_seat_type(row.seat_type),
            "ended_at": _iso(_date(row.ended_at)),
            "operation_id": _identifier(row.operation_id),
            "nv_listed_at": _iso(_date(row.nv_listed_at)),
            "nv_listing_confirmed_at": _iso(_date(row.nv_listing_confirmed_at)),
            "nv_remote_card_id": _identifier(row.nv_remote_card_id),
            "nv_remote_order_id": _identifier(row.nv_remote_order_id),
            "nv_identifiers_valid": all(not str(getattr(row, key) or "").strip() or _identifier(getattr(row, key))
                                        for key in ("nv_remote_card_id", "nv_remote_order_id")),
            "sale_status": str(row.sale_status or ""),
            "sold_at": _iso(_date(row.sold_at)),
            "membership_invited_at": _iso(_date(row.invited_at)),
            "warranty_hours": row.warranty_hours,
            "nv_team5x_warranty_until": _iso(_date(getattr(row, "nv_team5x_warranty_until", None))),
            "oauth_acquired_at": _iso(_date(child.codex_rt_acquired_at)),
            "oauth_complete": all(str(value or "").strip() for value in (
                child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
            )),
            "oauth_has_any_credentials": any(str(value or "").strip() for value in (
                child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
                child.codex_session_token,
            )),
            # Ephemeral comparison only: never put this in logs/checkpoints or
            # public task DTOs. Detect writes racing the canonical account lease.
            "oauth_credential_version": hashlib.sha256(json.dumps([
                child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
                child.codex_session_token,
            ]).encode()).hexdigest(),
        }


def _action_target(job: dict) -> dict:
    return {key: job.get(key) for key in (
        "membership_id", "parent_account_id", "source_account_id", "child_id", "email",
    )}


def discover_mothers(settings: dict) -> list[dict]:
    """Discover real BUSINESS mothers; selection is not mutation eligibility.

    The invite capability still performs live seat, quota and cooldown checks
    under its existing cross-process fence.  Discovery never enables or writes
    the old delivery-device automation policy.
    """
    from services.business_mother_status import mother_dead_status
    plans, business = _plans(), _business()
    selected = {_positive(value) for value in settings.get("mother_ids", [])}
    selected.discard(0)
    result = []
    with Session(plans.engine) as session:
        rows = session.exec(select(GptPlanAccountModel).where(
            or_(
                GptPlanAccountModel.source_pool == "gpt_business",
                GptPlanAccountModel.id.in_(sorted(selected)),
            ),
        ).order_by(GptPlanAccountModel.id)).all()
        for parent in rows:
            reason = ""
            source = session.get(GptBusinessAccountModel, _positive(parent.source_account_id)) if parent.source_pool == "gpt_business" else None
            reason = _mother_identity_reason(parent, source)
            selectable = not reason
            if not selectable and int(parent.id) not in selected:
                continue
            if not reason:
                reason = _mother_action_reason(parent, source)
            policy = session.get(GptBusinessAutomationPolicyModel, int(source.id)) if source is not None else None
            # A mere device binding can be read-only monitoring.  Only an
            # enabled old rotator competes for workspace seats and must block.
            if not reason and bool(getattr(policy, "auto_rotation_enabled", False)):
                reason = "母号已启用旧设备自动轮换，避免两套任务争用席位"
            invite_blocker = "unavailable" if reason else None
            seats = plans._business_invitable_seat_count(source) if source is not None else 0
            summary = plans._safe_business_seat_summary(source) if source is not None else None
            typed_seats = plans._exact_business_typed_available_counts(summary or {}) or {}
            positive_types = [kind for kind, count in typed_seats.items() if count > 0]
            seat_type = positive_types[0] if len(positive_types) == 1 else "mixed" if positive_types else ""
            cap_seat_types = [kind for kind in ("default", "prolite")
                              if int(typed_seats.get(kind) or 0) > 0]
            if not cap_seat_types:
                # A full mother can have no currently free seat while still
                # having historical sales/jobs that determine its cap class.
                try:
                    from services.nv_order_history import NvSaleOrder
                    cap_seat_types = sorted({str(row or '').strip().lower()
                                             for row in session.exec(select(NvSaleOrder.seat_type).where(
                                                 NvSaleOrder.parent_account_id == int(parent.id))).all()
                                             if str(row or '').strip().lower() in {'default', 'prolite'}})
                except Exception:
                    cap_seat_types = []
            # Keep a configured cap visible even when the seat is temporarily
            # full; existing sold jobs can still finish their lifecycle.
            if not cap_seat_types:
                cap_seat_types = ["prolite"] if seat_type == "prolite" else ["default"] if seat_type == "default" else []
            revenue_cap = _mother_revenue_cap(session, int(parent.id), settings, cap_seat_types)
            if not reason and revenue_cap.get("rotation_blocked"):
                reason = "营收已达到轮转上限，已停止新增轮转任务"
                invite_blocker = "revenue_cap"
            quota = plans._business_invite_quota_for_source(session, int(source.id)) if source is not None else {}
            from core.business_invite_policy import invitable_counts_by_type, quota_for_seat
            eligible_seats = invitable_counts_by_type(typed_seats, quota)
            cooldown = business._business_invite_cooldown_from_parent(source) if source is not None else {}
            recovery_quota = ([quota_for_seat(quota, kind).get("next_available_at")
                               for kind, count in typed_seats.items() if count > 0]
                              if isinstance(quota.get("by_type"), dict) else [quota.get("next_available_at")])
            typed_recovery = [_date(value) for value in recovery_quota if _date(value) is not None]
            quota_recovery = (min(typed_recovery) if typed_recovery and not any(eligible_seats.values()) else None)
            recovery_times = [value for value in (
                _date(cooldown.get("resume_at")), quota_recovery,
            ) if value is not None]
            remaining = (min(seats, sum(eligible_seats.values())) if isinstance(quota.get("by_type"), dict)
                         else min(seats, max(0, int(quota.get("remaining") or 0))))
            if not reason and cooldown.get("active"):
                reason = "母号邀请失败冷却中"
                invite_blocker = "invite_cooldown"
            if not reason and remaining <= 0:
                reason = f"母号暂无已确认可邀请席位或 {BUSINESS_INVITE_WINDOW_HOURS} 小时邀请额度"
                # This is display evidence, not a new invitation gate. Missing
                # quota metadata must not become "exhausted" through the old
                # fail-closed remaining=0 default used for eligibility.
                quota_remaining = remaining if seats > 0 and isinstance(quota.get("by_type"), dict) else quota.get("remaining")
                invite_blocker = ("invite_quota" if type(quota_remaining) is int and quota_remaining <= 0
                                  else "seat_capacity" if seats <= 0 else None)
            if not reason:
                try:
                    binding, _ = plans._business_child_facade_binding(int(parent.id), require_action=True)
                    if binding.source_account_id != source.id or binding.normalized_email != _email(parent.email):
                        reason = "母号来源绑定已变化"
                except HTTPException as exc:
                    reason = _safe_error(exc)
                if reason:
                    invite_blocker = "unavailable"
            result.append({
                **mother_dead_status(parent, source if source is not None
                                     and _email(source.email) == _email(parent.email) else None),
                "id": int(parent.id), "email": _email(parent.email),
                "parent_account_id": int(parent.id),
                "source_account_id": int(source.id) if source is not None else 0,
                "parent_email": _email(parent.email),
                "business_usage_type": plans._public_business_usage_type(parent.business_usage_type),
                "selectable": selectable, "eligible": not reason, "reason": reason,
                "invite_blocker": invite_blocker,
                "available": remaining, "seat_type": seat_type,
                "available_seat_types": typed_seats,
                "available_seats": remaining,
                "invite_quota": {**quota, "window_hours": BUSINESS_INVITE_WINDOW_HOURS},
                "quota_by_type": quota.get("by_type", {}),
                "invitable_by_type": eligible_seats,
                "quota_remaining": max(0, int(quota.get("remaining") or 0)),
                "quota_reset_at": str(quota.get("reset_at") or ""),
                "invite_cooldown": cooldown,
                "next_available_at": _iso(max(recovery_times)) if recovery_times else "",
                "note": plans._sanitize_member_task_text(str(parent.note or "")),
                "revenue_cap": revenue_cap,
                "rotation_blocked": bool(revenue_cap.get("rotation_blocked")),
            })
    return result


def _security_complete(status: dict) -> bool:
    return bool(status.get("credentials_readable") is True and status.get("has_password")
                and status.get("has_totp") and status.get("password_state") == "configured"
                and status.get("mfa_state") == "enabled")


def _security_progress_from_snapshot(snapshot: Any) -> dict[str, Any] | None:
    if not isinstance(snapshot, dict):
        return None
    meta = snapshot.get("meta")
    if not isinstance(meta, dict):
        return None
    return normalize_security_progress(meta.get("security_progress"))


def _security_progress_update(progress: dict[str, Any] | None) -> dict[str, Any]:
    return {"security_progress": progress} if progress is not None else {}


def _terminal_security_progress(
    job: dict,
    reason: str,
    *,
    status: str,
    code: str,
    snapshot: Any = None,
) -> dict[str, Any]:
    current = _security_progress_from_snapshot(snapshot)
    if current is None:
        current = normalize_security_progress(_context(job).get("security_progress"))
    current = current or {}
    terminal = current.get("status") in {"failed", "review"}
    retry_mode = current.get("retry_mode")
    if retry_mode not in {"manual", "verify_first"}:
        retry_mode = "verify_first"
    return normalize_security_progress({
        "stage": current.get("stage") or "session_check",
        "status": status,
        "code": (current.get("code") if terminal else "") or code,
        "reason": (current.get("reason") if terminal else "") or reason,
        "retry_mode": retry_mode,
        "retry_attempt": current.get("retry_attempt", 0),
        "retry_limit": current.get("retry_limit", 0),
        "completed_stages": current.get("completed_stages", []),
        # An old checkpoint or an intermediate failed substep is not proof
        # that the current canonical task has ended safely. Only preserve a
        # fresh, terminal source snapshot's explicit task-level permission.
        "task_retry": (current.get("task_retry") if terminal
                       and _security_progress_from_snapshot(snapshot) is not None else None),
    }) or {}


def _security_failed_result(job: dict, snapshot: dict, checkpoint: Callable | None) -> dict:
    """Schedule only source-proven retries after the canonical lease is released."""
    plans = _plans()
    reason = plans._sanitize_member_task_text(snapshot.get("error") or "安全设置任务未完成")
    progress = _terminal_security_progress(
        job, reason, status="failed", code="security_failed", snapshot=snapshot,
    )
    policy = normalize_task_retry(progress.get("task_retry"))
    if snapshot.get("status") != "failed":
        # A user's explicit cancellation must not restart itself.
        policy = normalize_task_retry({"strategy": "manual", "reason_code": "insufficient_evidence"})
    updates = {"context": {
        "security_attempted": False,
        "task_retry": policy,
        **_security_progress_update(progress),
    }}
    if _context(job).get("security_recovery") or _context(job).get("security_retry"):
        # This separate one-shot budget never becomes a new ordinary retry
        # budget. Preserve both the original attempts and all saved material.
        updates["context"]["task_retry"] = {"strategy": "manual", "reason_code": "insufficient_evidence"}
        return _result("review", error="本次受限安全核验仍未完成；保留已有密码与 2FA，未再次启动：" + reason,
                       updates=updates)
    if policy and policy.get("strategy") in {"safe_resume", "verify_existing"}:
        # Persist the exact terminal proof and clear the attempted fence before
        # returning retry. A crash must never fabricate permission from an old
        # error string, and the next worker still uses the canonical capability.
        _checkpoint(job, updates, checkpoint)
        label = ("临时故障，稍后先核验原密码/2FA 再继续，不重复设置"
                 if policy["strategy"] == "verify_existing"
                 else "临时故障，稍后重新核验账号状态并安全继续")
        return _result("retry", delay=60, error=f"安全设置{label}：{reason}", updates=updates)
    return _result("failed", error=f"安全设置任务已结束：{reason}", updates=updates)


def _existing_listing_error(job: dict, member: dict | None = None) -> str:
    """Validate immutable prior-listing evidence, never invent an empty baseline."""
    context = _context(job)
    basis = context.get("existing_listing")
    if context.get("existing_member") is not True or not isinstance(basis, dict) or basis.get("kind") != "persisted_nv_listing":
        return "已有上架记录缺少可确认的历史销售周期证据"
    for key in ("parent_account_id", "source_account_id", "child_id", "email", "membership_id", "remote_user_id"):
        if basis.get(key) != job.get(key):
            return "已有上架记录的冻结成员身份不一致"
    invited, listed, confirmed = (_date(basis.get(key)) for key in
                                   ("membership_invited_at", "nv_listed_at", "nv_listing_confirmed_at"))
    if not invited or not listed or not confirmed or not invited <= listed <= confirmed <= _now():
        return "已有上架记录缺少本次成员周期的真实 NV 上架确认时间"
    warranty = basis.get("warranty_hours")
    absolute = _date(basis.get("nv_team5x_warranty_until"))
    if basis.get("nv_team5x_warranty_until") and (absolute is None or absolute <= listed):
        return "已有上架记录的 5X 质保截止时间无效"
    if absolute is None and (not isinstance(warranty, int) or isinstance(warranty, bool) or not 1 <= warranty <= 87600):
        return "已有上架记录的原质保时长无效，不能自动计算过保时间"
    if not _identifier(basis.get("remote_user_id")):
        return "已有上架记录没有冻结已加入成员身份"
    if basis.get("identifiers_valid") is False or (member and member.get("nv_identifiers_valid") is False):
        return "已有上架记录的远端卡片或订单标识无效"
    if member:
        for key in ("membership_invited_at", "nv_listed_at", "nv_listing_confirmed_at", "warranty_hours"):
            if member.get(key) != basis.get(key):
                return "已有上架记录的成员周期、上架确认或原质保已变化"
        if _date(member.get("nv_team5x_warranty_until")) != absolute:
            return "已有上架记录的 5X 质保截止时间已变化"
        for key in ("nv_remote_card_id", "nv_remote_order_id"):
            frozen = _identifier(basis.get(key))
            learned = _identifier(context.get(key))
            live = _identifier(member.get(key))
            if (frozen and frozen != live) or (learned and learned != live):
                return "已有上架记录的 NV 卡片或订单身份已变化"
    return ""


def discover_existing_children(settings: dict) -> list[dict]:
    """Read current members for the explicitly managed mothers; no remote I/O."""
    plans = _plans()
    selected = {_positive(value) for value in settings.get("mother_ids", [])}
    selected -= {_positive(value) for value in settings.get("paused_mother_ids", [])}
    selected.discard(0)
    candidates = []
    with Session(plans.engine) as session:
        for parent_id in sorted(selected):
            parent = session.get(GptPlanAccountModel, parent_id)
            source = session.get(GptBusinessAccountModel, _positive(parent.source_account_id)) if parent else None
            if _mother_identity_reason(parent, source):
                continue  # The mother directory itself retains this invalid selection.
            members = session.exec(select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.business_account_id == int(source.id),
                GptBusinessChildMembershipModel.ended_at.is_(None),
            ).order_by(GptBusinessChildMembershipModel.id)).all()
            email_counts = Counter(_email(row.email) for row in members)
            child_counts = Counter(row.pro_account_id for row in members if row.pro_account_id)
            for row in members:
                child = session.get(GptPlanAccountModel, _positive(row.pro_account_id))
                candidate = dict(parent_account_id=parent_id, source_account_id=int(source.id),
                    parent_email=_email(parent.email), child_id=_positive(row.pro_account_id), email=_email(row.email),
                    membership_id=int(row.id), remote_user_id=_identifier(row.remote_user_id),
                    seat_type=plans._safe_business_child_seat_type(row.seat_type), step="security", status="pending", error="",
                    context={"existing_member": True, "membership_invited_at": _iso(_date(row.invited_at)),
                             "existing_invite_id": _identifier(row.remote_invite_id)})
                error = ""
                if (str(row.source or "") != "pool" or child is None):
                    error = "该成员不是有完整套餐账号绑定的受管子号，需要人工接管"
                elif (not candidate["email"] or candidate["email"] == candidate["parent_email"]
                      or _email(child.email) != candidate["email"] or child.business_parent_id != source.id):
                    error = "成员邮箱、套餐账号或母号归属不一致，不能自动接管"
                elif email_counts[candidate["email"]] > 1 or child_counts[row.pro_account_id] > 1:
                    error = "当前成员身份存在重复记录，不能唯一接管销售周期"
                elif not candidate["remote_user_id"] and not candidate["context"]["existing_invite_id"]:
                    error = "成员缺少正式成员或已保存邀请身份，不能安全继续；不会重复邀请"
                elif row.intent_remote_started or str(row.end_reason or "").startswith("pending:"):
                    error = "成员存在未确认的退出操作，需要按原操作核对"
                elif str(row.sale_status or "") not in {"unlisted", "listed", "sold", "refunded", "partial_refund"}:
                    error = "成员的本地销售状态无效，需要人工核对"
                listing = (str(row.sale_status or "") != "unlisted" or row.nv_listed_at is not None
                           or row.nv_listing_confirmed_at is not None or bool(row.nv_remote_card_id)
                           or bool(row.nv_remote_order_id) or row.sold_at is not None
                           or getattr(row, "nv_team5x_warranty_until", None) is not None)
                if listing:
                    candidate.update(step="wait_sale", status="waiting")
                    basis = {key: candidate[key] for key in ("parent_account_id", "source_account_id", "child_id", "email", "membership_id", "remote_user_id")}
                    basis.update(kind="persisted_nv_listing", membership_invited_at=_iso(_date(row.invited_at)),
                        nv_listed_at=_iso(_date(row.nv_listed_at)), nv_listing_confirmed_at=_iso(_date(row.nv_listing_confirmed_at)),
                        nv_remote_card_id=_identifier(row.nv_remote_card_id), nv_remote_order_id=_identifier(row.nv_remote_order_id),
                        warranty_hours=row.warranty_hours,
                        nv_team5x_warranty_until=_iso(_date(getattr(row, "nv_team5x_warranty_until", None))),
                        identifiers_valid=all(not str(getattr(row, key) or "").strip() or bool(_identifier(getattr(row, key)))
                                              for key in ("nv_remote_card_id", "nv_remote_order_id")))
                    candidate["context"]["existing_listing"] = basis
                    error = error or _existing_listing_error(candidate)
                    if any(str(getattr(row, key) or "").strip() and not _identifier(getattr(row, key))
                           for key in ("nv_remote_card_id", "nv_remote_order_id")):
                        error = error or "已有上架记录的远端卡片或订单标识无效"
                elif not error:
                    if child.dangerous or not child.enabled or plans._catalog_category(child) == "refunded":
                        error = "子号已停用、Dead 或已退款，不能自动执行安全设置或上架"
                    else:
                        status = plans._chatgpt_security_status_for_email(candidate["email"])
                        if status.get("credentials_readable") is not True:
                            error = "子号已保存的安全凭证状态不可确认，请人工核对"
                        elif _security_complete(status):
                            invited, acquired = _date(row.invited_at), _date(child.codex_rt_acquired_at)
                            complete = (all(str(value or "").strip() for value in (
                                child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
                            )) and candidate["remote_user_id"] and invited is not None and acquired is not None and invited <= acquired <= _now())
                            candidate["step"] = "publish" if complete else "oauth"
                if error:
                    candidate.update(status="review", error=plans._sanitize_member_task_text(error))
                candidates.append(candidate)
    return candidates


def _checkpoint(job: dict, updates: dict, checkpoint: Callable | None) -> None:
    if not callable(checkpoint):
        raise RuntimeError("自动售号持久检查点不可用")
    # Returning normally means the runner has committed its owner-token CAS.
    # Never treat an explicitly false acknowledgement as a committed fence.
    if checkpoint(updates) is False:
        raise RuntimeError("自动售号持久检查点未确认")
    for key, value in updates.items():
        if key == "context":
            job["context"] = {**_context(job), **value}
        else:
            job[key] = value


def _operation(job: dict) -> str:
    operation = _identifier(job.get("operation_id"))
    if not operation:
        raise HTTPException(409, "自动售号缺少持久操作 ID")
    return operation


def _assert_new_invite_allowed(job: dict) -> None:
    _assert_parent(job, require_action=True)
    if job["parent_account_id"] not in _settings(job).get("mother_ids", []):
        raise HTTPException(409, "该母号不在自动售号授权范围")
    mother = next((item for item in discover_mothers(_settings(job))
                   if item["parent_account_id"] == job["parent_account_id"]), None)
    if mother and mother.get("eligible"):
        return
    if mother and mother.get("invite_blocker") == "invite_cooldown":
        raise HTTPException(409, {
            "code": "invite_cooldown_active",
            "message": "母号邀请冷却中，等待预计恢复时间后重新检查",
            "invite_cooldown": mother.get("invite_cooldown") or {},
        })
    if not mother or not mother.get("eligible"):
        raise HTTPException(409, "母号暂无已确认席位、邀请额度或处于冷却/已退款状态")


def _invite_condition_wait_seconds(exc: HTTPException) -> int:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    if detail.get("code") == "invite_cooldown_active":
        return cooldown_wait_seconds(detail.get("invite_cooldown") or detail, now=_now())
    # Local quota can become available after a policy change; don't defer it
    # to an old reset deadline or confuse it with a remote rejection cooldown.
    return 600



def _new_candidate_mail_policy(job: dict) -> tuple[str, str]:
    """Resolve automatic mail source only after an exact seat/quota decision."""
    configured = resolve_candidate_mail_provider(_settings(job).get("mail_provider", "auto"), "")
    if configured != "auto":
        # An explicit source does not depend on seat type; leave the canonical
        # invitation capability in charge of selecting the live typed seat.
        return "", configured
    with Session(_plans().engine) as session:
        source = session.get(GptBusinessAccountModel, int(job["source_account_id"]))
        if source is None or _email(source.email) != _email(job.get("parent_email")):
            raise HTTPException(409, "母号身份暂不可用，等待重新核验后选择子号")
        summary = _plans()._safe_business_seat_summary(source) or {}
        quota = _plans()._business_invite_quota_for_source(session, int(source.id))
        seat_type = _business()._derive_exact_business_invite_seat_type(summary, required_count=1, invite_quota=quota)
        provider = resolve_candidate_mail_provider("auto", seat_type, session=session)
    if provider == "auto":
        raise HTTPException(409, "尚未确认实际席位类型，等待核验后按席位默认邮箱配置选择子号")
    return seat_type, provider


def _bound_candidate_mail_provider(job: dict, child) -> str:
    """A saved child never changes source when global defaults change."""
    saved = _context(job).get("invite_candidate_provider")
    if saved in {"icloud", "gmail", "outlook"}:
        return saved
    actual = _business()._business_child_candidate_mail_provider(child)
    if actual in {"icloud", "gmail", "outlook"}:
        return actual
    return resolve_candidate_mail_provider(_settings(job).get("mail_provider", "auto"), "")


def _reserve_gmail_candidate(job: dict, seat_type: str, excluded: set) -> dict | None:
    from services.nv_automation_store import reserve_gmail_candidate
    return reserve_gmail_candidate(job.get("id"), job.get("worker_token"),
                                   seat_type=seat_type, excluded_ids=excluded)


def _select(job: dict, checkpoint: Callable | None) -> dict:
    try:
        _assert_new_invite_allowed(job)
    except HTTPException as exc:
        return _result("wait", delay=_invite_condition_wait_seconds(exc), error=_safe_error(exc))
    excluded = {
        _positive(item) for item in [
            *(job.get("occupied_child_ids") or []),
            *(_context(job).get("excluded_child_ids") or []),
        ]
    }
    child_id = _positive(job.get("child_id"))
    if child_id:
        # A checkpoint can commit before the process publishes its step result.
        # Recovery must retain that stable selection, not pick another child.
        with Session(_plans().engine) as session:
            child = session.get(GptPlanAccountModel, child_id)
            if child is None or _email(child.email) != _email(job.get("email")):
                return _review("已预留子号身份发生变化")
            candidates, _ = _business()._allocation_candidates_for_parent(
                session, int(job["source_account_id"]), child_id, existing_selection=True,
            )
            if len(candidates) != 1 or child_id in excluded:
                return _result("wait", delay=60, error="已预留子号暂不可用，保留原选择等待")
            updates = {"child_id": child_id, "email": _email(child.email)}
    else:
        provider, selected_seat = "", ""
        updates = None
        try:
            # The shared picker ranks prepared accounts first, then ordinary
            # fallback stock. The preparation producer's on/off switch is not
            # an inventory gate, and a saved choice must never be re-ranked.
            selected_seat, provider = _new_candidate_mail_policy(job)
            selected = _business()._auto_select_unseen_regular_business_child(
                int(job["source_account_id"]),
                excluded_ids=excluded,
                candidate_mail_provider=provider,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            if detail.get("code") == "no_eligible_regular_candidate" and provider in {"icloud", "gmail", "outlook"}:
                if provider == "gmail":
                    try:
                        updates = _reserve_gmail_candidate(job, selected_seat, excluded)
                    except Exception:
                        return _result("wait", delay=30, error="Gmail 子号预留未完成或任务策略已变化，将自动重新检查")
                label = {"icloud": "iCloud", "gmail": "Gmail", "outlook": "Outlook"}[provider]
                kind = "高级席位" if selected_seat == "prolite" else "普通席位" if selected_seat == "default" else "当前任务"
                message = f"{kind}当前使用 {label}：暂无已注册 GPT、已关联普通号池且可收件的可用子号（已排除占用、已使用及停用账号）"
                if provider == "gmail":
                    message = f"{kind}当前使用 Gmail：暂无可用的已注册账号或未注册子号；请补充已启用、收件授权验证通过的 Gmail 子号，系统将自动注册并设置密码/2FA"
                if updates is None:
                    return _result("wait", delay=300, error=message)
            else:
                return _result("wait", delay=300, error=_safe_error(exc))
        if updates is None:
            updates = {"child_id": int(selected.id), "email": _email(selected.email), "context": {
                "invite_candidate_provider": provider,
                "invite_candidate_seat_type": selected_seat or None,
            }}
            if selected_seat:
                updates["seat_type"] = selected_seat
    if not updates["email"]:
        return _review("候选子号邮箱无效")
    updates["context"] = {**updates.get("context", {}), "invite_progress": None, "invite_failure": None}
    try:
        _checkpoint(job, updates, checkpoint)
    except Exception:
        return _result("retry", delay=30, error="子号预留未成功，稍后重新选择")
    return _result("advance", next_step="invite", updates=updates)


def _invited_member(job: dict) -> dict | None:
    """Find only the selected child's newly created invitation, never rebind."""
    _assert_parent(job)
    started = _date(_context(job).get("invite_started_at"))
    if started is None:
        return None
    with Session(_plans().engine) as session:
        rows = session.exec(select(GptBusinessChildMembershipModel).where(
            GptBusinessChildMembershipModel.business_account_id == _positive(job.get("source_account_id")),
            GptBusinessChildMembershipModel.pro_account_id == _positive(job.get("child_id")),
            GptBusinessChildMembershipModel.ended_at.is_(None),
        )).all()
        rows = [row for row in rows if _email(row.email) == _email(job.get("email"))]
        if len(rows) != 1:
            return None
        row = rows[0]
        created = _date(row.created_at)
        if created is None or created < started or not (
            _identifier(row.remote_user_id) or _identifier(row.remote_invite_id)
        ):
            return None
        updates = {
            "membership_id": int(row.id),
            "remote_user_id": _identifier(row.remote_user_id),
            "seat_type": _plans()._safe_business_child_seat_type(row.seat_type),
        }
    _member({**job, **updates})
    return updates


def validate_legacy_unsent_invite_recovery(job: dict, session: Session) -> dict[str, Any]:
    """Validate one explicitly selected legacy review using local state only.

    Older workers retained only the exact source message saying that pre-login
    failed before the invite request.  This validator does not turn absence
    into remote success: it merely refuses recovery if any local mutation
    marker, membership row, identity change, or candidate-health change makes
    that historical no-send assertion inconsistent.
    """
    context = _context(job)
    started = _date(context.get("invite_started_at"))
    if context.get("invite_attempted") is not True or started is None:
        raise RuntimeError("旧邀请任务缺少可核验的邀请前登录检查点")

    parent_id = _positive(job.get("parent_account_id"))
    source_id = _positive(job.get("source_account_id"))
    child_id = _positive(job.get("child_id"))
    parent_email = _email(job.get("parent_email"))
    child_email = _email(job.get("email"))
    parent = session.get(GptPlanAccountModel, parent_id)
    source = session.get(GptBusinessAccountModel, source_id)
    child = session.get(GptPlanAccountModel, child_id)
    reason = _mother_identity_reason(parent, source) or _mother_action_reason(parent, source)
    if (
        reason
        or not parent_email
        or not child_email
        or parent_email == child_email
        or _email(getattr(parent, "email", "")) != parent_email
        or _email(getattr(source, "email", "")) != parent_email
        or child is None
        or _email(child.email) != child_email
    ):
        raise RuntimeError(reason or "旧邀请任务的母号或子号身份已变化")
    policy = session.get(GptBusinessAutomationPolicyModel, source_id)
    if bool(getattr(policy, "auto_rotation_enabled", False)):
        raise RuntimeError("母号启用了旧设备自动轮换，不能恢复该邀请任务")

    operation_id = _identifier(job.get("operation_id"))
    old_operation = session.get(GptBusinessInviteOperationModel, operation_id) if operation_id else None
    if old_operation is not None and bool(old_operation.remote_started):
        raise RuntimeError("旧邀请操作存在已发送远端请求的记录，不能按未发送恢复")

    # Any active/current ownership, or any membership created during/after the
    # frozen attempt, defeats the legacy no-send recovery.  Ended rows remain
    # relevant: a quickly accepted-and-removed invite must never be replayed.
    rows = session.exec(select(GptBusinessChildMembershipModel).where(or_(
        GptBusinessChildMembershipModel.pro_account_id == child_id,
        GptBusinessChildMembershipModel.business_account_id == source_id,
        func.lower(func.trim(GptBusinessChildMembershipModel.email)) == child_email,
    ))).all()
    for row in rows:
        same_child = (
            int(row.pro_account_id or 0) == child_id
            or _email(row.email) == child_email
        )
        if not same_child:
            continue
        created = _date(row.created_at)
        if (
            row.ended_at is None
            or _identifier(row.remote_user_id)
            or _identifier(row.remote_invite_id)
            or created is None
            or created >= started
        ):
            raise RuntimeError("旧邀请期间已经出现成员或远端邀请记录，不能重新发送")

    candidates, _ = _business()._allocation_candidates_for_parent(
        session,
        source_id,
        child_id,
        existing_selection=True,
    )
    if (
        len(candidates) != 1
        or int(candidates[0].id or 0) != child_id
        or _email(candidates[0].email) != child_email
    ):
        raise RuntimeError("旧任务选中的普通账号目前不可邀请")
    return {
        "code": "business_child_prelogin_failed",
        "failure_stage": "unknown",
        "failure_reason": "历史任务已确认在普通账号登录阶段失败，未发送 BUSINESS 邀请",
        "retryable": False,
        "remote_invite_sent": False,
    }


def _finish_dead_invite_candidate(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    """Resume local cleanup only after the no-invite/reselection fence commits.

    Keep the rejected identity in an audit checkpoint, not the active child
    binding. Otherwise ordinary deleted-child reconciliation would cancel the
    mother task before it can select a replacement. A crash at either checkpoint
    may repeat local cleanup, but can never replay the rejected invitation.
    """
    evidence = _context(job).get("invite_dead_candidate")
    if (not isinstance(evidence, dict)
            or evidence.get("confirmed_dead") is not True
            or evidence.get("remote_invite_sent") is not False
            or not _positive(evidence.get("child_id"))
            or not _email(evidence.get("email"))
            or _email(evidence.get("email")) == _email(job.get("parent_email"))
            or job.get("child_id") or job.get("email") or job.get("membership_id")
            or job.get("remote_user_id")
            or _context(job).get("invite_attempted") is not False):
        return _review("停用候选号的身份或未发送邀请证据不完整，未执行删除")
    if evidence.get("cleanup_complete") is True:
        return _result("advance", next_step="select", error="停用候选号已清理，继续选择其他账号")
    try:
        cleanup = _business()._purge_confirmed_dead_uninvited_business_candidate(
            int(evidence["child_id"]), email=_email(evidence["email"]),
            confirmed_dead=True, remote_invite_sent=False,
        )
    except Exception:
        return _result("retry", delay=30, error="停用候选号本地清理暂未完成，稍后重试；未发送邀请")
    if not isinstance(cleanup, dict):
        return _review("停用候选号清理未返回可确认结果，未继续邀请")
    if cleanup.get("reason") == "cleanup_failed":
        return _result("retry", delay=30, error="停用候选号本地清理暂未完成，稍后重试；未发送邀请")
    if cleanup.get("deleted") is True or cleanup.get("reason") == "account_missing":
        updates = {"context": {"invite_dead_candidate": {
            **evidence, "cleanup_complete": True,
        }}}
        _checkpoint(job, updates, checkpoint)
        _log(emit, f"{_email(evidence['email'])}：远端已明确停用，本地候选号已删除；继续选择其他账号")
        return _result("advance", next_step="select", updates=updates,
                       error="停用候选号已删除，重新选择准备池或普通池账号")
    # A real membership, sale, device or different owner's lease is never
    # discarded just because an earlier login reported deactivation.
    return _review("子号已明确停用，但仍有关联记录或其他操作，未删除；请先完成关联清理")


def _prepare_child_before_invite(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    """Prepare the selected account before acquiring the invitation lease.

    Every retry first checks saved security/session state; already confirmed
    password and 2FA are reused. No invitation fence is armed by preparation.
    """
    from services.gpt_plan_preparation_capabilities import prepare_account
    from services.nv_invite_preparation import normalize_preparation, STAGES
    from services import nv_gmail_production as gmail_production
    gmail_owned = bool(_context(job).get("gmail_production_alias_id"))
    child_id, email = _positive(job.get("child_id")), _email(job.get("email"))
    if not child_id or not email or job.get("membership_id") or job.get("remote_user_id"):
        return {"ok": False, "error": "选中账号的身份或未邀请状态已变化，等待重新检查"}
    started = _iso(_now())
    state = {"child_id": child_id, "email": email, "stage": "queued", "status": "running",
             "started_at": started, "updated_at": started, "finished_at": None,
             "security_confirmed": False, "registered_verified": False, "error": ""}

    def save_state():
        clean = normalize_preparation(state, job)
        if clean is None:
            raise RuntimeError("邀请前准备进度无效，未继续执行")
        _checkpoint(job, {"context": {
            "invite_preparation": clean,
            "invite_preparation_completed": clean["status"] == "completed",
            "invite_preparation_started_at": clean["started_at"],
            "invite_preparation_finished_at": clean["finished_at"],
        }}, checkpoint)

    # Persist no-send evidence before any authentication/security operation.
    _checkpoint(job, {"context": {"invite_attempted": False, "invite_started_at": "",
                                  "invite_progress": None, "invite_failure": None}}, checkpoint)
    save_state()

    def prep_checkpoint(stage: str, details: dict):
        # The source also supplies a private lease token. Never copy it to the
        # public NV context; the process-owned lease can recover after death.
        state.update(stage=stage if stage in STAGES else state["stage"], updated_at=_iso(_now()))
        for key in ("security_confirmed", "registered_verified"):
            if details.get(key) is True:
                state[key] = True
        progress = normalize_security_progress(details.get("security_progress"))
        if progress:
            state["security_progress"] = progress
        save_state()
        if gmail_owned:
            gmail_production.mark_preparation(job, state["stage"], {
                key: state[key] for key in ("registered_verified", "security_confirmed")})

    try:
        if gmail_owned:
            gmail_production.mark_preparation(job, "queued")
            _log(emit, "已预留 Gmail 子号，开始自动注册或登录 GPT，并设置密码/2FA")
        settings = {"browser_mode": _settings(job).get("browser_mode", "headless"), "_expected_email": email}
        result = prepare_account(child_id, settings,
                                 lambda message: _log(emit, f"邀请前准备：{message}"), prep_checkpoint)
    except Exception as exc:
        result = {"ok": False, "error": _safe_error(exc)}
    result = result if isinstance(result, dict) else {"ok": False, "error": "准备未返回明确结果"}
    if gmail_owned:
        try:
            alias = gmail_production.complete_preparation(job, result)
            if not alias:
                raise RuntimeError("Gmail 子号注册结果尚未关联，等待自动重新检查")
        except Exception as exc:
            result = {**result, "ok": False, "error": _safe_error(exc)}
    complete = (result.get("ok") is True and result.get("security_confirmed") is True
                and result.get("registered_verified") is True)
    reason = _plans()._sanitize_member_task_text(str(result.get("error") or "登录或密码/2FA尚未完成"))[:400]
    # The shared preparation pool has manual-retry wording; this NV consumer
    # schedules state-aware retries itself and must describe its own policy.
    for old in ("需要人工验证", "等待人工核验", "等待核对", "未自动重试"):
        reason = reason.replace(old, "等待自动重新检查")
    finished = _iso(_now())
    state.update(status="completed" if complete else "failed", updated_at=finished, finished_at=finished,
                 stage="ready" if complete else result.get("stage") if result.get("stage") in STAGES else state["stage"],
                 security_confirmed=result.get("security_confirmed") is True,
                 registered_verified=result.get("registered_verified") is True,
                 error="" if complete else reason,
                 confirmed_dead=result.get("dead") is True and result.get("error_code") == "account_deactivated")
    progress = normalize_security_progress(result.get("security_progress"))
    if progress:
        state["security_progress"] = progress
    save_state()
    if complete:
        _log(emit, "登录验证与密码/2FA准备已完成，邀请阶段复用已确认会话")
        return {"ok": True}
    if gmail_owned and result.get("error_code") == "gmail_source_exhausted" and result.get("source_error_code") == "user_already_exists":
        return {"ok": False, "gmail_reselect": True, "error": reason}
    return {"ok": False, "dead": result.get("dead") is True and result.get("error_code") == "account_deactivated",
            "error": f"邀请前准备失败：{reason}；未发送邀请，将自动检查已有结果后重试"}


def _reject_dead_invite_candidate(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    """Persist exact no-send evidence before removing the selected candidate."""
    child_id, rejected_email = _positive(job.get("child_id")), _email(job.get("email"))
    updates = {
        "child_id": 0, "email": "", "membership_id": 0, "remote_user_id": "",
        "context": {
            "invite_attempted": False, "invite_started_at": "",
            "invite_failure": None, "invite_progress": None,
            "invite_preparation": None, "invite_preparation_completed": False,
            "invite_preparation_started_at": None, "invite_preparation_finished_at": None,
            "excluded_child_ids": sorted({child_id, *(
                _positive(value) for value in (_context(job).get("excluded_child_ids") or []) if _positive(value)
            )}),
            "invite_dead_candidate": {
                "child_id": child_id, "email": rejected_email,
                "confirmed_dead": True, "remote_invite_sent": False,
                "detected_at": _iso(_now()), "cleanup_complete": False,
            },
        },
    }
    _checkpoint(job, updates, checkpoint)
    _log(emit, f"{rejected_email}：邀请前已明确停用，未发送邀请，正在清理本地候选号")
    result = _finish_dead_invite_candidate(job, emit, checkpoint)
    result["updates"] = {
        **updates, **result.get("updates", {}),
        "context": {**updates["context"], **result.get("updates", {}).get("context", {})},
    }
    return result


def _reject_gmail_invite_candidate(job, emit, checkpoint):
    from services.nv_automation_store import release_rejected_gmail_candidate
    try:
        updates = release_rejected_gmail_candidate(job.get("id"), job.get("worker_token"))
    except Exception:
        return _result("wait", delay=30, error="Gmail 子号已停止新号生产，等待当前操作结束后自动改选")
    _checkpoint(job, updates, checkpoint)
    _log(emit, "当前 Gmail 子号已移出生产任务，保留失败记录，自动改选其他可用母号的子号")
    return _result("advance", next_step="select", updates=updates)


def _invite(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    from services.nv_gmail_production import candidate_rejection
    if candidate_rejection(job) and not _context(job).get("invite_attempted"):
        return _reject_gmail_invite_candidate(job, emit, checkpoint)
    if not job.get("child_id") and _context(job).get("invite_dead_candidate"):
        return _finish_dead_invite_candidate(job, emit, checkpoint)
    if _context(job).get("invite_attempted"):
        updates = _invited_member(job)
        if updates:
            return _result("advance", next_step="security", updates=updates)
        if job.get("membership_id") or job.get("remote_user_id"):
            return _review("此前邀请结果尚未确认")
        # No local membership was found after the prior attempt. Clear the
        # stale mutation fence and retry the invite stage so an old review row
        # cannot remain stuck forever; the next attempt creates a fresh
        # operation checkpoint before sending anything remotely.
        return _result("retry", delay=60,
                       error="此前邀请结果尚未确认，将自动重新读取并从当前阶段重试",
                       updates={"context": {"invite_attempted": False,
                                              "invite_started_at": "",
                                              "invite_progress": None,
                                              "task_retry": {"strategy": "safe_resume",
                                                              "reason_code": "no_remote_attempt"}}})
    from services.nv_invite_preparation import normalize_preparation, unsent_preparation
    saved_preparation = normalize_preparation(_context(job).get("invite_preparation"), job)
    if (saved_preparation and saved_preparation.get("confirmed_dead")
            and unsent_preparation(job, _context(job))):
        return _reject_dead_invite_candidate(job, emit, checkpoint)
    try:
        _assert_new_invite_allowed(job)
    except HTTPException as exc:
        return _result("wait", delay=_invite_condition_wait_seconds(exc), error=_safe_error(exc))
    child_id = _positive(job.get("child_id"))
    _plans()._release_stopped_plan_preparation_operation(child_id)
    with Session(_plans().engine) as session:
        child = session.get(GptPlanAccountModel, child_id)
        if child is None or _email(child.email) != _email(job.get("email")):
            return _review("选中的子号身份已变化")
        candidates, _ = _business()._allocation_candidates_for_parent(
            session, int(job["source_account_id"]), child_id, existing_selection=True,
        )
        if len(candidates) != 1:
            return _result("retry", delay=60, error="选中的普通子号目前不可邀请")
        bound_provider = _bound_candidate_mail_provider(job, child)
    preparation = _prepare_child_before_invite(job, emit, checkpoint)
    if preparation.get("gmail_reselect") is True:
        return _reject_gmail_invite_candidate(job, emit, checkpoint)
    if preparation.get("dead") is True:
        return _reject_dead_invite_candidate(job, emit, checkpoint)
    if preparation.get("ok") is not True:
        # Preparation re-reads persisted security state before each attempt.
        # A condition wait keeps recovery automatic without consuming the
        # remote-invitation retry budget or spinning in the current worker.
        return _result("wait", delay=300, error=preparation.get("error") or "邀请前准备未完成",
                       updates={"context": {"task_retry": {
                           "strategy": "safe_resume", "reason_code": "no_remote_attempt"}}})
    operation = _operation(job)
    _checkpoint(job, {"context": {
        "invite_attempted": True, "invite_started_at": _iso(_now()),
        "invite_failure": None, "invite_progress": None,
        # Each retry is a new invitation operation. Clear the prior display
        # checkpoints so verification/send times cannot be attributed to the
        # current attempt.
        "invite_verification_started_at": None,
        "invite_verification_finished_at": None,
        "invite_send_started_at": None,
        "invite_send_finished_at": None,
    }}, checkpoint)
    _log(emit, "已保存邀请检查点，调用母号能力核验子号会话并执行单次邀请")
    try:
        body = _plans().GptPlanBusinessChildInviteRequest(
            operation_id=operation, pro_account_id=child_id,
            candidate_mail_provider=bound_provider,
        )
        expected_seat = _context(job).get("invite_candidate_seat_type")
        if expected_seat in {"default", "prolite"}:
            body._expected_seat_type = expected_seat
        body._expected_target = {key: job.get(key) for key in (
            "parent_account_id", "source_account_id", "parent_email", "child_id", "email",
        )}
        # The source layer projects browser output to fixed, credential-free
        # stage markers before invoking this callback.  Keep a compatibility
        # guard while older API workers are still running during deployment.
        if hasattr(body, "_log_fn"):
            body._log_fn = lambda message: _log(emit, message)
        def report_invite_progress(event):
            previous = normalize_invite_progress(_context(job).get("invite_progress"), job, require_operation=True)
            verified = bool(previous and previous["verification_completed"])
            if event.get("phase") == "verify_child":
                verified = event.get("state") == "completed"
            # The verification and remote POST are one canonical worker step,
            # so they do not have separate NvAutomationStep ledger rows. Keep
            # credential-free timestamps in the job context as each callback
            # arrives; this lets the UI explain exactly what was executed
            # without inventing times for historical records.
            now_iso = _iso(_now())
            timing = {}
            current_context = _context(job)
            if event.get("phase") == "verify_child":
                if event.get("state") == "running":
                    timing["invite_verification_started_at"] = (
                        current_context.get("invite_verification_started_at") or now_iso
                    )
                elif event.get("state") in {"completed", "failed"}:
                    timing["invite_verification_started_at"] = (
                        current_context.get("invite_verification_started_at") or now_iso
                    )
                    timing["invite_verification_finished_at"] = now_iso
            elif event.get("phase") == "send_invite":
                timing["invite_verification_started_at"] = current_context.get("invite_verification_started_at", "")
                timing["invite_verification_finished_at"] = current_context.get("invite_verification_finished_at", "")
                if event.get("state") == "running":
                    timing["invite_send_started_at"] = (
                        current_context.get("invite_send_started_at") or now_iso
                    )
                elif event.get("state") in {"completed", "failed"}:
                    timing["invite_send_started_at"] = (
                        current_context.get("invite_send_started_at") or now_iso
                    )
                    timing["invite_send_finished_at"] = now_iso
            progress = normalize_invite_progress({**event, "operation_id": operation,
                                                  "updated_at": now_iso, "verification_completed": verified},
                                                 job, require_operation=True)
            if progress is None:
                raise RuntimeError("邀请进度与当前子号不一致，未继续执行")
            _checkpoint(job, {"context": {"invite_progress": progress, **timing}}, checkpoint)
            phase = "验证子号状态" if progress["phase"] == "verify_child" else "发送邀请"
            state = {"running": "开始", "completed": "完成", "failed": "失败"}[progress["state"]]
            _log(emit, f"{phase}：{state}" + ("；未发送 BUSINESS 邀请" if progress["phase"] == "verify_child"
                                             and progress["state"] == "failed" else ""))
        if hasattr(body, "_invite_progress_fn"):
            body._invite_progress_fn = report_invite_progress
        result = _plans().member_business_invite(
            int(job["parent_account_id"]), body,
        )
    except HTTPException as exc:
        code = exc.detail.get("code") if isinstance(exc.detail, dict) else ""
        if code == "business_child_prelogin_dead":
            detail = exc.detail
            if (detail.get("confirmed_dead") is not True
                    or detail.get("remote_invite_sent") is not False
                    or _positive(detail.get("pro_account_id")) != child_id
                    or not _email(detail.get("email"))
                    or _email(detail.get("email")) != _email(job.get("email"))
                    or job.get("membership_id") or job.get("remote_user_id")):
                return _review("子号停用或未发送邀请的证据不完整，未删除或更换账号")
            return _reject_dead_invite_candidate(job, emit, checkpoint)
        if code == "business_invite_seat_changed":
            cleared = {"context": {"invite_attempted": False, "invite_started_at": "",
                "task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}}}
            _checkpoint(job, cleared, checkpoint)
            return _result("wait", delay=300, error="实际可邀请席位已变化，保留原子号及邮箱类型，等待对应席位恢复后自动重试", updates=cleared)
        if code in {"invite_cooldown_active", "invite_quota_exhausted"}:
            return _result("wait", delay=_invite_condition_wait_seconds(exc), error=_safe_error(exc), updates={"context": {
                "invite_attempted": False, "invite_started_at": "",
            }})
        failure = _prelogin_failure(exc.detail)
        if failure is not None:
            # The source contract explicitly proves that the BUSINESS invite
            # mutation was never sent.  Commit that fact before returning a
            # retry result: a worker crash between here and finish_step must not
            # strand a false mutation fence or cause an unsafe reconciliation.
            cleared = {"context": {
                "invite_attempted": False,
                "invite_started_at": "",
                "invite_failure": failure,
                "task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"},
            }}
            _checkpoint(job, cleared, checkpoint)
            reason = str(failure.get("failure_reason") or "邀请前登录失败")
            return _result(
                "retry",
                delay=60,
                error=f"子号登录验证失败，未发送 BUSINESS 邀请；下次从当前阶段重试：{reason}",
                updates=cleared,
            )
        return _review(_safe_error(exc))
    except Exception as exc:
        return _review(_safe_error(exc))
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("persistence_confirmed") is not True or any(
        result.get(key) for key in ("partial", "action_required", "binding_changed", "identity_changed")
    ):
        return _review("邀请未同时确认远端成功及本地成员归属")
    updates = _invited_member(job)
    if updates is None:
        return _review("邀请响应成功，但选定子号的新成员记录尚未确认")
    return _result("advance", next_step="security", updates={
        **updates,
        "context": {"invite_failure": None},
    })


def _oauth_advance_result(job: dict, member: dict) -> dict:
    from services.nv_oauth_completion import completion_proof
    quota_recovery = _context(job).get("quota_rt_recovery") is True
    result = _result("advance", next_step="wait_warranty" if quota_recovery else "publish", updates={
        "remote_user_id": member["remote_user_id"], "seat_type": member["seat_type"],
        **({"context": {"quota_rt_recovery": False,
                         "quota_rt_recovery_started_at": None,
                         "oauth_failure": None,
                         "oauth_failure_detail": ""}} if quota_recovery else {}),
    })
    # Only consumed by finish_step's transaction; never checkpoint this proof.
    result["_oauth_completion"] = completion_proof(job, member)
    return result


def _oauth_complete(job: dict, member: dict) -> bool:
    context = _context(job)
    floor = _date(context.get("oauth_started_at") or context.get("invite_started_at") or (
        context.get("membership_invited_at") if context.get("existing_member") is True else None
    ))
    acquired = _date(member.get("oauth_acquired_at"))
    return bool(
        member.get("oauth_complete") and member.get("remote_user_id")
        and floor is not None and acquired is not None and floor <= acquired <= _now()
        and (not context.get("oauth_membership_invited_at")
             or _date(context["oauth_membership_invited_at"]) == _date(member.get("membership_invited_at")))
        and (context.get("existing_member") is not True
             or context.get("membership_invited_at") == member.get("membership_invited_at"))
    )


def _oauth_count(job: dict, key: str) -> int | None:
    value = _context(job).get(key)
    return value if type(value) is int and value >= 0 else None


def _oauth_max_executions(job: dict) -> int:
    value = _settings(job).get("max_attempts", 3)
    return value if type(value) is int and 1 <= value <= 5 else 3


def _oauth_retry_problem(job: dict, member: dict, *, allow_extra_execution=False,
                         allow_manual_provider_error=False, allow_unknown_failure=True) -> tuple[str, str] | None:
    """A prior failure is evidence, not permission to overwrite credentials."""
    context = _context(job)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    started = _date(context.get("oauth_started_at"))
    invited = _date(context.get("oauth_membership_invited_at"))
    if (started is None or started != _date(context.get("oauth_failure_started_at"))
            or invited is None or invited != _date(member.get("membership_invited_at"))
            or not invited <= started <= _now()
            or member.get("oauth_complete") is not False):
        return "unconfirmed_evidence", "账号归属已变化或已有完整凭证，未重复获取 RT"
    # Partial old bundles are retained until a complete new bundle commits.
    # before_start compares the credential version under the account lease.
    return retry_problem(context, max_executions=_oauth_max_executions(job),
                         phone_allowed=_settings(job).get("oauth_phone_retry_enabled") is True,
                         allow_extra_execution=allow_extra_execution,
                         allow_manual_provider_error=allow_manual_provider_error,
                         allow_unknown_failure=allow_unknown_failure)


def _oauth_failed_result(job: dict, member: dict, checkpoint: Callable | None) -> dict:
    context = _context(job)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    reason = context.get("oauth_failure_detail") or (failure or {}).get("reason") or "OAuth 失败原因未记录"
    if failure and failure["code"] in {"exchange_failed", "partial_credentials"}:
        reason = "OAuth 授权兑换未完成" if failure["code"] == "exchange_failed" else "OAuth 返回的凭证不完整"
    elif failure and failure["code"] == "oauth_unknown":
        # Unknown is a closed terminal result for the OAuth stage.  Preserve
        # the raw detail in the log, but keep the operator-facing outcome
        # actionable: the bounded retry starts this stage again automatically.
        reason = "OAuth 阶段结果未确认，已记录并从 OAuth 阶段自动重试"
    if failure and failure["code"] in HARD_FAILURE_CODES:
        updates = {"context": {"oauth_retry_ready": False, "oauth_recovery_requested": False,
            "oauth_retry_blocked_reason": "permanent_failure",
            "task_retry": {"strategy": "manual", "reason_code": "configuration_required"}}}
        _checkpoint(job, updates, checkpoint)
        return _result("failed", error=reason, updates=updates)
    unknown_extra = bool(
        failure and failure.get("code") == "oauth_unknown"
        and context.get("oauth_unknown_auto_retry_count", 0) == 0
    )
    problem = _oauth_retry_problem(job, member, allow_extra_execution=unknown_extra)
    if problem and problem[0] == "permanent_failure":
        updates = {"context": {"oauth_retry_ready": False,
            "oauth_retry_blocked_reason": "permanent_failure"}}
        _checkpoint(job, updates, checkpoint)
        return _result("failed", error=problem[1], updates=updates)
    if problem and problem[0] == "unconfirmed_evidence":
        updates = {"context": {"oauth_attempted": True, "oauth_retry_ready": False, "oauth_retry_blocked_reason": problem[0],
                               "task_retry": {"strategy": "manual", "reason_code": "insufficient_evidence"}}}
        _checkpoint(job, updates, checkpoint)
        return _result("review", error=f"{problem[1]}；获取 RT 未完成：{reason}", updates=updates)
    # The NV policy permits only known terminal failures with no complete local
    # credential bundle. Stable partial records remain untouched; permissions,
    # record version and ownership are rechecked under the account lease.
    updates = {"context": {
        "oauth_attempted": False, "oauth_retry_ready": True,
        "oauth_retry_blocked_reason": problem[0] if problem else None,
        "task_retry": {"strategy": "manual", "reason_code": "configuration_required"}
            if problem else {"strategy": "safe_resume", "reason_code": "network_temporary"},
    }}
    _checkpoint(job, updates, checkpoint)
    if problem:
        return _result("failed", error=f"{problem[1]}；获取 RT 失败：{reason}", updates=updates)
    return _result("retry", delay=60,
        error=f"已确认未取得本次凭证，将在次数与费用授权范围内自动重试；获取 RT 失败：{reason}", updates=updates)


def _restore_legacy_oauth_diagnostic(job: dict, emit: Callable, checkpoint: Callable | None) -> None:
    """Narrow historical repair, only while an explicit worker owns this job."""
    context = _context(job)
    if context.get("oauth_failure") is not None or not context.get("oauth_attempted"):
        return
    from services.nv_oauth_legacy import oauth_legacy_failure_evidence
    evidence = oauth_legacy_failure_evidence(job)
    if not evidence:
        return
    failure = normalize_oauth_failure(evidence.get("oauth_failure"))
    if failure is None:
        return
    counters = {}
    for field, key in (("oauth_execution_attempts", "execution_attempts"),
                       ("oauth_reconciliation_attempts", "reconciliation_attempts")):
        count = evidence.get(key)
        if _oauth_count(job, field) is None and type(count) is int and count >= 0:
            counters[field] = count
    _checkpoint(job, {"context": {"oauth_failure": failure,
        "oauth_failure_detail": failure["reason"], "oauth_failure_started_at": context.get("oauth_started_at"),
        **counters}}, checkpoint)
    _log(emit, "已核实旧日志：上次 OAuth 停在手机号短信验证超时；恢复真实失败原因与执行计数，尚未重新授权")


def _oauth_recovery_problem(job: dict, member: dict) -> str | None:
    """A separate one-time recovery, never manufactured terminal evidence."""
    context = _context(job)
    if context.get("oauth_recovery_requested") is not True:
        return "本次未进入串行恢复批次，未重新发起 OAuth"
    manual_recovery = _manual_oauth_recovery_granted(context)
    if recoverable_failure(context.get("oauth_failure")) or manual_recovery:
        # A valid manual grant uses the same fresh cycle/complete-bundle gate.
        # Stable old partial credentials or a login session remain untouched
        # until a complete replacement commits; before_start still detects
        # changes under the account lease. The legacy no-credential-only path
        # below must not reject this explicitly authorized recovery.
        problem = _oauth_retry_problem(job, member, allow_extra_execution=manual_recovery,
                                       allow_manual_provider_error=manual_recovery,
                                       allow_unknown_failure=True)
        return problem[1] if problem else None
    if context.get("oauth_recovery_attempts", 0) != 0:
        return "旧 RT 任务的一次恢复已使用，请根据本次明确失败原因处理"
    started = _date(context.get("oauth_started_at"))
    invited = _date(context.get("oauth_membership_invited_at"))
    if (started is None or invited is None or not invited <= started <= _now()
            or invited != _date(member.get("membership_invited_at"))):
        return "旧 RT 任务的邀请周期或成员归属已变化，未重新获取"
    if member.get("oauth_has_any_credentials") is not False or member.get("oauth_acquired_at"):
        return "子号已有凭证或获取时间记录，需核对完整性；未覆盖已有凭证"
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if not manual_recovery and failure and (failure["code"] not in {
        "oauth_unknown", "browser_start_failed", "browser_timeout", "control_timeout", "sms_timeout",
    } or failure["callback_received"] or failure["exchange_started"]):
        return "上次 OAuth 有明确不可自动重试的结果，未重新获取"
    count = _oauth_count(job, "oauth_execution_attempts")
    if count is None or count < 1:
        return "旧 RT 任务的真实执行次数无法从完整日志确认，未重新获取"
    if count >= _oauth_max_executions(job) and not manual_recovery:
        return "实际 OAuth 已达本任务上限，已停止重新授权"
    return None


def _recover_unfinished_oauth(job: dict, emit: Callable, checkpoint: Callable | None) -> dict | None:
    context = _context(job)
    if context.get("oauth_recovery_requested") is not True:
        return None
    if _oauth_count(job, "oauth_execution_attempts") is None:
        from services.nv_oauth_recovery import historical_oauth_execution_count
        count = historical_oauth_execution_count(job)
        if type(count) is int and count >= 1:
            _checkpoint(job, {"context": {"oauth_execution_attempts": count}}, checkpoint)
    problem = _oauth_recovery_problem(job, _member(job))
    if problem:
        return _review(problem)
    _log(emit, "已取得本次人工短信验证恢复许可；准备一次受限恢复，将先取得子号独占操作权并再次核对归属与凭证"
         if _manual_oauth_recovery_granted(_context(job)) else
         "旧 RT 未保存完整凭证；准备一次受限恢复，将先取得子号独占操作权并再次核对归属与凭证")
    return _security_or_oauth(job, emit, checkpoint, recover_legacy=True)


def _saved_oauth_evidence_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _reconcile_saved_oauth_readonly(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    """A saved-RT marker permits only this read, regardless of old retry grants."""
    context = _context(job)
    started = _saved_oauth_evidence_time(context.get("oauth_started_at"))
    invited = _saved_oauth_evidence_time(context.get("oauth_membership_invited_at"))
    saved = _saved_oauth_evidence_time(context.get("oauth_saved_reconcile_at"))
    if (started is None or invited is None or saved is None
            or not invited <= started <= saved <= _now()
            or (context.get("membership_invited_at")
                and _saved_oauth_evidence_time(context["membership_invited_at"]) != invited)):
        return _review("已保存 RT 的只读核对缺少有效授权时间、保存时间或原邀请周期证据")

    def matches(member: dict) -> bool:
        return bool(
            member.get("oauth_complete") is True
            and _saved_oauth_evidence_time(member.get("oauth_acquired_at")) == saved
            and _saved_oauth_evidence_time(member.get("membership_invited_at")) == invited
            and member.get("oauth_credential_version")
        )

    try:
        before = _member(job)
        if not matches(before):
            return _review("已保存 RT 的凭证、保存时间或原邀请周期已变化，未重新获取 RT")
        reconciliations = _oauth_count(job, "oauth_reconciliation_attempts")
        if reconciliations is not None:
            _checkpoint(job, {"context": {"oauth_reconciliation_attempts": reconciliations + 1}}, checkpoint)
        target = {
            **_action_target(job), "parent_email": job.get("parent_email"),
            "membership_invited_at": context["oauth_membership_invited_at"],
            "remote_user_id": before.get("remote_user_id") or job.get("remote_user_id"),
            "remote_invite_id": context.get("existing_invite_id"),
        }
        _log(emit, "正在只读核对已保存 RT 与当前工作区成员状态")
        result = _plans()._reconcile_persisted_business_child_oauth(
            target, acquired_after=context["oauth_started_at"],
        )
        # Recheck even a transient read failure: it must not conceal changed
        # credentials, a new invitation cycle, or a changed known member ID.
        after = _member(job)
        if (not matches(after)
                or after.get("oauth_credential_version") != before.get("oauth_credential_version")
                or any(after.get(key) != before.get(key) for key in ("membership_id", "child_id", "email"))
                or (before.get("remote_user_id") and after.get("remote_user_id") != before["remote_user_id"])):
            return _review("只读核对期间已保存 RT 或成员身份发生变化，未重新获取 RT")
        if isinstance(result, dict) and result.get("eligible") is True:
            if result.get("verified") is True and result.get("reason_code") == "verified":
                if _oauth_complete(job, after) and not after.get("remote_invite_id"):
                    return _oauth_advance_result(job, after)
                return _review("已保存 RT 尚未确认当前工作区中的正式成员身份")
            if result.get("retryable") is True and result.get("reason_code") in {
                "workspace_refresh_busy", "workspace_read_failed", "workspace_read_unconfirmed",
            }:
                updates = {"context": {
                    "oauth_reconcile_only": True, "oauth_saved_reconcile_at": context["oauth_saved_reconcile_at"],
                    "oauth_attempted": True, "oauth_retry_ready": False, "oauth_recovery_requested": False,
                    "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"},
                }}
                _checkpoint(job, updates, checkpoint)
                # Read waits do not consume the exhausted OAuth retry budget.
                return _result("wait", delay=60, error="RT 已保存，工作区读取暂未完成；稍后仅重试成员核对", updates=updates)
        return _review("已保存 RT 或当前工作区成员状态未通过只读核对，未重新获取 RT")
    except Exception as exc:
        return _review("已保存 RT 的只读核对未能确认：" + _safe_error(exc))


def _reconcile_saved_oauth(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    """Reconcile first; an authorized batch may consume one legacy recovery."""
    _restore_legacy_oauth_diagnostic(job, emit, checkpoint)
    context = _context(job)
    started = context.get("oauth_started_at")
    invited = context.get("oauth_membership_invited_at") or context.get("membership_invited_at")
    if _date(started) is None or _date(invited) is None:
        return _review("RT 任务缺少本次授权与邀请周期证据；请人工核对，未重新发起 OAuth")
    reconciliations = _oauth_count(job, "oauth_reconciliation_attempts")
    if reconciliations is not None:
        _checkpoint(job, {"context": {"oauth_reconciliation_attempts": reconciliations + 1}}, checkpoint)
    target = {
        **_action_target(job), "parent_email": job.get("parent_email"),
        "membership_invited_at": invited,
        "remote_user_id": job.get("remote_user_id"),
        "remote_invite_id": context.get("existing_invite_id"),
    }
    _log(emit, "正在核对本次 RT 落库与工作区成员状态，不重新授权或覆盖 RT")
    result = _plans()._reconcile_persisted_business_child_oauth(target, acquired_after=started)
    if isinstance(result, dict) and result.get("reason_code") == "local_evidence_unconfirmed":
        return _result("retry", delay=60, error="本地 RT 状态暂时读取失败，稍后自动重读；本轮未重新授权",
            updates={"context": {"oauth_attempted": True, "oauth_retry_ready": False,
                "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"}}})
    if isinstance(result, dict) and result.get("eligible") is True:
        if result.get("verified") is True and result.get("reason_code") == "verified":
            member = _member(job)
            if _oauth_complete(job, member) and _date(member.get("membership_invited_at")) == _date(invited):
                return _oauth_advance_result(job, member)
            return _review("核对后本次成员的 RT 或邀请周期发生变化，请人工核对")
        if result.get("retryable") is True and result.get("reason_code") in {
            "workspace_refresh_busy", "workspace_read_failed", "workspace_read_unconfirmed",
        }:
            updates = {"context": {
                # This fence stays set even across manual retry/restarts. The
                # next attempt may read membership, but may never reauthorize.
                "oauth_attempted": True,
                "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"},
            }}
            _checkpoint(job, updates, checkpoint)
            return _result("retry", delay=60, error="RT 已保存，成员状态读取暂时失败；稍后仅重试成员核对", updates=updates)
    if isinstance(result, dict) and result.get("reason_code") == "oauth_evidence_missing":
        failure = normalize_oauth_failure(_context(job).get("oauth_failure"))
        if (_context(job).get("oauth_recovery_requested") is True
                and (_manual_oauth_recovery_granted(_context(job)) or not failure
                     or (not failure["retryable"] and failure["code"] != "phone_verification_not_authorized"))):
            recovered = _recover_unfinished_oauth(job, emit, checkpoint)
            if recovered is not None:
                return recovered
        if failure is not None:
            return _oauth_failed_result(job, _member(job), checkpoint)
        # A terminal worker without a persisted failure classification is an
        # explicit unknown OAuth attempt. Preserve the attempt fence, classify
        # it as a bounded transient failure, and let the normal retry policy
        # restart OAuth automatically from this stage.
        unknown = OAuthAttemptFailure("oauth_unknown").oauth_failure
        detail = _context(job).get("oauth_failure_detail") or "OAuth 结果未确认"
        _checkpoint(job, {"context": {
            "oauth_failure": unknown,
            "oauth_failure_detail": detail,
            "oauth_failure_started_at": _context(job).get("oauth_started_at"),
            "oauth_unknown_auto_retry": True,
        }}, checkpoint)
        return _oauth_failed_result(job, _member(job), checkpoint)
    original = _context(job).get("oauth_failure_detail")
    return _review((f"获取 RT 失败：{original}；" if original else "") + "本次 RT 或成员状态未通过核对；" + (
        _plans()._sanitize_member_task_text(result.get("error") or "需要人工处理，未重新发起 OAuth")
        if isinstance(result, dict) else "需要人工处理，未重新发起 OAuth"
    ))


def _security_check_evidence(job: dict, result: str) -> dict:
    # Display evidence only: never a substitute for the canonical completion
    # check. Bind it to this child/membership so reselection cannot reuse it.
    return {"result": result, "child_id": job["child_id"],
            "membership_id": job["membership_id"], "email": _email(job["email"]),
            "checked_at": _iso(_now())}


def _security_permission_review(job, reason=None):
    from services.nv_security_recovery import SECURITY_RETRY_SPENT_REASON
    progress = normalize_security_progress(_context(job).get("security_progress"))
    actual = progress.get("reason") if progress else ""
    reason = reason or SECURITY_RETRY_SPENT_REASON
    return _result("review", error=reason + ("；上次实际失败：" + actual if actual else ""), updates={
        "context": {"task_retry": {"strategy": "manual", "reason_code": "insufficient_evidence"}},
    })


def _security_or_oauth(job: dict, emit: Callable, checkpoint: Callable | None, *, reconcile: bool = False,
                       recover_legacy: bool = False) -> dict:
    if (job.get("step") == "oauth" and _context(job).get("oauth_reconcile_only") is True
            and _context(job).get("quota_rt_recovery") is not True):
        return _reconcile_saved_oauth_readonly(job, emit, checkpoint)
    plans = _plans()
    step = str(job["step"])
    member = _member(job)
    target = _action_target(job)
    action = "setup_security" if step == "security" else "oauth"
    quota_recovery = step == "oauth" and _context(job).get("quota_rt_recovery") is True
    # A quota read has already proved that the saved RT is revoked. Force a
    # fresh OAuth acquisition even though the old bundle is otherwise complete.
    complete = (plans._business_child_action_complete(target, action)
                if step == "security" else (_oauth_complete(job, member) and not quota_recovery))
    if complete:
        if step == "security":
            _log(emit, "密码与 Authenticator 2FA 已完成且凭据可读，跳过重复设置")
        return _result("advance", next_step="oauth" if step == "security" else "publish", updates={
            "remote_user_id": member["remote_user_id"], "seat_type": member["seat_type"],
            **({"context": {"security_check": _security_check_evidence(job,
                "verified" if _context(job).get("security_started_at") or _context(job).get("security_attempted")
                else "reused")}} if step == "security" else {}),
        })
    retrying_oauth = (step == "oauth" and not quota_recovery and not recover_legacy
                      and _context(job).get("oauth_retry_ready") is True)
    if retrying_oauth and not _context(job).get("oauth_attempted"):
        # Explicit manual recovery grants one new attempt, independently of
        # the exhausted automatic budget. Reconcile saved credentials first;
        # the canonical lease and store checkpoint consume the grant once.
        if _manual_oauth_recovery_granted(_context(job)):
            return _reconcile_saved_oauth(job, emit, checkpoint)
        if (reconcile or _oauth_retry_problem(job, member)
                or normalize_task_retry(_context(job).get("task_retry"))
                    != {"strategy": "safe_resume", "reason_code": "network_temporary"}):
            return _oauth_failed_result(job, member, checkpoint)
    if (not recover_legacy and not quota_recovery
            and (reconcile or _context(job).get(f"{step}_attempted"))):
        if step == "oauth":
            return _reconcile_saved_oauth(job, emit, checkpoint)
        task_id = _identifier(_context(job).get("canonical_task_id"))
        if step == "security" and task_id:
            from api.tasks import _task_store
            if _task_store.exists(task_id):
                previous = _task_store.snapshot(task_id)
                progress = _security_progress_from_snapshot(previous)
                if (
                    progress is not None
                    and progress != normalize_security_progress(
                        _context(job).get("security_progress")
                    )
                ):
                    _checkpoint(
                        job,
                        {"context": {"security_progress": progress}},
                        checkpoint,
                    )
                if previous.get("status") in {"failed", "stopped"}:
                    plans._wait_business_child_operation_release(int(job["child_id"]))
                    return _security_failed_result(job, previous, checkpoint)
        if step == "security":
            from services.nv_security_recovery import security_has_history
            if security_has_history(_context(job)):
                return _security_permission_review(job)
            # This is a real first attempt, not a cleared historical marker.
            return _result("retry", delay=30, error="本地核对确认尚无安全设置执行记录，可开始首次设置", updates={
                "context": {"task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}},
            })
        return _review("安全设置或 RT 的此前任务未确认完成")
    # Resolve the canonical capability before marking the browser mutation.
    security_recovery = None
    security_retry = None
    if step == "security" and _context(job).get("security_retry"):
        from services.nv_security_recovery import normalize_security_retry
        security_retry = normalize_security_retry(_context(job)["security_retry"], job)
        if security_retry is None or security_retry["phase"] != "queued":
            return _security_permission_review(job)
        status = plans._chatgpt_security_status_for_email(_email(job.get("email")))
        if (status.get("credentials_readable") is not True or status.get("has_password") is not True
                or status.get("password_state") != security_retry["credential_state"]
                or any(status.get(key) != security_retry[key] for key in
                       ("mfa_state", "has_totp", "has_recovery_codes"))
                or _date(status.get("updated_at")) != _date(security_retry["security_updated_at"])
                or _date(member.get("membership_invited_at")) != _date(security_retry["membership_invited_at"])
                or _context(job).get("canonical_task_id") != security_retry["source_task_id"]
                or _context(job).get("security_task_id") != security_retry["source_task_id"]
                or job.get("attempts") != security_retry["prior_attempts"]):
            return _security_permission_review(job, "手动核验排队后账号安全状态、成员周期或执行次数已变化，未使用旧许可")
        security_retry = {**security_retry, "phase": "started", "started_at": _iso(_now())}
    elif step == "security" and _context(job).get("security_recovery"):
        from services.nv_security_recovery import normalize_security_recovery
        security_recovery = normalize_security_recovery(_context(job)["security_recovery"], job)
        if security_recovery is None or security_recovery["phase"] != "queued":
            return _security_permission_review(job)
        status = plans._chatgpt_security_status_for_email(_email(job.get("email")))
        if (status.get("credentials_readable") is not True or status.get("has_password") is not True
                or status.get("password_state") != security_recovery["credential_state"]
                or any(status.get(key) != security_recovery[key] for key in
                       ("mfa_state", "has_totp", "has_recovery_codes"))
                or _date(status.get("updated_at")) != _date(security_recovery["security_updated_at"])
                or _context(job).get("canonical_task_id") != security_recovery["source_task_id"]
                or _context(job).get("security_task_id") != security_recovery["source_task_id"]):
            return _review("排队后账号安全状态或原任务已变化，未使用旧恢复授权")
        security_recovery = {**security_recovery, "phase": "started", "started_at": _iso(_now())}
    current = plans._resolve_business_child_batch_action_target(int(job["membership_id"]), action)
    if any(current.get(key) != value for key, value in target.items()):
        return _review("安全设置或 RT 目标身份已变化")
    _assert_parent(job, require_action=True)
    verified_unsubmitted_password = None
    if step == "security":
        from services.nv_legacy_security_login import (
            requires_unsubmitted_password_evidence,
            verified_unsubmitted_password as legacy_password_evidence,
        )
        verified_unsubmitted_password = legacy_password_evidence(job)
        if requires_unsubmitted_password_evidence(job) and verified_unsubmitted_password is None:
            return _security_permission_review(job, "旧首次密码未提交证据已变化，未启动新的登录或安全设置")
    initial_progress = normalize_security_progress({
        "stage": "session_check",
        "status": "running",
        "code": "session_check",
        "reason": "正在检查当前登录与安全状态",
        "retry_mode": "none",
        "retry_attempt": 0,
        "retry_limit": 0,
        "completed_stages": [],
    }) if step == "security" else None
    if step == "security":
        _checkpoint(job, {"context": {
            **({"security_recovery": security_recovery} if security_recovery else {}),
            **({"security_retry": security_retry} if security_retry else {}),
            "security_attempted": True, "security_started_at": _iso(_now()), "task_retry": None,
            "security_check": None,
            # A crash cannot let an older failed task authorize another launch.
            "canonical_task_id": "", "security_task_id": "",
            **_security_progress_update(initial_progress),
        }}, checkpoint)
    safe_emit = lambda text: _log(emit, str(text))
    if step == "security":
        if security_retry:
            retry_origin = "自动" if security_retry["kind"] == "security_stage_retry_v1" else "手动"
            _log(emit, f"开始本阶段{retry_origin}安全核验：保留原密码和 2FA，核对同一账号与远端状态；已有密钥只验证，不重新绑定")
        elif security_recovery:
            _log(emit, "开始一次受限安全恢复：保留已保存密码和 2FA，先核验当前账号与远端 MFA 状态")
        _log(emit, "密码或 2FA 尚未完整，开始设置密码与 Authenticator 2FA")
        launched = plans._start_member_business_child_security_setup_internal(
            int(job["parent_account_id"]), int(job["child_id"]),
            browser_mode=_settings(job).get("browser_mode", "headless"),
            proxy=plans._resolve_proxy(None),
            **({"verified_unsubmitted_password": verified_unsubmitted_password}
               if verified_unsubmitted_password is not None else {}),
        )
        task_id = _identifier(launched.get("task_id"))
        if not task_id:
            progress = _terminal_security_progress(
                job,
                "安全设置任务未返回可核验任务 ID",
                status="review",
                code="security_failed",
            )
            return _result("review", error="安全设置任务未返回可核验任务 ID；请人工核对，未自动重试", updates={
                "context": _security_progress_update(progress),
            })
        _checkpoint(job, {"context": {"security_task_id": task_id, "canonical_task_id": task_id}}, checkpoint)
        last_progress = initial_progress

        def persist_progress(task_snapshot):
            nonlocal last_progress
            progress = _security_progress_from_snapshot(task_snapshot)
            if progress is None or progress == last_progress:
                return
            _checkpoint(job, {"context": {"security_progress": progress}}, checkpoint)
            last_progress = progress

        snapshot = plans._wait_business_child_security_task(
            task_id,
            emit=safe_emit,
            on_snapshot=persist_progress,
        )
        persist_progress(snapshot)
        plans._wait_business_child_operation_release(int(job["child_id"]))
    else:
        # This read precedes the canonical lease/checkpoint transaction. A
        # positive balance is only a prerequisite; identity, credentials, fees
        # and the exact failed attempt are still checked in before_start.
        failure = normalize_oauth_failure(_context(job).get("oauth_failure"))
        balance_recovery = bool(failure and failure["code"] == "sms_balance_insufficient")
        if balance_recovery:
            if _settings(job).get("oauth_phone_retry_enabled") is not True:
                return _oauth_failed_result(job, member, checkpoint)
            from services.nv_oauth_balance import oauth_balance_gate
            problem = oauth_balance_gate.refresh(force=True)
            if problem:
                # Finish this batch item without consuming its one-use grant.
                # A later batch must revalidate balance and mint its own grant;
                # a completed manual batch cannot authorize a deferred launch.
                return _result("failed", error=problem)

        class PreflightStopped(RuntimeError):
            def __init__(self, result):
                self.result = result

        recovery_allow_phone = _settings(job).get("oauth_phone_retry_enabled") is True
        manual_recovery = recover_legacy and _manual_oauth_recovery_granted(_context(job))

        def before_start():
            # Runs inside the canonical account operation lease. A successful
            # read before acquiring that lease cannot authorize overwriting a
            # credential saved by another actor in the meantime.
            latest = _member(job)
            if _oauth_complete(job, latest) and not quota_recovery:
                raise PreflightStopped(_oauth_advance_result(job, latest))
            credential_changed = any(latest.get(key) != member.get(key) for key in (
                "oauth_credential_version", "oauth_acquired_at", "membership_invited_at",
                "oauth_has_any_credentials", "oauth_complete",
            ))
            if (credential_changed and not quota_recovery) or (
                quota_recovery and latest.get("membership_invited_at") != member.get("membership_invited_at")
            ):
                raise PreflightStopped(_review("获取 RT 前凭证或邀请周期已变化，未启动 OAuth；请核对已保存的凭证"))
            if manual_recovery and not _manual_oauth_recovery_granted(_context(job)):
                raise PreflightStopped(_review("本次手动重新获取许可已变化，未重复启动 OAuth"))
            if retrying_oauth and _oauth_retry_problem(job, latest):
                raise PreflightStopped(_oauth_failed_result(job, latest, checkpoint))
            if recover_legacy:
                problem = _oauth_recovery_problem(job, latest)
                if problem:
                    raise PreflightStopped(_review(problem))
            if balance_recovery:
                problem = oauth_balance_gate.problem()
                if problem:
                    raise PreflightStopped(_result("failed", error=problem))
            _assert_parent(job, require_action=True)
            current_target = plans._resolve_business_child_batch_action_target(int(job["membership_id"]), "oauth")
            if any(current_target.get(key) != value for key, value in target.items()):
                raise PreflightStopped(_review("获取 RT 前成员身份已变化，未启动 OAuth"))
            executions = _oauth_count(job, "oauth_execution_attempts")
            quota_attempts = _oauth_count(job, "quota_rt_recovery_attempts") or 0
            unknown_extra = bool(
                not manual_recovery and executions is not None
                and executions >= _oauth_max_executions(job)
                and normalize_oauth_failure(_context(job).get("oauth_failure"))
                and normalize_oauth_failure(_context(job).get("oauth_failure")).get("code") == "oauth_unknown"
                and not normalize_oauth_failure(_context(job).get("oauth_failure")).get("callback_received")
                and not normalize_oauth_failure(_context(job).get("oauth_failure")).get("exchange_started")
                and _context(job).get("oauth_unknown_auto_retry_count", 0) == 0
            )
            if quota_recovery and quota_attempts >= _oauth_max_executions(job):
                raise PreflightStopped(_result("failed", error="额度恢复重新获取 RT 已达本任务上限，已停止自动重试",
                    updates={"context": {"oauth_retry_blocked_reason": "execution_limit"}}))
            if (not quota_recovery and executions is not None and executions >= _oauth_max_executions(job)
                    and not (manual_recovery or unknown_extra)):
                raise PreflightStopped(_result("failed", error="实际 OAuth 已达本任务上限，未启动新的授权",
                    updates={"context": {"oauth_retry_blocked_reason": "execution_limit"}}))
            _checkpoint(job, {"context": {
                "oauth_attempted": True, "oauth_started_at": _iso(_now()),
                **({"quota_rt_recovery_started_at": _iso(_now())} if quota_recovery else {}),
                "oauth_membership_invited_at": latest["membership_invited_at"],
                "oauth_execution_attempts": (executions or 0) + 1,
                **({"quota_rt_recovery_attempts": quota_attempts + 1} if quota_recovery else {}),
                **({"oauth_unknown_auto_retry_count": 1} if unknown_extra else {}),
                **({"oauth_reconciliation_attempts": 0} if _oauth_count(job, "oauth_reconciliation_attempts") is None else {}),
                "oauth_retry_ready": False, "oauth_retry_blocked_reason": None,
                "oauth_failure": None, "oauth_failure_started_at": None, "oauth_failure_detail": "",
                "task_retry": None,
                **({"oauth_recovery_phone_allowed": recovery_allow_phone} if recover_legacy or retrying_oauth else {}),
                **({"oauth_manual_recovery": None, "oauth_recovery_requested": False} if manual_recovery else
                   {"oauth_recovery_attempts": 1, "oauth_recovery_requested": False} if recover_legacy else {}),
            }}, checkpoint)

        try:
            recovery_options = ({"allow_phone_verification": False}
                                if (recover_legacy or retrying_oauth) and not recovery_allow_phone else {})
            if recover_legacy or retrying_oauth or quota_recovery:
                recovery_options["expected_invited_at"] = member["membership_invited_at"]
            snapshot = plans._run_business_child_oauth_with_lease(
                target, emit=safe_emit, before_start=before_start,
                **({"allow_existing_credentials": True} if quota_recovery else {}),
                **recovery_options,
            )
        except PreflightStopped as exc:
            return exc.result
        except HTTPException as exc:
            if (exc.status_code == 409 and isinstance(exc.detail, dict)
                    and exc.detail.get("code") == "gpt_pro_account_busy"):
                return _result("wait", delay=60, error="子号正在执行其他操作，60 秒后自动检查；未重复启动 OAuth",
                    updates={"context": {"oauth_retry_blocked_reason": "account_busy"}})
            raise
        except RuntimeError as exc:
            if quota_recovery:
                # Startup/preflight failures occur before a canonical OAuth
                # result exists. Keep this quota repair in the same stage and
                # retry it automatically, while exposing the sanitized local
                # reason instead of converting it to an opaque review state.
                detail = _safe_error(exc)
                return _result("retry", delay=60,
                               error=f"额度刷新后重新获取 RT 启动失败：{detail}",
                               updates={"context": {
                                   "oauth_attempted": False,
                                   "oauth_retry_ready": False,
                                   "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"},
                               }})
            raise
        plans._wait_business_child_operation_release(int(job["child_id"]))
    if not isinstance(snapshot, dict) or snapshot.get("status") != "done":
        if isinstance(snapshot, dict) and snapshot.get("status") in {"failed", "stopped"}:
            if step == "security":
                return _security_failed_result(job, snapshot, checkpoint)
            failure = normalize_oauth_failure(snapshot.get("oauth_failure"))
            if snapshot.get("status") == "stopped":
                failure = OAuthAttemptFailure("oauth_cancelled").oauth_failure
            elif failure is None:
                failure = OAuthAttemptFailure("oauth_unknown").oauth_failure
            detail = plans._sanitize_member_task_text(snapshot.get("error") or failure["reason"])[:500]
            _checkpoint(job, {"context": {
                "oauth_failure": failure, "oauth_failure_detail": detail,
                "oauth_failure_started_at": _context(job).get("oauth_started_at"),
                "oauth_unknown_auto_retry": failure.get("code") == "oauth_unknown",
            }}, checkpoint)
            _log(emit, f"RT 原始失败原因：{detail}；先核对是否已保存凭证，再判断能否安全重试")
            if quota_recovery:
                # The old RT is already known to be revoked by the quota API.
                # Keep the sale/warranty lifecycle in place and retry only this
                # OAuth stage; read-only reconciliation must not accept the
                # revoked bundle as a newly acquired credential.
                return _result("retry", delay=60,
                               error=f"额度刷新后自动重新获取 RT 失败：{detail}",
                               updates={"context": {
                                   "oauth_attempted": False,
                                   "oauth_retry_ready": True,
                                   "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"},
                               }})
            return _reconcile_saved_oauth(job, emit, checkpoint)
        # A still-running/pending canonical task is not a human-review state.
        # Poll the same task again; no new browser mutation is launched.
        if isinstance(snapshot, dict) and snapshot.get("status") not in {"failed", "stopped", "done"}:
            detail = plans._sanitize_member_task_text(snapshot.get("error") or "任务仍在执行")
            return _result("retry", delay=30, error=f"{step}任务尚未结束，30 秒后自动检查：{detail}")
        detail = plans._sanitize_member_task_text(
            snapshot.get("error") if isinstance(snapshot, dict) else "未确认结果",
        )
        if step == "security":
            progress = _terminal_security_progress(
                job,
                detail or "安全设置任务结果未确认",
                status="review",
                code="security_failed",
                snapshot=snapshot,
            )
            return _result("review", error="安全设置任务未完成：" + detail + "；请人工核对，未自动重试", updates={
                "context": _security_progress_update(progress),
            })
        return _review("RT任务未完成：" + detail)
    member = _member(job)
    complete = plans._business_child_action_complete(target, action) if step == "security" else _oauth_complete(job, member)
    if not complete:
        if step == "security":
            progress = normalize_security_progress({
                "stage": "totp_verify",
                "status": "review",
                "code": "security_failed",
                "reason": "安全设置任务已结束，但密码与 2FA 完整状态尚未确认",
                "retry_mode": "verify_first",
                "retry_attempt": 0,
                "retry_limit": 0,
                "completed_stages": [],
            })
            return _result("review", error="任务已结束，但本次成员的完整安全信息尚未落库确认；请人工核对，未自动重试", updates={
                "context": _security_progress_update(progress),
            })
        if quota_recovery:
            return _result("retry", delay=60,
                           error="额度刷新后重新获取 RT 未确认完整凭证，将在本阶段自动重试",
                           updates={"context": {
                               "oauth_attempted": False,
                               "oauth_retry_ready": True,
                               "task_retry": {"strategy": "safe_resume", "reason_code": "network_temporary"},
                           }})
        return _reconcile_saved_oauth(job, emit, checkpoint)
    if step == "oauth":
        return _oauth_advance_result(job, member)
    return _result("advance", next_step="oauth", updates={
        "remote_user_id": member["remote_user_id"], "seat_type": member["seat_type"],
        **({"context": {"security_check": _security_check_evidence(job, "configured")}}
           if step == "security" else {}),
    })


def _baseline(snapshot: nexusvault.NexusVaultSalesSnapshot, email: str) -> dict:
    if snapshot.inventory_complete is not True:
        raise HTTPException(409, "NV 库存/出库分页未完整确认，不能创建上架基线")
    if any(_email(row.email) == email for row in (*snapshot.inventory_records, *snapshot.sold_records)) or email in {
        _email(value) for value in snapshot.unconfirmed_sold_emails
    }:
        raise HTTPException(409, "NV 已存在该邮箱的卡片或历史订单，不能自动创建另一销售周期")
    return {"email": email, "clear": True, "captured_at": _iso(_now())}


def _listing_context_valid(job: dict) -> bool:
    context = _context(job)
    baseline = context.get("publish_baseline")
    started = _date(context.get("publish_started_at"))
    captured = _date(baseline.get("captured_at")) if isinstance(baseline, dict) else None
    return bool(
        context.get("publish_attempted") is True
        and isinstance(baseline, dict) and baseline.get("clear") is True
        and _email(baseline.get("email")) == _email(job.get("email"))
        and captured is not None and started is not None
        and captured <= started <= _now()
    )


def _read_tier_usage(access_token: str, account_id: str, proxy: str) -> tuple[int, dict]:
    """Exactly one GET using the saved AT, no refresh/login/redirect or mutation."""
    from curl_cffi import requests as cffi_requests
    response = cffi_requests.get(
        "https://chatgpt.com/backend-api/wham/usage",
        headers={"Authorization": f"Bearer {access_token}", "Chatgpt-Account-Id": account_id,
                 "Accept": "application/json", "User-Agent": "codex_cli_rs/0.116.0"},
        proxies={"http": proxy, "https": proxy} if proxy else None,
        timeout=20, impersonate="chrome110", allow_redirects=False,
    )
    try:
        status = int(response.status_code)
        # Do not expose raw errors or permit an unbounded provider payload to
        # reach a durable job context/log. Only the small classifier sees JSON.
        if len(response.content) > 512 * 1024:
            return status, {}
        if status != 200 and not response.content.lstrip().startswith(b"{"):
            return status, {}
        try:
            payload = response.json()
        except (ValueError, TypeError):
            return status, {}
        if status != 200:
            error = payload.get("error") if isinstance(payload, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            return status, ({"error": {"code": code}} if code in {
                "account_deactivated", "account_deleted", "user_deactivated",
            } else {})
        return status, payload if isinstance(payload, dict) else {}
    finally:
        response.close()


def _probe_member_quota_tier(job: dict, member: dict) -> tuple[dict | None, str]:
    """Confirm an unlisted ordinary member's own current five-hour category."""
    if member.get("seat_type") == "prolite":
        return make_quota_tier(job, member, source="membership", now=_now()), ""
    if member.get("seat_type") != "default":
        return None, "成员实际席位类型未知"
    from platforms.chatgpt.status_probe import _decode_jwt_payload
    plans = _plans()
    with Session(plans.engine) as session:
        child = session.get(GptPlanAccountModel, _positive(job.get("child_id")))
        source = session.get(GptBusinessAccountModel, _positive(job.get("source_account_id")))
        parent = session.get(GptPlanAccountModel, _positive(job.get("parent_account_id")))
        if child is None or source is None or parent is None:
            return None, "成员或母号身份不存在"
        token = str(child.codex_access_token or "").strip()
        payload = _decode_jwt_payload(token)
        auth = payload.get("https://api.openai.com/auth")
        profile = payload.get("https://api.openai.com/profile")
        auth = auth if isinstance(auth, dict) else {}
        profile = profile if isinstance(profile, dict) else {}
        workspace = _identifier(auth.get("chatgpt_account_id"))
        token_email = _email(profile.get("email") or payload.get("email"))
        token_user = _identifier(auth.get("chatgpt_user_id") or auth.get("user_id"))
        _, source_workspace, _ = _business()._business_cookie_at_team(source.cookie_blob)
        known_workspaces = {_identifier(value) for value in (source_workspace, parent.chatgpt_account_id) if _identifier(value)}
        if (not token or token_email != _email(job.get("email")) or not workspace
                or token_user != _identifier(member.get("remote_user_id"))
                or known_workspaces != {workspace}
                or child.business_parent_id != source.id
                or _email(child.email) != _email(job.get("email"))):
            return None, "Codex 凭证的邮箱、用户或目标工作区尚未通过核对"
        credential_fingerprint = hashlib.sha256(token.encode()).hexdigest()
    try:
        status, payload = _read_tier_usage(token, workspace, plans._resolve_proxy(None))
    except Exception:
        return None, "额度接口连接失败，未将查询失败当作无 5 小时限制"
    if status != 200:
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict) and error.get("code") in {"account_deactivated", "account_deleted", "user_deactivated"}:
            current = _member(job, require_remote=True)
            with Session(plans.engine) as session:
                latest = session.get(GptPlanAccountModel, _positive(job.get("child_id")))
                unchanged = latest is not None and hashlib.sha256(str(latest.codex_access_token or "").strip().encode()).hexdigest() == credential_fingerprint
            if unchanged and all(current.get(key) == member.get(key) for key in
                    ("child_id", "membership_id", "email", "remote_user_id", "seat_type", "membership_invited_at")):
                raise HTTPException(409, {"code": "account_deactivated", "child_id": job["child_id"], "email": _email(job["email"])})
        return None, f"额度接口返回 HTTP {status}，未将查询失败当作无 5 小时限制"
    windows = usage_windows(payload)
    if windows is None:
        return None, "额度接口未返回完整、明确的限额窗口，无法区分有无 5 小时限制"
    # A read cannot authorize a different member/credential selected while the
    # request was in flight. Keep tokens/fingerprints out of persisted evidence.
    current = _member(job, require_remote=True)
    if any(current.get(key) != member.get(key) for key in ("child_id", "membership_id", "email", "remote_user_id", "seat_type")):
        return None, "额度查询期间子号身份或席位已变化"
    with Session(plans.engine) as session:
        child = session.get(GptPlanAccountModel, _positive(job.get("child_id")))
        if child is None or hashlib.sha256(str(child.codex_access_token or "").strip().encode()).hexdigest() != credential_fingerprint:
            return None, "额度查询期间 Codex 凭证已更新，请重新核验"
    return make_quota_tier(job, current, source="openai_usage", windows_seconds=windows,
                           workspace_id=workspace, now=_now()), ""


def _cycle_quota_tier(job: dict, snapshot: nexusvault.NexusVaultSalesSnapshot, evidence: dict) -> dict | None:
    """Use the already identity-checked NV cycle, never a same-email guess."""
    member = _member(job, allow_ended=True, require_remote=True)
    if member.get("seat_type") == "prolite":
        return make_quota_tier(job, member, source="membership", now=_now())
    previous = normalize_quota_tier(_context(job).get("quota_tier"), {**job, "seat_type": member.get("seat_type")}, now=_now())
    if member.get("seat_type") != "default" or snapshot.inventory_complete is not True:
        return previous
    card_ids = {_identifier(evidence.get("nv_remote_card_id"))}
    alias = evidence.get("nv_card_identity")
    if isinstance(alias, dict):
        card_ids.update(_identifier(alias.get(key)) for key in ("inventory_card_id", "order_card_id"))
    card_ids.discard("")
    matched = [row for row in snapshot.inventory_records if _email(row.email) == _email(job.get("email"))
               and card_ids.intersection({_identifier(row.remote_card_id), _identifier(row.inventory_card_id),
                                           _identifier(row.explicit_card_id)})]
    if len(matched) != 1:
        return previous
    row = matched[0]
    quota = getattr(row, "quota", None)
    windows = nv_windows(quota)
    if windows is None:
        return previous
    proof = make_quota_tier(job, member, source="nv_card", windows_seconds=windows,
        remote_card_id=_identifier(row.inventory_card_id or row.remote_card_id),
        observed_at=quota["updated_at"], now=_now())
    if proof and previous and _date(proof["observed_at"]) < _date(previous["observed_at"]):
        return previous  # An old NV cache cannot replace newer direct evidence.
    return proof or previous


def _publish(job: dict, emit: Callable, checkpoint: Callable | None) -> dict:
    from services.nv_publish_preflight import has_publish_evidence
    if has_publish_evidence(_context(job)):
        return _reconcile_nv(job, nexusvault.fetch_sales_snapshot(include_inventory=True))
    member = _member(job, require_remote=True)
    if not _identifier(job.get("remote_user_id")):
        return _review("上架前尚未冻结已加入成员的远端身份")
    if (member["sale_status"] != "unlisted" or member["nv_listing_confirmed_at"] or member["nv_listed_at"]
            or member.get("nv_team5x_warranty_until")):
        return _review("成员已有上架/出售状态，不能自动重复上架")
    _assert_parent(job, require_action=True)
    seat_type = member["seat_type"]
    if seat_type not in {"default", "prolite"}:
        return _result("failed", error="成员的实际席位类型未知，不能确定普通/高级上架价格；未上传 NV")
    # 5X can be kept in a prepared/manual-sale pool while NexusVault has its
    # 5X storefront disabled.  Persist the decision before any NV read/write
    # and park the job; the normal scheduler will not scan this manual row.
    if seat_type == "prolite" and _settings(job).get("auto_publish_prolite_to_nv", True) is not True:
        try:
            _checkpoint(job, {"seat_type": seat_type, "context": {
                "seat_type": seat_type,
                "manual_sale_required": True,
                "sale_source": "manual",
                "publish_attempted": False,
            }}, checkpoint)
        except Exception as exc:
            return _review(_safe_error(exc))
        _log(emit, "5X 已关闭自动上架 NV，RT 已完成，等待人工售卖")
        return _result("wait", next_step="wait_sale", delay=86400,
                       error="5X 自动上架已关闭，等待人工售卖",
                       updates={"context": {"manual_sale_required": True, "sale_source": "manual"}})
    plans = _plans()
    from services.nv_automation_store import NvAutomationPriceChanged, with_legacy_prices
    from services.nv_tier_policy import price_for_tier

    prices = with_legacy_prices(_settings(job))
    tier, reason = _probe_member_quota_tier(job, member)
    if tier is None:
        return _result("retry", delay=300, error=f"上架前档位核验暂未完成：{reason}；未上传 NV")
    price = plans._strict_nexusvault_price_yuan(_context(job).get("nv_price_override") or price_for_tier(prices, tier["tier"]))
    warranty = plans._strict_nexusvault_warranty_hours(_settings(job).get("warranty_hours", 1))
    team5x_warranty = None
    if tier["tier"] == "prolite":
        from services.nv_listing_warranty import resolve_team5x_warranty
        try:
            # Validate before the read/checkpoint; missing 5X configuration is
            # a conclusive no-upload failure, never an uncertain mutation.
            resolve_team5x_warranty(_settings(job), now=_now())
        except ValueError as exc:
            return _result("failed", error=f"5X 上架质保未配置或已失效：{exc}；未上传 NV")
    # Freeze an explicit no-send proof before the first remote read.  A
    # timeout/connection failure during this read is therefore safe to retry;
    # it must never be routed to reconciliation (which is reserved for an
    # upload whose outcome is genuinely unknown).
    context = _context(job)
    if not has_publish_evidence(context):
        try:
            _checkpoint(job, {"context": {
                "publish_attempted": False,
                "publish_preflight": {
                    "version": 1, "status": "running", "remote_publish_sent": False,
                    "started_at": _iso(_now()), "child_id": int(job.get("child_id") or 0),
                    "membership_id": int(job.get("membership_id") or 0),
                    "email": _email(job.get("email")),
                },
            }}, checkpoint)
        except Exception as exc:
            return _review(_safe_error(exc))
    # The read session is mandatory BEFORE account credentials are uploaded.
    baseline = _baseline(nexusvault.fetch_sales_snapshot(include_inventory=True), _email(job["email"]))
    # A full paginated read may take time; do not rely on its earlier health check.
    _assert_parent(job, require_action=True)
    started_at = _now()
    if tier["tier"] == "prolite":
        try:
            team5x_warranty = resolve_team5x_warranty(_settings(job), now=started_at)
        except ValueError as exc:
            return _result("failed", error=f"5X 上架质保未配置或已失效：{exc}；未上传 NV")
    try:
        _checkpoint(job, {"seat_type": seat_type, "context": {
            "publish_baseline": baseline, "publish_attempted": True,
            "publish_started_at": _iso(started_at), "price_yuan": price,
            "warranty_hours": 0 if team5x_warranty else warranty, "seat_type": seat_type,
            "quota_tier": tier,
            **({"team5x_warranty": team5x_warranty} if team5x_warranty else {}),
        }}, checkpoint)
    except NvAutomationPriceChanged:
        return _result("retry", delay=30, error="上架价格或 5X 质保配置已更新，尚未发送 NV 请求；稍后按最新配置重试")
    label = TIER_LABELS[tier["tier"]] + ("（高级席位）" if tier["tier"] == "prolite" else "")
    warranty_label = f"质保至 {team5x_warranty['until']}" if team5x_warranty else "质保 1 小时"
    _log(emit, f"已持久保存 NV 空基线及单次上架检查点：{label}，价格 ¥{price}，{warranty_label}")
    try:
        body = plans.GptPlanNexusVaultListingRequest(price_yuan=price, warranty_hours=warranty,
                                                   team5x_warranty=team5x_warranty)
        body._expected_target = {key: job.get(key) for key in (
            "parent_account_id", "source_account_id", "parent_email", "child_id", "email",
            "membership_id", "remote_user_id", "seat_type",
        )}
        result = plans.publish_business_child_to_nexusvault(
            int(job["membership_id"]), body,
        )
    except Exception as exc:
        return _child_deactivation_result(job, exc) or _review(_safe_error(exc))
    if not isinstance(result, dict) or result.get("ok") is not True or type(result.get("published")) is not int or result.get("published") != 1 or any(
        result.get(key) for key in ("partial", "action_required", "binding_changed", "identity_changed")
    ):
        return _review("NV 未明确确认本次上架成功")
    member = _member(job, require_remote=True)
    if member["sale_status"] != "listed" or not member["nv_listed_at"] or not member["nv_listing_confirmed_at"]:
        return _review("NV 上架响应成功，但本地上架确认记录不完整")
    if team5x_warranty and _date(member.get("nv_team5x_warranty_until")) != _date(team5x_warranty["until"]):
        return _review("NV 上架响应成功，但本地 5X 质保截止时间未准确保存")
    context = {
        "publish_confirmed": True, "nv_listed_at": member["nv_listed_at"],
        "nv_listing_confirmed_at": member["nv_listing_confirmed_at"],
    }
    return _result("advance", next_step="wait_sale", updates={"context": context})


def _cycle_card_identity(job: dict, snapshot: nexusvault.NexusVaultSalesSnapshot,
                         email: str, floor: datetime, sold: list) -> dict | None:
    """Keep inventory IDs and order-card IDs distinct unless NV proves a link.

    The client only supplies links corroborated by all three complete sources.
    Persist the exact pair/order/time so an archived inventory card can later
    be checked against its original order without re-learning an email alias.
    """
    previous = _context(job).get("nv_card_identity")

    def validate(proof):
        keys = {"kind", "email", "listing_started_at", "sold_at", "inventory_card_id",
                "order_card_id", "remote_order_id"}
        if not isinstance(proof, dict) or set(proof) != keys:
            raise HTTPException(409, "NV 卡片关联证据格式无效，不能仅按邮箱确认")
        sold_at = _date(proof["sold_at"])
        if (proof["kind"] != "nv_card_identity_v1" or proof["email"] != email
                or _date(proof["listing_started_at"]) != floor
                or sold_at is None or not floor <= sold_at <= _now()
                or any(not _identifier(proof[key]) or _identifier(proof[key]) != proof[key]
                       for key in ("inventory_card_id", "order_card_id", "remote_order_id"))):
            raise HTTPException(409, "NV 卡片关联证据的邮箱、周期或身份不一致")
        return {**proof, "listing_started_at": _iso(floor), "sold_at": _iso(sold_at)}

    frozen = validate(previous) if previous is not None else None
    links = []
    for link in getattr(snapshot, "card_identity_links", ()):
        if _email(link.email) != email:
            continue
        linked_time = _date(link.sold_at)
        if linked_time is not None and linked_time < floor:
            continue
        proof = validate({
            "kind": "nv_card_identity_v1", "email": email,
            "listing_started_at": _iso(floor), "sold_at": _iso(linked_time),
            "inventory_card_id": link.inventory_card_id,
            "order_card_id": link.order_card_id, "remote_order_id": link.remote_order_id,
        })
        if proof not in links:
            links.append(proof)
    if len(links) > 1 or (frozen and links and links[0] != frozen):
        raise HTTPException(409, "NV 库存与订单卡片的已确认关联发生冲突")
    proof = frozen or (links[0] if links else None)
    if proof is None:
        return None
    if frozen and not links and any(_email(row.email) == email for row in snapshot.inventory_records):
        # Missing inventory after archiving is expected. Visible inventory,
        # however, must still corroborate the original link in all sources;
        # old proof cannot override a newly conflicting/invalid remote field.
        raise HTTPException(409, "NV 当前库存的卡片、订单或出售时间关联未通过复核")
    if not any(
        _identifier(row.remote_order_id) == proof["remote_order_id"]
        and _identifier(row.remote_card_id) == proof["order_card_id"]
        and _date(row.sold_at) == _date(proof["sold_at"])
        for row in sold
    ):
        raise HTTPException(409, "NV 未返回已关联的同一卡片、订单与出售时间，不能确认过保")
    # A new inventory object must not inherit an old order merely because its
    # public card ID or email is reused. Old DTOs have no raw inventory field.
    for row in (*snapshot.inventory_records, *sold):
        if _email(row.email) != email:
            continue
        inventory_id = _identifier(getattr(row, "inventory_card_id", ""))
        explicit_id = _identifier(getattr(row, "explicit_card_id", ""))
        remote_order = _identifier(getattr(row, "remote_order_id", ""))
        sold_at = _date(getattr(row, "sold_at", None))
        if inventory_id and inventory_id != proof["inventory_card_id"]:
            raise HTTPException(409, "NV 当前库存身份与本周期已确认的库存卡片不一致")
        if explicit_id and explicit_id != proof["order_card_id"]:
            raise HTTPException(409, "NV 当前卡片标识与本周期已确认的订单卡片不一致")
        if remote_order and remote_order != proof["remote_order_id"]:
            raise HTTPException(409, "NV 当前库存或出售记录的订单身份与已确认关联不一致")
        if sold_at is not None and sold_at != _date(proof["sold_at"]):
            raise HTTPException(409, "NV 当前库存或出售记录的出售时间与已确认关联不一致")
    return proof


def _cycle_warranty(context: dict, basis: dict, rows: list, floor: datetime) -> dict:
    """Use this listing's frozen deadline, and reject conflicting remote terms."""
    from services.nv_listing_warranty import normalize_team5x_warranty
    try:
        frozen = normalize_team5x_warranty(context.get("team5x_warranty"), require_future=False)
    except ValueError:
        raise HTTPException(409, "本次 5X 上架质保记录无效") from None
    adopted = _date(basis.get("nv_team5x_warranty_until"))
    absolute = _date(frozen["until"]) if frozen else adopted
    if frozen and adopted and absolute != adopted:
        raise HTTPException(409, "本次 5X 上架与接管质保截止时间冲突")
    remote = {_date(value) for row in rows
              if (value := getattr(row, "team5x_warranty_until", None)) is not None}
    if remote and (None in remote or len(remote) != 1 or absolute not in remote):
        raise HTTPException(409, "NV 远端 5X 质保截止时间与本次冻结记录不一致")
    if absolute is not None:
        if absolute <= floor:
            raise HTTPException(409, "本次 5X 质保截止时间不晚于上架时间")
        return {"team5x_warranty": normalize_team5x_warranty(
            {"mode": "until", "until": _iso(absolute)}, require_future=False), "warranty_hours": 0}
    hours = basis.get("warranty_hours", context.get("warranty_hours", 1))
    if type(hours) is not int or not 1 <= hours <= 87600:
        raise HTTPException(409, "本次上架质保时长无效")
    return {"warranty_hours": hours}


def _cycle_evidence(job: dict, snapshot: nexusvault.NexusVaultSalesSnapshot) -> dict:
    """Match one cycle against an original baseline OR verified prior listing."""
    if snapshot.inventory_complete is not True:
        raise HTTPException(409, "NV 库存/出库记录未完整读取")
    context = _context(job)
    existing = context.get("existing_listing")
    member = None
    if existing is not None:
        member = _member(job, allow_ended=True, require_remote=True)
        reason = _existing_listing_error(job, member)
        if reason:
            raise HTTPException(409, reason)
        basis = existing
    else:
        if not _listing_context_valid(job):
            raise HTTPException(409, "本次上架缺少持久、完整的远端空基线")
        basis = {}
    email = _email(job.get("email"))
    floor = _date(basis.get("nv_listed_at") or context.get("nv_listed_at") or context.get("publish_started_at"))
    inventory = [row for row in snapshot.inventory_records if _email(row.email) == email]
    sold = [row for row in snapshot.sold_records if _email(row.email) == email and _date(row.sold_at) is not None and _date(row.sold_at) >= floor]
    # A legacy adoption may freeze empty IDs before a manual read-only sales
    # refresh fills them. Preserve that same membership's newly learned IDs;
    # they still must pass the full remote cycle/alias checks below. Never
    # replace an already frozen task ID with a different local value.
    card_id = _identifier(context.get("nv_remote_card_id") or basis.get("nv_remote_card_id")
                          or (member or {}).get("nv_remote_card_id"))
    order_id = _identifier(context.get("nv_remote_order_id") or basis.get("nv_remote_order_id")
                           or (member or {}).get("nv_remote_order_id"))
    from services.nv_refund_policy import match_cycle_refund
    try:
        refund = match_cycle_refund(snapshot, email=email, remote_order_id=order_id,
            remote_card_id=card_id, sold_at=context.get("sold_at") or (member or {}).get("sold_at"),
            listed_at=floor)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    if refund:
        warranty = _cycle_warranty(context, basis, [], floor)
        absolute = warranty.get("team5x_warranty")
        deadline = _date(absolute["until"]) if absolute else _date(refund["sold_at"]) + timedelta(hours=warranty["warranty_hours"])
        return {"status": "refunded" if refund["full_refund"] else "partial_refund",
                "nv_remote_card_id": card_id, "nv_remote_order_id": refund["remote_order_id"],
                "sold_at": refund["sold_at"], "warranty_until": _iso(deadline),
                "nv_refund": refund, **warranty}
    if context.get("nv_refund"):
        raise HTTPException(409, "NV 未返回本周期已确认退款记录，未恢复为已出售或执行退出")
    identity = _cycle_card_identity(job, snapshot, email, floor, sold)

    def logical_card(value):
        identifier = _identifier(value)
        if identity and identifier in {identity["inventory_card_id"], identity["order_card_id"]}:
            return identity["order_card_id"]
        return identifier

    current_card_ids = {_identifier(row.remote_card_id) for row in inventory}
    sale_card_ids = {_identifier(row.remote_card_id) for row in sold if _identifier(row.remote_card_id)}
    ids = {logical_card(value) for value in current_card_ids | sale_card_ids}
    if "" in current_card_ids or len(ids) > 1 or (card_id and ids and ids != {logical_card(card_id)}):
        raise HTTPException(409, "NV 同邮箱卡片不唯一或与本次卡片身份不一致")
    if not card_id and ids:
        card_id = next(iter(ids))
    if any(row.status not in {"available", "sold"} for row in inventory):
        raise HTTPException(409, "NV 卡片状态尚不能确认")
    statuses = {row.status for row in inventory}
    if len(statuses) > 1:
        raise HTTPException(409, "NV 同一卡片返回相互冲突的库存状态")
    warranty = _cycle_warranty(context, basis, [*inventory, *sold], floor)
    if sold:
        # An order without a card ID is usable only after that exact order was
        # bound, or when no card exists and the new order itself is unique.
        if card_id:
            matched = [row for row in sold if (
                logical_card(row.remote_card_id) == logical_card(card_id)
                or (order_id and _identifier(row.remote_order_id) == order_id)
            )]
            if len(matched) != len(sold):
                raise HTTPException(409, "NV 订单缺少能绑定本次卡片的身份，不能仅按邮箱确认出售")
        else:
            matched = sold
            orders = {_identifier(row.remote_order_id) for row in matched}
            if "" in orders or len(orders) != 1:
                raise HTTPException(409, "NV 出库订单没有唯一有效身份")
        timestamps = {_date(row.sold_at) for row in matched}
        orders = {_identifier(row.remote_order_id) for row in matched if _identifier(row.remote_order_id)}
        if len(timestamps) != 1 or len(orders) > 1 or (order_id and orders and orders != {order_id}):
            raise HTTPException(409, "NV 本次卡片的出售时间或订单身份不唯一")
        if identity and (timestamps != {_date(identity["sold_at"])} or orders != {identity["remote_order_id"]}):
            raise HTTPException(409, "NV 本次出售与已确认的卡片关联证据不一致")
        sold_at = next(iter(timestamps))
        if sold_at > _now() or statuses == {"available"}:
            raise HTTPException(409, "NV 出售证据与当前时间/在售状态冲突")
        previous_sale = _date(context.get("sold_at"))
        if previous_sale is not None and previous_sale != sold_at:
            raise HTTPException(409, "NV 本周期已确认出售时间发生变化")
        absolute = warranty.get("team5x_warranty")
        deadline = _date(absolute["until"]) if absolute else sold_at + timedelta(hours=warranty["warranty_hours"])
        if deadline < sold_at:
            raise HTTPException(409, "NV 出售时间晚于本次 5X 质保截止时间，需人工核对")
        return {
            "status": "sold", "nv_remote_card_id": card_id,
            "nv_remote_order_id": next(iter(orders)) if orders else order_id,
            "sold_at": _iso(sold_at),
            "warranty_until": _iso(deadline), **warranty,
            **({"nv_card_identity": identity} if identity else {}),
        }
    if context.get("sold_at"):
        raise HTTPException(409, "NV 暂未返回本周期已确认的出库证据，不能自动退出")
    if statuses == {"available"} and card_id:
        return {"status": "available", "nv_remote_card_id": card_id, "nv_remote_order_id": order_id, **warranty}
    if email in {_email(value) for value in snapshot.unconfirmed_sold_emails} or statuses == {"sold"}:
        raise HTTPException(409, "NV 有出库记录但出售时间无效，不能计算质保")
    raise HTTPException(409, "NV 未找到本周期唯一卡片/订单，上架结果仍需核对")


def _persist_evidence(job: dict, evidence: dict) -> dict:
    """Sync the existing membership only after authoritative cycle matching."""
    _member(job, allow_ended=True)
    context = _context(job)
    existing = context.get("existing_listing")
    basis = existing if isinstance(existing, dict) else {}
    started = _date(basis.get("nv_listed_at") or context.get("publish_started_at"))
    expected_floor = _date(basis.get("nv_listed_at") or context.get("nv_listed_at"))
    with Session(_plans().engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        row = session.get(GptBusinessChildMembershipModel, int(job["membership_id"]))
        child = session.get(GptPlanAccountModel, int(job["child_id"]))
        parent = session.get(GptPlanAccountModel, int(job["parent_account_id"]))
        source = session.get(GptBusinessAccountModel, int(job["source_account_id"]))
        if (
            row is None or child is None or parent is None or source is None
            or row.pro_account_id != int(job["child_id"])
            or row.business_account_id != int(job["source_account_id"])
            or parent.source_pool != "gpt_business" or parent.source_account_id != source.id
            or _email(parent.email) != _email(job["parent_email"])
            or _email(source.email) != _email(job["parent_email"])
            or _email(row.email) != _email(job["email"])
            or _email(child.email) != _email(job["email"])
            or str(row.source or "") != "pool"
            or (row.ended_at is None and child.business_parent_id != source.id)
            or not _identifier(job.get("remote_user_id"))
            or _identifier(row.remote_user_id) != _identifier(job.get("remote_user_id"))
            or str(row.sale_status or "") not in {"unlisted", "listed", "sold", "refunded", "partial_refund"}
        ):
            raise HTTPException(409, "NV 核对后本地成员/母号身份已变化，未写回")
        if existing is not None:
            current = dict(membership_invited_at=_iso(_date(row.invited_at)),
                nv_listed_at=_iso(_date(row.nv_listed_at)), nv_listing_confirmed_at=_iso(_date(row.nv_listing_confirmed_at)),
                warranty_hours=row.warranty_hours, nv_remote_card_id=_identifier(row.nv_remote_card_id),
                nv_team5x_warranty_until=_iso(_date(getattr(row, "nv_team5x_warranty_until", None))),
                nv_remote_order_id=_identifier(row.nv_remote_order_id),
                nv_identifiers_valid=all(not str(getattr(row, key) or "").strip() or bool(_identifier(getattr(row, key)))
                                         for key in ("nv_remote_card_id", "nv_remote_order_id")))
            reason = _existing_listing_error(job, current)
            if reason:
                raise HTTPException(409, reason)
        local_floor = _date(row.nv_listed_at)
        local_deadline = _date(getattr(row, "nv_team5x_warranty_until", None))
        absolute = evidence.get("team5x_warranty")
        deadline = _date(absolute.get("until")) if isinstance(absolute, dict) else None
        if (
            started is None
            or (expected_floor is not None and local_floor != expected_floor)
            or (local_floor is not None and local_floor < started)
            or (_identifier(row.nv_remote_card_id) and _identifier(row.nv_remote_card_id) != evidence["nv_remote_card_id"])
            or (_identifier(row.nv_remote_order_id) and _identifier(row.nv_remote_order_id) != evidence["nv_remote_order_id"])
            or (local_deadline is not None and local_deadline != deadline)
        ):
            raise HTTPException(409, "本地 NV 上架周期已变化，未写回远端状态")
        now = _now()
        if row.sale_status in {"refunded", "partial_refund"} and evidence["status"] not in {"refunded", "partial_refund"}:
            raise HTTPException(409, "本周期已记录 NV 退款，旧出售快照不能覆盖")
        row.nv_listed_at = local_floor or started
        row.nv_listing_confirmed_at = _date(row.nv_listing_confirmed_at) or now
        row.nv_remote_card_id = evidence["nv_remote_card_id"]
        row.nv_remote_order_id = evidence["nv_remote_order_id"]
        row.nv_last_synced_at = now
        row.warranty_hours = evidence["warranty_hours"]
        row.nv_team5x_warranty_until = deadline
        if evidence["status"] in {"refunded", "partial_refund"}:
            from services.nv_refund_policy import apply_membership_refund
            if not apply_membership_refund(session, row, evidence["nv_refund"]):
                raise HTTPException(409, "本地退款订单或成员身份已变化，未写回")
        elif evidence["status"] == "sold":
            row.sale_status = "sold"
            row.sold_at = _date(evidence["sold_at"])
        elif row.sale_status == "unlisted":
            row.sale_status = "listed"
            row.sold_at = None
        row.updated_at = now
        session.add(row)
        session.commit()
        return {
            "publish_confirmed": True,
            "nv_listed_at": _iso(_date(row.nv_listed_at)),
            "nv_listing_confirmed_at": _iso(_date(row.nv_listing_confirmed_at)),
            "nv_last_synced_at": _iso(now),
            **{key: value for key, value in evidence.items() if key != "status"},
        }


def _nv_workspace_deactivation(job: dict, snapshot: nexusvault.NexusVaultSalesSnapshot) -> dict | None:
    """Apply the configured mother-DEAD rule only to this active listing.

    A generic unknown inventory status is not evidence. The client recognizes
    the specific NV blocked-workspace/402 response without forwarding raw text;
    the canonical writer rechecks persistent ownership in its transaction.
    """
    email = _email(job.get("email"))
    rows = [row for row in snapshot.inventory_records if _email(row.email) == email]
    if not any(getattr(row, "workspace_deactivated", False) is True for row in rows):
        return None
    if snapshot.inventory_complete is not True or len(rows) != 1 or not email:
        raise HTTPException(409, "NV 工作区停用记录不完整或卡片不唯一，未标记母号 Dead")
    context = _context(job)
    member = _member(job, require_remote=True)
    basis = context.get("existing_listing")
    if basis is not None:
        reason = _existing_listing_error(job, member)
        if reason:
            raise HTTPException(409, reason)
    elif context.get("publish_confirmed") is not True or not _listing_context_valid(job):
        raise HTTPException(409, "NV 工作区停用记录缺少本次上架确认，未标记母号 Dead")
    basis = basis or {}
    floor = _date(basis.get("nv_listed_at") or context.get("nv_listed_at")
                  or context.get("publish_started_at"))
    row = rows[0]
    checked = _date(getattr(row, "workspace_deactivated_at", None))
    confirmed = _date(member.get("nv_listing_confirmed_at"))
    if (floor is None or checked is None or confirmed is None
            or _date(member.get("nv_listed_at")) != floor
            or not floor <= confirmed <= checked <= _now()):
        raise HTTPException(409, "NV 工作区停用检查时间不属于当前上架周期，未标记母号 Dead")
    card_id = _identifier(row.remote_card_id)
    local_ids = {_identifier(value) for value in (
        context.get("nv_remote_card_id"), basis.get("nv_remote_card_id"), member.get("nv_remote_card_id"),
    ) if value}
    if not card_id or local_ids != {card_id}:
        raise HTTPException(409, "NV 工作区停用卡片与当前子号不一致，未标记母号 Dead")
    # Do not associate a blocked old card with a different same-email sale.
    if any(_email(sale.email) == email and (_date(sale.sold_at) or floor) >= floor
           and _identifier(sale.remote_card_id) != card_id for sale in snapshot.sold_records):
        raise HTTPException(409, "NV 工作区停用卡片与本周期订单身份冲突，未标记母号 Dead")
    from services.nv_workspace_deactivation import mark_deactivated_mother, REASON
    try:
        mark_deactivated_mother(job, {
            "workspace_deactivated": True, "email": email, "remote_card_id": card_id,
            "listed_at": _iso(floor), "checked_at": _iso(checked),
        })
    except ValueError:
        raise HTTPException(409, "NV 工作区停用记录与当前母号、子号或任务已不一致，未修改标记") from None
    return _result("failed", error=REASON)


def _reconcile_nv(job: dict, snapshot: nexusvault.NexusVaultSalesSnapshot) -> dict:
    context = _context(job)
    # A 5X account parked for manual sale has no NV cycle by design.  Do not
    # feed it through cycle evidence (which requires an NV empty baseline),
    # otherwise the harmless absence of a listing becomes a review/409 state
    # and hides the 已售出 control in the UI.
    if (context.get("manual_sale_required") is True
            and context.get("manual_sale") is not True
            and not context.get("sold_at")):
        return _result("wait", next_step="wait_sale", delay=86400,
                       error="5X 自动上架已关闭，等待人工售卖",
                       updates={"context": {"manual_sale_required": True,
                                              "sale_source": "manual"}})
    deactivated = _nv_workspace_deactivation(job, snapshot)
    if deactivated is not None:
        return deactivated
    evidence = _cycle_evidence(job, snapshot)
    context = _persist_evidence(job, evidence)
    if evidence["status"] == "refunded":
        return _result("advance", next_step="leave", updates={"context": context})
    if evidence["status"] == "partial_refund":
        return _result("review", error="NV 部分退款，未按全额退款自动退出，请核对退款结果", updates={"context": context})
    tier = _cycle_quota_tier(job, snapshot, evidence)
    if tier is not None:
        context["quota_tier"] = tier
    if evidence["status"] == "available":
        return _result("advance" if job.get("step") == "publish" else "wait", next_step="wait_sale", delay=60, updates={"context": context})
    waiting = _exit_wait_result(context["warranty_until"], context, job=job)
    if waiting is not None:
        if waiting["outcome"] == "wait" and not waiting.get("error") and job.get("step") != "wait_warranty":
            waiting["outcome"] = "advance"
        return waiting
    return _result("advance", next_step="leave", updates={"context": context})


def _leave_target(job: dict, member: dict) -> dict:
    return {
        **_action_target(job), "parent_email": _email(job["parent_email"]),
        "source": "pool", "user_id": _identifier(job["remote_user_id"]),
        "invite_id": member["remote_invite_id"], "operation_id": _operation(job),
    }


def _ensure_leave_session(job: dict, emit: Callable) -> dict:
    from services.business_session_health import ensure_session_for_automation
    return ensure_session_for_automation(_positive(job.get("source_account_id")), emit=emit,
        browser_mode=_settings(job).get("browser_mode", "headless"))


def _leave_preflight_wait(job: dict, error, emit: Callable, checkpoint: Callable | None) -> dict:
    from services.nv_exit_recovery import BusinessExitPreflightError, normalize_leave_preflight
    failure = error if isinstance(error, BusinessExitPreflightError) else BusinessExitPreflightError(error.detail)
    delay = 60 if failure.failure["retryable"] else 900
    retry_at = _date(failure.retry_at)
    if retry_at:
        delay = max(delay, min(86400, int((retry_at - _now()).total_seconds()) + 1))
    value = normalize_leave_preflight({**failure.failure, "retry_at": _iso(_now() + timedelta(seconds=delay))})
    context = {"leave_attempted": False, "leave_target": None, "leave_started_at": "",
               "leave_preflight": value,
               "task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}}
    _checkpoint(job, {"context": context}, checkpoint)
    _log(emit, value["message"])
    return _result("wait", next_step="leave", delay=delay, error=value["message"], updates={"context": context})


def _leave(job: dict, emit: Callable, checkpoint: Callable | None, *, reconcile: bool = False) -> dict:
    previous = _context(job).get("leave_target")
    if isinstance(previous, dict):
        expected = {
            **_action_target(job), "parent_email": _email(job.get("parent_email")),
            "source": "pool", "user_id": _identifier(job.get("remote_user_id")),
            "operation_id": _operation(job),
        }
        if any(previous.get(key) != value for key, value in expected.items()):
            return _review("此前退出操作的冻结成员身份已变化")
        # Canonical exit can purge a released Dead child. Its immutable ended
        # membership and operation ID remain sufficient to confirm completion.
        if _plans()._business_child_batch_leave_complete(previous, require_operation=True):
            return _result("advance", next_step="done", updates={"context": {"left_at": _iso(_now())}})
    member = _member(job, allow_ended=True, require_remote=True)
    target = _leave_target(job, member)
    # A previously attempted release must use its original frozen invite/user
    # identity too; refreshing the row must not redirect the canonical delete.
    if isinstance(previous, dict):
        if any(previous.get(key) != target.get(key) for key in target):
            return _review("此前退出操作的冻结成员身份已变化")
        target = dict(previous)
    if member["ended_at"]:
        if _plans()._business_child_batch_leave_complete(target, require_operation=True):
            return _result("advance", next_step="done", updates={"context": {"left_at": member["ended_at"]}})
        return _review("成员已退出，但不是本自动任务可确认的退出操作")
    if reconcile or _context(job).get("leave_attempted"):
        from services.nv_exit_recovery import legacy_preflight_failure, saved_preflight_failure, BusinessExitPreflightError
        if _context(job).get("leave_preflight"):
            with Session(_plans().engine) as session:
                saved_noop = saved_preflight_failure(session, job)
            if saved_noop:
                proof = _context(job)["leave_preflight"]
                _log(emit, "已核对中断前仅完成会话预检、未发送移除请求，恢复会话检查步骤")
                return _leave_preflight_wait(job, BusinessExitPreflightError({
                    "code": proof["code"], "session_health": {"status": proof["status"]},
                    "retryable": proof["retryable"], "retry_at": proof["retry_at"],
                }), emit, checkpoint)
        safe_to_resume = False
        if isinstance(previous, dict):
            with Session(_plans().engine) as session:
                safe_to_resume = legacy_preflight_failure(session, job)
        if safe_to_resume:
            _log(emit, "已确认旧任务仅在母号会话预检失败、尚未发送移除请求，恢复会话检查步骤")
            return _leave_preflight_wait(job, BusinessExitPreflightError({
                "code": "business_session_unavailable", "session_health": {"status": "error"},
            }), emit, checkpoint)
        return _review(f"此前退出结果尚未确认，操作 ID {target['operation_id']}")
    from services.nv_job_exit_policy import manual_exit_authorized, manual_sale_early_exit_authorized
    manual_exit = manual_exit_authorized(job, now=_now().timestamp())
    if _settings(job).get("auto_exit") is not True and not manual_exit:
        return _result("wait", delay=60, error="自动退出开关未开启")
    if not _identifier(job.get("remote_user_id")):
        return _review("没有冻结正式成员身份，不能自动退出")
    manual_sale = _context(job).get("manual_sale") is True
    if manual_sale:
        # Manual sales have no NV listing/order to reconcile. The local sale
        # confirmation and configured warranty deadline are the frozen cycle
        # facts; the canonical member identity check above still applies.
        # Exit-delay and one-click-exit controls live under private context
        # keys (``_job_exit_delay_v1`` / ``_manual_exit_v1``).  They are
        # policy inputs, not worker checkpoints; passing them through the
        # checkpoint validator makes an otherwise safe exit fail with an
        # unsupported-field ValueError.  Keep only the allow-listed lifecycle
        # evidence when writing the leave checkpoint.
        # Only persist the immutable sale/warranty evidence needed by the
        # leave checkpoint.  Replaying unrelated historical fields (for
        # example security_retry or quota_tier) can trigger validators for a
        # different stage and block an otherwise valid manual exit.
        context = _context(job)
        confirmed = {key: context[key] for key in
                     ("sold_at", "warranty_until", "team5x_warranty", "warranty_hours")
                     if key in context}
        evidence = {"status": "sold", "warranty_until": confirmed.get("warranty_until"),
                    "team5x_warranty": confirmed.get("team5x_warranty"),
                    "warranty_hours": confirmed.get("warranty_hours", 0)}
        if not evidence["warranty_until"]:
            return _review("人工出售缺少本地质保截止时间，不能安排自动退出")
        refunded = False
    else:
        # Always read again here.  A previous scan/local manual sold flag is NOT
        # authorization to remove a member after a delay or process restart.
        snapshot = nexusvault.fetch_sales_snapshot(include_inventory=True)
        deactivated = _nv_workspace_deactivation(job, snapshot)
        if deactivated is not None:
            return deactivated
        evidence = _cycle_evidence(job, snapshot)
        if evidence["status"] not in {"sold", "refunded"}:
            return _review("退出前未重新确认本周期出售证据或全额退款证据")
        confirmed = _persist_evidence(job, evidence)
        refunded = evidence["status"] == "refunded"
        tier = _cycle_quota_tier(job, snapshot, evidence)
        if tier is not None:
            confirmed["quota_tier"] = tier
    waiting = None if refunded else _exit_wait_result(evidence["warranty_until"], confirmed, emit=emit, check_enabled=False, job=job)
    if waiting is not None:
        return waiting
    # Session recovery is a read/login capability, BEFORE any exit-attempt marker.
    # Canonical remove still performs its own preflight and frozen identity gate.
    from services.nv_exit_recovery import BusinessExitPreflightError, CODES
    try:
        _log(emit, "退出前检查母号会话，必要时自动恢复 Cookie")
        _ensure_leave_session(job, emit)
    except HTTPException as exc:
        if isinstance(exc, BusinessExitPreflightError) or isinstance(exc.detail, dict) and exc.detail.get("code") in CODES:
            return _leave_preflight_wait(job, exc, emit, checkpoint)
        raise
    _assert_parent(job, require_action=True)
    _plans()._business_child_batch_leave_complete(target)
    # Remote account/evidence checks can take time. Re-read immediately before
    # the durable authorization checkpoint; its transaction also gates a policy
    # change occurring between this read and the actual leave_attempted write.
    waiting = None if refunded else _exit_wait_result(evidence["warranty_until"], confirmed, emit=emit, check_enabled=False, job=job)
    if waiting is not None:
        return waiting
    from services.nv_automation_store import NvAutomationExitDelayChanged
    try:
        _checkpoint(job, {"context": {
            **confirmed, "leave_attempted": True, "leave_started_at": _iso(_now()),
            "leave_target": target, "leave_preflight": None,
        }}, checkpoint)
    except NvAutomationExitDelayChanged:
        waiting = _exit_wait_result(evidence["warranty_until"], confirmed, emit=emit, job=job)
        if waiting is not None:
            return waiting
        # Settings may have changed again while returning from the CAS. Never
        # reuse a rejected authorization; rescan and acquire a new checkpoint.
        return _result("wait", next_step="wait_warranty", delay=1,
            error="自动退出延迟已更新，等待重新核对退出时间", updates={"context": confirmed})
    warranty_label = (f"质保截止 {evidence['warranty_until']}" if manual_sale
                      else (f"真实质保（截止 {evidence['warranty_until']}）" if evidence.get("team5x_warranty")
                      else f"{evidence['warranty_hours']} 小时真实质保"))
    if refunded:
        _log(emit, f"NV 已确认本订单全额退款，不再等待质保及退出延迟，退出当前子号空间；操作 ID {target['operation_id']}")
    elif manual_sale_early_exit_authorized(job, now=_now().timestamp()):
        _log(emit, f"已确认人工售出及本单手动退出指令，无需等待质保或退出延迟结束，立即退出当前子号空间；操作 ID {target['operation_id']}")
    else:
        _log(emit, f"已确认同周期售出，{warranty_label}及当前配置的退出延迟均已结束，"
             f"{'按单号手动指令立即退出' if manual_exit else '执行单次自动退出'}；操作 ID {target['operation_id']}")
    try:
        _plans()._run_business_child_batch_leave(target)
    except BusinessExitPreflightError as exc:
        return _leave_preflight_wait(job, exc, emit, checkpoint)
    except Exception as exc:
        # This existing wrapper emits sanitized reasons, not remote payloads.
        detail = _plans()._sanitize_member_task_text(str(exc)) if isinstance(exc, RuntimeError) else _safe_error(exc)
        return _review(f"{detail} ；操作 ID {target['operation_id']}")
    return _result("advance", next_step="done", updates={"context": {"left_at": _iso(_now())}})


def _deleted_child_result(job: dict) -> dict | None:
    from services import nv_automation_store as store
    if job.get("status") == "cancelled":
        return _result("cancelled", error=store.DELETED_CHILD_REASON)
    if not job.get("email") or not (job.get("child_id") or job.get("membership_id")):
        return None
    with Session(_plans().engine) as session:
        reason = store.deleted_child_reason(session, job)
    return _result("cancelled", error=reason) if reason else None


def _assert_retry_target(job: dict) -> None:
    """No-attempt evidence does not authorize a changed account identity."""
    if job.get("membership_id"):
        _member(job, allow_ended=job.get("step") == "leave")
    elif job.get("child_id") and job.get("email"):
        _assert_parent(job)
        with Session(_plans().engine) as session:
            child = session.get(GptPlanAccountModel, _positive(job.get("child_id")))
            if child is None or _email(child.email) != _email(job.get("email")):
                raise HTTPException(409, "自动售号子号身份已变化，不能重试原任务")


def execute_step(job_dict: dict, emit: Callable, checkpoint: Callable | None = None) -> dict:
    """Execute one durable step, with at most one canonical remote mutation."""
    job = {**job_dict, "context": _context(job_dict)}
    step = str(job.get("step") or "")
    try:
        if step == "dead_cleanup":
            from services.nv_dead_child_cleanup_capabilities import execute
            return execute(job, emit, checkpoint)
        if (step == "oauth" and _context(job).get("oauth_reconcile_only") is True
                and _context(job).get("quota_rt_recovery") is not True):
            return _reconcile_saved_oauth_readonly(job, emit, checkpoint)
        deleted = _deleted_child_result(job)
        if deleted is not None:
            return deleted
        if step == "select":
            return _select(job, checkpoint)
        if step == "invite":
            return _invite(job, emit, checkpoint)
        if step in {"security", "oauth"}:
            return _security_or_oauth(job, emit, checkpoint)
        if step == "publish":
            return _publish(job, emit, checkpoint)
        if step == "renew":
            from services.nv_listing_renewal import execute
            return execute(job, emit, checkpoint)
        if step in {"wait_sale", "wait_warranty"}:
            return _reconcile_nv(job, nexusvault.fetch_sales_snapshot(include_inventory=True))
        if step == "leave":
            return _leave(job, emit, checkpoint)
        if step == "done":
            return _result("advance", next_step="done")
        return _result("failed", error="未知自动售号步骤")
    except Exception as exc:
        dead = _child_deactivation_result(job, exc)
        if dead is not None:
            return dead
        if step == "invite":
            from services.nv_invite_preparation import unsent_preparation
            if unsent_preparation(job, _context(job)):
                return _result("wait", delay=300,
                    error="邀请前准备暂未完成，未发送邀请；将自动检查已保存结果后继续：" + _safe_error(exc))
        from services.nv_publish_preflight import unsent_preflight
        preflight_read_error = (isinstance(exc, nexusvault.NexusVaultRequestError)
                               or isinstance(exc, HTTPException) and exc.status_code == 409
                               and exc.detail == "NV 库存/出库分页未完整确认，不能创建上架基线")
        if preflight_read_error and step == "publish" and unsent_preflight(job, _context(job)):
            proof = {**(_context(job).get("publish_preflight") or {}),
                     "version": 1, "status": "failed", "remote_publish_sent": False,
                     "finished_at": _iso(_now()), "error": _safe_error(exc)}
            return _result("wait", delay=60, error="上架前 NV 只读检查失败，尚未提交账号；将自动重试：" + _safe_error(exc),
                           updates={"context": {"publish_attempted": False, "publish_preflight": proof,
                                                 "task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}}})
        if isinstance(exc, nexusvault.NexusVaultRequestError):
            if step in {"wait_sale", "wait_warranty"} or (step == "leave" and not _context(job).get("leave_attempted")):
                return _result("wait", delay=60, error="NV 只读核对暂未完成：" + _safe_error(exc))
        if step == "security":
            detail = _safe_error(exc)
            current = normalize_security_progress(_context(job).get("security_progress")) or {}
            browser_timeout = (isinstance(exc, TimeoutError) and current.get("stage") == "session_check"
                               and current.get("code") == "browser_init_started" and not current.get("completed_stages"))
            if browser_timeout:
                detail = "浏览器初始化等待超时，需核验旧进程结束后再检查账号安全状态"
            progress = _terminal_security_progress(
                job,
                detail,
                status="review",
                code="browser_init_timeout" if browser_timeout else "security_failed",
            )
            return _result("review", error=detail + "；请人工核对，未自动重试", updates={
                "context": _security_progress_update(progress),
            })
        return _review(_safe_error(exc))


def _reassess_existing_member(job: dict, checkpoint: Callable | None) -> dict | None:
    """Explicit recovery can fill missing initial evidence, never rebind a cycle."""
    context = _context(job)
    if job.get("step") == "security":
        from services.nv_security_recovery import security_has_history
        if security_has_history(context):
            return None
    if context.get("existing_member") is not True or any(context.get(key) for key in (
        "invite_attempted", "security_attempted", "oauth_attempted", "publish_attempted", "leave_attempted",
        "invite_started_at", "security_started_at", "oauth_started_at", "publish_started_at", "leave_started_at",
        "invite_started", "security_started", "oauth_started", "nv_publish_started", "leave_started", "leave_target",
        "publish_confirmed", "nv_remote_card_id", "nv_remote_order_id", "sold_at", "sale_verified_at",
        "oauth_failure", "oauth_retry_ready", "oauth_execution_attempts",
    )):
        return None
    old_listing = context.get("existing_listing")
    # Complete historical evidence is already frozen, even before its first scan.
    if old_listing is not None and not _existing_listing_error(job):
        return None
    rows = [row for row in discover_existing_children(_settings(job))
            if row["membership_id"] == job.get("membership_id")]
    if len(rows) != 1:
        return _review("当前已接管成员不在原母号管理范围或已退出，不能重新绑定")
    candidate = rows[0]
    if any(candidate.get(key) != job.get(key) for key in (
        "parent_account_id", "source_account_id", "parent_email", "child_id", "email", "membership_id",
    )):
        return _review("已有成员的冻结归属已变化，不能重新绑定")
    if job.get("remote_user_id") and candidate["remote_user_id"] != job["remote_user_id"]:
        return _review("已有成员的正式远端身份已变化，不能重新绑定")
    new_context = candidate["context"]
    if context.get("membership_invited_at") and context["membership_invited_at"] != new_context.get("membership_invited_at"):
        return _review("已有成员邀请周期已变化，不能重新绑定")
    if context.get("existing_invite_id") and not candidate["remote_user_id"] and context["existing_invite_id"] != new_context.get("existing_invite_id"):
        return _review("已有成员邀请身份已变化，不能重新绑定")
    if isinstance(old_listing, dict):
        new_listing = new_context.get("existing_listing")
        if not isinstance(new_listing, dict):
            return _review("已有售后记录不能降级成新的上架流程")
        for key, value in old_listing.items():
            if key == "warranty_hours":
                known = isinstance(value, int) and not isinstance(value, bool) and value > 0
            else:
                known = value not in (None, "", 0)
            if known and new_listing.get(key) != value:
                return _review("已有上架记录的已知周期、身份或质保发生变化，不能覆盖原证据")
    if candidate["status"] == "review":
        return _review(candidate["error"])
    updates = {key: candidate[key] for key in ("remote_user_id", "seat_type", "context")}
    _checkpoint(job, updates, checkpoint)
    return _result("advance", next_step=candidate["step"], updates=updates)


def reconcile_step(job_dict: dict, emit: Callable, checkpoint: Callable | None = None) -> dict:
    """Recovery never reissues invite/upload/browser/delete side effects."""
    job = {**job_dict, "context": _context(job_dict)}
    step = str(job.get("step") or "")
    try:
        if step == "dead_cleanup":
            from services.nv_dead_child_cleanup_capabilities import execute
            return execute(job, emit, checkpoint, reconcile=True)
        if step == "renew":
            from services.nv_listing_renewal import execute
            return execute(job, emit, checkpoint, reconcile=True)
        if (step == "oauth" and _context(job).get("oauth_reconcile_only") is True
                and _context(job).get("quota_rt_recovery") is not True):
            return _reconcile_saved_oauth_readonly(job, emit, checkpoint)
        deleted = _deleted_child_result(job)
        if deleted is not None:
            return deleted
        reassessed = _reassess_existing_member(job, checkpoint)
        if reassessed is not None:
            return reassessed
        if step == "security":
            # Terminal failure handlers intentionally clear the in-flight
            # marker. It is not evidence that setup never ran. Always inspect
            # completion/history/permissions before considering a new launch.
            return _security_or_oauth(job, emit, checkpoint, reconcile=True)
        if step == "oauth" and (_context(job).get("oauth_retry_ready") is True
                or _context(job).get("oauth_failure") is not None):
            # A cleared marker following a proven failure is not a first
            # attempt. Recheck the saved evidence, budget and fee permission.
            return _security_or_oauth(job, emit, checkpoint, reconcile=True)
        if step == "leave" and _context(job).get("leave_preflight"):
            # Preserve the typed preflight's backoff and canonical no-mutation
            # proof instead of the generic 30-second retry below.
            return _leave(job, emit, checkpoint, reconcile=True)
        stage_retry_mode = None
        if step in {"invite", "publish", "leave"}:
            from services.nv_automation_store import _stage_retry_mode
            with Session(_plans().engine) as session:
                stage_retry_mode = _stage_retry_mode(job, session)
        if (step in {"invite", "publish", "leave"} and stage_retry_mode == "retry"
                or step in {"security", "oauth"} and _context(job).get(f"{step}_attempted") is False):
            _assert_retry_target(job)
            # Only an explicit, internally consistent no-send checkpoint is a
            # no-op. Missing markers or contradictory remote-started evidence
            # must not turn into a fresh write on the next scheduling cycle.
            updates = {"context": {"task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}}}
            if step == "publish":
                from services.nv_publish_preflight import unsent_preflight
                if unsent_preflight(job, _context(job)):
                    return _result("wait", delay=5, error="已确认上次未提交账号，将自动重新执行 NV 上架预检", updates=updates)
            return _result("retry", delay=30, error="本步骤尚未发起远端操作，可从当前步骤继续", updates=updates)
        if step == "select":
            from services.nv_automation_store import _stage_retry_mode
            if _stage_retry_mode(job) == "reconcile":
                return _review("选择阶段包含后续操作记录，需先核对原账号流程，未重新选择子号")
            return _result("retry", delay=30, error="等待重新选择可用子号")
        if step == "invite":
            updates = _invited_member(job)
            return _result("advance", next_step="security", updates=updates) if updates else _review("未确认本次邀请的新成员记录")
        if step in {"security", "oauth"}:
            return _security_or_oauth(job, emit, checkpoint, reconcile=True)
        if step in {"publish", "wait_sale", "wait_warranty"}:
            if step in {"wait_sale", "wait_warranty"} and _context(job).get("quota_rt_recovery") is True:
                # A revoked RT must not block a sale that has already reached
                # its warranty-plus-delay deadline.  Quota repair remains a
                # best-effort background task before the deadline; once due,
                # hand the job to the normal leave worker immediately and let
                # its identity/evidence fence decide whether DELETE is safe.
                quota_context = _context(job)
                _enabled, delay_hours = _live_exit_settings(job, quota_context)
                deadline = auto_exit_at(quota_context.get("warranty_until"), delay_hours)
                if deadline is not None and deadline <= _now():
                    return _result("advance", next_step="leave", updates={
                        "context": {"quota_rt_recovery": False}
                    })
                # Keep the sold lifecycle step (and its exit countdown) while
                # borrowing the mother-page child OAuth implementation solely
                # to repair the rejected RT.
                return _security_or_oauth({**job, "step": "oauth"}, emit, checkpoint, reconcile=False)
            return _reconcile_nv(job, nexusvault.fetch_sales_snapshot(include_inventory=True))
        if step == "leave":
            return _leave(job, emit, checkpoint, reconcile=True)
        if step == "done":
            return _result("advance", next_step="done")
        return _result("failed", error="未知自动售号恢复步骤")
    except Exception as exc:
        dead = _child_deactivation_result(job, exc)
        if dead is not None:
            return dead
        if step == "security":
            detail = _safe_error(exc)
            progress = _terminal_security_progress(
                job,
                detail,
                status="review",
                code="security_failed",
            )
            return _result("review", error=detail + "；请人工核对，未自动重试", updates={
                "context": _security_progress_update(progress),
            })
        return _review(_safe_error(exc))


def scan_sales(job_dicts: list[dict], emit: Callable) -> list[dict]:
    """One complete remote read serves all jobs, including the empty preflight."""
    started = time.monotonic()
    manual_only = bool(job_dicts) and all(_context(job).get("manual_sale") is True for job in job_dicts)
    snapshot = None if manual_only else nexusvault.fetch_sales_snapshot(include_inventory=True)
    if snapshot is not None and snapshot.inventory_complete is not True:
        raise nexusvault.NexusVaultRequestError("NV 库存/出库记录未完整读取，已暂停新邀请")
    emails = Counter(_email(job.get("email")) for job in job_dicts)
    results = []
    sold_targets = []
    for job in job_dicts:
        try:
            local_context = _context(job)
            manual_sale = local_context.get("manual_sale") is True and _date(local_context.get("sold_at")) is not None
            if manual_sale:
                # Manual sales have no NV card to reconcile. Preserve their
                # sale/warranty state and run only the credential-bound usage
                # probe, fenced to this child and membership identity.
                result = _result("wait", next_step="wait_warranty", updates={"context": {}})
                sold_targets.append((job, result, {
                    **{key: job.get(key) for key in ("child_id", "membership_id", "email", "remote_user_id")},
                    "status": "sold", "sold_at": local_context.get("sold_at"),
                    "nv_remote_card_id": local_context.get("nv_remote_card_id", "") or "",
                }))
            elif not _email(job.get("email")) or emails[_email(job.get("email"))] > 1:
                result = _review("多个自动任务指向同一邮箱，无法唯一确认销售周期")
            else:
                result = _reconcile_nv(job, snapshot)
                # Only a successful match from THIS NV scan authorizes the
                # optional usage read. A local sold label / same-email card
                # / stale context alone must never cause a credential query.
                context = result.get("updates", {}).get("context", {})
                if not context.get("nv_refund") and _date(context.get("sold_at")) is not None and _identifier(context.get("nv_remote_card_id")):
                    sold_targets.append((job, result, {**context, "status": "sold"}))
        except Exception as exc:
            result = _review(_safe_error(exc))
        result.update(job_id=job.get("id"), version=job.get("version"))
        results.append(result)
    # Per-account observations are independent of the sale/exit decision.
    # NV sales require this scan's card evidence; manual sales use their
    # locally confirmed sale timestamp and the same child/member credential
    # fence. Only a 401 may use the shared credential lease to refresh AT once;
    # a rejected RT is handed to the separately leased OAuth stage below.
    # The scan process has a 300s watchdog. Quota work must leave room for the
    # authoritative NV results to commit, including slow 401 refresh chains.
    _scan_sold_quotas(sold_targets, emit, deadline=min(started + 210, time.monotonic() + 90))
    # Finished orders remain financially auditable, but never reactivate a
    # historical member/job or authorize a second exit.
    if snapshot is not None and getattr(snapshot, "refund_records", ()):
        from services.nv_refunds import list_refund_targets, record_refund
        from services.nv_refund_policy import match_cycle_refund
        from services.nv_order_history import NvSaleOrder
        with Session(_plans().engine) as session:
            for target in list_refund_targets(session):
                try:
                    proof = match_cycle_refund(snapshot, check_inventory=False, **{key: target[key] for key in
                        ("email", "remote_order_id", "remote_card_id", "sold_at", "listed_at")})
                except ValueError:
                    continue
                if proof:
                    order = session.get(NvSaleOrder, target["sale_order_id"])
                    if order is not None:
                        record_refund(session, order, proof)
            session.commit()
    _log(emit, f"NV 完整读取完成，核对 {len(job_dicts)} 个自动售号任务")
    return results


def _scan_sold_quotas(targets: list[tuple[dict, dict, dict]], emit: Callable, *, deadline: float | None = None) -> None:
    if not targets:
        return
    from services.nv_sold_quota import (normalize_sold_quota, query_sold_quota, sold_quota_error,
                                       SoldQuotaDeactivated, _DEAD_RESULT_KEY)

    def read_one(job, evidence):
        try:
            observation = query_sold_quota(job, evidence)
            identity = {**job, "context": {**_context(job), **evidence}}
            return (normalize_sold_quota(observation, identity) or sold_quota_error(job, evidence, "query_error"), None)
        except SoldQuotaDeactivated as exc:
            identity = {**job, "context": {**_context(job), **evidence}}
            return normalize_sold_quota(exc.observation, identity), exc.proof
        except Exception:
            # Never let a quota failure invalidate confirmed NV sale evidence
            # or surface exception text containing credentials/provider data.
            return sold_quota_error(job, evidence, "query_error"), None

    deadline = deadline if deadline is not None else time.monotonic() + 90
    def previous_check(target):
        observation = _context(target[0]).get("sold_quota")
        checked = _date(observation.get("checked_at")) if isinstance(observation, dict) else None
        return checked or datetime.min.replace(tzinfo=timezone.utc)
    # Oldest / never checked first prevents a slow first page starving later
    # sold accounts on every NV scan. Deferred observations retain their age.
    queue = sorted(targets, key=previous_check)
    submitted = completed = 0
    with ThreadPoolExecutor(max_workers=min(3, len(queue)), thread_name_prefix="nv-sold-quota") as pool:
        futures = {}
        while submitted < len(queue) or futures:
            # Two bounded usage GETs and one refresh POST can take 60 seconds.
            # Do not prequeue tasks that may only start near the watchdog.
            while (submitted < len(queue) and len(futures) < 3
                   and time.monotonic() + 65 <= deadline):
                job, result, evidence = queue[submitted]
                futures[pool.submit(read_one, job, evidence)] = result
                submitted += 1
            if not futures:
                break
            finished, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in finished:
                result = futures.pop(future)
                observation, deactivation = future.result()
                if observation is not None:
                    result["updates"]["context"]["sold_quota"] = observation
                    if (observation.get("status") == "error"
                            and observation.get("error_code") == "refresh_rejected"):
                        # A revoked RT cannot be retried with the same grant.
                        # Move this sold account into the existing OAuth worker;
                        # it returns to wait_warranty after a fresh RT is saved.
                        result.update(
                            outcome="wait",
                            next_step="wait_warranty",
                            error="额度接口拒绝旧 RT，已进入售后阶段自动刷新 RT",
                        )
                        result["updates"]["context"].update({
                            "quota_rt_recovery": True,
                            "quota_rt_recovery_started_at": _iso(_now()),
                            "oauth_attempted": False,
                            "oauth_retry_ready": False,
                            "oauth_failure": None,
                            "oauth_failure_detail": "",
                            "task_retry": None,
                        })
                        result["quota_rt_recovery"] = True
                    if deactivation is not None:
                        # Keep this scan's verified sale facts, but do not
                        # turn a deactivated child's warranty into normal exit.
                        result["updates"]["context"]["child_deactivation"] = deactivation.evidence
                        result[_DEAD_RESULT_KEY] = deactivation
                        result.update(outcome="failed", next_step=deactivation.evidence["step"],
                                      error="OpenAI 已明确停用该子号，等待核对并清理关联")
                completed += 1
    _log(emit, f"已更新 {completed} 个已出售子号的额度查询状态；{len(queue) - submitted} 个等待下轮；未出售账号未额外查询")
