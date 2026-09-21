"""Local safety checks for deleting an explicitly deactivated, unused candidate.

The caller owns the account deletion transaction. This module never contacts a
provider, removes a remote member, or deletes automation/order audit records.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from sqlalchemy import inspect, or_, func
from sqlmodel import select

from core.db import GptBusinessAccountModel, GptBusinessChildMembershipModel


def candidate_cleanup_block_reason(session, account) -> str:
    """Fail closed if this identity could own a subscription or remote resource."""
    account_id = int(account.id)
    email = str(account.email or "").strip().lower()
    if (str(account.catalog_category or "").strip().lower() not in {"", "regular"}
            or str(account.plan_type or "").strip().lower() not in {"", "free", "chatgptfreeplan"}
            or str(account.source_pool or "").strip().lower() == "gpt_business"
            or account.is_pro or str(account.refund_status or "").strip()
            or account.subscribed_at is not None or account.pro_expires_at is not None):
        return "not_regular_candidate"
    if session.exec(select(GptBusinessAccountModel.id).where(
        func.lower(func.trim(GptBusinessAccountModel.email)) == email,
    ).limit(1)).first() is not None:
        return "mother_account"
    if account.business_invited_at is not None:
        return "previously_invited"
    if session.exec(select(GptBusinessChildMembershipModel.id).where(or_(
        GptBusinessChildMembershipModel.pro_account_id == account_id,
        func.lower(func.trim(GptBusinessChildMembershipModel.email)) == email,
    )).limit(1)).first() is not None:
        return "membership_history_exists"
    try:
        extra = json.loads(account.extra_json or "{}")
    except (TypeError, ValueError):
        return "account_metadata_unknown"
    if not isinstance(extra, dict):
        return "account_metadata_unknown"
    if any(extra.get(key) for key in (
        "cpa_synced", "cpa_synced_to_id", "cpa_device_id", "cpa_auth_name",
        "cpa_sync_pending", "cpa_cleanup_pending", "sub2api_synced",
        "sub2api_device_id", "sub2api_remote_account_id", "sub2api_sync_pending",
        "delivery_replacement_pending", "business_device_binding",
        "nv_remote_card_id", "nv_remote_order_id", "nv_listing_confirmed_at",
    )):
        return "remote_resource_linked"

    # Optional modules have their own tables; inspecting on this connection
    # avoids initializing a service or creating a schema during cleanup.
    schema = inspect(session.connection())
    if schema.has_table("chatgpt_security_operation_leases"):
        from core.db import ChatGptSecurityOperationLeaseModel

        if session.exec(select(ChatGptSecurityOperationLeaseModel.email).where(
            func.lower(func.trim(ChatGptSecurityOperationLeaseModel.email)) == email,
            ChatGptSecurityOperationLeaseModel.expires_at > datetime.now(timezone.utc),
        ).limit(1)).first() is not None:
            return "operation_busy"
    if schema.has_table("nv_sale_orders"):
        from services.nv_order_history import NvSaleOrder

        if session.exec(select(NvSaleOrder.id).where(or_(
            NvSaleOrder.child_id == account_id,
            func.lower(func.trim(NvSaleOrder.email)) == email,
        )).limit(1)).first() is not None:
            return "sale_order_exists"
    if schema.has_table("nv_automation_jobs"):
        from services.nv_automation_store import NvAutomationJob, TERMINAL_STATUSES

        jobs = session.exec(select(NvAutomationJob).where(or_(
            NvAutomationJob.child_id == account_id,
            NvAutomationJob.active_child_key == str(account_id),
            func.lower(func.trim(NvAutomationJob.email)) == email,
        ))).all()
        for job in jobs:
            if job.status not in TERMINAL_STATUSES or job.active_child_key is not None:
                return "nv_job_active"
            try:
                context = json.loads(job.context_json or "{}")
            except (TypeError, ValueError):
                return "nv_job_evidence_unknown"
            if not isinstance(context, dict):
                return "nv_job_evidence_unknown"
            if job.membership_id is not None or str(job.remote_user_id or "").strip() or any(
                context.get(key) for key in (
                    "invite_attempted", "invite_confirmed", "remote_member_id", "existing_member",
                    "existing_invite_id", "nv_publish_started", "nv_publish_confirmed",
                    "nv_remote_card_id", "nv_remote_order_id", "publish_attempted", "publish_confirmed",
                )
            ):
                return "nv_remote_identity_exists"
    if schema.has_table("gpt_plan_preparation_jobs"):
        from services.gpt_plan_preparation_store import PreparationJob, BUSY

        if session.exec(select(PreparationJob.id).where(
            PreparationJob.account_id == account_id,
            PreparationJob.status.in_(BUSY),
        ).limit(1)).first() is not None:
            return "preparation_job_active"
    if schema.has_table("gpt_plan_preparations"):
        from services.gpt_plan_preparation_store import GptPlanPreparationModel, BUSY

        preparation = session.get(GptPlanPreparationModel, account_id)
        if preparation is not None and preparation.state in BUSY:
            return "preparation_job_active"
    return ""


def detach_candidate_preparation(session, account_id: int) -> None:
    """Remove readiness and archive terminal references without removing audit."""
    schema = inspect(session.connection())
    if schema.has_table("gpt_plan_preparations"):
        from services.gpt_plan_preparation_store import GptPlanPreparationModel

        preparation = session.get(GptPlanPreparationModel, account_id)
        if preparation is not None:
            session.delete(preparation)
    if schema.has_table("gpt_plan_preparation_jobs"):
        from services.gpt_plan_preparation_store import PreparationJob

        for job in session.exec(select(PreparationJob).where(PreparationJob.account_id == account_id)).all():
            job.account_id = -account_id
            session.add(job)
    if schema.has_table("nv_automation_jobs"):
        from services.nv_automation_store import NvAutomationJob

        for job in session.exec(select(NvAutomationJob).where(NvAutomationJob.child_id == account_id)).all():
            # The safety check already rejected active jobs/reservations. Keep
            # terminal status, email, context, steps and logs as immutable audit.
            job.child_id = -account_id
            session.add(job)
