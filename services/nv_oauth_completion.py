"""Ephemeral proof for completing OAuth after retained security recovery history.

This is not an authorization to run OAuth. It only allows an empty task member
ID to be enriched by the already-verified current membership. The proof travels
from the capability to the result transaction, never into logs or checkpoints.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re

from sqlmodel import select, func, or_

IDENTITY_KEYS = ("id", "parent_account_id", "source_account_id", "parent_email",
                 "child_id", "membership_id", "email", "remote_user_id", "seat_type")
CONTEXT_KEYS = ("oauth_started_at", "oauth_membership_invited_at", "membership_invited_at",
                "existing_member", "oauth_saved_reconcile_at", "oauth_reconcile_only")
MEMBER_KEYS = ("membership_id", "child_id", "email", "remote_user_id", "remote_invite_id",
               "seat_type", "membership_invited_at", "oauth_acquired_at", "oauth_credential_version")
COMPLETION_ERROR = "RT 结果写回核验未通过：当前成员身份、邀请周期或凭证已变化；未重新授权"


@dataclass(frozen=True)
class OAuthCompletionProof:
    identity: tuple = field(repr=False)
    context: tuple = field(repr=False)
    member: tuple = field(repr=False)


def completion_proof(job, member):
    return OAuthCompletionProof(
        tuple(job.get(key) for key in IDENTITY_KEYS),
        tuple((job.get("context") or {}).get(key) for key in CONTEXT_KEYS),
        tuple(member.get(key) for key in MEMBER_KEYS),
    )


def _utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if value.tzinfo is None:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value):
    parsed = _utc(value)
    return parsed.isoformat() if parsed else ""


def validate_completion(session, job, result):
    """Re-read all bindings under the result transaction before permitting enrichment."""
    from core.db import (GptPlanAccountModel as Account, GptBusinessAccountModel as Mother,
                         GptBusinessChildMembershipModel as Membership,
                         GptPlanAccountOperationLeaseModel as AccountLease,
                         ChatGptSecurityOperationLeaseModel as SecurityLease)

    def require(condition):
        if not condition:
            raise ValueError(COMPLETION_ERROR)

    proof = result.get("_oauth_completion")
    require(type(proof) is OAuthCompletionProof)
    context = json.loads(job.context_json or "{}")
    values = result.get("updates") or {}
    remote = values.get("remote_user_id")
    require(job.step == "oauth" and result.get("outcome") == "advance"
            and result.get("next_step") == "publish" and not job.remote_user_id
            and isinstance(remote, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", remote))
    require(proof.identity == tuple(getattr(job, key) for key in IDENTITY_KEYS)
            and proof.context == tuple(context.get(key) for key in CONTEXT_KEYS))
    require(all(key not in values or values[key] == getattr(job, key)
                for key in IDENTITY_KEYS if key != "remote_user_id"))
    additions = values.get("context") or {}
    require(all(key not in additions or additions[key] == context.get(key) for key in CONTEXT_KEYS))
    parent, source = session.get(Account, job.parent_account_id), session.get(Mother, job.source_account_id)
    child, member = session.get(Account, job.child_id), session.get(Membership, job.membership_id)
    email = lambda value: str(value or "").strip().casefold()
    require(parent is not None and source is not None and child is not None and member is not None)
    require(parent.source_pool == "gpt_business" and parent.source_account_id == source.id
            and parent.business_parent_id is None
            and email(parent.email) == email(source.email) == email(job.parent_email)
            and email(child.email) == email(member.email) == email(job.email)
            and email(job.email) != email(job.parent_email)
            and member.business_account_id == child.business_parent_id == source.id
            and member.pro_account_id == child.id and member.source == "pool"
            and member.ended_at is None and member.remote_user_id == remote and not member.remote_invite_id
            and member.seat_type in {"default", "prolite"}
            and member.seat_type == values.get("seat_type", job.seat_type) == job.seat_type)
    require(all(row.enabled and not row.dangerous and not row.policy_warning
                and not str(row.refund_status or "").strip() for row in (parent, child)))
    try:
        intent = json.loads(member.intent_payload_json or "{}")
    except (ValueError, TypeError):
        raise ValueError(COMPLETION_ERROR) from None
    require(intent == {} and not member.intent_remote_started and not member.end_reason
            and not member.replacement_pro_account_id and not member.replacement_email
            and not member.replacement_completed_at)
    now = datetime.now(timezone.utc)
    invited = _utc(context.get("oauth_membership_invited_at") or context.get("membership_invited_at"))
    started, acquired = _utc(context.get("oauth_started_at")), _utc(child.codex_rt_acquired_at)
    require(invited is not None and started is not None and acquired is not None
            and invited <= started <= acquired <= now and _utc(member.invited_at) == invited
            and (child.business_invited_at is None or _utc(child.business_invited_at) == invited))
    require(all(key not in context or _utc(context[key]) == invited
                for key in ("oauth_membership_invited_at", "membership_invited_at")))
    require(not context.get("oauth_saved_reconcile_at")
            or _utc(context["oauth_saved_reconcile_at"]) == acquired)
    require(all(str(value or "").strip() for value in
                (child.codex_access_token, child.codex_refresh_token, child.codex_id_token)))
    current = dict(membership_id=member.id, child_id=child.id, email=email(member.email),
        remote_user_id=member.remote_user_id, remote_invite_id=member.remote_invite_id or "",
        seat_type=member.seat_type, membership_invited_at=_iso(member.invited_at),
        oauth_acquired_at=_iso(child.codex_rt_acquired_at),
        oauth_credential_version=hashlib.sha256(json.dumps([
            child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
            child.codex_session_token,
        ]).encode()).hexdigest())
    require(proof.member == tuple(current.get(key) for key in MEMBER_KEYS))
    active = session.exec(select(Membership.id).where(Membership.ended_at == None,
        or_(Membership.pro_account_id == child.id, func.lower(func.trim(Membership.email)) == email(job.email)),
    )).all()
    require(active == [member.id])
    for model, identifiers in ((AccountLease, (child.id, parent.id)),
                               (SecurityLease, (email(child.email), email(parent.email)))):
        for identifier in identifiers:
            lease = session.get(model, identifier)
            require(lease is None or (_utc(lease.expires_at) is not None and _utc(lease.expires_at) <= now))
    return remote
