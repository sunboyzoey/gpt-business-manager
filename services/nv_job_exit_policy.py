"""Order-scoped exit choices. Only the store's explicit UI actions write these.

The private context keys are deliberately absent from worker checkpoint keys.
They bind to one member and one NV sale, never an email's later invitation.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from services.nv_auto_exit_policy import auto_exit_at, normalize_auto_exit_delay_hours


EXIT_DELAY_KEY = "_job_exit_delay_v1"
MANUAL_EXIT_KEY = "_manual_exit_v1"


def job_context(job, context=None):
    if context is not None:
        return context if isinstance(context, dict) else {}
    if isinstance(job, dict) and isinstance(job.get("context"), dict):
        return job["context"]
    raw = job.get("context_json") if isinstance(job, dict) else getattr(job, "context_json", "")
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _get(job, key):
    return job.get(key) if isinstance(job, dict) else getattr(job, key, None)


def normalized_exit_evidence(value):
    """Compare identity timestamps by instant, not their JSON spelling."""
    time_keys = {"membership_invited_at", "oauth_membership_invited_at", "publish_started_at",
                 "nv_listed_at", "nv_listing_confirmed_at", "listing_started_at", "sold_at"}
    if isinstance(value, dict):
        result = {}
        for key, nested in value.items():
            parsed = auto_exit_at(nested, 0) if key in time_keys else None
            result[key] = parsed.isoformat() if parsed is not None else normalized_exit_evidence(nested)
        return result
    if isinstance(value, list):
        return [normalized_exit_evidence(item) for item in value]
    return value


def _cycle_card_anchor(context, email):
    """An additional corroborated alias keeps the job's original card anchor.

    NV can first supply this proof during the final fresh read. It adds
    evidence, not a new sale. Existing proof replacement is independently
    forbidden by the store and by the live NV verifier.
    """
    card = context.get("nv_remote_card_id")
    proof = context.get("nv_card_identity")
    if proof is None:
        return card, True
    keys = {"kind", "email", "listing_started_at", "sold_at", "inventory_card_id",
            "order_card_id", "remote_order_id"}
    if not isinstance(proof, dict) or set(proof) != keys:
        return None, False
    identifier_keys = ("inventory_card_id", "order_card_id", "remote_order_id")
    if (proof["kind"] != "nv_card_identity_v1" or proof["email"] != email.strip().casefold()
            or any(not isinstance(proof[key], str) or not proof[key] or proof[key].strip() != proof[key]
                   for key in identifier_keys)
            or proof["remote_order_id"] != context.get("nv_remote_order_id")
            or card not in {proof["inventory_card_id"], proof["order_card_id"]}
            or not auto_exit_at(proof["listing_started_at"], 0)
            or auto_exit_at(proof["listing_started_at"], 0) != auto_exit_at(context.get("nv_listed_at"), 0)
            or not auto_exit_at(proof["sold_at"], 0)
            or auto_exit_at(proof["sold_at"], 0) != auto_exit_at(context.get("sold_at"), 0)):
        return None, False
    # The NV verifier preserves a job's already-bound nv_remote_card_id. It
    # might initially be either the inventory ID or the order-card ID. Do not
    # replace it merely because the fresh read adds a proof linking the two.
    return card, True


def exit_identity(job, context=None):
    """Freeze stable sale identity, excluding policy and changing check times."""
    context = job_context(job, context)
    identity = {key: _get(job, key) for key in (
        "id", "parent_account_id", "source_account_id", "parent_email", "child_id",
        "membership_id", "email", "remote_user_id",
    )}
    if (any(type(identity[key]) is not int or identity[key] <= 0 for key in
            ("parent_account_id", "source_account_id", "child_id", "membership_id"))
            or any(not isinstance(identity[key], str) or not identity[key].strip() for key in
                   ("id", "parent_email", "email", "remote_user_id"))):
        return None
    identity["cycle"] = {key: context.get(key) for key in (
        "listing_cycle_id", "membership_invited_at", "oauth_membership_invited_at",
        "publish_started_at", "nv_listed_at", "nv_remote_card_id", "nv_remote_order_id",
        "sold_at", "existing_listing",
    )}
    if context.get("manual_sale") is not True and (not context.get("sold_at") or not context.get("nv_listed_at")):
        return None
    card_anchor, valid_card = (None, True) if context.get("manual_sale") is True else _cycle_card_anchor(context, identity["email"])
    if not valid_card:
        return None
    identity["cycle"]["nv_remote_card_id"] = card_anchor or "manual-sale"
    identity = normalized_exit_evidence(identity)
    try:
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (ValueError, TypeError):
        return None
    return hashlib.sha256(raw.encode()).hexdigest()


def job_exit_override(job, context=None):
    context = job_context(job, context)
    record = context.get(EXIT_DELAY_KEY)
    identity = exit_identity(job, context)
    if not identity or not isinstance(record, dict) or record.get("identity") != identity:
        return None
    try:
        return normalize_auto_exit_delay_hours(record.get("hours"))
    except ValueError:
        return None


# Public spelling used by the execution layer; retain the policy-local alias.
exit_delay_override = job_exit_override


def manual_exit_requested_at(job, context=None):
    context = job_context(job, context)
    record = context.get(MANUAL_EXIT_KEY)
    if (not isinstance(record, dict) or not record.get("request_id")
            or not record.get("identity") or record.get("identity") != exit_identity(job, context)
            or job_exit_override(job, context) is None):
        return None
    try:
        value = datetime.fromisoformat(record["requested_at"].replace("Z", "+00:00"))
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo is not None else None
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


def manual_exit_authorized(job, context=None, *, now=None):
    """A scoped release request bypasses scheduling switches.

    NV sales also require warranty expiry here. Manual-sale timing is checked
    by the caller, with only exit-now allowed to waive its countdown. The lease
    and canonical membership checks remain required for every sale.
    """
    context = job_context(job, context)
    if (_get(job, "step") != "leave" or _get(job, "status") in {"completed", "cancelled"}
            or manual_exit_requested_at(job, context) is None):
        return False
    if context.get("manual_sale") is True:
        return True
    deadline = auto_exit_at(context.get("warranty_until"), job_exit_override(job, context))
    instant = datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now, timezone.utc)
    return bool(deadline and deadline <= instant)


def manual_sale_early_exit_authorized(job, context=None, *, now=None):
    """Only exit-now can waive a manual sale's countdown, not an auto marker."""
    context = job_context(job, context)
    record = context.get(MANUAL_EXIT_KEY)
    return bool(context.get("manual_sale") is True and isinstance(record, dict)
                and record.get("early_exit") is True
                and manual_exit_authorized(job, context, now=now))
