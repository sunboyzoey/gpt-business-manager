"""Credential-free proof that a publish worker has not crossed its upload fence."""
from __future__ import annotations


def has_publish_evidence(context: dict) -> bool:
    return any(context.get(key) for key in (
        "publish_attempted", "publish_started_at", "publish_started", "publish_baseline",
        "publish_confirmed", "existing_listing", "nv_publish_started", "nv_publish_confirmed",
        "nv_remote_card_id", "nv_remote_order_id", "nv_card_id", "nv_order_id",
        "nv_listing_started_at", "nv_listed_at", "nv_listing_confirmed_at", "nv_confirmed_at",
        "nv_baseline_card_ids", "nv_baseline_order_ids", "nv_baseline_complete",
        "sold_at", "sale_verified_at", "sale_confirmed", "manual_sale",
        "nv_card_identity", "listing_cycle_id", "team5x_warranty", "warranty_until",
    ))


def normalize_preflight(value, job):
    if not isinstance(value, dict):
        return None
    get = job.get if isinstance(job, dict) else lambda k, d=None: getattr(job, k, d)
    if (value.get("version") != 1 or value.get("status") not in {"running", "failed"}
            or value.get("remote_publish_sent") is not False):
        return None
    for key in ("child_id", "membership_id"):
        if type(value.get(key)) is not int or value[key] <= 0 or value[key] != get(key):
            return None
    email = str(get("email") or "").strip().casefold()
    if not email or value.get("email") != email:
        return None
    from datetime import datetime
    try:
        datetime.fromisoformat(value["started_at"])
    except (ValueError, TypeError, KeyError):
        return None
    return {key: value[key] for key in (
        "version", "status", "remote_publish_sent", "child_id", "membership_id", "email",
        "started_at", "finished_at", "error",
    ) if key in value}


def unsent_preflight(job, context):
    get = job.get if isinstance(job, dict) else lambda k, d=None: getattr(job, k, d)
    return bool(get("step") == "publish" and context.get("publish_attempted") is False
                and not has_publish_evidence(context)
                and normalize_preflight(context.get("publish_preflight"), job))
