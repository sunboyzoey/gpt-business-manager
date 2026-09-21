"""Three sale policies; legacy settings expand only when a key is absent.

Ordinary TEAM window classification is evidence, never inferred from a missing
usage value. This module is pure configuration/selection, with no network IO.
"""
from __future__ import annotations

from services.nv_auto_exit_policy import normalize_auto_exit_delay_hours


TIERS = ("default_5h", "default_no_5h", "prolite")
TIER_LABELS = {"default_5h": "普通席位 · 有 5 小时限制",
               "default_no_5h": "普通席位 · 无 5 小时限制", "prolite": "Business Pro 5X"}
TIER_PRICE_KEYS = tuple(f"{tier}_price_yuan" for tier in TIERS)
TIER_DELAY_KEYS = tuple(f"{tier}_auto_exit_delay_hours" for tier in TIERS)
TIER_DEFAULTS = {**{key: "" for key in TIER_PRICE_KEYS}, **{key: 2.0 for key in TIER_DELAY_KEYS}}


def expand_legacy_tier_settings(values):
    result = dict(values)
    if "price_yuan" in result:
        result.setdefault("default_price_yuan", result["price_yuan"])
        result.setdefault("prolite_price_yuan", result["price_yuan"])
    if "default_price_yuan" in result:
        for tier in ("default_5h", "default_no_5h"):
            result.setdefault(f"{tier}_price_yuan", result["default_price_yuan"])
    if "auto_exit_delay_hours" in result:
        for key in TIER_DELAY_KEYS:
            result.setdefault(key, result["auto_exit_delay_hours"])
    return result


def price_for_tier(settings, tier):
    if tier not in TIERS:
        return None
    return expand_legacy_tier_settings(settings).get(f"{tier}_price_yuan") or None


def exit_delay_for_tier(settings, tier, seat_type=""):
    values = {**TIER_DEFAULTS, **expand_legacy_tier_settings(settings)}
    if tier in TIERS:
        return normalize_auto_exit_delay_hours(values[f"{tier}_auto_exit_delay_hours"])
    # The common legacy delay remains safe while a legacy child is waiting
    # for classification. Distinct policies never pick a guessed/shorter one.
    possible = ("default_5h", "default_no_5h") if seat_type == "default" else TIERS
    delays = {normalize_auto_exit_delay_hours(values[f"{key}_auto_exit_delay_hours"]) for key in possible}
    return next(iter(delays)) if len(delays) == 1 else None


def job_policy(job, context=None):
    from services.nv_account_tier import quota_tier_key
    value = job if isinstance(job, dict) else {key: getattr(job, key, None) for key in (
        "child_id", "membership_id", "email", "remote_user_id", "seat_type", "context_json",
    )}
    if context is None:
        import json
        context = value.get("context")
        if context is None:
            try:
                context = json.loads(value.get("context_json") or "{}")
            except (TypeError, ValueError):
                context = {}
    tier = quota_tier_key(value, context=context)
    label = TIER_LABELS.get(tier) or ("普通席位 · 5 小时限制待识别" if value.get("seat_type") == "default" else "席位档位待识别")
    return tier, label


def job_exit_delay(job, settings, context=None):
    from services.nv_job_exit_policy import job_exit_override
    override = job_exit_override(job, context)
    if override is not None:
        return override
    tier, _ = job_policy(job, context)
    seat_type = job.get("seat_type", "") if isinstance(job, dict) else job.seat_type
    # A 5X membership is itself the durable tier evidence. Manual-sale jobs
    # intentionally skip the NV quota read, so do not leave their delay as
    # unknown merely because there is no remote quota proof.
    if tier == "unknown" and seat_type == "prolite":
        tier = "prolite"
    return exit_delay_for_tier(settings, tier, seat_type)
