"""Credential-free evidence for NV's three local pricing/release categories.

An ordinary member is not "unlimited" merely because a quota read failed or a
field was absent. We only classify complete, successful quota windows. The
category concerns the five-hour window, not unlimited total model usage.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


TIERS = ("default_5h", "default_no_5h", "prolite")
TIER_LABELS = {
    "default_5h": "普通席位 · 有 5 小时限制",
    "default_no_5h": "普通席位 · 无 5 小时限制",
    "prolite": "Business Pro 5X",
    "unknown": "待核验 5 小时限制",
}


def _date(value: Any) -> datetime | None:
    try:
        value = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _identifier(value: Any) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else ""


def _email(value: Any) -> str:
    text = str(value or "").strip().casefold()
    return text if len(text) <= 320 and re.fullmatch(r"[^\s@]+@[^\s@]+", text) else ""


def windows_tier(windows_seconds: Any) -> str:
    """Never treat an empty/partial/invalid set of windows as absence of 5h."""
    if (not isinstance(windows_seconds, (list, tuple)) or not windows_seconds
            or len(windows_seconds) > 20
            or any(type(value) is not int or value <= 0 or value > 366 * 86400 for value in windows_seconds)):
        return "unknown"
    if 18000 in windows_seconds:
        return "default_5h"
    return "default_no_5h" if all(value > 18000 for value in windows_seconds) else "unknown"


def usage_windows(payload: Any) -> list[int] | None:
    """Read the exact successful wham rate-limit contract, never guess duration."""
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    rate = payload.get("rate_limit")
    if not isinstance(rate, dict) or not {"primary_window", "secondary_window"} <= set(rate):
        return None
    windows = []
    for name in ("primary_window", "secondary_window"):
        window = rate[name]
        if window is None:  # Explicitly absent is distinct from a missing key.
            continue
        if not isinstance(window, dict):
            return None
        seconds = window.get("limit_window_seconds")
        if type(seconds) is not int or seconds <= 0:
            return None
        windows.append(seconds)
    return windows if windows_tier(windows) != "unknown" else None


def nv_windows(quota: Any) -> list[int] | None:
    if (not isinstance(quota, dict) or quota.get("ok") is not True
            or quota.get("source") != "codex_usage" or _date(quota.get("updated_at")) is None
            or not isinstance(quota.get("windows"), dict) or not quota["windows"]):
        return None
    result = []
    for window in quota["windows"].values():
        value = window.get("window_minutes") if isinstance(window, dict) else None
        if type(value) not in (int, float) or value <= 0 or not float(value * 60).is_integer():
            return None
        result.append(int(value * 60))
    return result if windows_tier(result) != "unknown" else None


def normalize_quota_tier(value: Any, job: dict | None = None, *, now: datetime | None = None) -> dict | None:
    """Allowlist and bind a category proof to one exact child/membership.

    Token payloads, raw HTTP data and arbitrary nested strings never enter the
    durable context. A default proof cannot be reused for a different seat.
    """
    if not isinstance(value, dict) or value.get("schema") != "nv_quota_tier_v1":
        return None
    tier, source, seat = value.get("tier"), value.get("source"), value.get("seat_type")
    if tier not in TIERS or source not in {"openai_usage", "nv_card", "membership"}:
        return None
    if seat != ("prolite" if tier == "prolite" else "default"):
        return None
    checked = _date(value.get("verified_at"))
    observed = _date(value.get("observed_at") or value.get("verified_at"))
    current = _date(now) if now is not None else datetime.now(timezone.utc)
    if checked is None or observed is None or checked > current or observed > checked:
        return None
    child, membership = value.get("child_id"), value.get("membership_id")
    email, remote = _email(value.get("email")), _identifier(value.get("remote_user_id"))
    if (type(child) is not int or child <= 0 or type(membership) is not int or membership <= 0
            or not email or email != value.get("email") or not remote):
        return None
    if tier == "prolite":
        if source != "membership":
            return None
        durations: list[int] = []
    else:
        durations = value.get("windows_seconds")
        if source == "membership" or windows_tier(durations) != tier:
            return None
        durations = sorted(set(durations))
    clean = dict(schema="nv_quota_tier_v1", tier=tier, seat_type=seat, source=source,
                 verified_at=checked.isoformat(), observed_at=observed.isoformat(), child_id=child,
                 membership_id=membership, email=email, remote_user_id=remote,
                 windows_seconds=durations, five_hour_limited=(None if tier == "prolite" else tier == "default_5h"))
    if source == "openai_usage":
        workspace = _identifier(value.get("workspace_id"))
        if not workspace:
            return None
        clean["workspace_id"] = workspace
    if source == "nv_card":
        card_id = _identifier(value.get("remote_card_id"))
        if not card_id:
            return None
        clean["remote_card_id"] = card_id
    if job is not None:
        if (any(job.get(key) != clean[key] for key in ("child_id", "membership_id", "remote_user_id"))
                or _email(job.get("email")) != email
                or job.get("seat_type") not in {None, "", seat}):
            return None
    return clean


def quota_tier_key(job: dict, context: dict | None = None) -> str:
    context = context if isinstance(context, dict) else job.get("context")
    evidence = normalize_quota_tier(context.get("quota_tier"), job) if isinstance(context, dict) else None
    return evidence["tier"] if evidence else "unknown"


def make_quota_tier(job: dict, member: dict, *, source: str, windows_seconds: list[int] | None = None,
                    workspace_id: str = "", remote_card_id: str = "", observed_at: Any = None,
                    now: datetime | None = None) -> dict | None:
    current = now or datetime.now(timezone.utc)
    seat = member.get("seat_type")
    tier = "prolite" if seat == "prolite" else windows_tier(windows_seconds) if seat == "default" else "unknown"
    return normalize_quota_tier({
        "schema": "nv_quota_tier_v1", "tier": tier, "source": source,
        "seat_type": seat, "verified_at": current.isoformat(),
        "observed_at": observed_at or current.isoformat(),
        **{key: member.get(key) for key in ("child_id", "membership_id", "email", "remote_user_id")},
        "windows_seconds": windows_seconds or [], "workspace_id": workspace_id,
        "remote_card_id": remote_card_id,
    }, {**job, "seat_type": seat}, now=current)
