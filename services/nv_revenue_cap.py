"""Pure helpers for mother rotation revenue caps.

Revenue caps are evaluated against the immutable NV sale ledger.  This module
contains no database or network access so the scheduler, API and UI can share
the same validation and boundary semantics.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Iterable


REVENUE_CAP_KEYS = {
    "default": "default_revenue_cap_yuan",
    "prolite": "prolite_revenue_cap_yuan",
}
MAX_CAP_YUAN = Decimal("999999999.99")


def normalize_cap_yuan(value: Any) -> str:
    """Return a canonical non-negative CNY amount; an empty value means no cap."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return ""
    if isinstance(value, bool):
        raise ValueError("营收上限必须是非负金额")
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, AttributeError):
        raise ValueError("营收上限必须是非负金额") from None
    if not amount.is_finite() or amount < 0 or amount > MAX_CAP_YUAN:
        raise ValueError("营收上限必须在 0 至 999999999.99 元之间")
    return str(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def normalize_caps(settings: dict[str, Any] | None) -> dict[str, str]:
    settings = settings if isinstance(settings, dict) else {}
    return {tier: normalize_cap_yuan(settings.get(key, ""))
            for tier, key in REVENUE_CAP_KEYS.items()}


def evaluate_caps(
    revenue_cents: int | dict[str, int | None] | None,
    seat_types: Iterable[str] | None,
    settings: dict[str, Any] | None,
) -> dict[str, Any]:
    """Evaluate configured caps for a mother.

    ``revenue_cents`` is the received amount only (pending warranty orders are
    deliberately excluded by the caller).  A cap applies only when that seat
    type is present.  The comparison is inclusive: reaching the configured
    amount stops rotation, which avoids one extra sale at the boundary.
    """
    # A mixed mother may sell ordinary and Pro 5X seats concurrently.  Callers
    # can pass a per-tier mapping so one tier's sales never consume the other's
    # cap.  A scalar remains supported for legacy/single-tier mothers.
    per_tier = revenue_cents if isinstance(revenue_cents, dict) else None
    cents = max(0, int(revenue_cents or 0)) if per_tier is None else max(
        0, sum(max(0, int(value or 0)) for value in per_tier.values()))
    present = {str(value).strip().lower() for value in (seat_types or ())}
    result: dict[str, Any] = {"revenue_cents": cents, "revenue_yuan": f"{Decimal(cents) / 100:.2f}", "tiers": {}}
    blocked = False
    for tier, cap in normalize_caps(settings).items():
        applies = tier in present
        threshold = Decimal(cap) if cap else None
        tier_cents = max(0, int((per_tier or {}).get(tier) or 0)) if per_tier is not None else cents
        exceeded = bool(applies and threshold is not None and Decimal(tier_cents) / 100 >= threshold)
        result["tiers"][tier] = {
            "applies": applies,
            "threshold_yuan": cap or None,
            "current_yuan": f"{Decimal(tier_cents) / 100:.2f}",
            "exceeded": exceeded,
        }
        blocked = blocked or exceeded
    result["rotation_blocked"] = blocked
    result["blocked_tiers"] = [tier for tier, item in result["tiers"].items() if item["exceeded"]]
    return result
