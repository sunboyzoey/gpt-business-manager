"""NV automatic release timing; manual membership actions do not use this rule.

The warranty and receipt deadlines retain their original meaning. This grace
period only delays the automatic workspace exit, including already queued jobs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation


AUTO_EXIT_GRACE_SECONDS = 2 * 60 * 60
DEFAULT_AUTO_EXIT_DELAY_HOURS = 2
MAX_AUTO_EXIT_DELAY_HOURS = 168


def normalize_auto_exit_delay_hours(value: int | float | Decimal = DEFAULT_AUTO_EXIT_DELAY_HOURS) -> float:
    """Validate the live automatic-exit grace period without rounding it down.

    A malformed setting must not accidentally authorize an earlier deletion.
    JSON numbers (and internal Decimals) are accepted; booleans, strings,
    non-finite values and more than two effective decimal places are not.
    """
    message = "自动退出延迟须为 0–168 小时的数字，最多两位小数"
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError(message)
    try:
        amount = Decimal(str(value))
        if (not amount.is_finite() or amount < 0 or amount > MAX_AUTO_EXIT_DELAY_HOURS
                or amount != amount.quantize(Decimal("0.01"))):
            raise ValueError(message)
    except (InvalidOperation, OverflowError) as exc:
        raise ValueError(message) from exc
    return float(amount)


def auto_exit_at(warranty_until: datetime | str | None,
                 delay_hours: int | float | Decimal = DEFAULT_AUTO_EXIT_DELAY_HOURS) -> datetime | None:
    """Return a UTC deadline, or no permission when the warranty is unknown."""
    if not isinstance(warranty_until, (datetime, str)):
        return None
    try:
        deadline = (warranty_until if isinstance(warranty_until, datetime)
                    else datetime.fromisoformat(warranty_until.strip().replace("Z", "+00:00")))
        deadline = (deadline.replace(tzinfo=timezone.utc) if deadline.tzinfo is None
                    else deadline.astimezone(timezone.utc))
        return deadline + timedelta(hours=normalize_auto_exit_delay_hours(delay_hours))
    except (ValueError, TypeError, OverflowError):
        return None


def auto_exit_at_iso(warranty_until: datetime | str | None,
                     delay_hours: int | float | Decimal = DEFAULT_AUTO_EXIT_DELAY_HOURS) -> str | None:
    deadline = auto_exit_at(warranty_until, delay_hours)
    return deadline.isoformat() if deadline is not None else None
