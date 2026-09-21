"""Use the mother's persisted invitation deadline for local task scheduling."""
from datetime import datetime, timezone
import math


def cooldown_wait_seconds(cooldown, *, default=600, now=None):
    if not isinstance(cooldown, dict) or cooldown.get("active") is False:
        return default
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    value = cooldown.get("until") or cooldown.get("resume_at")
    if isinstance(value, str) and value:
        try:
            until = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            return max(5, min(86400, math.ceil((until - current).total_seconds())))
        except (ValueError, OverflowError):
            pass
    remaining = cooldown.get("remaining_seconds")
    if type(remaining) is int and remaining >= 0:
        return max(5, min(86400, remaining))
    return default
