"""Credential-free display evidence; a disabled switch alone is not DEAD."""
from datetime import datetime, timezone


def mother_dead_status(parent, source=None):
    marked = [row for row in (parent, source)
              if row is not None and getattr(row, "dangerous", False) is True]
    timestamps = []
    for row in marked:
        value = getattr(row, "dangerous_detected_at", None)
        if isinstance(value, datetime):
            timestamps.append(value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                              else value.astimezone(timezone.utc))
    return {"is_dead": bool(marked),
            "dead_detected_at": min(timestamps).isoformat() if timestamps else None}
