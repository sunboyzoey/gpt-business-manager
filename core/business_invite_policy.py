"""Shared BUSINESS invitation policy without a local count limit."""

BUSINESS_INVITE_WINDOW_HOURS = 30


def quota_for_seat(quota: dict, seat_type: str) -> dict:
    """Select exact typed evidence, retaining compatibility with old snapshots."""
    if seat_type not in {"default", "prolite"}:
        raise ValueError("未知的邀请席位类型")
    if not isinstance(quota, dict):
        return {}
    by_type = quota.get("by_type")
    if isinstance(by_type, dict):
        item = by_type.get(seat_type)
        return item if isinstance(item, dict) else {}
    if quota.get("seat_type") and quota["seat_type"] != seat_type:
        return {}
    return quota


def invitable_counts_by_type(typed_counts: dict | None, quota: dict) -> dict[str, int]:
    """Invitation admission is constrained only by real seat capacity."""
    def count(value):
        return max(0, value) if type(value) is int else 0
    typed_counts = typed_counts or {}
    return {kind: count(typed_counts.get(kind)) for kind in ("default", "prolite")}
