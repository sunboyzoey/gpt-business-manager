"""Validate explicit Team 5x warranty terms for the NV listing contract.

NV accepts only an absolute ``until`` deadline. A locally configured duration
is resolved once by the publishing workflow; persisted terms must be reused on
retries instead of extending the warranty each time.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation


MAX_TEAM5X_WARRANTY_HOURS = 87600


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("NV 质保校验时间必须包含时区")
    return now.astimezone(timezone.utc)


def _normalize_hours(value: object) -> float:
    message = "Team 5x 质保时长须大于 0 且不超过 87600 小时，最多两位小数"
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError(message)
    try:
        amount = Decimal(str(value))
        if (not amount.is_finite() or amount <= 0 or amount > MAX_TEAM5X_WARRANTY_HOURS
                or amount != amount.quantize(Decimal("0.01"))):
            raise ValueError(message)
    except (InvalidOperation, OverflowError) as exc:
        raise ValueError(message) from exc
    return float(amount)


def normalize_team5x_warranty(
    value: object, *, now: datetime | None = None, require_future: bool = True,
) -> dict | None:
    """Normalize a wire warranty, optionally accepting a historical deadline."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"mode", "until"}:
        raise ValueError("Team 5x 质保须为仅包含 mode 和 until 的对象")
    if value["mode"] != "until":
        raise ValueError("NV Team 5x 上架质保仅支持 mode=until")
    raw_until = value["until"]
    if not isinstance(raw_until, str) or not raw_until.strip():
        raise ValueError("Team 5x 质保截止时间须为带时区的 ISO 时间")
    try:
        deadline = datetime.fromisoformat(raw_until.strip().replace("Z", "+00:00"))
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise ValueError("missing timezone")
        deadline = deadline.astimezone(timezone.utc)
        # NV parses dates through JavaScript Date and returns millisecond
        # precision. Freeze the same value locally so a successful listing
        # cannot appear to have conflicting terms after the first read-back.
        deadline = deadline.replace(microsecond=(deadline.microsecond // 1000) * 1000)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Team 5x 质保截止时间须为带时区的 ISO 时间") from exc
    if require_future and deadline <= _utc_now(now):
        raise ValueError("Team 5x 质保截止时间必须晚于当前时间，请重新配置质保")
    return {"mode": "until", "until": deadline.isoformat(timespec="milliseconds")}


def validate_team5x_settings(settings: dict, *, now: datetime | None = None) -> dict:
    """Validate saved configuration without requiring terms to publish yet.

Unset fields remain unset. A historical but valid fixed deadline can be saved
so unrelated configuration changes remain possible; publishing checks expiry.
The returned mapping contains only the three Team 5x configuration fields.
"""
    if not isinstance(settings, dict):
        raise ValueError("Team 5x 质保配置须为对象")
    mode = settings.get("team5x_warranty_mode", "duration")
    if mode not in ("duration", "until"):
        raise ValueError("Team 5x 质保方式须为 duration 或 until")
    hours = settings.get("team5x_warranty_hours")
    if hours is not None:
        hours = _normalize_hours(hours)
    until = settings.get("team5x_warranty_until")
    if until is None or until == "":
        until = ""
    else:
        until = normalize_team5x_warranty(
            {"mode": "until", "until": until}, now=now, require_future=False,
        )["until"]
    return {
        "team5x_warranty_mode": mode,
        "team5x_warranty_hours": hours,
        "team5x_warranty_until": until,
    }


def resolve_team5x_warranty(settings: dict, *, now: datetime | None = None) -> dict:
    """Resolve explicit operator configuration to the future NV wire deadline."""
    values = validate_team5x_settings(settings, now=now)
    current = _utc_now(now)
    if values["team5x_warranty_mode"] == "duration":
        hours = values["team5x_warranty_hours"]
        if hours is None:
            raise ValueError("请先配置 Team 5x 上架质保时长（小时）")
        try:
            until = (current + timedelta(hours=hours)).isoformat()
        except OverflowError as exc:
            raise ValueError("Team 5x 质保截止时间超出有效日期范围") from exc
    else:
        until = values["team5x_warranty_until"]
        if not until:
            raise ValueError("请先配置 Team 5x 上架质保截止时间")
    return normalize_team5x_warranty({"mode": "until", "until": until}, now=current)
