"""Identity-bound, credential-free evidence for preparation before invitation."""
from datetime import datetime

from services.chatgpt_security_progress import normalize_security_progress, _safe_reason

STAGES = {"queued", "cookie_check", "login", "security", "verify", "ready"}


def normalize_preparation(value, job):
    if not isinstance(value, dict):
        return None
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    email = str(value.get("email") or "").strip().casefold()
    if (type(value.get("child_id")) is not int or value["child_id"] <= 0
            or value["child_id"] != get("child_id") or not email
            or email != str(get("email") or "").strip().casefold()
            or value.get("stage") not in STAGES
            or value.get("status") not in {"running", "completed", "failed"}):
        return None
    result = {key: value[key] for key in ("child_id", "stage", "status")}
    result["email"] = email
    dates = {}
    for key in ("started_at", "updated_at", "finished_at"):
        raw = value.get(key)
        if key == "finished_at" and raw is None:
            result[key] = None
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00")) if isinstance(raw, str) else None
            if parsed is None or parsed.tzinfo is None:
                return None
        except (ValueError, TypeError):
            return None
        result[key] = parsed.isoformat()
        dates[key] = parsed
    if (dates["updated_at"] < dates["started_at"] or
            "finished_at" in dates and not dates["started_at"] <= dates["finished_at"] <= dates["updated_at"]):
        return None
    for key in ("security_confirmed", "registered_verified"):
        result[key] = value.get(key) is True
    if result["status"] == "completed" and not (
            result["stage"] == "ready" and result["security_confirmed"]
            and result["registered_verified"] and result["finished_at"]):
        return None
    result["error"] = _safe_reason(value.get("error"))[:500]
    result["confirmed_dead"] = value.get("confirmed_dead") is True and result["status"] == "failed"
    result["security_progress"] = normalize_security_progress(value.get("security_progress"))
    return result


def unsent_preparation(job, context):
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    return (get("step") == "invite"
            and not get("membership_id") and not get("remote_user_id")
            and context.get("invite_attempted") is False
            and not any(context.get(key) for key in (
                "invite_started_at", "invite_confirmed", "existing_member", "existing_invite_id"))
            and normalize_preparation(context.get("invite_preparation"), job) is not None)
