"""Display-only checkpoints inside the canonical, single invitation operation.

These markers never grant permission to retry or send an invitation. The
existing mutation fence and canonical no-send evidence remain authoritative.
"""
from datetime import datetime

from services.business_invite_login_diagnostics import normalize_prelogin_failure


def _get(job, key, default=None):
    return job.get(key, default) if isinstance(job, dict) else getattr(job, key, default)


def normalize_invite_progress(value, job, *, require_operation=False):
    if not isinstance(value, dict):
        return None
    if value.get("phase") not in {"verify_child", "send_invite"} or value.get("state") not in {"running", "completed", "failed"}:
        return None
    if "verification_completed" in value and type(value["verification_completed"]) is not bool:
        return None
    child_id = value.get("child_id")
    email = str(value.get("email") or "").strip().lower()
    if (type(child_id) is not int or child_id <= 0 or child_id != _get(job, "child_id")
            or not email or email != str(_get(job, "email", "") or "").strip().lower()):
        return None
    operation = value.get("operation_id")
    if (not isinstance(operation, str) or not operation
            or (require_operation and operation != _get(job, "operation_id"))):
        return None
    updated_at = value.get("updated_at")
    try:
        if not isinstance(updated_at, str) or datetime.fromisoformat(updated_at.replace("Z", "+00:00")).tzinfo is None:
            return None
    except (ValueError, TypeError):
        return None
    return {"phase": value["phase"], "state": value["state"], "child_id": child_id,
            "email": email, "operation_id": operation, "updated_at": updated_at,
            "verification_completed": value.get("verification_completed") is True}


def public_invite_display(job, context):
    step = _get(job, "step", "")
    progress = normalize_invite_progress(context.get("invite_progress"), job,
                                        require_operation=step == "invite")
    failure = normalize_prelogin_failure(context.get("invite_failure"))
    if progress is not None:
        progress = {key: value for key, value in progress.items() if key != "operation_id"}
    if step != "invite":
        return step, progress
    from services.nv_invite_preparation import normalize_preparation
    if normalize_preparation(context.get("invite_preparation"), job) and not progress:
        return "verify_child", None
    # An explicit no-send failure from old workers locates the failure even
    # though they had no structured progress callback. Never infer success.
    if failure is not None or (progress and progress["phase"] == "verify_child"):
        return "verify_child", progress
    if context.get("invite_attempted") is False and progress is None:
        return "verify_child", None
    return "invite", progress


def invite_display_label(step, progress):
    if step == "verify_child":
        return "验证子号状态"
    if step == "invite":
        return "发送邀请" if progress and progress["phase"] == "send_invite" else "核验 / 邀请（阶段待确认）"
    return None


def project_invite_steps(rows, job, public):
    """Split the latest invite ledger for presentation, not execution history."""
    result = []
    progress = public.get("invite_progress")
    timing = public.get("invite_timing") if isinstance(public.get("invite_timing"), dict) else {}
    verifying = public.get("display_step") == "verify_child"
    proof = bool(progress and progress["phase"] == "send_invite" and progress["verification_completed"])
    for row in rows:
        preparation = public.get("invite_preparation")
        if row["step"] != "invite":
            if row["step"] == "security" and preparation:
                row = {**row, "label": "安全状态复核"}
            result.append(row)
            continue
        active = _get(job, "step") == "invite"
        state = _get(job, "status")
        verify_status = (state if active and verifying and not proof else "completed" if proof
                         else "pending" if _get(job, "step") == "select" else "unknown")
        verify_started = timing.get("invite_verification_started_at")
        verify_finished = timing.get("invite_verification_finished_at")
        verify_note = ""
        if preparation:
            verify_started = preparation["started_at"]
            verify_finished = preparation["finished_at"]
            verify_status = ("completed" if preparation["status"] == "completed"
                             else state if active else preparation["status"])
        if verify_status == "completed" and not (verify_started or verify_finished):
            # Older jobs predate the structured timing checkpoints. Their
            # completed status is still authoritative, but the UI must say
            # that the timestamps are unavailable instead of showing blanks
            # that look like an unexecuted step.
            verify_note = "已完成（时间未记录）"
        result.append(dict(step="verify_child", label="登录验证 + 密码/2FA" if preparation else "验证子号状态", status=verify_status,
                           attempts=None, error=preparation.get("error", "") if preparation else row["error"] if active and verifying else "",
                           started_at=verify_started, finished_at=verify_finished,
                           timing_note=verify_note, display_only=True))
        result.append({**row, "label": "发送邀请", **({"status": "pending", "error": "", "started_at": None,
                       "finished_at": None} if active and verifying else {})})
    return result
