"""Bounded adoption of old, pre-password login failures.

The vanished browser task is not reconstructed as a success. Durable per-job
stage/log evidence and unchanged first-password state allow only the original
security stage to retry under its existing account identity and attempt budget.
"""
import re

from sqlmodel import select

from services.chatgpt_security_progress import normalize_security_progress, normalize_task_retry


def is_legacy_pre_password_failure(context):
    """Recognize the old diagnostic family, never prove non-submission."""
    progress = normalize_security_progress(context.get("security_progress"))
    return bool(progress and progress["stage"] == "session_check" and progress["status"] == "failed"
                and progress["code"] == "security_failed"
                and normalize_task_retry(progress.get("task_retry")) == {
                    "strategy": "manual", "reason_code": "unknown_failure"}
                and (progress["reason"] == "登录会话未返回可核验的账号邮箱，未确认登录成功"
                     or re.fullmatch(r"未跳转到 OTP 页 \(当前 URL: \[链接已隐藏\]\)?", progress["reason"])))


def _queued_retry(context, job, status=None):
    """A grant can carry the old proof, but can never replace its log evidence."""
    from collections.abc import Mapping
    from services.nv_security_recovery import normalize_security_retry
    from services.nv_task_recovery import _date
    grant = normalize_security_retry(context.get("security_retry"), job)
    attempts = job.get("attempts") if isinstance(job, Mapping) else job.attempts
    if (not grant or grant["phase"] != "queued" or grant["prior_attempts"] != attempts
            or grant["source_task_id"] != context.get("canonical_task_id")
            or grant["source_task_id"] != context.get("security_task_id")
            or _date(grant["source_started_at"]) != _date(context.get("security_started_at"))
            or grant["credential_state"] != "pending" or grant["has_totp"] or grant["has_recovery_codes"]
            or grant["mfa_state"] not in {"not_configured", "disabled"}):
        return None
    if status is not None and (
            status.get("password_state") != grant["credential_state"]
            or any(status.get(key) != grant[key] for key in ("mfa_state", "has_totp", "has_recovery_codes"))
            or _date(status.get("updated_at")) != _date(grant["security_updated_at"])):
        return None
    return grant


def _pre_password_evidence(session, job, status, *, admitted=False):
    from services import nv_automation_store as store
    from services.nv_task_recovery import _date

    context = store._decode(job.context_json)
    progress = normalize_security_progress(context.get("security_progress"))
    started = _date(context.get("security_started_at"))
    task_id = context.get("security_task_id")
    task = re.fullmatch(r"gpt_plan_business_child_setup_security_(\d+)_(\d+)_(\d{13})_[a-f0-9]{8}",
                        str(task_id or ""))
    unknown = {"strategy": "manual", "reason_code": "unknown_failure"}
    grant = _queued_retry(context, job, status) if admitted else None
    expected_retry = ({"strategy": "verify_existing" if grant else "safe_resume", "reason_code": "controls_unavailable"}
                      if admitted else unknown)
    if admitted and context.get("security_retry") is not None and grant is None:
        return None
    if (not progress or progress["stage"] != "session_check" or progress["status"] != "failed"
            or progress["code"] != "security_failed" or progress["completed_stages"]
            or normalize_task_retry(progress.get("task_retry")) != unknown
            or normalize_task_retry(context.get("task_retry")) != expected_retry
            or context.get("security_attempted") is not False or not started
            or not task or task_id != context.get("canonical_task_id")
            or int(task[1]) != job.parent_account_id or int(task[2]) != job.child_id
            or abs(int(task[3]) / 1000 - started.timestamp()) > 30
            or status.get("credentials_readable") is not True or status.get("has_password") is not True
            or status.get("password_state") != "pending"
            or status.get("mfa_state") not in {"not_configured", "disabled"}
            or status.get("has_totp") is not False or status.get("has_recovery_codes") is not False):
        return None
    password_at, updated = _date(status.get("password_updated_at")), _date(status.get("updated_at"))
    if (not password_at or not updated or not started <= password_at <= updated
            or updated.timestamp() > job.updated_at + 5):
        return None
    reason = progress["reason"]
    missing_session = reason == "登录会话未返回可核验的账号邮箱，未确认登录成功"
    otp_entry = re.fullmatch(r"未跳转到 OTP 页 \(当前 URL: \[链接已隐藏\]\)?", reason) is not None
    if not missing_session and not otp_entry:
        return None
    if store.safe_message(status.get("last_error") or "") != store.safe_message(reason):
        return None
    logs = session.exec(select(store.NvAutomationLog.message).where(
        store.NvAutomationLog.job_id == job.id, store.NvAutomationLog.step == "security",
        store.NvAutomationLog.created_at >= started.timestamp(),
        store.NvAutomationLog.created_at <= job.updated_at + 5,
    ).order_by(store.NvAutomationLog.id).limit(501)).all()
    if not logs or len(logs) > 500:
        return None
    lines = [re.sub(r"^(?:\[\d{2}:\d{2}:\d{2}\]\s*){0,2}", "", line) for line in logs]
    # Require a new candidate created in this exact attempt, plus a terminal
    # failure. Any later password/TOTP phase or auth rejection vetoes adoption.
    if ("[账号安全] 注册密码已安全保存" not in lines
            or "[账号安全] 设置未完成：" + reason not in lines
            or any(any(marker in line for marker in (
                "account_deactivated", "account_deleted", "密码已提交", "密码提交", "密码表单",
                "补设密码", "密码设置邮件", "开始设置 Authenticator", "密钥已保存",
                "账号身份不一致", "身份与目标账号不一致", "密码不正确", "invalid password",
            )) for line in lines)):
        return None
    if missing_session and "[GPT PRO 登录] 读取登录会话暂未完成，未确认登录成功" not in lines:
        return None  # A real JSON response missing identity is not a read failure.
    if otp_entry and "[GPT PRO 登录] 3/5 等待 OTP 输入页" not in lines:
        return None
    return True


def retry_instruction(session, job, status):
    if _pre_password_evidence(session, job, status):
        return {"strategy": "safe_resume", "reason_code": "controls_unavailable"}
    return None


def requires_unsubmitted_password_evidence(job):
    context = job.get("context") or {}
    return bool(job.get("step") == "security" and is_legacy_pre_password_failure(context)
                and (context.get("security_retry") is not None
                     or normalize_task_retry(context.get("task_retry")) == {
                         "strategy": "safe_resume", "reason_code": "controls_unavailable"}))


def verified_unsubmitted_password(job):
    """Revalidate one admitted attempt before its worker clears old evidence.

    This is an in-process proof, not a new persisted retry grant or a public
    request field. The canonical child/security leases still own execution.
    """
    from sqlmodel import Session
    from services import nv_automation_store as store
    from services.chatgpt_security_store import _status
    from services.nv_task_recovery import Security, _date

    context = job.get("context") or {}
    if (not requires_unsubmitted_password_evidence(job) or not job.get("worker_token")
            or context.get("security_recovery")
            or context.get("security_retry") is not None and not _queued_retry(context, job)
            or context.get("security_attempted") is not False):
        return None
    with Session(store.engine) as session:
        current = session.get(store.NvAutomationJob, job.get("id"))
        if (current is None or current.status != "running" or current.pause_requested
                or current.worker_token != job["worker_token"]
                or any(getattr(current, field) != job.get(field) for field in (
                    "operation_id", "attempts", "parent_account_id", "source_account_id",
                    "child_id", "membership_id", "email", "parent_email"))):
            return None
        saved = store._decode(current.context_json)
        if any(saved.get(key) != context.get(key) for key in (
                "security_attempted", "security_started_at", "security_task_id",
                "canonical_task_id", "security_progress", "task_retry", "security_retry")):
            return None
        row = session.get(Security, str(current.email).strip().lower())
        if row is None:
            return None
        status = _status(row, str(current.email).strip().lower())
        if not _pre_password_evidence(session, current, status, admitted=True):
            return None
        # MFA has no timestamp before first enrollment. Preserve that exact
        # empty value; the receiver rechecks it under the security lease.
        mfa_updated = status.get("mfa_updated_at")
        if not isinstance(mfa_updated, str) or (mfa_updated and _date(mfa_updated) is None):
            return None
        from platforms.chatgpt.account_security import VerifiedUnsubmittedPasswordEvidence
        return VerifiedUnsubmittedPasswordEvidence(
            email=str(current.email).strip().lower(),
            security_updated_at=status["updated_at"],
            password_updated_at=status["password_updated_at"],
            mfa_updated_at=mfa_updated,
        )
