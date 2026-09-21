"""Read-only NV admission for a narrowly identified interrupted MFA setup.

This grants a fresh remote inspection, never permission to rebind MFA from
historical text. The canonical browser workflow must recheck the exact account
and explicitly disabled Authenticator before attempting enrollment.
"""
from collections.abc import Mapping
from datetime import datetime, timezone
import re

from services.chatgpt_security_progress import normalize_security_progress, normalize_task_retry
from services.chatgpt_security_recovery import can_inspect_pending_totp


_ENTRY_FAILURES = {
    "totp_authenticator_entry_missing": "未找到 Authenticator App 绑定入口",
    "totp_activation_entry_missing": "未找到 Authenticator 2FA 启用入口",
}
_SUPERSEDED_REASONS = {"unknown_failure", "remote_change_unverified"}
_INSPECTION_RETRY = {"strategy": "verify_existing", "reason_code": "controls_unavailable"}
_BROWSER_RETRY = {"strategy": "verify_existing", "reason_code": "network_temporary"}
_BROWSER_FAILURE = "浏览器初始化失败，尚未开始账号会话或安全修改"
_BROWSER_TIMEOUT = "浏览器初始化等待超时，需核验旧进程结束后再检查账号安全状态"
_PASSWORD_EARLY_STATES = {"code_required", "link_required"}
_PASSWORD_STATES_WITH_READABLE_CREDENTIAL = {
    "pending", "unknown", "configured", *_PASSWORD_EARLY_STATES,
}
SECURITY_MANUAL_RETRY_REASON = "已排队一次手动安全核验；保留历史次数及原密码与 2FA，先核对当前账号和远端 MFA 状态"
SECURITY_RETRY_SPENT_REASON = "上次安全核验许可已使用；本地安全设置仍未完成，可明确手动重试一次，未自动重新启动"
SECURITY_STAGE_RETRY_REASON = "已按剩余次数排队重试原安全阶段；保留原密码与 2FA，先核对当前账号及已保存凭据"


def security_has_history(context):
    """A cleared in-flight marker is never proof that a task never ran."""
    return bool(isinstance(context, Mapping) and any(context.get(key) for key in (
        "security_recovery", "security_retry", "security_started_at", "security_task_id",
        "canonical_task_id", "security_attempted")))


def normalize_security_retry(value, job=None):
    """One snapshot-bound grant; old manual grants remain wire-compatible."""
    if not isinstance(value, dict):
        return None
    fields = {"kind", "request_id", "sequence", "phase", "job_id", "email", "parent_account_id",
        "source_account_id", "child_id", "membership_id", "remote_user_id", "membership_invited_at",
        "source_task_id", "source_started_at", "admitted_at", "started_at", "security_updated_at",
        "credential_state", "mfa_state", "has_totp", "has_recovery_codes", "prior_attempts"}
    if (set(value) != fields or not isinstance(value.get("kind"), str)
            or value["kind"] not in {"security_manual_retry_v1", "security_stage_retry_v1"}
            or not isinstance(value.get("request_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value["request_id"])
            or type(value.get("sequence")) is not int or not 1 <= value["sequence"] <= 10**6
            or type(value.get("prior_attempts")) is not int or not 0 <= value["prior_attempts"] <= 10**6
            or not isinstance(value.get("phase"), str) or value["phase"] not in {"queued", "started"}
            or not isinstance(value.get("job_id"), str) or not value["job_id"]
            or not isinstance(value.get("email"), str) or not re.fullmatch(r"[^\s@]+@[^\s@]+", value["email"])
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in
                   ("parent_account_id", "source_account_id", "child_id", "membership_id"))
            or not isinstance(value.get("remote_user_id"), str)
            or value["remote_user_id"] and not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value["remote_user_id"])
            or not isinstance(value.get("credential_state"), str)
            or value["credential_state"] not in _PASSWORD_STATES_WITH_READABLE_CREDENTIAL
            or not isinstance(value.get("mfa_state"), str)
            or value["mfa_state"] not in {"pending", "disabled", "not_configured", "enabled"}
            or type(value.get("has_totp")) is not bool or type(value.get("has_recovery_codes")) is not bool):
        return None
    if (value["mfa_state"] == "enabled" and not value["has_totp"]
            or value["has_recovery_codes"] and not value["has_totp"]):
        return None
    source_task = value.get("source_task_id")
    if not isinstance(source_task, str):
        return None
    task = re.fullmatch(r"gpt_plan_business_child_setup_security_(\d+)_(\d+)_(\d{13})_[a-f0-9]{8}", source_task)
    original, admitted, updated, invited = (_time(value.get(key)) for key in
        ("source_started_at", "admitted_at", "security_updated_at", "membership_invited_at"))
    if (not task or int(task[1]) != value["parent_account_id"] or int(task[2]) != value["child_id"]
            or not original or not admitted or not updated or not invited
            or not invited <= original <= admitted <= datetime.now(timezone.utc)
            or updated > admitted or abs(int(task[3]) / 1000 - original.timestamp()) > 30):
        return None
    consumed = _time(value.get("started_at"))
    if ((value["phase"] == "queued" and value["started_at"] != "")
            or (value["phase"] == "started" and (not consumed or not admitted <= consumed <= datetime.now(timezone.utc)))):
        return None
    if job is not None:
        get = job.get if isinstance(job, Mapping) else lambda key: getattr(job, key, None)
        if (value["job_id"] != get("id") or value["email"] != str(get("email") or "").strip().casefold()
                or any(value[key] != get(key) for key in
                    ("parent_account_id", "source_account_id", "child_id", "membership_id"))
                or value["remote_user_id"] != str(get("remote_user_id") or "")):
            return None
    return dict(value)


def validate_security_retry(job, previous, value):
    old, clean = normalize_security_retry(previous, job), normalize_security_retry(value, job)
    if old is None or clean is None:
        raise ValueError("手动安全核验许可只能由明确手动重试创建，身份不可改变")
    if clean == old:
        return clean
    if (any(clean[key] != old[key] for key in clean if key not in {"phase", "started_at"})
            or old["phase"] != "queued" or clean["phase"] != "started"):
        raise ValueError("手动安全核验许可不能重放、重置次数或更换原任务")
    return clean


def manual_security_retry_problem(context, status):
    """Current evidence, not an old manual label, owns stage-retry admission.

    Callers must also prove the target/period, terminal handoff and absent task,
    worker and leases. This permits the canonical state machine, not a password
    reset: unknown/submitted passwords and saved seeds must be verified there.
    """
    if not isinstance(context, Mapping) or not isinstance(status, Mapping):
        return "缺少当前安全设置记录，不能创建手动核验许可"
    if (status.get("credentials_readable") is not True or status.get("has_password") is not True
            or status.get("password_state") not in _PASSWORD_STATES_WITH_READABLE_CREDENTIAL):
        return "缺少可读取的原密码或密码状态不明确，需先补充安全凭据"
    if status.get("mfa_state") == "enabled" and status.get("has_totp") is not True:
        return "远端 2FA 已启用但缺少已保存密钥，不能自动重新绑定"
    if (status.get("mfa_state") not in {"pending", "disabled", "not_configured", "enabled"}
            or type(status.get("has_totp")) is not bool or type(status.get("has_recovery_codes")) is not bool):
        return "当前 MFA 凭据状态不明确，不能创建手动核验许可"
    if status["has_recovery_codes"] and not status["has_totp"]:
        return "已保存恢复码但缺少原 2FA 密钥，不能重复设置"
    if status["mfa_state"] == "pending" and not status["has_totp"] and not (
            can_inspect_pending_totp(status) and status.get("last_error") in _ENTRY_FAILURES.values()):
        return "先前 2FA 绑定结果未确认且缺少原密钥，不能重复设置"
    task = context.get("security_task_id")
    if (not isinstance(task, str) or task != context.get("canonical_task_id")
            or not re.fullmatch(r"gpt_plan_business_child_setup_security_\d+_\d+_\d{13}_[a-f0-9]{8}", task)):
        return "原安全任务身份不完整，不能创建手动核验许可"
    raw_progress = context.get("security_progress")
    progress = normalize_security_progress(raw_progress)
    if (not isinstance(raw_progress, Mapping) or raw_progress.get("status") not in {"failed", "review"}
            or not progress or not progress["code"] or not progress["reason"]):
        return "尚未取得安全任务的明确终态，不能重复启动"
    policy = normalize_task_retry(progress.get("task_retry"))
    confirmed_password_settings_failure = _confirmed_password_settings_failure(context, status, progress)
    for known_policy in (policy, normalize_task_retry(context.get("task_retry"))):
        if known_policy and known_policy["reason_code"] in {"identity_mismatch", "remote_change_unverified", "untracked_prior_state"}:
            if known_policy["reason_code"] == "remote_change_unverified" and confirmed_password_settings_failure:
                # Exact current evidence supersedes only this historical
                # password-submission marker. Never erase the old policy or
                # relax identity, lease, task/period or uncertain-MFA gates.
                continue
            return "原安全失败条件尚未恢复，不能自动修改账号安全设置"
    if progress["code"] in {"account_deactivated", "session_identity_mismatch", "session_origin_untrusted",
                            "login_origin_untrusted", "browser_init_cleanup_pending"}:
        return "原安全任务仍有身份、停用或清理未确认问题，不能重复启动"
    if progress["stage"] == "done" or "done" in progress["completed_stages"]:
        return "安全任务已到完成阶段，需先核对完成结果"
    if not status["has_totp"] and (progress["stage"] == "totp_verify"
            or any(stage in progress["completed_stages"] for stage in ("totp_settings", "totp_verify"))):
        return "原 2FA 可能已提交但缺少已保存密钥，不能重复设置"
    # A pending ciphertext is not proof that a password was never submitted.
    # The executor's unknown/seed/submission-marker paths enforce verification
    # before any mutation; do not admit contradictory older pending evidence.
    submitted = ("password_submit" in progress["completed_stages"]
        or progress["stage"] in {"password_submit", "password_verify", "totp_identity", "totp_settings", "totp_verify"})
    # `code_required`/`link_required` are valid pre-submission states emitted
    # by the canonical password flow.  Once a password submission stage has
    # run, however, retaining either early state is contradictory evidence:
    # do not turn it into permission to replay a potentially mutated password.
    if (status["password_state"] in _PASSWORD_EARLY_STATES and submitted):
        return "密码设置流程可能已提交但当前仍处于邮箱验证或链接验证状态，不能重复设置"
    if (status["password_state"] == "pending" and submitted and not status["has_totp"]
            and not any(marker in str(status.get("last_error") or "") for marker in ("密码已提交", "密码提交"))):
        return "原密码可能已提交但当前记录缺少独立核验保护，不能重设密码"
    started, updated, password_updated = (_time(value) for value in (
        context.get("security_started_at"), status.get("updated_at"), status.get("password_updated_at")))
    if (not started or not updated or not password_updated
            or not password_updated <= updated <= datetime.now(timezone.utc)):
        return "原任务或当前安全凭据版本不完整，不能创建核验许可"
    return None


def _confirmed_password_settings_failure(context, status, progress):
    """Legacy password-success -> unopened-MFA-panel failure, not rebind proof.

    The older tracker retained password submission_started even after a fresh
    exact-account password login completed. Match that one canonical failure
    plus unchanged current security state; callers still prove the original
    terminal task, identity, ownership, lease and remaining attempt budget.
    """
    if (progress["stage"] != "totp_settings" or progress["status"] != "failed"
            or progress["code"] != "security_failed"
            or progress["reason"] != "无法打开 ChatGPT Security 设置"
            or status.get("last_error") != progress["reason"]
            or status.get("credentials_readable") is not True
            or status.get("has_password") is not True or status.get("password_state") != "configured"
            or status.get("mfa_state") not in {"disabled", "not_configured"}
            or status.get("has_totp") is not False or status.get("has_recovery_codes") is not False
            or not {"session_check", "password_verify"}.issubset(progress["completed_stages"])
            or any(stage in progress["completed_stages"] for stage in
                   ("totp_identity", "totp_settings", "totp_verify", "done"))):
        return False
    started, password_updated, mfa_updated, updated = (_time(value) for value in (
        context.get("security_started_at"), status.get("password_updated_at"),
        status.get("mfa_updated_at"), status.get("updated_at")))
    return bool(started and password_updated and mfa_updated and updated
        and started <= password_updated <= updated <= datetime.now(timezone.utc)
        and started <= mfa_updated <= updated)


def browser_security_recovery_retry(context: Mapping, security_status: Mapping) -> dict | None:
    """Narrow pre-session interruption, not a generic timeout replay policy.

    The caller must prove the original process/task and leases are no longer
    live. Legacy evidence only covers unchanged configured-password/pending-MFA
    entry failures superseded by the exact outer 20-minute wait timeout.
    """
    if (not isinstance(context, Mapping) or not isinstance(security_status, Mapping)
            or context.get("security_recovery") or context.get("security_retry")):
        return None
    task_id = context.get("security_task_id")
    if (not isinstance(task_id, str) or task_id != context.get("canonical_task_id")
            or not re.fullmatch(r"gpt_plan_business_child_setup_security_\d+_\d+_\d{13}_[a-f0-9]{8}", task_id)):
        return None
    progress = normalize_security_progress(context.get("security_progress"))
    if (not progress or progress["stage"] != "session_check"
            or progress["status"] not in {"failed", "review"} or progress["completed_stages"]):
        return None
    for value in (context.get("task_retry"), progress.get("task_retry")):
        policy = normalize_task_retry(value)
        if policy and policy not in (
            _BROWSER_RETRY, {"strategy": "manual", "reason_code": "insufficient_evidence"},
            {"strategy": "manual", "reason_code": "unknown_failure"},
        ):
            return None
    if (security_status.get("credentials_readable") is not True
            or security_status.get("has_password") is not True
            or security_status.get("password_state") != "configured"
            or security_status.get("mfa_state") not in {"pending", "disabled", "not_configured"}
            or type(security_status.get("has_totp")) is not bool
            or type(security_status.get("has_recovery_codes")) is not bool):
        return None
    started = _time(context.get("security_started_at"))
    updated = _time(security_status.get("updated_at"))
    password_updated = _time(security_status.get("password_updated_at"))
    mfa_updated = _time(security_status.get("mfa_updated_at"))
    if not started or not updated or not password_updated or not mfa_updated or not (
        password_updated <= updated <= datetime.now(timezone.utc) and mfa_updated <= updated
    ):
        return None
    typed = (
        progress["code"] == "browser_init_failed" and progress["reason"] == _BROWSER_FAILURE
        or progress["code"] == "browser_init_timeout" and progress["reason"] == _BROWSER_TIMEOUT
    )
    legacy = (
        progress["code"] == "security_failed" and progress["reason"] == "操作未能确认（TimeoutError）"
        and progress["retry_mode"] == "verify_first" and context.get("security_attempted") is True
        and can_inspect_pending_totp(security_status) and security_status.get("has_recovery_codes") is False
        and security_status.get("last_error") in _ENTRY_FAILURES.values() and updated < started
    )
    if not typed and not legacy:
        return None
    # A browser-init timeout cannot explain later password/MFA writes.
    if progress["code"] == "browser_init_timeout" and updated > started:
        return None
    return dict(_BROWSER_RETRY)


def normalize_security_recovery(value, job=None):
    """One immutable, identity-bound admission; queued -> started consumes it."""
    if not isinstance(value, dict):
        return None
    keys = {"kind", "attempts", "phase", "job_id", "email", "parent_account_id", "source_account_id",
            "child_id", "membership_id", "source_task_id", "source_started_at", "admitted_at",
            "started_at", "security_updated_at", "credential_state", "mfa_state", "has_totp", "has_recovery_codes"}
    if (set(value) != keys or value.get("kind") != "browser_init_verify_v1"
            or type(value.get("attempts")) is not int or value["attempts"] != 1
            or value.get("phase") not in {"queued", "started"}
            or not isinstance(value.get("job_id"), str) or not value["job_id"]
            or not isinstance(value.get("email"), str)
            or not re.fullmatch(r"[^\s@]+@[^\s@]+", value["email"])
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in
                   ("parent_account_id", "source_account_id", "child_id", "membership_id"))
            or value.get("credential_state") != "configured"
            or value.get("mfa_state") not in {"pending", "disabled", "not_configured"}
            or type(value.get("has_totp")) is not bool or type(value.get("has_recovery_codes")) is not bool):
        return None
    task = re.fullmatch(r"gpt_plan_business_child_setup_security_(\d+)_(\d+)_(\d{13})_[a-f0-9]{8}", str(value.get("source_task_id")))
    original, admitted, updated = (_time(value.get(key)) for key in
                                   ("source_started_at", "admitted_at", "security_updated_at"))
    if (not task or int(task[1]) != value["parent_account_id"] or int(task[2]) != value["child_id"]
            or not original or not admitted or not updated or not original <= admitted <= datetime.now(timezone.utc)
            or updated > admitted or abs(int(task[3]) / 1000 - original.timestamp()) > 30):
        return None
    consumed = _time(value.get("started_at"))
    if ((value["phase"] == "queued" and value["started_at"] != "")
            or (value["phase"] == "started" and (not consumed or not admitted <= consumed <= datetime.now(timezone.utc)))):
        return None
    if job is not None:
        get = job.get if isinstance(job, Mapping) else lambda key: getattr(job, key, None)
        if value["job_id"] != get("id") or value["email"] != str(get("email") or "").strip().casefold() or any(
            value[key] != get(key) for key in ("parent_account_id", "source_account_id", "child_id", "membership_id")
        ):
            return None
    return dict(value)


def validate_security_recovery(job, previous, value):
    clean = normalize_security_recovery(value, job)
    old = normalize_security_recovery(previous, job)
    if clean is None or previous is not None and old is None:
        raise ValueError("安全恢复授权的任务身份或次数无效")
    if old is None:
        raise ValueError("安全恢复授权只能由受限恢复调度创建")
    if any(clean[key] != old[key] for key in clean if key not in {"phase", "started_at"}):
        raise ValueError("安全恢复授权不能更改原任务、账号或安全状态")
    if clean == old:
        return clean
    if old["phase"] != "queued" or clean["phase"] != "started":
        raise ValueError("安全恢复授权已消费，不能重复执行")
    return clean


def _time(value):
    try:
        if isinstance(value, str) and 0 < len(value) <= 80:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return result.astimezone(timezone.utc) if result.tzinfo is not None else None
        if type(value) in {float, int}:
            return datetime.fromtimestamp(value, timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    return None


def _policy_permits_inspection(value):
    if value is None:
        return True
    policy = normalize_task_retry(value)
    return policy == _INSPECTION_RETRY or bool(
        policy and policy["strategy"] == "manual" and policy["reason_code"] in _SUPERSEDED_REASONS
    )


def security_recovery_retry(context: Mapping, security_status: Mapping, *, snapshot=None) -> dict | None:
    """Project exact entry failures against current credential-free evidence.

    The caller must also verify the job's child/member/email identity, terminal
    job state, exclusive operation lease and retry budget. Pass the canonical
    snapshot whenever it still exists; running/stopped/mismatched snapshots veto
    recovery. After a restart, a persisted completed NV handoff, matching task
    IDs and the unchanged exact local failure still admit read-only inspection.
    No context or stored credential is changed by this function.
    """
    if (not isinstance(context, Mapping) or not isinstance(security_status, Mapping)
            or context.get("security_recovery") or context.get("security_retry")):
        return None
    if not can_inspect_pending_totp(security_status) or security_status.get("has_recovery_codes") is True:
        return None
    task_id = context.get("security_task_id")
    if (not isinstance(task_id, str) or not task_id.strip() or len(task_id) > 200
            or task_id != context.get("canonical_task_id")):
        return None
    if not _policy_permits_inspection(context.get("task_retry")):
        return None
    progress = normalize_security_progress(context.get("security_progress"))
    if (not progress or progress["stage"] != "totp_settings"
            or progress["status"] not in {"failed", "review"}
            or progress["retry_mode"] != "verify_first"
            or "session_check" not in progress["completed_stages"]
            or any(stage in progress["completed_stages"] for stage in ("totp_settings", "totp_verify", "done"))
            or not _policy_permits_inspection(progress.get("task_retry"))):
        return None
    reason = progress["reason"]
    if reason not in _ENTRY_FAILURES.values() or security_status.get("last_error") != reason:
        return None
    if progress["code"] not in {"security_failed", *_ENTRY_FAILURES}:
        return None
    if progress["code"] in _ENTRY_FAILURES and _ENTRY_FAILURES[progress["code"]] != reason:
        return None
    started = _time(context.get("security_started_at"))
    mfa_updated = _time(security_status.get("mfa_updated_at"))
    password_updated = _time(security_status.get("password_updated_at"))
    updated = _time(security_status.get("updated_at"))
    if (not all((started, mfa_updated, password_updated, updated))
            or not started <= mfa_updated <= updated <= datetime.now(timezone.utc)
            or password_updated > updated):
        return None
    if snapshot is not None:
        if (not isinstance(snapshot, Mapping) or snapshot.get("id") != task_id
                or snapshot.get("status") != "failed"):
            return None
        created, finished = _time(snapshot.get("created_at")), _time(snapshot.get("updated_at"))
        meta = snapshot.get("meta")
        source_progress = normalize_security_progress(meta.get("security_progress")) if isinstance(meta, Mapping) else None
        # NV turns a canonical `review` diagnostic into a failed job and may
        # persist this narrowly projected instruction. Those two fields can
        # differ; every actual substep/error/completion field must still match.
        comparable = lambda value: {key: item for key, item in value.items() if key not in {"status", "task_retry"}}
        if (not created or not finished or not source_progress
                or source_progress["status"] not in {"failed", "review"}
                or not _policy_permits_inspection(source_progress.get("task_retry"))
                or comparable(source_progress) != comparable(progress)
                or not started <= created <= mfa_updated <= updated <= finished <= datetime.now(timezone.utc)):
            return None
    elif context.get("security_attempted") is not False:
        # A streamed failure while a worker may still own the operation is not
        # a terminal handoff. Never derive that handoff from an absent worker.
        return None
    return dict(_INSPECTION_RETRY)
