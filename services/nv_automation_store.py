"""Durable, credential-free NV lifecycle state.

Transactions protect reservations and worker fencing; they never span browser or
HTTP operations. The public recovery entry points prepare a read-only balance
check before opening their write transaction. An interrupted mutation is
reconciled, never blindly replayed.
"""
from __future__ import annotations

import json
import re
import socket
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional

from sqlalchemy import Column, String, func, inspect, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import object_session
from sqlmodel import Field, Session, SQLModel, select

from core.business_invite_policy import BUSINESS_INVITE_WINDOW_HOURS
from core.db import engine
from services.business_invite_login_diagnostics import normalize_prelogin_failure
from services.nv_invite_progress import (normalize_invite_progress, public_invite_display,
    invite_display_label, project_invite_steps)
from services.chatgpt_oauth_failure import normalize_oauth_failure
from services.chatgpt_security_progress import normalize_security_progress, normalize_task_retry
from services.nv_oauth_manual_recovery import (
    MANUAL_SMS_FAILURE_CODES, MANUAL_SMS_RECOVERY_CODES,
    manual_sms_recovery_granted, manual_sms_recovery_problem,
    legacy_unknown_recovery_evidence_valid,
)
from services.nv_oauth_sms_history import historical_sms_502_failure
from services.nv_oauth_retry_policy import (
    recoverable_failure, recovery_evidence_valid, retry_problem,
    classify_legacy_number_request, manual_provider_recovery_evidence_valid,
)
from services.nv_auto_exit_policy import auto_exit_at, auto_exit_at_iso, normalize_auto_exit_delay_hours
from services.nv_job_exit_policy import (EXIT_DELAY_KEY, MANUAL_EXIT_KEY, exit_identity,
    job_exit_override, manual_exit_authorized, manual_exit_requested_at, normalized_exit_evidence,
    manual_sale_early_exit_authorized)
from services.nv_tier_policy import (TIERS, TIER_DEFAULTS, TIER_PRICE_KEYS, TIER_DELAY_KEYS,
    expand_legacy_tier_settings, job_policy, job_exit_delay, price_for_tier)

DEFAULTS = dict(enabled=False, mother_ids=[], price_yuan="", default_price_yuan="", prolite_price_yuan="", warranty_hours=1,
                team5x_warranty_mode="duration", team5x_warranty_hours=None, team5x_warranty_until="",
                team5x_auto_renew=False,
                auto_publish_prolite_to_nv=True,
                auto_exit=False, auto_exit_delay_hours=2.0, mail_provider="auto", browser_mode="headless",
                max_concurrent=3, browser_concurrent=2, scan_interval_seconds=300,
                max_attempts=3, oauth_phone_retry_enabled=False, paused_mother_ids=[],
                default_revenue_cap_yuan="", prolite_revenue_cap_yuan="")
DEFAULTS.update(TIER_DEFAULTS)
STEP_LABELS = dict(select="选择子号", invite="核验并邀请", security="检查密码 / 2FA",
                   oauth="获取 RT", dead_cleanup="清理停用子号", publish="上架 NV", renew="续期上架", wait_sale="等待出售",
                   wait_warranty="等待自动退出", leave="退出空间", done="已完成")
STATUS_LABELS = dict(pending="待执行", running="执行中", waiting="等待中", retry="等待重试",
                     review="需要核对", failed="失败", paused="已暂停", completed="已完成", cancelled="已移除")
TERMINAL_STATUSES = ("completed", "cancelled")
DELETED_CHILD_REASON = "子号已从本地账号库删除，自动移除旧任务；保留步骤日志与销售历史"
DEAD_MOTHER_REASON = "母号已停用，已停止自动处理"
PRODUCTION = ("select", "invite", "security", "oauth", "publish", "dead_cleanup")
BROWSER_STEPS = {"invite", "security", "oauth", "dead_cleanup"}
WAIT_STEPS = {"wait_sale", "wait_warranty"}

def _manual_sale_mode(job) -> bool:
    """Manual-sale jobs bypass NV sale scans but keep local exit scheduling."""
    context = _decode(job.context_json) if not isinstance(job, dict) else (job.get("context") or {})
    return isinstance(context, dict) and (context.get("manual_sale_required") is True or context.get("manual_sale") is True)
# Scheduler-owned metadata, not a capability/client checkpoint field. A
# successful production stage keeps this account ahead of untouched jobs;
# waiting, failure, pause and sales monitoring always release the preference.
_PRODUCTION_CONTINUATION = "_production_continuation_at"
# Identifiers/evidence only. Passwords, tokens, cookies and remote bodies are
# deliberately not permitted in checkpoints or public job state.
CONTEXT_KEYS = {
    "manual_sale_required",
    "child_deactivation",
    "security_recovery", "security_retry",
    "nv_refund",
    "nv_listing_started_at", "nv_listed_at", "nv_listing_confirmed_at", "nv_confirmed_at",
    "nv_remote_card_id", "nv_remote_order_id", "nv_card_id", "nv_order_id",
    "nv_baseline_card_ids", "nv_baseline_order_ids", "nv_baseline_complete",
    "nv_publish_started", "nv_publish_confirmed", "nv_inventory_verified_at",
    "sold_at", "warranty_until", "sale_verified_at", "sale_confirmed", "sale_source",
    "invite_started", "invite_confirmed", "security_started", "oauth_started",
    "leave_started", "leave_confirmed", "remote_member_id", "canonical_task_id",
    "canonical_operation_id", "excluded_child_ids", "selection_attempts",
    "listing_cycle_id", "membership_invited_at", "verification_reason",
    "invite_attempted", "invite_started_at", "security_attempted", "security_started_at",
    "security_task_id", "oauth_attempted", "oauth_started_at", "publish_baseline",
    "publish_attempted", "publish_started_at", "publish_confirmed", "price_yuan",
    "warranty_hours", "team5x_warranty", "nv_last_synced_at", "leave_attempted", "leave_started_at",
    "leave_target", "leave_preflight", "left_at", "seat_type", "existing_member", "existing_listing",
    "existing_invite_id", "dead_child_cleanup", "nv_card_identity", "nv_recheck_generation", "nv_recheck_version",
    "nv_scan_generation", "nv_scan_version", "security_progress", "security_check",
    "invite_failure", "invite_progress", "invite_dead_candidate", "task_retry", "oauth_membership_invited_at", "retry_batch_id",
    "invite_verification_started_at", "invite_verification_finished_at",
    "invite_send_started_at", "invite_send_finished_at",
    "invite_candidate_provider", "invite_candidate_seat_type",
    "gmail_production_alias_id", "gmail_production_source_id",
    "gmail_rejected_candidate",
    # Candidate preparation runs before the BUSINESS invitation mutation. It
    # records only credential-free stage evidence so a retry can resume safely.
    "invite_preparation", "invite_preparation_completed",
    "invite_preparation_started_at", "invite_preparation_finished_at",
    "publish_preflight",
    "oauth_failure", "oauth_execution_attempts", "oauth_reconciliation_attempts",
    "oauth_retry_ready", "oauth_failure_started_at", "oauth_failure_detail",
    "oauth_retry_blocked_reason", "oauth_manual_recovery", "oauth_unknown_auto_retry",
    "oauth_unknown_auto_retry_count",
    "oauth_reconcile_only", "oauth_saved_reconcile_at",
    "oauth_recovery_requested", "oauth_recovery_attempts", "oauth_recovery_phone_allowed", "quota_tier", "sold_quota",
    "dujiao_order_id", "dujiao_plan_code", "dujiao_external_account_id", "dujiao_sold_at", "dujiao_warranty_hours", "dujiao_warranty_until",
    "quota_rt_recovery", "quota_rt_recovery_started_at", "quota_rt_recovery_attempts",
    # Dujiao order proof (identifiers/timestamps only; never credentials).
    "dujiao_order_id", "dujiao_plan_code", "dujiao_external_account_id",
    "dujiao_sold_at", "dujiao_warranty_hours", "dujiao_warranty_until",
}
PRICE_KEYS = ("default_price_yuan", *TIER_PRICE_KEYS)
OAUTH_COUNT_KEYS = ("oauth_execution_attempts", "oauth_reconciliation_attempts", "oauth_recovery_attempts", "quota_rt_recovery_attempts")
OAUTH_RETRY_BLOCKED_REASONS = {
    "phone_cost_not_authorized", "execution_limit", "unconfirmed_evidence", "account_busy", "phone_rejected_manual",
    "sms_number_http_502_manual",
    "permanent_failure", "unknown_failure",
}
_TRUSTED_INTERNAL_CONFIRMATION = object()
_LAST_SCAN_SUMMARY_KEY = "_nv_last_scan_summary"
# A scan is a read/settlement lane for waiting jobs.  Keep the parent ids it
# admitted in the settings payload so the production dispatcher can continue
# with unrelated mothers while fencing the same mother until the scan result
# is committed.  This is internal scheduler metadata and is never exposed by
# the public settings contract.
_SCAN_PARENT_IDS_KEY = "_nv_scan_parent_ids"


class NvAutomationPriceChanged(RuntimeError):
    """A pre-publish price changed before its durable mutation checkpoint."""


class NvOAuthRetryBlocked(RuntimeError):
    """Fixed, credential-free single-account retry explanations for the API."""


class NvSecurityRetryBlocked(RuntimeError):
    """Fixed, credential-free security admission diagnostics for action APIs."""


class NvAutomationExitDelayChanged(RuntimeError):
    """Latest automatic-exit deadline does not permit a new remote release."""


def with_legacy_prices(values):
    """Fill only absent split-price keys; explicit empty drafts stay empty."""
    return expand_legacy_tier_settings(values)


def _normalized_price(value):
    if not isinstance(value, str):
        raise ValueError("上架价格必须是字符串")
    value = value.strip()
    if not value:
        return ""
    if re.fullmatch(r"\d{1,6}(?:\.\d{1,2})?", value) is None:
        raise ValueError("上架价格格式无效")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise ValueError("上架价格格式无效") from None
    if not amount.is_finite() or not Decimal("0.01") <= amount <= Decimal("999999.99"):
        raise ValueError("上架价格超出范围")
    return f"{amount:.2f}"


class NvAutomationSettings(SQLModel, table=True):
    __tablename__ = "nv_automation_settings"
    id: int = Field(default=1, primary_key=True)
    payload_json: str = "{}"
    next_scan_at: float = 0
    scan_token: str = ""
    scan_heartbeat_at: float = 0
    scan_pid: int = 0
    scan_host: str = ""
    scan_verified_at: float = 0
    scan_verified_config_generation: int = 0
    scan_error: str = ""
    config_generation: int = 0
    scan_request_generation: int = 0
    scan_claim_generation: int = 0
    scan_claim_config_generation: int = 0
    scan_completed_generation: int = 0
    scan_recovery_generation: int = 0
    scan_recovery_batch_id: str = ""
    scan_reason: str = ""
    scan_claim_reason: str = ""
    last_scan_at: float = 0
    updated_at: float = Field(default_factory=time.time)


class NvAutomationJob(SQLModel, table=True):
    __tablename__ = "nv_automation_jobs"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    parent_account_id: int = Field(index=True)
    source_account_id: int = 0
    parent_email: str = ""
    child_id: Optional[int] = Field(default=None, index=True)
    email: str = Field(default="", index=True)
    membership_id: Optional[int] = None
    remote_user_id: str = ""
    seat_type: str = ""
    step: str = "select"
    status: str = Field(default="pending", index=True)
    attempts: int = 0
    next_run_at: float = Field(default_factory=time.time, index=True)
    settings_json: str = "{}"
    context_json: str = "{}"
    operation_id: str = ""
    worker_token: str = ""
    worker_pid: int = 0
    worker_host: str = ""
    heartbeat_at: float = 0
    step_started_at: float = 0
    pause_requested: bool = False
    resume_status: str = "pending"
    reconcile_requested: bool = False
    # Nullable unique reservations survive restarts and cover every producer.
    active_parent_key: Optional[str] = Field(default=None, sa_column=Column(String, unique=True))
    active_child_key: Optional[str] = Field(default=None, sa_column=Column(String, unique=True))
    active_membership_key: Optional[str] = Field(default=None, sa_column=Column(String, unique=True))
    # Unlike the active reservation above, this marker is never cleared.  A
    # current BUSINESS membership is admitted into the lifecycle at most once,
    # including review/completed records and across process restarts.
    existing_membership_key: Optional[str] = Field(default=None, sa_column=Column(String, unique=True))
    error: str = ""
    version: int = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    finished_at: float = 0
    retry_batch_checked_at: float = 0


class NvAutomationStep(SQLModel, table=True):
    __tablename__ = "nv_automation_steps"
    id: str = Field(primary_key=True)
    job_id: str = Field(index=True)
    step: str
    status: str = "running"
    attempts: int = 1
    error: str = ""
    started_at: float = Field(default_factory=time.time)
    finished_at: float = 0


class NvAutomationLog(SQLModel, table=True):
    __tablename__ = "nv_automation_logs"
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    step: str = ""
    message: str
    created_at: float = Field(default_factory=time.time)


class NvAutomationRetryBatch(SQLModel, table=True):
    __tablename__ = "nv_automation_retry_batches"
    id: str = Field(primary_key=True)
    active_key: Optional[str] = Field(default=None, sa_column=Column(String, unique=True))
    status: str = "running"
    items_json: str = "[]"
    current_job_id: str = ""
    origin: str = "manual"
    scan_generation: int = 0
    deadline_at: float = 0
    deferred_count: int = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


def init_tables():
    from services import nv_order_history as history
    from services.nv_listing_renewal import NvListingRenewal
    SQLModel.metadata.create_all(engine, tables=[model.__table__ for model in
        (NvAutomationSettings, NvAutomationJob, NvAutomationStep, NvAutomationLog, NvAutomationRetryBatch, NvListingRenewal, *history.MODELS)])
    if engine.dialect.name != "sqlite":
        history.backfill()
        return
    # SQLModel/SQLAlchemy create_all() deliberately does not ALTER existing
    # tables.  Keep the small state-machine migration local and idempotent so an
    # older SQLite database can safely adopt generation fences on startup.
    migrations = {
        "nv_automation_settings": {
            "scan_verified_config_generation": "INTEGER NOT NULL DEFAULT 0",
            "config_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_request_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_claim_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_claim_config_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_completed_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_recovery_generation": "INTEGER NOT NULL DEFAULT 0",
            "scan_recovery_batch_id": "VARCHAR NOT NULL DEFAULT ''",
            "scan_reason": "VARCHAR NOT NULL DEFAULT ''",
            "scan_claim_reason": "VARCHAR NOT NULL DEFAULT ''",
            "last_scan_at": "FLOAT NOT NULL DEFAULT 0",
        },
        "nv_automation_jobs": {
            "existing_membership_key": "VARCHAR",
            "retry_batch_checked_at": "FLOAT NOT NULL DEFAULT 0",
        },
        "nv_automation_retry_batches": {
            "origin": "VARCHAR NOT NULL DEFAULT 'manual'",
            "scan_generation": "INTEGER NOT NULL DEFAULT 0",
            "deadline_at": "FLOAT NOT NULL DEFAULT 0",
            "deferred_count": "INTEGER NOT NULL DEFAULT 0",
        },
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, columns in migrations.items():
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for name, ddl in columns.items():
                if name not in existing:
                    connection.exec_driver_sql(
                        f'ALTER TABLE "{table_name}" ADD COLUMN "{name}" {ddl}'
                    )
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "ux_nv_automation_jobs_existing_membership_key "
            "ON nv_automation_jobs(existing_membership_key)"
        )
    history.backfill()


@contextmanager
def transaction():
    with Session(engine) as session:
        if engine.dialect.name == "sqlite":
            session.exec(text("BEGIN IMMEDIATE"))
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _decode(raw):
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def safe_message(value):
    msg = str(value or "")
    msg = re.sub(r"(?i)bearer\s+[^\s,;]+", "Bearer [已隐藏]", msg)
    msg = re.sub(r"eyJ[A-Za-z0-9_-]{15,}(?:\.[A-Za-z0-9_-]+){1,2}", "[凭证已隐藏]", msg)
    msg = re.sub(r"(?i)((?:access_token|refresh_token|id_token|password|secret|cookie|authorization|api[_-]?key)\s*['\"]?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)", r"\1[已隐藏]", msg)
    msg = re.sub(r"https?://[^\s]+", "[链接已隐藏]", msg)
    return msg[:1500]


def _oauth_count(value):
    """Return a durable OAuth counter without coercing legacy values."""
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def _oauth_time(value):
    """Parse an explicitly timezone-aware OAuth fence timestamp."""
    if not isinstance(value, str) or not value.strip() or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _oauth_public_fields(context):
    blocked = context.get("oauth_retry_blocked_reason")
    started = _oauth_time(context.get("oauth_started_at"))
    failure_started = _oauth_time(context.get("oauth_failure_started_at"))
    saved_reconcile_at = _oauth_time(context.get("oauth_saved_reconcile_at"))
    return {
        "oauth_failure": normalize_oauth_failure(context.get("oauth_failure")),
        "oauth_retry_recoverable": recovery_evidence_valid(context),
        "oauth_manual_retry_available": manual_provider_recovery_evidence_valid(context),
        "oauth_retry_ready": context.get("oauth_retry_ready") is True,
        # A mutation checkpoint is not proof that a browser/task was started.
        "oauth_started_at": started.isoformat() if started else None,
        "oauth_failure_started_at": failure_started.isoformat() if failure_started else None,
        "oauth_reconcile_only": context.get("oauth_reconcile_only") is True,
        "oauth_saved_reconcile_at": saved_reconcile_at.isoformat() if saved_reconcile_at else None,
        # Missing legacy counters stay unknown.  ``job.attempts`` also counts
        # read-only reconciliation and must never masquerade as OAuth usage.
        "oauth_execution_attempts": _oauth_count(context.get("oauth_execution_attempts")),
        "oauth_reconciliation_attempts": _oauth_count(context.get("oauth_reconciliation_attempts")),
        "oauth_recovery_attempts": _oauth_count(context.get("oauth_recovery_attempts")),
        "oauth_retry_blocked_reason": blocked if blocked in OAUTH_RETRY_BLOCKED_REASONS else None,
    }


def _settings(row):
    raw = with_legacy_prices(_decode(row.payload_json) if row else {})
    # payload_json also carries narrowly-scoped internal scheduler metadata.
    # Never expose unknown/internal keys through the public settings contract.
    result = {**DEFAULTS, **{key: raw[key] for key in DEFAULTS if key in raw}}
    # Return independent lists, never share mutable defaults.
    return {**result, "mother_ids": list(result["mother_ids"]),
            "paused_mother_ids": list(result["paused_mother_ids"])}


def _write_settings_payload(row, settings, *, last_scan_summary=None):
    raw = _decode(row.payload_json)
    internal = {}
    if isinstance(raw.get(_LAST_SCAN_SUMMARY_KEY), dict):
        internal[_LAST_SCAN_SUMMARY_KEY] = raw[_LAST_SCAN_SUMMARY_KEY]
    if last_scan_summary is not None:
        internal[_LAST_SCAN_SUMMARY_KEY] = last_scan_summary
    reserved = raw.get(_SCAN_PARENT_IDS_KEY)
    if isinstance(reserved, list):
        internal[_SCAN_PARENT_IDS_KEY] = [int(value) for value in reserved
                                          if isinstance(value, int) and not isinstance(value, bool)]
    row.payload_json = _json({**settings, **internal})


def _last_scan_summary(row):
    value = _decode(row.payload_json).get(_LAST_SCAN_SUMMARY_KEY) if row else None
    if not isinstance(value, dict):
        return None
    result = {}
    for key in ("checked", "recovered", "still_review", "skipped", "errors"):
        count = value.get(key)
        result[key] = max(0, count) if isinstance(count, int) and not isinstance(count, bool) else 0
    return result


def _scan_parent_ids(row):
    """Return the mothers fenced by the currently running scan."""
    value = _decode(row.payload_json).get(_SCAN_PARENT_IDS_KEY) if row else None
    if not isinstance(value, list):
        return set()
    return {int(item) for item in value
            if isinstance(item, int) and not isinstance(item, bool)}


def _set_scan_parent_ids(row, parent_ids):
    raw = _decode(row.payload_json)
    raw[_SCAN_PARENT_IDS_KEY] = sorted({int(item) for item in parent_ids
                                        if isinstance(item, int) and not isinstance(item, bool)})
    row.payload_json = _json(raw)


def _settings_row(session):
    row = session.get(NvAutomationSettings, 1)
    if not row:
        row = NvAutomationSettings()
        session.add(row)
        session.flush()
    return row


def _scan_reason(value, fallback="等待 NV 核对"):
    return safe_message(value or fallback)[:300]


def _request_scan_row(row, reason, *, now=None):
    """Coalesce scan events without losing one raised during an active scan."""
    now = time.time() if now is None else float(now)
    claim_generation = int(row.scan_claim_generation or 0)
    request_generation = int(row.scan_request_generation or 0)
    completed_generation = int(row.scan_completed_generation or 0)
    if row.scan_token:
        target_generation = max(request_generation, claim_generation + 1)
    elif request_generation > completed_generation and row.next_scan_at <= now:
        target_generation = request_generation
    else:
        target_generation = max(request_generation, completed_generation) + 1
    pending_before = (
        request_generation > (claim_generation if row.scan_token else completed_generation)
        and row.next_scan_at <= now
    )
    next_reason = _scan_reason(reason)
    if pending_before and row.scan_reason and row.scan_reason != next_reason:
        next_reason = "多个事件等待 NV 核对"
    row.scan_request_generation = target_generation
    row.scan_reason = next_reason
    row.next_scan_at = 0
    return target_generation


def _configuration_changed(row, reason):
    row.config_generation = int(row.config_generation or 0) + 1
    row.scan_verified_at = 0
    row.scan_verified_config_generation = 0
    if _settings(row)["enabled"]:
        _request_scan_row(row, reason)
    else:
        # A disabled configuration has no scheduled work.  Enabling it creates
        # a fresh event generation; a stale in-flight scan is fenced below.
        row.next_scan_at = 0


def get_settings():
    with Session(engine) as session:
        return _settings(session.get(NvAutomationSettings, 1))


def save_settings(values, *, confirm_auto_exit=_TRUSTED_INTERNAL_CONFIRMATION,
                  confirm_oauth_phone_retry=_TRUSTED_INTERNAL_CONFIRMATION,
                  sync_listed_prices=False, confirm_sync_listed_prices=False,
                  price_batch_request_id=None, price_batch_expected_prices=None):
    if type(sync_listed_prices) is not bool:
        raise ValueError("同步在售价格选项必须为布尔值")
    if sync_listed_prices:
        if confirm_sync_listed_prices is not True:
            raise ValueError("批量修改 NV 在售价格前必须明确确认")
        if not isinstance(price_batch_expected_prices, dict) or set(price_batch_expected_prices) != set(TIERS):
            raise ValueError("批量改价需提供保存前的三档默认价格")
        price_batch_expected_prices = {key: _normalized_price(value) for key, value in price_batch_expected_prices.items()}
        try:
            price_batch_request_id = str(uuid.UUID(price_batch_request_id or ""))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("批量改价请求编号无效") from None
    with transaction() as session:
        row = _settings_row(session)
        before = _settings(row)
        result = {**before, **{k: v for k, v in with_legacy_prices(values).items() if k in DEFAULTS and k != "paused_mother_ids"}}
        from core.business_invite_mail_provider import resolve_candidate_mail_provider
        result["mail_provider"] = resolve_candidate_mail_provider(result.get("mail_provider"), "")
        for key in (*PRICE_KEYS, "price_yuan"):
            result[key] = _normalized_price(result[key])
        for key in ("auto_exit_delay_hours", *TIER_DELAY_KEYS):
            result[key] = normalize_auto_exit_delay_hours(result[key])
        from services.nv_listing_warranty import validate_team5x_settings
        from services.nv_revenue_cap import normalize_cap_yuan
        for key in ("default_revenue_cap_yuan", "prolite_revenue_cap_yuan"):
            result[key] = normalize_cap_yuan(result.get(key, ""))
        result.update(validate_team5x_settings(result))
        if type(result["team5x_auto_renew"]) is not bool:
            raise ValueError("5X 自动续期开关必须为布尔值")
        if type(result["auto_publish_prolite_to_nv"]) is not bool:
            raise ValueError("5X 自动上架开关必须为布尔值")
        if result["team5x_auto_renew"] and result["team5x_warranty_hours"] is None:
            raise ValueError("开启 5X 自动续期前请设置续期时长")
        delay_changed = any(result[key] != before[key] for key in TIER_DELAY_KEYS)
        if result["enabled"] and any(not result[key] for key in TIER_PRICE_KEYS):
            raise ValueError("启用自动售号前必须设置三种席位档位的上架价格")
        if (result["auto_exit"] and (not before["auto_exit"] or
                any(result[key] < before[key] for key in TIER_DELAY_KEYS))
                and confirm_auto_exit is not _TRUSTED_INTERNAL_CONFIRMATION
                and confirm_auto_exit is not True):
            raise ValueError("开启自动退出或缩短退出延迟前必须明确确认，已有等待账号也会重新计算")
        if type(result["oauth_phone_retry_enabled"]) is not bool:
            raise ValueError("OAuth 手机验证重试开关必须是布尔值")
        if (not before["oauth_phone_retry_enabled"] and result["oauth_phone_retry_enabled"]
                and confirm_oauth_phone_retry is not _TRUSTED_INTERNAL_CONFIRMATION
                and confirm_oauth_phone_retry is not True):
            raise ValueError("开启 OAuth 手机验证重试前必须明确确认可能产生额外短信费用")
        if sync_listed_prices:
            from services.nv_price_batch import create_batch_locked
            # Defaults and a frozen set of remote targets commit atomically.
            # Active-batch/identity errors must not leave a half-saved config.
            batch = create_batch_locked(session, before, result, price_batch_request_id,
                                        expected_prices=price_batch_expected_prices)
            if batch and batch.get("replayed") is True:
                # A lost-response retry returns its original batch, not a new
                # settings write that could undo a subsequent operator save.
                return before
        changed = result != before
        _write_settings_payload(row, result)
        row.updated_at = time.time()
        if before["enabled"] and not result["enabled"]:
            for job in session.exec(select(NvAutomationJob).where(
                    NvAutomationJob.status.notin_(TERMINAL_STATUSES))).all():
                _clear_production_continuation(session, job)
        if delay_changed:
            _reschedule_auto_exit_jobs(session, result, row.updated_at)
        if changed:
            _configuration_changed(row, "自动售号配置已更新")
        session.add(row)
        return result


def _warranty_next_run_at(job, context, deadline, now):
    """Keep RT repair backoff independent of the sold account's exit clock."""
    if job.step == "wait_warranty" and context.get("quota_rt_recovery") is True:
        # The earlier event wins: retry OAuth before warranty expiry, or let
        # the existing exit reconciliation take over once the exit is due.
        recovery_at = max(now, job.next_run_at)
        return min(recovery_at, max(now, deadline.timestamp())) if deadline else recovery_at
    return max(now, deadline.timestamp()) if deadline else 0


def _reschedule_auto_exit_jobs(session, settings, now):
    """Re-time queued exits atomically with configuration, never replay effects.

    Pauses and failures retain their status and evidence. Running workers keep
    their lease; their final checkpoint/result rechecks the same live policy.
    Already-dispatched releases cannot be undone and are not rescheduled.
    """
    jobs = session.exec(select(NvAutomationJob).where(
        NvAutomationJob.status.notin_(TERMINAL_STATUSES),
        NvAutomationJob.step.in_(["wait_warranty", "leave"]),
    )).all()
    for job in jobs:
        context = _decode(job.context_json)
        if context.get("nv_refund"):
            continue  # Refund exits have no warranty-delay schedule.
        if job_exit_override(job, context) is not None:
            continue  # An order-specific choice is never rewritten by defaults.
        if any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at")):
            continue
        delay = job_exit_delay(job, settings, context)
        deadline = auto_exit_at(context.get("warranty_until"), delay)
        if (job.step == "leave" and not job.worker_token and job.status != "running"
                and (deadline is None or deadline.timestamp() > now)):
            job.step = "wait_warranty"
            if job.status in {"pending", "waiting"}:
                job.status = "waiting"
        job.next_run_at = _warranty_next_run_at(job, context, deadline, now)
        if (job.step == "wait_warranty" and context.get("quota_rt_recovery") is True
                and job.status in {"pending", "waiting", "retry"}):
            job.reconcile_requested = True
        job.updated_at = now
        if not job.worker_token and job.status != "running":
            job.version += 1
        delay_label = f"{delay:g} 小时" if delay is not None else "档位待核验，暂停自动退出"
        _log(session, job, f"自动退出延迟已更新为 {delay_label}；最早退出时间："
             + (deadline.isoformat() if deadline else "档位或质保时间待确认，不允许自动退出")
             + "；原暂停/失败状态及已发出的操作不受影响")
        session.add(job)


def _save_mother_scope(session, row, settings, mother_ids, *, paused_mother_ids=None):
    """Persist a scope change with the same scheduler fence as selection saves."""
    result = {**settings, "mother_ids": list(mother_ids)}
    if paused_mother_ids is not None:
        result["paused_mother_ids"] = list(paused_mother_ids)
    if result == settings:
        return settings
    _write_settings_payload(row, result)
    row.updated_at = time.time()
    _configuration_changed(row, "母号接管范围已更新")
    session.add(row)
    return result


def save_mother_selection(mother_ids, selectable_ids):
    """Atomically replace only the managed-mother scope.

    Existing selections may be retained or removed after becoming ineligible;
    only newly-added IDs require a fresh local ``selectable`` proof.  No other
    setting is copied from a potentially stale UI draft.
    """
    if not isinstance(mother_ids, list) or any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in mother_ids
    ):
        raise ValueError("母号编号无效，请重新读取列表")
    if len(mother_ids) != len(set(mother_ids)) or len(mother_ids) > 500:
        raise ValueError("母号不能重复且最多选择 500 个")
    selectable = {
        value for value in selectable_ids
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    }
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        reserved_parents = _scan_parent_ids(row)
        current = set(settings["mother_ids"])
        if not set(mother_ids).difference(current).issubset(selectable):
            raise ValueError("新增母号不存在或当前不可用于自动售号")
        if any(_mother_dead_reason(session, parent_id)
               for parent_id in set(mother_ids).difference(current)):
            raise ValueError(DEAD_MOTHER_REASON)
        return _save_mother_scope(session, row, settings, mother_ids)


def remove_mother_management(mother_id):
    """Remove one mother from the latest local scope without deleting its data.

    A repeated removal is a no-op. The short transaction preserves concurrent
    changes to other mothers/settings and leaves jobs, credentials and sales
    history intact, including existing sale/warranty waiting jobs.
    """
    if not isinstance(mother_id, int) or isinstance(mother_id, bool) or mother_id <= 0:
        raise ValueError("母号编号无效，请重新读取列表")
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        return _save_mother_scope(session, row, settings,
            [value for value in settings["mother_ids"] if value != mother_id],
            paused_mother_ids=[value for value in settings["paused_mother_ids"] if value != mother_id])


def pause_mother(parent_id, paused):
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        ids = set(settings["paused_mother_ids"])
        ids.add(parent_id) if paused else ids.discard(parent_id)
        next_ids = sorted(ids)
        if settings["paused_mother_ids"] == next_ids:
            return {"parent_account_id": parent_id, "paused": paused}
        settings["paused_mother_ids"] = next_ids
        if paused:
            for job in session.exec(select(NvAutomationJob).where(
                    NvAutomationJob.parent_account_id == parent_id,
                    NvAutomationJob.status.notin_(TERMINAL_STATUSES))).all():
                _clear_production_continuation(session, job)
        _write_settings_payload(row, settings)
        row.updated_at = time.time()
        _configuration_changed(row, "母号暂停范围已更新")
        session.add(row)
        return {"parent_account_id": parent_id, "paused": paused}


def _iso(value):
    if not value:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _security_result(job, context):
    proof = context.get("security_check")
    if (not isinstance(proof, dict)
            or proof.get("result") not in ("reused", "configured", "verified")
            or any(type(proof.get(key)) is not int or proof[key] <= 0
                   or proof[key] != getattr(job, key) for key in ("child_id", "membership_id"))
            or not isinstance(proof.get("email"), str) or not proof["email"]
            or proof["email"] != str(job.email or "").strip().lower()
            or _oauth_time(proof.get("checked_at")) is None):
        return ""
    return proof["result"]


def _public_security_progress(job, context):
    # Progress belongs to the security step only. A completed transition must
    # never leave an old failure banner on OAuth/publish/sale rows.
    if job.step != "security":
        return None
    progress = normalize_security_progress(context.get("security_progress"))
    if progress is not None:
        resume_status = job.resume_status if job.status == "paused" else job.status
        if (
            job.status in {"review", "failed", "paused"}
            and progress["status"] not in {"review", "failed"}
        ):
            # A killed/paused outer worker cannot leave the UI claiming that a
            # browser sub-step is still spinning. Preserve the last exact stage
            # but require verification before any manual retry.
            progress = normalize_security_progress({
                **progress,
                "status": "failed" if resume_status == "failed" else "review",
                "reason": job.error or progress["reason"] or "安全设置任务已停止，恢复前需要先核验当前状态",
                "retry_mode": "verify_first",
            })
        return progress
    # Historical jobs did not have structured progress. Only this exact,
    # previously emitted proof maps to a specific sub-step; other free-form
    # errors remain generic and are never interpreted as authorization.
    if not re.fullmatch(
        r"(?:安全设置任务(?:已结束|未完成)：)?"
        r"密码已提交[^；\n]{0,500}；全新登录复核失败：[^\n]{1,500}",
        str(job.error or ""),
    ):
        return None
    return normalize_security_progress({
        "stage": "password_verify",
        "status": "failed" if job.status == "failed" else "review",
        "code": "password_verification_failed",
        "reason": safe_message(job.error),
        "retry_mode": "verify_first",
        "retry_attempt": 0,
        "retry_limit": 0,
        "completed_stages": [],
    })


def _normalized_invite_failure(value):
    """Return the credential-free, exact pre-invite failure envelope."""
    normalized = normalize_prelogin_failure(value)
    if normalized is None:
        return None
    return {"code": "business_child_prelogin_failed", **normalized}


def _job_max_attempts(job):
    value = _decode(job.settings_json).get("max_attempts", 3)
    return value if type(value) is int and 1 <= value <= 5 else 3


def _public_listed_at(job, context):
    """Expose the recorded NV listing cycle, never task or manual-status time."""
    source = context
    if not context.get("nv_listed_at"):
        source = context.get("existing_listing")
        if (context.get("existing_member") is not True or not isinstance(source, dict)
                or source.get("kind") != "persisted_nv_listing"
                or any(source.get(key) != getattr(job, key) for key in (
                    "parent_account_id", "source_account_id", "child_id", "email",
                    "membership_id", "remote_user_id"))):
            return None
    try:
        dates = []
        for key in ("nv_listed_at", "nv_listing_confirmed_at"):
            value = source.get(key)
            if not isinstance(value, str) or not value.strip():
                return None
            date = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            dates.append(date.replace(tzinfo=timezone.utc) if date.tzinfo is None
                         else date.astimezone(timezone.utc))
        listed, confirmed = dates
        return listed.isoformat() if listed <= confirmed else None
    except (TypeError, ValueError, OverflowError):
        return None


def _public(job, scan=None):
    from services.nv_refund_policy import job_refund
    from services.nv_security_recovery import normalize_security_recovery, normalize_security_retry
    from services.nv_listing_renewal import public_status
    from services.nv_dead_child_cleanup import public_state as cleanup_state
    from services.nv_task_recovery import public_plan, security_manual_retry_status
    context = _oauth_context_for_retry(object_session(job), job)
    refund = job_refund(job, context)
    display_step, invite_progress = public_invite_display(job, context)
    invite_timing = {
        key: context.get(key) for key in (
            "invite_verification_started_at", "invite_verification_finished_at",
            "invite_send_started_at", "invite_send_finished_at",
        ) if isinstance(context.get(key), str) and context.get(key).strip()
    }
    from services.nv_invite_preparation import normalize_preparation
    invite_preparation = normalize_preparation(context.get("invite_preparation"), job)
    from services.nv_sold_quota import normalize_sold_quota
    quota_identity = {key: getattr(job, key) for key in
                      ("child_id", "membership_id", "email", "remote_user_id")}
    sold_quota = normalize_sold_quota(context.get("sold_quota"), {**quota_identity, "context": context}) if context.get("sold_at") else None
    tier, tier_label = job_policy(job, context)
    delay = job_exit_delay(job, _settings(scan), context)
    oauth = _oauth_public_fields(context)
    security_retry = security_manual_retry_status(object_session(job), job, _settings(scan))
    mother_block = _mother_dead_reason(object_session(job), job.parent_account_id, job.source_account_id)
    display_production = ("select", "verify_child", "invite", "security", "oauth", "publish")
    percent = round(display_production.index(display_step) / len(display_production) * 100) if display_step in display_production else 100
    cleanup = cleanup_state(job)
    if job.step == "dead_cleanup":
        percent = {"queued": 0, "checking": 10, "removing": 35, "submitted": 50,
                   "verifying": 75, "complete": 100 if job.status == "cancelled" else 99}.get((cleanup or {}).get("phase"), 0)
    if job.step == "wait_sale" and job.status == "review":
        # An imported historical row without sufficient NV proof is a review,
        # not a successfully completed publish cycle.
        percent = round(display_production.index("publish") / len(display_production) * 100)
    existing_member = context.get("existing_member") is True
    existing_listing = context.get("existing_listing")
    existing_listing = existing_listing if isinstance(existing_listing, dict) else {}
    warranty = existing_listing.get("warranty_hours") if existing_listing else context.get("warranty_hours")
    if not isinstance(warranty, int) or isinstance(warranty, bool) or warranty <= 0:
        # A historical listing without a frozen warranty is unknown; the live
        # default must never be presented as evidence for that old sale cycle.
        warranty = None if existing_member and existing_listing else _decode(job.settings_json).get("warranty_hours", 1)
    if warranty is not None and (
        not isinstance(warranty, int) or isinstance(warranty, bool) or warranty <= 0
    ):
        warranty = 1
    from services.nv_listing_warranty import normalize_team5x_warranty
    raw_absolute = context.get("team5x_warranty")
    if raw_absolute is None and existing_listing.get("nv_team5x_warranty_until"):
        raw_absolute = {"mode": "until", "until": existing_listing["nv_team5x_warranty_until"]}
    try:
        absolute = normalize_team5x_warranty(raw_absolute, require_future=False)
    except ValueError:
        absolute = None
    if absolute is not None:
        warranty = None
    step_label = invite_display_label(display_step, invite_progress) or STEP_LABELS.get(job.step, job.step)
    if invite_preparation and display_step == "verify_child":
        step_label = "登录验证 + 密码/2FA"
    return dict(id=job.id, version=job.version, parent_account_id=job.parent_account_id, parent_email=job.parent_email,
                child_id=job.child_id, email=job.email, membership_id=job.membership_id,
                seat_type=job.seat_type, step=job.step, display_step=display_step,
                candidate_mail_provider=context.get("invite_candidate_provider"),
                candidate_seat_type=context.get("invite_candidate_seat_type"),
                step_label=step_label,
                status=job.status, status_label=STATUS_LABELS.get(job.status, job.status),
                attempts=job.attempts, max_attempts=_job_max_attempts(job),
                next_run_at=None if mother_block or (_manual_sale_mode(job) and job.step == "wait_sale") else _iso(job.next_run_at),
                error=mother_block if mother_block and job.status not in TERMINAL_STATUSES else job.error,
                processing_blocked_reason=mother_block, mother_is_dead=bool(mother_block),
                updated_at=_iso(job.updated_at), created_at=_iso(job.created_at),
                listed_at=_public_listed_at(job, context),
                sold_at=context.get("sold_at"), warranty_until=context.get("warranty_until"),
                sold_quota=None if refund else sold_quota, nv_refund=refund,
                auto_exit_at=None if refund else auto_exit_at_iso(context.get("warranty_until"), delay),
                manual_sale=context.get("manual_sale") is True,
                manual_sale_required=context.get("manual_sale_required") is True,
                quota_rt_recovery=context.get("quota_rt_recovery") is True,
                auto_exit_delay_hours=delay, policy_tier=tier, policy_tier_label=tier_label,
                exit_delay_source="job" if job_exit_override(job, context) is not None else "global",
                exit_controls=_exit_controls(job),
                manual_exit_requested_at=manual_exit_requested_at(job, context),
                production_percent=percent, pause_requested=job.pause_requested,
                dead_child_cleanup=cleanup,
                recovery_plan=public_plan(object_session(job), job, _settings(scan)),
                paused_by_mother=False, existing_member=existing_member,
                origin="existing_child" if existing_member else "new_invite",
                origin_label="已有子号接管" if existing_member else "自动新邀请",
                warranty_hours=warranty,
                team5x_warranty=absolute,
                nv_team5x_warranty_until=absolute["until"] if absolute else None,
                listing_renewal=public_status(job, session=object_session(job)),
                nv_recheck_status=_nv_recheck_status(job, scan),
                invite_failure=_normalized_invite_failure(context.get("invite_failure")),
                invite_progress=invite_progress,
                invite_timing=invite_timing,
                invite_preparation=invite_preparation,
                invite_preparation_completed=bool(invite_preparation and invite_preparation["status"] == "completed"),
                task_retry=normalize_task_retry(context.get("task_retry"))
                    if job.status != "cancelled" and job.step in {"security", "oauth"} else None,
                security_progress=_public_security_progress(job, context) if job.status != "cancelled" else None,
                security_recovery=normalize_security_recovery(context.get("security_recovery"), job),
                security_retry=normalize_security_retry(context.get("security_retry"), job),
                security_manual_retry_available=security_retry.get("available") is True,
                security_retry_blocked_reason=security_retry.get("reason") or None,
                security_result=_security_result(job, context),
                security_setup_started=(context.get("security_attempted") is True
                    or _oauth_time(context.get("security_started_at")) is not None),
                **oauth)


def _exit_controls(job):
    """Local display hints; action endpoints repeat canonical identity checks."""
    from services.nv_order_history import _evidence
    context = _decode(job.context_json)
    reason = _mother_dead_reason(object_session(job), job.parent_account_id, job.source_account_id)
    if reason:
        pass
    elif context.get("nv_refund"):
        reason = "NV 退款订单不使用质保后退出延迟"
    elif job.status in TERMINAL_STATUSES or job.step == "done":
        reason = "本次订单已结束"
    elif job.status == "running" or job.worker_token or job.worker_pid:
        reason = "该子号正在执行，请等待当前步骤结束"
    elif any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at")):
        reason = "退出请求已发出，需先确认执行结果"
    elif manual_exit_requested_at(job, context) and job.status not in {"failed", "review", "paused"}:
        reason = "已进入退出队列，请查看退出进度"
    elif context.get("manual_sale") is True:
        permitted = job.step in {"wait_warranty", "leave"} and exit_identity(job, context) is not None
        # The countdown governs automatic release. A separately confirmed,
        # identity-bound operator request may release a manual sale earlier.
        reason = "" if permitted else "人工出售记录尚未确认"
        return {"can_update": permitted, "can_exit_now": permitted,
                "reason": reason, "exit_now_reason": reason}
    elif job.step not in {"wait_warranty", "leave"}:
        reason = "尚未进入售后等待阶段"
    elif context.get("nv_price_edit"):
        reason = "该子号正在核对 NV 改价"
    elif exit_identity(job, context) is None or _evidence(job) is None:
        reason = "尚未确认本次出售记录与真实质保时间"
    deadline = auto_exit_at(context.get("warranty_until"), 0)
    exit_reason = reason or ("真实质保尚未结束" if not deadline or deadline.timestamp() > time.time() else "")
    return {"can_update": not reason, "can_exit_now": not exit_reason,
            "reason": reason, "exit_now_reason": exit_reason}


def _assert_exit_identity_current(session, job):
    """Never apply an old order action to a re-invited/rebound child."""
    from core.db import (GptPlanAccountModel as Account, GptBusinessAccountModel as Mother,
                         GptBusinessChildMembershipModel as Membership)
    schema = inspect(session.connection())
    if _mother_dead_reason(session, job.parent_account_id, job.source_account_id):
        raise RuntimeError(DEAD_MOTHER_REASON)
    if any(not schema.has_table(model.__tablename__) for model in (Account, Mother, Membership)):
        raise RuntimeError("无法核对当前母号与子号归属，请先刷新账号")
    parent = session.get(Account, job.parent_account_id)
    source = session.get(Mother, job.source_account_id)
    child = session.get(Account, job.child_id)
    member = session.get(Membership, job.membership_id)
    email = lambda value: str(value or "").strip().casefold()
    context = _decode(job.context_json)
    if (parent is None or source is None or child is None or member is None
            or parent.source_pool != "gpt_business" or parent.source_account_id != source.id
            or parent.business_parent_id is not None
            or email(parent.email) != email(job.parent_email) or email(source.email) != email(job.parent_email)
            or member.business_account_id != source.id or member.pro_account_id != child.id
            or child.business_parent_id != source.id or member.source != "pool"
            or member.ended_at is not None
            or email(child.email) != email(job.email) or email(member.email) != email(job.email)
            or member.remote_user_id != job.remote_user_id):
        raise RuntimeError("母号或子号归属已变化，不能操作原订单的退出时间")
    date = lambda value: auto_exit_at(value, 0)
    expected_invited = context.get("membership_invited_at") or context.get("oauth_membership_invited_at")
    if context.get("manual_sale") is True:
        if (not expected_invited or date(expected_invited) != date(member.invited_at)
                or member.sale_status != "sold" or date(member.sold_at) != date(context.get("sold_at"))):
            raise RuntimeError("本次邀请或人工出售记录已变化，请刷新后再操作")
        return
    local_card = str(member.nv_remote_card_id or "").strip()
    cards = {str(context.get("nv_remote_card_id") or "").strip()}
    proof = context.get("nv_card_identity")
    if isinstance(proof, dict):
        cards.update(str(proof.get(key) or "") for key in ("inventory_card_id", "order_card_id"))
    absolute = date(getattr(member, "nv_team5x_warranty_until", None))
    frozen = context.get("team5x_warranty")
    frozen_absolute = date(frozen.get("until")) if isinstance(frozen, dict) and frozen.get("mode") == "until" else None
    if absolute is not None:
        warranty_valid = absolute == frozen_absolute == date(context.get("warranty_until"))
    else:
        warranty_valid = (frozen_absolute is None and type(member.warranty_hours) is int
                         and 1 <= member.warranty_hours <= 87600 and date(member.sold_at) is not None
                         and date(member.sold_at) + timedelta(hours=member.warranty_hours) == date(context.get("warranty_until")))
    if (not expected_invited or date(expected_invited) != date(member.invited_at)
            or date(member.nv_listed_at) != date(context.get("nv_listed_at"))
            or date(member.sold_at) != date(context.get("sold_at"))
            or member.sale_status != "sold"
            or local_card not in cards
            or str(member.nv_remote_order_id or "").strip() != str(context.get("nv_remote_order_id") or "").strip()
            or not warranty_valid):
        raise RuntimeError("本次邀请或 NV 出售/质保记录已变化，请刷新后再操作")


def _validate_exit_action(session, job, version, *, immediate):
    if job is None:
        raise KeyError("子号任务不存在")
    if type(version) is not int or version < 0:
        raise ValueError("任务版本无效，请刷新后重试")
    if job.version != version:
        raise RuntimeError("任务状态已更新，请刷新后重试")
    controls = _exit_controls(job)
    key = "can_exit_now" if immediate else "can_update"
    if not controls[key]:
        raise RuntimeError(controls["exit_now_reason"] if immediate else controls["reason"])
    _assert_exit_identity_current(session, job)


def _set_exit_choice(session, job, hours, *, request_id=None):
    now = time.time()
    context = _decode(job.context_json)
    identity = exit_identity(job, context)
    context[EXIT_DELAY_KEY] = {"identity": identity, "hours": hours, "updated_at": _iso(now)}
    manual_immediate = context.get("manual_sale") is True and request_id is not None
    deadline = (datetime.fromtimestamp(now, timezone.utc) if manual_immediate
                else auto_exit_at(context.get("warranty_until"), hours))
    if deadline is None:
        raise RuntimeError("无法确认本次真实质保截止时间")
    due = manual_immediate or deadline.timestamp() <= now
    if due:
        context[MANUAL_EXIT_KEY] = {"identity": identity,
            "request_id": request_id or ("delay-" + uuid.uuid4().hex),
            "requested_at": _iso(now), "warranty_until": context.get("warranty_until"),
            "early_exit": manual_immediate}
    else:
        context.pop(MANUAL_EXIT_KEY, None)
    # In-flight scans are CAS-fenced and cannot restore a deadline from before
    # this operator choice. No scan is requested by this single-order action.
    for key in ("nv_recheck_generation", "nv_recheck_version", "nv_scan_generation", "nv_scan_version"):
        context.pop(key, None)
    job.context_json = _json(context)
    job.step, job.status = ("leave", "pending") if due else ("wait_warranty", "waiting")
    job.next_run_at = _warranty_next_run_at(job, context, deadline, now)
    job.pause_requested = False
    job.reconcile_requested = not due and context.get("quota_rt_recovery") is True
    job.active_parent_key = None
    job.attempts = 0
    job.error = ""
    job.updated_at = now
    job.version += 1
    message = ("已请求人工退出空间；执行前仍核对当前成员身份" if context.get("manual_sale") is True else
               "已结束本单退出延迟，立即进入退出流程；执行前仍核对真实质保与成员身份"
               if request_id else f"本单质保后退出延迟已调整为 {hours:g} 小时；预计退出：{deadline.isoformat()}"
               + ("；已到期，立即进入退出流程" if due else ""))
    _log(session, job, message)
    session.add(job)


def update_job_exit_delay(job_id, *, version, delay_hours):
    hours = normalize_auto_exit_delay_hours(delay_hours)
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        _validate_exit_action(session, job, version, immediate=False)
        _set_exit_choice(session, job, hours)
        return _public(job, _settings_row(session))


def request_job_exit_now(job_id, *, version, request_id):
    if not isinstance(request_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id) is None:
        raise ValueError("退出请求标识无效")
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        if job is not None:
            context = _decode(job.context_json)
            record = context.get(MANUAL_EXIT_KEY)
            if (isinstance(record, dict) and record.get("request_id") == request_id
                    and manual_exit_requested_at(job, context) is not None):
                return _public(job, _settings_row(session))
            # A few historical manual-sale jobs were created before the
            # invitation timestamp became part of the durable sale evidence.
            # The membership row is the authoritative current identity; fill
            # the omitted evidence once, before the normal CAS identity fence
            # runs.  This preserves the fence (all current IDs, sale status
            # and sold timestamp are still checked) while allowing those old
            # jobs to be exited instead of being permanently stuck in review.
            if context.get("manual_sale") is True and not (
                    context.get("membership_invited_at")
                    or context.get("oauth_membership_invited_at")):
                from core.db import GptBusinessChildMembershipModel as Membership
                member = session.get(Membership, job.membership_id)
                if member is not None and member.invited_at is not None:
                    context["membership_invited_at"] = _iso(member.invited_at)
                    job.context_json = _json(context)
                    session.add(job)
        _validate_exit_action(session, job, version, immediate=True)
        _set_exit_choice(session, job, 0.0, request_id=request_id)
        return _public(job, _settings_row(session))


def _worker(job, live_settings=None):
    value = {k: getattr(job, k) for k in ("id", "parent_account_id", "source_account_id", "parent_email",
        "child_id", "email", "membership_id", "remote_user_id", "seat_type", "step", "operation_id",
        "attempts", "version", "worker_token", "reconcile_requested", "status")}
    context = _decode(job.context_json)
    value.update(settings=with_legacy_prices(_decode(job.settings_json)), context=context,
                 **_oauth_public_fields(context))
    if live_settings is not None:
        # Until a child is reserved, retries follow the current source policy.
        # Once bound, its provider/seat checkpoint owns this production cycle.
        if not job.child_id and not job.email and not job.membership_id:
            value["settings"]["mail_provider"] = live_settings.get("mail_provider", "auto")
        value["settings"]["auto_publish_prolite_to_nv"] = live_settings.get("auto_publish_prolite_to_nv", True) is True
        value["settings"]["auto_exit"] = bool(live_settings["auto_exit"])
        value["settings"]["auto_exit_delay_hours"] = live_settings.get("auto_exit_delay_hours", 2.0)
        for key in TIER_DELAY_KEYS:
            value["settings"][key] = with_legacy_prices(live_settings).get(key, 2.0)
        value["settings"]["oauth_phone_retry_enabled"] = (
            live_settings.get("oauth_phone_retry_enabled") is True
        )
        if value["context"].get("publish_attempted") is not True:
            # Prices remain live until the single upload checkpoint. Once a
            # POST may have occurred, only that cycle's original price applies.
            live_prices = with_legacy_prices(live_settings)
            for key in (*PRICE_KEYS, "price_yuan", "team5x_warranty_mode", "team5x_warranty_hours", "team5x_warranty_until"):
                if key in live_prices:
                    value["settings"][key] = live_prices[key]
    return value


def list_jobs(q="", status="", page=1, page_size=50, parent_account_id=None, scope="all", managed_only: bool = False):
    if scope not in {"all", "active", "completed"}:
        raise ValueError("任务范围无效")
    page, page_size = max(1, int(page)), max(1, min(100, int(page_size)))
    with Session(engine) as session:
        scan = session.get(NvAutomationSettings, 1)
        settings = _settings(scan)
        query = select(NvAutomationJob).where(NvAutomationJob.status != "cancelled")
        if managed_only:
            # Filter before counting/pagination; an empty managed scope must
            # stay empty while unfiltered historical audit remains available.
            query = query.where(NvAutomationJob.parent_account_id.in_(settings["mother_ids"]))
        if scope == "active":
            query = query.where(NvAutomationJob.status.notin_(TERMINAL_STATUSES))
        elif scope == "completed":
            query = query.where(NvAutomationJob.status == "completed")
        if parent_account_id is not None:
            query = query.where(NvAutomationJob.parent_account_id == int(parent_account_id))
        if status == "attention":
            query = query.where(NvAutomationJob.status.in_(("failed", "review")))
        elif status:
            query = query.where(NvAutomationJob.status == status)
        if q.strip():
            term = "%" + q.strip().replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.where(NvAutomationJob.email.ilike(term, escape="\\") | NvAutomationJob.parent_email.ilike(term, escape="\\"))
        rows = session.exec(query.order_by(NvAutomationJob.created_at.desc())).all()
        paused = set(settings["paused_mother_ids"])
        items = [_public(j, scan) for j in rows[(page - 1) * page_size:page * page_size]]
        for item in items:
            item["paused_by_mother"] = item["parent_account_id"] in paused
        return dict(items=items, total=len(rows), page=page, page_size=page_size)


def _queue_job_status(job):
    return job.resume_status if job.status == "paused" else job.status


def _mother_queue(mother, jobs, settings, scan):
    """Explain stored state only; a due time is not a promise to start work."""
    parent_id = int(mother["id"])
    selected = parent_id in settings["mother_ids"]
    paused = parent_id in settings["paused_mother_ids"]
    active = [job for job in jobs if job.status not in TERMINAL_STATUSES]
    counts = {step: sum(job.step == step for job in active) for step in STEP_LABELS if step != "done"}

    def priority(job):
        status = _queue_job_status(job)
        rank = (0 if job.status == "running" else 1 if status == "review" else
                2 if status == "failed" else 3 if job.status != "paused" and job.step in PRODUCTION else
                4 if job.status != "paused" and job.step == "leave" else
                5 if job.status != "paused" and job.step == "wait_warranty" else
                6 if job.status != "paused" else 7)
        return rank, job.next_run_at, job.created_at, job.id

    current = min(active, key=priority) if active else None
    public = _public(current, scan) if current else None
    if public:
        public["paused_by_mother"] = paused
        public["error"] = safe_message(public["error"])
    queue = dict(selected=selected, paused=paused, state="ready", state_label="等待调度", reason="",
                 wait_reason=None,
                 current_job=public, active_job_count=len(active), task_counts=counts,
                 next_check_at=None, next_check_label="尚无确定检查时间")
    notes = []
    if not selected:
        notes.append("该母号未在已保存的接管范围内，后续任务不再调度")
    if not settings["enabled"]:
        notes.append("自动售号已关闭，后续任务不再调度")
    if paused:
        notes.append("母号已暂停，后续任务不再调度")
    if mother.get("selectable") is False:
        notes.append("母号当前不可接管：" + safe_message(mother.get("reason") or "资格不满足"))
    elif current and mother.get("eligible") is not True:
        notes.append("当前新邀请条件未满足：" + safe_message(mother.get("reason") or "资格待确认"))
    for status, label in (("review", "需核对"), ("failed", "失败")):
        count = sum(job is not current and _queue_job_status(job) == status for job in active)
        if count:
            notes.append(f"另有 {count} 条{label}任务，请查看该母号全部任务")

    def finish(state, label, reason):
        queue.update(state=state, state_label=label,
                     reason=safe_message("； ".join([reason, *notes])))
        return queue

    def scan_time():
        if scan and scan.scan_token:
            queue["next_check_label"] = "NV 扫描进行中"
        else:
            queue["next_check_at"] = _iso(scan.next_scan_at) if scan else None
            queue["next_check_label"] = "下次 NV 扫描" if queue["next_check_at"] else "等待 NV 扫描调度"

    if mother.get("processing_blocked_reason") == DEAD_MOTHER_REASON:
        queue["wait_reason"] = "unavailable"
        queue["next_check_label"] = "已停止自动处理"
        return finish("unavailable", "母号已停用", DEAD_MOTHER_REASON)
    if current and current.status == "running":
        if current.pause_requested:
            notes.append("当前任务已请求暂停，将在当前步骤结束后停止")
        queue["next_check_label"] = "当前步骤执行中，结束时间未确定"
        return finish("running", "执行中", f"正在{public['step_label']}；当前执行尚未中止")
    if current and _queue_job_status(current) in {"review", "failed"}:
        state = _queue_job_status(current)
        if current.status == "paused":
            notes.append("该任务当前已暂停，恢复前仍需处理异常")
        return finish(state, STATUS_LABELS[state], safe_message(current.error) or
                      ("远端结果需要核对，不会自动重复提交" if state == "review" else "任务失败，请查看原因后处理"))
    if not selected:
        return finish("not_selected", "未接管", "尚未保存接管该母号")
    if not settings["enabled"]:
        return finish("disabled", "全局已关闭", "尚未执行的任务不会启动")
    if paused:
        return finish("paused", "母号已暂停", "恢复母号后才会继续调度")
    if current and current.status == "paused":
        return finish("job_paused", "任务已暂停", "当前任务需要手动恢复")
    if current and current.step in WAIT_STEPS and current.status == "waiting" and not current.reconcile_requested:
        if _manual_sale_mode(current):
            sold = _decode(current.context_json).get("manual_sale") is True
            if sold:
                queue["next_check_at"] = _iso(current.next_run_at)
                queue["next_check_label"] = "自动退出倒计时"
                return finish("wait_warranty", "人工已售出", "按退出延迟等待自动退出核验")
            queue["next_check_at"] = None
            queue["next_check_label"] = "等待人工操作"
            return finish("wait_sale", "人工已售出" if sold else "待人工售卖",
                          "RT 已完成，未上传 NV；出售后点击已售出")
        scan_time()
        delay = job_exit_delay(current, settings)
        delay_reason = (f"真实质保截止后仍保留 {delay:g} 小时缓冲；到达最早自动退出时间后，仍需核实远端出售与成员身份"
                        if delay is not None else "账号档位待核验，暂不安排自动退出；等待 NV 额度证据")
        reason = ("已上架，等待远端出售证据" if current.step == "wait_sale" else
                  delay_reason)
        if current.step == "wait_warranty" and not settings["auto_exit"]:
            notes.append("自动退出未开启；手动退出不受质保后额外延迟限制")
        if scan and scan.scan_error:
            notes.append("最近 NV 扫描失败：" + safe_message(scan.scan_error))
        return finish(current.step, STEP_LABELS[current.step], reason)
    if current and current.step == "leave" and not settings["auto_exit"]:
        return finish("wait_auto_exit", "等待退出授权", "自动退出未开启，不会执行退出操作")
    if not current:
        if mother.get("selectable") is False:
            queue["wait_reason"] = "unavailable"
            return finish("unavailable", "不可接管", safe_message(mother.get("reason") or "母号资格不满足"))
        if mother.get("eligible") is not True:
            blocker = mother.get("invite_blocker")
            if isinstance(blocker, str) and blocker in {"invite_quota", "invite_cooldown", "seat_capacity", "unavailable"}:
                queue["wait_reason"] = blocker
            if blocker == "unavailable":
                return finish("unavailable", "不可邀请", safe_message(mother.get("reason") or "母号资格不满足"))
            queue["next_check_at"] = mother.get("next_available_at") or None
            queue["next_check_label"] = ("预计资格恢复时间（不代表任务启动）" if queue["next_check_at"]
                                         else "等待邀请条件恢复，检查时间未确定")
            if blocker == "invite_quota":
                return finish("waiting_capacity", "等待邀请额度",
                              f"{BUSINESS_INVITE_WINDOW_HOURS} 小时邀请额度已用完；额度恢复后仍需重新检查席位及其他邀请条件")
            if blocker == "invite_cooldown":
                return finish("waiting_capacity", "等待邀请冷却", safe_message(mother.get("reason") or "母号邀请失败冷却中"))
            if blocker == "seat_capacity":
                return finish("waiting_capacity", "等待可用席位", safe_message(mother.get("reason") or "暂无已确认可邀请席位"))
            return finish("waiting_capacity", "等待邀请条件", safe_message(mother.get("reason") or "暂无可邀请席位或额度"))
    needs_preflight = not current or (current.step in {"select", "invite"} and not current.reconcile_requested)
    if needs_preflight and (not scan or not scan.scan_verified_at or scan.scan_error):
        scan_time()
        if scan and scan.scan_error:
            return finish("preflight_failed", "NV 预检未通过", safe_message(scan.scan_error))
        return finish("preflight", "等待 NV 首次预检", "NV 完整只读预检通过后才会开始新的邀请")
    if current:
        queue["next_check_at"] = _iso(current.next_run_at)
        queue["next_check_label"] = "最早可调度时间（仍受并发与资格限制）" if queue["next_check_at"] else "等待任务调度"
        return finish("production", "等待核对调度" if current.reconcile_requested else "等待调度", f"{public['step_label']}：{STATUS_LABELS.get(current.status, '待执行')}" +
                      ("；" + safe_message(current.error) if current.error else ""))
    return finish("ready", "可邀请，等待调度", "邀请条件已满足，等待调度器建立任务；尚无确定启动时间")


def summarize_mothers(discovered):
    """Attach queues from all durable jobs, without leases, writes or scans."""
    with Session(engine) as session:
        scan = session.get(NvAutomationSettings, 1)
        settings = _settings(scan)
        items = {int(item["id"]): dict(item) for item in discovered}
        for parent_id in settings["mother_ids"]:
            if parent_id not in items:
                items[parent_id] = dict(id=parent_id, parent_account_id=parent_id,
                    source_account_id=0, email="", parent_email="", note="",
                    business_usage_type=None,
                    selectable=False, eligible=False, reason="母号未返回或已不存在，请核对接管范围",
                    invite_blocker="unavailable",
                    available=0, available_seats=0, available_seat_types={}, seat_type="",
                    quota_remaining=0, next_available_at="")
        grouped = {parent_id: [] for parent_id in items}
        if grouped:
            for job in session.exec(select(NvAutomationJob).where(NvAutomationJob.parent_account_id.in_(list(grouped)))):
                grouped[job.parent_account_id].append(job)
        for parent_id, item in items.items():
            blocked = _mother_dead_reason(session, parent_id, item.get("source_account_id"))
            if blocked:
                item.update(is_dead=True, selectable=False, eligible=False, reason=blocked,
                            invite_blocker="unavailable", processing_blocked_reason=blocked)
            item["queue"] = _mother_queue(item, grouped[parent_id], settings, scan)
        return dict(items=list(items.values()), selected_ids=settings["mother_ids"], paused_ids=settings["paused_mother_ids"])


def get_job(job_id):
    with Session(engine) as session:
        job = session.get(NvAutomationJob, job_id)
        if not job:
            return None
        result = _public(job, session.get(NvAutomationSettings, 1))
        rows = session.exec(select(NvAutomationStep).where(NvAutomationStep.job_id == job_id).order_by(NvAutomationStep.started_at)).all()
        latest = {r.step: r for r in rows}
        # ``dead_cleanup`` is an exceptional branch, not a normal lifecycle
        # step.  Do not render a misleading queued row for every OAuth/invite
        # job merely because the label exists in STEP_LABELS.
        visible_steps = [
            (key, label) for key, label in STEP_LABELS.items()
            if key != "done" and (key != "dead_cleanup" or job.step == "dead_cleanup" or key in latest)
        ]
        result["steps"] = [dict(step=key, label=label, status=latest[key].status if key in latest else ("waiting" if job.step == key else "pending"),
            attempts=latest[key].attempts if key in latest else 0, error=latest[key].error if key in latest else "",
            started_at=_iso(latest[key].started_at) if key in latest else None,
            finished_at=_iso(latest[key].finished_at) if key in latest else None) for key, label in visible_steps]
        result["steps"] = project_invite_steps(result["steps"], job, result)
        logs = session.exec(select(NvAutomationLog).where(NvAutomationLog.job_id == job_id).order_by(NvAutomationLog.id.desc()).limit(200)).all()
        result["logs"] = [dict(id=r.id, step=r.step, message=r.message, created_at=_iso(r.created_at)) for r in reversed(logs)]
        return result


def get_job_context(job_id):
    """Return the internal context for trusted outbound integrations.

    The normal public job representation intentionally omits credentials and
    internal proofs.  Dujiao event replay still needs the immutable sale
    proof to decide whether a callback was already committed.
    """
    with Session(engine) as session:
        job = session.get(NvAutomationJob, job_id)
        if not job:
            return None
        return {"version": int(job.version or 0), "context": _decode(job.context_json)}


def get_counts(managed_only: bool = False):
    with Session(engine) as session:
        counts = {k: 0 for k in STATUS_LABELS if k != "cancelled"}
        query = select(NvAutomationJob.status).where(NvAutomationJob.status != "cancelled")
        if managed_only:
            settings = _settings(session.get(NvAutomationSettings, 1))
            query = query.where(NvAutomationJob.parent_account_id.in_(settings["mother_ids"]))
        for status in session.exec(query):
            counts[status] = counts.get(status, 0) + 1
        return {**counts, "total": sum(counts.values())}


def _log(session, job, message):
    session.add(NvAutomationLog(job_id=job.id, step=job.step, message=safe_message(message)))


def append_log(job_id, token, message):
    with transaction() as session:
        job = _owned(session, job_id, token)
        _log(session, job, message)


def _owned(session, job_id, token):
    job = session.get(NvAutomationJob, job_id)
    if not job or job.status != "running" or not token or job.worker_token != token:
        raise RuntimeError("任务执行权已改变，当前执行已停止")
    if deleted_child_reason(session, job):
        # Recheck inside the checkpoint/result transaction too: deletion could
        # have committed between the preceding cleanup and this lock.
        raise RuntimeError("子号已删除，当前执行已停止")
    return job


def deleted_child_reason(session, job):
    """Prove local deletion, never infer it from health or remote membership.

    Account deletion can clear both child references while retaining the ended
    membership. Missing schemas, a reused email, or conflicting frozen identity
    are not deletion evidence. Read only canonical plan accounts, never PRO.
    """
    from core.db import GptBusinessChildMembershipModel as Membership, GptPlanAccountModel as Account
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    if get("status") in TERMINAL_STATUSES or get("step") == "done":
        return ""
    if get("step") == "dead_cleanup":
        # Canonical removal can purge the dead child before its worker saves
        # the remote readback. This dedicated step owns its stricter completion
        # fence; generic deletion must not prematurely release its mother.
        return ""
    child_id = _positive_identifier(get("child_id"))
    membership_id = _positive_identifier(get("membership_id"))
    email = str(get("email") or "").strip().lower()
    if (not email or email == str(get("parent_email") or "").strip().lower()
            or not (child_id or membership_id)):
        return ""
    schema = inspect(session.connection())
    if not schema.has_table(Account.__tablename__):
        return ""
    # Presence by either ID or email means this is an identity/rebinding issue,
    # not proof that the selected local account was deleted.
    if session.exec(select(Account.id).where(or_(
        Account.id == child_id, func.lower(func.trim(Account.email)) == email,
    ))).first() is not None:
        return ""
    parent = session.exec(select(Account.email, Account.source_pool, Account.source_account_id,
                                 Account.business_parent_id).where(Account.id == get("parent_account_id"))).first()
    if parent and (str(parent.email or "").strip().lower() != str(get("parent_email") or "").strip().lower()
                   or parent.source_pool != "gpt_business" or parent.source_account_id != get("source_account_id")
                   or parent.business_parent_id is not None):
        return ""
    if membership_id:
        if not schema.has_table(Membership.__tablename__):
            return ""
        member = session.get(Membership, membership_id)
        if member is not None:
            if (member.business_account_id != get("source_account_id")
                    or str(member.email or "").strip().lower() != email
                    or (child_id and member.pro_account_id not in (None, child_id))):
                return ""
            if get("remote_user_id") and str(member.remote_user_id or "") != get("remote_user_id"):
                return ""
            context = get("context") if isinstance(job, dict) else _decode(job.context_json)
            context = context if isinstance(context, dict) else {}
            if (context.get("existing_invite_id") and not member.remote_user_id
                    and context["existing_invite_id"] != member.remote_invite_id):
                return ""
            invited = context.get("membership_invited_at")
            member_invited = member.invited_at
            if member_invited is not None and member_invited.tzinfo is None:
                member_invited = member_invited.replace(tzinfo=timezone.utc)
            if (context.get("existing_member") is True and invited
                    and _oauth_time(invited) != member_invited):
                return ""
            target = context.get("leave_target")
            if (get("step") == "leave" and context.get("leave_attempted") is True
                    and member.ended_at is not None and isinstance(target, dict)
                    and get("operation_id") and member.operation_id == get("operation_id")
                    and all(target.get(key) == get(key) for key in (
                        "parent_account_id", "source_account_id", "membership_id", "email", "operation_id"))
                    and target.get("source") == member.source == "pool"
                    and target.get("user_id") == member.remote_user_id
                    and target.get("invite_id") == member.remote_invite_id
                    and target.get("child_id") and (not child_id or target["child_id"] == child_id)):
                # Our confirmed canonical leave may itself purge a Dead child.
                # Keep that job available for _leave's stricter completion proof;
                # cleanup must not replace an authenticated exit with cancellation.
                return ""
            if not child_id:
                if member.ended_at is None or member.source != "pool":
                    return ""
                if member.pro_account_id and session.exec(select(Account.id).where(Account.id == member.pro_account_id)).first() is not None:
                    return ""
        elif not child_id:
            return ""
    return DELETED_CHILD_REASON if child_id or membership_id else ""


def _cancel_deleted_child(session, job, reason):
    job.status = "cancelled"
    job.error = reason
    job.pause_requested = job.reconcile_requested = False
    job.next_run_at = 0
    job.updated_at = job.finished_at = time.time()
    job.version += 1
    # A cancelled worker is fenced immediately. Keep its reservations until
    # the supervisor proves its process exited; an HTTP/browser call might
    # already be in flight when deletion commits.
    if not job.worker_token:
        job.active_parent_key = job.active_child_key = job.active_membership_key = None
        job.worker_pid = 0
    _finish_ledger(session, job, "cancelled", reason)
    _log(session, job, reason)
    session.add(job)


def _cleanup_deleted_children_locked(session, job_ids=None):
    query = select(NvAutomationJob).where(NvAutomationJob.status.notin_(TERMINAL_STATUSES))
    if job_ids is not None:
        query = query.where(NvAutomationJob.id.in_(list(job_ids)))
    removed, parents = [], set()
    for job in session.exec(query).all():
        reason = deleted_child_reason(session, job)
        if reason:
            _cancel_deleted_child(session, job, reason)
            removed.append(job.id)
            parents.add(job.parent_account_id)
    session.flush()
    return dict(cancelled_job_ids=removed, parent_account_ids=sorted(parents))


def cleanup_deleted_child_jobs(job_ids=None):
    """Local, idempotent cleanup; does not invite, complete sales, or scan NV."""
    with transaction() as session:
        return _cleanup_deleted_children_locked(session, job_ids)


def release_cancelled_worker(job_id, token):
    """Supervisor-only release after observing the exact worker process exit."""
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        if not job or job.status != "cancelled" or not token or job.worker_token != token:
            return False
        job.worker_token, job.worker_pid = "", 0
        job.active_parent_key = job.active_child_key = job.active_membership_key = None
        job.updated_at = time.time()
        job.version += 1
        session.add(job)
        return True


def _occupied_worker_clause():
    return or_(NvAutomationJob.status == "running",
               (NvAutomationJob.status == "cancelled") & (NvAutomationJob.worker_token != ""))


def _normalize_oauth_context_additions(context, additions):
    """Validate monotonic counters and closed retry evidence in one update."""
    touched = any(key in additions for key in (
        *OAUTH_COUNT_KEYS, "oauth_failure", "oauth_failure_started_at",
        "oauth_failure_detail", "oauth_retry_ready", "oauth_retry_blocked_reason",
        "oauth_recovery_requested", "oauth_recovery_phone_allowed", "oauth_manual_recovery",
        "oauth_reconcile_only", "oauth_saved_reconcile_at",
    ))
    if not touched:
        return additions

    if "oauth_reconcile_only" in additions:
        if type(additions["oauth_reconcile_only"]) is not bool:
            raise ValueError("已保存 RT 只读核对标记格式无效")
        if context.get("oauth_reconcile_only") is True and additions["oauth_reconcile_only"] is not True:
            raise ValueError("已保存 RT 只读核对不能转为重新授权")
    if "oauth_saved_reconcile_at" in additions:
        value = additions["oauth_saved_reconcile_at"]
        parsed = _oauth_time(value)
        if (parsed is None or parsed > datetime.now(timezone.utc)
                or datetime.fromisoformat(value.strip().replace("Z", "+00:00")).utcoffset() != timedelta(0)):
            raise ValueError("已保存 RT 核对时间格式无效")
        previous = context.get("oauth_saved_reconcile_at")
        if previous and _oauth_time(previous) != parsed:
            raise ValueError("已保存 RT 核对时间不能由执行任务修改")
        additions["oauth_saved_reconcile_at"] = parsed.isoformat()

    if "oauth_manual_recovery" in additions:
        # Only dispatch of a confirmed manual batch can mint this capability.
        # Workers may consume it, never create or replace one in a checkpoint.
        if additions["oauth_manual_recovery"] is not None:
            raise ValueError("人工 OAuth 恢复许可只能由已确认的串行批次创建")
        context.pop("oauth_manual_recovery", None)
        context.pop("_oauth_single_retry_id", None)
        additions.pop("oauth_manual_recovery")

    for key in OAUTH_COUNT_KEYS:
        if key not in additions:
            continue
        current = _oauth_count(context.get(key))
        next_value = _oauth_count(additions[key])
        if next_value is None:
            raise ValueError("OAuth 执行与核对次数格式无效")
        # The first structured value may be reconstructed from exact legacy
        # evidence and can therefore exceed one.  Once present it is a strict
        # monotonic counter: no reset, decrement, or multi-step jump.
        if current is not None and next_value not in {current, current + 1}:
            raise ValueError("OAuth 执行与核对次数不能回退或跳变")
        additions[key] = next_value

    if "oauth_failure" in additions:
        raw_failure = additions["oauth_failure"]
        if raw_failure is None:
            context.pop("oauth_failure", None)
            additions.pop("oauth_failure")
        else:
            failure = normalize_oauth_failure(raw_failure)
            if failure is None:
                raise ValueError("OAuth 失败证据格式无效")
            additions["oauth_failure"] = failure

    if "oauth_failure_detail" in additions:
        raw_detail = additions["oauth_failure_detail"]
        if raw_detail is None or raw_detail == "":
            context.pop("oauth_failure_detail", None)
            additions.pop("oauth_failure_detail")
        elif not isinstance(raw_detail, str):
            raise ValueError("OAuth 失败详情格式无效")
        else:
            additions["oauth_failure_detail"] = safe_message(raw_detail)[:500]

    if "oauth_failure_started_at" in additions:
        raw_started = additions["oauth_failure_started_at"]
        if raw_started is None or raw_started == "":
            context.pop("oauth_failure_started_at", None)
            additions.pop("oauth_failure_started_at")
        elif _oauth_time(raw_started) is None:
            raise ValueError("OAuth 失败时间格式无效")
        else:
            additions["oauth_failure_started_at"] = raw_started.strip()

    if "oauth_retry_ready" in additions and type(additions["oauth_retry_ready"]) is not bool:
        raise ValueError("OAuth 重试许可格式无效")
    if "oauth_recovery_requested" in additions and type(additions["oauth_recovery_requested"]) is not bool:
        raise ValueError("OAuth 恢复许可格式无效")
    if "oauth_recovery_phone_allowed" in additions and type(additions["oauth_recovery_phone_allowed"]) is not bool:
        raise ValueError("OAuth 恢复费用许可格式无效")
    if "oauth_recovery_attempts" in additions and additions["oauth_recovery_attempts"] not in {0, 1}:
        raise ValueError("旧 OAuth 只允许一次受限恢复")

    if "oauth_retry_blocked_reason" in additions:
        reason = additions["oauth_retry_blocked_reason"]
        if reason is None or reason == "":
            context.pop("oauth_retry_blocked_reason", None)
            additions.pop("oauth_retry_blocked_reason")
        elif reason not in OAUTH_RETRY_BLOCKED_REASONS:
            raise ValueError("OAuth 重试阻断原因无效")

    prospective = {**context, **additions}
    if prospective.get("oauth_reconcile_only") is True and (
            _oauth_time(prospective.get("oauth_saved_reconcile_at")) is None
            or prospective.get("oauth_retry_ready") is True
            or prospective.get("oauth_recovery_requested") is True
            or prospective.get("oauth_manual_recovery") is not None):
        raise ValueError("已保存 RT 只读核对不能包含重新授权许可")
    failure = normalize_oauth_failure(prospective.get("oauth_failure"))
    if failure is not None:
        started = _oauth_time(prospective.get("oauth_failure_started_at"))
        oauth_started = _oauth_time(prospective.get("oauth_started_at"))
        if started is None or oauth_started is None or started != oauth_started:
            raise ValueError("OAuth 失败证据与本次执行时间不一致")
        executions = _oauth_count(prospective.get("oauth_execution_attempts"))
        if executions is None or executions < 1:
            raise ValueError("OAuth 失败证据缺少真实执行次数")
    if prospective.get("oauth_retry_ready") is True:
        policy = normalize_task_retry(prospective.get("task_retry"))
        blocked = prospective.get("oauth_retry_blocked_reason")
        allowed_policy = (
            policy == {"strategy": "safe_resume", "reason_code": "network_temporary"}
            or (
                blocked in {"phone_cost_not_authorized", "execution_limit"}
                and policy == {"strategy": "manual", "reason_code": "configuration_required"}
            )
        )
        if (not recoverable_failure(failure)
                or prospective.get("oauth_attempted") is not False
                or not allowed_policy):
            raise ValueError("OAuth 自动重试缺少安全许可证据")
    return additions


def _update_fields(job, values, *, verified_oauth_remote_id=None):
    def validate_nested(value):
        if isinstance(value, dict):
            for key, nested in value.items():
                if re.search(r"(?i)(password|secret|cookie|authorization|(?:^|_)token(?:$|_)|api_key|raw|response)", str(key)):
                    raise ValueError("任务检查点不得保存凭证或原始响应")
                validate_nested(nested)
        elif isinstance(value, list):
            for nested in value:
                validate_nested(nested)
        elif not isinstance(value, (str, int, float, bool, type(None))):
            raise ValueError("任务检查点字段格式无效")

    validate_nested(values)
    context = _decode(job.context_json)
    frozen_identity_changed = any(key in values and values[key] != getattr(job, key) for key in
        ("parent_account_id", "source_account_id", "child_id", "membership_id", "email"))
    if any(key in values and values[key] != getattr(job, key) for key in ("child_id", "email")):
        for key in ("invite_preparation", "invite_preparation_completed",
                    "invite_preparation_started_at", "invite_preparation_finished_at",
                    "invite_candidate_provider", "invite_candidate_seat_type",
                    "gmail_production_alias_id", "gmail_production_source_id"):
            context.pop(key, None)
    remote_changed = "remote_user_id" in values and values["remote_user_id"] != job.remote_user_id
    verified_enrichment = (job.step == "oauth" and not job.remote_user_id
        and bool(verified_oauth_remote_id) and values.get("remote_user_id") == verified_oauth_remote_id)
    if (context.get("security_recovery") or context.get("security_retry")) and (
            frozen_identity_changed or remote_changed and not verified_enrichment):
        raise ValueError("浏览器中断核验不能改变冻结的子号或母号身份")
    if context.get("dead_child_cleanup") and any(
            key in values and values[key] != getattr(job, key) for key in
            ("child_id", "email", "membership_id", "remote_user_id", "seat_type")):
        raise ValueError("停用子号清理不能更改冻结的账号身份")
    if (context.get(EXIT_DELAY_KEY) or context.get(MANUAL_EXIT_KEY)) and any(
            key in values and values[key] != getattr(job, key) for key in
            ("child_id", "email", "membership_id", "remote_user_id")):
        raise ValueError("已设置单号退出策略的订单不能修改子号身份")
    if context.get("publish_attempted") is True and context.get("seat_type") and "seat_type" in values and values["seat_type"] != context["seat_type"]:
        raise ValueError("已尝试上架的销售周期不能修改席位类型")
    for key in ("child_id", "email", "membership_id", "remote_user_id", "seat_type"):
        if key in values:
            setattr(job, key, values[key])
    if "child_id" in values:
        job.active_child_key = str(job.child_id) if job.child_id else None
    if "membership_id" in values:
        job.active_membership_key = str(job.membership_id) if job.membership_id else None
    additions = values.get("context", {})
    if not isinstance(additions, dict) or any(k not in CONTEXT_KEYS for k in additions):
        raise ValueError("任务检查点包含不支持的字段")
    additions = dict(additions)
    if ("invite_candidate_provider" in additions
            and additions["invite_candidate_provider"] not in {None, "icloud", "gmail", "outlook"}):
        raise ValueError("自动邀请候选邮箱类型无效")
    if ("invite_candidate_seat_type" in additions
            and additions["invite_candidate_seat_type"] not in {None, "default", "prolite"}):
        raise ValueError("自动邀请候选席位类型无效")
    for key in ("gmail_production_alias_id", "gmail_production_source_id"):
        if key in additions and additions[key] is not None and (type(additions[key]) is not int or additions[key] <= 0):
            raise ValueError("Gmail 自动售号子号标识无效")
    if not frozen_identity_changed:
        for key in ("invite_candidate_provider", "invite_candidate_seat_type",
                    "gmail_production_alias_id", "gmail_production_source_id"):
            if context.get(key) and key in additions and additions[key] != context[key]:
                raise ValueError("已预留子号不能修改邀请邮箱或席位类型")
    if "publish_preflight" in additions:
        from services.nv_publish_preflight import normalize_preflight
        proof = normalize_preflight(additions["publish_preflight"], job)
        if proof is None:
            raise ValueError("NV 上架预检记录无效或与当前子号不一致")
        additions["publish_preflight"] = proof
    if context.get("publish_attempted") is True and additions.get("publish_attempted") is False:
        raise ValueError("已提交的 NV 上架不能回退成未提交")
    if "invite_preparation" in additions:
        from services.nv_invite_preparation import normalize_preparation
        raw = additions["invite_preparation"]
        proof = normalize_preparation(raw, job)
        if raw is not None and proof is None:
            raise ValueError("邀请前准备记录无效或与当前子号不一致")
        additions["invite_preparation"] = proof
        additions["invite_preparation_completed"] = bool(proof and proof["status"] == "completed")
    if "child_deactivation" in additions:
        from services.nv_dead_child_cleanup import normalize_deactivation_evidence
        proof = normalize_deactivation_evidence(additions["child_deactivation"], job)
        if proof is None:
            raise ValueError("停用证据与当前子号、阶段或邀请周期不一致")
        if context.get("child_deactivation") and context["child_deactivation"] != proof:
            raise ValueError("已记录的子号停用证据不能覆盖或改绑")
        additions["child_deactivation"] = proof
    if "security_recovery" in additions:
        from services.nv_security_recovery import validate_security_recovery
        additions["security_recovery"] = validate_security_recovery(
            job, context.get("security_recovery"), additions["security_recovery"])
    if "security_retry" in additions:
        from services.nv_security_recovery import validate_security_retry
        additions["security_retry"] = validate_security_retry(
            job, context.get("security_retry"), additions["security_retry"])
    if "nv_refund" in additions:
        from services.nv_refund_policy import job_refund
        refund = job_refund(job, {**context, **additions})
        if refund is None:
            raise ValueError("NV 退款证据与当前销售周期不一致")
        previous = context.get("nv_refund")
        if previous and (previous.get("remote_order_id") != refund["remote_order_id"]
                or previous.get("full_refund") and not refund["full_refund"]
                or previous.get("refund_amount_cents", 0) > refund["refund_amount_cents"]):
            raise ValueError("已保存的 NV 退款证据不能回退或改绑订单")
        additions["nv_refund"] = refund
    if "dead_child_cleanup" in additions:
        from services.nv_dead_child_cleanup import validate_checkpoint
        additions["dead_child_cleanup"] = validate_checkpoint(
            job, context.get("dead_child_cleanup"), additions["dead_child_cleanup"])
    if "team5x_warranty" in additions:
        from services.nv_listing_warranty import normalize_team5x_warranty
        additions["team5x_warranty"] = normalize_team5x_warranty(additions["team5x_warranty"], require_future=False)
        previous_warranty = normalize_team5x_warranty(context.get("team5x_warranty"), require_future=False)
        if context.get("publish_attempted") is True and additions["team5x_warranty"] != previous_warranty:
            raise ValueError("已尝试上架的销售周期不能修改 5X 质保截止时间")
    if "leave_preflight" in additions:
        from services.nv_exit_recovery import normalize_leave_preflight
        proof = additions["leave_preflight"]
        normalized = normalize_leave_preflight(proof)
        if proof is not None and normalized is None:
            raise ValueError("退出前会话核验记录无效")
        additions["leave_preflight"] = normalized
    if "invite_progress" in additions:
        proof = additions["invite_progress"]
        if proof is not None:
            proof = normalize_invite_progress(proof, job, require_operation=True)
            if proof is None:
                raise ValueError("邀请进度无效或与当前子号不一致")
        additions["invite_progress"] = proof
    if "security_check" in additions:
        proof = additions["security_check"]
        if proof is None:
            context.pop("security_check", None)
            additions.pop("security_check")
        elif not _security_result(job, {"security_check": proof}):
            raise ValueError("安全核验结果无效或与当前子号不一致")
        else:
            additions["security_check"] = {key: proof[key] for key in
                ("result", "child_id", "membership_id", "email", "checked_at")}
    if "sold_quota" in additions:
        from services.nv_sold_quota import normalize_sold_quota
        identity = {key: getattr(job, key) for key in
                    ("child_id", "membership_id", "email", "remote_user_id")}
        proof = normalize_sold_quota(additions["sold_quota"],
                                     {**identity, "context": {**context, **additions}})
        if proof is None:
            raise ValueError("已售子号额度快照无效或与本次销售周期不一致")
        additions["sold_quota"] = proof
    if "quota_tier" in additions:
        from services.nv_account_tier import normalize_quota_tier
        identity = {key: getattr(job, key) for key in
                    ("child_id", "membership_id", "email", "remote_user_id", "seat_type")}
        proof = normalize_quota_tier(additions["quota_tier"], identity)
        if proof is None:
            raise ValueError("席位额度档位证据无效或与当前子号不一致")
        additions["quota_tier"] = proof
    if "task_retry" in additions:
        additions["task_retry"] = normalize_task_retry(additions["task_retry"])
    additions = _normalize_oauth_context_additions(context, additions)
    if "security_progress" in additions:
        raw_progress = additions["security_progress"]
        if raw_progress is None:
            context.pop("security_progress", None)
            additions.pop("security_progress")
        else:
            progress = normalize_security_progress(raw_progress)
            if progress is None:
                raise ValueError("安全设置子步骤格式无效")
            additions["security_progress"] = progress
    if "invite_failure" in additions:
        raw_failure = additions["invite_failure"]
        if raw_failure is None:
            context.pop("invite_failure", None)
            additions.pop("invite_failure")
        else:
            failure = _normalized_invite_failure(raw_failure)
            if failure is None:
                raise ValueError("邀请前登录失败信息格式无效")
            additions["invite_failure"] = failure
    if (context.get("nv_card_identity") is not None
            and "nv_card_identity" in additions
            and normalized_exit_evidence(additions["nv_card_identity"])
                != normalized_exit_evidence(context["nv_card_identity"])):
        raise ValueError("已确认的 NV 库存与订单卡片关联不能修改")
    if len(_json(additions)) > 24000:
        raise ValueError("任务检查点过大")
    if context.get("publish_attempted") is True:
        for key in ("price_yuan", "seat_type"):
            if key in additions and key in context and additions[key] != context[key]:
                raise ValueError("已尝试上架的销售周期不能修改价格或席位类型")
    if (context.get(EXIT_DELAY_KEY) or context.get(MANUAL_EXIT_KEY)) and (
            exit_identity(job, context) != exit_identity(job, {**context, **additions})):
        raise ValueError("本单退出策略的邀请或 NV 销售周期已变化，请人工核对")
    context.update(additions)
    job.context_json = _json(context)


def _security_start_blocker(job, context):
    """A queue claim is not permission to replay a consumed security grant."""
    from services.nv_security_recovery import normalize_security_recovery, normalize_security_retry, security_has_history
    if context.get("security_retry") is not None:
        grant = normalize_security_retry(context["security_retry"], job)
        if not grant or grant["phase"] != "queued" or grant["prior_attempts"] != job.attempts:
            return "本次安全核验许可已消费或依据已变化，请明确手动重试再核验一次"
        if (grant["kind"] == "security_stage_retry_v1"
                and job.attempts >= min(3, _job_max_attempts(job))):
            return "安全设置当前阶段已达到自动重试上限；可手动重试一次，历史次数保留"
        return ""
    if context.get("security_recovery") is not None:
        grant = normalize_security_recovery(context["security_recovery"], job)
        return "" if grant and grant["phase"] == "queued" else "旧安全恢复许可已消费，请明确手动重试再核验一次"
    if job.attempts >= min(3, _job_max_attempts(job)):
        return "安全核验已达到自动尝试上限，可明确手动重试再核验一次"
    policy = normalize_task_retry(context.get("task_retry"))
    if policy and policy["strategy"] == "manual":
        return "安全核验需要明确手动授权，未自动启动新操作"
    if security_has_history(context) and (not policy or policy["strategy"] not in {"safe_resume", "verify_existing"}
                                          or policy["reason_code"] == "no_remote_attempt"):
        return "原安全任务缺少自动恢复依据，请明确手动核验"
    return ""


def _release_rejected_gmail_candidate(session, job):
    """Release only an uninvited Gmail candidate with persisted production rejection."""
    from services import gmail_store as gmail, gmail_registration as registration
    from services.gmail_production_policy import within_alias_limit
    context = _decode(job.context_json)
    alias = session.get(gmail.GmailAlias, context.get("gmail_production_alias_id"))
    source = session.get(gmail.GmailSource, alias.source_id) if alias else None
    if (not alias or not source or alias.production_job_id != job.id
            or alias.gpt_plan_account_id != job.child_id or alias.email != job.email.lower()
            or context.get("gmail_production_source_id") != alias.source_id
            or job.step != "invite" or job.membership_id or job.remote_user_id
            or context.get("invite_attempted") is not False
            or context.get("invite_confirmed") or context.get("publish_attempted") or context.get("sale_confirmed")
            or not (source.production_blocked or not within_alias_limit(session, alias))):
        raise RuntimeError("Gmail 子号的未邀请状态或生产限制已变化，等待自动重新检查")
    from core.db import GptBusinessChildMembershipModel, GptPlanAccountModel, GptPlanAccountOperationLeaseModel
    plan = session.get(GptPlanAccountModel, job.child_id)
    if (not plan or plan.email.lower() != alias.email or plan.business_parent_id
            or session.exec(select(GptBusinessChildMembershipModel.id).where(
                (GptBusinessChildMembershipModel.pro_account_id == job.child_id)
                | (GptBusinessChildMembershipModel.email == alias.email))).first() is not None):
        raise RuntimeError("Gmail 子号存在空间关联，保留当前记录并等待自动重新检查")
    lease = session.get(GptPlanAccountOperationLeaseModel, job.child_id)
    from datetime import timezone, datetime
    if lease and lease.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        raise RuntimeError("Gmail 子号登录仍在执行，结束后自动改选")
    rejected = dict(child_id=job.child_id, email=alias.email, source_id=source.id,
                    alias_id=alias.id, reason="source_exhausted" if source.production_blocked else "alias_limit_exceeded",
                    remote_invite_sent=False, detected_at=time.time())
    alias.production_job_id = ""
    if not registration._has_registered_identity(*registration._existing(session, alias)):
        alias.registration_status = "failed"
        alias.registration_stage = rejected["reason"]
        alias.registration_error = source.production_block_reason if source.production_blocked else "超过每个 Gmail 母号最多 3 个子号的限制"
        alias.registration_retry_at = None
        plan.enabled = False
        session.add(plan)
    session.add(alias)
    updates = {"child_id": 0, "email": "", "context": {
        "gmail_production_alias_id": None, "gmail_production_source_id": None,
        "invite_preparation": None, "invite_preparation_completed": False,
        "invite_preparation_started_at": None, "invite_preparation_finished_at": None,
        "invite_candidate_provider": None, "invite_candidate_seat_type": None,
        "invite_attempted": False, "invite_started_at": "", "invite_failure": None, "invite_progress": None,
        "gmail_rejected_candidate": rejected,
        "excluded_child_ids": sorted(set(context.get("excluded_child_ids") or []) | {job.child_id}),
    }}
    _update_fields(job, updates)
    session.add(job)
    return updates


def release_rejected_gmail_candidate(job_id, token):
    with transaction() as session:
        job = _owned(session, job_id, token)
        updates = _release_rejected_gmail_candidate(session, job)
        job.updated_at = time.time()
        session.add(job)
        return updates


def reserve_gmail_candidate(job_id, token, *, seat_type="", excluded_ids=None):
    """Commit Gmail alias ownership and NV child identity in one transaction."""
    from core.business_invite_mail_provider import resolve_candidate_mail_provider
    from services.nv_gmail_production import allocate_candidate
    if seat_type not in {"", "default", "prolite"}:
        raise ValueError("Gmail 子号选择的席位类型无效")
    try:
        with transaction() as session:
            job = _owned(session, job_id, token)
            settings = _settings(_settings_row(session))
            if job.pause_requested or not _enabled_for(job, settings):
                raise RuntimeError("任务已暂停或母号策略已变化，未选择 Gmail 子号")
            if (job.step != "select" or job.child_id or job.email
                    or job.membership_id or job.remote_user_id):
                raise RuntimeError("任务已选择子号或阶段已变化，保留原选择")
            if resolve_candidate_mail_provider(settings.get("mail_provider", "auto"), seat_type, session=session) != "gmail":
                raise RuntimeError("邮箱选择策略已变化，将按最新配置重新选择")
            excluded = set(excluded_ids or ())
            excluded.update(row.child_id for row in session.exec(select(NvAutomationJob).where(
                NvAutomationJob.active_child_key.is_not(None), NvAutomationJob.id != job.id)).all() if row.child_id)
            updates = allocate_candidate(session, job, excluded_ids=excluded)
            if updates is None:
                return None
            updates["context"].update(invite_candidate_provider="gmail", invite_candidate_seat_type=seat_type or None)
            if seat_type:
                updates["seat_type"] = seat_type
            _update_fields(job, updates)
            job.updated_at = time.time()
            session.add(job)
            return updates
    except IntegrityError as exc:
        raise RuntimeError("Gmail 子号已被其他任务预留，将重新选择") from exc


def checkpoint(job_id, token, updates):
    cleanup_deleted_child_jobs([job_id])
    policy_paused = False
    try:
        with transaction() as session:
            job = _owned(session, job_id, token)
            settings = _settings(_settings_row(session))
            boundary = any(updates.get("context", {}).get(key) is True for key in
                           ("invite_attempted", "security_attempted", "oauth_attempted", "publish_attempted", "leave_attempted"))
            preparation = updates.get("context", {}).get("invite_preparation")
            boundary = boundary or (bool(_decode(job.context_json).get("gmail_production_alias_id"))
                                    and isinstance(preparation, dict) and preparation.get("status") == "running")
            cleanup_submission = updates.get("context", {}).get("dead_child_cleanup")
            boundary = boundary or (job.step == "dead_cleanup" and isinstance(cleanup_submission, dict)
                                    and cleanup_submission.get("phase") == "submitted")
            manual_leave = (manual_exit_authorized(job)
                and updates.get("context", {}).get("leave_attempted") is True
                and not any(updates.get("context", {}).get(key) is True for key in
                            ("invite_attempted", "security_attempted", "oauth_attempted", "publish_attempted")))
            automatic_blocked = (not _enabled_for(job, settings)
                or (updates.get("context", {}).get("leave_attempted") is True and not settings["auto_exit"]))
            if boundary and (job.pause_requested
                    or _mother_dead_reason(session, job.parent_account_id, job.source_account_id)
                    or (automatic_blocked and not manual_leave)):
                # Commit pause intent, but NOT the attempted marker. The remote
                # call is still forbidden and can be safely reconciled later.
                job.pause_requested = True
                policy_paused = True
            else:
                proposed = updates.get("context", {})
                current_context = _decode(job.context_json)
                if (job.step == "select" and not job.child_id and updates.get("child_id")
                        and proposed.get("invite_candidate_provider")):
                    from core.business_invite_mail_provider import resolve_candidate_mail_provider
                    current_provider = resolve_candidate_mail_provider(
                        settings.get("mail_provider", "auto"), proposed.get("invite_candidate_seat_type"), session=session)
                    if current_provider != proposed["invite_candidate_provider"]:
                        raise RuntimeError("席位默认邮箱配置已变化，将按最新配置重新选择子号")
                prospective_context = {**current_context, **proposed}
                starting_security = (job.step == "security" and proposed.get("security_attempted") is True
                                     and current_context.get("security_attempted") is not True)
                if starting_security:
                    if job.reconcile_requested:
                        raise ValueError("安全状态核对不允许启动新的安全设置")
                    problem = _security_start_blocker(job, current_context)
                    if problem:
                        raise ValueError(problem)
                    if current_context.get("security_retry") is not None:
                        from services.nv_security_recovery import validate_security_retry
                        grant = validate_security_retry(job, current_context["security_retry"], proposed.get("security_retry"))
                        if grant["phase"] != "started":
                            raise ValueError("本次手动安全核验许可尚未消费，未启动新的设置")
                    elif current_context.get("security_recovery") is not None:
                        from services.nv_security_recovery import validate_security_recovery
                        grant = validate_security_recovery(job, current_context["security_recovery"], proposed.get("security_recovery"))
                        if grant["phase"] != "started":
                            raise ValueError("安全设置中断核验许可尚未消费，未启动新的设置")
                prospective_job = {key: updates.get(key, getattr(job, key)) for key in
                                   ("id", "parent_account_id", "source_account_id", "parent_email",
                                    "child_id", "membership_id", "email", "remote_user_id", "seat_type")}
                if proposed.get("leave_attempted") is True and current_context.get("leave_attempted") is not True:
                    if current_context.get("manual_sale") is True:
                        if not manual_exit_authorized(job):
                            raise RuntimeError("人工出售账号必须明确点击退出空间，不能自动退出")
                        _assert_exit_identity_current(session, job)
                    elif prospective_context.get("nv_refund"):
                        from services.nv_refund_policy import assert_refund_exit
                        assert_refund_exit(session, job, prospective_context)
                    else:
                        deadline = auto_exit_at(proposed.get("warranty_until", current_context.get("warranty_until")),
                                                job_exit_delay(prospective_job, settings, prospective_context))
                        if deadline is None or deadline.timestamp() > time.time():
                            raise NvAutomationExitDelayChanged("自动退出延迟已更新或质保时间未确认，尚未发送退出请求")
                current_count = _oauth_count(current_context.get("oauth_execution_attempts"))
                if current_context.get("oauth_reconcile_only") is True and (
                        any(key in proposed and proposed[key] != current_context.get(key)
                            for key in ("oauth_execution_attempts", "oauth_recovery_attempts", "oauth_started_at",
                                        "oauth_membership_invited_at"))
                        or proposed.get("oauth_attempted") is True and current_context.get("oauth_attempted") is not True):
                    raise RuntimeError("本任务仅允许核对已保存 RT，未启动新的 OAuth")
                next_count = (_oauth_count(proposed.get("oauth_execution_attempts"))
                              if "oauth_execution_attempts" in proposed else None)
                starting_oauth = (
                    job.step == "oauth"
                    and proposed.get("oauth_attempted") is True
                    and next_count is not None
                    and next_count == (current_count or 0) + 1
                )
                if "oauth_manual_recovery" in proposed and not starting_oauth:
                    raise RuntimeError("人工 OAuth 恢复许可只能在本次实际执行前消费一次")
                if starting_oauth:
                    if current_context.get("oauth_reconcile_only") is True:
                        raise RuntimeError("本任务仅允许核对已保存 RT，未启动新的 OAuth")
                    expected = (current_count or 0) + 1
                    manual_recovery = (current_context.get("oauth_manual_recovery") is not None
                                       or "oauth_manual_recovery" in proposed)
                    if next_count != expected or (next_count > _job_max_attempts(job) and not manual_recovery):
                        raise RuntimeError("实际 OAuth 已达本任务上限或执行次数证据无效，未启动新的 OAuth")
                    if (proposed.get("oauth_recovery_phone_allowed") is True
                            and settings.get("oauth_phone_retry_enabled") is not True):
                        raise RuntimeError("额外短信费用授权已关闭，未启动新的 OAuth")
                    prior_failure = normalize_oauth_failure(current_context.get("oauth_failure"))
                    if prior_failure and prior_failure["code"] == "sms_balance_insufficient":
                        from services.nv_oauth_balance import oauth_balance_gate
                        balance_problem = oauth_balance_gate.problem()
                        if balance_problem:
                            raise RuntimeError(balance_problem)
                    legacy_recovery = proposed.get("oauth_recovery_attempts") == 1
                    if manual_recovery:
                        grant = current_context.get("oauth_manual_recovery")
                        problem = manual_sms_recovery_problem(current_context,
                            max_executions=_job_max_attempts(job),
                            phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
                            allow_extra_execution=True)
                        batch = (session.get(NvAutomationRetryBatch, grant.get("batch_id"))
                                 if isinstance(grant, dict) and isinstance(grant.get("batch_id"), str) else None)
                        # Minted only by the single-account action endpoint;
                        # absent from CONTEXT_KEYS, so workers cannot create it.
                        single = (isinstance(grant, dict)
                            and isinstance(grant.get("batch_id"), str)
                            and re.fullmatch(r"manual-rt-[a-f0-9]{32}", grant["batch_id"])
                            and current_context.get("_oauth_single_retry_id") == grant["batch_id"])
                        batch_valid = (batch is not None and batch.origin == "manual"
                            and batch.status == "running" and batch.active_key == "active"
                            and batch.current_job_id == job.id)
                        needs_phone = bool(prior_failure and (prior_failure["charge_possible"]
                            or prior_failure["code"] in {"phone_verification_not_authorized", "sms_balance_insufficient"}))
                        old_started = _oauth_time(current_context.get("oauth_started_at"))
                        new_started = _oauth_time(proposed.get("oauth_started_at"))
                        invited = _oauth_time(current_context.get("oauth_membership_invited_at"))
                        if (problem is not None or not manual_sms_recovery_granted(current_context)
                                or not (single or batch_valid)
                                or "oauth_manual_recovery" not in proposed or proposed["oauth_manual_recovery"] is not None
                                or proposed.get("oauth_recovery_requested") is not False
                                or needs_phone and proposed.get("oauth_recovery_phone_allowed") is not True
                                or proposed.get("oauth_recovery_attempts", current_context.get("oauth_recovery_attempts"))
                                   != current_context.get("oauth_recovery_attempts")
                                or invited is None or old_started is None or new_started is None
                                or not invited <= old_started <= new_started <= datetime.now(timezone.utc)
                                or _oauth_time(proposed.get("oauth_membership_invited_at")) != invited
                                or any(key in updates and updates[key] != getattr(job, key)
                                       for key in ("child_id", "membership_id", "email", "remote_user_id"))):
                            raise RuntimeError(problem[1] if problem else "人工 OAuth 恢复许可、批次或邀请周期无效，未启动新的 OAuth")
                        # This grant is consumed durably before launching. It
                        # never turns a rejected SMS into automatic retry evidence.
                    elif legacy_recovery:
                        old_started = _oauth_time(current_context.get("oauth_started_at"))
                        invited = _oauth_time(current_context.get("oauth_membership_invited_at"))
                        if (current_context.get("oauth_recovery_requested") is not True
                                or current_context.get("oauth_recovery_attempts", 0) != 0
                                or current_context.get("oauth_attempted") is not True
                                or current_count is None or current_count < 1
                                or old_started is None or invited is None or invited > old_started
                                or _oauth_time(proposed.get("oauth_membership_invited_at")) != invited
                                or proposed.get("oauth_recovery_requested") is not False
                                or type(proposed.get("oauth_recovery_phone_allowed")) is not bool
                                or (prior_failure is not None and (
                                    prior_failure["code"] not in {"oauth_unknown", "browser_start_failed", "browser_timeout", "control_timeout", "sms_timeout"}
                                    or prior_failure["callback_received"] or prior_failure["exchange_started"]
                                ))):
                            raise RuntimeError("旧 OAuth 恢复许可或邀请周期无效，未启动新的 OAuth")
                        if proposed["oauth_recovery_phone_allowed"] and settings.get("oauth_phone_retry_enabled") is not True:
                            raise RuntimeError("额外短信费用授权已关闭，未启动新的 OAuth")
                        # This is a separately authorized recovery, not proof
                        # that the old failure was terminal. The canonical
                        # caller holds the account lease and forbids SMS when
                        # the live cost policy is off.
                    elif prior_failure is not None or current_context.get("oauth_retry_ready") is True:
                        policy = normalize_task_retry(current_context.get("task_retry"))
                        retry_context = _oauth_context_for_retry(session, job)
                        problem = retry_problem(retry_context,
                            max_executions=_job_max_attempts(job),
                            phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
                            allow_unknown_failure=True)
                        if (current_context.get("oauth_retry_ready") is not True
                                or policy != {"strategy": "safe_resume", "reason_code": "network_temporary"}):
                            raise RuntimeError("OAuth 自动重试缺少安全许可证据，未启动新的 OAuth")
                        if problem:
                            message = ("未授权可能产生的额外短信费用，未启动新的 OAuth"
                                if problem[0] == "phone_cost_not_authorized" else
                                f"OAuth 自动重试缺少安全许可证据：{problem[1]}，未启动新的 OAuth")
                            raise RuntimeError(message)
                        if prior_failure["code"] == "sms_provider_error":
                            invited = _oauth_time(current_context.get("oauth_membership_invited_at"))
                            oauth_started = _oauth_time(current_context.get("oauth_started_at"))
                            next_started = _oauth_time(proposed.get("oauth_started_at"))
                            if (invited is None or invited != _oauth_time(proposed.get("oauth_membership_invited_at"))
                                    or next_started is None or not oauth_started < next_started <= datetime.now(timezone.utc)
                                    or any(key in updates and updates[key] != getattr(job, key) for key in (
                                        "parent_account_id", "source_account_id", "child_id",
                                        "membership_id", "email", "remote_user_id",
                                    ))):
                                raise RuntimeError("OAuth 邀请周期、目标身份或新执行时间已变化，未启动新的 OAuth")
                    elif current_count not in {None, 0}:
                        raise RuntimeError("OAuth 历史执行结果未确认，未启动新的 OAuth")
                if proposed.get("publish_attempted") is True and _decode(job.context_json).get("publish_attempted") is not True:
                    seat_type = proposed.get("seat_type")
                    if seat_type not in {"default", "prolite"}:
                        raise ValueError("NV 上架检查点缺少准确席位类型")
                    tier, _ = job_policy(prospective_job, prospective_context)
                    if tier == "unknown":
                        raise NvAutomationPriceChanged("账号额度档位尚未核验，尚未发送 NV 请求")
                    current_price = _normalized_price(current_context.get("nv_price_override") or price_for_tier(settings, tier) or "")
                    if not current_price or proposed.get("price_yuan") != current_price:
                        raise NvAutomationPriceChanged("上架价格已更新，尚未发送 NV 请求")
                    if tier == "prolite":
                        if settings.get("auto_publish_prolite_to_nv", True) is not True:
                            raise NvAutomationPriceChanged("5X 自动上架已关闭，未发送 NV 请求")
                        from services.nv_listing_warranty import normalize_team5x_warranty, resolve_team5x_warranty
                        started = _oauth_time(proposed.get("publish_started_at"))
                        if started is None:
                            raise ValueError("5X 上架检查点缺少准确开始时间")
                        try:
                            expected_warranty = resolve_team5x_warranty(settings, now=started)
                            submitted_warranty = normalize_team5x_warranty(proposed.get("team5x_warranty"), now=started)
                        except ValueError:
                            raise NvAutomationPriceChanged("5X 质保配置已变化，尚未发送 NV 请求") from None
                        if submitted_warranty != expected_warranty:
                            raise NvAutomationPriceChanged("5X 质保配置已变化，尚未发送 NV 请求")
                    elif proposed.get("team5x_warranty") is not None:
                        raise ValueError("普通席位不能提交 5X 质保")
                    frozen_settings = with_legacy_prices(_decode(job.settings_json))
                    frozen_settings.update({key: settings[key] for key in (*PRICE_KEYS, "price_yuan", "team5x_warranty_mode", "team5x_warranty_hours", "team5x_warranty_until")})
                    job.settings_json = _json(frozen_settings)
                _update_fields(job, updates)
                progress = _decode(job.context_json).get("security_progress")
                previous_progress = normalize_security_progress(current_context.get("security_progress")) or {}
                if (job.step == "security" and isinstance(progress, dict)
                        and (progress.get("stage"), progress.get("status")) != (
                            previous_progress.get("stage"), previous_progress.get("status"))):
                    from services.chatgpt_security_progress import STAGE_LABELS
                    state_label = {"running": "开始", "retrying": "重试", "completed": "完成",
                                   "failed": "失败", "review": "待核对"}.get(progress.get("status"), "状态更新")
                    _log(session, job, "安全子步骤：" + STAGE_LABELS.get(progress.get("stage"), "安全设置")
                         + " · " + state_label)
                if starting_security:
                    # Persist the count with the pre-mutation marker. Queue
                    # claims, local checks and read-only reconciliation cost 0.
                    job.attempts += 1
                    ledger = session.get(NvAutomationStep, job.operation_id)
                    if ledger is not None:
                        ledger.attempts = job.attempts
                        session.add(ledger)
                job.updated_at = time.time()
            session.add(job)
    except IntegrityError:
        raise RuntimeError("该子号已被另一个任务预留，请重新选择") from None
    if policy_paused:
        raise RuntimeError("自动任务已暂停或退出授权已关闭，未发送新的远端请求")


def _positive_identifier(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _safe_identity(value, limit=320):
    value = str(value or "").strip()
    if len(value) > limit or any(ord(character) < 32 for character in value):
        return ""
    return value


def create_existing_child_jobs(candidates):
    """Durably take over current BUSINESS memberships before inviting anew.

    Membership admission is permanent and child reservations are unique, while
    the parent execution reservation is acquired only for a running step.  This
    permits every existing child of one mother to be queued without allowing
    concurrent mutations against that mother.
    """
    created = []
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        if not settings["enabled"]:
            return []
        selected = set(settings["mother_ids"])
        paused = set(settings["paused_mother_ids"])
        existing_memberships = {
            int(value) for value in session.exec(
                select(NvAutomationJob.membership_id)
                .where(NvAutomationJob.membership_id != None)
            ).all() if value
        }
        reserved_children = {
            str(value) for value in session.exec(
                select(NvAutomationJob.active_child_key)
                .where(NvAutomationJob.active_child_key != None)
            ).all() if value
        }
        reserved_memberships = {
            str(value) for value in session.exec(
                select(NvAutomationJob.active_membership_key)
                .where(NvAutomationJob.active_membership_key != None)
            ).all() if value
        }
        for candidate in candidates if isinstance(candidates, list) else []:
            if not isinstance(candidate, dict):
                continue
            if deleted_child_reason(session, candidate):
                continue
            parent_id = _positive_identifier(candidate.get("parent_account_id"))
            membership_id = _positive_identifier(candidate.get("membership_id"))
            child_id = _positive_identifier(candidate.get("child_id"))
            if (
                not parent_id or not membership_id
                or parent_id not in selected or parent_id in paused
                or _mother_dead_reason(session, parent_id, candidate.get("source_account_id"))
                or membership_id in existing_memberships
                or str(membership_id) in reserved_memberships
                or (child_id and str(child_id) in reserved_children)
            ):
                continue
            step = str(candidate.get("step") or "security")
            status = str(candidate.get("status") or "pending")
            error = safe_message(candidate.get("error"))
            if step not in {"security", "oauth", "publish", "wait_sale", "wait_warranty"}:
                step, status = "security", "review"
                error = error or "已有子号接管阶段无效，请人工核对"
            if status not in {"pending", "waiting", "review"}:
                status = "review"
                error = error or "已有子号接管状态无效，请人工核对"
            if status == "waiting" and step not in WAIT_STEPS:
                status = "review"
                error = error or "已有子号等待状态与阶段不一致，请人工核对"
            if status == "pending" and step in WAIT_STEPS:
                status = "waiting"
            raw_context = candidate.get("context")
            raw_context = raw_context if isinstance(raw_context, dict) else {}
            context = {
                key: value for key, value in raw_context.items()
                if key in CONTEXT_KEYS
            }
            context["existing_member"] = True
            job = NvAutomationJob(
                parent_account_id=parent_id,
                source_account_id=_positive_identifier(candidate.get("source_account_id")),
                parent_email=_safe_identity(candidate.get("parent_email")),
                child_id=child_id or None,
                email=_safe_identity(candidate.get("email")),
                membership_id=membership_id,
                remote_user_id=_safe_identity(candidate.get("remote_user_id"), 200),
                seat_type=str(candidate.get("seat_type") or "") if candidate.get("seat_type") in {"default", "prolite"} else "",
                step=step,
                status=status,
                error=error,
                active_child_key=str(child_id) if child_id else None,
                active_membership_key=str(membership_id),
                existing_membership_key=str(membership_id),
                settings_json=_json(settings),
            )
            try:
                _update_fields(job, {"context": context})
            except ValueError:
                job.context_json = _json({"existing_member": True})
                job.status = "review"
                job.error = "已有子号接管证据格式无效，请人工核对"
            try:
                with session.begin_nested():
                    session.add(job)
                    session.flush()
            except IntegrityError:
                continue
            _log(session, job, "已接管母号中的现有子号，建立持久化任务")
            existing_memberships.add(membership_id)
            reserved_memberships.add(str(membership_id))
            if child_id:
                reserved_children.add(str(child_id))
            created.append(job.id)
        if created:
            _request_scan_row(row, "发现现有子号，等待 NV 核对")
            session.add(row)
    return created


def create_discovered_jobs(mothers):
    created = []
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        row = _settings_row(session)
        settings = _settings(row)
        if not settings["enabled"] or not row.scan_verified_at or row.scan_error:
            return []
        if row.scan_verified_config_generation != row.config_generation:
            return []
        selected, paused = set(settings["mother_ids"]), set(settings["paused_mother_ids"])
        # Existing-member production is independent of invitation capacity, but
        # must finish (or be explicitly resolved) before opening a new seat
        # lifecycle for the same mother.
        production_blockers = set(session.exec(
            select(NvAutomationJob.parent_account_id).where(
                or_(
                    NvAutomationJob.status.notin_(TERMINAL_STATUSES)
                    & NvAutomationJob.step.in_(list(PRODUCTION)),
                    (NvAutomationJob.status == "cancelled") & (NvAutomationJob.worker_token != ""),
                ),
            )
        ).all())
        for mother in mothers:
            parent_id = int(mother.get("id") or 0)
            if (parent_id not in selected or parent_id in paused or mother.get("eligible") is not True
                    or mother.get("rotation_blocked") is True
                    or parent_id in production_blockers
                    or _mother_dead_reason(session, parent_id, mother.get("source_account_id"))):
                continue
            job = NvAutomationJob(parent_account_id=parent_id, source_account_id=int(mother.get("source_account_id") or 0),
                parent_email=mother.get("email", ""), seat_type=mother.get("seat_type", ""),
                settings_json=_json(settings))
            session.add(job)
            _log(session, job, "已发现可用母号，建立持久化子号任务")
            production_blockers.add(parent_id)
            created.append(job.id)
        if created:
            _request_scan_row(row, "新生产任务已建立，等待 NV 核对")
            session.add(row)
    return created


def _mother_dead_reason(session, parent_id, source_id=0):
    """Read both authoritative flags; never mutate lifecycle or sales history.

    Some offline store-only installations do not have the account tables. They
    retain their existing behavior; available rows are always checked afresh in
    the caller's transaction, rather than trusting stale discovery/job DTOs.
    """
    if session is None:
        return ""
    from core.db import GptPlanAccountModel as Account, GptBusinessAccountModel as Mother
    table_names = set(inspect(session.connection()).get_table_names())
    source_ids = {int(source_id or 0)}
    if Account.__tablename__ in table_names:
        parent = session.exec(select(Account.dangerous, Account.source_pool, Account.source_account_id)
                              .where(Account.id == int(parent_id or 0))).first()
        if parent is not None:
            if parent[0]:
                return DEAD_MOTHER_REASON
            if parent[1] == "gpt_business":
                source_ids.add(int(parent[2] or 0))
    source_ids.discard(0)
    if source_ids and Mother.__tablename__ in table_names:
        if session.exec(select(Mother.id).where(
                Mother.id.in_(source_ids), Mother.dangerous == True)).first() is not None:
            return DEAD_MOTHER_REASON
    return ""


def _has_processable_mother(session, settings):
    selected = set(settings["mother_ids"]) - set(settings["paused_mother_ids"])
    # Keep empty-scope preflight behavior for legacy callers; a configured scope
    # consisting solely of stopped/paused mothers must not keep polling NV.
    return not settings["mother_ids"] or any(
        not _mother_dead_reason(session, parent_id) for parent_id in selected)


def _enabled_for(job, settings):
    return (settings["enabled"] and job.parent_account_id not in settings["paused_mother_ids"]
            and job.parent_account_id in settings["mother_ids"]
            and not _mother_dead_reason(object_session(job), job.parent_account_id, job.source_account_id))


def _leave_preflight_wait(job):
    """Only a typed, explicit no-mutation result can waive mutation attempts."""
    context = _decode(job.context_json)
    if job.step != "leave" or not context.get("leave_preflight"):
        return None
    from services.nv_exit_recovery import normalize_leave_preflight
    proof = normalize_leave_preflight(context["leave_preflight"])
    if proof is None or any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at")):
        return None
    return proof


def _recover_legacy_leave_preflights_locked(session, settings, *, manual=False, job_id=None):
    """Reconcile only durable proof that the old facade preflight never sent DELETE.

    Retain the old operation and frozen target. The capability must verify the
    evidence again before clearing markers, and waits before any new attempt.
    """
    from services.nv_exit_recovery import legacy_preflight_failure, saved_preflight_failure
    query = select(NvAutomationJob).where(
        NvAutomationJob.step == "leave", NvAutomationJob.status.in_(["review", "failed"]))
    if job_id is not None:
        query = query.where(NvAutomationJob.id == job_id)
    for job in session.exec(query).all():
        if (job.worker_token or job.worker_pid or job.pause_requested
                or _mother_dead_reason(session, job.parent_account_id, job.source_account_id)):
            continue
        authorized = (manual_exit_authorized(job) if manual else
                      _enabled_for(job, settings) and settings["auto_exit"]
                      and manual_exit_requested_at(job) is None)
        if not authorized or not (legacy_preflight_failure(session, job)
                                  or saved_preflight_failure(session, job)):
            continue
        job.status, job.reconcile_requested, job.next_run_at = "pending", True, time.time()
        job.updated_at, job.version = time.time(), job.version + 1
        session.add(job)
        _log(session, job, "已确认原退出仅母号会话预检失败，未发出成员移除；排队核对原操作记录")


def recover_legacy_publish_preflights():
    """Repair old publish reviews caused by a preflight read failure.

    Older workers did not persist ``publish_attempted=False``.  Only rows
    with the exact historical no-send log and no persisted upload evidence are
    migrated; an unknown remote outcome remains in reconciliation.
    """
    from core.db import (GptBusinessAccountModel as Mother,
                         GptBusinessChildMembershipModel as Membership,
                         GptPlanAccountModel as Account)
    from services.nv_order_history import NvSaleOrder
    from services.nv_publish_preflight import has_publish_evidence, normalize_preflight

    prefix = "上架前 NV 只读检查失败，尚未提交账号："
    baseline_error = re.compile(
        r"HTTP 409：本次上架缺少持久、完整的远端空基线\s*；请人工核对，未自动重试")
    harmless_followups = {
        "已请求核对远端结果", "已请求从失败步骤重试", "开始核对：上架 NV",
    }
    now = time.time()
    changed = 0
    with transaction() as session:
        settings = _settings(_settings_row(session))
        if not settings["enabled"]:
            return 0
        tables = set(inspect(session.connection()).get_table_names())
        if not {Account.__tablename__, Mother.__tablename__, Membership.__tablename__,
                NvSaleOrder.__tablename__}.issubset(tables):
            return 0  # Missing canonical tables cannot prove an unused cycle.
        statement = select(NvAutomationJob).where(
            NvAutomationJob.step == "publish",
            NvAutomationJob.status.in_(["review", "failed"]),
        )
        if engine.dialect.name != "sqlite":
            statement = statement.with_for_update()
        for job in session.exec(statement).all():
            context = _decode(job.context_json)
            if (not _enabled_for(job, settings) or job.pause_requested
                    or job.worker_token or job.worker_pid or job.active_parent_key is not None
                    or "publish_preflight" in context or has_publish_evidence(context)
                    or any(context.get(key) for key in (
                        "leave_attempted", "leave_target", "left_at", "manual_sale_required",
                        "child_deactivation", "dead_child_cleanup", "nv_price_edit"))):
                continue
            # A job's absence of upload markers is insufficient: the canonical
            # membership and its saved sale history must agree with that claim.
            member = session.get(Membership, job.membership_id) if job.membership_id else None
            child = session.get(Account, job.child_id) if job.child_id else None
            parent = session.get(Account, job.parent_account_id)
            source = session.get(Mother, job.source_account_id) if job.source_account_id else None
            email = str(job.email or "").strip().casefold()
            parent_email = str(job.parent_email or "").strip().casefold()
            remote = str(job.remote_user_id or "").strip()
            if (any(row is None for row in (member, child, parent, source))
                    or not re.fullmatch(r"[^\s@]+@[^\s@]+", email) or email == parent_email
                    or not parent_email or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", remote)
                    or parent.source_pool != "gpt_business" or parent.business_parent_id is not None
                    or parent.source_account_id != source.id
                    or any(str(row.email or "").strip().casefold() != parent_email for row in (parent, source))
                    or child.business_parent_id != source.id
                    or member.business_account_id != source.id or member.pro_account_id != child.id
                    or any(str(row.email or "").strip().casefold() != email for row in (member, child))
                    or str(member.remote_user_id or "").strip() != remote
                    or member.source != "pool" or member.ended_at is not None
                    or member.sale_status != "unlisted"
                    or any(getattr(member, key) for key in (
                        "nv_listed_at", "nv_listing_confirmed_at", "nv_team5x_warranty_until",
                        "nv_remote_card_id", "nv_remote_order_id", "sold_at",
                        "intent_remote_started", "operation_id", "end_reason"))
                    or job.active_child_key != str(child.id)
                    or job.active_membership_key != str(member.id)):
                continue
            invited = member.invited_at
            invited = (invited.replace(tzinfo=timezone.utc) if invited and invited.tzinfo is None else invited)
            if (invited is None or context.get("membership_invited_at")
                    and _oauth_time(context["membership_invited_at"]) != invited):
                continue
            if session.exec(select(NvSaleOrder.id).where(or_(
                    NvSaleOrder.job_id == job.id, NvSaleOrder.membership_id == member.id,
                    NvSaleOrder.child_id == child.id, func.lower(NvSaleOrder.email) == email))).first():
                continue
            logs = session.exec(select(NvAutomationLog).where(
                NvAutomationLog.job_id == job.id,
            ).order_by(NvAutomationLog.id.desc()).limit(30)).all()
            match = next((row for row in logs if row.step == "publish"
                          and str(row.message or "").startswith(prefix)
                          and str(row.message)[len(prefix):].strip()), None)
            if (match is None or not (invited.timestamp() <= match.created_at <= now)
                    or not (str(job.error or "").strip() == str(match.message).strip()
                            or baseline_error.fullmatch(str(job.error or "").strip()))):
                continue
            # Only the known read-only reconciliation detour may follow the
            # historical no-send result. Any newer execution/error supersedes
            # it, even when a damaged context has lost its upload checkpoint.
            if any(row.step != "publish" or not (
                    str(row.message or "").strip() in harmless_followups
                    or baseline_error.fullmatch(str(row.message or "").strip()))
                    for row in logs if row.id > match.id):
                continue
            proof = {"version": 1, "status": "failed", "remote_publish_sent": False,
                     "started_at": _iso(match.created_at), "finished_at": _iso(match.created_at),
                     "child_id": int(job.child_id or 0), "membership_id": int(job.membership_id or 0),
                     "email": email, "error": safe_message(str(match.message)[len(prefix):])[:500]}
            proof = normalize_preflight(proof, job)
            if proof is None:
                continue
            context.update(publish_attempted=False, publish_preflight=proof,
                           task_retry={"strategy": "safe_resume", "reason_code": "no_remote_attempt"})
            job.context_json = _json(context)
            job.status, job.reconcile_requested, job.next_run_at = "pending", False, now
            job.error = "已确认上次 NV 只读预检未提交账号，自动回到上架前检查"
            job.updated_at, job.version = now, job.version + 1
            # Keep the original failed step and attempt count for audit. The
            # next normal claim creates its own operation/ledger as usual.
            _log(session, job, job.error)
            session.add(job)
            changed += 1
    return changed


def _review_scan_safe(job, settings):
    """Whether a manual *read-only* NV reconciliation may inspect this job."""
    context = _decode(job.context_json)
    return bool(
        not _manual_sale_mode(job)
        and
        job.status in {"review", "failed"}
        and job.step in WAIT_STEPS
        and not job.pause_requested
        and not job.worker_token
        and _enabled_for(job, settings)
        and manual_exit_requested_at(job, context) is None
        and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))
    )


def _review_scan_marker(job):
    context = _decode(job.context_json)
    generation = context.get("nv_recheck_generation")
    version = context.get("nv_recheck_version")
    if (
        job.reconcile_requested is not True
        or not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0
        or not isinstance(version, int) or isinstance(version, bool) or version < 0
    ):
        return None
    return generation, version


def _scan_snapshot_marker(job):
    """Return the exact global-scan snapshot which admitted this job."""
    context = _decode(job.context_json)
    generation = context.get("nv_scan_generation")
    version = context.get("nv_scan_version")
    if (
        not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0
        or not isinstance(version, int) or isinstance(version, bool) or version < 0
    ):
        return None
    return generation, version


def _waiting_scan_safe(job, settings):
    context = _decode(job.context_json)
    manual_sold = (
        context.get("manual_sale") is True
        and isinstance(context.get("sold_at"), str)
        and bool(context.get("sold_at").strip())
        and job.step == "wait_warranty"
    )
    return bool(
        job.status == "waiting"
        and job.step in WAIT_STEPS
        # Parked manual-sale rows are excluded until sold. Once a 5X account
        # is confirmed sold, it still needs the same periodic quota probe as an
        # NV sale; scan_sales already avoids the NV snapshot for manual-only
        # batches and uses the child credential fence instead.
        and (not _manual_sale_mode(job) or manual_sold)
        and not job.pause_requested
        and not job.worker_token
        and _enabled_for(job, settings)
        and manual_exit_requested_at(job, context) is None
        and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))
    )


def _mark_scan_snapshot(job, generation, *, manual):
    """Fence one job into a claimed scan without creating another lease."""
    marker = _scan_snapshot_marker(job)
    if marker == (generation, job.version):
        return
    next_version = int(job.version or 0) + 1
    updates = {
        "nv_scan_generation": generation,
        "nv_scan_version": next_version,
    }
    if manual:
        # Keep the manual request marker live across a failed whole-snapshot
        # read. A later generation may retry it as part of one shared read.
        updates["nv_recheck_version"] = next_version
    _update_fields(job, {"context": updates})
    job.version = next_version


def _nv_recheck_status(job, scan):
    marker = _review_scan_marker(job)
    settings = _settings(scan) if scan else DEFAULTS
    if (
        marker is None
        or marker[1] != job.version
        or not _review_scan_safe(job, settings)
    ):
        return ""
    generation, _version = marker
    if scan and scan.scan_token and generation <= int(scan.scan_claim_generation or 0):
        return "running"
    return "queued"


def _clear_review_scan_marker(job, *, now):
    context = _decode(job.context_json)
    context.pop("nv_recheck_generation", None)
    context.pop("nv_recheck_version", None)
    job.context_json = _json(context)
    job.reconcile_requested = False
    job.updated_at = now
    job.version += 1


def _oauth_reauthorization_problem(job, settings):
    """Return a fail-closed gate only for a new OAuth browser execution.

    Existing saved-credential reconciliation keeps ``oauth_attempted=true``
    and deliberately bypasses this gate because it is read-only and free.
    """
    if job.step != "oauth":
        return None
    context = _oauth_context_for_retry(object_session(job), job)
    # A quota read may discover that the saved RT has been revoked even though
    # the rest of the OAuth bundle is complete.  This is a new, fenced browser
    # acquisition, so the normal "complete credentials" evidence gate does
    # not apply to the intentionally requested quota repair.
    if context.get("quota_rt_recovery") is True:
        if context.get("oauth_attempted") is False and context.get("oauth_retry_ready") is True:
            policy_context = dict(context)
            # Quota repair has its own bounded budget; historical OAuth
            # attempts must not consume the fresh RT reacquisition allowance.
            policy_context["oauth_execution_attempts"] = context.get("quota_rt_recovery_attempts", 0)
            problem = retry_problem(
                policy_context,
                max_executions=_job_max_attempts(job),
                phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
                allow_unknown_failure=True,
            )
            if problem:
                code, message = problem
                return "review" if code == "unconfirmed_evidence" else "failed", code, message
        return None
    is_reauthorization = (
        context.get("oauth_attempted") is False
        and (context.get("oauth_retry_ready") is True or context.get("oauth_failure") is not None)
    )
    if not is_reauthorization:
        return None
    if context.get("oauth_retry_ready") is not True:
        return "review", "unconfirmed_evidence", "执行结果证据不足，未自动重新获取 RT"
    problem = retry_problem(context, max_executions=_job_max_attempts(job),
                            phone_allowed=settings.get("oauth_phone_retry_enabled") is True)
    if problem:
        code, message = problem
        return "review" if code == "unconfirmed_evidence" else "failed", code, message
    policy = normalize_task_retry(context.get("task_retry"))
    if policy != {"strategy": "safe_resume", "reason_code": "network_temporary"}:
        return "review", "unconfirmed_evidence", "OAuth 失败证据需先核对后才能重新授权"
    return None


def _stop_unsafe_oauth_reauthorization(session, job, problem, now):
    status, code, message = problem
    context = _decode(job.context_json)
    # A cost/limit block preserves the validated no-result evidence so an
    # explicit later reconcile can re-evaluate policy without scraping logs.
    context["oauth_retry_ready"] = code in {"phone_cost_not_authorized", "execution_limit"}
    context["oauth_retry_blocked_reason"] = code
    context["task_retry"] = {
        "strategy": "manual",
        "reason_code": "configuration_required"
            if code in {"phone_cost_not_authorized", "execution_limit"}
            else "insufficient_evidence",
    }
    job.context_json = _json(context)
    job.status = status
    job.error = safe_message((job.error + "；" + message).strip("；"))
    job.updated_at = now
    job.version += 1
    _finish_ledger(session, job, status, job.error)
    _log(session, job, message)
    session.add(job)


def claim_manual_exit(job_id=None):
    """Claim only an explicitly requested exit, including with automation off.

    These jobs use the same durable worker/parent reservations and total
    concurrency limit as automation, but do not wait for unrelated NV scans.
    """
    with transaction() as session:
        _cleanup_deleted_children_locked(session, [job_id] if job_id else None)
        settings = _settings(_settings_row(session))
        _recover_legacy_leave_preflights_locked(session, settings, manual=True, job_id=job_id)
        now = time.time()
        # Normalize the same legacy idle lease as claim_due before claiming.
        for idle in session.exec(select(NvAutomationJob).where(
                NvAutomationJob.status != "running", NvAutomationJob.worker_token == "",
                NvAutomationJob.active_parent_key != None)).all():
            idle.active_parent_key = None
            session.add(idle)
        running = session.exec(select(NvAutomationJob).where(_occupied_worker_clause())).all()
        if len(running) >= min(10, settings["max_concurrent"]):
            return None
        parents_busy = {job.parent_account_id for job in running}
        query = select(NvAutomationJob).where(
            NvAutomationJob.step == "leave", NvAutomationJob.status.in_(["pending", "retry", "waiting"]),
            NvAutomationJob.next_run_at <= now,
        )
        if job_id is not None:
            query = query.where(NvAutomationJob.id == job_id)
        for job in session.exec(query.order_by(NvAutomationJob.next_run_at, NvAutomationJob.created_at)).all():
            if (job.worker_token or job.pause_requested or job.parent_account_id in parents_busy
                    or _mother_dead_reason(session, job.parent_account_id, job.source_account_id)
                    or not manual_exit_authorized(job, now=now)):
                continue
            context = _decode(job.context_json)
            if (job.attempts >= _job_max_attempts(job) and not job.reconcile_requested
                    and not _leave_preflight_wait(job)
                    and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))):
                job.status = "failed"
                job.error = "退出前核对未能完成，已达到自动重试上限；可手动再次结束延迟"
                job.updated_at, job.version = now, job.version + 1
                _log(session, job, job.error)
                session.add(job)
                continue
            if any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at")):
                # An explicitly requested reconcile may inspect the original
                # operation, never silently issue another membership DELETE.
                if not job.reconcile_requested or not job.operation_id:
                    job.status, job.error = "review", "退出请求已发出，需先确认执行结果"
                    job.updated_at, job.version = now, job.version + 1
                    _log(session, job, job.error)
                    session.add(job)
                    continue
            else:
                try:
                    _assert_exit_identity_current(session, job)
                except RuntimeError as exc:
                    job.status, job.error = "review", safe_message(exc)
                    job.updated_at, job.version = now, job.version + 1
                    _log(session, job, job.error)
                    session.add(job)
                    continue
            job.active_parent_key = str(job.parent_account_id)
            job.status, job.worker_token = "running", uuid.uuid4().hex
            job.worker_pid, job.worker_host = 0, socket.gethostname()
            job.heartbeat_at = job.step_started_at = job.updated_at = now
            job.attempts += 1
            if not job.reconcile_requested or not job.operation_id:
                job.operation_id = uuid.uuid4().hex
            job.version += 1
            session.add(job)
            ledger = session.get(NvAutomationStep, job.operation_id)
            if ledger:
                ledger.status, ledger.attempts = "running", job.attempts
                ledger.error, ledger.finished_at = "", 0
            else:
                ledger = NvAutomationStep(id=job.operation_id, job_id=job.id, step="leave", attempts=job.attempts)
            session.add(ledger)
            _log(session, job, "开始执行本单退出：重新核对真实质保与当前成员身份")
            value = _worker(job, settings)
            value["occupied_child_ids"] = [int(v) for v in session.exec(select(NvAutomationJob.active_child_key).where(
                NvAutomationJob.active_child_key != None)).all() if v != job.active_child_key]
            return value
    return None


def claim_due():
    _prepare_oauth_balance()
    now = time.time()
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        configuration = _settings_row(session)
        settings = _settings(configuration)
        if not settings["enabled"]:
            return None
        # A running NV scan only fences the mothers admitted to that scan.
        # Production work for unrelated mothers may proceed concurrently.
        scan_parent_ids = _scan_parent_ids(configuration) if configuration.scan_token else set()
        _recover_legacy_leave_preflights_locked(session, settings)
        # Older workers incorrectly reconciled parked manual-sale 5X jobs
        # against NV, turning the intentional empty listing into a review
        # state. Restore those rows to the waiting-for-sale state so the
        # 已售出 action is available again; no remote call is required.
        manual_sale_reviews = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step == "wait_sale",
            NvAutomationJob.status.in_(["review", "failed", "retry"]),
        )).all()
        for job in manual_sale_reviews:
            context = _decode(job.context_json)
            if (context.get("manual_sale_required") is True
                    and context.get("manual_sale") is not True
                    and not context.get("sold_at")
                    and not context.get("publish_attempted")
                    and not context.get("nv_remote_card_id")
                    and not context.get("nv_remote_order_id")):
                job.status = "waiting"
                job.error = "5X 自动上架已关闭，等待人工售卖"
                job.next_run_at = now + 86400
                job.attempts = 0
                job.reconcile_requested = False
                job.updated_at = now
                job.version += 1
                _finish_ledger(session, job, "waiting", job.error)
                _log(session, job, job.error)
                session.add(job)
        # A failed invite with no membership/remote operation is safe to
        # restart from the invite stage.  Older versions parked this case in
        # review after a transient 409, which made the task require a manual
        # click even though no remote mutation had been confirmed.
        invite_reviews = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step == "invite",
            NvAutomationJob.status.in_(["review", "failed"]),
        )).all()
        from core.db import GptBusinessInviteOperationModel
        for job in invite_reviews:
            context = _decode(job.context_json)
            try:
                operation = session.get(GptBusinessInviteOperationModel, job.operation_id) if job.operation_id else None
            except Exception:
                operation = None
            if (job.membership_id is None and not job.remote_user_id
                    and context.get("invite_attempted") is True
                    and (operation is None or not bool(getattr(operation, "remote_started", False)))):
                context.update({"invite_attempted": False, "invite_started_at": "",
                                "invite_progress": None,
                                "task_retry": {"strategy": "safe_resume",
                                                "reason_code": "no_remote_attempt"}})
                job.context_json = _json(context)
                job.status, job.error = "retry", "邀请未产生成员记录，将自动从邀请阶段重试"
                job.next_run_at = now
                job.attempts = 0
                job.reconcile_requested = False
                job.updated_at = now
                job.version += 1
                _finish_ledger(session, job, "retry", job.error)
                _log(session, job, job.error)
                session.add(job)
        retry_batch = _advance_retry_batch_locked(session, settings)
        if (not retry_batch
                and configuration.scan_recovery_generation > configuration.scan_completed_generation):
            return None  # The frozen recovery settled; the pending scan is next.
        now = time.time()  # Include a job prepared by this same transaction.
        # Parent keys are execution leases, not lifecycle ownership.  Older
        # versions retained them between steps; normalize those idle keys so a
        # review task cannot indefinitely hide another existing child.
        idle_parent_keys = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status != "running",
            NvAutomationJob.worker_token == "",
            NvAutomationJob.active_parent_key != None,
        )).all()
        for idle in idle_parent_keys:
            idle.active_parent_key = None
            session.add(idle)
        running = session.exec(select(NvAutomationJob).where(_occupied_worker_clause())).all()
        if retry_batch and (running or not retry_batch.current_job_id or retry_batch.status != "running"):
            return None
        if len(running) >= min(10, settings["max_concurrent"]):
            return None
        browser_busy = sum(j.step in BROWSER_STEPS for j in running)
        parents_busy = {j.parent_account_id for j in running}
        existing_production_parents = {
            candidate.parent_account_id
            for candidate in session.exec(select(NvAutomationJob).where(
                NvAutomationJob.status.notin_(TERMINAL_STATUSES),
                NvAutomationJob.step.in_(list(PRODUCTION)),
            )).all()
            if _decode(candidate.context_json).get("existing_member") is True
        }
        # Repair the one known quota-recovery writeback bug before selecting
        # due work. Review rows are normally never auto-started; this exact
        # marker is the safe exception because no remote result was committed.
        legacy_quota_reviews = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step == "oauth", NvAutomationJob.status == "review",
        )).all()
        for job in legacy_quota_reviews:
            context = _decode(job.context_json)
            if (context.get("quota_rt_recovery") is True
                    and str(job.error or "").startswith("本地步骤结果写回失败：ValueError")):
                context.update({
                    "oauth_attempted": False,
                    "oauth_retry_ready": False,
                    "oauth_failure": None,
                    "oauth_failure_detail": "",
                    "task_retry": None,
                })
                job.context_json = _json(context)
                job.status, job.reconcile_requested = "pending", False
                job.error = "额度恢复任务已从旧版写回异常恢复，将自动重新获取 RT"
                job.next_run_at = now
                job.updated_at = now
                job.version += 1
                _finish_ledger(session, job, "pending", job.error)
                _log(session, job, job.error)
                session.add(job)
        due = session.exec(select(NvAutomationJob).where(NvAutomationJob.status.in_(["pending", "retry", "waiting"]), NvAutomationJob.next_run_at <= now).order_by(NvAutomationJob.next_run_at)).all()
        due.sort(key=lambda job: (
            # An expired warranty/exit deadline has priority over production
            # retries (especially when max_concurrent=1); a stuck RT repair
            # must not delay the actual space-removal operation.
            0 if (job.step == "wait_warranty" and
                  (lambda d: d is not None and d.timestamp() <= now)(
                      auto_exit_at(_decode(job.context_json).get("warranty_until"),
                                   job_exit_delay(job, settings, _decode(job.context_json)))) ) else 1,
            0 if _production_continuation_time(job, now) else 1,
            _production_continuation_time(job, now),
            0 if _decode(job.context_json).get("existing_member") is True and job.step in PRODUCTION else 1,
            job.next_run_at,
            job.created_at,
            job.id,
        ))
        for job in due:
            if job.step == "renew":
                continue  # Dedicated renewal queue repeats its own authorization checks.
            if manual_exit_requested_at(job) is not None:
                continue  # Only the explicit-exit queue handles this request.
            if retry_batch and job.id != retry_batch.current_job_id:
                continue
            existing_member = _decode(job.context_json).get("existing_member") is True
            if (not _enabled_for(job, settings)
                    or (job.step in WAIT_STEPS and not job.reconcile_requested)
                    or job.parent_account_id in parents_busy
                    or job.parent_account_id in scan_parent_ids):
                continue
            oauth_problem = None if job.reconcile_requested else _oauth_reauthorization_problem(job, settings)
            if oauth_problem is not None:
                _stop_unsafe_oauth_reauthorization(session, job, oauth_problem, now)
                continue
            if job.step == "security" and not job.reconcile_requested:
                problem = _security_start_blocker(job, _decode(job.context_json))
                if problem:
                    job.status, job.error = "failed", problem
                    job.updated_at, job.version = now, job.version + 1
                    _finish_ledger(session, job, job.status, job.error)
                    _log(session, job, problem)
                    session.add(job)
                    continue
            if job.status == "retry" and not job.reconcile_requested:
                # Old retry rows must not bypass limits simply because they
                # were saved before finish_step enforced the current policy.
                context = _decode(job.context_json)
                policy = normalize_task_retry(context.get("task_retry"))
                oauth_reauthorization = (
                    job.step in {"oauth", "wait_sale", "wait_warranty"}
                    and context.get("quota_rt_recovery") is True
                    and context.get("oauth_attempted") is False
                ) or (
                    job.step == "oauth"
                    and context.get("quota_rt_recovery") is not True
                    and context.get("oauth_attempted") is False
                    and context.get("oauth_retry_ready") is True
                )
                if context.get("quota_rt_recovery") is True and oauth_reauthorization:
                    retry_count = _oauth_count(context.get("quota_rt_recovery_attempts"))
                elif oauth_reauthorization:
                    retry_count = _oauth_count(context.get("oauth_execution_attempts"))
                else:
                    retry_count = job.attempts
                exhausted = (retry_count is None or retry_count >= _job_max_attempts(job)) and not _leave_preflight_wait(job)
                if job.step == "security" and not _security_start_blocker(job, context):
                    exhausted = False  # A valid one-use grant may exceed the automatic budget.
                unproven = job.step in {"security", "oauth"} and (
                    not policy or policy.get("strategy") not in {"safe_resume", "verify_existing"}
                )
                if exhausted or unproven:
                    job.status = "failed" if exhausted else "review"
                    reason = ("已达到重试上限，未再次启动任务" if exhausted
                              else "旧重试记录缺少安全重试依据，请人工核对；未启动新的安全设置或 OAuth")
                    job.error = safe_message((job.error + "；" + reason).strip("；"))
                    if unproven:
                        context["task_retry"] = {"strategy": "manual", "reason_code": "insufficient_evidence"}
                        job.context_json = _json(context)
                    job.updated_at = now
                    job.version += 1
                    _finish_ledger(session, job, job.status, job.error)
                    _log(session, job, reason)
                    session.add(job)
                    continue
            if (not existing_member and job.step in {"select", "invite"}
                    and not job.reconcile_requested
                    and _decode(job.context_json).get("invite_attempted") is not True
                    and job.parent_account_id in existing_production_parents):
                if retry_batch:
                    _defer_retry_batch_current(session, retry_batch, job, "同母号还有未完成的已有子号任务，保留等待")
                continue
            if job.step == "leave" and not settings["auto_exit"]:
                if retry_batch:
                    _defer_retry_batch_current(session, retry_batch, job, "未开启自动退出，保留原任务等待")
                continue
            if job.step in {"select", "invite"} and not job.reconcile_requested and (
                not configuration.scan_verified_at
                or configuration.scan_error
                or configuration.scan_verified_config_generation != configuration.config_generation
            ):
                if retry_batch:
                    _defer_retry_batch_current(session, retry_batch, job, "等待 NV 完整读取确认，暂未启动本项")
                continue
            if job.step in BROWSER_STEPS and browser_busy >= settings["browser_concurrent"]:
                continue
            job.active_parent_key = str(job.parent_account_id)
            job.status, job.worker_token = "running", uuid.uuid4().hex
            job.worker_pid, job.worker_host = 0, socket.gethostname()
            job.heartbeat_at = job.step_started_at = job.updated_at = now
            # Reconciliation must inspect the original mutation, not invent a
            # new operation identity which could make a remote write repeat.
            if job.step != "security":
                job.attempts += 1
            if not job.reconcile_requested or not job.operation_id:
                job.operation_id = uuid.uuid4().hex
            job.version += 1
            session.add(job)
            ledger = session.get(NvAutomationStep, job.operation_id)
            if ledger:
                ledger.status, ledger.attempts = "running", job.attempts
                ledger.error, ledger.finished_at = "", 0
            else:
                ledger = NvAutomationStep(id=job.operation_id, job_id=job.id, step=job.step, attempts=job.attempts)
            session.add(ledger)
            if job.step in WAIT_STEPS and _decode(job.context_json).get("quota_rt_recovery") is True:
                _log(session, job, "开始执行：售后刷新 RT（保留已售出状态与退出倒计时）")
            else:
                _log(session, job, ("开始核对：" if job.reconcile_requested else "开始执行：") + STEP_LABELS[job.step])
            value = _worker(job, settings)
            value["occupied_child_ids"] = [int(v) for v in session.exec(select(NvAutomationJob.active_child_key).where(NvAutomationJob.active_child_key != None)).all() if v != job.active_child_key]
            return value
    return None


def _production_continuation_time(job, now):
    value = _decode(job.context_json).get(_PRODUCTION_CONTINUATION)
    return value if (job.status == "pending" and job.step in PRODUCTION
                     and type(value) in (float, int) and 0 < value <= now
                     and not job.pause_requested) else 0


def _clear_production_continuation(session, job):
    context = _decode(job.context_json)
    if _PRODUCTION_CONTINUATION in context:
        context.pop(_PRODUCTION_CONTINUATION)
        job.context_json = _json(context)
        session.add(job)


def worker_job(job_id, token):
    cleanup_deleted_child_jobs([job_id])
    with Session(engine) as session:
        job = _owned(session, job_id, token)
        if _mother_dead_reason(session, job.parent_account_id, job.source_account_id):
            raise RuntimeError(DEAD_MOTHER_REASON)
        value = _worker(job, _settings(session.get(NvAutomationSettings, 1)))
        value["occupied_child_ids"] = [int(v) for v in session.exec(select(NvAutomationJob.active_child_key).where(NvAutomationJob.active_child_key != None)).all() if v != job.active_child_key]
        return value


def heartbeat(job_id, token, pid=0):
    cleanup_deleted_child_jobs([job_id])
    with transaction() as session:
        job = _owned(session, job_id, token)
        job.heartbeat_at = time.time()
        if pid:
            job.worker_pid = pid
        session.add(job)


def _finish_ledger(session, job, status, error=""):
    step = session.get(NvAutomationStep, job.operation_id)
    if step:
        step.status, step.error, step.finished_at = status, error, time.time()
        session.add(step)


def _apply_result(session, job, result):
    if job.status == "cancelled":
        raise RuntimeError("子号已删除，旧任务已移除")
    outcome = result.get("outcome")
    if outcome == "cancelled":
        if job.step == "dead_cleanup":
            from services.nv_dead_child_cleanup import finish_locked
            finish_locked(session, job)
            return
        reason = deleted_child_reason(session, job)
        if not reason:
            raise RuntimeError("未确认子号删除，保留原任务等待核对")
        _cancel_deleted_child(session, job, reason)
        return
    if outcome not in {"advance", "wait", "retry", "review", "failed"}:
        raise ValueError("步骤未返回明确结果")
    sold_additions = (result.get("updates") or {}).get("context") or {}
    sold_observation = sold_additions.get("sold_quota")
    if ("_sold_quota_deactivation" in result or sold_additions.get("child_deactivation")
            and isinstance(sold_observation, dict) and sold_observation.get("error_code") == "account_deactivated"):
        from services.nv_sold_quota import validate_sold_deactivation
        validate_sold_deactivation(session, job, result)
        result = {key: value for key, value in result.items() if key != "_sold_quota_deactivation"}
    if (manual_exit_requested_at(job) is not None
            and result.get("next_step", job.step) not in {"leave", "wait_warranty", "done"}):
        raise ValueError("单号退出授权不能启动其他自动售号步骤")
    previous_step = job.step
    if previous_step in WAIT_STEPS:
        current_ledger = session.get(NvAutomationStep, job.operation_id)
        if not current_ledger or current_ledger.step != previous_step:
            job.operation_id = uuid.uuid4().hex
            session.add(NvAutomationStep(id=job.operation_id, job_id=job.id, step=previous_step, attempts=0))
            session.flush()
    values = result.get("updates") or {}
    context = _decode(job.context_json)
    was_quota_recovery = context.get("quota_rt_recovery") is True
    verified_remote = None
    if ((context.get("security_recovery") or context.get("security_retry"))
            and "remote_user_id" in values and values["remote_user_id"] != job.remote_user_id
            and previous_step == "oauth" and outcome == "advance" and result.get("next_step") == "publish"):
        from services.nv_oauth_completion import validate_completion
        verified_remote = validate_completion(session, job, result)
    _update_fields(job, values, verified_oauth_remote_id=verified_remote)
    job.error = safe_message(result.get("error", ""))
    now = time.time()
    delay = max(5, min(86400, int(result.get("delay_seconds") or 60)))
    next_step = result.get("next_step", job.step)
    if next_step not in STEP_LABELS:
        raise ValueError("步骤名称无效")
    quota_recovery_active = _decode(job.context_json).get("quota_rt_recovery") is True
    # A read-only publish preflight has a durable no-send proof.  If the user
    # previously pressed “核对远端结果”, clear that handoff when the safe
    # retry is queued so the scheduler invokes the normal publish preflight
    # instead of looping on reconciliation.
    updated_context = _decode(job.context_json)
    from services.nv_publish_preflight import unsent_preflight
    if (previous_step == next_step == "publish" and outcome in {"wait", "retry"}
            and unsent_preflight(job, updated_context)):
        job.reconcile_requested = False
    if next_step in WAIT_STEPS and quota_recovery_active:
        # A sold account stays in its warranty step; reconcile_requested is the
        # scheduler handoff for the hidden RT-repair substep.
        job.reconcile_requested = True
    elif next_step in WAIT_STEPS and not quota_recovery_active:
        job.reconcile_requested = False
    elif (next_step == "leave" and outcome == "advance"
          and not _decode(job.context_json).get("leave_attempted")):
        # Quota recovery can advance an expired sold account directly to the
        # leave step.  The handoff used the reconciliation worker, but the
        # actual membership removal must run through the normal worker; if the
        # flag leaked into leave, reconcile_step would treat the fresh leave
        # as an unconfirmed old mutation and park it in review.
        job.reconcile_requested = False
    if outcome == "advance":
        # Adapters confirm the effect. The engine never infers remote success.
        job.step = next_step
        job.status = "completed" if next_step == "done" else ("waiting" if next_step in WAIT_STEPS else "pending")
        job.next_run_at = now if job.status == "pending" else now + delay
        job.attempts = 0
        if next_step == "done":
            job.active_child_key = job.active_membership_key = None
            job.finished_at = now
        _finish_ledger(session, job, "completed")
    else:
        job.status = {"wait": "waiting", "retry": "retry", "review": "review", "failed": "failed"}[outcome]
        if outcome == "wait":
            job.step = next_step
            # Checking cooldown, availability or a sale/warranty condition is
            # not a failed operation attempt. Preserve preceding real failures,
            # but do not let condition polling exhaust their retry budget.
            if unsent_preflight(job, _decode(job.context_json)):
                job.attempts = 0  # Only read-only checks occurred; no upload was attempted.
            elif _leave_preflight_wait(job):
                # The typed facade proof establishes no membership DELETE.
                # Historical reconciliation polls must not exhaust its budget.
                job.attempts = 0
            elif previous_step == next_step == "security":
                pass  # No attempt was charged merely for claiming a security check.
            elif not (previous_step == next_step == "leave" and manual_exit_requested_at(job) is not None):
                job.attempts = max(0, job.attempts - 1) if previous_step == next_step else 0
        if outcome == "retry":
            retry_context = _decode(job.context_json)
            retry_policy = normalize_task_retry(retry_context.get("task_retry"))
            if job.step != "security" and job.reconcile_requested and retry_policy == {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}:
                job.attempts = max(0, job.attempts - 1)
            maximum = _job_max_attempts(job)
            quota_reauthorization = (
                previous_step in {"oauth", "wait_sale", "wait_warranty"}
                and retry_context.get("quota_rt_recovery") is True
                and retry_context.get("oauth_attempted") is False
            )
            oauth_reauthorization = quota_reauthorization or (
                previous_step == "oauth"
                and retry_context.get("oauth_attempted") is False
                and retry_context.get("oauth_retry_ready") is True
            )
            if quota_reauthorization:
                retry_count = _oauth_count(retry_context.get("quota_rt_recovery_attempts"))
            elif oauth_reauthorization:
                retry_count = _oauth_count(retry_context.get("oauth_execution_attempts"))
            else:
                retry_count = job.attempts
            security_granted = job.step == "security" and not _security_start_blocker(job, retry_context)
            unknown_extra = bool(
                oauth_reauthorization
                and retry_context.get("oauth_unknown_auto_retry_count", 0) == 0
                and isinstance(retry_context.get("oauth_failure"), dict)
                and retry_context["oauth_failure"].get("code") == "oauth_unknown"
            )
            security_spent = (job.step == "security" and not security_granted
                              and (retry_context.get("security_retry") is not None or retry_context.get("security_recovery") is not None))
            if security_spent:
                job.status = "failed"
                job.error = (job.error + "；" + _security_start_blocker(job, retry_context)).strip("；")
            elif (retry_count is None or retry_count >= maximum) and not (security_granted or unknown_extra):
                job.status = "failed"
                suffix = ("实际 OAuth 已达本任务上限" if oauth_reauthorization
                          else "已达到重试上限")
                job.error = (job.error + "；" + suffix).strip("；")
            else:
                delay = max(delay, [60, 300, 900][min(2, max(0, retry_count - 1))])
        job.next_run_at = now + delay
        _finish_ledger(session, job, job.status, job.error)
    if previous_step != job.step:
        context = _decode(job.context_json)
        context.pop("task_retry", None)
        if previous_step == "security":
            for key in ("security_progress", "security_task_id", "canonical_task_id"):
                context.pop(key, None)
        if previous_step == "oauth":
            for key in ("oauth_failure", "oauth_failure_detail", "oauth_failure_started_at",
                        "oauth_retry_ready", "oauth_retry_blocked_reason", "oauth_manual_recovery",
                        "_oauth_single_retry_id",
                        "oauth_recovery_requested", "oauth_reconcile_only", "oauth_saved_reconcile_at"):
                context.pop(key, None)
        job.context_json = _json(context)
    # A result computed before a config save must not restore an old deadline.
    context = _decode(job.context_json)
    if (job.step in {"wait_warranty", "leave"} and job.status in {"pending", "waiting"}
            and not context.get("nv_refund")
            and not manual_sale_early_exit_authorized(job, context)
            and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))):
        current_settings = _settings(_settings_row(session))
        exit_hours = job_exit_delay(job, current_settings, context)
        deadline = auto_exit_at(context.get("warranty_until"), exit_hours)
        if deadline is not None:
            job.next_run_at = max(_warranty_next_run_at(job, context, deadline, now),
                                  job.next_run_at if _leave_preflight_wait(job) else 0)
            if job.step == "leave" and deadline.timestamp() > now:
                job.step, job.status = "wait_warranty", "waiting"
        elif job.step == "leave":
            job.step, job.status = "wait_warranty", "waiting" if exit_hours is None else "review"
            job.next_run_at = 0
            job.error = ("账号档位待核验，暂不安排自动退出；等待 NV 额度证据" if exit_hours is None
                         else "真实质保截止时间无法确认，不能安排自动退出")
    if (job.step == "wait_warranty" and manual_exit_requested_at(job, context) is not None
            and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))):
        # The immediate worker found a newer real warranty. Withdraw only the
        # pending immediate command; retain the chosen order-specific delay.
        # This lets a later explicit click resume after that warranty ends.
        context.pop(MANUAL_EXIT_KEY, None)
        job.context_json = _json(context)
    if (job.step == "leave" and job.status == "waiting"
            and manual_exit_requested_at(job, context) is not None
            and not any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))):
        # Temporary read failures before any DELETE may retry, but never spin
        # immediately or become stuck when the global automation switch is off.
        if job.attempts >= _job_max_attempts(job) and not _leave_preflight_wait(job):
            job.status = "failed"
            job.error = (job.error + "；退出前核对已达到自动重试上限，可手动再次结束延迟").strip("；")
        else:
            job.status = "retry"
            job.next_run_at = now + max(delay, [60, 300, 900][min(2, max(0, job.attempts - 1))])
    # Sold quota repair borrows the OAuth reconciliation worker while keeping
    # the durable sale/warranty step. Preserve the handoff on every retry so
    # the next claim does not run a normal NV scan and silently skip RT repair.
    job.reconcile_requested = bool(
        context.get("quota_rt_recovery") is True
        and job.step in WAIT_STEPS
        and job.status in {"retry", "waiting", "pending"}
    )
    if job.step == "publish" and job.status in {"retry", "waiting", "pending"}:
        from services.nv_publish_preflight import has_publish_evidence
        # A delayed check after an upload remains reconciliation; only the
        # explicit no-send preflight can return to a fresh publication pass.
        job.reconcile_requested = has_publish_evidence(context)
    if job.pause_requested and job.status != "completed":
        job.resume_status, job.status = job.status, "paused"
        job.pause_requested = False
    if (job.status not in TERMINAL_STATUSES
            and _mother_dead_reason(session, job.parent_account_id, job.source_account_id)):
        # Keep accepted remote evidence and the step ledger, but never let an
        # in-flight result reopen a stopped mother's next operational step.
        if job.status != "paused":
            job.resume_status, job.status = job.status, "paused"
        job.error = DEAD_MOTHER_REASON
        job.next_run_at = 0
    context = _decode(job.context_json)
    if (outcome == "advance" and previous_step in PRODUCTION and job.step in PRODUCTION
            and job.status == "pending" and previous_step != job.step
            and _enabled_for(job, _settings(_settings_row(session)))):
        previous = context.get(_PRODUCTION_CONTINUATION)
        context[_PRODUCTION_CONTINUATION] = (
            previous if type(previous) in (float, int) and 0 < previous <= now else now)
    else:
        context.pop(_PRODUCTION_CONTINUATION, None)
    job.context_json = _json(context)
    # The parent reservation serializes only the active remote step.  Durable
    # production blockers are derived from unfinished jobs, allowing another
    # existing child of this mother to continue after this step stops.
    job.active_parent_key = None
    job.worker_token = ""
    job.worker_pid = 0
    job.updated_at = now
    job.version += 1
    _log(session, job, job.error or ("当前步骤：" + STEP_LABELS[job.step]))
    session.add(job)
    # The accepted worker/scan result and historical sale are committed together.
    # Rejected stale results never reach this write; no remote calls are made.
    from services.nv_order_history import sync_order
    sync_order(session, job)
    if (was_quota_recovery and context.get("quota_rt_recovery") is False
            and outcome == "advance" and job.step == "wait_warranty" and job.status == "waiting"):
        configuration = _settings_row(session)
        _request_scan_row(configuration, "售后 RT 已更新，立即刷新账号额度")
        session.add(configuration)
        _log(session, job, "售后 RT 已恢复，已安排立即查询额度；退出倒计时保持不变")
    if (outcome == "advance" and previous_step == "publish"
            and not _mother_dead_reason(session, job.parent_account_id, job.source_account_id)):
        configuration = _settings_row(session)
        _request_scan_row(configuration, "子号已上架，等待 NV 核对")
        session.add(configuration)


def finish_step(job_id, token, result):
    cleanup_deleted_child_jobs([job_id])
    with transaction() as session:
        job = _owned(session, job_id, token)
        _apply_result(session, job, result)


def _interrupted_result(session, job, message):
    from services.nv_invite_preparation import normalize_preparation, unsent_preparation
    context = _decode(job.context_json)
    if unsent_preparation(job, context):
        from core.db import GptBusinessInviteOperationModel
        operation = session.get(GptBusinessInviteOperationModel, job.operation_id) if job.operation_id else None
        if operation is None or not operation.remote_started:
            proof = normalize_preparation(context.get("invite_preparation"), job)
            reason = "邀请前准备进程中断，未发送邀请；将自动检查已保存的登录及密码/2FA结果后继续"
            if proof["status"] == "running":
                now = datetime.now(timezone.utc).isoformat()
                proof.update(status="failed", updated_at=now, finished_at=now, error=reason)
            return {"outcome": "wait", "delay_seconds": 300, "error": reason,
                    "updates": {"context": {"invite_preparation": proof,
                        "task_retry": {"strategy": "safe_resume", "reason_code": "no_remote_attempt"}}}}
    return {"outcome": "review", "error": message}


def mark_interrupted(job_id, token, message="执行中断，需核对远端结果后继续"):
    try:
        cleanup_deleted_child_jobs([job_id])
        with transaction() as session:
            job = _owned(session, job_id, token)
            _apply_result(session, job, _interrupted_result(session, job, message))
    except RuntimeError:
        pass


def _is_exact_legacy_unsent_invite_review(value):
    return re.fullmatch(
        r"HTTP 409：普通账号登录失败，未发送 BUSINESS 邀请\s*；请人工核对，未自动重试",
        str(value or "").strip(),
    ) is not None


def prepare_legacy_unsent_invite_retry(job_id, expected_version, validator):
    """Move one explicitly selected legacy no-send review to manual retry.

    This is deliberately not a migration or scheduler hook.  A trusted caller
    must name the exact job/version, and a local-only capability validator must
    re-check the frozen mother/child identity while this transaction owns the
    row.  The function never starts a worker or remote operation.
    """
    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", job_id):
        raise ValueError("旧邀请任务编号无效")
    if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 0:
        raise ValueError("旧邀请任务版本无效")
    if not callable(validator):
        raise ValueError("旧邀请任务缺少本地核验器")

    cleanup_deleted_child_jobs([job_id])
    with transaction() as session:
        statement = select(NvAutomationJob).where(NvAutomationJob.id == job_id)
        if engine.dialect.name != "sqlite":
            statement = statement.with_for_update()
        job = session.exec(statement).one_or_none()
        if job is None:
            raise KeyError(job_id)
        if int(job.version) != expected_version:
            raise RuntimeError("旧邀请任务状态已变化，请重新读取后再处理")
        context = _decode(job.context_json)
        settings = _settings(_settings_row(session))
        if (
            job.step != "invite"
            or job.status != "review"
            or job.reconcile_requested
            or job.pause_requested
            or bool(job.worker_token)
            or int(job.worker_pid or 0) != 0
            or job.active_parent_key is not None
        ):
            raise RuntimeError("旧邀请任务当前状态不允许准备人工重试")
        if not _enabled_for(job, settings):
            raise RuntimeError("旧邀请任务的母号未启用、未接管或已暂停")
        if (
            context.get("invite_attempted") is not True
            or not str(context.get("invite_started_at") or "").strip()
            or context.get("invite_failure") is not None
            or job.membership_id is not None
            or bool(str(job.remote_user_id or "").strip())
            or any(context.get(key) for key in (
                "invite_confirmed", "remote_member_id", "security_attempted",
                "oauth_attempted", "publish_attempted", "leave_attempted",
            ))
            or not _is_exact_legacy_unsent_invite_review(job.error)
        ):
            raise RuntimeError("该任务不属于可安全恢复的旧版未发送邀请记录")

        try:
            failure = validator(_worker(job, settings), session)
        except RuntimeError as exc:
            raise RuntimeError(safe_message(exc)) from None
        except Exception:
            raise RuntimeError("旧邀请任务本地核验失败，未修改任务") from None
        failure = _normalized_invite_failure(failure)
        if failure is None or failure.get("remote_invite_sent") is not False:
            raise RuntimeError("旧邀请任务未取得可靠的未发送核验结果")

        _update_fields(job, {"context": {
            "invite_attempted": False,
            "invite_started_at": "",
            "invite_failure": failure,
        }})
        job.status = "failed"
        job.resume_status = "failed"
        job.reconcile_requested = False
        job.error = "旧任务已确认未发送 BUSINESS 邀请，可人工重新登录并邀请"
        job.next_run_at = time.time()
        job.active_parent_key = None
        job.worker_token = ""
        job.worker_pid = 0
        job.worker_host = ""
        job.updated_at = time.time()
        job.version += 1
        _finish_ledger(session, job, "failed", job.error)
        _log(session, job, "已完成旧邀请任务本地核验；未启动登录或邀请，等待人工重试")
        session.add(job)
    return get_job(job_id)


def _apply_job_action(session, job, action):
    """One mutation path shared by single-account UI and confirmed batches."""
    if job.step == "renew" and action in {"retry", "reconcile"}:
        raise RuntimeError("续期任务请通过续期上架按钮恢复，不能使用普通步骤重试")
    if _decode(job.context_json).get("nv_price_edit"):
        raise RuntimeError("该子号正在核对 NV 改价，请先完成价格核对")
    if job.status in TERMINAL_STATUSES:
        raise RuntimeError("子号已删除，旧任务已移除" if job.status == "cancelled" else "任务已完成")
    if action != "pause" and _mother_dead_reason(session, job.parent_account_id, job.source_account_id):
        raise RuntimeError(DEAD_MOTHER_REASON)
    if action == "pause":
        _clear_production_continuation(session, job)
        if job.status == "running":
            job.pause_requested = True
        elif job.status != "paused":
            job.resume_status, job.status = job.status, "paused"
    elif action == "resume" and job.status == "paused":
        job.status = job.resume_status
    elif action == "retry" and (job.status in {"failed", "retry"}
            or job.status == "review" and _stage_retry_mode(job) == "retry"):
        job.status, job.next_run_at = "pending", time.time()
        stage_mode = _stage_retry_mode(job)
        if stage_mode is not None:
            # A manual click authorizes one claim, not a fresh automatic
            # budget. An uncertain write still goes through reconciliation.
            job.reconcile_requested = stage_mode == "reconcile"
        elif job.step != "security":
            job.attempts = 0
    elif action == "reconcile" and job.status in {"review", "failed"}:
        job.status, job.reconcile_requested, job.next_run_at = "pending", True, time.time()
    else:
        raise RuntimeError("当前状态不支持此操作；不确定结果只能先核对")
    job.updated_at = time.time()
    job.version += 1
    _log(session, job, {"pause": "已请求暂停；执行中的步骤完成后停止", "resume": "已恢复调度", "retry": "已请求从失败步骤重试", "reconcile": "已请求核对远端结果"}[action])
    session.add(job)


def _active_retry_batch(session):
    return session.exec(select(NvAutomationRetryBatch).where(NvAutomationRetryBatch.active_key == "active")).first()


def _scheduled_retry_batch(session, generation):
    return session.exec(select(NvAutomationRetryBatch).where(
        NvAutomationRetryBatch.scan_generation == generation,
    ).order_by(NvAutomationRetryBatch.created_at)).first()


def _request_retry_batch_scan(session, row, batch):
    if batch.scan_generation:
        return
    generation = _request_scan_row(row, "手动串行恢复已排队，处理后检查 NV")
    batch.scan_generation = generation
    if not row.scan_token:
        row.scan_recovery_generation = generation
        row.scan_recovery_batch_id = batch.id
    session.add(row)
    session.add(batch)


def _retry_batch_items(batch):
    items = json.loads(batch.items_json)
    if not isinstance(items, list) or len(items) > 500 or any(not isinstance(item, dict) for item in items):
        raise ValueError("串行处理记录格式无效")
    return items


def _retry_batch_oauth_progress(logs):
    """Presentation-only exact log markers; never retry or billing authority."""
    progress = None
    stages = (
        ("RT 任务已启动", "start", "RT 任务已启动"),
        ("[DrissionPage] 启动浏览器", "login", "正在启动登录浏览器"),
        ("[DrissionPage] 1/5", "login", "正在打开 OAuth 授权页"),
        ("[DrissionPage] 2/5", "login", "正在填写登录邮箱"),
        ("[DrissionPage] 3/5", "login", "正在完成登录验证"),
        ("[DrissionPage] 4/5", "login", "正在完成邮箱或 Authenticator 验证"),
        ("[DrissionPage] 5/5", "oauth", "正在完成 OAuth 授权与回调"),
    )
    for log in logs:
        message = str(log.message or "")
        body = re.sub(r"^\s*(?:\[\d{2}:\d{2}:\d{2}\]\s*){0,2}", "", message)
        for marker, stage, label in stages:
            if marker in message:
                progress = dict(stage=stage, label=label, updated_at=_iso(log.created_at))
                break
        # Match only the application's known provider status lines; publish
        # fixed labels, never the logged phone, activation ID or provider body.
        if body.startswith("[smsbower] add_phone 启动 (") or body.startswith("[smsbower] >>> 国家 "):
            progress = dict(stage="phone", label="正在申请验证手机号", updated_at=_iso(log.created_at))
        elif re.fullmatch(r"\[smsbower \d{1,6}/\d{1,2}/\d{1,2}\] 取号成功 \(号码已脱敏,id 已脱敏\)", body):
            progress = dict(stage="phone", label="已取得验证手机号，正在提交", updated_at=_iso(log.created_at))
        elif body.startswith("[smsbower] 等 SMS (max "):
            progress = dict(stage="wait_sms", label="正在等待短信验证码", updated_at=_iso(log.created_at))
            wait = re.fullmatch(r"\[smsbower\] 等 SMS \(max (\d{2,3})s, 轮询 \d{1,2}s\)", body)
            if wait and 60 <= int(wait[1]) <= 300:
                progress["timeout_seconds"] = int(wait[1])
        elif body == "[smsbower] 收到 SMS 验证码（内容不写入日志）":
            progress = dict(stage="wait_sms", label="已收到短信，正在完成验证", updated_at=_iso(log.created_at))
        elif body.startswith("[smsbower]"):
            if "等待短信：已等待" in body:
                progress = dict(stage="wait_sms", label="正在等待短信验证码", updated_at=_iso(log.created_at))
                wait = re.fullmatch(r"\[smsbower\] 等待短信：已等待 (\d{1,3}) / (\d{2,3}) 秒", body)
                if wait and 60 <= int(wait[2]) <= 300 and 0 <= int(wait[1]) <= int(wait[2]):
                    progress.update(elapsed_seconds=int(wait[1]), timeout_seconds=int(wait[2]))
        if "已保存完整 OAuth 凭证" in message:
            progress = dict(stage="save", label="正在核对已保存的 RT", updated_at=_iso(log.created_at))
    return progress


def _retry_item_oauth_evidence(session, batch, item, job):
    """Return only evidence from this item, not a later retry of the same job."""
    if not item.get("started_at") or job is None:
        return {}
    context = _decode(job.context_json)
    if context.get("retry_batch_id") != batch.id:
        return {}
    result = {"oauth_executions_after": _oauth_count(context.get("oauth_execution_attempts"))}
    lower = item["started_at"]
    # A persisted before_start counter can be followed by a launch exception.
    # Only the canonical exact event proves an RT task really got an ID.
    launch = session.exec(select(NvAutomationLog).where(
        NvAutomationLog.job_id == job.id, NvAutomationLog.step == "oauth",
        NvAutomationLog.created_at >= lower,
        NvAutomationLog.message == "RT 任务已启动",
    ).order_by(NvAutomationLog.created_at.desc(), NvAutomationLog.id.desc())).first()
    if launch is not None:
        result.update(oauth_execution_state="started", oauth_attempt_started_at=launch.created_at)
        ledger = session.exec(select(NvAutomationStep).where(
            NvAutomationStep.job_id == job.id, NvAutomationStep.step == "oauth",
            NvAutomationStep.finished_at >= launch.created_at,
        ).order_by(NvAutomationStep.finished_at.desc())).first()
        if ledger is not None:
            result["oauth_attempt_finished_at"] = ledger.finished_at
        logs = session.exec(select(NvAutomationLog).where(
            NvAutomationLog.job_id == job.id, NvAutomationLog.step == "oauth",
            NvAutomationLog.created_at >= launch.created_at,
        ).order_by(NvAutomationLog.created_at.desc(), NvAutomationLog.id.desc()).limit(200)).all()
        result["oauth_progress"] = _retry_batch_oauth_progress(reversed(logs))
    else:
        before, after = item.get("oauth_executions_before"), result["oauth_executions_after"]
        started = _oauth_time(context.get("oauth_started_at"))
        checkpoint = bool(started and started.timestamp() >= lower)
        changed = before != after
        result["oauth_execution_state"] = "unknown" if checkpoint or changed else "not_started"
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if failure and result.get("oauth_execution_state") == "started":
        result["oauth_failure_code"] = failure["code"]
    return result


def _retry_item_summary(item):
    state, status = item.get("oauth_execution_state"), item.get("status")
    if status == "running" and item.get("job_status") in {"failed", "review"}:
        status = item["job_status"]
    if state is None:
        return "历史批次未记录本次 RT 启动证据，请查看该账号日志"
    if status == "queued":
        return "等待本批串行处理，尚未重新获取 RT" if item.get("step") == "oauth" else "等待本批串行处理"
    if status == "running":
        if state == "started":
            if item.get("job_status") == "retry":
                return "本次 RT 步骤已结束，等待下一次有限重试"
            return "本次 RT 任务已启动，正在处理" if not item.get("oauth_attempt_finished_at") else "本次 RT 步骤已结束，正在继续后续流程"
        if state == "unknown":
            return "已记录本次 OAuth 执行检查点，尚未确认 RT 任务启动"
        return "本批正在核对执行条件，尚未重新获取 RT" if item.get("step") == "oauth" else "本批正在处理当前步骤"
    if state == "started":
        if item.get("oauth_failure_code") == "sms_timeout":
            return "本次已重新执行 RT 流程，但再次等待短信超时"
        if status in {"failed", "review"}:
            return "本次 RT 任务已启动，但本轮处理再次失败" if status == "failed" else "本次 RT 任务已启动，结果尚需核对"
        if status == "completed":
            return "本次 RT 任务已启动，已完成本轮处理"
        return "本次 RT 任务已启动，后续处理已暂停或延后"
    if state == "unknown":
        return "本次 OAuth 已记录执行检查点，但没有确认 RT 任务启动的证据"
    if item.get("step") == "oauth":
        return "本次未重新获取 RT；" + (safe_message(item.get("error")) or "仅核对已有凭证或等待执行条件")
    return safe_message(item.get("error")) or "本轮处理已结束"


def _public_retry_batch(session, batch):
    if batch is None:
        return None
    items = []
    updated_at = batch.updated_at
    for saved in _retry_batch_items(batch):
        item = {key: saved.get(key) for key in (
            "job_id", "parent_account_id", "email", "parent_email", "status", "step", "error", "job_status",
            "started_at", "finished_at", "oauth_executions_before", "oauth_executions_after",
            "oauth_attempt_started_at", "oauth_attempt_finished_at", "oauth_execution_state",
            "oauth_progress", "result_summary", "child_id", "display_step", "invite_progress", "invite_failure",
            "invite_preparation", "invite_preparation_completed",
        )}
        # Display current availability using the frozen mother identity, while
        # retaining the batch's historical result and execution evidence.
        item["mother_is_dead"] = bool(_mother_dead_reason(
            session, saved.get("parent_account_id"), saved.get("source_account_id")))
        # Terminal rows are historical evidence, never a view of tomorrow's job.
        if item["status"] in {"running", "queued"}:
            job = session.get(NvAutomationJob, item["job_id"])
            if job and job.status == "cancelled":
                item.update(status="skipped", job_status="cancelled", error=DELETED_CHILD_REASON)
                updated_at = max(updated_at, job.updated_at)
            elif job and item["status"] == "running" and _decode(job.context_json).get("retry_batch_id") == batch.id:
                updated_at = max(updated_at, job.updated_at)
                item.update(email=job.email or item["email"], step=job.step,
                            error=safe_message(job.error) if job.status not in {"pending", "running"} else "", job_status=job.status,
                            next_run_at=_iso(job.next_run_at), attempts=job.attempts)
                item.update(_retry_item_oauth_evidence(session, batch, saved, job))
                item.update(_invite_display_snapshot(job))
                item["result_summary"] = _retry_item_summary(item)
        if item.get("display_step") not in {*STEP_LABELS, "verify_child"}:
            item["display_step"] = item["step"]
        item["step_label"] = (invite_display_label(item["display_step"], item.get("invite_progress"))
                              or STEP_LABELS.get(item["step"], "步骤待确认"))
        item["error"] = safe_message(item.get("error"))
        item["result_summary"] = safe_message(item.get("result_summary") or _retry_item_summary(item))
        for key in ("started_at", "finished_at", "oauth_attempt_started_at", "oauth_attempt_finished_at"):
            item[key] = _iso(item.get(key))
        items.append(item)
    return dict(id=batch.id, status=batch.status, origin=batch.origin,
                scan_generation=batch.scan_generation or None, deferred_count=batch.deferred_count,
                total=len(items),
                finished=sum(item["status"] not in {"queued", "running"} for item in items),
                current_job_id=batch.current_job_id or None, created_at=_iso(batch.created_at),
                updated_at=_iso(updated_at), items=items)


def get_retry_batch(batch_id=None, *, latest_manual=False):
    with Session(engine) as session:
        if batch_id is not None:
            if not isinstance(batch_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", batch_id):
                raise ValueError("串行恢复批次编号无效")
            batch = session.get(NvAutomationRetryBatch, batch_id)
        elif latest_manual:
            batch = session.exec(select(NvAutomationRetryBatch).where(
                NvAutomationRetryBatch.origin == "manual",
            ).order_by(NvAutomationRetryBatch.created_at.desc())).first()
        else:
            batch = _active_retry_batch(session) or session.exec(
                select(NvAutomationRetryBatch).order_by(NvAutomationRetryBatch.created_at.desc())
            ).first()
        return _public_retry_batch(session, batch)


def start_retry_batch(request_id):
    cleanup_deleted_child_jobs()
    if not isinstance(request_id, str):
        raise ValueError("请求 ID 无效")
    try:
        identifier = str(uuid.UUID(request_id))
    except (ValueError, AttributeError):
        raise ValueError("请求 ID 无效") from None
    _prepare_oauth_balance(force=True)
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        reserved_parents = _scan_parent_ids(row)
        if not settings["enabled"]:
            raise RuntimeError("请先启用自动售号")
        # Retries of a request and double-clicks cannot reset attempts twice.
        prior = session.get(NvAutomationRetryBatch, identifier) or _active_retry_batch(session)
        if prior:
            if prior.active_key:
                _request_retry_batch_scan(session, row, prior)
            return _public_retry_batch(session, prior)
        boundary = row.scan_claim_generation if row.scan_token else row.scan_completed_generation
        if row.scan_request_generation > boundary:
            prior = _scheduled_retry_batch(session, row.scan_request_generation)
            if prior:
                return _public_retry_batch(session, prior)
        # The completed recovery for a pending scan cannot be replaced by a
        # stream of manual batches; finish that scan first.
        if (not row.scan_token and row.scan_recovery_generation > row.scan_completed_generation
                and row.scan_recovery_batch_id):
            prior = session.get(NvAutomationRetryBatch, row.scan_recovery_batch_id)
            if prior:
                return _public_retry_batch(session, prior)
        batch = _create_retry_batch_locked(session, settings, identifier)
        _request_retry_batch_scan(session, row, batch)
        return _public_retry_batch(session, batch)


def _legacy_oauth_batch_recovery(job):
    context = _decode(job.context_json)
    if (job.step != "oauth" or context.get("oauth_attempted") is not True
            or context.get("oauth_recovery_attempts", 0) != 0):
        return False
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    return context.get("oauth_failure") is None or (failure is not None
        and failure.get("code") in {"oauth_unknown", "browser_timeout", "control_timeout", "sms_timeout", "browser_start_failed"}
        and failure.get("callback_received") is False and failure.get("exchange_started") is False
    )


def _manual_sms_recovery_context(session, job):
    """Project narrowly audited old 502 evidence without changing durable state.

    Only an explicit manual batch may use this projection. Freezing a batch
    does not alter the original failure or mint permission; dispatch repeats
    the audit before persisting the classification and one-use permission.
    """
    context = _oauth_context_for_retry(session, job)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if job.step == "oauth" and failure and failure["code"] == "sms_provider_error":
        audited = historical_sms_502_failure(session, job)
        if audited is not None:
            context.update(
                oauth_failure=audited,
                oauth_failure_detail=audited["reason"],
                oauth_retry_ready=False,
                oauth_retry_blocked_reason="sms_number_http_502_manual",
            )
    return context


def _oauth_context_for_retry(session, job):
    """Read-only compatibility for exact, closed historical OAuth failures."""
    context = _decode(job.context_json)
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if session is not None and job.step == "oauth" and failure and failure["code"] == "oauth_unknown":
        from services.nv_oauth_password_history import historical_password_page_context
        context = historical_password_page_context(session, job)
        failure = normalize_oauth_failure(context.get("oauth_failure"))
        # Closed unknown outcomes are eligible for a bounded fresh OAuth
        # attempt once the normal cycle/identity fence is present. The marker
        # is a derived projection and does not alter persisted evidence.
        if failure and failure.get("code") == "oauth_unknown":
            context = {**context, "oauth_unknown_auto_retry": True}
    if session is not None and job.step == "oauth" and failure and failure["code"] == "sms_configuration_error":
        from services.nv_oauth_balance_history import historical_sms_balance_failure
        audited = historical_sms_balance_failure(session, job)
        if audited is not None:
            context = {**context, "oauth_failure": audited, "oauth_failure_detail": audited["reason"]}
            failure = audited
    started = _oauth_time(context.get("oauth_started_at"))
    if (session is None or job.step != "oauth" or not started or not failure
            or failure["code"] != "sms_provider_error"):
        return context
    logs = session.exec(select(NvAutomationLog.message).where(
        NvAutomationLog.job_id == job.id, NvAutomationLog.step == "oauth",
        NvAutomationLog.created_at >= started.timestamp(),
    ).order_by(NvAutomationLog.id).limit(501)).all()
    # Controlled logs can veto an inconsistent "no callback" provider DTO.
    # This read-only projection only removes eligibility; it never infers a
    # terminal failure or grants another execution from historical prose.
    from services.nv_oauth_legacy import _contradictory
    if any(_contradictory(str(message)) for message in logs):
        return {**context, "oauth_failure": {**failure, "callback_received": True}}
    # A truncated read cannot exclude a later callback or exchange. Preserve
    # the durable DTO, but remove retry eligibility from this projection until
    # a complete audit can inspect it; do not invent a callback observation.
    if len(logs) > 500:
        return {**context, "oauth_failure": {**failure, "terminal": False, "retryable": False}}
    return classify_legacy_number_request(context, logs)


def _prepare_oauth_balance(*, force=False):
    """Close the read session before any provider call; never take a write lock."""
    needed = False
    with Session(engine) as session:
        settings = _settings(session.get(NvAutomationSettings, 1))
        if not settings["enabled"] or settings.get("oauth_phone_retry_enabled") is not True:
            return
        candidates = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step == "oauth", NvAutomationJob.status.in_(["failed", "review"]),
        )).all()
        for job in candidates:
            if (not _enabled_for(job, settings) or job.pause_requested or job.worker_token or job.worker_pid
                    or _saved_oauth_reconcile_evidence(session, job, settings) is not None):
                continue
            context = _oauth_context_for_retry(session, job)
            failure = normalize_oauth_failure(context.get("oauth_failure"))
            if (failure and failure["code"] == "sms_balance_insufficient" and recovery_evidence_valid(context)):
                needed = True
                break
    if needed:
        from services.nv_oauth_balance import oauth_balance_gate
        oauth_balance_gate.refresh(force=force)


def _saved_oauth_reconcile_evidence(session, job, settings, *, allow_same_saved=False):
    """Return a safe saved timestamp for this frozen cycle; no remote calls.

    Local credentials admit a read-only worker, never prove remote membership
    or grant another OAuth. Rechecking the same saved record after a review
    result requires an explicit manual action; scheduler ticks remain idempotent.
    """
    if (job.step != "oauth" or job.status not in {"failed", "review"}
            or not _enabled_for(job, settings) or job.pause_requested
            or job.worker_token or job.worker_pid or job.active_parent_key):
        return None
    context = _decode(job.context_json)
    if (manual_exit_requested_at(job, context) is not None
            or any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at", "nv_price_edit"))):
        return None
    ids = (job.parent_account_id, job.source_account_id, job.child_id, job.membership_id)
    if any(_positive_identifier(value) == 0 for value in ids):
        return None
    started = _oauth_time(context.get("oauth_started_at"))
    invited = _oauth_time(context.get("oauth_membership_invited_at") or context.get("membership_invited_at"))
    now = datetime.now(timezone.utc)
    if started is None or invited is None or not invited <= started <= now:
        return None
    if any(key in context and _oauth_time(context[key]) != invited
           for key in ("oauth_membership_invited_at", "membership_invited_at")):
        return None

    from core.db import (GptPlanAccountModel as Account, GptBusinessAccountModel as Mother,
                         GptBusinessChildMembershipModel as Membership,
                         GptPlanAccountOperationLeaseModel as AccountLease,
                         ChatGptSecurityOperationLeaseModel as SecurityLease)
    tables = session.info.get("nv_saved_oauth_tables")
    if tables is None:
        tables = session.info["nv_saved_oauth_tables"] = set(inspect(session.connection()).get_table_names())
    if any(model.__tablename__ not in tables for model in (Account, Mother, Membership, AccountLease, SecurityLease)):
        return None  # Missing lease evidence cannot authorize scheduling.
    parent, source = session.get(Account, job.parent_account_id), session.get(Mother, job.source_account_id)
    child, member = session.get(Account, job.child_id), session.get(Membership, job.membership_id)
    email = lambda value: str(value or "").strip().casefold()
    child_email, parent_email = email(job.email), email(job.parent_email)
    if (not re.fullmatch(r"[^\s@]+@[^\s@]+", child_email)
            or not re.fullmatch(r"[^\s@]+@[^\s@]+", parent_email) or child_email == parent_email
            or parent is None or source is None or child is None or member is None
            or parent.source_pool != "gpt_business" or parent.source_account_id != source.id
            or parent.business_parent_id is not None
            or email(parent.email) != parent_email or email(source.email) != parent_email
            or member.business_account_id != source.id or member.pro_account_id != child.id
            or child.business_parent_id != source.id or member.source != "pool" or member.ended_at is not None
            or email(child.email) != child_email or email(member.email) != child_email
            # Source is an identity binding; canonical GPT Plans rows own
            # current availability. Old BUSINESS refund flags may be stale.
            or any(not row.enabled or row.dangerous or row.policy_warning or str(row.refund_status or "").strip()
                   for row in (parent, child))):
        return None

    def utc(value):
        if not isinstance(value, datetime):
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    acquired = utc(child.codex_rt_acquired_at)
    if (utc(member.invited_at) != invited
            or child.business_invited_at is not None and utc(child.business_invited_at) != invited
            or acquired is None or not started <= acquired <= now
            or not all(str(value or "").strip() for value in (
                child.codex_access_token, child.codex_refresh_token, child.codex_id_token))
            or (_oauth_time(context.get("oauth_saved_reconcile_at")) == acquired
                and not (allow_same_saved and context.get("oauth_reconcile_only") is True))):
        return None
    if (job.remote_user_id and member.remote_user_id != job.remote_user_id
            or context.get("existing_invite_id") and not member.remote_user_id
            and member.remote_invite_id != context["existing_invite_id"]):
        return None
    if any(value and (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value))
           for value in (job.remote_user_id, member.remote_user_id, member.remote_invite_id,
                         context.get("existing_invite_id"))):
        return None
    try:
        intent = json.loads(member.intent_payload_json or "{}")
    except (ValueError, TypeError):
        return None
    if (intent != {} or member.intent_remote_started or member.end_reason
            or member.replacement_pro_account_id or member.replacement_email or member.replacement_completed_at):
        return None
    active_members = session.exec(select(Membership.id).where(
        Membership.ended_at == None,
        or_(Membership.pro_account_id == child.id, func.lower(func.trim(Membership.email)) == child_email),
    )).all()
    if active_members != [member.id]:
        return None
    for identifier in (child.id, parent.id):
        lease = session.get(AccountLease, identifier)
        if lease is not None and (utc(lease.expires_at) is None or utc(lease.expires_at) > now):
            return None
    for address in (child_email, parent_email):
        lease = session.get(SecurityLease, address)
        if lease is not None and (utc(lease.expires_at) is None or utc(lease.expires_at) > now):
            return None
    competing = session.exec(select(NvAutomationJob.id).where(
        NvAutomationJob.id != job.id,
        or_(NvAutomationJob.child_id == child.id, NvAutomationJob.membership_id == member.id),
        or_(NvAutomationJob.status == "running", NvAutomationJob.worker_token != "",
            NvAutomationJob.worker_pid != 0, NvAutomationJob.active_child_key != None,
            NvAutomationJob.active_membership_key != None),
    )).first()
    return None if competing else acquired.isoformat()


def _saved_oauth_reconcile_context(context, acquired_at):
    context = {**context, "oauth_reconcile_only": True, "oauth_saved_reconcile_at": acquired_at,
               "oauth_attempted": True, "oauth_retry_ready": False, "oauth_recovery_requested": False,
               "task_retry": {"strategy": "verify_existing", "reason_code": "network_temporary"}}
    context.pop("oauth_manual_recovery", None)
    context.pop("_oauth_single_retry_id", None)
    return context


def recover_saved_oauth_jobs(job_ids=None, *, child_id=None, source_account_id=None):
    """Queue newly saved credentials for fenced, read-only membership checks."""
    if job_ids is not None:
        if (not isinstance(job_ids, (list, tuple, set)) or len(job_ids) > 500
                or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value)
                       for value in job_ids)):
            raise ValueError("RT 核对任务编号无效")
        if not job_ids:
            return {"queued": 0, "job_ids": []}
    if any(value is not None and not _positive_identifier(value) for value in (child_id, source_account_id)):
        raise ValueError("RT 核对账号编号无效")
    queued = []
    with transaction() as session:
        settings = _settings(_settings_row(session))
        if not settings["enabled"]:
            return {"queued": 0, "job_ids": []}
        query = select(NvAutomationJob).where(NvAutomationJob.step == "oauth",
                                             NvAutomationJob.status.in_(["failed", "review"]))
        if job_ids is not None:
            query = query.where(NvAutomationJob.id.in_(job_ids))
        if child_id is not None:
            query = query.where(NvAutomationJob.child_id == child_id)
        if source_account_id is not None:
            query = query.where(NvAutomationJob.source_account_id == source_account_id)
        batch = _active_retry_batch(session)
        busy_items = {item["job_id"] for item in _retry_batch_items(batch)
                      if item["status"] in {"queued", "running"}} if batch else set()
        for job in session.exec(query.order_by(NvAutomationJob.created_at, NvAutomationJob.id)).all():
            if job.id in busy_items:
                continue
            # Quota recovery explicitly requires a fresh OAuth grant.  Never
            # convert its review row into the saved-RT read-only queue.
            if _decode(job.context_json).get("quota_rt_recovery") is True:
                continue
            acquired = _saved_oauth_reconcile_evidence(session, job, settings)
            if acquired is None:
                continue
            _apply_job_action(session, job, "reconcile")
            job.context_json = _json(_saved_oauth_reconcile_context(_decode(job.context_json), acquired))
            session.add(job)
            _log(session, job, "检测到本次邀请周期已保存完整 RT，已排队仅核对成员状态；不会重新授权或购买短信")
            queued.append(job.id)
    return {"queued": len(queued), "job_ids": queued}


def _stage_retry_mode(job, session=None):
    """Choose the failed stage's handler, independently of an old error label.

    Security/OAuth/renewal retain their credential/charge-specific grants.
    This is routing only: the selected canonical capability must still check
    current ownership, members, remote state and all mutation permissions.
    """
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    context = (get("context") or {}) if isinstance(job, dict) else _decode(job.context_json)
    step = get("step")
    if step == "select":
        if any(context.get(key) for key in (
                "invite_attempted", "invite_started_at", "invite_confirmed",
                "security_attempted", "oauth_attempted", "publish_attempted", "leave_attempted")):
            return "reconcile"
        return "retry"
    if step == "dead_cleanup":
        return "reconcile"  # The cleanup capability owns its submitted phase.
    if step not in {"invite", "publish", "leave"}:
        return None
    if (context.get(f"{step}_attempted") is not False
            or context.get(f"{step}_started_at") or context.get(f"{step}_started")):
        return "reconcile"
    if step == "invite" and (get("membership_id") or get("remote_user_id") or any(
            context.get(key) for key in ("invite_confirmed", "existing_member",
                "existing_invite_id", "remote_member_id", "membership_invited_at"))):
        return "reconcile"
    if step == "invite":
        failure = context.get("invite_failure")
        if failure is not None and (not isinstance(failure, dict)
                                    or failure.get("remote_invite_sent") is not False):
            return "reconcile"
        if session is None and not isinstance(job, dict):
            session = object_session(job)
        if session is not None and get("operation_id"):
            from core.db import GptBusinessInviteOperationModel
            old_operation = session.get(GptBusinessInviteOperationModel, get("operation_id"))
            if old_operation is not None and old_operation.remote_started:
                # Keep this exact operation identity for reconciliation. This
                # is a veto on replay, not a dependency on old invitation jobs.
                return "reconcile"
    if step == "publish" and any(context.get(key) for key in (
            "publish_confirmed", "nv_publish_started", "nv_publish_confirmed",
            "nv_remote_card_id", "nv_remote_order_id", "existing_listing")):
        return "reconcile"
    if step == "leave" and any(context.get(key) for key in (
            "leave_target", "leave_confirmed", "left_at")):
        return "reconcile"
    return "retry"


def _retry_batch_skip_reason(job, settings, *, automatic, session=None):
    if job.step == "renew":
        return "续期任务使用独立上架记录，请通过续期上架按钮核对或重试"
    if _mother_dead_reason(session or object_session(job), job.parent_account_id, job.source_account_id):
        return DEAD_MOTHER_REASON
    if job.step == "leave" and session is not None and (not automatic or settings["auto_exit"]):
        from services.nv_exit_recovery import legacy_preflight_failure, saved_preflight_failure
        if legacy_preflight_failure(session, job) or saved_preflight_failure(session, job):
            # A proven preflight wait never consumed a DELETE attempt; keep
            # its existing independent session recovery and historical count.
            return ""
    stage_mode = _stage_retry_mode(job)
    if stage_mode is not None:
        if _decode(job.context_json).get("nv_price_edit"):
            return "该子号正在核对 NV 改价，等待当前操作结束"
        if automatic and job.attempts >= _job_max_attempts(job):
            return "已达到本阶段自动重试上限；可手动重试当前阶段，历史次数保留"
        if job.step == "leave" and not settings["auto_exit"]:
            return "未开启自动退出，保留原任务等待"
        # Failure classification locates the previous problem; it cannot
        # permanently replace a new execution/reconciliation of this stage.
        return ""
    context = _oauth_context_for_retry(session, job)
    manual_legacy_recovery = (
        not automatic and job.step == "oauth"
        and _legacy_oauth_batch_recovery(job)
        and legacy_unknown_recovery_evidence_valid(context)
    )
    if job.step == "security":
        from services.nv_security_recovery import security_has_history
        if security_has_history(context):
            if not automatic:
                from services.nv_task_recovery import security_manual_retry_status
                state = security_manual_retry_status(session or object_session(job), job, settings)
                return "" if state.get("available") is True else (state.get("reason") or "安全核验尚未获得手动恢复许可")
            from services.nv_task_recovery import security_automatic_retry_status
            state = security_automatic_retry_status(session or object_session(job), job, settings)
            if state.get("available") is True:
                return ""
            problem = _security_start_blocker(job, context)
            if problem:
                return problem
    if job.step == "oauth" and session is not None:
        if _saved_oauth_reconcile_evidence(session, job, settings, allow_same_saved=not automatic) is not None:
            return ""
        if context.get("oauth_reconcile_only") is True:
            return "已保存 RT 的本次核对已处理或证据已变化，保留人工核对记录，不重新授权"
    if not automatic and session is not None:
        context = _manual_sms_recovery_context(session, job)
    if job.step == "oauth" and recoverable_failure(context.get("oauth_failure")):
        problem = retry_problem(context, max_executions=_job_max_attempts(job),
            phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
            allow_extra_execution=not automatic, allow_unknown_failure=True)
        if problem is None and context["oauth_failure"]["code"] == "sms_balance_insufficient":
            from services.nv_oauth_balance import oauth_balance_gate
            return oauth_balance_gate.problem() or ""
        return problem[1] if problem else ""
    if job.step in WAIT_STEPS:
        return "退出操作已有未确认记录，需人工核对" if not _review_scan_safe(job, settings) else ""
    policy = normalize_task_retry(context.get("task_retry"))
    legacy_recovery = _legacy_oauth_batch_recovery(job)
    if (job.step == "dead_cleanup" and session is not None and policy
            and policy.get("strategy") == "manual" and policy.get("reason_code") == "unknown_failure"):
        from services.nv_dead_child_cleanup import dead_marker_recovery_eligible
        if dead_marker_recovery_eligible(session, job):
            # Ignore only this inherited policy; all later budgets still run.
            policy = None
    failure = normalize_oauth_failure(context.get("oauth_failure")) if job.step == "oauth" else None
    executions = _oauth_count(context.get("oauth_execution_attempts"))
    if (automatic and failure and failure["code"] == "sms_timeout"
            and executions is not None and executions >= _job_max_attempts(job)):
        return "RT 自动重试已达上限；可点击“立即串行恢复失败任务”再获取一次 RT"
    manual_sms_recovery = False
    if failure and (failure["code"] in MANUAL_SMS_FAILURE_CODES
                    or not automatic and failure["code"] in MANUAL_SMS_RECOVERY_CODES):
        # Explicitly terminated phone failures are safe to retry automatically
        # when the operator has enabled phone-retry fee authorization.  Older
        # code treated these two catalog entries as manual-only, which left a
        # topped-up account permanently parked in ``review``.  The policy still
        # enforces the frozen cycle evidence, cumulative OAuth limit and live
        # fee switch; only the human click is removed.  Provider results with
        # unknown charge/callback state remain outside this branch and stay in
        # manual review.
        problem = retry_problem(context, max_executions=_job_max_attempts(job),
            phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
            allow_extra_execution=False if automatic else True)
        if problem:
            return problem[1]
        if not automatic:
            manual_sms_recovery = True
    authorized_phone_retry = bool(
        failure and failure.get("retryable") is True and failure.get("terminal") is True
        and context.get("oauth_retry_ready") is True
        and context.get("oauth_retry_blocked_reason") == "phone_cost_not_authorized"
        and settings.get("oauth_phone_retry_enabled") is True
    )
    hard_manual = policy and policy.get("reason_code") in {
        "identity_mismatch", "auth_rejected", "credentials_missing", "remote_change_unverified",
    }
    if policy and policy.get("strategy") == "manual" and (
            hard_manual or not (legacy_recovery or authorized_phone_retry or manual_sms_recovery)):
        reasons = {
            "identity_mismatch": "账号或成员身份不一致", "auth_rejected": "账号登录被拒绝",
            "credentials_missing": "缺少必要登录凭证", "remote_change_unverified": "远端修改结果尚未确认",
            "configuration_required": "需要检查或补充配置", "unknown_failure": "失败原因尚未确认",
            "untracked_prior_state": "原有操作缺少可验证记录", "insufficient_evidence": "缺少安全恢复依据",
        }
        return "当前任务需要人工处理：" + reasons.get(policy.get("reason_code"), "缺少安全恢复依据")
    if job.step == "oauth":
        executions = _oauth_count(context.get("oauth_execution_attempts"))
        if (executions is not None and executions >= _job_max_attempts(job)
                and not manual_sms_recovery and not manual_legacy_recovery):
            return "实际 OAuth 已达本任务上限，未启动新的 OAuth"
        if (failure and (failure.get("charge_possible") is True or failure.get("code") == "phone_verification_not_authorized")
                and settings.get("oauth_phone_retry_enabled") is not True and not legacy_recovery):
            return "未授权额外接码费用，手机号验证自动重试未开启"
    elif automatic and job.attempts >= _job_max_attempts(job):
        return "已达到本任务重试上限，本轮保留失败记录"
    if automatic and job.step == "leave" and not settings["auto_exit"]:
        return "未开启自动退出，保留原任务等待"
    return ""


def _retry_batch_oauth_attempt(job):
    """Freeze credential-free identity of the failed execution, not its budget."""
    context = _decode(job.context_json)
    started = _oauth_time(context.get("oauth_started_at"))
    failed = _oauth_time(context.get("oauth_failure_started_at"))
    return dict(executions=_oauth_count(context.get("oauth_execution_attempts")),
                started_at=started.isoformat() if started else None,
                failed_at=failed.isoformat() if failed else None,
                failure=normalize_oauth_failure(context.get("oauth_failure")))


def _create_retry_batch_locked(session, settings, identifier, *, generation=0):
    """Freeze one bounded snapshot for both manual and scheduled recovery."""
    automatic = generation > 0
    candidates = session.exec(select(NvAutomationJob).where(
        NvAutomationJob.status.in_(["failed", "review"]),
    )).all()
    candidates = [job for job in candidates if _enabled_for(job, settings)
                  and not job.pause_requested and not job.worker_token and not job.worker_pid]
    # Rotate capped automatic snapshots so a persistent early failure cannot
    # hide later mothers forever. This timestamp never alters job evidence.
    candidates.sort(key=lambda job: (
        job.retry_batch_checked_at if automatic else 0,
        0 if _decode(job.context_json).get("existing_member") is True else 1,
        job.created_at, job.id,
    ))
    now = time.time()
    items = []
    for job in candidates[:500]:
        reason = _retry_batch_skip_reason(job, settings, automatic=automatic, session=session)
        saved_oauth = (_saved_oauth_reconcile_evidence(session, job, settings, allow_same_saved=not automatic)
                       if not reason else None)
        items.append(dict(job_id=job.id, email=job.email, parent_email=job.parent_email,
                          parent_account_id=job.parent_account_id, source_account_id=job.source_account_id,
                          frozen_version=job.version, frozen_status=job.status,
                          **({"frozen_oauth_attempt": _retry_batch_oauth_attempt(job)}
                             if not automatic and job.step == "oauth" else {}),
                          **({"saved_oauth_reconcile_at": saved_oauth} if saved_oauth else {}),
                          status="skipped" if reason else "queued", step=job.step, error=reason,
                          started_at=None, finished_at=now if reason else None,
                          oauth_executions_before=_oauth_count(_decode(job.context_json).get("oauth_execution_attempts")),
                          oauth_executions_after=_oauth_count(_decode(job.context_json).get("oauth_execution_attempts")),
                          oauth_execution_state="not_started"))
        job.retry_batch_checked_at = now
        session.add(job)
    active = any(item["status"] == "queued" for item in items)
    batch = NvAutomationRetryBatch(
        id=identifier, active_key="active" if active else None,
        status="running" if active else "completed", items_json=_json(items),
        origin="automatic" if automatic else "manual", scan_generation=generation,
        deadline_at=now + 30 * 60, deferred_count=max(0, len(candidates) - 500),
    )
    session.add(batch)
    session.flush()
    return batch


def _invite_display_snapshot(job):
    context = _decode(job.context_json)
    step, progress = public_invite_display(job, context)
    from services.nv_invite_preparation import normalize_preparation
    preparation = normalize_preparation(context.get("invite_preparation"), job)
    return dict(child_id=job.child_id, display_step=step, invite_progress=progress,
                candidate_mail_provider=context.get("invite_candidate_provider"),
                invite_preparation=preparation,
                invite_preparation_completed=bool(preparation and preparation["status"] == "completed"),
                invite_failure=_normalized_invite_failure(context.get("invite_failure")))


def _finish_retry_batch_item(batch, item, job, status, reason=""):
    session = object_session(batch)
    if session is not None:
        item.update(_retry_item_oauth_evidence(session, batch, item, job))
    item.update(status=status, error=safe_message(reason or (job.error if job else "")))
    if job:
        item.update(step=job.step, email=job.email or item["email"], job_status=job.status)
        item.update(_invite_display_snapshot(job))
    item["finished_at"] = time.time()
    item["result_summary"] = _retry_item_summary(item)
    batch.current_job_id = ""
    batch.updated_at = time.time()


def _defer_retry_batch_current(session, batch, job, reason):
    items = _retry_batch_items(batch)
    item = next((item for item in items if item["job_id"] == job.id and item["status"] == "running"), None)
    if item is None:
        return
    job.status, job.next_run_at = "waiting", time.time() + 60
    job.error, job.updated_at = reason, time.time()
    job.version += 1
    session.add(job)
    _log(session, job, reason + "；本批继续处理下一个账号")
    _finish_retry_batch_item(batch, item, job, "skipped", reason)
    batch.items_json = _json(items)
    session.add(batch)


def _advance_retry_batch_locked(session, settings):
    configuration = _settings_row(session)
    batch = _active_retry_batch(session)
    if (not configuration.scan_token
            and configuration.scan_request_generation > configuration.scan_completed_generation
            and configuration.scan_recovery_generation != configuration.scan_request_generation):
        scheduled = _scheduled_retry_batch(session, configuration.scan_request_generation)
        if scheduled:
            configuration.scan_recovery_generation = configuration.scan_request_generation
            configuration.scan_recovery_batch_id = scheduled.id
            session.add(configuration)
    if batch is None:
        return None
    if configuration.scan_token:
        return batch  # A queued manual request cannot overlap a scan worker.
    if not batch.deadline_at:
        # Adopt persisted batches created before bounded cycle scheduling.
        batch.deadline_at = time.time() + 30 * 60
        session.add(batch)
    items = _retry_batch_items(batch)
    expired = bool(batch.deadline_at and time.time() >= batch.deadline_at)
    current = next((item for item in items if item["status"] == "running"), None)
    if current:
        job = session.get(NvAutomationJob, current["job_id"])
        if job is None:
            _finish_retry_batch_item(batch, current, None, "skipped", "原任务已不存在")
        elif job.status == "cancelled":
            _finish_retry_batch_item(batch, current, job, "skipped", "子号已删除，旧任务已移除")
        elif _mother_dead_reason(session, job.parent_account_id, job.source_account_id) and job.status != "running":
            _finish_retry_batch_item(batch, current, job, "skipped", DEAD_MOTHER_REASON)
        elif _decode(job.context_json).get("retry_batch_id") != batch.id:
            _finish_retry_batch_item(batch, current, job, "skipped", "任务已由其他操作更新，未重复处理")
        elif job.status == "running":
            return batch
        elif batch.status == "stopping":
            if job.status != "completed":
                _apply_job_action(session, job, "pause")
            _finish_retry_batch_item(batch, current, job, "stopped", "本批已停止，后续步骤未执行")
        elif job.status == "completed" or (job.step in WAIT_STEPS and job.status == "waiting"):
            _finish_retry_batch_item(batch, current, job, "completed", "已完成本轮处理，后续按正常售后流程运行")
        elif job.status in {"failed", "review"}:
            _finish_retry_batch_item(batch, current, job, job.status)
        elif job.status == "retry":
            # The failure and its bounded retry deadline remain on the job.
            # Do not hold the entire serial batch during this account's backoff.
            _finish_retry_batch_item(batch, current, job, "failed",
                (job.error + "；当前阶段已记录失败并安排重试，本批继续下一个账号").lstrip("；"))
        elif job.status == "paused" or not _enabled_for(job, {**settings, "enabled": True}):
            if job.status != "paused":
                _apply_job_action(session, job, "pause")
            _finish_retry_batch_item(batch, current, job, "skipped", "任务或母号已暂停、移出管理范围")
        elif job.status == "waiting":
            # Cooling-down jobs remain in their normal durable waiting state.
            # Do not make this batch wait hours before processing other mothers.
            _finish_retry_batch_item(batch, current, job, "skipped", job.error or "等待执行条件恢复，已保留原任务等待")
        elif expired or (job.status == "retry" and batch.deadline_at
                         and job.next_run_at > batch.deadline_at):
            _finish_retry_batch_item(batch, current, job, "skipped", "后续步骤按原计划等待；本轮继续 NV 检查")
        else:
            return batch  # pending / bounded retry: finish this account first.
    if batch.status == "stopping":
        for item in items:
            if item["status"] == "queued":
                item.update(status="stopped", error="本批已停止，未启动账号操作", finished_at=time.time())
                item["result_summary"] = _retry_item_summary(item)
        batch.status, batch.active_key = "stopped", None
    elif settings["enabled"]:
        for item in items:
            if item["status"] != "queued":
                continue
            job = session.get(NvAutomationJob, item["job_id"])
            if expired:
                _finish_retry_batch_item(batch, item, job, "skipped", "本轮串行处理已到时限，留待后续处理")
                continue
            if job is not None and _mother_dead_reason(session, job.parent_account_id, job.source_account_id):
                _finish_retry_batch_item(batch, item, job, "skipped", DEAD_MOTHER_REASON)
                continue
            if job is None or any((
                job.version != item["frozen_version"], job.status != item["frozen_status"],
                job.parent_account_id != item["parent_account_id"], job.source_account_id != item["source_account_id"],
                job.email != item["email"], job.step != item["step"],
                not _enabled_for(job, settings), job.pause_requested, bool(job.worker_token), bool(job.worker_pid),
            )):
                _finish_retry_batch_item(batch, item, job, "skipped", "任务状态或管理范围已变化，未重复启动")
                continue
            if ("frozen_oauth_attempt" in item
                    and item["frozen_oauth_attempt"] != _retry_batch_oauth_attempt(job)):
                _finish_retry_batch_item(batch, item, job, "skipped", "本次 RT 失败记录或执行次数已变化，请重新发起串行恢复")
                continue
            saved_oauth = _saved_oauth_reconcile_evidence(
                session, job, settings, allow_same_saved=batch.origin == "manual")
            if ("saved_oauth_reconcile_at" in item
                    and item["saved_oauth_reconcile_at"] != saved_oauth):
                _finish_retry_batch_item(batch, item, job, "skipped", "已保存 RT 的落库时间、归属或执行状态已变化，未重复处理")
                continue
            reason = _retry_batch_skip_reason(job, settings, automatic=batch.origin == "automatic", session=session)
            if reason:
                _finish_retry_batch_item(batch, item, job, "skipped", reason)
                continue
            if job.step in WAIT_STEPS:
                generation = _request_scan_row(configuration, "串行恢复已合并等待阶段异常，等待 NV 核对")
                next_version = job.version + 1
                _update_fields(job, {"context": {
                    "nv_recheck_generation": generation, "nv_recheck_version": next_version,
                }})
                job.reconcile_requested, job.version = True, next_version
                job.updated_at = time.time()
                session.add(job)
                session.add(configuration)
                _finish_retry_batch_item(batch, item, job, "merged", "已并入本轮 NV 只读检查")
                continue
            original_context = _decode(job.context_json)
            context = (_manual_sms_recovery_context(session, job)
                       if batch.origin == "manual" and not saved_oauth else _oauth_context_for_retry(session, job))
            failure = normalize_oauth_failure(context.get("oauth_failure")) if job.step == "oauth" else None
            manual_legacy_recovery = bool(
                batch.origin == "manual" and not saved_oauth
                and _legacy_oauth_batch_recovery(job)
                and legacy_unknown_recovery_evidence_valid(context)
            )
            manual_sms_recovery = bool(not saved_oauth and batch.origin == "manual" and failure and failure["code"] in MANUAL_SMS_RECOVERY_CODES
                and manual_sms_recovery_problem(context, max_executions=_job_max_attempts(job),
                    phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
                    allow_extra_execution=True) is None)
            oauth_failure_recheck = (
                job.step == "oauth"
                and context.get("oauth_attempted") is False
                and context.get("oauth_retry_ready") is True
                and normalize_oauth_failure(context.get("oauth_failure")) is not None
            )
            action = (_stage_retry_mode(job) or ("reconcile" if saved_oauth or manual_sms_recovery or job.status == "review"
                      or context.get(f"{job.step}_attempted") is True
                      or oauth_failure_recheck else "retry"))
            attempts = job.attempts
            from services.nv_security_recovery import security_has_history
            manual_security = job.step == "security" and batch.origin == "manual" and security_has_history(context)
            automatic_security = job.step == "security" and batch.origin == "automatic" and security_has_history(context)
            if manual_security:
                from services.nv_task_recovery import queue_manual_security_retry
                try:
                    queue_manual_security_retry(session, job, settings, request_id=batch.id)
                except RuntimeError as exc:
                    _finish_retry_batch_item(batch, item, job, "skipped", str(exc))
                    continue
                context = _decode(job.context_json)
            elif automatic_security:
                from services.nv_task_recovery import queue_automatic_security_retry
                try:
                    queue_automatic_security_retry(session, job, settings, request_id=batch.id)
                except RuntimeError as exc:
                    _finish_retry_batch_item(batch, item, job, "skipped", str(exc))
                    continue
                context = _decode(job.context_json)
            else:
                _apply_job_action(session, job, action)
            if batch.origin == "automatic":
                job.attempts = attempts
            if saved_oauth:
                context = _saved_oauth_reconcile_context(context, saved_oauth)
            elif batch.origin == "automatic" and context.get("oauth_manual_recovery") is not None:
                # A new automatic batch has independently passed its own
                # budget/fee checks. An unconsumed permission from a previous
                # manual request cannot transfer here or poison its checkpoint.
                context.pop("oauth_manual_recovery", None)
                context.pop("_oauth_single_retry_id", None)
                context["oauth_recovery_requested"] = False
            elif _legacy_oauth_batch_recovery(job):
                context["oauth_recovery_requested"] = True
                if manual_legacy_recovery:
                    context["oauth_manual_recovery"] = {
                        "origin": "manual", "batch_id": batch.id,
                        "started_at": context["oauth_started_at"],
                        "execution_attempts": context["oauth_execution_attempts"],
                    }
            if manual_sms_recovery:
                # Freeze a one-execution permission to this explicitly manual
                # batch and the exact failed attempt. No counters/evidence reset.
                context.pop("_oauth_single_retry_id", None)
                context["oauth_recovery_requested"] = True
                context["oauth_manual_recovery"] = {
                    "origin": "manual", "batch_id": batch.id,
                    "started_at": context["oauth_started_at"],
                    "execution_attempts": context["oauth_execution_attempts"],
                }
            context["retry_batch_id"] = batch.id
            job.context_json = _json(context)
            session.add(job)
            _log(session, job, "已进入串行处理，仅核对本次已保存 RT 与成员状态，不重新授权或购买短信" if saved_oauth else
                 "已进入一键串行处理；本批已授权一次受限 RT 重试，先核对原结果再继续" if (manual_sms_recovery or manual_legacy_recovery) else
                 "已进入一键串行处理；本批仅核对原结果后继续" if action == "reconcile"
                 else "已进入一键串行处理；从当前失败步骤开始本轮有限重试")
            if manual_sms_recovery:
                if context.get("oauth_failure") != original_context.get("oauth_failure"):
                    _log(session, job, f"已从本次完整历史日志确认：{failure['reason']}；仅细化原错误分类，未认定号码未分配或未扣费，原执行次数保留")
                _log(session, job, "已授权本批重新获取 RT 一次；累计执行次数保留，自动重试上限不变；先核对已有凭证，再检查成员与接码费用授权")
            item.update(status="running", error="", started_at=time.time(), finished_at=None,
                        oauth_executions_before=_oauth_count(context.get("oauth_execution_attempts")),
                        oauth_executions_after=_oauth_count(context.get("oauth_execution_attempts")),
                        oauth_execution_state="not_started")
            batch.current_job_id = job.id
            batch.updated_at = time.time()
            break
        if not any(item["status"] in {"queued", "running"} for item in items):
            batch.status, batch.active_key = "completed", None
    batch.items_json = _json(items)
    session.add(batch)
    return batch if batch.active_key else None


def advance_retry_batch():
    _prepare_oauth_balance()
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        _advance_retry_batch_locked(session, _settings(_settings_row(session)))


def stop_retry_batch(identifier):
    with transaction() as session:
        batch = session.get(NvAutomationRetryBatch, identifier)
        if batch is None:
            raise KeyError(identifier)
        if batch.active_key:
            batch.status, batch.updated_at = "stopping", time.time()
            items = _retry_batch_items(batch)
            for item in items:
                if item["status"] == "queued":
                    item.update(status="stopped", error="本批已停止，未启动账号操作", finished_at=time.time())
                    item["result_summary"] = _retry_item_summary(item)
            batch.items_json = _json(items)
            session.add(batch)
            if batch.current_job_id:
                job = session.get(NvAutomationJob, batch.current_job_id)
                if job and job.status == "running":
                    _apply_job_action(session, job, "pause")
            _advance_retry_batch_locked(session, _settings(_settings_row(session)))
            session.flush()
        return _public_retry_batch(session, batch)


def job_action(job_id, action):
    cleanup_deleted_child_jobs([job_id])
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        if not job:
            raise KeyError(job_id)
        if action != "pause" and _mother_dead_reason(session, job.parent_account_id, job.source_account_id):
            raise RuntimeError(DEAD_MOTHER_REASON)
        from services.nv_security_recovery import normalize_security_retry, security_has_history
        saved_context = _decode(job.context_json)
        security_action = action == "retry" and job.step == "security" and security_has_history(saved_context)
        security_repeat = (security_action and job.status in {"pending", "running"}
                           and normalize_security_retry(saved_context.get("security_retry"), job) is not None)
        batch = _active_retry_batch(session)
        if batch and batch.current_job_id == job.id and action != "pause" and not security_repeat:
            raise RuntimeError("该任务正在串行批次中，请先停止本批，避免重复启动")
        settings = _settings(_settings_row(session))
        context = _oauth_context_for_retry(session, job)
        if security_action:
            from services.nv_task_recovery import queue_manual_security_retry
            try:
                queue_manual_security_retry(session, job, settings)
            except RuntimeError as exc:
                raise NvSecurityRetryBlocked(str(exc)) from None
        elif job.step == "oauth" and (
                action in {"retry", "reconcile"} and context.get("oauth_reconcile_only") is True
                or action == "retry" and (
                    recovery_evidence_valid(context) or manual_provider_recovery_evidence_valid(context))):
            if job.status not in {"review", "failed", "retry"} or job.worker_token or job.worker_pid:
                raise NvOAuthRetryBlocked("RT 任务仍在执行或状态已变化，未重复启动")
            if not _enabled_for(job, settings) or job.pause_requested:
                raise NvOAuthRetryBlocked("任务或母号已暂停，请先恢复调度")
            saved = _saved_oauth_reconcile_evidence(session, job, settings, allow_same_saved=True)
            if saved:
                context = _saved_oauth_reconcile_context(context, saved)
            else:
                if context.get("oauth_reconcile_only") is True:
                    raise NvOAuthRetryBlocked("已保存 RT 的时间、归属或执行状态未通过核对；未重新授权，请核对任务记录")
                problem = manual_sms_recovery_problem(context, max_executions=_job_max_attempts(job),
                    phone_allowed=settings.get("oauth_phone_retry_enabled") is True,
                    allow_extra_execution=True)
                if problem:
                    raise NvOAuthRetryBlocked(problem[1])
                # Same one-use grant as a manual batch, scoped to this exact
                # failed attempt. A second click sees pending and is rejected.
                request_id = "manual-rt-" + uuid.uuid4().hex
                context.update(oauth_recovery_requested=True, retry_batch_id=request_id,
                    _oauth_single_retry_id=request_id,
                    oauth_manual_recovery={"origin": "manual", "batch_id": request_id,
                        "started_at": context["oauth_started_at"],
                        "execution_attempts": context["oauth_execution_attempts"]})
            job.context_json = _json(context)
            job.status, job.reconcile_requested, job.next_run_at = "pending", True, time.time()
            job.error = ""
            job.updated_at = time.time()
            job.version += 1
            _log(session, job, "RT 已保存，已排队自动核验后续状态" if saved else
                "已请求重新获取 RT：先检查已保存凭证，无完整凭证则启动一次新 OAuth；累计次数保留")
            session.add(job)
        else:
            _apply_job_action(session, job, action)
    return get_job(job_id)


def mark_job_manual_sold(job_id, *, version, external=False, warranty_until=None, warranty_hours=None):
    """Record an operator sale for a parked 5X job without an NV listing.

    The local sale anchors the configured 5X warranty and post-warranty exit
    delay, so manual and NV sales share the same countdown. No NV request is
    made; the eventual member removal still uses the normal identity checks.
    """
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        if job is None:
            raise KeyError(job_id)
        if type(version) is not int or version < 0 or job.version != version:
            raise RuntimeError("任务状态已更新，请刷新后重试")
        context = _decode(job.context_json)
        if job.seat_type != "prolite":
            raise RuntimeError("仅高级席位 5X 支持人工售卖标记")
        if context.get("manual_sale") is True or context.get("sold_at"):
            return _public(job, _settings_row(session))
        manual_pending = context.get("manual_sale_required") is True
        # A 5X task can be left in the publish review step when the NV
        # storefront is disabled between RT completion and the checkpoint.
        # If no remote listing/order was confirmed, an operator's explicit
        # sale click is still the same safe local transition.
        unpublished_prolite = (
            job.step == "publish" and context.get("publish_confirmed") is not True
            and not context.get("nv_remote_card_id") and not context.get("nv_remote_order_id")
        )
        # An external delivery callback may mark an otherwise normally listed
        # 5X job as sold. The public manual-sale endpoint keeps the stricter
        # unpublished-only rule.
        external_pending = bool(external and job.step == "wait_sale" and job.status == "waiting")
        if not (manual_pending or unpublished_prolite or external_pending):
            raise RuntimeError("该任务未处于待人工售卖状态")
        from core.db import GptBusinessChildMembershipModel as Membership
        membership = session.get(Membership, int(job.membership_id or 0))
        if membership is None or membership.ended_at is not None or membership.sale_status in {"refunded", "partial_refund"}:
            raise RuntimeError("子号成员状态已变化，不能标记人工售卖")
        now = datetime.now(timezone.utc)
        iso = now.isoformat()
        membership.sale_status = "sold"
        membership.sold_at = now
        membership.updated_at = now
        session.add(membership)
        # Apply the same configured 5X warranty + post-warranty exit delay as
        # an NV sale.  Manual sales have no remote NV evidence, so the local
        # sale confirmation is the cycle anchor.  If no explicit warranty is
        # configured, retain a zero-warranty anchor and still honour delay.
        from services.nv_listing_warranty import normalize_team5x_warranty, resolve_team5x_warranty
        # A delivered shop order supplies the absolute deadline that was
        # snapshotted on that order.  Validate it before storing so a forged
        # or malformed callback cannot extend a warranty indefinitely. Older
        # callbacks omit it and continue using the source-side configuration.
        warranty_contract = None
        callback_deadline = str(warranty_until or "").strip()
        if external and callback_deadline:
            warranty_contract = normalize_team5x_warranty(
                {"mode": "until", "until": callback_deadline}, now=now, require_future=False
            )
            warranty_until = warranty_contract["until"]
        elif external and warranty_hours == 0:
            # The shop explicitly sold a no-warranty package.  Anchor the
            # contract at sale time so only the configured exit delay remains.
            warranty_until = iso
        else:
            try:
                warranty_contract = resolve_team5x_warranty(_settings(_settings_row(session)), now=now)
                warranty_until = warranty_contract["until"]
            except (ValueError, TypeError):
                warranty_contract = None
                warranty_until = iso
        if external and warranty_hours is not None:
            context_warranty_hours = warranty_hours
        else:
            context_warranty_hours = None
        context.update({"manual_sale": True, "manual_sale_required": False,
                        "sale_source": "manual", "sold_at": iso,
                        "warranty_until": warranty_until, "team5x_warranty": warranty_contract,
                        "quota_tier": "prolite",
                        "sale_confirmed": True})
        if context_warranty_hours is not None:
            context["warranty_hours"] = context_warranty_hours
        job.context_json = _json(context)
        job.step, job.status = "wait_warranty", "waiting"
        settings = _settings(_settings_row(session))
        delay = job_exit_delay(job, settings, context)
        deadline = auto_exit_at(warranty_until, delay)
        job.next_run_at = deadline.timestamp() if deadline else 0
        job.reconcile_requested = False
        job.pause_requested = False
        job.active_parent_key = None
        job.attempts = 0
        job.error = ""
        job.updated_at = time.time()
        job.version += 1
        _log(session, job, "已人工标记售出；按当前退出延迟启动自动倒计时，到时自动核验并退出空间")
        session.add(job)
        session.flush()
        return _public(job, _settings_row(session))


def mark_job_dujiao_sold(job_id, *, version, order_id, plan_code,
                         external_account_id=None, sold_at=None,
                         warranty_hours=None, warranty_until=None):
    """Apply a verified Dujiao delivery to a local 5X job, idempotently."""
    if type(version) is not int or version < 0:
        raise ValueError("任务版本无效，请刷新后重试")
    order_id, plan_code = str(order_id or "").strip(), str(plan_code or "").strip()
    external_account_id = str(external_account_id or "").strip()
    if not order_id or not plan_code:
        raise ValueError("Dujiao 成交缺少订单或套餐标识")
    if type(warranty_hours) is not int or warranty_hours not in {1, 3, 5, 7, 9, 12}:
        raise ValueError("Dujiao 质保套餐无效")
    def parse(value, label):
        try:
            result = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise ValueError(f"Dujiao {label}时间无效")
        if result.tzinfo is None:
            raise ValueError(f"Dujiao {label}时间必须带时区")
        return result.astimezone(timezone.utc)
    sold, until = parse(sold_at, "成交"), parse(warranty_until, "质保截止")
    if abs((until - (sold + timedelta(hours=warranty_hours))).total_seconds()) > 1:
        raise ValueError("Dujiao 质保截止时间与成交套餐不一致")
    sold_iso, until_iso = sold.isoformat(), until.isoformat()
    with transaction() as session:
        job = session.get(NvAutomationJob, job_id)
        if job is None:
            raise KeyError(job_id)
        if job.version != version:
            raise RuntimeError("任务状态已更新，请刷新后重试")
        if job.seat_type != "prolite":
            raise RuntimeError("仅高级席位 5X 支持 Dujiao 成交")
        context = _decode(job.context_json)
        if context.get("sale_source") == "dujiao" and context.get("sold_at"):
            same = (str(context.get("dujiao_order_id") or "") == order_id
                    and str(context.get("dujiao_plan_code") or "") == plan_code
                    and str(context.get("sold_at")) == sold_iso
                    and str(context.get("warranty_until")) == until_iso)
            if same:
                return _public(job, _settings_row(session))
            raise RuntimeError("Dujiao 成交已绑定其他订单，拒绝覆盖")
        if context.get("sold_at") or context.get("manual_sale") is True:
            raise RuntimeError("该子号已存在其他销售周期，拒绝覆盖")
        from core.db import GptBusinessChildMembershipModel as Membership
        membership = session.get(Membership, int(job.membership_id or 0))
        if membership is None or membership.ended_at is not None:
            raise RuntimeError("子号成员状态已变化，不能记录 Dujiao 成交")
        if external_account_id and external_account_id not in {job.email, f"nvjob-{job.id}"}:
            raise RuntimeError("Dujiao 成交账号与本地子号不匹配")
        now = datetime.now(timezone.utc)
        membership.sale_status, membership.sold_at = "sold", sold
        membership.warranty_hours = warranty_hours
        membership.nv_team5x_warranty_until = until
        membership.updated_at = now
        session.add(membership)
        context.update({"manual_sale": True, "manual_sale_required": False,
                        "sale_source": "dujiao", "sale_confirmed": True,
                        "sold_at": sold_iso, "warranty_until": until_iso,
                        "warranty_hours": warranty_hours,
                        "team5x_warranty": {"mode": "until", "until": until_iso},
                        "dujiao_order_id": order_id, "dujiao_plan_code": plan_code,
                        "dujiao_external_account_id": external_account_id,
                        "dujiao_sold_at": sold_iso, "dujiao_warranty_hours": warranty_hours,
                        "dujiao_warranty_until": until_iso})
        job.context_json = _json(context)
        job.step, job.status = "wait_warranty", "waiting"
        settings = _settings(_settings_row(session))
        deadline = auto_exit_at(until_iso, job_exit_delay(job, settings, context))
        job.next_run_at = deadline.timestamp() if deadline else 0
        job.reconcile_requested = job.pause_requested = False
        job.active_parent_key, job.attempts, job.error = None, 0, ""
        job.updated_at, job.version = time.time(), job.version + 1
        _log(session, job, f"Dujiao 订单 {order_id} 已确认成交；质保 {warranty_hours} 小时，按退出延迟自动倒计时")
        session.add(job)
        session.flush()
        return _public(job, _settings_row(session))


def runtime_snapshot():
    with Session(engine) as session:
        row = session.get(NvAutomationSettings, 1)
        running = session.exec(select(NvAutomationJob).where(_occupied_worker_clause())).all()
        if not row:
            return dict(active_workers=len(running), active_browser_workers=sum(j.step in BROWSER_STEPS for j in running),
                next_scan_at=None, last_error="", scan_running=False, scan_pending=False,
                scan_verified_at=None, last_scan_at=None, next_scan_reason="等待启用自动售号",
                last_scan_summary=None, cycle=_cycle_snapshot(session, None, running))
        settings = _settings(row)
        processable = _has_processable_mother(session, settings)
        request_generation = int(row.scan_request_generation or 0)
        boundary = int(row.scan_claim_generation or 0) if row.scan_token else int(row.scan_completed_generation or 0)
        pending = bool(settings["enabled"] and processable and (
            request_generation > boundary
            or (not row.scan_token and row.next_scan_at <= time.time())
        ))
        verified = bool(row.scan_verified_at and row.scan_verified_config_generation == row.config_generation)
        if row.scan_token:
            reason = row.scan_reason if pending else row.scan_claim_reason
        else:
            reason = row.scan_reason
        return dict(active_workers=len(running), active_browser_workers=sum(j.step in BROWSER_STEPS for j in running),
            next_scan_at=_iso(row.next_scan_at) if processable else None, last_error=row.scan_error,
            scan_running=bool(row.scan_token), scan_pending=pending,
            scan_verified_at=_iso(row.scan_verified_at) if verified else None,
            last_scan_at=_iso(row.last_scan_at),
            next_scan_reason=_scan_reason(reason, "等待 NV 扫描调度"),
            last_scan_summary=_last_scan_summary(row), cycle=_cycle_snapshot(session, row, running))


def _cycle_snapshot(session, row, running):
    batch = None if row and row.scan_token else _active_retry_batch(session)
    if batch is None and row and row.scan_recovery_batch_id:
        batch = session.get(NvAutomationRetryBatch, row.scan_recovery_batch_id)
    items = _retry_batch_items(batch) if batch else []
    settings = _settings(row)
    pending = bool(row and row.scan_recovery_generation > row.scan_completed_generation)
    if not settings["enabled"]:
        phase = "disabled"
    elif row and row.scan_token:
        phase = "scanning"
    elif batch and batch.active_key:
        phase = "waiting_for_workers" if running and not any(
            job.id == batch.current_job_id for job in running) else "recovering"
    elif pending and running:
        phase = "waiting_for_workers"
    elif pending:
        phase = "recovering"
    else:
        phase = "idle"
    return dict(
        phase=phase, generation=int(row.scan_recovery_generation or 0) if row else 0,
        batch_id=batch.id if batch else None, batch_origin=batch.origin if batch else None,
        total=len(items), finished=sum(item["status"] not in {"queued", "running"} for item in items),
        skipped=sum(item["status"] == "skipped" for item in items),
        failed=sum(item["status"] == "failed" for item in items),
        review=sum(item["status"] == "review" for item in items),
    )


def request_scan(reason="人工请求 NV 核对", *, include_reviews=False):
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        if include_reviews and not settings["enabled"]:
            raise RuntimeError("请先启用自动售号")
        generation = _request_scan_row(row, reason)
        if include_reviews:
            candidates = session.exec(select(NvAutomationJob).where(
                NvAutomationJob.status.in_(["review", "failed"]),
            )).all()
            queued = 0
            for job in candidates:
                if not _review_scan_safe(job, settings):
                    continue
                next_version = int(job.version or 0) + 1
                _update_fields(job, {"context": {
                    "nv_recheck_generation": generation,
                    "nv_recheck_version": next_version,
                }})
                job.reconcile_requested = True
                job.version = next_version
                job.updated_at = time.time()
                session.add(job)
                _log(session, job, "已排队执行全局 NV 只读核对；原错误保留至取得新结果")
                queued += 1
            waiting_count = sum(
                1 for job in session.exec(select(NvAutomationJob).where(
                    NvAutomationJob.status == "waiting",
                    NvAutomationJob.step.in_(list(WAIT_STEPS)),
                )).all()
                if _waiting_scan_safe(job, settings)
            )
            skipped = len(candidates) - queued
            summary = {
                "generation": generation,
                "covered": waiting_count + queued,
                "review_queued": queued,
                "skipped": skipped,
                # Explicit aliases keep the service contract self-describing.
                "queued_review_count": queued,
                "skipped_count": skipped,
            }
            session.add(row)
            return summary
        session.add(row)
        return generation


def recover_deferred_quota_recovery():
    """Repair the old deadline overwrite without resetting attempts or leases.

    Only a current, identity-bound rejected-RT observation can wake an idle
    sold job. Real retry backoffs and paused/failed/running jobs are retained.
    """
    from services.nv_sold_quota import normalize_sold_quota

    now, changed = time.time(), 0
    with transaction() as session:
        settings = _settings(_settings_row(session))
        if not settings["enabled"]:
            return 0
        jobs = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step == "wait_warranty",
            NvAutomationJob.status.in_(["pending", "retry", "waiting"]),
            NvAutomationJob.worker_token == "",
            NvAutomationJob.worker_pid == 0,
        )).all()
        for job in jobs:
            context = _decode(job.context_json)
            if (context.get("quota_rt_recovery") is not True or job.pause_requested
                    or not context.get("sold_at") or not _enabled_for(job, settings)
                    or context.get("nv_refund") or manual_exit_requested_at(job, context) is not None
                    or any(context.get(key) for key in ("leave_attempted", "leave_target", "left_at"))):
                continue
            observation = normalize_sold_quota(context.get("sold_quota"), {
                "child_id": job.child_id, "membership_id": job.membership_id,
                "email": job.email, "remote_user_id": job.remote_user_id, "context": context,
            })
            if not observation or observation.get("error_code") != "refresh_rejected":
                continue
            deadline = auto_exit_at(context.get("warranty_until"), job_exit_delay(job, settings, context))
            overwritten = (deadline is not None and deadline.timestamp() > now
                           and abs(job.next_run_at - deadline.timestamp()) < 0.01
                           and job.next_run_at > job.updated_at + 900)
            if not overwritten and job.reconcile_requested:
                continue
            if overwritten:
                job.next_run_at = now
            job.reconcile_requested = True
            job.updated_at, job.version = now, job.version + 1
            _log(session, job, "已修复售后 RT 恢复调度；按恢复重试时间执行，不再等待质保结束")
            session.add(job)
            changed += 1
    return changed


def request_immediate_quota_recovery():
    """Wake sold-account RT repairs immediately from the UI dispatch action.

    These jobs deliberately keep ``wait_sale``/``wait_warranty`` as their
    durable lifecycle step.  Marking the reconciliation handoff here makes a
    manual dispatch deterministic: the next worker claims the hidden OAuth
    repair instead of running an ordinary NV wait scan.
    """
    now = time.time()
    changed = 0
    with transaction() as session:
        settings = _settings(_settings_row(session))
        if not settings["enabled"]:
            return 0
        jobs = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.step.in_(list(WAIT_STEPS)),
            NvAutomationJob.status.in_(["pending", "retry", "waiting"]),
        )).all()
        for job in jobs:
            context = _decode(job.context_json)
            if context.get("quota_rt_recovery") is not True or job.worker_token:
                continue
            job.status = "pending"
            job.reconcile_requested = True
            job.next_run_at = now
            job.updated_at = now
            job.version += 1
            _log(session, job, "已手动唤醒额度刷新后的 RT 自动恢复")
            session.add(job)
            changed += 1
    return changed


def request_due_warranty_scan():
    """Request one scan only after warranty end plus the current grace period.

    Moving each observed deadline forward prevents a failed scan from being
    relaunched every dispatcher tick.  Only a successful, version-matched scan
    result may advance a job toward leave; this function never does so.
    """
    now = time.time()
    with transaction() as session:
        row = _settings_row(session)
        settings = _settings(row)
        if not settings["enabled"] or not settings["auto_exit"]:
            # Normal periodic scans still monitor sales.  A deadline event is
            # needed only when it could unlock an authorized leave; enabling
            # auto-exit is itself a configuration scan event.
            return False
        # ``next_run_at`` is also used as the backoff for sold-account RT
        # recovery.  That backoff must not hide an already expired warranty:
        # a quota refresh may be scheduled several minutes in the future even
        # though the account is eligible to leave now.  Load all waiting
        # warranty rows and retain the normal next-run throttle below; quota
        # recovery rows are the explicit exception and are woken immediately.
        candidates = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status == "waiting",
            NvAutomationJob.step == "wait_warranty",
        )).all()
        due = []
        for job in candidates:
            if not _enabled_for(job, settings):
                continue
            context = _decode(job.context_json)
            deadline = auto_exit_at(context.get("warranty_until"), job_exit_delay(job, settings, context))
            quota_recovery = context.get("quota_rt_recovery") is True
            if (deadline is not None and deadline.timestamp() <= now
                    and (quota_recovery or job.next_run_at <= now)):
                due.append(job)
        if not due:
            return False
        retry_at = now + max(60, int(settings["scan_interval_seconds"]))
        needs_scan = False
        for job in due:
            context = _decode(job.context_json)
            if context.get("manual_sale") is True:
                # Manual sales have no NV evidence to scan.  Once their local
                # sale anchored delay expires, queue the same leave worker with
                # an explicit scoped authorization marker.
                identity = exit_identity(job, context)
                if identity is None:
                    continue
                context[MANUAL_EXIT_KEY] = {
                    "identity": identity, "request_id": "auto-" + uuid.uuid4().hex,
                    "requested_at": _iso(now), "warranty_until": context.get("warranty_until")}
                job.context_json = _json(context)
                job.step, job.status, job.next_run_at = "leave", "pending", now
                job.updated_at, job.version = now, job.version + 1
                session.add(job)
                _log(session, job, "人工售出倒计时结束，已排队自动核验并退出空间")
                continue
            # A rejected RT is repaired through the hidden OAuth worker. Do
            # not push that handoff behind the scan throttle; claim_due must
            # be able to start it on this dispatcher tick. Ordinary NV sales
            # still use the throttled read-only scan path.
            if _decode(job.context_json).get("quota_rt_recovery") is True:
                job.reconcile_requested = True
                job.next_run_at = now
                job.updated_at = now
                job.version += 1
                session.add(job)
                continue
            job.next_run_at = retry_at
            job.updated_at = now
            job.version += 1
            session.add(job)
            needs_scan = True
        if needs_scan:
            _request_scan_row(row, "已到最早自动退出时间，等待 NV 只读核对", now=now)
        session.add(row)
        return True


def claim_scan():
    _prepare_oauth_balance()
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        row = _settings_row(session)
        now = time.time()
        settings = _settings(row)
        if not settings["enabled"] or row.scan_token or not _has_processable_mother(session, settings):
            return None
        _recover_legacy_leave_preflights_locked(session, settings)
        request_generation = int(row.scan_request_generation or 0)
        completed_generation = int(row.scan_completed_generation or 0)
        if request_generation <= completed_generation:
            if row.next_scan_at > now:
                return None
            request_generation = max(request_generation, completed_generation) + 1
            row.scan_request_generation = request_generation
            row.scan_reason = _scan_reason(row.scan_reason, "定时 NV 核对")
        if row.scan_recovery_generation != request_generation:
            batch = _active_retry_batch(session) or _scheduled_retry_batch(session, request_generation)
            if batch is None:
                candidates = session.exec(select(NvAutomationJob).where(
                    NvAutomationJob.status.in_(["failed", "review"]),
                )).all()
                if any(_enabled_for(job, settings) and not job.pause_requested
                       and not job.worker_token and not job.worker_pid for job in candidates):
                    batch = _create_retry_batch_locked(session, settings, str(uuid.uuid4()),
                                                       generation=request_generation)
            elif not batch.scan_generation:
                batch.scan_generation = request_generation
                session.add(batch)
            row.scan_recovery_generation = request_generation
            row.scan_recovery_batch_id = batch.id if batch else ""
            session.add(row)
            session.flush()
        batch = _advance_retry_batch_locked(session, settings)
        if batch is not None:
            return None
        # Do not wait for every browser worker globally.  Reserve only the
        # mothers whose waiting/review jobs are admitted to this scan; other
        # mothers keep progressing through their own durable queue.
        busy_parents = {
            int(parent_id) for parent_id in session.exec(select(NvAutomationJob.parent_account_id).where(
                _occupied_worker_clause())).all()
        }
        reserved_parents = set()
        candidates = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status == "waiting",
            NvAutomationJob.step.in_(list(WAIT_STEPS)),
        )).all()
        for candidate in candidates:
            if candidate.parent_account_id in busy_parents:
                continue
            if _waiting_scan_safe(candidate, settings):
                reserved_parents.add(int(candidate.parent_account_id))
        review_candidates = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status.in_(("review", "failed")),
            NvAutomationJob.reconcile_requested == True,
        )).all()
        for candidate in review_candidates:
            if candidate.parent_account_id in busy_parents:
                continue
            if _review_scan_safe(candidate, settings):
                reserved_parents.add(int(candidate.parent_account_id))
        _set_scan_parent_ids(row, reserved_parents)
        row.scan_token, row.scan_heartbeat_at = uuid.uuid4().hex, time.time()
        row.scan_pid, row.scan_host = 0, socket.gethostname()
        row.scan_claim_generation = request_generation
        row.scan_claim_config_generation = int(row.config_generation or 0)
        row.scan_claim_reason = _scan_reason(row.scan_reason, "定时 NV 核对")
        row.scan_reason = ""
        row.next_scan_at = 0
        session.add(row)
        return row.scan_token


def scan_heartbeat(token, pid=0):
    with transaction() as session:
        row = _settings_row(session)
        if row.scan_token != token:
            raise RuntimeError("销售扫描执行权已改变")
        row.scan_heartbeat_at = time.time()
        if pid:
            row.scan_pid = pid
        session.add(row)


def scan_jobs(token):
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        row = _settings_row(session)
        if not row or row.scan_token != token:
            raise RuntimeError("销售扫描执行权已改变")
        settings = _settings(row)
        reserved_parents = _scan_parent_ids(row)
        # Paused jobs have no remote mutations. Resuming still requires a fresh
        # authoritative sale check; a local manual sale label never suffices.
        waiting = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status == "waiting",
            NvAutomationJob.step.in_(list(WAIT_STEPS)),
        )).all()
        claimed_generation = int(row.scan_claim_generation or 0)
        result = []
        for job in waiting:
            if int(job.parent_account_id) not in reserved_parents:
                continue
            if not _waiting_scan_safe(job, settings):
                continue
            # A sold quota repair is an OAuth worker substep, not an NV scan
            # candidate. Leave it to claim_due/reconcile_step so it can reuse
            # the mother-page RT acquisition flow.
            if _decode(job.context_json).get("quota_rt_recovery") is True:
                continue
            _mark_scan_snapshot(job, claimed_generation, manual=False)
            session.add(job)
            result.append(_worker(job, settings))
        manual = session.exec(select(NvAutomationJob).where(
            NvAutomationJob.status.in_(["review", "failed"]),
            NvAutomationJob.reconcile_requested == True,
        )).all()
        for job in manual:
            if int(job.parent_account_id) not in reserved_parents:
                continue
            marker = _review_scan_marker(job)
            if (
                marker is None
                or marker[0] > claimed_generation
                or marker[1] != job.version
                or not _review_scan_safe(job, settings)
            ):
                continue
            _mark_scan_snapshot(job, claimed_generation, manual=True)
            session.add(job)
            value = _worker(job, settings)
            value["nv_manual_recheck"] = True
            result.append(value)
        return result


def finish_scan(token, results, error=""):
    with transaction() as session:
        _cleanup_deleted_children_locked(session)
        row = _settings_row(session)
        if row.scan_token != token:
            return
        now = time.time()
        claim_generation = int(row.scan_claim_generation or 0)
        claim_config_generation = int(row.scan_claim_config_generation or 0)
        fresh_configuration = claim_config_generation == int(row.config_generation or 0)
        row.scan_token, row.scan_pid = "", 0
        row.scan_error = safe_message(error)
        row.last_scan_at = now
        row.scan_completed_generation = max(int(row.scan_completed_generation or 0), claim_generation)
        settings = _settings(row)
        all_jobs = session.exec(select(NvAutomationJob)).all()
        # A result is accepted only for a job durably admitted by scan_jobs()
        # into this exact claim. This prevents a same-version result for an
        # unrelated job from being injected into a global snapshot commit.
        scan_scope = {
            job.id: (job, marker)
            for job in all_jobs
            if (marker := _scan_snapshot_marker(job)) is not None
            and marker[0] == claim_generation
        }
        manual_scope = {
            job.id: (job, marker)
            for job in all_jobs
            if (marker := _review_scan_marker(job)) is not None
            and marker[0] <= claim_generation
        }
        safe_results = [result for result in results if isinstance(result, dict)]
        result_counts = {}
        result_by_id = {}
        for result in safe_results:
            identifier = result.get("job_id")
            result_counts[identifier] = result_counts.get(identifier, 0) + 1
            result_by_id[identifier] = result
        summary = {
            "checked": 0,
            "recovered": 0,
            "still_review": 0,
            "skipped": 0,
            "errors": 1 if error else 0,
        }
        candidate_ids = set(scan_scope) | set(manual_scope) | {
            identifier for identifier in result_by_id
            if isinstance(identifier, str) and identifier
        }
        malformed_results = sum(
            1 for result in safe_results
            if not isinstance(result.get("job_id"), str) or not result.get("job_id")
        )
        if not error and fresh_configuration:
            row.scan_verified_at = now
            row.scan_verified_config_generation = int(row.config_generation or 0)
            for identifier in candidate_ids:
                claimed = scan_scope.get(identifier)
                result = result_by_id.get(identifier)
                if claimed is None or result_counts.get(identifier) != 1 or result is None:
                    summary["skipped"] += 1
                    continue
                job, scan_marker = claimed
                manual = manual_scope.get(identifier)
                exact_snapshot = (
                    scan_marker == (claim_generation, job.version)
                    and result.get("version") == job.version
                )
                eligible = (
                    _review_scan_safe(job, settings)
                    if manual is not None
                    else _waiting_scan_safe(job, settings)
                )
                exact_manual = manual is None or manual[1][1] == job.version
                if not exact_snapshot or not exact_manual or not eligible:
                    summary["skipped"] += 1
                    continue
                from services.nv_sold_quota import StaleSoldQuotaDeactivation
                try:
                    _apply_result(session, job, result)
                except StaleSoldQuotaDeactivation:
                    # The bound child observation went stale after its GET.
                    # No job fields have changed; other sales can still commit.
                    summary["skipped"] += 1
                    continue
                summary["checked"] += 1
                if job.status == "review":
                    summary["still_review"] += 1
                elif job.status == "failed":
                    summary["errors"] += 1
                elif manual is not None:
                    summary["recovered"] += 1
            summary["skipped"] += malformed_results
        else:
            # A failed or stale-configuration scan never changes task errors,
            # markers, evidence, or steps. Its durable scope remains queued.
            summary["skipped"] = len(candidate_ids) + malformed_results
        # Release only the parent reservations belonging to this scan before
        # publishing the summary.  Newly queued work can then be claimed on
        # the next dispatcher tick without waiting for the global scan cycle.
        _set_scan_parent_ids(row, [])
        _write_settings_payload(row, settings, last_scan_summary=summary)
        newer_request = int(row.scan_request_generation or 0) > claim_generation
        if newer_request:
            # request_scan()/a configuration change happened after this claim;
            # preserve its due-now state and reason for the next generation.
            row.next_scan_at = 0
            row.scan_reason = _scan_reason(row.scan_reason, "有新事件等待 NV 核对")
        elif not settings["enabled"]:
            row.next_scan_at = 0
            row.scan_reason = "自动售号已关闭，等待重新启用"
        else:
            interval = max(60, int(settings["scan_interval_seconds"]))
            row.next_scan_at = now + interval
            row.scan_reason = "NV 扫描失败，等待计划重试" if error else "定时 NV 核对"
        row.scan_claim_reason = ""
        session.add(row)


def recover_stale(is_alive):
    """Only recover dead local workers. Live/foreign workers never lose a lease."""
    now, host = time.time(), socket.gethostname()
    released_parents = set()
    with transaction() as session:
        for job in session.exec(select(NvAutomationJob).where(_occupied_worker_clause())).all():
            if job.worker_host != host or now - job.heartbeat_at < 90 or (job.worker_pid and is_alive(job.worker_pid)):
                continue
            if job.status == "cancelled":
                job.worker_token, job.worker_pid = "", 0
                job.active_parent_key = job.active_child_key = job.active_membership_key = None
                job.updated_at = now
                job.version += 1
                session.add(job)
                released_parents.add(job.parent_account_id)
                continue
            _apply_result(session, job, _interrupted_result(session, job, "执行进程已退出，需核对远端结果；不会重复提交"))
        row = _settings_row(session)
        if row.scan_token and row.scan_host == host and now - row.scan_heartbeat_at > 90 and not (row.scan_pid and is_alive(row.scan_pid)):
            row.scan_token, row.scan_pid = "", 0
            _set_scan_parent_ids(row, [])
            row.next_scan_at = 0
            row.scan_error = "上次销售扫描中断，等待重新读取"
            row.scan_reason = "上次 NV 扫描中断，等待安全重试"
            row.scan_claim_reason = ""
            session.add(row)
    return dict(parent_account_ids=sorted(released_parents))
