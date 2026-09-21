"""Unified, credential-free CPA/Sub2API device management facade."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import threading
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from core.db import (
    DeliveryDeviceExhaustionCleanupModel,
    DeliveryDeviceReplenishmentDemandModel,
    DeliveryDeviceTeam401BatchModel,
    DeliveryDeviceTeam401TaskModel,
    GptBusinessAllocationJobModel,
    GptBusinessAllocationLeaseModel,
    GptBusinessAccountModel,
    GptBusinessAutomationPolicyModel,
    GptBusinessChildMembershipModel,
    GptBusinessRotationReservationModel,
    GptPlanAccountModel as GptProAccountModel,
    GptPlanAccountOperationLeaseModel as GptProAccountOperationLeaseModel,
    SyncDeviceModel,
    engine,
    resolve_business_delivery_binding,
)

# Internal legacy names below are aliases to the authoritative GPT plan tables.
# Device jobs and their fences therefore use plan ids exclusively.
from services import delivery_device_monitor as monitor


router = APIRouter(prefix="/delivery-devices", tags=["delivery-devices"])


class DeliveryDeviceCreateRequest(BaseModel):
    provider: str = "cpa"
    type: Optional[str] = None
    name: str
    api_url: str
    api_key: str = ""
    enabled: bool = True
    sub_group_ids: str = "2"


class DeliveryDeviceUpdateRequest(BaseModel):
    name: Optional[str] = None
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    enabled: Optional[bool] = None
    sub_group_ids: Optional[str] = None


class DeliveryDeviceRefreshTaskRequest(BaseModel):
    """Optional client idempotency key; an omitted body remains valid."""

    operation_id: str = ""


class DeliveryDeviceBusinessBindingsPutRequest(BaseModel):
    """Replace one device's complete set of locally bound BUSINESS mothers.

    A binding is directory metadata only.  Saving this DTO must never enqueue
    a delivery job or call an OpenAI/CPA/Sub2API mutation endpoint.
    """

    parent_ids: list[int] = Field(default_factory=list)
    expected_revisions: dict[int, int] = Field(default_factory=dict)

    @field_validator("parent_ids", mode="before")
    @classmethod
    def validate_parent_ids(cls, value: Any) -> list[int]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("parent_ids 必须是数组")
        if len(value) > 500:
            raise ValueError("单个设备最多绑定 500 个母号")
        result: list[int] = []
        for item in value:
            if (
                isinstance(item, bool)
                or not isinstance(item, int)
                or item <= 0
                or item > 2_147_483_647
            ):
                raise ValueError("parent_ids 只能包含正整数母号 ID")
            result.append(item)
        return result

    @field_validator("expected_revisions", mode="before")
    @classmethod
    def validate_expected_revisions(cls, value: Any) -> dict[int, int]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("expected_revisions 必须是对象")
        if len(value) > 500:
            raise ValueError("expected_revisions 最多包含 500 个母号")
        result: dict[int, int] = {}
        for raw_parent_id, revision in value.items():
            if isinstance(raw_parent_id, bool):
                raise ValueError("expected_revisions 的母号 ID 无效")
            if isinstance(raw_parent_id, int):
                parent_id = raw_parent_id
            elif (
                isinstance(raw_parent_id, str)
                and re.fullmatch(r"[1-9][0-9]*", raw_parent_id)
            ):
                parent_id = int(raw_parent_id)
            else:
                raise ValueError("expected_revisions 的母号 ID 无效")
            if parent_id > 2_147_483_647:
                raise ValueError("expected_revisions 的母号 ID 无效")
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
                or revision > 2_147_483_647
            ):
                raise ValueError("expected_revisions 只能包含非负整数版本")
            result[parent_id] = revision
        return result


class DeliveryTeamReplacementTaskRequest(BaseModel):
    """One exact, credential-free TEAM child replacement request."""

    operation_id: str = ""
    remote_id: str
    # All three immutable local identities are required.  A remote id or an
    # email match by itself is never sufficient authority for a destructive
    # mother/device operation.
    expected_business_parent_id: int
    expected_pro_account_id: int
    expected_membership_id: int


class DeliveryTeam401CorrectionBatchRequest(BaseModel):
    """Create/reuse one mother-scoped correction batch from the last scan."""

    business_parent_id: int
    operation_id: str = ""


_REFRESH_TASK_LOCK = threading.RLock()
_REFRESH_TASKS: dict[str, dict[str, Any]] = {}
_REFRESH_ACTIVE_BY_DEVICE: dict[str, str] = {}
_REFRESH_TASK_BY_OPERATION: dict[tuple[str, str], str] = {}
_REFRESH_TASK_TERMINAL = frozenset({"completed", "failed", "cancelled"})
_REFRESH_TASK_MAX_FINISHED = 50
_REFRESH_COUNT_KEYS = ("success", "skipped", "failed")
_REFRESH_LOG_MAX = 1000
_REFRESH_CHILD_LOG_MAX = 100
# A refresh that has committed a BUSINESS child cleanup remains the visible
# coordinator for its durable replenishment demand.  Polling is intentionally
# modest: the allocation scheduler owns retries, while this worker only
# mirrors progress and performs the final, non-mutating device verification.
_REFRESH_REPLENISHMENT_POLL_SECONDS = 2.0
_REFRESH_DEVICE_VERIFY_MAX_ATTEMPTS = 5
# Durable scheduler retries remain authoritative, but a single UI refresh
# must not occupy a device forever when the same recoverable checkpoint never
# advances.  Cooldown rows with a future resume time are exempt; all other
# repeated failures end with a stage-specific closed reason.
_REFRESH_FILL_MAX_ATTEMPTS = 12
_REFRESH_REPLENISHMENT_MAX_ATTEMPTS = 20
# A process-wide slot is acquired at the *individual child* boundary below.
# Executor pools are still grouped by mother, so children of one mother remain
# serial while unrelated mothers (including mothers on another device refresh)
# may progress concurrently.  The semaphore is the authoritative system-wide
# ceiling; the worker constants only avoid creating more waiting threads than
# can ever run.
_TEAM_CHILD_CONCURRENCY_MAX = 10
_TEAM_CHILD_OPERATION_SLOTS = threading.BoundedSemaphore(
    _TEAM_CHILD_CONCURRENCY_MAX,
)
# Per-device pools keep their existing resource profiles.  Multiple devices
# may run at once, but the global semaphore above still caps their combined
# in-flight children at ten.
_INVALID_REPLACEMENT_PARENT_WORKERS_MAX = 8
_EXHAUSTED_PARENT_WORKERS_MAX = 8
_CREDENTIAL_REPAIR_PARENT_WORKERS_MAX = 2
_MISSING_SYNC_PARENT_WORKERS_MAX = 3
# Missing-credential repair owns one account lease from the first token probe
# through managed-child OAuth and the verified upload.  A refresh may launch at
# most one complete browser OAuth for a child: an ``operation_busy`` result is
# known to occur before this worker owns a lease and may be polled briefly, but
# ``lease_lost`` or any OAuth result is terminal for this refresh.
_CREDENTIAL_UPLOAD_TRANSIENT_MAX_ATTEMPTS = 5
_MISSING_SYNC_TRANSIENT_RETRY_SECONDS = 1.0
_CREDENTIAL_RETRY_BACKOFF_MINUTES = 10
_CREDENTIAL_RETRY_EXTRA_KEY = "delivery_credential_retry_backoffs"
_TEAM_CHILD_PARENT_LOCKS_GUARD = threading.RLock()
_TEAM_CHILD_PARENT_LOCKS: dict[int, threading.RLock] = {}
_TEAM_CHILD_PROGRESS_CONTEXT = threading.local()
_SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# A BUSINESS mother in this one canonical state has already been refunded but
# the credit has not reached the payment method yet.  It must no longer own a
# delivery-device binding.  Intermediate refund states deliberately remain
# bound; they are still allowed by the replacement policy in gpt_business.py.
_REFUNDED_PARENT_CLEANUP_STATUS = "refunded_pending_credit"
_REFUNDED_PARENT_CLEANUP_OPERATION = "refunded_parent_device_cleanup"
_REFUNDED_PARENT_CLEANUP_LEASE_SECONDS = 60 * 60

_REFUNDED_PARENT_CPA_LINK_FIELDS = (
    "cpa_synced", "cpa_synced_to_id", "cpa_synced_to_name",
    "cpa_device_id", "cpa_config_domain", "cpa_auth_name",
    "cpa_synced_at", "cpa_usage", "cpa_monitor_alert",
    "cpa_disabled", "cpa_disabled_at", "cpa_disabled_reason",
    "cpa_lifecycle_state", "cpa_monitor_suppressed",
    "cpa_disable_pending", "cpa_disable_pending_at",
    "cpa_disable_pending_reason", "cpa_disable_last_error",
    "cpa_rotation_delete_required",
    "cpa_rotation_delete_required_target_id",
    "cpa_rotation_delete_required_auth_name",
    "cpa_rotation_delete_requested_at",
    "cpa_rotation_delete_confirmed",
    "cpa_rotation_delete_confirmed_at",
    "cpa_rotation_delete_confirmed_target_id",
    "cpa_rotation_delete_confirmed_auth_name",
    "cpa_rotation_delete_confirmed_ready_at",
    "cpa_migration_pending", "cpa_migration_target_id",
    "cpa_migration_source_disabled", "cpa_migration_started_at",
    "cpa_migration_last_error",
)
_REFUNDED_PARENT_SUB2API_LINK_FIELDS = (
    "sub2api_device_id", "sub2api_device_name",
    "sub2api_remote_account_id", "sub2api_synced_at",
    "sub2api_account_kind", "sub2api_business_parent_id",
    "sub2api_sync_pending", "sub2api_sync_pending_device_id",
    "sub2api_sync_pending_device_name",
    "sub2api_sync_pending_started_at",
    "sub2api_sync_pending_remote_account_id",
    "sub2api_sync_pending_operation_token",
    "sub2api_sync_pending_business_parent_id", "sub2api_usage",
    "sub2api_last_error", "sub2api_last_error_at",
    "sub2api_monitor_alert",
)

# TEAM 401 correction is intentionally independent from device refresh.  One
# process-wide semaphore bounds all child workers across every device/batch;
# the existing GPT BUSINESS parent RLock and durable allocation leases remain
# authoritative for mother-side removal/invitation.
_TEAM401_CONCURRENCY_MAX = 10
# Reuse the one process-wide child-operation gate.  Refresh reconciliation,
# manual replacement and explicit 401 correction together may never exceed
# ten in-flight child operations.
_TEAM401_OPERATION_SLOTS = _TEAM_CHILD_OPERATION_SLOTS
_TEAM401_THREADS_LOCK = threading.RLock()
_TEAM401_THREADS: dict[str, threading.Thread] = {}
_TEAM401_LEASE_SECONDS = 60 * 60
_TEAM401_RECHECK_SECONDS = 15
_TEAM401_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})
_TEAM401_ACTIVE_STATES = frozenset({"prepared", "queued", "running", "waiting"})
_TEAM401_STAGES = frozenset({
    "queued",
    "checking_account",
    "account_confirmed_active",
    "account_confirmed_dead",
    "acquiring_original_rt",
    "uploading_original_credential",
    "verifying_original_credential",
    "deleting_old_credential",
    "removing_old_child",
    "selecting_replacement",
    "candidate_login",
    "inviting_replacement",
    "accepting_replacement",
    "acquiring_replacement_rt",
    "uploading_replacement",
    "verifying_replacement",
    "waiting_cooldown",
    "waiting_replacement",
    "completed",
    "failed",
})
# A checked, active child finishes as ``repaired``; only a child explicitly
# proven account_deactivated enters the durable ``replaced`` chain.
_TEAM401_RESULTS = frozenset({"", "repaired", "replaced", "failed"})
_TEAM401_ERROR_MESSAGES = {
    "": "",
    "identity_changed": "设备账号或 TEAM 子号归属已变化，请重新扫描",
    "snapshot_not_401": "当前快照不再是 HTTP 401，未执行纠错",
    "device_changed": "设备配置已变化，请重新扫描",
    "operation_busy": "同一子号已有任务执行中，请稍后重试",
    "account_check_failed": "旧子号登录状态无法明确确认，未删除设备凭证或母号成员",
    "account_state_conflict": "旧子号本地状态与本次登录结果冲突，需人工复核",
    "device_delete_failed": "旧设备凭证删除未确认，已停止后续步骤",
    "account_missing": "本地子号不存在，已停止处理",
    "account_deactivated": "子号已停用，正在按换号流程处理",
    "oauth_failed": "获取子号 RT / OAuth 失败",
    "oauth_timeout": "获取子号 RT / OAuth 超时",
    "upload_failed": "新凭证上传设备失败",
    "device_verify_failed": "设备未确认新凭证生效",
    "business_parent_missing": "母号不存在，无法执行换号",
    "business_parent_unavailable": "母号当前不可安全执行换号",
    "business_parent_refunded_pending_credit": (
        "母号已退款未到账，纠错任务已取消"
    ),
    "seat_type_unknown": "旧子号席位类型未知，无法自动补位",
    "replacement_candidate_unavailable": "暂无可用替补子号",
    "waiting_cooldown": "母号处于邀请失败冷却期，任务将在到期后继续",
    "replacement_failed": "旧子号移除或替补流程失败",
    "replenishment_missing": "旧子号已移除，但补位任务未建立",
    "replenishment_action_required": "补位任务需要人工复核",
    "cleanup_lifecycle_busy": "同一子号已有移除任务执行中，等待其释放",
    "cleanup_lifecycle_owned": "同一子号已有任务跨越不可逆步骤，需人工复核",
    "replacement_verify_failed": "新子号凭证未在原设备确认生效",
    "request_corrupt": "任务身份校验失败，已停止处理",
    "internal_error": "任务执行失败，未继续后续步骤",
}
_TEAM401_STAGE_MESSAGES = {
    "queued": "纠错任务已加入队列",
    "checking_account": "正在登录旧子号并确认账号是否已停用",
    "account_confirmed_active": "已确认旧子号可用，保留母号成员",
    "account_confirmed_dead": "已确认旧子号停用，准备进入母号换号流程",
    "acquiring_original_rt": "旧子号可用，正在重新获取 RT / OAuth",
    "uploading_original_credential": "正在用新 RT 覆盖原设备凭证",
    "verifying_original_credential": "正在刷新额度并确认原子号凭证已生效",
    "deleting_old_credential": "正在精确删除设备中的旧 401 凭证",
    "removing_old_child": "正在调用母号能力移除旧子号",
    "selecting_replacement": "正在选择同席位类型的替补子号",
    "candidate_login": "正在登录新的普通账号",
    "inviting_replacement": "正在邀请替补子号加入母号",
    "accepting_replacement": "正在确认替补子号加入母号",
    "acquiring_replacement_rt": "正在让替补子号加入母号并获取 RT / OAuth",
    "uploading_replacement": "正在把替补子号上传到原设备",
    "verifying_replacement": "正在确认替补子号已在原设备生效",
    "waiting_cooldown": "母号处于邀请失败冷却期，等待到期后继续",
    "waiting_replacement": "替补流程已持久化，等待下一次检查",
    "completed": "TEAM 401 纠错已完成",
    "failed": "TEAM 401 纠错已停止",
}
_TEAM401_STAGE_PERCENT = {
    "queued": 0,
    "checking_account": 5,
    "account_confirmed_active": 15,
    "account_confirmed_dead": 15,
    "acquiring_original_rt": 30,
    "uploading_original_credential": 80,
    "verifying_original_credential": 95,
    "deleting_old_credential": 10,
    "removing_old_child": 20,
    "selecting_replacement": 30,
    "candidate_login": 40,
    "inviting_replacement": 50,
    "accepting_replacement": 60,
    "acquiring_replacement_rt": 70,
    "uploading_replacement": 85,
    "verifying_replacement": 95,
    "waiting_cooldown": 20,
    "waiting_replacement": 30,
    "completed": 100,
    "failed": 100,
}

_REFRESH_CHILD_TERMINAL = frozenset({
    "completed", "failed", "skipped", "blocked",
})
_REFRESH_CHILD_OPERATIONS = frozenset({
    "quota_exhausted_cleanup",
    "credential_invalid_replacement",
    "credential_repair",
    "credential_upload",
    # A database-backed BUSINESS allocation job selected one new child for a
    # still-available typed seat on a bound mother.  The allocation row is the
    # durable source of truth; this in-memory row is only its refresh-dialog
    # projection.
    "business_fill",
})
_REFRESH_CHILD_STATUSES = frozenset({
    "queued", "running", "completed", "failed", "skipped", "blocked",
    "pending",
})
_REFRESH_CHILD_STAGES = frozenset({
    "queued",
    "waiting_for_slot",
    "preflight",
    "removing_business_child",
    "removing_device_account",
    "removing_exhausted_account",
    "replenishment_pending",
    "checking_parent",
    "selecting_candidate",
    "waiting_candidate",
    "waiting_cooldown",
    "waiting_credential_retry",
    "waiting_resource",
    "waiting_typed_seat",
    "retrying_check",
    "fill_running",
    "planned",
    "candidate_login",
    "inviting",
    "invited",
    "pending_acceptance",
    "auto_accept",
    "rt_pending",
    "oauth_pending",
    "oauth_failed",
    "acquiring_oauth",
    "cpa_sync",
    "sub2api_sync",
    "uploading_credential",
    "active_verify",
    "completed",
    "failed",
    "skipped",
    "blocked",
    "pending",
})
_REFRESH_CHILD_RESULTS = frozenset({
    "success", "failed", "skipped", "blocked", "pending",
    "replenishment_handoff", "replacement_completed", "repaired",
    "uploaded", "removed",
})
_REFRESH_CHILD_ERRORS = frozenset({
    "operation_failed",
    "business_parent_missing",
    "business_parent_disabled",
    "business_parent_dangerous",
    "business_parent_refunded",
    "seat_type_unknown",
    "identity_changed",
    "operation_busy",
    "account_deactivated",
    "token_invalidated",
    "credential_unauthorized",
    "credential_replacement_failed",
    "credential_repair_failed",
    "upload_failed",
    "oauth_failed",
    "oauth_timeout",
    "lease_lost",
    "workspace_login_failed",
    "candidate_unavailable",
    "invite_failed",
    "acceptance_failed",
    "parent_unavailable",
    "device_verify_failed",
    "remote_absence_unconfirmed",
    "replenishment_missing",
    "replenishment_binding_changed",
    "replenishment_cancelled",
    "replenishment_action_required",
    "credential_retry_cooldown",
})

_REFRESH_CHILD_STAGE_LOG_MESSAGES = {
    "queued": "子号任务已加入处理队列",
    "waiting_for_slot": "正在等待子号处理槽位",
    "preflight": "正在核对子号、母号与设备绑定",
    "removing_business_child": "正在从母号移除旧子号",
    "removing_device_account": "正在从设备删除旧子号凭证",
    "removing_exhausted_account": "正在从设备删除额度耗尽的旧账号",
    "replenishment_pending": "旧子号清理已完成，正在等待同席位补位",
    "checking_parent": "正在检查母号席位与邀请失败冷却状态",
    "selecting_candidate": "正在选择安全的替补子号",
    "waiting_candidate": "暂无可用替补子号，等待下一次调度",
    "waiting_cooldown": "母号处于邀请失败冷却期，等待 10 分钟退避结束",
    "waiting_credential_retry": "子号凭证修复处于冷却期，等待预计重试时间",
    "waiting_resource": "正在等待母号操作资源",
    "waiting_typed_seat": "正在等待相同类型的可用席位",
    "retrying_check": "正在重新检查补位条件",
    "fill_running": "新子号补位流程正在运行",
    "planned": "已选定替补子号",
    "candidate_login": "正在登录新普通账号",
    "inviting": "正在邀请新子号加入母号",
    "invited": "新子号邀请已发送",
    "pending_acceptance": "正在等待新子号加入母号",
    "auto_accept": "正在确认新子号加入母号",
    "rt_pending": "正在获取新子号 RT / OAuth",
    "oauth_pending": "正在获取新子号 RT / OAuth",
    "oauth_failed": "RT / OAuth 获取失败，等待安全重试",
    "acquiring_oauth": "正在让子号加入母号并获取 RT / OAuth",
    "cpa_sync": "正在上传新子号凭证到 CPA 设备",
    "sub2api_sync": "正在上传新子号凭证到 SUB 设备",
    "uploading_credential": "正在上传子号凭证到设备",
    "active_verify": "正在确认新子号凭证已在设备生效",
    "completed": "子号任务已完成",
    "failed": "子号任务处理失败",
    "skipped": "子号任务已安全跳过",
    "blocked": "子号任务因安全条件被阻断",
    "pending": "子号任务正在等待已有操作完成",
}

_REFRESH_CHILD_ERROR_LOG_MESSAGES = {
    "operation_failed": "子号任务处理失败，安全状态已保留",
    "business_parent_missing": "母号不存在，子号任务已阻断",
    "business_parent_disabled": "母号已禁用，子号任务已阻断",
    "business_parent_dangerous": "母号已标记异常，子号任务已阻断",
    "business_parent_refunded": "母号已进入已退款列表，子号任务已阻断",
    "seat_type_unknown": "无法确认原席位类型，子号任务已阻断",
    "identity_changed": "子号归属或设备绑定已变化，已停止处理",
    "operation_busy": "同一子号已有任务处理中",
    "account_deactivated": "账号已停用，需要更换子号；本次凭证操作已停止",
    "token_invalidated": "子号凭证已失效，等待安全处理",
    "credential_unauthorized": "子号凭证操作未获授权",
    "credential_replacement_failed": "子号换号未完成，安全状态已保留",
    "credential_repair_failed": "子号凭证修复失败，安全状态已保留",
    "upload_failed": "子号凭证上传多次未确认，已停止自动重试，需要人工复核",
    "oauth_failed": "子号 RT / OAuth 多次失败，已停止自动重试，需要人工复核",
    "oauth_timeout": "子号 RT / OAuth 持续超时，已停止自动重试，需要人工复核",
    "lease_lost": "子号操作租约已变化，已停止本次处理",
    "workspace_login_failed": "子号登录或进入工作区失败",
    "candidate_unavailable": "持续没有可用替补子号，已停止自动重试，需要人工复核",
    "invite_failed": "新子号邀请多次失败，已停止自动重试，需要人工复核",
    "acceptance_failed": "新子号多次未确认加入母号，已停止自动重试，需要人工复核",
    "parent_unavailable": "母号当前不可用，子号任务已阻断",
    "device_verify_failed": "设备端凭证多次未确认，已停止自动重试，需要人工复核",
    "remote_absence_unconfirmed": "设备清单未能确认旧凭证已不存在，已停止换号以避免误删",
    "replenishment_missing": "补位任务未建立，需要人工复核",
    "replenishment_binding_changed": "补位任务绑定已变化，需要人工复核",
    "replenishment_cancelled": "补位任务已取消",
    "replenishment_action_required": "补位任务需要人工处理",
    "credential_retry_cooldown": "子号凭证修复处于独立冷却期",
}

_SAFE_ACCOUNT_OPERATION_LABELS = {
    "delivery_missing_credential_oauth": "设备补传 OAuth 任务",
    "delivery_credential_repair": "凭证修复任务",
    "cpa_sync": "CPA 凭证同步任务",
    "cpa_reconcile": "CPA 凭证对账任务",
    "cpa_disable": "CPA 凭证停用任务",
    "cpa_auto_upload_reconcile": "CPA 自动补传任务",
    "cpa_cleanup": "CPA 凭证清理任务",
    "sub2api_sync": "SUB 凭证同步任务",
    "sub2api_usage": "SUB 额度查询任务",
    "sub2api_unlink": "SUB 凭证删除任务",
    "delivery_exhaustion_cleanup": "设备换号清理任务",
    "upgrade_pro": "PRO 升级任务",
    "refund": "退款任务",
    "refund_burn": "焚决退款任务",
}
_SAFE_ACCOUNT_OPERATION_LABEL_VALUES = frozenset({
    *_SAFE_ACCOUNT_OPERATION_LABELS.values(),
    "账号任务",
})

_REFRESH_CHILD_SAFE_LOG_MESSAGES = frozenset({
    *_REFRESH_CHILD_STAGE_LOG_MESSAGES.values(),
    *_REFRESH_CHILD_ERROR_LOG_MESSAGES.values(),
    "新子号已获取 RT 并同步到原设备，换号完成",
    "子号 RT / OAuth 与设备凭证修复完成",
    "子号凭证已上传并确认",
    "旧账号已从设备安全移除",
    "子号任务状态已更新",
    "检测到同账号其他任务，等待其释放",
    "租约释放后本任务已继续",
    "OAuth 期间旧租约发生变化并已释放，本次自动重试已耗尽",
    "同账号任务租约已释放，但本次自动重试仍未完成，需要稍后重试",
    *(
        f"正在等待同账号任务释放，第 {attempt}/"
        f"{_CREDENTIAL_UPLOAD_TRANSIENT_MAX_ATTEMPTS - 1} 次重试"
        for attempt in range(1, _CREDENTIAL_UPLOAD_TRANSIENT_MAX_ATTEMPTS)
    ),
    *(
        f"多次等待后{label}仍在执行，需要稍后重试"
        for label in _SAFE_ACCOUNT_OPERATION_LABEL_VALUES
    ),
})

_REPLACEMENT_THREADS_LOCK = threading.RLock()
_REPLACEMENT_THREADS: dict[str, threading.Thread] = {}

_NONRETRYABLE_MANUAL_CLEANUP_STAGES = frozenset({
    "cleanup_identity_changed",
    "device_changed",
})

_CLEANUP_OPERATION = "delivery_exhaustion_cleanup"
_CLEANUP_LEASE_SECONDS = 20 * 60
_CLEANUP_RECOVERABLE_STATES = frozenset({
    "prepared", "running", "waiting", "action_required", "failed",
})
_CLEANUP_TRIGGERS = frozenset({
    "quota_exhausted", "manual_replace", "credential_invalid",
    "credential_missing_deactivated", "team401_replace",
})
_REPLACEMENT_CLEANUP_TRIGGERS = frozenset({
    "manual_replace", "credential_invalid",
    "credential_missing_deactivated", "team401_replace",
})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utcnow().isoformat()


def _safe_public_datetime(value: Any) -> str:
    """Serialize only a valid bounded ISO timestamp from trusted local state."""
    if isinstance(value, datetime):
        return value.isoformat()
    raw = str(value or "").strip()[:64]
    if not raw:
        return ""
    try:
        datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    return raw


def _safe_datetime_value(value: Any) -> Optional[datetime]:
    """Parse one trusted local ISO/datetime value into aware UTC."""
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = _safe_public_datetime(value)
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validated_provider(value: str) -> str:
    provider = monitor.normalize_provider(value)
    if provider not in {"cpa", "sub2api"}:
        raise HTTPException(400, "设备类型只支持 CPA 或 Sub2API")
    return provider


def _validated_url(value: str) -> str:
    url = str(value or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(400, "API 地址必须是有效的 http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(400, "API 地址不能包含账号密码、查询参数或片段")
    return url


def _safe_task_log_line(value: Any) -> str:
    """Defense in depth for task logs; callers still use a closed vocabulary."""
    text = str(value or "")[:500]
    text = re.sub(r"(?i)bearer\s+\S+", "Bearer [REDACTED]", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(api[_-]?key|token|cookie|password|secret)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+",
        "[ACCOUNT]",
        text,
    )
    return text


def _refresh_task_log(task_id: str, message: str) -> None:
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task:
            return
        logs = task.setdefault("logs", [])
        logs.append(_safe_task_log_line(message))
        if len(logs) > _REFRESH_LOG_MAX:
            removed = len(logs) - _REFRESH_LOG_MAX
            del logs[:removed]
            task["log_base"] = int(task.get("log_base") or 0) + removed
        task["updated_at"] = _iso_now()


def _safe_child_progress_email(value: Any) -> str:
    """Return an email-shaped UI label, never arbitrary upstream text."""
    email = str(value or "").strip()[:320]
    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,255}",
        email,
    ):
        return ""
    return email


def _business_child_progress_identity(
    source: dict[str, Any],
) -> dict[str, Any]:
    """Extract only the credential-free exact TEAM lifecycle identity."""
    navigation = (
        source.get("navigation")
        if isinstance(source.get("navigation"), dict)
        else {}
    )
    if (
        str(navigation.get("state") or "") == "mapped"
        and str(navigation.get("target_kind") or "") == "business_child"
    ):
        parent_value = navigation.get("business_parent_id")
        child_value = navigation.get("pro_account_id")
        membership_value = navigation.get("membership_id")
        email_value = source.get("email")
    else:
        parent_value = source.get("parent_id")
        child_value = source.get("child_id")
        membership_value = source.get("membership_id")
        email_value = source.get("email")
    try:
        parent_id = int(parent_value or 0)
        child_id = int(child_value or 0)
        membership_id = int(membership_value or 0)
    except (TypeError, ValueError):
        return {}
    if min(parent_id, child_id, membership_id) <= 0:
        return {}
    return {
        "key": f"business:{parent_id}:{child_id}:{membership_id}",
        "email": _safe_child_progress_email(email_value),
        "parent_id": parent_id,
        "child_id": child_id,
        "membership_id": membership_id,
    }


def _business_fill_progress_identity(
    job: GptBusinessAllocationJobModel,
) -> dict[str, Any]:
    """Project one durable device-fill job to a credential-free UI identity.

    A membership does not exist yet while the candidate is being logged in or
    invited.  A dedicated key therefore follows the selected child from the
    ``planned`` checkpoint onward; the eventual membership id is exposed as
    ``replacement_membership_id`` after remote acceptance is confirmed.
    """
    try:
        parent_id = int(job.selected_business_account_id or 0)
        child_id = int(job.selected_pro_account_id or 0)
    except (TypeError, ValueError):
        return {}
    if min(parent_id, child_id) <= 0:
        return {}
    return {
        "key": f"business-fill:{parent_id}:{child_id}",
        "email": _safe_child_progress_email(job.selected_email),
        "parent_id": parent_id,
        "child_id": child_id,
        "membership_id": 0,
    }


def _team_child_parent_lock(parent_id: int) -> threading.RLock:
    """Return the process-wide serial lane shared by every device refresh."""
    normalized = max(0, int(parent_id or 0))
    with _TEAM_CHILD_PARENT_LOCKS_GUARD:
        lock = _TEAM_CHILD_PARENT_LOCKS.get(normalized)
        if lock is None:
            lock = threading.RLock()
            _TEAM_CHILD_PARENT_LOCKS[normalized] = lock
        return lock


def _set_team_child_progress_context(
    task_id: str,
    identity: dict[str, Any],
) -> None:
    _TEAM_CHILD_PROGRESS_CONTEXT.task_id = str(task_id or "")
    _TEAM_CHILD_PROGRESS_CONTEXT.identity = dict(identity or {})


def _clear_team_child_progress_context() -> None:
    _TEAM_CHILD_PROGRESS_CONTEXT.task_id = ""
    _TEAM_CHILD_PROGRESS_CONTEXT.identity = {}


def _team_child_progress_context(
    task_id: str,
    identity: Optional[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    return (
        str(task_id or getattr(_TEAM_CHILD_PROGRESS_CONTEXT, "task_id", "")),
        dict(
            identity
            or getattr(_TEAM_CHILD_PROGRESS_CONTEXT, "identity", {})
            or {}
        ),
    )


def _refresh_child_log_message(row: dict[str, Any]) -> str:
    """Build one Chinese message exclusively from closed progress enums."""
    operation = str(row.get("operation") or "")
    status = str(row.get("status") or "")
    stage = str(row.get("stage") or "")
    result = str(row.get("result") or "")
    error = str(row.get("error") or "")
    # Retryable rows can retain a diagnostic from the previous attempt.  While
    # work is active, the current stage is authoritative; only terminal rows
    # render an error message ahead of their stage.
    if (
        status in _REFRESH_CHILD_TERMINAL
        and error in _REFRESH_CHILD_ERROR_LOG_MESSAGES
    ):
        return _REFRESH_CHILD_ERROR_LOG_MESSAGES[error]
    if status == "completed" or result in {
        "success", "replacement_completed", "repaired", "uploaded", "removed",
    }:
        if operation in {
            "quota_exhausted_cleanup", "credential_invalid_replacement",
        } and result == "replacement_completed":
            return "新子号已获取 RT 并同步到原设备，换号完成"
        if operation == "credential_repair" or result == "repaired":
            return "子号 RT / OAuth 与设备凭证修复完成"
        if operation == "credential_upload" or result == "uploaded":
            return "子号凭证已上传并确认"
        if operation == "business_fill":
            return "新子号已加入母号、取得 RT 并上传到设备"
        if result == "removed":
            return "旧账号已从设备安全移除"
    return _REFRESH_CHILD_STAGE_LOG_MESSAGES.get(
        stage,
        "子号任务状态已更新",
    )


def _refresh_task_child_append_log_locked(
    task: dict[str, Any],
    row: dict[str, Any],
) -> None:
    """Append one bounded credential-free event while task lock is held."""
    stage = str(row.get("stage") or "queued")
    if stage not in _REFRESH_CHILD_STAGES:
        stage = "pending"
    cursor = max(0, int(task.get("_child_log_cursor") or 0)) + 1
    task["_child_log_cursor"] = cursor
    event = {
        "seq": cursor,
        "stage": stage,
        "message": _safe_task_log_line(_refresh_child_log_message(row)),
        "created_at": _iso_now(),
    }
    logs = row.setdefault("_logs", [])
    if not isinstance(logs, list):
        logs = []
        row["_logs"] = logs
    logs.append(event)
    if len(logs) > _REFRESH_CHILD_LOG_MAX:
        del logs[:len(logs) - _REFRESH_CHILD_LOG_MAX]


def _refresh_task_child_safe_log(
    task_id: str,
    identity: dict[str, Any],
    *,
    stage: str,
    message: str,
) -> None:
    """Append one explicit event from the finite credential-free vocabulary."""
    safe_stage = str(stage or "pending")
    safe_message = str(message or "")
    if (
        safe_stage not in _REFRESH_CHILD_STAGES
        or safe_message not in _REFRESH_CHILD_SAFE_LOG_MESSAGES
    ):
        return
    key = str(identity.get("key") or "")
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        row = (task.get("child_progress") or {}).get(key) if task else None
        if not isinstance(row, dict):
            return
        cursor = max(0, int(task.get("_child_log_cursor") or 0)) + 1
        task["_child_log_cursor"] = cursor
        logs = row.setdefault("_logs", [])
        if not isinstance(logs, list):
            logs = []
            row["_logs"] = logs
        logs.append({
            "seq": cursor,
            "stage": safe_stage,
            "message": safe_message,
            "created_at": _iso_now(),
        })
        if len(logs) > _REFRESH_CHILD_LOG_MAX:
            del logs[:len(logs) - _REFRESH_CHILD_LOG_MAX]
        now = _iso_now()
        row["updated_at"] = now
        task["updated_at"] = now


def _active_child_operation_label(child_id: int) -> str:
    """Return one closed UI label for a currently live account lease."""
    try:
        with Session(engine) as session:
            lease = session.get(
                GptProAccountOperationLeaseModel,
                int(child_id),
            )
            if not (
                lease
                and _active_lease(lease.expires_at, _utcnow())
            ):
                return ""
            return _SAFE_ACCOUNT_OPERATION_LABELS.get(
                str(lease.operation or "").strip(),
                "账号任务",
            )
    except Exception:
        return ""


@contextmanager
def _team_child_operation_slot(
    task_id: str,
    identity: dict[str, Any],
):
    """Serialize one mother, then count one child against the global cap."""
    parent_lock = _team_child_parent_lock(int(identity["parent_id"]))
    # This order is shared by every call site: a same-parent waiter never takes
    # one of the ten process-wide child slots while it waits for its mother.
    parent_lock.acquire()
    try:
        _TEAM_CHILD_OPERATION_SLOTS.acquire()
        try:
            _set_team_child_progress_context(task_id, identity)
            yield
        finally:
            _clear_team_child_progress_context()
            _TEAM_CHILD_OPERATION_SLOTS.release()
    finally:
        parent_lock.release()


def _refresh_task_child_update(
    task_id: str,
    identity: dict[str, Any],
    *,
    operation: Optional[str] = None,
    status: Optional[str] = None,
    stage: Optional[str] = None,
    percent: Optional[int] = None,
    result: Optional[str] = None,
    error: Optional[str] = None,
    next_check_at: Optional[Any] = None,
) -> None:
    """Update one safe per-child snapshot using closed vocabulary only.

    No token, API key, remote response, exception message or remote credential
    identifier can enter this structure.  The UI receives only an email label,
    local numeric lifecycle ids and closed enum values.
    """
    key = str(identity.get("key") or "")
    try:
        parent_id = int(identity.get("parent_id") or 0)
        child_id = int(identity.get("child_id") or 0)
        membership_id = int(identity.get("membership_id") or 0)
    except (TypeError, ValueError):
        return
    current_lifecycle_key = f"business:{parent_id}:{child_id}:{membership_id}"
    fill_lifecycle_key = f"business-fill:{parent_id}:{child_id}"
    current_lifecycle = bool(
        key == current_lifecycle_key
        and min(parent_id, child_id, membership_id) > 0
    )
    fill_lifecycle = bool(
        key == fill_lifecycle_key
        and parent_id > 0
        and child_id > 0
        and membership_id == 0
    )
    if not current_lifecycle and not fill_lifecycle:
        return
    safe_operation = (
        str(operation) if operation in _REFRESH_CHILD_OPERATIONS else None
    )
    safe_status = str(status) if status in _REFRESH_CHILD_STATUSES else None
    safe_stage = str(stage) if stage in _REFRESH_CHILD_STAGES else None
    safe_result = str(result) if result in _REFRESH_CHILD_RESULTS else None
    safe_error = str(error) if error in _REFRESH_CHILD_ERRORS else None
    clear_error = bool(
        (error is not None and str(error) == "")
        or (
            error is None
            and safe_status in {"queued", "running"}
            and safe_stage is not None
        )
    )
    now = _iso_now()
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task:
            return
        rows = task.setdefault("child_progress", {})
        row = rows.get(key)
        progress_changed = False
        if not isinstance(row, dict):
            if safe_operation is None:
                return
            row = {
                "key": key,
                "email": _safe_child_progress_email(identity.get("email")),
                "parent_id": parent_id,
                "child_id": child_id,
                "membership_id": membership_id,
                "parent_email": _safe_child_progress_email(
                    identity.get("parent_email"),
                ),
                "parent_note": str(identity.get("parent_note") or "")[:200],
                "operation": safe_operation,
                "status": "queued",
                "stage": "queued",
                "percent": 0,
                "result": None,
                "error": None,
                "updated_at": now,
            }
            rows[key] = row
            progress_changed = True
        elif not row.get("email"):
            row["email"] = _safe_child_progress_email(identity.get("email"))
        if safe_operation is not None:
            progress_changed = progress_changed or row.get("operation") != safe_operation
            row["operation"] = safe_operation
        if safe_status is not None:
            progress_changed = progress_changed or row.get("status") != safe_status
            row["status"] = safe_status
        if safe_stage is not None:
            progress_changed = progress_changed or row.get("stage") != safe_stage
            row["stage"] = safe_stage
        if percent is not None:
            row["percent"] = max(0, min(100, int(percent)))
        if safe_result is not None:
            progress_changed = progress_changed or row.get("result") != safe_result
            row["result"] = safe_result
        if safe_error is not None:
            progress_changed = progress_changed or row.get("error") != safe_error
            row["error"] = safe_error
        elif clear_error:
            progress_changed = progress_changed or row.get("error") is not None
            row["error"] = None
        if next_check_at is not None:
            safe_next_check_at = _safe_public_datetime(next_check_at)
            progress_changed = bool(
                progress_changed
                or str(row.get("next_check_at") or "")
                != safe_next_check_at
            )
            row["next_check_at"] = safe_next_check_at
            row["resume_at"] = safe_next_check_at
        if safe_status in _REFRESH_CHILD_TERMINAL:
            row["percent"] = 100
        if progress_changed:
            _refresh_task_child_append_log_locked(task, row)
        row["updated_at"] = now
        task["updated_at"] = now


def _safe_child_failure_code(
    *values: Any,
    default: str = "",
) -> str:
    """Collapse internal/upstream diagnostics to one credential-free enum."""
    text = " ".join(str(value or "") for value in values).strip().lower()
    if any(marker in text for marker in (
        "account_deactivated", "account_deleted", "deleted or deactivated",
        "account has been deactivated", "账号已停用", "账户已停用", "已被停用",
    )):
        return "account_deactivated"
    for value in values:
        exact = str(value or "").strip().lower()
        if exact in _REFRESH_CHILD_ERRORS:
            return exact
    if any(marker in text for marker in (
        "gpt_pro_account_busy", "operation_busy", "account_busy",
        "账号正在执行", "账号刚被其他流程占用", "已有操作正在执行",
    )):
        return "operation_busy"
    if "timeout" in text or "timed out" in text or "超时" in text:
        return "oauth_timeout"
    # Never use a raw ``"lease" in text`` check here: the ordinary English
    # word ``Please`` contains that substring.  OpenAI's invalid-RT response
    # says "Please log in again", which previously turned a genuine
    # ``refresh_token_invalidated`` into the misleading ``lease_lost`` state.
    if (
        "租约" in text
        or "fenced" in text
        or "lease_lost" in text
        or "lease lost" in text
        or re.search(r"(?<![a-z0-9_])lease(?![a-z0-9_])", text)
    ):
        return "lease_lost"
    if any(marker in text for marker in (
        "not_authorized", "unauthorized", "credential_unauthorized", "未授权",
    )):
        return "credential_unauthorized"
    if any(marker in text for marker in (
        "token_invalidated", "invalid token", "status 401", "http_401",
    )):
        return "token_invalidated"
    if any(marker in text for marker in (
        "workspace_join", "workspace_login", "parent_session_unavailable",
        "进入工作区", "登录/进入工作区", "会话不可用",
    )):
        return "workspace_login_failed"
    if any(marker in text for marker in (
        "no_candidate", "candidate_unavailable", "waiting_candidate", "暂无可用",
    )):
        return "candidate_unavailable"
    if any(marker in text for marker in (
        "acceptance", "pending_acceptance", "auto_accept", "成员确认", "尚未加入",
    )):
        return "acceptance_failed"
    if "invite" in text or "邀请" in text:
        return "invite_failed"
    if any(marker in text for marker in (
        "cpa_failed", "sub2api_failed", "sync_failed", "upload_failed",
        "设备同步", "上传",
    )):
        return "upload_failed"
    if any(marker in text for marker in (
        "parent_missing", "parent_disabled", "parent_unsafe", "母号已不存在",
    )):
        return "parent_unavailable"
    if any(marker in text for marker in (
        "binding_conflict", "binding_changed", "binding_removed",
        "fill_job_missing", "identity_changed", "身份校验",
    )):
        return "replenishment_binding_changed"
    if "cancelled" in text or "canceled" in text or "已取消" in text:
        return "replenishment_cancelled"
    if any(marker in text for marker in (
        "oauth", "child_rt", "refresh_token", "refresh token", "rt_",
        "未取得 rt",
    )):
        return "oauth_failed"
    return default if default in _REFRESH_CHILD_ERRORS else ""


def _refresh_task_child_link_replenishment(
    task_id: str,
    identity: dict[str, Any],
    *,
    cleanup_job_id: str = "",
    replenishment_demand_id: str = "",
    fill_job_id: str = "",
) -> None:
    """Attach durable lifecycle ids to an internal child row.

    These ids are deliberately omitted by ``_refresh_task_snapshot``.  They
    only let later GET polls resolve the durable cleanup -> demand -> fill
    lifecycle after the device scan coordinator itself has finished.
    """
    key = str(identity.get("key") or "")
    cleanup_id = str(cleanup_job_id or "").strip()
    demand_id = str(replenishment_demand_id or "").strip()
    fill_id = str(fill_job_id or "").strip()
    if cleanup_id and not _SAFE_OPERATION_ID.fullmatch(cleanup_id):
        cleanup_id = ""
    if demand_id and not _SAFE_OPERATION_ID.fullmatch(demand_id):
        demand_id = ""
    if fill_id and not _SAFE_OPERATION_ID.fullmatch(fill_id):
        fill_id = ""
    if not key or (not cleanup_id and not demand_id and not fill_id):
        return
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        row = (task.get("child_progress") or {}).get(key) if task else None
        if not isinstance(row, dict):
            return
        changed = False
        if cleanup_id and str(row.get("_cleanup_job_id") or "") != cleanup_id:
            row["_cleanup_job_id"] = cleanup_id
            changed = True
        if demand_id and str(row.get("_replenishment_demand_id") or "") != demand_id:
            row["_replenishment_demand_id"] = demand_id
            changed = True
        if fill_id and str(row.get("_fill_job_id") or "") != fill_id:
            row["_fill_job_id"] = fill_id
            changed = True
        if changed:
            now = _iso_now()
            row["updated_at"] = now
            task["updated_at"] = now


def _business_fill_child_rt_action(actions: dict[str, Any]) -> dict[str, Any]:
    """Read the child RT checkpoint across the capability cutover."""
    current = actions.get("child_rt")
    if isinstance(current, dict):
        return current
    legacy = actions.get("rt")
    return legacy if isinstance(legacy, dict) else {}


def _safe_replenishment_child_stage(value: Any, *, has_fill: bool) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "waiting_seat_snapshot": "inviting",
        "waiting_device": "inviting",
        "fill_running": "inviting",
        "replace_invite_pending": "inviting",
        "seat_type_unconfirmed": "acquiring_oauth",
        "seat_type_mismatch": "acquiring_oauth",
        "oauth_checkpoint_stale": "acquiring_oauth",
        "cpa_failed": "uploading_credential",
        "sub2api_failed": "uploading_credential",
        "cpa_compensation_pending": "uploading_credential",
        "cpa_policy_changed": "uploading_credential",
        "sub2api_policy_changed": "uploading_credential",
        "candidate_account_deactivated": "inviting",
        "candidate_reselected": "inviting",
        "candidate_reselection_exhausted": "inviting",
        "candidate_reselection_forbidden": "inviting",
        "candidate_reselection_waiting": "inviting",
        "candidate_release_failed": "inviting",
    }
    raw = aliases.get(raw, raw)
    if raw in {
        "removing_device_account", "removing_exhausted_account",
        "removing_business_child", "uploading_credential", "active_verify",
    }:
        return raw
    if "sync" in raw or "upload" in raw or "cpa" in raw or "sub2api" in raw:
        return "uploading_credential"
    # Invitation acceptance and workspace membership are prerequisites inside
    # the child-owned RT capability, not an independent public device phase.
    if (
        raw in {"invited", "pending_acceptance", "auto_accept", "child_rt"}
        or "accept" in raw
        or "member" in raw
        or "oauth" in raw
        or raw.startswith("rt_")
    ):
        return "acquiring_oauth"
    # Candidate selection, first login, capacity/cooldown waits and the actual
    # invite send are all internal states of the mother invitation capability.
    return "inviting"


def _refresh_retry_terminal_error(raw_stage: Any, safe_error: str = "") -> str:
    if safe_error in _REFRESH_CHILD_ERRORS:
        return safe_error
    stage = str(raw_stage or "").strip().lower()
    if "candidate" in stage:
        return "candidate_unavailable"
    if "accept" in stage or "member" in stage:
        return "acceptance_failed"
    if "invite" in stage:
        return "invite_failed"
    if stage == "child_rt" or "oauth" in stage or stage.startswith("rt_"):
        return "oauth_failed"
    if any(marker in stage for marker in ("cpa", "sub2api", "sync", "upload")):
        return "upload_failed"
    if "parent" in stage or "session" in stage:
        return "parent_unavailable"
    return "replenishment_action_required"


def _refresh_replenishment_child_state(
    row: dict[str, Any],
    device_ref: str,
) -> Optional[dict[str, Any]]:
    """Read one linked durable lifecycle and return only closed safe values."""
    cleanup_id = str(row.get("_cleanup_job_id") or "").strip()
    demand_id = str(row.get("_replenishment_demand_id") or "").strip()
    if not cleanup_id and not demand_id:
        return None
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        parent_id = int(row.get("parent_id") or 0)
        parent_email = ""
        parent_note = ""
        # Some rolling-migration/unit-test databases may not yet have the
        # BUSINESS parent table.  Parent labelling is optional enrichment and
        # must never suppress the authoritative demand/fill lifecycle.
        try:
            with Session(engine) as parent_session:
                parent = parent_session.get(
                    GptBusinessAccountModel,
                    parent_id,
                )
                parent_email = _safe_child_progress_email(
                    parent.email if parent else "",
                )
                parent_note = str(parent.note if parent else "")[:200]
        except Exception:
            parent_email = ""
        with Session(engine) as session:
            demand = (
                session.get(DeliveryDeviceReplenishmentDemandModel, demand_id)
                if demand_id else None
            )
            if demand is None and cleanup_id:
                demand = session.exec(
                    select(DeliveryDeviceReplenishmentDemandModel).where(
                        DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                        == cleanup_id
                    )
                ).first()
            if demand is None:
                cleanup = (
                    session.get(
                        DeliveryDeviceExhaustionCleanupModel,
                        cleanup_id,
                    )
                    if cleanup_id else None
                )
                if cleanup is None:
                    return {
                        "parent_email": parent_email,
                        "parent_note": parent_note,
                        "next_check_at": "",
                        "resume_at": "",
                        "attempt_count": 0,
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": "replenishment_missing",
                        "demand_id": "",
                    }
                cleanup_state = str(
                    cleanup.state or "prepared",
                ).strip().lower()
                cleanup_stage = str(
                    cleanup.stage or "preflight",
                ).strip().lower()
                if (
                    cleanup_state != "completed"
                    and cleanup_stage in {
                        "business_replacement_quota_unavailable",
                        "waiting_cooldown",
                    }
                ):
                    cleanup_cooldown = _cleanup_replacement_cooldown(
                        session,
                        cleanup,
                        _cleanup_request(cleanup),
                    )
                    live_resume_at = _safe_datetime_value(
                        (cleanup_cooldown or {}).get("resume_at"),
                    )
                    # The parent row is authoritative.  A persisted timestamp
                    # may be a legacy 48-hour quota checkpoint and must not keep
                    # the task visually blocked after real invite cooldown ends.
                    effective_resume_at = live_resume_at
                    resume_at = _safe_public_datetime(effective_resume_at)
                    # Cooldown is an internal wait inside the mother invitation
                    # capability; it is not a seventh public device phase.
                    public_stage = "inviting"
                    return {
                        "parent_email": parent_email,
                        "next_check_at": resume_at,
                        "resume_at": resume_at,
                        "attempt_count": max(
                            0, int(cleanup.attempt_count or 0),
                        ),
                        "status": "running",
                        "stage": public_stage,
                        "percent": max(10, min(
                            39,
                            int(_replacement_progress(
                                public_stage,
                                "running",
                            )),
                        )),
                        "result": "pending",
                        "error": None,
                        "demand_id": "",
                    }
                if cleanup_state in {
                    "action_required", "failed", "superseded",
                }:
                    cleanup_error = _safe_child_failure_code(
                        cleanup_stage,
                        cleanup.error,
                        default="credential_replacement_failed",
                    )
                    return {
                        "parent_email": parent_email,
                        "next_check_at": "",
                        "resume_at": "",
                        "attempt_count": max(
                            0, int(cleanup.attempt_count or 0),
                        ),
                        "status": (
                            "skipped"
                            if cleanup_state == "superseded" else "failed"
                        ),
                        "stage": (
                            "skipped"
                            if cleanup_state == "superseded" else "failed"
                        ),
                        "percent": 100,
                        "result": (
                            "skipped"
                            if cleanup_state == "superseded" else "failed"
                        ),
                        "error": (
                            "identity_changed"
                            if cleanup_state == "superseded"
                            else cleanup_error
                        ),
                        "demand_id": "",
                    }
                if cleanup_state == "completed":
                    return {
                        "parent_email": parent_email,
                        "next_check_at": "",
                        "resume_at": "",
                        "attempt_count": max(
                            0, int(cleanup.attempt_count or 0),
                        ),
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": "replenishment_missing",
                        "demand_id": "",
                    }
                public_cleanup_stage = {
                    "business_remove_pending": "removing_business_child",
                    "removing_business_child": "removing_business_child",
                    "device_delete_pending": "removing_device_account",
                    "removing_device_account": "removing_device_account",
                    "replenishment_pending": "replenishment_pending",
                }.get(cleanup_stage, "preflight")
                return {
                    "parent_email": parent_email,
                    "next_check_at": "",
                    "resume_at": "",
                    "attempt_count": max(
                        0, int(cleanup.attempt_count or 0),
                    ),
                    "status": "running",
                    "stage": public_cleanup_stage,
                    "percent": max(10, min(
                        39,
                        int(_replacement_progress(
                            public_cleanup_stage,
                            "running",
                        )),
                    )),
                    "result": "pending",
                    "error": None,
                    "demand_id": "",
                }
            resolved_demand_id = str(demand.id or "")
            binding_matches = bool(
                str(demand.provider or "") == str(provider)
                and int(demand.device_id or 0) == int(provider_id)
                and int(demand.business_parent_id or 0) == parent_id
                and (
                    not cleanup_id
                    or str(demand.cleanup_job_id or "") == cleanup_id
                )
            )
            fill = (
                session.get(
                    GptBusinessAllocationJobModel,
                    str(demand.fill_job_id),
                )
                if str(demand.fill_job_id or "") else None
            )
            replacement_child_id = int(
                fill.selected_pro_account_id or 0
            ) if fill else 0
            replacement_child = (
                session.get(GptProAccountModel, replacement_child_id)
                if replacement_child_id > 0 else None
            )
            replacement_email = _safe_child_progress_email(
                replacement_child.email if replacement_child else ""
            )
            fill_attempt_count = max(
                0, int(fill.attempt_count or 0),
            ) if fill else 0
            durable_state_fields = {
                "parent_email": parent_email,
                "parent_note": parent_note,
                "next_check_at": _safe_public_datetime(
                    demand.next_check_at,
                ),
                "resume_at": _safe_public_datetime(demand.resume_at),
                "attempt_count": max(
                    max(0, int(demand.attempt_count or 0)),
                    fill_attempt_count,
                ),
                "fill_job_id": str(fill.id or "") if fill else "",
                "replacement_child_id": replacement_child_id,
                "replacement_membership_id": 0,
                "replacement_email": replacement_email,
                "delivery_ready": False,
            }
            if fill is not None:
                try:
                    from api import gpt_business

                    binding_matches = bool(
                        binding_matches
                        and gpt_business._replenishment_fill_job_is_bound(
                            demand,
                            fill,
                            require_persisted_fill_job_id=True,
                        )
                    )
                except Exception:
                    binding_matches = False
            elif str(demand.fill_job_id or ""):
                binding_matches = False

            demand_state = str(demand.state or "pending").strip().lower()
            fill_state = str(fill.state or "").strip().lower() if fill else ""
            raw_stage = str(
                (fill.stage if fill else None)
                or demand.stage
                or "replenishment_pending"
            ).strip().lower()
            safe_error = _safe_child_failure_code(
                raw_stage,
                fill.error if fill else "",
                demand.error,
            )
            pair_completed = bool(
                binding_matches
                and demand_state == "completed"
                and fill is not None
                and fill_state == "completed"
                and str(fill.stage or "").strip().lower() == "completed"
            )
            if pair_completed:
                fill_id = str(fill.id or "")
                actions = _json_object(fill.action_state_json)
                membership_action = (
                    actions.get("membership")
                    if isinstance(actions.get("membership"), dict)
                    else {}
                )
                rt_action = _business_fill_child_rt_action(actions)
                delivery_action = (
                    actions.get(provider)
                    if isinstance(actions.get(provider), dict)
                    else {}
                )
                try:
                    delivery_target_id = int(
                        delivery_action.get("target_id") or 0
                    )
                except (TypeError, ValueError):
                    delivery_target_id = 0
                active_memberships = list(session.exec(
                    select(GptBusinessChildMembershipModel).where(
                        GptBusinessChildMembershipModel.business_account_id
                        == parent_id,
                        GptBusinessChildMembershipModel.pro_account_id
                        == replacement_child_id,
                        GptBusinessChildMembershipModel.ended_at.is_(None),  # type: ignore[union-attr]
                    )
                ).all()) if replacement_child_id > 0 else []
                replacement_membership_id = (
                    int(active_memberships[0].id or 0)
                    if len(active_memberships) == 1 else 0
                )
                evidence_error = ""
                if (
                    replacement_child_id <= 0
                    or replacement_membership_id <= 0
                    or str(membership_action.get("status") or "")
                    != "member"
                ):
                    evidence_error = "acceptance_failed"
                elif rt_action.get("ready") is not True:
                    evidence_error = "oauth_failed"
                elif not (
                    delivery_action.get("synced") is True
                    and delivery_target_id == int(provider_id)
                ):
                    evidence_error = "upload_failed"

                if evidence_error:
                    return {
                        **durable_state_fields,
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": evidence_error,
                        "demand_id": resolved_demand_id,
                        "fill_job_id": fill_id,
                        "replacement_child_id": replacement_child_id,
                        "replacement_membership_id": replacement_membership_id,
                        "replacement_email": replacement_email,
                        "delivery_ready": False,
                    }
                if str(row.get("_verified_fill_job_id") or "") == fill_id:
                    return {
                        **durable_state_fields,
                        "status": "completed",
                        "stage": "completed",
                        "percent": 100,
                        "result": "replacement_completed",
                        "error": None,
                        "demand_id": resolved_demand_id,
                        "fill_job_id": fill_id,
                        "replacement_child_id": replacement_child_id,
                        "replacement_membership_id": replacement_membership_id,
                        "replacement_email": replacement_email,
                        "delivery_ready": True,
                    }
                if (
                    str(row.get("_device_verify_failed_fill_job_id") or "")
                    == fill_id
                ):
                    return {
                        **durable_state_fields,
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": "device_verify_failed",
                        "demand_id": resolved_demand_id,
                        "fill_job_id": fill_id,
                        "replacement_child_id": replacement_child_id,
                        "replacement_membership_id": replacement_membership_id,
                        "replacement_email": replacement_email,
                        "delivery_ready": True,
                    }
                return {
                    **durable_state_fields,
                    "status": "running",
                    "stage": "active_verify",
                    "percent": 95,
                    "result": "pending",
                    "error": None,
                    "demand_id": resolved_demand_id,
                    "fill_job_id": fill_id,
                    "replacement_child_id": replacement_child_id,
                    "replacement_membership_id": replacement_membership_id,
                    "replacement_email": replacement_email,
                    "delivery_ready": True,
                }
            if not binding_matches:
                return {
                    **durable_state_fields,
                    "status": "blocked",
                    "stage": "blocked",
                    "percent": 100,
                    "result": "blocked",
                    "error": "replenishment_binding_changed",
                    "demand_id": resolved_demand_id,
                }
            if demand_state == "cancelled":
                return {
                    **durable_state_fields,
                    "status": "skipped",
                    "stage": "skipped",
                    "percent": 100,
                    "result": "skipped",
                    "error": safe_error or "replenishment_cancelled",
                    "demand_id": resolved_demand_id,
                }
            # A manual continue reserves/restarts the exact fill before it can
            # update the older demand checkpoint.  During that narrow window
            # the fill is the live source of truth; do not let a stale
            # ``action_required`` demand paint a real running ``child_rt`` (or
            # queued worker) as blocked.
            fill_is_active = bool(
                binding_matches
                and fill is not None
                and fill_state in {"queued", "retry_queued", "running"}
            )
            if demand_state == "action_required" and not fill_is_active:
                return {
                    **durable_state_fields,
                    "status": "blocked",
                    "stage": "blocked",
                    "percent": 100,
                    "result": "blocked",
                    "error": _refresh_retry_terminal_error(
                        raw_stage,
                        safe_error,
                    ),
                    "demand_id": resolved_demand_id,
                }
            if fill is not None and fill_state in {"failed", "action_required"}:
                if not bool(fill.retryable):
                    return {
                        **durable_state_fields,
                        "status": "blocked" if fill_state == "action_required" else "failed",
                        "stage": "blocked" if fill_state == "action_required" else "failed",
                        "percent": 100,
                        "result": "blocked" if fill_state == "action_required" else "failed",
                        "error": _refresh_retry_terminal_error(
                            raw_stage,
                            safe_error,
                        ),
                        "demand_id": resolved_demand_id,
                    }
                if fill_attempt_count >= int(_REFRESH_FILL_MAX_ATTEMPTS):
                    exhausted_error = _refresh_retry_terminal_error(
                        raw_stage,
                        safe_error,
                    )
                    return {
                        **durable_state_fields,
                        "status": "blocked",
                        "stage": "blocked",
                        "percent": 100,
                        "result": "blocked",
                        "error": exhausted_error,
                        "demand_id": resolved_demand_id,
                    }
            demand_attempt_count = max(0, int(demand.attempt_count or 0))
            if (
                fill is None
                and demand_state in {"waiting", "retrying"}
                and demand_attempt_count
                >= int(_REFRESH_REPLENISHMENT_MAX_ATTEMPTS)
                and not (
                    str(demand.stage or "").strip().lower()
                    == "waiting_cooldown"
                    and demand.resume_at is not None
                )
            ):
                return {
                    **durable_state_fields,
                    "status": "blocked",
                    "stage": "blocked",
                    "percent": 100,
                    "result": "blocked",
                    "error": _refresh_retry_terminal_error(
                        raw_stage,
                        safe_error,
                    ),
                    "demand_id": resolved_demand_id,
                }

            public_stage = _safe_replenishment_child_stage(
                raw_stage,
                has_fill=fill is not None,
            )
            percent = min(99, max(
                40,
                int(_replacement_progress(public_stage, "running")),
            ))
            return {
                **durable_state_fields,
                "status": "running",
                "stage": public_stage,
                "percent": percent,
                "result": (
                    "pending" if fill is not None
                    else "replenishment_handoff"
                ),
                # Retryable allocation rows often retain the previous attempt's
                # diagnostic while their current stage has already advanced.
                # Showing that stale code would turn e.g. ``invited`` into an
                # "邀请失败" log.  Active progress is represented by its
                # current closed stage; an error is published only at a
                # terminal outcome above.
                "error": None,
                "demand_id": resolved_demand_id,
                "fill_job_id": str(fill.id or "") if fill else "",
                "replacement_child_id": replacement_child_id,
                "replacement_membership_id": 0,
                "replacement_email": replacement_email,
                "delivery_ready": False,
            }
    except Exception:
        # Snapshot hydration is read-only enrichment.  A rolling migration or
        # temporary DB read failure must not expose an exception or break the
        # task endpoint; retain the last already-sanitized in-memory state.
        return None


def _refresh_direct_fill_child_state(
    row: dict[str, Any],
    device_ref: str,
) -> Optional[dict[str, Any]]:
    """Hydrate one refresh-created BUSINESS fill from its durable job.

    Unlike replacement demands, a free-seat fill has no old membership and no
    cleanup row.  The allocation job nevertheless owns every irreversible
    checkpoint (candidate, invite, acceptance, OAuth and delivery), so the
    refresh dialog can recover its exact progress by reading that row.
    """
    fill_id = str(row.get("_fill_job_id") or "").strip()
    if not fill_id:
        return None
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        parent_id = int(row.get("parent_id") or 0)
        child_id = int(row.get("child_id") or 0)
        if min(parent_id, child_id) <= 0:
            return None
        with Session(engine) as session:
            fill = session.get(GptBusinessAllocationJobModel, fill_id)
            parent = session.get(GptBusinessAccountModel, parent_id)
            parent_email = _safe_child_progress_email(
                parent.email if parent else "",
            )
            parent_note = str(parent.note if parent else "")[:200]
            if fill is None:
                return {
                    "parent_email": parent_email,
                    "parent_note": parent_note,
                    "next_check_at": "",
                    "resume_at": "",
                    "attempt_count": 0,
                    "status": "failed",
                    "stage": "failed",
                    "percent": 100,
                    "result": "failed",
                    "error": "replenishment_missing",
                    "fill_job_id": fill_id,
                    "replacement_child_id": child_id,
                    "replacement_membership_id": 0,
                    "replacement_email": _safe_child_progress_email(
                        row.get("email"),
                    ),
                    "delivery_ready": False,
                }
            request = _json_object(fill.request_json)
            policy = session.get(
                GptBusinessAutomationPolicyModel,
                parent_id,
            )
            target_id = int(
                request.get(
                    "cpa_target_id"
                    if provider == "cpa"
                    else "sub2api_device_id"
                ) or 0
            )
            policy_target_id = int(
                getattr(
                    policy,
                    "cpa_target_id"
                    if provider == "cpa"
                    else "sub2api_device_id",
                    0,
                ) or 0
            ) if policy else 0
            binding_matches = bool(
                str(request.get("job_kind") or "")
                == "master_dispatch_fill"
                and str(request.get("delivery_type") or "") == provider
                and target_id == int(provider_id)
                and int(fill.selected_business_account_id or 0) == parent_id
                and int(fill.selected_pro_account_id or 0) == child_id
                and policy
                and bool(policy.auto_rotation_enabled)
                and str(policy.delivery_type or "") == provider
                and policy_target_id == int(provider_id)
                and int(policy.revision or 0)
                == int(request.get("policy_revision") or -1)
            )
            replacement_email = _safe_child_progress_email(
                fill.selected_email,
            )
            active_memberships = list(session.exec(
                select(GptBusinessChildMembershipModel).where(
                    GptBusinessChildMembershipModel.business_account_id
                    == parent_id,
                    GptBusinessChildMembershipModel.pro_account_id
                    == child_id,
                    GptBusinessChildMembershipModel.ended_at.is_(None),  # type: ignore[union-attr]
                )
            ).all())
            membership_id = (
                int(active_memberships[0].id or 0)
                if len(active_memberships) == 1 else 0
            )
            actions = _json_object(fill.action_state_json)
            membership_action = (
                actions.get("membership")
                if isinstance(actions.get("membership"), dict)
                else {}
            )
            rt_action = _business_fill_child_rt_action(actions)
            delivery_action = (
                actions.get(provider)
                if isinstance(actions.get(provider), dict)
                else {}
            )
            try:
                delivery_target_id = int(
                    delivery_action.get("target_id") or 0
                )
            except (TypeError, ValueError):
                delivery_target_id = 0
            state = str(fill.state or "queued").strip().lower()
            raw_stage = str(fill.stage or "planned").strip().lower()
            attempts = max(0, int(fill.attempt_count or 0))
            common = {
                "parent_email": parent_email,
                "parent_note": parent_note,
                "next_check_at": "",
                "resume_at": "",
                "attempt_count": attempts,
                "fill_job_id": fill_id,
                "replacement_child_id": child_id,
                "replacement_membership_id": membership_id,
                "replacement_email": replacement_email,
                "delivery_ready": False,
            }
            if not binding_matches:
                return {
                    **common,
                    "status": "blocked",
                    "stage": "blocked",
                    "percent": 100,
                    "result": "blocked",
                    "error": "replenishment_binding_changed",
                }
            if state == "completed" and raw_stage == "completed":
                evidence_error = ""
                if (
                    membership_id <= 0
                    or str(membership_action.get("status") or "") != "member"
                ):
                    evidence_error = "acceptance_failed"
                elif rt_action.get("ready") is not True:
                    # ``already_ready`` jobs also persist ready=True in the
                    # terminal action snapshot.  Anything else is not enough
                    # evidence to call the child delivered.
                    evidence_error = "oauth_failed"
                elif not (
                    delivery_action.get("synced") is True
                    and delivery_target_id == int(provider_id)
                ):
                    evidence_error = "upload_failed"
                if evidence_error:
                    return {
                        **common,
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": evidence_error,
                    }
                if str(row.get("_verified_fill_job_id") or "") == fill_id:
                    return {
                        **common,
                        "status": "completed",
                        "stage": "completed",
                        "percent": 100,
                        "result": "success",
                        "error": None,
                        "delivery_ready": True,
                    }
                if (
                    str(row.get("_device_verify_failed_fill_job_id") or "")
                    == fill_id
                ):
                    return {
                        **common,
                        "status": "failed",
                        "stage": "failed",
                        "percent": 100,
                        "result": "failed",
                        "error": "device_verify_failed",
                        "delivery_ready": True,
                    }
                return {
                    **common,
                    "status": "running",
                    "stage": "active_verify",
                    "percent": 95,
                    "result": "pending",
                    "error": None,
                    "delivery_ready": True,
                }
            safe_error = _safe_child_failure_code(
                raw_stage,
                fill.error,
            )
            if state in {"failed", "action_required"} and (
                not bool(fill.retryable)
                or attempts >= int(_REFRESH_FILL_MAX_ATTEMPTS)
            ):
                blocked = state == "action_required"
                return {
                    **common,
                    "status": "blocked" if blocked else "failed",
                    "stage": "blocked" if blocked else "failed",
                    "percent": 100,
                    "result": "blocked" if blocked else "failed",
                    "error": _refresh_retry_terminal_error(
                        raw_stage,
                        safe_error,
                    ),
                }
            public_stage = _safe_replenishment_child_stage(
                raw_stage,
                has_fill=True,
            )
            return {
                **common,
                "status": "running",
                "stage": public_stage,
                "percent": min(94, max(
                    5,
                    int(_replacement_progress(public_stage, "running")),
                )),
                "result": "pending",
                # A retryable allocation checkpoint may retain the previous
                # diagnostic; the closed current stage is authoritative.
                "error": None,
            }
    except Exception:
        return None


def _refresh_task_apply_replenishment_state(
    task_id: str,
    key: str,
    state: dict[str, Any],
) -> None:
    safe_status = str(state.get("status") or "")
    safe_stage = str(state.get("stage") or "")
    safe_result = str(state.get("result") or "")
    safe_error = str(state.get("error") or "")
    if (
        safe_status not in _REFRESH_CHILD_STATUSES
        or safe_stage not in _REFRESH_CHILD_STAGES
        or safe_result not in _REFRESH_CHILD_RESULTS
        or (safe_error and safe_error not in _REFRESH_CHILD_ERRORS)
    ):
        return
    percent = max(0, min(100, int(state.get("percent") or 0)))
    demand_id = str(state.get("demand_id") or "").strip()
    fill_job_id = str(state.get("fill_job_id") or "").strip()
    if demand_id and not _SAFE_OPERATION_ID.fullmatch(demand_id):
        demand_id = ""
    if fill_job_id and not _SAFE_OPERATION_ID.fullmatch(fill_job_id):
        fill_job_id = ""
    try:
        replacement_child_id = max(
            0, int(state.get("replacement_child_id") or 0),
        )
        replacement_membership_id = max(
            0, int(state.get("replacement_membership_id") or 0),
        )
    except (TypeError, ValueError):
        replacement_child_id = 0
        replacement_membership_id = 0
    replacement_email = _safe_child_progress_email(
        state.get("replacement_email"),
    )
    parent_email = _safe_child_progress_email(state.get("parent_email"))
    parent_note = str(state.get("parent_note") or "")[:200]
    next_check_at = _safe_public_datetime(state.get("next_check_at"))
    resume_at = _safe_public_datetime(state.get("resume_at"))
    try:
        attempt_count = max(0, int(state.get("attempt_count") or 0))
    except (TypeError, ValueError):
        attempt_count = 0
    delivery_ready = state.get("delivery_ready") is True
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        row = (task.get("child_progress") or {}).get(str(key)) if task else None
        if not isinstance(row, dict):
            return
        changes = {
            "status": safe_status,
            "stage": safe_stage,
            "percent": percent,
            "result": safe_result,
            "error": safe_error or None,
        }
        if demand_id:
            changes["_replenishment_demand_id"] = demand_id
        if fill_job_id:
            changes["_fill_job_id"] = fill_job_id
        if replacement_child_id > 0:
            changes["replacement_child_id"] = replacement_child_id
        if replacement_membership_id > 0:
            changes["replacement_membership_id"] = replacement_membership_id
        if replacement_email:
            changes["replacement_email"] = replacement_email
        if parent_email:
            changes["parent_email"] = parent_email
        if parent_note:
            changes["parent_note"] = parent_note
        changes["next_check_at"] = next_check_at
        changes["resume_at"] = resume_at
        changes["attempt_count"] = attempt_count
        changes["_delivery_ready"] = delivery_ready
        has_logs = bool(
            isinstance(row.get("_logs"), list) and row.get("_logs")
        )
        if (
            has_logs
            and all(row.get(name) == value for name, value in changes.items())
        ):
            return
        progress_changed = any(
            row.get(name) != changes[name]
            for name in ("status", "stage", "result", "error")
        ) or not has_logs
        row.update(changes)
        if progress_changed:
            _refresh_task_child_append_log_locked(task, row)
        now = _iso_now()
        row["updated_at"] = now
        task["updated_at"] = now


def _refresh_task_hydrate_replenishment_children(
    task_id: str,
    device_ref: str,
) -> list[dict[str, Any]]:
    """Hydrate every linked cleanup/demand row from durable state.

    The returned rows remain internal copies.  Durable identifiers and device
    verification markers are never serialized by the public task endpoint.
    """
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task or str(task.get("device_ref") or "") != str(device_ref):
            return []
        hydration_rows = [
            dict(row)
            for row in (task.get("child_progress") or {}).values()
            if isinstance(row, dict)
            and (
                str(row.get("_cleanup_job_id") or "")
                or str(row.get("_replenishment_demand_id") or "")
                or str(row.get("_fill_job_id") or "")
            )
        ]
    for hydration_row in hydration_rows:
        hydrated = (
            _refresh_replenishment_child_state(
                hydration_row,
                device_ref,
            )
            if (
                str(hydration_row.get("_cleanup_job_id") or "")
                or str(
                    hydration_row.get("_replenishment_demand_id") or ""
                )
            )
            else _refresh_direct_fill_child_state(
                hydration_row,
                device_ref,
            )
        )
        if hydrated is not None:
            _refresh_task_apply_replenishment_state(
                str(task_id),
                str(hydration_row.get("key") or ""),
                hydrated,
            )
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task or str(task.get("device_ref") or "") != str(device_ref):
            return []
        return [
            dict(row)
            for row in (task.get("child_progress") or {}).values()
            if isinstance(row, dict)
            and (
                str(row.get("_cleanup_job_id") or "")
                or str(row.get("_replenishment_demand_id") or "")
                or str(row.get("_fill_job_id") or "")
            )
        ]


def _refresh_remote_confirms_replacement(
    row: dict[str, Any],
    remote_items: list[dict[str, Any]],
) -> bool:
    """Require one exact, enabled device-link lifecycle for the new child."""
    try:
        parent_id = int(row.get("parent_id") or 0)
        child_id = int(row.get("replacement_child_id") or 0)
        membership_id = int(row.get("replacement_membership_id") or 0)
    except (TypeError, ValueError):
        return False
    if min(parent_id, child_id, membership_id) <= 0:
        return False
    exact: list[dict[str, Any]] = []
    for item in remote_items:
        if not isinstance(item, dict):
            continue
        navigation = (
            item.get("navigation")
            if isinstance(item.get("navigation"), dict)
            else {}
        )
        try:
            matches = bool(
                str(navigation.get("state") or "") == "mapped"
                and str(navigation.get("match_basis") or "")
                == "device_link"
                and str(navigation.get("target_kind") or "")
                == "business_child"
                and int(navigation.get("business_parent_id") or 0)
                == parent_id
                and int(navigation.get("pro_account_id") or 0) == child_id
                and int(navigation.get("membership_id") or 0)
                == membership_id
            )
        except (TypeError, ValueError):
            matches = False
        if matches:
            exact.append(item)
    if len(exact) != 1:
        return False
    item = exact[0]
    try:
        repair_status = int(item.get("credential_repair_status") or 0)
    except (TypeError, ValueError):
        repair_status = 0
    return bool(
        item.get("disabled") is not True
        and item.get("credential_repair_required") is not True
        and repair_status != 401
    )


def _refresh_task_record_device_verification(
    task_id: str,
    key: str,
    fill_job_id: str,
    *,
    verified: bool,
) -> None:
    """Persist only an in-memory closed verification marker for one fill."""
    if not fill_job_id or not _SAFE_OPERATION_ID.fullmatch(fill_job_id):
        return
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        row = (task.get("child_progress") or {}).get(str(key)) if task else None
        if not isinstance(row, dict):
            return
        if str(row.get("_fill_job_id") or "") != fill_job_id:
            return
        if verified:
            row["_verified_fill_job_id"] = fill_job_id
            row.pop("_device_verify_failed_fill_job_id", None)
            row.pop("_device_verify_attempts", None)
        else:
            attempts = (
                int(row.get("_device_verify_attempts") or 0) + 1
                if str(row.get("_device_verify_attempt_fill_job_id") or "")
                == fill_job_id else 1
            )
            row["_device_verify_attempt_fill_job_id"] = fill_job_id
            row["_device_verify_attempts"] = attempts
            if attempts >= int(_REFRESH_DEVICE_VERIFY_MAX_ATTEMPTS):
                row["_device_verify_failed_fill_job_id"] = fill_job_id
        now = _iso_now()
        row["updated_at"] = now
        task["updated_at"] = now


def _wait_for_refresh_business_deliveries(
    task_id: str,
    device_ref: str,
) -> dict[str, int]:
    """Keep the top refresh active through refill, upload and device proof."""
    waiting_logged = False
    while True:
        rows = _refresh_task_hydrate_replenishment_children(
            task_id,
            device_ref,
        )
        if not rows:
            return {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "invalid_completed": 0,
                "invalid_failed": 0,
            }

        ready = [
            row for row in rows
            if str(row.get("status") or "") not in _REFRESH_CHILD_TERMINAL
            and row.get("_delivery_ready") is True
            and str(row.get("_fill_job_id") or "")
        ]
        if ready:
            try:
                refreshed = monitor.refresh_device(device_ref)
            except Exception:
                refreshed = {"ok": False, "items": []}
            remote_items = [
                item for item in list(refreshed.get("items") or [])
                if isinstance(item, dict)
            ] if bool(refreshed.get("ok")) else []
            for row in ready:
                _refresh_task_record_device_verification(
                    task_id,
                    str(row.get("key") or ""),
                    str(row.get("_fill_job_id") or ""),
                    verified=bool(
                        refreshed.get("ok")
                        and _refresh_remote_confirms_replacement(
                            row,
                            remote_items,
                        )
                    ),
                )
            rows = _refresh_task_hydrate_replenishment_children(
                task_id,
                device_ref,
            )

        active = [
            row for row in rows
            if str(row.get("status") or "") not in _REFRESH_CHILD_TERMINAL
        ]
        if not active:
            completed = sum(
                1 for row in rows
                if str(row.get("status") or "") == "completed"
            )
            failed = len(rows) - completed
            invalid_rows = [
                row for row in rows
                if str(row.get("operation") or "")
                == "credential_invalid_replacement"
            ]
            invalid_completed = sum(
                1 for row in invalid_rows
                if str(row.get("status") or "") == "completed"
            )
            invalid_failed = len(invalid_rows) - invalid_completed
            if failed:
                _refresh_task_log(
                    task_id,
                    f"子号换号流程已结束：{completed} 个完成，{failed} 个需复核",
                )
            else:
                _refresh_task_log(
                    task_id,
                    f"{completed} 个子号已完成邀请、RT、设备上传与回查确认",
                )
            return {
                "total": len(rows),
                "completed": completed,
                "failed": failed,
                "invalid_completed": invalid_completed,
                "invalid_failed": invalid_failed,
            }

        if not waiting_logged:
            _refresh_task_log(
                task_id,
                "旧子号清理已完成，正在等待新子号加入母号、获取 RT、上传并通过设备回查",
            )
            waiting_logged = True
        _refresh_task_update(
            task_id,
            status="running",
            stage="waiting_business_delivery",
        )
        time.sleep(max(0.05, float(_REFRESH_REPLENISHMENT_POLL_SECONDS)))


def _refresh_task_fail_active_children(task_id: str) -> None:
    """Close any child rows left active by a fatal refresh-level failure."""
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task:
            return
        now = _iso_now()
        for row in (task.get("child_progress") or {}).values():
            if not isinstance(row, dict):
                continue
            if str(row.get("status") or "") in _REFRESH_CHILD_TERMINAL:
                continue
            if (
                str(row.get("_cleanup_job_id") or "")
                or str(row.get("_replenishment_demand_id") or "")
                or str(row.get("_fill_job_id") or "")
            ):
                # A refresh-level failure does not cancel a cleanup handoff
                # already committed to the durable BUSINESS scheduler.  Keep
                # it active so later GET polls can hydrate the final fill.
                continue
            row["status"] = "failed"
            row["stage"] = "failed"
            row["percent"] = 100
            row["result"] = "failed"
            row["error"] = "operation_failed"
            _refresh_task_child_append_log_locked(task, row)
            row["updated_at"] = now
        task["updated_at"] = now


def _refresh_task_update(
    task_id: str,
    *,
    status: Optional[str] = None,
    stage: Optional[str] = None,
    done: Optional[int] = None,
    total: Optional[int] = None,
    counts: Optional[dict[str, int]] = None,
    result: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
) -> None:
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task:
            return
        if status is not None:
            task["status"] = str(status)
        if stage is not None:
            task["stage"] = str(stage)
        if done is not None:
            task["done"] = max(0, int(done))
        if total is not None:
            task["total"] = max(0, int(total))
        if counts is not None:
            task["counts"] = {
                key: max(0, int(counts.get(key) or 0))
                for key in _REFRESH_COUNT_KEYS
            }
        if result is not None:
            task["result"] = dict(result)
        if error is not None:
            task["error"] = _safe_task_log_line(error)
        task["updated_at"] = _iso_now()
        if status in _REFRESH_TASK_TERMINAL:
            task["finished_at"] = task["updated_at"]
            device_ref = str(task.get("device_ref") or "")
            if _REFRESH_ACTIVE_BY_DEVICE.get(device_ref) == task_id:
                _REFRESH_ACTIVE_BY_DEVICE.pop(device_ref, None)


def _prune_refresh_tasks_locked() -> None:
    finished = sorted(
        (
            task for task in _REFRESH_TASKS.values()
            if str(task.get("status") or "") in _REFRESH_TASK_TERMINAL
        ),
        key=lambda item: str(item.get("finished_at") or item.get("updated_at") or ""),
        reverse=True,
    )
    for old in finished[_REFRESH_TASK_MAX_FINISHED:]:
        task_id = str(old.get("task_id") or "")
        operation_id = str(old.get("operation_id") or "")
        device_ref = str(old.get("device_ref") or "")
        _REFRESH_TASKS.pop(task_id, None)
        if operation_id:
            _REFRESH_TASK_BY_OPERATION.pop((device_ref, operation_id), None)


def _refresh_task_child_public_logs(
    row: dict[str, Any],
) -> tuple[list[dict[str, Any]], int]:
    """Serialize only closed Chinese events; never trust stored free text."""
    raw_logs = row.get("_logs") if isinstance(row.get("_logs"), list) else []
    events: list[dict[str, Any]] = []
    for raw in raw_logs[-_REFRESH_CHILD_LOG_MAX:]:
        if not isinstance(raw, dict):
            continue
        try:
            seq = max(0, int(raw.get("seq") or 0))
        except (TypeError, ValueError):
            continue
        if seq <= 0:
            continue
        stage = str(raw.get("stage") or "pending")
        if stage not in _REFRESH_CHILD_STAGES:
            stage = "pending"
        message = str(raw.get("message") or "")
        if message not in _REFRESH_CHILD_SAFE_LOG_MESSAGES:
            message = "子号任务状态已更新"
        created_at = str(raw.get("created_at") or "")[:64]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.+-]{8,40}", created_at):
            created_at = ""
        events.append({
            "seq": seq,
            "stage": stage,
            "message": message,
            "created_at": created_at,
        })
    events.sort(key=lambda item: int(item["seq"]))
    return events, int(events[-1]["seq"]) if events else 0


def _refresh_task_snapshot(device_ref: str, task_id: str, *, since: int = 0) -> dict:
    try:
        canonical = monitor.device_key(*monitor.parse_device_key(device_ref))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    # The worker stays active until durable refill + exact device verification
    # finish.  GET hydration is still retained so polls see each DB checkpoint
    # immediately between worker wake-ups.
    _refresh_task_hydrate_replenishment_children(
        str(task_id),
        canonical,
    )
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task or str(task.get("device_ref") or "") != canonical:
            raise HTTPException(404, "刷新任务不存在")
        logs = list(task.get("logs") or [])
        base = max(0, int(task.get("log_base") or 0))
        requested = max(0, int(since or 0))
        cursor = max(0, min(requested - base, len(logs)))
        next_cursor = base + len(logs)
        result = dict(task.get("result") or {}) if task.get("result") else None
        raw_counts = dict(task.get("counts") or {})
        raw_child_progress = task.get("child_progress") or {}
        public_child_logs = {
            str(key): _refresh_task_child_public_logs(row)
            for key, row in raw_child_progress.items()
            if isinstance(row, dict)
        }
        child_progress = sorted(
            (
                {
                    "key": str(row.get("key") or ""),
                    "email": _safe_child_progress_email(row.get("email")),
                    "parent_id": max(0, int(row.get("parent_id") or 0)),
                    "child_id": max(0, int(row.get("child_id") or 0)),
                    "membership_id": max(
                        0, int(row.get("membership_id") or 0),
                    ),
                    "parent_email": _safe_child_progress_email(
                        row.get("parent_email"),
                    ),
                    "replacement_email": _safe_child_progress_email(
                        row.get("replacement_email"),
                    ),
                    "replacement_child_id": max(
                        0, int(row.get("replacement_child_id") or 0),
                    ),
                    "replacement_membership_id": max(
                        0, int(row.get("replacement_membership_id") or 0),
                    ),
                    "next_check_at": _safe_public_datetime(
                        row.get("next_check_at"),
                    ),
                    "resume_at": _safe_public_datetime(
                        row.get("resume_at"),
                    ),
                    "attempt_count": max(
                        0, int(row.get("attempt_count") or 0),
                    ),
                    "operation": str(row.get("operation") or ""),
                    "status": str(row.get("status") or "queued"),
                    "stage": str(row.get("stage") or "queued"),
                    "percent": max(
                        0, min(100, int(row.get("percent") or 0)),
                    ),
                    "result": str(row.get("result") or "") or None,
                    "error": str(row.get("error") or "") or None,
                    "updated_at": str(row.get("updated_at") or ""),
                    "logs": list(
                        public_child_logs.get(str(row.get("key") or ""), ([], 0))[0]
                    ),
                    "log_cursor": int(
                        public_child_logs.get(str(row.get("key") or ""), ([], 0))[1]
                    ),
                }
                for row in raw_child_progress.values()
                if isinstance(row, dict)
            ),
            key=lambda row: (
                int(row["parent_id"]),
                int(row["child_id"]),
                int(row["membership_id"]),
            ),
        )
        return {
            "task_id": str(task["task_id"]),
            "device_ref": canonical,
            "status": str(task.get("status") or "queued"),
            "stage": str(task.get("stage") or "queued"),
            "logs": logs[cursor:],
            "since": next_cursor,
            "progress": {
                "done": int(task.get("done") or 0),
                "total": int(task.get("total") or 0),
            },
            "counts": {
                key: max(0, int(raw_counts.get(key) or 0))
                for key in _REFRESH_COUNT_KEYS
            },
            "child_progress": child_progress,
            "result": result,
            "error": str(task.get("error") or "") or None,
            "created_at": str(task.get("created_at") or ""),
            "started_at": str(task.get("started_at") or "") or None,
            "updated_at": str(task.get("updated_at") or ""),
            "finished_at": str(task.get("finished_at") or "") or None,
            "timestamps": {
                "created_at": str(task.get("created_at") or ""),
                "started_at": str(task.get("started_at") or "") or None,
                "updated_at": str(task.get("updated_at") or ""),
                "finished_at": str(task.get("finished_at") or "") or None,
            },
        }


def _json_object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(str(raw or "{}"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _normalized_email(value: Any) -> str:
    return str(value or "").strip().casefold()


def _business_child_mapping(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one exact active BUSINESS child without exposing its identity."""
    email = _normalized_email(remote.get("email"))
    remote_id = str(remote.get("remote_id") or "").strip()
    matches: list[dict[str, Any]] = []
    with Session(engine) as session:
        memberships = session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
            )
        ).all()
        seen_children: set[int] = set()
        for membership in memberships:
            child_id = int(membership.pro_account_id or 0)
            child = session.get(GptProAccountModel, child_id) if child_id else None
            member_email = _normalized_email(membership.email)
            child_email = _normalized_email(child.email) if child else ""
            extra = _json_object(child.extra_json) if child else {}
            identity_match = bool(email and email in {member_email, child_email})
            remote_match = False
            if provider == "cpa":
                remote_match = bool(
                    remote_id
                    and str(extra.get("cpa_auth_name") or "").strip() == remote_id
                )
            else:
                remote_match = bool(
                    remote_id
                    and str(extra.get("sub2api_remote_account_id") or "").strip()
                    == remote_id
                )
            if not identity_match and not remote_match:
                continue
            if child_id:
                seen_children.add(child_id)
            parent_id = int(membership.business_account_id)
            policy = session.get(
                GptBusinessAutomationPolicyModel, parent_id,
            )
            matches.append({
                "parent_id": parent_id,
                "membership_id": int(membership.id or 0),
                "seat_type": (
                    str(getattr(membership, "seat_type", "") or "").strip().lower()
                    if str(getattr(membership, "seat_type", "") or "").strip().lower()
                    in {"default", "prolite"}
                    else ""
                ),
                "child_id": child_id,
                "email": str(child.email if child else membership.email or "").strip(),
                "remote_user_id": str(membership.remote_user_id or "").strip(),
                "remote_invite_id": str(
                    getattr(membership, "remote_invite_id", "") or ""
                ).strip(),
                "child_parent_id": int(child.business_parent_id or 0) if child else 0,
                # These local facts are refreshed in the same DB snapshot as
                # the exact lifecycle mapping.  Credential-invalid cleanup
                # must never trust the older monitor inventory for its
                # destructive authorization evidence.
                "policy_revision": int(policy.revision or 0) if policy else 0,
                "child_dangerous": bool(
                    getattr(child, "dangerous", False)
                ) if child else False,
                "dangerous_detected_at": (
                    getattr(child, "dangerous_detected_at").isoformat()
                    if child and getattr(child, "dangerous_detected_at", None)
                    else ""
                ),
                "invalid_reason": (
                    "access_deactivated"
                    if child and bool(getattr(child, "dangerous", False))
                    else ""
                ),
                "identity_emails": [
                    value for value in {member_email, child_email} if value
                ],
                "extra": extra,
            })

        # A current child row without a matching active membership is a stale
        # lifecycle conflict, not an "unmapped" remote account safe to delete.
        for child in session.exec(
            select(GptProAccountModel).where(
                GptProAccountModel.business_parent_id.is_not(None)  # type: ignore[union-attr]
            )
        ).all():
            child_id = int(child.id or 0)
            if child_id in seen_children:
                continue
            extra = _json_object(child.extra_json)
            identity_match = bool(email and _normalized_email(child.email) == email)
            remote_match = (
                str(extra.get("cpa_auth_name") or "").strip() == remote_id
                if provider == "cpa" and remote_id
                else str(extra.get("sub2api_remote_account_id") or "").strip()
                == remote_id
                if provider == "sub2api" and remote_id
                else False
            )
            if identity_match or remote_match:
                matches.append({"stale": True, "child_id": child_id})

        ordinary_link_ids: set[int] = set()
        if remote_id:
            for account in session.exec(
                select(GptProAccountModel).where(
                    GptProAccountModel.business_parent_id.is_(None)  # type: ignore[union-attr]
                )
            ).all():
                extra = _json_object(account.extra_json)
                try:
                    cpa_target_id = int(
                        extra.get("cpa_synced_to_id")
                        or extra.get("cpa_device_id")
                        or 0
                    )
                    sub_device_id = int(extra.get("sub2api_device_id") or 0)
                except (TypeError, ValueError):
                    continue
                exact_link = (
                    provider == "cpa"
                    and bool(extra.get("cpa_synced"))
                    and cpa_target_id == int(provider_id)
                    and str(extra.get("cpa_auth_name") or "").strip()
                    == remote_id
                ) or (
                    provider == "sub2api"
                    and sub_device_id == int(provider_id)
                    and str(extra.get("sub2api_remote_account_id") or "").strip()
                    == remote_id
                )
                if exact_link:
                    ordinary_link_ids.add(int(account.id or 0))

    if not matches:
        return {"state": "unmapped"}
    if ordinary_link_ids:
        # The same remote credential cannot safely be attributed to both a
        # normal GPT account and a BUSINESS child.
        return {"state": "ambiguous"}
    unique = {
        (
            int(item.get("parent_id") or 0),
            int(item.get("membership_id") or 0),
            int(item.get("child_id") or 0),
        )
        for item in matches
    }
    if len(unique) != 1 or any(item.get("stale") for item in matches):
        return {"state": "ambiguous"}
    match = matches[0]
    extra = dict(match.pop("extra", {}))
    identity_emails = {
        _normalized_email(value)
        for value in match.pop("identity_emails", [])
        if _normalized_email(value)
    }
    if email and email not in identity_emails:
        return {"state": "conflict"}
    if (
        int(match.get("child_id") or 0) <= 0
        or int(match.get("child_parent_id") or 0)
        != int(match.get("parent_id") or 0)
        or not (
            str(match.get("remote_user_id") or "")
            or str(match.get("remote_invite_id") or "")
        )
    ):
        return {"state": "conflict"}
    if provider == "cpa":
        try:
            target_id = int(
                extra.get("cpa_synced_to_id")
                or extra.get("cpa_device_id")
                or 0
            )
        except (TypeError, ValueError):
            target_id = 0
        auth_name = str(extra.get("cpa_auth_name") or "").strip()
        try:
            missing_target_id = int(
                extra.get("cpa_remote_missing_target_id") or 0
            )
        except (TypeError, ValueError):
            missing_target_id = 0
        stale_exact_link = bool(
            extra.get("cpa_remote_missing") is True
            and missing_target_id == int(provider_id)
        )
        if (
            not (bool(extra.get("cpa_synced")) or stale_exact_link)
            or target_id != int(provider_id)
            or not auth_name
            or not remote_id
            or auth_name != remote_id
        ):
            return {"state": "conflict"}
        match["auth_name"] = auth_name
        match["link_epoch"] = str(extra.get("cpa_synced_at") or "")
    else:
        try:
            target_id = int(extra.get("sub2api_device_id") or 0)
        except (TypeError, ValueError):
            target_id = 0
        linked_remote_id = str(
            extra.get("sub2api_remote_account_id") or ""
        ).strip()
        if target_id != int(provider_id) or not remote_id or linked_remote_id != remote_id:
            return {"state": "conflict"}
        match["remote_account_id"] = linked_remote_id
        match["link_epoch"] = str(extra.get("sub2api_synced_at") or "")
    match["target_kind"] = (
        "member" if str(match.get("remote_user_id") or "") else "invite"
    )
    match["state"] = "mapped"
    return match


def _mapping_is_current(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    current = _business_child_mapping(provider, provider_id, remote)
    if not bool(
        current.get("state") == "mapped"
        and int(current.get("parent_id") or 0)
        == int(expected.get("parent_id") or 0)
        and int(current.get("membership_id") or 0)
        == int(expected.get("membership_id") or 0)
        and int(current.get("child_id") or 0)
        == int(expected.get("child_id") or 0)
    ):
        return False

    # Older cleanup callers only carry the three lifecycle ids above. Newer
    # destructive flows persist a fuller immutable identity; when a field is
    # present, compare it too so an invite->member transition, seat change,
    # device rebind, or policy revision cannot pass a stale DELETE guard.
    for field in (
        "remote_user_id",
        "remote_invite_id",
        "seat_type",
        "link_epoch",
        "target_kind",
    ):
        if field in expected and str(current.get(field) or "") != str(
            expected.get(field) or ""
        ):
            return False
    if "email" in expected and _normalized_email(current.get("email")) != (
        _normalized_email(expected.get("email"))
    ):
        return False
    if "policy_revision" in expected and int(
        current.get("policy_revision") or 0
    ) != int(expected.get("policy_revision") or 0):
        return False
    if "remote_id" in expected:
        current_remote_id = str((
            current.get("auth_name")
            if provider == "cpa"
            else current.get("remote_account_id")
        ) or "")
        if current_remote_id != str(expected.get("remote_id") or ""):
            return False
    return True


def _ordinary_account_mapping(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Resolve exactly one non-BUSINESS local account for a remote identity.

    Email alone never authorizes a DELETE.  The local device id and stable
    remote id must both match; a conflicting email or duplicate linkage fails
    closed so an unrelated credential cannot be removed by a device refresh.
    """
    remote_id = str(remote.get("remote_id") or "").strip()
    remote_email = _normalized_email(remote.get("email"))
    if not remote_id:
        return {"state": "conflict"}
    exact: list[dict[str, Any]] = []
    conflicting = False
    with Session(engine) as session:
        accounts = session.exec(
            select(GptProAccountModel).where(
                GptProAccountModel.business_parent_id.is_(None)  # type: ignore[union-attr]
            )
        ).all()
        for account in accounts:
            extra = _json_object(account.extra_json)
            try:
                linked_device = int(
                    extra.get("cpa_synced_to_id")
                    or extra.get("cpa_device_id")
                    or 0
                ) if provider == "cpa" else int(
                    extra.get("sub2api_device_id") or 0
                )
            except (TypeError, ValueError):
                continue
            linked_remote_id = str((
                extra.get("cpa_auth_name")
                if provider == "cpa"
                else extra.get("sub2api_remote_account_id")
            ) or "").strip()
            linked = bool(
                linked_device == int(provider_id)
                and linked_remote_id == remote_id
                and (
                    bool(extra.get("cpa_synced"))
                    if provider == "cpa"
                    else True
                )
            )
            if not linked:
                continue
            account_email = _normalized_email(account.email)
            if remote_email and account_email != remote_email:
                conflicting = True
                continue
            exact.append({
                "state": "mapped",
                "account_id": int(account.id or 0),
                "child_id": int(account.id or 0),
                "email": str(account.email or "").strip(),
                "is_pro": bool(account.is_pro),
                "refund_status": str(account.refund_status or ""),
                "link_epoch": str((
                    extra.get("cpa_synced_at")
                    if provider == "cpa"
                    else extra.get("sub2api_synced_at")
                ) or ""),
                "auth_name": linked_remote_id if provider == "cpa" else "",
                "remote_account_id": (
                    linked_remote_id if provider == "sub2api" else ""
                ),
            })
    if conflicting:
        return {"state": "conflict"}
    if not exact:
        return {"state": "unmapped"}
    if len(exact) != 1 or int(exact[0].get("account_id") or 0) <= 0:
        return {"state": "ambiguous"}
    return exact[0]


def _ordinary_mapping_is_current(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    current = _ordinary_account_mapping(provider, provider_id, remote)
    return bool(
        current.get("state") == "mapped"
        and int(current.get("account_id") or 0)
        == int(expected.get("account_id") or expected.get("child_id") or 0)
    )


def _internal_device_or_error(provider: str, provider_id: int) -> dict[str, Any]:
    internal = monitor._internal_device(provider, int(provider_id))  # type: ignore[attr-defined]
    if not internal:
        raise LookupError("device_missing")
    if not str(internal.get("api_url") or "").strip() or not str(
        internal.get("api_key") or ""
    ).strip():
        raise RuntimeError("device_unconfigured")
    return internal


def _device_epoch(provider: str, provider_id: int) -> str:
    """Opaque local fence for endpoint/key/config changes during a task."""
    internal = _internal_device_or_error(provider, provider_id)
    payload = {
        "provider": provider,
        "provider_id": int(provider_id),
        "api_url": str(internal.get("api_url") or "").strip().rstrip("/"),
        "api_key": str(internal.get("api_key") or ""),
        "updated_at": str(internal.get("updated_at") or ""),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _device_epoch_is_current(
    provider: str,
    provider_id: int,
    expected_epoch: str,
) -> bool:
    try:
        return bool(expected_epoch) and _device_epoch(provider, provider_id) == expected_epoch
    except Exception:
        return False


def _confirm_missing_business_child_remote_absent(
    provider: str,
    provider_id: int,
    expected_epoch: str,
    request: dict[str, Any],
) -> None:
    """Re-list one device and prove an old BUSINESS lifecycle is absent.

    This is the destructive fence for ``credential_missing_deactivated``.
    Email, the exact parent/child/membership navigation tuple, and any stable
    remote id recorded in the local link must all be absent.  The helper only
    performs a full read; it never disables or deletes a device credential.
    """
    if not _device_epoch_is_current(provider, provider_id, expected_epoch):
        raise RuntimeError("device_changed")
    try:
        refreshed = monitor.refresh_device(
            monitor.device_key(provider, int(provider_id)),
        )
    except Exception as exc:
        raise RuntimeError("remote_absence_unconfirmed") from exc
    if not bool(refreshed.get("ok")):
        raise RuntimeError("remote_absence_unconfirmed")
    expected_email = _normalized_email(request.get("email"))
    expected_remote_id = str(request.get("linked_remote_id") or "").strip()
    expected_lifecycle = (
        int(request.get("business_parent_id") or 0),
        int(request.get("account_id") or 0),
        int(request.get("membership_id") or 0),
    )
    for raw in list(refreshed.get("items") or []):
        if not isinstance(raw, dict):
            continue
        if expected_email and _normalized_email(raw.get("email")) == expected_email:
            raise RuntimeError("remote_absence_unconfirmed")
        if (
            expected_remote_id
            and str(raw.get("remote_id") or "").strip() == expected_remote_id
        ):
            raise RuntimeError("remote_absence_unconfirmed")
        navigation = (
            raw.get("navigation")
            if isinstance(raw.get("navigation"), dict)
            else {}
        )
        try:
            lifecycle = (
                int(navigation.get("business_parent_id") or 0),
                int(navigation.get("pro_account_id") or 0),
                int(navigation.get("membership_id") or 0),
            )
        except (TypeError, ValueError):
            lifecycle = (0, 0, 0)
        if all(expected_lifecycle) and lifecycle == expected_lifecycle:
            raise RuntimeError("remote_absence_unconfirmed")
    if not _device_epoch_is_current(provider, provider_id, expected_epoch):
        raise RuntimeError("device_changed")


def _delete_cpa_remote_exact(
    internal: dict[str, Any],
    remote: dict[str, Any],
    *,
    before_mutation=None,
) -> None:
    """Delete one exact auth_name and re-list to prove its absence."""
    from services.cpa_manager import delete_auth_files, list_auth_files_strict

    remote_id = str(remote.get("remote_id") or "").strip()
    snapshot_name = str(remote.get("name") or "").strip()
    if not remote_id or not snapshot_name or snapshot_name != remote_id:
        raise RuntimeError("remote_identity_missing")
    url = str(internal.get("api_url") or "")
    key = str(internal.get("api_key") or "")
    expected_email = _normalized_email(remote.get("email"))
    files = list_auth_files_strict(api_url=url, api_key=key)
    exact = [item for item in files if str(item.get("name") or "") == remote_id]
    if len(exact) > 1:
        raise RuntimeError("remote_identity_ambiguous")
    if exact:
        actual_email = _normalized_email(
            exact[0].get("email") or exact[0].get("account")
        )
        if expected_email and actual_email and expected_email != actual_email:
            raise RuntimeError("remote_identity_mismatch")
        if before_mutation is not None and not bool(before_mutation()):
            raise RuntimeError("operation_fenced")
        delete_auth_files([remote_id], api_url=url, api_key=key)
    confirmed = list_auth_files_strict(api_url=url, api_key=key)
    if any(str(item.get("name") or "") == remote_id for item in confirmed):
        raise RuntimeError("remote_delete_unconfirmed")


def _delete_sub2api_remote_exact(
    internal: dict[str, Any],
    remote: dict[str, Any],
    *,
    before_mutation=None,
) -> None:
    from services.sub2api_admin import (
        Sub2ApiAdminError,
        delete_account,
        get_account_by_id,
    )

    remote_id = str(remote.get("remote_id") or "").strip()
    email = str(remote.get("email") or "").strip()
    name = str(remote.get("name") or "").strip()
    if not remote_id or (not email and not name):
        raise RuntimeError("remote_identity_missing")
    try:
        confirmation = delete_account(
            str(internal.get("api_url") or ""),
            str(internal.get("api_key") or ""),
            remote_id,
            expected_email=email,
            expected_name=name,
            before_mutation=before_mutation,
        )
    except Sub2ApiAdminError as exc:
        # A 404 can be produced by the initial identity GET *or* by a
        # deployment whose DELETE route is absent.  Independently probe the
        # immutable id again: only a second authoritative GET 404 proves
        # absence; a present row or any transport/5xx result remains closed.
        if int(exc.status_code or 0) != 404:
            raise
        if before_mutation is not None and not bool(before_mutation()):
            raise RuntimeError("operation_fenced") from exc
        try:
            get_account_by_id(
                str(internal.get("api_url") or ""),
                str(internal.get("api_key") or ""),
                remote_id,
            )
        except Sub2ApiAdminError as confirmation_exc:
            if int(confirmation_exc.status_code or 0) == 404:
                return
            raise
        raise RuntimeError("remote_delete_unconfirmed") from exc
    if not bool(confirmation.get("absence_confirmed")):
        raise RuntimeError("remote_delete_unconfirmed")


def _cache_cpa_exhaustion(child_id: int, remote: dict[str, Any]) -> None:
    from api.gpt_plan_operations import _cache_cpa_usage

    usage = remote.get("usage") if isinstance(remote.get("usage"), dict) else {}
    _cache_cpa_usage(int(child_id), {
        "p5_used_percent": usage.get("usage_5h_percent"),
        "p5_reset_at": usage.get("usage_5h_reset_at"),
        "p5_window_seconds": usage.get("usage_5h_window_seconds"),
        "week_used_percent": usage.get("usage_week_percent"),
        "week_reset_at": usage.get("usage_week_reset_at"),
        "week_window_seconds": usage.get("usage_week_window_seconds"),
        # The caller has already required the successful monitor snapshot's
        # top-level JSON boolean to be literally true.
        "limit_reached": True,
        "credit_balance": usage.get("credit_balance"),
    })


def _mark_cpa_rotation_delete_required(
    child_id: int,
    *,
    provider_id: int,
    auth_name: str,
    operation_token: str,
) -> bool:
    from api.gpt_plan_operations import _gpt_pro_account_operation_token_is_current

    if (
        not str(auth_name or "").strip()
        or not _gpt_pro_account_operation_token_is_current(
            int(child_id), str(operation_token),
        )
    ):
        return False
    with Session(engine) as session:
        child = session.get(GptProAccountModel, int(child_id))
        if not child or child.business_parent_id is None:
            return False
        extra = _json_object(child.extra_json)
        try:
            linked_target = int(
                extra.get("cpa_synced_to_id")
                or extra.get("cpa_device_id")
                or 0
            )
        except (TypeError, ValueError):
            return False
        linked_auth = str(extra.get("cpa_auth_name") or "").strip()
        if (
            not bool(extra.get("cpa_synced"))
            or linked_target != int(provider_id)
            or linked_auth != str(auth_name).strip()
        ):
            return False
        extra.update({
            "cpa_rotation_delete_required": True,
            "cpa_rotation_delete_required_target_id": int(provider_id),
            "cpa_rotation_delete_required_auth_name": linked_auth,
            "cpa_rotation_delete_requested_at": _iso_now(),
        })
        for key in (
            "cpa_rotation_delete_confirmed",
            "cpa_rotation_delete_confirmed_at",
            "cpa_rotation_delete_confirmed_target_id",
            "cpa_rotation_delete_confirmed_auth_name",
            "cpa_rotation_delete_confirmed_ready_at",
        ):
            extra.pop(key, None)
        child.extra_json = json.dumps(extra, ensure_ascii=False)
        child.updated_at = _utcnow()
        session.add(child)
        session.commit()
    return True


def _confirm_cpa_rotation_delete(
    child_id: int,
    *,
    provider_id: int,
    auth_name: str,
    operation_token: str,
) -> bool:
    """Bind confirmed remote absence to the current rotation-ready epoch."""
    from api.gpt_plan_operations import _gpt_pro_account_operation_token_is_current

    if not _gpt_pro_account_operation_token_is_current(
        int(child_id), str(operation_token),
    ):
        return False
    with Session(engine) as session:
        child = session.get(GptProAccountModel, int(child_id))
        if not child or child.business_parent_id is None:
            return False
        extra = _json_object(child.extra_json)
        linked_auth = str(extra.get("cpa_auth_name") or "").strip()
        ready_at = str(extra.get("cpa_rotation_ready_at") or "").strip()
        try:
            linked_target = int(
                extra.get("cpa_synced_to_id")
                or extra.get("cpa_device_id")
                or 0
            )
            required_target = int(
                extra.get("cpa_rotation_delete_required_target_id") or 0
            )
        except (TypeError, ValueError):
            return False
        expected_auth = str(auth_name or "").strip()
        if not (
            bool(extra.get("cpa_rotation_delete_required"))
            and bool(extra.get("cpa_disabled"))
            and str(extra.get("cpa_rotation_reason") or "") == "quota_exhausted"
            and ready_at
            and linked_target == int(provider_id) == required_target
            and linked_auth == expected_auth
            and str(extra.get("cpa_rotation_delete_required_auth_name") or "").strip()
            == expected_auth
        ):
            return False
        confirmed_at = _iso_now()
        extra.update({
            "cpa_rotation_delete_confirmed": True,
            "cpa_rotation_delete_confirmed_at": confirmed_at,
            "cpa_rotation_delete_confirmed_target_id": int(provider_id),
            "cpa_rotation_delete_confirmed_auth_name": expected_auth,
            "cpa_rotation_delete_confirmed_ready_at": ready_at,
        })
        child.extra_json = json.dumps(extra, ensure_ascii=False)
        child.updated_at = _utcnow()
        session.add(child)
        session.commit()
    return True


def _matching_rotation_job_ids(
    ids: list[str],
    *,
    provider: str,
    provider_id: int,
    parent_id: int,
    child_id: int,
) -> list[str]:
    matched: list[str] = []
    with Session(engine) as session:
        for job_id in dict.fromkeys(str(value) for value in ids if str(value)):
            job = session.get(GptBusinessAllocationJobModel, job_id)
            if not job:
                continue
            request = _json_object(job.request_json)
            expected_kind = "cpa_rotation" if provider == "cpa" else "sub2api_rotation"
            target = (
                request.get("cpa_target_id")
                if provider == "cpa"
                else request.get("sub2api_device_id")
            )
            if (
                str(request.get("job_kind") or "") == expected_kind
                and int(request.get("parent_id") or 0) == int(parent_id)
                and int(request.get("old_pro_account_id") or 0) == int(child_id)
                and int(target or 0) == int(provider_id)
            ):
                matched.append(job_id)
    return matched


def _rotation_job_state(job_id: str) -> tuple[str, str]:
    with Session(engine) as session:
        job = session.get(GptBusinessAllocationJobModel, str(job_id))
        if not job:
            return "missing", "missing"
        return str(job.state or ""), str(job.stage or "")


def _rotation_job_checkpoint(job_id: str) -> tuple[str, str, bool]:
    """Return only the safe fields needed by the bounded polling task."""
    with Session(engine) as session:
        job = session.get(GptBusinessAllocationJobModel, str(job_id))
        if not job:
            return "missing", "missing", False
        actions = _json_object(job.action_state_json)
        cooldown = actions.get("cooldown")
        has_cooldown = bool(
            isinstance(cooldown, dict)
            and str(cooldown.get("resume_at") or "").strip()
        )
        return str(job.state or ""), str(job.stage or ""), has_cooldown


def _cpa_delete_job_is_pending(
    job_id: str,
    *,
    provider_id: int,
    parent_id: int,
    child_id: int,
    device_epoch: str = "",
) -> bool:
    with Session(engine) as session:
        job = session.get(GptBusinessAllocationJobModel, str(job_id))
        if not job:
            return False
        request = _json_object(job.request_json)
        actions = _json_object(job.action_state_json)
        delete_state = actions.get("cpa_remote_delete")
        return bool(
            str(job.state or "") == "action_required"
            and str(job.stage or "") == "cpa_delete_pending"
            and not bool(job.remote_mutated)
            and (
                bool(request.get("cpa_remote_delete_required"))
                or bool(delete_state.get("required"))
            )
            and int(request.get("cpa_target_id") or 0) == int(provider_id)
            and int(request.get("parent_id") or 0) == int(parent_id)
            and int(request.get("old_pro_account_id") or 0) == int(child_id)
            and isinstance(delete_state, dict)
            and str(delete_state.get("status") or "") == "pending"
            and (
                not str(device_epoch or "")
                or str(delete_state.get("device_epoch") or "")
                == str(device_epoch)
            )
        )


def _bind_cpa_delete_job_epoch(
    job_id: str,
    *,
    provider_id: int,
    parent_id: int,
    child_id: int,
    device_epoch: str,
) -> bool:
    if not str(device_epoch or ""):
        return False
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            job = session.get(GptBusinessAllocationJobModel, str(job_id))
        else:
            job = session.exec(
                select(GptBusinessAllocationJobModel)
                .where(GptBusinessAllocationJobModel.id == str(job_id))
                .with_for_update()
            ).first()
        if not job:
            session.rollback()
            return False
        request = _json_object(job.request_json)
        actions = _json_object(job.action_state_json)
        current = actions.get("cpa_remote_delete")
        if not (
            str(job.state or "") == "action_required"
            and str(job.stage or "") == "cpa_delete_pending"
            and not bool(job.remote_mutated)
            and int(request.get("cpa_target_id") or 0) == int(provider_id)
            and int(request.get("parent_id") or 0) == int(parent_id)
            and int(request.get("old_pro_account_id") or 0) == int(child_id)
            and isinstance(current, dict)
            and str(current.get("status") or "") == "pending"
            and not (
                str(current.get("device_epoch") or "")
                and str(current.get("device_epoch") or "")
                != str(device_epoch)
            )
        ):
            session.rollback()
            return False
        current = dict(current)
        current.update({
            "required": True,
            "device_epoch": str(device_epoch),
            "updated_at": _iso_now(),
        })
        actions["cpa_remote_delete"] = current
        job.action_state_json = json.dumps(actions, ensure_ascii=False)
        job.updated_at = _utcnow()
        session.add(job)
        session.commit()
    return True


def _adopt_existing_cpa_job_for_delete(
    job_id: str,
    *,
    provider_id: int,
    parent_id: int,
    child_id: int,
    ignore_operation_token: str,
    device_epoch: str = "",
) -> str:
    """CAS a quiescent legacy job into the non-startable delete checkpoint."""
    from api import gpt_business

    with gpt_business._ALLOCATION_THREADS_LOCK:
        local = gpt_business._ALLOCATION_THREADS.get(str(job_id))
        if local and local.is_alive():
            return "busy"
    now = _utcnow()
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            job = session.get(GptBusinessAllocationJobModel, str(job_id))
        else:
            job = session.exec(
                select(GptBusinessAllocationJobModel)
                .where(GptBusinessAllocationJobModel.id == str(job_id))
                .with_for_update()
            ).first()
        if not job:
            session.rollback()
            return "unsafe"
        request = _json_object(job.request_json)
        target_id = int(request.get("cpa_target_id") or 0)
        if not (
            str(request.get("job_kind") or "") == "cpa_rotation"
            and int(request.get("parent_id") or 0) == int(parent_id)
            and int(request.get("old_pro_account_id") or 0) == int(child_id)
            and target_id == int(provider_id)
            and str(job.state or "") == "action_required"
            and not bool(job.remote_mutated)
        ):
            session.rollback()
            return "busy" if str(job.state or "") in {
                "queued", "retry_queued", "running", "completed",
            } else "unsafe"
        active_lease = session.exec(
            select(GptBusinessAllocationLeaseModel)
            .where(GptBusinessAllocationLeaseModel.job_id == str(job_id))
            .where(GptBusinessAllocationLeaseModel.expires_at > now)
        ).first()
        account_claim = session.get(
            GptProAccountOperationLeaseModel,
            int(child_id),
        )
        claim_expires_at = (
            account_claim.expires_at.replace(tzinfo=timezone.utc)
            if account_claim
            and account_claim.expires_at
            and account_claim.expires_at.tzinfo is None
            else account_claim.expires_at if account_claim else None
        )
        claim_busy = bool(
            account_claim
            and claim_expires_at
            and claim_expires_at > now
            and str(account_claim.token or "")
            != str(ignore_operation_token or "")
        )
        if active_lease or claim_busy:
            session.rollback()
            return "busy"
        actions = _json_object(job.action_state_json)
        actions["cpa_remote_delete"] = {
            "required": True,
            "status": "pending",
            "target_id": int(provider_id),
            "device_epoch": str(device_epoch or ""),
            "updated_at": _iso_now(),
        }
        job.state = "action_required"
        job.stage = "cpa_delete_pending"
        job.retryable = True
        job.worker_token = ""
        job.error = ""
        job.action_state_json = json.dumps(actions, ensure_ascii=False)
        job.updated_at = now
        session.add(job)
        session.commit()
    return "adopted"


def _confirm_cpa_delete_job(
    job_id: str,
    *,
    provider_id: int,
    parent_id: int,
    child_id: int,
) -> bool:
    """CAS the credential-free job checkpoint from pending to confirmed."""
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            job = session.get(GptBusinessAllocationJobModel, str(job_id))
        else:
            job = session.exec(
                select(GptBusinessAllocationJobModel)
                .where(GptBusinessAllocationJobModel.id == str(job_id))
                .with_for_update()
            ).first()
        if not job:
            session.rollback()
            return False
        request = _json_object(job.request_json)
        actions = _json_object(job.action_state_json)
        current = actions.get("cpa_remote_delete")
        if not (
            str(job.state or "") == "action_required"
            and str(job.stage or "") == "cpa_delete_pending"
            and not bool(job.remote_mutated)
            and (
                bool(request.get("cpa_remote_delete_required"))
                or bool(current.get("required"))
            )
            and int(request.get("cpa_target_id") or 0) == int(provider_id)
            and int(request.get("parent_id") or 0) == int(parent_id)
            and int(request.get("old_pro_account_id") or 0) == int(child_id)
            and isinstance(current, dict)
            and str(current.get("status") or "") == "pending"
        ):
            session.rollback()
            return False
        actions["cpa_remote_delete"] = {
            "required": True,
            "status": "confirmed",
            "target_id": int(provider_id),
            "device_epoch": str(current.get("device_epoch") or ""),
            "updated_at": _iso_now(),
        }
        job.action_state_json = json.dumps(actions, ensure_ascii=False)
        job.stage = "detected"
        job.updated_at = _utcnow()
        session.add(job)
        session.commit()
    return True


def reconcile_pending_cpa_rotation_deletes(limit: int = 20) -> dict[str, Any]:
    """Confirm already-absent CPA auth files; never issues a DELETE itself."""
    from api.gpt_business import _prepare_cpa_rotation_job
    from api.gpt_plan_operations import (
        _claim_gpt_pro_account_operation,
        _release_gpt_pro_account_operation,
    )
    from services.cpa_manager import list_auth_files

    bounded = max(1, min(int(limit or 20), 100))
    with Session(engine) as session:
        rows = session.exec(
            select(GptBusinessAllocationJobModel)
            .where(GptBusinessAllocationJobModel.state == "action_required")
            .where(GptBusinessAllocationJobModel.stage == "cpa_delete_pending")
            .order_by(GptBusinessAllocationJobModel.updated_at)
            .limit(bounded)
        ).all()
        ids = [str(row.id) for row in rows]
    summary: dict[str, Any] = {
        "ok": True,
        "considered": len(ids),
        "confirmed": 0,
        "present": 0,
        "uncertain": 0,
        "started": 0,
    }
    for job_id in ids:
        token = ""
        child_id = 0
        try:
            with Session(engine) as session:
                job = session.get(GptBusinessAllocationJobModel, job_id)
                if not job:
                    summary["uncertain"] += 1
                    continue
                request = _json_object(job.request_json)
                actions = _json_object(job.action_state_json)
                checkpoint = actions.get("cpa_remote_delete")
                parent_id = int(request.get("parent_id") or 0)
                child_id = int(request.get("old_pro_account_id") or 0)
                target_id = int(request.get("cpa_target_id") or 0)
                device_epoch = str(
                    checkpoint.get("device_epoch") or ""
                ) if isinstance(checkpoint, dict) else ""
                child = session.get(GptProAccountModel, child_id)
                membership = session.exec(
                    select(GptBusinessChildMembershipModel)
                    .where(
                        GptBusinessChildMembershipModel.business_account_id
                        == parent_id
                    )
                    .where(
                        GptBusinessChildMembershipModel.pro_account_id
                        == child_id
                    )
                    .where(
                        GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
                    )
                ).first()
                extra = _json_object(child.extra_json) if child else {}
                auth_name = str(extra.get("cpa_auth_name") or "").strip()
                email = str(child.email or "").strip() if child else ""
                try:
                    linked_target = int(
                        extra.get("cpa_synced_to_id")
                        or extra.get("cpa_device_id")
                        or 0
                    )
                except (TypeError, ValueError):
                    linked_target = 0
                safe_binding = bool(
                    isinstance(checkpoint, dict)
                    and bool(checkpoint.get("required"))
                    and str(checkpoint.get("status") or "") == "pending"
                    and device_epoch
                    and parent_id > 0
                    and child_id > 0
                    and target_id > 0
                    and child
                    and membership
                    and int(child.business_parent_id or 0) == parent_id
                    and bool(extra.get("cpa_rotation_delete_required"))
                    and bool(extra.get("cpa_disabled"))
                    and linked_target == target_id
                    and auth_name
                    and str(
                        extra.get("cpa_rotation_delete_required_auth_name")
                        or ""
                    ).strip() == auth_name
                )
            if not safe_binding or not _device_epoch_is_current(
                "cpa", target_id, device_epoch,
            ):
                summary["uncertain"] += 1
                continue
            internal = _internal_device_or_error("cpa", target_id)
            files = list_auth_files(
                api_url=str(internal.get("api_url") or ""),
                api_key=str(internal.get("api_key") or ""),
            )
            exact = [
                item for item in files
                if str(item.get("name") or "") == auth_name
            ]
            if len(exact) > 1:
                summary["uncertain"] += 1
                continue
            if exact:
                listed_email = _normalized_email(
                    exact[0].get("email") or exact[0].get("account")
                )
                if listed_email and listed_email != _normalized_email(email):
                    summary["uncertain"] += 1
                else:
                    summary["present"] += 1
                continue
            token = _claim_gpt_pro_account_operation(
                child_id,
                "cpa_delete_reconcile",
                allow_managed_business_child=True,
            )
            if not _cpa_delete_job_is_pending(
                job_id,
                provider_id=target_id,
                parent_id=parent_id,
                child_id=child_id,
                device_epoch=device_epoch,
            ) or not _device_epoch_is_current("cpa", target_id, device_epoch):
                summary["uncertain"] += 1
                continue
            if not _confirm_cpa_rotation_delete(
                child_id,
                provider_id=target_id,
                auth_name=auth_name,
                operation_token=token,
            ) or not _confirm_cpa_delete_job(
                job_id,
                provider_id=target_id,
                parent_id=parent_id,
                child_id=child_id,
            ):
                summary["uncertain"] += 1
                continue
            summary["confirmed"] += 1
            prepared = _prepare_cpa_rotation_job(job_id, start=True)
            if str(prepared.get("state") or "") in {
                "queued", "retry_queued", "running",
            }:
                summary["started"] += 1
        except Exception:
            summary["uncertain"] += 1
        finally:
            if token:
                _release_gpt_pro_account_operation(child_id, token)
    return summary


def _aware_cleanup_time(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _cleanup_usage_snapshot(provider: str, remote: dict[str, Any]) -> dict[str, Any]:
    usage = remote.get("usage") if isinstance(remote.get("usage"), dict) else {}
    if provider == "cpa":
        # An explicit top-level limit_reached=true means no usable delivery
        # capacity.  Store 100% used so every existing UI renders 0% remaining,
        # even if the remote omitted one of its window percentages.
        return {
            "usage_5h_percent": 100,
            "usage_5h_reset_at": usage.get("usage_5h_reset_at"),
            "usage_5h_window_seconds": usage.get("usage_5h_window_seconds"),
            "usage_week_percent": 100,
            "usage_week_reset_at": usage.get("usage_week_reset_at"),
            "usage_week_window_seconds": usage.get("usage_week_window_seconds"),
            "limit_reached": True,
            "credit_balance": usage.get("credit_balance"),
        }
    from services.sub2api_admin import sanitize_admin_payload

    sanitized = sanitize_admin_payload(usage)
    result = dict(sanitized) if isinstance(sanitized, dict) else {}
    result.update({"limit_reached": True, "used_percent": 100})
    return sanitize_admin_payload(result)


def _manual_replacement_usage_snapshot(
    provider: str,
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Keep only public quota evidence without turning it into exhaustion."""
    usage = remote.get("usage") if isinstance(remote.get("usage"), dict) else {}
    if provider == "cpa":
        return {
            key: usage.get(key)
            for key in (
                "usage_5h_percent", "usage_5h_reset_at",
                "usage_5h_window_seconds", "usage_week_percent",
                "usage_week_reset_at", "usage_week_window_seconds",
                "limit_reached", "credit_balance", "checked_at",
            )
            if key in usage
        }
    from services.sub2api_admin import sanitize_admin_payload

    sanitized = sanitize_admin_payload(usage)
    return dict(sanitized) if isinstance(sanitized, dict) else {}


def _cleanup_remote_snapshot(
    provider: str,
    remote: dict[str, Any],
) -> dict[str, str]:
    remote_id = str(remote.get("remote_id") or "").strip()
    name = str(remote.get("name") or "").strip()
    email = str(remote.get("email") or "").strip()
    if not remote_id:
        raise RuntimeError("remote_identity_missing")
    if provider == "cpa" and (not name or name != remote_id):
        raise RuntimeError("remote_identity_missing")
    if provider == "sub2api" and not (name or email):
        raise RuntimeError("remote_identity_missing")
    return {
        "remote_id": remote_id,
        "name": name,
        "email": email,
    }


_DEACTIVATED_CLEANUP_TRIGGERS = frozenset({
    "credential_invalid", "credential_missing_deactivated",
})


def _deactivated_cleanup_lifecycle_values(
    *,
    provider: str,
    provider_id: int,
    parent_id: int,
    account_id: int,
    membership_id: int,
    remote_id: str,
    request: dict[str, Any],
) -> Optional[tuple[Any, ...]]:
    trigger = str(request.get("trigger_kind") or "").strip().lower()
    if trigger not in _DEACTIVATED_CLEANUP_TRIGGERS:
        return None
    remote = request.get("remote") if isinstance(
        request.get("remote"), dict,
    ) else {}
    return (
        str(provider or request.get("provider") or "").strip().lower(),
        int(provider_id or request.get("provider_id") or 0),
        int(parent_id or request.get("business_parent_id") or 0),
        int(account_id or request.get("account_id") or 0),
        int(membership_id or request.get("membership_id") or 0),
        str(remote_id or remote.get("remote_id") or "").strip(),
        _normalized_email(request.get("email") or remote.get("email")),
        str(request.get("remote_user_id") or "").strip(),
        str(request.get("remote_invite_id") or "").strip(),
        str(request.get("seat_type") or "").strip().lower(),
        int(request.get("policy_revision") or 0),
        str(request.get("link_epoch") or "").strip(),
        str(request.get("dangerous_detected_at") or "").strip(),
    )


def _deactivated_cleanup_lifecycle(
    job: DeliveryDeviceExhaustionCleanupModel,
    request: dict[str, Any],
) -> Optional[tuple[Any, ...]]:
    """Return the exact credential-free child lifecycle for deduplication."""
    return _deactivated_cleanup_lifecycle_values(
        provider=str(job.provider or ""),
        provider_id=int(job.provider_id or 0),
        parent_id=int(job.business_parent_id or 0),
        account_id=int(job.account_id or 0),
        membership_id=int(job.membership_id or 0),
        remote_id=str(job.remote_id or ""),
        request=request,
    )


def _cleanup_request_is_intact(
    job: DeliveryDeviceExhaustionCleanupModel,
    request: dict[str, Any],
) -> bool:
    encoded = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest() == str(
        job.request_hash or ""
    )


def _cleanup_duplicate_safety(
    session: Session,
    job: DeliveryDeviceExhaustionCleanupModel,
    *,
    now: Optional[datetime] = None,
) -> str:
    """Classify an old equivalent cleanup as safe, busy or irreversible."""
    current = now or _utcnow()
    request = _json_object(job.request_json)
    if not _cleanup_request_is_intact(job, request):
        return "owned"
    if any((
        bool(job.business_remove_confirmed),
        bool(job.device_delete_confirmed),
        bool(job.local_snapshot_persisted),
        str(job.state or "") == "completed",
    )):
        return "owned"
    demand = session.exec(
        select(DeliveryDeviceReplenishmentDemandModel).where(
            DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
            == str(job.id)
        )
    ).first()
    if demand is not None:
        return "owned"
    operation_id = str(job.business_operation_id or "")
    if operation_id:
        mutation = session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.operation_id == operation_id
            )
        ).first()
        if mutation is not None:
            return "owned"
        reservation = session.get(
            GptBusinessRotationReservationModel,
            operation_id,
        )
        if reservation is not None:
            if str(reservation.state or "") == "consumed":
                return "owned"
            if str(reservation.state or "") == "reserved":
                return "busy"
    if (
        str(job.state or "") == "running"
        and _active_lease(job.lease_expires_at, current)
    ):
        return "busy"
    account_lease = session.get(
        GptProAccountOperationLeaseModel,
        int(job.account_id or 0),
    )
    if account_lease and _active_lease(account_lease.expires_at, current):
        return "busy"
    allocation_leases = session.exec(
        select(GptBusinessAllocationLeaseModel).where(
            GptBusinessAllocationLeaseModel.job_id == str(job.id)
        )
    ).all()
    if any(_active_lease(row.expires_at, current) for row in allocation_leases):
        return "busy"
    linked_team_tasks = session.exec(
        select(DeliveryDeviceTeam401TaskModel)
        .where(DeliveryDeviceTeam401TaskModel.cleanup_job_id == str(job.id))
        .where(DeliveryDeviceTeam401TaskModel.state.in_([
            "prepared", "queued", "running", "waiting",
        ]))
    ).all()
    if linked_team_tasks:
        return "busy"
    return "safe"


def _team401_cleanup_authority_locked(
    session: Session,
    job: DeliveryDeviceExhaustionCleanupModel,
    request: dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Fence duplicate dead-child cleanups against the TEAM401 authority.

    This helper runs inside the same write transaction as the generic cleanup
    claim.  That placement is intentional: the recovery scheduler may inspect
    an older ``credential_invalid`` row before the TEAM401 scheduler resumes
    its newer ``credential_missing_deactivated`` row.  The exact immutable
    lifecycle, rather than trigger name or email alone, decides equivalence.

    A duplicate is superseded only while it has neither an active lease nor an
    irreversible checkpoint.  Anything already running or past a mutation
    boundary is left untouched and reported as a closed conflict so two jobs
    can never race the same BUSINESS member.
    """
    current = now or _utcnow()
    lifecycle = _deactivated_cleanup_lifecycle(job, request)
    if lifecycle is None:
        return {"state": "none"}

    # A TEAM401 task remains the durable authority after a process restart and
    # while an operator may retry a failed item.  Cancelled rows intentionally
    # relinquish authority; every other state keeps its exact cleanup binding.
    linked_tasks = session.exec(
        select(DeliveryDeviceTeam401TaskModel)
        .where(DeliveryDeviceTeam401TaskModel.cleanup_job_id != "")
    ).all()
    authority_ids: set[str] = set()
    for task in linked_tasks:
        if str(task.state or "") == "cancelled":
            continue
        cleanup_id = str(task.cleanup_job_id or "").strip()
        if not cleanup_id:
            continue
        linked = session.get(DeliveryDeviceExhaustionCleanupModel, cleanup_id)
        if linked is None or str(linked.state or "") == "superseded":
            continue
        same_core_identity = bool(
            str(linked.provider or "") == str(job.provider or "")
            and int(linked.provider_id or 0) == int(job.provider_id or 0)
            and int(linked.business_parent_id or 0)
            == int(job.business_parent_id or 0)
            and int(linked.account_id or 0) == int(job.account_id or 0)
            and int(linked.membership_id or 0) == int(job.membership_id or 0)
            and str(linked.remote_id or "") == str(job.remote_id or "")
        )
        if not same_core_identity:
            continue
        linked_request = _json_object(linked.request_json)
        # A TEAM-bound row owns this exact destructive resource even when its
        # immutable request can no longer be trusted.  Treat corruption or a
        # conflicting lifecycle as an ambiguity, never as permission for the
        # generic scheduler to remove the same member.
        if not _cleanup_request_is_intact(linked, linked_request):
            return {"state": "owned", "authority_id": cleanup_id}
        linked_lifecycle = _deactivated_cleanup_lifecycle(
            linked,
            linked_request,
        )
        if linked_lifecycle is None or linked_lifecycle != lifecycle:
            return {"state": "owned", "authority_id": cleanup_id}
        if linked_lifecycle == lifecycle:
            authority_ids.add(cleanup_id)

    if not authority_ids:
        return {"state": "none"}
    if len(authority_ids) != 1:
        return {"state": "owned", "authority_id": ""}
    authority_id = next(iter(authority_ids))

    if str(job.id) != authority_id:
        safety = _cleanup_duplicate_safety(session, job, now=current)
        if safety != "safe":
            return {"state": safety, "authority_id": authority_id}
        job.state = "superseded"
        job.stage = "superseded_by_team401_cleanup"
        job.worker_token = ""
        job.lease_expires_at = None
        job.resume_at = None
        job.error = ""
        job.updated_at = current
        session.add(job)
        return {"state": "superseded", "authority_id": authority_id}

    # The authoritative row may proceed only after every exact duplicate is
    # proven safe to retire.  Classify all rows first so a later busy/owned row
    # cannot leave an earlier duplicate partially superseded.
    candidates = session.exec(
        select(DeliveryDeviceExhaustionCleanupModel)
        .where(DeliveryDeviceExhaustionCleanupModel.provider == str(job.provider))
        .where(
            DeliveryDeviceExhaustionCleanupModel.provider_id
            == int(job.provider_id or 0)
        )
        .where(
            DeliveryDeviceExhaustionCleanupModel.business_parent_id
            == int(job.business_parent_id or 0)
        )
        .where(
            DeliveryDeviceExhaustionCleanupModel.account_id
            == int(job.account_id or 0)
        )
        .where(
            DeliveryDeviceExhaustionCleanupModel.membership_id
            == int(job.membership_id or 0)
        )
        .where(
            DeliveryDeviceExhaustionCleanupModel.remote_id
            == str(job.remote_id or "")
        )
        .where(DeliveryDeviceExhaustionCleanupModel.id != str(job.id))
        .where(DeliveryDeviceExhaustionCleanupModel.state != "superseded")
    ).all()
    duplicates: list[DeliveryDeviceExhaustionCleanupModel] = []
    classifications: list[str] = []
    for candidate in candidates:
        candidate_request = _json_object(candidate.request_json)
        if (
            not _cleanup_request_is_intact(candidate, candidate_request)
            or _deactivated_cleanup_lifecycle(candidate, candidate_request)
            != lifecycle
        ):
            continue
        duplicates.append(candidate)
        classifications.append(
            _cleanup_duplicate_safety(session, candidate, now=current)
        )
    if "owned" in classifications:
        return {"state": "owned", "authority_id": authority_id}
    if "busy" in classifications:
        return {"state": "busy", "authority_id": authority_id}
    for duplicate in duplicates:
        duplicate.state = "superseded"
        duplicate.stage = "superseded_by_team401_cleanup"
        duplicate.worker_token = ""
        duplicate.lease_expires_at = None
        duplicate.resume_at = None
        duplicate.error = ""
        duplicate.updated_at = current
        session.add(duplicate)
    return {"state": "ready", "authority_id": authority_id}


def _create_or_get_cleanup_job(
    *,
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    mapping: dict[str, Any],
    device_epoch: str,
    trigger_kind: str = "quota_exhausted",
    operation_id: str = "",
) -> DeliveryDeviceExhaustionCleanupModel:
    normalized_trigger = str(trigger_kind or "quota_exhausted").strip().lower()
    if normalized_trigger not in _CLEANUP_TRIGGERS:
        raise RuntimeError("cleanup_trigger_invalid")
    replacement_cleanup = normalized_trigger in _REPLACEMENT_CLEANUP_TRIGGERS
    normalized_operation_id = str(operation_id or "").strip()
    if normalized_trigger == "manual_replace" and not normalized_operation_id:
        raise RuntimeError("cleanup_operation_id_missing")
    identity = _cleanup_remote_snapshot(provider, remote)
    account_id = int(mapping.get("account_id") or mapping.get("child_id") or 0)
    parent_id = int(mapping.get("parent_id") or 0)
    membership_id = int(mapping.get("membership_id") or 0)
    if account_id <= 0:
        raise RuntimeError("local_identity_missing")
    if normalized_trigger == "credential_invalid" and not (
        provider == "cpa"
        and parent_id > 0
        and membership_id > 0
        and int(mapping.get("policy_revision") or 0) > 0
        and mapping.get("child_dangerous") is True
        and str(mapping.get("invalid_reason") or "") == "access_deactivated"
        and remote.get("credential_repair_required") is True
        and int(remote.get("credential_repair_status") or 0) == 401
    ):
        raise RuntimeError("credential_invalid_evidence_missing")
    if normalized_trigger == "credential_missing_deactivated" and not (
        provider in {"cpa", "sub2api"}
        and parent_id > 0
        and membership_id > 0
        and int(mapping.get("policy_revision") or 0) > 0
        and mapping.get("child_dangerous") is True
        and str(mapping.get("invalid_reason") or "") == "access_deactivated"
        and mapping.get("missing_remote_confirmed") is True
        and remote.get("credential_missing") is True
    ):
        raise RuntimeError("credential_missing_evidence_missing")
    if normalized_trigger == "team401_replace" and not (
        provider in {"cpa", "sub2api"}
        and parent_id > 0
        and membership_id > 0
        and int(mapping.get("policy_revision") or 0) > 0
        and mapping.get("missing_remote_confirmed") is True
        and remote.get("credential_missing") is True
        and remote.get("credential_repair_required") is True
        and int(remote.get("credential_repair_status") or 0) == 401
    ):
        raise RuntimeError("credential_invalid_evidence_missing")
    request = {
        "trigger_kind": normalized_trigger,
        "operation_id": normalized_operation_id,
        "provider": provider,
        "provider_id": int(provider_id),
        "device_epoch": str(device_epoch or ""),
        "account_id": account_id,
        "scope": "business_child" if parent_id > 0 else "account",
        "business_parent_id": parent_id or None,
        "membership_id": membership_id or None,
        # The freed seat category is immutable cleanup evidence.  The mother
        # runner must refill this exact type; it may never silently substitute
        # a normal seat for a former prolite seat (or vice versa).
        "seat_type": (
            str(mapping.get("seat_type") or "").strip().lower()
            if str(mapping.get("seat_type") or "").strip().lower()
            in {"default", "prolite"}
            else ""
        ),
        "target_kind": str(mapping.get("target_kind") or "member"),
        "remote_user_id": str(mapping.get("remote_user_id") or ""),
        "remote_invite_id": str(mapping.get("remote_invite_id") or ""),
        "email": str(mapping.get("email") or identity["email"] or "").strip(),
        "remote": identity,
        "usage": (
            _cleanup_usage_snapshot(provider, remote)
            if normalized_trigger == "quota_exhausted"
            else _manual_replacement_usage_snapshot(provider, remote)
        ),
        "credential_status_code": (
            int(remote.get("credential_repair_status") or 0)
            if normalized_trigger in {"credential_invalid", "team401_replace"}
            else None
        ),
        "credential_missing": bool(
            normalized_trigger in {
                "credential_missing_deactivated", "team401_replace",
            }
        ),
        "linked_remote_id": str(mapping.get("linked_remote_id") or ""),
        "policy_revision": int(mapping.get("policy_revision") or 0),
        "invalid_reason": str(mapping.get("invalid_reason") or ""),
        "dangerous_detected_at": str(
            mapping.get("dangerous_detected_at") or ""
        ),
        "link_epoch": str(mapping.get("link_epoch") or ""),
    }
    encoded = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    request_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    idempotency_scope = {
        key: request.get(key) for key in (
            "provider", "provider_id", "account_id", "business_parent_id",
            "membership_id", "policy_revision", "invalid_reason", "link_epoch",
        )
    }
    # A 401 file can become "missing" only because the explicit TEAM401 flow
    # deleted that exact file before discovering the child is dead.  These two
    # trigger names therefore describe one immutable child lifecycle and must
    # share an idempotency family; otherwise concurrent refresh/TEAM401 paths
    # can create two mother-removal jobs for the same member.
    idempotency_scope["trigger_kind"] = (
        "credential_deactivated"
        if normalized_trigger in {
            "credential_invalid", "credential_missing_deactivated",
        }
        else normalized_trigger
    )
    idempotency_scope["remote_id"] = identity["remote_id"]
    idempotency_prefix = {
        "manual_replace": "delivery-manual-replace:",
        "credential_invalid": "delivery-credential-invalid:",
        # Reuse the credential-invalid lifecycle family so the replenishment
        # runner releases the exact old-child quarantine after completion.
        "credential_missing_deactivated": "delivery-credential-invalid:",
        "team401_replace": "delivery-team401-replace:",
    }.get(normalized_trigger, "delivery-exhaustion:")
    idempotency_key = idempotency_prefix + hashlib.sha256(
        json.dumps(
            idempotency_scope,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    with Session(engine) as session:
        if (
            normalized_trigger in _DEACTIVATED_CLEANUP_TRIGGERS
            and session.get_bind().dialect.name == "sqlite"
        ):
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        # Prefer an exact same-trigger idempotency row before considering a
        # legacy row from the sibling 401 trigger.  The two sibling triggers
        # intentionally share a key in new data, so a sibling row still has to
        # pass the lifecycle/checkpoint safety path below.  During a rolling
        # upgrade both rows can exist; choosing the older sibling when an
        # exact current row exists would detach its retry from that row.
        previous = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel).where(
                DeliveryDeviceExhaustionCleanupModel.idempotency_key
                == idempotency_key
            )
        ).first()
        previous_trigger = str(
            _json_object(previous.request_json).get("trigger_kind")
            if previous else ""
        ).strip().lower()
        desired_lifecycle = _deactivated_cleanup_lifecycle_values(
            provider=provider,
            provider_id=int(provider_id),
            parent_id=parent_id,
            account_id=account_id,
            membership_id=membership_id,
            remote_id=identity["remote_id"],
            request=request,
        )
        if (
            desired_lifecycle is not None
            and previous_trigger != normalized_trigger
        ):
            equivalents = session.exec(
                select(DeliveryDeviceExhaustionCleanupModel)
                .where(DeliveryDeviceExhaustionCleanupModel.provider == provider)
                .where(
                    DeliveryDeviceExhaustionCleanupModel.provider_id
                    == int(provider_id)
                )
                .where(
                    DeliveryDeviceExhaustionCleanupModel.account_id
                    == account_id
                )
                .where(
                    DeliveryDeviceExhaustionCleanupModel.business_parent_id
                    == parent_id
                )
                .where(
                    DeliveryDeviceExhaustionCleanupModel.membership_id
                    == membership_id
                )
                .where(
                    DeliveryDeviceExhaustionCleanupModel.remote_id
                    == identity["remote_id"]
                )
                .where(
                    DeliveryDeviceExhaustionCleanupModel.state
                    != "superseded"
                )
                .order_by(DeliveryDeviceExhaustionCleanupModel.created_at.desc())
            ).all()
            for equivalent in equivalents:
                equivalent_request = _json_object(equivalent.request_json)
                if (
                    _deactivated_cleanup_lifecycle(
                        equivalent,
                        equivalent_request,
                    ) != desired_lifecycle
                    or str(equivalent_request.get("trigger_kind") or "")
                    == normalized_trigger
                ):
                    continue
                safety = _cleanup_duplicate_safety(session, equivalent)
                if safety == "safe":
                    session.expunge(equivalent)
                    session.rollback()
                    return equivalent
                session.rollback()
                raise RuntimeError(
                    "cleanup_lifecycle_busy"
                    if safety == "busy"
                    else "cleanup_lifecycle_owned"
                )
        operation_job = (
            session.exec(
                select(DeliveryDeviceExhaustionCleanupModel).where(
                    DeliveryDeviceExhaustionCleanupModel.manual_operation_id
                    == normalized_operation_id
                )
            ).first()
            if normalized_trigger == "manual_replace" else None
        )
        if operation_job:
            operation_request = _json_object(operation_job.request_json)
            comparable_operation = dict(operation_request)
            comparable_request = dict(request)
            comparable_operation.pop("usage", None)
            comparable_request.pop("usage", None)
            if comparable_operation != comparable_request:
                raise RuntimeError("cleanup_operation_id_conflict")
            return operation_job
        if previous:
            previous_request = _json_object(previous.request_json)
            comparable_previous = dict(previous_request)
            comparable_request = dict(request)
            comparable_previous.pop("operation_id", None)
            comparable_request.pop("operation_id", None)
            if replacement_cleanup:
                comparable_previous.pop("usage", None)
                comparable_request.pop("usage", None)
            if normalized_trigger == "manual_replace":
                if str(previous.manual_operation_id or previous_request.get(
                    "operation_id"
                ) or "") != normalized_operation_id:
                    raise RuntimeError("cleanup_lifecycle_already_bound")
            if comparable_previous != comparable_request:
                raise RuntimeError("cleanup_idempotency_conflict")
            return previous
        job_id = f"delivery-cleanup-{uuid.uuid4().hex}"
        job = DeliveryDeviceExhaustionCleanupModel(
            id=job_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            request_json=encoded,
            provider=provider,
            provider_id=int(provider_id),
            account_id=account_id,
            business_parent_id=parent_id or None,
            membership_id=membership_id or None,
            remote_id=identity["remote_id"],
            manual_operation_id=(
                normalized_operation_id
                if normalized_trigger == "manual_replace" else None
            ),
            state="prepared",
            # A device-originated lifecycle always starts at the exact device
            # credential boundary.  Mother removal is not authorized until
            # this checkpoint has been durably confirmed.
            stage="device_delete_pending",
            business_operation_id=f"{job_id}:business-remove",
        )
        session.add(job)
        try:
            session.commit()
            session.refresh(job)
            return job
        except IntegrityError:
            session.rollback()
            winner = None
            if normalized_trigger == "manual_replace":
                winner = session.exec(
                    select(DeliveryDeviceExhaustionCleanupModel).where(
                        DeliveryDeviceExhaustionCleanupModel.manual_operation_id
                        == normalized_operation_id
                    )
                ).first()
            if winner is None:
                winner = session.exec(
                    select(DeliveryDeviceExhaustionCleanupModel).where(
                        DeliveryDeviceExhaustionCleanupModel.idempotency_key
                        == idempotency_key
                    )
                ).first()
            winner_request = _json_object(winner.request_json) if winner else {}
            comparable_winner = dict(winner_request)
            comparable_request = dict(request)
            comparable_winner.pop("operation_id", None)
            comparable_request.pop("operation_id", None)
            if replacement_cleanup:
                comparable_winner.pop("usage", None)
                comparable_request.pop("usage", None)
            if normalized_trigger == "manual_replace":
                if winner and str(
                    winner.manual_operation_id
                    or winner_request.get("operation_id")
                    or ""
                ) != normalized_operation_id:
                    raise RuntimeError("cleanup_lifecycle_already_bound")
            if not winner or comparable_winner != comparable_request:
                raise RuntimeError("cleanup_idempotency_conflict")
            return winner


def _cleanup_request(job: DeliveryDeviceExhaustionCleanupModel) -> dict[str, Any]:
    request = _json_object(job.request_json)
    encoded = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if (
        hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        != str(job.request_hash or "")
    ):
        raise RuntimeError("cleanup_request_corrupt")
    return request


def _cleanup_trigger(request: dict[str, Any]) -> str:
    value = str(request.get("trigger_kind") or "quota_exhausted").strip().lower()
    return value if value in _CLEANUP_TRIGGERS else ""


def _cleanup_replacement_cooldown(
    session: Session,
    job: DeliveryDeviceExhaustionCleanupModel,
    request: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Return the mother's persisted 10-minute invite-failure cooldown."""
    if (
        _cleanup_trigger(request) not in _REPLACEMENT_CLEANUP_TRIGGERS
        or bool(job.business_remove_confirmed)
        or int(job.business_parent_id or 0) <= 0
    ):
        return None
    try:
        from api import gpt_business

        cooldown, _invite_quota, _remove_quota = (
            gpt_business._business_rotation_cooldown(
                session,
                int(job.business_parent_id),
                operation_id=str(job.business_operation_id or ""),
                seat_type=request.get("seat_type"),
            )
        )
    except Exception:
        # A quota read failure must not invent a cooldown or expose a database
        # diagnostic.  The normal fenced preflight remains authoritative.
        return None
    if not isinstance(cooldown, dict):
        return None
    return {
        "reason": str(cooldown.get("reason") or "")[:64],
        "resume_at": _safe_public_datetime(cooldown.get("resume_at")),
    }


def _cleanup_audit_key(request: dict[str, Any]) -> str:
    trigger = _cleanup_trigger(request)
    if trigger == "manual_replace":
        return "delivery_manual_replacement"
    if trigger == "credential_invalid":
        return "delivery_credential_invalid_replacement"
    if trigger == "credential_missing_deactivated":
        return "delivery_credential_missing_replacement"
    if trigger == "team401_replace":
        return "delivery_team401_replacement"
    return "delivery_exhaustion"


def _legacy_rotation_matches_cleanup(
    legacy: GptBusinessAllocationJobModel,
    request: dict[str, Any],
) -> bool:
    legacy_request = _json_object(legacy.request_json)
    kind = str(legacy_request.get("job_kind") or "")
    provider = str(request.get("provider") or "")
    if kind != ("cpa_rotation" if provider == "cpa" else "sub2api_rotation"):
        return False
    target = (
        legacy_request.get("cpa_target_id")
        if provider == "cpa"
        else legacy_request.get("sub2api_device_id")
    )
    return bool(
        int(legacy_request.get("old_pro_account_id") or 0)
        == int(request.get("account_id") or 0)
        and int(legacy_request.get("parent_id") or 0)
        == int(request.get("business_parent_id") or 0)
        and int(target or 0) == int(request.get("provider_id") or 0)
    )


def _legacy_rotation_has_business_mutation_evidence(
    session: Session,
    legacy: GptBusinessAllocationJobModel,
) -> bool:
    # The replacement flow persists a membership intent using the rotation job
    # id before it may call the BUSINESS DELETE.  Its presence is authoritative
    # crash-recovery evidence; cleanup must leave that old worker in charge.
    operation_row = session.exec(
        select(GptBusinessChildMembershipModel).where(
            GptBusinessChildMembershipModel.operation_id == str(legacy.id)
        )
    ).first()
    return operation_row is not None


def _active_lease(value: Optional[datetime], now: datetime) -> bool:
    expires = _aware_cleanup_time(value)
    return bool(expires and expires > now)


def _claim_cleanup_job(job_id: str) -> dict[str, Any]:
    """Atomically claim job + account + optional BUSINESS parent/child leases."""
    now = _utcnow()
    expires = now + timedelta(seconds=_CLEANUP_LEASE_SECONDS)
    worker_token = f"cleanup-worker-{uuid.uuid4().hex}"
    try:
        with Session(engine) as session:
            is_sqlite = session.get_bind().dialect.name == "sqlite"
            if is_sqlite:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                job = session.get(DeliveryDeviceExhaustionCleanupModel, job_id)
            else:
                job = session.exec(
                    select(DeliveryDeviceExhaustionCleanupModel)
                    .where(DeliveryDeviceExhaustionCleanupModel.id == job_id)
                    .with_for_update()
                ).first()
            if not job:
                session.rollback()
                return {"state": "missing"}
            if str(job.state or "") == "completed":
                session.rollback()
                return {"state": "completed"}
            if str(job.state or "") == "superseded":
                session.rollback()
                return {"state": "superseded"}
            if (
                str(job.state or "") == "running"
                and _active_lease(job.lease_expires_at, now)
            ):
                session.rollback()
                return {"state": "busy"}
            request = _cleanup_request(job)
            account_id = int(request.get("account_id") or 0)
            parent_id = int(request.get("business_parent_id") or 0)
            if account_id <= 0:
                job.state = "failed"
                job.stage = "invalid_request"
                job.error = "cleanup request invalid"
                job.updated_at = now
                session.add(job)
                session.commit()
                return {"state": "failed"}

            authority = _team401_cleanup_authority_locked(
                session,
                job,
                request,
                now=now,
            )
            authority_state = str(authority.get("state") or "none")
            if authority_state == "superseded":
                session.commit()
                return {"state": "superseded"}
            if authority_state == "busy":
                session.rollback()
                return {"state": "busy"}
            if authority_state == "owned":
                # A duplicate has either an irreversible checkpoint or an
                # ambiguous competing TEAM401 binding.  Neither job may claim
                # the child automatically; an operator must reconcile which
                # remote mutation actually happened.
                session.rollback()
                return {"state": "cleanup_lifecycle_owned"}

            if parent_id > 0:
                parent = session.get(GptBusinessAccountModel, parent_id) if is_sqlite else session.exec(
                    select(GptBusinessAccountModel)
                    .where(GptBusinessAccountModel.id == parent_id)
                    .with_for_update()
                ).first()
                if not parent:
                    job.state = "action_required"
                    job.stage = "business_parent_missing"
                    job.error = "BUSINESS parent missing"
                    job.updated_at = now
                    session.add(job)
                    session.commit()
                    return {"state": "failed"}

                # Invitation cooldown belongs to the later mother invitation
                # capability.  It must never delay or authorize the preceding
                # device deletion / mother removal checkpoints.

                legacy_rows = session.exec(
                    select(GptBusinessAllocationJobModel).where(
                        GptBusinessAllocationJobModel.old_pro_account_id
                        == account_id
                    )
                ).all()
                for legacy in legacy_rows:
                    if not _legacy_rotation_matches_cleanup(legacy, request):
                        continue
                    if str(legacy.state or "") == "completed" or (
                        not bool(legacy.retryable)
                        and str(legacy.stage or "")
                        == "superseded_by_device_cleanup"
                    ):
                        continue
                    live_legacy_lease = session.exec(
                        select(GptBusinessAllocationLeaseModel).where(
                            GptBusinessAllocationLeaseModel.job_id
                            == str(legacy.id)
                        )
                    ).all()
                    if any(_active_lease(row.expires_at, now) for row in live_legacy_lease):
                        session.rollback()
                        return {"state": "busy"}
                    if _legacy_rotation_has_business_mutation_evidence(
                        session, legacy,
                    ):
                        job.state = "superseded"
                        job.stage = "legacy_rotation_recovery_owned"
                        job.error = ""
                        job.updated_at = now
                        session.add(job)
                        session.commit()
                        return {"state": "superseded"}
                    # No active worker and no durable evidence that BUSINESS was
                    # touched: make the old replacement permanently non-resumable
                    # before this cleanup takes the same parent/child resources.
                    legacy.state = "failed"
                    legacy.stage = "superseded_by_device_cleanup"
                    legacy.retryable = False
                    legacy.worker_token = ""
                    legacy.error = "Superseded by exhausted-account cleanup"
                    legacy.updated_at = now
                    session.add(legacy)

            account = session.get(GptProAccountModel, account_id)
            if not account:
                job.state = "action_required"
                job.stage = "account_missing"
                job.error = "local account missing"
                job.updated_at = now
                session.add(job)
                session.commit()
                return {"state": "failed"}
            account_claim = session.get(
                GptProAccountOperationLeaseModel, account_id,
            )
            if account_claim and not _active_lease(account_claim.expires_at, now):
                session.delete(account_claim)
                session.flush()
                account_claim = None
            if account_claim:
                session.rollback()
                return {"state": "busy"}
            session.add(GptProAccountOperationLeaseModel(
                account_id=account_id,
                operation=_CLEANUP_OPERATION,
                token=worker_token,
                expires_at=expires,
                created_at=now,
                updated_at=now,
            ))

            if parent_id > 0:
                for key in (f"parent:{parent_id}", f"child:{account_id}"):
                    lease = session.get(GptBusinessAllocationLeaseModel, key)
                    if lease and not _active_lease(lease.expires_at, now):
                        session.delete(lease)
                        session.flush()
                        lease = None
                    if lease:
                        session.rollback()
                        return {"state": "busy"}
                    session.add(GptBusinessAllocationLeaseModel(
                        resource_key=key,
                        job_id=job_id,
                        owner_token=worker_token,
                        expires_at=expires,
                        created_at=now,
                        updated_at=now,
                    ))

            job.state = "running"
            job.worker_token = worker_token
            job.lease_expires_at = expires
            job.resume_at = None
            job.attempt_count = int(job.attempt_count or 0) + 1
            job.error = ""
            job.updated_at = now
            session.add(job)
            session.commit()
            return {
                "state": "claimed",
                "worker_token": worker_token,
                "request": request,
            }
    except IntegrityError:
        return {"state": "busy"}


def _cleanup_claim_is_current(job_id: str, worker_token: str) -> bool:
    now = _utcnow()
    with Session(engine) as session:
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
        if not job or str(job.state or "") != "running" or str(
            job.worker_token or ""
        ) != str(worker_token):
            return False
        claim = session.get(GptProAccountOperationLeaseModel, int(job.account_id))
        if not (
            claim
            and str(claim.token or "") == str(worker_token)
            and str(claim.operation or "") == _CLEANUP_OPERATION
            and _active_lease(claim.expires_at, now)
        ):
            return False
        parent_id = int(job.business_parent_id or 0)
        if parent_id <= 0:
            return True
        for key in (f"parent:{parent_id}", f"child:{int(job.account_id)}"):
            lease = session.get(GptBusinessAllocationLeaseModel, key)
            if not (
                lease
                and str(lease.job_id or "") == str(job_id)
                and str(lease.owner_token or "") == str(worker_token)
                and _active_lease(lease.expires_at, now)
            ):
                return False
    return True


def _release_cleanup_claims(job_id: str, worker_token: str) -> None:
    if not worker_token:
        return
    with Session(engine) as session:
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
        account_id = int(job.account_id or 0) if job else 0
        if account_id:
            claim = session.get(GptProAccountOperationLeaseModel, account_id)
            if claim and str(claim.token or "") == str(worker_token):
                session.delete(claim)
        rows = session.exec(
            select(GptBusinessAllocationLeaseModel).where(
                GptBusinessAllocationLeaseModel.job_id == str(job_id)
            )
        ).all()
        for row in rows:
            if str(row.owner_token or "") == str(worker_token):
                session.delete(row)
        session.commit()


def _update_cleanup_job(
    job_id: str,
    expected_worker_token: str,
    **changes: Any,
) -> bool:
    with Session(engine) as session:
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
        if not job or str(job.worker_token or "") != str(expected_worker_token):
            return False
        for key, value in changes.items():
            setattr(job, key, value)
        job.updated_at = _utcnow()
        session.add(job)
        session.commit()
    return True


def _complete_cleanup_and_enqueue_replenishment(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> Optional[str]:
    """Commit cleanup completion and the BUSINESS refill demand atomically.

    Ordinary/PRO accounts intentionally create no demand.  For a BUSINESS
    child, ``cleanup_job_id`` is the idempotency boundary, so retrying this
    handoff after a crash can never create a second future invitation.
    """
    parent_id = int(request.get("business_parent_id") or 0)
    provider = str(request.get("provider") or "").strip().lower()
    device_id = int(request.get("provider_id") or 0)
    raw_seat_type = str(request.get("seat_type") or "").strip().lower()
    seat_type = raw_seat_type if raw_seat_type in {"default", "prolite"} else ""
    now = _utcnow()
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
        if job and str(job.state or "") == "completed":
            previous = session.exec(
                select(DeliveryDeviceReplenishmentDemandModel).where(
                    DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                    == str(job_id)
                )
            ).first()
            session.rollback()
            if parent_id <= 0:
                return None
            if previous is not None:
                return str(previous.id)
            # A completed BUSINESS cleanup without its atomic handoff is an
            # invariant violation; do not guess a second lifecycle from it.
            raise RuntimeError("replenishment_handoff_missing")
        if (
            not job
            or str(job.worker_token or "") != str(worker_token or "")
            or str(job.state or "") != "running"
        ):
            session.rollback()
            raise RuntimeError("cleanup_fenced")
        if (
            not bool(job.device_delete_confirmed)
            or not bool(job.local_snapshot_persisted)
            or (parent_id > 0 and not bool(job.business_remove_confirmed))
        ):
            session.rollback()
            raise RuntimeError("cleanup_checkpoint_incomplete")

        demand_id: Optional[str] = None
        if parent_id > 0:
            previous = session.exec(
                select(DeliveryDeviceReplenishmentDemandModel).where(
                    DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                    == str(job_id)
                )
            ).first()
            if previous is None:
                demand_id = f"replenishment-{uuid.uuid4().hex}"
                demand = DeliveryDeviceReplenishmentDemandModel(
                    id=demand_id,
                    cleanup_job_id=str(job_id),
                    provider=provider,
                    device_id=device_id,
                    business_parent_id=parent_id,
                    seat_type=seat_type,
                    state="pending" if seat_type else "action_required",
                    stage="queued" if seat_type else "seat_type_unknown",
                    next_check_at=now if seat_type else None,
                    error=(
                        ""
                        if seat_type
                        else "原子号席位类型无法确认，请人工复核"
                    ),
                    created_at=now,
                    updated_at=now,
                )
                session.add(demand)
            else:
                demand_id = str(previous.id)

        job.state = "completed"
        job.stage = "completed"
        job.error = ""
        job.completed_at = job.completed_at or now
        job.worker_token = ""
        job.lease_expires_at = None
        job.resume_at = None
        job.updated_at = now
        session.add(job)
        session.commit()
        return demand_id


def _cleanup_live_state(request: dict[str, Any]) -> dict[str, Any]:
    account_id = int(request.get("account_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    remote = request.get("remote") if isinstance(request.get("remote"), dict) else {}
    remote_id = str(remote.get("remote_id") or "").strip()
    expected_email = _normalized_email(request.get("email") or remote.get("email"))
    with Session(engine) as session:
        account = session.get(GptProAccountModel, account_id)
        if not account:
            return {"account_missing": True}
        extra = _json_object(account.extra_json)
        account_email = _normalized_email(account.email)
        if expected_email and account_email != expected_email:
            return {"identity_conflict": True}
        audit = extra.get(_cleanup_audit_key(request))
        local_audit = bool(
            isinstance(audit, dict)
            and str(audit.get("cleanup_job_id") or "")
            == str(request.get("cleanup_job_id") or "")
        )
        if provider == "cpa":
            try:
                linked_device = int(
                    extra.get("cpa_synced_to_id")
                    or extra.get("cpa_device_id")
                    or 0
                )
            except (TypeError, ValueError):
                linked_device = 0
            linked_remote = str(extra.get("cpa_auth_name") or "").strip()
            link_current = bool(
                extra.get("cpa_synced")
                and linked_device == provider_id
                and linked_remote == remote_id
            )
            different_link = bool(
                extra.get("cpa_synced")
                and (linked_device != provider_id or linked_remote != remote_id)
            )
            sub_removed_audit = False
        else:
            try:
                linked_device = int(extra.get("sub2api_device_id") or 0)
            except (TypeError, ValueError):
                linked_device = 0
            linked_remote = str(
                extra.get("sub2api_remote_account_id") or ""
            ).strip()
            link_current = bool(
                linked_device == provider_id and linked_remote == remote_id
            )
            different_link = bool(
                linked_remote
                and (linked_device != provider_id or linked_remote != remote_id)
            )
            removed = extra.get("sub2api_last_removed")
            sub_removed_audit = bool(
                isinstance(removed, dict)
                and int(removed.get("device_id") or 0) == provider_id
                and str(removed.get("remote_account_id") or "") == remote_id
                and str(removed.get("reason") or "")
                == str(request.get("cleanup_reason") or "")
                and bool(removed.get("remote_deleted"))
            )
        membership = (
            session.get(GptBusinessChildMembershipModel, membership_id)
            if membership_id > 0 else None
        )
        business_current = bool(
            parent_id > 0
            and membership
            and membership.ended_at is None
            and int(membership.business_account_id) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and int(account.business_parent_id or 0) == parent_id
        )
        business_finished = bool(
            parent_id > 0
            and membership
            and membership.ended_at is not None
            and int(membership.business_account_id) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and account.business_parent_id is None
        )
    return {
        "link_current": link_current,
        "different_link": different_link,
        "local_audit": local_audit,
        "sub_removed_audit": sub_removed_audit,
        "business_current": business_current,
        "business_finished": business_finished,
    }


def _persist_missing_credential_absence_snapshot(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    """Close the stale device link before delegating mother removal.

    A missing-credential replacement has no remote DELETE to perform, so a
    fresh full-device absence check is its device-side mutation boundary.  The
    local link/audit must be persisted while the membership is still active;
    requiring mother removal first would silently invert the public
    device->mother ordering.  The finished form remains accepted solely for
    crash recovery from rows written by older workers.
    """
    if not _cleanup_claim_is_current(job_id, worker_token):
        raise RuntimeError("cleanup_fenced")
    account_id = int(request.get("account_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    expected_email = _normalized_email(request.get("email"))
    linked_remote_id = str(request.get("linked_remote_id") or "").strip()
    link_epoch = str(request.get("link_epoch") or "").strip()
    audit_key = _cleanup_audit_key(request)
    now = _utcnow()
    with Session(engine) as session:
        account = session.get(GptProAccountModel, account_id)
        membership = session.get(
            GptBusinessChildMembershipModel,
            membership_id,
        )
        cleanup = session.get(
            DeliveryDeviceExhaustionCleanupModel,
            str(job_id),
        )
        claim = session.get(GptProAccountOperationLeaseModel, account_id)
        active_membership = bool(
            account
            and membership
            and int(account.business_parent_id or 0) == parent_id
            and membership.ended_at is None
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == account_id
        )
        finished_membership = bool(
            account
            and membership
            and account.business_parent_id is None
            and membership.ended_at is not None
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and cleanup
            and str(membership.operation_id or "")
            == str(cleanup.business_operation_id or "")
        )
        if not (
            account
            and membership
            and cleanup
            and claim
            and str(claim.token or "") == str(worker_token)
            and str(claim.operation or "") == _CLEANUP_OPERATION
            and _active_lease(claim.expires_at, now)
            and _normalized_email(account.email) == expected_email
            and _normalized_email(membership.email) == expected_email
            and (active_membership or finished_membership)
        ):
            raise RuntimeError("cleanup_identity_changed")
        extra = _json_object(account.extra_json)
        previous = extra.get(audit_key)
        if (
            isinstance(previous, dict)
            and str(previous.get("cleanup_job_id") or "") == str(job_id)
        ):
            return
        if provider == "cpa":
            try:
                current_device_id = int(
                    extra.get("cpa_synced_to_id")
                    or extra.get("cpa_device_id")
                    or 0
                )
            except (TypeError, ValueError):
                current_device_id = -1
            current_remote_id = str(extra.get("cpa_auth_name") or "").strip()
            current_epoch = str(extra.get("cpa_synced_at") or "").strip()
            if (
                current_device_id not in {0, provider_id}
                or (current_remote_id and current_remote_id != linked_remote_id)
                or (not linked_remote_id and current_remote_id)
                or (link_epoch and current_epoch and current_epoch != link_epoch)
            ):
                raise RuntimeError("cleanup_identity_changed")
            for key in (
                "cpa_synced", "cpa_synced_to_id", "cpa_synced_to_name",
                "cpa_device_id", "cpa_config_domain", "cpa_auth_name",
                "cpa_synced_at", "cpa_usage", "cpa_monitor_alert",
                "cpa_disabled", "cpa_disabled_at", "cpa_disabled_reason",
                "cpa_lifecycle_state", "cpa_monitor_suppressed",
                "cpa_disable_pending", "cpa_disable_pending_at",
                "cpa_disable_pending_reason", "cpa_disable_last_error",
                "cpa_rotation_delete_required",
                "cpa_rotation_delete_required_target_id",
                "cpa_rotation_delete_required_auth_name",
                "cpa_rotation_delete_requested_at",
                "cpa_rotation_delete_confirmed",
                "cpa_rotation_delete_confirmed_at",
                "cpa_rotation_delete_confirmed_target_id",
                "cpa_rotation_delete_confirmed_auth_name",
                "cpa_rotation_delete_confirmed_ready_at",
            ):
                extra.pop(key, None)
            extra["cpa_last_removed"] = {
                "target_id": provider_id,
                "auth_name": linked_remote_id,
                "removed_at": now.isoformat(),
                "reason": "credential_missing_deactivated",
                "remote_deleted": False,
                "remote_absent_confirmed": True,
            }
        elif provider == "sub2api":
            try:
                current_device_id = int(extra.get("sub2api_device_id") or 0)
            except (TypeError, ValueError):
                current_device_id = -1
            current_remote_id = str(
                extra.get("sub2api_remote_account_id") or ""
            ).strip()
            current_epoch = str(extra.get("sub2api_synced_at") or "").strip()
            if (
                current_device_id not in {0, provider_id}
                or (current_remote_id and current_remote_id != linked_remote_id)
                or (not linked_remote_id and current_remote_id)
                or (link_epoch and current_epoch and current_epoch != link_epoch)
            ):
                raise RuntimeError("cleanup_identity_changed")
            for key in (
                "sub2api_device_id", "sub2api_device_name",
                "sub2api_remote_account_id", "sub2api_synced_at",
                "sub2api_account_kind", "sub2api_business_parent_id",
                "sub2api_sync_pending", "sub2api_sync_pending_device_id",
                "sub2api_sync_pending_device_name",
                "sub2api_sync_pending_started_at",
                "sub2api_sync_pending_remote_account_id",
                "sub2api_sync_pending_operation_token",
                "sub2api_sync_pending_business_parent_id", "sub2api_usage",
                "sub2api_last_error", "sub2api_last_error_at",
                "sub2api_monitor_alert",
            ):
                extra.pop(key, None)
            extra["sub2api_status"] = "unlinked"
            extra["sub2api_last_removed"] = {
                "device_id": provider_id,
                "remote_account_id": linked_remote_id,
                "removed_at": now.isoformat(),
                "reason": "credential_missing_deactivated",
                "remote_deleted": False,
                "remote_absent_confirmed": True,
            }
        else:
            raise RuntimeError("cleanup_identity_changed")
        extra[audit_key] = {
            "cleanup_job_id": str(job_id),
            "provider": provider,
            "provider_id": provider_id,
            "remote_id": linked_remote_id,
            "removed_at": now.isoformat(),
            "business_parent_id": parent_id,
            "reason": "credential_missing_deactivated",
            "remote_absent_confirmed": True,
        }
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = now
        session.add(account)
        session.commit()


def _persist_cleanup_account_snapshot(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    from services.sub2api_admin import sanitize_admin_payload

    if not _cleanup_claim_is_current(job_id, worker_token):
        raise RuntimeError("cleanup_fenced")
    account_id = int(request.get("account_id") or 0)
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    remote = request.get("remote") if isinstance(request.get("remote"), dict) else {}
    remote_id = str(remote.get("remote_id") or "").strip()
    trigger = _cleanup_trigger(request)
    replacement_cleanup = trigger in _REPLACEMENT_CLEANUP_TRIGGERS
    removal_reason = (
        "credential_invalid_replacement"
        if trigger == "credential_invalid"
        else "manual_device_replacement"
    )
    audit_key = _cleanup_audit_key(request)
    now = _utcnow()
    with Session(engine) as session:
        account = session.get(GptProAccountModel, account_id)
        claim = session.get(GptProAccountOperationLeaseModel, account_id)
        if not (
            account
            and claim
            and str(claim.token or "") == str(worker_token)
            and str(claim.operation or "") == _CLEANUP_OPERATION
            and _active_lease(claim.expires_at, now)
        ):
            raise RuntimeError("cleanup_fenced")
        extra = _json_object(account.extra_json)
        prior_audit = extra.get(audit_key)
        same_audit = bool(
            isinstance(prior_audit, dict)
            and str(prior_audit.get("cleanup_job_id") or "") == str(job_id)
        )
        if provider == "cpa":
            try:
                linked_device = int(
                    extra.get("cpa_synced_to_id")
                    or extra.get("cpa_device_id")
                    or 0
                )
            except (TypeError, ValueError):
                linked_device = 0
            linked_remote = str(extra.get("cpa_auth_name") or "").strip()
            exact_link = bool(
                linked_device == provider_id
                and linked_remote == remote_id
                and (bool(extra.get("cpa_synced")) or replacement_cleanup)
            )
            if not exact_link and not same_audit:
                raise RuntimeError("local_link_changed")
            if replacement_cleanup:
                for key in (
                    "cpa_synced", "cpa_synced_to_id", "cpa_synced_to_name",
                    "cpa_device_id", "cpa_config_domain", "cpa_auth_name",
                    "cpa_synced_at", "cpa_usage", "cpa_monitor_alert",
                    "cpa_disabled", "cpa_disabled_at", "cpa_disabled_reason",
                    "cpa_lifecycle_state", "cpa_monitor_suppressed",
                    "cpa_disable_pending", "cpa_disable_pending_at",
                    "cpa_disable_pending_reason", "cpa_disable_last_error",
                    "cpa_rotation_delete_required",
                    "cpa_rotation_delete_required_target_id",
                    "cpa_rotation_delete_required_auth_name",
                    "cpa_rotation_delete_requested_at",
                    "cpa_rotation_delete_confirmed",
                    "cpa_rotation_delete_confirmed_at",
                    "cpa_rotation_delete_confirmed_target_id",
                    "cpa_rotation_delete_confirmed_auth_name",
                    "cpa_rotation_delete_confirmed_ready_at",
                ):
                    extra.pop(key, None)
                extra["cpa_last_removed"] = {
                    "target_id": provider_id,
                    "auth_name": remote_id,
                    "removed_at": now.isoformat(),
                    "reason": removal_reason,
                    "remote_deleted": True,
                }
            else:
                usage = request.get("usage") if isinstance(request.get("usage"), dict) else {}
                extra["cpa_usage"] = {
                    "usage_5h_percent": 100,
                    "usage_5h_reset_at": usage.get("usage_5h_reset_at"),
                    "usage_5h_window_seconds": usage.get("usage_5h_window_seconds"),
                    "usage_week_percent": 100,
                    "usage_week_reset_at": usage.get("usage_week_reset_at"),
                    "usage_week_window_seconds": usage.get("usage_week_window_seconds"),
                    "limit_reached": True,
                    "credit_balance": usage.get("credit_balance"),
                    "checked_at": now.isoformat(),
                }
                extra["cpa_synced"] = False
                extra["cpa_disabled"] = True
                extra["cpa_disabled_at"] = now.isoformat()
                extra["cpa_disabled_reason"] = "quota_exhausted_removed"
                extra["cpa_lifecycle_state"] = "quota_exhausted_removed"
                extra["cpa_monitor_suppressed"] = True
                for key in (
                    "cpa_rotation_delete_required",
                    "cpa_rotation_delete_required_target_id",
                    "cpa_rotation_delete_required_auth_name",
                    "cpa_rotation_delete_requested_at",
                    "cpa_rotation_delete_confirmed",
                    "cpa_rotation_delete_confirmed_at",
                    "cpa_rotation_delete_confirmed_target_id",
                    "cpa_rotation_delete_confirmed_auth_name",
                    "cpa_rotation_delete_confirmed_ready_at",
                ):
                    extra.pop(key, None)
        else:
            linked_remote = str(
                extra.get("sub2api_remote_account_id") or ""
            ).strip()
            if linked_remote and not same_audit:
                raise RuntimeError("local_link_changed")
            if not replacement_cleanup:
                payload = request.get("usage") if isinstance(request.get("usage"), dict) else {}
                payload = sanitize_admin_payload({
                    **payload,
                    "limit_reached": True,
                    "used_percent": 100,
                })
                extra["sub2api_usage"] = {
                    "source": "active",
                    "payload": payload,
                    "limit_reached": True,
                    "checked_at": now.isoformat(),
                }
                extra["sub2api_status"] = "limit_reached"
        if replacement_cleanup:
            extra[audit_key] = {
                "cleanup_job_id": str(job_id),
                "provider": provider,
                "provider_id": provider_id,
                "remote_id": remote_id,
                "removed_at": now.isoformat(),
                "business_parent_id": request.get("business_parent_id"),
                "reason": removal_reason,
            }
        else:
            extra[audit_key] = {
                "cleanup_job_id": str(job_id),
                "provider": provider,
                "provider_id": provider_id,
                "remote_id": remote_id,
                "limit_reached": True,
                "remaining_percent": 0,
                "removed_at": now.isoformat(),
                "business_parent_id": request.get("business_parent_id"),
                "refund_eligible": bool(
                    account.is_pro and not str(account.refund_status or "").strip()
                ),
            }
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = now
        session.add(account)
        session.commit()


def _persist_manual_replacement_quarantine(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    """Exclude the old child from every candidate pool before mother removal."""
    if _cleanup_trigger(request) not in _REPLACEMENT_CLEANUP_TRIGGERS:
        return
    if not _cleanup_claim_is_current(job_id, worker_token):
        raise RuntimeError("cleanup_fenced")
    account_id = int(request.get("account_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    remote = request.get("remote") if isinstance(request.get("remote"), dict) else {}
    remote_id = str(remote.get("remote_id") or "").strip()
    now = _utcnow()
    with Session(engine) as session:
        account = session.get(GptProAccountModel, account_id)
        claim = session.get(GptProAccountOperationLeaseModel, account_id)
        if not (
            account
            and claim
            and str(claim.token or "") == str(worker_token)
            and str(claim.operation or "") == _CLEANUP_OPERATION
            and _active_lease(claim.expires_at, now)
        ):
            raise RuntimeError("cleanup_fenced")
        extra = _json_object(account.extra_json)
        existing = extra.get("delivery_replacement_pending")
        if isinstance(existing, dict):
            if str(existing.get("cleanup_job_id") or "") != str(job_id):
                raise RuntimeError("replacement_quarantine_conflict")
            if int(existing.get("business_parent_id") or 0) != parent_id:
                raise RuntimeError("replacement_quarantine_conflict")
            return
        if int(account.business_parent_id or 0) != parent_id:
            raise RuntimeError("cleanup_identity_changed")
        extra["delivery_replacement_pending"] = {
            "cleanup_job_id": str(job_id),
            "provider": str(request.get("provider") or ""),
            "provider_id": int(request.get("provider_id") or 0),
            "remote_id": remote_id,
            "business_parent_id": parent_id,
            "created_at": now.isoformat(),
        }
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = now
        session.add(account)
        session.commit()


def _cleanup_device_account(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    from api.gpt_plan_operations import (
        _cache_sub2api_usage,
        _delete_linked_sub2api_remote,
        delete_managed_business_child_from_sub2api,
    )

    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    account_id = int(request.get("account_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    epoch = str(request.get("device_epoch") or "")
    remote = request.get("remote") if isinstance(request.get("remote"), dict) else {}
    replacement_cleanup = (
        _cleanup_trigger(request) in _REPLACEMENT_CLEANUP_TRIGGERS
    )
    if _cleanup_trigger(request) in {
        "credential_missing_deactivated", "team401_replace",
    }:
        # There is deliberately no second remote DELETE in this path.  The old
        # file is already absent (TEAM401 may have deleted it), so a fresh full
        # inventory read plus the fenced local absence snapshot is the durable
        # device-first checkpoint.  Mother removal is authorized only after it.
        _confirm_missing_business_child_remote_absent(
            provider,
            provider_id,
            epoch,
            request,
        )
        _persist_missing_credential_absence_snapshot(
            job_id,
            worker_token,
            request,
        )
        return
    state = _cleanup_live_state(request)
    if state.get("identity_conflict") or state.get("different_link"):
        raise RuntimeError("cleanup_identity_changed")
    if state.get("local_audit"):
        return
    if not _device_epoch_is_current(provider, provider_id, epoch):
        raise RuntimeError("device_changed")

    def _guard(*, require_link: bool = True) -> bool:
        if not _cleanup_claim_is_current(job_id, worker_token):
            return False
        if not _device_epoch_is_current(provider, provider_id, epoch):
            return False
        current = _cleanup_live_state(request)
        if current.get("identity_conflict") or current.get("different_link"):
            return False
        if parent_id > 0 and not (
            current.get("business_current") or current.get("business_finished")
        ):
            return False
        return bool(current.get("link_current")) if require_link else True

    if provider == "cpa":
        if state.get("link_current") and not replacement_cleanup:
            _cache_cpa_exhaustion(account_id, {
                "usage": request.get("usage") or {},
            })
        internal = _internal_device_or_error(provider, provider_id)
        _delete_cpa_remote_exact(
            internal,
            remote,
            before_mutation=lambda: _guard(require_link=True),
        )
    else:
        if state.get("link_current"):
            if not replacement_cleanup:
                cached = _cache_sub2api_usage(
                    account_id,
                    {
                        **dict(request.get("usage") or {}),
                        "limit_reached": True,
                        "used_percent": 100,
                    },
                    source="active",
                    operation_token=worker_token,
                    expected_business_parent_id=parent_id or None,
                    expected_device_id=provider_id,
                    expected_remote_account_id=str(remote.get("remote_id") or ""),
                )
                if cached is None:
                    raise RuntimeError("usage_cache_fenced")
            if parent_id > 0 and not replacement_cleanup:
                delete_managed_business_child_from_sub2api(
                    account_id,
                    expected_business_parent_id=parent_id,
                    operation_token=worker_token,
                    deletion_guard=lambda: _guard(require_link=True),
                    reason=str(request.get("cleanup_reason") or ""),
                )
            else:
                _delete_linked_sub2api_remote(
                    account_id,
                    reason=str(request.get("cleanup_reason") or ""),
                    operation_token=worker_token,
                    expected_business_parent_id=(
                        parent_id
                        if parent_id > 0 and state.get("business_current")
                        else None
                    ),
                    deletion_guard=lambda: _guard(require_link=True),
                )
        elif not state.get("sub_removed_audit"):
            raise RuntimeError("local_link_changed")
    _persist_cleanup_account_snapshot(job_id, worker_token, request)


def _cleanup_business_end_reason(request: dict[str, Any]) -> str:
    return {
        "manual_replace": "manual_device_replacement",
        "credential_invalid": "credential_invalid",
        "credential_missing_deactivated": "credential_missing_deactivated",
        "team401_replace": "device_credential_401",
    }.get(_cleanup_trigger(request), "quota_exhausted")


def _reconcile_finished_business_remove_checkpoint(
    job_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> bool:
    """CAS an exact completed BUSINESS intent across the post-remove crash gap."""
    if not _cleanup_claim_is_current(job_id, worker_token):
        return False
    parent_id = int(request.get("business_parent_id") or 0)
    account_id = int(request.get("account_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    if min(parent_id, account_id, membership_id) <= 0:
        return False
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
        membership = session.get(
            GptBusinessChildMembershipModel, membership_id,
        )
        account = session.get(GptProAccountModel, account_id)
        if not (
            job
            and str(job.state or "") == "running"
            and str(job.worker_token or "") == str(worker_token)
            and not bool(job.business_remove_confirmed)
            and membership
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and membership.ended_at is not None
            and str(membership.operation_id or "")
            == str(job.business_operation_id or "")
            and str(membership.end_reason or "")
            == _cleanup_business_end_reason(request)
            and _normalized_email(membership.email)
            == _normalized_email(request.get("email"))
            and account
            and account.business_parent_id is None
        ):
            session.rollback()
            return False
        pending = _json_object(account.extra_json).get(
            "delivery_replacement_pending"
        )
        if not (
            isinstance(pending, dict)
            and str(pending.get("cleanup_job_id") or "") == str(job_id)
            and int(pending.get("business_parent_id") or 0) == parent_id
        ):
            session.rollback()
            return False
        job.business_remove_confirmed = True
        # New workers can only reach this crash gap after device deletion.
        # Preserve a recovery path for legacy mother-first rows by sending
        # those exact historical checkpoints back through device deletion.
        job.stage = (
            "replenishment_pending"
            if bool(job.device_delete_confirmed)
            and bool(job.local_snapshot_persisted)
            else "device_delete_pending"
        )
        job.updated_at = _utcnow()
        session.add(job)
        session.commit()
        return True


def _cleanup_business_child(
    job: DeliveryDeviceExhaustionCleanupModel,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    """Delegate one exact old-child removal to the mother capability.

    Device orchestration owns only the ordering/checkpoints.  Resolving whether
    the active remote identity is a member or a pending invite, acquiring the
    mother/child mutation leases and issuing remove versus revoke all belong to
    ``gpt_business``.  Keeping that decision behind the public automation
    boundary also makes UI- and device-triggered removals share one contract.
    """
    from api import gpt_business

    parent_id = int(request.get("business_parent_id") or 0)
    if parent_id <= 0:
        return
    account_id = int(request.get("account_id") or 0)
    operation_id = str(job.business_operation_id or "")
    if not _cleanup_claim_is_current(str(job.id), worker_token):
        raise RuntimeError("cleanup_fenced")
    result = gpt_business.remove_managed_business_child_for_automation(
        parent_id,
        child_id=account_id,
        operation_id=operation_id,
        end_reason=_cleanup_business_end_reason(request),
        expected_operation_token=worker_token,
    )
    if not bool(result.get("ok")):
        raise RuntimeError("business_cleanup_unconfirmed")


def _manual_replacement_worker_preflight(
    job: DeliveryDeviceExhaustionCleanupModel,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    """Recheck every DB fence while the cleanup owns parent/child leases."""
    from api import gpt_business

    if not _cleanup_claim_is_current(str(job.id), worker_token):
        raise RuntimeError("cleanup_fenced")
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    account_id = int(request.get("account_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    seat_type = str(request.get("seat_type") or "")
    trigger = _cleanup_trigger(request)
    remote = request.get("remote") if isinstance(request.get("remote"), dict) else {}
    if seat_type not in {"default", "prolite"}:
        raise RuntimeError("seat_type_unknown")
    if not _device_epoch_is_current(
        provider, provider_id, str(request.get("device_epoch") or ""),
    ):
        raise RuntimeError("device_changed")
    if trigger in {"credential_missing_deactivated", "team401_replace"}:
        _confirm_missing_business_child_remote_absent(
            provider,
            provider_id,
            str(request.get("device_epoch") or ""),
            request,
        )
    elif not _mapping_is_current(provider, provider_id, remote, {
        "parent_id": parent_id,
        "membership_id": membership_id,
        "child_id": account_id,
    }):
        raise RuntimeError("cleanup_identity_changed")
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        child = session.get(GptProAccountModel, account_id)
        membership = session.get(GptBusinessChildMembershipModel, membership_id)
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        if not parent or not bool(parent.enabled) or bool(parent.dangerous):
            raise RuntimeError("business_parent_unsafe")
        if gpt_business._business_parent_refund_blocks_replacement(
            parent, session,
        ):
            raise RuntimeError("business_parent_unsafe")
        if not bool(
            gpt_business._business_account_team_session_status(parent).get("usable")
        ):
            raise RuntimeError("business_parent_session_unavailable")
        if not (
            child
            and int(child.business_parent_id or 0) == parent_id
            and membership
            and membership.ended_at is None
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and str(membership.seat_type or "").strip().lower() == seat_type
        ):
            raise RuntimeError("cleanup_identity_changed")
        if trigger in {
            "credential_invalid", "credential_missing_deactivated",
        } and not (
            (
                provider == "cpa"
                if trigger == "credential_invalid"
                else provider in {"cpa", "sub2api"}
            )
            and str(request.get("invalid_reason") or "")
            == "access_deactivated"
            and int(request.get("policy_revision") or 0) > 0
            and bool(child.dangerous)
            and (
                int(request.get("credential_status_code") or 0) == 401
                if trigger == "credential_invalid"
                else bool(request.get("credential_missing"))
            )
        ):
            raise RuntimeError(
                "credential_replacement_no_longer_authorized"
            )
        binding = gpt_business._business_initial_fill_binding(policy) if policy else {}
        if not (
            policy
            and bool(policy.auto_rotation_enabled)
            and (
                trigger not in {
                    "credential_invalid", "credential_missing_deactivated",
                    "team401_replace",
                }
                or int(policy.revision or 0)
                == int(request.get("policy_revision") or 0)
            )
            and str(binding.get("delivery_type") or "") == provider
            and int(binding.get("target_id") or 0) == provider_id
        ):
            raise RuntimeError("device_binding_changed")
        # Candidate selection and invitation cooldown are mother-invitation
        # concerns.  The durable replenishment capability evaluates them only
        # after device deletion and mother removal have been confirmed.


def _run_delivery_exhaustion_cleanup(
    job_id: str,
    *,
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    claim = _claim_cleanup_job(str(job_id))
    claim_state = str(claim.get("state") or "failed")
    if claim_state == "completed":
        try:
            from api import gpt_business

            gpt_business.purge_released_dead_business_child_for_delivery_cleanup(
                str(job_id),
            )
        except Exception:
            pass
        return {"kind": "success", "resumed": False}
    if claim_state == "superseded":
        try:
            from api import gpt_business

            gpt_business.purge_released_dead_business_child_for_delivery_cleanup(
                str(job_id),
            )
        except Exception:
            pass
        return {"kind": "superseded", "resumed": False}
    if claim_state == "busy":
        return {"kind": "busy", "resumed": False}
    if claim_state == "waiting_cooldown":
        return {
            "kind": "waiting",
            "resumed": False,
            "stage": "waiting_cooldown",
            "resume_at": _safe_public_datetime(claim.get("resume_at")),
        }
    if claim_state == "cleanup_lifecycle_owned":
        return {
            "kind": "failed",
            "resumed": False,
            "error_code": "cleanup_lifecycle_owned",
        }
    if claim_state != "claimed":
        return {"kind": "failed", "resumed": False}
    worker_token = str(claim["worker_token"])
    request = dict(claim["request"])
    request["cleanup_job_id"] = str(job_id)
    trigger = _cleanup_trigger(request)
    replacement_cleanup = trigger in _REPLACEMENT_CLEANUP_TRIGGERS
    request["cleanup_reason"] = {
        "manual_replace": f"delivery_manual_replacement:{job_id}",
        "credential_invalid": (
            f"delivery_credential_invalid_replacement:{job_id}"
        ),
        "credential_missing_deactivated": (
            f"delivery_credential_missing_replacement:{job_id}"
        ),
        "team401_replace": f"delivery_team401_replacement:{job_id}",
    }.get(trigger, f"delivery_exhaustion_cleanup:{job_id}")
    try:
        with Session(engine) as session:
            job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
            if not job:
                raise RuntimeError("cleanup_missing")
            business_done = bool(job.business_remove_confirmed)
            device_done = bool(
                job.device_delete_confirmed and job.local_snapshot_persisted
            )

        # Reconcile, but never repeat, a mother mutation that completed before
        # an older/new worker persisted its local checkpoint.  This is a
        # database-only recovery read; the first new remote mutation below is
        # still always the exact device deletion.
        if (
            int(request.get("business_parent_id") or 0) > 0
            and not business_done
        ):
            business_done = _reconcile_finished_business_remove_checkpoint(
                job_id, worker_token, request,
            )

        # The quarantine is local selection fencing, not a mother mutation.
        # Establish it before the first remote boundary so an old child cannot
        # be selected by another mother while this device-first lifecycle is
        # between checkpoints.
        if replacement_cleanup and int(request.get("business_parent_id") or 0) > 0:
            if not device_done and not business_done:
                if task_id:
                    _refresh_task_update(task_id, stage="preflight")
                    _refresh_task_child_update(
                        task_id,
                        child_progress_identity or {},
                        status="running",
                        stage="preflight",
                        percent=10,
                    )
                _manual_replacement_worker_preflight(
                    job, worker_token, request,
                )
            _persist_manual_replacement_quarantine(
                job_id, worker_token, request,
            )

        if not device_done:
            if task_id:
                _refresh_task_update(
                    task_id,
                    stage=(
                        "removing_device_account"
                        if replacement_cleanup
                        else "removing_exhausted_account"
                    ),
                )
                _refresh_task_child_update(
                    task_id,
                    child_progress_identity or {},
                    status="running",
                    stage=(
                        "removing_device_account"
                        if replacement_cleanup
                        else "removing_exhausted_account"
                    ),
                    percent=25,
                )
            _cleanup_device_account(job_id, worker_token, request)
            if not _update_cleanup_job(
                job_id,
                worker_token,
                device_delete_confirmed=True,
                local_snapshot_persisted=True,
                stage=(
                    "business_remove_pending"
                    if int(request.get("business_parent_id") or 0) > 0
                    else "device_removed"
                ),
            ):
                raise RuntimeError("cleanup_fenced")
            device_done = True

        with Session(engine) as session:
            job = session.get(DeliveryDeviceExhaustionCleanupModel, str(job_id))
            if not job:
                raise RuntimeError("cleanup_missing")
            business_done = bool(job.business_remove_confirmed)
            device_done = bool(
                job.device_delete_confirmed and job.local_snapshot_persisted
            )
        if int(request.get("business_parent_id") or 0) > 0 and not device_done:
            # This is the hard object-capability boundary: no code path may
            # reach mother remove/revoke until the exact old device credential
            # has a durable absence checkpoint.
            raise RuntimeError("device_delete_unconfirmed")
        if int(request.get("business_parent_id") or 0) > 0 and not business_done:
            business_done = _reconcile_finished_business_remove_checkpoint(
                job_id, worker_token, request,
            )
        if int(request.get("business_parent_id") or 0) > 0 and not business_done:
            if task_id:
                _refresh_task_update(task_id, stage="removing_business_child")
                _refresh_task_child_update(
                    task_id,
                    child_progress_identity or {},
                    status="running",
                    stage="removing_business_child",
                    percent=40,
                )
            _cleanup_business_child(job, worker_token, request)
            if not _update_cleanup_job(
                job_id,
                worker_token,
                business_remove_confirmed=True,
                stage="replenishment_pending",
            ):
                raise RuntimeError("cleanup_fenced")
            business_done = True
        # This cleanup transaction remains cleanup-only.  It records a durable
        # mother-side demand after BUSINESS removal; the refresh coordinator may
        # separately start reconciliation only after this commit has completed.
        demand_id = _complete_cleanup_and_enqueue_replenishment(
            job_id,
            worker_token,
            request,
        )
        if task_id:
            _refresh_task_child_update(
                task_id,
                child_progress_identity or {},
                status="running",
                stage="replenishment_pending",
                percent=95,
            )
        return {
            "kind": "success",
            "resumed": True,
            "replenishment_demand_id": demand_id,
        }
    except Exception as exc:
        # The job and both remote-operation intents remain authoritative.  Never
        # copy an upstream response/header/URL into this credential-free record.
        failure_code = str(exc or "").strip()
        if failure_code == "business_replacement_quota_unavailable":
            resume_at = ""
            rollback_attempt_count: Optional[int] = None
            try:
                with Session(engine) as session:
                    current = session.get(
                        DeliveryDeviceExhaustionCleanupModel,
                        str(job_id),
                    )
                    cooldown = (
                        _cleanup_replacement_cooldown(
                            session,
                            current,
                            request,
                        )
                        if current else None
                    )
                    resume_at = str(
                        (cooldown or {}).get("resume_at") or ""
                    )
                    if current and not any((
                        bool(current.business_remove_confirmed),
                        bool(current.device_delete_confirmed),
                        bool(current.local_snapshot_persisted),
                    )):
                        # The quota raced between the pre-claim check and the
                        # leased worker preflight.  No irreversible boundary
                        # was crossed, so this was a due-time deferral rather
                        # than a cleanup attempt.
                        rollback_attempt_count = max(
                            0, int(current.attempt_count or 0) - 1,
                        )
            except Exception:
                resume_at = ""
            waiting_changes: dict[str, Any] = {
                "state": "waiting",
                "stage": "waiting_cooldown",
                "resume_at": _safe_datetime_value(resume_at),
                "error": "",
                "worker_token": "",
                "lease_expires_at": None,
            }
            if rollback_attempt_count is not None:
                waiting_changes["attempt_count"] = rollback_attempt_count
            _update_cleanup_job(
                job_id,
                worker_token,
                **waiting_changes,
            )
            return {
                "kind": "waiting",
                "resumed": True,
                "stage": "waiting_cooldown",
                "resume_at": _safe_public_datetime(resume_at),
            }
        safe_failure_stage = (
            failure_code
            if failure_code in {
                "business_parent_unsafe",
                "business_parent_session_unavailable",
                "credential_replacement_no_longer_authorized",
                "cleanup_identity_changed",
                "device_binding_changed",
                "device_changed",
                "replacement_candidate_unavailable",
                "seat_type_unknown",
                "remote_absence_unconfirmed",
            }
            else ""
        )
        _update_cleanup_job(
            job_id,
            worker_token,
            state="action_required",
            resume_at=None,
            **({"stage": safe_failure_stage} if safe_failure_stage else {}),
            error=(
                "TEAM replacement cleanup needs retry"
                if replacement_cleanup
                else "Exhausted-account cleanup needs retry"
            ),
            worker_token="",
            lease_expires_at=None,
        )
        return {"kind": "failed", "resumed": True}
    finally:
        _release_cleanup_claims(job_id, worker_token)
        try:
            from api import gpt_business

            gpt_business.purge_released_dead_business_child_for_delivery_cleanup(
                str(job_id),
            )
        except Exception:
            # Remote cleanup response/state remains authoritative.  The mother
            # finalizer records its own credential-free pending marker and is
            # retried again when replenishment/TEAM401 reaches a terminal state.
            pass


def reconcile_pending_delivery_exhaustion_cleanups(
    limit: int = 20,
) -> dict[str, Any]:
    """Resume durable device-only exhaustion cleanups after crashes/failures."""
    bounded = max(1, min(int(limit or 20), 100))
    now = _utcnow()
    with Session(engine) as session:
        due_rows = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel)
            .where(
                DeliveryDeviceExhaustionCleanupModel.state.in_(
                    sorted(_CLEANUP_RECOVERABLE_STATES)
                )
            )
            .where(or_(
                DeliveryDeviceExhaustionCleanupModel.resume_at.is_(None),
                DeliveryDeviceExhaustionCleanupModel.resume_at <= now,
            ))
            .order_by(DeliveryDeviceExhaustionCleanupModel.updated_at)
            .limit(bounded)
        ).all()
        # Older builds persisted the removed 48-hour quota deadline in
        # ``resume_at``. Those rows would never reach the live preflight above,
        # so inspect every future cooldown checkpoint against the authoritative
        # mother field and clear or correct it in place.
        future_cooldown_rows = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel)
            .where(
                DeliveryDeviceExhaustionCleanupModel.state.in_(
                    sorted(_CLEANUP_RECOVERABLE_STATES)
                )
            )
            .where(DeliveryDeviceExhaustionCleanupModel.stage.in_([
                "waiting_cooldown",
                "business_replacement_quota_unavailable",
            ]))
            .where(DeliveryDeviceExhaustionCleanupModel.resume_at > now)
            .order_by(DeliveryDeviceExhaustionCleanupModel.updated_at)
        ).all()
        recovered_rows: list[DeliveryDeviceExhaustionCleanupModel] = []
        for row in future_cooldown_rows:
            try:
                request = _cleanup_request(row)
                live = _cleanup_replacement_cooldown(session, row, request)
            except Exception:
                live = None
            if live is None:
                row.resume_at = None
                row.updated_at = now
                session.add(row)
                recovered_rows.append(row)
                continue
            live_resume_at = _safe_datetime_value(live.get("resume_at"))
            if _aware_cleanup_time(row.resume_at) != live_resume_at:
                row.resume_at = live_resume_at
                row.updated_at = now
                session.add(row)
        session.commit()
        rows = list(due_rows)
        seen_ids = {str(row.id) for row in rows}
        rows.extend(
            row for row in recovered_rows
            if str(row.id) not in seen_ids
        )
        rows.sort(key=lambda row: (
            _aware_cleanup_time(row.updated_at)
            or datetime.min.replace(tzinfo=timezone.utc)
        ))
        rows = rows[:bounded]
        ids = [str(row.id) for row in rows]
    summary: dict[str, Any] = {
        "ok": True,
        "considered": len(ids),
        "resumed": 0,
        "completed": 0,
        "busy": 0,
        "waiting": 0,
        "superseded": 0,
        "failed": 0,
    }
    for job_id in ids:
        result = _run_delivery_exhaustion_cleanup(job_id)
        kind = str(result.get("kind") or "failed")
        if bool(result.get("resumed")):
            summary["resumed"] += 1
        if kind == "success":
            summary["completed"] += 1
        elif kind == "busy":
            summary["busy"] += 1
        elif kind == "waiting":
            summary["waiting"] += 1
        elif kind == "superseded":
            summary["superseded"] += 1
        else:
            summary["failed"] += 1
    return summary


def _process_exhausted_remote(
    task_id: str,
    *,
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    device_epoch: str,
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    task_id, child_progress_identity = _team_child_progress_context(
        task_id,
        child_progress_identity or _business_child_progress_identity(remote),
    )
    remote_id = str(remote.get("remote_id") or "").strip()
    if remote_id:
        with Session(engine) as session:
            pending = session.exec(
                select(DeliveryDeviceExhaustionCleanupModel)
                .where(DeliveryDeviceExhaustionCleanupModel.provider == provider)
                .where(DeliveryDeviceExhaustionCleanupModel.provider_id == int(provider_id))
                .where(DeliveryDeviceExhaustionCleanupModel.remote_id == remote_id)
                .where(DeliveryDeviceExhaustionCleanupModel.state != "completed")
                .order_by(DeliveryDeviceExhaustionCleanupModel.created_at)
            ).all()
        # A mother-first manual replacement deliberately leaves a short-lived
        # remote link after the membership is ended.  Resume its frozen saga
        # instead of reclassifying the released child as an ordinary account.
        if len(pending) == 1:
            result = _run_delivery_exhaustion_cleanup(
                str(pending[0].id),
                task_id=task_id,
                child_progress_identity=child_progress_identity,
            )
            kind = str(result.get("kind") or "failed")
            if kind in {"busy", "superseded"}:
                return {"kind": "skipped"}
            return {"kind": kind if kind in _REFRESH_COUNT_KEYS else "failed"}
        if len(pending) > 1:
            return {"kind": "skipped"}
    mapping = _business_child_mapping(provider, provider_id, remote)
    state = str(mapping.get("state") or "")
    if state in {"ambiguous", "conflict"}:
        # An identity collision is never downgraded to an unmapped deletion.
        return {"kind": "skipped"}
    if state != "mapped":
        mapping = _ordinary_account_mapping(provider, provider_id, remote)
        state = str(mapping.get("state") or "")
    if state in {"ambiguous", "conflict"}:
        return {"kind": "skipped"}
    if not _device_epoch_is_current(provider, provider_id, device_epoch):
        return {"kind": "skipped"}
    if state == "unmapped":
        # No local lifecycle exists to recover.  The immutable monitor snapshot
        # still gives an exact remote id; delete it under the device epoch and
        # require authoritative absence confirmation.
        _refresh_task_update(task_id, stage="removing_exhausted_account")
        internal = _internal_device_or_error(provider, provider_id)
        if provider == "cpa":
            _delete_cpa_remote_exact(
                internal,
                remote,
                before_mutation=lambda: _device_epoch_is_current(
                    provider, provider_id, device_epoch,
                ),
            )
        else:
            _delete_sub2api_remote_exact(
                internal,
                remote,
                before_mutation=lambda: _device_epoch_is_current(
                    provider, provider_id, device_epoch,
                ),
            )
        return {"kind": "success"}
    if state != "mapped":
        return {"kind": "skipped"}
    job = _create_or_get_cleanup_job(
        provider=provider,
        provider_id=provider_id,
        remote=remote,
        mapping=mapping,
        device_epoch=device_epoch,
    )
    result = _run_delivery_exhaustion_cleanup(
        str(job.id),
        task_id=task_id,
        child_progress_identity=child_progress_identity,
    )
    kind = str(result.get("kind") or "failed")
    if kind in {"busy", "superseded"}:
        return {"kind": "skipped"}
    return {"kind": kind if kind in _REFRESH_COUNT_KEYS else "failed"}


def _exhausted_business_parent_id(remote: dict[str, Any]) -> int:
    """Return the exact BUSINESS parent encoded by a monitor snapshot.

    Only an exact mapped lifecycle is eligible for a parent lane.  Ordinary,
    unmapped and ambiguous rows stay in the device-local fallback lane so
    grouping can never promote a weak email match into destructive authority.
    ``_process_exhausted_remote`` still performs the complete live mapping and
    fencing checks before any mutation.
    """
    navigation = (
        remote.get("navigation")
        if isinstance(remote.get("navigation"), dict)
        else {}
    )
    if not (
        str(navigation.get("state") or "") == "mapped"
        and str(navigation.get("target_kind") or "") == "business_child"
    ):
        return 0
    try:
        parent_id = int(navigation.get("business_parent_id") or 0)
        child_id = int(navigation.get("pro_account_id") or 0)
        membership_id = int(navigation.get("membership_id") or 0)
    except (TypeError, ValueError):
        return 0
    return parent_id if min(parent_id, child_id, membership_id) > 0 else 0


def _link_exhausted_child_replenishment(
    task_id: str,
    identity: dict[str, Any],
    *,
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
) -> bool:
    """Link an exact TEAM exhaustion cleanup without changing worker DTOs."""
    remote_id = str(remote.get("remote_id") or "").strip()
    if not remote_id:
        return False
    try:
        with Session(engine) as session:
            jobs = session.exec(
                select(DeliveryDeviceExhaustionCleanupModel)
                .where(DeliveryDeviceExhaustionCleanupModel.provider == provider)
                .where(
                    DeliveryDeviceExhaustionCleanupModel.provider_id
                    == int(provider_id)
                )
                .where(DeliveryDeviceExhaustionCleanupModel.remote_id == remote_id)
                .order_by(DeliveryDeviceExhaustionCleanupModel.created_at.desc())
            ).all()
            job = next((
                item for item in jobs
                if int(item.business_parent_id or 0)
                == int(identity.get("parent_id") or 0)
                and int(item.account_id or 0)
                == int(identity.get("child_id") or 0)
                and int(item.membership_id or 0)
                == int(identity.get("membership_id") or 0)
            ), None)
            if job is None:
                return False
            demand = session.exec(
                select(DeliveryDeviceReplenishmentDemandModel).where(
                    DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                    == str(job.id)
                )
            ).first()
            demand_id = str(demand.id or "") if demand else ""
        _refresh_task_child_link_replenishment(
            task_id,
            identity,
            cleanup_job_id=str(job.id),
            replenishment_demand_id=demand_id,
        )
        if demand_id:
            try:
                from api import gpt_business

                gpt_business.run_or_resume_business_replenishment_for_automation(
                    demand_id,
                )
            except Exception:
                pass
        return True
    except Exception:
        return False


def _process_exhausted_remote_lane(
    task_id: str,
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    indexed_remotes: list[tuple[int, dict[str, Any]]],
    total: int,
) -> list[tuple[int, str]]:
    """Process one mother's exhausted children serially in one worker lane."""
    outcomes: list[tuple[int, str]] = []
    for index, remote in indexed_remotes:
        _refresh_task_log(task_id, f"正在处理账号 {index}/{total}")
        identity = _business_child_progress_identity(remote)
        if identity:
            _refresh_task_child_update(
                task_id,
                identity,
                operation="quota_exhausted_cleanup",
                status="queued",
                stage="waiting_for_slot",
                percent=5,
            )
        try:
            if identity:
                with _team_child_operation_slot(task_id, identity):
                    _refresh_task_child_update(
                        task_id,
                        identity,
                        status="running",
                        stage="preflight",
                        percent=10,
                    )
                    outcome = _process_exhausted_remote(
                        task_id,
                        provider=provider,
                        provider_id=provider_id,
                        remote=remote,
                        device_epoch=device_epoch,
                    )
            else:
                outcome = _process_exhausted_remote(
                    task_id,
                    provider=provider,
                    provider_id=provider_id,
                    remote=remote,
                    device_epoch=device_epoch,
                )
            kind = str(outcome.get("kind") or "failed")
            if kind not in _REFRESH_COUNT_KEYS:
                kind = "failed"
        except Exception:
            # Remote exceptions often embed URLs, headers or bodies.  Only a
            # controlled operator message is retained.
            kind = "failed"
            _refresh_task_log(
                task_id,
                f"账号 {index}/{total} 处理失败，安全恢复记录已保留",
            )
        if identity:
            linked_replenishment = bool(
                kind == "success"
                and _link_exhausted_child_replenishment(
                    task_id,
                    identity,
                    provider=provider,
                    provider_id=provider_id,
                    remote=remote,
                )
            )
            if kind == "success":
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="running" if linked_replenishment else "completed",
                    stage=(
                        "replenishment_pending"
                        if linked_replenishment else "completed"
                    ),
                    percent=40 if linked_replenishment else 100,
                    result=(
                        "replenishment_handoff"
                        if linked_replenishment else "removed"
                    ),
                )
            elif kind == "skipped":
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="skipped",
                    stage="skipped",
                    percent=100,
                    result="skipped",
                )
            else:
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="failed",
                    stage="failed",
                    percent=100,
                    result="failed",
                    error="operation_failed",
                )
        outcomes.append((index, kind))
    return outcomes


def _normalized_delivery_email(value: Any) -> str:
    return str(value or "").strip().casefold()


def _credential_retry_device_key(provider: str, provider_id: int) -> str:
    return f"{str(provider or '').strip().lower()}:{int(provider_id)}"


def _business_child_device_identity_matches(
    *,
    membership: Optional[GptBusinessChildMembershipModel],
    child: Optional[GptProAccountModel],
    policy: Optional[GptBusinessAutomationPolicyModel],
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
) -> bool:
    """Validate one local child lifecycle without contacting any remote API."""
    try:
        parent_id = int(expected.get("parent_id") or 0)
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
        policy_revision = int(expected.get("policy_revision") or 0)
        normalized_provider = str(provider or "").strip().lower()
        target_id = (
            int(getattr(policy, "cpa_target_id", 0) or 0)
            if normalized_provider == "cpa"
            else int(getattr(policy, "sub2api_device_id", 0) or 0)
        )
    except (TypeError, ValueError):
        return False
    return bool(
        min(parent_id, child_id, membership_id, int(provider_id)) > 0
        and normalized_provider in {"cpa", "sub2api"}
        and membership
        and membership.ended_at is None
        and int(membership.id or 0) == membership_id
        and int(membership.business_account_id or 0) == parent_id
        and int(membership.pro_account_id or 0) == child_id
        and _normalized_delivery_email(membership.email)
        == _normalized_delivery_email(expected.get("email"))
        and child
        and int(child.id or 0) == child_id
        and int(child.business_parent_id or 0) == parent_id
        and _normalized_delivery_email(child.email)
        == _normalized_delivery_email(expected.get("email"))
        and policy
        and bool(policy.auto_rotation_enabled)
        and str(policy.delivery_type or "").strip().lower()
        == normalized_provider
        and target_id == int(provider_id)
        and int(policy.revision or 0) == policy_revision
    )


def _mark_business_child_remote_missing(
    *,
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
) -> bool:
    """Publish a confirmed remote absence before attempting any repair.

    The previous linkage identifiers are intentionally retained as audit/fence
    data, but public serializers must stop advertising the child as synced.
    A later exact upload verification is the only path that restores an active
    link.
    """
    normalized_provider = str(provider or "").strip().lower()
    try:
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
    except (TypeError, ValueError):
        return False
    if normalized_provider not in {"cpa", "sub2api"}:
        return False
    try:
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            membership = session.get(
                GptBusinessChildMembershipModel,
                membership_id,
            )
            child = session.get(GptProAccountModel, child_id)
            policy = session.get(
                GptBusinessAutomationPolicyModel,
                int(expected.get("parent_id") or 0),
            )
            if not _business_child_device_identity_matches(
                membership=membership,
                child=child,
                policy=policy,
                provider=normalized_provider,
                provider_id=int(provider_id),
                expected=expected,
            ):
                session.rollback()
                return False
            extra = _json_object(child.extra_json)
            now = _iso_now()
            if normalized_provider == "cpa":
                try:
                    linked_device_id = int(
                        extra.get("cpa_synced_to_id")
                        or extra.get("cpa_device_id")
                        or 0
                    )
                except (TypeError, ValueError):
                    linked_device_id = -1
                if linked_device_id not in {0, int(provider_id)}:
                    session.rollback()
                    return False
                extra.update({
                    "cpa_synced": False,
                    "cpa_remote_missing": True,
                    "cpa_remote_missing_at": now,
                    "cpa_remote_missing_target_id": int(provider_id),
                    "cpa_lifecycle_state": "remote_missing",
                    "cpa_monitor_suppressed": True,
                })
            else:
                try:
                    linked_device_id = int(
                        extra.get("sub2api_device_id") or 0
                    )
                except (TypeError, ValueError):
                    linked_device_id = -1
                if linked_device_id not in {0, int(provider_id)}:
                    session.rollback()
                    return False
                extra.update({
                    "sub2api_remote_missing": True,
                    "sub2api_remote_missing_at": now,
                    "sub2api_remote_missing_device_id": int(provider_id),
                    "sub2api_status": "unlinked",
                })
            child.extra_json = json.dumps(extra, ensure_ascii=False)
            child.updated_at = _utcnow()
            session.add(child)
            session.commit()
            return True
    except Exception:
        return False


def _business_child_credential_retry_backoff(
    *,
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Return one active credential-only retry window for this child/device."""
    try:
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
        with Session(engine) as session:
            membership = session.get(
                GptBusinessChildMembershipModel,
                membership_id,
            )
            child = session.get(GptProAccountModel, child_id)
            policy = session.get(
                GptBusinessAutomationPolicyModel,
                int(expected.get("parent_id") or 0),
            )
            if not _business_child_device_identity_matches(
                membership=membership,
                child=child,
                policy=policy,
                provider=provider,
                provider_id=int(provider_id),
                expected=expected,
            ):
                return None
            extra = _json_object(child.extra_json)
        entries = extra.get(_CREDENTIAL_RETRY_EXTRA_KEY)
        if not isinstance(entries, dict):
            return None
        raw = entries.get(_credential_retry_device_key(provider, provider_id))
        if not isinstance(raw, dict):
            return None
        retry_at = _safe_datetime_value(raw.get("retry_at"))
        if not (
            retry_at
            and retry_at > _utcnow()
            and int(raw.get("parent_id") or 0)
            == int(expected.get("parent_id") or 0)
            and int(raw.get("membership_id") or 0) == membership_id
        ):
            return None
        return {
            "retry_at": retry_at.isoformat(),
            "error_code": _safe_child_failure_code(
                raw.get("error_code"),
                default="oauth_failed",
            ),
        }
    except Exception:
        return None


def _persist_business_child_credential_retry_backoff(
    *,
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
    error_code: str,
) -> str:
    """Persist a bounded OAuth retry window, separate from mother cooldown."""
    try:
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
        safe_error = _safe_child_failure_code(
            error_code,
            default="oauth_failed",
        )
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            membership = session.get(
                GptBusinessChildMembershipModel,
                membership_id,
            )
            child = session.get(GptProAccountModel, child_id)
            policy = session.get(
                GptBusinessAutomationPolicyModel,
                int(expected.get("parent_id") or 0),
            )
            if not _business_child_device_identity_matches(
                membership=membership,
                child=child,
                policy=policy,
                provider=provider,
                provider_id=int(provider_id),
                expected=expected,
            ):
                session.rollback()
                return ""
            now = _utcnow()
            retry_at = now + timedelta(
                minutes=_CREDENTIAL_RETRY_BACKOFF_MINUTES,
            )
            extra = _json_object(child.extra_json)
            entries = extra.get(_CREDENTIAL_RETRY_EXTRA_KEY)
            entries = dict(entries) if isinstance(entries, dict) else {}
            entries[_credential_retry_device_key(provider, provider_id)] = {
                "provider": str(provider),
                "device_id": int(provider_id),
                "parent_id": int(expected.get("parent_id") or 0),
                "membership_id": membership_id,
                "failed_at": now.isoformat(),
                "retry_at": retry_at.isoformat(),
                "error_code": safe_error,
            }
            # One child has one active delivery binding, but bound this audit
            # map defensively so historical device switches cannot grow it.
            if len(entries) > 4:
                entries = dict(list(entries.items())[-4:])
            extra[_CREDENTIAL_RETRY_EXTRA_KEY] = entries
            child.extra_json = json.dumps(extra, ensure_ascii=False)
            child.updated_at = now
            session.add(child)
            session.commit()
            return retry_at.isoformat()
    except Exception:
        return ""


def _clear_business_child_delivery_repair_state(
    *,
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
) -> bool:
    """Clear stale/backoff markers only after exact remote verification."""
    try:
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            membership = session.get(
                GptBusinessChildMembershipModel,
                membership_id,
            )
            child = session.get(GptProAccountModel, child_id)
            policy = session.get(
                GptBusinessAutomationPolicyModel,
                int(expected.get("parent_id") or 0),
            )
            if not _business_child_device_identity_matches(
                membership=membership,
                child=child,
                policy=policy,
                provider=provider,
                provider_id=int(provider_id),
                expected=expected,
            ):
                session.rollback()
                return False
            extra = _json_object(child.extra_json)
            entries = extra.get(_CREDENTIAL_RETRY_EXTRA_KEY)
            if isinstance(entries, dict):
                entries = dict(entries)
                entries.pop(
                    _credential_retry_device_key(provider, provider_id),
                    None,
                )
                if entries:
                    extra[_CREDENTIAL_RETRY_EXTRA_KEY] = entries
                else:
                    extra.pop(_CREDENTIAL_RETRY_EXTRA_KEY, None)
            if str(provider).strip().lower() == "cpa":
                try:
                    linked_device_id = int(
                        extra.get("cpa_synced_to_id")
                        or extra.get("cpa_device_id")
                        or 0
                    )
                except (TypeError, ValueError):
                    linked_device_id = 0
                if (
                    linked_device_id == int(provider_id)
                    and str(extra.get("cpa_auth_name") or "").strip()
                ):
                    extra["cpa_synced"] = True
                    extra["cpa_lifecycle_state"] = "active"
                    extra["cpa_monitor_suppressed"] = False
                for key in (
                    "cpa_remote_missing",
                    "cpa_remote_missing_at",
                    "cpa_remote_missing_target_id",
                ):
                    extra.pop(key, None)
            else:
                try:
                    linked_device_id = int(
                        extra.get("sub2api_device_id") or 0
                    )
                except (TypeError, ValueError):
                    linked_device_id = 0
                if (
                    linked_device_id == int(provider_id)
                    and str(
                        extra.get("sub2api_remote_account_id") or ""
                    ).strip()
                ):
                    extra["sub2api_status"] = "linked"
                for key in (
                    "sub2api_remote_missing",
                    "sub2api_remote_missing_at",
                    "sub2api_remote_missing_device_id",
                ):
                    extra.pop(key, None)
            child.extra_json = json.dumps(extra, ensure_ascii=False)
            child.updated_at = _utcnow()
            session.add(child)
            session.commit()
            return True
    except Exception:
        return False


def _business_device_reconcile_inventory(
    provider: str,
    provider_id: int,
    remote_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one credential-free expected-vs-actual BUSINESS child snapshot.

    A remote row is present only when the monitor resolved it to the exact
    active parent/child/membership lifecycle.  A same-email row with an
    ambiguous target blocks auto-upload instead of being treated as absent;
    this prevents refresh from creating duplicate credentials.
    """
    from api import gpt_business

    normalized_provider = str(provider or "").strip().lower()
    normalized_device_id = int(provider_id)
    with Session(engine) as session:
        policy_query = select(GptBusinessAutomationPolicyModel).where(
            GptBusinessAutomationPolicyModel.auto_rotation_enabled == True  # noqa: E712
        )
        if normalized_provider == "cpa":
            policy_query = policy_query.where(
                GptBusinessAutomationPolicyModel.delivery_type == "cpa",
                GptBusinessAutomationPolicyModel.cpa_target_id
                == normalized_device_id,
            )
        else:
            policy_query = policy_query.where(
                GptBusinessAutomationPolicyModel.delivery_type == "sub2api",
                GptBusinessAutomationPolicyModel.sub2api_device_id
                == normalized_device_id,
            )
        policies = list(session.exec(policy_query).all())
        parent_ids = sorted({
            int(row.business_account_id)
            for row in policies
            if int(row.business_account_id or 0) > 0
        })
        parents = {
            int(row.id or 0): row
            for row in session.exec(
                select(GptBusinessAccountModel).where(
                    GptBusinessAccountModel.id.in_(parent_ids)  # type: ignore[union-attr]
                )
            ).all()
        } if parent_ids else {}
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.business_account_id.in_(
                    parent_ids
                ),  # type: ignore[union-attr]
                GptBusinessChildMembershipModel.ended_at.is_(None),  # type: ignore[union-attr]
            )
        ).all()) if parent_ids else []
        child_ids = sorted({
            int(row.pro_account_id)
            for row in memberships
            if int(row.pro_account_id or 0) > 0
        })
        children = {
            int(row.id or 0): row
            for row in session.exec(
                select(GptProAccountModel).where(
                    GptProAccountModel.id.in_(child_ids)  # type: ignore[union-attr]
                )
            ).all()
        } if child_ids else {}
        parent_refund_blocked = {
            parent_id: gpt_business._business_parent_refund_blocks_replacement(
                parent, session,
            )
            for parent_id, parent in parents.items()
        }

    policy_by_parent = {
        int(row.business_account_id): row for row in policies
    }
    memberships_by_parent: dict[int, list[GptBusinessChildMembershipModel]] = {
        parent_id: [] for parent_id in parent_ids
    }
    for membership in memberships:
        memberships_by_parent.setdefault(
            int(membership.business_account_id), [],
        ).append(membership)

    exact_remote_lifecycles: dict[
        tuple[int, int, int], list[dict[str, Any]]
    ] = {}
    remote_by_email: dict[str, list[dict[str, Any]]] = {}
    for remote in remote_items:
        if not isinstance(remote, dict):
            continue
        email = _normalized_delivery_email(remote.get("email"))
        if email:
            remote_by_email.setdefault(email, []).append(remote)
        if bool(remote.get("disabled")):
            continue
        navigation = (
            remote.get("navigation")
            if isinstance(remote.get("navigation"), dict)
            else {}
        )
        if (
            str(navigation.get("state") or "") == "mapped"
            and str(navigation.get("target_kind") or "")
            == "business_child"
        ):
            try:
                lifecycle = (
                    int(navigation.get("business_parent_id") or 0),
                    int(navigation.get("pro_account_id") or 0),
                    int(navigation.get("membership_id") or 0),
                )
            except (TypeError, ValueError):
                lifecycle = (0, 0, 0)
            if all(value > 0 for value in lifecycle):
                exact_remote_lifecycles.setdefault(lifecycle, []).append(remote)

    expected: list[dict[str, Any]] = []
    present: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    invalid_replacements: list[dict[str, Any]] = []
    invalid_replacement_blockers: list[dict[str, Any]] = []
    missing_deactivated: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    pending = 0
    unmanaged = 0
    for parent_id in parent_ids:
        parent = parents.get(parent_id)
        policy = policy_by_parent[parent_id]
        parent_blocker = (
            "business_parent_missing"
            if parent is None
            else "business_parent_disabled"
            if not bool(parent.enabled)
            else "business_parent_dangerous"
            if bool(parent.dangerous)
            else "business_parent_refunded"
            if bool(parent_refund_blocked.get(parent_id))
            else ""
        )
        parent_unsafe = bool(parent_blocker)
        for membership in memberships_by_parent.get(parent_id, []):
            child_id = int(membership.pro_account_id or 0)
            child = children.get(child_id)
            email = _normalized_delivery_email(membership.email)
            remote_user_id = str(membership.remote_user_id or "").strip()
            remote_invite_id = str(
                membership.remote_invite_id or ""
            ).strip()
            if child_id <= 0 or child is None:
                unmanaged += 1
                continue
            if (
                int(child.business_parent_id or 0) != parent_id
                or _normalized_delivery_email(child.email) != email
            ):
                conflicts.append({
                    "parent_id": parent_id,
                    "membership_id": int(membership.id or 0),
                    "child_id": child_id,
                    "reason": "local_identity_conflict",
                })
                continue
            # A pool child with an exact remote invitation is already owned by
            # this mother and is precisely the lifecycle which the managed
            # child RT capability can finish: accept/join the workspace, then
            # acquire OAuth.  Treating every row without ``remote_user_id`` as
            # an opaque pending row made device refresh silently ignore a
            # freshly invited child forever.  Only a purely local row (neither
            # member nor invitation evidence) remains non-actionable.
            if not remote_user_id and not remote_invite_id:
                pending += 1
                continue
            item = {
                "parent_id": parent_id,
                "membership_id": int(membership.id or 0),
                "child_id": child_id,
                "email": email,
                "remote_user_id": remote_user_id,
                "remote_invite_id": remote_invite_id,
                "membership_state": (
                    "member" if remote_user_id else "invited"
                ),
                "has_codex_rt": bool(
                    str(child.codex_refresh_token or "").strip()
                ),
                "seat_type": str(membership.seat_type or ""),
                "policy_revision": int(policy.revision or 0),
                "eligible": bool(
                    not parent_unsafe
                    and bool(child.enabled)
                    and not bool(child.dangerous)
                    and not bool(child.policy_warning)
                ),
            }
            expected.append(item)
            lifecycle = (parent_id, child_id, int(membership.id or 0))
            lifecycle_rows = list(exact_remote_lifecycles.get(lifecycle) or [])
            lifecycle_count = len(lifecycle_rows)
            if lifecycle_count == 1:
                remote = lifecycle_rows[0]
                if bool(remote.get("credential_repair_required")):
                    navigation = (
                        remote.get("navigation")
                        if isinstance(remote.get("navigation"), dict)
                        else {}
                    )
                    if str(navigation.get("match_basis") or "") != "device_link":
                        conflicts.append({
                            **item,
                            "reason": "remote_identity_conflict",
                        })
                    elif (
                        provider == "cpa"
                        and bool(child.dangerous)
                        and int(remote.get("credential_repair_status") or 0) == 401
                    ):
                        replacement = {
                            **item,
                            "child_dangerous": True,
                            "invalid_reason": "access_deactivated",
                            "dangerous_detected_at": (
                                child.dangerous_detected_at.isoformat()
                                if child.dangerous_detected_at
                                else ""
                            ),
                            "remote_id": str(remote.get("remote_id") or ""),
                            "credential_repair_status": int(
                                remote.get("credential_repair_status") or 0
                            ),
                            "credential_repair_code": str(
                                remote.get("credential_repair_code") or ""
                            )[:96],
                            # The monitor DTO is already credential-free.  It is
                            # retained only in memory so the worker can re-resolve
                            # the immutable device link before creating a job.
                            "remote": dict(remote),
                        }
                        if parent_blocker:
                            invalid_replacement_blockers.append({
                                **{
                                    key: replacement[key]
                                    for key in (
                                        "parent_id", "membership_id", "child_id",
                                    )
                                },
                                "reason": parent_blocker,
                            })
                        elif str(item.get("seat_type") or "") not in {
                            "default", "prolite",
                        }:
                            invalid_replacement_blockers.append({
                                **{
                                    key: replacement[key]
                                    for key in (
                                        "parent_id", "membership_id", "child_id",
                                    )
                                },
                                "reason": "seat_type_unknown",
                            })
                        else:
                            invalid_replacements.append(replacement)
                    elif item["eligible"]:
                        repairs.append({
                            **item,
                            "remote_id": str(remote.get("remote_id") or ""),
                            "credential_repair_status": int(
                                remote.get("credential_repair_status") or 0
                            ),
                            "credential_repair_code": str(
                                remote.get("credential_repair_code") or ""
                            )[:96],
                            # Credential-free monitor DTO, retained only for
                            # exact re-resolution if OAuth proves this child is
                            # deactivated and the same refresh must upgrade to
                            # a durable mother-first replacement.
                            "remote": dict(remote),
                        })
                    else:
                        conflicts.append({
                            **item,
                            "reason": "child_not_eligible",
                        })
                    continue
                present.append(item)
                continue
            if lifecycle_count > 1:
                conflicts.append({
                    **item,
                    "reason": "duplicate_remote_identity",
                })
                continue
            same_email = remote_by_email.get(email, [])
            if same_email:
                # The monitor saw this email but could not prove that it is the
                # exact active lifecycle.  Never POST another credential beside
                # an ambiguous/conflicting remote identity.
                conflicts.append({**item, "reason": "remote_identity_conflict"})
                continue
            normalized_seat_type = str(
                item.get("seat_type") or ""
            ).strip().lower()
            if (
                not parent_unsafe
                and bool(child.enabled)
                and bool(child.dangerous)
                and normalized_seat_type in {"default", "prolite"}
            ):
                # A complete device inventory found no row for this exact
                # active lifecycle, while the authoritative plan account is
                # already marked dead.  Do not attempt to upload its stale RT.
                # The worker performs an independent absence read and all
                # mother/policy/membership fences before creating the durable
                # cleanup + same-seat replenishment handoff.
                missing_deactivated.append({
                    **item,
                    "child_dangerous": True,
                    "invalid_reason": "access_deactivated",
                    "dangerous_detected_at": (
                        child.dangerous_detected_at.isoformat()
                        if child.dangerous_detected_at else ""
                    ),
                })
            elif item["eligible"]:
                missing.append(item)
            else:
                conflicts.append({**item, "reason": "child_not_eligible"})

    empty_parent_ids = [
        parent_id for parent_id in parent_ids
        if not memberships_by_parent.get(parent_id)
        and parents.get(parent_id) is not None
        and bool(parents[parent_id].enabled)
        and not bool(parents[parent_id].dangerous)
        and not bool(parent_refund_blocked.get(parent_id))
    ]
    return {
        "bound_parent_ids": parent_ids,
        "active_memberships": len(memberships),
        "expected": expected,
        "present": present,
        "repairs": repairs,
        "invalid_replacements": invalid_replacements,
        "invalid_replacement_blockers": invalid_replacement_blockers,
        "missing_deactivated": missing_deactivated,
        "missing": missing,
        "conflicts": conflicts,
        "pending": pending,
        "unmanaged": unmanaged,
        "empty_parent_ids": empty_parent_ids,
    }


def _business_child_delivery_guard(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Fence every OAuth/upload phase to the exact current device binding."""
    from api import gpt_business

    if not _device_epoch_is_current(provider, provider_id, device_epoch):
        raise HTTPException(409, "设备配置在凭证对账期间发生变化")
    parent_id = int(expected["parent_id"])
    membership_id = int(expected["membership_id"])
    child_id = int(expected["child_id"])
    with Session(engine) as session:
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        membership = session.get(
            GptBusinessChildMembershipModel, membership_id,
        )
        child = session.get(GptProAccountModel, child_id)
        parent = session.get(GptBusinessAccountModel, parent_id)
        parent_refund_blocked = bool(
            parent
            and gpt_business._business_parent_refund_blocks_replacement(
                parent, session,
            )
        )
    current_target = 0
    current_provider = str(getattr(policy, "delivery_type", "") or "")
    if current_provider == "cpa":
        current_target = int(getattr(policy, "cpa_target_id", 0) or 0)
    elif current_provider == "sub2api":
        current_target = int(
            getattr(policy, "sub2api_device_id", 0) or 0
        )
    child_extra = _json_object(getattr(child, "extra_json", "")) if child else {}
    expected_remote_user_id = str(
        expected.get("remote_user_id") or ""
    ).strip()
    expected_remote_invite_id = str(
        expected.get("remote_invite_id") or ""
    ).strip()
    current_remote_user_id = str(
        getattr(membership, "remote_user_id", "") or ""
    ).strip()
    current_remote_invite_id = str(
        getattr(membership, "remote_invite_id", "") or ""
    ).strip()
    # A device task may start while the exact pool membership is still a
    # pending invitation.  The child RT capability is allowed to turn that
    # *same membership row* into a confirmed member while the task is running.
    # No other identity transition is accepted.
    remote_membership_matches = bool(
        (
            expected_remote_user_id
            and current_remote_user_id == expected_remote_user_id
        )
        or (
            not expected_remote_user_id
            and expected_remote_invite_id
            and (
                current_remote_user_id
                or current_remote_invite_id == expected_remote_invite_id
            )
        )
    )
    expected_remote_id = str(expected.get("remote_id") or "").strip()
    exact_repair_link = True
    if expected_remote_id and current_provider == "cpa":
        try:
            repair_link_device = int(
                child_extra.get("cpa_synced_to_id")
                or child_extra.get("cpa_device_id")
                or 0
            )
        except (TypeError, ValueError):
            repair_link_device = 0
        exact_repair_link = bool(
            child_extra.get("cpa_synced")
            and repair_link_device == int(provider_id)
            and str(child_extra.get("cpa_auth_name") or "").strip()
            == expected_remote_id
        )
    elif expected_remote_id and current_provider == "sub2api":
        try:
            repair_link_device = int(
                child_extra.get("sub2api_device_id") or 0
            )
        except (TypeError, ValueError):
            repair_link_device = 0
        active_repair_link = bool(
            repair_link_device == int(provider_id)
            and str(
                child_extra.get("sub2api_remote_account_id") or ""
            ).strip() == expected_remote_id
        )
        removed = child_extra.get("sub2api_last_removed")
        try:
            removed_device_id = int(
                removed.get("device_id") or 0
            ) if isinstance(removed, dict) else 0
        except (TypeError, ValueError):
            removed_device_id = 0
        deleted_repair_link = bool(
            isinstance(removed, dict)
            and removed_device_id == int(provider_id)
            and str(removed.get("remote_account_id") or "").strip()
            == expected_remote_id
            and str(removed.get("reason") or "")
            == "credential_401_repair"
            and removed.get("remote_deleted") is True
        )
        exact_repair_link = active_repair_link or deleted_repair_link
    if not (
        policy
        and bool(policy.auto_rotation_enabled)
        and current_provider == str(provider)
        and current_target == int(provider_id)
        and int(policy.revision or 0)
        == int(expected.get("policy_revision") or 0)
        and parent
        and bool(parent.enabled)
        and not bool(parent.dangerous)
        and not parent_refund_blocked
        and membership
        and membership.ended_at is None
        and int(membership.business_account_id or 0) == parent_id
        and int(membership.pro_account_id or 0) == child_id
        and remote_membership_matches
        and _normalized_delivery_email(membership.email)
        == str(expected.get("email") or "")
        and child
        and int(child.business_parent_id or 0) == parent_id
        and _normalized_delivery_email(child.email)
        == str(expected.get("email") or "")
        and bool(child.enabled)
        and not bool(child.dangerous)
        and not bool(child.policy_warning)
        and exact_repair_link
    ):
        raise HTTPException(409, "母号绑定或子号归属在凭证对账期间发生变化")
    return {
        "provider": str(provider),
        "device_id": int(provider_id),
        "parent_id": parent_id,
        "child_id": child_id,
    }


def _sync_missing_business_child(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    task_id, progress_identity = _team_child_progress_context(
        task_id,
        child_progress_identity or _business_child_progress_identity(expected),
    )
    guard = lambda: _business_child_delivery_guard(
        provider=provider,
        provider_id=provider_id,
        device_epoch=device_epoch,
        expected=expected,
    )
    lease_token = ""
    oauth_started = False
    oauth_completed = False

    def _result(
        ok: bool,
        *,
        error_code: str = "",
        retry_at: str = "",
        oauth_refreshed: bool = False,
    ) -> dict[str, Any]:
        return {
            "ok": bool(ok),
            "parent_id": int(expected["parent_id"]),
            "child_id": int(expected["child_id"]),
            "membership_id": int(expected["membership_id"]),
            "error_code": str(error_code or ""),
            "retry_at": _safe_public_datetime(retry_at),
            "oauth_refreshed": bool(oauth_refreshed),
        }

    def _upload(operation_token: str) -> dict[str, Any]:
        guard()
        if task_id:
            _refresh_task_child_update(
                task_id,
                progress_identity,
                status="running",
                stage="uploading_credential",
                percent=80 if oauth_completed else 45,
                error="",
            )
        if provider == "cpa":
            from api.gpt_plan_operations import sync_account_to_cpa

            uploaded = sync_account_to_cpa(
                int(expected["child_id"]),
                int(provider_id),
                expected_business_parent_id=int(expected["parent_id"]),
                operation_token=str(operation_token or ""),
                delivery_guard=guard,
                allow_credential_reauth=False,
            )
        else:
            from api.gpt_plan_operations import sync_account_to_sub2api

            uploaded = sync_account_to_sub2api(
                int(expected["child_id"]),
                int(provider_id),
                expected_business_parent_id=int(expected["parent_id"]),
                operation_token=str(operation_token or ""),
                delivery_guard=guard,
                allow_credential_reauth=False,
            )
        guard()
        if not bool(uploaded.get("ok")):
            raise _SafeChildOperationError(_safe_child_failure_code(
                uploaded.get("error_code"),
                uploaded.get("error"),
                uploaded.get("message"),
                default="upload_failed",
            ))
        return uploaded

    active_backoff = _business_child_credential_retry_backoff(
        provider=provider,
        provider_id=int(provider_id),
        expected=expected,
    )
    if active_backoff:
        return _result(
            False,
            error_code="credential_retry_cooldown",
            retry_at=str(active_backoff.get("retry_at") or ""),
        )

    try:
        from api.gpt_plan_operations import (
            _claim_gpt_pro_account_operation,
            _release_gpt_pro_account_operation,
        )

        lease_token = _claim_gpt_pro_account_operation(
            int(expected["child_id"]),
            "delivery_missing_credential_oauth",
            ttl_hours=1,
            allow_managed_business_child=True,
        )
        # Inventory owns a fresh DB snapshot.  When it already proves that the
        # child has no RT, compose the child RT capability first instead of
        # attempting an upload merely to manufacture a 401.  Apart from making
        # the object boundary explicit, this also gives the refresh UI the
        # correct visible order: 获取 RT -> 上传设备 -> 回查。
        known_rt_missing = expected.get("has_codex_rt") is False
        if known_rt_missing:
            first_error = "token_invalidated"
        else:
            try:
                _upload(lease_token)
                return _result(True)
            except Exception as first_exc:
                first_error = (
                    first_exc.code
                    if isinstance(first_exc, _SafeChildOperationError)
                    else _safe_child_failure_code(
                        getattr(first_exc, "detail", ""),
                        str(first_exc),
                        f"http_{int(getattr(first_exc, 'status_code', 0) or 0)}",
                        default="upload_failed",
                    )
                )
                if first_error not in {
                    "token_invalidated", "credential_unauthorized",
                }:
                    return _result(False, error_code=first_error)

        # ``token_invalidated`` is raised while the sync primitive is still in
        # its OAuth-refresh preflight, before it creates a durable device-write
        # intent.  If a rolling recovery removed our caller-owned lease in that
        # narrow gap, rebuild it once under an atomic no-intent fence.  Never do
        # this for a generic 401: that can be a post-upload health probe, where
        # repeating the operation without compensation would be unsafe.
        if first_error == "token_invalidated":
            from api.gpt_plan_operations import (
                _gpt_pro_account_operation_token_is_current,
                _reclaim_gpt_pro_account_operation_before_remote_write,
            )

            if not _gpt_pro_account_operation_token_is_current(
                int(expected["child_id"]), lease_token,
            ):
                try:
                    guard()
                    lease_token = (
                        _reclaim_gpt_pro_account_operation_before_remote_write(
                            int(expected["child_id"]),
                            "delivery_missing_credential_oauth",
                            lease_token,
                            provider=provider,
                        )
                    )
                except Exception as reclaim_exc:
                    reclaim_error = _safe_child_failure_code(
                        getattr(reclaim_exc, "detail", ""),
                        str(reclaim_exc),
                        default="lease_lost",
                    )
                    return _result(False, error_code=reclaim_error)

        if task_id:
            _refresh_task_child_update(
                task_id,
                progress_identity,
                status="running",
                stage="acquiring_oauth",
                percent=55,
                error="",
            )

        def _oauth_started() -> None:
            nonlocal oauth_started
            oauth_started = True

        try:
            _wait_for_business_child_credential_oauth(
                expected=expected,
                guard=guard,
                operation_token=lease_token,
                on_started=_oauth_started,
            )
            oauth_completed = True
        except Exception as oauth_exc:
            error_code = (
                oauth_exc.code
                if isinstance(oauth_exc, _SafeChildOperationError)
                else _safe_child_failure_code(
                    getattr(oauth_exc, "detail", ""),
                    str(oauth_exc),
                    default="oauth_failed",
                )
            )
            if error_code == "account_deactivated":
                if not _mark_exact_business_child_deactivated(
                    expected,
                    operation_token=lease_token,
                ):
                    error_code = "lease_lost"
                return _result(False, error_code=error_code)
            retry_at = ""
            if oauth_started:
                # Once a managed OAuth task has actually started, every
                # non-deactivation terminal result gets the same child/device
                # retry window.  This includes a lease handoff: the old OAuth
                # worker may still be settling, so the next device refresh must
                # not immediately open another browser for the same child.
                retry_at = _persist_business_child_credential_retry_backoff(
                    provider=provider,
                    provider_id=int(provider_id),
                    expected=expected,
                    error_code=error_code,
                )
            return _result(
                False,
                error_code=(
                    "credential_retry_cooldown" if retry_at else error_code
                ),
                retry_at=retry_at,
            )

        try:
            _upload(lease_token)
        except Exception as upload_exc:
            error_code = (
                upload_exc.code
                if isinstance(upload_exc, _SafeChildOperationError)
                else _safe_child_failure_code(
                    getattr(upload_exc, "detail", ""),
                    str(upload_exc),
                    default="upload_failed",
                )
            )
            # OAuth has completed in this branch.  Any upload/fence failure is
            # therefore a credential-repair failure for this exact child and
            # device, not permission to restart OAuth/upload again in the same
            # refresh.  Persisting the independent ten-minute backoff also
            # lets an uncertain remote write settle before the next attempt.
            retry_at = _persist_business_child_credential_retry_backoff(
                provider=provider,
                provider_id=int(provider_id),
                expected=expected,
                error_code=error_code,
            )
            return _result(
                False,
                error_code=(
                    "credential_retry_cooldown" if retry_at else error_code
                ),
                retry_at=retry_at,
                oauth_refreshed=True,
            )
        return _result(True, oauth_refreshed=True)
    except Exception as exc:
        error_code = (
            exc.code
            if isinstance(exc, _SafeChildOperationError)
            else _safe_child_failure_code(
                getattr(exc, "detail", ""),
                str(exc),
                default="upload_failed",
            )
        )
        return _result(False, error_code=error_code or "upload_failed")
    finally:
        if lease_token:
            try:
                _release_gpt_pro_account_operation(
                    int(expected["child_id"]),
                    lease_token,
                )
            except Exception:
                pass


def _missing_deactivated_cleanup_mapping(
    provider: str,
    provider_id: int,
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Snapshot the exact dead lifecycle and any stale local device link."""
    from api import gpt_business

    parent_id = int(expected.get("parent_id") or 0)
    child_id = int(expected.get("child_id") or 0)
    membership_id = int(expected.get("membership_id") or 0)
    email = _normalized_delivery_email(expected.get("email"))
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        child = session.get(GptProAccountModel, child_id)
        membership = session.get(
            GptBusinessChildMembershipModel,
            membership_id,
        )
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        binding = (
            gpt_business._business_initial_fill_binding(policy)
            if policy else {}
        )
        if not (
            parent
            and bool(parent.enabled)
            and not bool(parent.dangerous)
            and child
            and bool(child.enabled)
            and bool(child.dangerous)
            and int(child.business_parent_id or 0) == parent_id
            and _normalized_delivery_email(child.email) == email
            and membership
            and membership.ended_at is None
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == child_id
            and _normalized_delivery_email(membership.email) == email
            and str(membership.seat_type or "").strip().lower()
            in {"default", "prolite"}
            and policy
            and bool(policy.auto_rotation_enabled)
            and int(policy.revision or 0)
            == int(expected.get("policy_revision") or 0)
            and str(binding.get("delivery_type") or "") == provider
            and int(binding.get("target_id") or 0) == int(provider_id)
        ):
            raise RuntimeError("cleanup_identity_changed")
        extra = _json_object(child.extra_json)
        if provider == "cpa":
            try:
                linked_device_id = int(
                    extra.get("cpa_synced_to_id")
                    or extra.get("cpa_device_id")
                    or 0
                )
            except (TypeError, ValueError):
                linked_device_id = -1
            linked_remote_id = str(extra.get("cpa_auth_name") or "").strip()
            link_epoch = str(extra.get("cpa_synced_at") or "").strip()
        elif provider == "sub2api":
            try:
                linked_device_id = int(extra.get("sub2api_device_id") or 0)
            except (TypeError, ValueError):
                linked_device_id = -1
            linked_remote_id = str(
                extra.get("sub2api_remote_account_id") or ""
            ).strip()
            link_epoch = str(extra.get("sub2api_synced_at") or "").strip()
        else:
            raise RuntimeError("cleanup_identity_changed")
        if linked_device_id not in {0, int(provider_id)}:
            raise RuntimeError("cleanup_identity_changed")
        return {
            **expected,
            "account_id": child_id,
            "parent_id": parent_id,
            "child_id": child_id,
            "membership_id": membership_id,
            "email": email,
            "seat_type": str(membership.seat_type or "").strip().lower(),
            "target_kind": (
                "member" if str(membership.remote_user_id or "").strip()
                else "invite"
            ),
            "remote_user_id": str(membership.remote_user_id or ""),
            "remote_invite_id": str(membership.remote_invite_id or ""),
            "policy_revision": int(policy.revision or 0),
            "child_dangerous": True,
            "invalid_reason": "access_deactivated",
            "missing_remote_confirmed": True,
            "linked_remote_id": linked_remote_id,
            "link_epoch": link_epoch,
            "dangerous_detected_at": (
                child.dangerous_detected_at.isoformat()
                if child.dangerous_detected_at else ""
            ),
        }


def _replace_deactivated_missing_business_child(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Enter the durable mother replacement for one dead, absent child.

    The caller's inventory is only a hint.  Before the first destructive
    mother operation this helper re-resolves the authoritative plan account,
    active membership, typed seat and exact device policy, then performs a
    second complete device read proving that the email, persisted remote id
    and parent/child/membership lifecycle are all absent.  The existing
    cleanup/replenishment state machine owns remove, invitation, RT and upload.
    """
    task_id, progress_identity = _team_child_progress_context(
        task_id,
        child_progress_identity or _business_child_progress_identity(expected),
    )
    try:
        mapping = _missing_deactivated_cleanup_mapping(
            provider,
            int(provider_id),
            expected,
        )
        absence_request = {
            "email": mapping["email"],
            "linked_remote_id": mapping.get("linked_remote_id") or "",
            "business_parent_id": mapping["parent_id"],
            "account_id": mapping["child_id"],
            "membership_id": mapping["membership_id"],
        }
        _confirm_missing_business_child_remote_absent(
            provider,
            int(provider_id),
            device_epoch,
            absence_request,
        )
        synthetic_basis = json.dumps({
            "provider": provider,
            "provider_id": int(provider_id),
            "parent_id": int(mapping["parent_id"]),
            "child_id": int(mapping["child_id"]),
            "membership_id": int(mapping["membership_id"]),
            "email": str(mapping["email"]),
        }, sort_keys=True, separators=(",", ":"))
        synthetic_id = "missing-business-" + hashlib.sha256(
            synthetic_basis.encode("utf-8"),
        ).hexdigest()[:32]
        remote = {
            "remote_id": synthetic_id,
            "name": synthetic_id,
            "email": str(mapping["email"]),
            "credential_missing": True,
        }
        job = _create_or_get_cleanup_job(
            provider=provider,
            provider_id=int(provider_id),
            remote=remote,
            mapping=mapping,
            device_epoch=device_epoch,
            trigger_kind="credential_missing_deactivated",
        )
        result = _run_delivery_exhaustion_cleanup(
            str(job.id),
            task_id=task_id,
            child_progress_identity=progress_identity,
        )
        kind = str(result.get("kind") or "failed")
        demand_id = str(result.get("replenishment_demand_id") or "").strip()
        with Session(engine) as session:
            current = session.get(
                DeliveryDeviceExhaustionCleanupModel,
                str(job.id),
            )
            stage = str(current.stage or "") if current else ""
            if not demand_id:
                demand = session.exec(
                    select(DeliveryDeviceReplenishmentDemandModel).where(
                        DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                        == str(job.id)
                    )
                ).first()
                demand_id = str(demand.id or "") if demand else ""
        if kind == "success" and demand_id:
            try:
                from api import gpt_business

                gpt_business.run_or_resume_business_replenishment_for_automation(
                    demand_id,
                )
            except Exception:
                pass
        return {
            "ok": kind == "success" and bool(demand_id),
            "kind": kind if kind != "success" or demand_id else "failed",
            "cleanup_job_id": str(job.id),
            "replenishment_demand_id": demand_id,
            "stage": stage,
            "error_code": (
                "" if kind != "success" or demand_id
                else "replenishment_missing"
            ),
            "upgraded_to_replacement": True,
        }
    except Exception as exc:
        closed = str(exc or "").strip()
        return {
            "ok": False,
            "kind": "failed",
            "error_code": (
                "remote_absence_unconfirmed"
                if closed == "remote_absence_unconfirmed"
                else "identity_changed"
                if closed in {"cleanup_identity_changed", "device_changed"}
                else "credential_replacement_failed"
            ),
            "upgraded_to_replacement": True,
        }


def _sync_or_replace_deactivated_missing_business_child(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Upload one missing credential, or safely replace a proven-dead child."""
    sync_kwargs: dict[str, Any] = {
        "provider": provider,
        "provider_id": provider_id,
        "device_epoch": device_epoch,
        "expected": expected,
    }
    if task_id:
        sync_kwargs["task_id"] = task_id
    if child_progress_identity is not None:
        sync_kwargs["child_progress_identity"] = child_progress_identity
    outcome = _sync_missing_business_child(**sync_kwargs)
    if bool(outcome.get("ok")) or str(outcome.get("error_code") or "") != (
        "account_deactivated"
    ):
        return outcome
    return _replace_deactivated_missing_business_child(
        provider=provider,
        provider_id=int(provider_id),
        device_epoch=device_epoch,
        expected=expected,
        task_id=task_id,
        child_progress_identity=child_progress_identity,
    )


class _SafeChildOperationError(RuntimeError):
    """Internal control-flow error carrying only a closed public code."""

    def __init__(self, code: str):
        safe_code = (
            str(code) if str(code) in _REFRESH_CHILD_ERRORS
            else "operation_failed"
        )
        super().__init__(safe_code)
        self.code = safe_code


def _oauth_snapshot_safe_error(snapshot: dict[str, Any]) -> str:
    result = (
        snapshot.get("result")
        if isinstance(snapshot.get("result"), dict)
        else {}
    )
    return _safe_child_failure_code(
        result.get("error_code"),
        result.get("stage"),
        result.get("error_message"),
        snapshot.get("error"),
        default="oauth_failed",
    )


def _mark_exact_business_child_deactivated(
    expected: dict[str, Any],
    *,
    operation_token: str,
) -> bool:
    """CAS the dead semantic while the exact child operation lease is owned."""
    try:
        parent_id = int(expected.get("parent_id") or 0)
        child_id = int(expected.get("child_id") or 0)
        membership_id = int(expected.get("membership_id") or 0)
        email = _normalized_delivery_email(expected.get("email"))
        if min(parent_id, child_id, membership_id) <= 0 or not email:
            return False
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            child = session.get(GptProAccountModel, child_id)
            membership = session.get(
                GptBusinessChildMembershipModel,
                membership_id,
            )
            lease = session.get(GptProAccountOperationLeaseModel, child_id)
            now = _utcnow()
            if not (
                child
                and membership
                and lease
                and str(operation_token or "")
                and str(lease.token or "") == str(operation_token)
                and _active_lease(lease.expires_at, now)
                and membership.ended_at is None
                and int(membership.business_account_id or 0) == parent_id
                and int(membership.pro_account_id or 0) == child_id
                and _normalized_delivery_email(membership.email) == email
                and int(child.business_parent_id or 0) == parent_id
                and _normalized_delivery_email(child.email) == email
            ):
                session.rollback()
                return False
            child.dangerous = True
            child.dangerous_detected_at = child.dangerous_detected_at or now
            child.updated_at = now
            session.add(child)
            session.commit()
            return True
    except Exception:
        # The public safe error remains authoritative even during a rolling DB
        # migration; persistence is best-effort and never exposes DB details.
        return False


def _wait_for_business_child_credential_oauth(
    *,
    expected: dict[str, Any],
    guard,
    operation_token: str = "",
    timeout_seconds: int = 12 * 60,
    on_started=None,
) -> None:
    """Acquire a genuinely new RT and wait for the managed OAuth worker."""
    from api import gpt_business

    child_id = int(expected["child_id"])
    parent_id = int(expected["parent_id"])
    guard()
    launched = gpt_business.start_managed_business_child_oauth_capability(
        parent_id,
        child_id,
        allow_workspace_login=True,
        expected_operation_token=str(operation_token or ""),
    )
    oauth_task_id = str(launched.get("task_id") or "").strip()
    if not oauth_task_id:
        raise _SafeChildOperationError("oauth_failed")
    if callable(on_started):
        on_started()
    deadline = time.monotonic() + max(30, int(timeout_seconds))
    while time.monotonic() < deadline:
        snapshot = gpt_business.managed_business_child_oauth_capability_status(
            parent_id,
            child_id,
            oauth_task_id,
            0,
        )
        status = str(snapshot.get("status") or "").strip().lower()
        if status == "done":
            result = (
                snapshot.get("result")
                if isinstance(snapshot.get("result"), dict)
                else {}
            )
            if str(result.get("stage") or "done") != "done":
                raise _SafeChildOperationError(
                    _oauth_snapshot_safe_error(snapshot),
                )
            guard()
            return
        if status in {"failed", "error", "cancelled"}:
            raise _SafeChildOperationError(
                _oauth_snapshot_safe_error(snapshot),
            )
        guard()
        time.sleep(1.0)
    raise _SafeChildOperationError("oauth_timeout")


def _repair_business_child_credential(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
    remote_already_deleted: bool = False,
    oauth_already_confirmed: bool = False,
    oauth_checkpoint: Any = None,
) -> dict[str, Any]:
    """Replace one exact mapped 401 credential after obtaining a fresh RT."""
    from api.gpt_plan_operations import (
        _claim_gpt_pro_account_operation,
        _gpt_pro_account_operation_token_is_current,
        _release_gpt_pro_account_operation,
    )

    task_id, progress_identity = _team_child_progress_context(
        task_id,
        child_progress_identity or _business_child_progress_identity(expected),
    )
    lease_token = ""

    def guard() -> dict[str, Any]:
        state = _business_child_delivery_guard(
            provider=provider,
            provider_id=provider_id,
            device_epoch=device_epoch,
            expected=expected,
        )
        if lease_token and not _gpt_pro_account_operation_token_is_current(
            int(expected["child_id"]), lease_token,
        ):
            raise RuntimeError("credential_repair_lease_lost")
        return state

    try:
        if not (
            int(expected.get("credential_repair_status") or 0) == 401
            and str(expected.get("remote_id") or "").strip()
        ):
            raise RuntimeError("credential_repair_not_authorized")
        lease_token = _claim_gpt_pro_account_operation(
            int(expected["child_id"]),
            "delivery_credential_repair",
            ttl_hours=1,
            allow_managed_business_child=True,
        )
        if not oauth_already_confirmed:
            if task_id:
                _refresh_task_child_update(
                    task_id,
                    progress_identity,
                    status="running",
                    stage="acquiring_oauth",
                    percent=30,
                )
            _wait_for_business_child_credential_oauth(
                expected=expected,
                guard=guard,
                operation_token=lease_token,
            )
            if callable(oauth_checkpoint):
                oauth_checkpoint()
        guard()
        if task_id:
            _refresh_task_child_update(
                task_id,
                progress_identity,
                status="running",
                stage="uploading_credential",
                percent=80,
            )
        if provider == "cpa":
            from api.gpt_plan_operations import sync_account_to_cpa

            result = sync_account_to_cpa(
                int(expected["child_id"]),
                int(provider_id),
                expected_business_parent_id=int(expected["parent_id"]),
                operation_token=lease_token,
                delivery_guard=guard,
                allow_credential_reauth=False,
            )
        else:
            from api.gpt_plan_operations import sync_account_to_sub2api

            result = sync_account_to_sub2api(
                int(expected["child_id"]),
                int(provider_id),
                expected_business_parent_id=int(expected["parent_id"]),
                operation_token=lease_token,
                delivery_guard=guard,
                allow_credential_reauth=False,
                replace_invalid_remote_id=(
                    ""
                    if remote_already_deleted
                    else str(expected["remote_id"])
                ),
            )
        guard()
        result_ok = bool(result.get("ok"))
        return {
            "ok": result_ok,
            "parent_id": int(expected["parent_id"]),
            "child_id": int(expected["child_id"]),
            "membership_id": int(expected["membership_id"]),
            "error_code": (
                ""
                if result_ok
                else _safe_child_failure_code(
                    result.get("error_code"),
                    result.get("error"),
                    result.get("message"),
                    default="upload_failed",
                )
            ),
        }
    except Exception as exc:
        error_code = (
            exc.code
            if isinstance(exc, _SafeChildOperationError)
            else _safe_child_failure_code(
                getattr(exc, "detail", ""),
                str(exc),
                default="credential_repair_failed",
            )
        )
        if error_code == "account_deactivated" and not (
            _mark_exact_business_child_deactivated(
                expected,
                operation_token=lease_token,
            )
        ):
            error_code = "lease_lost"
        return {
            "ok": False,
            "parent_id": int(expected["parent_id"]),
            "child_id": int(expected["child_id"]),
            "membership_id": int(expected["membership_id"]),
            "error_code": error_code,
        }
    finally:
        if lease_token:
            _release_gpt_pro_account_operation(
                int(expected["child_id"]),
                lease_token,
            )


def _replace_invalid_business_child_credential(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
    task_id: str = "",
    child_progress_identity: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Mother-first replacement for one exact dead child whose credential is 401.

    A dead account must not enter the OAuth repair path.  Re-resolving the
    immutable remote link here prevents a stale monitor snapshot from creating
    a destructive cleanup job.  The cleanup worker then rechecks the safe
    parent, policy binding, seat cooldown and replacement candidate before it
    performs the first remote mutation.
    """
    task_id, progress_identity = _team_child_progress_context(
        task_id,
        child_progress_identity or _business_child_progress_identity(expected),
    )
    remote = (
        dict(expected.get("remote") or {})
        if isinstance(expected.get("remote"), dict)
        else {}
    )
    mapping = _business_child_mapping(provider, int(provider_id), remote)
    exact = bool(
        provider == "cpa"
        and str(mapping.get("state") or "") == "mapped"
        and int(mapping.get("parent_id") or 0)
        == int(expected.get("parent_id") or 0)
        and int(mapping.get("membership_id") or 0)
        == int(expected.get("membership_id") or 0)
        and int(mapping.get("child_id") or 0)
        == int(expected.get("child_id") or 0)
        and int(mapping.get("policy_revision") or 0) > 0
        and int(mapping.get("policy_revision") or 0)
        == int(expected.get("policy_revision") or 0)
        and mapping.get("child_dangerous") is True
        and expected.get("child_dangerous") is True
        and str(mapping.get("invalid_reason") or "")
        == "access_deactivated"
        and str(expected.get("invalid_reason") or "")
        == "access_deactivated"
        and int(expected.get("credential_repair_status") or 0) == 401
        and remote.get("credential_repair_required") is True
        and int(remote.get("credential_repair_status") or 0) == 401
    )
    if not exact:
        return {
            "ok": False,
            "kind": "skipped",
            "error_code": "credential_replacement_identity_changed",
        }
    try:
        job = _create_or_get_cleanup_job(
            provider=provider,
            provider_id=int(provider_id),
            remote=remote,
            mapping=mapping,
            device_epoch=device_epoch,
            trigger_kind="credential_invalid",
        )
        result = _run_delivery_exhaustion_cleanup(
            str(job.id),
            task_id=task_id,
            child_progress_identity=progress_identity,
        )
        kind = str(result.get("kind") or "failed")
        demand_id = str(result.get("replenishment_demand_id") or "").strip()
        with Session(engine) as session:
            current = session.get(
                DeliveryDeviceExhaustionCleanupModel, str(job.id),
            )
            stage = str(current.stage or "") if current else ""
            if not demand_id:
                demand = session.exec(
                    select(DeliveryDeviceReplenishmentDemandModel).where(
                        DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                        == str(job.id)
                    )
                ).first()
                demand_id = str(demand.id or "") if demand else ""
        if kind == "success" and demand_id:
            # Cleanup is only the handoff boundary.  Start/reuse the durable
            # replenishment runner now; its allocation job owns invite,
            # acceptance, RT/OAuth and delivery to the exact original device.
            try:
                from api import gpt_business

                gpt_business.run_or_resume_business_replenishment_for_automation(
                    demand_id,
                )
            except Exception:
                # The durable scheduler will resume due demands.  Never turn a
                # safe committed cleanup into a retry that could remove twice.
                pass
        return {
            "ok": kind == "success" and bool(demand_id),
            "kind": (
                kind
                if kind != "success" or demand_id
                else "failed"
            ),
            "cleanup_job_id": str(job.id),
            "replenishment_demand_id": demand_id,
            "stage": stage,
            "error_code": (
                ""
                if kind != "success" or demand_id
                else "replenishment_missing"
            ),
        }
    except Exception:
        return {
            "ok": False,
            "kind": "failed",
            "error_code": "credential_replacement_failed",
        }


def _replace_invalid_business_parent_group(
    *,
    task_id: str,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace one mother's invalid children serially inside its worker.

    The device refresh already owns one device-scoped coordinator thread.  A
    parent group gets one child worker so unrelated mothers can make progress
    concurrently while every destructive operation for the same mother stays
    ordered.  The durable cleanup job, account operation lease and parent
    allocation fences remain the source of truth; this helper only controls
    local scheduling and isolates one item failure from the rest of the group.
    """
    outcomes: list[dict[str, Any]] = []
    for expected in expected_items:
        identity = _business_child_progress_identity(expected)
        _refresh_task_child_update(
            task_id,
            identity,
            operation="credential_invalid_replacement",
            status="queued",
            stage="waiting_for_slot",
            percent=5,
        )
        try:
            with _team_child_operation_slot(task_id, identity):
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="running",
                    stage="preflight",
                    percent=10,
                )
                outcome = _replace_invalid_business_child_credential(
                    provider=provider,
                    provider_id=provider_id,
                    device_epoch=device_epoch,
                    expected=expected,
                )
        except Exception:
            outcome = {
                "ok": False,
                "kind": "failed",
                "error_code": "credential_replacement_failed",
            }
        if not isinstance(outcome, dict):
            outcome = {
                "ok": False,
                "kind": "failed",
                "error_code": "parent_worker_invalid_result",
            }
        cleanup_job_id = str(outcome.get("cleanup_job_id") or "").strip()
        replenishment_demand_id = str(
            outcome.get("replenishment_demand_id") or ""
        ).strip()
        if cleanup_job_id or replenishment_demand_id:
            _refresh_task_child_link_replenishment(
                task_id,
                identity,
                cleanup_job_id=cleanup_job_id,
                replenishment_demand_id=replenishment_demand_id,
            )
        outcome_kind = str(outcome.get("kind") or "failed").strip().lower()
        if bool(outcome.get("ok")) or outcome_kind == "success":
            _refresh_task_child_update(
                task_id,
                identity,
                status="running",
                stage="replenishment_pending",
                percent=40,
                result="replenishment_handoff",
            )
        elif outcome_kind in {"busy", "pending", "waiting", "in_progress"}:
            _refresh_task_child_update(
                task_id,
                identity,
                status="pending",
                stage=(
                    "replenishment_pending"
                    if cleanup_job_id or replenishment_demand_id
                    else "pending"
                ),
                percent=40 if cleanup_job_id or replenishment_demand_id else 10,
                result=(
                    "replenishment_handoff"
                    if cleanup_job_id or replenishment_demand_id
                    else "pending"
                ),
                error="operation_busy",
            )
        elif outcome_kind == "skipped":
            _refresh_task_child_update(
                task_id,
                identity,
                status="skipped",
                stage="skipped",
                percent=100,
                result="skipped",
                error="identity_changed",
            )
        else:
            safe_error = _safe_child_failure_code(
                outcome.get("error_code"),
                outcome.get("stage"),
                default="credential_replacement_failed",
            )
            _refresh_task_child_update(
                task_id,
                identity,
                status="failed",
                stage="failed",
                percent=100,
                result="failed",
                error=safe_error,
            )
        outcomes.append(
            outcome if isinstance(outcome, dict)
            else {"ok": False, "error_code": "parent_worker_invalid_result"}
        )
    return outcomes


def _repair_or_replace_deactivated_business_child(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Repair a 401 once, then upgrade a proven-dead child in-place.

    The first OAuth attempt is non-destructive.  Only its closed
    ``account_deactivated`` result authorizes re-resolving the exact CPA link
    and entering the existing mother-first durable cleanup state machine.
    """
    outcome = _repair_business_child_credential(
        provider=provider,
        provider_id=provider_id,
        device_epoch=device_epoch,
        expected=expected,
    )
    if bool(outcome.get("ok")) or str(outcome.get("error_code") or "") != (
        "account_deactivated"
    ):
        return outcome
    replacement = dict(expected)
    replacement.update({
        "child_dangerous": True,
        "invalid_reason": "access_deactivated",
    })
    task_id, identity = _team_child_progress_context(
        "",
        _business_child_progress_identity(expected),
    )
    if task_id:
        _refresh_task_child_update(
            task_id,
            identity,
            operation="credential_invalid_replacement",
            status="running",
            stage="preflight",
            percent=10,
            error="",
        )
    replaced = _replace_invalid_business_child_credential(
        provider=provider,
        provider_id=provider_id,
        device_epoch=device_epoch,
        expected=replacement,
    )
    return {
        **replaced,
        "upgraded_to_replacement": True,
    }


def _run_business_child_parent_group(
    worker,
    *,
    task_id: str,
    operation: str,
    provider: str,
    provider_id: int,
    device_epoch: str,
    expected_items: list[dict[str, Any]],
    complete_on_success: bool = True,
) -> list[dict[str, Any]]:
    """Run non-destructive credential work serially for one mother."""
    outcomes: list[dict[str, Any]] = []
    for expected in expected_items:
        identity = _business_child_progress_identity(expected)
        _refresh_task_child_update(
            task_id,
            identity,
            operation=operation,
            status="queued",
            stage="waiting_for_slot",
            percent=5,
        )
        max_attempts = (
            int(_CREDENTIAL_UPLOAD_TRANSIENT_MAX_ATTEMPTS)
            if operation == "credential_upload" else 1
        )
        outcome: dict[str, Any] = {}
        saw_transient_lease = False
        for attempt_index in range(max(1, max_attempts)):
            if attempt_index:
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="running",
                    stage="retrying_check",
                    percent=min(35, 10 + attempt_index * 4),
                    result="pending",
                    error="",
                )
            try:
                # Reacquire the parent lane and global child slot for every
                # retry.  Waiting for another lease never consumes one of the
                # ten process-wide child-operation slots and never blocks a
                # same-parent owner from completing its current operation.
                with _team_child_operation_slot(task_id, identity):
                    _refresh_task_child_update(
                        task_id,
                        identity,
                        status="running",
                        stage=(
                            "acquiring_oauth"
                            if operation == "credential_repair"
                            else "uploading_credential"
                        ),
                        percent=min(45, 10 + attempt_index * 5),
                        error="",
                    )
                    outcome = worker(
                        provider=provider,
                        provider_id=provider_id,
                        device_epoch=device_epoch,
                        expected=expected,
                    )
            except Exception:
                outcome = {
                    "ok": False,
                    "error_code": "parent_worker_failed",
                }
            if not isinstance(outcome, dict):
                outcome = {
                    "ok": False,
                    "error_code": "parent_worker_invalid_result",
                }
            transient_error = _safe_child_failure_code(
                outcome.get("error_code"),
                outcome.get("stage"),
            )
            if bool(outcome.get("ok")):
                if saw_transient_lease:
                    _refresh_task_child_safe_log(
                        task_id,
                        identity,
                        stage="uploading_credential",
                        message="租约释放后本任务已继续",
                    )
                break
            retryable_lease = bool(
                operation == "credential_upload"
                and transient_error == "operation_busy"
            )
            if not retryable_lease:
                if (
                    operation == "credential_upload"
                    and transient_error == "lease_lost"
                ):
                    _refresh_task_child_safe_log(
                        task_id,
                        identity,
                        stage="waiting_resource",
                        message=(
                            "OAuth 期间旧租约发生变化并已释放，"
                            "本次自动重试已耗尽"
                        ),
                    )
                break
            if attempt_index + 1 >= max_attempts:
                active_operation = _active_child_operation_label(
                    int(identity.get("child_id") or 0),
                )
                if active_operation:
                    terminal_message = (
                        f"多次等待后{active_operation}仍在执行，需要稍后重试"
                    )
                elif transient_error == "lease_lost":
                    terminal_message = (
                        "OAuth 期间旧租约发生变化并已释放，"
                        "本次自动重试已耗尽"
                    )
                else:
                    terminal_message = (
                        "同账号任务租约已释放，但本次自动重试仍未完成，"
                        "需要稍后重试"
                    )
                _refresh_task_child_safe_log(
                    task_id,
                    identity,
                    stage="waiting_resource",
                    message=terminal_message,
                )
                break
            if not saw_transient_lease:
                _refresh_task_child_safe_log(
                    task_id,
                    identity,
                    stage="waiting_resource",
                    message="检测到同账号其他任务，等待其释放",
                )
            retry_number = attempt_index + 1
            _refresh_task_child_safe_log(
                task_id,
                identity,
                stage="waiting_resource",
                message=(
                    f"正在等待同账号任务释放，第 {retry_number}/"
                    f"{max_attempts - 1} 次重试"
                ),
            )
            saw_transient_lease = True
            _refresh_task_child_update(
                task_id,
                identity,
                status="running",
                stage="waiting_resource",
                percent=min(35, 10 + attempt_index * 4),
                result="pending",
                error="",
            )
            time.sleep(max(
                0.05,
                float(_MISSING_SYNC_TRANSIENT_RETRY_SECONDS),
            ))
        upgraded_to_replacement = bool(
            outcome.get("upgraded_to_replacement"),
        )
        cleanup_job_id = str(outcome.get("cleanup_job_id") or "").strip()
        replenishment_demand_id = str(
            outcome.get("replenishment_demand_id") or ""
        ).strip()
        if upgraded_to_replacement and (
            cleanup_job_id or replenishment_demand_id
        ):
            _refresh_task_child_link_replenishment(
                task_id,
                identity,
                cleanup_job_id=cleanup_job_id,
                replenishment_demand_id=replenishment_demand_id,
            )
        if upgraded_to_replacement and (
            cleanup_job_id or replenishment_demand_id
        ):
            _refresh_task_child_update(
                task_id,
                identity,
                operation="credential_invalid_replacement",
                status="running",
                stage="replenishment_pending",
                percent=40,
                result=(
                    "replenishment_handoff"
                    if replenishment_demand_id else "pending"
                ),
                error="",
            )
        elif str(outcome.get("error_code") or "") == (
            "credential_retry_cooldown"
        ):
            _refresh_task_child_update(
                task_id,
                identity,
                status="pending",
                stage="waiting_credential_retry",
                percent=55,
                result="pending",
                error="",
                next_check_at=outcome.get("retry_at") or "",
            )
        elif bool(outcome.get("ok")):
            _refresh_task_child_update(
                task_id,
                identity,
                status="completed" if complete_on_success else "running",
                stage="completed" if complete_on_success else "active_verify",
                percent=100 if complete_on_success else 90,
                result=(
                    "repaired"
                    if complete_on_success and operation == "credential_repair"
                    else "uploaded"
                    if complete_on_success
                    else "pending"
                ),
                next_check_at="",
            )
        else:
            safe_error = _safe_child_failure_code(
                outcome.get("error_code"),
                outcome.get("stage"),
                default=(
                    "credential_repair_failed"
                    if operation == "credential_repair"
                    else "upload_failed"
                ),
            )
            _refresh_task_child_update(
                task_id,
                identity,
                status="failed",
                stage="failed",
                percent=100,
                result="failed",
                error=safe_error,
            )
        outcomes.append(
            outcome if isinstance(outcome, dict)
            else {"ok": False, "error_code": "parent_worker_invalid_result"}
        )
    return outcomes


def _business_child_parent_groups(
    expected_items: list[dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:
    groups: dict[int, list[dict[str, Any]]] = {}
    for item in expected_items:
        try:
            parent_id = int(item.get("parent_id") or 0)
        except (TypeError, ValueError):
            parent_id = 0
        groups.setdefault(parent_id, []).append(item)
    return groups


def _remote_confirms_expected_business_child(
    expected: dict[str, Any],
    remote_items: list[dict[str, Any]],
) -> bool:
    """Require one enabled exact device-link row for the current lifecycle."""
    try:
        lifecycle = (
            int(expected.get("parent_id") or 0),
            int(expected.get("child_id") or 0),
            int(expected.get("membership_id") or 0),
        )
    except (TypeError, ValueError):
        return False
    if min(lifecycle) <= 0:
        return False
    exact: list[dict[str, Any]] = []
    for item in remote_items:
        if not isinstance(item, dict):
            continue
        navigation = (
            item.get("navigation")
            if isinstance(item.get("navigation"), dict)
            else {}
        )
        try:
            matches = bool(
                str(navigation.get("state") or "") == "mapped"
                and str(navigation.get("match_basis") or "") == "device_link"
                and str(navigation.get("target_kind") or "")
                == "business_child"
                and int(navigation.get("business_parent_id") or 0)
                == lifecycle[0]
                and int(navigation.get("pro_account_id") or 0)
                == lifecycle[1]
                and int(navigation.get("membership_id") or 0)
                == lifecycle[2]
            )
        except (TypeError, ValueError):
            matches = False
        if matches:
            exact.append(item)
    try:
        repair_status = int(
            exact[0].get("credential_repair_status") or 0
        ) if len(exact) == 1 else 0
    except (TypeError, ValueError):
        repair_status = 0
    return bool(
        len(exact) == 1
        and exact[0].get("disabled") is not True
        and exact[0].get("credential_repair_required") is not True
        and repair_status != 401
    )


def _reconcile_inventory_missing_business_children(
    task_id: str,
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    remote_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Upload every missing current child without touching scanned 401 rows.

    This is the refresh-button reconciliation boundary.  It deliberately uses
    only ``inventory['missing']``; credential-invalid rows remain operator-
    initiated TEAM 401 corrections.  Existing child work is mother-serial and
    shares the process-wide ten-child gate.
    """
    inventory = _business_device_reconcile_inventory(
        provider,
        int(provider_id),
        remote_items,
    )
    # ``present`` contains only one exact active lifecycle mapped from the
    # authoritative device inventory.  It is therefore also the recovery path
    # for a credential which appeared after a previous scan marked it missing.
    for present in list(inventory.get("present") or []):
        _clear_business_child_delivery_repair_state(
            provider=provider,
            provider_id=int(provider_id),
            expected=present,
        )
    missing = list(inventory.get("missing") or [])
    missing_deactivated = list(
        inventory.get("missing_deactivated") or []
    )
    result = {
        "bound_parents": len(inventory.get("bound_parent_ids") or []),
        "active_children": int(inventory.get("active_memberships") or 0),
        "missing_children": len(missing),
        "deactivated_missing_children": len(missing_deactivated),
        "uploaded_children": 0,
        "upload_failed": 0,
        "upload_pending_replacement": 0,
        "replacement_handoffs": 0,
        "replacement_failed": 0,
        "credential_retry_deferred": 0,
        "lifecycle_reconciled": 0,
        "lifecycle_reconcile_failed": 0,
        "conflict_children": len(inventory.get("conflicts") or []),
        "pending_children": int(inventory.get("pending") or 0),
        "unmanaged_children": int(inventory.get("unmanaged") or 0),
    }
    if not missing and not missing_deactivated:
        return result

    if missing_deactivated:
        for item in missing_deactivated:
            _mark_business_child_remote_missing(
                provider=provider,
                provider_id=int(provider_id),
                expected=item,
            )
            _refresh_task_child_update(
                task_id,
                _business_child_progress_identity(item),
                operation="credential_invalid_replacement",
                status="queued",
                stage="queued",
                percent=0,
            )
        _refresh_task_update(
            task_id,
            stage="replacing_deactivated_missing_children",
        )
        _refresh_task_log(
            task_id,
            (
                f"发现 {len(missing_deactivated)} 个当前子号已停用且设备凭证缺失，"
                "开始通过母号能力安全换号"
            ),
        )
        groups = _business_child_parent_groups(missing_deactivated)
        workers = min(
            _TEAM_CHILD_CONCURRENCY_MAX,
            _MISSING_SYNC_PARENT_WORKERS_MAX,
            max(1, len(groups)),
        )
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=(
                f"device-dead-missing-{provider}-{provider_id}"
            ),
        ) as executor:
            futures = {
                executor.submit(
                    _run_business_child_parent_group,
                    _replace_deactivated_missing_business_child,
                    task_id=task_id,
                    operation="credential_invalid_replacement",
                    provider=provider,
                    provider_id=int(provider_id),
                    device_epoch=device_epoch,
                    expected_items=items,
                    complete_on_success=False,
                ): items
                for items in groups.values()
            }
            for future in as_completed(futures):
                expected_items = futures[future]
                try:
                    outcomes = list(future.result())
                except Exception:
                    outcomes = [
                        {
                            "ok": False,
                            "error_code": "credential_replacement_failed",
                        }
                        for _ in expected_items
                    ]
                for index, _expected in enumerate(expected_items):
                    outcome = (
                        outcomes[index] if index < len(outcomes) else {}
                    )
                    kind = str(
                        outcome.get("kind") or "failed"
                    ).strip().lower()
                    linked = bool(
                        str(outcome.get("cleanup_job_id") or "").strip()
                        or str(
                            outcome.get("replenishment_demand_id") or ""
                        ).strip()
                    )
                    if linked and (
                        bool(outcome.get("ok"))
                        or kind in {
                            "success", "busy", "pending", "waiting",
                            "in_progress",
                        }
                    ):
                        result["replacement_handoffs"] += 1
                        result["upload_pending_replacement"] += 1
                    else:
                        result["replacement_failed"] += 1

    for item in missing:
        # The device inventory was read successfully and contains neither an
        # exact lifecycle row nor a same-email conflict.  Publish that remote
        # absence before repair so stale local fields cannot keep rendering an
        # "已同步" link while OAuth/upload is still pending.
        _mark_business_child_remote_missing(
            provider=provider,
            provider_id=int(provider_id),
            expected=item,
        )
        _refresh_task_child_update(
            task_id,
            _business_child_progress_identity(item),
            operation="credential_upload",
            status="queued",
            stage="queued",
            percent=0,
        )
    _refresh_task_update(task_id, stage="syncing_missing_children")
    _refresh_task_log(
        task_id,
        f"发现 {len(missing)} 个当前子号缺少设备凭证，开始逐个补传",
    )
    groups = _business_child_parent_groups(missing)
    workers = min(
        _TEAM_CHILD_CONCURRENCY_MAX,
        _MISSING_SYNC_PARENT_WORKERS_MAX,
        max(1, len(groups)),
    )
    successful: list[dict[str, Any]] = []
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix=f"device-missing-{provider}-{provider_id}",
    ) as executor:
        futures = {
            executor.submit(
                _run_business_child_parent_group,
                _sync_missing_business_child,
                task_id=task_id,
                operation="credential_upload",
                provider=provider,
                provider_id=int(provider_id),
                device_epoch=device_epoch,
                expected_items=items,
                complete_on_success=False,
            ): items
            for items in groups.values()
        }
        for future in as_completed(futures):
            expected_items = futures[future]
            try:
                outcomes = list(future.result())
            except Exception:
                outcomes = [
                    {"ok": False, "error_code": "upload_failed"}
                    for _ in expected_items
                ]
            for index, expected in enumerate(expected_items):
                outcome = outcomes[index] if index < len(outcomes) else {}
                if bool(outcome.get("ok")) and not bool(
                    outcome.get("upgraded_to_replacement")
                ):
                    successful.append(expected)
                elif str(outcome.get("error_code") or "") == (
                    "credential_retry_cooldown"
                ):
                    result["credential_retry_deferred"] += 1
                else:
                    result["upload_failed"] += 1

    if successful:
        _refresh_task_log(
            task_id,
            f"正在回查 {len(successful)} 个新上传的子号凭证",
        )
        try:
            verified_snapshot = monitor.refresh_device_pro_inventory(
                monitor.device_key(provider, int(provider_id)),
            )
        except Exception:
            verified_snapshot = {"ok": False, "items": []}
        verified_items = [
            dict(item)
            for item in list(verified_snapshot.get("items") or [])
            if isinstance(item, dict)
        ] if bool(verified_snapshot.get("ok")) else []
        for expected in successful:
            identity = _business_child_progress_identity(expected)
            if (
                bool(verified_snapshot.get("ok"))
                and _remote_confirms_expected_business_child(
                    expected,
                    verified_items,
                )
            ):
                _clear_business_child_delivery_repair_state(
                    provider=provider,
                    provider_id=int(provider_id),
                    expected=expected,
                )
                try:
                    from api import gpt_business

                    lifecycle = (
                        gpt_business
                        .complete_managed_business_child_delivery_for_automation(
                            int(expected["parent_id"]),
                            int(expected["child_id"]),
                            int(expected["membership_id"]),
                            provider=provider,
                            device_id=int(provider_id),
                        )
                    )
                    if bool(lifecycle.get("reconciled")):
                        result["lifecycle_reconciled"] += 1
                    elif not bool(lifecycle.get("ok")):
                        result["lifecycle_reconcile_failed"] += 1
                        _refresh_task_log(
                            task_id,
                            "子号已上传设备，但旧补位任务状态暂未完成收口",
                        )
                except Exception:
                    # The credential is already proven active on this exact
                    # device, so never relabel the remote delivery as failed.
                    # Keep a separate visible warning for the stale local fill
                    # checkpoint instead of silently retaining “待 RT”.
                    result["lifecycle_reconcile_failed"] += 1
                    _refresh_task_log(
                        task_id,
                        "子号已上传设备，但旧补位任务状态暂未完成收口",
                    )
                result["uploaded_children"] += 1
                _refresh_task_child_update(
                    task_id,
                    identity,
                    status="completed",
                    stage="completed",
                    percent=100,
                    result="uploaded",
                    error="",
                )
            else:
                # A management upload response is not an active linkage.  If
                # the exact device inventory cannot map the same lifecycle,
                # restore the stale marker and keep the retry audit intact.
                _mark_business_child_remote_missing(
                    provider=provider,
                    provider_id=int(provider_id),
                    expected=expected,
                )
                retry_at = _persist_business_child_credential_retry_backoff(
                    provider=provider,
                    provider_id=int(provider_id),
                    expected=expected,
                    error_code="device_verify_failed",
                )
                if retry_at:
                    result["credential_retry_deferred"] += 1
                    _refresh_task_child_update(
                        task_id,
                        identity,
                        status="pending",
                        stage="waiting_credential_retry",
                        percent=90,
                        result="pending",
                        error="",
                        next_check_at=retry_at,
                    )
                else:
                    result["upload_failed"] += 1
                    _refresh_task_child_update(
                        task_id,
                        identity,
                        status="failed",
                        stage="failed",
                        percent=100,
                        result="failed",
                        error="device_verify_failed",
                    )
    return result


def _link_refresh_master_dispatch_children(
    task_id: str,
    child_job_ids: list[str],
) -> list[str]:
    """Attach newly selected durable fill jobs to per-child refresh rows."""
    linked: list[str] = []
    with Session(engine) as session:
        jobs = [
            session.get(GptBusinessAllocationJobModel, str(job_id))
            for job_id in child_job_ids
            if str(job_id or "").strip()
        ]
        parent_ids = sorted({
            int(job.selected_business_account_id or 0)
            for job in jobs if job is not None
        })
        parents = {
            int(parent.id or 0): parent
            for parent in (
                session.exec(select(GptBusinessAccountModel).where(
                    GptBusinessAccountModel.id.in_(parent_ids)  # type: ignore[union-attr]
                )).all()
                if parent_ids else []
            )
        }
        for job in jobs:
            if job is None:
                continue
            request = _json_object(job.request_json)
            if str(request.get("job_kind") or "") != "master_dispatch_fill":
                continue
            identity = _business_fill_progress_identity(job)
            if not identity:
                continue
            parent = parents.get(int(identity["parent_id"]))
            identity["parent_email"] = _safe_child_progress_email(
                parent.email if parent else "",
            )
            identity["parent_note"] = str(
                parent.note if parent else "",
            )[:200]
            _refresh_task_child_update(
                task_id,
                identity,
                operation="business_fill",
                status="queued",
                stage="planned",
                percent=5,
            )
            _refresh_task_child_link_replenishment(
                task_id,
                identity,
                fill_job_id=str(job.id),
            )
            linked.append(str(job.id))
    return linked


def _dispatch_available_bound_business_children(
    task_id: str,
    *,
    provider: str,
    provider_id: int,
    device_ref: str,
    device_epoch: str,
) -> dict[str, Any]:
    """Fill every currently available typed seat through durable allocations.

    One dispatch wave can select at most one child per mother because the
    parent lease is intentionally exclusive.  Re-scan after a completed wave
    so a partially occupied mother with another real typed seat can create a
    second independent child job.  Four waves bound a single refresh; the
    shared invitation policy independently enforces the configured quota.
    """
    from api.gpt_business import (
        BizMasterDispatchRequest,
        start_business_master_dispatch,
    )

    result = {
        "fill_waves": 0,
        "fill_started": 0,
        "fill_completed": 0,
        "fill_failed": 0,
        "fill_blocked": 0,
        "fill_task_ids": [],
    }
    seen_jobs: set[str] = set()
    for wave in range(1, 5):
        if not _device_epoch_is_current(
            provider,
            int(provider_id),
            device_epoch,
        ):
            break
        operation_id = f"device-refresh-fill:{task_id}:{wave}"
        snapshot = start_business_master_dispatch(
            provider,
            int(provider_id),
            BizMasterDispatchRequest(
                operation_id=operation_id,
                empty_only=False,
            ),
        )
        result["fill_waves"] += 1
        result["fill_task_ids"].append(
            str(snapshot.get("task_id") or ""),
        )
        items = [
            item for item in list(snapshot.get("items") or [])
            if isinstance(item, dict)
        ]
        job_ids = [
            str(item.get("job_id") or "").strip()
            for item in items
            if str(item.get("job_id") or "").strip()
            and str(item.get("job_id") or "").strip() not in seen_jobs
        ]
        linked = _link_refresh_master_dispatch_children(
            task_id,
            job_ids,
        )
        seen_jobs.update(linked)
        result["fill_started"] += len(linked)
        result["fill_blocked"] += sum(
            1 for item in items
            if str(item.get("status") or "") == "skipped"
        )
        if not linked:
            break
        _refresh_task_update(
            task_id,
            status="running",
            stage="waiting_business_delivery",
        )
        _refresh_task_log(
            task_id,
            f"第 {wave} 轮已为 {len(linked)} 个母号建立独立子号补位任务",
        )
        _wait_for_refresh_business_deliveries(
            task_id,
            device_ref,
        )
        # The waiter returns cumulative rows, so derive this wave's terminal
        # counts from the exact linked ids instead of adding its aggregate.
        with _REFRESH_TASK_LOCK:
            task = _REFRESH_TASKS.get(str(task_id)) or {}
            rows = list((task.get("child_progress") or {}).values())
        wave_rows = [
            row for row in rows
            if str(row.get("_fill_job_id") or "") in set(linked)
        ]
        completed = sum(
            1 for row in wave_rows
            if str(row.get("status") or "") == "completed"
        )
        failed = len(wave_rows) - completed
        result["fill_completed"] += completed
        result["fill_failed"] += failed
        if completed == 0 or failed:
            # A failed child retains its durable job and retry checkpoints.  A
            # new wave must not race another candidate into the same mother.
            break
    return result


def _reconcile_bound_business_device_children(
    task_id: str,
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    remote_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Repair missing current-child credentials and enqueue empty-parent fills."""
    _refresh_task_update(task_id, stage="reconciling_children")
    _refresh_task_log(task_id, "正在核对绑定母号的当前子号与设备凭证")
    inventory = _business_device_reconcile_inventory(
        provider, provider_id, remote_items,
    )
    invalid_replacements = list(
        inventory.get("invalid_replacements") or []
    )
    invalid_replaced = 0
    invalid_replacement_pending = 0
    invalid_replacement_failed = 0
    if invalid_replacements:
        for item in invalid_replacements:
            _refresh_task_child_update(
                task_id,
                _business_child_progress_identity(item),
                operation="credential_invalid_replacement",
                status="queued",
                stage="queued",
                percent=0,
            )
        _refresh_task_update(
            task_id, stage="replacing_invalid_credentials",
        )
        _refresh_task_log(
            task_id,
            f"发现 {len(invalid_replacements)} 个已停用且凭证返回 401 的当前子号，开始安全换号",
        )
        # The refresh task itself is already isolated per device.  Split this
        # device's invalid children by mother: different mothers use separate
        # workers, while one mother's children remain serial in their original
        # snapshot order.  Existing durable jobs/DB leases still fence retries
        # and cross-device races.
        parent_groups: dict[int, list[dict[str, Any]]] = {}
        for item in invalid_replacements:
            try:
                parent_id = int(item.get("parent_id") or 0)
            except (TypeError, ValueError):
                parent_id = 0
            parent_groups.setdefault(parent_id, []).append(item)
        workers = min(
            _INVALID_REPLACEMENT_PARENT_WORKERS_MAX,
            max(1, len(parent_groups)),
        )
        _refresh_task_log(
            task_id,
            (
                f"已按 {len(parent_groups)} 个母号建立独立换号任务，"
                f"本设备最多 {workers} 个母号并发；全局最多 "
                f"{_TEAM_CHILD_CONCURRENCY_MAX} 个子号同时处理；同一母号内串行处理"
            ),
        )
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=(
                f"device-invalid-parent-{provider}-{provider_id}"
            ),
        ) as executor:
            futures = {
                executor.submit(
                    _replace_invalid_business_parent_group,
                    task_id=task_id,
                    provider=provider,
                    provider_id=provider_id,
                    device_epoch=device_epoch,
                    expected_items=items,
                ): parent_id
                for parent_id, items in parent_groups.items()
            }
            completed = 0
            for future in as_completed(futures):
                group_size = len(parent_groups[futures[future]])
                try:
                    outcomes = future.result()
                except Exception:
                    outcomes = [{"ok": False}] * group_size
                for outcome in outcomes:
                    completed += 1
                    outcome_kind = str(
                        outcome.get("kind") or "failed"
                    ).strip().lower()
                    if bool(outcome.get("ok")) or outcome_kind == "success":
                        invalid_replaced += 1
                        _refresh_task_log(
                            task_id,
                            f"旧子号清理完成，正在持续跟踪母号补位 {completed}/{len(invalid_replacements)}",
                        )
                    elif outcome_kind in {
                        "busy", "pending", "waiting", "in_progress",
                    }:
                        invalid_replacement_pending += 1
                        _refresh_task_log(
                            task_id,
                            f"失效子号换号已有任务处理中 {completed}/{len(invalid_replacements)}",
                        )
                    else:
                        invalid_replacement_failed += 1
                        _refresh_task_log(
                            task_id,
                            f"失效子号换号暂未完成 {completed}/{len(invalid_replacements)}，安全阻断状态已保留",
                        )

    invalid_replacement_blockers = list(
        inventory.get("invalid_replacement_blockers") or []
    )
    if invalid_replacement_blockers:
        expected_email_by_child = {
            int(item.get("child_id") or 0): str(item.get("email") or "")
            for item in list(inventory.get("expected") or [])
            if isinstance(item, dict)
        }
        for item in invalid_replacement_blockers:
            blocked = dict(item)
            blocked["email"] = expected_email_by_child.get(
                int(item.get("child_id") or 0), "",
            )
            reason = str(item.get("reason") or "")
            safe_reason = (
                reason
                if reason in _REFRESH_CHILD_ERRORS
                else "operation_failed"
            )
            _refresh_task_child_update(
                task_id,
                _business_child_progress_identity(blocked),
                operation="credential_invalid_replacement",
                status="blocked",
                stage="blocked",
                percent=100,
                result="blocked",
                error=safe_reason,
            )
        refund_blocked = sum(
            1
            for item in invalid_replacement_blockers
            if str(item.get("reason") or "")
            == "business_parent_refunded"
        )
        if refund_blocked:
            _refresh_task_log(
                task_id,
                f"{refund_blocked} 个失效子号所属母号已进入已退款列表，已阻断自动换号",
            )
        other_blocked = len(invalid_replacement_blockers) - refund_blocked
        if other_blocked:
            _refresh_task_log(
                task_id,
                f"{other_blocked} 个失效子号因母号安全状态或席位类型不满足条件，已阻断自动换号",
            )

    repairs = list(inventory.get("repairs") or [])
    repaired = 0
    repair_failed = 0
    repair_upgraded_to_replacement = 0
    if repairs:
        for item in repairs:
            _refresh_task_child_update(
                task_id,
                _business_child_progress_identity(item),
                operation="credential_repair",
                status="queued",
                stage="queued",
                percent=0,
            )
        _refresh_task_update(task_id, stage="repairing_invalid_credentials")
        _refresh_task_log(
            task_id,
            f"发现 {len(repairs)} 个当前子号凭证返回 401，开始重新获取 RT 并覆盖上传",
        )
        repair_parent_groups = _business_child_parent_groups(repairs)
        workers = min(
            _CREDENTIAL_REPAIR_PARENT_WORKERS_MAX,
            max(1, len(repair_parent_groups)),
        )
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"device-credential-repair-{provider}",
        ) as executor:
            futures = {
                executor.submit(
                    _run_business_child_parent_group,
                    _repair_or_replace_deactivated_business_child,
                    task_id=task_id,
                    operation="credential_repair",
                    provider=provider,
                    provider_id=provider_id,
                    device_epoch=device_epoch,
                    expected_items=items,
                ): len(items)
                for items in repair_parent_groups.values()
            }
            completed = 0
            for future in as_completed(futures):
                try:
                    outcomes = future.result()
                except Exception:
                    outcomes = [{"ok": False}] * futures[future]
                for outcome in outcomes:
                    completed += 1
                    if (
                        bool(outcome.get("upgraded_to_replacement"))
                        and bool(outcome.get("ok"))
                    ):
                        repair_upgraded_to_replacement += 1
                        invalid_replaced += 1
                        _refresh_task_log(
                            task_id,
                            f"凭证修复确认账号停用，已升级为持续换号任务 {completed}/{len(repairs)}",
                        )
                    elif bool(outcome.get("ok")):
                        repaired += 1
                        _refresh_task_log(
                            task_id,
                            f"失效凭证修复完成 {completed}/{len(repairs)}",
                        )
                    else:
                        repair_failed += 1
                        _refresh_task_log(
                            task_id,
                            f"失效凭证修复失败 {completed}/{len(repairs)}，已记录明确失败原因并停止本次操作",
                        )

    missing = list(inventory["missing"])
    uploaded = 0
    upload_failed = 0
    missing_upgraded_to_replacement = 0
    if missing:
        for item in missing:
            _refresh_task_child_update(
                task_id,
                _business_child_progress_identity(item),
                operation="credential_upload",
                status="queued",
                stage="queued",
                percent=0,
            )
        _refresh_task_update(task_id, stage="syncing_missing_children")
        _refresh_task_log(
            task_id,
            f"发现 {len(missing)} 个当前子号缺少设备凭证，开始自动补传",
        )
        missing_parent_groups = _business_child_parent_groups(missing)
        workers = min(
            _MISSING_SYNC_PARENT_WORKERS_MAX,
            max(1, len(missing_parent_groups)),
        )
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"device-reconcile-{provider}",
        ) as executor:
            futures = {
                executor.submit(
                    _run_business_child_parent_group,
                    _sync_or_replace_deactivated_missing_business_child,
                    task_id=task_id,
                    operation="credential_upload",
                    provider=provider,
                    provider_id=provider_id,
                    device_epoch=device_epoch,
                    expected_items=items,
                ): len(items)
                for items in missing_parent_groups.values()
            }
            completed = 0
            for future in as_completed(futures):
                try:
                    outcomes = future.result()
                except Exception:
                    outcomes = [{"ok": False}] * futures[future]
                for outcome in outcomes:
                    completed += 1
                    if (
                        bool(outcome.get("upgraded_to_replacement"))
                        and (
                            outcome.get("cleanup_job_id")
                            or outcome.get("replenishment_demand_id")
                        )
                    ):
                        if bool(outcome.get("ok")):
                            missing_upgraded_to_replacement += 1
                            invalid_replaced += 1
                            message = "已升级为持续换号任务"
                        else:
                            invalid_replacement_pending += 1
                            message = "已有安全换号任务处理中"
                        _refresh_task_log(task_id, (
                            f"补传确认账号停用，{message} "
                            f"{completed}/{len(missing)}"
                        ))
                    elif bool(outcome.get("ok")):
                        uploaded += 1
                        _refresh_task_log(
                            task_id,
                            f"子号凭证补传完成 {completed}/{len(missing)}",
                        )
                    else:
                        upload_failed += 1
                        _refresh_task_log(
                            task_id,
                            f"子号凭证补传失败 {completed}/{len(missing)}，已记录明确失败原因并停止本次操作",
                        )
    else:
        replacement_background = invalid_replaced + invalid_replacement_pending
        replacement_review = (
            invalid_replacement_failed + len(invalid_replacement_blockers)
        )
        if replacement_background or replacement_review:
            details: list[str] = []
            if replacement_background:
                details.append(
                    f"{replacement_background} 个换号任务正在持续补位"
                )
            if replacement_review:
                details.append(f"{replacement_review} 个换号任务需复核")
            _refresh_task_log(
                task_id,
                "凭证对账已完成，" + "，".join(details),
            )
        elif repairs:
            details = []
            if repaired:
                details.append(f"{repaired} 个失效凭证已修复")
            if repair_failed:
                details.append(f"{repair_failed} 个凭证修复需复核")
            _refresh_task_log(
                task_id,
                "凭证对账已完成" + (
                    "，" + "，".join(details) if details else ""
                ),
            )
        else:
            _refresh_task_log(task_id, "绑定母号的当前子号凭证均已在设备中")

    empty_parent_ids = list(inventory["empty_parent_ids"])
    fill_snapshot: dict[str, Any] = {}
    if empty_parent_ids:
        _refresh_task_update(task_id, stage="dispatching_empty_parents")
        _refresh_task_log(
            task_id,
            f"发现 {len(empty_parent_ids)} 个已绑定但没有当前子号的母号，开始安全补位",
        )
        try:
            from api.gpt_business import (
                BizMasterDispatchRequest,
                start_business_master_dispatch,
            )

            fill_snapshot = start_business_master_dispatch(
                provider,
                int(provider_id),
                BizMasterDispatchRequest(
                    operation_id=f"device-refresh:{task_id}",
                    empty_only=True,
                ),
            )
            _refresh_task_update(task_id, stage="waiting_business_delivery")
            started = int(
                (fill_snapshot.get("counts") or {}).get("started") or 0
            )
            if started:
                _refresh_task_log(
                    task_id,
                    f"已启动 {started} 个空母号补位任务；邀请、获取 RT 与设备上传在独立任务中继续",
                )
            else:
                _refresh_task_log(
                    task_id,
                    "空母号当前没有可安全启动的邀请任务，已保留席位、冷却与候选检查结果",
                )
        except Exception:
            fill_snapshot = {
                "status": "action_required",
                "counts": {"started": 0, "failed": 1},
            }
            _refresh_task_log(
                task_id,
                "空母号补位调度暂未启动，设备刷新与已完成的凭证补传不回滚",
            )

    fill_counts = (
        fill_snapshot.get("counts")
        if isinstance(fill_snapshot.get("counts"), dict)
        else {}
    )
    fill_items = (
        fill_snapshot.get("items")
        if isinstance(fill_snapshot.get("items"), list)
        else []
    )
    deferred_blocked = sum(
        1 for item in fill_items
        if isinstance(item, dict)
        and str(item.get("status") or "") == "skipped"
        and str(item.get("stage") or "") in {
            "replenishment_pending", "fill_already_pending",
        }
    )
    raw_skipped = int(fill_counts.get("skipped") or 0)
    conflicts = len(inventory["conflicts"])
    return {
        "bound_parents": len(inventory["bound_parent_ids"]),
        "active_children": int(inventory["active_memberships"]),
        "managed_children": len(inventory["expected"]),
        "present_children": len(inventory["present"]),
        "credential_repairs": len(repairs),
        "repaired_children": repaired,
        "repair_failed": repair_failed,
        "credential_invalid_children": len(invalid_replacements)
        + len(invalid_replacement_blockers)
        + repair_upgraded_to_replacement
        + missing_upgraded_to_replacement,
        "credential_replacements": len(invalid_replacements)
        + repair_upgraded_to_replacement
        + missing_upgraded_to_replacement,
        "credential_replacement_handoffs": invalid_replaced,
        "credential_replacement_completed": invalid_replaced,
        "credential_replacement_pending": invalid_replacement_pending,
        "credential_replacement_failed": invalid_replacement_failed,
        "credential_replacement_blocked": len(
            invalid_replacement_blockers
        ),
        "credential_replacement_blockers": [
            {
                "parent_id": int(item.get("parent_id") or 0),
                "child_id": int(item.get("child_id") or 0),
                "membership_id": int(item.get("membership_id") or 0),
                "reason": str(item.get("reason") or "")[:96],
            }
            for item in invalid_replacement_blockers
        ],
        "missing_children": len(missing),
        "uploaded_children": uploaded,
        "upload_failed": upload_failed,
        "conflict_children": conflicts,
        "pending_children": int(inventory["pending"]),
        "unmanaged_children": int(inventory["unmanaged"]),
        "empty_parents": len(empty_parent_ids),
        "fill_task_id": str(fill_snapshot.get("task_id") or ""),
        "fill_started": int(fill_counts.get("started") or 0),
        "fill_completed": int(fill_counts.get("success") or 0),
        "fill_pending": int(fill_counts.get("pending") or 0)
        + deferred_blocked,
        "fill_skipped": max(0, raw_skipped - deferred_blocked),
        "fill_failed": int(fill_counts.get("failed") or 0)
        + int(fill_counts.get("action_required") or 0),
    }


def _reconcile_legacy_business_quota_state(
    *,
    provider: str,
    provider_id: int,
    device_epoch: str,
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Close the old hourly-poller quota-disabled state-machine gap.

    A still-disabled exact credential retains the original terminal exhaustion
    evidence and is handed to the durable cleanup path.  If the short window
    has already reset and the exact credential now has a successful, non-limit
    quota response, only the stale local disabled marker is repaired.  Errors,
    ambiguous/email-only mappings, and hand-disabled credentials do nothing.
    """
    from api import gpt_business

    if str(provider) != "cpa":
        return {"state": "none"}
    navigation = (
        remote.get("navigation")
        if isinstance(remote.get("navigation"), dict)
        else {}
    )
    if not (
        str(navigation.get("state") or "") == "mapped"
        and str(navigation.get("match_basis") or "") == "device_link"
        and str(navigation.get("target_kind") or "") == "business_child"
    ):
        return {"state": "none"}
    try:
        parent_id = int(navigation.get("business_parent_id") or 0)
        child_id = int(navigation.get("pro_account_id") or 0)
        membership_id = int(navigation.get("membership_id") or 0)
    except (TypeError, ValueError):
        return {"state": "none"}
    if min(parent_id, child_id, membership_id) <= 0:
        return {"state": "none"}
    if not _device_epoch_is_current(provider, provider_id, device_epoch):
        return {"state": "none"}

    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            child = session.get(GptProAccountModel, child_id)
        else:
            child = session.exec(
                select(GptProAccountModel)
                .where(GptProAccountModel.id == child_id)
                .with_for_update()
            ).first()
        parent = session.get(GptBusinessAccountModel, parent_id)
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        membership = session.get(
            GptBusinessChildMembershipModel,
            membership_id,
        )
        extra = _json_object(getattr(child, "extra_json", "")) if child else {}
        try:
            linked_target = int(
                extra.get("cpa_synced_to_id")
                or extra.get("cpa_device_id")
                or 0
            )
        except (TypeError, ValueError):
            linked_target = 0
        valid = bool(
            child
            and parent
            and policy
            and membership
            and bool(policy.auto_rotation_enabled)
            and str(policy.delivery_type or "") == "cpa"
            and int(policy.cpa_target_id or 0) == int(provider_id)
            and bool(parent.enabled)
            and not bool(parent.dangerous)
            and not gpt_business._business_parent_refund_blocks_replacement(
                parent, session,
            )
            and bool(child.enabled)
            and not bool(child.dangerous)
            and not bool(child.policy_warning)
            and int(child.business_parent_id or 0) == parent_id
            and membership.ended_at is None
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == child_id
            and str(membership.remote_user_id or "").strip()
            and _normalized_delivery_email(membership.email)
            == _normalized_delivery_email(child.email)
            == _normalized_delivery_email(remote.get("email"))
            and bool(extra.get("cpa_synced"))
            and linked_target == int(provider_id)
            and str(extra.get("cpa_auth_name") or "").strip()
            == str(remote.get("remote_id") or "").strip()
            and bool(extra.get("cpa_disabled"))
            and str(extra.get("cpa_lifecycle_state") or "")
            == "business_child_quota_disabled"
            and str(extra.get("cpa_rotation_reason") or "")
            == "quota_exhausted"
            and str(extra.get("cpa_rotation_ready_at") or "").strip()
        )
        if not valid:
            session.rollback()
            return {"state": "none"}

        if bool(remote.get("disabled")):
            recovered_remote = dict(remote)
            recovered_remote["limit_reached"] = True
            cached_usage = extra.get("cpa_usage")
            if isinstance(cached_usage, dict):
                recovered_remote["usage"] = dict(cached_usage)
            session.rollback()
            return {"state": "exhausted", "remote": recovered_remote}

        healthy = bool(
            str(remote.get("usage_status") or "").strip().lower() == "ok"
            and remote.get("limit_reached") is False
            and isinstance(remote.get("usage"), dict)
        )
        if not healthy or not _device_epoch_is_current(
            provider, provider_id, device_epoch,
        ):
            session.rollback()
            return {"state": "none"}

        usage = dict(remote.get("usage") or {})
        extra["cpa_disabled"] = False
        extra["cpa_lifecycle_state"] = "active"
        extra["cpa_monitor_suppressed"] = False
        extra["cpa_usage"] = {
            "usage_5h_percent": usage.get("usage_5h_percent"),
            "usage_5h_reset_at": usage.get("usage_5h_reset_at"),
            "usage_5h_window_seconds": usage.get("usage_5h_window_seconds"),
            "usage_week_percent": usage.get("usage_week_percent"),
            "usage_week_reset_at": usage.get("usage_week_reset_at"),
            "usage_week_window_seconds": usage.get("usage_week_window_seconds"),
            "limit_reached": False,
            "credit_balance": usage.get("credit_balance"),
            "checked_at": str(remote.get("checked_at") or _iso_now()),
        }
        for key in (
            "cpa_disabled_at",
            "cpa_disabled_reason",
            "cpa_rotation_reason",
            "cpa_rotation_ready_at",
            "cpa_monitor_alert",
        ):
            extra.pop(key, None)
        child.extra_json = json.dumps(extra, ensure_ascii=False)
        child.updated_at = _utcnow()
        session.add(child)
        session.commit()
        return {"state": "recovered"}


def _safe_inventory_remote_id(value: Any) -> str:
    """Return a bounded public remote id or an opaque stable replacement."""
    raw = str(value or "").strip()
    token_shaped = bool(re.fullmatch(
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        raw,
    ))
    if (
        raw
        and len(raw) <= 500
        and not token_shaped
        and re.fullmatch(r"[A-Za-z0-9@._:+-]+", raw)
    ):
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"account-{digest}"


def _safe_inventory_plan(value: Any) -> str:
    raw = str(value or "").strip()[:120]
    if (
        raw
        and re.fullmatch(r"[A-Za-z0-9_. -]+", raw)
        and monitor.is_known_plan(raw)
    ):
        return raw
    return ""


def _inventory_account_result(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    *,
    remaining_percent: float | int | None,
    status: str,
    action: str,
    result: str,
    message: str,
) -> dict[str, Any]:
    raw_remote_id = str(remote.get("remote_id") or "").strip()
    public_remote_id = _safe_inventory_remote_id(raw_remote_id)
    plan = _safe_inventory_plan(remote.get("plan"))
    raw_label = str(remote.get("plan_label") or "").strip()[:120]
    plan_label = (
        raw_label
        if raw_label and re.fullmatch(r"[A-Za-z0-9_. 0-9Xx\u4e00-\u9fff-]+", raw_label)
        else ""
    )
    key = hashlib.sha256(
        f"{provider}\0{int(provider_id)}\0{raw_remote_id}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "key": key,
        "remote_id": public_remote_id,
        "email": _safe_child_progress_email(remote.get("email")),
        "plan": plan,
        "plan_label": plan_label,
        "remaining_percent": remaining_percent,
        "status": status,
        "action": action,
        "result": result,
        "message": message,
    }


_TEAM_QUOTA_ERROR_CODES = frozenset({
    "",
    "401",
    "403",
    "429",
    "http_5xx",
    "timeout",
    "scan_error",
    "identity_missing",
    "mapping_unavailable",
    "disable_failed",
})
_TEAM_MAPPING_STATES = frozenset({
    "mapped", "unmapped", "ambiguous", "conflict", "source_missing",
})


def _inventory_positive_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(str(value or "").strip())
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _safe_inventory_note(value: Any) -> str:
    return _safe_task_log_line(str(value or "")[:500])


def _safe_team_navigation(remote: dict[str, Any]) -> dict[str, Any]:
    raw = remote.get("navigation")
    raw = raw if isinstance(raw, dict) else {}
    state = str(raw.get("state") or "unmapped").strip().lower()
    if state not in _TEAM_MAPPING_STATES:
        state = "unmapped"
    if state != "mapped" or str(
        raw.get("target_kind") or ""
    ).strip().lower() != "business_child":
        return {"state": state, "target_page": "gpt_plans"}
    parent_id = _inventory_positive_int(raw.get("business_parent_id"))
    child_id = _inventory_positive_int(raw.get("pro_account_id"))
    membership_id = _inventory_positive_int(raw.get("membership_id"))
    plan_account_id = _inventory_positive_int(raw.get("plan_account_id"))
    if not all((parent_id, child_id, membership_id, plan_account_id)):
        return {"state": "conflict", "target_page": "gpt_plans"}
    seat_type = str(raw.get("seat_type") or "").strip().lower()
    if seat_type not in {"default", "prolite"}:
        seat_type = ""
    target_tab = str(raw.get("target_tab") or "").strip().lower()
    if target_tab not in {"member", "refunded"}:
        target_tab = "member"
    return {
        "state": "mapped",
        "match_basis": (
            "device_link"
            if str(raw.get("match_basis") or "") == "device_link"
            else "exact_email"
        ),
        "target_page": "gpt_plans",
        "target_tab": target_tab,
        "target_kind": "business_child",
        "plan_account_id": plan_account_id,
        "source_pool": "gpt_business",
        "source_account_id": parent_id,
        "business_parent_id": parent_id,
        "business_parent_email": _safe_child_progress_email(
            raw.get("business_parent_email")
        ),
        "business_parent_note": _safe_inventory_note(
            raw.get("business_parent_note")
        ),
        "pro_account_id": child_id,
        "membership_id": membership_id,
        "seat_type": seat_type,
    }


def _team_inventory_child_result(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_remote_id = str(remote.get("remote_id") or "").strip()
    public_remote_id = _safe_inventory_remote_id(raw_remote_id)
    key = hashlib.sha256(
        f"team\0{provider}\0{int(provider_id)}\0{raw_remote_id}".encode(
            "utf-8"
        )
    ).hexdigest()[:24]
    navigation = _safe_team_navigation(remote)
    mapping_state = str(navigation.get("state") or "unmapped")
    mapped = mapping_state == "mapped"
    plan = _safe_inventory_plan(remote.get("plan"))
    raw_label = str(remote.get("plan_label") or "").strip()[:120]
    plan_label = (
        raw_label
        if raw_label and re.fullmatch(
            r"[A-Za-z0-9_. 0-9Xx\u4e00-\u9fff-]+",
            raw_label,
        )
        else "未知套餐"
    )
    raw_error_code = str(remote.get("quota_error_code") or "").strip()
    error_code = (
        raw_error_code
        if raw_error_code in _TEAM_QUOTA_ERROR_CODES
        else "scan_error"
    )
    try:
        raw_http_status = int(remote.get("quota_http_status") or 0)
    except (TypeError, ValueError):
        raw_http_status = 0
    http_status = (
        raw_http_status if 100 <= raw_http_status <= 599 else None
    )
    if not error_code and http_status is not None:
        error_code = {
            401: "401",
            403: "403",
            429: "429",
        }.get(
            http_status,
            "http_5xx" if http_status >= 500 else "scan_error",
        )
    account_issue = bool(
        error_code == "401" or remote.get("account_issue") is True
    )
    remaining = remote.get("remaining_percent")
    quota_status = str(remote.get("usage_status") or "").strip().lower()
    quota_confirmed = bool(
        remote.get("quota_checked") is True
        and quota_status in {"ok", "limit_reached"}
        and not isinstance(remaining, bool)
        and isinstance(remaining, (int, float))
        and 0.0 <= float(remaining) <= 100.0
    )
    public_remaining: float | int | None = None
    if quota_confirmed:
        public_remaining = (
            int(float(remaining))
            if float(remaining).is_integer()
            else float(remaining)
        )

    action = "none"
    result = ""
    if bool(remote.get("disabled")):
        status = "disabled"
        result = "already_disabled"
        message = "TEAM/BUSINESS 子号凭证当前已在设备中禁用"
    elif error_code == "401":
        status = "abnormal"
        result = "quota_unknown"
        message = "额度查询返回 HTTP 401，账号凭证异常"
    elif error_code:
        status = "failed"
        result = "quota_unknown"
        message = {
            "403": "额度查询返回 HTTP 403",
            "429": "额度查询受限（HTTP 429）",
            "http_5xx": "额度服务暂时不可用（HTTP 5xx）",
            "timeout": "额度查询超时",
            "identity_missing": "缺少额度查询标识",
            "mapping_unavailable": "本地归属映射不可用",
        }.get(error_code, "额度查询失败")
    elif account_issue:
        status = "abnormal"
        result = "quota_unknown"
        message = "账号凭证状态异常，额度仅展示"
    elif not mapped:
        error_code = "mapping_unavailable"
        status = "unmapped" if mapping_state == "unmapped" else "conflict"
        result = "mapping_unavailable"
        message = (
            "本地归属未映射，额度仅展示"
            if status == "unmapped"
            else "本地归属映射冲突，额度仅展示"
        )
    elif not quota_confirmed:
        error_code = "scan_error"
        status = "failed"
        result = "quota_unknown"
        message = "额度查询失败"
    elif float(public_remaining or 0) == 0.0:
        status = "depleted"
        result = "depleted"
        message = "TEAM 子号剩余额度为 0%，未执行任何变更"
    else:
        status = "healthy"
        result = "healthy"
        message = "TEAM 子号额度正常，仅展示"

    child = {
        "key": key,
        "remote_id": public_remote_id,
        "email": _safe_child_progress_email(remote.get("email")),
        "plan": plan,
        "plan_label": plan_label,
        "seat_type": str(navigation.get("seat_type") or ""),
        "child_id": (
            int(navigation.get("pro_account_id") or 0) if mapped else None
        ),
        "membership_id": (
            int(navigation.get("membership_id") or 0) if mapped else None
        ),
        "remaining_percent": public_remaining,
        "status": status,
        "action": action,
        "result": result,
        "error_code": error_code,
        "http_status": http_status,
        "account_issue": account_issue,
        "message": message,
        "navigation": navigation,
    }
    group = {
        "mapping_state": mapping_state,
        "parent_id": (
            int(navigation.get("business_parent_id") or 0) if mapped else None
        ),
        "parent_email": (
            str(navigation.get("business_parent_email") or "") if mapped else ""
        ),
        "parent_note": (
            str(navigation.get("business_parent_note") or "") if mapped else ""
        ),
        "plan_account_id": (
            int(navigation.get("plan_account_id") or 0) if mapped else None
        ),
        "target_tab": (
            str(navigation.get("target_tab") or "member")
            if mapped
            else ""
        ),
    }
    return child, group


def _team_inventory_groups(
    rows: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for child, meta in rows:
        parent_id = meta.get("parent_id")
        if isinstance(parent_id, int) and parent_id > 0:
            group_key = f"parent-{parent_id}"
        else:
            group_key = f"remote-{child['key']}"
        group = groups.get(group_key)
        if group is None:
            mapped = isinstance(parent_id, int) and parent_id > 0
            group_navigation = (
                {
                    "state": "mapped",
                    "target_page": "gpt_plans",
                    "target_tab": (
                        str(meta.get("target_tab") or "member")
                        if str(meta.get("target_tab") or "member")
                        in {"member", "refunded"}
                        else "member"
                    ),
                    "target_kind": "business_parent",
                    "plan_account_id": meta.get("plan_account_id"),
                    "source_pool": "gpt_business",
                    "source_account_id": parent_id,
                    "business_parent_id": parent_id,
                }
                if mapped
                else {
                    "state": str(meta.get("mapping_state") or "unmapped"),
                    "target_page": "gpt_plans",
                }
            )
            group = {
                "key": group_key,
                "mapping_state": str(meta.get("mapping_state") or "unmapped"),
                "parent_id": parent_id if mapped else None,
                "parent_email": str(meta.get("parent_email") or "") if mapped else "",
                "parent_note": str(meta.get("parent_note") or "") if mapped else "",
                "navigation": group_navigation,
                "children": [],
            }
            groups[group_key] = group
        group["children"].append(child)
    result = list(groups.values())
    for group in result:
        group["children"].sort(
            key=lambda item: (
                str(item.get("email") or "").casefold(),
                str(item.get("remote_id") or ""),
            )
        )
    result.sort(key=lambda item: (
        item.get("parent_id") is None,
        str(item.get("parent_email") or "").casefold(),
        str(item.get("key") or ""),
    ))
    return result


def _merge_bound_business_parent_groups(
    provider: str,
    provider_id: int,
    groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep bound mothers visible even when the device has zero TEAM rows."""
    merged = [dict(group) for group in groups]
    known_parent_ids = {
        int(group.get("parent_id") or 0)
        for group in merged
        if int(group.get("parent_id") or 0) > 0
    }
    with Session(engine) as session:
        query = select(GptBusinessAutomationPolicyModel).where(
            GptBusinessAutomationPolicyModel.auto_rotation_enabled == True  # noqa: E712
        )
        if provider == "cpa":
            query = query.where(
                GptBusinessAutomationPolicyModel.delivery_type == "cpa",
                GptBusinessAutomationPolicyModel.cpa_target_id
                == int(provider_id),
            )
        else:
            query = query.where(
                GptBusinessAutomationPolicyModel.delivery_type == "sub2api",
                GptBusinessAutomationPolicyModel.sub2api_device_id
                == int(provider_id),
            )
        parent_ids = sorted({
            int(policy.business_account_id)
            for policy in session.exec(query).all()
            if int(policy.business_account_id or 0) > 0
        })
        parents = {
            int(parent.id or 0): parent
            for parent in (
                session.exec(select(GptBusinessAccountModel).where(
                    GptBusinessAccountModel.id.in_(parent_ids)  # type: ignore[union-attr]
                )).all()
                if parent_ids else []
            )
        }
        plan_ids = {
            int(account.source_account_id): int(account.id or 0)
            for account in (
                session.exec(select(GptProAccountModel).where(
                    GptProAccountModel.source_pool == "gpt_business",
                    GptProAccountModel.source_account_id.in_(parent_ids),  # type: ignore[union-attr]
                )).all()
                if parent_ids else []
            )
            if int(account.source_account_id or 0) > 0
            and int(account.id or 0) > 0
        }
    for parent_id in parent_ids:
        if parent_id in known_parent_ids:
            continue
        parent = parents.get(parent_id)
        if parent is None:
            continue
        plan_account_id = plan_ids.get(parent_id)
        merged.append({
            "key": f"parent-{parent_id}",
            "mapping_state": "mapped",
            "parent_id": parent_id,
            "parent_email": _safe_child_progress_email(parent.email),
            "parent_note": _safe_inventory_note(parent.note),
            "navigation": {
                "state": "mapped",
                "target_page": "gpt_plans",
                "target_tab": "member",
                "target_kind": "business_parent",
                "plan_account_id": plan_account_id,
                "source_pool": "gpt_business",
                "source_account_id": parent_id,
                "business_parent_id": parent_id,
            },
            # This is a mother container, not a fabricated remote credential.
            # Per-child upload/fill rows are carried by task.child_progress.
            "children": [],
        })
    merged.sort(key=lambda item: (
        item.get("parent_id") is None,
        str(item.get("parent_email") or "").casefold(),
        str(item.get("key") or ""),
    ))
    return merged


def _disable_depleted_device_pro_account(
    provider: str,
    provider_id: int,
    expected_epoch: str,
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Disable one exact, confirmed-empty PRO or mapped TEAM credential.

    The legacy function name is retained for test/call-site compatibility. A
    TEAM/BUSINESS row must additionally carry one authoritative mapped child
    lifecycle; an unmapped/conflicting row is display-only even when its quota
    payload contains a numeric zero.
    """
    plan = remote.get("plan")
    is_pro = monitor.is_pro_plan(plan)
    is_team = monitor.is_team_plan(plan)
    if not is_pro and not is_team:
        raise RuntimeError("plan_not_quota_managed")
    if (
        str(remote.get("quota_error_code") or "").strip()
        or remote.get("account_issue") is True
        or remote.get("quota_http_status") not in (None, "", 0)
    ):
        raise RuntimeError("quota_or_account_abnormal")
    if is_team:
        navigation = _safe_team_navigation(remote)
        if str(navigation.get("state") or "") != "mapped":
            raise RuntimeError("team_mapping_not_authoritative")
    remaining = remote.get("remaining_percent")
    if (
        isinstance(remaining, bool)
        or not isinstance(remaining, (int, float))
        or float(remaining) != 0.0
        or remote.get("quota_checked") is not True
        or str(remote.get("usage_status") or "").strip().lower()
        not in {"ok", "limit_reached"}
    ):
        raise RuntimeError("quota_not_confirmed_depleted")
    remote_id = str(remote.get("remote_id") or "").strip()
    if not remote_id:
        raise RuntimeError("remote_identity_missing")
    if not _device_epoch_is_current(provider, provider_id, expected_epoch):
        raise RuntimeError("device_changed")
    return monitor.disable_exact_account(
        monitor.device_key(provider, provider_id),
        remote_id,
        expected_email=str(remote.get("email") or "").strip(),
        expected_name=str(remote.get("name") or "").strip(),
        before_mutation=lambda: _device_epoch_is_current(
            provider,
            provider_id,
            expected_epoch,
        ),
    )


class _RefundedParentCleanupError(RuntimeError):
    """Closed diagnostic used by the refunded-parent cleanup boundary."""

    def __init__(self, code: str):
        super().__init__(str(code or "cleanup_failed"))
        self.code = str(code or "cleanup_failed")


def _refunded_parent_policy_matches_device(
    row: Optional[GptBusinessAutomationPolicyModel],
    provider: str,
    provider_id: int,
) -> bool:
    if row is None:
        return False
    delivery_type = str(row.delivery_type or "").strip().lower()
    if provider == "cpa":
        return bool(
            delivery_type in {"", "cpa"}
            and int(row.cpa_target_id or 0) == int(provider_id)
            and int(row.sub2api_device_id or 0) <= 0
        )
    return bool(
        provider == "sub2api"
        and delivery_type in {"", "sub2api"}
        and int(row.sub2api_device_id or 0) == int(provider_id)
        and int(row.cpa_target_id or 0) <= 0
    )


def _refunded_parent_cleanup_ids(
    provider: str,
    provider_id: int,
) -> list[int]:
    """Return only bound mothers in the canonical pending-credit state."""
    with Session(engine) as session:
        policies = list(session.exec(
            select(GptBusinessAutomationPolicyModel)
        ).all())
        parent_ids = sorted({
            int(row.business_account_id)
            for row in policies
            if int(row.business_account_id or 0) > 0
            and _refunded_parent_policy_matches_device(
                row, provider, int(provider_id),
            )
        })
        if not parent_ids:
            return []
        parents = {
            int(row.id or 0): row
            for row in session.exec(
                select(GptBusinessAccountModel).where(
                    GptBusinessAccountModel.id.in_(parent_ids)  # type: ignore[union-attr]
                )
            ).all()
        }
    return [
        parent_id for parent_id in parent_ids
        if str(
            getattr(parents.get(parent_id), "refund_status", "") or ""
        ).strip().lower() == _REFUNDED_PARENT_CLEANUP_STATUS
    ]


def _refunded_parent_cleanup_safe_message(code: str) -> str:
    return {
        "cleanup_busy": "母号或子号正在执行其他操作，已保留设备绑定",
        "device_changed": "设备配置在清理期间发生变化，已保留设备绑定",
        "binding_changed": "母号设备绑定在清理期间发生变化，未重复处理",
        "refund_state_changed": "母号退款状态已变化，已保留设备绑定",
        "identity_conflict": "设备账号与本地子号归属不一致，已保留设备绑定",
        "remote_delete_failed": "设备账号删除或缺失确认失败，已保留设备绑定",
        "commit_failed": "设备账号已核对，但解除绑定未能安全提交",
    }.get(str(code or ""), "退款母号设备清理未完成，已保留设备绑定")


def _current_business_parent_refund_status(parent_id: int) -> str:
    try:
        with Session(engine) as session:
            parent = session.get(GptBusinessAccountModel, int(parent_id))
            return str(parent.refund_status or "").strip().lower() if parent else ""
    except Exception:
        return ""


def _refunded_parent_cleanup_plan(
    parent_id: int,
    provider: str,
    provider_id: int,
    remote_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an exact parent/child/membership/device cleanup snapshot.

    Email is only collision evidence.  Destructive candidates require either
    an exact persisted device remote id or the monitor's exact active
    parent/child/membership navigation tuple.  An email-only or ambiguous row
    blocks the whole parent and therefore can never authorize a delete.
    """
    from api import gpt_business

    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, int(parent_id))
        policy = session.get(GptBusinessAutomationPolicyModel, int(parent_id))
        if parent is None:
            raise _RefundedParentCleanupError("identity_conflict")
        if str(parent.refund_status or "").strip().lower() != (
            _REFUNDED_PARENT_CLEANUP_STATUS
        ):
            raise _RefundedParentCleanupError("refund_state_changed")
        if not _refunded_parent_policy_matches_device(
            policy, provider, int(provider_id),
        ):
            raise _RefundedParentCleanupError("binding_changed")
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel)
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(parent_id)
            )
            .where(
                GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
            )
        ).all())
        children = {
            int(row.id or 0): row
            for row in session.exec(
                select(GptProAccountModel).where(
                    GptProAccountModel.id.in_([
                        int(item.pro_account_id)
                        for item in memberships
                        if int(item.pro_account_id or 0) > 0
                    ])  # type: ignore[union-attr]
                )
            ).all()
        } if any(int(item.pro_account_id or 0) > 0 for item in memberships) else {}

        identities: list[dict[str, Any]] = []
        identity_by_membership: dict[int, dict[str, Any]] = {}
        linked_remote: dict[str, dict[str, Any]] = {}
        email_owners: dict[str, list[dict[str, Any]]] = {}
        for membership in memberships:
            membership_id = int(membership.id or 0)
            child_id = int(membership.pro_account_id or 0)
            child = children.get(child_id) if child_id > 0 else None
            if child_id > 0 and (
                child is None
                or int(child.business_parent_id or 0) != int(parent_id)
            ):
                raise _RefundedParentCleanupError("identity_conflict")
            emails = {
                _normalized_delivery_email(membership.email),
                _normalized_delivery_email(child.email) if child else "",
            }
            emails.discard("")
            link: dict[str, Any] = {}
            if child is not None:
                links, incomplete = gpt_business._business_child_delivery_links(
                    child
                )
                if incomplete or len(links) > 1:
                    raise _RefundedParentCleanupError("identity_conflict")
                matching = [
                    item for item in links
                    if str(item.get("provider") or "") == provider
                    and int(item.get("device_id") or 0) == int(provider_id)
                ]
                if len(matching) > 1:
                    raise _RefundedParentCleanupError("identity_conflict")
                link = dict(matching[0]) if matching else {}
            identity = {
                "membership_id": membership_id,
                "child_id": child_id,
                "email": str(
                    (child.email if child else membership.email) or ""
                ).strip(),
                "emails": sorted(emails),
                "link": link,
            }
            identities.append(identity)
            if membership_id > 0:
                identity_by_membership[membership_id] = identity
            for email in emails:
                email_owners.setdefault(email, []).append(identity)
            remote_id = str(link.get("remote_id") or "").strip()
            if remote_id:
                if remote_id in linked_remote:
                    raise _RefundedParentCleanupError("identity_conflict")
                linked_remote[remote_id] = identity

        remote_by_id: dict[str, dict[str, Any]] = {}
        candidates: list[dict[str, Any]] = []
        candidate_ids: set[str] = set()
        for remote in remote_items:
            remote_id = str(remote.get("remote_id") or "").strip()
            if not remote_id:
                continue
            if remote_id in remote_by_id:
                raise _RefundedParentCleanupError("identity_conflict")
            remote_by_id[remote_id] = remote
            navigation = (
                remote.get("navigation")
                if isinstance(remote.get("navigation"), dict)
                else {}
            )
            mapped_to_parent = bool(
                str(navigation.get("state") or "").strip().lower() == "mapped"
                and str(navigation.get("target_kind") or "").strip().lower()
                == "business_child"
                and _inventory_positive_int(
                    navigation.get("business_parent_id")
                ) == int(parent_id)
            )
            email = _normalized_delivery_email(remote.get("email"))
            touches_parent = bool(
                remote_id in linked_remote
                or (email and email in email_owners)
                or mapped_to_parent
            )
            if not touches_parent:
                continue
            if not mapped_to_parent:
                raise _RefundedParentCleanupError("identity_conflict")
            membership_id = _inventory_positive_int(
                navigation.get("membership_id")
            )
            child_id = _inventory_positive_int(navigation.get("pro_account_id"))
            identity = identity_by_membership.get(membership_id)
            if not (
                identity
                and child_id > 0
                and int(identity.get("child_id") or 0) == child_id
                and (not email or email in set(identity.get("emails") or []))
            ):
                raise _RefundedParentCleanupError("identity_conflict")
            linked_identity = linked_remote.get(remote_id)
            if linked_identity is not None and linked_identity is not identity:
                raise _RefundedParentCleanupError("identity_conflict")
            if remote_id not in candidate_ids:
                candidates.append(dict(remote))
                candidate_ids.add(remote_id)

        # An exact persisted remote id found in the complete inventory must
        # also have passed the exact lifecycle validation above.
        for remote_id in linked_remote:
            if remote_id in remote_by_id and remote_id not in candidate_ids:
                raise _RefundedParentCleanupError("identity_conflict")

        return {
            "parent_id": int(parent_id),
            "parent_email": str(parent.email or "").strip(),
            "parent_note": str(parent.note or "").strip(),
            "policy_revision": int(policy.revision or 0),
            "identities": identities,
            "child_ids": sorted({
                int(item["child_id"])
                for item in identities
                if int(item.get("child_id") or 0) > 0
            }),
            "candidates": candidates,
        }


def _acquire_refunded_parent_child_leases(
    parent_id: int,
    child_ids: list[int],
    operation_id: str,
    worker_token: str,
) -> None:
    """Fence account-local device writes while the parent lease is held."""
    now = _utcnow()
    expires = now + timedelta(seconds=_REFUNDED_PARENT_CLEANUP_LEASE_SECONDS)
    with Session(engine) as session:
        parent_lease = session.get(
            GptBusinessAllocationLeaseModel, f"parent:{int(parent_id)}",
        )
        if not (
            parent_lease
            and str(parent_lease.job_id or "") == str(operation_id)
            and str(parent_lease.owner_token or "") == str(worker_token)
            and _active_lease(parent_lease.expires_at, now)
        ):
            raise _RefundedParentCleanupError("cleanup_busy")
        for child_id in sorted({int(value) for value in child_ids if int(value) > 0}):
            claim = session.get(GptProAccountOperationLeaseModel, child_id)
            if claim and not _active_lease(claim.expires_at, now):
                session.delete(claim)
                session.flush()
                claim = None
            if claim and not (
                str(claim.token or "") == str(worker_token)
                and str(claim.operation or "")
                == _REFUNDED_PARENT_CLEANUP_OPERATION
            ):
                session.rollback()
                raise _RefundedParentCleanupError("cleanup_busy")
            if claim is None:
                claim = GptProAccountOperationLeaseModel(
                    account_id=child_id,
                    operation=_REFUNDED_PARENT_CLEANUP_OPERATION,
                    token=str(worker_token),
                    expires_at=expires,
                    created_at=now,
                    updated_at=now,
                )
            else:
                claim.expires_at = expires
                claim.updated_at = now
            session.add(claim)
        session.commit()


def _release_refunded_parent_child_leases(
    child_ids: list[int],
    worker_token: str,
) -> None:
    try:
        with Session(engine) as session:
            for child_id in sorted({
                int(value) for value in child_ids if int(value) > 0
            }):
                claim = session.get(GptProAccountOperationLeaseModel, child_id)
                if (
                    claim
                    and str(claim.token or "") == str(worker_token)
                    and str(claim.operation or "")
                    == _REFUNDED_PARENT_CLEANUP_OPERATION
                ):
                    session.delete(claim)
            session.commit()
    except Exception:
        # The finite lease is the crash-recovery fence.  Never mask the public
        # cleanup result merely because best-effort release failed.
        pass


def _refunded_parent_cleanup_claim_is_current(
    plan: dict[str, Any],
    provider: str,
    provider_id: int,
    expected_epoch: str,
    operation_id: str,
    worker_token: str,
) -> bool:
    from api import gpt_business

    parent_id = int(plan.get("parent_id") or 0)
    try:
        gpt_business._renew_workspace_refresh_parent_lease(
            parent_id, operation_id, worker_token,
        )
        if not _device_epoch_is_current(
            provider, int(provider_id), expected_epoch,
        ):
            return False
        now = _utcnow()
        with Session(engine) as session:
            parent = session.get(GptBusinessAccountModel, parent_id)
            policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
            lease = session.get(
                GptBusinessAllocationLeaseModel, f"parent:{parent_id}",
            )
            if not (
                parent
                and str(parent.refund_status or "").strip().lower()
                == _REFUNDED_PARENT_CLEANUP_STATUS
                and _refunded_parent_policy_matches_device(
                    policy, provider, int(provider_id),
                )
                and int(policy.revision or 0)
                == int(plan.get("policy_revision") or 0)
                and lease
                and str(lease.job_id or "") == str(operation_id)
                and str(lease.owner_token or "") == str(worker_token)
                and _active_lease(lease.expires_at, now)
            ):
                return False
            for identity in list(plan.get("identities") or []):
                child_id = int(identity.get("child_id") or 0)
                membership_id = int(identity.get("membership_id") or 0)
                membership = session.get(
                    GptBusinessChildMembershipModel, membership_id,
                )
                if not (
                    membership
                    and membership.ended_at is None
                    and int(membership.business_account_id or 0) == parent_id
                    and int(membership.pro_account_id or 0) == child_id
                ):
                    return False
                if child_id <= 0:
                    continue
                child = session.get(GptProAccountModel, child_id)
                claim = session.get(GptProAccountOperationLeaseModel, child_id)
                if not (
                    child
                    and int(child.business_parent_id or 0) == parent_id
                    and claim
                    and str(claim.token or "") == str(worker_token)
                    and str(claim.operation or "")
                    == _REFUNDED_PARENT_CLEANUP_OPERATION
                    and _active_lease(claim.expires_at, now)
                ):
                    return False
                expected_link = (
                    identity.get("link")
                    if isinstance(identity.get("link"), dict)
                    else {}
                )
                expected_remote_id = str(
                    expected_link.get("remote_id") or ""
                ).strip()
                links, incomplete = (
                    gpt_business._business_child_delivery_links(child)
                )
                matching = [
                    item for item in links
                    if str(item.get("provider") or "") == provider
                    and int(item.get("device_id") or 0) == int(provider_id)
                ]
                if (
                    incomplete
                    or len(links) > 1
                    or len(matching) > 1
                    or str(
                        (matching[0] if matching else {}).get("remote_id")
                        or ""
                    ).strip() != expected_remote_id
                ):
                    return False
        return True
    except Exception:
        return False


def _refunded_parent_plan_identity_signature(
    plan: dict[str, Any],
) -> tuple[tuple[int, int, str, str], ...]:
    return tuple(sorted(
        (
            int(item.get("membership_id") or 0),
            int(item.get("child_id") or 0),
            _normalized_delivery_email(item.get("email")),
            str(
                (
                    item.get("link")
                    if isinstance(item.get("link"), dict)
                    else {}
                ).get("remote_id")
                or ""
            ).strip(),
        )
        for item in list(plan.get("identities") or [])
    ))


def _finalize_refunded_parent_absence_snapshot(
    plan: dict[str, Any],
    provider: str,
    provider_id: int,
    expected_epoch: str,
    operation_id: str,
    worker_token: str,
) -> dict[str, Any]:
    """Persist a final full inventory and prove this parent has no remotes."""
    if not _refunded_parent_cleanup_claim_is_current(
        plan, provider, int(provider_id), expected_epoch,
        operation_id, worker_token,
    ):
        raise _RefundedParentCleanupError("device_changed")
    try:
        refreshed = monitor.refresh_device_pro_inventory(
            monitor.device_key(provider, int(provider_id))
        )
    except Exception as exc:
        raise _RefundedParentCleanupError("remote_delete_failed") from exc
    if not bool(refreshed.get("ok")) or not _device_epoch_is_current(
        provider, int(provider_id), expected_epoch,
    ):
        raise _RefundedParentCleanupError("remote_delete_failed")
    final_items = [
        dict(item) for item in list(refreshed.get("items") or [])
        if isinstance(item, dict)
    ]
    final_plan = _refunded_parent_cleanup_plan(
        int(plan.get("parent_id") or 0),
        provider,
        int(provider_id),
        final_items,
    )
    if _refunded_parent_plan_identity_signature(final_plan) != (
        _refunded_parent_plan_identity_signature(plan)
    ):
        raise _RefundedParentCleanupError("identity_conflict")
    if list(final_plan.get("candidates") or []):
        raise _RefundedParentCleanupError("remote_delete_failed")
    if not _refunded_parent_cleanup_claim_is_current(
        final_plan, provider, int(provider_id), expected_epoch,
        operation_id, worker_token,
    ):
        raise _RefundedParentCleanupError("device_changed")
    return final_plan


def _best_effort_refresh_refunded_cleanup_snapshot(
    provider: str,
    provider_id: int,
    expected_epoch: str,
) -> None:
    """Persist current device rows after a partially successful delete batch."""
    try:
        if not _device_epoch_is_current(
            provider, int(provider_id), expected_epoch,
        ):
            return
        monitor.refresh_device_pro_inventory(
            monitor.device_key(provider, int(provider_id))
        )
    except Exception:
        # Snapshot refresh is observability recovery only.  It must never turn
        # a fail-closed partial cleanup into an unbind or hide the first error.
        pass


def _clear_refunded_parent_child_device_link(
    child: GptProAccountModel,
    *,
    provider: str,
    provider_id: int,
    remote_id: str,
    remote_deleted: bool,
    now: datetime,
) -> None:
    extra = _json_object(child.extra_json)
    if provider == "cpa":
        for key in _REFUNDED_PARENT_CPA_LINK_FIELDS:
            extra.pop(key, None)
        extra["cpa_last_removed"] = {
            "target_id": int(provider_id),
            "auth_name": str(remote_id),
            "removed_at": now.isoformat(),
            "reason": "business_parent_refunded_pending_credit",
            "remote_deleted": bool(remote_deleted),
            "remote_absent_confirmed": True,
        }
    else:
        for key in _REFUNDED_PARENT_SUB2API_LINK_FIELDS:
            extra.pop(key, None)
        extra["sub2api_status"] = "unlinked"
        extra["sub2api_last_removed"] = {
            "device_id": int(provider_id),
            "remote_account_id": str(remote_id),
            "removed_at": now.isoformat(),
            "reason": "business_parent_refunded_pending_credit",
            "remote_deleted": bool(remote_deleted),
            "remote_absent_confirmed": True,
        }
    child.extra_json = json.dumps(extra, ensure_ascii=False)
    child.updated_at = now


def _commit_refunded_parent_device_unbind(
    plan: dict[str, Any],
    provider: str,
    provider_id: int,
    expected_epoch: str,
    operation_id: str,
    worker_token: str,
    removed_remote_ids: set[str],
) -> None:
    """CAS-clear child device links and the policy in one local transaction."""
    from api import gpt_business

    if not _refunded_parent_cleanup_claim_is_current(
        plan, provider, provider_id, expected_epoch,
        operation_id, worker_token,
    ):
        raise _RefundedParentCleanupError("commit_failed")
    parent_id = int(plan.get("parent_id") or 0)
    now = _utcnow()
    affected_batch_ids: set[str] = set()
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            parent = session.get(GptBusinessAccountModel, parent_id)
            policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        else:
            parent = session.exec(
                select(GptBusinessAccountModel)
                .where(GptBusinessAccountModel.id == parent_id)
                .with_for_update()
            ).first()
            policy = session.exec(
                select(GptBusinessAutomationPolicyModel)
                .where(
                    GptBusinessAutomationPolicyModel.business_account_id
                    == parent_id
                )
                .with_for_update()
            ).first()
        parent_lease = session.get(
            GptBusinessAllocationLeaseModel, f"parent:{parent_id}",
        )
        if not (
            parent
            and str(parent.refund_status or "").strip().lower()
            == _REFUNDED_PARENT_CLEANUP_STATUS
            and _refunded_parent_policy_matches_device(
                policy, provider, int(provider_id),
            )
            and int(policy.revision or 0)
            == int(plan.get("policy_revision") or 0)
            and parent_lease
            and str(parent_lease.job_id or "") == str(operation_id)
            and str(parent_lease.owner_token or "") == str(worker_token)
            and _active_lease(parent_lease.expires_at, now)
        ):
            session.rollback()
            raise _RefundedParentCleanupError("commit_failed")

        for identity in list(plan.get("identities") or []):
            child_id = int(identity.get("child_id") or 0)
            membership_id = int(identity.get("membership_id") or 0)
            membership = session.get(
                GptBusinessChildMembershipModel, membership_id,
            )
            if not (
                membership
                and membership.ended_at is None
                and int(membership.business_account_id or 0) == parent_id
                and int(membership.pro_account_id or 0) == child_id
            ):
                session.rollback()
                raise _RefundedParentCleanupError("commit_failed")
            link = (
                identity.get("link")
                if isinstance(identity.get("link"), dict)
                else {}
            )
            expected_remote_id = str(link.get("remote_id") or "").strip()
            if child_id <= 0:
                if expected_remote_id:
                    session.rollback()
                    raise _RefundedParentCleanupError("commit_failed")
                continue
            child = session.get(GptProAccountModel, child_id)
            claim = session.get(GptProAccountOperationLeaseModel, child_id)
            if not (
                child
                and int(child.business_parent_id or 0) == parent_id
                and claim
                and str(claim.token or "") == str(worker_token)
                and str(claim.operation or "")
                == _REFUNDED_PARENT_CLEANUP_OPERATION
                and _active_lease(claim.expires_at, now)
            ):
                session.rollback()
                raise _RefundedParentCleanupError("commit_failed")
            links, incomplete = gpt_business._business_child_delivery_links(child)
            matching = [
                item for item in links
                if str(item.get("provider") or "") == provider
                and int(item.get("device_id") or 0) == int(provider_id)
            ]
            if incomplete or len(links) > 1 or len(matching) > 1:
                session.rollback()
                raise _RefundedParentCleanupError("commit_failed")
            current_remote_id = str(
                (matching[0] if matching else {}).get("remote_id") or ""
            ).strip()
            if current_remote_id != expected_remote_id:
                session.rollback()
                raise _RefundedParentCleanupError("commit_failed")
            if expected_remote_id:
                _clear_refunded_parent_child_device_link(
                    child,
                    provider=provider,
                    provider_id=int(provider_id),
                    remote_id=expected_remote_id,
                    remote_deleted=expected_remote_id in removed_remote_ids,
                    now=now,
                )
                session.add(child)

        # A waiting/recoverable 401 task for this exact mother/device must not
        # wake after the refunded-parent cleanup has removed its delivery
        # binding.  This changes task coordination only; local account and
        # membership/history rows remain untouched.
        active_tasks = session.exec(
            select(DeliveryDeviceTeam401TaskModel)
            .where(DeliveryDeviceTeam401TaskModel.provider == provider)
            .where(
                DeliveryDeviceTeam401TaskModel.provider_id == int(provider_id)
            )
            .where(
                DeliveryDeviceTeam401TaskModel.business_parent_id == parent_id
            )
            .where(
                DeliveryDeviceTeam401TaskModel.state.not_in(
                    list(_TEAM401_TERMINAL_STATES)
                )
            )
        ).all()
        for task in active_tasks:
            task.state = "cancelled"
            task.stage = "failed"
            task.result = "failed"
            task.error_code = "business_parent_refunded_pending_credit"
            task.worker_token = ""
            task.lease_expires_at = None
            task.next_check_at = None
            task.completed_at = task.completed_at or now
            task.updated_at = now
            _team401_append_log(
                task,
                stage="failed",
                error_code="business_parent_refunded_pending_credit",
            )
            affected_batch_ids.add(str(task.batch_id or ""))
            session.add(task)

        policy.auto_rotation_enabled = False
        policy.delivery_type = ""
        policy.cpa_target_id = None
        policy.sub2api_device_id = None
        policy.revision = int(policy.revision or 0) + 1
        policy.last_scan_at = now
        policy.last_error = ""
        policy.updated_at = now
        session.add(policy)
        session.commit()
    for batch_id in sorted(value for value in affected_batch_ids if value):
        try:
            _team401_recompute_batch(batch_id)
        except Exception:
            # The task rows and device unbind already committed atomically.
            # Aggregate repair is derived state and must never relabel that
            # irreversible success as a failed/unbound-false response.
            pass


def _cleanup_one_refunded_parent_binding(
    parent_id: int,
    provider: str,
    provider_id: int,
    expected_epoch: str,
    remote_items: list[dict[str, Any]],
) -> tuple[dict[str, Any], set[str]]:
    """Delete all exact child credentials, then atomically remove the binding."""
    from api import gpt_business

    result: dict[str, Any] = {
        "parent_id": int(parent_id),
        "parent_email": "",
        "parent_note": "",
        "refund_status": "",
        "status": "failed",
        "binding_removed": False,
        "removed_accounts": [],
        "failed_accounts": [],
        "message": "退款母号设备清理未完成，已保留设备绑定",
    }
    removed_ids: set[str] = set()
    child_ids: list[int] = []
    operation_id = ""
    worker_token = ""
    current_remote: Optional[dict[str, Any]] = None
    try:
        with gpt_business._business_parent_mutation_lock(int(parent_id)):
            try:
                operation_id, worker_token = (
                    gpt_business._acquire_workspace_refresh_parent_lease(
                        int(parent_id)
                    )
                )
            except Exception as exc:
                raise _RefundedParentCleanupError("cleanup_busy") from exc
            try:
                plan = _refunded_parent_cleanup_plan(
                    int(parent_id), provider, int(provider_id), remote_items,
                )
                result["parent_email"] = _safe_child_progress_email(
                    plan.get("parent_email")
                )
                result["parent_note"] = _safe_inventory_note(
                    plan.get("parent_note")
                )
                result["refund_status"] = _REFUNDED_PARENT_CLEANUP_STATUS
                child_ids = list(plan.get("child_ids") or [])
                _acquire_refunded_parent_child_leases(
                    int(parent_id), child_ids, operation_id, worker_token,
                )
                internal = _internal_device_or_error(provider, int(provider_id))

                def guard() -> bool:
                    return _refunded_parent_cleanup_claim_is_current(
                        plan, provider, int(provider_id), expected_epoch,
                        operation_id, worker_token,
                    )

                for current_remote in list(plan.get("candidates") or []):
                    if not guard():
                        raise _RefundedParentCleanupError("device_changed")
                    if provider == "cpa":
                        _delete_cpa_remote_exact(
                            internal, current_remote, before_mutation=guard,
                        )
                    else:
                        _delete_sub2api_remote_exact(
                            internal, current_remote, before_mutation=guard,
                        )
                    remote_id = str(current_remote.get("remote_id") or "").strip()
                    removed_ids.add(remote_id)
                    result["removed_accounts"].append({
                        "remote_id": _safe_inventory_remote_id(remote_id),
                        "email": _safe_child_progress_email(
                            current_remote.get("email")
                        ),
                    })
                    current_remote = None

                plan = _finalize_refunded_parent_absence_snapshot(
                    plan,
                    provider,
                    int(provider_id),
                    expected_epoch,
                    operation_id,
                    worker_token,
                )
                try:
                    _commit_refunded_parent_device_unbind(
                        plan,
                        provider,
                        int(provider_id),
                        expected_epoch,
                        operation_id,
                        worker_token,
                        removed_ids,
                    )
                except _RefundedParentCleanupError:
                    raise
                except Exception as exc:
                    raise _RefundedParentCleanupError(
                        "commit_failed"
                    ) from exc
                result["status"] = "cleaned"
                result["binding_removed"] = True
                result["message"] = (
                    f"母号已退款未到账，已删除 {len(removed_ids)} 个设备账号并解除绑定"
                    if removed_ids
                    else "母号已退款未到账，设备中无关联账号，已解除绑定"
                )
            finally:
                _release_refunded_parent_child_leases(child_ids, worker_token)
                if operation_id and worker_token:
                    try:
                        gpt_business._release_workspace_refresh_parent_lease(
                            int(parent_id), operation_id, worker_token,
                        )
                    except Exception:
                        pass
    except _RefundedParentCleanupError as exc:
        result["refund_status"] = _current_business_parent_refund_status(
            int(parent_id)
        )
        if current_remote is not None:
            result["failed_accounts"].append({
                "remote_id": _safe_inventory_remote_id(
                    current_remote.get("remote_id")
                ),
                "email": _safe_child_progress_email(
                    current_remote.get("email")
                ),
                "error": _refunded_parent_cleanup_safe_message(exc.code),
            })
        result["message"] = _refunded_parent_cleanup_safe_message(exc.code)
    except Exception:
        result["refund_status"] = _current_business_parent_refund_status(
            int(parent_id)
        )
        if current_remote is not None:
            result["failed_accounts"].append({
                "remote_id": _safe_inventory_remote_id(
                    current_remote.get("remote_id")
                ),
                "email": _safe_child_progress_email(
                    current_remote.get("email")
                ),
                "error": _refunded_parent_cleanup_safe_message(
                    "remote_delete_failed"
                ),
            })
        result["message"] = _refunded_parent_cleanup_safe_message(
            "remote_delete_failed"
        )
    if removed_ids and not bool(result.get("binding_removed")):
        _best_effort_refresh_refunded_cleanup_snapshot(
            provider, int(provider_id), expected_epoch,
        )
    return result, removed_ids


def _cleanup_refunded_parent_bindings(
    provider: str,
    provider_id: int,
    expected_epoch: str,
    remote_items: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    cleanups: list[dict[str, Any]] = []
    removed_remote_ids: set[str] = set()
    for parent_id in _refunded_parent_cleanup_ids(provider, int(provider_id)):
        result, removed = _cleanup_one_refunded_parent_binding(
            parent_id,
            provider,
            int(provider_id),
            expected_epoch,
            remote_items,
        )
        cleanups.append(result)
        removed_remote_ids.update(removed)
    return cleanups, removed_remote_ids


def _empty_pro_inventory_result() -> dict[str, Any]:
    return {
        # Device refresh is a read-only remote inventory/quota workflow.  Its
        # only writes are the sanitized local snapshot rows persisted by the
        # monitor service; remote credentials and BUSINESS lifecycle state are
        # never changed here.
        "mode": "inventory_quota_scan",
        "scanned": 0,
        "pro": 0,
        "healthy": 0,
        "depleted": 0,
        # Compatibility counter: refresh never increments it because remote
        # credential disabling is no longer a device-refresh capability.
        "disabled": 0,
        "failed": 0,
        "skipped": 0,
        "team": 0,
        "team_healthy": 0,
        "team_depleted": 0,
        "team_failed": 0,
        "team_abnormal": 0,
        "warning": "",
        "account_results": [],
        # Kept only as a stable empty compatibility field. Refresh no longer
        # resolves TEAM accounts to mothers or builds parent groups.
        "team_groups": [],
        "refunded_parent_cleanups": [],
        "business_reconciliation": {
            "bound_parents": 0,
            "fill_started": 0,
        },
    }


class _InventoryRefreshError(RuntimeError):
    """Closed first-scan diagnostic safe for task logs and DTOs."""

    def __init__(self, message: str):
        self.public_message = str(message or "设备账号清单刷新失败")[:200]
        super().__init__(self.public_message)


def _safe_inventory_refresh_error(provider: str, value: Any) -> str:
    """Allow only monitor-produced list failure text and an HTTP status."""
    label = "CPA" if str(provider) == "cpa" else "Sub2API"
    raw = str(value or "").strip()
    match = re.fullmatch(
        r"(?:CPA|Sub2API) 远端账号读取失败(?: \(HTTP ([1-5][0-9]{2})\))?",
        raw,
    )
    if match:
        status = str(match.group(1) or "")
        return (
            f"{label} 远端账号读取失败（HTTP {status}）"
            if status
            else f"{label} 远端账号读取失败"
        )
    return f"{label} 远端账号读取失败"


def _run_delivery_inventory_refresh_task(task_id: str) -> None:
    """Refresh only the remote account inventory and quota snapshots.

    A refresh must stay observational: zero quota, HTTP 401, a missing TEAM
    credential or a refunded mother are returned as account state only.  This
    worker must not disable/delete a remote credential or enter BUSINESS
    remove/invite/OAuth/RT/upload/replenishment/correction capabilities.
    """
    with _REFRESH_TASK_LOCK:
        task = _REFRESH_TASKS.get(str(task_id))
        if not task:
            return
        task["status"] = "running"
        task["stage"] = "scanning_inventory"
        task["started_at"] = _iso_now()
        task["updated_at"] = task["started_at"]
        device_ref = str(task.get("device_ref") or "")
        provider = str(task.get("provider") or "")
        provider_id = int(task.get("provider_id") or 0)
    summary = _empty_pro_inventory_result()
    try:
        expected_epoch = _device_epoch(provider, provider_id)
        _refresh_task_update(task_id, stage="scanning_inventory")
        _refresh_task_log(task_id, "正在扫描设备账号清单")
        refreshed = monitor.refresh_device_pro_inventory(
            device_ref,
            before_persist=lambda: _device_epoch_is_current(
                provider,
                provider_id,
                expected_epoch,
            ),
        )
        if not bool(refreshed.get("ok")):
            raise _InventoryRefreshError(_safe_inventory_refresh_error(
                provider,
                refreshed.get("refresh_error"),
            ))
        if not _device_epoch_is_current(provider, provider_id, expected_epoch):
            raise RuntimeError("device_changed")
        items = [
            dict(item)
            for item in list(refreshed.get("items") or [])
            if isinstance(item, dict)
        ]
        summary["scanned"] = len(items)
        _refresh_task_update(
            task_id,
            stage="checking_pro_quota",
            done=0,
            total=len(items),
        )
        _refresh_task_log(
            task_id,
            f"账号清单扫描完成，共 {len(items)} 个账号",
        )
        _refresh_task_log(
            task_id,
            "正在识别套餐并查询 PRO 与 TEAM/BUSINESS 子号额度",
        )

        account_results: list[dict[str, Any]] = []
        for remote in items:
            plan = _safe_inventory_plan(remote.get("plan"))
            if not plan:
                summary["skipped"] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=None,
                    status="skipped",
                    action="none",
                    result="plan_unknown",
                    message="套餐类型无法识别，未查询额度",
                ))
                continue
            if monitor.is_team_plan(plan):
                summary["team"] += 1
                if bool(remote.get("disabled")):
                    summary["skipped"] += 1
                    account_results.append(_inventory_account_result(
                        provider,
                        provider_id,
                        remote,
                        remaining_percent=remote.get("remaining_percent"),
                        status="disabled",
                        action="none",
                        result="already_disabled",
                        message="TEAM/BUSINESS 子号凭证当前已在设备中禁用",
                    ))
                    continue
                remaining = remote.get("remaining_percent")
                quota_status = str(
                    remote.get("usage_status") or ""
                ).strip().lower()
                quota_confirmed = bool(
                    remote.get("quota_checked") is True
                    and quota_status in {"ok", "limit_reached"}
                    and not str(remote.get("quota_error_code") or "").strip()
                    and remote.get("account_issue") is not True
                    and remote.get("quota_http_status") in (None, "", 0)
                    and not isinstance(remaining, bool)
                    and isinstance(remaining, (int, float))
                    and 0.0 <= float(remaining) <= 100.0
                )
                if not quota_confirmed:
                    summary["team_abnormal"] += 1
                    summary["team_failed"] += 1
                    account_results.append(_inventory_account_result(
                        provider,
                        provider_id,
                        remote,
                        remaining_percent=None,
                        status="failed",
                        action="none",
                        result="quota_unknown",
                        message="TEAM/BUSINESS 子号额度查询失败，仅记录状态",
                    ))
                    continue
                public_remaining: float | int = (
                    int(float(remaining))
                    if float(remaining).is_integer()
                    else float(remaining)
                )
                depleted = float(remaining) == 0.0
                summary[
                    "team_depleted" if depleted else "team_healthy"
                ] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=public_remaining,
                    status="depleted" if depleted else "healthy",
                    action="none",
                    result="depleted" if depleted else "healthy",
                    message=(
                        "TEAM/BUSINESS 子号剩余额度为 0%，仅记录状态"
                        if depleted
                        else "TEAM/BUSINESS 子号额度正常，仅记录状态"
                    ),
                ))
                continue
            if not monitor.is_pro_plan(plan):
                summary["skipped"] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=None,
                    status="skipped",
                    action="none",
                    result="non_pro",
                    message="非 PRO 套餐，未查询额度",
                ))
                continue
            summary["pro"] += 1
            if bool(remote.get("disabled")):
                summary["skipped"] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=None,
                    status="disabled",
                    action="none",
                    result="already_disabled",
                    message="PRO 账号已在设备中禁用",
                ))
                continue
            remaining = remote.get("remaining_percent")
            quota_status = str(
                remote.get("usage_status") or ""
            ).strip().lower()
            quota_confirmed = bool(
                remote.get("quota_checked") is True
                and quota_status in {"ok", "limit_reached"}
                and not str(remote.get("quota_error_code") or "").strip()
                and remote.get("account_issue") is not True
                and remote.get("quota_http_status") in (None, "", 0)
                and not isinstance(remaining, bool)
                and isinstance(remaining, (int, float))
                and 0.0 <= float(remaining) <= 100.0
            )
            if not quota_confirmed:
                summary["failed"] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=None,
                    status="failed",
                    action="none",
                    result="quota_unknown",
                    message="PRO 额度查询失败或结果不明确，仅记录状态",
                ))
                continue
            public_remaining: float | int = (
                int(float(remaining))
                if float(remaining).is_integer()
                else float(remaining)
            )
            if float(remaining) > 0.0:
                summary["healthy"] += 1
                account_results.append(_inventory_account_result(
                    provider,
                    provider_id,
                    remote,
                    remaining_percent=public_remaining,
                    status="healthy",
                    action="none",
                    result="healthy",
                    message="PRO 账号剩余额度大于 0%，保持启用",
                ))
                continue
            summary["depleted"] += 1
            account_results.append(_inventory_account_result(
                provider,
                provider_id,
                remote,
                remaining_percent=public_remaining,
                status="depleted",
                action="none",
                result="depleted",
                message="PRO 账号剩余额度为 0%，仅记录状态",
            ))

        _refresh_task_update(
            task_id,
            stage="finalizing_inventory",
            done=len(items),
            total=len(items),
        )
        summary["account_results"] = account_results
        # Refresh stops at the inventory boundary. All BUSINESS replacement,
        # upload, invitation, RT and replenishment capabilities are not device
        # refresh capabilities and are never attached to this task.
        counts = {
            "success": (
                int(summary["healthy"])
                + int(summary["depleted"])
                + int(summary["team_healthy"])
                + int(summary["team_depleted"])
            ),
            "skipped": int(summary["skipped"]),
            "failed": (
                int(summary["failed"])
                + int(summary["team_failed"])
            ),
        }
        terminal_stage = (
            "completed_with_warning"
            if (
                summary["failed"]
                or summary["team_failed"]
            )
            else "completed"
        )
        warning_parts: list[str] = []
        if summary["failed"]:
            warning_parts.append(
                f"{summary['failed']} 个 PRO 账号额度未知，状态需复核"
            )
        if summary["team_failed"]:
            warning_parts.append(
                f"{summary['team_failed']} 个 TEAM/BUSINESS 子号额度或归属状态需复核"
            )
        summary["warning"] = "；".join(warning_parts)
        _refresh_task_log(
            task_id,
            (
                f"设备刷新完成：扫描 {summary['scanned']} 个账号，"
                f"PRO {summary['pro']} 个，TEAM/BUSINESS {summary['team']} 个"
            ),
        )
        _refresh_task_update(
            task_id,
            status="completed",
            stage=terminal_stage,
            done=len(items),
            total=len(items),
            counts=counts,
            result=summary,
            error="",
        )
    except Exception as exc:
        public_error = (
            exc.public_message
            if isinstance(exc, _InventoryRefreshError)
            else "设备账号清单刷新失败"
        )
        _refresh_task_log(task_id, public_error)
        _refresh_task_update(
            task_id,
            status="failed",
            stage="failed",
            counts={"success": 0, "skipped": 0, "failed": 1},
            result=summary,
            error=public_error,
        )


def _run_delivery_refresh_task(task_id: str) -> None:
    """Compatibility alias fenced to the scan-only refresh worker."""
    return _run_delivery_inventory_refresh_task(task_id)


def start_delivery_device_refresh_task(
    device_ref: str,
    body: Optional[DeliveryDeviceRefreshTaskRequest] = None,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if monitor.get_device(canonical, include_accounts=False) is None:
        raise HTTPException(404, "设备不存在")
    operation_id = str(body.operation_id if body else "").strip()
    if operation_id and not _SAFE_OPERATION_ID.fullmatch(operation_id):
        raise HTTPException(400, "operation_id 格式无效")

    with _REFRESH_TASK_LOCK:
        # Repeat the device check while holding the same lock used by the
        # deletion commit fence. This closes the previous check/register race.
        if monitor.get_device(canonical, include_accounts=False) is None:
            raise HTTPException(404, "设备不存在")
        _prune_refresh_tasks_locked()
        if operation_id:
            prior_id = _REFRESH_TASK_BY_OPERATION.get((canonical, operation_id))
            prior = _REFRESH_TASKS.get(str(prior_id or ""))
            if prior:
                return {
                    "ok": True,
                    "task_id": str(prior["task_id"]),
                    "device_ref": canonical,
                    "status": str(prior.get("status") or "queued"),
                    "reused": True,
                }
        active_id = _REFRESH_ACTIVE_BY_DEVICE.get(canonical)
        active = _REFRESH_TASKS.get(str(active_id or ""))
        if active and str(active.get("status") or "") not in _REFRESH_TASK_TERMINAL:
            return {
                "ok": True,
                "task_id": str(active["task_id"]),
                "device_ref": canonical,
                "status": str(active.get("status") or "queued"),
                "reused": True,
            }

        task_id = f"device-refresh-{uuid.uuid4().hex}"
        now = _iso_now()
        task = {
            "task_id": task_id,
            "operation_id": operation_id,
            "device_ref": canonical,
            "provider": provider,
            "provider_id": provider_id,
            "status": "queued",
            "stage": "queued",
            "logs": [],
            "log_base": 0,
            "done": 0,
            "total": 0,
            "counts": {
                "success": 0,
                "skipped": 0,
                "failed": 0,
            },
            "child_progress": {},
            "_child_log_cursor": 0,
            "result": None,
            "error": "",
            "created_at": now,
            "started_at": "",
            "updated_at": now,
            "finished_at": "",
        }
        _REFRESH_TASKS[task_id] = task
        _REFRESH_ACTIVE_BY_DEVICE[canonical] = task_id
        if operation_id:
            _REFRESH_TASK_BY_OPERATION[(canonical, operation_id)] = task_id
        thread = threading.Thread(
            target=_run_delivery_inventory_refresh_task,
            args=(task_id,),
            name=f"delivery-refresh-{provider}-{provider_id}",
            daemon=True,
        )
        thread.start()
    return {
        "ok": True,
        "task_id": task_id,
        "device_ref": canonical,
        "status": "queued",
        "reused": False,
    }


def _team401_task_request(
    row: DeliveryDeviceTeam401TaskModel,
) -> dict[str, Any]:
    request = _json_object(row.request_json)
    encoded = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != str(
        row.request_hash or ""
    ):
        raise RuntimeError("request_corrupt")
    return request


def _team401_safe_error_code(value: Any, *, default: str = "internal_error") -> str:
    raw = str(value or "").strip().lower()
    if raw in _TEAM401_ERROR_MESSAGES:
        return raw
    mapped = _safe_child_failure_code(raw, default=default)
    return {
        "identity_changed": "identity_changed",
        "operation_busy": "operation_busy",
        "account_check_failed": "account_check_failed",
        "account_state_conflict": "account_state_conflict",
        "account_deactivated": "account_deactivated",
        "oauth_failed": "oauth_failed",
        "oauth_timeout": "oauth_timeout",
        "upload_failed": "upload_failed",
        "device_verify_failed": "device_verify_failed",
        "business_parent_missing": "business_parent_missing",
        "business_parent_disabled": "business_parent_unavailable",
        "business_parent_dangerous": "business_parent_unavailable",
        "business_parent_refunded": "business_parent_unavailable",
        "seat_type_unknown": "seat_type_unknown",
        "candidate_unavailable": "replacement_candidate_unavailable",
        "replenishment_missing": "replenishment_missing",
        "replenishment_action_required": "replenishment_action_required",
    }.get(mapped, default)


def _team401_log_entries(raw: Any) -> list[dict[str, Any]]:
    try:
        value = json.loads(str(raw or "[]"))
    except Exception:
        value = []
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value[-100:]:
        if not isinstance(item, dict):
            continue
        try:
            seq = max(1, int(item.get("seq") or 0))
        except (TypeError, ValueError):
            continue
        stage = str(item.get("stage") or "queued")
        if stage not in _TEAM401_STAGES:
            stage = "queued"
        result.append({
            "seq": seq,
            "stage": stage,
            "message": _safe_task_log_line(item.get("message") or ""),
            "created_at": _safe_public_datetime(item.get("created_at")),
        })
    return result


def _team401_append_log(
    row: DeliveryDeviceTeam401TaskModel,
    *,
    stage: str,
    error_code: str = "",
) -> None:
    logs = _team401_log_entries(row.logs_json)
    message = (
        _TEAM401_ERROR_MESSAGES.get(error_code, "")
        if error_code
        else _TEAM401_STAGE_MESSAGES.get(stage, "纠错任务状态已更新")
    )
    if logs and str(logs[-1].get("stage") or "") == stage and str(
        logs[-1].get("message") or ""
    ) == message:
        return
    logs.append({
        "seq": int(logs[-1].get("seq") or 0) + 1 if logs else 1,
        "stage": stage,
        "message": message,
        "created_at": _iso_now(),
    })
    row.logs_json = json.dumps(
        logs[-100:],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _team401_recompute_batch(batch_id: str) -> None:
    now = _utcnow()
    with Session(engine) as session:
        batch = session.get(DeliveryDeviceTeam401BatchModel, str(batch_id))
        if batch is None:
            return
        tasks = session.exec(
            select(DeliveryDeviceTeam401TaskModel).where(
                DeliveryDeviceTeam401TaskModel.batch_id == str(batch_id)
            )
        ).all()
        total = len(tasks)
        completed = sum(str(row.state or "") == "completed" for row in tasks)
        failed = sum(
            str(row.state or "") in {"failed", "cancelled"}
            for row in tasks
        )
        # ``cancelled`` is a terminal child outcome (for example when its
        # mother entered refunded/pending-credit while queued).  Counting it as
        # active left the enclosing batch permanently stuck in ``running`` and
        # also kept later UI polling alive forever.
        active = total - completed - failed
        batch.total_count = total
        batch.completed_count = completed
        batch.failed_count = failed
        if total > 0 and active == 0:
            batch.state = "completed" if failed == 0 else "failed"
            batch.error_code = "" if failed == 0 else "child_tasks_failed"
            batch.completed_at = batch.completed_at or now
        elif active > 0:
            batch.state = "running"
            batch.error_code = ""
            batch.completed_at = None
        else:
            batch.state = "failed"
            batch.error_code = "no_tasks"
            batch.completed_at = batch.completed_at or now
        batch.updated_at = now
        session.add(batch)
        session.commit()


def _team401_task_checkpoint(
    task_id: str,
    expected_worker_token: str,
    **changes: Any,
) -> bool:
    allowed = {
        "branch", "state", "stage", "result", "error_code",
        "device_delete_confirmed", "account_checked", "oauth_confirmed",
        "device_upload_confirmed", "device_verify_confirmed",
        "cleanup_job_id", "replenishment_demand_id", "fill_job_id",
        "replacement_child_id", "replacement_membership_id",
        "replacement_email", "next_check_at", "completed_at",
        "worker_token", "lease_expires_at",
    }
    batch_id = ""
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        if not row or str(row.worker_token or "") != str(
            expected_worker_token or ""
        ):
            session.rollback()
            return False
        previous_stage = str(row.stage or "queued")
        previous_error = str(row.error_code or "")
        for key, value in changes.items():
            if key not in allowed:
                continue
            if key == "stage":
                value = str(value or "")
                if value not in _TEAM401_STAGES:
                    value = "failed"
            elif key == "branch":
                value = str(value or "checking")
                if value not in {"checking", "repair", "replace"}:
                    value = "checking"
            elif key == "state":
                value = str(value or "running")
                if value not in {
                    "prepared", "queued", "running", "waiting",
                    "completed", "failed", "cancelled",
                }:
                    value = "failed"
            elif key == "result":
                value = str(value or "")
                if value not in _TEAM401_RESULTS:
                    value = "failed"
            elif key == "error_code":
                value = _team401_safe_error_code(value, default="internal_error") \
                    if value else ""
            setattr(row, key, value)
        current_stage = str(row.stage or "queued")
        current_error = str(row.error_code or "")
        if current_stage != previous_stage or current_error != previous_error:
            _team401_append_log(
                row,
                stage=current_stage,
                error_code=current_error,
            )
        row.updated_at = _utcnow()
        batch_id = str(row.batch_id)
        session.add(row)
        session.commit()
    _team401_recompute_batch(batch_id)
    return True


def _team401_task_claim_is_current(task_id: str, worker_token: str) -> bool:
    now = _utcnow()
    with Session(engine) as session:
        row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        parent = (
            session.get(
                GptBusinessAccountModel,
                int(row.business_parent_id or 0),
            )
            if row and int(row.business_parent_id or 0) > 0
            else None
        )
        return bool(
            row
            and str(row.state or "") == "running"
            and str(row.worker_token or "") == str(worker_token or "")
            and _active_lease(row.lease_expires_at, now)
            and str(getattr(parent, "refund_status", "") or "")
            .strip().lower() != _REFUNDED_PARENT_CLEANUP_STATUS
        )


def _team401_live_parent_invite_cooldown_until(
    session: Session,
    parent_id: int,
    *,
    now: Optional[datetime] = None,
) -> Optional[datetime]:
    """Return only the mother's currently-active invite API backoff.

    Older builds copied the legacy 48-hour invite/remove quota deadline into
    TEAM401 rows.  The parent ``invite_cooldown_until`` field is now the sole
    scheduling authority for this particular wait.  This helper deliberately
    does not inspect the per-child/device credential retry map: credential
    repair backoff and mother invitation backoff are independent gates.
    """
    current = _aware_cleanup_time(now) or _utcnow()
    parent = session.get(GptBusinessAccountModel, int(parent_id or 0))
    live_until = _aware_cleanup_time(
        getattr(parent, "invite_cooldown_until", None),
    ) if parent is not None else None
    if live_until is None or live_until <= current:
        return None
    return live_until


def _team401_recalibrate_waiting_cooldown_row(
    session: Session,
    row: DeliveryDeviceTeam401TaskModel,
    *,
    now: Optional[datetime] = None,
) -> Optional[datetime]:
    """Rewrite one TEAM401 wait from the live mother cooldown snapshot."""
    if not (
        str(row.state or "") == "waiting"
        and str(row.stage or "") == "waiting_cooldown"
    ):
        return _aware_cleanup_time(row.next_check_at)
    current = _aware_cleanup_time(now) or _utcnow()
    live_until = _team401_live_parent_invite_cooldown_until(
        session,
        int(row.business_parent_id or 0),
        now=current,
    )
    if _aware_cleanup_time(row.next_check_at) != live_until:
        # ``None`` is intentional: a cleared real cooldown makes this task due
        # immediately.  Do not replace it with the historic quota reset time.
        row.next_check_at = live_until
        row.updated_at = current
        session.add(row)
    return live_until


def _team401_recalibrate_replenishment_cooldown(
    demand_id: str,
    parent_id: int,
) -> Optional[datetime]:
    """Keep a linked replenishment wait aligned with the same mother gate."""
    now = _utcnow()
    with Session(engine) as session:
        demand = session.get(
            DeliveryDeviceReplenishmentDemandModel,
            str(demand_id or ""),
        )
        if not (
            demand
            and int(demand.business_parent_id or 0) == int(parent_id or 0)
            and str(demand.stage or "") == "waiting_cooldown"
            and str(demand.state or "") not in {"completed", "cancelled"}
        ):
            return None
        live_until = _team401_live_parent_invite_cooldown_until(
            session,
            int(parent_id or 0),
            now=now,
        )
        changed = False
        if _aware_cleanup_time(demand.next_check_at) != live_until:
            demand.next_check_at = live_until
            changed = True
        if _aware_cleanup_time(demand.resume_at) != live_until:
            demand.resume_at = live_until
            changed = True
        if live_until is None and str(demand.stage or "") != "retrying_check":
            demand.stage = "retrying_check"
            changed = True
        if changed:
            demand.updated_at = now
            session.add(demand)
            session.commit()
        return live_until


def _team401_parent_head_is_current(
    session: Session,
    row: DeliveryDeviceTeam401TaskModel,
) -> bool:
    """Allow only the oldest non-terminal TEAM401 task for one mother.

    The ordering is persisted, so a pending acceptance/cooldown continues to
    serialize that mother's later children across process restarts. Different
    mothers remain independent. This is stronger than holding an in-process
    RLock only around individual remove/invite calls, which allowed complete
    child lifecycles to interleave between asynchronous checkpoints.
    """
    active = session.exec(
        select(DeliveryDeviceTeam401TaskModel)
        .where(
            DeliveryDeviceTeam401TaskModel.business_parent_id
            == int(row.business_parent_id or 0)
        )
        .where(
            DeliveryDeviceTeam401TaskModel.state.not_in(
                list(_TEAM401_TERMINAL_STATES)
            )
        )
        .order_by(
            DeliveryDeviceTeam401TaskModel.created_at,
            DeliveryDeviceTeam401TaskModel.id,
        )
    ).all()
    return bool(active and str(active[0].id) == str(row.id))


def _team401_resume_stage(row: DeliveryDeviceTeam401TaskModel) -> str:
    """Choose the next idempotent checkpoint for initial claim or retry."""
    branch = str(row.branch or "checking")
    if branch == "checking":
        return (
            "removing_old_child"
            if bool(row.device_delete_confirmed)
            else "checking_account"
        )
    if branch == "repair":
        if bool(row.device_upload_confirmed):
            return "verifying_original_credential"
        if bool(row.oauth_confirmed):
            return "uploading_original_credential"
        return "acquiring_original_rt"
    if bool(row.device_upload_confirmed):
        return "verifying_replacement"
    if str(row.cleanup_job_id or ""):
        return "waiting_replacement"
    if bool(row.device_delete_confirmed):
        return "removing_old_child"
    return "deleting_old_credential"


def _claim_team401_task(task_id: str) -> dict[str, Any]:
    now = _utcnow()
    token = f"team401-worker-{uuid.uuid4().hex}"
    expires = now + timedelta(seconds=_TEAM401_LEASE_SECONDS)
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        else:
            row = session.exec(
                select(DeliveryDeviceTeam401TaskModel)
                .where(DeliveryDeviceTeam401TaskModel.id == str(task_id))
                .with_for_update()
            ).first()
        if row is None:
            session.rollback()
            return {"state": "missing"}
        state = str(row.state or "prepared")
        if state in _TEAM401_TERMINAL_STATES:
            session.rollback()
            return {"state": state}
        if not _team401_parent_head_is_current(session, row):
            session.rollback()
            return {"state": "parent_waiting"}
        parent = session.get(
            GptBusinessAccountModel, int(row.business_parent_id or 0),
        )
        if (
            parent
            and str(parent.refund_status or "").strip().lower()
            == _REFUNDED_PARENT_CLEANUP_STATUS
        ):
            row.state = "cancelled"
            row.stage = "failed"
            row.result = "failed"
            row.error_code = "business_parent_refunded_pending_credit"
            row.worker_token = ""
            row.lease_expires_at = None
            row.next_check_at = None
            row.completed_at = row.completed_at or now
            row.updated_at = now
            _team401_append_log(
                row,
                stage="failed",
                error_code="business_parent_refunded_pending_credit",
            )
            batch_id = str(row.batch_id or "")
            session.add(row)
            session.commit()
            if batch_id:
                _team401_recompute_batch(batch_id)
            return {"state": "cancelled"}
        if state == "running" and _active_lease(row.lease_expires_at, now):
            session.rollback()
            return {"state": "busy"}
        if state == "waiting" and str(row.stage or "") == "waiting_cooldown":
            live_until = _team401_recalibrate_waiting_cooldown_row(
                session,
                row,
                now=now,
            )
            if live_until is not None and live_until > now:
                # Persist a correction from a legacy 48-hour timestamp to the
                # mother's actual ten-minute invite API backoff.
                session.commit()
                return {
                    "state": "waiting",
                    "next_check_at": _safe_public_datetime(live_until),
                }
        if state == "waiting" and _aware_cleanup_time(row.next_check_at) \
                and _aware_cleanup_time(row.next_check_at) > now:
            session.rollback()
            return {
                "state": "waiting",
                "next_check_at": _safe_public_datetime(row.next_check_at),
            }
        try:
            request = _team401_task_request(row)
        except Exception:
            row.state = "failed"
            row.stage = "failed"
            row.result = "failed"
            row.error_code = "request_corrupt"
            row.worker_token = ""
            row.lease_expires_at = None
            row.next_check_at = None
            row.completed_at = row.completed_at or now
            row.updated_at = now
            _team401_append_log(row, stage="failed", error_code="request_corrupt")
            batch_id = str(row.batch_id)
            session.add(row)
            session.commit()
            _team401_recompute_batch(batch_id)
            return {"state": "failed"}
        row.state = "running"
        if str(row.stage or "") in {"queued", "failed"}:
            row.stage = _team401_resume_stage(row)
        row.error_code = ""
        row.worker_token = token
        row.lease_expires_at = expires
        row.next_check_at = None
        row.attempt_count = int(row.attempt_count or 0) + 1
        row.updated_at = now
        _team401_append_log(row, stage=str(row.stage or "queued"))
        session.add(row)
        session.commit()
        return {"state": "claimed", "worker_token": token, "request": request}


def _team401_expected(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "parent_id": int(request.get("business_parent_id") or 0),
        "child_id": int(request.get("child_id") or 0),
        "membership_id": int(request.get("membership_id") or 0),
        "email": _normalized_email(request.get("source_email")),
        "remote_user_id": str(request.get("remote_user_id") or ""),
        "remote_invite_id": str(request.get("remote_invite_id") or ""),
        "target_kind": str(request.get("target_kind") or ""),
        "seat_type": str(request.get("seat_type") or ""),
        "policy_revision": int(request.get("policy_revision") or 0),
        "link_epoch": str(request.get("link_epoch") or ""),
        "remote_id": str(request.get("remote_id") or ""),
        "credential_repair_status": 401,
        "credential_repair_code": "credential_401",
        "remote": dict(request.get("remote") or {}),
    }


def _team401_snapshot_authority(
    request: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    if not _device_epoch_is_current(
        provider,
        provider_id,
        str(request.get("device_epoch") or ""),
    ):
        raise RuntimeError("device_changed")
    canonical = monitor.device_key(provider, provider_id)
    snapshot = monitor.get_accounts(canonical)
    rows = list(snapshot.get("items") or []) if isinstance(snapshot, dict) else []
    matches = [
        dict(item) for item in rows
        if isinstance(item, dict)
        and str(item.get("remote_id") or "") == str(request.get("remote_id") or "")
    ]
    if len(matches) != 1:
        raise RuntimeError("identity_changed")
    remote = matches[0]
    navigation = remote.get("navigation") if isinstance(
        remote.get("navigation"), dict,
    ) else {}
    if not (
        str(remote.get("quota_error_code") or "") == "401"
        and remote.get("credential_repair_required") is True
        and _inventory_positive_int(
            remote.get("credential_repair_status")
        ) == 401
        and monitor.is_team_plan(remote.get("plan"))
        and str(navigation.get("state") or "") == "mapped"
        and str(navigation.get("match_basis") or "") == "device_link"
        and str(navigation.get("target_kind") or "") == "business_child"
        and int(navigation.get("business_parent_id") or 0)
        == int(request.get("business_parent_id") or 0)
        and int(navigation.get("pro_account_id") or 0)
        == int(request.get("child_id") or 0)
        and int(navigation.get("membership_id") or 0)
        == int(request.get("membership_id") or 0)
    ):
        raise RuntimeError("snapshot_not_401")
    mapping = _business_child_mapping(provider, provider_id, remote)
    if not (
        str(mapping.get("state") or "") == "mapped"
        and int(mapping.get("parent_id") or 0)
        == int(request.get("business_parent_id") or 0)
        and int(mapping.get("child_id") or 0)
        == int(request.get("child_id") or 0)
        and int(mapping.get("membership_id") or 0)
        == int(request.get("membership_id") or 0)
        and int(mapping.get("policy_revision") or 0)
        == int(request.get("policy_revision") or 0)
        and str(mapping.get("link_epoch") or "")
        == str(request.get("link_epoch") or "")
    ):
        raise RuntimeError("identity_changed")
    return remote, mapping


def _team401_sub_delete_audit_matches(request: dict[str, Any]) -> bool:
    if str(request.get("provider") or "") != "sub2api":
        return False
    child_id = int(request.get("child_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    with Session(engine) as session:
        child = session.get(GptProAccountModel, child_id)
        membership = session.get(
            GptBusinessChildMembershipModel,
            membership_id,
        )
        if not (
            child
            and membership
            and membership.ended_at is None
            and int(child.business_parent_id or 0) == parent_id
            and int(membership.business_account_id or 0) == parent_id
            and int(membership.pro_account_id or 0) == child_id
        ):
            return False
        removed = _json_object(child.extra_json).get("sub2api_last_removed")
        return bool(
            isinstance(removed, dict)
            and int(removed.get("device_id") or 0)
            == int(request.get("provider_id") or 0)
            and str(removed.get("remote_account_id") or "")
            == str(request.get("remote_id") or "")
            and str(removed.get("reason") or "") == "credential_401_repair"
            and removed.get("remote_deleted") is True
        )


def _team401_parent_preflight(request: dict[str, Any]) -> None:
    """Fail closed before the first irreversible device mutation.

    The 401 scan authorizes the exact child identity, while this DB-only
    preflight proves the mother can still own the repair/replacement workflow.
    Pending/manual refund reviews remain allowed by the shared BUSINESS policy;
    an actually refunded catalogue row, disabled/dead mother, expired Team
    session or changed device binding blocks the DELETE.
    """
    from api import gpt_business

    parent_id = int(request.get("business_parent_id") or 0)
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    expected_revision = int(request.get("policy_revision") or 0)
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        if parent is None:
            raise RuntimeError("business_parent_missing")
        if (
            not bool(parent.enabled)
            or bool(parent.dangerous)
            or gpt_business._business_parent_refund_blocks_replacement(
                parent,
                session,
            )
        ):
            raise RuntimeError("business_parent_unavailable")
        if policy is None or int(policy.revision or 0) != expected_revision:
            raise RuntimeError("identity_changed")
        if not bool(policy.auto_rotation_enabled):
            raise RuntimeError("business_parent_unavailable")
        current_provider = str(policy.delivery_type or "")
        current_device_id = (
            int(policy.cpa_target_id or 0)
            if current_provider == "cpa"
            else int(policy.sub2api_device_id or 0)
            if current_provider == "sub2api"
            else 0
        )
        if current_provider != provider or current_device_id != provider_id:
            raise RuntimeError("identity_changed")
        session_status = gpt_business._business_account_team_session_status(
            parent,
        )
        if not bool(session_status.get("usable")):
            raise RuntimeError("business_parent_unavailable")


def _team401_check_old_child_account(
    task_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Use the shared managed-child login while holding the exact child lease."""
    from api import gpt_business
    from api.gpt_plan_operations import (
        _claim_gpt_pro_account_operation,
        _gpt_pro_account_operation_token_is_current,
        _release_gpt_pro_account_operation,
    )

    child_id = int(request.get("child_id") or 0)
    operation_token = ""
    _team401_parent_preflight(request)
    _team401_snapshot_authority(request)
    try:
        operation_token = _claim_gpt_pro_account_operation(
            child_id,
            "delivery_team401_correction",
            ttl_hours=1,
            allow_managed_business_child=True,
        )
        if not (
            _team401_task_claim_is_current(task_id, worker_token)
            and _gpt_pro_account_operation_token_is_current(
                child_id,
                operation_token,
            )
            and _device_epoch_is_current(
                str(request.get("provider") or ""),
                int(request.get("provider_id") or 0),
                str(request.get("device_epoch") or ""),
            )
        ):
            return {
                "ok": False,
                "classification": "unknown",
                "error_code": "identity_changed",
            }
        result = gpt_business.check_managed_business_child_login_for_automation(
            int(request.get("business_parent_id") or 0),
            child_id,
            int(request.get("membership_id") or 0),
            expected_operation_token=operation_token,
            headless=True,
            otp_timeout=180,
        )
        if not (
            _team401_task_claim_is_current(task_id, worker_token)
            and _gpt_pro_account_operation_token_is_current(
                child_id,
                operation_token,
            )
        ):
            return {
                "ok": False,
                "classification": "unknown",
                "error_code": "identity_changed",
            }
        # The browser wait is intentionally outside a DB transaction.  Repeat
        # both authority checks before the caller is allowed to select either
        # the destructive replacement branch or the non-destructive RT branch.
        _team401_parent_preflight(request)
        _team401_snapshot_authority(request)
        return result if isinstance(result, dict) else {
            "ok": False,
            "classification": "unknown",
            "error_code": "account_check_failed",
        }
    except Exception as exc:
        return {
            "ok": False,
            "classification": "unknown",
            "error_code": _team401_safe_error_code(
                str(exc or ""),
                default="account_check_failed",
            ),
        }
    finally:
        if operation_token:
            _release_gpt_pro_account_operation(child_id, operation_token)


def _team401_delete_old_credential(
    task_id: str,
    worker_token: str,
    request: dict[str, Any],
) -> None:
    """Delete only the exact linked 401 credential and persist Sub audit."""
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    child_id = int(request.get("child_id") or 0)
    parent_id = int(request.get("business_parent_id") or 0)
    remote = dict(request.get("remote") or {})
    _team401_parent_preflight(request)
    if provider == "sub2api" and _team401_sub_delete_audit_matches(request):
        return

    from api.gpt_plan_operations import (
        _claim_gpt_pro_account_operation,
        _gpt_pro_account_operation_token_is_current,
        _release_gpt_pro_account_operation,
    )

    account_token = ""

    def guard() -> bool:
        if not _team401_task_claim_is_current(task_id, worker_token):
            return False
        if not _device_epoch_is_current(
            provider,
            provider_id,
            str(request.get("device_epoch") or ""),
        ):
            return False
        if account_token and not _gpt_pro_account_operation_token_is_current(
            child_id,
            account_token,
        ):
            return False
        try:
            # Re-evaluate the mother/refund/session/device-policy fence at the
            # provider's last possible before-mutation callback. The earlier
            # preflight cannot authorize a DELETE after an intervening state
            # change while the provider inventory was being listed.
            _team401_parent_preflight(request)
        except RuntimeError:
            return False
        expected = _team401_expected(request)
        return _mapping_is_current(provider, provider_id, remote, expected)

    try:
        # The task row is the durable delete intent.  On the first execution
        # the 401 snapshot must still be authoritative.  If a worker crashed
        # after the exact DELETE but before its checkpoint, the old row can be
        # absent from the next persisted inventory; in that one case continue
        # to the provider's idempotent absence check instead of getting stuck
        # forever on ``identity_changed``.
        try:
            _team401_snapshot_authority(request)
        except RuntimeError as exc:
            code = str(exc or "")
            canonical = monitor.device_key(provider, provider_id)
            snapshot = monitor.get_accounts(canonical)
            rows = (
                list(snapshot.get("items") or [])
                if isinstance(snapshot, dict) else []
            )
            same_remote = [
                item for item in rows
                if isinstance(item, dict)
                and str(item.get("remote_id") or "")
                == str(request.get("remote_id") or "")
            ]
            expected = _team401_expected(request)
            if (
                code not in {"identity_changed", "snapshot_not_401"}
                or same_remote
                or not _mapping_is_current(
                    provider,
                    provider_id,
                    remote,
                    expected,
                )
            ):
                raise
        account_token = _claim_gpt_pro_account_operation(
            child_id,
            "delivery_team401_correction",
            ttl_hours=1,
            allow_managed_business_child=True,
        )
        if provider == "cpa":
            _delete_cpa_remote_exact(
                _internal_device_or_error(provider, provider_id),
                remote,
                before_mutation=guard,
            )
        else:
            from api.gpt_plan_operations import _delete_linked_sub2api_remote

            deleted = _delete_linked_sub2api_remote(
                child_id,
                reason="credential_401_repair",
                expected_business_parent_id=parent_id,
                operation_token=account_token,
                deletion_guard=guard,
            )
            if not bool(deleted.get("ok")) or not bool(
                deleted.get("absence_confirmed")
                or deleted.get("idempotent")
            ):
                raise RuntimeError("device_delete_failed")
    finally:
        if account_token:
            _release_gpt_pro_account_operation(child_id, account_token)


def _team401_verify_device_child(
    request: dict[str, Any],
    *,
    child_id: int,
    membership_id: int,
) -> bool:
    provider = str(request.get("provider") or "")
    provider_id = int(request.get("provider_id") or 0)
    if not _device_epoch_is_current(
        provider,
        provider_id,
        str(request.get("device_epoch") or ""),
    ):
        return False
    refreshed = monitor.refresh_device_pro_inventory(
        monitor.device_key(provider, provider_id),
    )
    if not bool(refreshed.get("ok")):
        return False
    matches = []
    for raw in list(refreshed.get("items") or []):
        if not isinstance(raw, dict) or bool(raw.get("disabled")):
            continue
        navigation = raw.get("navigation") if isinstance(
            raw.get("navigation"), dict,
        ) else {}
        if (
            str(navigation.get("state") or "") == "mapped"
            and str(navigation.get("target_kind") or "") == "business_child"
            and int(navigation.get("business_parent_id") or 0)
            == int(request.get("business_parent_id") or 0)
            and int(navigation.get("pro_account_id") or 0) == int(child_id)
            and int(navigation.get("membership_id") or 0)
            == int(membership_id)
            and not str(raw.get("quota_error_code") or "").strip()
            and str(raw.get("usage_status") or "").strip().lower()
            not in {"error", "failed", "unknown"}
        ):
            matches.append(raw)
    return len(matches) == 1


def _team401_run_original_credential_repair(
    task_id: str,
    worker_token: str,
    request: dict[str, Any],
    row: DeliveryDeviceTeam401TaskModel,
) -> str:
    """Resume the non-destructive old-child RT/upload/verify branch."""
    child_id = int(request.get("child_id") or 0)
    membership_id = int(request.get("membership_id") or 0)
    if bool(row.device_upload_confirmed):
        if not _team401_task_checkpoint(
            task_id,
            worker_token,
            stage="verifying_original_credential",
        ):
            return "stopped"
        if not _team401_verify_device_child(
            request,
            child_id=child_id,
            membership_id=membership_id,
        ):
            _team401_fail(task_id, worker_token, "device_verify_failed")
            return "failed"
        _team401_task_checkpoint(
            task_id,
            worker_token,
            state="completed",
            stage="completed",
            result="repaired",
            error_code="",
            device_verify_confirmed=True,
            next_check_at=None,
            worker_token="",
            lease_expires_at=None,
            completed_at=_utcnow(),
        )
        return "completed"

    stage = (
        "uploading_original_credential"
        if bool(row.oauth_confirmed)
        else "acquiring_original_rt"
    )
    if not _team401_task_checkpoint(task_id, worker_token, stage=stage):
        return "stopped"

    def oauth_checkpoint() -> None:
        if not _team401_task_checkpoint(
            task_id,
            worker_token,
            oauth_confirmed=True,
            stage="uploading_original_credential",
        ):
            raise RuntimeError("identity_changed")

    outcome = _repair_business_child_credential(
        provider=str(request.get("provider") or ""),
        provider_id=int(request.get("provider_id") or 0),
        device_epoch=str(request.get("device_epoch") or ""),
        expected=_team401_expected(request),
        remote_already_deleted=bool(row.device_delete_confirmed),
        oauth_already_confirmed=bool(row.oauth_confirmed),
        oauth_checkpoint=oauth_checkpoint,
    )
    if not bool(outcome.get("ok")):
        error_code = _team401_safe_error_code(
            outcome.get("error_code"),
            default="oauth_failed",
        )
        if error_code == "account_deactivated":
            if not _team401_task_checkpoint(
                task_id,
                worker_token,
                branch="replace",
                account_checked=True,
                oauth_confirmed=False,
                stage="account_confirmed_dead",
                error_code="",
            ):
                return "stopped"
            return "replace"
        _team401_fail(task_id, worker_token, error_code)
        return "failed"
    if not _team401_task_checkpoint(
        task_id,
        worker_token,
        oauth_confirmed=True,
        device_upload_confirmed=True,
        stage="verifying_original_credential",
    ):
        return "stopped"
    if not _team401_verify_device_child(
        request,
        child_id=child_id,
        membership_id=membership_id,
    ):
        _team401_fail(task_id, worker_token, "device_verify_failed")
        return "failed"
    _team401_task_checkpoint(
        task_id,
        worker_token,
        state="completed",
        stage="completed",
        result="repaired",
        error_code="",
        device_verify_confirmed=True,
        next_check_at=None,
        worker_token="",
        lease_expires_at=None,
        completed_at=_utcnow(),
    )
    return "completed"


def _team401_fail(
    task_id: str,
    worker_token: str,
    error_code: Any,
) -> None:
    code = _team401_safe_error_code(error_code)
    _team401_task_checkpoint(
        task_id,
        worker_token,
        state="failed",
        result="failed",
        error_code=code,
        next_check_at=None,
        worker_token="",
        lease_expires_at=None,
        completed_at=_utcnow(),
    )


def _team401_wait(
    task_id: str,
    worker_token: str,
    *,
    stage: str,
    next_check_at: Any = None,
    error_code: str = "",
) -> None:
    due = _safe_datetime_value(next_check_at) or (
        _utcnow() + timedelta(seconds=_TEAM401_RECHECK_SECONDS)
    )
    _team401_task_checkpoint(
        task_id,
        worker_token,
        state="waiting",
        stage=stage,
        error_code=error_code,
        next_check_at=due,
        worker_token="",
        lease_expires_at=None,
    )


def _team401_replacement_public_stage(value: Any) -> str:
    stage = str(value or "").strip().lower()
    if stage in {
        "queued", "checking_account", "account_confirmed_active",
        "account_confirmed_dead", "acquiring_original_rt",
        "uploading_original_credential", "verifying_original_credential",
        "deleting_old_credential", "removing_old_child",
        "uploading_replacement", "verifying_replacement", "completed",
        "failed",
    }:
        return stage
    if stage == "active_verify":
        return "verifying_replacement"
    if "sync" in stage or "upload" in stage:
        return "uploading_replacement"
    # Joining the workspace is part of the child RT capability.  Once the
    # mother's invite call is confirmed (``invited``), acceptance/member waits
    # must never appear as a seventh public phase.
    if (
        stage in {
            "invited", "auto_accept", "pending_acceptance",
            "seat_type_unconfirmed", "seat_type_mismatch", "child_rt",
        }
        or "accept" in stage
        or "member" in stage
        or "oauth" in stage
        or stage.startswith("rt_")
    ):
        return "acquiring_replacement_rt"
    # Selection, ordinary-account login, invitation API cooldown and the send
    # itself are internal details of the one mother invitation capability.
    return "inviting_replacement"


def _team401_replacement_error(stage: Any) -> str:
    raw = str(stage or "").strip().lower()
    if raw in {"cleanup_lifecycle_owned", "duplicate_cleanup_irreversible"}:
        return "cleanup_lifecycle_owned"
    if raw == "seat_type_unknown":
        return "seat_type_unknown"
    if raw in {"parent_missing"}:
        return "business_parent_missing"
    if raw in {"parent_unsafe", "binding_removed", "parent_session_unavailable"}:
        return "business_parent_unavailable"
    if "candidate" in raw:
        return "replacement_candidate_unavailable"
    if raw in {"fill_job_missing", "fill_binding_conflict"}:
        return "replenishment_action_required"
    if raw == "child_rt" or "oauth" in raw or raw.startswith("rt_"):
        return "oauth_failed"
    return "replacement_failed"


def _team401_run_replacement(
    task_id: str,
    worker_token: str,
    request: dict[str, Any],
    row: DeliveryDeviceTeam401TaskModel,
) -> None:
    from api import gpt_business

    parent_id = int(request.get("business_parent_id") or 0)
    if (
        bool(row.device_upload_confirmed)
        and int(row.replacement_child_id or 0) > 0
        and int(row.replacement_membership_id or 0) > 0
    ):
        if not _team401_task_checkpoint(
            task_id,
            worker_token,
            stage="verifying_replacement",
        ):
            return
        if not _team401_verify_device_child(
            request,
            child_id=int(row.replacement_child_id or 0),
            membership_id=int(row.replacement_membership_id or 0),
        ):
            _team401_fail(task_id, worker_token, "replacement_verify_failed")
            return
        _team401_task_checkpoint(
            task_id,
            worker_token,
            state="completed",
            stage="completed",
            result="replaced",
            error_code="",
            device_verify_confirmed=True,
            next_check_at=None,
            worker_token="",
            lease_expires_at=None,
            completed_at=_utcnow(),
        )
        return
    if str(request.get("seat_type") or "") not in {"default", "prolite"}:
        _team401_fail(task_id, worker_token, "seat_type_unknown")
        return
    cleanup_id = str(row.cleanup_job_id or "")
    if not cleanup_id:
        mapping = _team401_expected(request)
        mapping.update({
            "state": "mapped",
            "account_id": int(request.get("child_id") or 0),
            "missing_remote_confirmed": True,
            "linked_remote_id": str(request.get("remote_id") or ""),
            "target_kind": str(request.get("target_kind") or "member"),
        })
        remote = dict(request.get("remote") or {})
        remote["credential_missing"] = True
        # The exact provider row was authorized by an account-level credential
        # probe before it was deleted.  Carry only that credential-free proof
        # into the mother workflow; quota_error_code alone is never sufficient
        # (especially for a Sub2API management-key 401).
        remote["credential_repair_required"] = True
        remote["credential_repair_status"] = 401
        try:
            job = _create_or_get_cleanup_job(
                provider=str(request.get("provider") or ""),
                provider_id=int(request.get("provider_id") or 0),
                remote=remote,
                mapping=mapping,
                device_epoch=str(request.get("device_epoch") or ""),
                trigger_kind="team401_replace",
            )
        except RuntimeError as exc:
            lifecycle_error = str(exc or "").strip()
            if lifecycle_error == "cleanup_lifecycle_busy":
                _team401_wait(
                    task_id,
                    worker_token,
                    stage="waiting_replacement",
                    error_code="cleanup_lifecycle_busy",
                )
                return
            if lifecycle_error == "cleanup_lifecycle_owned":
                _team401_fail(
                    task_id,
                    worker_token,
                    "cleanup_lifecycle_owned",
                )
                return
            raise
        cleanup_id = str(job.id)
        if not _team401_task_checkpoint(
            task_id,
            worker_token,
            branch="replace",
            account_checked=True,
            cleanup_job_id=cleanup_id,
            stage="removing_old_child",
        ):
            return

    cleanup_result = _run_delivery_exhaustion_cleanup(cleanup_id)
    kind = str(cleanup_result.get("kind") or "failed")
    if kind == "waiting":
        # Never copy a legacy cleanup deadline into the child coordinator.
        # Re-read the mother's real invite API cooldown at this boundary.
        with Session(engine) as session:
            live_until = _team401_live_parent_invite_cooldown_until(
                session,
                parent_id,
            )
        if live_until is not None:
            _team401_wait(
                task_id,
                worker_token,
                stage="waiting_cooldown",
                next_check_at=live_until,
                error_code="waiting_cooldown",
            )
        else:
            # ``None`` makes the durable task immediately scheduler-eligible;
            # the next claim re-evaluates the cleanup under current policy.
            _team401_task_checkpoint(
                task_id,
                worker_token,
                state="waiting",
                stage="waiting_cooldown",
                error_code="waiting_cooldown",
                next_check_at=None,
                worker_token="",
                lease_expires_at=None,
            )
        return
    if kind == "busy":
        _team401_wait(
            task_id,
            worker_token,
            stage="waiting_replacement",
            error_code="operation_busy",
        )
        return
    if kind not in {"success", "completed"}:
        cleanup_error = str(cleanup_result.get("error_code") or "").strip()
        if cleanup_error in _TEAM401_ERROR_MESSAGES:
            _team401_fail(task_id, worker_token, cleanup_error)
            return
        with Session(engine) as session:
            cleanup = session.get(
                DeliveryDeviceExhaustionCleanupModel,
                cleanup_id,
            )
            cleanup_stage = str(cleanup.stage or "") if cleanup else ""
        _team401_fail(
            task_id,
            worker_token,
            _team401_replacement_error(cleanup_stage),
        )
        return

    demand_id = str(cleanup_result.get("replenishment_demand_id") or "")
    with Session(engine) as session:
        if not demand_id:
            demand = session.exec(
                select(DeliveryDeviceReplenishmentDemandModel).where(
                    DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                    == cleanup_id
                )
            ).first()
            demand_id = str(demand.id) if demand else ""
    if not demand_id:
        _team401_fail(task_id, worker_token, "replenishment_missing")
        return
    if not _team401_task_checkpoint(
        task_id,
        worker_token,
        branch="replace",
        cleanup_job_id=cleanup_id,
        replenishment_demand_id=demand_id,
        stage="inviting_replacement",
    ):
        return

    # A demand may have been persisted by an older build with a 48-hour quota
    # reset.  Normalize it before the direct runner checks ``next_check_at``.
    _team401_recalibrate_replenishment_cooldown(demand_id, parent_id)
    gpt_business.run_or_resume_business_replenishment_for_automation(
        demand_id,
    )
    # The bound allocation job may itself have replayed an old cooldown action
    # into the demand.  Normalize the copied value once more before exposing it
    # through the TEAM401 task.
    _team401_recalibrate_replenishment_cooldown(demand_id, parent_id)

    with Session(engine) as session:
        demand = session.get(DeliveryDeviceReplenishmentDemandModel, demand_id)
        fill = (
            session.get(GptBusinessAllocationJobModel, str(demand.fill_job_id))
            if demand and str(demand.fill_job_id or "") else None
        )
        demand_state = str(demand.state or "") if demand else ""
        demand_stage = str(demand.stage or "") if demand else ""
        fill_state = str(fill.state or "") if fill else ""
        fill_stage = str(fill.stage or "") if fill else ""
        fill_id = str(fill.id) if fill else ""
        replacement_child_id = int(fill.selected_pro_account_id or 0) if fill else 0
        replacement_email = str(fill.selected_email or "") if fill else ""
        replacement_membership = None
        if replacement_child_id > 0:
            replacement_membership = session.exec(
                select(GptBusinessChildMembershipModel)
                .where(
                    GptBusinessChildMembershipModel.business_account_id
                    == parent_id
                )
                .where(
                    GptBusinessChildMembershipModel.pro_account_id
                    == replacement_child_id
                )
                .where(
                    GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
                )
                .order_by(GptBusinessChildMembershipModel.created_at.desc())
            ).first()
        replacement_membership_id = int(
            replacement_membership.id or 0
        ) if replacement_membership else 0
        next_check_at = (
            demand.resume_at or demand.next_check_at if demand else None
        )

    if demand is None:
        _team401_fail(task_id, worker_token, "replenishment_missing")
        return
    if demand_state in {"cancelled", "action_required"} or (
        fill_state in {"failed", "action_required"}
        and fill is not None
        and not bool(fill.retryable)
    ):
        _team401_fail(
            task_id,
            worker_token,
            _team401_replacement_error(fill_stage or demand_stage),
        )
        return
    if demand_state != "completed" or fill_state != "completed":
        _team401_task_checkpoint(
            task_id,
            worker_token,
            fill_job_id=fill_id,
            replacement_child_id=replacement_child_id or None,
            replacement_email=replacement_email,
        )
        _team401_wait(
            task_id,
            worker_token,
            stage=_team401_replacement_public_stage(fill_stage or demand_stage),
            next_check_at=next_check_at,
        )
        return
    if min(replacement_child_id, replacement_membership_id) <= 0:
        _team401_fail(task_id, worker_token, "replacement_verify_failed")
        return
    _team401_task_checkpoint(
        task_id,
        worker_token,
        fill_job_id=fill_id,
        replacement_child_id=replacement_child_id,
        replacement_membership_id=replacement_membership_id,
        replacement_email=replacement_email,
        device_upload_confirmed=True,
        stage="verifying_replacement",
    )
    if not _team401_verify_device_child(
        request,
        child_id=replacement_child_id,
        membership_id=replacement_membership_id,
    ):
        _team401_fail(task_id, worker_token, "replacement_verify_failed")
        return
    _team401_task_checkpoint(
        task_id,
        worker_token,
        state="completed",
        stage="completed",
        result="replaced",
        error_code="",
        device_verify_confirmed=True,
        next_check_at=None,
        worker_token="",
        lease_expires_at=None,
        completed_at=_utcnow(),
    )


def _run_team401_task(task_id: str) -> None:
    claim = _claim_team401_task(task_id)
    if str(claim.get("state") or "") != "claimed":
        return
    worker_token = str(claim.get("worker_token") or "")
    request = dict(claim.get("request") or {})
    try:
        with Session(engine) as session:
            row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
            if row is None:
                return
            session.expunge(row)
        branch = str(row.branch or "checking")
        if branch == "checking":
            # Compatibility: an old worker may already have crossed the exact
            # provider DELETE before this version starts.  Such a row cannot
            # safely return to login/repair and must continue its old durable
            # replacement chain.
            if bool(row.device_delete_confirmed):
                if not _team401_task_checkpoint(
                    task_id,
                    worker_token,
                    branch="replace",
                    account_checked=True,
                    stage="removing_old_child",
                ):
                    return
            elif bool(row.account_checked):
                _team401_fail(task_id, worker_token, "account_state_conflict")
                return
            else:
                if not _team401_task_checkpoint(
                    task_id,
                    worker_token,
                    stage="checking_account",
                ):
                    return
                checked = _team401_check_old_child_account(
                    task_id,
                    worker_token,
                    request,
                )
                classification = str(
                    checked.get("classification") or "unknown"
                ).strip().lower()
                if bool(checked.get("ok")) and classification == "dead":
                    if not _team401_task_checkpoint(
                        task_id,
                        worker_token,
                        branch="replace",
                        account_checked=True,
                        oauth_confirmed=False,
                        stage="account_confirmed_dead",
                    ):
                        return
                elif bool(checked.get("ok")) and classification == "alive":
                    if not _team401_task_checkpoint(
                        task_id,
                        worker_token,
                        branch="repair",
                        account_checked=True,
                        stage="account_confirmed_active",
                    ):
                        return
                else:
                    _team401_fail(
                        task_id,
                        worker_token,
                        checked.get("error_code") or "account_check_failed",
                    )
                    return

        with Session(engine) as session:
            current = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
            if current is None:
                return
            session.expunge(current)
        if str(current.branch or "") == "repair":
            outcome = _team401_run_original_credential_repair(
                task_id,
                worker_token,
                request,
                current,
            )
            if outcome != "replace":
                return
            with Session(engine) as session:
                current = session.get(
                    DeliveryDeviceTeam401TaskModel,
                    str(task_id),
                )
                if current is None:
                    return
                session.expunge(current)

        # Existing branch=replace rows and newly proven-dead children share the
        # same mother-owned durable replacement capability.  No browser/login
        # implementation is duplicated on the device side.
        if str(current.branch or "") != "replace":
            _team401_fail(task_id, worker_token, "account_state_conflict")
            return
        if not bool(current.device_delete_confirmed):
            if not _team401_task_checkpoint(
                task_id,
                worker_token,
                stage="deleting_old_credential",
            ):
                return
            _team401_delete_old_credential(task_id, worker_token, request)
            if not _team401_task_checkpoint(
                task_id,
                worker_token,
                device_delete_confirmed=True,
                stage="removing_old_child",
            ):
                return
        with Session(engine) as session:
            current = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
            if current is None:
                return
            session.expunge(current)
        _team401_run_replacement(task_id, worker_token, request, current)
    except Exception as exc:
        raw = str(exc or "").strip()
        _team401_fail(
            task_id,
            worker_token,
            _team401_safe_error_code(raw),
        )


def _team401_worker_entry(task_id: str) -> None:
    cleanup_job_id = ""
    try:
        with Session(engine) as session:
            row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
            parent_id = int(row.business_parent_id or 0) if row else 0
        # Acquire the mother lane before the global ten-child slot: waiters for
        # the same mother therefore never consume all slots and starve another
        # mother's independent lifecycle.
        parent_lock = _team_child_parent_lock(parent_id)
        with parent_lock:
            with _TEAM401_OPERATION_SLOTS:
                _run_team401_task(str(task_id))
    finally:
        try:
            with Session(engine) as session:
                row = session.get(
                    DeliveryDeviceTeam401TaskModel, str(task_id),
                )
                if row and str(row.state or "").strip().lower() in {
                    "completed", "failed", "cancelled",
                }:
                    cleanup_job_id = str(row.cleanup_job_id or "")
            if cleanup_job_id:
                from api import gpt_business

                gpt_business.purge_released_dead_business_child_for_delivery_cleanup(
                    cleanup_job_id,
                )
        except Exception:
            pass
        with _TEAM401_THREADS_LOCK:
            current = _TEAM401_THREADS.get(str(task_id))
            if current is threading.current_thread():
                _TEAM401_THREADS.pop(str(task_id), None)
        # Pump the durable queue immediately after releasing the shared global
        # slot.  A batch with more than ten children must not wait for the
        # minute scheduler tick before child 11 can start.
        resume_pending_team401_corrections(
            limit=_TEAM401_CONCURRENCY_MAX,
        )


def _start_team401_worker(task_id: str) -> bool:
    with _TEAM401_THREADS_LOCK:
        current = _TEAM401_THREADS.get(str(task_id))
        if current and current.is_alive():
            return False
        thread = threading.Thread(
            target=_team401_worker_entry,
            args=(str(task_id),),
            name=f"team401-{str(task_id)[-12:]}",
            daemon=True,
        )
        _TEAM401_THREADS[str(task_id)] = thread
        thread.start()
        return True


def resume_pending_team401_corrections(limit: int = 10) -> dict[str, int]:
    """Resume due durable child rows after a process restart."""
    bounded = max(1, min(int(limit or 10), _TEAM401_CONCURRENCY_MAX))
    now = _utcnow()
    with Session(engine) as session:
        # One-way recovery for TEAM401 rows written before invite API failures
        # became a dedicated ten-minute mother cooldown.  Scan this narrow
        # stage before the due query: otherwise a legacy 48-hour timestamp can
        # keep a row invisible to the scheduler for two days.  Other waiting
        # stages (including child credential retry) are intentionally untouched.
        cooldown_rows = session.exec(
            select(DeliveryDeviceTeam401TaskModel)
            .where(DeliveryDeviceTeam401TaskModel.state == "waiting")
            .where(
                DeliveryDeviceTeam401TaskModel.stage == "waiting_cooldown"
            )
            .order_by(DeliveryDeviceTeam401TaskModel.updated_at)
        ).all()
        for row in cooldown_rows:
            _team401_recalibrate_waiting_cooldown_row(
                session,
                row,
                now=now,
            )
        session.commit()
        active_rows = session.exec(
            select(DeliveryDeviceTeam401TaskModel)
            .where(
                DeliveryDeviceTeam401TaskModel.state.not_in(
                    list(_TEAM401_TERMINAL_STATES)
                )
            )
            .order_by(
                DeliveryDeviceTeam401TaskModel.created_at,
                DeliveryDeviceTeam401TaskModel.id,
            )
        ).all()
        parent_heads: dict[int, str] = {}
        for active in active_rows:
            parent_heads.setdefault(
                int(active.business_parent_id or 0), str(active.id),
            )
        due_rows = session.exec(
            select(DeliveryDeviceTeam401TaskModel)
            .where(or_(
                DeliveryDeviceTeam401TaskModel.state.in_([
                    "prepared", "queued",
                ]),
                and_(
                    DeliveryDeviceTeam401TaskModel.state == "waiting",
                    or_(
                        DeliveryDeviceTeam401TaskModel.next_check_at.is_(None),  # type: ignore[union-attr]
                        DeliveryDeviceTeam401TaskModel.next_check_at <= now,
                    ),
                ),
                and_(
                    DeliveryDeviceTeam401TaskModel.state == "running",
                    or_(
                        DeliveryDeviceTeam401TaskModel.lease_expires_at.is_(None),  # type: ignore[union-attr]
                        DeliveryDeviceTeam401TaskModel.lease_expires_at <= now,
                    ),
                ),
            ))
            .order_by(DeliveryDeviceTeam401TaskModel.updated_at)
        ).all()
        task_ids = [
            str(row.id) for row in due_rows
            if parent_heads.get(int(row.business_parent_id or 0))
            == str(row.id)
        ][:bounded]
    started = sum(_start_team401_worker(task_id) for task_id in task_ids)
    return {"considered": len(task_ids), "started": int(started)}


def recover_orphaned_team401_after_restart(limit: int = 10) -> dict[str, int]:
    """Release only worker leases orphaned by this process restart.

    This entry point is called exactly once by the application lifespan after
    DB initialization.  Periodic recovery deliberately does *not* clear live
    leases, so another local worker can never be stolen by the queue pump.
    """
    now = _utcnow()
    recovered = 0
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        rows = session.exec(
            select(DeliveryDeviceTeam401TaskModel).where(
                DeliveryDeviceTeam401TaskModel.state == "running"
            )
        ).all()
        for row in rows:
            row.state = "queued"
            row.worker_token = ""
            row.lease_expires_at = None
            row.next_check_at = now
            row.updated_at = now
            _team401_append_log(
                row,
                stage=str(row.stage or "queued"),
            )
            session.add(row)
            recovered += 1
        if recovered:
            session.commit()
    resumed = resume_pending_team401_corrections(limit=limit)
    return {
        "recovered": int(recovered),
        "considered": int(resumed.get("considered") or 0),
        "started": int(resumed.get("started") or 0),
    }


_TEAM401_STEP_LABELS = {
    "delete_old_credential": "精确删除旧设备凭证",
    "remove_old_child": "从母号移除旧子号",
    "invite_replacement": "母号选择、登录并邀请替补子号",
    "get_replacement_rt": "子号加入母号并获取 RT / OAuth",
    "upload_replacement": "上传替补子号凭证",
    "verify_replacement": "确认替补凭证在设备生效",
}
_TEAM401_CHECK_STEP_LABELS = {
    "check_old_account": "登录旧子号并确认账号状态",
}
_TEAM401_REPAIR_STEP_LABELS = {
    **_TEAM401_CHECK_STEP_LABELS,
    "get_original_rt": "重新获取旧子号 RT / OAuth",
    "upload_original_credential": "覆盖上传旧子号凭证",
    "verify_original_credential": "刷新额度并确认旧子号生效",
}
_TEAM401_STAGE_STEP = {
    "checking_account": "check_old_account",
    "account_confirmed_active": "check_old_account",
    "account_confirmed_dead": "check_old_account",
    "acquiring_original_rt": "get_original_rt",
    "uploading_original_credential": "upload_original_credential",
    "verifying_original_credential": "verify_original_credential",
    "deleting_old_credential": "delete_old_credential",
    "removing_old_child": "remove_old_child",
    "waiting_cooldown": "invite_replacement",
    "selecting_replacement": "invite_replacement",
    "waiting_replacement": "invite_replacement",
    "candidate_login": "invite_replacement",
    "inviting_replacement": "invite_replacement",
    "accepting_replacement": "get_replacement_rt",
    "acquiring_replacement_rt": "get_replacement_rt",
    "uploading_replacement": "upload_replacement",
    "verifying_replacement": "verify_replacement",
}


def _team401_durable_progress(
    row: DeliveryDeviceTeam401TaskModel,
) -> dict[str, Any]:
    """Return a credential-free view of cleanup/demand/fill checkpoints."""
    result: dict[str, Any] = {
        "cleanup_remove_confirmed": False,
        "selection_confirmed": False,
        "candidate_login_required": False,
        "candidate_login_confirmed": False,
        "invite_confirmed": False,
        "accept_confirmed": False,
        "replacement_rt_confirmed": False,
        "replacement_upload_confirmed": False,
        "replacement_child_id": int(row.replacement_child_id or 0),
        "replacement_membership_id": int(row.replacement_membership_id or 0),
        "replacement_email": str(row.replacement_email or ""),
        "fill_job_id": str(row.fill_job_id or ""),
        "public_stage": _team401_replacement_public_stage(
            row.stage or "queued",
        ),
        "next_check_at": row.next_check_at,
    }
    if str(row.branch or "") != "replace":
        return result
    with Session(engine) as session:
        cleanup = (
            session.get(
                DeliveryDeviceExhaustionCleanupModel,
                str(row.cleanup_job_id),
            )
            if str(row.cleanup_job_id or "") else None
        )
        demand = (
            session.get(
                DeliveryDeviceReplenishmentDemandModel,
                str(row.replenishment_demand_id),
            )
            if str(row.replenishment_demand_id or "") else None
        )
        fill_id = str(
            row.fill_job_id
            or (demand.fill_job_id if demand else "")
            or ""
        )
        fill = session.get(GptBusinessAllocationJobModel, fill_id) \
            if fill_id else None
        result["cleanup_remove_confirmed"] = bool(
            cleanup and cleanup.business_remove_confirmed
        )
        if demand:
            result["next_check_at"] = (
                demand.resume_at or demand.next_check_at or row.next_check_at
            )
        if not fill:
            if demand:
                result["public_stage"] = _team401_replacement_public_stage(
                    demand.stage,
                )
            return result
        actions = _json_object(fill.action_state_json)
        selected_child_id = int(fill.selected_pro_account_id or 0)
        selected_email = _normalized_email(fill.selected_email)
        result.update({
            "fill_job_id": str(fill.id),
            "replacement_child_id": selected_child_id,
            "replacement_email": selected_email,
            "selection_confirmed": bool(selected_child_id and selected_email),
        })
        fill_stage = str(fill.stage or "")
        prelogin_state = actions.get("prelogin")
        result["candidate_login_required"] = bool(
            prelogin_state.get("required")
            if isinstance(prelogin_state, dict)
            else True
        )
        result["candidate_login_confirmed"] = bool(
            not result["candidate_login_required"]
            or (
                isinstance(prelogin_state, dict)
                and prelogin_state.get("completed") is True
            )
            or (
                fill.remote_mutated
                and fill_stage not in {
                    "planned", "candidate_login", "waiting_candidate",
                }
            )
        )
        result["public_stage"] = _team401_replacement_public_stage(
            fill_stage or (demand.stage if demand else ""),
        )
        mother_invite_state = actions.get("mother_invite")
        mother_invite_status = str(
            mother_invite_state.get("status")
            if isinstance(mother_invite_state, dict) else ""
        ).strip().lower()
        result["invite_confirmed"] = bool(
            selected_child_id
            and (
                mother_invite_status == "completed"
                or (
                    not isinstance(mother_invite_state, dict)
                    and fill.remote_mutated
                    and fill_stage not in {
                        "planned", "candidate_login", "waiting_candidate",
                        "mother_invite", "candidate_account_deactivated",
                        "candidate_release_failed", "parent_session_unavailable",
                        "seat_capacity_unreliable",
                    }
                )
            )
        )
        membership = None
        if selected_child_id > 0:
            membership = session.exec(
                select(GptBusinessChildMembershipModel)
                .where(
                    GptBusinessChildMembershipModel.business_account_id
                    == int(row.business_parent_id)
                )
                .where(
                    GptBusinessChildMembershipModel.pro_account_id
                    == selected_child_id
                )
                .where(
                    GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
                )
                .order_by(GptBusinessChildMembershipModel.created_at.desc())
            ).first()
        membership_state = actions.get("membership")
        membership_status = str(
            membership_state.get("status")
            if isinstance(membership_state, dict) else ""
        ).strip().lower()
        accept_confirmed = bool(
            membership
            and (
                str(membership.remote_user_id or "").strip()
                or membership_status == "member"
            )
        )
        result["accept_confirmed"] = accept_confirmed
        result["replacement_membership_id"] = int(
            membership.id or 0
        ) if membership else 0
        rt_state = _business_fill_child_rt_action(actions)
        result["replacement_rt_confirmed"] = bool(
            isinstance(rt_state, dict) and rt_state.get("ready") is True
        )
        delivery_state = actions.get(str(row.provider or ""))
        result["replacement_upload_confirmed"] = bool(
            isinstance(delivery_state, dict)
            and delivery_state.get("synced") is True
        )
        if str(fill.state or "") == "completed" and (
            not demand or str(demand.state or "") == "completed"
        ):
            result["replacement_rt_confirmed"] = True
            result["replacement_upload_confirmed"] = True
            result["public_stage"] = "verifying_replacement"
    return result


def _team401_task_steps(
    row: DeliveryDeviceTeam401TaskModel,
    durable: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    durable = durable or _team401_durable_progress(row)
    stage = str(durable.get("public_stage") or row.stage or "queued")
    current_key = _TEAM401_STAGE_STEP.get(stage, "")
    failed = str(row.state or "") == "failed"
    branch = str(row.branch or "checking")
    if branch == "checking":
        labels = _TEAM401_CHECK_STEP_LABELS
    elif branch == "repair":
        labels = _TEAM401_REPAIR_STEP_LABELS
    elif bool(row.account_checked):
        labels = {**_TEAM401_CHECK_STEP_LABELS, **_TEAM401_STEP_LABELS}
    else:
        # Compatibility for pre-login-policy replacement rows already in
        # flight when this state machine version starts.
        labels = _TEAM401_STEP_LABELS
    replacement_keys = {
        "remove_old_child", "invite_replacement", "get_replacement_rt",
        "upload_replacement", "verify_replacement",
    }
    repair_keys = {
        "get_original_rt", "upload_original_credential",
        "verify_original_credential",
    }
    completed: set[str] = set()
    if bool(row.account_checked):
        completed.add("check_old_account")
    if branch == "repair" and bool(row.oauth_confirmed):
        completed.add("get_original_rt")
    if branch == "repair" and bool(row.device_upload_confirmed):
        completed.add("upload_original_credential")
    if branch == "repair" and bool(row.device_verify_confirmed):
        completed.add("verify_original_credential")
    if bool(row.device_delete_confirmed):
        completed.add("delete_old_credential")
    if bool(durable.get("cleanup_remove_confirmed")):
        completed.add("remove_old_child")
    if bool(durable.get("invite_confirmed")):
        completed.add("invite_replacement")
    if bool(durable.get("replacement_rt_confirmed")):
        completed.add("get_replacement_rt")
    if bool(durable.get("replacement_upload_confirmed")):
        completed.add("upload_replacement")
    if bool(row.device_verify_confirmed):
        completed.add("verify_replacement")
    if str(row.state or "") == "completed" and str(row.result or "") == "repaired":
        completed.update(repair_keys)
    elif str(row.state or "") == "completed":
        completed.update(replacement_keys)

    result: list[dict[str, Any]] = []
    for key, label in labels.items():
        if key in completed:
            status = "completed"
        elif key == current_key and failed:
            status = "failed"
        elif key == current_key and str(row.state or "") in {"running", "waiting"}:
            status = "running" if str(row.state or "") == "running" else "pending"
        else:
            status = "pending"
        result.append({
            "key": key,
            "status": status,
            "label": label,
            "error": (
                _TEAM401_ERROR_MESSAGES.get(str(row.error_code or ""), "")
                if status == "failed" else ""
            ),
            "updated_at": _safe_public_datetime(row.updated_at),
        })
    return result


def _team401_task_snapshot_row(
    row: DeliveryDeviceTeam401TaskModel,
) -> dict[str, Any]:
    try:
        immutable_request = _team401_task_request(row)
        request_version = int(immutable_request.get("version") or 1)
    except Exception:
        safe_error = "request_corrupt"
        request_version = 0
    else:
        safe_error = _team401_safe_error_code(row.error_code) \
            if str(row.error_code or "") else ""
    state = str(row.state or "prepared")
    status = "queued" if state == "prepared" else state
    if status not in {"queued", "running", "waiting", "completed", "failed"}:
        status = "failed"
        safe_error = safe_error or "internal_error"
    durable = _team401_durable_progress(row)
    stage = _team401_replacement_public_stage(
        durable.get("public_stage") or row.stage or "queued"
    )
    if stage not in _TEAM401_STAGES:
        stage = "failed"
    logs = _team401_log_entries(row.logs_json)
    persisted_diagnostic_stages = {
        str(item.get("stage") or "")
        for item in logs
        if isinstance(item, dict)
    }
    if status in {"queued", "running", "waiting"} and (
        not logs or str(logs[-1].get("stage") or "") != stage
    ):
        logs.append({
            "seq": int(logs[-1].get("seq") or 0) + 1 if logs else 1,
            "stage": stage,
            "message": _TEAM401_STAGE_MESSAGES.get(
                stage,
                "纠错任务状态已更新",
            ),
            "created_at": _safe_public_datetime(row.updated_at),
        })
        logs = logs[-100:]
    branch = str(row.branch or "checking")
    account_state = (
        "active"
        if (
            request_version >= 2
            and bool(row.account_checked)
            and branch == "repair"
            and "account_confirmed_active" in persisted_diagnostic_stages
        )
        else "dead"
        if (
            request_version >= 2
            and bool(row.account_checked)
            and branch == "replace"
            and "account_confirmed_dead" in persisted_diagnostic_stages
        )
        else "unknown"
    )
    return {
        "task_id": str(row.id),
        "key": str(row.id),
        # These are opaque lifecycle identifiers, not credentials.  Returning
        # them lets the UI prove that an older TEAM401 snapshot and the current
        # replenishment DTO describe the same durable operation, so effective
        # demand/fill state can replace stale child logs without touching an
        # unrelated task under the same mother account.
        "replenishment_demand_id": str(
            row.replenishment_demand_id or ""
        ),
        "fill_job_id": str(
            durable.get("fill_job_id") or row.fill_job_id or ""
        ),
        "source_email": _safe_child_progress_email(row.source_email),
        "replacement_email": _safe_child_progress_email(
            durable.get("replacement_email") or row.replacement_email
        ),
        "remote_id": _safe_inventory_remote_id(row.remote_id),
        "parent_id": int(row.business_parent_id),
        "child_id": int(row.child_id),
        "membership_id": int(row.membership_id),
        "branch": branch,
        "account_state": account_state,
        "status": status,
        "stage": stage,
        "result": str(row.result or ""),
        "error_code": safe_error,
        "error": _TEAM401_ERROR_MESSAGES.get(safe_error, ""),
        "retryable": status == "failed" and safe_error != "request_corrupt",
        "progress": {"percent": int(_TEAM401_STAGE_PERCENT.get(stage, 0))},
        "steps": _team401_task_steps(row, durable),
        "logs": logs,
        "attempt_count": max(0, int(row.attempt_count or 0)),
        "next_check_at": _safe_public_datetime(
            durable.get("next_check_at") or row.next_check_at
        ) or None,
        "created_at": _safe_public_datetime(row.created_at),
        "updated_at": _safe_public_datetime(row.updated_at),
        "finished_at": _safe_public_datetime(row.completed_at) or None,
    }


def _team401_batch_snapshot(
    device_ref: str,
    batch_id: str,
    *,
    reused: Optional[bool] = None,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _team401_recompute_batch(str(batch_id))
    with Session(engine) as session:
        batch = session.get(DeliveryDeviceTeam401BatchModel, str(batch_id))
        if not batch or not (
            str(batch.provider or "") == provider
            and int(batch.provider_id or 0) == provider_id
        ):
            raise HTTPException(404, "TEAM 401 纠错批次不存在")
        rows = session.exec(
            select(DeliveryDeviceTeam401TaskModel)
            .where(DeliveryDeviceTeam401TaskModel.batch_id == str(batch.id))
            .order_by(DeliveryDeviceTeam401TaskModel.created_at)
        ).all()
        items = [_team401_task_snapshot_row(row) for row in rows]
        status = str(batch.state or "prepared")
        if status == "prepared":
            status = "queued"
        if status not in {"queued", "running", "completed", "failed"}:
            status = "failed"
        running = sum(
            item["status"] in {"queued", "running", "waiting"}
            for item in items
        )
        result = {
            "ok": True,
            "batch_id": str(batch.id),
            "operation_id": str(batch.operation_id or ""),
            "device_ref": canonical,
            "business_parent_id": int(batch.business_parent_id),
            "status": status,
            "total": len(items),
            "completed": sum(item["status"] == "completed" for item in items),
            "failed": sum(item["status"] == "failed" for item in items),
            "running": int(running),
            "retryable": any(bool(item.get("retryable")) for item in items),
            "items": items,
            "created_at": _safe_public_datetime(batch.created_at),
            "updated_at": _safe_public_datetime(batch.updated_at),
            "finished_at": _safe_public_datetime(batch.completed_at) or None,
        }
        if reused is not None:
            result["reused"] = bool(reused)
        return result


def _team401_batch_candidates(
    provider: str,
    provider_id: int,
    parent_id: int,
    device_epoch: str,
) -> list[dict[str, Any]]:
    canonical = monitor.device_key(provider, provider_id)
    snapshot = monitor.get_accounts(canonical)
    rows = list(snapshot.get("items") or []) if isinstance(snapshot, dict) else []
    candidates: list[dict[str, Any]] = []
    seen_remote_ids: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        remote = dict(raw)
        navigation = remote.get("navigation") if isinstance(
            remote.get("navigation"), dict,
        ) else {}
        remote_id = str(remote.get("remote_id") or "").strip()
        if not (
            remote_id
            and remote_id not in seen_remote_ids
            and str(remote.get("quota_error_code") or "") == "401"
            and remote.get("credential_repair_required") is True
            and _inventory_positive_int(
                remote.get("credential_repair_status")
            ) == 401
            and monitor.is_team_plan(remote.get("plan"))
            and str(navigation.get("state") or "") == "mapped"
            and str(navigation.get("match_basis") or "") == "device_link"
            and str(navigation.get("target_kind") or "") == "business_child"
            and int(navigation.get("business_parent_id") or 0) == parent_id
        ):
            continue
        mapping = _business_child_mapping(provider, provider_id, remote)
        if not (
            str(mapping.get("state") or "") == "mapped"
            and int(mapping.get("parent_id") or 0) == parent_id
            and int(mapping.get("child_id") or 0)
            == int(navigation.get("pro_account_id") or 0)
            and int(mapping.get("membership_id") or 0)
            == int(navigation.get("membership_id") or 0)
            and int(mapping.get("policy_revision") or 0) > 0
        ):
            continue
        seen_remote_ids.add(remote_id)
        safe_remote = {
            "remote_id": remote_id,
            "name": str(remote.get("name") or "")[:500],
            "email": _normalized_email(remote.get("email")),
            "credential_repair_required": True,
            "credential_repair_status": 401,
        }
        request = {
            "version": 2,
            "provider": provider,
            "provider_id": int(provider_id),
            "device_epoch": device_epoch,
            "remote_id": remote_id,
            "remote": safe_remote,
            "source_email": _normalized_email(
                mapping.get("email") or remote.get("email")
            ),
            "business_parent_id": parent_id,
            "child_id": int(mapping.get("child_id") or 0),
            "membership_id": int(mapping.get("membership_id") or 0),
            "seat_type": str(mapping.get("seat_type") or ""),
            "target_kind": str(mapping.get("target_kind") or "member"),
            "remote_user_id": str(mapping.get("remote_user_id") or ""),
            "remote_invite_id": str(mapping.get("remote_invite_id") or ""),
            "policy_revision": int(mapping.get("policy_revision") or 0),
            "link_epoch": str(mapping.get("link_epoch") or ""),
            "dangerous_detected_at": str(
                mapping.get("dangerous_detected_at") or ""
            ),
            "snapshot_checked_at": _safe_public_datetime(
                remote.get("checked_at")
            ),
        }
        candidates.append(request)
    candidates.sort(key=lambda item: (
        str(item.get("source_email") or "").casefold(),
        str(item.get("remote_id") or ""),
    ))
    return candidates


def start_team401_correction_batch(
    device_ref: str,
    body: DeliveryTeam401CorrectionBatchRequest,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if monitor.get_device(canonical, include_accounts=False) is None:
        raise HTTPException(404, "设备不存在")
    parent_id = int(body.business_parent_id or 0)
    if parent_id <= 0:
        raise HTTPException(400, "business_parent_id 无效")
    operation_id = str(body.operation_id or "").strip() or (
        f"team401-{uuid.uuid4().hex}"
    )
    if not _SAFE_OPERATION_ID.fullmatch(operation_id):
        raise HTTPException(400, "operation_id 格式无效")

    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        if (
            parent
            and str(parent.refund_status or "").strip().lower()
            == _REFUNDED_PARENT_CLEANUP_STATUS
        ):
            raise HTTPException(409, {
                "code": "business_parent_refunded_pending_credit",
                "message": "母号已退款未到账，请先手动清理设备账号并解除绑定",
                "business_parent_id": parent_id,
                "refund_status": _REFUNDED_PARENT_CLEANUP_STATUS,
            })
        operation_row = session.exec(
            select(DeliveryDeviceTeam401BatchModel).where(
                DeliveryDeviceTeam401BatchModel.operation_id == operation_id
            )
        ).first()
        if operation_row:
            if not (
                str(operation_row.provider or "") == provider
                and int(operation_row.provider_id or 0) == provider_id
                and int(operation_row.business_parent_id or 0) == parent_id
            ):
                raise HTTPException(409, "operation_id 已绑定另一个纠错批次")
            batch_id = str(operation_row.id)
            session.expunge(operation_row)
            return _team401_batch_snapshot(canonical, batch_id, reused=True)
        active = session.exec(
            select(DeliveryDeviceTeam401BatchModel)
            .where(DeliveryDeviceTeam401BatchModel.provider == provider)
            .where(DeliveryDeviceTeam401BatchModel.provider_id == provider_id)
            .where(
                DeliveryDeviceTeam401BatchModel.business_parent_id == parent_id
            )
            .where(
                DeliveryDeviceTeam401BatchModel.state.in_(["prepared", "running"])
            )
            .order_by(DeliveryDeviceTeam401BatchModel.created_at.desc())
        ).first()
        if active:
            batch_id = str(active.id)
            session.expunge(active)
            return _team401_batch_snapshot(canonical, batch_id, reused=True)

    device_epoch = _device_epoch(provider, provider_id)
    candidates = _team401_batch_candidates(
        provider,
        provider_id,
        parent_id,
        device_epoch,
    )
    if not candidates:
        raise HTTPException(409, {
            "code": "team401_no_authorized_children",
            "message": "当前扫描结果中没有可纠错的 TEAM 401 子号",
        })
    batch_id = f"team401-batch-{uuid.uuid4().hex}"
    batch_scope = {
        "provider": provider,
        "provider_id": provider_id,
        "business_parent_id": parent_id,
        "operation_id": operation_id,
    }
    batch_key = "delivery-team401-batch:" + hashlib.sha256(
        json.dumps(
            batch_scope,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    now = _utcnow()
    task_ids: list[str] = []
    try:
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            batch = DeliveryDeviceTeam401BatchModel(
                id=batch_id,
                idempotency_key=batch_key,
                operation_id=operation_id,
                provider=provider,
                provider_id=provider_id,
                business_parent_id=parent_id,
                device_epoch=device_epoch,
                state="prepared",
                total_count=len(candidates),
                created_at=now,
                updated_at=now,
            )
            session.add(batch)
            for request in candidates:
                encoded = json.dumps(
                    request,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                request_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
                lifecycle_scope = {
                    key: request.get(key) for key in (
                        "provider", "provider_id", "remote_id",
                        "business_parent_id", "child_id", "membership_id",
                        "device_epoch", "policy_revision", "link_epoch",
                        "snapshot_checked_at",
                    )
                }
                idempotency_key = "delivery-team401-child:" + hashlib.sha256(
                    json.dumps(
                        lifecycle_scope,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                previous = session.exec(
                    select(DeliveryDeviceTeam401TaskModel).where(
                        DeliveryDeviceTeam401TaskModel.idempotency_key
                        == idempotency_key
                    )
                ).first()
                if previous:
                    raise HTTPException(409, {
                        "code": "team401_snapshot_already_processed",
                        "message": "该 401 快照已有纠错任务，请刷新设备后重试",
                        "batch_id": str(previous.batch_id),
                    })
                task_id = f"team401-task-{uuid.uuid4().hex}"
                row = DeliveryDeviceTeam401TaskModel(
                    id=task_id,
                    batch_id=batch_id,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    request_json=encoded,
                    provider=provider,
                    provider_id=provider_id,
                    remote_id=str(request.get("remote_id") or ""),
                    source_email=str(request.get("source_email") or ""),
                    business_parent_id=parent_id,
                    child_id=int(request.get("child_id") or 0),
                    membership_id=int(request.get("membership_id") or 0),
                    branch="checking",
                    state="prepared",
                    stage="queued",
                    logs_json=json.dumps([{
                        "seq": 1,
                        "stage": "queued",
                        "message": _TEAM401_STAGE_MESSAGES["queued"],
                        "created_at": now.isoformat(),
                    }], ensure_ascii=False, separators=(",", ":")),
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
                task_ids.append(task_id)
            session.commit()
    except HTTPException:
        raise
    except IntegrityError as exc:
        # Concurrent duplicate clicks can both pass the read-only precheck.
        # The unique operation/idempotency indexes serialize the commit; the
        # loser must return the winner's exact batch instead of turning an
        # otherwise idempotent HTTP retry into a 409.
        with Session(engine) as session:
            winner = session.exec(
                select(DeliveryDeviceTeam401BatchModel).where(
                    DeliveryDeviceTeam401BatchModel.operation_id
                    == operation_id
                )
            ).first()
            if winner and (
                str(winner.provider or "") == provider
                and int(winner.provider_id or 0) == provider_id
                and int(winner.business_parent_id or 0) == parent_id
            ):
                winner_id = str(winner.id)
                session.expunge(winner)
                return _team401_batch_snapshot(
                    canonical,
                    winner_id,
                    reused=True,
                )
        raise HTTPException(409, "纠错批次已由其他请求创建") from exc

    _team401_recompute_batch(batch_id)
    for task_id in task_ids[:_TEAM401_CONCURRENCY_MAX]:
        _start_team401_worker(task_id)
    return _team401_batch_snapshot(canonical, batch_id, reused=False)


def list_team401_correction_batches(
    device_ref: str,
    *,
    parent_id: Optional[int] = None,
    limit: int = 20,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    bounded = max(1, min(int(limit or 20), 100))
    with Session(engine) as session:
        query = (
            select(DeliveryDeviceTeam401BatchModel)
            .where(DeliveryDeviceTeam401BatchModel.provider == provider)
            .where(DeliveryDeviceTeam401BatchModel.provider_id == provider_id)
        )
        if parent_id is not None:
            query = query.where(
                DeliveryDeviceTeam401BatchModel.business_parent_id
                == int(parent_id)
            )
        rows = session.exec(
            query.order_by(
                DeliveryDeviceTeam401BatchModel.created_at.desc()
            ).limit(bounded)
        ).all()
        batch_ids = [str(row.id) for row in rows]
    items = [
        _team401_batch_snapshot(canonical, batch_id)
        for batch_id in batch_ids
    ]
    return {"ok": True, "device_ref": canonical, "items": items, "count": len(items)}


def get_team401_correction_task(
    device_ref: str,
    batch_id: str,
    task_id: str,
) -> dict[str, Any]:
    batch = _team401_batch_snapshot(device_ref, batch_id)
    with Session(engine) as session:
        row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        if not row or str(row.batch_id or "") != str(batch_id):
            raise HTTPException(404, "TEAM 401 子任务不存在")
        return {"ok": True, "batch_id": str(batch_id), **_team401_task_snapshot_row(row)}


def retry_team401_correction_task(
    device_ref: str,
    batch_id: str,
    task_id: str,
) -> dict[str, Any]:
    batch = _team401_batch_snapshot(device_ref, batch_id)
    provider, provider_id = monitor.parse_device_key(
        str(batch["device_ref"]),
    )
    now = _utcnow()
    # A failed TEAM401 row may already have crossed old-device deletion and
    # mother removal, with its shared replenishment/fill stopped at a retryable
    # step such as OAuth.  Resume those authoritative mother jobs before
    # re-queueing the thin device coordinator; otherwise it would immediately
    # observe the same terminal demand and fail again without doing work.
    with Session(engine) as session:
        preliminary = session.get(
            DeliveryDeviceTeam401TaskModel, str(task_id),
        )
        if not preliminary or str(preliminary.batch_id or "") != str(batch_id):
            raise HTTPException(404, "TEAM 401 子任务不存在")
        demand_id = str(preliminary.replenishment_demand_id or "")
        demand = (
            session.get(DeliveryDeviceReplenishmentDemandModel, demand_id)
            if demand_id else None
        )
        demand_requires_retry = bool(
            str(preliminary.state or "") == "failed"
            and str(preliminary.error_code or "") != "request_corrupt"
            and demand
            and str(demand.state or "") == "action_required"
        )
    if demand_requires_retry:
        from api import gpt_business

        continuation = (
            gpt_business
            .continue_business_device_replenishment_for_automation(
                provider,
                provider_id,
                demand_id,
            )
        )
        if str(continuation.get("kind") or "") == "not_ready":
            raise HTTPException(409, "母号补位任务当前不能从失败步骤继续")

    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        if not row or str(row.batch_id or "") != str(batch_id):
            session.rollback()
            raise HTTPException(404, "TEAM 401 子任务不存在")
        if str(row.state or "") == "completed":
            session.rollback()
            return {"ok": True, "batch_id": str(batch_id), "reused": True, **_team401_task_snapshot_row(row)}
        if str(row.state or "") != "failed" or str(row.error_code or "") == "request_corrupt":
            session.rollback()
            raise HTTPException(409, "该子任务当前不能安全重试")
        request = _team401_task_request(row)
        if not _device_epoch_is_current(
            str(request.get("provider") or ""),
            int(request.get("provider_id") or 0),
            str(request.get("device_epoch") or ""),
        ):
            session.rollback()
            raise HTTPException(409, "设备配置已变化，请重新扫描并创建批次")
        row.state = "queued"
        row.stage = _team401_resume_stage(row)
        row.result = ""
        row.error_code = ""
        row.worker_token = ""
        row.lease_expires_at = None
        row.next_check_at = now
        row.completed_at = None
        row.updated_at = now
        _team401_append_log(row, stage=str(row.stage or "queued"))
        session.add(row)
        session.commit()
    _team401_recompute_batch(str(batch["batch_id"]))
    _start_team401_worker(str(task_id))
    with Session(engine) as session:
        row = session.get(DeliveryDeviceTeam401TaskModel, str(task_id))
        return {"ok": True, "batch_id": str(batch_id), "reused": False, **_team401_task_snapshot_row(row)}


def _manual_replacement_existing_job(
    provider: str,
    provider_id: int,
    remote_id: str,
    body: DeliveryTeamReplacementTaskRequest,
    operation_id: str,
) -> Optional[DeliveryDeviceExhaustionCleanupModel]:
    with Session(engine) as session:
        operation_row = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel).where(
                DeliveryDeviceExhaustionCleanupModel.manual_operation_id
                == str(operation_id)
            )
        ).first()
        if operation_row and not (
            str(operation_row.provider or "") == str(provider)
            and int(operation_row.provider_id or 0) == int(provider_id)
            and str(operation_row.remote_id or "") == str(remote_id)
            and int(operation_row.business_parent_id or 0)
            == int(body.expected_business_parent_id)
            and int(operation_row.account_id or 0)
            == int(body.expected_pro_account_id)
            and int(operation_row.membership_id or 0)
            == int(body.expected_membership_id)
        ):
            raise HTTPException(409, "operation_id 已绑定另一个更换任务")
        if operation_row:
            session.expunge(operation_row)
            return operation_row
        rows = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel)
            .where(DeliveryDeviceExhaustionCleanupModel.provider == provider)
            .where(DeliveryDeviceExhaustionCleanupModel.provider_id == int(provider_id))
            .where(DeliveryDeviceExhaustionCleanupModel.remote_id == str(remote_id))
            .order_by(DeliveryDeviceExhaustionCleanupModel.created_at.desc())
        ).all()
        for row in rows:
            request = _json_object(row.request_json)
            if _cleanup_trigger(request) != "manual_replace":
                continue
            previous_operation = str(
                row.manual_operation_id
                or request.get("operation_id")
                or ""
            )
            expected = (
                (body.expected_business_parent_id, request.get("business_parent_id")),
                (body.expected_pro_account_id, request.get("account_id")),
                (body.expected_membership_id, request.get("membership_id")),
            )
            if any(
                wanted is not None and int(wanted) != int(actual or 0)
                for wanted, actual in expected
            ):
                continue
            if previous_operation != str(operation_id):
                raise HTTPException(409, {
                    "code": "team_replacement_already_exists",
                    "message": "该 TEAM 子号已有更换任务，请刷新界面查看原任务",
                    "task_id": str(row.id),
                })
            session.expunge(row)
            return row
    return None


def _manual_replacement_remote(
    canonical: str,
    remote_id: str,
) -> dict[str, Any]:
    snapshot = monitor.get_accounts(canonical)
    rows = snapshot.get("items") if isinstance(snapshot, dict) else []
    if not isinstance(rows, list):
        rows = []
    matches = [
        dict(item) for item in rows
        if isinstance(item, dict)
        and str(item.get("remote_id") or "").strip() == str(remote_id)
    ]
    if len(matches) != 1:
        raise HTTPException(409, {
            "code": "device_account_snapshot_changed",
            "message": "设备账号快照已变化，请刷新设备后重试",
        })
    return matches[0]


def _manual_replacement_preflight(
    *,
    provider: str,
    provider_id: int,
    mapping: dict[str, Any],
    operation_id: str,
) -> dict[str, Any]:
    """Database-only destructive preflight; no OpenAI/device request occurs."""
    from api import gpt_business

    parent_id = int(mapping.get("parent_id") or 0)
    account_id = int(mapping.get("child_id") or 0)
    membership_id = int(mapping.get("membership_id") or 0)
    seat_type = str(mapping.get("seat_type") or "").strip().lower()
    if parent_id <= 0 or account_id <= 0 or membership_id <= 0:
        raise HTTPException(409, "TEAM 子号本地归属不完整")
    if seat_type not in {"default", "prolite"}:
        raise HTTPException(409, "该子号席位类型未知，不能自动更换")
    now = _utcnow()
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        child = session.get(GptProAccountModel, account_id)
        membership = session.get(GptBusinessChildMembershipModel, membership_id)
        policy = session.get(GptBusinessAutomationPolicyModel, parent_id)
        if not parent or not bool(parent.enabled) or bool(parent.dangerous):
            raise HTTPException(409, "母号当前不可安全执行更换")
        if gpt_business._business_parent_refund_blocks_replacement(
            parent, session,
        ):
            raise HTTPException(409, "母号已进入已退款列表，不能更换子号")
        team_session = gpt_business._business_account_team_session_status(parent)
        if not bool(team_session.get("usable")):
            raise HTTPException(409, "母号登录会话不可用，请先重新登录")
        if not (
            child
            and int(child.business_parent_id or 0) == parent_id
            and membership
            and membership.ended_at is None
            and int(membership.business_account_id) == parent_id
            and int(membership.pro_account_id or 0) == account_id
            and str(membership.seat_type or "").strip().lower() == seat_type
        ):
            raise HTTPException(409, "TEAM 子号归属已变化，请刷新设备后重试")
        binding = (
            gpt_business._business_initial_fill_binding(policy)
            if policy else {}
        )
        delivery_type = str(binding.get("delivery_type") or "").strip().lower()
        bound_id = int(binding.get("target_id") or 0)
        if not (
            policy
            and bool(policy.auto_rotation_enabled)
            and delivery_type == provider
            and bound_id == int(provider_id)
        ):
            raise HTTPException(409, "母号已不再绑定当前设备，不能更换")
        for key in (f"parent:{parent_id}", f"child:{account_id}"):
            lease = session.get(GptBusinessAllocationLeaseModel, key)
            if lease and _active_lease(lease.expires_at, now):
                raise HTTPException(409, "母号或子号已有操作正在执行")
        account_lease = session.get(GptProAccountOperationLeaseModel, account_id)
        if account_lease and _active_lease(account_lease.expires_at, now):
            raise HTTPException(409, "子号已有设备操作正在执行")
        cooldown, invite_quota, remove_quota = (
            gpt_business._business_rotation_cooldown(
                session,
                parent_id,
                operation_id=operation_id,
                seat_type=seat_type,
            )
        )
        conflicting = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel)
            .where(DeliveryDeviceExhaustionCleanupModel.account_id == account_id)
            .where(DeliveryDeviceExhaustionCleanupModel.state != "completed")
        ).first()
        if conflicting:
            raise HTTPException(409, "该子号已有清理或更换任务正在执行")
    return {
        "parent_id": parent_id,
        "account_id": account_id,
        "membership_id": membership_id,
        "seat_type": seat_type,
        # The later mother invitation capability owns this wait.  Surface the
        # snapshot for UI context without using it to block device deletion or
        # mother removal.
        "invite_cooldown": {
            "active": cooldown is not None,
            "reason": str((cooldown or {}).get("failure_reason") or ""),
            "started_at": str((cooldown or {}).get("started_at") or ""),
            "until": str((cooldown or {}).get("until") or ""),
            "resume_at": str((cooldown or {}).get("resume_at") or ""),
        },
        "invite_quota": {
            "remaining": int(invite_quota.get("remaining") or 0),
            "limit": int(invite_quota.get("limit") or 0),
            "reset_at": str(invite_quota.get("reset_at") or ""),
        },
        "remove_quota": {
            "remaining": int(remove_quota.get("remaining") or 0),
            "limit": int(remove_quota.get("limit") or 0),
            "reset_at": str(
                remove_quota.get("next_available_at")
                or remove_quota.get("reset_at")
                or ""
            ),
        },
    }


def _run_manual_team_replacement(job_id: str) -> None:
    try:
        result = _run_delivery_exhaustion_cleanup(str(job_id))
        if str(result.get("kind") or "") not in {"success", "busy"}:
            return
        demand_id = str(result.get("replenishment_demand_id") or "")
        if not demand_id:
            with Session(engine) as session:
                demand = session.exec(
                    select(DeliveryDeviceReplenishmentDemandModel).where(
                        DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                        == str(job_id)
                    )
                ).first()
                demand_id = str(demand.id) if demand else ""
        if demand_id:
            from api import gpt_business

            gpt_business.run_or_resume_business_replenishment_for_automation(
                demand_id,
            )
    finally:
        with _REPLACEMENT_THREADS_LOCK:
            current = _REPLACEMENT_THREADS.get(str(job_id))
            if current is threading.current_thread():
                _REPLACEMENT_THREADS.pop(str(job_id), None)


def _start_manual_team_replacement_worker(job_id: str) -> bool:
    with _REPLACEMENT_THREADS_LOCK:
        current = _REPLACEMENT_THREADS.get(str(job_id))
        if current and current.is_alive():
            return False
        thread = threading.Thread(
            target=_run_manual_team_replacement,
            args=(str(job_id),),
            name=f"team-device-replacement-{str(job_id)[-12:]}",
            daemon=True,
        )
        _REPLACEMENT_THREADS[str(job_id)] = thread
        thread.start()
        return True


def _replacement_progress(stage: str, status: str) -> int:
    if status == "completed":
        return 100
    normalized = str(stage or "").strip().lower()
    exact = {
        "queued": 0,
        "preflight": 5,
        "device_delete_pending": 10,
        "removing_device_account": 20,
        "removing_exhausted_account": 20,
        "business_remove_pending": 30,
        "removing_business_child": 35,
        "replenishment_pending": 45,
        "checking_parent": 45,
        "waiting_candidate": 45,
        "planned": 45,
        "candidate_login": 45,
        "mother_invite": 50,
        "inviting": 50,
        "invited": 65,
        "pending_acceptance": 70,
        "auto_accept": 70,
        "rt_pending": 70,
        "oauth_pending": 70,
        "oauth_failed": 70,
        "acquiring_oauth": 70,
        "child_rt": 70,
        "cpa_sync": 85,
        "sub2api_sync": 85,
        "uploading_credential": 85,
        "active_verify": 95,
        "completed": 100,
    }
    if normalized in exact:
        return exact[normalized]
    if "invite" in normalized:
        return 50
    if "accept" in normalized or "member" in normalized:
        return 70
    if "oauth" in normalized or normalized.startswith("rt_"):
        return 70
    if "sync" in normalized or "upload" in normalized:
        return 85
    if status == "action_required":
        return 40
    return 45


_NONRETRYABLE_REPLENISHMENT_STAGES = frozenset({
    "seat_type_unknown",
    "fill_binding_conflict",
    "fill_job_missing",
    "binding_removed",
    "parent_missing",
})


def _manual_replenishment_retryable(
    demand: Optional[DeliveryDeviceReplenishmentDemandModel],
    fill: Optional[GptBusinessAllocationJobModel],
) -> bool:
    if demand is None:
        return False
    state = str(demand.state or "").strip().lower()
    stage = str(demand.stage or "").strip().lower()
    if state in {"completed", "cancelled"}:
        return False
    if stage in _NONRETRYABLE_REPLENISHMENT_STAGES:
        return False
    if fill is not None and str(fill.state or "") in {
        "failed", "action_required",
    } and not bool(fill.retryable):
        return False
    return True


def _manual_replacement_task_snapshot(
    device_ref: str,
    task_id: str,
    *,
    since: int = 0,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    with Session(engine) as session:
        job = session.get(DeliveryDeviceExhaustionCleanupModel, str(task_id))
        if not job:
            raise HTTPException(404, "TEAM 子号更换任务不存在")
        request = _cleanup_request(job)
        if not (
            _cleanup_trigger(request) == "manual_replace"
            and str(request.get("provider") or "") == provider
            and int(request.get("provider_id") or 0) == provider_id
        ):
            raise HTTPException(404, "TEAM 子号更换任务不存在")
        demand = session.exec(
            select(DeliveryDeviceReplenishmentDemandModel).where(
                DeliveryDeviceReplenishmentDemandModel.cleanup_job_id
                == str(job.id)
            )
        ).first()
        fill = (
            session.get(GptBusinessAllocationJobModel, str(demand.fill_job_id))
            if demand and str(demand.fill_job_id or "") else None
        )

        cleanup_state = str(job.state or "prepared")
        stage = str(job.stage or "queued")
        status = "queued" if cleanup_state == "prepared" else "running"
        retryable = (
            cleanup_state not in {"completed", "superseded"}
            and stage not in _NONRETRYABLE_MANUAL_CLEANUP_STAGES
        )
        error = str(job.error or "")[:200]
        resume_at = ""
        if cleanup_state in {"action_required", "failed", "superseded"}:
            status = "action_required"
        elif cleanup_state == "completed":
            stage = str(demand.stage or "replenishment_pending") if demand else "replenishment_pending"
            if not demand:
                status = "action_required"
                error = "补位任务未建立，请重试"
            elif str(demand.state or "") == "completed":
                status = "completed"
                stage = "completed"
                retryable = False
            elif str(demand.state or "") in {"cancelled", "action_required"}:
                status = "action_required"
                retryable = _manual_replenishment_retryable(demand, fill)
                error = str(demand.error or "")[:200]
            elif fill:
                stage = str(fill.stage or demand.stage or "fill_running")
                if (
                    str(fill.state or "") in {"failed", "action_required"}
                    and not bool(fill.retryable)
                ):
                    status = "action_required"
                    retryable = False
                    error = "新子号补位需要人工复核"
                else:
                    status = "running"
                    retryable = True
            else:
                status = "running"
                retryable = True
            if demand:
                resume_at = (
                    demand.resume_at.isoformat() if demand.resume_at
                    else demand.next_check_at.isoformat() if demand.next_check_at
                    else ""
                )

        if status == "completed":
            stage = "completed"
        elif cleanup_state != "completed":
            stage = {
                "device_delete_pending": "removing_device_account",
                "removing_device_account": "removing_device_account",
                "business_remove_pending": "removing_business_child",
                "removing_business_child": "removing_business_child",
            }.get(str(stage or "").strip().lower(), "removing_device_account")
        else:
            stage = _safe_replenishment_child_stage(
                stage,
                has_fill=fill is not None,
            )

        logs = ["已确认 TEAM 子号、母号、席位类型及邀请失败冷却状态"]
        if bool(job.device_delete_confirmed):
            logs.append("旧账号已从当前设备精确删除")
        elif stage == "removing_device_account":
            logs.append("正在删除当前设备中的旧账号")
        if bool(job.business_remove_confirmed):
            logs.append("旧子号已从母号移除")
        elif bool(job.device_delete_confirmed):
            logs.append("正在从母号移除旧子号")
        if demand:
            logs.append("已建立同席位类型补位任务")
        if fill:
            fill_stage = str(fill.stage or "")
            if "invite" in fill_stage or fill_stage in {"planned", "candidate_login"}:
                logs.append("正在选择并邀请新的子号")
            if (
                fill_stage in {"invited", "pending_acceptance", "auto_accept"}
                or "accept" in fill_stage
                or "member" in fill_stage
                or "oauth" in fill_stage
                or fill_stage.startswith("rt_")
            ):
                logs.append("正在通过子号能力加入母号并获取 RT / OAuth")
            if "sync" in fill_stage or "upload" in fill_stage or fill_stage == "active_verify":
                logs.append("正在将新子号同步到原设备")
        if status == "completed":
            logs.append("新子号已获取 RT 并同步到原设备，更换完成")
        if status == "action_required" and error:
            logs.append("任务需要人工处理或重试")
        safe_logs = [_safe_task_log_line(line) for line in logs]
        cursor = max(0, min(int(since or 0), len(safe_logs)))
        new_child_id = int(fill.selected_pro_account_id or 0) if fill else 0
        updated_at = (
            fill.updated_at if fill else demand.updated_at if demand else job.updated_at
        )
        completed_at = (
            fill.completed_at if fill and fill.completed_at
            else demand.completed_at if demand and demand.completed_at
            else job.completed_at if status == "completed"
            else None
        )
        return {
            "ok": True,
            "task_id": str(job.id),
            "device_ref": canonical,
            "operation_id": str(request.get("operation_id") or ""),
            "remote_id": str(
                (request.get("remote") or {}).get("remote_id")
                if isinstance(request.get("remote"), dict) else ""
            ),
            "account_label": str(
                request.get("email")
                or (
                    (request.get("remote") or {}).get("remote_id")
                    if isinstance(request.get("remote"), dict) else ""
                )
                or "TEAM 子号"
            ),
            "status": status,
            "stage": stage,
            "logs": safe_logs[cursor:],
            "since": len(safe_logs),
            "progress": {"percent": _replacement_progress(stage, status)},
            "error": _safe_task_log_line(error) if error else None,
            "resume_at": resume_at,
            "retryable": bool(retryable),
            "result": {
                "business_parent_id": int(request.get("business_parent_id") or 0),
                "old_pro_account_id": int(request.get("account_id") or 0),
                "membership_id": int(request.get("membership_id") or 0),
                "remote_id": str(
                    (request.get("remote") or {}).get("remote_id")
                    if isinstance(request.get("remote"), dict) else ""
                ),
                "old_account_email": str(request.get("email") or ""),
                "seat_type": str(request.get("seat_type") or ""),
                "business_removed": bool(job.business_remove_confirmed),
                "device_removed": bool(job.device_delete_confirmed),
                "replenishment_demand_id": str(demand.id) if demand else "",
                "fill_job_id": str(demand.fill_job_id or "") if demand else "",
                "new_pro_account_id": new_child_id or None,
            },
            "created_at": job.created_at.isoformat(),
            "updated_at": updated_at.isoformat() if updated_at else "",
            "finished_at": completed_at.isoformat() if completed_at else None,
            "timestamps": {
                "created_at": job.created_at.isoformat(),
                "updated_at": updated_at.isoformat() if updated_at else "",
                "finished_at": completed_at.isoformat() if completed_at else None,
            },
        }


def list_delivery_team_replacement_tasks(
    device_ref: str,
    *,
    limit: int = 20,
) -> dict[str, Any]:
    """Return active first, then recent durable replacements for UI recovery."""
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if monitor.get_device(canonical, include_accounts=False) is None:
        raise HTTPException(404, "设备不存在")
    bounded = max(1, min(int(limit or 20), 100))
    with Session(engine) as session:
        rows = session.exec(
            select(DeliveryDeviceExhaustionCleanupModel)
            .where(DeliveryDeviceExhaustionCleanupModel.provider == provider)
            .where(
                DeliveryDeviceExhaustionCleanupModel.provider_id
                == int(provider_id)
            )
            .where(
                DeliveryDeviceExhaustionCleanupModel.idempotency_key.like(
                    "delivery-manual-replace:%"
                )
            )
            .order_by(DeliveryDeviceExhaustionCleanupModel.created_at.desc())
            .limit(max(100, bounded * 5))
        ).all()
        task_ids = [str(row.id) for row in rows]
    active_items: list[dict[str, Any]] = []
    completed_items: list[dict[str, Any]] = []
    for task_id in task_ids:
        snapshot = _manual_replacement_task_snapshot(canonical, task_id)
        result = snapshot.get("result") if isinstance(
            snapshot.get("result"), dict,
        ) else {}
        item = {
            **snapshot,
            "remote_id": str(result.get("remote_id") or ""),
            "account_label": str(
                result.get("old_account_email")
                or result.get("remote_id")
                or "TEAM 子号"
            ),
        }
        if str(snapshot.get("status") or "") == "completed":
            completed_items.append(item)
        else:
            active_items.append(item)
    items = (active_items + completed_items)[:bounded]
    return {
        "ok": True,
        "device_ref": canonical,
        "items": items,
        "count": len(items),
        "active_count": len(active_items),
    }


def start_delivery_team_replacement_task(
    device_ref: str,
    body: DeliveryTeamReplacementTaskRequest,
) -> dict[str, Any]:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if monitor.get_device(canonical, include_accounts=False) is None:
        raise HTTPException(404, "设备不存在")
    remote_id = str(body.remote_id or "").strip()
    if not remote_id or len(remote_id) > 500:
        raise HTTPException(400, "remote_id 无效")
    if min(
        int(body.expected_business_parent_id),
        int(body.expected_pro_account_id),
        int(body.expected_membership_id),
    ) <= 0:
        raise HTTPException(400, "TEAM 子号本地归属标识无效")
    operation_id = str(body.operation_id or "").strip() or (
        f"manual-replace-{uuid.uuid4().hex}"
    )
    if not _SAFE_OPERATION_ID.fullmatch(operation_id):
        raise HTTPException(400, "operation_id 格式无效")

    previous = _manual_replacement_existing_job(
        provider, provider_id, remote_id, body, operation_id,
    )
    if previous:
        if str(previous.state or "") != "completed":
            _start_manual_team_replacement_worker(str(previous.id))
        snapshot = _manual_replacement_task_snapshot(canonical, str(previous.id))
        return {**snapshot, "reused": True}

    remote = _manual_replacement_remote(canonical, remote_id)
    mapping = _business_child_mapping(provider, provider_id, remote)
    if str(mapping.get("state") or "") != "mapped":
        raise HTTPException(409, {
            "code": "team_child_mapping_unavailable",
            "message": "账号无法唯一映射到当前 TEAM 子号，未执行任何操作",
        })
    expected = (
        (body.expected_business_parent_id, mapping.get("parent_id")),
        (body.expected_pro_account_id, mapping.get("child_id")),
        (body.expected_membership_id, mapping.get("membership_id")),
    )
    if any(
        wanted is not None and int(wanted) != int(actual or 0)
        for wanted, actual in expected
    ):
        raise HTTPException(409, "界面中的 TEAM 子号归属已过期，请刷新后重试")
    preflight = _manual_replacement_preflight(
        provider=provider,
        provider_id=provider_id,
        mapping=mapping,
        operation_id=operation_id,
    )
    job = _create_or_get_cleanup_job(
        provider=provider,
        provider_id=provider_id,
        remote=remote,
        mapping=mapping,
        device_epoch=_device_epoch(provider, provider_id),
        trigger_kind="manual_replace",
        operation_id=operation_id,
    )
    _start_manual_team_replacement_worker(str(job.id))
    snapshot = _manual_replacement_task_snapshot(canonical, str(job.id))
    return {
        **snapshot,
        "reused": False,
        "operation_id": operation_id,
        "preflight": preflight,
    }


def retry_delivery_team_replacement_task(
    device_ref: str,
    task_id: str,
) -> dict[str, Any]:
    snapshot = _manual_replacement_task_snapshot(device_ref, task_id)
    provider, provider_id = monitor.parse_device_key(
        str(snapshot["device_ref"]),
    )
    if str(snapshot.get("status") or "") == "completed":
        return {**snapshot, "reused": True}
    if not bool(snapshot.get("retryable")):
        raise HTTPException(409, "该更换任务当前不能安全重试")
    result = snapshot.get("result") if isinstance(
        snapshot.get("result"), dict,
    ) else {}
    demand_id = str(result.get("replenishment_demand_id") or "")
    if demand_id:
        with Session(engine) as session:
            demand = session.get(
                DeliveryDeviceReplenishmentDemandModel, demand_id,
            )
            demand_state = str(demand.state or "") if demand else ""
        if demand_state == "action_required":
            from api import gpt_business

            continuation = (
                gpt_business
                .continue_business_device_replenishment_for_automation(
                    provider,
                    provider_id,
                    demand_id,
                )
            )
            if str(continuation.get("kind") or "") == "not_ready":
                raise HTTPException(409, "该补位任务需要人工复核，不能自动重试")
    _start_manual_team_replacement_worker(str(task_id))
    return _manual_replacement_task_snapshot(device_ref, task_id)


def _public_result(device_ref: str, refresh: dict | None = None) -> dict:
    device = monitor.get_device(device_ref, include_accounts=True)
    if not device:
        raise HTTPException(404, "设备不存在")
    refresh_error = ""
    if isinstance(refresh, dict):
        refresh_error = str(refresh.get("refresh_error") or "")
    refresh_error = refresh_error or str(device.get("accounts_refresh_error") or "")
    accounts = list(device.get("accounts") or [])
    return {
        "ok": True,
        "device": device,
        "refresh": refresh,
        "refresh_ok": bool(refresh.get("ok")) if isinstance(refresh, dict) else not bool(refresh_error),
        "refresh_error": refresh_error,
        "accounts_refresh_error": refresh_error,
        "accounts_refreshed_at": device.get("accounts_refreshed_at"),
        "accounts": accounts,
        "items": accounts,
        "total": len(accounts),
    }


def create_delivery_device(body: DeliveryDeviceCreateRequest) -> dict:
    provider = _validated_provider(body.type or body.provider)
    name = str(body.name or "").strip()
    if not name:
        raise HTTPException(400, "设备名称不能为空")
    api_url = _validated_url(body.api_url)
    api_key = str(body.api_key or "").strip()
    if not api_key:
        raise HTTPException(400, "API 密钥不能为空")
    if provider == "cpa":
        if body.enabled is False:
            raise HTTPException(400, "CPA 共享目标不支持停用，请删除目标或保持启用")
        from api.gpt_plan_operations import _cpa_sync_targets_snapshot, _save_cpa_sync_targets

        targets, revision = _cpa_sync_targets_snapshot()
        old_ids = {
            int(item.get("id") or 0)
            for item in targets
            if isinstance(item, dict) and str(item.get("id") or "").isdigit()
        }
        saved, _new_revision = _save_cpa_sync_targets(
            [*targets, {"name": name, "api_url": api_url, "api_key": api_key}],
            expected_revision=revision,
            return_revision=True,
        )
        created = next(
            (
                item for item in saved
                if int(item.get("id") or 0) not in old_ids
                and str(item.get("api_url") or "").rstrip("/").lower() == api_url.lower()
            ),
            None,
        )
        if not created:
            raise HTTPException(500, "CPA 设备保存后未能确认设备 ID")
        device_ref = monitor.device_key("cpa", created["id"])
    else:
        with Session(engine) as session:
            row = SyncDeviceModel(
                name=name,
                type="sub2api",
                api_url=api_url,
                api_key=api_key,
                platform="chatgpt",
                sub_group_ids=str(body.sub_group_ids or "2").strip() or "2",
                wants_refresh_token=True,
                enabled=bool(body.enabled),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            device_ref = monitor.device_key("sub2api", row.id)
    # Device persistence is authoritative. A transient remote failure is kept
    # on the snapshot state and never rolls the newly saved connection back.
    refresh = monitor.refresh_device(device_ref)
    return _public_result(device_ref, refresh)


def update_delivery_device(device_ref: str, body: DeliveryDeviceUpdateRequest) -> dict:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    with monitor.device_refresh_lock(canonical):
        _assert_no_hosting_worker(canonical)
        return _update_delivery_device_locked(canonical, body)


def _update_delivery_device_locked(
    device_ref: str,
    body: DeliveryDeviceUpdateRequest,
) -> dict:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    api_url = _validated_url(body.api_url) if body.api_url is not None else None
    if provider == "cpa":
        if body.enabled is False:
            raise HTTPException(400, "CPA 共享目标不支持停用，请删除目标或保持启用")
        from api.gpt_plan_operations import _cpa_sync_targets_snapshot, _save_cpa_sync_targets

        targets, revision = _cpa_sync_targets_snapshot()
        found = False
        updated: list[dict] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            try:
                current_id = int(target.get("id") or 0)
            except (TypeError, ValueError):
                current_id = 0
            item = dict(target)
            if current_id == provider_id:
                found = True
                if body.name is not None:
                    name = str(body.name or "").strip()
                    if not name:
                        raise HTTPException(400, "设备名称不能为空")
                    item["name"] = name
                if api_url is not None:
                    item["api_url"] = api_url
                # The read DTO never contains the old key. Empty/omitted means
                # keep it; a non-empty value explicitly rotates the key.
                if body.api_key is not None and str(body.api_key or "").strip():
                    item["api_key"] = str(body.api_key).strip()
            updated.append(item)
        if not found:
            raise HTTPException(404, "CPA 设备不存在")
        _save_cpa_sync_targets(
            updated,
            expected_revision=revision,
            return_revision=True,
        )
    else:
        from api.devices import DeviceUpdateRequest, update_device

        update_payload: dict = {}
        if body.name is not None:
            name = str(body.name or "").strip()
            if not name:
                raise HTTPException(400, "设备名称不能为空")
            update_payload["name"] = name
        if api_url is not None:
            update_payload["api_url"] = api_url
        if body.api_key is not None and str(body.api_key or "").strip():
            update_payload["api_key"] = str(body.api_key).strip()
        if body.enabled is not None:
            update_payload["enabled"] = bool(body.enabled)
        if body.sub_group_ids is not None:
            update_payload["sub_group_ids"] = str(body.sub_group_ids or "2").strip() or "2"
        # Reuse the canonical GPT PRO/BUSINESS reference fence. In particular,
        # a bound Sub2API device cannot silently change URL or clear its key.
        update_device(provider_id, DeviceUpdateRequest(**update_payload))
    refresh = monitor.refresh_device(device_ref)
    return _public_result(device_ref, refresh)


def _active_refresh_task_for_device(device_ref: str) -> Optional[dict[str, Any]]:
    with _REFRESH_TASK_LOCK:
        task_id = str(_REFRESH_ACTIVE_BY_DEVICE.get(str(device_ref)) or "")
        task = _REFRESH_TASKS.get(task_id) if task_id else None
        if not task or str(task.get("status") or "") in _REFRESH_TASK_TERMINAL:
            return None
        return {
            "task_id": task_id,
            "status": str(task.get("status") or "queued"),
            "stage": str(task.get("stage") or "queued"),
        }


def _json_references_cpa_target(value: Any, target_id: int) -> bool:
    """Recognize only explicit CPA target references in durable job payloads."""
    if isinstance(value, list):
        return any(_json_references_cpa_target(item, target_id) for item in value)
    if not isinstance(value, dict):
        return isinstance(value, str) and value.strip().lower() == f"cpa:{target_id}"
    provider = str(value.get("provider") or value.get("delivery_type") or "").strip().lower()
    for key, item in value.items():
        normalized_key = str(key or "").strip().lower()
        if normalized_key in {"device_ref", "target_device_ref", "source_device_ref"}:
            if str(item or "").strip().lower() == f"cpa:{target_id}":
                return True
        if normalized_key == "cpa_target_id":
            try:
                if int(item or 0) == int(target_id):
                    return True
            except (TypeError, ValueError):
                pass
        if provider == "cpa" and normalized_key in {
            "provider_id", "device_id", "target_id",
        }:
            try:
                if int(item or 0) == int(target_id):
                    return True
            except (TypeError, ValueError):
                pass
        if isinstance(item, (dict, list)) and _json_references_cpa_target(
            item, target_id,
        ):
            return True
    return False


def _cpa_delete_error(
    *,
    status_code: int,
    code: str,
    message: str,
    device_ref: str,
    target_id: int,
    blockers: Optional[Any] = None,
    **extra: Any,
) -> HTTPException:
    detail: dict[str, Any] = {
        "code": code,
        "message": message,
        "device_ref": device_ref,
        "target_id": int(target_id),
        "blockers": blockers or {},
        "cleared_stale_links": 0,
    }
    detail.update(extra)
    return HTTPException(status_code, detail)


def _public_cpa_delete_blockers(
    blockers: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    """Map detailed internal fences to the four stable UI blocker groups."""
    local_link_types = {
        "gpt_pro_state_invalid",
        "business_child_link",
        "gpt_pro_link_scope_conflict",
        "gpt_pro_uncommitted_reference",
    }
    business_policy_types = {
        "business_policy",
        "business_direct_link",
        "business_direct_state_invalid",
    }
    grouped_items: dict[str, list[dict[str, Any]]] = {
        "remote_accounts": [],
        "local_links": [],
        "business_policies": [],
        "pending_operations": [],
    }
    counts = {
        "remote_accounts": 0,
        "local_links": 0,
        "business_policies": 0,
        "pending_operations": 0,
    }
    for raw in blockers:
        item = dict(raw)
        operation_type = str(item.get("type") or "unknown")
        if operation_type == "remote_accounts":
            category = "remote_accounts"
        elif operation_type in local_link_types:
            category = "local_links"
        elif operation_type in business_policy_types:
            category = "business_policies"
        else:
            category = "pending_operations"
        item["operation_type"] = operation_type
        grouped_items[category].append(item)
        counts[category] += max(
            1,
            int(item.get("count") or 0),
        )
    public = {
        category: {
            "count": counts[category],
            "items": items[:100],
        }
        for category, items in grouped_items.items()
    }
    return public, counts


def _cpa_target_registry_in_session(
    session: Session,
    *,
    fallback_targets: list[dict],
) -> tuple[list[dict], int]:
    from core.config_store import ConfigItem
    from api.gpt_plan_operations import (
        _CPA_SYNC_TARGETS_KEY,
        _CPA_SYNC_TARGETS_REVISION_KEY,
    )

    target_item = session.get(ConfigItem, _CPA_SYNC_TARGETS_KEY)
    revision_item = session.get(ConfigItem, _CPA_SYNC_TARGETS_REVISION_KEY)
    if target_item is None:
        targets: Any = list(fallback_targets)
    else:
        try:
            targets = json.loads(str(target_item.value or "[]"))
        except Exception as exc:
            raise HTTPException(503, {
                "code": "cpa_target_registry_invalid",
                "message": "CPA 设备配置损坏，暂不能删除设备",
            }) from exc
    if not isinstance(targets, list) or any(not isinstance(item, dict) for item in targets):
        raise HTTPException(503, {
            "code": "cpa_target_registry_invalid",
            "message": "CPA 设备配置损坏，暂不能删除设备",
        })
    try:
        revision = int(revision_item.value or 0) if revision_item else 0
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, {
            "code": "cpa_target_registry_invalid",
            "message": "CPA 设备配置版本损坏，暂不能删除设备",
        }) from exc
    return list(targets), revision


def _strict_extra_json(raw: Any) -> dict[str, Any]:
    value = json.loads(str(raw or "{}"))
    if not isinstance(value, dict):
        raise ValueError("extra_json must be an object")
    return value


def _delete_empty_cpa_target_transaction(
    *,
    target_id: int,
    device_ref: str,
    expected_targets: list[dict],
    expected_revision: int,
    expected_api_url: str,
    expected_api_key: str,
    remote_checked_at: datetime,
) -> dict[str, Any]:
    """Atomically clear verified-stale links and delete one CPA registry row."""
    from api.gpt_plan_operations import (
        _CPA_CONFIG_WRITE_LOCK,
        _begin_cpa_config_write,
        _clear_manual_cpa_link_after_confirmed_target_absence,
        _manual_cpa_target_delete_account_state,
        _write_cpa_targets_in_session,
    )

    with _CPA_CONFIG_WRITE_LOCK:
        with Session(engine) as session:
            _begin_cpa_config_write(session)
            targets, revision = _cpa_target_registry_in_session(
                session,
                fallback_targets=expected_targets,
            )
            target = next((
                item for item in targets
                if str(item.get("id") or "").isdigit()
                and int(item.get("id") or 0) == int(target_id)
            ), None)
            current_url = str((target or {}).get("api_url") or "").strip().rstrip("/")
            current_key = str((target or {}).get("api_key") or "").strip()
            if (
                revision != int(expected_revision)
                or target is None
                or current_url.lower() != str(expected_api_url).rstrip("/").lower()
                or current_key != str(expected_api_key)
            ):
                raise _cpa_delete_error(
                    status_code=409,
                    code="cpa_sync_targets_revision_conflict",
                    message="CPA 设备配置在远端核对后发生变化，请刷新后重试",
                    device_ref=device_ref,
                    target_id=target_id,
                    expected_revision=int(expected_revision),
                    current_revision=int(revision),
                )

            blockers: list[dict[str, Any]] = []
            candidates: list[GptProAccountModel] = []
            now = _utcnow()

            active_memberships_by_child: dict[int, list[GptBusinessChildMembershipModel]] = {}
            for membership in session.exec(
                select(GptBusinessChildMembershipModel).where(
                    GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
                )
            ).all():
                child_id = int(membership.pro_account_id or 0)
                if child_id > 0:
                    active_memberships_by_child.setdefault(child_id, []).append(membership)

            policy_query = select(GptBusinessAutomationPolicyModel).where(
                GptBusinessAutomationPolicyModel.cpa_target_id == int(target_id)
            )
            if session.get_bind().dialect.name != "sqlite":
                policy_query = policy_query.with_for_update()
            for policy in session.exec(policy_query).all():
                if _business_policy_device_ref(policy) != device_ref:
                    continue
                parent_id = int(policy.business_account_id or 0)
                parent = session.get(GptBusinessAccountModel, parent_id)
                blockers.append({
                    "type": "business_policy",
                    "business_account_id": parent_id,
                    "email": str(getattr(parent, "email", "") or ""),
                    "note": str(getattr(parent, "note", "") or "")[:500],
                    "message": "BUSINESS 母号仍绑定当前设备，请先解除绑定",
                })

            account_query = select(GptProAccountModel)
            if session.get_bind().dialect.name != "sqlite":
                account_query = account_query.with_for_update()
            accounts = session.exec(account_query).all()
            for account in accounts:
                active_memberships = active_memberships_by_child.get(
                    int(account.id or 0), [],
                )
                if account.business_parent_id is not None or active_memberships:
                    # A retired TEAM child is historical account data, even if
                    # its old device JSON is malformed. It cannot be repaired
                    # through the removed device automation UI and therefore
                    # must not permanently block an empty device deletion.
                    continue
                try:
                    _strict_extra_json(account.extra_json)
                except Exception:
                    blockers.append({
                        "type": "gpt_pro_state_invalid",
                        "account_id": int(account.id or 0),
                        "email": str(account.email or ""),
                        "message": "账号 CPA 状态无法解析",
                    })
                    continue
                state = _manual_cpa_target_delete_account_state(account, target_id)
                if not state.get("references_target"):
                    continue
                lease = session.get(
                    GptProAccountOperationLeaseModel,
                    int(account.id or 0),
                )
                lease_expires = _aware_cleanup_time(lease.expires_at) if lease else None
                lease_active = bool(lease_expires and lease_expires > now)
                if state.get("business_lifecycle"):
                    # TEAM/BUSINESS delivery is retired. Preserve the old
                    # account/membership metadata as history, but do not make
                    # it an active device-config blocker with no unlink UI.
                    continue
                if state.get("pending"):
                    blockers.append({
                        "type": "gpt_pro_pending_operation",
                        "account_id": int(account.id or 0),
                        "email": str(account.email or ""),
                        "states": list(state.get("pending") or []),
                    })
                elif lease_active:
                    blockers.append({
                        "type": "gpt_pro_operation_lease",
                        "account_id": int(account.id or 0),
                        "email": str(account.email or ""),
                        "operation": str(lease.operation or ""),
                        "expires_at": lease_expires.isoformat() if lease_expires else "",
                    })
                elif state.get("scope_conflict"):
                    blockers.append({
                        "type": "gpt_pro_link_scope_conflict",
                        "account_id": int(account.id or 0),
                        "email": str(account.email or ""),
                    })
                elif state.get("committed"):
                    candidates.append(account)
                else:
                    blockers.append({
                        "type": "gpt_pro_uncommitted_reference",
                        "account_id": int(account.id or 0),
                        "email": str(account.email or ""),
                    })

            cleanups = session.exec(
                select(DeliveryDeviceExhaustionCleanupModel)
                .where(DeliveryDeviceExhaustionCleanupModel.provider == "cpa")
                .where(DeliveryDeviceExhaustionCleanupModel.provider_id == int(target_id))
                .where(DeliveryDeviceExhaustionCleanupModel.state.in_([
                    "prepared", "running", "action_required", "failed",
                ]))
            ).all()
            for cleanup in cleanups:
                blockers.append({
                    "type": "delivery_exhaustion_cleanup",
                    "job_id": str(cleanup.id),
                    "state": str(cleanup.state or ""),
                    "stage": str(cleanup.stage or ""),
                })

            demands = session.exec(
                select(DeliveryDeviceReplenishmentDemandModel)
                .where(DeliveryDeviceReplenishmentDemandModel.provider == "cpa")
                .where(DeliveryDeviceReplenishmentDemandModel.device_id == int(target_id))
            ).all()
            for demand in demands:
                if str(demand.state or "") in {"completed", "cancelled"}:
                    continue
                blockers.append({
                    "type": "delivery_replenishment",
                    "job_id": str(demand.id),
                    "state": str(demand.state or ""),
                    "stage": str(demand.stage or ""),
                    "business_account_id": int(demand.business_parent_id or 0),
                })

            # Retired/terminal BUSINESS delivery jobs are audit history only;
            # they must not prevent deletion of an otherwise empty device.
            job_query = select(GptBusinessAllocationJobModel).where(
                GptBusinessAllocationJobModel.state.notin_([
                    "completed", "failed", "cancelled",
                ])
            )
            for job in session.exec(job_query).all():
                try:
                    request = _strict_extra_json(job.request_json)
                    action = _strict_extra_json(job.action_state_json)
                except Exception:
                    blockers.append({
                        "type": "business_job_state_invalid",
                        "job_id": str(job.id),
                        "message": "BUSINESS 调度任务状态无法解析",
                    })
                    continue
                if not (
                    _json_references_cpa_target(request, target_id)
                    or _json_references_cpa_target(action, target_id)
                ):
                    continue
                blockers.append({
                    "type": "business_delivery_job",
                    "job_id": str(job.id),
                    "state": str(job.state or ""),
                    "stage": str(job.stage or ""),
                })

            # Serialize the final device-exists check with refresh-task
            # creation. Once this lock is held, either the queued task wins and
            # deletion reports it, or registry deletion commits before a new
            # task can observe the target.
            with _REFRESH_TASK_LOCK:
                active_refresh = _active_refresh_task_for_device(device_ref)
                if active_refresh:
                    blockers.append({"type": "device_refresh_task", **active_refresh})

                if blockers:
                    public_blockers, counts = _public_cpa_delete_blockers(blockers)
                    raise _cpa_delete_error(
                        status_code=409,
                        code="cpa_device_delete_blocked",
                        message="CPA 设备仍有关联配置或进行中的操作，请按明细处理后重试",
                        device_ref=device_ref,
                        target_id=target_id,
                        blockers=public_blockers,
                        blocker_counts=counts,
                        blocker_total=len(blockers),
                        remote_account_count=counts["remote_accounts"],
                        local_link_count=counts["local_links"],
                        business_policy_count=counts["business_policies"],
                        pending_operation_count=counts["pending_operations"],
                        remote_verified_empty=True,
                        remote_checked_at=remote_checked_at.isoformat(),
                    )

                cleared: list[dict[str, Any]] = []
                for account in candidates:
                    cleared.append(
                        _clear_manual_cpa_link_after_confirmed_target_absence(
                            session,
                            account,
                            target_id=target_id,
                            target_name=str(target.get("name") or ""),
                            confirmed_at=remote_checked_at,
                        )
                    )
                kept = [
                    item for item in targets
                    if not (
                        str(item.get("id") or "").isdigit()
                        and int(item.get("id") or 0) == int(target_id)
                    )
                ]
                new_revision = _write_cpa_targets_in_session(session, kept)
                session.commit()
    return {
        "ok": True,
        "device_ref": device_ref,
        "target_id": int(target_id),
        "remote_verified_empty": True,
        "remote_checked_at": remote_checked_at.isoformat(),
        "cleared_stale_links": len(cleared),
        "cleared_account_ids": [int(item["account_id"]) for item in cleared],
        "target_revision": int(new_revision),
    }


def _delete_cpa_delivery_device(provider_id: int, device_ref: str) -> dict[str, Any]:
    from api.gpt_plan_operations import _cpa_sync_targets_snapshot
    from services.cpa_manager import list_auth_files_strict

    active_refresh = _active_refresh_task_for_device(device_ref)
    if active_refresh:
        blockers, counts = _public_cpa_delete_blockers([{
            "type": "device_refresh_task", **active_refresh,
        }])
        raise _cpa_delete_error(
            status_code=409,
            code="cpa_device_delete_blocked",
            message="CPA 设备正在刷新账号，请等待任务完成后重试",
            device_ref=device_ref,
            target_id=provider_id,
            blockers=blockers,
            blocker_counts=counts,
            blocker_total=1,
            remote_account_count=0,
            local_link_count=0,
            business_policy_count=0,
            pending_operation_count=1,
        )

    targets, revision = _cpa_sync_targets_snapshot()
    target = next((
        item for item in targets
        if isinstance(item, dict)
        and str(item.get("id") or "").isdigit()
        and int(item.get("id") or 0) == int(provider_id)
    ), None)
    if not target:
        raise HTTPException(404, "CPA 设备不存在")
    api_url = str(target.get("api_url") or "").strip().rstrip("/")
    api_key = str(target.get("api_key") or "").strip()
    if not api_url:
        raise _cpa_delete_error(
            status_code=409,
            code="cpa_device_remote_verification_failed",
            message="CPA 设备地址为空，无法确认远端账号为空",
            device_ref=device_ref,
            target_id=provider_id,
        )
    try:
        remote_files = list_auth_files_strict(api_url=api_url, api_key=api_key)
    except Exception as exc:
        raise _cpa_delete_error(
            status_code=409,
            code="cpa_device_remote_verification_failed",
            message="CPA 远端账号实时核对失败，设备未删除",
            device_ref=device_ref,
            target_id=provider_id,
            error_type=type(exc).__name__,
        ) from exc
    remote_checked_at = _utcnow()
    if remote_files:
        raise _cpa_delete_error(
            status_code=409,
            code="cpa_device_not_empty",
            message="CPA 远端仍存在账号（包括已停用凭据），请先清理后再删除设备",
            device_ref=device_ref,
            target_id=provider_id,
            blockers={
                "remote_accounts": {
                    "count": len(remote_files),
                    # Remote-controlled fields are never echoed in a delete
                    # error. The count is sufficient to explain the fence.
                    "items": [],
                },
                "local_links": {"count": 0, "items": []},
                "business_policies": {"count": 0, "items": []},
                "pending_operations": {"count": 0, "items": []},
            },
            blocker_counts={
                "remote_accounts": len(remote_files),
                "local_links": 0,
                "business_policies": 0,
                "pending_operations": 0,
            },
            blocker_total=len(remote_files),
            remote_verified_empty=False,
            remote_account_count=len(remote_files),
            local_link_count=0,
            business_policy_count=0,
            pending_operation_count=0,
            remote_checked_at=remote_checked_at.isoformat(),
        )

    return _delete_empty_cpa_target_transaction(
        target_id=provider_id,
        device_ref=device_ref,
        expected_targets=targets,
        expected_revision=revision,
        expected_api_url=api_url,
        expected_api_key=api_key,
        remote_checked_at=remote_checked_at,
    )


def delete_delivery_device(device_ref: str) -> dict:
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    with monitor.device_refresh_lock(canonical):
        _assert_no_hosting_worker(canonical)
        if provider == "cpa":
            result = _delete_cpa_delivery_device(provider_id, canonical)
        else:
            # Reuse the existing reference fences. Importing here avoids a
            # module cycle while keeping one authoritative Sub2API deletion
            # policy. The shared RLock also covers direct /devices mutations.
            from api.devices import delete_device

            delete_device(provider_id)
            result = {"ok": True, "device_ref": canonical}
        monitor.delete_snapshots(canonical)
        from services.device_hosting_store import forget_device
        forget_device(canonical)
        return result


def delivery_device_accounts(device_ref: str, *, refresh: bool = False) -> dict:
    try:
        if refresh:
            return monitor.refresh_device(device_ref)
        return monitor.get_accounts(device_ref)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, "设备不存在") from exc


# -- Local-only BUSINESS mother bindings -----------------------------------

def _assert_no_hosting_worker(
    device_ref: Optional[str], *, source_account_id: Optional[int] = None,
    session: Optional[Session] = None,
) -> None:
    from services.device_hosting_store import has_active_workers
    if has_active_workers(device_ref, source_account_id=source_account_id, session=session):
        raise HTTPException(409, {
            "code": "device_hosting_operation_running",
            "message": "子号托管步骤正在执行，请先暂停托管并等待当前步骤结束后修改设备或母号绑定",
        })


def _delivery_binding_device(device_ref: str) -> dict[str, Any]:
    """Resolve a public device identity without contacting the remote device."""
    try:
        provider, provider_id = monitor.parse_device_key(device_ref)
        canonical = monitor.device_key(provider, provider_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    internal = monitor._internal_device(provider, provider_id)  # type: ignore[attr-defined]
    if not internal:
        raise HTTPException(404, "设备不存在")
    fallback = f"{'Sub2API' if provider == 'sub2api' else 'CPA'} {provider_id}"
    name = str(internal.get("name") or "").strip()
    if not name or re.match(r"(?i)^[a-z][a-z0-9+.-]*://", name):
        name = fallback
    enabled = bool(internal.get("enabled", True))
    configured = bool(
        str(internal.get("api_url") or "").strip()
        and str(internal.get("api_key") or "").strip()
    )
    return {
        "device_ref": canonical,
        "provider": provider,
        "provider_id": int(provider_id),
        "device_id": int(provider_id),
        "name": name[:200],
        "enabled": enabled,
        "state": (
            "configured" if enabled and configured
            else "disabled" if not enabled
            else "unconfigured"
        ),
    }


def _business_policy_device_ref(
    row: Optional[GptBusinessAutomationPolicyModel],
) -> str:
    provider, provider_id = resolve_business_delivery_binding(row)
    return (
        monitor.device_key(provider, provider_id)
        if provider and provider_id is not None else ""
    )


def _refunded_business_parent_ids(session: Session) -> set[int]:
    result: set[int] = set()
    rows = session.exec(
        select(GptProAccountModel).where(
            GptProAccountModel.source_pool == "gpt_business"
        )
    ).all()
    for row in rows:
        if str(row.catalog_category or "").strip().lower() != "refunded":
            continue
        try:
            parent_id = int(row.source_account_id or 0)
        except (TypeError, ValueError):
            parent_id = 0
        if parent_id > 0:
            result.add(parent_id)
    return result


def _business_binding_eligibility(
    parent: Optional[GptBusinessAccountModel],
    *,
    refunded_parent_ids: set[int],
) -> dict[str, Any]:
    if parent is None:
        return {
            "logged_in": False,
            "eligible": False,
            "blockers": [{"code": "missing", "message": "母号不存在"}],
        }
    parent_id = int(parent.id or 0)
    logged_in = bool(
        str(parent.cookie_blob or "").strip()
        or parent.cookie_updated_at is not None
    )
    blockers: list[dict[str, str]] = []
    if not logged_in:
        blockers.append({"code": "never_logged", "message": "母号尚未登录"})
    if not bool(parent.enabled):
        blockers.append({"code": "disabled", "message": "母号已禁用"})
    if bool(parent.dangerous):
        blockers.append({"code": "dangerous", "message": "母号已标记异常"})
    # Match the durable "已登录" tab: intermediate/manual refund review does
    # not move the mother out of that tab.  Only the refunded-pending-credit
    # state (or the plan catalogue's refunded category below) blocks a new
    # binding.
    if str(parent.refund_status or "").strip().lower() == "refunded_pending_credit":
        blockers.append({"code": "refund", "message": "母号已退款未到账"})
    if parent_id in refunded_parent_ids:
        blockers.append({"code": "refunded", "message": "母号已进入已退款列表"})
    return {
        "logged_in": logged_in,
        "eligible": not blockers,
        "blockers": blockers,
    }


def _business_binding_item(
    parent_id: int,
    parent: Optional[GptBusinessAccountModel],
    policy: Optional[GptBusinessAutomationPolicyModel],
    *,
    plan_account_id: Optional[int],
    plan_account_type: str,
    current_device_ref: str,
    refunded_parent_ids: set[int],
    business_usage_type: Optional[str] = None,
) -> dict[str, Any]:
    eligibility = _business_binding_eligibility(
        parent,
        refunded_parent_ids=refunded_parent_ids,
    )
    bound_device_ref = _business_policy_device_ref(policy)
    provider = ""
    device_id: Optional[int] = None
    if bound_device_ref:
        provider, parsed_id = monitor.parse_device_key(bound_device_ref)
        device_id = int(parsed_id)
    bound_here = bound_device_ref == current_device_ref
    note = str(getattr(parent, "note", "") or "").strip()[:500]
    # Display/filter metadata only. Reading bindings must not refresh a remote
    # workspace or infer unknown typed capacity as free seats.
    from api.gpt_plans import _safe_business_seat_summary, _exact_business_typed_available_counts
    summary = _safe_business_seat_summary(parent) if parent is not None else None
    typed_available = _exact_business_typed_available_counts(summary or {})
    return {
        "id": int(parent_id),
        "account_id": int(parent_id),
        "parent_id": int(parent_id),
        "business_account_id": int(parent_id),
        # ``parent_id`` belongs to the BUSINESS source table and cannot be
        # used by the GPT plan page's ``focus_account_id`` deep link.  Expose
        # the independently mapped catalogue id as a public navigation-only
        # identity.  It is deliberately nullable: clients must not guess or
        # fall back to the source id when a catalogue row is unavailable.
        "plan_account_id": (
            int(plan_account_id)
            if plan_account_id is not None and int(plan_account_id) > 0
            else None
        ),
        # The target directory tab is also authoritative.  A mother that was
        # bound while active may later move to the refunded catalogue; forcing
        # every link to member/team would then produce an empty focused list.
        "plan_account_type": (
            plan_account_type
            if plan_account_id is not None
            and plan_account_type in {"member", "refunded"}
            else None
        ),
        "catalog_category": (
            plan_account_type
            if plan_account_id is not None
            and plan_account_type in {"member", "refunded"}
            else None
        ),
        "email": str(getattr(parent, "email", "") or "").strip(),
        "note": note,
        "remark": note,
        "business_usage_type": (
            business_usage_type if business_usage_type in {"sale", "self_use", "transit"} else None
        ),
        "available_seat_types": typed_available,
        "enabled": bool(getattr(parent, "enabled", False)),
        "dangerous": bool(getattr(parent, "dangerous", False)),
        "refund_status": str(getattr(parent, "refund_status", "") or ""),
        "logged_in": bool(eligibility["logged_in"]),
        "eligible": bool(eligibility["eligible"]),
        # An existing binding may always be retained or removed even if the
        # mother later leaves the candidate pool.
        "selectable": bool(eligibility["eligible"] or bound_here),
        "blockers": list(eligibility["blockers"]),
        "policy_revision": int(getattr(policy, "revision", 0) or 0),
        "bound": bool(bound_device_ref),
        "bound_here": bound_here,
        "device_ref": bound_device_ref,
        "provider": provider,
        "device_id": device_id,
    }


def delivery_device_business_bindings(device_ref: str) -> dict[str, Any]:
    """Read local mother bindings and eligible mothers; never touch a remote."""
    device = _delivery_binding_device(device_ref)
    canonical = str(device["device_ref"])
    with Session(engine) as session:
        parents = session.exec(
            select(GptBusinessAccountModel).order_by(GptBusinessAccountModel.id)
        ).all()
        policies = session.exec(select(GptBusinessAutomationPolicyModel)).all()
        plan_accounts = session.exec(
            select(GptProAccountModel).where(
                GptProAccountModel.source_pool == "gpt_business"
            )
        ).all()
        parent_map = {
            int(row.id): row for row in parents if int(row.id or 0) > 0
        }
        policy_map = {
            int(row.business_account_id): row
            for row in policies
            if int(row.business_account_id or 0) > 0
        }
        # ``ux_gpt_plan_accounts_source`` makes this mapping one-to-one.  Keep
        # the source id and plan id separate even when their numeric values
        # happen to coincide in one database.
        plan_account_map = {
            int(row.source_account_id): {
                "id": int(row.id),
                "business_usage_type": row.business_usage_type,
                # GPT plan catalogue semantics treat only the explicit
                # refunded lifecycle as refunded.  BUSINESS source rows are
                # otherwise members even if a legacy plan_type is blank.
                "account_type": (
                    "refunded"
                    if str(row.catalog_category or "").strip().lower()
                    == "refunded"
                    else "member"
                ),
            }
            for row in plan_accounts
            if int(row.source_account_id or 0) > 0 and int(row.id or 0) > 0
        }
        refunded_parent_ids = _refunded_business_parent_ids(session)

    current_ids = sorted(
        parent_id for parent_id, row in policy_map.items()
        if _business_policy_device_ref(row) == canonical
    )
    current_set = set(current_ids)
    bindings = [
        _business_binding_item(
            parent_id,
            parent_map.get(parent_id),
            policy_map.get(parent_id),
            plan_account_id=(
                int(plan_account_map[parent_id]["id"])
                if parent_id in plan_account_map else None
            ),
            plan_account_type=(
                str(plan_account_map[parent_id]["account_type"])
                if parent_id in plan_account_map else ""
            ),
            current_device_ref=canonical,
            refunded_parent_ids=refunded_parent_ids,
            business_usage_type=plan_account_map.get(parent_id, {}).get("business_usage_type"),
        )
        for parent_id in current_ids
    ]
    candidates: list[dict[str, Any]] = []
    for parent_id in sorted(parent_map):
        item = _business_binding_item(
            parent_id,
            parent_map[parent_id],
            policy_map.get(parent_id),
            plan_account_id=(
                int(plan_account_map[parent_id]["id"])
                if parent_id in plan_account_map else None
            ),
            plan_account_type=(
                str(plan_account_map[parent_id]["account_type"])
                if parent_id in plan_account_map else ""
            ),
            current_device_ref=canonical,
            refunded_parent_ids=refunded_parent_ids,
            business_usage_type=plan_account_map.get(parent_id, {}).get("business_usage_type"),
        )
        if bool(item["eligible"]) or parent_id in current_set:
            candidates.append(item)
    expected_revisions = {
        str(item["parent_id"]): int(item["policy_revision"])
        for item in [*candidates, *bindings]
    }
    return {
        "ok": True,
        "device": device,
        "device_ref": canonical,
        "bindings": bindings,
        # ``items`` is a stable list alias for simple CRUD clients.
        "items": bindings,
        "candidates": candidates,
        "parent_ids": current_ids,
        "expected_revisions": expected_revisions,
        "total": len(bindings),
    }


def _normalize_business_binding_parent_ids(values: list[int]) -> set[int]:
    if len(values) > 500:
        raise HTTPException(400, "单个设备最多绑定 500 个母号")
    result: set[int] = set()
    for value in values:
        if isinstance(value, bool):
            raise HTTPException(400, "母号 ID 无效")
        try:
            parent_id = int(value)
        except (TypeError, ValueError):
            raise HTTPException(400, "母号 ID 无效") from None
        if parent_id <= 0:
            raise HTTPException(400, "母号 ID 必须为正整数")
        result.add(parent_id)
    return result


def _clear_business_delivery_binding_policy(
    row: GptBusinessAutomationPolicyModel,
    *,
    now: datetime,
) -> None:
    """Clear only local delivery metadata on one canonical policy row.

    Device-page batch edits and the GPT-plan mother facade deliberately share
    this primitive.  In particular, an unbind cannot leave the retired
    rotation flags enabled, and it never touches memberships, credentials or
    delivery jobs.
    """
    row.delivery_type = ""
    row.cpa_target_id = None
    row.sub2api_device_id = None
    row.auto_rotation_enabled = False
    row.rotate_default = False
    row.rotate_prolite = False
    row.last_scan_at = None
    row.last_error = ""
    row.revision = int(row.revision or 0) + 1
    row.updated_at = now


def _set_business_delivery_binding_policy(
    row: GptBusinessAutomationPolicyModel,
    *,
    provider: str,
    provider_id: int,
    now: datetime,
) -> bool:
    """Normalize one policy to a pure local binding; return whether it changed."""
    canonical = monitor.device_key(provider, provider_id)
    before_ref = _business_policy_device_ref(row)
    normalized = bool(
        str(row.delivery_type or "").strip().lower() == provider
        and before_ref == canonical
        and not bool(row.auto_rotation_enabled)
        and not bool(row.rotate_default)
        and not bool(row.rotate_prolite)
        and (
            int(row.cpa_target_id or 0) == provider_id
            if provider == "cpa"
            else int(row.sub2api_device_id or 0) == provider_id
        )
    )
    if normalized:
        return False
    row.delivery_type = provider
    row.cpa_target_id = provider_id if provider == "cpa" else None
    row.sub2api_device_id = provider_id if provider == "sub2api" else None
    row.auto_rotation_enabled = False
    row.rotate_default = False
    row.rotate_prolite = False
    row.last_scan_at = None
    row.last_error = ""
    row.revision = int(row.revision or 0) + 1
    row.updated_at = now
    return True


def _assert_plan_parent_binding_in_transaction(
    session: Session,
    *,
    parent_id: int,
    expected_plan_account_id: Optional[int],
    expected_plan_email: str,
) -> None:
    """Fence a plan-facade source mapping in the policy write transaction."""
    if expected_plan_account_id is None:
        return
    if (
        isinstance(expected_plan_account_id, bool)
        or not isinstance(expected_plan_account_id, int)
        or expected_plan_account_id <= 0
    ):
        raise HTTPException(400, "套餐账号 ID 无效")
    query = select(GptProAccountModel).where(
        GptProAccountModel.id == expected_plan_account_id
    )
    if session.get_bind().dialect.name != "sqlite":
        query = query.with_for_update()
    plan = session.exec(query).first()
    normalized_email = str(expected_plan_email or "").strip().casefold()
    if (
        plan is None
        or str(plan.source_pool or "").strip() != "gpt_business"
        or int(plan.source_account_id or 0) != parent_id
        or str(plan.email or "").strip().casefold() != normalized_email
    ):
        raise HTTPException(409, {
            "code": "plan_business_source_binding_changed",
            "message": "套餐目录中的 BUSINESS 母号身份已变化，请刷新后重试",
            "account_id": expected_plan_account_id,
        })


def put_delivery_device_business_bindings(
    device_ref: str,
    body: DeliveryDeviceBusinessBindingsPutRequest,
) -> dict[str, Any]:
    """Atomically replace local bindings, without delivery side effects."""
    device = _delivery_binding_device(device_ref)
    canonical = str(device["device_ref"])
    provider = str(device["provider"])
    provider_id = int(device["provider_id"])
    desired = _normalize_business_binding_parent_ids(list(body.parent_ids or []))
    # The request model has already rejected booleans, coercible strings and
    # negative revisions; never silently discard malformed concurrency fences.
    expected = dict(body.expected_revisions or {})

    with ExitStack() as binding_locks:
        binding_locks.enter_context(monitor.device_refresh_lock(canonical))
        if provider == "cpa":
            from api.gpt_plan_operations import _CPA_CONFIG_WRITE_LOCK

            binding_locks.enter_context(_CPA_CONFIG_WRITE_LOCK)
        # A direct CPA registry edit uses the same config lock, while Sub2API
        # edits use the refresh lock.  Re-resolve under that lock so a deleted
        # target can never gain a dangling binding.
        device = _delivery_binding_device(canonical)
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite" and not session.in_transaction():
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            policy_query = select(GptBusinessAutomationPolicyModel)
            parent_query = select(GptBusinessAccountModel)
            if session.get_bind().dialect.name != "sqlite":
                policy_query = policy_query.with_for_update()
                parent_query = parent_query.with_for_update()
            parents = session.exec(parent_query).all()
            # Match mother deletion's lock order (parent, then policy) so two
            # PostgreSQL transactions cannot wait on each other in reverse.
            policies = session.exec(policy_query).all()
            policy_map = {
                int(row.business_account_id): row
                for row in policies
                if int(row.business_account_id or 0) > 0
            }
            parent_map = {
                int(row.id): row for row in parents if int(row.id or 0) > 0
            }
            current = {
                parent_id for parent_id, row in policy_map.items()
                if _business_policy_device_ref(row) == canonical
            }
            additions_to_unavailable = sorted(desired - current)
            if (
                str(device.get("state") or "") != "configured"
                and additions_to_unavailable
            ):
                raise HTTPException(409, {
                    "code": "delivery_device_unavailable_for_new_binding",
                    "message": "设备已停用或配置不完整，只能保留或解除已有绑定",
                    "device_ref": canonical,
                    "device_state": str(device.get("state") or "unconfigured"),
                    "new_parent_ids": additions_to_unavailable,
                })
            affected = current | desired
            missing_expected = sorted(affected - set(expected))
            if missing_expected:
                raise HTTPException(409, {
                    "code": "business_binding_revision_required",
                    "message": "母号绑定已变化，请刷新后重新保存",
                    "missing_parent_ids": missing_expected,
                })
            for parent_id in sorted(affected):
                current_revision = int(
                    getattr(policy_map.get(parent_id), "revision", 0) or 0
                )
                if int(expected[parent_id]) != current_revision:
                    raise HTTPException(409, {
                        "code": "business_binding_revision_conflict",
                        "message": "母号绑定已被其他页面修改，请刷新后重试",
                        "business_account_id": parent_id,
                        "expected_revision": int(expected[parent_id]),
                        "current_revision": current_revision,
                    })
            missing_parents = sorted(desired - set(parent_map))
            if missing_parents:
                raise HTTPException(404, {
                    "code": "business_parent_not_found",
                    "message": "部分 BUSINESS 母号不存在",
                    "parent_ids": missing_parents,
                })

            refunded_parent_ids = _refunded_business_parent_ids(session)
            for parent_id in sorted(desired):
                if parent_id in current:
                    continue
                eligibility = _business_binding_eligibility(
                    parent_map[parent_id],
                    refunded_parent_ids=refunded_parent_ids,
                )
                if not bool(eligibility["eligible"]):
                    raise HTTPException(409, {
                        "code": "business_parent_not_eligible_for_device_binding",
                        "message": "只能绑定已登录、未退款且状态正常的 BUSINESS 母号",
                        "business_account_id": parent_id,
                        "blockers": list(eligibility["blockers"]),
                    })

            now = _utcnow()
            added: list[int] = []
            moved: list[int] = []
            removed: list[int] = []
            unchanged: list[int] = []
            for parent_id in sorted(affected):
                row = policy_map.get(parent_id)
                before_ref = _business_policy_device_ref(row)
                after_ref = canonical if parent_id in desired else ""
                if before_ref != after_ref:
                    _assert_no_hosting_worker(None, source_account_id=parent_id, session=session)
                if parent_id in desired:
                    if row is None:
                        row = GptBusinessAutomationPolicyModel(
                            business_account_id=parent_id,
                            created_at=now,
                            updated_at=now,
                        )
                        policy_map[parent_id] = row
                    changed = _set_business_delivery_binding_policy(
                        row,
                        provider=provider,
                        provider_id=provider_id,
                        now=now,
                    )
                    if not changed:
                        unchanged.append(parent_id)
                        continue
                    session.add(row)
                    if not before_ref:
                        added.append(parent_id)
                    elif before_ref == canonical:
                        unchanged.append(parent_id)
                    else:
                        moved.append(parent_id)
                else:
                    if row is None or before_ref != canonical:
                        continue
                    _clear_business_delivery_binding_policy(row, now=now)
                    session.add(row)
                    removed.append(parent_id)
            session.commit()

        result = delivery_device_business_bindings(canonical)
    return {
        **result,
        "added_parent_ids": added,
        "moved_parent_ids": moved,
        "removed_parent_ids": removed,
        "unchanged_parent_ids": unchanged,
    }


def bind_business_parent_delivery_device(
    parent_id: int,
    *,
    device_ref: str,
    expected_revision: int,
    expected_plan_account_id: Optional[int] = None,
    expected_plan_email: str = "",
) -> dict[str, Any]:
    """Bind exactly one mother through the shared local policy/CAS rules."""
    if (
        isinstance(parent_id, bool)
        or not isinstance(parent_id, int)
        or parent_id <= 0
        or parent_id > 2_147_483_647
        or isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
        or expected_revision > 2_147_483_647
    ):
        raise HTTPException(400, "母号 ID 或绑定版本无效")
    target = _delivery_binding_device(device_ref)
    canonical = str(target["device_ref"])
    provider = str(target["provider"])
    provider_id = int(target["provider_id"])

    with Session(engine) as session:
        observed = session.get(GptBusinessAutomationPolicyModel, parent_id)
        observed_ref = _business_policy_device_ref(observed)
    lock_refs = sorted({value for value in (observed_ref, canonical) if value})

    with ExitStack() as binding_locks:
        for value in lock_refs:
            binding_locks.enter_context(monitor.device_refresh_lock(value))
        if any(value.startswith("cpa:") for value in lock_refs):
            from api.gpt_plan_operations import _CPA_CONFIG_WRITE_LOCK

            binding_locks.enter_context(_CPA_CONFIG_WRITE_LOCK)
        # Device deletion/update uses the same lock.  Resolve again only from
        # the local registry before creating a durable reference.
        target = _delivery_binding_device(canonical)

        with Session(engine) as session:
            if (
                session.get_bind().dialect.name == "sqlite"
                and not session.in_transaction()
            ):
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            parent_query = select(GptBusinessAccountModel).where(
                GptBusinessAccountModel.id == parent_id
            )
            policy_query = select(GptBusinessAutomationPolicyModel).where(
                GptBusinessAutomationPolicyModel.business_account_id == parent_id
            )
            if session.get_bind().dialect.name != "sqlite":
                parent_query = parent_query.with_for_update()
                policy_query = policy_query.with_for_update()
            parent = session.exec(parent_query).first()
            if parent is None:
                raise HTTPException(404, "BUSINESS 母号不存在")
            _assert_plan_parent_binding_in_transaction(
                session,
                parent_id=parent_id,
                expected_plan_account_id=expected_plan_account_id,
                expected_plan_email=expected_plan_email,
            )
            row = session.exec(policy_query).first()
            current_revision = int(getattr(row, "revision", 0) or 0)
            if current_revision != expected_revision:
                raise HTTPException(409, {
                    "code": "business_binding_revision_conflict",
                    "message": "母号绑定已被其他页面修改，请刷新后重试",
                    "business_account_id": parent_id,
                    "expected_revision": expected_revision,
                    "current_revision": current_revision,
                })
            before_ref = _business_policy_device_ref(row)
            already_bound_here = before_ref == canonical
            if not already_bound_here:
                _assert_no_hosting_worker(None, source_account_id=parent_id, session=session)
            if (
                not already_bound_here
                and (
                    not bool(target.get("enabled"))
                    or str(target.get("state") or "") != "configured"
                )
            ):
                raise HTTPException(409, {
                    "code": "delivery_device_not_bindable",
                    "message": "目标设备已停用或配置不完整，不能新增或切换绑定",
                    "device_ref": canonical,
                    "state": str(target.get("state") or "unconfigured"),
                })
            if not already_bound_here:
                eligibility = _business_binding_eligibility(
                    parent,
                    refunded_parent_ids=_refunded_business_parent_ids(session),
                )
                if not bool(eligibility["eligible"]):
                    raise HTTPException(409, {
                        "code": "business_parent_not_eligible_for_device_binding",
                        "message": "只能绑定已登录、未退款且状态正常的 BUSINESS 母号",
                        "business_account_id": parent_id,
                        "blockers": list(eligibility["blockers"]),
                    })

            now = _utcnow()
            if row is None:
                row = GptBusinessAutomationPolicyModel(
                    business_account_id=parent_id,
                    created_at=now,
                    updated_at=now,
                )
            changed = _set_business_delivery_binding_policy(
                row,
                provider=provider,
                provider_id=provider_id,
                now=now,
            )
            if changed:
                session.add(row)
                session.commit()
                current_revision = int(row.revision or 0)

    return {
        "ok": True,
        "business_account_id": parent_id,
        "previous_device_ref": before_ref,
        "device_ref": canonical,
        "policy_revision": current_revision,
        "changed": changed,
        "added": bool(changed and not before_ref),
        "moved": bool(changed and before_ref and before_ref != canonical),
    }


def unbind_business_parent_delivery_binding(
    parent_id: int,
    *,
    expected_revision: int,
    expected_device_ref: Optional[str] = None,
    expected_plan_account_id: Optional[int] = None,
    expected_plan_email: str = "",
) -> dict[str, Any]:
    """Clear one mother's local binding even when its old device is missing.

    ``expected_device_ref`` is used by the device-scoped DELETE route so that
    it cannot accidentally unbind a mother that has already moved elsewhere.
    The GPT-plan facade omits it and removes whichever binding is protected by
    ``expected_revision``.  Neither mode resolves credentials or contacts a
    device.
    """
    if (
        isinstance(parent_id, bool)
        or not isinstance(parent_id, int)
        or parent_id <= 0
        or parent_id > 2_147_483_647
        or isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
        or expected_revision > 2_147_483_647
    ):
        raise HTTPException(400, "母号 ID 或绑定版本无效")

    canonical_expected = ""
    if expected_device_ref is not None:
        try:
            provider, provider_id = monitor.parse_device_key(expected_device_ref)
            canonical_expected = monitor.device_key(provider, provider_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    # Read only the lock identity here.  The policy row and its revision are
    # re-read under the database write fence below; every legitimate binding
    # mutation increments that revision.
    with Session(engine) as session:
        observed = session.get(GptBusinessAutomationPolicyModel, parent_id)
        observed_ref = _business_policy_device_ref(observed)
    lock_refs = sorted({
        value
        for value in (
            (canonical_expected,) if canonical_expected else (observed_ref,)
        )
        if value
    })

    with ExitStack() as binding_locks:
        for value in lock_refs:
            binding_locks.enter_context(monitor.device_refresh_lock(value))
        if any(value.startswith("cpa:") for value in lock_refs):
            from api.gpt_plan_operations import _CPA_CONFIG_WRITE_LOCK

            binding_locks.enter_context(_CPA_CONFIG_WRITE_LOCK)

        with Session(engine) as session:
            if (
                session.get_bind().dialect.name == "sqlite"
                and not session.in_transaction()
            ):
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            # Keep the same parent -> policy lock order as the batch PUT and
            # mother deletion paths.
            parent_query = select(GptBusinessAccountModel).where(
                GptBusinessAccountModel.id == parent_id
            )
            policy_query = select(GptBusinessAutomationPolicyModel).where(
                GptBusinessAutomationPolicyModel.business_account_id == parent_id
            )
            if session.get_bind().dialect.name != "sqlite":
                parent_query = parent_query.with_for_update()
                policy_query = policy_query.with_for_update()
            session.exec(parent_query).first()
            _assert_plan_parent_binding_in_transaction(
                session,
                parent_id=parent_id,
                expected_plan_account_id=expected_plan_account_id,
                expected_plan_email=expected_plan_email,
            )
            row = session.exec(policy_query).first()
            current_revision = int(getattr(row, "revision", 0) or 0)
            if current_revision != expected_revision:
                raise HTTPException(409, {
                    "code": "business_binding_revision_conflict",
                    "message": "母号绑定已被其他页面修改，请刷新后重试",
                    "business_account_id": parent_id,
                    "expected_revision": expected_revision,
                    "current_revision": current_revision,
                })
            before_ref = _business_policy_device_ref(row)
            removed = bool(
                row is not None
                and before_ref
                and (
                    not canonical_expected
                    or before_ref == canonical_expected
                )
            )
            if removed and row is not None:
                _assert_no_hosting_worker(None, source_account_id=parent_id, session=session)
                _clear_business_delivery_binding_policy(row, now=_utcnow())
                session.add(row)
                session.commit()
                current_revision = int(row.revision or 0)

    return {
        "ok": True,
        "business_account_id": parent_id,
        "removed": removed,
        "previous_device_ref": before_ref,
        "device_ref": "" if removed else before_ref,
        "policy_revision": current_revision,
    }


def delete_delivery_device_business_binding(
    device_ref: str,
    parent_id: int,
    *,
    expected_revision: int,
) -> dict[str, Any]:
    """Idempotently unbind one mother using a local revision fence."""
    device = _delivery_binding_device(device_ref)
    canonical = str(device["device_ref"])
    if (
        isinstance(parent_id, bool)
        or isinstance(expected_revision, bool)
        or int(parent_id) <= 0
        or int(parent_id) > 2_147_483_647
        or int(expected_revision) < 0
        or int(expected_revision) > 2_147_483_647
    ):
        raise HTTPException(400, "母号 ID 或绑定版本无效")
    provider = str(device["provider"])
    with ExitStack() as binding_locks:
        binding_locks.enter_context(monitor.device_refresh_lock(canonical))
        if provider == "cpa":
            from api.gpt_plan_operations import _CPA_CONFIG_WRITE_LOCK

            binding_locks.enter_context(_CPA_CONFIG_WRITE_LOCK)
        _delivery_binding_device(canonical)
        mutation = unbind_business_parent_delivery_binding(
            int(parent_id),
            expected_revision=int(expected_revision),
            expected_device_ref=canonical,
        )
        result = delivery_device_business_bindings(canonical)
    return {
        **result,
        "removed": bool(mutation["removed"]),
        "removed_parent_id": int(parent_id),
    }


@router.get("")
def list_delivery_devices(include_accounts: bool = Query(True)):
    from core.scheduler import scheduler

    result = monitor.list_devices(include_accounts=include_accounts)
    return {
        **result,
        "monitor_schedule": scheduler.delivery_device_monitor_schedule(),
    }


@router.post("")
def post_delivery_device(body: DeliveryDeviceCreateRequest):
    return create_delivery_device(body)


@router.put("/{device_ref}")
def put_delivery_device(device_ref: str, body: DeliveryDeviceUpdateRequest):
    return update_delivery_device(device_ref, body)


@router.delete("/{device_ref}")
def remove_delivery_device(device_ref: str):
    return delete_delivery_device(device_ref)


@router.get("/{device_ref}/business-bindings")
def get_delivery_device_business_bindings(device_ref: str):
    return delivery_device_business_bindings(device_ref)


@router.put("/{device_ref}/business-bindings")
def replace_delivery_device_business_bindings(
    device_ref: str,
    body: DeliveryDeviceBusinessBindingsPutRequest,
):
    return put_delivery_device_business_bindings(device_ref, body)


@router.delete("/{device_ref}/business-bindings/{parent_id}")
def remove_delivery_device_business_binding(
    device_ref: str,
    parent_id: int,
    expected_revision: int = Query(..., ge=0),
):
    return delete_delivery_device_business_binding(
        device_ref,
        parent_id,
        expected_revision=expected_revision,
    )


@router.get("/{device_ref}/accounts")
def get_delivery_device_accounts(
    device_ref: str,
    refresh: bool = Query(False),
):
    return delivery_device_accounts(device_ref, refresh=refresh)


@router.post("/{device_ref}/accounts/refresh")
def refresh_delivery_device_accounts(device_ref: str):
    return delivery_device_accounts(device_ref, refresh=True)


@router.post("/{device_ref}/accounts/refresh-tasks", status_code=202)
def create_delivery_device_refresh_task(
    device_ref: str,
    body: Optional[DeliveryDeviceRefreshTaskRequest] = None,
):
    return start_delivery_device_refresh_task(device_ref, body)


@router.get("/{device_ref}/accounts/refresh-tasks/{task_id}")
def get_delivery_device_refresh_task(
    device_ref: str,
    task_id: str,
    since: int = Query(0, ge=0),
):
    return _refresh_task_snapshot(device_ref, task_id, since=since)


def create_delivery_team401_correction_batch(
    device_ref: str,
    body: DeliveryTeam401CorrectionBatchRequest,
):
    return start_team401_correction_batch(device_ref, body)


def list_delivery_team401_correction_batch_routes(
    device_ref: str,
    business_parent_id: Optional[int] = Query(None, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    return list_team401_correction_batches(
        device_ref,
        parent_id=business_parent_id,
        limit=limit,
    )


def get_delivery_team401_correction_batch(
    device_ref: str,
    batch_id: str,
):
    return _team401_batch_snapshot(device_ref, batch_id)


def get_delivery_team401_correction_item(
    device_ref: str,
    batch_id: str,
    task_id: str,
):
    return get_team401_correction_task(device_ref, batch_id, task_id)


def retry_delivery_team401_correction_item(
    device_ref: str,
    batch_id: str,
    task_id: str,
):
    return retry_team401_correction_task(device_ref, batch_id, task_id)


def create_delivery_team_replacement_task(
    device_ref: str,
    body: DeliveryTeamReplacementTaskRequest,
):
    return start_delivery_team_replacement_task(device_ref, body)


def list_delivery_team_replacement_task_routes(
    device_ref: str,
    limit: int = Query(20, ge=1, le=100),
):
    return list_delivery_team_replacement_tasks(device_ref, limit=limit)


def get_delivery_team_replacement_task(
    device_ref: str,
    task_id: str,
    since: int = Query(0, ge=0),
):
    return _manual_replacement_task_snapshot(
        device_ref, task_id, since=since,
    )


def retry_delivery_team_replacement_task_route(
    device_ref: str,
    task_id: str,
):
    return retry_delivery_team_replacement_task(device_ref, task_id)


# Provider/id aliases avoid URL-encoding ':' for clients that prefer segments.
@router.get("/{provider}/{provider_id}/accounts")
def get_delivery_device_accounts_by_parts(
    provider: str,
    provider_id: int,
    refresh: bool = Query(False),
):
    return delivery_device_accounts(
        monitor.device_key(provider, provider_id),
        refresh=refresh,
    )


@router.post("/{provider}/{provider_id}/refresh")
def refresh_delivery_device_by_parts(provider: str, provider_id: int):
    return delivery_device_accounts(
        monitor.device_key(provider, provider_id),
        refresh=True,
    )
