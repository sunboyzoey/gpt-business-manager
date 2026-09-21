"""同步设备管理 API — CPA / Sub2API 等多设备号池管理。"""
from __future__ import annotations

import json
import logging
from contextlib import nullcontext
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from core.db import (
    GptBusinessAutomationPolicyModel,
    GptPlanAccountModel as GptProAccountModel,
    SyncDeviceModel,
    engine,
    resolve_business_delivery_binding,
)
from api.delivery_devices import (
    DeliveryDeviceBusinessBindingsPutRequest,
    DeliveryDeviceCreateRequest,
    DeliveryDeviceRefreshTaskRequest,
    DeliveryTeam401CorrectionBatchRequest,
    DeliveryTeamReplacementTaskRequest,
    DeliveryDeviceUpdateRequest,
)

router = APIRouter(prefix="/devices", tags=["devices"])
logger = logging.getLogger(__name__)


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


class DeviceCreateRequest(BaseModel):
    name: str
    type: str = "cpa"
    api_url: str
    api_key: str = ""
    platform: str = "chatgpt"
    target_count: int = 10
    concurrency: int = 1
    register_delay_seconds: float = 0
    executor_type: str = "protocol"
    mail_provider: str = "cfworker"
    domain_rules: dict = Field(default_factory=dict)
    business_domains: list[Any] = Field(default_factory=list)
    sub_group_ids: str = "2"
    wants_refresh_token: bool = True
    priority: int = 0
    sync_batch_size: int = 5
    auto_replenish_batch_size: int = 0
    default_proxy_id: int = -1
    enabled: bool = True


class DeviceUpdateRequest(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    platform: Optional[str] = None
    target_count: Optional[int] = None
    concurrency: Optional[int] = None
    register_delay_seconds: Optional[float] = None
    executor_type: Optional[str] = None
    mail_provider: Optional[str] = None
    domain_rules: Optional[dict] = None
    business_domains: Optional[list[Any]] = None
    sub_group_ids: Optional[str] = None
    wants_refresh_token: Optional[bool] = None
    priority: Optional[int] = None
    sync_batch_size: Optional[int] = None
    auto_replenish_batch_size: Optional[int] = None
    default_proxy_id: Optional[int] = None
    enabled: Optional[bool] = None


class DeviceReplenishRequest(BaseModel):
    count: Optional[int] = None


class BusinessQuotaResetRequest(BaseModel):
    hostnames: list[str] = Field(default_factory=list)


DEVICE_TYPES = ("cpa", "sub2api", "gpt2web", "grok2api", "adobe2api")
DEVICE_TYPE_ALIASES = {
    "sub": "sub2api",
    "sub-2-api": "sub2api",
}
GROK2API_EXECUTOR_TYPES = {"protocol", "headless"}
ADOBE2API_EXECUTOR_TYPES = {"protocol"}


def _normalize_device_type(value: str | None) -> str:
    """Return the persisted/public canonical type while accepting old rows."""
    normalized = str(value or "").strip().lower()
    return DEVICE_TYPE_ALIASES.get(normalized, normalized)


def _is_sub2api_device_type(value: str | None) -> bool:
    return _normalize_device_type(value) == "sub2api"


def _normalize_device_platform(device_type: str, platform: str | None) -> str:
    device_type = _normalize_device_type(device_type)
    if device_type == "grok2api":
        return "grok"
    if device_type == "adobe2api":
        return "adobe"
    return str(platform or "chatgpt").strip() or "chatgpt"


def _normalize_device_executor(device_type: str, executor_type: str | None) -> str:
    device_type = _normalize_device_type(device_type)
    normalized = str(executor_type or "protocol").strip() or "protocol"
    if device_type == "grok2api":
        return normalized if normalized in GROK2API_EXECUTOR_TYPES else "protocol"
    if device_type == "adobe2api":
        return normalized if normalized in ADOBE2API_EXECUTOR_TYPES else "protocol"
    return normalized


def _device_type_error() -> str:
    return "设备类型必须是 cpa、sub2api、gpt2web、grok2api 或 adobe2api"


def _gpt_plan_sub2api_device_reference_count(session: Session, device_id: int) -> int:
    """Count active/pending GPT 套餐 links without trusting JSON SQL support."""
    wanted = int(device_id)
    count = 0
    for account in session.exec(select(GptProAccountModel)).all():
        try:
            extra = json.loads(account.extra_json or "{}")
        except Exception:
            continue
        if not isinstance(extra, dict):
            continue
        try:
            business_parent_link = int(
                extra.get("sub2api_business_parent_id") or 0
            )
        except (TypeError, ValueError):
            business_parent_link = 0
        # TEAM/BUSINESS delivery was retired from CPA/SUB device management.
        # Preserve its old linkage as account history, but never treat it as
        # an active device-config reference with no remaining unlink UI.
        if (
            account.business_parent_id is not None
            or str(extra.get("sub2api_account_kind") or "").strip().lower()
            == "business_child"
            or business_parent_link > 0
        ):
            continue
        candidates = (
            extra.get("sub2api_device_id"),
            extra.get("sub2api_sync_pending_device_id")
                if extra.get("sub2api_sync_pending") else None,
        )
        for value in candidates:
            try:
                linked_id = int(value or 0)
            except (TypeError, ValueError):
                linked_id = 0
            if linked_id == wanted:
                count += 1
                break
    return count


def _sub2api_device_reference_counts(session: Session, device_id: int) -> dict:
    plan_accounts = _gpt_plan_sub2api_device_reference_count(session, device_id)
    business_parents = 0
    for policy in session.exec(select(GptBusinessAutomationPolicyModel)).all():
        provider, provider_id = resolve_business_delivery_binding(policy)
        if provider == "sub2api" and provider_id == int(device_id):
            business_parents += 1
    return {
        "gpt_plan_accounts": plan_accounts,
        "business_parents": business_parents,
        "total": plan_accounts + business_parents,
    }


def _lock_device_for_reference_safe_mutation(
    session: Session,
    device_id: int,
) -> Optional[SyncDeviceModel]:
    """Serialize the reference scan and device update/delete critical section."""
    if session.get_bind().dialect.name == "sqlite":
        if not session.in_transaction():
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        return session.get(SyncDeviceModel, int(device_id))
    return session.exec(
        select(SyncDeviceModel)
        .where(SyncDeviceModel.id == int(device_id))
        .with_for_update()
    ).first()


def _delivery_refresh_mutation_lock(device_id: int):
    """Share the Sub2API refresh lock for config update/delete operations."""
    with Session(engine) as session:
        device = session.get(SyncDeviceModel, int(device_id))
        is_sub2api = bool(device and _is_sub2api_device_type(device.type))
    if not is_sub2api:
        return nullcontext()
    from services import delivery_device_monitor

    return delivery_device_monitor.device_refresh_lock(
        delivery_device_monitor.device_key("sub2api", int(device_id))
    )


def _sub2api_delete_preflight(device_id: int) -> Optional[tuple[Any, ...]]:
    """Confirm the configured Sub2API inventory is empty before deletion."""
    with Session(engine) as session:
        device = session.get(SyncDeviceModel, int(device_id))
        if not device or not _is_sub2api_device_type(device.type):
            return None
        expected = (
            str(device.api_url or "").strip().rstrip("/"),
            str(device.api_key or ""),
            str(device.sub_group_ids or "2").strip() or "2",
            str(device.updated_at or ""),
        )
    from services.sub2api_admin import list_accounts

    try:
        accounts = list_accounts(
            expected[0],
            expected[1],
            group_ids=expected[2],
        )
    except Exception as exc:
        logger.warning(
            "Sub2API delete preflight failed: device_id=%s error_type=%s",
            int(device_id),
            type(exc).__name__,
        )
        raise HTTPException(
            409,
            "Sub2API 远端账号核对失败，设备未删除",
        ) from exc
    if list(accounts or []):
        raise HTTPException(
            409,
            "Sub2API 远端仍存在账号，请先在远端清理后再删除设备",
        )
    return expected


def _normalize_business_domains(raw: Any, *, existing: Any = None) -> list[dict[str, Any]]:
    from services.device_manager import normalize_business_domain_entries

    entries = normalize_business_domain_entries(raw, existing=existing)
    if existing is None:
        return entries

    existing_entries = normalize_business_domain_entries(existing)
    existing_map = {
        str(item.get("hostname") or "").strip().lower(): item
        for item in existing_entries
        if str(item.get("hostname") or "").strip()
    }
    for entry in entries:
        hostname = str(entry.get("hostname") or "").strip().lower()
        previous = existing_map.get(hostname)
        if not previous:
            continue
        entry["used_count"] = max(0, int(previous.get("used_count") or 0))
        entry["inflight_count"] = max(0, int(previous.get("inflight_count") or 0))
    return entries


def _serialize(
    d: SyncDeviceModel,
    *,
    current_count: int | None = None,
    count_source: str = "cache",
    count_error: str = "",
) -> dict:
    resolved_count = d.current_count if current_count is None else current_count
    return {
        "id": d.id,
        "name": d.name,
        # 历史数据库中的 ``sub`` 行也统一向前端暴露为 canonical ``sub2api``。
        "type": _normalize_device_type(d.type),
        "api_url": d.api_url,
        "api_key": d.api_key,
        "platform": d.platform,
        "target_count": d.target_count,
        "concurrency": d.concurrency,
        "register_delay_seconds": d.register_delay_seconds,
        "executor_type": d.executor_type,
        "mail_provider": d.mail_provider,
        "domain_rules": d.get_domain_rules(),
        "business_domains": _normalize_business_domains(d.business_domains),
        "sub_group_ids": d.sub_group_ids,
        "wants_refresh_token": bool(getattr(d, "wants_refresh_token", False)),
        "priority": d.priority,
        "sync_batch_size": d.sync_batch_size,
        "auto_replenish_batch_size": d.auto_replenish_batch_size,
        "default_proxy_id": d.default_proxy_id,
        "current_count": resolved_count,
        "count_source": count_source,
        "count_error": count_error,
        "last_check_at": d.last_check_at.isoformat() if d.last_check_at else None,
        "enabled": d.enabled,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }


@router.get("")
def list_devices():
    with Session(engine) as s:
        devices = s.exec(
            select(SyncDeviceModel).order_by(SyncDeviceModel.id)
        ).all()
        # 列表页必须快速返回，不能在 GET /devices 中同步探测远端设备。
        # 远端接口异常/超时会让“设备管理”页面看起来完全没反应；
        # 真实数量刷新交给单设备“检查”和“同步设备管理”动作。
        return {"items": [_serialize(d) for d in devices]}


# Unified CPA/Sub2API facade.  These static routes must stay above
# ``/{device_id}``, otherwise FastAPI can parse ``monitor`` as the dynamic int
# route and return a misleading 422.
@router.get("/monitor")
def list_delivery_device_monitor(include_accounts: bool = Query(True)):
    from services.delivery_device_monitor import list_devices as _list
    from core.scheduler import scheduler

    result = _list(include_accounts=include_accounts)
    return {
        **result,
        "monitor_schedule": scheduler.delivery_device_monitor_schedule(),
    }


@router.post("/monitor")
def create_delivery_device_monitor(body: DeliveryDeviceCreateRequest):
    from api.delivery_devices import (
        create_delivery_device,
    )

    return create_delivery_device(body)


@router.put("/monitor/{device_ref}")
def update_delivery_device_monitor(
    device_ref: str,
    body: DeliveryDeviceUpdateRequest,
):
    from api.delivery_devices import (
        update_delivery_device,
    )

    return update_delivery_device(device_ref, body)


@router.delete("/monitor/{device_ref}")
def delete_delivery_device_monitor(device_ref: str):
    from api.delivery_devices import delete_delivery_device

    return delete_delivery_device(device_ref)


@router.get("/{device_id}")
def get_device(device_id: int):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")
        return _serialize(d)


@router.post("")
def create_device(req: DeviceCreateRequest):
    device_type = _normalize_device_type(req.type)
    if device_type not in DEVICE_TYPES:
        raise HTTPException(400, _device_type_error())
    with Session(engine) as s:
        d = SyncDeviceModel(
            name=req.name,
            type=device_type,
            api_url=req.api_url,
            api_key=req.api_key,
            platform=_normalize_device_platform(device_type, req.platform),
            target_count=max(req.target_count, 1),
            concurrency=max(req.concurrency, 1),
            register_delay_seconds=max(req.register_delay_seconds, 0),
            executor_type=_normalize_device_executor(device_type, req.executor_type),
            mail_provider=req.mail_provider,
            domain_rules_json=json.dumps(req.domain_rules, ensure_ascii=False),
            business_domains=json.dumps(
                _normalize_business_domains(req.business_domains),
                ensure_ascii=False,
            ),
            sub_group_ids=req.sub_group_ids or "2",
            wants_refresh_token=bool(req.wants_refresh_token),
            priority=max(req.priority, 0),
            sync_batch_size=max(req.sync_batch_size, 1),
            auto_replenish_batch_size=max(req.auto_replenish_batch_size, 0),
            default_proxy_id=req.default_proxy_id,
            enabled=req.enabled,
        )
        s.add(d)
        s.commit()
        s.refresh(d)
        return _serialize(d)


@router.put("/{device_id}")
def update_device(device_id: int, req: DeviceUpdateRequest):
    with _delivery_refresh_mutation_lock(device_id):
        return _update_device_locked(device_id, req)


def _update_device_locked(device_id: int, req: DeviceUpdateRequest):
    with Session(engine) as s:
        d = _lock_device_for_reference_safe_mutation(s, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")
        if _is_sub2api_device_type(d.type):
            from api.delivery_devices import _assert_no_hosting_worker
            _assert_no_hosting_worker(f"sub2api:{device_id}", session=s)
        references = _sub2api_device_reference_counts(s, device_id)
        reference_count = int(references["total"])
        requested_type = (
            _normalize_device_type(req.type)
            if req.type is not None else _normalize_device_type(d.type)
        )
        requested_url = (
            str(req.api_url or "").strip().rstrip("/").lower()
            if req.api_url is not None
            else str(d.api_url or "").strip().rstrip("/").lower()
        )
        current_url = str(d.api_url or "").strip().rstrip("/").lower()
        requested_platform = (
            _normalize_device_platform(requested_type, req.platform)
            if req.platform is not None
            else str(d.platform or "chatgpt").strip()
        )
        if reference_count and (
            requested_type != _normalize_device_type(d.type)
            or requested_url != current_url
            or str(requested_platform or "").strip().lower() not in {"", "chatgpt"}
            or (req.api_key is not None and not str(req.api_key or "").strip())
        ):
            details = []
            if int(references["gpt_plan_accounts"]):
                details.append(
                    f"{references['gpt_plan_accounts']} 个非 BUSINESS GPT 套餐账号"
                )
            if int(references["business_parents"]):
                details.append(
                    f"{references['business_parents']} 个 BUSINESS 母号绑定"
                )
            raise HTTPException(
                409,
                "该 Sub2API 设备仍被 " + "、".join(details) + " 引用，"
                "不能更换类型、地址、平台或清空 API Key；请先删除远端账号或解绑",
            )
        if req.type is not None:
            device_type = _normalize_device_type(req.type)
            if device_type not in DEVICE_TYPES:
                raise HTTPException(400, _device_type_error())
            d.type = device_type
            d.platform = _normalize_device_platform(device_type, d.platform)
            d.executor_type = _normalize_device_executor(device_type, d.executor_type)
        elif _is_sub2api_device_type(d.type) and d.type != "sub2api":
            # 任意一次保存都会把 legacy ``sub`` 行渐进迁移到 canonical 值。
            d.type = "sub2api"
        if req.name is not None:
            d.name = req.name
        if req.api_url is not None:
            d.api_url = req.api_url
        if req.api_key is not None:
            d.api_key = req.api_key
        if req.platform is not None:
            d.platform = _normalize_device_platform(d.type, req.platform)
        if req.target_count is not None:
            d.target_count = max(req.target_count, 1)
        if req.concurrency is not None:
            d.concurrency = max(req.concurrency, 1)
        if req.register_delay_seconds is not None:
            d.register_delay_seconds = max(req.register_delay_seconds, 0)
        if req.executor_type is not None:
            d.executor_type = _normalize_device_executor(d.type, req.executor_type)
        if req.mail_provider is not None:
            d.mail_provider = req.mail_provider
        if req.domain_rules is not None:
            d.domain_rules_json = json.dumps(req.domain_rules, ensure_ascii=False)
        if req.business_domains is not None:
            d.business_domains = json.dumps(
                _normalize_business_domains(req.business_domains, existing=d.business_domains),
                ensure_ascii=False,
            )
        if req.sub_group_ids is not None:
            d.sub_group_ids = req.sub_group_ids
        if req.wants_refresh_token is not None:
            d.wants_refresh_token = bool(req.wants_refresh_token)
        if req.priority is not None:
            d.priority = max(req.priority, 0)
        if req.sync_batch_size is not None:
            d.sync_batch_size = max(req.sync_batch_size, 1)
        if req.auto_replenish_batch_size is not None:
            d.auto_replenish_batch_size = max(req.auto_replenish_batch_size, 0)
        if req.default_proxy_id is not None:
            d.default_proxy_id = req.default_proxy_id
        if req.enabled is not None:
            d.enabled = req.enabled
        d.updated_at = _utcnow()
        s.add(d)
        s.commit()
        s.refresh(d)
        return _serialize(d)


@router.delete("/{device_id}")
def delete_device(device_id: int):
    with _delivery_refresh_mutation_lock(device_id):
        expected_sub2api = _sub2api_delete_preflight(device_id)
        result = _delete_device_locked(
            device_id,
            expected_sub2api=expected_sub2api,
        )
        if expected_sub2api is not None:
            from services import delivery_device_monitor

            delivery_device_monitor.delete_snapshots(
                delivery_device_monitor.device_key("sub2api", int(device_id))
            )
        return result


def _delete_device_locked(
    device_id: int,
    *,
    expected_sub2api: Optional[tuple[Any, ...]] = None,
):
    with Session(engine) as s:
        d = _lock_device_for_reference_safe_mutation(s, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")
        if _is_sub2api_device_type(d.type):
            from api.delivery_devices import _assert_no_hosting_worker
            _assert_no_hosting_worker(f"sub2api:{device_id}", session=s)
        if expected_sub2api is not None:
            current_sub2api = (
                str(d.api_url or "").strip().rstrip("/"),
                str(d.api_key or ""),
                str(d.sub_group_ids or "2").strip() or "2",
                str(d.updated_at or ""),
            )
            if (
                not _is_sub2api_device_type(d.type)
                or current_sub2api != expected_sub2api
            ):
                raise HTTPException(
                    409,
                    "Sub2API 设备配置在远端核对后发生变化，请重试",
                )
        references = _sub2api_device_reference_counts(s, device_id)
        if int(references["total"]):
            details = []
            if int(references["gpt_plan_accounts"]):
                details.append(
                    f"{references['gpt_plan_accounts']} 个非 BUSINESS GPT 套餐账号"
                )
            if int(references["business_parents"]):
                details.append(
                    f"{references['business_parents']} 个 BUSINESS 母号绑定"
                )
            raise HTTPException(
                409,
                "该 Sub2API 设备仍被 " + "、".join(details) + " 引用，请先解绑",
            )
        if _is_sub2api_device_type(d.type):
            from services.device_hosting_store import forget_device
            forget_device(f"sub2api:{device_id}", session=s)
        s.delete(d)
        s.commit()
        return {"ok": True}


@router.post("/{device_id}/check")
def check_device_pool(device_id: int):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")

    from services.device_manager import check_device_pool as _check
    result = _check(device_id)
    return result


@router.get("/{device_ref}/accounts")
def get_delivery_device_account_snapshot(
    device_ref: str,
    refresh: bool = Query(False),
):
    from api.delivery_devices import delivery_device_accounts

    return delivery_device_accounts(device_ref, refresh=refresh)


@router.get("/{device_ref}/business-bindings")
def get_delivery_device_business_bindings(device_ref: str):
    from api.delivery_devices import delivery_device_business_bindings

    return delivery_device_business_bindings(device_ref)


@router.put("/{device_ref}/business-bindings")
def replace_delivery_device_business_bindings(
    device_ref: str,
    body: DeliveryDeviceBusinessBindingsPutRequest,
):
    from api.delivery_devices import put_delivery_device_business_bindings

    return put_delivery_device_business_bindings(device_ref, body)


@router.delete("/{device_ref}/business-bindings/{parent_id}")
def remove_delivery_device_business_binding(
    device_ref: str,
    parent_id: int,
    expected_revision: int = Query(..., ge=0),
):
    from api.delivery_devices import delete_delivery_device_business_binding

    return delete_delivery_device_business_binding(
        device_ref,
        parent_id,
        expected_revision=expected_revision,
    )


@router.post("/{device_ref}/accounts/refresh")
def refresh_delivery_device_account_snapshot(device_ref: str):
    from api.delivery_devices import delivery_device_accounts

    return delivery_device_accounts(device_ref, refresh=True)


@router.post("/{device_ref}/accounts/refresh-tasks", status_code=202)
def create_delivery_device_account_refresh_task(
    device_ref: str,
    body: Optional[DeliveryDeviceRefreshTaskRequest] = None,
):
    from api.delivery_devices import start_delivery_device_refresh_task

    return start_delivery_device_refresh_task(device_ref, body)


@router.get("/{device_ref}/accounts/refresh-tasks/{task_id}")
def get_delivery_device_account_refresh_task(
    device_ref: str,
    task_id: str,
    since: int = Query(0, ge=0),
):
    from api.delivery_devices import _refresh_task_snapshot

    return _refresh_task_snapshot(device_ref, task_id, since=since)


def create_delivery_device_team401_correction_batch(
    device_ref: str,
    body: DeliveryTeam401CorrectionBatchRequest,
):
    from api.delivery_devices import start_team401_correction_batch

    return start_team401_correction_batch(device_ref, body)


def list_delivery_device_team401_correction_batches(
    device_ref: str,
    business_parent_id: Optional[int] = Query(None, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    from api.delivery_devices import list_team401_correction_batches

    return list_team401_correction_batches(
        device_ref,
        parent_id=business_parent_id,
        limit=limit,
    )


def get_delivery_device_team401_correction_batch(
    device_ref: str,
    batch_id: str,
):
    from api.delivery_devices import _team401_batch_snapshot

    return _team401_batch_snapshot(device_ref, batch_id)


def get_delivery_device_team401_correction_item(
    device_ref: str,
    batch_id: str,
    task_id: str,
):
    from api.delivery_devices import get_team401_correction_task

    return get_team401_correction_task(device_ref, batch_id, task_id)


def retry_delivery_device_team401_correction_item(
    device_ref: str,
    batch_id: str,
    task_id: str,
):
    from api.delivery_devices import retry_team401_correction_task

    return retry_team401_correction_task(device_ref, batch_id, task_id)


def create_delivery_device_team_replacement_task(
    device_ref: str,
    body: DeliveryTeamReplacementTaskRequest,
):
    from api.delivery_devices import start_delivery_team_replacement_task

    return start_delivery_team_replacement_task(device_ref, body)


def list_delivery_device_team_replacement_tasks(
    device_ref: str,
    limit: int = Query(20, ge=1, le=100),
):
    from api.delivery_devices import list_delivery_team_replacement_tasks

    return list_delivery_team_replacement_tasks(device_ref, limit=limit)


def get_delivery_device_team_replacement_task(
    device_ref: str,
    task_id: str,
    since: int = Query(0, ge=0),
):
    from api.delivery_devices import _manual_replacement_task_snapshot

    return _manual_replacement_task_snapshot(
        device_ref, task_id, since=since,
    )


def retry_delivery_device_team_replacement_task(
    device_ref: str,
    task_id: str,
):
    from api.delivery_devices import retry_delivery_team_replacement_task

    return retry_delivery_team_replacement_task(device_ref, task_id)


def _sub2api_device_or_404(device_id: int) -> SyncDeviceModel:
    with Session(engine) as s:
        device = s.get(SyncDeviceModel, device_id)
        if not device:
            raise HTTPException(404, "设备不存在")
        if not _is_sub2api_device_type(device.type):
            raise HTTPException(400, "仅 Sub2API 设备支持此操作")
        # Materialize the fields used after the session closes.
        _ = (device.api_url, device.api_key, device.type)
        return device


def _raise_sub2api_admin_http_error(exc: Exception) -> None:
    from services.sub2api_admin import (
        Sub2ApiAccountAmbiguous,
        Sub2ApiAccountNotFound,
        Sub2ApiAdminError,
        Sub2ApiIdentityMismatch,
    )

    if isinstance(exc, Sub2ApiAccountNotFound):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, Sub2ApiAccountAmbiguous):
        raise HTTPException(409, str(exc)) from exc
    if isinstance(exc, Sub2ApiIdentityMismatch):
        raise HTTPException(409, "Sub2API 远端账号身份与删除确认不一致") from exc
    if isinstance(exc, Sub2ApiAdminError):
        # Local validation is a bad request. Remote/network failures are a bad
        # gateway; never echo an upstream body/message that could contain tokens.
        if int(exc.status_code or 0) == 0 and exc.payload is None:
            raise HTTPException(400, str(exc)) from exc
        remote_status = int(exc.status_code or 0)
        if remote_status == 404:
            raise HTTPException(404, "Sub2API 远端账号不存在") from exc
        if remote_status == 409:
            raise HTTPException(409, "Sub2API 远端账号状态冲突或尚未收敛") from exc
        suffix = f" (HTTP {remote_status})" if 100 <= remote_status <= 599 else ""
        logger.warning(
            "Sub2API admin request failed: type=%s status=%s",
            type(exc).__name__,
            remote_status,
        )
        raise HTTPException(502, f"Sub2API 远端请求失败{suffix}") from exc
    raise exc


@router.get("/{device_id}/sub2api/accounts/resolve")
def resolve_sub2api_account(
    device_id: int,
    email: str = Query(""),
    name: str = Query(""),
):
    """Resolve one exact remote account without exposing credentials."""
    device = _sub2api_device_or_404(device_id)
    from services.sub2api_admin import find_account_exact, public_account_identity

    try:
        account = find_account_exact(
            device.api_url,
            device.api_key,
            email=email,
            name=name,
        )
        return {"ok": True, "account": public_account_identity(account)}
    except Exception as exc:
        _raise_sub2api_admin_http_error(exc)


@router.get("/{device_id}/sub2api/accounts/{remote_account_id}/usage")
def get_sub2api_account_usage(
    device_id: int,
    remote_account_id: str,
    source: str = Query("passive"),
    force: bool = Query(False),
):
    """Read cached/passive usage by default.

    ``source=active`` or ``force=true`` is an explicit opt-in: the remote
    Sub2API service may probe upstream and persist refreshed limit headers.
    """
    device = _sub2api_device_or_404(device_id)
    from services.sub2api_admin import get_account_usage, sanitize_admin_payload

    try:
        usage = get_account_usage(
            device.api_url,
            device.api_key,
            remote_account_id,
            source=source,
            force=force,
        )
        return {
            "ok": True,
            "remote_account_id": str(remote_account_id),
            "source": str(source or "passive").strip().lower(),
            "force": bool(force),
            "usage": sanitize_admin_payload(usage, secrets=(device.api_key,)),
        }
    except Exception as exc:
        _raise_sub2api_admin_http_error(exc)


@router.get("/{device_id}/sub2api/accounts/{remote_account_id}/quota")
def query_sub2api_openai_quota(device_id: int, remote_account_id: str):
    """Query upstream OpenAI quota; Sub2API may refresh credentials."""
    device = _sub2api_device_or_404(device_id)
    from services.sub2api_admin import query_openai_quota, sanitize_admin_payload

    try:
        quota = query_openai_quota(
            device.api_url,
            device.api_key,
            remote_account_id,
        )
        return {
            "ok": True,
            "remote_account_id": str(remote_account_id),
            "quota": sanitize_admin_payload(quota, secrets=(device.api_key,)),
        }
    except Exception as exc:
        _raise_sub2api_admin_http_error(exc)


@router.delete("/{device_id}/sub2api/accounts/{remote_account_id}")
def delete_sub2api_remote_account(
    device_id: int,
    remote_account_id: str,
    expected_email: str = Query(""),
    expected_name: str = Query(""),
):
    """Explicitly delete one remote id; never called by local lifecycle hooks."""
    device = _sub2api_device_or_404(device_id)
    from services.sub2api_admin import delete_account

    try:
        response = delete_account(
            device.api_url,
            device.api_key,
            remote_account_id,
            expected_email=expected_email,
            expected_name=expected_name,
        )
        return {
            "ok": True,
            **response,
        }
    except Exception as exc:
        _raise_sub2api_admin_http_error(exc)


class Gpt2webCleanupRequest(BaseModel):
    pool: str = "main"            # main / warmup
    filter: str = "disabled"      # disabled / throttled / all


@router.post("/{device_id}/gpt2web/cleanup-invalid")
def gpt2web_cleanup_invalid(device_id: int, req: Gpt2webCleanupRequest | None = None):
    """删除 GPT2WEB 设备远端无效账号 (调 /api/admin/accounts/bulk-delete)。"""
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")
        if d.type != "gpt2web":
            raise HTTPException(400, "仅 GPT2WEB 设备支持此操作")

    body = req or Gpt2webCleanupRequest()
    from services.device_manager import delete_gpt2web_invalid_accounts
    ok, deleted, msg = delete_gpt2web_invalid_accounts(
        d.api_url, d.api_key,
        pool=body.pool, filter=body.filter,
    )
    if not ok:
        raise HTTPException(400, msg)

    # 删除后刷新一下设备记录的远端账号数
    try:
        from services.device_manager import _count_gpt2web_pool, _update_device_count
        count = _count_gpt2web_pool(d.api_url, d.api_key)
        if count >= 0:
            _update_device_count(d.id, count)
    except Exception:
        pass

    return {"ok": True, "deleted": deleted, "message": msg}


@router.post("/{device_id}/business-domains/reset-quota")
def reset_device_business_domain_quota(
    device_id: int,
    req: BusinessQuotaResetRequest | None = None,
):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")

    from services.device_manager import reset_business_domain_quota as _reset

    result = _reset(device_id, hostnames=req.hostnames if req else None)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "重置 BUSINESS 域名额度失败")
    return result


@router.post("/check-all")
def check_all_devices():
    from services.device_manager import check_all_devices as _check_all
    return _check_all()


@router.post("/{device_id}/replenish")
def replenish_device(device_id: int, req: DeviceReplenishRequest | None = None):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")

    from services.device_manager import replenish_device as _replenish
    count = req.count if req and req.count and req.count > 0 else None
    result = _replenish(device_id, count=count)
    return result


@router.post("/{device_id}/test")
def test_device(device_id: int):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if not d:
            raise HTTPException(404, "设备不存在")

    from services.device_manager import test_device as _test
    return _test(device_id)
