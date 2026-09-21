"""同步设备号池管理 — 多设备维护、检查、补号"""
from __future__ import annotations

import json
import logging
import random
import threading
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from core.db import SyncDeviceModel, engine

logger = logging.getLogger(__name__)

DEVICE_REPLENISH_SOURCE = "device_replenish"
DEVICE_TEST_SOURCE = "device_test"
_business_domain_lock = threading.Lock()


def normalize_device_type(value: Any) -> str:
    """Canonicalize legacy device type aliases without requiring a DB migration."""
    normalized = str(value or "").strip().lower()
    if normalized in {"sub", "sub-2-api"}:
        return "sub2api"
    return normalized


def is_sub2api_device_type(value: Any) -> bool:
    return normalize_device_type(value) == "sub2api"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _count_cpa_pool(api_url: str, api_key: str) -> int:
    from services.cpa_manager import list_auth_files, _count_healthy
    files = list_auth_files(api_url=api_url, api_key=api_key)
    return _count_healthy(files)


def _is_sub_account_active(account: Any) -> bool:
    if not isinstance(account, dict):
        return False
    if account.get("disabled") is True:
        return False
    status = str(account.get("status") or "").strip().lower()
    return status != "disabled"


def _coerce_int(value: Any) -> int:
    if isinstance(value, bool):
        return -1
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return -1


def _parse_sub_group_ids(group_ids: Any) -> list[int]:
    if isinstance(group_ids, (list, tuple, set)):
        raw_parts = group_ids
    else:
        raw_parts = str(group_ids or "2").split(",")

    parsed: list[int] = []
    for part in raw_parts:
        try:
            value = int(str(part).strip())
        except (TypeError, ValueError):
            continue
        if value > 0 and value not in parsed:
            parsed.append(value)
    return parsed or [2]


def _extract_sub_pool_count(data: Any) -> int:
    if isinstance(data, list):
        return sum(1 for item in data if _is_sub_account_active(item))
    if not isinstance(data, dict):
        return -1

    for key in ("active_count", "valid_count", "enabled_count", "total", "count"):
        count = _coerce_int(data.get(key))
        if count >= 0:
            return count

    for key in ("data", "result"):
        count = _extract_sub_pool_count(data.get(key))
        if count >= 0:
            return count

    for key in ("items", "accounts", "rows", "list"):
        value = data.get(key)
        if isinstance(value, list):
            return sum(1 for item in value if _is_sub_account_active(item))
    return -1


def _unwrap_sub_pool_payload(data: Any) -> Any:
    current = data
    for _ in range(4):
        if not isinstance(current, dict):
            break
        if "data" in current and (
            len(current) == 1
            or any(key in current for key in ("code", "message", "success", "ok", "error"))
        ):
            current = current.get("data")
            continue
        if "result" in current and (
            len(current) == 1
            or any(key in current for key in ("code", "message", "success", "ok", "error"))
        ):
            current = current.get("result")
            continue
        break
    return current


def _extract_sub_pool_items(data: Any) -> list[dict[str, Any]]:
    payload = _unwrap_sub_pool_payload(data)
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "accounts", "rows", "list"):
        items = payload.get(key)
        if isinstance(items, list):
            return [dict(item) for item in items if isinstance(item, dict)]
    return []


def _sub_account_remote_id(account: dict[str, Any]) -> str:
    value = account.get("id") or account.get("account_id")
    if isinstance(value, bool):
        return ""
    text = str(value or "").strip()
    if not text or (text.isdigit() and int(text) <= 0):
        return ""
    return text


def _fetch_sub_group_account_ids(
    url: str,
    group_id: int,
    request_kwargs: dict[str, Any],
) -> set[str] | None:
    """读取一个 group 的完整账号 ID 集；无法证明完整性时返回 None。"""
    from curl_cffi import requests as cffi_requests

    page_size = 100
    account_ids: set[str] = set()
    seen_pages: set[tuple[str, ...]] = set()
    for page in range(1, 1001):
        response = cffi_requests.get(
            url,
            params={
                "platform": "openai",
                "type": "oauth",
                "status": "active",
                "group": group_id,
                "page": page,
                "page_size": page_size,
            },
            **request_kwargs,
        )
        if response.status_code != 200:
            return None
        try:
            data = response.json()
        except Exception:
            return None
        items = _extract_sub_pool_items(data)
        payload = _unwrap_sub_pool_payload(data)
        payload_dict = payload if isinstance(payload, dict) else {}
        total = _coerce_int(payload_dict.get("total"))
        if not items:
            return set() if total == 0 else None

        page_ids: list[str] = []
        for account in items:
            account_id = _sub_account_remote_id(account)
            if not account_id:
                return None
            page_ids.append(account_id)
            if _is_sub_account_active(account):
                account_ids.add(account_id)
        fingerprint = tuple(page_ids)
        if fingerprint in seen_pages:
            return None
        seen_pages.add(fingerprint)

        pages = _coerce_int(payload_dict.get("pages"))
        if pages > 0:
            if page >= pages:
                return account_ids
            continue

        reported_page_size = _coerce_int(payload_dict.get("page_size"))
        effective_page_size = reported_page_size if reported_page_size > 0 else len(items)
        if total >= 0:
            if page * max(1, effective_page_size) >= total:
                return account_ids
            continue
        if len(items) < page_size:
            return account_ids
    return None


def _count_sub_pool(api_url: str, api_key: str, group_ids: Any = "2") -> int:
    from curl_cffi import requests as cffi_requests
    url = f"{api_url.rstrip('/')}/api/v1/admin/accounts"
    headers = {
        "Accept": "application/json",
        "x-api-key": api_key,
    }
    request_kwargs = {
        "headers": headers,
        "timeout": 15,
        # Sub2API admin keys must not cross an unverified TLS connection.
        "verify": True,
        "impersonate": "chrome110",
    }
    try:
        parsed_group_ids = _parse_sub_group_ids(group_ids)
        if len(parsed_group_ids) > 1:
            # 同一账号可同时属于多个 group。逐组读取 ID 后取并集，不能把各组
            # total 直接相加，否则设备会误判号池充足并停止补号。
            unique_ids: set[str] = set()
            for group_id in parsed_group_ids:
                group_account_ids = _fetch_sub_group_account_ids(
                    url,
                    group_id,
                    request_kwargs,
                )
                if group_account_ids is None:
                    return -1
                unique_ids.update(group_account_ids)
            return len(unique_ids)

        total = 0
        for group_id in parsed_group_ids:
            r = cffi_requests.get(
                url,
                params={
                    "platform": "openai",
                    "type": "oauth",
                    "status": "active",
                    "group": group_id,
                    "page": 1,
                    "page_size": 1,
                },
                **request_kwargs,
            )
            if r.status_code != 200:
                return -1
            count = _extract_sub_pool_count(r.json())
            if count < 0:
                return -1
            total += count
        return total
    except Exception as exc:
        # HTTP 客户端异常可能包含请求头；不要把管理密钥写进日志。
        logger.warning("Sub2API 查询号池失败: type=%s", type(exc).__name__)
        return -1


def _extract_count_from_response(data: Any) -> int:
    if isinstance(data, list):
        return len(data)
    if not isinstance(data, dict):
        return -1

    for key in (
        "active_count",
        "valid_count",
        "enabled_count",
        "active_accounts",
        "accounts_count",
        "account_count",
        "total",
        "count",
    ):
        value = data.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())

    for key in ("data", "accounts", "items", "tokens", "rows", "list"):
        value = data.get(key)
        count = _extract_count_from_response(value)
        if count >= 0:
            return count
    return -1


def _count_gpt2web_pool(api_url: str, api_key: str) -> int:
    """查 GPT2WEB 正式池可用账号数。

    优先调 /api/admin/stats 的 active_main_accounts。
    失败回退到 /api/admin/accounts?pool=main, 客户端过滤 status==active。
    都不可用时再退到老的 /api/admin-sync/* (向后兼容旧版 GPT2WEB)。
    """
    from curl_cffi import requests as cffi_requests

    base = api_url.rstrip("/")
    new_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    legacy_headers = {
        "Accept": "application/json",
        "X-Admin-API-Key": api_key,
    }

    # 1) 新接口 /api/admin/stats: 直接拿 active_main_accounts
    try:
        r = cffi_requests.get(
            f"{base}/api/admin/stats",
            headers=new_headers,
            timeout=15, verify=True, impersonate="chrome110",
        )
        if r.status_code == 200:
            data = r.json() if r.text else {}
            if isinstance(data, dict):
                inner = data.get("data") if isinstance(data.get("data"), dict) else data
                value = inner.get("active_main_accounts")
                if isinstance(value, int) and value >= 0:
                    return value
                if isinstance(value, str) and value.strip().isdigit():
                    return int(value.strip())
    except Exception:
        pass

    # 2) 新接口 /api/admin/accounts?pool=main: 客户端过滤 status==active
    try:
        r = cffi_requests.get(
            f"{base}/api/admin/accounts",
            params={"pool": "main"},
            headers=new_headers,
            timeout=20, verify=True, impersonate="chrome110",
        )
        if r.status_code == 200:
            data = r.json() if r.text else {}
            payload = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
            items = payload.get("list") if isinstance(payload, dict) else None
            if isinstance(items, list):
                return sum(
                    1 for item in items
                    if isinstance(item, dict) and str(item.get("status") or "").lower() == "active"
                )
    except Exception:
        pass

    # 3) 旧接口兜底 (向后兼容老版 GPT2WEB)
    for path in (
        "/api/admin-sync/accounts/count",
        "/api/admin-sync/accounts/stats",
        "/api/admin-sync/accounts",
    ):
        try:
            r = cffi_requests.get(
                f"{base}{path}",
                headers=legacy_headers,
                timeout=15, verify=True, impersonate="chrome110",
            )
            if r.status_code != 200:
                continue
            count = _extract_count_from_response(r.json())
            if count >= 0:
                return count
        except Exception:
            continue
    return -1


def delete_gpt2web_invalid_accounts(
    api_url: str, api_key: str,
    *, pool: str = "main", filter: str = "disabled",
) -> tuple[bool, int, str]:
    """POST /api/admin/accounts/bulk-delete 删除无效账号。

    filter 合法值:
      - "disabled"  删除 status IN ('disabled','probe_failed')
      - "throttled" 删除 status='throttled'
      - "all"       清空整个 pool (慎用)

    返回 (ok, deleted_count, message)。
    """
    from curl_cffi import requests as cffi_requests

    base = api_url.rstrip("/").rstrip()
    pool = (pool or "main").strip().lower() or "main"
    filter_value = (filter or "disabled").strip().lower() or "disabled"

    url = f"{base}/api/admin/accounts/bulk-delete"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {"pool": pool, "filter": filter_value}

    try:
        r = cffi_requests.post(
            url, headers=headers, json=payload,
            timeout=60, verify=True, impersonate="chrome110",
        )
    except Exception as e:
        return False, 0, f"请求异常: {e}"

    if r.status_code not in (200, 201):
        err = ""
        try:
            data = r.json() or {}
            err = str(data.get("message") or data.get("error") or data.get("detail") or "")
        except Exception:
            err = (r.text or "")[:200]
        return False, 0, f"HTTP {r.status_code}: {err or '无错误信息'}"

    try:
        data = r.json() or {}
    except Exception:
        return False, 0, "响应非 JSON"

    payload_dict = data.get("data") if isinstance(data.get("data"), dict) else data
    deleted = payload_dict.get("deleted") if isinstance(payload_dict, dict) else None
    if isinstance(deleted, str) and deleted.strip().isdigit():
        deleted = int(deleted.strip())
    if not isinstance(deleted, int):
        deleted = 0

    return True, deleted, f"已删除 {deleted} 个 {filter_value} 状态的账号 (pool={pool})"


def get_gpt2web_remote_count(api_url: str, api_key: str) -> int:
    return _count_gpt2web_pool(api_url, api_key)


def get_sub2api_remote_count(api_url: str, api_key: str, group_ids: Any = "2") -> int:
    return _count_sub_pool(api_url, api_key, group_ids)


def get_grok2api_remote_count(api_url: str, api_key: str) -> int:
    return _count_grok2api_pool(api_url, api_key)


def get_adobe2api_remote_count(api_url: str, api_key: str) -> int:
    from platforms.adobe.adobe2api_upload import get_adobe2api_remote_count as _impl
    return _impl(api_url, api_key)


def _count_grok2api_pool(api_url: str, api_key: str) -> int:
    from curl_cffi import requests as cffi_requests

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    try:
        count_url = f"{api_url.rstrip('/')}/admin/api/tokens/count"
        request_kwargs = {
            "timeout": 15,
            "verify": False,
            "impersonate": "chrome110",
        }
        r = cffi_requests.get(
            count_url,
            headers=headers,
            **request_kwargs,
        )
        if r.status_code == 401:
            r = cffi_requests.get(
                count_url,
                headers={"Accept": "application/json"},
                params={"app_key": api_key},
                **request_kwargs,
            )
        if r.status_code != 200:
            return -1
        data = r.json()
        if not isinstance(data, dict):
            return -1
        return int(data.get("total", -1))
    except Exception as e:
        logger.warning(f"Grok2API 查询号池失败: {e}")
        return -1


def _get_device(device_id: int) -> SyncDeviceModel | None:
    with Session(engine) as s:
        return s.get(SyncDeviceModel, device_id)


def normalize_business_domain_entries(
    raw: Any,
    *,
    existing: Any = None,
) -> list[dict[str, Any]]:
    """Normalize legacy/new BUSINESS domain config.

    Supported persisted shapes:
      - ["a.example.com", "b.example.com"]  (legacy, unlimited)
      - [{"hostname": "a.example.com", "max_accounts": 10, ...}]
    """
    if isinstance(raw, str):
        try:
            raw_items = json.loads(raw or "[]")
        except Exception:
            raw_items = []
    else:
        raw_items = raw or []
    if not isinstance(raw_items, list):
        raw_items = []

    existing_map: dict[str, dict[str, Any]] = {}
    if existing is not None:
        for item in normalize_business_domain_entries(existing):
            host = str(item.get("hostname") or "").strip().lower()
            if host:
                existing_map[host] = item

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_items:
        if isinstance(item, str):
            hostname = item
            item_data: dict[str, Any] = {}
        elif isinstance(item, dict):
            hostname = (
                item.get("hostname")
                or item.get("domain")
                or item.get("value")
                or item.get("label")
                or ""
            )
            item_data = item
        else:
            continue

        hostname = str(hostname or "").strip().lower()
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        previous = existing_map.get(hostname, {})

        def _int_value(*keys: str, default: int = 0) -> int:
            for key in keys:
                value = item_data.get(key)
                if value is None and previous:
                    value = previous.get(key)
                if value is None:
                    continue
                try:
                    return max(0, int(value))
                except (TypeError, ValueError):
                    continue
            return default

        entries.append(
            {
                "hostname": hostname,
                "max_accounts": _int_value(
                    "max_accounts",
                    "max",
                    "limit",
                    "register_limit",
                    default=0,
                ),
                "used_count": _int_value("used_count", "used", default=0),
                "inflight_count": _int_value("inflight_count", "inflight", default=0),
            }
        )
    return entries


def has_business_domain_entries(raw: Any) -> bool:
    return bool(normalize_business_domain_entries(raw))


def reset_business_domain_quota(
    device_id: int,
    hostnames: list[str] | None = None,
) -> dict[str, Any]:
    selected_hosts = {
        str(host or "").strip().lower()
        for host in (hostnames or [])
        if str(host or "").strip()
    }
    with _business_domain_lock:
        with Session(engine) as s:
            d = s.get(SyncDeviceModel, device_id)
            if not d:
                return {"ok": False, "error": "设备不存在"}
            entries = normalize_business_domain_entries(d.business_domains)
            if not entries:
                return {"ok": False, "error": "设备未配置 BUSINESS 域名"}

            reset_count = 0
            for entry in entries:
                hostname = str(entry.get("hostname") or "").strip().lower()
                if selected_hosts and hostname not in selected_hosts:
                    continue
                entry["used_count"] = 0
                entry["inflight_count"] = 0
                reset_count += 1

            if reset_count <= 0:
                return {"ok": False, "error": "没有匹配的 BUSINESS 域名"}

            d.business_domains = json.dumps(entries, ensure_ascii=False)
            d.updated_at = _utcnow()
            s.add(d)
            s.commit()
            return {
                "ok": True,
                "device_id": device_id,
                "reset_count": reset_count,
                "business_domains": entries,
            }


def reserve_business_domain_for_device(device_id: int) -> dict[str, Any]:
    """Reserve the first selected BUSINESS domain that has remaining quota."""
    with _business_domain_lock:
        with Session(engine) as s:
            d = s.get(SyncDeviceModel, device_id)
            if not d:
                raise RuntimeError("设备不存在，无法分配 BUSINESS 域名")
            entries = normalize_business_domain_entries(d.business_domains)
            if not entries:
                raise RuntimeError("设备未配置 BUSINESS 域名")

            for entry in entries:
                max_accounts = int(entry.get("max_accounts") or 0)
                used_count = int(entry.get("used_count") or 0)
                inflight_count = int(entry.get("inflight_count") or 0)
                if max_accounts > 0 and used_count + inflight_count >= max_accounts:
                    continue

                entry["inflight_count"] = inflight_count + 1
                d.business_domains = json.dumps(entries, ensure_ascii=False)
                d.updated_at = _utcnow()
                s.add(d)
                s.commit()
                return dict(entry)

            raise RuntimeError("所选 BUSINESS 域名注册额度已用尽")


def finish_business_domain_reservation(
    device_id: int,
    hostname: str,
    *,
    success: bool,
) -> None:
    hostname = str(hostname or "").strip().lower()
    if not hostname:
        return
    with _business_domain_lock:
        with Session(engine) as s:
            d = s.get(SyncDeviceModel, device_id)
            if not d:
                return
            entries = normalize_business_domain_entries(d.business_domains)
            changed = False
            for entry in entries:
                if str(entry.get("hostname") or "").strip().lower() != hostname:
                    continue
                entry["inflight_count"] = max(0, int(entry.get("inflight_count") or 0) - 1)
                if success:
                    entry["used_count"] = max(0, int(entry.get("used_count") or 0) + 1)
                changed = True
                break
            if changed:
                d.business_domains = json.dumps(entries, ensure_ascii=False)
                d.updated_at = _utcnow()
                s.add(d)
                s.commit()


def _update_device_count(device_id: int, count: int):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if d:
            d.current_count = count
            d.last_check_at = _utcnow()
            d.updated_at = _utcnow()
            s.add(d)
            s.commit()


def _increment_device_count(device_id: int, delta: int = 1):
    with Session(engine) as s:
        d = s.get(SyncDeviceModel, device_id)
        if d:
            d.current_count = max(0, int(d.current_count or 0) + int(delta or 0))
            d.last_check_at = _utcnow()
            d.updated_at = _utcnow()
            s.add(d)
            s.commit()


def check_device_pool(device_id: int) -> dict[str, Any]:
    d = _get_device(device_id)
    if not d:
        return {"ok": False, "error": "设备不存在"}
    try:
        count_source = "remote"
        device_type = normalize_device_type(d.type)
        if device_type == "cpa":
            count = _count_cpa_pool(d.api_url, d.api_key)
        elif device_type == "sub2api":
            count = _count_sub_pool(d.api_url, d.api_key, d.sub_group_ids)
        elif device_type == "gpt2web":
            count = _count_gpt2web_pool(d.api_url, d.api_key)
        elif device_type == "grok2api":
            count = _count_grok2api_pool(d.api_url, d.api_key)
        elif device_type == "adobe2api":
            count = get_adobe2api_remote_count(d.api_url, d.api_key)
        else:
            return {"ok": False, "error": f"未知设备类型: {d.type}"}

        if count < 0:
            if device_type == "gpt2web":
                return {
                    "ok": False,
                    "error": "查询 GPT2WEB 真实号池失败，请确认远端 /api/admin-sync/accounts/count 可用",
                }
            if device_type == "grok2api":
                return {
                    "ok": False,
                    "error": "查询 GROK2API 真实号池失败，请确认远端 /admin/api/tokens/count 可用",
                }
            if device_type == "adobe2api":
                return {
                    "ok": False,
                    "error": "查询 ADOBE2API 真实号池失败，请确认远端 /api/v1/admin/accounts/summary 可用",
                }
            else:
                return {"ok": False, "error": "查询号池失败"}

        _update_device_count(device_id, count)
        return {
            "ok": True,
            "device_id": device_id,
            "name": d.name,
            "type": device_type,
            "current_count": count,
            "target_count": d.target_count,
            "need_replenish": count < d.target_count,
            "missing": max(0, d.target_count - count),
            "count_source": count_source,
        }
    except Exception as e:
        logger.error(f"检查设备 {d.name} 号池失败: {e}")
        return {"ok": False, "error": str(e)}


def check_all_devices() -> dict[str, Any]:
    with Session(engine) as s:
        devices = s.exec(
            select(SyncDeviceModel)
            .where(SyncDeviceModel.enabled == True)
            .order_by(SyncDeviceModel.id)
        ).all()
        device_ids = [d.id for d in devices]

    results = []
    for did in device_ids:
        results.append(check_device_pool(did))
    return {"items": results}


def _build_device_register_extra(device: SyncDeviceModel) -> dict:
    from core.config_store import config_store
    merged = config_store.get_all().copy()

    device_type = normalize_device_type(device.type)
    # BUSINESS 域优先:配置了就走 BUSINESS 流程(强制 cfworker 邮箱,跳过普通域)
    biz_domains = normalize_business_domain_entries(getattr(device, "business_domains", "[]"))
    if biz_domains:
        merged["_sync_device_business_domains"] = "1"
        merged["mail_provider"] = "cfworker"  # BUSINESS 必须配合 cfworker 接码
        merged["_sync_device_id"] = str(device.id)
        merged["_sync_device_type"] = device_type
        merged["_sync_batch_size"] = str(device.sync_batch_size)
        merged["business_switch_to_codex"] = "0"
        if device_type == "sub2api" and device.sub_group_ids:
            merged["sub2api_group_ids"] = device.sub_group_ids
        # CPA/Sub2API 设备 + BUSINESS 域名 + RT 模式 → 走"长跑感"补号
        # phase 2/3 失败的号入库到 RT 长跑界面的对应队列、不算 attempt 失败,
        # 任务持续跑直到 target_count 个号真正成功上传到远端
        if device_type in {"cpa", "sub2api"}:
            # 优先看设备自身的 wants_refresh_token 开关;否则降级看全局配置
            wants_rt = bool(getattr(device, "wants_refresh_token", False))
            if not wants_rt:
                mode = str(merged.get("chatgpt_registration_mode") or "").strip().lower()
                wants_rt = (
                    mode in ("rt", "refresh_token", "oauth")
                    or str(merged.get("chatgpt_has_refresh_token_solution") or "").strip().lower()
                    in ("1", "true", "yes")
                )
            if wants_rt:
                # 同步注入到 extra,让 platform.register() 里的 wants_refresh_token 判定通过
                merged["chatgpt_registration_mode"] = "rt"
                merged["chatgpt_has_refresh_token_solution"] = "1"
                merged["_business_long_run_mode"] = "1"
        return merged

    rules = device.get_domain_rules()
    domains = rules.get("domains", [])
    if domains:
        merged["cfworker_domain_override"] = random.choice(domains)

    max_per_sub = rules.get("max_accounts_per_subdomain")
    if max_per_sub:
        merged["cfworker_subdomain_max_accounts"] = str(max_per_sub)

    strategy = rules.get("subdomain_strategy")
    if strategy:
        merged["cfworker_subdomain_strategy"] = strategy

    prefix = rules.get("subdomain_prefix")
    if prefix:
        merged["cfworker_subdomain_prefix"] = prefix

    merged["mail_provider"] = device.mail_provider
    merged["_sync_device_id"] = str(device.id)
    merged["_sync_device_type"] = device_type
    merged["_sync_batch_size"] = str(device.sync_batch_size)

    if device_type == "sub2api" and device.sub_group_ids:
        merged["sub2api_group_ids"] = device.sub_group_ids
    if device_type == "grok2api":
        merged["grok2api_url"] = device.api_url
        merged["grok2api_app_key"] = device.api_key
        merged["grok_skip_payment_link"] = "1"
    if device_type == "adobe2api":
        merged["adobe2api_url"] = device.api_url
        merged["adobe2api_api_key"] = device.api_key
        # Adobe 注册默认走随机子域名 (与手动注册一致)，避免和 force_subdomain 冲突
        merged.setdefault("cfworker_subdomain_mode", "random")

    return merged


def replenish_device(device_id: int, count: int | None = None) -> dict[str, Any]:
    d = _get_device(device_id)
    if not d:
        return {"ok": False, "error": "设备不存在"}
    if not d.enabled:
        return {"ok": False, "error": "设备已禁用"}

    if count is not None:
        try:
            count = max(0, int(count))
        except (TypeError, ValueError):
            count = 0
        if count <= 0:
            return {"ok": False, "error": "补号数量必须大于 0"}

    from api.tasks import RegisterTaskRequest, enqueue_register_task, has_active_register_task

    if has_active_register_task(
        source=DEVICE_REPLENISH_SOURCE,
        meta={"device_id": device_id},
    ):
        return {"ok": False, "error": "该设备已存在进行中的补号任务"}

    # 总是先查一次真实远端水位线,即使用户明确传了 count 也要 cap 到 missing,
    # 避免历史 bug:UI 弹窗里用户填的数字 > 缺口时,远端账号数会被注册到超过 target
    pool_result = check_device_pool(device_id)
    if not pool_result.get("ok"):
        return {"ok": False, "error": f"号池检查失败: {pool_result.get('error')}"}
    missing = max(0, int(pool_result.get("missing") or 0))

    if missing <= 0:
        return {"ok": True, "message": "号池充足，无需补号", "triggered": False}

    if count is None:
        count = missing
    elif count > missing:
        logger.info(
            f"[设备] {d.name}: 用户请求补 {count} 个,但远端缺口仅 {missing} 个,已 cap 到 {missing}"
        )
        count = missing

    extra = _build_device_register_extra(d)
    executor_type = (
        "protocol"
        if extra.get("_sync_device_business_domains")
        else d.executor_type
    )
    req = RegisterTaskRequest(
        platform=d.platform,
        count=count,
        concurrency=d.concurrency,
        register_delay_seconds=d.register_delay_seconds,
        executor_type=executor_type,
        extra=extra,
    )
    task_id = enqueue_register_task(
        req,
        source=DEVICE_REPLENISH_SOURCE,
        meta={"device_id": device_id, "device_name": d.name},
    )
    logger.info(f"[设备] {d.name}: 创建补号任务 {task_id}，补充 {count} 个")
    return {"ok": True, "triggered": True, "task_id": task_id, "count": count}


def maintain_all_devices() -> dict[str, Any]:
    # GPT PRO 专用 CPA 设备(CPA 号池配置里绑定的那些)只由 GPT PRO 编排器维护,
    # 这里跳过全部,避免设备管理往 PRO 专用池塞普通注册号导致两套维护冲突。
    gpt_pro_dev_ids = set()
    try:
        from services.gpt_plan_cpa_manager import _bound_device_ids
        gpt_pro_dev_ids = set(_bound_device_ids())
    except Exception:
        gpt_pro_dev_ids = set()

    with Session(engine) as s:
        devices = s.exec(
            select(SyncDeviceModel)
            .where(SyncDeviceModel.enabled == True)
            .order_by(SyncDeviceModel.id)
        ).all()
        device_ids = [d.id for d in devices if d.id not in gpt_pro_dev_ids]

    if not device_ids:
        return {"ok": True, "message": "无启用的设备"}

    results = []
    for did in device_ids:
        pool = check_device_pool(did)
        if pool.get("ok") and pool.get("need_replenish"):
            device = _get_device(did)
            missing = max(int(pool.get("missing") or 0), 0)
            limit = max(
                int(getattr(device, "auto_replenish_batch_size", 0) or 0),
                0,
            )
            replenish_count = min(missing, limit) if limit > 0 else missing
            rep = replenish_device(did, count=replenish_count)
            results.append({**pool, "replenish": rep})
        else:
            results.append(pool)
    return {"items": results}


def upload_account_to_device(account, device_id: int) -> tuple[bool, str]:
    d = _get_device(device_id)
    if not d:
        return False, "设备不存在"

    device_type = normalize_device_type(d.type)
    if device_type == "cpa":
        from services.chatgpt_sync import upload_chatgpt_account_to_cpa
        return upload_chatgpt_account_to_cpa(account, api_url=d.api_url, api_key=d.api_key, priority=d.priority)
    elif device_type == "sub2api":
        from platforms.chatgpt.sub2api_upload import upload_chatgpt_account_to_sub2api
        group_ids = _parse_sub_group_ids(getattr(d, "sub_group_ids", None))
        return upload_chatgpt_account_to_sub2api(account, api_url=d.api_url, api_key=d.api_key, group_ids=group_ids)
    elif device_type == "gpt2web":
        from platforms.chatgpt.gpt2web_upload import upload_to_gpt2web

        ok, msg = upload_to_gpt2web(
            account,
            api_url=d.api_url,
            api_key=d.api_key,
            default_proxy_id=d.default_proxy_id,
        )
        if d.id is not None:
            count = _count_gpt2web_pool(d.api_url, d.api_key)
            if count >= 0:
                _update_device_count(d.id, count)
        return ok, msg
    elif device_type == "grok2api":
        if str(getattr(account, "platform", "") or "").strip().lower() != "grok":
            return False, "Grok2API 设备只支持同步 Grok 账号"
        from platforms.grok.grok2api_upload import upload_to_grok2api

        ok, msg = upload_to_grok2api(
            account,
            api_url=d.api_url,
            app_key=d.api_key,
        )
        if ok and d.id is not None:
            _increment_device_count(d.id, 1)
        return ok, msg
    elif device_type == "adobe2api":
        if str(getattr(account, "platform", "") or "").strip().lower() != "adobe":
            return False, "Adobe2API 设备只支持同步 Adobe 账号"
        from platforms.adobe.adobe2api_upload import upload_to_adobe2api

        ok, msg = upload_to_adobe2api(
            account,
            api_url=d.api_url,
            api_key=d.api_key,
        )
        if ok and d.id is not None:
            _increment_device_count(d.id, 1)
        return ok, msg
    else:
        return False, f"未知设备类型: {d.type}"


def upload_accounts_to_device(accounts: list[Any], device_id: int) -> list[tuple[Any, bool, str]]:
    try:
        return _upload_accounts_to_device_impl(accounts, device_id)
    except Exception as exc:
        # 兜底:任何异常都返回失败结果而不是让上层 task 崩,避免账号在本机被误删
        logger.exception(f"upload_accounts_to_device 异常 device_id={device_id}: {exc}")
        return [(account, False, f"上传异常: {exc}") for account in accounts]


def _upload_accounts_to_device_impl(accounts: list[Any], device_id: int) -> list[tuple[Any, bool, str]]:
    d = _get_device(device_id)
    if not d:
        return [(account, False, "设备不存在") for account in accounts]

    if d.type != "gpt2web":
        return [
            (account, *upload_account_to_device(account, device_id))
            for account in accounts
        ]

    from platforms.chatgpt.gpt2web_upload import extract_st_for_gpt2web, upload_tokens_to_gpt2web

    # GPT2WEB 强制走 ST:批量收 ST,缺则 fetch_session_token 在线拿
    st_pairs: list[tuple[Any, str]] = []
    results: list[tuple[Any, bool, str]] = []
    for account in accounts:
        st, source = extract_st_for_gpt2web(account)
        if st:
            st_pairs.append((account, st))
            if source == "fetched":
                logger.info(
                    f"GPT2WEB({d.name}): {getattr(account,'email','?')} 从 /api/auth/session 抓到 ST"
                )
        else:
            results.append((account, False, "账号缺少 ST,且 access_token 在线拿 ST 失败"))

    if st_pairs:
        ok, msg = upload_tokens_to_gpt2web(
            [st for _, st in st_pairs],
            api_url=d.api_url,
            api_key=d.api_key,
            mode="st",
            client_id=None,
            default_proxy_id=d.default_proxy_id,
        )
        results.extend((account, ok, f"ST: {msg}") for account, _ in st_pairs)

    if d.id is not None and st_pairs:
        count = _count_gpt2web_pool(d.api_url, d.api_key)
        if count >= 0:
            _update_device_count(d.id, count)

    return results


def test_device(device_id: int) -> dict[str, Any]:
    """测试设备：注册 1 个账号并同步到设备，不受设备启用状态限制。"""
    d = _get_device(device_id)
    if not d:
        return {"ok": False, "error": "设备不存在"}

    try:
        from api.tasks import RegisterTaskRequest, enqueue_register_task

        extra = _build_device_register_extra(d)
        executor_type = (
            "protocol"
            if extra.get("_sync_device_business_domains")
            else d.executor_type
        )
        req = RegisterTaskRequest(
            platform=d.platform,
            count=1,
            concurrency=1,
            register_delay_seconds=d.register_delay_seconds,
            executor_type=executor_type,
            extra=extra,
        )
        task_id = enqueue_register_task(
            req,
            source=DEVICE_TEST_SOURCE,
            meta={"device_id": device_id, "device_name": d.name, "test": True},
        )
        logger.info(f"[设备] {d.name}: 创建测试任务 {task_id}")
        return {"ok": True, "task_id": task_id, "device_name": d.name}
    except Exception as e:
        logger.error(f"[设备] {d.name}: 测试失败: {e}")
        return {"ok": False, "error": str(e)}
