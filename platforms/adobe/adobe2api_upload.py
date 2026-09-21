"""Adobe2API 设备 — 同步 Adobe 账号 Cookie 到外部管理后端。

接口约定 (Admin API):
- 鉴权: 三选一 Header
    Authorization: Bearer <admin_api_key>
    X-Admin-API-Key: <admin_api_key>
    X-API-Key: <admin_api_key>
- 号池数量: GET  /api/v1/admin/accounts/summary
- 批量导入: POST /api/v1/admin/accounts/import-cookies
    body: {"items": [{"name": "...", "cookie": "..."}]}
    返回: {imported_count, refreshed_count, failed_count, refresh_failed_count, status}
"""
from __future__ import annotations

import logging
from typing import Tuple

from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)


def _build_headers(api_key: str) -> dict:
    api_key = (api_key or "").strip()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if api_key:
        # 三个 Header 都塞,让远端任选其一鉴权
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-Admin-API-Key"] = api_key
        headers["X-API-Key"] = api_key
    return headers


def _request_options() -> dict:
    return {
        "proxies": None,
        "verify": False,
        "timeout": 30,
        "impersonate": "chrome110",
    }


def get_adobe2api_summary(api_url: str, api_key: str) -> dict:
    """获取号池汇总,返回原始 JSON dict (失败返回空 dict)。"""
    base = (api_url or "").rstrip("/")
    if not base:
        return {}
    try:
        r = cffi_requests.get(
            f"{base}/api/v1/admin/accounts/summary",
            headers=_build_headers(api_key),
            **_request_options(),
        )
        if r.status_code != 200:
            logger.warning(
                "Adobe2API summary HTTP %s: %s", r.status_code, (r.text or "")[:200]
            )
            return {}
        data = r.json()
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning(f"Adobe2API 查询号池失败: {e}")
        return {}


def get_adobe2api_remote_count(api_url: str, api_key: str) -> int:
    """从 /accounts/summary 读出 total。失败返回 -1。"""
    data = get_adobe2api_summary(api_url, api_key)
    if not data:
        return -1
    try:
        return int(data.get("total", -1))
    except Exception:
        return -1


def _extract_cookie(account) -> str:
    extra = getattr(account, "extra", {}) or {}
    cookie = str(extra.get("cookie", "") or "").strip()
    return cookie


def upload_to_adobe2api(
    account,
    api_url: str | None = None,
    api_key: str | None = None,
) -> Tuple[bool, str]:
    """单账号上传 — POST /api/v1/admin/accounts/import-cookies。"""
    base = (api_url or "").rstrip("/")
    if not base:
        return False, "Adobe2API api_url 未配置"
    cookie = _extract_cookie(account)
    if not cookie:
        return False, "账号缺少 Cookie (注册流程未落盘)"
    name = (
        getattr(account, "email", None)
        or getattr(account, "user_id", None)
        or f"account_{getattr(account, 'id', 'unknown')}"
    )
    payload = {"items": [{"name": str(name), "cookie": cookie}]}
    try:
        r = cffi_requests.post(
            f"{base}/api/v1/admin/accounts/import-cookies",
            headers=_build_headers(api_key or ""),
            json=payload,
            **_request_options(),
        )
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {(r.text or '')[:300]}"
        data = r.json() if r.text else {}
        if not isinstance(data, dict):
            return True, "已上传 (远端未返回 JSON)"
        imported = int(data.get("imported_count", 0) or 0)
        failed = int(data.get("failed_count", 0) or 0)
        if imported >= 1:
            refreshed = int(data.get("refreshed_count", 0) or 0)
            msg = f"导入成功 (refresh: {refreshed})"
            return True, msg
        if failed >= 1:
            return False, f"远端返回失败: {data}"
        return False, f"远端未导入任何账号: {data}"
    except Exception as e:
        logger.warning(f"Adobe2API 上传失败: {e}")
        return False, f"网络/解析异常: {e}"


def upload_many_to_adobe2api(
    accounts: list,
    api_url: str | None = None,
    api_key: str | None = None,
) -> Tuple[bool, str]:
    """批量上传 — 复用同一个 import-cookies 接口,一次提交多条。"""
    base = (api_url or "").rstrip("/")
    if not base:
        return False, "Adobe2API api_url 未配置"
    items = []
    for acc in accounts:
        cookie = _extract_cookie(acc)
        if not cookie:
            continue
        name = (
            getattr(acc, "email", None)
            or getattr(acc, "user_id", None)
            or f"account_{getattr(acc, 'id', 'unknown')}"
        )
        items.append({"name": str(name), "cookie": cookie})
    if not items:
        return False, "没有任何账号包含可上传的 Cookie"

    payload = {"items": items}
    try:
        r = cffi_requests.post(
            f"{base}/api/v1/admin/accounts/import-cookies",
            headers=_build_headers(api_key or ""),
            json=payload,
            **_request_options(),
        )
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {(r.text or '')[:300]}"
        data = r.json() if r.text else {}
        if isinstance(data, dict):
            imported = int(data.get("imported_count", 0) or 0)
            refreshed = int(data.get("refreshed_count", 0) or 0)
            failed = int(data.get("failed_count", 0) or 0)
            return imported > 0, (
                f"imported={imported} refreshed={refreshed} failed={failed}"
            )
        return True, "已上传 (远端未返回 JSON)"
    except Exception as e:
        logger.warning(f"Adobe2API 批量上传失败: {e}")
        return False, f"网络/解析异常: {e}"
