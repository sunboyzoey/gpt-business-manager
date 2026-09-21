"""grok2api 自动导入"""

from __future__ import annotations

import logging
from typing import Tuple

from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)

DEFAULT_POOL = "auto"


def _get_config_value(key: str) -> str:
    try:
        from core.config_store import config_store

        return str(config_store.get(key, "") or "")
    except Exception:
        return ""


def resolve_grok2api_pool(account, pool_name: str | None = None) -> str:
    resolved = str(pool_name or DEFAULT_POOL).strip()
    return resolved or DEFAULT_POOL


def _extract_sso(account) -> str:
    extra = getattr(account, "extra", {}) or {}
    token = (
        extra.get("sso")
        or extra.get("sso_token")
        or extra.get("sso_rw")
        or getattr(account, "token", "")
    )
    token = str(token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def build_grok2api_payload(
    account,
    pool_name: str | None = None,
    quota=None,
) -> dict:
    token = _extract_sso(account)
    if not token:
        raise ValueError("账号缺少 sso token")

    pool_name = resolve_grok2api_pool(account, pool_name=pool_name)
    return {"pool": pool_name, "tokens": [token], "tags": []}


def _request_options() -> dict:
    return {
        "proxies": None,
        "verify": False,
        "timeout": 30,
        "impersonate": "chrome110",
    }


def _build_headers(app_key: str) -> dict:
    return {
        "Authorization": f"Bearer {app_key}",
        "Content-Type": "application/json",
    }


def upload_to_grok2api(
    account,
    api_url: str | None = None,
    app_key: str | None = None,
    pool_name: str | None = None,
    quota=None,
) -> Tuple[bool, str]:
    """上传 Grok 账号到 grok2api 管理接口。"""
    if not api_url:
        api_url = _get_config_value("grok2api_url")
    if not app_key:
        app_key = _get_config_value("grok2api_app_key")

    api_url = str(api_url or "").strip()
    app_key = str(app_key or "").strip()
    if not api_url:
        return False, "grok2api URL 未配置"
    if not app_key:
        return False, "grok2api 后台管理密码未配置"

    payload = build_grok2api_payload(account, pool_name=pool_name, quota=quota)
    pool_name = str(payload.get("pool") or DEFAULT_POOL)
    upload_url = f"{api_url.rstrip('/')}/admin/api/tokens/add"
    headers = _build_headers(app_key)

    try:
        resp = cffi_requests.post(
            upload_url,
            headers=headers,
            json=payload,
            **_request_options(),
        )
        if resp.status_code in (200, 201):
            return True, f"导入成功: pool={pool_name}"

        error_msg = f"导入失败: HTTP {resp.status_code}"
        if resp.status_code == 401:
            error_msg = "导入失败: HTTP 401，请在全局配置填写 grok2api 后台管理密码，不是 /v1/* 普通 API Key"
        try:
            detail = resp.json()
            if isinstance(detail, dict):
                detail_msg = detail.get("message") or detail.get("detail")
                if resp.status_code != 401 and detail_msg:
                    error_msg = detail_msg
        except Exception:
            if resp.status_code != 401:
                error_msg = f"{error_msg} - {resp.text[:200]}"
        return False, error_msg
    except Exception as e:
        logger.error(f"grok2api 导入异常: {e}")
        return False, f"导入异常: {e}"


def remove_from_grok2api(
    account,
    api_url: str | None = None,
    app_key: str | None = None,
    pool_name: str | None = None,
) -> Tuple[bool, str]:
    """追加导入模式不做远端清理。保留函数兼容旧调用点。"""
    return True, "追加导入模式不清理远端 token"
