from __future__ import annotations

from typing import Tuple

import requests


def _get_config(key: str, default: str = "") -> str:
    try:
        from core.config_store import config_store

        value = str(config_store.get(key, "") or "").strip()
        return value or default
    except Exception:
        return default


def verify_grok2api(api_url: str | None = None, app_key: str | None = None) -> Tuple[bool, str]:
    api_url = str(api_url or _get_config("grok2api_url", "")).strip()
    app_key = str(app_key or _get_config("grok2api_app_key", "")).strip()

    if not api_url:
        return False, "grok2api URL 未配置"
    if not app_key:
        return False, "grok2api 后台管理密码未配置"

    try:
        resp = requests.get(
            f"{api_url.rstrip('/')}/v1/admin/verify",
            headers={"Authorization": f"Bearer {app_key}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return True, "grok2api 鉴权正常"
        if resp.status_code == 401:
            return False, "grok2api 鉴权失败: HTTP 401，请填写后台管理密码，不是 /v1/* 普通 API Key"
        return False, f"grok2api 鉴权失败: HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, f"grok2api 连接失败: {e}"


def ensure_grok2api_ready() -> Tuple[bool, str]:
    api_url = _get_config("grok2api_url", "http://127.0.0.1:8011")
    app_key = _get_config("grok2api_app_key", "grok2api")

    ok, msg = verify_grok2api(api_url=api_url, app_key=app_key)
    if ok:
        return True, msg

    from services.external_apps import list_status, start, stop

    try:
        status = next((item for item in list_status() if item["name"] == "grok2api"), None)
        if status and not status.get("repo_exists"):
            return False, "grok2api 未安装，请先到“设置 → 插件”里手动安装"
        running = bool(status and status.get("running"))

        if running:
            stop("grok2api")
        start("grok2api")
    except Exception as e:
        return False, f"{msg}; 自动重启 grok2api 失败: {e}"

    return verify_grok2api(api_url=api_url, app_key=app_key)
