"""外部系统同步（自动导入 / 回填）"""

from __future__ import annotations

import json
from typing import Any

from services.chatgpt_sync import (
    _get_account_extra,
    persist_cpa_sync_result,
    upload_chatgpt_account_to_cpa,
)


def _is_config_enabled(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def is_business_account(account) -> bool:
    """判断是否为 BUSINESS 类型(extra_json.account_type == 'BUSINESS')"""
    try:
        if hasattr(account, "get_extra"):
            extra = account.get_extra()
        else:
            extra = _get_account_extra(account)
        return str(extra.get("account_type", "")).upper() == "BUSINESS"
    except Exception:
        return False


def should_sync_to_cpa(account) -> tuple[bool, str]:
    """是否应该同步到 CPA。

    默认仅同步 BUSINESS 账号(由 config_store.cpa_sync_business_only 控制,默认 True)。
    """
    from core.config_store import config_store

    only_business = str(
        config_store.get("cpa_sync_business_only", "true") or "true"
    ).strip().lower() in {"1", "true", "yes", "on"}
    if not only_business:
        return True, "全量同步模式"
    if is_business_account(account):
        return True, "BUSINESS"
    return False, "非 BUSINESS 类型,跳过 CPA 同步"


def sync_account(account) -> list[dict[str, Any]]:
    """根据平台将账号同步到外部系统。"""
    from core.config_store import config_store

    platform = getattr(account, "platform", "")
    extra_data = _get_account_extra(account)
    results: list[dict[str, Any]] = []

    device_id_raw = extra_data.get("_sync_device_id")
    if device_id_raw:
        try:
            device_id = int(device_id_raw)
        except (TypeError, ValueError):
            device_id = 0
        if device_id > 0:
            from services.device_manager import upload_account_to_device
            ok, msg = upload_account_to_device(account, device_id)
            device_type = extra_data.get("_sync_device_type", "cpa").upper()
            results.append({"name": f"设备#{device_id}({device_type})", "ok": ok, "msg": msg})
            return results

    if platform == "chatgpt":
        cpa_url = str(config_store.get("cpa_api_url", "") or "").strip()
        if cpa_url:
            should_sync, reason = should_sync_to_cpa(account)
            if should_sync:
                ok, msg = upload_chatgpt_account_to_cpa(account)
                persist_cpa_sync_result(account, ok, msg)
                results.append({"name": "CPA", "ok": ok, "msg": msg})
            else:
                results.append({"name": "CPA", "ok": True, "msg": f"已跳过: {reason}"})

        codex_proxy_url = str(config_store.get("codex_proxy_url", "") or "").strip()
        if codex_proxy_url:
            upload_type = str(config_store.get("codex_proxy_upload_type", "at") or "at").strip().lower()
            extra = _get_account_extra(account)

            class _CP:
                pass

            cp = _CP()
            cp.access_token = extra.get("access_token") or account.token
            cp.refresh_token = extra.get("refresh_token", "")

            if upload_type == "rt":
                from platforms.chatgpt.cpa_upload import upload_to_codex_proxy
                ok, msg = upload_to_codex_proxy(cp)
                results.append({"name": "CodexProxy(RT)", "ok": ok, "msg": msg})
            else:
                from platforms.chatgpt.cpa_upload import upload_at_to_codex_proxy
                ok, msg = upload_at_to_codex_proxy(cp)
                results.append({"name": "CodexProxy(AT)", "ok": ok, "msg": msg})

        # 关键逻辑：ChatGPT 现在支持同时回填 CPA 和 Sub2API，互不覆盖、分别上报结果。
        sub2api_url = str(config_store.get("sub2api_api_url", "") or "").strip()
        sub2api_key = str(config_store.get("sub2api_api_key", "") or "").strip()
        if sub2api_url and sub2api_key:
            from platforms.chatgpt.sub2api_upload import upload_chatgpt_account_to_sub2api

            ok, msg = upload_chatgpt_account_to_sub2api(
                account,
                api_url=sub2api_url,
                api_key=sub2api_key,
            )
            results.append({"name": "Sub2API", "ok": ok, "msg": msg})

    elif platform == "grok":
        grok2api_url = str(config_store.get("grok2api_url", "") or "").strip()
        if grok2api_url:
            from services.grok2api_runtime import ensure_grok2api_ready
            from platforms.grok.grok2api_upload import upload_to_grok2api

            ready, ready_msg = ensure_grok2api_ready()
            if not ready:
                results.append({"name": "grok2api", "ok": False, "msg": ready_msg})
                return results

            ok, msg = upload_to_grok2api(account)
            results.append({"name": "grok2api", "ok": ok, "msg": msg})

    elif platform == "kiro":
        from platforms.kiro.account_manager_upload import resolve_manager_path, upload_to_kiro_manager

        configured_path = str(config_store.get("kiro_manager_path", "") or "").strip()
        target_path = resolve_manager_path(configured_path or None)
        if configured_path or target_path.parent.exists() or target_path.exists():
            ok, msg = upload_to_kiro_manager(account, path=configured_path or None)
            results.append({"name": "Kiro Manager", "ok": ok, "msg": msg})

    return results
