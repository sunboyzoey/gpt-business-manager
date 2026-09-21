"""CPA 号池维护：CLIProxyAPI 实时删坏号，本模块只负责数数量 + 补注册。

架构分工：
  CLIProxyAPI（实时）：检测到 401/403(banned)/429(free) → 自动删除 auth
  本模块（定时）：每 N 分钟查一次号池数量 → 不足 threshold 就注册补满
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


DEFAULT_INTERVAL_MINUTES = 5
DEFAULT_THRESHOLD = 1000
DEFAULT_CONCURRENCY = 3
DEFAULT_REGISTER_DELAY_SECONDS = 0.0
AUTO_REGISTER_SOURCE = "cpa_replenish"


@dataclass
class CpaMaintenanceConfig:
    enabled: bool
    interval_minutes: int
    threshold: int
    concurrency: int
    register_delay_seconds: float


def _get_config_store():
    from core.config_store import config_store

    return config_store


def _to_bool(value: str | None, default: bool = False) -> bool:
    raw = str(value or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _to_int(value: str | None, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(float(str(value or "").strip())))
    except Exception:
        return default


def _to_float(value: str | None, default: float, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(str(value or "").strip()))
    except Exception:
        return default


def get_cpa_maintenance_config() -> CpaMaintenanceConfig:
    config_store = _get_config_store()
    return CpaMaintenanceConfig(
        enabled=_to_bool(config_store.get("cpa_cleanup_enabled", ""), default=False),
        interval_minutes=_to_int(
            config_store.get("cpa_cleanup_interval_minutes", ""),
            DEFAULT_INTERVAL_MINUTES,
            minimum=1,
        ),
        threshold=_to_int(
            config_store.get("cpa_cleanup_threshold", ""),
            DEFAULT_THRESHOLD,
            minimum=1,
        ),
        concurrency=_to_int(
            config_store.get("cpa_cleanup_concurrency", ""),
            DEFAULT_CONCURRENCY,
            minimum=1,
        ),
        register_delay_seconds=_to_float(
            config_store.get("cpa_cleanup_register_delay_seconds", ""),
            DEFAULT_REGISTER_DELAY_SECONDS,
            minimum=0.0,
        ),
    )


def get_cpa_maintenance_interval_seconds() -> int:
    config_store = _get_config_store()
    api_url = str(config_store.get("cpa_api_url", "") or "").strip()
    config = get_cpa_maintenance_config()
    if not config.enabled or not api_url:
        return 0
    return config.interval_minutes * 60


def _api_base(api_url: str | None = None) -> str:
    config_store = _get_config_store()
    base_url = str(api_url or config_store.get("cpa_api_url", "") or "").strip()
    if not base_url:
        raise RuntimeError("CPA API URL 未配置")
    return base_url.rstrip("/")


def _headers(api_key: str | None = None) -> dict[str, str]:
    config_store = _get_config_store()
    token = str(api_key or config_store.get("cpa_api_key", "") or "").strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request(method: str, path: str, *, api_url: str | None = None, api_key: str | None = None, json_body: dict | None = None) -> Any:
    response = requests.request(
        method,
        f"{_api_base(api_url)}{path}",
        headers=_headers(api_key),
        json=json_body,
        timeout=30,
        verify=True,
    )
    response.raise_for_status()
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return response.text


def list_auth_files(*, api_url: str | None = None, api_key: str | None = None) -> list[dict[str, Any]]:
    data = _request("GET", "/v0/management/auth-files", api_url=api_url, api_key=api_key)
    files = data.get("files", []) if isinstance(data, dict) else []
    return [item for item in files if isinstance(item, dict)]


def list_auth_files_strict(*, api_url: str | None = None, api_key: str | None = None) -> list[dict[str, Any]]:
    """Return one complete auth-file listing or raise on an unknown shape.

    Ordinary monitoring keeps the historical tolerant projection above.  A
    device deletion, however, must never turn a malformed/partial response
    into an authoritative empty list, so it uses this strict variant.
    """
    data = _request(
        "GET",
        "/v0/management/auth-files",
        api_url=api_url,
        api_key=api_key,
    )
    if not isinstance(data, dict) or "files" not in data:
        raise RuntimeError("CPA 凭据列表响应格式异常")
    files = data.get("files")
    if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
        raise RuntimeError("CPA 凭据列表响应不完整")
    return list(files)


def delete_auth_files(names: list[str], *, api_url: str | None = None, api_key: str | None = None) -> Any:
    clean_names = [name for name in names if str(name).strip()]
    if not clean_names:
        return {"deleted": 0}
    return _request(
        "DELETE",
        "/v0/management/auth-files",
        api_url=api_url,
        api_key=api_key,
        json_body={"names": clean_names},
    )


def set_auth_file_disabled(name: str, disabled: bool, *,
                           api_url: str | None = None, api_key: str | None = None) -> Any:
    """停用/启用某个 auth-file(不删除)。对应 CLIProxyAPI:
    PATCH /v0/management/auth-files/status  {"name": <文件名>, "disabled": true/false}。"""
    if not str(name or "").strip():
        return {"ok": False, "error": "empty name"}
    return _request(
        "PATCH",
        "/v0/management/auth-files/status",
        api_url=api_url,
        api_key=api_key,
        json_body={"name": str(name).strip(), "disabled": bool(disabled)},
    )


def reset_quota(auth_index: int, *, api_url: str | None = None, api_key: str | None = None) -> Any:
    """清除某账号在 CPA 内部的限流/冷却路由标记(让 CPA 重新把流量路由给它)。
    对应 CLIProxyAPI: POST /v0/management/reset-quota {"auth_index": N}。"""
    return _request(
        "POST",
        "/v0/management/reset-quota",
        api_url=api_url,
        api_key=api_key,
        json_body={"auth_index": auth_index},
    )


def _count_healthy(files: list[dict[str, Any]]) -> int:
    """统计健康的凭证数量（CLIProxyAPI 已自动删坏号，剩下非 disabled 的都是好的）"""
    return sum(
        1
        for item in files
        if str(item.get("name", "")).strip()
        and not item.get("disabled", False)
        and str(item.get("status", "")).strip().lower() not in ("disabled", "error")
    )


def _normalize_executor(executor: str | None) -> str:
    value = str(executor or "").strip()
    if value in {"protocol", "headless", "headed"}:
        return value
    return "protocol"


def _normalize_solver(solver: str | None) -> str:
    value = str(solver or "").strip()
    if value in {"yescaptcha", "local_solver", "manual"}:
        return value
    return "yescaptcha"


def _trigger_register(count: int, *, config: CpaMaintenanceConfig, remaining: int) -> dict[str, Any]:
    from api.tasks import RegisterTaskRequest, enqueue_register_task, has_active_register_task

    if has_active_register_task(platform="chatgpt", source=AUTO_REGISTER_SOURCE):
        print(f"[CPA] 已存在进行中的自动补注册任务，跳过本轮")
        return {"triggered": False, "reason": "task_running"}

    config_store = _get_config_store()
    req = RegisterTaskRequest(
        platform="chatgpt",
        count=count,
        concurrency=config.concurrency,
        register_delay_seconds=config.register_delay_seconds,
        executor_type=_normalize_executor(config_store.get("default_executor", "protocol")),
        captcha_solver=_normalize_solver(config_store.get("default_captcha_solver", "yescaptcha")),
        extra={},
    )
    task_id = enqueue_register_task(
        req,
        source=AUTO_REGISTER_SOURCE,
        meta={
            "remaining": remaining,
            "threshold": config.threshold,
            "missing": count,
        },
    )
    print(
        f"[CPA] 号池 {remaining}/{config.threshold}，"
        f"已创建注册任务 {task_id}，补充 {count} 个"
    )
    return {"triggered": True, "task_id": task_id, "count": count}


def maintain_cpa_credentials() -> dict[str, Any]:
    """
    CPA 号池维护（简化版）。

    CLIProxyAPI 已实时删除坏号（401/403-banned/429-free），
    本函数只需：查数量 → 不足就补注册。
    """
    config = get_cpa_maintenance_config()
    if not config.enabled:
        return {"ok": False, "reason": "disabled"}

    # 查询号池
    files = list_auth_files()
    remaining = _count_healthy(files)

    result: dict[str, Any] = {
        "ok": True,
        "total": len(files),
        "remaining": remaining,
        "threshold": config.threshold,
    }

    if remaining >= config.threshold:
        print(f"[CPA] 号池充足: {remaining}/{config.threshold}，无需补充")
        result["register"] = {"triggered": False, "reason": "pool_sufficient"}
        return result

    # 号池不足，补注册
    missing = config.threshold - remaining
    print(f"[CPA] 号池不足: {remaining}/{config.threshold}，需补充 {missing} 个")
    result["register"] = _trigger_register(missing, config=config, remaining=remaining)
    return result
