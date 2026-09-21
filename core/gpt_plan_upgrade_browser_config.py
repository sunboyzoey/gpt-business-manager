"""GPT 套餐管理专属的升级浏览器策略。

套餐管理单独持久这份配置，不读写旧 GPT PRO 界面的配置。配置只在
``upgrade-pro`` 入口按请求快照解析；普通登录、注册、退款和 BUSINESS 结账
不会自动继承它。
"""

from __future__ import annotations

from typing import Any, Optional

from sqlmodel import Session

from .config_store import config_store
from .db import GptPlanRoxyProxyModel as RoxyProxyModel, engine as default_engine


UPGRADE_BROWSER_BACKEND_KEY = "gpt_plan_upgrade_browser_backend"
UPGRADE_ROXY_PROXY_ID_KEY = "gpt_plan_upgrade_roxy_proxy_id"
DEFAULT_UPGRADE_BROWSER_BACKEND = "local"
VALID_UPGRADE_BROWSER_BACKENDS = frozenset({"local", "roxybrowser"})


class UpgradeBrowserConfigError(ValueError):
    """可安全转换为 HTTP 错误的配置/代理选择错误。"""

    def __init__(self, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _normalize_backend(value: Any, *, strict: bool = False) -> str:
    backend = str(value or "").strip().lower()
    if backend in VALID_UPGRADE_BROWSER_BACKENDS:
        return backend
    if strict:
        raise UpgradeBrowserConfigError(
            "browser_backend 只支持 local 或 roxybrowser",
            status_code=400,
        )
    return DEFAULT_UPGRADE_BROWSER_BACKEND


def _normalize_proxy_id(value: Any) -> Optional[int]:
    if value in (None, "", 0, "0"):
        return None
    try:
        proxy_id = int(value)
    except (TypeError, ValueError):
        raise UpgradeBrowserConfigError("roxy_proxy_id 必须是正整数", status_code=400)
    if proxy_id <= 0:
        raise UpgradeBrowserConfigError("roxy_proxy_id 必须是正整数", status_code=400)
    return proxy_id


def load_upgrade_browser_config() -> dict[str, Any]:
    """读取套餐管理专属配置；历史库没有配置时回退到本地浏览器。"""

    backend = _normalize_backend(
        config_store.get(
            UPGRADE_BROWSER_BACKEND_KEY,
            DEFAULT_UPGRADE_BROWSER_BACKEND,
        )
    )
    try:
        proxy_id = _normalize_proxy_id(
            config_store.get(UPGRADE_ROXY_PROXY_ID_KEY, "")
        )
    except UpgradeBrowserConfigError:
        # 配置库里若存在旧的非法值，不阻塞配置页面；执行/下次保存会纠正。
        proxy_id = None
    if backend == "local":
        proxy_id = None
    return {
        "browser_backend": backend,
        "use_roxy": backend == "roxybrowser",
        "enabled": backend == "roxybrowser",
        "roxy_proxy_id": proxy_id,
    }


def validate_roxy_proxy(
    proxy_id: Any,
    *,
    db_engine=None,
    status_code: int = 400,
) -> Optional[int]:
    """校验所选代理仍存在且启用；未指定代理是合法的 Roxy 模式。"""

    normalized = _normalize_proxy_id(proxy_id)
    if normalized is None:
        return None
    target_engine = db_engine if db_engine is not None else default_engine
    with Session(target_engine) as session:
        proxy = session.get(RoxyProxyModel, normalized)
        if not proxy:
            raise UpgradeBrowserConfigError(
                f"所选 Roxy 代理不存在（ID {normalized}）",
                status_code=status_code,
            )
        if not bool(proxy.enabled):
            raise UpgradeBrowserConfigError(
                f"所选 Roxy 代理已停用（ID {normalized}）",
                status_code=status_code,
            )
    return normalized


def save_upgrade_browser_config(
    *,
    browser_backend: Any,
    roxy_proxy_id: Any = None,
    db_engine=None,
) -> dict[str, Any]:
    """校验并原子保存套餐管理策略；切回 local 时清空已选代理。"""

    backend = _normalize_backend(browser_backend, strict=True)
    proxy_id = None
    if backend == "roxybrowser":
        proxy_id = validate_roxy_proxy(
            roxy_proxy_id,
            db_engine=db_engine,
            status_code=400,
        )
    config_store.set_many(
        {
            UPGRADE_BROWSER_BACKEND_KEY: backend,
            UPGRADE_ROXY_PROXY_ID_KEY: str(proxy_id or ""),
        }
    )
    return {
        "browser_backend": backend,
        "use_roxy": backend == "roxybrowser",
        "enabled": backend == "roxybrowser",
        "roxy_proxy_id": proxy_id,
    }


def _model_fields_set(body: Any) -> set[str]:
    fields_set = getattr(body, "model_fields_set", None)
    if fields_set is None:  # Pydantic v1 compatibility
        fields_set = getattr(body, "__fields_set__", set())
    return set(fields_set or set())


def resolve_upgrade_browser_selection(
    body: Any,
    *,
    db_engine=None,
) -> dict[str, Any]:
    """把请求显式值与套餐管理配置合并为本次升级的不可变快照。

    兼容规则：

    * 显式 ``browser_backend`` 永远优先于套餐管理配置；
    * 显式选择 ``roxybrowser`` 但省略代理，保留旧语义（Roxy 无指定代理）；
    * 省略浏览器字段时才继承套餐管理配置及其代理；
    * 每次执行前重新确认配置/显式代理仍存在且启用。
    """

    configured = load_upgrade_browser_config()
    fields_set = _model_fields_set(body)
    backend_is_explicit = (
        "browser_backend" in fields_set
        and getattr(body, "browser_backend", None) is not None
    )
    proxy_is_explicit = "roxy_proxy_id" in fields_set

    if backend_is_explicit:
        backend = _normalize_backend(
            getattr(body, "browser_backend", None),
            strict=True,
        )
    else:
        backend = configured["browser_backend"]

    if backend == "local":
        proxy_id = None
    elif proxy_is_explicit:
        proxy_id = _normalize_proxy_id(getattr(body, "roxy_proxy_id", None))
    elif backend_is_explicit:
        # 旧调用显式指定 Roxy 但未传代理时，不暗中套用全局代理。
        proxy_id = None
    else:
        proxy_id = configured["roxy_proxy_id"]

    if backend == "roxybrowser" and proxy_id is not None:
        proxy_id = validate_roxy_proxy(
            proxy_id,
            db_engine=db_engine,
            status_code=409,
        )

    return {
        "browser_backend": backend,
        "use_roxy": backend == "roxybrowser",
        "enabled": backend == "roxybrowser",
        "roxy_proxy_id": proxy_id,
    }


def apply_upgrade_browser_selection(body: Any, *, db_engine=None) -> dict[str, Any]:
    """解析共享策略并把本次快照写回请求对象，供现有升级链路透明复用。"""

    selection = resolve_upgrade_browser_selection(body, db_engine=db_engine)
    body.browser_backend = selection["browser_backend"]
    body.roxy_proxy_id = selection["roxy_proxy_id"]
    return selection
