"""GPT PRO ⇄ CPA 号池自动维护编排器。

目标: 让 CPA (CLIProxyAPI) 里始终保持 threshold 个 GPT PRO codex 凭证。

每轮维护 (maintain_once):
  1. 回收: PRO 账号购买满 refund_days 天且未退款 → 自动退款 → 删除其在 CPA 的凭证
  2. 补充: 已是 PRO 且有 codex_refresh_token 但还没同步到 CPA 的账号 → 上传 CPA
  3. (可选, 需开 auto_buy) 仍不足 → 升级空闲普通账号补号 (真实扣费)

安全: 默认关闭 (enabled=0); 单实例锁; 每轮处理数量上限 max_per_run。
配置存 config_store; 维护日志存内存环 (最近 200 条)。
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_LOCK = threading.Lock()
_RUNNING = False
_LOG: deque = deque(maxlen=200)
_LAST_RUN: dict[str, Any] = {}

CONFIG_KEYS = {
    "enabled": ("gpt_pro_cpa_enabled", "0"),
    "device_id": ("gpt_pro_cpa_device_id", ""),
    "api_url": ("gpt_pro_cpa_api_url", ""),
    "api_key": ("gpt_pro_cpa_api_key", ""),
    "threshold": ("gpt_pro_cpa_threshold", "10"),
    "refund_days": ("gpt_pro_cpa_refund_days", "2"),
    "interval_minutes": ("gpt_pro_cpa_interval_minutes", "10"),
    "max_per_run": ("gpt_pro_cpa_max_per_run", "3"),
    "auto_buy": ("gpt_pro_cpa_auto_buy", "0"),
    "card_max_uses": ("gpt_pro_card_max_uses", "6"),
    "recycle_hour": ("gpt_pro_cpa_recycle_hour", "0"),  # 每天几点跑退款回收(0-23)
    "devices": ("gpt_pro_cpa_devices", "[]"),  # JSON: [{device_id, threshold, api_url?, api_key?, refund_enabled, replenish_enabled, auto_buy, refund_days}]
}


def _cs():
    from core.config_store import config_store
    return config_store


def _to_int(v, default: int, minimum: int = 0) -> int:
    try:
        n = int(str(v).strip())
        return n if n >= minimum else default
    except Exception:
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_managed_business_child(account) -> bool:
    """CPA 自动编排器的 BUSINESS 子号安全边界。"""
    return getattr(account, "business_parent_id", None) is not None


def _is_business_child_cpa_lifecycle(account) -> bool:
    """账号当前或历史 CPA 凭证是否属于 BUSINESS 子号生命周期。

    ``business_parent_id`` 在子号释放后会被清空，因此退款这种破坏性操作
    不能只看当前归属；同步 BUSINESS 子号时写入的 durable kind 也必须参与
    最终执行前的安全判断。
    """
    if _is_managed_business_child(account):
        return True
    try:
        import json
        extra = json.loads(getattr(account, "extra_json", "") or "{}")
    except Exception:
        extra = {}
    return bool(
        isinstance(extra, dict)
        and (
            extra.get("cpa_account_kind") == "business_child"
            or extra.get("cpa_business_membership_stale")
        )
    )


def _log(msg: str, action: str = "info", account: str = "", ok: Optional[bool] = None) -> None:
    entry = {
        "ts": _now().isoformat(),
        "action": action,
        "account": account,
        "ok": ok,
        "msg": msg,
    }
    _LOG.appendleft(entry)
    print(f"[GPTPRO/CPA] {action} {account} {msg}", flush=True)


def _resolve_device_endpoint(device_id, api_url=None, api_key=None) -> tuple[str, str, str]:
    """device_id → (设备名, api_url, api_key);无 device_id 时用手填。"""
    if device_id:
        try:
            from core.db import engine, SyncDeviceModel
            from sqlmodel import Session
            with Session(engine) as s:
                d = s.get(SyncDeviceModel, int(device_id))
                if d and (d.api_url or "").strip():
                    return d.name or f"#{device_id}", d.api_url.strip(), (d.api_key or "").strip()
        except Exception as exc:
            _log(f"读取设备 {device_id} 失败: {exc}", "warn")
        # Stable device-bound configs must never fall back to a copied key.
        # Restoring the shared SyncDevice row is the only recovery path.
        return f"#{device_id}", "", ""
    return "", str(api_url or "").strip(), str(api_key or "").strip()


def get_config() -> dict[str, Any]:
    import json
    cs = _cs()
    raw = {k: cs.get(key, dflt) for k, (key, dflt) in CONFIG_KEYS.items()}
    try:
        dev_list = json.loads(raw["devices"]) or []
    except Exception:
        dev_list = []
    g_refund = _to_int(raw["refund_days"], 2, 1)
    g_autobuy = str(raw["auto_buy"]) in ("1", "true", "yes")
    devices = []
    for d in (dev_list if isinstance(dev_list, list) else []):
        if not isinstance(d, dict):
            continue
        did = _to_int(d.get("device_id"), 0)
        name, url, key = _resolve_device_endpoint(did, d.get("api_url"), d.get("api_key"))
        devices.append({
            "device_id": did, "name": name, "api_url": url, "api_key": key,
            "threshold": _to_int(d.get("threshold"), 10, 1),
            "refund_days": _to_int(d.get("refund_days"), g_refund, 1),
            "auto_buy": bool(d.get("auto_buy", g_autobuy)),
            "refund_enabled": bool(d.get("refund_enabled", d.get("enabled", True))),
            "replenish_enabled": bool(d.get("replenish_enabled", d.get("enabled", True))),
        })
    # 向后兼容: 没有 devices 列表但旧单设备已配 → 迁移成单元素
    if not devices:
        old_did = _to_int(raw["device_id"], 0)
        old_url = str(raw["api_url"] or "").strip()
        if old_did or old_url:
            name, url, key = _resolve_device_endpoint(old_did, old_url, raw["api_key"])
            if url:
                devices.append({
                    "device_id": old_did, "name": name, "api_url": url, "api_key": key,
                    "threshold": _to_int(raw["threshold"], 10, 1),
                    "refund_days": g_refund, "auto_buy": g_autobuy,
                    "refund_enabled": True, "replenish_enabled": True,
                })
    return {
        "enabled": str(raw["enabled"]) in ("1", "true", "yes"),
        "auto_buy": str(raw["auto_buy"]) in ("1", "true", "yes"),
        "devices": devices,
        "threshold_total": sum(d["threshold"] for d in devices),
        "refund_days": _to_int(raw["refund_days"], 2, 1),
        "interval_minutes": _to_int(raw["interval_minutes"], 10, 1),
        "max_per_run": _to_int(raw["max_per_run"], 3, 1),
        "card_max_uses": _to_int(raw["card_max_uses"], 6, 1),
        "recycle_hour": min(23, _to_int(raw["recycle_hour"], 0, 0)),
    }


def _auto_pool_endpoint_by_device_id(device_id: int) -> tuple[str, str]:
    """Resolve a bound auto-pool endpoint from current shared device config.

    Account-level copied keys are intentionally not consulted.  A missing or
    ambiguous stable id fails closed until the shared device is restored.
    """
    try:
        wanted = int(device_id or 0)
    except (TypeError, ValueError):
        return "", ""
    if wanted <= 0:
        return "", ""
    matches = [
        item for item in get_config().get("devices", [])
        if isinstance(item, dict) and int(item.get("device_id") or 0) == wanted
    ]
    if len(matches) != 1:
        return "", ""
    item = matches[0]
    return (
        str(item.get("api_url") or "").strip(),
        str(item.get("api_key") or "").strip(),
    )


def set_config(data: dict[str, Any]) -> dict[str, Any]:
    import json
    cs = _cs()
    mapping = {}
    if "enabled" in data:
        mapping[CONFIG_KEYS["enabled"][0]] = "1" if data["enabled"] else "0"
    if "auto_buy" in data:
        mapping[CONFIG_KEYS["auto_buy"][0]] = "1" if data["auto_buy"] else "0"
    for k in ("refund_days", "interval_minutes", "max_per_run", "card_max_uses", "recycle_hour"):
        if k in data and data[k] is not None:
            mapping[CONFIG_KEYS[k][0]] = str(int(data[k]))
    if "devices" in data and isinstance(data["devices"], list):
        clean = []
        for x in data["devices"]:
            if not isinstance(x, dict):
                continue
            clean.append({
                "device_id": int(x.get("device_id") or 0),
                "threshold": max(1, int(x.get("threshold") or 1)),
                "api_url": str(x.get("api_url") or "").strip(),
                "api_key": str(x.get("api_key") or "").strip(),
                "refund_days": max(1, int(x.get("refund_days") or 2)),
                "auto_buy": bool(x.get("auto_buy")),
                "refund_enabled": bool(x.get("refund_enabled", True)),
                "replenish_enabled": bool(x.get("replenish_enabled", True)),
            })
        mapping[CONFIG_KEYS["devices"][0]] = json.dumps(clean, ensure_ascii=False)
    for key, val in mapping.items():
        cs.set(key, val)
    return get_config()


def _bound_device_ids() -> list:
    """所有被 GPT PRO 绑定的 CPA 设备 id(供 device_manager 跳过)。"""
    try:
        return [d["device_id"] for d in get_config().get("devices", []) if d.get("device_id")]
    except Exception:
        return []


def _cpa_count(api_url: str, api_key: str) -> int:
    from services.cpa_manager import list_auth_files, _count_healthy
    return _count_healthy(list_auth_files(api_url=api_url, api_key=api_key))


def _cpa_counts(api_url: str, api_key: str) -> tuple[int, int]:
    """返回 (总凭证数, 健康凭证数)。总数=CPA 里所有有名字的文件(含 error 坏号)。"""
    from services.cpa_manager import list_auth_files, _count_healthy
    files = list_auth_files(api_url=api_url, api_key=api_key)
    total = sum(1 for f in files if str(f.get("name", "")).strip())
    return total, _count_healthy(files)


def _overdue_pro(devices: list) -> list:
    """按"每台 CPA 各自的退款天数"判断到期、未退款、未封禁的 PRO 账号。

    只处理归属到传入设备(已启用设备)的账号:账号经 extra.cpa_api_url 归属到某台设备,
    用该设备的 refund_days 判定;归属不到这些设备的账号不回收。
    """
    import json
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session, select
    device_days = {
        int(d.get("device_id") or 0): d["refund_days"]
        for d in devices
        if int(d.get("device_id") or 0) > 0
    }
    legacy_url_days = {
        d["api_url"]: d["refund_days"]
        for d in devices
        if d.get("api_url")
    }
    if not device_days and not legacy_url_days:
        return []
    now_ts = _now().timestamp()
    out = []
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel).where(GptProAccountModel.is_pro == True)).all()  # noqa: E712
        for a in rows:
            # BUSINESS 池选子号的生命周期由母号管理，绝不进入
            # GPT PRO 订阅到期退款/回收逻辑。
            if _is_business_child_cpa_lifecycle(a):
                continue
            if a.refund_status or a.dangerous:
                continue
            sub = a.subscribed_at
            if sub is None:
                continue
            try:
                ex = json.loads(a.extra_json) if getattr(a, "extra_json", None) else {}
            except Exception:
                ex = {}
            try:
                bound_device_id = int(ex.get("cpa_device_id") or 0)
            except (TypeError, ValueError):
                bound_device_id = 0
            if bound_device_id:
                days = device_days.get(bound_device_id)
            else:
                # Compatibility only for pre-device-id auto-pool linkage.
                days = legacy_url_days.get(ex.get("cpa_api_url"))
            if days is None:
                continue
            ts = sub.replace(tzinfo=timezone.utc).timestamp() if sub.tzinfo is None else sub.timestamp()
            if ts <= now_ts - days * 86400:
                out.append(a.id)
    return out


def _pro_with_rt_unsynced() -> list:
    """是 PRO、有 codex_refresh_token、未退款、extra.cpa_synced 不为真 的账号。"""
    import json
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session, select
    out = []
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel).where(GptProAccountModel.is_pro == True)).all()  # noqa: E712
        for a in rows:
            if _is_business_child_cpa_lifecycle(a):
                continue
            if a.refund_status or a.dangerous:
                continue
            if not (a.codex_refresh_token or "").strip():
                continue
            try:
                ex = json.loads(a.extra_json) if getattr(a, "extra_json", None) else {}
            except Exception:
                ex = {}
            if ex.get("cpa_synced"):
                continue
            if (
                ex.get("cpa_auto_upload_pending")
                or ex.get("cpa_cleanup_pending")
                or ex.get("cpa_disable_pending")
            ):
                continue
            out.append(a.id)
    return out


def _count_idle_regular() -> int:
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session, select
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel)).all()
        return sum(
            1 for a in rows
            if (not a.is_pro)
            and a.enabled
            and not a.refund_status
            and not a.dangerous
            and not _is_managed_business_child(a)
        )


def _count_cards() -> int:
    try:
        from core.db import engine, CardModel
        from sqlmodel import Session, select
        with Session(engine) as s:
            rows = s.exec(select(CardModel)).all()
            return sum(1 for c in rows if str(getattr(c, "status", "")).lower() in ("", "unused"))
    except Exception:
        return -1


def _account_extra(account_id: int) -> dict:
    import json
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    with Session(engine) as s:
        a = s.get(GptProAccountModel, account_id)
        if not a:
            return {}
        try:
            return json.loads(a.extra_json) if getattr(a, "extra_json", None) else {}
        except Exception:
            return {}


def _set_account_extra(account_id: int, patch: dict, *, remove: tuple[str, ...] = ()) -> None:
    import json
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    with Session(engine) as s:
        a = s.get(GptProAccountModel, account_id)
        if not a:
            return
        try:
            ex = json.loads(a.extra_json) if getattr(a, "extra_json", None) else {}
        except Exception:
            ex = {}
        for key in remove:
            ex.pop(key, None)
        ex.update(patch)
        a.extra_json = json.dumps(ex, ensure_ascii=False)
        a.updated_at = _now()
        s.add(a)
        s.commit()


def _set_account_extra_fenced(
    account_id: int,
    operation_token: str,
    patch: dict,
    *,
    remove: tuple[str, ...] = (),
) -> bool:
    """Merge account state only while this worker still owns the shared lease."""
    import json
    from core.db import (
        engine,
        GptProAccountModel,
        GptProAccountOperationLeaseModel,
    )
    from sqlmodel import Session

    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        account = session.get(GptProAccountModel, int(account_id))
        if session.get_bind().dialect.name == "sqlite":
            lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
        else:
            from sqlmodel import select
            lease = session.exec(
                select(GptProAccountOperationLeaseModel)
                .where(GptProAccountOperationLeaseModel.account_id == int(account_id))
                .with_for_update()
            ).first()
        if not account or not lease or lease.token != operation_token:
            return False
        expires_at = lease.expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not expires_at or expires_at <= _now():
            return False
        try:
            extra = json.loads(account.extra_json or "{}")
        except Exception:
            extra = {}
        for key in remove:
            extra.pop(key, None)
        extra.update(patch)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _now()
        session.add(account)
        session.commit()
        return True


def _account_email(account_id: int) -> str:
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    with Session(engine) as s:
        a = s.get(GptProAccountModel, account_id)
        return a.email if a else ""


_AUTO_UPLOAD_INTENT_FIELDS = (
    "cpa_auto_upload_pending",
    "cpa_auto_upload_pending_token",
    "cpa_auto_upload_pending_started_at",
    "cpa_auto_upload_pending_last_error",
)


def _clear_auto_upload_linkage_after_compensation(
    account_id: int,
    operation_token: str = "",
) -> None:
    """Clear conservative upload intent only after remote disable is confirmed."""
    patch = {
        "cpa_synced": False,
        "cpa_monitor_suppressed": True,
        "cpa_disable_pending": False,
        "cpa_lifecycle_state": "upload_compensated_disabled",
    }
    remove = (
        *_AUTO_UPLOAD_INTENT_FIELDS,
        "cpa_auth_name",
        "cpa_device_id",
        "cpa_api_url",
        "cpa_api_key",
        "cpa_config_domain",
        "cpa_disable_token",
    )
    if operation_token:
        _set_account_extra_fenced(
            account_id,
            operation_token,
            patch,
            remove=remove,
        )
    else:
        _set_account_extra(account_id, patch, remove=remove)


def _claim_manager_account_operation(account_id: int, operation: str) -> tuple[str, str]:
    """Claim the same durable lease table using the manager's dynamic engine."""
    from core.db import (
        engine,
        GptProAccountModel,
        GptProAccountOperationLeaseModel,
    )
    from sqlmodel import Session

    token = uuid.uuid4().hex
    now = _now()
    with Session(engine) as session:
        is_sqlite = session.get_bind().dialect.name == "sqlite"
        if is_sqlite:
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        if not session.get(GptProAccountModel, int(account_id)):
            return "", "账号不存在"
        if is_sqlite:
            current = session.get(GptProAccountOperationLeaseModel, int(account_id))
        else:
            from sqlmodel import select
            current = session.exec(
                select(GptProAccountOperationLeaseModel)
                .where(GptProAccountOperationLeaseModel.account_id == int(account_id))
                .with_for_update()
            ).first()
        if current:
            expires_at = current.expires_at
            if expires_at and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at and expires_at > now:
                return "", f"账号正在执行 {current.operation}，已被占用"
            session.delete(current)
            session.flush()
        session.add(GptProAccountOperationLeaseModel(
            account_id=int(account_id),
            operation=operation,
            token=token,
            expires_at=now + timedelta(hours=24),
            created_at=now,
            updated_at=now,
        ))
        try:
            session.commit()
        except Exception:
            session.rollback()
            return "", "账号刚被其他操作占用"
    return token, ""


def _manager_operation_token_is_current(account_id: int, token: str) -> bool:
    from core.db import (
        engine,
        GptProAccountOperationLeaseModel,
    )
    from sqlmodel import Session

    if not token:
        return False
    with Session(engine) as session:
        current = session.get(GptProAccountOperationLeaseModel, int(account_id))
        if not current or current.token != token:
            return False
        expires_at = current.expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return bool(expires_at and expires_at > _now())


def _release_manager_account_operation(account_id: int, token: str) -> None:
    from core.db import (
        engine,
        GptProAccountOperationLeaseModel,
    )
    from sqlalchemy import delete
    from sqlmodel import Session

    if not token:
        return
    with Session(engine) as session:
        session.execute(
            delete(GptProAccountOperationLeaseModel)
            .where(GptProAccountOperationLeaseModel.account_id == int(account_id))
            .where(GptProAccountOperationLeaseModel.token == token)
        )
        session.commit()


def _upload_account_to_cpa(
    account_id: int,
    api_url: str,
    api_key: str,
    device_id: int = 0,
    *,
    expected_business_parent_id: Optional[int] = None,
    persist_account_linkage: bool = True,
    operation_token: str = "",
    before_remote_mutation=None,
    credential_bundle: Optional[dict[str, str]] = None,
) -> tuple[bool, str]:
    """上传凭证，并在网络请求前后校验账号归属。

    自动 GPT PRO 号池编排不传 ``expected_business_parent_id``，并保留自己
    独立配置域所需的账号级 endpoint linkage。GPT PRO/BUSINESS 页面的手动
    同步传 ``persist_account_linkage=False``：上传器只做远端写入，最终 linkage
    由共享 ``/gpt-pro/cpa-sync-targets`` 编排层原子切换，绝不复制 API key。

    BUSINESS 代理调用必须传准确母号。若上传期间归属发生变化，新文件会被
    best-effort 停用且不会落本地 active 标记。

    手动/Business 编排传入已严格持久化的 ``credential_bundle``，上传器不会
    再刷新一次 RT；自动号池未传 bundle 时则在自身账号租约下刷新一次。
    """
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    from platforms.chatgpt.cpa_upload import upload_to_cpa
    from api.gpt_pro import (
        _cpa_health_failure_reason,
        _disable_cpa_email_at_endpoint,
        _disable_exact_cpa_auth_name,
        _gpt_pro_resolve_codex_credentials,
        _probe_uploaded_cpa_credential,
    )

    owned_operation_token = ""
    if not operation_token:
        owned_operation_token, claim_error = _claim_manager_account_operation(
            account_id,
            "cpa_auto_upload",
        )
        if not owned_operation_token:
            return False, f"账号被其他操作占用，拒绝 CPA 上传: {claim_error}"
        operation_token = owned_operation_token

    def _scope_matches(account) -> bool:
        if (
            not account
            or not bool(account.enabled)
            or bool(account.dangerous)
            or bool(str(getattr(account, "refund_status", "") or "").strip())
        ):
            return False
        parent_id = getattr(account, "business_parent_id", None)
        if expected_business_parent_id is None:
            if parent_id is not None:
                return False
            if persist_account_linkage and not bool(getattr(account, "is_pro", False)):
                return False
            if persist_account_linkage and _is_business_child_cpa_lifecycle(account):
                return False
            try:
                import json
                state = json.loads(getattr(account, "extra_json", "") or "{}")
            except Exception:
                state = {}
            if persist_account_linkage and (
                state.get("cpa_cleanup_pending")
                or state.get("cpa_disable_pending")
                or (
                    state.get("cpa_auto_upload_pending")
                    and str(state.get("cpa_auto_upload_pending_token") or "")
                    != operation_token
                )
            ):
                return False
            return True
        return parent_id == int(expected_business_parent_id)

    def _lease_current() -> bool:
        return _manager_operation_token_is_current(account_id, operation_token)

    def _persist_uploaded_pending(email: str, fname: str, reason: str) -> bool:
        patch = {
            "cpa_synced": True,
            "cpa_auth_name": fname,
            "cpa_device_id": int(device_id or 0),
            "cpa_api_url": api_url,
            "cpa_config_domain": "auto_pool",
            "cpa_synced_at": _now().isoformat(),
            "cpa_lifecycle_state": "upload_compensation_pending",
            "cpa_monitor_suppressed": True,
            "cpa_disable_pending": True,
            "cpa_disable_reason": str(reason or "CPA 上传后安全状态变化")[:500],
            "cpa_disable_requested_at": _now().isoformat(),
            "cpa_disable_last_error": "",
        }
        if not int(device_id or 0):
            # Only legacy endpoint-only linkage keeps a copied key.
            patch["cpa_api_key"] = api_key
        return _set_account_extra_fenced(
            account_id,
            operation_token,
            patch,
            remove=("cpa_api_key",) if int(device_id or 0) else (),
        )

    try:
        if persist_account_linkage and int(device_id or 0):
            current_url, current_key = _auto_pool_endpoint_by_device_id(device_id)
            if not current_url:
                return False, f"CPA 自动号池设备 {device_id} 已不存在，拒绝上传"
            api_url, api_key = current_url, current_key
        if not _lease_current():
            return False, "CPA 上传操作租约已失效"
        with Session(engine) as s:
            a = s.get(GptProAccountModel, account_id)
            if not a:
                return False, "账号不存在"
            if not _scope_matches(a):
                return False, "账号 PRO/退款/BUSINESS 归属或安全状态已变化，拒绝上传 CPA"
            email = a.email
            if not str(a.codex_refresh_token or "").strip():
                return False, "账号缺少 refresh_token，请先补 RT 后再上传"
            account_for_refresh = a

        resolved_chatgpt_account_id = ""
        if credential_bundle is None:
            # Auto-pool callers enter through this low-level uploader directly.
            # Refresh exactly once while the shared account lease is held, and
            # require any rotated RT to be durable before writing a CPA file.
            try:
                resolved_access_token, resolved_chatgpt_account_id = (
                    _gpt_pro_resolve_codex_credentials(
                        account_for_refresh,
                        _require_persist=True,
                    )
                )
            except Exception as exc:
                detail = str(getattr(exc, "detail", "") or "").lower()
                if "持久化" in detail:
                    safe_reason = "OAuth 凭证持久化失败"
                elif any(marker in detail for marker in (
                    "invalid_grant",
                    "refresh_token_reused",
                    "refresh_token_invalidated",
                    "session has ended",
                )):
                    safe_reason = "refresh_token 已失效，需要重新获取 OAuth"
                elif any(marker in detail for marker in (
                    "timeout", "timed out", "proxy", "connection",
                )):
                    safe_reason = "OAuth 刷新网络异常"
                else:
                    safe_reason = "OAuth access_token 刷新失败"
                return False, f"CPA 上传前 {safe_reason}"
            if not _lease_current():
                return False, "CPA 上传操作租约在 OAuth 刷新后已失效"
            with Session(engine) as s:
                refreshed = s.get(GptProAccountModel, account_id)
                if not _scope_matches(refreshed):
                    return False, "账号在 OAuth 刷新后安全状态已变化，拒绝上传 CPA"
                refreshed_rt = str(refreshed.codex_refresh_token or "").strip()
            token = {
                "type": "codex",
                "access_token": str(resolved_access_token or "").strip(),
                "refresh_token": refreshed_rt,
                "email": email,
            }
        else:
            # Manual/Business orchestration already refreshed under the same
            # lease and passes that one immutable bundle to avoid RT reuse from
            # a second refresh inside the uploader.
            token = {
                "type": "codex",
                "access_token": str(
                    credential_bundle.get("access_token") or ""
                ).strip(),
                "refresh_token": str(
                    credential_bundle.get("refresh_token") or ""
                ).strip(),
                "email": email,
            }
            resolved_chatgpt_account_id = str(
                credential_bundle.get("chatgpt_account_id") or ""
            ).strip()
        if not token["access_token"]:
            return False, "账号缺少刚刷新的 access_token，拒绝上传 CPA"
        if not token["refresh_token"]:
            return False, "账号缺少 refresh_token，请先补 RT 后再上传"
        # 分配 CPA 专用代理并写入 proxy_url(仅写文件, 不做实际请求)。无可用代理则不写。
        try:
            from services.cpa_proxy_pool import assign_proxy
            proxy_url = assign_proxy(account_id)
            if proxy_url:
                token["proxy_url"] = proxy_url
        except Exception as _pe:
            _log(f"分配 CPA 代理失败(忽略, 不写 proxy_url): {_pe}", "warn", email)
        if not _lease_current():
            return False, "CPA 上传操作租约在远端写入前已失效"
        with Session(engine) as s:
            if not _scope_matches(s.get(GptProAccountModel, account_id)):
                return False, "账号在远端写入前安全状态已变化，拒绝上传 CPA"

        fname = f"{email}.json"
        if persist_account_linkage:
            # Intent-before-upload makes a timeout/process crash recoverable.
            # The hourly CPA refresh treats this as a disable/reconcile job.
            intent_written = _set_account_extra_fenced(account_id, operation_token, {
                "cpa_auto_upload_pending": True,
                "cpa_auto_upload_pending_token": operation_token,
                "cpa_auto_upload_pending_started_at": _now().isoformat(),
                "cpa_auto_upload_pending_last_error": "",
                "cpa_auth_name": fname,
                "cpa_device_id": int(device_id or 0),
                "cpa_api_url": api_url,
                "cpa_config_domain": "auto_pool",
                "cpa_monitor_suppressed": True,
            }, remove=("cpa_api_key",) if int(device_id or 0) else ())
            if not intent_written or not _lease_current():
                return False, "CPA 上传 intent 写入后租约失效；已保留 pending"
        try:
            if before_remote_mutation is not None:
                guarded = before_remote_mutation()
                if guarded is False:
                    return False, "CPA delivery guard 拒绝远端上传"
            ok, msg = upload_to_cpa(
                token,
                api_url=api_url,
                api_key=api_key,
                filename=fname,
            )
        except Exception as exc:
            if persist_account_linkage and _lease_current():
                _set_account_extra_fenced(account_id, operation_token, {
                    "cpa_auto_upload_pending_last_error": str(exc)[:500],
                })
            return False, f"CPA 上传结果未知，已保留 pending: {exc}"
        if not ok:
            if persist_account_linkage and _lease_current():
                _set_account_extra_fenced(
                    account_id,
                    operation_token,
                    {"cpa_auto_upload_pending_last_error": str(msg or "上传失败")[:500]},
                )
            suffix = "；已保留 pending 等待远端核对" if persist_account_linkage else ""
            return False, f"{msg}{suffix}"

        if persist_account_linkage:
            probe = _probe_uploaded_cpa_credential(
                auth_name=fname,
                chatgpt_account_id=resolved_chatgpt_account_id,
                api_url=api_url,
                api_key=api_key,
            )
            if not bool(probe.get("ok")):
                reason = _cpa_health_failure_reason(probe)
                if not _persist_uploaded_pending(email, fname, reason):
                    return False, (
                        reason
                        + "；CPA 已上传但补偿 intent 写入失败，保留原上传 pending 等待核对"
                    )
                disabled = _disable_exact_cpa_auth_name(
                    fname,
                    api_url,
                    api_key,
                    before_request=_lease_current,
                )
                if disabled.get("ok"):
                    _set_account_extra_fenced(account_id, operation_token, {
                        "cpa_disabled": True,
                        "cpa_disabled_at": _now().isoformat(),
                        "cpa_disabled_reason": reason,
                        "cpa_disable_pending": False,
                        "cpa_disable_last_error": "",
                        "cpa_lifecycle_state": "upload_compensated_disabled",
                    })
                    _clear_auto_upload_linkage_after_compensation(
                        account_id,
                        operation_token,
                    )
                    return False, reason + "；已确认精确停用刚上传的无效凭据"
                _set_account_extra_fenced(account_id, operation_token, {
                    "cpa_disable_pending": True,
                    "cpa_disable_last_attempt_at": _now().isoformat(),
                    "cpa_disable_last_error": str(
                        disabled.get("error") or "精确停用未确认"
                    )[:500],
                    "cpa_lifecycle_state": "upload_compensation_pending",
                })
                return False, reason + "；精确停用未确认，已保留 pending 等待重试"

        # A caller-supplied mutation guard means the caller owns the durable
        # post-upload fence/compensation protocol.  Once the POST succeeded we
        # must report that fact even if its lease changed during the request;
        # otherwise the caller cannot persist and run exact compensation.
        delegated_delivery_fence = bool(
            before_remote_mutation is not None and not persist_account_linkage
        )
        endpoint_still_current = True
        still_matches = True
        lease_still_current = True
        if not delegated_delivery_fence:
            if persist_account_linkage and int(device_id or 0):
                current_url, _current_key = _auto_pool_endpoint_by_device_id(device_id)
                endpoint_still_current = bool(
                    current_url
                    and current_url.rstrip("/").lower() == api_url.rstrip("/").lower()
                )
            with Session(engine) as s:
                current = s.get(GptProAccountModel, account_id)
                still_matches = _scope_matches(current)
            lease_still_current = _lease_current()
        if not still_matches or not lease_still_current or not endpoint_still_current:
            reason = (
                "上传期间账号 PRO/退款/BUSINESS 安全状态、操作租约或设备配置发生变化"
            )
            if not lease_still_current:
                return False, f"{reason}；已由预写 intent 保留待清理"
            if not _persist_uploaded_pending(email, fname, reason):
                return False, f"{reason}；旧 worker 已被 fencing，预写 intent 保留待清理"
            try:
                result = _disable_cpa_email_at_endpoint(
                    email,
                    api_url,
                    api_key,
                    before_mutation=_lease_current,
                )
                if result.get("ok"):
                    _set_account_extra_fenced(account_id, operation_token, {
                        "cpa_disabled": True,
                        "cpa_disabled_at": _now().isoformat(),
                        "cpa_disabled_reason": reason,
                        "cpa_disable_pending": False,
                        "cpa_disable_last_error": "",
                        "cpa_lifecycle_state": "upload_compensated_disabled",
                    })
                    _clear_auto_upload_linkage_after_compensation(
                        account_id,
                        operation_token,
                    )
                else:
                    _set_account_extra_fenced(account_id, operation_token, {
                        "cpa_disable_pending": True,
                        "cpa_disable_last_attempt_at": _now().isoformat(),
                        "cpa_disable_last_error": str(result.get("error") or reason)[:500],
                    })
            except Exception as exc:
                _set_account_extra_fenced(account_id, operation_token, {
                    "cpa_disable_pending": True,
                    "cpa_disable_last_attempt_at": _now().isoformat(),
                    "cpa_disable_last_error": str(exc)[:500],
                })
                _log(f"上传后补偿停用失败，已保留 pending: {exc}", "warn", email, False)
            return False, f"{reason}；凭据已进入停用补偿流程"
        if persist_account_linkage:
            patch = {
                "cpa_synced": True, "cpa_auth_name": fname,
                "cpa_device_id": int(device_id or 0),
                "cpa_api_url": api_url,
                "cpa_config_domain": "auto_pool",
                "cpa_synced_at": _now().isoformat(),
                # 自动管理器上传的是 GPT PRO 生命周期。若这个普通号曾经是
                # BUSINESS 子号，此处显式清掉遗留 stale 标记后才可恢复 PRO 编排。
                "cpa_account_kind": "gpt_pro",
                "cpa_business_parent_id": None,
                "cpa_business_membership_stale": False,
                # 重新同步代表账号再次进入 active 生命周期；覆盖之前
                # “子号释放/额度用满”留下的本地停用标记。
                "cpa_lifecycle_state": "active",
                "cpa_monitor_suppressed": False,
                "cpa_disabled": False,
                "cpa_disabled_at": "",
                "cpa_disabled_reason": "",
                "cpa_disable_pending": False,
                "cpa_disable_reason": "",
                "cpa_disable_requested_at": "",
                "cpa_disable_last_attempt_at": "",
                "cpa_disable_last_error": "",
                "cpa_disable_attempts": 0,
                "cpa_monitor_alert": None,
            }
            if not int(device_id or 0):
                patch["cpa_api_key"] = api_key
            finalized = _set_account_extra_fenced(
                account_id,
                operation_token,
                patch,
                remove=(
                    "cpa_api_key",
                    "cpa_auto_upload_pending",
                    "cpa_auto_upload_pending_token",
                    "cpa_auto_upload_pending_started_at",
                    "cpa_auto_upload_pending_last_error",
                    "cpa_rotation_ready_at",
                    "cpa_rotation_reason",
                ) if int(device_id or 0) else (
                    "cpa_auto_upload_pending",
                    "cpa_auto_upload_pending_token",
                    "cpa_auto_upload_pending_started_at",
                    "cpa_auto_upload_pending_last_error",
                    "cpa_rotation_ready_at",
                    "cpa_rotation_reason",
                ),
            )
            if not finalized:
                return False, "CPA 已上传但 linkage fencing 失败；预写 intent 保留待清理"
        return True, msg
    finally:
        if owned_operation_token:
            _release_manager_account_operation(account_id, owned_operation_token)


def _delete_account_files_by_email(
    email: str,
    endpoints: list,
    *,
    before_mutation=None,
) -> int:
    """Delete all exact email/name variants and confirm remote absence.

    Listing, deletion, and the confirmation listing are a single safety
    contract: any uncertainty raises so callers preserve durable linkage.
    """
    import re
    from services.cpa_manager import list_auth_files, delete_auth_files
    el = str(email or "").strip().lower()
    if not el:
        return 0
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", el).lower()

    def _matches(item: dict) -> bool:
        field_email = str(
            item.get("email") or item.get("account") or ""
        ).strip().lower()
        if field_email:
            return field_email == el
        name = str(item.get("name") or "").strip().lower()
        stem = name[:-5] if name.endswith(".json") else name
        if not stem:
            return False
        for candidate in {el, safe}:
            if stem == candidate:
                return True
            if stem.endswith(candidate):
                prefix = stem[:-len(candidate)]
                # Supported variants are provider/type prefixes such as
                # ``oauth_<safe-email>``.  Requiring a delimiter avoids a
                # suffix collision like ``notvictim@example.com``.
                if prefix.endswith(("_", "-")):
                    return True
        return False

    total = 0
    for url, key in endpoints:
        if not url:
            continue
        try:
            files = list_auth_files(api_url=url, api_key=key)
        except Exception as exc:
            raise RuntimeError(f"CPA 凭据列表读取失败 {url}: {exc}") from exc
        names = sorted({
            str(item.get("name"))
            for item in files
            if _matches(item) and item.get("name")
        })
        if names:
            if before_mutation is not None and not bool(before_mutation()):
                raise RuntimeError("CPA 删除操作租约已失效")
            try:
                delete_auth_files(names, api_url=url, api_key=key)
            except Exception as exc:
                raise RuntimeError(f"CPA 凭据删除失败 {names}@{url}: {exc}") from exc
            total += len(names)
        try:
            confirmed = list_auth_files(api_url=url, api_key=key)
        except Exception as exc:
            raise RuntimeError(f"CPA 删除后确认失败 {url}: {exc}") from exc
        remaining = [
            str(item.get("name") or "")
            for item in confirmed
            if _matches(item)
        ]
        if remaining:
            raise RuntimeError(
                f"CPA 删除后仍存在 {el} 的凭据: {remaining[:5]}"
            )
    return total


def _refund_and_remove(account_id: int) -> tuple[bool, str]:
    """退款 + 从该账号所属的那台 CPA 设备删除其凭证(按邮箱删全部文件变体)。"""
    # 防御性二次校验：即使旧自动退款任务已经入队，子号后来
    # 被分配到 BUSINESS 后也绝不能真正执行 PRO 退款。
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    with Session(engine) as s:
        account = s.get(GptProAccountModel, account_id)
        if account and _is_business_child_cpa_lifecycle(account):
            parent_id = getattr(account, "business_parent_id", None)
            return False, (
                f"BUSINESS 子号 CPA 生命周期(母号 {parent_id or '-'})"
                "禁止 GPT PRO 自动退款"
            )
    from api.gpt_pro import refund_account, GptProActionRequest
    try:
        res = refund_account(account_id, GptProActionRequest())
    except Exception as exc:
        return False, f"退款调用异常: {exc}"
    ar = (res or {}).get("login", {}) if isinstance(res, dict) else {}
    success = bool((res or {}).get("refund_success") or (isinstance(ar, dict) and ar.get("action_result", {}).get("refund_success")))
    if not success:
        return False, f"退款未成功: stage={(res or {}).get('stage')}"
    ex = _account_extra(account_id)
    if ex.get("cpa_cleanup_pending"):
        return True, "已退款；CPA 凭据清理待整点任务重试"
    # ``refund_account`` owns the refund lease and invokes the one canonical
    # cleanup helper before it returns.  Never issue a second cross-domain
    # deletion here, and never turn a completed refund into a refund retry.
    return True, "已退款；CPA 凭据清理已完成或无需清理"


def dedupe_pool() -> dict[str, Any]:
    """每台设备内同一邮箱的多份 auth-file 只保留一份,其余删除。
    保留优先级:未停用 > 文件名为 {email}.json。"""
    from collections import defaultdict
    from services.cpa_manager import list_auth_files, delete_auth_files
    cfg = get_config()
    summary: dict[str, Any] = {"checked": 0, "duplicated": 0, "removed": 0, "errors": []}
    seen = set()
    for d in cfg["devices"]:
        url, key = d["api_url"], d["api_key"]
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            files = list_auth_files(api_url=url, api_key=key)
        except Exception as exc:
            summary["errors"].append(f"{url}: {exc}")
            continue
        groups = defaultdict(list)
        for f in files:
            em = (f.get("email") or f.get("name") or "").lower()
            if em:
                groups[em].append(f)
        del_names = []
        for em, fs in groups.items():
            summary["checked"] += 1
            if len(fs) <= 1:
                continue
            summary["duplicated"] += 1

            def _score(f):
                name = (f.get("name") or "").lower()
                return (0 if f.get("disabled") else 1, 1 if name == f"{em}.json" else 0)

            fs_sorted = sorted(fs, key=_score, reverse=True)
            for f in fs_sorted[1:]:
                if f.get("name"):
                    del_names.append(f["name"])
        if del_names:
            try:
                delete_auth_files(del_names, api_url=url, api_key=key)
                summary["removed"] += len(del_names)
                _log(f"去重: {url} 删除 {len(del_names)} 份重复凭证", "dedupe", ok=True)
            except Exception as exc:
                summary["errors"].append(f"{url} delete: {exc}")
    try:
        get_cpa_accounts(force=True)
    except Exception:
        pass
    summary["ok"] = True
    return summary


def get_status() -> dict[str, Any]:
    cfg = get_config()
    devices_status = []
    agg_total = 0
    agg_healthy = 0
    errors = []
    for d in cfg["devices"]:
        tot = heal = None
        err = ""
        if d["api_url"]:
            try:
                tot, heal = _cpa_counts(d["api_url"], d["api_key"])
                agg_total += tot
                agg_healthy += heal
            except Exception as exc:
                err = str(exc)
                errors.append(f"{d['name'] or d['device_id']}: {exc}")
        devices_status.append({
            "device_id": d["device_id"], "name": d["name"], "threshold": d["threshold"],
            "total": tot, "healthy": heal, "error": err,
        })
    return {
        "config": cfg,
        "running": _RUNNING,
        "devices": devices_status,
        "pool_total": agg_total if cfg["devices"] else None,
        "pool_healthy": agg_healthy if cfg["devices"] else None,
        "threshold_total": cfg["threshold_total"],
        "pool_error": "; ".join(errors),
        "to_recycle": len(_overdue_pro([d for d in cfg["devices"] if d.get("refund_enabled")])),
        "pro_unsynced": len(_pro_with_rt_unsynced()),
        "idle_regular": _count_idle_regular(),
        "cards_available": _count_cards(),
        "last_run": _LAST_RUN,
        "log": list(_LOG)[:50],
    }


def recycle_once(manual: bool = False) -> dict[str, Any]:
    """退款回收:按各设备退款天数,把到期 PRO 退款并从所属 CPA 删凭证。每天定时一次。"""
    global _RUNNING
    cfg = get_config()
    devices = [d for d in cfg["devices"] if d.get("refund_enabled")]
    if not devices and not manual:
        return {"ok": False, "reason": "no_refund_devices"}
    if not _LOCK.acquire(blocking=False):
        return {"ok": False, "reason": "running"}
    _RUNNING = True
    started = _now().isoformat()
    summary = {"recycled": 0, "failed": 0, "started_at": started}
    try:
        if not devices:
            _log("没有启用退款的 CPA 设备, 跳过", "warn")
            summary["error"] = "no_refund_devices"
            return {"ok": False, **summary}
        cap = cfg["max_per_run"]
        # 严格按"订阅满 refund_days 天"判断, 从各自所属设备删凭证。
        # 绝不按 error/限流状态删号:error 多是 5h 额度用满会自动恢复, 删了就白亏。
        for aid in _overdue_pro(devices)[:cap]:
            _log("订阅到期, 开始退款回收", "recycle", account=str(aid))
            ok, msg = _refund_and_remove(aid)
            _log(msg, "recycle", account=str(aid), ok=ok)
            summary["recycled" if ok else "failed"] += 1
        _log(f"退款完成: 回收 {summary['recycled']}, 失败 {summary['failed']}", "done")
        summary["ok"] = True
        return {"ok": True, **summary}
    except Exception as exc:
        _log(f"退款异常: {exc}", "error")
        summary["error"] = str(exc)
        return {"ok": False, **summary}
    finally:
        summary["finished_at"] = _now().isoformat()
        _LAST_RUN.clear()
        _LAST_RUN.update(summary)
        _RUNNING = False
        _LOCK.release()


def replenish_once(manual: bool = False) -> dict[str, Any]:
    """补充:逐设备补到各自阈值(存活数: token 有效含限流, 死号才算缺);含「救急重置」层。"""
    global _RUNNING
    cfg = get_config()
    devices = [d for d in cfg["devices"] if d.get("replenish_enabled")]
    if not devices and not manual:
        return {"ok": False, "reason": "no_replenish_devices"}
    if not _LOCK.acquire(blocking=False):
        return {"ok": False, "reason": "running"}
    _RUNNING = True
    started = _now().isoformat()
    summary = {"uploaded": 0, "bought": 0, "rescued": 0, "failed": 0, "started_at": started}
    try:
        if not devices:
            _log("没有启用补充的 CPA 设备, 跳过", "warn")
            summary["error"] = "no_replenish_devices"
            return {"ok": False, **summary}
        cap = cfg["max_per_run"]
        try:
            acct = get_cpa_accounts(force=True)
        except Exception as exc:
            acct = {"accounts": []}
            _log(f"查账号列表失败: {exc}", "warn")
        for d in devices:
            did, url, key, thr = d["device_id"], d["api_url"], d["api_key"], d["threshold"]
            if not url:
                continue
            dev_accts = [a for a in acct.get("accounts", []) if a.get("device_url") == url]
            present_emails = {(a.get("email") or "").lower() for a in dev_accts}
            alive = sum(1 for a in dev_accts if a.get("reachable"))
            tag = d["name"] or url
            # 上传未同步的 PRO+RT 账号到这台设备
            for aid in _pro_with_rt_unsynced():
                if alive >= thr or summary["uploaded"] >= cap:
                    break
                email_aid = _account_email(aid)
                # 该号其实已在这台 CPA 上(本地同步标记丢失)→ 补回标记,不重复上传
                if email_aid and email_aid.lower() in present_emails:
                    linkage = {
                        "cpa_synced": True, "cpa_auth_name": f"{email_aid}.json",
                        "cpa_device_id": int(did or 0), "cpa_api_url": url,
                        "cpa_config_domain": "auto_pool",
                    }
                    if not int(did or 0):
                        linkage["cpa_api_key"] = key
                    _set_account_extra(
                        aid,
                        linkage,
                        remove=("cpa_api_key",) if int(did or 0) else (),
                    )
                    _log(f"[{tag}] 已在该设备,补标记跳过", "skip", account=str(aid), ok=True)
                    continue
                ok, msg = _upload_account_to_cpa(aid, url, key, did)
                _log(f"[{tag}] {msg}", "upload", account=str(aid), ok=ok)
                if ok:
                    summary["uploaded"] += 1
                    alive += 1
                else:
                    summary["failed"] += 1
            # 仍不足 → 自动买号补这台(按该设备自己的自动买号开关)
            if alive < thr and d["auto_buy"]:
                budget = min(thr - alive, cap)
                _log(f"[{tag}] 缺 {thr - alive} 个, 自动买号(本轮最多 {budget})", "buy")
                for _ in range(budget):
                    if _buy_one(url, key, device_id=did, log_fn=_log):
                        summary["bought"] += 1
                        alive += 1
                    else:
                        summary["failed"] += 1
                        break
            elif alive < thr:
                _log(f"[{tag}] 缺 {thr - alive} 个, 未开自动买号", "warn")
            # 救急层:只剩 1 个存活号且其 5h 额度已用满一半 → 重置一个到期号续命
            try:
                _maybe_rescue(d, dev_accts, alive, summary, tag)
            except Exception as exc:
                _log(f"[{tag}] 救急异常: {exc}", "warn")

        _log(f"补充完成: 上传 {summary['uploaded']}, 买号 {summary['bought']}, 救急 {summary['rescued']}, 失败 {summary['failed']}", "done")
        summary["ok"] = True
        return {"ok": True, **summary}
    except Exception as exc:
        _log(f"补充异常: {exc}", "error")
        summary["error"] = str(exc)
        return {"ok": False, **summary}
    finally:
        summary["finished_at"] = _now().isoformat()
        _LAST_RUN.clear()
        _LAST_RUN.update(summary)
        _RUNNING = False
        _LOCK.release()


def maintain_once(manual: bool = False) -> dict[str, Any]:
    """手动「退款+补充」一起跑(供旧入口/一键维护用)。"""
    r = recycle_once(manual=manual)
    p = replenish_once(manual=manual)
    out = {"ok": bool(r.get("ok") or p.get("ok"))}
    out.update({k: v for k, v in r.items() if k not in ("ok",)})
    out.update({k: v for k, v in p.items() if k not in ("ok",)})
    return out


def _account_referral_remaining(account_id: int):
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session
    with Session(engine) as s:
        a = s.get(GptProAccountModel, account_id)
        return a.referral_remaining if a else 0


def _referral_cf_domain() -> str:
    """复用「一键批量重置」的 CF 邀请域名清单,取默认(第一个)。"""
    try:
        from api.gpt_pro import _load_cf_domains
        domains = _load_cf_domains()
        return domains[0] if domains else ""
    except Exception:
        return ""


def _run_referral_reset(account_id: int, cf_domain: str, browser_mode: str = "headless") -> bool:
    """对单个账号同步跑一次推荐邀请「重置」流程(复用一键批量重置的核心)。成功 True。"""
    try:
        from api.gpt_pro import _do_invite_auto, GptProReferralInviteAutoRequest
    except Exception as exc:
        _log(f"救急: 导入重置流程失败 {exc}", "error")
        return False
    body = GptProReferralInviteAutoRequest(cf_domain=cf_domain, browser_mode=browser_mode)
    task_id = f"cpa-rescue-{account_id}-{int(time.time())}"

    def _rlog(m):
        _log(str(m), "rescue", account=str(account_id))

    try:
        _do_invite_auto(task_id, account_id, body, _rlog)
        return True
    except Exception as exc:
        _log(f"救急: 重置失败 {exc}", "rescue", account=str(account_id), ok=False)
        return False


def _maybe_rescue(d: dict, dev_accts: list, alive: int, summary: dict, tag: str) -> None:
    """只剩 1 个存活号且其 5h 已用 ≥ 50% 时:随机挑一个本设备「到期需退款」且还有重置次数的号,
    跑重置(推荐邀请)续命,成功后调 CPA reset-quota 解除冷却,再刷新列表。"""
    if alive != 1:
        return
    alive_accts = [a for a in dev_accts if a.get("reachable")]
    if len(alive_accts) != 1:
        return
    # 5h 或 周 任一窗口用满一半即视为有压力(取较大者)
    used = max(int(alive_accts[0].get("usage_5h_percent") or 0),
               int(alive_accts[0].get("usage_week_percent") or 0))
    if used < 50:  # 两个窗口都还剩 > 50%,不救急
        return
    overdue_ids = _overdue_pro([d])  # 本设备到期需退款的号
    if not overdue_ids:
        _log(f"[{tag}] 救急: 无到期可重置账号", "rescue")
        return
    cf_domain = _referral_cf_domain()
    if not cf_domain:
        _log(f"[{tag}] 救急: 未配置 CF 邀请域名, 跳过", "warn")
        return
    email_to_auth = {(a.get("email") or "").lower(): a.get("auth_index") for a in dev_accts}
    url, key = d["api_url"], d["api_key"]
    import random
    random.shuffle(overdue_ids)
    for aid in overdue_ids:
        rem = _account_referral_remaining(aid)
        if rem == 0:  # 没重置机会了 → 换下一个
            continue
        email_aid = _account_email(aid)
        _log(f"[{tag}] 救急: 重置 {email_aid} (剩余邀请={rem})", "rescue", account=str(aid))
        if not _run_referral_reset(aid, cf_domain):
            summary["failed"] += 1
            continue
        auth_index = email_to_auth.get((email_aid or "").lower())
        if auth_index is not None:
            try:
                from services.cpa_manager import reset_quota
                reset_quota(auth_index, api_url=url, api_key=key)
                _log(f"[{tag}] 救急: 已重置 CPA 冷却 (auth_index={auth_index})", "rescue", account=str(aid), ok=True)
            except Exception as exc:
                _log(f"[{tag}] 救急: reset-quota 失败 {exc}", "warn")
        summary["rescued"] += 1
        try:
            get_cpa_accounts(force=True)
        except Exception:
            pass
        break


def _poll_status(getter, key: str, success_set: set, fail_set: set, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st = getter() or {}
        except Exception:
            return False
        v = str(st.get(key, "")).strip().lower()
        if v in success_set:
            return True
        if v in fail_set:
            return False
        time.sleep(5)
    return False


def _pick_idle_regular_id() -> Optional[int]:
    from core.db import engine, GptProAccountModel
    from sqlmodel import Session, select
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel)).all()
        for a in rows:
            if ((not a.is_pro)
                    and a.enabled
                    and not a.refund_status
                    and not a.dangerous
                    and not _is_managed_business_child(a)):
                return a.id
    return None


def _buy_one(api_url: str, api_key: str, *, device_id: int = 0, log_fn=_log) -> bool:
    """升级一个空闲普通号补凭证: 升级(自动选卡)→ 取 codex RT → 上传到指定 CPA 设备。
    卡的 6 次上限 / 失败关卡 / 自动换卡均由升级层自动处理。返回是否最终上传成功。"""
    from api.gpt_pro import (
        upgrade_pro_account, upgrade_pro_status, oauth_account, oauth_account_status,
        GptProActionRequest,
    )
    aid = _pick_idle_regular_id()
    if not aid:
        log_fn("无空闲普通号可买", "buy")
        return False
    log_fn("开始升级买号(自动选卡)", "buy", account=str(aid))
    try:
        res = upgrade_pro_account(aid, GptProActionRequest(auto_pick_seconds=5))
    except Exception as exc:
        log_fn(f"升级调用异常: {exc}", "buy", account=str(aid), ok=False)
        return False
    if not res.get("ok"):
        log_fn(f"升级未启动: {res.get('stage')} {res.get('error', '')}", "buy", account=str(aid), ok=False)
        return False
    task_id = res.get("task_id")
    ok_sub = _poll_status(
        lambda: upgrade_pro_status(aid, task_id), "stage",
        {"success"}, {"failed", "timeout", "cancelled"}, timeout=480,
    )
    if not ok_sub:
        log_fn("升级失败/超时(卡已按规则处理, 自动换卡下轮再试)", "buy", account=str(aid), ok=False)
        return False
    log_fn("升级成功, 取 codex RT", "buy", account=str(aid), ok=True)
    try:
        o = oauth_account(aid, GptProActionRequest())
        otid = o.get("task_id")
        if otid:
            _poll_status(
                lambda: oauth_account_status(aid, otid, 0), "status",
                {"success", "done", "finished"}, {"failed", "error", "timeout"}, timeout=420,
            )
    except Exception as exc:
        log_fn(f"取 codex RT 异常(继续尝试上传): {exc}", "buy", account=str(aid))
    ok2, msg = _upload_account_to_cpa(aid, api_url, api_key, device_id)
    log_fn(f"上传 CPA: {msg}", "upload", account=str(aid), ok=ok2)
    return ok2


_ACCT_CACHE: dict = {"at": 0.0, "data": None}
_ACCT_CACHE_TTL = 900  # 15 分钟(用量查询不频繁)
_USAGE_CACHE: dict = {}  # email -> 上次 wham/usage 结果(含 reset_at), 用于"已知限流到 reset 前不再查"


def _usage_history_path() -> str:
    import os
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "cpa_usage_history.json")


def _load_history() -> dict:
    import json
    try:
        with open(_usage_history_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_history(hist: dict) -> None:
    import json
    try:
        with open(_usage_history_path(), "w", encoding="utf-8") as f:
            json.dump(hist, f, ensure_ascii=False)
    except Exception:
        pass


def _usage_delta(snaps: list, now: float, window: float, cur_success: int):
    """滚动窗口用量 = 现在累计 - window 秒前的累计(快照不足时用最早快照,偏少但不报错)。"""
    target = now - window
    base = None
    for ts, succ, _fail in snaps:
        if ts <= target:
            base = succ
    if base is None:
        base = snaps[0][1] if snaps else cur_success
    return max(0, cur_success - base)


_USAGE_PROBE_LOCAL = threading.local()


def _set_last_account_usage_probe(**values: Any) -> None:
    """Keep one credential-free probe result in the current quota worker.

    ``_fetch_account_usage`` is used by older callers that intentionally only
    understand ``dict | None``.  The delivery-device monitor additionally
    needs to distinguish a downstream ChatGPT 401 from a CPA management-key
    failure or a transient transport error.  A thread-local side channel keeps
    that extra diagnosis scoped to the exact worker without changing the
    established return contract or ever retaining the remote response body.
    """
    _USAGE_PROBE_LOCAL.value = {
        "ok": bool(values.get("ok")),
        "status_code": int(values.get("status_code") or 0),
        "management_status_code": int(values.get("management_status_code") or 0),
        "error_code": str(values.get("error_code") or "")[:96],
        "credential_repair_required": bool(
            values.get("credential_repair_required")
        ),
    }


def _clear_last_account_usage_probe() -> None:
    _USAGE_PROBE_LOCAL.value = None


def _last_account_usage_probe() -> dict[str, Any]:
    value = getattr(_USAGE_PROBE_LOCAL, "value", None)
    return dict(value) if isinstance(value, dict) else {}


def _fetch_account_usage(api_url: str, api_key: str, auth_index: str, account_id: str, timeout: int = 25):
    """通过 CPA 的 /v0/management/api-call 中转, 用该凭证的 token 调 chatgpt.com wham/usage,
    拿真实 5 小时 / 周限额(百分比 + 重置时间)。不本地碰 RT。失败返回 None。"""
    import json
    import requests
    _clear_last_account_usage_probe()
    if not auth_index:
        _set_last_account_usage_probe(
            ok=False,
            error_code="missing_auth_index",
        )
        return None
    body = {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": {
            "Authorization": "Bearer $TOKEN$",
            "Content-Type": "application/json",
            "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
            "Chatgpt-Account-Id": account_id or "",
        },
    }
    headers = {
        "Authorization": f"Bearer {api_key or ''}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        r = requests.post(api_url.rstrip("/") + "/v0/management/api-call",
                          headers=headers, json=body, timeout=timeout, verify=True)
        management_status = int(getattr(r, "status_code", 0) or 0)
        if management_status < 200 or management_status >= 300:
            _set_last_account_usage_probe(
                ok=False,
                management_status_code=management_status,
                error_code="management_http_error",
            )
            return None
        outer = r.json()
        upstream_status = int(outer.get("status_code") or 0)
        if upstream_status != 200:
            error_code = "credential_unauthorized" if upstream_status == 401 else "upstream_http_error"
            try:
                upstream_body = json.loads(outer.get("body") or "{}")
            except Exception:
                upstream_body = {}
            nested_error = upstream_body.get("error")
            upstream_code = str(
                upstream_body.get("code")
                or (
                    nested_error.get("code")
                    if isinstance(nested_error, dict)
                    else ""
                )
            ).strip().lower()
            if upstream_status == 401 and upstream_code:
                safe_code = "".join(
                    char for char in upstream_code
                    if char.isalnum() or char in {"_", "-", "."}
                )[:96]
                error_code = safe_code or error_code
            _set_last_account_usage_probe(
                ok=False,
                status_code=upstream_status,
                management_status_code=management_status,
                error_code=error_code,
                credential_repair_required=upstream_status == 401,
            )
            return None
        inner = json.loads(outer.get("body") or "{}")
        rl = inner.get("rate_limit") or {}
        cr = inner.get("credits") or {}
        # ⚠ primary/secondary_window 的位置不代表时长!按 limit_window_seconds 归类:
        #   ~18000s(5h)→ 5 小时窗口;  ~604800s(7天)→ 周窗口。
        #   (以前死板地把 primary 当 5h、secondary 当周,导致把周用量当成 5h 显示。)
        p5 = None
        week = None
        for w in (rl.get("primary_window"), rl.get("secondary_window")):
            if not isinstance(w, dict):
                continue
            secs = int(w.get("limit_window_seconds") or 0)
            if secs and secs <= 6 * 3600:        # ≤6 小时 → 5h 窗口
                p5 = w
            elif secs >= 24 * 3600:              # ≥1 天 → 周窗口
                week = w
            elif p5 is None:                     # 未知时长兜底: 先占 5h 槽
                p5 = w
        p5 = p5 or {}
        week = week or {}
        # 注: week 槽是"较长的那个窗口", 真实时长不固定(7天/30天…), 用 *_window_seconds 让前端动态标注周/月。
        # 字段名保持不变(week_used_percent 等), 自动退款/救急/存活判定都不受影响。
        result = {
            "reachable": True,   # 拿到 rate_limit = 该凭证 token 有效(判"存活"用这个, 别用 5h 是否有值)
            "p5_used_percent": p5.get("used_percent"),
            "p5_reset_at": p5.get("reset_at"),
            "p5_window_seconds": p5.get("limit_window_seconds"),
            "week_used_percent": week.get("used_percent"),
            "week_reset_at": week.get("reset_at"),
            "week_window_seconds": week.get("limit_window_seconds"),
            "limit_reached": rl.get("limit_reached"),
            "credit_balance": cr.get("balance"),
        }
        _set_last_account_usage_probe(
            ok=True,
            status_code=200,
            management_status_code=management_status,
        )
        return result
    except Exception:
        _set_last_account_usage_probe(
            ok=False,
            error_code="quota_probe_failed",
        )
        return None


def get_cpa_accounts(force: bool = False) -> dict:
    """CPA 真实账号列表 + 真实 5h/周限额(15 分钟缓存)。
    用量经 /v0/management/api-call 中转打 wham/usage 拿(CPA 用存的 token, 不本地碰 RT)。"""
    now = time.time()
    if (not force) and _ACCT_CACHE["data"] is not None and now - _ACCT_CACHE["at"] < _ACCT_CACHE_TTL:
        return _ACCT_CACHE["data"]
    cfg = get_config()
    devices = cfg["devices"]
    if not devices:
        return {"ok": False, "error": "未配置任何 CPA 设备", "fetched_at": None, "accounts": []}
    from services.cpa_manager import list_auth_files

    accounts = []
    errors = []
    for dev in devices:
        api_url, api_key = dev["api_url"], dev["api_key"]
        # 设备身份用 api_url(手填模式下 device_id 都是 0,不能用它区分多台设备)
        did, dname = dev["device_id"], (dev["name"] or api_url or f"#{dev['device_id']}")
        if not api_url:
            continue
        try:
            files = list_auth_files(api_url=api_url, api_key=api_key)
        except Exception as exc:
            errors.append(f"{dname}: {exc}")
            continue
        for f in files:
            email = str(f.get("email") or f.get("account") or f.get("name") or "").strip()
            if not email:
                continue
            idt = f.get("id_token") or {}
            disabled = bool(f.get("disabled"))
            usage = None
            skipped = False
            ukey = f"{api_url}:{email}"
            if not disabled:
                cached = _USAGE_CACHE.get(ukey)
                # 已知限流(任一窗口 100%)且未到重置时间 → 直接用缓存, 不再查
                _cached_reset = max(int((cached or {}).get("p5_reset_at") or 0),
                                    int((cached or {}).get("week_reset_at") or 0)) if cached else 0
                if (cached and (cached.get("limit_reached")
                                or cached.get("p5_used_percent") == 100
                                or cached.get("week_used_percent") == 100)
                        and _cached_reset > now):
                    usage = cached
                    skipped = True
                else:
                    usage = _fetch_account_usage(
                        api_url, api_key, f.get("auth_index"), idt.get("chatgpt_account_id"),
                    )
                    if usage:
                        _USAGE_CACHE[ukey] = usage
            u = usage or {}
            p5 = u.get("p5_used_percent")
            if disabled:
                display_status = "停用"
            elif usage is None:
                display_status = "失效"
            elif u.get("limit_reached") or p5 == 100:
                display_status = "限流"
            else:
                display_status = "健康"
            accounts.append({
                "email": email,
                "name": f.get("name"),
                "device_id": did,
                "device_url": api_url,
                "device_name": dname,
                "status": f.get("status"),
                "display_status": display_status,
                "usage_skipped": skipped,
                "disabled": disabled,
                "plan": idt.get("plan_type"),
                "active_start": idt.get("chatgpt_subscription_active_start"),
                "active_until": idt.get("chatgpt_subscription_active_until"),
                "success_total": int(f.get("success") or 0),
                "failed_total": int(f.get("failed") or 0),
                "reachable": usage is not None,   # token 是否有效(判存活用这个)
                "usage_5h_percent": u.get("p5_used_percent"),
                "usage_5h_reset_at": u.get("p5_reset_at"),
                "usage_week_percent": u.get("week_used_percent"),
                "usage_week_reset_at": u.get("week_reset_at"),
                "limit_reached": u.get("limit_reached"),
                "credit_balance": u.get("credit_balance"),
                "updated_at": f.get("updated_at") or f.get("last_refresh"),
            })
    data = {"ok": True, "fetched_at": now, "error": "; ".join(errors),
            "threshold_total": cfg["threshold_total"], "accounts": accounts}
    _ACCT_CACHE["at"] = now
    _ACCT_CACHE["data"] = data
    return data


def _alive_count(force: bool = False) -> int:
    """存活凭证数 = wham/usage 能查到额度的(token 有效, 含被 5h 限流的 error)。
    死号(查不到额度/relay 失败)不计入 → 这些才需要补。"""
    data = get_cpa_accounts(force=force)
    return sum(1 for a in data.get("accounts", []) if a.get("reachable"))


def get_interval_seconds() -> int:
    """补充任务的调度间隔;没有启用补充的设备则返回 0(调度器跳过)。"""
    cfg = get_config()
    if not any(d.get("replenish_enabled") for d in cfg["devices"]):
        return 0
    return cfg["interval_minutes"] * 60


def get_recycle_hour() -> int:
    """退款回收每天执行的小时(0-23);无启用退款的设备返回 -1(调度器跳过)。"""
    cfg = get_config()
    if not any(d.get("refund_enabled") for d in cfg["devices"]):
        return -1
    return cfg["recycle_hour"]


def maintain_gpt_pro_cpa() -> dict[str, Any]:
    """调度器入口(间隔触发)= 补充一轮。"""
    return replenish_once(manual=False)


def recycle_gpt_pro_cpa() -> dict[str, Any]:
    """调度器入口(每天定时)= 退款回收一轮。"""
    return recycle_once(manual=False)
