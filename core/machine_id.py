"""本机机器标识 helper, 用于 BUSINESS 子域名机器隔离。

优先级:
  1) config_store.get("business_machine_id") — 用户手动配置
  2) sha1(socket.gethostname())[:12] — fallback, hostname 变更会导致 ID 变

用户手动设的话, 即使迁移机器/换主机名也能保持同一个 owner_machine_id,
让该机器创建的所有 BUSINESS 子域 / 已注册账号继续归属本机。
"""
from __future__ import annotations

import hashlib
import socket
import threading


_CACHE: dict[str, str] = {}
_CACHE_LOCK = threading.Lock()


def _default_machine_id() -> str:
    try:
        host = socket.gethostname() or "local"
    except Exception:
        host = "local"
    return hashlib.sha1(
        host.encode("utf-8", errors="ignore"), usedforsecurity=False
    ).hexdigest()[:12]


def current_machine_id() -> str:
    """返回本机标识 (12 位 hex 字符串风格)。优先读 config, fallback hostname 哈希。

    结果在进程内会缓存到 config 改变前不重读, 避免热路径每次去 IO。
    用户在 Settings 改 business_machine_id 后, 调用 invalidate_machine_id_cache() 清缓存。
    """
    with _CACHE_LOCK:
        cached = _CACHE.get("id")
        if cached:
            return cached
    try:
        from core.config_store import config_store
        configured = str(config_store.get("business_machine_id", "") or "").strip()
    except Exception:
        configured = ""
    machine_id = configured or _default_machine_id()
    with _CACHE_LOCK:
        _CACHE["id"] = machine_id
    return machine_id


def invalidate_machine_id_cache() -> None:
    """用户改了 business_machine_id 配置后调一下, 让下次 current_machine_id() 重读。"""
    with _CACHE_LOCK:
        _CACHE.pop("id", None)
