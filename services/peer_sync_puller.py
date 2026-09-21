"""Peer-to-peer pending_rt 同步 (Consumer 侧拉取客户端)。

读取配置 peer_sources,依次向每个 peer producer 发 POST /peer-sync/pull?limit=N,
把返回的 rows 落到本机 SQLite。

配置示例 (config_store):
  peer_sync_role           = "consumer"
  peer_sources             = '[{"name":"reg-a","base_url":"http://10.0.0.1:8000"},
                               {"name":"reg-b","base_url":"http://10.0.0.2:8000"}]'
  peer_pull_batch          = "20"     # 单次每个 peer 最多拉多少条
  peer_pull_local_threshold = "5"     # 本机 pending_rt 少于此值才向 peer 要
  peer_pull_timeout_seconds = "20"
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from core.config_store import config_store
from services.peer_sync import (
    consumer_write_local,
    is_consumer,
    pending_rt_count,
)


_log = logging.getLogger(__name__)

DEFAULT_PULL_BATCH = 20
DEFAULT_LOCAL_THRESHOLD = 5
DEFAULT_PULL_TIMEOUT = 20

_pull_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
#  配置读取
# ─────────────────────────────────────────────────────────────


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def load_peer_sources() -> List[Dict[str, str]]:
    """读 peer_sources 配置,标准化成 [{name, base_url}, ...]。"""
    raw = config_store.get("peer_sources", "")
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: List[Dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        base_url = str(item.get("base_url") or "").strip().rstrip("/")
        if not base_url:
            continue
        out.append({
            "name": str(item.get("name") or base_url).strip(),
            "base_url": base_url,
        })
    return out


def pull_batch_size() -> int:
    return max(1, min(_safe_int(config_store.get("peer_pull_batch", ""), DEFAULT_PULL_BATCH), 1000))


def local_threshold() -> int:
    return max(0, _safe_int(config_store.get("peer_pull_local_threshold", ""), DEFAULT_LOCAL_THRESHOLD))


def pull_timeout() -> int:
    return max(3, _safe_int(config_store.get("peer_pull_timeout_seconds", ""), DEFAULT_PULL_TIMEOUT))


# ─────────────────────────────────────────────────────────────
#  对单个 peer 发请求
# ─────────────────────────────────────────────────────────────


def query_peer_status(base_url: str, timeout: int = 5) -> Dict[str, Any]:
    """GET <base>/api/peer-sync/status,返回 {role, pending_rt, _ok, _error}。"""
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        return {"_ok": False, "_error": "base_url 为空"}
    try:
        r = requests.get(
            f"{base_url}/api/peer-sync/status",
            timeout=timeout,
        )
        if r.status_code != 200:
            return {"_ok": False, "_error": f"HTTP {r.status_code}", "_status": r.status_code}
        data = r.json() if r.text else {}
        return {**data, "_ok": True}
    except Exception as e:
        return {"_ok": False, "_error": f"{e}"}


def pull_from_peer(source: Dict[str, str], limit: int, timeout: int) -> Dict[str, Any]:
    """POST <base>/api/peer-sync/pull?limit=N → 返回 rows 并写入本机。

    返回 {ok, name, fetched, written, error?}
    """
    base_url = (source.get("base_url") or "").strip().rstrip("/")
    name = source.get("name") or base_url
    if not base_url or limit <= 0:
        return {"ok": False, "name": name, "fetched": 0, "written": 0,
                "error": "缺 base_url 或 limit<=0"}

    try:
        r = requests.post(
            f"{base_url}/api/peer-sync/pull",
            params={"limit": int(limit)},
            timeout=timeout,
        )
    except Exception as e:
        return {"ok": False, "name": name, "fetched": 0, "written": 0,
                "error": f"HTTP 请求异常: {e}"}

    if r.status_code != 200:
        return {"ok": False, "name": name, "fetched": 0, "written": 0,
                "error": f"HTTP {r.status_code}: {(r.text or '')[:200]}"}

    try:
        data = r.json() if r.text else {}
    except Exception as e:
        return {"ok": False, "name": name, "fetched": 0, "written": 0,
                "error": f"响应非 JSON: {e}"}

    if not data.get("ok"):
        return {"ok": False, "name": name, "fetched": 0, "written": 0,
                "error": data.get("error") or "peer 返回 ok=False"}

    rows = data.get("rows") or []
    if not rows:
        return {"ok": True, "name": name, "fetched": 0, "written": 0}

    write_result = consumer_write_local(rows)
    return {
        "ok": True,
        "name": name,
        "fetched": len(rows),
        "written": write_result.get("written", 0),
        "inserted": write_result.get("inserted", 0),
        "updated": write_result.get("updated", 0),
    }


# ─────────────────────────────────────────────────────────────
#  入口: 拉一轮
# ─────────────────────────────────────────────────────────────


def pull_from_peers(*, requested: Optional[int] = None,
                    force: bool = False) -> Dict[str, Any]:
    """从所有 peer_sources 拉一轮 pending_rt。

    - requested: 本轮总共想要的条数;None = 用 peer_pull_batch * 配置源数
    - force: True = 跳过本机阈值检查 (手动按钮触发)

    顺序遍历 sources,直到拉够 requested 或所有 source 都返回 0。
    """
    if not is_consumer():
        return {"ok": False, "error": "本机 peer_sync_role != consumer",
                "fetched_total": 0, "results": []}

    sources = load_peer_sources()
    if not sources:
        return {"ok": False, "error": "peer_sources 配置为空",
                "fetched_total": 0, "results": []}

    batch = pull_batch_size()
    threshold = local_threshold()
    timeout = pull_timeout()
    local_count = pending_rt_count()

    if not force and local_count >= threshold:
        return {
            "ok": True,
            "skipped": True,
            "reason": f"本机 pending_rt={local_count} >= 阈值 {threshold},跳过",
            "fetched_total": 0,
            "results": [],
        }

    if not _pull_lock.acquire(blocking=False):
        return {"ok": False, "error": "上一轮 pull 尚未结束",
                "fetched_total": 0, "results": []}

    try:
        want_total = int(requested) if requested else batch * len(sources)
        want_total = max(1, want_total)
        results: List[Dict[str, Any]] = []
        fetched_total = 0
        for source in sources:
            if fetched_total >= want_total:
                break
            this_limit = min(batch, want_total - fetched_total)
            result = pull_from_peer(source, limit=this_limit, timeout=timeout)
            results.append(result)
            fetched_total += int(result.get("fetched", 0))

        _log.info(
            "[PeerSync.Consumer] pull round done: requested=%d fetched=%d sources=%d local_before=%d",
            want_total, fetched_total, len(sources), local_count,
        )
        return {
            "ok": True,
            "fetched_total": fetched_total,
            "local_before": local_count,
            "local_after": pending_rt_count(),
            "results": results,
        }
    finally:
        _pull_lock.release()
