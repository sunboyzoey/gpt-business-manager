"""动态住宅代理工厂 (711proxy 风格 rotating API)。

每次调 borrow_dynamic_proxy() 返回一个新出口 IP 的代理 URL,
适用于 BUSINESS RT 长跑每注册一个号换一个 IP 的场景。

设计:
- 711proxy /gen 接口是白名单制 (IP 白名单),不带 token
- 调用本身可能限频,这里加 _MIN_INTERVAL 0.5s 软节流
- 失败/未启用返回 None, 调用方 fallback 到普通代理池
"""
from __future__ import annotations

import collections
import secrets
import threading
import time
from typing import Optional

from core.config_store import config_store

_LOCK = threading.Lock()
_LAST_CALL_AT: float = 0.0
_MIN_INTERVAL = 0.5  # 防 711proxy /gen 接口被限频

# ── 本地 IP 预拉池 ──────────────────────────────────────────────
# 后台 daemon 持续拉新 IP 进池, worker borrow 时 0 排队从池取。
# 适合 20+ 并发场景, 避免启动时大家排队等同步拉。
_POOL_LOCK = threading.Lock()
_POOL: "collections.deque[tuple[str, float]]" = collections.deque()  # (proxy_url, born_at)
_POOL_DAEMON: Optional[threading.Thread] = None
_POOL_STOP = threading.Event()

_POOL_TARGET_SIZE = 30           # 池目标容量 (运行时可被 configure_pool_for_concurrency 调整)
_POOL_REFILL_INTERVAL = 3.0      # 后台每 N 秒拉一个新 IP 进池
_POOL_IP_TTL_SECONDS = 60.0      # 单个 IP 寿命 (超过自动剔除)
_POOL_LAST_CONCURRENCY_HINT = 0  # 上次自适应的并发数, 供 status 接口暴露


def configure_pool_for_concurrency(concurrency: int) -> dict:
    """根据 BUSINESS RT 长跑的并发数自动算池参数, 让 daemon 拉新速率 ≥ worker 消耗速率。

    数学:
      单号注册时长 T ≈ 60-90s
      worker 消耗速率 = concurrency / T  (IPs/s)
      daemon 拉新速率 = 1 / refill_interval (IPs/s)
      要求: 拉新 ≥ 消耗 → refill_interval ≤ T / concurrency
      池容量留 50% 缓冲: N ≥ concurrency × 1.5

    返回最终采用的参数, 供日志/UI 显示。
    """
    global _POOL_TARGET_SIZE, _POOL_REFILL_INTERVAL, _POOL_LAST_CONCURRENCY_HINT
    concurrency = max(1, int(concurrency))
    _POOL_LAST_CONCURRENCY_HINT = concurrency
    # 池容量
    _POOL_TARGET_SIZE = max(30, int(concurrency * 1.5))
    # refill 间隔: 60/c 但下限 1.0s (711proxy 限频), 上限 5.0s (避免太懒)
    _POOL_REFILL_INTERVAL = max(1.0, min(5.0, 60.0 / concurrency))
    return {
        "concurrency": concurrency,
        "target": _POOL_TARGET_SIZE,
        "refill_interval": _POOL_REFILL_INTERVAL,
    }


def _is_enabled() -> bool:
    raw = str(config_store.get("dynamic_proxy_enabled", "0") or "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _force_sessid_enabled() -> bool:
    """是否在每次调 /gen 时自动追加 &sessid=<随机>。

    711proxy 的 sessType=rotating 实测是「时间窗」(同一窗口内池子只有几个 IP),
    不带 sessid 时 unique 数极少 → 短时间多个号会用到同一 IP → OpenAI 风控。
    带随机 sessid 后 711proxy 内部会给每个 sessid 分新 IP, 多样性显著提升。
    默认开启 ('1'), 用户可在 Settings 关闭对照测试。
    """
    raw = str(config_store.get("dynamic_proxy_force_sessid", "1") or "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _api_url() -> str:
    return str(config_store.get("dynamic_proxy_api_url", "") or "").strip()


def _resolve_request_url() -> str:
    """返回最终调用的 URL, 如启用 force_sessid 则在 query 末尾追加 &sessid=<随机12位hex>。"""
    base = _api_url()
    if not base:
        return ""
    if not _force_sessid_enabled():
        return base
    sessid = secrets.token_hex(6)  # 12 字 hex
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}sessid={sessid}"


def _api_via_proxy() -> Optional[str]:
    """调 711proxy /gen 接口时是否要走代理。空字符串 = 直连。
    某些机器(如本机 Clash 系统代理关了)可能需要把 711proxy /gen 也走代理。
    """
    via = str(config_store.get("dynamic_proxy_api_via", "") or "").strip()
    return via or None


def fetch_one_ip() -> tuple[bool, str, str]:
    """从 711proxy API 拉一个 rotating IP。

    返回 (ok, proxy_url, raw_response_or_error)
      ok=True  : proxy_url 是 http://[user:pass@]host:port 形式, 可直接喂给 requests
      ok=False : raw 是错误描述, proxy_url=''
    """
    global _LAST_CALL_AT
    import requests

    url = _resolve_request_url()  # 已含随机 sessid (如启用 force_sessid)
    if not url:
        return False, "", "未配置 dynamic_proxy_api_url"

    via = _api_via_proxy()
    proxies = {"http": via, "https": via} if via else None

    with _LOCK:
        delta = time.time() - _LAST_CALL_AT
        if delta < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - delta)
        try:
            r = requests.get(url, timeout=12, proxies=proxies)
            _LAST_CALL_AT = time.time()
        except Exception as exc:
            _LAST_CALL_AT = time.time()
            return False, "", f"调 711proxy API 失败: {exc}"

    if r.status_code != 200:
        return False, "", f"HTTP {r.status_code}: {(r.text or '')[:200]}"

    body = (r.text or "").strip()
    if not body:
        return False, "", "返回空"

    # 取第一行 (split=\r\n 时, count=1 时只有 1 行)
    first_line = body.split("\r\n")[0].split("\n")[0].strip()
    if not first_line:
        return False, "", f"解析失败: {body[:200]}"

    # 多种可能格式:
    #   1.2.3.4:8080
    #   user:pass@1.2.3.4:8080
    #   http://1.2.3.4:8080
    #   http://user:pass@1.2.3.4:8080
    if first_line.startswith(("http://", "https://", "socks5://", "socks4://")):
        proxy_url = first_line
    else:
        proxy_url = f"http://{first_line}"

    return True, proxy_url, body[:200]


def _evict_expired_locked() -> int:
    """剔除池里寿命到期的 IP. 调用方必须持有 _POOL_LOCK. 返回剔除数。"""
    removed = 0
    now = time.time()
    # _POOL 按入池时间从旧到新排序 (deque appendright)
    while _POOL and now - _POOL[0][1] > _POOL_IP_TTL_SECONDS:
        _POOL.popleft()
        removed += 1
    return removed


def _push_to_pool(proxy_url: str) -> None:
    if not proxy_url:
        return
    with _POOL_LOCK:
        _evict_expired_locked()
        _POOL.append((proxy_url, time.time()))
        # 超容量时弹最旧的
        while len(_POOL) > _POOL_TARGET_SIZE:
            _POOL.popleft()


def _pop_from_pool() -> Optional[str]:
    """从池里 pop 一个最新进池的 IP (从右侧弹, 更年轻)。"""
    with _POOL_LOCK:
        _evict_expired_locked()
        if not _POOL:
            return None
        url, _ = _POOL.pop()
        return url


def pool_snapshot() -> dict:
    """供 status 接口 / UI 展示池状态."""
    with _POOL_LOCK:
        _evict_expired_locked()
        now = time.time()
        ages = [int(now - born) for _, born in _POOL]
        return {
            "size": len(_POOL),
            "target": _POOL_TARGET_SIZE,
            "ttl_seconds": int(_POOL_IP_TTL_SECONDS),
            "refill_interval_seconds": round(_POOL_REFILL_INTERVAL, 1),
            "concurrency_hint": _POOL_LAST_CONCURRENCY_HINT,
            "oldest_age_seconds": max(ages) if ages else 0,
            "youngest_age_seconds": min(ages) if ages else 0,
            "daemon_running": bool(_POOL_DAEMON and _POOL_DAEMON.is_alive()),
        }


def _pool_daemon_loop() -> None:
    """后台 daemon: 持续拉新 IP 进池, 维持容量在 target."""
    while not _POOL_STOP.is_set():
        try:
            if _is_enabled() and _api_url():
                # 先剔除过期再判容量
                with _POOL_LOCK:
                    _evict_expired_locked()
                    current_size = len(_POOL)
                if current_size < _POOL_TARGET_SIZE:
                    ok, proxy_url, _ = fetch_one_ip()
                    if ok:
                        _push_to_pool(proxy_url)
        except Exception:
            pass  # daemon 不能因单次异常退出
        if _POOL_STOP.wait(_POOL_REFILL_INTERVAL):
            break


def start_pool_daemon(concurrency_hint: int = 0) -> dict:
    """启动后台预拉 daemon. 已运行则 no-op。

    concurrency_hint > 0 时按并发数自动调池参数 (target / refill_interval)。
    返回最终池配置 (供日志使用)。
    """
    global _POOL_DAEMON
    cfg = {"target": _POOL_TARGET_SIZE, "refill_interval": _POOL_REFILL_INTERVAL, "concurrency": 0}
    if concurrency_hint > 0:
        cfg = configure_pool_for_concurrency(concurrency_hint)
    with _POOL_LOCK:
        if _POOL_DAEMON and _POOL_DAEMON.is_alive():
            return cfg
        _POOL_STOP.clear()
        _POOL_DAEMON = threading.Thread(
            target=_pool_daemon_loop,
            name="dynamic-proxy-pool-daemon",
            daemon=True,
        )
    _POOL_DAEMON.start()
    return cfg


def stop_pool_daemon() -> None:
    """停止 daemon 并清空池."""
    _POOL_STOP.set()
    with _POOL_LOCK:
        _POOL.clear()


def borrow_dynamic_proxy() -> Optional[str]:
    """供 BUSINESS RT 长跑代理选择链使用。

    取 IP 优先级:
      1. 本地池 pop 一个 (O(1), 零网络)
      2. 池空 → 同步调 /gen (fallback)
      3. 仍失败 → None (调用方走普通代理选择链)
    """
    if not _is_enabled():
        return None
    # 1. 池里取
    pooled = _pop_from_pool()
    if pooled:
        return pooled
    # 2. 池空, 同步拉一个
    ok, proxy_url, _ = fetch_one_ip()
    return proxy_url if ok else None


def batch_test_diversity(count: int = 10, interval_seconds: float = 1.0) -> dict:
    """连续多次调 /gen, 看返回的 IP 多样性。

    用于判断 711proxy 这个 sessType=rotating 实际行为:
      - 每次换 (per-request rotating)  → unique = count
      - 时间窗换 (10 min sticky)       → unique 远小于 count
      - 完全 sticky                      → unique = 1
    """
    count = max(1, min(int(count or 10), 30))
    interval = max(0.3, float(interval_seconds))

    items: list[dict] = []
    for i in range(count):
        if i > 0:
            time.sleep(interval)
        ok, proxy_url, raw = fetch_one_ip()
        items.append({
            "ok": ok,
            "proxy_url": proxy_url if ok else "",
            "raw": raw,
        })

    ok_items = [it for it in items if it["ok"]]
    ips = [it["proxy_url"].replace("http://", "").strip() for it in ok_items]
    unique = list(dict.fromkeys(ips))  # 保序去重

    if not ips:
        verdict = "全部失败,无法判断 (检查白名单/Clash 节点/限频)"
    elif len(unique) == 1:
        verdict = "⚠ 全部相同 → rotating 是 sticky 的, 需要在 URL 加 sessid 之类参数才能换 IP"
    elif len(unique) < len(ips) * 0.5:
        verdict = f"⚠ 多样性不足 ({len(unique)}/{len(ips)}) → rotating 是时间窗模式, 短时间内拿到的 IP 会重"
    else:
        verdict = f"✅ 多样性良好 ({len(unique)}/{len(ips)}) → 每次注册都拿不同 IP"

    return {
        "count_requested": count,
        "count_ok": len(ok_items),
        "count_unique": len(unique),
        "ips": ips,
        "unique_ips": unique,
        "items": items,
        "verdict": verdict,
    }


def test_fetch_with_verification() -> dict:
    """供 UI「测试」按钮使用。

    1) 调 711proxy API 拉一个代理
    2) 用拉到的代理访问 https://api.ipify.org 验证出口 IP
    3) 返回完整诊断信息给前端展示
    """
    import requests

    result: dict = {
        "ok": False,
        "api_url": _api_url(),
        "enabled": _is_enabled(),
        "via_proxy": _api_via_proxy() or "(直连)",
    }
    if not _api_url():
        result["error"] = "未配置 dynamic_proxy_api_url"
        return result

    ok, proxy_url, raw_or_err = fetch_one_ip()
    result["raw_response"] = raw_or_err
    if not ok:
        result["error"] = raw_or_err
        return result

    result["proxy_url"] = proxy_url

    # 验证出口 IP
    try:
        r = requests.get(
            "https://api.ipify.org",
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=15,
        )
        if r.status_code == 200:
            result["verified_out_ip"] = (r.text or "").strip()
            result["ok"] = True
        else:
            result["verified_out_ip"] = ""
            result["error"] = f"代理可达但 ipify HTTP {r.status_code}"
    except Exception as exc:
        result["verified_out_ip"] = ""
        result["error"] = f"代理拉到了但访问 ipify 失败: {exc}"

    return result
