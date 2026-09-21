"""
代理订阅池管理 — mihomo 控制、订阅更新、节点测试、IP 池轮询
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests
import yaml
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MIHOMO_DIR = Path("/opt/mihomo")
MIHOMO_BIN = MIHOMO_DIR / "mihomo"
MIHOMO_CONFIG = MIHOMO_DIR / "config.yaml"
MIHOMO_API = "http://127.0.0.1:9090"
MIHOMO_SECRET = "register-server-secret"

TARGET_TEST_URL = "https://chatgpt.com"
REGION_CHECK_URL = "https://cloudflare.com/cdn-cgi/trace"
BLOCKED_REGIONS = {"CN", "HK"}

_pool_lock = threading.Lock()
_proxy_pool: list[dict] = []
_pool_index = 0
_subscription_generation = 0
_protocol_probe_lock = threading.Lock()
_protocol_probe_cache: dict[str, tuple[float, dict]] = {}

_test_status = {"running": False, "progress": "", "results": [], "updated_at": 0}
_test_lock = threading.Lock()

LISTENER_BASE_PORT = 7891

DATA_DIR = Path(os.environ.get("APP_RUNTIME_DIR") or os.environ.get("GBM_RUNTIME_DIR") or Path(__file__).parent.parent / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
POOL_FILE = DATA_DIR / "proxy_pool.json"
CHATGPT_PROTOCOL_POOL_FILE = DATA_DIR / "chatgpt_protocol_proxy_pool.json"

_chatgpt_protocol_status = {
    "running": False,
    "progress": "",
    "results": [],
    "pool": [],
    "updated_at": 0,
}
_chatgpt_protocol_lock = threading.Lock()
_chatgpt_protocol_pool_index = 0


def _save_pool():
    try:
        POOL_FILE.write_text(
            json.dumps(
                {"pool": _proxy_pool, "index": _pool_index, "results": _test_status.get("results", []),
                 "updated_at": _test_status.get("updated_at", 0)},
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def _load_pool():
    global _proxy_pool, _pool_index
    if not POOL_FILE.exists():
        return
    try:
        d = json.loads(POOL_FILE.read_text(encoding="utf-8"))
        _proxy_pool = d.get("pool", [])
        _pool_index = d.get("index", 0)
        _test_status["updated_at"] = float(d.get("updated_at") or 0)
        results = d.get("results", [])
        if results:
            _test_status["results"] = results
            ok_count = sum(1 for r in results if r.get("status") == "ok")
            _test_status["progress"] = f"已加载: {ok_count}/{len(results)} 可用"
    except Exception:
        pass


_load_pool()


def _save_chatgpt_protocol_pool():
    try:
        with _chatgpt_protocol_lock:
            payload = {
                "results": _chatgpt_protocol_status.get("results", []),
                "pool": _chatgpt_protocol_status.get("pool", []),
                "updated_at": _chatgpt_protocol_status.get("updated_at", 0),
                "progress": _chatgpt_protocol_status.get("progress", ""),
            }
        CHATGPT_PROTOCOL_POOL_FILE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _load_chatgpt_protocol_pool():
    if not CHATGPT_PROTOCOL_POOL_FILE.exists():
        return
    try:
        payload = json.loads(CHATGPT_PROTOCOL_POOL_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    with _chatgpt_protocol_lock:
        _chatgpt_protocol_status["results"] = payload.get("results", []) or []
        _chatgpt_protocol_status["pool"] = payload.get("pool", []) or []
        _chatgpt_protocol_status["updated_at"] = float(payload.get("updated_at") or 0)
        _chatgpt_protocol_status["progress"] = str(payload.get("progress") or "")


_load_chatgpt_protocol_pool()


def get_pool() -> list[dict]:
    with _pool_lock:
        return list(_proxy_pool)


def get_pool_size() -> int:
    with _pool_lock:
        return len(_proxy_pool)


def next_proxy() -> dict | None:
    global _pool_index
    with _pool_lock:
        if not _proxy_pool:
            return None
        p = _proxy_pool[_pool_index % len(_proxy_pool)]
        _pool_index += 1
        return p


def get_test_status() -> dict:
    with _test_lock:
        return dict(_test_status)


def get_chatgpt_protocol_test_status() -> dict:
    with _chatgpt_protocol_lock:
        return {
            "running": bool(_chatgpt_protocol_status.get("running")),
            "progress": str(_chatgpt_protocol_status.get("progress") or ""),
            "results": list(_chatgpt_protocol_status.get("results") or []),
            "pool": list(_chatgpt_protocol_status.get("pool") or []),
            "updated_at": float(_chatgpt_protocol_status.get("updated_at") or 0),
        }


def _proxy_addr_key(addr: str) -> str:
    try:
        from core.proxy_utils import normalize_proxy_url

        addr = normalize_proxy_url(addr) or ""
    except Exception:
        addr = str(addr or "").strip()
    return str(addr or "").strip().rstrip("/").lower()


def next_chatgpt_protocol_proxy(skip_addr: str = "") -> dict | None:
    """从已通过 ChatGPT 协议预检的缓存池里轮询取代理，不触发现场测速。"""
    global _chatgpt_protocol_pool_index
    skip_key = _proxy_addr_key(skip_addr)
    with _chatgpt_protocol_lock:
        pool = [
            dict(item)
            for item in (_chatgpt_protocol_status.get("pool") or [])
            if str(item.get("addr") or "").strip()
        ]
        if not pool:
            return None
        for _ in range(len(pool)):
            idx = _chatgpt_protocol_pool_index % len(pool)
            _chatgpt_protocol_pool_index += 1
            item = pool[idx]
            if skip_key and _proxy_addr_key(str(item.get("addr") or "")) == skip_key:
                continue
            return item
    return None


def _mihomo_api(method: str, path: str, data=None, timeout=10):
    headers = {"Authorization": f"Bearer {MIHOMO_SECRET}"}
    url = f"{MIHOMO_API}{path}"
    try:
        r = requests.request(method, url, json=data, headers=headers, timeout=timeout)
        return r.json() if r.text else {}
    except Exception as e:
        return {"error": str(e)}


def is_mihomo_installed() -> bool:
    return MIHOMO_BIN.exists()


def is_mihomo_running() -> bool:
    try:
        r = requests.get(
            f"{MIHOMO_API}/version",
            headers={"Authorization": f"Bearer {MIHOMO_SECRET}"},
            timeout=3,
        )
        return r.status_code == 200
    except Exception:
        return False


def install_mihomo():
    MIHOMO_DIR.mkdir(parents=True, exist_ok=True)
    import platform as _platform
    arch = _platform.machine()
    arch_name = "linux-arm64" if arch in ("aarch64", "arm64") else "linux-amd64"
    dl_url = f"https://github.com/MetaCubeX/mihomo/releases/download/v1.19.0/mihomo-{arch_name}-v1.19.0.gz"
    gz_path = MIHOMO_DIR / "mihomo.gz"
    subprocess.run(["wget", "-q", "-O", str(gz_path), dl_url], check=True, timeout=120)
    subprocess.run(["gunzip", "-f", str(gz_path)], check=True)
    bin_path = MIHOMO_DIR / f"mihomo-{arch_name}-v1.19.0"
    if bin_path.exists():
        bin_path.rename(MIHOMO_BIN)
    elif not MIHOMO_BIN.exists():
        for f in MIHOMO_DIR.iterdir():
            if f.name.startswith("mihomo") and not f.name.endswith(".gz"):
                f.rename(MIHOMO_BIN)
                break
    MIHOMO_BIN.chmod(0o755)
    return True


def _build_base_config(subscription_url: str) -> dict:
    return {
        "mixed-port": 7890,
        "external-controller": "0.0.0.0:9090",
        "secret": MIHOMO_SECRET,
        "mode": "rule",
        "log-level": "warning",
        "proxy-providers": {
            "subscription": {
                "type": "http",
                "url": subscription_url,
                "interval": 3600,
                "path": "./providers/sub.yaml",
                "health-check": {
                    "enable": True,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300,
                },
            }
        },
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "use": ["subscription"]},
        ],
        "rules": ["MATCH,PROXY"],
    }


def _restart_mihomo():
    subprocess.run(["systemctl", "restart", "mihomo"], timeout=15, capture_output=True)
    time.sleep(2)


def _setup_mihomo_service():
    service = f"""[Unit]
Description=mihomo proxy
After=network.target

[Service]
Type=simple
ExecStart={MIHOMO_BIN} -d {MIHOMO_DIR}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/mihomo.service").write_text(service)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", "mihomo"], capture_output=True)


def ensure_mihomo() -> dict:
    if not is_mihomo_installed():
        try:
            install_mihomo()
        except Exception as e:
            return {"ok": False, "msg": f"安装 mihomo 失败: {e}"}
    _setup_mihomo_service()
    if not MIHOMO_CONFIG.exists():
        from core.config_store import config_store
        sub_url = str(config_store.get("proxy_subscription_url", "") or "").strip()
        if not sub_url:
            return {"ok": False, "msg": "未配置代理订阅地址"}
        config = _build_base_config(sub_url)
        MIHOMO_DIR.mkdir(parents=True, exist_ok=True)
        MIHOMO_CONFIG.write_text(
            yaml.dump(config, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
    if not is_mihomo_running():
        _restart_mihomo()
    return {"ok": True, "msg": "mihomo 已就绪"}


def update_subscription(subscription_url: str = "") -> dict:
    global _pool_index, _subscription_generation
    if not subscription_url:
        from core.config_store import config_store
        subscription_url = str(config_store.get("proxy_subscription_url", "") or "").strip()
    if not subscription_url:
        return {"ok": False, "msg": "未配置代理订阅地址"}

    MIHOMO_DIR.mkdir(parents=True, exist_ok=True)
    (MIHOMO_DIR / "providers").mkdir(exist_ok=True)

    try:
        r = requests.get(subscription_url, timeout=30, verify=True, headers={"User-Agent": "clash-meta"})
        r.raise_for_status()
        sub_content = r.text
    except Exception as e:
        return {"ok": False, "msg": f"下载订阅失败: {e}"}

    sub_path = MIHOMO_DIR / "providers" / "sub.yaml"
    sub_path.write_text(sub_content, encoding="utf-8")

    try:
        sub_data = yaml.safe_load(sub_content)
    except Exception as e:
        return {"ok": False, "msg": f"解析订阅失败: {e}"}

    proxies = sub_data.get("proxies", [])
    if not proxies:
        return {"ok": False, "msg": "订阅中没有节点"}

    config = _build_base_config(subscription_url)
    config["proxies"] = [
        p for p in proxies
        if not any(kw in p.get("name", "") for kw in ("流量", "到期", "套餐"))
    ]

    listeners = []
    node_names_seen = set()
    for i, p in enumerate(proxies):
        name = p.get("name", f"node_{i}")
        ptype = p.get("type", "")
        if ptype in ("", "socks5") or any(kw in name for kw in ("流量", "到期", "套餐")):
            continue
        if name in node_names_seen:
            continue
        node_names_seen.add(name)
        port = LISTENER_BASE_PORT + len(listeners)
        listeners.append({"name": f"in_{len(listeners)}", "type": "mixed", "port": port, "proxy": name})
    config["listeners"] = listeners

    valid_proxies = [p for p in proxies if p.get("name", "") in node_names_seen]
    config["proxy-groups"] = [
        {"name": "PROXY", "type": "select", "proxies": [p["name"] for p in valid_proxies]},
    ]
    config.pop("proxy-providers", None)

    MIHOMO_CONFIG.write_text(
        yaml.dump(config, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )

    # A subscription can reuse listener ports/names for different endpoints.
    # Old successful checks must not authorize the replacement configuration.
    _subscription_generation += 1
    with _pool_lock:
        _proxy_pool.clear()
        _pool_index = 0
    with _test_lock:
        _test_status.update(results=[], updated_at=0, progress="订阅已更新，请重新检测")
    with _chatgpt_protocol_lock:
        _chatgpt_protocol_status.update(pool=[], results=[], updated_at=0, progress="订阅已更新，请重新检测")
    _save_pool()
    _save_chatgpt_protocol_pool()

    if not is_mihomo_installed():
        setup_result = ensure_mihomo()
        if not setup_result.get("ok"):
            return setup_result
    else:
        _restart_mihomo()

    return {"ok": True, "msg": f"订阅更新成功，共 {len(valid_proxies)} 个节点", "count": len(valid_proxies)}


def get_nodes() -> list[dict]:
    if not MIHOMO_CONFIG.exists():
        return []
    try:
        cfg = yaml.safe_load(MIHOMO_CONFIG.read_text(encoding="utf-8"))
        proxies = cfg.get("proxies", [])
        listeners = cfg.get("listeners", [])
        port_map = {ls.get("proxy", ""): ls.get("port", 0) for ls in listeners}

        result = []
        for p in proxies:
            name = p.get("name", "")
            if any(kw in name for kw in ("流量", "到期", "套餐")):
                continue
            result.append({
                "name": name,
                "type": p.get("type", ""),
                "server": p.get("server", ""),
                "port": port_map.get(name, 0),
                "addr": f"http://127.0.0.1:{port_map.get(name, 0)}" if port_map.get(name, 0) else "",
            })
        return result
    except Exception:
        return []


def _normalize_node_name(node_name: str) -> str:
    target = str(node_name or "").strip()
    if target.startswith("clash:"):
        target = target.split(":", 1)[1].strip()
    return target


def _mixed_proxy_url() -> str:
    cfg = _mihomo_api("GET", "/configs", timeout=5)
    port = cfg.get("mixed-port") if isinstance(cfg, dict) else None
    if not port and MIHOMO_CONFIG.exists():
        try:
            config = yaml.safe_load(MIHOMO_CONFIG.read_text(encoding="utf-8")) or {}
            port = config.get("mixed-port")
        except Exception:
            port = None
    try:
        port = int(port or 7890)
    except (TypeError, ValueError):
        port = 7890
    return f"http://127.0.0.1:{port}"


def _find_node(target: str) -> dict | None:
    with _pool_lock:
        for item in _proxy_pool:
            if str(item.get("name") or "").strip() == target:
                return dict(item)

    for node in get_nodes():
        if str(node.get("name") or "").strip() == target:
            return dict(node)
    return None


def select_node_for_mixed_port(node_name: str) -> dict | None:
    """Select a mihomo node globally and return the stable mixed-port URL.

    curl_cffi can fail TLS handshakes through per-listener node ports on some
    mihomo configs. Selecting the node via controller API and using mixed-port
    keeps node choice automatic while avoiding those listener compatibility
    issues.
    """
    target = _normalize_node_name(node_name)
    if not target:
        return None

    node = _find_node(target)
    if not node:
        return None

    resp = _mihomo_api("GET", "/proxies", timeout=5)
    proxies = resp.get("proxies") if isinstance(resp, dict) else None
    if not isinstance(proxies, dict):
        return None

    selected_groups: list[str] = []
    for group_name, meta in proxies.items():
        if not isinstance(meta, dict):
            continue
        options = meta.get("all") or []
        if target not in options:
            continue
        group_type = str(meta.get("type") or "")
        if group_type not in {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}:
            continue
        result = _mihomo_api(
            "PUT",
            f"/proxies/{quote(str(group_name), safe='')}",
            data={"name": target},
            timeout=5,
        )
        if isinstance(result, dict) and result.get("error"):
            continue
        selected_groups.append(str(group_name))

    if not selected_groups:
        return None

    original_addr = str(node.get("addr") or "").strip()
    return {
        **node,
        "name": target,
        "addr": _mixed_proxy_url(),
        "node_addr": original_addr,
        "selected_groups": selected_groups,
        "mixed_port": True,
    }


def resolve_node_proxy(node_name: str, *, use_mixed_port: bool = False) -> dict | None:
    """Resolve a Clash/mihomo node name to its local listener proxy URL."""
    target = _normalize_node_name(node_name)
    if not target:
        return None

    if use_mixed_port:
        selected = select_node_for_mixed_port(target)
        if selected:
            return selected

    node = _find_node(target)
    if node:
        addr = str(node.get("addr") or "").strip()
        if addr:
            return {**node, "addr": addr}
    return None


def _node_region_key(node_name: str) -> str:
    name = str(node_name or "").strip()
    upper = name.upper()
    if "🇯🇵" in name or "日本" in name or "JAPAN" in upper or " JP" in upper:
        return "jp"
    if "🇭🇰" in name or "香港" in name or "HONG KONG" in upper or " HK" in upper:
        return "hk"
    if "🇺🇸" in name or "美国" in name or "UNITED STATES" in upper or " US" in upper:
        return "us"
    return ""


def _chatgpt_probe_impersonates() -> list[str]:
    try:
        from platforms.chatgpt.protocol_register import get_chrome_impersonates

        values = get_chrome_impersonates()
        if values:
            return list(reversed(values))
    except Exception:
        pass
    return ["chrome136", "chrome133a", "chrome131"]


def probe_chatgpt_protocol_proxy(
    proxy_addr: str,
    *,
    timeout: int = 8,
    cache_ttl: int = 45,
) -> dict:
    """Check whether curl_cffi protocol registration can reach ChatGPT."""
    proxy_addr = str(proxy_addr or "").strip()
    if not proxy_addr:
        return {"ok": False, "status": 0, "latency": 0, "error": "空代理"}

    now = time.time()
    with _protocol_probe_lock:
        cached = _protocol_probe_cache.get(proxy_addr)
        if cache_ttl > 0 and cached and cached[0] > now:
            return dict(cached[1])

    t0 = time.time()
    result = None
    try:
        from curl_cffi import requests as curl_requests

        for impersonate in _chatgpt_probe_impersonates():
            session = None
            try:
                session = curl_requests.Session(impersonate=impersonate)
                session.trust_env = False
                session.proxies = {"http": proxy_addr, "https": proxy_addr}
                r = session.get(TARGET_TEST_URL, timeout=timeout, allow_redirects=True)
                status = int(getattr(r, "status_code", 0) or 0)
                csrf = None
                csrf_status = 0
                csrf_content_type = ""
                if 200 <= status < 400:
                    csrf = session.get(
                        f"{TARGET_TEST_URL.rstrip('/')}/api/auth/csrf",
                        headers={"Accept": "application/json", "Referer": TARGET_TEST_URL},
                        timeout=timeout,
                        allow_redirects=True,
                    )
                    csrf_status = int(getattr(csrf, "status_code", 0) or 0)
                    csrf_content_type = str(csrf.headers.get("content-type") or "").lower()
                latency = int((time.time() - t0) * 1000)
                ok = (
                    200 <= status < 400
                    and 200 <= csrf_status < 400
                    and "application/json" in csrf_content_type
                )
                result = {
                    "ok": ok,
                    "status": csrf_status or status,
                    "home_status": status,
                    "csrf_status": csrf_status,
                    "latency": latency,
                    "error": "" if ok else f"HTTP {csrf_status or status}",
                    "url": str(getattr(csrf or r, "url", "") or ""),
                    "impersonate": impersonate,
                }
                if ok:
                    break
            except Exception as e:
                latency = int((time.time() - t0) * 1000)
                result = {
                    "ok": False,
                    "status": 0,
                    "latency": latency,
                    "error": f"{type(e).__name__}: {str(e)[:160]}",
                    "url": "",
                    "impersonate": impersonate,
                }
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
    except Exception as e:
        latency = int((time.time() - t0) * 1000)
        result = {
            "ok": False,
            "status": 0,
            "latency": latency,
            "error": f"{type(e).__name__}: {str(e)[:160]}",
            "url": "",
        }

    if result is None:
        result = {"ok": False, "status": 0, "latency": 0, "error": "无可用指纹", "url": ""}
    with _protocol_probe_lock:
        _protocol_probe_cache[proxy_addr] = (time.time() + cache_ttl, dict(result))
    return result


def _iter_protocol_fallback_candidates(
    *,
    region: str,
    skip_name: str,
    skip_addr: str,
):
    seen = set()
    for node in get_nodes():
        name = str(node.get("name") or "").strip()
        addr = str(node.get("addr") or "").strip()
        key = addr or name
        if not key or key in seen:
            continue
        seen.add(key)
        if name == skip_name or addr == skip_addr:
            continue
        if region and _node_region_key(name) != region:
            continue
        yield dict(node)

    with _pool_lock:
        pool = list(_proxy_pool)
    for node in pool:
        name = str(node.get("name") or "").strip()
        addr = str(node.get("addr") or "").strip()
        key = addr or name
        if not key or key in seen:
            continue
        seen.add(key)
        if name == skip_name or addr == skip_addr:
            continue
        if region and _node_region_key(name) != region:
            continue
        yield dict(node)


def resolve_chatgpt_protocol_proxy(
    node_name: str,
    *,
    timeout: int = 8,
) -> dict | None:
    """Resolve a Clash node and auto-fallback when curl_cffi cannot use it."""
    target = _normalize_node_name(node_name)
    preferred = resolve_node_proxy(target, use_mixed_port=False)
    if not preferred:
        return None

    preferred_addr = str(preferred.get("addr") or "").strip()
    preferred_name = str(preferred.get("name") or target).strip()
    preferred_probe = probe_chatgpt_protocol_proxy(preferred_addr, timeout=timeout)
    preferred = {**preferred, "protocol_probe": preferred_probe}
    if preferred_probe.get("ok"):
        return preferred

    region = _node_region_key(preferred_name or target)
    reason = str(preferred_probe.get("error") or f"HTTP {preferred_probe.get('status') or 0}")
    for candidate in _iter_protocol_fallback_candidates(
        region=region,
        skip_name=preferred_name,
        skip_addr=preferred_addr,
    ):
        addr = str(candidate.get("addr") or "").strip()
        if not addr:
            continue
        probe = probe_chatgpt_protocol_proxy(addr, timeout=timeout)
        if not probe.get("ok"):
            continue
        return {
            **candidate,
            "protocol_probe": probe,
            "protocol_fallback": True,
            "fallback_from": preferred_name or target,
            "fallback_reason": reason,
        }

    return preferred


def _generic_test_results_by_name() -> dict[str, dict]:
    with _test_lock:
        results = list(_test_status.get("results") or [])
    return {
        str(item.get("name") or "").strip(): dict(item)
        for item in results
        if str(item.get("name") or "").strip()
    }


def _chatgpt_protocol_probe_node(
    node: dict,
    *,
    index: int,
    timeout: int,
    cache_ttl: int,
    generic_by_name: dict[str, dict],
) -> tuple[dict, dict | None]:
    name = str(node.get("name") or "").strip()
    port = int(node.get("port") or 0)
    addr = str(node.get("addr") or "").strip()
    if not addr and port:
        addr = f"http://127.0.0.1:{port}"

    generic = generic_by_name.get(name) or {}
    base = {
        **node,
        "_index": index,
        "name": name,
        "port": port,
        "addr": addr,
        "region": str(generic.get("region") or "").strip().upper(),
    }
    if not port or not addr:
        return {
            **base,
            "status": "skip",
            "latency": 0,
            "error": "无端口",
            "protocol_probe": {"ok": False, "latency": 0, "error": "无端口"},
        }, None

    probe = probe_chatgpt_protocol_proxy(addr, timeout=timeout, cache_ttl=cache_ttl)
    ok = bool(probe.get("ok"))
    latency = int(probe.get("latency") or 0)
    entry = {
        **base,
        "status": "ok" if ok else "fail",
        "latency": latency,
        "error": "" if ok else str(probe.get("error") or "协议预检失败"),
        "protocol_probe": probe,
    }
    if not ok:
        return entry, None

    pool_entry = {
        "name": name,
        "port": port,
        "addr": addr,
        "latency": latency,
        "region": entry.get("region") or "",
        "protocol": "chatgpt",
    }
    return entry, pool_entry


def test_chatgpt_protocol_nodes(
    *,
    timeout: int = 6,
    cache_ttl: int = 600,
    max_workers: int = 8,
) -> list[dict]:
    """Run curl_cffi-compatible ChatGPT registration probes for each Clash node."""
    generation = _subscription_generation
    with _chatgpt_protocol_lock:
        if _chatgpt_protocol_status.get("running"):
            return list(_chatgpt_protocol_status.get("results") or [])
        _chatgpt_protocol_status["running"] = True
        _chatgpt_protocol_status["progress"] = "开始 ChatGPT 协议预检..."
        _chatgpt_protocol_status["results"] = []
        _chatgpt_protocol_status["pool"] = []

    nodes = get_nodes()
    if not nodes:
        with _chatgpt_protocol_lock:
            _chatgpt_protocol_status["running"] = False
            _chatgpt_protocol_status["progress"] = "没有节点"
            _chatgpt_protocol_status["updated_at"] = time.time()
        _save_chatgpt_protocol_pool()
        return []

    generic_by_name = _generic_test_results_by_name()
    worker_count = max(1, min(int(max_workers or 8), len(nodes)))
    results: list[dict] = []
    pool: list[dict] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                _chatgpt_protocol_probe_node,
                node,
                index=index,
                timeout=timeout,
                cache_ttl=cache_ttl,
                generic_by_name=generic_by_name,
            )
            for index, node in enumerate(nodes)
        ]
        for future in as_completed(futures):
            try:
                entry, pool_entry = future.result()
            except Exception as exc:
                entry = {
                    "_index": len(results),
                    "name": "",
                    "status": "fail",
                    "latency": 0,
                    "error": str(exc)[:160],
                    "protocol_probe": {"ok": False, "latency": 0, "error": str(exc)[:160]},
                }
                pool_entry = None
            results.append(entry)
            if pool_entry:
                pool.append(pool_entry)
            completed += 1
            with _chatgpt_protocol_lock:
                _chatgpt_protocol_status["progress"] = f"ChatGPT 协议预检 {completed}/{len(nodes)}"

    results.sort(key=lambda item: int(item.get("_index") or 0))
    for item in results:
        item.pop("_index", None)
    pool.sort(key=lambda item: int(item.get("latency") or 0))
    changed = generation != _subscription_generation
    if changed:
        results, pool = [], []

    with _chatgpt_protocol_lock:
        _chatgpt_protocol_status["running"] = False
        _chatgpt_protocol_status["results"] = results
        _chatgpt_protocol_status["pool"] = pool
        _chatgpt_protocol_status["updated_at"] = time.time()
        _chatgpt_protocol_status["progress"] = f"ChatGPT 协议预检完成: {len(pool)}/{len(nodes)} 可用"
        if changed:
            _chatgpt_protocol_status["progress"] = "订阅已更新，请重新检测"
    _save_chatgpt_protocol_pool()
    return results


def test_chatgpt_protocol_nodes_async() -> dict:
    with _chatgpt_protocol_lock:
        if _chatgpt_protocol_status.get("running"):
            return {"ok": True, "msg": "ChatGPT 协议预检已在运行"}
    thread = threading.Thread(target=test_chatgpt_protocol_nodes, daemon=True)
    thread.start()
    return {"ok": True, "msg": "开始 ChatGPT 协议预检节点..."}


def get_chatgpt_protocol_pool(
    *,
    refresh: bool = False,
    max_age_seconds: int = 600,
) -> dict:
    status = get_chatgpt_protocol_test_status()
    updated_at = float(status.get("updated_at") or 0)
    stale = not updated_at or (time.time() - updated_at) > max_age_seconds
    if refresh or (stale and not status.get("running")):
        test_chatgpt_protocol_nodes()
        status = get_chatgpt_protocol_test_status()
    return {
        "pool": list(status.get("pool") or []),
        "running": bool(status.get("running")),
        "progress": str(status.get("progress") or ""),
        "updated_at": float(status.get("updated_at") or 0),
    }


def test_nodes(callback=None) -> list[dict]:
    global _proxy_pool, _pool_index
    generation = _subscription_generation

    with _test_lock:
        if _test_status["running"]:
            return []
        _test_status["running"] = True
        _test_status["progress"] = "开始测试..."
        _test_status["results"] = []

    nodes = get_nodes()
    if not nodes:
        with _pool_lock:
            _proxy_pool = []
            _pool_index = 0
        with _test_lock:
            _test_status["running"] = False
            _test_status["progress"] = "没有节点"
            _test_status["updated_at"] = time.time()
        _save_pool()
        return []

    results = []
    working = []

    for i, node in enumerate(nodes):
        port = node.get("port", 0)
        if not port:
            results.append({**node, "status": "skip", "latency": 0, "error": "无端口"})
            continue

        with _test_lock:
            _test_status["progress"] = f"测试 {i+1}/{len(nodes)}: {node['name']}"

        proxy_addr = f"http://127.0.0.1:{port}"
        try:
            t0 = time.time()
            r = requests.get(TARGET_TEST_URL, proxies={"https": proxy_addr, "http": proxy_addr}, timeout=10, verify=True)
            latency = int((time.time() - t0) * 1000)
            ok = 200 <= r.status_code < 400
            if not ok:
                results.append({**node, "status": "fail", "latency": latency, "error": f"HTTP {r.status_code}"})
                continue

            region = ""
            try:
                tr = requests.get(REGION_CHECK_URL, proxies={"https": proxy_addr, "http": proxy_addr}, timeout=8, verify=True)
                for line in tr.text.splitlines():
                    if line.startswith("loc="):
                        region = line.split("=", 1)[1].strip().upper()
                        break
            except Exception:
                pass

            if region in BLOCKED_REGIONS:
                results.append({**node, "status": "blocked", "latency": latency, "error": f"地区 {region} 不可用"})
                continue

            entry = {**node, "status": "ok", "latency": latency, "error": "", "region": region}
            results.append(entry)
            working.append({
                "name": node["name"], "port": port,
                "addr": f"http://127.0.0.1:{port}",
                "latency": latency, "region": region,
            })
        except Exception as e:
            results.append({**node, "status": "fail", "latency": 0, "error": str(e)[:80]})

    working.sort(key=lambda x: x["latency"])
    changed = generation != _subscription_generation
    if changed:
        results, working = [], []

    with _pool_lock:
        _proxy_pool = working
        _pool_index = 0

    with _test_lock:
        _test_status["running"] = False
        _test_status["progress"] = f"测试完成: {len(working)}/{len(nodes)} 可用"
        _test_status["results"] = results
        _test_status["updated_at"] = time.time()
        if changed:
            _test_status["progress"] = "订阅已更新，请重新检测"

    _save_pool()

    if callback:
        callback(results)

    return results


def test_nodes_async() -> dict:
    t = threading.Thread(target=test_nodes, daemon=True)
    t.start()
    return {"ok": True, "msg": "开始测试节点..."}


_PROXY_ERROR_KEYWORDS = (
    "SSLError", "SSL:", "SSL_", "UNEXPECTED_EOF",
    "Connection refused", "Connection timed out", "Connection reset",
    "Max retries exceeded",
    "curl: (28)", "curl: (35)", "curl: (7)", "curl: (56)",
    "ConnectTimeoutError", "ProxyError",
    "Couldn't connect to server",
)


def is_proxy_error(error_msg: str) -> bool:
    return any(kw in error_msg for kw in _PROXY_ERROR_KEYWORDS)


def disable_proxy(addr: str) -> bool:
    global _pool_index
    if not addr:
        return False
    with _pool_lock:
        removed = [p for p in _proxy_pool if p.get("addr") == addr]
        _proxy_pool[:] = [p for p in _proxy_pool if p.get("addr") != addr]
        if _pool_index >= len(_proxy_pool) and _proxy_pool:
            _pool_index = 0
    with _chatgpt_protocol_lock:
        pool = _chatgpt_protocol_status.get("pool") or []
        removed.extend(p for p in pool if p.get("addr") == addr)
        _chatgpt_protocol_status["pool"] = [p for p in pool if p.get("addr") != addr]
        for item in _chatgpt_protocol_status.get("results") or []:
            if item.get("addr") == addr:
                item.update(status="fail", error="代理连接失败，请重新检测")
    with _test_lock:
        for item in _test_status.get("results") or []:
            if item.get("addr") == addr:
                item.update(status="fail", error="代理连接失败，请重新检测")
    _save_pool()
    _save_chatgpt_protocol_pool()
    return bool(removed)
