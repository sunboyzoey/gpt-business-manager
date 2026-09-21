"""RoxyBrowser 指纹浏览器本地 API 客户端。

GPT PRO「升级 PRO」按钮勾选「指纹浏览器」时使用: 每次升级**新建**一个带指定代理的
浏览器 profile(dirId), 拿到 CDP 调试端口交给 DrissionPage 接管, 复用现有登录/checkout/
填卡逻辑; 处理完 close + delete 掉这个临时 profile(用完即删, 不留垃圾)。

代理由 GPT PRO 界面的「代理管理」维护(host/port/账号密码 + 备注), 也可从 RoxyBrowser
/proxy/list 导入; 升级时弹窗选一个, 通过 /browser/create 的 proxyInfo(custom) 塞给新窗口。

约束(来自 RoxyBrowser 官方):
- 所有请求头必须带 token(API Key); 默认 host http://127.0.0.1:50000;
- 不支持 headless, 故本模式必然有头运行;
- /browser/open 不能直接传代理 → 代理必须在 /browser/create 时定;
- /browser/open 返回 data.http(CDP 调试地址 127.0.0.1:PORT), DrissionPage 用它接管;
- /proxy/list 返回的代理没有备注字段 → 备注只存应用侧。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests


class RoxyBrowserError(RuntimeError):
    """RoxyBrowser API 调用失败(未启动 / token 错 / profile 不存在等)。"""


class RoxyBrowserClient:
    def __init__(self, api_host: str, token: str, *, timeout: int = 60):
        host = str(api_host or "").strip() or "http://127.0.0.1:50000"
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"http://{host}"
        self.base_url = host.rstrip("/")
        self.token = str(token or "").strip()
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "token": self.token,
        }

    def _post(self, path: str, payload: dict) -> dict:
        try:
            r = requests.post(
                f"{self.base_url}{path}", headers=self.headers,
                json=payload, timeout=self.timeout,
            )
        except Exception as exc:
            raise RoxyBrowserError(
                f"连接 RoxyBrowser 失败({self.base_url}{path}): {exc}. "
                "请确认 RoxyBrowser 已启动且 API 开关已开启。"
            ) from exc
        return self._parse(path, r)

    def _get(self, path: str, params: dict) -> dict:
        try:
            r = requests.get(
                f"{self.base_url}{path}", headers=self.headers,
                params=params, timeout=self.timeout,
            )
        except Exception as exc:
            raise RoxyBrowserError(
                f"连接 RoxyBrowser 失败({self.base_url}{path}): {exc}. "
                "请确认 RoxyBrowser 已启动且 API 开关已开启。"
            ) from exc
        return self._parse(path, r)

    def _parse(self, path: str, r) -> dict:
        try:
            data = r.json()
        except Exception as exc:
            raise RoxyBrowserError(f"RoxyBrowser 返回非 JSON: {r.text[:200]}") from exc
        if data.get("code") != 0:
            raise RoxyBrowserError(
                f"RoxyBrowser {path} 失败: code={data.get('code')} "
                f"msg={data.get('msg') or data.get('message')}"
            )
        return data.get("data", {}) or {}

    # ── 窗口(profile) ──
    def create_browser(self, workspace_id: int, *, window_name: str, proxy_info: dict,
                       os: str = "", os_version: str = "", core_version: str = "") -> dict:
        """新建一个浏览器 profile(带代理 + 指纹 OS/内核版本), 返回 {dirId, ...}。

        os: Windows|macOS|Linux|IOS|Android(默认 RoxyBrowser 侧 Windows);
        os_version: 依 os 而定(macOS 如 15.3.2, 留空=RoxyBrowser 取最新);
        core_version: 浏览器内核版本(如 138/137…, 留空=RoxyBrowser 默认)。
        不传指纹参数时 RoxyBrowser 用默认(可能是旧内核 → ChatGPT 新版页面点不动)。
        """
        payload: dict = {
            "workspaceId": workspace_id,
            "windowName": window_name or "",
            "proxyInfo": proxy_info,
        }
        if os:
            payload["os"] = os
        if os_version:
            payload["osVersion"] = os_version
        if core_version:
            payload["coreVersion"] = str(core_version)
        return self._post("/browser/create", payload)

    def open_window(self, workspace_id: int, dir_id: str) -> dict:
        """打开指定 profile, 返回 {ws, http, driver, ...}。headless 固定 False(不支持)。"""
        return self._post("/browser/open", {
            "workspaceId": workspace_id,
            "dirId": dir_id,
            "headless": False,
        })

    def close_window(self, dir_id: str) -> None:
        try:
            self._post("/browser/close", {"dirId": dir_id})
        except RoxyBrowserError:
            # 关窗失败(可能本就没开)不阻断主流程
            pass

    def delete_browser(self, workspace_id: int, dir_ids: list) -> None:
        """删除 profile(用完清理)。失败静默。"""
        try:
            self._post("/browser/delete", {
                "workspaceId": workspace_id, "dirIds": list(dir_ids),
            })
        except RoxyBrowserError:
            pass

    def list_browsers(self, workspace_id: int, *, page_index: int = 1, page_size: int = 200) -> list:
        """列出 workspace 下的所有 profile, 返回规范化 list(每项含 dirId / windowName ...)。"""
        data = self._get("/browser/list_v3", {
            "workspaceId": workspace_id, "page_index": page_index, "page_size": page_size,
        })
        return _extract_rows(data)

    def connection_info(self, dir_ids: Optional[list] = None) -> list:
        """当前**打开中**的 profile 列表(dirId/pid/ws/...)。dir_ids 为空 = 查所有打开的。"""
        params: dict = {}
        if dir_ids:
            params["dirIds"] = ",".join(str(x) for x in dir_ids)
        data = self._get("/browser/connection_info", params)
        return _extract_rows(data)

    # ── 工作区 ──
    def list_workspaces(self, *, page_index: int = 1, page_size: int = 50) -> list:
        """列出团队工作区, 返回规范化 list(每项含 id / workspaceName)。"""
        data = self._get("/browser/workspace", {
            "page_index": page_index, "page_size": page_size,
        })
        return _extract_rows(data)

    # ── 代理 ──
    def list_proxies(self, workspace_id: int, *, page_index: int = 1, page_size: int = 200) -> list:
        """列出 RoxyBrowser 里已配置的代理, 返回规范化 list。"""
        data = self._get("/proxy/list", {
            "workspaceId": workspace_id, "page_index": page_index, "page_size": page_size,
        })
        return _extract_rows(data)

    def detect_proxy(self, workspace_id: int, proxy_id: int) -> None:
        """触发 RoxyBrowser 对某代理做一次连通性检测(结果异步写回代理记录, 之后用 list_proxies 读)。"""
        self._post("/proxy/detect", {"workspaceId": workspace_id, "id": int(proxy_id)})


def _extract_rows(data: Any) -> list:
    """从 RoxyBrowser 列表返回里取出行数组(兼容 list / {list|rows|records|data|items:[...]})。"""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("list", "rows", "records", "data", "items"):
            v = data.get(key)
            if isinstance(v, list):
                return v
    return []


def _extract_debug_address(open_data: dict) -> str:
    """从 open_window 返回里取 DrissionPage 可接管的调试地址 127.0.0.1:PORT。

    优先 http 字段; 兜底从 ws (ws://127.0.0.1:PORT/devtools/...) 里解析 host:port。
    """
    http_addr = str(open_data.get("http") or "").strip()
    if http_addr:
        return http_addr.replace("http://", "").replace("https://", "").rstrip("/")

    ws = str(open_data.get("ws") or open_data.get("webSocketDebuggerUrl") or "").strip()
    if ws:
        parsed = urlparse(ws)
        if parsed.hostname and parsed.port:
            return f"{parsed.hostname}:{parsed.port}"
        m = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+)", ws)
        if m:
            return m.group(1)
    return ""


_VALID_PROXY_CATEGORY = {"HTTP", "HTTPS", "SOCKS5"}


def build_proxy_info(proxy: Optional[dict]) -> dict:
    """把应用侧代理 dict 转成 RoxyBrowser /browser/create 的 proxyInfo。

    一律用 custom(直接塞 host/port/账号密码)—— 实测该 RoxyBrowser 版本 /browser/create
    的 choose+moduleId 会返回 code=101 参数错误, 只有 custom 可用。无代理 → noproxy。
    """
    if not proxy or not str(proxy.get("host") or "").strip():
        return {"proxyMethod": "custom", "proxyCategory": "noproxy"}

    cat = str(proxy.get("protocol") or "SOCKS5").strip().upper()
    if cat not in _VALID_PROXY_CATEGORY:
        cat = "SOCKS5"
    return {
        "proxyMethod": "custom",
        "proxyCategory": cat,
        "host": str(proxy.get("host") or "").strip(),
        "port": str(proxy.get("port") or "").strip(),
        "proxyUserName": str(proxy.get("username") or ""),
        "proxyPassword": str(proxy.get("password") or ""),
    }


def proxy_label(proxy: Optional[dict]) -> str:
    if not proxy or not str(proxy.get("host") or "").strip():
        return "无代理"
    note = str(proxy.get("note") or "").strip()
    base = f"{proxy.get('host')}:{proxy.get('port')}"
    return f"{note}({base})" if note else base


def load_roxy_config() -> dict:
    """从 config_store 读 RoxyBrowser 配置, 返回规范化 dict。"""
    from core.config_store import config_store

    return {
        "api_host": str(config_store.get("roxybrowser_api_host", "http://127.0.0.1:50000") or "").strip()
        or "http://127.0.0.1:50000",
        "token": str(config_store.get("roxybrowser_api_token", "") or "").strip(),
        "workspace_id": str(config_store.get("roxybrowser_workspace_id", "") or "").strip(),
        # dir_id 已弃用(改为每次动态新建), 保留读取以兼容旧配置但不再必需
        "dir_id": str(config_store.get("roxybrowser_dir_id", "") or "").strip(),
        # 指纹:OS / 系统版本 / 内核版本。默认 macOS + 最新内核 138,
        # 避免默认(Windows + 旧内核)导致 ChatGPT 新版页面 JS 失效(按钮点不动)。
        "fp_os": str(config_store.get("roxybrowser_fp_os", "macOS") or "macOS").strip() or "macOS",
        "fp_os_version": str(config_store.get("roxybrowser_fp_os_version", "") or "").strip(),
        "fp_core_version": str(config_store.get("roxybrowser_fp_core_version", "138") or "138").strip() or "138",
    }


def resolve_workspace_id(*, persist: bool = True) -> int:
    """读取并校验 workspaceId; 未配置时用 token 自动发现。

    - 已配数字 → 直接用
    - 未配置且只有一个工作区 → 自动采用并持久化到 config(下次直接读)
    - 多个工作区 → 报错并列出各 id, 让用户手动指定
    """
    from core.config_store import config_store

    cfg = load_roxy_config()
    if not cfg["token"]:
        raise RoxyBrowserError("未配置 roxybrowser_api_token(RoxyBrowser -> API -> API Key)")
    raw = str(cfg["workspace_id"] or "").strip()
    if raw:
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise RoxyBrowserError(f"roxybrowser_workspace_id 非法: {raw!r}(需为数字)")

    # 未配置 → 用 token 自动发现工作区
    rows = RoxyBrowserClient(cfg["api_host"], cfg["token"]).list_workspaces()
    valid = [w for w in rows if str(w.get("id") or "").strip()]
    if not valid:
        raise RoxyBrowserError("RoxyBrowser 没有可用工作区, 请先在客户端创建团队/工作区")
    if len(valid) > 1:
        opts = ", ".join(
            f"{w.get('id')}={w.get('workspaceName') or w.get('name') or ''}" for w in valid
        )
        raise RoxyBrowserError(f"检测到多个工作区, 请在 设置→指纹浏览器 手动填 workspaceId: {opts}")
    wid = int(valid[0]["id"])
    if persist:
        try:
            config_store.set("roxybrowser_workspace_id", str(wid))
        except Exception:
            pass
    return wid


# ── 已关闭窗口自动清理(不管自动/手动关窗, 都从 RoxyBrowser 删掉我们创建的那个 profile) ──
# 只删「我们自己创建、且已记录 dirId」的窗口, 绝不碰用户手动建的 profile。
_GPTPRO_WINDOW_NAME = "gptpro-upgrade"      # 创建时的 windowName(仅便于人眼识别; 清扫不靠它)
_CREATE_GRACE = 90                          # 秒: 刚创建的窗口在此宽限期内不清扫(避开 create→open 竞态)
_recent_creates: dict = {}                  # dirId -> 创建时间戳
_recent_lock = threading.Lock()
_sweeper_started = False
_sweeper_lock = threading.Lock()

_TRACK_PATH = os.path.join(os.getcwd(), "data", "roxy_created_windows.json")
_track_lock = threading.Lock()


def _mark_created(dir_id: str) -> None:
    with _recent_lock:
        _recent_creates[str(dir_id)] = time.time()


def _recent_protected() -> set:
    now = time.time()
    with _recent_lock:
        for k in [k for k, v in _recent_creates.items() if now - v > _CREATE_GRACE]:
            _recent_creates.pop(k, None)
        return set(_recent_creates.keys())


def _track_load() -> list:
    try:
        with open(_TRACK_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return [str(x) for x in data] if isinstance(data, list) else []
    except Exception:
        return []


def _track_save(ids: list) -> None:
    try:
        os.makedirs(os.path.dirname(_TRACK_PATH), exist_ok=True)
        tmp = f"{_TRACK_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(list(dict.fromkeys(str(x) for x in ids)), fh)
        os.replace(tmp, _TRACK_PATH)
    except Exception:
        pass


def _track_add(dir_id: str) -> None:
    with _track_lock:
        ids = _track_load()
        if str(dir_id) not in ids:
            ids.append(str(dir_id))
            _track_save(ids)


def _track_remove(dir_ids) -> None:
    rm = {str(x) for x in dir_ids}
    with _track_lock:
        ids = [x for x in _track_load() if x not in rm]
        _track_save(ids)


def cleanup_closed_gptpro_windows(*, log=None) -> int:
    """删除所有**已关闭**的、由本工具创建并记录了 dirId 的 RoxyBrowser 窗口。

    - 只处理我们跟踪的 dirId, 绝不碰用户自己建的 profile
    - 正在打开的窗口不删(connection_info 判定); 刚创建的窗口宽限期内不删
    - 已不存在(被别处删过)的 dirId 从跟踪表清掉
    - 未配置 / RoxyBrowser 未启动 / 任何异常 → 静默返回 0
    """
    _log = log or (lambda m: None)
    tracked = _track_load()
    if not tracked:
        return 0
    try:
        cfg = load_roxy_config()
        if not cfg["token"] or not str(cfg["workspace_id"] or "").strip():
            return 0
        ws = int(cfg["workspace_id"])
    except Exception:
        return 0
    client = RoxyBrowserClient(cfg["api_host"], cfg["token"])
    try:
        existing: list = []
        page = 1
        while page <= 50:
            batch = client.list_browsers(ws, page_index=page, page_size=200)
            if not batch:
                break
            existing.extend(batch)
            if len(batch) < 200:
                break
            page += 1
        existing_ids = {str(r.get("dirId")) for r in existing}
    except Exception:
        return 0
    try:
        open_ids = {str(r.get("dirId")) for r in client.connection_info()}
    except Exception:
        open_ids = set()
    protected = _recent_protected()
    gone = [d for d in tracked if d not in existing_ids]                 # 已不存在 → 只从跟踪表清
    to_delete = [
        d for d in tracked
        if d in existing_ids and d not in open_ids and d not in protected
    ]
    if to_delete:
        try:
            client.delete_browser(ws, to_delete)
            _log(f"[RoxyBrowser] 已清理关闭的窗口 {len(to_delete)} 个: {to_delete}")
        except Exception:
            to_delete = []
    if gone or to_delete:
        _track_remove(gone + to_delete)
    return len(to_delete)


def ensure_cleanup_sweeper(*, interval: int = 45, log=None) -> None:
    """启动后台清扫线程(幂等): 每 interval 秒把已关闭的本工具窗口从 RoxyBrowser 删掉。"""
    global _sweeper_started
    with _sweeper_lock:
        if _sweeper_started:
            return
        _sweeper_started = True

    def _loop():
        while True:
            try:
                cleanup_closed_gptpro_windows(log=log)
            except Exception:
                pass
            time.sleep(max(15, int(interval)))

    threading.Thread(target=_loop, name="roxy-window-sweeper", daemon=True).start()


class RoxyBrowserSession:
    """新建一个带指定代理的 RoxyBrowser 窗口并交给 DrissionPage 接管的一次会话。

    用法:
        with RoxyBrowserSession(proxy=proxy_dict, log=log) as page:
            ... 用 page 跑登录/checkout ...
    或手动:
        sess = RoxyBrowserSession(proxy=proxy_dict, log=log); page = sess.open(); ...; sess.close()

    open()  → /browser/create(带代理) → 拿新 dirId → /browser/open → ChromiumPage 接管。
    close() → /browser/close + /browser/delete, 处理完自动关窗并删掉临时 profile。
    """

    def __init__(self, *, proxy: Optional[dict] = None, window_name: str = "", log=None):
        self._log = log or (lambda m: print(m, flush=True))
        self.cfg = load_roxy_config()
        self.proxy = proxy
        self.window_name = str(window_name or "").strip() or _GPTPRO_WINDOW_NAME
        self._client: Optional[RoxyBrowserClient] = None
        self._workspace_id: Optional[int] = None
        self.dir_id = ""   # 动态创建后填入
        self.page = None

    def validate(self) -> None:
        if not self.cfg["token"]:
            raise RoxyBrowserError("未配置 roxybrowser_api_token(RoxyBrowser -> API -> API Key)")
        # workspaceId 未配置时自动发现(单工作区自动采用并持久化)
        self._workspace_id = resolve_workspace_id(persist=True)

    def open(self):
        """新建带代理窗口 → DrissionPage 接管, 返回 ChromiumPage。"""
        from DrissionPage import ChromiumPage

        self.validate()
        assert self._workspace_id is not None
        self._client = RoxyBrowserClient(self.cfg["api_host"], self.cfg["token"])

        proxy_info = build_proxy_info(self.proxy)
        fp_os = str(self.cfg.get("fp_os") or "")
        fp_os_ver = str(self.cfg.get("fp_os_version") or "")
        fp_core = str(self.cfg.get("fp_core_version") or "")
        self._log(f"[RoxyBrowser] 新建窗口(代理 {proxy_label(self.proxy)}; "
                  f"指纹 os={fp_os or '默认'} osVer={fp_os_ver or '最新'} core={fp_core or '默认'})…")
        create_data = self._client.create_browser(
            self._workspace_id, window_name=self.window_name, proxy_info=proxy_info,
            os=fp_os, os_version=fp_os_ver, core_version=fp_core,
        )
        self.dir_id = str(create_data.get("dirId") or create_data.get("dir_id") or "").strip()
        if not self.dir_id:
            raise RoxyBrowserError(f"RoxyBrowser 创建窗口未返回 dirId: {create_data!r}")

        _track_add(self.dir_id)                  # 持久记录: 这是我们创建的窗口, 关闭后要删
        _mark_created(self.dir_id)               # 宽限保护, 避免 create→open 竞态被后台清扫误删
        ensure_cleanup_sweeper(log=self._log)    # 启动后台清扫(幂等): 窗口一旦关闭就自动删除记录
        self._log(f"[RoxyBrowser] 已创建 profile dirId={self.dir_id}, 打开窗口…")
        open_data = self._client.open_window(self._workspace_id, self.dir_id)
        addr = _extract_debug_address(open_data)
        if not addr:
            # 打开失败也要把刚建的 profile 删掉, 避免残留
            self._client.delete_browser(self._workspace_id, [self.dir_id])
            raise RoxyBrowserError(f"RoxyBrowser 未返回可用调试地址: {open_data!r}")
        self._log(f"[RoxyBrowser] DrissionPage 接管 CDP 地址 {addr}")
        self.page = ChromiumPage(addr_or_opts=addr)
        return self.page

    def close(self) -> None:
        """关窗 + 删除临时 profile(下一个账号前调用, 实现自动退出+清理)。"""
        if self._client is not None and self.dir_id and self._workspace_id is not None:
            self._log(f"[RoxyBrowser] 处理完成, 关闭并删除临时 profile dirId={self.dir_id}")
            self._client.close_window(self.dir_id)
            self._client.delete_browser(self._workspace_id, [self.dir_id])
            _track_remove([self.dir_id])
        self.page = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def open_existing_window(dir_id: str, *, log=None):
    """打开一个**已存在**的 RoxyBrowser profile(不新建、不改代理、不删),返回 ChromiumPage。

    用于「登录 Claude」:重开注册时保留的同一 profile。代理沿用该 profile 创建时
    绑定的代理(RoxyBrowser 把代理绑在 profile 上,/browser/open 不碰代理),
    因此重开必然是注册时那个代理。
    """
    from DrissionPage import ChromiumPage

    _log = log or (lambda m: print(m, flush=True))
    did = str(dir_id or "").strip()
    if not did:
        raise RoxyBrowserError("缺少 dirId,无法打开已存在窗口")
    cfg = load_roxy_config()
    if not cfg["token"]:
        raise RoxyBrowserError("未配置 roxybrowser_api_token(RoxyBrowser -> API -> API Key)")
    ws = resolve_workspace_id(persist=True)
    client = RoxyBrowserClient(cfg["api_host"], cfg["token"])
    _mark_created(did)   # 宽限保护:避免刚打开就被后台清扫误删(即便已 untrack 也无害)
    _log(f"[RoxyBrowser] 打开已存在 profile dirId={did}…")
    open_data = client.open_window(ws, did)
    addr = _extract_debug_address(open_data)
    if not addr:
        raise RoxyBrowserError(f"打开已存在窗口失败,未返回调试地址: {open_data!r}")
    _log(f"[RoxyBrowser] DrissionPage 接管 CDP 地址 {addr}")
    return ChromiumPage(addr_or_opts=addr)
