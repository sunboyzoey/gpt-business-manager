"""Bounded local Chromium startup with task-owned process/profile cleanup.

DrissionPage may launch Chrome and raise before returning a page. Launching the
process ourselves retains ownership in that case. Drission only attaches to the
verified browser's unique WebSocket URL; it cannot spawn a late replacement.
No process-name/global Chrome kill and no user-profile cleanup is permitted.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse

import psutil


_REASONS = {
    "cdp_not_ready": "本地调试接口未就绪",
    "browser_connect_error": "本地浏览器连接失败",
    "browser_attach_timeout": "浏览器接管超时",
    "process_exited": "浏览器进程提前退出",
    "configuration_error": "启动配置不可用",
    "initialization_failed": "浏览器初始化未完成",
}
_TRANSIENT = {"cdp_not_ready", "browser_connect_error", "browser_attach_timeout", "process_exited"}
_PROFILE_PREFIX = "any-register-browser-"


class BrowserInitializationError(RuntimeError):
    """Credential-free pre-navigation failure; callers must honor both gates."""
    code = "browser_init_failed"
    stage = "browser_init"

    def __init__(self, reason="initialization_failed", *, attempts=1, cleanup_complete=False):
        self.reason = reason if reason in _REASONS else "initialization_failed"
        self.attempts = int(attempts)
        self.cleanup_complete = cleanup_complete is True
        self.retryable = self.cleanup_complete and self.reason in _TRANSIENT
        if not self.cleanup_complete:
            message = "浏览器清理未确认，已停止自动重试"
        elif self.retryable:
            message = "本地浏览器启动暂时失败，已清理本次启动进程"
        elif self.reason == "configuration_error":
            message = "浏览器启动配置错误，已停止自动重试"
        else:
            message = "本地浏览器初始化失败，已停止自动重试"
        super().__init__(f"{message}（{_REASONS[self.reason]}）")


def _log(log, message):
    if callable(log):
        try:
            log(f"[浏览器初始化] {message}")
        except Exception:
            pass


def _cleanup_owned(owner):
    try:
        return owner.cleanup() is True
    except Exception:
        # Cleanup failure must not be masked by a retryable connection error,
        # and implementation exception text must not enter account task logs.
        return False


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def _executable(options):
    from DrissionPage._functions.browser import get_chrome_path

    def candidates():
        # Deployment overrides must win over ChromiumOptions' default "chrome".
        for key in ("DRISSION_BROWSER_PATH", "CHROME_PATH", "CHROMIUM_PATH", "GOOGLE_CHROME_SHIM"):
            yield os.environ.get(key, "")
        yield options.browser_path
        # DrissionPage does not discover every Linux distribution's binary name.
        yield from ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
        # Discover lazily: a valid explicit path does not need an ini/platform scan.
        try:
            yield get_chrome_path(options.ini_path)
        except (OSError, RuntimeError):
            # Missing/inaccessible platform configuration is a missing browser,
            # with the same actionable diagnostic as an empty discovery result.
            return

    for value in candidates():
        if not value:
            continue
        value = os.path.expanduser(str(value).strip())
        path = shutil.which(value) or value
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return str(Path(path).resolve())
    raise FileNotFoundError("没有可用的本地 Chromium 可执行文件")


class _OwnedBrowser:
    def __init__(self):
        self.port = _free_port()
        self.profile = Path(tempfile.mkdtemp(prefix=_PROFILE_PREFIX)).resolve()
        self.profile_identity = self.profile.stat().st_dev, self.profile.stat().st_ino
        self.process = None
        self.started_at = time.time()
        self.known = {}
        self.uncertain = False
        self._lock = threading.RLock()

    def launch(self, options):
        from DrissionPage._functions.browser import get_launch_args, set_flags, set_prefs
        options.auto_port(False)
        options.new_env(False)
        options.use_system_user_path(False)
        options.set_local_port(self.port)
        options.set_user_data_path(str(self.profile))
        options.set_argument("--remote-debugging-address", "127.0.0.1")
        options.existing_only(True)
        args, _ = get_launch_args(options)
        # Do not inherit a pipe, app URL or positional startup navigation.
        args = [arg for arg in args if arg.startswith("--")
                and not arg.startswith(("--remote-debugging-pipe", "--app="))]
        set_prefs(options)
        set_flags(options)
        command = [_executable(options), f"--remote-debugging-port={self.port}", *args, "about:blank"]
        self.started_at = time.time()
        self.process = subprocess.Popen(command, shell=False, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, start_new_session=os.name != "nt")
        self._capture()

    def _identity(self, process):
        try:
            return process.pid, process.create_time()
        except psutil.NoSuchProcess:
            return None

    def _matches_profile(self, process):
        try:
            command = process.cmdline()
            return (process.create_time() >= self.started_at - 1
                    and f"--user-data-dir={self.profile}" in command
                    and all(arg == f"--remote-debugging-port={self.port}" for arg in command
                            if arg.startswith("--remote-debugging-port=")))
        except psutil.NoSuchProcess:
            return False

    def _capture(self):
        """Record exact birth identities while ancestry is still available."""
        if self.process is None:
            return
        try:
            root = psutil.Process(self.process.pid)
            if root.pid in self.known and root.create_time() != self.known[root.pid]:
                return  # The original process exited and its PID was reused.
            if (self._matches_profile(root)
                    and f"--remote-debugging-port={self.port}" in root.cmdline()):
                identity = self._identity(root)
                if identity:
                    self.known[identity[0]] = identity[1]
                for child in root.children(recursive=True):
                    identity = self._identity(child)
                    if identity and identity[0] not in self.known:
                        self.known[identity[0]] = identity[1]
            elif self.process.poll() is None:
                self.uncertain = True
        except psutil.NoSuchProcess:
            pass
        except (psutil.AccessDenied, OSError):
            self.uncertain = True

    def _live(self):
        live = []
        for pid, born in list(self.known.items()):
            try:
                process = psutil.Process(pid)
                if process.create_time() == born and process.status() != psutil.STATUS_ZOMBIE:
                    live.append(process)
            except psutil.NoSuchProcess:
                pass
            except (psutil.AccessDenied, OSError):
                self.uncertain = True
        return live

    def owns_listener(self):
        self._capture()
        for process in self._live():
            try:
                connections = process.net_connections(kind="tcp")
                if any(item.status == psutil.CONN_LISTEN and item.laddr.port == self.port
                       and item.laddr.ip in {"127.0.0.1", "::1"} for item in connections):
                    return True
            except psutil.NoSuchProcess:
                pass
            except (psutil.AccessDenied, OSError):
                # Lack of port ownership proof is not permission to attach.
                continue
        return False

    def _find_profile_orphans(self):
        # Chrome children may outlive their parent. Only this random, exclusively
        # created profile plus a post-launch birth time can identify such orphans.
        for process in psutil.process_iter():
            try:
                if self._matches_profile(process):
                    identity = self._identity(process)
                    if identity and identity[0] not in self.known:
                        self.known[identity[0]] = identity[1]
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

    def cleanup(self):
        with self._lock:
            self._capture()
            if self.process is not None:
                self._find_profile_orphans()
            live = self._live()
            for process in live:
                try:
                    if process.create_time() == self.known.get(process.pid):
                        process.terminate()
                except psutil.NoSuchProcess:
                    pass
                except (psutil.AccessDenied, OSError):
                    self.uncertain = True
            _, remaining = psutil.wait_procs(live, timeout=1.5)
            for process in remaining:
                try:
                    if process.create_time() == self.known.get(process.pid):
                        process.kill()
                except psutil.NoSuchProcess:
                    pass
                except (psutil.AccessDenied, OSError):
                    self.uncertain = True
            psutil.wait_procs(remaining, timeout=1.0)
            if self.process is not None:
                try:
                    self.process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    self.uncertain = True
                self._find_profile_orphans()
            if self.uncertain or self._live():
                return False
            try:
                metadata = self.profile.lstat()
            except FileNotFoundError:
                return True
            if (not stat.S_ISDIR(metadata.st_mode) or self.profile.is_symlink()
                    or (metadata.st_dev, metadata.st_ino) != self.profile_identity
                    or not self.profile.name.startswith(_PROFILE_PREFIX)):
                return False
            try:
                shutil.rmtree(self.profile)
                return True
            except OSError:
                return False


def _local_json(port, path, timeout):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("本地调试接口响应无效")
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("本地调试接口响应过大")
        return json.loads(data)
    finally:
        connection.close()


def _wait_ready(owner, deadline):
    while time.monotonic() < deadline:
        if owner.process.poll() is not None:
            raise BrowserInitializationError("process_exited")
        try:
            if owner.owns_listener():
                timeout = min(0.5, max(0.01, deadline - time.monotonic()))
                version = _local_json(owner.port, "/json/version", timeout)
                tabs = _local_json(owner.port, "/json", timeout)
                ws = version.get("webSocketDebuggerUrl", "")
                parsed = urlparse(ws)
                if (parsed.scheme == "ws" and parsed.hostname in {"127.0.0.1", "localhost"}
                        and parsed.port == owner.port
                        and re.fullmatch(r"/devtools/browser/[A-Za-z0-9-]+", parsed.path)
                        and isinstance(tabs, list) and any(isinstance(tab, dict) and tab.get("type") == "page" for tab in tabs)):
                    return ws
        except (OSError, ValueError, KeyError, AttributeError, http.client.HTTPException):
            pass
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise BrowserInitializationError("cdp_not_ready")


def _bounded_ready(owner, deadline):
    # Even a server trickling incomplete HTTP headers must not outlive the
    # caller's startup budget. The worker cannot create or attach any browser.
    done = threading.Event()
    result = {}
    def probe():
        try:
            result["websocket"] = _wait_ready(owner, deadline)
        except Exception as exc:
            result["error"] = exc
        finally:
            done.set()
    threading.Thread(target=probe, name="owned-browser-ready", daemon=True).start()
    if not done.wait(max(0, deadline - time.monotonic())):
        raise BrowserInitializationError("cdp_not_ready")
    if "error" in result:
        raise result["error"]
    return result["websocket"]


def _attach(options, page_factory, initialize, owner, deadline):
    done, cancelled = threading.Event(), threading.Event()
    result = {}

    def run():
        try:
            page = page_factory(addr_or_opts=options)
            if not cancelled.is_set() and initialize is not None:
                initialize(page)
            result["page"] = page
        except Exception as exc:
            result["error"] = exc
        finally:
            if cancelled.is_set():
                _cleanup_owned(owner)
            done.set()

    threading.Thread(target=run, name="owned-browser-attach", daemon=True).start()
    if not done.wait(max(0, deadline - time.monotonic())):
        cancelled.set()
        raise BrowserInitializationError("browser_attach_timeout")
    if "error" in result:
        raise result["error"]
    return result["page"]


def _wrap_quit(page, owner):
    original = page.quit

    def quit_owned(*_args, **_kwargs):
        done = threading.Event()
        def close():
            try:
                # Never let Drission force-kill or delete an inferred profile.
                original(timeout=1, force=False, del_data=False)
            except Exception:
                pass
            finally:
                done.set()
        threading.Thread(target=close, name="owned-browser-close", daemon=True).start()
        done.wait(1.5)
        return _cleanup_owned(owner)

    page.quit = quit_owned
    # Retain ownership when a caller keeps the page open for manual work.
    page._task_browser_owner = owner
    return page


def start_local_browser(options_factory, *, page_factory=None, initialize=None, log=None,
                        timeout=25.0, max_attempts=2):
    """Only blank-browser initialization is retried, never login/account work."""
    from DrissionPage import ChromiumPage
    from DrissionPage.errors import BrowserConnectError
    if not 0 < timeout <= 60 or type(max_attempts) is not int or not 1 <= max_attempts <= 2:
        raise ValueError("浏览器启动超时或重试次数超出安全范围")
    page_factory = page_factory or ChromiumPage
    for attempt in range(1, max_attempts + 1):
        owner = None
        try:
            _log(log, f"准备独立临时配置（第 {attempt}/{max_attempts} 次）")
            deadline = time.monotonic() + timeout
            owner = _OwnedBrowser()
            options = options_factory()
            owner.launch(options)
            _log(log, "Chrome 已启动，等待本任务本地调试接口")
            websocket = _bounded_ready(owner, deadline)
            options.set_address(websocket)
            _log(log, "本地调试接口已核验，正在接管空白页")
            page = _attach(options, page_factory, initialize, owner, deadline)
            page = _wrap_quit(page, owner)
            _log(log, "浏览器初始化完成")
            return page
        except BaseException as exc:
            if not isinstance(exc, Exception):
                if owner is not None:
                    _cleanup_owned(owner)
                raise
            if isinstance(exc, BrowserInitializationError):
                reason = exc.reason
            elif isinstance(exc, BrowserConnectError):
                reason = "browser_connect_error"
            elif isinstance(exc, (FileNotFoundError, PermissionError, ValueError)):
                reason = "configuration_error"
            else:
                reason = "initialization_failed"
            cleaned = _cleanup_owned(owner) if owner is not None else True
            error = BrowserInitializationError(reason, attempts=attempt, cleanup_complete=cleaned)
            _log(log, str(error))
            if not error.retryable or attempt == max_attempts:
                raise error from None
            _log(log, "仅重试本地空白浏览器启动，使用新的临时配置和端口")
