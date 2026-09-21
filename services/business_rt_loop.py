"""BUSINESS RT 长跑注册 runner（进程单例）。

跟 api/tasks.py 的"任务"形式不同：开始即跑、跑到所有 BUSINESS 域名满或人为停止。
管理 4 个新状态的账号（pending_rt / pending_seat_switch / ready_for_export / rt_unreachable），
提供批量「一键补 RT」/「一键改席位」/「导出 + 硬删除」。

复用：
- core.db.BusinessDomainModel（verified BUSINESS 子域池,与设备解耦）
- platforms.chatgpt.plugin._register_business_oauth（raise_on_failure=False）
- platforms.chatgpt.plugin._acquire_rt_via_oauth_login（单账号补 RT）
- core.db.save_account / list_accounts_paginated
"""
from __future__ import annotations

import collections
import json
import os
import random
import threading
import time
import traceback
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, Future, as_completed, wait
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from core.base_platform import Account, AccountStatus, RegisterConfig
from core.db import (
    AccountModel,
    BusinessDomainModel,
    TaskLog,
    engine,
    save_account,
    count_accounts_by_status,
    list_accounts_paginated,
)


_PLATFORM = "chatgpt"
_EXPORT_ROOT = os.path.abspath(os.path.join(os.getcwd(), "exports", "business_rt_loop"))
_TOTP_MIGRATION_BLOCKED_ERROR = (
    "检测到待 RT 账号已启用或正在确认 ChatGPT Authenticator 2FA；"
    "当前迁移包不传输安全凭据，为防目标机无法登录，"
    "已取消本次导出且未删除任何源记录"
)
_TOTP_STATUS_UNAVAILABLE_ERROR = (
    "无法核验待 RT 账号的 ChatGPT TOTP 安全状态；"
    "为防迁移后丢失登录凭据，已取消本次导出且未删除任何源记录"
)
_WORKER_TIMEOUT_SECONDS_DEFAULT = 300
_WORKER_TIMEOUT_SECONDS_MIN = 60
_WORKER_TIMEOUT_SECONDS_MAX = 1800
_WORKER_HEARTBEAT_SECONDS = 30
_PROXY_PRIORITY_MANUAL_FIRST = "manual_first"
_PROXY_PRIORITY_PROTOCOL_POOL_FIRST = "protocol_pool_first"
_PROXY_PRIORITY_SUBSCRIPTION_FIRST = "subscription_first"

# 子域自动 rotation: 满子域回收 + 池子下限补新
_ROTATION_TARGET_POOL_SIZE = 10           # 未满未 banned 子域数 < 这个值时补新
_ROTATION_MIN_INTERVAL_SECONDS = 60       # 两次 rotation 至少间隔 60s, 避免触发 CF/OpenAI 风控
_ROTATION_CHECK_INTERVAL_SECONDS = 30     # daemon thread 巡检周期
_DOMAIN_RECHECK_SECONDS = 10.0            # 无可用注册域名时不停止,等待后重查 verified 子域池
_SUBMIT_INTERVAL_MS_DEFAULT = 800         # worker 补位间隔,错开 /signin 和 send_otp 瞬时压力
_SUBMIT_INTERVAL_MS_MAX = 10000
_OTP_TIMEOUT_STREAK_THRESHOLD_DEFAULT = 5
_DOMAIN_FAILURE_LIMIT_DEFAULT = 20
_DOMAIN_FAILURE_PAUSE_SECONDS_DEFAULT = 60
_DOMAIN_FAILURE_PAUSE_SECONDS_MAX = 3600
_DOMAIN_RECENT_OUTCOME_WINDOW = 20
_DOMAIN_FATIGUED_FAILURE_THRESHOLD = 3
_DOMAIN_HIGH_RISK_FAILURE_THRESHOLD = 8
_DOMAIN_REPLACE_FAILURE_THRESHOLD = 12
_DOMAIN_HIGH_RISK_RECOVERY_SUCCESS_STREAK = 3
_DOMAIN_FATIGUE_RECOVERY_SUCCESS_STREAK = 5
_DOMAIN_HEALTHY_RECENT_SUCCESS_RATE = 0.70
# protocol 模式默认不启动浏览器,可默认 20 并发；切到 DrissionPage 时界面可手动调低。
_AUTO_RT_CONCURRENCY_DEFAULT = 20
# 连续 N 次 stage=otp 失败的账号判定为「OTP 链路不可达」,直接转 rt_unreachable
# 避免在收不到新 OTP 的导入号上无限消耗代理 / 邮件 / OpenAI 配额
_RT_OTP_FAIL_STREAK_TO_UNREACHABLE = 2
_RT_OAUTH_BROWSER_MODE_DEFAULT = "protocol"
_RT_OAUTH_BROWSER_MODES = {"protocol", "headless", "headed"}


def _machine_id_or_unknown() -> str:
    try:
        from core.machine_id import current_machine_id
        return current_machine_id()
    except Exception:
        return "unknown"


def _dynamic_proxy_snapshot() -> dict[str, Any]:
    """供 status 接口返回, 让前端展示「代理模式: 动态住宅/静态池」Tag。"""
    try:
        from core.config_store import config_store
        from core.dynamic_proxy import pool_snapshot
        enabled_raw = str(config_store.get("dynamic_proxy_enabled", "0") or "0").strip().lower()
        enabled = enabled_raw in {"1", "true", "yes", "on"}
        api_url = str(config_store.get("dynamic_proxy_api_url", "") or "").strip()
        via = str(config_store.get("dynamic_proxy_api_via", "") or "").strip()
        # 摘要 host (省略 query)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(api_url)
            host_summary = parsed.netloc or ""
        except Exception:
            host_summary = ""
        return {
            "enabled": enabled,
            "configured": bool(api_url),
            "api_host": host_summary,
            "via_proxy": via or "(直连)",
            "pool": pool_snapshot(),
        }
    except Exception:
        return {"enabled": False, "configured": False, "api_host": "", "via_proxy": "", "pool": {}}
_PROXY_PRIORITY_LABELS = {
    _PROXY_PRIORITY_MANUAL_FIRST: "手动代理优先",
    _PROXY_PRIORITY_PROTOCOL_POOL_FIRST: "ChatGPT预检池优先",
    _PROXY_PRIORITY_SUBSCRIPTION_FIRST: "订阅代理池优先",
}
_CLEARABLE_STATUS_LABELS = {
    AccountStatus.PENDING_INVITE.value: "待邀请",
    AccountStatus.PENDING_ACTIVATE.value: "待激活",
    AccountStatus.PENDING_SEAT_CHANGE.value: "待切席位",
    AccountStatus.PENDING_RT.value: "待 RT",
    AccountStatus.PENDING_SEAT_SWITCH.value: "待改席位(旧)",
    AccountStatus.RT_UNREACHABLE.value: "RT 不可达",
}
_PENDING_RT_MIGRATION_SCHEMA = "business_rt_pending_migration_v1"
_DOMAIN_AUTO_DELETE_BLOCKING_STATUSES = (
    AccountStatus.PENDING_INVITE.value,
    AccountStatus.PENDING_ACTIVATE.value,
    AccountStatus.PENDING_SEAT_CHANGE.value,
    AccountStatus.PENDING_RT.value,
    AccountStatus.PENDING_SEAT_SWITCH.value,
)


@dataclass
class _Counters:
    success: int = 0
    rt_failed: int = 0
    seat_failed: int = 0
    errors: int = 0
    attempts: int = 0
    domain_banned: int = 0  # 检测到 OpenAI Access Deactivated 自动拉黑的子域数量


@dataclass
class _RunnerState:
    state: str = "idle"  # idle | running | stopped | quota_exhausted | error
    started_at: str | None = None
    stopped_at: str | None = None
    last_error: str = ""
    counters: _Counters = field(default_factory=_Counters)
    config: dict[str, Any] = field(default_factory=dict)


class BusinessRTLoopRunner:
    """进程级单例。线程安全。"""

    _instance: "BusinessRTLoopRunner | None" = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "BusinessRTLoopRunner":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._state = _RunnerState()
        self._executor: ThreadPoolExecutor | None = None
        self._daemon: threading.Thread | None = None
        self._logs: collections.deque[str] = collections.deque(maxlen=500)
        self._register_logs: collections.deque[str] = collections.deque(maxlen=500)
        self._rt_logs: collections.deque[str] = collections.deque(maxlen=500)
        # 域名级配额跟踪(进程内,replace 设备配额体系)
        self._domain_lock = threading.Lock()
        self._domain_used: dict[str, int] = {}   # hostname -> 已用数
        self._domain_inflight: dict[str, int] = {}  # hostname -> 进行中数
        self._domain_reservations: dict[str, str] = {}  # reservation_id -> hostname
        # 检测到 OpenAI 风控的死域(本进程内即时共享给所有 worker)
        # 任一 worker 收到 trustandsafety / Deactivated 邮件后会 _mark_domain_banned,
        # 其它 worker 下次 _reserve_next_domain 立即跳过。
        # 同时持久化到 BusinessDomainModel.status='banned'.
        self._domain_banned: set[str] = set()
        # OTP silent throttle 软判定:
        #   连续 OTP 超时达到阈值 -> 记 1 次域名失败并短暂停顿
        #   域名失败次数达到阈值 -> 拉黑该 BUSINESS 子域
        self._domain_otp_timeout_streak: dict[str, int] = {}
        self._domain_failure_counts: dict[str, int] = {}
        self._domain_paused_until: dict[str, float] = {}
        # 域名健康恢复指标:
        #   success_streak 用于把"高风险"降回"疲劳"
        #   recent_outcomes 用于显示最近窗口成功率,避免只看累计失败误判
        self._domain_success_streak: dict[str, int] = {}
        self._domain_recent_outcomes: dict[str, collections.deque[str]] = {}
        # 子域自动 rotation: 由独立 daemon 线程串行调度 create_domain / delete_domain,
        # 避免 worker 并发触发 CF API rate-limit 或 OpenAI workspace 风控
        self._rotation_thread: threading.Thread | None = None
        self._rotation_stop = threading.Event()
        self._last_rotation_at: float = 0.0
        self._rotation_state: dict[str, Any] = {
            "enabled": False,
            "last_action_at": "",
            "last_action": "",
            "last_error": "",
            "target_pool_size": _ROTATION_TARGET_POOL_SIZE,
            "deleted_count": 0,
            "created_count": 0,
        }
        # fixup 批次进度（一次只能跑一个 batch,UI 通过 status 接口轮询）
        self._fixup_lock = threading.Lock()
        self._fixup_progress: dict[str, Any] = {
            "action": "",   # "fixup-rt" | "fixup-seat" | "rt-health-check" | ""
            "running": False,
            "total": 0,
            "done": 0,
            "success": 0,
            "failed": 0,
            "healthy": 0,
            "faulty": 0,
            "unknown": 0,
            "refreshed": 0,
            "started_at": "",
            "finished_at": "",
        }
        # 导入迁移包后的子域校验进度(导入完账号 → 异步跑 ensure_subdomain_verified)
        self._import_progress_lock = threading.Lock()
        self._import_progress: dict[str, Any] = {
            "running": False,
            "total": 0,
            "done": 0,
            "ok": 0,
            "failed": 0,
            "current_hostname": "",
            "started_at": "",
            "finished_at": "",
            "results": [],  # list of {hostname, ok, action, reason}
        }
        self._auto_rt_lock = threading.Lock()
        self._auto_rt_stop_event = threading.Event()
        self._auto_rt_thread: threading.Thread | None = None
        self._auto_rt_state: dict[str, Any] = {
            "running": False,
            "stopping": False,
            "concurrency": _AUTO_RT_CONCURRENCY_DEFAULT,
            "poll_interval_seconds": 3.0,
            "inflight": 0,
            "claimed": 0,
            "success": 0,
            "failed": 0,
            "uploaded": 0,
            "upload_failed": 0,
            "started_at": "",
            "stopped_at": "",
            "last_scan_at": "",
            "last_error": "",
            "rt_retry_limit_enabled": False,
            "max_retries": 5,
        }
        # 新流程 daemon: 邀请(单线程批量)
        self._invite_lock = threading.Lock()
        self._invite_stop_event = threading.Event()
        self._invite_thread: threading.Thread | None = None
        self._invite_state: dict[str, Any] = {
            "running": False,
            "stopping": False,
            "batch_size": 6,
            "batch_interval_seconds": 10.0,
            "batches": 0,
            "invited": 0,
            "failed": 0,
            "last_scan_at": "",
            "started_at": "",
            "stopped_at": "",
            "last_error": "",
        }
        # 新流程 daemon: 激活 (PENDING_ACTIVATE → PENDING_SEAT_CHANGE, 多并发)
        self._activate_lock = threading.Lock()
        self._activate_stop_event = threading.Event()
        self._activate_thread: threading.Thread | None = None
        self._activate_state: dict[str, Any] = {
            "running": False, "stopping": False,
            "concurrency": 5,
            "inflight": 0, "claimed": 0, "success": 0, "failed": 0,
            "started_at": "", "stopped_at": "", "last_scan_at": "", "last_error": "",
        }
        # 新流程 daemon: 切席位 (PENDING_SEAT_CHANGE → PENDING_RT, 多并发)
        self._seat_change_lock = threading.Lock()
        self._seat_change_stop_event = threading.Event()
        self._seat_change_thread: threading.Thread | None = None
        self._seat_change_state: dict[str, Any] = {
            "running": False, "stopping": False,
            "concurrency": 5,
            "inflight": 0, "claimed": 0, "success": 0, "failed": 0,
            "started_at": "", "stopped_at": "", "last_scan_at": "", "last_error": "",
        }

    # ------------------------------------------------------------------ logs

    @staticmethod
    def _infer_log_channel(msg: str, thread_name: str) -> str:
        text = str(msg or "")
        name = str(thread_name or "")
        if (
            name.startswith("biz-auto-rt")
            or name.startswith("biz-rt-fixup")
            or "自动补 RT" in text
            or "一键补 RT" in text
            or "[补 RT" in text
            or "[RT健康" in text
            or "RT 健康" in text
        ):
            return "rt"
        return "register"

    def _log(self, msg: str, *, channel: str | None = None) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        th = threading.current_thread()
        # 主线程/daemon 显示 "main",worker 线程取末段(如 biz-rt-loop_0 → loop_0)
        name = th.name
        if name == "MainThread":
            tid = "main"
        elif name.startswith("biz-rt-loop-daemon"):
            tid = "daemon"
        elif "_" in name:
            tid = name.rsplit("_", 1)[-1]  # 0/1/2
            tid = f"w{tid}"
        else:
            tid = name[-6:]
        line = f"[{ts}][{tid:>6s}] {msg}"
        self._logs.append(line)
        resolved_channel = channel or self._infer_log_channel(msg, name)
        if resolved_channel == "rt":
            self._rt_logs.append(line)
        elif resolved_channel == "register":
            self._register_logs.append(line)

    # ------------------------------------------------------------------ start/stop

    def start(self, *,
              concurrency: int = 3,
              max_per_domain: int = 500,
              domain_hostnames: list[str] | None = None,
              allow_quota_reset: bool = False,
              rt_retry_limit_enabled: bool = False,
              max_retries: int = 5,
              proxy_priority: str = _PROXY_PRIORITY_MANUAL_FIRST,
              worker_timeout_seconds: int = _WORKER_TIMEOUT_SECONDS_DEFAULT) -> dict[str, Any]:
        """启动 runner。

        rt_retry_limit_enabled=False（默认）时,补 RT 失败不会自动转 RT_UNREACHABLE,
        账号会一直留在「待 RT」队列等手动处理或继续重试。
        rt_retry_limit_enabled=True 时,rt_retry_count 达到 max_retries 才转 RT_UNREACHABLE。
        """
        requested_hostnames = self._normalize_domain_hostnames(domain_hostnames)
        all_verified_hostnames = self._list_verified_hostnames()
        if requested_hostnames:
            verified_set = set(all_verified_hostnames)
            missing = [h for h in requested_hostnames if h not in verified_set]
            if missing:
                preview = ", ".join(missing[:5])
                if len(missing) > 5:
                    preview += f" 等 {len(missing)} 个"
                return {
                    "ok": False,
                    "error": f"选中的 BUSINESS 域名未验证或不存在: {preview}",
                }
            requested_set = set(requested_hostnames)
            active_hostnames = [
                h for h in all_verified_hostnames if h in requested_set
            ]
            domain_scope_all = False
        else:
            active_hostnames = all_verified_hostnames
            domain_scope_all = True

        if not active_hostnames:
            return {
                "ok": False,
                "error": "没有任何 verified 的 BUSINESS 子域,请先到「Business 域名」页面添加并验证",
            }
        worker_timeout_seconds = max(
            _WORKER_TIMEOUT_SECONDS_MIN,
            min(_WORKER_TIMEOUT_SECONDS_MAX, int(worker_timeout_seconds or _WORKER_TIMEOUT_SECONDS_DEFAULT)),
        )
        proxy_priority = self._normalize_proxy_priority(proxy_priority)

        with self._lock:
            if self._state.state == "running":
                return {"ok": False, "error": "runner 已经在运行"}
            self._state = _RunnerState(
                state="running",
                started_at=datetime.now(timezone.utc).isoformat(),
                config={
                    "concurrency": int(concurrency),
                    "max_per_domain": int(max_per_domain),
                    "domain_scope_all": domain_scope_all,
                    "domain_hostnames": [] if domain_scope_all else active_hostnames,
                    "domain_count": len(active_hostnames),
                    "allow_quota_reset": bool(allow_quota_reset),
                    "rt_retry_limit_enabled": bool(rt_retry_limit_enabled),
                    "max_retries": int(max_retries),
                    "worker_timeout_seconds": worker_timeout_seconds,
                    "proxy_priority": proxy_priority,
                },
            )
            self._stop_event.clear()
            # 从 DB 初始化每个 hostname 的已用数(账号 email 后缀 ==  hostname)
            self._initialize_domain_used(active_hostnames)
            self._executor = ThreadPoolExecutor(
                max_workers=max(1, int(concurrency)),
                thread_name_prefix="biz-rt-loop",
            )
            self._daemon = threading.Thread(
                target=self._daemon_loop,
                name="biz-rt-loop-daemon",
                daemon=True,
            )
            self._daemon.start()
            # 启动 rotation 调度线程 (单线程串行 create/delete, 避免并发触发风控)
            self._rotation_stop.clear()
            self._rotation_state["enabled"] = True
            self._rotation_state["last_error"] = ""
            self._rotation_thread = threading.Thread(
                target=self._rotation_loop,
                name="biz-rt-rotation",
                daemon=True,
            )
            self._rotation_thread.start()
            # 启动动态代理预拉池 daemon (自适应并发数)
            try:
                from core.dynamic_proxy import start_pool_daemon, _is_enabled as _dyn_enabled
                if _dyn_enabled():
                    cfg = start_pool_daemon(concurrency_hint=int(concurrency))
                    self._log(
                        f"▶ 动态代理预拉池 daemon 已启动 "
                        f"(target={cfg.get('target')}, refill={cfg.get('refill_interval')}s, "
                        f"按并发 {concurrency} 自适应)"
                    )
            except Exception as exc:
                self._log(f"动态代理预拉池启动异常(忽略): {exc}")
            # 新流程下,注册产物落 PENDING_INVITE,后续靠 invite / activate / seat-change
            # 三个 daemon 接力到 PENDING_RT。这里一并自动启动,免去用户手动
            # /invite/start, /activate/start, /seat-change/start 三步;auto-rt 仍保留
            # 给用户手动控制 (RT 机可能跑在其它节点上,不强行起)。
            try:
                if self._is_new_business_flow_enabled():
                    invite_batch_size = self._int_config(
                        "business_invite_batch_size", 6, min_value=1, max_value=20,
                    )
                    invite_interval = self._int_config(
                        "business_invite_batch_interval_seconds", 10,
                        min_value=1, max_value=120,
                    )
                    activate_concurrency = self._int_config(
                        "business_activate_concurrency", 5,
                        min_value=1, max_value=20,
                    )
                    seat_concurrency = self._int_config(
                        "business_seat_change_concurrency", 5,
                        min_value=1, max_value=20,
                    )
                    if not (
                        self._invite_state.get("running")
                        or self._invite_state.get("stopping")
                    ):
                        r = self.start_invite_daemon(
                            batch_size=invite_batch_size,
                            batch_interval_seconds=float(invite_interval),
                        )
                        if r.get("ok"):
                            self._log(
                                f"▶ 邀请 daemon 已随注册自动启动 "
                                f"(batch={invite_batch_size}, interval={invite_interval}s)"
                            )
                    if not (
                        self._activate_state.get("running")
                        or self._activate_state.get("stopping")
                    ):
                        r = self.start_activate_daemon(concurrency=activate_concurrency)
                        if r.get("ok"):
                            self._log(
                                f"▶ 激活 daemon 已随注册自动启动 (并发 {activate_concurrency})"
                            )
                    if not (
                        self._seat_change_state.get("running")
                        or self._seat_change_state.get("stopping")
                    ):
                        r = self.start_seat_change_daemon(concurrency=seat_concurrency)
                        if r.get("ok"):
                            self._log(
                                f"▶ 切席位 daemon 已随注册自动启动 (并发 {seat_concurrency})"
                            )
            except Exception as exc:
                self._log(f"接力 daemon 自动启动失败(忽略): {exc}")
            retry_label = (
                f"RT 重试上限 {max_retries} 次" if rt_retry_limit_enabled
                else "RT 重试上限 关闭(可无限重试)"
            )
            quota_label = (
                "满后归零继续(高风险)" if allow_quota_reset
                else "满后停止"
            )
            domain_label = (
                f"全部 verified BUSINESS 子域 {len(active_hostnames)} 个"
                if domain_scope_all
                else f"指定 BUSINESS 子域 {len(active_hostnames)} 个"
            )
            self._log(
                f"▶ 启动: 注册并发 {concurrency} / 每域上限 {max_per_domain}"
                f" / worker超时 {worker_timeout_seconds}s"
                f" / 代理优先级 {_PROXY_PRIORITY_LABELS.get(proxy_priority, proxy_priority)}"
                f" / {domain_label} / {quota_label} / {retry_label}"
            )
            self._log(
                f"▶ 本机标识 (machine_id): {_machine_id_or_unknown()}"
                f" — 严格机器隔离: 只选本机 owner 的 BUSINESS 子域"
            )
            return {"ok": True}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if self._state.state != "running":
                return {"ok": False, "error": "runner 未在运行"}
            self._stop_event.set()
            self._rotation_stop.set()  # 通知 rotation 线程退出
            # 停动态代理预拉池
            try:
                from core.dynamic_proxy import stop_pool_daemon
                stop_pool_daemon()
            except Exception:
                pass
            self._state.state = "stopped"
            self._state.stopped_at = datetime.now(timezone.utc).isoformat()
            self._log("收到停止信号")
            return {"ok": True}

    def _is_business_runner_active(self) -> bool:
        return (
            self._state.state == "running"
            or (self._daemon is not None and self._daemon.is_alive())
        )

    def _is_auto_rt_active(self) -> bool:
        with self._auto_rt_lock:
            return bool(
                self._auto_rt_state.get("running")
                or self._auto_rt_state.get("stopping")
            )

    @staticmethod
    def _rt_oauth_browser_mode_config() -> str:
        from core.config_store import config_store

        mode = str(
            config_store.get(
                "business_rt_oauth_browser_mode",
                _RT_OAUTH_BROWSER_MODE_DEFAULT,
            )
            or _RT_OAUTH_BROWSER_MODE_DEFAULT
        ).strip().lower()
        if mode not in _RT_OAUTH_BROWSER_MODES:
            return _RT_OAUTH_BROWSER_MODE_DEFAULT
        return mode

    @classmethod
    def _status_config_snapshot(cls, config: dict[str, Any]) -> dict[str, Any]:
        snapshot = dict(config or {})
        snapshot["business_rt_oauth_browser_mode"] = cls._rt_oauth_browser_mode_config()
        return snapshot

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = self._state.state
            started_at = self._state.started_at
            stopped_at = self._state.stopped_at
            last_error = self._state.last_error
            config = dict(self._state.config)
            counters = {
                "success": self._state.counters.success,
                "rt_failed": self._state.counters.rt_failed,
                "seat_failed": self._state.counters.seat_failed,
                "errors": self._state.counters.errors,
                "attempts": self._state.counters.attempts,
                "domain_banned": self._state.counters.domain_banned,
            }
        with self._auto_rt_lock:
            auto_rt = dict(self._auto_rt_state)
        with self._invite_lock:
            invite = dict(self._invite_state)
        with self._activate_lock:
            activate = dict(self._activate_state)
        with self._seat_change_lock:
            seat_change = dict(self._seat_change_state)
        with self._fixup_lock:
            fixup_progress = dict(self._fixup_progress)
        with self._import_progress_lock:
            import_progress = dict(self._import_progress)
        with self._domain_lock:
            banned_hostnames = sorted(self._domain_banned)
            rotation_state = dict(self._rotation_state)
        return {
            "state": state,
            "started_at": started_at,
            "stopped_at": stopped_at,
            "last_error": last_error,
            "config": self._status_config_snapshot(config),
            "counters": counters,
            "banned_hostnames": banned_hostnames,
            "domain_otp_health": self._domain_otp_health_snapshot(),
            "domain_stats": self._domain_stats_snapshot(),
            "machine_id": _machine_id_or_unknown(),
            "dynamic_proxy": _dynamic_proxy_snapshot(),
            "drission_temp": self._drission_temp_snapshot(),
            "new_flow_enabled": self._is_new_business_flow_enabled(),
            "rotation": {
                "enabled": bool(rotation_state.get("enabled")),
                "target_pool_size": int(rotation_state.get("target_pool_size") or _ROTATION_TARGET_POOL_SIZE),
                "alive_pool_size": self._alive_pool_size(),
                "last_action_at": str(rotation_state.get("last_action_at") or ""),
                "last_action": str(rotation_state.get("last_action") or ""),
                "last_error": str(rotation_state.get("last_error") or ""),
                "deleted_count": int(rotation_state.get("deleted_count") or 0),
                "created_count": int(rotation_state.get("created_count") or 0),
            },
            "status_counts": count_accounts_by_status(
                _PLATFORM,
                [
                    AccountStatus.PENDING_INVITE.value,
                    AccountStatus.PENDING_ACTIVATE.value,
                    AccountStatus.PENDING_SEAT_CHANGE.value,
                    AccountStatus.PENDING_RT.value,
                    AccountStatus.PENDING_SEAT_SWITCH.value,
                    AccountStatus.READY_FOR_EXPORT.value,
                    AccountStatus.RT_UNREACHABLE.value,
                ],
            ),
            "rt_health_counts": self._count_ready_for_export_rt_health(),
            "recent_logs": list(self._logs)[-100:],
            "recent_register_logs": list(self._register_logs)[-100:],
            "recent_rt_logs": list(self._rt_logs)[-100:],
            "fixup_progress": fixup_progress,
            "import_subdomain_progress": import_progress,
            "auto_rt": auto_rt,
            "invite": invite,
            "activate": activate,
            "seat_change": seat_change,
        }

    @staticmethod
    def _drission_temp_snapshot() -> dict[str, Any]:
        try:
            from platforms.chatgpt.drission_temp import drission_temp_snapshot
            return drission_temp_snapshot()
        except Exception as exc:
            import tempfile
            fallback_root = Path(tempfile.gettempdir()) / "DrissionPage"
            return {
                "root": str(fallback_root),
                "profile_root": str(fallback_root / "autoPortData"),
                "exists": False,
                "total_bytes": 0,
                "total_human": "0B",
                "profile_count": 0,
                "active_profile_count": 0,
                "inactive_profile_count": 0,
                "error": str(exc),
            }

    def status_fast(self) -> dict[str, Any]:
        """轻量状态接口:不扫域名统计,用于自动化/探活避免被完整 status 阻塞。"""
        with self._lock:
            state = self._state.state
            started_at = self._state.started_at
            stopped_at = self._state.stopped_at
            last_error = self._state.last_error
            config = dict(self._state.config)
            counters = {
                "success": self._state.counters.success,
                "rt_failed": self._state.counters.rt_failed,
                "seat_failed": self._state.counters.seat_failed,
                "errors": self._state.counters.errors,
                "attempts": self._state.counters.attempts,
                "domain_banned": self._state.counters.domain_banned,
            }
        with self._auto_rt_lock:
            auto_rt = dict(self._auto_rt_state)
        with self._invite_lock:
            invite = dict(self._invite_state)
        with self._activate_lock:
            activate = dict(self._activate_state)
        with self._seat_change_lock:
            seat_change = dict(self._seat_change_state)
        with self._fixup_lock:
            fixup_progress = dict(self._fixup_progress)
        try:
            status_counts = count_accounts_by_status(
                _PLATFORM,
                [
                    AccountStatus.PENDING_INVITE.value,
                    AccountStatus.PENDING_ACTIVATE.value,
                    AccountStatus.PENDING_SEAT_CHANGE.value,
                    AccountStatus.PENDING_RT.value,
                    AccountStatus.PENDING_SEAT_SWITCH.value,
                    AccountStatus.READY_FOR_EXPORT.value,
                    AccountStatus.RT_UNREACHABLE.value,
                ],
            )
        except Exception as exc:
            status_counts = {}
            last_error = (
                f"{last_error}; status_counts: {exc}"
                if last_error else f"status_counts: {exc}"
            )
        return {
            "state": state,
            "started_at": started_at,
            "stopped_at": stopped_at,
            "last_error": last_error,
            "config": self._status_config_snapshot(config),
            "counters": counters,
            "status_counts": status_counts,
            "new_flow_enabled": self._is_new_business_flow_enabled(),
            "fixup_progress": fixup_progress,
            "auto_rt": auto_rt,
            "invite": invite,
            "activate": activate,
            "seat_change": seat_change,
        }

    # ------------------------------------------------------------------ daemon loop

    def _worker_timeout_seconds(self) -> int:
        try:
            value = int(
                self._state.config.get("worker_timeout_seconds")
                or _WORKER_TIMEOUT_SECONDS_DEFAULT
            )
        except Exception:
            value = _WORKER_TIMEOUT_SECONDS_DEFAULT
        return max(
            _WORKER_TIMEOUT_SECONDS_MIN,
            min(_WORKER_TIMEOUT_SECONDS_MAX, value),
        )

    def _daemon_loop(self) -> None:
        try:
            active: dict[Future, dict[str, Any]] = {}
            last_heartbeat = 0.0
            total_submitted = 0
            next_submit_not_before = 0.0

            def wait_for_submit_slot() -> bool:
                """提交 worker 前的节流。

                - 初始填满 concurrency 时,逐个错开提交。
                - 任一 worker 完成后,也不会立刻补位,会至少等到
                  next_submit_not_before,避免"完成即马上新注册"。
                """
                wait_seconds = max(0.0, next_submit_not_before - time.monotonic())
                if wait_seconds <= 0:
                    return True
                return not self._stop_event.wait(wait_seconds)

            def submit_one() -> bool | None:
                nonlocal total_submitted, next_submit_not_before
                if self._stop_event.is_set():
                    return False
                reserved = self._reserve_next_domain()
                if not reserved:
                    return None
                hostname, reservation_id = reserved
                with self._lock:
                    self._state.counters.attempts += 1
                future = self._executor.submit(
                    self._attempt_one, hostname, reservation_id
                )
                total_submitted += 1
                active[future] = {
                    "reservation_id": reservation_id,
                    "hostname": hostname,
                    "submitted_at": time.monotonic(),
                    "seq": total_submitted,
                }
                interval = self._submit_interval_seconds()
                if interval > 0:
                    next_submit_not_before = time.monotonic() + interval
                return True

            def collect_done(done_futures: set[Future]) -> None:
                nonlocal next_submit_not_before
                completed = 0
                for f in done_futures:
                    meta = active.pop(f, None) or {}
                    completed += 1
                    try:
                        f.result()
                    except Exception as e:
                        reservation_id = str(meta.get("reservation_id") or "")
                        if reservation_id:
                            self._release_domain(reservation_id, success=False)
                        self._log(f"worker 异常: {e}")
                        with self._lock:
                            self._state.counters.errors += 1
                if completed:
                    interval = self._submit_interval_seconds()
                    if interval > 0:
                        next_submit_not_before = max(
                            next_submit_not_before,
                            time.monotonic() + interval,
                        )

            def expire_slow_workers(timeout_seconds: int) -> None:
                nonlocal last_heartbeat
                now = time.monotonic()
                timed_out = [
                    (f, meta)
                    for f, meta in list(active.items())
                    if now - float(meta.get("submitted_at") or now) >= timeout_seconds
                ]
                if not timed_out:
                    return

                cancelled = 0
                running = 0
                for f, meta in timed_out:
                    active.pop(f, None)
                    if f.cancel():
                        cancelled += 1
                    else:
                        running += 1
                    reservation_id = str(meta.get("reservation_id") or "")
                    if reservation_id:
                        self._release_domain(reservation_id, success=False)
                with self._lock:
                    self._state.counters.errors += len(timed_out)
                self._log(
                    f"⚠ {len(timed_out)} 个 worker 超过 {timeout_seconds}s 未返回"
                    f"（running={running}, cancelled={cancelled}），已释放名额并继续补位"
                )
                if running:
                    old_executor = self._executor
                    self._executor = ThreadPoolExecutor(
                        max_workers=max(1, int(self._state.config.get("concurrency") or 1)),
                        thread_name_prefix="biz-rt-loop",
                    )
                    if old_executor:
                        old_executor.shutdown(wait=False, cancel_futures=True)
                    self._log("已重建 worker 线程池，滑动窗口继续补位")
                last_heartbeat = 0.0

            while not self._stop_event.is_set():
                concurrency = max(1, int(self._state.config.get("concurrency") or 1))
                timeout_seconds = self._worker_timeout_seconds()

                # 滑动窗口：尽量保持 active 数量接近 concurrency；某个 worker 完成后下一轮立即补位。
                no_domain = False
                submitted = 0
                while len(active) < concurrency and not self._stop_event.is_set():
                    if not wait_for_submit_slot():
                        break
                    submitted_result = submit_one()
                    if submitted_result is True:
                        submitted += 1
                        continue
                    if submitted_result is None:
                        no_domain = True
                    break

                if submitted:
                    self._log(
                        f"🪟 滑动窗口补位: 新增 {submitted}，"
                        f"运行中 {len(active)}/{concurrency}"
                    )

                if not active:
                    if no_domain:
                        self._handle_no_domain_idle()
                        continue
                    time.sleep(0.2)
                    continue

                done, _ = wait(
                    set(active.keys()),
                    timeout=1.0,
                    return_when=FIRST_COMPLETED,
                )
                if done:
                    collect_done(done)

                expire_slow_workers(timeout_seconds)

                now = time.monotonic()
                if now - last_heartbeat >= _WORKER_HEARTBEAT_SECONDS:
                    oldest = 0
                    if active:
                        oldest = int(
                            max(
                                now - float(meta.get("submitted_at") or now)
                                for meta in active.values()
                            )
                        )
                    self._log(
                        f"⏳ 滑动窗口运行中：运行中 {len(active)}/{concurrency}，"
                        f"最久 {oldest}s，worker超时 {timeout_seconds}s，"
                        "完成即补位"
                    )
                    last_heartbeat = now
        except Exception as e:
            self._log(f"daemon 异常退出: {e}\n{traceback.format_exc()[:500]}")
            with self._lock:
                self._state.state = "error"
                self._state.last_error = str(e)
        finally:
            if self._executor:
                self._executor.shutdown(wait=False)
            self._log("runner 已退出")

    def _handle_no_domain_idle(self) -> None:
        """没有可提交的新注册域名时的空转策略。

        旧逻辑会把 runner 标记为 domain_exhausted/quota_exhausted 并停止。
        新逻辑保持 runner 运行,等待 10 秒后刷新 verified 子域池,让自动
        rotation 或人工新增/恢复子域后无需重启长跑即可继续注册。
        """
        pause_wait = self._all_available_domains_paused_wait_seconds()
        if pause_wait > 0:
            wait_s = min(_DOMAIN_RECHECK_SECONDS, max(1.0, pause_wait))
            self._log(
                f"⏸ 当前可用 BUSINESS 子域均因 OTP 连续超时短暂停顿,"
                f"等待 {wait_s:.0f}s 后继续检查"
            )
            self._stop_event.wait(wait_s)
            return

        if not self._has_non_banned_domain_in_pool():
            self._wait_for_domain_pool_recheck(
                "所有 BUSINESS 子域均已被移出队列/拉黑"
            )
            return

        if self._state.config.get("allow_quota_reset"):
            self._log("⚠ 检测到无可用域名,配额归零后继续")
            self._reset_all_business_quotas()
            time.sleep(0.2)
            return

        self._wait_for_domain_pool_recheck("无可用域名且未开启归零开关")

    def _wait_for_domain_pool_recheck(self, reason: str) -> None:
        self._log(
            f"⏳ {reason},runner 不停止,"
            f"{_DOMAIN_RECHECK_SECONDS:.0f}s 后重新查询可用 BUSINESS 子域"
        )
        if self._stop_event.wait(_DOMAIN_RECHECK_SECONDS):
            return
        self._refresh_domain_pool()

    def _attempt_one(self, hostname: str, reservation_id: str) -> str:
        """单次注册尝试。返回 'success' / 'rt_failed' / 'seat_failed' / 'quota_exhausted' / 'error'。"""
        success = False
        outcome = "error"
        try:
            extra_config = self._build_extra_config(hostname)
            from platforms.chatgpt.plugin import ChatGPTPlatform
            instance = ChatGPTPlatform(
                config=RegisterConfig(executor_type="protocol", extra=extra_config),
            )
            instance._log_fn = self._log
            proxy, proxy_source = self._pick_proxy_with_source(extra_config)
            if proxy:
                from core.proxy_utils import redact_proxy_url
                self._log(
                    f"🌐 注册前已选择代理: {redact_proxy_url(proxy)} "
                    f"(来源: {proxy_source}); 后续注册/OAuth/RT 复用该代理"
                )
            else:
                self._log(
                    "⚠ 未找到任何可用代理,本次注册直连。"
                    "请确认: ①「代理管理」加了代理 或 "
                    "②「全局配置」填了 default_proxy (例如 http://127.0.0.1:7890)"
                )
            # 新流程: 协议注册 → 落 PENDING_INVITE,后续 invite/activate/seat-change 接力。
            # 原因: BUSINESS 域 catch-all 自动入 workspace 只让账号成为 member,
            # 并未分配 seat;直接 PATCH seat_type 会返回 "No active subscription found"。
            # 必须由 master POST /invites 创建邀请, 子号 GET accept-invite URL 后,
            # OpenAI 才会给该 user 分配 seat,之后才能切 seat_type。
            if self._is_new_business_flow_enabled():
                account = instance._register_business_protocol(
                    business_domain=hostname,
                    password=self._gen_password(),
                    proxy=proxy,
                    extra_config=extra_config,
                    log_fn=self._log,
                    skip_oauth_file=True,
                    skip_codex_switch=True,
                )
                from platforms.chatgpt.account_security import (
                    finalize_registered_platform_account,
                )

                account = finalize_registered_platform_account(
                    account,
                    config=extra_config,
                    proxy=proxy or "",
                    browser_mode="protocol",
                    log_fn=self._log,
                )
                merged = dict(account.extra or {})
                merged["business_email"] = account.email
                merged.setdefault("register_proxy", proxy or "")
                account.extra = merged
                account.status = AccountStatus.PENDING_INVITE
                save_account(account)
                outcome = "success"
                success = True
                self._record_domain_success(hostname)
                self._increment_counter_if_active(reservation_id, "success")
                self._log(f"✅ {account.email} 已注册,进入待邀请队列")
                return outcome

            account = instance._register_business_oauth(
                business_domain=hostname,
                password=self._gen_password(),
                proxy=proxy,
                extra_config=extra_config,
                log_fn=self._log,
                raise_on_failure=False,
            )
            from platforms.chatgpt.account_security import (
                finalize_registered_platform_account,
            )

            account = finalize_registered_platform_account(
                account,
                config=extra_config,
                proxy=proxy or "",
                browser_mode="protocol",
                log_fn=self._log,
            )
            # _register_business_oauth persists phase boundaries internally;
            # save once more so the security status/refreshed cookies are not
            # lost on branches that return without another state transition.
            save_account(account)
            status_value = (
                account.status.value if isinstance(account.status, AccountStatus)
                else str(account.status or "")
            )
            if status_value == AccountStatus.READY_FOR_EXPORT.value:
                outcome = "success"
                success = True
                self._record_domain_success(hostname)
                self._increment_counter_if_active(reservation_id, "success")
                self._log(f"✅ {account.email} 已就绪可导出")
            elif status_value == AccountStatus.REGISTERED.value:
                account.extra = dict(account.extra or {})
                if str(account.extra.get("refresh_token") or "").strip():
                    account.status = AccountStatus.READY_FOR_EXPORT
                    account.extra.setdefault("business_switch_to_codex", "0")
                    save_account(account)
                    self._log(f"✅ {account.email} 已拿到 RT，非 Codex 席位也已就绪可导出")
                else:
                    self._log(f"✅ {account.email} 已注册，等待后续补 RT")
                outcome = "success"
                success = True
                self._record_domain_success(hostname)
                self._increment_counter_if_active(reservation_id, "success")
            elif status_value == AccountStatus.PENDING_SEAT_SWITCH.value:
                account.extra = dict(account.extra or {})
                if str(account.extra.get("refresh_token") or "").strip():
                    account.status = AccountStatus.READY_FOR_EXPORT
                    save_account(account)
                    outcome = "success"
                    success = True
                    self._record_domain_success(hostname)
                    self._increment_counter_if_active(reservation_id, "success")
                    self._log(f"✅ {account.email} 已拿到 RT，席位未切换但已就绪可导出")
                else:
                    outcome = "seat_failed"
                    self._increment_counter_if_active(reservation_id, "seat_failed")
                    self._log(f"⚠ {account.email} 卡在席位切换")
            else:  # PENDING_RT 或其他
                register_only = str(
                    extra_config.get("business_rt_register_only") or ""
                ).strip().lower() in {"1", "true", "yes", "on"}
                if (
                    register_only
                    and status_value == AccountStatus.PENDING_RT.value
                ):
                    outcome = "success"
                    success = True
                    self._record_domain_success(hostname)
                    self._increment_counter_if_active(reservation_id, "success")
                    self._log(f"✅ {account.email} 已注册，进入待 RT 队列")
                else:
                    outcome = "rt_failed"
                    self._record_domain_success(hostname)
                    self._increment_counter_if_active(reservation_id, "rt_failed")
                    # 如果失败原因是手机号验证,直接删账号(留着也补不了 RT)
                    rt_err = (account.extra or {}).get("rt_acquisition_error", "")
                    if self._is_phone_verification_error(rt_err):
                        # 先查 DB 拿 id,再删
                        try:
                            with Session(engine) as s:
                                db_acc = s.exec(
                                    select(AccountModel)
                                    .where(AccountModel.platform == "chatgpt")
                                    .where(AccountModel.email == account.email)
                                ).first()
                                if db_acc:
                                    acc_id = db_acc.id
                                    s.delete(db_acc)
                                    s.commit()
                                    self._log(
                                        f"🗑 [注册 {account.email}] 命中手机号验证,已删除账号"
                                        f"(account_id={acc_id})"
                                    )
                        except Exception as del_exc:
                            self._log(f"⚠ [注册 {account.email}] 手机号验证后删除失败: {del_exc}")
                    else:
                        self._log(f"⚠ {account.email} 卡在 RT 获取")
        except Exception as e:
            # 优先识别 OpenAI 风控类异常 → 拉黑子域,后续 worker 不再选择
            from platforms.chatgpt.protocol_register import DomainDeactivatedError, OTPTimeoutError
            if isinstance(e, DomainDeactivatedError):
                self._mark_domain_banned(hostname, reason=str(e)[:200])
                outcome = "domain_banned"
            elif isinstance(e, OTPTimeoutError) or self._is_otp_timeout_error(e):
                self._increment_counter_if_active(reservation_id, "errors")
                self._record_domain_otp_timeout(hostname, str(e))
                self._log(f"❌ 注册异常: {e}")
                outcome = "error"
            else:
                self._increment_counter_if_active(reservation_id, "errors")
                self._log(f"❌ 注册异常: {e}")
                outcome = "error"
        finally:
            if not self._release_domain(reservation_id, success=success):
                self._log("⏭ 超时 worker 晚返回，域名名额和统计已在超时时处理")
        return outcome

    # ------------------------------------------------------------------ domain selection

    @staticmethod
    def _normalize_domain_hostnames(value: Any) -> list[str]:
        if not value:
            return []
        items: list[Any]
        if isinstance(value, str):
            items = value.replace("\n", ",").split(",")
        elif isinstance(value, (list, tuple, set)):
            items = list(value)
        else:
            items = [value]
        result: list[str] = []
        seen: set[str] = set()
        for item in items:
            hostname = str(item or "").strip().lower().lstrip("@")
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)
            result.append(hostname)
        return result

    def _selected_domain_filter(self) -> list[str] | None:
        if self._state.config.get("domain_scope_all", True):
            return None
        return self._normalize_domain_hostnames(
            self._state.config.get("domain_hostnames") or []
        )

    def _list_verified_hostnames(self, allowed_hostnames: list[str] | None = None) -> list[str]:
        """从 BusinessDomainModel 拉本机 verified 子域 (strict 机器隔离)。

        只返回 owner_machine_id == 本机 的, 避免多机协作时一台机器调度到另一台
        机器创建的子域 (会撞邮箱 / 抢码 / 互删)。
        公共域 (owner_machine_id == '') 不被自动选, 需要 UI 主动"认领"。
        """
        from core.machine_id import current_machine_id
        me = current_machine_id()
        with Session(engine) as s:
            rows = s.exec(
                select(BusinessDomainModel)
                .where(BusinessDomainModel.status == "verified")
                .where(BusinessDomainModel.owner_machine_id == me)
                .order_by(BusinessDomainModel.id)
            ).all()
            hostnames = [str(r.hostname).strip().lower() for r in rows if r.hostname]
        if allowed_hostnames is None:
            return hostnames
        allowed = set(self._normalize_domain_hostnames(allowed_hostnames))
        return [h for h in hostnames if h in allowed]

    def _initialize_domain_used(self, hostnames: list[str] | None = None) -> None:
        """从 DB 初始化 _domain_used: 每个 verified 子域当前已注册账号数。"""
        hostnames = hostnames or self._list_verified_hostnames(self._selected_domain_filter())
        used: dict[str, int] = {h: 0 for h in hostnames}
        with Session(engine) as s:
            rows = s.exec(
                select(AccountModel.email).where(AccountModel.platform == "chatgpt")
            ).all()
            for email in rows:
                if "@" not in str(email):
                    continue
                host = str(email).split("@", 1)[1].strip().lower()
                if host in used:
                    used[host] += 1
        with self._domain_lock:
            self._domain_used = used
            self._domain_inflight = {h: 0 for h in hostnames}
            self._domain_reservations = {}
        self._log(
            f"✓ verified BUSINESS 子域共 {len(hostnames)} 个,"
            f"已注册账号合计 {sum(used.values())} 个"
        )

    def _reserve_next_domain(self) -> tuple[str, str] | None:
        """从 verified 子域池里挑一个还有配额的,inflight+1 占住,返回 hostname。
        没有可用域名返回 None。
        """
        max_per_domain = int(self._state.config.get("max_per_domain") or 500)
        with self._domain_lock:
            if not self._domain_used:
                # 池为空,刷新一次(可能是用户中途加了新子域)
                pass
            candidates = [
                h for h in self._domain_used
                if h not in self._domain_banned
                and not self._is_domain_paused_locked(h)
                and self._domain_used[h] + self._domain_inflight.get(h, 0) < max_per_domain
            ]
            if not candidates:
                # 池里没人或都满了,刷一次 DB
                pass
            else:
                hostname = self._pick_balanced_random_domain_locked(candidates)
                self._domain_inflight[hostname] = self._domain_inflight.get(hostname, 0) + 1
                reservation_id = uuid.uuid4().hex
                self._domain_reservations[reservation_id] = hostname
                return hostname, reservation_id

        # 没拿到 → 重新加载子域池
        self._refresh_domain_pool()
        with self._domain_lock:
            if not self._domain_used:
                self._log("✗ 没有任何 verified 的 BUSINESS 子域(请到「Business 域名」页面验证至少一个子域)")
                return None
            candidates = [
                h for h in self._domain_used
                if h not in self._domain_banned
                and not self._is_domain_paused_locked(h)
                and self._domain_used[h] + self._domain_inflight.get(h, 0) < max_per_domain
            ]
            if not candidates:
                full_count = len(self._domain_used)
                banned_count = len(self._domain_banned)
                hint = ""
                if banned_count:
                    hint = f", 其中 {banned_count} 个本次运行已被 OpenAI 拉黑"
                self._log(
                    f"✗ {full_count} 个 BUSINESS 子域均已达上限"
                    f" {max_per_domain}{hint} (开启「满了归零」开关可清零继续)"
                )
                return None
            hostname = self._pick_balanced_random_domain_locked(candidates)
            self._domain_inflight[hostname] = self._domain_inflight.get(hostname, 0) + 1
            reservation_id = uuid.uuid4().hex
            self._domain_reservations[reservation_id] = hostname
            return hostname, reservation_id

    def _pick_balanced_random_domain_locked(self, candidates: list[str]) -> str:
        """在已持有 _domain_lock 时调用:先均衡,再随机。

        纯 random.choice(candidates) 在 20+ 并发下可能把多个 worker
        瞬间压到同一个子域。这里先按当前 inflight 最少、used 最少筛出
        一组"压力最低"的子域,再在这组里随机,保留随机性同时避免热点域。
        """
        if not candidates:
            raise RuntimeError("没有可用 BUSINESS 子域")

        def score(hostname: str) -> tuple[int, int]:
            return (
                int(self._domain_inflight.get(hostname, 0) or 0),
                int(self._domain_used.get(hostname, 0) or 0),
            )

        best_score = min(score(h) for h in candidates)
        balanced_candidates = [h for h in candidates if score(h) == best_score]
        return random.choice(balanced_candidates)

    def _is_domain_paused_locked(self, hostname: str, now: float | None = None) -> bool:
        """在已持有 _domain_lock 时调用:判断域名是否处于短暂停顿期。

        暂停过期后自动清理,让域名重新进入候选池。
        """
        host = (hostname or "").strip().lower()
        if not host:
            return False
        now = time.monotonic() if now is None else now
        until = float(self._domain_paused_until.get(host) or 0)
        if until <= 0:
            return False
        if until <= now:
            self._domain_paused_until.pop(host, None)
            return False
        return True

    def _domain_otp_health_snapshot(self) -> dict[str, Any]:
        """返回当前进程内 OTP 域名健康统计,供 status/UI 诊断。"""
        now = time.monotonic()
        with self._domain_lock:
            paused = {
                h: max(0, int(float(until or 0) - now))
                for h, until in self._domain_paused_until.items()
                if float(until or 0) > now
            }
            # 顺便清理过期 pause
            for h in list(self._domain_paused_until):
                if float(self._domain_paused_until.get(h) or 0) <= now:
                    self._domain_paused_until.pop(h, None)
            return {
                "otp_timeout_streak": dict(self._domain_otp_timeout_streak),
                "domain_failure_counts": dict(self._domain_failure_counts),
                "paused_hostnames": paused,
            }

    def _domain_stats_snapshot(self) -> list[dict[str, Any]]:
        """返回 BUSINESS RT 长跑界面展示的每域注册/健康统计。"""
        now = time.monotonic()
        with self._domain_lock:
            hostnames = sorted(
                set(self._domain_used)
                | set(self._domain_inflight)
                | set(self._domain_otp_timeout_streak)
                | set(self._domain_failure_counts)
                | set(self._domain_paused_until)
                | set(self._domain_banned)
                | set(self._domain_success_streak)
                | set(self._domain_recent_outcomes)
            )
            rows: list[dict[str, Any]] = []
            for host in hostnames:
                pause_remaining = 0
                until = float(self._domain_paused_until.get(host) or 0)
                if until > now:
                    pause_remaining = max(0, int(until - now))
                elif until:
                    self._domain_paused_until.pop(host, None)

                banned = host in self._domain_banned
                status = "banned" if banned else "paused" if pause_remaining > 0 else "active"
                health = self._domain_health_snapshot_locked(
                    host,
                    banned=banned,
                    pause_remaining=pause_remaining,
                )
                rows.append({
                    "hostname": host,
                    "status": status,
                    "banned": banned,
                    "used": int(self._domain_used.get(host, 0) or 0),
                    "inflight": int(self._domain_inflight.get(host, 0) or 0),
                    "otp_timeout_streak": int(self._domain_otp_timeout_streak.get(host, 0) or 0),
                    "failure_count": int(self._domain_failure_counts.get(host, 0) or 0),
                    "paused_remaining_seconds": pause_remaining,
                    **health,
                })
            rows.sort(key=lambda item: (
                0 if item["status"] == "active" else 1 if item["status"] == "paused" else 2,
                -int(item["inflight"]),
                -int(item["failure_count"]),
                item["hostname"],
            ))
            return rows

    def _append_domain_outcome_locked(self, hostname: str, outcome: str) -> None:
        host = (hostname or "").strip().lower()
        if not host:
            return
        dq = self._domain_recent_outcomes.get(host)
        if dq is None:
            dq = collections.deque(maxlen=_DOMAIN_RECENT_OUTCOME_WINDOW)
            self._domain_recent_outcomes[host] = dq
        dq.append(outcome)

    def _domain_recent_success_stats_locked(self, hostname: str) -> tuple[int, int, float]:
        outcomes = list(self._domain_recent_outcomes.get(hostname) or [])
        total = len(outcomes)
        success_count = sum(1 for item in outcomes if item == "success")
        rate = (success_count / total) if total else 0.0
        return success_count, total, rate

    def _domain_health_snapshot_locked(self, hostname: str, *,
                                       banned: bool,
                                       pause_remaining: int) -> dict[str, Any]:
        """在已持有 _domain_lock 时调用:给 UI 的人类可读域名健康判断。"""
        failure_count = int(self._domain_failure_counts.get(hostname, 0) or 0)
        otp_streak = int(self._domain_otp_timeout_streak.get(hostname, 0) or 0)
        success_streak = int(self._domain_success_streak.get(hostname, 0) or 0)
        recent_success, recent_total, recent_rate = self._domain_recent_success_stats_locked(hostname)

        if banned:
            status = "banned"
            label = "已拉黑"
            color = "default"
            action = "已移出队列"
            reason = "系统已拉黑该子域，不再分配新的注册任务"
        elif failure_count >= _DOMAIN_REPLACE_FAILURE_THRESHOLD:
            status = "replace"
            label = "建议更换"
            color = "red"
            action = "建议更换子域"
            reason = (
                f"域名失败 {failure_count} 次，已达到建议更换阈值 "
                f"{_DOMAIN_REPLACE_FAILURE_THRESHOLD}；即使近期成功也不自动恢复"
            )
        elif failure_count >= _DOMAIN_HIGH_RISK_FAILURE_THRESHOLD:
            if (
                success_streak >= _DOMAIN_HIGH_RISK_RECOVERY_SUCCESS_STREAK
                and pause_remaining <= 0
                and otp_streak == 0
            ):
                status = "fatigued"
                label = "疲劳"
                color = "orange"
                action = "降并发观察"
                reason = (
                    f"历史失败 {failure_count} 次，但已连续成功 {success_streak} 次，"
                    "从高风险降为疲劳"
                )
            else:
                status = "high_risk"
                label = "高风险"
                color = "volcano"
                action = "暂停或换代理"
                reason = (
                    f"域名失败 {failure_count} 次，达到高风险阈值 "
                    f"{_DOMAIN_HIGH_RISK_FAILURE_THRESHOLD}；需要连续成功 "
                    f"{_DOMAIN_HIGH_RISK_RECOVERY_SUCCESS_STREAK} 次且无新失败才降为疲劳"
                )
        elif (
            failure_count >= _DOMAIN_FATIGUED_FAILURE_THRESHOLD
            or pause_remaining > 0
            or otp_streak >= 3
        ):
            if (
                success_streak >= _DOMAIN_FATIGUE_RECOVERY_SUCCESS_STREAK
                and pause_remaining <= 0
                and otp_streak == 0
            ):
                if (
                    recent_total >= _DOMAIN_RECENT_OUTCOME_WINDOW
                    and recent_rate >= _DOMAIN_HEALTHY_RECENT_SUCCESS_RATE
                ):
                    status = "healthy"
                    label = "健康"
                    color = "green"
                    action = "继续使用"
                    reason = (
                        f"连续成功 {success_streak} 次，最近 {recent_total} 次成功率 "
                        f"{recent_rate:.0%}，已恢复健康"
                    )
                else:
                    status = "observe"
                    label = "观察"
                    color = "gold"
                    action = "继续观察"
                    reason = (
                        f"连续成功 {success_streak} 次，已从疲劳降为观察；"
                        "最近窗口成功率还不足以判定健康"
                    )
            else:
                status = "fatigued"
                label = "疲劳"
                color = "orange"
                action = "降并发观察"
                reasons: list[str] = []
                if failure_count >= _DOMAIN_FATIGUED_FAILURE_THRESHOLD:
                    reasons.append(f"域名失败 {failure_count} 次")
                if pause_remaining > 0:
                    reasons.append(f"暂停剩余 {pause_remaining}s")
                if otp_streak >= 3:
                    reasons.append(f"OTP 连续超时 {otp_streak} 次")
                reason = "，".join(reasons) or "近期验证码不稳定"
        elif failure_count > 0 or otp_streak > 0:
            status = "observe"
            label = "观察"
            color = "gold"
            action = "继续观察"
            reason = f"已有失败 {failure_count} 次，OTP 连续超时 {otp_streak} 次，暂未达到疲劳阈值"
        else:
            status = "healthy"
            label = "健康"
            color = "green"
            action = "继续使用"
            reason = "暂无 OTP 连续超时或域名失败"

        return {
            "health_status": status,
            "health_label": label,
            "health_color": color,
            "recommended_action": action,
            "health_reason": reason,
            "success_streak": success_streak,
            "recent_success_count": recent_success,
            "recent_window_total": recent_total,
            "recent_success_rate": round(recent_rate, 4),
        }

    def _all_available_domains_paused_wait_seconds(self) -> float:
        """如果所有未 banned 且未满配额的域名都在短暂停顿,返回最近恢复秒数。"""
        max_per_domain = int(self._state.config.get("max_per_domain") or 500)
        now = time.monotonic()
        with self._domain_lock:
            eligible = [
                h for h in self._domain_used
                if h not in self._domain_banned
                and self._domain_used.get(h, 0) + self._domain_inflight.get(h, 0) < max_per_domain
            ]
            if not eligible:
                return 0.0
            waits: list[float] = []
            for h in eligible:
                until = float(self._domain_paused_until.get(h) or 0)
                if until <= now:
                    self._domain_paused_until.pop(h, None)
                    return 0.0
                waits.append(until - now)
            return max(0.0, min(waits) if waits else 0.0)

    def _has_non_banned_domain_in_pool(self) -> bool:
        with self._domain_lock:
            return any(h not in self._domain_banned for h in self._domain_used)

    @staticmethod
    def _is_otp_timeout_error(exc: Exception) -> bool:
        text = str(exc or "")
        return "未获取到验证码" in text and "单轮" in text

    def _record_domain_success(self, hostname: str) -> None:
        host = (hostname or "").strip().lower()
        if not host:
            return
        with self._domain_lock:
            self._domain_otp_timeout_streak.pop(host, None)
            self._domain_paused_until.pop(host, None)
            self._domain_success_streak[host] = int(self._domain_success_streak.get(host) or 0) + 1
            self._append_domain_outcome_locked(host, "success")

    def _record_domain_otp_timeout(self, hostname: str, reason: str = "") -> None:
        """记录该子域一次 OTP 超时。

        规则:
          - 连续 OTP 超时达到 business_rt_otp_timeout_streak_threshold
            记 1 次域名失败,并把连续计数清零。
          - 域名失败次数达到 business_rt_domain_failure_limit 后,
            直接拉黑该 BUSINESS 子域。
          - 未达拉黑阈值时,仅短暂停顿 business_rt_domain_failure_pause_seconds。
        """
        host = (hostname or "").strip().lower()
        if not host:
            return
        streak_threshold = self._otp_timeout_streak_threshold()
        failure_limit = self._domain_failure_limit()
        pause_seconds = self._domain_failure_pause_seconds()
        should_ban = False
        failure_count = 0
        streak = 0
        with self._domain_lock:
            self._domain_success_streak[host] = 0
            self._append_domain_outcome_locked(host, "otp_timeout")
            streak = int(self._domain_otp_timeout_streak.get(host) or 0) + 1
            if streak < streak_threshold:
                self._domain_otp_timeout_streak[host] = streak
                self._log(
                    f"⚠ 子域 {host} OTP 超时连续 {streak}/{streak_threshold} 次"
                    "（未达到域名失败计数阈值）"
                )
                return

            self._domain_otp_timeout_streak[host] = 0
            failure_count = int(self._domain_failure_counts.get(host) or 0) + 1
            self._domain_failure_counts[host] = failure_count
            self._append_domain_outcome_locked(host, "domain_failure")
            if failure_count >= failure_limit:
                should_ban = True
            elif pause_seconds > 0:
                self._domain_paused_until[host] = time.monotonic() + pause_seconds

        if should_ban:
            self._mark_domain_banned(
                host,
                reason=(
                    f"连续 OTP 超时 {streak_threshold} 次累计为域名失败;"
                    f" 域名失败次数 {failure_count}/{failure_limit};"
                    f" 最近原因: {reason[:120]}"
                ),
            )
            return

        pause_label = f", 暂停 {pause_seconds}s 后再试" if pause_seconds > 0 else ""
        self._log(
            f"⚠ 子域 {host} 连续 OTP 超时 {streak_threshold} 次,"
            f"记为域名失败 {failure_count}/{failure_limit}{pause_label}"
        )

    def _release_domain(self, reservation_id: str, *, success: bool) -> bool:
        """释放 inflight,成功时 used+1。reservation_id 缺失代表已超时释放。"""
        with self._domain_lock:
            hostname = self._domain_reservations.pop(reservation_id, "")
            if not hostname:
                return False
            if hostname not in self._domain_inflight:
                return False
            self._domain_inflight[hostname] = max(0, self._domain_inflight[hostname] - 1)
            if success:
                self._domain_used[hostname] = self._domain_used.get(hostname, 0) + 1
            return True

    def _mark_domain_banned(self, hostname: str, *, reason: str = "") -> bool:
        """检测到 OpenAI 风控后,标记该子域为 banned。

        - 加入本进程共享 set, 其它 worker 立即在 _reserve_next_domain 跳过
        - 从 _domain_used / _domain_inflight 移除, 不再参与配额计算
        - DB 持久化: BusinessDomainModel.status='banned' + note
        - 醒目日志, 长跑界面通过 status 接口可见 domain_banned 计数 + banned 列表
        """
        host = (hostname or "").strip().lower()
        if not host:
            return False
        with self._domain_lock:
            if host in self._domain_banned:
                return False  # 别的 worker 已经标过了
            self._domain_banned.add(host)
            self._domain_used.pop(host, None)
            self._domain_inflight.pop(host, None)
            self._domain_otp_timeout_streak.pop(host, None)
            self._domain_paused_until.pop(host, None)
        # DB 持久化(失败不影响 in-memory 跳过)
        persisted = False
        try:
            with Session(engine) as s:
                row = s.exec(
                    select(BusinessDomainModel)
                    .where(BusinessDomainModel.hostname == host)
                ).first()
                if row is not None:
                    row.status = "banned"
                    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    suffix = f"[{stamp}] auto-banned: {reason[:160] or 'OpenAI Access Deactivated'}"
                    existing = (row.note or "").strip()
                    row.note = (existing + ("\n" if existing else "") + suffix)[:1000]
                    row.updated_at = datetime.now(timezone.utc)
                    s.add(row)
                    s.commit()
                    persisted = True
        except Exception as exc:
            self._log(f"⚠ 标记 {host}=banned 写库失败(内存已生效): {exc}")
        with self._lock:
            self._state.counters.domain_banned += 1
        suffix = "DB 已落库" if persisted else "仅内存,DB 写库失败"
        self._log("=" * 56)
        self._log(f"🚫 子域已拉黑: {host}")
        self._log(f"   原因: {reason or 'OpenAI Access Deactivated'}")
        self._log(f"   后续 worker 不再选择该子域 ({suffix})")
        self._log(f"   ◆ CF DNS + OpenAI workspace 记录保留(不自动删除)")
        self._log(f"   ◆ 同子域上剩余账号仍可继续补 RT,不被波及")
        self._log(f"   ◆ rotation 将自动补一个新子域接替")
        self._log(f"   在「Business 域名」页面可看到 status=banned;如需彻底删除请手动操作")
        self._log("=" * 56)
        return True

    def clear_banned_hostname(self, hostname: str) -> bool:
        """管理员手动恢复被自动拉黑的子域,从内存 banned set 移除。

        - DB 状态由 business_domain_service.reset_domain_status 处理
        - runner 没启动时调用也安全(空操作)
        - 重新放回 _domain_used / _domain_inflight,used 从 0 重新计数
          (准确的历史计数等下次 _initialize_domain_used 重算)
        """
        host = (hostname or "").strip().lower()
        if not host:
            return False
        with self._domain_lock:
            if host not in self._domain_banned:
                return False
            self._domain_banned.discard(host)
            self._domain_used.setdefault(host, 0)
            self._domain_inflight.setdefault(host, 0)
        self._log(
            f"✓ 子域 {host} 已从 banned 名单移除, 长跑后续可再次选择"
        )
        return True

    # ─────────────────────────────────────────────────────────────────
    # 子域自动 rotation: 单线程调度,满子域回收 + 池子下限补新
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _auto_delete_banned_domains_enabled() -> bool:
        """是否允许 rotation 自动删除已拉黑子域。

        默认关闭: 删除子域会同时删除 CF DNS + OpenAI workspace domain + 本地记录。
        开启后仍会检查该域是否存在待 RT / 待改席位账号,避免把仍需邮箱验证码
        的账号链路直接切断。
        """
        try:
            from core.config_store import config_store
            raw = str(
                config_store.get("business_rt_auto_delete_banned_domains", "0") or "0"
            ).strip().lower()
        except Exception:
            raw = "0"
        return raw in {"1", "true", "yes", "on"}

    def _domain_has_pending_accounts(self, hostname: str) -> bool:
        """该子域是否还有依赖邮箱验证码继续处理的账号。

        保留为诊断辅助方法,不再作为自动删除拉黑子域的阻断条件:
        BUSINESS 待 RT 账号后续不依赖该 BUSINESS 子域继续收信,所以删除
        banned 子域不会影响待 RT 队列继续补 RT。

        查询失败时按"有待处理"处理,宁可不删也不误删。
        """
        host = (hostname or "").strip().lower().lstrip("@")
        if not host:
            return True
        suffix = f"@{host}"
        try:
            with Session(engine) as s:
                rows = s.exec(
                    select(AccountModel.email)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status.in_(list(_DOMAIN_AUTO_DELETE_BLOCKING_STATUSES)))
                ).all()
        except Exception as exc:
            msg = f"检查 {host} 待处理账号失败,为安全起见跳过自动删除: {exc}"
            self._rotation_state["last_error"] = msg[:240]
            self._log(f"[rotation] ⚠ {msg}")
            return True
        return any(str(email or "").strip().lower().endswith(suffix) for email in rows)

    def _banned_hostnames_safe_to_delete(self) -> list[str]:
        """已废弃: banned 子域不再被 rotation 自动删除。

        旧逻辑会按 business_rt_auto_delete_banned_domains 配置自动删 banned 子域
        (同步删 CF DNS + OpenAI workspace + DB),但会让该子域上剩余的待补 RT 账号
        随 DNS 消失而彻底报废。

        新策略:
        - banned 子域保留 CF DNS + OpenAI workspace 记录,只从内存 active pool 摘掉
        - rotation 继续按 alive<target 自动补新子域接替
        - 如需彻底删除,请用「Business 域名」页面的删除按钮手动操作
          (走 services.business_domain_service.delete_domain)

        business_rt_auto_delete_banned_domains 配置已被忽略(向后兼容,DB 值不动)。
        """
        return []

    def _full_hostnames_safe_to_delete(self) -> list[str]:
        """挑「满了且 inflight=0」的子域作为可删候选。
        - 满 = used + inflight >= max_per_domain
        - inflight=0 = 没正在跑的 worker 在用它,删了不会砍掉进行中的注册
        - banned 子域**不**自动删 (留给用户手动决定)
        """
        max_per_domain = int(self._state.config.get("max_per_domain") or 500)
        with self._domain_lock:
            return [
                h for h in self._domain_used
                if h not in self._domain_banned
                and self._domain_inflight.get(h, 0) == 0
                and self._domain_used[h] >= max_per_domain
            ]

    def _alive_pool_size(self) -> int:
        """未满未 banned 的子域数 (= 接下来 worker 能选的池子大小)"""
        max_per_domain = int(self._state.config.get("max_per_domain") or 500)
        with self._domain_lock:
            return sum(
                1 for h in self._domain_used
                if h not in self._domain_banned
                and self._domain_used[h] + self._domain_inflight.get(h, 0) < max_per_domain
            )

    def _pick_rotation_base_domain(self) -> str:
        """选 base_domain 用于创建新子域。
        优先级:
          1. config_store.business_default_base_domain
          2. 现有 verified 子域里, 按子域数量分组, 数量最少的根域 (负载均衡)
          3. 空字符串 (调用方报错)
        """
        try:
            from core.config_store import config_store
            cfg = str(config_store.get("business_default_base_domain", "") or "").strip().lower()
            if cfg:
                return cfg
        except Exception:
            pass
        # 没配 business_default_base_domain → 从本机已有 verified 子域推导根域
        # (只看本机 owner, 避免拿别的机器的根域去 rotation)
        try:
            from collections import Counter
            from core.machine_id import current_machine_id
            me = current_machine_id()
            with Session(engine) as s:
                rows = s.exec(
                    select(BusinessDomainModel)
                    .where(BusinessDomainModel.status == "verified")
                    .where(BusinessDomainModel.owner_machine_id == me)
                ).all()
            cnt = Counter(r.base_domain for r in rows if r.base_domain)
            if cnt:
                # 子域数最少的根域 (新建子域分摊到该根域)
                return min(cnt, key=lambda d: cnt[d])
        except Exception:
            pass
        return ""

    def _rotate_domain_pool(self) -> None:
        """单线程调度:满了的子域回收 + 池子下限自动补新。

        - 不抢 worker 的锁,只通过 _domain_lock 读写 _domain_used/_domain_inflight
        - 限频: 两次 rotation 至少间隔 _ROTATION_MIN_INTERVAL_SECONDS
        - 失败容忍: 单步失败只打日志,不抛
        """
        now = time.time()
        if now - self._last_rotation_at < _ROTATION_MIN_INTERVAL_SECONDS:
            return

        banned_deletable = self._banned_hostnames_safe_to_delete()
        deletable = self._full_hostnames_safe_to_delete()
        alive = self._alive_pool_size()
        target = int(self._rotation_state.get("target_pool_size") or _ROTATION_TARGET_POOL_SIZE)
        need_add = alive < target

        if not banned_deletable and not deletable and not need_add:
            return  # 无事可做

        self._last_rotation_at = now
        action_summary = []
        attempted_delete = False

        # Step 0: 串行删除一个已拉黑且安全的子域。
        # 复用 rotation 线程,避免另起一条并发删除/创建线程打到 CF/OpenAI。
        if banned_deletable:
            host = banned_deletable[0]
            ok, reason = self._rotation_delete_one(host)
            action_summary.append(f"删除拉黑子域 {host}: {'OK' if ok else reason[:80]}")
            attempted_delete = True
            if ok:
                self._rotation_state["deleted_count"] += 1

        # Step 1: 串行删除一个满子域 (一次循环只删 1 个, 避免单次操作过长)
        if not attempted_delete and deletable:
            host = deletable[0]
            ok, reason = self._rotation_delete_one(host)
            action_summary.append(f"删除 {host}: {'OK' if ok else reason[:80]}")
            if ok:
                self._rotation_state["deleted_count"] += 1

        # Step 2: 池子还不够 → 加一个新子域
        if need_add:
            with self._domain_lock:
                banned_count = len(self._domain_banned)
            if banned_count:
                self._log(
                    f"[rotation] 检测到 {banned_count} 个 banned 子域(保留 DNS/workspace,不自动删) "
                    f"+ alive_pool={alive}<target={target}, 准备补一个新子域接替"
                )
            base = self._pick_rotation_base_domain()
            if not base:
                action_summary.append(
                    "需要补新子域但 business_default_base_domain 未配置, 且无 verified 域可推导"
                )
                self._rotation_state["last_error"] = (
                    "需要补新子域但根域未配置 (请在「全局配置」设 business_default_base_domain)"
                )
            else:
                ok, info = self._rotation_create_one(base)
                action_summary.append(
                    f"补新子域 (根域={base}): {info[:120]}"
                )
                if ok:
                    self._rotation_state["created_count"] += 1

        if action_summary:
            summary = "; ".join(action_summary)
            self._rotation_state["last_action_at"] = datetime.now(timezone.utc).isoformat()
            self._rotation_state["last_action"] = summary
            self._log(f"[rotation] {summary}")

    def _rotation_delete_one(self, hostname: str) -> tuple[bool, str]:
        """串行删一个满子域。删除前从 _domain_used/_domain_inflight 移除, 失败也不回滚 (DB 真删了就一致了)。"""
        # 先查 DB 拿 id
        try:
            with Session(engine) as s:
                row = s.exec(
                    select(BusinessDomainModel)
                    .where(BusinessDomainModel.hostname == hostname)
                ).first()
                if row is None:
                    # DB 里已没了 -- 内存清理掉就行
                    with self._domain_lock:
                        self._domain_used.pop(hostname, None)
                        self._domain_inflight.pop(hostname, None)
                    return True, "DB 已无该域, 内存清理完成"
                domain_id = row.id
        except Exception as exc:
            return False, f"查 DB 失败: {exc}"

        try:
            from services.business_domain_service import delete_domain
            delete_domain(domain_id)
        except Exception as exc:
            self._rotation_state["last_error"] = f"删除 {hostname} 失败: {exc}"
            return False, f"删除失败: {exc}"

        # 删 DB 成功 → 清内存
        with self._domain_lock:
            self._domain_used.pop(hostname, None)
            self._domain_inflight.pop(hostname, None)
            self._domain_banned.discard(hostname)
        return True, ""

    def _rotation_create_one(self, base_domain: str) -> tuple[bool, str]:
        """串行加一个新子域 (跑完整 CF DNS + OpenAI verify)。"""
        try:
            from services.business_domain_service import create_domain
            result = create_domain(base_domain, note="auto rotation")
        except Exception as exc:
            err = f"创建新子域 ({base_domain}) 失败: {exc}"
            self._rotation_state["last_error"] = str(exc)[:200]
            return False, err

        new_hostname = (result or {}).get("hostname", "")
        status = (result or {}).get("status", "")
        if new_hostname and status == "verified":
            # 加入内存池, 下次 reserve 立刻可选
            with self._domain_lock:
                self._domain_used.setdefault(new_hostname, 0)
                self._domain_inflight.setdefault(new_hostname, 0)
            self._rotation_state["last_error"] = ""
            return True, f"已加 {new_hostname} (verified)"
        return False, f"create_domain 返回非 verified: status={status} hostname={new_hostname}"

    def _rotation_loop(self) -> None:
        """daemon 线程, 周期巡检, 决定是否触发 _rotate_domain_pool。"""
        self._log(
            f"[rotation] 调度线程已启动 (target={_ROTATION_TARGET_POOL_SIZE}, "
            f"min_interval={_ROTATION_MIN_INTERVAL_SECONDS}s, "
            f"check_every={_ROTATION_CHECK_INTERVAL_SECONDS}s)"
        )
        while not self._rotation_stop.is_set():
            try:
                self._rotate_domain_pool()
            except Exception as exc:
                self._rotation_state["last_error"] = f"rotation 循环异常: {exc}"
                self._log(f"[rotation] 异常 (将继续): {exc}")
            # 用 Event.wait 而非 sleep, stop 时可立刻退出
            if self._rotation_stop.wait(_ROTATION_CHECK_INTERVAL_SECONDS):
                break
        self._log("[rotation] 调度线程已退出")
        self._rotation_state["enabled"] = False

    def _is_reservation_active(self, reservation_id: str) -> bool:
        with self._domain_lock:
            return reservation_id in self._domain_reservations

    def _increment_counter_if_active(self, reservation_id: str, counter_name: str) -> bool:
        if not self._is_reservation_active(reservation_id):
            return False
        with self._lock:
            value = getattr(self._state.counters, counter_name)
            setattr(self._state.counters, counter_name, value + 1)
        return True

    def _refresh_domain_pool(self) -> None:
        """重新拉 verified 子域,合并到现有计数(新增子域 used=0,旧的保留)。
        本进程已 banned 的子域即使 DB 里仍写着 verified 也跳过(防止异步 UI 改回来时再用)。
        """
        hostnames = self._list_verified_hostnames(self._selected_domain_filter())
        with self._domain_lock:
            for h in hostnames:
                if h in self._domain_banned:
                    continue
                if h not in self._domain_used:
                    self._domain_used[h] = 0
                if h not in self._domain_inflight:
                    self._domain_inflight[h] = 0
            # 已不在 verified 列表里的子域,不删除(保留计数避免歧义)

    def _pick_proxy_with_source(self, extra_config: dict) -> tuple[str | None, str]:
        """复用 api/tasks.py:1383-1415 的代理选取链。返回 (proxy_url, 来源描述)。

        固定优先级:
          1. 全局配置 proxy (config_store.proxy)
          2. 按 business_rt_proxy_priority 配置选择:
             - manual_first: 「代理管理」DB → ChatGPT 协议预检池 → 订阅代理池
             - protocol_pool_first: ChatGPT 协议预检池 → 「代理管理」DB → 订阅代理池
             - subscription_first: 订阅代理池 → ChatGPT 协议预检池 → 「代理管理」DB
          3. 全局配置 default_proxy
          全部为空 → 直连
        """
        from core.config_store import config_store as _cs
        from core.proxy_utils import normalize_proxy_url

        # 1. 全局配置 proxy
        explicit = (extra_config.get("proxy") or _cs.get("proxy", "") or "").strip()
        if explicit:
            return normalize_proxy_url(explicit), "全局配置.proxy"

        # 是否允许自动使用代理(开关)
        auto_use = str(
            extra_config.get("register_auto_use_proxy")
            or _cs.get("register_auto_use_proxy", "1")
            or "1"
        ).strip().lower() in ("1", "true", "yes")
        if not auto_use:
            return None, "自动代理已关闭"

        # 2. 动态住宅代理 (711proxy rotating) — 最优先, 每注册一个号换一个 IP
        try:
            from core.dynamic_proxy import borrow_dynamic_proxy
            dyn = borrow_dynamic_proxy()
            if dyn:
                return normalize_proxy_url(dyn), "动态住宅代理(711proxy rotating)"
        except Exception as exc:
            self._log(f"动态住宅代理 拉取异常(继续 fallback): {exc}")

        proxy_priority = self._normalize_proxy_priority(
            extra_config.get("business_rt_proxy_priority")
            or self._state.config.get("proxy_priority")
            or _cs.get("business_rt_proxy_priority", _PROXY_PRIORITY_MANUAL_FIRST)
            or _PROXY_PRIORITY_MANUAL_FIRST
        )

        def pick_protocol_pool() -> tuple[str | None, str]:
            try:
                from services.proxy_pool import next_chatgpt_protocol_proxy

                proto = next_chatgpt_protocol_proxy()
                if proto and proto.get("addr"):
                    name = proto.get("name") or "anonymous"
                    latency = proto.get("latency")
                    suffix = f",延迟 {latency}ms" if latency else ""
                    return (
                        normalize_proxy_url(str(proto["addr"])),
                        f"ChatGPT协议预检池:{name}{suffix}",
                    )
            except Exception as e:
                self._log(f"ChatGPT协议预检池 取节点异常: {e}")
            return None, ""

        def pick_manual_db() -> tuple[str | None, str]:
            try:
                from core.proxy_pool import proxy_pool
                picked = proxy_pool.get_next()
                if picked:
                    return normalize_proxy_url(str(picked)), "代理管理.DB"
            except Exception as e:
                self._log(f"代理管理.DB 取节点异常: {e}")
            return None, ""

        def pick_subscription_pool() -> tuple[str | None, str]:
            try:
                from services.proxy_pool import next_proxy as _sub_next
                sub = _sub_next()
                if sub and sub.get("addr"):
                    name = sub.get("name") or "anonymous"
                    return normalize_proxy_url(str(sub["addr"])), f"订阅代理池:{name}"
            except Exception as e:
                self._log(f"订阅代理池 取节点异常: {e}")
            return None, ""

        orders = {
            _PROXY_PRIORITY_MANUAL_FIRST: (
                pick_manual_db,
                pick_protocol_pool,
                pick_subscription_pool,
            ),
            _PROXY_PRIORITY_PROTOCOL_POOL_FIRST: (
                pick_protocol_pool,
                pick_manual_db,
                pick_subscription_pool,
            ),
            _PROXY_PRIORITY_SUBSCRIPTION_FIRST: (
                pick_subscription_pool,
                pick_protocol_pool,
                pick_manual_db,
            ),
        }
        for picker in orders[proxy_priority]:
            proxy, source = picker()
            if proxy:
                return proxy, source

        # 5. 全局配置 default_proxy
        default_proxy = (_cs.get("default_proxy", "") or "").strip()
        if default_proxy:
            return normalize_proxy_url(default_proxy), "全局配置.default_proxy"

        return None, "无可用代理"

    @staticmethod
    def _normalize_proxy_priority(value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {
            _PROXY_PRIORITY_MANUAL_FIRST,
            _PROXY_PRIORITY_PROTOCOL_POOL_FIRST,
            _PROXY_PRIORITY_SUBSCRIPTION_FIRST,
        }:
            return normalized
        return _PROXY_PRIORITY_MANUAL_FIRST

    @staticmethod
    def _submit_interval_seconds() -> float:
        """读取 worker 补位间隔。

        默认 800ms: 避免滑动窗口完成即补位导致 /signin、/authorize、
        /email-otp/send 在同一秒内堆叠。允许配置为 0 关闭节流。
        """
        try:
            from core.config_store import config_store
            raw = str(
                config_store.get(
                    "business_rt_submit_interval_ms",
                    str(_SUBMIT_INTERVAL_MS_DEFAULT),
                )
                or str(_SUBMIT_INTERVAL_MS_DEFAULT)
            ).strip()
            ms = int(float(raw))
        except Exception:
            ms = _SUBMIT_INTERVAL_MS_DEFAULT
        ms = max(0, min(_SUBMIT_INTERVAL_MS_MAX, ms))
        return ms / 1000.0

    @staticmethod
    def _int_config(key: str, default: int, *, min_value: int, max_value: int) -> int:
        try:
            from core.config_store import config_store
            raw = str(config_store.get(key, str(default)) or str(default)).strip()
            value = int(float(raw))
        except Exception:
            value = default
        return max(min_value, min(max_value, value))

    @staticmethod
    def _is_new_business_flow_enabled() -> bool:
        """新流程开关 (default ON): 注册落 PENDING_INVITE,后续 daemon 接力。

        关闭时回到旧 _register_business_oauth 一站式 4 阶段(Codex 路径)。
        """
        try:
            from core.config_store import config_store
            raw = str(config_store.get("business_new_flow_enabled", "1") or "1").strip().lower()
        except Exception:
            return True
        return raw in {"1", "true", "yes", "on"}

    @classmethod
    def _otp_timeout_streak_threshold(cls) -> int:
        return cls._int_config(
            "business_rt_otp_timeout_streak_threshold",
            _OTP_TIMEOUT_STREAK_THRESHOLD_DEFAULT,
            min_value=1,
            max_value=100,
        )

    @classmethod
    def _domain_failure_limit(cls) -> int:
        return cls._int_config(
            "business_rt_domain_failure_limit",
            _DOMAIN_FAILURE_LIMIT_DEFAULT,
            min_value=1,
            max_value=100,
        )

    @classmethod
    def _domain_failure_pause_seconds(cls) -> int:
        return cls._int_config(
            "business_rt_domain_failure_pause_seconds",
            _DOMAIN_FAILURE_PAUSE_SECONDS_DEFAULT,
            min_value=0,
            max_value=_DOMAIN_FAILURE_PAUSE_SECONDS_MAX,
        )

    def _build_extra_config(self, hostname: str) -> dict[str, Any]:
        from core.config_store import config_store
        proxy_priority = self._normalize_proxy_priority(
            self._state.config.get("proxy_priority")
            or config_store.get("business_rt_proxy_priority", _PROXY_PRIORITY_MANUAL_FIRST)
            or _PROXY_PRIORITY_MANUAL_FIRST
        )
        extra: dict[str, Any] = {
            "business_domain": hostname,
            "mail_provider": "cfworker",
            "chatgpt_registration_mode": "refresh_token",
            "chatgpt_has_refresh_token_solution": True,
            "business_rt_register_only": "1",
            "business_switch_to_codex": "0",
            "business_rt_proxy_priority": proxy_priority,
            "chatgpt_security_after_register": config_store.get(
                "chatgpt_security_after_register", "1"
            ),
            # 默认开启自动代理池,让 _attempt_one 里 _pick_subscription_proxy 兜底
            "register_auto_use_proxy": "1",
        }
        # 注入全局 cfworker / proxy 配置
        for key in (
            "cfworker_api_url", "cfworker_admin_token", "cfworker_custom_auth",
            "business_email_machine_prefix", "chatgpt_oauth_otp_wait_seconds",
            "proxy",
        ):
            value = config_store.get(key, "")
            if value:
                extra[key] = value
        # register_auto_use_proxy 用户全局禁用时尊重之
        opt = config_store.get("register_auto_use_proxy", "")
        if opt:
            extra["register_auto_use_proxy"] = str(opt)
        return extra

    def _reset_all_business_quotas(self) -> None:
        """配额归零: 把 _domain_used 全部清零,inflight 不动(可能还有任务在跑)。"""
        with self._domain_lock:
            count = len(self._domain_used)
            for h in self._domain_used:
                self._domain_used[h] = 0
        self._log(f"✓ {count} 个子域配额已归零")

    @staticmethod
    def _gen_password(length: int = 16) -> str:
        import string
        chars = string.ascii_letters + string.digits + "!@#$"
        return "".join(random.choice(chars) for _ in range(length))

    # ------------------------------------------------------------------ batch fixup

    def start_auto_rt(self, *,
                      concurrency: int = _AUTO_RT_CONCURRENCY_DEFAULT,
                      poll_interval_seconds: float = 3.0,
                      rt_retry_limit_enabled: bool = False,
                      max_retries: int = 5) -> dict[str, Any]:
        """启动自动补 RT watcher: 监控 pending_rt,有号就自动补 RT。"""
        concurrency = max(1, min(20, int(concurrency or _AUTO_RT_CONCURRENCY_DEFAULT)))
        poll_interval_seconds = max(1.0, min(60.0, float(poll_interval_seconds or 3.0)))
        max_retries = max(1, min(50, int(max_retries or 5)))
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {"ok": False, "error": "已有一键补救任务在运行,请等待完成"}
        with self._auto_rt_lock:
            if self._auto_rt_state.get("running") or self._auto_rt_state.get("stopping"):
                return {"ok": False, "error": "自动补 RT 已在运行"}
            self._auto_rt_stop_event.clear()
            self._auto_rt_state = {
                "running": True,
                "stopping": False,
                "concurrency": concurrency,
                "poll_interval_seconds": poll_interval_seconds,
                "inflight": 0,
                "claimed": 0,
                "success": 0,
                "failed": 0,
                "uploaded": 0,
                "upload_failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "stopped_at": "",
                "last_scan_at": "",
                "last_error": "",
                "rt_retry_limit_enabled": bool(rt_retry_limit_enabled),
                "max_retries": max_retries,
            }
            self._auto_rt_thread = threading.Thread(
                target=self._auto_rt_loop,
                args=(
                    concurrency,
                    poll_interval_seconds,
                    max_retries if rt_retry_limit_enabled else None,
                ),
                daemon=True,
                name="biz-auto-rt-driver",
            )
            self._auto_rt_thread.start()
        retry_label = (
            f"ON max={max_retries}" if rt_retry_limit_enabled else "OFF"
        )
        self._log(
            f"▶ 自动补 RT 启动: 并发 {concurrency},扫描间隔 {poll_interval_seconds:g}s,"
            f" RT 重试上限={retry_label}"
        )
        return {"ok": True, "concurrency": concurrency}

    def stop_auto_rt(self) -> dict[str, Any]:
        with self._auto_rt_lock:
            if not (
                self._auto_rt_state.get("running")
                or self._auto_rt_state.get("stopping")
            ):
                return {"ok": False, "error": "自动补 RT 未运行"}
            self._auto_rt_stop_event.set()
            self._auto_rt_state["stopping"] = True
        self._log("收到自动补 RT 停止信号")
        return {"ok": True}

    def _auto_rt_loop(self, concurrency: int, poll_interval_seconds: float,
                      max_retries: int | None) -> None:
        futures: dict[Future, int] = {}
        try:
            with ThreadPoolExecutor(
                max_workers=concurrency,
                thread_name_prefix="biz-auto-rt",
            ) as ex:
                while True:
                    for future in list(futures):
                        if not future.done():
                            continue
                        account_id = futures.pop(future)
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = {
                                "id": account_id,
                                "ok": False,
                                "error": str(exc),
                            }
                            self._log(f"自动补 RT 任务异常: {exc}")
                        self._record_auto_rt_result(result)

                    with self._auto_rt_lock:
                        self._auto_rt_state["inflight"] = len(futures)

                    if self._auto_rt_stop_event.is_set():
                        if not futures:
                            break
                        self._auto_rt_stop_event.wait(0.5)
                        continue

                    capacity = max(0, concurrency - len(futures))
                    claimed_ids = self._claim_pending_rt_accounts(capacity)
                    if claimed_ids:
                        with self._auto_rt_lock:
                            self._auto_rt_state["claimed"] += len(claimed_ids)
                            self._auto_rt_state["inflight"] = len(futures) + len(claimed_ids)
                        for account_id in claimed_ids:
                            futures[ex.submit(self._auto_rt_one, account_id, max_retries)] = account_id
                        continue

                    # 本机 pending_rt 已空 → consumer 模式下从 peer 拉一波,
                    # 拉过来的会落到本机 pending_rt,下一轮 _claim_pending_rt_accounts 自然能领到。
                    if capacity > 0:
                        try:
                            from services.peer_sync import is_consumer
                            from services.peer_sync_puller import pull_from_peers
                            if is_consumer():
                                result = pull_from_peers(requested=capacity, force=True)
                                fetched = int(result.get("fetched_total") or 0)
                                if fetched > 0:
                                    self._log(
                                        f"📥 自动补 RT: 本机 pending_rt 已空,"
                                        f"从 peer 拉了 {fetched} 条 → 下一轮 claim"
                                    )
                                    continue
                        except Exception as peer_exc:
                            self._log(f"⚠ peer pull 异常 (忽略,继续): {peer_exc}")

                    self._auto_rt_stop_event.wait(
                        0.2 if futures else poll_interval_seconds
                    )
        except Exception as exc:
            with self._auto_rt_lock:
                self._auto_rt_state["last_error"] = str(exc)
            self._log(f"❌ 自动补 RT 异常退出: {exc}")
        finally:
            with self._auto_rt_lock:
                self._auto_rt_state["running"] = False
                self._auto_rt_state["stopping"] = False
                self._auto_rt_state["inflight"] = 0
                self._auto_rt_state["stopped_at"] = datetime.now(timezone.utc).isoformat()
            self._log("✓ 自动补 RT 已停止")

    def _auto_rt_one(self, account_id: int,
                     max_retries: int | None) -> dict[str, Any]:
        result = self._fixup_one_rt(account_id, max_retries)
        if result.get("ok"):
            self._clear_auto_rt_claim(account_id)
            upload_result = self._auto_upload_fixed_rt_account(account_id)
            result.update(upload_result)
            return result
        delay = self._auto_rt_backoff_seconds(account_id)
        self._clear_auto_rt_claim(
            account_id,
            next_attempt_seconds=delay,
            error=str(result.get("error") or ""),
        )
        result["next_attempt_seconds"] = delay
        return result

    def _record_auto_rt_result(self, result: dict[str, Any]) -> None:
        ok = bool(result.get("ok"))
        upload_attempted = bool(result.get("upload_attempted"))
        uploaded = bool(result.get("uploaded"))
        with self._auto_rt_lock:
            if ok:
                self._auto_rt_state["success"] += 1
            else:
                self._auto_rt_state["failed"] += 1
                self._auto_rt_state["last_error"] = str(result.get("error") or "")
            if uploaded:
                self._auto_rt_state["uploaded"] += 1
            elif upload_attempted:
                self._auto_rt_state["upload_failed"] += 1

    @staticmethod
    def _parse_utc_datetime(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    def _claim_pending_rt_accounts(self, limit: int) -> list[int]:
        limit = max(0, int(limit or 0))
        now = datetime.now(timezone.utc)
        with self._auto_rt_lock:
            self._auto_rt_state["last_scan_at"] = now.isoformat()
        if limit <= 0:
            return []
        claimed: list[int] = []
        stale_before = now - timedelta(minutes=30)
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                rows = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.PENDING_RT.value)
                    .order_by(AccountModel.updated_at.asc())
                    .limit(max(50, limit * 8))
                ).all()
                for acc in rows:
                    if len(claimed) >= limit:
                        break
                    extra = acc.get_extra()
                    next_attempt_at = self._parse_utc_datetime(
                        extra.get("rt_auto_next_attempt_at")
                    )
                    if next_attempt_at and next_attempt_at > now:
                        continue
                    claimed_at = self._parse_utc_datetime(
                        extra.get("rt_auto_claimed_at")
                    )
                    if extra.get("rt_auto_claim_id") and claimed_at and claimed_at > stale_before:
                        continue
                    extra["rt_auto_claim_id"] = uuid.uuid4().hex
                    extra["rt_auto_claimed_at"] = now.isoformat()
                    extra.pop("rt_auto_next_attempt_at", None)
                    acc.set_extra(extra)
                    acc.updated_at = _utcnow()
                    s.add(acc)
                    if acc.id is not None:
                        claimed.append(acc.id)
                s.commit()
        except Exception as exc:
            with self._auto_rt_lock:
                self._auto_rt_state["last_error"] = str(exc)
            self._log(f"自动补 RT 扫描待 RT 队列异常: {exc}")
            return []
        if claimed:
            self._log(f"自动补 RT claim {len(claimed)} 个待 RT 账号")
        return claimed

    def _clear_auto_rt_claim(self, account_id: int, *,
                             next_attempt_seconds: int = 0,
                             error: str = "") -> None:
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra.pop("rt_auto_claim_id", None)
                extra.pop("rt_auto_claimed_at", None)
                if next_attempt_seconds > 0:
                    next_at = datetime.now(timezone.utc) + timedelta(
                        seconds=next_attempt_seconds
                    )
                    extra["rt_auto_next_attempt_at"] = next_at.isoformat()
                else:
                    extra.pop("rt_auto_next_attempt_at", None)
                if error:
                    extra["rt_auto_last_error"] = str(error)[:500]
                else:
                    extra.pop("rt_auto_last_error", None)
                acc.set_extra(extra)
                acc.updated_at = _utcnow()
                s.add(acc)
                s.commit()
        except Exception as exc:
            self._log(f"自动补 RT 清理 claim 失败(account_id={account_id}): {exc}")

    def _auto_rt_backoff_seconds(self, account_id: int) -> int:
        retry_count = 1
        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if acc:
                    retry_count = int(acc.get_extra().get("rt_retry_count") or 1)
        except Exception:
            pass
        if retry_count <= 1:
            return 120
        if retry_count == 2:
            return 300
        return 600

    # ============================================================== pipeline all-in-one

    def start_pipeline_all(self, *,
                            concurrency: int = 3,
                            max_per_domain: int = 500,
                            domain_hostnames: list | None = None,
                            invite_batch_size: int = 6,
                            invite_batch_interval_seconds: float = 10.0,
                            activate_concurrency: int = 5,
                            seat_change_concurrency: int = 5,
                            auto_rt_concurrency: int = _AUTO_RT_CONCURRENCY_DEFAULT,
                            auto_rt_poll_interval_seconds: float = 3.0) -> dict[str, Any]:
        """一键启动 register + invite + activate + seat_change + auto_rt 全 5 阶段 daemon.

        每个子 daemon 已运行时返回的 error 会被吞掉(视为已就位),只有所有都失败才整体失败。
        """
        results: dict[str, Any] = {}
        results["register"] = self.start(
            concurrency=concurrency, max_per_domain=max_per_domain,
            domain_hostnames=domain_hostnames,
        )
        results["invite"] = self.start_invite_daemon(
            batch_size=invite_batch_size, batch_interval_seconds=invite_batch_interval_seconds,
        )
        results["activate"] = self.start_activate_daemon(concurrency=activate_concurrency)
        results["seat_change"] = self.start_seat_change_daemon(concurrency=seat_change_concurrency)
        results["auto_rt"] = self.start_auto_rt(
            concurrency=auto_rt_concurrency,
            poll_interval_seconds=auto_rt_poll_interval_seconds,
        )
        any_ok = any(r.get("ok") for r in results.values())
        self._log(
            "▶ 全流程一键启动: " + ", ".join(
                f"{k}={'ok' if v.get('ok') else v.get('error')}" for k, v in results.items()
            )
        )
        return {"ok": any_ok, "results": results}

    def stop_pipeline_all(self) -> dict[str, Any]:
        """一键停止所有 daemon (register/invite/activate/seat_change/auto_rt)。"""
        results: dict[str, Any] = {}
        results["register"] = self.stop()
        results["invite"] = self.stop_invite_daemon()
        results["activate"] = self.stop_activate_daemon()
        results["seat_change"] = self.stop_seat_change_daemon()
        results["auto_rt"] = self.stop_auto_rt()
        self._log("收到全流程一键停止信号")
        return {"ok": True, "results": results}

    # ============================================================== invite daemon

    def start_invite_daemon(self, *,
                            batch_size: int = 6,
                            batch_interval_seconds: float = 10.0) -> dict[str, Any]:
        """启动邀请 daemon: 单线程批量发,每批 batch_size 个,批间停顿 batch_interval_seconds 秒。"""
        batch_size = max(1, min(20, int(batch_size or 6)))
        batch_interval_seconds = max(1.0, min(120.0, float(batch_interval_seconds or 10.0)))
        with self._invite_lock:
            if self._invite_state.get("running") or self._invite_state.get("stopping"):
                return {"ok": False, "error": "邀请 daemon 已在运行"}
            self._invite_stop_event.clear()
            self._invite_state.update({
                "running": True,
                "stopping": False,
                "batch_size": batch_size,
                "batch_interval_seconds": batch_interval_seconds,
                "batches": 0,
                "invited": 0,
                "failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "stopped_at": "",
                "last_scan_at": "",
                "last_error": "",
            })
            self._invite_thread = threading.Thread(
                target=self._invite_loop,
                args=(batch_size, batch_interval_seconds),
                daemon=True,
                name="biz-invite-driver",
            )
            self._invite_thread.start()
        self._log(f"▶ 邀请 daemon 启动: batch={batch_size}, interval={batch_interval_seconds:g}s")
        return {"ok": True, "batch_size": batch_size, "batch_interval_seconds": batch_interval_seconds}

    def stop_invite_daemon(self) -> dict[str, Any]:
        with self._invite_lock:
            if not (self._invite_state.get("running") or self._invite_state.get("stopping")):
                return {"ok": False, "error": "邀请 daemon 未运行"}
            self._invite_stop_event.set()
            self._invite_state["stopping"] = True
        self._log("收到邀请 daemon 停止信号")
        return {"ok": True}

    def _invite_loop(self, batch_size: int, batch_interval_seconds: float) -> None:
        try:
            while not self._invite_stop_event.is_set():
                claimed = self._claim_pending_invite_accounts(batch_size)
                with self._invite_lock:
                    self._invite_state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
                if not claimed:
                    # 没号可发,稍后再来
                    self._invite_stop_event.wait(min(batch_interval_seconds, 5.0))
                    continue
                emails = [c["email"] for c in claimed]
                try:
                    from platforms.chatgpt.plugin import _send_business_invites_batch
                    from core.config_store import config_store
                    proxy = str(config_store.get("default_proxy", "") or "").strip()
                    result = _send_business_invites_batch(emails, self._log, proxy=proxy)
                except Exception as exc:
                    self._log(f"[invite] daemon 批次异常: {exc}")
                    with self._invite_lock:
                        self._invite_state["last_error"] = str(exc)[:300]
                    # 释放 claim,等下一轮重试
                    for c in claimed:
                        self._clear_invite_claim(c["id"], next_attempt_seconds=60,
                                                  error=f"批量调用异常: {exc}")
                    if self._invite_stop_event.wait(batch_interval_seconds):
                        break
                    continue

                invited_map = {
                    str(i.get("email", "")).strip().lower(): str(i.get("invite_id", ""))
                    for i in (result.get("invited") or [])
                }
                errored_map = {
                    str(e.get("email", "")).strip().lower(): str(e.get("message", "邀请失败"))
                    for e in (result.get("errored") or [])
                }
                account_id_master = str(result.get("account_id", ""))
                batch_invited = 0
                batch_failed = 0
                for c in claimed:
                    email_l = str(c["email"]).strip().lower()
                    if email_l in invited_map:
                        self._advance_invite_to_activate(
                            c["id"], invite_id=invited_map[email_l],
                            master_account_id=account_id_master,
                        )
                        batch_invited += 1
                    else:
                        msg = errored_map.get(email_l, "未在响应中找到该 email")
                        self._clear_invite_claim(c["id"], next_attempt_seconds=60, error=msg)
                        batch_failed += 1

                with self._invite_lock:
                    self._invite_state["batches"] += 1
                    self._invite_state["invited"] += batch_invited
                    self._invite_state["failed"] += batch_failed
                self._log(
                    f"[invite] batch #{self._invite_state.get('batches')} "
                    f"sent={len(emails)} ok={batch_invited} err={batch_failed},"
                    f"等待 {batch_interval_seconds:g}s 再发下一批"
                )
                if self._invite_stop_event.wait(batch_interval_seconds):
                    break
        except Exception as exc:
            self._log(f"[invite] daemon 异常退出: {exc}\n{traceback.format_exc()[:400]}")
            with self._invite_lock:
                self._invite_state["last_error"] = str(exc)[:300]
        finally:
            with self._invite_lock:
                self._invite_state["running"] = False
                self._invite_state["stopping"] = False
                self._invite_state["stopped_at"] = datetime.now(timezone.utc).isoformat()
            self._log("[invite] daemon 已退出")

    def _claim_pending_invite_accounts(self, limit: int) -> list[dict[str, Any]]:
        """从 PENDING_INVITE 队列 claim 一批账号(凑多少算多少,不等待凑齐)。返回 [{id, email}, ...]。"""
        limit = max(0, int(limit or 0))
        if limit <= 0:
            return []
        now = datetime.now(timezone.utc)
        stale_before = now - timedelta(minutes=10)
        claimed: list[dict[str, Any]] = []
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                rows = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.PENDING_INVITE.value)
                    .order_by(AccountModel.updated_at.asc())
                    .limit(max(50, limit * 8))
                ).all()
                for acc in rows:
                    if len(claimed) >= limit:
                        break
                    extra = acc.get_extra()
                    next_attempt_at = self._parse_utc_datetime(
                        extra.get("invite_next_attempt_at")
                    )
                    if next_attempt_at and next_attempt_at > now:
                        continue
                    claimed_at = self._parse_utc_datetime(extra.get("invite_claimed_at"))
                    if extra.get("invite_claim_id") and claimed_at and claimed_at > stale_before:
                        continue
                    extra["invite_claim_id"] = uuid.uuid4().hex
                    extra["invite_claimed_at"] = now.isoformat()
                    extra.pop("invite_next_attempt_at", None)
                    acc.set_extra(extra)
                    acc.updated_at = _utcnow()
                    s.add(acc)
                    if acc.id is not None:
                        claimed.append({"id": int(acc.id), "email": acc.email})
                s.commit()
        except Exception as exc:
            with self._invite_lock:
                self._invite_state["last_error"] = str(exc)[:300]
            self._log(f"[invite] 扫描 PENDING_INVITE 异常: {exc}")
            return []
        return claimed

    def _advance_invite_to_activate(self, account_id: int, *,
                                     invite_id: str, master_account_id: str) -> None:
        """邀请成功 → 写回 invite_id + 推进到 PENDING_ACTIVATE。"""
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra.pop("invite_claim_id", None)
                extra.pop("invite_claimed_at", None)
                extra.pop("invite_next_attempt_at", None)
                extra.pop("invite_last_error", None)
                extra["business_invite_id"] = str(invite_id or "")
                if master_account_id:
                    extra["business_master_account_id"] = master_account_id
                extra["invite_sent_at"] = datetime.now(timezone.utc).isoformat()
                acc.set_extra(extra)
                acc.status = AccountStatus.PENDING_ACTIVATE.value
                acc.updated_at = _utcnow()
                s.add(acc)
                s.commit()
        except Exception as exc:
            self._log(f"[invite] 推进 PENDING_ACTIVATE 失败(account_id={account_id}): {exc}")

    def _clear_invite_claim(self, account_id: int, *,
                            next_attempt_seconds: int = 0,
                            error: str = "") -> None:
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra.pop("invite_claim_id", None)
                extra.pop("invite_claimed_at", None)
                if next_attempt_seconds > 0:
                    next_at = datetime.now(timezone.utc) + timedelta(seconds=next_attempt_seconds)
                    extra["invite_next_attempt_at"] = next_at.isoformat()
                else:
                    extra.pop("invite_next_attempt_at", None)
                if error:
                    extra["invite_last_error"] = str(error)[:500]
                acc.set_extra(extra)
                acc.updated_at = _utcnow()
                s.add(acc)
                s.commit()
        except Exception as exc:
            self._log(f"[invite] 清理 claim 失败(account_id={account_id}): {exc}")

    # ============================================================== activate+seat daemon

    # =================== activate daemon (PENDING_ACTIVATE → PENDING_SEAT_CHANGE)

    def start_activate_daemon(self, *,
                               concurrency: int = 5) -> dict[str, Any]:
        """激活 daemon: 多并发, worker 只做"拉邮件 + GET invite URL", 成功 → PENDING_SEAT_CHANGE."""
        concurrency = max(1, min(20, int(concurrency or 5)))
        with self._activate_lock:
            if self._activate_state.get("running") or self._activate_state.get("stopping"):
                return {"ok": False, "error": "激活 daemon 已在运行"}
            self._activate_stop_event.clear()
            self._activate_state.update({
                "running": True, "stopping": False,
                "concurrency": concurrency,
                "inflight": 0, "claimed": 0, "success": 0, "failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "stopped_at": "", "last_scan_at": "", "last_error": "",
            })
            self._activate_thread = threading.Thread(
                target=self._activate_loop, args=(concurrency,),
                daemon=True, name="biz-activate-driver",
            )
            self._activate_thread.start()
        self._log(f"▶ 激活 daemon 启动: 并发 {concurrency}")
        return {"ok": True, "concurrency": concurrency}

    def stop_activate_daemon(self) -> dict[str, Any]:
        with self._activate_lock:
            if not (self._activate_state.get("running") or self._activate_state.get("stopping")):
                return {"ok": False, "error": "激活 daemon 未运行"}
            self._activate_stop_event.set()
            self._activate_state["stopping"] = True
        self._log("收到激活 daemon 停止信号")
        return {"ok": True}

    # 向后兼容老 API 名
    start_activate_seat_daemon = start_activate_daemon
    stop_activate_seat_daemon = stop_activate_daemon

    def _activate_loop(self, concurrency: int) -> None:
        futures: dict[Future, int] = {}
        try:
            with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="biz-activate") as ex:
                while True:
                    for future in list(futures):
                        if not future.done():
                            continue
                        account_id = futures.pop(future)
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = {"id": account_id, "ok": False, "error": str(exc)}
                            self._log(f"[activate] worker 异常: {exc}")
                        self._record_activate_result(result)

                    with self._activate_lock:
                        self._activate_state["inflight"] = len(futures)

                    if self._activate_stop_event.is_set():
                        if not futures:
                            break
                        self._activate_stop_event.wait(0.5); continue

                    capacity = max(0, concurrency - len(futures))
                    claimed_ids = self._claim_pending_activate_accounts(capacity)
                    if claimed_ids:
                        with self._activate_lock:
                            self._activate_state["claimed"] += len(claimed_ids)
                            self._activate_state["inflight"] = len(futures) + len(claimed_ids)
                        for account_id in claimed_ids:
                            futures[ex.submit(self._activate_one, account_id)] = account_id
                        continue
                    self._activate_stop_event.wait(3.0)
        except Exception as exc:
            self._log(f"[activate] daemon 异常退出: {exc}\n{traceback.format_exc()[:400]}")
            with self._activate_lock:
                self._activate_state["last_error"] = str(exc)[:300]
        finally:
            with self._activate_lock:
                self._activate_state["running"] = False
                self._activate_state["stopping"] = False
                self._activate_state["stopped_at"] = datetime.now(timezone.utc).isoformat()
                self._activate_state["inflight"] = 0
            self._log("[activate] daemon 已退出")

    def _record_activate_result(self, result: dict[str, Any]) -> None:
        ok = bool(result.get("ok"))
        with self._activate_lock:
            if ok:
                self._activate_state["success"] += 1
            else:
                self._activate_state["failed"] += 1
                err = str(result.get("error") or "")
                if err:
                    self._activate_state["last_error"] = err[:300]

    def _claim_pending_activate_accounts(self, limit: int) -> list[int]:
        limit = max(0, int(limit or 0))
        if limit <= 0:
            return []
        now = datetime.now(timezone.utc)
        with self._activate_lock:
            self._activate_state["last_scan_at"] = now.isoformat()
        stale_before = now - timedelta(minutes=30)
        claimed: list[int] = []
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                rows = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.PENDING_ACTIVATE.value)
                    .order_by(AccountModel.updated_at.asc())
                    .limit(max(50, limit * 8))
                ).all()
                for acc in rows:
                    if len(claimed) >= limit:
                        break
                    extra = acc.get_extra()
                    next_at = self._parse_utc_datetime(extra.get("activate_next_attempt_at"))
                    if next_at and next_at > now:
                        continue
                    claimed_at = self._parse_utc_datetime(extra.get("activate_claimed_at"))
                    if extra.get("activate_claim_id") and claimed_at and claimed_at > stale_before:
                        continue
                    extra["activate_claim_id"] = uuid.uuid4().hex
                    extra["activate_claimed_at"] = now.isoformat()
                    extra.pop("activate_next_attempt_at", None)
                    acc.set_extra(extra)
                    acc.updated_at = _utcnow()
                    s.add(acc)
                    if acc.id is not None:
                        claimed.append(int(acc.id))
                s.commit()
        except Exception as exc:
            with self._activate_lock:
                self._activate_state["last_error"] = str(exc)[:300]
            self._log(f"[activate] 扫描 PENDING_ACTIVATE 异常: {exc}")
            return []
        if claimed:
            self._log(f"[activate] claim {len(claimed)} 个待激活账号")
        return claimed

    def _activate_one(self, account_id: int) -> dict[str, Any]:
        """worker: 仅做接受邀请 → 成功后转 PENDING_SEAT_CHANGE + 写 seat_change_eligible_at = now + N秒.

        N 由 business_activate_seat_wait_seconds 控制 (默认 10s),给 OpenAI 后端用户传播留时间。
        """
        from core.config_store import config_store
        from core.db import _utcnow
        from platforms.chatgpt.plugin import _activate_invite_via_email

        eligibility_delay = max(0, int(self._int_config(
            "business_activate_seat_wait_seconds", 10, min_value=0, max_value=120,
        )))
        cfworker_api_url = str(config_store.get("cfworker_api_url", "") or "").strip()
        cfworker_admin_token = str(config_store.get("cfworker_admin_token", "") or "").strip()
        cfworker_custom_auth = str(config_store.get("cfworker_custom_auth", "") or "").strip()
        proxy = str(config_store.get("default_proxy", "") or "").strip()

        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return {"id": account_id, "ok": False, "error": "账号不存在"}
                email = acc.email
                extra = acc.get_extra()
            extra_for_call = dict(extra or {})
            extra_for_call["business_email"] = email
            register_proxy = str(extra_for_call.get("register_proxy") or "").strip()
            use_proxy = register_proxy or proxy
            activate = _activate_invite_via_email(
                extra_for_call, cfworker_api_url, cfworker_admin_token, self._log,
                proxy=use_proxy, cfworker_custom_auth=cfworker_custom_auth,
                timeout_seconds=180,
            )
            if not activate.get("ok"):
                err = str(activate.get("error") or "激活失败")
                self._clear_activate_claim(account_id, next_attempt_seconds=120, error=err)
                return {"id": account_id, "ok": False, "error": err}

            # 推进到 PENDING_SEAT_CHANGE,写 invite_activated_at + seat_change_eligible_at
            eligible_at = datetime.now(timezone.utc) + timedelta(seconds=eligibility_delay)
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return {"id": account_id, "ok": False, "error": "账号已被删"}
                e = acc.get_extra()
                e.pop("activate_claim_id", None)
                e.pop("activate_claimed_at", None)
                e.pop("activate_next_attempt_at", None)
                e.pop("activate_last_error", None)
                e["invite_activated_at"] = datetime.now(timezone.utc).isoformat()
                if activate.get("invite_url"):
                    e["invite_activate_url"] = activate["invite_url"][:300]
                e["seat_change_eligible_at"] = eligible_at.isoformat()
                acc.set_extra(e)
                acc.status = AccountStatus.PENDING_SEAT_CHANGE.value
                acc.updated_at = _utcnow()
                s.add(acc); s.commit()
            self._log(f"[activate] ✅ {email} 已激活 → PENDING_SEAT_CHANGE (可切席位时间 {eligibility_delay}s 后)")
            return {"id": account_id, "ok": True, "email": email}
        except Exception as exc:
            self._clear_activate_claim(account_id, next_attempt_seconds=120,
                                       error=f"worker 异常: {exc}")
            return {"id": account_id, "ok": False, "error": str(exc)}

    def _clear_activate_claim(self, account_id: int, *,
                              next_attempt_seconds: int = 0, error: str = "") -> None:
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra.pop("activate_claim_id", None)
                extra.pop("activate_claimed_at", None)
                if next_attempt_seconds > 0:
                    next_at = datetime.now(timezone.utc) + timedelta(seconds=next_attempt_seconds)
                    extra["activate_next_attempt_at"] = next_at.isoformat()
                else:
                    extra.pop("activate_next_attempt_at", None)
                if error:
                    extra["activate_last_error"] = str(error)[:500]
                acc.set_extra(extra)
                acc.updated_at = _utcnow()
                s.add(acc); s.commit()
        except Exception as exc:
            self._log(f"[activate] 清理 claim 失败(account_id={account_id}): {exc}")

    # =================== seat_change daemon (PENDING_SEAT_CHANGE → PENDING_RT)

    def start_seat_change_daemon(self, *,
                                  concurrency: int = 5) -> dict[str, Any]:
        """切席位 daemon: 多并发, worker 用 master cookies 查 user_id + PATCH default."""
        concurrency = max(1, min(20, int(concurrency or 5)))
        with self._seat_change_lock:
            if self._seat_change_state.get("running") or self._seat_change_state.get("stopping"):
                return {"ok": False, "error": "切席位 daemon 已在运行"}
            self._seat_change_stop_event.clear()
            self._seat_change_state.update({
                "running": True, "stopping": False,
                "concurrency": concurrency,
                "inflight": 0, "claimed": 0, "success": 0, "failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "stopped_at": "", "last_scan_at": "", "last_error": "",
            })
            self._seat_change_thread = threading.Thread(
                target=self._seat_change_loop, args=(concurrency,),
                daemon=True, name="biz-seat-change-driver",
            )
            self._seat_change_thread.start()
        self._log(f"▶ 切席位 daemon 启动: 并发 {concurrency}")
        return {"ok": True, "concurrency": concurrency}

    def stop_seat_change_daemon(self) -> dict[str, Any]:
        with self._seat_change_lock:
            if not (self._seat_change_state.get("running") or self._seat_change_state.get("stopping")):
                return {"ok": False, "error": "切席位 daemon 未运行"}
            self._seat_change_stop_event.set()
            self._seat_change_state["stopping"] = True
        self._log("收到切席位 daemon 停止信号")
        return {"ok": True}

    def _seat_change_loop(self, concurrency: int) -> None:
        futures: dict[Future, int] = {}
        try:
            with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="biz-seat-change") as ex:
                while True:
                    for future in list(futures):
                        if not future.done():
                            continue
                        account_id = futures.pop(future)
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = {"id": account_id, "ok": False, "error": str(exc)}
                            self._log(f"[seat-change] worker 异常: {exc}")
                        self._record_seat_change_result(result)

                    with self._seat_change_lock:
                        self._seat_change_state["inflight"] = len(futures)

                    if self._seat_change_stop_event.is_set():
                        if not futures:
                            break
                        self._seat_change_stop_event.wait(0.5); continue

                    capacity = max(0, concurrency - len(futures))
                    claimed_ids = self._claim_pending_seat_change_accounts(capacity)
                    if claimed_ids:
                        with self._seat_change_lock:
                            self._seat_change_state["claimed"] += len(claimed_ids)
                            self._seat_change_state["inflight"] = len(futures) + len(claimed_ids)
                        for account_id in claimed_ids:
                            futures[ex.submit(self._switch_seat_one, account_id)] = account_id
                        continue
                    self._seat_change_stop_event.wait(3.0)
        except Exception as exc:
            self._log(f"[seat-change] daemon 异常退出: {exc}\n{traceback.format_exc()[:400]}")
            with self._seat_change_lock:
                self._seat_change_state["last_error"] = str(exc)[:300]
        finally:
            with self._seat_change_lock:
                self._seat_change_state["running"] = False
                self._seat_change_state["stopping"] = False
                self._seat_change_state["stopped_at"] = datetime.now(timezone.utc).isoformat()
                self._seat_change_state["inflight"] = 0
            self._log("[seat-change] daemon 已退出")

    def _record_seat_change_result(self, result: dict[str, Any]) -> None:
        ok = bool(result.get("ok"))
        with self._seat_change_lock:
            if ok:
                self._seat_change_state["success"] += 1
            else:
                self._seat_change_state["failed"] += 1
                err = str(result.get("error") or "")
                if err:
                    self._seat_change_state["last_error"] = err[:300]

    def _claim_pending_seat_change_accounts(self, limit: int) -> list[int]:
        """只 claim 已过 seat_change_eligible_at 的账号(避免太早 PATCH 撞 500)。"""
        limit = max(0, int(limit or 0))
        if limit <= 0:
            return []
        now = datetime.now(timezone.utc)
        with self._seat_change_lock:
            self._seat_change_state["last_scan_at"] = now.isoformat()
        stale_before = now - timedelta(minutes=30)
        claimed: list[int] = []
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                rows = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.PENDING_SEAT_CHANGE.value)
                    .order_by(AccountModel.updated_at.asc())
                    .limit(max(50, limit * 8))
                ).all()
                for acc in rows:
                    if len(claimed) >= limit:
                        break
                    extra = acc.get_extra()
                    # 还没到 eligible 时间就跳过
                    eligible_at = self._parse_utc_datetime(extra.get("seat_change_eligible_at"))
                    if eligible_at and eligible_at > now:
                        continue
                    next_at = self._parse_utc_datetime(extra.get("seat_change_next_attempt_at"))
                    if next_at and next_at > now:
                        continue
                    claimed_at = self._parse_utc_datetime(extra.get("seat_change_claimed_at"))
                    if extra.get("seat_change_claim_id") and claimed_at and claimed_at > stale_before:
                        continue
                    extra["seat_change_claim_id"] = uuid.uuid4().hex
                    extra["seat_change_claimed_at"] = now.isoformat()
                    extra.pop("seat_change_next_attempt_at", None)
                    acc.set_extra(extra)
                    acc.updated_at = _utcnow()
                    s.add(acc)
                    if acc.id is not None:
                        claimed.append(int(acc.id))
                s.commit()
        except Exception as exc:
            with self._seat_change_lock:
                self._seat_change_state["last_error"] = str(exc)[:300]
            self._log(f"[seat-change] 扫描 PENDING_SEAT_CHANGE 异常: {exc}")
            return []
        if claimed:
            self._log(f"[seat-change] claim {len(claimed)} 个待切席位账号")
        return claimed

    def _switch_seat_one(self, account_id: int) -> dict[str, Any]:
        """worker: 查 user_id + PATCH seat_type=default (重试 N 次)。"""
        from core.config_store import config_store
        from core.db import _utcnow
        from platforms.chatgpt.plugin import (
            _resolve_business_user_id_by_email,
            _resolve_master_workspace_id,
            _switch_business_seat,
        )

        seat_retries = max(1, int(self._int_config(
            "business_seat_switch_retry_count", 3, min_value=1, max_value=10,
        )))
        seat_retry_interval = max(1, int(self._int_config(
            "business_seat_switch_retry_interval_seconds", 5, min_value=1, max_value=60,
        )))
        proxy = str(config_store.get("default_proxy", "") or "").strip()

        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return {"id": account_id, "ok": False, "error": "账号不存在"}
                email = acc.email
                extra = acc.get_extra()
            extra_for_call = dict(extra or {})
            register_proxy = str(extra_for_call.get("register_proxy") or "").strip()
            use_proxy = register_proxy or proxy

            master_account_id = str(extra_for_call.get("business_master_account_id") or "").strip()
            if not master_account_id:
                master_account_id = _resolve_master_workspace_id(self._log, proxy=use_proxy)
            if not master_account_id:
                self._clear_seat_change_claim(account_id, next_attempt_seconds=120,
                                              error="master workspace id 解析失败")
                return {"id": account_id, "ok": False, "error": "no master workspace id"}

            child_user_id = _resolve_business_user_id_by_email(
                master_account_id, email, self._log, proxy=use_proxy,
            )
            if not child_user_id:
                self._clear_seat_change_claim(account_id, next_attempt_seconds=60,
                                              error=f"查 user_id 失败 (email={email})")
                return {"id": account_id, "ok": False, "error": "resolve user_id failed"}

            seat_target = str(config_store.get("business_seat_target", "default") or "default").strip().lower()
            if seat_target not in ("default", "usage_based"):
                seat_target = "default"
            seat_extra = {
                "access_token": extra_for_call.get("access_token", ""),
                "chatgpt_account_id": master_account_id,
                "chatgpt_user_id": child_user_id,
            }
            last_err = ""
            switched = False
            for attempt in range(seat_retries):
                seat_extra.pop("seat_type", None)
                try:
                    _switch_business_seat(
                        seat_extra, self._log, proxy=use_proxy,
                        enabled=True, target=seat_target,
                    )
                except Exception as exc:
                    last_err = str(exc)
                    self._log(f"[seat-change] 切席位异常 (尝试 {attempt+1}/{seat_retries}): {exc}")
                else:
                    if seat_extra.get("seat_type") == seat_target:
                        switched = True; break
                    last_err = "切换后 seat_type 未达预期"
                if attempt < seat_retries - 1:
                    time.sleep(seat_retry_interval)

            if not switched:
                self._clear_seat_change_claim(account_id, next_attempt_seconds=180,
                                              error=f"切席位 {seat_retries} 次均失败: {last_err}")
                return {"id": account_id, "ok": False, "error": f"seat switch failed: {last_err}"}

            # 推进到 PENDING_RT
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return {"id": account_id, "ok": False, "error": "账号已被删"}
                e = acc.get_extra()
                e.pop("seat_change_claim_id", None)
                e.pop("seat_change_claimed_at", None)
                e.pop("seat_change_next_attempt_at", None)
                e.pop("seat_change_last_error", None)
                e["seat_switched_to_chatgpt_at"] = int(time.time())
                e["seat_type"] = seat_target
                e["business_master_account_id"] = master_account_id
                acc.set_extra(e)
                acc.status = AccountStatus.PENDING_RT.value
                acc.updated_at = _utcnow()
                s.add(acc); s.commit()
            self._log(f"[seat-change] ✅ {email} 切 {seat_target} 席位 → PENDING_RT")
            return {"id": account_id, "ok": True, "email": email}
        except Exception as exc:
            self._clear_seat_change_claim(account_id, next_attempt_seconds=120,
                                          error=f"worker 异常: {exc}")
            return {"id": account_id, "ok": False, "error": str(exc)}

    def _clear_seat_change_claim(self, account_id: int, *,
                                  next_attempt_seconds: int = 0, error: str = "") -> None:
        try:
            from core.db import _utcnow
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra.pop("seat_change_claim_id", None)
                extra.pop("seat_change_claimed_at", None)
                if next_attempt_seconds > 0:
                    next_at = datetime.now(timezone.utc) + timedelta(seconds=next_attempt_seconds)
                    extra["seat_change_next_attempt_at"] = next_at.isoformat()
                else:
                    extra.pop("seat_change_next_attempt_at", None)
                if error:
                    extra["seat_change_last_error"] = str(error)[:500]
                acc.set_extra(extra)
                acc.updated_at = _utcnow()
                s.add(acc); s.commit()
        except Exception as exc:
            self._log(f"[seat-change] 清理 claim 失败(account_id={account_id}): {exc}")

    def _auto_upload_fixed_rt_account(self, account_id: int) -> dict[str, Any]:
        try:
            with Session(engine) as s:
                acc_model = s.get(AccountModel, account_id)
                if not acc_model:
                    return {"upload_attempted": False, "uploaded": False}
                email = acc_model.email
                status = acc_model.status
                extra = acc_model.get_extra()
                device_id_raw = (
                    extra.get("assigned_device_id")
                    or extra.get("_sync_device_id")
                    or ""
                )
                if status == AccountStatus.PENDING_SEAT_SWITCH.value:
                    return {"upload_attempted": False, "uploaded": False}
                if not str(extra.get("refresh_token") or "").strip():
                    return {"upload_attempted": False, "uploaded": False}
            try:
                device_id = int(device_id_raw or 0)
            except (TypeError, ValueError):
                device_id = 0
            if device_id <= 0:
                return {"upload_attempted": False, "uploaded": False}

            account = self._account_model_to_account(account_id)
            from services.device_manager import upload_accounts_to_device
            upload_ok = False
            upload_msg = ""
            for _acct, ok, msg in upload_accounts_to_device([account], device_id):
                upload_ok = bool(ok)
                upload_msg = str(msg or "")
                break
            if upload_ok:
                with Session(engine) as s:
                    acc_model = s.get(AccountModel, account_id)
                    if acc_model:
                        s.delete(acc_model)
                        s.commit()
                self._log(f"✓ [自动补 RT {email}] 已上传设备#{device_id}并删除本地账号")
                return {
                    "upload_attempted": True,
                    "uploaded": True,
                    "upload_message": upload_msg,
                }

            from core.db import _utcnow
            with Session(engine) as s:
                acc_model = s.get(AccountModel, account_id)
                if acc_model:
                    extra = acc_model.get_extra()
                    extra["device_upload_error"] = upload_msg[:500]
                    extra["last_device_upload_attempt_at"] = datetime.now(timezone.utc).isoformat()
                    acc_model.status = AccountStatus.READY_FOR_EXPORT.value
                    acc_model.set_extra(extra)
                    acc_model.updated_at = _utcnow()
                    s.add(acc_model)
                    s.commit()
            self._log(f"⚠ [自动补 RT {email}] 上传设备#{device_id}失败,留 ready_for_export: {upload_msg}")
            return {
                "upload_attempted": True,
                "uploaded": False,
                "upload_message": upload_msg,
            }
        except Exception as exc:
            self._log(f"⚠ 自动补 RT 上传设备异常(account_id={account_id}): {exc}")
            return {
                "upload_attempted": True,
                "uploaded": False,
                "upload_message": str(exc),
            }

    def fixup_rt_batch(self, account_ids: list[int],
                       concurrency: int = 3) -> dict[str, Any]:
        """异步触发「一键补 RT」。立即返回；进度从 status 接口的 fixup_progress 字段轮询。"""
        if not account_ids:
            return {"ok": False, "error": "account_ids 为空"}
        if self._is_auto_rt_active():
            return {"ok": False, "error": "自动补 RT 正在运行,请先停止后再手动补 RT"}
        concurrency = max(1, min(20, int(concurrency or 3)))
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {
                    "ok": False,
                    "error": (
                        f"已有 fixup 任务在跑 ({self._fixup_progress.get('action')},"
                        f"{self._fixup_progress.get('done')}/{self._fixup_progress.get('total')}),"
                        "请等待完成"
                    ),
                }
            self._fixup_progress = {
                "action": "fixup-rt",
                "running": True,
                "total": len(account_ids),
                "done": 0,
                "success": 0,
                "failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        threading.Thread(
            target=self._do_fixup_rt_batch,
            args=(list(account_ids), concurrency),
            daemon=True,
            name="biz-fixup-rt-driver",
        ).start()
        return {"ok": True, "queued": len(account_ids), "concurrency": concurrency}

    def _do_fixup_rt_batch(self, account_ids: list[int], concurrency: int) -> None:
        limit_enabled = bool(self._state.config.get("rt_retry_limit_enabled"))
        max_retries = (
            int(self._state.config.get("max_retries") or 5)
            if limit_enabled else None
        )
        self._log(
            f"▶ 一键补 RT 启动 共 {len(account_ids)} 个 并发 {concurrency}"
            f" RT 重试上限={'ON max=' + str(max_retries) if limit_enabled else 'OFF'}"
        )
        try:
            with ThreadPoolExecutor(
                max_workers=concurrency,
                thread_name_prefix="biz-rt-fixup",
            ) as ex:
                futures = [ex.submit(self._fixup_one_rt, aid, max_retries)
                           for aid in account_ids]
                for f in futures:
                    try:
                        result = f.result()
                        ok = bool(result.get("ok"))
                    except Exception as e:
                        ok = False
                        self._log(f"补 RT 任务异常: {e}")
                    with self._fixup_lock:
                        self._fixup_progress["done"] += 1
                        if ok:
                            self._fixup_progress["success"] += 1
                        else:
                            self._fixup_progress["failed"] += 1
            with self._fixup_lock:
                done = self._fixup_progress["done"]
                ok = self._fixup_progress["success"]
            self._log(f"✓ 一键补 RT 完成: 成功 {ok}/{done}")
        finally:
            with self._fixup_lock:
                self._fixup_progress["running"] = False

    class _LoginSessionMissing(BaseException):
        """专用 sentinel:`✗ 登录会话未拿到` 出现时由 log_fn 抛出,绕过 OAuth
        客户端内部所有 `except Exception` 兜底,让 fixup 早退失败。"""

    @staticmethod
    def _is_phone_verification_error(error_msg: str) -> bool:
        """命中手机号验证(add_phone 强制要求)的错误指纹判定。
        这种账号我们没有手机号能力,留在 DB 里只是垃圾,直接删。
        """
        text = str(error_msg or "").lower()
        markers = (
            "需要手机号验证",
            "命中手机验证",
            "手机验证",
            "手机号验证",
            "未配置可用的手机号能力",
            "add_phone",
            "add phone",
            "add-phone",
            "/add-phone",
            "phone_otp",
            "stage=add_phone",
            "phone verification",
            "phone number required",
            "phone required",
        )
        return any(m.lower() in text for m in markers)

    @staticmethod
    def _is_otp_unreachable_error(error_msg: str) -> bool:
        """命中「邮箱拉不到有效 OTP」类的失败指纹。
        典型：导入号子域 MX 不在本机 CF Worker 路由 / OpenAI 已风控不再发新 OTP，
        adapter 只能抓到注册时残留的旧 OTP,提交即被拒;120s 内拉不到第 2 枚 → 超时。
        """
        text = str(error_msg or "")
        lower = text.lower()
        if "stage=otp" not in lower:
            return False
        return (
            "OAuth 阶段 OTP 验证失败" in text
            or "oauth 阶段 otp 验证失败" in lower
            or "已尝试 0 个验证码" in text
            or "已尝试 1 个验证码" in text
        )

    def _delete_account_due_to_phone(self, account_id: int, email: str,
                                     context: str) -> None:
        """删除命中手机号验证的账号。context 用于日志区分来源(补 RT / 注册)。"""
        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if acc:
                    s.delete(acc)
                    s.commit()
        except Exception as exc:
            self._log(f"⚠ [{context} {email}] 删除账号失败: {exc}")
            return
        self._log(f"🗑 [{context} {email}] 命中手机号验证,已删除账号(无法绕过)")

    @staticmethod
    def _is_account_deactivated_error(error_msg: str) -> bool:
        """命中 OpenAI 端账号已 deactivated / deleted 的错误指纹。

        OAuth login 阶段如果 OpenAI 返回 4xx 且 body 含 deactivated 信号,
        error_msg 会带这些字符串。这种账号在 OpenAI 端已永久死亡,补 RT
        永远不会成功;留 DB 里只浪费 retry 计数、代理、邮件配额。
        """
        text = str(error_msg or "").lower()
        markers = (
            "account_deactivated",
            "account_deleted",
            "deleted or deactivated",
            "account has been deleted or deactivated",
            "you do not have an account because it has been deleted or deactivated",
            "账号已被停用",
            "账户已停用",
            "账号已停用",
        )
        return any(m in text for m in markers)

    def _delete_account_due_to_deactivated(self, account_id: int, email: str,
                                            context: str) -> None:
        """删除 OpenAI 端 deactivated 的账号。context 用于日志区分来源。"""
        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if acc:
                    s.delete(acc)
                    s.commit()
        except Exception as exc:
            self._log(f"⚠ [{context} {email}] 删除 deactivated 账号失败: {exc}")
            return
        self._log(
            f"🗑 [{context} {email}] OpenAI 端账号已 deactivated/deleted,"
            "已删除(死号,无法恢复)"
        )

    def _mark_account_rt_dead(self, account_id: int, email: str,
                              reason: str, context: str) -> None:
        """RT 死号(deactivated / 手机号验证)不再硬删, 改为标记 RT_UNREACHABLE 保留,
        停止重试但账号留在库里, 供在列表按 reason 筛选/手动处理(避免误删)。"""
        try:
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return
                extra = acc.get_extra()
                extra["rt_unreachable_reason"] = reason
                extra["rt_acquisition_error"] = f"{reason}: 已停止重试, 账号保留(未删除)"
                extra["last_rt_attempt_at"] = datetime.now(timezone.utc).isoformat()
                # 兼容 BUSINESS CSV 列表状态
                extra["business_csv_status"] = "rt_failed"
                extra["business_csv_rt_error"] = reason
                acc.status = AccountStatus.RT_UNREACHABLE.value
                acc.set_extra(extra)
                from core.db import _utcnow
                acc.updated_at = _utcnow()
                s.add(acc)
                s.commit()
        except Exception as exc:
            self._log(f"⚠ [{context} {email}] 标记 RT 死号失败: {exc}")
            return
        self._log(f"⛔ [{context} {email}] {reason} → 标记 RT_UNREACHABLE 并保留(不删除)")

    def _build_rt_fixup_extra_config(self, extra: dict[str, Any]) -> dict[str, Any]:
        from core.config_store import config_store

        configured_wait = str(
            (extra or {}).get("chatgpt_oauth_otp_wait_seconds")
            or config_store.get("chatgpt_oauth_otp_wait_seconds", "")
            or ""
        ).strip()
        extra_config = {
            "cfworker_api_url": str(config_store.get("cfworker_api_url", "") or ""),
            "cfworker_admin_token": str(config_store.get("cfworker_admin_token", "") or ""),
            "cfworker_custom_auth": str(config_store.get("cfworker_custom_auth", "") or ""),
            **{
                k: v
                for k, v in (extra or {}).items()
                if (
                    (k.startswith("chatgpt_") and k != "chatgpt_totp_secret")
                    or k in (
                        "business_domain",
                        "account_type",
                        "business_switch_to_codex",
                    )
                )
            },
        }
        if configured_wait:
            extra_config["chatgpt_oauth_otp_wait_seconds"] = configured_wait
        # BUSINESS CSV / 老号补 RT 命中 /add-phone 时需要把全局手机号能力注入
        # OAuthClient 与 Drission RT acquirer 都从 extra_config 读取这些 key。
        # 旧逻辑只注入 chatgpt_*，导致已配置 smsbower 但补 RT 仍报
        # "smsbower 未配置 smsbower_api_key"。
        try:
            all_cfg = config_store.get_all() or {}
        except Exception:
            all_cfg = {}
        for key, val in all_cfg.items():
            sk = str(key)
            if (
                sk.startswith("smsbower_")
                or sk.startswith("smstome_")
                or sk.startswith("chatgpt_add_phone_")
                or sk.startswith("chatgpt_phone_")
                or sk in ("openai_phone_number", "phone_number")
            ):
                extra_config.setdefault(sk, val)
        if (
            not extra_config.get("chatgpt_phone_number")
            and extra_config.get("chatgpt_add_phone_number")
        ):
            extra_config["chatgpt_phone_number"] = extra_config["chatgpt_add_phone_number"]
        # 补 RT 命中 add_phone 时是否允许用 smsbower 自动过手机验证(默认关)
        extra_config.setdefault(
            "chatgpt_rt_allow_phone_verification",
            str(config_store.get("chatgpt_rt_allow_phone_verification", "0") or "0"),
        )
        # Outlook 邮箱池注册出的普通号,OAuth login/RT 阶段也必须从同一个
        # Outlook 邮箱读验证码。这里复用 GPT PRO 已有的 OutlookMailbox adapter,
        # 让 BUSINESS CSV 的“平台管理 CHATGPT 注册逻辑”与补 RT 链路闭环。
        provider = str((extra or {}).get("mail_provider") or "").strip().lower()
        if provider == "outlook" and not extra_config.get("_otp_email_adapter"):
            outlook_rt = str((extra or {}).get("refresh_token") or "").strip()
            client_id = str((extra or {}).get("client_id") or "").strip()
            email = str((extra or {}).get("email") or "").strip()
            if outlook_rt and client_id and email:
                try:
                    from platforms.chatgpt.gpt_pro_login import (
                        GptProEmailAdapterForCodexOAuth,
                        build_outlook_mailbox,
                    )

                    snapshot = {
                        "email": email,
                        "password": str((extra or {}).get("password") or ""),
                        "client_id": client_id,
                        "refresh_token": outlook_rt,
                        "mail_access_type": str((extra or {}).get("mail_access_type") or ""),
                    }
                    mailbox, mb_account = build_outlook_mailbox(snapshot, proxy="")
                    extra_config["_otp_email_adapter"] = GptProEmailAdapterForCodexOAuth(
                        mailbox, mb_account, log_fn=self._log,
                    )
                except Exception as exc:
                    extra_config["outlook_otp_adapter_error"] = str(exc)[:300]
        return extra_config

    def _load_rt_fixup_security_credentials(
        self,
        email: str,
        fallback_password: str,
        extra_config: dict[str, Any],
    ) -> str:
        """Load post-registration login material for one RT repair.

        Passwords and TOTP seeds live only in the encrypted security store.  In
        particular, the public ``AccountModel.extra_json`` must never become a
        second plaintext copy.  This orchestration layer consumes only safe MFA
        status and the narrow password accessor.  The concrete browser login
        boundary is solely responsible for reading a TOTP seed.
        """
        # Do not propagate a legacy plaintext value that may already be present
        # in AccountModel.extra_json or supplied by an older caller.
        extra_config.pop("chatgpt_totp_secret", None)
        try:
            from services.chatgpt_security_store import (
                get_chatgpt_security_password,
                get_chatgpt_security_status,
            )

            security_status = get_chatgpt_security_status(email)
            if not bool(security_status.get("credentials_readable", True)):
                raise RuntimeError("encrypted ChatGPT credentials are unreadable")
            has_stored_password = bool(security_status.get("has_password"))
            stored_password = (
                get_chatgpt_security_password(email)
                if has_stored_password
                else ""
            )
        except Exception as exc:
            # Crypto/DB exceptions can include key material or SQL parameters.
            # Keep both the task log and the propagated error credential-free.
            self._log(
                f"❌ [补 RT {email}] 加密登录凭据读取失败 "
                f"({type(exc).__name__})"
            )
            raise RuntimeError(
                "ChatGPT 加密登录凭据读取失败，已停止本次补 RT"
            ) from None

        password = str(stored_password or fallback_password or "")
        mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
        requires_browser = bool(security_status.get("has_totp")) or mfa_state in {
            "pending",
            "enabled",
            "unmanaged",
        }
        if requires_browser:
            configured_mode = str(
                extra_config.get("business_rt_oauth_browser_mode") or ""
            ).strip().lower()
            if configured_mode not in {"headless", "headed"}:
                configured_mode = "headless"
                extra_config["business_rt_oauth_browser_mode"] = configured_mode
            mode_label = (
                "有头浏览器" if configured_mode == "headed" else "无头浏览器"
            )
            self._log(
                f"🔐 [补 RT {email}] 已检测到 Authenticator 安全状态，"
                f"本次自动使用{mode_label}"
            )
        elif has_stored_password:
            self._log(f"🔐 [补 RT {email}] 已从加密仓库加载登录密码")
        return password

    def _fixup_one_rt(self, account_id: int,
                      max_retries: int | None,
                      browser_mode: str | None = None) -> dict[str, Any]:
        """补单个号的 RT。

        max_retries=None 表示不限制重试次数(开关 OFF)。
        max_retries=N 时,rt_retry_count >= N 直接转 RT_UNREACHABLE,不再尝试。
        """
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                return {"id": account_id, "ok": False, "error": "账号不存在"}
            email = acc_model.email
            password = acc_model.password or ""
            extra = acc_model.get_extra()
        if max_retries is not None and int(extra.get("rt_retry_count") or 0) >= max_retries:
            # 已超限,直接转 RT_UNREACHABLE
            self._mark_account_status(account_id, AccountStatus.RT_UNREACHABLE)
            return {"id": account_id, "email": email, "ok": False,
                    "error": f"超过最大重试 {max_retries},已转 rt_unreachable"}
        try:
            from platforms.chatgpt.plugin import ChatGPTPlatform, _read_switch_codex_flag
            extra_for_config = dict(extra or {})
            extra_for_config.setdefault("email", email)
            extra_for_config.setdefault("password", password)
            extra_config = self._build_rt_fixup_extra_config(extra_for_config)
            requested_browser_mode = str(browser_mode or "").strip().lower()
            if requested_browser_mode in _RT_OAUTH_BROWSER_MODES:
                extra_config["business_rt_oauth_browser_mode"] = requested_browser_mode
                self._log(
                    f"[补 RT {email}] 本次 OAuth 浏览器模式: {requested_browser_mode}"
                )
            password = self._load_rt_fixup_security_credentials(
                email,
                password,
                extra_config,
            )
            instance = ChatGPTPlatform(
                config=RegisterConfig(executor_type="protocol", extra=extra_config),
            )
            # 复用 runner 的代理选取链(全局.proxy → 代理管理.DB → 订阅池 → default_proxy)
            proxy, proxy_source = self._pick_proxy_with_source(extra_config)
            if proxy:
                from core.proxy_utils import redact_proxy_url
                self._log(
                    f"🌐 [补 RT {email}] 使用代理: {redact_proxy_url(proxy)} "
                    f"(来源: {proxy_source})"
                )
            else:
                self._log(f"⚠ [补 RT {email}] 未找到代理,将直连")

            rt_extra = instance._acquire_rt_via_oauth_login_with_retry(
                email, password, proxy, extra_config, self._log,
                context=f"[补 RT {email}]",
            )
            # 成功:按账号原配置决定是否继续进入待改席位队列。
            account = self._account_model_to_account(account_id)
            instance._apply_rt_success(account, rt_extra)
            switch_codex = _read_switch_codex_flag(extra_config)
            account.extra = dict(account.extra or {})
            account.extra["business_switch_to_codex"] = "1" if switch_codex else "0"
            if switch_codex:
                next_label = "已就绪可导出（Codex 席位可后续单独处理）"
            else:
                next_label = "已就绪可导出（不要求 Codex 席位）"
            account.status = AccountStatus.READY_FOR_EXPORT
            if not switch_codex:
                account.extra.pop("seat_switch_error", None)
            save_account(account)
            self._log(f"✓ [补 RT {email}] 成功,{next_label}")
            return {"id": account_id, "email": email, "ok": True,
                    "next_status": account.status.value}
        except Exception as e:
            err_msg = str(e)
            # 账号 deactivated / 手机号验证:不再硬删账号,改为标记 RT_UNREACHABLE 保留,
            # 停止重试(不浪费配额),但账号留在库里供筛选/手动处理。
            if self._is_account_deactivated_error(err_msg):
                self._mark_account_rt_dead(account_id, email, "account_deactivated", "补 RT")
                return {"id": account_id, "email": email, "ok": False,
                        "error": "account_deactivated_kept"}
            if self._is_phone_verification_error(err_msg):
                self._mark_account_rt_dead(account_id, email, "phone_verification_required", "补 RT")
                return {"id": account_id, "email": email, "ok": False,
                        "error": "phone_verification_required_kept"}
            # 普通失败:rt_retry_count++;若启用了上限且达到则转 RT_UNREACHABLE
            with Session(engine) as s:
                acc_model = s.get(AccountModel, account_id)
                if not acc_model:
                    return {"id": account_id, "ok": False, "error": "账号不存在"}
                extra = acc_model.get_extra()
                extra["rt_retry_count"] = int(extra.get("rt_retry_count") or 0) + 1
                extra["rt_acquisition_error"] = err_msg[:500]
                extra["last_rt_attempt_at"] = datetime.now(timezone.utc).isoformat()
                if self._is_otp_unreachable_error(err_msg):
                    otp_streak = int(extra.get("rt_otp_fail_streak") or 0) + 1
                    extra["rt_otp_fail_streak"] = otp_streak
                else:
                    extra["rt_otp_fail_streak"] = 0
                    otp_streak = 0
                if otp_streak >= _RT_OTP_FAIL_STREAK_TO_UNREACHABLE:
                    acc_model.status = AccountStatus.RT_UNREACHABLE.value
                    extra["rt_unreachable_reason"] = "otp_unreachable"
                    final_status = "rt_unreachable"
                elif (max_retries is not None
                        and extra["rt_retry_count"] >= max_retries):
                    acc_model.status = AccountStatus.RT_UNREACHABLE.value
                    extra["rt_unreachable_reason"] = "retry_limit"
                    final_status = "rt_unreachable"
                else:
                    acc_model.status = AccountStatus.PENDING_RT.value
                    final_status = "pending_rt"
                acc_model.set_extra(extra)
                from core.db import _utcnow
                acc_model.updated_at = _utcnow()
                s.add(acc_model)
                s.commit()
            err_brief = err_msg.strip().split("\n", 1)[0][:140]
            self._log(
                f"✗ [补 RT {email}] 失败 ({final_status},第 {extra['rt_retry_count']} 次): {err_brief}"
            )
            return {"id": account_id, "email": email, "ok": False, "error": err_msg}

    def fixup_seat_batch(self, account_ids: list[int],
                         concurrency: int = 3) -> dict[str, Any]:
        """异步触发「一键改席位」。立即返回；进度从 status.fixup_progress 轮询。"""
        if not account_ids:
            return {"ok": False, "error": "account_ids 为空"}
        if self._is_auto_rt_active():
            return {"ok": False, "error": "自动补 RT 正在运行,请先停止后再改席位"}
        concurrency = max(1, min(20, int(concurrency or 3)))
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {
                    "ok": False,
                    "error": (
                        f"已有 fixup 任务在跑 ({self._fixup_progress.get('action')},"
                        f"{self._fixup_progress.get('done')}/{self._fixup_progress.get('total')}),"
                        "请等待完成"
                    ),
                }
            self._fixup_progress = {
                "action": "fixup-seat",
                "running": True,
                "total": len(account_ids),
                "done": 0,
                "success": 0,
                "failed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        threading.Thread(
            target=self._do_fixup_seat_batch,
            args=(list(account_ids), concurrency),
            daemon=True,
            name="biz-fixup-seat-driver",
        ).start()
        return {"ok": True, "queued": len(account_ids), "concurrency": concurrency}

    def _do_fixup_seat_batch(self, account_ids: list[int], concurrency: int) -> None:
        self._log(f"▶ 一键改席位 启动 共 {len(account_ids)} 个 并发 {concurrency}")
        try:
            with ThreadPoolExecutor(
                max_workers=concurrency,
                thread_name_prefix="biz-seat-fixup",
            ) as ex:
                futures = [ex.submit(self._fixup_one_seat, aid) for aid in account_ids]
                for f in futures:
                    try:
                        result = f.result()
                        ok = bool(result.get("ok"))
                    except Exception as e:
                        ok = False
                        self._log(f"改席位任务异常: {e}")
                    with self._fixup_lock:
                        self._fixup_progress["done"] += 1
                        if ok:
                            self._fixup_progress["success"] += 1
                        else:
                            self._fixup_progress["failed"] += 1
            with self._fixup_lock:
                done = self._fixup_progress["done"]
                ok = self._fixup_progress["success"]
            self._log(f"✓ 一键改席位 完成: 成功 {ok}/{done}")
        finally:
            with self._fixup_lock:
                self._fixup_progress["running"] = False

    def _fixup_one_seat(self, account_id: int) -> dict[str, Any]:
        from platforms.chatgpt.plugin import _switch_business_seat_to_codex
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                return {"id": account_id, "ok": False, "error": "账号不存在"}
            email = acc_model.email
            extra = acc_model.get_extra()
        # 复用 runner 的代理选取链
        proxy, proxy_source = self._pick_proxy_with_source(extra)
        if proxy:
            from core.proxy_utils import redact_proxy_url
            self._log(
                f"🌐 [改席位 {email}] 使用代理: {redact_proxy_url(proxy)} "
                f"(来源: {proxy_source})"
            )
        else:
            self._log(f"⚠ [改席位 {email}] 未找到代理,将直连")
        try:
            _switch_business_seat_to_codex(extra, self._log, proxy=proxy, enabled=True)
        except Exception as e:
            retry_count = 0
            with Session(engine) as s:
                acc_model = s.get(AccountModel, account_id)
                if acc_model:
                    cur_extra = acc_model.get_extra()
                    cur_extra["seat_switch_error"] = str(e)[:500]
                    cur_extra["seat_retry_count"] = int(cur_extra.get("seat_retry_count") or 0) + 1
                    retry_count = cur_extra["seat_retry_count"]
                    cur_extra["last_seat_attempt_at"] = datetime.now(timezone.utc).isoformat()
                    acc_model.set_extra(cur_extra)
                    from core.db import _utcnow
                    acc_model.updated_at = _utcnow()
                    s.add(acc_model)
                    s.commit()
            err_brief = str(e).strip().split("\n", 1)[0][:140]
            self._log(f"✗ [改席位 {email}] 失败 (第 {retry_count} 次): {err_brief}")
            return {"id": account_id, "email": email, "ok": False, "error": str(e)}
        if extra.get("seat_type") != "usage_based":
            self._log(f"✗ [改席位 {email}] 失败: 切换后 seat_type 仍不是 usage_based")
            return {"id": account_id, "email": email, "ok": False,
                    "error": "切换后 seat_type 仍不是 usage_based"}
        self._log(f"✓ [改席位 {email}] 成功,可导出")
        # 成功:状态推到 READY_FOR_EXPORT
        account = self._account_model_to_account(account_id)
        account.extra = dict(account.extra or {})
        account.extra.update(extra)
        account.extra.pop("seat_switch_error", None)
        account.status = AccountStatus.READY_FOR_EXPORT
        save_account(account)
        return {"id": account_id, "email": email, "ok": True,
                "next_status": account.status.value}

    def reset_rt_unreachable(self, account_ids: list[int]) -> dict[str, Any]:
        """把 RT_UNREACHABLE 账号重置回 PENDING_RT,清空 rt_retry_count。"""
        if not account_ids:
            return {"ok": False, "error": "account_ids 为空"}
        reset_count = 0
        with Session(engine) as s:
            for aid in account_ids:
                acc = s.get(AccountModel, aid)
                if not acc or acc.status != AccountStatus.RT_UNREACHABLE.value:
                    continue
                extra = acc.get_extra()
                extra["rt_retry_count"] = 0
                extra["rt_otp_fail_streak"] = 0
                extra.pop("rt_acquisition_error", None)
                extra.pop("rt_unreachable_reason", None)
                acc.set_extra(extra)
                acc.status = AccountStatus.PENDING_RT.value
                from core.db import _utcnow
                acc.updated_at = _utcnow()
                s.add(acc)
                reset_count += 1
            s.commit()
        return {"ok": True, "reset_count": reset_count}

    # ensure_subdomain_verified 误判产生的 reason 白名单
    # 这些原因来自"导入校验"流程中的网络层抖动 (SSL EOF / timeout) 或 OpenAI/CF 临时拒绝,
    # 不代表子域真不可达,可以安全恢复回 pending_rt 由 runner 自然路径重新尝试。
    _TRANSIENT_MISMARK_REASONS: tuple[str, ...] = (
        "cf_zone_not_found", "openai_list_failed", "openai_add_failed",
        "cf_write_failed", "exception", "openai_response_invalid",
        "transient_giveup",
    )

    def recover_transient_mismarked(self, dry_run: bool = False) -> dict[str, Any]:
        """把"导入校验"误标的 rt_unreachable 账号恢复回 pending_rt。

        - 只命中 _TRANSIENT_MISMARK_REASONS 白名单的 reason
        - 真死号 (otp_unreachable / bulk_otp_streak_backfill / retry_limit) 不动
        - dry_run=True 只返回预览,不写库
        - 写库时清空 rt_retry_count / rt_otp_fail_streak / rt_acquisition_error /
          rt_unreachable_reason 四个字段,让 runner 重新从干净状态开始
        """
        reasons = list(self._TRANSIENT_MISMARK_REASONS)

        breakdown: dict[str, int] = {}
        preserved: dict[str, int] = {}
        recovered = 0
        with Session(engine) as s:
            rows = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.status == AccountStatus.RT_UNREACHABLE.value)
            ).all()
            from core.db import _utcnow
            for acc in rows:
                extra = acc.get_extra()
                reason = str(extra.get("rt_unreachable_reason") or "")
                if reason in reasons:
                    breakdown[reason] = breakdown.get(reason, 0) + 1
                    if not dry_run:
                        extra["rt_retry_count"] = 0
                        extra["rt_otp_fail_streak"] = 0
                        extra.pop("rt_acquisition_error", None)
                        extra.pop("rt_unreachable_reason", None)
                        acc.set_extra(extra)
                        acc.status = AccountStatus.PENDING_RT.value
                        acc.updated_at = _utcnow()
                        s.add(acc)
                        recovered += 1
                else:
                    key = reason or "(no_reason)"
                    preserved[key] = preserved.get(key, 0) + 1
            if not dry_run and recovered:
                s.commit()

        if not dry_run:
            self._log(
                f"♻ 一键恢复误标: {recovered} 个账号从 rt_unreachable 重置回 pending_rt"
            )
        return {
            "ok": True,
            "dry_run": dry_run,
            "recovered": recovered if not dry_run else sum(breakdown.values()),
            "breakdown": breakdown,
            "preserved": preserved,
            "whitelist_reasons": reasons,
        }

    def delete_rt_unreachable(self, account_ids: list[int]) -> dict[str, Any]:
        """硬删除 RT_UNREACHABLE 账号。只删除当前仍处于 RT 不可达状态的账号。"""
        if not account_ids:
            return {"ok": False, "error": "account_ids 为空"}
        deleted_count = 0
        deleted_ids: list[int] = []
        deleted_emails: list[str] = []
        with Session(engine) as s:
            for aid in account_ids:
                acc = s.get(AccountModel, aid)
                if not acc or acc.status != AccountStatus.RT_UNREACHABLE.value:
                    continue
                deleted_count += 1
                if acc.id is not None:
                    deleted_ids.append(int(acc.id))
                deleted_emails.append(acc.email)
                s.delete(acc)
            if deleted_count:
                log_entry = TaskLog(
                    platform=_PLATFORM,
                    email=f"delete-rt-unreachable:{deleted_count}",
                    status="deleted",
                    detail_json=json.dumps({
                        "action": "delete_rt_unreachable",
                        "count": deleted_count,
                        "account_ids": deleted_ids,
                        "emails": deleted_emails,
                    }, ensure_ascii=False),
                )
                s.add(log_entry)
            s.commit()
        self._log(f"🗑 RT 不可达硬删除 {deleted_count} 个账号")
        return {"ok": True, "deleted_count": deleted_count}

    def export_pending_rt_migration(self, *, account_ids: list[int] | None = None,
                                    count: int = 100,
                                    remove_from_source: bool = False) -> dict[str, Any]:
        """导出「待 RT」迁移包,供其它机器导入后继续补 RT。

        remove_from_source=True 时会从本机删除这些 pending_rt 账号,避免多机重复
        同时补同一个账号。只导出 status=pending_rt 的账号。
        """
        count = max(1, min(10000, int(count or 100)))
        ids = [int(x) for x in (account_ids or []) if x is not None]
        if remove_from_source and self._is_auto_rt_active():
            return {"ok": False, "error": "自动补 RT 正在运行,请先停止后再导出并移出源队列"}

        with Session(engine) as s:
            stmt = (
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.status == AccountStatus.PENDING_RT.value)
            )
            if ids:
                stmt = stmt.where(AccountModel.id.in_(ids))
            else:
                stmt = stmt.order_by(AccountModel.updated_at.asc()).limit(count)
            accounts = list(s.exec(stmt).all())
            if not accounts:
                return {"ok": False, "error": "没有可导出的待 RT 账号"}

            try:
                from services.chatgpt_security_store import (
                    get_chatgpt_totp_protected_emails,
                )

                protected_emails = get_chatgpt_totp_protected_emails(
                    account.email for account in accounts
                )
            except Exception as exc:
                # Keep crypto/DB exception details out of API responses and do
                # not create a partial package when safety cannot be proven.
                self._log(
                    "待 RT 迁移导出安全状态核验失败，已拒绝导出 "
                    f"({type(exc).__name__})"
                )
                return {
                    "ok": False,
                    "count": 0,
                    "removed_count": 0,
                    "error": _TOTP_STATUS_UNAVAILABLE_ERROR,
                }
            if protected_emails:
                self._log(
                    "待 RT 迁移导出已拒绝："
                    f"{len(protected_emails)} 个账号存在 TOTP 安全凭据"
                )
                return {
                    "ok": False,
                    "count": 0,
                    "removed_count": 0,
                    "blocked_count": len(protected_emails),
                    "error": _TOTP_MIGRATION_BLOCKED_ERROR,
                }

            export_id = uuid.uuid4().hex[:16]
            try:
                from core.machine_id import current_machine_id
                source_machine_id = current_machine_id()
            except Exception:
                source_machine_id = ""
            payload = {
                "schema": _PENDING_RT_MIGRATION_SCHEMA,
                "version": 1,
                "source_machine_id": source_machine_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "remove_from_source": bool(remove_from_source),
                "count": len(accounts),
                "accounts": [
                    self._pending_rt_migration_payload(acc)
                    for acc in accounts
                ],
            }
            file_path = self._write_pending_rt_migration_file(export_id, payload)

            removed_count = 0
            account_ids_out = [int(a.id) for a in accounts if a.id is not None]
            emails = [a.email for a in accounts]
            if remove_from_source:
                for acc in accounts:
                    s.delete(acc)
                    removed_count += 1

            s.add(TaskLog(
                platform=_PLATFORM,
                email=f"pending-rt-migration-export:{len(accounts)}",
                status="exported",
                detail_json=json.dumps({
                    "action": "export_pending_rt_migration",
                    "export_id": export_id,
                    "count": len(accounts),
                    "removed_count": removed_count,
                    "account_ids": account_ids_out,
                    "emails": emails,
                    "file_path": file_path,
                }, ensure_ascii=False),
            ))
            s.commit()

        self._log(
            f"📦 导出待 RT 迁移包 {len(accounts)} 个"
            f"{'，源机已移出' if remove_from_source else ''}"
            f" → {os.path.basename(file_path)}"
        )
        return {
            "ok": True,
            "export_id": export_id,
            "count": len(accounts),
            "removed_count": removed_count,
            "file_path": file_path,
            "download_url": f"/api/business-rt-loop/exports/{export_id}/download",
        }

    def import_pending_rt_migration(self, payload: Any, *,
                                    overwrite_existing: bool = True,
                                    reset_retry: bool = True,
                                    auto_verify_subdomains: bool = True) -> dict[str, Any]:
        """导入待 RT 迁移包。导入后账号进入 pending_rt 队列。

        auto_verify_subdomains: 导入后异步校验所有 hostname 的 OpenAI workspace +
            CF DNS,缺失的自动补齐(add_domain + DNS + verify);失败 hostname 对应
            账号自动标 rt_unreachable + reason。进度在 status() 的
            import_subdomain_progress 字段。
        """
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception as exc:
                return {"ok": False, "error": f"迁移包 JSON 解析失败: {exc}"}
        if isinstance(payload, list):
            accounts_raw = payload
            schema = _PENDING_RT_MIGRATION_SCHEMA
        elif isinstance(payload, dict):
            schema = str(payload.get("schema") or "")
            accounts_raw = payload.get("accounts") or []
        else:
            return {"ok": False, "error": "迁移包格式错误"}
        if schema and schema != _PENDING_RT_MIGRATION_SCHEMA:
            return {"ok": False, "error": f"不支持的迁移包 schema: {schema}"}
        if not isinstance(accounts_raw, list) or not accounts_raw:
            return {"ok": False, "error": "迁移包里没有账号"}

        imported = 0
        updated = 0
        skipped = 0
        errors: list[str] = []
        emails: list[str] = []
        from core.db import _utcnow
        with Session(engine) as s:
            for idx, raw in enumerate(accounts_raw, start=1):
                try:
                    normalized = self._normalize_pending_rt_migration_account(
                        raw,
                        reset_retry=reset_retry,
                    )
                    email = normalized["email"]
                except Exception as exc:
                    skipped += 1
                    errors.append(f"第 {idx} 条格式错误: {exc}")
                    continue

                existing = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.email == email)
                ).first()
                if existing and existing.status == AccountStatus.READY_FOR_EXPORT.value:
                    skipped += 1
                    errors.append(f"{email}: 已是可导出,跳过")
                    continue
                if existing and not overwrite_existing:
                    skipped += 1
                    errors.append(f"{email}: 已存在,跳过")
                    continue

                if existing:
                    existing.password = normalized["password"]
                    existing.user_id = normalized["user_id"]
                    existing.region = normalized["region"]
                    existing.token = normalized["token"]
                    existing.cashier_url = normalized["cashier_url"]
                    existing.status = AccountStatus.PENDING_RT.value
                    existing.extra_json = json.dumps(normalized["extra"], ensure_ascii=False)
                    existing.updated_at = _utcnow()
                    s.add(existing)
                    updated += 1
                else:
                    s.add(AccountModel(
                        platform=_PLATFORM,
                        email=email,
                        password=normalized["password"],
                        user_id=normalized["user_id"],
                        region=normalized["region"],
                        token=normalized["token"],
                        status=AccountStatus.PENDING_RT.value,
                        cashier_url=normalized["cashier_url"],
                        extra_json=json.dumps(normalized["extra"], ensure_ascii=False),
                    ))
                    imported += 1
                emails.append(email)

            if imported or updated:
                s.add(TaskLog(
                    platform=_PLATFORM,
                    email=f"pending-rt-migration-import:{imported + updated}",
                    status="imported",
                    detail_json=json.dumps({
                        "action": "import_pending_rt_migration",
                        "imported": imported,
                        "updated": updated,
                        "skipped": skipped,
                        "emails": emails[:200],
                        "errors": errors[:50],
                    }, ensure_ascii=False),
                ))
            s.commit()

        self._log(
            f"📥 导入待 RT 迁移包: 新增 {imported},覆盖 {updated},跳过 {skipped}"
        )

        verify_started = False
        if auto_verify_subdomains and emails:
            hostnames = sorted({
                e.split("@", 1)[1].strip().lower()
                for e in emails if "@" in e
            })
            if hostnames:
                with self._import_progress_lock:
                    if self._import_progress.get("running"):
                        self._log(
                            "⚠ 上一次导入校验仍在进行,本次跳过自动校验"
                            "(可通过 status.import_subdomain_progress 查看进度)"
                        )
                    else:
                        self._import_progress = {
                            "running": True,
                            "total": len(hostnames),
                            "done": 0,
                            "ok": 0,
                            "failed": 0,
                            "current_hostname": "",
                            "started_at": datetime.now(timezone.utc).isoformat(),
                            "finished_at": "",
                            "results": [],
                        }
                        verify_started = True
                if verify_started:
                    threading.Thread(
                        target=self._ensure_subdomains_for_import_async,
                        args=(hostnames, list(emails)),
                        daemon=True,
                        name="biz-rt-import-domain-verify",
                    ).start()
                    self._log(
                        f"🔎 导入校验启动: 待校验 {len(hostnames)} 个 hostname "
                        "(异步,可在 status.import_subdomain_progress 查看进度)"
                    )

        return {
            "ok": True,
            "imported_count": imported,
            "updated_count": updated,
            "skipped_count": skipped,
            "errors": errors[:50],
            "auto_verify_started": verify_started,
        }

    def _ensure_subdomains_for_import_async(self, hostnames: list[str],
                                            emails: list[str]) -> None:
        """后台跑:对每个 hostname 调 ensure_subdomain_verified。

        重要设计:**任何失败都不再 mark 账号 unreachable**。
        - 校验只是"尽力补齐"的辅助步骤,不能因为网络抖动/CF/OpenAI 临时错误
          就把整子域几百个号永久标死。
        - 失败结果只记录在 import_subdomain_progress.results,前端可见。
        - 账号留在 pending_rt,由 runner 自然路径补 RT;真正不可达的会被
          runner 的 OTP streak 机制接手(连续 2 次 stage=otp 失败转 unreachable)。
        - 设计参考:此前一次大规模导入因 SSL EOF 抖动误标 9059 个号 unreachable
          (reason: cf_zone_not_found/openai_list_failed/exception),实际 CF/OpenAI
          状态都是正常的,只是请求层抖动。
        """
        # emails 参数保留向后兼容,本实现已经不依赖它
        _ = emails
        from services.business_domain_service import ensure_subdomain_verified

        try:
            for h in hostnames:
                with self._import_progress_lock:
                    self._import_progress["current_hostname"] = h
                try:
                    res = ensure_subdomain_verified(h, note="imported_via_migration")
                except Exception as exc:
                    res = {"ok": False, "hostname": h, "action": "failed",
                           "reason": "exception", "error": str(exc)[:200]}

                entry = {
                    "hostname": h,
                    "ok": bool(res.get("ok")),
                    "action": str(res.get("action") or ""),
                    "reason": str(res.get("reason") or ""),
                }
                with self._import_progress_lock:
                    self._import_progress["results"].append(entry)
                    self._import_progress["done"] += 1
                    if entry["ok"]:
                        self._import_progress["ok"] += 1
                    else:
                        self._import_progress["failed"] += 1

                if entry["ok"]:
                    self._log(f"✓ [导入校验 {h}] action={entry['action']}")
                else:
                    self._log(
                        f"✗ [导入校验 {h}] reason={entry['reason']} "
                        f"err={str(res.get('error') or '')[:140]} "
                        "(账号保持 pending_rt,runner 自然路径会继续尝试)"
                    )
        finally:
            with self._import_progress_lock:
                self._import_progress["running"] = False
                self._import_progress["current_hostname"] = ""
                self._import_progress["finished_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )
                ok = self._import_progress["ok"]
                total = self._import_progress["total"]
                failed = self._import_progress["failed"]
            self._log(
                f"📋 导入校验完成: {ok}/{total} 成功,{failed} 失败 "
                "(失败的子域不再触发账号 unreachable,"
                "详情见 status.import_subdomain_progress.results)"
            )

    @staticmethod
    def _normalize_clearable_status(status: str) -> str:
        value = str(status or "").strip().lower()
        return value if value in _CLEARABLE_STATUS_LABELS else ""

    def clear_accounts_by_status(self, status: str) -> dict[str, Any]:
        """硬删除指定 BUSINESS RT 队列状态的全部账号。"""
        normalized = self._normalize_clearable_status(status)
        if not normalized:
            return {
                "ok": False,
                "error": ("只允许清理 pending_invite / pending_activate / pending_seat_change / "
                          "pending_rt / pending_seat_switch / rt_unreachable"),
            }
        if self._is_auto_rt_active():
            return {"ok": False, "error": "自动补 RT 正在运行,请先停止后再清理"}
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {
                    "ok": False,
                    "error": (
                        f"后台任务正在运行 ({self._fixup_progress.get('action')},"
                        f"{self._fixup_progress.get('done')}/{self._fixup_progress.get('total')}),"
                        "请等待完成后再清理"
                    ),
                }
            deleted_count = 0
            deleted_ids: list[int] = []
            deleted_emails: list[str] = []
            with Session(engine) as s:
                accounts = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == normalized)
                ).all()
                for acc in accounts:
                    deleted_count += 1
                    if acc.id is not None:
                        deleted_ids.append(int(acc.id))
                    deleted_emails.append(acc.email)
                    s.delete(acc)
                if deleted_count:
                    log_entry = TaskLog(
                        platform=_PLATFORM,
                        email=f"clear-{normalized}:{deleted_count}",
                        status="deleted",
                        detail_json=json.dumps({
                            "action": "clear_business_rt_status",
                            "status": normalized,
                            "status_label": _CLEARABLE_STATUS_LABELS[normalized],
                            "count": deleted_count,
                            "account_ids": deleted_ids,
                            "emails": deleted_emails,
                        }, ensure_ascii=False),
                    )
                    s.add(log_entry)
                s.commit()
        label = _CLEARABLE_STATUS_LABELS[normalized]
        self._log(f"🗑 一键清理「{label}」{deleted_count} 个账号")
        return {
            "ok": True,
            "status": normalized,
            "status_label": label,
            "deleted_count": deleted_count,
        }

    # ------------------------------------------------------------------ RT health check

    def rt_health_check(self, *, concurrency: int = 5,
                        unknown_only: bool = False) -> dict[str, Any]:
        """异步检测所有 READY_FOR_EXPORT 账号的 RT 是否还能刷新 AT。"""
        if self._is_auto_rt_active():
            return {"ok": False, "error": "自动补 RT 正在运行,请先停止后再检测"}
        concurrency = max(1, min(20, int(concurrency or 5)))
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {
                    "ok": False,
                    "error": (
                        f"已有任务在跑 ({self._fixup_progress.get('action')},"
                        f"{self._fixup_progress.get('done')}/{self._fixup_progress.get('total')}),"
                        "请等待完成"
                    ),
                }
            account_ids = self._list_ready_for_export_account_ids(
                unknown_only=unknown_only,
            )
            if not account_ids:
                error = (
                    "没有可重试的不确定账号" if unknown_only
                    else "没有可检测的可导出账号"
                )
                return {"ok": False, "error": error}
            self._fixup_progress = {
                "action": "rt-health-check-unknown" if unknown_only else "rt-health-check",
                "running": True,
                "total": len(account_ids),
                "done": 0,
                "success": 0,
                "failed": 0,
                "healthy": 0,
                "faulty": 0,
                "unknown": 0,
                "refreshed": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": "",
            }
        threading.Thread(
            target=self._do_rt_health_check_batch,
            args=(account_ids, concurrency, unknown_only),
            daemon=True,
            name="biz-rt-health-driver",
        ).start()
        return {
            "ok": True,
            "queued": len(account_ids),
            "concurrency": concurrency,
            "unknown_only": bool(unknown_only),
        }

    @staticmethod
    def _list_ready_for_export_account_ids(*, unknown_only: bool = False) -> list[int]:
        with Session(engine) as s:
            rows = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.status == AccountStatus.READY_FOR_EXPORT.value)
                .order_by(AccountModel.updated_at.desc())
            ).all()
        ids: list[int] = []
        for acc in rows:
            if acc.id is None:
                continue
            if unknown_only:
                extra = acc.get_extra()
                if str(extra.get("rt_health_status") or "").strip().lower() != "unknown":
                    continue
            ids.append(int(acc.id))
        return ids

    @staticmethod
    def _count_ready_for_export_rt_health() -> dict[str, int]:
        counts = {"ok": 0, "unknown": 0, "unchecked": 0}
        with Session(engine) as s:
            rows = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.status == AccountStatus.READY_FOR_EXPORT.value)
            ).all()
        for acc in rows:
            status = str(acc.get_extra().get("rt_health_status") or "").strip().lower()
            if status == "ok":
                counts["ok"] += 1
            elif status == "unknown":
                counts["unknown"] += 1
            else:
                counts["unchecked"] += 1
        counts["total"] = sum(counts.values())
        return counts

    def _do_rt_health_check_batch(self, account_ids: list[int], concurrency: int,
                                  unknown_only: bool = False) -> None:
        scope_label = "不确定账号" if unknown_only else "全部可导出账号"
        self._log(
            f"▶ [RT健康检测] 开始: 范围={scope_label},数量={len(account_ids)},并发={concurrency}"
        )
        try:
            with ThreadPoolExecutor(
                max_workers=concurrency,
                thread_name_prefix="biz-rt-health",
            ) as ex:
                futures = [ex.submit(self._rt_health_check_one, aid) for aid in account_ids]
                for f in as_completed(futures):
                    try:
                        result = f.result()
                    except Exception as exc:
                        result = {
                            "health": "unknown",
                            "ok": False,
                            "error": str(exc),
                            "refreshed": False,
                        }
                        self._log(f"RT健康检测任务异常: {exc}")
                    health = str(result.get("health") or "unknown")
                    with self._fixup_lock:
                        self._fixup_progress["done"] += 1
                        if health == "healthy":
                            self._fixup_progress["success"] += 1
                            self._fixup_progress["healthy"] += 1
                            if result.get("refreshed"):
                                self._fixup_progress["refreshed"] += 1
                        elif health == "faulty":
                            self._fixup_progress["failed"] += 1
                            self._fixup_progress["faulty"] += 1
                        else:
                            self._fixup_progress["failed"] += 1
                            self._fixup_progress["unknown"] += 1
            with self._fixup_lock:
                done = self._fixup_progress["done"]
                healthy = self._fixup_progress["healthy"]
                faulty = self._fixup_progress["faulty"]
                unknown = self._fixup_progress["unknown"]
                refreshed = self._fixup_progress["refreshed"]
            self._log(
                f"✓ [RT健康检测] 完成: 正常 {healthy},故障 {faulty},"
                f"不确定 {unknown},RT轮换 {refreshed},总计 {done}"
            )
        finally:
            with self._fixup_lock:
                self._fixup_progress["running"] = False
                self._fixup_progress["finished_at"] = datetime.now(timezone.utc).isoformat()

    def _rt_health_check_one(self, account_id: int) -> dict[str, Any]:
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                return {
                    "id": account_id,
                    "ok": False,
                    "health": "unknown",
                    "error": "账号不存在",
                }
            if acc_model.status != AccountStatus.READY_FOR_EXPORT.value:
                return {
                    "id": account_id,
                    "email": acc_model.email,
                    "ok": False,
                    "health": "unknown",
                    "error": f"账号状态不是 ready_for_export: {acc_model.status}",
                }
            email = acc_model.email
            extra = acc_model.get_extra()
            refresh_token = str(extra.get("refresh_token") or "").strip()
            client_id = str(extra.get("client_id") or "").strip() or None

        if not refresh_token:
            err = "账号缺少 refresh_token"
            self._persist_rt_health_failure(account_id, err, health="faulty")
            self._log(f"✗ [RT健康 {email}] 判定故障: {err},已移入 rt_unreachable")
            return {
                "id": account_id,
                "email": email,
                "ok": False,
                "health": "faulty",
                "error": err,
            }

        proxy, proxy_source = self._pick_proxy_with_source(extra)
        if proxy:
            from core.proxy_utils import redact_proxy_url
            self._log(
                f"🌐 [RT健康 {email}] 使用代理: {redact_proxy_url(proxy)} "
                f"(来源: {proxy_source})"
            )
        else:
            self._log(f"⚠ [RT健康 {email}] 未找到代理,将直连")
        try:
            from platforms.chatgpt.token_refresh import TokenRefreshManager
            manager = TokenRefreshManager(proxy_url=proxy)
            result = manager.refresh_by_oauth_token(
                refresh_token=refresh_token,
                client_id=client_id,
            )
        except Exception as exc:
            err = str(exc)
            health = self._classify_rt_refresh_failure(err)
            self._persist_rt_health_failure(account_id, err, health=health)
            if health == "faulty":
                self._log(f"✗ [RT健康 {email}] 判定故障: {err[:160]},已移入 rt_unreachable")
            else:
                self._log(f"⚠ [RT健康 {email}] 暂不判死: {err[:160]},保留 ready_for_export")
            return {
                "id": account_id,
                "email": email,
                "ok": False,
                "health": health,
                "error": err,
            }

        if result.success and result.access_token:
            rotated = bool(result.refresh_token and result.refresh_token != refresh_token)
            self._persist_rt_health_success(account_id, result)
            if rotated:
                self._log(
                    f"✓ [RT健康 {email}] 刷新成功,AT已更新,RT已轮换"
                )
            else:
                self._log(f"✓ [RT健康 {email}] 刷新成功,AT已更新")
            return {
                "id": account_id,
                "email": email,
                "ok": True,
                "health": "healthy",
                "refreshed": rotated,
                "proxy_source": proxy_source,
            }

        err = str(result.error_message or "OAuth token 刷新失败")
        health = self._classify_rt_refresh_failure(err)
        self._persist_rt_health_failure(account_id, err, health=health)
        if health == "faulty":
            self._log(f"✗ [RT健康 {email}] 判定故障: {err[:160]},已移入 rt_unreachable")
        else:
            self._log(f"⚠ [RT健康 {email}] 暂不判死: {err[:160]},保留 ready_for_export")
        return {
            "id": account_id,
            "email": email,
            "ok": False,
            "health": health,
            "error": err,
            "proxy_source": proxy_source,
        }

    @staticmethod
    def _classify_rt_refresh_failure(error_msg: str) -> str:
        """Return faulty for account-specific RT death; unknown for network/rate-limit."""
        text = str(error_msg or "").strip().lower()
        if not text:
            return "unknown"
        faulty_markers = (
            "账号缺少 refresh_token",
            "missing refresh_token",
            "http 401",
            "invalid_grant",
            "refresh token is invalid",
            "refresh token expired",
            "refresh token revoked",
            "token has been revoked",
            "invalid refresh token",
        )
        if any(marker in text for marker in faulty_markers):
            return "faulty"
        if "http 400" in text and (
            "invalid_request" in text
            and ("refresh" in text or "token" in text)
        ):
            return "faulty"
        return "unknown"

    @staticmethod
    def _persist_rt_health_success(account_id: int, result: Any) -> None:
        from core.db import _utcnow
        now = datetime.now(timezone.utc)
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                return
            extra = acc_model.get_extra()
            extra["access_token"] = result.access_token
            if result.refresh_token:
                extra["refresh_token"] = result.refresh_token
            extra["rt_health_status"] = "ok"
            extra["rt_health_checked_at"] = now.isoformat()
            extra["last_refresh"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            if getattr(result, "expires_at", None):
                try:
                    expires_at = result.expires_at
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    extra["expired"] = expires_at.astimezone(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                except Exception:
                    pass
            extra.pop("rt_health_error", None)
            extra.pop("rt_acquisition_error", None)
            acc_model.token = result.access_token
            acc_model.status = AccountStatus.READY_FOR_EXPORT.value
            acc_model.set_extra(extra)
            acc_model.updated_at = _utcnow()
            s.add(acc_model)
            s.commit()

    @staticmethod
    def _persist_rt_health_failure(account_id: int, error_msg: str, *,
                                   health: str) -> None:
        from core.db import _utcnow
        now = datetime.now(timezone.utc)
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                return
            extra = acc_model.get_extra()
            brief = str(error_msg or "").strip()[:500]
            extra["rt_health_checked_at"] = now.isoformat()
            extra["rt_health_error"] = brief
            if health == "faulty":
                extra["rt_health_status"] = "dead"
                extra["rt_acquisition_error"] = f"RT健康检测判定故障: {brief}"
                acc_model.status = AccountStatus.RT_UNREACHABLE.value
            else:
                extra["rt_health_status"] = "unknown"
                # 保留可导出,但记录最近一次检测失败原因。
                acc_model.status = AccountStatus.READY_FOR_EXPORT.value
            acc_model.set_extra(extra)
            acc_model.updated_at = _utcnow()
            s.add(acc_model)
            s.commit()

    # ------------------------------------------------------------------ export

    def export(self, *, count: int, format: str,
               check_rt_health: bool = True,
               rt_health_concurrency: int = 5) -> dict[str, Any]:
        """导出 READY_FOR_EXPORT 的前 N 个账号,生成文件成功后硬删账号。"""
        with self._fixup_lock:
            if self._fixup_progress.get("running"):
                return {
                    "ok": False,
                    "error": (
                        f"后台任务正在运行 ({self._fixup_progress.get('action')},"
                        f"{self._fixup_progress.get('done')}/{self._fixup_progress.get('total')}),"
                        "请等待完成后再导出"
                    ),
                }
            return self._export_ready_for_export_locked(
                count=count,
                format=format,
                check_rt_health=check_rt_health,
                rt_health_concurrency=rt_health_concurrency,
            )

    def _export_ready_for_export_locked(self, *, count: int, format: str,
                                        check_rt_health: bool = True,
                                        rt_health_concurrency: int = 5) -> dict[str, Any]:
        fmt = (format or "cpa").strip().lower()
        if fmt not in ("cpa", "sub2api", "kanwang"):
            return {"ok": False, "error": "format 必须是 cpa、sub2api 或 kanwang"}
        count = max(1, int(count or 1))
        rt_health_concurrency = max(1, min(20, int(rt_health_concurrency or 5)))
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        health_summary = {
            "enabled": bool(check_rt_health),
            "checked": 0,
            "healthy": 0,
            "faulty": 0,
            "unknown": 0,
            "selected": 0,
        }
        if check_rt_health:
            selected_ids, health_summary = self._select_exportable_after_rt_health_check(
                count=count,
                concurrency=rt_health_concurrency,
            )
            if not selected_ids:
                return {
                    "ok": False,
                    "error": (
                        "导出前 RT 检测后没有可导出的非故障账号"
                        f"（检测 {health_summary['checked']} 个,"
                        f"故障 {health_summary['faulty']} 个,"
                        f"不确定 {health_summary['unknown']} 个）"
                    ),
                    "rt_health": health_summary,
                }
        else:
            selected_ids = []
        with Session(engine) as s:
            if selected_ids:
                by_id = {
                    acc.id: acc
                    for acc in s.exec(
                        select(AccountModel)
                        .where(AccountModel.platform == _PLATFORM)
                        .where(AccountModel.status == AccountStatus.READY_FOR_EXPORT.value)
                        .where(AccountModel.id.in_(selected_ids))
                    ).all()
                }
                accounts = [by_id[aid] for aid in selected_ids if aid in by_id]
            else:
                accounts = s.exec(
                    select(AccountModel)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.READY_FOR_EXPORT.value)
                    .order_by(AccountModel.updated_at.desc())
                    .limit(count)
                ).all()
            if not accounts:
                return {"ok": False, "error": "没有可导出的账号"}
            account_ids = [a.id for a in accounts]
            emails = [a.email for a in accounts]
            payloads = self._build_export_payloads(accounts, fmt)
            export_id = uuid.uuid4().hex[:16]
            file_path = self._write_export_file(export_id, fmt, payloads)
            # 硬删账号
            for a in accounts:
                s.delete(a)
            # 操作审计日志
            log_entry = TaskLog(
                platform=_PLATFORM,
                email=f"export:{len(account_ids)}",
                status="exported",
                detail_json=json.dumps({
                    "export_id": export_id,
                    "format": fmt,
                    "count": len(account_ids),
                    "account_ids": account_ids,
                    "emails": emails,
                    "file_path": file_path,
                    "rt_health": health_summary,
                }, ensure_ascii=False),
            )
            s.add(log_entry)
            s.commit()
        if check_rt_health:
            self._log(
                f"导出前 RT 检测: 检测 {health_summary['checked']} 个,"
                f"正常 {health_summary['healthy']},故障 {health_summary['faulty']},"
                f"不确定 {health_summary['unknown']},选中 {len(account_ids)}"
            )
        self._log(f"导出 {fmt} {len(account_ids)} 个账号 → {os.path.basename(file_path)}")
        return {
            "ok": True,
            "export_id": export_id,
            "format": fmt,
            "count": len(account_ids),
            "deleted_count": len(account_ids),
            "file_path": file_path,
            "download_url": f"/api/business-rt-loop/exports/{export_id}/download",
            "rt_health": health_summary,
        }

    def _select_exportable_after_rt_health_check(self, *, count: int,
                                                 concurrency: int) -> tuple[list[int], dict[str, Any]]:
        """检测 ready_for_export 候选账号,跳过明确故障账号,返回满足导出的账号 id。"""
        with Session(engine) as s:
            candidate_ids = [
                int(aid)
                for aid in s.exec(
                    select(AccountModel.id)
                    .where(AccountModel.platform == _PLATFORM)
                    .where(AccountModel.status == AccountStatus.READY_FOR_EXPORT.value)
                    .order_by(AccountModel.updated_at.desc())
                ).all()
                if aid is not None
            ]
        summary: dict[str, Any] = {
            "enabled": True,
            "checked": 0,
            "healthy": 0,
            "faulty": 0,
            "unknown": 0,
            "selected": 0,
        }
        if not candidate_ids:
            return [], summary

        selected_ids: list[int] = []
        self._log(
            f"▶ [导出前RT检测] 目标 {count} 个,候选 {len(candidate_ids)} 个,"
            f"并发 {concurrency}"
        )
        idx = 0
        pending: dict[Future, int] = {}
        ex = ThreadPoolExecutor(
            max_workers=concurrency,
            thread_name_prefix="biz-rt-export-health",
        )

        def submit_more() -> None:
            nonlocal idx
            while len(pending) < concurrency and idx < len(candidate_ids):
                aid = candidate_ids[idx]
                idx += 1
                pending[ex.submit(self._rt_health_check_one, aid)] = aid

        try:
            submit_more()
            while pending and len(selected_ids) < count:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    pending.pop(f, None)
                    try:
                        result = f.result()
                    except Exception as exc:
                        result = {
                            "id": None,
                            "health": "unknown",
                            "error": str(exc),
                        }
                        self._log(f"导出前RT检测任务异常: {exc}")
                    account_id = result.get("id")
                    health = str(result.get("health") or "unknown")
                    summary["checked"] += 1
                    if health == "faulty":
                        summary["faulty"] += 1
                        continue
                    if health == "healthy":
                        summary["healthy"] += 1
                    else:
                        summary["unknown"] += 1
                    if account_id is None:
                        continue
                    try:
                        aid = int(account_id)
                    except Exception:
                        continue
                    with Session(engine) as s:
                        acc = s.get(AccountModel, aid)
                        if not acc or acc.status != AccountStatus.READY_FOR_EXPORT.value:
                            continue
                    if aid not in selected_ids:
                        selected_ids.append(aid)
                    if len(selected_ids) >= count:
                        break
                if len(selected_ids) < count:
                    submit_more()
                if summary["checked"] % max(concurrency, 1) == 0 or len(selected_ids) >= count:
                    self._log(
                        f"⏳ [导出前RT检测] 已检测 {summary['checked']} 个,"
                        f"可导出 {len(selected_ids)}/{count},故障 {summary['faulty']},"
                        f"不确定 {summary['unknown']}"
                    )
        finally:
            for f in pending:
                f.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
        summary["selected"] = len(selected_ids)
        return selected_ids, summary

    def _build_export_payloads(self, accounts: list[AccountModel], fmt: str) -> list[dict[str, Any]]:
        """生成单账号 payload 列表（不上传，只是本地文件）。"""
        out = []
        for acc_model in accounts:
            extra = acc_model.get_extra()
            if fmt == "kanwang":
                refresh_token = str(extra.get("refresh_token") or "").strip()
                if not refresh_token:
                    raise RuntimeError(f"{acc_model.email} 缺少 refresh_token,无法导出卡网格式")
                out.append({
                    "email": acc_model.email,
                    "filename": f"{self._safe_filename(acc_model.email)}.txt",
                    "payload": refresh_token,
                })
            elif fmt == "cpa":
                account_obj = self._account_view_for_export(acc_model, extra)
                from platforms.chatgpt.cpa_upload import generate_token_json
                token_data = generate_token_json(account_obj)
                out.append({
                    "email": acc_model.email,
                    "filename": f"{self._safe_filename(acc_model.email)}.json",
                    "payload": token_data,
                })
            elif fmt == "sub2api":
                account_obj = self._account_view_for_export(acc_model, extra)
                from platforms.chatgpt.sub2api_upload import (
                    build_sub2api_bundle_from_token_data,
                )
                from platforms.chatgpt.cpa_upload import generate_token_json
                token_data = generate_token_json(account_obj)
                payload = build_sub2api_bundle_from_token_data(
                    token_data, account=account_obj,
                )
                out.append({
                    "email": acc_model.email,
                    "filename": f"{self._safe_filename(acc_model.email)}.json",
                    "payload": payload,
                })
        return out

    @staticmethod
    def _account_view_for_export(acc_model: AccountModel, extra: dict) -> Any:
        """构造一个鸭子类型对象,satisfy generate_token_json / build_sub2api_*。"""
        class _View:
            email = acc_model.email
            access_token = extra.get("access_token", "") or acc_model.token or ""
            refresh_token = extra.get("refresh_token", "") or ""
            id_token = extra.get("id_token", "") or ""
            session_token = extra.get("session_token", "") or ""
            account_id = extra.get("oauth_account_id", "") or acc_model.user_id or ""
            cpa_priority = int(extra.get("cpa_priority") or 0)

            def get_extra(self):
                return dict(extra)
        return _View()

    @staticmethod
    def _safe_filename(email: str) -> str:
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in email)[:120]

    @staticmethod
    def _write_export_file(export_id: str, fmt: str, payloads: list[dict[str, Any]]) -> str:
        if fmt == "kanwang":
            return BusinessRTLoopRunner._write_export_txt(export_id, fmt, payloads)
        if fmt == "sub2api":
            return BusinessRTLoopRunner._write_sub2api_bundle(export_id, payloads)
        return BusinessRTLoopRunner._write_export_zip(export_id, fmt, payloads)

    @staticmethod
    def _pending_rt_migration_payload(acc_model: AccountModel) -> dict[str, Any]:
        return {
            "platform": acc_model.platform,
            "email": acc_model.email,
            "password": acc_model.password,
            "user_id": acc_model.user_id or "",
            "region": acc_model.region or "",
            "token": acc_model.token or "",
            "status": AccountStatus.PENDING_RT.value,
            "cashier_url": acc_model.cashier_url or "",
            "extra": acc_model.get_extra(),
            "created_at": acc_model.created_at.isoformat() if acc_model.created_at else "",
            "updated_at": acc_model.updated_at.isoformat() if acc_model.updated_at else "",
        }

    @staticmethod
    def _normalize_pending_rt_migration_account(raw: Any, *,
                                                reset_retry: bool = True) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError("账号项必须是对象")
        email = str(raw.get("email") or "").strip().lower()
        if "@" not in email:
            raise ValueError("缺少合法 email")
        password = str(raw.get("password") or "")
        if not password:
            raise ValueError(f"{email} 缺少 password")
        domain = email.split("@", 1)[1].strip().lower()

        extra_raw = raw.get("extra")
        if extra_raw is None and raw.get("extra_json") is not None:
            extra_raw = raw.get("extra_json")
        if isinstance(extra_raw, str):
            try:
                extra = json.loads(extra_raw or "{}")
            except Exception:
                extra = {}
        elif isinstance(extra_raw, dict):
            extra = dict(extra_raw)
        else:
            extra = {}

        extra.setdefault("account_type", "BUSINESS")
        extra.setdefault("business_domain", domain)
        extra.setdefault("mail_provider", "cfworker")
        extra.setdefault("register_mode", "oauth_business")
        extra.setdefault("business_switch_to_codex", "0")
        # 源机器 claim/backoff 在目标机器无意义,必须清掉,否则导入后可能长时间不被消费。
        for key in ("rt_auto_claim_id", "rt_auto_claimed_at", "rt_auto_next_attempt_at"):
            extra.pop(key, None)
        if reset_retry:
            extra["rt_retry_count"] = 0
            extra.pop("rt_acquisition_error", None)
            extra.pop("last_rt_attempt_at", None)

        return {
            "email": email,
            "password": password,
            "user_id": str(raw.get("user_id") or ""),
            "region": str(raw.get("region") or ""),
            "token": str(raw.get("token") or ""),
            "cashier_url": str(raw.get("cashier_url") or ""),
            "extra": extra,
        }

    @staticmethod
    def _write_pending_rt_migration_file(export_id: str, payload: dict[str, Any]) -> str:
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        file_path = os.path.join(_EXPORT_ROOT, f"pending_rt_migration_{export_id}.json")
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        return file_path

    @staticmethod
    def _write_export_zip(export_id: str, fmt: str, payloads: list[dict[str, Any]]) -> str:
        import zipfile
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        file_path = os.path.join(_EXPORT_ROOT, f"{fmt}_{export_id}.zip")
        with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in payloads:
                content = json.dumps(item["payload"], ensure_ascii=False, indent=2)
                zf.writestr(item["filename"], content)
        return file_path

    @staticmethod
    def _write_export_txt(export_id: str, fmt: str, payloads: list[dict[str, Any]]) -> str:
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        file_path = os.path.join(_EXPORT_ROOT, f"{fmt}_{export_id}.txt")
        lines = [str(item["payload"]).strip() for item in payloads]
        with open(file_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")
        return file_path

    @staticmethod
    def _write_sub2api_bundle(export_id: str, payloads: list[dict[str, Any]]) -> str:
        from platforms.chatgpt.sub2api_upload import merge_sub2api_bundles

        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        file_path = os.path.join(_EXPORT_ROOT, f"sub2api_{export_id}.json")
        bundle = merge_sub2api_bundles([item["payload"] for item in payloads])
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
            f.write("\n")
        return file_path

    @staticmethod
    def find_export_file(export_id: str) -> str | None:
        cpa_zip_candidate = os.path.join(_EXPORT_ROOT, f"cpa_{export_id}.zip")
        if os.path.exists(cpa_zip_candidate):
            return cpa_zip_candidate
        sub2api_json_candidate = os.path.join(_EXPORT_ROOT, f"sub2api_{export_id}.json")
        if os.path.exists(sub2api_json_candidate):
            return sub2api_json_candidate
        legacy_sub2api_zip_candidate = os.path.join(_EXPORT_ROOT, f"sub2api_{export_id}.zip")
        if os.path.exists(legacy_sub2api_zip_candidate):
            return legacy_sub2api_zip_candidate
        txt_candidate = os.path.join(_EXPORT_ROOT, f"kanwang_{export_id}.txt")
        if os.path.exists(txt_candidate):
            return txt_candidate
        migration_candidate = os.path.join(_EXPORT_ROOT, f"pending_rt_migration_{export_id}.json")
        if os.path.exists(migration_candidate):
            return migration_candidate
        return None

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _account_model_to_account(account_id: int) -> Account:
        with Session(engine) as s:
            acc_model = s.get(AccountModel, account_id)
            if not acc_model:
                raise RuntimeError(f"账号 {account_id} 不存在")
            return Account(
                platform=acc_model.platform,
                email=acc_model.email,
                password=acc_model.password,
                user_id=acc_model.user_id or "",
                region=acc_model.region or "",
                token=acc_model.token or "",
                status=AccountStatus(acc_model.status) if acc_model.status in {
                    s.value for s in AccountStatus
                } else AccountStatus.REGISTERED,
                extra=acc_model.get_extra(),
            )

    @staticmethod
    def _mark_account_status(account_id: int, status: AccountStatus) -> None:
        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return
            acc.status = status.value
            from core.db import _utcnow
            acc.updated_at = _utcnow()
            s.add(acc)
            s.commit()

    # paginated list 直接走 core.db.list_accounts_paginated
    @staticmethod
    def _account_extra_for_ui(extra: dict[str, Any]) -> dict[str, Any]:
        """只返回列表页需要的诊断字段,避免把 cookies/token 大对象塞进轮询响应。"""
        allowed_keys = {
            "account_type",
            "business_domain",
            "mail_provider",
            "device_id",
            "rt_retry_count",
            "seat_retry_count",
            "rt_auto_next_attempt_at",
            "rt_auto_last_error",
            "rt_acquisition_error",
            "seat_switch_error",
            "rt_health_status",
            "rt_health_error",
            "rt_unreachable_reason",
            "rt_otp_fail_streak",
            # 新流程: 每阶段错误/调度信息
            "invite_last_error",
            "invite_next_attempt_at",
            "activate_last_error",
            "activate_next_attempt_at",
            "seat_change_last_error",
            "seat_change_next_attempt_at",
            "seat_change_eligible_at",
            "business_invite_id",
            "business_master_account_id",
            "seat_type",
        }
        if not isinstance(extra, dict):
            return {}
        out: dict[str, Any] = {}
        for key in allowed_keys:
            if key not in extra:
                continue
            value = extra.get(key)
            if isinstance(value, str):
                out[key] = value[:1000]
            elif isinstance(value, (int, float, bool)) or value is None:
                out[key] = value
            elif isinstance(value, (list, dict)):
                # UI 当前不需要复杂结构；转短字符串避免巨大 JSON 拖慢响应。
                out[key] = json.dumps(value, ensure_ascii=False)[:1000]
            else:
                out[key] = str(value)[:1000]
        # 阶段时间线 (前端渲染 stepper 用):每阶段返回完成时间(ISO 字符串或 epoch 秒)
        # 字段名以 _at 结尾, 已完成才会有值。空值表示未到达该阶段。
        pipeline = {
            "registered_at": extra.get("created_time") or extra.get("register_at") or "",
            "invite_sent_at": extra.get("invite_sent_at") or "",
            "activated_at": extra.get("invite_activated_at") or "",
            "seat_switched_at": extra.get("seat_switched_to_chatgpt_at")
                or extra.get("seat_switched_to_codex_at") or "",
            "rt_acquired_at": (extra.get("rt_acquired_at")
                               if extra.get("rt_acquired_at")
                               else ("done" if extra.get("refresh_token") else "")),
        }
        out["pipeline_stages"] = pipeline
        return out

    @staticmethod
    def list_accounts(status: str | None, page: int, page_size: int) -> dict[str, Any]:
        result = list_accounts_paginated(_PLATFORM, status, page, page_size)
        return {
            "total": result["total"],
            "page": page,
            "page_size": page_size,
            "items": [
                {
                    "id": a.id,
                    "email": a.email,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else "",
                    "updated_at": a.updated_at.isoformat() if a.updated_at else "",
                    "extra": BusinessRTLoopRunner._account_extra_for_ui(a.get_extra()),
                }
                for a in result["items"]
            ],
        }
