"""定时任务调度 - 账号有效性检测、trial 到期提醒"""
from contextlib import contextmanager
from datetime import datetime, timezone
import math
from typing import Callable
from sqlmodel import Session, select
from .db import engine, AccountModel
from .registry import get, load_all
from .base_platform import Account, AccountStatus, RegisterConfig
import threading
import time


# 后台任务总开关(存 config_store;默认开)。关闭后调度器跳过对应任务。
TASK_TOGGLE_KEYS = {
    "cpa_maintenance": "scheduler_cpa_maintenance_enabled",
    "device_maintenance": "scheduler_device_maintenance_enabled",
}


def task_enabled(name: str) -> bool:
    """读取某个后台任务总开关;缺省视为开启。"""
    key = TASK_TOGGLE_KEYS.get(name)
    if not key:
        return True
    try:
        from .config_store import config_store
        return str(config_store.get(key, "1")).strip().lower() not in ("0", "false", "no", "off", "")
    except Exception:
        return True


class Scheduler:
    def __init__(self):
        self._running = False
        self._thread: threading.Thread = None
        self._generation = 0
        self._loop_interval_seconds = 60
        # 暂停计数(可重入):>0 时 _loop 跳过所有维护任务。
        # 用于批量重置等独占任务期间挂起后台 curl_cffi 请求,
        # 避免与前台任务并发触碰 BoringSSL 句柄导致 TLS 崩(curl 35 invalid library)。
        self._pause_count = 0
        self._pause_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._trial_check_interval_seconds = 3600
        self._last_trial_check_at = 0.0
        self._last_cpa_maintenance_at = 0.0
        self._last_device_maintenance_at = 0.0
        self._device_maintenance_interval_seconds = 300
        self._last_gpt_business_mail_check_at = 0.0
        self._gpt_business_mail_check_interval_seconds = 300  # 5 分钟
        self._last_gpt_plan_mail_check_at = 0.0
        self._gpt_plan_mail_check_interval_seconds = 300  # 5 分钟
        self._last_gpt_plan_appeal_backfill_at = 0.0
        self._gpt_plan_appeal_backfill_interval_seconds = 60
        self._last_gpt_plan_refunded_mail_check_at = 0.0
        # 已退款目录通常远大于当前会员目录，且不再承担退款迁移判断。
        # 独立低频 lane 避免它占满会员/活动 BUSINESS 子号的五分钟轮次。
        self._gpt_plan_refunded_mail_check_interval_seconds = 3600
        self._last_business_sub2api_usage_hour = ""  # BUSINESS 子号独立 scope
        self._last_delivery_device_monitor_at = time.time()
        self._delivery_device_monitor_last_started_at: float | None = None
        self._delivery_device_monitor_interval_seconds = 3600
        self._delivery_device_monitor_lock = threading.RLock()
        # The dispatcher must never execute remote/network/database maintenance
        # inline.  Every task type owns one single-flight daemon worker so a
        # slow mailbox or device cannot delay unrelated recovery work.
        self._task_threads: dict[str, threading.Thread] = {}
        self._task_threads_lock = threading.RLock()
        self._task_last_started_at: dict[str, float] = {}
        self._task_last_finished_at: dict[str, float] = {}
        self._task_last_error_type: dict[str, str] = {}

    def start(self):
        with self._lifecycle_lock:
            if self._running:
                return
            self._generation += 1
            generation = self._generation
            self._stop_event.clear()
            self._running = True
            self._last_trial_check_at = 0.0
            self._last_cpa_maintenance_at = 0.0
            self._last_device_maintenance_at = 0.0
            self._last_gpt_business_mail_check_at = 0.0
            self._last_gpt_plan_mail_check_at = 0.0
            self._last_gpt_plan_appeal_backfill_at = 0.0
            self._last_gpt_plan_refunded_mail_check_at = 0.0
            # Device creation already performs an immediate refresh. Delay the
            # all-device sweep so a process restart cannot fan out quota probes
            # to every production device at once.
            with self._delivery_device_monitor_lock:
                self._last_delivery_device_monitor_at = time.time()
                self._delivery_device_monitor_last_started_at = None
            self._thread = threading.Thread(
                target=self._loop,
                args=(generation,),
                daemon=True,
                name=f"scheduler-dispatcher-{generation}",
            )
            self._thread.start()
        print("[Scheduler] 已启动")

    def stop(self):
        with self._lifecycle_lock:
            self._running = False
            self._stop_event.set()

    def _generation_is_running(self, generation: int) -> bool:
        """Fence dispatchers/workers created by an older scheduler run."""
        with self._lifecycle_lock:
            return bool(
                self._running
                and not self._stop_event.is_set()
                and int(generation) == int(self._generation)
            )

    def _start_isolated_task(
        self,
        task_name: str,
        target: Callable[[], object],
        *,
        error_label: str,
        expected_generation: int | None = None,
    ) -> bool:
        """Start one daemon worker for a task type without allowing overlap.

        The registry is intentionally per task type rather than a shared pool:
        a blocked worker consumes only its own slot.  Completed workers are
        replaceable on the next dispatcher tick, while a live worker fences a
        duplicate invocation of the same task.
        """
        name = str(task_name or "").strip()
        with self._lifecycle_lock:
            generation = (
                int(self._generation)
                if expected_generation is None
                else int(expected_generation)
            )
            if (
                not name
                or not self._running
                or self._stop_event.is_set()
                or generation != int(self._generation)
            ):
                return False
        with self._pause_lock:
            if self._pause_count > 0:
                return False
        with self._task_threads_lock:
            current = self._task_threads.get(name)
            if current is not None and current.is_alive():
                return False

            def _runner() -> None:
                try:
                    if not self._generation_is_running(generation):
                        return
                    target()
                    with self._task_threads_lock:
                        self._task_last_error_type.pop(name, None)
                except Exception as exc:
                    error_type = type(exc).__name__
                    with self._task_threads_lock:
                        self._task_last_error_type[name] = error_type
                    # Exception text may contain request headers or secrets.
                    print(f"[Scheduler/{name}] {error_label}错误: {error_type}")
                finally:
                    with self._task_threads_lock:
                        self._task_last_finished_at[name] = time.time()

            thread = threading.Thread(
                target=_runner,
                daemon=True,
                name=f"scheduler-{name}",
            )
            self._task_threads[name] = thread
            self._task_last_started_at[name] = time.time()
            try:
                # Linearize launch against stop(): after stop acquires the
                # lifecycle lock, no later worker can be started.
                with self._lifecycle_lock:
                    if (
                        not self._running
                        or self._stop_event.is_set()
                        or generation != int(self._generation)
                    ):
                        if self._task_threads.get(name) is thread:
                            self._task_threads.pop(name, None)
                        return False
                    thread.start()
            except Exception:
                if self._task_threads.get(name) is thread:
                    self._task_threads.pop(name, None)
                raise
            return True

    def delivery_device_monitor_schedule(self) -> dict:
        """Return the authoritative, process-local device sweep schedule.

        The delivery-device monitor intentionally uses one global hourly sweep,
        not one timer per device.  Exposing the scheduler anchor prevents the UI
        from incorrectly deriving the next run from a device's ``refreshed_at``
        (which is also changed by manual refreshes and device creation).
        Epoch values are milliseconds so clients do not reinterpret naive
        database timestamps in their local timezone.
        """
        now = time.time()
        with self._pause_lock:
            paused = self._pause_count > 0
        with self._delivery_device_monitor_lock:
            anchor = float(self._last_delivery_device_monitor_at)
            last_started_at = self._delivery_device_monitor_last_started_at
            interval = int(self._delivery_device_monitor_interval_seconds)
        with self._task_threads_lock:
            monitor_thread = self._task_threads.get("delivery_device_monitor")
            running = bool(monitor_thread and monitor_thread.is_alive())

        next_run_at = anchor + interval
        if not self._running:
            state = "stopped"
        elif paused:
            state = "paused"
        elif running:
            state = "running"
        elif now >= next_run_at:
            # The main scheduler checks once per loop, so a due sweep can wait
            # for up to ``_loop_interval_seconds`` before its worker starts.
            state = "due"
        else:
            state = "waiting"

        return {
            "scope": "global",
            "enabled": bool(self._running),
            "state": state,
            "running": running,
            "paused": paused,
            "interval_seconds": interval,
            "poll_interval_seconds": int(self._loop_interval_seconds),
            "last_started_at": (
                int(last_started_at * 1000)
                if last_started_at is not None
                else None
            ),
            "next_run_at": int(next_run_at * 1000),
            "server_time": int(now * 1000),
            "seconds_until_next_run": max(
                0,
                int(math.ceil(next_run_at - now)),
            ),
        }

    @property
    def is_paused(self) -> bool:
        return self._pause_count > 0

    def pause(self):
        with self._pause_lock:
            self._pause_count += 1
            cnt = self._pause_count
        print(f"[Scheduler] 已暂停后台任务 (count={cnt})")

    def resume(self):
        with self._pause_lock:
            if self._pause_count > 0:
                self._pause_count -= 1
            cnt = self._pause_count
        print(f"[Scheduler] 恢复后台任务 (count={cnt})")

    @contextmanager
    def paused(self):
        """上下文管理器:进入时暂停后台维护,退出时恢复(可重入、异常安全)。"""
        self.pause()
        try:
            yield
        finally:
            self.resume()

    def _loop(self, generation: int | None = None):
        run_generation = (
            int(self._generation) if generation is None else int(generation)
        )
        while self._generation_is_running(run_generation):
            # 被暂停时只空转,不触发任何维护任务(短睡以便快速响应恢复)
            if self._pause_count > 0:
                self._stop_event.wait(5)
                continue
            now = time.time()
            if now - self._last_trial_check_at >= self._trial_check_interval_seconds:
                self._dispatch_one(
                    "trial_expiry", self._task_trial_expiry, "Trial 检查",
                    expected_generation=run_generation,
                )

            # 定时注册任务检查
            self._dispatch_one(
                "scheduled_jobs", self._task_scheduled_jobs,
                "定时注册任务检查",
                expected_generation=run_generation,
            )

            # 统一 CPA/Sub2API 设备页的账号清单与额度快照。额度探测可能包含
            # 多个远端请求，因此放在独立 daemon 线程，既不阻塞主调度循环，
            # 也与 BUSINESS 的删除/换号 worker 故障隔离。
            with self._delivery_device_monitor_lock:
                delivery_monitor_due = (
                    now - self._last_delivery_device_monitor_at
                    >= self._delivery_device_monitor_interval_seconds
                )
            if delivery_monitor_due:
                self._dispatch_one(
                    "delivery_device_monitor",
                    self._task_delivery_device_monitor,
                    "设备账号额度刷新",
                    expected_generation=run_generation,
                )

            if (
                now - self._last_gpt_business_mail_check_at
                >= self._gpt_business_mail_check_interval_seconds
            ):
                self._dispatch_one(
                    "gpt_business_mail", self._task_gpt_business_mail,
                    "GPT BUSINESS 邮件监控",
                    expected_generation=run_generation,
                )

            if (
                now - self._last_gpt_plan_mail_check_at
                >= self._gpt_plan_mail_check_interval_seconds
            ):
                self._dispatch_one(
                    "gpt_plan_mail", self._task_gpt_plan_mail,
                    "GPT 套餐邮件监控",
                    expected_generation=run_generation,
                )

            if (
                now - self._last_gpt_plan_appeal_backfill_at
                >= self._gpt_plan_appeal_backfill_interval_seconds
            ):
                # DEAD 存量申诉邮件补查独占 worker；慢邮箱不能阻塞常规邮件监控。
                self._dispatch_one(
                    "gpt_plan_appeal_backfill",
                    self._task_gpt_plan_appeal_backfill,
                    "GPT 套餐申诉邮件补查",
                    expected_generation=run_generation,
                )

            if (
                now - self._last_gpt_plan_refunded_mail_check_at
                >= self._gpt_plan_refunded_mail_check_interval_seconds
            ):
                self._dispatch_one(
                    "gpt_plan_refunded_mail",
                    self._task_gpt_plan_refunded_mail,
                    "GPT 套餐已退款账号邮件监控",
                    expected_generation=run_generation,
                )

            # CPA/Sub2API 设备只维护账号清单、套餐及额度快照。不要从
            # scheduler 自动补注册/补设备，也不要恢复旧的设备删除、
            # 禁用、TEAM 401、轮换、母号调度或补位链路；否则后台轮询
            # 会绕过“刷新只读”边界修改远端设备或 BUSINESS 成员。统一
            # device monitor 是本调度器唯一的 CPA/Sub2API 入口；新设备
            # 托管使用独立且显式启用的 runtime，不能由此处扫描隐式触发。
            # Remote removal may have succeeded while the local account purge
            # was fenced by another durable worker or a transient DB error.
            # Retry that strictly local cleanup in its own single-flight lane;
            # it must never wait behind device/network maintenance.
            self._dispatch_one(
                "dead_business_child_purge",
                self._task_dead_business_child_purge,
                "dead BUSINESS 子号本地清理",
                expected_generation=run_generation,
            )

            self._stop_event.wait(self._loop_interval_seconds)

    def _dispatch_one(
        self,
        task_name: str,
        target: Callable[[], object],
        error_label: str,
        *,
        expected_generation: int | None = None,
    ) -> bool:
        try:
            return self._start_isolated_task(
                task_name,
                target,
                error_label=error_label,
                expected_generation=expected_generation,
            )
        except Exception as exc:
            print(
                f"[Scheduler/{task_name}] 无法启动{error_label}: "
                f"{type(exc).__name__}"
            )
            return False

    def _task_trial_expiry(self) -> None:
        now = time.time()
        if now - self._last_trial_check_at < self._trial_check_interval_seconds:
            return
        self.check_trial_expiry()
        self._last_trial_check_at = time.time()

    def _task_cpa_maintenance(self) -> None:
        if not task_enabled("cpa_maintenance"):
            return
        interval = self._get_cpa_maintenance_interval_seconds()
        now = time.time()
        if not interval or now - self._last_cpa_maintenance_at < interval:
            return
        self.check_cpa_credentials()
        self._last_cpa_maintenance_at = time.time()

    def _task_scheduled_jobs(self) -> None:
        from api.scheduled import check_and_run_scheduled_jobs

        check_and_run_scheduled_jobs()

    def _task_device_maintenance(self) -> None:
        now = time.time()
        if (
            not task_enabled("device_maintenance")
            or now - self._last_device_maintenance_at
            < self._device_maintenance_interval_seconds
        ):
            return
        self.maintain_devices()
        self._last_device_maintenance_at = time.time()

    def _task_gpt_business_mail(self) -> None:
        now = time.time()
        if (
            now - self._last_gpt_business_mail_check_at
            < self._gpt_business_mail_check_interval_seconds
        ):
            return
        try:
            from api.gpt_business import _run_business_monitor_round

            summary = _run_business_monitor_round()
            if summary.get("scanned"):
                print(
                    f"[GPTBUSINESS/MailMonitor] 扫描 {summary['scanned']} 账号, "
                    f"成功 {summary['success']}, 失败 {summary['failed']}, "
                    f"新告警 {summary.get('total_new_alerts', 0)}, "
                    f"耗时 {summary.get('duration_seconds', 0)}s"
                )
        finally:
            self._last_gpt_business_mail_check_at = time.time()

    def _task_gpt_plan_mail(self) -> None:
        now = time.time()
        if (
            now - self._last_gpt_plan_mail_check_at
            < self._gpt_plan_mail_check_interval_seconds
        ):
            return
        try:
            from services.gpt_plan_mail_monitor import run_monitor_round

            summary = run_monitor_round(lane="priority")
            if summary.get("scanned"):
                print(
                    f"[GPTPlans/MailMonitor/Priority] 扫描 {summary['scanned']} 账号, "
                    f"成功 {summary['success']}, 失败 {summary['failed']}, "
                    f"新邮件 {summary.get('total_new_messages', 0)}, "
                    f"耗时 {summary.get('duration_seconds', 0)}s"
                )
        finally:
            self._last_gpt_plan_mail_check_at = time.time()

    def _task_gpt_plan_appeal_backfill(self) -> None:
        now = time.time()
        if (
            now - self._last_gpt_plan_appeal_backfill_at
            < self._gpt_plan_appeal_backfill_interval_seconds
        ):
            return
        try:
            from services.gpt_plan_appeals import run_backfill_round

            summary = run_backfill_round()
            counts = {
                key: max(0, int(summary.get(key) or 0))
                for key in ("scanned", "found", "not_found", "errors", "skipped")
            }
            if any(counts.values()):
                print(
                    f"[GPTPlans/AppealBackfill] 扫描 {counts['scanned']} 账号, "
                    f"找到 {counts['found']}, 未找到 {counts['not_found']}, "
                    f"错误 {counts['errors']}, 跳过 {counts['skipped']}"
                )
        finally:
            self._last_gpt_plan_appeal_backfill_at = time.time()

    def _task_gpt_plan_refunded_mail(self) -> None:
        now = time.time()
        if (
            now - self._last_gpt_plan_refunded_mail_check_at
            < self._gpt_plan_refunded_mail_check_interval_seconds
        ):
            return
        try:
            from services.gpt_plan_mail_monitor import run_refunded_monitor_round

            summary = run_refunded_monitor_round()
            if summary.get("scanned"):
                print(
                    f"[GPTPlans/MailMonitor/Refunded] 扫描 {summary['scanned']} 账号, "
                    f"成功 {summary['success']}, 失败 {summary['failed']}, "
                    f"新邮件 {summary.get('total_new_messages', 0)}, "
                    f"耗时 {summary.get('duration_seconds', 0)}s"
                )
        finally:
            self._last_gpt_plan_refunded_mail_check_at = time.time()

    def _task_business_sub2api_usage(self) -> None:
        import datetime as _dt
        from api.gpt_business import refresh_business_sub2api_usage

        marker = f"business:{_dt.datetime.now().strftime('%Y-%m-%d %H')}"
        if self._last_business_sub2api_usage_hour == marker:
            return
        summary = refresh_business_sub2api_usage(active=True)
        if summary.get("total"):
            print(f"[GPTBUSINESS/Sub2API] 额度整点刷新: {summary}")
        self._last_business_sub2api_usage_hour = marker

    def _task_cpa_delete_recovery(self) -> None:
        from api.delivery_devices import reconcile_pending_cpa_rotation_deletes

        summary = reconcile_pending_cpa_rotation_deletes()
        if summary.get("confirmed"):
            print(f"[GPTBUSINESS/CPA] 删除确认恢复: {summary}")

    def _task_delivery_cleanup_recovery(self) -> None:
        from api.delivery_devices import (
            reconcile_pending_delivery_exhaustion_cleanups,
        )

        summary = reconcile_pending_delivery_exhaustion_cleanups()
        if summary.get("resumed"):
            print(f"[Delivery] 恢复耗尽账号清理作业: {summary}")

    def _task_delivery_team401_recovery(self) -> None:
        from api.delivery_devices import resume_pending_team401_corrections

        summary = resume_pending_team401_corrections(limit=10)
        if summary.get("started"):
            print(f"[Delivery] 恢复 TEAM 401 纠错作业: {summary}")

    def _task_business_rotation_recovery(self) -> None:
        from api.gpt_business import resume_due_business_delivery_rotations

        summary = resume_due_business_delivery_rotations()
        if summary.get("started"):
            print(f"[GPTBUSINESS/Delivery] 恢复轮换作业: {summary}")

    def _task_business_dispatch_recovery(self) -> None:
        from api.gpt_business import resume_due_business_master_dispatches

        summary = resume_due_business_master_dispatches()
        if summary.get("started"):
            print(f"[GPTBUSINESS/Delivery] 恢复母号调度作业: {summary}")

    def _task_business_replenishment(self) -> None:
        from api.gpt_business import resume_due_business_replenishments

        summary = resume_due_business_replenishments()
        if summary.get("considered"):
            print(f"[GPTBUSINESS/Delivery] 自动补位调度: {summary}")

    def _task_dead_business_child_purge(self) -> None:
        from api.gpt_business import (
            reconcile_pending_dead_business_child_purges,
        )

        summary = reconcile_pending_dead_business_child_purges(limit=20)
        if summary.get("deleted") or summary.get("cleared"):
            print(f"[GPTBUSINESS] dead 子号本地清理恢复: {summary}")

    def _task_delivery_device_monitor(self) -> dict:
        """Run the hourly CPA/Sub2API inventory sweep in its own task slot."""
        now = time.time()
        with self._delivery_device_monitor_lock:
            if (
                now - self._last_delivery_device_monitor_at
                < self._delivery_device_monitor_interval_seconds
            ):
                return {"ok": True, "skipped": "not_due"}
            self._last_delivery_device_monitor_at = now
            self._delivery_device_monitor_last_started_at = now
        return self._refresh_delivery_device_monitor_snapshots()

    def _get_cpa_maintenance_interval_seconds(self) -> int:
        from services.cpa_manager import get_cpa_maintenance_interval_seconds

        return get_cpa_maintenance_interval_seconds()

    def check_trial_expiry(self):
        """检查 trial 到期账号，更新状态"""
        now = int(datetime.now(timezone.utc).timestamp())
        with Session(engine) as s:
            accounts = s.exec(
                select(AccountModel).where(AccountModel.status == "trial")
            ).all()
            updated = 0
            for acc in accounts:
                if acc.trial_end_time and acc.trial_end_time < now:
                    acc.status = AccountStatus.EXPIRED.value
                    acc.updated_at = datetime.now(timezone.utc)
                    s.add(acc)
                    updated += 1
            s.commit()
            if updated:
                print(f"[Scheduler] {updated} 个 trial 账号已到期")

    def check_accounts_valid(self, platform: str = None, limit: int = 50):
        """批量检测账号有效性"""
        load_all()
        with Session(engine) as s:
            q = select(AccountModel).where(
                AccountModel.status.in_(["registered", "trial", "subscribed"])
            )
            if platform:
                q = q.where(AccountModel.platform == platform)
            accounts = s.exec(q.limit(limit)).all()

        results = {"valid": 0, "invalid": 0, "error": 0}
        for acc in accounts:
            try:
                PlatformCls = get(acc.platform)
                plugin = PlatformCls(config=RegisterConfig())
                import json
                account_obj = Account(
                    platform=acc.platform,
                    email=acc.email,
                    password=acc.password,
                    user_id=acc.user_id,
                    region=acc.region,
                    token=acc.token,
                    extra=json.loads(acc.extra_json or "{}"),
                )
                valid = plugin.check_valid(account_obj)
                with Session(engine) as s:
                    a = s.get(AccountModel, acc.id)
                    if a:
                        if acc.platform != "chatgpt":
                            a.status = acc.status if valid else AccountStatus.INVALID.value
                        a.updated_at = datetime.now(timezone.utc)
                        s.add(a)
                        s.commit()
                if valid:
                    results["valid"] += 1
                else:
                    results["invalid"] += 1
            except Exception:
                results["error"] += 1
        return results

    def check_cpa_credentials(self):
        """清理 CPA 中的 error 凭证，并在低于阈值时自动补注册。"""
        from services.cpa_manager import maintain_cpa_credentials

        return maintain_cpa_credentials()

    def maintain_devices(self):
        """遍历所有启用的同步设备，检查号池并按需补号。"""
        from services.device_manager import maintain_all_devices

        return maintain_all_devices()

    def _refresh_delivery_device_monitor_snapshots(self):
        """Refresh device account, plan, state and quota snapshots each hour.

        This task is observational. It persists sanitized inventory/quota
        snapshots but never disables/deletes credentials or starts BUSINESS
        replacement, invitation, OAuth/RT, upload or replenishment work.
        """
        try:
            from api.delivery_devices import (
                DeliveryDeviceRefreshTaskRequest,
                start_delivery_device_refresh_task,
            )
            from services.delivery_device_monitor import list_devices

            inventory = list_devices(include_accounts=False)
            marker = datetime.now(timezone.utc).strftime("%Y%m%dT%H")
            summary = {
                "ok": True,
                "total": 0,
                "started": 0,
                "reused": 0,
                "failed": 0,
            }
            for device in list(inventory.get("items") or []):
                if not isinstance(device, dict) or device.get("enabled") is False:
                    continue
                device_ref = str(device.get("device_ref") or "").strip()
                if not device_ref:
                    continue
                summary["total"] += 1
                try:
                    result = start_delivery_device_refresh_task(
                        device_ref,
                        DeliveryDeviceRefreshTaskRequest(
                            operation_id=f"scheduler-hourly:{marker}",
                        ),
                    )
                except Exception:
                    summary["failed"] += 1
                    continue
                if bool(result.get("reused")):
                    summary["reused"] += 1
                else:
                    summary["started"] += 1
            summary["ok"] = summary["failed"] == 0
            if summary.get("total"):
                print(f"[DeliveryDevices] 设备账号与额度定时刷新: {summary}")
            return summary
        except Exception as exc:
            # Do not stringify arbitrary transport errors: some HTTP clients
            # include request headers or credentials in exception messages.
            print(
                "[DeliveryDevices] 设备账号额度刷新错误: "
                f"{type(exc).__name__}"
            )
            return {"ok": False, "error_type": type(exc).__name__}


scheduler = Scheduler()
