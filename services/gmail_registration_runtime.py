"""Resume only explicitly started Gmail registration jobs from durable stages."""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)


class GmailRegistrationRuntime:
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._active: dict[int, tuple[int, str]] = {}
        self._attempted: dict[int, float] = {}

    def tick(self):
        from api.tasks import RegisterTaskRequest, enqueue_register_task, _task_store
        from services.gmail_registration import list_due_registration_retries

        with self._lock:
            for alias_id, (_, task_id) in list(self._active.items()):
                if not _task_store.exists(task_id) or _task_store.snapshot(task_id).get("status") in {"done", "failed", "stopped"}:
                    self._active.pop(alias_id, None)
            mothers = {mother_id for mother_id, _ in self._active.values()}
            now = time.monotonic()
            self._attempted = {key: stamp for key, stamp in self._attempted.items() if now - stamp < 60}
            for row in list_due_registration_retries(limit=100):
                if self._stop.is_set() or len(self._active) >= 2:
                    break
                alias_id, source_id = row["alias_id"], row["source_id"]
                if alias_id in self._active or alias_id in self._attempted or source_id in mothers:
                    continue
                options = dict(row.get("options") or {})
                executor = options.pop("executor_type", "headless")
                if executor not in {"protocol", "headless", "headed"}:
                    executor = "headless"
                proxy_key = options.pop("registration_proxy_key", "")
                self._attempted[alias_id] = now
                from services.registration_proxy import resolve_registration_proxy
                from services.gmail_registration import defer_registration_for_proxy
                try:
                    resolve_registration_proxy(proxy_key)
                except ValueError as exc:
                    defer_registration_for_proxy(alias_id, f"等待注册代理：{exc}")
                    continue
                try:
                    task_id = enqueue_register_task(RegisterTaskRequest(
                        platform="chatgpt", count=1, concurrency=1, executor_type=executor,
                        proxy_key=proxy_key,
                        extra={**options, "mail_provider": "gmail", "gmail_source_id": source_id,
                               "gmail_alias_ids": [alias_id], "_gmail_retry": True},
                    ), source="gmail_recovery", meta={"gmail_alias_id": alias_id, "gmail_source_id": source_id})
                except Exception:
                    # Error text may contain provider credentials; the durable row owns diagnostics.
                    logger.warning("Gmail recovery enqueue deferred for alias %s", alias_id)
                    continue
                self._active[alias_id] = (source_id, task_id)
                mothers.add(source_id)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.warning("Gmail registration recovery will retry after a local error")
            self._stop.wait(15)

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        from services.gmail_registration import recover_registration_state
        recover_registration_state(startup=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="gmail-registration-recovery", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)


gmail_registration_runtime = GmailRegistrationRuntime()
