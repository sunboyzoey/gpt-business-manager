"""Bounded, in-memory Gmail verification queue; unverified secrets never enter DB."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import threading
import time
from typing import Optional
from uuid import uuid4

from services import gmail_store as store


_PROGRESS = {
    "browser": "正在启动独立浏览器验证 Gmail 可用性",
    "email": "正在验证 Google 账号",
    "password": "正在验证登录密码",
    "totp": "正在验证 Authenticator 2FA",
    "recovery": "正在确认已配置的辅助邮箱",
    "inbox": "正在确认 Gmail 收件箱可用",
    "imap": "正在验证 Gmail 收件授权",
    "completed": "验证通过，正在保存母号",
    "failed": "验证未通过，正在记录结果",
}


def _safe_verifier_result(result) -> tuple[bool, str, str]:
    # Values are fixed developer messages; arbitrary upstream text never crosses API.
    from services.gmail_verifier import _MESSAGES
    if not isinstance(result, dict):
        return False, "verification_failed", _MESSAGES["verification_failed"]
    code = result.get("code")
    if code not in _MESSAGES:
        code = "verification_failed"
    ok = result.get("ok") is True and code == "verified" and result.get("method") == "web"
    if not ok and code == "verified":
        code = "verification_failed"
    return ok, code, _MESSAGES[code]


@dataclass
class _Job:
    public: dict
    payload: list = field(repr=False)
    proxy_url: Optional[str] = None
    cancelled: threading.Event = field(default_factory=threading.Event, repr=False)
    source_id: Optional[int] = None
    finished_at: Optional[float] = None


class GmailImportJobManager:
    MAX_ACTIVE = 16
    MAX_RETAINED = 100
    RETENTION_SECONDS = 3600

    def __init__(self):
        self._condition = threading.Condition(threading.RLock())
        self._jobs: dict[str, _Job] = {}
        self._queue: list[str] = []
        self._worker: Optional[threading.Thread] = None
        self._stopping = False

    def _prune_locked(self):
        now = time.monotonic()
        finished = [(job.finished_at, key) for key, job in self._jobs.items() if job.finished_at is not None]
        for finished_at, key in sorted(finished):
            if now - finished_at > self.RETENTION_SECONDS or len(self._jobs) >= self.MAX_RETAINED:
                self._jobs.pop(key, None)

    def _start(self, payload: list, proxy_url: Optional[str], source_id=None) -> dict:
        with self._condition:
            self._prune_locked()
            if self._stopping:
                raise store.GmailStoreError("service_stopping", "服务正在关闭，未开始验证，请重启后重新提交", 503)
            if sum(job.public["status"] in {"queued", "running"} for job in self._jobs.values()) >= self.MAX_ACTIVE:
                raise store.GmailStoreError("verification_busy", "Gmail 验证队列已满，请等待当前任务完成后重试", 429)
            job_id = uuid4().hex
            rows = [{"line": number, "email": credentials.email if credentials is not None else "",
                     "status": "queued", "step": "queued", "message": "等待验证"}
                    for number, credentials, _ in payload]
            public = dict(id=job_id, status="queued", total=len(rows), processed=0,
                          created=0, updated=0, skipped=0, failed=0, rows=rows, errors=[], items=[])
            self._jobs[job_id] = _Job(public, payload, proxy_url, source_id=source_id)
            self._queue.append(job_id)
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._work, name="gmail-verification", daemon=True)
                self._worker.start()
            self._condition.notify_all()
            return {"job_id": job_id}

    def start_import(self, data: str, *, proxy_url: Optional[str] = None) -> dict:
        proxy = store.normalize_proxy_url(proxy_url) if proxy_url is not None else None
        return self._start(store.parse_import(data), proxy)

    def start_verify(self, source_id: int) -> dict:
        snapshot = store.verification_snapshot(source_id)
        # Do not decrypt until its turn, and reread the revision before using it.
        return self._start([(1, snapshot, "")], None, source_id=source_id)

    def get(self, job_id: str) -> dict:
        with self._condition:
            self._prune_locked()
            job = self._jobs.get(job_id)
            if job is None:
                raise store.GmailStoreError("import_job_not_found", "验证任务不存在或已过期；服务重启会清除未完成的登录资料，请重新提交验证", 404)
            return deepcopy(job.public)

    def cancel(self, job_id: str) -> dict:
        with self._condition:
            job = self._jobs.get(job_id)
            if job is None:
                raise store.GmailStoreError("import_job_not_found", "验证任务不存在或已过期，请重新读取最新状态", 404)
            if job.public["status"] in {"queued", "running"}:
                job.cancelled.set()
                if job.public["status"] == "queued":
                    self._finish_cancelled_locked(job)
                    job.payload.clear()
                    self._queue = [key for key in self._queue if key != job_id]
                else:
                    for row in job.public["rows"]:
                        if row["status"] == "validating":
                            row["message"] = "已请求取消，正在关闭验证浏览器"
                self._condition.notify_all()
            return deepcopy(job.public)

    def _finish_cancelled_locked(self, job):
        for row in job.public["rows"]:
            if row["status"] in {"queued", "validating"}:
                row.update(status="cancelled", step="cancelled", message="已取消，未保存本行资料")
        job.public["status"] = "cancelled"
        job.finished_at = time.monotonic()

    def _progress(self, job, index, step, _message):
        with self._condition:
            if not job.cancelled.is_set():
                safe_step = step if step in _PROGRESS else "browser"
                job.public["rows"][index].update(step=safe_step, message=_PROGRESS[safe_step])

    def _finish_row(self, job, index, *, outcome, message, item=None):
        row = job.public["rows"][index]
        row.update(status=outcome, step="completed" if outcome != "failed" else "failed", message=message)
        job.public[outcome] += 1
        job.public["processed"] += 1
        if outcome == "failed":
            job.public["errors"].append({"line": row["line"], "message": message})
        if item is not None:
            job.public["items"] = [value for value in job.public["items"] if value["id"] != item["id"]] + [item]

    def _verify_import(self, job, index, credentials):
        if not credentials.auto_authorize:
            from services.gmail_verifier import verify_login
            with store.verification_guard(credentials.email):
                identity = store.source_identity(credentials.email)
                proxy = job.proxy_url
                if proxy is None:
                    proxy = store.source_proxy(identity[0]) if identity else ""
                result = verify_login(credentials.email, credentials.login_password, credentials.recovery_email,
                                      credentials.totp_secret, proxy_url=proxy,
                                      progress=lambda step, message: self._progress(job, index, step, message),
                                      should_stop=job.cancelled.is_set)
                ok, code, message = _safe_verifier_result(result)
                with self._condition:
                    if job.cancelled.is_set() or code == "cancelled":
                        job.cancelled.set()
                        return
                    if not ok:
                        self._finish_row(job, index, outcome="failed", message=message)
                        return
                    outcome, item = store._save_imported_credentials(
                        credentials, expected_identity=identity,
                        verification={"ok": True, "method": "web"}, proxy_url=job.proxy_url)
                    self._finish_row(job, index, outcome=outcome,
                        message="验证通过，母号已保存" if outcome != "skipped" else "验证通过，已更新可用状态",
                        item=item)
            return

        with store.verification_guard(credentials.email):
            identity = store.source_identity(credentials.email)
            # A blank unspecified import proxy preserves the saved configuration.
            proxy = job.proxy_url
            if proxy is None:
                proxy = store.source_proxy(identity[0]) if identity else ""
            existing = next((row for row in store.list_sources()
                             if identity and row["id"] == identity[0]), None)
            if existing and existing.get("has_app_password"):
                from services.gmail_verifier import verify_login
                result = verify_login(
                    credentials.email, credentials.login_password, credentials.recovery_email,
                    credentials.totp_secret, proxy_url=proxy,
                    progress=lambda step, message: self._progress(job, index, step, message),
                    should_stop=job.cancelled.is_set,
                )
                ok, code, message = _safe_verifier_result(result)
                with self._condition:
                    if job.cancelled.is_set() or code == "cancelled":
                        job.cancelled.set()
                        return
                    if not ok:
                        self._finish_row(job, index, outcome="failed", message=message)
                        return
                    outcome, item = store._save_imported_credentials(
                        credentials, expected_identity=identity,
                        verification={"ok": True, "method": "web"}, proxy_url=job.proxy_url)
                    snapshot = store.verification_snapshot(item["id"])
                    from core.gmail_crypto import decrypt_gmail_password
                    password = decrypt_gmail_password(snapshot.email, snapshot.app_password_ciphertext)
                    store._check_app_password(snapshot.email, password, snapshot.proxy_url)
                    item = store.record_verification_result(
                        snapshot, ok=True, method="imap", message="Gmail 收件授权验证通过")
                    remaining = int(item.get("remaining_alias_count") or 0)
                    if remaining:
                        store.generate_aliases(item["id"], count=remaining, prefix="child")
                        item = next(row for row in store.list_sources() if row["id"] == item["id"])
                    self._finish_row(job, index, outcome=outcome,
                        message="登录与已有收件授权验证完成，已自动生成 3 个子号", item=item)
                return
            from services import gmail_app_password_store as setup
            from services.gmail_app_password_browser import provision_app_password
            state = {"snapshot": None, "outcome": "", "item": None}

            def save_source_and_claim():
                if job.cancelled.is_set():
                    return False
                state["outcome"], state["item"] = store._save_imported_credentials(
                    credentials, expected_identity=identity,
                    verification={"ok": True, "method": "web"}, proxy_url=job.proxy_url)
                state["snapshot"] = setup.begin_inline(state["item"]["id"])
                setup.before_create(state["snapshot"])
                return True

            def save_password(password):
                setup.save_created(state["snapshot"], password)
                return True

            result = provision_app_password(
                credentials.email, credentials.login_password, credentials.recovery_email,
                credentials.totp_secret, proxy_url=proxy,
                app_name=f"Auto Sale Import {index + 1}",
                progress=lambda step, message: self._progress(job, index, step, message),
                should_stop=job.cancelled.is_set, before_create=save_source_and_claim,
                on_created=save_password,
            )
            ok = isinstance(result, dict) and result.get("ok") is True
            code = result.get("code", "verification_failed") if isinstance(result, dict) else "verification_failed"
            message = "Gmail 登录与收件授权未完成，请查看授权任务状态"
            with self._condition:
                if job.cancelled.is_set() or code == "cancelled":
                    job.cancelled.set()
                    return
                snapshot = state["snapshot"]
                if not ok or snapshot is None:
                    if snapshot is not None:
                        setup.finish_failure(snapshot, code)
                        state["item"] = next((row for row in store.list_sources()
                                              if row["id"] == snapshot.source_id), state["item"])
                    self._finish_row(job, index, outcome="failed", message=message, item=state["item"])
                    return
                try:
                    setup.heartbeat(snapshot, stage="imap")
                    store._check_app_password(credentials.email, setup.verification_password(snapshot), proxy)
                    setup.finish_success(snapshot)
                    item = next(row for row in store.list_sources() if row["id"] == snapshot.source_id)
                    remaining = int(item.get("remaining_alias_count") or 0)
                    if remaining:
                        store.generate_aliases(snapshot.source_id, count=remaining, prefix="child")
                        item = next(row for row in store.list_sources() if row["id"] == snapshot.source_id)
                    self._finish_row(job, index, outcome=state["outcome"],
                        message="登录与收件授权完成，已自动生成 3 个子号", item=item)
                except store.GmailStoreError as exc:
                    setup.finish_failure(snapshot, "imap_" + exc.code)
                    item = next((row for row in store.list_sources() if row["id"] == snapshot.source_id), state["item"])
                    self._finish_row(job, index, outcome="failed", message="应用密码已保存，收件验证将自动重试", item=item)

    def _verify_saved(self, job, index):
        from services.gmail_verifier import verify_login
        snapshot = store.verification_snapshot(job.source_id)
        with store.verification_guard(snapshot.email):
            if snapshot.login_password_ciphertext:
                credentials = store.decrypt_verification_credentials(snapshot)
                result = verify_login(credentials.email, credentials.login_password, credentials.recovery_email,
                    credentials.totp_secret, proxy_url=snapshot.proxy_url,
                    progress=lambda step, message: self._progress(job, index, step, message),
                    should_stop=job.cancelled.is_set)
                ok, code, message = _safe_verifier_result(result)
                method = "web"
            else:
                from core.gmail_crypto import decrypt_gmail_password
                method, code, ok = "imap", "verified", True
                message = "Gmail 收件授权验证通过"
                self._progress(job, index, "imap", "")
                try:
                    password = decrypt_gmail_password(snapshot.email, snapshot.app_password_ciphertext)
                    store._check_app_password(snapshot.email, password, snapshot.proxy_url)
                except store.GmailStoreError as exc:
                    ok, code, message = False, "verification_failed", exc.message
                except Exception:
                    ok, code, message = False, "verification_failed", "应用密码解密或验证失败，请检查服务器密钥或重新保存应用密码"
            with self._condition:
                if job.cancelled.is_set() or code == "cancelled":
                    job.cancelled.set()
                    return
                item = store.record_verification_result(snapshot, ok=ok, method=method, message=message)
                self._finish_row(job, index, outcome="updated" if ok else "failed", message=message, item=item)

    def _run_job(self, job):
        for index in range(len(job.payload)):
            with self._condition:
                if job.cancelled.is_set():
                    break
                number, credentials, error = job.payload[index]
                # Remove the pending plaintext reference as soon as it is in use.
                job.payload[index] = (number, None, "")
                if error:
                    self._finish_row(job, index, outcome="failed", message=error)
                    continue
                job.public["rows"][index].update(status="validating", step="browser", message="正在验证 Gmail 母号")
            try:
                if job.source_id is not None:
                    self._verify_saved(job, index)
                else:
                    self._verify_import(job, index, credentials)
            except store.GmailStoreError as exc:
                with self._condition:
                    if not job.cancelled.is_set():
                        self._finish_row(job, index, outcome="failed", message=exc.message)
            except Exception:
                with self._condition:
                    if not job.cancelled.is_set():
                        self._finish_row(job, index, outcome="failed", message="Gmail 验证未完成，本行资料未保存，请稍后重新验证")
            finally:
                credentials = None
        with self._condition:
            job.payload.clear()
            if job.cancelled.is_set():
                self._finish_cancelled_locked(job)
            else:
                job.public["status"] = "completed"
                job.finished_at = time.monotonic()

    def _work(self):
        while True:
            with self._condition:
                while not self._queue and not self._stopping:
                    self._condition.wait()
                if self._stopping:
                    return
                job_id = self._queue.pop(0)
                job = self._jobs.get(job_id)
                if job is None or job.cancelled.is_set():
                    continue
                job.public["status"] = "running"
            self._run_job(job)

    def shutdown(self, timeout: float = 40):
        with self._condition:
            self._stopping = True
            for job in self._jobs.values():
                if job.public["status"] in {"queued", "running"}:
                    job.cancelled.set()
                    if job.public["status"] == "queued":
                        job.payload.clear()
                        self._finish_cancelled_locked(job)
            self._queue.clear()
            self._condition.notify_all()
            worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(0, min(timeout, 45)))
        return worker is None or not worker.is_alive()


manager = GmailImportJobManager()


def shutdown_jobs(timeout: float = 40):
    return manager.shutdown(timeout)
