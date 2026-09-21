"""Serial, durable preparation supervisor with a bounded isolated worker.

The timer enqueues only after an explicit opt-in. Manual batches also run while
the timer is disabled. A browser timeout does not hold up other queued accounts.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from services import gpt_plan_preparation_store as store

ROOT = Path(__file__).resolve().parents[1]
WORKER_TIMEOUT = 25 * 60


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class PreparationRuntime:
    def __init__(self):
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._child = None
        self._error = ""

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="gpt-plan-preparation-dispatcher")
            self._thread.start()

    def stop(self):
        # Let an in-flight worker persist its checkpoint and finish. Its own
        # timeout remains active even when the web server is being restarted.
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=3)

    def wake(self):
        self._wake.set()

    def status(self):
        return {"running": bool(self._thread and self._thread.is_alive()), "last_error": self._error}

    def _launch(self, job):
        database = store.engine.url
        if database.get_backend_name() == "sqlite" and database.database and database.database != ":memory:":
            database = database.set(database=str(Path(database.database).resolve()))
        environment = dict(os.environ)
        environment["DATABASE_URL"] = database.render_as_string(hide_password=False)
        process = subprocess.Popen([sys.executable, "-m", "services.gpt_plan_preparation", "--job", job["id"], "--token", job["token"]],
                                   cwd=str(ROOT), env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        self._child = (process, job["id"], job["token"], time.monotonic())
        store.heartbeat(job["id"], job["token"], process.pid)

    def _reap(self):
        if not self._child:
            return
        process, job_id, token, started = self._child
        if process.poll() is None:
            if time.monotonic() - started <= WORKER_TIMEOUT + 20:
                return
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            except ProcessLookupError:
                pass
        self._child = None
        store.interrupt_job(job_id, token)

    def tick(self):
        self._reap()
        store.recover_stale(_alive)
        settings = store.get_settings()
        if settings["enabled"]:
            store.enqueue(settings["batch_size"], automatic=True, due_only=True)
        job = store.claim_next()
        if job:
            try:
                self._launch(job)
            except Exception:
                store.interrupt_job(job["id"], job["token"])
                raise

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
                self._error = ""
            except Exception:
                # No raw exceptions: DB URLs, auth material and browser output
                # must not leak into the public dispatcher status.
                self._error = "准备调度暂时失败，将在下次检查时重试"
            self._wake.wait(5)
            self._wake.clear()


preparation_runtime = PreparationRuntime()


def run_worker(job_id, token):
    job = store.worker_job(job_id, token)
    if not job:
        return
    stopped = threading.Event()

    def heartbeat():
        while not stopped.wait(10):
            if not store.heartbeat(job_id, token, os.getpid()):
                # Fence any late browser write by stopping this exact worker.
                os.killpg(os.getpgrp(), signal.SIGTERM)
                os._exit(2)

    def deadline():
        if not stopped.wait(WORKER_TIMEOUT):
            # Independent worker deadline survives a web-server restart.
            os.killpg(os.getpgrp(), signal.SIGTERM)

    threading.Thread(target=heartbeat, daemon=True).start()
    threading.Thread(target=deadline, daemon=True).start()
    try:
        from services.gpt_plan_preparation_capabilities import prepare_account, check_account_cookie
        fn = check_account_cookie if job["kind"] == "check_cookie" else prepare_account
        result = fn(job["account_id"], job["settings"],
                    lambda message: store.append_log(job_id, token, message),
                    lambda stage, details=None: store.checkpoint(job_id, token, stage, details))
        store.finish(job_id, token, result)
    except Exception:
        store.finish(job_id, token, {"ok": False, "error_code": "preparation_worker_error",
                                   "error": "准备执行异常，已保留当前步骤与凭据，请检查任务后重试", "retryable": False})
    finally:
        stopped.set()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    run_worker(args.job, args.token)
