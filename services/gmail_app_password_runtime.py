"""Run only explicitly requested Gmail application-password setup jobs."""
from __future__ import annotations

import logging
import threading

from services import gmail_store

logger = logging.getLogger(__name__)


def _jobs():
    from services import gmail_app_password_store
    return gmail_app_password_store


def run_job(job_id: str, stop_event: threading.Event | None = None):
    store = _jobs()
    snapshot = store.claim(job_id)
    if snapshot is None:
        return
    stop_event = stop_event or threading.Event()
    heartbeat_stop = threading.Event()
    lease_lost = threading.Event()

    def heartbeat():
        while not heartbeat_stop.wait(10):
            try:
                if store.heartbeat(snapshot) is False:
                    lease_lost.set()
                    return
            except Exception:
                lease_lost.set()
                return

    def should_stop():
        return stop_event.is_set() or lease_lost.is_set() or not store.is_current(snapshot)

    def progress(stage, _message):
        # Store maps stages to fixed messages, never browser text.
        # Retain the actual failing phase; terminal status is set atomically
        # by finish_success/finish_failure after the browser result arrives.
        if stage in {"failed", "completed"}:
            return
        if isinstance(stage, str) and stage.startswith("reauth_"):
            stage = stage.removeprefix("reauth_")
        store.heartbeat(snapshot, stage=stage)

    def before_create():
        if should_stop():
            raise gmail_store.GmailStoreError("source_changed", "母号状态已变化，未创建应用密码", 409)
        store.before_create(snapshot)

    keeper = threading.Thread(target=heartbeat, name="gmail-app-password-heartbeat", daemon=True)
    keeper.start()
    try:
        with gmail_store.verification_guard(snapshot.email):
            if should_stop():
                store.finish_failure(snapshot, "cancelled" if stop_event.is_set() else "source_changed")
                return
            if not snapshot.has_pending_password:
                from services.gmail_app_password_browser import provision_app_password
                credentials = gmail_store.decrypt_verification_credentials(snapshot.verification)
                try:
                    result = provision_app_password(
                        credentials.email, credentials.login_password, credentials.recovery_email,
                        credentials.totp_secret, proxy_url=snapshot.proxy_url,
                        app_name=f"Auto Sale {snapshot.source_id} {snapshot.job_id[:8]}",
                        progress=progress, should_stop=should_stop,
                        before_create=before_create,
                        on_created=lambda password: store.save_created(snapshot, password),
                    )
                finally:
                    credentials = None
                if not isinstance(result, dict) or result.get("ok") is not True:
                    store.finish_failure(snapshot, result.get("code", "verification_failed")
                                         if isinstance(result, dict) else "verification_failed")
                    return
            # The password was saved durably by on_created even if shutdown
            # arrived immediately after Google's single-use display appeared.
            if should_stop():
                store.finish_failure(snapshot, "cancelled" if stop_event.is_set() else "source_changed")
                return
            store.heartbeat(snapshot, stage="imap")
            from services.gmail_transport import GmailTransport, GmailTransportError
            transport = None
            password = None
            try:
                password = store.verification_password(snapshot)
                transport = GmailTransport(snapshot.email, password, proxy_url=snapshot.proxy_url)
                transport.connect_test()
            except GmailTransportError as exc:
                store.finish_failure(snapshot, "imap_" + exc.code)
                return
            finally:
                password = None
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass
            store.finish_success(snapshot)
    except gmail_store.GmailStoreError as exc:
        try:
            store.finish_failure(snapshot, exc.code)
        except Exception:
            logger.warning("Gmail application-password job awaits durable recovery")
    except Exception:
        # Never publish upstream exception text or account credentials.
        try:
            store.finish_failure(snapshot, "verification_failed")
        except Exception:
            logger.warning("Gmail application-password job awaits durable recovery")
    finally:
        heartbeat_stop.set()
        keeper.join(timeout=2)


class GmailAppPasswordRuntime:
    def __init__(self):
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                store = _jobs()
                store.recover()
                rows = store.list_queued(limit=1)
                if rows:
                    run_job(rows[0]["id"], self._stop)
                    continue
            except Exception:
                logger.warning("Gmail application-password worker will retry a local operation")
            self._wake.wait(3)
            self._wake.clear()

    def start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._wake.set()
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="gmail-app-password-setup", daemon=True)
            self._thread.start()

    def wake(self):
        self.start()

    def stop(self, timeout=20):
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)


gmail_app_password_runtime = GmailAppPasswordRuntime()
