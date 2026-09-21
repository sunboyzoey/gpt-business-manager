from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from sqlmodel import create_engine

from services import gmail_app_password_store as app_jobs
from services import gmail_import_jobs as imports
from services import gmail_store as store


def _wait(manager, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = manager.get(job_id)
        if result["status"] in {"completed", "cancelled"}:
            return result
        time.sleep(.01)
    raise AssertionError("import did not finish")


def test_three_field_import_uses_one_login_to_authorize_and_create_three_aliases(monkeypatch):
    temp = tempfile.TemporaryDirectory()
    engine = create_engine(f"sqlite:///{Path(temp.name) / 'gmail.sqlite'}",
                           connect_args={"check_same_thread": False})
    manager = imports.GmailImportJobManager()
    monkeypatch.setattr(store, "engine", engine)
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"t" * 32).decode())
    store.init_tables(engine)
    app_jobs.init_tables(engine)
    calls = []

    def provision(email, password, recovery, totp, **kwargs):
        calls.append((email, bool(password), recovery, bool(totp)))
        kwargs["progress"]("password", "ignored private value")
        assert kwargs["before_create"]() is True
        assert kwargs["on_created"]("abcdefghijklmnop") is True
        return {"ok": True, "code": "app_password_created"}

    try:
        with patch("services.gmail_app_password_browser.provision_app_password", side_effect=provision), \
             patch.object(store, "_check_app_password") as imap:
            job_id = manager.start_import(
                "fixtureparent744@gmail.com----fixture-password----JBSWY3DPEHPK3PXP"
            )["job_id"]
            result = _wait(manager, job_id)
        assert (result["created"], result["failed"]) == (1, 0)
        assert calls == [("fixtureparent744@gmail.com", True, "", True)]
        assert imap.call_count == 1
        item = result["items"][0]
        assert item["receive_ready"] is True and item["alias_count"] == 3
        assert [row["email"] for row in reversed(store.list_aliases(item["id"]))] == [
            "fixtureparent744+child1@gmail.com", "fixtureparent744+child2@gmail.com",
            "fixtureparent744+child3@gmail.com",
        ]
        assert app_jobs.latest_for_source(item["id"])["status"] == "succeeded"
    finally:
        manager.shutdown(3)
        engine.dispose()
        temp.cleanup()


def test_three_field_parser_keeps_recovery_optional_and_rejects_bad_totp():
    parsed = store.parse_import("Owner@gmail.com---login-pass---JBSWY3DPEHPK3PXP")
    credentials = parsed[0][1]
    assert credentials.email == "owner@gmail.com" and credentials.recovery_email == ""
    assert credentials.auto_authorize is True
    bad = store.parse_import("owner@gmail.com---login-pass---not-a-base32-secret")
    assert bad[0][1] is None and "2FA" in bad[0][2]
