"""Provisioning persistence tests. SQLite is isolated; no Google/IMAP calls."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import json

import pytest
from sqlalchemy import inspect
from sqlmodel import Session, create_engine, select

from core.gmail_crypto import decrypt_gmail_password, encrypt_gmail_secret
from services import gmail_app_password_store as jobs
from services import gmail_store as sources

PASSWORD = "abcdefghijklmnop"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(sources, "engine", engine)
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"j" * 32).decode())
    sources.init_tables()
    jobs.init_tables()
    with Session(engine) as session:
        row = sources.GmailSource(email="fixture@gmail.com", login_password_ciphertext=encrypt_gmail_secret(
            "fixture@gmail.com", "login_password", "google-login-private"))
        session.add(row)
        session.commit()
        identity = row.id
    yield engine, identity
    engine.dispose()


def mutate_source(setup, **changes):
    engine, identity = setup
    with Session(engine) as session:
        row = session.get(sources.GmailSource, identity)
        for key, value in changes.items():
            setattr(row, key, value)
        session.add(row)
        session.commit()


def source(setup):
    with Session(setup[0]) as session:
        return session.get(sources.GmailSource, setup[1])


def active(setup):
    job = jobs.begin(setup[1])
    return job, jobs.claim(job["id"])


def expire(setup, job_id):
    with Session(setup[0]) as session:
        row = session.get(jobs.GmailAppPasswordJob, job_id)
        row.lease_expires_at = sources.utcnow() - timedelta(seconds=1)
        session.add(row)
        session.commit()


def test_read_missing_table_does_not_initialize_or_touch_other_engines(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    monkeypatch.setattr(sources, "engine", engine)
    assert jobs.list_jobs() == []
    assert jobs.latest_for_source(1) is None
    assert jobs.list_queued() == []
    assert jobs.recover() == {"recovered": 0, "needs_user": 0}
    with pytest.raises(sources.GmailStoreError) as caught:
        jobs.get_job("missing")
    assert caught.value.status_code == 404
    assert inspect(engine).get_table_names() == []
    engine.dispose()


def test_concurrent_begin_and_claim_one_source_only_one_job_and_worker(setup):
    with ThreadPoolExecutor(max_workers=5) as pool:
        created = list(pool.map(lambda _: jobs.begin(setup[1]), range(5)))
    assert len({row["id"] for row in created}) == 1
    with ThreadPoolExecutor(max_workers=5) as pool:
        claimed = list(pool.map(lambda _: jobs.claim(created[0]["id"]), range(5)))
    assert sum(snapshot is not None for snapshot in claimed) == 1
    assert jobs.get_job(created[0]["id"])["attempts"] == 1


def test_valid_source_is_noop_and_unverified_existing_password_only_verifies(setup):
    cipher = sources._encrypt("fixture@gmail.com", PASSWORD)
    mutate_source(setup, app_password_ciphertext=cipher, receive_verified=True)
    job = jobs.begin(setup[1])
    assert job["status"] == "succeeded"
    assert jobs.claim(job["id"]) is None
    assert jobs.begin(setup[1])["id"] == job["id"]
    mutate_source(setup, receive_verified=False, credential_revision=2)
    queued, snapshot = active(setup)
    assert queued["id"] != job["id"]
    assert snapshot.has_pending_password
    assert jobs.verification_password(snapshot) == PASSWORD
    with pytest.raises(sources.GmailStoreError):
        jobs.before_create(snapshot)
    jobs.finish_success(snapshot)
    assert source(setup).receive_verified


def test_disabled_and_missing_credentials_cannot_enqueue(setup):
    mutate_source(setup, enabled=False)
    with pytest.raises(sources.GmailStoreError) as caught:
        jobs.begin(setup[1])
    assert caught.value.code == "source_disabled"
    mutate_source(setup, enabled=True, login_password_ciphertext="")
    with pytest.raises(sources.GmailStoreError) as caught:
        jobs.begin(setup[1])
    assert caught.value.code == "credentials_missing"
    assert jobs.list_jobs() == []


def test_created_password_durable_before_imap_then_ready_and_secret_free(setup):
    job, snapshot = active(setup)
    jobs.before_create(snapshot)
    jobs.save_created(snapshot, "abcd efgh ijkl mnop")
    assert jobs.verification_password(snapshot) == PASSWORD
    assert not source(setup).app_password_ciphertext
    assert not source(setup).receive_verified
    assert jobs.get_job(job["id"])["has_pending_password"]
    finished = jobs.finish_success(snapshot)
    saved_source = source(setup)
    assert saved_source.receive_verified
    assert saved_source.credential_revision == 2
    assert decrypt_gmail_password(saved_source.email, saved_source.app_password_ciphertext) == PASSWORD
    public = json.dumps(finished, default=str) + repr(snapshot)
    for secret in (PASSWORD, snapshot.worker_token, saved_source.app_password_ciphertext, "google-login-private", "ciphertext"):
        assert secret not in public
    assert not jobs.is_current(snapshot)


def test_imap_failure_retains_password_and_never_recreates(setup):
    job, snapshot = active(setup)
    jobs.before_create(snapshot)
    jobs.save_created(snapshot, PASSWORD)
    failed = jobs.finish_failure(snapshot, "imap_authentication_failed")
    assert failed["can_retry"] and failed["has_pending_password"]
    assert failed["next_retry_at"] is None
    jobs.retry(job["id"])
    resumed = jobs.claim(job["id"])
    assert resumed.has_pending_password
    assert jobs.verification_password(resumed) == PASSWORD
    with pytest.raises(sources.GmailStoreError):
        jobs.before_create(resumed)
    jobs.finish_success(resumed)


def test_restart_after_create_without_saved_password_never_recreates(setup):
    job, snapshot = active(setup)
    jobs.before_create(snapshot)
    expire(setup, job["id"])
    assert jobs.recover() == {"recovered": 0, "needs_user": 1}
    recovered = jobs.get_job(job["id"])
    assert recovered["error_code"] == "create_result_unknown"
    assert not recovered["can_retry"]
    assert jobs.begin(setup[1])["id"] == job["id"]
    with pytest.raises(sources.GmailStoreError):
        jobs.retry(job["id"])
    assert jobs.claim(job["id"]) is None
    assert jobs.list_queued() == []


def test_live_worker_is_untouched_and_saved_password_resume_fences_old_worker(setup):
    job, snapshot = active(setup)
    jobs.before_create(snapshot)
    jobs.save_created(snapshot, PASSWORD)
    assert jobs.recover() == {"recovered": 0, "needs_user": 0}
    assert jobs.heartbeat(snapshot, stage="imap")
    expire(setup, job["id"])
    assert jobs.recover() == {"recovered": 1, "needs_user": 0}
    resumed = jobs.claim(job["id"])
    assert resumed and resumed.has_pending_password
    assert jobs.verification_password(resumed) == PASSWORD
    assert not jobs.is_current(snapshot)
    assert not jobs.heartbeat(snapshot)
    with pytest.raises(sources.GmailStoreError):
        jobs.finish_success(snapshot)
    with pytest.raises(sources.GmailStoreError):
        jobs.finish_failure(snapshot, "network_timeout")
    jobs.finish_success(resumed)


def test_source_revision_disabled_and_new_auth_fence_all_writes(setup):
    job, snapshot = active(setup)
    mutate_source(setup, credential_revision=2, enabled=False)
    assert not jobs.is_current(snapshot)
    with pytest.raises(sources.GmailStoreError):
        jobs.before_create(snapshot)
    failed = jobs.finish_failure(snapshot, "network_timeout")
    assert failed["error_code"] == "source_disabled"
    assert failed["next_retry_at"] is None
    mutate_source(setup, enabled=True)
    jobs.retry(job["id"])
    snapshot = jobs.claim(job["id"])
    jobs.before_create(snapshot)
    replacement = sources._encrypt("fixture@gmail.com", "ponmlkjihgfedcba")
    mutate_source(setup, app_password_ciphertext=replacement, receive_verified=True, credential_revision=3)
    with pytest.raises(sources.GmailStoreError):
        jobs.save_created(snapshot, PASSWORD)
    # The one-time Google result survives in the job even after the source edit.
    assert jobs.get_job(job["id"])["has_pending_password"]
    with pytest.raises(sources.GmailStoreError):
        jobs.finish_success(snapshot)
    assert source(setup).app_password_ciphertext == replacement
    assert jobs.finish_failure(snapshot, "failed")["error_code"] == "source_changed"
    assert jobs.begin(setup[1])["error_code"] == "already_ready"
    assert source(setup).app_password_ciphertext == replacement


def test_bounded_auto_retry_and_safe_manual_retry_from_last_phase(setup, monkeypatch):
    clock = [sources.utcnow()]
    monkeypatch.setattr(sources, "utcnow", lambda: clock[0])
    job = jobs.begin(setup[1])
    for attempt in range(1, 4):
        snapshot = jobs.claim(job["id"])
        assert snapshot
        failed = jobs.finish_failure(snapshot, "network_timeout")
        assert failed["attempts"] == attempt
        if attempt < 3:
            assert failed["next_retry_at"]
            assert jobs.list_queued() == []
            clock[0] += timedelta(minutes=2)
            assert len(jobs.list_queued()) == 1
        else:
            assert failed["next_retry_at"] is None
            assert failed["can_retry"]
            clock[0] += timedelta(days=1)
            assert jobs.list_queued() == []
    jobs.retry(job["id"])
    snapshot = jobs.claim(job["id"])
    assert snapshot
    assert jobs.finish_failure(snapshot, "network_timeout")["next_retry_at"]


def test_precreate_challenge_can_retry_and_unknown_error_never_leaks(setup):
    job, snapshot = active(setup)
    result = jobs.finish_failure(snapshot, "captcha_required")
    assert result["status"] == "needs_user"
    assert result["can_retry"]
    jobs.retry(job["id"])
    resumed = jobs.claim(job["id"])
    result = jobs.finish_failure(resumed, "https://secret:private@host/token=very-secret")
    assert result["error_code"] == "failed"
    assert "very-secret" not in json.dumps(result, default=str)
    assert jobs.claim(job["id"]) is None


def test_before_create_twice_and_wrong_worker_never_mutate_saved_result(setup):
    job, snapshot = active(setup)
    assert not jobs.is_current(replace(snapshot, worker_token="wrong"))
    jobs.before_create(snapshot)
    with pytest.raises(sources.GmailStoreError):
        jobs.before_create(snapshot)
    jobs.save_created(snapshot, PASSWORD)
    with pytest.raises(sources.GmailStoreError):
        jobs.save_created(snapshot, "ponmlkjihgfedcba")
    assert jobs.verification_password(snapshot) == PASSWORD


def test_latest_sources_not_limited_by_history_page(setup):
    engine, source_id = setup
    start = sources.utcnow()
    with Session(engine) as session:
        for index in range(105):
            session.add(jobs.GmailAppPasswordJob(source_id=source_id + index, email=f"fixture{index}@gmail.com",
                source_revision=1, status="succeeded", created_at=start + timedelta(seconds=index)))
        latest = jobs.GmailAppPasswordJob(source_id=source_id, email="fixture@gmail.com", source_revision=1,
            created_at=start + timedelta(seconds=200))
        session.add(latest)
        session.commit()
        newest_id = latest.id
    assert len(jobs.list_jobs()) == 100
    latest = {row["source_id"]: row for row in jobs.latest_jobs_by_source()}
    assert len(latest) == 105
    assert latest[source_id]["id"] == newest_id


def test_browser_progress_aliases_and_tls_reason_are_fixed(setup):
    job, snapshot = active(setup)
    jobs.heartbeat(snapshot, "account")
    assert jobs.get_job(job["id"])["stage"] == "identity"
    jobs.heartbeat(snapshot, "app_password")
    assert jobs.get_job(job["id"])["stage"] == "app_passwords"
    jobs.heartbeat(snapshot, "creating")
    assert jobs.get_job(job["id"])["stage"] == "app_passwords"
    jobs.before_create(snapshot)
    jobs.heartbeat(snapshot, "creating")
    assert jobs.get_job(job["id"])["stage"] == "create_started"
    jobs.save_created(snapshot, PASSWORD)
    jobs.heartbeat(snapshot, "imap")
    result = jobs.finish_failure(snapshot, "imap_tls_error")
    assert result["error_code"] == "imap_tls_error"
    assert result["next_retry_at"] is None
    assert result["has_pending_password"]
    assert result["can_retry"]


def test_dead_worker_recovery_and_forged_revision_cannot_commit(setup, monkeypatch):
    job, snapshot = active(setup)
    monkeypatch.setattr(jobs, "_worker_dead", lambda _job: True)
    assert jobs.recover() == {"recovered": 1, "needs_user": 0}
    resumed = jobs.claim(job["id"])
    assert resumed
    wrong = replace(resumed, revision=resumed.revision + 1)
    with pytest.raises(sources.GmailStoreError):
        jobs.before_create(wrong)
    assert jobs.is_current(resumed)


def test_busy_verification_guard_retries_without_any_create_attempt(setup, monkeypatch):
    now = [sources.utcnow()]
    monkeypatch.setattr(sources, "utcnow", lambda: now[0])
    job, snapshot = active(setup)
    result = jobs.finish_failure(snapshot, "source_busy")
    assert result["error_code"] == "source_busy"
    assert "稍后自动继续" in result["message"]
    assert result["next_retry_at"] is not None
    assert result["can_retry"]
    assert not result["has_pending_password"]
    assert jobs.list_queued() == []
    now[0] += timedelta(minutes=1)
    assert [row["id"] for row in jobs.list_queued()] == [job["id"]]
    resumed = jobs.claim(job["id"])
    assert resumed and not resumed.has_pending_password
    jobs.before_create(resumed)
    jobs.save_created(resumed, PASSWORD)
    jobs.finish_success(resumed)
