"""Proxy choices must survive queueing/recovery and never fall back to direct."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlmodel import Session, create_engine

from api import tasks
from services import gmail_registration as registration, gmail_store as store
from services import registration_proxy
from services.gmail_registration_runtime import GmailRegistrationRuntime


@pytest.fixture
def prepared_request(monkeypatch):
    monkeypatch.setattr(registration, "validate_registration_request", lambda **kw: {})
    monkeypatch.setattr(registration_proxy, "resolve_registration_proxy", lambda key: {
        "key": "manual:7", "url": "http://127.0.0.1:7811", "label": "checked fixture", "kind": "manual", "proxy_id": 7
    } if key == "manual:7" else (_ for _ in ()).throw(ValueError("代理未检测通过")))
    return tasks.RegisterTaskRequest(platform="chatgpt", proxy_key="manual:7", extra={"gmail_alias_ids": [1]})


def test_enqueue_validates_proxy_before_creating_job_and_defaults_headless(prepared_request):
    callbacks = BackgroundTasks()
    prepared_request.proxy_key = None
    with pytest.raises(HTTPException) as error:
        tasks.enqueue_register_task(prepared_request, background_tasks=callbacks)
    assert error.value.status_code == 409
    assert not callbacks.tasks
    prepared_request.proxy_key = "manual:7"
    task_id = tasks.enqueue_register_task(prepared_request, background_tasks=callbacks)
    queued = callbacks.tasks[0].args[1]
    assert queued.executor_type == "headless"
    assert queued.proxy_key == queued.extra["registration_proxy_key"] == "manual:7"
    assert queued.proxy is None and queued.proxy_node is None
    tasks._task_store.finish(task_id, status="stopped", success=0, skipped=0, errors=[])


@pytest.mark.parametrize("field,value", [("proxy", "http://127.0.0.1:7890"), ("proxy_node", "unchecked-node")])
def test_raw_overrides_cannot_bypass_managed_selection(prepared_request, field, value):
    setattr(prepared_request, field, value)
    with pytest.raises(HTTPException) as error:
        tasks._prepare_register_request(prepared_request)
    assert error.value.status_code == 400


@pytest.mark.parametrize("executor", ["protocol", "headed", "headless"])
def test_explicit_executor_is_preserved(prepared_request, executor):
    prepared_request.executor_type = executor
    assert tasks._prepare_register_request(prepared_request).executor_type == executor


@pytest.mark.parametrize("still_available", [True, False])
@pytest.mark.parametrize("proxy_failure", [True, False])
def test_worker_revalidates_before_alias_allocation_and_uses_selected_proxy(prepared_request, monkeypatch, still_available, proxy_failure):
    req = tasks._prepare_register_request(prepared_request)
    captured = {}
    mailbox = Mock()
    mailbox.get_email.return_value = SimpleNamespace(email="owner+child1@gmail.com", extra={})
    mailbox.load_registered_account.return_value = None
    mailbox.get_registration_password.return_value = "fixture-password"
    factory = Mock(return_value=mailbox)
    monkeypatch.setattr("core.base_mailbox.create_mailbox", factory)
    monkeypatch.setattr("core.config_store.config_store.get_all", lambda: {"default_proxy": "http://do-not-use.invalid:9"})
    monkeypatch.setattr(tasks, "_save_task_log", Mock())
    report_fail = Mock()
    monkeypatch.setattr("core.proxy_pool.proxy_pool.report_fail", report_fail)
    failure = "ProxyError fixture stopped before network" if proxy_failure else "fixture stopped before network"

    class FixturePlatform:
        def __init__(self, config, mailbox):
            captured["config"] = config
            self.mailbox = mailbox

        def bind_task_control(self, control):
            pass

        def register(self, **kwargs):
            raise RuntimeError(failure)

    monkeypatch.setattr("core.registry.get", lambda platform: FixturePlatform)
    if not still_available:
        monkeypatch.setattr(registration_proxy, "resolve_registration_proxy", Mock(side_effect=ValueError("代理已停用")))
    task_id = f"fixture-proxy-task-{still_available}-{proxy_failure}"
    tasks._create_task_record(task_id, req, "manual")
    tasks._run_register(task_id, req)
    snapshot = tasks._task_store.snapshot(task_id)
    if still_available:
        assert captured["config"].proxy == "http://127.0.0.1:7811"
        assert captured["config"].executor_type == "headless"
        assert factory.call_args.kwargs["proxy"] == captured["config"].proxy
        assert factory.call_args.kwargs["extra"]["registration_proxy_key"] == "manual:7"
        assert factory.call_args.kwargs["extra"]["executor_type"] == "headless"
        mailbox.get_email.assert_called_once()
        assert any("fixture stopped before network" in error for error in snapshot["errors"])
    else:
        factory.assert_not_called()
        assert any("代理已停用" in error for error in snapshot["errors"])
    if still_available and proxy_failure:
        report_fail.assert_called_once_with("http://127.0.0.1:7811", proxy_id=7)
    else:
        report_fail.assert_not_called()


def test_recovery_reuses_choice_and_defaults_old_jobs_to_headless(monkeypatch):
    monkeypatch.setattr(registration, "list_due_registration_retries", lambda **kw: [
        {"alias_id": 1, "source_id": 4, "options": {"registration_proxy_key": "manual:8"}}
    ])
    resolver = Mock(return_value={"key": "manual:8"})
    enqueue = Mock(return_value="fixture-recovery-task")
    monkeypatch.setattr(registration_proxy, "resolve_registration_proxy", resolver)
    monkeypatch.setattr(tasks, "enqueue_register_task", enqueue)
    GmailRegistrationRuntime().tick()
    resolver.assert_called_once_with("manual:8")
    req = enqueue.call_args.args[0]
    assert req.proxy_key == "manual:8" and req.executor_type == "headless"
    assert req.extra["gmail_alias_ids"] == [1] and req.extra["_gmail_retry"]


def test_bad_recovery_proxy_defers_with_visible_reason_without_enqueue(monkeypatch):
    monkeypatch.setattr(registration, "list_due_registration_retries", lambda **kw: [
        {"alias_id": 1, "source_id": 4, "options": {"registration_proxy_key": "manual:8"}}
    ])
    monkeypatch.setattr(registration_proxy, "resolve_registration_proxy", Mock(side_effect=ValueError("代理检测失败")))
    deferred, enqueue = Mock(), Mock()
    monkeypatch.setattr(registration, "defer_registration_for_proxy", deferred)
    monkeypatch.setattr(tasks, "enqueue_register_task", enqueue)
    GmailRegistrationRuntime().tick()
    enqueue.assert_not_called()
    deferred.assert_called_once_with(1, "等待注册代理：代理检测失败")


def test_choice_persists_without_storing_proxy_password_and_defer_keeps_stage(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'gmail.db'}")
    monkeypatch.setattr(store, "engine", engine)
    store.init_tables(engine)
    options = registration._options({"registration_proxy_key": "manual:7", "executor_type": "headless",
                                    "proxy": "http://secret:password@proxy.invalid:80"})
    assert "password" not in json.dumps(options)
    with Session(engine) as session:
        session.add(store.GmailAlias(source_id=1, tag="child1", email="owner+child1@gmail.com", registration_status="retry_pending",
                                    registration_stage="email_verification", registration_options_json=json.dumps(options)))
        session.commit()
    registration.defer_registration_for_proxy(1, "等待注册代理：代理检测失败")
    with Session(engine) as session:
        row = session.get(store.GmailAlias, 1)
        assert row.registration_status == "retry_pending" and row.registration_stage == "email_verification"
        assert row.registration_retry_at and row.registration_error == "等待注册代理：代理检测失败"
        assert json.loads(row.registration_options_json)["registration_proxy_key"] == "manual:7"
        assert not row.registration_lease_token
    engine.dispose()


def test_gmail_browser_defaults_headless(monkeypatch):
    import time
    from services import gmail_verifier
    monkeypatch.delenv("GMAIL_VERIFY_HEADLESS", raising=False)
    captured = []
    monkeypatch.setattr(gmail_verifier, "start_local_browser", lambda factory, **kw: captured.append(factory()))
    gmail_verifier._start_browser(None, time.monotonic() + 30)
    assert captured[0].is_headless is True
