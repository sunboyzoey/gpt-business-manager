"""Eligibility, persisted health and check lifecycle; no network access."""
from __future__ import annotations

import importlib
import json
import threading

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlmodel import Session, create_engine

from core.db import ProxyModel, get_session
from core.proxy_pool import ProxyHealth, ProxyPool, init_proxy_health
from services.registration_proxy import list_registration_proxy_options, resolve_registration_proxy


@pytest.fixture
def proxy_env(tmp_path, monkeypatch):
    manual = importlib.import_module("core.proxy_pool")
    subscription = importlib.import_module("services.proxy_pool")
    api = importlib.import_module("api.proxies")
    db_engine = create_engine(f"sqlite:///{tmp_path / 'proxies.sqlite'}", connect_args={"check_same_thread": False})
    ProxyModel.__table__.create(db_engine)
    init_proxy_health(db_engine)
    monkeypatch.setattr(manual, "engine", db_engine)
    pool = ProxyPool()
    monkeypatch.setattr(api, "proxy_pool", pool)
    monkeypatch.setattr(subscription, "_proxy_pool", [])
    monkeypatch.setattr(subscription, "_test_status", {"running": False, "results": [], "updated_at": 0})
    monkeypatch.setattr(subscription, "_chatgpt_protocol_status", {"running": False, "results": [], "pool": [], "updated_at": 0})
    monkeypatch.setattr(subscription, "get_nodes", lambda: [])
    monkeypatch.setattr(subscription, "POOL_FILE", tmp_path / "pool.json")
    monkeypatch.setattr(subscription, "CHATGPT_PROTOCOL_POOL_FILE", tmp_path / "protocol.json")

    def sessions():
        with Session(db_engine) as session:
            yield session

    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[get_session] = sessions
    with TestClient(app) as client:
        yield db_engine, pool, subscription, client
    db_engine.dispose()


def add_proxy(db_engine, url="http://secret-user:secret-password@proxy.example:8080", enabled=True):
    with Session(db_engine) as session:
        proxy = ProxyModel(url=url, is_active=enabled)
        session.add(proxy)
        session.commit()
        session.refresh(proxy)
        return proxy


def test_unchecked_not_selected_and_pass_does_not_reenable_disabled(proxy_env):
    db_engine, pool, subscription, client = proxy_env
    active = add_proxy(db_engine)
    disabled = add_proxy(db_engine, "http://disabled.example:8080", enabled=False)
    assert list_registration_proxy_options() == {"items": [], "total": 0}
    assert pool.get_next() is None
    pool.record_check(active.url, {"ok": True, "latency": 40}, active.id)
    pool.record_check(disabled.url, {"ok": True}, disabled.id)
    rows = client.get("/proxies").json()
    assert rows[1]["is_active"] is False
    assert rows[1]["last_check_ok"] is True
    assert rows[1]["is_usable"] is False
    payload = client.get("/proxies/registration-options").json()
    assert payload["total"] == 1
    assert payload["items"][0]["key"] == f"manual:{active.id}"
    assert "secret-user" not in json.dumps(payload)
    assert "secret-password" not in json.dumps(payload)
    assert "url" not in payload["items"][0]
    assert resolve_registration_proxy(f"manual:{active.id}")["url"] == active.url
    assert pool.get_next() == active.url


def test_health_survives_reinitialization_and_invalidates_changed_url(proxy_env):
    db_engine, pool, subscription, client = proxy_env
    proxy = add_proxy(db_engine)
    pool.record_check(proxy.url, {"ok": True}, proxy.id)
    init_proxy_health(db_engine)
    assert ProxyPool().get_next() == proxy.url
    with Session(db_engine) as session:
        current = session.get(ProxyModel, proxy.id)
        current.url = "http://different.example:8080"
        session.add(current)
        session.commit()
    assert pool.get_next() is None
    assert client.get("/proxies").json()[0]["last_check_ok"] is None
    with pytest.raises(ValueError):
        resolve_registration_proxy(f"manual:{proxy.id}")


def test_disable_delete_and_latest_failure_revoke_selection(proxy_env):
    db_engine, pool, subscription, client = proxy_env
    proxy = add_proxy(db_engine)
    key = f"manual:{proxy.id}"
    pool.record_check(proxy.url, {"ok": True}, proxy.id)
    client.patch(f"/proxies/{proxy.id}/toggle")
    with pytest.raises(ValueError):
        resolve_registration_proxy(key)
    client.patch(f"/proxies/{proxy.id}/toggle")
    assert resolve_registration_proxy(key)["url"] == proxy.url
    pool.record_check(proxy.url, {"ok": False, "error": proxy.url}, proxy.id)
    row = client.get("/proxies").json()[0]
    assert row["is_active"] is True
    assert row["last_check_ok"] is False
    assert "secret-password" not in row["last_check_error"]
    with pytest.raises(ValueError):
        resolve_registration_proxy(key)
    pool.record_check(proxy.url, {"ok": True}, proxy.id)
    assert client.delete(f"/proxies/{proxy.id}").status_code == 200
    with Session(db_engine) as session:
        assert session.get(ProxyHealth, proxy.id) is None
    with pytest.raises(ValueError):
        resolve_registration_proxy(key)


def test_check_job_reports_real_progress_and_continues_after_exception(proxy_env, monkeypatch):
    db_engine, pool, subscription, client = proxy_env
    first = add_proxy(db_engine)
    add_proxy(db_engine, "http://second.example:8080", enabled=False)
    started, release = threading.Event(), threading.Event()

    def probe(url, **kwargs):
        assert kwargs["cache_ttl"] == 0
        if url == first.url:
            started.set()
            assert release.wait(timeout=3)
            raise RuntimeError(f"bad credentials {first.url}")
        return {"ok": True, "latency": 22}

    monkeypatch.setattr(subscription, "probe_chatgpt_protocol_proxy", probe)
    status = pool.prepare_check()
    thread = threading.Thread(target=pool.check_all, kwargs={"job_id": status["job_id"]})
    thread.start()
    assert started.wait(timeout=3)
    try:
        interim = client.get("/proxies/check-status").json()
        assert interim["running"] is True
        assert interim["total"] == 2
        assert interim["completed"] == 0
        duplicate = pool.prepare_check()
        assert duplicate["started"] is False
        assert duplicate["job_id"] == status["job_id"]
    finally:
        release.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    final = client.get("/proxies/check-status").json()
    assert final["running"] is False
    assert final["completed"] == 2
    assert final["ok"] == final["fail"] == 1
    assert final["finished_at"]
    assert "secret-password" not in json.dumps(final)
    assert client.get("/proxies").json()[1]["is_active"] is False


def test_add_rejects_bad_urls_without_echoing_credentials(proxy_env):
    db_engine, pool, subscription, client = proxy_env
    for url in ("secret-password", "http://user:secret-password@host:99999", "file:///secret-password", "http://proxy.example"):
        response = client.post("/proxies", json={"url": url})
        assert response.status_code == 400
        assert "secret-password" not in response.text
    response = client.post("/proxies/bulk", json={"proxies": ["host:8080:user:password", "invalid"]})
    assert response.json() == {"added": 1, "skipped": 1}
    assert client.get("/proxies").json()[0]["last_check_ok"] is None


def test_subscription_selection_only_uses_latest_passed_current_listener(proxy_env, monkeypatch):
    db_engine, pool, subscription, client = proxy_env
    node = {"name": "US node", "addr": "http://127.0.0.1:7891", "port": 7891}
    monkeypatch.setattr(subscription, "get_nodes", lambda: [node, {"name": "unchecked", "addr": "http://127.0.0.1:7892"}])
    subscription._proxy_pool = [{**node, "latency": 10, "region": "US"}]
    subscription._test_status.update(updated_at=100, results=[{**node, "status": "ok"}])
    assert list_registration_proxy_options()["total"] == 1
    key = "subscription:US node"
    assert resolve_registration_proxy(key)["url"] == node["addr"]
    subscription._chatgpt_protocol_status.update(updated_at=101, results=[{**node, "status": "fail"}])
    with pytest.raises(ValueError):
        resolve_registration_proxy(key)
    subscription._test_status.update(updated_at=102)
    assert resolve_registration_proxy(key)["url"] == node["addr"]
    node["addr"] = "http://127.0.0.1:9999"
    with pytest.raises(ValueError):
        resolve_registration_proxy(key)


def test_subscription_disable_removes_both_pools_and_persists(proxy_env, monkeypatch):
    db_engine, pool, subscription, client = proxy_env
    node = {"name": "node", "addr": "http://127.0.0.1:7891", "port": 7891}
    monkeypatch.setattr(subscription, "get_nodes", lambda: [node])
    subscription._proxy_pool = [dict(node)]
    subscription._test_status.update(updated_at=100, results=[{**node, "status": "ok"}])
    subscription._chatgpt_protocol_status.update(updated_at=101, pool=[dict(node)], results=[{**node, "status": "ok"}])
    assert list_registration_proxy_options()["total"] == 1
    assert subscription.disable_proxy(node["addr"]) is True
    assert list_registration_proxy_options()["total"] == 0
    assert json.loads(subscription.POOL_FILE.read_text())["pool"] == []
    assert json.loads(subscription.CHATGPT_PROTOCOL_POOL_FILE.read_text())["pool"] == []


def test_invalid_key_error_never_echoes_input(proxy_env):
    with pytest.raises(ValueError) as exc:
        resolve_registration_proxy("http://secret-user:secret-password@proxy:1234")
    assert "secret-password" not in str(exc.value)


def test_subscription_update_invalidates_cached_results_without_network(proxy_env, monkeypatch, tmp_path):
    db_engine, pool, subscription, client = proxy_env
    node = {"name": "node", "addr": "http://127.0.0.1:7891", "port": 7891}
    subscription._proxy_pool = [dict(node)]
    subscription._chatgpt_protocol_status.update(pool=[dict(node)], results=[{**node, "status": "ok"}])
    monkeypatch.setattr(subscription, "MIHOMO_DIR", tmp_path / "mihomo")
    monkeypatch.setattr(subscription, "MIHOMO_CONFIG", tmp_path / "mihomo/config.yaml")
    monkeypatch.setattr(subscription, "is_mihomo_installed", lambda: True)
    monkeypatch.setattr(subscription, "_restart_mihomo", lambda: None)
    monkeypatch.setattr(subscription, "_subscription_generation", 0)

    class Response:
        text = "proxies:\n  - name: node\n    type: ss\n    server: replacement.example\n    port: 443\n    password: secret-password\n"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(subscription.requests, "get", lambda *args, **kwargs: Response())
    assert subscription.update_subscription("https://subscription.example/list")["ok"]
    assert subscription.get_pool() == []
    assert subscription.get_chatgpt_protocol_test_status()["pool"] == []
    assert subscription._subscription_generation == 1
    assert "secret-password" not in subscription.POOL_FILE.read_text()


def test_check_http_denials_and_subscription_replacement_cannot_publish_passed_nodes(proxy_env, monkeypatch):
    db_engine, pool, subscription, client = proxy_env
    node = {"name": "node", "addr": "http://127.0.0.1:7891", "port": 7891}
    monkeypatch.setattr(subscription, "get_nodes", lambda: [node])
    monkeypatch.setattr(subscription, "_subscription_generation", 0)

    class Response:
        status_code = 403
        text = "loc=US\n"

    monkeypatch.setattr(subscription.requests, "get", lambda *args, **kwargs: Response())
    assert subscription.test_nodes()[0]["status"] == "fail"
    assert subscription.get_pool() == []

    def replace_during_check(*args, **kwargs):
        subscription._subscription_generation += 1
        response = Response()
        response.status_code = 200
        return response

    monkeypatch.setattr(subscription.requests, "get", replace_during_check)
    assert subscription.test_nodes() == []
    assert subscription.get_pool() == []
    assert subscription.get_test_status()["running"] is False
