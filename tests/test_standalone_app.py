from pathlib import Path
from fastapi.testclient import TestClient


def test_empty_project_startup_and_api_isolation():
    import main
    from core.db import engine
    from core.config_store import config_store
    assert "gmail-business-tests-" in str(engine.url)
    assert main.ROOT == Path(__file__).resolve().parents[1]
    with TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        health = client.get("/healthz")
        assert health.json() == {"ok": True, "project": "gmail-business-manager"}
        assert health.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        config_store.set("auth_password_hash", "")
        blocked = client.get("/api/gmail/sources")
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "admin_setup_required"
        assert client.post("/api/auth/setup", json={"password": "standalone-test-password"}).status_code == 200
        assert client.get("/api/gmail/sources").json() == {"items": []}
        assert client.get("/api/gmail/aliases").json() == {"items": []}
        assert client.get("/api/workspace/summary").json()["ordinary_total"] == 0
        assert client.get("/api/gpt-plans/accounts").status_code == 200
        for retired in (
            "/api/adobe/accounts", "/api/claude/accounts", "/api/devin/accounts",
            "/api/nv-automation/settings", "/api/team-workflow/status",
            "/api/platforms",
        ):
            assert client.get(retired).status_code == 404
        assert client.get("/api/nonexistent").status_code == 404
        assert config_store.get("business_invite_default_mail_provider") == "gmail"
        assert config_store.get("business_invite_prolite_mail_provider") == "gmail"


def test_parent_environment_is_not_imported_as_configuration(monkeypatch):
    from core.config_store import _runtime_env_values
    monkeypatch.setenv("DUJIAO_API_SECRET", "parent-secret-never-use")
    monkeypatch.setenv("GBM_CONFIG_DEFAULT_PROXY", "http://127.0.0.1:7890")
    values = _runtime_env_values()
    assert "DUJIAO_API_SECRET" not in values
    assert values["DEFAULT_PROXY"] == "http://127.0.0.1:7890"


def test_new_project_does_not_link_old_engine():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "core").is_symlink()
    assert not (root / "services").is_symlink()
    assert not (root / "frontend/src").is_symlink()
    for retired in (
        "api/adobe.py", "api/nv_automation.py", "services/dujiao_integration.py",
        "services/turnstile_solver", "frontend/src/pages/NvAutomation.tsx",
        "frontend/src/pages/AdobeAdminAccounts.tsx",
    ):
        assert not (root / retired).exists()
    main = (root / "main.py").read_text()
    assert '"127.0.0.1"' in main
    assert '"8011"' in main
