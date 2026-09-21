import hashlib

from fastapi.testclient import TestClient


def _reset_auth():
    from sqlmodel import SQLModel
    from core.config_store import config_store
    from core.db import engine

    SQLModel.metadata.create_all(engine)

    for key in ("auth_password_hash", "auth_totp_secret", "auth_token_version"):
        config_store.set(key, "")


def test_password_setup_uses_argon2id_and_http_only_cookie():
    import main
    from core.config_store import config_store

    _reset_auth()
    try:
        with TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
            response = client.post("/api/auth/setup", json={"password": "correct horse battery staple"})
            assert response.status_code == 200
            assert config_store.get("auth_password_hash").startswith("$argon2id$")
            assert "gbm_session=" in response.headers["set-cookie"]
            assert "HttpOnly" in response.headers["set-cookie"]
            assert "SameSite=strict" in response.headers["set-cookie"]
            assert client.get("/api/auth/status").json()["authenticated"] is True
            assert client.get("/api/gmail/sources").status_code == 200
        with TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as anonymous:
            assert anonymous.get("/api/gmail/sources").status_code == 401
    finally:
        _reset_auth()


def test_uninitialized_installation_blocks_business_apis():
    import main

    _reset_auth()
    with TestClient(main.app) as client:
        assert client.get("/api/auth/status").status_code == 200
        response = client.get("/api/gmail/sources")
        assert response.status_code == 403
        assert response.json() == {
            "detail": "请先初始化管理员密码",
            "code": "admin_setup_required",
        }


def test_initial_admin_setup_rejects_remote_requests():
    import main

    _reset_auth()
    with TestClient(main.app, base_url="https://manager.example", client=("203.0.113.8", 50000)) as client:
        response = client.post("/api/auth/setup", json={"password": "remote-password"})
        assert response.status_code == 403
        assert "127.0.0.1" in response.json()["detail"]


def test_legacy_sha256_password_is_migrated_on_successful_login():
    import main
    from core.config_store import config_store

    _reset_auth()
    password = "old-but-valid-password"
    config_store.set("auth_password_hash", hashlib.sha256(password.encode()).hexdigest())
    try:
        with TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
            response = client.post("/api/auth/login", json={"password": password})
            assert response.status_code == 200
            assert config_store.get("auth_password_hash").startswith("$argon2id$")
    finally:
        _reset_auth()


def test_admin_totp_seed_is_encrypted_at_rest():
    import main
    from api.auth import _totp_at, generate_totp_secret
    from core.config_store import config_store

    _reset_auth()
    try:
        with TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
            assert client.post("/api/auth/setup", json={"password": "correct horse battery staple"}).status_code == 200
            secret = generate_totp_secret()
            code = _totp_at(secret, __import__("time").time_ns() // 1_000_000_000 // 30)
            response = client.post("/api/auth/2fa/enable", json={"secret": secret, "code": code})
            assert response.status_code == 200
            stored = config_store.get("auth_totp_secret")
            assert stored.startswith("aesgcm:v1:")
            assert secret not in stored
    finally:
        _reset_auth()
