"""No-network checks for standalone Gmail inventory and invitation boundaries."""
import base64
from datetime import timedelta
import json

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from sqlmodel import SQLModel, Session, create_engine, select

from core.credential_crypto import decrypt_credential
from core.db import (AccountModel, ChatGptAccountSecurityModel,
    ChatGptSecurityOperationLeaseModel, GptPlanAccountModel, GptPlanAccountOperationLeaseModel,
    GptBusinessAccountModel)
from services import gmail_store as store, gmail_registration as registration, workspace_accounts as workspace


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'workspace.db'}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(store, "engine", engine)
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"w" * 32).decode())
    store.init_tables(engine)
    SQLModel.metadata.create_all(engine, tables=[model.__table__ for model in (
        AccountModel, ChatGptAccountSecurityModel, ChatGptSecurityOperationLeaseModel,
        GptPlanAccountModel, GptPlanAccountOperationLeaseModel, GptBusinessAccountModel)])
    with Session(engine) as session:
        session.add(store.GmailSource(email="owner@gmail.com", usability_status="usable", receive_verified=True,
                                      app_password_ciphertext=store._encrypt("owner@gmail.com", "abcdefghijklmnop")))
        session.commit()
    store.generate_aliases(1, count=3, prefix="child")
    yield engine
    engine.dispose()


def test_registered_import_encrypts_without_claiming_remote_identity(db):
    result = workspace.import_ordinary("owner+child1@gmail.com----demo-password----JBSWY3DPEHPK3PXP", "registered")
    assert result["created"] == 1
    assert result["items"][0]["registration_verification"] == "declared"
    assert "demo-password" not in json.dumps(result)
    with Session(db) as session:
        alias = session.get(store.GmailAlias, 1)
        plan = session.get(GptPlanAccountModel, alias.gpt_plan_account_id)
        security = session.get(ChatGptAccountSecurityModel, alias.email)
        assert alias.registration_status == "registered"
        assert alias.registration_stage == "imported_registered_unverified"
        assert alias.registered_at is None
        assert not plan.password and not plan.cookie_blob and not plan.chatgpt_user_id
        assert registration._has_registered_identity(None, plan) is False
        assert session.exec(select(AccountModel)).all() == []
        assert decrypt_credential(alias.email, "password", security.password_ciphertext) == "demo-password"
        assert decrypt_credential(alias.email, "totp_secret", security.totp_secret_ciphertext) == "JBSWY3DPEHPK3PXP"
        assert json.loads(plan.extra_json)["gmail_alias_id"] == alias.id
    with pytest.raises(store.GmailStoreError):
        registration.validate_registration_request(alias_ids=[1], count=1, include_retries=True)
    assert store.list_aliases()[2]["registration_verification"] == "declared"


def test_import_is_atomic_and_rejects_nonlocal_aliases(db):
    with pytest.raises(store.GmailStoreError):
        workspace.import_ordinary("owner+child1@gmail.com----candidate\nowner+unknown@gmail.com----candidate", "registered")
    with Session(db) as session:
        assert session.exec(select(GptPlanAccountModel)).all() == []
        assert session.exec(select(ChatGptAccountSecurityModel)).all() == []
    for email in ("plain@gmail.com", "someone@outlook.com", "other+child1@gmail.com"):
        with pytest.raises(store.GmailStoreError):
            workspace.import_ordinary(email, "unregistered")


def test_import_never_downgrades_registered_or_steals_work(db):
    workspace.import_ordinary("owner+child1@gmail.com", "registered")
    with pytest.raises(store.GmailStoreError):
        workspace.import_ordinary("owner+child1@gmail.com", "unregistered")
    with Session(db) as session:
        alias = session.get(store.GmailAlias, 2)
        alias.registration_lease_token = "active-worker"
        session.add(alias)
        session.commit()
    with pytest.raises(store.GmailStoreError) as error:
        workspace.import_ordinary("owner+child2@gmail.com", "registered")
    assert error.value.code == "alias_busy"


def test_unregistered_inventory_and_summary(db):
    result = workspace.import_ordinary("owner+child1@gmail.com", "unregistered")
    assert result["items"][0]["registration_status"] == "unregistered"
    assert registration.validate_registration_request(alias_ids=[1], count=1)["count"] == 1
    assert workspace.summary() == {"gmail_sources": 1, "ordinary_total": 3, "ordinary_registered": 0,
        "ordinary_unregistered": 3, "ordinary_pending": 0, "business_mothers": 0}


def test_gmail_bundle_import_creates_hidden_receiver_and_is_idempotent(db, monkeypatch):
    monkeypatch.setattr(store, "_check_app_password", lambda email, password, proxy: None)
    bundle = {
        "schema": "gmail-business-manager.ordinary-gmail.v1",
        "version": 1,
        "export_id": "export-1",
        "receiver": {"email": "portable@gmail.com", "app_password": "abcdefghijklmnop"},
        "children": [
            {"email": "portable+child1@gmail.com", "tag": "child1", "registration_status": "unregistered"},
            {"email": "portable+child2@gmail.com", "tag": "child2", "registration_status": "registered",
             "chatgpt_password": "child-password", "chatgpt_totp_secret": "JBSWY3DPEHPK3PXP"},
        ],
    }
    first = workspace.import_gmail_bundle(json.dumps(bundle))
    second = workspace.import_gmail_bundle(json.dumps(bundle))
    assert first["created"] == 2 and first["receiver"] == "portable@gmail.com"
    assert second["created"] == 0 and second["updated"] == 2
    with Session(db) as session:
        source = session.exec(select(store.GmailSource).where(store.GmailSource.email == "portable@gmail.com")).one()
        aliases = session.exec(select(store.GmailAlias).where(store.GmailAlias.source_id == source.id)).all()
        assert source.receive_verified is True and source.enabled is True
        assert len(aliases) == 2
        registered = next(alias for alias in aliases if alias.email.endswith("+child2@gmail.com"))
        security = session.get(ChatGptAccountSecurityModel, registered.email)
        assert registered.registration_stage == "imported_registered_unverified"
        assert decrypt_credential(registered.email, "password", security.password_ciphertext) == "child-password"
        plan = session.get(GptPlanAccountModel, registered.gpt_plan_account_id)
        assert json.loads(plan.extra_json)["gmail_bundle_export_id"] == "export-1"


def test_existing_login_timestamp_prevents_duplicate_registration_after_transient_error(db):
    workspace.import_ordinary("owner+child1@gmail.com", "registered")
    with Session(db) as session:
        plan = session.exec(select(GptPlanAccountModel)).one()
        plan.last_login_at, plan.last_login_error = store.utcnow(), "登录失败"
        session.add(plan)
        session.commit()
        assert registration._has_registered_identity(None, plan)
    assert store.list_aliases()[2]["registration_verification"] == "declared"
    with Session(db) as session:
        plan = session.exec(select(GptPlanAccountModel)).one()
        plan.last_login_error = ""
        plan.chatgpt_user_id = "verified-test-user"
        session.add(plan)
        session.commit()
    assert store.list_aliases()[2]["registration_verification"] == "verified"


def test_public_import_errors_do_not_echo_credentials(db):
    from api.workspace import router
    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)
    response = client.post("/api/workspace/ordinary/import", json={"data": "owner+child1@gmail.com----secret-password", "registration_status": "bad"})
    assert response.status_code == 422
    assert "secret-password" not in response.text
    response = client.post("/api/workspace/ordinary/import", json={"data": "owner+child1@gmail.com----secret-password", "registration_status": "registered"})
    assert response.status_code == 200
    assert "secret-password" not in response.text


def test_registration_rejects_other_providers_before_start(db, monkeypatch):
    from api.tasks import RegisterTaskRequest, _prepare_register_request
    for provider in ("outlook", "icloud", "cfworker"):
        with pytest.raises(HTTPException) as exc:
            _prepare_register_request(RegisterTaskRequest(platform="chatgpt", extra={"mail_provider": provider}))
        assert exc.value.status_code == 400
    monkeypatch.setattr("services.registration_proxy.resolve_registration_proxy",
                        lambda key: {"key": key})
    prepared = _prepare_register_request(RegisterTaskRequest(platform="chatgpt", proxy_key="manual:1", extra={"gmail_alias_ids": [1]}))
    assert prepared.extra["mail_provider"] == "gmail"


def test_invite_defaults_and_manual_inputs_are_gmail_only(db):
    from core.business_invite_mail_provider import resolve_candidate_mail_provider
    assert resolve_candidate_mail_provider("auto", "unknown") == "gmail"
    assert resolve_candidate_mail_provider("auto", "default", defaults={"default": "gmail", "prolite": "gmail"}) == "gmail"
    with pytest.raises(ValueError):
        resolve_candidate_mail_provider("outlook", "default")
    workspace.import_ordinary("owner+child1@gmail.com", "registered")
    with Session(db) as session:
        with pytest.raises(store.GmailStoreError):
            workspace.validate_invite_inputs(session, emails=["external@gmail.com"])
        with pytest.raises(store.GmailStoreError) as exc:
            workspace.validate_invite_inputs(session, emails=["owner+child1@gmail.com"])
        assert exc.value.code == "gmail_registration_required"


def test_mother_import_links_sources_without_fabricating_remote_state(db, monkeypatch):
    from api import workspace_mothers as mothers
    monkeypatch.setattr(mothers, "engine", db)
    result = mothers.import_mothers(mothers.MotherImport(data="mother@example.com----demo-password----JBSWY3DPEHPK3PXP"))
    assert result["imported"] == 1 and result["skipped"] == 0
    assert "demo-password" not in json.dumps(result)
    with Session(db) as session:
        plan = session.get(GptPlanAccountModel, result["items"][0]["account_id"])
        source = session.get(GptBusinessAccountModel, plan.source_account_id)
        security = session.get(ChatGptAccountSecurityModel, plan.email)
        assert plan.source_pool == "gpt_business" and plan.catalog_category == "member"
        assert source.email == plan.email == "mother@example.com"
        assert not plan.cookie_blob and not plan.chatgpt_account_id and not plan.last_login_at
        assert not source.cookie_blob
        assert not any("seat" in key or "workspace_id" == key for key in json.loads(source.extra_json))
        assert not plan.password and not source.password
        assert json.loads(plan.extra_json)["workspace_verification"] == "pending_login"
        assert security.password_state == "imported_unverified" and security.mfa_state == "imported_unverified"
        assert decrypt_credential(plan.email, "password", security.password_ciphertext) == "demo-password"
    duplicate = mothers.import_mothers(mothers.MotherImport(data="mother@example.com----replacement-password"))
    assert duplicate["skipped"] == 1 and duplicate["imported"] == 0
    with Session(db) as session:
        security = session.get(ChatGptAccountSecurityModel, "mother@example.com")
        assert decrypt_credential(security.email, "password", security.password_ciphertext) == "demo-password"


def test_business_mother_transfer_bundle_imports_provider_and_secrets(db, monkeypatch):
    from api import workspace_mothers as mothers
    monkeypatch.setattr(mothers, "engine", db)
    bundle = {
        "schema": "gmail-business-manager.business-mother.v1",
        "version": 1,
        "account": {
            "email": "portable@gmail.com",
            "chatgpt_password": "portable-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "mail_provider": "gmail",
            "client_id": "",
            "refresh_token": "",
        },
    }
    result = mothers.import_mothers(mothers.MotherImport(
        data=json.dumps(bundle),
        # The bundle is authoritative; a stale UI selector must not override it.
        mail_provider="outlook",
    ))
    with Session(db) as session:
        plan = session.get(GptPlanAccountModel, result["items"][0]["account_id"])
        security = session.get(ChatGptAccountSecurityModel, plan.email)
        assert plan.mail_provider == "gmail"
        assert json.loads(plan.extra_json)["workspace_verification"] == "pending_login"
        assert decrypt_credential(plan.email, "password", security.password_ciphertext) == "portable-password"
        assert decrypt_credential(plan.email, "totp_secret", security.totp_secret_ciphertext) == "JBSWY3DPEHPK3PXP"


def test_business_mother_transfer_bundle_rejects_unknown_schema(db, monkeypatch):
    from api import workspace_mothers as mothers
    monkeypatch.setattr(mothers, "engine", db)
    with pytest.raises(HTTPException) as exc:
        mothers.import_mothers(mothers.MotherImport(data=json.dumps({
            "schema": "unknown", "version": 1, "account": {},
        })))
    assert exc.value.status_code == 422


def test_confirmed_business_mother_exports_portable_bundle(db, monkeypatch):
    from api import auth, business_manager_transfer as transfer
    from services import chatgpt_security_store as security_store
    monkeypatch.setattr(transfer, "engine", db)
    monkeypatch.setattr(auth, "require_sensitive_credential_export_auth_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(security_store, "get_chatgpt_security_status", lambda email: {
        "password_state": "configured", "mfa_state": "enabled",
    })
    monkeypatch.setattr(security_store, "get_chatgpt_security_secrets", lambda email: {
        "password": "chatgpt-password", "totp_secret": "JBSWY3DPEHPK3PXP",
    })
    with Session(db) as session:
        source = GptBusinessAccountModel(email="export@gmail.com")
        session.add(source)
        session.flush()
        plan = GptPlanAccountModel(
            email=source.email, mail_provider="gmail", plan_type="business_master",
            catalog_category="member", source_pool="gpt_business", source_account_id=source.id,
        )
        session.add(plan)
        session.commit()
        session.refresh(plan)
        plan_id = plan.id
    request = Request({
        "type": "http", "method": "POST", "path": "/", "query_string": b"",
        "headers": [], "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "scheme": "http",
    })
    response = transfer.export_business_manager_mother(plan_id, request)
    payload = json.loads(response.body)
    assert payload["schema"] == transfer.SCHEMA
    assert payload["account"]["mail_provider"] == "gmail"
    assert payload["account"]["chatgpt_password"] == "chatgpt-password"
    assert response.headers["cache-control"].startswith("no-store")


def test_newly_upgraded_confirmed_business_account_exports_without_legacy_source(db, monkeypatch):
    from api import auth, business_manager_transfer as transfer
    from services import chatgpt_security_store as security_store
    monkeypatch.setattr(transfer, "engine", db)
    monkeypatch.setattr(auth, "require_sensitive_credential_export_auth_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(security_store, "get_chatgpt_security_status", lambda email: {
        "password_state": "configured", "mfa_state": "enabled",
    })
    monkeypatch.setattr(security_store, "get_chatgpt_security_secrets", lambda email: {
        "password": "chatgpt-password", "totp_secret": "JBSWY3DPEHPK3PXP",
    })
    with Session(db) as session:
        plan = GptPlanAccountModel(
            email="new-business@gmail.com", mail_provider="gmail", plan_type="business",
            catalog_category="member", source_pool="", plan_checked_at=store.utcnow(),
        )
        session.add(plan)
        session.commit()
        session.refresh(plan)
        plan_id = plan.id
    request = Request({
        "type": "http", "method": "POST", "path": "/", "query_string": b"",
        "headers": [], "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "scheme": "http",
    })
    payload = json.loads(transfer.export_business_manager_mother(plan_id, request).body)
    assert payload["account"]["email"] == "new-business@gmail.com"


def test_mother_role_conflict_rolls_back_entire_batch(db, monkeypatch):
    from api import workspace_mothers as mothers
    monkeypatch.setattr(mothers, "engine", db)
    workspace.import_ordinary("owner+child1@gmail.com", "registered")
    with pytest.raises(HTTPException) as exc:
        mothers.import_mothers(mothers.MotherImport(data="new-mother@example.com----candidate\nowner+child1@gmail.com----candidate"))
    assert exc.value.status_code == 409
    with Session(db) as session:
        assert session.exec(select(GptBusinessAccountModel)).all() == []
        assert session.get(ChatGptAccountSecurityModel, "new-mother@example.com") is None
        assert len(session.exec(select(GptPlanAccountModel)).all()) == 1


def test_mother_import_rejects_alias_even_without_plan_row(db, monkeypatch):
    from api import workspace_mothers as mothers
    monkeypatch.setattr(mothers, "engine", db)
    with pytest.raises(HTTPException) as exc:
        mothers.import_mothers(mothers.MotherImport(data="owner+child1@gmail.com----candidate", mail_provider="gmail"))
    assert exc.value.status_code == 409
    with Session(db) as session:
        assert session.exec(select(GptPlanAccountModel)).all() == []
        assert session.exec(select(GptBusinessAccountModel)).all() == []


def test_bootstrap_ignores_parent_runtime_and_credential_environment(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    import sys
    project = Path(__file__).resolve().parents[1]
    env = {**os.environ, "GBM_RUNTIME_DIR": str(tmp_path / "isolated"),
           "DATABASE_URL": "sqlite:///parent-do-not-use.db", "APP_RUNTIME_DIR": "/parent-do-not-use",
           "APP_CREDENTIAL_ENCRYPTION_KEY": "fake-parent-key", "APP_CREDENTIAL_ENCRYPTION_KEY_FILE": "/fake-parent-key",
           "APP_JWT_SECRET": "fake-parent-jwt"}
    for key in ("GBM_DATABASE_URL", "GBM_APP_CREDENTIAL_ENCRYPTION_KEY", "GBM_APP_CREDENTIAL_ENCRYPTION_KEY_FILE", "GBM_APP_JWT_SECRET"):
        env.pop(key, None)
    code = "import os,json; from bootstrap import configure; runtime=configure(); print(json.dumps({'runtime':str(runtime),'database':os.environ['DATABASE_URL'],'inherited':any(key in os.environ for key in ['APP_CREDENTIAL_ENCRYPTION_KEY','APP_CREDENTIAL_ENCRYPTION_KEY_FILE','APP_JWT_SECRET'])}))"
    result = subprocess.run([sys.executable, "-c", code], cwd=project, env=env, capture_output=True, text=True, timeout=10, check=True)
    state = json.loads(result.stdout)
    assert state["runtime"] == str(tmp_path / "isolated")
    assert state["database"] == "sqlite:///" + str(tmp_path / "isolated" / "workspace.db")
    assert state["inherited"] is False


def test_legacy_plan_import_and_update_cannot_bypass_alias_rules(db, monkeypatch):
    from api import gpt_plans
    monkeypatch.setattr(gpt_plans, "engine", db)
    for provider, data in (("outlook", "outside@example.com----candidate"),
                           ("gmail", "outside+child@gmail.com----candidate")):
        with pytest.raises(HTTPException) as exc:
            gpt_plans.batch_import(gpt_plans.GptPlanBatchImportRequest(data=data, mail_provider=provider))
        assert exc.value.status_code == 400
    result = workspace.import_ordinary("owner+child1@gmail.com", "unregistered")
    account_id = result["items"][0]["gpt_plan_account_id"]
    for body in (gpt_plans.GptPlanAccountUpdateRequest(mail_provider="outlook"),
                 gpt_plans.GptPlanAccountUpdateRequest(password="plaintext-candidate")):
        with pytest.raises(HTTPException) as exc:
            gpt_plans.update_account(account_id, body)
        assert exc.value.status_code == 400


def test_direct_business_invitation_rejects_manual_external_email_before_remote_read(db, monkeypatch):
    from api import gpt_business
    monkeypatch.setattr(gpt_business, "engine", db)
    remote_called = []
    monkeypatch.setattr(gpt_business, "_biz_at_team_or_400", lambda *_: remote_called.append(True))
    with pytest.raises(HTTPException) as exc:
        gpt_business._invite_member_biz_impl(1, gpt_business.BizInviteMemberRequest(emails=["external@example.com"]))
    assert exc.value.status_code == 400
    assert remote_called == []
