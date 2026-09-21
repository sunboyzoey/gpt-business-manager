"""Imported passwords can log in without weakening managed-MFA checks."""
from unittest.mock import Mock

import pytest
from sqlmodel import SQLModel, Session, create_engine

from core.db import GptPlanAccountModel
from platforms.chatgpt import gpt_pro_login as login
from services import chatgpt_security_store as security_store


def _security(monkeypatch, **overrides):
    status = {"has_password": True, "has_totp": False, "credentials_readable": True,
              "password_state": "imported_unverified", "mfa_state": "not_configured", **overrides}
    monkeypatch.setattr(security_store, "get_chatgpt_security_status", lambda _: status)
    secrets = Mock(return_value={"password": "synthetic-password", "totp_secret": ""})
    monkeypatch.setattr(security_store, "get_chatgpt_security_secrets", secrets)
    return secrets


def test_saved_password_without_mfa_uses_password_route(monkeypatch):
    _security(monkeypatch)
    expected = login.GptProLoginResult(ok=True, email="mother@example.com")
    password = Mock(return_value=expected)
    otp = Mock()
    monkeypatch.setattr(login, "_login_with_password_totp", password)
    monkeypatch.setattr(login, "_login_with_email_otp", otp)
    assert login.login_with_account_auth("mother@example.com", proxy="", keep_browser_open=False) is expected
    assert password.call_args.args == ("mother@example.com", "synthetic-password", "")
    assert password.call_args.kwargs["keep_browser_open"] is False
    otp.assert_not_called()


@pytest.mark.parametrize("mfa_state", ["pending", "enabled", "unmanaged"])
def test_known_mfa_with_missing_seed_never_uses_password_only_or_otp(monkeypatch, mfa_state):
    _security(monkeypatch, mfa_state=mfa_state)
    password, otp = Mock(), Mock()
    monkeypatch.setattr(login, "_login_with_password_totp", password)
    monkeypatch.setattr(login, "_login_with_email_otp", otp)
    result = login.login_with_account_auth("mother@example.com")
    assert not result.ok and result.stage == "security_credentials_incomplete"
    password.assert_not_called()
    otp.assert_not_called()


def test_unreadable_saved_password_fails_without_fallback(monkeypatch):
    secrets = _security(monkeypatch, credentials_readable=False)
    password, otp = Mock(), Mock()
    monkeypatch.setattr(login, "_login_with_password_totp", password)
    monkeypatch.setattr(login, "_login_with_email_otp", otp)
    result = login.login_with_account_auth("mother@example.com")
    assert not result.ok and result.stage == "security_credentials_unavailable"
    secrets.assert_not_called()
    password.assert_not_called()
    otp.assert_not_called()


def test_signup_retains_email_otp_flow_even_with_staged_password(monkeypatch):
    secrets = _security(monkeypatch)
    expected = login.GptProLoginResult(ok=False, email="new@example.com")
    otp, password = Mock(return_value=expected), Mock()
    monkeypatch.setattr(login, "_login_with_email_otp", otp)
    monkeypatch.setattr(login, "_login_with_password_totp", password)
    mailbox = object()
    assert login.login_with_account_auth("new@example.com", mailbox=mailbox, is_signup=True) is expected
    assert otp.call_args.kwargs["mailbox"] is mailbox
    assert otp.call_args.kwargs["is_signup"] is True
    secrets.assert_not_called()
    password.assert_not_called()


@pytest.mark.parametrize("primitive_totp_proof", [False, True])
def test_password_only_success_never_marks_mfa_enabled(monkeypatch, primitive_totp_proof):
    from platforms.chatgpt import account_security
    page = Mock()
    monkeypatch.setattr(login, "_create_browser", lambda **_: page)
    authenticate = Mock(return_value=(True, "", primitive_totp_proof))
    monkeypatch.setattr(account_security, "_reauthenticate_with_password", authenticate)
    monkeypatch.setattr(account_security, "_raise_for_auth_login_page_error", lambda _: None)
    monkeypatch.setattr(login, "_optional_gmail_login_code_provider", lambda *_, **__: None)
    monkeypatch.setattr(login, "_on_workspace_chooser", lambda _: False)
    monkeypatch.setattr(login, "_wait_for_chatgpt_home", lambda *_, **__: True)
    monkeypatch.setattr(login, "_verified_login_session", lambda *_, **__: ({
        "user": {"email": "mother@example.com", "id": "synthetic-user"},
        "account": {"id": "synthetic-account", "planType": "team"},
        "accessToken": "synthetic-session"}, ""))
    monkeypatch.setattr(login, "_collect_cookies", lambda _: {})
    monkeypatch.setattr(login.time, "sleep", lambda _: None)
    update = Mock()
    monkeypatch.setattr(security_store, "update_chatgpt_security_state", update)
    result = login._login_with_password_totp("mother@example.com", "synthetic-password", "", keep_browser_open=False)
    assert result.ok
    assert authenticate.call_args.args[3] == ""
    update.assert_called_once_with("mother@example.com", password_state="configured", last_error="")
    page.quit.assert_called_once()


def test_unexpected_challenge_stays_explicit_failure(monkeypatch):
    from platforms.chatgpt import account_security
    page = Mock()
    monkeypatch.setattr(login, "_create_browser", lambda **_: page)
    monkeypatch.setattr(login, "_optional_gmail_login_code_provider", lambda *_, **__: None)
    monkeypatch.setattr(account_security, "_reauthenticate_with_password",
                        lambda *_, **__: (False, "账号要求 Authenticator 验证，但未保存 2FA 密钥", False))
    update = Mock()
    monkeypatch.setattr(security_store, "update_chatgpt_security_state", update)
    result = login._login_with_password_totp("mother@example.com", "synthetic-password", "", keep_browser_open=False)
    assert not result.ok and result.stage == "password_login"
    assert "未保存 2FA 密钥" in result.error
    update.assert_not_called()
    page.quit.assert_called_once()


@pytest.mark.parametrize("is_signup", [False, True])
def test_plan_login_initializes_mailbox_only_for_signup(monkeypatch, tmp_path, is_signup):
    from api import gpt_plans as plans
    engine = create_engine(f"sqlite:///{tmp_path / 'login.db'}")
    SQLModel.metadata.create_all(engine, tables=[GptPlanAccountModel.__table__])
    monkeypatch.setattr(plans, "engine", engine)
    with Session(engine) as session:
        session.add(GptPlanAccountModel(email="mother@example.com", mail_provider="outlook"))
        session.commit()
    _security(monkeypatch)
    mailbox, mailbox_account = object(), object()
    build = Mock(return_value=(mailbox, mailbox_account))
    dispatch = Mock(return_value=login.GptProLoginResult(ok=False, email="mother@example.com", error="synthetic verification failure"))
    monkeypatch.setattr(login, "build_mailbox_for_account", build)
    monkeypatch.setattr(login, "login_with_email_otp", dispatch)
    result, public, _ = plans._execute_plan_login(1, plans.GptPlanLoginRequest(proxy=""), is_signup=is_signup)
    assert result.ok is False and public["ok"] is False
    assert dispatch.call_args.kwargs["is_signup"] is is_signup
    if is_signup:
        build.assert_called_once()
        assert dispatch.call_args.kwargs["mailbox"] is mailbox
    else:
        build.assert_not_called()
        assert dispatch.call_args.kwargs["mailbox"] is None
        assert dispatch.call_args.kwargs["mailbox_account"] is None
    engine.dispose()
