import sqlite3

import pytest

from core.credential_crypto import CredentialCryptoError, CredentialKeyError, decrypt_credential, encrypt_credential
from core.gmail_crypto import (
    decrypt_gmail_password, encrypt_gmail_password, decrypt_gmail_secret, encrypt_gmail_secret,
)


@pytest.fixture
def configured_key(monkeypatch):
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY", "01" * 32)


def test_gmail_encryption_is_random_and_bound_to_source(configured_key):
    password = "test-only-secret"
    first = encrypt_gmail_password("source@gmail.com", password)
    second = encrypt_gmail_password("source@gmail.com", password)
    assert first != second and password not in first
    assert decrypt_gmail_password(" SOURCE@gmail.com ", first) == password
    with pytest.raises(CredentialCryptoError):
        decrypt_gmail_password("another@gmail.com", first)


def test_gmail_envelope_cannot_be_used_as_platform_password(configured_key):
    gmail = encrypt_gmail_password("source@gmail.com", "test-only-secret")
    platform = encrypt_credential("source@gmail.com", "password", "platform-secret")
    with pytest.raises(CredentialCryptoError):
        decrypt_credential("source@gmail.com", "password", gmail)
    with pytest.raises(CredentialCryptoError):
        decrypt_gmail_password("source@gmail.com", platform)
    # Even substituting the envelope prefix cannot cross the AAD namespace.
    payload = platform.split(":", 2)[2]
    payload += "=" * (-len(payload) % 4)
    with pytest.raises(CredentialCryptoError):
        decrypt_gmail_password("source@gmail.com", "gmail-source:aesgcm:v1:" + payload)


def test_missing_key_is_not_replaced_when_only_gmail_ciphertext_exists(tmp_path, monkeypatch):
    database = tmp_path / "gmail.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE gmail_sources (app_password_ciphertext TEXT)")
        connection.execute("INSERT INTO gmail_sources VALUES (?)", ("saved-ciphertext",))
    key_path = tmp_path / "missing.key"
    monkeypatch.delenv("APP_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY_FILE", str(key_path))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(database))
    with pytest.raises(CredentialKeyError, match="missing while encrypted rows exist"):
        encrypt_gmail_password("source@gmail.com", "test-only-secret")
    assert not key_path.exists()


@pytest.mark.parametrize("envelope", ["plaintext", "gmail-source:aesgcm:v1:bad!", "gmail-source:aesgcm:v1:YQ=="])
def test_bad_envelope_has_safe_error(configured_key, envelope):
    with pytest.raises(CredentialCryptoError) as error:
        decrypt_gmail_password("source@gmail.com", envelope)
    assert envelope not in str(error.value)


@pytest.mark.parametrize("field", ["login_password", "totp_secret", "verification_url"])
def test_imported_credentials_are_separate_from_app_password(configured_key, field):
    plaintext = "fixture-sensitive-value"
    ciphertext = encrypt_gmail_secret("source@gmail.com", field, plaintext)
    assert plaintext not in ciphertext
    assert decrypt_gmail_secret("source@gmail.com", field, ciphertext) == plaintext
    with pytest.raises(CredentialCryptoError):
        decrypt_gmail_password("source@gmail.com", ciphertext)
    with pytest.raises(CredentialCryptoError):
        decrypt_gmail_secret("other@gmail.com", field, ciphertext)


@pytest.mark.parametrize("column", ["login_password_ciphertext", "totp_secret_ciphertext", "verification_url_ciphertext"])
def test_imported_only_credentials_also_protect_missing_key(tmp_path, monkeypatch, column):
    database = tmp_path / "gmail-import.db"
    with sqlite3.connect(database) as connection:
        connection.execute(f"CREATE TABLE gmail_sources (app_password_ciphertext TEXT, {column} TEXT)")
        connection.execute(f"INSERT INTO gmail_sources ({column}) VALUES (?)", ("saved-ciphertext",))
    key_path = tmp_path / "missing.key"
    monkeypatch.delenv("APP_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("APP_CREDENTIAL_ENCRYPTION_KEY_FILE", str(key_path))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(database))
    with pytest.raises(CredentialKeyError, match="missing while encrypted rows exist"):
        encrypt_gmail_secret("source@gmail.com", "login_password", "fixture-secret")
    assert not key_path.exists()
