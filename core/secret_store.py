"""Encrypted application-secret storage backed by the normal config table."""
from __future__ import annotations

from core.config_store import config_store
from core.credential_crypto import decrypt_credential, encrypt_credential


def _identity(key: str) -> str:
    normalized = str(key or "").strip().casefold()
    if not normalized:
        raise ValueError("secret key must not be empty")
    return f"config:{normalized}"


def get_secret(key: str, default: str = "") -> str:
    value = str(config_store.get(key, "") or "")
    if not value:
        return default
    if value.startswith("aesgcm:v1:"):
        return decrypt_credential(_identity(key), "api_secret", value)
    # Existing installations stored provider keys as plain config values.
    # Migrate on first read and never return ciphertext to a provider.
    set_secret(key, value)
    return value


def set_secret(key: str, value: str) -> None:
    plaintext = str(value or "").strip()
    config_store.set(
        key,
        encrypt_credential(_identity(key), "api_secret", plaintext) if plaintext else "",
    )


def has_secret(key: str) -> bool:
    return bool(str(config_store.get(key, "") or ""))


__all__ = ["get_secret", "has_secret", "set_secret"]
