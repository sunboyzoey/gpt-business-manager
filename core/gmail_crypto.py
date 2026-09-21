"""Gmail source credentials, isolated from platform-account credential envelopes."""
from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.credential_crypto import (
    CredentialCryptoError,
    load_credential_encryption_key,
    normalize_credential_email,
)

_PREFIX = "gmail-source:aesgcm:v1:"
_FIELDS = frozenset({"app_password", "login_password", "totp_secret", "verification_url"})


def _aad(source_email: str, field_name: str) -> bytes:
    if field_name not in _FIELDS:
        raise ValueError("unsupported Gmail credential field")
    email = normalize_credential_email(source_email)
    return f"gmail-source-credentials:v1:{email}:{field_name}".encode("utf-8")


def encrypt_gmail_secret(source_email: str, field_name: str, plaintext: str) -> str:
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Gmail 凭据不能为空")
    aad = _aad(source_email, field_name)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(load_credential_encryption_key()).encrypt(
        nonce, plaintext.encode("utf-8"), aad,
    )
    return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_gmail_secret(source_email: str, field_name: str, ciphertext: str) -> str:
    if not isinstance(ciphertext, str) or not ciphertext.startswith(_PREFIX):
        raise CredentialCryptoError("Gmail 授权密文格式不支持")
    try:
        payload = base64.b64decode(ciphertext[len(_PREFIX):], altchars=b"-_", validate=True)
        if len(payload) < 28:
            raise ValueError("invalid envelope")
        return AESGCM(load_credential_encryption_key()).decrypt(
            payload[:12], payload[12:], _aad(source_email, field_name),
        ).decode("utf-8")
    except (ValueError, binascii.Error, InvalidTag, UnicodeDecodeError):
        raise CredentialCryptoError("Gmail 授权密文校验失败") from None


def encrypt_gmail_password(source_email: str, password: str) -> str:
    """Compatibility entry point for existing IMAP application credentials."""
    return encrypt_gmail_secret(source_email, "app_password", password)


def decrypt_gmail_password(source_email: str, ciphertext: str) -> str:
    return decrypt_gmail_secret(source_email, "app_password", ciphertext)
