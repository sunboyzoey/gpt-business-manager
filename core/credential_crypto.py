"""Authenticated encryption for per-account ChatGPT credentials.

The database only receives versioned AES-256-GCM envelopes.  The encryption
key is loaded from ``APP_CREDENTIAL_ENCRYPTION_KEY`` (base64url or 64 hex
characters).  For a local installation without that environment variable, a
random key is created under ``APP_RUNTIME_DIR`` (or the source-tree ``data``
fallback) as ``chatgpt_security.key`` with mode 0600.

The key is intentionally independent from ``config_store``: configuration
values can be exported through the API, while this key must never be returned
by an application endpoint or stored beside the ciphertext in the database.
"""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import re
import secrets
import sqlite3
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENV_KEY_NAME = "APP_CREDENTIAL_ENCRYPTION_KEY"
ENV_KEY_FILE_NAME = "APP_CREDENTIAL_ENCRYPTION_KEY_FILE"
DEFAULT_KEY_FILE = (
    Path(__file__).resolve().parent.parent / "data" / "chatgpt_security.key"
)

_ENVELOPE_PREFIX = "aesgcm:v1:"
_AAD_PREFIX = "chatgpt-account-security:v1"
_ALLOWED_FIELDS = frozenset({"password", "totp_secret", "recovery_codes", "api_secret"})
_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class CredentialKeyError(RuntimeError):
    """Raised when the application encryption key cannot be loaded safely."""


class CredentialCryptoError(RuntimeError):
    """Raised when a credential envelope is malformed or cannot be decrypted."""


def normalize_credential_email(email: str) -> str:
    """Return the canonical email key shared by storage and AES-GCM AAD."""
    normalized = unicodedata.normalize("NFKC", str(email or "")).strip().casefold()
    if not normalized:
        raise ValueError("email must not be empty")
    if len(normalized) > 320:
        raise ValueError("email is too long")
    return normalized


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    encoded = str(value or "").strip()
    if not encoded:
        raise ValueError("empty base64 value")
    padding = "=" * ((-len(encoded)) % 4)
    return base64.b64decode(
        encoded + padding,
        altchars=b"-_",
        validate=True,
    )


def _decode_key_material(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        try:
            text_value = value.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise CredentialKeyError("credential encryption key has invalid encoding") from exc
    else:
        text_value = str(value or "").strip()

    try:
        if _HEX_KEY_RE.fullmatch(text_value):
            key = bytes.fromhex(text_value)
        else:
            key = _b64decode(text_value)
    except (ValueError, binascii.Error) as exc:
        raise CredentialKeyError(
            "credential encryption key must be 32-byte base64url or 64 hex characters"
        ) from exc
    if len(key) != 32:
        raise CredentialKeyError("credential encryption key must decode to exactly 32 bytes")
    return key


def _key_file_path() -> Path:
    override = str(os.getenv(ENV_KEY_FILE_NAME, "") or "").strip()
    if override:
        return Path(override).expanduser()
    runtime_dir = str(os.getenv("APP_RUNTIME_DIR", "") or "").strip()
    if runtime_dir:
        # Docker mounts APP_RUNTIME_DIR as durable storage.  Keeping the AES
        # key there prevents a container rebuild from making all saved TOTP
        # seeds permanently unreadable.
        return Path(runtime_dir).expanduser() / "chatgpt_security.key"
    return DEFAULT_KEY_FILE


def _sqlite_has_encrypted_rows() -> bool:
    """Detect a lost key before silently creating an incompatible new one."""
    database_url = str(os.getenv("DATABASE_URL", "sqlite:///account_manager.db") or "")
    if not database_url.startswith("sqlite:///"):
        # A non-SQLite deployment must provide an explicit durable key.
        return True
    db_path = Path(database_url.removeprefix("sqlite:///")).expanduser()
    if not db_path.is_absolute():
        db_path = Path.cwd() / db_path
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    connection = None
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        # Both stores use this installation key with independent authenticated
        # namespaces. Never create a replacement if either has saved secrets.
        for table_name, columns in (
            ("chatgpt_account_security", (
                "password_ciphertext", "totp_secret_ciphertext", "recovery_codes_ciphertext",
            )),
            ("gmail_sources", (
                "app_password_ciphertext", "login_password_ciphertext",
                "totp_secret_ciphertext", "verification_url_ciphertext",
            )),
        ):
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            if table:
                # Additive Gmail migrations may not have run yet. Inspect old
                # columns without overlooking newer, non-IMAP credentials.
                present = {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})")}
                stored_columns = [column for column in columns if column in present]
                if not stored_columns:
                    return True
                condition = " OR ".join(f"COALESCE({column}, '') <> ''" for column in stored_columns)
                if connection.execute(f"SELECT 1 FROM {table_name} WHERE {condition} LIMIT 1").fetchone():
                    return True
        return False
    except sqlite3.Error:
        # An unreadable existing database is not a safe situation in which to
        # invent a replacement key.
        return True
    finally:
        if connection is not None:
            connection.close()


def _read_key_file(path: Path) -> bytes:
    if path.is_symlink():
        raise CredentialKeyError("credential encryption key file must not be a symlink")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise CredentialKeyError("unable to read credential encryption key file") from exc
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise CredentialKeyError("unable to secure credential encryption key file") from exc
    return _decode_key_material(value)


def _create_key_file(path: Path) -> bytes:
    key = secrets.token_bytes(32)
    encoded = (_b64encode(key) + "\n").encode("ascii")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CredentialKeyError("unable to create credential key directory") from exc

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another worker may have won the first-start race.
        return _read_key_file(path)
    except OSError as exc:
        raise CredentialKeyError("unable to create credential encryption key file") from exc

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:
        # Do not expose key material in the error and do not leave a partial key
        # file that a later process could mistake for a valid key.
        try:
            path.unlink()
        except OSError:
            pass
        raise CredentialKeyError("unable to persist credential encryption key")
    return key


def load_credential_encryption_key() -> bytes:
    """Load the configured key or create the local 0600 fallback key."""
    configured = str(os.getenv(ENV_KEY_NAME, "") or "").strip()
    if configured:
        return _decode_key_material(configured)

    path = _key_file_path()
    if path.exists() or path.is_symlink():
        return _read_key_file(path)
    if _sqlite_has_encrypted_rows():
        raise CredentialKeyError(
            "credential encryption key is missing while encrypted rows exist"
        )
    return _create_key_file(path)


def _associated_data(email: str, field_name: str) -> bytes:
    normalized_email = normalize_credential_email(email)
    normalized_field = str(field_name or "").strip().lower()
    if normalized_field not in _ALLOWED_FIELDS:
        raise ValueError("unsupported credential field")
    return f"{_AAD_PREFIX}:{normalized_email}:{normalized_field}".encode("utf-8")


def encrypt_credential(email: str, field_name: str, plaintext: str) -> str:
    """Encrypt one credential using email and field name as authenticated data."""
    if not isinstance(plaintext, str):
        raise TypeError("credential plaintext must be a string")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(load_credential_encryption_key()).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        _associated_data(email, field_name),
    )
    return _ENVELOPE_PREFIX + _b64encode(nonce + ciphertext)


def decrypt_credential(email: str, field_name: str, envelope: str) -> str:
    """Decrypt one credential, failing closed on corruption or AAD mismatch."""
    value = str(envelope or "")
    if not value.startswith(_ENVELOPE_PREFIX):
        raise CredentialCryptoError("unsupported credential envelope")
    try:
        payload = _b64decode(value[len(_ENVELOPE_PREFIX):])
    except (ValueError, binascii.Error) as exc:
        raise CredentialCryptoError("malformed credential envelope") from exc
    if len(payload) < 12 + 16:
        raise CredentialCryptoError("malformed credential envelope")
    nonce, ciphertext = payload[:12], payload[12:]
    try:
        plaintext = AESGCM(load_credential_encryption_key()).decrypt(
            nonce,
            ciphertext,
            _associated_data(email, field_name),
        )
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise CredentialCryptoError("credential authentication failed") from exc


__all__ = [
    "CredentialCryptoError",
    "CredentialKeyError",
    "DEFAULT_KEY_FILE",
    "decrypt_credential",
    "encrypt_credential",
    "load_credential_encryption_key",
    "normalize_credential_email",
]
