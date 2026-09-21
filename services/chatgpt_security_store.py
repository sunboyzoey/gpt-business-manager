"""Private persistence boundary for post-registration ChatGPT credentials.

The functions in this module never consult or update ``AccountModel.password``.
That column predates this store and has different meanings in different account
pools.  Callers must explicitly opt in to this store for the password confirmed
by the post-registration security flow.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import json
import re
import secrets
from typing import Any, Iterable

from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from core.credential_crypto import (
    CredentialCryptoError,
    CredentialKeyError,
    decrypt_credential,
    encrypt_credential,
    load_credential_encryption_key,
    normalize_credential_email,
)
from core.db import (
    ChatGptAccountSecurityModel,
    ChatGptSecurityOperationLeaseModel,
    engine,
)


_STATE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|totp(?:_secret)?|otp|mfa(?:_secret)?|"
    r"recovery(?:_code)?|secret|access_token|refresh_token|session_token)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+")
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
_SIX_DIGIT_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
_DEFAULT_SECURITY_LEASE_SECONDS = 15 * 60


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_chatgpt_security_store_ready() -> None:
    """Fail closed unless the independent AES-256 credential key is usable.

    Local installations may create the documented mode-0600 key file here.
    The key bytes intentionally never cross this service boundary or enter an
    API response.  Existing encrypted rows plus a missing key remain a hard
    failure in ``load_credential_encryption_key``.
    """
    key = load_credential_encryption_key()
    if not isinstance(key, bytes) or len(key) != 32:
        raise CredentialKeyError("credential encryption key is unavailable")
    del key


def _normalize_state(value: Any, *, default: str) -> str:
    state = str(value if value is not None else default).strip().lower()
    if not _STATE_RE.fullmatch(state):
        raise ValueError("invalid ChatGPT security state")
    return state


def _normalize_totp_secret(secret: str) -> str:
    normalized = re.sub(r"[\s-]+", "", str(secret or "")).upper().rstrip("=")
    if len(normalized) < 16:
        raise ValueError("TOTP secret is too short")
    padding = "=" * ((-len(normalized)) % 8)
    try:
        decoded = base64.b32decode(normalized + padding, casefold=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    if len(decoded) < 10:
        raise ValueError("TOTP secret is too short")
    return normalized


def _normalize_recovery_codes(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = re.split(r"[\r\n,]+", value)
    else:
        raw_items = [str(item or "") for item in value]
    result: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        code = str(item or "").strip()
        if not code or code in seen:
            continue
        if len(code) > 128:
            raise ValueError("recovery code is too long")
        seen.add(code)
        result.append(code)
    return result


def _decrypt_optional(email: str, field_name: str, ciphertext: str) -> str:
    if not str(ciphertext or ""):
        return ""
    return decrypt_credential(email, field_name, ciphertext)


def _known_secret_values(row: ChatGptAccountSecurityModel) -> tuple[str, ...]:
    values: list[str] = []
    encrypted_fields = (
        ("password", row.password_ciphertext),
        ("totp_secret", row.totp_secret_ciphertext),
        ("recovery_codes", row.recovery_codes_ciphertext),
    )
    for field_name, ciphertext in encrypted_fields:
        if not ciphertext:
            continue
        try:
            plaintext = decrypt_credential(row.email, field_name, ciphertext)
        except (CredentialCryptoError, CredentialKeyError):
            continue
        if plaintext:
            values.append(plaintext)
        if field_name == "recovery_codes":
            try:
                decoded = json.loads(plaintext)
            except (TypeError, ValueError):
                decoded = []
            if isinstance(decoded, list):
                values.extend(str(item) for item in decoded if str(item or ""))
    return tuple(dict.fromkeys(values))


def _sanitize_error(value: Any, known_secrets: Iterable[str] = ()) -> str:
    text = str(value or "")
    for secret in sorted(
        (str(item) for item in known_secrets if str(item or "")),
        key=len,
        reverse=True,
    ):
        text = text.replace(secret, "<redacted>")
    text = _BEARER_RE.sub("Bearer <redacted>", text)
    text = _JWT_RE.sub("<redacted-jwt>", text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>",
        text,
    )
    text = _SIX_DIGIT_CODE_RE.sub("<redacted-code>", text)
    return text[:500]


def _iso(value: datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _status(row: ChatGptAccountSecurityModel | None, email: str) -> dict[str, Any]:
    if row is None:
        return {
            "email": email,
            "has_password": False,
            "has_chatgpt_password": False,
            "has_totp": False,
            "has_chatgpt_totp": False,
            "has_recovery_codes": False,
            "credentials_readable": True,
            "password_state": "not_configured",
            "mfa_state": "not_configured",
            "last_error": "",
            "password_updated_at": "",
            "mfa_updated_at": "",
            "updated_at": "",
        }
    has_password = bool(str(row.password_ciphertext or ""))
    has_totp = bool(str(row.totp_secret_ciphertext or ""))
    credentials_readable = True
    try:
        for field_name, ciphertext in (
            ("password", row.password_ciphertext),
            ("totp_secret", row.totp_secret_ciphertext),
            ("recovery_codes", row.recovery_codes_ciphertext),
        ):
            if ciphertext:
                decrypt_credential(row.email, field_name, ciphertext)
    except (CredentialCryptoError, CredentialKeyError):
        credentials_readable = False
    return {
        "email": row.email,
        "has_password": has_password,
        "has_chatgpt_password": has_password,
        "has_totp": has_totp,
        "has_chatgpt_totp": has_totp,
        "has_recovery_codes": bool(str(row.recovery_codes_ciphertext or "")),
        "credentials_readable": credentials_readable,
        "password_state": str(row.password_state or "not_configured"),
        "mfa_state": str(row.mfa_state or "not_configured"),
        "last_error": str(row.last_error or ""),
        "password_updated_at": _iso(row.password_updated_at),
        "mfa_updated_at": _iso(row.mfa_updated_at),
        "updated_at": _iso(row.updated_at),
    }


def _mutate(email: str, apply) -> dict[str, Any]:
    """Upsert one normalized row, retrying a first-insert race once."""
    normalized_email = normalize_credential_email(email)
    for attempt in range(2):
        with Session(engine) as session:
            row = session.get(ChatGptAccountSecurityModel, normalized_email)
            if row is None:
                now = _utcnow()
                row = ChatGptAccountSecurityModel(
                    email=normalized_email,
                    created_at=now,
                    updated_at=now,
                )
            apply(row)
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                if attempt == 0:
                    continue
                raise
            session.refresh(row)
            return _status(row, normalized_email)
    raise RuntimeError("unable to persist ChatGPT security state")


def acquire_chatgpt_security_lease(
    email: str,
    *,
    ttl_seconds: int = _DEFAULT_SECURITY_LEASE_SECONDS,
) -> str | None:
    """Atomically claim one normalized email for a remote security workflow.

    An active row is never overwritten.  An expired row is replaced with a new
    opaque owner token in one conditional UPDATE; first acquisition uses the
    primary-key constraint as the compare-and-swap fence.
    """
    normalized_email = normalize_credential_email(email)
    try:
        ttl = max(1, int(ttl_seconds))
    except (TypeError, ValueError):
        ttl = _DEFAULT_SECURITY_LEASE_SECONDS
    now = _utcnow()
    expires_at = now + timedelta(seconds=ttl)
    owner_token = secrets.token_urlsafe(32)

    with Session(engine) as session:
        claimed = session.exec(
            update(ChatGptSecurityOperationLeaseModel)
            .where(ChatGptSecurityOperationLeaseModel.email == normalized_email)
            .where(ChatGptSecurityOperationLeaseModel.expires_at <= now)
            .values(
                owner_token=owner_token,
                expires_at=expires_at,
                updated_at=now,
            )
        )
        if int(getattr(claimed, "rowcount", 0) or 0) == 1:
            session.commit()
            return owner_token

        # The UPDATE above deliberately starts the write transaction before the
        # missing-row probe on SQLite.  Concurrent first claims therefore
        # serialize; other databases are fenced by the primary-key insert.
        existing = session.get(
            ChatGptSecurityOperationLeaseModel,
            normalized_email,
        )
        if existing is not None:
            session.rollback()
            return None
        session.add(
            ChatGptSecurityOperationLeaseModel(
                email=normalized_email,
                owner_token=owner_token,
                expires_at=expires_at,
                created_at=now,
                updated_at=now,
            )
        )
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            return None
        return owner_token


def renew_chatgpt_security_lease(
    email: str,
    owner_token: str,
    *,
    ttl_seconds: int = _DEFAULT_SECURITY_LEASE_SECONDS,
) -> bool:
    """Extend an unexpired lease only for its current fencing token."""
    normalized_email = normalize_credential_email(email)
    token = str(owner_token or "")
    if not token:
        return False
    try:
        ttl = max(1, int(ttl_seconds))
    except (TypeError, ValueError):
        ttl = _DEFAULT_SECURITY_LEASE_SECONDS
    now = _utcnow()
    with Session(engine) as session:
        renewed = session.exec(
            update(ChatGptSecurityOperationLeaseModel)
            .where(ChatGptSecurityOperationLeaseModel.email == normalized_email)
            .where(ChatGptSecurityOperationLeaseModel.owner_token == token)
            .where(ChatGptSecurityOperationLeaseModel.expires_at > now)
            .values(
                expires_at=now + timedelta(seconds=ttl),
                updated_at=now,
            )
        )
        session.commit()
        return int(getattr(renewed, "rowcount", 0) or 0) == 1


def release_chatgpt_security_lease(email: str, owner_token: str) -> bool:
    """Release only the exact live owner's row; stale tokens are harmless."""
    normalized_email = normalize_credential_email(email)
    token = str(owner_token or "")
    if not token:
        return False
    with Session(engine) as session:
        released = session.exec(
            delete(ChatGptSecurityOperationLeaseModel)
            .where(ChatGptSecurityOperationLeaseModel.email == normalized_email)
            .where(ChatGptSecurityOperationLeaseModel.owner_token == token)
        )
        session.commit()
        return int(getattr(released, "rowcount", 0) or 0) == 1


def stage_chatgpt_password(
    email: str,
    password: str,
    state: str = "pending",
) -> dict[str, Any]:
    """Encrypt a candidate password before the remote mutation is attempted."""
    if not isinstance(password, str) or not password:
        raise ValueError("ChatGPT password must not be empty")
    normalized_email = normalize_credential_email(email)
    ciphertext = encrypt_credential(normalized_email, "password", password)
    normalized_state = _normalize_state(state, default="pending")

    def apply(row: ChatGptAccountSecurityModel) -> None:
        now = _utcnow()
        row.password_ciphertext = ciphertext
        row.password_state = normalized_state
        row.password_updated_at = now
        row.updated_at = now
        row.last_error = ""

    return _mutate(normalized_email, apply)


def stage_chatgpt_totp(
    email: str,
    secret: str,
    state: str = "pending",
    recovery_codes: str | Iterable[str] | None = None,
) -> dict[str, Any]:
    """Encrypt the TOTP seed before submitting the enable-MFA confirmation."""
    normalized_email = normalize_credential_email(email)
    normalized_secret = _normalize_totp_secret(secret)
    secret_ciphertext = encrypt_credential(
        normalized_email,
        "totp_secret",
        normalized_secret,
    )
    codes = _normalize_recovery_codes(recovery_codes)
    recovery_ciphertext = (
        encrypt_credential(
            normalized_email,
            "recovery_codes",
            json.dumps(codes, ensure_ascii=False),
        )
        if codes
        else None
    )
    normalized_state = _normalize_state(state, default="pending")

    def apply(row: ChatGptAccountSecurityModel) -> None:
        now = _utcnow()
        row.totp_secret_ciphertext = secret_ciphertext
        # Recovery codes belong to one exact TOTP enrollment.  Starting a new
        # enrollment must never leave the previous seed's now-invalid codes
        # attached to the account.
        row.recovery_codes_ciphertext = recovery_ciphertext or ""
        row.mfa_state = normalized_state
        row.mfa_updated_at = now
        row.updated_at = now
        row.last_error = ""

    return _mutate(normalized_email, apply)


def stage_chatgpt_recovery_codes(
    email: str,
    recovery_codes: str | Iterable[str],
) -> dict[str, Any]:
    """Encrypt recovery codes obtained after MFA confirmation."""
    normalized_email = normalize_credential_email(email)
    codes = _normalize_recovery_codes(recovery_codes)
    if not codes:
        raise ValueError("recovery codes must not be empty")
    ciphertext = encrypt_credential(
        normalized_email,
        "recovery_codes",
        json.dumps(codes, ensure_ascii=False),
    )

    def apply(row: ChatGptAccountSecurityModel) -> None:
        now = _utcnow()
        row.recovery_codes_ciphertext = ciphertext
        row.mfa_updated_at = now
        row.updated_at = now
        row.last_error = ""

    return _mutate(normalized_email, apply)


def update_chatgpt_security_state(
    email: str,
    password_state: str | None = None,
    mfa_state: str | None = None,
    last_error: str = "",
) -> dict[str, Any]:
    """Update only public workflow state; raw secret values never leave here."""
    normalized_email = normalize_credential_email(email)
    normalized_password_state = (
        _normalize_state(password_state, default="not_configured")
        if password_state is not None
        else None
    )
    normalized_mfa_state = (
        _normalize_state(mfa_state, default="not_configured")
        if mfa_state is not None
        else None
    )

    def apply(row: ChatGptAccountSecurityModel) -> None:
        now = _utcnow()
        if normalized_password_state is not None:
            row.password_state = normalized_password_state
            row.password_updated_at = now
        if normalized_mfa_state is not None:
            row.mfa_state = normalized_mfa_state
            row.mfa_updated_at = now
        row.last_error = _sanitize_error(last_error, _known_secret_values(row))
        row.updated_at = now

    return _mutate(normalized_email, apply)


def get_chatgpt_security_secrets(email: str) -> dict[str, Any]:
    """Return decrypted material for trusted backend automation only."""
    normalized_email = normalize_credential_email(email)
    with Session(engine) as session:
        row = session.get(ChatGptAccountSecurityModel, normalized_email)
        if row is None:
            return {
                "email": normalized_email,
                "password": "",
                "totp_secret": "",
                "recovery_codes": [],
            }
        password = _decrypt_optional(
            row.email,
            "password",
            row.password_ciphertext,
        )
        totp_secret = _decrypt_optional(
            row.email,
            "totp_secret",
            row.totp_secret_ciphertext,
        )
        recovery_raw = _decrypt_optional(
            row.email,
            "recovery_codes",
            row.recovery_codes_ciphertext,
        )
    recovery_codes: list[str] = []
    if recovery_raw:
        try:
            decoded = json.loads(recovery_raw)
        except (TypeError, ValueError) as exc:
            raise CredentialCryptoError("invalid encrypted recovery-code payload") from exc
        if not isinstance(decoded, list) or not all(
            isinstance(item, str) for item in decoded
        ):
            raise CredentialCryptoError("invalid encrypted recovery-code payload")
        recovery_codes = decoded
    return {
        "email": normalized_email,
        "password": password,
        "totp_secret": totp_secret,
        "recovery_codes": recovery_codes,
    }


def get_chatgpt_security_password(email: str) -> str:
    """Return only the saved password for a trusted login caller.

    Keeping this accessor separate from ``get_chatgpt_security_secrets`` lets
    non-browser orchestration retrieve the password it needs without ever
    receiving (or unnecessarily decrypting) the TOTP seed and recovery codes.
    """
    normalized_email = normalize_credential_email(email)
    with Session(engine) as session:
        row = session.get(ChatGptAccountSecurityModel, normalized_email)
        if row is None:
            return ""
        return _decrypt_optional(
            row.email,
            "password",
            row.password_ciphertext,
        )


def get_chatgpt_security_status(email: str) -> dict[str, Any]:
    """Return a JSON-safe, credential-free status snapshot."""
    normalized_email = normalize_credential_email(email)
    with Session(engine) as session:
        row = session.get(ChatGptAccountSecurityModel, normalized_email)
        return _status(row, normalized_email)


def get_chatgpt_security_statuses(emails: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Return credential-free states for a page of accounts in one query."""
    normalized_emails: list[str] = []
    seen: set[str] = set()
    for email in emails:
        try:
            normalized = normalize_credential_email(email)
        except (TypeError, ValueError):
            continue
        if normalized not in seen:
            normalized_emails.append(normalized)
            seen.add(normalized)
    if not normalized_emails:
        return {}
    with Session(engine) as session:
        rows = session.exec(
            select(ChatGptAccountSecurityModel).where(
                ChatGptAccountSecurityModel.email.in_(normalized_emails)
            )
        ).all()
    by_email = {row.email: row for row in rows}
    return {
        email: _status(by_email.get(email), email)
        for email in normalized_emails
    }


def get_chatgpt_totp_protected_emails(emails: Iterable[str]) -> set[str]:
    """Return accounts that cannot use credential-free migration yet.

    Existing peer/file migration formats do not carry the encrypted security
    store (and the peer endpoint is intentionally unauthenticated).  Treat any
    saved TOTP material, or a durable pending/enabled/unmanaged MFA state, as
    protected.
    Only normalized email identifiers leave this helper; seeds and ciphertext
    remain inside the security-store boundary.
    """
    statuses = get_chatgpt_security_statuses(emails)
    return {
        email
        for email, status in statuses.items()
        if bool(status.get("has_totp"))
        or str(status.get("mfa_state") or "").strip().lower()
        in {"pending", "enabled", "unmanaged"}
    }


__all__ = [
    "acquire_chatgpt_security_lease",
    "ensure_chatgpt_security_store_ready",
    "get_chatgpt_security_password",
    "get_chatgpt_security_secrets",
    "get_chatgpt_security_status",
    "get_chatgpt_security_statuses",
    "get_chatgpt_totp_protected_emails",
    "release_chatgpt_security_lease",
    "renew_chatgpt_security_lease",
    "stage_chatgpt_password",
    "stage_chatgpt_recovery_codes",
    "stage_chatgpt_totp",
    "update_chatgpt_security_state",
]
