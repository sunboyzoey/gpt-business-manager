"""Credential-free admission rules for interrupted ChatGPT security setup."""

from collections.abc import Mapping


def can_inspect_pending_totp(status: Mapping[str, object]) -> bool:
    """Allow checking an interrupted enrollment, without authorizing enrollment.

    The executor must still prove the exact account session and inspect remote
    MFA. Only an explicitly disabled remote authenticator permits enrollment;
    enabled, unknown, or challenged state must stop when no seed is stored.
    """
    return (
        status.get("credentials_readable") is True
        and status.get("password_state") == "configured"
        and status.get("has_password") is True
        and status.get("mfa_state") == "pending"
        and status.get("has_totp") is False
    )
