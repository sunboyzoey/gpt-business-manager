"""Credential-free eligibility for one explicitly requested extra OAuth retry.

This never changes automatic OAuth failure evidence or grants permission itself.
The store binds and consumes the marker under its job CAS; the capability must
also reconcile saved credentials and recheck ownership under the account lease.
"""
from __future__ import annotations

import re
from typing import Any

from services.nv_oauth_retry_policy import (
    RECOVERABLE_CODES, recovery_evidence_valid, retry_problem,
    manual_provider_recovery_evidence_valid,
)
from services.chatgpt_oauth_failure import normalize_oauth_failure

# Legacy classifications retained for old stored-task fallbacks. New automatic
# eligibility is owned by nv_oauth_retry_policy, not by these historical names.
MANUAL_SMS_FAILURE_CODES = frozenset({"sms_rejected", "sms_number_http_502"})
# ``oauth_unknown`` is now handled by the normal bounded automatic retry
# path. Keep it out of the explicit SMS/manual-recovery catalogue so the
# manual button cannot claim ownership of an OAuth failure that is already
# eligible for automatic stage retry.
MANUAL_SMS_RECOVERY_CODES = frozenset(RECOVERABLE_CODES - {"oauth_unknown"})
_GRANT_KEYS = {"origin", "batch_id", "started_at", "execution_attempts"}


def _evidence_valid(context: Any) -> bool:
    return recovery_evidence_valid(context) or manual_provider_recovery_evidence_valid(context)


def legacy_unknown_recovery_evidence_valid(context: Any) -> bool:
    """Allow one explicit batch retry for a closed, unknown login-route failure.

    The browser has already terminated and reported no callback or exchange.
    This is deliberately manual-batch-only (the marker below is never minted
    by automatic scheduling) and does not claim the remote transaction was
    successful; the worker rechecks credentials and membership under lease.
    """
    if not isinstance(context, dict) or context.get("oauth_reconcile_only") is True:
        return False
    failure = normalize_oauth_failure(context.get("oauth_failure"))
    if not failure or failure["code"] != "oauth_unknown" or failure["terminal"] is not True:
        return False
    if failure["callback_received"] or failure["exchange_started"]:
        return False
    started = context.get("oauth_started_at")
    failed = context.get("oauth_failure_started_at")
    count = context.get("oauth_execution_attempts")
    return (isinstance(started, str) and started.strip() == started and bool(started)
            and failed == started and type(count) is int and count >= 1
            and context.get("oauth_attempted") is True
            and context.get("oauth_retry_ready") is False)


def legacy_unknown_manual_recovery_granted(context: Any) -> bool:
    """Validate the one-use marker minted by an explicit manual batch."""
    if not legacy_unknown_recovery_evidence_valid(context):
        return False
    marker = context.get("oauth_manual_recovery")
    return bool(
        isinstance(marker, dict)
        and set(marker) == _GRANT_KEYS
        and marker.get("origin") == "manual"
        and isinstance(marker.get("batch_id"), str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", marker["batch_id"])
        and marker["batch_id"] == context.get("retry_batch_id")
        and marker.get("started_at") == context.get("oauth_started_at")
        and type(marker.get("execution_attempts")) is int
        and marker["execution_attempts"] == context.get("oauth_execution_attempts")
    )


def manual_sms_recovery_problem(context: Any, *, max_executions: int,
                                phone_allowed: bool,
                                allow_extra_execution: bool = False) -> tuple[str, str] | None:
    """Inspect eligibility before a grant exists; only literal None permits it."""
    return retry_problem(context, max_executions=max_executions,
                         phone_allowed=phone_allowed, allow_extra_execution=allow_extra_execution,
                         allow_manual_provider_error=allow_extra_execution is True)


def manual_sms_recovery_granted(context: Any) -> bool:
    """Match an exact one-use marker to this still-unconsumed failed attempt."""
    if not _evidence_valid(context) or context.get("oauth_recovery_requested") is not True:
        return False
    marker = context.get("oauth_manual_recovery")
    if not isinstance(marker, dict) or set(marker) != _GRANT_KEYS:
        return False
    batch_id = marker.get("batch_id")
    return bool(
        marker.get("origin") == "manual"
        and isinstance(batch_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", batch_id)
        and batch_id == context.get("retry_batch_id")
        and isinstance(marker.get("started_at"), str)
        and marker["started_at"] == context.get("oauth_started_at")
        and type(marker.get("execution_attempts")) is int
        and marker["execution_attempts"] == context["oauth_execution_attempts"]
    )
