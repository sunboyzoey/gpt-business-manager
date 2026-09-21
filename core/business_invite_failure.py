"""Conservative evidence for a parent-level remote invitation rejection.

This recognizes the existing per-email response contract, not undocumented
upstream error codes. Generic HTTP errors and target/account login problems
must not turn a short request backoff into a day-long mother cooldown.
"""

import re
from typing import Any, Iterable


BUSINESS_INVITE_REJECTION_COOLDOWN_SECONDS = 24 * 60 * 60

_AUTH_FAILURE = re.compile(
    r"\b(?:unauthori[sz]ed|unauthenticated|authentication|authenticate|login)\b"
    r"|\b(?:log|sign)\s+in\b"
    r"|\b(?:invalid|expired|missing)\s+(?:access\s+)?(?:token|session|credential)s?\b"
    r"|\b(?:token|session|credential)s?\s+(?:is\s+|has\s+)?(?:invalid|expired|missing)\b"
    r"|登录|登入|认证|凭证|令牌",
    re.IGNORECASE,
)
_TARGET_FAILURE = re.compile(
    r"\balready\b.{0,60}\b(?:member|invited|invitation)\b"
    r"|\binvitation\b.{0,40}\balready\b"
    r"|\b(?:invalid|malformed)\s+(?:e\s*mail|email)\b"
    r"|\b(?:email|e\s*mail)(?:\s+address)?\s+(?:is\s+)?(?:invalid|malformed|not\s+valid)\b"
    r"|邮箱.{0,20}(?:无效|不正确|格式)|(?:已|已经).{0,20}(?:成员|邀请)",
    re.IGNORECASE,
)


def _error_text(value: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(value, str):
        return value[:4096].replace("_", " ").replace("-", " ")
    if isinstance(value, dict):
        return " ".join(
            _error_text(value.get(key), depth + 1)
            for key in ("error", "message", "detail", "code", "type", "reason")
        )
    if isinstance(value, list):
        return " ".join(_error_text(item, depth + 1) for item in value[:100])
    return ""


def is_explicit_business_invite_rejection(
    status: int,
    payload: Any,
    attempted_emails: Iterable[str],
) -> bool:
    """Require an unambiguous attempted-target rejection in errored_emails.

    Matching success evidence wins over rejection evidence. Authentication,
    invalid-email and already-member/invited failures retain short backoff.
    A generic detail/error body, including HTTP 4xx, proves no such rejection.
    """
    if status == 401 or (status != 200 and not 400 <= status < 500):
        return False
    if not isinstance(payload, dict) or _AUTH_FAILURE.search(_error_text(payload)):
        return False
    attempted = {str(email or "").strip().lower() for email in attempted_emails}
    successes = payload.get("account_invites")
    if isinstance(successes, list):
        attempted -= {
            str(item.get("email_address") or item.get("email") or "").strip().lower()
            for item in successes if isinstance(item, dict)
        }
    errors = payload.get("errored_emails")
    entries: list[tuple[str, Any]] = []
    if isinstance(errors, dict):
        entries = [(str(email).strip().lower(), error) for email, error in errors.items()]
    elif isinstance(errors, list):
        for item in errors:
            if isinstance(item, dict):
                entries.append((
                    str(item.get("email_address") or item.get("email") or "").strip().lower(),
                    item,
                ))
            elif isinstance(item, str):
                entries.append((item.strip().lower(), ""))
    matching = [error for email, error in entries if email and email in attempted]
    if any(_AUTH_FAILURE.search(_error_text(error)) for error in matching):
        return False
    return any(not _TARGET_FAILURE.search(_error_text(error)) for error in matching)
