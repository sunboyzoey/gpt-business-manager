"""Shared, account-pool-neutral helpers for ChatGPT mailbox monitoring.

This module intentionally imports no GPT PRO, BUSINESS, or plan account
models.  A mailbox monitor may therefore keep using the same subject and
parsing rules after one of the legacy account-pool modules is removed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Optional


MAX_SEEN_IDS = 100
MAX_ALERTS_PER_ACCOUNT = 20
MAX_INBOX_PER_ACCOUNT = 100
MAX_FETCH_PER_ROUND = 15
MONITOR_INTERVAL_SECONDS = 300
# IMAP INTERNALDATE is commonly second-granular while the local successful
# scan watermark includes microseconds.  Re-reading this tiny window prevents
# a message delivered after the fetch started, but stamped in the same second,
# from falling just behind the next round's cutoff.  Stable provider identity
# remains the deduplication authority.
MAIL_WATERMARK_OVERLAP = timedelta(seconds=2)

DANGEROUS_SUBJECT_KEYWORDS = ("Access Deactivated", "访问权限已停用")
POLICY_WARNING_SUBJECT_KEYWORDS = (
    "Usage Policy Violation",
    "Deactivation Warning",
    "使用政策",
    "停用警告",
)
BELL_SUBJECT_KEYWORDS = DANGEROUS_SUBJECT_KEYWORDS

# Refund notices use a dedicated lifecycle state and never enter the ordinary
# unread inbox/alert channels.
REFUND_SUBJECT_PATTERNS = (
    "Your refund from OpenAI",
    "OpenAI OpCo, LLC refund",
)

REFUND_REJECT_RE = re.compile(
    r"订阅费用不予退款|订阅费用不可退款|订阅.{0,4}不予退款|无法批准.{0,8}退款|"
    r"不予退款|subscription.{0,20}non-refundable|payments are non-refundable|"
    r"unable to (issue|provide|approve).{0,24}refund",
    re.I,
)

_APPEAL_TEXT_KEYWORDS = (
    "申诉", "提出申诉", "提交申诉", "上诉", "复审", "重新审核", "填写此表单", "此表单", "表单",
    "appeal", "request a review", "request a re-review", "submit a request",
    "let us know", "contact us", "believe this", "believe that",
    "was a mistake", "in error", "dispute", "this form", "fill out",
)
_APPEAL_URL_KEYWORDS = (
    "appeal", "form", "review", "request", "dispute", "typeform", "survey",
    "help.openai.com/en/requests", "openai.com/form",
)
_APPEAL_EXCLUDES = (
    "unsubscribe", "退订", "/privacy", "隐私", "/terms", "条款", "mailto:",
    "twitter.com", "x.com/openai", "linkedin.com", "facebook.com",
    "instagram.com", "youtube.com", "help.openai.com/en/articles",
    "openai.com/policies", "openai.com/blog", "list-manage",
    "campaign-archive",
)
_HREF_RE = re.compile(
    r'<a\b[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.I | re.S,
)
_URL_RE = re.compile(r'https?://[^\s<>"\'\)\]]+')


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def aware_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def parse_message_time(value: Any) -> Optional[datetime]:
    """Parse the normalized mail time into an aware datetime."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            from email.utils import parsedate_to_datetime

            parsed = parsedate_to_datetime(text)
            if parsed is None:
                return None
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def safe_json_loads(text: Any, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(str(text))
    except Exception:
        return default


def make_mail_alert(message: dict[str, Any]) -> dict[str, Any]:
    """Store only safe message metadata; full bodies remain in the mailbox."""
    sent_at = str(message.get("time") or "")
    trusted_received_at = ""
    if message.get("received_time_trusted") is True:
        trusted_received_at = str(
            message.get("received_at") or sent_at
        ).strip()
    alert = {
        "id": str(message.get("id") or ""),
        "from": str(message.get("from") or ""),
        "subject": str(message.get("subject") or ""),
        "preview": str(message.get("preview") or "")[:300],
        # Sort/display by the server-observed delivery time when available;
        # preserve the sender Date separately for diagnostics.
        "time": trusted_received_at or sent_at,
        "sent_at": sent_at,
        "folder": str(message.get("folder") or ""),
        "is_html": bool(message.get("is_html")),
        "detected_at": utcnow().isoformat(),
    }
    if trusted_received_at:
        alert["received_at"] = trusted_received_at
        alert["received_time_trusted"] = True
        alert["received_at_source"] = str(
            message.get("received_at_source") or "provider_received_time"
        )
    identity_scheme = str(message.get("identity_scheme") or "").strip()
    if identity_scheme:
        alert["identity_scheme"] = identity_scheme
        try:
            alert["identity_version"] = int(
                message.get("identity_version") or 0
            )
        except (TypeError, ValueError):
            alert["identity_version"] = 0
    return alert


def is_refund_subject(subject: Any) -> bool:
    text = str(subject or "")
    return any(pattern in text for pattern in REFUND_SUBJECT_PATTERNS)


def extract_appeal_url(body: Any, is_html: bool = True) -> Optional[str]:
    """Extract a likely appeal URL without depending on a legacy pool API."""
    text = str(body or "")
    if not text:
        return None

    def excluded(url: str) -> bool:
        lowered = url.lower()
        return (
            not lowered.startswith("http")
            or any(value in lowered for value in _APPEAL_EXCLUDES)
        )

    candidates: list[tuple[int, str]] = []
    if is_html or "<a" in text.lower():
        for match in _HREF_RE.finditer(text):
            href = str(match.group(1) or "").strip()
            if excluded(href):
                continue
            anchor = re.sub(r"<[^>]+>", " ", match.group(2) or "")
            anchor = re.sub(r"\s+", " ", anchor).strip().lower()
            lowered_href = href.lower()
            score = 0
            if any(value in anchor for value in _APPEAL_TEXT_KEYWORDS):
                score += 10
            if any(value in lowered_href for value in _APPEAL_URL_KEYWORDS):
                score += 5
            if "openai.com" in lowered_href or "chatgpt.com" in lowered_href:
                score += 1
            if score:
                candidates.append((score, href))
        if candidates:
            return sorted(candidates, key=lambda value: value[0], reverse=True)[0][1]

    for match in _URL_RE.finditer(text):
        url = str(match.group(0) or "").rstrip('.,);]>"\'')
        if excluded(url):
            continue
        if any(value in url.lower() for value in _APPEAL_URL_KEYWORDS):
            return url
    return None
