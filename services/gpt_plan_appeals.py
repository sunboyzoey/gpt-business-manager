"""Durable, account-local appeal-link lookup; never submit or resume accounts.

Only ``appeal_url`` and this service's metadata key are persisted. Mailbox I/O
runs outside short transactions and never advances mailbox/lifecycle state.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from html import unescape
import json
import math
import re
import threading
import time
from urllib.parse import urlsplit
import uuid

from sqlalchemy import text
from sqlmodel import Session, select

from core.db import GptPlanAccountModel as Account, engine
from services.chatgpt_mail_common import DANGEROUS_SUBJECT_KEYWORDS, extract_appeal_url


LOOKUP_STATE_KEY = "appeal_link_lookup"
ERROR_RETRY_SECONDS = 30 * 60
NOT_FOUND_RETRY_SECONDS = 6 * 60 * 60
LOOKUP_LEASE_SECONDS = 30 * 60
MAX_ROUND_ACCOUNTS = 20
MAX_LOOKUP_WORKERS = 2
SCAN_PAGE_SIZE = 100
FETCH_LIMIT = 100
_round_lock = threading.Lock()
_account_locks_guard = threading.Lock()
_account_locks: dict[tuple[int, int], threading.Lock] = {}
_MESSAGES = {
    "running": "正在自动查找该账号申诉链接，请稍后刷新",
    "error": "读取该账号邮件失败，请检查邮箱配置后重试",
    "not_found": "近期停用邮件中未找到安全的申诉链接，将稍后自动重试",
    "identity_changed": "账号信息已变化，请刷新后重新查找申诉链接",
    "invalid_metadata": "账号附加信息格式异常，暂未查找申诉链接",
    "not_dead": "该账号当前无需自动查找申诉链接",
}


def safe_appeal_url(value) -> str:
    """Return a browser-safe HTTPS appeal URL or an empty string."""
    raw = str(value or "")
    if re.search(r"[\x00-\x1f\x7f\\]", raw):
        return ""
    raw = raw.strip()
    if not raw or len(raw) > 8192 or re.search(r"\s", raw):
        return ""
    try:
        parsed = urlsplit(raw)
        if (parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return ""
        parsed.port
    except ValueError:
        return ""
    return raw


def extract_appeal_link(messages) -> str:
    """Search every deactivation mail; truncated previews are not link proof."""
    for item in messages or []:
        if not isinstance(item, dict):
            continue
        subject = str(item.get("subject") or "").casefold()
        if not any(word.casefold() in subject for word in DANGEROUS_SUBJECT_KEYWORDS):
            continue
        extracted = extract_appeal_url(item.get("body"), bool(item.get("is_html")))
        url = safe_appeal_url(unescape(extracted or ""))
        if url:
            return url
    return ""


def _extra(account):
    try:
        value = json.loads(account.extra_json or "{}")
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _epoch(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return 0.0
    return float(value) if math.isfinite(value) and 0 < value < 253402300800 else 0.0


def _iso(value):
    stamp = _epoch(value)
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat() if stamp else ""


def _identity(account):
    created = getattr(account, "created_at", None)
    if created is not None:
        created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    return {"email": str(account.email or ""), "created_at": created.isoformat() if created else ""}


def _state(account, extra=None):
    extra = _extra(account) if extra is None else extra
    value = extra.get(LOOKUP_STATE_KEY) if isinstance(extra, dict) else None
    if not isinstance(value, dict) or value.get("identity") != _identity(account):
        return {}
    return value


def public_lookup_state(account, *, now=None):
    """Credential-free status, derived without writes or mailbox work."""
    now = time.time() if now is None else now
    extra = _extra(account)
    state = _state(account, extra)
    result = {"status": "pending", "last_checked_at": _iso(state.get("last_checked_at")),
              "next_retry_at": "", "error": ""}
    if safe_appeal_url(account.appeal_url):
        result["status"] = "ready"
    elif not bool(account.dangerous):
        result["status"] = "idle"
    elif extra is None:
        result.update(status="error", error=_MESSAGES["invalid_metadata"])
    elif state.get("lease_token") and _epoch(state.get("lease_until")) > now:
        result.update(status="running", next_retry_at=_iso(state.get("lease_until")))
    elif state.get("status") in {"error", "not_found"} and _epoch(state.get("next_retry_at")) > now:
        result.update(status=state["status"], next_retry_at=_iso(state.get("next_retry_at")),
                      error=_MESSAGES[state["status"]])
    return result


def _result(account, *, reason="", now=None):
    url = safe_appeal_url(account.appeal_url)
    return {"ok": bool(url), "account_id": int(account.id), "account": str(account.email or ""),
            "appeal_url": url, "appeal_link_lookup": public_lookup_state(account, now=now),
            **({"reason": reason, "error": _MESSAGES.get(reason, "")} if reason else {})}


@contextmanager
def _transaction(bind):
    with Session(bind) as session:
        if bind.dialect.name == "sqlite":
            session.exec(text("BEGIN IMMEDIATE"))
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def _locked_account(session, account_id):
    account = session.exec(select(Account).where(Account.id == account_id).with_for_update()).first()
    if account is None:
        raise KeyError(account_id)
    return account


def _save_state(session, account, extra, state):
    account.extra_json = json.dumps({**extra, LOOKUP_STATE_KEY: state}, ensure_ascii=False)
    account.updated_at = datetime.now(timezone.utc)
    session.add(account)


def _cached_messages(account):
    result = []
    for raw in (account.pending_alerts_json, account.pending_inbox_json):
        try:
            items = json.loads(raw or "[]")
        except (TypeError, ValueError):
            continue
        if isinstance(items, list):
            result.extend(item for item in items if isinstance(item, dict))
    return result


def _fetch_messages(snapshot):
    from api.gpt_plans import _fetch_recent_messages

    _method, messages = _fetch_recent_messages(snapshot, limit=FETCH_LIMIT)
    return messages


def lookup_appeal_link(account_id, *, manual=False, database_engine=None):
    """Share one per-account lease across explicit retries and automatic work."""
    if type(account_id) is not int or account_id <= 0:
        raise ValueError("套餐账号编号无效")
    bind = database_engine if database_engine is not None else engine
    with _account_locks_guard:
        lock = _account_locks.setdefault((id(bind), account_id), threading.Lock())
    if not lock.acquire(blocking=False):
        with Session(bind) as session:
            account = session.get(Account, account_id)
            if account is None:
                raise KeyError(account_id)
            return _result(account, reason="running" if not safe_appeal_url(account.appeal_url) else "")
    try:
        return _lookup_locked(account_id, bind, manual=manual)
    finally:
        lock.release()


def _lookup_locked(account_id, bind, *, manual):
    now = time.time()
    with _transaction(bind) as session:
        account = _locked_account(session, account_id)
        if safe_appeal_url(account.appeal_url):
            return _result(account)
        if not manual and not account.dangerous:
            return _result(account, reason="not_dead")
        extra = _extra(account)
        if extra is None:
            return _result(account, reason="invalid_metadata")
        state = _state(account, extra)
        if state.get("lease_token") and _epoch(state.get("lease_until")) > now:
            return _result(account, reason="running", now=now)
        if not manual and _epoch(state.get("next_retry_at")) > now:
            return _result(account, reason=state.get("status", "error"), now=now)
        identity = _identity(account)
        token = uuid.uuid4().hex
        attempts = state.get("attempts", 0)
        attempts = attempts if type(attempts) is int and 0 <= attempts < 1_000_000 else 0
        state = {"identity": identity, "status": "running", "attempts": attempts + 1,
                 "last_checked_at": _epoch(state.get("last_checked_at")), "next_retry_at": 0,
                 "lease_token": token, "lease_until": now + LOOKUP_LEASE_SECONDS}
        from api.gpt_plans import _account_mail_snapshot

        snapshot = _account_mail_snapshot(account)
        cached = _cached_messages(account)
        _save_state(session, account, extra, state)

    url = extract_appeal_link(cached)
    outcome = "ready" if url else "not_found"
    if not url:
        try:
            url = extract_appeal_link(_fetch_messages(snapshot))
            outcome = "ready" if url else "not_found"
        except Exception:
            outcome = "error"

    now = time.time()
    with _transaction(bind) as session:
        account = _locked_account(session, account_id)
        if _identity(account) != identity:
            return _result(account, reason="identity_changed")
        extra = _extra(account)
        if extra is None:
            return _result(account, reason="invalid_metadata")
        current_state = _state(account, extra)
        current_url = safe_appeal_url(account.appeal_url)
        if current_state.get("lease_token") != token:
            return _result(account, reason="" if current_url else "running")
        if current_url:
            outcome = "ready"
        elif not manual and not account.dangerous:
            outcome = "idle"
        elif url:
            account.appeal_url = url
        delay = ERROR_RETRY_SECONDS if outcome == "error" else NOT_FOUND_RETRY_SECONDS if outcome == "not_found" else 0
        finished = {"identity": identity, "status": outcome, "attempts": state["attempts"],
                    "last_checked_at": now, "next_retry_at": now + delay if delay else 0}
        _save_state(session, account, extra, finished)
        return _result(account, reason=outcome if outcome in {"error", "not_found"} else "", now=now)


def _due_accounts(bind):
    """Keyset pages bound memory; cooled/ready rows never consume fetch slots."""
    selected = []
    after_id = 0
    now = time.time()
    while len(selected) < MAX_ROUND_ACCOUNTS:
        with Session(bind) as session:
            rows = session.exec(select(Account.id, Account.email, Account.created_at,
                Account.dangerous, Account.appeal_url, Account.extra_json).where(
                Account.dangerous == True, Account.id > after_id).order_by(Account.id).limit(SCAN_PAGE_SIZE)).all()
        if not rows:
            break
        for row in rows:
            after_id = row.id
            if public_lookup_state(row, now=now)["status"] == "pending":
                selected.append(row.id)
                if len(selected) >= MAX_ROUND_ACCOUNTS:
                    break
    return selected


def run_backfill_round(*, database_engine=None):
    """Independently scan existing DEAD Plan rows, including disabled accounts."""
    summary = {"scanned": 0, "found": 0, "not_found": 0, "errors": 0, "skipped": 0}
    if not _round_lock.acquire(blocking=False):
        return {**summary, "already_running": True}
    try:
        bind = database_engine if database_engine is not None else engine
        identifiers = _due_accounts(bind)
        if not identifiers:
            return summary
        with ThreadPoolExecutor(max_workers=MAX_LOOKUP_WORKERS, thread_name_prefix="plan-appeal") as executor:
            futures = [executor.submit(lookup_appeal_link, account_id, database_engine=bind)
                       for account_id in identifiers]
            for future in as_completed(futures):
                summary["scanned"] += 1
                try:
                    result = future.result()
                except Exception:
                    summary["errors"] += 1
                    continue
                if result.get("ok"):
                    summary["found"] += 1
                elif result.get("reason") == "not_found":
                    summary["not_found"] += 1
                elif result.get("reason") == "error":
                    summary["errors"] += 1
                else:
                    summary["skipped"] += 1
        return summary
    finally:
        _round_lock.release()
