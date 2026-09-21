"""Authoritative mailbox monitor for GPT 套餐管理 accounts.

Every enabled member/refunded row is read and mutated exclusively through
``GptPlanAccountModel``.  ``source_pool`` is migration provenance only; this
service never reads or writes a GPT PRO/BUSINESS source queue.  Consequently
the plan directory keeps mail alerts and refund transitions working after the
legacy GPT PRO page and its tables are retired.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from core.db import (
    GptPlanAccountModel,
    GptPlanAccountUpgradeModel,
    engine,
)
from services.chatgpt_mail_common import (
    BELL_SUBJECT_KEYWORDS,
    DANGEROUS_SUBJECT_KEYWORDS,
    MAIL_WATERMARK_OVERLAP,
    MAX_ALERTS_PER_ACCOUNT,
    MAX_FETCH_PER_ROUND,
    MAX_INBOX_PER_ACCOUNT,
    MAX_SEEN_IDS,
    POLICY_WARNING_SUBJECT_KEYWORDS,
    REFUND_REJECT_RE,
    aware_utc,
    is_refund_subject,
    make_mail_alert,
    parse_message_time,
    safe_json_loads,
    utcnow,
)
from services.gpt_plan_appeals import extract_appeal_link, safe_appeal_url


_monitor_lock = threading.Lock()
_priority_monitor_lock = threading.Lock()
_refunded_monitor_lock = threading.Lock()
_account_locks_guard = threading.Lock()
_account_locks: dict[int, threading.Lock] = {}
_monitor_write_lock = threading.Lock()
_WATERMARK_UNSET = object()

# Mailbox I/O is network-bound.  A small, bounded pool prevents hundreds of
# refunded rows from turning the advertised five-minute member sweep into a
# multi-hour serial job, while the per-account locks below still fence manual
# checks and duplicate scheduler lanes for the same row.
MAX_MONITOR_WORKERS = 10
MONITOR_LANE_PRIORITY = "priority"
MONITOR_LANE_REFUNDED = "refunded"
MONITOR_LANE_ALL = "all"
_MONITOR_LANES = frozenset({
    MONITOR_LANE_PRIORITY,
    MONITOR_LANE_REFUNDED,
    MONITOR_LANE_ALL,
})

# IMAP UIDs are scoped by both mailbox folder and UIDVALIDITY.  Version 3 is
# the first Plan-directory identity that includes all three values.  The
# marker lives in ``extra_json`` so an upgrade scan can establish a baseline
# exactly once instead of turning an old mailbox into hundreds of "new" rows.
MAIL_IMAP_IDENTITY_VERSION = 3
MAIL_IMAP_IDENTITY_VERSION_KEY = "mail_imap_identity_version"
MAIL_GRAPH_CUTOVER_CLEANUP_VERSION = 1
MAIL_GRAPH_CUTOVER_CLEANUP_VERSION_KEY = (
    "mail_graph_cutover_cleanup_version"
)
MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION = 1
MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION_KEY = (
    "mail_legacy_imap_cutover_cleanup_version"
)
MAIL_MONITOR_FETCH_LIMIT_KEY = "mail_monitor_fetch_limit"
_MAIL_MONITOR_FETCH_LIMIT_STEPS = (15, 100, 250, 500, 1000)

# A legacy pending item is removed only when the current IMAP snapshot proves
# that it is the same message, INTERNALDATE is no later than the previous
# successful watermark, and the old alert was created at least a day after the
# message actually reached the server.  This deliberately leaves ambiguous or
# genuinely recent unread rows untouched.
_MIGRATION_FALSE_POSITIVE_MIN_LAG = timedelta(days=1)

# The Plan directory was first attached to 188 Graph mailboxes during this one
# recorded 25-minute cutover (observed batch: 17:16:25Z..17:40:57Z).  That
# release queued 414 old Graph messages as unread.  Cleanup is deliberately a
# one-time, provider/ID/window/time-gated migration; no generic "old lag"
# deletion rule is applied to ordinary unread mail.
_KNOWN_PLAN_MAIL_CUTOVER_START = datetime(
    2026,
    8,
    29,
    17,
    tzinfo=timezone.utc,
)
_KNOWN_PLAN_MAIL_CUTOVER_END = datetime(
    2026,
    8,
    29,
    18,
    tzinfo=timezone.utc,
)
_KNOWN_LEGACY_IMAP_CUTOVER_START = datetime(
    2026,
    8,
    29,
    16,
    tzinfo=timezone.utc,
)
_KNOWN_LEGACY_IMAP_CUTOVER_END = datetime(
    2026,
    8,
    29,
    20,
    tzinfo=timezone.utc,
)


def _is_known_graph_cutover_false_positive(item: dict[str, Any]) -> bool:
    """Recognize only the recorded Graph first-attach false-positive batch."""
    item_id = str(item.get("id") or "")
    detected_at = parse_message_time(item.get("detected_at"))
    received_at = parse_message_time(
        item.get("received_at") or item.get("time")
    )
    return bool(
        item_id.startswith(("AQMk", "AAMk"))
        and detected_at is not None
        and received_at is not None
        and _KNOWN_PLAN_MAIL_CUTOVER_START
        <= detected_at
        < _KNOWN_PLAN_MAIL_CUTOVER_END
        and detected_at - received_at >= _MIGRATION_FALSE_POSITIVE_MIN_LAG
    )


def _is_known_legacy_imap_cutover_false_positive(
    item: dict[str, Any],
) -> bool:
    """Recognize only bare-UID rows from the recorded legacy IMAP batch."""
    item_id = str(item.get("id") or "")
    detected_at = parse_message_time(item.get("detected_at"))
    received_at = parse_message_time(
        item.get("received_at") or item.get("time")
    )
    return bool(
        item_id.isdigit()
        and detected_at is not None
        and received_at is not None
        and _KNOWN_LEGACY_IMAP_CUTOVER_START
        <= detected_at
        < _KNOWN_LEGACY_IMAP_CUTOVER_END
        and detected_at - received_at >= _MIGRATION_FALSE_POSITIVE_MIN_LAG
    )


def _retain_without_known_cutover_false_positives(
    rows: list[Any],
    predicate,
) -> tuple[list[Any], set[str]]:
    """Keep malformed/ambiguous rows and remove only predicate-proven IDs."""
    retained: list[Any] = []
    removed_ids: set[str] = set()
    for item in rows:
        if isinstance(item, dict) and predicate(item):
            removed_ids.add(str(item.get("id") or ""))
            continue
        retained.append(item)
    return retained, removed_ids


def cleanup_known_cutover_false_positives(
    *,
    database_engine=None,
) -> dict[str, Any]:
    """Apply the two proven 2026-08-29 queue repairs without mailbox I/O.

    This is deliberately a local-data migration rather than a monitor round:
    expired Graph/IMAP credentials must not leave the known first-attach
    backlog visible forever.  The same narrow predicates used by normal
    reconciliation are applied to both queue columns, and a durable per-account
    marker makes the operation idempotent.  Malformed queue/metadata JSON is
    preserved and skipped instead of being replaced or partially migrated.
    """
    bind = database_engine or engine
    summary: dict[str, Any] = {
        "accounts_examined": 0,
        "accounts_migrated": 0,
        "pending_inbox_removed": 0,
        "pending_alerts_removed": 0,
        "unique_message_ids_removed": 0,
        "malformed_accounts_skipped": 0,
    }
    all_removed_ids: set[tuple[int, str]] = set()

    with Session(bind) as session:
        accounts = session.exec(select(GptPlanAccountModel)).all()
        for account in accounts:
            provider = str(
                getattr(account, "mail_access_type", "") or ""
            ).strip().lower()
            if provider not in {"graph", "imap_pop"}:
                continue

            account_extra = safe_json_loads(
                getattr(account, "extra_json", ""),
                None,
            )
            pending = safe_json_loads(
                getattr(account, "pending_alerts_json", ""),
                None,
            )
            inbox = safe_json_loads(
                getattr(account, "pending_inbox_json", ""),
                None,
            )
            if (
                not isinstance(account_extra, dict)
                or not isinstance(pending, list)
                or not isinstance(inbox, list)
            ):
                summary["malformed_accounts_skipped"] += 1
                continue

            if provider == "graph":
                marker_key = MAIL_GRAPH_CUTOVER_CLEANUP_VERSION_KEY
                marker_version = MAIL_GRAPH_CUTOVER_CLEANUP_VERSION
                predicate = _is_known_graph_cutover_false_positive
            else:
                marker_key = MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION_KEY
                marker_version = MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION
                predicate = _is_known_legacy_imap_cutover_false_positive
            try:
                current_version = int(account_extra.get(marker_key) or 0)
            except (TypeError, ValueError):
                current_version = 0
            if current_version >= marker_version:
                continue

            summary["accounts_examined"] += 1
            retained_pending, removed_pending = (
                _retain_without_known_cutover_false_positives(
                    pending,
                    predicate,
                )
            )
            retained_inbox, removed_inbox = (
                _retain_without_known_cutover_false_positives(
                    inbox,
                    predicate,
                )
            )
            account.pending_alerts_json = json.dumps(
                retained_pending,
                ensure_ascii=False,
            )
            account.pending_inbox_json = json.dumps(
                retained_inbox,
                ensure_ascii=False,
            )
            account_extra[marker_key] = marker_version
            account.extra_json = json.dumps(account_extra, ensure_ascii=False)
            account.updated_at = _utcnow()
            session.add(account)

            summary["accounts_migrated"] += 1
            summary["pending_alerts_removed"] += len(removed_pending)
            summary["pending_inbox_removed"] += len(removed_inbox)
            account_id = int(getattr(account, "id", 0) or 0)
            all_removed_ids.update(
                (account_id, message_id)
                for message_id in removed_pending | removed_inbox
            )

        session.commit()

    summary["unique_message_ids_removed"] = len(all_removed_ids)
    return summary

_MAIL_MONITOR_MUTATED_FIELDS = (
    "refund_status",
    "refund_detected_at",
    "catalog_category",
    "source_state",
    "refund_rejected_at",
    "dangerous",
    "dangerous_detected_at",
    "appeal_url",
    "policy_warning",
    "policy_warning_detected_at",
    "seen_mail_ids_json",
    "pending_alerts_json",
    "pending_inbox_json",
    "last_mail_check_at",
    "last_mail_check_error",
    "updated_at",
)


def _account_monitor_lock(account_id: int) -> threading.Lock:
    """Return the process-local lock for one authoritative Plan row.

    A scheduled all-account round may take several minutes.  It must not make
    the user-facing "check this account now" action silently report zero mail.
    The global lock therefore fences full rounds only; this per-account lock
    prevents two workers from fetching and overwriting the same mailbox row.
    """
    normalized_id = int(account_id)
    with _account_locks_guard:
        lock = _account_locks.get(normalized_id)
        if lock is None:
            lock = threading.Lock()
            _account_locks[normalized_id] = lock
        return lock


_REGULAR_PLAN_TYPES = frozenset({"", "free", "chatgptfreeplan"})


def is_managed_business_child(account: GptPlanAccountModel) -> bool:
    """Return whether this Plan row currently belongs to a BUSINESS mother."""
    return getattr(account, "business_parent_id", None) is not None


def is_business_child_mail_health_account(account: GptPlanAccountModel) -> bool:
    """Only an active BUSINESS child uses child mailbox-health semantics."""
    return is_managed_business_child(account)


def business_child_mail_monitor_enabled(account: GptPlanAccountModel) -> bool:
    """The child monitor defaults on and can be explicitly disabled per row."""
    if not is_business_child_mail_health_account(account):
        return False
    extra = safe_json_loads(getattr(account, "extra_json", ""), {})
    value = extra.get("business_child_monitor_enabled", True)
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def _utcnow():
    # Kept as a local seam for deterministic monitor tests.
    return utcnow()


class _FetchedMessages(list):
    """List-compatible fetch result carrying successful provider metadata."""

    def __init__(self, values, *, scan_metadata: dict[str, Any] | None = None):
        super().__init__(values or [])
        self.scan_metadata = (
            dict(scan_metadata) if isinstance(scan_metadata, dict) else {}
        )


def _fetch_recent(account: GptPlanAccountModel) -> list[dict[str, Any]]:
    # 取件原语已被套餐页的手动“邮箱”功能验证：
    # Outlook 优先 Graph，可回退 IMAP；iCloud 按别名从 QQ/iCloud 收件源读取。
    from api.gpt_plans import _account_mail_snapshot, _fetch_recent_messages

    extra = safe_json_loads(getattr(account, "extra_json", ""), {})
    if not isinstance(extra, dict):
        extra = {}
    try:
        requested_limit = int(extra.get(MAIL_MONITOR_FETCH_LIMIT_KEY) or 0)
    except (TypeError, ValueError):
        requested_limit = 0
    fetch_limit = next(
        (
            step
            for step in _MAIL_MONITOR_FETCH_LIMIT_STEPS
            if step >= max(requested_limit, MAX_FETCH_PER_ROUND)
        ),
        _MAIL_MONITOR_FETCH_LIMIT_STEPS[-1],
    )
    _method, messages, scan_metadata = _fetch_recent_messages(
        _account_mail_snapshot(account),
        # The common path stays at 15.  Only one account whose previous round
        # could not reach its watermark is widened on its next round.
        limit=fetch_limit,
        return_metadata=True,
    )
    return _FetchedMessages(messages, scan_metadata=scan_metadata)


def _process_account(
    account: GptPlanAccountModel,
    *,
    subscribed_at=None,
) -> dict[str, Any]:
    """Fetch and process one account; kept as a deterministic worker seam."""
    scan_started_at = _utcnow()
    messages = _fetch_recent(account)
    return _process_messages(
        account,
        messages,
        subscribed_at=subscribed_at,
        scan_started_at=scan_started_at,
        scan_metadata=getattr(messages, "scan_metadata", None),
        advance_successful_watermark=bool(
            getattr(messages, "scan_metadata", {}).get(
                "watermark_coverage_complete",
                True,
            )
        ),
    )


def _process_messages(
    account: GptPlanAccountModel,
    messages: list[dict[str, Any]],
    *,
    subscribed_at=None,
    scan_started_at=None,
    scan_metadata: dict[str, Any] | None = None,
    previous_successful_watermark=_WATERMARK_UNSET,
    advance_successful_watermark: bool = True,
) -> dict[str, Any]:
    current_persisted_watermark = aware_utc(
        getattr(account, "last_mail_check_at", None)
    )
    if previous_successful_watermark is _WATERMARK_UNSET:
        previous_check_at = current_persisted_watermark
    else:
        previous_check_at = aware_utc(previous_successful_watermark)
    incremental_cutoff = (
        previous_check_at - MAIL_WATERMARK_OVERLAP
        if previous_check_at is not None
        else None
    )
    successful_watermark = aware_utc(scan_started_at) or _utcnow()
    # A manual fetch may wait for an already-running scheduled check after its
    # network request completed.  Never move the successful watermark
    # backwards when that happens.
    if (
        current_persisted_watermark is not None
        and successful_watermark < current_persisted_watermark
    ):
        successful_watermark = current_persisted_watermark

    seen_ids = safe_json_loads(account.seen_mail_ids_json, [])
    if not isinstance(seen_ids, list):
        seen_ids = []
    seen_ids = [str(value) for value in seen_ids if value]
    seen_set = set(seen_ids)
    pending = safe_json_loads(account.pending_alerts_json, [])
    if not isinstance(pending, list):
        pending = []
    pending = [value for value in pending if isinstance(value, dict)]
    inbox = safe_json_loads(account.pending_inbox_json, [])
    if not isinstance(inbox, list):
        inbox = []
    inbox = [value for value in inbox if isinstance(value, dict)]
    fresh_ids = [str(msg.get("id") or "") for msg in messages if msg.get("id")]

    def _message_identities(message: dict[str, Any]) -> set[str]:
        identities = {
            str(message.get("id") or ""),
            str(message.get("legacy_id") or ""),
        }
        legacy_ids = message.get("legacy_ids")
        if isinstance(legacy_ids, (list, tuple, set)):
            identities.update(str(value or "") for value in legacy_ids)
        identities.discard("")
        return identities

    def _message_was_seen(message: dict[str, Any]) -> bool:
        return bool(_message_identities(message) & seen_set)

    def _trusted_received_time(message: dict[str, Any]):
        # ``Date`` is supplied by the sender and can be stale or forged.  Only
        # provider-normalized receivedDateTime / IMAP INTERNALDATE may advance
        # the unread queue.
        if message.get("received_time_trusted") is not True:
            return None
        return parse_message_time(
            message.get("received_at") or message.get("time")
        )

    def _lifecycle_message_time(message: dict[str, Any]):
        received_at = _trusted_received_time(message)
        if received_at is not None:
            return received_at
        # Compatibility for deterministic/internal callers created before the
        # fetch contract exposed the trust marker.  A provider row explicitly
        # marked untrusted must never use its sender Date to cross a paid-plan
        # subscription boundary.
        if "received_time_trusted" in message:
            return None
        return parse_message_time(message.get("time"))

    account_extra = safe_json_loads(getattr(account, "extra_json", ""), {})
    if not isinstance(account_extra, dict):
        account_extra = {}
    try:
        stored_imap_identity_version = int(
            account_extra.get(MAIL_IMAP_IDENTITY_VERSION_KEY) or 0
        )
    except (TypeError, ValueError):
        stored_imap_identity_version = 0
    def _uses_current_imap_identity(message: dict[str, Any]) -> bool:
        if str(message.get("identity_scheme") or "") != "imap_uidvalidity":
            return False
        try:
            return (
                int(message.get("identity_version") or 0)
                >= MAIL_IMAP_IDENTITY_VERSION
            )
        except (TypeError, ValueError):
            return False

    scan_metadata = scan_metadata if isinstance(scan_metadata, dict) else {}
    effective_watermark_advance = bool(
        advance_successful_watermark
        or (
            current_persisted_watermark is None
            and scan_metadata.get("full_mailbox_scope") is True
        )
    )
    if scan_metadata.get("full_mailbox_scope") is True:
        coverage_complete = bool(
            scan_metadata.get("watermark_coverage_complete")
        )
        try:
            current_fetch_limit = int(
                scan_metadata.get("requested_limit") or MAX_FETCH_PER_ROUND
            )
        except (TypeError, ValueError):
            current_fetch_limit = MAX_FETCH_PER_ROUND
        if current_persisted_watermark is None or coverage_complete:
            account_extra.pop(MAIL_MONITOR_FETCH_LIMIT_KEY, None)
        else:
            next_fetch_limit = next(
                (
                    step
                    for step in _MAIL_MONITOR_FETCH_LIMIT_STEPS
                    if step > current_fetch_limit
                ),
                _MAIL_MONITOR_FETCH_LIMIT_STEPS[-1],
            )
            account_extra[MAIL_MONITOR_FETCH_LIMIT_KEY] = next_fetch_limit
        account.extra_json = json.dumps(account_extra, ensure_ascii=False)
    try:
        metadata_imap_version = int(
            scan_metadata.get("identity_version") or 0
        )
    except (TypeError, ValueError):
        metadata_imap_version = 0
    has_current_imap_identity = bool(
        (
            str(scan_metadata.get("identity_scheme") or "")
            == "imap_uidvalidity"
            and metadata_imap_version >= MAIL_IMAP_IDENTITY_VERSION
            and scan_metadata.get("uidvalidity_verified") is True
        )
        or any(_uses_current_imap_identity(msg) for msg in messages)
    )
    identity_upgrade = bool(
        has_current_imap_identity
        and stored_imap_identity_version < MAIL_IMAP_IDENTITY_VERSION
    )
    if identity_upgrade:
        account_extra[MAIL_IMAP_IDENTITY_VERSION_KEY] = (
            MAIL_IMAP_IDENTITY_VERSION
        )
        account.extra_json = json.dumps(account_extra, ensure_ascii=False)

    subscription_time = aware_utc(
        subscribed_at
        if subscribed_at is not None
        else getattr(account, "subscribed_at", None)
    )
    business_child = is_business_child_mail_health_account(account)

    # Refund mail is a lifecycle signal, including during the first baseline
    # scan.  With a known subscription time, an unparseable/older mail date is
    # rejected so an old subscription cycle cannot move the row back again.
    valid_refund_messages: list[dict[str, Any]] = []
    if not business_child:
        for msg in messages:
            if not is_refund_subject(msg.get("subject")):
                continue
            message_time = _lifecycle_message_time(msg)
            if subscription_time is not None and (
                message_time is None or message_time <= subscription_time
            ):
                continue
            valid_refund_messages.append(msg)

    old_refund_status = str(getattr(account, "refund_status", "") or "")
    old_category = str(getattr(account, "catalog_category", "") or "")
    old_source_state = str(getattr(account, "source_state", "") or "")
    refund_detected = bool(valid_refund_messages)
    refund_transition = False
    refund_transition_detail: dict[str, Any] | None = None
    if refund_detected and old_refund_status != "refund_credited":
        # Reconcile all four local fields atomically in the caller's session.
        # Existing detection timestamps remain stable across subsequent scans.
        account.refund_status = "refunded_pending_credit"
        if getattr(account, "refund_detected_at", None) is None:
            account.refund_detected_at = _utcnow()
        account.catalog_category = "refunded"
        account.source_state = "refunded_pending_credit"
        refund_transition = (
            old_refund_status != "refunded_pending_credit"
            or old_category != "refunded"
            or old_source_state != "refunded_pending_credit"
        )
        if refund_transition:
            refund_transition_detail = {
                "from_refund_status": old_refund_status,
                "to_refund_status": "refunded_pending_credit",
                "from_catalog_category": old_category,
                "to_catalog_category": "refunded",
                "from_source_state": old_source_state,
                "to_source_state": "refunded_pending_credit",
            }

    # Support replies after the current subscription may signal that a refund
    # was rejected.  Old-cycle rejection timestamps are cleared first.  A
    # valid refund notice always wins and suppresses rejection detection.
    refund_rejected = False
    if not business_child and str(getattr(account, "refund_status", "") or "") not in {
        "refunded_pending_credit",
        "refund_credited",
    }:
        current_rejected = aware_utc(getattr(account, "refund_rejected_at", None))
        if (
            current_rejected is not None
            and subscription_time is not None
            and current_rejected <= subscription_time
        ):
            account.refund_rejected_at = None
            current_rejected = None
        newest_rejection = None
        if not valid_refund_messages:
            for msg in messages:
                sender = str(msg.get("from") or "").lower()
                from_support = (
                    "support@openai.com" in sender
                    or "support_at_openai_com" in sender
                )
                text = (
                    str(msg.get("subject") or "")
                    + "\n"
                    + str(msg.get("body") or msg.get("preview") or "")
                )
                if not from_support and REFUND_REJECT_RE.search(text) is None:
                    continue
                message_time = _lifecycle_message_time(msg)
                if subscription_time is not None and (
                    message_time is None or message_time <= subscription_time
                ):
                    continue
                candidate_time = message_time or _utcnow()
                if newest_rejection is None or candidate_time > newest_rejection:
                    newest_rejection = candidate_time
        if newest_rejection is not None and (
            current_rejected is None or newest_rejection > current_rejected
        ):
            account.refund_rejected_at = newest_rejection
            refund_rejected = True

    # 风险状态与 PRO monitor 一致：首次基线也检测历史封禁/告警邮件。
    if not bool(account.dangerous):
        for msg in messages:
            subject = str(msg.get("subject") or "").casefold()
            if any(keyword.casefold() in subject for keyword in DANGEROUS_SUBJECT_KEYWORDS):
                account.dangerous = True
                account.dangerous_detected_at = _utcnow()
                break
    # A recent deactivation notice may omit the form link while an older
    # notice contains it. Search all supplied complete bodies, not only the
    # first matching subject. Never replace an already saved safe link.
    if not safe_appeal_url(getattr(account, "appeal_url", "")):
        appeal_url = extract_appeal_link(messages)
        if appeal_url:
            account.appeal_url = appeal_url
    if not bool(account.policy_warning):
        for msg in messages:
            subject = str(msg.get("subject") or "")
            if any(keyword in subject for keyword in POLICY_WARNING_SUBJECT_KEYWORDS):
                account.policy_warning = True
                account.policy_warning_detected_at = _utcnow()
                break

    first_scan = previous_check_at is None
    baseline_only = first_scan or identity_upgrade

    # Clean only migration false positives that can be proved.  IMAP requires
    # an exact v2/bare alias -> v3 identity match plus INTERNALDATE.  Graph uses
    # a separate one-time migration restricted to the recorded 2026-08-29
    # first-attach batch; it is intentionally not a generic age-based rule.
    proven_legacy_received: dict[str, Any] = {}
    for msg in messages:
        received_at = _trusted_received_time(msg)
        if received_at is None:
            continue
        if str(msg.get("identity_scheme") or "") != "imap_uidvalidity":
            continue
        primary_id = str(msg.get("id") or "")
        for identity in _message_identities(msg):
            if identity and identity != primary_id:
                proven_legacy_received[identity] = received_at

    removed_migration_ids: set[str] = set()

    def _retain_proven_imap_pending(
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        retained: list[dict[str, Any]] = []
        for item in rows:
            item_id = str(item.get("id") or "")
            received_at = proven_legacy_received.get(item_id)
            detected_at = parse_message_time(item.get("detected_at"))
            proven_false_positive = bool(
                previous_check_at is not None
                and received_at is not None
                and detected_at is not None
                and received_at <= previous_check_at
                and detected_at - received_at
                >= _MIGRATION_FALSE_POSITIVE_MIN_LAG
            )
            if proven_false_positive:
                removed_migration_ids.add(item_id)
                continue
            retained.append(item)
        return retained

    if proven_legacy_received:
        pending = _retain_proven_imap_pending(pending)
        inbox = _retain_proven_imap_pending(inbox)

    try:
        graph_cleanup_version = int(
            account_extra.get(MAIL_GRAPH_CUTOVER_CLEANUP_VERSION_KEY) or 0
        )
    except (TypeError, ValueError):
        graph_cleanup_version = 0
    graph_cutover_cleanup = bool(
        str(getattr(account, "mail_access_type", "") or "").strip().lower()
        == "graph"
        and graph_cleanup_version < MAIL_GRAPH_CUTOVER_CLEANUP_VERSION
    )

    if graph_cutover_cleanup:
        pending, removed_pending = (
            _retain_without_known_cutover_false_positives(
                pending,
                _is_known_graph_cutover_false_positive,
            )
        )
        inbox, removed_inbox = (
            _retain_without_known_cutover_false_positives(
                inbox,
                _is_known_graph_cutover_false_positive,
            )
        )
        removed_migration_ids.update(removed_pending)
        removed_migration_ids.update(removed_inbox)
        account_extra[MAIL_GRAPH_CUTOVER_CLEANUP_VERSION_KEY] = (
            MAIL_GRAPH_CUTOVER_CLEANUP_VERSION
        )
        account.extra_json = json.dumps(account_extra, ensure_ascii=False)

    try:
        legacy_imap_cleanup_version = int(
            account_extra.get(
                MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION_KEY
            )
            or 0
        )
    except (TypeError, ValueError):
        legacy_imap_cleanup_version = 0
    legacy_imap_cutover_cleanup = bool(
        str(getattr(account, "mail_access_type", "") or "").strip().lower()
        == "imap_pop"
        and legacy_imap_cleanup_version
        < MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION
    )

    if legacy_imap_cutover_cleanup:
        pending, removed_pending = (
            _retain_without_known_cutover_false_positives(
                pending,
                _is_known_legacy_imap_cutover_false_positive,
            )
        )
        inbox, removed_inbox = (
            _retain_without_known_cutover_false_positives(
                inbox,
                _is_known_legacy_imap_cutover_false_positive,
            )
        )
        removed_migration_ids.update(removed_pending)
        removed_migration_ids.update(removed_inbox)
        account_extra[MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION_KEY] = (
            MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION
        )
        account.extra_json = json.dumps(account_extra, ensure_ascii=False)

    new_alerts: list[dict[str, Any]] = []
    new_inbox: list[dict[str, Any]] = []
    if not baseline_only:
        for msg in messages:
            message_id = str(msg.get("id") or "")
            if not message_id or _message_was_seen(msg):
                continue
            received_at = _trusted_received_time(msg)
            if (
                incremental_cutoff is None
                or received_at is None
                or received_at <= incremental_cutoff
            ):
                continue
            subject = str(msg.get("subject") or "")
            # Paid-plan refund notices use lifecycle fields.  A BUSINESS child
            # has no independent paid subscription, so keep the same subject
            # as ordinary inbox mail and never move the child to 已退款.
            if not business_child and is_refund_subject(subject):
                continue
            alert = make_mail_alert(msg)
            if any(keyword in subject for keyword in BELL_SUBJECT_KEYWORDS):
                new_alerts.append(alert)
            # 与 PRO 一样，封禁件同时存在铃铛和收件箱通道。
            new_inbox.append(alert)

    if new_alerts:
        existing = {str(item.get("id") or "") for item in pending}
        for alert in new_alerts:
            if alert.get("id") not in existing:
                pending.insert(0, alert)
                existing.add(str(alert.get("id") or ""))
        pending = pending[:MAX_ALERTS_PER_ACCOUNT]
    if new_inbox:
        existing = {str(item.get("id") or "") for item in inbox}
        for alert in new_inbox:
            if alert.get("id") not in existing:
                inbox.insert(0, alert)
                existing.add(str(alert.get("id") or ""))
        inbox = inbox[:MAX_INBOX_PER_ACCOUNT]

    retained_seen_ids = seen_ids
    if has_current_imap_identity:
        # The v3 scan used v2 folder+UID and bare UID only as compatibility
        # aliases.  Retaining either forever would make a later UIDVALIDITY
        # reset or a same-UID message in another folder look already seen.
        retained_seen_ids = [
            value
            for value in seen_ids
            if not str(value).strip().isdigit()
            and not (
                str(value).startswith("imap:")
                and str(value).count(":") == 2
            )
        ]
    account.seen_mail_ids_json = json.dumps(
        list(dict.fromkeys(fresh_ids + retained_seen_ids))[:MAX_SEEN_IDS],
        ensure_ascii=False,
    )
    account.pending_alerts_json = json.dumps(pending, ensure_ascii=False)
    account.pending_inbox_json = json.dumps(inbox, ensure_ascii=False)
    account.last_mail_check_at = (
        successful_watermark
        if effective_watermark_advance
        else current_persisted_watermark
    )
    account.last_mail_check_error = ""
    account.updated_at = _utcnow()
    return {
        "email": str(account.email or ""),
        "fetched": len(messages),
        "new_alerts": len(new_alerts),
        "new_inbox": len(new_inbox),
        "first_scan": first_scan,
        "identity_upgrade": identity_upgrade,
        "watermark_advanced": effective_watermark_advance,
        "historical_migration_false_positives_removed": len(
            removed_migration_ids
        ),
        "pending_total": len(pending),
        "inbox_total": len(inbox),
        "refund_detected": refund_detected,
        "refund_transition": refund_transition,
        "refund_transition_detail": refund_transition_detail,
        "refund_rejected": refund_rejected,
    }


def _is_monitored_account(account: GptPlanAccountModel) -> bool:
    """All enabled local member/refunded rows are authoritative."""
    if not bool(account.enabled):
        return False
    if is_business_child_mail_health_account(account):
        return business_child_mail_monitor_enabled(account)
    if bool(getattr(account, "is_pro", False)):
        return True
    category = str(getattr(account, "catalog_category", "") or "").strip().lower()
    if category == "refunded":
        return True
    plan_type = str(getattr(account, "plan_type", "") or "").strip().lower()
    return plan_type not in _REGULAR_PLAN_TYPES


def _monitor_lane_for_account(account: GptPlanAccountModel) -> str:
    """Classify one enabled authoritative row into a scheduler lane."""
    if not _is_monitored_account(account):
        return ""
    # An attached BUSINESS child has child health semantics even if an old
    # import accidentally left its catalogue category as refunded.
    if is_business_child_mail_health_account(account):
        return MONITOR_LANE_PRIORITY
    category = str(
        getattr(account, "catalog_category", "") or ""
    ).strip().lower()
    if category == "refunded":
        return MONITOR_LANE_REFUNDED
    return MONITOR_LANE_PRIORITY


def reconcile_fetched_messages(
    account_id: int,
    messages: list[dict[str, Any]],
    *,
    fetched_at=None,
    previous_successful_watermark=_WATERMARK_UNSET,
    scan_metadata: dict[str, Any] | None = None,
    advance_successful_watermark: bool = True,
    database_engine=None,
) -> dict[str, Any]:
    """Persist one manual mailbox fetch into the authoritative Plan row.

    The mailbox dialog and the scheduled monitor must share the same refund
    classifier.  Previously ``/fetch-mail`` merely displayed messages, so a
    visible refund notice did not update ``refund_status``,
    ``refund_detected_at``, ``catalog_category`` and ``source_state`` until a
    later scheduled round happened to fetch the same notice.  This helper
    reconciles those fields together in one local transaction and never reads
    a legacy GPT PRO/BUSINESS account table.
    """
    normalized_id = int(account_id)
    checked_at = aware_utc(fetched_at) or _utcnow()
    bind = database_engine or engine
    lock = _account_monitor_lock(normalized_id)
    # A manual fetch has already paid the network cost.  Wait for an in-flight
    # monitor of this exact row rather than discarding the fetched lifecycle
    # evidence.  Other accounts and the full-round lock do not block it.
    with lock:
        with Session(bind) as session:
            account = session.get(GptPlanAccountModel, normalized_id)
            if account is None:
                raise LookupError("套餐账号不存在")

            detail: dict[str, Any] = {
                "email": str(account.email or ""),
                "fetched": len(messages or []),
                "new_alerts": 0,
                "new_inbox": 0,
                "first_scan": False,
                "pending_total": 0,
                "inbox_total": 0,
                "refund_detected": False,
                "refund_transition": False,
                "refund_transition_detail": None,
                "refund_rejected": False,
            }
            # Disabled DEAD accounts do not resume ordinary lifecycle/mail
            # monitoring, but mail explicitly fetched by the user can still
            # supply their missing appeal link.
            if account.dangerous and not safe_appeal_url(account.appeal_url):
                found_appeal_url = extract_appeal_link(messages or [])
                if found_appeal_url:
                    account.appeal_url = found_appeal_url
            if _is_monitored_account(account):
                upgrade = session.get(
                    GptPlanAccountUpgradeModel,
                    normalized_id,
                )
                subscription_candidates = [
                    aware_utc(getattr(account, "subscribed_at", None)),
                    aware_utc(
                        getattr(upgrade, "plan_upgraded_at", None)
                        if upgrade is not None
                        else None
                    ),
                ]
                subscribed_at = max(
                    (
                        value
                        for value in subscription_candidates
                        if value is not None
                    ),
                    default=None,
                )
                detail = _process_messages(
                    account,
                    list(messages or []),
                    subscribed_at=subscribed_at,
                    scan_started_at=checked_at,
                    scan_metadata=scan_metadata,
                    previous_successful_watermark=(
                        previous_successful_watermark
                    ),
                    advance_successful_watermark=(
                        advance_successful_watermark
                    ),
                )

            account.last_used = checked_at
            account.last_mail_fetch_at = checked_at
            account.last_mail_error = ""
            account.updated_at = checked_at
            session.add(account)
            session.commit()
            session.refresh(account)

            detail.update({
                "plan_account_id": normalized_id,
                "refund_status": str(account.refund_status or ""),
                "refund_detected_at": (
                    account.refund_detected_at.isoformat()
                    if account.refund_detected_at is not None
                    else ""
                ),
                "account_type": (
                    "refunded"
                    if str(account.catalog_category or "").strip().lower()
                    == "refunded"
                    else (
                        "regular"
                        if str(account.plan_type or "").strip().lower()
                        in _REGULAR_PLAN_TYPES
                        else "member"
                    )
                ),
            })
            return detail


def _empty_monitor_summary(*, lane: str) -> dict[str, Any]:
    return {
        "started_at": _utcnow().isoformat(),
        "lane": lane,
        "max_workers": MAX_MONITOR_WORKERS,
        "scanned": 0,
        "success": 0,
        "failed": 0,
        "total_new_alerts": 0,
        "total_new_inbox": 0,
        "total_new_messages": 0,
        "refund_detected": False,
        "refund_transition": False,
        "refund_transitions": [],
        "details": [],
        "errors": [],
    }


def _monitor_round_lock(lane: str) -> threading.Lock:
    if lane == MONITOR_LANE_PRIORITY:
        return _priority_monitor_lock
    if lane == MONITOR_LANE_REFUNDED:
        return _refunded_monitor_lock
    return _monitor_lock


def _process_monitor_target(
    target_id: int,
    target_email: str,
    *,
    expected_lane: str,
    lock_already_acquired: bool = False,
) -> dict[str, Any]:
    """Fetch and commit one row under its own account lock and DB session."""
    account_lock = _account_monitor_lock(target_id)
    acquired = bool(lock_already_acquired)
    if not acquired:
        acquired = account_lock.acquire(blocking=False)
    if not acquired:
        return {
            "status": "skipped",
            "account_id": target_id,
            "email": target_email,
            "reason": "该账号的邮件检查正在执行",
        }
    try:
        try:
            with Session(engine) as session:
                account = session.get(GptPlanAccountModel, target_id)
                if account is None or not _is_monitored_account(account):
                    return {"status": "ignored", "account_id": target_id}
                current_lane = _monitor_lane_for_account(account)
                if (
                    expected_lane != MONITOR_LANE_ALL
                    and current_lane != expected_lane
                ):
                    return {"status": "ignored", "account_id": target_id}
                upgrade = session.get(GptPlanAccountUpgradeModel, target_id)
                subscription_candidates = [
                    aware_utc(getattr(account, "subscribed_at", None)),
                    aware_utc(
                        getattr(upgrade, "plan_upgraded_at", None)
                        if upgrade is not None
                        else None
                    ),
                ]
                subscribed_at = max(
                    (
                        value
                        for value in subscription_candidates
                        if value is not None
                    ),
                    default=None,
                )
                # Do not hold a database transaction open across mailbox I/O.
                # Ten network workers may run concurrently, while persistence
                # remains a tiny serialized SQLite write section.
                previous_dead = (bool(account.dangerous), account.dangerous_detected_at)
                session.expunge(account)
            detail = _process_account(account, subscribed_at=subscribed_at)
            with Session(engine) as session:
                fresh = session.get(GptPlanAccountModel, target_id)
                if fresh is None or not _is_monitored_account(fresh):
                    return {"status": "ignored", "account_id": target_id}
                if fresh.email != account.email or fresh.created_at != account.created_at:
                    return {"status": "ignored", "account_id": target_id}
                current_lane = _monitor_lane_for_account(fresh)
                if (
                    expected_lane != MONITOR_LANE_ALL
                    and current_lane != expected_lane
                ):
                    return {"status": "ignored", "account_id": target_id}
                for field_name in _MAIL_MONITOR_MUTATED_FIELDS:
                    if field_name in {"dangerous", "dangerous_detected_at"}:
                        # An unchanged detached mailbox snapshot is not a new
                        # health observation. NV may have marked this child
                        # dead (or a real login review cleared it) during I/O.
                        if (not account.dangerous
                                or (bool(account.dangerous), account.dangerous_detected_at) == previous_dead):
                            continue
                        if field_name == "dangerous_detected_at" and fresh.dangerous_detected_at is not None:
                            continue
                    if field_name == "appeal_url":
                        # Manual and automatic lookups can finish while this
                        # detached mailbox snapshot is in flight. Retain the
                        # newer committed link; an empty old snapshot must
                        # never clear it and force another manual lookup.
                        if not safe_appeal_url(fresh.appeal_url):
                            candidate = safe_appeal_url(account.appeal_url)
                            if candidate:
                                fresh.appeal_url = candidate
                        continue
                    setattr(fresh, field_name, getattr(account, field_name))
                # Persist only the mail identity marker instead of copying the
                # entire detached ``extra_json`` snapshot.  Device/business
                # operations may legitimately update unrelated keys while
                # mailbox network I/O is in flight.
                source_extra = safe_json_loads(account.extra_json, {})
                fresh_extra = safe_json_loads(fresh.extra_json, {})
                if not isinstance(source_extra, dict):
                    source_extra = {}
                if not isinstance(fresh_extra, dict):
                    fresh_extra = {}
                metadata_changed = False
                for metadata_key in (
                    MAIL_IMAP_IDENTITY_VERSION_KEY,
                    MAIL_GRAPH_CUTOVER_CLEANUP_VERSION_KEY,
                    MAIL_LEGACY_IMAP_CUTOVER_CLEANUP_VERSION_KEY,
                    MAIL_MONITOR_FETCH_LIMIT_KEY,
                ):
                    if metadata_key not in source_extra:
                        continue
                    fresh_extra[metadata_key] = source_extra[metadata_key]
                    metadata_changed = True
                if (
                    MAIL_MONITOR_FETCH_LIMIT_KEY not in source_extra
                    and MAIL_MONITOR_FETCH_LIMIT_KEY in fresh_extra
                ):
                    fresh_extra.pop(MAIL_MONITOR_FETCH_LIMIT_KEY, None)
                    metadata_changed = True
                if metadata_changed:
                    fresh.extra_json = json.dumps(
                        fresh_extra,
                        ensure_ascii=False,
                    )
                session.add(fresh)
                with _monitor_write_lock:
                    session.commit()
                return {
                    "status": "success",
                    "account_id": target_id,
                    "email": str(fresh.email or target_email),
                    "detail": detail,
                }
        except Exception as exc:
            with Session(engine) as session:
                account = session.get(GptPlanAccountModel, target_id)
                if account is None:
                    return {"status": "ignored", "account_id": target_id}
                redaction_values = (
                    str(account.password or ""),
                    str(account.client_id or ""),
                    str(account.refresh_token or ""),
                )
                from api.gpt_plans import _redact_text

                safe_error = _redact_text(exc, *redaction_values)[:300]
                session.rollback()
                try:
                    fresh = session.get(GptPlanAccountModel, target_id)
                    if fresh is not None:
                        # ``last_mail_check_at`` is the previous successful
                        # fetch watermark.  A network/parse failure must not
                        # advance it or a message arriving during the failed
                        # round could be skipped forever.
                        fresh.last_mail_check_error = safe_error
                        fresh.updated_at = _utcnow()
                        session.add(fresh)
                        with _monitor_write_lock:
                            session.commit()
                except Exception:
                    session.rollback()
                return {
                    "status": "error",
                    "account_id": target_id,
                    "email": str(account.email or target_email),
                    "error": safe_error,
                }
    finally:
        if not lock_already_acquired:
            account_lock.release()


def _merge_monitor_result(summary: dict[str, Any], result: dict[str, Any]) -> None:
    status = str(result.get("status") or "")
    if status == "skipped":
        summary.setdefault("skipped_accounts", []).append({
            "account_id": int(result.get("account_id") or 0),
            "email": str(result.get("email") or ""),
            "reason": str(result.get("reason") or ""),
        })
        return
    if status == "ignored":
        return
    summary["scanned"] += 1
    if status == "error":
        summary["failed"] += 1
        summary["errors"].append({
            "email": str(result.get("email") or ""),
            "error": str(result.get("error") or "")[:300],
        })
        return

    detail = result.get("detail")
    detail = detail if isinstance(detail, dict) else {}
    summary["success"] += 1
    summary["total_new_alerts"] += int(detail.get("new_alerts", 0))
    summary["total_new_inbox"] += int(detail.get("new_inbox", 0))
    summary["total_new_messages"] += int(detail.get("new_inbox", 0))
    summary["refund_detected"] = bool(
        summary["refund_detected"] or detail.get("refund_detected")
    )
    summary["refund_transition"] = bool(
        summary["refund_transition"] or detail.get("refund_transition")
    )
    if detail.get("refund_transition_detail"):
        summary["refund_transitions"].append({
            "account_id": int(result.get("account_id") or 0),
            "email": str(result.get("email") or ""),
            **detail["refund_transition_detail"],
        })
    summary["details"].append(detail)


def run_monitor_round(
    *,
    account_id: int | None = None,
    lane: str = MONITOR_LANE_ALL,
) -> dict[str, Any]:
    """Run one authoritative plan-directory mailbox round.

    Scheduled callers use separate priority/refunded lanes.  The default
    ``all`` lane is retained for maintenance commands and compatibility tests;
    an explicit single-account check ignores the lane and remains protected by
    exactly the same per-account lock as scheduled workers.
    """
    normalized_lane = str(lane or MONITOR_LANE_ALL).strip().lower()
    if normalized_lane not in _MONITOR_LANES:
        raise ValueError(f"unsupported mail monitor lane: {normalized_lane}")
    full_round = account_id is None
    summary = _empty_monitor_summary(lane=normalized_lane)
    started_at = time.time()

    round_lock: threading.Lock | None = None
    target_lock: threading.Lock | None = None
    target_lock_acquired = False
    if full_round:
        round_lock = _monitor_round_lock(normalized_lane)
        if not round_lock.acquire(blocking=False):
            summary.update({
                "skipped": True,
                "reason": "上一轮套餐邮件检查尚未结束",
                "duration_seconds": 0.0,
            })
            return summary
    else:
        normalized_lane = MONITOR_LANE_ALL
        summary["lane"] = "account"
        target_lock = _account_monitor_lock(int(account_id))
        target_lock_acquired = target_lock.acquire(blocking=False)
        if not target_lock_acquired:
            summary.update({
                "skipped": True,
                "reason": "该账号的邮件检查正在执行，请稍后重试",
                "duration_seconds": 0.0,
            })
            return summary

    try:
        with Session(engine) as session:
            query = select(GptPlanAccountModel)
            if account_id is not None:
                query = query.where(GptPlanAccountModel.id == int(account_id))
            else:
                query = query.where(GptPlanAccountModel.enabled == True)  # noqa: E712
            candidates = session.exec(query).all()
            targets = [
                (int(account.id or 0), str(account.email or ""))
                for account in candidates
                if account.id is not None
                and _is_monitored_account(account)
                and (
                    account_id is not None
                    or normalized_lane == MONITOR_LANE_ALL
                    or _monitor_lane_for_account(account) == normalized_lane
                )
            ]

        if not full_round:
            if targets:
                _merge_monitor_result(
                    summary,
                    _process_monitor_target(
                        targets[0][0],
                        targets[0][1],
                        expected_lane=MONITOR_LANE_ALL,
                        lock_already_acquired=True,
                    ),
                )
        elif targets:
            # Test/development ``sqlite://`` StaticPool databases expose one
            # physical in-memory connection; concurrent ORM sessions on that
            # same connection are not transaction-safe.  The production file
            # database still receives the full bounded network concurrency.
            in_memory_sqlite = bool(
                getattr(getattr(engine, "dialect", None), "name", "")
                == "sqlite"
                and getattr(getattr(engine, "url", None), "database", None)
                in {None, "", ":memory:"}
            )
            workers = 1 if in_memory_sqlite else min(
                MAX_MONITOR_WORKERS,
                len(targets),
            )
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix=f"gpt-plan-mail-{normalized_lane}",
            ) as executor:
                futures = {
                    executor.submit(
                        _process_monitor_target,
                        target_id,
                        target_email,
                        expected_lane=normalized_lane,
                    ): (target_id, target_email)
                    for target_id, target_email in targets
                }
                results = [future.result() for future in as_completed(futures)]
            # Stable output helps operators and tests without serializing the
            # network work itself.
            results.sort(key=lambda value: int(value.get("account_id") or 0))
            for result in results:
                _merge_monitor_result(summary, result)
    finally:
        if target_lock_acquired and target_lock is not None:
            target_lock.release()
        if round_lock is not None:
            round_lock.release()

    summary["duration_seconds"] = round(time.time() - started_at, 2)
    return summary


def run_priority_monitor_round() -> dict[str, Any]:
    """Five-minute member and active BUSINESS-child mailbox lane."""
    return run_monitor_round(lane=MONITOR_LANE_PRIORITY)


def run_refunded_monitor_round() -> dict[str, Any]:
    """Low-frequency refunded-account mailbox lane."""
    return run_monitor_round(lane=MONITOR_LANE_REFUNDED)
