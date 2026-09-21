"""NexusVault inventory publishing client.

This module is the only place where NexusVault's inventory API key or separate
read-session cookie is read and attached to an outbound request.  Callers get
credential-free, allow-listed results.  Raw remote responses are never returned
because rejection payloads may echo submitted OAuth material.

The pool endpoint performs a real external mutation.  Requests are therefore
sent exactly once: in particular, a timeout has an unknown outcome and must be
reconciled in NexusVault before an operator retries.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit
import base64
import json
import os
import re

from services import nv_http as requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.credential_crypto import CredentialKeyError, load_credential_encryption_key


DEFAULT_BASE_URL = "https://nvtokens.com"
INVENTORY_API_KEY_CONFIG = "gpt_plan_nexusvault_inventory_api_key"
SALES_SESSION_COOKIE_CONFIG = "gpt_plan_nexusvault_sales_session_cookie"
BASE_URL_CONFIG = "gpt_plan_nexusvault_base_url"
DEFAULT_WARRANTY_HOURS = 1
DEFAULT_WARRANTY_NAME = "质保首登（1小时）"

_MAX_RESPONSE_BYTES = 1_000_000
_KEY_ENVELOPE_PREFIX = "aesgcm:nexusvault:v1:"
_KEY_ENVELOPE_AAD = b"nexusvault-inventory-api-key:v1"
_COOKIE_ENVELOPE_PREFIX = "aesgcm:nexusvault-session:v1:"
_COOKIE_ENVELOPE_AAD = b"nexusvault-read-session-cookie:v1"
_MAX_COOKIE_LENGTH = 16_384
_SOLD_CARD_PAGE_LIMIT = 96
_SOLD_ORDER_PAGE_LIMIT = 50
_MAX_SOLD_PAGES = 200
_SAFE_SUMMARY_FIELDS = frozenset({
    "published",
    "imported",
    "accepted",
    "rejected",
    "import_rejected",
    "skipped",
    "duplicates",
    "quota_blocked",
    "price_cents",
})
class NexusVaultError(RuntimeError):
    """Base error safe to surface through a local API response."""


class NexusVaultConfigurationError(NexusVaultError):
    """The local NexusVault target is absent or unsafe."""


class NexusVaultRequestError(NexusVaultError):
    """The remote service could not be reached or returned an HTTP error."""


class NexusVaultRequestTimeout(NexusVaultRequestError):
    """A remote mutation timed out and may or may not have completed."""


class NexusVaultPublishRejected(NexusVaultError):
    """NexusVault answered conclusively but did not publish the card."""


class NexusVaultSessionExpired(NexusVaultRequestError):
    """The separately configured read-only web session is no longer valid."""


@dataclass(frozen=True)
class NexusVaultPublishResult:
    published: int
    summary: dict[str, int]
    status_code: int


@dataclass(frozen=True)
class NexusVaultSoldRecord:
    """Credential-free subset of one authoritative remote sale record."""

    email: str
    sold_at: datetime
    remote_order_id: str = ""
    remote_card_id: str = ""
    # Provenance is diagnostic metadata, not a change to the existing sale
    # identity/equality contract. In particular cards.id is NOT orders.card_id.
    source: str = field(default="", compare=False)
    inventory_card_id: str = field(default="", compare=False)
    explicit_card_id: str = field(default="", compare=False)
    team5x_warranty_until: datetime | None = None


@dataclass(frozen=True)
class NexusVaultInventoryRecord:
    """Only identity and lifecycle state, never the uploaded credential body."""

    email: str
    status: str
    remote_card_id: str = ""
    sold_at: datetime | None = None
    inventory_card_id: str = ""
    explicit_card_id: str = ""
    remote_order_id: str = ""
    # A successful, complete quota observation may distinguish ordinary TEAM
    # windows.  It is metadata only, never a replacement for sale identity.
    quota: dict[str, Any] | None = field(default=None, compare=False)
    team5x_warranty_until: datetime | None = None
    price_cents: int | None = None
    pool_price_cents: int | None = None
    health_status: str = ""
    archived: bool = False
    fallback_pool_only: bool | None = None
    # Only the observed workspace-specific Codex 402 inspection signature.
    # Callers must still bind the card, current membership and listing time;
    # this flag alone never authorizes an account-state change.
    workspace_deactivated: bool = False
    workspace_deactivated_at: datetime | None = None


@dataclass(frozen=True)
class NexusVaultCardIdentityLink:
    """Read-only, one-to-one proof linking NV's two card-ID namespaces.

    This is not an instruction to replace an existing local binding. Consumers
    must additionally verify the email, sale cycle and any previously bound IDs.
    """

    email: str
    sold_at: datetime
    inventory_card_id: str
    order_card_id: str
    remote_order_id: str


@dataclass(frozen=True)
class NexusVaultRefundRecord:
    """Allow-listed order refund evidence, not permission to leave a team.

    Incomplete/partial evidence remains observable but full_refund is false.
    The inventory alias requires the same complete three-source proof as sales.
    Callers must still bind the order, card and sale time to their local cycle.
    """

    email: str
    sold_at: datetime | None = None
    refunded_at: datetime | None = None
    remote_order_id: str = ""
    remote_card_id: str = ""
    amount_cents: int | None = None
    refund_amount_cents: int | None = None
    supplier_amount_cents: int | None = None
    order_status: str = ""
    settlement_status: str = ""
    full_refund: bool = False
    inventory_card_id: str = ""
    identity_valid: bool = False


@dataclass(frozen=True)
class NexusVaultSalesSnapshot:
    """Complete paginated snapshot used for one all-or-nothing reconciliation."""

    sold_records: tuple[NexusVaultSoldRecord, ...]
    order_count: int
    sold_card_count: int
    pages_fetched: int
    inventory_records: tuple[NexusVaultInventoryRecord, ...] = ()
    inventory_complete: bool = False
    unconfirmed_sold_emails: tuple[str, ...] = ()
    card_identity_links: tuple[NexusVaultCardIdentityLink, ...] = ()
    refund_records: tuple[NexusVaultRefundRecord, ...] = ()


def normalize_base_url(value: Any) -> str:
    """Return the one approved NexusVault API origin.

    The API key authorizes inventory writes, so allowing an arbitrary base URL
    would turn a settings typo (or a compromised browser) into credential
    exfiltration.  A trailing slash is accepted for operator convenience; all
    other origins, ports, paths and URL components fail closed.
    """
    raw = str(value or DEFAULT_BASE_URL).strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise NexusVaultConfigurationError("NexusVault 地址格式无效") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise NexusVaultConfigurationError("NexusVault 地址格式无效") from exc
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != "nvtokens.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise NexusVaultConfigurationError(
            "NexusVault 地址只允许 https://nvtokens.com"
        )
    return DEFAULT_BASE_URL


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    raw = str(value or "")
    return base64.urlsafe_b64decode(raw + "=" * ((-len(raw)) % 4))


def _encrypt_api_key(value: str) -> str:
    try:
        nonce = os.urandom(12)
        ciphertext = AESGCM(load_credential_encryption_key()).encrypt(
            nonce,
            value.encode("utf-8"),
            _KEY_ENVELOPE_AAD,
        )
        return _KEY_ENVELOPE_PREFIX + _b64encode(nonce + ciphertext)
    except CredentialKeyError as exc:
        raise NexusVaultConfigurationError(
            "NexusVault 库存 API Key 加密仓库未就绪"
        ) from exc


def _decrypt_api_key(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if not raw.startswith(_KEY_ENVELOPE_PREFIX):
        # Environment fallback and installations created before this client
        # may contain plaintext.  It is accepted for compatibility, but every
        # write through save_config is encrypted at rest.
        return raw
    try:
        envelope = _b64decode(raw[len(_KEY_ENVELOPE_PREFIX):])
        if len(envelope) <= 12:
            raise ValueError("short envelope")
        return AESGCM(load_credential_encryption_key()).decrypt(
            envelope[:12],
            envelope[12:],
            _KEY_ENVELOPE_AAD,
        ).decode("utf-8")
    except Exception as exc:
        raise NexusVaultConfigurationError(
            "NexusVault 库存 API Key 无法解密，请重新配置"
        ) from exc


def _encrypt_session_cookie(value: str) -> str:
    try:
        nonce = os.urandom(12)
        ciphertext = AESGCM(load_credential_encryption_key()).encrypt(
            nonce,
            value.encode("utf-8"),
            _COOKIE_ENVELOPE_AAD,
        )
        return _COOKIE_ENVELOPE_PREFIX + _b64encode(nonce + ciphertext)
    except CredentialKeyError as exc:
        raise NexusVaultConfigurationError(
            "NexusVault 只读登录会话加密仓库未就绪"
        ) from exc


def _decrypt_session_cookie(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if not raw.startswith(_COOKIE_ENVELOPE_PREFIX):
        # Environment-only deployments may inject the cookie as plaintext.
        # Every database write made through save_config remains encrypted.
        return raw
    try:
        envelope = _b64decode(raw[len(_COOKIE_ENVELOPE_PREFIX):])
        if len(envelope) <= 12:
            raise ValueError("short envelope")
        return AESGCM(load_credential_encryption_key()).decrypt(
            envelope[:12],
            envelope[12:],
            _COOKIE_ENVELOPE_AAD,
        ).decode("utf-8")
    except Exception as exc:
        raise NexusVaultConfigurationError(
            "NexusVault 只读登录会话无法解密，请重新配置"
        ) from exc


def _normalize_session_cookie(value: Any) -> str:
    cookie = str(value or "").strip()
    # DevTools commonly copies the request header as ``Cookie: name=value``.
    # Accept that harmless prefix while still rejecting a complete cURL/header
    # block through the control-character checks below.
    if cookie[:7].casefold() == "cookie:":
        cookie = cookie[7:].strip()
    if (
        not cookie
        or len(cookie) > _MAX_COOKIE_LENGTH
        or "=" not in cookie
        or any(ord(char) < 32 or ord(char) > 126 for char in cookie)
    ):
        raise NexusVaultConfigurationError(
            "NexusVault 只读登录 Cookie 格式无效"
        )
    return cookie


def load_config() -> tuple[str, str]:
    """Load the target and secret key without exposing either through config APIs."""
    from core.config_store import config_store

    base_url = normalize_base_url(
        config_store.get(BASE_URL_CONFIG, DEFAULT_BASE_URL)
    )
    api_key = _decrypt_api_key(
        config_store.get(INVENTORY_API_KEY_CONFIG, "")
    ).strip()
    if not api_key:
        raise NexusVaultConfigurationError("请先配置 NexusVault 库存 API Key")
    if len(api_key) > 4096 or any(ord(char) < 32 for char in api_key):
        raise NexusVaultConfigurationError("NexusVault 库存 API Key 格式无效")
    return base_url, api_key


def load_sales_session_config() -> tuple[str, str]:
    """Load the independently stored browser session used only for reads."""
    from core.config_store import config_store

    base_url = normalize_base_url(
        config_store.get(BASE_URL_CONFIG, DEFAULT_BASE_URL)
    )
    cookie = _decrypt_session_cookie(
        config_store.get(SALES_SESSION_COOKIE_CONFIG, "")
    )
    if not str(cookie or "").strip():
        raise NexusVaultConfigurationError(
            "请先配置 NexusVault 只读网页登录 Cookie"
        )
    return base_url, _normalize_session_cookie(cookie)


def public_config() -> dict[str, Any]:
    """Return a secret-free configuration status for the UI."""
    from core.config_store import config_store

    raw_base_url = str(
        config_store.get(BASE_URL_CONFIG, DEFAULT_BASE_URL) or DEFAULT_BASE_URL
    )
    try:
        base_url = normalize_base_url(raw_base_url)
    except NexusVaultConfigurationError:
        # Do not reflect an unsafe configured URL to the browser.  PUT can be
        # used to restore the canonical origin.
        base_url = DEFAULT_BASE_URL
    raw_api_key = str(
        config_store.get(INVENTORY_API_KEY_CONFIG, "") or ""
    ).strip()
    try:
        api_key_configured = bool(_decrypt_api_key(raw_api_key).strip())
    except NexusVaultConfigurationError:
        api_key_configured = False
    raw_session_cookie = str(
        config_store.get(SALES_SESSION_COOKIE_CONFIG, "") or ""
    ).strip()
    try:
        session_cookie_configured = bool(
            _normalize_session_cookie(
                _decrypt_session_cookie(raw_session_cookie)
            ).strip()
        )
    except NexusVaultConfigurationError:
        session_cookie_configured = False
    return {
        "ok": True,
        "base_url": base_url,
        "api_key_configured": api_key_configured,
        "query_session_configured": session_cookie_configured,
        "warranty_hours": DEFAULT_WARRANTY_HOURS,
    }


def save_config(
    *,
    base_url: Any = None,
    api_key: Any = None,
    query_cookie: Any = None,
    session_cookie: Any = None,
) -> dict[str, Any]:
    """Persist validated settings; an empty key deliberately means preserve."""
    from core.config_store import config_store

    updates: dict[str, str] = {}
    if base_url is not None:
        updates[BASE_URL_CONFIG] = normalize_base_url(base_url)
    if api_key is not None:
        normalized_key = str(api_key or "").strip()
        if normalized_key:
            if len(normalized_key) > 4096 or any(
                ord(char) < 32 for char in normalized_key
            ):
                raise NexusVaultConfigurationError(
                    "NexusVault 库存 API Key 格式无效"
                )
            updates[INVENTORY_API_KEY_CONFIG] = _encrypt_api_key(normalized_key)
    if (
        query_cookie is not None
        and session_cookie is not None
        and str(query_cookie or "").strip() != str(session_cookie or "").strip()
    ):
        raise NexusVaultConfigurationError("NexusVault 只读 Cookie 配置冲突")
    cookie_input = query_cookie if query_cookie is not None else session_cookie
    if cookie_input is not None:
        normalized_cookie = str(cookie_input or "").strip()
        if normalized_cookie:
            updates[SALES_SESSION_COOKIE_CONFIG] = _encrypt_session_cookie(
                _normalize_session_cookie(normalized_cookie)
            )
    if updates:
        config_store.set_many(updates)
    return public_config()


def _read_bounded_json(response: Any) -> Any:
    """Decode one bounded JSON response without reflecting its body."""
    raw_length = str(response.headers.get("content-length") or "").strip()
    if raw_length:
        try:
            announced_length = int(raw_length)
        except ValueError as exc:
            raise NexusVaultRequestError("NexusVault 返回内容长度异常") from exc
        if announced_length < 0 or announced_length > _MAX_RESPONSE_BYTES:
            raise NexusVaultRequestError("NexusVault 返回内容异常")
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise NexusVaultRequestError("NexusVault 返回内容异常")
    try:
        return json.loads(bytes(body).decode("utf-8")) if body else {}
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise NexusVaultRequestError("NexusVault 返回内容不是有效 JSON") from exc


def _safe_remote_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 200:
        return ""
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        return ""
    return text


def _safe_remote_email(value: Any) -> str:
    email = str(value or "").strip().casefold()
    if (
        not email
        or len(email) > 320
        or email.count("@") != 1
        or any(char.isspace() or ord(char) < 32 for char in email)
    ):
        return ""
    return email


def _record_email(item: dict[str, Any]) -> str:
    # A human-facing label is not always an email. Do not let a nonempty label
    # hide the real email field and make an existing card look absent.
    return next((
        email for key in ("account_label", "account_email", "email")
        if (email := _safe_remote_email(item.get(key)))
    ), "")


def _safe_remote_sold_at(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or len(raw) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    result = parsed.astimezone(timezone.utc)
    # Reject obviously poisoned timestamps while allowing modest remote clock
    # skew.  Older records remain valid because sold-orders is historical.
    if (
        result.year < 2020
        or result
        > datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=10)
    ):
        return None
    return result


def sanitize_quota_evidence(value: Any) -> dict[str, Any] | None:
    """Keep only a complete, timestamped successful Codex window observation.

    Missing windows and failed checks are *unknown*, not proof that an account
    has no five-hour limit.  Reject the whole observation if even one window
    is malformed; dropping that window could turn a five-hour account into an
    apparently unlimited account.  ``reset_after_seconds`` is deliberately
    ignored because remaining reset time is not the window's full duration.
    """
    if (
        not isinstance(value, dict)
        or value.get("ok") is not True
        or value.get("source") != "codex_usage"
    ):
        return None
    updated_at = _safe_remote_sold_at(value.get("updated_at"))
    windows = value.get("windows")
    if updated_at is None or not isinstance(windows, dict) or not 1 <= len(windows) <= 8:
        return None
    clean: dict[str, dict[str, int | float]] = {}
    for label, window in windows.items():
        if (
            not isinstance(label, str)
            or not re.fullmatch(r"(?:primary|secondary|[1-9][0-9]{0,3}[mhd])", label)
            or not isinstance(window, dict)
        ):
            return None
        minutes = window.get("window_minutes")
        if (
            type(minutes) not in {int, float}
            or not 0 < minutes <= 366 * 24 * 60
        ):
            return None
        clean[label] = {"window_minutes": minutes}
    return {
        "ok": True,
        "source": "codex_usage",
        "windows": clean,
        "updated_at": updated_at.isoformat(),
    }


@dataclass(frozen=True)
class _CardIdentityObservation:
    """Allow-listed original-source evidence, before sale deduplication."""

    email: str
    sold_at: datetime | None
    inventory_card_id: str
    explicit_card_id: str
    remote_order_id: str
    status: str
    valid: bool


def _identity_identifier(value: Any) -> str:
    # A link is durable evidence. Be stricter than the legacy display IDs and
    # never accept arbitrary response text/objects as an identity proof.
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else ""


def _has_refund_evidence(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    # These are observed NV order fields. Do not guess other status enums or
    # equate an unknown settlement state with a successful/full refund.
    if any(str(item.get(key) or "").strip().casefold() == "refunded"
           for key in ("status", "order_status", "settlement_status")):
        return True
    if item.get("refunded_at") not in (None, ""):
        return True
    amount = item.get("refund_amount_cents")
    # A malformed nonempty refund amount is uncertainty, never a valid sale.
    return amount not in (None, "") and not (type(amount) is int and amount == 0)


def _identity_timestamp(value: Any) -> datetime | None:
    # Never let datetime's truncation create an apparently exact cycle match.
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        value.strip(),
    ):
        return None
    return _safe_remote_sold_at(value)


def _card_identity_observation(item: Any, *, order: bool) -> _CardIdentityObservation:
    if not isinstance(item, dict):
        return _CardIdentityObservation("", None, "", "", "", "unknown", False)
    email = _record_email(item)
    emails = {
        value for key in ("account_label", "account_email", "email")
        if (value := _safe_remote_email(item.get(key)))
    }
    ids = {key: _identity_identifier(item.get(key)) for key in ("id", "card_id", "order_id")}
    valid = bool(email) and len(emails) == 1 and all(
        item.get(key) in (None, "") or ids[key] for key in ids
    )
    sold_at = _identity_timestamp(item.get("sold_at"))
    raw_status = str(item.get("status") or "").strip().casefold()
    status = raw_status if raw_status in {"available", "sold"} else "unknown"
    refund = order and _has_refund_evidence(item)
    if not order and _has_refund_evidence(item):
        status, valid = "unknown", False
    if order:
        # An order's legacy created_at fallback may still be shown as a sale,
        # but cannot establish a new cross-namespace card identity.
        valid = bool(valid and sold_at and ids["card_id"] and (ids["order_id"] or ids["id"]))
        if ids["order_id"] and ids["id"] and ids["order_id"] != ids["id"]:
            valid = False
        if raw_status and status != "sold" and not (refund and raw_status == "refunded"):
            valid = False
    return _CardIdentityObservation(
        email=email,
        sold_at=sold_at,
        inventory_card_id="" if order else ids["id"],
        explicit_card_id=ids["card_id"],
        remote_order_id=(ids["order_id"] or ids["id"]) if order else ids["order_id"],
        status="refunded" if refund else "sold" if order and not raw_status else status,
        valid=bool(valid),
    )


def _card_identity_links(
    *,
    complete: bool,
    orders: list[_CardIdentityObservation],
    sold_cards: list[_CardIdentityObservation],
    inventory: list[_CardIdentityObservation],
    include_refunds: bool = False,
) -> tuple[NexusVaultCardIdentityLink, ...]:
    if not complete:
        return ()
    by_source: list[dict[str, list[_CardIdentityObservation]]] = []
    for rows in (orders, sold_cards, inventory):
        grouped: dict[str, list[_CardIdentityObservation]] = {}
        for row in rows:
            if row.email:
                grouped.setdefault(row.email, []).append(row)
        by_source.append(grouped)
    order_emails, sold_emails, inventory_emails = by_source
    # Unrelated archived orders may have lost their email. They cannot propose
    # a link, but still participate in every ID collision check below. An
    # unidentified inventory row already makes inventory_complete false.
    inventory_ids = Counter(row.inventory_card_id for row in inventory if row.inventory_card_id)
    sold_inventory_ids = Counter(row.inventory_card_id for row in sold_cards if row.inventory_card_id)
    order_card_ids = Counter(row.explicit_card_id for row in orders if row.explicit_card_id)
    order_ids = Counter(row.remote_order_id for row in orders if row.remote_order_id)
    explicit_card_emails: dict[str, set[str]] = {}
    explicit_order_emails: dict[str, set[str]] = {}
    for row in inventory + sold_cards:
        if row.explicit_card_id:
            explicit_card_emails.setdefault(row.explicit_card_id, set()).add(row.email)
        if row.remote_order_id:
            explicit_order_emails.setdefault(row.remote_order_id, set()).add(row.email)
    links: list[NexusVaultCardIdentityLink] = []
    for email, inventory_rows in inventory_emails.items():
        sold_rows = sold_emails.get(email, [])
        # Count raw rows, even byte-for-byte duplicates. Merged sale records
        # cannot prove that the inventory itself was unique.
        if len(inventory_rows) != 1 or len(sold_rows) != 1:
            continue
        current, sold = inventory_rows[0], sold_rows[0]
        if (
            not current.valid or not sold.valid
            or current.status != "sold" or sold.status != "sold"
            or not current.inventory_card_id
            or current.inventory_card_id != sold.inventory_card_id
            or current.sold_at is None or current.sold_at != sold.sold_at
        ):
            continue
        email_orders = order_emails.get(email, [])
        if any(not row.valid for row in email_orders):
            continue
        matching_orders = [row for row in email_orders if row.sold_at == current.sold_at]
        if len(matching_orders) != 1:
            continue
        order = matching_orders[0]
        if order.status != "sold" and not (include_refunds and order.status == "refunded"):
            continue
        if current.inventory_card_id == order.explicit_card_id:
            # Same-namespace IDs already compare directly and need no alias.
            continue
        if any(
            (row.explicit_card_id and row.explicit_card_id != order.explicit_card_id)
            or (row.remote_order_id and row.remote_order_id != order.remote_order_id)
            for row in (current, sold)
        ):
            continue
        # IDs must be one-to-one throughout each source, not merely within an
        # email group. A reused order/card identity in another cycle or account
        # invalidates the proposed association rather than silently rebinding.
        if (
            inventory_ids[current.inventory_card_id] != 1
            or sold_inventory_ids[current.inventory_card_id] != 1
            or order_card_ids[order.explicit_card_id] != 1
            or order_ids[order.remote_order_id] != 1
            or explicit_card_emails.get(order.explicit_card_id, set()) - {email}
            or explicit_order_emails.get(order.remote_order_id, set()) - {email}
        ):
            continue
        links.append(NexusVaultCardIdentityLink(
            email=email,
            sold_at=current.sold_at,
            inventory_card_id=current.inventory_card_id,
            order_card_id=order.explicit_card_id,
            remote_order_id=order.remote_order_id,
        ))
    return tuple(sorted(links, key=lambda row: (row.email, row.sold_at, row.inventory_card_id)))


def _page_collection(payload: Any, key: str) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
        raise NexusVaultRequestError("NexusVault 出库查询返回结构异常")
    pagination = payload.get("pagination")
    return list(payload[key]), pagination if isinstance(pagination, dict) else {}


def _pagination_decision(
    *,
    pagination: dict[str, Any],
    page: int,
    item_count: int,
    raw_count: int,
    limit: int,
    expected_total_pages: int | None,
    expected_total: int | None,
) -> tuple[bool, bool, int | None, int | None, bool]:
    """Return pagination continuation, terminal completeness and consistency.

    A short page without explicit pagination is useful positive evidence, but it
    cannot prove that the remote collection is complete: the server may cap its
    actual page size below the requested limit.  Likewise, contradictory page
    metadata stops the read without allowing callers to infer absence.
    """
    decisions: list[bool] = []
    consistent = True

    reported_page = pagination.get("page")
    if "page" in pagination and (
        not isinstance(reported_page, int)
        or isinstance(reported_page, bool)
        or reported_page != page
    ):
        consistent = False

    total_pages = pagination.get("total_pages")
    if isinstance(total_pages, int) and not isinstance(total_pages, bool):
        if total_pages <= 0 or total_pages > _MAX_SOLD_PAGES:
            raise NexusVaultRequestError("NexusVault 出库分页信息异常")
        if expected_total_pages is not None and total_pages != expected_total_pages:
            consistent = False
        expected_total_pages = total_pages if expected_total_pages is None else expected_total_pages
        if page > total_pages:
            consistent = False
        decisions.append(page < total_pages)
    elif "total_pages" in pagination:
        consistent = False

    total = pagination.get("total")
    if isinstance(total, int) and not isinstance(total, bool):
        if total < 0 or total > limit * _MAX_SOLD_PAGES:
            raise NexusVaultRequestError("NexusVault 出库分页信息异常")
        if expected_total is not None and total != expected_total:
            consistent = False
        expected_total = total if expected_total is None else expected_total
        if raw_count > total:
            consistent = False
        decisions.append(raw_count < total)
    elif "total" in pagination:
        consistent = False

    has_more = pagination.get("has_more")
    if isinstance(has_more, bool):
        decisions.append(has_more)
    elif "has_more" in pagination:
        consistent = False

    if not decisions:
        return item_count >= limit, False, expected_total_pages, expected_total, False
    if not consistent:
        return False, False, expected_total_pages, expected_total, False
    if any(decision != decisions[0] for decision in decisions[1:]):
        return False, False, expected_total_pages, expected_total, False
    has_next = decisions[0]
    if not has_next and (
        (expected_total_pages is not None and page != expected_total_pages)
        or (expected_total is not None and raw_count != expected_total)
    ):
        consistent = False
    return (
        has_next,
        bool(not has_next and consistent),
        expected_total_pages,
        expected_total,
        consistent,
    )


def _remote_get_page(
    *,
    base_url: str,
    session_cookie: str,
    path: str,
    params: dict[str, Any],
) -> Any:
    try:
        response = requests.get(
            f"{base_url}{path}",
            headers={
                "accept": "application/json, text/plain, */*",
                "cookie": session_cookie,
                "referer": f"{base_url}/workspace/inventory",
                "user-agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/151.0.0.0 Safari/537.36"
                ),
            },
            params=params,
            timeout=(10, 45),
            allow_redirects=False,
            stream=True,
        )
    except requests.Timeout as exc:
        raise NexusVaultRequestTimeout("NexusVault 出库查询超时") from exc
    except requests.RequestException as exc:
        raise NexusVaultRequestError("无法连接 NexusVault 出库查询服务") from exc
    except Exception as exc:
        raise NexusVaultRequestError("无法连接 NexusVault 出库查询服务") from exc
    try:
        if response.status_code in {401, 403}:
            raise NexusVaultSessionExpired(
                "NexusVault 只读网页登录会话已失效，请重新配置 Cookie"
            )
        if response.status_code < 200 or response.status_code >= 300:
            raise NexusVaultRequestError(
                f"NexusVault 出库查询失败（HTTP {int(response.status_code)}）"
            )
        try:
            return _read_bounded_json(response)
        except NexusVaultRequestError:
            raise
        except requests.Timeout as exc:
            raise NexusVaultRequestTimeout("NexusVault 出库查询超时") from exc
        except requests.RequestException as exc:
            raise NexusVaultRequestError("读取 NexusVault 出库结果失败") from exc
        except Exception as exc:
            raise NexusVaultRequestError("读取 NexusVault 出库结果失败") from exc
    finally:
        response.close()


def _team5x_deadline(item: dict[str, Any], *, order: bool = False) -> datetime | None:
    """Only an explicitly absolute warranty is a 5X deadline, not expires_at.

    Orders expose warranty_mode/until; inventory exposes team5x_warranty_*.
    Never reinterpret a malformed absolute warranty as the legacy one hour.
    """
    from services.nv_listing_warranty import normalize_team5x_warranty

    prefix = "warranty" if order else "team5x_warranty"
    if item.get(f"{prefix}_mode") != "until":
        return None
    try:
        value = normalize_team5x_warranty(
            {"mode": "until", "until": item.get(f"{prefix}_until")},
            require_future=False,
        )
        return datetime.fromisoformat(value["until"])
    except (ValueError, TypeError, KeyError):
        raise NexusVaultRequestError("NV 返回的 5X 质保截止时间无效，未推断过保或退出") from None


def _refund_order_record(item: Any) -> NexusVaultRefundRecord | None:
    if not _has_refund_evidence(item):
        return None
    observation = _card_identity_observation(item, order=True)

    def cents(key: str) -> int | None:
        value = item.get(key)
        return value if type(value) is int and 0 <= value <= 99_999_999 else None

    def status(key: str) -> str:
        value = item.get(key)
        if value in (None, ""):
            return ""
        return "refunded" if isinstance(value, str) and value.strip().casefold() == "refunded" else "unknown"

    amount, refund_amount, supplier_amount = (cents(key) for key in (
        "amount_cents", "refund_amount_cents", "supplier_amount_cents",
    ))
    refunded_at = _identity_timestamp(item.get("refunded_at"))
    order_status, settlement_status = status("order_status"), status("settlement_status")
    full_refund = bool(
        observation.valid and observation.sold_at is not None
        and refunded_at is not None and observation.sold_at <= refunded_at <= datetime.now(timezone.utc)
        and order_status == settlement_status == "refunded"
        and amount is not None and amount > 0 and refund_amount == amount and supplier_amount == 0
    )
    return NexusVaultRefundRecord(
        email=observation.email, sold_at=observation.sold_at, refunded_at=refunded_at,
        remote_order_id=observation.remote_order_id, remote_card_id=observation.explicit_card_id,
        amount_cents=amount, refund_amount_cents=refund_amount, supplier_amount_cents=supplier_amount,
        order_status=order_status, settlement_status=settlement_status,
        full_refund=full_refund, identity_valid=observation.valid,
    )


def _refund_blocks_sale(refund: NexusVaultRefundRecord, sale: NexusVaultSoldRecord) -> bool:
    """A refund veto is cycle-specific; never infer an alias from email alone."""
    if not refund.email or refund.email != sale.email:
        return False
    if refund.remote_order_id and sale.remote_order_id:
        if refund.remote_order_id != sale.remote_order_id:
            return False
        # Orders may contain multiple cards. Explicit card IDs share a
        # namespace; native inventory IDs do not and cannot be compared here.
        return not (refund.remote_card_id and sale.explicit_card_id
                    and refund.remote_card_id != sale.explicit_card_id)
    if refund.sold_at is None or refund.sold_at != sale.sold_at:
        return False
    return bool(
        (refund.remote_card_id and refund.remote_card_id in {sale.remote_card_id, sale.explicit_card_id})
        or (refund.inventory_card_id and refund.inventory_card_id == sale.inventory_card_id)
    )


def _sold_order_record(item: Any) -> NexusVaultSoldRecord | None:
    if not isinstance(item, dict) or _has_refund_evidence(item):
        return None
    email = _record_email(item)
    # The NV settlement page itself falls back to ``created_at`` for legacy
    # orders whose dedicated sold timestamp was not persisted.
    sold_at = _safe_remote_sold_at(item.get("sold_at") or item.get("created_at"))
    if not email or sold_at is None:
        return None
    return NexusVaultSoldRecord(
        email=email,
        sold_at=sold_at,
        remote_order_id=_safe_remote_identifier(
            item.get("order_id") or item.get("id")
        ),
        remote_card_id=_safe_remote_identifier(item.get("card_id")),
        source="sold_orders",
        explicit_card_id=_identity_identifier(item.get("card_id")),
        team5x_warranty_until=_team5x_deadline(item, order=True),
    )


def _sold_card_record(item: Any) -> NexusVaultSoldRecord | None:
    if (not isinstance(item, dict) or _has_refund_evidence(item)
            or str(item.get("status") or "").strip().casefold() != "sold"):
        return None
    email = _record_email(item)
    sold_at = _safe_remote_sold_at(item.get("sold_at"))
    if not email or sold_at is None:
        return None
    return NexusVaultSoldRecord(
        email=email,
        sold_at=sold_at,
        remote_order_id=_safe_remote_identifier(item.get("order_id")),
        remote_card_id=_safe_remote_identifier(
            item.get("card_id") or item.get("id")
        ),
        source="sold_cards",
        inventory_card_id=_identity_identifier(item.get("id")),
        explicit_card_id=_identity_identifier(item.get("card_id")),
        team5x_warranty_until=_team5x_deadline(item),
    )


def _workspace_deactivated_check(item: dict[str, Any]) -> bool:
    """Recognize one observed inspection result, never generic blocked/402.

    Exact messages also reject appended credentials, unrelated errors and
    quoted/negated diagnostic text. Raw messages stay inside this parser.
    """
    return (
        item.get("status") == "inventory"
        and item.get("check_status") == "blocked"
        and item.get("check_message") == "工作区已停用，已作为异常永久移出可售账号和兜底池"
        and item.get("reject_reason") == "巡检确认工作区已停用，已作为异常移除：工作区已停用（Codex 套餐接口 HTTP 402）"
    )


def _inventory_card_record(item: Any) -> NexusVaultInventoryRecord | None:
    if not isinstance(item, dict):
        return None
    email = _record_email(item)
    if not email:
        return None
    # Never echo an arbitrary remote status: an unexpected API payload could
    # otherwise expose credential data through the status/diagnostic fields.
    raw_status = str(item.get("status") or "").strip().casefold()
    status = raw_status if raw_status in {"available", "sold"} and not _has_refund_evidence(item) else "unknown"
    check_details = item.get("check_details")
    workspace_deactivated = _workspace_deactivated_check(item)
    return NexusVaultInventoryRecord(
        email=email,
        status=status,
        remote_card_id=_safe_remote_identifier(item.get("card_id") or item.get("id")),
        sold_at=_safe_remote_sold_at(item.get("sold_at")),
        inventory_card_id=_identity_identifier(item.get("id")),
        explicit_card_id=_identity_identifier(item.get("card_id")),
        remote_order_id=_identity_identifier(item.get("order_id")),
        quota=sanitize_quota_evidence(
            check_details.get("quota") if isinstance(check_details, dict) else None
        ),
        team5x_warranty_until=_team5x_deadline(item),
        price_cents=item.get("price_cents") if type(item.get("price_cents")) is int and 0 < item["price_cents"] <= 99_999_999 else None,
        pool_price_cents=item.get("pool_price_cents") if type(item.get("pool_price_cents")) is int and 0 < item["pool_price_cents"] <= 99_999_999 else None,
        health_status=item.get("check_status") if isinstance(item.get("check_status"), str) and item["check_status"] in {"healthy", "unhealthy", "error", "unknown"} else "",
        archived=bool(item.get("archived_at")),
        fallback_pool_only=item.get("fallback_pool_only") if type(item.get("fallback_pool_only")) is bool else None,
        workspace_deactivated=workspace_deactivated,
        workspace_deactivated_at=_identity_timestamp(item.get("last_checked_at")) if workspace_deactivated else None,
    )


def _fetch_paginated_sales(
    *,
    base_url: str,
    session_cookie: str,
    path: str,
    collection_key: str,
    extra_params: dict[str, Any] | None,
    limit: int,
    parser: Any,
) -> tuple[list[Any], int, int, bool]:
    records: list[Any] = []
    raw_count = 0
    expected_total_pages: int | None = None
    expected_total: int | None = None
    all_pages_consistent = True
    for page in range(1, _MAX_SOLD_PAGES + 1):
        params = {"page": page, "limit": limit, **(extra_params or {})}
        payload = _remote_get_page(
            base_url=base_url,
            session_cookie=session_cookie,
            path=path,
            params=params,
        )
        items, pagination = _page_collection(payload, collection_key)
        raw_count += len(items)
        records.extend(record for item in items if (record := parser(item)) is not None)
        (
            has_next,
            terminal_complete,
            next_total_pages,
            next_total,
            page_metadata_consistent,
        ) = _pagination_decision(
            pagination=pagination,
            page=page,
            item_count=len(items),
            raw_count=raw_count,
            limit=limit,
            expected_total_pages=expected_total_pages,
            expected_total=expected_total,
        )
        all_pages_consistent = all_pages_consistent and page_metadata_consistent
        expected_total_pages = next_total_pages
        expected_total = next_total
        if not has_next:
            return records, raw_count, page, bool(
                terminal_complete and all_pages_consistent
            )
    raise NexusVaultRequestError("NexusVault 出库记录页数超过安全上限")


def fetch_sales_snapshot(
    *,
    base_url: str | None = None,
    session_cookie: str | None = None,
    include_inventory: bool = False,
) -> NexusVaultSalesSnapshot:
    """Fetch sales and optionally complete inventory without mutation.

    Only an explicitly complete unfiltered inventory can distinguish a card
    still on sale from a missing one. All reads finish before returning, so an
    inventory page failure cannot be mistaken for an empty inventory.
    """
    if base_url is None or session_cookie is None:
        configured_base_url, configured_cookie = load_sales_session_config()
        base_url = configured_base_url if base_url is None else base_url
        session_cookie = configured_cookie if session_cookie is None else session_cookie
    target_base_url = normalize_base_url(base_url)
    normalized_cookie = _normalize_session_cookie(session_cookie)
    unconfirmed_sold_emails: set[str] = set()
    order_identity_rows: list[_CardIdentityObservation] = []
    sold_identity_rows: list[_CardIdentityObservation] = []
    inventory_identity_rows: list[_CardIdentityObservation] = []
    refund_records: list[NexusVaultRefundRecord] = []

    def parse_sale(item: Any, *, order: bool) -> NexusVaultSoldRecord | None:
        (order_identity_rows if order else sold_identity_rows).append(
            _card_identity_observation(item, order=order)
        )
        if order and (refund := _refund_order_record(item)) is not None:
            refund_records.append(refund)
            return None
        record = _sold_order_record(item) if order else _sold_card_record(item)
        if record is None and isinstance(item, dict) and (
            order or str(item.get("status") or "").strip().casefold() == "sold"
        ):
            email = _record_email(item)
            if email:
                # Archived orders may have no usable timestamp and no current
                # card. Keep existence evidence without inventing a sale time.
                unconfirmed_sold_emails.add(email)
        return record

    def parse_inventory(item: Any) -> NexusVaultInventoryRecord | None:
        inventory_identity_rows.append(_card_identity_observation(item, order=False))
        return _inventory_card_record(item)

    # sold-orders is authoritative history and continues to contain archived
    # cards.  Current sold cards are fetched as a secondary source and can add
    # the remote card id before an order disappears from the inventory view.
    order_records, order_count, order_pages, orders_complete = _fetch_paginated_sales(
        base_url=target_base_url,
        session_cookie=normalized_cookie,
        path="/api/supplier/sold-orders",
        collection_key="orders",
        extra_params=None,
        limit=_SOLD_ORDER_PAGE_LIMIT,
        parser=lambda item: parse_sale(item, order=True),
    )
    card_records, card_count, card_pages, sold_cards_complete = _fetch_paginated_sales(
        base_url=target_base_url,
        session_cookie=normalized_cookie,
        path="/api/supplier/cards",
        collection_key="cards",
        extra_params={"group": "sold"},
        limit=_SOLD_CARD_PAGE_LIMIT,
        parser=lambda item: parse_sale(item, order=False),
    )
    inventory_records: list[NexusVaultInventoryRecord] = []
    inventory_pages = 0
    inventory_complete = False
    if include_inventory:
        (
            inventory_records,
            _inventory_count,
            inventory_pages,
            inventory_pages_complete,
        ) = _fetch_paginated_sales(
            base_url=target_base_url,
            session_cookie=normalized_cookie,
            path="/api/supplier/cards",
            collection_key="cards",
            extra_params=None,
            limit=_SOLD_CARD_PAGE_LIMIT,
            parser=parse_inventory,
        )
        # Fetching every page is not sufficient if an inventory row cannot be
        # identified. Such a snapshot may confirm known available accounts,
        # but must not classify other local accounts as definitively absent.
        inventory_complete = bool(
            orders_complete
            and sold_cards_complete
            and inventory_pages_complete
            and len(inventory_records) == _inventory_count
        )

    # Refund identity uses the original raw rows and the existing complete,
    # collision-checked three-source association. Keep these aliases separate
    # from sale links: a refunded order must never validate an active sale.
    refund_links = _card_identity_links(
        complete=inventory_complete, orders=order_identity_rows,
        sold_cards=sold_identity_rows, inventory=inventory_identity_rows,
        include_refunds=True,
    )
    refund_records = [replace(refund, inventory_card_id=next((
        link.inventory_card_id for link in refund_links
        if link.email == refund.email and link.sold_at == refund.sold_at
        and link.remote_order_id == refund.remote_order_id and link.order_card_id == refund.remote_card_id
    ), "")) for refund in refund_records]

    refunds_by_email: dict[str, list[NexusVaultRefundRecord]] = {}
    for refund in refund_records:
        refunds_by_email.setdefault(refund.email, []).append(refund)
    grouped: dict[tuple[str, datetime], list[NexusVaultSoldRecord]] = {}
    for record in order_records + card_records:
        if any(_refund_blocks_sale(refund, record) for refund in refunds_by_email.get(record.email, ())):
            continue
        key = (record.email, record.sold_at)
        grouped.setdefault(key, []).append(record)
    merged: list[NexusVaultSoldRecord] = []
    for (email, sold_at), records in grouped.items():
        order_ids = {row.remote_order_id for row in records if row.remote_order_id}
        card_ids = {row.remote_card_id for row in records if row.remote_card_id}
        deadlines = {row.team5x_warranty_until for row in records if row.team5x_warranty_until is not None}
        if len(order_ids) <= 1 and len(card_ids) <= 1:
            if len(deadlines) > 1:
                raise NexusVaultRequestError("NV 同一订单的 5X 质保截止时间不一致，未推断过保或退出")
            # Preserve the historical unique order/card complement: archived
            # orders may omit card_id, and current cards may omit order_id.
            inventory_ids = {row.inventory_card_id for row in records if row.inventory_card_id}
            explicit_ids = {row.explicit_card_id for row in records if row.explicit_card_id}
            merged.append(NexusVaultSoldRecord(
                email=email, sold_at=sold_at,
                remote_order_id=next(iter(order_ids), ""),
                remote_card_id=next(iter(card_ids), ""),
                source=records[0].source if len(records) == 1 else "merged",
                inventory_card_id=next(iter(inventory_ids), "") if len(inventory_ids) <= 1 else "",
                explicit_card_id=next(iter(explicit_ids), "") if len(explicit_ids) <= 1 else "",
                team5x_warranty_until=next(iter(deadlines), None),
            ))
        else:
            # Equal email + second is not a remote identity. Two distinct
            # cards/orders must stay distinguishable for lifecycle matching;
            # never manufacture a card/order pair by overwriting one record.
            merged.extend(dict.fromkeys(records))
    return NexusVaultSalesSnapshot(
        sold_records=tuple(sorted(
            merged,
            key=lambda item: (item.email, item.sold_at, item.remote_card_id, item.remote_order_id),
        )),
        order_count=order_count,
        sold_card_count=card_count,
        pages_fetched=order_pages + card_pages + inventory_pages,
        inventory_records=tuple(inventory_records),
        inventory_complete=inventory_complete,
        unconfirmed_sold_emails=tuple(sorted(unconfirmed_sold_emails)),
        card_identity_links=_card_identity_links(
            complete=inventory_complete,
            orders=order_identity_rows,
            sold_cards=sold_identity_rows,
            inventory=inventory_identity_rows,
        ),
        refund_records=tuple(refund_records),
    )


def _safe_summary(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict) or not isinstance(payload.get("summary"), dict):
        return {}
    summary: dict[str, int] = {}
    for key in _SAFE_SUMMARY_FIELDS:
        value = payload["summary"].get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            summary[key] = value
    return summary


def _validate_bundle(sub2api_data: Any, email: str) -> dict[str, Any]:
    if not isinstance(sub2api_data, dict):
        raise ValueError("Sub2API 凭证格式无效")
    accounts = sub2api_data.get("accounts")
    if not isinstance(accounts, list) or len(accounts) != 1:
        raise ValueError("NexusVault 单次上架必须且只能包含一个账号")
    account = accounts[0]
    credentials = account.get("credentials") if isinstance(account, dict) else None
    if not isinstance(credentials, dict):
        raise ValueError("Sub2API 凭证缺少账号授权信息")
    remote_email = str(credentials.get("email") or "").strip().casefold()
    if not remote_email or remote_email != str(email or "").strip().casefold():
        raise ValueError("Sub2API 凭证邮箱与待上架子号不一致")
    for key in ("access_token", "refresh_token", "id_token"):
        if not str(credentials.get(key) or "").strip():
            raise ValueError(f"Sub2API 凭证缺少 {key}")
    return sub2api_data


def publish_sub2api_card(
    *,
    sub2api_data: dict[str, Any],
    email: str,
    password: str,
    two_factor_secret: str,
    price_yuan: str,
    warranty_hours: int = DEFAULT_WARRANTY_HOURS,
    team5x_warranty: dict[str, Any] | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> NexusVaultPublishResult:
    """Import and publish one account through ``cards/pool`` exactly once."""
    normalized_email = str(email or "").strip().casefold()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("待上架子号邮箱无效")
    if not str(password or ""):
        raise ValueError("子号尚未保存 ChatGPT 登录密码")
    if not str(two_factor_secret or ""):
        raise ValueError("子号尚未保存长期 Authenticator 2FA 密钥")
    if warranty_hours != DEFAULT_WARRANTY_HOURS:
        raise ValueError("NexusVault 当前只支持默认 1 小时质保")
    bundle = _validate_bundle(sub2api_data, normalized_email)
    from services.nv_listing_warranty import normalize_team5x_warranty

    absolute_warranty = normalize_team5x_warranty(team5x_warranty)

    if base_url is None or api_key is None:
        configured_base_url, configured_api_key = load_config()
        base_url = configured_base_url if base_url is None else base_url
        api_key = configured_api_key if api_key is None else api_key
    target_base_url = normalize_base_url(base_url)
    normalized_api_key = str(api_key or "").strip()
    if not normalized_api_key:
        raise NexusVaultConfigurationError("请先配置 NexusVault 库存 API Key")

    payload = {
        "data": bundle,
        "inventory_token": {
            "email": normalized_email,
            "password": str(password),
            "two_factor_secret": str(two_factor_secret),
        },
        "price_yuan": str(price_yuan),
        "warranty_name": DEFAULT_WARRANTY_NAME,
        "fallback_pool_enabled": False,
    }
    if absolute_warranty is not None:
        # NV 2026-09-09: only a top-level absolute deadline is accepted for
        # Team5x. The legacy warranty channel applies to other categories.
        payload.pop("warranty_name")
        payload["team5x_warranty"] = absolute_warranty
    try:
        response = requests.post(
            f"{target_base_url}/api/inventory/cards/pool",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "x-api-key": normalized_api_key,
            },
            json=payload,
            timeout=(10, 90),
            allow_redirects=False,
            stream=True,
        )
    except requests.Timeout as exc:
        raise NexusVaultRequestTimeout(
            "NexusVault 请求超时，本次上架结果未知；请先到 NV 平台核对后再重试"
        ) from exc
    except requests.RequestException as exc:
        raise NexusVaultRequestError("无法连接 NexusVault，请检查网络后重试") from exc

    try:
        try:
            raw_length = str(response.headers.get("content-length") or "").strip()
            if raw_length:
                try:
                    announced_length = int(raw_length)
                except ValueError as exc:
                    raise NexusVaultRequestError(
                        "NexusVault 返回内容长度异常"
                    ) from exc
                if announced_length < 0 or announced_length > _MAX_RESPONSE_BYTES:
                    raise NexusVaultRequestError("NexusVault 返回内容异常")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise NexusVaultRequestError("NexusVault 返回内容异常")
            try:
                response_payload = (
                    json.loads(bytes(body).decode("utf-8")) if body else {}
                )
            except (UnicodeDecodeError, TypeError, ValueError):
                response_payload = {}
        except NexusVaultRequestError:
            raise
        except requests.Timeout as exc:
            raise NexusVaultRequestTimeout(
                "NexusVault 请求超时，本次上架结果未知；"
                "请先到 NV 平台核对后再重试"
            ) from exc
        except requests.RequestException as exc:
            raise NexusVaultRequestError(
                "读取 NexusVault 响应失败；本次结果未知，请先到 NV 平台核对"
            ) from exc
    finally:
        response.close()
    if response.status_code < 200 or response.status_code >= 300:
        # Return a fixed diagnosis, never the untrusted response which can
        # include submitted passwords, seeds or OAuth credentials.
        remote_error = str(response_payload.get("error") or "") if isinstance(response_payload, dict) else ""
        if response.status_code == 400 and "team5x" in remote_error.casefold() and "质保" in remote_error:
            raise NexusVaultPublishRejected(
                "NV 拒绝 5X 质保参数：请设置带时区且晚于当前时间的质保截止时间；未确认上架成功"
            )
        raise NexusVaultRequestError(
            f"NexusVault 上架请求失败（HTTP {response.status_code}）；"
            "远端详情未透传，请到 NV 平台核对"
        )

    summary = _safe_summary(response_payload)
    published = summary.get("published")
    # Deliberately do not coerce "1", True, or any success-looking top-level
    # flag.  The documented, authoritative completion signal is the integer
    # ``summary.published`` count.
    if not isinstance(published, int) or isinstance(published, bool) or published != 1:
        raise NexusVaultPublishRejected(
            "NexusVault 未确认账号成功入池"
            f"（published={published if isinstance(published, int) else 0}）；"
            "请到 NV 平台核对健康、套餐、重复账号、价格及质保设置"
        )
    return NexusVaultPublishResult(
        published=1,
        summary=summary,
        status_code=int(response.status_code),
    )


__all__ = [
    "BASE_URL_CONFIG",
    "DEFAULT_BASE_URL",
    "DEFAULT_WARRANTY_HOURS",
    "DEFAULT_WARRANTY_NAME",
    "INVENTORY_API_KEY_CONFIG",
    "SALES_SESSION_COOKIE_CONFIG",
    "NexusVaultConfigurationError",
    "NexusVaultCardIdentityLink",
    "NexusVaultError",
    "NexusVaultPublishRejected",
    "NexusVaultPublishResult",
    "NexusVaultRequestError",
    "NexusVaultRequestTimeout",
    "NexusVaultSalesSnapshot",
    "NexusVaultSessionExpired",
    "NexusVaultSoldRecord",
    "NexusVaultInventoryRecord",
    "fetch_sales_snapshot",
    "load_config",
    "load_sales_session_config",
    "normalize_base_url",
    "public_config",
    "publish_sub2api_card",
    "save_config",
    "sanitize_quota_evidence",
]
