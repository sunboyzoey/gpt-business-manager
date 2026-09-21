"""Credential-free CPA/Sub2API device inventory and quota snapshots.

This module is deliberately a facade, not another device registry:

* CPA endpoints come from the shared CPA target registry (the persisted config
  key keeps its legacy name for migration compatibility).
* Sub2API endpoints come from ``SyncDeviceModel``.
* Only sanitized remote account identities and quota data are persisted.

Raw CPA auth files, API keys, access tokens and refresh tokens never cross the
service boundary or enter the snapshot tables.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

from sqlmodel import Session, select

from core.db import (
    DeliveryDeviceAccountSnapshotModel,
    DeliveryDeviceMonitorStateModel,
    GptBusinessAccountModel,
    GptBusinessChildMembershipModel,
    GptPlanAccountModel,
    GptPlanAccountModel as GptProAccountModel,
    SyncDeviceModel,
    engine,
)

# ``GptProAccountModel`` remains only as a local compatibility spelling.  All
# inventory attribution and quota reconciliation below query plan accounts.


logger = logging.getLogger(__name__)
_REFRESH_LOCKS_GUARD = threading.Lock()
_REFRESH_LOCKS: dict[str, threading.RLock] = {}
_SUPPORTED_PROVIDERS = frozenset({"cpa", "sub2api"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    if provider in {"sub", "sub-2-api"}:
        return "sub2api"
    return provider


def device_key(provider: Any, provider_id: Any) -> str:
    normalized = normalize_provider(provider)
    if normalized not in _SUPPORTED_PROVIDERS:
        raise ValueError("设备类型只支持 cpa 或 sub2api")
    if isinstance(provider_id, bool):
        raise ValueError("设备 ID 无效")
    try:
        numeric_id = int(provider_id)
    except (TypeError, ValueError):
        raise ValueError("设备 ID 无效") from None
    if numeric_id <= 0:
        raise ValueError("设备 ID 无效")
    return f"{normalized}:{numeric_id}"


def parse_device_key(value: Any) -> tuple[str, int]:
    raw = str(value or "").strip().lower()
    if ":" not in raw:
        raise ValueError("设备标识必须是 cpa:ID 或 sub2api:ID")
    provider, raw_id = raw.split(":", 1)
    key = device_key(provider, raw_id)
    normalized, numeric = key.split(":", 1)
    return normalized, int(numeric)


def _refresh_lock(key: str) -> threading.RLock:
    with _REFRESH_LOCKS_GUARD:
        return _REFRESH_LOCKS.setdefault(key, threading.RLock())


def device_refresh_lock(device_ref: str) -> threading.RLock:
    """Serialize one device's refresh, update and delete boundaries."""
    provider, provider_id = parse_device_key(device_ref)
    return _refresh_lock(device_key(provider, provider_id))


def _bounded_text(value: Any, limit: int = 500) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return str(value).strip()[:limit]


def _safe_text(
    value: Any,
    *,
    secrets: tuple[str, ...] | list[str] = (),
    limit: int = 500,
) -> str:
    """Bound public metadata and redact credentials echoed by a remote API."""
    text = _bounded_text(value, limit=limit)
    for secret in secrets:
        normalized = str(secret or "")
        if len(normalized) >= 4:
            text = text.replace(normalized, "[REDACTED]")
    return text


def _known_secret_values(value: Any, *, _depth: int = 0) -> tuple[str, ...]:
    """Collect credential values only from explicitly sensitive remote fields.

    A remote service may echo an access token into an otherwise public field
    such as ``name`` or ``status``.  The public DTO still uses an allowlist, but
    those known credential values must also be replaced wherever they recur.
    """
    if _depth >= 10 or not isinstance(value, dict):
        return ()
    secrets: list[str] = []
    sensitive_names = {
        "api_key", "apikey", "access_token", "refresh_token", "id_token",
        "token", "authorization", "cookie", "password", "secret",
        "credentials",
    }

    def visit(item: Any, *, sensitive: bool, depth: int) -> None:
        if depth >= 10:
            return
        if isinstance(item, dict):
            for raw_key, child in item.items():
                key = str(raw_key).strip().lower().replace("-", "_")
                key_sensitive = key in sensitive_names or any(
                    marker in key
                    for marker in ("_token", "api_key", "password", "secret")
                )
                # Structured JWT metadata contains useful public claims such as
                # plan_type.  Treat a scalar id_token as secret, but inspect a
                # decoded dict by its individual leaf names instead of hiding
                # every claim in that container.
                child_sensitive = sensitive or (
                    key_sensitive
                    and not isinstance(child, (dict, list, tuple))
                ) or key == "credentials"
                visit(child, sensitive=child_sensitive, depth=depth + 1)
            return
        if isinstance(item, (list, tuple)):
            for child in item[:100]:
                visit(child, sensitive=sensitive, depth=depth + 1)
            return
        if sensitive and isinstance(item, str) and len(item) >= 4:
            secrets.append(item)

    visit(value, sensitive=False, depth=_depth)
    return tuple(dict.fromkeys(secrets))


def _cpa_targets_snapshot() -> tuple[list[dict[str, Any]], int]:
    # Import lazily to keep this service independent from FastAPI import order.
    from api.gpt_plan_operations import _cpa_sync_targets_snapshot

    targets, revision = _cpa_sync_targets_snapshot()
    return [dict(item) for item in targets if isinstance(item, dict)], int(revision)


def _sub2api_device_rows() -> list[dict[str, Any]]:
    with Session(engine) as session:
        rows = session.exec(select(SyncDeviceModel).order_by(SyncDeviceModel.id)).all()
        result: list[dict[str, Any]] = []
        for row in rows:
            provider = normalize_provider(row.type)
            if provider != "sub2api" or not row.id:
                continue
            result.append({
                "id": int(row.id),
                "name": str(row.name or "").strip(),
                "api_url": str(row.api_url or "").strip().rstrip("/"),
                "api_key": str(row.api_key or "").strip(),
                "enabled": bool(row.enabled),
                "sub_group_ids": str(row.sub_group_ids or "").strip() or "2",
                "updated_at": row.updated_at,
            })
        return result


def _internal_device(provider: str, provider_id: int) -> dict[str, Any] | None:
    if provider == "cpa":
        targets, revision = _cpa_targets_snapshot()
        for target in targets:
            try:
                current_id = int(target.get("id") or 0)
            except (TypeError, ValueError):
                continue
            if current_id == provider_id:
                return {
                    "provider": "cpa",
                    "provider_id": provider_id,
                    "name": str(target.get("name") or "").strip(),
                    "api_url": str(target.get("api_url") or "").strip().rstrip("/"),
                    "api_key": str(target.get("api_key") or "").strip(),
                    "enabled": True,
                    "sub_group_ids": "",
                    "config_revision": int(revision),
                }
        return None
    for row in _sub2api_device_rows():
        if int(row["id"]) == provider_id:
            return {
                "provider": "sub2api",
                "provider_id": provider_id,
                **row,
            }
    return None


def _device_config_token(internal: dict[str, Any]) -> tuple[Any, ...]:
    """Build a private comparison token; credentials never leave this module."""
    updated_at = internal.get("updated_at")
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    return (
        normalize_provider(internal.get("provider")),
        int(internal.get("provider_id") or internal.get("id") or 0),
        str(internal.get("name") or "").strip(),
        str(internal.get("api_url") or "").strip().rstrip("/"),
        str(internal.get("api_key") or ""),
        bool(internal.get("enabled", True)),
        str(internal.get("sub_group_ids") or ""),
        int(internal.get("config_revision") or 0),
        str(updated_at or ""),
    )


def _device_config_is_current(expected: dict[str, Any]) -> bool:
    provider = normalize_provider(expected.get("provider"))
    provider_id = int(expected.get("provider_id") or expected.get("id") or 0)
    current = _internal_device(provider, provider_id)
    return bool(
        current
        and _device_config_token(current) == _device_config_token(expected)
    )


def _refresh_commit_allowed(
    expected: dict[str, Any],
    before_persist: Callable[[], bool] | None,
) -> bool:
    if not _device_config_is_current(expected):
        return False
    if before_persist is None:
        return True
    try:
        return bool(before_persist())
    except Exception:
        return False


def _superseded_refresh_result(key: str) -> dict[str, Any]:
    return {
        "ok": False,
        "device_ref": key,
        "items": [],
        "accounts": [],
        "total": 0,
        "refresh_error": "设备配置已变化，本次刷新结果已丢弃",
        "partial_errors": [],
        "superseded": True,
    }


def _public_base(internal: dict[str, Any]) -> dict[str, Any]:
    provider = normalize_provider(internal.get("provider"))
    provider_id = int(internal.get("provider_id") or internal.get("id") or 0)
    result = {
        "id": device_key(provider, provider_id),
        "device_ref": device_key(provider, provider_id),
        "device_key": device_key(provider, provider_id),
        "provider": provider,
        "provider_id": provider_id,
        "type": provider,
        "name": str(internal.get("name") or "").strip(),
        "api_url": str(internal.get("api_url") or "").strip().rstrip("/"),
        "api_key_configured": bool(str(internal.get("api_key") or "").strip()),
        "enabled": bool(internal.get("enabled", True)),
    }
    if provider == "sub2api":
        result["sub_group_ids"] = str(internal.get("sub_group_ids") or "2")
    return result


def _state_map() -> dict[str, DeliveryDeviceMonitorStateModel]:
    with Session(engine) as session:
        rows = session.exec(select(DeliveryDeviceMonitorStateModel)).all()
        # Materialize every used field before the session closes.
        return {
            row.device_key: DeliveryDeviceMonitorStateModel(
                device_key=row.device_key,
                provider=row.provider,
                provider_id=row.provider_id,
                account_count=row.account_count,
                refreshed_at=row.refreshed_at,
                refresh_error=row.refresh_error,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        }


def _normalized_email(value: Any) -> str:
    return str(value or "").strip().casefold()


def _json_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _positive_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(str(value or "").strip())
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _plan_target_tab(plan: dict[str, Any]) -> str:
    if str(plan.get("catalog_category") or "").strip().lower() == "refunded":
        return "refunded"
    plan_type = str(plan.get("plan_type") or "").strip().lower()
    return "regular" if plan_type in {"", "free", "chatgptfreeplan"} else "member"


def _delivery_link_key(
    provider: str,
    provider_id: int,
    remote_id: Any,
) -> tuple[str, int, str] | None:
    remote = str(remote_id or "").strip()
    if not remote:
        return None
    return provider, int(provider_id), remote


def _navigation_context() -> dict[str, Any]:
    """Build a credential-free, batch navigation index for device snapshots.

    Device/account navigation is read-only.  A persisted device id + remote id
    link is authoritative.  Legacy rows without that link may use a normalized
    exact-email fallback only when the local GPT identity and its current
    BUSINESS lifecycle are globally unique.  No token, cookie, device key or
    raw ``extra_json`` leaves this function.
    """
    with Session(engine) as session:
        # Compatibility spelling, authoritative rows: this query reads the
        # GPT plan table after the one-time id cutover.
        pro_rows = session.exec(select(GptProAccountModel)).all()
        membership_rows = session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.ended_at.is_(None)  # type: ignore[union-attr]
            )
        ).all()
        parent_rows = session.exec(select(GptBusinessAccountModel)).all()
        plan_rows = list(pro_rows)

    accounts: dict[int, dict[str, Any]] = {}
    identities_by_email: dict[str, list[tuple[str, int]]] = {}
    device_links: dict[
        tuple[str, int, str],
        list[tuple[str, int]],
    ] = {}
    for row in pro_rows:
        # BUSINESS mother catalogue rows mirror a separate mother workspace
        # identity.  Do not register them a second time as a plan-owned
        # PRO/child credential identity.
        if str(getattr(row, "source_pool", "") or "").strip() == "gpt_business":
            continue
        account_id = _positive_int(row.id)
        if account_id <= 0:
            continue
        email = _normalized_email(row.email)
        parent_id = _positive_int(row.business_parent_id)
        accounts[account_id] = {
            "account_id": account_id,
            "email": email,
            "business_parent_id": parent_id,
        }
        if email:
            identities_by_email.setdefault(email, []).append(
                ("gpt_plan", account_id)
            )

        extra = _json_object(row.extra_json)
        if bool(extra.get("cpa_synced")):
            cpa_id = _positive_int(
                extra.get("cpa_synced_to_id") or extra.get("cpa_device_id")
            )
            key = _delivery_link_key("cpa", cpa_id, extra.get("cpa_auth_name"))
            if key and cpa_id > 0:
                device_links.setdefault(key, []).append(("gpt_plan", account_id))
        sub_id = _positive_int(extra.get("sub2api_device_id"))
        key = _delivery_link_key(
            "sub2api",
            sub_id,
            extra.get("sub2api_remote_account_id"),
        )
        if key and sub_id > 0:
            device_links.setdefault(key, []).append(("gpt_plan", account_id))

    memberships_by_child: dict[int, list[dict[str, Any]]] = {}
    memberships_by_email: dict[str, list[dict[str, Any]]] = {}
    for row in membership_rows:
        membership_id = _positive_int(row.id)
        parent_id = _positive_int(row.business_account_id)
        child_id = _positive_int(row.pro_account_id)
        email = _normalized_email(row.email)
        item = {
            "membership_id": membership_id,
            "business_parent_id": parent_id,
            "pro_account_id": child_id,
            "email": email,
            "seat_type": str(row.seat_type or "").strip().lower(),
        }
        if child_id:
            memberships_by_child.setdefault(child_id, []).append(item)
        if email:
            memberships_by_email.setdefault(email, []).append(item)

    parent_emails: dict[int, str] = {}
    parent_notes: dict[int, str] = {}
    for row in parent_rows:
        parent_id = _positive_int(row.id)
        if parent_id <= 0:
            continue
        email = _normalized_email(row.email)
        parent_emails[parent_id] = email
        parent_notes[parent_id] = _bounded_text(row.note, 500)
        if email:
            identities_by_email.setdefault(email, []).append(
                ("gpt_business", parent_id)
            )
        extra = _json_object(row.extra_json)
        cpa_state = extra.get("business_master_cpa")
        cpa_state = cpa_state if isinstance(cpa_state, dict) else {}
        cpa_link = cpa_state.get("link")
        cpa_link = cpa_link if isinstance(cpa_link, dict) else {}
        cpa_id = _positive_int(cpa_link.get("target_id"))
        key = _delivery_link_key("cpa", cpa_id, cpa_link.get("auth_name"))
        if key and cpa_id > 0:
            device_links.setdefault(key, []).append(
                ("gpt_business", parent_id)
            )
        sub_state = extra.get("business_master_sub2api")
        sub_state = sub_state if isinstance(sub_state, dict) else {}
        sub_link = sub_state.get("link")
        sub_link = sub_link if isinstance(sub_link, dict) else {}
        sub_id = _positive_int(sub_link.get("device_id"))
        key = _delivery_link_key(
            "sub2api",
            sub_id,
            sub_link.get("remote_account_id"),
        )
        if key and sub_id > 0:
            device_links.setdefault(key, []).append(
                ("gpt_business", parent_id)
            )
    plans_by_source: dict[tuple[str, int], list[dict[str, Any]]] = {}
    plans_by_id: dict[int, dict[str, Any]] = {}
    for row in plan_rows:
        plan_id = _positive_int(row.id)
        if plan_id <= 0:
            continue
        plan_item = {
            "plan_account_id": plan_id,
            "email": _normalized_email(row.email),
            "catalog_category": str(row.catalog_category or ""),
            "plan_type": str(row.plan_type or ""),
        }
        plans_by_id[plan_id] = plan_item
        source_pool = str(row.source_pool or "").strip()
        source_id = _positive_int(row.source_account_id)
        # Only BUSINESS mother catalogue provenance still needs a source
        # cross-reference.  Plan-owned PRO/regular/child rows resolve by their
        # own stable plan id and never through legacy GPT PRO provenance.
        if source_pool != "gpt_business" or source_id <= 0:
            continue
        plans_by_source.setdefault((source_pool, source_id), []).append(plan_item)

    return {
        "accounts": accounts,
        "identities_by_email": identities_by_email,
        "device_links": device_links,
        "memberships_by_child": memberships_by_child,
        "memberships_by_email": memberships_by_email,
        "parent_emails": parent_emails,
        "parent_notes": parent_notes,
        "plans_by_source": plans_by_source,
        "plans_by_id": plans_by_id,
    }


def _unavailable_navigation(state: str) -> dict[str, Any]:
    return {"state": state, "target_page": "gpt_plans"}


def _device_account_navigation(
    provider: str,
    provider_id: int,
    remote: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one safe GPT Plans deep-link target from authoritative state."""
    remote_id = str(remote.get("remote_id") or "").strip()
    remote_email = _normalized_email(remote.get("email"))
    link_key = _delivery_link_key(provider, provider_id, remote_id)
    raw_linked = list(
        (context.get("device_links") or {}).get(link_key, [])
    ) if link_key else []
    linked = list(dict.fromkeys(
        (str(item[0]), _positive_int(item[1]))
        for item in raw_linked
        if isinstance(item, (list, tuple))
        and len(item) == 2
        and str(item[0]) in {"gpt_plan", "gpt_business"}
        and _positive_int(item[1]) > 0
    ))

    match_basis = "device_link"
    if linked:
        candidates = linked
    else:
        match_basis = "exact_email"
        if not remote_email:
            return _unavailable_navigation("unmapped")
        candidates = list(dict.fromkeys(
            (str(item[0]), _positive_int(item[1]))
            for item in (context.get("identities_by_email") or {}).get(remote_email, [])
            if isinstance(item, (list, tuple))
            and len(item) == 2
            and str(item[0]) in {"gpt_plan", "gpt_business"}
            and _positive_int(item[1]) > 0
        ))
        if not candidates:
            return _unavailable_navigation("unmapped")

    if len(candidates) != 1:
        return _unavailable_navigation("ambiguous")
    identity_kind, identity_id = candidates[0]

    if identity_kind == "gpt_business":
        parent_id = identity_id
        parent_email = _normalized_email(
            (context.get("parent_emails") or {}).get(parent_id)
        )
        if not parent_email or (remote_email and remote_email != parent_email):
            return _unavailable_navigation("conflict")
        # An email-only match cannot choose between a mother and an active
        # child with the same email.  A direct mother device link remains the
        # authoritative identity and intentionally bypasses this legacy guard.
        if (
            match_basis == "exact_email"
            and (context.get("memberships_by_email") or {}).get(parent_email)
        ):
            return _unavailable_navigation("ambiguous")
        plans = list(
            (context.get("plans_by_source") or {}).get(
                ("gpt_business", parent_id),
                [],
            )
        )
        if len(plans) != 1:
            return _unavailable_navigation(
                "source_missing" if not plans else "ambiguous"
            )
        plan = plans[0]
        if _normalized_email(plan.get("email")) != parent_email:
            return _unavailable_navigation("conflict")
        return {
            "state": "mapped",
            "match_basis": match_basis,
            "target_kind": "business_parent",
            "target_page": "gpt_plans",
            "plan_account_id": _positive_int(plan.get("plan_account_id")),
            "target_tab": _plan_target_tab(plan),
            "source_pool": "gpt_business",
            "source_account_id": parent_id,
            "pro_account_id": None,
            "business_parent_id": parent_id,
            "business_parent_email": parent_email,
            "business_parent_note": _bounded_text(
                (context.get("parent_notes") or {}).get(parent_id),
                500,
            ),
            "membership_id": None,
        }

    account_id = identity_id
    account = (context.get("accounts") or {}).get(account_id)
    if not isinstance(account, dict):
        return _unavailable_navigation("conflict")
    account_email = _normalized_email(account.get("email"))
    if remote_email and remote_email != account_email:
        # A stable remote id pointing at a different email is an identity
        # conflict.  Never let exact-email fallback override that durable link.
        return _unavailable_navigation("conflict")

    parent_id = _positive_int(account.get("business_parent_id"))
    child_memberships = list(
        (context.get("memberships_by_child") or {}).get(account_id, [])
    )
    same_email_memberships = list(
        (context.get("memberships_by_email") or {}).get(account_email, [])
    ) if account_email else []

    if parent_id > 0:
        current = [
            item for item in child_memberships
            if _positive_int(item.get("business_parent_id")) == parent_id
            and _positive_int(item.get("pro_account_id")) == account_id
            and _positive_int(item.get("membership_id")) > 0
            and _normalized_email(item.get("email")) in {"", account_email}
        ]
        # Exact-email fallback is safe only when this email denotes this one
        # active child lifecycle globally.  Device-link matches use the same
        # lifecycle uniqueness guard because the UI must not jump to a stale
        # or duplicate membership.
        lifecycle_keys = {
            (
                _positive_int(item.get("business_parent_id")),
                _positive_int(item.get("pro_account_id")),
                _positive_int(item.get("membership_id")),
            )
            for item in same_email_memberships
        }
        if len(current) != 1 or lifecycle_keys != {
            (parent_id, account_id, _positive_int(current[0].get("membership_id")))
        }:
            return _unavailable_navigation("ambiguous")
        membership = current[0]
        parent_email = _normalized_email(
            (context.get("parent_emails") or {}).get(parent_id)
        )
        if not parent_email:
            return _unavailable_navigation("conflict")
        plans = list(
            (context.get("plans_by_source") or {}).get(("gpt_business", parent_id), [])
        )
        if len(plans) != 1:
            return _unavailable_navigation("source_missing" if not plans else "ambiguous")
        plan = plans[0]
        if _normalized_email(plan.get("email")) != parent_email:
            return _unavailable_navigation("conflict")
        return {
            "state": "mapped",
            "match_basis": match_basis,
            "target_kind": "business_child",
            "target_page": "gpt_plans",
            "plan_account_id": _positive_int(plan.get("plan_account_id")),
            "target_tab": _plan_target_tab(plan),
            "source_pool": "gpt_business",
            "source_account_id": parent_id,
            "pro_account_id": account_id,
            "business_parent_id": parent_id,
            "business_parent_email": parent_email,
            "business_parent_note": _bounded_text(
                (context.get("parent_notes") or {}).get(parent_id),
                500,
            ),
            "seat_type": str(membership.get("seat_type") or "").strip().lower(),
            "membership_id": _positive_int(membership.get("membership_id")),
        }

    # A row advertised as an ordinary PRO cannot simultaneously have an active
    # BUSINESS membership.  Treat stale cross-pool lifecycle state as a
    # conflict even when its email is unique.
    if child_memberships or same_email_memberships:
        return _unavailable_navigation("conflict")
    plan = (context.get("plans_by_id") or {}).get(account_id)
    if not isinstance(plan, dict):
        return _unavailable_navigation("source_missing")
    if _normalized_email(plan.get("email")) != account_email:
        return _unavailable_navigation("conflict")
    return {
        "state": "mapped",
        "match_basis": match_basis,
        "target_page": "gpt_plans",
        "target_kind": "pro_account",
        "plan_account_id": _positive_int(plan.get("plan_account_id")),
        "target_tab": _plan_target_tab(plan),
        "source_pool": "gpt_plan",
        "source_account_id": account_id,
        "pro_account_id": account_id,
        "business_parent_id": None,
        "membership_id": None,
    }


def _snapshot_items(
    key: str,
    *,
    navigation_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    try:
        provider, provider_id = parse_device_key(key)
    except ValueError:
        provider, provider_id = "", 0
    with Session(engine) as session:
        rows = session.exec(
            select(DeliveryDeviceAccountSnapshotModel)
            .where(DeliveryDeviceAccountSnapshotModel.device_key == key)
            .order_by(DeliveryDeviceAccountSnapshotModel.remote_id)
        ).all()
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row.payload_json or "{}")
            except Exception:
                payload = {}
            if isinstance(payload, dict):
                # Device inventory is intentionally independent from BUSINESS
                # mother/member attribution. Drop navigation left by older
                # snapshots instead of rehydrating it from account tables.
                payload.pop("navigation", None)
                # Older snapshots stored the sanitized quota payload but did
                # not project its plan_type to the table-facing top level.
                # Enrich the read DTO without weakening the payload allowlist.
                plan = str(payload.get("plan") or "").strip()
                if not plan:
                    plan = _usage_plan_code(payload.get("usage"))
                    if plan:
                        payload["plan"] = plan
                if plan and not str(payload.get("plan_label") or "").strip():
                    payload["plan_label"] = _plan_label(plan)
                if navigation_context is not None and provider and provider_id > 0:
                    payload["navigation"] = _device_account_navigation(
                        provider,
                        provider_id,
                        payload,
                        navigation_context,
                    )
                items.append(payload)
        return items


def _public_device(
    internal: dict[str, Any],
    *,
    state: DeliveryDeviceMonitorStateModel | None = None,
    include_accounts: bool = False,
    navigation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = _public_base(internal)
    key = str(result["device_key"])
    refresh_error = str(state.refresh_error or "") if state else ""
    result.update({
        "account_count": int(state.account_count or 0) if state else 0,
        "accounts_refreshed_at": (
            state.refreshed_at.isoformat() if state and state.refreshed_at else None
        ),
        "accounts_refresh_error": refresh_error,
    })
    if include_accounts:
        accounts = _snapshot_items(
            key,
            navigation_context=navigation_context,
        )
        partial_errors = _partial_quota_errors(accounts)
        warning = _quota_warning(len(partial_errors))
        fatal_error = refresh_error if refresh_error and refresh_error != warning else ""
        result.update({
            "accounts": accounts,
            "accounts_refresh_ok": not bool(fatal_error),
            "accounts_refresh_fatal_error": fatal_error,
            "accounts_warning": warning,
            "accounts_warning_count": len(partial_errors),
        })
    return result


def list_devices(*, include_accounts: bool = True) -> dict[str, Any]:
    """Return the two canonical registries as one credential-free view."""
    states = _state_map()
    items: list[dict[str, Any]] = []
    cpa_targets, revision = _cpa_targets_snapshot()
    for target in cpa_targets:
        try:
            provider_id = int(target.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if provider_id <= 0:
            continue
        internal = {
            "provider": "cpa",
            "provider_id": provider_id,
            "name": str(target.get("name") or "").strip(),
            "api_url": str(target.get("api_url") or "").strip().rstrip("/"),
            "api_key": str(target.get("api_key") or "").strip(),
            "enabled": True,
        }
        key = device_key("cpa", provider_id)
        items.append(_public_device(
            internal,
            state=states.get(key),
            include_accounts=include_accounts,
            navigation_context=None,
        ))
    for row in _sub2api_device_rows():
        internal = {
            "provider": "sub2api",
            "provider_id": int(row["id"]),
            **row,
        }
        key = device_key("sub2api", row["id"])
        items.append(_public_device(
            internal,
            state=states.get(key),
            include_accounts=include_accounts,
            navigation_context=None,
        ))
    items.sort(key=lambda item: (str(item["provider"]), int(item["provider_id"])))
    return {"ok": True, "items": items, "cpa_revision": revision}


def get_device(device_ref: str, *, include_accounts: bool = True) -> dict[str, Any] | None:
    provider, provider_id = parse_device_key(device_ref)
    internal = _internal_device(provider, provider_id)
    if not internal:
        return None
    key = device_key(provider, provider_id)
    with Session(engine) as session:
        state = session.get(DeliveryDeviceMonitorStateModel, key)
        detached = None
        if state:
            detached = DeliveryDeviceMonitorStateModel(
                device_key=state.device_key,
                provider=state.provider,
                provider_id=state.provider_id,
                account_count=state.account_count,
                refreshed_at=state.refreshed_at,
                refresh_error=state.refresh_error,
                created_at=state.created_at,
                updated_at=state.updated_at,
            )
    return _public_device(
        internal,
        state=detached,
        include_accounts=include_accounts,
        navigation_context=None,
    )


def _quota_percentage(value: Any, *, _depth: int = 0) -> float | None:
    if _depth >= 12:
        return None
    found: list[float] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in {
                "percentage", "percent", "usage_percent", "used_percent",
                "utilization", "usage_5h_percent", "usage_week_percent",
                "p5_used_percent", "week_used_percent",
            } and isinstance(item, (int, float)) and not isinstance(item, bool):
                number = float(item)
                if normalized == "utilization" and 0 <= number <= 1:
                    number *= 100
                if 0 <= number <= 100:
                    found.append(number)
            nested = _quota_percentage(item, _depth=_depth + 1)
            if nested is not None:
                found.append(nested)
    elif isinstance(value, list):
        for item in value:
            nested = _quota_percentage(item, _depth=_depth + 1)
            if nested is not None:
                found.append(nested)
    return max(found) if found else None


def _literal_limit_reached(value: Any, *, _depth: int = 0) -> bool:
    if _depth >= 12:
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized == "limit_reached" and item is True:
                return True
            if normalized in {"status", "state", "error_code"} and str(item or "").strip().lower() in {
                "limit_reached", "quota_exceeded", "exhausted", "depleted",
            }:
                return True
            if _literal_limit_reached(item, _depth=_depth + 1):
                return True
    elif isinstance(value, list):
        return any(_literal_limit_reached(item, _depth=_depth + 1) for item in value)
    return False


def _usage_state(usage: Any, *, disabled: bool = False, error: str = "") -> tuple[str, float | None, bool]:
    if disabled:
        return "disabled", _quota_percentage(usage), False
    if error:
        return "error", _quota_percentage(usage), False
    percent = _quota_percentage(usage)
    limited = _literal_limit_reached(usage) or (percent is not None and percent >= 100)
    if limited:
        return "limit_reached", percent, True
    if usage:
        return "ok", percent, False
    return "unknown", percent, False


def _usage_plan_code(value: Any, *, _depth: int = 0) -> str:
    """Extract a sanitized plan code from known quota response containers."""
    if _depth >= 8 or not isinstance(value, dict):
        return ""
    for key in (
        "plan_type", "plan_name", "subscription_plan", "subscription_tier",
        "plan", "tier",
    ):
        item = value.get(key)
        if isinstance(item, (str, int, float)) and not isinstance(item, bool):
            plan = _bounded_text(item, 120)
            if plan:
                return plan
    for key in (
        "data", "usage", "quota", "subscription", "openai", "chatgpt", "codex",
    ):
        nested = value.get(key)
        if isinstance(nested, dict):
            plan = _usage_plan_code(nested, _depth=_depth + 1)
            if plan:
                return plan
    return ""


def _plan_label(plan: Any) -> str:
    """Return a closed operator-facing label while retaining the raw code."""
    code = str(plan or "").strip()
    normalized = re.sub(
        r"[^a-z0-9]+",
        "_",
        code.casefold(),
    ).strip("_")
    if not normalized:
        return "未知套餐"
    if normalized in {"self_serve_business_prolite", "team_5x"}:
        return "TEAM 5X 套餐"
    if normalized in {
        "team", "chatgptteamplan", "business", "chatgptbusinessplan",
        "self_serve_business",
    }:
        return "BUSINESS 普通席位"
    if normalized == "business_master":
        return "BUSINESS 母号"
    if normalized in {
        "pro", "chatgpt_pro", "chatgptpro", "chatgptproplan",
        "self_serve_pro", "pro_20x", "gpt_pro", "gpt_pro_20x",
    }:
        return "GPT PRO"
    if normalized in {
        "plus", "chatgpt_plus", "chatgptplus", "chatgptplusplan",
        "self_serve_plus",
    }:
        return "ChatGPT Plus"
    if normalized in {
        "go", "chatgpt_go", "chatgptgo", "chatgptgoplan",
        "self_serve_go",
    }:
        return "ChatGPT GO"
    if normalized in {
        "free", "chatgpt_free", "chatgptfreeplan", "self_serve_free",
    }:
        return "Free"
    return "未知套餐"


_KNOWN_PLAN_CODES = frozenset({
    "free", "chatgpt_free", "chatgptfreeplan", "self_serve_free",
    "go", "chatgpt_go", "chatgptgo", "chatgptgoplan", "self_serve_go",
    "plus", "chatgpt_plus", "chatgptplus", "chatgptplusplan",
    "self_serve_plus",
    "pro", "gpt_pro", "gpt_pro_20x", "chatgpt_pro",
    "chatgpt_pro_plan", "chatgptpro", "chatgptproplan",
    "self_serve_pro", "pro_20x",
    "team", "team_5x", "chatgptteamplan", "business",
    "business_master", "chatgptbusinessplan", "self_serve_business",
    "self_serve_business_prolite",
})


def _normalized_plan_code(plan: Any) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(plan or "").strip().casefold(),
    ).strip("_")


def is_known_plan(plan: Any) -> bool:
    return _normalized_plan_code(plan) in _KNOWN_PLAN_CODES


def is_pro_plan(plan: Any) -> bool:
    """Return whether one explicit plan code denotes ChatGPT PRO.

    This is a positive allowlist. BUSINESS ``prolite``/5X seats are classified
    separately as TEAM/BUSINESS even though the inventory refresh also probes
    their quota.
    """
    normalized = _normalized_plan_code(plan)
    compact = normalized.replace("_", "")
    return normalized in {
        "pro",
        "gpt_pro",
        "gpt_pro_20x",
        "chatgpt_pro",
        "chatgpt_pro_plan",
        "self_serve_pro",
        "pro_20x",
    } or compact in {
        "pro",
        "gptpro",
        "gptpro20x",
        "chatgptpro",
        "chatgptproplan",
        "selfservepro",
        "pro20x",
    }


def is_team_plan(plan: Any) -> bool:
    """Return whether a plan can denote one TEAM/BUSINESS child credential.

    ``business_master`` is the workspace owner itself, not a child credential.
    It must not enter the child-quota inventory or be grouped under itself.
    """
    return _normalized_plan_code(plan) in {
        "team",
        "team_5x",
        "chatgptteamplan",
        "business",
        "chatgptbusinessplan",
        "self_serve_business",
        "self_serve_business_prolite",
    }


def _is_team_child_quota_eligible(
    plan: Any,
    navigation: dict[str, Any] | None,
) -> bool:
    """Keep mapped BUSINESS parents out of the TEAM-child quota lane."""
    if not is_team_plan(plan):
        return False
    target_kind = str(
        (navigation or {}).get("target_kind") or ""
    ).strip().lower()
    return target_kind != "business_parent"


_QUOTA_ERROR_MESSAGES = {
    "401": "额度查询返回 HTTP 401，账号凭证异常",
    "403": "额度查询返回 HTTP 403",
    "429": "额度查询受限（HTTP 429）",
    "http_5xx": "额度服务暂时不可用（HTTP 5xx）",
    "timeout": "额度查询超时",
    "scan_error": "额度查询失败",
    "identity_missing": "缺少额度查询标识",
    "mapping_unavailable": "本地归属映射不可用",
}


def _exception_http_status(exc: Any) -> int:
    try:
        status = int(getattr(exc, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    response = getattr(exc, "response", None)
    if not status and response is not None:
        try:
            status = int(getattr(response, "status_code", 0) or 0)
        except (TypeError, ValueError):
            status = 0
    return status if 100 <= status <= 599 else 0


def _quota_error_code(
    *statuses: Any,
    exceptions: tuple[Any, ...] = (),
) -> tuple[str, int]:
    safe_statuses: list[int] = []
    for value in statuses:
        try:
            parsed = int(value or 0)
        except (TypeError, ValueError):
            continue
        if 100 <= parsed <= 599 and parsed not in safe_statuses:
            safe_statuses.append(parsed)
    for exc in exceptions:
        parsed = _exception_http_status(exc)
        if parsed and parsed not in safe_statuses:
            safe_statuses.append(parsed)
    for preferred in (401, 403, 429):
        if preferred in safe_statuses:
            return str(preferred), preferred
    for status in safe_statuses:
        if 500 <= status <= 599:
            return "http_5xx", status
    if safe_statuses:
        return "scan_error", safe_statuses[0]
    for exc in exceptions:
        name = type(exc).__name__.casefold()
        if isinstance(exc, TimeoutError) or "timeout" in name:
            return "timeout", 0
    return "scan_error", 0


def _quota_error_message(code: Any) -> str:
    return _QUOTA_ERROR_MESSAGES.get(str(code or ""), "额度查询失败")


def _remaining_quota_percent(
    usage_status: Any,
    usage_percent: Any,
    limit_reached: Any,
) -> float | int | None:
    """Convert a confirmed used percentage to remaining percentage."""
    if limit_reached is True:
        return 0
    if str(usage_status or "").strip().lower() != "ok":
        return None
    if isinstance(usage_percent, bool) or not isinstance(
        usage_percent, (int, float)
    ):
        return None
    remaining = max(0.0, min(100.0, 100.0 - float(usage_percent)))
    return int(remaining) if remaining.is_integer() else remaining


def _local_cpa_oauth_claims(email: str) -> dict[str, str]:
    """Resolve non-secret CPA probe metadata for a locally managed account.

    Newer CLIProxyAPI auth-file listings may omit ``id_token`` even though the
    uploaded access/refresh-token pair is valid.  The monitor still needs the
    workspace account id for ``wham/usage``.  Decode it from the fresh local AT
    in memory only; neither the token nor its payload is persisted in snapshots.
    """
    normalized = str(email or "").strip()
    if not normalized:
        return {}
    try:
        with Session(engine) as session:
            account = session.exec(
                select(GptProAccountModel).where(
                    GptProAccountModel.email == normalized
                )
            ).first()
            if not account or not str(account.codex_access_token or "").strip():
                return {}
            access_token = str(account.codex_access_token)
            membership = None
            if account.business_parent_id is not None:
                membership = session.exec(
                    select(GptBusinessChildMembershipModel).where(
                        GptBusinessChildMembershipModel.pro_account_id == int(account.id),
                        GptBusinessChildMembershipModel.ended_at.is_(None),  # type: ignore[union-attr]
                    )
                ).first()
        from platforms.chatgpt.utils import decode_jwt_payload

        payload = decode_jwt_payload(access_token) or {}
        auth = payload.get("https://api.openai.com/auth") or {}
        if not isinstance(auth, dict):
            auth = {}
        plan = str(auth.get("chatgpt_plan_type") or "").strip()
        if str(getattr(membership, "seat_type", "") or "").strip().lower() == "prolite":
            plan = "self_serve_business_prolite"
        return {
            "account_id": str(auth.get("chatgpt_account_id") or "").strip(),
            "plan": plan,
        }
    except Exception:
        return {}


def _cpa_public_account(
    raw: dict[str, Any],
    *,
    api_url: str,
    api_key: str,
    pro_quota_only: bool = False,
    include_team_quota: bool = True,
    navigation_context: dict[str, Any] | None = None,
    provider_id: int = 0,
) -> dict[str, Any]:
    from services.gpt_plan_cpa_manager import (
        _clear_last_account_usage_probe,
        _fetch_account_usage,
        _last_account_usage_probe,
    )

    checked_at = _utcnow().isoformat()
    secrets = tuple(dict.fromkeys((str(api_key or ""), *_known_secret_values(raw))))
    name = _safe_text(raw.get("name"), secrets=secrets)
    email = _safe_text(raw.get("email") or raw.get("account"), secrets=secrets)
    if not email and name.lower().endswith(".json") and "@" in name:
        email = name[:-5]
    # CPA auth-file names are stable identities and are already visible to the
    # operator. auth_index remains internal because it selects a credential.
    remote_id = name or email
    if not remote_id:
        fingerprint = json.dumps(
            {
                "provider": _safe_text(raw.get("provider") or raw.get("type"), secrets=secrets),
                "status": _safe_text(raw.get("status"), secrets=secrets),
                "updated_at": _safe_text(raw.get("updated_at") or raw.get("last_refresh"), secrets=secrets),
            },
            sort_keys=True,
        )
        remote_id = "auth-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:20]
    id_token = raw.get("id_token") if isinstance(raw.get("id_token"), dict) else {}
    disabled = bool(raw.get("disabled"))
    usage: dict[str, Any] = {}
    error = ""
    credential_status_code = 0
    credential_error_code = ""
    credential_repair_required = False
    quota_error_code = ""
    quota_http_status = 0
    auth_index = str(raw.get("auth_index") or "").strip()
    account_id = str(id_token.get("chatgpt_account_id") or "").strip()
    plan = _safe_text(id_token.get("plan_type"), secrets=secrets)
    if (not account_id or not plan) and email:
        local_claims = _local_cpa_oauth_claims(email)
        account_id = account_id or str(local_claims.get("account_id") or "").strip()
        plan = plan or _safe_text(local_claims.get("plan"), secrets=secrets)
    navigation = (
        _device_account_navigation(
            "cpa",
            int(provider_id),
            {"remote_id": remote_id, "email": email},
            navigation_context,
        )
        if navigation_context is not None and int(provider_id) > 0
        else {}
    )
    quota_plan_eligible = bool(
        is_pro_plan(plan)
        or (
            include_team_quota
            and _is_team_child_quota_eligible(plan, navigation)
        )
    )
    should_query_quota = bool(
        not disabled
        and auth_index
        and account_id
        and (not pro_quota_only or quota_plan_eligible)
    )
    if should_query_quota:
        # Clear the worker-local diagnosis first.  Existing tests and rolling
        # deployments may replace ``_fetch_account_usage`` with the legacy
        # callable; an absent probe then safely remains a generic warning.
        _clear_last_account_usage_probe()
        try:
            raw_usage = _fetch_account_usage(
                api_url,
                api_key,
                auth_index,
                account_id,
            )
            probe = _last_account_usage_probe()
        except Exception as exc:
            # Preserve the already-classified identity.  Falling through to
            # the generic parallel-worker row would erase ``plan=pro`` and
            # make a failed PRO quota probe look like an unknown plan.
            raw_usage = None
            probe = {}
            quota_error_code, quota_http_status = _quota_error_code(
                exceptions=(exc,),
            )
        if isinstance(raw_usage, dict):
            usage = {
                "usage_5h_percent": raw_usage.get("p5_used_percent"),
                "usage_5h_reset_at": raw_usage.get("p5_reset_at"),
                "usage_5h_window_seconds": raw_usage.get("p5_window_seconds"),
                "usage_week_percent": raw_usage.get("week_used_percent"),
                "usage_week_reset_at": raw_usage.get("week_reset_at"),
                "usage_week_window_seconds": raw_usage.get("week_window_seconds"),
                "limit_reached": raw_usage.get("limit_reached") if isinstance(raw_usage.get("limit_reached"), bool) else None,
                "credit_balance": raw_usage.get("credit_balance"),
            }
        else:
            credential_status_code = int(probe.get("status_code") or 0)
            management_status_code = int(
                probe.get("management_status_code") or 0
            )
            credential_error_code = _safe_text(
                probe.get("error_code"),
                secrets=secrets,
                limit=96,
            )
            credential_repair_required = bool(
                probe.get("credential_repair_required")
                and credential_status_code == 401
                and 200 <= int(probe.get("management_status_code") or 0) < 300
            )
            if not quota_error_code:
                quota_error_code, quota_http_status = _quota_error_code(
                    credential_status_code,
                    management_status_code,
                )
            error = _quota_error_message(quota_error_code)
    elif (
        not disabled
        and (not pro_quota_only or quota_plan_eligible)
    ):
        quota_error_code = "identity_missing"
        error = _quota_error_message(quota_error_code)
    if pro_quota_only and not disabled and not quota_plan_eligible:
        usage_status, usage_percent, limit_reached = "skipped", None, False
    else:
        usage_status, usage_percent, limit_reached = _usage_state(
            usage,
            disabled=disabled,
            error=error,
        )
    remaining_percent = _remaining_quota_percent(
        usage_status,
        usage_percent,
        limit_reached,
    )
    if (
        should_query_quota
        and usage_status == "ok"
        and remaining_percent is None
    ):
        quota_error_code = quota_error_code or "scan_error"
        error = _quota_error_message(quota_error_code)
        usage_status = "error"
    return {
        "remote_id": remote_id[:500],
        "email": email,
        "name": name,
        "provider": _safe_text(raw.get("provider") or raw.get("type"), secrets=secrets) or "codex",
        "status": _safe_text(raw.get("status"), secrets=secrets),
        "disabled": disabled,
        "plan": plan,
        "plan_label": _plan_label(plan),
        "usage": usage,
        "usage_percent": usage_percent,
        "remaining_percent": remaining_percent,
        "quota_checked": bool(should_query_quota),
        "limit_reached": limit_reached,
        "usage_status": usage_status,
        "checked_at": checked_at,
        "error": error,
        "quota_error_code": quota_error_code,
        "quota_http_status": (
            quota_http_status if quota_http_status else None
        ),
        "account_issue": quota_error_code == "401",
        "credential_repair_status": (
            credential_status_code if credential_status_code else None
        ),
        "credential_repair_code": credential_error_code,
        "credential_repair_required": credential_repair_required,
    }


def _sub2api_public_account(
    identity: dict[str, Any],
    *,
    api_url: str,
    api_key: str,
    pro_quota_only: bool = False,
    include_team_quota: bool = True,
    navigation_context: dict[str, Any] | None = None,
    provider_id: int = 0,
) -> dict[str, Any]:
    from services.sub2api_admin import (
        Sub2ApiAdminError,
        get_account_usage,
        query_openai_quota,
        sanitize_admin_payload,
    )

    checked_at = _utcnow().isoformat()
    secrets = tuple(dict.fromkeys((str(api_key or ""), *_known_secret_values(identity))))
    remote_id = _safe_text(
        identity.get("id") or identity.get("account_id"),
        secrets=secrets,
        limit=128,
    )
    disabled = bool(identity.get("disabled")) or (
        identity.get("schedulable") is False
    ) or str(identity.get("status") or "").strip().lower() in {
        "disabled", "inactive",
    }
    usage: Any = {}
    error = ""
    credential_status_code = 0
    credential_error_code = ""
    credential_repair_required = False
    quota_error_code = ""
    quota_http_status = 0
    identity_plan = _safe_text(
        identity.get("plan") or identity.get("plan_type"),
        secrets=secrets,
    )
    if not identity_plan:
        local_claims = _local_cpa_oauth_claims(identity.get("email") or "")
        identity_plan = _safe_text(local_claims.get("plan"), secrets=secrets)
    email = _safe_text(identity.get("email"), secrets=secrets)
    navigation = (
        _device_account_navigation(
            "sub2api",
            int(provider_id),
            {"remote_id": remote_id, "email": email},
            navigation_context,
        )
        if navigation_context is not None and int(provider_id) > 0
        else {}
    )
    quota_plan_eligible = bool(
        is_pro_plan(identity_plan)
        or (
            include_team_quota
            and _is_team_child_quota_eligible(
                identity_plan,
                navigation,
            )
        )
    )
    should_query_quota = bool(
        not disabled
        and remote_id
        and (not pro_quota_only or quota_plan_eligible)
    )
    if should_query_quota:
        try:
            usage = query_openai_quota(api_url, api_key, remote_id)
        except Exception as primary_exc:
            try:
                usage = get_account_usage(
                    api_url,
                    api_key,
                    remote_id,
                    source="active",
                    force=True,
                )
            except Exception as fallback_exc:
                primary_status = (
                    int(primary_exc.status_code or 0)
                    if isinstance(primary_exc, Sub2ApiAdminError)
                    else 0
                )
                fallback_status = (
                    int(fallback_exc.status_code or 0)
                    if isinstance(fallback_exc, Sub2ApiAdminError)
                    else 0
                )
                quota_error_code, quota_http_status = _quota_error_code(
                    primary_status,
                    fallback_status,
                    exceptions=(primary_exc, fallback_exc),
                )
                credential_status_code = quota_http_status
                credential_error_code = (
                    "admin_or_credential_unauthorized"
                    if quota_error_code == "401"
                    else ""
                )
                # A Sub2API 401 may describe its admin key rather than the one
                # OpenAI child credential. It is still surfaced as an account
                # issue for this scan, but never authorizes OAuth or mutation.
                credential_repair_required = False
                error = _quota_error_message(quota_error_code)
                usage = {}
    elif (
        not disabled
        and (not pro_quota_only or quota_plan_eligible)
    ):
        quota_error_code = "identity_missing"
        error = _quota_error_message(quota_error_code)
    usage = sanitize_admin_payload(usage, secrets=(api_key,))
    # In the safe inventory mode the list/JWT identity is authoritative for
    # plan classification. Never probe an unknown plan and then infer it from
    # a quota response.
    plan = identity_plan if pro_quota_only else (_usage_plan_code(usage) or identity_plan)
    if pro_quota_only and not disabled and not quota_plan_eligible:
        usage_status, usage_percent, limit_reached = "skipped", None, False
    else:
        usage_status, usage_percent, limit_reached = _usage_state(
            usage,
            disabled=disabled,
            error=error,
        )
    remaining_percent = _remaining_quota_percent(
        usage_status,
        usage_percent,
        limit_reached,
    )
    if (
        should_query_quota
        and usage_status == "ok"
        and remaining_percent is None
    ):
        quota_error_code = quota_error_code or "scan_error"
        error = _quota_error_message(quota_error_code)
        usage_status = "error"
    safe_group_ids: list[int] = []
    if isinstance(identity.get("group_ids"), list):
        for value in identity["group_ids"][:100]:
            if isinstance(value, bool):
                continue
            try:
                parsed = int(str(value).strip())
            except (TypeError, ValueError):
                continue
            if parsed > 0 and parsed not in safe_group_ids:
                safe_group_ids.append(parsed)
    try:
        safe_group_id = int(str(identity.get("group_id") or "").strip())
    except (TypeError, ValueError):
        safe_group_id = 0
    return {
        "remote_id": remote_id,
        "email": email,
        "name": _safe_text(identity.get("name"), secrets=secrets),
        "provider": _safe_text(identity.get("platform") or identity.get("provider"), secrets=secrets) or "openai",
        "status": _safe_text(identity.get("status"), secrets=secrets),
        "disabled": disabled,
        "schedulable": identity.get("schedulable") is not False,
        "plan": plan,
        "plan_label": _plan_label(plan),
        "group_id": safe_group_id if safe_group_id > 0 else None,
        "group_ids": safe_group_ids,
        "usage": usage,
        "usage_percent": usage_percent,
        "remaining_percent": remaining_percent,
        "quota_checked": bool(should_query_quota),
        "limit_reached": limit_reached,
        "usage_status": usage_status,
        "checked_at": checked_at,
        "error": error,
        "quota_error_code": quota_error_code,
        "quota_http_status": (
            quota_http_status if quota_http_status else None
        ),
        "account_issue": quota_error_code == "401",
        "credential_repair_status": (
            credential_status_code if credential_status_code else None
        ),
        "credential_repair_code": credential_error_code,
        "credential_repair_required": credential_repair_required,
    }


def _quota_error_account(
    raw: dict[str, Any],
    *,
    secrets: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Keep a remote identity visible when its quota worker crashes."""
    name = _safe_text(raw.get("name"), secrets=secrets)
    email = _safe_text(
        raw.get("email") or raw.get("account_email") or raw.get("account"),
        secrets=secrets,
    )
    remote_id = _safe_text(
        raw.get("remote_id") or raw.get("id") or raw.get("account_id") or name or email,
        secrets=secrets,
        limit=500,
    )
    if not remote_id:
        identity = json.dumps(
            {
                "name": name,
                "email": email,
                "status": _safe_text(raw.get("status"), secrets=secrets),
            },
            sort_keys=True,
        )
        remote_id = "account-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return {
        "remote_id": remote_id,
        "email": email,
        "name": name,
        "provider": _safe_text(
            raw.get("platform") or raw.get("provider") or raw.get("type"),
            secrets=secrets,
        ),
        "status": _safe_text(raw.get("status"), secrets=secrets),
        "disabled": bool(raw.get("disabled")),
        "plan": "",
        "plan_label": "未知套餐",
        "usage": {},
        "usage_percent": None,
        "remaining_percent": None,
        "quota_checked": False,
        "limit_reached": False,
        "usage_status": "error",
        "checked_at": _utcnow().isoformat(),
        "error": "额度查询失败",
        "quota_error_code": "scan_error",
        "quota_http_status": None,
        "account_issue": False,
        "navigation": {},
    }


def _parallel_map_accounts(
    raw_items: list[dict[str, Any]],
    worker,
    *,
    secrets: tuple[str, ...] | list[str] = (),
) -> list[dict[str, Any]]:
    if not raw_items:
        return []
    results: list[dict[str, Any]] = []
    # Bounded fan-out keeps device saves responsive without launching one
    # network thread per credential on large pools.
    max_workers = min(4, len(raw_items))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="delivery-quota") as executor:
        futures = {executor.submit(worker, item): item for item in raw_items}
        for future in as_completed(futures):
            try:
                item = future.result()
            except Exception:
                # One malformed/temporarily unreachable account must not hide
                # every other account on the device.
                logger.warning("Delivery device account quota worker failed: type=%s", type(future.exception()).__name__)
                item = _quota_error_account(futures[future], secrets=secrets)
            if isinstance(item, dict):
                results.append(item)
    results.sort(key=lambda item: (
        str(item.get("email") or item.get("name") or "").casefold(),
        str(item.get("remote_id") or ""),
    ))
    return results


def _fetch_accounts(
    internal: dict[str, Any],
    *,
    pro_quota_only: bool = False,
    include_team_quota: bool = True,
) -> list[dict[str, Any]]:
    provider = normalize_provider(internal.get("provider"))
    api_url = str(internal.get("api_url") or "").strip()
    api_key = str(internal.get("api_key") or "").strip()
    try:
        provider_id = int(
            internal.get("provider_id") or internal.get("id") or 0
        )
    except (TypeError, ValueError):
        provider_id = 0
    # Inventory/quota snapshots deliberately do not consult BUSINESS mother,
    # membership or device-link tables.
    navigation_context = None
    if not api_url:
        raise RuntimeError("device_url_missing")
    if provider == "cpa":
        from services.cpa_manager import list_auth_files

        raw_items = list_auth_files(api_url=api_url, api_key=api_key)
        return _parallel_map_accounts(
            raw_items,
            lambda item: _cpa_public_account(
                item,
                api_url=api_url,
                api_key=api_key,
                pro_quota_only=pro_quota_only,
                include_team_quota=include_team_quota,
                navigation_context=navigation_context,
                provider_id=provider_id,
            ),
            secrets=(api_key, *(
                secret
                for item in raw_items
                for secret in _known_secret_values(item)
            )),
        )
    if provider == "sub2api":
        from services.sub2api_admin import list_accounts

        identities = list_accounts(
            api_url,
            api_key,
            group_ids=internal.get("sub_group_ids"),
        )
        return _parallel_map_accounts(
            identities,
            lambda item: _sub2api_public_account(
                item,
                api_url=api_url,
                api_key=api_key,
                pro_quota_only=pro_quota_only,
                include_team_quota=include_team_quota,
                navigation_context=navigation_context,
                provider_id=provider_id,
            ),
            secrets=(api_key, *(
                secret
                for item in identities
                for secret in _known_secret_values(item)
            )),
        )
    raise RuntimeError("unsupported_provider")


def _safe_refresh_error(provider: str, exc: Exception) -> str:
    status = 0
    try:
        status = int(getattr(exc, "status_code", 0) or 0)
    except Exception:
        status = 0
    response = getattr(exc, "response", None)
    if not status and response is not None:
        try:
            status = int(getattr(response, "status_code", 0) or 0)
        except Exception:
            status = 0
    label = "CPA" if provider == "cpa" else "Sub2API"
    suffix = f" (HTTP {status})" if 100 <= status <= 599 else ""
    return f"{label} 远端账号读取失败{suffix}"


def _persist_refresh_failure(provider: str, provider_id: int, error: str) -> None:
    key = device_key(provider, provider_id)
    now = _utcnow()
    with Session(engine) as session:
        state = session.get(DeliveryDeviceMonitorStateModel, key)
        if not state:
            state = DeliveryDeviceMonitorStateModel(
                device_key=key,
                provider=provider,
                provider_id=provider_id,
            )
        # Keep account_count/refreshed_at and all snapshot rows untouched: a
        # temporary list failure must not make a populated device look empty.
        state.refresh_error = error[:500]
        state.updated_at = now
        session.add(state)
        session.commit()


def _persist_snapshot(provider: str, provider_id: int, items: list[dict[str, Any]]) -> datetime:
    key = device_key(provider, provider_id)
    now = _utcnow()
    unique_items: dict[str, dict[str, Any]] = {}
    for item in items:
        remote_id = str(item.get("remote_id") or "").strip()
        if remote_id:
            unique_items[remote_id] = item
    items = list(unique_items.values())
    with Session(engine) as session:
        old_rows = session.exec(
            select(DeliveryDeviceAccountSnapshotModel).where(
                DeliveryDeviceAccountSnapshotModel.device_key == key
            )
        ).all()
        for row in old_rows:
            session.delete(row)
        for item in items:
            remote_id = str(item.get("remote_id") or "").strip()
            if not remote_id:
                continue
            snapshot_id = hashlib.sha256(
                f"{key}\0{remote_id}".encode("utf-8")
            ).hexdigest()
            session.add(DeliveryDeviceAccountSnapshotModel(
                snapshot_id=snapshot_id,
                device_key=key,
                remote_id=remote_id[:500],
                payload_json=json.dumps(item, ensure_ascii=False, separators=(",", ":")),
                checked_at=now,
                created_at=now,
                updated_at=now,
            ))
        state = session.get(DeliveryDeviceMonitorStateModel, key)
        if not state:
            state = DeliveryDeviceMonitorStateModel(
                device_key=key,
                provider=provider,
                provider_id=provider_id,
                created_at=now,
            )
        state.account_count = len(items)
        state.refreshed_at = now
        per_account_errors = sum(1 for item in items if str(item.get("usage_status")) == "error")
        state.refresh_error = (
            f"{per_account_errors} 个账号额度查询失败" if per_account_errors else ""
        )
        state.updated_at = now
        session.add(state)
        session.commit()
    return now


def _partial_quota_errors(accounts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Project account-level quota failures without exposing remote payloads.

    The account rows have already passed the monitor's credential allowlist.
    Keep this summary deliberately smaller still: one public identity plus a
    closed, generic operator message.  A quota probe failure is a warning; it
    does not mean that listing or persisting the device failed.
    """
    failures: list[dict[str, str]] = []
    for item in accounts:
        if str(item.get("usage_status") or "").strip().lower() != "error":
            continue
        account = _bounded_text(
            item.get("name") or item.get("email") or item.get("remote_id"),
            500,
        )
        failures.append({
            "account": account or "未知账号",
            "error": "额度查询失败",
        })
    return failures


def _quota_warning(count: int) -> str:
    return f"{max(0, int(count))} 个账号额度查询失败" if count else ""


def refresh_device(
    device_ref: str,
    *,
    before_persist: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Refresh one device atomically, preserving old rows on list failure."""
    provider, provider_id = parse_device_key(device_ref)
    internal = _internal_device(provider, provider_id)
    if not internal:
        raise LookupError("设备不存在")
    key = device_key(provider, provider_id)
    lock = _refresh_lock(key)
    with lock:
        try:
            items = _fetch_accounts(internal)
        except Exception as exc:
            if not _refresh_commit_allowed(internal, before_persist):
                return _superseded_refresh_result(key)
            error = _safe_refresh_error(provider, exc)
            logger.warning(
                "Delivery device refresh failed: device=%s error_type=%s",
                key,
                type(exc).__name__,
            )
            _persist_refresh_failure(provider, provider_id, error)
            response = get_accounts(device_ref)
            response.update({"ok": False, "refresh_error": error})
            return response
        if not _refresh_commit_allowed(internal, before_persist):
            return _superseded_refresh_result(key)
        refreshed_at = _persist_snapshot(provider, provider_id, items)
        response = get_accounts(device_ref)
        response.update({
            # Successful remote listing + atomic snapshot persistence is a
            # successful device refresh even when individual quota probes
            # produced warning rows.
            "ok": True,
            "refreshed": True,
            "refreshed_at": refreshed_at.isoformat(),
        })
        return response


def refresh_device_pro_inventory(
    device_ref: str,
    *,
    before_persist: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Inventory every account and probe supported quota-managed plans.

    Unlike :func:`refresh_device`, this facade is intentionally narrow and is
    used by the interactive "refresh device" task. Explicit PRO and
    TEAM/BUSINESS plans are quota-probed; other and unknown plans remain
    visible without a quota request. This monitor step only persists sanitized
    local snapshots. Neither it nor the interactive refresh worker mutates a
    remote credential or BUSINESS child lifecycle state.
    """
    provider, provider_id = parse_device_key(device_ref)
    internal = _internal_device(provider, provider_id)
    if not internal:
        raise LookupError("设备不存在")
    key = device_key(provider, provider_id)
    lock = _refresh_lock(key)
    with lock:
        try:
            items = _fetch_accounts(
                internal,
                pro_quota_only=True,
                include_team_quota=True,
            )
        except Exception as exc:
            if not _refresh_commit_allowed(internal, before_persist):
                return _superseded_refresh_result(key)
            error = _safe_refresh_error(provider, exc)
            logger.warning(
                "Delivery device PRO inventory refresh failed: device=%s error_type=%s",
                key,
                type(exc).__name__,
            )
            _persist_refresh_failure(provider, provider_id, error)
            return {
                "ok": False,
                "device_ref": key,
                "items": [],
                "accounts": [],
                "total": 0,
                "refresh_error": error,
                "partial_errors": [],
            }
        if not _refresh_commit_allowed(internal, before_persist):
            return _superseded_refresh_result(key)
        refreshed_at = _persist_snapshot(provider, provider_id, items)
        partial_errors = _partial_quota_errors(items)
        return {
            "ok": True,
            "refreshed": True,
            "device_ref": key,
            "items": items,
            "accounts": items,
            "total": len(items),
            "refreshed_at": (
                refreshed_at.isoformat()
                if isinstance(refreshed_at, datetime)
                else _utcnow().isoformat()
            ),
            "warning": _quota_warning(len(partial_errors)),
            "warning_count": len(partial_errors),
            "partial_errors": partial_errors,
        }


def _mark_snapshot_account_disabled(
    provider: str,
    provider_id: int,
    remote_id: str,
) -> None:
    """Reflect a confirmed remote disable in the local public snapshot."""
    key = device_key(provider, provider_id)
    snapshot_id = hashlib.sha256(
        f"{key}\0{remote_id}".encode("utf-8")
    ).hexdigest()
    with Session(engine) as session:
        row = session.get(DeliveryDeviceAccountSnapshotModel, snapshot_id)
        if not row or str(row.device_key or "") != key or str(
            row.remote_id or ""
        ) != remote_id:
            return
        try:
            payload = json.loads(row.payload_json or "{}")
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            return
        payload["disabled"] = True
        if provider == "sub2api":
            payload["schedulable"] = False
        payload["usage_status"] = "disabled"
        payload["checked_at"] = _utcnow().isoformat()
        row.payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        row.updated_at = _utcnow()
        session.add(row)
        session.commit()


def disable_exact_account(
    device_ref: str,
    remote_id: Any,
    *,
    expected_email: str = "",
    expected_name: str = "",
    before_mutation: Any = None,
) -> dict[str, Any]:
    """Disable one exact credential without deleting or changing local plans."""
    provider, provider_id = parse_device_key(device_ref)
    canonical = device_key(provider, provider_id)
    exact_remote_id = str(remote_id or "").strip()
    if not exact_remote_id or len(exact_remote_id) > 500:
        raise ValueError("远端账号标识无效")
    email = str(expected_email or "").strip()
    name = str(expected_name or "").strip()
    if not email and not name:
        raise ValueError("精确禁用必须提供账号邮箱或名称")
    lock = _refresh_lock(canonical)
    with lock:
        internal = _internal_device(provider, provider_id)
        if not internal:
            raise LookupError("设备不存在")
        api_url = str(internal.get("api_url") or "").strip()
        api_key = str(internal.get("api_key") or "").strip()
        if not api_url or (provider == "sub2api" and not api_key):
            raise RuntimeError("设备连接未配置")
        if provider == "sub2api":
            from services.sub2api_admin import set_account_schedulable

            result = set_account_schedulable(
                api_url,
                api_key,
                exact_remote_id,
                False,
                expected_email=email,
                expected_name=name,
                before_mutation=before_mutation,
            )
            _mark_snapshot_account_disabled(
                provider,
                provider_id,
                exact_remote_id,
            )
            return {
                "result": (
                    "disabled" if bool(result.get("updated"))
                    else "already_disabled"
                ),
                "remote_id": exact_remote_id,
            }

        from services.cpa_manager import (
            list_auth_files_strict,
            set_auth_file_disabled,
        )

        def cpa_identity(raw: dict[str, Any]) -> tuple[str, str]:
            actual_name = str(raw.get("name") or "").strip()
            actual_email = str(
                raw.get("email") or raw.get("account") or ""
            ).strip()
            if (
                not actual_email
                and actual_name.lower().endswith(".json")
                and "@" in actual_name
            ):
                actual_email = actual_name[:-5]
            return actual_name, actual_email

        def exact_match(raw: dict[str, Any]) -> bool:
            actual_name, actual_email = cpa_identity(raw)
            if actual_name != exact_remote_id:
                return False
            if name and actual_name.casefold() != name.casefold():
                return False
            if email and actual_email.casefold() != email.casefold():
                return False
            return True

        before_rows = list_auth_files_strict(api_url=api_url, api_key=api_key)
        matches = [row for row in before_rows if exact_match(row)]
        if len(matches) != 1:
            raise RuntimeError("CPA 精确凭证身份无法确认")
        if bool(matches[0].get("disabled")):
            _mark_snapshot_account_disabled(
                provider,
                provider_id,
                exact_remote_id,
            )
            return {"result": "already_disabled", "remote_id": exact_remote_id}
        if before_mutation is not None:
            if not callable(before_mutation) or not bool(before_mutation()):
                raise RuntimeError("CPA 禁用操作已被配置版本栅栏终止")
        set_auth_file_disabled(
            exact_remote_id,
            True,
            api_url=api_url,
            api_key=api_key,
        )
        after_rows = list_auth_files_strict(api_url=api_url, api_key=api_key)
        confirmed = [row for row in after_rows if exact_match(row)]
        if len(confirmed) != 1 or not bool(confirmed[0].get("disabled")):
            raise RuntimeError("CPA 凭证禁用回读未确认")
        _mark_snapshot_account_disabled(provider, provider_id, exact_remote_id)
        return {"result": "disabled", "remote_id": exact_remote_id}


def get_accounts(device_ref: str) -> dict[str, Any]:
    device = get_device(device_ref, include_accounts=True)
    if not device:
        raise LookupError("设备不存在")
    accounts = list(device.pop("accounts", []))
    partial_errors = _partial_quota_errors(accounts)
    warning = _quota_warning(len(partial_errors))
    refresh_error = str(device.get("accounts_refresh_error") or "")
    # ``refresh_error`` historically stores both fatal list failures and the
    # generated per-account warning.  Preserve that database/UI contract while
    # making ``ok`` describe the device-level operation accurately.
    fatal_refresh_error = bool(refresh_error and refresh_error != warning)
    return {
        "ok": not fatal_refresh_error,
        "device_id": device["device_key"],
        "device_ref": device["device_key"],
        "device_key": device["device_key"],
        "device_type": device["provider"],
        "provider": device["provider"],
        "provider_id": device["provider_id"],
        "device": device,
        "items": accounts,
        "accounts": accounts,
        "total": len(accounts),
        "refreshed_at": device.get("accounts_refreshed_at"),
        "refresh_error": refresh_error,
        "accounts_refresh_error": refresh_error,
        "warning": warning,
        "warning_count": len(partial_errors),
        "partial_errors": partial_errors,
    }


def delete_snapshots(device_ref: str) -> None:
    provider, provider_id = parse_device_key(device_ref)
    key = device_key(provider, provider_id)
    with Session(engine) as session:
        for row in session.exec(
            select(DeliveryDeviceAccountSnapshotModel).where(
                DeliveryDeviceAccountSnapshotModel.device_key == key
            )
        ).all():
            session.delete(row)
        state = session.get(DeliveryDeviceMonitorStateModel, key)
        if state:
            session.delete(state)
        session.commit()


def refresh_all_devices(*, enabled_only: bool = True) -> dict[str, Any]:
    inventory = list_devices(include_accounts=False)
    summary = {"ok": True, "total": 0, "refreshed": 0, "failed": 0}
    for device in inventory.get("items", []):
        if enabled_only and device.get("enabled") is False:
            continue
        summary["total"] += 1
        try:
            result = refresh_device(str(device["device_key"]))
        except Exception:
            summary["failed"] += 1
            continue
        if result.get("ok"):
            summary["refreshed"] += 1
        else:
            summary["failed"] += 1
    summary["ok"] = summary["failed"] == 0
    return summary
