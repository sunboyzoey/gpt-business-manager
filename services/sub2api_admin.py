"""Small, explicit Sub2API administrator client.

The client intentionally contains no lifecycle hooks.  In particular, deleting a
local account or disabling a sync device does not call :func:`delete_account`.
Callers must resolve and pass one concrete remote account id themselves.

Sub2API deployments have returned both naked JSON values and envelopes such as
``{"code": 0, "data": ...}``.  All public helpers accept either shape and return
the unwrapped payload.
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit


_REMOTE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_USAGE_SOURCES = frozenset({"passive", "active"})
_DELETE_CONFIRM_DELAYS_SECONDS = (0.0, 0.1, 0.25, 0.5)
_SAFE_PLAN_CODES = frozenset({
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
# Admin usage/quota payloads can grow new fields without notice.  A denylist is
# unsafe here: a new ``proxy_url`` or ``credential_v2`` key would be returned to
# the browser until this client learned about it.  Only the following
# operational fields are allowed across the local API boundary.  Unknown keys
# are deliberately discarded, including inside otherwise allowed containers.
_SAFE_ADMIN_TEXT_KEYS = frozenset({
    "id", "account_id", "user_id", "email", "name", "platform", "provider",
    "type", "status", "source", "model", "plan", "plan_name", "plan_type", "tier",
    "subscription_plan", "subscription_tier", "subscription_status",
    "subscription_tier_raw", "limit_name", "metered_feature", "error_code",
    "product", "period_type", "period_start", "period_end",
    "billing_period_start", "billing_period_end", "top_up_method", "credit_type",
    "grok_entitlement_status", "grok_quota_snapshot_state",
    "grok_last_quota_probe_at", "grok_last_headers_seen_at",
    "reset_at", "reset_time", "resets_at", "expires_at",
    "subscription_expires_at", "created_at", "updated_at", "fetched_at",
    "checked_at",
})
_SAFE_ADMIN_NUMERIC_KEYS = frozenset({
    "total", "used", "remaining", "limit", "capacity", "available",
    "consumed", "granted", "percentage", "percent", "usage_percent",
    "used_percent", "utilization", "reset_after", "reset_seconds",
    "reset_after_seconds", "remaining_seconds", "limit_window_seconds",
    "window_seconds", "window_minutes", "window_hours", "requests",
    "used_requests", "limit_requests", "requests_used", "requests_remaining",
    "tokens", "tokens_used", "tokens_remaining", "token_limit", "cost",
    "standard_cost", "user_cost", "credits", "balance", "credit_balance",
    "available_count", "reset_unix", "grok_retry_after_seconds",
    "grok_last_status_code", "grok_free_token_limit", "monthly_limit_cents",
    "used_cents", "included_used_cents", "prepaid_balance", "monthly_limit",
    "monthly_used", "on_demand_cap", "on_demand_used", "status_code", "amount",
    "minimum_balance",
})
_SAFE_ADMIN_BOOL_KEYS = frozenset({
    "active", "allowed", "available", "disabled", "expired", "force",
    "has_usage", "limit_reached", "is_unified_billing_user", "partial",
    "schedulable",
})
_SAFE_ADMIN_CONTAINER_KEYS = frozenset({
    "data", "usage", "quota", "limits", "limit", "rate_limit",
    "rate_limits", "windows", "window", "primary", "secondary",
    "primary_window", "secondary_window", "five_hour", "seven_day",
    "seven_day_sonnet", "seven_day_fable", "thirty_day", "weekly", "daily",
    "monthly", "gemini_shared_daily", "gemini_pro_daily", "gemini_flash_daily",
    "gemini_shared_minute", "gemini_pro_minute", "gemini_flash_minute",
    "window_stats", "grok_request_quota", "grok_token_quota",
    "grok_local_usage", "grok_local_usage_24h", "grok_local_usage_7d",
    "grok_local_usage_monthly", "grok_billing", "product_usage", "ai_credits",
    "additional_rate_limits", "rate_limit_reset_credits", "credits", "openai",
    "chatgpt", "codex", "items", "periods", "subscription", "plan",
})


class Sub2ApiAdminError(RuntimeError):
    """A validated local error or a rejected Sub2API admin request."""

    def __init__(self, message: str, *, status_code: int = 0, payload: Any = None):
        super().__init__(message)
        self.status_code = int(status_code or 0)
        self.payload = payload


class Sub2ApiAccountNotFound(Sub2ApiAdminError):
    pass


class Sub2ApiAccountAmbiguous(Sub2ApiAdminError):
    pass


class Sub2ApiIdentityMismatch(Sub2ApiAdminError):
    pass


def unwrap_sub2api_response(value: Any) -> Any:
    """Unwrap common Sub2API response envelopes without altering naked data."""
    current = value
    for _ in range(4):
        if not isinstance(current, dict):
            break
        wrapper_markers = {"code", "message", "success", "ok", "error"}
        has_wrapper_marker = bool(wrapper_markers.intersection(current))
        if "data" in current and (has_wrapper_marker or len(current) == 1):
            current = current.get("data")
            continue
        if "result" in current and (has_wrapper_marker or len(current) == 1):
            current = current.get("result")
            continue
        break
    return current


def _assert_success_envelope(payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    raw_code = payload.get("code")
    try:
        envelope_status = int(raw_code)
    except (TypeError, ValueError):
        envelope_status = 0
    if not 100 <= envelope_status <= 599:
        envelope_status = 0
    if payload.get("success") is False or payload.get("ok") is False:
        raise Sub2ApiAdminError(
            "Sub2API 返回失败",
            status_code=envelope_status,
            payload={},
        )
    code = raw_code
    if code is None:
        return
    normalized = str(code).strip().lower()
    if normalized not in {"", "0", "200", "ok", "success"}:
        raise Sub2ApiAdminError(
            "Sub2API 返回失败",
            status_code=envelope_status,
            payload={},
        )


def _normalize_base_url(api_url: str) -> str:
    raw = str(api_url or "").strip().rstrip("/")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise Sub2ApiAdminError("Sub2API API URL 必须是有效的 http(s) 地址")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise Sub2ApiAdminError("Sub2API API URL 不能包含账号密码、查询参数或片段")
    path = parsed.path.rstrip("/")
    if any(part == ".." for part in path.split("/")):
        raise Sub2ApiAdminError("Sub2API API URL 路径无效")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _normalize_remote_account_id(account_id: Any) -> str:
    if isinstance(account_id, bool):
        raise Sub2ApiAdminError("Sub2API 远端账号 ID 无效")
    value = str(account_id or "").strip()
    if not _REMOTE_ID_RE.fullmatch(value):
        raise Sub2ApiAdminError("Sub2API 远端账号 ID 无效")
    if value.isdigit() and int(value) <= 0:
        raise Sub2ApiAdminError("Sub2API 远端账号 ID 无效")
    return value


def _request_json(
    method: str,
    api_url: str,
    api_key: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    expected_statuses: tuple[int, ...] = (200,),
) -> Any:
    from curl_cffi import requests as cffi_requests

    base = _normalize_base_url(api_url)
    key = str(api_key or "").strip()
    if not key:
        raise Sub2ApiAdminError("Sub2API API Key 未配置")
    headers = {
        "Accept": "application/json",
        "x-api-key": key,
    }
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    request = getattr(cffi_requests, method.lower(), None)
    if not callable(request):
        raise Sub2ApiAdminError(f"不支持的 HTTP 方法: {method}")
    try:
        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "params": params,
            "timeout": 20,
            # Admin credentials must never silently cross an unverified TLS
            # connection. Plain HTTP remains available for explicitly configured
            # local deployments; HTTPS always verifies its certificate.
            "verify": True,
            "impersonate": "chrome110",
        }
        if json_body is not None:
            request_kwargs["json"] = dict(json_body)
        response = request(f"{base}{path}", **request_kwargs)
    except Sub2ApiAdminError:
        raise
    except Exception:
        # Do not embed arbitrary transport exception text in an API response;
        # proxy URLs and client implementations sometimes include credentials.
        raise Sub2ApiAdminError("Sub2API 网络请求失败", status_code=502, payload={}) from None

    status = int(getattr(response, "status_code", 0) or 0)
    payload: Any = None
    raw_text = getattr(response, "text", "")
    if status != 204:
        try:
            payload = response.json()
        except Exception:
            if isinstance(raw_text, str) and raw_text.strip():
                raise Sub2ApiAdminError(
                    "Sub2API 返回了非 JSON 响应",
                    status_code=status or 502,
                    payload={},
                )
    if status not in expected_statuses:
        raise Sub2ApiAdminError(
            f"Sub2API HTTP {status}",
            status_code=status,
            payload={},
        )
    _assert_success_envelope(payload)
    return unwrap_sub2api_response(payload)


def _account_items(payload: Any) -> list[dict[str, Any]]:
    value = unwrap_sub2api_response(payload)
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("items", "accounts", "rows", "list"):
        items = value.get(key)
        if isinstance(items, list):
            return [dict(item) for item in items if isinstance(item, dict)]
    for key in ("account", "item"):
        item = value.get(key)
        if isinstance(item, dict):
            return [dict(item)]
    if any(key in value for key in ("id", "account_id")):
        return [dict(value)]
    return []


def _account_email(account: dict[str, Any]) -> str:
    credentials = account.get("credentials")
    nested = credentials if isinstance(credentials, dict) else {}
    extra = account.get("extra")
    extra_data = extra if isinstance(extra, dict) else {}
    return str(
        account.get("email")
        or account.get("account_email")
        or nested.get("email")
        or extra_data.get("email")
        or ""
    ).strip()


def _account_name(account: dict[str, Any]) -> str:
    return str(account.get("name") or account.get("account_name") or "").strip()


def _account_plan(account: dict[str, Any]) -> str:
    """Extract one allowlisted plan scalar without exposing credentials.

    Sub2API commonly keeps ``plan_type`` in its redacted ``credentials``
    object.  Returning that one bounded classification value is safe; the
    credential container itself never crosses this client boundary.
    """
    containers = [account]
    for key in ("credentials", "extra"):
        nested = account.get(key)
        if isinstance(nested, dict):
            containers.append(nested)
    for container in containers:
        for key in (
            "plan_type", "plan", "plan_name", "subscription_plan",
            "subscription_tier", "tier",
        ):
            value = container.get(key)
            if (
                isinstance(value, (str, int, float))
                and not isinstance(value, bool)
            ):
                plan = str(value).strip()[:120]
                normalized = re.sub(
                    r"[^a-z0-9]+",
                    "_",
                    plan.casefold(),
                ).strip("_")
                if normalized in _SAFE_PLAN_CODES:
                    return plan
    return ""


def _account_matches_exact(
    account: dict[str, Any],
    *,
    email: str = "",
    name: str = "",
) -> bool:
    expected_email = str(email or "").strip().casefold()
    expected_name = str(name or "").strip().casefold()
    actual_email = _account_email(account).casefold()
    actual_name = _account_name(account).casefold()
    if expected_email:
        # Some admin list/get deployments redact credentials and expose an email
        # only as ``name``.  It is still an exact comparison, never a substring.
        if actual_email:
            if actual_email != expected_email:
                return False
        elif actual_name != expected_email:
            return False
    if expected_name and actual_name != expected_name:
        return False
    return bool(expected_email or expected_name)


def remote_account_id(account: dict[str, Any]) -> str:
    """Return a validated id from one remote account record."""
    return _normalize_remote_account_id(account.get("id") or account.get("account_id"))


def public_account_identity(account: dict[str, Any]) -> dict[str, Any]:
    """Return only non-credential identity fields suitable for a local API."""
    email = _account_email(account)
    name = _account_name(account)
    if not email and "@" in name:
        email = name
    result: dict[str, Any] = {
        "id": remote_account_id(account),
        "email": email,
        "name": name,
    }
    for key in ("platform", "type", "status", "disabled", "schedulable"):
        value = account.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value
    plan = _account_plan(account)
    if plan:
        result["plan"] = plan
        result["plan_type"] = plan
    raw_group_id = account.get("group_id")
    if not isinstance(raw_group_id, bool):
        try:
            parsed_group_id = int(str(raw_group_id).strip())
        except (TypeError, ValueError):
            parsed_group_id = 0
        if parsed_group_id > 0:
            result["group_id"] = parsed_group_id
    raw_group_ids = account.get("group_ids")
    if isinstance(raw_group_ids, list):
        safe_group_ids: list[int] = []
        for value in raw_group_ids[:100]:
            if isinstance(value, bool):
                continue
            try:
                parsed = int(str(value).strip())
            except (TypeError, ValueError):
                continue
            if parsed > 0 and parsed not in safe_group_ids:
                safe_group_ids.append(parsed)
        result["group_ids"] = safe_group_ids
    return result


def _parse_group_ids(group_ids: Any) -> list[int | None]:
    """Normalize an optional Sub2API group filter without trusting callers."""
    if group_ids is None or str(group_ids or "").strip() == "":
        return [None]
    raw = group_ids if isinstance(group_ids, (list, tuple, set)) else str(group_ids).split(",")
    result: list[int | None] = []
    for item in raw:
        try:
            group_id = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if group_id > 0 and group_id not in result:
            result.append(group_id)
    return result or [None]


def _list_account_records(
    api_url: str,
    api_key: str,
    *,
    group_id: int | None = None,
) -> list[dict[str, Any]]:
    """Read a complete, non-overlapping account collection.

    Sub2API versions use several pagination envelopes.  We keep requesting
    pages until an authoritative total/page marker or an empty page proves
    completion.  Repeated/overlapping pages fail closed instead of silently
    presenting a partial device inventory.
    """
    page_size = 100
    records: list[dict[str, Any]] = []
    observed_ids: set[str] = set()
    expected_total: int | None = None
    expected_pages: int | None = None
    for page in range(1, 1001):
        params: dict[str, Any] = {
            "platform": "openai",
            "type": "oauth",
            "page": page,
            "page_size": page_size,
        }
        if group_id is not None:
            params["group"] = int(group_id)
        payload = _request_json(
            "GET",
            api_url,
            api_key,
            "/api/v1/admin/accounts",
            params=params,
        )
        items = _account_items(payload)
        if not items:
            if expected_total is not None and len(observed_ids) < expected_total:
                raise Sub2ApiAdminError(
                    "Sub2API 账号分页提前结束",
                    status_code=502,
                )
            return records

        page_ids: list[str] = []
        for item in items:
            try:
                account_id = remote_account_id(item)
            except Sub2ApiAdminError as exc:
                raise Sub2ApiAdminError(
                    "Sub2API 账号列表包含无效 ID",
                    status_code=502,
                ) from exc
            if account_id in observed_ids:
                raise Sub2ApiAdminError(
                    "Sub2API 账号分页重复，无法确认完整账号集合",
                    status_code=502,
                )
            observed_ids.add(account_id)
            page_ids.append(account_id)
            records.append(item)

        payload_dict = payload if isinstance(payload, dict) else {}
        total = _non_negative_int(payload_dict.get("total"))
        pages = _positive_int(
            payload_dict.get("pages")
            or payload_dict.get("total_pages")
            or payload_dict.get("totalPages")
        )
        has_more = payload_dict.get("has_more")
        if has_more is None:
            has_more = payload_dict.get("hasMore")
        reported_page = _positive_int(payload_dict.get("page"))
        if reported_page is not None and reported_page != page:
            raise Sub2ApiAdminError(
                "Sub2API 返回的分页页码与请求不一致",
                status_code=502,
            )
        if total is not None:
            if expected_total is None:
                expected_total = total
            elif expected_total != total:
                raise Sub2ApiAdminError(
                    "Sub2API 分页期间账号总数发生变化",
                    status_code=502,
                )
        if pages is not None:
            if expected_pages is None:
                expected_pages = pages
            elif expected_pages != pages:
                raise Sub2ApiAdminError(
                    "Sub2API 分页期间总页数发生变化",
                    status_code=502,
                )

        if expected_total is not None:
            if len(observed_ids) > expected_total:
                raise Sub2ApiAdminError(
                    "Sub2API 分页数量超过声明总数",
                    status_code=502,
                )
            if len(observed_ids) == expected_total:
                return records
        if expected_pages is not None and page >= expected_pages:
            return records
        if has_more is False:
            return records
        # Naked lists and old envelopes without pagination metadata are read
        # until an empty page.  A server that ignores ``page`` is caught by the
        # overlap guard above.
    raise Sub2ApiAdminError("Sub2API 账号分页超过安全上限", status_code=502)


def list_accounts(
    api_url: str,
    api_key: str,
    *,
    group_ids: Any = None,
) -> list[dict[str, Any]]:
    """Return the complete credential-free OpenAI OAuth account inventory."""
    unique: dict[str, dict[str, Any]] = {}
    for group_id in _parse_group_ids(group_ids):
        for raw in _list_account_records(
            api_url,
            api_key,
            group_id=group_id,
        ):
            public = public_account_identity(raw)
            unique[str(public["id"])] = public
    return list(unique.values())


def sanitize_admin_payload(
    value: Any,
    *,
    secrets: tuple[str, ...] | list[str] = (),
    _depth: int = 0,
) -> Any:
    """Return a strictly allowlisted usage/quota view for the local API.

    ``secrets`` provides defense-in-depth redaction for the few allowed text
    fields, but security does not depend on discovering or pattern-matching a
    secret value. Free-form strings and unknown keys never cross the boundary.
    """
    if _depth >= 12:
        return None
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            output_key = str(key)
            known_key = (
                normalized_key in _SAFE_ADMIN_CONTAINER_KEYS
                or normalized_key in _SAFE_ADMIN_BOOL_KEYS
                or normalized_key in _SAFE_ADMIN_NUMERIC_KEYS
                or normalized_key in _SAFE_ADMIN_TEXT_KEYS
            )
            if known_key and item is None:
                cleaned[output_key] = None
            elif (
                normalized_key in _SAFE_ADMIN_CONTAINER_KEYS
                and isinstance(item, (dict, list))
            ):
                cleaned[output_key] = sanitize_admin_payload(
                    item,
                    secrets=secrets,
                    _depth=_depth + 1,
                )
            elif normalized_key in _SAFE_ADMIN_BOOL_KEYS and isinstance(item, bool):
                cleaned[output_key] = item
            elif (
                normalized_key in _SAFE_ADMIN_NUMERIC_KEYS
                and isinstance(item, (int, float))
                and not isinstance(item, bool)
            ):
                cleaned[output_key] = item
            elif (
                normalized_key in _SAFE_ADMIN_TEXT_KEYS
                and isinstance(item, (str, int, float))
                and not isinstance(item, bool)
            ):
                # Bound text-like metadata so a remote service cannot use an
                # otherwise safe field for an unbounded response.
                if isinstance(item, str):
                    safe_text = item[:500]
                    for secret in secrets:
                        if isinstance(secret, str) and len(secret) >= 4:
                            safe_text = safe_text.replace(secret, "[REDACTED]")
                    cleaned[output_key] = safe_text
                else:
                    cleaned[output_key] = item
        return cleaned
    if isinstance(value, list):
        return [
            sanitize_admin_payload(
                item,
                secrets=secrets,
                _depth=_depth + 1,
            )
            for item in value
        ]
    # Scalar numeric/bool payloads are useful and cannot contain credentials.
    # Bare strings are intentionally rejected because there is no field name to
    # establish that they are safe metadata rather than a token or URL.
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def find_account_exact(
    api_url: str,
    api_key: str,
    *,
    email: str = "",
    name: str = "",
) -> dict[str, Any]:
    """Find exactly one account by case-insensitive email and/or name.

    The remote ``search`` parameter is only a candidate reducer.  A local exact
    comparison is always applied, preventing a partial match from being used as a
    remote id for quota or delete operations.
    """
    expected_email = str(email or "").strip().casefold()
    expected_name = str(name or "").strip().casefold()
    if not expected_email and not expected_name:
        raise Sub2ApiAdminError("必须提供 email 或 name 进行精确查找")
    search = str(email or name).strip()
    matches: list[dict[str, Any]] = []
    matched_ids: set[str] = set()
    observed_ids: set[str] = set()
    page_size = 100
    seen_page_ids: set[tuple[str, ...]] = set()
    expected_total: int | None = None
    expected_pages: int | None = None
    complete = False
    for page in range(1, 51):
        payload = _request_json(
            "GET",
            api_url,
            api_key,
            "/api/v1/admin/accounts",
            params={"search": search, "page": page, "page_size": page_size},
        )
        items = _account_items(payload)
        try:
            page_ids = tuple(remote_account_id(account) for account in items)
        except Sub2ApiAdminError as exc:
            raise Sub2ApiAdminError(
                "Sub2API 账号列表包含无效 ID",
                status_code=502,
            ) from exc
        if page_ids and page_ids in seen_page_ids:
            raise Sub2ApiAdminError(
                "Sub2API 账号分页未推进，无法安全完成精确查找",
                status_code=502,
            )
        if page_ids:
            seen_page_ids.add(page_ids)
        overlapping_ids = observed_ids.intersection(page_ids)
        if overlapping_ids:
            raise Sub2ApiAdminError(
                "Sub2API 账号分页发生重叠，无法证明结果完整",
                status_code=502,
            )
        observed_ids.update(page_ids)

        for account, account_id in zip(items, page_ids):
            if not _account_matches_exact(account, email=email, name=name):
                continue
            if account_id not in matched_ids:
                matches.append(account)
                matched_ids.add(account_id)

        payload_dict = payload if isinstance(payload, dict) else {}
        # A naked list is still paged until an empty page proves exhaustion; a
        # short list alone is not completion evidence. If a server ignores the
        # page parameter, the repeated/overlapping ID guards above fail closed.
        # A naked single-account object is an explicit non-collection response.
        naked_list = isinstance(payload, list)
        naked_account = (
            isinstance(payload, dict)
            and any(key in payload for key in ("id", "account_id"))
            and not any(key in payload for key in ("items", "accounts", "rows", "list"))
        )
        if naked_account:
            complete = True
            break
        if naked_list:
            if not items:
                complete = True
                break
            continue

        reported_total = _non_negative_int(payload_dict.get("total"))
        reported_pages = _positive_int(
            payload_dict.get("pages")
            or payload_dict.get("total_pages")
            or payload_dict.get("totalPages")
        )
        reported_page = _positive_int(payload_dict.get("page"))
        has_more = payload_dict.get("has_more")
        if has_more is None:
            has_more = payload_dict.get("hasMore")

        if reported_page is not None and reported_page != page:
            raise Sub2ApiAdminError(
                "Sub2API 返回的分页页码与请求不一致",
                status_code=502,
            )
        if reported_total is not None:
            if expected_total is None:
                expected_total = reported_total
            elif reported_total != expected_total:
                raise Sub2ApiAdminError(
                    "Sub2API 分页期间账号总数发生变化",
                    status_code=502,
                )
        if reported_pages is not None:
            if expected_pages is None:
                expected_pages = reported_pages
            elif reported_pages != expected_pages:
                raise Sub2ApiAdminError(
                    "Sub2API 分页期间总页数发生变化",
                    status_code=502,
                )

        observed_count = len(observed_ids)
        if expected_total is not None:
            if observed_count > expected_total:
                raise Sub2ApiAdminError(
                    "Sub2API 分页返回数量超过声明总数",
                    status_code=502,
                )
            if observed_count == expected_total:
                if has_more is True or (expected_pages is not None and page < expected_pages):
                    raise Sub2ApiAdminError(
                        "Sub2API 分页完成标记与声明总数冲突",
                        status_code=502,
                    )
                complete = True
                break
            if has_more is False or (expected_pages is not None and page >= expected_pages):
                raise Sub2ApiAdminError(
                    "Sub2API 分页提前结束，账号集合不完整",
                    status_code=502,
                )
            if not items:
                raise Sub2ApiAdminError(
                    "Sub2API 分页在读满总数前返回空页",
                    status_code=502,
                )
            continue

        if expected_pages is not None:
            if page >= expected_pages:
                if has_more is True:
                    raise Sub2ApiAdminError(
                        "Sub2API 总页数与 has_more 冲突",
                        status_code=502,
                    )
                complete = True
                break
            if has_more is False or not items:
                raise Sub2ApiAdminError(
                    "Sub2API 分页在最后一页前中断",
                    status_code=502,
                )
            continue

        if has_more is False:
            complete = True
            break
        if has_more is True:
            if not items:
                raise Sub2ApiAdminError(
                    "Sub2API has_more=true 但返回空页",
                    status_code=502,
                )
            continue
        raise Sub2ApiAdminError(
            "Sub2API 账号列表缺少完整分页信息",
            status_code=502,
        )
    else:
        raise Sub2ApiAdminError("Sub2API 账号分页超过安全上限", status_code=502)
    if not complete:
        raise Sub2ApiAdminError("Sub2API 未能确认账号集合完整", status_code=502)
    if not matches:
        label = str(email or name).strip()
        raise Sub2ApiAccountNotFound(f"Sub2API 未找到精确匹配账号: {label}")
    if len(matches) != 1:
        raise Sub2ApiAccountAmbiguous(
            f"Sub2API 精确匹配到 {len(matches)} 个账号，请同时提供 email 与 name"
        )
    # Never return the raw admin record to callers; it may contain credentials.
    return public_account_identity(matches[0])


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def get_account_by_id(api_url: str, api_key: str, account_id: Any) -> dict[str, Any]:
    remote_id = _normalize_remote_account_id(account_id)
    payload = _request_json(
        "GET",
        api_url,
        api_key,
        f"/api/v1/admin/accounts/{quote(remote_id, safe='')}",
    )
    items = _account_items(payload)
    try:
        exact = [item for item in items if remote_account_id(item) == remote_id]
    except Sub2ApiAdminError as exc:
        raise Sub2ApiAdminError(
            "Sub2API 按 ID 返回了无效账号身份",
            status_code=502,
        ) from exc
    if len(exact) != 1:
        raise Sub2ApiAdminError("Sub2API 按 ID 返回的账号身份不唯一", status_code=502)
    return public_account_identity(exact[0])


def get_account_usage(
    api_url: str,
    api_key: str,
    account_id: Any,
    *,
    source: str = "passive",
    force: bool = False,
) -> Any:
    """Read usage for one id.

    ``source='passive'`` and ``force=False`` are deliberately the defaults.
    ``source='active'`` or a forced request can probe upstream and persist fresh
    rate-limit headers in Sub2API; callers must opt in explicitly.
    """
    normalized_source = str(source or "passive").strip().lower()
    if normalized_source not in _USAGE_SOURCES:
        raise Sub2ApiAdminError("usage source 只能是 passive 或 active")
    remote_id = _normalize_remote_account_id(account_id)
    payload = _request_json(
        "GET",
        api_url,
        api_key,
        f"/api/v1/admin/accounts/{quote(remote_id, safe='')}/usage",
        params={
            "source": normalized_source,
            "force": "true" if bool(force) else "false",
        },
    )
    return sanitize_admin_payload(payload, secrets=(str(api_key or ""),))


def query_openai_quota(api_url: str, api_key: str, account_id: Any) -> Any:
    """Query an OpenAI account quota through Sub2API.

    This is *not* a strictly read-only operation: Sub2API may refresh credentials
    and contact OpenAI while serving the request.
    """
    remote_id = _normalize_remote_account_id(account_id)
    payload = _request_json(
        "GET",
        api_url,
        api_key,
        f"/api/v1/admin/openai/accounts/{quote(remote_id, safe='')}/quota",
    )
    return sanitize_admin_payload(payload, secrets=(str(api_key or ""),))


def set_account_schedulable(
    api_url: str,
    api_key: str,
    account_id: Any,
    schedulable: bool,
    *,
    expected_email: str = "",
    expected_name: str = "",
    before_mutation: Any = None,
) -> dict[str, Any]:
    """Set scheduling for one exact Sub2API account and verify by ID.

    This is the non-destructive disable primitive used by device quota
    monitoring.  It deliberately never calls the account DELETE endpoint.
    """
    remote_id = _normalize_remote_account_id(account_id)
    if not str(expected_email or "").strip() and not str(expected_name or "").strip():
        raise Sub2ApiAdminError(
            "修改 Sub2API 调度状态必须提供 expected_email 或 expected_name"
        )
    before = get_account_by_id(api_url, api_key, remote_id)
    if not _account_matches_exact(
        before,
        email=expected_email,
        name=expected_name,
    ):
        raise Sub2ApiIdentityMismatch("Sub2API 远端账号身份与调度确认不一致")
    desired = bool(schedulable)
    if before.get("schedulable") is desired:
        return {
            "updated": False,
            "remote_account_id": remote_id,
            "schedulable": desired,
            "account": public_account_identity(before),
        }
    if before_mutation is not None:
        if not callable(before_mutation) or not bool(before_mutation()):
            raise Sub2ApiAdminError(
                "Sub2API 调度操作已被配置版本栅栏终止",
                status_code=409,
            )
    _request_json(
        "POST",
        api_url,
        api_key,
        f"/api/v1/admin/accounts/{quote(remote_id, safe='')}/schedulable",
        json_body={"schedulable": desired},
    )
    after = get_account_by_id(api_url, api_key, remote_id)
    if not _account_matches_exact(
        after,
        email=expected_email,
        name=expected_name,
    ):
        raise Sub2ApiIdentityMismatch("Sub2API 回读账号身份与调度确认不一致")
    if after.get("schedulable") is not desired:
        raise Sub2ApiAdminError(
            "Sub2API 调度状态回读未确认",
            status_code=409,
            payload={},
        )
    return {
        "updated": True,
        "remote_account_id": remote_id,
        "schedulable": desired,
        "account": public_account_identity(after),
    }


def delete_account(
    api_url: str,
    api_key: str,
    account_id: Any,
    *,
    expected_email: str = "",
    expected_name: str = "",
    before_mutation: Any = None,
) -> dict[str, Any]:
    """Delete one id only after an exact remote identity preflight.

    The returned confirmation is deliberately credential-free and does not
    include the remote DELETE response body.
    """
    remote_id = _normalize_remote_account_id(account_id)
    if not str(expected_email or "").strip() and not str(expected_name or "").strip():
        raise Sub2ApiAdminError("删除 Sub2API 账号必须提供 expected_email 或 expected_name")
    account = get_account_by_id(api_url, api_key, remote_id)
    if not _account_matches_exact(
        account,
        email=expected_email,
        name=expected_name,
    ):
        raise Sub2ApiIdentityMismatch("Sub2API 远端账号身份与删除确认不一致")
    identity = public_account_identity(account)
    if before_mutation is not None:
        if not callable(before_mutation) or not bool(before_mutation()):
            raise Sub2ApiAdminError(
                "Sub2API 删除操作已被配置版本栅栏终止",
                status_code=409,
            )
    _request_json(
        "DELETE",
        api_url,
        api_key,
        f"/api/v1/admin/accounts/{quote(remote_id, safe='')}",
        expected_statuses=(200, 204),
    )
    # Some deployments update the admin read model shortly after DELETE.  Poll
    # for a short, fixed interval, but only treat an authoritative 404 (including
    # a wrapped logical 404) as confirmation.  This remains fail-closed: a
    # present record or an indeterminate remote error never becomes success.
    last_confirmation_error: Sub2ApiAdminError | None = None
    last_state = "present"
    absence_confirmed = False
    for delay in _DELETE_CONFIRM_DELAYS_SECONDS:
        if delay:
            time.sleep(delay)
        try:
            get_account_by_id(api_url, api_key, remote_id)
            last_state = "present"
            last_confirmation_error = None
        except Sub2ApiAdminError as exc:
            if exc.status_code == 404:
                absence_confirmed = True
                break
            if exc.status_code in {408, 429, 500, 502, 503, 504}:
                last_state = "error"
                last_confirmation_error = exc
                continue
            raise
    if not absence_confirmed:
        if last_state == "error" and last_confirmation_error is not None:
            raise Sub2ApiAdminError(
                "Sub2API 删除结果暂时无法确认",
                status_code=502,
                payload={},
            ) from last_confirmation_error
        raise Sub2ApiAdminError(
            "Sub2API 删除后仍能读取该账号，未确认删除完成",
            status_code=409,
            payload={},
        )
    return {
        "deleted": True,
        "remote_account_id": remote_id,
        "account": identity,
        "absence_confirmed": True,
    }


# Descriptive aliases for call sites that prefer the product name in imports.
find_sub2api_account_exact = find_account_exact
get_sub2api_account_usage = get_account_usage
query_sub2api_openai_quota = query_openai_quota
delete_sub2api_account = delete_account
