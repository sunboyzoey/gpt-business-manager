"""Credential-free NexusVault price reads and explicit, single-card price edits.

The existing encrypted web-session configuration is shared with NV sales reads.
Despite its legacy ``read session`` name, that cookie is used for a write here
*only* when the caller explicitly invokes ``edit_card_price`` in response to an
operator price change.  Market/inventory reads never mutate prices.  Mutations
are sent once, without redirects or retries, and still require the caller to
read back the same available inventory card before updating local state.

``cards.id`` is the inventory UUID, not the sales order's ``card_id``.  Keep the
two namespaces separate.  An available card's ``price_cents`` is its current
editable price; sold cards may return zero there and retain the historical pool
price only in ``pool_price_cents``.  Neither is a substitute for a frozen order.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import re
import time
from typing import Any

from services import nv_http as requests

from services import nexusvault as nv


_PAGE_LIMIT = 96
_MAX_PAGES = 200
_MAX_READ_SECONDS = 120
_MAX_CENTS = 99_999_999
_PLANS = (("team", "default", "TEAM"),
          ("business_pro_5x", "prolite", "Business Pro 5X"))


class NexusVaultPriceEditUnconfirmed(nv.NexusVaultRequestError):
    """The edit might have happened; never automatically resubmit it."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int(value: Any, *, maximum: int = _MAX_CENTS) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def _timestamp(value: Any) -> str | None:
    parsed = nv._safe_remote_sold_at(value)
    return parsed.isoformat() if parsed is not None else None


def _identifier(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    result = value.strip()
    return result if re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", result) else ""


def _connection(base_url: str | None, session_cookie: str | None) -> tuple[str, str]:
    # Normalize before reading/attaching credentials even when the caller
    # supplies a base URL explicitly (also useful to isolate unit tests).
    if base_url is not None:
        nv.normalize_base_url(base_url)
    if base_url is None or session_cookie is None:
        configured_base, configured_cookie = nv.load_sales_session_config()
        base_url = configured_base if base_url is None else base_url
        session_cookie = configured_cookie if session_cookie is None else session_cookie
    return nv.normalize_base_url(base_url), nv._normalize_session_cookie(session_cookie)


def _request(
    method: str, *, base_url: str, path: str, session_cookie: str = "",
    params: dict[str, Any] | None = None, payload: dict[str, Any] | None = None,
) -> tuple[Any, int]:
    """Bounded response; no raw remote error, credential, or redirect escapes."""
    target = nv.normalize_base_url(base_url)
    mutation = method == "PATCH"
    headers = {
        "accept": "application/json",
        "referer": f"{target}/workspace/inventory",
    }
    if session_cookie:
        headers["cookie"] = nv._normalize_session_cookie(session_cookie)
    if mutation:
        headers.update({"content-type": "application/json", "origin": target})
    try:
        if mutation:
            response = requests.patch(
                f"{target}{path}", headers=headers, json=payload,
                timeout=(10, 45), allow_redirects=False, stream=True,
            )
        else:
            response = requests.get(
                f"{target}{path}", headers=headers, params=params,
                timeout=(10, 45), allow_redirects=False, stream=True,
            )
    except requests.Timeout:
        if mutation:
            raise NexusVaultPriceEditUnconfirmed(
                "NV 改价请求超时，结果未知；请刷新价格核对，未自动重试"
            ) from None
        raise nv.NexusVaultRequestTimeout("NV 价格查询超时") from None
    except Exception:
        if mutation:
            raise NexusVaultPriceEditUnconfirmed(
                "NV 改价连接中断，结果未确认；请刷新价格核对，未自动重试"
            ) from None
        raise nv.NexusVaultRequestError("无法连接 NV 价格查询服务") from None
    try:
        status = int(response.status_code)
        if status in {401, 403}:
            raise nv.NexusVaultSessionExpired("NV 登录会话已失效，请重新配置 Cookie")
        if not 200 <= status < 300:
            if mutation:
                raise NexusVaultPriceEditUnconfirmed(
                    f"NV 改价返回 HTTP {status}，未确认更新；请刷新价格核对，未自动重试"
                )
            raise nv.NexusVaultRequestError(f"NV 价格查询失败（HTTP {status}）")
        try:
            return nv._read_bounded_json(response), status
        except Exception:
            if mutation:
                raise NexusVaultPriceEditUnconfirmed(
                    "NV 改价响应无法确认；请刷新价格核对，未自动重试"
                ) from None
            raise nv.NexusVaultRequestError("NV 价格查询返回内容无效或超出限制") from None
    finally:
        try:
            response.close()
        except Exception:
            pass


def read_market(
    *, base_url: str | None = None, session_cookie: str | None = None,
) -> dict[str, Any]:
    """Read NV's authenticated price board; no inventory API key is sent."""
    base_url, session_cookie = _connection(base_url, session_cookie)
    payload, _ = _request(
        "GET", base_url=base_url, session_cookie=session_cookie, path="/api/pool/price-board",
    )
    board = payload.get("board") if isinstance(payload, dict) else None
    if not isinstance(board, dict) or not isinstance(board.get("plans"), list):
        raise nv.NexusVaultRequestError("NV 行情返回结构异常")
    rows: dict[str, dict[str, Any]] = {}
    allowed_plans = {item[0] for item in _PLANS}
    for item in board["plans"]:
        if (not isinstance(item, dict) or not isinstance(item.get("plan"), str)
                or item["plan"] not in allowed_plans):
            continue
        plan = item["plan"]
        if plan in rows:
            raise nv.NexusVaultRequestError("NV 行情包含重复套餐，无法确认价格")
        rows[plan] = item
    plans = []
    for plan, seat_type, label in _PLANS:
        row = rows.get(plan, {})
        clean = {key: _int(row.get(key)) for key in (
            "min_cents", "p25_cents", "median_cents", "p75_cents",
            "max_cents", "avg_cents", "inventory_token_count",
        )}
        # This is NV's boolean "has a quote" flag, not an inventory count.
        clean["available"] = row.get("available") if type(row.get("available")) is bool else None
        if (clean["min_cents"] is not None and clean["max_cents"] is not None
                and clean["min_cents"] > clean["max_cents"]):
            raise nv.NexusVaultRequestError("NV 行情价格区间异常")
        plans.append({"plan": plan, "seat_type": seat_type, "label": label, **clean})
    return {
        "currency": "CNY", "updated_at": _timestamp(board.get("updated_at")),
        "fetched_at": _now(), "cache_ready": board.get("cache_ready") is True,
        "plans": plans,
    }


def _inventory_card(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise nv.NexusVaultRequestError("NV 库存价格记录结构异常")
    card_id = _identifier(item.get("id"))
    emails = {
        email for key in ("inventory_token_email", "account_label", "account_email", "email")
        if (email := nv._safe_remote_email(item.get(key)))
    }
    if not card_id or len(emails) != 1:
        raise nv.NexusVaultRequestError("NV 库存账号身份缺失或不一致，无法核对价格")
    status = item.get("status")
    plan = _identifier(item.get("plan")) or "unknown"
    check_details = item.get("check_details")
    return {
        "id": card_id, "email": next(iter(emails)),
        "status": status if isinstance(status, str) and status in {
            "available", "sold", "disabled", "deleted", "invalid"
        } else "unknown",
        "plan": plan,
        "price_cents": _int(item.get("price_cents")),
        "pool_price_cents": _int(item.get("pool_price_cents")),
        "created_at": _timestamp(item.get("uploaded_at") or item.get("created_at")),
        "sold_at": _timestamp(item.get("sold_at")),
        "quota": nv.sanitize_quota_evidence(
            check_details.get("quota") if isinstance(check_details, dict) else None
        ),
    }


def read_inventory_prices(
    *, base_url: str | None = None, session_cookie: str | None = None,
) -> dict[str, Any]:
    """Return an all-or-nothing, complete paginated inventory price snapshot.

    No card credentials, inventory token object, raw check_details, or
    unrestricted remote field is returned.  Only successful, complete quota
    window durations may be retained as classification evidence.
    Missing/inconsistent pagination or duplicate
    inventory IDs are errors, never an empty/partial successful inventory.
    """
    base_url, session_cookie = _connection(base_url, session_cookie)
    cards: list[dict[str, Any]] = []
    ids: set[str] = set()
    expected_pages = expected_total = None
    started = time.monotonic()
    for page in range(1, _MAX_PAGES + 1):
        if time.monotonic() - started >= _MAX_READ_SECONDS:
            raise nv.NexusVaultRequestTimeout("NV 库存价格分页查询超时，未返回部分清单")
        payload, _ = _request(
            "GET", base_url=base_url, session_cookie=session_cookie,
            path="/api/supplier/cards", params={"page": page, "limit": _PAGE_LIMIT},
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("cards"), list):
            raise nv.NexusVaultRequestError("NV 库存价格返回结构异常")
        metadata = payload.get("pagination")
        if not isinstance(metadata, dict):
            raise nv.NexusVaultRequestError("NV 库存价格分页信息缺失，无法确认完整清单")
        metadata = dict(metadata)
        if "has_next" in metadata:
            if type(metadata["has_next"]) is not bool or (
                "has_more" in metadata and metadata["has_more"] != metadata["has_next"]
            ):
                raise nv.NexusVaultRequestError("NV 库存价格分页信息不一致")
            metadata["has_more"] = metadata["has_next"]
        # Some APIs use zero pages for a proven empty collection.
        if (page == 1 and metadata.get("total_pages") == 0
                and type(metadata.get("total_pages")) is int
                and metadata.get("total") == 0 and type(metadata.get("total")) is int
                and not payload["cards"] and metadata.get("has_more") is not True):
            metadata["total_pages"] = 1
        for item in payload["cards"]:
            card = _inventory_card(item)
            if card["id"] in ids:
                raise nv.NexusVaultRequestError("NV 库存分页出现重复账号，请重新刷新价格")
            ids.add(card["id"])
            cards.append(card)
        has_next, complete, expected_pages, expected_total, consistent = nv._pagination_decision(
            pagination=metadata, page=page, item_count=len(payload["cards"]),
            raw_count=len(cards), limit=_PAGE_LIMIT, expected_total_pages=expected_pages,
            expected_total=expected_total,
        )
        if not consistent or (has_next and not payload["cards"]):
            raise nv.NexusVaultRequestError("NV 库存价格分页不完整或发生变化，请重新刷新")
        if not has_next:
            if not complete:
                raise nv.NexusVaultRequestError("NV 库存价格清单尚未完整读取")
            return {"cards": cards, "complete": True, "pages_fetched": page, "fetched_at": _now()}
    raise nv.NexusVaultRequestError("NV 库存价格分页超出安全限制，未返回部分清单")


def edit_card_price(
    card_id: str, price_yuan: Any, *, base_url: str | None = None,
    session_cookie: str | None = None,
) -> dict[str, int]:
    """Submit one explicit operator price edit, exactly once.

    Caller must first establish an unambiguous *available* inventory-card/email
    identity, then read back that same card after this call.  This low-level
    primitive does not search by email, change global prices, retry, update
    local jobs, or alter any historical order's receipt/price.
    """
    identity = _identifier(card_id)
    if not identity or identity != card_id:
        raise ValueError("NV 库存账号 ID 无效")
    if isinstance(price_yuan, bool) or not isinstance(price_yuan, (str, int, float, Decimal)):
        raise ValueError("NV 价格必须是最多两位小数的人民币金额")
    raw = str(price_yuan).strip()
    if not re.fullmatch(r"\d{1,6}(?:\.\d{1,2})?", raw):
        raise ValueError("NV 价格必须是最多两位小数的人民币金额")
    try:
        price = Decimal(raw)
    except InvalidOperation:
        raise ValueError("NV 价格格式无效") from None
    if not Decimal("0.01") <= price <= Decimal("999999.99"):
        raise ValueError("NV 价格必须在 0.01-999999.99 元之间")
    cents = int(price * 100)
    base_url, session_cookie = _connection(base_url, session_cookie)
    payload, status = _request(
        "PATCH", base_url=base_url, session_cookie=session_cookie,
        path="/api/supplier/cards/price",
        payload={"card_ids": [identity], "price_yuan": f"{price:.2f}"},
    )
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if (not isinstance(summary, dict) or type(summary.get("updated")) is not int
            or summary["updated"] != 1 or _int(summary.get("price_cents")) != cents):
        raise NexusVaultPriceEditUnconfirmed(
            "NV 未确认该账号更新为指定价格；请刷新价格核对，未自动重试"
        )
    return {"updated": 1, "price_cents": cents, "status_code": status}
