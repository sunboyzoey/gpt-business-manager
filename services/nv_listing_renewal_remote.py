"""Single-shot renewal of one existing NV inventory card.

The caller must authorize and journal the exact unsold inventory-card identity
before calling, and read back that same card afterward. Supplying ``card_ids``
selects NV's documented publish_existing mode; no action/mode selector, account
import, credential upload, automatic withdrawal, or retry is performed here.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re
from typing import Any

from services import nexusvault as nv
from services import nv_http as requests
from services.nv_listing_warranty import normalize_team5x_warranty


_ZERO_ACK_COUNTS = ("imported", "rejected", "import_rejected", "skipped", "duplicates", "quota_blocked")


class RenewalError(nv.NexusVaultError):
    """A fixed, credential-free failure suitable for a durable task message."""

    requires_readback = False


class RenewalValidationError(RenewalError, ValueError):
    """Invalid local input; no request was sent."""


class RenewalConfigurationError(RenewalError):
    """Local connection configuration could not be used; no request was sent."""


class RenewalRejected(RenewalError):
    """NV explicitly rejected this request; no automatic retry is allowed."""


class RenewalUncertain(RenewalError):
    """The mutation may have happened; only read-back reconciliation may follow."""

    requires_readback = True


@dataclass(frozen=True)
class RenewalResult:
    """Acknowledgement only, not proof of the card's resulting saleability."""

    inventory_card_id: str
    price_yuan: str
    warranty_until: str
    status_code: int
    published: int = 1
    confirmed: bool = True
    requires_readback: bool = True


def _price(value: Any) -> str:
    message = "NV 续期价格须为 0.01–999999.99 元，最多两位小数"
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise RenewalValidationError(message)
    raw = str(value).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,2})?", raw):
        raise RenewalValidationError(message)
    try:
        amount = Decimal(raw)
        if not Decimal("0.01") <= amount <= Decimal("999999.99"):
            raise RenewalValidationError(message)
    except InvalidOperation:
        raise RenewalValidationError(message) from None
    return f"{amount:.2f}"


def _connection() -> tuple[str, str]:
    try:
        configured_base, configured_key = nv.load_config()
        base = nv.normalize_base_url(configured_base)
        if not isinstance(configured_key, str):
            raise ValueError
        key = configured_key.strip()
        if not key or any(ord(char) < 32 or ord(char) == 127 for char in key):
            raise ValueError
    except Exception:
        raise RenewalConfigurationError("NV 续期配置不可用，请检查库存 API 配置；未发送请求") from None
    return base, key


def renew_existing_card(
    *, inventory_card_id: str, price_yuan: Any, warranty_until: str,
) -> RenewalResult:
    """Publish an existing inventory ID once with the requested 5X deadline.

    The ID is the original inventory ``cards.id``, never an order-card alias.
    A 2xx response with integer summary.published=1 acknowledges the request;
    the caller must still verify identity, deadline, price and pool status by
    reading NV before changing the locally frozen listing terms. An existing
    available card may be rejected by NV; this function never unpublishes it.
    """
    if not isinstance(inventory_card_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,160}", inventory_card_id,
    ):
        raise RenewalValidationError("NV 续期库存账号 ID 无效；未发送请求")
    price = _price(price_yuan)
    try:
        warranty = normalize_team5x_warranty({"mode": "until", "until": warranty_until})
    except (ValueError, TypeError, OverflowError):
        raise RenewalValidationError("NV 续期截止须为带时区且晚于当前时间的 ISO 时间；未发送请求") from None
    base, api_key = _connection()
    payload = {
        "card_ids": [inventory_card_id],
        "price_yuan": price,
        "team5x_warranty": warranty,
        "fallback_pool_enabled": False,
    }
    try:
        response = requests.post(
            f"{base}/api/inventory/cards/pool",
            headers={"accept": "application/json", "content-type": "application/json", "x-api-key": api_key},
            json=payload, timeout=(10, 90), allow_redirects=False, stream=True,
        )
    except requests.Timeout:
        raise RenewalUncertain("NV 续期请求超时，结果未知；需回读核对，未自动重试") from None
    except Exception:
        raise RenewalUncertain("NV 续期连接中断，结果未知；需回读核对，未自动重试") from None

    try:
        status = response.status_code
        if type(status) is not int or not 100 <= status <= 599:
            raise RenewalUncertain("NV 续期响应状态无法确认；需回读核对，未自动重试")
        if 400 <= status < 500 and status != 408:
            # Do not read or reflect a rejection body, which may contain keys.
            raise RenewalRejected(f"NV 明确拒绝续期请求（HTTP {status}）；未自动撤回、重新导入或重试")
        if not 200 <= status < 300:
            raise RenewalUncertain(f"NV 续期返回 HTTP {status}，结果未知；需回读核对，未自动重试")
        try:
            body = nv._read_bounded_json(response)
        except Exception:
            raise RenewalUncertain("NV 续期响应未完整读取，结果未知；需回读核对，未自动重试") from None
        summary = body.get("summary") if isinstance(body, dict) else None
        if not isinstance(summary, dict) or type(summary.get("published")) is not int or summary["published"] != 1:
            raise RenewalUncertain("NV 未明确确认本次单号续期成功；需回读核对，未自动重试")
        # One existing card cannot both be published and rejected/skipped, nor
        # should publish_existing import a new account. Treat malformed counts
        # and explicit failure/partial flags as conflicting acknowledgement,
        # even though a later read-back might still establish the actual state.
        conflict = any(
            key in summary and (type(summary[key]) is not int or summary[key] != 0)
            for key in _ZERO_ACK_COUNTS
        ) or any(key in body and body[key] is not True for key in ("ok", "success")) or any(
            body.get(key) for key in ("error", "errors", "partial", "action_required", "binding_changed", "identity_changed")
        )
        if conflict:
            raise RenewalUncertain("NV 续期响应包含相互矛盾的结果；需回读核对，未自动重试")
        return RenewalResult(
            inventory_card_id=inventory_card_id, price_yuan=price,
            warranty_until=warranty["until"], status_code=status,
        )
    except RenewalError:
        raise
    except Exception:
        raise RenewalUncertain("NV 续期响应无法确认；需回读核对，未自动重试") from None
    finally:
        try:
            response.close()
        except Exception:
            # Closing a consumed stream must neither leak errors nor replay it.
            pass
