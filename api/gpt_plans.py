"""GPT 套餐账号管理 API。

``gpt_plan_accounts`` 是套餐账号、退款、邮件、RT 和设备状态的本地
唯一权威数据源。历史 GPT PRO 数据只允许在数据库升级时执行一次性
迁移；本 API 不再执行来源同步或运行时回查。GPT BUSINESS 母号的
工作区管理仍可通过明确的 ``gpt_business`` 绑定委托给 BUSINESS
模块，但套餐行自身的邮件队列始终由套餐模块管理。

邮箱 OAuth 凭证、ChatGPT 会话令牌、Cookie 和卡要素只保存在服务端，
不通过列表或动作响应返回给浏览器。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from email import message_from_bytes
from email.policy import default as email_default_policy
from email.utils import parsedate_to_datetime, parseaddr
import json
import re
import threading
import time
import uuid
from typing import Any, Callable, Dict, Literal, Optional
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, PrivateAttr, StrictBool, StrictInt, model_validator
from sqlalchemy import and_, delete as sa_delete, inspect, or_
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select
from services.chatgpt_oauth_failure import normalize_oauth_failure
from services.chatgpt_security_recovery import can_inspect_pending_totp
from services.gpt_plan_appeals import safe_appeal_url, extract_appeal_link, public_lookup_state
from core.business_invite_policy import quota_for_seat

from core.db import (
    ChatGptAccountSecurityModel,
    DeliveryDeviceReplenishmentDemandModel,
    GptBusinessAccountModel,
    GptBusinessAutomationPolicyModel,
    GptBusinessChildMembershipModel,
    GptPlanAccountModel,
    GptPlanAccountOperationLeaseModel,
    GptPlanAccountUpgradeModel,
    IcloudHmeAliasModel,
    GptPlanCardModel,
    GptPlanPaymentAccountModel,
    GptPlanRoxyProxyModel,
    SyncDeviceModel,
    engine,
    resolve_business_delivery_binding,
)


router = APIRouter(prefix="/gpt-plans", tags=["gpt-plans"])

# 银行卡/支付账号是套餐管理的独立资产。子路由复用成熟的页面契约，
# 但底层模型分别是 gpt_plan_cards / gpt_plan_payment_accounts。
from api.gpt_plan_cards import (  # noqa: E402
    pa_router as _plan_payment_accounts_router,
    router as _plan_cards_router,
)
from api.gpt_plan_cpa_proxy import router as _plan_cpa_proxy_router  # noqa: E402

router.include_router(_plan_cards_router)
router.include_router(_plan_payment_accounts_router)
router.include_router(_plan_cpa_proxy_router)

MAX_FINISHED_IMPORT_TASKS = 20
MAX_FINISHED_UPGRADE_TASKS = 50
GPT_PLAN_OPERATION_LEASE_HOURS = 2
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso_utc(value: Optional[datetime]) -> str:
    aware = _aware_utc(value)
    return aware.isoformat() if aware else ""


_PLAN_LABELS = {
    "free": "免费套餐",
    "chatgptfreeplan": "免费套餐",
    "plus": "PLUS 套餐",
    "chatgptplusplan": "PLUS 套餐",
    "self_serve_plus": "PLUS 套餐",
    "go": "GO 套餐",
    "chatgptgo": "GO 套餐",
    "chatgptgoplan": "GO 套餐",
    "chatgpt_go": "GO 套餐",
    "self_serve_go": "GO 套餐",
    "pro": "PRO 套餐",
    "chatgptproplan": "PRO 套餐",
    "self_serve_pro": "PRO 套餐",
    "pro_20x": "PRO 20X",
    "pro_5x": "PRO 5X",
    "team": "TEAM 套餐",
    "chatgptteamplan": "TEAM 套餐",
    "business": "BUSINESS 套餐",
    "chatgptbusinessplan": "BUSINESS 套餐",
    "self_serve_business": "BUSINESS 套餐",
    "self_serve_business_prolite": "TEAM 5X 套餐",
    "business_master": "BUSINESS 母号",
}

_REGULAR_PLAN_TYPES = frozenset({"", "free", "chatgptfreeplan"})
_MEMBER_PLAN_TYPES = {
    "go": frozenset({
        "go",
        "chatgptgo",
        "chatgptgoplan",
        "chatgpt_go",
        "self_serve_go",
    }),
    "plus": frozenset({"plus", "chatgptplusplan", "self_serve_plus"}),
    "pro": frozenset({"pro", "chatgptproplan", "self_serve_pro", "pro_20x", "pro_5x"}),
    "team": frozenset({
        "team",
        "business",
        "chatgptteamplan",
        "chatgptbusinessplan",
        "self_serve_business",
        "self_serve_business_prolite",
        "business_master",
    }),
}

_CATALOG_CATEGORIES = frozenset({"regular", "member", "refunded"})
_BUSINESS_USAGE_TYPES = frozenset({"sale", "self_use", "transit"})
_BUSINESS_USAGE_FILTERS = frozenset({"unassigned", *_BUSINESS_USAGE_TYPES})
_BUSINESS_SEAT_FILTERS = frozenset({"available", "full", "unknown"})
_BUSINESS_CHILD_2FA_FILTERS = frozenset({
    "enabled",
    "not_enabled",
    "needs_attention",
})
_BUSINESS_CHILD_RT_FILTERS = frozenset({"acquired", "missing"})
_BUSINESS_CHILD_SALE_STATUSES = frozenset({"unlisted", "listed", "sold", "refunded", "partial_refund"})
_PUBLIC_REFUND_STATES = frozenset({
    "",
    "refund_manual_pending",
    "refund_pending",
    "refund_escalated",
    "refunded_pending_credit",
    "refund_credited",
})


def _normalize_plan_type(value: Any) -> str:
    return str(value or "").strip().lower()


def _plan_label(value: Any) -> str:
    plan_type = _normalize_plan_type(value)
    if not plan_type:
        return "未检测"
    return _PLAN_LABELS.get(plan_type, str(value or "").strip())


def _canonical_member_plan(value: Any) -> str:
    plan_type = _normalize_plan_type(value)
    for member_plan, aliases in _MEMBER_PLAN_TYPES.items():
        if plan_type in aliases:
            return member_plan
    return ""


def _account_type(value: Any) -> str:
    # 任何非免费套餐都留在会员 Tab，避免服务端新增套餐代码时账号从两个
    # 主 Tab 同时消失；未识别的会员代码 member_plan 为空并继续原样展示。
    return "regular" if _normalize_plan_type(value) in _REGULAR_PLAN_TYPES else "member"


def _public_business_usage_type(value: Any) -> Optional[str]:
    """Return the catalog's narrow BUSINESS usage label or ``None``.

    Empty and legacy-invalid values are intentionally indistinguishable to the
    browser: both mean that an operator still needs to classify the mother.
    """
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _BUSINESS_USAGE_TYPES else None


def _catalog_category(account: GptPlanAccountModel) -> str:
    """Return the mutually-exclusive directory category for one account.

    Legacy/manual rows have an empty ``catalog_category`` and continue to be
    classified from their detected plan. ``refunded`` is the local lifecycle
    override populated by refund actions and mail monitoring.
    """
    explicit = str(getattr(account, "catalog_category", "") or "").strip().lower()
    # 退款是目录生命周期覆盖项；普通/会员仍由实时检测到的 plan_type
    # 决定，确保普通账号在套餐页升级后会立即移入会员 Tab。
    if explicit == "refunded":
        return "refunded"
    return _account_type(account.plan_type)


def _catalog_category_predicate(category: str):
    explicit = func.lower(func.trim(func.coalesce(
        GptPlanAccountModel.catalog_category,
        "",
    )))
    plan_expr = func.lower(func.trim(func.coalesce(
        GptPlanAccountModel.plan_type,
        "",
    )))
    not_refunded = explicit != "refunded"
    if category == "regular":
        return and_(not_refunded, plan_expr.in_(tuple(_REGULAR_PLAN_TYPES)))
    if category == "member":
        return and_(not_refunded, ~plan_expr.in_(tuple(_REGULAR_PLAN_TYPES)))
    if category == "refunded":
        return explicit == "refunded"
    raise ValueError(f"unsupported catalog category: {category}")


def _has_saved_login_predicate():
    # BUSINESS 的“已登录”定义同样包含“曾保存过 Cookie，但当前 blob 已清空”
    # 的账号；套餐目录必须保持这一持久登录语义。
    return or_(
        GptPlanAccountModel.cookie_updated_at.is_not(None),  # type: ignore[union-attr]
        func.length(func.trim(func.coalesce(
            GptPlanAccountModel.cookie_blob,
            "",
        ))) > 0,
    )


def _normalize_mail_provider(value: Any) -> str:
    provider = str(value or "outlook").strip().lower()
    if provider in {"icloud", "qqmail"}:
        return "icloud"
    if provider not in {"outlook", "gmail"}:
        raise HTTPException(400, "mail_provider 只支持 outlook、icloud 或 gmail")
    return provider


def _mail_access_meta(value: Any) -> tuple[str, str]:
    mail_type = str(value or "").strip().lower()
    return {
        "graph": ("Graph API", "success"),
        "imap_pop": ("IMAP/POP", "warning"),
        "": ("未检测", "default"),
    }.get(mail_type, (mail_type or "未知", "default"))


_CHATGPT_SECURITY_PUBLIC_FIELDS = (
    "has_password",
    "has_chatgpt_password",
    "has_totp",
    "has_chatgpt_totp",
    "has_recovery_codes",
    "credentials_readable",
    "password_state",
    "mfa_state",
    "last_error",
    "password_updated_at",
    "mfa_updated_at",
    "updated_at",
)


def _unavailable_chatgpt_security_status() -> Dict[str, Any]:
    """Fail-closed public state used when the independent store is unavailable."""
    return {
        "has_password": False,
        "has_chatgpt_password": False,
        "has_totp": False,
        "has_chatgpt_totp": False,
        "has_recovery_codes": False,
        "credentials_readable": False,
        "password_state": "unknown",
        "mfa_state": "unknown",
        "last_error": "账号安全状态暂时不可用",
        "password_updated_at": "",
        "mfa_updated_at": "",
        "updated_at": "",
    }


def _public_chatgpt_security_status(value: Any) -> Dict[str, Any]:
    """Copy only credential-free fields from the encrypted-store snapshot."""
    source = value if isinstance(value, dict) else {}
    fallback = _unavailable_chatgpt_security_status()
    public = {
        key: source.get(key, fallback[key])
        for key in _CHATGPT_SECURITY_PUBLIC_FIELDS
    }
    # Old rows may predate store-level error redaction.  Apply the API's final
    # response redactor as a second boundary before returning the message.
    public["last_error"] = _redact_text(public.get("last_error", ""))
    return public


def _chatgpt_security_status_for_email(email: str) -> Dict[str, Any]:
    from services.chatgpt_security_store import get_chatgpt_security_status

    try:
        return get_chatgpt_security_status(str(email or ""))
    except Exception:
        return _unavailable_chatgpt_security_status()


def _chatgpt_security_email_key(email: Any) -> str:
    from core.credential_crypto import normalize_credential_email

    try:
        return normalize_credential_email(str(email or ""))
    except (TypeError, ValueError):
        return ""


def _chatgpt_security_status_map(
    emails: list[str],
) -> Dict[str, Dict[str, Any]]:
    """Read one account page in a single security-store query."""
    from core.credential_crypto import normalize_credential_email
    from services.chatgpt_security_store import get_chatgpt_security_statuses

    normalized: list[str] = []
    for email in emails:
        try:
            normalized.append(normalize_credential_email(email))
        except (TypeError, ValueError):
            continue
    try:
        rows = get_chatgpt_security_statuses(emails)
    except Exception:
        rows = {}
    return {
        email: rows.get(email, _unavailable_chatgpt_security_status())
        for email in normalized
        if email
    }


def _safe_plan_appeal_url(value: Any) -> str:
    """Only browser-safe HTTPS links may leave the account's appeal field."""
    return safe_appeal_url(value)


def _serialize_account(
    account: GptPlanAccountModel,
    upgrade: Optional[GptPlanAccountUpgradeModel] = None,
    member_source: Optional[Dict[str, Any]] = None,
    chatgpt_security: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """显式 allow-list DTO；不得把任何凭证或原始 Cookie 放入返回值。"""
    mail_type = str(account.mail_access_type or "").strip().lower()
    mail_label, mail_color = _mail_access_meta(mail_type)
    from services.gmail_plan_support import account_mail_provider, gmail_receive_metadata
    provider = account_mail_provider(account)
    gmail_meta = gmail_receive_metadata(account) if provider == "gmail" else {}
    has_cookie = bool(str(account.cookie_blob or "").strip())
    has_saved_login = bool(has_cookie or account.cookie_updated_at is not None)
    cookie_expires_at = _aware_utc(account.cookie_expires_at)
    cookie_valid = (
        cookie_expires_at > _utcnow() if cookie_expires_at is not None else None
    )
    has_mail_credentials = gmail_meta.get("gmail_receive_ready", False) if provider == "gmail" else (
        provider == "icloud"
        or bool(str(account.password or "").strip())
        or bool(
            str(account.client_id or "").strip()
            and str(account.refresh_token or "").strip()
        )
    )
    plan_type = _normalize_plan_type(account.plan_type)
    account_type = _catalog_category(account)
    member_plan = (
        _canonical_member_plan(plan_type) if account_type == "member" else ""
    )
    secret_values = (
        str(account.password or ""),
        str(account.client_id or ""),
        str(account.refresh_token or ""),
        str(account.cookie_blob or ""),
    )
    checkout_country = str(getattr(upgrade, "checkout_country", "") or "")
    checkout_currency = str(getattr(upgrade, "checkout_currency", "") or "")
    upgraded_at = getattr(upgrade, "plan_upgraded_at", None)
    checkout_target = str(getattr(upgrade, "checkout_target", "") or "")
    live_policy_warning = bool(account.policy_warning)
    live_policy_warning_detected_at = _iso_utc(account.policy_warning_detected_at)
    live_dangerous = bool(account.dangerous)
    live_dangerous_detected_at = _iso_utc(account.dangerous_detected_at)
    mail_monitor_owner = "plan"
    last_mail_check_at = _iso_utc(account.last_mail_check_at)
    last_mail_check_error = str(account.last_mail_check_error or "")
    unread_count = len(_safe_json_list(account.pending_alerts_json))
    inbox_unread_count = len(_safe_json_list(account.pending_inbox_json))
    delegated_business = str(account.source_pool or "").strip() == "gpt_business"
    public_source_pool = (
        "gpt_business"
        if delegated_business
        else "gpt_plan"
        if account_type in {"member", "refunded"}
        else ""
    )
    public_source_account_id = (
        int(account.source_account_id or 0) or None
        if delegated_business
        else int(account.id or 0) or None
        if account_type in {"member", "refunded"}
        else None
    )
    return {
        "id": account.id,
        "email": account.email,
        "mail_provider": provider,
        **gmail_meta,
        "mail_access_type": mail_type,
        "mail_access_type_label": mail_label,
        "mail_access_type_color": mail_color,
        "has_mail_credentials": has_mail_credentials,
        "has_password": bool(str(account.password or "").strip()),
        "plan_type": plan_type,
        "plan_label": _plan_label(plan_type),
        "account_type": account_type,
        "catalog_category": account_type,
        "member_plan": member_plan,
        "plan_checked_at": _iso_utc(account.plan_checked_at),
        # 升级摘要来自独立表。subscribed_at 是前端兼容别名，
        # 两者都只表示已经过套餐复核，不表示“创建了 checkout”。
        "plan_upgraded_at": _iso_utc(upgraded_at),
        "subscribed_at": _iso_utc(upgraded_at),
        "business_upgraded_at": (
            _iso_utc(upgraded_at) if member_plan == "team" else ""
        ),
        "payment_card_last4": str(
            getattr(upgrade, "payment_card_last4", "") or ""
        ),
        "payment_account_id": int(
            getattr(upgrade, "payment_account_id", 0) or 0
        ),
        "payment_account_name": str(
            getattr(upgrade, "payment_account_name", "") or ""
        ),
        "payment_account_type": str(
            getattr(upgrade, "payment_account_type", "") or ""
        ),
        "last_checkout_at": _iso_utc(
            getattr(upgrade, "checkout_created_at", None)
        ),
        "last_checkout_plan": checkout_target,
        "last_checkout_status": str(
            getattr(upgrade, "checkout_status", "") or ""
        ),
        "last_checkout_country": checkout_country,
        "last_checkout_currency": checkout_currency,
        "last_checkout_region": (
            f"{checkout_country}/{checkout_currency}"
            if checkout_country and checkout_currency
            else ""
        ),
        "last_checkout_workspace": str(
            getattr(upgrade, "workspace_name", "") or ""
        ),
        "chatgpt_account_id": str(account.chatgpt_account_id or ""),
        "chatgpt_user_id": str(account.chatgpt_user_id or ""),
        "source_pool": public_source_pool,
        "source_account_id": public_source_account_id,
        "source_state": str(getattr(account, "source_state", "") or ""),
        "source_synced_at": _iso_utc(
            getattr(account, "source_synced_at", None)
        ),
        "business_usage_type": _public_business_usage_type(
            getattr(account, "business_usage_type", "")
        ),
        "dangerous": live_dangerous,
        "dead": live_dangerous,
        "dangerous_detected_at": live_dangerous_detected_at,
        "appeal_url": _safe_plan_appeal_url(account.appeal_url),
        "appeal_done_at": _iso_utc(account.appeal_done_at),
        "appeal_link_lookup": public_lookup_state(account),
        # Dead/policy state is owned by this row and updates atomically with mail.
        "policy_warning": live_policy_warning,
        "policy_warning_detected_at": live_policy_warning_detected_at,
        "has_cookie": has_cookie,
        "cookie_valid": cookie_valid,
        "cookie_updated_at": _iso_utc(account.cookie_updated_at),
        "cookie_expires_at": _iso_utc(account.cookie_expires_at),
        "login_status": "logged_in" if has_saved_login else "not_logged_in",
        "login_status_label": "已登录" if has_saved_login else "未登录",
        "last_login_at": _iso_utc(account.last_login_at),
        "last_login_error": _redact_text(account.last_login_error, *secret_values),
        "last_mail_fetch_at": _iso_utc(account.last_mail_fetch_at),
        "last_mail_error": _redact_text(account.last_mail_error, *secret_values),
        "mail_monitor_owner": mail_monitor_owner,
        "last_mail_check_at": last_mail_check_at,
        "last_mail_check_error": _redact_text(
            last_mail_check_error,
            *secret_values,
        ),
        "unread_count": unread_count,
        "inbox_unread_count": inbox_unread_count,
        "note": str(account.note or ""),
        "enabled": bool(account.enabled),
        "created_at": _iso_utc(account.created_at),
        "updated_at": _iso_utc(account.updated_at),
        "last_used": _iso_utc(account.last_used),
        # Password/TOTP values live in the independent encrypted security
        # store.  Only its credential-free workflow state may cross this DTO.
        "chatgpt_security": _public_chatgpt_security_status(
            chatgpt_security
            if chatgpt_security is not None
            else _chatgpt_security_status_for_email(account.email)
        ),
        # BUSINESS workspace state is injected in one batched query; all other
        # member state is constructed directly from this account row.
        "member_source": member_source if account_type in {"member", "refunded"} else None,
    }


def serialize_gpt_plan_account(
    account: GptPlanAccountModel,
    upgrade: Optional[GptPlanAccountUpgradeModel] = None,
    member_source: Optional[Dict[str, Any]] = None,
    chatgpt_security: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """公共安全序列化入口，供测试和后续服务复用。"""
    return _serialize_account(
        account,
        upgrade,
        member_source,
        chatgpt_security,
    )


class GptPlanBatchImportRequest(BaseModel):
    data: str
    enabled: bool = True
    mail_provider: str = "gmail"


class GptPlanAccountUpdateRequest(BaseModel):
    password: Optional[str] = None
    client_id: Optional[str] = None
    refresh_token: Optional[str] = None
    mail_access_type: Optional[str] = None
    mail_provider: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class GptPlanAccountNoteRequest(BaseModel):
    """Single-field note mutation; never accepts account credentials."""

    note: str


class GptPlanBusinessUsageRequest(BaseModel):
    """Operator-owned classification for one BUSINESS mother only."""

    model_config = {"extra": "forbid"}
    business_usage_type: Optional[Literal["sale", "self_use", "transit"]] = Field(...)


class GptPlanBusinessWorkspaceReferralsRequest(BaseModel):
    """Toggle the one allow-listed remote BUSINESS Workspace preference."""

    model_config = {"extra": "forbid"}
    enabled: StrictBool


class GptPlanBusinessChildSaleRequest(BaseModel):
    """Operator-owned sale lifecycle metadata for one active membership.

    Raw scalar types are retained until the endpoint validates them.  In
    particular, JSON booleans must never be coerced into a warranty duration.
    Each field may be patched independently, while an empty body is rejected.
    """

    model_config = {"extra": "forbid"}
    sale_status: Any = None
    sold_at: Any = None
    warranty_hours: Any = None


class GptPlanNexusVaultConfigRequest(BaseModel):
    """Write-only NexusVault credential settings.

    The API key is intentionally never returned by a response.  Sending an
    empty key preserves the existing value so opening and saving the settings
    dialog cannot accidentally erase a configured secret.
    """

    model_config = {"extra": "forbid"}
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    query_cookie: Optional[str] = None


class GptPlanNexusVaultListingRequest(BaseModel):
    """Price, legacy TEAM warranty and explicit 5X deadline for one listing."""

    model_config = {"extra": "forbid"}
    price_yuan: Any
    warranty_hours: Any = 1
    team5x_warranty: Optional[dict[str, Any]] = None
    # Durable automation freezes the exact server-resolved membership before
    # entering this canonical capability. HTTP input can neither populate nor
    # serialize this guard.
    _expected_target: Optional[dict[str, Any]] = PrivateAttr(default=None)


class GptPlanNexusVaultBatchListingRequest(GptPlanNexusVaultListingRequest):
    """Selected membership identities; raw IDs retain strict validation."""

    membership_ids: Any


class GptPlanLoginRequest(BaseModel):
    proxy: Optional[str] = None
    headless: bool = True
    otp_timeout: int = 180
    keep_browser_open: bool = False
    # None = /upgrade-pro 使用服务端统一配置；普通登录仍回退 local。
    browser_backend: Optional[str] = None
    roxy_proxy_id: Optional[int] = None


class GptPlanSecuritySetupTaskRequest(BaseModel):
    """Narrow request envelope for the credential-producing security flow."""

    params: Dict[str, Any] = Field(default_factory=dict)
    # The Plan UI uses the flat shape; ``params`` remains compatible with the
    # established generic action-task envelope.
    browser_mode: Optional[str] = None
    proxy: Optional[str] = None


class GptPlanMsLoginRequest(BaseModel):
    """Open the saved Microsoft mailbox in a visible browser."""

    proxy: Optional[str] = None
    headless: bool = False


class GptPlanUpgradeProRequest(GptPlanLoginRequest):
    """GPT 套餐池升级 PRO 所需的最小入参。"""

    auto_pick_seconds: int = 8
    checkout_card: Optional[str] = None
    pro_only: bool = False
    # 内部套餐规格。两种规格共用 ChatGPT PRO 结账流程，成功后保留所选库存标签。
    target_plan: Literal["pro", "pro_20x", "pro_5x"] = "pro"


class GptPlanUpgradeManualConfirmRequest(BaseModel):
    """已退款账号重新升级 PRO 后的人工裁定。

    ``task_id`` 只用来同步当前进程内仍存在的浏览器任务；
    权威状态保存在 ``gpt_plan_account_upgrades``，因此服务重启后
    仍可以不传 task_id 完成确认。
    """

    success: bool
    task_id: Optional[str] = None


class GptPlanBusinessCheckoutRequest(GptPlanLoginRequest):
    workspace_name: str
    # Omission uses the current persisted default; an explicit value applies
    # only to this checkout and never changes the shared preference.
    coupon: Optional[str] = None
    seat_quantity: int = 2
    seat_type: str = "default"
    country: str = "US"
    currency: str = "USD"
    auto_fill: bool = True
    # 真实扣款开关；默认必须为 False。
    auto_submit: bool = False
    checkout_card: Optional[str] = None


class GptPlanBusinessCheckoutConfigRequest(BaseModel):
    coupon: str


class GptPlanBusinessInviteConfigRequest(BaseModel):
    limit: Optional[StrictInt] = Field(default=None, ge=1, le=100)
    default_limit: Optional[StrictInt] = Field(default=None, ge=1, le=100)
    prolite_limit: Optional[StrictInt] = Field(default=None, ge=1, le=100)

    @model_validator(mode="after")
    def complete_limits(self):
        if self.limit is not None:
            if self.default_limit is not None or self.prolite_limit is not None:
                raise ValueError("请提交分类上限或旧版统一上限，不能混用")
        elif self.default_limit is None or self.prolite_limit is None:
            raise ValueError("请同时填写普通席位和高级席位的邀请上限")
        return self


class GptPlanBusinessInviteUsageRequest(BaseModel):
    model_config = {"extra": "forbid"}

    seat_type: Literal["default", "prolite"]
    target_used: StrictInt = Field(ge=0)
    window_started_at: str = Field(min_length=1, max_length=64)
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,128}$")
    note: str = Field(default="", max_length=500)


class GptPlanRefundedMigrationRequest(BaseModel):
    """Move one safe local refunded account into a paid-plan category."""

    target_plan: Literal["pro", "business", "plus", "go"]


class GptPlanMemberRefundRequest(BaseModel):
    """Refund action for one locally authoritative plan account."""

    refund_manual: bool = False
    refund_message: Optional[str] = None
    proxy: Optional[str] = None
    # 套餐管理的退款流程需要让操作人能看到客服页面和接管异常挑战。
    # 字段继续保留以兼容旧客户端，但服务端退款入口始终强制使用有头浏览器。
    headless: bool = False
    keep_browser_open: bool = False
    otp_timeout: int = 180


class GptPlanMemberOauthRequest(BaseModel):
    proxy: Optional[str] = None
    headless: bool = True
    keep_browser_open: bool = False
    otp_timeout: int = 180


class GptPlanMemberDeviceSyncRequest(BaseModel):
    device_ref: str


class GptPlanBusinessProBurnRequest(BaseModel):
    # Keep raw JSON scalar types until the facade rejects booleans, floats and
    # strings.  A normal ``list[int]`` would coerce ``true`` to account id 1.
    account_ids: list[Any]
    concurrency: int = 1
    kick: bool = True


class GptPlanBusinessChildInviteRequest(BaseModel):
    """Invite one server-owned regular account into a bound BUSINESS mother.

    ``pro_account_id`` deliberately remains untyped until the endpoint applies
    strict JSON scalar validation.  In particular, JSON ``true`` must never be
    accepted as account id ``1``.  Omitting the id selects through the source
    BUSINESS pool policy; callers never submit an email or seat type.
    """

    operation_id: str = ""
    pro_account_id: Any = None
    manual_email: Any = None
    candidate_mail_provider: Any = "auto"
    # Internal automation identity fence.  A JSON field with this name is
    # ignored by Pydantic and cannot set the private value.
    _expected_target: Optional[dict[str, Any]] = PrivateAttr(default=None)
    _expected_seat_type: str = PrivateAttr(default="")
    # Server-only observer for invitation pre-login; never settable over JSON.
    _log_fn: Optional[Callable[[str], None]] = PrivateAttr(default=None)
    _state_guard: Optional[Callable[[], Any]] = PrivateAttr(default=None)
    _selection_observer: Optional[Callable[[int, str], Any]] = PrivateAttr(default=None)
    _invite_progress_fn: Optional[Callable[[dict[str, Any]], Any]] = PrivateAttr(default=None)


class GptPlanBusinessBatchInviteRequest(BaseModel):
    """Snapshot and sequentially fill a selected set of BUSINESS mothers."""

    model_config = {"extra": "forbid"}
    account_ids: list[Any] = Field(default_factory=list)
    select_all_matching: Any = False
    account_id: Any = None
    keyword: Optional[str] = None
    login_status: Any = None
    business_usage_type: Any = None
    # Batch fill intentionally accepts only positively verified vacancies.
    business_seat_filter: Literal["available"] = "available"
    candidate_mail_provider: Any = "auto"
    # Optional child-owned post processing.  Invitation itself remains the
    # mother capability; these switches merely compose the established child
    # security/OAuth capabilities after the new membership is persisted.
    post_setup_security: Any = False
    post_acquire_rt: Any = False
    security_browser_mode: Any = "headless"


class GptPlanPreparedBatchInviteRequest(BaseModel):
    """Prepare Gmail children in parallel, then invite them in one command."""

    model_config = {"extra": "forbid"}
    seat_type: Any
    count: Any
    post_acquire_rt: Any = True


class GptPlanBusinessChildBatchActionRequest(BaseModel):
    """Run one child capability sequentially for exact membership ids."""

    model_config = {"extra": "forbid"}
    action: Literal["setup_security", "oauth", "leave_workspace"]
    # Keep raw scalar types until the authority boundary rejects JSON booleans
    # and coercible strings instead of silently treating them as integer ids.
    membership_ids: list[Any] = Field(default_factory=list)
    browser_mode: Literal["headless", "headed"] = "headless"
    force: Any = False
    confirm_remove: StrictBool = False


class GptPlanBusinessMotherBatchLeaveRequest(BaseModel):
    """Exit every currently joined child derived from one exact mother."""

    model_config = {"extra": "forbid"}
    confirm_remove: StrictBool = False


class GptPlanBusinessChildReplaceRequest(BaseModel):
    """Confirm a full-seat replacement using one persisted membership row."""

    operation_id: str
    membership_id: Any
    new_pro_account_id: Any = None
    candidate_mail_provider: Any = "auto"
    confirm_replace: Any = False


class GptPlanBusinessChildRemoveRequest(BaseModel):
    """Release one exact persisted BUSINESS child without replacing it.

    The browser deliberately submits only the local membership identity.  The
    facade derives every remote identifier from the bound database row so a
    stale or forged user/invite id can never select another workspace member.
    """

    operation_id: str
    membership_id: Any
    confirm_remove: Any = False
    # A queued batch freezes its server-derived identity.  This is deliberately
    # private: neither HTTP input nor the public schema can set this guard.
    _batch_expected_target: Optional[dict[str, Any]] = PrivateAttr(default=None)


class GptPlanBusinessDeviceMigrationRequest(BaseModel):
    operation_id: str
    target_device_ref: str
    # Preserve the JSON scalar until the facade rejects bool/string values.
    # Python bool is an int subclass and must never become revision 1.
    expected_policy_revision: Any


class GptPlanBusinessDeviceBindingPutRequest(BaseModel):
    """Bind one server-resolved BUSINESS mother to one local device.

    The browser supplies only a device identity and an optimistic policy
    revision.  It can never choose a BUSINESS source id, and the facade never
    accepts migration, invitation, credential or upload options.
    """

    device_ref: Any
    # Keep the raw JSON scalar so ``true`` and coercible strings cannot become
    # valid revisions at this authority boundary.
    expected_policy_revision: Any


class GptPlanCheckoutRegionRequest(BaseModel):
    country: str
    currency: str


class GptPlanUpgradeBrowserConfigRequest(BaseModel):
    browser_backend: Optional[Literal["local", "roxybrowser"]] = None
    roxy_proxy_id: Optional[int] = None
    use_roxy: Optional[bool] = None


class GptPlanRoxyProxyBatchRequest(BaseModel):
    data: str = ""
    protocol: str = "SOCKS5"


class GptPlanRoxyProxyUpdateRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class GptPlanRoxyProxyImportRequest(BaseModel):
    prune: bool = False


class GptPlanRoxyProxyDetectRequest(BaseModel):
    ids: list[int] = []


class GptPlanIcloudConfigUpdateRequest(BaseModel):
    values: Dict[str, str]


class GptPlanFetchMailRequest(BaseModel):
    limit: int = 10
    folder: Optional[str] = None


class GptPlanDismissAlertsRequest(BaseModel):
    # None / [] = 清空该账号全部铃铛提醒。
    alert_ids: Optional[list[str]] = None


class GptPlanDismissInboxRequest(BaseModel):
    # None / [] = 清空该账号全部新邮件提醒。
    inbox_ids: Optional[list[str]] = None


@dataclass
class _ImportTask:
    id: str
    total: int
    status: str = "pending"
    processed: int = 0
    success: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "progress": f"{self.processed}/{self.total}",
            "total": self.total,
            "processed": self.processed,
            "success": self.success,
            "failed": self.failed,
            "errors": list(self.errors),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class _ImportTaskStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, _ImportTask] = {}

    def create(self, task_id: str, total: int) -> None:
        with self._lock:
            self._items[task_id] = _ImportTask(id=task_id, total=total)

    def mark_running(self, task_id: str) -> None:
        with self._lock:
            item = self._items[task_id]
            item.status = "running"
            item.updated_at = time.time()

    def update(
        self,
        task_id: str,
        *,
        processed: int,
        success: int,
        failed: int,
        error: str = "",
    ) -> None:
        with self._lock:
            item = self._items[task_id]
            item.processed = processed
            item.success = success
            item.failed = failed
            if error:
                item.errors.append(error[:500])
            item.updated_at = time.time()

    def finish(self, task_id: str, *, failed_message: str = "") -> None:
        with self._lock:
            item = self._items[task_id]
            item.status = "failed" if failed_message else "done"
            if failed_message:
                item.errors.append(failed_message[:500])
            item.updated_at = time.time()
            finished = sorted(
                (
                    value
                    for value in self._items.values()
                    if value.status in {"done", "failed"}
                ),
                key=lambda value: value.updated_at,
                reverse=True,
            )
            for old in finished[MAX_FINISHED_IMPORT_TASKS:]:
                self._items.pop(old.id, None)

    def snapshot(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._items.get(task_id)
            return item.public() if item else None

    def list(self, limit: int) -> list[Dict[str, Any]]:
        with self._lock:
            items = sorted(
                self._items.values(), key=lambda value: value.updated_at, reverse=True
            )[:limit]
            return [item.public() for item in items]


_import_tasks = _ImportTaskStore()


def _upgrade_summary_map(
    session: Session,
    account_ids: list[int],
) -> dict[int, GptPlanAccountUpgradeModel]:
    if not account_ids:
        return {}
    rows = session.exec(
        select(GptPlanAccountUpgradeModel).where(
            col(GptPlanAccountUpgradeModel.account_id).in_(account_ids)
        )
    ).all()
    return {int(row.account_id): row for row in rows}


def _get_upgrade_summary(
    session: Session,
    account_id: int,
) -> Optional[GptPlanAccountUpgradeModel]:
    return session.get(GptPlanAccountUpgradeModel, int(account_id))


def _normalized_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _public_refund_status(value: Any) -> str:
    status = str(value or "").strip()
    return status if status in _PUBLIC_REFUND_STATES else "unknown"


def _safe_json_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _safe_json_list(value: Any) -> list[dict[str, Any]]:
    """容错读取邮件队列，且丢弃非对象项。

    队列可能来自旧版数据库，API 不能因一条损坏数据让整个
    提醒汇总失败。
    """
    try:
        parsed = json.loads(str(value or "[]"))
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _member_capability(
    supported: bool,
    reason: str = "",
    *,
    formats: Optional[list[str]] = None,
    providers: Optional[list[str]] = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "supported": bool(supported),
        "reason": "" if supported else str(reason or "当前账号不支持该操作")[:300],
    }
    if formats is not None:
        result["formats"] = list(formats)
    if providers is not None:
        result["providers"] = list(providers)
    return result


def _unsupported_member_capabilities(reason: str) -> dict[str, dict[str, Any]]:
    return {
        "refund": _member_capability(False, reason),
        "pro_refund_burn": {
            **_member_capability(False, reason),
            "remaining": 0,
            "limit": 4,
        },
        "business_children": _member_capability(False, reason),
        "oauth": _member_capability(False, reason),
        "oauth_file": _member_capability(
            False,
            reason,
            formats=["cpa", "sub2api"],
        ),
        "sync_device": _member_capability(
            False,
            reason,
            providers=["cpa", "sub2api"],
        ),
        "device_usage": _member_capability(
            False,
            reason,
            providers=["cpa", "sub2api"],
        ),
    }


def _missing_member_source(
    account: GptPlanAccountModel,
    reason: str,
) -> dict[str, Any]:
    safe_reason = str(reason or "会员账号当前不可操作")[:300]
    return {
        "source_pool": str(account.source_pool or ""),
        "source_account_id": account.source_account_id,
        "source_missing": True,
        "source_error": safe_reason,
        "has_codex_rt": False,
        "codex_refresh_token_len": 0,
        "codex_rt_acquired_at": "",
        "refund_status": "",
        "refund_detected_at": "",
        "refund_credited_at": "",
        "refund_manual_at": "",
        "human_review_requested_at": "",
        "invite_cooldown": None,
        "invite_cooldown_active": False,
        "invite_cooldown_started_at": "",
        "invite_cooldown_until": "",
        "invite_cooldown_reason": "",
        "policy_warning": False,
        "policy_warning_detected_at": "",
        "dangerous": bool(account.dangerous),
        "dangerous_detected_at": _iso_utc(account.dangerous_detected_at),
        "mail_monitor_owner": "plan",
        "last_mail_check_at": _iso_utc(
            getattr(account, "last_mail_check_at", None)
        ),
        "last_mail_check_error": str(
            getattr(account, "last_mail_check_error", "") or ""
        )[:300],
        "unread_count": len(_safe_json_list(getattr(
            account,
            "pending_alerts_json",
            "[]",
        ))),
        "inbox_unread_count": len(_safe_json_list(getattr(
            account,
            "pending_inbox_json",
            "[]",
        ))),
        "business_workspace": None,
        "business_device_binding": None,
        "cpa": None,
        "sub2api": None,
        "capabilities": _unsupported_member_capabilities(safe_reason),
    }


_BUSINESS_TEAM_SESSION_REASON_MESSAGES = {
    "usable": "",
    "never_logged": "BUSINESS 母号从未登录 Team 工作区",
    "missing_access_token": "BUSINESS 母号缺少 Team Access Token",
    "invalid_access_token": "BUSINESS 母号 Team 登录会话无效",
    "expired_access_token": "BUSINESS 母号 AT 已到期，请检查会话以尝试刷新",
    "missing_workspace": "BUSINESS 母号会话缺少 Team 工作区",
    "invalid_team_plan": "当前会话不是 Team/BUSINESS 工作区",
    "remote_session_invalid": "BUSINESS 会话已被远端拒绝，请检查会话或重新登录母号",
}


def _safe_business_count(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 1_000_000 else None


def _safe_business_time(value: Any) -> str:
    text = str(value or "").strip()
    if 1 <= len(text) <= 80 and re.fullmatch(r"[0-9TZ:+.\- ]+", text):
        return text
    return ""


def _safe_business_vacancy_policy(raw_policy: Any) -> Optional[dict[str, Any]]:
    """Return the persisted DELETE-member policy as a strict public DTO.

    ``vacancy_policy`` lives beside other private BUSINESS state in
    ``extra_json``.  Never forward that object directly: older rows or manual
    repairs may contain the original ``policy_notice`` or unrelated secrets.
    A missing policy is distinct from a captured DELETE response whose policy
    was empty, so the former remains ``None`` while the latter is represented
    by ``policy_present=False`` and nullable values.
    """
    if not isinstance(raw_policy, dict):
        return None

    def nullable_count(key: str, *, maximum: int = 1_000_000) -> Optional[int]:
        value = raw_policy.get(key)
        # Do not coerce strings, floats or JSON booleans at this trust
        # boundary.  The canonical writer persists JSON integers.
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if 0 <= value <= maximum else None

    http_status = nullable_count("http_status", maximum=599)

    def nullable_time(key: str) -> Optional[str]:
        value = raw_policy.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            return None
        return _safe_business_time(value) or None

    return {
        "vacancy_ordinal": nullable_count("vacancy_ordinal"),
        "free_vacancy_threshold": nullable_count("free_vacancy_threshold"),
        "billing_starts_at": nullable_time("billing_starts_at"),
        "expires_at": nullable_time("expires_at"),
        "captured_at": nullable_time("captured_at"),
        "http_status": http_status,
        "policy_present": (
            raw_policy.get("policy_present")
            if isinstance(raw_policy.get("policy_present"), bool)
            else False
        ),
    }


def _safe_business_seat_summary(source: Any) -> Optional[dict[str, Any]]:
    from api.gpt_business import _business_workspace_snapshot

    workspace = _business_workspace_snapshot(source)
    raw = (
        workspace.get("seat_summary")
        if isinstance(workspace, dict)
        and isinstance(workspace.get("seat_summary"), dict)
        else None
    )
    if raw is None:
        return None

    raw_by_type = raw.get("by_type") if isinstance(raw.get("by_type"), dict) else {}
    capacity_known = bool(raw.get("seat_type_capacity_known"))
    occupancy_known = bool(raw.get("seat_type_occupancy_known"))
    by_type: dict[str, dict[str, Any]] = {}
    for seat_type in ("default", "prolite"):
        item = raw_by_type.get(seat_type)
        item = item if isinstance(item, dict) else {}
        can_invite = item.get("can_invite")
        total_by_type = _safe_business_count(item.get("total"))
        used_by_type = _safe_business_count(item.get("used"))
        available_by_type = _safe_business_count(item.get("available"))
        raw_exact = item.get("availability_exact")
        availability_exact = raw_exact if isinstance(raw_exact, bool) else None
        # Older persisted snapshots predate availability_exact.  Derive a
        # positive value only when both typed capacity and typed occupancy are
        # known and the arithmetic fields are present; otherwise preserve the
        # unknown state as None instead of inventing False.
        if (
            availability_exact is None
            and capacity_known
            and occupancy_known
            and total_by_type is not None
            and available_by_type is not None
        ):
            availability_exact = True
        by_type[seat_type] = {
            "total": total_by_type,
            "used": used_by_type,
            "available": available_by_type,
            "can_invite": can_invite if isinstance(can_invite, bool) else None,
            "known": availability_exact is True,
            "capacity_known": bool(capacity_known and total_by_type is not None),
            "availability_exact": availability_exact,
        }

    def seat_types(field: str) -> list[str]:
        values = raw.get(field)
        if not isinstance(values, list):
            return []
        return [
            value for value in (str(item or "").strip().lower() for item in values)
            if value in {"default", "prolite"}
        ]

    owner_type = str(raw.get("owner_seat_type") or "").strip().lower()
    if owner_type not in {"default", "prolite"}:
        owner_type = ""
    total = _safe_business_count(raw.get("total"))
    used = _safe_business_count(raw.get("used"))
    available = _safe_business_count(raw.get("available"))
    return {
        "total": total,
        "used": used,
        "available": available,
        "known": bool(raw.get("known")),
        "full": bool(raw.get("full")),
        "owner_seat_type": owner_type,
        "seat_type_capacity_known": capacity_known,
        "seat_type_occupancy_known": occupancy_known,
        "invitable_seat_types": seat_types("invitable_seat_types"),
        "requestable_seat_types": seat_types("requestable_seat_types"),
        "by_type": by_type,
        "checked_at": _safe_business_time(
            raw.get("checked_at")
            or raw.get("snapshot_at")
            or workspace.get("checked_at")
        ),
    }


def _safe_business_quota(raw_quota: Any, *, _nested: bool = False) -> Optional[dict[str, Any]]:
    if not isinstance(raw_quota, dict):
        return None
    result = {
        "snapshot_at": _safe_business_time(raw_quota.get("snapshot_at")),
        "limited": raw_quota.get("limited") is not False,
        "today_success_count": _safe_business_count(
            raw_quota.get("today_success_count")
        ),
        "total_success_count": _safe_business_count(
            raw_quota.get("total_success_count")
        ),
        "limit": _safe_business_count(raw_quota.get("limit")),
        "used": _safe_business_count(raw_quota.get("used")),
        "consumed_used": _safe_business_count(raw_quota.get("consumed_used")),
        "reserved": _safe_business_count(raw_quota.get("reserved")),
        "remaining": _safe_business_count(raw_quota.get("remaining")),
        "window_hours": _safe_business_count(raw_quota.get("window_hours")),
        "window_started_at": _safe_business_time(raw_quota.get("window_started_at")),
        "window_ends_at": _safe_business_time(raw_quota.get("window_ends_at")),
        "reset_at": _safe_business_time(raw_quota.get("reset_at")),
        "next_available_at": _safe_business_time(raw_quota.get("next_available_at")),
        "earliest_recovery_at": _safe_business_time(
            raw_quota.get("earliest_recovery_at")
        ),
        "cycle_state": (
            str(raw_quota.get("cycle_state") or "")
            if str(raw_quota.get("cycle_state") or "") in {"inactive", "provisional", "active", "unlimited"}
            else ""
        ),
    }
    for key in ("legacy_shared_used", "legacy_shared_reserved", "typed_consumed_used", "typed_reserved",
                "recorded_typed_used", "adjusted_typed_used", "usage_max_used"):
        if key in raw_quota:
            result[key] = _safe_business_count(raw_quota.get(key))
    if type(raw_quota.get("manual_adjustment")) is int:
        result["manual_adjustment"] = raw_quota["manual_adjustment"]
    if "usage_editable" in raw_quota:
        result["usage_editable"] = raw_quota.get("usage_editable") is True
        result["usage_edit_reason"] = str(raw_quota.get("usage_edit_reason") or "")[:300]
        revision = str(raw_quota.get("usage_revision") or "")
        result["usage_revision"] = revision if re.fullmatch(r"[0-9a-f]{64}", revision) else ""
        for key in ("usage_window_started_at", "usage_window_ends_at"):
            result[key] = _safe_business_time(raw_quota.get(key))
    if "legacy_shared_reset_at" in raw_quota:
        result["legacy_shared_reset_at"] = _safe_business_time(raw_quota.get("legacy_shared_reset_at"))
    if raw_quota.get("seat_type") in {"default", "prolite"}:
        result["seat_type"] = raw_quota["seat_type"]
    if not _nested and isinstance(raw_quota.get("by_type"), dict):
        result["mode"] = (
            "unlimited_audit"
            if raw_quota.get("mode") == "unlimited_audit"
            else "by_seat_type"
        )
        result["by_type"] = {kind: _safe_business_quota(raw_quota["by_type"].get(kind), _nested=True)
                             for kind in ("default", "prolite")}
    return result


def _safe_business_invite_cooldown(source: Any) -> dict[str, Any]:
    """Allow-list the persisted BUSINESS invitation failure backoff."""
    try:
        from api.gpt_business import _business_invite_cooldown_from_parent
        raw = _business_invite_cooldown_from_parent(source)
    except Exception:
        raw = {}
    return _safe_business_invite_cooldown_payload(raw)


def _safe_business_invite_cooldown_payload(raw: Any) -> dict[str, Any]:
    """Retain only safe cooldown evidence across the mother capability facade."""
    raw = raw if isinstance(raw, dict) else {}
    reason = str(raw.get("reason") or "")
    if not re.fullmatch(r"[a-z0-9_.:-]{0,160}", reason):
        reason = "invite_failed" if reason else ""
    started_at = _safe_business_time(raw.get("started_at"))
    until = _safe_business_time(raw.get("until"))
    resume_at = _safe_business_time(raw.get("resume_at"))
    remaining = raw.get("remaining_seconds")
    remaining_seconds = (
        max(0, min(int(remaining), 86400))
        if isinstance(remaining, int) and not isinstance(remaining, bool)
        else 0
    )
    return {
        "active": bool(raw.get("active")) and bool(until),
        "started_at": started_at,
        "until": until,
        "resume_at": resume_at,
        "reason": reason,
        "category": "explicit_rejection" if raw.get("category") == "explicit_rejection" else "request_failure",
        "duration_seconds": (
            max(0, min(raw["duration_seconds"], 86400))
            if type(raw.get("duration_seconds")) is int else 0
        ),
        "remaining_seconds": remaining_seconds,
    }


def _safe_business_rotation_state(
    source: Any,
) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]], int]:
    """Extract both safe quotas and a count, never workspace member rows."""
    from api.gpt_business import _business_workspace_snapshot, _invite_quota

    workspace = _business_workspace_snapshot(source)
    if not isinstance(workspace, dict):
        workspace = {}
    raw_quota = workspace.get("rotation_quota")
    quota = _safe_business_quota(raw_quota)
    invite_quota: Optional[dict[str, Any]] = None
    source_id = int(getattr(source, "id", 0) or 0)
    if source_id > 0:
        try:
            with Session(engine) as session:
                invite_quota = _safe_business_quota(
                    _invite_quota(session, source_id)
                )
        except Exception:
            invite_quota = None
    if invite_quota is None:
        invite_quota = _safe_business_quota(workspace.get("invite_quota"))
    replaceable = workspace.get("replaceable_children")
    replaceable_count = (
        min(1_000_000, sum(1 for item in replaceable if isinstance(item, dict)))
        if isinstance(replaceable, list)
        else 0
    )
    return quota, invite_quota, replaceable_count


def _safe_business_invite_candidate_summary(source: Any) -> int:
    """Read only the eligible ordinary-account count for the collapsed row."""
    source_id = int(getattr(source, "id", 0) or 0)
    if source_id <= 0:
        return 0
    try:
        with Session(engine) as session:
            count = len(_plan_business_candidate_records(session, source_id))
    except Exception:
        # A database upgraded by an older process may briefly lack one of the
        # normalized membership/lease tables.  Fail closed until migration is
        # complete instead of enabling an invitation from an invented count.
        return 0
    return min(1_000_000, max(0, int(count)))


_CPA_SYNC_TARGETS_CONFIG_KEY = "gpt_plan_cpa_sync_targets"


def _business_binding_positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 < parsed <= 2_147_483_647 else None


def _safe_business_device_name(value: Any, fallback: str) -> str:
    text = "".join(
        char for char in str(value or "").strip()
        if char >= " " and char != "\x7f"
    )[:200]
    # Legacy CPA rows sometimes persisted api_url as the display-name
    # fallback.  This facade is public and must never turn a private endpoint
    # into an account-list label.
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", text):
        return fallback
    return text or fallback


def _empty_business_device_binding(
    policy: Optional[GptBusinessAutomationPolicyModel] = None,
) -> dict[str, Any]:
    revision = _business_binding_positive_int(
        getattr(policy, "revision", None)
    )
    # Revision zero is valid, while the positive-id helper deliberately rejects
    # it.  Keep malformed/negative revisions at the safe initial value.
    if revision is None:
        try:
            raw_revision = int(getattr(policy, "revision", 0) or 0)
        except (TypeError, ValueError):
            raw_revision = 0
        revision = raw_revision if 0 <= raw_revision <= 2_147_483_647 else 0
    return {
        "bound": False,
        "provider": "",
        "device_ref": "",
        "device_id": None,
        "name": "",
        "state": "unbound",
        "enabled": False,
        "auto_rotation_enabled": bool(
            getattr(policy, "auto_rotation_enabled", False)
        ),
        "policy_revision": revision,
        "updated_at": _iso_utc(getattr(policy, "updated_at", None)),
    }


def _safe_cpa_binding_targets(session: Session) -> dict[int, dict[str, Any]]:
    """Read only public CPA identities from the shared registry in one query."""
    raw_value = ""
    try:
        from core.config_store import ConfigItem, _get_env_fallback_value

        if inspect(session.get_bind()).has_table(ConfigItem.__tablename__):
            item = session.get(ConfigItem, _CPA_SYNC_TARGETS_CONFIG_KEY)
            raw_value = str(item.value or "") if item else ""
        if not raw_value.strip():
            # Preserve the registry's legacy environment/.env fallback without
            # opening a second database session or exposing any target secrets.
            raw_value = _get_env_fallback_value(_CPA_SYNC_TARGETS_CONFIG_KEY)
    except Exception:
        raw_value = ""
    try:
        rows = json.loads(raw_value) if raw_value else []
    except (TypeError, ValueError):
        rows = []
    if not isinstance(rows, list):
        rows = []

    targets: dict[int, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        target_id = _business_binding_positive_int(raw.get("id"))
        if target_id is None or target_id in targets:
            continue
        registry_enabled = raw.get("enabled") is not False
        credentials_configured = bool(
            str(raw.get("api_url") or "").strip()
            and str(raw.get("api_key") or "").strip()
        )
        enabled = registry_enabled and credentials_configured
        targets[target_id] = {
            "name": _safe_business_device_name(raw.get("name"), f"CPA {target_id}"),
            "state": (
                "configured" if enabled
                else "disabled" if not registry_enabled
                else "unconfigured"
            ),
            "enabled": enabled,
        }
    return targets


def _safe_sub2api_binding_targets(
    session: Session,
    device_ids: set[int],
) -> dict[int, dict[str, Any]]:
    if not device_ids:
        return {}
    try:
        if not inspect(session.get_bind()).has_table(SyncDeviceModel.__tablename__):
            return {}
        rows = session.exec(
            select(SyncDeviceModel).where(
                SyncDeviceModel.id.in_(sorted(device_ids))  # type: ignore[union-attr]
            )
        ).all()
    except Exception:
        return {}

    targets: dict[int, dict[str, Any]] = {}
    for row in rows:
        device_id = _business_binding_positive_int(getattr(row, "id", None))
        device_type = str(getattr(row, "type", "") or "").strip().lower()
        platform = str(getattr(row, "platform", "") or "").strip().lower()
        if (
            device_id is None
            or device_type not in {"sub", "sub2api", "sub-2-api"}
            or platform not in {"", "chatgpt"}
        ):
            continue
        registry_enabled = bool(getattr(row, "enabled", False))
        credentials_configured = bool(
            str(getattr(row, "api_url", "") or "").strip()
            and str(getattr(row, "api_key", "") or "").strip()
        )
        enabled = registry_enabled and credentials_configured
        targets[device_id] = {
            "name": _safe_business_device_name(
                getattr(row, "name", ""),
                f"Sub2API {device_id}",
            ),
            "state": (
                "configured" if enabled
                else "disabled" if not registry_enabled
                else "unconfigured"
            ),
            "enabled": enabled,
        }
    return targets


def _business_device_binding_map(
    session: Session,
    business_ids: set[int],
) -> dict[int, dict[str, Any]]:
    """Resolve BUSINESS delivery bindings in bounded, credential-free queries.

    A binding is durable policy state and is intentionally distinct from the
    mother's own CPA/Sub2API credential-sync state.  Missing or disabled device
    records keep their provider/id/ref so the UI can offer a safe migration.
    """
    parent_ids = sorted({
        int(value) for value in business_ids
        if _business_binding_positive_int(value) is not None
    })
    result = {
        parent_id: _empty_business_device_binding()
        for parent_id in parent_ids
    }
    if not parent_ids:
        return result
    try:
        if not inspect(session.get_bind()).has_table(
            GptBusinessAutomationPolicyModel.__tablename__
        ):
            return result
        policies = session.exec(
            select(GptBusinessAutomationPolicyModel).where(
                GptBusinessAutomationPolicyModel.business_account_id.in_(  # type: ignore[union-attr]
                    parent_ids
                )
            )
        ).all()
    except Exception:
        return result

    normalized: dict[
        int,
        tuple[GptBusinessAutomationPolicyModel, str, Optional[int]],
    ] = {}
    cpa_ids: set[int] = set()
    sub2api_ids: set[int] = set()
    for policy in policies:
        parent_id = _business_binding_positive_int(
            getattr(policy, "business_account_id", None)
        )
        if parent_id is None or parent_id not in result:
            continue
        provider, device_id = resolve_business_delivery_binding(policy)
        normalized[parent_id] = (policy, provider, device_id)
        if provider == "cpa" and device_id is not None:
            cpa_ids.add(device_id)
        elif provider == "sub2api" and device_id is not None:
            sub2api_ids.add(device_id)

    cpa_targets = _safe_cpa_binding_targets(session) if cpa_ids else {}
    sub2api_targets = _safe_sub2api_binding_targets(session, sub2api_ids)
    for parent_id, (policy, provider, device_id) in normalized.items():
        base = _empty_business_device_binding(policy)
        if not provider or device_id is None:
            result[parent_id] = base
            continue
        target = (
            cpa_targets.get(device_id)
            if provider == "cpa"
            else sub2api_targets.get(device_id)
        )
        fallback = (
            f"CPA {device_id}"
            if provider == "cpa"
            else f"Sub2API {device_id}"
        )
        result[parent_id] = {
            **base,
            "bound": True,
            "provider": provider,
            "device_ref": f"{provider}:{device_id}",
            "device_id": device_id,
            "name": str((target or {}).get("name") or fallback),
            "state": str((target or {}).get("state") or "missing"),
            "enabled": bool((target or {}).get("enabled")),
        }
    return result


def _business_device_binding_options(
    session: Session,
) -> list[dict[str, Any]]:
    """Return the shared local device registries as one public allow-list."""
    result: list[dict[str, Any]] = []
    for device_id, target in _safe_cpa_binding_targets(session).items():
        result.append({
            "device_ref": f"cpa:{device_id}",
            "provider": "cpa",
            "device_id": int(device_id),
            "name": str(target.get("name") or f"CPA {device_id}"),
            "device_name": str(target.get("name") or f"CPA {device_id}"),
            "state": str(target.get("state") or "missing"),
            "enabled": bool(target.get("enabled")),
        })

    try:
        rows = session.exec(select(SyncDeviceModel)).all()
    except Exception:
        rows = []
    sub2api_ids = {
        int(row.id)
        for row in rows
        if _business_binding_positive_int(getattr(row, "id", None)) is not None
    }
    for device_id, target in _safe_sub2api_binding_targets(
        session,
        sub2api_ids,
    ).items():
        result.append({
            "device_ref": f"sub2api:{device_id}",
            "provider": "sub2api",
            "device_id": int(device_id),
            "name": str(target.get("name") or f"Sub2API {device_id}"),
            "device_name": str(
                target.get("name") or f"Sub2API {device_id}"
            ),
            "state": str(target.get("state") or "missing"),
            "enabled": bool(target.get("enabled")),
        })
    result.sort(key=lambda item: (
        str(item.get("provider") or ""),
        int(item.get("device_id") or 0),
    ))
    return result


def _safe_business_workspace_referrals(source: Any) -> dict[str, Any]:
    """Expose only strict referral scalars from the persisted workspace cache."""
    from api.gpt_business import _business_workspace_snapshot

    snapshot = _business_workspace_snapshot(source)
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    enabled = snapshot.get("workspace_referrals_enabled")
    visible = snapshot.get("workspace_referrals_enabled_visible")
    return {
        "workspace_referrals_enabled": (
            enabled if isinstance(enabled, bool) else None
        ),
        "workspace_referrals_enabled_visible": (
            visible if isinstance(visible, bool) else None
        ),
        "workspace_referrals_enabled_checked_at": _safe_business_time(
            snapshot.get("workspace_referrals_enabled_checked_at")
        ),
    }


def _business_member_workspace(
    source: Any,
) -> dict[str, Any]:
    from api.gpt_business import _business_account_team_session_status

    session_status = _business_account_team_session_status(source)
    reason = str(session_status.get("reason") or "invalid_access_token")
    if reason not in _BUSINESS_TEAM_SESSION_REASON_MESSAGES:
        reason = "invalid_access_token"
    team_id = str(session_status.get("team_id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", team_id):
        team_id = ""
    team_plan = str(session_status.get("plan_type") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", team_plan):
        team_plan = ""
    rotation_quota, invite_quota, replaceable_count = _safe_business_rotation_state(source)
    invite_cooldown = _safe_business_invite_cooldown(source)
    invite_candidate_count = _safe_business_invite_candidate_summary(source)
    referrals = _safe_business_workspace_referrals(source)
    from services.business_session_health import public_health
    from services.business_default_payment import public_snapshot
    return {
        "team_session_usable": bool(session_status.get("usable")),
        "team_session_reason": reason,
        "team_id": team_id,
        "team_plan": team_plan,
        "seat_summary": _safe_business_seat_summary(source),
        "rotation_quota": rotation_quota,
        "invite_quota": invite_quota,
        "invite_cooldown": invite_cooldown,
        "replaceable_count": replaceable_count,
        "invite_candidate_count": invite_candidate_count,
        "session_health": public_health(source),
        "default_payment_method": public_snapshot(source),
        **referrals,
    }


def _live_member_capabilities(
    account: GptPlanAccountModel,
    source: Any,
    *,
    source_pool: str,
    business_workspace: Optional[dict[str, Any]] = None,
) -> dict[str, dict[str, Any]]:
    category = _catalog_category(account)
    refund_status = _public_refund_status(getattr(source, "refund_status", ""))
    has_rt = bool(str(getattr(source, "codex_refresh_token", "") or "").strip())

    unhealthy_reason = ""
    if not bool(getattr(source, "enabled", False)):
        unhealthy_reason = "账号已被禁用"
    elif bool(getattr(source, "dangerous", False)):
        unhealthy_reason = "账号已标记 Dead"
    elif source_pool == "gpt_plan" and getattr(source, "business_parent_id", None) is not None:
        unhealthy_reason = "账号已归属 GPT BUSINESS 母号"
    elif category == "refunded":
        unhealthy_reason = "已退款账号不能再次执行远端动作"

    healthy_member = not unhealthy_reason and category == "member"
    final_refund_states = {"refunded_pending_credit", "refund_credited"}
    refund_ready = (
        healthy_member
        and refund_status not in final_refund_states
        and refund_status != "unknown"
    )
    refund_reason = unhealthy_reason or (
        "账号已进入最终退款状态"
        if refund_status in final_refund_states
        else "账号退款状态未知，拒绝自动操作"
        if refund_status == "unknown"
        else "仅会员账号支持该操作"
    )
    action_ready = healthy_member and not refund_status
    action_reason = unhealthy_reason or (
        f"账号当前处于退款状态：{refund_status}"
        if refund_status
        else "仅会员账号支持该操作"
    )
    download_reason = "" if has_rt else "账号尚未取得 Codex RT"
    # BUSINESS sources are workspace mothers.  Their own RT must not be
    # reacquired, downloaded, queried, or uploaded through delivery-device
    # actions.  CPA/Sub2API now expose inventory and quota refresh only.
    business_master_credential_reason = (
        "BUSINESS 母号暂不支持重新获取 RT、下载 CPA/SUB 凭证或同步母号凭证；"
        "CPA/SUB 设备的 BUSINESS 子号自动化已停用"
    )
    credential_action_ready = action_ready and source_pool != "gpt_business"
    oauth_reason = (
        business_master_credential_reason
        if source_pool == "gpt_business"
        else action_reason
    )
    oauth_file_supported = has_rt and source_pool != "gpt_business"
    oauth_file_reason = (
        business_master_credential_reason
        if source_pool == "gpt_business"
        else download_reason
    )
    sync_device_supported = credential_action_ready and has_rt
    sync_device_reason = (
        business_master_credential_reason
        if source_pool == "gpt_business"
        else action_reason if not action_ready else "账号尚未取得 Codex RT"
    )
    device_usage_supported = action_ready and source_pool != "gpt_business"
    device_usage_reason = (
        business_master_credential_reason
        if source_pool == "gpt_business"
        else action_reason
    )

    if source_pool != "gpt_business":
        burn_supported = False
        burn_reason = "仅 GPT BUSINESS 母号支持焚决退款 PRO"
        burn_remaining = 0
        burn_limit = 4
        business_children_supported = False
        business_children_reason = "仅 GPT BUSINESS 母号支持子号管理"
    else:
        workspace = business_workspace or {}
        raw_invite_quota = workspace.get("invite_quota")
        invite_quota = (
            raw_invite_quota if isinstance(raw_invite_quota, dict) else {}
        )
        # PRO burn always sends a default-seat invitation; advanced quota
        # cannot authorize that endpoint's fixed remote request.
        invite_quota = quota_for_seat(invite_quota, "default")
        burn_remaining = 2_147_483_647
        burn_limit = 0
        session_usable = bool(workspace.get("team_session_usable"))
        session_reason = str(workspace.get("team_session_reason") or "")
        invite_cooldown = workspace.get("invite_cooldown")
        invite_cooldown = (
            invite_cooldown if isinstance(invite_cooldown, dict) else {}
        )
        cooldown_active = bool(invite_cooldown.get("active"))
        # A pending/manual/escalated refund marker is not a terminal BUSINESS
        # lifecycle state.  Keep PRO burn available while the mother remains
        # in the member catalogue; only the authoritative transition to the
        # refunded catalogue (or another unhealthy/session/cooldown guard)
        # disables it.  This intentionally mirrors BUSINESS child management.
        burn_supported = bool(
            healthy_member
            and session_usable
            and not cooldown_active
        )
        burn_reason = (
            unhealthy_reason or "仅会员账号支持该操作"
            if not healthy_member
            else _BUSINESS_TEAM_SESSION_REASON_MESSAGES.get(
                session_reason,
                "BUSINESS 母号 Team 登录会话不可用",
            )
            if not session_usable
            else "母号邀请仍在冷却，请等待显示的恢复时间后重试"
            if cooldown_active
            else ""
        )
        # BUSINESS child management follows the local directory lifecycle,
        # rather than treating every in-progress refund marker as a terminal
        # refund.  ``refund_manual_pending`` / ``refund_pending`` /
        # ``refund_escalated`` mothers remain in the member directory and the
        # source BUSINESS UI continues to support their invitations.  The
        # catalogue transition to ``refunded`` is the durable terminal gate;
        # ``healthy_member`` already includes that check together with the
        # enabled/dead/source-integrity guards above.
        business_children_supported = bool(healthy_member and session_usable)
        business_children_reason = (
            unhealthy_reason or "仅会员账号支持该操作"
            if not healthy_member
            else _BUSINESS_TEAM_SESSION_REASON_MESSAGES.get(
                session_reason,
                "BUSINESS 母号 Team 登录会话不可用",
            )
            if not session_usable
            else ""
        )

    burn_capability = {
        **_member_capability(burn_supported, burn_reason),
        "remaining": burn_remaining,
        "limit": burn_limit,
        "limited": source_pool != "gpt_business",
    }

    return {
        # Pending/escalated/manual-pending states may be retried. Only final
        # refund states disable another refund attempt.
        "refund": _member_capability(refund_ready, refund_reason),
        "pro_refund_burn": burn_capability,
        "business_children": _member_capability(
            business_children_supported,
            business_children_reason,
        ),
        "oauth": _member_capability(credential_action_ready, oauth_reason),
        # Download is a local export of an already-owned RT.  It deliberately
        # remains available for refunded rows, but never fabricates an RT.
        "oauth_file": _member_capability(
            oauth_file_supported,
            oauth_file_reason,
            formats=["cpa", "sub2api"],
        ),
        "sync_device": _member_capability(
            sync_device_supported,
            sync_device_reason,
            providers=["cpa", "sub2api"],
        ),
        "device_usage": _member_capability(
            device_usage_supported,
            device_usage_reason,
            providers=["cpa", "sub2api"],
        ),
    }


def _live_member_source(
    session: Session,
    account: GptPlanAccountModel,
    source: Any,
    *,
    source_pool: str,
    replenishment: Optional[DeliveryDeviceReplenishmentDemandModel] = None,
    business_device_binding: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    refresh_token = str(getattr(source, "codex_refresh_token", "") or "")
    cpa_status = None
    sub2api_status = None
    business_workspace = None
    replenishment_status = None
    if source_pool == "gpt_plan":
        # These serializers are explicit allow-lists and never return OAuth
        # tokens, device API keys, or the raw source extra_json.
        from api.gpt_plan_operations import (
            serialize_gpt_pro_cpa_status,
            serialize_gpt_pro_sub2api_status,
        )

        cpa_status = serialize_gpt_pro_cpa_status(source)
        sub2api_status = serialize_gpt_pro_sub2api_status(source)
    elif source_pool == "gpt_business":
        from api.gpt_business import (
            _serialize_replenishment_with_fill,
            serialize_business_master_cpa_status,
            serialize_business_master_sub2api_status,
        )

        cpa_status = serialize_business_master_cpa_status(source)
        sub2api_status = serialize_business_master_sub2api_status(source)
        business_workspace = _business_member_workspace(
            source,
        )
        replenishment_status = _serialize_replenishment_with_fill(
            session,
            replenishment,
        )
    invite_cooldown = (
        _safe_business_invite_cooldown(source)
        if source_pool == "gpt_business" else None
    )
    return {
        "source_pool": source_pool,
        "source_account_id": int(getattr(source, "id", 0) or 0),
        "source_missing": False,
        "source_error": "",
        "has_codex_rt": bool(refresh_token.strip()),
        "codex_refresh_token_len": len(refresh_token),
        "codex_rt_acquired_at": _iso_utc(
            getattr(source, "codex_rt_acquired_at", None)
        ),
        "refund_status": _public_refund_status(
            getattr(source, "refund_status", "")
        ),
        "refund_detected_at": _iso_utc(
            getattr(source, "refund_detected_at", None)
        ),
        "refund_credited_at": _iso_utc(
            getattr(source, "refund_credited_at", None)
        ),
        "refund_manual_at": _iso_utc(
            getattr(source, "refund_manual_at", None)
        ),
        "human_review_requested_at": _iso_utc(
            getattr(source, "human_review_requested_at", None)
        ),
        "invite_cooldown": invite_cooldown,
        "invite_cooldown_active": bool(
            (invite_cooldown or {}).get("active")
        ),
        "invite_cooldown_started_at": str(
            (invite_cooldown or {}).get("started_at") or ""
        ),
        "invite_cooldown_until": str(
            (invite_cooldown or {}).get("until") or ""
        ),
        "invite_cooldown_reason": str(
            (invite_cooldown or {}).get("reason") or ""
        ),
        "policy_warning": bool(getattr(source, "policy_warning", False)),
        "policy_warning_detected_at": _iso_utc(
            getattr(source, "policy_warning_detected_at", None)
        ),
        "dangerous": bool(getattr(source, "dangerous", False)),
        "dangerous_detected_at": _iso_utc(
            getattr(source, "dangerous_detected_at", None)
        ),
        "mail_monitor_owner": "plan",
        "last_mail_check_at": _iso_utc(account.last_mail_check_at),
        "last_mail_check_error": str(account.last_mail_check_error or "")[:300],
        "unread_count": len(_safe_json_list(account.pending_alerts_json)),
        "inbox_unread_count": len(_safe_json_list(account.pending_inbox_json)),
        "business_workspace": business_workspace,
        "business_device_binding": (
            business_device_binding if source_pool == "gpt_business" else None
        ),
        "replenishment": replenishment_status,
        "cpa": cpa_status,
        "sub2api": sub2api_status,
        "capabilities": _live_member_capabilities(
            account,
            source,
            source_pool=source_pool,
            business_workspace=business_workspace,
        ),
    }


def _member_source_map(
    session: Session,
    accounts: list[GptPlanAccountModel],
) -> dict[int, dict[str, Any]]:
    """Build member action state from the authoritative plan row.

    Only BUSINESS mothers retain an explicit delegation to a workspace row.
    Every other paid/refunded account is self-owned, including legacy rows whose
    one-time cutover metadata has not yet been cleared.
    """
    relevant = [
        account
        for account in accounts
        if account.id is not None
        and _catalog_category(account) in {"member", "refunded"}
    ]
    business_ids = {
        int(account.source_account_id or 0)
        for account in relevant
        if str(account.source_pool or "") == "gpt_business"
        and int(account.source_account_id or 0) > 0
    }
    source_rows: dict[tuple[str, int], Any] = {}
    replenishment_rows: dict[int, DeliveryDeviceReplenishmentDemandModel] = {}
    business_device_bindings: dict[int, dict[str, Any]] = {}
    if business_ids:
        rows = session.exec(
            select(GptBusinessAccountModel).where(
                GptBusinessAccountModel.id.in_(sorted(business_ids))  # type: ignore[union-attr]
            )
        ).all()
        source_rows.update({("gpt_business", int(row.id or 0)): row for row in rows})
        # Reuse the BUSINESS selector so both directories obey the same rule:
        # newest non-terminal demand wins; only when none remain do we show the
        # newest terminal history row.
        from api.gpt_business import _latest_replenishments_by_parent

        replenishment_rows = _latest_replenishments_by_parent(
            session,
            sorted(business_ids),
        )
        business_device_bindings = _business_device_binding_map(
            session,
            business_ids,
        )
    result: dict[int, dict[str, Any]] = {}
    for account in relevant:
        account_id = int(account.id or 0)
        source_pool = str(account.source_pool or "").strip()
        source_id = int(account.source_account_id or 0)
        if source_pool != "gpt_business":
            result[account_id] = _live_member_source(
                session,
                account,
                account,
                source_pool="gpt_plan",
            )
            continue
        source = source_rows.get((source_pool, source_id))
        if source is None:
            result[account_id] = _missing_member_source(
                account,
                "BUSINESS 母号不存在或已被删除",
            )
            continue
        if _normalized_email(account.email) != _normalized_email(
            getattr(source, "email", "")
        ):
            result[account_id] = _missing_member_source(
                account,
                "套餐账号与 BUSINESS 母号身份不一致",
            )
            continue
        result[account_id] = _live_member_source(
            session,
            account,
            source,
            source_pool=source_pool,
            replenishment=replenishment_rows.get(source_id),
            business_device_binding=business_device_bindings.get(source_id),
        )
    return result


@dataclass(frozen=True)
class _PlanMailStateOwner:
    """套餐账号对应的唯一本地邮件队列 owner。"""

    plan_account_id: int
    kind: Literal["plan"]
    row: GptPlanAccountModel


def _resolve_plan_mail_state_owner(
    session: Session,
    account: GptPlanAccountModel,
) -> _PlanMailStateOwner:
    """Return the plan row; source tables never own plan-directory mail."""
    del session
    return _PlanMailStateOwner(
        plan_account_id=int(account.id or 0),
        kind="plan",
        row=account,
    )


def _require_plan_member_for_mail(
    session: Session,
    account_id: int,
) -> tuple[GptPlanAccountModel, _PlanMailStateOwner]:
    account = session.get(GptPlanAccountModel, int(account_id))
    if not account:
        raise HTTPException(404, "账号不存在")
    if getattr(account, "business_parent_id", None) is not None:
        raise HTTPException(409, "BUSINESS 子号邮件提醒必须通过所属母号访问")
    if _catalog_category(account) not in {"member", "refunded"}:
        raise HTTPException(409, "只有会员账号和已退款账号支持邮件监控提醒")
    return account, _resolve_plan_mail_state_owner(session, account)


@dataclass(frozen=True)
class _MemberSourceBinding:
    plan_account_id: int
    source_pool: str
    source_account_id: int
    normalized_email: str


def _resolve_member_source_binding(
    account_id: int,
) -> tuple[_MemberSourceBinding, dict[str, Any]]:
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if _catalog_category(account) not in {"member", "refunded"}:
            raise HTTPException(409, "只有会员或已退款账号支持该操作")
        member_source = _member_source_map(session, [account]).get(int(account_id))
        if not member_source or bool(member_source.get("source_missing")):
            reason = (
                str((member_source or {}).get("source_error") or "")
                or "会员账号当前不可操作"
            )
            raise HTTPException(409, reason)
        binding = _MemberSourceBinding(
            plan_account_id=int(account_id),
            source_pool=str(member_source["source_pool"]),
            source_account_id=int(member_source["source_account_id"]),
            normalized_email=_normalized_email(account.email),
        )
        return binding, member_source


def _assert_member_source_binding_current(
    binding: _MemberSourceBinding,
) -> dict[str, Any]:
    current, member_source = _resolve_member_source_binding(binding.plan_account_id)
    if current != binding:
        raise HTTPException(409, "套餐账号状态已变化，请重新打开账号")
    return member_source


def _require_member_capability(
    member_source: dict[str, Any],
    action: str,
) -> None:
    capabilities = member_source.get("capabilities")
    capability = capabilities.get(action) if isinstance(capabilities, dict) else None
    if not isinstance(capability, dict) or not bool(capability.get("supported")):
        reason = str((capability or {}).get("reason") or "当前账号不支持该操作")
        raise HTTPException(409, reason[:300])


_MEMBER_ACTION_TASKS: dict[str, dict[str, Any]] = {}
_MEMBER_ACTION_TASK_LOCK = threading.RLock()
_MEMBER_ACTION_TASK_RETAIN_SECONDS = 2 * 60 * 60
_MEMBER_ACTION_TASK_MAX_LOGS = 800
_REFUND_TASK_RESULT_KEYS = frozenset({
    "ok",
    "stage",
    "refund_success",
    "manual_opened",
    "human_escalated",
    "refund_status",
    "rotation_paused",
    "restore_required",
})
_OAUTH_TASK_RESULT_KEYS = frozenset({
    "stage",
    "codex_refresh_token_len",
    "codex_access_token_len",
    "codex_id_token_len",
    "codex_session_token_len",
    "acquired_at",
    "workspace_refreshed",
    "workspace_status",
    "workspace_refresh_warning",
})
_PRO_BURN_TASK_RESULT_KEYS = frozenset({
    "total",
    "burned",
})


def _sanitize_member_task_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [redacted]",
        text,
    )
    text = re.sub(
        r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b",
        "[jwt-redacted]",
        text,
    )
    text = re.sub(
        r"(?i)([?&](?:code|authorization_code|oauth_code|otp|sms_code|"
        r"verification_code|token|access_token|refresh_token|id_token|"
        r"session_token)=)[^&#\s\"'<>]+",
        r"\1[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|"
        r"session[_ -]?token|authorization[_ -]?code|oauth[_ -]?code|token)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+",
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:otp|sms)(?:[\s_-]+(?:otp|code|verification(?:[\s_-]+code)?))?|"
        r"\bverification(?:[\s_-]+code)?|短信(?:验证码|码)?|验证码)"
        r"\s*(?:is|为|是)?\s*[:=：]?\s*[\"']?\d{4,8}\b",
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:phone|mobile)(?:[_ -]?(?:number|no))?|手机号|手机号码|电话)"
        r"\s*[\"']?\s*[:=：]?\s*[\"']?\+?[\d()\s-]{7,20}\d",
        lambda match: f"{match.group(1)}=[phone-redacted]",
        text,
    )
    text = re.sub(r"(?<!\w)\+\d{7,15}\b", "[phone-redacted]", text)
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[phone-redacted]", text)
    # Add directory-specific cookie/card/password redaction. Never echo
    # account credentials into public task snapshots.
    text = _redact_text(text)
    text = re.sub(
        r"(?i)\b(password|passwd|cookie|set-cookie|api[_ -]?key|secret)"
        r"\s*[:=]\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=<redacted>",
        text,
    )
    return text[:500]


def _safe_member_task_result(action: str, value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    allowed_by_action = {
        "refund": _REFUND_TASK_RESULT_KEYS,
        "oauth": _OAUTH_TASK_RESULT_KEYS,
        "pro_refund_burn": _PRO_BURN_TASK_RESULT_KEYS,
    }
    allowed = allowed_by_action.get(str(action), frozenset())
    result: dict[str, Any] = {}
    for key in allowed:
        if key not in value:
            continue
        item = value.get(key)
        if isinstance(item, bool) or item is None:
            result[key] = item
        elif isinstance(item, int):
            result[key] = max(0, item)
        elif isinstance(item, (str, float)):
            result[key] = _sanitize_member_task_text(item)
    return result


def _prune_member_action_tasks_locked() -> None:
    cutoff = _utcnow() - timedelta(seconds=_MEMBER_ACTION_TASK_RETAIN_SECONDS)
    stale: list[str] = []
    for task_id, task in _MEMBER_ACTION_TASKS.items():
        finished = task.get("finished_at")
        if not finished:
            continue
        try:
            parsed = datetime.fromisoformat(str(finished))
            parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            parsed = datetime.min.replace(tzinfo=timezone.utc)
        if parsed < cutoff:
            stale.append(task_id)
    for task_id in stale:
        _MEMBER_ACTION_TASKS.pop(task_id, None)


def _create_member_action_task(
    binding: _MemberSourceBinding,
    action: str,
    *,
    source_task_id: str = "",
) -> str:
    task_id = uuid.uuid4().hex
    with _MEMBER_ACTION_TASK_LOCK:
        _prune_member_action_tasks_locked()
        _MEMBER_ACTION_TASKS[task_id] = {
            "task_id": task_id,
            "action": str(action),
            "plan_account_id": int(binding.plan_account_id),
            "source_pool": str(binding.source_pool),
            "source_account_id": int(binding.source_account_id),
            "normalized_email": str(binding.normalized_email),
            "source_task_id": str(source_task_id or ""),
            "status": "running",
            "logs": [],
            "result": None,
            "error": "",
            "started_at": _iso_utc(_utcnow()),
            "finished_at": "",
        }
    return task_id


def _member_action_task_log(task_id: str, message: Any) -> None:
    safe = _sanitize_member_task_text(message)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {safe}"
    with _MEMBER_ACTION_TASK_LOCK:
        task = _MEMBER_ACTION_TASKS.get(str(task_id))
        if not task:
            return
        logs = task.setdefault("logs", [])
        logs.append(line)
        if len(logs) > _MEMBER_ACTION_TASK_MAX_LOGS:
            task["logs"] = logs[-_MEMBER_ACTION_TASK_MAX_LOGS:]


def _finish_member_action_task(
    task_id: str,
    *,
    result: Optional[dict[str, Any]] = None,
    error: str = "",
    final_log: str = "",
) -> None:
    with _MEMBER_ACTION_TASK_LOCK:
        task = _MEMBER_ACTION_TASKS.get(str(task_id))
        if not task:
            return
        action = str(task.get("action") or "")
        safe_error = _sanitize_member_task_text(error) if error else ""
        safe_final_log = _sanitize_member_task_text(final_log) if final_log else ""
        if safe_final_log:
            logs = task.setdefault("logs", [])
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {safe_final_log}")
            if len(logs) > _MEMBER_ACTION_TASK_MAX_LOGS:
                task["logs"] = logs[-_MEMBER_ACTION_TASK_MAX_LOGS:]
        task["status"] = "failed" if safe_error else "done"
        task["result"] = _safe_member_task_result(action, result)
        task["error"] = safe_error
        task["finished_at"] = _iso_utc(_utcnow())
        _prune_member_action_tasks_locked()


def _bound_member_action_task(
    account_id: int,
    task_id: str,
    action: str,
) -> dict[str, Any]:
    with _MEMBER_ACTION_TASK_LOCK:
        task = _MEMBER_ACTION_TASKS.get(str(task_id))
        if (
            not task
            or int(task.get("plan_account_id") or 0) != int(account_id)
            or str(task.get("action") or "") != str(action)
        ):
            # Do not disclose whether a valid random task belongs to a different
            # plan account or action.
            raise HTTPException(404, "任务不存在或已过期")
        snapshot = dict(task)
    binding = _MemberSourceBinding(
        plan_account_id=int(snapshot["plan_account_id"]),
        source_pool=str(snapshot["source_pool"]),
        source_account_id=int(snapshot["source_account_id"]),
        normalized_email=str(snapshot["normalized_email"]),
    )
    _assert_member_source_binding_current(binding)
    return snapshot


def _own_member_task_snapshot(
    task: dict[str, Any],
    *,
    since: int,
) -> dict[str, Any]:
    logs = list(task.get("logs") or [])
    offset = max(0, int(since or 0))
    action = str(task.get("action") or "")
    return {
        "task_id": str(task.get("task_id") or ""),
        "action": action,
        "status": str(task.get("status") or "running"),
        "logs": [_sanitize_member_task_text(item) for item in logs[offset:]],
        "since": len(logs),
        "result": _safe_member_task_result(action, task.get("result")),
        "error": _sanitize_member_task_text(task.get("error") or ""),
        "started_at": str(task.get("started_at") or ""),
        "finished_at": str(task.get("finished_at") or ""),
    }


def _source_refund_status(binding: _MemberSourceBinding) -> str:
    with Session(engine) as session:
        model = (
            GptBusinessAccountModel
            if binding.source_pool == "gpt_business"
            else GptPlanAccountModel
        )
        source = session.get(model, int(binding.source_account_id))
        if not source or _normalized_email(source.email) != binding.normalized_email:
            return ""
        return _public_refund_status(source.refund_status)


def _refresh_directory_after_refund(binding: _MemberSourceBinding) -> None:
    """Promote the locally owned row after a terminal refund transition."""
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(binding.plan_account_id))
        if not account or _normalized_email(account.email) != binding.normalized_email:
            return
        if binding.source_pool == "gpt_business":
            if (
                str(account.source_pool or "") != "gpt_business"
                or int(account.source_account_id or 0) != binding.source_account_id
            ):
                return
            source = session.get(
                GptBusinessAccountModel,
                int(binding.source_account_id),
            )
        else:
            if int(binding.source_account_id) != int(binding.plan_account_id):
                return
            source = account
        if not source or _normalized_email(source.email) != binding.normalized_email:
            return
        if str(source.refund_status or "").strip() != "refunded_pending_credit":
            return
        now = _utcnow()
        account.catalog_category = "refunded"
        account.source_state = "refunded_pending_credit"
        account.updated_at = now
        session.add(account)
        session.commit()


def _refund_task_result(
    raw: Any,
    *,
    binding: _MemberSourceBinding,
) -> dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    flow = value.get("flow") if isinstance(value.get("flow"), dict) else {}
    refund_status = _source_refund_status(binding)
    stage = str(value.get("stage") or flow.get("stage") or "")
    manual_opened = bool(
        value.get("manual_opened")
        or flow.get("manual")
        or stage == "manual_opened"
    )
    rotation_paused = bool(value.get("rotation_paused"))
    restore_required = bool(value.get("restore_required"))
    if binding.source_pool == "gpt_business" and refund_status:
        rotation_paused = True
        restore_required = bool(restore_required or not bool(value.get("ok")))
    return {
        "ok": bool(value.get("ok")),
        "stage": stage,
        "refund_success": bool(value.get("refund_success") or flow.get("refund_success")),
        "manual_opened": manual_opened,
        "human_escalated": bool(
            value.get("human_escalated") or flow.get("human_escalated")
        ),
        "refund_status": refund_status,
        "rotation_paused": rotation_paused,
        "restore_required": restore_required,
    }


def _run_member_refund_task(
    task_id: str,
    binding: _MemberSourceBinding,
    body: GptPlanMemberRefundRequest,
) -> None:
    log = lambda message: _member_action_task_log(task_id, message)
    try:
        member_source = _assert_member_source_binding_current(binding)
        _require_member_capability(member_source, "refund")
        log("开始执行套餐账号退款流程")
        log("正在启动可见浏览器，请勿关闭退款窗口")
        if binding.source_pool != "gpt_business":
            from api import gpt_plan_operations as gpt_pro

            source_body = gpt_pro.GptProActionRequest(
                refund_manual=bool(body.refund_manual),
                refund_message=body.refund_message,
                proxy=body.proxy,
                # GPT 套餐管理中的自动/人工退款均必须可见；不要把调用方
                # 遗留的 headless=true 继续传入底层。GPT PRO 独立路由不受影响。
                headless=False,
                keep_browser_open=(
                    True if body.refund_manual else bool(body.keep_browser_open)
                ),
                otp_timeout=max(30, int(body.otp_timeout or 180)),
            )
            raw = gpt_pro._do_refund_one(
                int(binding.source_account_id),
                source_body,
                log,
            )
        else:
            from api import gpt_business

            source_body = gpt_business.GptBusinessRefundRequest(
                refund_manual=bool(body.refund_manual),
                refund_message=body.refund_message,
                proxy=body.proxy,
                # BUSINESS 源模型本来默认有头，但套餐 facade 曾用请求默认值
                # 覆盖成无头。这里在服务端边界强制可见，避免旧前端复发。
                headless=False,
                keep_browser_open=(
                    True if body.refund_manual else bool(body.keep_browser_open)
                ),
                otp_timeout=max(30, int(body.otp_timeout or 180)),
            )
            raw = gpt_business.refund_business_account(
                int(binding.source_account_id),
                source_body,
            )
        _refresh_directory_after_refund(binding)
        result = _refund_task_result(raw, binding=binding)
        if result["ok"]:
            # 完成日志与终态在同一个锁内发布，前端不会再看到“已完成”
            # 日志却仍处于 running，也不会因先读到终态而漏掉最后一行。
            _finish_member_action_task(
                task_id,
                result=result,
                final_log="套餐账号退款流程已完成",
            )
        else:
            error = "退款流程未完成"
            if isinstance(raw, dict):
                error = str(raw.get("error") or error)
            _finish_member_action_task(
                task_id,
                result=result,
                error=error,
                final_log=error,
            )
    except Exception as exc:
        _refresh_directory_after_refund(binding)
        status = _source_refund_status(binding)
        result = {
            "ok": False,
            "stage": "failed",
            "refund_success": status == "refunded_pending_credit",
            "manual_opened": False,
            "human_escalated": status == "refund_escalated",
            "refund_status": status,
            "rotation_paused": bool(
                binding.source_pool == "gpt_business" and status
            ),
            "restore_required": bool(
                binding.source_pool == "gpt_business" and status
            ),
        }
        error = str(getattr(exc, "detail", "") or exc)
        _finish_member_action_task(
            task_id,
            result=result,
            error=error,
            final_log=error,
        )


def _oauth_source_snapshot(
    task: dict[str, Any],
    *,
    since: int,
) -> dict[str, Any]:
    source_pool = str(task.get("source_pool") or "")
    source_task_id = str(task.get("source_task_id") or "")
    if source_pool != "gpt_business":
        from api.gpt_plan_operations import _snapshot_invite_task

        raw = _snapshot_invite_task(source_task_id, since=max(0, int(since or 0)))
    else:
        from api.gpt_business import _snapshot_oauth_task

        raw = _snapshot_oauth_task(source_task_id, since=max(0, int(since or 0)))
    if raw is None:
        raise HTTPException(404, "任务不存在或已过期")
    raw_account_id = raw.get("account_id")
    if raw_account_id is not None and raw_account_id != "":
        try:
            matches = int(raw_account_id) == int(task.get("source_account_id") or 0)
        except (TypeError, ValueError):
            matches = False
        if not matches:
            # Treat a mismatched source snapshot exactly like an unknown task.
            raise HTTPException(404, "任务不存在或已过期")
    raw_status = str(raw.get("status") or "running").strip().lower()
    status = raw_status if raw_status in {"running", "done", "failed"} else "running"
    safe_result = _safe_member_task_result("oauth", raw.get("result"))
    safe_error = _sanitize_member_task_text(raw.get("error") or "")
    finished_at = str(raw.get("finished_at") or "")
    if status in {"done", "failed"}:
        finished_at = finished_at or _iso_utc(_utcnow())
        # Mirror only the terminal public state.  The immutable source binding
        # and private source_task_id remain untouched, while finished_at lets
        # the same two-hour retention policy prune completed facade tasks.
        with _MEMBER_ACTION_TASK_LOCK:
            current = _MEMBER_ACTION_TASKS.get(str(task.get("task_id") or ""))
            if current:
                current["status"] = status
                current["result"] = safe_result
                current["error"] = safe_error
                current["finished_at"] = finished_at
                _prune_member_action_tasks_locked()
    return {
        "task_id": str(task.get("task_id") or ""),
        "action": "oauth",
        "status": status,
        "logs": [
            _sanitize_member_task_text(item)
            for item in list(raw.get("logs") or [])
        ],
        "since": max(0, int(raw.get("since") or 0)),
        "result": safe_result,
        "error": safe_error,
        "started_at": str(raw.get("started_at") or task.get("started_at") or ""),
        "finished_at": finished_at,
    }


def _safe_pro_burn_progress(value: Any) -> Optional[dict[str, int]]:
    if not isinstance(value, dict):
        return None
    safe: dict[str, int] = {}
    for key in ("done", "total", "burned"):
        raw = value.get(key)
        if isinstance(raw, bool):
            continue
        try:
            parsed = int(raw)
        except (TypeError, ValueError):
            continue
        safe[key] = min(1_000_000, max(0, parsed))
    return safe or None


def _pro_burn_source_snapshot(
    task: dict[str, Any],
    *,
    since: int,
) -> dict[str, Any]:
    from api.gpt_plan_operations import _snapshot_invite_task

    raw = _snapshot_invite_task(
        str(task.get("source_task_id") or ""),
        since=max(0, int(since or 0)),
    )
    if raw is None:
        raise HTTPException(404, "任务不存在或已过期")
    raw_status = str(raw.get("status") or "running").strip().lower()
    status = raw_status if raw_status in {"running", "done", "failed"} else "running"
    safe_result = _safe_member_task_result("pro_refund_burn", raw.get("result"))
    safe_error = _sanitize_member_task_text(raw.get("error") or "")
    finished_at = _safe_business_time(raw.get("finished_at"))
    if status in {"done", "failed"}:
        finished_at = finished_at or _iso_utc(_utcnow())
        with _MEMBER_ACTION_TASK_LOCK:
            current = _MEMBER_ACTION_TASKS.get(str(task.get("task_id") or ""))
            if current:
                current["status"] = status
                current["result"] = safe_result
                current["error"] = safe_error
                current["finished_at"] = finished_at
                _prune_member_action_tasks_locked()
    logs = raw.get("logs") if isinstance(raw.get("logs"), list) else []
    try:
        next_since = max(0, int(raw.get("since") or 0))
    except (TypeError, ValueError):
        next_since = 0
    return {
        "task_id": str(task.get("task_id") or ""),
        "action": "pro_refund_burn",
        "status": status,
        "logs": [_sanitize_member_task_text(item) for item in logs],
        "since": next_since,
        "progress": _safe_pro_burn_progress(raw.get("progress")),
        "result": safe_result,
        "error": safe_error,
        "started_at": (
            _safe_business_time(raw.get("started_at"))
            or _safe_business_time(task.get("started_at"))
        ),
        "finished_at": finished_at,
    }


def _strict_pro_burn_target_ids(values: Any) -> list[int]:
    """Validate burn targets without accepting Pydantic/JSON coercions."""
    if not isinstance(values, list):
        raise HTTPException(400, "account_ids 必须是账号 ID 数组")
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise HTTPException(400, "account_ids 只能包含正整数账号 ID")
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    if not result:
        raise HTTPException(400, "未选择有效的 PRO 账号")
    return result


def _eligible_pro_burn_targets(
    session: Session,
    account_ids: Optional[list[int]] = None,
) -> list[GptPlanAccountModel]:
    """Return the exact plan-owned candidate set for the burn workflow."""
    statement = select(GptPlanAccountModel).where(
        GptPlanAccountModel.is_pro == True,  # noqa: E712
        GptPlanAccountModel.enabled == True,  # noqa: E712
        GptPlanAccountModel.dangerous == False,  # noqa: E712
        func.trim(func.coalesce(GptPlanAccountModel.refund_status, "")) == "",
        GptPlanAccountModel.business_parent_id.is_(None),  # type: ignore[union-attr]
    )
    if account_ids is not None:
        statement = statement.where(
            GptPlanAccountModel.id.in_(account_ids)  # type: ignore[union-attr]
        )
    rows = list(session.exec(statement).all())
    # Python ordering keeps this independent of backend-specific NULL syntax:
    # subscribed rows first, newest first, then stable descending id.
    return sorted(
        rows,
        key=lambda row: (
            getattr(row, "subscribed_at", None) is not None,
            _aware_utc(getattr(row, "subscribed_at", None))
            or datetime.min.replace(tzinfo=timezone.utc),
            int(getattr(row, "id", 0) or 0),
        ),
        reverse=True,
    )


def _safe_pro_burn_candidate(row: GptPlanAccountModel) -> dict[str, Any]:
    return {
        "id": int(row.id or 0),
        "email": _normalized_email(row.email),
        "subscribed_at": _iso_utc(row.subscribed_at),
    }


_BUSINESS_FACADE_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{7,159}$")


def _strict_business_facade_operation_id(value: Any) -> str:
    operation_id = str(value or "").strip()
    if not _BUSINESS_FACADE_OPERATION_ID_RE.fullmatch(operation_id):
        raise HTTPException(
            400,
            "operation_id 必须是 8-160 位字母、数字、冒号、下划线或连字符",
        )
    return operation_id


def _strict_optional_business_child_id(value: Any, field: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise HTTPException(400, f"{field} 必须是正整数")
    return int(value)


def _strict_business_candidate_mail_provider(value: Any) -> str:
    if not isinstance(value, str):
        raise HTTPException(
            400,
            "此独立项目的邀请候选仅支持 auto 或 gmail",
        )
    provider = value.strip().lower()
    if provider not in {"auto", "gmail"}:
        raise HTTPException(
            400,
            "此独立项目的邀请候选仅支持 auto 或 gmail",
        )
    return provider


_BUSINESS_MANUAL_EMAIL_LOCAL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
_BUSINESS_MANUAL_EMAIL_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _strict_optional_business_manual_email(value: Any) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise HTTPException(400, "manual_email 必须是邮箱字符串")
    email = value.strip().lower()
    if len(email) > 254 or any(ord(char) > 127 for char in email):
        raise HTTPException(400, "manual_email 格式无效")
    if email.count("@") != 1:
        raise HTTPException(400, "manual_email 格式无效")
    local, domain = email.rsplit("@", 1)
    if (
        not local
        or len(local) > 64
        or not _BUSINESS_MANUAL_EMAIL_LOCAL_RE.fullmatch(local)
        or not domain
        or len(domain) > 253
        or domain.startswith(".")
        or domain.endswith(".")
    ):
        raise HTTPException(400, "manual_email 格式无效")
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not _BUSINESS_MANUAL_EMAIL_LABEL_RE.fullmatch(label)
        for label in labels
    ):
        raise HTTPException(400, "manual_email 格式无效")
    return email


def _assert_cached_business_invitable_seat(
    binding: _MemberSourceBinding,
) -> dict[str, Any]:
    """Require one exact typed vacancy in the last persisted workspace read."""
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, int(binding.source_account_id))
        if (
            parent is None
            or _normalized_email(parent.email) != binding.normalized_email
        ):
            raise HTTPException(409, "BUSINESS 工作区绑定已变化，请刷新后重试")
        seat_summary = _safe_business_seat_summary(parent)
    if not isinstance(seat_summary, dict):
        raise HTTPException(409, {
            "code": "business_seat_snapshot_missing",
            "message": "尚无已保存的 BUSINESS 席位快照，请先刷新席位",
        })
    exact_types: list[str] = []
    by_type = seat_summary.get("by_type")
    by_type = by_type if isinstance(by_type, dict) else {}
    for seat_type in ("default", "prolite"):
        item = by_type.get(seat_type)
        item = item if isinstance(item, dict) else {}
        available = item.get("available")
        if (
            item.get("availability_exact") is True
            and isinstance(available, int)
            and not isinstance(available, bool)
            and available > 0
        ):
            exact_types.append(seat_type)
    if not (
        bool(seat_summary.get("seat_type_capacity_known"))
        and bool(seat_summary.get("seat_type_occupancy_known"))
    ):
        raise HTTPException(409, {
            "code": "business_seat_snapshot_unknown",
            "message": "数据库中的分类席位状态不完整，请先刷新席位",
        })
    if not exact_types:
        raise HTTPException(409, {
            "code": "no_cached_invitable_seat",
            "message": "数据库席位快照显示母号已满席；请使用明确的替换流程",
        })
    return {
        "seat_types": exact_types,
        "checked_at": str(seat_summary.get("checked_at") or ""),
    }


def _safe_business_child_seat_type(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"default", "standard", "regular"}:
        return "default"
    if normalized in {"prolite", "pro-lite"}:
        return "prolite"
    return ""


def _safe_business_child_email(value: Any) -> str:
    return _normalized_email(str(value or "")[:320])


def _safe_business_remote_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 200 or any(ord(char) < 32 for char in text):
        return ""
    return text


def _safe_business_child_error(value: Any) -> str:
    return _sanitize_member_task_text(str(value or ""))[:500]


def _safe_business_dead_candidate_cleanup(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    account_id = value.get("account_id")
    if not isinstance(account_id, int) or isinstance(account_id, bool) or account_id <= 0:
        return None
    raw_reason = str(value.get("reason") or "")
    return {
        "account_id": account_id,
        "email": _safe_business_child_email(value.get("email")),
        "deleted": value.get("deleted") is True,
        "skipped": value.get("deleted") is not True,
        "reason": raw_reason if re.fullmatch(r"[a-z0-9_]{1,80}", raw_reason) else "cleanup_unknown",
        "confirmed_dead": value.get("confirmed_dead") is True,
        "remote_invite_sent": value.get("remote_invite_sent") if type(value.get("remote_invite_sent")) is bool else None,
    }


def _raise_safe_business_source_error(exc: Exception) -> None:
    """Keep source HTTP semantics while dropping arbitrary remote payloads."""
    if not isinstance(exc, HTTPException):
        raise HTTPException(502, "BUSINESS 工作区操作失败，请稍后重试") from exc
    try:
        status_code = int(exc.status_code)
    except (TypeError, ValueError):
        status_code = 502
    if status_code < 400 or status_code > 599:
        status_code = 502
    detail = exc.detail
    if isinstance(detail, dict):
        raw_code = str(detail.get("code") or "").strip().lower()
        code = raw_code if re.fullmatch(r"[a-z0-9_-]{1,80}", raw_code) else ""
        message = _safe_business_child_error(
            detail.get("message") or detail.get("detail") or detail.get("error")
        )
        safe_detail: dict[str, Any] = {
            "code": code,
            "message": message or "BUSINESS 工作区操作未完成",
        }
        if code == "business_child_prelogin_dead":
            child_id = detail.get("pro_account_id")
            if isinstance(child_id, int) and not isinstance(child_id, bool) and child_id > 0:
                safe_detail["pro_account_id"] = child_id
            safe_detail["email"] = _safe_business_child_email(detail.get("email"))
            safe_detail["confirmed_dead"] = detail.get("confirmed_dead") is True
            safe_detail["remote_invite_sent"] = detail.get("remote_invite_sent") if type(detail.get("remote_invite_sent")) is bool else None
            cleanup = _safe_business_dead_candidate_cleanup(detail.get("dead_candidate_cleanup"))
            if cleanup is not None:
                safe_detail["dead_candidate_cleanup"] = cleanup
        if code == "business_invite_progress_checkpoint_failed":
            for field, allowed in (("phase", {"verify_child", "send_invite"}),
                                   ("state", {"running", "completed", "failed"})):
                if detail.get(field) in allowed:
                    safe_detail[field] = detail[field]
            child_id = detail.get("pro_account_id")
            if isinstance(child_id, int) and not isinstance(child_id, bool) and child_id >= 0:
                safe_detail["pro_account_id"] = child_id
            safe_detail["email"] = _safe_business_child_email(detail.get("email"))
            safe_detail["remote_invite_sent"] = detail.get("remote_invite_sent") if type(detail.get("remote_invite_sent")) is bool else None
        if isinstance(detail.get("dead_candidate_cleanups"), list):
            safe_detail["dead_candidate_cleanups"] = [
                safe for item in detail["dead_candidate_cleanups"][:100]
                if (safe := _safe_business_dead_candidate_cleanup(item)) is not None
            ]
        if code == "business_child_prelogin_failed":
            from services.business_invite_login_diagnostics import normalize_prelogin_failure

            prelogin = normalize_prelogin_failure(detail)
            if prelogin is not None:
                safe_detail.update(prelogin)
                if prelogin.get("failure_reason"):
                    safe_detail["message"] += "：" + prelogin["failure_reason"]
        quota = _safe_business_quota(detail.get("invite_quota"))
        if quota is not None:
            safe_detail["invite_quota"] = quota
        if isinstance(detail.get("invite_cooldown"), dict):
            safe_detail["invite_cooldown"] = _safe_business_invite_cooldown_payload(detail["invite_cooldown"])
            safe_detail["resume_at"] = safe_detail["invite_cooldown"]["resume_at"]
        raise HTTPException(status_code, safe_detail) from exc
    message = _safe_business_child_error(detail)
    raise HTTPException(
        status_code,
        message or "BUSINESS 工作区操作未完成",
    ) from exc


def _safe_business_child_mail_provider(child: GptPlanAccountModel) -> str:
    # Keep candidate display, filtering, login routing and source invitation on
    # one provider classifier.  The source helper also covers legacy rows whose
    # first-class column still has the old ``outlook`` schema default while
    # ``extra_json`` records iCloud.
    from api import gpt_business

    return gpt_business._business_child_candidate_mail_provider(child)


def _plan_account_has_business_login_credentials(
    account: GptPlanAccountModel,
) -> bool:
    provider = _safe_business_child_mail_provider(account)
    if provider == "gmail":
        from services.gmail_plan_support import gmail_receive_ready
        return bool(gmail_receive_ready(account))
    return bool(
        provider == "icloud"
        or str(account.password or "").strip()
        or (
            str(account.client_id or "").strip()
            and str(account.refresh_token or "").strip()
        )
    )


def _pro_child_has_business_login_credentials(child: GptPlanAccountModel) -> bool:
    if _safe_business_child_mail_provider(child) == "gmail":
        from services.gmail_plan_support import gmail_receive_ready
        return bool(gmail_receive_ready(child))
    return bool(
        _safe_business_child_mail_provider(child) == "icloud"
        or str(child.password or "").strip()
        or (
            str(child.client_id or "").strip()
            and str(child.refresh_token or "").strip()
        )
    )


def _business_child_account_capabilities(
    child: GptPlanAccountModel,
    *,
    chatgpt_security: Optional[Dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return credential-free login, setup and mail capabilities for a child.

    Login and mailbox access are deliberately separate capabilities.  An
    Authenticator-managed ChatGPT account can log in with the encrypted
    password/TOTP store even when it has no usable mailbox credential; mail
    viewing still requires the mailbox itself. An interrupted enrollment with
    a confirmed password has a separate setup admission rule; it never enables
    ordinary login or OAuth without the Authenticator seed.
    """
    provider = _safe_business_child_mail_provider(child)
    mail_access_type = str(child.mail_access_type or "").strip().lower()
    has_password = bool(str(child.password or "").strip())
    has_mail_oauth = bool(
        str(child.client_id or "").strip()
        and str(child.refresh_token or "").strip()
    )
    # iCloud aliases are read through the globally configured QQ mailbox and
    # therefore do not need a password/OAuth pair on every child row.
    from services.gmail_plan_support import gmail_receive_metadata
    gmail_meta = gmail_receive_metadata(child) if provider == "gmail" else {}
    has_mail_credentials = (bool(gmail_meta.get("gmail_receive_ready")) if provider == "gmail" else bool(
        provider == "icloud" or has_password or has_mail_oauth
    ))
    if chatgpt_security is None:
        try:
            from services.chatgpt_security_store import get_chatgpt_security_status

            security_status = get_chatgpt_security_status(child.email)
            security_state_available = True
        except Exception:
            security_status = _unavailable_chatgpt_security_status()
            security_state_available = False
    else:
        security_status = chatgpt_security
        # The batched reader uses the explicit fail-closed state if the
        # encrypted credential store cannot be read.  Do not accidentally
        # turn that fallback into an OTP-capable account merely because a
        # dictionary was supplied by the caller.
        security_state_available = not (
            str(security_status.get("password_state") or "").strip().lower()
            == "unknown"
            and str(security_status.get("mfa_state") or "").strip().lower()
            == "unknown"
            and not bool(security_status.get("credentials_readable"))
        )
    mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
    mfa_expected = bool(security_status.get("has_totp")) or mfa_state in {
        "pending",
        "enabled",
        "unmanaged",
    }
    security_credentials_ready = bool(
        mfa_expected
        and security_status.get("password_state") == "configured"
        and security_status.get("has_password")
        and security_status.get("has_totp")
        and security_status.get("credentials_readable", True)
    )
    chatgpt_login_credentials_ready = bool(
        security_state_available
        and (
            security_credentials_ready
            if mfa_expected
            else (has_mail_credentials or (provider == "gmail" and has_password))
        )
    )
    oauth_security_ready = bool(
        security_state_available
        and (not mfa_expected or security_credentials_ready)
    )
    has_cookie = bool(str(child.cookie_blob or "").strip())
    has_saved_login = bool(has_cookie or child.cookie_updated_at is not None)
    cookie_expires_at = _aware_utc(child.cookie_expires_at)
    cookie_valid = (
        cookie_expires_at > _utcnow()
        if cookie_expires_at is not None
        else None
    )
    login_health_ok = bool(
        child.enabled
        and not child.dangerous
        and not child.policy_warning
        and not str(child.refund_status or "").strip()
    )
    if not child.enabled or child.dangerous:
        login_disabled_reason = "子号已停用或标记为 Dead"
    elif child.policy_warning:
        login_disabled_reason = "子号存在政策告警"
    elif str(child.refund_status or "").strip():
        login_disabled_reason = "子号已进入退款流程"
    elif not security_state_available:
        login_disabled_reason = "子号安全状态读取失败，已停止登录"
    elif mfa_state == "unmanaged":
        login_disabled_reason = "远端已开启 2FA，但本地没有 Authenticator 密钥"
    elif mfa_state == "pending" and not security_credentials_ready:
        login_disabled_reason = "子号 2FA 设置尚未确认，本地密码或 Authenticator 密钥不完整"
    elif mfa_expected and not security_credentials_ready:
        login_disabled_reason = "子号已启用 2FA，但本地密码或 Authenticator 密钥不完整"
    elif not has_mail_credentials and not (provider == "gmail" and has_password):
        login_disabled_reason = "子号缺少可用于 OTP 登录的邮箱凭证"
    else:
        login_disabled_reason = ""
    if not security_state_available:
        oauth_disabled_reason = "子号安全状态读取失败，不能获取 RT"
    elif mfa_state == "unmanaged":
        oauth_disabled_reason = "远端已开启 2FA，但本地没有 Authenticator 密钥"
    elif mfa_state == "pending" and not security_credentials_ready:
        oauth_disabled_reason = "子号 2FA 设置尚未确认，本地密码或 Authenticator 密钥不完整，不能获取 RT"
    elif mfa_expected and not security_credentials_ready:
        oauth_disabled_reason = (
            "子号已启用 2FA，但本地 ChatGPT 密码或 Authenticator 密钥不完整"
        )
    else:
        oauth_disabled_reason = ""
    pending_totp_inspection = can_inspect_pending_totp(security_status)
    can_setup_security = bool(
        login_health_ok
        and (chatgpt_login_credentials_ready or pending_totp_inspection)
    )
    security_setup_recovery_hint = (
        "2FA 设置尚未确认，将先核对当前账号的远端状态；仅明确未开启时继续设置"
        if can_setup_security and pending_totp_inspection else ""
    )
    review_login_allowed = bool(
        child.enabled
        and child.dangerous
        and not child.policy_warning
        and not str(child.refund_status or "").strip()
        and chatgpt_login_credentials_ready
    )
    if not child.dangerous:
        review_login_disabled_reason = "子号未标记为 Dead，请使用普通登录"
    elif not child.enabled:
        review_login_disabled_reason = "子号已被人工禁用"
    elif child.policy_warning:
        review_login_disabled_reason = "子号存在政策告警，不能执行登录复核"
    elif str(child.refund_status or "").strip():
        review_login_disabled_reason = "子号已进入退款流程，不能执行登录复核"
    elif not security_state_available:
        review_login_disabled_reason = "子号安全状态读取失败，不能执行登录复核"
    elif mfa_state == "unmanaged":
        review_login_disabled_reason = "远端已开启 2FA，但本地没有 Authenticator 密钥"
    elif mfa_expected and not security_credentials_ready:
        review_login_disabled_reason = "子号的密码或 Authenticator 密钥不完整"
    elif not has_mail_credentials and not (provider == "gmail" and has_password):
        review_login_disabled_reason = "子号缺少可用于 OTP 登录复核的邮箱凭证"
    else:
        review_login_disabled_reason = ""
    return {
        "mail_provider": provider,
        **gmail_meta,
        "mail_access_type": mail_access_type,
        "has_password": has_password,
        "has_mail_oauth": has_mail_oauth,
        "has_mail_credentials": has_mail_credentials,
        "chatgpt_auth_mode": "password_totp" if mfa_expected else "email_otp",
        "chatgpt_security_credentials_ready": security_credentials_ready,
        "chatgpt_oauth_credentials_ready": oauth_security_ready,
        "chatgpt_oauth_disabled_reason": oauth_disabled_reason,
        # Only the credential-free allow-list crosses the BUSINESS child
        # facade. Passwords, TOTP seeds and ciphertext stay in the encrypted
        # security store and are available solely through the guarded export.
        "chatgpt_security": _public_chatgpt_security_status(security_status),
        "has_cookie": has_cookie,
        "has_saved_login": has_saved_login,
        "cookie_valid": cookie_valid,
        "cookie_updated_at": _iso_utc(child.cookie_updated_at),
        "cookie_expires_at": _iso_utc(child.cookie_expires_at),
        "login_status": "logged_in" if has_saved_login else "not_logged_in",
        "can_chatgpt_login": bool(
            login_health_ok and chatgpt_login_credentials_ready
        ),
        "chatgpt_login_disabled_reason": login_disabled_reason,
        "can_setup_chatgpt_security": can_setup_security,
        "chatgpt_security_setup_disabled_reason": (
            "" if can_setup_security else login_disabled_reason
        ),
        "chatgpt_security_setup_recovery_hint": security_setup_recovery_hint,
        # Dead 子号的登录复核是独立诊断能力：它允许重新走一次真实
        # ChatGPT 登录来确认远端状态。只有复核登录成功、账号租约与母子
        # 归属均未变化时，专用路由才会清除 OAuth 产生的 Dead 标记。
        "can_review_chatgpt_login": review_login_allowed,
        "chatgpt_login_review_disabled_reason": review_login_disabled_reason,
        # Mail remains available for Dead/warning/refund rows because it is the
        # diagnostic path used to understand those states.
        "can_fetch_mail": has_mail_credentials,
        "fetch_mail_disabled_reason": (
            "" if has_mail_credentials else "子号缺少可用邮件凭证"
        ),
    }


def _safe_business_child_device_snapshot(
    child: GptPlanAccountModel,
) -> dict[str, dict[str, Any]]:
    """Return the minimal public CPA/Sub2API state for one managed child.

    The shared serializers know how to interpret legacy storage, but some of
    their diagnostic fields are intentionally useful only in the source UI and
    can contain historical free-form transport errors.  This facade therefore
    narrows them again to linkage and closed state fields.
    """
    from api.gpt_plan_operations import (
        serialize_gpt_pro_cpa_status,
        serialize_gpt_pro_sub2api_status,
    )

    def safe_name(value: Any) -> str:
        return _sanitize_member_task_text(value)[:120]

    cpa_raw = serialize_gpt_pro_cpa_status(child)
    cpa_raw = cpa_raw if isinstance(cpa_raw, dict) else {}
    raw_cpa_link = (
        cpa_raw.get("cpa_synced_to")
        if isinstance(cpa_raw.get("cpa_synced_to"), dict)
        else {}
    )
    raw_target_id = raw_cpa_link.get("target_id")
    cpa_target_id = (
        int(raw_target_id)
        if isinstance(raw_target_id, int)
        and not isinstance(raw_target_id, bool)
        and raw_target_id > 0
        else 0
    )
    cpa_link = (
        {
            "target_id": cpa_target_id,
            "name": safe_name(raw_cpa_link.get("name")),
            "synced_at": _safe_business_time(raw_cpa_link.get("synced_at")),
        }
        if cpa_target_id > 0
        else None
    )
    cpa_disabled = bool(cpa_raw.get("cpa_disabled"))
    cpa_pending = bool(cpa_raw.get("cpa_sync_pending"))
    cpa_state = (
        "disabled"
        if cpa_disabled
        else "sync_pending"
        if cpa_pending
        else "linked"
        if cpa_link
        else "unlinked"
    )

    sub_raw = serialize_gpt_pro_sub2api_status(child)
    sub_raw = sub_raw if isinstance(sub_raw, dict) else {}
    raw_sub_link = (
        sub_raw.get("sub2api_synced_to")
        if isinstance(sub_raw.get("sub2api_synced_to"), dict)
        else {}
    )
    raw_device_id = raw_sub_link.get("device_id")
    sub_device_id = (
        int(raw_device_id)
        if isinstance(raw_device_id, int)
        and not isinstance(raw_device_id, bool)
        and raw_device_id > 0
        else 0
    )
    sub_link = (
        {
            "device_id": sub_device_id,
            "name": safe_name(raw_sub_link.get("name")),
            "synced_at": _safe_business_time(raw_sub_link.get("synced_at")),
        }
        if sub_device_id > 0
        else None
    )
    sub_state = str(sub_raw.get("sub2api_status") or "").strip().lower()
    if sub_state not in {"unlinked", "linked", "ok", "limit_reached", "error"}:
        sub_state = "linked" if sub_link else "unlinked"
    sub_pending = bool(sub_raw.get("sub2api_sync_pending"))
    if sub_pending:
        sub_state = "sync_pending"

    return {
        "cpa": {
            "state": cpa_state,
            "cpa_synced_to": cpa_link,
            "cpa_disabled": cpa_disabled,
            "cpa_sync_pending": cpa_pending,
        },
        "sub2api": {
            "state": sub_state,
            "sub2api_synced_to": sub_link,
            "sub2api_status": sub_state,
            "sub2api_sync_pending": sub_pending,
        },
    }


def _plan_business_candidate_records(
    session: Session,
    parent_id: int,
    *,
    candidate_mail_provider: str = "auto",
    seat_type: str = "",
    require_registration: bool = True,
) -> list[dict[str, Any]]:
    """Build the sole GPT Plans ordinary-account BUSINESS candidate set.

    Selection delegates to the BUSINESS module's shared DB query so manual
    invitation, allocation, replenishment and TEAM 401 replacement enforce the
    same enabled/non-dead/no-alert/unassigned/non-PRO/no-refund policy.  Every
    completed membership is globally audit-only and is never reused, including
    history created by another mother. Candidate identity is the durable GPT
    plan account id.
    """
    from api import gpt_business

    del parent_id
    from core.business_invite_mail_provider import resolve_candidate_mail_provider
    requested_provider = resolve_candidate_mail_provider(
        _strict_business_candidate_mail_provider(candidate_mail_provider), seat_type, session=session,
    )
    records: list[dict[str, Any]] = []
    rows = session.exec(
        gpt_business._regular_business_child_candidate_query(session)
    ).all()
    from services.gpt_plan_preparation_store import preparation_ready_ids
    from services.gmail_plan_support import gmail_registration_ready

    ready_ids = preparation_ready_ids(session)
    for child in gpt_business._prioritize_prepared_business_children(
        session, rows, ready_ids=ready_ids,
    ):
        child_id = int(child.id or 0)
        if (
            child_id <= 0
            or not _plan_account_has_business_login_credentials(child)
            or (require_registration and _safe_business_child_mail_provider(child) == "gmail"
                and not gmail_registration_ready(child))
            or not gpt_business._business_child_matches_candidate_mail_provider(
                child, requested_provider,
            )
        ):
            continue
        records.append({
            "child": child,
            "plan_account_id": child_id,
            "candidate_source": "prepared" if child_id in ready_ids else "regular",
            "prepared": child_id in ready_ids,
        })
    return records


def _safe_business_pending_intent(value: Any) -> Optional[dict[str, Any]]:
    """Allow-list a durable BUSINESS operation without returning raw result JSON."""
    if not isinstance(value, dict):
        return None
    kind = str(value.get("kind") or "").strip().lower()
    if kind not in {"remove", "revoke", "replace"}:
        return None
    operation_id = _safe_business_remote_identifier(value.get("operation_id"))
    if not operation_id:
        return None
    target = value.get("target") if isinstance(value.get("target"), dict) else {}
    replacement = (
        value.get("replacement")
        if isinstance(value.get("replacement"), dict)
        else {}
    )
    pro_ids: list[int] = []
    raw_pro_ids = target.get("pro_account_ids")
    if isinstance(raw_pro_ids, list):
        pro_ids = [
            int(item) for item in raw_pro_ids
            if isinstance(item, int) and not isinstance(item, bool) and item > 0
        ][:20]
    target_pro_id = target.get("pro_account_id")
    safe_target_pro_id = (
        int(target_pro_id)
        if isinstance(target_pro_id, int)
        and not isinstance(target_pro_id, bool)
        and target_pro_id > 0
        else None
    )
    membership_id = value.get("membership_id")
    return {
        "operation_id": operation_id,
        "membership_id": (
            int(membership_id)
            if isinstance(membership_id, int)
            and not isinstance(membership_id, bool)
            and membership_id > 0
            else None
        ),
        "kind": kind,
        "source": str(value.get("source") or "")[:30],
        "target": {
            "kind": str(target.get("kind") or "")[:20],
            "email": _safe_business_child_email(target.get("email")),
            "pro_account_id": safe_target_pro_id,
            "pro_account_ids": pro_ids,
            "user_id": _safe_business_remote_identifier(target.get("user_id")),
            "invite_id": _safe_business_remote_identifier(target.get("invite_id")),
        },
        "replacement": {
            "pro_account_id": (
                int(replacement["pro_account_id"])
                if isinstance(replacement.get("pro_account_id"), int)
                and not isinstance(replacement.get("pro_account_id"), bool)
                and int(replacement["pro_account_id"]) > 0
                else None
            ),
            "email": _safe_business_child_email(replacement.get("email")),
            "seat_type": _safe_business_child_seat_type(
                replacement.get("seat_type")
            ),
        },
        "stage": str(value.get("stage") or "")[:80],
        "state": str(value.get("state") or "")[:40],
        "action_required": bool(value.get("action_required")),
        "created_at": _safe_business_time(value.get("created_at")),
        "updated_at": _safe_business_time(value.get("updated_at")),
    }


def _business_child_facade_binding(
    account_id: int,
    *,
    require_action: bool = False,
    preflight_session: bool = False,
) -> tuple[_MemberSourceBinding, dict[str, Any]]:
    binding, member_source = _resolve_member_source_binding(account_id)
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "只有 GPT BUSINESS 母号支持子号管理")
    if preflight_session:
        # Check before the old local-expiry gate, otherwise an expired AT could
        # never use a still-valid browser Cookie to renew itself.
        from services.business_session_health import ensure_session
        ensure_session(int(binding.source_account_id))
        member_source = _assert_member_source_binding_current(binding)
    if require_action:
        # Child management and mother credential export are separate
        # capabilities.  Disabling a BUSINESS mother's own OAuth/download must
        # never disable invitations, replacements, or child OAuth.
        _require_member_capability(member_source, "business_children")
        workspace = member_source.get("business_workspace")
        workspace = workspace if isinstance(workspace, dict) else {}
        if not bool(workspace.get("team_session_usable")):
            reason = str(workspace.get("team_session_reason") or "invalid_access_token")
            raise HTTPException(
                409,
                _BUSINESS_TEAM_SESSION_REASON_MESSAGES.get(
                    reason,
                    "BUSINESS 母号 Team 登录会话不可用",
                ),
            )
    return binding, member_source


def _safe_business_child_candidate(
    child: GptPlanAccountModel,
    *,
    plan_account_id: int = 0,
) -> dict[str, Any]:
    return {
        "pro_account_id": int(child.id or 0),
        "plan_account_id": max(0, int(plan_account_id or 0)),
        "email": _safe_business_child_email(child.email),
        "status": "candidate",
        "mail_provider": _safe_business_child_mail_provider(child),
        "has_codex_rt": bool(str(child.codex_refresh_token or "").strip()),
        "codex_rt_acquired_at": _iso_utc(child.codex_rt_acquired_at),
    }


def _business_children_snapshot(
    binding: _MemberSourceBinding,
) -> dict[str, Any]:
    """Build the expanded BUSINESS row exclusively from normalized DB state."""
    from api import gpt_business

    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, int(binding.source_account_id))
        if (
            parent is None
            or _normalized_email(parent.email) != binding.normalized_email
        ):
            raise HTTPException(409, "BUSINESS 工作区绑定已变化，请刷新后重试")
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel)
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(binding.source_account_id)
            )
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .order_by(col(GptBusinessChildMembershipModel.invited_at).desc())
        ).all())
        child_ids = {
            int(row.pro_account_id)
            for row in memberships
            if (
                str(row.source or "").strip().lower() == "pool"
                and row.pro_account_id is not None
                and int(row.pro_account_id) > 0
            )
        }
        children = {
            int(row.id): row
            for row in session.exec(
                select(GptPlanAccountModel).where(
                    GptPlanAccountModel.id.in_(sorted(child_ids))  # type: ignore[union-attr]
                )
            ).all()
            if row.id is not None
        } if child_ids else {}
        child_security_statuses = _chatgpt_security_status_map([
            str(child.email or "") for child in children.values()
        ])
        invite_quota = _safe_business_quota(
            gpt_business._invite_quota(
                session,
                int(binding.source_account_id),
            )
        )
        rotation_quota = _safe_business_quota(
            gpt_business._rotation_quota(
                session,
                int(binding.source_account_id),
            )
        )
        invite_cooldown = _safe_business_invite_cooldown(parent)
        candidate_count = len(_plan_business_candidate_records(
            session,
            int(binding.source_account_id),
        ))
        pending_raw = gpt_business._business_pending_intents(
            session,
            int(binding.source_account_id),
        )
        seat_summary = _safe_business_seat_summary(parent)
        # Read the current parent row on every expansion.  The workspace cache
        # may predate the latest successful DELETE-member response, while the
        # canonical vacancy policy is persisted directly on this row.
        vacancy_policy = _safe_business_vacancy_policy(
            gpt_business._get_vacancy_policy(parent)
        )

        members: list[dict[str, Any]] = []
        invites: list[dict[str, Any]] = []
        managed_children: list[dict[str, Any]] = []
        replaceable_children: list[dict[str, Any]] = []
        active_count = 0

        for membership in memberships:
            email = _safe_business_child_email(membership.email)
            seat_type = _safe_business_child_seat_type(membership.seat_type)
            managed_pool_membership = (
                str(membership.source or "").strip().lower() == "pool"
            )
            pro_account_id = (
                int(membership.pro_account_id)
                if managed_pool_membership
                and membership.pro_account_id is not None
                and int(membership.pro_account_id) > 0
                else None
            )
            child = children.get(pro_account_id or 0)
            user_id = _safe_business_remote_identifier(membership.remote_user_id)
            invite_id = _safe_business_remote_identifier(membership.remote_invite_id)
            active_count += 1
            kind = "member" if user_id else "invite" if invite_id else "local"
            common = {
                "membership_id": int(membership.id or 0),
                "pro_account_id": pro_account_id,
                "email": email,
                "source": "gpt_pro_regular" if child is not None else "manual",
                "seat_type": seat_type,
                "status": kind,
                "invited_at": _iso_utc(membership.invited_at),
                **_business_child_warranty_snapshot(membership),
            }
            if user_id:
                member = {**common, "user_id": user_id}
                members.append(member)
                replaceable_children.append({
                    **common,
                    "kind": "member",
                    "user_id": user_id,
                })
            elif invite_id:
                invite = {**common, "invite_id": invite_id}
                invites.append(invite)
                replaceable_children.append({
                    **common,
                    "kind": "invite",
                    "invite_id": invite_id,
                })

            if child is not None:
                child_extra = _safe_json_object(child.extra_json)
                child_account_capabilities = _business_child_account_capabilities(
                    child,
                    chatgpt_security=child_security_statuses.get(
                        _chatgpt_security_email_key(child.email),
                        _unavailable_chatgpt_security_status(),
                    ),
                )
                # Device state is stored alongside other private runtime data
                # in extra_json.  Always cross the established serializer
                # allow-lists instead of returning that document or selecting
                # fields ad hoc at this facade boundary.
                device_status = _safe_business_child_device_snapshot(child)
                cpa_status = device_status["cpa"]
                sub2api_status = device_status["sub2api"]
                pending_alerts_count = len(_safe_json_list(
                    child.pending_alerts_json,
                ))
                pending_inbox_count = len(_safe_json_list(
                    child.pending_inbox_json,
                ))
                monitor_enabled = bool(
                    child.enabled
                    and child_extra.get("business_child_monitor_enabled", True)
                )
                last_mail_error = _redact_text(
                    child.last_mail_check_error or "",
                    child.password or "",
                    child.client_id or "",
                    child.refresh_token or "",
                )[:300]
                managed_children.append({
                    **common,
                    **child_account_capabilities,
                    "user_id": user_id,
                    "invite_id": invite_id,
                    "rt_supported": True,
                    "enabled": bool(child.enabled),
                    "dangerous": bool(child.dangerous),
                    "dangerous_detected_at": _iso_utc(
                        child.dangerous_detected_at
                    ),
                    "policy_warning": bool(child.policy_warning),
                    "policy_warning_detected_at": _iso_utc(
                        child.policy_warning_detected_at
                    ),
                    "refund_status": _public_refund_status(child.refund_status),
                    "has_codex_rt": bool(str(child.codex_refresh_token or "").strip()),
                    "codex_rt_acquired_at": _iso_utc(child.codex_rt_acquired_at),
                    "cpa": cpa_status,
                    "cpa_synced_to": cpa_status.get("cpa_synced_to"),
                    "sub2api": sub2api_status,
                    "sub2api_synced_to": sub2api_status.get(
                        "sub2api_synced_to"
                    ),
                    "sub2api_status": str(
                        sub2api_status.get("sub2api_status") or "unlinked"
                    ),
                    "sub2api_sync_pending": bool(
                        sub2api_status.get("sub2api_sync_pending")
                    ),
                    "monitor_enabled": monitor_enabled,
                    "last_mail_check_at": _iso_utc(child.last_mail_check_at),
                    "last_mail_check_error": last_mail_error,
                    "pending_alerts_count": pending_alerts_count,
                    "pending_inbox_count": pending_inbox_count,
                    "mail_monitor": {
                        "supported": True,
                        "enabled": monitor_enabled,
                        "monitor_enabled": monitor_enabled,
                        "last_check_at": _iso_utc(child.last_mail_check_at),
                        "last_mail_check_at": _iso_utc(child.last_mail_check_at),
                        "last_error": last_mail_error,
                        "last_mail_check_error": last_mail_error,
                        "pending_alerts_count": pending_alerts_count,
                        "pending_inbox_count": pending_inbox_count,
                    },
                    "can_get_rt": bool(
                        child.enabled
                        and not child.dangerous
                        and not child.policy_warning
                        and not str(child.refund_status or "").strip()
                        and (user_id or invite_id)
                        and child_account_capabilities.get(
                            "chatgpt_oauth_credentials_ready",
                            False,
                        )
                    ),
                })

        pending_intents = [
            item for item in (
                _safe_business_pending_intent(value) for value in pending_raw
            )
            if item is not None
        ]
        candidate_count = max(0, int(candidate_count or 0))

    return {
        "ok": True,
        "account_id": int(binding.plan_account_id),
        "members": members,
        "invites": invites,
        "managed_children": managed_children,
        "replaceable_children": replaceable_children,
        "seat_summary": seat_summary,
        "invite_quota": invite_quota,
        "rotation_quota": rotation_quota,
        "invite_cooldown": invite_cooldown,
        "vacancy_policy": vacancy_policy,
        "candidate_count": candidate_count,
        "invite_candidate_count": candidate_count,
        "pending_intents": pending_intents,
        "total": active_count,
        "workspace_checked_at": (
            str((seat_summary or {}).get("checked_at") or "")
        ),
        "checked_at": str((seat_summary or {}).get("checked_at") or ""),
        "snapshot_source": "database",
    }


def _safe_business_child_mutation_result(
    raw: Any,
    *,
    operation_id: str,
) -> dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    invited = value.get("invited") if isinstance(value.get("invited"), list) else []
    errored = value.get("errored") if isinstance(value.get("errored"), list) else []
    managed_ids = (
        value.get("managed_child_ids")
        if isinstance(value.get("managed_child_ids"), list)
        else []
    )

    def positive_id(key: str) -> Optional[int]:
        raw_id = value.get(key)
        if isinstance(raw_id, int) and not isinstance(raw_id, bool) and raw_id > 0:
            return int(raw_id)
        return None

    safe_errors: list[dict[str, Any]] = []
    for item in errored[:20]:
        item = item if isinstance(item, dict) else {"error": item}
        raw_id = item.get("pro_account_id")
        safe_errors.append({
            "email": _safe_business_child_email(item.get("email")),
            "pro_account_id": (
                int(raw_id)
                if isinstance(raw_id, int)
                and not isinstance(raw_id, bool)
                and raw_id > 0
                else None
            ),
            "error": _safe_business_child_error(item.get("error")),
        })
    return {
        "ok": bool(value.get("ok")),
        "partial": bool(value.get("partial")),
        "action_required": bool(value.get("action_required")),
        "idempotent": bool(value.get("idempotent")),
        "operation_id": operation_id,
        "status": (
            int(value.get("status"))
            if isinstance(value.get("status"), int)
            and not isinstance(value.get("status"), bool)
            else None
        ),
        "seat_type": _safe_business_child_seat_type(value.get("seat_type")),
        "invited": [
            email for email in (
                _safe_business_child_email(item) for item in invited[:20]
            )
            if email
        ],
        "managed_child_ids": [
            int(item) for item in managed_ids[:20]
            if isinstance(item, int) and not isinstance(item, bool) and item > 0
        ],
        "auto_selected_pro_account_id": positive_id("auto_selected_pro_account_id"),
        "resolved_new_pro_account_id": positive_id("resolved_new_pro_account_id"),
        "removed": bool(value.get("removed")),
        "invite_failed": bool(value.get("invite_failed")),
        "warning": _safe_business_child_error(value.get("warning")),
        "error": _safe_business_child_error(value.get("error")),
        "errored": safe_errors,
        "dead_candidate_cleanups": [
            safe for item in (value.get("dead_candidate_cleanups") or [])[:100]
            if (safe := _safe_business_dead_candidate_cleanup(item)) is not None
        ] if isinstance(value.get("dead_candidate_cleanups"), list) else [],
    }


def _confirm_business_child_persistence(
    result: dict[str, Any],
    children: Optional[dict[str, Any]],
    *,
    expected_manual_email: str = "",
) -> None:
    """A successful pool mutation is public only after its DB ownership exists."""
    expected = {
        int(item)
        for item in (result.get("managed_child_ids") or [])
        if isinstance(item, int) and not isinstance(item, bool) and item > 0
    }
    for key in ("resolved_new_pro_account_id", "auto_selected_pro_account_id"):
        item = result.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item > 0:
            expected.add(int(item))
    active = {
        int(item.get("pro_account_id"))
        for item in (
            (children or {}).get("managed_children")
            if isinstance((children or {}).get("managed_children"), list)
            else []
        )
        if isinstance(item, dict)
        and isinstance(item.get("pro_account_id"), int)
        and not isinstance(item.get("pro_account_id"), bool)
        and int(item.get("pro_account_id")) > 0
    }
    active_emails = {
        _safe_business_child_email(item.get("email"))
        for collection in ("members", "invites")
        for item in (
            (children or {}).get(collection)
            if isinstance((children or {}).get(collection), list)
            else []
        )
        if isinstance(item, dict) and _safe_business_child_email(item.get("email"))
    }
    normalized_manual = _safe_business_child_email(expected_manual_email)
    has_expected = bool(expected or normalized_manual)
    confirmed = bool(
        has_expected
        and expected.issubset(active)
        and (not normalized_manual or normalized_manual in active_emails)
    )
    result["persistence_confirmed"] = confirmed
    if bool(result.get("ok")) and has_expected and not confirmed:
        result["ok"] = False
        result["partial"] = True
        result["action_required"] = True
        result["warning"] = (
            "远端邀请已接受，但本地子号归属尚未确认；"
            "请刷新工作区后重新发起"
        )


_PLAN_ICLOUD_CONFIG_KEYS = frozenset({
    "qqmail_user",
    "qqmail_auth_code",
    "qqmail_imap_host",
    "qqmail_imap_port",
    "qqmail_pool_file",
    "qqmail_require_apple_header",
    "icloud_hme_base_url",
    "icloud_hme_api_key",
    "icloud_hme_pool_file",
    "icloud_cookie",
})
_PLAN_ICLOUD_SECRET_KEYS = frozenset({
    "qqmail_auth_code",
    "icloud_hme_api_key",
    "icloud_cookie",
})


@router.get("/icloud-config")
def get_plan_icloud_config():
    from core.config_store import config_store

    result: dict[str, Any] = {}
    for key in _PLAN_ICLOUD_CONFIG_KEYS:
        value = str(config_store.get(key, "") or "")
        if key in _PLAN_ICLOUD_SECRET_KEYS:
            result[key] = ""
            result[f"{key}_set"] = bool(value)
        else:
            result[key] = value
    return result


@router.put("/icloud-config")
def put_plan_icloud_config(body: GptPlanIcloudConfigUpdateRequest):
    from core.config_store import config_store

    updates: dict[str, str] = {}
    for key, value in (body.values or {}).items():
        if key not in _PLAN_ICLOUD_CONFIG_KEYS:
            continue
        normalized = str(value if value is not None else "")
        if key in _PLAN_ICLOUD_SECRET_KEYS and not normalized:
            continue
        updates[key] = normalized
    if updates:
        config_store.set_many(updates)
    return {"ok": True}


@router.get("/nvtokens-config")
def get_plan_nexusvault_config():
    """Return only secret-free NexusVault configuration flags."""
    from services.nexusvault import public_config

    return public_config()


@router.put("/nvtokens-config")
def put_plan_nexusvault_config(body: GptPlanNexusVaultConfigRequest):
    """Persist write-only inventory/query credentials without reflecting them."""
    from services.nexusvault import NexusVaultConfigurationError, save_config

    try:
        return save_config(
            base_url=body.base_url,
            api_key=body.api_key,
            query_cookie=body.query_cookie,
        )
    except NexusVaultConfigurationError as exc:
        raise HTTPException(400, str(exc)) from exc


def _upsert_plan_icloud_account(
    session: Session,
    email: Any,
    *,
    now: datetime,
) -> str:
    normalized = _normalized_email(email)
    if not normalized or "@" not in normalized:
        return "skipped"
    account = session.exec(
        select(GptPlanAccountModel).where(
            func.lower(GptPlanAccountModel.email) == normalized
        )
    ).first()
    if account is None:
        session.add(GptPlanAccountModel(
            email=normalized,
            mail_provider="icloud",
            catalog_category="regular",
            extra_json=json.dumps({"mail_provider": "icloud"}, ensure_ascii=False),
            created_at=now,
            updated_at=now,
        ))
        return "created"
    changed = False
    if str(account.mail_provider or "").strip().lower() != "icloud":
        account.mail_provider = "icloud"
        changed = True
    extra = _safe_json_object(account.extra_json)
    if extra.get("mail_provider") != "icloud":
        extra["mail_provider"] = "icloud"
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        changed = True
    # Never downgrade an existing paid/refunded/BUSINESS account merely because
    # its mailbox alias appears in HME.  New rows are ordinary accounts.
    if changed:
        account.updated_at = now
        session.add(account)
        return "updated"
    return "exists"


@router.post("/icloud/import-from-hme")
def import_plan_icloud_from_hme():
    raise HTTPException(400, "此独立项目的普通账号仅支持 Gmail 子号")


@router.get("/upgrade-browser-config")
def get_plan_upgrade_browser_config():
    from core.gpt_plan_upgrade_browser_config import load_upgrade_browser_config

    return load_upgrade_browser_config()


@router.put("/upgrade-browser-config")
def put_plan_upgrade_browser_config(body: GptPlanUpgradeBrowserConfigRequest):
    from core.gpt_plan_upgrade_browser_config import (
        UpgradeBrowserConfigError,
        load_upgrade_browser_config,
        save_upgrade_browser_config,
    )

    current = load_upgrade_browser_config()
    backend = body.browser_backend
    if body.use_roxy is not None:
        selected = "roxybrowser" if body.use_roxy else "local"
        if backend is not None and backend != selected:
            raise HTTPException(400, "use_roxy 与 browser_backend 不一致")
        backend = selected
    fields_set = getattr(body, "model_fields_set", None)
    if fields_set is None:
        fields_set = getattr(body, "__fields_set__", set())
    proxy_id = (
        body.roxy_proxy_id
        if "roxy_proxy_id" in set(fields_set or set())
        else current.get("roxy_proxy_id")
    )
    try:
        saved = save_upgrade_browser_config(
            browser_backend=backend or current["browser_backend"],
            roxy_proxy_id=proxy_id,
            db_engine=engine,
        )
    except UpgradeBrowserConfigError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    return {"ok": True, **saved}


def _plan_roxy_proxy_out(proxy: GptPlanRoxyProxyModel) -> dict[str, Any]:
    raw_check_status = getattr(proxy, "check_status", -1)
    check_status = (
        int(raw_check_status)
        if isinstance(raw_check_status, int) and not isinstance(raw_check_status, bool)
        else -1
    )
    return {
        "id": proxy.id,
        "host": proxy.host,
        "port": proxy.port,
        "protocol": proxy.protocol,
        "username": proxy.username,
        "password": proxy.password,
        "note": proxy.note,
        "roxy_module_id": proxy.roxy_module_id,
        "last_ip": proxy.last_ip,
        "last_country": proxy.last_country,
        "enabled": bool(proxy.enabled),
        "check_status": check_status,
        "checked_at": _iso_utc(getattr(proxy, "checked_at", None)),
        "created_at": _iso_utc(proxy.created_at),
        "updated_at": _iso_utc(proxy.updated_at),
    }


def _parse_plan_roxy_proxy_lines(
    data: str,
    *,
    default_protocol: str,
) -> list[dict[str, str]]:
    protocol = str(default_protocol or "SOCKS5").strip().upper()
    if protocol not in {"HTTP", "HTTPS", "SOCKS5"}:
        raise HTTPException(400, "protocol 只支持 HTTP/HTTPS/SOCKS5")
    parsed: list[dict[str, str]] = []
    for raw in str(data or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        note = ""
        for separator in (" #", "\t", " | ", "|"):
            if separator in line:
                line, raw_note = line.split(separator, 1)
                note = raw_note.strip().lstrip("#").strip()
                line = line.strip()
                break
        row_protocol = protocol
        prefixed = re.match(r"^(https?|socks5)://(.+)$", line, re.IGNORECASE)
        if prefixed:
            row_protocol = prefixed.group(1).upper()
            line = prefixed.group(2)
        parts = [part.strip() for part in line.split(":")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        parsed.append({
            "host": parts[0],
            "port": parts[1],
            "protocol": row_protocol,
            "username": parts[2] if len(parts) >= 3 else "",
            "password": parts[3] if len(parts) >= 4 else "",
            "note": note,
        })
    return parsed


@router.get("/roxy/proxies")
def list_plan_roxy_proxies():
    with Session(engine) as session:
        rows = session.exec(
            select(GptPlanRoxyProxyModel).order_by(col(GptPlanRoxyProxyModel.id).desc())
        ).all()
    return {"total": len(rows), "items": [_plan_roxy_proxy_out(row) for row in rows]}


@router.post("/roxy/proxies")
def add_plan_roxy_proxies(body: GptPlanRoxyProxyBatchRequest):
    parsed = _parse_plan_roxy_proxy_lines(
        body.data,
        default_protocol=body.protocol,
    )
    if not parsed:
        raise HTTPException(400, "没有解析到有效代理行")
    now = _utcnow()
    with Session(engine) as session:
        for item in parsed:
            session.add(GptPlanRoxyProxyModel(created_at=now, updated_at=now, **item))
        session.commit()
    return {"ok": True, "added": len(parsed)}


@router.put("/roxy/proxies/{proxy_id}")
def update_plan_roxy_proxy(
    proxy_id: int,
    body: GptPlanRoxyProxyUpdateRequest,
):
    with Session(engine) as session:
        proxy = session.get(GptPlanRoxyProxyModel, int(proxy_id))
        if proxy is None:
            raise HTTPException(404, "代理不存在")
        for field_name in (
            "host",
            "port",
            "protocol",
            "username",
            "password",
            "note",
            "enabled",
        ):
            value = getattr(body, field_name)
            if value is not None:
                if field_name == "protocol":
                    value = str(value).strip().upper()
                    if value not in {"HTTP", "HTTPS", "SOCKS5"}:
                        raise HTTPException(400, "protocol 只支持 HTTP/HTTPS/SOCKS5")
                setattr(proxy, field_name, value)
        proxy.updated_at = _utcnow()
        session.add(proxy)
        session.commit()
        session.refresh(proxy)
        return {"ok": True, "item": _plan_roxy_proxy_out(proxy)}


@router.delete("/roxy/proxies/{proxy_id}")
def delete_plan_roxy_proxy(proxy_id: int):
    with Session(engine) as session:
        proxy = session.get(GptPlanRoxyProxyModel, int(proxy_id))
        if proxy is None:
            raise HTTPException(404, "代理不存在")
        session.delete(proxy)
        session.commit()
    return {"ok": True}


@router.post("/roxy/proxies/import")
def import_plan_roxy_proxies(
    body: Optional[GptPlanRoxyProxyImportRequest] = None,
):
    from core.roxy_browser import (
        RoxyBrowserClient,
        RoxyBrowserError,
        load_roxy_config,
        resolve_workspace_id,
    )

    try:
        workspace_id = resolve_workspace_id()
        config = load_roxy_config()
        client = RoxyBrowserClient(config["api_host"], config["token"])
        remote_rows: list[dict[str, Any]] = []
        for page in range(1, 51):
            batch = client.list_proxies(workspace_id, page_index=page, page_size=200)
            remote_rows.extend(batch)
            if len(batch) < 200:
                break
    except RoxyBrowserError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"从 RoxyBrowser 导入失败: {exc}") from exc

    now = _utcnow()
    imported = updated = skipped = removed = 0
    with Session(engine) as session:
        by_key = {
            (str(row.host).strip().lower(), str(row.port).strip()): row
            for row in session.exec(select(GptPlanRoxyProxyModel)).all()
        }
        fetched_keys: set[tuple[str, str]] = set()
        for remote in remote_rows:
            host = str(remote.get("host") or "").strip()
            port = str(remote.get("port") or "").strip()
            if not host or not port:
                continue
            key = (host.lower(), port)
            fetched_keys.add(key)
            protocol = str(
                remote.get("protocol") or remote.get("proxyCategory") or "SOCKS5"
            ).strip().upper()
            if protocol not in {"HTTP", "HTTPS", "SOCKS5"}:
                protocol = "SOCKS5"
            values = {
                "roxy_module_id": str(remote.get("id") or ""),
                "last_ip": str(remote.get("lastIp") or ""),
                "last_country": str(remote.get("lastCountry") or ""),
            }
            remote_username = str(
                remote.get("proxyUserName") or remote.get("username") or ""
            )
            remote_password = str(
                remote.get("proxyPassword") or remote.get("password") or ""
            )
            row = by_key.get(key)
            if row is None:
                row = GptPlanRoxyProxyModel(
                    host=host,
                    port=port,
                    protocol=protocol,
                    username=str(remote.get("proxyUserName") or remote.get("username") or ""),
                    password=str(remote.get("proxyPassword") or remote.get("password") or ""),
                    note=str(remote.get("remark") or ""),
                    created_at=now,
                    updated_at=now,
                    **values,
                )
                session.add(row)
                by_key[key] = row
                imported += 1
                continue
            changed = False
            remark = str(remote.get("remark") or "").strip()
            if remark and not str(row.note or "").strip():
                row.note = remark
                changed = True
            if remote_username and not str(row.username or "").strip():
                row.username = remote_username
                changed = True
            if remote_password and not str(row.password or "").strip():
                row.password = remote_password
                changed = True
            for field_name, value in values.items():
                if value and str(getattr(row, field_name, "") or "") != value:
                    setattr(row, field_name, value)
                    changed = True
            if changed:
                row.updated_at = now
                session.add(row)
                updated += 1
            else:
                skipped += 1
        if bool(body and body.prune):
            for key, row in list(by_key.items()):
                if str(row.roxy_module_id or "").strip() and key not in fetched_keys:
                    session.delete(row)
                    removed += 1
        session.commit()
    return {
        "ok": True,
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "removed": removed,
        "total_fetched": len(remote_rows),
    }


@router.post("/roxy/proxies/detect")
def detect_plan_roxy_proxies(body: GptPlanRoxyProxyDetectRequest):
    from core.roxy_browser import (
        RoxyBrowserClient,
        RoxyBrowserError,
        load_roxy_config,
        resolve_workspace_id,
    )

    requested_ids = {int(value) for value in body.ids if int(value) > 0}
    with Session(engine) as session:
        rows = session.exec(select(GptPlanRoxyProxyModel)).all()
    targets = [
        row
        for row in rows
        if (not requested_ids or int(row.id or 0) in requested_ids)
        and str(row.roxy_module_id or "").strip()
    ]
    skipped = [
        int(row.id or 0)
        for row in rows
        if (not requested_ids or int(row.id or 0) in requested_ids)
        and not str(row.roxy_module_id or "").strip()
    ]
    if not targets:
        raise HTTPException(400, "没有可检测的 RoxyBrowser 代理")
    try:
        workspace_id = resolve_workspace_id()
        config = load_roxy_config()
        client = RoxyBrowserClient(config["api_host"], config["token"])
        for target in targets:
            try:
                client.detect_proxy(workspace_id, int(target.roxy_module_id))
            except Exception:
                pass
        time.sleep(6)
        fresh = client.list_proxies(workspace_id)
    except RoxyBrowserError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"检测失败: {exc}") from exc
    by_module_id = {str(row.get("id") or ""): row for row in fresh}
    now = _utcnow()
    results: list[dict[str, Any]] = []
    alive = 0
    with Session(engine) as session:
        for target in targets:
            remote = by_module_id.get(str(target.roxy_module_id or "")) or {}
            check_status = remote.get("checkStatus")
            status = 1 if check_status == 1 else 0 if check_status is not None else -1
            row = session.get(GptPlanRoxyProxyModel, int(target.id or 0))
            if row is not None:
                row.check_status = status
                row.checked_at = now
                row.last_ip = str(remote.get("lastIp") or row.last_ip or "")
                row.last_country = str(
                    remote.get("lastCountry") or row.last_country or ""
                )
                row.updated_at = now
                session.add(row)
            if status == 1:
                alive += 1
            results.append({
                "id": int(target.id or 0),
                "check_status": status,
                "last_ip": str(remote.get("lastIp") or ""),
                "last_country": str(remote.get("lastCountry") or ""),
            })
        session.commit()
    return {
        "ok": True,
        "total": len(targets),
        "checked": len(targets),
        "alive": alive,
        "skipped": skipped,
        "skipped_no_module": skipped,
        "results": results,
    }


@router.post("/sync-source-accounts")
def sync_source_accounts():
    """Reject the retired mirror operation.

    Historical rows are detached by the database's one-time migration.  Keeping
    this route as a 410 response gives old frontends an explicit cutover signal
    without ever recreating a shadow row or overwriting local state.
    """
    raise HTTPException(
        410,
        {
            "code": "source_sync_retired",
            "message": "来源同步已停用；GPT 套餐管理已改为本地权威数据",
        },
    )


def _exact_business_typed_available_counts(
    summary: dict[str, Any],
) -> Optional[dict[str, int]]:
    """Return both exact typed vacancy counts or ``None`` when incomplete.

    The source BUSINESS invite implementation refuses to derive a seat type
    unless *both* default and prolite availability values are exact.  List and
    batch planning must use that same boundary; accepting one exact class here
    would create a task whose first remote invitation is guaranteed to fail.
    """
    if not (
        bool(summary.get("seat_type_capacity_known"))
        and bool(summary.get("seat_type_occupancy_known"))
    ):
        return None
    by_type = summary.get("by_type")
    by_type = by_type if isinstance(by_type, dict) else {}
    result: dict[str, int] = {}
    for seat_type in ("default", "prolite"):
        item = by_type.get(seat_type)
        item = item if isinstance(item, dict) else {}
        available = item.get("available")
        if (
            item.get("availability_exact") is not True
            or isinstance(available, bool)
            or not isinstance(available, int)
            or available < 0
        ):
            return None
        result[seat_type] = int(available)
    return result


def _business_seat_snapshot_bucket(source: GptBusinessAccountModel) -> str:
    """Classify only the persisted BUSINESS seat-capacity snapshot.

    This deliberately ignores login health, Dead state and invite cooldown.
    Those are separate operational capabilities and must not change what a
    seat-capacity filter means.  A positive aggregate vacancy is considered
    invitable only when its concrete default/prolite type is also exact.
    """
    summary = _safe_business_seat_summary(source)
    if not isinstance(summary, dict) or not bool(summary.get("known")):
        return "unknown"
    available = summary.get("available")
    if (
        isinstance(available, bool)
        or not isinstance(available, int)
        or available < 0
    ):
        return "unknown"
    if available <= 0:
        return "full"
    typed_available = _exact_business_typed_available_counts(summary)
    if typed_available is None or sum(typed_available.values()) <= 0:
        return "unknown"
    return "available"


def _business_source_ids_for_seat_filter(
    session: Session,
    seat_filter: str,
) -> list[int]:
    return [
        int(source.id)
        for source in session.exec(select(GptBusinessAccountModel)).all()
        if source.id is not None
        and _business_seat_snapshot_bucket(source) == seat_filter
    ]


@router.get("/accounts")
def list_accounts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    keyword: Optional[str] = Query(None),
    plan_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    login_status: Optional[str] = Query(None),
    account_type: Optional[str] = None,
    member_plan: Optional[str] = None,
    account_id: Optional[int] = None,
    upgrade_time_order: Optional[str] = None,
    business_usage_type: Optional[str] = None,
    business_seat_filter: Optional[str] = None,
    mail_provider: Optional[str] = None,
):
    if login_status not in {None, "", "logged_in", "not_logged_in"}:
        raise HTTPException(400, "login_status 只支持 logged_in 或 not_logged_in")
    if account_type not in {None, "", "regular", "member", "refunded"}:
        raise HTTPException(400, "account_type 只支持 regular/member/refunded")
    if member_plan not in {None, "", "go", "plus", "pro", "team"}:
        raise HTTPException(400, "member_plan 只支持 go/plus/pro/team")
    if account_type in {"regular", "refunded"} and member_plan:
        raise HTTPException(400, "普通/已退款账号不能同时指定 member_plan")
    if upgrade_time_order not in {None, "", "asc", "desc"}:
        raise HTTPException(400, "upgrade_time_order 只支持 asc 或 desc")
    if upgrade_time_order and account_type != "refunded":
        raise HTTPException(400, "upgrade_time_order 仅支持已退款账号")
    if business_usage_type not in {None, "", *_BUSINESS_USAGE_FILTERS}:
        raise HTTPException(
            400,
            "business_usage_type 只支持 unassigned/sale/self_use/transit",
        )
    if business_seat_filter not in {None, "", *_BUSINESS_SEAT_FILTERS}:
        raise HTTPException(
            400,
            "business_seat_filter 只支持 available/full/unknown",
        )
    has_business_filter = bool(business_usage_type or business_seat_filter)
    if has_business_filter and not (
        account_type == "member" and member_plan == "team"
    ):
        raise HTTPException(
            400,
            "BUSINESS 用途及席位筛选仅支持 BUSINESS 母号列表",
        )
    if account_id is not None and (
        isinstance(account_id, bool)
        or not isinstance(account_id, int)
        or account_id <= 0
    ):
        raise HTTPException(400, "account_id 必须是正整数")

    normalized_provider = _normalize_mail_provider(mail_provider) if mail_provider else None
    with Session(engine) as session:
        query = select(GptPlanAccountModel)
        if normalized_provider is not None:
            from services.gmail_plan_support import mail_provider_expression
            query = query.where(mail_provider_expression(GptPlanAccountModel) == normalized_provider)
        if account_id is not None:
            # Deep links use the durable local directory id.  Do not fall back
            # to an email contains query: a stale or mismatched id must simply
            # produce an empty result under the requested tab filters.
            query = query.where(GptPlanAccountModel.id == int(account_id))
        if keyword:
            term = str(keyword).strip()
            if term:
                query = query.where(
                    col(GptPlanAccountModel.email).contains(term)
                    | col(GptPlanAccountModel.note).contains(term)
                )
        if plan_type is not None:
            query = query.where(
                func.lower(GptPlanAccountModel.plan_type)
                == _normalize_plan_type(plan_type)
            )
        if enabled is not None:
            query = query.where(GptPlanAccountModel.enabled == enabled)
        plan_expr = func.lower(func.trim(func.coalesce(GptPlanAccountModel.plan_type, "")))
        if account_type in _CATALOG_CATEGORIES:
            query = query.where(_catalog_category_predicate(account_type))
        if account_type == "regular":
            from services.gpt_plan_preparation_store import preparation_ready_ids

            ready_ids = preparation_ready_ids(session)
            if ready_ids:
                query = query.where(GptPlanAccountModel.id.not_in(ready_ids))  # type: ignore[union-attr]
        if member_plan:
            query = query.where(
                _catalog_category_predicate("member"),
                plan_expr.in_(tuple(_MEMBER_PLAN_TYPES[member_plan])),
            )
        if has_business_filter:
            # BUSINESS-specific filters are also an authority boundary: a
            # TEAM-labelled local child or detached row must never be mistaken
            # for a workspace mother.
            query = query.join(
                GptBusinessAccountModel,
                GptBusinessAccountModel.id
                == GptPlanAccountModel.source_account_id,
            ).where(
                func.lower(func.trim(func.coalesce(
                    GptPlanAccountModel.source_pool,
                    "",
                ))) == "gpt_business",
                GptPlanAccountModel.source_account_id.is_not(None),  # type: ignore[union-attr]
                func.lower(func.trim(GptBusinessAccountModel.email))
                == func.lower(func.trim(GptPlanAccountModel.email)),
            )
        if business_usage_type:
            if business_usage_type == "unassigned":
                query = query.where(
                    or_(
                        GptPlanAccountModel.business_usage_type.is_(None),  # type: ignore[union-attr]
                        GptPlanAccountModel.business_usage_type == "",
                        ~GptPlanAccountModel.business_usage_type.in_(  # type: ignore[union-attr]
                            tuple(_BUSINESS_USAGE_TYPES)
                        ),
                    )
                )
            else:
                # Writers persist canonical lower-case values, so keep this an
                # indexed equality predicate rather than wrapping the column
                # in lower()/trim().
                query = query.where(
                    GptPlanAccountModel.business_usage_type
                    == business_usage_type
                )
        if business_seat_filter:
            source_ids = _business_source_ids_for_seat_filter(
                session,
                business_seat_filter,
            )
            if source_ids:
                query = query.where(
                    GptPlanAccountModel.source_account_id.in_(source_ids)  # type: ignore[union-attr]
                )
            else:
                query = query.where(GptPlanAccountModel.id == -1)
        if login_status == "logged_in":
            query = query.where(_has_saved_login_predicate())
        elif login_status == "not_logged_in":
            query = query.where(~_has_saved_login_predicate())

        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        uses_upgrade_time_order = bool(
            account_type in {"member", "refunded"} or member_plan
        )
        if uses_upgrade_time_order:
            # Upgrade summaries are one-to-one with directory accounts.  The
            # explicit NULL discriminator is portable across SQLite/Postgres:
            # known times first and unknown times last.  Matching id direction
            # is a stable tie-breaker for pagination and equal timestamps.
            ascending_upgrade_time = bool(
                account_type == "refunded"
                and (upgrade_time_order or "desc") == "asc"
            )
            upgrade_time_column = col(
                GptPlanAccountUpgradeModel.plan_upgraded_at
            )
            account_id_column = col(GptPlanAccountModel.id)
            query = query.outerjoin(
                GptPlanAccountUpgradeModel,
                GptPlanAccountUpgradeModel.account_id
                == GptPlanAccountModel.id,
            ).order_by(
                GptPlanAccountUpgradeModel.plan_upgraded_at.is_(None),
                (
                    upgrade_time_column.asc()
                    if ascending_upgrade_time
                    else upgrade_time_column.desc()
                ),
                (
                    account_id_column.asc()
                    if ascending_upgrade_time
                    else account_id_column.desc()
                ),
            )
        else:
            # Mixed and regular views retain their established ID ordering.
            query = query.order_by(col(GptPlanAccountModel.id).desc())
        rows = session.exec(
            query.offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        summaries = _upgrade_summary_map(
            session,
            [int(row.id) for row in rows if row.id is not None],
        )
        member_sources = _member_source_map(session, list(rows))
        security_statuses = _chatgpt_security_status_map(
            [str(row.email or "") for row in rows]
        )
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": [
                _serialize_account(
                    row,
                    summaries.get(int(row.id or 0)),
                    member_sources.get(int(row.id or 0)),
                    security_statuses.get(
                        _chatgpt_security_email_key(row.email),
                        _unavailable_chatgpt_security_status(),
                    ),
                )
                for row in rows
            ],
        }


@router.get("/accounts/stats")
@router.get("/stats")
def account_stats():
    from services.gpt_plan_preparation_store import preparation_ready_ids

    with Session(engine) as session:
        rows = session.exec(select(GptPlanAccountModel)).all()
        ready_ids = preparation_ready_ids(session)
    plans: dict[str, int] = {}
    logged_in = 0
    enabled_count = 0
    regular_count = 0
    preparation_count = 0
    member_count = 0
    refunded_count = 0
    dead_count = 0
    member_plan_counts = {"go": 0, "plus": 0, "pro": 0, "team": 0}
    for row in rows:
        plan_type = _normalize_plan_type(row.plan_type)
        plans[plan_type] = plans.get(plan_type, 0) + 1
        category = _catalog_category(row)
        if category == "regular":
            if int(row.id or 0) in ready_ids:
                preparation_count += 1
            else:
                regular_count += 1
        elif category == "member":
            member_count += 1
            canonical = _canonical_member_plan(plan_type)
            if canonical:
                member_plan_counts[canonical] += 1
        else:
            refunded_count += 1
        if str(row.cookie_blob or "").strip() or row.cookie_updated_at is not None:
            logged_in += 1
        if bool(row.dangerous):
            dead_count += 1
        if row.enabled:
            enabled_count += 1
    return {
        "total": len(rows),
        "enabled": enabled_count,
        "disabled": len(rows) - enabled_count,
        "logged_in": logged_in,
        "not_logged_in": len(rows) - logged_in,
        "regular": regular_count,
        "preparation": preparation_count,
        "member": member_count,
        "refunded": refunded_count,
        "dead": dead_count,
        "member_plans": member_plan_counts,
        "plans": [
            {
                "plan_type": plan_type,
                "plan_label": _plan_label(plan_type),
                "count": count,
            }
            for plan_type, count in sorted(plans.items(), key=lambda item: item[0])
        ],
    }


@router.post("/accounts/backfill-card-last4-from-mail")
def backfill_plan_card_last4_from_mail(
    limit_per_account: int = Query(50, ge=1, le=50),
):
    """Best-effort card-suffix backfill over local paid plan rows only."""
    return _backfill_all_plan_card_last4(int(limit_per_account))


@router.get("/accounts/{account_id}/mail-credential-copy")
def copy_member_mail_credential(account_id: int, response: Response):
    """Return one paid Outlook account's login line for an explicit copy action.

    Passwords deliberately stay out of every account/list DTO.  This narrowly
    scoped endpoint resolves exactly one local directory id, rejects regular,
    refunded and Dead rows, and marks the secret-bearing response as
    non-cacheable.  The frontend copies the returned line directly and never
    stores it in page state.
    """
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if _catalog_category(account) != "member":
            raise HTTPException(409, "只有会员账号支持导出邮箱密码")
        if bool(account.dangerous):
            raise HTTPException(409, "Dead 账号不支持导出邮箱密码")
        from services.gmail_plan_support import account_mail_provider
        if account_mail_provider(account) != "outlook":
            raise HTTPException(409, "仅 Outlook 邮箱支持导出邮箱密码")
        email = str(account.email or "").strip()
        password = str(account.password or "").strip()
        if not email or not password:
            raise HTTPException(409, "该账号缺少 Outlook 邮箱或密码")
        return {"copy_text": f"{email}----{password}"}


@router.get("/accounts/{account_id}")
def get_account(account_id: int):
    from services.gpt_plan_preparation_store import preparation_ready_ids

    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        member_source = _member_source_map(session, [account]).get(int(account_id))
        result = _serialize_account(
            account,
            _get_upgrade_summary(session, account_id),
            member_source,
        )
        result["preparation_state"] = (
            "ready" if _catalog_category(account) == "regular"
            and account.business_parent_id is None
            and int(account_id) in preparation_ready_ids(session) else ""
        )
        return result


@router.get("/accounts/{account_id}/appeal-script")
def get_plan_appeal_script(account_id: int, response: Response):
    """Prepare a fill-only draft from the addressed Plan account, never submit."""
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if account is None:
            raise HTTPException(404, "套餐账号不存在")
        url = _safe_plan_appeal_url(account.appeal_url)
        if not url:
            detail = ("该账号尚无申诉链接，后台将自动查找，请稍后刷新"
                      if not str(account.appeal_url or "").strip()
                      else "该账号申诉链接无效，请重新查找安全的 HTTPS 链接")
            raise HTTPException(400, detail)
        summary = _get_upgrade_summary(session, account_id)
        subscribed = getattr(summary, "plan_upgraded_at", None) or account.subscribed_at
        deactivated = account.dangerous_detected_at
        email = str(account.email or "")

    def dates(value):
        if value is None:
            return "", ""
        day = value.date()
        return day.isoformat(), day.strftime("%m/%d/%Y")

    start_ymd, start_mdy = dates(subscribed)
    end_ymd, end_mdy = dates(deactivated)
    from platforms.chatgpt.appeal_form import build_appeal_fill_snippet

    snippet = build_appeal_fill_snippet({
        "email": email, "case_id": "",
        "start_ymd": start_ymd, "start_mdy": start_mdy,
        "end_ymd": end_ymd, "end_mdy": end_mdy,
    }, use_pro_config=False)
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True, "account_id": account_id, "account": email,
            "appeal_url": url, "dates": {"start": start_ymd, "end": end_ymd},
            "script": snippet["script"], "bookmarklet": snippet["bookmarklet"],
            "auto_submit": False}


@router.post("/accounts/{account_id}/mark-appealed")
def mark_plan_account_appealed(account_id: int, done: bool = Query(...)):
    """Record only the user's explicit submitted/unsubmitted declaration."""
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if account is None:
            raise HTTPException(404, "套餐账号不存在")
        value = (account.appeal_done_at or _utcnow()) if done else None
        if account.appeal_done_at != value:
            account.appeal_done_at = value
            account.updated_at = _utcnow()
            session.add(account)
            session.commit()
        return {"ok": True, "account_id": account_id, "account": account.email,
                "appeal_done_at": _iso_utc(account.appeal_done_at)}


def _plan_appeal_link_from_messages(messages):
    return extract_appeal_link(messages)


@router.post("/accounts/{account_id}/refresh-appeal-link")
def refresh_plan_account_appeal_link(account_id: int):
    """Read this Plan mailbox only and narrowly backfill its appeal URL."""
    from services.gpt_plan_appeals import lookup_appeal_link

    try:
        result = lookup_appeal_link(account_id, manual=True, database_engine=engine)
    except KeyError:
        raise HTTPException(404, "套餐账号不存在") from None
    except ValueError:
        raise HTTPException(400, "套餐账号编号无效") from None
    if result["ok"]:
        return result
    code = 502 if result.get("reason") == "error" else 400 if result.get("reason") == "not_found" else 409
    raise HTTPException(code, result["error"])


def _plan_security_account(account_id: int) -> GptPlanAccountModel:
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        # The detached object is used only for its immutable scalar snapshot.
        return account


@router.get("/accounts/{account_id}/security")
def get_plan_account_security_status(account_id: int):
    account = _plan_security_account(account_id)
    return _public_chatgpt_security_status(
        _chatgpt_security_status_for_email(account.email)
    )


def _require_plan_security_setup_access(request: Request) -> None:
    from api.auth import require_sensitive_mutation_auth_header
    from core.credential_crypto import CredentialKeyError
    from services.chatgpt_security_store import (
        ensure_chatgpt_security_store_ready,
    )

    require_sensitive_mutation_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    try:
        ensure_chatgpt_security_store_ready()
    except CredentialKeyError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "ChatGPT 安全凭据加密仓库未就绪；请检查 "
                "APP_CREDENTIAL_ENCRYPTION_KEY 或本地密钥文件"
            ),
        ) from exc


def _append_plan_security_log(
    task_id: str,
    message: Any,
    *secrets: str,
) -> None:
    from api.tasks import _task_store

    safe = _redact_text(message, *secrets)
    _task_store.append_log(task_id, f"[{time.strftime('%H:%M:%S')}] {safe}")


def _plan_security_platform_account(
    account: GptPlanAccountModel,
    *,
    require_setup_capability: bool = False,
) -> tuple[Any, list[str]]:
    """Build the narrow platform adapter without mixing two passwords.

    ``GptPlanAccountModel.password`` is the Outlook mailbox password.  A
    ChatGPT password comes only from the encrypted store or is newly generated
    for this setup attempt; the mailbox password is namespaced in ``extra``.
    """
    from core.base_platform import Account
    from platforms.chatgpt.account_security import (
        _parse_cookie_payload,
        _session_cookie_from_map,
    )
    from platforms.chatgpt.utils import generate_random_password
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets,
        get_chatgpt_security_status,
    )

    status = get_chatgpt_security_status(account.email)
    if require_setup_capability:
        capabilities = _business_child_account_capabilities(
            account,
            chatgpt_security=status,
        )
        if not capabilities["can_setup_chatgpt_security"]:
            raise RuntimeError(
                capabilities["chatgpt_security_setup_disabled_reason"]
                or "子号当前不能设置密码与 2FA"
            )
    stored_password = ""
    if bool(status.get("has_password")):
        stored_password = str(
            get_chatgpt_security_secrets(account.email).get("password") or ""
        )
        if not stored_password:
            raise RuntimeError("已保存的 ChatGPT 密码为空，无法继续安全设置")
    elif str(status.get("password_state") or "").strip().lower() == "configured":
        raise RuntimeError("ChatGPT 密码状态与加密凭据不一致，无法继续安全设置")

    mailbox_password = str(account.password or "")
    chatgpt_password = stored_password or generate_random_password()
    # Keep the domains separate even under a deterministic/test generator.
    if not stored_password and chatgpt_password == mailbox_password:
        chatgpt_password = generate_random_password()
    if not chatgpt_password or (
        not stored_password and chatgpt_password == mailbox_password
    ):
        raise RuntimeError("无法生成独立的 ChatGPT 登录密码")

    cookies = _parse_cookie_payload(account.cookie_blob)
    session_token = _session_cookie_from_map(cookies)
    from services.gmail_plan_support import account_mail_provider
    provider = account_mail_provider(account)
    extra: Dict[str, Any] = {
        "mail_provider": provider,
        "provider": provider,
        "cookies": str(account.cookie_blob or ""),
        "session_token": session_token,
        "password_set_proven": (
            str(status.get("password_state") or "").strip().lower()
            == "configured"
        ),
        "graph_immutable_ids": True,
    }
    if provider == "gmail":
        from services.gmail_plan_support import gmail_binding_extra
        extra.update(gmail_binding_extra(account))
    if provider == "outlook":
        extra.update({
            "outlook_mail_password": mailbox_password,
            "outlook_mail_client_id": str(account.client_id or ""),
            "outlook_mail_refresh_token": str(account.refresh_token or ""),
            "outlook_mail_access_type": str(account.mail_access_type or ""),
        })

    return (
        Account(
            platform="chatgpt",
            email=str(account.email or ""),
            password=chatgpt_password,
            user_id=str(account.chatgpt_user_id or ""),
            extra=extra,
        ),
        [
            chatgpt_password,
            mailbox_password,
            str(account.client_id or ""),
            str(account.refresh_token or ""),
            str(account.cookie_blob or ""),
            session_token,
        ],
    )


def _merged_cookie_blob_from_security_patch(
    existing_value: Any,
    refreshed_value: Any,
) -> str:
    from platforms.chatgpt.account_security import _parse_cookie_payload

    cookies = _parse_cookie_payload(existing_value)
    cookies.update(_parse_cookie_payload(refreshed_value))
    return "; ".join(
        f"{name}={cookie_value}"
        for name, cookie_value in cookies.items()
        if str(name).strip() and str(cookie_value)
    )


@dataclass(frozen=True)
class _BusinessChildSecurityTarget:
    """Immutable ownership lease for one BUSINESS child security task."""

    binding: _MemberSourceBinding
    membership_id: int
    child_id: int
    normalized_email: str


def _assert_business_child_security_membership_snapshot(
    session: Session,
    target: _BusinessChildSecurityTarget,
    *,
    require_healthy: bool = True,
) -> GptPlanAccountModel:
    """Recheck exact mother/child ownership inside the persistence session.

    This deliberately duplicates only scalar identity checks, not the child
    action policy. The public routes obtain the target through the established
    managed-child resolver; this second check closes the long-running browser
    race before a refreshed session is committed.
    """
    plan_parent = session.get(
        GptPlanAccountModel,
        int(target.binding.plan_account_id),
    )
    source_parent = session.get(
        GptBusinessAccountModel,
        int(target.binding.source_account_id),
    )
    membership = session.get(
        GptBusinessChildMembershipModel,
        int(target.membership_id),
    )
    child = session.get(GptPlanAccountModel, int(target.child_id))
    identity_valid = bool(
        plan_parent is not None
        and source_parent is not None
        and membership is not None
        and child is not None
        and _catalog_category(plan_parent) == "member"
        and str(plan_parent.source_pool or "").strip().lower()
        == "gpt_business"
        and int(plan_parent.source_account_id or 0)
        == int(target.binding.source_account_id)
        and _normalized_email(plan_parent.email)
        == target.binding.normalized_email
        and _normalized_email(source_parent.email)
        == target.binding.normalized_email
        and int(membership.business_account_id)
        == int(target.binding.source_account_id)
        and int(membership.pro_account_id or 0) == int(target.child_id)
        and membership.ended_at is None
        and str(membership.source or "").strip().lower() == "pool"
        and _normalized_email(membership.email) == target.normalized_email
        and int(child.business_parent_id or 0)
        == int(target.binding.source_account_id)
        and _normalized_email(child.email) == target.normalized_email
    )
    if not identity_valid:
        raise HTTPException(409, "安全设置期间子号归属发生变化")
    if require_healthy and not bool(
        child.enabled
        and not child.dangerous
        and not child.policy_warning
        and not str(child.refund_status or "").strip()
    ):
        raise HTTPException(409, "子号已停用、告警或进入退款流程")
    return child


def _run_plan_security_setup_task(
    task_id: str,
    account_id: int,
    *,
    browser_mode: str,
    proxy: str,
    business_child_target: Optional[_BusinessChildSecurityTarget] = None,
    child_operation_token: str = "",
    verified_unsubmitted_password: Any = None,
) -> None:
    from api.tasks import _task_store

    _task_store.mark_running(task_id)
    secrets: list[str] = [proxy]
    latest_security_progress: dict[str, Any] | None = None

    def progress_fn(value: Any) -> None:
        nonlocal latest_security_progress
        from services.chatgpt_security_progress import normalize_security_progress

        if not isinstance(value, dict):
            return
        clean = normalize_security_progress({
            **value,
            "reason": _redact_text(value.get("reason") or "", *secrets),
        })
        if clean is not None and clean != latest_security_progress:
            _task_store.update_meta(task_id, {"security_progress": clean})
            latest_security_progress = clean

    progress_fn({
        "stage": "session_check", "status": "running", "code": "session_check",
        "reason": "正在检查登录会话与目标账号身份", "retry_mode": "none",
        "retry_attempt": 0, "retry_limit": 0, "completed_stages": [],
    })
    _append_plan_security_log(task_id, "开始设置 ChatGPT 密码与 Authenticator 2FA", proxy)
    try:
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, int(account_id))
            if not account:
                raise RuntimeError("账号不存在")
            if business_child_target is not None:
                account = _assert_business_child_security_membership_snapshot(
                    session,
                    business_child_target,
                )
            expected_email = _chatgpt_security_email_key(account.email)
            if not expected_email:
                raise RuntimeError("账号邮箱无效")
            business_binding = _capture_business_mother_login_binding(
                session,
                account,
            )
            platform_account, account_secrets = _plan_security_platform_account(
                account,
                require_setup_capability=business_child_target is not None,
            )
            secrets.extend(account_secrets)

        from core.base_platform import RegisterConfig
        from core.config_store import config_store
        from platforms.chatgpt.plugin import ChatGPTPlatform

        platform = ChatGPTPlatform(
            config=RegisterConfig(
                executor_type=(
                    "headed" if browser_mode == "headed" else "headless"
                ),
                proxy=proxy or None,
                extra=dict(config_store.get_all()),
            )
        )

        def log_fn(message: Any) -> None:
            _append_plan_security_log(task_id, message, *secrets)

        result = platform.execute_action(
            "setup_security",
            platform_account,
            {
                "browser_mode": browser_mode,
                "_log_fn": log_fn,
                "_progress_fn": progress_fn,
                "_confirmation_mode": "in_session",
                **({"_verified_unsubmitted_password": verified_unsubmitted_password}
                   if verified_unsubmitted_password is not None else {}),
            },
        )
        # The setup flow may have just generated a TOTP seed/recovery codes.
        # Add them to the final-result redaction set without ever placing them
        # in task metadata or an API DTO.
        try:
            from services.chatgpt_security_store import (
                get_chatgpt_security_secrets,
            )

            refreshed_secrets = get_chatgpt_security_secrets(expected_email)
            secrets.extend([
                str(refreshed_secrets.get("password") or ""),
                str(refreshed_secrets.get("totp_secret") or ""),
                *[
                    str(code or "")
                    for code in list(
                        refreshed_secrets.get("recovery_codes") or []
                    )
                ],
            ])
        except Exception:
            pass
        if isinstance(result, dict):
            result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
            result_security = result_data.get("security") if isinstance(result_data.get("security"), dict) else {}
            progress_fn(result_security.get("security_progress"))
        ok = bool(result.get("ok")) if isinstance(result, dict) else False
        patch = (
            result.get("account_extra_patch")
            if isinstance(result, dict)
            and isinstance(result.get("account_extra_patch"), dict)
            else {}
        )
        refreshed_cookie_blob = ""
        if patch.get("cookies"):
            refreshed_cookie_blob = _merged_cookie_blob_from_security_patch(
                platform_account.extra.get("cookies"),
                patch.get("cookies"),
            )

        # Browser automation may run for minutes. Re-resolve the immutable
        # membership lease even when the automation did not return cookies so
        # a moved/removed child can never be reported as a successful action
        # under its former mother.
        if business_child_target is not None:
            with Session(engine) as session:
                _assert_business_child_security_membership_snapshot(
                    session,
                    business_child_target,
                )

        if ok and refreshed_cookie_blob:
            now = _utcnow()
            with Session(engine) as session:
                account = session.get(GptPlanAccountModel, int(account_id))
                if not account:
                    raise RuntimeError("安全设置完成，但套餐账号已被删除")
                if business_child_target is not None:
                    account = _assert_business_child_security_membership_snapshot(
                        session,
                        business_child_target,
                    )
                if _chatgpt_security_email_key(account.email) != expected_email:
                    raise RuntimeError("安全设置期间账号邮箱发生变化，已停止写入 Cookie")
                # Merge against the row as it exists now, not only against
                # the browser-start snapshot. A concurrent successful login
                # may have refreshed unrelated tokens while this long task
                # was waiting on password/MFA screens.
                persisted_cookie_blob = _merged_cookie_blob_from_security_patch(
                    account.cookie_blob,
                    patch.get("cookies"),
                )
                account.cookie_blob = persisted_cookie_blob
                account.cookie_updated_at = now
                # The settings workflow returns cookie name/value pairs but no
                # authoritative expiry.  An unknown expiry is safer than
                # retaining the old session's timestamp.
                account.cookie_expires_at = None
                account.updated_at = now
                _sync_business_mother_login_cookie(
                    session,
                    account,
                    expected_binding=business_binding,
                    cookie_blob=persisted_cookie_blob,
                    cookie_expires_at=None,
                    updated_at=now,
                )
                session.add(account)
                session.commit()

        status = _public_chatgpt_security_status(
            _chatgpt_security_status_for_email(expected_email)
        )
        _task_store.update_meta(task_id, {"chatgpt_security": status})
        if ok:
            progress_fn({
                **(latest_security_progress or {}),
                "stage": "done", "status": "completed", "code": "security_complete",
                "reason": "密码与 Authenticator 2FA 已确认", "retry_mode": "none",
            })
            _append_plan_security_log(task_id, "密码与 Authenticator 2FA 设置完成", *secrets)
            _task_store.set_progress(task_id, "1/1")
            _task_store.finish(
                task_id,
                status="done",
                success=1,
                skipped=0,
                errors=[],
            )
            return

        error = _redact_text(
            (result or {}).get("error") if isinstance(result, dict) else "",
            *secrets,
        ) or "ChatGPT 密码与 Authenticator 2FA 设置失败"
        if not latest_security_progress or latest_security_progress.get("status") not in {"failed", "review"}:
            progress_fn({
                **(latest_security_progress or {"stage": "session_check"}),
                "status": "failed", "code": "security_failed", "reason": error,
                "retry_mode": "verify_first",
            })
        _append_plan_security_log(task_id, f"操作失败: {error}", *secrets)
        _task_store.finish(
            task_id,
            status="failed",
            success=0,
            skipped=0,
            errors=[error],
            error=error,
        )
    except Exception as exc:
        error = _redact_text(exc, *secrets) or "ChatGPT 安全设置执行异常"
        progress_fn({
            **(latest_security_progress or {"stage": "session_check"}),
            "status": "failed", "code": "security_failed", "reason": error,
            "retry_mode": "verify_first",
            # Source permission applies only to its own terminal failure, not
            # a later membership check or local persistence exception.
            "task_retry": {"strategy": "manual", "reason_code": "insufficient_evidence"},
        })
        _append_plan_security_log(task_id, f"操作异常: {error}", *secrets)
        try:
            status = _public_chatgpt_security_status(
                _chatgpt_security_status_for_email(
                    locals().get("expected_email", "")
                )
            )
            _task_store.update_meta(task_id, {"chatgpt_security": status})
        except Exception:
            pass
        _task_store.finish(
            task_id,
            status="failed",
            success=0,
            skipped=0,
            errors=[error],
            error=error,
        )
    finally:
        if child_operation_token:
            try:
                from api import gpt_plan_operations as gpt_pro

                gpt_pro._release_gpt_pro_account_operation(
                    int(account_id),
                    str(child_operation_token),
                )
            except Exception:
                # The lease expires on its own.  Never turn an already
                # terminal security result into a false failure merely because
                # best-effort cleanup raced with process shutdown.
                pass


def _run_claimed_plan_security_setup_task(
    task_id: str, account_id: int, *, browser_mode: str, proxy: str, operation_token: str,
) -> None:
    try:
        _run_plan_security_setup_task(task_id, account_id, browser_mode=browser_mode, proxy=proxy)
    finally:
        try:
            _release_plan_operation(account_id, operation_token)
        except Exception:
            # Cleanup must not replace the original task result or emit a raw
            # database exception containing an operation token.
            pass


@router.post("/accounts/{account_id}/security/setup/task")
def start_plan_account_security_setup(
    account_id: int,
    request: Request,
    body: Optional[GptPlanSecuritySetupTaskRequest] = None,
):
    _require_plan_security_setup_access(request)
    account = _plan_security_account(account_id)
    request_body = body or GptPlanSecuritySetupTaskRequest()
    params = dict(request_body.params or {})
    if request_body.browser_mode is not None:
        params["browser_mode"] = request_body.browser_mode
    if request_body.proxy is not None:
        params["proxy"] = request_body.proxy
    browser_mode = str(params.get("browser_mode") or "headless").strip().lower()
    if browser_mode not in {"headed", "headless"}:
        raise HTTPException(400, "browser_mode 只支持 headed 或 headless")
    proxy = _resolve_proxy(
        str(params.get("proxy") or "") if "proxy" in params else None
    )

    from api.tasks import _task_store

    task_id = (
        f"gpt_plan_setup_security_{int(account_id)}_"
        f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    )
    operation_token = _claim_plan_operation(int(account_id), "setup_security")
    task_created = False
    try:
        _task_store.create(
            task_id,
            platform="chatgpt",
            total=1,
            source="gpt_plan_security",
            meta={
                "action_id": "setup_security",
                "account_id": int(account_id),
                "email": str(account.email or ""),
            },
        )
        task_created = True
        threading.Thread(
            target=_run_claimed_plan_security_setup_task,
            args=(task_id, int(account_id)),
            kwargs={
                "browser_mode": browser_mode,
                "proxy": proxy,
                "operation_token": operation_token,
            },
            daemon=True,
            name=f"gpt-plan-security-{account_id}-{task_id[-8:]}",
        ).start()
    except BaseException:
        if task_created:
            try:
                _task_store.finish(task_id, status="failed", success=0, skipped=0,
                                   errors=["安全设置执行线程未能启动，请重试"],
                                   error="安全设置执行线程未能启动，请重试")
            except Exception:
                pass
        _release_plan_operation(int(account_id), operation_token)
        raise
    return {"ok": True, "task_id": task_id}


@router.get("/accounts/{account_id}/security/setup/task/{task_id}")
def get_plan_account_security_setup_task(
    account_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    from api.tasks import _task_store

    if not _task_store.exists(str(task_id)):
        raise HTTPException(404, "安全设置任务不存在")
    snapshot = _task_store.snapshot(str(task_id))
    meta = snapshot.get("meta") if isinstance(snapshot.get("meta"), dict) else {}
    if (
        snapshot.get("source") != "gpt_plan_security"
        or str(meta.get("action_id") or "") != "setup_security"
        or int(meta.get("account_id") or 0) != int(account_id)
    ):
        raise HTTPException(404, "安全设置任务不存在")
    logs = snapshot.get("logs") if isinstance(snapshot.get("logs"), list) else []
    logs_total = len(logs)
    logs_offset = min(int(since), logs_total)
    snapshot["logs"] = logs[logs_offset:]
    snapshot["logs_offset"] = logs_offset
    snapshot["logs_total"] = logs_total
    snapshot["since"] = logs_total
    return snapshot


@router.post("/accounts/{account_id}/security/export")
def export_plan_account_security_credentials(
    account_id: int,
    request: Request,
):
    from api.auth import require_sensitive_credential_export_auth_header

    require_sensitive_credential_export_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    account = _plan_security_account(account_id)
    return _plan_security_export_response(account)


def _plan_security_export_response(
    account: GptPlanAccountModel,
) -> Response:
    """Produce the one guarded secret-bearing response shared by Plan rows."""
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets,
        get_chatgpt_security_status,
    )

    try:
        secret = get_chatgpt_security_secrets(account.email)
        status = get_chatgpt_security_status(account.email)
    except Exception as exc:
        raise HTTPException(409, "安全凭据无法解密") from exc
    password = str(secret.get("password") or "")
    totp_secret = str(secret.get("totp_secret") or "")
    if (
        not password
        or not totp_secret
        or status.get("password_state") != "configured"
        or status.get("mfa_state") != "enabled"
    ):
        raise HTTPException(409, "密码或 Authenticator 2FA 尚未完成远端确认")
    safe_name = (
        re.sub(r"[^A-Za-z0-9._-]+", "_", str(account.email or ""))
        .strip("._")
        or "chatgpt"
    )
    return Response(
        content=f"{account.email}--{password}--{totp_secret}\n",
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{safe_name}_2fa.txt"'
            ),
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _update_plan_account_note(
    session: Session,
    account: GptPlanAccountModel,
    note: Any,
) -> None:
    """Persist one locally authoritative note.

    BUSINESS mothers keep their explicit workspace delegation, so their parent
    display note is updated atomically as well.  All other accounts write only
    the plan table and can never be overwritten by a retired synchronization.
    """
    normalized_note = str(note or "")
    if len(normalized_note) > 1000:
        raise HTTPException(400, "备注不能超过 1000 个字符")

    category = _catalog_category(account)
    source_pool = str(account.source_pool or "").strip()
    source_id = int(account.source_account_id or 0)
    business_bound_member = bool(
        category == "member" and source_pool == "gpt_business"
    )
    if business_bound_member:
        if source_id <= 0:
            raise HTTPException(409, "BUSINESS 母号绑定不完整")
        source = session.get(GptBusinessAccountModel, source_id)
        source_is_sync_eligible = bool(
            source
            and str(source.refund_status or "").strip()
            != "refunded_pending_credit"
        )
        if (
            not source_is_sync_eligible
            or source is None
            or _normalized_email(source.email) != _normalized_email(account.email)
        ):
            raise HTTPException(409, "BUSINESS 母号身份已变化，请刷新席位")
        source.note = normalized_note
        source.updated_at = _utcnow()
        session.add(source)
    account.note = normalized_note
    account.updated_at = _utcnow()
    session.add(account)


@router.put("/accounts/{account_id}/note")
@router.patch("/accounts/{account_id}/note")
def update_account_note(account_id: int, body: GptPlanAccountNoteRequest):
    """Update exactly one account note; never accepts or returns credentials."""
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        _update_plan_account_note(session, account, body.note)
        session.commit()
        session.refresh(account)
        member_source = _member_source_map(session, [account]).get(int(account_id))
        return _serialize_account(
            account,
            _get_upgrade_summary(session, account_id),
            member_source,
        )


def _require_business_usage_target(
    session: Session,
    account: GptPlanAccountModel,
) -> GptBusinessAccountModel:
    """Resolve an exact live BUSINESS-mother binding for catalog metadata."""
    source_pool = str(account.source_pool or "").strip().lower()
    source_id = int(account.source_account_id or 0)
    if not (
        _catalog_category(account) == "member"
        and _canonical_member_plan(account.plan_type) == "team"
        and source_pool == "gpt_business"
        and source_id > 0
    ):
        raise HTTPException(409, "只有 BUSINESS 母号可以设置账号用途")
    source = session.get(GptBusinessAccountModel, source_id)
    if (
        source is None
        or _normalized_email(source.email) != _normalized_email(account.email)
    ):
        raise HTTPException(409, "BUSINESS 母号绑定已变化，请刷新后重试")
    return source


@router.put("/accounts/{account_id}/business-usage")
@router.patch("/accounts/{account_id}/business-usage")
def update_business_usage(
    account_id: int,
    body: GptPlanBusinessUsageRequest,
):
    """Set or clear one BUSINESS mother's sale/self-use/transit classification."""
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        _require_business_usage_target(session, account)
        normalized = _public_business_usage_type(body.business_usage_type)
        account.business_usage_type = normalized or ""
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        member_source = _member_source_map(session, [account]).get(int(account_id))
        return _serialize_account(
            account,
            _get_upgrade_summary(session, account_id),
            member_source,
        )


@router.put("/accounts/{account_id}")
def update_account(account_id: int, body: GptPlanAccountUpdateRequest):
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        if _catalog_category(account) == "regular":
            from services.workspace_accounts import bind_gmail_plan
            from services.gmail_store import GmailStoreError
            if body.mail_provider is not None and body.mail_provider != "gmail":
                raise HTTPException(400, "普通账号仅支持 Gmail 子号")
            if body.client_id or body.refresh_token or body.mail_access_type not in {None, "", "imap"}:
                raise HTTPException(400, "Gmail 子号通过母号收件，不接受其他邮箱授权资料")
            if body.password is not None:
                raise HTTPException(400, "请通过普通账号导入入口更新加密的 GPT 密码")
            try:
                bind_gmail_plan(session, account)
            except GmailStoreError as exc:
                raise HTTPException(exc.status_code, exc.message) from None
        if body.password is not None:
            account.password = body.password
        if body.client_id is not None:
            account.client_id = body.client_id
        if body.refresh_token is not None:
            account.refresh_token = body.refresh_token
        if body.mail_access_type is not None:
            mail_type = str(body.mail_access_type or "").strip().lower()
            if mail_type not in {"", "graph", "imap_pop", "imap"}:
                raise HTTPException(400, "mail_access_type 只支持 graph/imap_pop/空")
            account.mail_access_type = mail_type
        if body.mail_provider is not None:
            account.mail_provider = _normalize_mail_provider(body.mail_provider)
        if body.note is not None:
            _update_plan_account_note(session, account, body.note)
        if body.enabled is not None:
            account.enabled = bool(body.enabled)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        member_source = _member_source_map(session, [account]).get(int(account_id))
        return _serialize_account(
            account,
            _get_upgrade_summary(session, account_id),
            member_source,
        )


@router.delete("/accounts/{account_id}")
def delete_account(account_id: int):
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        lease = session.get(GptPlanAccountOperationLeaseModel, int(account_id))
        if lease and (_aware_utc(lease.expires_at) or _utcnow()) > _utcnow():
            raise HTTPException(409, f"账号正在执行 {lease.operation}，不能删除")
        # 升级摘要和租约都是套餐池私有数据。删除账号时显式
        # 清理，不依赖 SQLite 是否开启外键 cascade。
        session.exec(
            sa_delete(GptPlanAccountUpgradeModel).where(
                GptPlanAccountUpgradeModel.account_id == int(account_id)
            )
        )
        session.exec(
            sa_delete(GptPlanAccountOperationLeaseModel).where(
                GptPlanAccountOperationLeaseModel.account_id == int(account_id)
            )
        )
        session.delete(account)
        session.commit()
    return {"ok": True, "id": account_id}


@router.get("/accounts/{account_id}/member-capabilities")
def member_capabilities(account_id: int):
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if _catalog_category(account) not in {"member", "refunded"}:
            raise HTTPException(409, "只有会员或已退款账号支持该操作")
        member_source = _member_source_map(session, [account]).get(int(account_id))
        if member_source is None:
            member_source = _missing_member_source(
                account,
                "会员账号的本地操作状态不完整",
            )
        return {
            "ok": True,
            "account_id": int(account_id),
            "member_source": member_source,
            "capabilities": member_source["capabilities"],
        }


@router.post("/accounts/{account_id}/business-workspace/refresh")
def refresh_member_business_workspace(account_id: int):
    """Refresh one bound BUSINESS workspace and return only facade allow-lists."""
    binding, member_source = _resolve_member_source_binding(account_id)
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "只有 GPT BUSINESS 母号支持刷新工作区")
    from services.business_session_health import ensure_session
    ensure_session(int(binding.source_account_id))
    member_source = _assert_member_source_binding_current(binding)
    workspace = member_source.get("business_workspace")
    workspace = workspace if isinstance(workspace, dict) else {}
    if not bool(workspace.get("team_session_usable")):
        reason = str(workspace.get("team_session_reason") or "invalid_access_token")
        raise HTTPException(
            409,
            _BUSINESS_TEAM_SESSION_REASON_MESSAGES.get(
                reason,
                "BUSINESS 母号 Team 登录会话不可用",
            ),
        )

    # The source response contains member rows and is intentionally discarded.
    # Only a newly resolved member_source allow-list crosses the facade boundary.
    from api.gpt_business import workspace_members

    source_result = workspace_members(int(binding.source_account_id))
    source_result = source_result if isinstance(source_result, dict) else {}
    current = _assert_member_source_binding_current(binding)
    fresh = bool(source_result.get("fresh")) and not bool(source_result.get("cached"))
    return {
        "ok": fresh,
        "fresh": fresh,
        "stale": not fresh,
        "error": (
            "" if fresh else str(
                source_result.get("warning")
                or "BUSINESS 工作区远端刷新失败，已保留数据库快照"
            )[:300]
        ),
        "account_id": int(account_id),
        "member_source": current,
        "business_workspace": current.get("business_workspace"),
    }


@router.post("/accounts/{account_id}/business-payment-method/refresh")
def refresh_member_business_default_payment(account_id: int):
    """Read the remote default only; never modify a payment method or checkout."""
    binding, _ = _resolve_member_source_binding(account_id)
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "只有 BUSINESS 母号支持读取默认支付方式")
    from services.business_default_payment import refresh_default_payment
    refresh_default_payment(int(binding.source_account_id), expected_plan_id=int(account_id))
    current = _assert_member_source_binding_current(binding)
    # A login/workspace change can happen after persistence but before facade
    # serialization. Use the current identity-bound DTO, never the old result.
    workspace = current.get("business_workspace") or {}
    method = workspace.get("default_payment_method")
    if not isinstance(method, dict):
        raise HTTPException(409, "母号数据已更新，请重新刷新默认支付方式")
    return {"ok": method["status"] in {"ready", "none"}, "default_payment_method": method,
            "member_source": current, "error": method["error"]}


@router.post("/accounts/{account_id}/business-session/check")
def check_member_business_session(account_id: int):
    """Check/renew one mother's session, without reconciling any members."""
    binding, _ = _resolve_member_source_binding(account_id)
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "只有 BUSINESS 母号支持检查会话")
    from services.business_session_health import check_session
    health = check_session(int(binding.source_account_id), force=True)
    current = _assert_member_source_binding_current(binding)
    if health is None:
        raise HTTPException(409, "BUSINESS 母号绑定已变化，请刷新后重试")
    return {"ok": health["status"] == "valid", "session_health": health,
            "member_source": current,
            "error": "" if health["status"] == "valid" else health["message"]}


@router.post("/accounts/{account_id}/business-workspace/referrals")
def update_member_business_workspace_referrals(
    account_id: int,
    body: GptPlanBusinessWorkspaceReferralsRequest,
):
    """Write the real Workspace setting through the safe BUSINESS facade."""
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
        preflight_session=True,
    )
    from api.gpt_business import (
        BizWorkspaceReferralsRequest,
        update_workspace_referrals_enabled,
    )

    # The source endpoint owns the durable parent lease, the fixed outbound URL
    # and the mandatory GET-after-POST confirmation.  Do not forward its raw
    # response; rebuild the public result from the persisted facade allow-list.
    update_workspace_referrals_enabled(
        int(binding.source_account_id),
        BizWorkspaceReferralsRequest(value=body.enabled),
    )
    current = _assert_member_source_binding_current(binding)
    workspace = current.get("business_workspace")
    workspace = workspace if isinstance(workspace, dict) else {}
    confirmed = workspace.get("workspace_referrals_enabled")
    if not isinstance(confirmed, bool) or confirmed is not body.enabled:
        raise HTTPException(502, {
            "code": "business_workspace_referrals_persistence_unconfirmed",
            "message": (
                "Workspace 推荐邀请设置已请求，但数据库回读未确认；"
                "请刷新成员/席位后重试"
            ),
        })
    visible = workspace.get("workspace_referrals_enabled_visible")
    visible = visible if isinstance(visible, bool) else None
    checked_at = _safe_business_time(
        workspace.get("workspace_referrals_enabled_checked_at")
    )
    return {
        "ok": True,
        "account_id": int(account_id),
        # ``enabled`` is retained as a compact mutation acknowledgement while
        # the canonical persisted field remains available to table clients.
        "enabled": confirmed,
        "workspace_referrals_enabled": confirmed,
        "workspace_referrals_enabled_visible": visible,
        "workspace_referrals_enabled_checked_at": checked_at,
        "member_source": current,
        "business_workspace": workspace,
    }


@router.get("/accounts/{account_id}/business-children")
def member_business_children(account_id: int):
    """Return the BUSINESS expansion panel from persisted normalized rows only."""
    binding, _member_source = _business_child_facade_binding(account_id)
    return _business_children_snapshot(binding)


_BUSINESS_CHILD_WARRANTY_MAX_HOURS = 24 * 365 * 10


def _business_parent_binding_query():
    """Return exact GPT Plan directory -> BUSINESS source identity bindings."""
    return (
        select(GptPlanAccountModel, GptBusinessAccountModel)
        .join(
            GptBusinessAccountModel,
            GptBusinessAccountModel.id
            == GptPlanAccountModel.source_account_id,
        )
        .where(
            func.lower(func.trim(func.coalesce(
                GptPlanAccountModel.source_pool,
                "",
            ))) == "gpt_business",
            GptPlanAccountModel.source_account_id.is_not(None),  # type: ignore[union-attr]
            func.lower(func.trim(GptBusinessAccountModel.email))
            == func.lower(func.trim(GptPlanAccountModel.email)),
        )
    )


def _business_parent_directory_query():
    """Return exact bindings whose parent is in the active member directory."""
    plan_expr = func.lower(func.trim(func.coalesce(
        GptPlanAccountModel.plan_type,
        "",
    )))
    return (
        _business_parent_binding_query()
        .where(
            _catalog_category_predicate("member"),
            plan_expr.in_(tuple(_MEMBER_PLAN_TYPES["team"])),
        )
    )


def _business_parent_source_ids_query(
    *,
    parent_account_id: int = 0,
    business_usage_type: str = "all",
):
    """Return source mother ids for the child-dimension catalogue.

    ``/accounts`` keeps its historical all-usage default.  The child catalogue
    passes an explicit usage scope so changing the child-view default cannot
    silently alter the mother catalogue or the per-mother expansion endpoint.
    """
    query = _business_parent_directory_query()
    if parent_account_id > 0:
        query = query.where(GptPlanAccountModel.id == int(parent_account_id))
    if business_usage_type == "unassigned":
        query = query.where(
            or_(
                GptPlanAccountModel.business_usage_type.is_(None),  # type: ignore[union-attr]
                GptPlanAccountModel.business_usage_type == "",
                ~GptPlanAccountModel.business_usage_type.in_(  # type: ignore[union-attr]
                    tuple(_BUSINESS_USAGE_TYPES)
                ),
            )
        )
    elif business_usage_type in _BUSINESS_USAGE_TYPES:
        query = query.where(
            GptPlanAccountModel.business_usage_type == business_usage_type
        )
    return query.with_only_columns(GptPlanAccountModel.source_account_id)


def _business_child_display_name(
    child: Optional[GptPlanAccountModel],
    _email: str,
) -> str:
    """Read only explicit harmless profile-name keys from account metadata."""
    if child is not None:
        extra = _safe_json_object(child.extra_json)
        for key in ("display_name", "profile_name", "full_name", "name"):
            value = _sanitize_member_task_text(extra.get(key) or "")[:120]
            if value:
                return value
    # The UI always renders email on its own line. Returning it again as a
    # synthetic name would make nearly every legacy child appear duplicated.
    return ""


def _business_child_warranty_snapshot(
    membership: GptBusinessChildMembershipModel,
) -> dict[str, Any]:
    sold_at = _aware_utc(getattr(membership, "sold_at", None))
    raw_sale_status = str(getattr(membership, "sale_status", "") or "").strip().lower()
    sale_status = (
        raw_sale_status
        if raw_sale_status in _BUSINESS_CHILD_SALE_STATUSES
        else "sold" if sold_at is not None else "unlisted"
    )
    raw_hours = getattr(membership, "warranty_hours", 0)
    warranty_hours = (
        int(raw_hours)
        if isinstance(raw_hours, int)
        and not isinstance(raw_hours, bool)
        and 0 <= int(raw_hours) <= _BUSINESS_CHILD_WARRANTY_MAX_HOURS
        else 0
    )
    absolute_until = _aware_utc(getattr(membership, "nv_team5x_warranty_until", None))
    warranty_until = absolute_until or (
        sold_at + timedelta(hours=warranty_hours)
        if sold_at is not None and warranty_hours > 0
        else None
    )
    now = _utcnow()
    if sale_status == "refunded":
        status = "refunded"
    elif sale_status == "partial_refund":
        status = "partial_refund"
    elif sold_at is None:
        status = "not_sold"
    elif warranty_hours <= 0 and absolute_until is None:
        status = "no_warranty"
    elif warranty_until is not None and warranty_until > now:
        status = "active"
    else:
        status = "expired"
    remaining_seconds = (
        max(0, int((warranty_until - now).total_seconds()))
        if warranty_until is not None and sale_status != "refunded"
        else 0
    )
    deletion_ready = bool(
        sale_status == "sold"
        and sold_at is not None
        and (warranty_hours > 0 or absolute_until is not None)
        and warranty_until is not None
        and warranty_until <= now
    )
    return {
        "sale_status": sale_status,
        "sold_at": _iso_utc(sold_at),
        "warranty_hours": warranty_hours,
        "nv_team5x_warranty_until": _iso_utc(absolute_until),
        # Keep one canonical name plus a compatibility alias for clients which
        # used the wording from the first UI design.
        "warranty_until": _iso_utc(warranty_until),
        "warranty_expires_at": _iso_utc(warranty_until),
        "warranty_status": status,
        "warranty_remaining_seconds": remaining_seconds,
        # 这是只读的生命周期结论，不会自动删除账号或归属记录。
        "deletion_ready": deletion_ready,
        "can_delete": deletion_ready,
        "nv_listed_at": _iso_utc(
            _aware_utc(getattr(membership, "nv_listed_at", None))
        ),
        "nv_listing_confirmed_at": _iso_utc(
            _aware_utc(getattr(membership, "nv_listing_confirmed_at", None))
        ),
        "nv_last_synced_at": _iso_utc(
            _aware_utc(getattr(membership, "nv_last_synced_at", None))
        ),
        "nv_remote_card_id": _safe_business_remote_identifier(
            getattr(membership, "nv_remote_card_id", "")
        ),
        "nv_remote_order_id": _safe_business_remote_identifier(
            getattr(membership, "nv_remote_order_id", "")
        ),
    }


def _business_child_parent_management_capability(
    parent: GptPlanAccountModel,
    source_parent: GptBusinessAccountModel,
) -> dict[str, Any]:
    """Compute only the parent admission needed by child row actions.

    ``_business_member_workspace`` also calculates quota presentation data and
    opens a session for every mother.  A child catalog page only needs session
    health and cooldown, so avoid turning a 500-row page into an N+1 quota
    query while retaining the established capability policy.
    """
    from api.gpt_business import _business_account_team_session_status

    raw_session = _business_account_team_session_status(source_parent)
    session_reason = str(raw_session.get("reason") or "invalid_access_token")
    if session_reason not in _BUSINESS_TEAM_SESSION_REASON_MESSAGES:
        session_reason = "invalid_access_token"
    workspace = {
        "team_session_usable": bool(raw_session.get("usable")),
        "team_session_reason": session_reason,
        "invite_cooldown": _safe_business_invite_cooldown(source_parent),
    }
    return _live_member_capabilities(
        parent,
        source_parent,
        source_pool="gpt_business",
        business_workspace=workspace,
    ).get("business_children") or _member_capability(
        False,
        "母号当前不可操作",
    )


def _business_child_dimension_item(
    membership: GptBusinessChildMembershipModel,
    child: Optional[GptPlanAccountModel],
    parent: GptPlanAccountModel,
    source_parent: GptBusinessAccountModel,
    *,
    chatgpt_security: Optional[dict[str, Any]] = None,
    parent_child_capability: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Serialize one active child relation without crossing credential data."""
    email = _safe_business_child_email(membership.email)
    user_id = _safe_business_remote_identifier(membership.remote_user_id)
    invite_id = _safe_business_remote_identifier(membership.remote_invite_id)
    membership_status = "member" if user_id else "invite" if invite_id else "local"
    managed = bool(
        child is not None
        and str(membership.source or "").strip().lower() == "pool"
        and int(membership.pro_account_id or 0) == int(child.id or 0)
        and int(getattr(child, "business_parent_id", None) or 0)
        == int(membership.business_account_id)
        and _normalized_email(child.email) == email
    )
    child_id = int(child.id or 0) if managed and child is not None else 0
    security = (
        _public_chatgpt_security_status(chatgpt_security)
        if managed
        else {
            **_public_chatgpt_security_status({}),
            "last_error": "",
        }
    )
    account_capabilities = (
        _business_child_account_capabilities(
            child,
            # Admission uses the original evidence: public DTO defaults must
            # not manufacture an explicit missing-seed/readability proof.
            chatgpt_security=(
                chatgpt_security if isinstance(chatgpt_security, dict)
                else _unavailable_chatgpt_security_status()
            ),
        )
        if managed and child is not None
        else {
            "mail_provider": "",
            "mail_access_type": "",
            "has_password": False,
            "has_mail_oauth": False,
            "has_mail_credentials": False,
            "chatgpt_auth_mode": "unavailable",
            "chatgpt_security_credentials_ready": False,
            "chatgpt_oauth_credentials_ready": False,
            "chatgpt_oauth_disabled_reason": "手动邮箱子号没有本地登录凭据",
            "chatgpt_security": security,
            "has_cookie": False,
            "has_saved_login": False,
            "cookie_valid": None,
            "cookie_updated_at": "",
            "cookie_expires_at": "",
            "login_status": "not_available",
            "can_chatgpt_login": False,
            "chatgpt_login_disabled_reason": "手动邮箱子号没有本地登录凭据",
            "can_setup_chatgpt_security": False,
            "chatgpt_security_setup_disabled_reason": "手动邮箱子号没有可管理的本地安全凭据",
            "chatgpt_security_setup_recovery_hint": "",
            "can_review_chatgpt_login": False,
            "chatgpt_login_review_disabled_reason": "手动邮箱子号没有本地登录凭据",
            "can_fetch_mail": False,
            "fetch_mail_disabled_reason": "手动邮箱子号没有本地邮件凭据",
        }
    )
    parent_child_capability = (
        parent_child_capability
        if isinstance(parent_child_capability, dict)
        else _business_child_parent_management_capability(parent, source_parent)
    )
    parent_allows_child_actions = bool(parent_child_capability.get("supported"))
    parent_action_reason = str(parent_child_capability.get("reason") or "")
    healthy_managed = bool(
        managed
        and child is not None
        and child.enabled
        and not child.dangerous
        and not child.policy_warning
        and not str(child.refund_status or "").strip()
    )
    has_codex_rt = bool(
        managed and child is not None
        and str(child.codex_refresh_token or "").strip()
    )
    has_complete_codex_credentials = bool(
        has_codex_rt
        and child is not None
        and str(child.codex_access_token or "").strip()
        and str(child.codex_id_token or "").strip()
    )
    has_remote_identity = bool(user_id or invite_id)
    can_get_rt = bool(
        healthy_managed
        and has_remote_identity
        and parent_allows_child_actions
        and account_capabilities.get("chatgpt_oauth_credentials_ready")
    )
    rt_reason = (
        ""
        if can_get_rt
        else parent_action_reason
        if not parent_allows_child_actions
        else "手动邮箱子号不支持获取 RT"
        if not managed
        else "子号缺少可确认的成员或邀请身份"
        if not has_remote_identity
        else str(
            account_capabilities.get("chatgpt_oauth_disabled_reason")
            or "子号当前状态不支持获取 RT"
        )
    )
    # Export is a local operation over an already-owned RT and the established
    # download route intentionally does not require a currently usable mother
    # session or another OTP login.  Device sync does require the mother's
    # child-management capability, so keep the two admission states separate.
    can_download_rt = bool(
        healthy_managed and has_remote_identity and has_codex_rt
    )
    can_sync_rt = bool(can_download_rt and parent_allows_child_actions)
    can_remove = bool(parent_allows_child_actions and has_remote_identity)
    remove_reason = (
        "" if can_remove else parent_action_reason
        if not parent_allows_child_actions else "子号缺少可确认的远端成员或邀请身份"
    )
    sale_snapshot = _business_child_warranty_snapshot(membership)
    nexusvault_security_ready = bool(
        security.get("credentials_readable", True)
        and security.get("has_password")
        and security.get("has_totp")
        and str(security.get("password_state") or "").strip().lower()
        == "configured"
        and str(security.get("mfa_state") or "").strip().lower()
        == "enabled"
    )
    can_list_nexusvault = bool(
        healthy_managed
        and membership_status == "member"
        and has_complete_codex_credentials
        and nexusvault_security_ready
        and sale_snapshot.get("sale_status") == "unlisted"
    )
    nexusvault_reason = (
        ""
        if can_list_nexusvault
        else "手动邮箱子号不能上架 NV"
        if not managed
        else "子号已停用、Dead、存在告警或处于退款流程"
        if not healthy_managed
        else "子号尚未成为 BUSINESS 正式成员"
        if membership_status != "member"
        else "子号缺少完整 OAuth/Sub2API 凭证，请先获取 RT"
        if not has_complete_codex_credentials
        else "子号需要先设置 ChatGPT 密码与 Authenticator 2FA"
        if not nexusvault_security_ready
        else "子号已经上架或出售"
    )
    empty_device_status = {
        "cpa": {
            "state": "unlinked",
            "cpa_synced_to": None,
            "cpa_disabled": False,
            "cpa_sync_pending": False,
        },
        "sub2api": {
            "state": "unlinked",
            "sub2api_synced_to": None,
            "sub2api_status": "unlinked",
            "sub2api_sync_pending": False,
        },
    }
    device_status = (
        _safe_business_child_device_snapshot(child)
        if managed and child is not None
        else empty_device_status
    )
    pending_alerts_count = (
        len(_safe_json_list(child.pending_alerts_json))
        if managed and child is not None else 0
    )
    pending_inbox_count = (
        len(_safe_json_list(child.pending_inbox_json))
        if managed and child is not None else 0
    )
    child_extra = (
        _safe_json_object(child.extra_json)
        if managed and child is not None else {}
    )
    monitor_enabled = bool(
        managed and child is not None and child.enabled
        and child_extra.get("business_child_monitor_enabled", True)
    )
    last_mail_error = (
        _redact_text(
            child.last_mail_check_error or "",
            child.password or "",
            child.client_id or "",
            child.refresh_token or "",
        )[:300]
        if managed and child is not None else ""
    )
    actions = {
        "login": _member_capability(
            bool(managed and account_capabilities.get("can_chatgpt_login")),
            str(account_capabilities.get("chatgpt_login_disabled_reason") or ""),
        ),
        "login_review": _member_capability(
            bool(managed and account_capabilities.get("can_review_chatgpt_login")),
            str(account_capabilities.get("chatgpt_login_review_disabled_reason") or ""),
        ),
        "fetch_mail": _member_capability(
            bool(managed and account_capabilities.get("can_fetch_mail")),
            str(account_capabilities.get("fetch_mail_disabled_reason") or ""),
        ),
        "security": _member_capability(
            bool(managed and account_capabilities.get("can_setup_chatgpt_security")),
            str(account_capabilities.get("chatgpt_security_setup_disabled_reason") or ""),
        ),
        "oauth": _member_capability(can_get_rt, rt_reason),
        "oauth_file": _member_capability(
            can_download_rt,
            "" if can_download_rt else "子号尚无可下载的有效 RT",
            formats=["cpa", "sub2api"],
        ),
        "sync_device": _member_capability(
            can_sync_rt,
            "" if can_sync_rt else parent_action_reason
            if can_download_rt and not parent_allows_child_actions
            else "子号尚无可同步的有效 RT",
            providers=["cpa", "sub2api"],
        ),
        "nexusvault_listing": {
            **_member_capability(can_list_nexusvault, nexusvault_reason),
            "warranty_hours": 1,
        },
        "remove": _member_capability(can_remove, remove_reason),
        # The child-centric view must never expose a second invitation entry.
        "invite": _member_capability(False, "子号视图不支持邀请新子号"),
    }
    return {
        "membership_id": int(membership.id or 0),
        "child_id": child_id or None,
        "pro_account_id": child_id or None,
        "child_email": email,
        "email": email,
        "child_name": _business_child_display_name(child if managed else None, email),
        "managed": managed,
        "source": (
            "pool"
            if str(membership.source or "").strip().lower() == "pool"
            else "manual"
        ),
        "parent_account_id": int(parent.id or 0),
        "parent_email": _safe_business_child_email(parent.email),
        "parent_note": _sanitize_member_task_text(parent.note or "")[:300],
        "seat_type": _safe_business_child_seat_type(membership.seat_type),
        "membership_status": membership_status,
        "status": membership_status,
        "user_id": user_id,
        "invite_id": invite_id,
        "invited_at": _iso_utc(membership.invited_at),
        **sale_snapshot,
        "chatgpt_security": security,
        "has_2fa": bool(security.get("has_totp")),
        "two_factor_status": str(security.get("mfa_state") or "unknown"),
        "has_codex_rt": has_codex_rt,
        "rt_supported": managed,
        "codex_rt_acquired_at": (
            _iso_utc(child.codex_rt_acquired_at)
            if managed and child is not None else ""
        ),
        "enabled": bool(child.enabled) if managed and child is not None else False,
        "dangerous": bool(child.dangerous) if managed and child is not None else False,
        "dead": bool(child.dangerous) if managed and child is not None else False,
        "policy_warning": (
            bool(child.policy_warning) if managed and child is not None else False
        ),
        "refund_status": (
            _public_refund_status(child.refund_status)
            if managed and child is not None else ""
        ),
        "account_capabilities": account_capabilities,
        "can_get_rt": can_get_rt,
        "cpa": device_status["cpa"],
        "cpa_synced_to": device_status["cpa"].get("cpa_synced_to"),
        "sub2api": device_status["sub2api"],
        "sub2api_synced_to": device_status["sub2api"].get(
            "sub2api_synced_to"
        ),
        "monitor_enabled": monitor_enabled,
        "last_mail_check_at": (
            _iso_utc(child.last_mail_check_at)
            if managed and child is not None else ""
        ),
        "last_mail_check_error": last_mail_error,
        "pending_alerts_count": pending_alerts_count,
        "pending_inbox_count": pending_inbox_count,
        "mail_monitor": {
            "supported": managed,
            "enabled": monitor_enabled,
            "monitor_enabled": monitor_enabled,
            "last_check_at": (
                _iso_utc(child.last_mail_check_at)
                if managed and child is not None else ""
            ),
            "last_mail_check_at": (
                _iso_utc(child.last_mail_check_at)
                if managed and child is not None else ""
            ),
            "last_error": last_mail_error,
            "last_mail_check_error": last_mail_error,
            "pending_alerts_count": pending_alerts_count,
            "pending_inbox_count": pending_inbox_count,
        },
        "actions": actions,
    }


def _business_child_dimension_rows(
    session: Session,
    *,
    page: int,
    page_size: int,
    keyword: str = "",
    parent_account_id: int = 0,
    business_usage_type: str = "sale",
    two_factor_status: str = "all",
    rt_status: str = "all",
    sale_status: str = "all",
) -> tuple[int, list[tuple[
    GptBusinessChildMembershipModel,
    Optional[GptPlanAccountModel],
]]]:
    """Query active children with DB-side filtering, counting and pagination."""
    child_join = and_(
        GptPlanAccountModel.id
        == GptBusinessChildMembershipModel.pro_account_id,
        func.lower(func.trim(func.coalesce(
            GptBusinessChildMembershipModel.source,
            "",
        ))) == "pool",
        GptPlanAccountModel.business_parent_id
        == GptBusinessChildMembershipModel.business_account_id,
        func.lower(func.trim(GptPlanAccountModel.email))
        == func.lower(func.trim(GptBusinessChildMembershipModel.email)),
    )
    parent_ids = _business_parent_source_ids_query(
        parent_account_id=parent_account_id,
        business_usage_type=business_usage_type,
    )
    conditions: list[Any] = [
        GptBusinessChildMembershipModel.ended_at.is_(None),  # type: ignore[union-attr]
        GptBusinessChildMembershipModel.business_account_id.in_(parent_ids),  # type: ignore[union-attr]
    ]
    normalized_two_factor_status = str(two_factor_status or "all").strip().lower()
    normalized_rt_status = str(rt_status or "all").strip().lower()
    normalized_sale_status = str(sale_status or "all").strip().lower()
    security_join = (
        ChatGptAccountSecurityModel.email
        == func.lower(func.trim(GptBusinessChildMembershipModel.email))
    )
    include_security_join = normalized_two_factor_status != "all"
    if include_security_join or normalized_rt_status != "all":
        # 手动邮箱成员没有本地账号、2FA 或 RT 能力。具体状态筛选只面向
        # 账号池子号，避免把“不支持”误报成“未开启/未获取”。
        conditions.append(GptPlanAccountModel.id.is_not(None))  # type: ignore[union-attr]
    normalized_mfa_state = func.lower(func.trim(func.coalesce(
        ChatGptAccountSecurityModel.mfa_state,
        "",
    )))
    if normalized_two_factor_status == "enabled":
        conditions.append(normalized_mfa_state == "enabled")
    elif normalized_two_factor_status == "not_enabled":
        conditions.append(or_(
            ChatGptAccountSecurityModel.email.is_(None),  # type: ignore[union-attr]
            normalized_mfa_state.in_((
                "",
                "not_configured",
                "disabled",
                "off",
                "none",
            )),
        ))
    elif normalized_two_factor_status == "needs_attention":
        conditions.extend([
            ChatGptAccountSecurityModel.email.is_not(None),  # type: ignore[union-attr]
            normalized_mfa_state.not_in((
                "",
                "enabled",
                "not_configured",
                "disabled",
                "off",
                "none",
            )),
        ])
    if normalized_rt_status == "acquired":
        conditions.append(
            func.trim(func.coalesce(GptPlanAccountModel.codex_refresh_token, "")) != ""
        )
    elif normalized_rt_status == "missing":
        conditions.append(
            func.trim(func.coalesce(GptPlanAccountModel.codex_refresh_token, "")) == ""
        )
    if normalized_sale_status in _BUSINESS_CHILD_SALE_STATUSES:
        conditions.append(
            GptBusinessChildMembershipModel.sale_status == normalized_sale_status
        )
    term = str(keyword or "").strip()[:200]
    if term:
        parent_match_ids = (
            _business_parent_directory_query()
            .where(
                or_(
                    col(GptPlanAccountModel.email).contains(term),
                    col(GptPlanAccountModel.note).contains(term),
                    col(GptBusinessAccountModel.email).contains(term),
                    col(GptBusinessAccountModel.note).contains(term),
                )
            )
            .with_only_columns(GptPlanAccountModel.source_account_id)
        )
        conditions.append(or_(
            col(GptBusinessChildMembershipModel.email).contains(term),
            col(GptPlanAccountModel.email).contains(term),
            col(GptPlanAccountModel.note).contains(term),
            GptBusinessChildMembershipModel.business_account_id.in_(  # type: ignore[union-attr]
                parent_match_ids
            ),
        ))
    count_query = (
        select(func.count())
        .select_from(GptBusinessChildMembershipModel)
        .join(GptPlanAccountModel, child_join, isouter=True)
    )
    rows_query = (
        select(GptBusinessChildMembershipModel, GptPlanAccountModel)
        .join(GptPlanAccountModel, child_join, isouter=True)
    )
    if include_security_join:
        count_query = count_query.join(
            ChatGptAccountSecurityModel,
            security_join,
            isouter=True,
        )
        rows_query = rows_query.join(
            ChatGptAccountSecurityModel,
            security_join,
            isouter=True,
        )
    total = session.exec(count_query.where(*conditions)).one()
    rows = session.exec(
        rows_query
        .where(*conditions)
        .order_by(
            col(GptBusinessChildMembershipModel.invited_at).desc(),
            col(GptBusinessChildMembershipModel.id).desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return int(total or 0), list(rows)


def _business_child_dimension_parent_map(
    session: Session,
    source_ids: set[int],
) -> dict[int, tuple[GptPlanAccountModel, GptBusinessAccountModel]]:
    if not source_ids:
        return {}
    rows = session.exec(
        _business_parent_directory_query().where(
            GptBusinessAccountModel.id.in_(sorted(source_ids))  # type: ignore[union-attr]
        )
    ).all()
    return {
        int(source.id or 0): (parent, source)
        for parent, source in rows
        if source.id is not None and parent.id is not None
    }


@router.get("/business-children")
def list_business_children(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    keyword: Optional[str] = Query(None),
    parent_account_id: Optional[int] = Query(None),
    business_usage_type: str = Query("sale"),
    two_factor_status: str = Query("all"),
    rt_status: str = Query("all"),
    sale_status: str = Query("all"),
):
    """List active BUSINESS children, defaulting to sale-purpose mothers.

    This default belongs only to the child-dimension catalogue.  Callers that
    need an explicit scope may use ``sale``, ``self_use``, ``transit``, ``unassigned`` or
    ``all``; the mother list and the per-mother expansion retain their existing
    unfiltered behaviour.
    """
    if parent_account_id is not None and (
        isinstance(parent_account_id, bool)
        or not isinstance(parent_account_id, int)
        or parent_account_id <= 0
    ):
        raise HTTPException(400, "parent_account_id 必须是正整数")
    normalized_usage = str(business_usage_type or "").strip().lower()
    if normalized_usage not in {"", "all", *_BUSINESS_USAGE_FILTERS}:
        raise HTTPException(
            400,
            "business_usage_type 只支持 all/unassigned/sale/self_use/transit",
        )
    # An explicitly empty query value is a backwards-compatible spelling of
    # ``all``.  Omitting the parameter still receives the requested ``sale``
    # default through FastAPI's query default above.
    normalized_usage = normalized_usage or "all"
    normalized_two_factor_status = str(two_factor_status or "").strip().lower()
    if normalized_two_factor_status not in {"all", *_BUSINESS_CHILD_2FA_FILTERS}:
        raise HTTPException(
            400,
            "two_factor_status 只支持 all/enabled/not_enabled/needs_attention",
        )
    normalized_rt_status = str(rt_status or "").strip().lower()
    if normalized_rt_status not in {"all", *_BUSINESS_CHILD_RT_FILTERS}:
        raise HTTPException(400, "rt_status 只支持 all/acquired/missing")
    normalized_sale_status = str(sale_status or "").strip().lower()
    if normalized_sale_status not in {"all", *_BUSINESS_CHILD_SALE_STATUSES}:
        raise HTTPException(400, "sale_status 只支持 all/unlisted/listed/sold/refunded/partial_refund")
    with Session(engine) as session:
        total, rows = _business_child_dimension_rows(
            session,
            page=int(page),
            page_size=int(page_size),
            keyword=str(keyword or ""),
            parent_account_id=int(parent_account_id or 0),
            business_usage_type=normalized_usage,
            two_factor_status=normalized_two_factor_status,
            rt_status=normalized_rt_status,
            sale_status=normalized_sale_status,
        )
        parent_map = _business_child_dimension_parent_map(
            session,
            {int(membership.business_account_id) for membership, _child in rows},
        )
        managed_emails = [
            str(child.email or "")
            for _membership, child in rows
            if child is not None
        ]
        security_map = _chatgpt_security_status_map(managed_emails)
        parent_capabilities = {
            source_id: _business_child_parent_management_capability(
                parent,
                source_parent,
            )
            for source_id, (parent, source_parent) in parent_map.items()
        }
        items: list[dict[str, Any]] = []
        for membership, child in rows:
            parent_pair = parent_map.get(int(membership.business_account_id))
            # The exact parent predicate was already part of the paged query.
            # Fail closed if a concurrent directory rebind occurs between the
            # page and its serialization instead of exposing an orphan row.
            if parent_pair is None:
                raise HTTPException(
                    409,
                    "BUSINESS 母号目录绑定在读取期间发生变化，请刷新后重试",
                )
            parent, source_parent = parent_pair
            items.append(_business_child_dimension_item(
                membership,
                child,
                parent,
                source_parent,
                parent_child_capability=parent_capabilities.get(
                    int(membership.business_account_id)
                ),
                chatgpt_security=(
                    security_map.get(
                        _chatgpt_security_email_key(child.email),
                        _unavailable_chatgpt_security_status(),
                    )
                    if child is not None else None
                ),
            ))
        return {
            "total": total,
            "page": int(page),
            "page_size": int(page_size),
            "business_usage_type": normalized_usage,
            "two_factor_status": normalized_two_factor_status,
            "rt_status": normalized_rt_status,
            "sale_status": normalized_sale_status,
            "items": items,
        }


def _strict_business_child_sold_at(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise HTTPException(400, "sold_at 必须是带时区的 ISO8601 时间或 null")
    text_value = value.strip()
    if len(text_value) > 80:
        raise HTTPException(400, "sold_at 格式无效")
    try:
        parsed = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, "sold_at 必须是带时区的 ISO8601 时间") from exc
    if parsed.tzinfo is None:
        raise HTTPException(400, "sold_at 必须包含时区")
    normalized = parsed.astimezone(timezone.utc)
    if normalized.year < 2000 or normalized.year > 2100:
        raise HTTPException(400, "sold_at 超出允许范围")
    return normalized


def _strict_business_child_sale_status(value: Any) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, "sale_status 必须是 unlisted、listed 或 sold")
    normalized = value.strip().lower()
    if normalized not in {"unlisted", "listed", "sold"}:
        raise HTTPException(400, "sale_status 只支持 unlisted/listed/sold")
    return normalized


def _strict_business_child_warranty_hours(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(400, "warranty_hours 必须是整数")
    if value < 0 or value > _BUSINESS_CHILD_WARRANTY_MAX_HOURS:
        raise HTTPException(
            400,
            f"warranty_hours 必须在 0-{_BUSINESS_CHILD_WARRANTY_MAX_HOURS} 之间",
        )
    return int(value)


def _active_business_child_dimension_target(
    session: Session,
    membership_id: int,
    *,
    require_member_parent: bool = True,
) -> tuple[
    GptBusinessChildMembershipModel,
    Optional[GptPlanAccountModel],
    GptPlanAccountModel,
    GptBusinessAccountModel,
]:
    membership = session.get(GptBusinessChildMembershipModel, int(membership_id))
    if membership is None or membership.ended_at is not None:
        raise HTTPException(404, "当前 BUSINESS 子号不存在")
    parent_query = (
        _business_parent_directory_query()
        if require_member_parent
        else _business_parent_binding_query()
    )
    pair = session.exec(
        parent_query.where(
            GptBusinessAccountModel.id == int(membership.business_account_id)
        )
    ).first()
    if pair is None:
        raise HTTPException(409, "子号的 BUSINESS 母号目录绑定已变化")
    parent, source_parent = pair
    child: Optional[GptPlanAccountModel] = None
    if (
        str(membership.source or "").strip().lower() == "pool"
        and membership.pro_account_id is not None
        and int(membership.pro_account_id) > 0
    ):
        candidate = session.get(GptPlanAccountModel, int(membership.pro_account_id))
        if (
            candidate is not None
            and int(getattr(candidate, "business_parent_id", None) or 0)
            == int(membership.business_account_id)
            and _normalized_email(candidate.email)
            == _safe_business_child_email(membership.email)
        ):
            child = candidate
    return membership, child, parent, source_parent


@router.patch("/business-children/{membership_id}/sale")
def update_business_child_sale(
    membership_id: int,
    body: GptPlanBusinessChildSaleRequest,
):
    """Update sale status/time/warranty on one active membership."""
    if membership_id <= 0:
        raise HTTPException(404, "当前 BUSINESS 子号不存在")
    fields_set_value = getattr(body, "model_fields_set", None)
    if fields_set_value is None:  # pragma: no cover - Pydantic v1 compatibility
        fields_set_value = getattr(body, "__fields_set__", set())
    fields_set = set(fields_set_value)
    mutable_fields = fields_set & {"sale_status", "sold_at", "warranty_hours"}
    if not mutable_fields:
        raise HTTPException(400, "至少需要提交 sale_status、sold_at 或 warranty_hours")
    sale_status = (
        _strict_business_child_sale_status(body.sale_status)
        if "sale_status" in mutable_fields else None
    )
    sold_at = (
        _strict_business_child_sold_at(body.sold_at)
        if "sold_at" in mutable_fields else None
    )
    warranty_hours = (
        _strict_business_child_warranty_hours(body.warranty_hours)
        if "warranty_hours" in mutable_fields else None
    )
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        membership, child, parent, source_parent = (
            _active_business_child_dimension_target(session, int(membership_id))
        )
        if membership.sale_status in {"refunded", "partial_refund"}:
            raise HTTPException(409, "NV 已确认退款，不可通过出售状态编辑覆盖")
        if sale_status in {"unlisted", "listed"}:
            if "sold_at" in mutable_fields and sold_at is not None:
                label = "未上架" if sale_status == "unlisted" else "已上架"
                raise HTTPException(400, f"{label}状态不能同时设置出售时间")
            previous_sale_status = str(membership.sale_status or "").strip().lower()
            membership.sale_status = sale_status
            membership.sold_at = None
            # Editing the local sale label is not an NV upload confirmation.
            # A new local listing cycle must not inherit an old NV proof.
            if sale_status == "unlisted" or previous_sale_status != sale_status:
                membership.nv_listed_at = None
                membership.nv_listing_confirmed_at = None
                membership.nv_team5x_warranty_until = None
            if previous_sale_status != sale_status:
                membership.nv_last_synced_at = None
                membership.nv_remote_card_id = ""
                membership.nv_remote_order_id = ""
        elif sale_status == "sold":
            if "sold_at" in mutable_fields and sold_at is None:
                raise HTTPException(400, "已出售状态不能清空出售时间")
            membership.sale_status = "sold"
            if "sold_at" not in mutable_fields and membership.sold_at is None:
                membership.sold_at = _utcnow()
        if "sold_at" in mutable_fields:
            membership.sold_at = sold_at
            # ``sale_status`` is the operator's explicit lifecycle choice.  The
            # editor always submits ``sold_at: null`` for both listed and
            # unlisted rows, so only infer a status from sold_at when the
            # caller did not submit sale_status at all.
            if "sale_status" not in mutable_fields:
                membership.sale_status = (
                    "sold" if sold_at is not None else "unlisted"
                )
                if sold_at is None:
                    membership.nv_listed_at = None
                    membership.nv_listing_confirmed_at = None
                    membership.nv_team5x_warranty_until = None
                    membership.nv_last_synced_at = None
                    membership.nv_remote_card_id = ""
                    membership.nv_remote_order_id = ""
        if "warranty_hours" in mutable_fields:
            membership.warranty_hours = int(warranty_hours or 0)
        membership.updated_at = _utcnow()
        session.add(membership)
        session.commit()
        session.refresh(membership)
        security = (
            _chatgpt_security_status_for_email(child.email)
            if child is not None else None
        )
        return {
            "ok": True,
            "item": _business_child_dimension_item(
                membership,
                child,
                parent,
                source_parent,
                chatgpt_security=security,
            ),
        }


def _strict_nexusvault_price_yuan(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise HTTPException(400, "上架价格必须是最多两位小数的人民币金额")
    raw = str(value).strip()
    if not re.fullmatch(r"\d{1,6}(?:\.\d{1,2})?", raw):
        raise HTTPException(400, "上架价格必须是最多两位小数的人民币金额")
    try:
        amount = Decimal(raw)
    except InvalidOperation as exc:
        raise HTTPException(400, "上架价格格式无效") from exc
    if amount < Decimal("0.01") or amount > Decimal("999999.99"):
        raise HTTPException(400, "上架价格必须在 0.01-999999.99 元之间")
    return f"{amount.quantize(Decimal('0.01')):.2f}"


def _strict_nexusvault_warranty_hours(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != 1:
        raise HTTPException(400, "NexusVault 当前只支持默认 1 小时质保")
    return 1


def _nexusvault_team5x_warranty(value: Any, *, require_future: bool = True) -> Optional[dict[str, str]]:
    from services.nv_listing_warranty import normalize_team5x_warranty

    try:
        return normalize_team5x_warranty(value, require_future=require_future)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _assert_nexusvault_child_ready(
    membership: GptBusinessChildMembershipModel,
    child: Optional[GptPlanAccountModel],
) -> GptPlanAccountModel:
    """Validate a live, locally managed child before any credential leaves."""
    if child is None or str(membership.source or "").strip().lower() != "pool":
        raise HTTPException(409, "手动邮箱子号没有可上架的本地凭证")
    if not bool(child.enabled) or bool(child.dangerous):
        raise HTTPException(409, "子号已停用或标记为 Dead，不能上架 NV")
    if bool(child.policy_warning):
        raise HTTPException(409, "子号存在政策告警，不能上架 NV")
    if str(child.refund_status or "").strip() or _catalog_category(child) == "refunded":
        raise HTTPException(409, "退款流程中的子号不能上架 NV")
    if not str(membership.remote_user_id or "").strip():
        raise HTTPException(409, "子号尚未成为 BUSINESS 正式成员")
    if (_business_child_warranty_snapshot(membership).get("sale_status") != "unlisted"
            or getattr(membership, "nv_team5x_warranty_until", None) is not None):
        raise HTTPException(409, "子号已经上架或出售，不能重复提交 NV")
    missing = [
        label
        for label, token in (
            ("AT", child.codex_access_token),
            ("RT", child.codex_refresh_token),
            ("ID Token", child.codex_id_token),
        )
        if not str(token or "").strip()
    ]
    if missing:
        raise HTTPException(
            409,
            "子号缺少完整 OAuth/Sub2API 凭证，请先获取 RT"
            f"（缺少 {', '.join(missing)}）",
        )
    return child


def _internal_expected_positive(value: Any) -> int:
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 0
    )


def _assert_nexusvault_listing_expected_target(
    expected: Optional[dict[str, Any]],
    membership: GptBusinessChildMembershipModel,
    child: GptPlanAccountModel,
    parent: GptPlanAccountModel,
    source_parent: GptBusinessAccountModel,
) -> None:
    """Fail closed when a durable job's frozen listing identity has changed."""
    if expected is None:
        return
    changed = "自动上架目标的母号、成员或子号身份已变化，未上传 NV"
    if not isinstance(expected, dict):
        raise HTTPException(409, changed)
    parent_id = _internal_expected_positive(expected.get("parent_account_id"))
    source_id = _internal_expected_positive(expected.get("source_account_id"))
    membership_id = _internal_expected_positive(expected.get("membership_id"))
    child_id = _internal_expected_positive(expected.get("child_id"))
    parent_email = _normalized_email(expected.get("parent_email"))
    email = _safe_business_child_email(expected.get("email"))
    remote_user_id = _safe_business_remote_identifier(
        expected.get("remote_user_id")
    )
    if (
        not all((parent_id, source_id, membership_id, child_id))
        or not parent_email
        or not email
        or email == parent_email
        or not remote_user_id
        or int(parent.id or 0) != parent_id
        or str(parent.source_pool or "") != "gpt_business"
        or int(parent.source_account_id or 0) != source_id
        or _normalized_email(parent.email) != parent_email
        or int(source_parent.id or 0) != source_id
        or _normalized_email(source_parent.email) != parent_email
        or int(membership.id or 0) != membership_id
        or int(membership.business_account_id or 0) != source_id
        or int(membership.pro_account_id or 0) != child_id
        or str(membership.source or "").strip().lower() != "pool"
        or _safe_business_child_email(membership.email) != email
        or _safe_business_remote_identifier(membership.remote_user_id)
        != remote_user_id
        or int(child.id or 0) != child_id
        or int(child.business_parent_id or 0) != source_id
        or _normalized_email(child.email) != email
    ):
        raise HTTPException(409, changed)
    if "seat_type" in expected:
        # Automatic pricing is based on this exact member, not its mother or
        # an earlier job snapshot. Recheck at every existing publish boundary
        # so a concurrent seat change cannot sell the account at the old tier.
        expected_seat = _safe_business_child_seat_type(expected["seat_type"])
        if not expected_seat or _safe_business_child_seat_type(membership.seat_type) != expected_seat:
            raise HTTPException(409, "自动上架子号的席位类型已变化或无法确认，未上传 NV")


@router.post("/business-children/{membership_id}/nvtokens-listing")
def publish_business_child_to_nexusvault(
    membership_id: int,
    body: GptPlanNexusVaultListingRequest,
):
    """Publish one BUSINESS child and mark it listed only after confirmation.

    This route intentionally composes the existing Sub2API credential builder
    with the encrypted ChatGPT security store.  Neither OAuth material nor the
    password/TOTP seed crosses the browser boundary or appears in the response.
    """
    if membership_id <= 0:
        raise HTTPException(404, "当前 BUSINESS 子号不存在")
    price_yuan = _strict_nexusvault_price_yuan(body.price_yuan)
    warranty_hours = _strict_nexusvault_warranty_hours(body.warranty_hours)
    requested_team5x_warranty = _nexusvault_team5x_warranty(body.team5x_warranty, require_future=False)

    from services.nexusvault import (
        NexusVaultConfigurationError,
        NexusVaultPublishRejected,
        NexusVaultRequestError,
        NexusVaultRequestTimeout,
        load_config,
        publish_sub2api_card,
    )

    try:
        nv_base_url, nv_api_key = load_config()
    except NexusVaultConfigurationError as exc:
        raise HTTPException(409, str(exc)) from exc

    raw_expected_target = body._expected_target
    expected_target = (
        dict(raw_expected_target)
        if isinstance(raw_expected_target, dict)
        else raw_expected_target
    )
    with Session(engine) as session:
        membership, child, parent, source_parent = (
            _active_business_child_dimension_target(
                session,
                int(membership_id),
                require_member_parent=False,
            )
        )
        child = _assert_nexusvault_child_ready(membership, child)
        _assert_nexusvault_listing_expected_target(
            expected_target, membership, child, parent, source_parent,
        )
        child_id = int(child.id or 0)
        expected_parent_id = int(membership.business_account_id)
        expected_email = _normalized_email(child.email)
        expected_seat_type = _safe_business_child_seat_type(membership.seat_type)
        team5x_warranty = requested_team5x_warranty if expected_seat_type == "prolite" else None
        if expected_seat_type == "prolite" and team5x_warranty is None:
            raise HTTPException(400, "5X 上架需先设置质保截止时间，未上传 NV")
        team5x_warranty = _nexusvault_team5x_warranty(team5x_warranty)

    operation = "nexusvault_listing"
    operation_token = _claim_plan_operation(child_id, operation)
    try:
        # Re-resolve after claiming the account lease so a stale membership
        # observed immediately before the claim cannot authorize a publish.
        with Session(engine) as session:
            membership, child, parent, source_parent = (
                _active_business_child_dimension_target(
                    session,
                    int(membership_id),
                    require_member_parent=False,
                )
            )
            child = _assert_nexusvault_child_ready(membership, child)
            _assert_nexusvault_listing_expected_target(
                expected_target, membership, child, parent, source_parent,
            )
            if (
                int(child.id or 0) != child_id
                or int(membership.business_account_id) != expected_parent_id
                or _normalized_email(child.email) != expected_email
                or not _plan_operation_is_current(
                    session, child_id, operation_token, operation
                )
            ):
                raise HTTPException(409, "子号归属或操作租约已变化，请刷新后重试")

            token_data = {
                "type": "codex",
                "email": child.email,
                "access_token": child.codex_access_token,
                "refresh_token": child.codex_refresh_token,
                "id_token": child.codex_id_token,
                "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
                "subscription_expires_at": child.pro_expires_at,
            }
            try:
                from platforms.chatgpt.sub2api_upload import (
                    build_sub2api_bundle_from_token_data,
                )

                sub2api_data = build_sub2api_bundle_from_token_data(
                    token_data,
                    account=child,
                )
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc

        try:
            from services.chatgpt_security_store import (
                get_chatgpt_security_secrets,
                get_chatgpt_security_status,
            )

            security_status = get_chatgpt_security_status(expected_email)
            if not bool(security_status.get("credentials_readable", True)):
                raise HTTPException(409, "子号密码与 2FA 凭证暂时无法解密")
            if (
                not bool(security_status.get("has_password"))
                or str(security_status.get("password_state") or "").strip().lower()
                != "configured"
            ):
                raise HTTPException(409, "子号需要先设置并确认 ChatGPT 登录密码")
            if (
                not bool(security_status.get("has_totp"))
                or str(security_status.get("mfa_state") or "").strip().lower()
                != "enabled"
            ):
                raise HTTPException(
                    409,
                    "子号需要先启用并保存长期 Authenticator 2FA 密钥",
                )
            security_secrets = get_chatgpt_security_secrets(expected_email)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(409, "子号密码与 2FA 凭证读取失败") from exc

        password = str(security_secrets.get("password") or "")
        totp_secret = str(security_secrets.get("totp_secret") or "")
        if not password or not totp_secret:
            raise HTTPException(409, "子号密码或长期 Authenticator 2FA 密钥不完整")

        # Security lookup and credential-bundle construction may take time.
        # Re-read the immutable identity and operation lease at the last local
        # boundary before the one-shot external publish.
        with Session(engine) as session:
            membership, current_child, parent, source_parent = (
                _active_business_child_dimension_target(
                    session,
                    int(membership_id),
                    require_member_parent=False,
                )
            )
            current_child = _assert_nexusvault_child_ready(
                membership, current_child,
            )
            _assert_nexusvault_listing_expected_target(
                expected_target,
                membership,
                current_child,
                parent,
                source_parent,
            )
            if (
                int(current_child.id or 0) != child_id
                or not _plan_operation_is_current(
                    session, child_id, operation_token, operation
                )
            ):
                raise HTTPException(
                    409,
                    "子号归属或操作租约已变化，未上传 NV",
                )

        # Record the lower bound before the remote mutation.  Using the later
        # response/commit time could miss an account that is extracted from NV
        # immediately after it enters the pool.
        nv_listing_started_at = _utcnow()
        if _safe_business_child_seat_type(membership.seat_type) != expected_seat_type:
            raise HTTPException(409, "子号席位类型已变化，未上传 NV，请刷新后重试")
        # Time may have elapsed while checking security and operation leases.
        team5x_warranty = _nexusvault_team5x_warranty(team5x_warranty)

        # The client performs one real mutation and deliberately has no retry.
        try:
            published = publish_sub2api_card(
                sub2api_data=sub2api_data,
                email=expected_email,
                password=password,
                two_factor_secret=totp_secret,
                price_yuan=price_yuan,
                warranty_hours=warranty_hours,
                base_url=nv_base_url,
                api_key=nv_api_key,
                **({"team5x_warranty": team5x_warranty} if team5x_warranty is not None else {}),
            )
        except NexusVaultRequestTimeout as exc:
            raise HTTPException(504, str(exc)) from exc
        except NexusVaultPublishRejected as exc:
            raise HTTPException(409, str(exc)) from exc
        except NexusVaultConfigurationError as exc:
            raise HTTPException(409, str(exc)) from exc
        except NexusVaultRequestError as exc:
            raise HTTPException(502, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

        # ``published`` is a typed result that can only be constructed by the
        # client after exact integer summary.published == 1 validation.
        if published.published != 1:
            raise HTTPException(409, "NexusVault 未确认账号成功入池")

        try:
            with Session(engine) as session:
                if session.get_bind().dialect.name == "sqlite":
                    session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                membership, child, parent, source_parent = (
                    _active_business_child_dimension_target(
                        session,
                        int(membership_id),
                        require_member_parent=False,
                    )
                )
                child = _assert_nexusvault_child_ready(membership, child)
                _assert_nexusvault_listing_expected_target(
                    expected_target,
                    membership,
                    child,
                    parent,
                    source_parent,
                )
                if (
                    int(child.id or 0) != child_id
                    or int(membership.business_account_id) != expected_parent_id
                    or _normalized_email(child.email) != expected_email
                    or _safe_business_child_seat_type(membership.seat_type) != expected_seat_type
                    or not _plan_operation_is_current(
                        session, child_id, operation_token, operation
                    )
                ):
                    raise HTTPException(
                        409,
                        "NV 已确认上架，但本地子号归属已变化；请人工核对后更新状态",
                    )
                now = _utcnow()
                membership.sale_status = "listed"
                membership.sold_at = None
                membership.warranty_hours = 0 if team5x_warranty else warranty_hours
                membership.nv_team5x_warranty_until = (
                    datetime.fromisoformat(team5x_warranty["until"]) if team5x_warranty else None
                )
                membership.nv_listed_at = nv_listing_started_at
                membership.nv_listing_confirmed_at = now
                membership.nv_last_synced_at = None
                membership.nv_remote_card_id = ""
                membership.nv_remote_order_id = ""
                membership.updated_at = now
                session.add(membership)
                session.commit()
                session.refresh(membership)
                public_security = _chatgpt_security_status_for_email(child.email)
                item = _business_child_dimension_item(
                    membership,
                    child,
                    parent,
                    source_parent,
                    chatgpt_security=public_security,
                )
        except Exception as exc:
            raise HTTPException(
                409,
                "NV 已确认上架，但本地状态未完成更新；请人工核对后更新状态",
            ) from exc
        return {
            "ok": True,
            "published": 1,
            "price_yuan": price_yuan,
            "warranty_hours": 0 if team5x_warranty else warranty_hours,
            "team5x_warranty": team5x_warranty,
            "summary": dict(published.summary),
            "item": item,
        }
    finally:
        _release_plan_operation(child_id, operation_token)


_NEXUSVAULT_BATCH_TASKS: dict[str, dict[str, Any]] = {}
_NEXUSVAULT_BATCH_LOCK = threading.RLock()
_NEXUSVAULT_BATCH_RUN_LOCK = threading.Lock()
_NEXUSVAULT_BATCH_RETAIN_SECONDS = 2 * 60 * 60
_NEXUSVAULT_BATCH_MAX_FINISHED = 50
_NEXUSVAULT_BATCH_MAX_LOGS = 400
_NEXUSVAULT_BATCH_TERMINAL = frozenset({"success", "failed", "skipped"})


def _prune_nexusvault_batch_tasks_locked() -> None:
    cutoff = _utcnow() - timedelta(seconds=_NEXUSVAULT_BATCH_RETAIN_SECONDS)
    finished = sorted(
        (
            (_aware_utc(task["finished_at"]), task_id)
            for task_id, task in _NEXUSVAULT_BATCH_TASKS.items()
            if task.get("finished_at") is not None
        ),
        reverse=True,
    )
    for index, (finished_at, task_id) in enumerate(finished):
        if index >= _NEXUSVAULT_BATCH_MAX_FINISHED or finished_at < cutoff:
            _NEXUSVAULT_BATCH_TASKS.pop(task_id, None)


def _nexusvault_batch_snapshot_locked(task: dict[str, Any]) -> dict[str, Any]:
    # Explicit projection: frozen ownership data and single-publish responses
    # never become part of the public task contract.
    items = [
        {
            key: list(item[key]) if key == "logs" else item[key]
            for key in (
                "membership_id", "email", "status", "stage", "error", "logs"
            )
        }
        for item in task["items"]
    ]
    total = len(items)
    completed = sum(item["status"] in _NEXUSVAULT_BATCH_TERMINAL for item in items)
    return {
        "task_id": task["task_id"],
        "status": task["status"],
        "total": total,
        "completed": completed,
        "succeeded": sum(item["status"] == "success" for item in items),
        "failed": sum(item["status"] == "failed" for item in items),
        "skipped": sum(item["status"] == "skipped" for item in items),
        "percent": min(
            99 if task["status"] == "running" else 100,
            int(completed * 100 / total) if total else 100,
        ),
        "items": items,
        "logs": list(task["logs"]),
        "error": task["error"],
    }


def _nexusvault_batch_log_locked(
    task: dict[str, Any], message: str, item: Optional[dict[str, Any]] = None,
) -> None:
    # Callers supply only local, fixed messages. Never log exception reprs,
    # request payloads, remote response bodies, or credential-builder output.
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
    if item is not None:
        item["logs"] = (item["logs"] + [line])[-20:]
        line = f"成员 #{item['membership_id']} {line}"
    task["logs"] = (task["logs"] + [line])[-_NEXUSVAULT_BATCH_MAX_LOGS:]


def _resolve_nexusvault_batch_target(membership_id: int) -> dict[str, Any]:
    with Session(engine) as session:
        membership, child, parent, _source_parent = (
            _active_business_child_dimension_target(
                session, membership_id, require_member_parent=False,
            )
        )
        return {
            "membership_id": int(membership.id),
            "parent_account_id": int(parent.id),
            "source_account_id": int(membership.business_account_id),
            "child_id": int(child.id) if child is not None else 0,
            "email": _safe_business_child_email(membership.email),
        }


def _nexusvault_batch_failure(exc: Exception) -> tuple[str, str]:
    """Use an exact local allow-list, never regex-redact unknown secret text."""
    safe_skips = {
        "当前 BUSINESS 子号不存在",
        "子号的 BUSINESS 母号目录绑定已变化",
        "手动邮箱子号没有可上架的本地凭证",
        "子号已停用或标记为 Dead，不能上架 NV",
        "子号存在政策告警，不能上架 NV",
        "退款流程中的子号不能上架 NV",
        "子号尚未成为 BUSINESS 正式成员",
        "子号已经上架或出售，不能重复提交 NV",
        "子号密码与 2FA 凭证暂时无法解密",
        "子号需要先设置并确认 ChatGPT 登录密码",
        "子号需要先启用并保存长期 Authenticator 2FA 密钥",
        "子号密码与 2FA 凭证读取失败",
        "子号密码或长期 Authenticator 2FA 密钥不完整",
        "子号成员归属已变化，请刷新后重新选择",
        "5X 上架需先设置质保截止时间，未上传 NV",
    }
    detail = exc.detail if isinstance(exc, HTTPException) else None
    if isinstance(detail, str) and detail in {
        "Team 5x 质保截止时间必须晚于当前时间，请重新配置质保",
        "Team 5x 质保截止时间须为带时区的 ISO 时间",
        "Team 5x 质保须为仅包含 mode 和 until 的对象",
        "NV Team 5x 上架质保仅支持 mode=until",
    }:
        return "skipped", detail + "；未上传 NV"
    if isinstance(detail, str) and detail in safe_skips:
        return "skipped", detail
    if isinstance(detail, str) and re.fullmatch(
        r"子号缺少完整 OAuth/Sub2API 凭证，请先获取 RT"
        r"（缺少 (?:AT|RT|ID Token)(?:, (?:AT|RT|ID Token))*）",
        detail,
    ):
        return "skipped", "子号缺少完整 OAuth/Sub2API 凭证，请先获取 RT"
    if isinstance(detail, dict) and detail.get("code") == "gpt_plan_account_busy":
        return "skipped", "子号正在执行其他操作，请等待完成后重新选择"
    from services.nexusvault import (
        NexusVaultConfigurationError, NexusVaultPublishRejected,
    )

    if isinstance(exc.__cause__, NexusVaultConfigurationError):
        return "failed", "NV 配置不可用，请检查上架配置"
    if isinstance(exc.__cause__, NexusVaultPublishRejected):
        return "failed", "NV 未确认上架成功，请在 NV 核对原因；未自动重试"
    return "failed", "NV 上架结果未知或本地状态未确认，请先在 NV 人工核对；未自动重试"


def _run_nexusvault_batch_listing_task(task_id: str) -> None:
    # The start endpoint claims this process-wide gate before spawning us.
    # Each child also retains the existing durable single-account lease.
    try:
        with _NEXUSVAULT_BATCH_LOCK:
            task = _NEXUSVAULT_BATCH_TASKS[task_id]
            targets = [dict(item["target"]) for item in task["items"]]
            body = GptPlanNexusVaultListingRequest(
                price_yuan=task["price_yuan"], warranty_hours=task["warranty_hours"],
                team5x_warranty=task.get("team5x_warranty"),
            )
        for index, target in enumerate(targets):
            with _NEXUSVAULT_BATCH_LOCK:
                item = task["items"][index]
                if item["status"] in _NEXUSVAULT_BATCH_TERMINAL:
                    continue
                item.update(status="running", stage="检查子号资格")
                _nexusvault_batch_log_locked(task, "检查子号身份和上架资格", item)
            try:
                current = _resolve_nexusvault_batch_target(target["membership_id"])
                if current != target:
                    raise HTTPException(409, "子号成员归属已变化，请刷新后重新选择")
                with Session(engine) as session:
                    membership, child, _parent, _source_parent = (
                        _active_business_child_dimension_target(
                            session, target["membership_id"],
                            require_member_parent=False,
                        )
                    )
                    _assert_nexusvault_child_ready(membership, child)
                with _NEXUSVAULT_BATCH_LOCK:
                    item["stage"] = "提交 NV 并确认本地状态"
                    _nexusvault_batch_log_locked(task, "开始单号 NV 上架流程", item)
                # Exactly one invocation; no retry on rejection, timeout, or
                # local commit failure after the remote mutation.
                result = publish_business_child_to_nexusvault(
                    target["membership_id"], body,
                )
                if (
                    not isinstance(result, dict)
                    or result.get("ok") is not True
                    or type(result.get("published")) is not int
                    or result["published"] != 1
                ):
                    raise RuntimeError("unconfirmed listing")
                with Session(engine) as session:
                    membership = session.get(
                        GptBusinessChildMembershipModel, target["membership_id"],
                    )
                    if (
                        membership is None
                        or membership.ended_at is not None
                        or membership.sale_status != "listed"
                        or membership.nv_listed_at is None
                        or int(membership.pro_account_id or 0) != target["child_id"]
                        or int(membership.business_account_id) != target["source_account_id"]
                        or _safe_business_child_email(membership.email) != target["email"]
                    ):
                        raise RuntimeError("local listing not confirmed")
                status, message = "success", "NV 已确认上架，本地状态已更新为已上架"
            except Exception as exc:
                status, message = _nexusvault_batch_failure(exc)
            with _NEXUSVAULT_BATCH_LOCK:
                item.update(
                    status=status,
                    stage={"success": "已上架", "failed": "上架失败", "skipped": "已跳过"}[status],
                    error="" if status == "success" else message,
                )
                _nexusvault_batch_log_locked(task, message, item)
        with _NEXUSVAULT_BATCH_LOCK:
            task.update(status="done", finished_at=_utcnow())
            _nexusvault_batch_log_locked(task, "批量 NV 上架处理完成")
    except Exception:
        with _NEXUSVAULT_BATCH_LOCK:
            task = _NEXUSVAULT_BATCH_TASKS.get(task_id)
            if task is not None:
                message = "批量 NV 任务中断，请核对未确认账号的 NV 状态；未自动重试"
                for item in task["items"]:
                    if item["status"] not in _NEXUSVAULT_BATCH_TERMINAL:
                        item.update(status="failed", stage="任务中断", error=message)
                        _nexusvault_batch_log_locked(task, message, item)
                task.update(status="failed", error=message, finished_at=_utcnow())
    finally:
        _NEXUSVAULT_BATCH_RUN_LOCK.release()


@router.post("/business-children/nvtokens-listing-tasks")
def start_business_child_nexusvault_listing_task(
    body: GptPlanNexusVaultBatchListingRequest,
):
    membership_ids = _strict_business_child_batch_membership_ids(body.membership_ids)
    price_yuan = _strict_nexusvault_price_yuan(body.price_yuan)
    warranty_hours = _strict_nexusvault_warranty_hours(body.warranty_hours)
    team5x_warranty = _nexusvault_team5x_warranty(body.team5x_warranty)
    with _NEXUSVAULT_BATCH_LOCK:
        _prune_nexusvault_batch_tasks_locked()
        for active in _NEXUSVAULT_BATCH_TASKS.values():
            if active["status"] == "running":
                raise HTTPException(409, {
                    "code": "nexusvault_batch_already_running",
                    "message": "已有批量 NV 上架任务正在执行，请等待完成",
                    "existing_task_id": active["task_id"],
                })
        if not _NEXUSVAULT_BATCH_RUN_LOCK.acquire(blocking=False):
            raise HTTPException(409, "上一批量 NV 上架任务正在收尾，请稍后再试")
        task_id = f"gpt_plan_nv_batch_{uuid.uuid4().hex}"
        task = {
            "task_id": task_id, "status": "running", "items": [], "logs": [],
            "error": "", "price_yuan": price_yuan, "warranty_hours": warranty_hours,
            "team5x_warranty": team5x_warranty,
            "finished_at": None,
        }
        _NEXUSVAULT_BATCH_TASKS[task_id] = task
        try:
            seen_children: set[int] = set()
            seen_emails: set[str] = set()
            for membership_id in membership_ids:
                target = {"membership_id": membership_id, "email": ""}
                status, error = "pending", ""
                try:
                    target = _resolve_nexusvault_batch_target(membership_id)
                    child_id, email = target["child_id"], target["email"]
                    if (child_id and child_id in seen_children) or (email and email in seen_emails):
                        status, error = "skipped", "所选成员指向同一子号，本批次已去重"
                    seen_children.add(child_id)
                    seen_emails.add(email)
                except Exception as exc:
                    status, error = _nexusvault_batch_failure(exc)
                item = {
                    "membership_id": membership_id, "email": target["email"],
                    "status": status, "stage": "等待处理" if status == "pending" else "已跳过" if status == "skipped" else "解析失败",
                    "error": error, "logs": [], "target": target,
                }
                task["items"].append(item)
                if error:
                    _nexusvault_batch_log_locked(task, error, item)
            _nexusvault_batch_log_locked(task, f"已创建批量 NV 上架任务，共 {len(task['items'])} 个成员")
            worker = threading.Thread(
                target=_run_nexusvault_batch_listing_task,
                args=(task_id,), daemon=True, name=f"gpt-plan-nv-batch-{task_id[-8:]}",
            )
            worker.start()
        except Exception as exc:
            message = "批量 NV 后台任务启动失败，尚未提交上架"
            for item in task["items"]:
                if item["status"] not in _NEXUSVAULT_BATCH_TERMINAL:
                    item.update(status="failed", stage="启动失败", error=message)
            task.update(status="failed", error=message, finished_at=_utcnow())
            _NEXUSVAULT_BATCH_RUN_LOCK.release()
            raise HTTPException(500, message) from exc
        return _nexusvault_batch_snapshot_locked(task)


@router.get("/business-children/nvtokens-listing-tasks/{task_id}")
def get_business_child_nexusvault_listing_task(task_id: str):
    with _NEXUSVAULT_BATCH_LOCK:
        _prune_nexusvault_batch_tasks_locked()
        task = _NEXUSVAULT_BATCH_TASKS.get(task_id)
        if task is None:
            raise HTTPException(404, "批量 NV 上架任务不存在或已过期")
        return _nexusvault_batch_snapshot_locked(task)


def _business_child_nv_legacy_result(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Separate unconfirmed local labels, grouping repeated invitation emails."""
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        email = _normalized_email(row["email"])
        key = email or f"membership:{row['membership_id']}"
        group = grouped.setdefault(key, {
            "email": email,
            "membership_ids": [],
            "record_count": 0,
            "reason": "仅有本地已上架标记，尚无本次 NV 上架确认；保留原销售状态，不计入 NV 异常",
        })
        group["membership_ids"].append(row["membership_id"])
        group["record_count"] += 1
    return {
        "listing_scope_version": 2,
        "legacy_pending": len(grouped),
        "legacy_records": len(rows),
        "legacy_details": sorted(grouped.values(), key=lambda item: item["email"]),
    }


@router.post("/business-children/nexusvault-sales-refresh")
def refresh_business_child_nexusvault_sales():
    """Reconcile confirmed NV listings, separating legacy local sale labels.

    Sales and full inventory are read before the first local write.  A missing
    sale is not evidence that the account is missing from NV: still-available,
    absent, and inconclusive inventory observations are reported separately.
    Mother/Dead/catalog filters never hide a pending NV sale. A local 'listed'
    label alone is not proof of NV publication. Old timestamp-only listings
    can gain proof from a uniquely attributable remote inventory/sale record.
    """
    from services.nexusvault import (
        NexusVaultConfigurationError,
        NexusVaultRequestError,
        NexusVaultRequestTimeout,
        NexusVaultSessionExpired,
        fetch_sales_snapshot,
        load_sales_session_config,
    )
    from services.nv_refund_policy import apply_membership_refund, match_cycle_refund

    with Session(engine) as session:
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.sale_status.in_({"listed", "sold", "partial_refund"}),
            )
        ).all())
        expected: dict[int, tuple[str, datetime, Optional[datetime]]] = {}
        expected_state: dict[int, tuple[str, Optional[datetime], str, str]] = {}
        invalid_local = 0
        details: list[dict[str, Any]] = []
        legacy_rows: list[dict[str, Any]] = []
        for membership in memberships:
            membership_id = int(membership.id or 0)
            email = _normalized_email(membership.email)
            confirmed_at = _aware_utc(membership.nv_listing_confirmed_at)
            listed_at = _aware_utc(membership.nv_listed_at)
            if confirmed_at is None and listed_at is None:
                legacy_rows.append({"membership_id": membership_id, "email": email})
                continue
            listed_floor = (
                listed_at
                or _aware_utc(membership.invited_at)
            )
            if membership_id <= 0 or not email or "@" not in email or listed_floor is None:
                invalid_local += 1
                details.append({
                    "membership_id": membership_id,
                    "email": _safe_business_child_email(membership.email),
                    "status": "invalid_local",
                    "reason": "本地邮箱或上架时间信息不完整，无法核对 NV 状态",
                })
                continue
            expected[membership_id] = (email, listed_floor, confirmed_at)
            expected_state[membership_id] = (
                str(membership.sale_status or "").strip().lower(),
                _aware_utc(membership.sold_at),
                str(membership.nv_remote_card_id or ""),
                str(membership.nv_remote_order_id or ""),
            )

    if not expected:
        return {
            "ok": True,
            "listed_candidates": len(memberships),
            "checked_listed": 0,
            "listed_checked": 0,
            "updated_sold": 0,
            "updated_refunded": 0,
            "updated_partial_refund": 0,
            "sold_found": 0,
            "sold_updated": 0,
            "updated": 0,
            "unchanged_listed": 0,
            "unmatched": invalid_local,
            "pending_sale": 0,
            "not_found": 0,
            "needs_review": 0,
            "details": details,
            "deletion_ready": 0,
            "skipped_changed": 0,
            "invalid_local": invalid_local,
            "remote_orders": 0,
            "remote_sold_cards": 0,
            "remote_sales": 0,
            "pages_fetched": 0,
            "synced_at": "",
            **_business_child_nv_legacy_result(legacy_rows),
        }

    try:
        base_url, query_cookie = load_sales_session_config()
        snapshot = fetch_sales_snapshot(
            base_url=base_url,
            session_cookie=query_cookie,
            include_inventory=True,
        )
    except NexusVaultConfigurationError as exc:
        raise HTTPException(409, str(exc)) from exc
    except NexusVaultSessionExpired as exc:
        # Do not return HTTP 401: that code is reserved for this application's
        # own login middleware and could incorrectly sign the operator out.
        raise HTTPException(409, str(exc)) from exc
    except NexusVaultRequestTimeout as exc:
        raise HTTPException(504, str(exc)) from exc
    except NexusVaultRequestError as exc:
        raise HTTPException(502, str(exc)) from exc

    remote_by_email: dict[str, list[Any]] = {}
    for record in snapshot.sold_records:
        remote_by_email.setdefault(record.email, []).append(record)
    inventory_by_email: dict[str, list[Any]] = {}
    for record in snapshot.inventory_records:
        inventory_by_email.setdefault(record.email, []).append(record)
    inventory_complete = snapshot.inventory_complete is True
    unconfirmed_sold_emails = set(snapshot.unconfirmed_sold_emails)
    matched: dict[int, Any] = {}
    remaining_states: dict[int, tuple[str, str]] = {}
    for membership_id, (email, listed_floor, _) in expected.items():
        eligible = [
            record
            for record in remote_by_email.get(email, ())
            # This lower bound is what prevents a previous invitation/listing
            # cycle for the same mailbox from being mistaken for this one.
            if record.sold_at >= listed_floor
        ]
        if eligible:
            matched[membership_id] = max(
                eligible,
                key=lambda record: record.sold_at,
            )
            continue
        inventory = inventory_by_email.get(email, ())
        if any(record.status == "available" for record in inventory):
            remaining_states[membership_id] = (
                "pending_sale", "NV 库存中仍为待售，尚未出库",
            )
        elif email in unconfirmed_sold_emails:
            remaining_states[membership_id] = (
                "needs_review",
                "NV 有该邮箱的出库记录，但出售时间无效，无法确认本次出库",
            )
        elif inventory:
            remaining_states[membership_id] = (
                "needs_review",
                "NV 有该账号的库存记录，但状态或出售时间不足以确认本次出库，请人工核对",
            )
        elif remote_by_email.get(email):
            remaining_states[membership_id] = (
                "needs_review",
                "仅找到早于本次上架的出售记录，请核对当前上架状态",
            )
        elif inventory_complete:
            remaining_states[membership_id] = (
                "not_found",
                "未找到对应上架记录：已完整查询 NV 库存和出库记录，均未找到该邮箱；保留本地已上架状态，请人工核对",
            )
        else:
            remaining_states[membership_id] = (
                "needs_review", "本次未取得完整、可核对的 NV 库存及出库记录，暂不能判断该账号是否仍在待售，请稍后核对",
            )

    sync_now = _utcnow()
    updated_sold = 0
    updated_refunded = 0
    updated_partial_refund = 0
    unchanged_listed = 0
    deletion_ready = 0
    skipped_changed = 0
    remaining_counts = {"pending_sale": 0, "not_found": 0, "needs_review": 0}
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        current_rows = list(session.exec(
            select(GptBusinessChildMembershipModel).where(
                GptBusinessChildMembershipModel.id.in_(sorted(expected))  # type: ignore[union-attr]
            )
        ).all())
        current_by_id = {
            int(row.id or 0): row
            for row in current_rows
            if row.id is not None
        }
        # Released listings can coexist with later invitations for the same
        # mailbox.  An email/time lower bound alone cannot uniquely assign a
        # sale to those cycles.  Include even sold/unlisted cycles in this
        # check, inside the write transaction, so an old listing cannot claim
        # the newer cycle's order (or a cycle created during the NV request).
        normalized_membership_email = func.lower(func.trim(
            func.coalesce(GptBusinessChildMembershipModel.email, "")
        ))
        cycle_counts = dict(session.exec(
            select(
                normalized_membership_email,
                func.count(GptBusinessChildMembershipModel.id),
            ).where(
                normalized_membership_email.in_(sorted({
                    email for email, _, _ in expected.values()
                }))
            ).group_by(normalized_membership_email)
        ).all())
        unverified_legacy = 0
        for membership_id, (expected_email, expected_floor, expected_confirmation) in expected.items():
            membership = current_by_id.get(membership_id)
            current_floor = (
                _aware_utc(getattr(membership, "nv_listed_at", None))
                or _aware_utc(membership.invited_at)
                if membership is not None else None
            )
            if (
                membership is None
                or (
                    str(membership.sale_status or "").strip().lower(),
                    _aware_utc(membership.sold_at),
                    str(membership.nv_remote_card_id or ""),
                    str(membership.nv_remote_order_id or ""),
                ) != expected_state[membership_id]
                or _normalized_email(membership.email) != expected_email
                or current_floor != expected_floor
                or _aware_utc(membership.nv_listing_confirmed_at) != expected_confirmation
            ):
                skipped_changed += 1
                details.append({
                    "membership_id": membership_id,
                    "email": expected_email,
                    "status": "skipped_changed",
                    "reason": "查询期间本地记录已删除、邮箱或上架信息已变化，本次已跳过，请刷新后重新核对",
                })
                continue
            # Refund evidence must win over stale cards.status=sold.  The
            # shared policy binds order/card/sold time to this listing cycle;
            # an incomplete current-cycle refund must never fall back to sale.
            if getattr(snapshot, "refund_records", ()):
                try:
                    refund = match_cycle_refund(
                        snapshot, email=expected_email,
                        remote_order_id=membership.nv_remote_order_id,
                        remote_card_id=membership.nv_remote_card_id,
                        sold_at=membership.sold_at, listed_at=membership.nv_listed_at,
                    )
                    if refund is not None:
                        if not apply_membership_refund(session, membership, refund):
                            raise ValueError("NV 退款与当前成员的订单或上架周期不一致")
                        if membership.sale_status == "refunded":
                            updated_refunded += 1
                        else:
                            updated_partial_refund += 1
                        details.append({
                            "membership_id": membership_id, "email": expected_email,
                            "status": membership.sale_status,
                            "reason": "NV 已确认本次订单全额退款，保留原出售记录" if refund["full_refund"]
                                else "NV 已确认部分退款，保留原出售与质保记录，等待处理",
                        })
                        continue
                except ValueError as exc:
                    remaining_counts["needs_review"] += 1
                    details.append({"membership_id": membership_id, "email": expected_email,
                                    "status": "needs_review", "reason": str(exc)})
                    continue
            # A confirmed sale is immutable under email-only inventory
            # fallback. Rechecking it discovers refunds, not a newer order.
            if membership.sale_status in {"sold", "partial_refund"}:
                details.append({
                    "membership_id": membership_id, "email": expected_email,
                    "status": membership.sale_status,
                    "reason": "本次未发现该订单的新退款，保留已确认的 NV 出售记录"
                        if membership.sale_status == "sold" else "NV 部分退款，等待处理",
                })
                continue
            record = matched.get(membership_id)
            if record is not None and cycle_counts.get(expected_email, 0) > 1:
                record = None
                remaining_states[membership_id] = (
                    "needs_review",
                    "同一邮箱存在多条本地邀请/上架记录，无法唯一确认本次出库归属；保留本地已上架状态，请人工核对",
                )
            absolute_until = _aware_utc(membership.nv_team5x_warranty_until)
            if record is not None:
                remote_until = _aware_utc(getattr(record, "team5x_warranty_until", None))
                inventory_terms = [item for item in inventory_by_email.get(expected_email, ())
                                   if getattr(item, "team5x_warranty_until", None) is not None]
                inventory_until = None
                inventory_ambiguous = False
                if inventory_terms:
                    # A missing order deadline is not the old one-hour plan
                    # when inventory reports absolute terms. Learn them only
                    # from one fully read, independently identified sale.
                    inventory_ambiguous = not inventory_complete or len(inventory_terms) != 1
                    if not inventory_ambiguous:
                        item = inventory_terms[0]
                        card = _safe_business_remote_identifier(record.remote_card_id)
                        order = _safe_business_remote_identifier(record.remote_order_id)
                        inventory_card = _safe_business_remote_identifier(item.remote_card_id)
                        inventory_order = _safe_business_remote_identifier(item.remote_order_id)
                        inventory_sold_at = _aware_utc(item.sold_at)
                        # Inventory IDs and order-card IDs can differ. Only
                        # the client's complete three-source identity proof
                        # can establish an alias between those namespaces.
                        links = [link for link in snapshot.card_identity_links
                                 if link.email == expected_email and link.sold_at == record.sold_at
                                 and link.remote_order_id == order
                                 and card in {link.inventory_card_id, link.order_card_id}
                                 and inventory_card in {link.inventory_card_id, link.order_card_id}
                                 and item.inventory_card_id == link.inventory_card_id
                                 and (not item.explicit_card_id or item.explicit_card_id == link.order_card_id)]
                        same_card = bool(card and inventory_card and card == inventory_card) or len(links) == 1
                        same_order = bool(order and inventory_order and order == inventory_order)
                        inventory_ambiguous = (
                            item.status != "sold" or not (same_card or same_order)
                            or (bool(card and inventory_card) and not same_card)
                            or (bool(order and inventory_order) and not same_order)
                            or (inventory_sold_at is not None and inventory_sold_at != record.sold_at)
                            or (inventory_sold_at is None and not same_order)
                        )
                        if not inventory_ambiguous:
                            inventory_until = _aware_utc(item.team5x_warranty_until)
                deadlines = {value for value in (remote_until, absolute_until, inventory_until) if value is not None}
                deadline = next(iter(deadlines), None)
                if (inventory_ambiguous or len(deadlines) > 1
                        or (deadline and (deadline <= expected_floor or deadline < record.sold_at))):
                    record = None
                    remaining_states[membership_id] = (
                        "needs_review", "NV 5X 质保截止时间与本次上架或出售记录不一致，未推断过保",
                    )
                else:
                    absolute_until = deadline
            if expected_confirmation is None:
                # nv_listed_at used to be set by the manual sale editor too.
                # Upgrade that legacy hint only after unique remote evidence;
                # mere absence must never inflate the NV missing count.
                inventory = inventory_by_email.get(expected_email, ())
                available_cards = [item for item in inventory if item.status == "available"]
                if cycle_counts.get(expected_email, 0) == 1 and (
                    record is not None or len(available_cards) == 1
                ):
                    membership.nv_listing_confirmed_at = sync_now
                    if record is None:
                        membership.nv_remote_card_id = _safe_business_remote_identifier(
                            available_cards[0].remote_card_id
                        )
                else:
                    unverified_legacy += 1
                    legacy_rows.append({"membership_id": membership_id, "email": expected_email})
                    continue
            membership.nv_last_synced_at = sync_now
            if record is None:
                unchanged_listed += 1
                detail_status, detail_reason = remaining_states[membership_id]
                remaining_counts[detail_status] += 1
            else:
                membership.sale_status = "sold"
                membership.sold_at = record.sold_at
                membership.nv_team5x_warranty_until = absolute_until
                membership.warranty_hours = 0 if absolute_until else 1
                membership.nv_remote_card_id = _safe_business_remote_identifier(
                    record.remote_card_id
                )
                membership.nv_remote_order_id = _safe_business_remote_identifier(
                    record.remote_order_id
                )
                updated_sold += 1
                if (absolute_until or record.sold_at + timedelta(hours=1)) <= sync_now:
                    deletion_ready += 1
                detail_status = "sold"
                detail_reason = "NV 已确认本次上架后的出售记录，本地已更新为已出售"
            details.append({
                "membership_id": membership_id,
                "email": expected_email,
                "status": detail_status,
                "reason": detail_reason,
            })
            membership.updated_at = sync_now
            session.add(membership)
        session.commit()

    return {
        "ok": True,
        "listed_candidates": len(memberships),
        "checked_listed": len(expected) - skipped_changed - unverified_legacy,
        "listed_checked": len(expected) - skipped_changed - unverified_legacy,
        "updated_sold": updated_sold,
        "updated_refunded": updated_refunded,
        "updated_partial_refund": updated_partial_refund,
        "sold_found": updated_sold,
        "sold_updated": updated_sold,
        "updated": updated_sold + updated_refunded + updated_partial_refund,
        "unchanged_listed": unchanged_listed,
        "unmatched": unchanged_listed + invalid_local,
        **remaining_counts,
        "details": sorted(details, key=lambda item: item["membership_id"]),
        "deletion_ready": deletion_ready,
        "skipped_changed": skipped_changed,
        "invalid_local": invalid_local,
        "remote_orders": int(snapshot.order_count),
        "remote_sold_cards": int(snapshot.sold_card_count),
        "remote_sales": len(snapshot.sold_records),
        "pages_fetched": int(snapshot.pages_fetched),
        "synced_at": _iso_utc(sync_now),
        **_business_child_nv_legacy_result(legacy_rows),
    }


def _business_device_facade_binding(
    account_id: int,
    *,
    mutation: bool = False,
) -> _MemberSourceBinding:
    """Resolve a plan row to its exact BUSINESS mother before device actions.

    The browser never gets authority merely by retaining a numeric source id.
    Re-resolving the plan row also verifies source pool and normalized email;
    mutating calls additionally reject a mother already in a refund lifecycle.
    """
    binding, member_source = _resolve_member_source_binding(int(account_id))
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "只有 GPT BUSINESS 母号支持绑定设备")
    current = _assert_member_source_binding_current(binding)
    if mutation and str(current.get("refund_status") or "").strip():
        raise HTTPException(409, "退款流程中的 BUSINESS 母号不能修改设备绑定")
    return binding


def _strict_business_binding_revision(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2_147_483_647
    ):
        raise HTTPException(400, "expected_policy_revision 无效")
    return int(value)


def _strict_business_binding_query_revision(value: Any) -> int:
    """Parse an HTTP query revision without accepting float-like coercions."""
    if isinstance(value, int) and not isinstance(value, bool):
        return _strict_business_binding_revision(value)
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)",
        value,
    ):
        raise HTTPException(400, "expected_policy_revision 无效")
    try:
        parsed = int(value)
    except ValueError:
        raise HTTPException(400, "expected_policy_revision 无效") from None
    return _strict_business_binding_revision(parsed)


def _member_business_device_binding_snapshot(
    account_id: int,
    *,
    resolved: Optional[_MemberSourceBinding] = None,
) -> dict[str, Any]:
    """Compose one credential-free, local-only mother binding snapshot."""
    source_binding = resolved or _business_device_facade_binding(account_id)
    parent_id = int(source_binding.source_account_id)
    from api.delivery_devices import (
        _business_binding_eligibility,
        _refunded_business_parent_ids,
    )

    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, parent_id)
        if (
            parent is None
            or _normalized_email(parent.email)
            != source_binding.normalized_email
        ):
            raise HTTPException(409, "BUSINESS 母号身份已变化，请刷新套餐目录")
        current = _business_device_binding_map(session, {parent_id})[parent_id]
        eligibility = _business_binding_eligibility(
            parent,
            refunded_parent_ids=_refunded_business_parent_ids(session),
        )
        devices = _business_device_binding_options(session)

    binding = {
        **current,
        "device_name": str(current.get("name") or ""),
        "eligible_for_new_binding": bool(eligibility.get("eligible")),
        "can_bind": bool(eligibility.get("eligible")),
        "can_unbind": bool(current.get("bound")),
        "can_retain_or_remove": bool(current.get("bound")),
        "binding_blockers": list(eligibility.get("blockers") or []),
    }
    current_ref = str(binding.get("device_ref") or "")
    if current_ref and not any(
        str(item.get("device_ref") or "") == current_ref for item in devices
    ):
        # Keep a deleted registry target visible as the selected value so the
        # operator can still understand and remove the durable stale binding.
        devices.append({
            "device_ref": current_ref,
            "provider": str(binding.get("provider") or ""),
            "device_id": binding.get("device_id"),
            "name": str(binding.get("device_name") or ""),
            "device_name": str(binding.get("device_name") or ""),
            "state": str(binding.get("state") or "missing"),
            "enabled": False,
        })
    devices.sort(key=lambda item: (
        str(item.get("provider") or ""),
        int(item.get("device_id") or 0),
    ))
    blockers = list(binding["binding_blockers"])
    return {
        "ok": True,
        "account_id": int(account_id),
        "business_account_id": parent_id,
        "parent_id": parent_id,
        "binding": binding,
        # Stable aliases ease the transition from the list-row DTO without
        # widening either object with credentials or automation state.
        "current_binding": dict(binding),
        "business_device_binding": dict(binding),
        "devices": devices,
        "eligible_for_new_binding": bool(binding["eligible_for_new_binding"]),
        "can_bind": bool(binding["can_bind"]),
        "can_unbind": bool(binding["can_unbind"]),
        "binding_blockers": blockers,
        "policy_revision": int(binding.get("policy_revision") or 0),
    }


@router.get("/accounts/{account_id}/business-device-binding")
def get_member_business_device_binding(account_id: int):
    """Read one BUSINESS mother's local delivery-device binding."""
    return _member_business_device_binding_snapshot(account_id)


@router.put("/accounts/{account_id}/business-device-binding")
def put_member_business_device_binding(
    account_id: int,
    body: GptPlanBusinessDeviceBindingPutRequest,
):
    """Bind or switch one mother through the canonical device CRUD/CAS path."""
    source_binding = _business_device_facade_binding(account_id)
    revision = _strict_business_binding_revision(body.expected_policy_revision)
    if not isinstance(body.device_ref, str):
        raise HTTPException(400, "device_ref 无效")
    requested_ref = body.device_ref.strip()
    if not requested_ref or len(requested_ref) > 100:
        raise HTTPException(400, "device_ref 无效")

    parent_id = int(source_binding.source_account_id)
    from api.delivery_devices import bind_business_parent_delivery_device

    mutation = bind_business_parent_delivery_device(
        parent_id,
        device_ref=requested_ref,
        expected_revision=revision,
        expected_plan_account_id=int(source_binding.plan_account_id),
        expected_plan_email=source_binding.normalized_email,
    )
    _assert_member_source_binding_current(source_binding)
    result = _member_business_device_binding_snapshot(
        account_id,
        resolved=source_binding,
    )
    result["changed"] = bool(mutation.get("changed"))
    result["moved"] = bool(mutation.get("moved"))
    return result


@router.delete("/accounts/{account_id}/business-device-binding")
def delete_member_business_device_binding(
    account_id: int,
    expected_policy_revision: Any = Query(...),
):
    """Unbind the current local policy, including a missing-device binding."""
    source_binding = _business_device_facade_binding(account_id)
    revision = _strict_business_binding_query_revision(
        expected_policy_revision
    )
    from api.delivery_devices import unbind_business_parent_delivery_binding

    mutation = unbind_business_parent_delivery_binding(
        int(source_binding.source_account_id),
        expected_revision=revision,
        expected_plan_account_id=int(source_binding.plan_account_id),
        expected_plan_email=source_binding.normalized_email,
    )
    _assert_member_source_binding_current(source_binding)
    result = _member_business_device_binding_snapshot(
        account_id,
        resolved=source_binding,
    )
    result["removed"] = bool(mutation.get("removed"))
    return result


def member_business_device_binding_options(account_id: int):
    binding = _business_device_facade_binding(account_id, mutation=True)
    from api.gpt_business import business_device_binding_options

    return business_device_binding_options(int(binding.source_account_id))


def member_business_device_migration_preview(
    account_id: int,
    target_device_ref: str = Query(...),
):
    binding = _business_device_facade_binding(account_id, mutation=True)
    from api.gpt_business import preview_business_device_binding_migration

    return preview_business_device_binding_migration(
        int(binding.source_account_id),
        str(target_device_ref or ""),
    )


def member_start_business_device_migration(
    account_id: int,
    body: GptPlanBusinessDeviceMigrationRequest,
):
    binding = _business_device_facade_binding(account_id, mutation=True)
    from api.gpt_business import (
        BizDeviceBindingMigrationRequest,
        start_business_device_binding_migration,
    )

    revision = body.expected_policy_revision
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 0
        or revision > 2_147_483_647
    ):
        raise HTTPException(400, "expected_policy_revision 无效")
    return start_business_device_binding_migration(
        int(binding.source_account_id),
        BizDeviceBindingMigrationRequest(
            operation_id=str(body.operation_id or ""),
            target_device_ref=str(body.target_device_ref or ""),
            expected_policy_revision=revision,
        ),
    )


def member_list_business_device_migrations(
    account_id: int,
    active_only: bool = True,
    operation_id: str = Query(""),
    limit: int = Query(20, ge=1, le=100),
):
    binding = _business_device_facade_binding(account_id)
    from api.gpt_business import list_business_device_binding_migrations

    return list_business_device_binding_migrations(
        int(binding.source_account_id),
        active_only=bool(active_only),
        operation_id=str(operation_id or ""),
        limit=int(limit),
    )


def member_get_business_device_migration(
    account_id: int,
    job_id: str,
):
    binding = _business_device_facade_binding(account_id)
    from api.gpt_business import get_business_device_binding_migration

    return get_business_device_binding_migration(
        int(binding.source_account_id),
        str(job_id),
    )


@router.get("/accounts/{account_id}/business-child-candidates")
def member_business_child_candidates(
    account_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=500),
    candidate_mail_provider: str = "auto",
    seat_type: str = "",
):
    """List the never-invited GPT Plans ordinary pool without source secrets."""
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
    )
    from core.business_invite_mail_provider import resolve_candidate_mail_provider
    with Session(engine) as session:
        requested_provider = resolve_candidate_mail_provider(
            _strict_business_candidate_mail_provider(candidate_mail_provider), seat_type, session=session,
        )
        parent = session.get(GptBusinessAccountModel, int(binding.source_account_id))
        if (
            parent is None
            or _normalized_email(parent.email) != binding.normalized_email
        ):
            raise HTTPException(409, "BUSINESS 工作区绑定已变化，请刷新后重试")
        records = _plan_business_candidate_records(
            session,
            int(binding.source_account_id),
            candidate_mail_provider=requested_provider,
        )
        total = len(records)
        start = (page - 1) * page_size
        rows = records[start:start + page_size]
        items = [
            {
                **_safe_business_child_candidate(
                    row["child"],
                    plan_account_id=int(row.get("plan_account_id") or 0),
                ),
                "candidate_source": row.get("candidate_source", "regular"),
                "prepared": row.get("prepared") is True,
            }
            for row in rows
        ]
    _assert_member_source_binding_current(binding)
    return {
        "ok": True,
        "account_id": int(account_id),
        "total": max(0, total),
        "page": int(page),
        "page_size": int(page_size),
        "candidate_mail_provider": requested_provider,
        "items": items,
    }


def _business_mutation_snapshot_after_source_call(
    binding: _MemberSourceBinding,
) -> tuple[Optional[dict[str, Any]], bool]:
    """Do not orphan an irreversible source call if the directory is rebound."""
    try:
        _assert_member_source_binding_current(binding)
    except HTTPException:
        return None, True
    return _business_children_snapshot(binding), False


def _resolve_plan_business_invite_target(
    binding: _MemberSourceBinding,
    *,
    pro_account_id: Optional[int],
    manual_email: str,
    candidate_mail_provider: str = "auto",
    existing_selection: bool = False,
) -> tuple[Optional[int], str, bool, str]:
    """Resolve this facade call's target; return child/email/auto/origin."""
    if pro_account_id is not None and manual_email:
        raise HTTPException(400, "pro_account_id 与 manual_email 只能选择一个")
    requested_provider = _strict_business_candidate_mail_provider(
        candidate_mail_provider
    )
    if manual_email and requested_provider != "auto":
        raise HTTPException(
            400,
            "手动邮箱邀请不能指定 candidate_mail_provider",
        )
    # Persisted capacity is display state, not an invitation admission fence.
    # The source capability reads the live workspace under its parent lease and
    # can also statelessly attach a target already accepted by OpenAI when the
    # cached snapshot (correctly) says the workspace is now full.
    with Session(engine) as session:
        parent = session.get(GptBusinessAccountModel, int(binding.source_account_id))
        if parent is None:
            raise HTTPException(409, "BUSINESS 工作区绑定已变化")
        if manual_email:
            from services.workspace_accounts import require_gmail_alias
            from services.gmail_store import GmailStoreError
            try:
                require_gmail_alias(session, manual_email)
            except GmailStoreError as exc:
                raise HTTPException(exc.status_code, exc.message) from None
            if manual_email == _normalized_email(parent.email):
                raise HTTPException(409, "不能邀请母号自身邮箱")
            active = session.exec(
                select(GptBusinessChildMembershipModel)
                .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
                .where(func.lower(GptBusinessChildMembershipModel.email) == manual_email)
            ).first()
            if active is not None:
                raise HTTPException(409, "该邮箱已经是某个 BUSINESS 母号的成员或待邀请")
            retired = session.exec(
                select(GptBusinessChildMembershipModel.id)
                .where(GptBusinessChildMembershipModel.ended_at.is_not(None))  # type: ignore[union-attr]
                .where(func.lower(func.trim(
                    GptBusinessChildMembershipModel.email
                )) == manual_email)
                .limit(1)
            ).first()
            if retired is not None:
                raise HTTPException(409, "该邮箱已退出可邀请普通账号池")
            known = session.exec(
                select(GptPlanAccountModel)
                .where(func.lower(GptPlanAccountModel.email) == manual_email)
                .order_by(col(GptPlanAccountModel.id).desc())
            ).first()
            from services.gmail_plan_support import gmail_registration_ready
            if known is None or not gmail_registration_ready(known):
                raise HTTPException(409, "手动邀请仅支持已完成登录核验且收件可用的 Gmail 子号，请先在普通账号中登录核验")
            if known is not None and (
                not bool(known.enabled)
                or bool(known.dangerous)
                or bool(known.policy_warning)
                or bool(str(known.refund_status or "").strip())
                or bool(_safe_json_list(known.pending_alerts_json))
            ):
                raise HTTPException(409, "该邮箱已在账号库标记为停用、告警或退款状态")
            return None, manual_email, False, "manual"

        records = _plan_business_candidate_records(
            session,
            int(binding.source_account_id),
            candidate_mail_provider=requested_provider,
            require_registration=not existing_selection,
        )
        allowed = {
            int(record["child"].id): record
            for record in records
            if record.get("child") is not None
            and getattr(record["child"], "id", None) is not None
        }
        if pro_account_id is not None:
            if pro_account_id not in allowed:
                raise HTTPException(
                    409,
                    "所选普通账号已不在当前邮箱类型的可邀请候选范围",
                )
            return pro_account_id, "", False, "plan_regular"
        if not records:
            raise HTTPException(409, "暂无符合条件且从未被邀请过的 GPT 套餐普通账号")
        # Do not freeze the first row in this facade. The BUSINESS mother owns
        # candidate claims and the pre-invite login; keeping auto mode intact
        # lets it mark an explicitly deactivated candidate Dead and atomically
        # continue with the next eligible ordinary account.
        return None, "", True, "plan_regular_auto"


def _assert_plan_business_invite_expected_target(
    expected: Optional[dict[str, Any]],
    binding: _MemberSourceBinding,
    *,
    pro_account_id: Optional[int],
    manual_email: str,
    candidate_mail_provider: str = "auto",
) -> None:
    """Validate an internal durable invite target without selecting a new row."""
    if expected is None:
        return
    changed = "自动邀请目标的母号或子号身份已变化，未发送邀请"
    if not isinstance(expected, dict):
        raise HTTPException(409, changed)
    parent_id = _internal_expected_positive(expected.get("parent_account_id"))
    source_id = _internal_expected_positive(expected.get("source_account_id"))
    child_id = _internal_expected_positive(expected.get("child_id"))
    parent_email = _normalized_email(expected.get("parent_email"))
    email = _safe_business_child_email(expected.get("email"))
    if (
        not all((parent_id, source_id, child_id))
        or not parent_email
        or not email
        or email == parent_email
        or manual_email
        or pro_account_id != child_id
        or binding.plan_account_id != parent_id
        or binding.source_pool != "gpt_business"
        or binding.source_account_id != source_id
        or binding.normalized_email != parent_email
    ):
        raise HTTPException(409, changed)
    from api import gpt_business

    requested_provider = _strict_business_candidate_mail_provider(
        candidate_mail_provider
    )
    with Session(engine) as session:
        parent = session.get(GptPlanAccountModel, parent_id)
        source = session.get(GptBusinessAccountModel, source_id)
        child = session.get(GptPlanAccountModel, child_id)
        active_membership = session.exec(
            select(GptBusinessChildMembershipModel.id)
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .where(or_(
                GptBusinessChildMembershipModel.pro_account_id == child_id,
                func.lower(func.trim(GptBusinessChildMembershipModel.email))
                == email,
            ))
            .limit(1)
        ).first()
        if (
            parent is None
            or source is None
            or child is None
            or str(parent.source_pool or "") != "gpt_business"
            or int(parent.source_account_id or 0) != source_id
            or _normalized_email(parent.email) != parent_email
            or _normalized_email(source.email) != parent_email
            or _normalized_email(child.email) != email
            or child.business_parent_id is not None
            or active_membership is not None
            # Revalidate the selected row directly.  Do not reuse the regular
            # candidate query here: the source invitation intentionally owns
            # this child's operation lease at this point, so that query would
            # exclude the legitimate in-flight target as "busy".
            or not gpt_business._is_business_child_candidate(child)
            or not _plan_account_has_business_login_credentials(child)
            or not gpt_business._business_child_matches_candidate_mail_provider(
                child, requested_provider,
            )
            or gpt_business._business_child_has_completed_history(
                session,
                child_id=child_id,
                email=email,
            )
        ):
            raise HTTPException(409, changed)


@router.post("/accounts/{account_id}/business-invite")
def member_business_invite(
    account_id: int,
    body: GptPlanBusinessChildInviteRequest,
):
    """Invite one pool child; the source derives the exact remaining seat type."""
    def state_check() -> None:
        if callable(body._state_guard) and body._state_guard() is False:
            raise HTTPException(409, "邀请托管状态已变化，已停止后续动作")

    state_check()
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
        preflight_session=True,
    )
    operation_id = (
        _strict_business_facade_operation_id(body.operation_id)
        if str(body.operation_id or "").strip()
        else f"plans-invite-{uuid.uuid4().hex}"
    )
    pro_account_id = _strict_optional_business_child_id(
        body.pro_account_id,
        "pro_account_id",
    )
    manual_email = _strict_optional_business_manual_email(body.manual_email)
    candidate_mail_provider = _strict_business_candidate_mail_provider(
        body.candidate_mail_provider
    )
    pro_account_id, manual_email, auto_selected, candidate_origin = (
        _resolve_plan_business_invite_target(
            binding,
            pro_account_id=pro_account_id,
            manual_email=manual_email,
            candidate_mail_provider=candidate_mail_provider,
            existing_selection=isinstance(body._expected_target, dict),
        )
    )
    raw_expected_target = body._expected_target
    expected_target = (
        dict(raw_expected_target)
        if isinstance(raw_expected_target, dict)
        else raw_expected_target
    )
    _assert_plan_business_invite_expected_target(
        expected_target,
        binding,
        pro_account_id=pro_account_id,
        manual_email=manual_email,
        candidate_mail_provider=candidate_mail_provider,
    )

    expected_check: Optional[Callable[[], None]] = None
    if expected_target is not None or callable(body._state_guard):
        # The source capability may spend minutes in a candidate login before
        # taking its mutation lock. Re-resolve the same candidate inside that
        # lock immediately before its remote POST; never substitute another.
        def expected_check() -> None:
            state_check()
            current_binding, _ = _business_child_facade_binding(
                int(account_id),
                require_action=True,
            )
            _assert_plan_business_invite_expected_target(
                expected_target,
                current_binding,
                pro_account_id=pro_account_id,
                manual_email=manual_email,
                candidate_mail_provider=candidate_mail_provider,
            )

    from api import gpt_business

    try:
        invite_kwargs: dict[str, Any] = {
            "prelogin_pro_account_ids": (
                [int(pro_account_id)]
                if pro_account_id is not None
                and candidate_origin == "plan_regular"
                else None if auto_selected else []
            ),
        }
        if expected_check is not None:
            invite_kwargs["_pre_remote_check"] = expected_check
        if callable(body._log_fn):
            invite_kwargs["_prelogin_log_fn"] = body._log_fn
        if callable(body._selection_observer):
            invite_kwargs["_selection_observer"] = body._selection_observer
        if callable(body._invite_progress_fn):
            invite_kwargs["_invite_progress_fn"] = body._invite_progress_fn
        source_body = gpt_business.BizInviteMemberRequest(
                emails=[manual_email] if manual_email else [],
                pro_account_ids=[pro_account_id] if pro_account_id is not None else [],
                pool_mode=bool(auto_selected or pro_account_id is not None),
                candidate_mail_provider=candidate_mail_provider,
                # Never accept a client-provided type.  The source endpoint performs
                # one exact live typed-capacity read while holding the parent fence.
                seat_type="",
                operation_id=operation_id,
            )
        source_body._expected_seat_type = str(body._expected_seat_type or "")
        source_body._existing_selection = isinstance(body._expected_target, dict)
        raw = gpt_business.invite_member_biz_for_plan_facade(
            int(binding.source_account_id), source_body,
            **invite_kwargs,
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    state_check()
    safe = _safe_business_child_mutation_result(
        raw,
        operation_id=operation_id,
    )
    raw_auto_selected_id = (
        int(raw.get("auto_selected_pro_account_id") or 0)
        if isinstance(raw, dict)
        else 0
    )
    if auto_selected and raw_auto_selected_id > 0:
        safe["auto_selected_pro_account_id"] = raw_auto_selected_id
    children, binding_changed = _business_mutation_snapshot_after_source_call(binding)
    _confirm_business_child_persistence(
        safe,
        children,
        expected_manual_email=manual_email,
    )
    raw_prelogin_required_ids = (
        raw.get("prelogin_browser_required_pro_account_ids")
        if isinstance(raw, dict)
        and isinstance(
            raw.get("prelogin_browser_required_pro_account_ids"), list,
        )
        else None
    )
    effective_pro_account_id = (
        int(pro_account_id)
        if pro_account_id is not None
        else raw_auto_selected_id if raw_auto_selected_id > 0 else None
    )
    safe["prelogin_required"] = bool(
        effective_pro_account_id is not None
        and candidate_origin in {"plan_regular", "plan_regular_auto"}
        and (
            raw_prelogin_required_ids is None
            or int(effective_pro_account_id) in {
                int(item) for item in raw_prelogin_required_ids
                if isinstance(item, int)
                and not isinstance(item, bool)
                and item > 0
            }
        )
    )
    # A regular candidate cannot reach the remote mutation unless the source
    # layer completed its pre-login under the child operation lease. A source
    # success therefore implies pre-login completed even if an older compatible
    # source response omitted the explicit completion list.
    safe["prelogin_completed"] = bool(
        safe["prelogin_required"]
        and (
            int(effective_pro_account_id) in {
                int(item)
                for item in (
                    raw.get("prelogin_completed_pro_account_ids", [])
                    if isinstance(raw, dict)
                    else []
                )
                if isinstance(item, int)
                and not isinstance(item, bool)
                and item > 0
            }
            or bool(safe.get("ok"))
            or bool(safe.get("action_required"))
        )
    )

    # The invite facade ends at the source-owned invitation checkpoint.
    # Joining the workspace and acquiring RT are explicit child operations;
    # starting them here made a successful invite depend on a second browser
    # workflow and gave GPT Plans a second implementation of BUSINESS
    # onboarding.  The caller may start RT through the dedicated child route
    # after this response has confirmed the persisted membership.
    safe.update({
        "account_id": int(account_id),
        "binding_changed": binding_changed,
        "business_children": children,
        "invite_quota": (
            children.get("invite_quota") if isinstance(children, dict) else None
        ),
    })
    return safe


_BUSINESS_BATCH_INVITE_TASKS: dict[str, dict[str, Any]] = {}
_BUSINESS_BATCH_INVITE_TASK_LOCK = threading.RLock()
_BUSINESS_BATCH_INVITE_RUN_LOCK = threading.Lock()
_PREPARED_BATCH_PARENT_LOCKS: dict[int, threading.Lock] = {}
_BUSINESS_BATCH_INVITE_RETAIN_SECONDS = 2 * 60 * 60
_BUSINESS_BATCH_INVITE_MAX_FINISHED = 50
_BUSINESS_BATCH_INVITE_MAX_TARGETS = 500
_BUSINESS_BATCH_INVITE_MAX_PER_MOTHER = 1_000
_BUSINESS_BATCH_INVITE_MAX_TOTAL = 5_000
_BUSINESS_BATCH_INVITE_MAX_POST_ACTION_TOTAL = 100
_BUSINESS_BATCH_INVITE_MAX_LOGS = 4_000
_BUSINESS_BATCH_MOTHER_TERMINAL = frozenset({
    "done", "partial", "failed", "skipped",
})
_BUSINESS_BATCH_INVITE_TERMINAL = frozenset({
    "success", "partial", "failed", "skipped",
})
_BUSINESS_BATCH_MOTHER_LABELS = {
    "pending": "等待处理",
    "running": "正在邀请",
    "done": "邀请完成",
    "partial": "部分完成",
    "failed": "邀请失败",
    "skipped": "已跳过",
}
_BUSINESS_BATCH_INVITE_LABELS = {
    "pending": "等待邀请",
    "running": "正在邀请",
    "success": "邀请成功",
    "partial": "邀请成功，后处理部分失败",
    "failed": "邀请失败",
    "skipped": "已跳过",
}


def _persist_prepared_batch_task(task: dict[str, Any]) -> None:
    if str(task.get("workflow") or "") != "prepare_then_batch":
        return
    from services.prepared_batch_invite_store import save
    save(task)


def _prepared_batch_parent_lock(account_id: int) -> threading.Lock:
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        return _PREPARED_BATCH_PARENT_LOCKS.setdefault(int(account_id), threading.Lock())


def _strict_business_batch_account_ids(values: Any) -> list[int]:
    if not isinstance(values, list):
        raise HTTPException(400, "account_ids 必须是账号 ID 数组")
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise HTTPException(400, "account_ids 只能包含正整数账号 ID")
        if value in seen:
            continue
        seen.add(value)
        result.append(int(value))
    if len(result) > _BUSINESS_BATCH_INVITE_MAX_TARGETS:
        raise HTTPException(
            400,
            f"单次最多选择 {_BUSINESS_BATCH_INVITE_MAX_TARGETS} 个母号",
        )
    return result


def _business_invitable_seat_count(source: GptBusinessAccountModel) -> int:
    """Return the exact typed vacancy count from the persisted snapshot."""
    summary = _safe_business_seat_summary(source)
    if (
        not isinstance(summary, dict)
        or _business_seat_snapshot_bucket(source) != "available"
    ):
        return 0
    aggregate = summary.get("available")
    if (
        isinstance(aggregate, bool)
        or not isinstance(aggregate, int)
        or aggregate <= 0
    ):
        return 0
    typed_available = _exact_business_typed_available_counts(summary)
    if typed_available is None:
        return 0
    typed_total = sum(typed_available.values())
    return max(0, min(int(aggregate), typed_total))


def _business_invite_quota_for_source(
    session: Session,
    source_account_id: int,
    *, seat_type: Optional[str] = None,
) -> dict[str, Any]:
    """Read the authoritative source-mother invitation window."""
    from api.gpt_business import _invite_quota

    return _invite_quota(session, int(source_account_id), seat_type=seat_type)


def _resolve_business_batch_invite_targets(
    body: GptPlanBusinessBatchInviteRequest,
) -> tuple[list[dict[str, Any]], str]:
    """Validate authority and freeze target ids/capacity before worker start."""
    if not isinstance(body.select_all_matching, bool):
        raise HTTPException(400, "select_all_matching 必须是布尔值")
    requested_ids = _strict_business_batch_account_ids(body.account_ids)
    select_all = bool(body.select_all_matching)
    if select_all == bool(requested_ids):
        raise HTTPException(
            400,
            "account_ids 与 select_all_matching 必须且只能选择一种方式",
        )
    focus_account_id: Optional[int] = None
    if body.account_id is not None:
        if (
            isinstance(body.account_id, bool)
            or not isinstance(body.account_id, int)
            or body.account_id <= 0
        ):
            raise HTTPException(400, "account_id 必须是正整数")
        if not select_all:
            raise HTTPException(
                400,
                "显式 account_ids 模式不能同时指定 account_id",
            )
        focus_account_id = int(body.account_id)
    login_status = str(body.login_status or "").strip()
    if login_status not in {"", "logged_in", "not_logged_in"}:
        raise HTTPException(
            400,
            "login_status 只支持 logged_in 或 not_logged_in",
        )
    usage_filter = str(body.business_usage_type or "").strip()
    if usage_filter not in {"", *_BUSINESS_USAGE_FILTERS}:
        raise HTTPException(
            400,
            "business_usage_type 只支持 unassigned/sale/self_use/transit",
        )
    candidate_mail_provider = _strict_business_candidate_mail_provider(
        body.candidate_mail_provider
    )
    if not isinstance(body.post_setup_security, bool):
        raise HTTPException(400, "post_setup_security 必须是布尔值")
    if not isinstance(body.post_acquire_rt, bool):
        raise HTTPException(400, "post_acquire_rt 必须是布尔值")
    security_browser_mode = str(body.security_browser_mode or "").strip().lower()
    if security_browser_mode not in {"headless", "headed"}:
        raise HTTPException(
            400,
            "security_browser_mode 只支持 headless 或 headed",
        )
    keyword = str(body.keyword or "").strip()
    if len(keyword) > 320:
        raise HTTPException(400, "keyword 不能超过 320 个字符")

    with Session(engine) as session:
        available_source_ids = _business_source_ids_for_seat_filter(
            session,
            "available",
        )
        if not available_source_ids:
            raise HTTPException(409, "当前没有已确认可邀请席位的 BUSINESS 母号")
        plan_expr = func.lower(func.trim(func.coalesce(
            GptPlanAccountModel.plan_type,
            "",
        )))
        query = (
            select(GptPlanAccountModel)
            .join(
                GptBusinessAccountModel,
                GptBusinessAccountModel.id
                == GptPlanAccountModel.source_account_id,
            )
            .where(
                _catalog_category_predicate("member"),
                plan_expr.in_(tuple(_MEMBER_PLAN_TYPES["team"])),
                func.lower(func.trim(func.coalesce(
                    GptPlanAccountModel.source_pool,
                    "",
                ))) == "gpt_business",
                GptPlanAccountModel.source_account_id.in_(  # type: ignore[union-attr]
                    available_source_ids
                ),
                func.lower(func.trim(GptBusinessAccountModel.email))
                == func.lower(func.trim(GptPlanAccountModel.email)),
            )
        )
        if select_all:
            if focus_account_id is not None:
                query = query.where(
                    GptPlanAccountModel.id == focus_account_id
                )
            if keyword:
                query = query.where(
                    col(GptPlanAccountModel.email).contains(keyword)
                    | col(GptPlanAccountModel.note).contains(keyword)
                )
            if login_status == "logged_in":
                query = query.where(_has_saved_login_predicate())
            elif login_status == "not_logged_in":
                query = query.where(~_has_saved_login_predicate())
            if usage_filter == "unassigned":
                query = query.where(or_(
                    GptPlanAccountModel.business_usage_type.is_(None),  # type: ignore[union-attr]
                    GptPlanAccountModel.business_usage_type == "",
                    ~GptPlanAccountModel.business_usage_type.in_(  # type: ignore[union-attr]
                        tuple(_BUSINESS_USAGE_TYPES)
                    ),
                ))
            elif usage_filter:
                query = query.where(
                    GptPlanAccountModel.business_usage_type == usage_filter
                )
        else:
            query = query.where(
                GptPlanAccountModel.id.in_(requested_ids)  # type: ignore[union-attr]
            )
        rows = list(session.exec(
            query.order_by(col(GptPlanAccountModel.id).desc())
        ).all())
        if not select_all:
            by_id = {int(row.id or 0): row for row in rows}
            if any(account_id not in by_id for account_id in requested_ids):
                # Deliberately do not reveal which arbitrary id exists or why
                # it failed the exact BUSINESS binding/capacity boundary.
                raise HTTPException(
                    409,
                    "所选账号中存在非 BUSINESS 母号、绑定已变化或无可邀请席位",
                )
            rows = [by_id[account_id] for account_id in requested_ids]
        elif len(rows) > _BUSINESS_BATCH_INVITE_MAX_TARGETS:
            raise HTTPException(
                409,
                f"筛选结果超过 {_BUSINESS_BATCH_INVITE_MAX_TARGETS} 个母号，请缩小范围",
            )
        if not rows:
            raise HTTPException(409, "当前筛选条件下没有可批量邀请的 BUSINESS 母号")
        source_ids = {int(row.source_account_id or 0) for row in rows}
        sources = {
            int(source.id or 0): source
            for source in session.exec(
                select(GptBusinessAccountModel).where(
                    GptBusinessAccountModel.id.in_(sorted(source_ids))  # type: ignore[union-attr]
                )
            ).all()
        }
        targets: list[dict[str, Any]] = []
        for row in rows:
            account_id = int(row.id or 0)
            source_id = int(row.source_account_id or 0)
            source = sources.get(source_id)
            seat_invites = (
                _business_invitable_seat_count(source)
                if source is not None else 0
            )
            if seat_invites <= 0:
                raise HTTPException(409, "所选 BUSINESS 母号席位快照已变化")
            if seat_invites > _BUSINESS_BATCH_INVITE_MAX_PER_MOTHER:
                raise HTTPException(409, "母号席位快照异常，请先刷新席位")
            typed_slots = _exact_business_typed_available_counts(_safe_business_seat_summary(source) or {})
            planned = min(int(seat_invites), sum(typed_slots.values()))
            if planned <= 0:
                if select_all:
                    continue
                raise HTTPException(409, "所选 BUSINESS 母号没有可邀请席位")
            targets.append({
                "account_id": account_id,
                "source_account_id": source_id,
                "email": _normalized_email(row.email),
                "planned_invites": planned,
                "invite_quota": _safe_business_quota(
                    _business_invite_quota_for_source(session, source_id)
                ) or {},
            })

        total_invites = sum(int(item["planned_invites"]) for item in targets)
        if total_invites > _BUSINESS_BATCH_INVITE_MAX_TOTAL:
            raise HTTPException(
                409,
                f"单次批量任务最多处理 {_BUSINESS_BATCH_INVITE_MAX_TOTAL} 个邀请席位",
            )
        if (
            bool(body.post_setup_security or body.post_acquire_rt)
            and total_invites > _BUSINESS_BATCH_INVITE_MAX_POST_ACTION_TOTAL
        ):
            raise HTTPException(
                409,
                "启用邀请后处理时，单次最多处理 "
                f"{_BUSINESS_BATCH_INVITE_MAX_POST_ACTION_TOTAL} 个子号",
            )

    # Re-resolve each directory binding through the established facade after
    # the set query.  This prevents a stale/malformed row from reaching the
    # worker even if it happens to satisfy the SQL predicates.
    for target in targets:
        binding, _member_source = _business_child_facade_binding(
            int(target["account_id"]),
            require_action=False,
        )
        if (
            binding.source_pool != "gpt_business"
            or int(binding.source_account_id) != int(target["source_account_id"])
            or binding.normalized_email != str(target["email"])
        ):
            raise HTTPException(409, "BUSINESS 母号绑定已变化，请刷新后重试")
    return targets, candidate_mail_provider


def _prune_business_batch_invite_tasks_locked() -> None:
    cutoff = _utcnow() - timedelta(
        seconds=_BUSINESS_BATCH_INVITE_RETAIN_SECONDS
    )
    finished = []
    for task_id, task in _BUSINESS_BATCH_INVITE_TASKS.items():
        finished_at = str(task.get("finished_at") or "")
        if not finished_at:
            continue
        try:
            parsed = datetime.fromisoformat(finished_at)
            parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            parsed = datetime.min.replace(tzinfo=timezone.utc)
        finished.append((parsed, task_id))
    finished.sort(reverse=True)
    keep_ids = {
        task_id
        for parsed, task_id in finished[:_BUSINESS_BATCH_INVITE_MAX_FINISHED]
        if parsed >= cutoff
    }
    for _parsed, task_id in finished:
        if task_id not in keep_ids:
            _BUSINESS_BATCH_INVITE_TASKS.pop(task_id, None)


def _recompute_business_batch_progress_locked(task: dict[str, Any]) -> None:
    mothers = task.get("mothers")
    mothers = mothers if isinstance(mothers, list) else []
    invitations = [
        invitation
        for mother in mothers
        for invitation in (
            mother.get("invitations")
            if isinstance(mother, dict)
            and isinstance(mother.get("invitations"), list)
            else []
        )
        if isinstance(invitation, dict)
    ]
    total_invites = len(invitations)
    completed_invites = sum(
        str(item.get("status") or "") in _BUSINESS_BATCH_INVITE_TERMINAL
        for item in invitations
    )
    successful_invites = sum(
        str(item.get("status") or "") == "success"
        for item in invitations
    )
    failed_invites = sum(
        str(item.get("status") or "") == "failed"
        for item in invitations
    )
    partial_invites = sum(
        str(item.get("status") or "") == "partial"
        for item in invitations
    )
    skipped_invites = sum(
        str(item.get("status") or "") == "skipped"
        for item in invitations
    )
    completed_mothers = sum(
        str(mother.get("status") or "") in _BUSINESS_BATCH_MOTHER_TERMINAL
        for mother in mothers
        if isinstance(mother, dict)
    )
    percent = (
        int(completed_invites * 100 / total_invites)
        if total_invites > 0 else
        int(completed_mothers * 100 / len(mothers)) if mothers else 100
    )
    if str(task.get("status") or "") not in {"done", "failed"}:
        percent = min(99, percent)
    task["progress"] = {
        "total_mothers": len(mothers),
        "completed_mothers": completed_mothers,
        "total_invites": total_invites,
        "completed_invites": completed_invites,
        "successful_invites": successful_invites,
        "failed_invites": failed_invites,
        "partial_invites": partial_invites,
        "skipped_invites": skipped_invites,
        "percent": min(100, max(0, percent)),
    }
    for mother in mothers:
        if not isinstance(mother, dict):
            continue
        entries = mother.get("invitations")
        entries = entries if isinstance(entries, list) else []
        completed = sum(
            str(item.get("status") or "") in _BUSINESS_BATCH_INVITE_TERMINAL
            for item in entries if isinstance(item, dict)
        )
        mother["completed_invites"] = completed
        mother["successful_invites"] = sum(
            str(item.get("status") or "") == "success"
            for item in entries if isinstance(item, dict)
        )
        mother["failed_invites"] = sum(
            str(item.get("status") or "") == "failed"
            for item in entries if isinstance(item, dict)
        )
        mother["partial_invites"] = sum(
            str(item.get("status") or "") == "partial"
            for item in entries if isinstance(item, dict)
        )
        mother["skipped_invites"] = sum(
            str(item.get("status") or "") == "skipped"
            for item in entries if isinstance(item, dict)
        )
        mother_percent = (
            int(completed * 100 / len(entries)) if entries else 100
        )
        status = str(mother.get("status") or "pending")
        if status not in _BUSINESS_BATCH_MOTHER_TERMINAL:
            mother_percent = min(99, mother_percent)
        mother["percent"] = mother_percent
        mother["status_label"] = _BUSINESS_BATCH_MOTHER_LABELS.get(
            status,
            "未知状态",
        )
        for item in entries:
            if isinstance(item, dict):
                item_status = str(item.get("status") or "pending")
                item["status_label"] = _BUSINESS_BATCH_INVITE_LABELS.get(
                    item_status,
                    "未知状态",
                )
        current_index = mother.get("current_invite_index")
        if (
            isinstance(current_index, int)
            and not isinstance(current_index, bool)
            and 1 <= current_index <= len(entries)
            and isinstance(entries[current_index - 1], dict)
        ):
            mother["current_invite"] = dict(entries[current_index - 1])
        else:
            mother["current_invite"] = None
    _persist_prepared_batch_task(task)


def _business_batch_invite_log(task_id: str, message: Any) -> None:
    safe = _sanitize_member_task_text(message)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {safe}"
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        task = _BUSINESS_BATCH_INVITE_TASKS.get(str(task_id))
        if task is None:
            return
        logs = task.setdefault("logs", [])
        log_cursor = max(0, int(task.get("log_cursor") or len(logs)))
        log_start = max(
            0,
            int(task.get("log_start") or max(0, log_cursor - len(logs))),
        )
        logs.append(line)
        log_cursor += 1
        if len(logs) > _BUSINESS_BATCH_INVITE_MAX_LOGS:
            removed = len(logs) - _BUSINESS_BATCH_INVITE_MAX_LOGS
            task["logs"] = logs[removed:]
            log_start += removed
        task["log_start"] = log_start
        task["log_cursor"] = log_cursor
        _persist_prepared_batch_task(task)


def _business_batch_invite_error(value: Any) -> str:
    detail = getattr(value, "detail", None)
    if isinstance(detail, dict):
        raw = detail.get("message") or detail.get("detail") or detail.get("error")
    else:
        raw = detail
    return _sanitize_member_task_text(raw or value or "邀请失败")


def _public_business_batch_invite_task(
    task_id: str,
    *,
    since: int = 0,
) -> dict[str, Any]:
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        task = _BUSINESS_BATCH_INVITE_TASKS.get(str(task_id))
        if task is None:
            from services.prepared_batch_invite_store import load
            restored = load(str(task_id))
            if restored is not None:
                _BUSINESS_BATCH_INVITE_TASKS[str(task_id)] = restored
                task = restored
        if task is None:
            raise HTTPException(404, "批量邀请任务不存在或已过期")
        _recompute_business_batch_progress_locked(task)
        logs = list(task.get("logs") or [])
        mothers = json.loads(json.dumps(
            task.get("mothers") or [],
            ensure_ascii=False,
        ))
        progress = dict(task.get("progress") or {})
        log_cursor = max(0, int(task.get("log_cursor") or len(logs)))
        log_start = max(
            0,
            int(task.get("log_start") or max(0, log_cursor - len(logs))),
        )
        requested_cursor = min(log_cursor, max(0, int(since or 0)))
        offset = max(0, requested_cursor - log_start)
        candidate_mail_provider = str(
            task.get("candidate_mail_provider") or "auto"
        ).strip().lower()
        if candidate_mail_provider not in {"auto", "outlook", "icloud", "gmail"}:
            # The task creator stores only normalized values.  Keep the public
            # response fail-closed if an in-memory task is ever malformed.
            candidate_mail_provider = "auto"
        return {
            "ok": True,
            "task_id": str(task.get("task_id") or ""),
            "status": str(task.get("status") or "running"),
            "outcome": str(task.get("outcome") or ""),
            "has_failures": bool(task.get("has_failures")),
            "candidate_mail_provider": candidate_mail_provider,
            "workflow": str(task.get("workflow") or "sequential"),
            "phase": str(task.get("phase") or ""),
            "attempts": max(0, int(task.get("attempts") or 0)),
            "next_retry_at": str(task.get("next_retry_at") or ""),
            "seat_type": _safe_business_child_seat_type(task.get("seat_type")),
            "post_setup_security": bool(task.get("post_setup_security")),
            "post_acquire_rt": bool(task.get("post_acquire_rt")),
            "security_browser_mode": str(
                task.get("security_browser_mode") or "headless"
            ),
            "current_account_id": task.get("current_account_id"),
            "current_account_email": str(
                task.get("current_account_email") or ""
            ),
            "progress": progress,
            "mothers": mothers,
            "logs": [
                _sanitize_member_task_text(item) for item in logs[offset:]
            ],
            "since": log_cursor,
            "error": _sanitize_member_task_text(task.get("error") or ""),
            "started_at": str(task.get("started_at") or ""),
            "finished_at": str(task.get("finished_at") or ""),
        }


def _active_business_pool_membership_ids(account_id: int) -> set[int]:
    binding, _member_source = _business_child_facade_binding(
        int(account_id),
        require_action=False,
    )
    with Session(engine) as session:
        return {
            int(value)
            for value in session.exec(
                select(GptBusinessChildMembershipModel.id)
                .where(
                    GptBusinessChildMembershipModel.business_account_id
                    == int(binding.source_account_id)
                )
                .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
                .where(
                    func.lower(func.trim(GptBusinessChildMembershipModel.source))
                    == "pool"
                )
            ).all()
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
        }


def _resolve_persisted_batch_invited_child(
    account_id: int,
    before_membership_ids: set[int],
    result: dict[str, Any],
    *,
    action: Literal["setup_security", "oauth"] = "setup_security",
) -> dict[str, Any]:
    """Resolve the new child from DB ownership, using response ids only as hints."""
    binding, _member_source = _business_child_facade_binding(
        int(account_id),
        require_action=True,
    )
    hinted_child_ids = {
        int(value)
        for value in (
            result.get("auto_selected_pro_account_id"),
            result.get("resolved_new_pro_account_id"),
            *(result.get("managed_child_ids") or []),
        )
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    }
    hinted_emails = {
        _safe_business_child_email(value)
        for value in (result.get("invited") or [])
        if _safe_business_child_email(value)
    }
    with Session(engine) as session:
        rows = list(session.exec(
            select(GptBusinessChildMembershipModel, GptPlanAccountModel)
            .join(
                GptPlanAccountModel,
                GptPlanAccountModel.id
                == GptBusinessChildMembershipModel.pro_account_id,
            )
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(binding.source_account_id)
            )
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .where(
                func.lower(func.trim(GptBusinessChildMembershipModel.source))
                == "pool"
            )
            .where(
                GptPlanAccountModel.business_parent_id
                == int(binding.source_account_id)
            )
            .where(
                func.lower(func.trim(GptPlanAccountModel.email))
                == func.lower(func.trim(GptBusinessChildMembershipModel.email))
            )
            .order_by(col(GptBusinessChildMembershipModel.id).desc())
        ).all())

    new_rows = [
        (membership, child)
        for membership, child in rows
        if int(membership.id or 0) not in before_membership_ids
    ]
    candidates = new_rows
    if len(candidates) != 1 and hinted_child_ids:
        candidates = [
            (membership, child)
            for membership, child in rows
            if int(child.id or 0) in hinted_child_ids
        ]
    if len(candidates) != 1 and hinted_emails:
        candidates = [
            (membership, child)
            for membership, child in rows
            if _safe_business_child_email(child.email) in hinted_emails
        ]
    if len(candidates) != 1:
        raise HTTPException(
            409,
            "邀请已返回成功，但无法唯一确认新子号的持久成员关系",
        )
    membership, child = candidates[0]
    target = _resolve_business_child_batch_action_target(
        int(membership.id or 0),
        action,
    )
    if (
        int(target["parent_account_id"]) != int(account_id)
        or int(target["child_id"]) != int(child.id or 0)
    ):
        raise HTTPException(409, "新子号归属在后处理前发生变化")
    return target


def _business_batch_invite_step_update(
    task_id: str,
    mother_index: int,
    invite_index: int,
    step_name: str,
    *,
    status: str,
    label: str,
    error: str = "",
    task_ref: str = "",
) -> None:
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        task = _BUSINESS_BATCH_INVITE_TASKS.get(str(task_id))
        if task is None:
            return
        invitation = task["mothers"][mother_index]["invitations"][invite_index]
        step = invitation.setdefault("steps", {}).setdefault(step_name, {})
        if status == "running" and not str(step.get("started_at") or ""):
            step["started_at"] = _iso_utc(_utcnow())
        step.update({
            "status": status,
            "label": label,
            "error": _sanitize_member_task_text(error),
        })
        if task_ref:
            step["task_id"] = _safe_business_remote_identifier(task_ref)
        if status in {"success", "failed", "skipped"}:
            step["finished_at"] = _iso_utc(_utcnow())
        _persist_prepared_batch_task(task)


def _run_business_batch_invite_post_actions(
    task_id: str,
    mother_index: int,
    invite_index: int,
    target: dict[str, Any],
    *,
    post_setup_security: bool,
    post_acquire_rt: bool,
    security_browser_mode: str,
) -> list[str]:
    errors: list[str] = []
    email = str(target.get("email") or "")

    def emit(message: Any) -> None:
        _business_batch_invite_log(task_id, f"{email}：{message}")

    security_ok = True
    if post_setup_security:
        security_setting = False
        try:
            _business_batch_invite_step_update(
                task_id,
                mother_index,
                invite_index,
                "security",
                status="running",
                label="检查密码 / 2FA",
            )
            if _business_child_action_complete(target, "setup_security"):
                _business_batch_invite_step_update(
                    task_id,
                    mother_index,
                    invite_index,
                    "security",
                    status="skipped",
                    label="已完成，跳过设置",
                )
                emit("密码与 Authenticator 2FA 已完成，跳过重复设置")
            else:
                security_setting = True
                _business_batch_invite_step_update(
                    task_id,
                    mother_index,
                    invite_index,
                    "security",
                    status="running",
                    label="正在设置密码与 2FA",
                )
                launched = _start_member_business_child_security_setup_internal(
                    int(target["parent_account_id"]),
                    int(target["child_id"]),
                    browser_mode=security_browser_mode,
                    proxy=_resolve_proxy(None),
                )
                inner_task_id = str(launched.get("task_id") or "")
                snapshot = _wait_business_child_security_task(
                    inner_task_id,
                    emit=emit,
                )
                if (
                    str(snapshot.get("status") or "") != "done"
                    or not _business_child_action_complete(
                        target,
                        "setup_security",
                    )
                ):
                    raise RuntimeError(snapshot.get("error") or "密码与 2FA 设置失败")
                _business_batch_invite_step_update(
                    task_id,
                    mother_index,
                    invite_index,
                    "security",
                    status="success",
                    label="密码与 2FA 设置成功",
                    task_ref=inner_task_id,
                )
                emit("密码与 Authenticator 2FA 设置成功")
        except Exception as exc:
            security_ok = False
            error = _business_batch_invite_error(exc)
            errors.append(f"2FA：{error}")
            failure_label = (
                "密码与 2FA 设置失败" if security_setting else "密码 / 2FA 检查失败"
            )
            _business_batch_invite_step_update(
                task_id,
                mother_index,
                invite_index,
                "security",
                status="failed",
                label=failure_label,
                error=error,
            )
            emit(f"{failure_label}：{error}")

    if post_acquire_rt:
        if post_setup_security and not security_ok:
            _business_batch_invite_step_update(
                task_id,
                mother_index,
                invite_index,
                "rt",
                status="skipped",
                label="前置密码与 2FA 设置失败，未获取 RT",
                error="前置密码与 2FA 设置失败",
            )
        else:
            try:
                if _business_child_action_complete(target, "oauth"):
                    _business_batch_invite_step_update(
                        task_id,
                        mother_index,
                        invite_index,
                        "rt",
                        status="skipped",
                        label="RT 已存在",
                    )
                    emit("RT 已存在，跳过重复获取")
                else:
                    _business_batch_invite_step_update(
                        task_id,
                        mother_index,
                        invite_index,
                        "rt",
                        status="running",
                        label="正在获取 RT",
                    )
                    if post_setup_security:
                        _wait_business_child_operation_release(
                            int(target["child_id"])
                        )
                    snapshot = _run_business_child_oauth_with_lease(
                        target,
                        emit=emit,
                    )
                    inner_task_id = str(snapshot.get("task_id") or "")
                    if (
                        str(snapshot.get("status") or "") != "done"
                        or not _business_child_action_complete(target, "oauth")
                    ):
                        raise RuntimeError(snapshot.get("error") or "RT 获取失败")
                    _business_batch_invite_step_update(
                        task_id,
                        mother_index,
                        invite_index,
                        "rt",
                        status="success",
                        label="RT 获取成功",
                        task_ref=inner_task_id,
                    )
                    emit("RT 获取成功")
            except Exception as exc:
                error = _business_batch_invite_error(exc)
                errors.append(f"RT：{error}")
                _business_batch_invite_step_update(
                    task_id,
                    mother_index,
                    invite_index,
                    "rt",
                    status="failed",
                    label="RT 获取失败",
                    error=error,
                )
                emit(f"RT 获取失败：{error}")
    return errors


def _run_business_batch_invite_task(task_id: str) -> None:
    acquired = _BUSINESS_BATCH_INVITE_RUN_LOCK.acquire(blocking=False)
    if not acquired:
        error = "已有另一个批量邀请任务正在执行，本任务未启动"
        _business_batch_invite_log(task_id, error)
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is not None:
                for mother in task.get("mothers") or []:
                    mother["status"] = "skipped"
                    mother["error"] = error
                    mother["finished_at"] = _iso_utc(_utcnow())
                    for invitation in mother.get("invitations") or []:
                        invitation["status"] = "skipped"
                        invitation["error"] = error
                        invitation["finished_at"] = _iso_utc(_utcnow())
                task["status"] = "failed"
                task["outcome"] = "failed"
                task["has_failures"] = True
                task["error"] = error
                task["finished_at"] = _iso_utc(_utcnow())
                _recompute_business_batch_progress_locked(task)
        return
    try:
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is None:
                return
            task["status"] = "running"
            task["started_at"] = task.get("started_at") or _iso_utc(_utcnow())
            provider = str(task.get("candidate_mail_provider") or "auto")
            post_setup_security = bool(task.get("post_setup_security"))
            post_acquire_rt = bool(task.get("post_acquire_rt"))
            security_browser_mode = str(
                task.get("security_browser_mode") or "headless"
            )
            mother_count = len(task.get("mothers") or [])
        _business_batch_invite_log(
            task_id,
            f"批量邀请开始，共 {mother_count} 个母号；母号之间严格串行处理",
        )

        for mother_index in range(mother_count):
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                if task is None:
                    return
                mother = task["mothers"][mother_index]
                mother["status"] = "running"
                mother["started_at"] = _iso_utc(_utcnow())
                task["current_account_id"] = int(mother["account_id"])
                task["current_account_email"] = str(mother["email"])
                _recompute_business_batch_progress_locked(task)
                account_id = int(mother["account_id"])
                email = str(mother["email"])
                planned = int(mother["planned_invites"])
            _business_batch_invite_log(
                task_id,
                f"母号 {mother_index + 1}/{mother_count}：{email}，计划邀请 {planned} 个子号",
            )

            stopped = False
            for invite_index in range(planned):
                with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                    task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                    if task is None:
                        return
                    invitation = task["mothers"][mother_index]["invitations"][invite_index]
                    invitation["status"] = "running"
                    invitation["started_at"] = _iso_utc(_utcnow())
                    invitation["steps"]["invite"].update({
                        "status": "running",
                        "label": "核验账号并邀请",
                        "started_at": invitation["started_at"],
                    })
                    task["mothers"][mother_index]["current_invite_index"] = invite_index + 1
                    _recompute_business_batch_progress_locked(task)
                _business_batch_invite_log(
                    task_id,
                    f"{email}：开始第 {invite_index + 1}/{planned} 次邀请，准备号优先、普通号补充",
                )
                try:
                    before_membership_ids = (
                        _active_business_pool_membership_ids(account_id)
                        if post_setup_security or post_acquire_rt
                        else set()
                    )
                    invite_body = GptPlanBusinessChildInviteRequest(
                        operation_id=(
                            f"plans-batch-{task_id}-{account_id}-{invite_index + 1}"
                        ),
                        pro_account_id=None,
                        manual_email=None,
                        candidate_mail_provider=provider,
                    )

                    def observe_selection(child_id: int, child_email: str) -> None:
                        # Display the source-owned selection immediately. This
                        # observer must not reselect or alter invitation guards.
                        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                            current_task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                            if current_task is None:
                                return
                            current = current_task["mothers"][mother_index]["invitations"][invite_index]
                            current["pro_account_id"] = int(child_id)
                            current["email"] = _safe_business_child_email(child_email)
                        _business_batch_invite_log(task_id, f"{email}：已选择子号 {child_email}")

                    invite_body._selection_observer = observe_selection
                    # Use the canonical pre-invite evidence, rather than calling
                    # every ready-cookie check a fresh login in batch progress.
                    invite_body._log_fn = lambda line: _business_batch_invite_log(
                        task_id, f"{email}：{line}",
                    )
                    result = member_business_invite(account_id, invite_body)
                    if not isinstance(result, dict) or not bool(result.get("ok")):
                        raw_error = ""
                        if isinstance(result, dict):
                            raw_error = str(
                                result.get("error")
                                or result.get("warning")
                                or ""
                            )
                            if not raw_error:
                                errors = result.get("errored")
                                if isinstance(errors, list) and errors:
                                    first = errors[0]
                                    if isinstance(first, dict):
                                        raw_error = str(first.get("error") or "")
                        raise RuntimeError(raw_error or "母号邀请接口未确认成功")
                    child_id = (
                        result.get("auto_selected_pro_account_id")
                        or result.get("resolved_new_pro_account_id")
                    )
                    invited = result.get("invited")
                    child_email = (
                        _safe_business_child_email(invited[0])
                        if isinstance(invited, list) and invited else ""
                    )
                    post_target: Optional[dict[str, Any]] = None
                    post_errors: list[str] = []
                    if post_setup_security or post_acquire_rt:
                        try:
                            post_target = _resolve_persisted_batch_invited_child(
                                account_id,
                                before_membership_ids,
                                result,
                                action=(
                                    "setup_security"
                                    if post_setup_security else "oauth"
                                ),
                            )
                            child_id = int(post_target["child_id"])
                            child_email = str(post_target["email"])
                        except Exception as exc:
                            persistence_error = _business_batch_invite_error(exc)
                            post_errors.append(f"成员确认：{persistence_error}")
                            first_requested = (
                                "security" if post_setup_security else "rt"
                            )
                            _business_batch_invite_step_update(
                                task_id,
                                mother_index,
                                invite_index,
                                first_requested,
                                status="failed",
                                label="后处理资格或归属核验失败",
                                error=persistence_error,
                            )
                            if post_setup_security and post_acquire_rt:
                                _business_batch_invite_step_update(
                                    task_id,
                                    mother_index,
                                    invite_index,
                                    "rt",
                                    status="skipped",
                                    label="成员归属未确认，未获取 RT",
                                    error=persistence_error,
                                )
                    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                        task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                        if task is None:
                            return
                        invitation = task["mothers"][mother_index]["invitations"][invite_index]
                        invitation.update({
                            "status": "running",
                            "pro_account_id": (
                                int(child_id)
                                if isinstance(child_id, int)
                                and not isinstance(child_id, bool)
                                and child_id > 0 else None
                            ),
                            "email": child_email,
                        })
                        invitation["steps"]["invite"].update({
                            "status": "success",
                            "label": "邀请成功",
                            "finished_at": _iso_utc(_utcnow()),
                        })
                        _recompute_business_batch_progress_locked(task)
                    _business_batch_invite_log(
                        task_id,
                        f"{email}：第 {invite_index + 1}/{planned} 次邀请成功"
                        + (f"，子号 {child_email}" if child_email else ""),
                    )
                    if post_target is not None:
                        try:
                            post_errors.extend(
                                _run_business_batch_invite_post_actions(
                                    task_id,
                                    mother_index,
                                    invite_index,
                                    post_target,
                                    post_setup_security=post_setup_security,
                                    post_acquire_rt=post_acquire_rt,
                                    security_browser_mode=security_browser_mode,
                                )
                            )
                        except Exception as exc:
                            # The remote invitation is already confirmed and
                            # persisted at this point.  Even an unexpected
                            # orchestration error must therefore remain a
                            # post-processing partial result, never be
                            # relabelled as an invitation failure (which would
                            # also incorrectly stop the rest of this mother).
                            post_error = _business_batch_invite_error(exc)
                            post_errors.append(f"后处理：{post_error}")
                            requested_steps = (
                                ("security", "rt")
                                if post_setup_security and post_acquire_rt
                                else ("security",)
                                if post_setup_security
                                else ("rt",)
                            )
                            for step_name in requested_steps:
                                with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                                    step = (
                                        _BUSINESS_BATCH_INVITE_TASKS.get(task_id, {})
                                        .get("mothers", [])[mother_index]
                                        .get("invitations", [])[invite_index]
                                        .get("steps", {})
                                        .get(step_name)
                                    )
                                    step_status = (
                                        str(step.get("status") or "")
                                        if isinstance(step, dict) else ""
                                    )
                                if step_status in {"pending", "running"}:
                                    _business_batch_invite_step_update(
                                        task_id,
                                        mother_index,
                                        invite_index,
                                        step_name,
                                        status="failed",
                                        label="后处理异常",
                                        error=post_error,
                                    )
                            _business_batch_invite_log(
                                task_id,
                                f"{email}：子号邀请已成功，后处理异常：{post_error}",
                            )
                    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                        task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                        if task is None:
                            return
                        invitation = task["mothers"][mother_index]["invitations"][invite_index]
                        invitation.update({
                            "status": "partial" if post_errors else "success",
                            "error": "；".join(post_errors),
                            "finished_at": _iso_utc(_utcnow()),
                        })
                        _recompute_business_batch_progress_locked(task)
                    if post_errors:
                        _business_batch_invite_log(
                            task_id,
                            f"{email}：子号邀请已成功，但后处理部分失败："
                            + "；".join(post_errors),
                        )
                except Exception as exc:
                    error = _business_batch_invite_error(exc)
                    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                        task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                        if task is None:
                            return
                        mother = task["mothers"][mother_index]
                        invitation = mother["invitations"][invite_index]
                        invitation.update({
                            "status": "failed",
                            "error": error,
                            "finished_at": _iso_utc(_utcnow()),
                        })
                        invitation["steps"]["invite"].update({
                            "status": "failed",
                            "label": "邀请失败",
                            "error": error,
                            "finished_at": invitation["finished_at"],
                        })
                        for step_name in ("security", "rt"):
                            step = invitation.get("steps", {}).get(step_name)
                            if isinstance(step, dict) and step.get("status") == "pending":
                                step.update({
                                    "status": "skipped",
                                    "label": "邀请失败，未执行后处理",
                                    "error": "邀请失败",
                                    "finished_at": invitation["finished_at"],
                                })
                        for later in mother["invitations"][invite_index + 1:]:
                            later.update({
                                "status": "skipped",
                                "error": "本母号前序邀请失败，已停止后续邀请",
                                "finished_at": _iso_utc(_utcnow()),
                            })
                            for step in (later.get("steps") or {}).values():
                                if isinstance(step, dict) and step.get("status") == "pending":
                                    step.update({
                                        "status": "skipped",
                                        "label": "前序邀请失败，已停止",
                                        "error": "本母号前序邀请失败",
                                        "finished_at": later["finished_at"],
                                    })
                        mother["error"] = error
                        mother["status"] = (
                            "partial"
                            if any(
                                item.get("status") in {"success", "partial"}
                                for item in mother["invitations"]
                            ) else "failed"
                        )
                        mother["finished_at"] = _iso_utc(_utcnow())
                        mother["current_invite_index"] = None
                        _recompute_business_batch_progress_locked(task)
                    _business_batch_invite_log(
                        task_id,
                        f"{email}：第 {invite_index + 1}/{planned} 次邀请失败：{error}；"
                        "已停止该母号，继续处理下一个母号",
                    )
                    stopped = True
                    break

            if not stopped:
                with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                    task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                    if task is None:
                        return
                    mother = task["mothers"][mother_index]
                    mother["status"] = (
                        "partial"
                        if any(
                            item.get("status") == "partial"
                            for item in mother["invitations"]
                        )
                        else "done"
                    )
                    mother["current_invite_index"] = None
                    mother["finished_at"] = _iso_utc(_utcnow())
                    _recompute_business_batch_progress_locked(task)
                _business_batch_invite_log(
                    task_id,
                    f"{email}：已完成全部 {planned} 次邀请",
                )

        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is None:
                return
            _recompute_business_batch_progress_locked(task)
            progress = task["progress"]
            successes = int(progress["successful_invites"])
            failures = int(progress["failed_invites"])
            partials = int(progress.get("partial_invites") or 0)
        # Append the final line before publishing the terminal state.  Pollers
        # stop after done/failed, so the terminal snapshot must already contain
        # every user-facing log line.
        _business_batch_invite_log(
            task_id,
            f"批量邀请结束：完整成功 {successes} 个，后处理部分失败 {partials} 个，"
            f"邀请失败 {failures} 个",
        )
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is None:
                return
            task["status"] = "done"
            task["outcome"] = (
                "success" if failures <= 0 and partials <= 0
                else "partial" if successes > 0 or partials > 0
                else "failed"
            )
            task["has_failures"] = failures > 0 or partials > 0
            task["current_account_id"] = None
            task["current_account_email"] = ""
            task["finished_at"] = _iso_utc(_utcnow())
            _recompute_business_batch_progress_locked(task)
            _prune_business_batch_invite_tasks_locked()
    except Exception as exc:
        error = _business_batch_invite_error(exc)
        _business_batch_invite_log(task_id, f"批量邀请异常终止：{error}")
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is not None:
                for mother in task.get("mothers") or []:
                    for invitation in mother.get("invitations") or []:
                        if invitation.get("status") == "running":
                            invitation.update({
                                "status": "failed",
                                "error": error,
                                "finished_at": _iso_utc(_utcnow()),
                            })
                        elif invitation.get("status") == "pending":
                            invitation.update({
                                "status": "skipped",
                                "error": "批量任务异常终止",
                                "finished_at": _iso_utc(_utcnow()),
                            })
                    if mother.get("status") == "running":
                        mother["status"] = "failed"
                        mother["error"] = error
                    elif mother.get("status") == "pending":
                        mother["status"] = "skipped"
                        mother["error"] = "批量任务异常终止"
                    mother["finished_at"] = _iso_utc(_utcnow())
                    mother["current_invite_index"] = None
                task["status"] = "failed"
                task["outcome"] = "failed"
                task["has_failures"] = True
                task["error"] = error
                task["current_account_id"] = None
                task["current_account_email"] = ""
                task["finished_at"] = _iso_utc(_utcnow())
                _recompute_business_batch_progress_locked(task)
                _prune_business_batch_invite_tasks_locked()
    finally:
        _BUSINESS_BATCH_INVITE_RUN_LOCK.release()


def _prepared_batch_ready_gmail_children(
    account_id: int,
    count: int,
) -> list[dict[str, Any]]:
    """Return invitation candidates that already have password and 2FA."""
    from services.gpt_plan_preparation_store import _security_ready_now

    with Session(engine) as session:
        records = _plan_business_candidate_records(
            session,
            int(account_id),
            candidate_mail_provider="gmail",
            seat_type="",
            require_registration=True,
        )
        result: list[dict[str, Any]] = []
        for record in records:
            child = record.get("child")
            child_id = int(getattr(child, "id", 0) or 0)
            email = _safe_business_child_email(getattr(child, "email", ""))
            if child_id <= 0 or not email or not _security_ready_now(email):
                continue
            result.append({"child_id": child_id, "email": email})
            if len(result) >= int(count):
                break
        return result


def _prepared_batch_invite_many(
    account_id: int,
    child_ids: list[int],
    *,
    seat_type: str,
    operation_id: str,
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Send one remote invitation command containing every prepared child."""
    binding, _member_source = _business_child_facade_binding(
        int(account_id),
        require_action=True,
        preflight_session=True,
    )
    normalized_ids = list(dict.fromkeys(int(value) for value in child_ids))
    if not normalized_ids or len(normalized_ids) != len(child_ids):
        raise HTTPException(409, "批量邀请子号身份重复或为空")
    with Session(engine) as session:
        allowed = {
            int(record["child"].id): record["child"]
            for record in _plan_business_candidate_records(
                session,
                int(binding.source_account_id),
                candidate_mail_provider="gmail",
                seat_type=seat_type,
                require_registration=True,
            )
        }
        if any(child_id not in allowed for child_id in normalized_ids):
            raise HTTPException(409, "准备完成的子号资格已变化，尚未发送批量邀请")
        from services.gpt_plan_preparation_store import _security_ready_now
        if any(not _security_ready_now(allowed[child_id].email) for child_id in normalized_ids):
            raise HTTPException(409, "仍有子号未完成密码或 2FA，尚未发送批量邀请")

    from api import gpt_business
    source_body = gpt_business.BizInviteMemberRequest(
        pro_account_ids=normalized_ids,
        pool_mode=True,
        candidate_mail_provider="gmail",
        seat_type=seat_type,
        operation_id=operation_id,
    )
    source_body._expected_seat_type = seat_type
    source_body._existing_selection = True
    try:
        raw = gpt_business.invite_member_biz_for_plan_facade(
            int(binding.source_account_id),
            source_body,
            prelogin_pro_account_ids=normalized_ids,
            **({"_prelogin_log_fn": log_fn} if callable(log_fn) else {}),
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    safe = _safe_business_child_mutation_result(raw, operation_id=operation_id)
    children, binding_changed = _business_mutation_snapshot_after_source_call(binding)
    _confirm_business_child_persistence(safe, children)
    safe.update({
        "account_id": int(account_id),
        "binding_changed": binding_changed,
        "business_children": children,
        "invite_quota": children.get("invite_quota") if isinstance(children, dict) else None,
    })
    return safe


def _prepared_batch_membership_target(account_id: int, child_id: int) -> dict[str, Any]:
    """Resolve the exact persisted membership created by the batch invitation."""
    binding, _source = _business_child_facade_binding(
        int(account_id), require_action=True,
    )
    with Session(engine) as session:
        membership = session.exec(
            select(GptBusinessChildMembershipModel)
            .where(GptBusinessChildMembershipModel.business_account_id == int(binding.source_account_id))
            .where(GptBusinessChildMembershipModel.pro_account_id == int(child_id))
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .order_by(col(GptBusinessChildMembershipModel.id).desc())
        ).first()
        if membership is None:
            raise RuntimeError("批量邀请已返回，但本地成员关系尚未写入")
        membership_id = int(membership.id or 0)
        invited_at = _iso_utc(membership.invited_at)
    target = _resolve_business_child_batch_action_target(membership_id, "oauth")
    target["membership_invited_at"] = invited_at
    return target


def _prepared_batch_rt_current(target: dict[str, Any]) -> bool:
    """Only an RT saved in this membership cycle completes automatic delivery."""
    try:
        invited_at = _aware_utc(datetime.fromisoformat(str(target["membership_invited_at"]).replace("Z", "+00:00")))
    except (KeyError, TypeError, ValueError):
        return False
    with Session(engine) as session:
        child = session.get(GptPlanAccountModel, int(target["child_id"]))
        acquired_at = _aware_utc(getattr(child, "codex_rt_acquired_at", None)) if child is not None else None
        return bool(child and str(child.codex_refresh_token or "").strip()
                    and acquired_at is not None and acquired_at >= invited_at)


def _prepared_batch_acquire_rt(
    task_id: str,
    account_id: int,
    child: dict[str, Any],
    index: int,
) -> tuple[bool, str]:
    """Acquire one child's RT with bounded retries and durable checkpoints."""
    email = str(child["email"])
    target = _prepared_batch_membership_target(account_id, int(child["child_id"]))
    if _prepared_batch_rt_current(target):
        _business_batch_invite_step_update(
            task_id, 0, index, "rt", status="success", label="RT 已就绪",
        )
        return True, ""
    from core.config_store import config_store
    allow_phone = str(config_store.get("chatgpt_rt_allow_phone_verification", "1") or "1").strip().lower() in {
        "1", "true", "yes", "on",
    }
    last_error = ""
    for attempt in range(1, 4):
        _business_batch_invite_step_update(
            task_id, 0, index, "rt", status="running",
            label=f"正在获取 RT（第 {attempt}/3 次）",
        )
        _business_batch_invite_log(task_id, f"{email}：开始获取 RT（第 {attempt}/3 次）")
        try:
            if _prepared_batch_rt_current(target):
                _business_batch_invite_step_update(
                    task_id, 0, index, "rt", status="success", label="RT 已就绪",
                )
                return True, ""
            snapshot = _run_business_child_oauth_with_lease(
                target,
                emit=lambda line: _business_batch_invite_log(task_id, f"{email}：{line}"),
                allow_phone_verification=allow_phone,
                expected_invited_at=str(target["membership_invited_at"]),
                allow_existing_credentials=True,
            )
            if str(snapshot.get("status") or "") == "done" and _prepared_batch_rt_current(target):
                _business_batch_invite_step_update(
                    task_id, 0, index, "rt", status="success", label="RT 获取成功",
                    task_ref=str(snapshot.get("task_id") or ""),
                )
                _business_batch_invite_log(task_id, f"{email}：RT 获取成功")
                return True, ""
            last_error = _business_batch_invite_error(snapshot.get("error") or "RT 获取失败")
        except Exception as exc:
            # A previous attempt may have saved the RT before its final status
            # response failed. Re-read durable account state before retrying.
            if _prepared_batch_rt_current(target):
                _business_batch_invite_step_update(
                    task_id, 0, index, "rt", status="success", label="RT 已保存并确认",
                )
                return True, ""
            last_error = _business_batch_invite_error(exc)
        if attempt < 3:
            _business_batch_invite_log(task_id, f"{email}：RT 尚未完成，5 秒后从 RT 阶段重试")
            time.sleep(5)
    _business_batch_invite_step_update(
        task_id, 0, index, "rt", status="failed", label="RT 获取失败",
        error=last_error or "RT 获取失败",
    )
    return False, last_error or "RT 获取失败"


def _run_prepared_business_batch_invite_task(task_id: str) -> None:
    """Register children concurrently on distinct proxies, then invite once."""
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        existing = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
        account_id_for_lock = int((((existing or {}).get("mothers") or [{}])[0]).get("account_id") or 0)
    run_lock = _prepared_batch_parent_lock(account_id_for_lock)
    if not run_lock.acquire(blocking=False):
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task:
                task.update(status="failed", outcome="failed", has_failures=True,
                            error="已有另一个批量邀请任务正在执行", finished_at=_iso_utc(_utcnow()))
        return
    try:
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if not task:
                return
            mother = task["mothers"][0]
            mother.update(status="running", started_at=_iso_utc(_utcnow()))
            account_id = int(mother["account_id"])
            seat_type = str(task["seat_type"])
            prepared = list(task.get("prepared_children") or [])
            registrations = list(task.get("registrations") or [])
            task["attempts"] = int(task.get("attempts") or 0) + 1
            task["status"] = "running"
            task["error"] = ""
            task["next_retry_at"] = ""
            task["current_account_id"] = account_id
            task["current_account_email"] = mother["email"]
            task["phase"] = "prepare"
            _recompute_business_batch_progress_locked(task)
        _business_batch_invite_log(
            task_id,
            f"开始准备 {len(prepared) + len(registrations)} 个 Gmail 子号；"
            f"{len(registrations)} 个注册任务使用不同代理并发执行",
        )

        from api.tasks import RegisterTaskRequest, enqueue_register_task, _task_store
        registration_tasks: list[dict[str, Any]] = []
        used_alias_ids = {int(item.get("alias_id") or 0) for item in registrations}
        used_proxy_keys = {str(item.get("proxy_key") or "") for item in registrations}
        for index, item in enumerate(registrations):
            invite_index = len(prepared) + index
            email = _safe_business_child_email(item.get("email"))
            with Session(engine) as session:
                existing_child = session.exec(select(GptPlanAccountModel).where(
                    func.lower(func.trim(GptPlanAccountModel.email)) == email
                ).order_by(col(GptPlanAccountModel.id).desc())).first()
            from services.gpt_plan_preparation_store import _security_ready_now
            if existing_child is not None and _security_ready_now(email):
                _business_batch_invite_step_update(
                    task_id, 0, invite_index, "prepare",
                    status="success", label="注册、密码与 2FA 已完成",
                )
                _business_batch_invite_log(task_id, f"{email}：检测到已完成准备，跳过重复注册")
                continue
            _business_batch_invite_step_update(
                task_id, 0, invite_index, "prepare",
                status="running", label="正在注册并设置密码 / 2FA",
            )
            def enqueue_item() -> str:
                return enqueue_register_task(
                    RegisterTaskRequest(
                        platform="chatgpt",
                        count=1,
                        concurrency=1,
                        executor_type="headless",
                        proxy_key=str(item["proxy_key"]),
                        extra={
                            "mail_provider": "gmail",
                            "gmail_alias_ids": [int(item["alias_id"])],
                            "_gmail_retry": True,
                            "chatgpt_registration_mode": "refresh_token",
                            "chatgpt_security_after_register": "1",
                        },
                    ),
                    source="business_prepared_batch",
                    meta={"business_batch_task_id": task_id, "gmail_alias_id": int(item["alias_id"])},
                )
            try:
                register_task_id = enqueue_item()
            except Exception:
                # The read-only selection may become stale before its worker
                # claims the exact alias/proxy. Replace only this not-yet-run
                # slot, persist the new identity, and keep the batch automatic.
                from services.gmail_registration import list_candidates
                from services.registration_proxy import list_registration_proxy_options
                candidates = [row for row in list_candidates()
                              if int(row.get("id") or 0) not in used_alias_ids - {int(item["alias_id"])}]
                proxies = [row for row in (list_registration_proxy_options().get("items") or [])
                           if str(row.get("key") or "") not in used_proxy_keys - {str(item["proxy_key"])}]
                if not candidates or not proxies:
                    raise
                used_alias_ids.discard(int(item["alias_id"]))
                used_proxy_keys.discard(str(item["proxy_key"]))
                replacement, proxy = candidates[0], proxies[0]
                item.update(alias_id=int(replacement["id"]),
                            email=_safe_business_child_email(replacement.get("email")),
                            proxy_key=str(proxy["key"]),
                            proxy_label=str(proxy.get("label") or proxy["key"])[:160])
                used_alias_ids.add(int(item["alias_id"]))
                used_proxy_keys.add(str(item["proxy_key"]))
                with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                    stored = _BUSINESS_BATCH_INVITE_TASKS[task_id]
                    stored["registrations"][index] = dict(item)
                    stored["mothers"][0]["invitations"][invite_index]["email"] = str(item["email"])
                    _persist_prepared_batch_task(stored)
                _business_batch_invite_log(task_id, f"原候选号或代理已变化，自动改选 {item['email']}")
                register_task_id = enqueue_item()
            registration_tasks.append({**item, "task_id": register_task_id, "invite_index": invite_index})
            _business_batch_invite_step_update(
                task_id, 0, invite_index, "prepare",
                status="running", label="正在注册并设置密码 / 2FA", task_ref=register_task_id,
            )
            _business_batch_invite_log(
                task_id,
                f"{item['email']}：注册任务已启动，代理 {item['proxy_label']}",
            )

        deadline = time.monotonic() + 30 * 60
        pending = {str(item["task_id"]): item for item in registration_tasks}
        while pending and time.monotonic() < deadline:
            for register_task_id, item in list(pending.items()):
                snapshot = _task_store.snapshot(register_task_id)
                status = str(snapshot.get("status") or "")
                if status not in {"done", "failed", "stopped"}:
                    continue
                pending.pop(register_task_id, None)
                if status != "done" or int(snapshot.get("success") or 0) < 1:
                    error = _business_batch_invite_error(
                        snapshot.get("error") or (snapshot.get("errors") or ["注册失败"])[0]
                    )
                    _business_batch_invite_step_update(
                        task_id, 0, int(item["invite_index"]), "prepare",
                        status="failed", label="注册或 2FA 失败", error=error,
                    )
                    raise RuntimeError(f"{item['email']}：{error}")
                _business_batch_invite_step_update(
                    task_id, 0, int(item["invite_index"]), "prepare",
                    status="success", label="注册、密码与 2FA 已完成",
                )
                _business_batch_invite_log(task_id, f"{item['email']}：注册、密码与 2FA 已完成")
            if pending:
                time.sleep(1)
        if pending:
            raise RuntimeError("并发注册等待超过 30 分钟，尚未发送邀请")

        child_rows = list(prepared)
        from services.gpt_plan_preparation_store import _security_ready_now
        with Session(engine) as session:
            for item in registrations:
                email = _safe_business_child_email(item.get("email"))
                child = session.exec(select(GptPlanAccountModel).where(
                    func.lower(func.trim(GptPlanAccountModel.email)) == email
                ).order_by(col(GptPlanAccountModel.id).desc())).first()
                if child is None or not _security_ready_now(email):
                    raise RuntimeError(f"{email}：注册任务结束但密码或 2FA 尚未完成")
                child_rows.append({"child_id": int(child.id), "email": email})
        if len(child_rows) != len(mother["invitations"]):
            raise RuntimeError("准备完成的子号数量与邀请数量不一致")

        for index, child in enumerate(child_rows):
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                invitation = _BUSINESS_BATCH_INVITE_TASKS[task_id]["mothers"][0]["invitations"][index]
                invitation["pro_account_id"] = int(child["child_id"])
                invitation["email"] = str(child["email"])
                invitation["status"] = "running"
                invitation["started_at"] = invitation.get("started_at") or _iso_utc(_utcnow())
            if index < len(prepared):
                _business_batch_invite_step_update(
                    task_id, 0, index, "prepare",
                    status="success", label="密码与 2FA 已就绪",
                )
            _business_batch_invite_step_update(
                task_id, 0, index, "invite", status="running", label="等待统一批量邀请",
            )
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            _BUSINESS_BATCH_INVITE_TASKS[task_id]["phase"] = "invite"
            _persist_prepared_batch_task(_BUSINESS_BATCH_INVITE_TASKS[task_id])
        _business_batch_invite_log(
            task_id,
            f"全部 {len(child_rows)} 个子号已准备完成，正在调用一次母号批量邀请接口",
        )
        binding, _member_source = _business_child_facade_binding(
            int(account_id), require_action=True,
        )
        child_by_id = {int(item["child_id"]): item for item in child_rows}
        with Session(engine) as session:
            existing_memberships = list(session.exec(
                select(GptBusinessChildMembershipModel)
                .where(GptBusinessChildMembershipModel.business_account_id == int(binding.source_account_id))
                .where(GptBusinessChildMembershipModel.pro_account_id.in_(list(child_by_id)))  # type: ignore[union-attr]
                .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            ).all())
        existing_ids = {int(row.pro_account_id or 0) for row in existing_memberships}
        invited = {str(child_by_id[child_id]["email"]) for child_id in existing_ids if child_id in child_by_id}
        missing_ids = [child_id for child_id in child_by_id if child_id not in existing_ids]
        result: dict[str, Any] = {"invited": list(invited), "errored": []}
        if missing_ids:
            result = _prepared_batch_invite_many(
                account_id,
                missing_ids,
                seat_type=seat_type,
                operation_id=f"plans-prepared-batch-{task_id}-{account_id}",
                log_fn=lambda line: _business_batch_invite_log(task_id, str(line)),
            )
            invited.update(_safe_business_child_email(value) for value in result.get("invited") or [])
        else:
            _business_batch_invite_log(task_id, "成员关系已全部存在，跳过重复批量邀请")
        errors = {
            _safe_business_child_email(item.get("email")): _business_batch_invite_error(item.get("error"))
            for item in result.get("errored") or [] if isinstance(item, dict)
        }
        successful_children: list[tuple[int, dict[str, Any]]] = []
        for index, child in enumerate(child_rows):
            email = str(child["email"])
            success = email in invited
            error = errors.get(email, "") if not success else ""
            _business_batch_invite_step_update(
                task_id, 0, index, "invite",
                status="success" if success else "failed",
                label="批量邀请成功" if success else "批量邀请失败",
                error=error or ("母号批量邀请未确认该子号" if not success else ""),
            )
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                invitation = _BUSINESS_BATCH_INVITE_TASKS[task_id]["mothers"][0]["invitations"][index]
                invitation.update(
                    status="running" if success else "failed",
                    error=error or ("母号批量邀请未确认该子号" if not success else ""),
                    finished_at="" if success else _iso_utc(_utcnow()),
                )
            if success:
                successful_children.append((index, child))
                _business_batch_invite_step_update(
                    task_id, 0, index, "rt", status="pending", label="等待自动获取 RT",
                )
        if len(successful_children) != len(child_rows):
            raise RuntimeError("部分子号尚未确认邀请成功，将自动核对成员后仅重试缺失子号")
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            _BUSINESS_BATCH_INVITE_TASKS[task_id]["phase"] = "rt"
            _persist_prepared_batch_task(_BUSINESS_BATCH_INVITE_TASKS[task_id])
        rt_failures: list[str] = []
        for index, child in successful_children:
            rt_ok, rt_error = _prepared_batch_acquire_rt(task_id, account_id, child, index)
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                invitation = _BUSINESS_BATCH_INVITE_TASKS[task_id]["mothers"][0]["invitations"][index]
                invitation.update(
                    status="success" if rt_ok else "partial",
                    error="" if rt_ok else rt_error,
                    finished_at=_iso_utc(_utcnow()),
                )
            if not rt_ok:
                rt_failures.append(f"{child['email']}：{rt_error}")
        if rt_failures:
            raise RuntimeError("；".join(rt_failures[:3]))
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS[task_id]
            mother = task["mothers"][0]
            _recompute_business_batch_progress_locked(task)
            failures = int(mother.get("failed_invites") or 0)
            successes = int(mother.get("successful_invites") or 0)
            partials = int(mother.get("partial_invites") or 0)
            mother.update(status="done" if failures == 0 and partials == 0 else "partial" if successes or partials else "failed",
                          finished_at=_iso_utc(_utcnow()), current_invite_index=None)
            task.update(status="done", phase="done",
                        outcome="success" if failures == 0 and partials == 0 else "partial" if successes or partials else "failed",
                        has_failures=failures > 0 or partials > 0, finished_at=_iso_utc(_utcnow()),
                        current_account_id=None, current_account_email="")
            _recompute_business_batch_progress_locked(task)
        _business_batch_invite_log(
            task_id,
            f"一次批量邀请完成：成功 {len(invited)} 个，失败 {len(child_rows) - len(invited)} 个",
        )
    except Exception as exc:
        error = _business_batch_invite_error(exc)
        _business_batch_invite_log(task_id, f"准备后批量邀请失败：{error}")
        retry = False
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task:
                mother = task["mothers"][0]
                terminal_markers = (
                    "母号不存在", "母号已退款", "母号已停用", "绑定已变化",
                    "账号已删除", "席位类型只支持", "身份已变化",
                )
                retry = not any(marker in error for marker in terminal_markers)
                for invitation in mother.get("invitations") or []:
                    if invitation.get("status") != "success":
                        invitation.update(
                            status="pending" if retry else "failed",
                            error=error,
                            finished_at="" if retry else _iso_utc(_utcnow()),
                        )
                        for step in (invitation.get("steps") or {}).values():
                            if isinstance(step, dict) and step.get("status") in {"running", "failed", "skipped"}:
                                step.update(status="pending" if retry else "failed",
                                            label="等待自动重试" if retry else "已达到自动重试上限",
                                            error=error, finished_at="" if retry else _iso_utc(_utcnow()))
                mother.update(status="pending" if retry else "failed", error=error,
                              finished_at="" if retry else _iso_utc(_utcnow()), current_invite_index=None)
                task.update(status="pending" if retry else "failed",
                            phase="retry" if retry else "failed",
                            outcome="" if retry else "failed", has_failures=not retry, error=error,
                            finished_at="" if retry else _iso_utc(_utcnow()),
                            current_account_id=None, current_account_email="")
                _recompute_business_batch_progress_locked(task)
        if retry:
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                retry_task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id) or {}
                attempts = int(retry_task.get("attempts") or 1)
            retry_delay = min(300, 15 * (2 ** min(max(0, attempts - 1), 5)))
            with _BUSINESS_BATCH_INVITE_TASK_LOCK:
                retry_task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
                if retry_task is not None:
                    retry_task["next_retry_at"] = _iso_utc(
                        _utcnow() + timedelta(seconds=retry_delay)
                    )
                    _persist_prepared_batch_task(retry_task)
            _business_batch_invite_log(task_id, f"{retry_delay} 秒后自动从数据库已确认阶段继续，无需人工操作")
            threading.Timer(
                retry_delay,
                _run_prepared_business_batch_invite_task,
                args=(task_id,),
            ).start()
    finally:
        run_lock.release()


def resume_prepared_business_batch_invite_tasks() -> int:
    """Restore unfinished prepared batches and continue from durable evidence."""
    from services.prepared_batch_invite_store import unfinished

    resumed = 0
    for restored in unfinished():
        task_id = str(restored.get("task_id") or "").strip()
        mothers = restored.get("mothers") if isinstance(restored.get("mothers"), list) else []
        if not task_id or not mothers:
            continue
        restored["status"] = "running"
        restored["finished_at"] = ""
        restored["error"] = ""
        mother = mothers[0]
        mother["status"] = "running"
        mother["finished_at"] = ""
        for invitation in mother.get("invitations") or []:
            if str(invitation.get("status") or "") in {"failed", "partial"}:
                invitation["status"] = "pending"
                invitation["error"] = ""
                invitation["finished_at"] = ""
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            if task_id in _BUSINESS_BATCH_INVITE_TASKS:
                continue
            _BUSINESS_BATCH_INVITE_TASKS[task_id] = restored
            _recompute_business_batch_progress_locked(restored)
        threading.Thread(
            target=_run_prepared_business_batch_invite_task,
            args=(task_id,), daemon=True,
            name=f"gpt-plan-prepared-resume-{task_id[:8]}",
        ).start()
        resumed += 1
    return resumed


@router.post("/accounts/{account_id}/prepared-batch-invite-tasks")
def start_prepared_business_batch_invite_task(
    account_id: int,
    body: GptPlanPreparedBatchInviteRequest,
    request: Request = None,  # type: ignore[assignment]
):
    """Prepare exact Gmail stock first, then send one remote batch invite."""
    if request is None:
        raise HTTPException(401, "批量注册与设置 2FA 需要敏感操作认证")
    _require_plan_security_setup_access(request)
    seat_type = _safe_business_child_seat_type(body.seat_type)
    if seat_type not in {"default", "prolite"}:
        raise HTTPException(400, "seat_type 只支持 default 或 prolite")
    if isinstance(body.count, bool) or not isinstance(body.count, int):
        raise HTTPException(400, "子号数量必须是整数")
    count = int(body.count)
    if not 1 <= count <= 20:
        raise HTTPException(400, "单次子号数量须为 1 至 20")
    if not isinstance(body.post_acquire_rt, bool):
        raise HTTPException(400, "post_acquire_rt 必须是布尔值")

    binding, _member_source = _business_child_facade_binding(
        int(account_id), require_action=True, preflight_session=True,
    )
    with Session(engine) as session:
        source = session.get(GptBusinessAccountModel, int(binding.source_account_id))
        summary = _safe_business_seat_summary(source) if source is not None else None
        typed = _exact_business_typed_available_counts(summary or {})
        available = int((typed or {}).get(seat_type, 0))
        if available < count:
            raise HTTPException(409, {
                "code": "insufficient_typed_seat_capacity",
                "message": f"该席位类型仅剩 {available} 个空位，不能准备 {count} 个子号",
                "seat_type": seat_type,
                "available": available,
            })

    prepared = _prepared_batch_ready_gmail_children(int(account_id), count)
    needed = count - len(prepared)
    prepared_emails = {str(item["email"]) for item in prepared}
    registrations: list[dict[str, Any]] = []
    if needed > 0:
        from services.gmail_registration import list_candidates
        aliases = [
            item for item in list_candidates()
            if _safe_business_child_email(item.get("email")) not in prepared_emails
        ]
        if len(aliases) < needed:
            raise HTTPException(
                409,
                f"可用 Gmail 子号不足：已有 {len(prepared)} 个就绪，还需要 {needed} 个可注册子号",
            )
        from services.registration_proxy import list_registration_proxy_options
        proxy_items = list_registration_proxy_options().get("items") or []
        unique_proxies: list[dict[str, Any]] = []
        seen_proxy_keys: set[str] = set()
        for item in proxy_items:
            key = str(item.get("key") or "")
            if not key or key in seen_proxy_keys:
                continue
            seen_proxy_keys.add(key)
            unique_proxies.append(item)
        if len(unique_proxies) < needed:
            raise HTTPException(
                409,
                f"不同的可用代理不足：并发注册 {needed} 个子号需要 {needed} 个代理，当前只有 {len(unique_proxies)} 个",
            )
        registrations = [{
            "alias_id": int(alias["id"]),
            "email": _safe_business_child_email(alias.get("email")),
            "proxy_key": str(proxy["key"]),
            "proxy_label": str(proxy.get("label") or proxy["key"])[:160],
        } for alias, proxy in zip(aliases[:needed], unique_proxies[:needed])]

    task_id = uuid.uuid4().hex
    children = [*prepared, *registrations]
    now = _iso_utc(_utcnow())
    invitations = []
    for index, child in enumerate(children):
        already_ready = index < len(prepared)
        invitations.append({
            "index": index + 1,
            "status": "pending",
            "status_label": _BUSINESS_BATCH_INVITE_LABELS["pending"],
            "pro_account_id": child.get("child_id"),
            "email": str(child.get("email") or ""),
            "error": "",
            "started_at": "",
            "finished_at": "",
            "steps": {
                "prepare": {
                    "status": "success" if already_ready else "pending",
                    "label": "密码与 2FA 已就绪" if already_ready else "等待注册、密码与 2FA",
                    "error": "", "task_id": "", "started_at": "", "finished_at": now if already_ready else "",
                },
                "invite": {
                    "status": "pending", "label": "等待统一批量邀请", "error": "",
                    "task_id": "", "started_at": "", "finished_at": "",
                },
                "rt": {
                    "status": "pending", "label": "邀请成功后自动获取 RT", "error": "",
                    "task_id": "", "started_at": "", "finished_at": "",
                },
            },
        })
    mother = {
        "account_id": int(account_id),
        "email": binding.normalized_email,
        "status": "pending",
        "status_label": _BUSINESS_BATCH_MOTHER_LABELS["pending"],
        "planned_invites": count,
        "completed_invites": 0,
        "successful_invites": 0,
        "failed_invites": 0,
        "partial_invites": 0,
        "skipped_invites": 0,
        "percent": 0,
        "current_invite": None,
        "current_invite_index": None,
        "error": "",
        "started_at": "",
        "finished_at": "",
        "invitations": invitations,
    }
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        _prune_business_batch_invite_tasks_locked()
        active = next((item for item in _BUSINESS_BATCH_INVITE_TASKS.values()
                       if item.get("status") in {"pending", "running"}
                       and not item.get("finished_at")
                       and int((((item.get("mothers") or [{}])[0]).get("account_id") or 0)) == int(account_id)), None)
        if active is not None:
            raise HTTPException(409, {
                "code": "business_batch_invite_already_running",
                "message": "已有批量邀请任务正在执行，请等待完成后再启动",
                "existing_task_id": str((active or {}).get("task_id") or ""),
            })
        _BUSINESS_BATCH_INVITE_TASKS[task_id] = {
            "task_id": task_id,
            "workflow": "prepare_then_batch",
            "seat_type": seat_type,
            "status": "running",
            "outcome": "",
            "has_failures": False,
            "candidate_mail_provider": "gmail",
            "post_setup_security": True,
            "post_acquire_rt": True,
            "attempts": 0,
            "phase": "prepare",
            "security_browser_mode": "headless",
            "current_account_id": None,
            "current_account_email": "",
            "prepared_children": prepared,
            "registrations": registrations,
            "mothers": [mother],
            "logs": [], "log_start": 0, "log_cursor": 0,
            "error": "", "started_at": now, "finished_at": "",
        }
        _recompute_business_batch_progress_locked(_BUSINESS_BATCH_INVITE_TASKS[task_id])
    threading.Thread(
        target=_run_prepared_business_batch_invite_task,
        args=(task_id,), daemon=True,
        name=f"gpt-plan-prepared-batch-{task_id[:8]}",
    ).start()
    return _public_business_batch_invite_task(task_id, since=0)


@router.post("/business-batch-invite-tasks")
def start_business_batch_invite_task(
    body: GptPlanBusinessBatchInviteRequest,
    request: Request = None,  # type: ignore[assignment]
):
    if bool(body.post_setup_security):
        if request is None:
            raise HTTPException(401, "批量设置 2FA 需要敏感操作认证")
        _require_plan_security_setup_access(request)
    targets, candidate_mail_provider = _resolve_business_batch_invite_targets(
        body
    )
    security_browser_mode = str(
        body.security_browser_mode or "headless"
    ).strip().lower()
    task_id = uuid.uuid4().hex
    mothers: list[dict[str, Any]] = []
    for target in targets:
        planned = int(target["planned_invites"])
        mothers.append({
            "account_id": int(target["account_id"]),
            "email": str(target["email"]),
            "status": "pending",
            "status_label": _BUSINESS_BATCH_MOTHER_LABELS["pending"],
            "planned_invites": planned,
            "completed_invites": 0,
            "successful_invites": 0,
            "failed_invites": 0,
            "partial_invites": 0,
            "skipped_invites": 0,
            "percent": 0,
            "current_invite": None,
            "current_invite_index": None,
            "error": "",
            "started_at": "",
            "finished_at": "",
            "invitations": [
                {
                    "index": index + 1,
                    "status": "pending",
                    "status_label": _BUSINESS_BATCH_INVITE_LABELS["pending"],
                    "pro_account_id": None,
                    "email": "",
                    "error": "",
                    "started_at": "",
                    "finished_at": "",
                    "steps": {
                        "invite": {
                            "status": "pending",
                            "label": "等待邀请",
                            "error": "",
                            "task_id": "",
                            "started_at": "",
                            "finished_at": "",
                        },
                        "security": {
                            "status": (
                                "pending"
                                if bool(body.post_setup_security)
                                else "not_requested"
                            ),
                            "label": (
                                "等待检查密码 / 2FA"
                                if bool(body.post_setup_security)
                                else "未要求设置密码与 2FA"
                            ),
                            "error": "",
                            "task_id": "",
                            "started_at": "",
                            "finished_at": "",
                        },
                        "rt": {
                            "status": (
                                "pending"
                                if bool(body.post_acquire_rt)
                                else "not_requested"
                            ),
                            "label": (
                                "等待获取 RT"
                                if bool(body.post_acquire_rt)
                                else "未要求获取 RT"
                            ),
                            "error": "",
                            "task_id": "",
                            "started_at": "",
                            "finished_at": "",
                        },
                    },
                }
                for index in range(planned)
            ],
        })
    with _BUSINESS_BATCH_INVITE_TASK_LOCK:
        _prune_business_batch_invite_tasks_locked()
        active = next((
            task
            for task in _BUSINESS_BATCH_INVITE_TASKS.values()
            if str(task.get("status") or "") == "running"
            and not str(task.get("finished_at") or "")
        ), None)
        if active is not None:
            raise HTTPException(409, {
                "code": "business_batch_invite_already_running",
                "message": "已有批量邀请任务正在执行，请等待完成后再启动",
                "existing_task_id": str(active.get("task_id") or ""),
            })
        # A worker publishes its terminal snapshot before leaving its ``try``
        # block and releasing RUN_LOCK in ``finally``.  During that short
        # cleanup window the registry has no active task, but starting a new
        # worker would make its non-blocking acquire fail and incorrectly turn
        # a valid request into a failed task.  Probe the run gate while the
        # registry lock serializes all starters.  This acquire is deliberately
        # non-blocking: workers take RUN_LOCK before TASK_LOCK, so waiting here
        # would invert the lock order and could deadlock.
        run_gate_available = _BUSINESS_BATCH_INVITE_RUN_LOCK.acquire(
            blocking=False
        )
        if not run_gate_available:
            raise HTTPException(409, {
                "code": "business_batch_invite_finishing",
                "message": "上一批量邀请任务正在收尾，请稍后再试",
            })
        _BUSINESS_BATCH_INVITE_RUN_LOCK.release()
        _BUSINESS_BATCH_INVITE_TASKS[task_id] = {
            "task_id": task_id,
            "status": "running",
            "outcome": "",
            "has_failures": False,
            "candidate_mail_provider": candidate_mail_provider,
            "post_setup_security": bool(body.post_setup_security),
            "post_acquire_rt": bool(body.post_acquire_rt),
            "security_browser_mode": security_browser_mode,
            "current_account_id": None,
            "current_account_email": "",
            "mothers": mothers,
            "logs": [],
            "log_start": 0,
            "log_cursor": 0,
            "error": "",
            "started_at": _iso_utc(_utcnow()),
            "finished_at": "",
        }
        _recompute_business_batch_progress_locked(
            _BUSINESS_BATCH_INVITE_TASKS[task_id]
        )
    worker = threading.Thread(
        target=_run_business_batch_invite_task,
        args=(task_id,),
        daemon=True,
        name=f"gpt-plan-business-batch-{task_id[:8]}",
    )
    try:
        worker.start()
    except Exception as exc:
        error = _business_batch_invite_error(exc)
        _business_batch_invite_log(
            task_id,
            f"批量邀请后台任务启动失败：{error}",
        )
        with _BUSINESS_BATCH_INVITE_TASK_LOCK:
            task = _BUSINESS_BATCH_INVITE_TASKS.get(task_id)
            if task is not None:
                for mother in task.get("mothers") or []:
                    mother["status"] = "skipped"
                    mother["error"] = "后台任务启动失败"
                    mother["finished_at"] = _iso_utc(_utcnow())
                    for invitation in mother.get("invitations") or []:
                        invitation["status"] = "skipped"
                        invitation["error"] = "后台任务启动失败"
                        invitation["finished_at"] = _iso_utc(_utcnow())
                task["status"] = "failed"
                task["outcome"] = "failed"
                task["has_failures"] = True
                task["error"] = error
                task["finished_at"] = _iso_utc(_utcnow())
                _recompute_business_batch_progress_locked(task)
        raise HTTPException(500, "批量邀请后台任务启动失败") from exc
    return _public_business_batch_invite_task(task_id, since=0)


@router.get("/business-batch-invite-tasks/{task_id}")
def get_business_batch_invite_task(
    task_id: str,
    since: int = Query(0, ge=0),
):
    return _public_business_batch_invite_task(
        str(task_id),
        since=max(0, int(since or 0)),
    )


def _existing_managed_business_child_oauth_target(
    binding: _MemberSourceBinding,
    child_id: int,
) -> int:
    """Resolve one exact active pool child without exposing ended audit rows."""
    with Session(engine) as session:
        membership = session.exec(
            select(GptBusinessChildMembershipModel)
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(binding.source_account_id)
            )
            .where(GptBusinessChildMembershipModel.pro_account_id == int(child_id))
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .where(func.lower(GptBusinessChildMembershipModel.source) == "pool")
            .order_by(col(GptBusinessChildMembershipModel.id).desc())
        ).first()
        if membership is None:
            # Do not disclose whether the child exists under another mother.
            raise HTTPException(404, "该母号下不存在这个可获取 RT 的受管子号")
        child = session.get(GptPlanAccountModel, int(child_id))
        normalized_email = _safe_business_child_email(membership.email)
        if (
            child is None
            or int(getattr(child, "business_parent_id", None) or 0)
            != int(binding.source_account_id)
            or not normalized_email
            or _normalized_email(child.email) != normalized_email
        ):
            raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")
        if (
            not bool(child.enabled)
            or bool(child.dangerous)
            or bool(child.policy_warning)
            or bool(str(child.refund_status or "").strip())
        ):
            raise HTTPException(409, "子号已停用、告警或进入退款流程，不能获取 RT")
        if not (
            _safe_business_remote_identifier(membership.remote_user_id)
            or _safe_business_remote_identifier(membership.remote_invite_id)
        ):
            raise HTTPException(409, "子号缺少可确认的 BUSINESS 成员或邀请身份")

    return int(membership.id or 0)


def _existing_managed_business_child_account_target(
    binding: _MemberSourceBinding,
    child_id: int,
    *,
    action: Literal["login", "login_review", "fetch_mail", "security_status", "setup_security"],
) -> tuple[int, GptPlanAccountModel]:
    """Resolve one exact active pool child for its own login/mail operation."""
    with Session(engine) as session:
        membership = session.exec(
            select(GptBusinessChildMembershipModel)
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(binding.source_account_id)
            )
            .where(GptBusinessChildMembershipModel.pro_account_id == int(child_id))
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .where(func.lower(GptBusinessChildMembershipModel.source) == "pool")
            .order_by(col(GptBusinessChildMembershipModel.id).desc())
        ).first()
        if membership is None:
            raise HTTPException(404, "该母号下不存在这个可操作的受管子号")
        child = session.get(GptPlanAccountModel, int(child_id))
        normalized_email = _safe_business_child_email(membership.email)
        if (
            child is None
            or int(getattr(child, "business_parent_id", None) or 0)
            != int(binding.source_account_id)
            or not normalized_email
            or _normalized_email(child.email) != normalized_email
        ):
            raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")

        capabilities = _business_child_account_capabilities(child)
        if action == "login" and not bool(capabilities["can_chatgpt_login"]):
            raise HTTPException(
                409,
                str(capabilities["chatgpt_login_disabled_reason"] or "子号当前不能登录"),
            )
        if action == "setup_security" and not bool(capabilities["can_setup_chatgpt_security"]):
            raise HTTPException(
                409,
                str(capabilities["chatgpt_security_setup_disabled_reason"] or "子号当前不能设置密码与 2FA"),
            )
        if action == "login_review" and not bool(
            capabilities["can_review_chatgpt_login"]
        ):
            raise HTTPException(
                409,
                str(
                    capabilities["chatgpt_login_review_disabled_reason"]
                    or "子号当前不能执行登录复核"
                ),
            )
        if action == "fetch_mail" and not bool(capabilities["can_fetch_mail"]):
            raise HTTPException(
                409,
                str(capabilities["fetch_mail_disabled_reason"] or "子号当前不能取件"),
            )
        return int(membership.id or 0), child


def _business_child_security_target(
    account_id: int,
    child_id: int,
    *,
    require_login: bool = True,
    purpose: Literal["credentials", "setup"] = "credentials",
) -> tuple[_BusinessChildSecurityTarget, GptPlanAccountModel]:
    """Resolve an exact pool child with action-specific security admission.

    Manual membership rows intentionally have no credential owner and are
    rejected by the established managed-child resolver. Setup may inspect an
    interrupted enrollment without a seed, while credentials retain the login
    gate. Setup and credential access always enforce child health and ownership.
    """
    if (
        isinstance(account_id, bool)
        or int(account_id) <= 0
        or isinstance(child_id, bool)
        or int(child_id) <= 0
    ):
        raise HTTPException(404, "该母号下不存在这个可设置安全信息的受管子号")
    binding, _member_source = _business_child_facade_binding(
        int(account_id),
        require_action=False,
    )
    membership_id, child = _existing_managed_business_child_account_target(
        binding,
        int(child_id),
        action=(
            "setup_security" if purpose == "setup"
            else "login" if require_login else "security_status"
        ),
    )
    _assert_member_source_binding_current(binding)
    normalized_email = _normalized_email(child.email)
    if not normalized_email:
        raise HTTPException(409, "子号邮箱无效，不能设置安全信息")
    target = _BusinessChildSecurityTarget(
        binding=binding,
        membership_id=int(membership_id),
        child_id=int(child_id),
        normalized_email=normalized_email,
    )
    # Resolve once more through the immutable scalar lease so route and worker
    # share the same identity predicate from the first browser instruction.
    with Session(engine) as session:
        child = _assert_business_child_security_membership_snapshot(
            session,
            target,
            require_healthy=bool(require_login or purpose == "setup"),
        )
    return target, child


@router.get(
    "/accounts/{account_id}/business-child-security/{child_id}"
)
def get_member_business_child_security_status(
    account_id: int,
    child_id: int,
):
    _target, child = _business_child_security_target(
        account_id,
        child_id,
        require_login=False,
    )
    return _public_chatgpt_security_status(
        _chatgpt_security_status_for_email(child.email)
    )


def _start_member_business_child_security_setup_internal(
    account_id: int,
    child_id: int,
    *,
    browser_mode: str,
    proxy: str,
    verified_unsubmitted_password: Any = None,
) -> dict[str, Any]:
    """Launch the canonical child security worker under the account lease."""
    target, child = _business_child_security_target(
        account_id, child_id, purpose="setup",
    )
    if browser_mode not in {"headed", "headless"}:
        raise HTTPException(400, "browser_mode 只支持 headed 或 headless")

    from api.tasks import _task_store
    from api import gpt_plan_operations as gpt_pro
    from api import gpt_business

    if gpt_business.managed_business_child_oauth_capability_running(
        int(target.binding.source_account_id),
        int(child_id),
    ):
        raise HTTPException(409, "该子号正在获取 RT，请等待完成后再设置 2FA")

    operation_token = gpt_pro._claim_gpt_pro_account_operation(
        int(child_id),
        "business_child_security_setup",
        ttl_hours=1,
        allow_managed_business_child=True,
    )

    task_id = (
        f"gpt_plan_business_child_setup_security_{int(account_id)}_"
        f"{int(child_id)}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    )
    try:
        _task_store.create(
            task_id,
            platform="chatgpt",
            total=1,
            source="gpt_plan_business_child_security",
            meta={
                "action_id": "setup_security",
                "account_id": int(account_id),
                "child_id": int(child_id),
                "membership_id": int(target.membership_id),
                "email": str(child.email or ""),
            },
        )
        worker = threading.Thread(
            target=_run_plan_security_setup_task,
            args=(task_id, int(child_id)),
            kwargs={
                "browser_mode": browser_mode,
                "proxy": proxy,
                "business_child_target": target,
                "child_operation_token": operation_token,
                **({"verified_unsubmitted_password": verified_unsubmitted_password}
                   if verified_unsubmitted_password is not None else {}),
            },
            daemon=True,
            name=(
                f"gpt-plan-child-security-{account_id}-{child_id}-"
                f"{task_id[-8:]}"
            ),
        )
        worker.start()
    except Exception:
        gpt_pro._release_gpt_pro_account_operation(
            int(child_id),
            operation_token,
        )
        if _task_store.exists(task_id):
            _task_store.finish(
                task_id,
                status="failed",
                success=0,
                skipped=0,
                errors=["安全设置后台任务启动失败"],
                error="安全设置后台任务启动失败",
            )
        raise
    return {"ok": True, "task_id": task_id}


@router.post(
    "/accounts/{account_id}/business-child-security/{child_id}/setup/task"
)
def start_member_business_child_security_setup(
    account_id: int,
    child_id: int,
    request: Request,
    body: Optional[GptPlanSecuritySetupTaskRequest] = None,
):
    _require_plan_security_setup_access(request)
    request_body = body or GptPlanSecuritySetupTaskRequest()
    params = dict(request_body.params or {})
    if request_body.browser_mode is not None:
        params["browser_mode"] = request_body.browser_mode
    if request_body.proxy is not None:
        params["proxy"] = request_body.proxy
    browser_mode = str(params.get("browser_mode") or "headless").strip().lower()
    proxy = _resolve_proxy(
        str(params.get("proxy") or "") if "proxy" in params else None
    )
    return _start_member_business_child_security_setup_internal(
        int(account_id),
        int(child_id),
        browser_mode=browser_mode,
        proxy=proxy,
    )


@router.get(
    "/accounts/{account_id}/business-child-security/{child_id}/setup/task/{task_id}"
)
def get_member_business_child_security_setup_task(
    account_id: int,
    child_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    from api.tasks import _task_store

    if not _task_store.exists(str(task_id)):
        raise HTTPException(404, "子号安全设置任务不存在")
    snapshot = _task_store.snapshot(str(task_id))
    meta = snapshot.get("meta") if isinstance(snapshot.get("meta"), dict) else {}
    if (
        snapshot.get("source") != "gpt_plan_business_child_security"
        or str(meta.get("action_id") or "") != "setup_security"
        or int(meta.get("account_id") or 0) != int(account_id)
        or int(meta.get("child_id") or 0) != int(child_id)
        or int(meta.get("membership_id") or 0) <= 0
    ):
        # A 404 avoids disclosing another mother's task existence.
        raise HTTPException(404, "子号安全设置任务不存在")
    current_target, _child = _business_child_security_target(
        int(account_id),
        int(child_id),
        require_login=False,
    )
    if int(current_target.membership_id) != int(meta.get("membership_id") or 0):
        raise HTTPException(409, "子号成员关系已变化，请重新发起安全设置")
    logs = snapshot.get("logs") if isinstance(snapshot.get("logs"), list) else []
    logs_total = len(logs)
    logs_offset = min(int(since), logs_total)
    snapshot["logs"] = logs[logs_offset:]
    snapshot["logs_offset"] = logs_offset
    snapshot["logs_total"] = logs_total
    snapshot["since"] = logs_total
    return snapshot


@router.post(
    "/accounts/{account_id}/business-child-security/{child_id}/export"
)
def export_member_business_child_security_credentials(
    account_id: int,
    child_id: int,
    request: Request,
):
    from api.auth import require_sensitive_credential_export_auth_header

    # Authenticate before resolving the mother/child identity so an
    # unauthenticated caller cannot use this sensitive endpoint as an oracle.
    require_sensitive_credential_export_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    _target, child = _business_child_security_target(account_id, child_id)
    return _plan_security_export_response(child)


def _raise_safe_business_child_account_action_error(
    exc: Exception,
    *,
    action_label: str,
    child: GptPlanAccountModel,
) -> None:
    status_code = 502
    detail: Any = exc
    if isinstance(exc, HTTPException):
        try:
            candidate_status = int(exc.status_code)
        except (TypeError, ValueError):
            candidate_status = 502
        if 400 <= candidate_status <= 599:
            status_code = candidate_status
        detail = exc.detail
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("detail") or detail.get("error")
    safe_detail = _redact_text(
        detail,
        str(child.password or ""),
        str(child.client_id or ""),
        str(child.refresh_token or ""),
        str(child.cookie_blob or ""),
    )[:500]
    raise HTTPException(
        status_code,
        safe_detail or f"子号{action_label}失败，请稍后重试",
    ) from exc


@router.post("/accounts/{account_id}/business-child-login/{child_id}")
def login_member_business_child(
    account_id: int,
    child_id: int,
    body: Optional[GptPlanLoginRequest] = None,
):
    """Log in one exact active BUSINESS pool child via the Plans facade."""
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可操作的受管子号")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=False,
    )
    membership_id, child = _existing_managed_business_child_account_target(
        binding,
        int(child_id),
        action="login",
    )
    _assert_member_source_binding_current(binding)
    body = body or GptPlanLoginRequest()
    try:
        from api import gpt_plan_operations as gpt_pro

        raw = gpt_pro._run_drission_login(
            int(child_id),
            gpt_pro.GptProActionRequest(
                proxy=body.proxy,
                headless=bool(body.headless),
                otp_timeout=max(30, min(int(body.otp_timeout or 180), 900)),
                keep_browser_open=bool(body.keep_browser_open),
                browser_backend=body.browser_backend,
                roxy_proxy_id=body.roxy_proxy_id,
            ),
        )
    except Exception as exc:
        _raise_safe_business_child_account_action_error(
            exc,
            action_label="登录",
            child=child,
        )
    value = raw if isinstance(raw, dict) else {}
    safe_error = _redact_text(
        value.get("error") or "",
        str(child.password or ""),
        str(child.client_id or ""),
        str(child.refresh_token or ""),
        str(child.cookie_blob or ""),
        str(value.get("access_token") or ""),
        str(value.get("session_token") or ""),
    )[:500]
    plan_type = _normalize_plan_type(value.get("plan_type"))
    return {
        "ok": bool(value.get("ok")),
        "account_id": int(account_id),
        "membership_id": int(membership_id),
        "child_id": int(child_id),
        "stage": str(value.get("stage") or "")[:80],
        "error": safe_error,
        "plan_type": plan_type,
        "plan_label": _plan_label(plan_type),
        "account_type": _account_type(plan_type),
        "member_plan": _canonical_member_plan(plan_type),
        "dead": bool(value.get("dead")),
    }


@router.post("/accounts/{account_id}/business-child-login-review/{child_id}")
def review_dead_member_business_child_login(
    account_id: int,
    child_id: int,
    body: Optional[GptPlanLoginRequest] = None,
):
    """Re-run a real ChatGPT login for one exact active Dead pool child.

    This is deliberately separate from normal child login and from RT.  A
    successful browser login refreshes the saved session.  ``dangerous`` is
    cleared only when the same operation lease and exact mother/child binding
    still hold after the browser returns; a failure keeps the Dead state.
    """
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可登录复核的受管子号")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=False,
    )
    membership_id, child = _existing_managed_business_child_account_target(
        binding,
        int(child_id),
        action="login_review",
    )
    _assert_member_source_binding_current(binding)
    body = body or GptPlanLoginRequest()
    from api import gpt_plan_operations as gpt_pro

    operation = "business_child_dead_review"
    operation_token = gpt_pro._claim_gpt_pro_account_operation(
        int(child_id),
        operation,
        allow_managed_business_child=True,
    )
    try:
        try:
            raw = gpt_pro._run_drission_login(
                int(child_id),
                gpt_pro.GptProActionRequest(
                    proxy=body.proxy,
                    headless=bool(body.headless),
                    otp_timeout=max(30, min(int(body.otp_timeout or 180), 900)),
                    keep_browser_open=bool(body.keep_browser_open),
                    browser_backend=body.browser_backend,
                    roxy_proxy_id=body.roxy_proxy_id,
                ),
            )
        except Exception as exc:
            _raise_safe_business_child_account_action_error(
                exc,
                action_label="登录复核",
                child=child,
            )

        value = raw if isinstance(raw, dict) else {}
        safe_error = _redact_text(
            value.get("error") or "",
            str(child.password or ""),
            str(child.client_id or ""),
            str(child.refresh_token or ""),
            str(child.cookie_blob or ""),
            str(value.get("access_token") or ""),
            str(value.get("session_token") or ""),
        )[:500]
        login_ok = bool(value.get("ok"))
        dead_confirmed = bool(value.get("dead")) or (
            str(value.get("stage") or "").strip().lower()
            == "account_deactivated"
        )
        recovered = bool(login_ok and not dead_confirmed)
        review_result = (
            "active_login_succeeded"
            if recovered
            else "account_deactivated"
            if dead_confirmed
            else "login_failed"
        )

        # The browser action can take minutes.  Re-resolve the exact active
        # pool membership and Plan binding before committing the review.
        _assert_member_source_binding_current(binding)
        current_membership_id, current_child = (
            _existing_managed_business_child_account_target(
                binding,
                int(child_id),
                action="fetch_mail",
            )
        )
        if int(current_membership_id) != int(membership_id):
            raise HTTPException(409, "登录复核期间子号成员关系已变化")
        reviewed_at = _utcnow()
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            if not gpt_pro._gpt_pro_account_operation_is_current(
                session,
                int(child_id),
                operation_token,
                operation,
            ):
                raise HTTPException(409, "登录复核操作租约已变化，请重新发起")
            plan_parent = session.get(
                GptPlanAccountModel,
                int(binding.plan_account_id),
            )
            persisted = session.get(GptPlanAccountModel, int(child_id))
            membership = session.get(
                GptBusinessChildMembershipModel,
                int(membership_id),
            )
            exact_binding = bool(
                plan_parent
                and _normalized_email(plan_parent.email)
                == binding.normalized_email
                and str(plan_parent.source_pool or "").strip().lower()
                == "gpt_business"
                and int(plan_parent.source_account_id or 0)
                == int(binding.source_account_id)
                and persisted
                and bool(persisted.enabled)
                and not bool(persisted.policy_warning)
                and not str(persisted.refund_status or "").strip()
                and int(getattr(persisted, "business_parent_id", None) or 0)
                == int(binding.source_account_id)
                and _normalized_email(persisted.email)
                == _normalized_email(current_child.email)
                and membership
                and membership.ended_at is None
                and int(membership.business_account_id or 0)
                == int(binding.source_account_id)
                and int(membership.pro_account_id or 0) == int(child_id)
                and str(membership.source or "").strip().lower() == "pool"
                and _normalized_email(membership.email)
                == _normalized_email(persisted.email)
                and bool(
                    _safe_business_remote_identifier(membership.remote_user_id)
                    or _safe_business_remote_identifier(
                        membership.remote_invite_id
                    )
                )
            )
            if not exact_binding:
                raise HTTPException(409, "登录复核期间子号归属已变化")

            extra = _safe_json_object(persisted.extra_json)
            extra["dead_login_reviewed_at"] = reviewed_at.isoformat()
            extra["dead_login_review_result"] = review_result
            if recovered:
                extra["dead_login_review_recovered_at"] = reviewed_at.isoformat()
                extra["dead_login_review_previous_detected_at"] = _iso_utc(
                    persisted.dangerous_detected_at
                )
                for key in (
                    "codex_oauth_account_deactivated",
                    "codex_oauth_account_deactivated_at",
                    "codex_oauth_account_deactivated_task_id",
                ):
                    extra.pop(key, None)
                if (
                    str(extra.get("business_rotation_oauth_status") or "")
                    .strip().lower()
                    == "account_deactivated"
                ):
                    extra.pop("business_rotation_oauth_status", None)
                    extra.pop("business_rotation_oauth_finished_at", None)
                persisted.dangerous = False
                persisted.dangerous_detected_at = None
            # Never persist browser error text here; it can contain a URL or
            # transient authentication material.  Only the redacted response
            # returned to this caller contains the current failure reason.
            persisted.extra_json = json.dumps(extra, ensure_ascii=False)
            persisted.updated_at = reviewed_at
            session.add(persisted)
            session.commit()

        plan_type = _normalize_plan_type(value.get("plan_type"))
        return {
            "ok": login_ok,
            "account_id": int(account_id),
            "membership_id": int(membership_id),
            "child_id": int(child_id),
            "stage": str(value.get("stage") or "")[:80],
            "error": safe_error,
            "plan_type": plan_type,
            "plan_label": _plan_label(plan_type),
            "account_type": _account_type(plan_type),
            "member_plan": _canonical_member_plan(plan_type),
            "review_result": review_result,
            "dead": bool(dead_confirmed and not recovered),
            "dead_cleared": recovered,
            "reviewed_at": reviewed_at.isoformat(),
        }
    finally:
        gpt_pro._release_gpt_pro_account_operation(
            int(child_id),
            operation_token,
        )


@router.post("/accounts/{account_id}/business-child-fetch-mail/{child_id}")
def fetch_member_business_child_mail(
    account_id: int,
    child_id: int,
    body: Optional[GptPlanFetchMailRequest] = None,
):
    """Fetch recent mail for one exact active BUSINESS pool child."""
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可操作的受管子号")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=False,
    )
    membership_id, child = _existing_managed_business_child_account_target(
        binding,
        int(child_id),
        action="fetch_mail",
    )
    _assert_member_source_binding_current(binding)
    body = body or GptPlanFetchMailRequest()
    limit = max(1, min(int(body.limit or 10), 50))
    snapshot = _account_mail_snapshot(child)
    try:
        # Share the Plan mailbox reader's global Inbox/Junk ordering and
        # explicit provider failures, without running the main mail route's
        # lifecycle reconciliation for this managed child.
        method, messages = _fetch_recent_messages(
            snapshot,
            limit=limit,
            folder=str(body.folder or "").strip(),
            fallback_imap_on_graph_error=True,
        )
    except Exception as exc:
        if not isinstance(exc, HTTPException):
            exc = HTTPException(400, f"取件失败: {exc}")
        _raise_safe_business_child_account_action_error(
            exc,
            action_label="取件",
            child=child,
        )
    messages = list(messages or [])[:limit]
    mail_access_type = (
        "icloud" if method == "qqmail"
        else snapshot["mail_access_type"] or ("imap_pop" if method == "imap" else method)
    )
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(child_id))
        if account is not None:
            account.last_used = _utcnow()
            session.add(account)
            session.commit()
    return {
        "account_id": int(account_id),
        "membership_id": int(membership_id),
        "child_id": int(child_id),
        "email": _safe_business_child_email(snapshot["email"]),
        "mail_access_type": str(mail_access_type or "")[:40],
        "method": str(method or "")[:40],
        "count": len(messages),
        "messages": messages,
    }


def _assert_business_child_not_batch_locked(child_id: int) -> None:
    """Keep a manual RT click out of a running batch child operation."""
    now = _utcnow()
    with Session(engine) as session:
        lease = session.get(GptPlanAccountOperationLeaseModel, int(child_id))
        if lease and (_aware_utc(lease.expires_at) or now) > now:
            raise HTTPException(
                409,
                {
                    "code": "gpt_plan_account_busy",
                    "message": f"子号正在执行 {lease.operation}，请等待完成后再试",
                    "operation": str(lease.operation or "account_operation"),
                    "expires_at": _iso_utc(lease.expires_at),
                },
            )


@router.post("/accounts/{account_id}/business-child-oauth/{child_id}")
def member_business_child_oauth_start(account_id: int, child_id: int):
    """Start or reuse OAuth for one exact existing managed BUSINESS child."""
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可获取 RT 的受管子号")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
    )
    membership_id = _existing_managed_business_child_oauth_target(
        binding,
        int(child_id),
    )
    # Close the plan-row rebind race before launching a browser task.  The
    # source launcher independently fences token writeback to the same active
    # parent/child membership.
    _assert_member_source_binding_current(binding)
    _assert_business_child_not_batch_locked(int(child_id))
    try:
        from api import gpt_business

        raw = gpt_business.start_managed_business_child_oauth_capability(
            int(binding.source_account_id),
            int(child_id),
            allow_workspace_login=True,
            direct_oauth=True,
            headless=True,
            keep_browser_open=False,
            otp_timeout=180,
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    value = raw if isinstance(raw, dict) else {}
    task_id = _safe_business_remote_identifier(value.get("task_id"))
    if not bool(value.get("ok", True)) or not task_id:
        raise HTTPException(502, "RT 任务未能安全启动，请稍后重试")
    return {
        "ok": True,
        "account_id": int(account_id),
        "membership_id": int(membership_id),
        "rt_child_id": int(child_id),
        "rt_status": "running",
        "rt_task_id": task_id,
        "rt_task_idempotent": bool(value.get("idempotent")),
    }


@router.get(
    "/accounts/{account_id}/business-child-oauth/{child_id}/{task_id}"
)
def member_business_child_oauth_status(
    account_id: int,
    child_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    """Return a redacted RT task snapshot for one exact bound BUSINESS child."""
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
    )
    if int(child_id) <= 0:
        raise HTTPException(404, "任务不存在或已过期")
    from api import gpt_business

    try:
        raw = gpt_business.managed_business_child_oauth_capability_status(
            int(binding.source_account_id),
            int(child_id),
            str(task_id or ""),
            since=max(0, int(since or 0)),
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    _assert_member_source_binding_current(binding)
    value = raw if isinstance(raw, dict) else {}
    status = str(value.get("status") or "running").strip().lower()
    if status not in {"running", "done", "failed"}:
        status = "running"
    logs = value.get("logs") if isinstance(value.get("logs"), list) else []
    result = {
        "task_id": str(task_id or ""),
        "action": "oauth",
        "status": status,
        "logs": [_sanitize_member_task_text(item) for item in logs[-100:]],
        "since": max(0, int(value.get("since") or 0)),
        "result": _safe_member_task_result("oauth", value.get("result")),
        "error": _sanitize_member_task_text(value.get("error") or ""),
        "started_at": str(value.get("started_at") or ""),
        "finished_at": str(value.get("finished_at") or ""),
    }
    return result


# BUSINESS child bulk actions keep a bounded in-memory working set and a
# credential-free durable snapshot. Canonical account/security/membership
# stores remain the authority for deciding whether a step must run again.
_BUSINESS_CHILD_BATCH_ACTION_TASKS: dict[str, dict[str, Any]] = {}
_BUSINESS_CHILD_BATCH_ACTION_LOCK = threading.RLock()
_BUSINESS_CHILD_BATCH_ACTION_RUN_LOCK = threading.Lock()
_BUSINESS_CHILD_BATCH_ACTION_MAX_TARGETS = 100
_BUSINESS_CHILD_BATCH_ACTION_MAX_FINISHED = 50
_BUSINESS_CHILD_BATCH_ACTION_RETAIN_SECONDS = 2 * 60 * 60
_BUSINESS_CHILD_BATCH_ACTION_MAX_LOGS = 4_000
_BUSINESS_CHILD_BATCH_ITEM_MAX_LOGS = 300
_BUSINESS_CHILD_ACTION_WAIT_SECONDS = 20 * 60
_BUSINESS_CHILD_ACTION_POLL_SECONDS = 1.0
_BUSINESS_CHILD_BATCH_TERMINAL = frozenset({"success", "failed", "skipped"})


def _persist_business_child_batch_action_task(task: dict[str, Any]) -> None:
    from services.business_child_batch_action_store import save
    save(task)


def _strict_business_child_batch_membership_ids(values: Any) -> list[int]:
    if not isinstance(values, list) or not values:
        raise HTTPException(400, "membership_ids 必须是非空成员 ID 数组")
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise HTTPException(400, "membership_ids 只能包含正整数成员 ID")
        if int(value) in seen:
            continue
        seen.add(int(value))
        result.append(int(value))
    if len(result) > _BUSINESS_CHILD_BATCH_ACTION_MAX_TARGETS:
        raise HTTPException(
            400,
            f"单次最多处理 {_BUSINESS_CHILD_BATCH_ACTION_MAX_TARGETS} 个子号",
        )
    return result


def _resolve_business_child_batch_action_target(
    membership_id: int,
    action: Literal["setup_security", "oauth", "leave_workspace"],
) -> dict[str, Any]:
    """Derive one exact child and mother solely from the membership id."""
    if action == "leave_workspace":
        return _resolve_business_child_batch_leave_target(int(membership_id))
    with Session(engine) as session:
        membership, child, parent, _source_parent = (
            _active_business_child_dimension_target(session, int(membership_id))
        )
        if (
            child is None
            or str(membership.source or "").strip().lower() != "pool"
            or membership.pro_account_id is None
        ):
            raise HTTPException(409, "所选成员不是可自动操作的账号池子号")
        if not bool(
            child.enabled
            and not child.dangerous
            and not child.policy_warning
            and not str(child.refund_status or "").strip()
        ):
            raise HTTPException(409, "所选子号已停用、告警或进入退款流程")
        if not bool(
            _safe_business_remote_identifier(membership.remote_user_id)
            or _safe_business_remote_identifier(membership.remote_invite_id)
        ):
            raise HTTPException(409, "所选子号缺少远端成员或邀请身份")
        frozen = {
            "membership_id": int(membership.id or 0),
            "parent_account_id": int(parent.id or 0),
            "source_account_id": int(membership.business_account_id),
            "child_id": int(child.id or 0),
            "email": _safe_business_child_email(child.email),
        }

    # Reuse the public child capability's complete ownership predicates rather
    # than widening this batch endpoint into another action implementation.
    if action == "setup_security":
        target, _child = _business_child_security_target(
            int(frozen["parent_account_id"]),
            int(frozen["child_id"]),
            purpose="setup",
        )
        resolved_membership_id = int(target.membership_id)
    else:
        binding, _member_source = _business_child_facade_binding(
            int(frozen["parent_account_id"]),
            require_action=True,
        )
        resolved_membership_id = _existing_managed_business_child_oauth_target(
            binding,
            int(frozen["child_id"]),
        )
    if resolved_membership_id != int(frozen["membership_id"]):
        raise HTTPException(409, "子号成员关系在任务创建期间发生变化")
    return frozen


def _resolve_business_child_batch_leave_target(membership_id: int) -> dict[str, Any]:
    # A manually invited email and an unhealthy pool child are both removable;
    # security/OAuth prerequisites must not become exit prerequisites.
    with Session(engine) as session:
        membership, _child, parent, source_parent = (
            _active_business_child_dimension_target(
                session, membership_id, require_member_parent=False,
            )
        )
        frozen = {
            "membership_id": int(membership.id),
            "parent_account_id": int(parent.id),
            "source_account_id": int(source_parent.id),
            "parent_email": _normalized_email(parent.email),
            "child_id": int(membership.pro_account_id or 0),
            "email": _safe_business_child_email(membership.email),
            "source": str(membership.source or "").strip().lower(),
            "user_id": _safe_business_remote_identifier(membership.remote_user_id),
            "invite_id": _safe_business_remote_identifier(membership.remote_invite_id),
            "operation_id": f"batch-leave-{uuid.uuid4().hex}",
        }
    if not frozen["email"] or frozen["email"] == frozen["parent_email"]:
        raise HTTPException(409, "不能退出 BUSINESS 工作区母号/所有者或未知邮箱")
    if not frozen["user_id"]:
        raise HTTPException(409, "批量退出仅支持已加入成员，不能撤销待接受邀请")
    # Check the same mother capability/session used by single-member removal.
    binding, _member_source = _business_child_facade_binding(
        int(frozen["parent_account_id"]), require_action=True,
    )
    _assert_business_child_batch_leave_binding(frozen, binding)
    _business_child_batch_leave_complete(frozen)
    return frozen


def _assert_business_child_batch_leave_binding(
    target: dict[str, Any], binding: _MemberSourceBinding,
) -> None:
    if (
        binding.plan_account_id != int(target["parent_account_id"])
        or binding.source_pool != "gpt_business"
        or binding.source_account_id != int(target["source_account_id"])
        or binding.normalized_email != target["parent_email"]
    ):
        raise HTTPException(409, "批量退出目标的母号绑定已变化，未执行退出")


def _business_child_batch_leave_complete(
    target: dict[str, Any], *, require_operation: bool = False,
) -> bool:
    """Validate the frozen row, never resolve a replacement by child/email."""
    changed = "批量退出目标的成员或母号身份已变化，未确认退出"
    with Session(engine) as session:
        parent = session.get(GptPlanAccountModel, int(target["parent_account_id"]))
        source = session.get(GptBusinessAccountModel, int(target["source_account_id"]))
        membership = session.get(
            GptBusinessChildMembershipModel, int(target["membership_id"]),
        )
        if (
            parent is None or source is None or membership is None
            or str(parent.source_pool or "") != "gpt_business"
            or int(parent.source_account_id or 0) != int(target["source_account_id"])
            or _normalized_email(parent.email) != target["parent_email"]
            or _normalized_email(source.email) != target["parent_email"]
            or int(membership.business_account_id) != int(target["source_account_id"])
            or _safe_business_child_email(membership.email) != target["email"]
            or str(membership.source or "").strip().lower() != target["source"]
            or _safe_business_remote_identifier(membership.remote_user_id) != target["user_id"]
            or _safe_business_remote_identifier(membership.remote_invite_id) != target["invite_id"]
            or not target["user_id"]
            or target["email"] == target["parent_email"]
        ):
            raise HTTPException(409, changed)
        ended = membership.ended_at is not None
        child_id = int(target["child_id"])
        child = session.get(GptPlanAccountModel, child_id) if child_id else None
        # Canonical removal can purge a released Dead child and detach its id
        # from history; the immutable membership/remote identity still applies.
        purged_after_exit = bool(
            ended and child_id and child is None and membership.pro_account_id is None
        )
        if int(membership.pro_account_id or 0) != child_id and not purged_after_exit:
            raise HTTPException(409, changed)
        if child_id and not ended and (
            child is None
            or int(child.business_parent_id or 0) != int(target["source_account_id"])
            or _normalized_email(child.email) != target["email"]
        ):
            raise HTTPException(409, changed)
        if not ended and (
            bool(membership.intent_remote_started)
            or str(membership.end_reason or "").startswith("pending:")
        ):
            # A recovered batch may continue only its own immutable operation.
            # The canonical remove capability will reconcile that operation
            # before deciding whether another remote request is necessary.
            if str(membership.operation_id or "") != str(target["operation_id"]):
                raise HTTPException(409, "该成员已有另一项未确认的退出操作")
            return False
        if require_operation:
            return bool(
                ended
                and str(membership.operation_id or "") == target["operation_id"]
                and (
                    child is None
                    or int(child.business_parent_id or 0) != int(target["source_account_id"])
                )
            )
        return ended


def _run_business_child_batch_leave(target: dict[str, Any]) -> None:
    body = GptPlanBusinessChildRemoveRequest(
        operation_id=str(target["operation_id"]),
        membership_id=int(target["membership_id"]),
        confirm_remove=True,
    )
    body._batch_expected_target = dict(target)
    try:
        result = member_business_remove(int(target["parent_account_id"]), body)
    except Exception as exc:
        from services.nv_exit_recovery import BusinessExitPreflightError
        if isinstance(exc, BusinessExitPreflightError):
            # Typed only before the canonical source mutation was called.
            # Do not flatten this proven no-op into an unknown remote outcome.
            raise
        # Keep the same immutable operation id. The batch worker persists it
        # and later resumes through the canonical removal capability, which
        # first reconciles the durable intent and current member state.
        if isinstance(exc, HTTPException):
            detail = _business_child_batch_action_error(exc)[:350]
            raise RuntimeError(
                f"HTTP {exc.status_code}：{detail}"
            ) from None
        raise RuntimeError(
            f"退出结果暂未确认（{type(exc).__name__}）"
        ) from None
    if not isinstance(result, dict) or not (
        result.get("ok") is True
        and result.get("removed") is True
        and result.get("persistence_confirmed") is True
        and result.get("release_kind") == "member"
        and not any(result.get(key) for key in (
            "partial", "action_required", "binding_changed", "identity_changed", "revoked",
        ))
        and result.get("membership_id") == int(target["membership_id"])
        and result.get("account_id") == int(target["parent_account_id"])
        and result.get("operation_id") == target["operation_id"]
    ):
        reason = "退出接口未返回可确认结果"
        extra: list[str] = []
        if isinstance(result, dict):
            if any(result.get(key) for key in ("binding_changed", "identity_changed")) or (
                result.get("membership_id") != int(target["membership_id"])
                or result.get("account_id") != int(target["parent_account_id"])
            ):
                reason = "退出期间成员或母号身份已变化"
            elif result.get("persistence_confirmed") is not True:
                reason = "本地退出历史尚未确认"
            elif result.get("partial") or result.get("action_required"):
                reason = "退出仅部分完成，等待自动核对"
            elif result.get("release_kind") != "member" or result.get("revoked"):
                reason = "返回的操作不是已加入成员退出"
            else:
                reason = "未确认该成员及本次操作已完成退出"
            status_code = result.get("status")
            if isinstance(status_code, int) and not isinstance(status_code, bool):
                extra.append(f"HTTP {status_code}")
            for key in ("warning", "error"):
                if isinstance(result.get(key), str) and result[key].strip():
                    safe = _sanitize_member_task_text(result[key])[:130]
                    if safe not in extra:
                        extra.append(safe)
        if extra:
            # Whitespace terminates token/password redaction even after these
            # already-sanitized fragments pass through public task logging.
            reason += "：" + " ； ".join(extra)
        raise RuntimeError(reason[:380])
    if not _business_child_batch_leave_complete(target, require_operation=True):
        raise RuntimeError("退出历史尚未确认，等待自动核对")


def _business_child_action_complete(
    target: dict[str, Any],
    action: Literal["setup_security", "oauth", "leave_workspace"],
) -> bool:
    if action == "leave_workspace":
        return _business_child_batch_leave_complete(target)
    current = _resolve_business_child_batch_action_target(
        int(target["membership_id"]),
        action,
    )
    if any(
        current.get(key) != target.get(key)
        for key in (
            "membership_id",
            "parent_account_id",
            "source_account_id",
            "child_id",
            "email",
        )
    ):
        raise HTTPException(409, "子号成员归属已变化")
    if action == "setup_security":
        status = _chatgpt_security_status_for_email(str(target["email"]))
        return bool(
            status.get("credentials_readable")
            and status.get("has_password")
            and status.get("has_totp")
            and str(status.get("password_state") or "").strip().lower()
            == "configured"
            and str(status.get("mfa_state") or "").strip().lower()
            == "enabled"
        )
    with Session(engine) as session:
        child = session.get(GptPlanAccountModel, int(target["child_id"]))
        return bool(child and str(child.codex_refresh_token or "").strip())


def _prune_business_child_batch_action_tasks_locked() -> None:
    cutoff = _utcnow() - timedelta(
        seconds=_BUSINESS_CHILD_BATCH_ACTION_RETAIN_SECONDS
    )
    finished: list[tuple[datetime, str]] = []
    for task_id, task in _BUSINESS_CHILD_BATCH_ACTION_TASKS.items():
        if not str(task.get("finished_at") or ""):
            continue
        try:
            parsed = datetime.fromisoformat(str(task["finished_at"]))
            parsed = parsed if parsed.tzinfo else parsed.replace(
                tzinfo=timezone.utc
            )
        except (TypeError, ValueError):
            parsed = datetime.min.replace(tzinfo=timezone.utc)
        finished.append((parsed, task_id))
    finished.sort(reverse=True)
    keep = {
        task_id
        for parsed, task_id in finished[:_BUSINESS_CHILD_BATCH_ACTION_MAX_FINISHED]
        if parsed >= cutoff
    }
    for _parsed, task_id in finished:
        if task_id not in keep:
            _BUSINESS_CHILD_BATCH_ACTION_TASKS.pop(task_id, None)


def _recompute_business_child_batch_action_progress_locked(
    task: dict[str, Any],
) -> None:
    items = task.get("items") if isinstance(task.get("items"), list) else []
    total = len(items)
    completed = sum(
        str(item.get("status") or "") in _BUSINESS_CHILD_BATCH_TERMINAL
        for item in items if isinstance(item, dict)
    )
    success = sum(
        str(item.get("status") or "") == "success"
        for item in items if isinstance(item, dict)
    )
    failed = sum(
        str(item.get("status") or "") == "failed"
        for item in items if isinstance(item, dict)
    )
    skipped = sum(
        str(item.get("status") or "") == "skipped"
        for item in items if isinstance(item, dict)
    )
    percent = int(completed * 100 / total) if total else 100
    if str(task.get("status") or "") not in {"done", "failed"}:
        percent = min(99, percent)
    task["progress"] = {
        "total": total,
        "completed": completed,
        "success": success,
        "successful": success,
        "failed": failed,
        "skipped": skipped,
        "percent": min(100, max(0, percent)),
    }
    _persist_business_child_batch_action_task(task)


def _business_child_batch_action_log(
    task_id: str,
    message: Any,
    *,
    item_index: Optional[int] = None,
) -> None:
    safe = _sanitize_member_task_text(message)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {safe}"
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
        if task is None:
            return
        logs = task.setdefault("logs", [])
        cursor = max(0, int(task.get("log_cursor") or len(logs)))
        start = max(0, int(task.get("log_start") or max(0, cursor - len(logs))))
        logs.append(line)
        cursor += 1
        if len(logs) > _BUSINESS_CHILD_BATCH_ACTION_MAX_LOGS:
            removed = len(logs) - _BUSINESS_CHILD_BATCH_ACTION_MAX_LOGS
            task["logs"] = logs[removed:]
            start += removed
        task["log_cursor"] = cursor
        task["log_start"] = start
        if item_index is not None:
            items = task.get("items") if isinstance(task.get("items"), list) else []
            if 0 <= int(item_index) < len(items):
                item_logs = items[int(item_index)].setdefault("logs", [])
                item_logs.append(line)
                if len(item_logs) > _BUSINESS_CHILD_BATCH_ITEM_MAX_LOGS:
                    items[int(item_index)]["logs"] = item_logs[
                        -_BUSINESS_CHILD_BATCH_ITEM_MAX_LOGS:
                    ]
        _persist_business_child_batch_action_task(task)


def _business_child_batch_action_error(value: Any) -> str:
    detail = getattr(value, "detail", None)
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("detail") or detail.get("error")
    return _sanitize_member_task_text(detail or value or "子号操作失败")


def _wait_business_child_security_task(
    task_id: str,
    *,
    emit: Callable[[Any], None],
    on_snapshot: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    from api.tasks import _task_store

    cursor = 0
    deadline = time.monotonic() + _BUSINESS_CHILD_ACTION_WAIT_SECONDS
    while time.monotonic() < deadline:
        if not _task_store.exists(str(task_id)):
            raise RuntimeError("子号安全设置任务不存在或已过期")
        snapshot = _task_store.snapshot(str(task_id))
        if on_snapshot is not None:
            # The NV caller persists a bounded progress DTO under its lease.
            # Let ownership failures propagate; never hide them and continue.
            on_snapshot(snapshot)
        logs = snapshot.get("logs") if isinstance(snapshot.get("logs"), list) else []
        for line in logs[cursor:]:
            emit(line)
        cursor = len(logs)
        status = str(snapshot.get("status") or "running").strip().lower()
        if status in {"done", "failed", "stopped"}:
            return snapshot
        time.sleep(_BUSINESS_CHILD_ACTION_POLL_SECONDS)
    raise TimeoutError("子号安全设置等待超过 20 分钟")


def _run_business_child_oauth_with_lease(
    target: dict[str, Any],
    *,
    emit: Callable[[Any], None],
    before_start: Callable[[], None] | None = None,
    allow_phone_verification: bool = True,
    expected_invited_at: str | None = None,
    allow_existing_credentials: bool = False,
) -> dict[str, Any]:
    """Run the canonical managed-child OAuth under one CAS account lease."""
    from api import gpt_business
    from api import gpt_plan_operations as gpt_pro

    if type(allow_phone_verification) is not bool:
        raise ValueError("allow_phone_verification must be a boolean")
    if expected_invited_at is not None and (not isinstance(expected_invited_at, str) or not expected_invited_at.strip()):
        raise ValueError("expected_invited_at must be a nonempty timestamp")

    child_id = int(target["child_id"])
    source_account_id = int(target["source_account_id"])
    operation_token = gpt_pro._claim_gpt_pro_account_operation(
        child_id,
        "business_child_batch_oauth",
        ttl_hours=1,
        allow_managed_business_child=True,
    )
    task_id = ""
    try:
        if before_start is not None:
            before_start()
        raw = gpt_business.start_managed_business_child_oauth_capability(
            source_account_id,
            child_id,
            allow_workspace_login=True,
            direct_oauth=True,
            expected_operation_token=operation_token,
            headless=True,
            keep_browser_open=False,
            otp_timeout=180,
            **({"allow_phone_verification": False} if not allow_phone_verification else {}),
            **({"expected_invited_at": expected_invited_at} if expected_invited_at is not None else {}),
            **({"allow_existing_credentials": True} if allow_existing_credentials else {}),
        )
        task_id = _safe_business_remote_identifier((raw or {}).get("task_id"))
        if not bool((raw or {}).get("ok", True)) or not task_id:
            detail = _sanitize_member_task_text(
                (raw or {}).get("error") or (raw or {}).get("message") or ""
            ).strip()
            raise RuntimeError("RT 任务未能安全启动" + (f"：{detail}" if detail else ""))
        emit("RT 任务已启动")
        cursor = 0
        deadline = time.monotonic() + _BUSINESS_CHILD_ACTION_WAIT_SECONDS
        while time.monotonic() < deadline:
            snapshot = gpt_business.managed_business_child_oauth_capability_status(
                source_account_id,
                child_id,
                task_id,
                since=cursor,
            )
            logs = (
                snapshot.get("logs")
                if isinstance(snapshot.get("logs"), list) else []
            )
            for line in logs:
                emit(line)
            cursor = max(cursor, int(snapshot.get("since") or cursor))
            status = str(snapshot.get("status") or "running").strip().lower()
            if status in {"done", "failed"}:
                task_result = snapshot.get("result")
                failure = normalize_oauth_failure(task_result.get("oauth_failure")) if isinstance(task_result, dict) else None
                return {
                    "task_id": task_id,
                    "status": status,
                    "error": _sanitize_member_task_text(
                        snapshot.get("error") or ""
                    ),
                    **({"oauth_failure": failure} if failure is not None else {}),
                }
            time.sleep(_BUSINESS_CHILD_ACTION_POLL_SECONDS)
        raise TimeoutError("子号 RT 等待超过 20 分钟")
    finally:
        gpt_pro._release_gpt_pro_account_operation(child_id, operation_token)


def _reconcile_persisted_business_child_oauth(
    target: dict[str, Any],
    acquired_after: str,
) -> dict[str, Any]:
    """Re-read membership only after this exact OAuth attempt saved credentials.

    ``target`` includes the ordinary batch identity plus ``parent_email`` and
    ``membership_invited_at``; optional remote IDs strengthen its identity fence.
    The five-field result never contains credentials or remote response text.
    ``retryable`` authorizes another read of this helper, never another OAuth.
    """
    def result(code: str, error: str = "", *, eligible: bool = False,
               verified: bool = False, retryable: bool = False) -> dict[str, Any]:
        return {"eligible": eligible, "verified": verified,
                "retryable": retryable, "reason_code": code, "error": error}

    def date(value: Any) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("missing timestamp")
        return _aware_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))

    def identifier(value: Any) -> str:
        return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else ""

    try:
        if not isinstance(target, dict) or any(
            type(target.get(key)) is not int or target[key] <= 0
            for key in ("membership_id", "parent_account_id", "source_account_id", "child_id")
        ):
            raise ValueError("invalid identity")
        email = _normalized_email(target.get("email"))
        parent_email = _normalized_email(target.get("parent_email"))
        if (not re.fullmatch(r"[^\s@]+@[^\s@]+", email)
                or not re.fullmatch(r"[^\s@]+@[^\s@]+", parent_email)
                or email == parent_email):
            raise ValueError("invalid email")
        floor = date(acquired_after)
        invited_at = date(target.get("membership_invited_at"))
        if not invited_at <= floor <= _utcnow():
            raise ValueError("invalid cycle")
        if any(target.get(key) and not identifier(target[key])
               for key in ("remote_user_id", "remote_invite_id")):
            raise ValueError("invalid remote identity")
    except (TypeError, ValueError, AttributeError, OverflowError):
        return result("oauth_evidence_invalid", "本次 OAuth 的冻结身份或邀请周期证据不完整，需要人工核对")

    def local_snapshot() -> dict[str, Any]:
        with Session(engine) as session:
            membership, child, parent, source = _active_business_child_dimension_target(
                session, target["membership_id"],
            )
            if (
                child is None or parent.id != target["parent_account_id"]
                or source.id != target["source_account_id"]
                or child.id != target["child_id"]
                or parent.business_parent_id is not None
                or _normalized_email(parent.email) != parent_email
                or _normalized_email(source.email) != parent_email
                or _normalized_email(child.email) != email
                or _normalized_email(membership.email) != email
                or _aware_utc(membership.invited_at) != invited_at
                or not child.enabled or child.dangerous or child.policy_warning
                or bool(str(child.refund_status or "").strip())
            ):
                raise HTTPException(409, "identity changed")
            remote_user = identifier(membership.remote_user_id)
            remote_invite = identifier(membership.remote_invite_id)
            if (
                (membership.remote_user_id and not remote_user)
                or (membership.remote_invite_id and not remote_invite)
                or (target.get("remote_user_id") and target["remote_user_id"] != remote_user)
                or (target.get("remote_invite_id") and not remote_user
                    and target["remote_invite_id"] != remote_invite)
            ):
                raise HTTPException(409, "remote identity changed")
            acquired = _aware_utc(child.codex_rt_acquired_at)
            complete = bool(acquired and floor <= acquired <= _utcnow() and all(
                str(value or "").strip() for value in (
                    child.codex_access_token, child.codex_refresh_token, child.codex_id_token,
                )
            ))
            return {"complete": complete, "acquired_at": acquired,
                    "remote_user_id": remote_user, "remote_invite_id": remote_invite}

    try:
        before = local_snapshot()
    except HTTPException:
        return result("identity_changed", "母子账号绑定、邀请周期或账号状态已变化，需要人工核对")
    except Exception:
        return result("local_evidence_unconfirmed", "本地 OAuth 落库证据读取失败，需要人工核对")
    if not before["complete"]:
        return result("oauth_evidence_missing", "未确认本次 OAuth 已保存完整凭证，需要人工核对")

    # This capability reads the remote workspace and synchronizes membership;
    # it does not log in, accept an invitation, refresh RT or issue OAuth.
    from api import gpt_business
    workspace = None
    remote_error = None
    try:
        workspace = gpt_business.workspace_members(target["source_account_id"])
    except Exception as exc:
        remote_error = exc

    # A read failure cannot hide a concurrent rebind/removal or lost evidence.
    try:
        after = local_snapshot()
    except HTTPException:
        return result("identity_changed", "核对期间母子账号绑定、邀请周期或账号状态已变化，需要人工核对")
    except Exception:
        return result("local_evidence_unconfirmed", "核对后的本地 OAuth 证据读取失败，需要人工核对")
    if not after["complete"] or after["acquired_at"] != before["acquired_at"]:
        return result("oauth_evidence_changed", "核对期间本次 OAuth 落库证据已变化，需要人工核对")
    if before["remote_user_id"] and before["remote_user_id"] != after["remote_user_id"]:
        return result("identity_changed", "核对期间已确认的远端成员身份已变化，需要人工核对")

    if remote_error is not None:
        network_errors = (TimeoutError, ConnectionError)
        try:
            from curl_cffi.requests.exceptions import ConnectionError as CurlConnectionError, Timeout as CurlTimeout
            network_errors += (CurlConnectionError, CurlTimeout)
        except ImportError:
            pass
        transient = isinstance(remote_error, network_errors)
        busy = False
        if isinstance(remote_error, HTTPException):
            detail = remote_error.detail if isinstance(remote_error.detail, dict) else {}
            busy = remote_error.status_code == 409 and detail.get("code") == "business_parent_automation_busy"
            transient = busy or remote_error.status_code in {408, 429, 502, 503, 504}
        return result(
            "workspace_refresh_busy" if busy else "workspace_read_failed",
            "本次 RT 已保存，工作区读取暂未完成，稍后仅重试成员核对" if transient
            else "本次 RT 已保存，工作区核对失败，需要人工核对",
            eligible=True, retryable=transient,
        )
    if isinstance(workspace, dict) and workspace.get("fresh") is False and workspace.get("cached") is True:
        return result("workspace_read_unconfirmed", "本次 RT 已保存，远端刷新失败，仅取得旧成员快照",
                      eligible=True, retryable=True)
    if (not isinstance(workspace, dict) or workspace.get("fresh") is not True
            or workspace.get("cached") is not False
            or not isinstance(workspace.get("members"), list)
            or not isinstance(workspace.get("invites"), list)
            or not isinstance(workspace.get("membership_conflicts"), list)):
        return result("workspace_evidence_invalid", "工作区未返回完整的本次成员证据，需要人工核对", eligible=True)
    if any(not isinstance(row, dict) for key in ("members", "invites", "membership_conflicts") for row in workspace[key]):
        return result("workspace_evidence_invalid", "工作区成员证据格式不完整，需要人工核对", eligible=True)
    if any(_normalized_email(row.get("email")) == email for row in workspace["membership_conflicts"]):
        return result("workspace_membership_conflict", "目标子号的成员记录写回冲突，需要人工核对", eligible=True)
    members = [row for row in workspace["members"] if _normalized_email(row.get("email")) == email]
    invites = [row for row in workspace["invites"] if _normalized_email(row.get("email")) == email]
    if len(members) == 1 and not invites:
        remote = members[0]
        if (remote.get("deactivated") is False and identifier(remote.get("user_id"))
                and remote["user_id"] == after["remote_user_id"]
                and not after["remote_invite_id"]):
            return result("verified", eligible=True, verified=True)
        return result("workspace_member_unconfirmed", "远端成员与本地记录未一致确认，需要人工核对", eligible=True)
    if not members and len(invites) == 1:
        return result("workspace_invite_pending", "RT 已保存，但远端仍为待接受邀请，需要核对加入状态", eligible=True)
    return result("workspace_member_missing" if not members and not invites else "workspace_identity_ambiguous",
                  "未确认目标子号唯一的远端成员身份，需要人工核对", eligible=True)


def _wait_business_child_operation_release(
    child_id: int,
    *,
    timeout_seconds: float = 10.0,
) -> None:
    """Bridge the security terminal-publication / lease-release handoff."""
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while True:
        now = _utcnow()
        with Session(engine) as session:
            lease = session.get(GptPlanAccountOperationLeaseModel, int(child_id))
            active = bool(
                lease and (_aware_utc(lease.expires_at) or now) > now
            )
        if not active:
            return
        if time.monotonic() >= deadline:
            raise HTTPException(409, "子号前序操作仍在收尾，请稍后重试")
        time.sleep(0.05)


def _run_business_child_batch_action_task_owned(task_id: str) -> None:
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
        if task is None:
            return
        task["status"] = "running"
        task["attempts"] = int(task.get("attempts") or 0) + 1
        task["next_retry_at"] = ""
        task["error"] = ""
        action = str(task.get("action") or "")
        force = bool(task.get("force"))
        browser_mode = str(task.get("browser_mode") or "headless")
        total = len(task.get("items") or [])
    _business_child_batch_action_log(
        task_id,
        f"批量子号操作开始，共 {total} 个；严格逐个执行",
    )

    for index in range(total):
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
            if task is None:
                return
            item = task["items"][index]
            if str(item.get("status") or "") in {"success", "skipped", "failed"}:
                continue
            item["status"] = "running"
            item["status_label"] = "执行中"
            item["step"] = "正在核验成员归属"
            item["steps"][action].update({
                "status": "running",
                "label": "正在核验成员归属",
                "started_at": _iso_utc(_utcnow()),
            })
            item["started_at"] = _iso_utc(_utcnow())
            target = dict(item["target"])
            _recompute_business_child_batch_action_progress_locked(task)

        emit = lambda message, item_index=index: _business_child_batch_action_log(
            task_id,
            message,
            item_index=item_index,
        )
        emit(f"{target['email']}：开始服务端归属核验")
        try:
            already_complete = _business_child_action_complete(
                target,
                action,  # type: ignore[arg-type]
            )
            if already_complete and not force:
                skipped_label = (
                    "已退出，无需重复执行" if action == "leave_workspace"
                    else "已完成，无需重复执行"
                )
                with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                    item = _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index]
                    item.update({
                        "status": "skipped",
                        "status_label": "已跳过",
                        "step": skipped_label,
                        "finished_at": _iso_utc(_utcnow()),
                    })
                    item["steps"][action].update({
                        "status": "skipped",
                        "label": skipped_label,
                        "finished_at": item["finished_at"],
                    })
                    _recompute_business_child_batch_action_progress_locked(
                        _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]
                    )
                emit(f"{target['email']}：{skipped_label}，已跳过")
                continue

            inner_task_id = ""
            running_label = (
                "正在退出空间" if action == "leave_workspace"
                else "正在设置密码与 Authenticator 2FA" if action == "setup_security"
                else "正在获取 RT"
            )
            with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index][
                    "step"
                ] = running_label
                _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index][
                    "steps"
                ][action]["label"] = running_label
            if action == "leave_workspace":
                _run_business_child_batch_leave(target)
            elif action == "setup_security":
                launched = _start_member_business_child_security_setup_internal(
                    int(target["parent_account_id"]),
                    int(target["child_id"]),
                    browser_mode=browser_mode,
                    proxy=_resolve_proxy(None),
                )
                inner_task_id = str(launched.get("task_id") or "")
                with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                    _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index][
                        "inner_task_id"
                    ] = inner_task_id
                snapshot = _wait_business_child_security_task(
                    inner_task_id,
                    emit=emit,
                )
                if str(snapshot.get("status") or "") != "done":
                    raise RuntimeError(snapshot.get("error") or "安全设置失败")
            else:
                snapshot = _run_business_child_oauth_with_lease(
                    target,
                    emit=emit,
                )
                inner_task_id = str(snapshot.get("task_id") or "")
                with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                    _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index][
                        "inner_task_id"
                    ] = inner_task_id
                if str(snapshot.get("status") or "") != "done":
                    raise RuntimeError(snapshot.get("error") or "RT 获取失败")

            if not _business_child_action_complete(
                target,
                action,  # type: ignore[arg-type]
            ):
                raise RuntimeError(
                    "任务已结束，但服务端尚未确认最终状态"
                )
            with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                item = _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]["items"][index]
                item.update({
                    "status": "success",
                    "status_label": "操作成功",
                    "step": "操作完成",
                    "finished_at": _iso_utc(_utcnow()),
                })
                item["steps"][action].update({
                    "status": "success",
                    "label": "操作完成",
                    "task_id": inner_task_id,
                    "finished_at": item["finished_at"],
                })
                _recompute_business_child_batch_action_progress_locked(
                    _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]
                )
            emit(f"{target['email']}：操作完成")
        except Exception as exc:
            error = _business_child_batch_action_error(exc)
            terminal_leave_markers = (
                "另一项未确认的退出操作",
                "身份已变化",
                "绑定已变化",
                "母号不存在",
                "母号已退款",
                "母号已停用",
                "不能退出 BUSINESS 工作区母号",
                "缺少远端成员",
            )
            retry_leave = action == "leave_workspace" and not any(
                marker in error for marker in terminal_leave_markers
            )
            with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
                current = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(task_id)
                if current is None:
                    return
                current["items"][index].update({
                    "status": "pending" if retry_leave else "failed",
                    "status_label": "等待自动重试" if retry_leave else "操作失败",
                    "step": "等待自动核对后重试" if retry_leave else "操作失败",
                    "error": error,
                    "attempts": int(current["items"][index].get("attempts") or 0) + 1,
                    "finished_at": "" if retry_leave else _iso_utc(_utcnow()),
                })
                failed_item = current["items"][index]
                failed_item["steps"][action].update({
                    "status": "pending" if retry_leave else "failed",
                    "label": "等待自动核对后重试" if retry_leave else "操作失败",
                    "error": error,
                    "task_id": str(failed_item.get("inner_task_id") or ""),
                    "finished_at": "" if retry_leave else failed_item["finished_at"],
                })
                _recompute_business_child_batch_action_progress_locked(current)
            emit(
                f"{target['email']}：{error}；"
                + ("将自动核对并重试，同时继续处理下一个子号" if retry_leave else "继续下一个子号")
            )

    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(task_id)
        if task is None:
            return
        _recompute_business_child_batch_action_progress_locked(task)
        progress = dict(task["progress"])
        pending_retry = action == "leave_workspace" and any(
            str(item.get("status") or "") == "pending"
            for item in task.get("items") or []
        )
        attempts = int(task.get("attempts") or 1)
    if pending_retry:
        retry_delay = min(300, 15 * (2 ** min(max(0, attempts - 1), 5)))
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(task_id)
            if task is None:
                return
            task["status"] = "pending"
            task["outcome"] = ""
            task["has_failures"] = False
            task["next_retry_at"] = _iso_utc(
                _utcnow() + timedelta(seconds=retry_delay)
            )
            _recompute_business_child_batch_action_progress_locked(task)
        _business_child_batch_action_log(
            task_id,
            f"仍有退出结果待确认，{retry_delay} 秒后自动读取成员状态并继续",
        )
        timer = threading.Timer(
            retry_delay,
            _run_business_child_batch_action_task,
            args=(task_id,),
        )
        timer.daemon = True
        timer.start()
        return
    _business_child_batch_action_log(
        task_id,
        "批量子号操作完成："
        f"成功 {progress['successful']}，失败 {progress['failed']}，"
        f"跳过 {progress['skipped']}",
    )
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(task_id)
        if task is None:
            return
        task["status"] = "done"
        task["outcome"] = (
            "success"
            if int(progress["failed"]) == 0
            else "partial"
            if int(progress["successful"]) + int(progress["skipped"]) > 0
            else "failed"
        )
        task["has_failures"] = int(progress["failed"]) > 0
        task["finished_at"] = _iso_utc(_utcnow())
        _recompute_business_child_batch_action_progress_locked(task)
        _prune_business_child_batch_action_tasks_locked()


def _run_business_child_batch_action_task(task_id: str) -> None:
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        current = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
        if current is None or str(current.get("status") or "") in {"done", "failed"}:
            return
    acquired = _BUSINESS_CHILD_BATCH_ACTION_RUN_LOCK.acquire(blocking=False)
    if not acquired:
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
            if task is not None:
                task["status"] = "pending"
                task["next_retry_at"] = _iso_utc(_utcnow() + timedelta(seconds=3))
                _recompute_business_child_batch_action_progress_locked(task)
        _business_child_batch_action_log(task_id, "另一批子号任务正在执行，3 秒后自动继续")
        timer = threading.Timer(3, _run_business_child_batch_action_task, args=(task_id,))
        timer.daemon = True
        timer.start()
        return
    try:
        _run_business_child_batch_action_task_owned(task_id)
    except Exception as exc:
        error = _business_child_batch_action_error(exc)
        _business_child_batch_action_log(
            task_id,
            f"批量子号操作异常终止：{error}",
        )
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
            if task is not None:
                for item in task.get("items") or []:
                    if item.get("status") in {"pending", "running"}:
                        item.update({
                            "status": "failed",
                            "status_label": "操作失败",
                            "step": "任务异常终止",
                            "error": error,
                            "finished_at": _iso_utc(_utcnow()),
                        })
                        for step in (item.get("steps") or {}).values():
                            if (
                                isinstance(step, dict)
                                and str(step.get("status") or "")
                                in {"pending", "running"}
                            ):
                                step.update({
                                    "status": "failed",
                                    "label": "任务异常终止",
                                    "error": error,
                                    "finished_at": item["finished_at"],
                                })
                task.update({
                    "status": "failed",
                    "outcome": "failed",
                    "has_failures": True,
                    "error": error,
                    "finished_at": _iso_utc(_utcnow()),
                })
                _recompute_business_child_batch_action_progress_locked(task)
    finally:
        _BUSINESS_CHILD_BATCH_ACTION_RUN_LOCK.release()


def _public_business_child_batch_action_task(
    task_id: str,
    *,
    since: int = 0,
) -> dict[str, Any]:
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        task = _BUSINESS_CHILD_BATCH_ACTION_TASKS.get(str(task_id))
        if task is None:
            from services.business_child_batch_action_store import load
            restored = load(str(task_id))
            if restored is not None:
                _BUSINESS_CHILD_BATCH_ACTION_TASKS[str(task_id)] = restored
                task = restored
        if task is None:
            raise HTTPException(404, "批量子号任务不存在或已过期")
        _recompute_business_child_batch_action_progress_locked(task)
        logs = list(task.get("logs") or [])
        cursor = max(0, int(task.get("log_cursor") or len(logs)))
        start = max(0, int(task.get("log_start") or max(0, cursor - len(logs))))
        requested = min(cursor, max(0, int(since or 0)))
        offset = max(0, requested - start)
        public_items: list[dict[str, Any]] = []
        for raw_item in task.get("items") or []:
            item = json.loads(json.dumps(raw_item, ensure_ascii=False))
            item.pop("target", None)
            item["logs"] = [
                _sanitize_member_task_text(line)
                for line in list(item.get("logs") or [])
            ]
            public_items.append(item)
        return {
            "ok": True,
            "task_id": str(task.get("task_id") or ""),
            "action": str(task.get("action") or ""),
            "browser_mode": str(task.get("browser_mode") or "headless"),
            "force": bool(task.get("force")),
            "attempts": max(0, int(task.get("attempts") or 0)),
            "next_retry_at": str(task.get("next_retry_at") or ""),
            "status": str(task.get("status") or "running"),
            "outcome": str(task.get("outcome") or ""),
            "has_failures": bool(task.get("has_failures")),
            "progress": dict(task.get("progress") or {}),
            "items": public_items,
            "logs": [
                _sanitize_member_task_text(line) for line in logs[offset:]
            ],
            "since": cursor,
            "error": _sanitize_member_task_text(task.get("error") or ""),
            "started_at": str(task.get("started_at") or ""),
            "finished_at": str(task.get("finished_at") or ""),
        }


@router.post("/business-child-batch-action-tasks")
def start_business_child_batch_action_task(
    body: GptPlanBusinessChildBatchActionRequest,
    request: Request,
):
    if not isinstance(body.force, bool):
        raise HTTPException(400, "force 必须是布尔值")
    if body.action == "leave_workspace":
        if body.confirm_remove is not True:
            raise HTTPException(400, "批量退出空间必须明确传 confirm_remove=true")
        if body.force:
            raise HTTPException(400, "批量退出空间禁止 force=true，不会自动重试退出")
    # Authenticate before resolving membership ids so this sensitive route
    # cannot be used as an ownership oracle.
    if body.action == "setup_security":
        _require_plan_security_setup_access(request)
    membership_ids = _strict_business_child_batch_membership_ids(
        body.membership_ids
    )
    targets = [
        _resolve_business_child_batch_action_target(
            membership_id,
            body.action,
        )
        for membership_id in membership_ids
    ]
    task_id = f"gpt_plan_business_child_batch_{uuid.uuid4().hex}"
    items = [
        {
            "membership_id": int(target["membership_id"]),
            "parent_account_id": int(target["parent_account_id"]),
            "child_id": int(target["child_id"]),
            "email": str(target["email"]),
            "status": "pending",
            "status_label": "等待处理",
            "step": "等待处理",
            "steps": {
                body.action: {
                    "status": "pending",
                    "label": (
                        "等待退出空间" if body.action == "leave_workspace"
                        else "等待设置密码与 2FA"
                        if body.action == "setup_security" else "等待获取 RT"
                    ),
                    "error": "",
                    "task_id": "",
                    "started_at": "",
                    "finished_at": "",
                },
            },
            "error": "",
            "inner_task_id": "",
            "logs": [],
            "started_at": "",
            "finished_at": "",
            "target": dict(target),
        }
        for target in targets
    ]
    with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
        _prune_business_child_batch_action_tasks_locked()
        for active in _BUSINESS_CHILD_BATCH_ACTION_TASKS.values():
            if (
                str(active.get("status") or "") not in {"pending", "running"}
                or str(active.get("finished_at") or "")
            ):
                continue
            raise HTTPException(409, {
                "code": "business_child_batch_action_already_running",
                "message": "已有批量子号操作正在执行，请等待完成后再启动",
                "existing_task_id": str(active.get("task_id") or ""),
                "existing_action": str(active.get("action") or ""),
            })
        run_gate_available = _BUSINESS_CHILD_BATCH_ACTION_RUN_LOCK.acquire(
            blocking=False
        )
        if not run_gate_available:
            raise HTTPException(409, {
                "code": "business_child_batch_action_finishing",
                "message": "上一批量子号操作正在收尾，请稍后再试",
            })
        _BUSINESS_CHILD_BATCH_ACTION_RUN_LOCK.release()
        _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id] = {
            "task_id": task_id,
            "action": body.action,
            "browser_mode": body.browser_mode,
            "force": bool(body.force),
            "status": "running",
            "outcome": "",
            "has_failures": False,
            "items": items,
            "logs": [],
            "log_start": 0,
            "log_cursor": 0,
            "error": "",
            "started_at": _iso_utc(_utcnow()),
            "finished_at": "",
        }
        _recompute_business_child_batch_action_progress_locked(
            _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]
        )
    worker = threading.Thread(
        target=_run_business_child_batch_action_task,
        args=(task_id,),
        daemon=True,
        name=f"gpt-plan-child-batch-{task_id[-8:]}",
    )
    try:
        worker.start()
    except Exception as exc:
        error = _business_child_batch_action_error(exc)
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            task = _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id]
            for item in task["items"]:
                item.update({
                    "status": "failed",
                    "status_label": "启动失败",
                    "step": "后台任务启动失败",
                    "error": error,
                    "finished_at": _iso_utc(_utcnow()),
                })
                item["steps"][body.action].update({
                    "status": "failed",
                    "label": "后台任务启动失败",
                    "error": error,
                    "finished_at": item["finished_at"],
                })
            task.update({
                "status": "failed",
                "outcome": "failed",
                "has_failures": True,
                "error": error,
                "finished_at": _iso_utc(_utcnow()),
            })
            _recompute_business_child_batch_action_progress_locked(task)
        raise HTTPException(500, "批量子号后台任务启动失败") from exc
    return _public_business_child_batch_action_task(task_id, since=0)


@router.post("/accounts/{account_id}/business-child-batch-leave-tasks")
def start_business_mother_batch_leave_task(
    account_id: int,
    body: GptPlanBusinessMotherBatchLeaveRequest,
    request: Request,
):
    """Derive and exit every currently joined non-owner member of one mother."""
    if body.confirm_remove is not True:
        raise HTTPException(400, "退出母号全部子号必须明确确认")
    binding, _member_source = _business_child_facade_binding(
        int(account_id), require_action=True, preflight_session=True,
    )
    with Session(engine) as session:
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel)
            .where(
                GptBusinessChildMembershipModel.business_account_id
                == int(binding.source_account_id)
            )
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .order_by(col(GptBusinessChildMembershipModel.id))
        ).all())
    membership_ids = [
        int(row.id or 0)
        for row in memberships
        if int(row.id or 0) > 0
        and bool(_safe_business_remote_identifier(row.remote_user_id))
        and _safe_business_child_email(row.email) != binding.normalized_email
    ]
    if not membership_ids:
        raise HTTPException(409, "该母号当前没有可退出的已加入子号")
    return start_business_child_batch_action_task(
        GptPlanBusinessChildBatchActionRequest(
            action="leave_workspace",
            membership_ids=membership_ids,
            force=False,
            confirm_remove=True,
        ),
        request,
    )


def resume_business_child_batch_action_tasks() -> int:
    """Restore unfinished child batches and continue from canonical evidence."""
    from services.business_child_batch_action_store import unfinished

    resumed = 0
    for restored in unfinished():
        task_id = str(restored.get("task_id") or "").strip()
        if not task_id or not isinstance(restored.get("items"), list):
            continue
        restored["status"] = "pending"
        restored["finished_at"] = ""
        restored["next_retry_at"] = ""
        for item in restored["items"]:
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "") == "running":
                item["status"] = "pending"
                item["status_label"] = "等待恢复执行"
                item["step"] = "服务重启后自动恢复"
                item["finished_at"] = ""
                action = str(restored.get("action") or "")
                step = (item.get("steps") or {}).get(action)
                if isinstance(step, dict):
                    step.update({
                        "status": "pending",
                        "label": "服务重启后自动恢复",
                        "finished_at": "",
                    })
        with _BUSINESS_CHILD_BATCH_ACTION_LOCK:
            if task_id in _BUSINESS_CHILD_BATCH_ACTION_TASKS:
                continue
            _BUSINESS_CHILD_BATCH_ACTION_TASKS[task_id] = restored
            _recompute_business_child_batch_action_progress_locked(restored)
        threading.Thread(
            target=_run_business_child_batch_action_task,
            args=(task_id,),
            daemon=True,
            name=f"gpt-plan-child-batch-resume-{task_id[-8:]}",
        ).start()
        resumed += 1
    return resumed


@router.get("/business-child-batch-action-tasks/{task_id}")
def get_business_child_batch_action_task(
    task_id: str,
    since: int = Query(0, ge=0),
):
    return _public_business_child_batch_action_task(
        str(task_id),
        since=max(0, int(since or 0)),
    )


def _existing_managed_business_child_download_target(
    binding: _MemberSourceBinding,
    child_id: int,
) -> int:
    """Admit only an active, healthy pool child which already owns a RT.

    The caller supplies the plan-directory id and child id only.  The real
    BUSINESS parent is always derived from ``binding`` and never crosses the
    facade response.  The source downloader repeats the parent-scoped
    ownership check while holding the child operation claim, closing the
    remove/rebind race after this inexpensive admission check.
    """
    membership_id = _existing_managed_business_child_oauth_target(
        binding,
        int(child_id),
    )
    with Session(engine) as session:
        child = session.get(GptPlanAccountModel, int(child_id))
        if (
            child is None
            or int(getattr(child, "business_parent_id", None) or 0)
            != int(binding.source_account_id)
        ):
            raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")
        if not str(child.codex_refresh_token or "").strip():
            raise HTTPException(409, "子号尚未取得 RT，请先完成获取 RT")
    return int(membership_id)


def _confirm_managed_business_child_remote_member_for_download(
    binding: _MemberSourceBinding,
    child_id: int,
    membership_id: int,
) -> None:
    """Reconcile an invite-shaped local row before exporting its credential.

    OAuth may complete immediately after an invitation while the normalized
    membership row still contains only ``remote_invite_id``.  The low-level
    exporter intentionally requires a confirmed remote member, so reconcile
    that narrow stale state against OpenAI instead of weakening its fence.
    """
    with Session(engine) as session:
        membership = session.get(
            GptBusinessChildMembershipModel,
            int(membership_id),
        )
        if (
            membership is None
            or membership.ended_at is not None
            or int(membership.business_account_id)
            != int(binding.source_account_id)
            or int(membership.pro_account_id or 0) != int(child_id)
            or str(membership.source or "").strip().lower() != "pool"
        ):
            raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")
        if _safe_business_remote_identifier(membership.remote_user_id):
            return
        email = _safe_business_child_email(membership.email)
        if not email:
            raise HTTPException(409, "子号缺少可确认的 BUSINESS 成员身份")

    try:
        from api import gpt_business

        remote_status, _remote = gpt_business._remote_child_membership_status(
            int(binding.source_account_id),
            email,
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    if str(remote_status or "").strip().lower() != "member":
        raise HTTPException(409, "子号尚未确认加入 BUSINESS 工作区，暂不能下载凭证")

    # The source reconciler persists the exact remote user id.  Require that
    # durable write before crossing the credential-export boundary.
    with Session(engine) as session:
        membership = session.get(
            GptBusinessChildMembershipModel,
            int(membership_id),
        )
        if (
            membership is None
            or membership.ended_at is not None
            or int(membership.business_account_id)
            != int(binding.source_account_id)
            or int(membership.pro_account_id or 0) != int(child_id)
            or not _safe_business_remote_identifier(membership.remote_user_id)
        ):
            raise HTTPException(409, "远端成员已确认，但本地归属尚未完成对账，请重试")


@router.get(
    "/accounts/{account_id}/business-child-oauth-file/{child_id}"
)
def download_member_business_child_oauth_file(
    account_id: int,
    child_id: int,
    fmt: str = Query("cpa"),
):
    """Download a bound BUSINESS child's CPA/Sub2API credential file.

    ``account_id`` is the public plan-directory account id.  The source parent
    id is resolved server-side; accepting it from the browser would permit a
    confused-deputy cross-workspace download.
    """
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可下载 RT 的受管子号")
    fmt_normalized = _normalized_oauth_file_format(fmt)
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=False,
    )
    membership_id = _existing_managed_business_child_download_target(
        binding,
        int(child_id),
    )
    _assert_member_source_binding_current(binding)
    _confirm_managed_business_child_remote_member_for_download(
        binding,
        int(child_id),
        membership_id,
    )
    _assert_member_source_binding_current(binding)

    try:
        from api import gpt_business

        response = gpt_business.download_managed_business_child_oauth_file(
            int(binding.source_account_id),
            int(child_id),
            fmt_normalized,
        )
    except Exception as exc:
        # Credential exporters intentionally return token material on success;
        # their exception payloads must therefore never be relayed through the
        # plan facade.  Preserve only a bounded HTTP class and use our own text
        # so a future source error cannot disclose its real parent id or token.
        status_code = 502
        if isinstance(exc, HTTPException):
            try:
                candidate_status = int(exc.status_code)
            except (TypeError, ValueError):
                candidate_status = 502
            if 400 <= candidate_status <= 599:
                status_code = candidate_status
        message = (
            "子号 RT 或 BUSINESS 归属已变化，请刷新成员列表后重试"
            if status_code in {400, 404, 409}
            else "RT 凭证文件生成失败，请稍后重试"
        )
        raise HTTPException(status_code, message) from exc

    # A plan/source rebind during file generation must fail closed.  The
    # generated response remains server-local and is not returned in that case.
    _assert_member_source_binding_current(binding)
    if response is None or not hasattr(response, "headers"):
        raise HTTPException(502, "RT 凭证文件生成失败，请稍后重试")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@router.post(
    "/accounts/{account_id}/business-child-sync-device/{child_id}"
)
def sync_member_business_child_device(
    account_id: int,
    child_id: int,
    body: GptPlanMemberDeviceSyncRequest,
):
    """Synchronize one exact BUSINESS child to an enabled CPA/Sub2API device.

    This is deliberately a child-only facade.  It does not re-enable syncing a
    BUSINESS mother's own credential and it does not start device automation or
    replacement work.  The public plan id is resolved to its immutable source
    mother, while the child must still be an active pool membership owned by
    that mother and already hold a refresh token.
    """
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个可同步 RT 的受管子号")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
    )
    membership_id = _existing_managed_business_child_download_target(
        binding,
        int(child_id),
    )
    provider, provider_id, canonical = _parse_plan_device_ref(body.device_ref)
    _assert_member_source_binding_current(binding)

    try:
        from api import gpt_business

        if provider == "cpa":
            source_result = gpt_business.sync_managed_business_child_cpa(
                int(binding.source_account_id),
                int(child_id),
                gpt_business.BizChildCpaSyncRequest(target_id=provider_id),
            )
        else:
            source_result = gpt_business.sync_managed_business_child_sub2api(
                int(binding.source_account_id),
                int(child_id),
                gpt_business.BizChildSub2ApiSyncRequest(device_id=provider_id),
            )
    except Exception as exc:
        _raise_safe_business_source_error(exc)

    value = source_result if isinstance(source_result, dict) else None
    if value is None or value.get("ok") is not True:
        # A transport call returning without an affirmative source result is
        # not proof that the credential exists on the target device.  Never
        # turn an ambiguous/negative lower-level result into facade success.
        raise HTTPException(502, "子号同步结果未确认，请稍后重试")

    # Both source sync paths fence the child operation.  Repeat the directory
    # binding check before exposing their result so a concurrent plan/source
    # rebind cannot turn this endpoint into a cross-workspace deputy.
    _assert_member_source_binding_current(binding)
    with Session(engine) as session:
        child = session.get(GptPlanAccountModel, int(child_id))
        if (
            child is None
            or int(getattr(child, "business_parent_id", None) or 0)
            != int(binding.source_account_id)
        ):
            raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")
        public_status = _safe_business_child_device_snapshot(child)
        status = public_status[provider]

    return {
        "ok": True,
        "account_id": int(account_id),
        "membership_id": int(membership_id),
        "child_id": int(child_id),
        "device_ref": canonical,
        "provider": provider,
        "status": status,
        "sync": {
            "idempotent": bool(value.get("idempotent")),
            "message": _sanitize_member_task_text(
                value.get("message") or ""
            )[:300],
        },
    }


def _business_child_release_target(
    binding: _MemberSourceBinding,
    *,
    membership_id: int,
    operation_id: str,
) -> dict[str, Any]:
    """Derive an immutable remove/revoke target from one bound membership."""
    with Session(engine) as session:
        membership = session.get(
            GptBusinessChildMembershipModel,
            int(membership_id),
        )
        if (
            membership is None
            or int(membership.business_account_id)
            != int(binding.source_account_id)
        ):
            raise HTTPException(404, "该母号下不存在这个可移除子号")
        if (
            membership.ended_at is not None
            and str(membership.operation_id or "") != operation_id
        ):
            raise HTTPException(409, "该子号已经离开母号，请刷新成员列表")

        user_id = _safe_business_remote_identifier(membership.remote_user_id)
        invite_id = _safe_business_remote_identifier(membership.remote_invite_id)
        email = _safe_business_child_email(membership.email)
        pro_account_id = (
            int(membership.pro_account_id)
            if membership.pro_account_id is not None
            and int(membership.pro_account_id) > 0
            else None
        )
        # Accepted invitations retain their original invite id in durable
        # history, so a confirmed user id takes precedence over that stale
        # invite identity.  This matches the delegated BUSINESS workspace.
        kind = "member" if user_id else "invite" if invite_id else ""
        if not kind:
            raise HTTPException(409, "该子号缺少可确认的远端成员或邀请身份")
        if kind == "invite" and not email:
            raise HTTPException(409, "待撤销邀请缺少可确认的邮箱")

        if pro_account_id is not None and membership.ended_at is None:
            child = session.get(GptPlanAccountModel, int(pro_account_id))
            if (
                child is None
                or int(getattr(child, "business_parent_id", None) or 0)
                != int(binding.source_account_id)
                or _normalized_email(child.email) != email
            ):
                raise HTTPException(409, "子号的 BUSINESS 归属已变化，请刷新成员列表")
    return {
        "kind": kind,
        "membership_id": int(membership_id),
        "user_id": user_id,
        "invite_id": invite_id,
        "email": email,
        "pro_account_id": pro_account_id,
    }


def _business_child_release_is_persisted(
    binding: _MemberSourceBinding,
    *,
    membership_id: int,
    operation_id: str,
) -> bool:
    with Session(engine) as session:
        membership = session.get(
            GptBusinessChildMembershipModel,
            int(membership_id),
        )
        if (
            membership is None
            or int(membership.business_account_id)
            != int(binding.source_account_id)
            or membership.ended_at is None
            or str(membership.operation_id or "") != operation_id
        ):
            return False
        if membership.pro_account_id is None:
            return True
        child = session.get(GptPlanAccountModel, int(membership.pro_account_id))
        return bool(
            child is None
            or int(getattr(child, "business_parent_id", None) or 0)
            != int(binding.source_account_id)
        )


@router.post("/accounts/{account_id}/business-remove")
def member_business_remove(
    account_id: int,
    body: GptPlanBusinessChildRemoveRequest,
):
    """Remove a member or revoke an invite without selecting a replacement."""
    if body.confirm_remove is not True:
        raise HTTPException(400, "移除子号必须明确传 confirm_remove=true")
    try:
        binding, _member_source = _business_child_facade_binding(
            account_id,
            require_action=True,
            preflight_session=True,
        )
    except HTTPException as exc:
        from services.nv_exit_recovery import BusinessExitPreflightError, CODES
        if isinstance(exc.detail, dict) and exc.detail.get("code") in CODES:
            raise BusinessExitPreflightError(exc.detail) from None
        raise
    operation_id = _strict_business_facade_operation_id(body.operation_id)
    membership_id = _strict_optional_business_child_id(
        body.membership_id,
        "membership_id",
    )
    if membership_id is None:
        raise HTTPException(400, "membership_id 必须是正整数")
    target = _business_child_release_target(
        binding,
        membership_id=int(membership_id),
        operation_id=operation_id,
    )
    expected = body._batch_expected_target
    if expected is not None:
        _assert_business_child_batch_leave_binding(expected, binding)
        # Durable dead-child cleanup also freezes pending invitations. Keep
        # the existing member-only batch semantics when kind is omitted, and
        # never let a queued invitation become a different member deletion.
        expected_kind = expected.get("kind", "member")
        expected_ended = False
        if expected_kind == "invite":
            with Session(engine) as session:
                frozen_membership = session.get(
                    GptBusinessChildMembershipModel, int(expected["membership_id"]),
                )
                expected_ended = bool(
                    frozen_membership is None
                    or frozen_membership.ended_at is not None
                    or bool(frozen_membership.intent_remote_started)
                    or str(frozen_membership.end_reason or "").startswith("pending:")
                    or str(frozen_membership.source or "") != expected.get("source")
                    or (expected.get("invited_at") and _iso_utc(frozen_membership.invited_at)
                        != expected["invited_at"])
                )
        if (
            expected_kind not in {"member", "invite"}
            or target["kind"] != expected_kind
            or (expected_kind == "invite" and (bool(expected["user_id"]) or not expected["invite_id"]))
            or int(target["membership_id"]) != int(expected["membership_id"])
            or target["user_id"] != expected["user_id"]
            or target["invite_id"] != expected["invite_id"]
            or target["email"] != expected["email"]
            or int(target["pro_account_id"] or 0) != int(expected["child_id"])
            or operation_id != expected["operation_id"]
            or expected_ended
            or (expected_kind == "member" and _business_child_batch_leave_complete(expected))
        ):
            raise HTTPException(409, "批量退出目标的远端成员身份已变化，未执行退出")

    from api import gpt_business

    try:
        if target["kind"] == "member":
            raw = gpt_business.remove_member_biz(
                int(binding.source_account_id),
                gpt_business.BizRemoveMemberRequest(
                    user_id=str(target["user_id"]),
                    email=str(target["email"]),
                    pro_account_id=target["pro_account_id"],
                    operation_id=operation_id,
                ),
            )
        else:
            raw = gpt_business.revoke_invite_biz(
                int(binding.source_account_id),
                gpt_business.BizRevokeInviteRequest(
                    email=str(target["email"]),
                    pro_account_id=target["pro_account_id"],
                    operation_id=operation_id,
                ),
            )
    except Exception as exc:
        _raise_safe_business_source_error(exc)

    safe = _safe_business_child_mutation_result(
        raw,
        operation_id=operation_id,
    )
    persisted = _business_child_release_is_persisted(
        binding,
        membership_id=int(membership_id),
        operation_id=operation_id,
    )
    safe["persistence_confirmed"] = bool(persisted)
    if bool(safe.get("ok")) and not persisted:
        safe["ok"] = False
        safe["partial"] = True
        safe["action_required"] = True
        safe["warning"] = "远端释放已返回成功，但本地子号历史尚未确认；请使用同一 operation_id 对账"
    children, binding_changed = _business_mutation_snapshot_after_source_call(binding)
    safe.update({
        "account_id": int(account_id),
        "binding_changed": binding_changed,
        "membership_id": int(membership_id),
        "release_kind": str(target["kind"]),
        "removed": bool(safe.get("ok") and persisted),
        "revoked": bool(
            target["kind"] == "invite" and safe.get("ok") and persisted
        ),
        "released_to_pro": bool(
            isinstance(raw, dict) and raw.get("released_to_pro")
        ),
        "business_children": children,
        "invite_quota": (
            children.get("invite_quota") if isinstance(children, dict) else None
        ),
        "rotation_quota": (
            children.get("rotation_quota") if isinstance(children, dict) else None
        ),
        "vacancy_policy": (
            children.get("vacancy_policy") if isinstance(children, dict) else None
        ),
    })
    return safe


@router.post("/accounts/{account_id}/business-replace")
def member_business_replace(
    account_id: int,
    body: GptPlanBusinessChildReplaceRequest,
):
    """Replace an exact persisted occupant after an explicit UI confirmation."""
    if body.confirm_replace is not True:
        raise HTTPException(400, "满席替换必须明确传 confirm_replace=true")
    binding, _member_source = _business_child_facade_binding(
        account_id,
        require_action=True,
        preflight_session=True,
    )
    operation_id = _strict_business_facade_operation_id(body.operation_id)
    membership_id = _strict_optional_business_child_id(
        body.membership_id,
        "membership_id",
    )
    if membership_id is None:
        raise HTTPException(400, "membership_id 必须是正整数")
    new_pro_account_id = _strict_optional_business_child_id(
        body.new_pro_account_id,
        "new_pro_account_id",
    )
    candidate_mail_provider = _strict_business_candidate_mail_provider(
        body.candidate_mail_provider
    )

    with Session(engine) as session:
        membership = session.get(GptBusinessChildMembershipModel, membership_id)
        if (
            membership is None
            or int(membership.business_account_id) != int(binding.source_account_id)
        ):
            # Do not disclose whether the membership belongs to another mother.
            raise HTTPException(404, "该母号下不存在这个可替换子号")
        if membership.ended_at is not None and str(membership.operation_id or "") != operation_id:
            raise HTTPException(409, "该子号已经离开母号，请刷新成员列表")
        old_user_id = _safe_business_remote_identifier(membership.remote_user_id)
        old_invite_id = _safe_business_remote_identifier(membership.remote_invite_id)
        old_kind = "member" if old_user_id else "invite" if old_invite_id else ""
        if not old_kind:
            raise HTTPException(409, "该子号缺少可确认的远端成员或邀请身份")
        old_email = _safe_business_child_email(membership.email)
        old_pro_account_id = (
            int(membership.pro_account_id)
            if membership.pro_account_id is not None
            and int(membership.pro_account_id) > 0
            else None
        )

    from api import gpt_business

    try:
        raw = gpt_business.replace_business_child(
            int(binding.source_account_id),
            gpt_business.BizReplaceChildRequest(
                old_kind=old_kind,
                old_user_id=old_user_id,
                old_email=old_email,
                old_pro_account_id=old_pro_account_id,
                new_pro_account_id=new_pro_account_id,
                pool_mode=True,
                candidate_mail_provider=candidate_mail_provider,
                operation_id=operation_id,
                # The source reads the exact old occupant and binds its seat type;
                # accepting this field from the browser would permit type spoofing.
                seat_type="",
            ),
        )
    except Exception as exc:
        _raise_safe_business_source_error(exc)
    safe = _safe_business_child_mutation_result(
        raw,
        operation_id=operation_id,
    )
    children, binding_changed = _business_mutation_snapshot_after_source_call(binding)
    _confirm_business_child_persistence(safe, children)
    safe.update({
        "account_id": int(account_id),
        "binding_changed": binding_changed,
        "business_children": children,
        "invite_quota": (
            children.get("invite_quota") if isinstance(children, dict) else None
        ),
    })
    return safe


@router.get("/accounts/{account_id}/pro-refund-burn/candidates")
def member_pro_refund_burn_candidates(account_id: int):
    """List healthy standalone PRO rows available to this BUSINESS mother."""
    binding, member_source = _resolve_member_source_binding(account_id)
    _require_member_capability(member_source, "pro_refund_burn")
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "仅 GPT BUSINESS 母号支持焚决退款 PRO")
    with Session(engine) as session:
        rows = _eligible_pro_burn_targets(session)
    # Recheck after the query so a directory/source rebind cannot make this
    # response look authoritative for a different BUSINESS mother.
    current = _assert_member_source_binding_current(binding)
    _require_member_capability(current, "pro_refund_burn")
    capability = current["capabilities"]["pro_refund_burn"]
    remaining = max(0, int(capability.get("remaining") or 0))
    items = [_safe_pro_burn_candidate(row) for row in rows]
    return {
        "ok": True,
        "account_id": int(account_id),
        "items": items,
        "total": len(items),
        "max_select": (
            min(len(items), remaining)
            if bool(capability.get("supported")) else 0
        ),
    }


@router.post("/accounts/{account_id}/pro-refund-burn")
def start_member_pro_refund_burn(
    account_id: int,
    body: GptPlanBusinessProBurnRequest,
):
    """Start the source BUSINESS burn flow behind an immutable facade task."""
    binding, member_source = _resolve_member_source_binding(account_id)
    _require_member_capability(member_source, "pro_refund_burn")
    if binding.source_pool != "gpt_business":
        raise HTTPException(409, "仅 GPT BUSINESS 母号支持焚决退款 PRO")
    target_ids = _strict_pro_burn_target_ids(body.account_ids)

    # Reload every submitted target from the authoritative PRO table.  The
    # worker repeats this predicate after taking its per-PRO lease as well.
    with Session(engine) as session:
        eligible_rows = _eligible_pro_burn_targets(session, target_ids)
    eligible_ids = {int(row.id or 0) for row in eligible_rows}
    invalid_ids = [target_id for target_id in target_ids if target_id not in eligible_ids]
    if invalid_ids:
        raise HTTPException(409, "所选 PRO 账号状态已变化，请刷新候选列表后重试")

    current = _assert_member_source_binding_current(binding)
    _require_member_capability(current, "pro_refund_burn")
    capability = current["capabilities"]["pro_refund_burn"]
    try:
        concurrency = int(body.concurrency)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "concurrency 必须是整数") from exc
    concurrency = max(1, min(concurrency, 4))

    from api import gpt_business

    source_response = gpt_business.business_pro_refund_burn(
        int(binding.source_account_id),
        gpt_business.GptBusinessProBurnRequest(
            account_ids=target_ids,
            concurrency=concurrency,
            kick=bool(body.kick),
        ),
    )
    source_response = source_response if isinstance(source_response, dict) else {}
    source_task_id = str(source_response.get("task_id") or "").strip()
    if not source_task_id:
        raise HTTPException(502, "焚决任务未返回有效 task_id")
    task_id = _create_member_action_task(
        binding,
        "pro_refund_burn",
        source_task_id=source_task_id,
    )

    def safe_count(key: str, fallback: int = 0) -> int:
        value = source_response.get(key, fallback)
        if isinstance(value, bool):
            return max(0, int(fallback))
        try:
            return min(1_000_000, max(0, int(value)))
        except (TypeError, ValueError):
            return max(0, int(fallback))

    targets = safe_count("targets", len(target_ids))
    source_invite_quota = _safe_business_quota(source_response.get("invite_quota"))
    remaining = (
        max(0, int(quota_for_seat(source_invite_quota, "default").get("remaining") or 0))
        if isinstance(source_invite_quota, dict)
        else max(0, int(capability.get("remaining") or 0) - targets)
    )
    return {
        "ok": True,
        "task_id": task_id,
        "status": "running",
        "requested": len(target_ids),
        "targets": targets,
        # The source endpoint's historical ``capped_to`` means quota room,
        # which is easy for clients to mistake for an execution count.  At the
        # facade boundary it deliberately means the actual number admitted.
        "capped_to": targets,
        "remaining": remaining,
        "invite_quota": source_invite_quota,
    }


# Keep the literal candidates/start routes above this dynamic task route;
# otherwise Starlette can interpret ``candidates`` as a task id.
@router.get("/accounts/{account_id}/pro-refund-burn/{task_id}")
def member_pro_refund_burn_status(
    account_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    task = _bound_member_action_task(
        account_id,
        task_id,
        "pro_refund_burn",
    )
    return _pro_burn_source_snapshot(task, since=since)


@router.post("/accounts/{account_id}/refund")
def start_member_refund(
    account_id: int,
    body: Optional[GptPlanMemberRefundRequest] = None,
):
    body = body or GptPlanMemberRefundRequest()
    binding, member_source = _resolve_member_source_binding(account_id)
    _require_member_capability(member_source, "refund")
    task_id = _create_member_action_task(binding, "refund")
    thread = threading.Thread(
        target=_run_member_refund_task,
        args=(task_id, binding, body),
        name=f"gpt-plan-refund-{task_id[:8]}",
        daemon=True,
    )
    try:
        thread.start()
    except Exception as exc:
        _finish_member_action_task(task_id, error=f"退款后台任务启动失败: {exc}")
        raise HTTPException(500, "退款后台任务启动失败") from exc
    return {"ok": True, "task_id": task_id, "status": "running"}


@router.get("/accounts/{account_id}/refund/{task_id}")
def member_refund_status(
    account_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    task = _bound_member_action_task(account_id, task_id, "refund")
    return _own_member_task_snapshot(task, since=since)


@router.post("/accounts/{account_id}/oauth")
def start_member_oauth(
    account_id: int,
    body: Optional[GptPlanMemberOauthRequest] = None,
):
    body = body or GptPlanMemberOauthRequest()
    binding, member_source = _resolve_member_source_binding(account_id)
    _require_member_capability(member_source, "oauth")
    _assert_member_source_binding_current(binding)
    if binding.source_pool != "gpt_business":
        from api import gpt_plan_operations as gpt_pro

        source_response = gpt_pro.oauth_account(
            int(binding.source_account_id),
            gpt_pro.GptProActionRequest(
                proxy=body.proxy,
                headless=bool(body.headless),
                keep_browser_open=bool(body.keep_browser_open),
                otp_timeout=max(30, int(body.otp_timeout or 180)),
            ),
        )
    else:
        from api import gpt_business

        source_response = gpt_business.oauth_account(
            int(binding.source_account_id),
            gpt_business.GptBusinessActionRequest(
                proxy=body.proxy,
                headless=bool(body.headless),
                keep_browser_open=bool(body.keep_browser_open),
                otp_timeout=max(30, int(body.otp_timeout or 180)),
            ),
        )
    source_task_id = str(
        (source_response or {}).get("task_id")
        if isinstance(source_response, dict)
        else ""
    ).strip()
    if not source_task_id:
        raise HTTPException(502, "OAuth 任务未返回有效 task_id")
    task_id = _create_member_action_task(
        binding,
        "oauth",
        source_task_id=source_task_id,
    )
    return {"ok": True, "task_id": task_id, "status": "running"}


@router.get("/accounts/{account_id}/oauth/{task_id}")
def member_oauth_status(
    account_id: int,
    task_id: str,
    since: int = Query(0, ge=0),
):
    task = _bound_member_action_task(account_id, task_id, "oauth")
    return _oauth_source_snapshot(task, since=since)


def _normalized_oauth_file_format(value: Any) -> str:
    normalized = str(value or "cpa").strip().lower()
    if normalized in {"sub", "sub-2-api"}:
        normalized = "sub2api"
    if normalized not in {"cpa", "sub2api"}:
        raise HTTPException(400, "fmt 只支持 cpa 或 sub2api")
    return normalized


@router.get("/accounts/{account_id}/oauth-file")
def download_member_oauth_file(account_id: int, fmt: str = Query("cpa")):
    fmt_normalized = _normalized_oauth_file_format(fmt)
    binding, member_source = _resolve_member_source_binding(account_id)
    _require_member_capability(member_source, "oauth_file")
    current_source = _assert_member_source_binding_current(binding)
    _require_member_capability(current_source, "oauth_file")
    if binding.source_pool != "gpt_business":
        from api.gpt_plan_operations import _download_pro_oauth_file

        response = _download_pro_oauth_file(
            int(binding.source_account_id),
            fmt_normalized,
            require_refresh_token=True,
        )
    else:
        from api.gpt_business import download_business_oauth_file

        response = download_business_oauth_file(
            int(binding.source_account_id),
            fmt_normalized,
        )
    # Lower-level exporters already set these headers; enforce them again at
    # this boundary so future refactors cannot make token files cacheable.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _parse_plan_device_ref(value: Any) -> tuple[str, int, str]:
    from services import delivery_device_monitor

    try:
        provider, provider_id = delivery_device_monitor.parse_device_key(value)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    canonical = delivery_device_monitor.device_key(provider, provider_id)
    device = delivery_device_monitor.get_device(canonical, include_accounts=False)
    if not device:
        raise HTTPException(404, "设备不存在")
    if not bool(device.get("enabled", True)):
        raise HTTPException(409, "设备已停用")
    return provider, int(provider_id), canonical


@router.post("/accounts/{account_id}/sync-device")
def sync_member_device(
    account_id: int,
    body: GptPlanMemberDeviceSyncRequest,
):
    binding, member_source = _resolve_member_source_binding(account_id)
    if binding.source_pool == "gpt_business":
        raise HTTPException(
            410,
            "CPA/SUB 设备的 BUSINESS 子号同步功能已停用；设备仅支持刷新账号与额度",
        )
    _require_member_capability(member_source, "sync_device")
    provider, provider_id, canonical = _parse_plan_device_ref(body.device_ref)
    _assert_member_source_binding_current(binding)
    if provider == "cpa":
        from api.gpt_plan_operations import sync_account_to_cpa

        source_result = sync_account_to_cpa(
            int(binding.source_account_id),
            int(provider_id),
        )
    else:
        from api.gpt_plan_operations import sync_account_to_sub2api

        source_result = sync_account_to_sub2api(
            int(binding.source_account_id),
            int(provider_id),
        )
    refreshed = _assert_member_source_binding_current(binding)
    status = refreshed.get("cpa") if provider == "cpa" else refreshed.get("sub2api")
    sync_summary = None
    if isinstance(source_result, dict):
        sync_summary = {
            "idempotent": bool(source_result.get("idempotent")),
            "message": _sanitize_member_task_text(source_result.get("message") or ""),
        }
    return {
        "ok": True,
        "account_id": int(account_id),
        "device_ref": canonical,
        "provider": provider,
        "status": status,
        "sync": sync_summary,
    }


def _safe_member_device_usage(provider: str, result: Any) -> dict[str, Any]:
    value = result if isinstance(result, dict) else {}

    def safe_number(
        raw: Any,
        *,
        minimum: float = 0,
        maximum: float = 1_000_000_000_000_000,
    ) -> Optional[float | int]:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return None
        numeric = float(raw)
        if not minimum <= numeric <= maximum:
            return None
        return raw

    def safe_time(raw: Any) -> Any:
        numeric = safe_number(raw, maximum=100_000_000_000_000)
        if numeric is not None:
            return numeric
        text = str(raw or "").strip()
        if 1 <= len(text) <= 80 and re.fullmatch(r"[0-9TZ:+.\- ]+", text):
            return text
        return None

    if provider == "cpa":
        limit = value.get("limit_reached")
        return {
            "usage_5h_percent": safe_number(
                value.get("usage_5h_percent"), maximum=100,
            ),
            "usage_5h_reset_at": safe_time(value.get("usage_5h_reset_at")),
            "usage_5h_window_seconds": safe_number(
                value.get("usage_5h_window_seconds"), maximum=315_360_000,
            ),
            "usage_week_percent": safe_number(
                value.get("usage_week_percent"), maximum=100,
            ),
            "usage_week_reset_at": safe_time(value.get("usage_week_reset_at")),
            "usage_week_window_seconds": safe_number(
                value.get("usage_week_window_seconds"), maximum=315_360_000,
            ),
            "limit_reached": limit if isinstance(limit, bool) else None,
            "credit_balance": safe_number(value.get("credit_balance")),
            "checked_at": safe_time(value.get("checked_at")),
        }
    from services.sub2api_admin import sanitize_admin_payload

    source = str(value.get("source") or value.get("mode") or "passive").lower()
    if source not in {"active", "passive"}:
        source = "passive"
    limit_reached = value.get("limit_reached")
    return {
        "mode": source,
        "source": source,
        "payload": sanitize_admin_payload(value.get("payload")),
        "limit_reached": limit_reached if isinstance(limit_reached, bool) else None,
        "checked_at": safe_time(value.get("checked_at")) or "",
    }


@router.get("/accounts/{account_id}/device-usage")
def member_device_usage(
    account_id: int,
    device_ref: str = Query(...),
    active: bool = Query(False),
):
    binding, member_source = _resolve_member_source_binding(account_id)
    if binding.source_pool == "gpt_business":
        raise HTTPException(
            410,
            "CPA/SUB 设备的 BUSINESS 子号查询功能已停用；请从设备刷新查看账号与额度",
        )
    _require_member_capability(member_source, "device_usage")
    provider, provider_id, canonical = _parse_plan_device_ref(device_ref)
    if provider == "cpa":
        linked = (member_source.get("cpa") or {}).get("cpa_synced_to") or {}
        linked_id = int(linked.get("target_id") or 0)
    else:
        linked = (member_source.get("sub2api") or {}).get("sub2api_synced_to") or {}
        linked_id = int(linked.get("device_id") or 0)
    if linked_id != int(provider_id):
        raise HTTPException(409, "账号未关联到指定设备")
    _assert_member_source_binding_current(binding)
    if provider == "cpa":
        from api.gpt_plan_operations import get_account_cpa_usage

        result = get_account_cpa_usage(int(binding.source_account_id))
    else:
        from api.gpt_plan_operations import get_account_sub2api_usage

        result = get_account_sub2api_usage(
            int(binding.source_account_id),
            active=bool(active),
        )
    _assert_member_source_binding_current(binding)
    return {
        "ok": True,
        "account_id": int(account_id),
        "device_ref": canonical,
        "provider": provider,
        "usage": _safe_member_device_usage(provider, result),
    }


def _count_import_lines(data: str) -> int:
    return sum(
        1
        for raw_line in str(data or "").splitlines()
        if str(raw_line or "").strip()
        and not str(raw_line or "").strip().startswith("#")
    )


def _parse_import_line(raw_line: str, line_number: int) -> tuple[str, str, str, str]:
    parts = [part.strip() for part in str(raw_line or "").strip().split("----")]
    if len(parts) == 2:
        email, password = parts
        refresh_token = ""
        client_id = ""
    elif len(parts) >= 4:
        email, password, third, fourth = parts[:4]
        if _UUID_RE.match(third) and not _UUID_RE.match(fourth):
            client_id, refresh_token = third, fourth
        else:
            refresh_token, client_id = third, fourth
    else:
        raise ValueError(
            f"行 {line_number}: 格式错误，应为 邮箱----密码 或 "
            "邮箱----密码----refresh_token----client_id"
        )
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError(f"行 {line_number}: 无效的邮箱地址: {email}")
    return email, password, refresh_token, client_id


def _execute_batch_import(task_id: str, request: GptPlanBatchImportRequest) -> None:
    """Keep the legacy progress contract while using the strict local importer."""
    from services.workspace_accounts import import_ordinary
    from services.gmail_store import GmailStoreError
    _import_tasks.mark_running(task_id)
    processed = success = failed = 0
    for line in request.data.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        error = ""
        try:
            # Legacy imports do not declare registration state: imported GPT
            # credentials are conservatively held for login verification.
            import_ordinary(line, "registered")
            success += 1
        except GmailStoreError as exc:
            failed += 1
            error = exc.message
        except Exception:
            failed += 1
            error = "本地导入未完成，请检查凭证加密配置后重试"
        processed += 1
        _import_tasks.update(task_id, processed=processed, success=success, failed=failed, error=error)
    _import_tasks.finish(task_id)


@router.post("/batch-import")
def batch_import(request: GptPlanBatchImportRequest):
    # 在启动后台线程前校验，避免任务永远停在 pending。
    if request.mail_provider != "gmail":
        raise HTTPException(400, "普通账号仅支持已有 Gmail 子号；BUSINESS 母号请使用母号导入入口")
    from services.workspace_accounts import _parse, require_gmail_alias
    from services.gmail_store import GmailStoreError
    try:
        rows = _parse(request.data, "registered")
        with Session(engine) as session:
            for email, _, _ in rows:
                require_gmail_alias(session, email)
    except GmailStoreError as exc:
        raise HTTPException(exc.status_code, exc.message) from None
    total = _count_import_lines(request.data)
    task_id = f"gpt_plan_import_{uuid.uuid4().hex}"
    _import_tasks.create(task_id, total)
    threading.Thread(
        target=_execute_batch_import,
        args=(task_id, request),
        daemon=True,
        name=f"gpt-plan-import-{task_id[-8:]}",
    ).start()
    return {"task_id": task_id, "total": total}


@router.get("/import-tasks/{task_id}")
def get_import_task(task_id: str):
    snapshot = _import_tasks.snapshot(task_id)
    if not snapshot:
        raise HTTPException(404, "导入任务不存在")
    return snapshot


@router.get("/import-tasks")
def list_import_tasks(limit: int = Query(20, ge=1, le=100)):
    items = _import_tasks.list(limit)
    return {"total": len(items), "items": items}


def _resolve_proxy(value: Optional[str]) -> str:
    if value is not None:
        return str(value or "").strip()
    try:
        from core.config_store import config_store

        return str(config_store.get("default_proxy", "") or "").strip()
    except Exception:
        return ""


def _account_mail_snapshot(account: GptPlanAccountModel) -> dict:
    from services.gmail_plan_support import account_mail_provider, gmail_binding_extra
    return {
        "email": account.email,
        "password": account.password or "",
        "client_id": account.client_id or "",
        "refresh_token": account.refresh_token or "",
        "mail_access_type": account.mail_access_type or "",
        "mail_provider": account_mail_provider(account),
        **gmail_binding_extra(account),
        "last_mail_check_at": account.last_mail_check_at,
        # Plan monitor has an explicit time/identity cutover.  Keep this opt-in
        # out of legacy BUSINESS/PRO monitors that still persist default IDs.
        "graph_immutable_ids": True,
    }


def _redact_text(value: Any, *secrets: str) -> str:
    text = str(value or "")
    for secret in secrets:
        secret = str(secret or "")
        if secret:
            text = text.replace(secret, "<redacted>")
    # 防止底层异常偶然携带 Bearer/JWT。
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+", "Bearer <redacted>", text)
    text = re.sub(
        r"(?i)((?:oai-access|access|session|refresh|id)[_-]?token\s*[:=]\s*)"
        r"[^\s,;]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "<redacted-jwt>",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\b", "<redacted-jwt-fragment>", text)
    text = re.sub(
        r"(?i)((?:cvc|cvv|cvn)\s*[:=]\s*)\d{3,4}",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "<redacted-card>",
        text,
    )
    return text[:500]


def _roxy_proxy_dict(proxy_id: Any) -> Optional[dict]:
    try:
        parsed_id = int(proxy_id or 0)
    except (TypeError, ValueError):
        return None
    if parsed_id <= 0:
        return None
    with Session(engine) as session:
        proxy = session.get(GptPlanRoxyProxyModel, parsed_id)
        if not proxy:
            return None
        return {
            "id": proxy.id,
            "host": proxy.host,
            "port": proxy.port,
            "protocol": proxy.protocol,
            "username": proxy.username,
            "password": proxy.password,
            "note": proxy.note,
            "roxy_module_id": proxy.roxy_module_id,
        }


def _refresh_plan_roxy_proxy(proxy_id: Any) -> None:
    """Refresh the selected fingerprint proxy before a payment operation.

    Payment must not silently use a stale local endpoint.  A missing/deleted
    proxy or an unreachable Roxy service is reported before checkout creation.
    """
    try:
        parsed_id = int(proxy_id or 0)
    except (TypeError, ValueError):
        parsed_id = 0
    if parsed_id <= 0:
        return
    with Session(engine) as session:
        local = session.get(GptPlanRoxyProxyModel, parsed_id)
        if not local:
            raise HTTPException(409, "所选 Roxy 代理不存在，请重新选择")
        module_id = str(local.roxy_module_id or "").strip()
        note = str(local.note or "").strip()
        host = str(local.host or "").strip()
        port = str(local.port or "").strip()

    try:
        from core.roxy_browser import (
            RoxyBrowserClient,
            load_roxy_config,
            resolve_workspace_id,
        )

        config = load_roxy_config()
        workspace_id = resolve_workspace_id()
        rows = RoxyBrowserClient(
            config["api_host"],
            config["token"],
        ).list_proxies(workspace_id)
    except Exception as exc:
        raise HTTPException(
            502,
            f"无法从 RoxyBrowser 刷新所选代理: {_redact_text(exc)}",
        ) from exc

    match = None
    if module_id:
        match = next(
            (row for row in rows if str(row.get("id") or "") == module_id),
            None,
        )
    if match is None and note:
        same_note = [
            row for row in rows
            if str(row.get("remark") or "").strip() == note
        ]
        if len(same_note) == 1:
            match = same_note[0]
    if match is None and host and port:
        match = next(
            (
                row for row in rows
                if str(row.get("host") or "").strip() == host
                and str(row.get("port") or "").strip() == port
            ),
            None,
        )
    if match is None:
        with Session(engine) as session:
            stale = session.get(GptPlanRoxyProxyModel, parsed_id)
            if stale:
                session.delete(stale)
                session.commit()
        raise HTTPException(
            409,
            "所选代理已从 RoxyBrowser 删除，已同步移除，请重新选择",
        )

    with Session(engine) as session:
        local = session.get(GptPlanRoxyProxyModel, parsed_id)
        if not local:
            raise HTTPException(409, "所选 Roxy 代理已被删除")
        fresh_host = str(match.get("host") or "").strip()
        fresh_port = str(match.get("port") or "").strip()
        fresh_protocol = str(match.get("protocol") or "").strip().upper()
        if fresh_host:
            local.host = fresh_host
        if fresh_port:
            local.port = fresh_port
        if fresh_protocol in {"HTTP", "HTTPS", "SOCKS5"}:
            local.protocol = fresh_protocol
        local.username = str(match.get("proxyUserName") or "")
        local.password = str(match.get("proxyPassword") or "")
        if match.get("id"):
            local.roxy_module_id = str(match.get("id"))
        if match.get("lastIp"):
            local.last_ip = str(match.get("lastIp"))
        if match.get("lastCountry"):
            local.last_country = str(match.get("lastCountry"))
        local.updated_at = _utcnow()
        session.add(local)
        session.commit()


def _upsert_upgrade_summary(
    session: Session,
    account_id: int,
) -> GptPlanAccountUpgradeModel:
    row = session.get(GptPlanAccountUpgradeModel, int(account_id))
    if row is None:
        now = _utcnow()
        row = GptPlanAccountUpgradeModel(
            account_id=int(account_id),
            created_at=now,
            updated_at=now,
        )
    return row


def _record_detected_plan_upgrade(
    session: Session,
    account: GptPlanAccountModel,
    *,
    old_plan_type: str,
    new_plan_type: str,
    checked_at: datetime,
) -> None:
    """A later real login is the authority for pending checkout confirmation."""
    canonical = _canonical_member_plan(new_plan_type)
    if not canonical:
        return
    summary = _upsert_upgrade_summary(session, int(account.id or 0))
    if summary.plan_upgraded_at is None and _account_type(old_plan_type) == "regular":
        summary.plan_upgraded_at = checked_at
    expected = "business" if canonical == "team" else canonical
    checkout_target = str(summary.checkout_target or "")
    detected_plan = _normalize_plan_type(new_plan_type)
    pro_variants = {"pro_20x", "pro_5x"}
    target_matches = (
        checkout_target == expected
        or (canonical == "pro" and checkout_target in {"pro", *pro_variants}
            and (detected_plan not in pro_variants or checkout_target not in pro_variants
                 or detected_plan == checkout_target))
    )
    if target_matches and summary.checkout_status in {
        "created",
        "submitted",
        "confirmation_pending",
    }:
        summary.checkout_status = "success"
        summary.plan_upgraded_at = summary.plan_upgraded_at or checked_at
        if canonical == "pro" and checkout_target in pro_variants and detected_plan not in pro_variants:
            # The session API may expose only the generic PRO family. Keep
            # the specific plan of this pending checkout when confirming it;
            # an explicitly detected different variant never takes this path.
            account.plan_type = checkout_target
            session.add(account)
    summary.updated_at = checked_at
    session.add(summary)


@dataclass(frozen=True)
class _BusinessMotherLoginBinding:
    plan_account_id: int
    normalized_email: str
    source_account_id: int
    source_created_at: Optional[datetime]
    source_cookie_updated_at: Optional[datetime]


def _capture_business_mother_login_binding(
    session: Session,
    account: GptPlanAccountModel,
) -> Optional[_BusinessMotherLoginBinding]:
    """Freeze a BUSINESS delegation before the long browser login starts."""
    if (
        str(account.source_pool or "").strip() != "gpt_business"
        or account.business_parent_id is not None
    ):
        return None
    try:
        source_id = int(account.source_account_id or 0)
    except (TypeError, ValueError):
        source_id = 0
    source = (
        session.get(GptBusinessAccountModel, source_id)
        if source_id > 0
        else None
    )
    normalized_email = _normalized_email(account.email)
    if (
        source is None
        or not normalized_email
        or _normalized_email(source.email) != normalized_email
    ):
        raise HTTPException(409, "BUSINESS 母号绑定已失效，请先刷新套餐目录")
    return _BusinessMotherLoginBinding(
        plan_account_id=int(account.id or 0),
        normalized_email=normalized_email,
        source_account_id=source_id,
        source_created_at=_aware_utc(source.created_at),
        source_cookie_updated_at=_aware_utc(source.cookie_updated_at),
    )


def _sync_business_mother_login_cookie(
    session: Session,
    account: GptPlanAccountModel,
    *,
    expected_binding: Optional[_BusinessMotherLoginBinding],
    cookie_blob: str,
    cookie_expires_at: Optional[datetime],
    updated_at: datetime,
) -> bool:
    """Persist a fresh Plan login session to its delegated BUSINESS mother.

    BUSINESS workspace operations intentionally remain delegated to
    ``gpt_business_accounts``.  The Plan login endpoint therefore has one
    narrowly scoped dual-write: a bound BUSINESS mother with an exact
    source id + email match receives the newly obtained cookie.  Other plan
    types and broken/stale bindings can never write a BUSINESS row.
    """
    if expected_binding is None:
        return False
    if not str(cookie_blob or "").strip():
        raise HTTPException(502, "登录成功但未取得新的 BUSINESS Cookie，请重试")
    current_source_id = int(account.source_account_id or 0)
    if (
        int(account.id or 0) != expected_binding.plan_account_id
        or _normalized_email(account.email) != expected_binding.normalized_email
        or str(account.source_pool or "").strip() != "gpt_business"
        or current_source_id != expected_binding.source_account_id
        or account.business_parent_id is not None
    ):
        raise HTTPException(409, "登录期间 BUSINESS 母号绑定发生变化，请重新登录")
    source = session.get(
        GptBusinessAccountModel,
        expected_binding.source_account_id,
    )
    if (
        source is None
        or _normalized_email(source.email) != expected_binding.normalized_email
        or _aware_utc(source.created_at) != expected_binding.source_created_at
    ):
        raise HTTPException(409, "登录期间 BUSINESS 母号身份发生变化，请重新登录")
    if (
        _aware_utc(source.cookie_updated_at)
        != expected_binding.source_cookie_updated_at
    ):
        raise HTTPException(409, "BUSINESS Cookie 已被另一登录更新，请重新登录")
    source.cookie_blob = cookie_blob
    source.cookie_updated_at = updated_at
    source.cookie_expires_at = cookie_expires_at
    source.last_used = updated_at
    source.updated_at = updated_at
    account.source_state = "logged"
    session.add(source)
    return True


def _execute_plan_login(
    account_id: int,
    body: GptPlanLoginRequest,
    *,
    post_login_action: Optional[Any] = None,
    force_keep_open: Optional[bool] = None,
    is_signup: bool = False,
    record_detected_upgrade: bool = True,
) -> tuple[Any, dict, Callable[[Any], None]]:
    """Run one Plan login and persist an allow-listed result.

    The Plan row owns login state.  A BUSINESS mother additionally updates its
    explicit workspace delegation so member operations use the same fresh
    Cookie; no other account type writes another account table.
    """
    from platforms.chatgpt.gpt_pro_login import (
        build_cookie_blob_from_result,
        build_mailbox_for_account,
        login_with_email_otp,
    )

    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        if not account.enabled:
            raise HTTPException(409, "账号已被禁用")
        snapshot = _account_mail_snapshot(account)
        business_cookie_binding = _capture_business_mother_login_binding(
            session,
            account,
        )

    proxy = _resolve_proxy(body.proxy)

    def _safe_login_log(message: Any) -> None:
        print(
            _redact_text(
                message,
                snapshot["password"],
                snapshot["client_id"],
                snapshot["refresh_token"],
                proxy,
            ),
            flush=True,
        )

    try:
        from services.chatgpt_security_store import get_chatgpt_security_status

        security_status = get_chatgpt_security_status(snapshot["email"])
        mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
        managed_mfa = bool(security_status.get("has_totp")) or mfa_state in {
            "pending",
            "enabled",
            "unmanaged",
        }
        saved_password_login = not is_signup and bool(security_status.get("has_password"))
        if managed_mfa or saved_password_login:
            # The canonical dispatcher decrypts the ChatGPT password/TOTP.
            # Do not require or initialize a mailbox that this path cannot use.
            mailbox = None
            mailbox_account = None
        else:
            mailbox, mailbox_account = build_mailbox_for_account(
                snapshot,
                proxy=proxy,
            )
        result = login_with_email_otp(
            email=snapshot["email"],
            mailbox=mailbox,
            mailbox_account=mailbox_account,
            headless=bool(body.headless),
            proxy=proxy,
            otp_timeout=max(30, min(int(body.otp_timeout or 180), 900)),
            keep_browser_open=(
                bool(body.keep_browser_open)
                if force_keep_open is None
                else bool(force_keep_open)
            ),
            is_signup=bool(is_signup),
            post_login_action=post_login_action,
            log_fn=_safe_login_log,
            browser_backend=str(
                getattr(body, "browser_backend", "local") or "local"
            ),
            roxy_proxy=_roxy_proxy_dict(
                getattr(body, "roxy_proxy_id", None)
            ),
        )
    except Exception as exc:
        safe_error = _redact_text(
            exc,
            snapshot["password"],
            snapshot["client_id"],
            snapshot["refresh_token"],
            proxy,
        )
        now = _utcnow()
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, account_id)
            if account:
                account.last_login_at = now
                account.last_login_error = safe_error
                account.updated_at = now
                session.add(account)
                session.commit()
        raise HTTPException(502, f"登录执行失败: {safe_error or '未知错误'}")

    # ``detected_plan_type`` is only the result of this browser session.  A
    # successful login must not silently move an account that is already in a
    # paid member directory (PRO / BUSINESS / PLUS / GO) to another package.
    # Regular and refunded rows deliberately remain eligible for re-detection.
    detected_plan_type = _normalize_plan_type(
        getattr(result, "plan_type", "")
    )
    effective_plan_type = detected_plan_type
    effective_account_type = _account_type(effective_plan_type)
    if bool(getattr(result, "ok", False)):
        cookie_blob = ""
        cookie_expires_at = None
        try:
            cookie_blob, cookie_expires_at = build_cookie_blob_from_result(result)
        except Exception:
            cookie_blob, cookie_expires_at = "", None
        now = _utcnow()
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, account_id)
            if account:
                old_plan_type = _normalize_plan_type(account.plan_type)
                old_account_type = _catalog_category(account)
                plan_type_may_change = old_account_type in {
                    "regular",
                    "refunded",
                }
                if plan_type_may_change:
                    account.plan_type = detected_plan_type
                account.plan_checked_at = now
                account.chatgpt_account_id = str(
                    getattr(result, "account_id", "") or ""
                )
                account.chatgpt_user_id = str(getattr(result, "user_id", "") or "")
                account.last_used = now
                account.last_login_at = now
                account.last_login_error = ""
                account.updated_at = now
                if cookie_blob:
                    account.cookie_blob = cookie_blob
                    account.cookie_updated_at = now
                    account.cookie_expires_at = cookie_expires_at
                _sync_business_mother_login_cookie(
                    session,
                    account,
                    expected_binding=business_cookie_binding,
                    cookie_blob=cookie_blob,
                    cookie_expires_at=cookie_expires_at,
                    updated_at=now,
                )
                if record_detected_upgrade and plan_type_may_change:
                    _record_detected_plan_upgrade(
                        session,
                        account,
                        old_plan_type=old_plan_type,
                        new_plan_type=detected_plan_type,
                        checked_at=now,
                    )
                session.add(account)
                session.commit()
                # The frontend treats these fields as the committed directory
                # state and immediately switches tabs from them.  Return the
                # persisted value, not a detected value that we intentionally
                # ignored for an existing paid member.
                effective_plan_type = _normalize_plan_type(account.plan_type)
                effective_account_type = _catalog_category(account)

    safe_error = _redact_text(
        getattr(result, "error", ""),
        snapshot["password"],
        snapshot["client_id"],
        snapshot["refresh_token"],
        str(getattr(result, "access_token", "") or ""),
        str(getattr(result, "session_token", "") or ""),
        proxy,
    )
    if not bool(getattr(result, "ok", False)):
        now = _utcnow()
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, account_id)
            if account:
                account.last_login_at = now
                account.last_login_error = safe_error or "登录失败"
                if (
                    str(getattr(result, "stage", "") or "")
                    == "account_deactivated"
                    or "account_deactivated" in safe_error
                ):
                    account.dangerous = True
                    account.dangerous_detected_at = (
                        account.dangerous_detected_at or now
                    )
                account.updated_at = now
                session.add(account)
                session.commit()
    public = {
        "ok": bool(getattr(result, "ok", False)),
        "stage": str(getattr(result, "stage", "") or ""),
        "error": safe_error,
        "plan_type": effective_plan_type,
        "plan_label": _plan_label(effective_plan_type),
        "account_type": effective_account_type,
        "member_plan": (
            _canonical_member_plan(effective_plan_type)
            if effective_account_type == "member"
            else ""
        ),
    }
    return result, public, _safe_login_log


@router.post("/accounts/{account_id}/login")
def login_account(account_id: int, body: Optional[GptPlanLoginRequest] = None):
    operation_token = _claim_plan_operation(int(account_id), "login")
    try:
        _, public, _ = _execute_plan_login(
            account_id,
            body or GptPlanLoginRequest(),
        )
    finally:
        _release_plan_operation(int(account_id), operation_token)
    # Explicit allow-list: never return result.to_dict(), action_result, tokens,
    # cookies, page objects or mailbox credentials.
    return public


@router.post("/accounts/{account_id}/ms-web-login")
def ms_web_login(
    account_id: int,
    body: Optional[GptPlanMsLoginRequest] = None,
):
    """Start the Microsoft-mail browser flow from a local plan account."""
    body = body or GptPlanMsLoginRequest()
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        email = str(account.email or "").strip()
        password = str(account.password or "").strip()
        from services.gmail_plan_support import account_mail_provider
        provider = account_mail_provider(account)

    if provider != "outlook":
        raise HTTPException(400, "邮箱登录仅支持微软邮箱")
    if not email:
        raise HTTPException(400, "该账号没有保存邮箱")
    if not password:
        raise HTTPException(400, "该账号没有保存密码，无法自动登录微软邮箱")

    proxy = _resolve_proxy(body.proxy)
    headless = bool(body.headless)

    def _worker() -> None:
        from platforms.chatgpt.gpt_pro_login import run_ms_web_login

        try:
            run_ms_web_login(
                email,
                password,
                proxy=proxy,
                headless=headless,
                log_fn=lambda message: print(
                    _redact_text(message, password, proxy),
                    flush=True,
                ),
            )
        except Exception as exc:
            print(
                f"[套餐邮箱登录] 线程异常: {_redact_text(exc, password, proxy)}",
                flush=True,
            )

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"gpt-plan-ms-login-{account_id}",
    ).start()
    return {
        "ok": True,
        "email": email,
        "note": "已在后台打开浏览器登录微软网页版邮箱，请在弹出的窗口里使用或完成验证。",
    }


# -- Checkout region -----------------------------------------------------------

_CHECKOUT_COUNTRY_KEY = "gpt_plan_checkout_country"
_CHECKOUT_CURRENCY_KEY = "gpt_plan_checkout_currency"
_BUSINESS_CHECKOUT_COUPON_KEY = "gpt_plan_business_coupon"
_DEFAULT_BUSINESS_CHECKOUT_COUPON = "cloudelligent"


def _validate_business_checkout_coupon(value: str) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, "BUSINESS 优惠码必须是文本")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise HTTPException(400, "BUSINESS 优惠码不能包含换行或控制字符")
    coupon = value.strip()
    if not coupon:
        raise HTTPException(400, "请填写 BUSINESS 优惠码")
    if len(coupon) > 200:
        raise HTTPException(400, "BUSINESS 优惠码不能超过 200 个字符")
    return coupon


def _business_checkout_coupon(override: Optional[str] = None) -> str:
    if override is not None:
        return _validate_business_checkout_coupon(override)
    from core.config_store import config_store

    return _validate_business_checkout_coupon(config_store.get(
        _BUSINESS_CHECKOUT_COUPON_KEY, _DEFAULT_BUSINESS_CHECKOUT_COUPON,
    ))


@router.get("/business-checkout-config")
def get_business_checkout_config():
    return {"ok": True, "coupon": _business_checkout_coupon()}


@router.put("/business-checkout-config")
def put_business_checkout_config(body: GptPlanBusinessCheckoutConfigRequest):
    from core.config_store import config_store

    coupon = _validate_business_checkout_coupon(body.coupon)
    config_store.set(_BUSINESS_CHECKOUT_COUPON_KEY, coupon)
    # Re-read the committed value; do not claim persistence based on a draft.
    return get_business_checkout_config()


@router.get("/business-invite-config")
def get_business_invite_config():
    raise HTTPException(410, "本项目已取消 BUSINESS 邀请次数限制")


@router.put("/business-invite-config")
def put_business_invite_config(body: GptPlanBusinessInviteConfigRequest):
    raise HTTPException(410, "本项目已取消 BUSINESS 邀请次数限制")


@router.get("/{account_id}/business-invite-usage")
def get_business_invite_usage(account_id: int):
    raise HTTPException(410, "邀请已用次数不再支持人工调整")


@router.put("/{account_id}/business-invite-usage")
def put_business_invite_usage(account_id: int, body: GptPlanBusinessInviteUsageRequest):
    raise HTTPException(410, "邀请已用次数不再支持人工调整")


_COUNTRY_CURRENCY = {
    "US": "USD", "JP": "JPY", "GB": "GBP", "CA": "CAD", "AU": "AUD",
    "NZ": "NZD", "DE": "EUR", "FR": "EUR", "IT": "EUR", "ES": "EUR",
    "NL": "EUR", "IE": "EUR", "AT": "EUR", "BE": "EUR", "FI": "EUR",
    "PT": "EUR", "GR": "EUR", "CH": "CHF", "SE": "SEK", "NO": "NOK",
    "DK": "DKK", "PL": "PLN", "CZ": "CZK", "HU": "HUF", "RO": "RON",
    "PH": "PHP", "IN": "INR", "SG": "SGD", "HK": "HKD", "TW": "TWD",
    "KR": "KRW", "MY": "MYR", "TH": "THB", "VN": "VND", "ID": "IDR",
    "BR": "BRL", "MX": "MXN", "AR": "ARS", "CL": "CLP", "CO": "COP",
    "PE": "PEN", "NG": "NGN", "ZA": "ZAR", "EG": "EGP", "KE": "KES",
    "MA": "MAD", "AE": "AED", "SA": "SAR", "IL": "ILS", "TR": "TRY",
    "QA": "QAR", "KW": "KWD", "RU": "RUB", "UA": "UAH", "CN": "CNY",
    "PK": "PKR", "BD": "BDT", "LK": "LKR",
}


def _get_checkout_region() -> tuple[str, str]:
    from core.config_store import config_store

    country = str(config_store.get(_CHECKOUT_COUNTRY_KEY, "") or "").strip().upper()
    currency = str(config_store.get(_CHECKOUT_CURRENCY_KEY, "") or "").strip().upper()
    return country or "PH", currency or "PHP"


def _checkout_region_for_upgrade(body: GptPlanUpgradeProRequest) -> tuple[str, str]:
    try:
        proxy_id = int(body.roxy_proxy_id or 0)
    except (TypeError, ValueError):
        proxy_id = 0
    if proxy_id > 0:
        with Session(engine) as session:
            proxy = session.get(GptPlanRoxyProxyModel, proxy_id)
        country = str(getattr(proxy, "last_country", "") or "").strip().upper()
        if country in _COUNTRY_CURRENCY:
            return country, _COUNTRY_CURRENCY[country]
    return _get_checkout_region()


@router.get("/checkout-region")
def get_checkout_region():
    country, currency = _get_checkout_region()
    return {"country": country, "currency": currency}


@router.put("/checkout-region")
def put_checkout_region(body: GptPlanCheckoutRegionRequest):
    from core.config_store import config_store

    country = str(body.country or "").strip().upper()
    currency = str(body.currency or "").strip().upper()
    if len(country) != 2 or not country.isalpha():
        raise HTTPException(400, "country 必须是 2 位国家代码")
    if len(currency) != 3 or not currency.isalpha():
        raise HTTPException(400, "currency 必须是 3 位币种代码")
    config_store.set(_CHECKOUT_COUNTRY_KEY, country)
    config_store.set(_CHECKOUT_CURRENCY_KEY, currency)
    return {"ok": True, "country": country, "currency": currency}


# -- Independent GPT Plan account leases and PRO task state -------------------

def _claim_plan_operation(account_id: int, operation: str) -> str:
    from services.gpt_plan_login_lease import (
        login_lease_owner_stopped,
        new_login_lease_token,
        new_preparation_lease_token,
        preparation_lease_owner_stopped,
    )

    token = (new_login_lease_token() if operation == "login" else
             new_preparation_lease_token() if operation == "account_preparation" else uuid.uuid4().hex)
    now = _utcnow()
    expires_at = now + timedelta(hours=GPT_PLAN_OPERATION_LEASE_HOURS)
    try:
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            account = session.get(GptPlanAccountModel, int(account_id))
            if not account:
                raise HTTPException(404, "账号不存在")
            current = session.get(
                GptPlanAccountOperationLeaseModel,
                int(account_id),
            )
            if current and (
                (_aware_utc(current.expires_at) or now) <= now
                or (
                    current.operation == "login"
                    and login_lease_owner_stopped(current.token)
                )
                or (
                    current.operation == "account_preparation"
                    and preparation_lease_owner_stopped(current.token)
                )
            ):
                session.delete(current)
                session.flush()
                current = None
            if current:
                operation_label = {
                    "account_preparation": "账号准备",
                    "setup_security": "密码与 2FA 设置",
                    "login": "登录",
                }.get(current.operation, current.operation)
                raise HTTPException(
                    409,
                    {
                        "code": "gpt_plan_account_busy",
                        "message": f"账号正在执行{operation_label}，请等待完成后再试",
                        "operation": current.operation,
                        "expires_at": _iso_utc(current.expires_at),
                    },
                )
            session.add(GptPlanAccountOperationLeaseModel(
                account_id=int(account_id),
                operation=str(operation or "account_operation"),
                token=token,
                expires_at=expires_at,
                created_at=now,
                updated_at=now,
            ))
            session.commit()
    except IntegrityError as exc:
        raise HTTPException(409, "账号刚被其他付款任务占用，请稍后重试") from exc
    return token


def _release_stopped_plan_preparation_operation(account_id: int) -> bool:
    """Unblock candidate checks only for an exactly identified dead local owner.

    Candidate selection reads busy leases before the next preparation claim.
    Use the same process identity proof as the claim path, then compare the
    observed token in the DELETE so a concurrent replacement is never unlocked.
    Legacy, foreign and unreadable owners retain their normal expiry path.
    """
    from services.gpt_plan_login_lease import preparation_lease_owner_stopped

    if type(account_id) is not int or account_id <= 0:
        return False
    with Session(engine) as session:
        lease = session.get(GptPlanAccountOperationLeaseModel, account_id)
        if (lease is None or lease.operation != "account_preparation"
                or not preparation_lease_owner_stopped(lease.token)):
            return False
        result = session.execute(sa_delete(GptPlanAccountOperationLeaseModel).where(
            GptPlanAccountOperationLeaseModel.account_id == account_id,
            GptPlanAccountOperationLeaseModel.operation == "account_preparation",
            GptPlanAccountOperationLeaseModel.token == lease.token,
        ).execution_options(synchronize_session=False))
        session.commit()
        return result.rowcount == 1


def _release_plan_operation(account_id: int, token: str) -> None:
    if not token:
        return
    with Session(engine) as session:
        session.execute(
            sa_delete(GptPlanAccountOperationLeaseModel)
            .where(GptPlanAccountOperationLeaseModel.account_id == int(account_id))
            .where(GptPlanAccountOperationLeaseModel.token == str(token))
        )
        session.commit()


def _plan_operation_is_current(
    session: Session,
    account_id: int,
    token: str,
    operation: str,
) -> bool:
    current = session.get(GptPlanAccountOperationLeaseModel, int(account_id))
    return bool(
        current
        and current.token == token
        and current.operation == operation
        and (_aware_utc(current.expires_at) or _utcnow()) > _utcnow()
    )


def _ensure_refunded_plan_account(
    session: Session,
    account: GptPlanAccountModel,
) -> GptPlanAccountModel:
    """Validate one locally owned refunded account before reuse/migration."""
    if _catalog_category(account) != "refunded":
        raise HTTPException(409, "只有已退款账号可以执行该操作")
    if str(account.refund_status or "").strip() != "refunded_pending_credit":
        raise HTTPException(409, "账号已不在“已退款未到账”状态")
    if account.business_parent_id is not None:
        raise HTTPException(409, "BUSINESS 子号不能作为已退款账号重新升级或迁移")
    if not bool(account.enabled):
        raise HTTPException(409, "账号已被禁用，不能重新升级或迁移")
    if bool(account.dangerous):
        raise HTTPException(409, "Dead 账号不能重新升级或迁移")
    if bool(account.policy_warning):
        raise HTTPException(409, "存在用量政策告警的账号不能重新升级或迁移")
    return account


def _ensure_regular_upgrade_candidate(
    session: Session,
    account_id: int,
) -> GptPlanAccountModel:
    account = session.get(GptPlanAccountModel, int(account_id))
    if not account:
        raise HTTPException(404, "账号不存在")
    if not account.enabled:
        raise HTTPException(409, "账号已被禁用，不能升级")
    if bool(account.dangerous):
        raise HTTPException(409, "Dead 账号不能发起付款升级")
    if _catalog_category(account) == "refunded":
        _ensure_refunded_plan_account(session, account)
    elif _account_type(account.plan_type) != "regular":
        raise HTTPException(409, "只有普通/Free 账号可以发起升级")
    summary = session.get(GptPlanAccountUpgradeModel, int(account_id))
    if summary and summary.checkout_status in {
        "confirmation_pending",
        "manual_confirmation_pending",
    }:
        if summary.checkout_status == "manual_confirmation_pending":
            raise HTTPException(409, "上一笔 PRO 升级正在等待人工确认结果")
        raise HTTPException(409, "上一笔付款已跳转成功但套餐待复核，请先点登录重新检测套餐")
    return account


_REFUNDED_MIGRATION_PLAN_TYPES = {
    "pro": ("pro_20x", "pro"),
    "plus": ("plus", "plus"),
    "go": ("go", "go"),
}


def _new_business_source_from_refunded(
    account: GptPlanAccountModel,
    *,
    migrated_at: datetime,
) -> GptBusinessAccountModel:
    """Create the explicitly delegated BUSINESS workspace parent."""
    from services.gmail_plan_support import account_mail_provider
    source_extra = _safe_json_object(account.extra_json)
    source_extra["mail_provider"] = account_mail_provider(account)
    return GptBusinessAccountModel(
        email=str(account.email or ""),
        password=str(account.password or ""),
        client_id=str(account.client_id or ""),
        refresh_token=str(account.refresh_token or ""),
        mail_access_type=str(account.mail_access_type or ""),
        dangerous=bool(account.dangerous),
        dangerous_detected_at=account.dangerous_detected_at,
        policy_warning=bool(account.policy_warning),
        policy_warning_detected_at=account.policy_warning_detected_at,
        codex_access_token=str(account.codex_access_token or ""),
        codex_refresh_token=str(account.codex_refresh_token or ""),
        codex_id_token=str(account.codex_id_token or ""),
        codex_session_token=str(account.codex_session_token or ""),
        codex_rt_acquired_at=account.codex_rt_acquired_at,
        note=str(account.note or ""),
        extra_json=json.dumps(source_extra, ensure_ascii=False),
        business_upgraded_at=migrated_at,
        cookie_blob=str(account.cookie_blob or ""),
        cookie_updated_at=account.cookie_updated_at,
        cookie_expires_at=account.cookie_expires_at,
        refund_status="",
        refund_detected_at=account.refund_detected_at,
        refund_credited_at=account.refund_credited_at,
        refund_manual_at=account.refund_manual_at,
        human_review_requested_at=account.human_review_requested_at,
        last_mail_check_at=account.last_mail_check_at,
        last_mail_check_error=str(account.last_mail_check_error or ""),
        seen_mail_ids_json=str(account.seen_mail_ids_json or "[]"),
        pending_alerts_json=str(account.pending_alerts_json or "[]"),
        pending_inbox_json=str(account.pending_inbox_json or "[]"),
        enabled=bool(account.enabled),
        created_at=account.created_at,
        updated_at=migrated_at,
        last_used=account.last_used,
    )


def _business_source_for_refunded_migration(
    session: Session,
    account: GptPlanAccountModel,
    *,
    migrated_at: datetime,
) -> GptBusinessAccountModel:
    """Restore an exact existing delegation; never adopt a source by email."""
    email = _normalized_email(account.email)
    matches = session.exec(
        select(GptBusinessAccountModel.id).where(
            func.lower(func.trim(GptBusinessAccountModel.email)) == email
        )
    ).all()
    if account.source_pool != "gpt_business":
        if matches:
            raise HTTPException(
                409, "同邮箱 BUSINESS 母号已存在，但不是当前账号的原绑定记录；未合并，请核对归属",
            )
        return _new_business_source_from_refunded(account, migrated_at=migrated_at)

    source_id = int(account.source_account_id or 0)
    if source_id <= 0:
        raise HTTPException(409, "原 BUSINESS 母号绑定缺失，未创建或认领其他母号")
    from api.gpt_business import _lock_business_parent_state_mutation

    business = _lock_business_parent_state_mutation(session, [source_id]).get(source_id)
    if business is None:
        raise HTTPException(409, "原绑定的 BUSINESS 母号不存在，请先核对归属")
    if _normalized_email(business.email) != email:
        raise HTTPException(409, "原绑定的 BUSINESS 母号邮箱不一致，未执行迁移")
    if len(matches) != 1 or matches[0] != source_id:
        raise HTTPException(409, "同邮箱 BUSINESS 母号记录不唯一，未执行迁移")
    other_owner = session.exec(
        select(GptPlanAccountModel.id).where(
            GptPlanAccountModel.id != account.id,
            func.lower(func.trim(GptPlanAccountModel.source_pool)) == "gpt_business",
            GptPlanAccountModel.source_account_id == source_id,
        )
    ).first()
    if other_owner is not None:
        raise HTTPException(409, "原 BUSINESS 母号还关联其他套餐账号，未执行迁移")
    child_membership = session.exec(
        select(GptBusinessChildMembershipModel.id).where(
            GptBusinessChildMembershipModel.ended_at.is_(None),
            or_(
                GptBusinessChildMembershipModel.pro_account_id == account.id,
                func.lower(func.trim(GptBusinessChildMembershipModel.email)) == email,
            ),
        )
    ).first()
    if child_membership is not None:
        raise HTTPException(409, "该账号仍有未结束的 BUSINESS 子号归属，不能迁移为母号")
    if not business.enabled or business.dangerous or business.policy_warning:
        raise HTTPException(409, "原 BUSINESS 母号已禁用、Dead 或存在政策告警，未执行迁移")
    if str(business.refund_status or "").strip() not in {"", "refunded_pending_credit"}:
        raise HTTPException(409, "原 BUSINESS 母号退款状态与当前账号不一致，未执行迁移")

    # The original source owns workspace identity, cookies, member history,
    # device bindings and invitation limits. Do not rebuild or overwrite it
    # with the (possibly older) directory snapshot.
    business.refund_status = ""
    business.business_upgraded_at = migrated_at
    business.updated_at = migrated_at
    return business


@router.post("/accounts/{account_id}/migrate-refunded")
def migrate_refunded_account(
    account_id: int,
    body: GptPlanRefundedMigrationRequest,
):
    """Atomically move one local refunded account into a paid-plan category."""
    plan_token = _claim_plan_operation(account_id, "migrate_refunded")
    try:
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            account = session.exec(
                select(GptPlanAccountModel)
                .where(GptPlanAccountModel.id == int(account_id))
                .with_for_update()
            ).first()
            if not account:
                raise HTTPException(404, "账号不存在")
            if not _plan_operation_is_current(
                session,
                account_id,
                plan_token,
                "migrate_refunded",
            ):
                raise HTTPException(409, "套餐迁移租约已失效，请重试")
            _ensure_refunded_plan_account(session, account)

            target = str(body.target_plan)
            now = _utcnow()
            if target == "business":
                business = _business_source_for_refunded_migration(
                    session, account,
                    migrated_at=now,
                )
                session.add(business)
                session.flush()
                account.source_pool = "gpt_business"
                account.source_account_id = int(business.id or 0)
                account.plan_type = "business_master"
                account.source_state = (
                    "logged"
                    if business.cookie_updated_at is not None
                    or bool(str(business.cookie_blob or "").strip())
                    else "never_logged"
                )
                account.is_pro = False
            else:
                plan_type, source_state = _REFUNDED_MIGRATION_PLAN_TYPES[target]
                account.source_pool = ""
                account.source_account_id = None
                account.plan_type = plan_type
                account.source_state = source_state
                account.is_pro = target == "pro"
                if target == "pro":
                    account.subscribed_at = now

            account.refund_status = ""
            account.catalog_category = "member"
            account.plan_checked_at = now
            account.source_synced_at = None
            account.updated_at = now
            summary = _upsert_upgrade_summary(session, int(account_id))
            summary.plan_upgraded_at = now
            summary.updated_at = now
            session.add(account)
            session.add(summary)
            session.commit()
            session.refresh(account)
            member_source = _member_source_map(session, [account]).get(int(account_id))
            public_account = _serialize_account(
                account,
                summary,
                member_source,
            )
            return {
                "ok": True,
                "id": int(account_id),
                "email": str(account.email or ""),
                "target_plan": target,
                "migrated_at": _iso_utc(now),
                "account": public_account,
            }
    except IntegrityError as exc:
        raise HTTPException(
            409,
            "迁移时检测到同邮箱或 BUSINESS 母号冲突，所有变更均已回滚",
        ) from exc
    finally:
        _release_plan_operation(account_id, plan_token)



_PLAN_UPGRADE_TASKS: dict[str, dict] = {}
_PLAN_UPGRADE_LOCK = threading.Lock()
# phase1 失败尚未启动填卡/订阅任务。保留有头页面供查看，下一次
# 同账号升级开始前回收该页面，避免一重试就积累一个浏览器。
_PLAN_CHECKOUT_FAILURE_PAGES: dict[int, Any] = {}


def _close_previous_checkout_failure_page(account_id: int) -> None:
    with _PLAN_UPGRADE_LOCK:
        page = _PLAN_CHECKOUT_FAILURE_PAGES.pop(int(account_id), None)
    if page is not None:
        try:
            page.quit()
        except Exception:
            # 用户可能已经手动关闭了这个只用于查看错误的窗口。
            pass

# 发布人工确认之前，已退款升级的不确定结果曾被
# 自动写成以下状态。它们不再被当成真实的 PRO 失败，
# 并可由同一人工接口在升级后安全收敛。
_REFUNDED_MANUAL_CONFIRMABLE_STATUSES = frozenset({
    "manual_confirmation_pending",
    "confirmation_pending",
    "failed",
    "timeout",
    "pro_failed",
})

_UPGRADE_TASK_PUBLIC_KEYS = frozenset({
    "task_id",
    "account_id",
    "stage",
    "stage_at",
    "started_at",
    "finished_at",
    "auth_stage",
    "pay_url",
    "checkout_session_id",
    "region",
    "go_then_pro",
    "pro_only",
    "target_plan",
    "detected_plan",
    "cards_count",
    "pick_timeout",
    "error",
    "confirmed_plan",
    "manual_confirmation_required",
})


def _public_upgrade_task(task: dict) -> dict:
    public = {
        key: task.get(key)
        for key in _UPGRADE_TASK_PUBLIC_KEYS
        if key in task
    }
    if "error" in public:
        public["error"] = _redact_text(public.get("error") or "")
    return public


def _prune_upgrade_tasks_locked() -> None:
    finished = sorted(
        (
            task
            for task in _PLAN_UPGRADE_TASKS.values()
            if task.get("finished_at")
        ),
        key=lambda item: str(item.get("finished_at") or ""),
        reverse=True,
    )
    for old in finished[MAX_FINISHED_UPGRADE_TASKS:]:
        _PLAN_UPGRADE_TASKS.pop(str(old.get("task_id") or ""), None)


def _set_upgrade_task_stage(task_id: str, stage: str, **extra: Any) -> bool:
    with _PLAN_UPGRADE_LOCK:
        task = _PLAN_UPGRADE_TASKS.get(task_id)
        if not task:
            return False
        task["stage"] = stage
        task["stage_at"] = _iso_utc(_utcnow())
        for key, value in extra.items():
            task[key] = value
        if stage in {
            "success",
            "failed",
            "timeout",
            "confirmation_pending",
            "manual_confirmation_pending",
            "manual_not_upgraded",
        }:
            task["finished_at"] = _iso_utc(_utcnow())
            _prune_upgrade_tasks_locked()
        return True


def _parse_card_text(text: str) -> Optional[dict]:
    raw = str(text or "")
    if not raw.strip():
        return None
    number = ""
    labelled = re.search(
        r"(?:card\s*number|card\s*no|卡号|卡號|number|卡片号码)\s*[:：]?\s*([\d][\d\s\-]{11,25})",
        raw,
        re.IGNORECASE,
    )
    if labelled:
        number = re.sub(r"\D", "", labelled.group(1))
    if not (13 <= len(number) <= 19):
        for candidate in re.findall(r"\d[\d\s\-]{11,23}\d", raw):
            digits = re.sub(r"\D", "", candidate)
            if 13 <= len(digits) <= 19:
                number = digits
                break
    expiry = re.search(r"(\d{1,2})\s*[/\-.]\s*(\d{2,4})", raw)
    cvc = re.search(r"(?:cvv|cvc|cvn|安全码|安全碼|校验码)\s*[:：]?\s*(\d{3,4})", raw, re.IGNORECASE)
    if not (13 <= len(number) <= 19) or not expiry or not cvc:
        return None
    month = int(expiry.group(1))
    if not 1 <= month <= 12:
        return None
    year = int(expiry.group(2))
    if year < 100:
        year += 2000
    return {
        "number": number,
        "exp_month": month,
        "exp_year": year,
        "cvc": cvc.group(1),
    }


def _fetch_plan_bank_cards(log_fn: Callable[[Any], None]) -> list[dict[str, Any]]:
    """Load only the Plan-owned card/payment inventory for checkout UI."""

    from core.config_store import config_store
    from platforms.chatgpt.gpt_pro_login import _DEFAULT_BILLING_ADDRESS

    try:
        max_uses = max(
            1,
            int(str(config_store.get("gpt_plan_card_max_uses", "") or 6) or 6),
        )
    except Exception:
        max_uses = 6
    with Session(engine) as session:
        disabled_payment_ids = {
            int(row.id or 0)
            for row in session.exec(
                select(GptPlanPaymentAccountModel).where(
                    GptPlanPaymentAccountModel.enabled == False  # noqa: E712
                )
            ).all()
        }
        rows = session.exec(
            select(GptPlanCardModel)
            .where(GptPlanCardModel.enabled == True)  # noqa: E712
            .order_by(
                col(GptPlanCardModel.priority).asc(),
                col(GptPlanCardModel.id).desc(),
            )
        ).all()
        cards: list[dict[str, Any]] = []
        for card in rows:
            if int(card.payment_account_id or 0) in disabled_payment_ids:
                continue
            if int(card.use_count or 0) >= max_uses:
                continue
            if card.status not in ("unused", "") and not (
                card.status == "used" and not card.single_use
            ):
                continue
            cards.append({
                "id": card.id,
                "label": card.label or "",
                "priority": int(card.priority or 100),
                "number": card.number or "",
                "number_masked": card.masked(),
                "exp_month": card.exp_month,
                "exp_year": card.exp_year,
                "cvc": card.cvc or "",
                "holder_name": card.holder_name or "",
                **_DEFAULT_BILLING_ADDRESS,
                "brand": "",
            })
    log_fn(f"[GPT 套餐升级] 套餐管理卡池可用卡 {len(cards)} 张")
    return cards


def _record_checkout_created(
    account_id: int,
    *,
    target: str,
    checkout_session_id: str,
    country: str,
    currency: str,
    status: str = "created",
    workspace_name: str = "",
    seat_type: str = "",
    seat_quantity: int = 0,
) -> None:
    now = _utcnow()
    with Session(engine) as session:
        summary = _upsert_upgrade_summary(session, int(account_id))
        summary.checkout_created_at = now
        summary.checkout_target = str(target or "")
        summary.checkout_status = str(status or "created")
        summary.checkout_session_id = str(checkout_session_id or "")
        summary.checkout_country = str(country or "").upper()
        summary.checkout_currency = str(currency or "").upper()
        summary.workspace_name = str(workspace_name or "")
        summary.seat_type = str(seat_type or "")
        summary.seat_quantity = int(seat_quantity or 0)
        summary.updated_at = now
        session.add(summary)
        session.commit()


def _set_checkout_summary_status(
    account_id: int,
    status: str,
    *,
    operation_token: str = "",
    operation: str = "upgrade_pro",
) -> bool:
    with Session(engine) as session:
        if operation_token and not _plan_operation_is_current(
            session,
            account_id,
            operation_token,
            operation,
        ):
            return False
        summary = session.get(GptPlanAccountUpgradeModel, int(account_id))
        if not summary:
            return False
        summary.checkout_status = str(status or "")
        summary.updated_at = _utcnow()
        session.add(summary)
        session.commit()
        return True


def _confirm_pro_after_checkout(page: Any, log_fn: Callable[[Any], None]) -> dict:
    """Patchable confirmation boundary used by mocked tests and real checkout."""
    from platforms.chatgpt.gpt_pro_login import _detect_current_plan

    try:
        detected = _detect_current_plan(page, log_fn) or {}
    except Exception as exc:
        return {"confirmed": False, "error": _redact_text(exc)}
    return {
        "confirmed": bool(detected.get("ok") and detected.get("is_pro")),
        "plan_type": str(detected.get("plan") or ""),
        "error": "" if detected.get("ok") else "套餐复核请求失败",
    }


def _card_last4_from_phase2(phase2: dict) -> str:
    picked = (phase2.get("stripe_fill") or {}).get("picked_card") or {}
    masked = re.sub(r"\D", "", str(picked.get("number_masked") or ""))
    return masked[-4:] if len(masked) >= 4 else ""


def _persist_pro_checkout_result(
    account_id: int,
    operation_token: str,
    phase2: dict,
    *,
    confirmed: bool,
    pending_status: str = "confirmation_pending",
    target_plan: str = "pro",
) -> bool:
    now = _utcnow()
    picked_card_id = phase2.get("picked_card_id")
    last4 = _card_last4_from_phase2(phase2)
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account or not _plan_operation_is_current(
            session,
            account_id,
            operation_token,
            "upgrade_pro",
        ):
            return False
        summary = _upsert_upgrade_summary(session, int(account_id))
        summary.checkout_status = (
            "success" if confirmed else str(pending_status or "confirmation_pending")
        )
        if last4:
            summary.payment_card_last4 = last4

        card = None
        if picked_card_id not in (None, ""):
            try:
                card = session.get(GptPlanCardModel, int(picked_card_id))
            except (TypeError, ValueError):
                card = None
        if card is not None:
            try:
                from core.config_store import config_store

                max_uses = int(str(config_store.get("gpt_plan_card_max_uses", "") or 6) or 6)
            except Exception:
                max_uses = 6
            card.use_count = int(card.use_count or 0) + 1
            card.used_at = now
            # Plan cards have their own table, so this id unambiguously belongs
            # to gpt_plan_accounts.  Keeping the reservation makes the Plan
            # card page's owner/audit trail complete without touching GPT PRO.
            card.reserved_by_account_id = int(account_id)
            card.updated_at = now
            if card.use_count >= max(1, max_uses):
                card.status = "used"
            session.add(card)
            summary.payment_account_id = int(card.payment_account_id or 0)
            if card.payment_account_id:
                payment_account = session.get(
                    GptPlanPaymentAccountModel,
                    int(card.payment_account_id),
                )
                if payment_account:
                    summary.payment_account_name = payment_account.name or ""
                    summary.payment_account_type = payment_account.account_type or ""

        if confirmed:
            account.plan_type = target_plan if target_plan in {"pro", "pro_20x", "pro_5x"} else "pro"
            account.plan_checked_at = now
            account.last_used = now
            account.updated_at = now
            summary.plan_upgraded_at = now
            session.add(account)
        summary.updated_at = now
        session.add(summary)
        session.commit()
        return True


def _upgrade_pro_worker(
    task_id: str,
    account_id: int,
    operation_token: str,
    page: Any,
    *,
    pick_timeout: int,
    auto_pick_seconds: int,
    direct_card: Optional[dict],
    go_then_pro: bool,
    country: str,
    currency: str,
    go_to_pro_wait: int,
    pro_only: bool,
    manual_confirmation_required: bool,
    log_fn: Callable[[Any], None],
    target_plan: str = "pro",
    pro_plan_name: str = "chatgptpro",
) -> None:
    from platforms.chatgpt.gpt_pro_login import run_checkout_phase2

    def stage_callback(stage: str) -> None:
        # 已退款账号的新一轮 PRO 升级由操作人裁定。
        # phase2 内部的 timeout/pro_failed/success 都只是浏览器
        # 观测，不得越过人工确认改变任务终态。
        if manual_confirmation_required and str(stage or "") in {
            "success",
            "failed",
            "timeout",
            "cancelled",
            "pro_failed",
            "confirmation_pending",
        }:
            return
        _set_upgrade_task_stage(task_id, str(stage or ""))

    try:
        phase2 = run_checkout_phase2(
            page,
            timeout=pick_timeout,
            auto_pick_seconds=auto_pick_seconds,
            direct_card=direct_card,
            stage_cb=stage_callback,
            go_then_pro=go_then_pro,
            country=country,
            currency=currency,
            go_to_pro_wait=go_to_pro_wait,
            pro_plan_name=pro_plan_name,
            pro_only=pro_only,
            card_loader=_fetch_plan_bank_cards,
        ) or {}
        if manual_confirmation_required:
            if bool(phase2.get("subscription_success")):
                # 记录已实际使用的卡摘要，但明确不自动把
                # 账号改成 PRO。底层套餐探测结果也不参与裁定。
                _persist_pro_checkout_result(
                    account_id,
                    operation_token,
                    phase2,
                    confirmed=False,
                    pending_status="manual_confirmation_pending",
                    target_plan=target_plan,
                )
                reason = "付款流程已结束，请人工确认是否升级成功"
            elif phase2.get("timeout"):
                reason = "等待时间已到，系统不自动判定失败，请人工确认"
            else:
                reason = "浏览器未能自动确认结果，请人工确认是否升级成功"
            # summary 在创建任务时已持久化为待人工确认。
            # 这里再写一次是为了兼容正在运行的旧进程任务。
            _set_checkout_summary_status(
                account_id,
                "manual_confirmation_pending",
                operation_token=operation_token,
            )
            _set_upgrade_task_stage(
                task_id,
                "manual_confirmation_pending",
                error=reason,
                manual_confirmation_required=True,
            )
            return
        if not bool(phase2.get("subscription_success")):
            stage = "timeout" if phase2.get("timeout") else "failed"
            reason = "等待选卡或付款超时" if stage == "timeout" else "订阅跳转未确认"
            _set_checkout_summary_status(
                account_id,
                "failed",
                operation_token=operation_token,
            )
            _set_upgrade_task_stage(task_id, stage, error=reason)
            return

        confirmation = _confirm_pro_after_checkout(page, log_fn)
        confirmed = bool(confirmation.get("confirmed"))
        persisted = _persist_pro_checkout_result(
            account_id,
            operation_token,
            phase2,
            confirmed=confirmed,
            target_plan=target_plan,
        )
        if not persisted:
            _set_checkout_summary_status(
                account_id,
                "failed",
                operation_token=operation_token,
            )
            _set_upgrade_task_stage(
                task_id,
                "failed",
                error="账号或升级租约已变化，拒绝回写本地套餐",
            )
        elif confirmed:
            _set_upgrade_task_stage(
                task_id,
                "success",
                confirmed_plan=target_plan,
            )
        else:
            _set_upgrade_task_stage(
                task_id,
                "confirmation_pending",
                error="付款跳转已完成，但未复核到 PRO 套餐；请稍后点登录重新检测",
                confirmed_plan=str(confirmation.get("plan_type") or ""),
            )
    except Exception as exc:
        safe_error = _redact_text(exc, str(direct_card or ""))
        if manual_confirmation_required:
            _set_checkout_summary_status(
                account_id,
                "manual_confirmation_pending",
                operation_token=operation_token,
            )
            _set_upgrade_task_stage(
                task_id,
                "manual_confirmation_pending",
                error=(
                    "自动流程异常，系统未判定升级失败："
                    f"{safe_error or '未知异常'}"
                ),
                manual_confirmation_required=True,
            )
        else:
            _set_checkout_summary_status(
                account_id,
                "failed",
                operation_token=operation_token,
            )
            _set_upgrade_task_stage(
                task_id,
                "failed",
                error=safe_error,
            )
    finally:
        with _PLAN_UPGRADE_LOCK:
            current_task = _PLAN_UPGRADE_TASKS.get(task_id)
            keep_page_open = bool(
                manual_confirmation_required
                and current_task
                and current_task.get("stage") == "manual_confirmation_pending"
            )
        if not keep_page_open:
            try:
                page.quit()
            except Exception:
                pass
        with _PLAN_UPGRADE_LOCK:
            task = _PLAN_UPGRADE_TASKS.get(task_id)
            if task:
                if keep_page_open:
                    task["page"] = page
                else:
                    task.pop("page", None)
                task.pop("operation_token", None)
                task.pop("direct_card", None)
        _release_plan_operation(account_id, operation_token)


def _start_upgrade_pro_claimed(
    account_id: int,
    body: GptPlanUpgradeProRequest,
    operation_token: str,
) -> dict:
    from platforms.chatgpt.gpt_pro_login import (
        _detect_current_plan,
        open_pro_checkout_phase1,
    )

    _refresh_plan_roxy_proxy(body.roxy_proxy_id)
    target_plan = body.target_plan if body.target_plan in {"pro", "pro_20x", "pro_5x"} else "pro"
    country, currency = _checkout_region_for_upgrade(body)
    with Session(engine) as session:
        upgrade_account = session.get(GptPlanAccountModel, int(account_id))
        manual_confirmation_required = bool(
            upgrade_account
            and _catalog_category(upgrade_account) == "refunded"
        )
        refunded_plan_before_login = str(
            getattr(upgrade_account, "plan_type", "") or ""
        )
    direct_card = _parse_card_text(body.checkout_card or "")
    if body.checkout_card and not direct_card:
        raise HTTPException(400, "手动银行卡文本无法解析")
    _close_previous_checkout_failure_page(account_id)
    try:
        from core.config_store import config_store

        ph_go_first = str(config_store.get("gpt_plan_ph_go_first", "") or "1") != "0"
        go_plan_name = str(config_store.get("gpt_plan_go_plan_name", "") or "chatgptgoplan")
        go_to_pro_wait = int(str(config_store.get("gpt_plan_go_to_pro_wait_seconds", "") or 60) or 60)
        pro5x_plan_name = str(config_store.get("gpt_plan_pro5x_plan_name", "") or "chatgptprolite")
    except Exception:
        ph_go_first = True
        go_plan_name = "chatgptgoplan"
        go_to_pro_wait = 60
        pro5x_plan_name = "chatgptprolite"

    captured: dict[str, Any] = {}

    def post_login_action(page: Any, login_result: Any) -> dict:
        captured["page"] = page
        log = getattr(login_result, "_log_fn", None) or (lambda message: print(_redact_text(message), flush=True))
        if body.pro_only:
            mode = "pro_only"
        # 菲律宾的 GO→PRO 中转只适用于 PRO20X。PRO5X 是独立的
        # $100 档位，必须直接创建 chatgptprolite checkout。
        elif target_plan == "pro_5x" or not (ph_go_first and country == "PH"):
            mode = "direct_pro"
        else:
            detected = _detect_current_plan(page, log) or {}
            captured["plan_detect"] = detected
            if detected.get("is_pro"):
                mode = "already_pro"
            elif detected.get("is_go") or detected.get("has_active") or not detected.get("ok"):
                mode = "pro_only"
            else:
                mode = "go_first"
        captured["mode"] = mode
        if mode == "already_pro":
            return {"ok": True, "already_pro": True}
        if mode == "pro_only":
            return {"ok": True, "pro_only": True}
        return open_pro_checkout_phase1(
            page,
            login_result,
            country=country,
            currency=currency,
            plan_name=(go_plan_name if mode == "go_first" else (pro5x_plan_name if target_plan == "pro_5x" else "chatgptpro")),
            card_loader=_fetch_plan_bank_cards,
        )

    result, login_public, safe_log = _execute_plan_login(
        account_id,
        body,
        post_login_action=post_login_action,
        force_keep_open=True,
        is_signup=True,
        record_detected_upgrade=False,
    )
    if manual_confirmation_required:
        # 升级登录发生在付款之前，此时远端很可能仍返回
        # Free。已退款目录展示的是原始会员类型，不能因这个
        # 付款前快照改成普通账号，否则人工确认“未升级”后
        # 将丢失再次升级入口。
        with Session(engine) as session:
            account_after_login = session.get(GptPlanAccountModel, int(account_id))
            if (
                account_after_login
                and _catalog_category(account_after_login) == "refunded"
                and refunded_plan_before_login
                and account_after_login.plan_type != refunded_plan_before_login
            ):
                account_after_login.plan_type = refunded_plan_before_login
                account_after_login.updated_at = _utcnow()
                session.add(account_after_login)
                session.commit()
    page = captured.get("page")

    def close_page() -> None:
        if page is not None:
            try:
                page.quit()
            except Exception:
                pass

    if not login_public.get("ok"):
        close_page()
        return {
            "ok": False,
            "stage": "login_failed",
            "error": login_public.get("error") or "登录失败",
        }
    action = getattr(result, "action_result", None) or {}
    if not action.get("ok"):
        # 登录成功不代表结账创建成功。过去这里无条件 quit，导致
        # 用户刚看到登录成功，窗口便消失且只能看到短暂错误 toast。
        # 此处不启动 phase2，也不把账号标记为已付款/待确认。
        browser_kept_open = page is not None and not body.headless
        if browser_kept_open:
            with _PLAN_UPGRADE_LOCK:
                _PLAN_CHECKOUT_FAILURE_PAGES[int(account_id)] = page
        else:
            close_page()
        error = _redact_text(
            action.get("error") or "创建 checkout 失败",
            str(getattr(result, "access_token", "") or ""),
            str(getattr(result, "session_token", "") or ""),
        )
        checkout_stage = str(action.get("stage") or "checkout")
        if checkout_stage not in {"session", "checkout", "checkout_navigation"}:
            checkout_stage = "checkout"
        http_status = action.get("status")
        if type(http_status) is not int or not 100 <= http_status <= 599:
            http_status = None
        safe_log(
            f"[GPT 套餐升级] account_id={account_id} target={target_plan} "
            f"stage={checkout_stage} HTTP={http_status} "
            f"browser_kept_open={browser_kept_open} error={error}"
        )
        return {
            "ok": False,
            "stage": "checkout_failed",
            "checkout_stage": checkout_stage,
            "http_status": http_status,
            "error": error,
            "browser_kept_open": browser_kept_open,
            "region": f"{country}/{currency}",
        }

    mode = str(captured.get("mode") or "direct_pro")
    if mode == "already_pro":
        if manual_confirmation_required:
            # 已退款账号即使被浏览器自动检测为 PRO，也不在
            # 此处自动移出已退款目录。先持久化待确认状态，人工
            # 确认接口才是唯一的成功/未升级裁定边界。
            _record_checkout_created(
                account_id,
                target=target_plan,
                checkout_session_id="",
                country=country,
                currency=currency,
                status="manual_confirmation_pending",
            )
            task_id = uuid.uuid4().hex[:16]
            now_iso = _iso_utc(_utcnow())
            task = {
                "task_id": task_id,
                "account_id": int(account_id),
                "stage": "manual_confirmation_pending",
                "stage_at": now_iso,
                "started_at": now_iso,
                "finished_at": now_iso,
                "auth_stage": "登录",
                "region": f"{country}/{currency}",
                "detected_plan": "pro",
                "target_plan": target_plan,
                "manual_confirmation_required": True,
                "error": "已检测到 PRO，请人工确认本次升级是否成功",
                # 只保存在进程内，不通过状态 API 返回。
                "page": page,
            }
            with _PLAN_UPGRADE_LOCK:
                _PLAN_UPGRADE_TASKS[task_id] = task
                _prune_upgrade_tasks_locked()
            _release_plan_operation(account_id, operation_token)
            return {"ok": True, **_public_upgrade_task(task)}
        close_page()
        now = _utcnow()
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, int(account_id))
            if account and _plan_operation_is_current(
                session,
                account_id,
                operation_token,
                "upgrade_pro",
            ):
                # 远端只返回 PRO 家族，不能把已有的具体档位（例如
                # PRO 20X）误改成操作人本次点击的另一个档位。
                current_plan = _normalize_plan_type(account.plan_type)
                if not (
                    _catalog_category(account) == "member"
                    and _canonical_member_plan(current_plan) == "pro"
                ):
                    account.plan_type = target_plan
                account.plan_checked_at = now
                account.updated_at = now
                session.add(account)
                session.commit()
        return {
            "ok": True,
            "already_pro": True,
            "stage": "success",
            "region": f"{country}/{currency}",
            "detected_plan": "pro",
        }
    if page is None:
        return {"ok": False, "stage": "internal_error", "error": "checkout 页面引用丢失"}

    pro_only = mode == "pro_only"
    go_then_pro = mode == "go_first"
    cards_count = int((action.get("card_picker") or {}).get("cards_count") or 0)
    if cards_count <= 0 and not direct_card and not pro_only:
        close_page()
        return {"ok": False, "stage": "no_cards", "error": "本地卡池没有可用卡"}

    _record_checkout_created(
        account_id,
            target=target_plan,
        checkout_session_id=str(action.get("checkout_session_id") or ""),
        country=country,
        currency=currency,
        status=(
            "manual_confirmation_pending"
            if manual_confirmation_required
            else "created"
        ),
    )
    task_id = uuid.uuid4().hex[:16]
    now_iso = _iso_utc(_utcnow())
    task = {
        "task_id": task_id,
        "account_id": int(account_id),
        "stage": "creating_pro_checkout" if pro_only else "awaiting_card_pick",
        "stage_at": now_iso,
        "started_at": now_iso,
        "auth_stage": "登录",
        "pay_url": str(action.get("pay_url") or ""),
        "checkout_session_id": str(action.get("checkout_session_id") or ""),
        "region": str(action.get("region") or f"{country}/{currency}"),
        "go_then_pro": go_then_pro,
        "pro_only": pro_only,
        "target_plan": target_plan,
        "detected_plan": str((captured.get("plan_detect") or {}).get("plan") or ""),
        "cards_count": cards_count,
        "pick_timeout": 300,
        "manual_confirmation_required": manual_confirmation_required,
    }
    if manual_confirmation_required:
        # 人工确认期间保留有头浏览器；它不在任何
        # API 响应中暴露，且人工确认后会尝试关闭。
        task["page"] = page
        task["operation_token"] = operation_token
    with _PLAN_UPGRADE_LOCK:
        _PLAN_UPGRADE_TASKS[task_id] = task

    threading.Thread(
        target=_upgrade_pro_worker,
        args=(task_id, account_id, operation_token, page),
        kwargs={
            "pick_timeout": 300,
            "auto_pick_seconds": max(0, min(int(body.auto_pick_seconds or 0), 300)),
            "direct_card": direct_card,
            "go_then_pro": go_then_pro,
            "country": country,
            "currency": currency,
            "go_to_pro_wait": 5 if pro_only else max(0, go_to_pro_wait),
            "pro_only": pro_only,
            "manual_confirmation_required": manual_confirmation_required,
            "target_plan": target_plan,
            "pro_plan_name": (pro5x_plan_name if target_plan == "pro_5x" else "chatgptpro"),
            "log_fn": safe_log,
        },
        daemon=True,
        name=f"gpt-plan-upgrade-{task_id}",
    ).start()
    return {"ok": True, **_public_upgrade_task(task)}


@router.post("/accounts/{account_id}/upgrade-pro")
def upgrade_pro(
    account_id: int,
    body: Optional[GptPlanUpgradeProRequest] = None,
):
    from core.gpt_plan_upgrade_browser_config import (
        UpgradeBrowserConfigError,
        apply_upgrade_browser_selection,
    )

    body = body or GptPlanUpgradeProRequest()
    with Session(engine) as session:
        _ensure_regular_upgrade_candidate(session, account_id)
    try:
        # 在任务开始前把服务端浏览器配置固化为不可变快照。
        apply_upgrade_browser_selection(body, db_engine=engine)
    except UpgradeBrowserConfigError as exc:
        raise HTTPException(exc.status_code, str(exc))
    operation_token = _claim_plan_operation(account_id, "upgrade_pro")
    handed_to_worker = False
    try:
        result = _start_upgrade_pro_claimed(account_id, body, operation_token)
        handed_to_worker = bool(result.get("task_id"))
        return result
    finally:
        if not handed_to_worker:
            _release_plan_operation(account_id, operation_token)


@router.get("/accounts/{account_id}/upgrade-pro/status/{task_id}")
def upgrade_pro_status(account_id: int, task_id: str):
    with _PLAN_UPGRADE_LOCK:
        task = _PLAN_UPGRADE_TASKS.get(str(task_id))
        if task and int(task.get("account_id") or 0) == int(account_id):
            return _public_upgrade_task(task)

    # 服务重启后内存任务会丢失，但已退款升级从
    # checkout 创建起就已持久化为待人工确认。轮询接口
    # 从 summary 恢复这一状态，避免前端对 404 无限重试。
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        summary = session.get(GptPlanAccountUpgradeModel, int(account_id))
        if (
            account
            and summary
            and _catalog_category(account) == "refunded"
            and str(summary.checkout_target or "") in {"pro", "pro_20x", "pro_5x"}
            and str(summary.checkout_status or "")
            in _REFUNDED_MANUAL_CONFIRMABLE_STATUSES
        ):
            return {
                "task_id": str(task_id),
                "account_id": int(account_id),
                "stage": "manual_confirmation_pending",
                "stage_at": _iso_utc(summary.updated_at),
                "started_at": _iso_utc(summary.checkout_created_at),
                "manual_confirmation_required": True,
                "target_plan": str(summary.checkout_target or ""),
                "error": "升级流程等待人工确认结果",
            }
    raise HTTPException(404, "升级任务不存在")


def _manual_upgrade_memory_task(
    account_id: int,
    task_id: Optional[str],
) -> tuple[str, Optional[dict]]:
    """Find an optional in-memory task without making it authoritative."""

    requested = str(task_id or "").strip()
    with _PLAN_UPGRADE_LOCK:
        if requested:
            task = _PLAN_UPGRADE_TASKS.get(requested)
            if task is None:
                # 服务重启/内存任务被清理后依然允许依据
                # 持久化 summary 确认。
                return requested, None
            if int(task.get("account_id") or 0) != int(account_id):
                raise HTTPException(409, "升级任务与当前账号不匹配")
            return requested, task

        matches = [
            task
            for task in _PLAN_UPGRADE_TASKS.values()
            if int(task.get("account_id") or 0) == int(account_id)
            and bool(task.get("manual_confirmation_required"))
        ]
        if not matches:
            return "", None
        task = max(matches, key=lambda item: str(item.get("started_at") or ""))
        return str(task.get("task_id") or ""), task


def _finish_manual_upgrade_memory_task(
    account_id: int,
    task_id: str,
    stage: str,
) -> None:
    page = None
    if task_id:
        _set_upgrade_task_stage(
            task_id,
            stage,
            error="",
            manual_confirmation_required=True,
        )
        with _PLAN_UPGRADE_LOCK:
            task = _PLAN_UPGRADE_TASKS.get(task_id)
            if task and int(task.get("account_id") or 0) == int(account_id):
                page = task.pop("page", None)
                task.pop("operation_token", None)
                task.pop("direct_card", None)
    if page is not None:
        try:
            page.quit()
        except Exception:
            pass


@router.post("/accounts/{account_id}/upgrade-pro/manual-confirm")
def manual_confirm_refunded_pro_upgrade(
    account_id: int,
    body: GptPlanUpgradeManualConfirmRequest,
):
    """人工裁定已退款账号的本次 PRO 重新升级结果。

    新任务以 ``manual_confirmation_pending`` 为持久化边界；
    历史版本对同类不确定结果写入的 failed/timeout/pro_failed
    也在这里交由人工收敛。内存 task 存在时用于防止
    phase2 仍运行时提前裁定，不存在时（例如服务重启）
    仍可依据 summary 完成。
    """

    resolved_task_id, memory_task = _manual_upgrade_memory_task(
        account_id,
        body.task_id,
    )
    if memory_task is not None:
        memory_stage = str(memory_task.get("stage") or "")
        if memory_stage not in {
            "manual_confirmation_pending",
            "manual_not_upgraded",
            "success",
            "confirmation_pending",
            "failed",
            "timeout",
            "pro_failed",
        }:
            raise HTTPException(409, "后台付款流程尚未进入人工确认阶段")

    now = _utcnow()
    idempotent = False
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        account = session.get(GptPlanAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        summary = session.get(GptPlanAccountUpgradeModel, int(account_id))
        if not summary or str(summary.checkout_target or "") not in {"pro", "pro_20x", "pro_5x"}:
            raise HTTPException(409, "未找到可人工确认的 PRO 升级记录")

        current_status = str(summary.checkout_status or "")
        if body.success:
            if (
                current_status == "success"
                and _catalog_category(account) == "member"
                and _canonical_member_plan(account.plan_type) == "pro"
            ):
                idempotent = True
            else:
                if current_status not in _REFUNDED_MANUAL_CONFIRMABLE_STATUSES:
                    raise HTTPException(409, "该 PRO 升级记录当前不等待人工确认")
                _ensure_refunded_plan_account(session, account)
                account.source_pool = ""
                account.source_account_id = None
                account.plan_type = "pro_5x" if str(summary.checkout_target or "") == "pro_5x" else "pro_20x"
                account.source_state = "pro"
                account.is_pro = True
                account.subscribed_at = now
                account.refund_status = ""
                account.catalog_category = "member"
                account.plan_checked_at = now
                account.source_synced_at = None
                account.last_used = now
                account.updated_at = now
                summary.checkout_status = "success"
                summary.plan_upgraded_at = now
                summary.updated_at = now
                session.add(account)
                session.add(summary)
        else:
            if (
                current_status == "manual_not_upgraded"
                and _catalog_category(account) == "refunded"
            ):
                idempotent = True
            else:
                if current_status not in _REFUNDED_MANUAL_CONFIRMABLE_STATUSES:
                    raise HTTPException(409, "该 PRO 升级记录当前不等待人工确认")
                if (
                    _catalog_category(account) != "refunded"
                    or str(account.refund_status or "").strip()
                    != "refunded_pending_credit"
                ):
                    raise HTTPException(409, "账号已不在“已退款未到账”状态")
                # “未升级”是中性人工结论，不写 failed/pro_failed，
                # 不将账号迁为当前 PRO，也不改历史升级时间。
                # 旧版升级登录可能曾把付款前的 Free 快照写入
                # plan_type；这里恢复“原始 PRO 已退款”目录身份，
                # 使账号仍能再次发起升级，不表示当前订阅生效。
                if _canonical_member_plan(account.plan_type) != "pro":
                    account.plan_type = "pro_5x" if str(summary.checkout_target or "") == "pro_5x" else "pro_20x"
                    account.updated_at = now
                    session.add(account)
                summary.checkout_status = "manual_not_upgraded"
                summary.updated_at = now
                session.add(summary)

        # 手工裁定是该次升级的终点。进程崩溃后遗留的
        # upgrade_pro 租约在同一事务中清理，不影响后续重试。
        session.execute(
            sa_delete(GptPlanAccountOperationLeaseModel)
            .where(GptPlanAccountOperationLeaseModel.account_id == int(account_id))
            .where(GptPlanAccountOperationLeaseModel.operation == "upgrade_pro")
        )
        session.commit()
        session.refresh(account)
        session.refresh(summary)
        public_account = _serialize_account(account, summary)

    final_stage = "success" if body.success else "manual_not_upgraded"
    _finish_manual_upgrade_memory_task(
        account_id,
        resolved_task_id,
        final_stage,
    )
    return {
        "ok": True,
        "account_id": int(account_id),
        "task_id": resolved_task_id,
        "success": bool(body.success),
        "stage": final_stage,
        "idempotent": idempotent,
        "confirmed_at": _iso_utc(now),
        "account": public_account,
    }


# -- BUSINESS hosted checkout --------------------------------------------------

@router.post("/accounts/{account_id}/business-checkout-link")
def business_checkout_link(
    account_id: int,
    body: GptPlanBusinessCheckoutRequest,
):
    from platforms.chatgpt.gpt_pro_login import (
        _build_direct_card,
        _build_team_checkout_js,
        _fill_stripe_hosted_checkout,
    )

    workspace_name = str(body.workspace_name or "").strip()
    if not workspace_name:
        raise HTTPException(400, "请填写工作区名称")
    coupon = _business_checkout_coupon(body.coupon)
    seat_type = str(body.seat_type or "default").strip().lower()
    if seat_type not in {"default", "prolite"}:
        raise HTTPException(400, "seat_type 只支持 default 或 prolite")
    seats = 2 if seat_type == "prolite" else max(2, int(body.seat_quantity or 2))
    country = str(body.country or "US").strip().upper()
    currency = str(body.currency or "USD").strip().upper()
    if len(country) != 2 or len(currency) != 3:
        raise HTTPException(400, "结账国家/币种格式不正确")
    if body.auto_submit and not body.auto_fill:
        raise HTTPException(400, "auto_submit=true 时必须同时开启 auto_fill")
    parsed_card = _parse_card_text(body.checkout_card or "")
    if body.checkout_card and not parsed_card:
        raise HTTPException(400, "手动银行卡文本无法解析")
    with Session(engine) as session:
        account = _ensure_regular_upgrade_candidate(session, account_id)
        account_email = account.email

    operation_token = _claim_plan_operation(account_id, "business_checkout")
    captured: dict[str, Any] = {}
    try:
        _refresh_plan_roxy_proxy(body.roxy_proxy_id)

        def post_login_action(page: Any, login_result: Any) -> dict:
            captured["page"] = page
            log = getattr(login_result, "_log_fn", None) or (lambda message: print(_redact_text(message), flush=True))
            try:
                checkout = page.run_js(
                    _build_team_checkout_js(
                        workspace_name,
                        coupon,
                        seats,
                        country,
                        currency,
                        seat_type=seat_type,
                    )
                ) or {}
            except Exception as exc:
                return {"ok": False, "error": _redact_text(exc)}
            if not checkout.get("ok") or not body.auto_fill or not checkout.get("url"):
                return checkout
            try:
                page.get(str(checkout.get("url")), timeout=60)
                time.sleep(1)
            except Exception as exc:
                checkout["fill"] = {"ok": False, "error": _redact_text(exc)}
                return checkout
            card = _build_direct_card(parsed_card) if parsed_card else None
            if card is None:
                cards = _fetch_plan_bank_cards(log)
                card = cards[0] if cards else None
            if card is None:
                checkout["fill"] = {"ok": False, "error": "本地卡池为空，未自动填卡"}
                return checkout
            checkout["fill"] = _fill_stripe_hosted_checkout(
                page,
                card,
                log_fn=log,
                email=account_email,
                auto_submit=bool(body.auto_submit),
            )
            checkout["filled_card"] = str(card.get("number_masked") or "")
            return checkout

        result, login_public, _ = _execute_plan_login(
            account_id,
            body,
            post_login_action=post_login_action,
            force_keep_open=bool(body.auto_fill),
        )
        checkout = getattr(result, "action_result", None) or {}
        if not login_public.get("ok"):
            return {
                "ok": False,
                "stage": "login_failed",
                "error": login_public.get("error") or "登录失败",
            }
        if not checkout.get("ok"):
            page = captured.get("page")
            if page is not None:
                try:
                    page.quit()
                except Exception:
                    pass
            return {
                "ok": False,
                "stage": "checkout_failed",
                "error": _redact_text(
                    checkout.get("error") or "生成 BUSINESS 支付链接失败",
                    body.checkout_card or "",
                ),
            }

        fill = checkout.get("fill") if isinstance(checkout.get("fill"), dict) else None
        submitted = bool(fill and fill.get("submitted"))
        _record_checkout_created(
            account_id,
            target="business",
            checkout_session_id=str(checkout.get("checkout_session_id") or ""),
            country=country,
            currency=currency,
            status="submitted" if submitted else "created",
            workspace_name=workspace_name,
            seat_type=seat_type,
            seat_quantity=seats,
        )
        fill_public = None
        if fill is not None:
            fill_public = {
                "ok": bool(fill.get("ok")),
                "submit_found": bool(fill.get("submit_found")),
                "submitted": submitted,
                "error": _redact_text(fill.get("error") or "", body.checkout_card or ""),
                "log": [
                    _redact_text(item, body.checkout_card or "")
                    for item in list(fill.get("log") or [])[:50]
                ],
            }
        # Creating a link (and even clicking its submit button) is not proof of
        # a paid Team plan. A later login must detect the real plan before the
        # account moves to the member/TEAM category.
        return {
            "ok": True,
            "url": str(checkout.get("url") or ""),
            "checkout_session_id": str(checkout.get("checkout_session_id") or ""),
            "auto_fill": bool(body.auto_fill),
            "auto_submit": bool(body.auto_submit),
            "fill": fill_public,
            "filled_card": _redact_text(
                checkout.get("filled_card") or "",
                body.checkout_card or "",
            ),
            "workspace_name": workspace_name,
            "seat_quantity": seats,
            "seat_type": seat_type,
            "country": country,
            "currency": currency,
            "coupon": coupon,
            "confirmation_required": True,
        }
    finally:
        _release_plan_operation(account_id, operation_token)


def _looks_like_html(value: str) -> bool:
    lower = str(value or "")[:2000].lower()
    return any(
        marker in lower
        for marker in ("<!doctype html", "<html", "<body", "<table", "<div", "<p>", "<br")
    )


def _html_preview(value: str, limit: int = 300) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", str(value or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    for source, target in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(source, target)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _graph_messages(
    mailbox: Any,
    mailbox_account: Any,
    limit: int,
    *,
    scan_metadata: Optional[dict[str, Any]] = None,
) -> list[dict]:
    rows = mailbox._fetch_graph_messages(mailbox_account, top=limit)
    if scan_metadata is not None:
        folder_coverage: dict[str, dict[str, Any]] = {}
        for folder_name in ("inbox", "junkemail"):
            folder_rows = [
                row
                for row in rows
                if str(row.get("folder") or "").lower() == folder_name
            ]
            received_values = [
                str(row.get("time") or "")
                for row in folder_rows
                if row.get("time")
            ]
            folder_coverage[folder_name] = {
                "complete": len(folder_rows) < max(int(limit or 0), 1),
                "oldest_received_at": min(received_values)
                if received_values
                else "",
            }
        scan_metadata["folder_coverage"] = folder_coverage
    messages = []
    for row in rows:
        body = str(row.get("body") or "")
        preview = str(row.get("preview") or "") or _html_preview(body)
        messages.append(
            {
                "id": str(row.get("id") or ""),
                "from": str(row.get("from") or ""),
                "subject": str(row.get("subject") or ""),
                "preview": preview,
                "body": body,
                "is_html": _looks_like_html(body),
                "time": str(row.get("time") or ""),
                "message_id": str(row.get("message_id") or ""),
                # Graph's receivedDateTime is a server-side delivery time,
                # unlike the sender-controlled RFC Date header.
                "received_at": str(row.get("time") or ""),
                "received_time_trusted": bool(row.get("time")),
                "received_at_source": "graph_receivedDateTime",
                "identity_scheme": "graph_message_id",
                "identity_version": 1,
                "folder": str(row.get("folder") or ""),
            }
        )
    # Inbox/Junk are queried separately.  A move racing those requests can
    # expose the same ImmutableId in both responses; de-duplicate before the
    # global limit so the duplicate cannot evict another genuinely new mail.
    deduplicated: list[dict] = []
    seen_message_ids: set[str] = set()
    for message in messages:
        message_id = str(message.get("id") or "")
        if message_id and message_id in seen_message_ids:
            continue
        if message_id:
            seen_message_ids.add(message_id)
        deduplicated.append(message)
    deduplicated.sort(key=lambda row: row.get("time", ""), reverse=True)
    return deduplicated[:limit]


def _decode_mail_part(part: Any) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return str(raw or "")
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="ignore")
    except Exception:
        return payload.decode("utf-8", errors="ignore")


_IMAP_UIDVALIDITY_RE = re.compile(r"UIDVALIDITY\s+(\d+)", re.IGNORECASE)
_IMAP_INTERNALDATE_RE = re.compile(
    r'INTERNALDATE\s+"([^"]+)"',
    re.IGNORECASE,
)


def _imap_metadata_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="ignore")
    if isinstance(value, (list, tuple)):
        return " ".join(_imap_metadata_text(item) for item in value)
    return str(value or "")


def _imap_selected_uidvalidity(connection: Any, folder: str) -> str:
    candidates: list[Any] = []
    try:
        candidates.append(connection.response("UIDVALIDITY"))
    except Exception:
        pass
    try:
        candidates.append(connection.status(folder, "(UIDVALIDITY)"))
    except Exception:
        pass
    for candidate in candidates:
        text = _imap_metadata_text(candidate)
        matched = _IMAP_UIDVALIDITY_RE.search(text)
        if matched:
            return str(matched.group(1))
        # imaplib.response("UIDVALIDITY") commonly returns
        # ('UIDVALIDITY', [b'123']) rather than repeating the label in data.
        pieces = re.findall(r"\b\d+\b", text)
        if pieces and "UIDVALIDITY" in text.upper():
            return str(pieces[-1])
    return ""


def _imap_internaldate(response: Any) -> str:
    # A FETCH tuple is ``(metadata, raw_message)``.  Never scan the raw body
    # for INTERNALDATE: apart from needless memory work, a body could contain
    # text that merely looks like IMAP protocol metadata.
    metadata: list[Any] = []
    for item in response or []:
        if isinstance(item, tuple):
            if item:
                metadata.append(item[0])
        elif isinstance(item, (bytes, str)):
            metadata.append(item)
    text = _imap_metadata_text(metadata)
    matched = _IMAP_INTERNALDATE_RE.search(text)
    if not matched:
        return ""
    try:
        parsed = parsedate_to_datetime(matched.group(1))
    except Exception:
        return ""
    if parsed is None:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _imap_messages(
    mailbox: Any,
    mailbox_account: Any,
    limit: int,
    folders: list[str],
    *,
    scan_metadata: Optional[dict[str, Any]] = None,
) -> list[dict]:
    connection = mailbox._open_imap(mailbox_account)
    messages: list[dict] = []
    folder_errors: list[str] = []
    try:
        for folder in folders:
            try:
                status, _ = connection.select(folder, readonly=True)
                if status != "OK":
                    raise RuntimeError(f"SELECT 返回 {status}")
                uidvalidity = _imap_selected_uidvalidity(connection, folder)
                if not uidvalidity:
                    raise RuntimeError("服务器未返回 UIDVALIDITY")
                if scan_metadata is not None:
                    scan_metadata.update({
                        "identity_scheme": "imap_uidvalidity",
                        "identity_version": 3,
                        "uidvalidity_verified": True,
                    })
                status, data = connection.uid("search", None, "ALL")
                if status != "OK":
                    raise RuntimeError(f"SEARCH 返回 {status}")
                ids = data[0].split() if data and data[0] else []
                selected_ids = ids[-min(max(limit, 1), 1000):]
                folder_start_index = len(messages)
                for uid in reversed(selected_ids):
                    status, response = connection.uid(
                        "fetch",
                        uid,
                        "(RFC822 INTERNALDATE)",
                    )
                    if status != "OK":
                        # Keep manual mailbox viewing available on unusual
                        # servers, but mark its sender Date as untrusted so it
                        # cannot create a scheduled unread notification.
                        status, response = connection.uid(
                            "fetch",
                            uid,
                            "(RFC822)",
                        )
                    if status != "OK":
                        raise RuntimeError(
                            f"UID {uid!r} FETCH 返回 {status}"
                        )
                    raw = next(
                        (
                            item[1]
                            for item in response or []
                            if isinstance(item, tuple) and len(item) > 1 and item[1]
                        ),
                        None,
                    )
                    if not raw:
                        raise RuntimeError(f"UID {uid!r} FETCH 响应缺少正文")
                    message = message_from_bytes(raw, policy=email_default_policy)
                    plain: list[str] = []
                    html: list[str] = []
                    parts = message.walk() if message.is_multipart() else [message]
                    for part in parts:
                        content_type = str(part.get_content_type() or "").lower()
                        if content_type == "text/plain":
                            plain.append(_decode_mail_part(part))
                        elif content_type == "text/html":
                            html.append(_decode_mail_part(part))
                    body_html = "\n".join(html).strip()
                    body_text = "\n".join(plain).strip()
                    body = body_html or body_text
                    sender_name, sender_address = parseaddr(str(message.get("From", "")))
                    uid_text = uid.decode(errors="ignore") if isinstance(uid, bytes) else str(uid)
                    legacy_folder_uid = f"imap:{folder}:{uid_text}"
                    internaldate = _imap_internaldate(response)
                    if not internaldate:
                        raise RuntimeError(
                            f"UID {uid_text} 缺少可验证的 INTERNALDATE"
                        )
                    # UID is scoped by folder *and* UIDVALIDITY.  A mailbox
                    # rebuild may legally reuse all old UIDs, so folder+UID
                    # alone is not a durable identity.
                    stable_id = (
                        f"imap:{quote(str(folder), safe='')}:{uidvalidity}:"
                        f"{uid_text}"
                    )
                    identity_scheme = "imap_uidvalidity"
                    identity_version = 3
                    messages.append(
                        {
                            "id": stable_id,
                            "legacy_id": uid_text,
                            "legacy_ids": [legacy_folder_uid, uid_text],
                            "from": sender_address or sender_name,
                            "subject": mailbox._decode_header_value(
                                str(message.get("Subject", ""))
                            ),
                            "message_id": str(message.get("Message-ID", "") or "").strip(),
                            "preview": _html_preview(body_text or body),
                            "body": body,
                            "is_html": bool(body_html) or _looks_like_html(body),
                            "time": str(message.get("Date", "") or ""),
                            "received_at": internaldate,
                            "received_time_trusted": bool(internaldate),
                            "received_at_source": "imap_INTERNALDATE",
                            "identity_scheme": identity_scheme,
                            "identity_version": identity_version,
                            "folder": folder,
                        }
                    )
                if scan_metadata is not None:
                    folder_rows = messages[folder_start_index:]
                    received_values = [
                        str(row.get("received_at") or "")
                        for row in folder_rows
                        if row.get("received_at")
                    ]
                    scan_metadata.setdefault("folder_coverage", {})[
                        str(folder)
                    ] = {
                        "complete": len(selected_ids) >= len(ids),
                        "oldest_received_at": min(received_values)
                        if received_values
                        else "",
                    }
            except Exception as exc:
                folder_errors.append(f"{folder}: {exc}")
    finally:
        try:
            connection.logout()
        except Exception:
            pass
    if folder_errors:
        raise RuntimeError(
            "IMAP 文件夹取件失败: " + "; ".join(folder_errors)
        )
    def _sort_time(row: dict[str, Any]) -> float:
        text = str(
            row.get("received_at")
            if row.get("received_time_trusted")
            else row.get("time")
            or ""
        ).strip()
        if not text:
            return 0.0
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except Exception:
            try:
                parsed = parsedate_to_datetime(text)
            except Exception:
                return 0.0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    # Each folder was fetched newest-first, but concatenating folders before
    # truncation let an old INBOX block a newer Junk message.  Sort the merged
    # result first and only then apply the requested global limit.
    messages.sort(key=_sort_time, reverse=True)
    return messages[:limit]


def _fetch_recent_messages(
    snapshot: dict,
    *,
    limit: int,
    folder: str = "",
    return_metadata: bool = False,
    fallback_imap_on_graph_error: bool = False,
) -> tuple:
    from platforms.chatgpt.gpt_pro_login import build_mailbox_for_account

    def _result(method: str, rows: list[dict], metadata: dict[str, Any]):
        from services.chatgpt_mail_common import (
            MAIL_WATERMARK_OVERLAP,
            parse_message_time,
        )

        metadata = dict(metadata or {})
        metadata["requested_limit"] = max(int(limit or 0), 1)
        metadata["full_mailbox_scope"] = not str(folder or "").strip()
        previous_watermark = parse_message_time(
            snapshot.get("last_mail_check_at")
        )
        coverage_cutoff = (
            previous_watermark - MAIL_WATERMARK_OVERLAP
            if previous_watermark is not None
            else None
        )
        trusted_received_times = [
            parse_message_time(
                row.get("received_at") or row.get("time")
            )
            for row in rows
            if isinstance(row, dict)
            and row.get("received_time_trusted") is True
        ]
        trusted_received_times = [
            value for value in trusted_received_times if value is not None
        ]
        reaches_previous_watermark = bool(
            coverage_cutoff is not None
            and trusted_received_times
            and min(trusted_received_times) <= coverage_cutoff
        )
        folder_coverage = metadata.get("folder_coverage")
        if coverage_cutoff is None:
            provider_coverage_complete = True
        elif isinstance(folder_coverage, dict) and folder_coverage:
            provider_coverage_complete = all(
                bool(detail.get("complete"))
                or (
                    parse_message_time(detail.get("oldest_received_at"))
                    is not None
                    and parse_message_time(detail.get("oldest_received_at"))
                    <= coverage_cutoff
                )
                for detail in folder_coverage.values()
                if isinstance(detail, dict)
            )
        elif method == "gmail":
            # Gmail searches an explicit recent-message window before filtering
            # by alias. A short filtered result is not proof that every folder
            # was covered back to the prior watermark. Keep that watermark
            # until the adapter supplies folder-level coverage evidence.
            provider_coverage_complete = False
        else:
            provider_coverage_complete = bool(
                len(rows) < max(int(limit or 0), 1)
                or reaches_previous_watermark
            )
        # A non-paginated fetch can advance the global mailbox watermark only
        # when it covered all configured folders and returned fewer than the
        # requested cap.  Folder-specific or cap-saturated manual views are
        # lifecycle evidence, but not proof that no unseen mail was skipped.
        metadata["watermark_coverage_complete"] = bool(
            metadata["full_mailbox_scope"]
            and all(
                row.get("received_time_trusted") is True
                for row in rows
                if isinstance(row, dict)
            )
            and provider_coverage_complete
        )
        if return_metadata:
            return method, rows, metadata
        return method, rows

    mailbox, mailbox_account = build_mailbox_for_account(snapshot, proxy="")
    mail_provider = _normalize_mail_provider(snapshot.get("mail_provider"))
    if mail_provider in {"icloud", "gmail"}:
        rows = list(mailbox.list_recent(mailbox_account, limit=limit) or [])
        # Older/custom mailbox implementations may still return only a sender
        # Date.  Keep those rows visible in the manual inbox, but never treat
        # that untrusted timestamp as evidence of a newly received message.
        for row in rows:
            if isinstance(row, dict) and "received_time_trusted" not in row:
                row["received_time_trusted"] = False
        metadata = getattr(mailbox, "_last_list_recent_metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        return _result("gmail" if mail_provider == "gmail" else "qqmail", rows, dict(metadata))

    mail_type = str(snapshot.get("mail_access_type") or "").strip().lower()
    graph_error = ""
    if mail_type == "graph" or (
        not mail_type and snapshot.get("client_id") and snapshot.get("refresh_token")
    ):
        try:
            graph_metadata = {
                "identity_scheme": "graph_message_id",
                "identity_version": 1,
                "immutable_id_requested": True,
            }
            return _result(
                "graph",
                _graph_messages(
                    mailbox,
                    mailbox_account,
                    limit,
                    scan_metadata=graph_metadata,
                ),
                graph_metadata,
            )
        except Exception as exc:
            graph_error = str(exc)
            if mail_type == "graph" and not fallback_imap_on_graph_error:
                raise

    if mail_type in {"", "imap_pop"} or graph_error:
        folders = [folder] if folder else ["INBOX", "Junk"]
        metadata: dict[str, Any] = {}
        rows = _imap_messages(
            mailbox,
            mailbox_account,
            limit,
            folders,
            scan_metadata=metadata,
        )
        return _result("imap", rows, metadata)
    raise RuntimeError("无可用取件方式")


@router.post("/accounts/{account_id}/fetch-mail")
def fetch_account_mail(
    account_id: int,
    body: Optional[GptPlanFetchMailRequest] = None,
):
    body = body or GptPlanFetchMailRequest()
    limit = max(1, min(int(body.limit or 10), 50))
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, account_id)
        if not account:
            raise HTTPException(404, "账号不存在")
        snapshot = _account_mail_snapshot(account)
        previous_successful_watermark = _aware_utc(
            account.last_mail_check_at
        )

    fetch_started_at = _utcnow()
    try:
        fetch_result = _fetch_recent_messages(
            snapshot,
            limit=limit,
            folder=str(body.folder or "").strip(),
            return_metadata=True,
        )
        if len(fetch_result) >= 3:
            method, messages, scan_metadata = fetch_result[:3]
        else:
            method, messages = fetch_result
            scan_metadata = {}
    except Exception as exc:
        safe_error = _redact_text(
            exc,
            snapshot["password"],
            snapshot["client_id"],
            snapshot["refresh_token"],
        )
        now = _utcnow()
        with Session(engine) as session:
            account = session.get(GptPlanAccountModel, account_id)
            if account:
                account.last_mail_fetch_at = now
                account.last_mail_error = safe_error
                account.updated_at = now
                session.add(account)
                session.commit()
        raise HTTPException(400, f"取件失败: {safe_error or '未知错误'}")

    # The mailbox dialog is also authoritative lifecycle evidence.  Reuse the
    # same Plan-only classifier as the scheduled monitor so a refund notice
    # that the user can already see atomically moves the local row to 已退款.
    # This deliberately never reads or writes a legacy GPT PRO source row.
    from services.gpt_plan_mail_monitor import reconcile_fetched_messages

    lifecycle = reconcile_fetched_messages(
        int(account_id),
        list(messages or []),
        fetched_at=fetch_started_at,
        previous_successful_watermark=previous_successful_watermark,
        scan_metadata=scan_metadata,
        advance_successful_watermark=bool(
            scan_metadata.get("watermark_coverage_complete", False)
        ),
        database_engine=engine,
    )
    return {
        "email": snapshot["email"],
        "mail_access_type": snapshot["mail_access_type"] or method,
        "method": method,
        "count": len(messages),
        "messages": messages,
        "refund_detected": bool(lifecycle.get("refund_detected")),
        "refund_transition": bool(lifecycle.get("refund_transition")),
        "refund_status": str(lifecycle.get("refund_status") or ""),
        "refund_detected_at": str(
            lifecycle.get("refund_detected_at") or ""
        ),
        "account_type": str(lifecycle.get("account_type") or ""),
    }


_CARD_BRAND_RE = re.compile(
    r"(?:Visa|Master\s?card|Amex|American\s?Express|Discover|JCB|Union\s?Pay|Maestro)"
    r"\s*[-–—•·.*\s]{0,6}(\d{4})\b",
    re.IGNORECASE,
)
_CARD_ENDING_RE = re.compile(r"ending in\s*(\d{4})\b", re.IGNORECASE)


def _extract_plan_card_last4(messages: list[dict[str, Any]]) -> Optional[str]:
    """Return the latest receipt/subscription card suffix from fetched mail."""
    def suffix(blob: str) -> Optional[str]:
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", blob))
        matched = _CARD_BRAND_RE.search(text) or _CARD_ENDING_RE.search(text)
        return matched.group(1) if matched else None

    ordered = sorted(
        messages,
        key=lambda item: str(
            item.get("time") or item.get("date") or item.get("received") or ""
        ),
        reverse=True,
    )
    strong = re.compile(r"新套餐|订阅|receipt|your new plan|subscription", re.IGNORECASE)
    fallback = re.compile(
        r"付款方式|套餐|receipt|invoice|credit note|payment method|subscription|refund|退款",
        re.IGNORECASE,
    )
    for context in (strong, fallback):
        for message in ordered:
            blob = (
                str(message.get("subject") or "")
                + "\n"
                + str(message.get("body") or message.get("preview") or "")
            )
            if context.search(blob):
                found = suffix(blob)
                if found:
                    return found
    return None


def _apply_plan_payment_account_by_last4(
    session: Session,
    summary: GptPlanAccountUpgradeModel,
    last4: str,
) -> str:
    suffix = str(last4 or "").strip()[-4:]
    cards = [
        card
        for card in session.exec(select(GptPlanCardModel)).all()
        if suffix and str(card.number or "").endswith(suffix)
    ]
    payment_ids = {
        int(card.payment_account_id or 0)
        for card in cards
        if int(card.payment_account_id or 0) > 0
    }
    if len(payment_ids) != 1:
        return ""
    payment = session.get(GptPlanPaymentAccountModel, next(iter(payment_ids)))
    if payment is None:
        return ""
    summary.payment_account_id = int(payment.id or 0)
    summary.payment_account_name = str(payment.name or "")
    summary.payment_account_type = str(payment.account_type or "")
    return str(payment.name or "")


def _backfill_plan_card_last4(account_id: int, *, limit: int) -> dict[str, Any]:
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if account is None:
            raise HTTPException(404, "账号不存在")
        snapshot = _account_mail_snapshot(account)
        email = str(account.email or "")
    try:
        _method, messages = _fetch_recent_messages(snapshot, limit=limit)
    except Exception as exc:
        safe_error = _redact_text(
            exc,
            snapshot.get("password") or "",
            snapshot.get("client_id") or "",
            snapshot.get("refresh_token") or "",
        )
        raise HTTPException(400, f"取件失败: {safe_error or '未知错误'}") from exc
    last4 = _extract_plan_card_last4(messages)
    if not last4:
        return {
            "ok": False,
            "account_id": int(account_id),
            "email": email,
            "last4": None,
            "message": "邮件里没解析到卡尾号",
        }
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if account is None:
            raise HTTPException(404, "账号不存在")
        now = _utcnow()
        account.payment_card_last4 = last4
        account.last_used = now
        account.updated_at = now
        summary = _upsert_upgrade_summary(session, int(account_id))
        summary.payment_card_last4 = last4
        summary.updated_at = now
        payment_name = _apply_plan_payment_account_by_last4(
            session,
            summary,
            last4,
        )
        session.add(account)
        session.add(summary)
        session.commit()
    return {
        "ok": True,
        "account_id": int(account_id),
        "email": email,
        "last4": last4,
        "payment_account_name": payment_name,
        "message": f"已回填卡尾号 ****{last4}",
    }


def _backfill_all_plan_card_last4(limit_per_account: int) -> dict[str, Any]:
    with Session(engine) as session:
        rows = session.exec(
            select(GptPlanAccountModel).order_by(col(GptPlanAccountModel.id))
        ).all()
        summaries = _upgrade_summary_map(
            session,
            [int(row.id or 0) for row in rows if row.id is not None],
        )
        target_ids = [
            int(row.id or 0)
            for row in rows
            if row.id is not None
            and (
                bool(row.is_pro)
                or _canonical_member_plan(row.plan_type) == "pro"
            )
            and not str(row.payment_card_last4 or "").strip()
            and not str(
                getattr(summaries.get(int(row.id or 0)), "payment_card_last4", "")
                or ""
            ).strip()
        ]
    details: list[dict[str, Any]] = []
    filled = not_found = errors = 0
    for target_id in target_ids:
        try:
            result = _backfill_plan_card_last4(
                target_id,
                limit=int(limit_per_account),
            )
            details.append(result)
            if bool(result.get("ok")):
                filled += 1
            else:
                not_found += 1
        except Exception as exc:
            errors += 1
            detail = getattr(exc, "detail", None) if isinstance(exc, HTTPException) else exc
            details.append({
                "account_id": target_id,
                "status": "error",
                "error": _sanitize_member_task_text(detail),
            })
    return {
        "ok": errors == 0,
        "scanned": len(target_ids),
        "filled": filled,
        "not_found": not_found,
        "errors": errors,
        "details": details,
    }


@router.post("/accounts/{account_id}/backfill-card-last4-from-mail")
def backfill_one_plan_card_last4_from_mail(
    account_id: int,
    limit: int = Query(50, ge=1, le=50),
):
    return _backfill_plan_card_last4(int(account_id), limit=int(limit))


# -- 会员账号本地邮件监控 --------------------------------------------

def _plan_mail_owner_payload(owner: _PlanMailStateOwner) -> tuple[list[dict], list[dict]]:
    return (
        _safe_json_list(getattr(owner.row, "pending_alerts_json", "[]")),
        _safe_json_list(getattr(owner.row, "pending_inbox_json", "[]")),
    )


def _plan_mail_check_meta(owner: _PlanMailStateOwner) -> tuple[str, str]:
    return (
        _iso_utc(getattr(owner.row, "last_mail_check_at", None)),
        _redact_text(
            getattr(owner.row, "last_mail_check_error", "") or "",
            str(getattr(owner.row, "password", "") or ""),
            str(getattr(owner.row, "client_id", "") or ""),
            str(getattr(owner.row, "refresh_token", "") or ""),
        )[:300],
    )


def _require_plan_business_child_mail_owner(
    session: Session,
    account_id: int,
    child_id: int,
) -> tuple[GptPlanAccountModel, int, _PlanMailStateOwner]:
    """Resolve an active child through its exact Plans mother facade.

    A child id by itself is not sufficient authority: integer ids can be
    copied from another expanded mother.  The source BUSINESS id, normalized
    email, active pool membership, and the child's current parent pointer must
    all agree before its unread queue can be viewed or mutated.
    """
    if isinstance(child_id, bool) or int(child_id) <= 0:
        raise HTTPException(404, "该母号下不存在这个受管子号")
    binding, _member_source = _business_child_facade_binding(
        int(account_id),
        require_action=False,
    )
    membership = session.exec(
        select(GptBusinessChildMembershipModel)
        .where(
            GptBusinessChildMembershipModel.business_account_id
            == int(binding.source_account_id)
        )
        .where(GptBusinessChildMembershipModel.pro_account_id == int(child_id))
        .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
        .where(func.lower(GptBusinessChildMembershipModel.source) == "pool")
        .order_by(col(GptBusinessChildMembershipModel.id).desc())
    ).first()
    child = session.get(GptPlanAccountModel, int(child_id))
    membership_email = _normalized_email(
        getattr(membership, "email", "") if membership is not None else ""
    )
    if (
        membership is None
        or child is None
        or int(getattr(child, "business_parent_id", None) or 0)
        != int(binding.source_account_id)
        or not membership_email
        or _normalized_email(child.email) != membership_email
    ):
        # Deliberately do not disclose whether this child belongs elsewhere.
        raise HTTPException(404, "该母号下不存在这个受管子号")
    return (
        child,
        int(membership.id or 0),
        _resolve_plan_mail_state_owner(session, child),
    )


def _dismiss_plan_mail_items(
    owner: _PlanMailStateOwner,
    *,
    field_name: Literal["pending_alerts_json", "pending_inbox_json"],
    item_ids: Optional[list[str]],
) -> tuple[int, int]:
    pending = _safe_json_list(getattr(owner.row, field_name, "[]"))
    if not item_ids:
        removed = len(pending)
        pending = []
    else:
        remove_ids = {str(value) for value in item_ids}
        remaining = [
            item for item in pending
            if str(item.get("id") or "") not in remove_ids
        ]
        removed = len(pending) - len(remaining)
        pending = remaining
    setattr(owner.row, field_name, json.dumps(pending, ensure_ascii=False))
    owner.row.updated_at = _utcnow()
    return removed, len(pending)


@router.get("/alerts/summary")
def alerts_summary():
    """返回会员、已退款账号及活动 BUSINESS 子号的未读汇总。

    ``id`` 始终是持有邮件队列的 GPT 套餐账号 id。BUSINESS 子号额外
    返回母号 facade id，前端不能绕过母号归属直接操作其队列。
    """
    with Session(engine) as session:
        accounts = list(session.exec(
            select(GptPlanAccountModel).order_by(col(GptPlanAccountModel.id))
        ).all())
        child_ids = {
            int(account.id)
            for account in accounts
            if account.id is not None
            and getattr(account, "business_parent_id", None) is not None
        }
        parent_source_ids = {
            int(account.business_parent_id)
            for account in accounts
            if account.id in child_ids
            and account.business_parent_id is not None
        }
        parent_plans = {
            int(account.source_account_id): account
            for account in accounts
            if str(account.source_pool or "").strip().lower() == "gpt_business"
            and account.source_account_id is not None
            and int(account.source_account_id) in parent_source_ids
            and _catalog_category(account) == "member"
        }
        memberships = list(session.exec(
            select(GptBusinessChildMembershipModel)
            .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
            .where(func.lower(GptBusinessChildMembershipModel.source) == "pool")
            .order_by(col(GptBusinessChildMembershipModel.id).desc())
        ).all()) if child_ids else []
        membership_by_child: dict[tuple[int, int], GptBusinessChildMembershipModel] = {}
        for membership in memberships:
            if membership.pro_account_id is None:
                continue
            key = (
                int(membership.business_account_id),
                int(membership.pro_account_id),
            )
            membership_by_child.setdefault(key, membership)

        items: list[dict[str, Any]] = []
        total_unread = 0
        total_inbox = 0
        for account in accounts:
            category = _catalog_category(account)
            target: dict[str, Any]
            parent_source_id = getattr(account, "business_parent_id", None)
            if parent_source_id is not None:
                child_id = int(account.id or 0)
                parent_source_id = int(parent_source_id)
                parent_plan = parent_plans.get(parent_source_id)
                membership = membership_by_child.get((parent_source_id, child_id))
                if (
                    parent_plan is None
                    or membership is None
                    or _normalized_email(membership.email)
                    != _normalized_email(account.email)
                ):
                    continue
                target = {
                    "target_kind": "business_child",
                    "parent_id": int(parent_plan.id or 0),
                    "parent_email": str(parent_plan.email or ""),
                    "child_id": child_id,
                    "membership_id": int(membership.id or 0),
                    "account_type": "business_child",
                }
            elif category in {"member", "refunded"}:
                target = {
                    "target_kind": "account",
                    "parent_id": None,
                    "parent_email": "",
                    "child_id": None,
                    "membership_id": None,
                    "account_type": category,
                }
            else:
                continue
            owner = _resolve_plan_mail_state_owner(session, account)
            alerts, inbox = _plan_mail_owner_payload(owner)
            alert_count = len(alerts)
            inbox_count = len(inbox)
            total_unread += alert_count
            total_inbox += inbox_count
            if not alert_count and not inbox_count:
                continue
            latest = alerts[0] if alerts else inbox[0]
            items.append({
                "id": int(account.id or 0),
                "email": str(account.email or ""),
                "plan_type": _normalize_plan_type(account.plan_type),
                "member_plan": (
                    _canonical_member_plan(account.plan_type)
                    if target["account_type"] == "member" else ""
                ),
                "unread_count": alert_count,
                "inbox_unread_count": inbox_count,
                "latest_subject": str(latest.get("subject") or ""),
                "latest_time": str(latest.get("time") or ""),
                **target,
            })
        return {
            "total_unread": total_unread,
            "account_count": sum(
                1 for item in items if int(item["unread_count"]) > 0
            ),
            "total_inbox_unread": total_inbox,
            "inbox_account_count": sum(
                1 for item in items if int(item["inbox_unread_count"]) > 0
            ),
            "items": items,
        }


@router.get("/accounts/{account_id}/alerts")
def list_account_alerts(account_id: int):
    with Session(engine) as session:
        account, owner = _require_plan_member_for_mail(session, account_id)
        alerts, _inbox = _plan_mail_owner_payload(owner)
        checked_at, check_error = _plan_mail_check_meta(owner)
        return {
            "email": str(account.email or ""),
            "unread_count": len(alerts),
            "alerts": alerts,
            "last_mail_check_at": checked_at,
            "last_mail_check_error": check_error,
        }


@router.post("/accounts/{account_id}/alerts/dismiss")
def dismiss_account_alerts(
    account_id: int,
    body: Optional[GptPlanDismissAlertsRequest] = None,
):
    body = body or GptPlanDismissAlertsRequest()
    with Session(engine) as session:
        _account, owner = _require_plan_member_for_mail(session, account_id)
        removed, remaining = _dismiss_plan_mail_items(
            owner,
            field_name="pending_alerts_json",
            item_ids=body.alert_ids,
        )
        session.add(owner.row)
        session.commit()
        return {"ok": True, "removed": removed, "remaining": remaining}


@router.get("/accounts/{account_id}/inbox")
def list_account_inbox(account_id: int):
    with Session(engine) as session:
        account, owner = _require_plan_member_for_mail(session, account_id)
        _alerts, inbox = _plan_mail_owner_payload(owner)
        checked_at, check_error = _plan_mail_check_meta(owner)
        return {
            "email": str(account.email or ""),
            "inbox_unread_count": len(inbox),
            "items": inbox,
            "last_mail_check_at": checked_at,
            "last_mail_check_error": check_error,
        }


@router.post("/accounts/{account_id}/inbox/dismiss")
def dismiss_account_inbox(
    account_id: int,
    body: Optional[GptPlanDismissInboxRequest] = None,
):
    body = body or GptPlanDismissInboxRequest()
    with Session(engine) as session:
        _account, owner = _require_plan_member_for_mail(session, account_id)
        removed, remaining = _dismiss_plan_mail_items(
            owner,
            field_name="pending_inbox_json",
            item_ids=body.inbox_ids,
        )
        session.add(owner.row)
        session.commit()
        return {"ok": True, "removed": removed, "remaining": remaining}


@router.get("/accounts/{account_id}/business-children/{child_id}/alerts")
def list_business_child_alerts(account_id: int, child_id: int):
    with Session(engine) as session:
        child, membership_id, owner = _require_plan_business_child_mail_owner(
            session, account_id, child_id,
        )
        alerts, _inbox = _plan_mail_owner_payload(owner)
        checked_at, check_error = _plan_mail_check_meta(owner)
        return {
            "account_id": int(account_id),
            "child_id": int(child_id),
            "membership_id": membership_id,
            "email": str(child.email or ""),
            "unread_count": len(alerts),
            "alerts": alerts,
            "last_mail_check_at": checked_at,
            "last_mail_check_error": check_error,
        }


@router.post("/accounts/{account_id}/business-children/{child_id}/alerts/dismiss")
def dismiss_business_child_alerts(
    account_id: int,
    child_id: int,
    body: Optional[GptPlanDismissAlertsRequest] = None,
):
    body = body or GptPlanDismissAlertsRequest()
    with Session(engine) as session:
        _child, membership_id, owner = _require_plan_business_child_mail_owner(
            session, account_id, child_id,
        )
        removed, remaining = _dismiss_plan_mail_items(
            owner,
            field_name="pending_alerts_json",
            item_ids=body.alert_ids,
        )
        session.add(owner.row)
        session.commit()
        return {
            "ok": True,
            "membership_id": membership_id,
            "removed": removed,
            "remaining": remaining,
        }


@router.get("/accounts/{account_id}/business-children/{child_id}/inbox")
def list_business_child_inbox(account_id: int, child_id: int):
    with Session(engine) as session:
        child, membership_id, owner = _require_plan_business_child_mail_owner(
            session, account_id, child_id,
        )
        _alerts, inbox = _plan_mail_owner_payload(owner)
        checked_at, check_error = _plan_mail_check_meta(owner)
        return {
            "account_id": int(account_id),
            "child_id": int(child_id),
            "membership_id": membership_id,
            "email": str(child.email or ""),
            "inbox_unread_count": len(inbox),
            "items": inbox,
            "last_mail_check_at": checked_at,
            "last_mail_check_error": check_error,
        }


@router.post("/accounts/{account_id}/business-children/{child_id}/inbox/dismiss")
def dismiss_business_child_inbox(
    account_id: int,
    child_id: int,
    body: Optional[GptPlanDismissInboxRequest] = None,
):
    body = body or GptPlanDismissInboxRequest()
    with Session(engine) as session:
        _child, membership_id, owner = _require_plan_business_child_mail_owner(
            session, account_id, child_id,
        )
        removed, remaining = _dismiss_plan_mail_items(
            owner,
            field_name="pending_inbox_json",
            item_ids=body.inbox_ids,
        )
        session.add(owner.row)
        session.commit()
        return {
            "ok": True,
            "membership_id": membership_id,
            "removed": removed,
            "remaining": remaining,
        }


@router.post("/accounts/{account_id}/check-mail-now")
def check_account_mail_now(account_id: int):
    """立即使用套餐本地监控器检查一个会员账号。"""
    with Session(engine) as session:
        _require_plan_member_for_mail(session, account_id)

    from services.gpt_plan_mail_monitor import run_monitor_round

    result = run_monitor_round(account_id=int(account_id))

    public = dict(result or {})
    details = public.get("details")
    if not isinstance(details, list):
        details = []
        public["details"] = details
    new_inbox = sum(
        max(0, int(detail.get("new_inbox") or 0))
        for detail in details
        if isinstance(detail, dict)
    )
    public.setdefault("scanned", 0)
    public.setdefault("success", 0)
    public.setdefault("failed", 0)
    public.setdefault("total_new_alerts", 0)
    public.setdefault("total_new_inbox", new_inbox)
    public.setdefault("total_new_messages", new_inbox)
    raw_errors = public.get("errors")
    public["errors"] = [
        {
            "email": str(item.get("email") or ""),
            "error": _redact_text(item.get("error") or "")[:300],
        }
        for item in (raw_errors if isinstance(raw_errors, list) else [])
        if isinstance(item, dict)
    ]
    public["plan_account_id"] = int(account_id)
    public["mail_monitor_owner"] = "plan"
    return public
