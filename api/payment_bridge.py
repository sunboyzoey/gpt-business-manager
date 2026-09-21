"""对接外部支付系统的账号拉取与回调接口。"""

from __future__ import annotations

import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, select

from core.config_store import config_store
from core.db import AccountModel, engine

router = APIRouter(tags=["payment-bridge"])

_bridge_lock = threading.Lock()
_LOCK_STATUSES = {"reserved"}
_SUCCESS_STATUSES = {"success"}
_GROK_UNPAID_STATUSES = {"registered", "trial"}
_GROK_PAYMENT_STATUS_ALIASES = {
    "paid": "success",
    "success": "success",
    "failed": "failed",
    "failure": "failed",
    "skipped": "skipped",
    "skip": "skipped",
    "link_expired": "link_expired",
    "expired": "link_expired",
    "invalid_link": "link_expired",
}
_GROK_COMPLETE_STATUS_ALIASES = {
    "completed": "completed",
    "complete": "completed",
    "success": "completed",
    "done": "completed",
    "finished": "completed",
    "已完成": "completed",
}
_GROK_SYNC_STATUS_ALIASES = {
    "pending": "pending",
    "pending_sync": "pending",
    "wait_sync": "pending",
    "waiting": "pending",
    "待同步": "pending",
    "syncing": "syncing",
    "running": "syncing",
    "in_progress": "syncing",
    "同步中": "syncing",
    "synced": "synced",
    "success": "synced",
    "done": "synced",
    "同步成功": "synced",
    "已同步": "synced",
    "failed": "failed",
    "failure": "failed",
    "error": "failed",
    "同步失败": "failed",
    "skipped": "skipped",
    "skip": "skipped",
    "跳过": "skipped",
}
_REQUIRED_COOKIE_KEYS = {
    "__Secure-next-auth.session-token",
    "__Host-next-auth.csrf-token",
    "oai-did",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _parse_json_text(raw: str | None) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _bridge_meta(extra: dict) -> dict:
    meta = extra.get("payment_bridge")
    return meta if isinstance(meta, dict) else {}


def _grok_sync_meta(extra: dict) -> dict:
    meta = extra.get("grok_sync")
    return meta if isinstance(meta, dict) else {}


def _normalize_grok_sync_status(status: str, *, default: str = "") -> str:
    clean = str(status or "").strip().lower()
    if not clean:
        return default
    return _GROK_SYNC_STATUS_ALIASES.get(clean, "")


def _grok_sync_status_label(status: str) -> str:
    return {
        "pending": "待同步",
        "syncing": "同步中",
        "synced": "已同步",
        "failed": "同步失败",
        "skipped": "已跳过",
    }.get(status, status)


def _get_grok_sync_status(model: AccountModel) -> str:
    meta = _grok_sync_meta(model.get_extra())
    status = _normalize_grok_sync_status(str(meta.get("status") or ""), default="")
    if status:
        return status
    return "pending" if model.platform == "grok" and model.status == "completed" else ""


def _set_grok_sync_state(
    model: AccountModel,
    *,
    status: str,
    client_id: str = "",
    note: str = "",
    remote_id: str = "",
    synced_at: str = "",
) -> None:
    normalized = _normalize_grok_sync_status(status)
    if not normalized:
        raise ValueError("sync status 必须为 pending/syncing/synced/failed/skipped")
    extra = model.get_extra()
    meta = _grok_sync_meta(extra)
    meta["status"] = normalized
    meta["status_label"] = _grok_sync_status_label(normalized)
    meta["updated_at"] = _utcnow_iso()
    if client_id:
        meta["client_id"] = client_id
    if note:
        meta["note"] = note
    if remote_id:
        meta["remote_id"] = remote_id
    if normalized == "pending":
        meta["pending_at"] = _utcnow_iso()
    if normalized == "syncing":
        meta["syncing_at"] = _utcnow_iso()
    if normalized == "synced":
        meta["synced_at"] = synced_at or _utcnow_iso()
    if normalized == "failed":
        meta["failed_at"] = _utcnow_iso()
    if normalized == "skipped":
        meta["skipped_at"] = _utcnow_iso()
    extra["grok_sync"] = meta
    model.set_extra(extra)
    model.updated_at = _utcnow()


def _mail_provider_matches(extra: dict, account_type: str, email: str = "") -> bool:
    provider = str(extra.get("mail_provider") or "").strip().lower()
    if account_type == "outlook":
        return provider == "outlook"
    if account_type == "tempapi":
        return provider in {"cfworker", "tempapi"}
    if account_type == "icloud":
        if provider in {"icloud", "icloud_hme", "icloud-hme"}:
            return True
        if provider != "qqmail":
            return False
        clean_email = str(email or "").strip().lower()
        return bool(extra.get("icloud_hme_anonymous_id")) or clean_email.endswith("@icloud.com")
    return False


def _load_cookie_payload(extra: dict) -> dict:
    cookies = extra.get("cookies")
    if isinstance(cookies, dict):
        return {str(k): str(v) for k, v in cookies.items() if str(k).strip()}
    if isinstance(cookies, str):
        parsed = _parse_json_text(cookies)
        if parsed:
            return {str(k): str(v) for k, v in parsed.items() if str(k).strip()}

    cookie_file = str(extra.get("cookie_file") or "").strip()
    if not cookie_file:
        return {}

    try:
        file_data = _parse_json_text(Path(cookie_file).read_text(encoding="utf-8"))
    except Exception:
        return {}

    file_cookies = file_data.get("cookies")
    if not isinstance(file_cookies, dict):
        return {}
    return {str(k): str(v) for k, v in file_cookies.items() if str(k).strip()}


def _cookie_url(domain: str, path: str = "/") -> str:
    host = str(domain or "").strip().lstrip(".") or "grok.com"
    clean_path = str(path or "/").strip() or "/"
    if not clean_path.startswith("/"):
        clean_path = f"/{clean_path}"
    return f"https://{host}{clean_path}"


def _normalize_cookie_expires(value) -> int:
    if value in (None, "", "null"):
        return -1
    try:
        expires = int(float(value))
    except (TypeError, ValueError):
        return -1
    return expires if expires > 0 else -1


def _normalize_browser_cookies(cookie_list: list, cookies: dict) -> list[dict]:
    raw_items = cookie_list
    if not raw_items and cookies:
        raw_items = [
            {
                "name": name,
                "value": value,
                "domain": ".grok.com",
                "path": "/",
                "secure": True,
                "httpOnly": name in {"sso", "sso-rw"},
            }
            for name, value in cookies.items()
        ]

    normalized = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        domain = str(raw.get("domain") or ".grok.com").strip() or ".grok.com"
        path = str(raw.get("path") or "/").strip() or "/"
        expires = _normalize_cookie_expires(raw.get("expires", raw.get("expirationDate")))
        secure_value = raw.get("secure")
        http_only_value = raw.get("httpOnly")
        item = {
            "name": name,
            "value": str(raw.get("value") or ""),
            "domain": domain,
            "path": path,
            "expires": expires,
            "expirationDate": None if expires < 0 else expires,
            "secure": True if secure_value is None else bool(secure_value),
            "httpOnly": False if http_only_value is None else bool(http_only_value),
            "url": _cookie_url(domain, path),
        }
        same_site = str(raw.get("sameSite") or raw.get("same_site") or "").strip()
        if same_site:
            item["sameSite"] = same_site
        normalized.append(item)
    return normalized


def _load_grok_cookie_export(extra: dict) -> dict:
    cookie_file = str(extra.get("cookie_file") or "").strip()
    file_data = {}
    if cookie_file:
        try:
            file_data = _parse_json_text(Path(cookie_file).read_text(encoding="utf-8"))
        except Exception:
            file_data = {}

    file_cookies = file_data.get("cookies")
    if isinstance(file_cookies, dict):
        cookies = {str(k): str(v) for k, v in file_cookies.items() if str(k).strip()}
    else:
        cookies = _load_cookie_payload(extra)

    cookie_list = file_data.get("cookie_list")
    if not isinstance(cookie_list, list):
        cookie_list = []

    cookie_header = str(file_data.get("cookie_header") or "").strip()
    if not cookie_header and cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())

    browser_cookies = _normalize_browser_cookies(cookie_list, cookies)

    return {
        "cookies": cookies,
        "cookie_list": cookie_list,
        "browser_cookies": browser_cookies,
        "cookie_header": cookie_header,
        "saved_at": str(file_data.get("saved_at") or ""),
    }


def _normalize_fetch_account(model: AccountModel) -> Optional[dict]:
    extra = model.get_extra()
    cookies = _load_cookie_payload(extra)
    cashier_url = str(model.cashier_url or extra.get("cashier_url") or "").strip()
    session_token = str(
        extra.get("session_token")
        or cookies.get("__Secure-next-auth.session-token")
        or ""
    ).strip()

    if session_token and "__Secure-next-auth.session-token" not in cookies:
        cookies["__Secure-next-auth.session-token"] = session_token

    if not session_token or not _REQUIRED_COOKIE_KEYS.issubset(set(cookies.keys())):
        return None

    return {
        "email": model.email,
        "password": model.password,
        "session_token": session_token,
        "cookies": cookies,
        "cashier_url": cashier_url,
        "plus_payment_url": cashier_url,
        "plus_payment_link": cashier_url,
    }


def _is_fetchable(model: AccountModel, account_type: str) -> bool:
    if model.platform != "chatgpt":
        return False
    if model.status in {"subscribed", "completed", "expired", "invalid"}:
        return False

    extra = model.get_extra()
    if not _mail_provider_matches(extra, account_type, model.email):
        return False

    meta = _bridge_meta(extra)
    bridge_status = str(meta.get("status") or "").strip().lower()
    if bridge_status in _SUCCESS_STATUSES:
        return False

    return _normalize_fetch_account(model) is not None


def _set_bridge_state(
    model: AccountModel,
    *,
    status: str,
    account_type: str,
    client_id: str = "",
    note: str = "",
) -> str:
    extra = model.get_extra()
    meta = _bridge_meta(extra)
    reservation_id = ""
    meta.update(
        {
            "status": status,
            "type": account_type,
            "updated_at": _utcnow_iso(),
        }
    )
    if client_id:
        meta["client_id"] = client_id
    if status == "reserved":
        meta["reserved_at"] = _utcnow_iso()
        reservation_id = secrets.token_hex(8)
        meta["reservation_id"] = reservation_id
    else:
        meta.pop("reservation_id", None)
        meta.pop("reserved_at", None)
    if note:
        meta["note"] = note
    extra["payment_bridge"] = meta
    model.set_extra(extra)
    model.updated_at = _utcnow()
    return reservation_id


def _clear_bridge_lock(model: AccountModel, *, status: str, note: str = "") -> None:
    extra = model.get_extra()
    meta = _bridge_meta(extra)
    meta["status"] = status
    meta["updated_at"] = _utcnow_iso()
    meta.pop("reservation_id", None)
    meta.pop("reserved_at", None)
    if note:
        meta["note"] = note
    extra["payment_bridge"] = meta
    model.set_extra(extra)
    model.updated_at = _utcnow()


def _status_label(platform: str, status: str) -> str:
    if platform == "grok" and status == "subscribed":
        return "已支付"
    if platform == "grok" and status == "completed":
        return "已完成"
    return {
        "registered": "已注册",
        "trial": "试用中",
        "subscribed": "已订阅",
        "completed": "已完成",
        "expired": "已过期",
        "invalid": "已失效",
    }.get(status, status)


def _set_cashier_url(model: AccountModel, cashier_url: str) -> None:
    value = str(cashier_url or "").strip()
    extra = model.get_extra()
    extra["cashier_url"] = value
    model.cashier_url = value
    model.set_extra(extra)
    model.updated_at = _utcnow()


def _annotate_bridge_meta(model: AccountModel, **fields) -> None:
    extra = model.get_extra()
    meta = _bridge_meta(extra)
    for key, value in fields.items():
        if value is None or value == "":
            continue
        meta[key] = value
    meta["updated_at"] = _utcnow_iso()
    extra["payment_bridge"] = meta
    model.set_extra(extra)
    model.updated_at = _utcnow()


def _normalize_grok_payment_account(model: AccountModel, *, include_sso: bool = False) -> dict:
    extra = model.get_extra()
    meta = _bridge_meta(extra)
    item = {
        "id": model.id,
        "platform": model.platform,
        "email": model.email,
        "password": model.password,
        "status": model.status,
        "status_label": _status_label("grok", model.status),
        "payment_status": "unpaid",
        "cashier_url": str(model.cashier_url or extra.get("cashier_url") or "").strip(),
        "reservation_id": str(meta.get("reservation_id") or ""),
        "reserved_at": str(meta.get("reserved_at") or ""),
        "created_at": model.created_at.isoformat() if model.created_at else "",
        "updated_at": model.updated_at.isoformat() if model.updated_at else "",
    }
    if include_sso:
        item["sso"] = str(extra.get("sso") or "")
        item["sso_rw"] = str(extra.get("sso_rw") or "")
    return item


def _normalize_grok_paid_account(
    model: AccountModel,
    *,
    include_cookies: bool = True,
    include_cookie_list: bool = False,
    include_sso: bool = True,
) -> dict:
    extra = model.get_extra()
    cookie_export = _load_grok_cookie_export(extra)
    sync_status = _get_grok_sync_status(model)
    sync_meta = _grok_sync_meta(extra)
    item = {
        "id": model.id,
        "platform": model.platform,
        "email": model.email,
        "password": model.password,
        "status": model.status,
        "status_label": _status_label("grok", model.status),
        "payment_status": "paid",
        "sync_status": sync_status,
        "sync_status_label": _grok_sync_status_label(sync_status),
        "sync": {
            "status": sync_status,
            "status_label": _grok_sync_status_label(sync_status),
            "client_id": str(sync_meta.get("client_id") or ""),
            "remote_id": str(sync_meta.get("remote_id") or ""),
            "note": str(sync_meta.get("note") or ""),
            "pending_at": str(sync_meta.get("pending_at") or ""),
            "syncing_at": str(sync_meta.get("syncing_at") or ""),
            "synced_at": str(sync_meta.get("synced_at") or ""),
            "failed_at": str(sync_meta.get("failed_at") or ""),
            "skipped_at": str(sync_meta.get("skipped_at") or ""),
            "updated_at": str(sync_meta.get("updated_at") or ""),
        },
        "cashier_url": str(model.cashier_url or extra.get("cashier_url") or "").strip(),
        "created_at": model.created_at.isoformat() if model.created_at else "",
        "updated_at": model.updated_at.isoformat() if model.updated_at else "",
    }
    if include_sso:
        item["sso"] = str(extra.get("sso") or "")
        item["sso_rw"] = str(extra.get("sso_rw") or "")
    if include_cookies:
        item["cookies"] = cookie_export["cookies"]
        item["cookie_header"] = cookie_export["cookie_header"]
        item["browser_cookies"] = cookie_export["browser_cookies"]
        item["cookie_count"] = len(cookie_export["cookies"])
        item["cookie_saved_at"] = cookie_export["saved_at"]
        if include_cookie_list:
            item["cookie_list"] = cookie_export["cookie_list"]
    return item


def _is_grok_payment_fetchable(model: AccountModel) -> bool:
    if model.platform != "grok":
        return False
    if model.status not in _GROK_UNPAID_STATUSES:
        return False

    extra = model.get_extra()
    cashier_url = str(model.cashier_url or extra.get("cashier_url") or "").strip()
    if not cashier_url:
        return False

    meta = _bridge_meta(extra)
    bridge_status = str(meta.get("status") or "").strip().lower()
    if bridge_status in _LOCK_STATUSES or bridge_status in _SUCCESS_STATUSES:
        return False

    return True


def _is_grok_payment_reserved_for_client(model: AccountModel, client_id: str) -> bool:
    clean_client_id = str(client_id or "").strip()
    if not clean_client_id:
        return False
    if model.platform != "grok":
        return False
    if model.status not in _GROK_UNPAID_STATUSES:
        return False

    extra = model.get_extra()
    cashier_url = str(model.cashier_url or extra.get("cashier_url") or "").strip()
    if not cashier_url:
        return False

    meta = _bridge_meta(extra)
    return (
        str(meta.get("status") or "").strip().lower() == "reserved"
        and str(meta.get("type") or "").strip() == "grok_payment"
        and str(meta.get("client_id") or "").strip() == clean_client_id
    )


def _sync_grok_bridge_success_status(model: AccountModel) -> bool:
    if model.platform != "grok":
        return False
    if model.status in {"subscribed", "completed"}:
        return False
    meta = _bridge_meta(model.get_extra())
    if str(meta.get("status") or "").strip().lower() != "success":
        return False
    model.status = "subscribed"
    model.updated_at = _utcnow()
    return True


def _refresh_grok_payment_link(
    email: str,
    sso: str,
    sso_rw: str,
    *,
    max_attempts: int = 5,
) -> dict:
    clean_sso = str(sso or "").strip()
    if not clean_sso:
        return {"attempted": False, "ok": False, "error": "缺少 SSO cookie，无法刷新支付链接"}

    try:
        max_attempts = max(1, min(10, int(max_attempts or 5)))
    except (TypeError, ValueError):
        max_attempts = 5

    try:
        from platforms.grok.plugin import _resolve_payment_proxy
        from platforms.grok.protocol import GrokProtocolRegister

        config = config_store.get_all()
        fallback_proxy = str(config_store.get("default_proxy", "") or "").strip() or None
        payment_proxy, payment_proxy_label = _resolve_payment_proxy(
            config,
            fallback_proxy=fallback_proxy,
            log_fn=print,
        )
        reg = GrokProtocolRegister(
            proxy=fallback_proxy,
            payment_proxy=payment_proxy,
            payment_proxy_label=payment_proxy_label,
            log_fn=print,
        )
        url = reg.get_payment_link(
            str(email or "").strip(),
            clean_sso,
            str(sso_rw or "").strip(),
            max_attempts=max_attempts,
        )
        if url:
            return {
                "attempted": True,
                "ok": True,
                "cashier_url": url,
                "max_attempts": max_attempts,
            }
        error = str(getattr(reg, "last_payment_error", "") or "刷新支付链接失败").strip()
        return {
            "attempted": True,
            "ok": False,
            "error": error,
            "max_attempts": max_attempts,
        }
    except Exception as exc:
        return {
            "attempted": True,
            "ok": False,
            "error": str(exc),
            "max_attempts": max_attempts,
        }


def _bridge_token() -> str:
    return str(config_store.get("payment_bridge_admin_token", "") or "").strip()


def require_bridge_admin_token(
    admin_token: str = Query("", alias="adminToken"),
    x_admin_token: str = Header("", alias="X-Admin-Token"),
) -> None:
    expected = _bridge_token()
    if not expected:
        raise HTTPException(status_code=503, detail="payment bridge adminToken 未配置")
    supplied = str(x_admin_token or admin_token or "").strip()
    if not supplied or supplied != expected:
        raise HTTPException(status_code=401, detail="adminToken 无效")


@router.get("/fetch-accounts")
def fetch_accounts(
    type: str = Query(..., pattern="^(outlook|tempapi|icloud)$"),
    domain: str = Query(""),
    clientId: str = Query(""),
    reserve: bool = Query(True),
    _: None = Depends(require_bridge_admin_token),
):
    account_type = str(type or "").strip().lower()
    domain_filter = str(domain or "").strip().lower().lstrip("@")
    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "chatgpt")
                .order_by(AccountModel.created_at.asc())
            ).all()

            accounts = []
            for row in rows:
                if domain_filter and not row.email.lower().endswith(f".{domain_filter}") and not row.email.lower().endswith(f"@{domain_filter}"):
                    continue
                if not _is_fetchable(row, account_type):
                    continue
                normalized = _normalize_fetch_account(row)
                if not normalized:
                    continue
                accounts.append(normalized)

    return {"success": True, "accounts": accounts, "total": len(accounts)}


class AccountCallbackRequest(BaseModel):
    email: str
    status: str


class ReleaseAccountsRequest(BaseModel):
    clientId: str


class GrokPaymentCallbackRequest(BaseModel):
    id: Optional[int] = None
    email: str = ""
    clientId: str = ""
    reservation_id: str = ""
    status: str
    message: str = ""
    payment_reference: str = ""
    paid_at: str = ""
    clear_payment_url: bool = False
    refresh_payment_url: Optional[bool] = None
    refresh_attempts: int = 5


class GrokReleasePaymentAccountsRequest(BaseModel):
    clientId: str
    reservation_ids: list[str] = []


class GrokSyncCallbackRequest(BaseModel):
    id: Optional[int] = None
    email: str = ""
    clientId: str = ""
    status: str
    message: str = ""
    remote_id: str = ""
    synced_at: str = ""


class GrokCompleteCallbackRequest(BaseModel):
    id: Optional[int] = None
    email: str = ""
    clientId: str = ""
    status: str = "completed"
    message: str = ""
    remote_id: str = ""
    completed_at: str = ""


@router.post("/release-accounts")
def release_accounts(
    body: ReleaseAccountsRequest,
    _: None = Depends(require_bridge_admin_token),
):
    client_id = str(body.clientId or "").strip()
    if not client_id:
        raise HTTPException(status_code=400, detail="clientId 不能为空")

    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "chatgpt")
            ).all()

            released = []
            for row in rows:
                extra = row.get_extra()
                meta = _bridge_meta(extra)
                if meta.get("status") != "reserved":
                    continue
                if str(meta.get("client_id") or "").strip() != client_id:
                    continue
                _clear_bridge_lock(row, status="released", note=f"released by client {client_id}")
                session.add(row)
                released.append(row.email)

            if released:
                session.commit()

    return {"success": True, "released": released, "total": len(released)}


@router.get("/grok/fetch-payment-accounts")
def fetch_grok_payment_accounts(
    limit: int = Query(10, ge=1, le=100),
    clientId: str = Query(""),
    includeSso: bool = Query(False),
    _: None = Depends(require_bridge_admin_token),
):
    """领取 Grok 已注册未支付且已有支付链接的账号，领取后会加 reserved 锁。"""
    client_id = str(clientId or "").strip()
    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "grok")
                .order_by(AccountModel.created_at.asc())
            ).all()

            accounts = []
            skipped_missing_payment_url = 0
            resumed_reserved = 0
            repaired_success_status = 0
            for row in rows:
                if _sync_grok_bridge_success_status(row):
                    session.add(row)
                    repaired_success_status += 1
                    continue
                if row.status in _GROK_UNPAID_STATUSES:
                    extra = row.get_extra()
                    if not str(row.cashier_url or extra.get("cashier_url") or "").strip():
                        skipped_missing_payment_url += 1
                if _is_grok_payment_reserved_for_client(row, client_id):
                    accounts.append(_normalize_grok_payment_account(row, include_sso=includeSso))
                    resumed_reserved += 1
                    if len(accounts) >= limit:
                        break
                    continue
                if not _is_grok_payment_fetchable(row):
                    continue
                _set_bridge_state(
                    row,
                    status="reserved",
                    account_type="grok_payment",
                    client_id=client_id,
                    note="fetched for grok payment",
                )
                session.add(row)
                accounts.append(_normalize_grok_payment_account(row, include_sso=includeSso))
                if len(accounts) >= limit:
                    break

            if accounts:
                session.commit()
            elif repaired_success_status:
                session.commit()

    return {
        "success": True,
        "accounts": accounts,
        "total": len(accounts),
        "resumed_reserved": resumed_reserved,
        "repaired_success_status": repaired_success_status,
        "skipped_missing_payment_url": skipped_missing_payment_url,
    }


@router.get("/grok/paid-accounts")
def fetch_grok_paid_accounts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    email: str = Query(""),
    domain: str = Query(""),
    includeCompleted: bool = Query(False),
    syncStatus: str = Query(""),
    includeCookies: bool = Query(True),
    includeCookieList: bool = Query(True),
    includeSso: bool = Query(True),
    _: None = Depends(require_bridge_admin_token),
):
    """获取 Grok 已支付账号列表，可返回 Cookie。默认不包含已完成账号。"""
    email_filter = str(email or "").strip().lower()
    domain_filter = str(domain or "").strip().lower().lstrip("@")
    sync_filter = _normalize_grok_sync_status(syncStatus, default="")
    if syncStatus and not sync_filter:
        raise HTTPException(status_code=400, detail="syncStatus 必须为 pending/syncing/synced/failed/skipped")
    repaired_success_status = 0

    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "grok")
                .order_by(AccountModel.updated_at.desc())
            ).all()

            matched = []
            for row in rows:
                if _sync_grok_bridge_success_status(row):
                    session.add(row)
                    repaired_success_status += 1
                allowed_statuses = {"subscribed", "completed"} if includeCompleted else {"subscribed"}
                if row.status not in allowed_statuses:
                    continue
                row_email = str(row.email or "").lower()
                if email_filter and email_filter not in row_email:
                    continue
                if domain_filter and not row_email.endswith(f"@{domain_filter}"):
                    continue
                if sync_filter and row.status != "completed":
                    continue
                if sync_filter and _get_grok_sync_status(row) != sync_filter:
                    continue
                matched.append(row)

            if repaired_success_status:
                session.commit()

            total = len(matched)
            page_rows = matched[offset: offset + limit]
            accounts = [
                _normalize_grok_paid_account(
                    row,
                    include_cookies=includeCookies,
                    include_cookie_list=includeCookieList,
                    include_sso=includeSso,
                )
                for row in page_rows
            ]

    return {
        "success": True,
        "accounts": accounts,
        "total": total,
        "limit": limit,
        "offset": offset,
        "repaired_success_status": repaired_success_status,
    }


@router.get("/grok/completed-accounts")
def fetch_grok_completed_accounts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    email: str = Query(""),
    domain: str = Query(""),
    syncStatus: str = Query(""),
    includeCookies: bool = Query(True),
    includeCookieList: bool = Query(True),
    includeSso: bool = Query(True),
    _: None = Depends(require_bridge_admin_token),
):
    """获取 Grok 已完成账号列表，可返回 Cookie。"""
    email_filter = str(email or "").strip().lower()
    domain_filter = str(domain or "").strip().lower().lstrip("@")
    sync_filter = _normalize_grok_sync_status(syncStatus, default="")
    if syncStatus and not sync_filter:
        raise HTTPException(status_code=400, detail="syncStatus 必须为 pending/syncing/synced/failed/skipped")

    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "grok")
                .where(AccountModel.status == "completed")
                .order_by(AccountModel.updated_at.desc())
            ).all()

            matched = []
            for row in rows:
                row_email = str(row.email or "").lower()
                if email_filter and email_filter not in row_email:
                    continue
                if domain_filter and not row_email.endswith(f"@{domain_filter}"):
                    continue
                if sync_filter and _get_grok_sync_status(row) != sync_filter:
                    continue
                matched.append(row)

            total = len(matched)
            page_rows = matched[offset: offset + limit]
            accounts = [
                _normalize_grok_paid_account(
                    row,
                    include_cookies=includeCookies,
                    include_cookie_list=includeCookieList,
                    include_sso=includeSso,
                )
                for row in page_rows
            ]

    return {
        "success": True,
        "accounts": accounts,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/grok/release-payment-accounts")
def release_grok_payment_accounts(
    body: GrokReleasePaymentAccountsRequest,
    _: None = Depends(require_bridge_admin_token),
):
    client_id = str(body.clientId or "").strip()
    reservation_ids = {str(item or "").strip() for item in (body.reservation_ids or []) if str(item or "").strip()}
    if not client_id:
        raise HTTPException(status_code=400, detail="clientId 不能为空")

    with _bridge_lock:
        with Session(engine) as session:
            rows = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "grok")
            ).all()

            released = []
            for row in rows:
                extra = row.get_extra()
                meta = _bridge_meta(extra)
                if meta.get("status") != "reserved":
                    continue
                if str(meta.get("type") or "") != "grok_payment":
                    continue
                if str(meta.get("client_id") or "").strip() != client_id:
                    continue
                reservation_id = str(meta.get("reservation_id") or "").strip()
                if reservation_ids and reservation_id not in reservation_ids:
                    continue
                _clear_bridge_lock(row, status="released", note=f"released by client {client_id}")
                session.add(row)
                released.append(
                    {
                        "id": row.id,
                        "email": row.email,
                        "reservation_id": reservation_id,
                    }
                )

            if released:
                session.commit()

    return {"success": True, "released": released, "total": len(released)}


@router.post("/grok/payment-callback")
def grok_payment_callback(
    body: GrokPaymentCallbackRequest,
    _: None = Depends(require_bridge_admin_token),
):
    status = _GROK_PAYMENT_STATUS_ALIASES.get(str(body.status or "").strip().lower(), "")
    if not status:
        raise HTTPException(
            status_code=400,
            detail="status 必须为 success/paid/failed/skipped/link_expired",
        )

    email = str(body.email or "").strip().lower()
    reservation_id = str(body.reservation_id or "").strip()
    client_id = str(body.clientId or "").strip()
    note = str(body.message or "").strip()
    refresh_result: dict = {"attempted": False}

    with _bridge_lock:
        with Session(engine) as session:
            query = select(AccountModel).where(AccountModel.platform == "grok")
            if body.id is not None:
                query = query.where(AccountModel.id == body.id)
            elif email:
                query = query.where(AccountModel.email == email)
            else:
                raise HTTPException(status_code=400, detail="id 或 email 必须提供一个")

            account = session.exec(query).first()
            if not account:
                raise HTTPException(status_code=404, detail="账号不存在")

            meta = _bridge_meta(account.get_extra())
            current_reservation_id = str(meta.get("reservation_id") or "").strip()
            if reservation_id and current_reservation_id and reservation_id != current_reservation_id:
                raise HTTPException(status_code=409, detail="reservation_id 不匹配")

            if status == "success":
                _clear_bridge_lock(account, status="success", note=note or "grok payment success")
                account.status = "subscribed"
                _annotate_bridge_meta(
                    account,
                    client_id=client_id,
                    payment_reference=str(body.payment_reference or "").strip(),
                    paid_at=str(body.paid_at or "").strip() or _utcnow_iso(),
                    last_callback_status=status,
                )
            elif status == "link_expired":
                _clear_bridge_lock(account, status="link_expired", note=note or "grok payment link expired")
                _set_cashier_url(account, "")
                if body.refresh_payment_url is not False:
                    extra = account.get_extra()
                    refresh_result = _refresh_grok_payment_link(
                        account.email,
                        str(extra.get("sso") or ""),
                        str(extra.get("sso_rw") or ""),
                        max_attempts=body.refresh_attempts,
                    )
                    if refresh_result.get("ok") and refresh_result.get("cashier_url"):
                        _set_cashier_url(account, str(refresh_result["cashier_url"]))
                        _annotate_bridge_meta(
                            account,
                            client_id=client_id,
                            last_callback_status=status,
                            refresh_status="success",
                            refreshed_at=_utcnow_iso(),
                        )
                    else:
                        _annotate_bridge_meta(
                            account,
                            client_id=client_id,
                            last_callback_status=status,
                            refresh_status="failed" if refresh_result.get("attempted") else "skipped",
                            refresh_error=str(refresh_result.get("error") or ""),
                        )
                else:
                    _annotate_bridge_meta(
                        account,
                        client_id=client_id,
                        last_callback_status=status,
                        refresh_status="disabled",
                    )
            elif status == "failed":
                _clear_bridge_lock(account, status="failed", note=note or "grok payment failed")
                if body.clear_payment_url:
                    _set_cashier_url(account, "")
                _annotate_bridge_meta(account, client_id=client_id, last_callback_status=status)
            else:
                _clear_bridge_lock(account, status="skipped", note=note or "grok payment skipped")
                _annotate_bridge_meta(account, client_id=client_id, last_callback_status=status)

            session.add(account)
            session.commit()
            session.refresh(account)

    return {
        "success": True,
        "account": {
            "id": account.id,
            "email": account.email,
            "status": account.status,
            "status_label": _status_label("grok", account.status),
            "sync_status": _get_grok_sync_status(account),
            "sync_status_label": _grok_sync_status_label(_get_grok_sync_status(account)),
            "cashier_url": account.cashier_url,
        },
        "refresh": refresh_result,
    }


@router.post("/grok/sync-callback")
def grok_sync_callback(
    body: GrokSyncCallbackRequest,
    _: None = Depends(require_bridge_admin_token),
):
    status = _normalize_grok_sync_status(body.status)
    if not status:
        raise HTTPException(status_code=400, detail="status 必须为 pending/syncing/synced/failed/skipped")

    email = str(body.email or "").strip().lower()
    with _bridge_lock:
        with Session(engine) as session:
            query = select(AccountModel).where(AccountModel.platform == "grok")
            if body.id is not None:
                query = query.where(AccountModel.id == body.id)
            elif email:
                query = query.where(AccountModel.email == email)
            else:
                raise HTTPException(status_code=400, detail="id 或 email 必须提供一个")

            account = session.exec(query).first()
            if not account:
                raise HTTPException(status_code=404, detail="账号不存在")
            if account.status != "completed":
                raise HTTPException(status_code=409, detail="账号不是已完成状态，不能更新同步状态")

            try:
                _set_grok_sync_state(
                    account,
                    status=status,
                    client_id=str(body.clientId or "").strip(),
                    note=str(body.message or "").strip(),
                    remote_id=str(body.remote_id or "").strip(),
                    synced_at=str(body.synced_at or "").strip(),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

            session.add(account)
            session.commit()
            session.refresh(account)

    sync_status = _get_grok_sync_status(account)
    return {
        "success": True,
        "account": {
            "id": account.id,
            "email": account.email,
            "status": account.status,
            "status_label": _status_label("grok", account.status),
            "payment_status": "paid",
            "sync_status": sync_status,
            "sync_status_label": _grok_sync_status_label(sync_status),
        },
    }


@router.post("/grok/completed-callback")
@router.post("/grok/complete-callback")
def grok_complete_callback(
    body: GrokCompleteCallbackRequest,
    _: None = Depends(require_bridge_admin_token),
):
    status = _GROK_COMPLETE_STATUS_ALIASES.get(str(body.status or "").strip().lower(), "")
    if not status:
        raise HTTPException(status_code=400, detail="status 必须为 completed/complete/success/done")

    email = str(body.email or "").strip().lower()
    client_id = str(body.clientId or "").strip()
    note = str(body.message or "").strip()
    completed_at = str(body.completed_at or "").strip() or _utcnow_iso()

    with _bridge_lock:
        with Session(engine) as session:
            query = select(AccountModel).where(AccountModel.platform == "grok")
            if body.id is not None:
                query = query.where(AccountModel.id == body.id)
            elif email:
                query = query.where(AccountModel.email == email)
            else:
                raise HTTPException(status_code=400, detail="id 或 email 必须提供一个")

            account = session.exec(query).first()
            if not account:
                raise HTTPException(status_code=404, detail="账号不存在")
            if account.status not in {"subscribed", "completed"}:
                raise HTTPException(status_code=409, detail="账号不是已支付状态，不能更新为已完成")

            account.status = "completed"
            account.updated_at = _utcnow()
            _set_grok_sync_state(
                account,
                status="pending",
                client_id=client_id,
                note=note or "completed pending sync",
                remote_id=str(body.remote_id or "").strip(),
            )
            _annotate_bridge_meta(
                account,
                client_id=client_id,
                completed_at=completed_at,
                last_complete_callback_status=status,
            )

            session.add(account)
            session.commit()
            session.refresh(account)

    sync_status = _get_grok_sync_status(account)
    return {
        "success": True,
        "account": {
            "id": account.id,
            "email": account.email,
            "status": account.status,
            "status_label": _status_label("grok", account.status),
            "payment_status": "paid",
            "sync_status": sync_status,
            "sync_status_label": _grok_sync_status_label(sync_status),
        },
    }


@router.post("/account-callback")
def account_callback(
    body: AccountCallbackRequest,
    _: None = Depends(require_bridge_admin_token),
):
    email = str(body.email or "").strip().lower()
    status = str(body.status or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="email 不能为空")
    if status not in {"success", "failed", "skipped"}:
        raise HTTPException(status_code=400, detail="status 必须为 success/failed/skipped")

    with _bridge_lock:
        with Session(engine) as session:
            account = session.exec(
                select(AccountModel)
                .where(AccountModel.platform == "chatgpt")
                .where(AccountModel.email == email)
            ).first()
            if not account:
                raise HTTPException(status_code=404, detail="账号不存在")

            if status == "success":
                _clear_bridge_lock(account, status="success", note="payment success")
                account.status = "subscribed"
            elif status == "failed":
                _clear_bridge_lock(account, status="failed", note="payment failed")
            else:
                _clear_bridge_lock(account, status="skipped", note="payment skipped")

            session.add(account)
            session.commit()

    return {"success": True}
