"""BUSINESS 母号(团队 workspace 管理员)管理 + 以母号为维度批量直接邀请子号。

母号存 admin.openai.com 的 Cookie(含 oai-access-token),用它直接调 OpenAI 邀请接口
(不经过 CSV 上传)。可选某母号 → 从「已注册未邀请」的 business_csv 子号里批量邀请 N 个
(可设并发),邀请成功即置为 csv_uploaded(复用现有「激活」步骤接受邀请),并记录归属母号。
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from core.db import engine, AccountModel, BusinessMasterModel

router = APIRouter(prefix="/business-masters", tags=["business-masters"])

# 可直接邀请的子号状态(已注册、还没邀请过)
_INVITABLE_STATUS = {"registered", "csv_exported"}
_INVITE_BATCH = 6   # OpenAI 邀请接口一次最多 6 个


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _iso_utc(dt: Optional[datetime]) -> Optional[str]:
    a = _aware(dt)
    return a.isoformat() if a else None


def _resolve_cookie_meta(cookie_blob: str) -> dict:
    """从 cookie 串解析 workspace_id 和 access_token 过期时间。失败返回空字段。"""
    out = {"workspace_id": "", "expires_at": None, "bearer_ok": False}
    blob = str(cookie_blob or "").strip()
    if not blob:
        return out
    try:
        from services.business_domain_service import parse_cookie_blob
        from platforms.chatgpt.plugin import _decode_master_cookie_account_id
        cookies = parse_cookie_blob(blob)
        bearer = cookies.get("oai-access-token", "")
        out["bearer_ok"] = bool(bearer)
        if bearer:
            out["workspace_id"] = _decode_master_cookie_account_id(bearer) or ""
            try:
                payload_b64 = bearer.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload_b64))
                exp = int(claims.get("exp", 0))
                if exp:
                    out["expires_at"] = datetime.fromtimestamp(exp, tz=timezone.utc)
            except Exception:
                pass
    except Exception:
        pass
    return out


def _load_stats_json(blob: str) -> dict | None:
    try:
        d = json.loads(blob) if (blob or "").strip() else None
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _serialize(m: BusinessMasterModel) -> dict:
    exp = m.cookie_expires_at
    exp_aware = exp.replace(tzinfo=timezone.utc) if (exp and exp.tzinfo is None) else exp
    valid = bool(exp_aware and exp_aware > _utcnow())
    return {
        "id": m.id,
        "name": m.name,
        "workspace_id": m.workspace_id or "",
        "enabled": m.enabled,
        "has_cookie": bool((m.cookie_blob or "").strip()),
        "cookie_valid": valid,
        "cookie_expires_at": exp_aware.isoformat() if exp_aware else None,
        "invited_count": m.invited_count or 0,
        "last_invite_at": m.last_invite_at.isoformat() if m.last_invite_at else None,
        "stats": _load_stats_json(m.stats_json),
        "stats_updated_at": m.stats_updated_at.isoformat() if getattr(m, "stats_updated_at", None) else None,
        "plan_seats": int(getattr(m, "plan_seats", 0) or 0),
        "billing_paused_until": _iso_utc(getattr(m, "billing_paused_until", None)),
        "billing_paused": bool(getattr(m, "billing_paused_until", None)
                               and _aware(m.billing_paused_until) > _utcnow()),
        "note": m.note or "",
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "updated_at": m.updated_at.isoformat() if m.updated_at else None,
    }


class MasterIn(BaseModel):
    name: str
    cookie_blob: str = ""
    note: str = ""


class MasterPatch(BaseModel):
    name: Optional[str] = None
    cookie_blob: Optional[str] = None
    enabled: Optional[bool] = None
    note: Optional[str] = None
    plan_seats: Optional[int] = None   # 计费防护: 免费/计划席位阈值(手动设; 0=自动用下期账单席位)


class InviteRequest(BaseModel):
    count: int = 10
    concurrency: int = 3
    seat_type: str = "default"
    ignore_billing_guard: bool = False   # 忽略计费防护强制邀请(会产生账单, 慎用)

    @field_validator("seat_type", mode="before")
    @classmethod
    def _normalize_seat_type(cls, value: Any) -> str:
        seat_type = str(value or "").strip().lower()
        if seat_type not in {"default", "prolite"}:
            raise ValueError("seat_type must be 'default' or 'prolite'")
        return seat_type


@router.get("/invitable-count")
def invitable_count():
    """可邀请子号统计:registered_total(business_csv 账号总数)、invitable(已注册未邀请、未归属母号)。"""
    from services.business_csv import _account_extra, _is_business_csv_account, BUSINESS_CSV_MARKER
    total = invitable = assigned = 0
    with Session(engine) as s:
        rows = s.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))  # type: ignore[attr-defined]
        ).all()
    for r in rows:
        extra = _account_extra(r)
        if not _is_business_csv_account(extra):
            continue
        total += 1
        has_master = bool(str(extra.get("business_master_id") or "").strip())
        if has_master:
            assigned += 1
        elif str(extra.get("business_csv_status") or "") in _INVITABLE_STATUS:
            invitable += 1
    return {"registered_total": total, "invitable": invitable, "assigned": assigned}


def _master_status_counts() -> dict:
    """按母号统计其子号的 RT 进度: {master_id: {assigned, rt_ready, needs_rt, rt_failed}}。"""
    from services.business_csv import _account_extra, _is_business_csv_account, _has_chatgpt_rt, BUSINESS_CSV_MARKER
    out: dict[str, dict] = {}
    needs_rt_status = {"csv_uploaded", "activated", "activate_failed", "rt_failed", "registered", "csv_exported"}
    with Session(engine) as s:
        rows = s.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))  # type: ignore[attr-defined]
        ).all()
    for r in rows:
        extra = _account_extra(r)
        if not _is_business_csv_account(extra):
            continue
        mid = str(extra.get("business_master_id") or "").strip()
        if not mid:
            continue
        b = out.setdefault(mid, {"assigned": 0, "rt_ready": 0, "needs_rt": 0, "rt_failed": 0})
        b["assigned"] += 1
        if _has_chatgpt_rt(extra):
            b["rt_ready"] += 1
        else:
            st = str(extra.get("business_csv_status") or "")
            if st == "rt_failed":
                b["rt_failed"] += 1
            if st in needs_rt_status:
                b["needs_rt"] += 1
    return out


def _master_account_ids(master_id: int) -> list[int]:
    from services.business_csv import _account_extra, _is_business_csv_account, BUSINESS_CSV_MARKER
    ids: list[int] = []
    with Session(engine) as s:
        rows = s.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))  # type: ignore[attr-defined]
        ).all()
    for r in rows:
        extra = _account_extra(r)
        if not _is_business_csv_account(extra):
            continue
        if str(extra.get("business_master_id") or "").strip() == str(master_id) and r.id:
            ids.append(int(r.id))
    return ids


@router.get("")
def list_masters():
    counts = _master_status_counts()
    with Session(engine) as s:
        rows = s.exec(select(BusinessMasterModel).order_by(BusinessMasterModel.id.desc())).all()
        items = []
        for m in rows:
            d = _serialize(m)
            d["rt_counts"] = counts.get(str(m.id), {"assigned": 0, "rt_ready": 0, "needs_rt": 0, "rt_failed": 0})
            items.append(d)
        return {"items": items}


# 母号取 RT 固定用无头浏览器 + 该代理(protocol 易被风控挡在 login_session)
_MASTER_RT_BROWSER_MODE = "headless"
_MASTER_RT_PROXY = "http://127.0.0.1:7890"


@router.post("/{master_id}/rt/start")
def master_start_rt(master_id: int, body: dict | None = None):
    """对该母号名下、还没拿到 RT 的子号批量获取 RT。固定无头浏览器 + 指定代理。"""
    body = body or {}
    concurrency = max(1, min(int(body.get("concurrency") or 5), 20))
    browser_mode = _MASTER_RT_BROWSER_MODE
    proxy = str(body.get("proxy") or _MASTER_RT_PROXY).strip()
    # 母号 RT 默认允许 smsbower 自动过手机验证(可 body.allow_phone_verification=false 关)
    allow_phone = body.get("allow_phone_verification", True)
    allow_phone = str(allow_phone).strip().lower() not in ("0", "false", "no", "off")
    ids = _master_account_ids(master_id)
    if not ids:
        raise HTTPException(400, "该母号名下没有子号(先邀请)")
    # 写进这些账号 extra:代理(extra["proxy"] 优先级最高)+ 允许手机验证开关
    with Session(engine) as s:
        for acc in s.exec(select(AccountModel).where(AccountModel.id.in_(ids))).all():  # type: ignore[attr-defined]
            extra = acc.get_extra()
            if proxy:
                extra["proxy"] = proxy
            extra["chatgpt_rt_allow_phone_verification"] = "1" if allow_phone else "0"
            acc.set_extra(extra)
            acc.updated_at = _utcnow()
            s.add(acc)
        s.commit()
    from services.business_csv import BusinessCSVRunner
    result = BusinessCSVRunner.instance().start_rt(
        concurrency=concurrency, account_ids=ids, scope="selected", browser_mode=browser_mode,
    )
    if not result.get("ok"):
        raise HTTPException(409, result.get("error") or "RT 任务启动失败")
    result["browser_mode"] = browser_mode
    result["proxy"] = proxy
    return result


@router.post("/{master_id}/export-cpa")
def master_export_cpa(master_id: int, body: dict | None = None):
    """把该母号名下已拿到 RT 的子号导出为 CPA 格式,返回下载地址。"""
    body = body or {}
    fmt = str(body.get("format") or "cpa").strip().lower()
    if fmt not in {"cpa", "sub2api", "kanwang"}:
        fmt = "cpa"
    ids = _master_account_ids(master_id)
    if not ids:
        raise HTTPException(400, "该母号名下没有子号")
    from services.business_csv import BusinessCSVRunner
    result = BusinessCSVRunner.instance().export_ready(
        count=len(ids), format=fmt, account_ids=ids, scope="selected",
        delete_after_export=True,   # 导出后立即删除, 防止后续重复导出
    )
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "导出失败(可能还没有 RT 就绪的子号)")
    return result


@router.post("")
def create_master(body: MasterIn):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "请填写母号名称")
    meta = _resolve_cookie_meta(body.cookie_blob)
    now = _utcnow()
    with Session(engine) as s:
        m = BusinessMasterModel(
            name=name, cookie_blob=(body.cookie_blob or "").strip(),
            workspace_id=meta["workspace_id"], cookie_expires_at=meta["expires_at"],
            note=(body.note or "").strip(), created_at=now, updated_at=now,
        )
        s.add(m)
        s.commit()
        s.refresh(m)
        return _serialize(m)


@router.patch("/{master_id}")
def update_master(master_id: int, patch: MasterPatch):
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        if patch.name is not None:
            m.name = patch.name.strip()
        if patch.enabled is not None:
            m.enabled = bool(patch.enabled)
        if patch.note is not None:
            m.note = patch.note.strip()
        if patch.plan_seats is not None:
            m.plan_seats = max(0, int(patch.plan_seats or 0))
        if patch.cookie_blob is not None:
            m.cookie_blob = patch.cookie_blob.strip()
            meta = _resolve_cookie_meta(m.cookie_blob)
            m.workspace_id = meta["workspace_id"] or m.workspace_id
            m.cookie_expires_at = meta["expires_at"]
        m.updated_at = _utcnow()
        s.add(m)
        s.commit()
        s.refresh(m)
        return _serialize(m)


@router.delete("/{master_id}")
def delete_master(master_id: int):
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        s.delete(m)
        s.commit()
    return {"ok": True}


def _openai_get(url: str, cookie_blob: str, proxy: str = "", extra_headers: dict | None = None) -> tuple[int, Any]:
    """用母号 cookie 调 OpenAI 后台 GET。返回 (status, json|text)。"""
    from curl_cffi import requests as cr
    from services.business_domain_service import parse_cookie_blob, cookies_header
    cookies = parse_cookie_blob(cookie_blob)
    bearer = cookies.get("oai-access-token", "")
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Cookie": cookies_header(cookies),
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        "Accept": "*/*", "Referer": "https://chatgpt.com/admin/members",
    }
    if extra_headers:
        headers.update(extra_headers)
    proxies = {"http": proxy, "https": proxy} if (proxy or "").strip() else None
    r = cr.get(url, headers=headers, timeout=30, impersonate="chrome131", proxies=proxies)
    st = int(getattr(r, "status_code", 0) or 0)
    try:
        return st, (r.json() if st == 200 else (r.text or "")[:200])
    except Exception:
        return st, (getattr(r, "text", "") or "")[:200]


def _openai_delete(url: str, cookie_blob: str, workspace_id: str, proxy: str = "") -> tuple[int, Any]:
    """用母号 cookie 调 OpenAI 后台 DELETE(删成员)。返回 (status, json|text)。
    删成员的响应里带 policy_notice(含 vacancy_ordinal / free_vacancy_threshold)。"""
    from curl_cffi import requests as cr
    from services.business_domain_service import parse_cookie_blob, cookies_header
    cookies = parse_cookie_blob(cookie_blob)
    bearer = cookies.get("oai-access-token", "")
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Cookie": cookies_header(cookies),
        "chatgpt-account-id": workspace_id,
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        "Accept": "*/*", "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
    }
    proxies = {"http": proxy, "https": proxy} if (proxy or "").strip() else None
    r = cr.delete(url, headers=headers, timeout=30, impersonate="chrome131", proxies=proxies)
    st = int(getattr(r, "status_code", 0) or 0)
    try:
        return st, r.json()
    except Exception:
        return st, (getattr(r, "text", "") or "")[:200]


def _positive_seat_quantity(value: Any) -> Optional[int]:
    """把账单里的席位数量规范为正整数；脏值返回 ``None``。

    Stripe/OpenAI 的响应里 quantity 可能是数字或数字字符串。bool 虽是 int 的
    子类，但显然不是合法席位数；小数也不能作为席位数量使用。
    """
    if value is None or isinstance(value, bool):
        return None
    text = value.strip() if isinstance(value, str) else str(value)
    if not text:
        return None
    try:
        numeric = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if not numeric.is_finite() or numeric != numeric.to_integral_value():
        return None
    number = int(numeric)
    return number if number > 0 else None


def _nonnegative_seat_quantity(value: Any) -> Optional[int]:
    """Structured seat composition may explicitly encode a zero quantity."""
    if value is None or isinstance(value, bool):
        return None
    text = value.strip() if isinstance(value, str) else str(value)
    if not text:
        return None
    try:
        numeric = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if not numeric.is_finite() or numeric != numeric.to_integral_value():
        return None
    number = int(numeric)
    return number if number >= 0 else None


def _invoice_seat_type(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    if text in {"default", "default-seat", "standard", "standard-seat", "regular", "regular-seat"}:
        return "default"
    if text in {"prolite", "pro-lite", "prolite-seat", "pro-lite-seat"}:
        return "prolite"
    return ""


def _seat_composition(value: Any) -> Optional[dict[str, int]]:
    """Parse an explicit ``seat_quantities`` object/list.

    This helper intentionally accepts only type-labelled entries. It never infers
    a type from ordering, product price, or amount.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    if isinstance(value, dict) and (
        "seat_type" in value or "type" in value
    ):
        value = [value]
    elif isinstance(value, dict):
        value = [
            {"seat_type": key, "quantity": quantity}
            for key, quantity in value.items()
        ]
    if not isinstance(value, list):
        return None
    counts = {"default": 0, "prolite": 0}
    found = False
    for item in value:
        if not isinstance(item, dict):
            return None
        seat_type = _invoice_seat_type(
            item.get("seat_type") or item.get("type") or item.get("name")
        )
        quantity = _nonnegative_seat_quantity(
            item.get("quantity") if "quantity" in item else item.get("seat_quantity")
        )
        if not seat_type or quantity is None:
            return None
        counts[seat_type] += quantity
        found = True
    return counts if found and sum(counts.values()) > 0 else None


def _explicit_metadata_seat_composition(metadata: Any) -> Optional[dict[str, int]]:
    if not isinstance(metadata, dict):
        return None
    if "seat_quantities" in metadata:
        parsed = _seat_composition(metadata.get("seat_quantities"))
        if parsed:
            return parsed
    aliases = {
        "default": (
            "default_seat_quantity", "default_seats", "seat_quantity_default",
            "standard_seat_quantity", "standard_seats",
        ),
        "prolite": (
            "prolite_seat_quantity", "prolite_seats", "seat_quantity_prolite",
            "pro_lite_seat_quantity", "pro_lite_seats",
        ),
    }
    counts = {"default": 0, "prolite": 0}
    found = False
    for seat_type, keys in aliases.items():
        for key in keys:
            if key not in metadata:
                continue
            quantity = _nonnegative_seat_quantity(metadata.get(key))
            if quantity is None:
                return None
            counts[seat_type] = quantity
            found = True
            break
    return counts if found and sum(counts.values()) > 0 else None


def _structured_invoice_seat_composition(body: dict) -> tuple[Optional[dict[str, int]], str]:
    subscription = body.get("subscription_details")
    subscription = subscription if isinstance(subscription, dict) else {}
    candidates = (
        (body.get("seat_quantities"), "invoice.seat_quantities"),
        (subscription.get("seat_quantities"), "subscription_details.seat_quantities"),
    )
    for value, source in candidates:
        parsed = _seat_composition(value)
        if parsed:
            return parsed, source
    metadata_candidates = (
        (subscription.get("metadata"), "subscription_metadata"),
        (body.get("metadata"), "invoice_metadata"),
    )
    for metadata, source in metadata_candidates:
        parsed = _explicit_metadata_seat_composition(metadata)
        if parsed:
            suffix = ".seat_quantities" if isinstance(metadata, dict) and "seat_quantities" in metadata else ""
            return parsed, source + suffix
    return None, ""


def _invoice_line_seat_type(line: dict) -> str:
    if not isinstance(line, dict):
        return ""

    description = str(line.get("description") or "").strip().lower()
    # Stripe 的 upcoming invoice 可能同时含当前订阅行和按比例调整/退款行。
    # 调整行即使继承了同一个 price/metadata，也不能重复计入席位 entitlement。
    if bool(line.get("proration")) or any(token in description for token in (
        "proration", "prorated", "unused time", "remaining time", "credit",
        "adjustment", "refund", "折抵", "退款", "按比例",
    )):
        return ""

    metadata_candidates = [
        line,
        line.get("metadata"),
        line.get("price"),
        (line.get("price") or {}).get("metadata") if isinstance(line.get("price"), dict) else None,
        line.get("plan"),
        (line.get("plan") or {}).get("metadata") if isinstance(line.get("plan"), dict) else None,
    ]
    price = line.get("price")
    product = price.get("product") if isinstance(price, dict) else None
    if isinstance(product, dict):
        metadata_candidates.extend([product, product.get("metadata")])
    pricing = line.get("pricing")
    if isinstance(pricing, dict):
        metadata_candidates.append(pricing)
        price_details = pricing.get("price_details")
        if isinstance(price_details, dict):
            metadata_candidates.extend([price_details, price_details.get("metadata")])
    for candidate in metadata_candidates:
        if not isinstance(candidate, dict):
            continue
        for key in ("seat_type", "seat-type", "seatType"):
            seat_type = _invoice_seat_type(candidate.get(key))
            if seat_type:
                return seat_type

    # 2026-08 真实账单行不再附 seat_type metadata，但 price nickname 和
    # product description 仍是明确的产品身份：
    #   US_team_monthly_usd_v...          -> default
    #   US_team_prolite_monthly_usd_v...  -> prolite
    # 只识别这些明确名称，不根据价格、行顺序或“未出现 premium”猜测。
    identity_values: list[str] = [description]
    for candidate in metadata_candidates:
        if not isinstance(candidate, dict):
            continue
        for key in (
            "nickname", "lookup_key", "name", "product_name", "plan_name",
            "product", "price_id", "id",
        ):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                identity_values.append(value.strip().lower())

    def _identity_type(value: str) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""
        if (
            re.search(r"(?:^|[_\s-])team[_\s-]+pro[_\s-]*lite(?:[_\s-]|$)", text)
            or re.search(r"\bchatgpt\s+business\s+premium\s+subscription\b", text)
        ):
            return "prolite"
        if (
            re.search(r"(?:^|[_\s-])team[_\s-]+(?:monthly|annual|yearly)(?:[_\s-]|$)", text)
            or re.search(r"\bchatgpt\s+business\s+subscription\b", text)
        ):
            return "default"
        return ""

    for value in identity_values:
        seat_type = _identity_type(value)
        if seat_type:
            return seat_type

    if re.search(r"\bpro[\s_-]*lite\b", description):
        return "prolite"
    if re.search(r"\b(default|standard|regular)[\s_-]*(seat|member|user)s?\b", description):
        return "default"
    return ""


def _invoice_line_is_recurring(line: dict) -> bool:
    """Whether a Stripe invoice line is current recurring subscription state.

    Upcoming invoices may contain one-off invoice items and prorations alongside
    subscription lines.  A positive quantity by itself is therefore never enough
    evidence for seat capacity.
    """
    if not isinstance(line, dict) or bool(line.get("proration")):
        return False
    line_type = str(line.get("type") or "").strip().lower()
    if line_type == "subscription":
        return True
    if line_type and line_type not in {"subscription", "subscription_item"}:
        return False
    if str(line.get("subscription") or "").strip() or str(
        line.get("subscription_item") or ""
    ).strip():
        return True
    price = line.get("price")
    if isinstance(price, dict) and isinstance(price.get("recurring"), dict):
        return True
    plan = line.get("plan")
    if isinstance(plan, dict) and str(plan.get("interval") or "").strip():
        return True
    parent = line.get("parent")
    if isinstance(parent, dict) and isinstance(
        parent.get("subscription_item_details"), dict
    ):
        return True
    return False


def _invoice_line_looks_like_seat_product(line: dict) -> bool:
    """Detect an unclassified seat-looking line so partial splits fail closed."""
    if not isinstance(line, dict):
        return False
    values = [str(line.get("description") or "")]
    for candidate in (line.get("price"), line.get("plan"), line.get("pricing")):
        if not isinstance(candidate, dict):
            continue
        for key in ("nickname", "lookup_key", "name", "product_name", "plan_name"):
            value = candidate.get(key)
            if isinstance(value, str):
                values.append(value)
    text = " ".join(values).lower()
    return bool(
        re.search(r"\bseat(?:s)?\b", text)
        or "team_prolite" in text
        or "team-prolite" in text
        or "business premium subscription" in text
    )


def _recurring_invoice_seat_composition(body: dict) -> Optional[dict[str, int]]:
    """Read the current typed capacity from recurring Stripe seat products.

    All recurring lines that look like seat products must be classified.  This
    prevents a future third/renamed seat product from being silently omitted.
    """
    if not isinstance(body, dict):
        return None
    lines_obj = body.get("lines")
    lines = lines_obj.get("data") if isinstance(lines_obj, dict) else None
    if not isinstance(lines, list):
        return None
    counts = {"default": 0, "prolite": 0}
    found = False
    for line in lines:
        if not isinstance(line, dict) or not _invoice_line_is_recurring(line):
            continue
        seat_type = _invoice_line_seat_type(line)
        if not seat_type:
            if _invoice_line_looks_like_seat_product(line):
                return None
            continue
        quantity = _positive_seat_quantity(line.get("quantity"))
        if quantity is None:
            return None
        counts[seat_type] += quantity
        found = True
    return counts if found and sum(counts.values()) > 0 else None


def _parse_upcoming_invoice_seat_breakdown(body: dict) -> dict:
    """Return a trusted ``default``/``prolite`` entitlement breakdown.

    The split is marked known only for explicit structured data or a complete
    set of identifiable recurring seat-product lines. Unknown seat-looking lines
    make the whole split fail closed instead of returning a partial capacity.
    """
    unknown = {
        "default": None,
        "prolite": None,
        "total": _parse_upcoming_invoice_seats(body) if isinstance(body, dict) else None,
        "known": False,
        "source": "",
    }
    if not isinstance(body, dict):
        return unknown
    structured, source = _structured_invoice_seat_composition(body)
    if structured:
        typed_total = sum(structured.values())
        return {
            **structured,
            "total": typed_total,
            "known": True,
            "source": source,
        }

    counts = _recurring_invoice_seat_composition(body)
    if counts:
        typed_total = sum(counts.values())
        return {
            **counts,
            "total": typed_total,
            "known": True,
            "source": "recurring_invoice_lines",
        }
    return unknown


def _parse_upcoming_invoice_seats(body: dict) -> Optional[int]:
    """从 upcoming invoice 响应解析 workspace 的总席位数。

    混合普通/高级席位可能拆成多条 invoice line，所以不能继续只读第一条：

    1. 显式 ``seat_quantities`` 是最强证据；
    2. 其次汇总已明确分类的 recurring subscription seat lines；
    3. ``subscription_quantity`` 仅是创建订阅时的 metadata 快照，可能在后续扩容后落后，
       因此只在没有可信 recurring seat line 时作 fallback；
    4. 都没有可靠数据时返回 ``None``。
    """
    if not isinstance(body, dict):
        return None

    structured, _source = _structured_invoice_seat_composition(body)
    if structured:
        return sum(structured.values())

    recurring = _recurring_invoice_seat_composition(body)
    if recurring:
        return sum(recurring.values())

    subscription_details = body.get("subscription_details")
    metadata = (subscription_details.get("metadata")
                if isinstance(subscription_details, dict) else None)
    return _positive_seat_quantity(
        metadata.get("subscription_quantity") if isinstance(metadata, dict) else None
    )


def _fetch_upcoming_invoice(workspace_id: str, cookie_blob: str, proxy: str = "") -> dict:
    """拉该 workspace 下期预计账单(Stripe upcoming invoice), 解析席位数 + 金额。
    读不到返回 {}。"""
    path = f"/backend-api/invoices/upcoming?account_id={workspace_id}"
    st, body = _openai_get(
        f"https://chatgpt.com{path}", cookie_blob, proxy,
        extra_headers={"chatgpt-account-id": workspace_id,
                       "x-openai-target-path": path, "x-openai-target-route": path,
                       "Referer": "https://chatgpt.com/"},
    )
    if st != 200 or not isinstance(body, dict):
        return {}
    lines_obj = body.get("lines")
    lines = lines_obj.get("data") if isinstance(lines_obj, dict) else []
    lines = lines if isinstance(lines, list) else []
    line0 = next((line for line in lines if isinstance(line, dict)), {})
    seats = _parse_upcoming_invoice_seats(body)
    seat_breakdown = _parse_upcoming_invoice_seat_breakdown(body)
    total = body.get("total")
    subtotal = body.get("subtotal")
    unit = (line0.get("price") or {}).get("unit_amount") or (line0.get("plan") or {}).get("amount")
    cur = str(body.get("currency") or "usd").upper()
    return {
        "next_invoice_seats": seats,
        "next_invoice_seats_by_type": {
            "default": seat_breakdown["default"],
            "prolite": seat_breakdown["prolite"],
        },
        "next_invoice_seat_type_capacity_known": bool(seat_breakdown["known"]),
        "next_invoice_seat_type_capacity_source": str(seat_breakdown["source"] or ""),
        "next_invoice_total": (total / 100) if isinstance(total, (int, float)) else None,
        "next_invoice_subtotal": (subtotal / 100) if isinstance(subtotal, (int, float)) else None,
        "next_invoice_unit": (unit / 100) if isinstance(unit, (int, float)) else None,
        "next_invoice_currency": cur,
        "next_invoice_period_end": body.get("period_end"),
        "next_invoice_desc": line0.get("description") or "",
    }


def _local_invite_counts(master_id: int) -> dict:
    """本地 DB: 该母号名下已邀请子号数 + 全局「已注册未邀请」可邀请池数。"""
    from services.business_csv import _account_extra, _is_business_csv_account, BUSINESS_CSV_MARKER
    invited = pending = 0
    with Session(engine) as s:
        rows = s.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))  # type: ignore[attr-defined]
        ).all()
    for r in rows:
        extra = _account_extra(r)
        if not _is_business_csv_account(extra):
            continue
        if str(extra.get("business_master_id") or "").strip() == str(master_id):
            invited += 1
        elif (not str(extra.get("business_master_id") or "").strip()
              and str(extra.get("business_csv_status") or "") in _INVITABLE_STATUS):
            pending += 1
    return {"local_invited": invited, "local_pending_invite": pending}


def _compute_workspace_stats(master_id: int) -> dict:
    """用母号 session 解析 workspace 并把结果缓存进母号行(stats_json)。返回 stats dict。
    硬错误抛 HTTPException。"""
    from core.config_store import config_store
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        cookie_blob = (m.cookie_blob or "").strip()
        workspace_id = (m.workspace_id or "").strip()
    if not cookie_blob:
        raise HTTPException(400, "该母号没有 Cookie")
    if not workspace_id:
        workspace_id = _resolve_cookie_meta(cookie_blob).get("workspace_id") or ""
    if not workspace_id:
        raise HTTPException(400, "无法解析 workspace id(Cookie 可能已过期)")
    proxy = str(config_store.get("default_proxy", "") or "").strip()

    st_u, users = _openai_get(f"https://chatgpt.com/backend-api/accounts/{workspace_id}/users", cookie_blob, proxy)
    if st_u != 200:
        raise HTTPException(502, f"读取成员失败 HTTP {st_u}: {str(users)[:120]}(Cookie 可能过期,请重新粘贴)")
    items = (users or {}).get("items") or []
    owner_email = next((str(it.get("email") or "") for it in items
                        if str(it.get("role") or "") == "account-owner"), "")
    active_items = [it for it in items if not it.get("deactivated_time")]
    space_members = int((users or {}).get("total") or len(items))
    standard_members = sum(1 for it in active_items if str(it.get("role") or "") == "standard-user")
    # 成员明细(供界面展示 + 删成员): id / email / role / 是否停用
    members = [{
        "user_id": str(it.get("id") or it.get("account_user_id") or ""),
        "email": str(it.get("email") or ""),
        "role": str(it.get("role") or ""),
        "deactivated": bool(it.get("deactivated_time")),
    } for it in items]

    st_i, inv = _openai_get(f"https://chatgpt.com/backend-api/accounts/{workspace_id}/invites", cookie_blob, proxy)
    pending_invites = int((inv or {}).get("total") or 0) if st_i == 200 else 0

    local = _local_invite_counts(master_id)
    invoice = _fetch_upcoming_invoice(workspace_id, cookie_blob, proxy)

    now = _utcnow()
    # ── 计费防护计算 ──
    # 计费席位 = 下期账单席位数(读不到就用未停用成员数兜底)
    billing_seats = invoice.get("next_invoice_seats")
    if billing_seats is None:
        billing_seats = len(active_items)
    with Session(engine) as s:
        m0 = s.get(BusinessMasterModel, master_id)
        plan_seats_cfg = int(getattr(m0, "plan_seats", 0) or 0) if m0 else 0
        paused_until_prev = _aware(getattr(m0, "billing_paused_until", None)) if m0 else None
    # 阈值: 手动设了用手动值; 否则用当前计费席位(即以现状为基线, 不主动扩容)
    plan_seats = plan_seats_cfg if plan_seats_cfg > 0 else int(billing_seats or 0)
    used = len(active_items) + int(pending_invites or 0)          # 已占用(成员+待邀请)
    invitable_by_seat = max(0, plan_seats - used)                 # 还能免费邀请几个
    overflow = (int(billing_seats or 0) > plan_seats) or (used > plan_seats)

    # 自动暂停: 一旦溢出且当前未处于暂停 → 设一个暂停窗口(默认 24h, 可配), 之后自动恢复
    try:
        from core.config_store import config_store as _cs
        pause_hours = int(str(_cs.get("business_billing_pause_hours", "") or 24) or 24)
    except Exception:
        pause_hours = 24
    billing_paused_until = paused_until_prev if (paused_until_prev and paused_until_prev > now) else None
    if overflow and billing_paused_until is None:
        billing_paused_until = now + timedelta(hours=max(1, pause_hours))
    billing_paused = bool(billing_paused_until and billing_paused_until > now)

    stats = {
        "ok": True, "master_id": master_id,
        "workspace_id": workspace_id,
        "owner_email": owner_email,
        "space_members": space_members,           # 空间成员(含 owner)
        "active_members": len(active_items),       # 未停用成员
        "standard_members": standard_members,      # 普通成员(邀请进来的)
        "pending_invites": pending_invites,        # 已邀请待接受
        "members": members,                        # 成员明细列表
        **local,                                   # local_invited / local_pending_invite
        **invoice,                                 # 下期账单席位/金额
        # ── 计费防护 ──
        "billing_seats": int(billing_seats or 0),  # 计费席位
        "plan_seats": plan_seats,                  # 计划/免费席位阈值
        "used_seats": used,                        # 已占用(成员+待邀请)
        "invitable_by_seat": invitable_by_seat,    # 还能免费邀请几个
        "overflow": overflow,                      # 是否已超额(会出账单)
        "billing_paused": billing_paused,          # 计费防护是否已暂停
        "billing_paused_until": _iso_utc(billing_paused_until),
        "stats_updated_at": now.isoformat(),
    }
    # 缓存进母号行 + 落地暂停状态
    with Session(engine) as s:
        m2 = s.get(BusinessMasterModel, master_id)
        if m2:
            m2.workspace_id = workspace_id
            m2.billing_paused_until = billing_paused_until
            m2.stats_json = json.dumps({k: v for k, v in stats.items()
                                        if k not in ("ok", "master_id")}, ensure_ascii=False)
            m2.stats_updated_at = now
            m2.updated_at = now
            s.add(m2)
            s.commit()
    return stats


@router.get("/{master_id}/workspace-stats")
def workspace_stats(master_id: int):
    return _compute_workspace_stats(master_id)


class RemoveMemberRequest(BaseModel):
    user_id: str
    email: str = ""


@router.post("/{master_id}/members/remove")
def remove_member(master_id: int, body: RemoveMemberRequest):
    """删除 workspace 里的一个成员。响应 policy_notice 带 vacancy_ordinal / free_vacancy_threshold。
    删成员会腾出席位 → 删完刷新计费防护状态。"""
    from core.config_store import config_store
    user_id = (body.user_id or "").strip()
    if not user_id:
        raise HTTPException(400, "缺 user_id")
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        cookie_blob = (m.cookie_blob or "").strip()
        workspace_id = (m.workspace_id or "").strip() or _resolve_cookie_meta(cookie_blob).get("workspace_id") or ""
    if not cookie_blob or not workspace_id:
        raise HTTPException(400, "母号缺 Cookie / workspace")
    proxy = str(config_store.get("default_proxy", "") or "").strip()
    url = f"https://chatgpt.com/backend-api/accounts/{workspace_id}/users/{user_id}"
    st, resp = _openai_delete(url, cookie_blob, workspace_id, proxy)
    if st not in (200, 204):
        raise HTTPException(502, f"删除成员失败 HTTP {st}: {str(resp)[:160]}")
    policy = resp.get("policy_notice") if isinstance(resp, dict) else None
    # 若本地有该邮箱的子号, 解除其母号归属(回到可邀请池)
    if (body.email or "").strip():
        try:
            from services.business_csv import _account_extra  # noqa: F401
            with Session(engine) as s:
                acc = s.exec(select(AccountModel)
                             .where(AccountModel.platform == "chatgpt")
                             .where(AccountModel.email == body.email.strip().lower())).first()
                if acc:
                    extra = acc.get_extra()
                    if str(extra.get("business_master_id") or "") == str(master_id):
                        extra.pop("business_master_id", None)
                        extra.pop("business_master_name", None)
                        acc.set_extra(extra)
                        acc.updated_at = _utcnow()
                        s.add(acc)
                        s.commit()
        except Exception:
            pass
    stats = _compute_workspace_stats(master_id)   # 删完刷新席位/防护
    return {"ok": True, "status": st, "policy_notice": policy, "stats": stats}


@router.post("/{master_id}/resume-billing")
def resume_billing(master_id: int):
    """手动恢复计费防护(清除暂停)。注意: 若仍超额, 下次刷新会再次自动暂停。"""
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        m.billing_paused_until = None
        m.updated_at = _utcnow()
        s.add(m)
        s.commit()
    return {"ok": True}


# ── PRO 退款焚诀: 邀请 PRO 号进 team → 登录(自动入群)→ transfer 去个人空间(掉订阅)→ 踢出 ──

PRO_BURN_LIMIT_PER_MASTER = 4   # 每个 team 母号最多退 4 个 PRO


def _burned_count(source_label: str) -> int:
    """该母号(source_label 如 biz1 / master1)已成功焚过的 PRO 数量。"""
    if not source_label:
        return 0
    from core.db import GptPlanAccountModel as GptProAccountModel
    needle = f'"pro_refund_burn_master": "{source_label}"'
    with Session(engine) as s:
        rows = s.exec(
            select(GptProAccountModel).where(GptProAccountModel.extra_json.contains(needle))  # type: ignore[attr-defined]
        ).all()
    return len(rows)


def _master_at_and_team(m: BusinessMasterModel) -> tuple[str, str]:
    """从母号 cookie_blob 取 oai-access-token(AT)+ team account_id。"""
    blob = (m.cookie_blob or "")
    at = ""
    for part in blob.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() == "oai-access-token":
                at = v.strip()
    team = (m.workspace_id or "").strip() or _resolve_cookie_meta(blob).get("workspace_id") or ""
    return at, team


class ProRefundBurnRequest(BaseModel):
    account_ids: list[int]
    concurrency: int = 2
    kick: bool = True


def _normalize_pro_refund_burn_ids(values: list) -> list[int]:
    """按首次出现顺序规范化账号 ID，避免同一批次对同号发起多次远端操作。"""
    result: list[int] = []
    seen: set[int] = set()
    for value in values or []:
        try:
            account_id = int(value)
        except (TypeError, ValueError):
            continue
        if account_id <= 0 or account_id in seen:
            continue
        seen.add(account_id)
        result.append(account_id)
    return result


def _pro_refund_burn_account_email(account_id: int) -> str:
    from core.db import GptPlanAccountModel as GptProAccountModel

    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        return str(account.email or "") if account else "?"


def _run_pro_refund_burn_with_lease(account_id: int, action) -> tuple:
    """在统一 GPT PRO 账号租约内执行单号焚决。

    claim 位于所有 OpenAI/邮箱/浏览器调用之前；GPT PRO 升级、退款和 BUSINESS
    分配使用同一张租约表。释放时同时校验 account_id + token，旧任务不会误删
    已被新任务接管的租约。
    """
    from api.gpt_plan_operations import (
        _claim_gpt_pro_account_operation,
        _release_gpt_pro_account_operation,
    )

    aid = int(account_id)
    token = ""
    try:
        token = _claim_gpt_pro_account_operation(aid, "refund_burn")
    except HTTPException as exc:
        detail = exc.detail
        if isinstance(detail, dict):
            message = str(detail.get("message") or detail.get("code") or "账号正忙")
        else:
            message = str(detail or "账号正忙")
        return (aid, _pro_refund_burn_account_email(aid), f"跳过:{message}")
    except Exception as exc:
        return (aid, _pro_refund_burn_account_email(aid), f"租约失败:{str(exc)[:160]}")

    try:
        return action(aid)
    except Exception as exc:
        return (aid, _pro_refund_burn_account_email(aid), f"异常:{str(exc)[:160]}")
    finally:
        _release_gpt_pro_account_operation(aid, token)


def _start_pro_refund_burn(at: str, team: str, ids: list, conc: int, kick: bool,
                           proxy: str = "", source_label: str = "", *,
                           business_account_id: int = 0,
                           invite_quota_operation_id: str = "") -> str:
    """启动 PRO 退款焚诀后台任务(母号 AT + team 已给定)。返回 task_id。
    母号来源可以是 Business Masters 或 GPT BUSINESS 账号(谁有 team cookie 都行)。"""
    from api.gpt_plan_operations import _create_invite_task, _invite_task_log, _set_invite_progress, _invite_task_finish

    ids = _normalize_pro_refund_burn_ids(ids)
    if not ids:
        raise HTTPException(400, "未选择有效的 PRO 账号")
    prox = {"http": proxy, "https": proxy} if proxy else None
    Hm = {"Authorization": f"Bearer {at}", "chatgpt-account-id": team, "Content-Type": "application/json",
          "Accept": "*/*", "Origin": "https://chatgpt.com", "Referer": "https://chatgpt.com/"}
    task_id = _create_invite_task()

    quota_parent_id = int(business_account_id or 0)
    quota_operation_id = str(invite_quota_operation_id or "").strip()
    quota_remote_started: set[int] = set()
    quota_remote_started_lock = threading.Lock()

    def _quota_subject(aid: int) -> str:
        return f"pro:{int(aid)}"

    def _quota_consume(aid: int) -> None:
        if quota_parent_id <= 0 or not quota_operation_id:
            return
        from api.gpt_business import _consume_business_invite_quota
        _consume_business_invite_quota(
            quota_parent_id,
            quota_operation_id,
            [_quota_subject(aid)],
            action="pro_refund_burn",
        )

    def _quota_release(aid: int, reason: str) -> None:
        if quota_parent_id <= 0 or not quota_operation_id:
            return
        from api.gpt_business import _release_business_invite_quota
        _release_business_invite_quota(
            quota_parent_id,
            quota_operation_id,
            [_quota_subject(aid)],
            action="pro_refund_burn",
            reason=reason,
        )

    def _invite_cooldown_available() -> tuple[bool, str]:
        if quota_parent_id <= 0:
            return True, ""
        from api.gpt_business import _business_invite_cooldown_snapshot
        with Session(engine) as session:
            snapshot = _business_invite_cooldown_snapshot(
                session, quota_parent_id,
            )
        return (
            not bool(snapshot.get("active")),
            str(snapshot.get("resume_at") or ""),
        )

    def _invite_cooldown_fail(reason: str) -> None:
        if quota_parent_id <= 0:
            return
        from api.gpt_business import _record_business_invite_failure_cooldown
        _record_business_invite_failure_cooldown(
            quota_parent_id, reason,
        )

    def _one_claimed(aid: int) -> tuple:
        from curl_cffi import requests as cr
        from core.db import GptPlanAccountModel as GptProAccountModel
        from platforms.chatgpt.gpt_pro_login import build_mailbox_for_account, login_with_email_otp
        with Session(engine) as s:
            a = s.get(GptProAccountModel, aid)
            if not a:
                _quota_release(aid, "burn_target_missing_before_remote")
                return (aid, "?", "账号不存在")
            email = a.email
            if (
                not bool(a.is_pro)
                or not bool(a.enabled)
                or bool(a.dangerous)
                or bool(str(a.refund_status or "").strip())
                or a.business_parent_id is not None
            ):
                _quota_release(aid, "burn_target_ineligible_before_remote")
                return (
                    aid,
                    email,
                    "跳过:账号状态已变化，不再符合焚决条件",
                )
            try:
                account_extra = json.loads(a.extra_json or "{}")
            except Exception:
                account_extra = {}
            if not isinstance(account_extra, dict):
                account_extra = {}
            # 焚决目标可能是 iCloud HME 别名。旧实现固定调用
            # build_outlook_mailbox，忽略 extra_json.mail_provider，导致
            # QQMail 收件箱中的验证码永远不会被查询到（日志只显示
            # “baseline 0 封”，随后等待超时）。复用统一 provider 分发，
            # 与套餐界面普通登录保持一致。
            snap = {
                "email": a.email,
                "password": a.password or "",
                "client_id": a.client_id or "",
                "refresh_token": a.refresh_token or "",
                "mail_access_type": a.mail_access_type or "",
                "mail_provider": str(account_extra.get("mail_provider") or "outlook").strip().lower(),
            }
        steps = []
        # 1) 邀请
        cooldown_available, cooldown_until = _invite_cooldown_available()
        if not cooldown_available:
            return (
                aid,
                email,
                f"邀请冷却中，{cooldown_until or '稍后'}可重试",
            )
        try:
            with quota_remote_started_lock:
                quota_remote_started.add(int(aid))
            iv = cr.post(f"https://chatgpt.com/backend-api/accounts/{team}/invites", headers=Hm,
                         json={"email_addresses": [email], "role": "standard-user", "seat_type": "default"},
                         impersonate="chrome131", proxies=prox, timeout=30)
        except Exception as exc:
            _invite_cooldown_fail(
                f"request_exception:{type(exc).__name__}",
            )
            return (aid, email, f"邀请异常:{exc}")

        try:
            steps.append(f"邀请{iv.status_code}")
            # HTTP 200 也可能失败:成功进 account_invites,失败进 errored_emails。
            try:
                ivj = iv.json() if iv.status_code == 200 else {}
            except Exception:
                ivj = {}
            target = str(email or "").strip().lower()
            ok_inv = [
                x for x in (ivj.get("account_invites") or []) if isinstance(x, dict)
                and str(x.get("email_address") or x.get("email") or "").strip().lower() == target
            ]
            err_inv = [
                x for x in (ivj.get("errored_emails") or []) if isinstance(x, dict)
                and str(x.get("email_address") or x.get("email") or "").strip().lower() == target
            ]
            already_present = any(
                "already" in str(x.get("error") or "").lower()
                for x in err_inv
            )
            if iv.status_code != 200:
                _invite_cooldown_fail(f"http_{int(iv.status_code or 0)}")
                if iv.status_code in {400, 401, 403, 405, 415, 422}:
                    try:
                        _quota_release(aid, f"burn_invite_http_{iv.status_code}_definite_noop")
                    except Exception:
                        pass
                return (aid, email, f"邀请失败 HTTP {iv.status_code}")
            # Any exact success record is authoritative evidence that the
            # remote invitation may have been created.  Even if an anomalous
            # response also contains an error for the same target, consume the
            # reservation rather than release capacity and risk a fifth
            # invitation inside the fixed window.
            if ok_inv:
                _quota_consume(aid)
            elif already_present and not ok_inv:
                # The exact target is already present remotely.  Treat this as
                # an idempotent workflow continuation, but do not consume a
                # fresh fixed-window invitation unit: this POST performed no new
                # invitation. A new API invocation has a new quota operation
                # id, so consuming here would charge every replay again.
                try:
                    _quota_release(aid, "burn_invite_target_already_present")
                except Exception:
                    # A failed release conservatively leaves the reservation
                    # occupied; it must not turn a proven remote no-op into a
                    # confirmed invitation.
                    pass
                steps.append("邀请:目标已在团队")
            elif err_inv:
                _invite_cooldown_fail("explicit_rejection")
                try:
                    _quota_release(aid, "burn_invite_explicit_rejection")
                except Exception:
                    pass
                emsg = "; ".join(str(x.get("error") or "") for x in err_inv)
                return (aid, email, f"邀请失败:{emsg[:160]}")
            else:
                # Empty/malformed/target-mismatched 200 is not success. Keep the
                # reservation because the remote mutation cannot be ruled out.
                # This is an indeterminate result, not explicit server failure:
                # the durable operation remains reconcile-only and must not put
                # the whole BUSINESS mother into the invitation backoff.
                return (aid, email, "邀请结果不确定:未返回目标邮箱的成功或失败证据")
        except Exception as exc:
            # An HTTP response was already received. Any JSON/classification or
            # local ledger failure is indeterminate and must never start the
            # mother's invitation cooldown.
            return (aid, email, f"邀请后处理异常:{exc}")
        # 2) 登录(留窗, 捕获 page + AT)
        cap = {}

        def _act(page, result):
            cap["page"] = page
            cap["at"] = result.access_token
            return {"ok": True}
        page = None
        try:
            mb, mba = build_mailbox_for_account(snap, proxy=proxy)
            r = login_with_email_otp(email=email, mailbox=mb, mailbox_account=mba, headless=False,
                                     proxy=proxy, otp_timeout=180, keep_browser_open=True,
                                     is_signup=False, post_login_action=_act)
            page = cap.get("page")
            user_at = cap.get("at")
            if not page or not user_at:
                return (aid, email, f"登录失败:{getattr(r, 'error', '')}")
            steps.append("登录ok")
            # 3) transfer 去个人空间(掉订阅)
            tjs = ("return fetch('https://chatgpt.com/backend-api/accounts/transfer',{method:'POST',credentials:'include',"
                   "headers:{'Authorization':'Bearer %s','chatgpt-account-id':'%s','Content-Type':'application/json'},"
                   "body:JSON.stringify({workspace_id:'%s',transfer_personal:true})}).then(async r=>({status:r.status,body:await r.text()})).catch(e=>({err:String(e)}))"
                   % (user_at, team, team))
            tr = page.run_js(tjs) or {}
            ok_tr = isinstance(tr, dict) and str(tr.get("status")) == "200" and "success" in str(tr.get("body", "")).lower()
            steps.append(f"transfer{(tr or {}).get('status')}")
            if not ok_tr:
                return (aid, email, f"掉订阅失败(可能没进 team): {str(tr)[:160]}")
            # 4) 踢出
            if kick:
                uid = ""
                try:
                    gu = cr.get(f"https://chatgpt.com/backend-api/accounts/{team}/users", headers=Hm,
                                params={"query": email.split("@")[0], "limit": 20},
                                impersonate="chrome131", proxies=prox, timeout=30)
                    for it in (gu.json() or {}).get("items", []):
                        if str(it.get("email") or "").lower() == email.lower():
                            uid = it.get("id")
                            break
                except Exception:
                    pass
                if uid:
                    dk = cr.delete(f"https://chatgpt.com/backend-api/accounts/{team}/users/{uid}",
                                   headers=Hm, impersonate="chrome131", proxies=prox, timeout=30)
                    steps.append(f"踢出{dk.status_code}")
                    # 踢出响应带 policy_notice(fr/va)→ 落到母号(GPT BUSINESS 账号)供界面展示
                    try:
                        dkj = dk.json() if dk.status_code == 200 else None
                    except Exception:
                        dkj = None
                    policy = dkj.get("policy_notice") if isinstance(dkj, dict) else None
                    print(f"[burn-kick] master={source_label} kicked={email} http={dk.status_code} "
                          f"policy_notice={policy!r}", flush=True)
                    if source_label.startswith("biz"):
                        try:
                            biz_id = int(source_label[3:])
                            from api.gpt_business import _store_vacancy_policy
                            from core.db import GptBusinessAccountModel as _GBA
                            with Session(engine) as s3:
                                macc = s3.get(_GBA, biz_id)
                                if macc:
                                    _store_vacancy_policy(s3, macc, policy, http_status=int(dk.status_code))
                                    s3.commit()
                        except Exception as _exc:
                            print(f"[burn-kick] 存 policy 失败: {_exc}", flush=True)
                else:
                    steps.append("踢出:未找到成员")
            # 5) 本地标记
            with Session(engine) as s:
                a2 = s.get(GptProAccountModel, aid)
                if a2:
                    # 保留 is_pro=1(留在 PRO Tab + 继续被邮件监控);标为「已申请退款」,
                    # 退款邮件到了监控会自动把它推进「已退款未到账」Tab。
                    a2.is_pro = True
                    if (a2.refund_status or "") not in ("refunded_pending_credit", "refund_credited"):
                        a2.refund_status = "refund_pending"
                    _note = (a2.note or "").strip()
                    if "已焚" not in _note:
                        a2.note = (_note + " [已焚·待退款]").strip()
                    try:
                        ex = json.loads(a2.extra_json) if a2.extra_json else {}
                    except Exception:
                        ex = {}
                    ex["pro_refund_burned_at"] = _utcnow().isoformat()
                    ex["pro_refund_burn_master"] = source_label
                    a2.extra_json = json.dumps(ex, ensure_ascii=False)
                    a2.updated_at = _utcnow()
                    s.add(a2)
                    s.commit()
            return (aid, email, "✅ " + "/".join(steps))
        except Exception as exc:
            return (aid, email, f"异常({'/'.join(steps)}):{exc}")
        finally:
            if page is not None:
                try:
                    page.quit()
                except Exception:
                    pass

    def _one(aid: int) -> tuple:
        result = _run_pro_refund_burn_with_lease(aid, _one_claimed)
        message = str(result[2] if len(result) > 2 else "")
        with quota_remote_started_lock:
            reached_remote = int(aid) in quota_remote_started
        if not reached_remote:
            _quota_release(aid, "burn_worker_did_not_reach_remote_invite")
        return result

    def _worker():
        from concurrent.futures import ThreadPoolExecutor, as_completed
        done = 0
        burned = 0
        _invite_task_log(task_id, f"PRO 退款焚诀开始: {len(ids)} 个号, 母号 team={team}, 并发 {conc}")
        with ThreadPoolExecutor(max_workers=conc) as ex:
            futs = [ex.submit(_one, i) for i in ids]
            for fut in as_completed(futs):
                done += 1
                aid, email, msg = fut.result()
                if isinstance(msg, str) and msg.startswith("✅"):
                    burned += 1
                _invite_task_log(task_id, f"{email}: {msg}")
                _set_invite_progress(task_id, {"done": done, "total": len(ids), "burned": burned})
        _invite_task_finish(task_id, result={"total": len(ids), "burned": burned})
        _invite_task_log(task_id, f"完成: 掉订阅成功 {burned}/{len(ids)}")

    threading.Thread(target=_worker, daemon=True, name=f"pro-burn-{task_id[:8]}").start()
    return task_id


@router.post("/{master_id}/pro-refund-burn")
def pro_refund_burn(master_id: int, body: ProRefundBurnRequest):
    """(母号面板)对选中 PRO 号跑退款焚诀。用 GET /pro-refund-burn/{task_id} 轮询。"""
    from core.config_store import config_store
    ids = _normalize_pro_refund_burn_ids(body.account_ids or [])
    if not ids:
        raise HTTPException(400, "未选择 PRO 账号")
    conc = max(1, min(int(body.concurrency or 2), 4))
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        at, team = _master_at_and_team(m)
    if not at or not team:
        raise HTTPException(400, "母号 cookie 缺 AT/team(去登录母号刷新 cookie)")
    label = f"master{master_id}"
    # Keep the historic count for audit/compatibility only. It no longer caps
    # or rejects a burn request; only an actual invitation API failure creates
    # the mother's fixed ten-minute backoff.
    already = _burned_count(label)
    proxy = str(config_store.get("default_proxy", "") or "").strip()
    task_id = _start_pro_refund_burn(at, team, ids, conc, bool(body.kick), proxy, label)
    return {"task_id": task_id, "targets": len(ids), "already_burned": already}


@router.get("/pro-refund-burn/{task_id}")
def pro_refund_burn_status(task_id: str, since: int = 0):
    from api.gpt_plan_operations import _snapshot_invite_task
    snap = _snapshot_invite_task(task_id, since=since)
    if snap is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snap


def _refresh_stats_safe(master_id: int) -> None:
    """best-effort 刷新并缓存空间信息(邀请后自动调, 失败不影响主流程)。"""
    try:
        _compute_workspace_stats(master_id)
    except Exception:
        pass


def _invitable_pool(limit: int) -> list[dict]:
    """取「已注册未邀请」的 business_csv 子号(未归属任何母号),返回 [{id,email}]。"""
    from services.business_csv import _account_extra, _is_business_csv_account, BUSINESS_CSV_MARKER
    out: list[dict] = []
    with Session(engine) as s:
        rows = s.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))  # type: ignore[attr-defined]
            .order_by(AccountModel.id.asc())
        ).all()
    for r in rows:
        extra = _account_extra(r)
        if not _is_business_csv_account(extra):
            continue
        if str(extra.get("business_master_id") or "").strip():
            continue  # 已归属某母号
        if str(extra.get("business_csv_status") or "") not in _INVITABLE_STATUS:
            continue
        if not (r.email or "").strip():
            continue
        out.append({"id": r.id, "email": r.email.strip().lower()})
        if len(out) >= limit:
            break
    return out


@router.post("/{master_id}/invite")
def invite_with_master(master_id: int, body: InviteRequest):
    """用该母号从「已注册未邀请」池里批量邀请 count 个子号(concurrency 并发)。
    邀请成功 → 子号置 csv_uploaded + 记录归属母号(供后续「激活」「取 RT」)。"""
    from core.config_store import config_store
    from platforms.chatgpt.plugin import _send_business_invites_batch

    count = max(1, min(int(body.count or 1), 500))
    concurrency = max(1, min(int(body.concurrency or 3), 10))
    with Session(engine) as s:
        m = s.get(BusinessMasterModel, master_id)
        if not m:
            raise HTTPException(404, "母号不存在")
        if not m.enabled:
            raise HTTPException(400, "该母号已停用")
        cookie_blob = (m.cookie_blob or "").strip()
        workspace_id = (m.workspace_id or "").strip()
        master_name = m.name
    if not cookie_blob:
        raise HTTPException(400, "该母号没有 Cookie,请先编辑粘贴 admin.openai.com 的 Cookie")
    if not workspace_id:                       # 兜底再解析一次
        workspace_id = _resolve_cookie_meta(cookie_blob).get("workspace_id") or ""

    # ── 计费防护: 邀请前先算席位; 暂停中直接拦, 会超额则收窄数量到不出账单 ──
    if not bool(getattr(body, "ignore_billing_guard", False)):
        try:
            _st = _compute_workspace_stats(master_id)
        except HTTPException:
            _st = {}
        if _st.get("billing_paused"):
            raise HTTPException(409, f"计费防护已暂停邀请(至 {_st.get('billing_paused_until')} 自动恢复,"
                                     f"或在界面手动恢复)。当前计费席位 {_st.get('billing_seats')} 超阈值 {_st.get('plan_seats')}。")
        seat_room = _st.get("invitable_by_seat")
        if isinstance(seat_room, int):
            if seat_room <= 0:
                raise HTTPException(409, f"已达计划席位阈值 {_st.get('plan_seats')}(已占用 {_st.get('used_seats')}),"
                                         f"再邀请会产生账单;计费防护已拦截。如确需扩容请提高阈值或勾选忽略防护。")
            count = min(count, seat_room)     # 收窄到不超额

    pool = _invitable_pool(count)
    if not pool:
        return {"ok": True, "invited": 0, "errored": 0, "message": "没有可邀请的子号(需状态为已注册/已导出且未归属母号)"}

    email_to_id = {p["email"]: p["id"] for p in pool}
    groups = [pool[i:i + _INVITE_BATCH] for i in range(0, len(pool), _INVITE_BATCH)]
    proxy = str(config_store.get("default_proxy", "") or "").strip()
    logs: list[str] = []

    def _do_group(group: list[dict]) -> dict:
        emails = [g["email"] for g in group]
        return _send_business_invites_batch(
            emails, lambda msg: logs.append(str(msg)), proxy=proxy,
            cookie_blob=cookie_blob, workspace_id=workspace_id,
            seat_type=body.seat_type,
        )

    invited_all: list = []
    errored_all: list[dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for res in ex.map(_do_group, groups):
            invited_all.extend(res.get("invited") or [])
            errored_all.extend(res.get("errored") or [])

    # invited 可能是 [str] 或 [{"email","invite_id"}](_send_business_invites_batch 成功时是后者)
    invited_emails: list[str] = []
    for x in invited_all:
        e = x.get("email") if isinstance(x, dict) else x
        e = str(e or "").strip().lower()
        if e:
            invited_emails.append(e)

    now = _utcnow()
    invited_ids = [email_to_id[e] for e in invited_emails if e in email_to_id]
    if invited_ids:
        with Session(engine) as s:
            for acc in s.exec(select(AccountModel).where(AccountModel.id.in_(invited_ids))).all():  # type: ignore[attr-defined]
                extra = acc.get_extra()
                extra["business_csv_status"] = "csv_uploaded"
                extra["business_csv_uploaded_at"] = now.isoformat()
                extra["business_master_id"] = str(master_id)
                extra["business_master_name"] = master_name
                extra["business_csv_invited_at"] = now.isoformat()
                acc.set_extra(extra)
                acc.updated_at = now
                s.add(acc)
            m2 = s.get(BusinessMasterModel, master_id)
            if m2:
                m2.invited_count = (m2.invited_count or 0) + len(invited_ids)
                m2.last_invite_at = now
                m2.updated_at = now
                s.add(m2)
            s.commit()

    if invited_ids:
        _refresh_stats_safe(master_id)   # 邀请后自动刷新空间信息(待接受邀请数会 +）

    # 识别「席位已满」错误, 给出清晰提示(而不是一堆 401)
    hint = ""
    joined_err = " ".join(str(e.get("message") or "") for e in errored_all)
    seat_full = ("maximum paid seats" in joined_err.lower()
                 or "seats_entitled" in joined_err.lower())
    if seat_full:
        seat_m = re.search(r"paid_seat_count=(\d+),\s*seats_entitled=(\d+)", joined_err)
        if seat_m:
            hint = (f"该母号 Team 席位已满(已用 {seat_m.group(1)} / 购买 {seat_m.group(2)}),"
                    f"OpenAI 拒绝新邀请。需补买席位(true up)或移除成员后再邀请。")
        else:
            hint = "该母号 Team 席位已满,OpenAI 拒绝新邀请。需补买席位(true up)或移除成员后再邀请。"
    elif errored_all and not invited_ids:
        hint = str((errored_all[0] or {}).get("message") or "")[:160]

    return {"ok": True, "master_id": master_id,
            "requested": count, "picked": len(pool),
            "invited": len(invited_ids), "errored": len(errored_all),
            "message": hint or None,
            "seat_full": seat_full,
            "invited_emails": invited_emails[:50],
            "errored_sample": errored_all[:10],
            "logs": logs[-10:]}
