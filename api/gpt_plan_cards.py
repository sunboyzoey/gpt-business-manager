"""GPT 套餐管理专属支付卡池 API

CRUD + 批量 CSV 导入。卡号脱敏返回(只在创建/编辑接口里要求完整卡号)。
状态机由 core/db.py 的 reserve_card/release_card/mark_card_* 维护,
本 API 只暴露列表/编辑/手动改状态/导入/统计。
"""
from __future__ import annotations

import io
import csv
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlmodel import Session, select, col

from core.db import GptPlanCardModel as CardModel, GptPlanPaymentAccountModel as PaymentAccountModel, engine


router = APIRouter(prefix="/cards", tags=["gpt-plan-cards"])

# 每个支付账号最多挂几张 U卡(默认账号 is_default=True 豁免)
_MAX_CARDS_PER_ACCOUNT = 5


def _card_count(session, payment_account_id: int) -> int:
    return len(session.exec(
        select(CardModel).where(CardModel.payment_account_id == payment_account_id)
    ).all())


def _check_account_capacity(session, payment_account_id: int, adding: int = 1) -> None:
    """校验支付账号是否还能再加 adding 张卡(默认账号不限)。超限抛 400。"""
    if not payment_account_id:
        raise HTTPException(400, "必须指定支付账号(payment_account_id)")
    pa = session.get(PaymentAccountModel, payment_account_id)
    if not pa:
        raise HTTPException(404, "支付账号不存在")
    if pa.is_default:
        return
    cur = _card_count(session, payment_account_id)
    if cur + adding > _MAX_CARDS_PER_ACCOUNT:
        raise HTTPException(400, f"该支付账号最多 {_MAX_CARDS_PER_ACCOUNT} 张 U卡(当前 {cur} 张)")

# 导入卡片时,未提供持卡人则每张随机生成一个真实姓名(避免所有卡同名)
_FALLBACK_FIRST = ["James", "Mary", "John", "Linda", "Robert", "Patricia", "Michael",
                   "Jennifer", "David", "Susan", "Daniel", "Karen", "Mark", "Nancy"]
_FALLBACK_LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
                  "Davis", "Wilson", "Anderson", "Taylor", "Moore", "Martin", "Clark"]


def _random_holder_name() -> str:
    """随机一个真实英文姓名(大写),用作卡导入时的默认持卡人。"""
    import random
    try:
        import names
        return str(names.get_full_name()).upper()
    except Exception:
        return f"{random.choice(_FALLBACK_FIRST)} {random.choice(_FALLBACK_LAST)}".upper()


def _max_card_priority(session) -> int:
    """当前卡池里的最大优先级数字(没有卡则 0)。"""
    vals = session.exec(select(CardModel.priority)).all()
    return max([int(p or 0) for p in vals], default=0)


# ---------------------------------------------------------------------------
# Pydantic 输入/输出
# ---------------------------------------------------------------------------


class CardIn(BaseModel):
    payment_account_id: int = 0     # U卡归属的支付账号(必填)
    label: str = ""
    number: str
    exp_month: int = Field(ge=1, le=12)
    exp_year: int = Field(ge=2024, le=2099)
    cvc: str
    holder_name: str = ""
    country: str = "US"
    state: str = ""
    city: str = ""
    address_line1: str = ""
    address_line2: str = ""
    postal_code: str = ""
    single_use: bool = True
    priority: int = 100
    note: str = ""

    @field_validator("number")
    @classmethod
    def _strip_number(cls, v: str) -> str:
        v = (v or "").replace(" ", "").replace("-", "")
        if not v.isdigit() or len(v) < 12 or len(v) > 19:
            raise ValueError("卡号必须是 12-19 位数字")
        return v

    @field_validator("cvc")
    @classmethod
    def _check_cvc(cls, v: str) -> str:
        v = (v or "").strip()
        if not v.isdigit() or len(v) not in (3, 4):
            raise ValueError("CVC 必须是 3 或 4 位数字")
        return v


class CardPatch(BaseModel):
    payment_account_id: Optional[int] = None    # 改归属(移到别的支付账号)
    opened_at: Optional[str] = None             # 开卡时间(ISO 字符串; 空串=清除)
    label: Optional[str] = None
    number: Optional[str] = None
    exp_month: Optional[int] = None
    exp_year: Optional[int] = None
    cvc: Optional[str] = None
    holder_name: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    postal_code: Optional[str] = None
    single_use: Optional[bool] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    note: Optional[str] = None
    # 手动改状态(谨慎)
    status: Optional[str] = None
    last_error: Optional[str] = None


def _serialize(card: CardModel, *, reveal: bool = False) -> dict:
    return {
        "id": card.id,
        "payment_account_id": getattr(card, "payment_account_id", 0),
        "opened_at": card.opened_at.isoformat() if getattr(card, "opened_at", None) else None,
        "label": card.label,
        "number_masked": card.masked(),
        "number": card.number if reveal else "",
        "exp_month": card.exp_month,
        "exp_year": card.exp_year,
        "cvc": card.cvc if reveal else "",
        "holder_name": card.holder_name,
        "country": card.country,
        "state": card.state,
        "city": card.city,
        "address_line1": card.address_line1,
        "address_line2": card.address_line2,
        "postal_code": card.postal_code,
        "status": card.status,
        "reserved_by_account_id": card.reserved_by_account_id,
        "reserved_at": card.reserved_at.isoformat() if card.reserved_at else None,
        "used_at": card.used_at.isoformat() if card.used_at else None,
        "last_error": card.last_error,
        "single_use": card.single_use,
        "enabled": card.enabled,
        "priority": getattr(card, "priority", 100),
        "use_count": getattr(card, "use_count", 0),
        "note": card.note,
        "created_at": card.created_at.isoformat() if card.created_at else None,
        "updated_at": card.updated_at.isoformat() if card.updated_at else None,
    }


# ---------------------------------------------------------------------------
# 「每张卡支付了多少个账号」: 付款摘要 gpt_plan_account_upgrades 是权威
# 数据源。用摘要的 payment_card_last4 匹配卡尾号；摘要明确记录了
# payment_account_id 时，再要求与卡的支付账号一致以消歧。
# ---------------------------------------------------------------------------

def _paid_accounts_by_card(session, cards: list) -> dict:
    """返回每张卡在 GPT 套餐目录中支付成功的账号。"""
    from core.db import GptPlanAccountModel, GptPlanAccountUpgradeModel

    wanted = [c for c in cards if (c.number or "")]
    if not wanted:
        return {}
    last4_set = {(c.number or "")[-4:] for c in wanted}
    # 建 last4 -> [(payment_account_id, account)] 索引。账号主表上的同名
    # 兼容字段不参与统计，避免与升级摘要发生漂移。
    idx: dict[str, list] = {}
    summaries = session.exec(
        select(GptPlanAccountUpgradeModel).where(
            col(GptPlanAccountUpgradeModel.payment_card_last4) != ""
        )
    ).all()
    for summary in summaries:
        l4 = str(summary.payment_card_last4 or "").strip()[-4:]
        if not l4 or l4 not in last4_set:
            continue
        account = session.get(GptPlanAccountModel, int(summary.account_id))
        if account is None:
            continue
        pa_id = int(summary.payment_account_id or 0)
        idx.setdefault(l4, []).append((pa_id, account))
    out: dict[int, list] = {}
    for c in wanted:
        l4 = (c.number or "")[-4:]
        card_pa = int(getattr(c, "payment_account_id", 0) or 0)
        hits = []
        for pa_id, p in idx.get(l4, []):
            if pa_id and card_pa and pa_id != card_pa:
                continue  # PRO 明确标了别的支付账号 → 跳过
            hits.append({
                "id": p.id,
                "email": p.email,
                "is_pro": bool(getattr(p, "is_pro", False)),
                "created_at": p.created_at.isoformat() if getattr(p, "created_at", None) else None,
            })
        out[c.id] = hits
    return out


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------


@router.get("")
def api_list(status: Optional[str] = None, enabled_only: bool = False,
             payment_account_id: Optional[int] = None):
    """列表(脱敏)。可按 status / payment_account_id 过滤。每张卡附带 paid_account_count(支付过的账号数)"""
    with Session(engine) as session:
        stmt = select(CardModel)
        if status:
            stmt = stmt.where(CardModel.status == status)
        if enabled_only:
            stmt = stmt.where(CardModel.enabled == True)  # noqa: E712
        if payment_account_id is not None:
            stmt = stmt.where(CardModel.payment_account_id == payment_account_id)
        stmt = stmt.order_by(CardModel.priority.asc(), CardModel.id.desc())
        rows = session.exec(stmt).all()
        paid = _paid_accounts_by_card(session, rows)
        items = []
        for c in rows:
            d = _serialize(c)
            d["paid_account_count"] = len(paid.get(c.id, []))
            items.append(d)
        return {"items": items}


@router.get("/{card_id}/paid-accounts")
def api_card_paid_accounts(card_id: int):
    """该卡支付成功的 PRO 账号明细(按尾号+支付账号匹配)。用于卡片上点开查看。"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            raise HTTPException(404, "卡不存在")
        accounts = _paid_accounts_by_card(session, [card]).get(card_id, [])
        return {"card_id": card_id, "last4": (card.number or "")[-4:],
                "count": len(accounts), "accounts": accounts}


@router.get("/stats")
def api_stats():
    """池子概况:各状态数量、未用卡的可用数"""
    with Session(engine) as session:
        rows = session.exec(select(CardModel)).all()
        counts: dict[str, int] = {}
        for c in rows:
            counts[c.status] = counts.get(c.status, 0) + 1
        unused_available = sum(1 for c in rows if c.status == "unused" and c.enabled)
        return {
            "total": len(rows),
            "by_status": counts,
            "unused_available": unused_available,
        }


@router.get("/{card_id}")
def api_get(card_id: int, reveal: bool = False):
    """单条详情。reveal=true 返回完整卡号(谨慎)"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            raise HTTPException(404, "卡不存在")
        return _serialize(card, reveal=reveal)


@router.post("")
def api_create(req: CardIn):
    """新增一张卡"""
    with Session(engine) as session:
        _check_account_capacity(session, req.payment_account_id, adding=1)
        existing = session.exec(
            select(CardModel).where(CardModel.number == req.number)
        ).first()
        if existing:
            raise HTTPException(400, f"卡号已存在 (id={existing.id})")
        now = datetime.now(timezone.utc)
        card = CardModel(
            payment_account_id=req.payment_account_id,
            opened_at=now,
            label=req.label,
            number=req.number,
            exp_month=req.exp_month,
            exp_year=req.exp_year,
            cvc=req.cvc,
            holder_name=req.holder_name,
            country=req.country,
            state=req.state,
            city=req.city,
            address_line1=req.address_line1,
            address_line2=req.address_line2,
            postal_code=req.postal_code,
            single_use=req.single_use,
            priority=req.priority,
            note=req.note,
            status="unused",
            created_at=now,
            updated_at=now,
        )
        session.add(card)
        session.commit()
        session.refresh(card)
        return _serialize(card)


@router.patch("/{card_id}")
def api_update(card_id: int, patch: CardPatch):
    """编辑卡。status 字段允许手动改(例如把 failed 拉回 unused 重试)"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            raise HTTPException(404, "卡不存在")
        data = patch.model_dump(exclude_unset=True)
        if "number" in data:
            n = (data["number"] or "").replace(" ", "").replace("-", "")
            if not n.isdigit() or len(n) < 12 or len(n) > 19:
                raise HTTPException(400, "卡号必须是 12-19 位数字")
            data["number"] = n
        if "status" in data and data["status"] not in (
            "unused", "in_use", "used", "failed", "disabled",
        ):
            raise HTTPException(400, "status 必须是 unused/in_use/used/failed/disabled")
        # 改归属到别的支付账号 → 校验目标账号容量
        if "payment_account_id" in data and int(data["payment_account_id"] or 0) != int(card.payment_account_id or 0):
            _check_account_capacity(session, int(data["payment_account_id"] or 0), adding=1)
        # opened_at 字符串 → datetime(空串=清除)
        if "opened_at" in data:
            raw = (data.pop("opened_at") or "").strip()
            if raw:
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    card.opened_at = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except Exception:
                    raise HTTPException(400, "opened_at 格式无效(需 ISO 时间)")
            else:
                card.opened_at = None
        for k, v in data.items():
            setattr(card, k, v)
        # 改回 unused 时清理占用信息
        if data.get("status") == "unused":
            card.reserved_by_account_id = 0
            card.reserved_at = None
            card.used_at = None
            card.last_error = ""
        card.updated_at = datetime.now(timezone.utc)
        session.add(card)
        session.commit()
        session.refresh(card)
        return _serialize(card)


@router.delete("/{card_id}")
def api_delete(card_id: int):
    """删除卡(物理删除)。在用中的卡也允许删,但不建议"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            raise HTTPException(404, "卡不存在")
        session.delete(card)
        session.commit()
        return {"ok": True, "deleted_id": card_id}


class ImportRow(BaseModel):
    """CSV 一行的字段。number/exp_month/exp_year/cvc 必填。"""
    label: str = ""
    number: str
    exp_month: int
    exp_year: int
    cvc: str
    holder_name: str = ""
    country: str = "US"
    state: str = ""
    city: str = ""
    address_line1: str = ""
    address_line2: str = ""
    postal_code: str = ""
    single_use: bool = True
    note: str = ""


class ImportRequest(BaseModel):
    csv_text: str  # 整段 CSV 文本(含表头)
    payment_account_id: int = 0     # 导入的卡归属到哪个支付账号(必填)


def _parse_exp(raw: str) -> tuple[int, int]:
    """解析 '06/29' / '06/2029' / '06-29' 等 → (month, year4)。失败抛 ValueError。"""
    s = (raw or "").strip()
    m = re.match(r"^\s*(\d{1,2})\s*[/\-.]\s*(\d{2,4})\s*$", s)
    if not m:
        raise ValueError(f"有效期格式无效: {raw!r}")
    month = int(m.group(1))
    year = int(m.group(2))
    if year < 100:
        year += 2000
    if not (1 <= month <= 12):
        raise ValueError(f"月份无效: {month}")
    return month, year


def _parse_labeled_cards(text: str) -> list[dict]:
    """解析带标签的多行卡片格式(每张卡一个块),例如:
        Card Number: 493724202571978212
        Valid Thru: 06/29
        CVV: 390
    标签大小写不敏感,支持 Card Number/Number/卡号、Valid Thru/Exp/有效期、CVV/CVC/安全码。
    返回 [{number, exp, cvc}, ...]。
    """
    cards: list[dict] = []
    cur: dict = {}

    def _flush():
        if cur.get("number"):
            cards.append(dict(cur))
        cur.clear()

    num_re = re.compile(r"^\s*(?:card\s*number|card\s*no\.?|number|卡号)\s*[:：]\s*(.+)$", re.I)
    exp_re = re.compile(r"^\s*(?:valid\s*thru|valid\s*through|expir\w*|exp\.?(?:\s*date)?|有效期)\s*[:：]\s*(.+)$", re.I)
    cvv_re = re.compile(r"^\s*(?:cvv2?|cvc2?|security\s*code|安全码|安全代码)\s*[:：]\s*(.+)$", re.I)

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = num_re.match(s)
        if m:
            if cur.get("number"):
                _flush()
            cur["number"] = re.sub(r"\D", "", m.group(1))
            continue
        m = exp_re.match(s)
        if m:
            cur["exp"] = m.group(1).strip()
            continue
        m = cvv_re.match(s)
        if m:
            cur["cvc"] = re.sub(r"\D", "", m.group(1))
            continue
    _flush()
    return cards


@router.post("/import")
def api_import(req: ImportRequest):
    """批量导入。支持两种格式(自动识别):

    1) 带标签多行块(每张卡一块):
        Card Number: 493724202571978212
        Valid Thru: 06/29
        CVV: 390
    2) CSV(表头至少含 number,exp_month,exp_year,cvc;可选 label/holder_name/
       country/state/city/address_line1/address_line2/postal_code/single_use/note)
    """
    text = (req.csv_text or "").strip()
    if not text:
        raise HTTPException(400, "csv_text 为空")
    if not req.payment_account_id:
        raise HTTPException(400, "导入必须指定支付账号(payment_account_id)")
    with Session(engine) as _s0:
        _pa = _s0.get(PaymentAccountModel, req.payment_account_id)
        if not _pa:
            raise HTTPException(404, "支付账号不存在")

    # —— 格式 1: 带标签多行块 ——
    if re.search(r"card\s*number|valid\s*thru|^\s*cv[vc]\b", text, re.I | re.M):
        labeled = _parse_labeled_cards(text)
        if not labeled:
            raise HTTPException(400, "未解析到任何卡片(检查 Card Number / Valid Thru / CVV 标签)")
        ok, fail, errors = 0, 0, []
        now = datetime.now(timezone.utc)
        with Session(engine) as session:
            next_priority = _max_card_priority(session) + 1  # 新卡排到当前最大优先级之后
            for idx, c in enumerate(labeled, start=1):
                try:
                    number = (c.get("number") or "")
                    if not number.isdigit() or len(number) < 12 or len(number) > 19:
                        raise ValueError("卡号格式无效")
                    if session.exec(select(CardModel).where(CardModel.number == number)).first():
                        raise ValueError("卡号已存在")
                    _check_account_capacity(session, req.payment_account_id, adding=1)
                    month, year = _parse_exp(c.get("exp", ""))
                    cvc = c.get("cvc") or ""
                    if not cvc.isdigit() or len(cvc) not in (3, 4):
                        raise ValueError("CVC 格式无效")
                    session.add(CardModel(
                        payment_account_id=req.payment_account_id, opened_at=now,
                        number=number, exp_month=month, exp_year=year, cvc=cvc,
                        holder_name=(c.get("holder_name") or _random_holder_name()),
                        priority=next_priority,
                        country="US", single_use=True, status="unused",
                        created_at=now, updated_at=now,
                    ))
                    session.commit()
                    ok += 1
                    next_priority += 1   # 同批多张依次递增,保持导入顺序
                except Exception as exc:
                    session.rollback()
                    fail += 1
                    errors.append(f"卡 {idx} ({(c.get('number') or '')[-4:]}): {exc}")
        return {"ok": ok, "fail": fail, "errors": errors[:50]}

    # —— 格式 2: CSV ——
    reader = csv.DictReader(io.StringIO(text))
    required = {"number", "exp_month", "exp_year", "cvc"}
    if not required.issubset({(c or "").strip().lower() for c in (reader.fieldnames or [])}):
        raise HTTPException(400, f"CSV 表头必须含: {sorted(required)}")

    ok, fail, errors = 0, 0, []
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        next_priority = _max_card_priority(session) + 1
        for i, raw in enumerate(reader, start=2):  # row 1 是表头
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            try:
                number = row["number"].replace(" ", "").replace("-", "")
                if not number.isdigit() or len(number) < 12 or len(number) > 19:
                    raise ValueError("卡号格式无效")
                # 重复跳过
                if session.exec(
                    select(CardModel).where(CardModel.number == number)
                ).first():
                    raise ValueError("卡号已存在")
                exp_month = int(row["exp_month"])
                exp_year = int(row["exp_year"])
                if exp_year < 100:  # 兼容 2 位年份
                    exp_year += 2000
                cvc = row["cvc"]
                if not cvc.isdigit() or len(cvc) not in (3, 4):
                    raise ValueError("CVC 格式无效")
                _check_account_capacity(session, req.payment_account_id, adding=1)
                single_use_raw = row.get("single_use", "1").lower()
                single_use = single_use_raw in {"1", "true", "yes", "y", "t"}
                # 优先级: CSV 给了就用,否则按当前最大值+1 依次递增
                try:
                    pri = int(row["priority"]) if row.get("priority") else next_priority
                except (TypeError, ValueError):
                    pri = next_priority
                card = CardModel(
                    payment_account_id=req.payment_account_id, opened_at=now,
                    label=row.get("label", ""),
                    number=number,
                    exp_month=exp_month,
                    exp_year=exp_year,
                    cvc=cvc,
                    holder_name=(row.get("holder_name") or _random_holder_name()),
                    country=row.get("country", "US") or "US",
                    state=row.get("state", ""),
                    city=row.get("city", ""),
                    address_line1=row.get("address_line1", ""),
                    address_line2=row.get("address_line2", ""),
                    postal_code=row.get("postal_code", ""),
                    single_use=single_use,
                    priority=pri,
                    note=row.get("note", ""),
                    status="unused",
                    created_at=now,
                    updated_at=now,
                )
                session.add(card)
                session.commit()
                ok += 1
                next_priority = max(next_priority, pri) + 1
            except Exception as exc:
                session.rollback()
                fail += 1
                errors.append(f"行 {i}: {exc}")
    return {"ok": ok, "fail": fail, "errors": errors[:50]}


# ===========================================================================
# 支付账号(Payment Account)—— 卡的父级。类型 Y卡/E卡, 下挂最多 5 张 U卡。
# ===========================================================================

pa_router = APIRouter(prefix="/payment-accounts", tags=["gpt-plan-payment-accounts"])


_OPEN_CARD_INTERVAL_SECONDS = 24 * 3600   # E卡 24 小时只能开一张


class PaymentAccountIn(BaseModel):
    name: str
    account_type: str = "Y"          # Y = Y卡, E = E卡
    roxy_dir_id: str = ""            # 指纹浏览器 profile ID
    note: str = ""


class PaymentAccountPatch(BaseModel):
    name: Optional[str] = None
    account_type: Optional[str] = None
    roxy_dir_id: Optional[str] = None
    enabled: Optional[bool] = None
    note: Optional[str] = None


def _aware(dt):
    return None if dt is None else (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))


# ether.fi 交易日期是西/葡文(如 "mar, 11 ago 2026")→ 转中文 "2026年8月11日 周二"
_ES_PT_MONTH = {
    "ene": 1, "jan": 1, "feb": 2, "fev": 2, "mar": 3, "abr": 4, "may": 5, "mai": 5,
    "jun": 6, "jul": 7, "ago": 8, "sep": 9, "set": 9, "oct": 10, "out": 10,
    "nov": 11, "dic": 12, "dez": 12,
}
_ES_PT_WEEKDAY = {
    "lun": "周一", "seg": "周一", "mar": "周二", "ter": "周二", "mié": "周三", "mie": "周三",
    "qua": "周三", "jue": "周四", "qui": "周四", "vie": "周五", "sex": "周五",
    "sáb": "周六", "sab": "周六", "dom": "周日",
}


def _date_to_zh(s: str) -> str:
    """把 ether.fi 的西/葡文日期转成中文; 解析不了则原样返回。"""
    s = (s or "").strip()
    if not s:
        return s
    wd = ""
    rest = s
    if "," in s:
        head, rest = s.split(",", 1)
        wd = head.strip().lower()
        rest = rest.strip()
    m = re.match(r"(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\.?\s+(20\d\d)", rest)
    if not m:
        return s
    day = int(m.group(1))
    mon = _ES_PT_MONTH.get(m.group(2).lower()[:3])
    if not mon:
        return s
    out = f"{m.group(3)}年{mon}月{day}日"
    wd_zh = _ES_PT_WEEKDAY.get(wd)
    return f"{out} {wd_zh}" if wd_zh else out


def _serialize_pa(pa: PaymentAccountModel, *, card_count: int = 0, status_counts: Optional[dict] = None,
                  newest_card_opened_at=None) -> dict:
    import json as _json
    # E卡开卡冷却:按"最新一张卡的开卡时间"和"手动开卡时间"取较晚者 + 24h
    manual = _aware(getattr(pa, "last_card_opened_at", None))
    newest_card = _aware(newest_card_opened_at)
    opened_at = max([t for t in (manual, newest_card) if t], default=None)
    cooldown = 0
    if pa.account_type == "E" and opened_at:
        try:
            elapsed = (datetime.now(timezone.utc) - opened_at).total_seconds()
            cooldown = max(0, int(_OPEN_CARD_INTERVAL_SECONDS - elapsed))
        except Exception:
            cooldown = 0
    return {
        "id": pa.id,
        "name": pa.name,
        "account_type": pa.account_type,       # "Y" | "E"
        "enabled": pa.enabled,
        "is_default": pa.is_default,
        "roxy_dir_id": getattr(pa, "roxy_dir_id", "") or "",
        "note": pa.note,
        "card_count": card_count,
        "max_cards": None if pa.is_default else _MAX_CARDS_PER_ACCOUNT,
        "status_counts": status_counts or {},
        # E卡开卡:上次开卡时间 + 冷却剩余秒数(0=现在可开)。Y卡不限,cooldown 恒 0。
        "last_card_opened_at": opened_at.isoformat() if opened_at else None,
        "open_cooldown_seconds": cooldown,
        # 账号余额(ether.fi Saldo total)
        "balance_usd": getattr(pa, "balance_usd", 0.0) or 0.0,
        "balance_text": getattr(pa, "balance_text", "") or "",
        "balance_updated_at": pa.balance_updated_at.isoformat() if getattr(pa, "balance_updated_at", None) else None,
        # 交易统计(ether.fi 交易记录): 支付/成功退款/待退款
        "paid_count": getattr(pa, "paid_count", 0) or 0,
        "refunded_count": getattr(pa, "refunded_count", 0) or 0,
        "pending_refund_count": getattr(pa, "pending_refund_count", 0) or 0,
        "card_open_count": getattr(pa, "card_open_count", 0) or 0,
        # 未发起退款 = 支付 − 已退 − 待退; unrefunded_dates 为这些支付的日期(最近 N 笔)
        "unrefunded_count": max(0, (getattr(pa, "paid_count", 0) or 0)
                                - (getattr(pa, "refunded_count", 0) or 0)
                                - (getattr(pa, "pending_refund_count", 0) or 0)),
        "unrefunded_dates": [_date_to_zh(d) for d in _json.loads(getattr(pa, "unrefunded_dates_json", "[]") or "[]")],
        "pending_refund_updated_at": pa.pending_refund_updated_at.isoformat() if getattr(pa, "pending_refund_updated_at", None) else None,
        "created_at": pa.created_at.isoformat() if pa.created_at else None,
        "updated_at": pa.updated_at.isoformat() if pa.updated_at else None,
    }


@pa_router.get("")
def pa_list():
    """支付账号列表 + 每个账号的 U卡 数量/状态统计。"""
    with Session(engine) as s:
        accounts = s.exec(select(PaymentAccountModel).order_by(PaymentAccountModel.id.asc())).all()
        cards = s.exec(select(CardModel)).all()
        by_acc: dict[int, list] = {}
        for c in cards:
            by_acc.setdefault(int(c.payment_account_id or 0), []).append(c)
        out = []
        for pa in accounts:
            lst = by_acc.get(int(pa.id), [])
            sc: dict[str, int] = {}
            for c in lst:
                sc[c.status] = sc.get(c.status, 0) + 1
            newest = max([_aware(c.opened_at) for c in lst if getattr(c, "opened_at", None)], default=None)
            out.append(_serialize_pa(pa, card_count=len(lst), status_counts=sc, newest_card_opened_at=newest))
        return {"items": out}


def _newest_card_opened_at(session, pa_id: int):
    cards = session.exec(select(CardModel).where(CardModel.payment_account_id == pa_id)).all()
    return max([_aware(c.opened_at) for c in cards if getattr(c, "opened_at", None)], default=None)


@pa_router.post("")
def pa_create(req: PaymentAccountIn):
    """新建支付账号(只需名称 + 类型 Y/E)。"""
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(400, "账号名称不能为空")
    at = (req.account_type or "Y").strip().upper()
    if at not in ("Y", "E"):
        raise HTTPException(400, "account_type 必须是 Y 或 E")
    now = datetime.now(timezone.utc)
    with Session(engine) as s:
        pa = PaymentAccountModel(name=name, account_type=at, note=req.note or "",
                                 roxy_dir_id=(req.roxy_dir_id or "").strip(),
                                 created_at=now, updated_at=now)
        s.add(pa)
        s.commit()
        s.refresh(pa)
        return _serialize_pa(pa, card_count=0)


@pa_router.patch("/{pa_id}")
def pa_update(pa_id: int, patch: PaymentAccountPatch):
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        data = patch.model_dump(exclude_unset=True)
        if "account_type" in data:
            at = (data["account_type"] or "").strip().upper()
            if at not in ("Y", "E"):
                raise HTTPException(400, "account_type 必须是 Y 或 E")
            data["account_type"] = at
        if "name" in data and not (data["name"] or "").strip():
            raise HTTPException(400, "账号名称不能为空")
        for k, v in data.items():
            setattr(pa, k, v)
        pa.updated_at = datetime.now(timezone.utc)
        s.add(pa)
        s.commit()
        s.refresh(pa)
        cnt = _card_count(s, pa_id)
        return _serialize_pa(pa, card_count=cnt, newest_card_opened_at=_newest_card_opened_at(s, pa_id))


@pa_router.delete("/{pa_id}")
def pa_delete(pa_id: int, force: bool = False):
    """删除支付账号。默认在其下还有 U卡 时拒绝(force=true 连同 U卡 一起删)。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        cards = s.exec(select(CardModel).where(CardModel.payment_account_id == pa_id)).all()
        if cards and not force:
            raise HTTPException(400, f"该支付账号下还有 {len(cards)} 张 U卡,请先移走/删除,或用 force=true 一并删除")
        for c in cards:
            s.delete(c)
        s.delete(pa)
        s.commit()
        return {"ok": True, "deleted_id": pa_id, "deleted_cards": len(cards)}


@pa_router.post("/{pa_id}/mark-opened")
def pa_mark_opened(pa_id: int):
    """标记该 E卡 账号"今天已开卡"(记 now),开始 24h 倒计时。仍在冷却期内拒绝。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        if pa.account_type != "E":
            raise HTTPException(400, "只有 E卡 账号有开卡冷却")
        opened = getattr(pa, "last_card_opened_at", None)
        if opened:
            ts = opened if opened.tzinfo else opened.replace(tzinfo=timezone.utc)
            left = _OPEN_CARD_INTERVAL_SECONDS - (datetime.now(timezone.utc) - ts).total_seconds()
            if left > 0:
                raise HTTPException(400, f"还在开卡冷却中,约 {int(left // 3600)}h{int((left % 3600) // 60)}m 后可再开")
        pa.last_card_opened_at = datetime.now(timezone.utc)
        pa.updated_at = datetime.now(timezone.utc)
        s.add(pa)
        s.commit()
        s.refresh(pa)
        return _serialize_pa(pa, card_count=_card_count(s, pa_id), newest_card_opened_at=_newest_card_opened_at(s, pa_id))


class PaResetOpenedRequest(BaseModel):
    pass


@pa_router.post("/{pa_id}/reset-opened")
def pa_reset_opened(pa_id: int):
    """清除开卡冷却(误点/重置用)。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        pa.last_card_opened_at = None
        pa.updated_at = datetime.now(timezone.utc)
        s.add(pa)
        s.commit()
        s.refresh(pa)
        return _serialize_pa(pa, card_count=_card_count(s, pa_id), newest_card_opened_at=_newest_card_opened_at(s, pa_id))


def _profile_dir_id(row: dict) -> str:
    return str(row.get("dirId") or row.get("dir_id") or row.get("id") or "").strip()


def _profile_name(row: dict) -> str:
    return str(row.get("windowName") or row.get("window_name") or row.get("name") or "").strip()


def _minimize_window(page) -> None:
    """把指纹浏览器窗口最小化到后台(自动抓取时不抢焦点)。best-effort。"""
    try:
        page.set.window.mini()
    except Exception:
        pass


def _close_roxy_window(dir_id: str) -> None:
    """抓取结束后关闭该指纹浏览器窗口(不留痕)。best-effort, 失败静默。"""
    try:
        from core.roxy_browser import RoxyBrowserClient, load_roxy_config
        cfg = load_roxy_config()
        RoxyBrowserClient(cfg["api_host"], cfg["token"]).close_window(str(dir_id or "").strip())
    except Exception:
        pass


_ETHERFI_ACTIVE_CARD_ROW_RE = re.compile(
    r"(?:Virtual|Ativ|Activ|Active|虛擬|虚拟).*(?:Ativ|Activ|Active|使用中|啟用|启用)"
    r"|(?:Ativ|Activ|Active|使用中|啟用|启用).*(?:Virtual|虛擬|虚拟)",
    re.I,
)
_ETHERFI_REVEAL_RE = re.compile(
    r"ver\s*detal|mostrar\s*detal|show\s*(?:card\s*)?details?|"
    r"display\s*(?:card\s*)?details?|顯示(?:卡片)?詳情|显示(?:卡片)?详情|"
    r"查看(?:卡片)?詳情|查看(?:卡片)?详情",
    re.I,
)
_ETHERFI_HIDE_RE = re.compile(
    r"ocultar(?:\s*detal)?|hide(?:\s*(?:card\s*)?details?)?|隱藏|隐藏",
    re.I,
)


def _etherfi_active_card_last4(row_text: str) -> str:
    """从 ether.fi 多语言卡片行提取活跃虚拟卡末四位。"""
    text = str(row_text or "")
    match = re.search(r"(?<!\d)(\d{4})(?!\d)", text)
    if not match or not _ETHERFI_ACTIVE_CARD_ROW_RE.search(text):
        return ""
    return match.group(1)


def _parse_etherfi_revealed_card(text: str, want_l4: str | None = None) -> dict | None:
    """解析已揭示的 ether.fi 卡详情，兼容中/英/西/葡文字段标签。"""
    value = re.sub(r"\s+", " ", str(text or ""))
    number_match = None
    if want_l4 and re.fullmatch(r"\d{4}", str(want_l4)):
        number_match = re.search(
            r"(?<!\d)((?:\d[\s-]*){12}" + re.escape(str(want_l4)) + r")(?!\d)",
            value,
        )
    if not number_match:
        number_match = (
            re.search(
                r"(?:card\s*number|n[úu]mero\s+d[eo]\s+(?:tarjeta|cart[ãa]o)|"
                r"卡片號碼|卡片号码|卡號|卡号)\s*[:：]?\s*"
                r"((?:\d[\s-]*){16})(?!\d)",
                value,
                re.I,
            )
            or re.search(r"(?<!\d)((?:\d[\s-]*){16})(?!\d)", value)
        )
    if not number_match:
        return None

    number = re.sub(r"\D", "", number_match.group(1))
    if len(number) != 16 or (want_l4 and not number.endswith(str(want_l4))):
        return None

    # 卡详情通常把 EXP/CVV 标签放在卡号后面。扩大读取窗口并允许多语言标签，
    # 不再要求有效期后立刻就是 CVC 数字。
    after = value[number_match.end():number_match.end() + 260]
    exp_match = re.search(
        r"(?:EXP(?:IRY|IRATION)?(?:\s*DATE)?|VALID\s*THRU|VALIDADE|VENCIMENTO|"
        r"有效期(?:限)?|到期日?)?\s*[:：]?\s*"
        r"(0?[1-9]|1[0-2])\s*/\s*(\d{2,4})",
        after,
        re.I,
    )
    cvc_match = re.search(
        r"(?:CVV|CVC|C[ÓO]DIGO\s+DE\s+SEGURAN[ÇC]A|安全碼|安全码)\s*[:：]?\s*(\d{3,4})",
        after,
        re.I,
    )
    # 当前繁中页面先横向渲染标签「有效期限 (MM/YY)  CVV」，下一行才是
    # 「8/30  224」，因此 CVV 标签与数值并不相邻。此时取有效期之后的
    # 第一个 3/4 位独立数字作为 CVC。
    if exp_match and not cvc_match:
        cvc_match = re.search(r"(?<!\d)(\d{3,4})(?!\d)", after[exp_match.end():])
    if not exp_match or not cvc_match:
        return None

    year = int(exp_match.group(2))
    if year < 100:
        year += 2000
    return {
        "number": number,
        "exp_month": int(exp_match.group(1)),
        "exp_year": year,
        "cvc": cvc_match.group(1),
    }


def _scrape_etherfi_cards(dir_id: str, log=lambda m: None) -> list[dict]:
    """在该指纹浏览器窗口里打开 ether.fi Cash 卡页, 逐张点「Ver detalles」读完整卡号/有效期/CVV。
    返回 [{number, exp_month, exp_year, cvc}, ...](按卡号去重)。best-effort, 失败某张跳过。"""
    import re as _re
    import time as _time
    from core.roxy_browser import open_existing_window
    page = open_existing_window(dir_id, log=log)
    # 注意: 不要最小化! 同步卡靠点表格行切换详情面板(React 重渲染), 窗口最小化时
    # Chromium 判为 hidden、暂停渲染 → 点行不切卡, 每张都读成第一张。刷余额只读文本可最小化。
    page.get("https://www.ether.fi/app/cash/card")
    _time.sleep(4)

    def _txt() -> str:
        return _re.sub(r"\s+", " ", _re.sub(r"<[^>]+>", " ", page.html))

    def _click(pat: str) -> bool:
        for e in page.eles('xpath://button | //*[@role="button"] | //*[contains(@class,"cursor-pointer")]'):
            if _re.search(pat, (e.text or ""), _re.I):
                try:
                    e.click()
                    _time.sleep(2.2)
                    return True
                except Exception:
                    return False
        return False

    def _read(want_l4: str | None = None) -> dict | None:
        return _parse_etherfi_revealed_card(_txt(), want_l4)

    def _click_row(l4: str) -> bool:
        """点「Seus cartões」表里末四位为 l4 的行, 打开该卡的详情面板(揭示按钮才会出现)。"""
        for tr in page.eles('xpath://tr'):
            if l4 in (tr.text or ""):
                try:
                    tr.click()
                    _time.sleep(2)
                    return True
                except Exception:
                    return False
        return False

    # 揭示/收起明细按钮多语言: ES「Ver detalles / Ocultar detalles」, PT「Ver Detalhes / Ocultar」
    def _reveal_read(want_l4: str | None = None) -> dict | None:
        _click(_ETHERFI_REVEAL_RE.pattern)
        for _ in range(4):                         # 揭示后卡号渲染有延迟, 重试读取
            c = _read(want_l4)
            if c and (not want_l4 or c["number"].endswith(want_l4)):
                return c
            _time.sleep(1)
        return _read(want_l4)

    # 卡列表末四位(判断共有几张卡); 行文案 PT/ES: Virtual + Ativo/Activa/Active
    last4: list[str] = []
    for tr in page.eles('xpath://tr'):
        value = _etherfi_active_card_last4(tr.text or "")
        if value and value not in last4:
            last4.append(value)
    log(f"[etherfi] 卡列表 last4: {last4 or '(无表格, 只读当前卡)'}")

    results: dict[str, dict] = {}
    if not last4:
        # 无表格: 直接尝试揭示当前卡
        c = _reveal_read()
        if c:
            results[c["number"]] = c
        else:
            log("[etherfi] 未发现可识别的活跃卡行，且当前卡详情未完整揭示")
    else:
        for l4 in last4:
            _click(_ETHERFI_HIDE_RE.pattern)  # 收起上一张明细
            # 关键: 卡页初始不显示「Ver Detalhes」, 必须先点该卡在表格里的行, 详情面板才出现
            _click_row(l4)
            c = _reveal_read(l4)          # 揭示并读取(锁定末四位=l4)
            if c:
                results[c["number"]] = c
                log(f"[etherfi] 读到卡 ****{c['number'][-4:]} {c['exp_month']}/{str(c['exp_year'])[-2:]}")
            else:
                log(f"[etherfi] 卡 ****{l4} 未读到完整卡号/有效期/CVC（可能仍需验证或页面结构已变化）")
    return list(results.values())


@pa_router.post("/{pa_id}/sync-cards-from-browser")
def pa_sync_cards_from_browser(pa_id: int):
    """在该账号的指纹浏览器里自动抓 ether.fi 的完整卡信息, 按卡号去重后建 U卡(已存在忽略)。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        dir_id = (getattr(pa, "roxy_dir_id", "") or "").strip()
    if not dir_id:
        raise HTTPException(400, "该账号没有指纹浏览器ID,请先点「浏览器」打开并绑定一次")
    logs: list[str] = []
    try:
        cards = _scrape_etherfi_cards(dir_id, log=lambda m: logs.append(str(m)))
    except Exception as e:
        raise HTTPException(502, f"抓取卡信息失败: {e}")
    finally:
        _close_roxy_window(dir_id)   # 抓完自动关窗(后台无痕)
    synced: list[str] = []
    backfilled: list[str] = []
    skipped: list[str] = []
    now = datetime.now(timezone.utc)
    with Session(engine) as s:
        # ① 新卡入库(抓到完整卡号时)
        for c in cards:
            num = c["number"]
            exist = s.exec(select(CardModel).where(CardModel.number == num)).first()
            if exist:
                skipped.append(f"****{num[-4:]}")
                continue
            try:
                _check_account_capacity(s, pa_id, adding=1)
            except HTTPException:
                skipped.append(f"****{num[-4:]}(超5张)")
                continue
            s.add(CardModel(
                payment_account_id=pa_id, number=num, opened_at=now,
                exp_month=c["exp_month"], exp_year=c["exp_year"], cvc=c["cvc"],
                holder_name=_random_holder_name(), country="US", single_use=True, status="unused",
                priority=_max_card_priority(s) + 1, label="ether.fi",
                created_at=now, updated_at=now,
            ))
            s.commit()
            synced.append(f"****{num[-4:]}")
        # ② 开卡时间回填:不依赖能否抓到完整卡号——库里已有的卡直接用各自 created_at 回填。
        #    (这样即便 ether.fi 揭示被 passkey 门控、抓不到卡, 已存在卡的开卡时间也能补上)
        for exist in s.exec(select(CardModel).where(CardModel.payment_account_id == pa_id)).all():
            if getattr(exist, "opened_at", None) is None:
                exist.opened_at = exist.created_at or now
                exist.updated_at = now
                s.add(exist)
                s.commit()
                backfilled.append(f"****{(exist.number or '')[-4:]}")
    if not cards and not backfilled:
        return {"ok": True, "found": 0, "synced": 0, "backfilled": 0, "skipped": 0,
                "message": "没抓到卡(需先在浏览器里登录/过验证,或页面结构变了)", "logs": logs[-8:]}
    return {"ok": True, "found": len(cards), "synced": len(synced),
            "backfilled": len(backfilled), "skipped": len(skipped),
            "synced_cards": synced, "backfilled_cards": backfilled, "skipped_cards": skipped,
            "logs": logs[-8:]}


def _scrape_etherfi_balance(dir_id: str, log=lambda m: None, page=None) -> dict:
    """在指纹浏览器里打开 ether.fi Cash 保险库页(safe), 读 Saldo total 总余额 + 明细。
    返回 {balance_usd: float, balance_text: str}。读不到返回 {}。
    传入 page 则复用该已打开窗口(不另开/不关), 供与其它抓取共用一个会话。"""
    import re as _re
    import time as _time
    if page is None:
        from core.roxy_browser import open_existing_window
        page = open_existing_window(dir_id, log=log)
        _minimize_window(page)
    page.get("https://www.ether.fi/app/cash/safe")
    _time.sleep(5)
    vis = page.ele('tag:body').text
    lines = [ln.strip() for ln in vis.split("\n") if ln.strip()]
    # 总余额标签多语言/多版本: ether.fi 曾用「Saldo total」, 现改为「Patrimonio Neto」(净资产);
    # 兼容 ES/PT/EN 各种写法。找到标签后, 从该行起几行内取第一个 $金额。
    _BAL_LABEL = _re.compile(
        r"Saldo total|Patrimonio Neto|Patrim[oô]nio L[íi]quido|Patrim[oô]nio|"
        r"Net\s*Worth|Total\s*Balance|Saldo",
        _re.I)
    total = None
    for i, ln in enumerate(lines):
        if _BAL_LABEL.search(ln):
            for j in range(i, min(i + 4, len(lines))):
                m = _re.search(r"\$([\d,]+\.\d{2})", lines[j])
                if m:
                    total = float(m.group(1).replace(",", ""))
                    break
            if total is not None:
                break
    # 兜底: 有些版本 safe 页不显示「净资产」标签, 净资产就是页面**最顶部**第一个 $金额
    # (资产明细的单价/持仓在后面)。取前若干行里的第一个 $X.XX。
    if total is None:
        for ln in lines[:20]:
            m = _re.search(r"\$([\d,]+\.\d{2})", ln)
            if m:
                total = float(m.group(1).replace(",", ""))
                break
    if total is None:
        return {}
    # 明细: USDC / USDT 各自金额
    detail = []
    for tok in ("USDC", "USDT", "DAI"):
        for k, ln in enumerate(lines):
            if ln == tok or _re.search(rf"\b{tok}\b", ln):
                m = _re.search(r"\$([\d,]+\.\d{2})", ln) or (_re.search(r"\$([\d,]+\.\d{2})", lines[k - 1]) if k > 0 else None)
                if m:
                    detail.append(f"{tok} ${m.group(1)}")
                break
    return {"balance_usd": total, "balance_text": " · ".join(detail)}


@pa_router.post("/{pa_id}/sync-balance")
def pa_sync_balance(pa_id: int):
    """打开该账号的指纹浏览器抓 ether.fi 保险库总余额(Saldo total), 存到账号。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        dir_id = (getattr(pa, "roxy_dir_id", "") or "").strip()
    if not dir_id:
        raise HTTPException(400, "该账号没有指纹浏览器ID,请先点「浏览器」打开并绑定一次")
    logs: list[str] = []
    try:
        bal = _scrape_etherfi_balance(dir_id, log=lambda m: logs.append(str(m)))
    except Exception as e:
        raise HTTPException(502, f"抓取余额失败: {e}")
    finally:
        _close_roxy_window(dir_id)   # 抓完自动关窗(后台无痕)
    if not bal:
        return {"ok": False, "message": "没读到余额(先在浏览器里登录/过验证)", "logs": logs[-6:]}
    now = datetime.now(timezone.utc)
    with Session(engine) as s:
        row = s.get(PaymentAccountModel, pa_id)
        row.balance_usd = float(bal.get("balance_usd") or 0)
        row.balance_text = bal.get("balance_text") or ""
        row.balance_updated_at = now
        row.updated_at = now
        s.add(row)
        s.commit()
        return {"ok": True, "balance_usd": row.balance_usd, "balance_text": row.balance_text,
                **_serialize_pa(row, card_count=_card_count(s, pa_id),
                                newest_card_opened_at=_newest_card_opened_at(s, pa_id))}


@pa_router.post("/sync-all")
def pa_sync_all():
    """一键更新所有支付账号:每账号一个线程并发,同一浏览器会话内更新
    开卡数量 / 余额 / 支付数量 / 待退款数量(+成功退款)。
    返回 {ok, updated, failed, skipped, total, results}。"""
    from concurrent.futures import ThreadPoolExecutor

    with Session(engine) as s:
        accounts = s.exec(select(PaymentAccountModel).order_by(PaymentAccountModel.id.asc())).all()
        targets = [(pa.id, pa.name, (getattr(pa, "roxy_dir_id", "") or "").strip()) for pa in accounts]
    skipped = sum(1 for _, _, dir_id in targets if not dir_id)
    jobs = [(pid, name, dir_id) for pid, name, dir_id in targets if dir_id]

    def _one(job) -> dict:
        pa_id, name, dir_id = job
        from core.roxy_browser import open_existing_window
        tx: dict = {}
        bal: dict = {}
        try:
            # 一个会话内: 先交易记录(支付/退款/待退款/开卡) 再余额
            page = open_existing_window(dir_id, log=lambda m: None)
            _minimize_window(page)
            try:
                tx = _scrape_etherfi_tx_stats(dir_id, log=lambda m: None, page=page)
            except Exception:
                tx = {}
            try:
                bal = _scrape_etherfi_balance(dir_id, log=lambda m: None, page=page)
            except Exception:
                bal = {}
        except Exception as e:
            return {"id": pa_id, "name": name, "ok": False, "error": str(e)[:120]}
        finally:
            _close_roxy_window(dir_id)
        if not tx and not bal:
            return {"id": pa_id, "name": name, "ok": False, "error": "没读到数据(需先登录/过验证)"}
        now = datetime.now(timezone.utc)
        with Session(engine) as s2:
            row = s2.get(PaymentAccountModel, pa_id)
            if row:
                if bal:
                    row.balance_usd = float(bal.get("balance_usd") or 0)
                    row.balance_text = bal.get("balance_text") or ""
                    row.balance_updated_at = now
                if tx:
                    import json as _json2
                    row.paid_count = int(tx.get("paid_count") or 0)
                    row.refunded_count = int(tx.get("refunded_count") or 0)
                    row.pending_refund_count = int(tx.get("pending_refund_count") or 0)
                    row.card_open_count = int(tx.get("card_open_count") or 0)
                    row.unrefunded_dates_json = _json2.dumps(tx.get("unrefunded_dates") or [], ensure_ascii=False)
                    row.pending_refund_updated_at = now
                row.updated_at = now
                s2.add(row)
                s2.commit()
        return {"id": pa_id, "name": name, "ok": True,
                "balance_usd": float(bal.get("balance_usd") or 0) if bal else None,
                "paid": tx.get("paid_count"), "pending": tx.get("pending_refund_count"),
                "card_opens": tx.get("card_open_count")}

    results: list[dict] = []
    if jobs:
        # 有几个账号就开几个线程(全部同时刷)
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            results = list(ex.map(_one, jobs))
    updated = sum(1 for r in results if r.get("ok"))
    failed = len(results) - updated
    return {"ok": True, "updated": updated, "failed": failed, "skipped": skipped,
            "total": len(targets), "results": results[:50]}


def _scrape_etherfi_tx_stats(dir_id: str, log=lambda m: None, page=None) -> dict:
    """在指纹浏览器里打开 ether.fi 交易记录页, 统计 OpenAI 订阅相关笔数(滚动到底加载全部):
      - paid_count           支付笔数        : -$200
      - refunded_count       成功退款笔数    : +$200 且非 pending
      - pending_refund_count 待退款笔数      : +$200 且 pending(PENDIENTE/PENDENTE/PENDING)
    返回 {paid_count, refunded_count, pending_refund_count}。
    传入 page 则复用该已打开窗口(不另开/不关)。"""
    import re as _re
    import time as _time
    if page is None:
        from core.roxy_browser import open_existing_window
        page = open_existing_window(dir_id, log=log)
        _minimize_window(page)   # 只读文本, 可后台最小化
    page.get("https://www.ether.fi/app/cash/transaction-history")
    _time.sleep(6)

    # 开卡扣款文案多语言: ES「Pedido de tarjeta」PT「Pedido de cartão」EN「Card order」
    _CARD_OPEN = _re.compile(r"Pedido de (?:tarjeta|cart[ãa]o)|Card\s*order", _re.I)
    # 按「OpenAI 订阅」标签计数(而非死认 $200): 这样 PHP 等本币换算的订阅也能算进来。
    # 结构: 商户标签(OPENAI *CHATGPT SUBSCR) → [Cashback] → [₱本币行] → ±$X USD → [PENDIENTE]
    _SUB_LABEL = _re.compile(r"CHATGPT\s*SUBSCR", _re.I)      # 只认订阅(排除光 "OPENAI" 的手续费)
    _USD_AMT = _re.compile(r"^([+-])\s*\$\s*([\d,]+\.\d{2})\s*USD$")
    _MIN_SUB_USD = 100.0   # 只数 Pro 档订阅($200 或 PHP 本地化 ~$143); 排除 $25 Plus / 小额手续费 / 返现

    # 交易日期行(西/葡): "vie, 14 ago 2026" / "sáb, 8 ago 2026" 等
    _DATE_LINE = _re.compile(r"(lun|mar|mi[ée]|jue|vie|s[áa]b|dom)[,\.]?\s+\d{1,2}\s+\w+\s+20\d\d", _re.I)

    def _stats(t: str):
        """返回 (paid, done, pending, card_opens, paid_dates)。
        paid_dates: 每笔支付对应的日期字符串, 按页面顺序(新→旧)。"""
        lines = [ln.strip() for ln in t.split("\n") if ln.strip()]
        paid = pending = done = card_opens = 0
        paid_dates: list[str] = []
        cur_date = ""
        for i, ln in enumerate(lines):
            if _DATE_LINE.search(ln):                          # 记住当前日期分组
                cur_date = ln
                continue
            if _CARD_OPEN.search(ln):                          # 开卡($10 扣款)
                card_opens += 1
                continue
            if not _SUB_LABEL.search(ln):                      # 只在订阅项上取金额
                continue
            # 该订阅标签后第一条 USD 金额行(跳过 Cashback 返现行 与 ₱ 本币行)
            for j in range(i + 1, min(i + 5, len(lines))):
                if _re.search(r"cashback", lines[j], _re.I):
                    continue
                m = _USD_AMT.match(lines[j])
                if not m:
                    continue
                amt = float(m.group(2).replace(",", ""))
                if amt < _MIN_SUB_USD:                          # 小额(Plus/手续费)不计
                    break
                if m.group(1) == "-":                           # 扣款 → 支付
                    paid += 1
                    paid_dates.append(cur_date)
                else:                                           # 入账 → 退款(待/已)
                    is_pending = any(
                        _re.search(r"PENDI?ENTE|PENDING", lines[k], _re.I)
                        for k in range(j, min(j + 3, len(lines)))
                    )
                    if is_pending:
                        pending += 1
                    else:
                        done += 1
                break
        return paid, done, pending, card_opens, paid_dates

    prev = (-1, -1, -1, -1)
    for _ in range(15):                     # 滚动到底反复加载, 直到不再增长
        st = _stats(page.ele("tag:body").text)[:4]
        if st == prev:
            break
        prev = st
        try:
            page.scroll.to_bottom()
        except Exception:
            pass
        _time.sleep(1.5)
    paid, done, pending, card_opens, paid_dates = _stats(page.ele("tag:body").text)
    # 未发起退款 = 支付 − 已退 − 待退; 取最近 N 笔支付日期(paid_dates 是新→旧, 前 N 个即最新未退)
    unrefunded = max(0, paid - done - pending)
    unrefunded_dates = [d for d in paid_dates[:unrefunded] if d]
    log(f"[etherfi] 支付 {paid} · 成功退款 {done} · 待退款 {pending} · 开卡 {card_opens} · 未发起退款 {unrefunded}")
    return {"paid_count": paid, "refunded_count": done,
            "pending_refund_count": pending, "card_open_count": card_opens,
            "unrefunded_dates": unrefunded_dates}


@pa_router.post("/{pa_id}/sync-pending-refunds")
def pa_sync_pending_refunds(pa_id: int):
    """打开该账号指纹浏览器, 统计交易记录里 支付/成功退款/待退款 笔数, 存到账号。
    若统计相比上次有变化, **在同一浏览器会话里顺带刷新余额**(避免关窗再开窗的竞态)。
    返回 changed=True 表示有变化。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        dir_id = (getattr(pa, "roxy_dir_id", "") or "").strip()
        old = (int(getattr(pa, "paid_count", 0) or 0),
               int(getattr(pa, "refunded_count", 0) or 0),
               int(getattr(pa, "pending_refund_count", 0) or 0))
        had_prev = pa.pending_refund_updated_at is not None
    if not dir_id:
        raise HTTPException(400, "该账号没有指纹浏览器ID,请先点「浏览器」打开并绑定一次")
    logs: list[str] = []
    bal: dict = {}
    try:
        # 同一会话: 开一次窗 → 抓交易统计 →(有变化则)顺带抓余额 → 关一次窗
        from core.roxy_browser import open_existing_window
        page = open_existing_window(dir_id, log=lambda m: logs.append(str(m)))
        _minimize_window(page)
        res = _scrape_etherfi_tx_stats(dir_id, log=lambda m: logs.append(str(m)), page=page)
        new = (int(res.get("paid_count") or 0),
               int(res.get("refunded_count") or 0),
               int(res.get("pending_refund_count") or 0))
        changed = had_prev and (new != old)   # 首次统计不算「变更」
        if changed:
            try:
                bal = _scrape_etherfi_balance(dir_id, log=lambda m: logs.append(str(m)), page=page)
            except Exception as be:
                logs.append(f"[balance] 顺带刷余额失败: {be}")
    except Exception as e:
        raise HTTPException(502, f"抓取交易统计失败: {e}")
    finally:
        _close_roxy_window(dir_id)
    now = datetime.now(timezone.utc)
    with Session(engine) as s:
        import json as _json2
        row = s.get(PaymentAccountModel, pa_id)
        row.paid_count, row.refunded_count, row.pending_refund_count = new
        row.card_open_count = int(res.get("card_open_count") or 0)
        row.unrefunded_dates_json = _json2.dumps(res.get("unrefunded_dates") or [], ensure_ascii=False)
        row.pending_refund_updated_at = now
        if bal:                              # 有变化且余额抓到了 → 一并更新
            row.balance_usd = float(bal.get("balance_usd") or 0)
            row.balance_text = bal.get("balance_text") or ""
            row.balance_updated_at = now
        row.updated_at = now
        s.add(row)
        s.commit()
        return {"ok": True, "changed": changed, "balance_refreshed": bool(bal),
                "paid_count": new[0], "refunded_count": new[1], "pending_refund_count": new[2],
                **_serialize_pa(row, card_count=_card_count(s, pa_id),
                                newest_card_opened_at=_newest_card_opened_at(s, pa_id)),
                "logs": logs[-8:]}


@pa_router.post("/{pa_id}/open-browser")
def pa_open_browser(pa_id: int, dir_id: str = ""):
    """打开该支付账号的指纹浏览器窗口。优先级:
      1) 传了 dir_id(用户选定)→ 打开并保存到账号;
      2) 账号已保存 roxy_dir_id → 直接打开;
      3) 否则按账号名(通常是邮箱)在 RoxyBrowser 里查找同名 profile:
         唯一命中 → 打开并保存;0 个或多个 → 返回 need_select + 候选列表让用户选。
    """
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        name = pa.name
        saved_dir = (getattr(pa, "roxy_dir_id", "") or "").strip()
    from core.config_store import config_store as _cs
    api_host = str(_cs.get("roxybrowser_api_host", "") or "http://127.0.0.1:50000").strip()
    token = str(_cs.get("roxybrowser_api_token", "") or "").strip()
    try:
        ws_id = int(str(_cs.get("roxybrowser_workspace_id", "") or 0) or 0)
    except Exception:
        ws_id = 0
    if not token:
        raise HTTPException(400, "未配置 RoxyBrowser API Key(roxybrowser_api_token),无法打开浏览器")
    from core.roxy_browser import RoxyBrowserClient
    client = RoxyBrowserClient(api_host, token)

    def _open_and_save(d: str, matched_by: str = "") -> dict:
        try:
            data = client.open_window(ws_id, d)
        except Exception as e:
            raise HTTPException(502, f"打开指纹浏览器失败: {e}")
        # 保存 dir_id 到账号(下次直接用)
        if d != saved_dir:
            with Session(engine) as s2:
                row = s2.get(PaymentAccountModel, pa_id)
                if row:
                    row.roxy_dir_id = d
                    row.updated_at = datetime.now(timezone.utc)
                    s2.add(row)
                    s2.commit()
        return {"ok": True, "roxy_dir_id": d, "matched_by": matched_by,
                "message": "已打开指纹浏览器窗口", "data": {"http": (data or {}).get("http", "")}}

    target = (dir_id or "").strip()
    if target:                       # 1) 用户选定
        return _open_and_save(target, "selected")
    if saved_dir:                    # 2) 已保存 ID
        return _open_and_save(saved_dir, "saved")
    # 3) 按账号名(邮箱)查找
    try:
        profiles = client.list_browsers(ws_id)
    except Exception as e:
        raise HTTPException(502, f"列出指纹浏览器失败: {e}")
    nm = (name or "").strip().lower()
    # 先精确匹配窗口名 == 账号名;没有再退到"窗口名包含账号名(邮箱)"
    matches = [p for p in profiles if _profile_name(p).lower() == nm] if nm else []
    matched_how = "name"
    if len(matches) != 1 and nm:
        contains = [p for p in profiles if nm in _profile_name(p).lower()]
        if len(contains) == 1:
            matches, matched_how = contains, "name_contains"
    if len(matches) == 1:
        return _open_and_save(_profile_dir_id(matches[0]), matched_how)
    return {
        "ok": False,
        "need_select": True,
        "profiles": [{"dir_id": _profile_dir_id(p), "name": _profile_name(p)}
                     for p in profiles if _profile_dir_id(p)],
        "message": (f"匹配到多个包含「{name}」的浏览器,请选择"
                    if matches else f"未找到名称含「{name}」的指纹浏览器,请从列表选择一个"),
    }


def _open_browser_and_goto(pa_id: int, url: str, what: str) -> dict:
    """打开该账号绑定的指纹浏览器窗口, 并在窗口里跳转到 url。需先绑定 roxy_dir_id。"""
    with Session(engine) as s:
        pa = s.get(PaymentAccountModel, pa_id)
        if not pa:
            raise HTTPException(404, "支付账号不存在")
        dir_id = (getattr(pa, "roxy_dir_id", "") or "").strip()
    if not dir_id:
        raise HTTPException(400, "该账号没有指纹浏览器ID,请先点「浏览器」打开并绑定一次")
    from core.roxy_browser import open_existing_window
    try:
        page = open_existing_window(dir_id)
        page.get(url)
        # 把窗口拉到最前并最大化(有些窗口被最小化/缩小了)
        for _do in (
            lambda: page.set.window.max(),          # 取消最小化 + 最大化
            lambda: page.set.window.show(),          # 显示窗口
            lambda: page.run_cdp("Page.bringToFront"),  # 激活到最前
        ):
            try:
                _do()
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(502, f"打开{what}页面失败: {e}")
    return {"ok": True, "url": url, "message": f"已在浏览器打开{what}页面并置顶"}


@pa_router.post("/{pa_id}/open-recharge")
def pa_open_recharge(pa_id: int):
    """在该账号指纹浏览器里打开 ether.fi 充值(接收地址)页。"""
    return _open_browser_and_goto(
        pa_id, "https://www.ether.fi/app/cash/add/crypto/share-address", "充值")


@pa_router.post("/{pa_id}/open-order-card")
def pa_open_order_card(pa_id: int):
    """在该账号指纹浏览器里打开 ether.fi 开卡(order-card)页。"""
    return _open_browser_and_goto(
        pa_id, "https://www.ether.fi/app/cash/order-card", "开卡")
