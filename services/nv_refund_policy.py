"""Credential-free, exact-cycle NV refund evidence shared by UI and workers."""
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import re


def _date(value):
    try:
        value = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _id(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value) else ""


def normalize_nv_refund(value):
    if is_dataclass(value):
        value = asdict(value)
    if not isinstance(value, dict):
        return None
    email = str(value.get("email") or "").strip().lower()
    sold, refunded = _date(value.get("sold_at")), _date(value.get("refunded_at"))
    verified = _date(value.get("verified_at"))
    order, card = _id(value.get("remote_order_id")), _id(value.get("remote_card_id"))
    if (not email or "@" not in email or not order or not card or value.get("identity_valid") is not True
            or sold is None or refunded is None or verified is None or not sold <= refunded <= verified
            or verified > datetime.now(timezone.utc)):
        return None
    money = {}
    for key in ("amount_cents", "refund_amount_cents", "supplier_amount_cents"):
        raw = value.get(key)
        if raw is not None and (type(raw) is not int or not 0 <= raw <= 10**12):
            return None
        money[key] = raw
    amount, refund, net = (money[key] for key in ("amount_cents", "refund_amount_cents", "supplier_amount_cents"))
    order_status, settlement = (str(value.get(key) or "").lower() for key in ("order_status", "settlement_status"))
    # A timestamp or cards.status=sold alone is never an authoritative refund.
    statuses = {"refunded", "partially_refunded", "partial_refund"}
    if order_status not in statuses or settlement not in statuses:
        return None
    if amount is not None and net is not None and net > amount:
        return None
    full = (order_status == settlement == "refunded" and amount is not None and amount > 0
            and refund == amount and net == 0)
    if not full and (amount is None or refund is None or not 0 < refund <= amount):
        return None
    return dict(email=email, remote_order_id=order, remote_card_id=card,
                inventory_card_id=_id(value.get("inventory_card_id")),
                sold_at=sold.isoformat(), refunded_at=refunded.isoformat(), verified_at=verified.isoformat(),
                order_status=order_status, settlement_status=settlement, identity_valid=True,
                full_refund=full, **money)


def match_cycle_refund(snapshot, *, email, remote_order_id, remote_card_id, sold_at, listed_at, check_inventory=True):
    """None means no current-cycle refund. Ambiguous current evidence raises."""
    if snapshot.inventory_complete is not True:
        raise ValueError("NV 退款记录未完整读取")
    email = str(email or "").strip().lower()
    order, card = _id(remote_order_id), _id(remote_card_id)
    sold, floor = _date(sold_at), _date(listed_at)
    candidates = []
    for record in getattr(snapshot, "refund_records", ()):
        data = asdict(record) if is_dataclass(record) else record
        if str(data.get("email") or "").strip().lower() != email:
            continue
        record_order = _id(data.get("remote_order_id"))
        record_sold = _date(data.get("sold_at"))
        aliases = {_id(data.get("remote_card_id")), _id(data.get("inventory_card_id"))} - {""}
        if record_sold and floor and record_sold < floor:
            continue
        if order and record_order and order != record_order:
            if card in aliases and record_sold and (record_sold == sold or sold is None):
                raise ValueError("NV 本周期卡片退款记录的订单身份冲突")
            continue  # A prior order for the same email cannot refund this one.
        if sold and record_sold and sold != record_sold:
            if order and order == record_order:
                raise ValueError("NV 退款订单出售时间与本周期不一致")
            continue
        if not order and card not in aliases:
            # A current-time same-email refund without trustworthy alias must
            # not fall through to the stale sold-card record.
            raise ValueError("NV 有退款记录但无法确认本周期卡片身份")
        proof = normalize_nv_refund({**data, "verified_at": datetime.now(timezone.utc).isoformat()})
        if proof is None or not card or card not in aliases or floor is None or record_sold is None:
            raise ValueError("NV 退款记录的身份或退款金额未完整确认")
        candidates.append(proof)
    if not candidates:
        return None
    identities = {(p["remote_order_id"], p["remote_card_id"], p["sold_at"], p["refunded_at"],
                   p["amount_cents"], p["refund_amount_cents"], p["supplier_amount_cents"],
                   p["full_refund"], p["order_status"], p["settlement_status"]) for p in candidates}
    if len(identities) != 1:
        raise ValueError("NV 本周期存在冲突退款记录")
    proof = candidates[0]
    if check_inventory:
        aliases = {proof["remote_card_id"], proof["inventory_card_id"]} - {""}
        current_sales = [row for row in snapshot.sold_records
                         if _date(row.sold_at) is None or _date(row.sold_at) >= floor]
        for row in (*snapshot.inventory_records, *current_sales):
            if str(row.email or "").lower().strip() != email:
                continue
            row_card = _id(row.remote_card_id)
            row_order = _id(getattr(row, "remote_order_id", ""))
            row_sold = _date(getattr(row, "sold_at", None))
            if (not row_card or row_card not in aliases
                    or row_order and row_order != proof["remote_order_id"]
                    or row_sold and row_sold != _date(proof["sold_at"])
                    or getattr(row, "status", "sold") not in {"sold", "refunded"}):
                raise ValueError("NV 退款订单与当前同邮箱卡片或销售周期冲突，未退出空间")
    return proof


def membership_matches_refund(member, proof):
    proof = normalize_nv_refund(proof)
    return bool(proof and str(member.email or "").strip().lower() == proof["email"]
        and _id(member.nv_remote_card_id) in {proof["remote_card_id"], proof["inventory_card_id"]}
        and (not member.nv_remote_order_id or member.nv_remote_order_id == proof["remote_order_id"])
        and _date(member.nv_listed_at) is not None
        and _date(member.nv_listed_at) <= _date(proof["sold_at"])
        and (member.sold_at is None or _date(member.sold_at) == _date(proof["sold_at"])))


def job_refund(job, context):
    """Validate the frozen job cycle, never use email alone as authorization."""
    proof = normalize_nv_refund(context.get("nv_refund"))
    get = job.get if isinstance(job, dict) else lambda key: getattr(job, key, None)
    if (proof is None or proof["email"] != str(get("email") or "").lower().strip()
            or context.get("nv_remote_order_id") != proof["remote_order_id"]
            or context.get("nv_remote_card_id") not in {proof["remote_card_id"], proof["inventory_card_id"]}
            or _date(context.get("sold_at")) != _date(proof["sold_at"])
            or _date(context.get("nv_listed_at")) is None
            or _date(context["nv_listed_at"]) > _date(proof["sold_at"])):
        return None
    return proof


def assert_refund_exit(session, job, context):
    from core.db import GptBusinessChildMembershipModel
    proof = job_refund(job, context)
    member = session.get(GptBusinessChildMembershipModel, job.membership_id)
    if (not proof or proof["full_refund"] is not True or member is None
            or not membership_matches_refund(member, proof) or member.sale_status != "refunded"
            or member.business_account_id != job.source_account_id or member.pro_account_id != job.child_id
            or member.remote_user_id != job.remote_user_id or member.ended_at is not None):
        raise ValueError("NV 退款退出的当前成员、订单或全额退款证据不一致")
    return proof


def apply_membership_refund(session, membership, proof):
    """Caller owns the transaction and membership CAS. Never mutates accounts."""
    proof = normalize_nv_refund(proof)
    if proof is None or not membership_matches_refund(membership, proof):
        return False
    if membership.sale_status == "refunded" and not proof["full_refund"]:
        return False
    from sqlmodel import select
    from services.nv_order_history import NvSaleOrder
    from services.nv_refunds import record_refund, refund_for_order
    for order in session.exec(select(NvSaleOrder).where(NvSaleOrder.membership_id == membership.id)).all():
        if order.nv_order_id != proof["remote_order_id"]:
            continue
        previous = refund_for_order(session, order)
        if record_refund(session, order, proof) is None and previous:
            raise ValueError("NV 退款证据与已保存的订单退款冲突，未更新成员状态")
    membership.sale_status = "refunded" if proof["full_refund"] else "partial_refund"
    membership.nv_remote_order_id = proof["remote_order_id"]
    membership.sold_at = _date(proof["sold_at"])
    membership.nv_last_synced_at = _date(proof["verified_at"])
    membership.updated_at = datetime.now(timezone.utc)
    session.add(membership)
    return True
