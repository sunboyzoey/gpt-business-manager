"""Durable, cycle-bound NV *buyer* refunds, independent of account refunds.

This module has no remote calls or task/lifecycle writes. An existing sales
ledger row is the authority for attribution, including after its job is deleted.
Only the shared NV refund policy can normalize a verified remote proof.
"""
from __future__ import annotations

import json
import time

from sqlmodel import Field, Session, SQLModel, select


class NvSaleRefund(SQLModel, table=True):
    __tablename__ = "nv_sale_refunds"
    # No cascading foreign key: deleting jobs/accounts must retain accounting.
    sale_order_id: str = Field(primary_key=True)
    job_id: str = Field(index=True)
    parent_account_id: int = Field(index=True)
    source_account_id: int = 0
    membership_id: int = Field(index=True)
    email: str = Field(index=True)
    remote_order_id: str = Field(index=True)
    remote_card_id: str = Field(index=True)
    inventory_card_id: str = ""
    listed_at: str
    sold_at: str
    refunded_at: str
    amount_cents: int
    refund_amount_cents: int
    supplier_amount_cents: int | None = None
    full_refund: bool
    verified_at: str
    proof_json: str
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


def _history():
    from services import nv_order_history
    return nv_order_history


def _normalize(proof):
    from services.nv_refund_policy import normalize_nv_refund
    return normalize_nv_refund(proof)


def _bound_proof(order, proof):
    """Require exact remote identifiers and sale time, never email-only joins."""
    history = _history()
    normalized = _normalize(proof)
    if normalized is None:
        return None
    cards = {normalized["remote_card_id"], normalized.get("inventory_card_id", "")} - {""}
    listed, sold = history._date(order.listed_at), history._date(order.sold_at)
    if (not order.job_id or type(order.membership_id) is not int or order.membership_id <= 0
            or type(order.parent_account_id) is not int or order.parent_account_id <= 0
            or not order.nv_order_id or not order.nv_card_id or not listed or not sold or listed > sold
            or order.email.strip().casefold() != normalized["email"]
            or order.nv_order_id != normalized["remote_order_id"] or order.nv_card_id not in cards
            or sold != history._date(normalized["sold_at"])):
        return None
    return normalized


def _stored_proof(order, refund):
    """Do not apply an orphaned/corrupt refund to another ledger cycle."""
    if refund is None:
        return None
    if any(getattr(refund, key) != getattr(order, key) for key in
           ("job_id", "parent_account_id", "source_account_id", "membership_id", "email", "listed_at", "sold_at")):
        return None
    if refund.sale_order_id != order.id:
        return None
    try:
        proof = _bound_proof(order, json.loads(refund.proof_json))
    except (ValueError, TypeError):
        return None
    keys = ("remote_order_id", "remote_card_id", "inventory_card_id", "refunded_at", "amount_cents",
            "refund_amount_cents", "supplier_amount_cents", "full_refund", "verified_at")
    if proof is None or any(getattr(refund, key) != proof.get(key, "" if key == "inventory_card_id" else None)
                            for key in keys):
        return None
    return proof


def refund_for_order(session, order):
    """Return validated persisted proof, or None; SELECT only."""
    return _stored_proof(order, session.get(NvSaleRefund, order.id))


def refunds_for_orders(session, orders):
    """Bulk read for finance pages; no per-order account/context reads."""
    by_id = {order.id: order for order in orders}
    if not by_id:
        return {}
    result = {}
    # Read the small credential-free proof table without SQL parameter limits.
    for row in session.exec(select(NvSaleRefund)).all():
        order = by_id.get(row.sale_order_id)
        if order is not None:
            proof = _stored_proof(order, row)
            if proof is not None:
                result[order.id] = proof
    return result


def record_refund(session, job_or_order, proof):
    """Persist exact proof in the caller's transaction; return row or None.

    A job must still describe the frozen ledger identity. A NvSaleOrder may be
    passed by historical reconciliation even if the job/account no longer exists.
    This never opens a new sale, changes membership, or authorizes remote exit.
    """
    history = _history()
    if isinstance(job_or_order, history.NvSaleOrder):
        order = session.get(history.NvSaleOrder, job_or_order.id)
    else:
        job = job_or_order
        order = session.exec(select(history.NvSaleOrder).where(history.NvSaleOrder.job_id == job.id)).first()
        if order is None:
            return None
        evidence = history._evidence(job)
        if (evidence is None or any(getattr(order, key) != getattr(job, key) for key in
                ("parent_account_id", "source_account_id", "membership_id", "child_id"))
                or order.parent_email.casefold() != job.parent_email.strip().casefold()
                or any(getattr(order, key) != evidence[key] for key in ("email", "listed_at", "sold_at"))
                or order.nv_order_id != evidence["nv_order_id"]
                or order.nv_card_id not in evidence["card_aliases"]):
            return None
    if order is None:
        return None
    normalized = _bound_proof(order, proof)
    if normalized is None:
        return None
    previous = session.get(NvSaleRefund, order.id)
    old = _stored_proof(order, previous) if previous is not None else None
    material = lambda item: {key: value for key, value in (item or {}).items() if key != "verified_at"}
    if previous is not None:
        # A corrupt or conflicting persisted identity requires review, not repair
        # by reassigning it. Older snapshots cannot undo a known full refund.
        if (old is None or normalized["amount_cents"] != old["amount_cents"]
                or normalized["remote_card_id"] != old["remote_card_id"]
                or (old.get("inventory_card_id") and old["inventory_card_id"] != normalized.get("inventory_card_id"))
                or normalized["refund_amount_cents"] < old["refund_amount_cents"]
                or (old["full_refund"] and not normalized["full_refund"])
                or history._date(normalized["verified_at"]) < history._date(old["verified_at"])
                or history._date(normalized["refunded_at"]) < history._date(old["refunded_at"])):
            return None
        if normalized == old:
            return previous
        if (material(normalized) != material(old)
                and history._date(normalized["verified_at"]) == history._date(old["verified_at"])):
            return None
    values = {key: normalized.get(key, "" if key == "inventory_card_id" else None) for key in
        ("remote_order_id", "remote_card_id", "inventory_card_id", "refunded_at", "amount_cents",
         "refund_amount_cents", "supplier_amount_cents", "full_refund", "verified_at")}
    values.update(proof_json=json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                  updated_at=time.time())
    if previous is None:
        previous = NvSaleRefund(sale_order_id=order.id, job_id=order.job_id,
            parent_account_id=order.parent_account_id, source_account_id=order.source_account_id,
            membership_id=order.membership_id, email=order.email,
            listed_at=order.listed_at, sold_at=order.sold_at, **values)
    else:
        for key, value in values.items():
            setattr(previous, key, value)
    session.add(previous)
    # Keep material financial changes audited, without a revision on every scan.
    if material(old) != material(normalized):
        history._revision(session, "nv_buyer_refund", order.id, old or {}, normalized)
    session.flush()
    return previous


def list_refund_targets(session=None):
    """SELECT-only snapshot targets, including completed/deleted-job sales.

    Callers fetch NV read-only data, load sale_order_id in their transaction,
    and call record_refund(session, order, proof). Never run these old jobs.
    """
    history = _history()
    if session is None:
        with Session(history._store().engine) as own_session:
            return list_refund_targets(own_session)
    return [dict(sale_order_id=row.id, job_id=row.job_id, parent_account_id=row.parent_account_id,
                 membership_id=row.membership_id, email=row.email, remote_order_id=row.nv_order_id,
                 remote_card_id=row.nv_card_id, sold_at=row.sold_at, listed_at=row.listed_at)
            for row in session.exec(select(history.NvSaleOrder).order_by(history.NvSaleOrder.created_at,
                                                                        history.NvSaleOrder.id)).all()
            if row.nv_order_id and row.nv_card_id and row.membership_id
            and history._date(row.listed_at) and history._date(row.sold_at)]
