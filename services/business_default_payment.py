"""Read the remote BUSINESS default payment method, never checkout history.

Verified against ChatGPT's current c2675c8c-kconnwitb9zzv81k.js and a live
read-only response: GET /payments/payment_methods?account_id=<workspace>.
The default is an exact ID match, not the first card or upcoming invoice.
Only a credential-free display snapshot is persisted. No payment mutations.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session

from services import business_session_health as health

KEY = "business_default_payment_method_v1"
ENDPOINT = "https://chatgpt.com/backend-api/payments/payment_methods"
UNCONFIRMED = "远端未返回明确的默认支付方式"
INCOMPLETE = "默认支付方式详情不完整，请稍后重试"
FAILED = "默认支付方式读取失败，请稍后重试"
TIMEOUT = "默认支付方式读取超时，请稍后重试"
UNAUTHORIZED = "默认支付方式读取失败（HTTP 401），请检查会话或重新登录母号"
FORBIDDEN = "暂无权限读取默认支付方式（HTTP 403）"
ERRORS = {UNCONFIRMED, INCOMPLETE, FAILED, TIMEOUT, UNAUTHORIZED, FORBIDDEN}
BRANDS = {"visa", "mastercard", "amex", "american_express", "discover", "diners",
          "diners_club", "jcb", "unionpay", "union_pay", "cartes_bancaires", "eftpos"}


def _result(status="unknown", *, payment_type="", brand="", last4="", error="", checked_at=""):
    return {"status": status, "type": payment_type, "brand": brand, "last4": last4,
            "error": error, "checked_at": checked_at}


def parse_default(body):
    """Schema changes, missing/default IDs and duplicate IDs must fail closed."""
    unknown = _result(error=UNCONFIRMED)
    if not isinstance(body, dict) or body.get("error") or "default_payment_method_id" not in body:
        return unknown
    methods = body.get("payment_methods")
    if not isinstance(methods, list) or len(methods) > 100:
        return unknown
    # null is meaningful on THIS dedicated payment-method endpoint. It is NOT
    # meaningful on invoices, whose null can inherit a subscription default.
    default_id = body["default_payment_method_id"]
    if default_id is None:
        return _result("none")
    if not isinstance(default_id, str) or not re.fullmatch(r"pm_[A-Za-z0-9_]{1,240}", default_id):
        return unknown
    matches = [item for item in methods if isinstance(item, dict) and item.get("id") == default_id]
    if len(matches) != 1:
        return _result(error=INCOMPLETE)
    method = matches[0]
    kind = method.get("type")
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", kind):
        return _result(error=INCOMPLETE)
    brand = last4 = ""
    details = method.get(kind)
    if kind == "card":
        if not isinstance(details, dict):
            return _result(error=INCOMPLETE)
        raw_brand, raw_last4 = details.get("brand"), details.get("last4")
        if not isinstance(raw_last4, str) or not re.fullmatch(r"[0-9]{4}", raw_last4):
            return _result(error=INCOMPLETE)
        last4 = raw_last4
        brand = raw_brand.lower() if isinstance(raw_brand, str) and raw_brand.lower() in BRANDS else ""
    elif kind in {"us_bank_account", "sepa_debit", "bacs_debit", "au_becs_debit"} and isinstance(details, dict):
        raw_last4 = details.get("last4")
        last4 = raw_last4 if isinstance(raw_last4, str) and re.fullmatch(r"[0-9]{4}", raw_last4) else ""
    return _result("ready", payment_type=kind, brand=brand, last4=last4)


def public_snapshot(mother):
    """Local-only allowlist. Old account/workspace snapshots never cross over."""
    raw = health._extra(getattr(mother, "extra_json", "")).get(KEY)
    if not isinstance(raw, dict):
        return _result()
    identity, _ = health._identity(health._cookies(getattr(mother, "cookie_blob", "")).get("oai-access-token", ""))
    if (not identity.get("team") or raw.get("team") != identity["team"]
            or raw.get("email") != str(getattr(mother, "email", "")).strip().lower()
            or raw.get("source_created") != health._iso(getattr(mother, "created_at", None))):
        return _result()
    raw_status, raw_error = raw.get("status"), raw.get("error")
    status = raw_status if isinstance(raw_status, str) and raw_status in {"ready", "none", "unknown", "error"} else "unknown"
    result = _result(status, checked_at=health._iso(raw.get("checked_at")),
                     error=raw_error if isinstance(raw_error, str) and raw_error in ERRORS else "")
    if status == "ready":
        # Revalidate even persisted snapshots. Never expose raw provider data.
        result = parse_default({"default_payment_method_id": "pm_snapshot", "payment_methods": [{
            "id": "pm_snapshot", "type": raw.get("type"),
            str(raw.get("type")): {"brand": raw.get("brand"), "last4": raw.get("last4")},
        }]})
        result["checked_at"] = health._iso(raw.get("checked_at"))
    return result


def _lease_key(source_id):
    return f"business-payment-method:{int(source_id)}"


def _persist(snapshot, token, result):
    with Session(health._engine()) as session:
        health._begin(session)
        mother, plan = health._bound(session, snapshot.source_id, lock=True)
        lease = session.get(health.Lease, _lease_key(snapshot.source_id))
        if (not health._same(snapshot, mother, plan) or not lease or lease.owner_token != token
                or (health._date(lease.expires_at) or health._now()) <= health._now()):
            raise HTTPException(409, "读取期间母号会话或绑定已更新，请重新刷新默认支付方式")
        extra = health._extra(mother.extra_json)
        extra[KEY] = {**result, "team": snapshot.team, "email": snapshot.email,
                      "source_created": snapshot.source_created, "checked_at": health._iso(health._now())}
        changed = session.exec(update(health.Mother).where(
            health.Mother.id == snapshot.source_id,
            health.Mother.cookie_blob == snapshot.blob,
            health.Mother.extra_json == mother.extra_json,
            health.Mother.created_at == mother.created_at,
        ).values(extra_json=json.dumps(extra, ensure_ascii=False)))
        if changed.rowcount != 1:
            raise HTTPException(409, "母号数据已更新，请重新刷新默认支付方式")
        session.commit()
        session.expire_all()
        return public_snapshot(session.get(health.Mother, snapshot.source_id))


def refresh_default_payment(source_id, *, expected_plan_id=None):
    """One manual GET; reuse session health, persist by bound identity and lease."""
    try:
        return _refresh_default_payment(source_id, expected_plan_id=expected_plan_id)
    except SQLAlchemyError:
        # Includes the initial binding read and the session preflight: SQL
        # exceptions may include bound credential values even before our lease.
        raise HTTPException(503, "默认支付方式读取或保存失败，请稍后重试") from None


def _refresh_default_payment(source_id, *, expected_plan_id=None):
    # Session refresh is an existing identity-checked capability, not a billing
    # mutation. Never continue after failed identity or authentication proof.
    with Session(health._engine()) as session:
        mother, plan = health._bound(session, source_id)
        if (not health._eligible(mother, plan)
                or (expected_plan_id is not None and int(plan.id) != int(expected_plan_id))):
            raise HTTPException(409, "BUSINESS 母号绑定已变化，请刷新后重试")
        initial = health._capture(mother, plan)
    if health.ensure_session(source_id) is None:
        raise HTTPException(409, "BUSINESS 母号绑定已变化，请刷新后重试")
    token = uuid.uuid4().hex
    acquired = False
    try:
        with Session(health._engine()) as session:
            health._begin(session)
            mother, plan = health._bound(session, source_id)
            if not health._eligible(mother, plan):
                raise HTTPException(409, "该 BUSINESS 母号不可用，请刷新账号列表")
            snapshot = health._capture(mother, plan)
            if (snapshot.plan_id != initial.plan_id or snapshot.email != initial.email
                    or snapshot.source_created != initial.source_created
                    or snapshot.plan_created != initial.plan_created
                    or snapshot.team != initial.team or snapshot.user != initial.user
                    or health.public_health(mother)["status"] != "valid"):
                raise HTTPException(409, "母号会话或绑定已变化，请重新检查会话后刷新默认支付方式")
            if not health._TEAM.fullmatch(snapshot.team):
                raise HTTPException(409, "母号工作区身份无法确认，请重新登录")
            lease = session.get(health.Lease, _lease_key(source_id))
            if lease and (health._date(lease.expires_at) or health._now()) > health._now():
                raise HTTPException(409, "正在读取该母号的默认支付方式，请稍后重试")
            if lease:
                session.delete(lease)
                session.flush()
            session.add(health.Lease(resource_key=_lease_key(source_id), job_id=_lease_key(source_id),
                                    owner_token=token, expires_at=health._now() + timedelta(seconds=45)))
            session.commit()
            acquired = True
        from core.config_store import config_store
        at = health._cookies(snapshot.blob).get("oai-access-token", "")
        try:
            status, body, _ = health._request(
                ENDPOINT,
                headers={"Authorization": f"Bearer {at}", "chatgpt-account-id": snapshot.team,
                         "Accept": "application/json", "Referer": "https://chatgpt.com/"},
                params={"account_id": snapshot.team},
                proxy=str(config_store.get("default_proxy", "") or "").strip(),
            )
            result = parse_default(body) if status == 200 else _result(
                "error", error={401: UNAUTHORIZED, 403: FORBIDDEN}.get(status, FAILED))
        except Exception as exc:
            # Never serialize provider errors (can include credentials/URLs).
            timeout = "timeout" in type(exc).__name__.lower()
            result = _result("error", error=TIMEOUT if timeout else FAILED)
        return _persist(snapshot, token, result)
    except IntegrityError:
        raise HTTPException(409, "正在读取该母号的默认支付方式，请稍后重试") from None
    except SQLAlchemyError:
        raise HTTPException(503, "默认支付方式保存失败，请稍后重试") from None
    finally:
        if acquired:
            try:
                with Session(health._engine()) as session:
                    session.exec(delete(health.Lease).where(
                        health.Lease.resource_key == _lease_key(source_id), health.Lease.owner_token == token))
                    session.commit()
            except SQLAlchemyError:
                pass  # Bounded lease expiry; no SQL/credential exception leakage.
