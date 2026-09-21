"""Standalone ordinary inventory: only locally generated Gmail children.

An operator's registered declaration prevents another signup, but never creates
remote identity evidence. A successful existing login can verify that identity.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import timezone

from sqlalchemy import func, update
from sqlmodel import Session, select

from core.db import (
    AccountModel, ChatGptAccountSecurityModel, ChatGptSecurityOperationLeaseModel,
    GptPlanAccountModel, GptPlanAccountOperationLeaseModel,
)
from core.credential_crypto import encrypt_credential
from services import gmail_store as store


def require_gmail_alias(session, email: str):
    normalized = str(email or "").strip().lower()
    alias = session.exec(select(store.GmailAlias).where(store.GmailAlias.email == normalized)).first()
    source = session.get(store.GmailSource, alias.source_id) if alias else None
    if alias is None or source is None:
        raise store.GmailStoreError("gmail_alias_required", "普通账号仅支持已在 Gmail 母号管理中生成的子号，请先添加母号并生成子号")
    local, domain = source.email.split("@", 1)
    if domain != "gmail.com" or alias.email != f"{local}+{alias.tag}@gmail.com":
        raise store.GmailStoreError("gmail_alias_mismatch", "Gmail 子号与母号的关联无效", 409)
    return alias, source


def _extra(plan):
    try:
        value = json.loads(plan.extra_json or "{}")
    except (ValueError, TypeError):
        value = {}
    return value if isinstance(value, dict) else {}


def bind_gmail_plan(session, plan):
    alias, _ = require_gmail_alias(session, plan.email)
    plan.mail_provider = "gmail"
    plan.mail_access_type = "imap"
    plan.extra_json = json.dumps({**_extra(plan), "mail_provider": "gmail",
        "gmail_source_id": alias.source_id, "gmail_alias_id": alias.id}, ensure_ascii=False)
    return alias


def _parse(data, registration_status):
    if registration_status not in {"registered", "unregistered"}:
        raise store.GmailStoreError("invalid_status", "注册状态只能是 registered 或 unregistered")
    if not isinstance(data, str) or len(data) > 2_000_000:
        raise store.GmailStoreError("invalid_import", "导入资料为空或过长")
    rows, seen = [], set()
    for number, line in enumerate(data.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [value.strip() for value in line.split("----")]
        if not 1 <= len(parts) <= 3:
            raise store.GmailStoreError("invalid_import", f"第 {number} 行格式错误：子号邮箱----GPT密码----2FA密钥（后两项可选）")
        email, password, secret = (parts + ["", ""])[:3]
        email = email.lower()
        if not re.fullmatch(r"[a-z0-9.]+\+[a-z0-9-]+@gmail\.com", email):
            raise store.GmailStoreError("invalid_alias", f"第 {number} 行须为已生成的 Gmail 子号邮箱")
        if email in seen:
            raise store.GmailStoreError("duplicate_alias", f"第 {number} 行子号重复")
        if len(password) > 1024 or re.search(r"[\x00-\x1f\x7f]", password):
            raise store.GmailStoreError("invalid_password", f"第 {number} 行 GPT 密码格式无效")
        if secret:
            secret = re.sub(r"\s+", "", secret).upper().rstrip("=")
            try:
                if not re.fullmatch(r"[A-Z2-7]{2,256}", secret):
                    raise ValueError
                raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
                if base64.b32encode(raw).decode().rstrip("=") != secret:
                    raise ValueError
            except (ValueError, binascii.Error):
                raise store.GmailStoreError("invalid_totp", f"第 {number} 行 2FA 密钥必须为有效 Base32") from None
        rows.append((email, password, secret))
        seen.add(email)
    if not rows or len(rows) > 1000:
        raise store.GmailStoreError("invalid_import", "每次须导入 1 至 1000 个 Gmail 子号")
    return rows


def _active(lease):
    return bool(lease and lease.expires_at.replace(tzinfo=timezone.utc) > store.utcnow())


def validate_invite_inputs(session, *, emails=(), account_ids=()):
    """Fence direct BUSINESS routes before they read or mutate remote state."""
    from services.gmail_plan_support import gmail_registration_ready, account_mail_provider
    for raw_email in emails or ():
        email = str(raw_email or "").strip().lower()
        require_gmail_alias(session, email)
        plan = session.exec(select(GptPlanAccountModel).where(func.lower(GptPlanAccountModel.email) == email)).first()
        if plan is None or not gmail_registration_ready(plan):
            raise store.GmailStoreError("gmail_registration_required", "手动邀请仅支持已登录核验且收件可用的 Gmail 子号", 409)
    for account_id in account_ids or ():
        if type(account_id) is not int or account_id <= 0:
            raise store.GmailStoreError("invalid_account_id", "请选择有效的 Gmail 子号账号")
        plan = session.get(GptPlanAccountModel, account_id)
        if plan is None:
            raise store.GmailStoreError("account_not_found", "所选 Gmail 子号账号不存在", 404)
        require_gmail_alias(session, plan.email)
        if account_mail_provider(plan) != "gmail":
            raise store.GmailStoreError("gmail_required", "邀请仅支持 Gmail 子号")


def import_ordinary(data: str, registration_status: str = "unregistered") -> dict:
    rows = _parse(data, registration_status)
    from services.gmail_registration import _existing, _has_registered_identity
    items, created, updated = [], 0, 0
    with Session(store.engine) as session:
        # Acquire the same write fence as registration before checking ownership.
        session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
        prepared = []
        for email, password, secret in rows:
            alias, _ = require_gmail_alias(session, email)
            registered, plan = _existing(session, alias)
            if alias.registration_lease_token or alias.production_job_id:
                raise store.GmailStoreError("alias_busy", "子号正在执行注册或生产任务，请任务结束后再导入", 409)
            if alias.registration_stage in {"account_deactivated", "source_exhausted"}:
                raise store.GmailStoreError("alias_unavailable", "已停用或停止生产的子号不能通过导入重置", 409)
            if plan and (plan.business_parent_id or plan.catalog_category in {"member", "refunded"}
                    or str(plan.plan_type or "").lower() not in {"", "free", "chatgptfreeplan"}):
                raise store.GmailStoreError("not_ordinary", "已加入 BUSINESS、付费或退款的账号不能通过普通号导入覆盖", 409)
            if (plan and _active(session.get(GptPlanAccountOperationLeaseModel, plan.id))) or _active(
                    session.get(ChatGptSecurityOperationLeaseModel, email)):
                raise store.GmailStoreError("account_busy", "账号正在执行登录或安全操作，请稍后再导入", 409)
            verified = _has_registered_identity(registered, plan)
            if registration_status == "unregistered" and (verified or alias.registration_status == "registered" or alias.registered_at):
                raise store.GmailStoreError("registered_account", "已有注册记录的子号不能改成未注册，避免重复注册", 409)
            prepared.append((alias, plan, password, secret, verified))
        now = store.utcnow()
        for alias, plan, password, secret, verified in prepared:
            if plan is None:
                plan = GptPlanAccountModel(email=alias.email, catalog_category="regular", source_state="regular")
                created += 1
            else:
                updated += 1
            bind_gmail_plan(session, plan)
            extra = _extra(plan)
            extra.update(workspace_registration_declaration=registration_status,
                         workspace_registration_declared_at=now.isoformat())
            plan.extra_json = json.dumps(extra, ensure_ascii=False)
            plan.updated_at = now
            session.add(plan)
            session.flush()
            alias.gpt_plan_account_id = plan.id
            if registration_status == "registered":
                alias.registration_status = "registered"
                if not verified:
                    alias.registration_stage = "imported_registered_unverified"
                alias.registration_retry_at = None
                alias.registration_error = ""
            else:
                alias.registration_status = "unregistered"
                alias.registration_stage = ""
                alias.registration_retry_at = None
                alias.registration_error = ""
            alias.registration_updated_at = now
            session.add(alias)
            if password or secret:
                security = session.get(ChatGptAccountSecurityModel, alias.email) or ChatGptAccountSecurityModel(email=alias.email)
                if password:
                    security.password_ciphertext = encrypt_credential(alias.email, "password", password)
                    security.password_state = "imported_unverified"
                    security.password_updated_at = now
                if secret:
                    security.totp_secret_ciphertext = encrypt_credential(alias.email, "totp_secret", secret)
                    security.mfa_state = "imported_unverified"
                    security.mfa_updated_at = now
                    security.recovery_codes_ciphertext = ""
                security.updated_at = now
                security.last_error = ""
                session.add(security)
            items.append({"alias_id": alias.id, "email": alias.email, "gpt_plan_account_id": plan.id,
                          "registration_status": alias.registration_status,
                          "registration_verification": "verified" if verified else "declared" if registration_status == "registered" else "unregistered"})
        session.commit()
    return {"total": len(items), "created": created, "updated": updated, "items": items}


def import_gmail_bundle(data: str) -> dict:
    """Import one hidden Gmail receiver and its ordinary child inventory."""
    try:
        payload = json.loads(str(data or ""))
    except (TypeError, ValueError):
        raise store.GmailStoreError("invalid_bundle", "Gmail 子号迁移包不是有效 JSON") from None
    if (not isinstance(payload, dict)
            or payload.get("schema") != "gmail-business-manager.ordinary-gmail.v1"
            or payload.get("version") != 1):
        raise store.GmailStoreError("invalid_bundle", "不支持的 Gmail 子号迁移包版本")
    receiver = payload.get("receiver")
    children = payload.get("children")
    if not isinstance(receiver, dict) or not isinstance(children, list) or not children:
        raise store.GmailStoreError("invalid_bundle", "迁移包缺少接码资料或子号")
    if len(children) > store.MAX_ALIASES_PER_SOURCE:
        raise store.GmailStoreError("alias_limit", f"一个 Gmail 母号最多导入 {store.MAX_ALIASES_PER_SOURCE} 个子号")
    source_email = store.normalize_source_email(receiver.get("email"))
    app_password = store.normalize_app_password(receiver.get("app_password"))
    # A source-side localhost/Clash proxy is not portable to the Linux target.
    # The target validates Gmail directly and can use its own network routing.
    proxy_url = ""
    normalized_children = []
    seen = set()
    local = source_email.split("@", 1)[0]
    for index, item in enumerate(children, 1):
        if not isinstance(item, dict):
            raise store.GmailStoreError("invalid_bundle", f"第 {index} 个子号资料无效")
        email = str(item.get("email") or "").strip().lower()
        tag = str(item.get("tag") or "").strip().lower()
        expected = f"{local}+{tag}@gmail.com"
        if not re.fullmatch(r"[a-z0-9-]{1,64}", tag) or email != expected:
            raise store.GmailStoreError("invalid_alias", f"第 {index} 个子号与 Gmail 母号不匹配")
        if email in seen:
            raise store.GmailStoreError("duplicate_alias", f"第 {index} 个子号重复")
        seen.add(email)
        status = str(item.get("registration_status") or "unregistered").strip().lower()
        if status not in {"unregistered", "registered"}:
            status = "registered" if item.get("registered_at") else "unregistered"
        normalized_children.append({
            "email": email,
            "tag": tag,
            "status": status,
            "password": str(item.get("chatgpt_password") or ""),
            "totp": re.sub(r"\s+", "", str(item.get("chatgpt_totp_secret") or "")).upper().rstrip("="),
            "chatgpt_user_id": str(item.get("chatgpt_user_id") or ""),
            "chatgpt_account_id": str(item.get("chatgpt_account_id") or ""),
        })
    # Verify the shared receiver once before writing any child.
    store._check_app_password(source_email, app_password, proxy_url)
    from core.gmail_crypto import encrypt_gmail_password
    now = store.utcnow()
    created = updated = 0
    with Session(store.engine) as session:
        session.execute(update(store.GmailSource).where(store.GmailSource.email == source_email).values(
            email=store.GmailSource.email))
        source = session.exec(select(store.GmailSource).where(store.GmailSource.email == source_email)).first()
        if source is None:
            source = store.GmailSource(email=source_email)
            session.add(source)
            session.flush()
        source.app_password_ciphertext = encrypt_gmail_password(source_email, app_password)
        source.proxy_url = proxy_url
        source.enabled = True
        source.status = "ok"
        source.usability_status = "usable"
        source.usability_method = "imap"
        source.usability_checked_at = now
        source.usability_error = ""
        source.receive_verified = True
        source.last_checked_at = now
        source.last_error = ""
        source.generated_alias_count = max(int(source.generated_alias_count or 0), len(normalized_children))
        source.updated_at = now
        session.add(source)
        session.flush()

        result_items = []
        for item in normalized_children:
            alias = session.exec(select(store.GmailAlias).where(store.GmailAlias.email == item["email"])).first()
            if alias is not None and alias.source_id != source.id:
                raise store.GmailStoreError("alias_conflict", f'{item["email"]} 已绑定其他接码母号', 409)
            if alias is None:
                alias = store.GmailAlias(source_id=source.id, tag=item["tag"], email=item["email"])
                session.add(alias)
                session.flush()
                created += 1
            else:
                updated += 1
            if alias.registration_lease_token or alias.production_job_id:
                raise store.GmailStoreError("alias_busy", f'{item["email"]} 正在执行任务，未覆盖', 409)
            plan = session.exec(select(GptPlanAccountModel).where(GptPlanAccountModel.email == item["email"])).first()
            if plan and (plan.business_parent_id or plan.catalog_category in {"member", "refunded"}):
                raise store.GmailStoreError("not_ordinary", f'{item["email"]} 已是 BUSINESS、会员或退款账号', 409)
            if plan is None:
                plan = GptPlanAccountModel(email=item["email"], catalog_category="regular", source_state="regular")
            incoming_status = item["status"]
            if incoming_status == "unregistered" and (
                    alias.registration_status == "registered" or alias.registered_at
                    or plan.chatgpt_user_id or plan.chatgpt_account_id or plan.cookie_blob
                    or (plan.last_login_at and not plan.last_login_error)):
                incoming_status = "registered"
            bind_gmail_plan(session, plan)
            extra = _extra(plan)
            extra.update(
                workspace_registration_declaration=incoming_status,
                workspace_registration_declared_at=now.isoformat(),
                gmail_bundle_export_id=str(payload.get("export_id") or ""),
            )
            plan.extra_json = json.dumps(extra, ensure_ascii=False)
            plan.chatgpt_user_id = plan.chatgpt_user_id or item["chatgpt_user_id"]
            plan.chatgpt_account_id = plan.chatgpt_account_id or item["chatgpt_account_id"]
            plan.updated_at = now
            session.add(plan)
            session.flush()
            alias.gpt_plan_account_id = plan.id
            alias.registration_status = incoming_status
            verified_identity = bool(
                plan.chatgpt_user_id or plan.chatgpt_account_id or plan.cookie_blob
                or (plan.last_login_at and not plan.last_login_error)
            )
            alias.registration_stage = (
                "" if verified_identity
                else alias.registration_stage if alias.registration_stage in {"security_pending", "security_paused"}
                else "imported_registered_unverified"
            ) if incoming_status == "registered" else ""
            alias.registration_error = ""
            alias.registration_retry_at = None
            alias.registration_updated_at = now
            session.add(alias)
            if item["password"] or item["totp"]:
                security = session.get(ChatGptAccountSecurityModel, item["email"]) or ChatGptAccountSecurityModel(email=item["email"])
                if item["password"] and security.password_state != "configured":
                    security.password_ciphertext = encrypt_credential(item["email"], "password", item["password"])
                    security.password_state = "imported_unverified"
                    security.password_updated_at = now
                if item["totp"] and security.mfa_state != "enabled":
                    try:
                        raw = base64.b32decode(item["totp"] + "=" * (-len(item["totp"]) % 8))
                        if base64.b32encode(raw).decode().rstrip("=") != item["totp"]:
                            raise ValueError
                    except (ValueError, binascii.Error):
                        raise store.GmailStoreError("invalid_totp", f'{item["email"]} 的 GPT 2FA 密钥无效') from None
                    security.totp_secret_ciphertext = encrypt_credential(item["email"], "totp_secret", item["totp"])
                    security.mfa_state = "imported_unverified"
                    security.mfa_updated_at = now
                security.updated_at = now
                security.last_error = ""
                session.add(security)
            result_items.append({"alias_id": alias.id, "email": alias.email,
                                 "gpt_plan_account_id": plan.id, "registration_status": alias.registration_status})
        session.commit()
    return {"ok": True, "total": len(result_items), "created": created, "updated": updated,
            "receiver": source_email, "receive_ready": True, "items": result_items}


def summary():
    with Session(store.engine) as session:
        sources = session.exec(select(func.count(store.GmailSource.id))).one()
        aliases = session.exec(select(store.GmailAlias)).all()
        business = session.exec(select(func.count(GptPlanAccountModel.id)).where(
            func.lower(GptPlanAccountModel.plan_type).in_(("team", "business", "chatgptteamplan", "chatgptbusinessplan", "self_serve_business", "business_master")),
            GptPlanAccountModel.business_parent_id.is_(None))).one()
        registered = sum(row.registration_status == "registered" for row in aliases)
        return {"gmail_sources": sources, "ordinary_total": len(aliases), "ordinary_registered": registered,
                "ordinary_unregistered": sum(row.registration_status == "unregistered" for row in aliases),
                "ordinary_pending": len(aliases) - registered - sum(row.registration_status == "unregistered" for row in aliases),
                "business_mothers": business}
