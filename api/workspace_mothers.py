"""Explicit BUSINESS mother import; it does not fabricate seat availability."""
import base64
import json
import re
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from api.gmail import _SafeValidationRoute
from core.db import (engine, GptPlanAccountModel, GptBusinessAccountModel,
                     ChatGptAccountSecurityModel)
from core.credential_crypto import encrypt_credential

router = APIRouter(prefix="/workspace", tags=["workspace"], route_class=_SafeValidationRoute)
TRANSFER_SCHEMA = "gmail-business-manager.business-mother.v1"


class MotherImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: SecretStr
    mail_provider: Literal["outlook", "icloud", "gmail"] = "outlook"
    enabled: bool = True


def _parse_transfer_bundle(data: str):
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        raise HTTPException(422, "母号迁移包不是有效 JSON") from None
    if not isinstance(payload, dict) or payload.get("schema") != TRANSFER_SCHEMA or payload.get("version") != 1:
        raise HTTPException(422, "不支持的母号迁移包版本")
    account = payload.get("account")
    if not isinstance(account, dict):
        raise HTTPException(422, "母号迁移包缺少账号资料")
    provider = str(account.get("mail_provider") or "").strip().lower()
    if provider not in {"outlook", "icloud", "gmail"}:
        raise HTTPException(422, "母号迁移包的邮箱类型无效")
    email = str(account.get("email") or "").strip().casefold()
    password = str(account.get("chatgpt_password") or "")
    totp = str(account.get("totp_secret") or "").replace(" ", "").upper()
    client_id = str(account.get("client_id") or "").strip()
    refresh_token = str(account.get("refresh_token") or "").strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254 or not password:
        raise HTTPException(422, "母号迁移包的邮箱或 ChatGPT 密码无效")
    try:
        decoded = base64.b32decode(totp + "=" * ((-len(totp)) % 8))
        if len(decoded) < 10:
            raise ValueError()
    except Exception:
        raise HTTPException(422, "母号迁移包的 2FA 密钥无效") from None
    if provider == "outlook" and (client_id or refresh_token):
        try:
            UUID(client_id)
        except ValueError:
            raise HTTPException(422, "母号迁移包的 Outlook client_id 必须是 UUID") from None
        if not refresh_token:
            raise HTTPException(422, "母号迁移包的 Outlook 刷新凭据不完整")
    else:
        client_id = refresh_token = ""
    return [(email, password, totp, client_id, refresh_token)], provider


def _parse(data):
    stripped = str(data or "").strip()
    if stripped.startswith("{"):
        return _parse_transfer_bundle(stripped)
    rows, seen = [], set()
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if not lines or len(lines) > 500:
        raise HTTPException(422, "每次请输入 1–500 个母号")
    for number, line in enumerate(lines, 1):
        fields = [x.strip() for x in re.split(r"-{3,}", line)]
        if len(fields) not in (2, 3, 4):
            raise HTTPException(422, f"第 {number} 行格式错误：邮箱----密码[----2FA]，或 Outlook 四段资料")
        email, password = fields[:2]
        email = email.casefold()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254 or not password:
            raise HTTPException(422, f"第 {number} 行邮箱或密码无效")
        if email in seen:
            raise HTTPException(422, f"第 {number} 行母号重复")
        seen.add(email)
        totp = cid = rt = ""
        if len(fields) == 3:
            totp = fields[2].replace(" ", "").upper()
            try:
                decoded = base64.b32decode(totp + "=" * ((-len(totp)) % 8))
                if len(decoded) < 10:
                    raise ValueError()
            except Exception:
                raise HTTPException(422, f"第 {number} 行 2FA 密钥格式无效") from None
        if len(fields) == 4:
            try:
                UUID(fields[2]); cid, rt = fields[2:]
            except ValueError:
                try:
                    UUID(fields[3]); rt, cid = fields[2:]
                except ValueError:
                    raise HTTPException(422, f"第 {number} 行 Outlook client_id 必须是 UUID") from None
            if not rt:
                raise HTTPException(422, f"第 {number} 行 Outlook 刷新凭据不能为空")
        rows.append((email, password, totp, cid, rt))
    return rows, None


@router.post("/business/import")
def import_mothers(body: MotherImport):
    parsed, bundled_provider = _parse(body.data.get_secret_value())
    mail_provider = bundled_provider or body.mail_provider
    if mail_provider != "outlook" and any(row[3] for row in parsed):
        raise HTTPException(422, "四段邮箱授权格式仅适用于 Outlook")
    now = datetime.now(timezone.utc)
    items, skipped = [], 0
    try:
        with Session(engine) as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            for email, password, totp, cid, rt in parsed:
                existing = session.exec(select(GptPlanAccountModel).where(GptPlanAccountModel.email == email)).first()
                source = session.exec(select(GptBusinessAccountModel).where(GptBusinessAccountModel.email == email)).first()
                if existing:
                    if (existing.source_pool != "gpt_business" or not source
                            or existing.source_account_id != source.id or existing.business_parent_id is not None
                            or existing.catalog_category != "member"):
                        raise HTTPException(409, "导入包含已在其他账号目录中的邮箱，请先处理原账号")
                    items.append({"account_id": existing.id, "email": email, "skipped": True})
                    skipped += 1
                    continue
                if source:
                    raise HTTPException(409, "母号来源已存在但目录绑定缺失，请先修复原绑定")
                from services.gmail_store import GmailAlias
                if session.exec(select(GmailAlias).where(GmailAlias.email == email)).first() is not None:
                    raise HTTPException(409, "此邮箱已是 Gmail 普通子号，不能同时导入为 BUSINESS 母号")
                extra = {"mail_provider": mail_provider, "workspace_import": "mother",
                         "workspace_verification": "pending_login"}
                source = GptBusinessAccountModel(
                    email=email, enabled=body.enabled, client_id=cid, refresh_token=rt,
                    mail_access_type="graph" if cid else "", extra_json=json.dumps(extra),
                )
                session.add(source); session.flush()
                plan = GptPlanAccountModel(
                    email=email, enabled=body.enabled, mail_provider=mail_provider,
                    client_id=cid, refresh_token=rt, mail_access_type=source.mail_access_type,
                    catalog_category="member", plan_type="business_master",
                    source_pool="gpt_business", source_account_id=source.id,
                    source_state="never_logged", extra_json=json.dumps(extra),
                )
                security = session.get(ChatGptAccountSecurityModel, email)
                if security is not None:
                    raise HTTPException(409, "导入包含已有安全凭据的邮箱，未覆盖原凭据")
                security = ChatGptAccountSecurityModel(
                    email=email, password_ciphertext=encrypt_credential(email, "password", password),
                    password_state="imported_unverified", password_updated_at=now,
                )
                if totp:
                    security.totp_secret_ciphertext = encrypt_credential(email, "totp_secret", totp)
                    security.mfa_state, security.mfa_updated_at = "imported_unverified", now
                session.add(security); session.add(plan); session.flush()
                items.append({"account_id": plan.id, "email": email, "skipped": False})
            session.commit()
    except IntegrityError:
        raise HTTPException(409, "账号已被另一操作导入，请刷新后重试；本次没有部分写入") from None
    imported = len(items) - skipped
    return {"ok": True, "success": imported, "imported": imported, "skipped": skipped,
            "failed": 0, "items": items, "message": "母号已导入；请登录并刷新工作区以读取真实席位"}
