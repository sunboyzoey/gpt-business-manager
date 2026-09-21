"""Guarded export of one confirmed BUSINESS mother to the standalone manager."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from sqlmodel import Session

from core.db import engine, GptBusinessAccountModel, GptPlanAccountModel


router = APIRouter(prefix="/gpt-plans", tags=["gpt-plans"])
SCHEMA = "gmail-business-manager.business-mother.v1"
TEAM_PLAN_TYPES = {
    "team", "business", "chatgptteamplan", "chatgptbusinessplan",
    "self_serve_business", "self_serve_business_prolite", "business_master",
}


def _safe_filename(email: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", email).strip("._") or "business-mother"


@router.post("/accounts/{account_id}/business-manager-export")
def export_business_manager_mother(account_id: int, request: Request):
    """Export login material only; the destination refreshes real workspace state."""
    from api.auth import require_sensitive_credential_export_auth_header
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets,
        get_chatgpt_security_status,
    )
    from services.gmail_plan_support import account_mail_provider

    require_sensitive_credential_export_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    with Session(engine) as session:
        account = session.get(GptPlanAccountModel, int(account_id))
        if account is None:
            raise HTTPException(404, "账号不存在")
        if account.business_parent_id is not None:
            raise HTTPException(409, "BUSINESS 子号不能导出为母号")
        source_pool = str(account.source_pool or "").strip().lower()
        source = None
        if source_pool == "gpt_business":
            source_id = int(account.source_account_id or 0)
            source = session.get(GptBusinessAccountModel, source_id) if source_id > 0 else None
            if source is None or str(source.email or "").strip().casefold() != str(account.email or "").strip().casefold():
                raise HTTPException(409, "BUSINESS 母号来源绑定不完整，请先刷新账号")
        elif str(account.plan_type or "").strip().lower() not in TEAM_PLAN_TYPES or account.plan_checked_at is None:
            raise HTTPException(409, "只有已登录确认的 BUSINESS 母号可以导出")
        if account.refund_status or (source is not None and source.refund_status):
            raise HTTPException(409, "已退款或退款中的 BUSINESS 母号不能导出")
        provider = account_mail_provider(account)
        client_id = str(account.client_id or (source.client_id if source else "") or "").strip()
        refresh_token = str(account.refresh_token or (source.refresh_token if source else "") or "").strip()
        email = str(account.email or "").strip().casefold()

    try:
        status = get_chatgpt_security_status(email)
        secrets = get_chatgpt_security_secrets(email)
    except Exception as exc:
        raise HTTPException(409, "账号安全凭据无法解密") from exc
    password = str(secrets.get("password") or "")
    totp_secret = str(secrets.get("totp_secret") or "")
    if (
        not password
        or not totp_secret
        or status.get("password_state") != "configured"
        or status.get("mfa_state") != "enabled"
    ):
        raise HTTPException(409, "请先完成并确认该母号的 ChatGPT 密码与 Authenticator 2FA")

    bundle = {
        "schema": SCHEMA,
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "account": {
            "email": email,
            "chatgpt_password": password,
            "totp_secret": totp_secret,
            "mail_provider": provider if provider in {"outlook", "icloud", "gmail"} else "outlook",
            "client_id": client_id,
            "refresh_token": refresh_token,
        },
    }
    return Response(
        content=json.dumps(bundle, ensure_ascii=False, indent=2) + "\n",
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_filename(email)}_business_mother.json"',
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )
