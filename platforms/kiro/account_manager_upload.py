"""Kiro Account Manager 自动导入"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

DEFAULT_PROVIDER = "BuilderId"
DEFAULT_REGION = "us-east-1"
DEFAULT_START_URL = "https://view.awsapps.com/start"


def _get_config_value(key: str) -> str:
    try:
        from core.config_store import config_store

        return str(config_store.get(key, "") or "")
    except Exception:
        return ""


def _default_storage_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / ".kiro-account-manager" / "accounts.json"

    if os.name == "posix" and os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / ".kiro-account-manager" / "accounts.json"

    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / ".kiro-account-manager" / "accounts.json"

    return Path.home() / ".local" / "share" / ".kiro-account-manager" / "accounts.json"


def resolve_manager_path(path: str | None = None) -> Path:
    raw = str(path or _get_config_value("kiro_manager_path") or "").strip()
    target = Path(raw).expanduser() if raw else _default_storage_path()
    if target.suffix.lower() != ".json":
        target = target / "accounts.json"
    return target


def _atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _load_accounts(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.error(f"Kiro Manager 读取失败: {e}")
        return []


def _calc_client_id_hash(start_url: str) -> str:
    input_str = json.dumps({"startUrl": start_url}, separators=(",", ":"))
    return hashlib.sha1(input_str.encode("utf-8"), usedforsecurity=False).hexdigest()


def _guess_expires_at(access_token: str, existing: dict | None = None) -> str | None:
    if existing and existing.get("expiresAt"):
        return existing.get("expiresAt")
    # Builder ID access token 过期时间一般较短，这里给一个温和兜底
    dt = datetime.now(timezone.utc) + timedelta(hours=1)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _find_existing_index(accounts: list[dict], email: str | None, user_id: str | None) -> int | None:
    if user_id:
        for idx, item in enumerate(accounts):
            if item.get("userId") == user_id:
                return idx
    if email:
        for idx, item in enumerate(accounts):
            if item.get("email") == email:
                return idx
    return None


def build_manager_account(account, existing: dict | None = None) -> dict:
    extra = getattr(account, "extra", {}) or {}
    access_token = extra.get("accessToken") or extra.get("access_token") or getattr(account, "token", "")
    refresh_token = extra.get("refreshToken") or extra.get("refresh_token") or ""
    client_id = extra.get("clientId") or extra.get("client_id") or ""
    client_secret = extra.get("clientSecret") or extra.get("client_secret") or ""
    if not refresh_token:
        raise ValueError("账号缺少 refreshToken")
    if not client_id or not client_secret:
        raise ValueError("账号缺少 clientId / clientSecret")

    provider = extra.get("provider") or DEFAULT_PROVIDER
    start_url = extra.get("startUrl") or extra.get("start_url")
    region = extra.get("region") or DEFAULT_REGION
    email = getattr(account, "email", "") or extra.get("email")
    user_id = extra.get("userId") or extra.get("user_id") or getattr(account, "user_id", "") or None

    if provider == "BuilderId" and not email:
        raise ValueError("BuilderId 账号缺少 email")

    if provider == "Enterprise" and not start_url:
        start_url = DEFAULT_START_URL

    client_id_hash = (
        extra.get("clientIdHash")
        or extra.get("client_id_hash")
        or (existing or {}).get("clientIdHash")
        or _calc_client_id_hash(start_url or DEFAULT_START_URL)
    )
    machine_id = (
        extra.get("machineId")
        or extra.get("machine_id")
        or (existing or {}).get("machineId")
        or uuid.uuid4().hex.lower()
    )

    label = (existing or {}).get("label") or (
        "Kiro Enterprise 账号" if provider == "Enterprise" else "Kiro BuilderId 账号"
    )
    added_at = (existing or {}).get("addedAt") or datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    record = {
        "id": (existing or {}).get("id") or str(uuid.uuid4()),
        "email": email or None,
        "password": getattr(account, "password", "") or (existing or {}).get("password"),
        "label": label,
        "status": "active",
        "addedAt": added_at,
        "accessToken": access_token or (existing or {}).get("accessToken"),
        "refreshToken": refresh_token,
        "expiresAt": _guess_expires_at(access_token, existing=existing),
        "provider": provider,
        "userId": user_id or (existing or {}).get("userId"),
        "authMethod": extra.get("authMethod") or extra.get("auth_method") or "IdC",
        "clientId": client_id,
        "clientSecret": client_secret,
        "region": region,
        "clientIdHash": client_id_hash,
        "ssoSessionId": extra.get("ssoSessionId") or (existing or {}).get("ssoSessionId"),
        "idToken": extra.get("idToken") or (existing or {}).get("idToken"),
        "startUrl": start_url or (existing or {}).get("startUrl"),
        "profileArn": extra.get("profileArn") or (existing or {}).get("profileArn") or "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
        "usageData": (existing or {}).get("usageData"),
        "groupId": (existing or {}).get("groupId"),
        "tagLinks": (existing or {}).get("tagLinks") or [],
        "machineId": machine_id,
        "availableModelsCache": (existing or {}).get("availableModelsCache"),
    }
    return record


def upload_to_kiro_manager(account, path: str | None = None) -> Tuple[bool, str]:
    """将 Kiro 账号直接写入 kiro-account-manager 的 accounts.json。"""
    storage_path = resolve_manager_path(path)
    accounts = _load_accounts(storage_path)
    extra = getattr(account, "extra", {}) or {}
    email = getattr(account, "email", "") or extra.get("email")
    user_id = extra.get("userId") or extra.get("user_id") or getattr(account, "user_id", "") or None
    existing_idx = _find_existing_index(accounts, email, user_id)
    existing = accounts[existing_idx] if existing_idx is not None else None

    record = build_manager_account(account, existing=existing)
    if existing_idx is None:
        accounts.insert(0, record)
        action = "导入成功"
    else:
        accounts[existing_idx] = record
        action = "更新成功"

    try:
        _atomic_write(storage_path, json.dumps(accounts, ensure_ascii=False, indent=2))
        return True, f"{action}: {storage_path}"
    except Exception as e:
        logger.error(f"Kiro Manager 写入失败: {e}")
        return False, f"写入失败: {e}"


def sync_to_kiro_manager_api(account, api_url: str | None = None, api_key: str | None = None) -> Tuple[bool, str]:
    """将 Kiro 账号通过 HTTP API 同步到远程 Kiro Manager 服务器。"""
    import requests

    url = str(api_url or _get_config_value("kiro_manager_api_url") or "").strip().rstrip("/")
    key = str(api_key or _get_config_value("kiro_manager_api_key") or "").strip()
    if not url:
        return False, "未配置 Kiro Manager API 地址"
    if not key:
        return False, "未配置 Kiro Manager API Key"

    extra = getattr(account, "extra", {}) or {}
    refresh_token = extra.get("refreshToken") or extra.get("refresh_token") or ""
    if not refresh_token:
        return False, "账号缺少 refreshToken"

    client_id = extra.get("clientId") or extra.get("client_id") or ""
    client_secret = extra.get("clientSecret") or extra.get("client_secret") or ""
    auth_method = extra.get("authMethod") or extra.get("auth_method") or "idc"
    region = extra.get("region") or "us-east-1"
    machine_id = extra.get("machineId") or extra.get("machine_id") or ""

    payload: dict = {
        "refreshToken": refresh_token,
        "authMethod": auth_method,
        "plan": "free",
        "priority": 100,
    }
    if client_id:
        payload["clientId"] = client_id
    if client_secret:
        payload["clientSecret"] = client_secret
    if region:
        payload["authRegion"] = region
    if machine_id:
        payload["machineId"] = machine_id

    endpoint = f"{url}/api/admin/credentials"
    try:
        r = requests.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json", "x-api-key": key},
            timeout=15,
        )
        data = r.json() if r.content else {}
        if r.status_code == 200 and data.get("success"):
            cred_id = data.get("credentialId", "")
            return True, f"同步成功，ID: {cred_id}"
        msg = data.get("message") or data.get("error") or r.text[:200]
        return False, f"同步失败 ({r.status_code}): {msg}"
    except Exception as e:
        logger.error(f"Kiro Manager API 同步失败: {e}")
        return False, f"同步异常: {e}"
