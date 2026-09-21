"""
Sub2API 上传功能
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Tuple
from urllib.parse import unquote, urlsplit

from curl_cffi import requests as cffi_requests

from platforms.chatgpt.cpa_upload import generate_token_json

logger = logging.getLogger(__name__)

DEFAULT_GROUP_IDS = [2]
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


@dataclass(frozen=True)
class Sub2ApiUploadResult:
    """Credential-free result for callers that need the created remote id."""

    ok: bool
    message: str
    status_code: int = 0
    remote_account_id: str = ""
    proxy_sync_status: str = "not_configured"

    def as_tuple(self) -> Tuple[bool, str]:
        """Preserve the historical ``(ok, message)`` API."""
        return self.ok, self.message


def _get_config_value(key: str) -> str:
    try:
        from core.config_store import config_store

        return str(config_store.get(key, "") or "").strip()
    except Exception:
        return ""


def _parse_group_ids(raw: Any, fallback: list[int] | None = None) -> list[int]:
    candidates: list[Any]
    if isinstance(raw, str):
        candidates = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        candidates = list(raw)
    elif raw is None:
        candidates = []
    else:
        candidates = [raw]

    values: list[int] = []
    for item in candidates:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            values.append(int(text))
        except ValueError:
            continue

    return values or list(fallback or DEFAULT_GROUP_IDS)


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _extract_auth(payload: dict[str, Any]) -> dict[str, Any]:
    auth_info = payload.get("https://api.openai.com/auth")
    return auth_info if isinstance(auth_info, dict) else {}


def _extract_organization_id(id_token_payload: dict[str, Any]) -> str:
    auth_info = _extract_auth(id_token_payload)
    organization_id = str(auth_info.get("organization_id") or "").strip()
    if organization_id:
        return organization_id

    organizations = auth_info.get("organizations") or []
    if isinstance(organizations, list):
        for item in organizations:
            if isinstance(item, dict):
                organization_id = str(item.get("id") or "").strip()
                if organization_id:
                    return organization_id
    return ""


def _format_utc_timestamp(value: Any) -> str:
    """把账号自身携带的订阅到期时间规范成 RFC3339；无法确认则不输出。"""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp <= 0:
            return ""
        if timestamp > 10_000_000_000:
            timestamp /= 1000
        try:
            value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return ""
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        if text.isdigit():
            return _format_utc_timestamp(int(text))
        try:
            value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return ""
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _extract_profile_email(payload: dict[str, Any]) -> str:
    profile = payload.get("https://api.openai.com/profile")
    if isinstance(profile, dict):
        email = str(profile.get("email") or "").strip()
        if email:
            return email
    return str(payload.get("email") or "").strip()


def _require_consistent_values(
    label: str,
    values: tuple[Any, ...],
    *,
    case_insensitive: bool = False,
) -> None:
    normalized: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        normalized.add(text.casefold() if case_insensitive else text)
    if len(normalized) > 1:
        raise ValueError(f"目标账号的 {label} 在 OAuth 凭证来源之间不一致")


def _build_sub2api_account_payload_from_token_data(
    token_data: dict[str, Any],
    *,
    account: Any = None,
    group_ids: list[int] | None = None,
    sequence_index: int | None = None,
) -> dict[str, Any]:
    """生成 Sub2API 账号格式 (无 session_token)。

    对齐 Sub2API 20260827 管理后台导出结构。这里只使用目标账号自己的
    OAuth/JWT 身份字段；不会从参考文件复制 token、账号 ID 或额度缓存。

    ``sequence_index`` 仅为兼容旧调用保留。新格式要求 name/notes/email 一致，
    不再用日期和序号生成账号名。
    """
    access_token = str(token_data.get("access_token") or "").strip()
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    id_token = str(token_data.get("id_token") or getattr(account, "id_token", "") or "").strip()

    access_payload = _decode_jwt_payload(access_token)
    access_auth = _extract_auth(access_payload)
    id_payload = _decode_jwt_payload(id_token)
    id_auth = _extract_auth(id_payload)
    account_extra = _get_account_extra(account)

    token_email = str(token_data.get("email") or "").strip()
    account_email = str(getattr(account, "email", "") or "").strip()
    access_email = _extract_profile_email(access_payload)
    id_email = _extract_profile_email(id_payload)
    _require_consistent_values(
        "email",
        (token_email, account_email, access_email, id_email),
        case_insensitive=True,
    )
    _require_consistent_values(
        "chatgpt_account_id",
        (
            access_auth.get("chatgpt_account_id"),
            id_auth.get("chatgpt_account_id"),
            token_data.get("chatgpt_account_id"),
        ),
    )
    _require_consistent_values(
        "chatgpt_user_id",
        (
            access_auth.get("chatgpt_user_id"),
            id_auth.get("chatgpt_user_id"),
            token_data.get("chatgpt_user_id"),
        ),
    )

    email = str(
        _first_non_empty(
            token_email,
            account_email,
            access_email,
            id_email,
        )
        or ""
    ).strip()
    missing = [
        name
        for name, value in (
            ("email", email),
            ("access_token", access_token),
            ("refresh_token", refresh_token),
        )
        if not value
    ]
    if missing:
        raise ValueError(f"目标账号缺少必要凭证字段: {', '.join(missing)}")

    expires_at_raw = _first_non_empty(
        access_payload.get("exp"),
        token_data.get("expires_at"),
        getattr(account, "expires_at", None),
    )
    try:
        expires_at = int(expires_at_raw or 0)
    except (TypeError, ValueError):
        expires_at = 0
    if expires_at > 10_000_000_000:
        expires_at //= 1000

    organization_id = str(
        _first_non_empty(
            token_data.get("organization_id"),
            _extract_organization_id(access_payload),
            _extract_organization_id(id_payload),
            getattr(account, "organization_id", ""),
        )
        or ""
    ).strip()
    plan_type = str(
        _first_non_empty(
            token_data.get("plan_type"),
            access_auth.get("chatgpt_plan_type"),
            id_auth.get("chatgpt_plan_type"),
            getattr(account, "plan_type", ""),
            account_extra.get("plan_type"),
        )
        or ""
    ).strip()

    chatgpt_account_id = str(
        _first_non_empty(
            access_auth.get("chatgpt_account_id"),
            id_auth.get("chatgpt_account_id"),
            token_data.get("chatgpt_account_id"),
            token_data.get("account_id"),
            getattr(account, "account_id", ""),
        )
        or ""
    ).strip()
    chatgpt_user_id = str(
        _first_non_empty(
            access_auth.get("chatgpt_user_id"),
            id_auth.get("chatgpt_user_id"),
            token_data.get("chatgpt_user_id"),
            getattr(account, "user_id", ""),
        )
        or ""
    ).strip()
    client_id = str(
        _first_non_empty(
            token_data.get("client_id"),
            getattr(account, "client_id", ""),
            DEFAULT_CLIENT_ID,
        )
        or DEFAULT_CLIENT_ID
    ).strip() or DEFAULT_CLIENT_ID

    subscription_expires_at = _format_utc_timestamp(
        _first_non_empty(
            token_data.get("subscription_expires_at"),
            access_auth.get("chatgpt_subscription_active_until"),
            id_auth.get("chatgpt_subscription_active_until"),
            getattr(account, "subscription_expires_at", None),
            getattr(account, "pro_expires_at", None),
            account_extra.get("subscription_expires_at"),
            account_extra.get("pro_expires_at"),
        )
    )

    credentials = {
        "access_token": access_token,
        "chatgpt_account_id": chatgpt_account_id,
        "chatgpt_user_id": chatgpt_user_id,
        "client_id": client_id,
        "email": email,
        "expires_at": expires_at,
        "id_token": id_token,
        "organization_id": organization_id,
        "plan_type": plan_type,
        "refresh_token": refresh_token,
    }
    if subscription_expires_at:
        credentials["subscription_expires_at"] = subscription_expires_at

    payload = {
        "name": email,
        "notes": email,
        "platform": "openai",
        "type": "oauth",
        "credentials": credentials,
        "extra": {
            "email": email,
            "openai_long_context_billing_enabled": False,
            "openai_oauth_responses_websockets_v2_enabled": False,
            "openai_oauth_responses_websockets_v2_mode": "off",
            "privacy_mode": "training_off",
        },
        "concurrency": 30,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    }
    # group_ids 仅在上传场景需要;下载文件参考格式中不含。
    # 仅当显式传入非空 list/tuple/str 时才纳入,None 不写默认值。
    if group_ids is not None:
        parsed_group_ids = _parse_group_ids(group_ids)
        if parsed_group_ids:
            payload["group_ids"] = parsed_group_ids
    return payload


def build_sub2api_account_payload_from_token_data(
    token_data: dict[str, Any],
    *,
    account: Any = None,
    group_ids: list[int] | None = None,
    sequence_index: int | None = None,
) -> dict[str, Any]:
    return _build_sub2api_account_payload_from_token_data(
        token_data,
        account=account,
        group_ids=group_ids,
        sequence_index=sequence_index,
    )


def _build_sub2api_account_payload(account, group_ids: list[int] | None = None) -> dict[str, Any]:
    token_data = generate_token_json(account)
    return _build_sub2api_account_payload_from_token_data(
        token_data,
        account=account,
        group_ids=group_ids,
    )


def _get_account_extra(account: Any) -> dict[str, Any]:
    if hasattr(account, "get_extra"):
        try:
            extra = account.get_extra()
            if isinstance(extra, dict):
                return dict(extra)
        except Exception:
            pass
    try:
        extra = getattr(account, "extra", {})
    except Exception:
        extra = {}
    if isinstance(extra, dict):
        return dict(extra)
    extra_json = str(getattr(account, "extra_json", "") or "").strip()
    if extra_json:
        try:
            parsed = json.loads(extra_json)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


def resolve_sub2api_proxy_url(
    token_data: dict[str, Any],
    *,
    account: Any = None,
    proxy_url: str | None = None,
) -> str:
    """解析导出文件应绑定的代理，不分配新代理、也不回退全局代理。

    ``proxy_url`` 显式传空字符串表示强制不写代理；传 ``None`` 才会从目标
    token/account 的现有字段中查找。这样导出不会产生隐式数据库写入。
    """
    if proxy_url is not None:
        return str(proxy_url or "").strip()

    extra = _get_account_extra(account)
    candidates = (
        token_data.get("sub2api_proxy_url"),
        token_data.get("proxy_url"),
        token_data.get("register_proxy"),
        token_data.get("proxy"),
        extra.get("sub2api_proxy_url"),
        extra.get("proxy_url"),
        extra.get("register_proxy"),
        extra.get("proxy"),
        getattr(account, "proxy_url", "") if account is not None else "",
        getattr(account, "proxy", "") if account is not None else "",
    )
    return str(_first_non_empty(*candidates) or "").strip()


def _resolve_sub2api_remote_proxy_id(
    token_data: dict[str, Any],
    *,
    account: Any = None,
) -> int | None:
    """Read only an explicitly persisted Sub2API remote proxy id.

    Local CPA/Roxy proxy ids live in different databases and must never be
    reused here. No lookup or guess is made from host/port.
    """
    extra = _get_account_extra(account)
    raw = _first_non_empty(
        token_data.get("sub2api_proxy_id"),
        extra.get("sub2api_proxy_id"),
        getattr(account, "sub2api_proxy_id", None) if account is not None else None,
    )
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("Sub2API 远端 proxy_id 必须是正整数")
    try:
        proxy_id = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValueError("Sub2API 远端 proxy_id 必须是正整数") from None
    if proxy_id <= 0:
        raise ValueError("Sub2API 远端 proxy_id 必须是正整数")
    return proxy_id


def _attach_sub2api_account_context(
    sync_account: Any,
    *,
    source_account: Any,
    extra: dict[str, Any],
) -> Any:
    """Keep persisted Sub2API/proxy metadata on the lightweight sync object.

    ``build_chatgpt_sync_account`` intentionally copies only OAuth fields for
    the generic CPA flow.  Direct Sub2API create additionally needs to know
    whether the source account already has a proxy and, if so, whether an exact
    Sub2API remote ``proxy_id`` was persisted.  Dropping ``extra`` here could
    incorrectly report an unbound account as fully synced.
    """
    if sync_account is source_account:
        return sync_account
    try:
        setattr(sync_account, "extra", dict(extra))
    except Exception:
        # Fall back to the original account instead of losing proxy metadata.
        return source_account
    return sync_account


def _build_sub2api_proxy_payload(proxy_url: str, *, name: str = "") -> dict[str, Any] | None:
    """把现有代理 URL 转成 Sub2API data export 的 proxy 项。"""
    raw = str(proxy_url or "").strip()
    if not raw:
        return None
    try:
        from core.proxy_utils import coerce_proxy_url

        # 显式 URL 直接解析，保留调用者选择的 socks5 / socks5h 语义。
        normalized = raw if "://" in raw else str(
            coerce_proxy_url(raw, default_scheme="socks5") or ""
        ).strip()
        parts = urlsplit(normalized)
        protocol = str(parts.scheme or "").lower()
        if protocol not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError("unsupported protocol")
        host = str(parts.hostname or "").strip()
        port = int(parts.port or 0)
        if not host or not (1 <= port <= 65535):
            raise ValueError("invalid host or port")
        username = unquote(parts.username or "")
        password = unquote(parts.password or "")
    except Exception:
        # 代理可能包含密码，不能把原始 URL 写进异常或日志。
        raise ValueError("Sub2API 代理地址无法解析") from None

    proxy_key = f"{protocol}|{host}|{port}|{username}|{password}"
    return {
        "proxy_key": proxy_key,
        "name": str(name or f"{protocol}://{host}:{port}"),
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "status": "active",
        "fallback_mode": "none",
    }


def build_sub2api_bundle_from_token_data(
    token_data: dict[str, Any],
    *,
    account: Any = None,
    proxy_url: str | None = None,
    exported_at: Any = None,
) -> dict[str, Any]:
    """生成 Sub2API ``AdminDataPayload`` 单账号备份包。

    该格式与 ``POST /admin/accounts`` 的 direct create 请求体不同：这里只用
    ``proxy_key`` 关联同一个文件中的 proxy 项，不写 ``group_ids``/``proxy_id``。
    调用 ``POST /api/v1/admin/accounts/data`` 时仍须包装为
    ``{"data": bundle, "skip_default_group_bind": ...}``，不能直接把本函数返回值
    当作 HTTP 请求体。
    """
    account_payload = _build_sub2api_account_payload_from_token_data(
        token_data,
        account=account,
        group_ids=None,
    )
    credentials = account_payload.get("credentials") or {}
    if not str(credentials.get("id_token") or "").strip():
        raise ValueError("生成完整 Sub2API 导入包需要目标账号自己的 id_token")
    if not _decode_jwt_payload(str(credentials.get("access_token") or "")):
        raise ValueError("目标账号的 access_token 不是可解析的 JWT")
    if not _decode_jwt_payload(str(credentials.get("id_token") or "")):
        raise ValueError("目标账号的 id_token 不是可解析的 JWT")
    identity_missing = [
        key
        for key in ("chatgpt_account_id", "chatgpt_user_id")
        if not str(credentials.get(key) or "").strip()
    ]
    if identity_missing:
        raise ValueError(
            "目标账号 OAuth 凭证缺少身份字段: " + ", ".join(identity_missing)
        )
    resolved_proxy = resolve_sub2api_proxy_url(
        token_data,
        account=account,
        proxy_url=proxy_url,
    )
    proxy_payload = _build_sub2api_proxy_payload(
        resolved_proxy,
        name=f"{account_payload.get('credentials', {}).get('email') or 'OpenAI'} proxy",
    )
    proxies: list[dict[str, Any]] = []
    if proxy_payload:
        proxies.append(proxy_payload)
        account_payload["proxy_key"] = proxy_payload["proxy_key"]

    exported_at_text = _format_utc_timestamp(exported_at)
    if not exported_at_text:
        exported_at_text = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "exported_at": exported_at_text,
        "proxies": proxies,
        "accounts": [account_payload],
    }


def merge_sub2api_bundles(
    bundles: list[dict[str, Any]],
    *,
    exported_at: Any = None,
) -> dict[str, Any]:
    """合并单账号 Sub2API 包，并按 proxy_key 去重代理。"""
    proxies_by_key: dict[str, dict[str, Any]] = {}
    accounts_by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}
    for bundle in bundles:
        if not isinstance(bundle, dict):
            raise ValueError("Sub2API 合并输入必须是 AdminDataPayload")
        if not is_current_sub2api_bundle(bundle):
            raise ValueError("Sub2API 合并输入不是当前安全导出格式")
        for proxy in bundle.get("proxies") or []:
            if not isinstance(proxy, dict):
                continue
            key = str(proxy.get("proxy_key") or "")
            if key and key not in proxies_by_key:
                proxies_by_key[key] = dict(proxy)
        for account_payload in bundle.get("accounts") or []:
            if isinstance(account_payload, dict):
                credentials = account_payload.get("credentials") or {}
                identity = (
                    str(credentials.get("chatgpt_account_id") or ""),
                    str(credentials.get("chatgpt_user_id") or ""),
                    str(credentials.get("email") or "").strip().casefold(),
                )
                existing = accounts_by_identity.get(identity)
                if existing is not None and existing != account_payload:
                    raise ValueError("Sub2API 合并发现同一账号的凭证或代理不一致")
                accounts_by_identity.setdefault(identity, dict(account_payload))

    exported_at_text = _format_utc_timestamp(exported_at)
    if not exported_at_text:
        exported_at_text = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "exported_at": exported_at_text,
        "proxies": list(proxies_by_key.values()),
        "accounts": list(accounts_by_identity.values()),
    }


def is_current_sub2api_bundle(value: Any) -> bool:
    """判断缓存文件是否为当前安全导出格式，旧模板会被重新生成。"""
    if not isinstance(value, dict):
        return False
    proxies = value.get("proxies")
    accounts = value.get("accounts")
    if not isinstance(proxies, list) or not isinstance(accounts, list) or not accounts:
        return False

    proxy_keys: set[str] = set()
    for proxy in proxies:
        if not isinstance(proxy, dict):
            return False
        try:
            protocol = str(proxy.get("protocol") or "").strip().lower()
            host = str(proxy.get("host") or "").strip()
            port = int(proxy.get("port") or 0)
            username = str(proxy.get("username") or "")
            password = str(proxy.get("password") or "")
        except (TypeError, ValueError):
            return False
        expected = f"{protocol}|{host}|{port}|{username}|{password}"
        if not host or protocol not in {"http", "https", "socks5", "socks5h"}:
            return False
        if str(proxy.get("proxy_key") or "") != expected:
            return False
        proxy_keys.add(expected)

    referenced_proxy_keys: set[str] = set()
    for account_payload in accounts:
        if not isinstance(account_payload, dict):
            return False
        if "group_ids" in account_payload or "proxy_id" in account_payload:
            # 这两个字段只属于 POST /admin/accounts direct create，不属于
            # AdminDataAccount；旧缓存若混入它们必须重新生成。
            return False
        credentials = account_payload.get("credentials")
        extra = account_payload.get("extra")
        if not isinstance(credentials, dict) or not isinstance(extra, dict):
            return False
        email = str(credentials.get("email") or "").strip()
        if not email or any(
            str(value or "").strip() != email
            for value in (
                account_payload.get("name"),
                account_payload.get("notes"),
                extra.get("email"),
            )
        ):
            return False
        if account_payload.get("concurrency") != 30:
            return False
        if "model_mapping" in credentials:
            return False
        if any(
            key == "model_rate_limits" or key.startswith("codex_")
            for key in extra
        ):
            return False
        if not all(
            str(credentials.get(key) or "").strip()
            for key in (
                "access_token",
                "refresh_token",
                "id_token",
                "chatgpt_account_id",
                "chatgpt_user_id",
            )
        ):
            return False
        account_proxy_key = str(account_payload.get("proxy_key") or "")
        if account_proxy_key:
            if account_proxy_key not in proxy_keys:
                return False
            referenced_proxy_keys.add(account_proxy_key)
    return referenced_proxy_keys == proxy_keys


def upload_chatgpt_account_to_sub2api_result(
    account: Any,
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
) -> Sub2ApiUploadResult:
    """上传 ChatGPT 账号到 Sub2API，兼容 AccountModel.extra_json 和 OAuth 文件。"""
    try:
        extra = _get_account_extra(account)
        oauth_file = str(extra.get("oauth_file") or "").strip()

        if oauth_file and os.path.isfile(oauth_file):
            with open(oauth_file, "r", encoding="utf-8") as fh:
                token_data = json.load(fh)
            if not isinstance(token_data, dict):
                return Sub2ApiUploadResult(False, "OAuth 文件格式错误")

            try:
                from services.chatgpt_sync import build_chatgpt_sync_account

                sync_account = build_chatgpt_sync_account(account)
            except Exception:
                sync_account = account
            sync_account = _attach_sub2api_account_context(
                sync_account,
                source_account=account,
                extra=extra,
            )
            if getattr(sync_account, "client_id", "") and "client_id" not in token_data:
                token_data["client_id"] = getattr(sync_account, "client_id", "")
            payload_account = sync_account
            return upload_token_data_to_sub2api_result(
                token_data,
                api_url=api_url,
                api_key=api_key,
                group_ids=group_ids,
                account=payload_account,
            )

        try:
            from services.chatgpt_sync import build_chatgpt_sync_account

            sync_account = build_chatgpt_sync_account(account)
        except Exception:
            sync_account = account
        sync_account = _attach_sub2api_account_context(
            sync_account,
            source_account=account,
            extra=extra,
        )

        if not str(getattr(sync_account, "access_token", "") or "").strip():
            return Sub2ApiUploadResult(False, "账号缺少 access_token")
        if not str(getattr(sync_account, "refresh_token", "") or "").strip():
            return Sub2ApiUploadResult(
                False,
                "账号缺少 refresh_token，请先点「补 RT」拿到 RT 后再上传",
            )
        return upload_to_sub2api_result(
            sync_account,
            api_url=api_url,
            api_key=api_key,
            group_ids=group_ids,
        )
    except Exception as exc:
        # 文件解析器/HTTP 客户端异常可能把凭证内容带进异常文本，只记录类型。
        logger.error("Sub2API 同步异常: type=%s", type(exc).__name__)
        return Sub2ApiUploadResult(
            False,
            "上传异常，请检查账号凭证与 Sub2API 配置",
        )


def upload_chatgpt_account_to_sub2api(
    account: Any,
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
) -> Tuple[bool, str]:
    return upload_chatgpt_account_to_sub2api_result(
        account,
        api_url=api_url,
        api_key=api_key,
        group_ids=group_ids,
    ).as_tuple()


def upload_token_data_to_sub2api_result(
    token_data: dict[str, Any],
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
    account: Any = None,
) -> Sub2ApiUploadResult:
    api_url = str(api_url or _get_config_value("sub2api_api_url")).strip()
    api_key = str(api_key or _get_config_value("sub2api_api_key")).strip()
    resolved_group_ids = _parse_group_ids(
        _get_config_value("sub2api_group_ids") if group_ids is None else group_ids
    )

    if not api_url:
        return Sub2ApiUploadResult(False, "Sub2API API URL 未配置")
    if not api_key:
        return Sub2ApiUploadResult(False, "Sub2API API Key 未配置")
    if not str(token_data.get("access_token") or "").strip():
        return Sub2ApiUploadResult(False, "账号缺少 access_token")
    if not str(token_data.get("refresh_token") or "").strip():
        return Sub2ApiUploadResult(
            False,
            "账号缺少 refresh_token，请先点「补 RT」拿到 RT 后再上传",
        )

    try:
        payload = _build_sub2api_account_payload_from_token_data(
            token_data,
            account=account,
            group_ids=resolved_group_ids,
        )
        proxy_url = resolve_sub2api_proxy_url(token_data, account=account)
        remote_proxy_id = _resolve_sub2api_remote_proxy_id(
            token_data,
            account=account,
        )
    except ValueError as exc:
        return Sub2ApiUploadResult(False, str(exc))

    if proxy_url and remote_proxy_id is None:
        # POST /admin/accounts accepts only a remote proxy_id. A local proxy URL,
        # CPA id, or Roxy id cannot be mapped safely without querying/creating
        # remote proxy state, so stop before creating a partially synced account.
        return Sub2ApiUploadResult(
            False,
            "未上传：账号配置了代理，但缺少明确的 Sub2API 远端 proxy_id 映射",
            proxy_sync_status="blocked_missing_proxy_id",
        )
    proxy_sync_status = "not_configured"
    if remote_proxy_id is not None:
        payload["proxy_id"] = remote_proxy_id
        proxy_sync_status = "mapped"
    return _post_sub2api_payload_result(
        payload,
        api_url=api_url,
        api_key=api_key,
        proxy_sync_status=proxy_sync_status,
    )


def upload_token_data_to_sub2api(
    token_data: dict[str, Any],
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
    account: Any = None,
) -> Tuple[bool, str]:
    return upload_token_data_to_sub2api_result(
        token_data,
        api_url=api_url,
        api_key=api_key,
        group_ids=group_ids,
        account=account,
    ).as_tuple()


def _extract_created_remote_account_id(payload: Any) -> str:
    """Extract one validated id from a successful create response only."""
    current = payload
    for _ in range(5):
        if isinstance(current, (str, int)) and not isinstance(current, bool):
            candidate = str(current).strip()
            if (
                1 <= len(candidate) <= 128
                and all(char.isalnum() or char in "-_" for char in candidate)
                and (not candidate.isdigit() or int(candidate) > 0)
            ):
                return candidate
            return ""
        if not isinstance(current, dict):
            return ""
        direct = current.get("id") or current.get("account_id")
        if direct is not None:
            current = direct
            continue
        nested = _first_non_empty(
            current.get("data"),
            current.get("result"),
            current.get("account"),
            current.get("item"),
        )
        if nested is None:
            return ""
        current = nested
    return ""


def _is_failed_create_envelope(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("success") is False or payload.get("ok") is False:
        return True
    code = payload.get("code")
    if code is None:
        return False
    return str(code).strip().lower() not in {
        "",
        "0",
        "200",
        "201",
        "ok",
        "success",
    }


def _post_sub2api_payload_result(
    payload: dict[str, Any],
    *,
    api_url: str,
    api_key: str,
    proxy_sync_status: str = "not_configured",
) -> Sub2ApiUploadResult:
    url = f"{api_url.rstrip('/')}/api/v1/admin/accounts"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{api_url.rstrip('/')}/admin/accounts",
        "x-api-key": api_key,
    }

    try:
        response = cffi_requests.post(
            url,
            headers=headers,
            json=payload,
            proxies=None,
            verify=True,
            timeout=30,
            impersonate="chrome110",
        )

        status_code = int(response.status_code or 0)
        if status_code in (200, 201):
            response_payload: Any = None
            try:
                response_payload = response.json()
            except Exception:
                pass
            if _is_failed_create_envelope(response_payload):
                return Sub2ApiUploadResult(
                    False,
                    f"上传失败: HTTP {status_code}",
                    status_code=status_code,
                    proxy_sync_status=proxy_sync_status,
                )
            return Sub2ApiUploadResult(
                True,
                "上传成功",
                status_code=status_code,
                remote_account_id=_extract_created_remote_account_id(response_payload),
                proxy_sync_status=proxy_sync_status,
            )

        # Sub2API 的错误 body/message 可能回显刚提交的 OAuth 凭证；调用者只拿
        # 状态码，不透传或解析任何远端文本。
        return Sub2ApiUploadResult(
            False,
            f"上传失败: HTTP {status_code}",
            status_code=status_code,
            proxy_sync_status=proxy_sync_status,
        )
    except Exception as exc:
        logger.error("Sub2API 上传异常: type=%s", type(exc).__name__)
        return Sub2ApiUploadResult(
            False,
            "上传异常，请检查 Sub2API 地址、TLS 证书与网络",
            proxy_sync_status=proxy_sync_status,
        )


def _post_sub2api_payload(
    payload: dict[str, Any],
    *,
    api_url: str,
    api_key: str,
) -> Tuple[bool, str]:
    return _post_sub2api_payload_result(
        payload,
        api_url=api_url,
        api_key=api_key,
    ).as_tuple()


def upload_to_sub2api_result(
    account,
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
) -> Sub2ApiUploadResult:
    """上传单个账号到 Sub2API 管理后台。
    要求账号必须包含 refresh_token；AT-only 账号 10 天后即失效,拒绝上传。"""
    api_url = str(api_url or _get_config_value("sub2api_api_url")).strip()
    api_key = str(api_key or _get_config_value("sub2api_api_key")).strip()
    resolved_group_ids = _parse_group_ids(
        _get_config_value("sub2api_group_ids") if group_ids is None else group_ids
    )

    if not api_url:
        return Sub2ApiUploadResult(False, "Sub2API API URL 未配置")
    if not api_key:
        return Sub2ApiUploadResult(False, "Sub2API API Key 未配置")
    if not str(getattr(account, "access_token", "") or "").strip():
        return Sub2ApiUploadResult(False, "账号缺少 access_token")
    if not str(getattr(account, "refresh_token", "") or "").strip():
        return Sub2ApiUploadResult(
            False,
            "账号缺少 refresh_token，请先点「补 RT」拿到 RT 后再上传",
        )

    try:
        payload = _build_sub2api_account_payload(account, group_ids=resolved_group_ids)
        token_data = generate_token_json(account)
        proxy_url = resolve_sub2api_proxy_url(token_data, account=account)
        remote_proxy_id = _resolve_sub2api_remote_proxy_id(
            token_data,
            account=account,
        )
    except ValueError as exc:
        return Sub2ApiUploadResult(False, str(exc))

    if proxy_url and remote_proxy_id is None:
        return Sub2ApiUploadResult(
            False,
            "未上传：账号配置了代理，但缺少明确的 Sub2API 远端 proxy_id 映射",
            proxy_sync_status="blocked_missing_proxy_id",
        )
    proxy_sync_status = "not_configured"
    if remote_proxy_id is not None:
        payload["proxy_id"] = remote_proxy_id
        proxy_sync_status = "mapped"
    return _post_sub2api_payload_result(
        payload,
        api_url=api_url,
        api_key=api_key,
        proxy_sync_status=proxy_sync_status,
    )


def upload_to_sub2api(
    account,
    api_url: str | None = None,
    api_key: str | None = None,
    group_ids: list[int] | None = None,
) -> Tuple[bool, str]:
    return upload_to_sub2api_result(
        account,
        api_url=api_url,
        api_key=api_key,
        group_ids=group_ids,
    ).as_tuple()
