"""ChatGPT / Codex CLI 平台插件"""

import json
import re
import secrets
import hashlib
import inspect
import socket
import string
import threading
import time

from core.base_mailbox import BaseMailbox
from core.base_platform import Account, AccountStatus, BasePlatform, RegisterConfig
from core.registry import register
from platforms.chatgpt.chatgpt_registration_mode_adapter import (
    ChatGPTRegistrationContext,
    build_chatgpt_registration_mode_adapter,
)
from platforms.chatgpt.utils import generate_random_password


_SEAT_SWITCH_LOCK = threading.Lock()
_SEAT_SWITCH_LAST_TS: float = 0.0
_SEAT_SWITCH_DEFAULT_INTERVAL_MS = 500
_BUSINESS_EMAIL_PREFIX_KEY = "business_email_machine_prefix"
_BUSINESS_EMAIL_RANDOM_ALPHABET = string.ascii_lowercase + string.digits

_OUTLOOK_MAIL_PASSWORD_KEY = "outlook_mail_password"
_OUTLOOK_MAIL_CLIENT_ID_KEY = "outlook_mail_client_id"
_OUTLOOK_MAIL_REFRESH_TOKEN_KEY = "outlook_mail_refresh_token"
_OUTLOOK_MAIL_ACCESS_TYPE_KEY = "outlook_mail_access_type"


def _oauth_mail_provider(email: str, extra: dict | None) -> str:
    """Resolve mailbox ownership before considering a CF Worker fallback."""
    source = dict(extra or {})
    provider = str(
        source.get("_oauth_mail_provider")
        or source.get("mail_provider")
        or source.get("provider")
        or ""
    ).strip().lower()
    if provider in {"auto", "none"}:
        provider = ""
    if provider:
        return provider
    register_mode = str(source.get("register_mode") or "").lower()
    if "outlook" in register_mode or any(source.get(key) for key in (
        _OUTLOOK_MAIL_PASSWORD_KEY, _OUTLOOK_MAIL_CLIENT_ID_KEY, _OUTLOOK_MAIL_REFRESH_TOKEN_KEY,
    )):
        return "outlook"
    domain = str(email or "").rsplit("@", 1)[-1].strip().lower()
    if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
        return "outlook"
    if domain in {"icloud.com", "me.com", "mac.com"}:
        return "icloud"
    if domain in {"qq.com", "foxmail.com"}:
        return "qqmail"
    if domain == "gmail.com":
        return "gmail"
    if "cfworker" in register_mode or str(source.get("account_type") or "").upper() == "BUSINESS":
        return "cfworker"
    return ""


def _outlook_mail_credentials(
    extra: dict | None,
    *,
    allow_legacy_generic: bool = False,
) -> dict[str, str]:
    """Read namespaced Outlook mailbox credentials with a legacy fallback.

    Historically ``client_id``/``refresh_token`` represented Microsoft mail
    OAuth.  ChatGPT OAuth later reused the same keys and overwrote the mailbox
    refresh token.  New records use an explicit Outlook-mail namespace.
    Unqualified fields are accepted only for a live Outlook mailbox object or
    when the refresh token has a recognisable Microsoft shape.  Persisted
    ChatGPT accounts otherwise fail closed so their OpenAI RT cannot be sent to
    Microsoft.
    """
    source = dict(extra or {})
    password = str(
        source.get(_OUTLOOK_MAIL_PASSWORD_KEY)
        or source.get("outlook_password")
        or source.get("password")
        or ""
    ).strip()
    client_id = str(
        source.get(_OUTLOOK_MAIL_CLIENT_ID_KEY)
        or source.get("outlook_client_id")
        or ""
    ).strip()
    refresh_token = str(
        source.get(_OUTLOOK_MAIL_REFRESH_TOKEN_KEY)
        or source.get("outlook_refresh_token")
        or ""
    ).strip()
    mail_access_type = str(
        source.get(_OUTLOOK_MAIL_ACCESS_TYPE_KEY)
        or source.get("mail_access_type")
        or ""
    ).strip()

    legacy_refresh_token = str(source.get("refresh_token") or "").strip()
    legacy_looks_microsoft = legacy_refresh_token.startswith(("M.", "0."))
    explicit_outlook_refresh = bool(refresh_token)
    if not refresh_token and (
        allow_legacy_generic or legacy_looks_microsoft
    ):
        refresh_token = legacy_refresh_token
    if not client_id and refresh_token and (
        allow_legacy_generic
        or explicit_outlook_refresh
        or legacy_looks_microsoft
    ):
        client_id = str(source.get("client_id") or "").strip()
    return {
        "password": password,
        "client_id": client_id,
        "refresh_token": refresh_token,
        "mail_access_type": mail_access_type,
    }


def _chatgpt_oauth_credentials(extra: dict | None) -> dict[str, str]:
    """Return only credentials safe to send to OpenAI's OAuth endpoint.

    ``client_id`` and ``refresh_token`` were historically also used for
    Outlook mail OAuth.  Explicit ChatGPT ownership markers (or the standard
    ``rt_`` token shape) are therefore required for an unqualified RT, and a
    Microsoft-shaped token is always rejected.  Ambiguous/non-OpenAI client
    IDs fall back to the built-in OpenAI OAuth client.
    """
    from platforms.chatgpt.constants import OAUTH_CLIENT_ID

    source = dict(extra or {})

    def value(*keys: str) -> str:
        for key in keys:
            candidate = str(source.get(key) or "").strip()
            if candidate:
                return candidate
        return ""

    explicit_refresh = value("chatgpt_refresh_token", "openai_refresh_token")
    generic_refresh = value("refresh_token")
    candidate_refresh = explicit_refresh or generic_refresh
    microsoft_refresh = candidate_refresh.startswith(("M.", "0."))
    flag = str(source.get("chatgpt_has_refresh_token_solution") or "").strip().lower()
    registration_mode = str(
        source.get("chatgpt_registration_mode") or ""
    ).strip().lower()
    token_source = str(source.get("chatgpt_token_source") or "").strip().lower()
    register_mode = str(source.get("register_mode") or "").strip().lower()
    chatgpt_owned = bool(
        explicit_refresh
        or generic_refresh.startswith("rt_")
        or flag in {"1", "true", "yes", "on"}
        or registration_mode in {"rt", "refresh_token", "oauth"}
        or token_source in {"oauth", "register", "refresh", "login"}
        or register_mode.startswith("oauth_")
    )
    refresh_token = (
        candidate_refresh
        if candidate_refresh and chatgpt_owned and not microsoft_refresh
        else ""
    )

    candidate_client_id = value(
        "chatgpt_oauth_client_id",
        "openai_client_id",
        "client_id",
    )
    client_id = (
        candidate_client_id
        if candidate_client_id.startswith("app_")
        else OAUTH_CLIENT_ID
    )
    return {
        "refresh_token": refresh_token,
        "client_id": client_id,
    }


def _mailbox_extra_for_account(
    provider: str,
    mailbox_extra: dict | None,
) -> dict:
    """Return persistence-safe mailbox metadata for a ChatGPT account."""
    source = dict(mailbox_extra or {})
    if str(provider or source.get("provider") or "").strip().lower() == "gmail":
        return {key: source[key] for key in ("gmail_source_id", "gmail_alias_id") if key in source}
    if str(provider or source.get("provider") or "").strip().lower() != "outlook":
        return source

    credentials = _outlook_mail_credentials(
        source,
        allow_legacy_generic=True,
    )
    # Never let unqualified mailbox credentials overwrite ChatGPT OAuth fields.
    for key in (
        "password",
        "client_id",
        "refresh_token",
        "mail_access_type",
        "outlook_password",
        "outlook_client_id",
        "outlook_refresh_token",
        _OUTLOOK_MAIL_PASSWORD_KEY,
        _OUTLOOK_MAIL_CLIENT_ID_KEY,
        _OUTLOOK_MAIL_REFRESH_TOKEN_KEY,
        _OUTLOOK_MAIL_ACCESS_TYPE_KEY,
    ):
        source.pop(key, None)
    if credentials["password"]:
        source[_OUTLOOK_MAIL_PASSWORD_KEY] = credentials["password"]
    if credentials["client_id"]:
        source[_OUTLOOK_MAIL_CLIENT_ID_KEY] = credentials["client_id"]
    if credentials["refresh_token"]:
        source[_OUTLOOK_MAIL_REFRESH_TOKEN_KEY] = credentials["refresh_token"]
    if credentials["mail_access_type"]:
        source[_OUTLOOK_MAIL_ACCESS_TYPE_KEY] = credentials["mail_access_type"]
    source.setdefault("provider", "outlook")
    return source


def _sanitize_business_email_machine_prefix(value) -> str:
    """只保留邮箱 local-part 安全字符,用于区分多机注册实例。"""
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "", text)[:10]


def _default_business_email_machine_prefix() -> str:
    try:
        seed = socket.gethostname() or ""
    except Exception:
        seed = ""
    if not seed:
        seed = "local"
    digest = hashlib.sha1(
        seed.encode("utf-8", errors="ignore"), usedforsecurity=False
    ).hexdigest()[:6]
    return f"m{digest}"


def _business_email_machine_prefix(extra_config: dict | None = None) -> str:
    extra_config = extra_config or {}
    for key in (
        _BUSINESS_EMAIL_PREFIX_KEY,
        "business_rt_email_machine_prefix",
        "business_email_prefix",
    ):
        prefix = _sanitize_business_email_machine_prefix(extra_config.get(key))
        if prefix:
            return prefix
    try:
        from core.config_store import config_store

        for key in (
            _BUSINESS_EMAIL_PREFIX_KEY,
            "business_rt_email_machine_prefix",
            "business_email_prefix",
        ):
            prefix = _sanitize_business_email_machine_prefix(config_store.get(key, ""))
            if prefix:
                return prefix
    except Exception:
        pass
    return _default_business_email_machine_prefix()


def _generate_business_email_local_part(extra_config: dict | None = None, *, random_len: int = 16) -> str:
    prefix = _business_email_machine_prefix(extra_config)
    suffix = "".join(secrets.choice(_BUSINESS_EMAIL_RANDOM_ALPHABET) for _ in range(max(random_len, 12)))
    return f"{prefix}{suffix}"


def _read_switch_codex_flag(extra_config: dict) -> bool:
    """读 extra_config.business_switch_to_codex,默认 False(不勾选)。

    只有 "1" / "true" / "yes" / "on" / True 视为开启。
    """
    raw = (extra_config or {}).get("business_switch_to_codex", "")
    if raw is None or raw == "":
        return False
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _read_business_register_only_flag(extra_config: dict) -> bool:
    """BUSINESS 长跑拆分模式:注册阶段只落 pending_rt,由 RT 获取长跑消费。"""
    raw = (extra_config or {}).get("business_rt_register_only", "")
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _switch_codex_pref_value(extra_config: dict) -> str:
    return "1" if _read_switch_codex_flag(extra_config) else "0"


def _brief_error(exc_or_msg, limit: int = 180) -> str:
    text = str(exc_or_msg or "").strip().replace("\r", " ").replace("\n", " ")
    return text[:limit] or "未知错误"


def _redact_proxy_for_log(proxy) -> str:
    try:
        from core.proxy_utils import redact_proxy_url

        return redact_proxy_url(proxy)
    except Exception:
        return str(proxy or "").strip() or "直连"


def _proxy_compare_key(proxy) -> str:
    try:
        from core.proxy_utils import normalize_proxy_url

        normalized = normalize_proxy_url(proxy)
    except Exception:
        normalized = str(proxy or "").strip() or None
    return str(normalized or "").strip().rstrip("/").lower()


def _split_proxy_values(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        values = re.split(r"[\s,]+", str(raw or "").strip())
    result: list[str] = []
    for item in values:
        if isinstance(item, dict):
            value = item.get("addr") or item.get("url") or item.get("proxy") or ""
        else:
            value = item
        text = str(value or "").strip()
        if text:
            result.append(text)
    return result


def _is_rt_proxy_retryable_error(exc_or_msg) -> bool:
    text = str(exc_or_msg or "")
    low = text.lower()
    non_retryable_markers = (
        "cf worker api url 未配置",
        "cfworker api url 未配置",
        "未配置 cfworker",
        "密码为空",
        "password is required",
        "账号不存在",
        # 账号已死,换代理重试也救不回来,直接 raise 让上层删账号
        "account_deactivated",
        "account_deleted",
        "deleted or deactivated",
        "account has been deleted or deactivated",
        "you do not have an account because it has been deleted or deactivated",
        "账号已被停用",
        "账户已停用",
        "账号已停用",
    )
    if any(marker in low for marker in non_retryable_markers):
        return False
    retryable_markers = (
        "login_session",
        "登录会话未拿到",
        "http 403",
        " http 409",
        "http 409",
        " http 429",
        "http 429",
        "403",
        "409",
        "429",
        "session is no longer valid",
        "invalid_request_error",
        "just a moment",
        "challenge-platform",
        "cloudflare",
        "sentinel",
        "workspace/select",
        "authorize_continue",
        "csrf",
        "timeout",
        "timed out",
        "connection",
        "network",
        "tls",
        "ssl",
        "curl",
        "proxy",
    )
    return any(marker in low for marker in retryable_markers)


def _maybe_generate_payment_link(
    account_extra: dict,
    extra_config: dict,
    proxy,
    log_fn,
) -> None:
    """注册完成后,按表单开关 auto_payment_link 自动生成 Plus/Team 支付链接。

    输入:
      account_extra        : 当前正在构造的账号 extra 字典 (会被原地写入)
      extra_config         : 任务级 extra 配置,含 UI 表单字段
      proxy                : 当前任务代理 (传给 generate_*)
      log_fn               : 日志函数

    读取 extra_config:
      auto_payment_link        bool  开关(默认 false)
      payment_plan             str   plus / team
      payment_country          str   SG/US/TR/JP/HK/GB/EU/AU/CA/IN/BR/MX
      payment_workspace_name   str   Team 模式专用,默认 MyTeam
      payment_seat_quantity    int   Team 模式专用,默认 2
      payment_price_interval   str   Team 模式专用,默认 month

    成功 → account_extra["cashier_url"] = url
                       ["payment_plan"] = plan
                       ["payment_country"] = country
    失败 → account_extra["payment_error"] = str(exc) (不抛异常,不影响注册)
    """
    flag = str(extra_config.get("auto_payment_link", "")).strip().lower()
    if flag not in {"1", "true", "yes", "on"}:
        return
    plan = str(extra_config.get("payment_plan", "plus")).strip().lower()
    if plan not in {"plus", "team"}:
        log_fn(f"[支付链接] payment_plan={plan!r} 不支持,跳过")
        return
    country = str(extra_config.get("payment_country", "SG")).strip().upper() or "SG"
    access_token = (account_extra.get("access_token") or "").strip()
    if not access_token:
        log_fn("[支付链接] 注册流程未拿到 access_token (可能是 token_only / 协议失败),跳过")
        account_extra["payment_error"] = "no access_token"
        return

    # 构 SimpleNamespace 当 account 喂给 generate_*
    from types import SimpleNamespace
    pseudo = SimpleNamespace(
        access_token=access_token,
        cookies=account_extra.get("cookies", "") or "",
    )
    try:
        from platforms.chatgpt.payment import generate_plus_link, generate_team_link
        if plan == "plus":
            url = generate_plus_link(pseudo, proxy=proxy, country=country)
        else:
            workspace = str(extra_config.get("payment_workspace_name") or "MyTeam").strip() or "MyTeam"
            try:
                seats = int(extra_config.get("payment_seat_quantity") or 2)
            except (TypeError, ValueError):
                seats = 2
            seats = max(2, min(seats, 50))
            interval = str(extra_config.get("payment_price_interval") or "month").strip() or "month"
            url = generate_team_link(
                pseudo,
                workspace_name=workspace,
                price_interval=interval,
                seat_quantity=seats,
                proxy=proxy,
                country=country,
            )
        account_extra["cashier_url"] = url
        account_extra["payment_plan"] = plan
        account_extra["payment_country"] = country
        log_fn(f"[支付链接] ✅ {plan.upper()} ({country}): {url[:80]}...")
    except Exception as exc:
        account_extra["payment_error"] = str(exc)[:500]
        log_fn(f"[支付链接] ⚠️ 生成失败: {exc}")


def _resolve_business_user_id_by_email(
    account_id: str, email: str, log_fn, proxy: str = "",
) -> str:
    """用母号 cookies 查 /accounts/{aid}/users?query=email, 找到子号激活后的 user-XXX.

    新流程下,子号注册时的 access_token JWT 里没有 chatgpt_user_id(还没在 workspace),
    必须在激活后通过 master cookies 主动查。
    """
    try:
        from curl_cffi import requests as cffi_requests
    except Exception as exc:
        log_fn(f"[resolve_user_id] curl_cffi 不可用: {exc}")
        return ""
    try:
        from services.business_domain_service import get_openai_cookies, cookies_header
    except Exception as exc:
        log_fn(f"[resolve_user_id] 母号工具导入失败: {exc}")
        return ""

    try:
        cookies = get_openai_cookies()
    except Exception as exc:
        log_fn(f"[resolve_user_id] 母号 Cookie 不可用: {exc}")
        return ""
    bearer = cookies.get("oai-access-token", "")
    if not bearer:
        log_fn("[resolve_user_id] 母号 oai-access-token 缺失")
        return ""

    proxies = None
    if (proxy or "").strip():
        proxies = {"http": proxy.strip(), "https": proxy.strip()}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "chatgpt-account-id": account_id,
        "Cookie": cookies_header(cookies),
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Referer": "https://chatgpt.com/admin/members",
    }
    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/users"
    # query 用 email local-part 比整段 email 命中率更高(OpenAI 后端 query 是模糊匹配)
    query_token = (email or "").split("@", 1)[0]
    try:
        resp = cffi_requests.get(
            url, headers=headers, params={"query": query_token, "limit": 10},
            timeout=30, impersonate="chrome131", proxies=proxies,
        )
    except Exception as exc:
        log_fn(f"[resolve_user_id] HTTP 异常: {exc}")
        return ""
    if int(getattr(resp, "status_code", 0) or 0) != 200:
        log_fn(f"[resolve_user_id] HTTP {resp.status_code}: {(resp.text or '')[:200]}")
        return ""
    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    email_lc = (email or "").strip().lower()
    for item in (data.get("items") or []):
        if isinstance(item, dict) and str(item.get("email", "")).strip().lower() == email_lc:
            return str(item.get("id") or "").strip()
    return ""


def _switch_business_seat_to_codex(
    account_extra: dict, log_fn, proxy: str = "", enabled: bool = True,
    target: str = "usage_based",
) -> None:
    """BUSINESS 子号切换席位 (默认 ChatGPT(null) → Codex(usage_based))。

    OpenAI 接口 `seat_type` 字段只接受两个枚举值:
      - "usage_based"  → Codex 按用量席位
      - "default"      → ChatGPT 普通席位 (CODE 套餐)

    依赖:
      - config_store["openai_admin_cookies"]: 母号 admin.openai.com Cookie,内含 oai-access-token
      - account_extra["access_token"]      : 子号刚注册到的 access_token (JWT, 含 chatgpt_account_id/user_id)

    enabled=False 时直接跳过(用户在 UI 取消勾选)。任何一步失败都只打日志,不抛错。
    """
    target = (target or "usage_based").strip().lower()
    if target not in ("usage_based", "default"):
        log_fn(f"[BUSINESS] 跳过席位切换: target={target!r} 非法,只能是 'usage_based' / 'default'")
        return
    target_label = "Codex" if target == "usage_based" else "ChatGPT"

    if not enabled:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:UI 未勾选「切换为 {target_label} 席位」")
        return

    import base64

    try:
        from curl_cffi import requests as cffi_requests
    except Exception as exc:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:curl_cffi 不可用 ({exc})")
        return

    try:
        from services.business_domain_service import get_openai_cookies, cookies_header
    except Exception as exc:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:导入失败 ({exc})")
        return

    try:
        cookies = get_openai_cookies()
        bearer = cookies.get("oai-access-token", "")
    except Exception as exc:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:母号 Cookie 不可用 ({exc})")
        return
    if not bearer:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:母号 oai-access-token 缺失")
        return

    # 优先用调用方显式注入的 account_id / user_id (新流程:激活后从 master cookies 查到的);
    # 否则 fallback 到从子号 access_token JWT 解码(老 Codex 路径,注册时账号已在 workspace)。
    account_id = str(account_extra.get("chatgpt_account_id") or "").strip()
    user_id = str(account_extra.get("chatgpt_user_id") or "").strip()
    if not account_id or not user_id:
        child_token = (account_extra or {}).get("access_token", "")
        if not child_token:
            log_fn(f"[BUSINESS] 跳过 {target_label} 切换:子号 access_token 缺失且未注入 user_id")
            return
        try:
            payload_b64 = child_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            auth = claims.get("https://api.openai.com/auth", {}) or {}
            account_id = account_id or auth.get("chatgpt_account_id") or claims.get("chatgpt_account_id", "")
            user_id = user_id or auth.get("chatgpt_user_id") or claims.get("chatgpt_user_id", "")
        except Exception as exc:
            log_fn(f"[BUSINESS] 跳过 {target_label} 切换:解码子号 JWT 失败 ({exc})")
            return
    if not account_id or not user_id:
        log_fn(f"[BUSINESS] 跳过 {target_label} 切换:缺 account_id/user_id (account_id={account_id!r}, user_id={user_id!r})")
        return

    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {bearer}",
        "chatgpt-account-id": account_id,
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    cookie_str = cookies_header(cookies)
    if cookie_str:
        headers["Cookie"] = cookie_str

    interval_ms = _SEAT_SWITCH_DEFAULT_INTERVAL_MS
    try:
        from core.config_store import config_store
        raw = config_store.get("business_codex_switch_interval_ms", "")
        if raw not in ("", None):
            interval_ms = max(0, int(str(raw).strip()))
    except Exception:
        pass

    global _SEAT_SWITCH_LAST_TS
    with _SEAT_SWITCH_LOCK:
        wait = (_SEAT_SWITCH_LAST_TS + interval_ms / 1000.0) - time.time()
        if wait > 0:
            log_fn(f"[BUSINESS] 限速等待 {int(wait * 1000)}ms")
            time.sleep(wait)
        _SEAT_SWITCH_LAST_TS = time.time()

    proxies = None
    proxy_used = (proxy or "").strip()
    if proxy_used:
        proxies = {"http": proxy_used, "https": proxy_used}
        log_fn(f"[BUSINESS] 切换 {target_label} 席位: user_id={user_id} (proxy={proxy_used})")
    else:
        log_fn(f"[BUSINESS] 切换 {target_label} 席位: user_id={user_id} (无代理,直连)")
    try:
        resp = cffi_requests.patch(
            url, headers=headers,
            json={"seat_type": target},
            timeout=30,
            impersonate="chrome131",
            proxies=proxies,
        )
    except Exception as exc:
        log_fn(f"[BUSINESS] ❌ {target_label} 切换请求异常: {exc}")
        return

    ok = False
    try:
        body = resp.json() or {}
        ok = resp.status_code == 200 and bool(body.get("success"))
    except Exception:
        body = {}

    if ok:
        account_extra["seat_type"] = target
        ts = int(time.time())
        if target == "usage_based":
            account_extra["seat_switched_to_codex_at"] = ts
        else:
            account_extra["seat_switched_to_chatgpt_at"] = ts
        log_fn(f"[BUSINESS] ✅ 已切换为 {target_label} 席位 (account_id={account_id})")
    else:
        snippet = ""
        try:
            snippet = (resp.text or "")[:200]
        except Exception:
            pass
        log_fn(f"[BUSINESS] ❌ {target_label} 切换失败: HTTP {resp.status_code} {snippet}")


# 中性别名:新流程默认切 default(ChatGPT 席位),但底层函数兼容两个 target。
_switch_business_seat = _switch_business_seat_to_codex


def _decode_master_cookie_account_id(bearer: str) -> str:
    """[兼容旧调用] 试着从 master JWT 解出 chatgpt_account_id。

    实测 master 母号的 admin JWT 里没有这个字段,这条路通常返回 ""。
    新流程统一用 _resolve_master_workspace_id (走 /accounts/check)。
    """
    import base64
    try:
        payload_b64 = bearer.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        auth = claims.get("https://api.openai.com/auth", {}) or {}
        return (
            auth.get("chatgpt_account_id")
            or claims.get("chatgpt_account_id", "")
            or ""
        )
    except Exception:
        return ""


# master workspace id 的内存缓存 (避免每批 invite 都调一次 /accounts/check)
_MASTER_WORKSPACE_CACHE: dict = {"id": "", "expire_at": 0.0}
_MASTER_WORKSPACE_CACHE_TTL = 600  # 10 分钟


def _resolve_master_workspace_id(log_fn, proxy: str = "") -> str:
    """解析母号管理的 BUSINESS workspace id (chatgpt_account_id).

    优先级:
      1. config_store["openai_business_account_id"] (用户手动指定,固定不变最快)
      2. master JWT 里的 chatgpt_account_id (兼容旧版 JWT)
      3. GET /backend-api/accounts/check/v4-2023-04-27 (自动发现,缓存 10 分钟)

    多个 BUSINESS workspace 时取第一个,要指定就走配置项覆盖。
    """
    try:
        from core.config_store import config_store
        configured = str(config_store.get("openai_business_account_id", "") or "").strip()
        if configured:
            return configured
    except Exception:
        pass

    # 内存缓存
    now = time.time()
    if _MASTER_WORKSPACE_CACHE["id"] and now < _MASTER_WORKSPACE_CACHE["expire_at"]:
        return _MASTER_WORKSPACE_CACHE["id"]

    try:
        from services.business_domain_service import get_openai_cookies, cookies_header
        cookies = get_openai_cookies()
        bearer = cookies.get("oai-access-token", "")
    except Exception as exc:
        log_fn(f"[workspace_id] 母号 Cookie 不可用: {exc}")
        return ""

    if not bearer:
        log_fn("[workspace_id] 母号 oai-access-token 缺失")
        return ""

    # 优先从 JWT 解(兼容旧版)
    via_jwt = _decode_master_cookie_account_id(bearer)
    if via_jwt:
        _MASTER_WORKSPACE_CACHE.update({"id": via_jwt, "expire_at": now + _MASTER_WORKSPACE_CACHE_TTL})
        return via_jwt

    # /accounts/check 自动发现
    try:
        from curl_cffi import requests as cffi_requests
    except Exception as exc:
        log_fn(f"[workspace_id] curl_cffi 不可用: {exc}")
        return ""

    proxies = None
    if (proxy or "").strip():
        proxies = {"http": proxy.strip(), "https": proxy.strip()}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Cookie": cookies_header(cookies),
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Referer": "https://chatgpt.com/",
    }
    try:
        resp = cffi_requests.get(
            "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
            headers=headers, timeout=30, impersonate="chrome131", proxies=proxies,
        )
    except Exception as exc:
        log_fn(f"[workspace_id] /accounts/check HTTP 异常: {exc}")
        return ""

    if int(getattr(resp, "status_code", 0) or 0) != 200:
        log_fn(f"[workspace_id] /accounts/check HTTP {resp.status_code}: {(resp.text or '')[:160]}")
        return ""

    try:
        data = resp.json() or {}
        accounts = data.get("accounts") or {}
    except Exception as exc:
        log_fn(f"[workspace_id] /accounts/check 响应解析失败: {exc}")
        return ""

    # 优先选 plan_type=business 或 account_type=business 的
    chosen = ""
    for wid, info in accounts.items():
        if not isinstance(info, dict):
            continue
        acc = info.get("account") or {}
        plan = str(acc.get("plan_type", "") or acc.get("account_type", "")).lower()
        if "business" in plan or "enterprise" in plan:
            chosen = wid
            break
    if not chosen and accounts:
        # fallback: 第一个非 personal 的 account
        for wid, info in accounts.items():
            acc = info.get("account") or {}
            if not acc.get("personal"):
                chosen = wid
                break
    if not chosen and accounts:
        # 最后兜底:第一个
        chosen = list(accounts.keys())[0]

    if chosen:
        _MASTER_WORKSPACE_CACHE.update({"id": chosen, "expire_at": now + _MASTER_WORKSPACE_CACHE_TTL})
        log_fn(f"[workspace_id] 自动发现 master workspace: {chosen}")
    else:
        log_fn("[workspace_id] /accounts/check 未返回任何 workspace")
    return chosen


def _normalize_business_invite_seat_type(value: str) -> str:
    seat_type = str(value or "").strip().lower()
    if seat_type not in {"default", "prolite"}:
        raise ValueError("seat_type must be 'default' or 'prolite'")
    return seat_type


def _send_business_invites_batch(
    emails: list, log_fn, proxy: str = "",
    cookie_blob: str = "", workspace_id: str = "",
    seat_type: str = "default",
) -> dict:
    """母号批量发邀请。emails 最多 6 个,一次 POST 完成。

    cookie_blob / workspace_id 指定则用**该母号**的凭证(多母号列表用);
    都留空则回退全局 openai_admin_cookies(旧单母号行为)。

    返回 {
      ok: bool,                # POST 成功(HTTP 200)
      account_id: str,         # workspace id (写回账号 extra)
      invited: [str],          # OpenAI 接受的 email 列表
      errored: [{email, message}], # 拒收的 email
      raw_status: int,
      raw_snippet: str,
    }

    限频复用 _SEAT_SWITCH_LOCK/_SEAT_SWITCH_LAST_TS,避免和切席位/前一批邀请互相打架。
    """
    from services.business_domain_service import get_openai_cookies, cookies_header, parse_cookie_blob
    from platforms.chatgpt.team_invite import (
        _build_common_headers,
        _http_request,
        _extract_invited_emails_from_result,
        _extract_errored_emails_from_result,
    )

    seat_type = _normalize_business_invite_seat_type(seat_type)
    normalized = [str(e or "").strip().lower() for e in (emails or []) if str(e or "").strip()]
    if not normalized:
        return {"ok": False, "account_id": "", "invited": [], "errored": [],
                "raw_status": 0, "raw_snippet": "no emails"}

    use_specific = bool(str(cookie_blob or "").strip())
    try:
        cookies = parse_cookie_blob(cookie_blob) if use_specific else get_openai_cookies()
    except Exception as exc:
        log_fn(f"[invite] ❌ 母号 Cookie 不可用: {exc}")
        return {"ok": False, "account_id": "", "invited": [],
                "errored": [{"email": e, "message": f"母号 Cookie 不可用: {exc}"} for e in normalized],
                "raw_status": 0, "raw_snippet": str(exc)[:200]}

    bearer = cookies.get("oai-access-token", "")
    if not bearer:
        log_fn("[invite] ❌ 母号 oai-access-token 缺失")
        return {"ok": False, "account_id": "", "invited": [],
                "errored": [{"email": e, "message": "母号 oai-access-token 缺失"} for e in normalized],
                "raw_status": 0, "raw_snippet": "no bearer"}

    # workspace id: 显式传入 > 从该母号自己的 JWT 解 > (仅全局母号)回退全局解析
    account_id = str(workspace_id or "").strip()
    if not account_id:
        account_id = (_decode_master_cookie_account_id(bearer) if use_specific
                      else _resolve_master_workspace_id(log_fn, proxy=proxy))
    if not account_id:
        log_fn("[invite] ❌ 无法解析 master workspace id (JWT/check/config 均失败)")
        return {"ok": False, "account_id": "", "invited": [],
                "errored": [{"email": e, "message": "master workspace id 解析失败"} for e in normalized],
                "raw_status": 0, "raw_snippet": "workspace_id resolve failed"}

    interval_ms = _SEAT_SWITCH_DEFAULT_INTERVAL_MS
    try:
        from core.config_store import config_store
        raw = config_store.get("business_codex_switch_interval_ms", "")
        if raw not in ("", None):
            interval_ms = max(0, int(str(raw).strip()))
    except Exception:
        pass

    global _SEAT_SWITCH_LAST_TS
    with _SEAT_SWITCH_LOCK:
        wait = (_SEAT_SWITCH_LAST_TS + interval_ms / 1000.0) - time.time()
        if wait > 0:
            time.sleep(wait)
        _SEAT_SWITCH_LAST_TS = time.time()

    headers = _build_common_headers(account_id, bearer)
    cookie_str = cookies_header(cookies)
    if cookie_str:
        headers["cookie"] = cookie_str
    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
    payload = {
        "email_addresses": normalized,
        "role": "standard-user",
        "seat_type": seat_type,
        "resend_emails": True,
    }
    log_fn(
        f"[invite] POST /invites 批量 {len(normalized)} 个, seat_type={seat_type} "
        f"→ {normalized[:3]}{'...' if len(normalized)>3 else ''}"
    )
    try:
        resp, _backend = _http_request(
            method="POST", url=url, headers=headers,
            timeout=30, payload=payload, proxy=proxy,
        )
    except Exception as exc:
        log_fn(f"[invite] ❌ HTTP 异常: {exc}")
        return {"ok": False, "account_id": account_id, "invited": [],
                "errored": [{"email": e, "message": f"HTTP 异常: {exc}"} for e in normalized],
                "raw_status": 0, "raw_snippet": str(exc)[:200]}

    status = int(getattr(resp, "status_code", 0) or 0)
    snippet = ""
    try:
        snippet = (resp.text or "")[:300]
    except Exception:
        pass

    if status != 200:
        log_fn(f"[invite] ❌ HTTP {status}: {snippet}")
        return {"ok": False, "account_id": account_id, "invited": [],
                "errored": [{"email": e, "message": f"HTTP {status}: {snippet[:220]}"} for e in normalized],
                "raw_status": status, "raw_snippet": snippet}

    try:
        result = resp.json() or {}
    except Exception:
        result = {}

    invited_emails = _extract_invited_emails_from_result(result, normalized)
    errored_entries = _extract_errored_emails_from_result(result)

    # 抽取每个 email 的 invite_id (account_invites 数组 / dict 形态都兼容)
    invite_id_map: dict = {}
    raw_invites = result.get("account_invites")
    if isinstance(raw_invites, list):
        for item in raw_invites:
            if isinstance(item, dict):
                email_key = str(
                    item.get("email") or item.get("email_address")
                    or item.get("invited_email") or ""
                ).strip().lower()
                invite_id_val = str(item.get("id") or item.get("invite_id") or "").strip()
                if email_key and invite_id_val:
                    invite_id_map[email_key] = invite_id_val
    elif isinstance(raw_invites, dict):
        for k, item in raw_invites.items():
            if isinstance(item, dict):
                email_key = str(
                    item.get("email") or item.get("email_address") or k or ""
                ).strip().lower()
                invite_id_val = str(item.get("id") or item.get("invite_id") or k or "").strip()
                if email_key and invite_id_val:
                    invite_id_map[email_key] = invite_id_val

    invited_with_ids = [
        {"email": e, "invite_id": invite_id_map.get(e, "")}
        for e in invited_emails
    ]

    log_fn(
        f"[invite] ✅ {len(invited_with_ids)}/{len(normalized)} 成功"
        f"{', errored ' + str(len(errored_entries)) if errored_entries else ''}"
    )
    return {
        "ok": True,
        "account_id": account_id,
        "invited": invited_with_ids,
        "errored": errored_entries,
        "raw_status": status,
        "raw_snippet": snippet,
    }


# OpenAI 邀请邮件链接候选模式
# 实测主链接形如:
#   https://chatgpt.com/accept-invite?inv_ws_name=...&inv_email=...&wId=...&accept_wId=...
# 兼容 chat.openai.com / auth*.openai.com 的历史路径。
_OPENAI_INVITE_URL_REGEX = re.compile(
    r"https?://(?:chatgpt\.com|chat\.openai\.com|auth\.openai\.com|"
    r"auth0\.openai\.com|platform\.openai\.com)/[^\s\"'<>]*?"
    r"(?:accept-invite|accept_invite|/invite|/invitation)[^\s\"'<>]*",
    re.IGNORECASE,
)


def _qp_decode_safe(text: str) -> str:
    """对邮件原文做 quoted-printable 解码,任何异常都返回原文。

    OpenAI 邀请邮件正文用 QP 编码,导致:
      - `=` 被编码成 `=3D`
      - 长 URL 被软折行(`=` 后跟换行)拆成多行
    必须先解码才能提取完整 URL。
    """
    if not text:
        return ""
    try:
        import quopri
        return quopri.decodestring(text.encode("utf-8", "replace")).decode("utf-8", "replace")
    except Exception:
        return text


def _activate_invite_via_email(
    account_extra: dict, cfworker_api_url: str, cfworker_admin_token: str,
    log_fn, proxy: str = "",
    cfworker_custom_auth: str = "",
    timeout_seconds: int = 180,
) -> dict:
    """轮询 CF Worker /admin/mails 找到 OpenAI 邀请邮件,提取激活链接,
    用子号已注册时拿到的 cookies + access_token 模拟 GET 完成激活。

    返回 {ok, invite_url?, error?}
    """
    import email as _email
    from email import policy as _email_policy
    try:
        import requests as _req
    except Exception as exc:
        return {"ok": False, "error": f"requests 不可用: {exc}"}

    email_addr = str(account_extra.get("email") or account_extra.get("primary_email") or "").strip()
    if not email_addr:
        # 注册时 extra 里不一定有 email 字段(account.email 才存了),所以这里允许调用方传
        # 来自 extra 的 fallback 字段
        email_addr = str(account_extra.get("business_email") or "").strip()
    if not email_addr:
        return {"ok": False, "error": "extra 缺 email"}

    api = (cfworker_api_url or "").strip().rstrip("/")
    if not api:
        return {"ok": False, "error": "cfworker_api_url 未配置"}

    headers_mail = {"x-admin-auth": (cfworker_admin_token or "").strip()}
    if (cfworker_custom_auth or "").strip():
        headers_mail["x-custom-auth"] = cfworker_custom_auth.strip()

    deadline = time.time() + max(30, int(timeout_seconds or 180))
    seen_ids: set = set()
    invite_url: str = ""

    def _extract_invite_url(mail_obj: dict) -> str:
        candidates: list = []
        for k in ("text", "html"):
            v = mail_obj.get(k) or ""
            if v:
                candidates.append(v)
        raw = mail_obj.get("raw") or ""
        # MIME 解析 (拿到分段后的 plain/html);异常容忍。
        if raw:
            try:
                msg = _email.message_from_string(raw, policy=_email_policy.default)
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        try:
                            content = part.get_content()
                            if isinstance(content, str):
                                candidates.append(content)
                        except Exception:
                            pass
            except Exception:
                pass
            # 同时把原始 raw 也加进来(QP 解码后);某些 worker 不解析分段
            candidates.append(raw)
        # 优先 QP 解码版本(邀请邮件 URL 必然被 quoted-printable 折行);
        # 命中带 wId / accept_wId 参数的真邀请链接立即返回;
        # 否则取所有候选里最长的(避免被 raw 原文截断版本误捕获)。
        best = ""
        for body in candidates:
            for variant in (_qp_decode_safe(body), body):
                m = _OPENAI_INVITE_URL_REGEX.search(variant or "")
                if not m:
                    continue
                url = m.group(0)
                if "wId=" in url or "accept_wId=" in url:
                    return url
                if len(url) > len(best):
                    best = url
        return best

    while time.time() < deadline and not invite_url:
        try:
            resp = _req.get(
                f"{api}/admin/mails",
                params={"limit": 20, "offset": 0, "address": email_addr},
                headers=headers_mail, timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json() or {}
                for m in data.get("results") or []:
                    mid = m.get("id")
                    if mid in seen_ids:
                        continue
                    seen_ids.add(mid)
                    # 不再按 sender 过滤 — CF Worker 返回的 from 字段经常为空,
                    # 直接用 invite URL 正则判断是不是邀请邮件更可靠。
                    url = _extract_invite_url(m)
                    if url:
                        invite_url = url
                        log_fn(f"[activate] 邀请链接捕获: {url[:120]}...")
                        break
            else:
                log_fn(f"[activate] /admin/mails HTTP {resp.status_code},重试")
        except Exception as exc:
            log_fn(f"[activate] 拉邮件异常: {str(exc)[:120]}")
        if not invite_url:
            time.sleep(3)

    if not invite_url:
        return {"ok": False, "error": f"等 {timeout_seconds}s 未捕获邀请邮件链接"}

    # 用子号 cookies 模拟浏览器 GET invite URL,完成激活。
    # 注意:
    #   1. 不带 Authorization Bearer — /accept-invite 是浏览器路由,带 Bearer 会被识别为 API 调用触发 403
    #   2. 精简 cookies — 注册时拿到的 26+ 个 cookies 拼成 header 会超过 chatgpt.com 的 8KB 限制 (HTTP 431)
    #   3. 第一次可能 403,重试 2~3 次(OpenAI 后端 session 写入有 1~2s 延迟)
    cookies_blob = account_extra.get("cookies", "")
    cookies_all: dict = {}
    if isinstance(cookies_blob, str) and cookies_blob.strip():
        try:
            data = json.loads(cookies_blob)
            if isinstance(data, dict):
                cookies_all = {str(k): str(v) for k, v in data.items() if v is not None}
            elif isinstance(data, list):
                for c in data:
                    if isinstance(c, dict) and c.get("name"):
                        cookies_all[str(c["name"])] = str(c.get("value", ""))
        except Exception:
            pass
    elif isinstance(cookies_blob, dict):
        cookies_all = {str(k): str(v) for k, v in cookies_blob.items() if v is not None}

    # 只保留 chatgpt.com 路由必需的 next-auth session + 账号上下文
    _COOKIE_KEEP_PREFIXES = (
        "__Secure-next-auth.session-token",
        "__Secure-next-auth.callback-url",
        "__Host-next-auth.csrf-token",
        "_account",
        "oai-did",
        "auth-session-minimized",
        "oai-client-auth-session",
        "__Secure-oai-is",
    )
    cookies_dict = {
        k: v for k, v in cookies_all.items()
        if any(k.startswith(p) for p in _COOKIE_KEEP_PREFIXES)
    }
    if not cookies_dict:
        return {"ok": False, "error": "子号 cookies 缺少 next-auth session"}

    headers_get = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
    }

    proxies = None
    if (proxy or "").strip():
        proxies = {"http": proxy.strip(), "https": proxy.strip()}

    try:
        from curl_cffi import requests as cffi_requests
    except Exception as exc:
        return {"ok": False, "error": f"curl_cffi 不可用: {exc}", "invite_url": invite_url}

    last_status = 0
    last_err = ""
    for attempt in range(3):
        try:
            resp = cffi_requests.get(
                invite_url,
                headers=headers_get,
                cookies=cookies_dict,
                timeout=30,
                impersonate="chrome131",
                proxies=proxies,
                allow_redirects=True,
            )
            last_status = int(getattr(resp, "status_code", 0) or 0)
            final_url = str(getattr(resp, "url", "") or "")
            log_fn(f"[activate] GET 邀请链接 attempt {attempt+1} HTTP {last_status} → {final_url[:120]}")
            if 200 <= last_status < 400:
                return {"ok": True, "invite_url": invite_url, "status": last_status,
                        "final_url": final_url}
        except Exception as exc:
            last_err = str(exc)
            log_fn(f"[activate] GET 异常 attempt {attempt+1}: {last_err[:200]}")
        if attempt < 2:
            time.sleep(2)
    return {"ok": False,
            "error": f"激活链接 3 次均失败 (last HTTP {last_status}{', ' + last_err if last_err else ''})",
            "invite_url": invite_url}


def _make_business_rt_log_filter(downstream_log_fn):
    """OAuthClient 内部日志 → 用户可读的中文精简日志。

    规则：
      - 命中关键阶段（authorize_continue / OTP / add_phone / token） → 翻译成简短中文
      - 命中已知噪声（状态步进、device_id、Sentinel 模式、follow[N]、raw 响应体等） → 丢弃
      - 其他默认丢弃（避免刷屏）；调试时可通过 _BR_DEBUG=1 全量显示
    """
    import os
    import re

    debug_all = os.environ.get("BUSINESS_RT_LOG_DEBUG", "0") not in ("0", "", "false")

    # (regex, 中文模板 or None) 命中后 → 翻译；None=丢弃
    rules: list[tuple[re.Pattern, str | None]] = [
        # ──── 丢弃的噪声 ────
        (re.compile(r"^OAuth 策略:"), None),
        (re.compile(r"^OAuth 指纹:"), None),
        (re.compile(r"^force_new_browser:"), None),
        (re.compile(r"^状态步进\["), None),
        (re.compile(r"^OAuth 状态起点:"), None),
        (re.compile(r"device_id=\S+"), None),
        (re.compile(r"^authorize_continue: device_id="), None),
        (re.compile(r"^authorize_continue: Sentinel Browser 模式:"), None),
        (re.compile(r"^authorize_continue: Sentinel Browser 启动:"), None),
        (re.compile(r"^email_otp_validate: device_id="), None),
        (re.compile(r"^email_otp_validate: Sentinel Browser 模式:"), None),
        (re.compile(r"^email_otp_validate: Sentinel Browser 启动:"), None),
        (re.compile(r"^authorize_continue 响应:"), None),
        (re.compile(r"^add_phone 状态响应体"), None),
        (re.compile(r"^add-phone/send page="), None),
        (re.compile(r"^otp 响应详情:"), None),
        (re.compile(r"^OAuth OTP 等待窗口:"), None),
        (re.compile(r"^使用 wait_for_verification_code"), None),
        (re.compile(r"^\[stage="), None),
        (re.compile(r"^page=\S+\s+method=\S+\s+next="), None),
        # ──── 翻译成中文 ────
        (re.compile(r"^开始 OAuth 登录流程"), "▶ 开始 OAuth 登录"),
        (re.compile(r"^步骤1:\s*Bootstrap OAuth session"), "  1/7 初始化 OAuth 会话"),
        (re.compile(r"^/oauth/authorize -> 200"), "  ✓ OAuth 授权入口已就绪"),
        (re.compile(r"^login_session:\s*已获取"), "  ✓ 登录会话已建立"),
        (re.compile(r"^login_session:\s*未获取"), "  ✗ 登录会话未拿到"),
        (re.compile(r"^步骤2:\s*POST /api/accounts/authorize/continue"), "  2/7 提交邮箱"),
        (re.compile(r"^authorize_continue:\s*已通过 Playwright SentinelSDK 获取 token"), "  ✓ 已过 Sentinel 反爬"),
        (re.compile(r"^authorize_continue:\s*已通过 HTTP PoW 获取 token"), "  ✓ 已过 Sentinel（PoW）"),
        (re.compile(r"^/authorize/continue -> 200"), "  ✓ 邮箱已提交"),
        (re.compile(r"^/authorize/continue -> (\d+)"),
         lambda m: f"  ✗ 邮箱提交失败 HTTP {m.group(1)}"),
        (re.compile(r"^步骤4:\s*检测到邮箱 OTP 验证"), "  3/7 等待邮箱验证码"),
        (re.compile(r"^email_otp_validate:\s*已通过 Playwright SentinelSDK 获取 token"), "  ✓ 已过 OTP Sentinel"),
        (re.compile(r"^尝试 OTP:\s*(\d+)"),
         lambda m: f"  ↳ 提交邮箱验证码 {m.group(1)}"),
        (re.compile(r"^/email-otp/validate -> 200"), "  ✓ 邮箱验证码通过"),
        (re.compile(r"^OTP 验证通过"), None),  # 重复信息
        (re.compile(r"^步骤5:\s*OTP 后命中 add_phone"), "  4/7 命中手机验证"),
        (re.compile(r"^步骤5:\s*add_phone 使用配置手机号:\s*(\S+)"),
         lambda m: f"    ↳ 使用手机号 {m.group(1)}"),
        (re.compile(r"^/add-phone/send -> 200"), "    ✓ 手机号已提交"),
        (re.compile(r"^步骤5:\s*add_phone 轮询 SMS API"), "  5/7 等待 SMS 验证码"),
        (re.compile(r"^SMS API 收到验证码:\s*(\d+)"),
         lambda m: f"    ↳ SMS 验证码到达 {m.group(1)}"),
        (re.compile(r"^SMS API HTTP \d+"), None),  # 太频繁
        (re.compile(r"^SMS API 暂不可达"),
         lambda m: f"    ⏳ SMS 服务暂不可达，重试中"),
        (re.compile(r"^/phone-otp/validate -> 200"), "  ✓ 手机验证码通过"),
        (re.compile(r"^手机号 OTP 验证通过"), None),
        (re.compile(r"^步骤6:\s*命中 consent 状态"), "  6/7 已选 workspace，确认 consent"),
        (re.compile(r"^步骤6"), "  6/7 选择 workspace"),
        (re.compile(r"^步骤7:\s*POST /oauth/token"), "  7/7 换取 RT/AT"),
        (re.compile(r"^token_exchange 成功"), "  ✓ 已拿到 refresh_token / access_token"),
        (re.compile(r"^token_exchange"), None),
        (re.compile(r"^consent 直走拿到 code"), "    ✓ consent 确认成功"),
        (re.compile(r"^✅ OAuth 登录成功 \(consent 直走\)"), None),
        # workspace / consent 相关 (诊断用,保留可读关键步骤)
        (re.compile(r"^BUSINESS 账号 session 无 workspaces"), "    ↳ workspace 列表为空,以默认 workspace 提交"),
        (re.compile(r"^consent\.data 预热 -> (\d+)"),
         lambda m: f"    ↳ consent.data 预热 HTTP {m.group(1)}"),
        (re.compile(r"^consent\.data 预热跳过"), None),
        (re.compile(r"^workspace/select -> (\d+)"),
         lambda m: f"    ↳ workspace/select 响应 HTTP {m.group(1)}"),
        (re.compile(r"^workspace/select 第 (\d+) 次重试,等 (\S+)s"),
         lambda m: f"    ⏳ workspace/select 第 {m.group(1)} 次重试,等 {m.group(2)}s"),
        (re.compile(r"^workspace/select (\d+) body:\s*(.*)"),
         lambda m: f"    ↳ workspace/select {m.group(1)} body: {m.group(2)[:160]}"),
        (re.compile(r"^workspace/select 重试 \d+ 次后仍"), None),
        (re.compile(r"^workspace/select 重定向到"),
         lambda m: f"    ↳ workspace/select 跳转无 code,触发 consent 兜底"),
        (re.compile(r"^workspace_select 兜底:"), "    ↳ 重发 /oauth/authorize 走 consent"),
        (re.compile(r"^consent 兜底拿到 authorization code"), "    ✓ consent 兜底拿到 code"),
        (re.compile(r"^选择 workspace:"), None),
        (re.compile(r"^workspace state 终态无 code"), "    ↳ workspace 终态无 code,最后一搏"),
        (re.compile(r"^\[stage=workspace_select\]"), None),
        (re.compile(r"^workspace/select 请求:"), None),
        (re.compile(r"^workspace/select"), "  ↳ workspace/select"),
        # follow chain 诊断
        (re.compile(r"^follow\[\d+\]\s*\d+\s*(.*)"),
         lambda m: f"      [follow] {m.group(1)[:100]}"),
    ]

    def filtered_log(msg: str) -> None:
        text = str(msg or "").strip()
        if not text:
            return
        # 兜底：错误一定保留
        is_error = any(s in text for s in ("失败", "异常", "超时", "错误", "未获取", "✗"))
        for pat, replacement in rules:
            m = pat.search(text)
            if not m:
                continue
            if replacement is None:
                if debug_all:
                    downstream_log_fn(f"[RT.原文] {text}")
                return
            if callable(replacement):
                downstream_log_fn(replacement(m))
            else:
                downstream_log_fn(replacement)
            return
        # 未命中规则：错误打出来，其他默认丢
        if is_error:
            downstream_log_fn(f"  ⚠ {text}")
        elif debug_all:
            downstream_log_fn(f"[RT.原文] {text}")

    return filtered_log


class _BusinessOAuthEmailAdapter:
    """OAuthClient.login_and_get_tokens 用的 skymail_client。

    通过 CF Worker /admin/mails 拉 OTP，独立 seen_ids（与 BUSINESS 协议注册阶段隔离），
    避免阶段 2 读到阶段 1 已使用过的旧验证码。
    """

    from enum import Enum as _Enum

    class _ServiceType(_Enum):
        CFWORKER = "cfworker"

    service_type = _ServiceType.CFWORKER

    def __init__(self, email: str, api_url: str, admin_token: str,
                 custom_auth: str, log_fn) -> None:
        self._email = email
        self._api = (api_url or "").strip().rstrip("/")
        self._admin_token = (admin_token or "").strip()
        self._custom_auth = (custom_auth or "").strip()
        self._log = log_fn or (lambda _msg: None)
        self._seen_ids: set = set()
        self._baseline_ready = False
        self._baseline_attempted = False
        self._baseline_highest_numeric_id: int | None = None
        self._seen_ids_lock = threading.Lock()

    def create_email(self):
        return {"email": self._email}

    def prepare_for_verification(self) -> bool:
        """Read only old message IDs before OAuth can send another code."""
        import requests as _req
        from platforms.chatgpt.generate_oauth_json_protocol import _collect_existing_mail_ids

        self._baseline_attempted = True
        self._baseline_ready = False
        if not self._api or not self._admin_token or not self._email:
            return False
        try:
            baseline_ids = _collect_existing_mail_ids(
                {
                    "provider": "cfworker_admin", "email": self._email,
                    "api_base": self._api, "admin_token": self._admin_token,
                    "custom_auth": self._custom_auth,
                },
                strict=True, request_get=_req.get,
            )
            with self._seen_ids_lock:
                self._seen_ids.update(baseline_ids)
                if baseline_ids and all(mid.isdecimal() for mid in baseline_ids):
                    self._baseline_highest_numeric_id = max(map(int, baseline_ids))
                else:
                    self._baseline_highest_numeric_id = None
            self._baseline_ready = True
            return True
        except Exception:
            self._log("[OAuth 邮箱适配器] 无法建立新邮件基线，追加邮箱验证暂不可用")
            return False

    @staticmethod
    def _extract_code(mail_obj: dict) -> str:
        import re as _re
        import email as _email
        from email import policy as _email_policy

        candidates = []
        for k in ("text", "html"):
            v = mail_obj.get(k) or ""
            if v:
                candidates.append(v)
        raw = mail_obj.get("raw") or ""
        if raw:
            try:
                msg = _email.message_from_string(raw, policy=_email_policy.default)
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        try:
                            content = part.get_content()
                            if isinstance(content, str):
                                candidates.append(content)
                        except Exception:
                            pass
            except Exception:
                pass

        keyword_re = _re.compile(
            r"(?:to\s+continue|verification\s+code|"
            r"输入此临时验证码|enter\s+this\s+temporary\s+verification\s+code|"
            r"your\s+code\s+is)"
            r".{0,2000}?(?<!\d)(\d{6})(?!\d)",
            _re.IGNORECASE | _re.DOTALL,
        )
        for body in candidates:
            match = keyword_re.search(body)
            if match:
                return match.group(1)
        return ""

    def wait_for_verification_code(self, email=None, timeout=120, otp_sent_at=None,
                                    exclude_codes=None, **kwargs):
        """OAuthClient 在 OTP 阶段调用的接口，命中 hasattr 走阻塞拉取分支。"""
        import requests as _req

        requested_email = str(email or self._email).strip().lower()
        if requested_email != str(self._email).strip().lower():
            return ""
        if self._baseline_attempted and not self._baseline_ready:
            return ""
        deadline = time.time() + max(int(timeout or 60), 30)
        exclude = set(exclude_codes or [])
        headers = {"x-admin-auth": self._admin_token}
        if self._custom_auth:
            headers["x-custom-auth"] = self._custom_auth

        while time.time() < deadline:
            try:
                resp = _req.get(
                    f"{self._api}/admin/mails",
                    params={"limit": 20, "offset": 0, "address": self._email},
                    headers=headers, timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json() or {}
                    for m in data.get("results") or []:
                        raw_id = m.get("id") if isinstance(m, dict) else None
                        if not isinstance(raw_id, (str, int)) or isinstance(raw_id, bool) or not str(raw_id).strip():
                            continue
                        mid = str(raw_id)
                        with self._seen_ids_lock:
                            if mid in self._seen_ids:
                                continue
                            if self._baseline_highest_numeric_id is not None and mid.isdecimal() and int(mid) <= self._baseline_highest_numeric_id:
                                continue
                            self._seen_ids.add(mid)
                        code = self._extract_code(m)
                        if code and code not in exclude:
                            self._log("邮箱已收到验证码（内容不写入日志）")
                            return code
            except Exception:
                self._log("    ⏳ 邮箱拉取暂不可达，重试中")
            time.sleep(3)
        return ""

    # 兼容老调用方（如 RefreshTokenRegistrationEngine.email_service.get_verification_code）
    get_verification_code = wait_for_verification_code


class _OAuthMailContextEmailAdapter:
    """Adapt an existing OAuth mail context for the browser flow.

    Provider credentials stay in memory. A mailbox baseline is captured before
    OpenAI sends a new code so a stale registration OTP is not reused.
    """

    def __init__(self, mail_ctx: dict, log_fn) -> None:
        self._mail_ctx = dict(mail_ctx or {})
        self._log = log_fn or (lambda _msg: None)
        self._used_codes: set[str] = set()
        self._baseline_ids: set = set()
        self._baseline_ready = False
        self._provider_adapter = None
        provider = str(self._mail_ctx.get("provider") or "").strip().lower()
        if provider in {"outlook", "icloud", "qqmail", "gmail"}:
            from platforms.chatgpt.gpt_pro_login import (
                GptProEmailAdapterForCodexOAuth,
                build_mailbox_for_account,
            )

            mailbox_extra = dict(self._mail_ctx)
            mailbox_extra["mail_provider"] = provider
            if provider == "outlook":
                mailbox_extra["outlook_mail_refresh_token"] = self._mail_ctx.get("refresh_token", "")
                mailbox_extra["outlook_mail_client_id"] = self._mail_ctx.get("client_id", "")
                mailbox_extra["outlook_mail_access_type"] = self._mail_ctx.get("mail_access_type") or "graph"
            mailbox, mail_account = build_mailbox_for_account(mailbox_extra)
            self._provider_adapter = GptProEmailAdapterForCodexOAuth(
                mailbox, mail_account, log_fn=self._log,
            )
            self._baseline_ready = self._provider_adapter.prepare_for_verification() is True
        else:
            # Preserve the old constructor snapshot, but never mark a failed
            # read as an empty successful baseline.  Navigation prepares fresh
            # IDs again; waiting for a challenge must not recapture them.
            self.prepare_for_verification()

    def prepare_for_verification(self) -> bool:
        from platforms.chatgpt.generate_oauth_json_protocol import _collect_existing_mail_ids

        self._baseline_ready = False
        try:
            if self._provider_adapter is not None:
                self._baseline_ready = self._provider_adapter.prepare_for_verification() is True
            else:
                baseline = _collect_existing_mail_ids(self._mail_ctx, strict=True)
                self._baseline_ids = set(baseline)
                self._baseline_ready = True
            return self._baseline_ready
        except Exception:
            self._log("[OAuth 邮箱适配器] 无法建立新邮件基线，追加邮箱验证暂不可用")
            return False

    def wait_for_verification_code(
        self,
        email=None,
        timeout=120,
        otp_sent_at=None,
        exclude_codes=None,
        **kwargs,
    ) -> str:
        from platforms.chatgpt.generate_oauth_json_protocol import _fetch_otp

        _ = kwargs
        expected_email = str(self._mail_ctx.get("email") or "").strip().lower()
        if str(email or expected_email).strip().lower() != expected_email or not self._baseline_ready:
            return ""
        self._used_codes.update(str(code) for code in (exclude_codes or set()) if code)
        if self._provider_adapter is not None:
            code = self._provider_adapter.wait_for_verification_code(
                email=expected_email,
                timeout=timeout,
                otp_sent_at=otp_sent_at,
                exclude_codes=self._used_codes,
            )
        else:
            code = _fetch_otp(
                self._mail_ctx,
                self._used_codes,
                timeout_seconds=max(5, int(timeout or 120)),
                skip_mail_ids=self._baseline_ids,
            )
        if not code:
            return ""
        code = str(code).strip()
        self._used_codes.add(code)
        self._log("[OAuth 邮箱适配器] 已收到新验证码（内容不写入日志）")
        return code

    get_verification_code = wait_for_verification_code


@register
class ChatGPTPlatform(BasePlatform):
    name = "chatgpt"
    display_name = "ChatGPT"
    version = "1.0.0"
    supported_executors = ["protocol", "headless", "headed", "refresh_token", "oauth", "rt"]

    def __init__(self, config: RegisterConfig = None, mailbox: BaseMailbox = None):
        super().__init__(config)
        self.mailbox = mailbox

    def check_valid(self, account: Account) -> bool:
        try:
            from platforms.chatgpt.payment import check_subscription_status

            class _A:
                pass

            a = _A()
            extra = account.extra or {}
            a.access_token = extra.get("access_token") or account.token
            a.cookies = extra.get("cookies", "")
            status = check_subscription_status(a, proxy=self.config.proxy if self.config else None)
            return status not in ("expired", "invalid", "banned", None)
        except Exception:
            return False

    def register(self, email: str = None, password: str = None) -> Account:
        """Register first, then finalize password/TOTP using the new session.

        Security setup is fail-soft: a successfully created remote account is
        always returned and saved even if the settings UI changes or the fresh
        session cannot be reused.  The persisted state then exposes an explicit
        retry action instead of losing/re-registering the account.
        """
        # One platform instance can be reused by task runners.  Never let a
        # previous registration's mailbox closure leak into the next account.
        self._chatgpt_password_link_provider = None
        self._chatgpt_password_code_provider = None
        account = self._register_without_security(email=email, password=password)
        checkpoint = getattr(self.mailbox, "checkpoint_remote_registration", None)
        if callable(checkpoint):
            checkpoint(account)
        if getattr(self.mailbox, "_claim", None) and (self.config.extra or {}).get("mail_provider") == "gmail":
            setattr(account, "_gmail_registration_owned", True)
        return self._finalize_registration_security(account)

    def resume_gmail_registration(self, account: Account) -> Account:
        """Resume only the unfinished security stage of a persisted identity."""
        if getattr(self.mailbox, "_claim", None):
            setattr(account, "_gmail_registration_owned", True)
        self._chatgpt_password_link_provider, self._chatgpt_password_code_provider = (
            self._build_persisted_security_mail_providers(
                account, proxy=(self.config.proxy if self.config else None) or "",
                log_fn=getattr(self, "_log_fn", print),
            )
        )
        return self._finalize_registration_security(account)

    def _finalize_registration_security(self, account: Account) -> Account:
        extra_config = (
            dict(self.config.extra or {})
            if self.config and getattr(self.config, "extra", None)
            else {}
        )
        password_link_provider = getattr(
            self,
            "_chatgpt_password_link_provider",
            None,
        )
        password_code_provider = getattr(
            self,
            "_chatgpt_password_code_provider",
            None,
        )
        if (
            not callable(extra_config.get("_chatgpt_password_link_provider"))
            and callable(password_link_provider)
        ):
            # Process-local callback only.  It is consumed by account_security
            # and never attached to Account.extra or a serialized response.
            extra_config["_chatgpt_password_link_provider"] = (
                password_link_provider
            )
        if (
            not callable(extra_config.get("_chatgpt_password_code_provider"))
            and callable(password_code_provider)
        ):
            extra_config["_chatgpt_password_code_provider"] = (
                password_code_provider
            )
        log_fn = getattr(self, "_log_fn", print)
        try:
            from platforms.chatgpt.account_security import finalize_registered_platform_account

            return finalize_registered_platform_account(
                account,
                config=extra_config,
                proxy=(self.config.proxy if self.config else None) or "",
                browser_mode=(self.config.executor_type if self.config else "protocol"),
                log_fn=log_fn,
            )
        except Exception as exc:
            # Do not discard a real registration because local credential
            # persistence/browser setup failed.  No raw credential is included
            # in this status or log message.
            from platforms.chatgpt.account_security import _safe_error

            safe_error = _safe_error(exc, 180)
            if isinstance(getattr(account, "extra", None), dict):
                account.extra["chatgpt_security"] = {
                    "password_state": "unknown",
                    "mfa_state": "failed",
                    "has_password": bool(getattr(account, "password", "")),
                    "has_totp": False,
                    "error": f"注册后安全设置异常: {safe_error}",
                }
            log_fn(f"[账号安全] 注册已完成，但密码/2FA 保存流程异常: {safe_error}")
            return account

    @staticmethod
    def _capture_registration_mail_baseline(mailbox, mail_account, *, require_strict: bool = False) -> set:
        """Capture a strict baseline when password-action mail is supported.

        Message IDs are provider-owned opaque values.  In particular QQMail's
        IMAP implementation returns byte UIDs and later subtracts those same
        byte values from the current UID set.  Converting them to strings here
        makes ``b"493"`` and ``"b'493'"`` different IDs, so every historical
        message appears new and an expired OTP can be selected.
        """
        supports_action_link = callable(
            getattr(mailbox, "wait_for_action_link", None)
        )
        strict_getter = getattr(mailbox, "get_action_link_baseline", None)
        use_strict_getter = supports_action_link or (require_strict and callable(strict_getter))
        getter = strict_getter if use_strict_getter else getattr(mailbox, "get_current_ids", None)
        if supports_action_link and not callable(getter):
            raise RuntimeError("邮箱不支持安全的密码邮件基线")
        if not callable(getter):
            if require_strict:
                raise RuntimeError("邮箱不支持安全的密码邮件基线")
            return set()
        try:
            if use_strict_getter:
                result = getter(mail_account)
            else:
                # Inspect before calling: a TypeError raised inside a provider
                # is a failed snapshot, never permission to retry non-strictly.
                parameters = inspect.signature(getter).parameters
                strict_parameter = parameters.get("strict")
                explicit_strict = strict_parameter is not None and strict_parameter.kind in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
                if require_strict and not explicit_strict:
                    raise RuntimeError("邮箱不支持严格的新邮件基线")
                accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())
                if explicit_strict or accepts_kwargs:
                    result = getter(mail_account, strict=True)
                else:
                    result = getter(mail_account)
            if not isinstance(result, (set, frozenset, list, tuple)):
                raise RuntimeError("密码邮件基线响应格式错误")
            return {item for item in result if item not in (None, "")}
        except Exception:
            # The provider response may contain credentials.  Keep the public
            # failure explicit but intentionally discard the raw exception.
            raise RuntimeError("无法建立密码邮件基线，已阻止本次注册") from None

    def _build_password_mail_providers(
        self,
        mailbox,
        mail_account,
        *,
        before_ids: set | None = None,
        not_before: float | None = None,
        log_fn=None,
    ) -> tuple[object | None, object | None]:
        """Build account-local password link/code readers.

        The returned callables close over only ``mailbox`` and ``mail_account``.
        In particular, they are not resolved through mutable platform-instance
        attributes when invoked.  That matters for manual actions, where several
        accounts can run concurrently on the same worker process.
        """
        wait_for_action_link = getattr(mailbox, "wait_for_action_link", None)
        wait_for_code = getattr(mailbox, "wait_for_code", None)
        if mail_account is None or not (
            callable(wait_for_action_link) or callable(wait_for_code)
        ):
            return None, None
        baseline_ids = None if before_ids is None else set(before_ids)
        if baseline_ids is None and callable(wait_for_action_link):
            try:
                baseline_ids = self._capture_registration_mail_baseline(
                    mailbox,
                    mail_account,
                )
            except Exception:
                if callable(log_fn):
                    log_fn("[账号安全] 无法建立密码邮件基线，已停止安全设置")
                raise
        baseline_at = float(not_before or time.time())
        expected_email = str(getattr(mail_account, "email", "") or "").strip().lower()

        password_link_provider = None
        if callable(wait_for_action_link):
            def provide_password_link(*, email: str = "", timeout: int = 120) -> str:
                requested_email = str(email or "").strip().lower()
                if not expected_email or requested_email != expected_email:
                    return ""
                return str(
                    wait_for_action_link(
                        mail_account,
                        timeout=timeout,
                        before_ids=set(baseline_ids or set()),
                        not_before=baseline_at,
                    )
                    or ""
                ).strip()

            password_link_provider = provide_password_link

        # Newer settings builds ask for a fresh email OTP before exposing the
        # password form.  Capture that OTP's message-ID baseline immediately
        # before the password action is triggered, not before registration,
        # otherwise the signup OTP could be reused by mistake.
        code_state = {"before_ids": None}
        code_state_lock = threading.Lock()

        password_code_provider = None
        if callable(wait_for_code):
            def provide_password_code(
                *,
                email: str = "",
                timeout: int = 120,
                prepare: bool = False,
                exclude_codes=None,
            ) -> str | dict[str, bool]:
                requested_email = str(email or "").strip().lower()
                if not expected_email or requested_email != expected_email:
                    return ""
                if prepare:
                    # A failed refresh invalidates the previous challenge's
                    # baseline, so a later read cannot silently reuse it.
                    with code_state_lock:
                        code_state["before_ids"] = None
                    fresh_baseline = ChatGPTPlatform._capture_registration_mail_baseline(
                        mailbox,
                        mail_account,
                        require_strict=True,
                    )
                    with code_state_lock:
                        code_state["before_ids"] = set(fresh_baseline)
                    return {"baseline_ready": True, "strict": True}
                with code_state_lock:
                    fresh_baseline = code_state.get("before_ids")
                if fresh_baseline is None:
                    raise RuntimeError("密码验证码邮件基线尚未建立")
                return str(
                    wait_for_code(
                        mail_account,
                        keyword="",
                        timeout=max(1, int(timeout or 0)),
                        before_ids=set(fresh_baseline),
                        exclude_codes=set(exclude_codes or set()),
                    )
                    or ""
                ).strip()

            password_code_provider = provide_password_code

        return password_link_provider, password_code_provider

    def _prepare_password_link_provider(
        self,
        mailbox,
        mail_account,
        *,
        before_ids: set | None = None,
        not_before: float | None = None,
        log_fn=None,
    ) -> tuple[object | None, object | None]:
        """Compatibility bridge for the registration finalizer.

        Registration currently hands the readers to its finalizer through
        short-lived instance attributes.  Build them locally first so callers
        such as manual security setup can use the same implementation without
        touching those mutable attributes.
        """
        providers = self._build_password_mail_providers(
            mailbox,
            mail_account,
            before_ids=before_ids,
            not_before=not_before,
            log_fn=log_fn,
        )
        (
            self._chatgpt_password_link_provider,
            self._chatgpt_password_code_provider,
        ) = providers
        return providers

    def _restore_security_mailbox(self, account: Account, proxy: str, log_fn):
        """Recreate the exact persisted mailbox for a manual security action.

        ``get_email()`` must never be called here: doing so would allocate a
        different address from a provider pool.  Outlook credentials are also
        deliberately namespaced so an OpenAI refresh token cannot be mistaken
        for a Microsoft mail refresh token.
        """
        from core.base_mailbox import MailboxAccount, create_mailbox

        account_extra = dict(account.extra or {})
        provider = str(
            account_extra.get("mail_provider")
            or account_extra.get("provider")
            or ""
        ).strip().lower()
        register_mode = str(account_extra.get("register_mode") or "").strip().lower()
        if not provider and "outlook" in register_mode:
            provider = "outlook"
        elif not provider and "cfworker" in register_mode:
            provider = "cfworker"
        if not provider and any(
            account_extra.get(key)
            for key in (
                _OUTLOOK_MAIL_PASSWORD_KEY,
                _OUTLOOK_MAIL_CLIENT_ID_KEY,
                _OUTLOOK_MAIL_REFRESH_TOKEN_KEY,
            )
        ):
            provider = "outlook"
        if not provider:
            return None, None

        config_extra = (
            dict(self.config.extra or {})
            if self.config and getattr(self.config, "extra", None)
            else {}
        )
        config_extra.update(account_extra)
        config_extra["platform"] = "chatgpt"
        config_extra["_platform"] = "chatgpt"
        if provider == "gmail":
            config_extra.update(gmail_fixed_account=True, email=account.email)

        mailbox_provider = "qqmail" if provider in {"icloud", "qqmail"} else provider
        supported_providers = {
            "gmail",
            "applemail",
            "cfworker",
            "cloudmail",
            "duckmail",
            "freemail",
            "gptmail",
            "laoudo",
            "luckmail",
            "maliapi",
            "moemail",
            "opentrashmail",
            "outlook",
            "qqmail",
            "skymail",
            "tempmail_lol",
        }
        if mailbox_provider not in supported_providers:
            return None, None
        if mailbox_provider == "outlook":
            credentials = _outlook_mail_credentials(account_extra)
            if not credentials["password"] and not (
                credentials["client_id"] and credentials["refresh_token"]
            ):
                raise RuntimeError(
                    "当前账号缺少可用的 Outlook 邮箱凭证，无法读取密码设置验证码"
                )
            mail_access_type = credentials["mail_access_type"]
            if not mail_access_type and (
                credentials["client_id"] and credentials["refresh_token"]
            ):
                mail_access_type = "graph"
            mail_extra = {
                "provider": "outlook",
                _OUTLOOK_MAIL_PASSWORD_KEY: credentials["password"],
                _OUTLOOK_MAIL_CLIENT_ID_KEY: credentials["client_id"],
                _OUTLOOK_MAIL_REFRESH_TOKEN_KEY: credentials["refresh_token"],
                _OUTLOOK_MAIL_ACCESS_TYPE_KEY: mail_access_type,
                "graph_immutable_ids": bool(
                    account_extra.get("graph_immutable_ids")
                )
            }
        else:
            # Other existing providers already read their own namespaced
            # configuration.  Keep the exact address and persisted mailbox
            # token while allowing global provider settings (API URL/key) to
            # fill fields intentionally not duplicated per account.
            mail_extra = dict(account_extra)
            mail_extra["provider"] = mailbox_provider

        mailbox = create_mailbox(
            mailbox_provider,
            extra=config_extra,
            proxy=proxy or None,
        )
        mailbox._log_fn = log_fn
        task_control = getattr(self, "_task_control", None)
        if task_control is not None:
            mailbox._task_control = task_control

        mailbox_account_id = ""
        for key in (
            "mailbox_token",
            "mailbox_account_id",
            "mail_account_id",
            f"{mailbox_provider}_account_id",
        ):
            value = str(account_extra.get(key) or "").strip()
            if value:
                mailbox_account_id = value
                break
        mail_account = MailboxAccount(
            email=str(account.email or "").strip(),
            account_id=mailbox_account_id,
            extra=mail_extra,
        )
        return mailbox, mail_account

    def _build_persisted_security_mail_providers(
        self,
        account: Account,
        *,
        proxy: str = "",
        log_fn=None,
    ) -> tuple[object | None, object | None]:
        """Return isolated mail readers for one persisted account."""
        mailbox, mail_account = self._restore_security_mailbox(
            account,
            proxy,
            log_fn,
        )
        if mailbox is None or mail_account is None:
            return None, None
        try:
            return self._build_password_mail_providers(
                mailbox,
                mail_account,
                not_before=time.time(),
                log_fn=log_fn,
            )
        except Exception:
            # Provider exceptions can contain authorization details.  Keep the
            # manual action actionable without echoing the raw exception.
            raise RuntimeError(
                "无法读取该账号邮箱，未能建立密码验证码邮件基线"
            ) from None

    def _preserve_registration_mailbox(
        self,
        target_extra: dict,
        provider: str,
        mailbox,
        mail_account,
        *,
        before_ids: set | None = None,
        not_before: float | None = None,
        log_fn=None,
    ) -> None:
        """Persist namespaced mail metadata and prepare a one-shot link reader."""
        if isinstance(getattr(mail_account, "extra", None), dict):
            safe_mail_extra = _mailbox_extra_for_account(
                provider,
                mail_account.extra,
            )
            target_extra.update(safe_mail_extra)
        self._prepare_password_link_provider(
            mailbox,
            mail_account,
            before_ids=before_ids,
            not_before=not_before,
            log_fn=log_fn,
        )

    def _register_without_security(self, email: str = None, password: str = None) -> Account:
        if not password:
            password = generate_random_password()

        proxy = self.config.proxy if self.config else None
        extra_config = (self.config.extra or {}) if self.config and getattr(self.config, "extra", None) else {}
        log_fn = getattr(self, "_log_fn", print)

        mail_provider = extra_config.get("mail_provider", "")
        business_domain = (extra_config.get("business_domain") or "").strip().lower()
        executor_type = (self.config.executor_type if self.config else "protocol") or "protocol"
        # token 方案:rt / refresh_token / oauth → 用 OAuth PKCE 拿真实 refresh_token
        chatgpt_mode = str(extra_config.get("chatgpt_registration_mode") or "").strip().lower()
        wants_refresh_token = chatgpt_mode in ("rt", "refresh_token", "oauth") or \
            str(extra_config.get("chatgpt_has_refresh_token_solution") or "").strip().lower() in ("1", "true", "yes")

        # 自动从代理订阅池获取代理（如果没有手动指定）
        if not proxy and extra_config.get("register_auto_use_proxy", "1") in ("1", "true", "yes"):
            proxy = self._pick_subscription_proxy()
            if proxy:
                log_fn(f"[代理池] 自动选择节点: {_redact_proxy_for_log(proxy)}")

        executor_type = self.config.executor_type if self.config else "protocol"

        # ── BUSINESS 模式(优先 OAuth PKCE,降级到 signup 协议) ──
        if business_domain:
            if wants_refresh_token:
                # 长跑感模式:phase 2/3 失败不打断,账号入对应状态留 RT 长跑界面救援。
                # 由设备补号(CPA/SUB+BUSINESS+RT)经 _build_device_register_extra 触发。
                long_run = str(extra_config.get("_business_long_run_mode") or "").strip() == "1"
                account = self._register_business_oauth(
                    business_domain, password, proxy, extra_config, log_fn,
                    raise_on_failure=not long_run,
                )
                if long_run and account is not None:
                    # 给上传链路用:标记这个号"归属哪个设备",上传失败时留 DB,
                    # 下次同设备补号优先处理(c 方案)
                    dev_id = str(extra_config.get("_sync_device_id") or "").strip()
                    if dev_id and isinstance(account.extra, dict):
                        account.extra["assigned_device_id"] = dev_id
                return account
            return self._register_business_protocol(business_domain, password, proxy, extra_config, log_fn)

        # ── Outlook: protocol 走纯协议，headless/headed 仍走 DrissionPage ──
        if mail_provider == "outlook":
            if executor_type in ("refresh_token", "oauth", "rt"):
                return self._register_custom_provider_oauth(email, password, proxy, extra_config, log_fn)
            if executor_type == "protocol":
                return self._register_outlook_protocol(email, password, proxy, extra_config, log_fn)
            return self._register_drission(email, password, proxy, extra_config, log_fn)

        # ── CF Worker: 根据 executor_type 选择协议或浏览器 ──
        if mail_provider == "cfworker":
            if executor_type == "protocol":
                return self._register_cfworker_protocol(email, password, proxy, extra_config, log_fn)
            if executor_type in ("refresh_token", "oauth", "rt"):
                return self._register_cfworker_oauth(email, password, proxy, extra_config, log_fn)
            return self._register_drission(email, password, proxy, extra_config, log_fn)

        if mail_provider == "gmail":
            return self._register_custom_provider_oauth(email, password, proxy, extra_config, log_fn)

        if self.mailbox and (
            executor_type in ("refresh_token", "oauth", "rt")
            or "chatgpt_registration_mode" in extra_config
            or "chatgpt_has_refresh_token_solution" in extra_config
        ):
            return self._register_custom_provider_oauth(email, password, proxy, extra_config, log_fn)

        # ── 其他邮箱 → 纯协议 v2 引擎 ──
        from platforms.chatgpt.protocol_register import ChatGPTProtocolRegister

        reg = ChatGPTProtocolRegister(
            proxy=proxy,
            log_fn=log_fn,
            cookie_dir=extra_config.get("cookie_json_dir", "cookies"),
            browser_bootstrap=False,
        )

        mail_acct = None
        if self.mailbox:
            _mailbox = self.mailbox
            _fixed_email = email

            def _resolve_email(candidate_email: str = "") -> str:
                resolved_email = str(_fixed_email or candidate_email or "").strip()
                if not resolved_email:
                    raise RuntimeError("邮箱地址为空")
                return resolved_email

            mail_acct = _mailbox.get_email()
            current_email = _resolve_email(getattr(mail_acct, "email", ""))
            mail_baseline_at = time.time()
            before_ids = self._capture_registration_mail_baseline(
                _mailbox,
                mail_acct,
            )

            otp_timeout = self.get_mailbox_otp_timeout()

            def otp_cb():
                log_fn("等待验证码...")
                code = _mailbox.wait_for_code(
                    mail_acct, keyword="", timeout=otp_timeout, before_ids=before_ids,
                )
                if code:
                    log_fn("已获取验证码（内容不写入日志）")
                return code
        else:
            current_email = email or ""
            otp_cb = None

        if not current_email:
            raise RuntimeError("未获取到邮箱地址")

        result = reg.register(
            email=current_email,
            password=password,
            otp_callback=otp_cb,
        )

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "name": result.get("name", ""),
            "register_mode": "protocol_v2",
        }
        if mail_acct is not None:
            provider_hint = str(
                mail_provider
                or (getattr(mail_acct, "extra", None) or {}).get("provider")
                or ""
            )
            self._preserve_registration_mailbox(
                account_extra,
                provider_hint,
                self.mailbox,
                mail_acct,
                before_ids=before_ids,
                not_before=mail_baseline_at,
                log_fn=log_fn,
            )
        account_extra["password_set_proven"] = bool(
            result.get("password_set_proven", False)
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _pick_subscription_proxy(self) -> str | None:
        try:
            from services.proxy_pool import next_chatgpt_protocol_proxy

            p = next_chatgpt_protocol_proxy()
            if p:
                return p["addr"]
        except Exception:
            pass
        try:
            from services.proxy_pool import next_proxy

            p = next_proxy()
            return p["addr"] if p else None
        except Exception:
            return None

    def _register_custom_provider_oauth(self, email, password, proxy, extra_config, log_fn) -> Account:
        """使用通用邮箱适配 OAuth/RT 注册模式。"""
        from enum import Enum

        if not self.mailbox:
            raise RuntimeError("邮箱实例未初始化")

        _mailbox = self.mailbox
        if extra_config.get("mail_provider") == "gmail":
            _mailbox.registration_started(password=password)
            extra_config = {**extra_config, "_registration_stage_callback": _mailbox.mark_stage}
        _fixed_email = email
        otp_timeout = self.get_mailbox_otp_timeout()

        class _ServiceType(Enum):
            CUSTOM_PROVIDER = "custom_provider"

        class _MailboxEmailService:
            service_type = _ServiceType.CUSTOM_PROVIDER

            def __init__(self_svc):
                self_svc.mail_acct = None
                self_svc.email = ""
                self_svc.before_ids = set()
                self_svc.baseline_at = None

            def create_email(self_svc):
                if self_svc.mail_acct is None:
                    self_svc.mail_acct = _mailbox.get_email()
                    self_svc.baseline_at = time.time()
                    self_svc.before_ids = self._capture_registration_mail_baseline(
                        _mailbox,
                        self_svc.mail_acct,
                    )

                resolved_email = str(
                    _fixed_email or getattr(self_svc.mail_acct, "email", "") or ""
                ).strip()
                if not resolved_email:
                    raise RuntimeError("custom_provider 返回空邮箱地址")

                self_svc.email = resolved_email
                return {"email": resolved_email}

            def get_verification_code(
                self_svc,
                email=None,
                timeout=120,
                otp_sent_at=None,
                exclude_codes=None,
            ):
                if self_svc.mail_acct is None:
                    self_svc.create_email()
                if extra_config.get("mail_provider") == "gmail":
                    _mailbox.mark_stage("verification")
                return _mailbox.wait_for_code(
                    self_svc.mail_acct,
                    keyword="",
                    timeout=otp_timeout,
                    before_ids=self_svc.before_ids,
                    otp_sent_at=otp_sent_at,
                    exclude_codes=exclude_codes,
                )

        def _read_int(value, default: int) -> int:
            try:
                parsed = int(value)
            except Exception:
                return default
            return max(1, parsed)

        executor_type = self.config.executor_type if self.config else "protocol"
        browser_mode = executor_type if executor_type in ("protocol", "headless", "headed") else "protocol"
        max_retries = _read_int(
            extra_config.get("register_max_retries", extra_config.get("max_retries", 1)),
            1,
        )
        email_service = _MailboxEmailService()
        adapter = build_chatgpt_registration_mode_adapter(extra_config)
        context = ChatGPTRegistrationContext(
            email_service=email_service,
            proxy_url=proxy,
            callback_logger=log_fn,
            email=email,
            password=password,
            browser_mode=browser_mode,
            max_retries=max_retries,
            extra_config=dict(extra_config),
        )

        if extra_config.get("mail_provider") == "gmail" and extra_config.get("gmail_registration_resume") is True:
            # Both token modes recover an interrupted identity through login.
            from platforms.chatgpt.chatgpt_registration_mode_adapter import RefreshTokenChatGPTRegistrationAdapter
            result = RefreshTokenChatGPTRegistrationAdapter().run(context)
            if getattr(adapter, "mode", "") == "access_token_only":
                result.refresh_token = ""
        else:
            result = adapter.run(context)
        if not getattr(result, "success", False):
            if (extra_config.get("mail_provider") == "gmail"
                    and getattr(result, "error_code", "") == "user_already_exists"):
                _mailbox.registration_rejected("user_already_exists")
                raise RuntimeError("Gmail 母号已停止生产新子号，后续任务将改选其他可用母号")
            error_message = str(getattr(result, "error_message", "") or "OAuth 注册失败")
            raise RuntimeError(error_message)

        account = adapter.build_account(result, fallback_password=password)
        if isinstance(account, Account):
            account.extra.setdefault("mail_provider", extra_config.get("mail_provider") or "custom_provider")
            self._preserve_registration_mailbox(
                account.extra,
                str(account.extra.get("mail_provider") or "custom_provider"),
                _mailbox,
                email_service.mail_acct,
                before_ids=email_service.before_ids,
                not_before=email_service.baseline_at,
                log_fn=log_fn,
            )
        return account

    def _register_cfworker_protocol(self, email, password, proxy, extra_config, log_fn) -> Account:
        """使用协议引擎 + CF Worker 域名邮箱注册"""
        from platforms.chatgpt.protocol_register import ChatGPTProtocolRegister

        if not self.mailbox:
            raise RuntimeError("CF Worker 邮箱实例未初始化")

        mail_acct = self.mailbox.get_email()
        cfworker_email = str(email or getattr(mail_acct, "email", "") or "").strip()
        if not cfworker_email:
            raise RuntimeError("未获取到 CF Worker 邮箱地址")

        log_fn(f"[协议注册] 使用 CF Worker 域名邮箱: {cfworker_email}")

        _mailbox = self.mailbox
        mail_baseline_at = time.time()
        before_ids = self._capture_registration_mail_baseline(
            _mailbox,
            mail_acct,
        )
        otp_timeout = self.get_mailbox_otp_timeout()

        def otp_cb():
            log_fn("等待验证码...")
            code = _mailbox.wait_for_code(
                mail_acct, keyword="", timeout=otp_timeout, before_ids=before_ids,
            )
            if code:
                log_fn("已获取验证码（内容不写入日志）")
            return code

        reg = ChatGPTProtocolRegister(
            proxy=proxy,
            log_fn=log_fn,
            cookie_dir=extra_config.get("cookie_json_dir", "cookies"),
            browser_bootstrap=False,
        )

        result = reg.register(
            email=cfworker_email,
            password=password,
            otp_callback=otp_cb,
        )

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "name": result.get("name", ""),
            "register_mode": "protocol_cfworker",
            "mail_provider": "cfworker",
            "mailbox_token": str(getattr(mail_acct, "account_id", "") or ""),
            "cfworker_api_url": extra_config.get("cfworker_api_url", ""),
            "cfworker_quick_api_url": extra_config.get("cfworker_quick_api_url", ""),
        }
        self._preserve_registration_mailbox(
            account_extra,
            "cfworker",
            _mailbox,
            mail_acct,
            before_ids=before_ids,
            not_before=mail_baseline_at,
            log_fn=log_fn,
        )
        account_extra["password_set_proven"] = bool(
            result.get("password_set_proven", False)
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _register_outlook_protocol(self, email, password, proxy, extra_config, log_fn) -> Account:
        """使用协议引擎 + Outlook 邮箱池注册。"""
        from platforms.chatgpt.protocol_register import ChatGPTProtocolRegister

        if not self.mailbox:
            raise RuntimeError("Outlook 邮箱池未配置")

        mail_acct = self.mailbox.get_email()
        outlook_email = str(email or getattr(mail_acct, "email", "") or "").strip()
        if not outlook_email:
            raise RuntimeError("未获取到 Outlook 邮箱地址")

        log_fn(f"[协议注册] 使用 Outlook 邮箱注册: {outlook_email}")

        _mailbox = self.mailbox
        mail_baseline_at = time.time()
        before_ids = self._capture_registration_mail_baseline(
            _mailbox,
            mail_acct,
        )
        otp_timeout = self.get_mailbox_otp_timeout()

        def otp_cb():
            log_fn("等待验证码...")
            code = _mailbox.wait_for_code(
                mail_acct,
                keyword="",
                timeout=otp_timeout,
                before_ids=before_ids,
            )
            if code:
                log_fn("已获取验证码（内容不写入日志）")
            return code

        reg = ChatGPTProtocolRegister(
            proxy=proxy,
            log_fn=log_fn,
            cookie_dir=extra_config.get("cookie_json_dir", "cookies"),
            browser_bootstrap=False,
        )

        result = reg.register(
            email=outlook_email,
            password=password,
            otp_callback=otp_cb,
        )

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "name": result.get("name", ""),
            "register_mode": "protocol_outlook",
            "mail_provider": "outlook",
        }
        self._preserve_registration_mailbox(
            account_extra,
            "outlook",
            _mailbox,
            mail_acct,
            before_ids=before_ids,
            not_before=mail_baseline_at,
            log_fn=log_fn,
        )
        account_extra["password_set_proven"] = bool(
            result.get("password_set_proven", False)
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _register_cfworker_oauth(self, email, password, proxy, extra_config, log_fn) -> Account:
        """使用 OAuth PKCE 引擎 + CF Worker 域名邮箱注册，获取真实 refresh_token"""
        from enum import Enum
        from platforms.chatgpt.refresh_token_registration_engine import RefreshTokenRegistrationEngine

        if not self.mailbox:
            raise RuntimeError("CF Worker 邮箱实例未初始化")

        mail_acct = self.mailbox.get_email()
        cfworker_email = str(email or getattr(mail_acct, "email", "") or "").strip()
        if not cfworker_email:
            raise RuntimeError("未获取到 CF Worker 邮箱地址")

        log_fn(f"[OAuth注册] 使用 CF Worker 域名邮箱: {cfworker_email}")

        _mailbox = self.mailbox
        mail_baseline_at = time.time()
        before_ids = self._capture_registration_mail_baseline(
            _mailbox,
            mail_acct,
        )
        otp_timeout = self.get_mailbox_otp_timeout()

        class _ServiceType(Enum):
            CFWORKER = "cfworker"

        class _MailboxEmailService:
            service_type = _ServiceType.CFWORKER

            def create_email(self_svc):
                return {"email": cfworker_email}

            def get_verification_code(self_svc, email, timeout=120, otp_sent_at=None, exclude_codes=None):
                nonlocal before_ids
                code = _mailbox.wait_for_code(
                    mail_acct, keyword="", timeout=timeout, before_ids=before_ids,
                )
                if code:
                    before_ids = before_ids | {code}
                return code

        engine = RefreshTokenRegistrationEngine(
            email_service=_MailboxEmailService(),
            proxy_url=proxy,
            callback_logger=log_fn,
            browser_mode="protocol",
            max_retries=1,
            extra_config=dict(extra_config),
        )
        engine.email = cfworker_email
        engine.password = password or None
        result = engine.run()

        if not result.success:
            raise RuntimeError(f"OAuth 注册失败: {result.error_message}")

        account_extra = {
            "access_token": result.access_token,
            "refresh_token": result.refresh_token,
            "id_token": result.id_token,
            "session_token": result.session_token,
            "workspace_id": result.workspace_id,
            "register_mode": "oauth_cfworker",
            "mail_provider": "cfworker",
            "chatgpt_registration_mode": "refresh_token",
            "chatgpt_has_refresh_token_solution": True,
            "mailbox_token": str(getattr(mail_acct, "account_id", "") or ""),
            "cfworker_api_url": extra_config.get("cfworker_api_url", ""),
            "cfworker_quick_api_url": extra_config.get("cfworker_quick_api_url", ""),
        }
        self._preserve_registration_mailbox(
            account_extra,
            "cfworker",
            _mailbox,
            mail_acct,
            before_ids=before_ids,
            not_before=mail_baseline_at,
            log_fn=log_fn,
        )
        account_extra["password_set_proven"] = (
            getattr(result, "password_set_proven", False) is True
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result.email,
            password=result.password or password or "",
            user_id=result.account_id,
            token=result.access_token,
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _register_cfworker_protocol(self, email, password, proxy, extra_config, log_fn) -> Account:
        """普通 CF Worker + 协议注册(无浏览器)。从 liunx 分支移植。"""
        from platforms.chatgpt.protocol_register import ChatGPTProtocolRegister

        if not self.mailbox:
            raise RuntimeError("CF Worker 邮箱实例未初始化")

        mail_acct = self.mailbox.get_email()
        cfworker_email = str(email or getattr(mail_acct, "email", "") or "").strip()
        if not cfworker_email:
            raise RuntimeError("未获取到 CF Worker 邮箱地址")

        log_fn(f"[协议注册] 使用 CF Worker 域名邮箱: {cfworker_email}")

        _mailbox = self.mailbox
        mail_baseline_at = time.time()
        before_ids = self._capture_registration_mail_baseline(
            _mailbox,
            mail_acct,
        )
        otp_timeout = self.get_mailbox_otp_timeout()

        def otp_cb():
            log_fn("等待验证码...")
            code = _mailbox.wait_for_code(
                mail_acct, keyword="", timeout=otp_timeout, before_ids=before_ids,
            )
            if code:
                log_fn("已获取验证码（内容不写入日志）")
            return code

        reg = ChatGPTProtocolRegister(
            proxy=proxy,
            log_fn=log_fn,
            cookie_dir=extra_config.get("cookie_json_dir", "cookies"),
            browser_bootstrap=False,
        )

        result = reg.register(
            email=cfworker_email,
            password=password,
            otp_callback=otp_cb,
        )

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "name": result.get("name", ""),
            "register_mode": "protocol_cfworker",
            "mail_provider": "cfworker",
        }
        self._preserve_registration_mailbox(
            account_extra,
            "cfworker",
            _mailbox,
            mail_acct,
            before_ids=before_ids,
            not_before=mail_baseline_at,
            log_fn=log_fn,
        )
        account_extra["password_set_proven"] = bool(
            result.get("password_set_proven", False)
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _register_cfworker_oauth(self, email, password, proxy, extra_config, log_fn) -> Account:
        """普通 CF Worker + OAuth PKCE 注册(无浏览器,输出真实 refresh_token)。从 liunx 移植。"""
        from enum import Enum
        from platforms.chatgpt.refresh_token_registration_engine import RefreshTokenRegistrationEngine

        if not self.mailbox:
            raise RuntimeError("CF Worker 邮箱实例未初始化")

        mail_acct = self.mailbox.get_email()
        cfworker_email = str(email or getattr(mail_acct, "email", "") or "").strip()
        if not cfworker_email:
            raise RuntimeError("未获取到 CF Worker 邮箱地址")

        log_fn(f"[OAuth 注册] 使用 CF Worker 域名邮箱: {cfworker_email}")

        _mailbox = self.mailbox
        mail_baseline_at = time.time()
        before_ids = self._capture_registration_mail_baseline(
            _mailbox,
            mail_acct,
        )
        otp_timeout = self.get_mailbox_otp_timeout()

        class _ServiceType(Enum):
            CFWORKER = "cfworker"

        class _MailboxEmailService:
            service_type = _ServiceType.CFWORKER

            def create_email(self_svc):
                return {"email": cfworker_email}

            def get_verification_code(self_svc, email=None, timeout=120, otp_sent_at=None, exclude_codes=None, **kwargs):
                nonlocal before_ids
                code = _mailbox.wait_for_code(
                    mail_acct, keyword="", timeout=timeout, before_ids=before_ids,
                )
                if code:
                    before_ids = before_ids | {code}
                return code

        engine = RefreshTokenRegistrationEngine(
            email_service=_MailboxEmailService(),
            proxy_url=proxy,
            callback_logger=log_fn,
            browser_mode="protocol",
            max_retries=1,
            extra_config=dict(extra_config),
        )
        engine.email = cfworker_email
        engine.password = password or None
        result = engine.run()

        if not result.success:
            raise RuntimeError(f"OAuth 注册失败: {result.error_message}")

        account_extra = {
            "access_token": result.access_token,
            "refresh_token": result.refresh_token,
            "id_token": result.id_token,
            "session_token": result.session_token,
            "workspace_id": getattr(result, "workspace_id", "") or "",
            "register_mode": "oauth_cfworker",
            "mail_provider": "cfworker",
            "chatgpt_registration_mode": "refresh_token",
            "chatgpt_has_refresh_token_solution": True,
        }
        self._preserve_registration_mailbox(
            account_extra,
            "cfworker",
            _mailbox,
            mail_acct,
            before_ids=before_ids,
            not_before=mail_baseline_at,
            log_fn=log_fn,
        )
        account_extra["password_set_proven"] = (
            getattr(result, "password_set_proven", False) is True
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result.email or cfworker_email,
            password=result.password or password or "",
            user_id=getattr(result, "account_id", "") or "",
            token=result.access_token or "",
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _persist_account(self, account: Account, log_fn=None) -> bool:
        """幂等保存账号到 DB（按 platform+email upsert）。返回是否成功。"""
        try:
            from core.db import save_account as _save_account
            _save_account(account)
            return True
        except Exception as exc:
            if log_fn:
                log_fn(f"❌ 落库失败: {exc}")
            return False

    def _mark_rt_failed(self, account: Account, exc: Exception, log_fn=None) -> bool:
        """RT 获取失败：retry_count++、状态保持 PENDING_RT、写错误原因、落库。"""
        from datetime import datetime, timezone
        merged = dict(account.extra or {})
        merged["chatgpt_registration_mode"] = "refresh_token"
        merged["chatgpt_has_refresh_token_solution"] = True
        merged["register_mode"] = "oauth_business"
        merged["rt_acquisition_failed"] = True
        merged["rt_acquisition_error"] = str(exc)[:500]
        merged["rt_retry_count"] = int(merged.get("rt_retry_count") or 0) + 1
        merged["last_rt_attempt_at"] = datetime.now(timezone.utc).isoformat()
        account.extra = merged
        account.status = AccountStatus.PENDING_RT
        return self._persist_account(account, log_fn)

    def _mark_seat_failed(self, account: Account, reason: str, log_fn=None) -> bool:
        """Codex 席位切换失败：retry_count++、状态保持 PENDING_SEAT_SWITCH、写错误原因、落库。"""
        from datetime import datetime, timezone
        merged = dict(account.extra or {})
        merged["seat_switch_error"] = str(reason)[:500]
        merged["seat_retry_count"] = int(merged.get("seat_retry_count") or 0) + 1
        merged["last_seat_attempt_at"] = datetime.now(timezone.utc).isoformat()
        account.extra = merged
        account.status = AccountStatus.PENDING_SEAT_SWITCH
        return self._persist_account(account, log_fn)

    def _apply_rt_success(self, account: Account, rt_extra: dict) -> None:
        """RT 拿到后：合并 rt_extra 到 account.extra，清掉失败标记。"""
        merged = dict(account.extra or {})
        merged.update({k: v for k, v in rt_extra.items() if v})
        merged["chatgpt_registration_mode"] = "refresh_token"
        merged["chatgpt_has_refresh_token_solution"] = True
        merged["register_mode"] = "oauth_business"
        merged.pop("rt_acquisition_failed", None)
        merged.pop("rt_acquisition_error", None)
        account.extra = merged
        if rt_extra.get("access_token"):
            account.token = rt_extra["access_token"]

    def _iter_rt_retry_proxy_candidates(self, extra_config: dict,
                                        original_proxy) -> list[tuple[str, str]]:
        """收集 RT 失败后可尝试的备用代理；最终是否可用由预检决定。"""
        extra_config = extra_config or {}
        seen = {_proxy_compare_key(original_proxy)}
        candidates: list[tuple[str, str]] = []

        def add(proxy, source: str) -> None:
            try:
                from core.proxy_utils import normalize_proxy_url

                value = normalize_proxy_url(proxy)
            except Exception:
                value = str(proxy or "").strip() or None
            if not value:
                return
            key = _proxy_compare_key(value)
            if not key or key in seen:
                return
            seen.add(key)
            candidates.append((value, source))

        try:
            from core.config_store import config_store as _cs
        except Exception:
            _cs = None

        for key in (
            "business_rt_retry_proxy",
            "business_rt_retry_proxy_urls",
            "rt_retry_proxy",
            "rt_retry_proxy_urls",
        ):
            for value in _split_proxy_values(extra_config.get(key)):
                add(value, f"任务配置.{key}")
            if _cs is not None:
                try:
                    for value in _split_proxy_values(_cs.get(key, "")):
                        add(value, f"全局配置.{key}")
                except Exception:
                    pass

        auto_use = str(
            extra_config.get("register_auto_use_proxy")
            or (_cs.get("register_auto_use_proxy", "1") if _cs is not None else "1")
            or "1"
        ).strip().lower() in {"1", "true", "yes", "on"}

        for key, source in (("proxy", "全局配置.proxy"), ("default_proxy", "全局配置.default_proxy")):
            value = extra_config.get(key)
            if not value and _cs is not None:
                try:
                    value = _cs.get(key, "")
                except Exception:
                    value = ""
            add(value, source)

        if not auto_use:
            return candidates

        try:
            from core.dynamic_proxy import borrow_dynamic_proxy

            for _ in range(3):
                picked = borrow_dynamic_proxy()
                if picked:
                    add(picked, "动态住宅代理(711proxy rotating)")
                    break
        except Exception:
            pass

        try:
            from core.proxy_pool import proxy_pool

            for _ in range(6):
                picked = proxy_pool.get_next()
                if picked:
                    add(picked, "代理管理.DB")
        except Exception:
            pass

        try:
            from services.proxy_pool import next_chatgpt_protocol_proxy

            for _ in range(12):
                item = next_chatgpt_protocol_proxy(skip_addr=str(original_proxy or ""))
                if not item:
                    break
                name = str(item.get("name") or "anonymous").strip()
                add(item.get("addr"), f"ChatGPT协议预检池:{name}")
        except Exception:
            pass

        try:
            from services.proxy_pool import next_proxy as _sub_next

            for _ in range(8):
                item = _sub_next()
                if not item:
                    break
                name = str(item.get("name") or "anonymous").strip()
                add(item.get("addr"), f"订阅代理池:{name}")
        except Exception:
            pass

        return candidates

    def _pick_prechecked_rt_retry_proxy(self, extra_config: dict, original_proxy,
                                        log_fn, context: str) -> tuple[str, str] | None:
        """RT 失败后挑一个通过 chatgpt.com + csrf 预检的备用代理。"""
        extra_config = extra_config or {}
        try:
            from core.config_store import config_store as _cs
        except Exception:
            _cs = None

        def cfg_value(key: str, default: str = "") -> str:
            value = extra_config.get(key)
            if value not in (None, ""):
                return str(value)
            if _cs is not None:
                try:
                    value = _cs.get(key, "")
                    if value not in (None, ""):
                        return str(value)
                except Exception:
                    pass
            return default

        live_probe = str(cfg_value("business_rt_retry_live_probe", "0")).strip().lower() in {
            "1", "true", "yes", "on",
        }
        try:
            timeout = int(cfg_value("business_rt_retry_proxy_probe_timeout", "8"))
        except Exception:
            timeout = 8
        try:
            max_candidates = int(cfg_value("business_rt_retry_proxy_max_candidates", "8"))
        except Exception:
            max_candidates = 8
        timeout = max(3, min(20, timeout))
        max_candidates = max(1, min(20, max_candidates))

        try:
            from services.proxy_pool import probe_chatgpt_protocol_proxy
        except Exception as exc:
            log_fn(f"{context} [RT 2/2] 代理预检模块不可用: {_brief_error(exc)}")
            return None

        candidates = self._iter_rt_retry_proxy_candidates(extra_config, original_proxy)
        if not candidates:
            log_fn(f"{context} [RT 2/2] 没有可用备用代理,按原逻辑落 pending_rt")
            return None

        for proxy, source in candidates:
            if str(source or "").startswith("ChatGPT协议预检池:"):
                log_fn(
                    f"{context} [RT 2/2] 使用已有预检池代理: "
                    f"{_redact_proxy_for_log(proxy)} (来源: {source}),跳过现场慢预检"
                )
                return proxy, source

        for proxy, source in candidates:
            if str(source or "").startswith("动态住宅代理("):
                log_fn(
                    f"{context} [RT 2/2] 使用动态住宅备用代理: "
                    f"{_redact_proxy_for_log(proxy)} (来源: {source}),跳过现场慢预检"
                )
                return proxy, source

        if not live_probe:
            log_fn(
                f"{context} [RT 2/2] 未启用现场代理预检,且没有已有 ChatGPT 协议预检池代理,"
                "跳过备用代理重试"
            )
            return None

        checked = 0
        for proxy, source in candidates:
            if checked >= max_candidates:
                break
            checked += 1
            safe_proxy = _redact_proxy_for_log(proxy)
            log_fn(
                f"{context} [RT 2/2] 候选代理 {checked}/{min(len(candidates), max_candidates)}: "
                f"{safe_proxy} (来源: {source}),预检 chatgpt.com + csrf"
            )
            probe = probe_chatgpt_protocol_proxy(proxy, timeout=timeout, cache_ttl=60)
            if probe.get("ok"):
                log_fn(
                    f"{context} [RT 2/2] 代理预检通过: "
                    f"home={probe.get('home_status') or probe.get('status')}, "
                    f"csrf={probe.get('csrf_status') or probe.get('status')}, "
                    f"latency={probe.get('latency') or 0}ms"
                )
                return proxy, source
            reason = probe.get("error") or f"HTTP {probe.get('status') or 0}"
            log_fn(
                f"{context} [RT 2/2] 代理预检失败: {safe_proxy},"
                f"原因: {_brief_error(reason, 120)}"
            )

        log_fn(f"{context} [RT 2/2] 未找到预检通过的备用代理,按原逻辑落 pending_rt")
        return None

    def _acquire_rt_via_oauth_login_with_retry(self, email: str, password: str,
                                               proxy: str, extra_config: dict,
                                               log_fn, context: str = "[BUSINESS RT]") -> dict:
        """RT 获取：先用原注册代理；风控/网络类失败后换一个预检通过代理再试一次。"""
        safe_proxy = _redact_proxy_for_log(proxy)
        log_fn(f"{context} [RT 1/2] 使用原注册代理: {safe_proxy}")
        try:
            return self._acquire_rt_via_oauth_login(
                email, password, proxy, extra_config, log_fn,
            )
        except Exception as first_exc:
            log_fn(f"{context} [RT 1/2] ✗ 失败: {_brief_error(first_exc)}")
            if not _is_rt_proxy_retryable_error(first_exc):
                log_fn(f"{context} [RT 2/2] 非代理/风控类错误,不换代理重试")
                raise

            picked = self._pick_prechecked_rt_retry_proxy(
                extra_config, proxy, log_fn, context,
            )
            if not picked:
                raise

            retry_proxy, retry_source = picked
            log_fn(
                f"{context} [RT 2/2] 使用备用代理重试: "
                f"{_redact_proxy_for_log(retry_proxy)} (来源: {retry_source})"
            )
            try:
                rt_extra = self._acquire_rt_via_oauth_login(
                    email, password, retry_proxy, extra_config, log_fn,
                )
                log_fn(f"{context} [RT 2/2] ✓ 备用代理重试成功")
                return rt_extra
            except Exception as second_exc:
                log_fn(f"{context} [RT 2/2] ✗ 失败: {_brief_error(second_exc)}")
                raise RuntimeError(
                    f"{first_exc}; 备用代理重试仍失败: {second_exc}"
                ) from second_exc

    def _register_business_oauth(self, business_domain: str, password: str, proxy: str,
                                  extra_config: dict, log_fn,
                                  raise_on_failure: bool = True) -> Account:
        """BUSINESS +「有 RT」开关：一站式注册 + 拿 RT + 可选切 Codex 席位。

        状态流转（每个 phase 完成立刻入库）：
          phase 1 完成 → status = PENDING_RT
          phase 2 完成 → 不切 Codex 时 status = READY_FOR_EXPORT,否则 status = PENDING_SEAT_SWITCH
          phase 3 完成 → 已切 Codex 时 status = READY_FOR_EXPORT
          phase 4 写 OAuth 文件（READY_FOR_EXPORT 状态下，失败不回退）

        关键顺序（实测必须如此，调换会撞 add_phone）：
          阶段 1：协议注册（保留默认 ChatGPT 席位，不写中间态 oauth_file）
          阶段 2：OAuth 登录拿 RT（此时是 ChatGPT 席位，OpenAI 不强制 add_phone）
          阶段 3：按开关决定是否切 Codex 席位（RT 已颁发，安全切）
          阶段 4：写最终 oauth_file（含 RT）

        raise_on_failure:
          True  → 任一阶段失败 raise RuntimeError（旧任务系统语义,api/tasks.py 走这个）
          False → 任一阶段失败仅记录状态返回 account（长跑模式,services/business_rt_loop.py 走这个）
        """
        switch_codex = _read_switch_codex_flag(extra_config)
        register_only = _read_business_register_only_flag(extra_config)
        log_fn("[BUSINESS RT] 阶段 1/4：协议注册（暂保留 ChatGPT 席位）")
        account = self._register_business_protocol(
            business_domain, password, proxy, extra_config, log_fn,
            skip_oauth_file=True,      # 阶段 4 才写,避免中间态
            skip_codex_switch=True,    # 阶段 3 才切,避免撞 add_phone
        )
        # 阶段 1 内部已在缺 AT 时 raise; 走到这里 access_token 必非空

        # This method owns the first database write for BUSINESS OAuth.  Run
        # password/TOTP setup before publishing a PENDING_RT row; otherwise an
        # auto-RT worker (or a restart between the two calls) can claim an
        # account whose post-registration security setup never ran.
        from platforms.chatgpt.account_security import (
            finalize_registered_platform_account,
        )

        account = finalize_registered_platform_account(
            account,
            config=extra_config,
            proxy=proxy or "",
            browser_mode=str(
                extra_config.get("business_rt_oauth_browser_mode")
                or (self.config.executor_type if self.config else "protocol")
                or "protocol"
            ),
            log_fn=log_fn,
        )

        # phase 1 完成立刻入库为 PENDING_RT（砍掉 "已注册" 中间态）
        account.status = AccountStatus.PENDING_RT
        if not self._persist_account(account, log_fn):
            raise RuntimeError(
                f"BUSINESS 账号 {account.email} 注册完成，但安全状态首次落库失败"
            )
        if register_only:
            log_fn("[BUSINESS RT] 注册阶段完成：已写入 pending_rt，等待 RT 获取长跑处理")
            return account

        # 协议注册结束到 OAuth 登录之间留一段缓冲：workspace 在服务端绑定有传播延迟，
        # 太早发起 OAuth 登录会撞 workspace/select 400（"workspace not found"），
        # 但单独跑「补 RT」action 间隔足够长就一次过。可通过配置项覆盖。
        try:
            phase_wait = float(
                extra_config.get("business_rt_phase_wait_seconds") or 8
            )
        except Exception:
            phase_wait = 8.0
        if phase_wait > 0:
            log_fn(f"[BUSINESS RT] 等待 {phase_wait:.0f}s 让 workspace 在服务端绑定...")
            import time as _t
            _t.sleep(phase_wait)

        log_fn("[BUSINESS RT] 阶段 2/4：OAuth 登录拿 RT")
        try:
            rt_extra = self._acquire_rt_via_oauth_login_with_retry(
                account.email,
                account.password or password or "",
                proxy, extra_config, log_fn,
                context="[BUSINESS RT]",
            )
        except Exception as exc:
            persisted = self._mark_rt_failed(account, exc, log_fn)
            log_fn("[BUSINESS RT] ❌ RT 获取失败，已完成代理重试策略，按原逻辑落 pending_rt")
            log_fn("=" * 56)
            log_fn(f"❌ [失败] 注册成功但 RT 获取失败")
            log_fn(f"❌ 邮箱: {account.email}")
            log_fn(f"❌ RT 获取失败原因: {exc}")
            log_fn(
                f"❌ 状态: pending_rt"
                f"（{'已落库,可点「一键补 RT」' if persisted else '落库失败,无法补 RT'}）"
            )
            log_fn("=" * 56)
            if raise_on_failure:
                suffix = "已落库,可后续补 RT" if persisted else "落库失败,无法补 RT"
                raise RuntimeError(
                    f"RT 获取失败: {exc}; 账号 {account.email} {suffix}"
                )
            return account

        # phase 2 成功：写 RT extra,后续是否切 Codex 完全跟随界面/任务开关。
        self._apply_rt_success(account, rt_extra)
        merged = dict(account.extra or {})
        merged["business_switch_to_codex"] = "1" if switch_codex else "0"
        merged.pop("seat_switch_error", None)
        account.extra = merged
        if not switch_codex:
            account.status = AccountStatus.READY_FOR_EXPORT
            self._persist_account(account, log_fn)
            log_fn("[BUSINESS RT] 阶段 3/4：界面未勾选，跳过 Codex 席位切换")
            log_fn("[BUSINESS RT] 阶段 4/4：写最终 OAuth 文件（含 RT）")
            try:
                self._dump_business_oauth_file(account, extra_config, log_fn)
            except Exception as dump_exc:
                log_fn(f"OAuth 文件生成异常（状态不回退）: {dump_exc}")
            log_fn(
                f"[BUSINESS RT] ✅ 已拿到 RT，非 Codex 席位也已就绪可导出: "
                "RT=已获取（内容不写入日志）"
            )
            return account

        account.status = AccountStatus.PENDING_SEAT_SWITCH
        self._persist_account(account, log_fn)

        log_fn("[BUSINESS RT] 阶段 3/4：拿到 RT，切换 Codex 席位")
        try:
            _switch_business_seat_to_codex(
                account.extra, log_fn, proxy=proxy, enabled=switch_codex,
            )
        except Exception as seat_exc:
            persisted = self._mark_seat_failed(account, seat_exc, log_fn)
            log_fn(f"❌ Codex 席位切换异常: {seat_exc}")
            if raise_on_failure:
                suffix = "已落库,可后续手动切换" if persisted else "落库失败,无法手动切换"
                raise RuntimeError(
                    f"Codex 席位切换失败: 账号 {account.email} 已拿到 RT 但席位仍为 ChatGPT;"
                    f" {suffix}"
                )
            return account
        if (account.extra or {}).get("seat_type") != "usage_based":
            persisted = self._mark_seat_failed(account, "切换后 seat_type 仍不是 usage_based", log_fn)
            if raise_on_failure:
                suffix = "已落库,可后续手动切换" if persisted else "落库失败,无法手动切换"
                raise RuntimeError(
                    f"Codex 席位切换失败: 账号 {account.email} 已拿到 RT 但席位仍为 ChatGPT;"
                    f" {suffix}"
                )
            return account

        # phase 3 成功：状态推进到 READY_FOR_EXPORT 并入库
        account.status = AccountStatus.READY_FOR_EXPORT
        # 清掉残留的席位失败标记
        merged = dict(account.extra or {})
        merged.pop("seat_switch_error", None)
        account.extra = merged
        self._persist_account(account, log_fn)

        log_fn("[BUSINESS RT] 阶段 4/4：写最终 OAuth 文件（含 RT）")
        try:
            self._dump_business_oauth_file(account, extra_config, log_fn)
        except Exception as dump_exc:
            # phase 4 失败不回退状态（READY_FOR_EXPORT 已确定），只记日志
            log_fn(f"OAuth 文件生成异常（状态不回退）: {dump_exc}")
        log_fn("[BUSINESS RT] ✅ 全部完成: RT=已获取（内容不写入日志）")
        return account

    def _acquire_rt_via_oauth_login(self, email: str, password: str, proxy: str,
                                     extra_config: dict, log_fn) -> dict:
        """开全新 OAuth 会话登录已注册账号，返回 {access_token, refresh_token, id_token, session_token}。"""
        from platforms.chatgpt.oauth_client import OAuthClient

        cfworker_api_url = (extra_config.get("cfworker_api_url") or "").strip().rstrip("/")
        cfworker_admin_token = (extra_config.get("cfworker_admin_token") or "").strip()
        cfworker_custom_auth = (extra_config.get("cfworker_custom_auth") or "").strip()

        # Mail is optional for managed MFA, but a password-authenticated flow
        # may still request an additional email challenge.
        injected_adapter = extra_config.get("_otp_email_adapter")
        mail_provider = _oauth_mail_provider(email, extra_config)

        # 补 RT 时的 OAuth 浏览器模式。
        # - protocol:  纯 HTTP curl_cffi,快,但 OpenAI 新流程下 workspace_select 死循环
        # - headless:  DrissionPage 启动 Chromium 全程接管,无头(默认)
        # - headed:    同上但可见,调试用
        from core.config_store import config_store as _cs
        rt_browser_mode = str(
            extra_config.get("business_rt_oauth_browser_mode")
            or _cs.get("business_rt_oauth_browser_mode", "protocol")
            or "protocol"
        ).strip().lower()
        if rt_browser_mode not in ("protocol", "headless", "headed"):
            rt_browser_mode = "protocol"

        # The HTTP-only state machine has no stable public contract for an
        # Authenticator challenge.  Consult only the encrypted store's safe
        # metadata; the browser login boundary decrypts the seed locally.
        has_stored_totp = False
        try:
            from services.chatgpt_security_store import get_chatgpt_security_status

            security_status = get_chatgpt_security_status(email)
            mfa_state = str(
                security_status.get("mfa_state") or ""
            ).strip().lower()
            has_stored_totp = bool(security_status.get("has_totp")) or mfa_state in {
                "pending",
                "enabled",
                "unmanaged",
            }
            if has_stored_totp and not bool(
                security_status.get("credentials_readable", True)
            ):
                raise RuntimeError(
                    "账号 Authenticator 凭据无法解密，请检查加密密钥配置"
                )
        except RuntimeError:
            raise
        except Exception:
            # A missing account row is represented by a readable empty status
            # and remains compatible.  An unavailable status store is
            # different: protocol fallback could bypass an enrolled MFA flow.
            raise RuntimeError(
                "账号安全状态读取失败，已停止 OAuth 登录"
            ) from None
        if rt_browser_mode == "protocol" and has_stored_totp:
            rt_browser_mode = "headless"
            log_fn("  账号已启用 Authenticator 2FA，自动改用无头浏览器完成登录校验")

        if injected_adapter is not None:
            email_adapter = injected_adapter
            log_fn("  已保留当前账号邮箱适配器，供追加邮箱验证使用")
        elif mail_provider in {"", "cfworker", "cfworker_admin"} and cfworker_api_url and cfworker_admin_token:
            email_adapter = _BusinessOAuthEmailAdapter(
                email=email,
                api_url=cfworker_api_url,
                admin_token=cfworker_admin_token,
                custom_auth=cfworker_custom_auth,
                log_fn=log_fn,
            )
        elif has_stored_totp:
            email_adapter = None
        else:
            raise RuntimeError("当前账号邮箱取码未配置，无法完成 OAuth 邮箱验证")
        if has_stored_totp:
            log_fn("  Authenticator OAuth 优先使用密码 + 动态码；追加邮箱验证仅在页面要求时处理")

        if rt_browser_mode in ("headless", "headed"):
            from platforms.chatgpt.drission_rt_acquirer import acquire_rt_via_drission
            log_fn(f"  使用 DrissionPage 模式补 RT (headless={rt_browser_mode == 'headless'})")
            return acquire_rt_via_drission(
                email=email,
                password=password or "",
                proxy=proxy or "",
                extra_config=extra_config,
                log_fn=log_fn,
                email_adapter=email_adapter,
                headless=(rt_browser_mode == "headless"),
            )

        # protocol 模式: 原 OAuthClient + curl_cffi HTTP
        oauth_client = OAuthClient(
            dict(extra_config), proxy=proxy, verbose=False, browser_mode="protocol",
        )
        oauth_client._log = _make_business_rt_log_filter(log_fn)

        tokens = oauth_client.login_and_get_tokens(
            email=email,
            password=password or "",
            device_id="",
            user_agent=None,
            sec_ch_ua=None,
            impersonate=None,
            skymail_client=email_adapter,
            prefer_passwordless_login=True,
            allow_phone_verification=True,  # ★ 命中 add_phone 时走 SMSToMePhoneService 自动过
            force_new_browser=True,
            force_password_login=False,
            force_chatgpt_entry=False,
            screen_hint="login",
            complete_about_you_if_needed=False,
            login_source="business_rt_post_register_login",
        )
        if not tokens or not tokens.get("refresh_token"):
            last_err = getattr(oauth_client, "last_error", "") or "未知错误"
            raise RuntimeError(f"OAuth 登录未返回 refresh_token: {last_err}")

        session_token = ""
        try:
            session_token = (
                oauth_client._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")
                or oauth_client._get_cookie_value("__Secure-authjs.session-token", "chatgpt.com")
                or ""
            )
        except Exception:
            pass

        return {
            "access_token": tokens.get("access_token", ""),
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens.get("id_token", ""),
            "session_token": session_token or "",
        }

    def _dump_business_oauth_file(self, account: Account, extra_config: dict, log_fn) -> None:
        """把 account.extra 里的 tokens 序列化到 oauth_out/<email>.json（覆盖阶段 1 那份）。"""
        import os
        import re
        from platforms.chatgpt.cpa_upload import generate_token_json

        try:
            output_dir = str(
                extra_config.get("chatgpt_oauth_output_dir")
                or (self.config.extra or {}).get("chatgpt_oauth_output_dir")
                or "oauth_out"
            ).strip()
            output_dir = os.path.abspath(output_dir)
            os.makedirs(output_dir, exist_ok=True)
            safe_email = re.sub(r"[^a-zA-Z0-9._-]", "_", account.email or "")

            class _TokenAccount:
                pass

            extra = account.extra or {}
            token_account = _TokenAccount()
            token_account.email = account.email
            token_account.access_token = extra.get("access_token", "")
            token_account.refresh_token = extra.get("refresh_token", "")
            token_account.id_token = extra.get("id_token", "")
            token_account.session_token = extra.get("session_token", "")
            token_data = generate_token_json(token_account)
            file_path = os.path.join(output_dir, f"{safe_email}.json")
            with open(file_path, "w", encoding="utf-8") as fh:
                json.dump(token_data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.chmod(file_path, 0o600)
            extra["oauth_file"] = os.path.abspath(file_path)
            account.extra = extra
            log_fn(f"[BUSINESS RT] OAuth 文件已更新（含 RT）: {extra['oauth_file']}")
        except Exception as exc:
            log_fn(f"[BUSINESS RT] OAuth 文件写入失败（忽略）: {exc}")

    def _register_business_protocol(self, business_domain: str, password: str, proxy: str,
                                     extra_config: dict, log_fn,
                                     skip_oauth_file: bool = False,
                                     skip_codex_switch: bool = False) -> Account:
        """BUSINESS 模式:协议注册(不依赖浏览器,Linux 友好)。

        - 邮箱本地生成 random@business_domain
        - 跳过 CF Worker /admin/new_address(白名单拒绝)
        - 用 /admin/mails?address=... 读验证码(CF Worker D1 catch-all 存储)

        Args:
            skip_oauth_file: True 时不写阶段 1 的 AT-only oauth_file
                             （供 "有 RT" 路径用,避免被阶段 2 覆盖的中间态）
            skip_codex_switch: True 时不调 _switch_business_seat_to_codex
                             （供 "有 RT" 路径用,RT 拿到后再切）
        """
        # 校验 hostname 是已验证的 business 域(防伪造)
        try:
            from services.business_domain_service import is_business_hostname
            if not is_business_hostname(business_domain):
                raise RuntimeError(f"{business_domain} 不是已验证的 BUSINESS 子域")
        except ImportError:
            pass

        cfworker_api_url = (extra_config.get("cfworker_api_url") or "").strip().rstrip("/")
        cfworker_admin_token = (extra_config.get("cfworker_admin_token") or "").strip()
        cfworker_custom_auth = (extra_config.get("cfworker_custom_auth") or "").strip()
        if not cfworker_api_url:
            raise RuntimeError("CF Worker API URL 未配置(BUSINESS 模式需复用 CF Worker 收信)")

        # 本地生成邮箱: 机器前缀 + 强随机,降低多机并行碰撞概率。
        email_machine_prefix = _business_email_machine_prefix(extra_config)
        name_part = _generate_business_email_local_part(extra_config)
        email = f"{name_part}@{business_domain}"
        log_fn(f"[BUSINESS 协议注册] 邮箱: {email}")

        from platforms.chatgpt.protocol_register import (
            ChatGPTProtocolRegister,
            DomainDeactivatedError,
        )

        reg = ChatGPTProtocolRegister(
            proxy=proxy,
            log_fn=log_fn,
            cookie_dir=extra_config.get("cookie_json_dir", "cookies"),
            browser_bootstrap=False,
        )

        # 用 CF Worker /admin/mails 拉验证码
        import requests as _req
        import re as _re
        import email as _email
        from email import policy as _email_policy

        def _extract_code_from_mail(mail_obj: dict) -> str:
            """从邮件对象提取 6 位验证码。
            优先级:
              1. text/plain 或 text/html 里关键字('to continue' / 'verification code' / '输入') 后的第一个 6 位数
              2. MIME 解析失败时,从 raw 头之后的部分找
            """
            # 先尝试 text/html、text 字段
            candidates = []
            for k in ("text", "html"):
                v = mail_obj.get(k) or ""
                if v: candidates.append(v)
            # 解析 raw MIME
            raw = mail_obj.get("raw") or ""
            if raw:
                try:
                    msg = _email.message_from_string(raw, policy=_email_policy.default)
                    for part in msg.walk():
                        ct = part.get_content_type()
                        if ct in ("text/plain", "text/html"):
                            try:
                                content = part.get_content()
                                if isinstance(content, str):
                                    candidates.append(content)
                            except Exception:
                                pass
                except Exception:
                    pass

            keyword_re = _re.compile(
                r"(?:to\s+continue|verification\s+code|"
                r"输入此临时验证码|enter\s+this\s+temporary\s+verification\s+code|"
                r"your\s+code\s+is)"
                r".{0,2000}?(?<!\d)(\d{6})(?!\d)",
                _re.IGNORECASE | _re.DOTALL,
            )
            for body in candidates:
                match = keyword_re.search(body)
                if match:
                    return match.group(1)
            return ""

        def _detect_deactivation(mail_obj: dict) -> tuple[str, str]:
            """识别 OpenAI Trust & Safety 的封号 / 风控通知。

            返回 (from, subject); 二者任一非空表示命中风控信号:
              - From 含 trustandsafety@ (OpenAI 信任与安全团队发件人)
              - Subject 含 Deactivated / Suspended / Terminated
            """
            raw = mail_obj.get("raw") or ""
            if not raw:
                return "", ""
            from_match = _re.search(r"^From:\s*(.+?)$", raw, _re.MULTILINE)
            sub_match = _re.search(r"^Subject:\s*(.+?)$", raw, _re.MULTILINE)
            from_hdr = (from_match.group(1) if from_match else "").strip()
            subject = (sub_match.group(1) if sub_match else "").strip()
            lf, ls = from_hdr.lower(), subject.lower()
            if "trustandsafety@" in lf:
                return from_hdr, subject
            if any(k in ls for k in ("deactivated", "suspended", "terminated")):
                return from_hdr, subject
            return "", ""

        # seen_ids 保留为单轮内去重；当前策略为单轮 8s,不重发 send_otp
        otp_seen_ids: set = set()
        _SINGLE_ROUND_SECONDS = 8

        def otp_cb() -> str:
            log_fn(f"等待验证码 (单轮 {_SINGLE_ROUND_SECONDS}s,不重试)...")
            deadline = time.time() + _SINGLE_ROUND_SECONDS
            headers = {"x-admin-auth": cfworker_admin_token}
            if cfworker_custom_auth:
                headers["x-custom-auth"] = cfworker_custom_auth
            while time.time() < deadline:
                try:
                    resp = _req.get(
                        f"{cfworker_api_url}/admin/mails",
                        params={"limit": 20, "offset": 0, "address": email},
                        headers=headers, timeout=10,
                    )
                    if resp.status_code == 200:
                        data = resp.json() or {}
                        for m in data.get("results") or []:
                            mid = m.get("id")
                            if mid in otp_seen_ids:
                                continue
                            otp_seen_ids.add(mid)
                            # 风控邮件检测 — 命中即 fail-fast,不再傻等验证码
                            dead_from, dead_sub = _detect_deactivation(m)
                            if dead_from or dead_sub:
                                log_fn("=" * 56)
                                log_fn("🚫 检测到 OpenAI 风控邮件 (非验证码)")
                                log_fn(f"   邮箱: {email}")
                                log_fn(f"   子域: {business_domain}")
                                if dead_from:
                                    log_fn(f"   From: {dead_from[:120]}")
                                if dead_sub:
                                    log_fn(f"   Subject: {dead_sub[:120]}")
                                log_fn(
                                    f"   ⚠ OpenAI 直接拒绝注册,验证码邮件不会到达"
                                )
                                log_fn(
                                    f"   建议: 将子域 {business_domain}"
                                    " 标为 banned/失效,长跑跳过该子域"
                                )
                                log_fn("=" * 56)
                                raise DomainDeactivatedError(
                                    f"子域 {business_domain} 收到 OpenAI"
                                    f" Access Deactivated 通知"
                                    f" (Subject: {dead_sub[:80]})",
                                    hint_subject=dead_sub,
                                    hint_from=dead_from,
                                )
                            code = _extract_code_from_mail(m)
                            if code:
                                log_fn("已获取验证码（内容不写入日志）")
                                return code
                except DomainDeactivatedError:
                    raise
                except Exception as _e:
                    log_fn(f"读邮件异常(忽略): {_e}")
                time.sleep(1)  # 8s 内每秒轮询一次
            return ""

        result = reg.register(email=email, password=password, otp_callback=otp_cb)

        # 没拿到 access_token 的注册是死号: 不能登录、不能补 RT、不能上传, 直接判失败
        if not str(result.get("access_token") or "").strip():
            raise RuntimeError(
                f"注册流程未返回 access_token ({email}); "
                f"协议链路可能命中风控或 /api/auth/session 拿不到 token，账号不落库"
            )

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "auth_session": result.get("auth_session") or {},
            "account_id": result.get("account_id", ""),
            "user_id": result.get("user_id", ""),
            "name": result.get("name", ""),
            "register_mode": "protocol_business",
            "mail_provider": "cfworker",
            "account_type": "BUSINESS",
            "business_domain": business_domain,
            "business_email_machine_prefix": email_machine_prefix,
            "business_switch_to_codex": _switch_codex_pref_value(extra_config),
            "password_set_proven": bool(result.get("password_set_proven", False)),
        }
        if account_extra.get("access_token") and not skip_oauth_file:
            try:
                import os
                import re
                from platforms.chatgpt.cpa_upload import generate_token_json

                output_dir = str(
                    extra_config.get("chatgpt_oauth_output_dir")
                    or (self.config.extra or {}).get("chatgpt_oauth_output_dir")
                    or "oauth_out"
                ).strip()
                output_dir = os.path.abspath(output_dir)
                os.makedirs(output_dir, exist_ok=True)
                safe_email = re.sub(r"[^a-zA-Z0-9._-]", "_", result["email"])

                class _TokenAccount:
                    pass

                token_account = _TokenAccount()
                token_account.email = result["email"]
                token_account.access_token = account_extra.get("access_token", "")
                token_account.refresh_token = account_extra.get("refresh_token", "")
                token_account.id_token = account_extra.get("id_token", "")
                token_account.session_token = account_extra.get("session_token", "")
                token_data = generate_token_json(token_account)
                file_path = os.path.join(output_dir, f"{safe_email}.json")
                with open(file_path, "w", encoding="utf-8") as fh:
                    json.dump(token_data, fh, ensure_ascii=False, indent=2)
                    fh.write("\n")
                os.chmod(file_path, 0o600)
                account_extra["oauth_file"] = os.path.abspath(file_path)
                log_fn(f"[BUSINESS 协议注册] OAuth 文件已保存: {account_extra['oauth_file']}")
            except Exception as exc:
                log_fn(f"[BUSINESS 协议注册] OAuth 文件保存失败(忽略): {exc}")
        if not skip_codex_switch:
            _switch_business_seat_to_codex(
                account_extra, log_fn, proxy=proxy,
                enabled=_read_switch_codex_flag(extra_config),
            )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result["password"],
            user_id=result.get("account_id", "") or "",
            token=result.get("access_token", "") or "",
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _register_drission(self, email, password, proxy, extra_config, log_fn) -> Account:
        """使用 DrissionPage 浏览器注册（CF Worker / Outlook）"""
        from platforms.chatgpt.drission_register import register_chatgpt

        mail_provider = extra_config.get("mail_provider", "cfworker")
        # headless 优先由 executor_type 决定: headed → 有头(打开可见浏览器), headless → 无头。
        # 之前只读 drission_headless(从不被写入,恒为默认无头),导致选「有头浏览器」也不弹窗。
        executor_type = str((self.config.executor_type if self.config else "") or "").strip().lower()
        if executor_type == "headed":
            headless = False
        elif executor_type == "headless":
            headless = True
        else:
            headless = str(extra_config.get("drission_headless", "1")).strip().lower() in ("1", "true", "yes", "on")

        # 公共参数
        kwargs = {
            "password": password or "",
            "proxy": proxy or "",
            "headless": headless,
            "log_fn": log_fn,
        }
        mail_acct = None
        mail_before_ids = None
        mail_baseline_at = None
        is_business = False

        if mail_provider == "outlook":
            # Outlook: 从邮箱池取账号；验证码读取必须复用邮箱池的
            # Graph/IMAP 自动分流，不能把 IMAP 凭证强制送往 Graph。
            if not self.mailbox:
                raise RuntimeError("Outlook 邮箱池未配置")

            # 取一个未注册过 ChatGPT 的 Outlook 账号
            mail_acct = None
            max_skip = 20
            for _ in range(max_skip):
                try:
                    candidate = self.mailbox.get_email()
                except RuntimeError:
                    break
                # 检查是否已注册过 ChatGPT
                candidate_id = int(candidate.account_id or 0)
                if candidate_id:
                    from sqlmodel import Session as _Session
                    from core.db import engine as _engine, OutlookAccountModel
                    with _Session(_engine) as _s:
                        row = _s.get(OutlookAccountModel, candidate_id)
                        if row and row.gpt_register_status == "已注册":
                            # 已注册的不归还，保持 disabled，避免重复取出
                            log_fn(f"[DrissionPage] 跳过已注册账号: {candidate.email}")
                            continue
                mail_acct = candidate
                break

            if not mail_acct:
                raise RuntimeError("Outlook 邮箱池中没有可用的未注册账号")

            outlook_email = mail_acct.email
            outlook_extra = mail_acct.extra or {}

            # 尝试注册，如果邮箱已注册自动换下一个
            max_email_tries = 10
            result = None
            for email_try in range(max_email_tries):
                outlook_email = mail_acct.email
                outlook_extra = mail_acct.extra or {}

                log_fn(f"[DrissionPage] 使用 Outlook 邮箱注册: {outlook_email} (headless={headless})")

                try_kwargs = dict(kwargs)
                try_kwargs["email"] = outlook_email
                try_kwargs["mail_provider"] = "outlook"
                outlook_credentials = _outlook_mail_credentials(
                    outlook_extra,
                    allow_legacy_generic=True,
                )
                try_kwargs["outlook_client_id"] = outlook_credentials["client_id"]
                try_kwargs["outlook_refresh_token"] = outlook_credentials["refresh_token"]

                # Snapshot before the registration request can trigger mail.
                mail_baseline_at = time.time()
                try:
                    mail_before_ids = self._capture_registration_mail_baseline(
                        self.mailbox,
                        mail_acct,
                    )
                except Exception:
                    account_id = int(mail_acct.account_id or 0)
                    if account_id:
                        try:
                            from core.base_mailbox import OutlookMailbox

                            OutlookMailbox.return_account(account_id)
                        except Exception:
                            pass
                    raise

                # Bind immutable per-attempt objects.  ``wait_for_code`` owns
                # provider selection and also carries task cancellation
                # checkpoints, proxy settings and the strict pre-send ID
                # baseline used to reject stale OTP mail.
                attempt_mailbox = self.mailbox
                attempt_mail_account = mail_acct
                attempt_before_ids = set(mail_before_ids or set())

                def read_registration_code(
                    *,
                    timeout=15,
                    exclude_codes=None,
                    received_after_ts=0.0,
                    _mailbox=attempt_mailbox,
                    _mail_account=attempt_mail_account,
                    _before_ids=attempt_before_ids,
                ):
                    del received_after_ts  # Message-ID baseline is authoritative.
                    return _mailbox.wait_for_code(
                        _mail_account,
                        keyword="",
                        timeout=max(1, int(timeout or 0)),
                        before_ids=set(_before_ids),
                        exclude_codes=set(exclude_codes or set()),
                    )

                try_kwargs["outlook_code_reader"] = read_registration_code

                result = register_chatgpt(**try_kwargs)

                if result.get("success"):
                    break

                error_msg = result.get("error", "未知错误")
                account_id = int(mail_acct.account_id or 0)

                if "已注册" in error_msg or "登录页" in error_msg:
                    # 邮箱已注册过，标记并取下一个
                    if account_id:
                        try:
                            from sqlmodel import Session as _S2
                            from core.db import engine as _e2, OutlookAccountModel
                            with _S2(_e2) as _s2:
                                row = _s2.get(OutlookAccountModel, account_id)
                                if row:
                                    row.gpt_register_status = "已注册"
                                    row.enabled = False
                                    _s2.add(row)
                                    _s2.commit()
                        except Exception:
                            pass
                    log_fn(f"[DrissionPage] 邮箱已注册，自动换下一个 ({email_try+1}/{max_email_tries})")

                    # 取下一个
                    mail_acct = None
                    try:
                        mail_acct = self.mailbox.get_email()
                    except RuntimeError:
                        break
                    if not mail_acct:
                        break
                    continue
                else:
                    # 其他失败原因，归还邮箱并停止
                    try:
                        from core.base_mailbox import OutlookMailbox
                        if account_id:
                            OutlookMailbox.return_account(account_id)
                            log_fn(f"[DrissionPage] 注册失败，已归还: {outlook_email}")
                    except Exception:
                        pass
                    raise RuntimeError(f"DrissionPage 注册失败: {error_msg}")

            if not result or not result.get("success"):
                raise RuntimeError("所有 Outlook 邮箱均已注册或不可用")

            register_mode = "drission_outlook"

        else:
            # CF Worker / BUSINESS 走浏览器路径(罕见,通常 cfworker_protocol 已经接管)
            cfworker_api_url = extra_config.get("cfworker_api_url", "")
            cfworker_admin_token = extra_config.get("cfworker_admin_token", "")
            cfworker_custom_auth = extra_config.get("cfworker_custom_auth", "")
            cfworker_quick_api_url = extra_config.get("cfworker_quick_api_url", "")

            business_domain = (extra_config.get("business_domain") or "").strip().lower()
            is_business = bool(business_domain)

            if not cfworker_api_url:
                raise RuntimeError("CF Worker API URL 未配置")
            if not self.mailbox and not is_business:
                raise RuntimeError("CF Worker 邮箱实例未初始化")

            mail_acct = None
            if is_business:
                # 验证此 hostname 是已验证的 business 子域(防伪造)
                try:
                    from services.business_domain_service import is_business_hostname
                    if not is_business_hostname(business_domain):
                        raise RuntimeError(f"{business_domain} 不是已验证的 BUSINESS 子域")
                except ImportError:
                    pass
                # 本地生成 prefix+random@business_domain,跳过 CF Worker /admin/new_address
                email_machine_prefix = _business_email_machine_prefix(extra_config)
                name_part = _generate_business_email_local_part(extra_config)
                cfworker_email = f"{name_part}@{business_domain}"
                log_fn(f"[DrissionPage] BUSINESS 模式注册: {cfworker_email} (headless={headless})")
            else:
                mail_acct = self.mailbox.get_email()
                cfworker_email = str(
                    email or getattr(mail_acct, "email", "") or ""
                ).strip()
                if not cfworker_email:
                    raise RuntimeError("未获取到 CF Worker 邮箱地址")
                log_fn(
                    f"[DrissionPage] 使用 CF Worker 域名邮箱注册 "
                    f"(email={cfworker_email}, headless={headless})"
                )
                mail_baseline_at = time.time()
                mail_before_ids = self._capture_registration_mail_baseline(
                    self.mailbox,
                    mail_acct,
                )

                # Bind the exact mailbox account and the immutable pre-send
                # snapshot to this registration attempt.  The Drission engine
                # must not independently scan Quick API without that baseline,
                # otherwise a stale OTP (or a message for another address) can
                # be accepted under concurrent registrations.
                attempt_mailbox = self.mailbox
                attempt_mail_account = mail_acct
                attempt_before_ids = set(mail_before_ids or set())

                def read_cfworker_registration_code(
                    *,
                    timeout=15,
                    exclude_codes=None,
                    received_after_ts=0.0,
                    _mailbox=attempt_mailbox,
                    _mail_account=attempt_mail_account,
                    _before_ids=attempt_before_ids,
                ):
                    try:
                        return _mailbox.wait_for_code(
                            _mail_account,
                            keyword="",
                            timeout=max(1, int(timeout or 0)),
                            before_ids=set(_before_ids),
                            exclude_codes=set(exclude_codes or set()),
                            otp_sent_at=float(received_after_ts or 0.0),
                        )
                    except TimeoutError:
                        # One bounded wait elapsed.  Take a credential-free
                        # snapshot so the task can distinguish delivery failure
                        # (HTTP 200 / zero mail) from an unreadable mailbox.
                        try:
                            getter = getattr(_mailbox, "_get_mails", None)
                            mails = list(
                                getter(_mail_account.email)
                                if callable(getter)
                                else []
                            )
                            ids = {
                                str(item.get("id"))
                                for item in mails
                                if isinstance(item, dict)
                                and item.get("id") not in (None, "")
                            }
                            new_count = len(ids - set(_before_ids))
                            reason = (
                                "no_messages"
                                if not mails
                                else "no_new_message"
                                if new_count == 0
                                else "no_valid_code"
                            )
                            return {
                                "code": None,
                                "reason": reason,
                                "source": "mailbox_reader",
                                "last_http_status": 200,
                                "message_count": len(mails),
                                "new_message_count": new_count,
                                "terminal": False,
                            }
                        except Exception as exc:
                            return {
                                "code": None,
                                "reason": "mailbox_access_failed",
                                "source": "mailbox_reader",
                                "error_type": type(exc).__name__,
                                "terminal": False,
                            }

                kwargs["cfworker_code_reader"] = read_cfworker_registration_code

            kwargs["email"] = cfworker_email
            kwargs["cfworker_api_url"] = cfworker_api_url
            kwargs["cfworker_admin_token"] = cfworker_admin_token
            kwargs["cfworker_custom_auth"] = cfworker_custom_auth
            kwargs["cfworker_quick_api_url"] = cfworker_quick_api_url

            result = register_chatgpt(**kwargs)

            if not result.get("success"):
                raise RuntimeError(f"DrissionPage 注册失败: {result.get('error', '未知错误')}")

            register_mode = "drission_business" if is_business else "drission_cfworker"

        log_fn(f"[DrissionPage] 注册成功: {result.get('email')}")

        cookies_data = result.get("cookies", {})
        account_extra = {
            "cookies": json.dumps(cookies_data) if isinstance(cookies_data, dict) else str(cookies_data),
            "cookie_file": result.get("cookie_file", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "name": result.get("name", ""),
            "register_mode": register_mode,
            "mail_provider": mail_provider,
        }
        if mail_acct is not None:
            self._preserve_registration_mailbox(
                account_extra,
                mail_provider,
                self.mailbox,
                mail_acct,
                before_ids=mail_before_ids,
                not_before=mail_baseline_at,
                log_fn=log_fn,
            )
        if mail_provider == "cfworker" and not is_business and mail_acct is not None:
            account_extra.setdefault("mailbox_token", str(getattr(mail_acct, "account_id", "") or ""))
            account_extra.setdefault("cfworker_api_url", extra_config.get("cfworker_api_url", ""))
            account_extra.setdefault("cfworker_quick_api_url", extra_config.get("cfworker_quick_api_url", ""))
        # BUSINESS 标记
        if is_business:
            account_extra["account_type"] = "BUSINESS"
            account_extra["business_domain"] = business_domain
            account_extra["business_email_machine_prefix"] = email_machine_prefix
            _switch_business_seat_to_codex(
            account_extra, log_fn, proxy=proxy,
            enabled=_read_switch_codex_flag(extra_config),
        )
        account_extra["password_set_proven"] = bool(
            result.get("password_set_proven", False)
        )
        _maybe_generate_payment_link(account_extra, extra_config, proxy, log_fn)
        return Account(
            platform="chatgpt",
            email=result["email"],
            password=result.get("password", password),
            status=AccountStatus.REGISTERED,
            extra=account_extra,
        )

    def _build_oauth_mail_ctx(self, account: Account, extra: dict) -> tuple[dict | None, str]:
        provider = _oauth_mail_provider(account.email, extra)
        email = str(account.email or "").strip()
        if provider == "gmail":
            return {"provider": "gmail", "email": email,
                    **_mailbox_extra_for_account("gmail", extra)}, ""

        # BUSINESS 账号:catch-all 收件,用 admin /admin/mails?address=... 读 OTP
        # (与注册时同一条链路,而不是普通 cfworker 的 tempapi quick_api)
        if str(extra.get("account_type", "")).upper() == "BUSINESS" and provider in {"", "cfworker", "cfworker_admin"}:
            from core.config_store import config_store
            api_base = str(config_store.get("cfworker_api_url", "") or "").strip().rstrip("/")
            admin_token = str(config_store.get("cfworker_admin_token", "") or "").strip()
            if not api_base or not admin_token:
                return None, (
                    "BUSINESS 账号需要在「全局配置」配好 "
                    "cfworker_api_url 与 cfworker_admin_token 才能读 OAuth 验证码"
                )
            return {
                "provider": "cfworker_admin",
                "email": email,
                "api_base": api_base,
                "admin_token": admin_token,
                "custom_auth": str(config_store.get("cfworker_custom_auth", "") or "").strip(),
            }, ""

        if provider == "outlook":
            outlook_mail = _outlook_mail_credentials(extra)
            refresh_token = outlook_mail["refresh_token"]
            client_id = outlook_mail["client_id"]
            if not refresh_token or not client_id:
                return None, "Outlook 账号缺少 refresh_token/client_id，无法自动读取 OAuth 验证码"
            mail_ctx = {
                "provider": "outlook",
                "email": email,
                "refresh_token": refresh_token,
                "client_id": client_id,
                "outlook_code_type": "AUTH",
            }
            mail_access_type = outlook_mail["mail_access_type"]
            if mail_access_type:
                mail_ctx["mail_access_type"] = mail_access_type
            return mail_ctx, ""

        if provider == "cfworker":
            quick_api = (
                str(extra.get("cfworker_quick_api_url") or "").strip().rstrip("/")
                or str(extra.get("cfworker_api_url") or "").strip().rstrip("/")
                or "https://temp-api.cursom.shop"
            )
            return {
                "provider": "tempapi",
                "email": email,
                "api_base": quick_api,
                "jwt": str(extra.get("mailbox_token") or "").strip(),
                "address_id": "",
                "use_quick_api": True,
            }, ""

        return None, f"当前邮箱来源 {provider or '-'} 暂不支持自动生成 OAuth 文件"

    def _build_optional_oauth_email_adapter(
        self, account: Account, extra: dict, *, proxy: str = "", log_fn=None,
    ):
        """Restore only the account's own provider; managed MFA may omit it."""
        emit = log_fn or (lambda _msg: None)
        provider = _oauth_mail_provider(account.email, extra)
        if provider in {"outlook", "icloud", "qqmail", "gmail"}:
            from platforms.chatgpt.gpt_pro_login import (
                GptProEmailAdapterForCodexOAuth,
                build_mailbox_for_account,
            )

            mailbox_extra = {"email": account.email, "mail_provider": provider}
            if provider == "gmail":
                mailbox_extra.update(_mailbox_extra_for_account("gmail", extra))
            if provider == "outlook":
                credentials = _outlook_mail_credentials(extra)
                if not credentials["password"] and not (
                    credentials["refresh_token"] and credentials["client_id"]
                ):
                    return None
                mailbox_extra.update({
                    _OUTLOOK_MAIL_PASSWORD_KEY: credentials["password"],
                    _OUTLOOK_MAIL_CLIENT_ID_KEY: credentials["client_id"],
                    _OUTLOOK_MAIL_REFRESH_TOKEN_KEY: credentials["refresh_token"],
                    _OUTLOOK_MAIL_ACCESS_TYPE_KEY: credentials["mail_access_type"],
                    "graph_immutable_ids": bool(extra.get("graph_immutable_ids")),
                })
            mailbox, mail_account = build_mailbox_for_account(mailbox_extra, proxy=proxy)
            return GptProEmailAdapterForCodexOAuth(mailbox, mail_account, log_fn=emit)
        if provider not in {"cfworker", "cfworker_admin"}:
            return None
        from core.config_store import config_store

        cf_api = str(config_store.get("cfworker_api_url", "") or "").strip().rstrip("/")
        cf_admin = str(config_store.get("cfworker_admin_token", "") or "").strip()
        if cf_api and cf_admin and not str(extra.get("cfworker_quick_api_url") or "").strip():
            return _BusinessOAuthEmailAdapter(
                email=account.email,
                api_url=cf_api,
                admin_token=cf_admin,
                custom_auth=str(config_store.get("cfworker_custom_auth", "") or "").strip(),
                log_fn=emit,
            )
        mail_ctx, error = self._build_oauth_mail_ctx(account, extra)
        if error or not mail_ctx:
            return None
        if mail_ctx.get("provider") == "cfworker_admin":
            return _BusinessOAuthEmailAdapter(
                email=account.email,
                api_url=mail_ctx.get("api_base", ""),
                admin_token=mail_ctx.get("admin_token", ""),
                custom_auth=mail_ctx.get("custom_auth", ""),
                log_fn=emit,
            )
        return _OAuthMailContextEmailAdapter(mail_ctx, emit)

    def _generate_oauth_file_browser(self, account: Account, params: dict, proxy: str | None) -> dict:
        """通过 subprocess 调 scripts/generate_oauth_json_manual.py --browser-login 拿 OAuth。

        使用真实 DrissionPage 浏览器(可 headless),绕过 OpenAI 对协议 OAuth 的 add_phone 风控。
        """
        import os
        import subprocess
        import sys
        import json as _json
        import re as _re
        from datetime import datetime, timezone

        extra = dict(account.extra or {})
        extra.pop("chatgpt_totp_secret", None)
        email = str(account.email or "").strip()
        if not email:
            return {"ok": False, "error": "账号缺少邮箱"}

        # 邮件来源:BUSINESS / cfworker → tempapi(用 /open_api/quick_mails);Outlook → refresh_token+client_id
        provider_hint = str(extra.get("mail_provider") or "").strip().lower()
        is_business = str(extra.get("account_type", "")).upper() == "BUSINESS"

        # 输出目录
        # __file__ = platforms/chatgpt/plugin.py → 项目根需要 3 个 dirname
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        output_dir = str(
            params.get("output_dir")
            or (self.config.extra or {}).get("chatgpt_oauth_output_dir")
            or os.path.join(project_root, "output", "oauth_browser")
        ).strip()
        os.makedirs(output_dir, exist_ok=True)

        # headless 默认 true,允许用户关掉
        headless = str(params.get("headless", "1")).strip().lower() not in ("0", "false", "no", "off")
        browser_timeout = int(params.get("browser_timeout") or 180)

        # 构造 mail-provider 参数
        outlook_mail = _outlook_mail_credentials(extra)
        outlook_refresh_token = outlook_mail["refresh_token"]
        outlook_client_id = outlook_mail["client_id"]
        outlook_mail_access_type = outlook_mail["mail_access_type"]

        cmd = [
            sys.executable,
            os.path.join(project_root, "scripts", "generate_oauth_json_manual.py"),
            "--browser-login",
            "--email", email,
            "--output-dir", output_dir,
            "--browser-timeout", str(browser_timeout),
        ]
        if headless:
            cmd.append("--headless")

        if provider_hint == "outlook" and outlook_refresh_token and outlook_client_id:
            cmd.extend(["--mail-provider", "outlook"])
            if outlook_mail_access_type:
                cmd.extend(["--outlook-mail-access-type", outlook_mail_access_type])
        elif provider_hint == "cfworker" or is_business:
            # BUSINESS / cfworker → tempapi(用 quick_mails 端点)
            from core.config_store import config_store
            api_base = (config_store.get("cfworker_api_url", "") or "https://temp-api.cursom.shop").strip().rstrip("/")
            tempapi_auth = _json.dumps({"api_base": api_base, "address": email})
            cmd.extend(["--mail-provider", "tempapi"])
            cmd.extend(["--email-password", tempapi_auth])

        # 准备 env:让子进程对 localhost / 127.0.0.1 不走代理,
        # 否则 DrissionPage 连 Chromium DevTools (ws://127.0.0.1:port) 会被代理拦截握手失败
        sub_env = os.environ.copy()
        existing_no = sub_env.get("NO_PROXY") or sub_env.get("no_proxy") or ""
        merged_no = ",".join(
            sorted({*(p for p in existing_no.split(",") if p.strip()),
                    "localhost", "127.0.0.1", "::1"})
        )
        sub_env["NO_PROXY"] = merged_no
        sub_env["no_proxy"] = merged_no
        # Keep mailbox credentials out of argv/process listings and task logs.
        # The helper reads these private environment variables as defaults.
        if outlook_refresh_token:
            sub_env["CHATGPT_OAUTH_OUTLOOK_REFRESH_TOKEN"] = outlook_refresh_token
        if outlook_client_id:
            sub_env["CHATGPT_OAUTH_OUTLOOK_CLIENT_ID"] = outlook_client_id
        if proxy:
            sub_env["CHATGPT_OAUTH_PROXY"] = str(proxy)

        def _safe_child_log_line(value: object) -> str:
            text = str(value or "")
            text = _re.sub(
                r'("(?:access_token|refresh_token|id_token|session_token)"\s*:\s*")[^"]*(")',
                r'\1[已隐藏]\2',
                text,
                flags=_re.I,
            )
            text = _re.sub(
                r"(?i)([?&](?:code|state)=)[^&\s\"']+",
                r"\1[已隐藏]",
                text,
            )
            text = _re.sub(
                r"(?i)\b(https?://)([^\s/@:]+):([^\s/@]+)@",
                r"\1[认证信息已隐藏]@",
                text,
            )
            return text

        # 流式调用 + 实时日志(看得到进度)
        log_path = os.path.join(project_root, "logs", "oauth_browser.log")
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a") as _f:
                _f.write(f"\n========== {datetime.now()} ==========\n")
                _f.write(f"email: {email}\n")
                _f.write(f"headless: {headless}\n")
                _f.write(f"timeout: {browser_timeout}s\n")
                _f.write("cmd: OAuth browser helper（凭据参数不写入日志）\n")
                _f.write(f"NO_PROXY: {sub_env.get('NO_PROXY')}\n")
                _f.write(f"--- stdout/stderr stream ---\n")
                _f.flush()
        except Exception:
            pass

        stdout_lines = []
        stderr_lines = []
        try:
            popen = subprocess.Popen(
                cmd, cwd=project_root, env=sub_env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                bufsize=1,
            )

            # 用 select 同时读 stdout/stderr,写到日志
            import select
            deadline = time.time() + browser_timeout + 60
            log_file = open(log_path, "a") if os.path.exists(log_path) else None
            while True:
                if popen.poll() is not None:
                    # 进程退出,把剩余读完
                    try:
                        rest_out, rest_err = popen.communicate(timeout=5)
                    except Exception:
                        rest_out = rest_err = ""
                    if rest_out:
                        stdout_lines.append(rest_out)
                        if log_file: log_file.write(_safe_child_log_line(rest_out)); log_file.flush()
                    if rest_err:
                        stderr_lines.append(rest_err)
                        if log_file: log_file.write(f"[stderr] {_safe_child_log_line(rest_err)}"); log_file.flush()
                    break
                if time.time() > deadline:
                    popen.kill()
                    if log_file: log_file.write(f"\n[timeout killed after {browser_timeout+60}s]\n"); log_file.flush()
                    if log_file: log_file.close()
                    return {"ok": False, "error": f"浏览器 OAuth 超时(>{browser_timeout + 60}s)"}
                ready, _, _ = select.select([popen.stdout, popen.stderr], [], [], 1.0)
                for stream in ready:
                    line = stream.readline()
                    if not line:
                        continue
                    if stream is popen.stdout:
                        stdout_lines.append(line)
                        if log_file: log_file.write(_safe_child_log_line(line)); log_file.flush()
                    else:
                        stderr_lines.append(line)
                        if log_file: log_file.write(f"[stderr] {_safe_child_log_line(line)}"); log_file.flush()
            if log_file: log_file.write(f"[returncode] {popen.returncode}\n"); log_file.close()
        except Exception as e:
            return {"ok": False, "error": f"启动子进程失败: {e}"}

        proc_returncode = popen.returncode
        proc_stdout = "".join(stdout_lines)
        proc_stderr = "".join(stderr_lines)
        # 兼容下方代码用的变量名
        class _Proc:
            returncode = proc_returncode
            stdout = proc_stdout
            stderr = proc_stderr
        proc = _Proc()

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        # 提取最后一行 JSON
        result_json = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    result_json = _json.loads(line)
                    break
                except Exception:
                    continue
        if not result_json:
            return {
                "ok": False,
                "error": f"浏览器脚本无 JSON 输出 (returncode={proc.returncode})",
                "stdout_tail": _safe_child_log_line(stdout[-500:]) if stdout else "",
                "stderr_tail": _safe_child_log_line(stderr[-500:]) if stderr else "",
            }
        if not result_json.get("success"):
            return {
                "ok": False,
                "error": str(result_json.get("message") or "脚本返回 success=false"),
                "stderr_tail": _safe_child_log_line(stderr[-500:]) if stderr else "",
            }

        tokens = result_json.get("tokens") or {}
        access_token = str(tokens.get("access_token") or "").strip()
        refresh_token = str(tokens.get("refresh_token") or "").strip()
        id_token = str(tokens.get("id_token") or "").strip()
        if not access_token:
            return {"ok": False, "error": "脚本返回缺少 access_token"}

        oauth_file_path = str(result_json.get("file_path") or "").strip()
        account_id = str(result_json.get("account_id") or "").strip()
        expires_at = str(result_json.get("expires_at") or "").strip()

        # 解析 id_token 拿 plan_type
        plan_type = ""
        try:
            import base64
            payload_b64 = id_token.split(".")[1] + "=="
            claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
            plan_type = str(claims.get("https://api.openai.com/auth", {}).get("chatgpt_plan_type") or "")
        except Exception:
            pass

        return {
            "ok": True,
            "data": {
                "message": f"OAuth 刷新成功(浏览器),plan_type={plan_type or 'unknown'}",
                "file_path": oauth_file_path,
                "account_id": account_id,
                "expired": expires_at,
                "plan_type": plan_type,
            },
            "account_extra_patch": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "oauth_file": oauth_file_path,
                "chatgpt_account_id": account_id,
                "chatgpt_plan_type": plan_type,
            },
        }

    def _generate_oauth_file(self, account: Account, params: dict, proxy: str | None) -> dict:
        import os
        from datetime import datetime, timedelta, timezone

        from platforms.chatgpt.generate_oauth_json_protocol import (
            ProtocolOAuthClient,
            _extract_account_id_from_tokens,
            _extract_token_expired_str,
            _sanitize_filename,
        )

        log_fn = params.get("_log_fn") if callable(params.get("_log_fn")) else None

        def emit(msg: str) -> None:
            if log_fn:
                try:
                    log_fn(msg)
                except Exception:
                    pass

        emit(f"准备生成 OAuth 文件: {account.email}")
        extra = account.extra or {}
        mail_ctx, error = self._build_oauth_mail_ctx(account, extra)
        if error:
            emit(f"邮箱取码配置失败: {error}")
            return {"ok": False, "error": error}

        workspace_mode = str(params.get("workspace_mode") or "default").strip().lower()
        workspace_id = str(params.get("workspace_id") or "").strip()
        skip_workspace = workspace_mode == "personal"
        if workspace_mode != "workspace":
            workspace_id = ""

        # BUSINESS 子号:OpenAI 要求 workspace/select 必传 workspace_id,
        # 子号的工作区 ID 就是注册时记下的 extra.account_id(= 母号工作区 ID)
        if not workspace_id and str(extra.get("account_type", "")).upper() == "BUSINESS":
            workspace_id = str(extra.get("account_id") or "").strip()
            if workspace_id:
                emit(f"BUSINESS 账号自动套用工作区 ID: {workspace_id}")

        output_dir = str(
            params.get("output_dir")
            or (self.config.extra or {}).get("chatgpt_oauth_output_dir")
            or "oauth_out"
        ).strip()
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        emit(
            "OAuth 参数: "
            f"workspace_mode={workspace_mode or 'default'}, "
            f"workspace_id={workspace_id or '-'}, "
            f"output_dir={output_dir}"
        )

        client = ProtocolOAuthClient(
            email=account.email,
            proxy=proxy or "",
            mail_ctx=mail_ctx,
            skip_workspace=skip_workspace,
            workspace_id=workspace_id,
            log_fn=log_fn,
        )
        try:
            tokens = client.run()
        finally:
            client.close()

        if not isinstance(tokens, dict) or not tokens.get("access_token"):
            reason = ""
            if isinstance(tokens, dict):
                reason = str(
                    tokens.get("error_description")
                    or tokens.get("error")
                    or tokens.get("message")
                    or ""
                ).strip()
            if not reason:
                reason = str(getattr(client, "last_error", "") or "").strip()
            if not reason:
                recent_logs = getattr(client, "recent_logs", []) or []
                reason = str(recent_logs[-1] if recent_logs else "").strip()
            return {
                "ok": False,
                "error": f"OAuth 文件生成失败：未获取到 access_token{f'。最后状态：{reason}' if reason else ''}",
                "data": {
                    "message": "OAuth 文件生成失败",
                    "reason": reason,
                    "recent_logs": (getattr(client, "recent_logs", []) or [])[-12:],
                },
            }

        access_token = str(tokens.get("access_token") or "").strip()
        id_token = str(tokens.get("id_token") or "").strip()
        refresh_token = str(tokens.get("refresh_token") or "").strip()
        session_token = str(extra.get("session_token") or "").strip()
        account_id = _extract_account_id_from_tokens(tokens)
        if not account_id:
            emit("OAuth 文件生成失败: token 中缺少 account_id")
            return {"ok": False, "error": "OAuth 文件生成失败：token 中缺少 account_id"}

        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        last_refresh = datetime.now(timezone(timedelta(hours=8))).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%S+08:00"
        )
        expires_at = _extract_token_expired_str(access_token)
        file_path = os.path.abspath(os.path.join(output_dir, f"{_sanitize_filename(account.email)}.json"))
        payload = {
            "type": "codex",
            "email": account.email,
            "expired": str(expires_at or last_refresh).strip(),
            "id_token": id_token,
            "account_id": account_id,
            "access_token": access_token,
            "last_refresh": last_refresh,
            "refresh_token": refresh_token,
            "session_token": session_token,
            "generated_at": generated_at,
            "provider": str((mail_ctx or {}).get("provider") or ""),
            "oauth_token_response": tokens,
            "oauth_flow": "protocol",
            "workspace_mode": workspace_mode,
            "workspace_id": workspace_id,
        }
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.chmod(file_path, 0o600)
        emit(f"OAuth 文件已生成: {file_path}")

        return {
            "ok": True,
            "data": {
                "message": "OAuth 文件已生成",
                "oauth_file": file_path,
                "account_id": account_id,
                "expires_at": expires_at,
                "workspace_mode": workspace_mode,
                "workspace_id": workspace_id,
            },
            "account_extra_patch": {
                "oauth_file": file_path,
                "oauth_account_id": account_id,
                "oauth_generated_at": generated_at,
                "oauth_workspace_mode": workspace_mode,
                "oauth_workspace_id": workspace_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "session_token": session_token,
            },
        }

    def _action_acquire_rt(self, account: Account, params: dict, proxy) -> dict:
        """Acquire RT with the account's own optional mailbox context.

        Managed MFA requires the stored password/TOTP.  Mailbox access is
        best-effort and is used only if OAuth adds an email challenge.
        """
        from core.config_store import config_store

        log_fn = params.get("_log_fn") or print
        extra = dict(account.extra or {})
        extra.pop("chatgpt_totp_secret", None)
        from services.chatgpt_security_store import (
            get_chatgpt_security_password,
            get_chatgpt_security_status,
        )

        try:
            security_status = get_chatgpt_security_status(account.email)
        except Exception:
            return {
                "ok": False,
                "error": "账号安全状态读取失败，已停止 OAuth 登录",
            }
        mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
        has_stored_totp = bool(security_status.get("has_totp")) or mfa_state in {
            "pending",
            "enabled",
            "unmanaged",
        }
        if not bool(security_status.get("credentials_readable", True)):
            return {
                "ok": False,
                "error": (
                    "账号 Authenticator 凭据无法解密，请检查加密密钥配置"
                    if has_stored_totp
                    else "账号安全凭据无法解密，请检查加密密钥配置"
                ),
            }
        try:
            stored_password = (
                get_chatgpt_security_password(account.email)
                if bool(security_status.get("has_password"))
                else ""
            )
        except Exception:
            return {
                "ok": False,
                "error": "账号安全凭据无法解密，请检查加密密钥配置",
            }
        if stored_password:
            # Some internal workflows call this method directly instead of
            # passing through api.actions._to_platform_account.
            account.password = str(stored_password)
        email_domain = (account.email.split("@", 1)[-1] if "@" in (account.email or "") else "").lower()
        business_domain = str(extra.get("business_domain") or "").strip().lower() or email_domain
        account_type = str(extra.get("account_type", "")).upper()
        is_business = (account_type == "BUSINESS")
        mail_provider = _oauth_mail_provider(account.email, extra)
        if not email_domain:
            return {"ok": False, "error": "账号邮箱无效(缺 @ 域名)"}
        if has_stored_totp and (
            not stored_password or not bool(security_status.get("has_totp"))
        ):
            return {
                "ok": False,
                "error": (
                    "账号已启用 Authenticator，但本地 ChatGPT 密码或 "
                    "Authenticator 密钥不完整，无法获取 RT"
                ),
            }
        # 未开启 2FA 时，注入 OTP 邮箱适配器即可无密码登录；开启 2FA
        # 后必须使用上面从加密安全仓库读取的 ChatGPT 密码。
        if not account.password and not params.get("_otp_email_adapter"):
            return {"ok": False, "error": "账号缺密码,无法登录补 RT(且未注入 OTP 邮箱适配器)"}
        if not is_business:
            log_fn(f"[补 RT] 非 BUSINESS 账号(domain={email_domain}),走同一条 OAuth login 链路")

        api_url = str(config_store.get("cfworker_api_url", "") or "").strip().rstrip("/")
        admin_token = str(config_store.get("cfworker_admin_token", "") or "").strip()
        custom_auth = str(config_store.get("cfworker_custom_auth", "") or "").strip()
        # 调用方可注入自带 OTP 适配器(如 outlook 母号读自己的收件箱);有它就不强依赖 CF Worker。
        injected_otp_adapter = params.get("_otp_email_adapter")
        if injected_otp_adapter is None:
            try:
                mail_extra = dict(extra)
                mail_extra.setdefault("cfworker_api_url", api_url)
                injected_otp_adapter = self._build_optional_oauth_email_adapter(
                    account, mail_extra, proxy=proxy or "", log_fn=log_fn,
                )
            except Exception:
                # Provider errors can contain mail tokens/passwords.  A
                # missing optional mailbox must not stop password + TOTP.
                log_fn("[补 RT] 当前账号邮箱暂不可用；如页面追加邮箱验证，将提示配置或取件失败")
        if not has_stored_totp and injected_otp_adapter is None and mail_provider not in {"", "cfworker", "cfworker_admin"}:
            return {"ok": False, "error": "当前账号邮箱取码配置不可用，无法完成 OAuth 邮箱验证"}
        if (
            not has_stored_totp
            and not injected_otp_adapter
            and (not api_url or not admin_token)
        ):
            return {
                "ok": False,
                "error": "全局未配置 cfworker_api_url / cfworker_admin_token（无法读 OAuth login OTP）",
            }

        synthetic_extra_config = {
            "cfworker_api_url": api_url,
            "cfworker_admin_token": admin_token,
            "cfworker_custom_auth": custom_auth,
            "_oauth_mail_provider": mail_provider,
            "chatgpt_oauth_output_dir": str(
                config_store.get("chatgpt_oauth_output_dir", "") or "oauth_out"
            ).strip() or "oauth_out",
            "business_switch_to_codex": _switch_codex_pref_value(extra),
        }
        requested_output_dir = str(params.get("output_dir") or "").strip()
        if requested_output_dir:
            synthetic_extra_config["chatgpt_oauth_output_dir"] = requested_output_dir
        if injected_otp_adapter is not None:
            synthetic_extra_config["_otp_email_adapter"] = injected_otp_adapter
        # 本次调用允许覆盖全局 business_rt_oauth_browser_mode (前端 action 参数弹框选的)
        user_browser_mode = str(params.get("browser_mode") or "").strip().lower()
        if user_browser_mode in ("protocol", "headless", "headed"):
            synthetic_extra_config["business_rt_oauth_browser_mode"] = user_browser_mode
            log_fn(f"[补 RT] 本次 OAuth 浏览器模式: {user_browser_mode} (来自 action 参数,覆盖全局)")
        if has_stored_totp:
            configured_mode = str(
                synthetic_extra_config.get("business_rt_oauth_browser_mode") or ""
            ).strip().lower()
            if configured_mode != "headed":
                synthetic_extra_config["business_rt_oauth_browser_mode"] = "headless"
            log_fn("[补 RT] 检测到 Authenticator 安全状态，强制使用浏览器 OAuth")
        # 把 add_phone 阶段所有可能用到的 phone/SMS 全局配置都注入
        # 三条路径任一可走通即可:
        #   1) chatgpt_phone_number + chatgpt_phone_otp_code(s)   固定号 + 预设 OTP
        #   2) chatgpt_add_phone_number + chatgpt_add_phone_sms_api_url   固定号 + 轮询 SMS API
        #   3) smstome_cookie / 号码池文件                                SMSToMe 自动接管
        try:
            all_cfg = config_store.get_all() or {}
        except Exception:
            all_cfg = {}
        for key, val in all_cfg.items():
            sk = str(key)
            if (sk.startswith("smstome_")
                or sk.startswith("smsbower_")
                or sk.startswith("chatgpt_add_phone_")
                or sk.startswith("chatgpt_phone_")
                or sk in ("openai_phone_number", "phone_number")):
                synthetic_extra_config[sk] = val
        # _handle_add_phone_verification 走 chatgpt_phone_number 路径，
        # 而 chatgpt_add_phone_number 是 generate_oauth_json_protocol 的命名习惯；
        # 这里做个别名兼容：如果只配了 add_phone_number，就同时填到 chatgpt_phone_number
        if (not synthetic_extra_config.get("chatgpt_phone_number")
                and synthetic_extra_config.get("chatgpt_add_phone_number")):
            synthetic_extra_config["chatgpt_phone_number"] = (
                synthetic_extra_config["chatgpt_add_phone_number"]
            )

        has_phone = bool(synthetic_extra_config.get("chatgpt_phone_number"))
        has_sms_api = bool(synthetic_extra_config.get("chatgpt_add_phone_sms_api_url"))
        has_smstome = bool(synthetic_extra_config.get("smstome_cookie"))
        has_smsbower = bool(synthetic_extra_config.get("smsbower_api_key"))
        if not (has_phone or has_smstome or has_smsbower):
            log_fn("[补 RT] 警告：未配置任何手机号方案（chatgpt_phone_number / smstome_cookie / smsbower_api_key），命中 add_phone 将失败")
        elif has_smsbower:
            log_fn("[补 RT] add_phone 方案: smsbower 付费接码"
                   + (" + SMSToMe 兜底" if has_smstome else "")
                   + (" + 固定号兜底" if has_phone else ""))
        elif has_phone and has_sms_api:
            log_fn("[补 RT] add_phone 方案: 固定号 + SMS API 轮询")
        elif has_phone:
            log_fn("[补 RT] add_phone 方案: 固定号 + 预设 OTP")
        else:
            log_fn("[补 RT] add_phone 方案: SMSToMe 号码池")

        log_fn(f"[补 RT] 开始为 {account.email} 跑 OAuth login 拿 RT")
        # 自动重试 + 指数退避: OpenAI 对短时间反复登录的账号会逐级升级风控
        #   1) 409 session is no longer valid
        #   2) 403 Cloudflare Just a moment 人机挑战
        # 两种都需要等会话/挑战过期再试。退避序列设较长,避免触发更严的封禁。
        backoff_delays = [0, 120, 300, 600]  # 0s → 2min → 5min → 10min
        rt_extra = None
        last_exc: Exception | None = None
        for attempt, delay in enumerate(backoff_delays, start=1):
            if delay > 0:
                log_fn(f"[补 RT] 第 {attempt}/{len(backoff_delays)} 次尝试,先等 {delay}s 让 OpenAI 风控冷却...")
                time.sleep(delay)
            try:
                rt_extra = self._acquire_rt_via_oauth_login(
                    account.email, account.password, proxy or None,
                    synthetic_extra_config, log_fn,
                )
                if rt_extra and rt_extra.get("refresh_token"):
                    break
                last_exc = RuntimeError("OAuth 登录未返回 refresh_token")
            except Exception as exc:
                last_exc = exc
                msg = str(exc)
                msg_low = msg.lower()
                # 风控/会话/Cloudflare 类错误,等冷却再试
                retriable = (
                    "session is no longer valid" in msg_low
                    or "invalid_request_error" in msg_low
                    or "just a moment" in msg_low  # Cloudflare 人机挑战
                    or "challenge-platform" in msg_low
                    or "403" in msg
                    or "409" in msg
                    or "429" in msg
                )
                if not retriable:
                    log_fn(f"[补 RT] 不可重试错误,立即终止: {msg[:160]}")
                    break
                log_fn(f"[补 RT] 第 {attempt} 次失败 (可重试): {msg[:160]}")
        if not rt_extra or not rt_extra.get("refresh_token"):
            err = str(last_exc) if last_exc else "OAuth 登录未返回 refresh_token"
            return {"ok": False, "error": err}

        switch_codex = (
            False
            if bool(params.get("_skip_seat_switch"))
            else _read_switch_codex_flag(extra)
        )
        patch = {
            "access_token": rt_extra.get("access_token", "") or extra.get("access_token", ""),
            "refresh_token": rt_extra["refresh_token"],
            "id_token": rt_extra.get("id_token", "") or extra.get("id_token", ""),
            "session_token": rt_extra.get("session_token", "") or extra.get("session_token", ""),
            "chatgpt_registration_mode": "refresh_token",
            "chatgpt_has_refresh_token_solution": True,
            "register_mode": extra.get("register_mode") or "oauth_business",
            "business_switch_to_codex": _switch_codex_pref_value(extra),
        }

        # 拿到 RT 后，如果当前还没切 Codex 席位，自动切一次
        # （此时 RT 已颁发，OpenAI 不再要求 add_phone）
        if switch_codex and not extra.get("seat_switched_to_codex_at"):
            log_fn("[补 RT] 拿到 RT，开始切换 Codex 席位")
            _switch_business_seat_to_codex(
                patch, log_fn, proxy=proxy, enabled=True,
            )
            # _switch 会写 patch["seat_type"] / patch["seat_switched_to_codex_at"]
        elif not switch_codex:
            log_fn("[补 RT] 已拿到 RT，按配置跳过 Codex 席位切换")

        # 同步重写 oauth_file（CPA 格式 = generate_token_json 输出）
        merged_extra = dict(extra)
        merged_extra.update({k: v for k, v in patch.items() if v})
        view_account = Account(
            platform=account.platform,
            email=account.email,
            password=account.password,
            user_id=account.user_id,
            token=patch["access_token"],
            extra=merged_extra,
        )
        self._dump_business_oauth_file(view_account, synthetic_extra_config, log_fn)
        if view_account.extra.get("oauth_file"):
            patch["oauth_file"] = view_account.extra["oauth_file"]
            log_fn(f"[补 RT] CPA 格式文件已生成: {patch['oauth_file']}")

        log_fn("[补 RT] ✅ 完成: RT=已获取（内容不写入日志）")
        return {
            "ok": True,
            "data": {
                "access_token": patch["access_token"],
                "refresh_token": patch["refresh_token"],
                "id_token": patch["id_token"],
                "oauth_file": patch.get("oauth_file", ""),
            },
            "account_extra_patch": patch,
        }

    def _action_setup_security(self, account: Account, params: dict, proxy) -> dict:
        """Retry/verify the post-registration password + Authenticator setup."""
        from platforms.chatgpt.account_security import (
            VerifiedUnsubmittedPasswordEvidence,
            _safe_error,
            _session_cookie_from_map,
            configure_registered_account_security,
        )
        from services.chatgpt_security_store import get_chatgpt_security_status

        # In-process preparation can continue before the login helper closes
        # its page. This is not a browser ID or an HTTP-supplied configuration:
        # JSON values must never become a trusted live browser reference.
        browser_page = params.get("_browser_page")
        if browser_page is not None and not all(
            callable(getattr(browser_page, name, None)) for name in ("get", "run_js", "quit")
        ):
            return {"ok": False, "error": "无法复用登录浏览器：内部页面引用无效，尚未开始安全设置"}
        browser_kwargs = {"page": browser_page} if browser_page is not None else {}
        confirmation_mode = params.get("_confirmation_mode", "independent")
        if confirmation_mode not in {"independent", "in_session"}:
            return {"ok": False, "error": "账号安全确认模式无效，尚未开始安全设置"}
        audited_candidate = params.get("_verified_unsubmitted_password")
        candidate_kwargs = ({"verified_unsubmitted_password": audited_candidate}
                            if type(audited_candidate) is VerifiedUnsubmittedPasswordEvidence else {})

        log_fn = params.get("_log_fn") or print
        extra = account.extra or {}
        stored = get_chatgpt_security_status(account.email)
        password_flag = str(extra.get("password_set_proven") or "").strip().lower()
        stored_password_state = str(stored.get("password_state") or "")
        password_proven = (
            stored_password_state == "configured"
            or (stored_password_state in {"", "not_configured"}
                and password_flag in {"1", "true", "yes", "on"})
        )
        can_verify_saved_password = bool(stored.get("has_password")) and stored_password_state in {"pending", "unknown"}

        def unavailable(error: str) -> dict:
            from services.chatgpt_security_progress import normalize_security_progress

            progress = normalize_security_progress({
                "stage": "session_check", "status": "failed", "code": "security_failed",
                "reason": "安全设置所需邮箱配置不可用，尚未开始远端设置",
                "retry_mode": "manual", "retry_attempt": 0, "retry_limit": 0,
                "completed_stages": [],
            })
            callback = params.get("_progress_fn")
            if callable(callback):
                try:
                    callback(dict(progress))
                except Exception:
                    pass
            return {"ok": False, "data": {"message": "ChatGPT 安全设置未完成",
                    "security": {**stored, "security_progress": progress}}, "error": error}

        browser_mode = str(params.get("browser_mode") or "headless").strip().lower()
        password_link_provider = None
        password_code_provider = None
        try:
            (
                password_link_provider,
                password_code_provider,
            ) = self._build_persisted_security_mail_providers(
                account,
                proxy=proxy or "",
                log_fn=log_fn,
            )
        except Exception as exc:
            if not password_proven and not can_verify_saved_password:
                error = _safe_error(exc)
                log_fn(f"[账号安全] 邮箱读取器初始化失败：{error}")
                return unavailable(error)
            # A proven password remains sufficient for the ordinary
            # password/TOTP route.  Keep mailbox recovery optional, but make it
            # available whenever credentials exist because OpenAI can append an
            # email-verification challenge after a correct password.
            log_fn("[账号安全] 可选邮箱验证码读取器不可用；若登录追加邮箱校验将安全停止")
        if not password_proven and not can_verify_saved_password and not callable(password_code_provider):
            error = "该账号缺少可读取验证码的邮箱配置，无法补设密码"
            log_fn(f"[账号安全] {error}")
            return unavailable(error)
        result = configure_registered_account_security(
            email=account.email,
            password=account.password,
            password_set_proven=password_proven,
            cookies=extra.get("cookies"),
            session_token=str(extra.get("session_token") or ""),
            proxy=proxy or "",
            headless=browser_mode != "headed",
            enable_totp=True,
            log_fn=log_fn,
            progress_fn=params.get("_progress_fn"),
            **candidate_kwargs,
            password_link_provider=password_link_provider,
            password_code_provider=password_code_provider,
            # Ownership stays with the caller. The security helper still
            # creates/owns a clean browser when independently proving a newly
            # submitted password; an authenticated page is not password proof.
            **browser_kwargs,
            confirmation_mode=confirmation_mode,
        )
        patch: dict = {"chatgpt_security": result.safe_dict()}
        if result.cookies:
            patch["cookies"] = json.dumps(result.cookies, ensure_ascii=False)
            refreshed_session = _session_cookie_from_map(result.cookies)
            if refreshed_session:
                patch["session_token"] = refreshed_session
        if result.ok and result.password_state == "configured":
            patch["password_set_proven"] = True
        return {
            "ok": result.ok,
            "data": {
                "message": (
                    "ChatGPT 密码与 Authenticator 2FA 已确认"
                    if result.ok
                    else "ChatGPT 安全设置未完成"
                ),
                "security": result.safe_dict(),
            },
            "error": result.error if not result.ok else "",
            "account_extra_patch": patch,
        }

    def _action_switch_codex_seat(self, account: Account, params: dict, proxy) -> dict:
        """手动切换 Codex 席位 action（独立于 acquire_rt）。

        场景：RT 已拿到但 Codex 切换失败（母号 Cookie 失效、网络抖动等）；
        或用户在 ChatGPT 席位下需要单独切到 Codex。
        """
        return self._action_switch_seat(account, params, proxy, target="usage_based")

    def _action_switch_chatgpt_seat(self, account: Account, params: dict, proxy) -> dict:
        """手动切回 ChatGPT 普通席位 (seat_type='default')。

        场景：原本是 Codex (usage_based) 席位的子账号要回归 ChatGPT 套餐。
        """
        return self._action_switch_seat(account, params, proxy, target="default")

    def _action_switch_seat(self, account: Account, params: dict, proxy, *,
                            target: str) -> dict:
        """统一的席位切换 action 实现 (target = 'usage_based' | 'default')。"""
        log_fn = params.get("_log_fn") or print
        target_label = "Codex" if target == "usage_based" else "ChatGPT"
        extra = account.extra or {}
        if str(extra.get("account_type", "")).upper() != "BUSINESS":
            return {"ok": False, "error": f"账号不是 BUSINESS 账号，无法切换 {target_label} 席位"}
        if not (extra.get("access_token") or account.token):
            return {"ok": False, "error": "账号缺少 access_token，无法切换席位"}

        if extra.get("seat_type") == target:
            log_fn(f"[切 {target_label}] 账号已是 {target_label} 席位 (seat_type={target})，将再切一次确认状态")

        # _switch_business_seat_to_codex 会原地写入 patch
        patch: dict = {"access_token": extra.get("access_token") or account.token}
        _switch_business_seat_to_codex(patch, log_fn, proxy=proxy, enabled=True, target=target)

        if patch.get("seat_type") != target:
            return {"ok": False, "error": f"{target_label} 席位切换失败（详见日志）"}

        # 只回写 seat_* 字段,不动 access_token
        ts_field = "seat_switched_to_codex_at" if target == "usage_based" else "seat_switched_to_chatgpt_at"
        result_patch = {
            "seat_type": patch.get("seat_type"),
            ts_field: patch.get(ts_field),
        }
        return {
            "ok": True,
            "data": {"seat_type": target},
            "account_extra_patch": result_patch,
        }

    def get_platform_actions(self) -> list:
        return [
{"id": "probe_local_status", "label": "探测本地状态", "params": []},
            {"id": "sync_cliproxyapi_status", "label": "同步 CLIProxyAPI 状态", "params": []},
            {"id": "refresh_token", "label": "刷新 Token", "params": []},
            {
                "id": "generate_oauth_file",
                "label": "生成 OAuth 文件",
                "params": [
                    {
                        "key": "workspace_mode",
                        "label": "空间",
                        "type": "select",
                        "options": [
                            {"value": "default", "label": "默认空间"},
                            {"value": "personal", "label": "个人空间"},
                            {"value": "workspace", "label": "指定 Workspace ID"},
                        ],
                    },
                    {"key": "workspace_id", "label": "Workspace ID", "type": "text"},
                    {"key": "output_dir", "label": "输出目录", "type": "text"},
                ],
            },
            {
                "id": "payment_link",
                "label": "生成支付链接",
                "params": [
                    {"key": "country", "label": "地区", "type": "select", "options": ["US", "SG", "TR", "HK", "JP", "GB", "AU", "CA"]},
                    {"key": "plan", "label": "套餐", "type": "select", "options": ["plus", "team"]},
                ],
            },
            {
                "id": "upload_cpa",
                "label": "上传 CPA",
                "params": [
                    {"key": "api_url", "label": "CPA API URL", "type": "text"},
                    {"key": "api_key", "label": "CPA API Key", "type": "text"},
                ],
            },
            {
                "id": "upload_sub2api",
                "label": "上传 Sub2API",
                "params": [
                    {"key": "api_url", "label": "Sub2API API URL", "type": "text"},
                    {"key": "api_key", "label": "Sub2API API Key", "type": "text"},
                ],
            },
            {
                "id": "upload_tm",
                "label": "上传 Team Manager",
                "params": [
                    {"key": "api_url", "label": "TM API URL", "type": "text"},
                    {"key": "api_key", "label": "TM API Key", "type": "text"},
                ],
            },
            {"id": "upgrade_business", "label": "升级 Business", "params": []},
            {
                "id": "acquire_rt",
                "label": "补 RT (BUSINESS 二阶段登录)",
                "params": [
                    {
                        "key": "browser_mode",
                        "label": "OAuth 浏览器模式",
                        "type": "select",
                        "options": [
                            {"value": "headless", "label": "无头 (默认,推荐)"},
                            {"value": "headed", "label": "有头 (调试用,可见)"},
                            {"value": "protocol", "label": "纯协议 (快,新流程下易卡)"},
                        ],
                    },
                ],
            },
            {
                "id": "setup_security",
                "label": "设置密码与 2FA",
                "params": [
                    {
                        "key": "browser_mode",
                        "label": "浏览器模式",
                        "type": "select",
                        "options": [
                            {"value": "headless", "label": "无头 (默认)"},
                            {"value": "headed", "label": "有头 (调试)"},
                        ],
                    },
                ],
            },
            {"id": "switch_codex_seat", "label": "切换为 Codex 席位", "params": []},
            {"id": "switch_chatgpt_seat", "label": "切换为 ChatGPT 席位", "params": []},
            {
                "id": "upload_codex_proxy",
                "label": "上传 CodexProxy",
                "params": [
                    {"key": "api_url", "label": "API URL", "type": "text"},
                    {"key": "api_key", "label": "Admin Key", "type": "text"},
                ],
            },
        ]

    def execute_action(self, action_id: str, account: Account, params: dict) -> dict:
        proxy = self.config.proxy if self.config else None
        if not proxy:
            from core.config_store import config_store
            proxy = str(config_store.get("default_proxy", "") or "").strip() or None
        extra = account.extra or {}

        class _A:
            pass

        a = _A()
        a.email = account.email
        a.access_token = extra.get("access_token") or account.token
        chatgpt_oauth = _chatgpt_oauth_credentials(extra)
        a.refresh_token = chatgpt_oauth["refresh_token"]
        a.id_token = extra.get("id_token", "")
        a.session_token = extra.get("session_token", "")
        a.client_id = chatgpt_oauth["client_id"]
        a.cookies = extra.get("cookies", "")
        a.user_id = account.user_id

        if action_id == "probe_local_status":
            from platforms.chatgpt.status_probe import probe_local_chatgpt_status

            probe_result = probe_local_chatgpt_status(a, proxy=proxy)
            summary = (
                f"认证={probe_result.get('auth', {}).get('state', 'unknown')}, "
                f"订阅={probe_result.get('subscription', {}).get('plan', 'unknown')}, "
                f"Codex={probe_result.get('codex', {}).get('state', 'unknown')}"
            )
            return {
                "ok": True,
                "data": {
                    "message": f"本地状态探测完成：{summary}",
                    "probe": probe_result,
                },
                "account_extra_patch": {
                    "chatgpt_local": probe_result,
                },
            }

        if action_id == "sync_cliproxyapi_status":
            from services.cliproxyapi_sync import sync_chatgpt_cliproxyapi_status

            sync_result = sync_chatgpt_cliproxyapi_status(a)
            ok = bool(sync_result.get("uploaded")) and sync_result.get("remote_state") not in {"unreachable", "not_found"}
            summary = (
                f"远端状态={sync_result.get('status') or 'not_found'}, "
                f"探测={sync_result.get('remote_state') or 'not_checked'}"
            )
            return {
                "ok": ok,
                "data": {
                    "message": f"CLIProxyAPI 状态同步完成：{summary}",
                    "sync": sync_result,
                },
                "error": sync_result.get("message") if not ok else "",
                "account_extra_patch": {
                    "sync_statuses": {
                        "cliproxyapi": sync_result,
                    },
                },
            }

        if action_id == "refresh_token":
            from platforms.chatgpt.token_refresh import TokenRefreshManager

            manager = TokenRefreshManager(proxy_url=proxy)
            result = manager.refresh_account(a)
            if result.success:
                return {
                    "ok": True,
                    "data": {
                        "access_token": result.access_token,
                        "refresh_token": result.refresh_token,
                    },
                }
            return {"ok": False, "error": result.error_message}

        if action_id == "generate_oauth_file":
            # ProtocolOAuthClient and the legacy subprocess do not implement
            # Authenticator challenges.  Reuse the canonical RT browser flow
            # for enrolled accounts; it also writes the same CPA OAuth JSON.
            try:
                from services.chatgpt_security_store import (
                    get_chatgpt_security_status,
                )

                security_status = get_chatgpt_security_status(account.email)
            except Exception:
                return {
                    "ok": False,
                    "error": "账号安全状态读取失败，已停止 OAuth 文件生成",
                }
            mfa_state = str(
                security_status.get("mfa_state") or ""
            ).strip().lower()
            has_stored_totp = bool(
                security_status.get("has_totp")
            ) or mfa_state in {"pending", "enabled", "unmanaged"}
            if not bool(security_status.get("credentials_readable", True)):
                return {
                    "ok": False,
                    "error": (
                        "账号 Authenticator 凭据无法解密，请检查加密密钥配置"
                        if has_stored_totp
                        else "账号安全凭据无法解密，请检查加密密钥配置"
                    ),
                }
            if has_stored_totp:
                rt_params = dict(params)
                rt_params["_skip_seat_switch"] = True
                rt_params["browser_mode"] = (
                    "headless"
                    if str(params.get("headless", "1")).strip().lower()
                    not in ("0", "false", "no", "off")
                    else "headed"
                )
                log_fn = params.get("_log_fn") or print
                # Keep an injected mailbox for a possible additional email
                # challenge; the canonical action may restore one optionally.
                log_fn(
                    "账号已启用 Authenticator 2FA，使用密码 + 动态码的统一浏览器 OAuth 流程；追加邮箱验证按需处理"
                )
                return self._action_acquire_rt(account, rt_params, proxy)
            # 默认走协议 OAuth(Linux 友好,add_phone 自动接管);
            # 显式 params.use_browser=1 / use_protocol=0 才走浏览器路径
            raw = str(params.get("use_protocol", "1")).strip().lower()
            use_protocol = raw not in ("0", "false", "no", "off")
            if str(params.get("use_browser", "")).strip().lower() in ("1", "true", "yes"):
                use_protocol = False
            if use_protocol:
                return self._generate_oauth_file(account, params, proxy)
            try:
                return self._generate_oauth_file_browser(account, params, proxy)
            except Exception as e:
                # 浏览器路径异常,降级到协议 OAuth
                fallback = self._generate_oauth_file(account, params, proxy)
                if isinstance(fallback, dict):
                    fallback.setdefault("data", {})["browser_error"] = str(e)[:200]
                return fallback

        if action_id == "payment_link":
            from platforms.chatgpt.payment import generate_plus_link, generate_team_link

            plan = params.get("plan", "plus")
            country = params.get("country", "US")
            if plan == "plus":
                url = generate_plus_link(a, proxy=proxy, country=country)
            else:
                url = generate_team_link(
                    a,
                    workspace_name=params.get("workspace_name", "MyTeam"),
                    price_interval=params.get("price_interval", "month"),
                    seat_quantity=int(params.get("seat_quantity", 5) or 5),
                    proxy=proxy,
                    country=country,
                )
            return {"ok": bool(url), "data": {"url": url}}

        if action_id == "upload_cpa":
            from platforms.chatgpt.cpa_upload import generate_token_json, upload_to_cpa

            token_data = generate_token_json(a)
            ok, msg = upload_to_cpa(
                token_data,
                api_url=params.get("api_url"),
                api_key=params.get("api_key"),
            )
            return {"ok": ok, "data": msg}

        if action_id == "upload_sub2api":
            from platforms.chatgpt.sub2api_upload import upload_to_sub2api

            ok, msg = upload_to_sub2api(
                a,
                api_url=params.get("api_url"),
                api_key=params.get("api_key"),
            )
            return {"ok": ok, "data": msg}

        if action_id == "upload_tm":
            from platforms.chatgpt.cpa_upload import upload_to_team_manager

            ok, msg = upload_to_team_manager(
                a,
                api_url=params.get("api_url"),
                api_key=params.get("api_key"),
            )
            return {"ok": ok, "data": msg}

        if action_id == "upgrade_business":
            from datetime import datetime, timezone

            from platforms.chatgpt.business_upgrade import invite_business_emails

            ok, msg, data = invite_business_emails(
                [account.email],
                api_url=params.get("api_url"),
                api_key=params.get("api_key"),
                team_id=params.get("team_id"),
                verify=params.get("verify"),
                stop_on_error=params.get("stop_on_error"),
            )
            now = datetime.now(timezone.utc).isoformat()
            team_id = data.get("team_id") if isinstance(data, dict) else None
            patch = {
                "team_manager_business": {
                    "status": "invited" if ok else "failed",
                    "team_id": team_id,
                    "message": msg,
                    "updated_at": now,
                }
            }
            if ok:
                patch["team_manager_business"]["invited_at"] = now
            return {
                "ok": ok,
                "data": {
                    "message": msg,
                    "status_code": data.get("status_code") if isinstance(data, dict) else None,
                    "team_id": team_id,
                },
                "error": "" if ok else msg,
                "account_extra_patch": patch,
            }

        if action_id == "acquire_rt":
            return self._action_acquire_rt(account, params, proxy)

        if action_id == "setup_security":
            return self._action_setup_security(account, params, proxy)

        if action_id == "switch_codex_seat":
            return self._action_switch_codex_seat(account, params, proxy)

        if action_id == "switch_chatgpt_seat":
            return self._action_switch_chatgpt_seat(account, params, proxy)

        if action_id == "upload_codex_proxy":
            upload_type = str(
                params.get("upload_type")
                or (self.config.extra or {}).get("codex_proxy_upload_type")
                or "at"
            ).strip().lower()

            if upload_type == "rt":
                from platforms.chatgpt.cpa_upload import upload_to_codex_proxy

                ok, msg = upload_to_codex_proxy(
                    a,
                    api_url=params.get("api_url"),
                    api_key=params.get("api_key"),
                )
            else:
                from platforms.chatgpt.cpa_upload import upload_at_to_codex_proxy

                ok, msg = upload_at_to_codex_proxy(
                    a,
                    api_url=params.get("api_url"),
                    api_key=params.get("api_key"),
                )
            return {"ok": ok, "data": msg}

        raise NotImplementedError(f"未知操作: {action_id}")
