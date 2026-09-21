"""GPT2WEB token import helpers."""

from __future__ import annotations

import json
import logging
import time
from http.cookies import SimpleCookie
from typing import Any, Tuple

from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "__Secure-next-auth.session-token"


def _get_config_value(key: str) -> str:
    try:
        from core.config_store import config_store

        return str(config_store.get(key, "") or "").strip()
    except Exception:
        return ""


def _parse_json_text(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def _extract_from_cookie_map(cookies: dict[str, Any]) -> str:
    token = str(cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if token:
        return token

    parts: list[str] = []
    for i in range(10):
        value = str(cookies.get(f"{SESSION_COOKIE_NAME}.{i}") or "").strip()
        if not value:
            break
        parts.append(value)
    return "".join(parts).strip()


def _extract_from_cookie_list(cookies: list[Any]) -> str:
    cookie_map: dict[str, Any] = {}
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            cookie_map[name] = item.get("value", "")
    return _extract_from_cookie_map(cookie_map)


def _extract_from_cookie_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""

    parsed = _parse_json_text(raw)
    if isinstance(parsed, dict):
        cookie_obj = parsed.get("cookies") if isinstance(parsed.get("cookies"), dict) else parsed
        return _extract_from_cookie_map(cookie_obj)
    if isinstance(parsed, list):
        return _extract_from_cookie_list(parsed)

    if SESSION_COOKIE_NAME in raw and "=" in raw:
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
            morsel = cookie.get(SESSION_COOKIE_NAME)
            if morsel and str(morsel.value).strip():
                return str(morsel.value).strip()
        except Exception:
            pass

        marker = f"{SESSION_COOKIE_NAME}="
        idx = raw.find(marker)
        if idx >= 0:
            value = raw[idx + len(marker):].split(";", 1)[0].strip()
            if value:
                return value

    return raw


def extract_session_token(account: Any) -> str:
    """Extract ChatGPT session-token from a saved account-like object."""
    extra: dict[str, Any] = {}
    if hasattr(account, "get_extra"):
        try:
            loaded = account.get_extra()
            if isinstance(loaded, dict):
                extra = loaded
        except Exception:
            extra = {}
    elif isinstance(getattr(account, "extra", None), dict):
        extra = getattr(account, "extra")

    for value in (
        extra.get("session_token"),
        extra.get("sessionToken"),
        extra.get("st"),
        getattr(account, "session_token", ""),
        getattr(account, "sessionToken", ""),
        getattr(account, "st", ""),
    ):
        token = _extract_from_cookie_text(str(value or ""))
        if token:
            return token

    cookies = extra.get("cookies") or getattr(account, "cookies", "")
    if isinstance(cookies, dict):
        token = _extract_from_cookie_map(cookies)
    elif isinstance(cookies, list):
        token = _extract_from_cookie_list(cookies)
    else:
        token = _extract_from_cookie_text(str(cookies or ""))
    if token:
        return token

    # `AccountModel.token` is usually an access_token, so only trust an explicit
    # extra.token value for GPT2WEB's ST-compatible import format.
    return _extract_from_cookie_text(str(extra.get("token") or ""))


def _load_account_extra(account: Any) -> dict[str, Any]:
    if hasattr(account, "get_extra"):
        try:
            loaded = account.get_extra()
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            return {}
    extra = getattr(account, "extra", None)
    return extra if isinstance(extra, dict) else {}


def extract_refresh_token(account: Any) -> str:
    extra = _load_account_extra(account)
    for value in (
        extra.get("refresh_token"),
        extra.get("refreshToken"),
        extra.get("rt"),
        getattr(account, "refresh_token", ""),
        getattr(account, "refreshToken", ""),
        getattr(account, "rt", ""),
    ):
        token = str(value or "").strip()
        if token:
            return token
    return ""


def extract_access_token(account: Any) -> str:
    extra = _load_account_extra(account)
    for value in (
        extra.get("access_token"),
        extra.get("accessToken"),
        extra.get("at"),
        getattr(account, "access_token", ""),
        getattr(account, "accessToken", ""),
        getattr(account, "at", ""),
        getattr(account, "token", ""),
    ):
        token = str(value or "").strip()
        if token:
            return token
    return ""


def extract_client_id(account: Any) -> str:
    extra = _load_account_extra(account)
    for value in (
        extra.get("client_id"),
        extra.get("clientId"),
        getattr(account, "client_id", ""),
        getattr(account, "clientId", ""),
    ):
        client_id = str(value or "").strip()
        if client_id:
            return client_id
    return "app_EMoamEEZ73f0CkXaXp7hrann"


def extract_import_token(account: Any) -> tuple[str, str, str]:
    """Return the best GPT2WEB import mode, token, and client_id for an account."""
    access_token = extract_access_token(account)
    if access_token:
        return "at", access_token, ""

    refresh_token = extract_refresh_token(account)
    if refresh_token:
        return "rt", refresh_token, extract_client_id(account)

    session_token = extract_session_token(account)
    if session_token:
        return "st", session_token, ""

    return "", "", ""


def fetch_session_token_from_chatgpt(
    access_token: str, *, proxy: str | None = None, timeout: int = 30,
) -> str:
    """GET https://chatgpt.com/api/auth/session 拿 __Secure-next-auth.session-token。

    用 access_token 当 Bearer 调 ChatGPT 的 NextAuth session 接口,
    服务端会通过 Set-Cookie 下发 session-token (即 ST)。
    """
    access_token = str(access_token or "").strip()
    if not access_token:
        return ""

    url = "https://chatgpt.com/api/auth/session"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    proxies = None
    proxy_used = str(proxy or "").strip()
    if proxy_used:
        proxies = {"http": proxy_used, "https": proxy_used}

    try:
        resp = cffi_requests.get(
            url, headers=headers, timeout=timeout,
            verify=True, impersonate="chrome131", proxies=proxies,
        )
    except Exception as exc:
        logger.warning("fetch_session_token: HTTP 异常: %s", exc)
        return ""

    # 1) 先看 Set-Cookie (cookies jar)
    try:
        cookies_obj = getattr(resp, "cookies", None)
        if cookies_obj:
            for cookie in cookies_obj:
                name = getattr(cookie, "name", "") or ""
                if name == SESSION_COOKIE_NAME:
                    val = getattr(cookie, "value", "") or ""
                    if val.strip():
                        return val.strip()
    except Exception:
        pass

    # 2) 兜底:从 Set-Cookie header 文本里抠 (按 .0/.1/... 分片可能存在)
    try:
        raw_set_cookie = getattr(resp, "headers", {}).get("Set-Cookie", "") or ""
    except Exception:
        raw_set_cookie = ""
    if raw_set_cookie:
        chunks: dict[str, str] = {}
        for piece in raw_set_cookie.split(", "):  # 注意 RFC: ", " 是简化分割
            kv = piece.split(";", 1)[0].strip()
            if "=" not in kv:
                continue
            name, val = kv.split("=", 1)
            name = name.strip()
            val = val.strip()
            if name == SESSION_COOKIE_NAME:
                return val
            if name.startswith(f"{SESSION_COOKIE_NAME}."):
                chunks[name] = val
        if chunks:
            parts: list[str] = []
            for i in range(10):
                key = f"{SESSION_COOKIE_NAME}.{i}"
                if key not in chunks:
                    break
                parts.append(chunks[key])
            joined = "".join(parts).strip()
            if joined:
                return joined

    # 3) 最后兜底:响应 body 里如果有 sessionToken / session_token 字段也算
    try:
        body = resp.json() or {}
        for key in ("sessionToken", "session_token"):
            value = str(body.get(key) or "").strip()
            if value:
                return value
    except Exception:
        pass

    return ""


def extract_st_for_gpt2web(
    account: Any, *, proxy: str | None = None,
) -> tuple[str, str]:
    """GPT2WEB 专用:强制返回 ST,缺则用 access_token 在线拿。

    返回 (st, source):
      st="..."           取到的 ST
      source="extra"     来自 account.extra (已有)
      source="fetched"   现场调 /api/auth/session 拿到
      source=""          没拿到
    """
    existing = extract_session_token(account)
    if existing:
        return existing, "extra"

    at = extract_access_token(account)
    if not at:
        return "", ""

    st = fetch_session_token_from_chatgpt(at, proxy=proxy)
    if not st:
        return "", ""

    # 顺手写回 account.extra 给后续复用
    try:
        if hasattr(account, "get_extra") and hasattr(account, "set_extra"):
            extra = account.get_extra() or {}
            extra["session_token"] = st
            account.set_extra(extra)
        elif isinstance(getattr(account, "extra", None), dict):
            account.extra["session_token"] = st
    except Exception:
        pass

    return st, "fetched"


def _extract_error_message(response) -> str:
    message = f"上传失败: HTTP {response.status_code}"
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(
                data.get("message")
                or data.get("msg")
                or data.get("error")
                or data.get("detail")
                or message
            )
    except Exception:
        pass
    text = str(getattr(response, "text", "") or "").strip()
    if text:
        return f"{message} - {text[:200]}"
    return message


def _unwrap_data(data: Any) -> dict:
    if not isinstance(data, dict):
        return {}
    inner = data.get("data")
    if isinstance(inner, dict) and any(
        k in inner for k in ("created", "imported", "updated", "failed", "total", "results")
    ):
        return inner
    return data


def _success_code_failed(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    code = data.get("code")
    if isinstance(code, int) and code != 0:
        return True
    if isinstance(code, str) and code.strip() and code.strip() != "0":
        return True
    return data.get("ok") is False or data.get("success") is False


def _collect_failure_reasons(data: dict) -> list[str]:
    results = data.get("results")
    if not isinstance(results, list):
        return []
    reasons: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if str(item.get("status") or "").lower() != "failed":
            continue
        reason = str(item.get("reason") or item.get("error") or "").strip()
        email = str(item.get("email") or "").strip()
        if reason:
            reasons.append(f"{email}: {reason}" if email and email != "?" else reason)
    return reasons


def _count_successful_imports(data: dict) -> int:
    total = 0
    for key in ("created", "imported", "updated"):
        value = data.get(key)
        if isinstance(value, int):
            total += value
        elif isinstance(value, str) and value.strip().isdigit():
            total += int(value.strip())
    return total


def _format_success_message(data: Any) -> str:
    if not isinstance(data, dict):
        return "上传成功"

    inner = _unwrap_data(data)
    counters = []
    for key, label in (
        ("created", "新增"),
        ("imported", "导入"),
        ("updated", "更新"),
        ("skipped", "跳过"),
        ("failed", "失败"),
    ):
        value = inner.get(key)
        if isinstance(value, int):
            counters.append(f"{label}{value}")
    if counters:
        return "上传成功: " + ", ".join(counters)

    for key in ("message", "msg", "detail"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return "上传成功"


def _extract_failure_message(data: Any, fallback: str = "GPT2WEB 返回失败") -> str:
    if not isinstance(data, dict):
        return fallback
    inner = data.get("data")
    if isinstance(inner, dict):
        for key in ("message", "msg", "error", "detail"):
            value = str(inner.get(key) or "").strip()
            if value:
                return value
    for key in ("message", "msg", "error", "detail"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return fallback


def _evaluate_import_result(data: Any) -> tuple[bool, str]:
    if _success_code_failed(data):
        return False, _extract_failure_message(data)

    inner = _unwrap_data(data)
    failed_count = inner.get("failed")
    if isinstance(failed_count, str) and failed_count.strip().isdigit():
        failed_count = int(failed_count.strip())
    if isinstance(failed_count, int) and failed_count > 0:
        reasons = _collect_failure_reasons(inner)
        summary = _format_success_message(data)
        if reasons:
            summary += " | " + "; ".join(reasons)
        return False, summary

    return True, _format_success_message(data)


def _extract_async_job_id(data: Any) -> str:
    """新版接口同步响应:`{"import_id": "...", "total": N, "message": "importing"}`
    旧接口兼容:`{"async": true, "job_id": "..."}` (data 包一层)
    """
    if not isinstance(data, dict):
        return ""
    candidates: list[dict[str, Any]] = [data]
    inner = data.get("data")
    if isinstance(inner, dict):
        candidates.insert(0, inner)
    for item in candidates:
        # 新版字段
        import_id = str(item.get("import_id") or "").strip()
        if import_id:
            return import_id
        # 旧版字段
        is_async = item.get("async")
        job_id = str(item.get("job_id") or item.get("jobId") or item.get("id") or "").strip()
        if job_id and (is_async is True or str(is_async).lower() == "true"):
            return job_id
    return ""


def _summarize_import_status(payload: dict) -> tuple[bool, str]:
    """新版 /import-status/{id} 响应汇总。

    成功定义: finished=True 且 failed=0;同时 results[] 中失败项的 error 会带出。
    payload 示例:
      {"id": "...", "total": 3, "done": 3, "success": 2, "failed": 1,
       "finished": True,
       "results": [{"st": "...", "ok": True, "email": "..."},
                   {"st": "...", "ok": False, "error": "..."}]}
    """
    total = int(payload.get("total") or 0)
    success = int(payload.get("success") or 0)
    failed = int(payload.get("failed") or 0)
    parts: list[str] = []
    if total:
        parts.append(f"总数 {total}")
    parts.append(f"成功 {success}")
    if failed:
        parts.append(f"失败 {failed}")
    summary_text = "上传完成: " + ", ".join(parts)

    if failed > 0:
        reasons: list[str] = []
        for item in payload.get("results") or []:
            if not isinstance(item, dict) or item.get("ok"):
                continue
            err = str(item.get("error") or item.get("reason") or "").strip()
            tag = str(item.get("email") or item.get("st") or "").strip()
            if err:
                reasons.append(f"{tag}: {err}" if tag else err)
        if reasons:
            summary_text += " | " + "; ".join(reasons[:5])
        return False, summary_text

    return True, summary_text


def _poll_import_job(
    api_url: str,
    api_key: str,
    job_id: str,
    *,
    timeout_seconds: float = 120.0,
    interval_seconds: float = 2.0,
) -> tuple[bool, str]:
    """轮询 GPT2WEB 新版 /api/admin/accounts/import-status/{import_id}。

    新接口响应主要字段: total / done / success / failed / finished / results[]。
    finished=True 时根据 failed 数判定整体成败。
    """
    url = f"{api_url.rstrip('/')}/api/admin/accounts/import-status/{job_id}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    deadline = time.time() + max(float(timeout_seconds or 0), 1.0)

    while time.time() < deadline:
        response = cffi_requests.get(
            url,
            headers=headers,
            proxies=None,
            verify=True,
            timeout=30,
            impersonate="chrome110",
        )
        if response.status_code not in (200, 201):
            return False, _extract_error_message(response)

        try:
            data = response.json()
        except Exception:
            data = {}

        # 新接口直接平铺字段;但仍兼容 {"data": {...}} 旧包装
        payload = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
        if not isinstance(payload, dict):
            payload = {}

        if _success_code_failed(data):
            return False, _extract_failure_message(data)

        finished = bool(payload.get("finished"))
        # 老版兼容: status=done/finished/...
        status = str(payload.get("status") or "").strip().lower()
        if finished or status in {"done", "completed", "complete", "finished", "success"}:
            return _summarize_import_status(payload)
        if status in {"failed", "error", "cancelled", "canceled"}:
            return False, str(payload.get("message") or "GPT2WEB 异步导入失败")

        time.sleep(max(float(interval_seconds or 0), 0.2))

    return False, f"GPT2WEB 异步导入超时: import_id={job_id}"


DEFAULT_POOL = "main"
DEFAULT_PROXY_ID = 0


def upload_tokens_to_gpt2web(
    tokens: list[str],
    api_url: str | None = None,
    api_key: str | None = None,
    *,
    mode: str = "st",
    client_id: str | None = None,
    pool: str | None = None,
    proxy_id: int | None = None,
    # 兼容老调用方:这些参数保留但已废弃,不再发给新接口
    update_existing: bool | None = None,
    default_proxy_id: int | None = None,
) -> Tuple[bool, str]:
    """Import ChatGPT tokens into GPT2WEB (new /api/admin/accounts/import)."""
    api_url = str(api_url or _get_config_value("gpt2web_api_url")).strip()
    api_key = str(api_key or _get_config_value("gpt2web_admin_api_key")).strip()
    if not api_url:
        return False, "GPT2WEB API URL 未配置"
    if not api_key:
        return False, "GPT2WEB Admin 密码未配置"

    clean_tokens = [str(token or "").strip() for token in tokens if str(token or "").strip()]
    if not clean_tokens:
        return False, "账号缺少可导入 token"

    mode = str(mode or "st").strip().lower()
    if mode not in {"st", "rt", "at"}:
        return False, f"GPT2WEB 不支持的导入模式: {mode}"

    # 老参数 default_proxy_id 兼容:-1 → 0(自动);其他原值透传
    if proxy_id is None:
        if default_proxy_id is not None:
            proxy_id = 0 if int(default_proxy_id) < 0 else int(default_proxy_id)
        else:
            proxy_id = DEFAULT_PROXY_ID
    pool_value = str(pool or DEFAULT_POOL).strip().lower() or DEFAULT_POOL

    url = f"{api_url.rstrip('/')}/api/admin/accounts/import"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload: dict[str, Any] = {
        "tokens": clean_tokens,
        "mode": mode,
        "pool": pool_value,
        "proxy_id": int(proxy_id),
    }
    if mode == "rt":
        payload["client_id"] = str(client_id or "app_EMoamEEZ73f0CkXaXp7hrann").strip()

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
        if response.status_code not in (200, 201):
            return False, _extract_error_message(response)

        data = None
        try:
            data = response.json()
        except Exception:
            data = None
        # 新接口同步响应必带 import_id,需轮询拿最终结果
        job_id = _extract_async_job_id(data)
        if job_id:
            return _poll_import_job(api_url, api_key, job_id)
        # 兜底:没拿到 import_id,按老的同步结果解析
        return _evaluate_import_result(data)
    except Exception as exc:
        logger.error("GPT2WEB 上传异常: %s", exc)
        return False, f"上传异常: {exc}"


def upload_to_gpt2web(
    account: Any,
    api_url: str | None = None,
    api_key: str | None = None,
    *,
    pool: str | None = None,
    proxy_id: int | None = None,
    fetch_proxy: str | None = None,
    # 兼容老调用,已废弃
    update_existing: bool | None = None,
    default_proxy_id: int | None = None,
) -> Tuple[bool, str]:
    """Import one ChatGPT account into GPT2WEB.

    GPT2WEB 强制走 ST: 优先用 account.extra 里已有的 session_token;
    没有则用 access_token 调 https://chatgpt.com/api/auth/session 拿到再上传。
    """
    st, source = extract_st_for_gpt2web(account, proxy=fetch_proxy)
    if not st:
        return False, "账号缺少 session_token,且无法从 access_token 在线获取"
    ok, msg = upload_tokens_to_gpt2web(
        [st],
        api_url=api_url,
        api_key=api_key,
        mode="st",
        client_id=None,
        pool=pool,
        proxy_id=proxy_id,
        update_existing=update_existing,
        default_proxy_id=default_proxy_id,
    )
    return ok, f"ST({source}): {msg}"
