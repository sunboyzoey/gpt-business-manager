"""ChatGPT Business invitation helper."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Tuple

from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)


def _get_config_value(key: str, default: str = "") -> str:
    try:
        from core.config_store import config_store

        return str(config_store.get(key, default) or "").strip()
    except Exception:
        return default


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on", "y"}


def _normalize_emails(emails: Iterable[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in emails or []:
        email = str(raw or "").strip()
        if not email:
            continue
        key = email.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(email)
    return normalized


def _normalize_team_id(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        team_id = int(text)
    except (TypeError, ValueError):
        return None
    return team_id if team_id > 0 else None


def _response_json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return {"raw": str(getattr(response, "text", "") or "")[:1000]}


def _extract_error_message(response: Any, body: Any) -> str:
    status_code = int(getattr(response, "status_code", 0) or 0)
    base = f"HTTP {status_code}" if status_code else "请求失败"
    if isinstance(body, dict):
        for key in ("message", "detail", "error", "msg"):
            value = str(body.get(key) or "").strip()
            if value:
                return value
    text = str(getattr(response, "text", "") or "").strip()
    return f"{base}: {text[:300]}" if text else base


def _extract_message(body: Any, fallback: str) -> str:
    if isinstance(body, dict):
        for key in ("message", "detail", "msg"):
            value = str(body.get(key) or "").strip()
            if value:
                return value
        success = body.get("success")
        failed = body.get("failed")
        total = body.get("total")
        if total is not None and (success is not None or failed is not None):
            return f"邀请完成：成功 {success or 0}，失败 {failed or 0} / {total}"
    return fallback


def _is_body_success(body: Any) -> bool:
    if not isinstance(body, dict):
        return True
    failed = body.get("failed")
    if isinstance(failed, (int, float)) and failed > 0:
        return False
    for key in ("ok", "success"):
        if key in body:
            return bool(body.get(key))
    return True


def _item_email(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("email", "mail", "account", "address"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def _item_ok(item: Any, default: bool) -> bool:
    if not isinstance(item, dict):
        return default
    for key in ("ok", "success", "invited"):
        if key in item:
            return bool(item.get(key))
    status = str(item.get("status") or "").strip().lower()
    if status:
        if status in {"ok", "success", "succeeded", "invited", "sent"}:
            return True
        if status in {"error", "failed", "fail", "invalid"}:
            return False
    if item.get("error") or item.get("message_type") == "error":
        return False
    return default


def _item_message(item: Any, fallback: str) -> str:
    if not isinstance(item, dict):
        return fallback
    for key in ("message", "detail", "error", "msg"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return fallback


def _extract_per_email(body: Any, default_ok: bool, default_message: str) -> dict[str, dict[str, Any]]:
    if not isinstance(body, dict):
        return {}

    candidates = []
    for key in ("items", "results", "data", "invitations", "emails"):
        value = body.get(key)
        if isinstance(value, list):
            candidates = value
            break
        if isinstance(value, dict):
            nested_items = value.get("items") or value.get("results")
            if isinstance(nested_items, list):
                candidates = nested_items
                break

    per_email: dict[str, dict[str, Any]] = {}
    for item in candidates:
        email = _item_email(item).lower()
        if not email:
            continue
        ok = _item_ok(item, default_ok)
        per_email[email] = {
            "ok": ok,
            "message": _item_message(item, default_message),
            "raw": item,
        }

    failed_emails = body.get("failed_emails") or body.get("failedEmails")
    if isinstance(failed_emails, list):
        for raw_email in failed_emails:
            email = str(raw_email or "").strip().lower()
            if email:
                per_email[email] = {
                    "ok": False,
                    "message": default_message,
                    "raw": raw_email,
                }

    return per_email


def invite_business_emails(
    emails: Iterable[Any],
    *,
    api_url: str | None = None,
    api_key: str | None = None,
    team_id: Any = None,
    verify: Any = None,
    stop_on_error: Any = None,
    timeout: int = 60,
) -> Tuple[bool, str, dict[str, Any]]:
    """Send one batch invitation request to Team Manager."""

    api_url = str(api_url or _get_config_value("team_manager_url") or "").strip().rstrip("/")
    api_key = str(api_key or _get_config_value("team_manager_key") or "").strip()
    team_id_value = _normalize_team_id(
        team_id if team_id not in (None, "") else _get_config_value("team_manager_business_team_id", "1")
    )
    verify_value = _parse_bool(
        verify if verify is not None else _get_config_value("team_manager_business_verify", "0"),
        default=False,
    )
    stop_on_error_value = _parse_bool(
        stop_on_error if stop_on_error is not None else _get_config_value("team_manager_business_stop_on_error", "0"),
        default=False,
    )
    email_list = _normalize_emails(emails)

    if not api_url:
        return False, "Team Manager API URL 未配置", {}
    if not api_key:
        return False, "Team Manager API Key 未配置", {}
    if not team_id_value:
        return False, "Business Team ID 未配置或无效", {}
    if not email_list:
        return False, "没有可邀请的邮箱", {}

    url = f"{api_url}/api/invitations/batch"
    payload = {
        "team_id": team_id_value,
        "emails": email_list,
        "verify": verify_value,
        "stop_on_error": stop_on_error_value,
    }
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    try:
        response = cffi_requests.post(
            url,
            headers=headers,
            json=payload,
            proxies=None,
            verify=True,
            timeout=timeout,
            impersonate="chrome110",
        )
    except Exception as exc:
        logger.error("Business 邀请异常: %s", exc)
        return False, f"Business 邀请异常: {exc}", {
            "team_id": team_id_value,
            "verify": verify_value,
            "stop_on_error": stop_on_error_value,
            "emails": email_list,
        }

    body = _response_json(response)
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code < 200 or status_code >= 300:
        message = _extract_error_message(response, body)
        return False, f"Business 邀请失败: {message}", {
            "status_code": status_code,
            "response": body,
            "team_id": team_id_value,
            "verify": verify_value,
            "stop_on_error": stop_on_error_value,
            "emails": email_list,
        }

    ok = _is_body_success(body)
    message = _extract_message(body, "Business 邀请已提交" if ok else "Business 邀请失败")
    per_email = _extract_per_email(body, ok, message)
    return ok, message, {
        "status_code": status_code,
        "response": body,
        "team_id": team_id_value,
        "verify": verify_value,
        "stop_on_error": stop_on_error_value,
        "emails": email_list,
        "per_email": per_email,
    }
