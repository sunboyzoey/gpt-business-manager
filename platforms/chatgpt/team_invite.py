#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ChatGPT Team 邀请脚本 - 独立版本

功能：
- 邀请邮箱加入 ChatGPT Team
- 支持多 Team 轮询（每个 Team 限制邀请数）
- 记录邀请历史，防止重复邀请

用法:
    python team_invite.py --email xxx@xxx.com
    python team_invite.py --email xxx@xxx.com --team Team1
    python team_invite.py --emails a@x.com,b@y.com --account-id xxx --auth-token xxx

返回 JSON:
    {
        "success": true,
        "email": "xxx@xxx.com",
        "team_name": "Team1",
        "message": "邀请成功"
    }

Java 调用示例:
    ProcessBuilder pb = new ProcessBuilder("python", "team_invite.py", "--email", email, "--quiet");
    Process p = pb.start();
    String json = new String(p.getInputStream().readAllBytes());
    // 解析 JSON 获取结果
"""

import os
import sys
import json
import argparse
import requests
import warnings
from datetime import datetime

try:
    from curl_cffi import requests as curl_requests
except Exception:
    curl_requests = None

try:
    from urllib3.exceptions import NotOpenSSLWarning
except Exception:
    NotOpenSSLWarning = None

if NotOpenSSLWarning is not None:
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ==================== 配置区 ====================
INVITE_TRACKER_FILE = os.path.join(_PROJECT_DIR, "output", "invite_tracker.json")

# Team 配置 (需要填写)
# auth_token 获取方式: 登录 ChatGPT Team 管理员账号 → F12 → Network → 找任意请求的 Authorization header
TEAMS = [
    {
        "name": "Team1",
        "account_id": "",      # Team 账户 ID
        "auth_token": "",      # Bearer token
        "seat_type": "default", # default 或 prolite
        "max_invites": 4       # 最大邀请数
    },
    {
        "name": "Team2",
        "account_id": "",
        "auth_token": "",
        "seat_type": "default",
        "max_invites": 4
    }
]

# ==================== 日志工具 ====================
class Logger:
    def __init__(self, quiet=False):
        self.quiet = quiet

    def log(self, msg: str, level: str = "INFO"):
        if self.quiet:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = {"INFO": "ℹ️", "SUCCESS": "✓", "ERROR": "✗", "WARN": "⚠"}.get(level, "")
        print(f"[{timestamp}] {prefix} {msg}", file=sys.stderr)

logger = Logger()

TEAM_INVITE_IMPERSONATE = os.environ.get("TEAM_INVITE_IMPERSONATE", "chrome136").strip() or "chrome136"
TEAM_INVITE_USER_AGENT = os.environ.get(
    "TEAM_INVITE_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
).strip() or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"


def _pick_proxy_url(proxy: str = "") -> str:
    direct_proxy = str(proxy or "").strip()
    if direct_proxy:
        return direct_proxy
    return str(
        os.environ.get("TEAM_INVITE_PROXY")
        or os.environ.get("PROXY")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("HTTP_PROXY")
        or ""
    ).strip()


def _build_proxies(proxy: str = ""):
    proxy = _pick_proxy_url(proxy)
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _detect_backend_name(session=None) -> str:
    if session is not None:
        module_name = str(getattr(getattr(session, "__class__", None), "__module__", "") or "")
        if "curl_cffi" in module_name:
            return "curl_cffi"
        return "requests"
    if curl_requests is not None:
        return "curl_cffi"
    return "requests"


def _normalize_bearer_token(token: str) -> str:
    text = str(token or "").strip()
    if not text:
        return ""
    if text.lower().startswith("bearer "):
        return text
    return f"Bearer {text}"


def _normalize_invite_seat_type(value) -> str:
    """Normalize the seat type accepted by the Team invite endpoint."""
    seat_type = str(value or "default").strip().lower() or "default"
    if seat_type not in {"default", "prolite"}:
        raise ValueError("seat_type 必须是 default 或 prolite")
    return seat_type


def _build_common_headers(account_id: str, auth_token: str) -> dict:
    return {
        "accept": "*/*",
        "authorization": _normalize_bearer_token(auth_token),
        "chatgpt-account-id": str(account_id or "").strip(),
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "referer": "https://chatgpt.com/",
        "user-agent": TEAM_INVITE_USER_AGENT,
    }


def _create_http_session(timeout: int = 30, proxy: str = ""):
    proxies = _build_proxies(proxy)
    if curl_requests is not None and hasattr(curl_requests, "Session"):
        session = curl_requests.Session(impersonate=TEAM_INVITE_IMPERSONATE)
        if proxies:
            session.proxies = proxies
        return session
    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)
    return session


def _close_http_session(session):
    if session is None:
        return
    try:
        close_fn = getattr(session, "close", None)
        if callable(close_fn):
            close_fn()
    except Exception:
        pass


def _is_cloudflare_challenge(response) -> bool:
    try:
        content_type = str(response.headers.get("content-type", "")).lower()
    except Exception:
        content_type = ""
    try:
        server = str(response.headers.get("server", "")).lower()
    except Exception:
        server = ""
    text = str(getattr(response, "text", "") or "")
    text_lower = text.lower()
    text_head = text.lstrip()[:120].lower()
    return (
        "text/html" in content_type
        or "cloudflare" in server
        or "cf-chl" in text_lower
        or "just a moment" in text_lower
        or text_head.startswith("<!doctype html")
        or text_head.startswith("<html")
    )


def _extract_json_safe(response):
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _extract_error_detail(response) -> str:
    payload = _extract_json_safe(response)
    candidates = [
        payload.get("detail"),
        payload.get("message"),
        payload.get("error"),
        payload.get("error_description"),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            nested = (
                candidate.get("detail")
                or candidate.get("message")
                or candidate.get("error")
            )
            if nested:
                return str(nested).strip()
        if isinstance(candidate, list):
            compact = ", ".join(str(item).strip() for item in candidate if str(item).strip())
            if compact:
                return compact
        if candidate is not None:
            text = str(candidate).strip()
            if text:
                return text
    return ""


def _is_invite_quota_full_error(message: str) -> bool:
    raw_text = str(message or "").strip()
    if not raw_text:
        return False
    text = raw_text.lower()
    return (
        "unable to invite user due to an error" in text
        or "maximum number of seats" in text
        or ("free trial" in text and "seat" in text)
        or "invite quota full" in text
        or "邀请额度已满" in raw_text
        or "席位已满" in raw_text
    )


def _extract_text_head(response, limit: int = 200) -> str:
    text = str(getattr(response, "text", "") or "").strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit]


def _normalize_email_list(emails) -> list:
    normalized = []
    seen = set()
    raw_items = emails if isinstance(emails, (list, tuple, set)) else [emails]
    for raw in raw_items:
        if raw is None:
            continue
        chunks = str(raw).replace("\n", ",").split(",")
        for chunk in chunks:
            email = str(chunk or "").strip().lower()
            if not email or email in seen:
                continue
            seen.add(email)
            normalized.append(email)
    return normalized


def _extract_account_invite_email(entry) -> str:
    if not isinstance(entry, dict):
        return ""
    return str(
        entry.get("email")
        or entry.get("email_address")
        or entry.get("invited_email")
        or entry.get("user_email")
        or ""
    ).strip().lower()


def _extract_error_email_item(item) -> dict:
    if isinstance(item, str):
        email = str(item).strip().lower()
        return {"email": email, "message": "邀请失败"}
    if not isinstance(item, dict):
        return {"email": "", "message": "邀请失败"}
    email = str(
        item.get("email")
        or item.get("email_address")
        or item.get("invited_email")
        or item.get("user_email")
        or ""
    ).strip().lower()
    message = str(
        item.get("message")
        or item.get("error")
        or item.get("reason")
        or "邀请失败"
    ).strip() or "邀请失败"
    return {"email": email, "message": message}


def _extract_invited_emails_from_result(result: dict, requested_emails: list) -> list:
    account_invites = result.get("account_invites")
    invited = []
    seen = set()
    if isinstance(account_invites, list):
        for item in account_invites:
            email = _extract_account_invite_email(item)
            if email and email not in seen:
                seen.add(email)
                invited.append(email)
    elif isinstance(account_invites, dict):
        for _, item in account_invites.items():
            email = _extract_account_invite_email(item)
            if email and email not in seen:
                seen.add(email)
                invited.append(email)
    if invited:
        return invited
    return list(requested_emails or [])


def _extract_errored_emails_from_result(result: dict) -> list:
    raw_errors = result.get("errored_emails")
    normalized = []
    seen = set()
    if isinstance(raw_errors, dict):
        iterator = []
        for key, value in raw_errors.items():
            if isinstance(value, dict):
                item = dict(value)
                if not item.get("email"):
                    item["email"] = key
                iterator.append(item)
            else:
                iterator.append({"email": key, "message": value})
    elif isinstance(raw_errors, list):
        iterator = raw_errors
    else:
        iterator = []
    for item in iterator:
        entry = _extract_error_email_item(item)
        email = entry.get("email", "")
        if not email or email in seen:
            continue
        seen.add(email)
        normalized.append(entry)
    return normalized


def _http_request(method: str, url: str, headers: dict, timeout: int = 15, payload: dict = None, session=None, proxy: str = ""):
    method_text = str(method or "GET").strip().upper()
    backend_name = _detect_backend_name(session)

    if session is not None:
        kwargs = {
            "headers": headers,
            "timeout": timeout,
        }
        if payload is not None:
            kwargs["json"] = payload
        response = session.request(method_text, url, **kwargs)
        return response, backend_name

    proxies = _build_proxies(proxy)

    if curl_requests is not None:
        kwargs = {
            "headers": headers,
            "timeout": timeout,
            "impersonate": TEAM_INVITE_IMPERSONATE,
        }
        if proxies:
            kwargs["proxies"] = proxies
        if payload is not None:
            kwargs["json"] = payload
        method_fn = getattr(curl_requests, method_text.lower(), None)
        try:
            if callable(method_fn):
                resp = method_fn(url, **kwargs)
            else:
                resp = curl_requests.request(method_text, url, **kwargs)
            return resp, backend_name
        except Exception as e:
            raise RuntimeError(f"curl_cffi 请求失败: {str(e)}")

    kwargs = {
        "headers": headers,
        "timeout": timeout,
    }
    if proxies:
        kwargs["proxies"] = proxies
    if payload is not None:
        kwargs["json"] = payload
    resp = requests.request(method_text, url, **kwargs)
    return resp, backend_name

# ==================== 邀请记录管理 ====================
def load_invite_tracker() -> dict:
    """加载邀请记录"""
    if os.path.exists(INVITE_TRACKER_FILE):
        try:
            with open(INVITE_TRACKER_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.log(f"加载邀请记录失败: {e}", "WARN")
    return {"teams": {team["account_id"]: [] for team in TEAMS if team["account_id"]}}


def save_invite_tracker(tracker: dict):
    """保存邀请记录"""
    try:
        with open(INVITE_TRACKER_FILE, 'w', encoding='utf-8') as f:
            json.dump(tracker, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.log(f"保存邀请记录失败: {e}", "WARN")


def get_available_team(tracker: dict, specified_team: str = None) -> dict:
    """获取可用的 Team（未满的）"""
    for team in TEAMS:
        if not team["account_id"] or not team["auth_token"]:
            continue
        if specified_team and team["name"] != specified_team:
            continue
        account_id = team["account_id"]
        invited = tracker["teams"].get(account_id, [])
        if len(invited) < team["max_invites"]:
            return team
    return None


def is_already_invited(email: str, tracker: dict) -> tuple:
    """检查邮箱是否已被邀请"""
    for account_id, emails in tracker["teams"].items():
        if email in emails:
            # 找到对应的 team name
            for team in TEAMS:
                if team["account_id"] == account_id:
                    return True, team["name"]
            return True, "Unknown"
    return False, None

# ==================== 邀请 API ====================
def _warmup_invite_session(account_id: str, auth_token: str, session=None) -> dict:
    return get_team_info(account_id, auth_token, session=session)


def invite_to_team(
    emails,
    team: dict,
    session=None,
    skip_warmup: bool = False,
    seat_type: str = None,
) -> dict:
    """
    发送 Team 邀请

    Returns:
        {"success": bool, "message": str}
    """
    normalized_emails = _normalize_email_list(emails)
    if not normalized_emails:
        return {"success": False, "message": "缺少有效邮箱"}
    normalized_seat_type = _normalize_invite_seat_type(
        team.get("seat_type") if seat_type is None else seat_type
    )

    if not skip_warmup:
        warmup_result = _warmup_invite_session(team.get("account_id"), team.get("auth_token"), session=session)
        if not warmup_result.get("success"):
            return {
                "success": False,
                "message": str(warmup_result.get("message") or "邀请前预热会话失败"),
            }

    headers = _build_common_headers(team.get("account_id"), team.get("auth_token"))

    payload = {
        "email_addresses": normalized_emails,
        "role": "standard-user",
        "seat_type": normalized_seat_type,
        "resend_emails": True,
    }

    invite_url = f"https://chatgpt.com/backend-api/accounts/{team['account_id']}/invites"

    try:
        response, backend = _http_request(
            method="POST",
            url=invite_url,
            headers=headers,
            timeout=30,
            payload=payload,
            session=session,
        )

        if response.status_code == 200:
            result = _extract_json_safe(response)
            invited_emails = _extract_invited_emails_from_result(result, normalized_emails)
            errored_emails = _extract_errored_emails_from_result(result)
            errored_email_set = {item["email"] for item in errored_emails if item.get("email")}
            successful_emails = [email for email in invited_emails if email not in errored_email_set]

            if successful_emails and not errored_emails:
                return {
                    "success": True,
                    "message": "邀请成功",
                    "invited_emails": successful_emails,
                    "errored_emails": [],
                    "partial_success": False,
                }
            if successful_emails and errored_emails:
                return {
                    "success": True,
                    "message": f"部分邀请成功: {len(successful_emails)}/{len(normalized_emails)}",
                    "invited_emails": successful_emails,
                    "errored_emails": errored_emails,
                    "partial_success": True,
                }
            if errored_emails:
                return {
                    "success": False,
                    "message": f"邀请失败: {errored_emails}",
                    "invited_emails": [],
                    "errored_emails": errored_emails,
                    "partial_success": False,
                }
            return {
                "success": True,
                "message": "邀请已发送",
                "invited_emails": invited_emails,
                "errored_emails": [],
                "partial_success": False,
            }

        if response.status_code == 401:
            detail = _extract_error_detail(response)
            if "delinquent" in str(detail).lower():
                return {"success": False, "message": f"Team 订阅已欠费，请先续费: {detail}"}
            return {"success": False, "message": "认证失败，请更新 auth_token"}

        if response.status_code == 403:
            if _is_cloudflare_challenge(response):
                return {
                    "success": False,
                    "message": "请求被风控页面拦截（Cloudflare Challenge），不是账号权限问题",
                }
            return {"success": False, "message": "无权限，请检查 account_id"}

        text_head = _extract_text_head(response, limit=200)
        return {"success": False, "message": f"HTTP {response.status_code}({backend}): {text_head}"}

    except requests.exceptions.Timeout:
        return {"success": False, "message": "请求超时"}
    except Exception as e:
        return {"success": False, "message": f"请求异常: {str(e)}"}

# ==================== 主函数 ====================
def auto_invite(email: str, team_name: str = None, seat_type: str = None) -> dict:
    """
    自动邀请到可用的 Team

    Args:
        email: 要邀请的邮箱
        team_name: 指定 Team 名称（可选）
        seat_type: 显式席位类型；不传时读取 Team 配置，最终默认 default

    Returns:
        {
            "success": bool,
            "email": str,
            "team_name": str,
            "message": str
        }
    """
    # 加载邀请记录
    tracker = load_invite_tracker()

    # 检查是否已邀请
    already_invited, existing_team = is_already_invited(email, tracker)
    if already_invited:
        logger.log(f"{email} 已被邀请到 {existing_team}", "WARN")
        return {
            "success": False,
            "email": email,
            "team_name": existing_team,
            "message": f"已被邀请到 {existing_team}，跳过"
        }

    # 获取可用 Team
    team = get_available_team(tracker, team_name)
    if not team:
        if team_name:
            msg = f"指定的 Team {team_name} 已满或不存在"
        else:
            msg = "所有 Team 已满"
        logger.log(msg, "ERROR")
        return {
            "success": False,
            "email": email,
            "team_name": None,
            "message": msg
        }

    logger.log(f"邀请 {email} 到 {team['name']}...", "INFO")

    # 发送邀请
    result = invite_to_team([email], team, seat_type=seat_type)

    if result["success"]:
        # 记录邀请
        account_id = team["account_id"]
        if account_id not in tracker["teams"]:
            tracker["teams"][account_id] = []
        tracker["teams"][account_id].append(email)
        save_invite_tracker(tracker)

        invited_count = len(tracker["teams"][account_id])
        logger.log(f"邀请成功! {team['name']}: {invited_count}/{team['max_invites']}", "SUCCESS")

        return {
            "success": True,
            "email": email,
            "team_name": team["name"],
            "message": result["message"],
            "team_status": f"{invited_count}/{team['max_invites']}"
        }
    else:
        logger.log(f"邀请失败: {result['message']}", "ERROR")
        return {
            "success": False,
            "email": email,
            "team_name": team["name"],
            "message": result["message"]
        }


def get_team_status(account_id: str = None) -> dict:
    """获取 Team 的邀请状态

    Args:
        account_id: 动态传入的 account_id（可选），如果传入则只查询该 Team
    """
    tracker = load_invite_tracker()
    status = {}

    # 如果动态传入了 account_id
    if account_id:
        invited = tracker["teams"].get(account_id, [])
        status[account_id] = {
            "invited_count": len(invited),
            "emails": invited
        }
        return status

    # 否则遍历配置文件中的 TEAMS
    for team in TEAMS:
        if not team["account_id"]:
            continue
        aid = team["account_id"]
        invited = tracker["teams"].get(aid, [])
        status[team["name"]] = {
            "invited_count": len(invited),
            "max_invites": team["max_invites"],
            "available": team["max_invites"] - len(invited),
            "emails": invited
        }
    return status

# ==================== 获取 Team 信息 ====================
def get_team_info(account_id: str, auth_token: str, session=None) -> dict:
    """
    通过 API 获取 Team 信息（包括名称）

    Args:
        account_id: Team 账户 ID
        auth_token: Team 管理员 token

    Returns:
        {"success": bool, "team_name": str, "account_id": str, "message": str}
    """
    headers = _build_common_headers(account_id, auth_token)
    check_url = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
    invites_url = f"https://chatgpt.com/backend-api/accounts/{str(account_id or '').strip()}/invites"

    try:
        response, backend = _http_request(
            method="GET",
            url=check_url,
            headers=headers,
            timeout=30,
            payload=None,
            session=session,
        )

        if response.status_code == 200:
            result = _extract_json_safe(response)
            accounts = result.get("accounts", {})
            if not isinstance(accounts, dict):
                return {
                    "success": False,
                    "team_name": None,
                    "account_id": account_id,
                    "message": f"接口返回非预期结构({backend})",
                }

            team_name = None
            for acc_id, acc_info in accounts.items():
                if acc_id == account_id:
                    team_name = (acc_info or {}).get("account", {}).get("name", "Unknown")
                    break
            if not team_name:
                for _, acc_info in accounts.items():
                    team_name = (acc_info or {}).get("account", {}).get("name", "Unknown")
                    break
            invites_response, invites_backend = _http_request(
                method="GET",
                url=invites_url,
                headers=headers,
                timeout=30,
                payload=None,
                session=session,
            )
            if invites_response.status_code == 200:
                return {
                    "success": True,
                    "team_name": team_name,
                    "account_id": account_id,
                    "message": "获取成功"
                }
            if invites_response.status_code == 401:
                return {
                    "success": False,
                    "team_name": None,
                    "account_id": account_id,
                    "message": "认证失败，请更新 auth_token"
                }
            if invites_response.status_code == 403:
                if _is_cloudflare_challenge(invites_response):
                    return {
                        "success": False,
                        "team_name": None,
                        "account_id": account_id,
                        "message": "请求被风控页面拦截（Cloudflare Challenge），不是账号权限问题",
                    }
                return {
                    "success": False,
                    "team_name": None,
                    "account_id": account_id,
                    "message": "无权限，请检查 account_id",
                }
            invites_text_head = _extract_text_head(invites_response, limit=200)
            return {
                "success": False,
                "team_name": None,
                "account_id": account_id,
                "message": f"invites HTTP {invites_response.status_code}({invites_backend}): {invites_text_head}",
            }

        if response.status_code == 401:
            return {"success": False, "team_name": None, "account_id": account_id, "message": "认证失败，请更新 auth_token"}

        if response.status_code == 403:
            if _is_cloudflare_challenge(response):
                return {
                    "success": False,
                    "team_name": None,
                    "account_id": account_id,
                    "message": "请求被风控页面拦截（Cloudflare Challenge），不是账号权限问题",
                }
            return {"success": False, "team_name": None, "account_id": account_id, "message": "无权限，请检查 account_id"}

        text_head = _extract_text_head(response, limit=200)
        return {
            "success": False,
            "team_name": None,
            "account_id": account_id,
            "message": f"HTTP {response.status_code}({backend}): {text_head}",
        }

    except requests.exceptions.Timeout:
        return {"success": False, "team_name": None, "account_id": account_id, "message": "请求超时"}
    except Exception as e:
        return {"success": False, "team_name": None, "account_id": account_id, "message": f"请求异常: {str(e)}"}


def list_team_invites(account_id: str, auth_token: str, proxy: str = "", session=None) -> dict:
    """获取 Team 当前 invite 列表。"""
    headers = _build_common_headers(account_id, auth_token)
    invites_url = f"https://chatgpt.com/backend-api/accounts/{str(account_id or '').strip()}/invites"

    own_session = session is None
    if own_session:
        session = _create_http_session(timeout=30, proxy=proxy)

    try:
        response, backend = _http_request(
            method="GET",
            url=invites_url,
            headers=headers,
            timeout=30,
            payload=None,
            session=session,
            proxy=proxy,
        )
        if response.status_code == 200:
            result = _extract_json_safe(response)
            items = result.get("items")
            if not isinstance(items, list):
                items = []
            return {
                "success": True,
                "account_id": account_id,
                "items": items,
                "total": int(result.get("total") or len(items)),
                "limit": int(result.get("limit") or 0),
                "offset": int(result.get("offset") or 0),
            }
        if response.status_code == 401:
            return {"success": False, "account_id": account_id, "message": "认证失败，请更新 auth_token"}
        if response.status_code == 403:
            if _is_cloudflare_challenge(response):
                return {
                    "success": False,
                    "account_id": account_id,
                    "message": "请求被风控页面拦截（Cloudflare Challenge），不是账号权限问题",
                }
            return {"success": False, "account_id": account_id, "message": "无权限，请检查 account_id"}
        text_head = _extract_text_head(response, limit=200)
        return {
            "success": False,
            "account_id": account_id,
            "message": f"HTTP {response.status_code}({backend}): {text_head}",
        }
    except requests.exceptions.Timeout:
        return {"success": False, "account_id": account_id, "message": "请求超时"}
    except Exception as e:
        return {"success": False, "account_id": account_id, "message": f"请求异常: {str(e)}"}
    finally:
        if own_session:
            _close_http_session(session)


def delete_team_invite(email_address: str, account_id: str, auth_token: str, proxy: str = "", session=None) -> dict:
    """按邮箱撤销 Team 当前 pending invite。"""
    clean_email = str(email_address or "").strip().lower()
    clean_account_id = str(account_id or "").strip()
    clean_auth_token = str(auth_token or "").strip()
    if not clean_email:
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": "缺少邮箱",
        }
    if not clean_account_id:
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": "缺少 account_id",
        }
    if not clean_auth_token:
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": "缺少 auth_token",
        }

    headers = _build_common_headers(clean_account_id, clean_auth_token)
    invites_url = f"https://chatgpt.com/backend-api/accounts/{clean_account_id}/invites"
    payload = {"email_address": clean_email}

    own_session = session is None
    if own_session:
        session = _create_http_session(timeout=30, proxy=proxy)

    try:
        response, backend = _http_request(
            method="DELETE",
            url=invites_url,
            headers=headers,
            timeout=30,
            payload=payload,
            session=session,
            proxy=proxy,
        )
        if response.status_code in {200, 202, 204}:
            return {
                "success": True,
                "deleted": True,
                "invite_missing": False,
                "account_id": clean_account_id,
                "email_address": clean_email,
                "message": "已撤销邀请",
            }
        if response.status_code == 404:
            detail = _extract_error_detail(response)
            if "invite not found" in str(detail or "").strip().lower():
                return {
                    "success": True,
                    "deleted": False,
                    "invite_missing": True,
                    "account_id": clean_account_id,
                    "email_address": clean_email,
                    "message": "Invite不存在，按已清理处理",
                }
            text_head = _extract_text_head(response, limit=200)
            return {
                "success": False,
                "deleted": False,
                "invite_missing": False,
                "account_id": clean_account_id,
                "email_address": clean_email,
                "message": f"HTTP 404({backend}): {detail or text_head or 'Not Found'}",
            }
        if response.status_code == 401:
            return {
                "success": False,
                "deleted": False,
                "invite_missing": False,
                "account_id": clean_account_id,
                "email_address": clean_email,
                "message": "认证失败，请更新 auth_token",
            }
        if response.status_code == 403:
            if _is_cloudflare_challenge(response):
                return {
                    "success": False,
                    "deleted": False,
                    "invite_missing": False,
                    "account_id": clean_account_id,
                    "email_address": clean_email,
                    "message": "请求被风控页面拦截（Cloudflare Challenge），不是账号权限问题",
                }
            return {
                "success": False,
                "deleted": False,
                "invite_missing": False,
                "account_id": clean_account_id,
                "email_address": clean_email,
                "message": "无权限，请检查 account_id",
            }
        text_head = _extract_text_head(response, limit=200)
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": f"HTTP {response.status_code}({backend}): {text_head}",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": "请求超时",
        }
    except Exception as e:
        return {
            "success": False,
            "deleted": False,
            "invite_missing": False,
            "account_id": clean_account_id,
            "email_address": clean_email,
            "message": f"请求异常: {str(e)}",
        }
    finally:
        if own_session:
            _close_http_session(session)


# ==================== 单次邀请（动态参数） ====================
def single_invite_batch(
    emails,
    account_id: str,
    auth_token: str,
    proxy: str = "",
    seat_type: str = "default",
) -> dict:
    """
    单次邀请，使用动态传入的 account_id 和 auth_token

    Args:
        emails: 要邀请的邮箱列表
        account_id: Team 账户 ID
        auth_token: Team 管理员 token (Bearer xxx 或 xxx)
        seat_type: 邀请席位类型，default 或 prolite

    Returns:
        {"success": bool, "emails": list, "message": str}
    """
    normalized_emails = _normalize_email_list(emails)
    if not normalized_emails:
        return {
            "success": False,
            "emails": [],
            "account_id": account_id,
            "message": "缺少有效邮箱"
        }
    normalized_seat_type = _normalize_invite_seat_type(seat_type)

    # 确保 token 格式正确
    auth_token = _normalize_bearer_token(auth_token)

    team = {
        "name": "DynamicTeam",
        "account_id": account_id,
        "auth_token": auth_token,
        "max_invites": 999,
        "seat_type": normalized_seat_type,
    }

    logger.log(f"邀请 {len(normalized_emails)} 个邮箱到 Team...", "INFO")
    session = _create_http_session(timeout=30, proxy=proxy)
    try:
        warmup_result = _warmup_invite_session(account_id, auth_token, session=session)
        if not warmup_result.get("success"):
            result = {
                "success": False,
                "message": str(warmup_result.get("message") or "邀请前预热会话失败"),
                "invited_emails": [],
                "errored_emails": [],
                "partial_success": False,
            }
        else:
            result = invite_to_team(
                normalized_emails,
                team,
                session=session,
                skip_warmup=True,
                seat_type=normalized_seat_type,
            )
    finally:
        _close_http_session(session)

    if result["success"]:
        invited_count = len(_normalize_email_list(result.get("invited_emails")))
        logger.log(f"邀请成功! 成功={invited_count}/{len(normalized_emails)}", "SUCCESS")
        return {
            "success": True,
            "email": normalized_emails[0] if len(normalized_emails) == 1 else "",
            "emails": normalized_emails,
            "account_id": account_id,
            "message": result["message"],
            "invited_emails": _normalize_email_list(result.get("invited_emails")),
            "errored_emails": result.get("errored_emails") if isinstance(result.get("errored_emails"), list) else [],
            "partial_success": bool(result.get("partial_success")),
        }
    else:
        logger.log(f"邀请失败: {result['message']}", "ERROR")
        return {
            "success": False,
            "email": normalized_emails[0] if len(normalized_emails) == 1 else "",
            "emails": normalized_emails,
            "account_id": account_id,
            "message": result["message"],
            "invited_emails": _normalize_email_list(result.get("invited_emails")),
            "errored_emails": result.get("errored_emails") if isinstance(result.get("errored_emails"), list) else [],
            "partial_success": bool(result.get("partial_success")),
        }


def single_invite(
    email: str,
    account_id: str,
    auth_token: str,
    seat_type: str = "default",
) -> dict:
    return single_invite_batch(
        [email],
        account_id,
        auth_token,
        seat_type=seat_type,
    )


# ==================== 命令行入口 ====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ChatGPT Team 邀请脚本')
    parser.add_argument('--email', action='append', default=[],
                        help='要邀请的邮箱，可重复传入')
    parser.add_argument('--emails', type=str, default='',
                        help='批量邀请邮箱，支持逗号或换行分隔')
    parser.add_argument('--account-id', type=str, default=None,
                        help='Team 账户 ID (动态传入)')
    parser.add_argument('--auth-token', type=str, default=None,
                        help='Team 管理员 token (动态传入)')
    parser.add_argument('--proxy', type=str, default='',
                        help='代理地址，例如 http://127.0.0.1:7890')
    parser.add_argument('--team', type=str, default=None,
                        help='指定 Team 名称 (使用配置文件中的 Team)')
    parser.add_argument('--seat-type', type=_normalize_invite_seat_type, default=None,
                        choices=('default', 'prolite'),
                        help='邀请席位类型: default 或 prolite（默认 default）')
    parser.add_argument('--status', action='store_true',
                        help='查看 Team 状态')
    parser.add_argument('--get-team-name', action='store_true',
                        help='获取 Team 名称（需要 --account-id 和 --auth-token）')
    parser.add_argument('--output', type=str, default=None,
                        help='输出结果到文件')
    parser.add_argument('--quiet', action='store_true', default=False,
                        help='静默模式，只输出 JSON')

    args = parser.parse_args()

    if args.quiet:
        logger.quiet = True

    # 查看状态
    if args.status:
        result = get_team_status(account_id=args.account_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0)

    # 获取 Team 名称
    if args.get_team_name:
        if not args.account_id or not args.auth_token:
            print(json.dumps({
                "success": False,
                "error": "获取 Team 名称需要 --account-id 和 --auth-token"
            }, ensure_ascii=False))
            sys.exit(1)
        result = get_team_info(args.account_id, args.auth_token)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0 if result.get('success') else 1)

    # 邀请
    invite_emails = _normalize_email_list(list(args.email or []) + [args.emails])

    if not invite_emails:
        parser.print_help()
        sys.exit(1)

    # 动态参数模式
    if args.account_id and args.auth_token:
        result = single_invite_batch(
            emails=invite_emails,
            account_id=args.account_id,
            auth_token=args.auth_token,
            proxy=args.proxy,
            seat_type=args.seat_type or "default",
        )
    else:
        if len(invite_emails) > 1:
            print(json.dumps({
                "success": False,
                "emails": invite_emails,
                "error": "批量邀请需要 --account-id 和 --auth-token"
            }, ensure_ascii=False))
            sys.exit(1)
        # 使用配置文件模式
        valid_teams = [t for t in TEAMS if t["account_id"] and t["auth_token"]]
        if not valid_teams:
            print(json.dumps({
                "success": False,
                "error": "请配置 TEAMS 或传入 --account-id 和 --auth-token"
            }, ensure_ascii=False))
            sys.exit(1)
        result = auto_invite(
            email=invite_emails[0],
            team_name=args.team,
            seat_type=args.seat_type,
        )

    # 输出 JSON
    result_json = json.dumps(result, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result_json)
        logger.log(f"结果已保存到: {args.output}", "SUCCESS")
    else:
        print(result_json)

    sys.exit(0 if result.get('success') else 1)
