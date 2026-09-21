#!/usr/bin/env python3
"""
ChatGPT OAuth 协议刷新脚本 — 独立版本（无浏览器依赖）

纯 HTTP 协议完成 OAuth Authorization Code + PKCE 流程，
获取 access_token / refresh_token / id_token 并写入 OAUTH JSON 文件。

依赖：
    pip install curl_cffi

用法：
    python generate_oauth_json_protocol.py \
        --email xxx@outlook.com \
        --email-password '{"jwt":"...","api_base":"..."}' \
        --mail-provider outlook \
        --outlook-refresh-token REFRESH_TOKEN \
        --outlook-client-id CLIENT_ID \
        --proxy http://127.0.0.1:7890 \
        --output-dir ./output

输出：
    stdout 打印 JSON: {"success": true, "file_path": "...", "email": "...", ...}
    写入文件: output/{email}.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import secrets
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    curl_requests = None

# ==================== OAuth 常量 ====================

OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"

# ==================== Chrome 指纹 ====================

_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133",
        "build": 6943, "patch_range": (30, 150),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (30, 200),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]


def _supported_impersonates():
    try:
        from curl_cffi.requests.impersonate import BrowserType
        return {item.value for item in BrowserType}
    except Exception:
        return set()


_SUPPORTED = _supported_impersonates()
if _SUPPORTED:
    _CHROME_PROFILES = [p for p in _CHROME_PROFILES if p["impersonate"] in _SUPPORTED]
if not _CHROME_PROFILES:
    _CHROME_PROFILES = [
        {
            "major": 131, "impersonate": "chrome131",
            "build": 6778, "patch_range": (69, 205),
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        }
    ]


def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = (
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    )
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


# ==================== PKCE ====================

def _generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


# ==================== Sentinel Token (PoW) ====================

class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    def _get_config(self):
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            time.gmtime(),
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        nav_val = f"{nav_prop}-undefined"
        return [
            "1920x1080", now_str, 4294705152, random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None, None, "en-US", "en-US,en", random.random(), nav_val,
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed if seed is not None else self.requirements_seed
        difficulty = str(difficulty or "0")
        start_time = time.time()
        config = self._get_config()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)


def _fetch_sentinel_challenge(session, device_id, flow="authorize_continue",
                              user_agent=None, sec_ch_ua=None, impersonate=None):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate
    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _build_sentinel_token(session, device_id, flow="authorize_continue",
                          user_agent=None, sec_ch_ua=None, impersonate=None):
    challenge = _fetch_sentinel_challenge(
        session, device_id, flow=flow, user_agent=user_agent,
        sec_ch_ua=sec_ch_ua, impersonate=impersonate,
    )
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    if not c_value:
        return None
    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(seed=pow_data["seed"], difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = generator.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow}, separators=(",", ":"))


# ==================== Trace headers ====================

def _make_trace_headers():
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


# ==================== JWT 解码 ====================

def _decode_jwt_payload(token: str):
    try:
        parts = str(token or "").strip().split(".")
        if len(parts) != 3:
            return {}
        payload = str(parts[1] or "").strip()
        if not payload:
            return {}
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        parsed = json.loads(decoded.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_account_id_from_tokens(tokens: dict):
    if not isinstance(tokens, dict):
        return ""
    direct = str(tokens.get("account_id") or "").strip()
    if direct:
        return direct
    for token_key in ("access_token", "id_token"):
        payload = _decode_jwt_payload(tokens.get(token_key, ""))
        if not isinstance(payload, dict):
            continue
        auth_info = payload.get("https://api.openai.com/auth", {})
        if isinstance(auth_info, dict):
            account_id = str(
                auth_info.get("chatgpt_account_id")
                or auth_info.get("account_id")
                or auth_info.get("accountId")
                or ""
            ).strip()
            if account_id:
                return account_id
        payload_account_id = str(payload.get("account_id") or payload.get("accountId") or "").strip()
        if payload_account_id:
            return payload_account_id
    return ""


def _extract_token_expired_str(access_token: str):
    payload = _decode_jwt_payload(access_token)
    exp_timestamp = payload.get("exp")
    if isinstance(exp_timestamp, int) and exp_timestamp > 0:
        exp_dt = datetime.fromtimestamp(exp_timestamp, tz=timezone(timedelta(hours=8)))
        return exp_dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")
    return ""


def _extract_code_from_url(url: str):
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None


# ==================== 文件名工具 ====================

def _sanitize_filename(value: str):
    text = str(value or "").strip()
    if not text:
        return "account"
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._")
    return text or "account"


# ==================== 邮箱 OTP 获取 ====================

def _parse_tempapi_mail_auth(raw_value: str):
    text = str(raw_value or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    jwt_value = str(data.get("jwt") or "").strip()
    api_base = str(data.get("api_base") or "https://temp-api.cursom.shop").strip().rstrip("/")
    address = str(data.get("address") or data.get("email") or "").strip()
    address_id = str(data.get("address_id") or data.get("addressId") or "").strip()
    if not api_base and not address and not jwt_value:
        return {}
    return {"provider": "tempapi", "api_base": api_base, "jwt": jwt_value, "address": address, "address_id": address_id}


def _build_mail_ctx(mail_provider, email, email_password,
                    outlook_refresh_token="", outlook_client_id="",
                    outlook_mail_access_type=""):
    provider = str(mail_provider or "auto").strip().lower()
    if provider == "goodguy":
        provider = "tempapi"
    refresh_token = str(outlook_refresh_token or "").strip()
    client_id = str(outlook_client_id or "").strip()
    mail_access_type = str(outlook_mail_access_type or "").strip().lower()
    email_pwd = str(email_password or "").strip()
    tempapi_auth = _parse_tempapi_mail_auth(email_pwd)

    if provider == "auto":
        if refresh_token and client_id:
            provider = "outlook"
        elif tempapi_auth:
            provider = "tempapi"
        else:
            provider = "none"

    if provider == "tempapi":
        tempapi_email = str(email or tempapi_auth.get("address") or "").strip()
        return {
            "provider": "tempapi",
            "email": tempapi_email,
            "api_base": str(tempapi_auth.get("api_base") or "https://temp-api.cursom.shop").strip(),
            "jwt": str(tempapi_auth.get("jwt") or "").strip(),
            "address_id": str(tempapi_auth.get("address_id") or "").strip(),
            "use_quick_api": True,
        }, provider
    if provider == "outlook":
        if not refresh_token or not client_id:
            return None, "none"
        mail_ctx = {
            "provider": "outlook",
            "email": email,
            "refresh_token": refresh_token,
            "client_id": client_id,
            "outlook_code_type": "AUTH",
        }
        if mail_access_type:
            mail_ctx["mail_access_type"] = mail_access_type
        return mail_ctx, provider
    return None, "none"


def _fetch_otp_outlook(mail_ctx: dict, used_codes: set, timeout_seconds: int = 30):
    """通过 Microsoft Graph API 从 Outlook 邮箱获取 OTP 验证码"""
    refresh_token = str(mail_ctx.get("refresh_token") or "").strip()
    client_id = str(mail_ctx.get("client_id") or "").strip()
    if not refresh_token or not client_id:
        return None

    # 1. 用 refresh_token 换 access_token
    try:
        token_resp = curl_requests.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/Mail.Read",
            },
            timeout=20,
        )
        if token_resp.status_code != 200:
            return None
        token_data = token_resp.json()
        access_token = str(token_data.get("access_token") or "").strip()
        if not access_token:
            return None
    except Exception:
        return None

    # 2. 查询最近邮件
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    mail_access_type = str(mail_ctx.get("mail_access_type") or "").strip().lower()
    if mail_access_type == "me":
        mail_url = "https://graph.microsoft.com/v1.0/me/messages"
    else:
        email_addr = str(mail_ctx.get("email") or "").strip()
        mail_url = f"https://graph.microsoft.com/v1.0/users/{email_addr}/messages"

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            resp = curl_requests.get(
                mail_url,
                headers=headers,
                params={
                    "$filter": "contains(subject, 'OpenAI') or contains(subject, 'verification') or contains(subject, 'code')",
                    "$top": "5",
                    "$orderby": "receivedDateTime desc",
                    "$select": "subject,body,receivedDateTime",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                messages = resp.json().get("value") or []
                for msg in messages:
                    body_text = str(msg.get("body", {}).get("content") or msg.get("subject") or "")
                    codes = re.findall(r"\b(\d{6})\b", body_text)
                    for code in codes:
                        if code not in used_codes:
                            return code
        except Exception:
            pass
        time.sleep(5)
    return None


def _extract_body_from_raw_mime(raw: str) -> str:
    """从 MIME raw 邮件中解析出 subject + body 纯文本（去除 CSS/HTML 标签）。"""
    if not raw or len(raw) < 20:
        return raw
    try:
        from email import message_from_string, policy
        msg = message_from_string(raw, policy=policy.default)
        subject = str(msg["subject"] or "")
        body_part = msg.get_body(preferencelist=("plain", "html"))
        body_text = body_part.get_content() if body_part else ""
        no_style = re.sub(r'<style[^>]*>.*?</style>', '', body_text, flags=re.DOTALL | re.IGNORECASE)
        no_tags = re.sub(r'<[^>]+>', ' ', no_style)
        clean = re.sub(r'\s+', ' ', no_tags).strip()
        return f"{subject} {clean}"
    except Exception:
        return raw


def _fetch_otp_tempapi(mail_ctx: dict, used_codes: set, timeout_seconds: int = 30,
                       skip_mail_ids: set = None):
    """通过 TempAPI / CFWorker Quick API 获取 OTP 验证码"""
    api_base = str(mail_ctx.get("api_base") or "https://temp-api.cursom.shop").strip().rstrip("/")
    jwt = str(mail_ctx.get("jwt") or "").strip()
    email = str(mail_ctx.get("email") or "").strip()
    address_id = str(mail_ctx.get("address_id") or "").strip()
    use_quick_api = bool(mail_ctx.get("use_quick_api"))
    skip_ids = skip_mail_ids or set()

    if not email:
        return None
    if not use_quick_api and not jwt:
        return None

    headers = {"Accept": "application/json"}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            if use_quick_api:
                url = f"{api_base}/open_api/quick_mails"
                resp = curl_requests.get(url, params={"address": email, "limit": 10}, headers=headers, timeout=15)
            elif address_id:
                url = f"{api_base}/api/emails/{address_id}/messages"
                resp = curl_requests.get(url, headers=headers, timeout=15)
            else:
                url = f"{api_base}/api/emails/{email}/messages"
                resp = curl_requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                messages = data if isinstance(data, list) else data.get("results") or data.get("data") or data.get("messages") or []
                for msg in (messages if isinstance(messages, list) else []):
                    mid = str(msg.get("id") or msg.get("message_id") or "")
                    if mid and mid in skip_ids:
                        continue
                    raw_content = str(msg.get("raw") or "")
                    subject = str(msg.get("subject") or "")
                    body_text = str(msg.get("body") or msg.get("text") or msg.get("content") or "")
                    if raw_content and (not body_text or not subject):
                        full_text = _extract_body_from_raw_mime(raw_content)
                    else:
                        full_text = f"{subject} {body_text}"
                    codes = re.findall(r"\b(\d{6})\b", full_text)
                    for code in codes:
                        if code not in used_codes:
                            return code
        except Exception:
            pass
        time.sleep(5)
    return None


def _fetch_otp_cfworker_admin(mail_ctx: dict, used_codes: set, timeout_seconds: int = 30,
                              skip_mail_ids: set = None):
    """BUSINESS catch-all 邮件:用 admin /admin/mails?address=... 读 OTP。"""
    api_base = str(mail_ctx.get("api_base") or "").strip().rstrip("/")
    email = str(mail_ctx.get("email") or "").strip()
    admin_token = str(mail_ctx.get("admin_token") or "").strip()
    custom_auth = str(mail_ctx.get("custom_auth") or "").strip()
    if not api_base or not email or not admin_token:
        return None
    skip_ids = skip_mail_ids or set()

    headers = {"x-admin-auth": admin_token, "Accept": "application/json"}
    if custom_auth:
        headers["x-custom-auth"] = custom_auth

    deadline = time.time() + max(int(timeout_seconds or 0), 5)
    while time.time() < deadline:
        try:
            resp = curl_requests.get(
                f"{api_base}/admin/mails",
                params={"limit": 20, "offset": 0, "address": email},
                headers=headers, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json() or {}
                for msg in (data.get("results") or []):
                    mid = str(msg.get("id") or "")
                    if mid and mid in skip_ids:
                        continue
                    candidates: list[str] = []
                    for k in ("text", "html"):
                        v = msg.get(k)
                        if v:
                            candidates.append(str(v))
                    raw = str(msg.get("raw") or "")
                    if raw:
                        try:
                            extracted = _extract_body_from_raw_mime(raw)
                            if extracted:
                                candidates.append(extracted)
                        except Exception:
                            pass
                    body_blob = "\n".join(candidates)
                    for code in re.findall(r"(?<!\d)(\d{6})(?!\d)", body_blob):
                        if code not in used_codes:
                            return code
        except Exception:
            pass
        time.sleep(3)
    return None


def _fetch_otp(mail_ctx: dict, used_codes: set, timeout_seconds: int = 60,
               skip_mail_ids: set = None):
    if not mail_ctx:
        return None
    provider = str(mail_ctx.get("provider") or "").strip().lower()
    if provider == "gmail":
        from platforms.chatgpt.gpt_pro_login import build_mailbox_for_account
        mailbox, account = build_mailbox_for_account({**mail_ctx, "mail_provider": "gmail"})
        return mailbox.wait_for_code(account, timeout=timeout_seconds,
                                     before_ids=skip_mail_ids or set(), exclude_codes=used_codes)
    if provider == "outlook":
        return _fetch_otp_outlook(mail_ctx, used_codes, timeout_seconds)
    if provider == "tempapi":
        return _fetch_otp_tempapi(mail_ctx, used_codes, timeout_seconds,
                                  skip_mail_ids=skip_mail_ids)
    if provider == "cfworker_admin":
        return _fetch_otp_cfworker_admin(mail_ctx, used_codes, timeout_seconds,
                                         skip_mail_ids=skip_mail_ids)
    return None


def _collect_existing_mail_ids(
    mail_ctx: dict, *, strict: bool = False, request_get=None,
) -> set:
    """Snapshot message IDs before navigation; strict callers must see failures.

    Legacy protocol callers keep their fail-soft behavior.  Browser adapters
    request strict mode so an unreadable mailbox is never mistaken for an
    empty, successfully snapshotted mailbox.
    """
    ids = set()
    try:
        get = request_get or curl_requests.get
        if not isinstance(mail_ctx, dict) or not mail_ctx:
            raise RuntimeError("邮箱上下文未配置")
        provider = str(mail_ctx.get("provider") or "").strip().lower()
        if provider == "gmail":
            from platforms.chatgpt.gpt_pro_login import build_mailbox_for_account
            mailbox, account = build_mailbox_for_account({**mail_ctx, "mail_provider": "gmail"})
            return mailbox.get_current_ids(account, strict=True)
        api_base = str(mail_ctx.get("api_base") or "").strip().rstrip("/")
        email = str(mail_ctx.get("email") or "").strip()
        messages = None
        if provider == "tempapi" and api_base and email:
            use_quick = bool(mail_ctx.get("use_quick_api"))
            jwt = str(mail_ctx.get("jwt") or "").strip()
            headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}
            if use_quick:
                resp = get(
                    f"{api_base}/open_api/quick_mails",
                    params={"address": email, "limit": 20},
                    **({"headers": headers} if strict else {}), timeout=10,
                )
            else:
                if strict and not jwt:
                    raise RuntimeError("邮箱访问凭据未配置")
                address_id = str(mail_ctx.get("address_id") or email).strip() if strict else email
                resp = get(
                    f"{api_base}/api/emails/{address_id}/messages",
                    headers=headers, timeout=10,
                )
            if resp.status_code != 200:
                raise RuntimeError("邮箱基线读取失败")
            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                if not strict:
                    messages = data.get("results") or data.get("data") or data.get("messages") or []
                else:
                    for key in ("results", "data", "messages"):
                        if isinstance(data.get(key), list):
                            messages = data[key]
                            break
        elif provider == "cfworker_admin" and api_base and email:
            admin_token = str(mail_ctx.get("admin_token") or "").strip()
            custom_auth = str(mail_ctx.get("custom_auth") or "").strip()
            if strict and not admin_token:
                raise RuntimeError("邮箱访问凭据未配置")
            headers = {"x-admin-auth": admin_token}
            if custom_auth:
                headers["x-custom-auth"] = custom_auth
            if strict:
                # Capture every page before navigation, not only the newest
                # 20 messages.  Otherwise deleting newer mail could expose an
                # older, previously unseen OTP in the challenge's first page.
                page_size = 20
                baseline_deadline = time.monotonic() + 30.0
                for offset in range(0, 2000, page_size):
                    remaining = baseline_deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError("邮箱基线准备超时")
                    resp = get(
                        f"{api_base}/admin/mails",
                        params={"limit": page_size, "offset": offset, "address": email},
                        headers=headers, timeout=min(10.0, remaining),
                    )
                    if time.monotonic() > baseline_deadline:
                        raise RuntimeError("邮箱基线准备超时")
                    if resp.status_code != 200:
                        raise RuntimeError("邮箱基线读取失败")
                    data = resp.json()
                    page = data.get("results") if isinstance(data, dict) else None
                    if not isinstance(page, list):
                        raise RuntimeError("邮箱基线格式错误")
                    page_ids = set()
                    for message in page:
                        mid = message.get("id") if isinstance(message, dict) else None
                        if not isinstance(mid, (str, int)) or isinstance(mid, bool) or not str(mid).strip():
                            raise RuntimeError("邮箱基线缺少有效邮件 ID")
                        page_ids.add(str(mid))
                    if page and not page_ids.difference(ids):
                        raise RuntimeError("邮箱基线分页未前进")
                    ids.update(page_ids)
                    if len(page) < page_size:
                        return ids
                raise RuntimeError("邮箱基线分页超出安全读取上限")
            resp = get(
                f"{api_base}/admin/mails",
                params={"limit": 20, "offset": 0, "address": email},
                headers=headers, timeout=10,
            )
            if resp.status_code != 200:
                raise RuntimeError("邮箱基线读取失败")
            data = resp.json()
            if isinstance(data, dict):
                messages = data.get("results")
        if not isinstance(messages, list):
            raise RuntimeError("邮箱不支持基线读取或返回格式错误")
        for msg in messages:
            if not strict:
                mid = str(msg.get("id") or (msg.get("message_id") if provider == "tempapi" else "") or "")
                if mid:
                    ids.add(mid)
                continue
            if not isinstance(msg, dict):
                if strict:
                    raise RuntimeError("邮箱基线缺少有效邮件 ID")
                continue
            raw_id = msg.get("id")
            if raw_id in (None, ""):
                raw_id = msg.get("message_id")
            if not isinstance(raw_id, (str, int)) or isinstance(raw_id, bool) or not str(raw_id).strip():
                if strict:
                    raise RuntimeError("邮箱基线缺少有效邮件 ID")
                continue
            ids.add(str(raw_id))
        return ids
    except Exception:
        if strict:
            # HTTP/provider exceptions can contain authentication details.
            raise RuntimeError("无法建立 OAuth 邮件基线") from None
        return ids


# ==================== 日志工具 ====================

def _log(msg: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}", file=sys.stderr)


# ==================== OAuth 协议流程 ====================

class ProtocolOAuthClient:
    """纯协议 OAuth 客户端 — 不依赖任何浏览器"""

    def __init__(self, email: str, proxy: str = "", mail_ctx: dict = None,
                 skip_workspace: bool = False, workspace_id: str = "", log_fn=None):
        self.email = email
        self.mail_ctx = mail_ctx
        self.skip_workspace = skip_workspace
        self.workspace_id = str(workspace_id or "").strip()
        self._external_log = log_fn
        self.last_error = ""
        self.recent_logs = []
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.device_id = str(uuid.uuid4())
        self.accept_language = random.choice([
            "en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8",
            "en,en-US;q=0.9", "en-US,en;q=0.8",
        ])
        self.platform_version = f'"{random.randint(10, 15)}.0.0"'

        if curl_requests is None:
            raise RuntimeError("curl_cffi is required: pip install curl_cffi")

        self.session = curl_requests.Session(impersonate=self.impersonate)
        self.session.trust_env = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": self.platform_version,
        })
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def _emit(self, msg: str):
        _log(msg)
        self.recent_logs.append(msg)
        if len(self.recent_logs) > 80:
            self.recent_logs = self.recent_logs[-80:]
        error_markers = ("失败", "异常", "缺少", "未获取", "未提供", "未成功")
        if any(marker in msg for marker in error_markers):
            self.last_error = msg
        if self._external_log:
            try:
                self._external_log(msg)
            except Exception:
                pass

    def _oauth_json_headers(self, referer: str):
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": referer,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        h.update(_make_trace_headers())
        return h

    def _abs_url(self, url: str):
        raw = str(url or "").strip()
        if not raw:
            return ""
        if raw.startswith("/"):
            return f"{OAUTH_ISSUER}{raw}"
        return raw

    def _get_with_retry(self, label: str, url: str, *, headers: dict, params: dict = None, max_attempts: int = 3):
        last_error = None
        for attempt in range(1, max_attempts + 1):
            try:
                return self.session.get(
                    url, headers=headers, params=params,
                    allow_redirects=False, timeout=30, impersonate=self.impersonate,
                )
            except Exception as e:
                last_error = e
                self._emit(f"{label} 异常(第{attempt}/{max_attempts}次): {e}")
                if attempt < max_attempts:
                    time.sleep(1)
        raise last_error

    # --- Step 1: Bootstrap OAuth session ---
    def _bootstrap_oauth_session(self):
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(24)
        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "prompt": "login",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        authorize_url = f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(authorize_params)}"

        self._emit("1/7 获取授权入口（建立 OAuth 会话）")
        final_url = ""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://chatgpt.com/",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }

        current_url = authorize_url
        for hop in range(10):
            try:
                resp = self.session.get(
                    current_url, headers=headers,
                    allow_redirects=False, timeout=30, impersonate=self.impersonate,
                )
            except Exception as e:
                self._emit(f"bootstrap hop {hop+1} 异常: {e}")
                break
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                if loc.startswith("/"):
                    loc = f"{OAUTH_ISSUER}{loc}"
                final_url = loc
                current_url = loc
                continue
            final_url = str(resp.url or current_url)
            break

        has_login = any(getattr(c, "name", "") == "login_session" for c in self.session.cookies)
        self._emit(f"bootstrap 完成: login_session={'已获取' if has_login else '未获取'}, final={final_url[:140]}")

        return code_verifier, authorize_params, final_url

    # --- Step 2: Submit email ---
    def _post_authorize_continue(self, referer_url: str):
        sentinel_token = _build_sentinel_token(
            self.session, self.device_id, flow="authorize_continue",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        if not sentinel_token:
            self._emit("authorize_continue 的 sentinel token 获取失败")
            return None
        headers = self._oauth_json_headers(referer_url)
        headers["openai-sentinel-token"] = sentinel_token
        try:
            resp = self.session.post(
                f"{OAUTH_ISSUER}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": self.email}},
                headers=headers, timeout=30, allow_redirects=False,
                impersonate=self.impersonate,
            )
            return resp
        except Exception as e:
            self._emit(f"authorize/continue 异常: {e}")
            return None

    # --- Step 3-4: Send and validate OTP ---
    def _send_passwordless_otp(self, reason: str, referer_url: str):
        use_referer = self._abs_url(referer_url) or f"{OAUTH_ISSUER}/log-in/password"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": use_referer,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers.update(_make_trace_headers())
        self._emit(f"发送 OTP（{reason}）：POST /api/accounts/passwordless/send-otp")
        try:
            resp = self.session.post(
                f"{OAUTH_ISSUER}/api/accounts/passwordless/send-otp",
                json={}, headers=headers, timeout=30, allow_redirects=False,
                impersonate=self.impersonate,
            )
        except Exception as e:
            self._emit(f"passwordless/send-otp 异常: {e}")
            resp = None

        if resp is not None:
            self._emit(f"/passwordless/send-otp -> {resp.status_code}")
            if resp.status_code in {200, 204}:
                # Outlook 需要等待邮件稳定
                if self.mail_ctx and str(self.mail_ctx.get("provider") or "").lower() == "outlook":
                    delay = random.randint(10, 15)
                    self._emit(f"Outlook 等待邮件稳定中... ({delay}s)")
                    time.sleep(delay)
                return True

        self._emit("passwordless/send-otp 未成功，回退 GET /api/accounts/email-otp/send")
        headers_fallback = {
            "Accept": "application/json, text/plain, */*",
            "Origin": OAUTH_ISSUER,
            "Referer": f"{OAUTH_ISSUER}/email-verification",
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers_fallback.update(_make_trace_headers())
        try:
            fb = self.session.get(
                f"{OAUTH_ISSUER}/api/accounts/email-otp/send",
                headers=headers_fallback, timeout=30, allow_redirects=False,
                impersonate=self.impersonate,
            )
            self._emit(f"/email-otp/send -> {fb.status_code}")
            if fb.status_code in {200, 204}:
                if self.mail_ctx and str(self.mail_ctx.get("provider") or "").lower() == "outlook":
                    delay = random.randint(10, 15)
                    self._emit(f"Outlook 等待邮件稳定中... ({delay}s)")
                    time.sleep(delay)
            return fb.status_code in {200, 204}
        except Exception as e:
            self._emit(f"email-otp/send 回退异常: {e}")
            return False

    def _validate_otp(self, continue_url: str, page_type: str):
        if not self.mail_ctx:
            self._emit("未提供 mail_ctx，无法从邮箱读取 OTP")
            return False, continue_url, page_type

        existing_mail_ids = _collect_existing_mail_ids(self.mail_ctx)
        if existing_mail_ids:
            self._emit(f"已记录 {len(existing_mail_ids)} 封旧邮件，将只从新邮件提取验证码")

        send_ok = self._send_passwordless_otp("start", continue_url)
        if not send_ok:
            self._emit("发送 OTP 失败")
            return False, continue_url, page_type

        headers_otp = self._oauth_json_headers(f"{OAUTH_ISSUER}/email-verification")
        tried_codes = set()
        otp_deadline = time.time() + 120

        while time.time() < otp_deadline:
            remain = int(max(1, otp_deadline - time.time()))
            poll_timeout = min(30, remain)
            otp_code = _fetch_otp(self.mail_ctx, tried_codes, timeout_seconds=poll_timeout,
                                   skip_mail_ids=existing_mail_ids)
            if not otp_code:
                elapsed = int(120 - max(0, otp_deadline - time.time()))
                self._emit(f"OTP 等待中... ({elapsed}s/120s)")
                time.sleep(2)
                continue

            if otp_code in tried_codes:
                continue
            tried_codes.add(otp_code)
            self._emit("尝试 OTP（内容不写入日志）")

            try:
                resp_otp = self.session.post(
                    f"{OAUTH_ISSUER}/api/accounts/email-otp/validate",
                    json={"code": otp_code}, headers=headers_otp,
                    timeout=30, allow_redirects=False, impersonate=self.impersonate,
                )
            except Exception as e:
                self._emit(f"email-otp/validate 异常: {e}")
                time.sleep(2)
                continue

            self._emit(f"/email-otp/validate -> {resp_otp.status_code}")
            if resp_otp.status_code != 200:
                err_code = ""
                try:
                    err_data = resp_otp.json()
                    if isinstance(err_data, dict):
                        err_obj = err_data.get("error") or {}
                        if isinstance(err_obj, dict):
                            err_code = str(err_obj.get("code") or "").strip().lower()
                except Exception:
                    pass
                self._emit(f"OTP 校验失败: error_type={err_code or '-'}")

                if err_code == "max_check_attempts":
                    self._emit("命中 max_check_attempts，标记重试")
                    self._hit_max_check_attempts = True
                    return False, continue_url, page_type
                if err_code == "wrong_email_otp":
                    self._send_passwordless_otp("wrong_email_otp", continue_url)
                time.sleep(2)
                continue

            try:
                otp_data = resp_otp.json()
            except Exception:
                self._emit("email-otp/validate 响应解析失败")
                time.sleep(2)
                continue

            continue_url = str(otp_data.get("continue_url") or continue_url or "")
            page_type = str((otp_data.get("page") or {}).get("type", "") or page_type or "")
            self._emit(f"OTP 验证通过 page={page_type or '-'} next={continue_url[:140]}")
            return True, continue_url, page_type

        self._emit(f"OTP 验证失败，已尝试 {len(tried_codes)} 个验证码")
        return False, continue_url, page_type

    # --- Step 5-6: Follow consent / workspace and extract code ---
    def _follow_for_code(self, start_url: str, referer: str = None, max_hops: int = 16):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }
        if referer:
            headers["Referer"] = referer
        current_url = start_url
        for hop in range(max_hops):
            try:
                resp = self.session.get(
                    current_url, headers=headers, allow_redirects=False,
                    timeout=30, impersonate=self.impersonate,
                )
            except Exception as e:
                maybe_localhost = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if maybe_localhost:
                    code = _extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        self._emit(f"follow[{hop + 1}] 命中 localhost 回调")
                        return code
                self._emit(f"follow[{hop + 1}] 请求异常: {e}")
                return None
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = str(resp.headers.get("Location") or "")
                if loc.startswith("/"):
                    loc = f"{OAUTH_ISSUER}{loc}"
                code = _extract_code_from_url(loc)
                if code:
                    return code
                current_url = loc
                headers["Referer"] = current_url
                continue
            code = _extract_code_from_url(str(resp.url))
            if code:
                return code
            break
        return None

    def _try_handle_add_phone(self, consent_url: str) -> str | None:
        """OAuth 阶段遇到 add_phone 页面时,自动绑手机号 + 收 SMS 验证码 + 验证。

        成功返回新的 continue URL(供调用方继续提取 code);失败返回 None。
        所有配置都从 config_store 读:
          - chatgpt_add_phone_number     形如 +1xxxxxxxxxx
          - chatgpt_add_phone_sms_api_url  GET 该 URL 返回 {data:{fields:{content:"..."}}}
          - chatgpt_add_phone_sms_timeout  秒,默认 180（60–300），兼容旧 smsbower 配置
        """
        try:
            from core.config_store import config_store
            from platforms.chatgpt.sms_timeout import SmsWaitProgress, resolve_sms_timeout
        except Exception as exc:
            self._emit(f"add_phone 自动处理跳过:导入 config 失败 ({exc})")
            return None
        phone = str(config_store.get("chatgpt_add_phone_number", "") or "").strip()
        sms_url = str(config_store.get("chatgpt_add_phone_sms_api_url", "") or "").strip()
        timeout_s = resolve_sms_timeout(config_store)
        if not phone or not sms_url:
            self._emit("add_phone 自动处理跳过:未配置 chatgpt_add_phone_number / chatgpt_add_phone_sms_api_url")
            return None

        # Step 1: POST /api/accounts/add-phone/send
        send_url = f"{OAUTH_ISSUER}/api/accounts/add-phone/send"
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": f"{OAUTH_ISSUER}/add-phone",
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        h.update(_make_trace_headers())
        try:
            seen_content = ""
            try:
                pre_resp = curl_requests.get(sms_url, timeout=10)
                pre_data = pre_resp.json() or {}
                seen_content = str(((pre_data.get("data") or {}).get("fields") or {}).get("content") or "")
            except Exception:
                seen_content = ""

            self._emit("add_phone 自动处理:POST /api/accounts/add-phone/send（号码不写入日志）")
            resp = self.session.post(
                send_url, json={"phone_number": phone}, headers=h,
                allow_redirects=False, timeout=30, impersonate=self.impersonate,
            )
            self._emit(f"/add-phone/send -> {resp.status_code}")
            if resp.status_code != 200:
                self._emit(f"/add-phone/send 失败: {(resp.text or '')[:200]}")
                return None
        except Exception as exc:
            self._emit(f"/add-phone/send 异常: {exc}")
            return None

        # Step 2: 轮询短信
        self._emit(f"等待 SMS 验证码 (timeout={timeout_s}s)")
        sms_wait = SmsWaitProgress(timeout_s, self._emit, clock=time.time)
        sms_code = ""
        while sms_wait.remaining() > 0:
            sms_wait.report()
            try:
                r = curl_requests.get(sms_url, timeout=min(10, max(0.1, sms_wait.remaining())))
                if r.status_code == 200:
                    d = r.json() or {}
                    content = str(((d.get("data") or {}).get("fields") or {}).get("content") or "")
                    if content and content != seen_content:
                        m = re.search(r"(?<!\d)(\d{6})(?!\d)", content)
                        if m:
                            sms_code = m.group(1)
                            self._emit("SMS 验证码已到达（内容不写入日志）")
                            break
            except Exception:
                pass
            time.sleep(min(3, sms_wait.remaining()))
        sms_wait.report(force=True)
        if not sms_code:
            self._emit(f"等待 SMS 验证码超时 ({timeout_s}s)")
            return None

        # Step 3: POST /api/accounts/phone-otp/validate
        validate_url = f"{OAUTH_ISSUER}/api/accounts/phone-otp/validate"
        h2 = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": f"{OAUTH_ISSUER}/phone-verification",
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        h2.update(_make_trace_headers())
        try:
            vresp = self.session.post(
                validate_url, json={"code": sms_code}, headers=h2,
                allow_redirects=False, timeout=30, impersonate=self.impersonate,
            )
            self._emit(f"/phone-otp/validate -> {vresp.status_code}")
            if vresp.status_code != 200:
                self._emit(f"/phone-otp/validate 失败: {(vresp.text or '')[:200]}")
                return None
            try:
                payload = vresp.json() or {}
            except Exception:
                payload = {}
            next_url = str(payload.get("continue_url") or payload.get("location") or "")
            if not next_url:
                next_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._emit(f"add_phone 已自动完成,继续 OAuth: {next_url[:120]}")
            return self._abs_url(next_url)
        except Exception as exc:
            self._emit(f"/phone-otp/validate 异常: {exc}")
            return None

    def _submit_workspace_select(self, consent_url: str):
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": consent_url,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        h.update(_make_trace_headers())
        payload = {"workspace_id": self.workspace_id} if self.workspace_id else {}
        if self.workspace_id:
            self._emit(f"选择指定 workspace: {self.workspace_id}")
        resp = self.session.post(
            f"{OAUTH_ISSUER}/api/accounts/workspace/select",
            json=payload, headers=h, allow_redirects=False,
            timeout=30, impersonate=self.impersonate,
        )
        self._emit(f"workspace/select -> {resp.status_code}")
        if resp.status_code >= 400:
            try:
                self._emit(f"workspace/select body: {(resp.text or '')[:300]}")
            except Exception:
                pass
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = str(resp.headers.get("Location") or "")
            if loc.startswith("/"):
                loc = f"{OAUTH_ISSUER}{loc}"
            code = _extract_code_from_url(loc)
            if code:
                return code
            return self._follow_for_code(loc, referer=consent_url)
        if resp.status_code == 200:
            try:
                ws_data = resp.json()
                ws_next = ws_data.get("continue_url", "")
                if ws_next:
                    code = _extract_code_from_url(self._abs_url(ws_next))
                    if code:
                        return code
                    return self._follow_for_code(self._abs_url(ws_next), referer=consent_url)
            except Exception:
                pass
        return None

    def _extract_code(self, continue_url: str, page_type: str):
        consent_url = self._abs_url(continue_url)
        code = None

        is_add_phone = page_type == "add_phone" or "add-phone" in (consent_url or "")
        if is_add_phone:
            self._emit("5/7 检测到 add_phone 页面,尝试自动绑定配置手机号")
            handled = self._try_handle_add_phone(consent_url)
            if handled:
                consent_url = handled
            else:
                self._emit("5/7 add_phone 自动处理未生效,回退到直接跳转 consent URL")
                consent_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

        if consent_url:
            code = _extract_code_from_url(consent_url)
        if not code and consent_url:
            self._emit("5/7 跟随 continue_url 提取授权码")
            code = self._follow_for_code(consent_url, referer=f"{OAUTH_ISSUER}/log-in/password")

        if self.skip_workspace:
            self._emit("5/7 skip_workspace=True，跳过 workspace 选择（取个人账号 OAuth）")
            if not code:
                fallback = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
                self._emit("6/7 调用 workspace/select（默认个人账号）")
                code = self._submit_workspace_select(fallback)
            if not code:
                fallback = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
                code = self._follow_for_code(fallback, referer=f"{OAUTH_ISSUER}/log-in/password")
            return code

        consent_hint = any(
            kw in (consent_url or "") or kw in page_type
            for kw in ("consent", "sign-in-with-chatgpt", "workspace", "organization")
        )
        if not code and consent_hint:
            if not consent_url:
                consent_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._emit("6/7 处理 workspace/org 选择")
            code = self._submit_workspace_select(consent_url)

        if not code:
            fallback = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._emit("6/7 回退 consent 固定路径重试")
            code = self._submit_workspace_select(fallback)
            if not code:
                code = self._follow_for_code(fallback, referer=f"{OAUTH_ISSUER}/log-in/password")

        return code

    # --- Step 7: Exchange code for tokens ---
    def _exchange_code(self, code: str, code_verifier: str):
        self._emit("7/7 交换 token（authorization_code -> access_token）")
        resp = self.session.post(
            f"{OAUTH_ISSUER}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": self.ua},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OAUTH_REDIRECT_URI,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": code_verifier,
            },
            timeout=60, impersonate=self.impersonate,
        )
        self._emit(f"/oauth/token -> {resp.status_code}")
        if resp.status_code != 200:
            self._emit(f"token 交换失败: {resp.status_code} {str(resp.text or '')[:200]}")
            return None
        try:
            data = resp.json()
        except Exception:
            self._emit("token 响应解析失败")
            return None
        if not isinstance(data, dict) or not data.get("access_token"):
            self._emit("token 响应缺少 access_token")
            return None
        self._emit("OAuth 刷新成功")
        return data

    # --- Main flow ---
    def run(self, max_otp_retries: int = 2) -> dict | None:
        for attempt in range(max_otp_retries + 1):
            if attempt > 0:
                self._emit(f"OTP 重试 {attempt}/{max_otp_retries}：重新建立 OAuth 会话")
                time.sleep(3)
            result = self._run_once()
            if result is not None:
                return result
            if not getattr(self, '_hit_max_check_attempts', False):
                return None
            self._hit_max_check_attempts = False
        return None

    def _run_once(self) -> dict | None:
        self._hit_max_check_attempts = False
        code_verifier, authorize_params, authorize_final_url = self._bootstrap_oauth_session()
        if not authorize_final_url:
            self._emit("bootstrap 失败，无 authorize_final_url")
            return None

        self._emit("2/7 提交邮箱")
        continue_referer = (
            authorize_final_url if authorize_final_url.startswith(OAUTH_ISSUER)
            else f"{OAUTH_ISSUER}/log-in"
        )
        resp_continue = self._post_authorize_continue(continue_referer)
        if resp_continue is None:
            return None

        self._emit(f"/authorize/continue -> {resp_continue.status_code}")
        if resp_continue.status_code == 400 and "invalid_auth_step" in (resp_continue.text or ""):
            self._emit("invalid_auth_step，重新 bootstrap 后重试")
            code_verifier, authorize_params, authorize_final_url = self._bootstrap_oauth_session()
            if not authorize_final_url:
                return None
            continue_referer = (
                authorize_final_url if authorize_final_url.startswith(OAUTH_ISSUER)
                else f"{OAUTH_ISSUER}/log-in"
            )
            resp_continue = self._post_authorize_continue(continue_referer)
            if resp_continue is None:
                return None
            self._emit(f"/authorize/continue(重试) -> {resp_continue.status_code}")

        if resp_continue.status_code != 200:
            self._emit(f"邮箱提交失败: {str(resp_continue.text or '')[:180]}")
            return None

        try:
            continue_data = resp_continue.json()
        except Exception:
            self._emit("authorize/continue 响应解析失败")
            return None

        continue_url = str(continue_data.get("continue_url") or "")
        page_type = str((continue_data.get("page") or {}).get("type", "") or "")
        self._emit(f"continue page={page_type or '-'} next={continue_url[:140]}")

        # 3-4: OTP
        need_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in (continue_url or "")
            or "email-otp" in (continue_url or "")
            or "log-in/password" in (continue_url or "")
            or page_type == "login_password"
        )
        if need_otp:
            self._emit("3/7 进入验证码阶段")
            ok, continue_url, page_type = self._validate_otp(continue_url, page_type)
            if not ok:
                return None

        # 5-6: Extract code
        code = self._extract_code(continue_url, page_type)
        if not code:
            self._emit("未获取到 authorization code")
            return None

        # 7: Exchange
        return self._exchange_code(code, code_verifier)


# ==================== 主入口 ====================

def main():
    parser = argparse.ArgumentParser(
        description="ChatGPT OAuth 协议刷新脚本（纯 HTTP，无浏览器）"
    )
    parser.add_argument("--email", required=True, help="ChatGPT 账号邮箱")
    parser.add_argument("--chatgpt-password", default="", help="保留参数，协议模式不使用")
    parser.add_argument("--email-password", default="-", help="邮箱密码或 TempAPI JSON")
    parser.add_argument("--proxy", default="", help="代理地址，例如 http://127.0.0.1:7890")
    parser.add_argument("--output-dir", default="", help="OAUTH JSON 输出目录")
    parser.add_argument("--mail-provider", default="auto", choices=["auto", "outlook", "tempapi", "none"],
                        help="邮箱 OTP 获取方式")
    parser.add_argument("--outlook-refresh-token", default="", help="Outlook refresh token")
    parser.add_argument("--outlook-client-id", default="", help="Outlook client id")
    parser.add_argument("--outlook-mail-access-type", default="", help="Outlook mail access type")
    args = parser.parse_args()

    email = str(args.email or "").strip()
    proxy = str(args.proxy or "").strip()
    email_password = str(args.email_password or "").strip()

    if not email:
        print(json.dumps({"success": False, "message": "email is empty"}, ensure_ascii=False))
        return 1

    output_dir = str(args.output_dir or "").strip()
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
    if not os.path.isabs(output_dir):
        output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    try:
        mail_ctx, resolved_provider = _build_mail_ctx(
            args.mail_provider, email, email_password,
            args.outlook_refresh_token, args.outlook_client_id,
            args.outlook_mail_access_type,
        )
        if resolved_provider == "none":
            self._emit("mail_ctx 未提供，若触发 OTP 读取将失败")

        client = ProtocolOAuthClient(email=email, proxy=proxy, mail_ctx=mail_ctx)
        try:
            tokens = client.run()
        finally:
            client.close()

        if not isinstance(tokens, dict) or not tokens.get("access_token"):
            reason = ""
            if isinstance(tokens, dict):
                reason = str(
                    tokens.get("error_description") or tokens.get("error") or tokens.get("message") or ""
                ).strip()
            message = "oauth token response missing access_token"
            if reason:
                message = f"{message}: {reason}"
            print(json.dumps({
                "success": False, "message": message, "email": email,
                "provider": resolved_provider, "flow": "protocol",
            }, ensure_ascii=False))
            return 1

        access_token = str(tokens.get("access_token") or "").strip()
        id_token = str(tokens.get("id_token") or "").strip()
        refresh_token = str(tokens.get("refresh_token") or "").strip()
        account_id = _extract_account_id_from_tokens(tokens)

        if not account_id:
            print(json.dumps({
                "success": False, "message": "oauth token missing account_id",
                "email": email, "provider": resolved_provider, "flow": "protocol",
            }, ensure_ascii=False))
            return 1

        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        last_refresh = datetime.now(timezone(timedelta(hours=8))).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%S+08:00"
        )
        expires_at = _extract_token_expired_str(access_token)
        expired = str(expires_at or last_refresh).strip()

        file_name = f"{_sanitize_filename(email)}.json"
        file_path = os.path.abspath(os.path.join(output_dir, file_name))
        payload = {
            "type": "codex",
            "email": email,
            "expired": expired,
            "id_token": id_token,
            "account_id": account_id,
            "access_token": access_token,
            "last_refresh": last_refresh,
            "refresh_token": refresh_token,
            "generated_at": generated_at,
            "provider": resolved_provider,
            "oauth_token_response": tokens,
            "oauth_flow": "protocol",
        }
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.chmod(file_path, 0o600)

        print(json.dumps({
            "success": True,
            "message": "oauth json generated (protocol flow)",
            "email": email,
            "provider": resolved_provider,
            "file_path": file_path,
            "account_id": account_id,
            "expires_at": expires_at,
            "flow": "protocol",
        }, ensure_ascii=False))
        return 0

    except Exception as error:
        print(json.dumps({
            "success": False, "message": str(error), "email": email,
            "traceback": traceback.format_exc(), "flow": "protocol",
        }, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
