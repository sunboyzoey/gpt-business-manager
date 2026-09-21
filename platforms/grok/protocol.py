"""
Grok (x.ai) 纯协议注册引擎

注册流程:
1. 访问注册页 → 获取 Next.js action ID + state_tree
2. CreateEmailValidationCode (gRPC-web) → 发送验证码
3. 等待验证码 (通过外部 mailbox callback)
4. VerifyEmailValidationCode (gRPC-web) → 验证邮箱
5. 解决 Turnstile (YesCaptcha API)
6. 提交注册 (Next.js Server Action)
7. SSO cookie 链 → 获取 sso / sso-rw

参考: 53282dd1/grok_register_fixed.py
"""

import json
import os
import random
import re
import secrets
import string
import struct
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from curl_cffi import requests as curl_requests

# ── 常量 ──────────────────────────────────────────────────────

ACCOUNTS_BASE = "https://accounts.x.ai"
GRPC_SERVICE = "auth_mgmt.AuthManagement"
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
TURNSTILE_WEBSITE_URL = f"{ACCOUNTS_BASE}/sign-up?redirect=grok-com"
SIGNIN_WEBSITE_URL = f"{ACCOUNTS_BASE}/sign-in?redirect=grok-com"

_BROWSERS = ["chrome131", "chrome133a", "chrome136"]

COMMON_HEADERS = {
    "accept-language": "en-US,en;q=0.9",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

GRPC_HEADERS = {
    "content-type": "application/grpc-web+proto",
    "x-grpc-web": "1",
    "x-user-agent": "connect-es/2.1.1",
    "accept": "*/*",
    "origin": ACCOUNTS_BASE,
    "referer": f"{ACCOUNTS_BASE}/sign-up?redirect=grok-com",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
}

ACTION_ID_REGEX = re.compile(r"7f[a-fA-F0-9]{40}")
DEFAULT_STATE_TREE = (
    "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22"
    "%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22"
    "children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22"
    "refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2C"
    "null%2Cnull%2Ctrue%5D"
)

_ALLOWED_SSO_HOSTS = frozenset({
    "auth.x.ai", "auth.grok.com", "auth.grokipedia.com",
    "auth.grokusercontent.com", "accounts.x.ai",
})

FIRST_NAMES = [
    "Alex", "Ava", "Ethan", "Emma", "Liam", "Mia", "Noah", "Olivia",
    "Ryan", "Sophia", "James", "Isabella", "Lucas", "Charlotte", "Mason",
]
LAST_NAMES = [
    "Anderson", "Brown", "Clark", "Davis", "Evans", "Garcia", "Harris",
    "Johnson", "Miller", "Smith", "Wilson", "Moore", "Taylor", "Thomas",
]


# ── Protobuf 编码 ────────────────────────────────────────────

def encode_varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def encode_string_field(field_number: int, value: str) -> bytes:
    tag = (field_number << 3) | 2
    data = value.encode("utf-8")
    return encode_varint(tag) + encode_varint(len(data)) + data


def wrap_grpc_web(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def parse_grpc_web_response(data: bytes) -> dict:
    result = {"status": None, "payload": b"", "trailers": {}}
    if len(data) < 5:
        return result
    pos = 0
    while pos < len(data):
        if pos + 5 > len(data):
            break
        flag = data[pos]
        length = struct.unpack(">I", data[pos + 1: pos + 5])[0]
        pos += 5
        if pos + length > len(data):
            break
        frame_data = data[pos: pos + length]
        pos += length
        if flag == 0x80:
            trailer_str = frame_data.decode("utf-8", errors="replace")
            for line in trailer_str.strip().split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    result["trailers"][k.strip()] = v.strip()
            result["status"] = result["trailers"].get("grpc-status", "unknown")
        elif flag == 0x00:
            result["payload"] = frame_data
    return result


# ── 工具 ──────────────────────────────────────────────────────

def _rand_ua() -> Tuple[str, str]:
    """返回随机 (user_agent, sec_ch_ua)"""
    version = random.choice(["131", "133", "136"])
    ua = (
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
    )
    sec = f'"Not:A-Brand";v="99", "Google Chrome";v="{version}", "Chromium";v="{version}"'
    return ua, sec


def _rand_name() -> Tuple[str, str]:
    return secrets.choice(FIRST_NAMES), secrets.choice(LAST_NAMES)


def _rand_password(length: int = 14) -> str:
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*_-+="),
    ]
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + remaining
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def _delay(low=0.3, high=1.0):
    time.sleep(random.uniform(low, high))


def _extract_action_id_from_js(js_text: str) -> Optional[str]:
    if not js_text:
        return None
    m = ACTION_ID_REGEX.search(js_text)
    return m.group(0) if m else None


def _extract_action_id_from_html(html: str) -> Optional[str]:
    if not html:
        return None
    m = re.search(r'"(7f[a-fA-F0-9]{40})"', html)
    return m.group(1) if m else None


def _cookie_attr(cookie: Any, attr: str, default: Any = None) -> Any:
    try:
        return getattr(cookie, attr, default)
    except Exception:
        return default


def _collect_cookies(session) -> tuple[dict, list[dict]]:
    cookie_dict: dict[str, str] = {}
    cookie_list: list[dict] = []
    jar = getattr(getattr(session, "cookies", None), "jar", None)
    if jar:
        try:
            for cookie in list(jar):
                name = str(_cookie_attr(cookie, "name", "") or "").strip()
                value = str(_cookie_attr(cookie, "value", "") or "")
                if not name:
                    continue
                cookie_dict[name] = value
                cookie_list.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": str(_cookie_attr(cookie, "domain", "") or ""),
                        "path": str(_cookie_attr(cookie, "path", "/") or "/"),
                        "expires": _cookie_attr(cookie, "expires", None),
                        "secure": bool(_cookie_attr(cookie, "secure", False)),
                        "httpOnly": bool(
                            getattr(cookie, "has_nonstandard_attr", lambda _name: False)("HttpOnly")
                        ),
                    }
                )
        except Exception:
            pass
    if not cookie_dict:
        try:
            for name, value in session.cookies.items():
                clean_name = str(name or "").strip()
                if clean_name:
                    clean_value = str(value or "")
                    cookie_dict[clean_name] = clean_value
                    cookie_list.append({"name": clean_name, "value": clean_value})
        except Exception:
            pass
    return cookie_dict, cookie_list


def _save_cookies(
    email: str,
    session,
    *,
    output_dir: str = "cookies/grok",
    sso: str = "",
    sso_rw: str = "",
) -> tuple[str, dict]:
    cookie_dict, cookie_list = _collect_cookies(session)
    if sso and "sso" not in cookie_dict:
        cookie_dict["sso"] = sso
        cookie_list.append(
            {
                "name": "sso",
                "value": sso,
                "domain": ".grok.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
            }
        )
    if sso_rw and "sso-rw" not in cookie_dict:
        cookie_dict["sso-rw"] = sso_rw
        cookie_list.append(
            {
                "name": "sso-rw",
                "value": sso_rw,
                "domain": ".grok.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
            }
        )

    payload = {
        "platform": "grok",
        "email": str(email or "").strip(),
        "cookies": cookie_dict,
        "cookie_list": cookie_list,
        "cookie_header": "; ".join(f"{name}={value}" for name, value in cookie_dict.items()),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }

    os.makedirs(output_dir, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(email or "grok").strip())
    file_path = os.path.abspath(os.path.join(output_dir, f"{safe_name}.json"))
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return file_path, cookie_dict


def _normalize_subscription_tier(tier: str) -> tuple[str, str]:
    value = str(tier or "").strip().upper()
    if "GROK_PRO" in value or value.endswith("_PRO"):
        return "grok_pro", "Grok Pro"
    if "SUPERGROK" in value or "SUPER_GROK" in value or "SUPER" in value:
        return "supergrok", "SuperGrok"
    if value:
        return value.lower(), value
    return "basic", "普通号"


def _summarize_subscription_payload(data: dict) -> dict:
    from datetime import datetime, timezone

    subscriptions = data.get("subscriptions") if isinstance(data, dict) else []
    if not isinstance(subscriptions, list):
        subscriptions = []

    active = None
    fallback = None
    for item in subscriptions:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").upper()
        if status.endswith("_ACTIVE") or status == "ACTIVE":
            active = item
            break
        if fallback is None:
            fallback = item

    selected = active or fallback or {}
    tier_key, tier_label = _normalize_subscription_tier(str(selected.get("tier") or ""))
    status = str(selected.get("status") or "").strip()
    is_active = bool(active)
    if not selected:
        tier_key = "basic"
        tier_label = "普通号"
        status = "NO_SUBSCRIPTION"

    return {
        "account_type": tier_key if is_active else "basic",
        "account_type_label": tier_label if is_active else "普通号",
        "subscription_active": is_active,
        "subscription_status": status,
        "subscription_tier": str(selected.get("tier") or ""),
        "billing_period_end": str(
            selected.get("billingPeriodEnd")
            or ((selected.get("stripe") or {}).get("currentPeriodEnd") if isinstance(selected.get("stripe"), dict) else "")
            or ""
        ),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _subscription_probe_error(status: str) -> dict:
    from datetime import datetime, timezone

    return {
        "account_type": "unknown",
        "account_type_label": "未知",
        "subscription_active": False,
        "subscription_status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _set_session_cookie(session, name: str, value: str, *, domain: str = ".grok.com") -> None:
    clean_name = str(name or "").strip()
    clean_value = str(value or "")
    if not clean_name or not clean_value:
        return
    try:
        session.cookies.set(clean_name, clean_value, domain=domain, path="/")
    except Exception:
        pass


_PAYMENT_ROUTE_RETRYABLE_KEYWORDS = (
    "TLS connect error",
    "SSL",
    "UNEXPECTED_EOF",
    "Connection refused",
    "Connection timed out",
    "Connection reset",
    "ProxyError",
    "Couldn't connect to server",
    "curl: (28)",
    "curl: (35)",
    "curl: (56)",
)


def _payment_route_is_retryable(error_msg: str) -> bool:
    msg = str(error_msg or "")
    if any(keyword in msg for keyword in _PAYMENT_ROUTE_RETRYABLE_KEYWORDS):
        return True
    match = re.search(r"HTTP\s+(\d+)", msg)
    if not match:
        return False
    status = int(match.group(1))
    return status in {403, 429, 502, 503, 504, 520, 521, 522, 523, 524}


# ── 注册器 ────────────────────────────────────────────────────

class GrokProtocolRegister:
    """纯协议 Grok 注册（curl_cffi + gRPC-web）"""

    def __init__(
        self,
        proxy: Optional[str] = None,
        payment_proxy: Optional[str] = None,
        payment_proxy_label: str = "",
        log_fn: Callable = print,
        yescaptcha_key: str = "",
        captcha_solver: str = "yescaptcha",
        solver_url: Optional[str] = None,
        turnstile_timeout: int = 120,
        cookie_dir: str = "cookies/grok",
    ):
        self.proxy = proxy
        self.payment_proxy = (payment_proxy or "").strip() or None
        self.payment_proxy_label = (payment_proxy_label or "").strip()
        self.log = log_fn
        self.yescaptcha_key = yescaptcha_key
        self.captcha_solver = (captcha_solver or "yescaptcha").strip().lower() or "yescaptcha"
        self.solver_url = (solver_url or "").strip() or None
        self.turnstile_timeout = turnstile_timeout
        self.cookie_dir = (cookie_dir or "cookies/grok").strip() or "cookies/grok"

        # 随机指纹
        self._browser = random.choice(_BROWSERS)
        self._ua, self._sec_ch_ua = _rand_ua()
        self._headers = {
            **COMMON_HEADERS,
            "user-agent": self._ua,
            "sec-ch-ua": self._sec_ch_ua,
        }
        self._grpc_headers = {
            **GRPC_HEADERS,
            "user-agent": self._ua,
            "sec-ch-ua": self._sec_ch_ua,
        }

        self.session = curl_requests.Session(impersonate=self._browser)
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}

        self.state_tree = ""
        self.turnstile_sitekey = TURNSTILE_SITEKEY
        self.turnstile_website_url = TURNSTILE_WEBSITE_URL
        self.last_payment_error = ""

    # ── gRPC ──

    def _grpc_call(self, method: str, payload: bytes) -> dict:
        url = f"{ACCOUNTS_BASE}/{GRPC_SERVICE}/{method}"
        body = wrap_grpc_web(payload)
        resp = self.session.post(url, headers=self._grpc_headers, data=body)
        if resp.status_code != 200:
            raise RuntimeError(f"gRPC {method} failed: HTTP {resp.status_code} {resp.text[:300]}")
        parsed = parse_grpc_web_response(resp.content)
        grpc_status = parsed.get("status")
        if grpc_status and grpc_status != "0":
            msg = parsed["trailers"].get("grpc-message", "unknown")
            raise RuntimeError(f"gRPC {method} error: {msg}")
        return parsed

    # ── SSO Cookie 链 ──

    def _follow_sso_chain(self, url: str) -> Dict[str, str]:
        collected: Dict[str, str] = {}
        if not url:
            return collected

        self.log("[SSO] 获取 SSO cookies...")

        # 尝试自动重定向
        try:
            self.session.get(
                url,
                headers={
                    **self._headers,
                    "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "referer": f"{ACCOUNTS_BASE}/",
                    "sec-fetch-site": "cross-site",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-dest": "document",
                    "upgrade-insecure-requests": "1",
                },
                allow_redirects=True,
            )
        except Exception:
            pass

        for name in ("sso", "sso-rw"):
            jar = getattr(self.session.cookies, "jar", None)
            if jar:
                for cookie in jar:
                    if getattr(cookie, "name", "") == name and getattr(cookie, "value", ""):
                        collected[name] = cookie.value

        if not collected.get("sso"):
            # 手动逐跳
            hop_url = url
            for _ in range(8):
                try:
                    resp = self.session.get(
                        hop_url,
                        headers={**self._headers, "accept": "text/html,*/*;q=0.8", "referer": f"{ACCOUNTS_BASE}/"},
                        allow_redirects=False,
                    )
                except Exception:
                    break
                for name, value in resp.cookies.items():
                    if name in ("sso", "sso-rw") and value:
                        collected[name] = value
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    if location.startswith("/"):
                        p = urlparse(hop_url)
                        location = f"{p.scheme}://{p.netloc}{location}"
                    if urlparse(location).netloc not in _ALLOWED_SSO_HOSTS:
                        break
                    hop_url = location
                else:
                    break

        if collected.get("sso"):
            self.log(f"[SSO] OK: sso={collected['sso'][:40]}...")
        return collected

    # ── Turnstile ──

    def _solve_turnstile(self, page_url: Optional[str] = None) -> str:
        page_url = page_url or self.turnstile_website_url
        if self.captcha_solver == "local_solver":
            from core.base_captcha import LocalSolverCaptcha

            solver = LocalSolverCaptcha(self.solver_url)
            proxy_note = f" (代理: {self.proxy})" if self.proxy else ""
            self.log(f"[Turnstile] 调用本地 Solver 解码{proxy_note}...")
            token = solver.solve_turnstile(
                page_url,
                self.turnstile_sitekey,
                proxy=self.proxy,
            )
            if not token:
                raise RuntimeError("Turnstile 验证码求解失败")
            self.log(f"[Turnstile] OK: {token[:40]}...")
            return token

        if self.captcha_solver == "manual":
            from core.base_captcha import ManualCaptcha

            solver = ManualCaptcha()
            self.log("[Turnstile] 等待手动验证码 token...")
            token = solver.solve_turnstile(page_url, self.turnstile_sitekey)
            if not token:
                raise RuntimeError("Turnstile 验证码求解失败")
            self.log(f"[Turnstile] OK: {token[:40]}...")
            return token

        if self.captcha_solver != "yescaptcha":
            raise RuntimeError(f"Grok 暂不支持验证码服务: {self.captcha_solver}")

        if not self.yescaptcha_key:
            raise RuntimeError("需要 YesCaptcha Key 来解决 Turnstile 验证码")

        from core.base_captcha import YesCaptcha
        solver = YesCaptcha(self.yescaptcha_key)
        self.log("[Turnstile] 调用 YesCaptcha 解码...")
        token = solver.solve_turnstile(page_url, self.turnstile_sitekey)
        if not token:
            raise RuntimeError("Turnstile 验证码求解失败")
        self.log(f"[Turnstile] OK: {token[:40]}...")
        return token

    # ── 注册步骤 ──

    def _visit_signup(self) -> str:
        """Step 1: 访问注册页获取 action ID"""
        self.log("Step1: 访问注册页...")

        # 临时 session 提取配置
        tmp = curl_requests.Session(impersonate=self._browser)
        if self.proxy:
            tmp.proxies = {"https": self.proxy, "http": self.proxy}

        resp = tmp.get(
            TURNSTILE_WEBSITE_URL,
            headers={**self._headers, "accept": "text/html,*/*;q=0.8", "referer": "https://grok.com/"},
            allow_redirects=True,
        )
        page_url = str(resp.url or TURNSTILE_WEBSITE_URL)
        self.turnstile_website_url = page_url

        # 提取 action ID (从 JS chunks)
        # 注意: x.ai 的 script src 现在带 ?dpl=<hash> 查询串(如 ...js?dpl=7140...),
        # 老正则要求 .js 后紧跟 " 会全部匹配失败(chunk 数=0)→ 拿不到 action ID。
        # 这里允许可选的 ?query 尾巴。
        action_id = None
        script_paths = re.findall(
            r'<script[^>]+src="(/_next/static/chunks/[^"]+?\.js(?:\?[^"]*)?)"', resp.text)
        for path in reversed(script_paths):
            try:
                chunk_resp = tmp.get(
                    f"{ACCOUNTS_BASE}{path}",
                    headers={**self._headers, "accept": "*/*", "referer": page_url},
                )
                if chunk_resp.status_code == 200:
                    action_id = _extract_action_id_from_js(chunk_resp.text)
                    if action_id:
                        break
            except Exception:
                continue

        if not action_id:
            action_id = _extract_action_id_from_html(resp.text)
        if not action_id:
            raise RuntimeError("无法提取 Next.js action ID")

        # 提取 sitekey
        sk_match = re.search(r'sitekey["\s:]+["\']?(0x[0-9A-Za-z]+)', resp.text)
        if sk_match:
            self.turnstile_sitekey = sk_match.group(1)

        # 提取 state_tree
        tree_match = re.search(r'next-router-state-tree":"([^"]+)"', resp.text)
        if tree_match:
            self.state_tree = tree_match.group(1)

        try:
            tmp.close()
        except Exception:
            pass

        # 重建主 session 获取干净 __cf_bm
        self.session = curl_requests.Session(impersonate=self._browser)
        if self.proxy:
            self.session.proxies = {"https": self.proxy, "http": self.proxy}
        try:
            self.session.get(ACCOUNTS_BASE, headers={**self._headers, "accept": "text/html,*/*;q=0.8"}, timeout=10)
        except Exception:
            pass

        self.log(f"  action_id: {action_id[:16]}...")
        return action_id

    def _send_email_code(self, email: str) -> None:
        """Step 2: 发送验证码"""
        self.log(f"Step2: 发送验证码到 {email}...")
        payload = encode_string_field(1, email)
        self._grpc_call("CreateEmailValidationCode", payload)
        self.log("  验证码已发送")

    def _verify_email_code(self, email: str, code: str) -> None:
        """Step 3: 验证邮箱验证码"""
        self.log(f"Step3: 验证邮箱验证码 {code}...")
        payload = encode_string_field(1, email) + encode_string_field(2, code)
        self._grpc_call("VerifyEmailValidationCode", payload)
        self.log("  验证通过")

    def _submit_registration(
        self, email: str, password: str, given_name: str, family_name: str,
        turnstile_token: str, action_id: str, email_code: str,
    ) -> dict:
        """Step 5: 提交注册"""
        self.log("Step5: 提交注册...")

        payload = [{
            "emailValidationCode": email_code,
            "createUserAndSessionRequest": {
                "email": email,
                "givenName": given_name,
                "familyName": family_name,
                "clearTextPassword": password,
                "tosAcceptedVersion": "$undefined",
            },
            "turnstileToken": turnstile_token,
            "promptOnDuplicateEmail": True,
        }]

        tree_val = self.state_tree or DEFAULT_STATE_TREE
        cf_bm = ""
        try:
            cf_bm = self.session.cookies.get("__cf_bm", "")
        except Exception:
            pass

        headers = {
            "user-agent": self._ua,
            "accept": "text/x-component",
            "content-type": "text/plain;charset=UTF-8",
            "origin": ACCOUNTS_BASE,
            "referer": f"{ACCOUNTS_BASE}/sign-up",
            "cookie": f"__cf_bm={cf_bm}",
            "next-router-state-tree": tree_val,
            "next-action": action_id,
        }

        resp = self.session.post(f"{ACCOUNTS_BASE}/sign-up", json=payload, headers=headers)
        resp_text = resp.text or ""
        self.log(f"  HTTP {resp.status_code}, body={len(resp_text)} chars")

        # 解析 RSC 响应获取 verify_url
        verify_url = ""
        action_error = ""
        for raw_line in resp_text.splitlines():
            if ":" not in raw_line:
                continue
            _, line_payload = raw_line.split(":", 1)
            line_payload = line_payload.strip()
            if not line_payload.startswith("{"):
                continue
            try:
                obj = json.loads(line_payload)
            except Exception:
                continue
            if isinstance(obj, dict):
                if obj.get("url"):
                    verify_url = str(obj["url"]).replace("\\/", "/")
                if obj.get("error"):
                    action_error = str(obj["error"])

        if not verify_url:
            m = re.search(r'(https://[^"\s]+set-cookie\?q=[^:"\s]+)', resp_text)
            if m:
                verify_url = m.group(1).replace("\\/", "/")

        if action_error:
            self.log(f"  Server Action error: {action_error}")
            raise RuntimeError(f"注册失败: {action_error}")

        # 跟随 SSO cookie 链
        sso_cookies = self._follow_sso_chain(verify_url) if verify_url else {}

        return {
            "status_code": resp.status_code,
            "sso": sso_cookies.get("sso", ""),
            "sso_rw": sso_cookies.get("sso-rw", ""),
            "verify_url": verify_url,
        }

    def _create_session_fallback(self, email: str, password: str) -> Dict[str, str]:
        """通过 createSession RPC 登录获取 SSO。"""
        self.log("[SSO] 通过 createSession 登录获取 SSO...")
        signin_url = SIGNIN_WEBSITE_URL
        try:
            resp = self.session.get(
                SIGNIN_WEBSITE_URL,
                headers={
                    **self._headers,
                    "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "referer": f"{ACCOUNTS_BASE}/",
                },
                allow_redirects=True,
                timeout=15,
            )
            signin_url = str(resp.url or SIGNIN_WEBSITE_URL)
        except Exception:
            pass
        turnstile_token = self._solve_turnstile(signin_url)

        payload = {
            "rpc": "createSession",
            "req": {
                "createSessionRequest": {
                    "credentials": {
                        "case": "emailAndPassword",
                        "value": {"email": email, "clearTextPassword": password},
                    },
                },
                "turnstileToken": turnstile_token,
            },
        }
        resp = self.session.post(
            f"{ACCOUNTS_BASE}/api/rpc",
            headers={
                **self._headers,
                "accept": "application/json",
                "content-type": "application/json",
                "origin": ACCOUNTS_BASE,
                "referer": signin_url,
            },
            json=payload,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"createSession failed: HTTP {resp.status_code} {resp.text[:200]}")

        data = resp.json()
        cookie_setter_url = str(data.get("cookieSetterUrl") or "").strip()
        if not cookie_setter_url:
            raise RuntimeError("createSession 无 cookieSetterUrl")

        return self._follow_sso_chain(cookie_setter_url)

    def _prime_grok_cookies(self, sso: str, sso_rw: str) -> None:
        """登录后访问 grok.com，让服务端补充可下发的 Cookie。"""
        _set_session_cookie(self.session, "sso", sso)
        _set_session_cookie(self.session, "sso-rw", sso_rw)
        _set_session_cookie(self.session, "i18nextLng", "en", domain="grok.com")

        cookies = {"sso": sso, "sso-rw": sso_rw, "i18nextLng": "en"}
        try:
            resp = self.session.get(
                "https://grok.com/",
                headers={
                    **self._headers,
                    "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "referer": "https://accounts.x.ai/",
                },
                cookies=cookies,
                allow_redirects=True,
                timeout=20,
            )
            self.log(f"[Cookie] grok.com 访问完成: HTTP {resp.status_code}")
        except Exception as exc:
            self.log(f"[Cookie] grok.com 访问失败，仍保存当前 Cookie: {exc}")

    def probe_subscription(self, sso: str, sso_rw: str = "") -> dict:
        """使用当前 SSO 探测 Grok 订阅类型。"""
        clean_sso = str(sso or "").strip()
        clean_sso_rw = str(sso_rw or "").strip()
        if not clean_sso:
            return _subscription_probe_error("MISSING_SSO")

        cookies = {"sso": clean_sso, "i18nextLng": "en"}
        if clean_sso_rw:
            cookies["sso-rw"] = clean_sso_rw

        def request_with(session):
            return session.get(
                "https://grok.com/rest/subscriptions",
                headers={
                    "accept": "application/json, text/plain, */*",
                    "origin": "https://grok.com",
                    "referer": "https://grok.com/",
                    "user-agent": self._ua,
                },
                cookies=cookies,
                timeout=20,
            )

        try:
            resp = request_with(self.session)
            if resp.status_code in (403, 429):
                direct = curl_requests.Session(impersonate=self._browser)
                resp = request_with(direct)
            if resp.status_code != 200:
                return _subscription_probe_error(f"HTTP_{resp.status_code}")
            return _summarize_subscription_payload(resp.json())
        except Exception as exc:
            return _subscription_probe_error(f"ERROR: {exc}")

    def login_and_save_cookies(
        self,
        email: str,
        password: str,
        *,
        max_attempts: int = 2,
    ) -> dict:
        """重新登录已有账号并保存当前完整 Cookie jar。"""
        clean_email = str(email or "").strip()
        clean_password = str(password or "")
        if not clean_email:
            raise RuntimeError("缺少邮箱，无法重新登录")
        if not clean_password:
            raise RuntimeError("缺少密码，无法重新登录")

        max_attempts = max(1, int(max_attempts or 1))
        last_error = ""
        for attempt in range(1, max_attempts + 1):
            attempt_note = f" ({attempt}/{max_attempts})" if max_attempts > 1 else ""
            self.log(f"[Cookie] 重新登录 {clean_email}{attempt_note}...")
            self.session = curl_requests.Session(impersonate=self._browser)
            if self.proxy:
                self.session.proxies = {"https": self.proxy, "http": self.proxy}
            try:
                sso_cookies = self._create_session_fallback(clean_email, clean_password)
                sso = str(sso_cookies.get("sso") or "").strip()
                sso_rw = str(sso_cookies.get("sso-rw") or "").strip()
                if not sso:
                    raise RuntimeError("登录成功但未获取到 SSO cookie")

                self._prime_grok_cookies(sso, sso_rw)
                cookie_path, cookies = _save_cookies(
                    clean_email,
                    self.session,
                    output_dir=self.cookie_dir,
                    sso=sso,
                    sso_rw=sso_rw,
                )
                self.log(f"[Cookie] Cookie 已保存: {cookie_path}")
                subscription = self.probe_subscription(sso, sso_rw)
                return {
                    "email": clean_email,
                    "sso": sso,
                    "sso_rw": sso_rw,
                    "cookies": cookies,
                    "cookie_file": cookie_path,
                    "cookie_count": len(cookies),
                    "sso_account_type": subscription.get("account_type", "unknown"),
                    "sso_account_type_label": subscription.get("account_type_label", "未知"),
                    "sso_subscription": subscription,
                }
            except Exception as exc:
                last_error = str(exc)
                self.log(f"[Cookie] 重新登录失败{attempt_note}: {last_error}")
                if attempt < max_attempts:
                    _delay(1.0, 2.0)

        raise RuntimeError(f"重新登录获取 Cookie 失败: {last_error}")

    # ── Stripe 支付链接 ──

    def get_payment_link(self, email: str, sso: str, sso_rw: str, max_attempts: int = 5) -> str:
        """注册成功后获取 Grok SuperGrok/Pro 支付链接"""
        cookies = {"sso": sso, "i18nextLng": "en"}
        clean_sso_rw = str(sso_rw or "").strip()
        if clean_sso_rw:
            cookies["sso-rw"] = clean_sso_rw
        base_headers = {
            "accept": "*/*",
            "content-type": "application/json",
            "origin": "https://grok.com",
            "referer": "https://grok.com/",
            "user-agent": self._ua,
        }

        import uuid

        max_attempts = max(1, int(max_attempts or 1))
        self.last_payment_error = ""

        candidates: list[tuple[str, Optional[str]]] = []
        seen_proxy_keys = set()

        def add_candidate(label: str, proxy: Optional[str]) -> None:
            clean_proxy = str(proxy or "").strip() or None
            key = clean_proxy or ""
            if key in seen_proxy_keys:
                return
            seen_proxy_keys.add(key)
            candidates.append((label, clean_proxy))

        if self.payment_proxy:
            add_candidate(self.payment_proxy_label or "优先支付代理", self.payment_proxy)
        add_candidate("当前注册代理", self.proxy)
        add_candidate("直连", None)
        max_attempts = max(max_attempts, len(candidates))

        last_error = ""
        route_index = 0
        logged_route_key = object()

        def maybe_switch_route() -> bool:
            nonlocal route_index
            if route_index >= len(candidates) - 1:
                return False
            if not _payment_route_is_retryable(last_error):
                return False
            route_index += 1
            next_label, next_proxy = candidates[route_index]
            if next_proxy:
                self.log(f"[Payment] 当前支付线路失败，切换到{next_label}: {next_proxy}")
            else:
                self.log("[Payment] 当前支付线路失败，切换到直连")
            return True

        for attempt in range(1, max_attempts + 1):
            attempt_note = f" ({attempt}/{max_attempts})" if max_attempts > 1 else ""
            payment_label, payment_proxy = candidates[route_index]
            proxies = {"https": payment_proxy, "http": payment_proxy} if payment_proxy else None
            route_key = payment_proxy or ""
            if route_key != logged_route_key:
                if payment_proxy:
                    self.log(f"[Payment] 使用{payment_label}: {payment_proxy}")
                else:
                    self.log("[Payment] 使用直连请求支付链接")
                logged_route_key = route_key

            # Step 1: 创建 Stripe 客户
            self.log(f"[Payment] Step1: 创建 Stripe 客户{attempt_note}...")
            billing_name = f"{secrets.choice(FIRST_NAMES)} {secrets.choice(LAST_NAMES)}"
            try:
                resp1 = curl_requests.post(
                    "https://grok.com/rest/subscriptions/customer/new",
                    headers={**base_headers, "x-xai-request-id": str(uuid.uuid4())},
                    cookies=cookies,
                    json={"billingInfo": {"name": billing_name, "email": email}},
                    impersonate=self._browser,
                    timeout=20,
                    proxies=proxies,
                )
                if resp1.status_code not in (200, 201, 204):
                    preview = str(resp1.text or "").strip().replace("\n", " ")[:180]
                    last_error = f"创建客户失败: HTTP {resp1.status_code}"
                    if preview:
                        last_error = f"{last_error} - {preview}"
                    self.last_payment_error = last_error
                    self.log(f"[Payment] {last_error}")
                    maybe_switch_route()
                    _delay(1.0, 2.0)
                    continue
                self.log("[Payment] Step1: OK")
            except Exception as e:
                last_error = f"创建客户异常: {e}"
                self.last_payment_error = last_error
                self.log(f"[Payment] {last_error}")
                maybe_switch_route()
                _delay(1.0, 2.0)
                continue

            # Step 2: 创建订阅获取支付链接
            self.log(f"[Payment] Step2: 获取支付链接{attempt_note}...")
            try:
                resp2 = curl_requests.post(
                    "https://grok.com/rest/subscriptions/subscribe/new",
                    headers={**base_headers, "x-xai-request-id": str(uuid.uuid4())},
                    cookies=cookies,
                    json={
                        "stripeHosted": {
                            "successUrl": "https://grok.com/?checkout=success&tier=SUBSCRIPTION_TIER_GROK_PRO&interval=monthly#subscribe"
                        },
                        "priceId": "price_1R6nQ9HJohyvID2ck7FNrVdw",
                        "campaignId": "subcamp_HeAxW",
                        "ignoreExistingActiveSubscriptions": False,
                        "subscriptionType": "MONTHLY",
                        "requestedTier": "REQUESTED_TIER_GROK_PRO",
                    },
                    impersonate=self._browser,
                    timeout=20,
                    proxies=proxies,
                )
                if resp2.status_code != 200:
                    preview = str(resp2.text or "").strip().replace("\n", " ")[:180]
                    last_error = f"创建订阅失败: HTTP {resp2.status_code}"
                    if preview:
                        last_error = f"{last_error} - {preview}"
                    self.last_payment_error = last_error
                    self.log(f"[Payment] {last_error}")
                    maybe_switch_route()
                    _delay(1.0, 2.0)
                    continue
                data = resp2.json() if resp2.content else {}
                payment_link = str(data.get("url") or data.get("checkoutUrl") or "").strip()
                if payment_link:
                    self.last_payment_error = ""
                    self.log("[Payment] ✅ 支付链接已获取")
                    return payment_link
                last_error = f"未返回支付链接: {json.dumps(data, ensure_ascii=False)[:200]}"
                self.last_payment_error = last_error
                self.log(f"[Payment] {last_error}")
            except Exception as e:
                last_error = f"获取支付链接异常: {e}"
                self.last_payment_error = last_error
                self.log(f"[Payment] {last_error}")
                maybe_switch_route()

            _delay(1.0, 2.0)

        self.last_payment_error = last_error
        self.log(f"[Payment] 获取支付链接失败，已重试 {max_attempts} 次: {last_error}")
        return ""

    # ── 公开接口 ──

    def register(
        self,
        email: str,
        password: Optional[str] = None,
        otp_callback: Optional[Callable[[], str]] = None,
        skip_payment_link: bool = False,
    ) -> dict:
        """
        完整注册流程。

        Args:
            email: 注册邮箱
            password: 密码（留空随机生成）
            otp_callback: 获取验证码的回调函数

        Returns:
            dict: {"email", "password", "given_name", "family_name", "sso", "sso_rw"}
        """
        if not password:
            password = _rand_password()
        given_name, family_name = _rand_name()

        # Step 1: 访问注册页
        action_id = self._visit_signup()
        _delay(0.3, 0.8)

        # Step 2: 发送验证码
        self._send_email_code(email)

        # Step 3: 解决 Turnstile（耗时较长，与等待验证码并行）
        _delay(0.2, 0.5)
        turnstile_token = self._solve_turnstile()

        # Step 4: 等待验证码
        if not otp_callback:
            raise RuntimeError("需要 otp_callback 获取验证码")
        code = otp_callback() or ""
        if not code:
            raise RuntimeError("未获取到验证码")
        code = code.strip().replace("-", "").upper()

        # Step 5: 验证邮箱（紧接着提交，减少过期风险）
        _delay(0.2, 0.5)
        self._verify_email_code(email, code)

        # Step 6: 提交注册（验证码刚验证完，立即提交）
        _delay(0.3, 0.8)
        result = self._submit_registration(
            email, password, given_name, family_name,
            turnstile_token, action_id, code,
        )

        # Step 7: SSO fallback
        if result.get("status_code") == 200 and not result.get("sso"):
            try:
                _delay(0.5, 1.0)
                fallback = self._create_session_fallback(email, password)
                result["sso"] = fallback.get("sso", "")
                result["sso_rw"] = fallback.get("sso-rw", "")
            except Exception as e:
                self.log(f"[SSO] fallback 失败: {e}")

        if not result.get("sso"):
            raise RuntimeError("注册成功但未获取到 SSO cookie")

        self.log(f"✅ Grok 注册成功: {email}")

        cookie_path = ""
        cookies = {}
        try:
            cookie_path, cookies = _save_cookies(
                email,
                self.session,
                output_dir=self.cookie_dir,
                sso=result["sso"],
                sso_rw=result.get("sso_rw", ""),
            )
            self.log(f"  Cookie 已保存: {cookie_path}")
        except Exception as e:
            self.log(f"  Cookie 保存失败: {e}")

        # Step 8: 获取 Stripe 支付链接
        payment_link = ""
        if skip_payment_link:
            self.log("[Payment] 设备同步任务，跳过支付链接获取")
        else:
            try:
                _delay(0.3, 0.8)
                payment_link = self.get_payment_link(email, result["sso"], result.get("sso_rw", ""))
            except Exception as e:
                self.log(f"[Payment] 获取支付链接失败: {e}")

        return {
            "email": email,
            "password": password,
            "given_name": given_name,
            "family_name": family_name,
            "sso": result["sso"],
            "sso_rw": result.get("sso_rw", ""),
            "cookies": cookies,
            "cookie_file": cookie_path,
            "cashier_url": payment_link,
        }
