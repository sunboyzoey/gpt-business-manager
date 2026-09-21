"""
支付核心逻辑 — 生成 Plus/Team 支付链接、无痕打开浏览器、检测订阅状态
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Optional

from curl_cffi import requests as cffi_requests
from core.browser_runtime import ensure_browser_display_available
from core.proxy_utils import build_requests_proxy_config

# from ..database.models import Account  # removed: external dep

logger = logging.getLogger(__name__)

PAYMENT_CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
TEAM_CHECKOUT_BASE_URL = "https://chatgpt.com/checkout/openai_llc/"


def _build_proxies(proxy: Optional[str]) -> Optional[dict]:
    return build_requests_proxy_config(proxy)


_COUNTRY_CURRENCY_MAP = {
    "SG": "SGD",
    "US": "USD",
    "TR": "TRY",
    "JP": "JPY",
    "HK": "HKD",
    "GB": "GBP",
    "EU": "EUR",
    "AU": "AUD",
    "CA": "CAD",
    "IN": "INR",
    "BR": "BRL",
    "MX": "MXN",
}


def _extract_oai_did(cookies_str: str) -> Optional[str]:
    """从 cookie 字符串中提取 oai-device-id"""
    for part in cookies_str.split(";"):
        part = part.strip()
        if part.startswith("oai-did="):
            return part[len("oai-did=") :].strip()
    return None


def _extract_cookie_value(cookies_str: str, name: str) -> Optional[str]:
    """通用 cookie 取值,支持 'name=' 前缀匹配,返回 URL-decoded 后的原值"""
    target = name + "="
    for part in (cookies_str or "").split(";"):
        part = part.strip()
        if part.startswith(target):
            return part[len(target):].strip()
    return None


# 浏览器请求 /payments/checkout 时附带的 SPA 标识,缺这些 OpenAI 后端会
# 把请求判定为"API 直调"而不给 trial promo。值不一定要每天更新 ——
# OpenAI 检查的是"格式像合法 SPA 请求"而不是"必须是某个特定 build"。
# 这里固定一组从用户真实抓包拿到的 prod 标识。
_CHATGPT_SPA_HEADERS = {
    "oai-client-build-number": "6782977",
    "oai-client-version": "prod-9e28b4117fc5a7f525e5033449e299b74816d3b7",
    "Origin": "https://chatgpt.com",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9",
    "x-openai-target-path": "/backend-api/payments/checkout",
    "x-openai-target-route": "/backend-api/payments/checkout",
}


def _build_checkout_headers(
    access_token: str,
    cookies_str: str,
    promo_campaign_id: str,
) -> dict:
    """构造一个尽量贴近浏览器 SPA 的请求 header 集合。

    关键点:
      - Referer 必须含 ?promo_campaign=<id> query param,
        OpenAI 后端识别用户"从 promo 入口进来"靠这个
      - x-oai-is 同步 __Secure-oai-is cookie (浏览器 SPA 行为)
      - oai-device-id 同步 oai-did cookie
      - SPA 标识 header (build / version) 防止被识别为 API 直调

    没加的:
      - openai-sentinel-token: 需要执行 OpenAI 的 sentinel.sdk.js 计算 POW,
        伪造难,目前忽略 —— 如果加了上面 4 项 trial 还不出,再考虑搞 sentinel
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "oai-language": "zh-CN",
        "Referer": f"https://chatgpt.com/?promo_campaign={promo_campaign_id}",
    }
    headers.update(_CHATGPT_SPA_HEADERS)
    if cookies_str:
        headers["cookie"] = cookies_str
        oai_did = _extract_oai_did(cookies_str)
        if oai_did:
            headers["oai-device-id"] = oai_did
        # __Secure-oai-is cookie 同步到 x-oai-is header
        # (浏览器 SPA 行为 —— 服务端校验这两个一致)
        oai_is = _extract_cookie_value(cookies_str, "__Secure-oai-is")
        if oai_is:
            headers["x-oai-is"] = oai_is
    return headers


def _parse_cookie_str(cookies_str: str, domain: str) -> list:
    """将 'key=val; key2=val2' 格式解析为 Playwright cookie 列表"""
    cookies = []
    for part in cookies_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        cookies.append(
            {
                "name": name.strip(),
                "value": value.strip(),
                "domain": domain,
                "path": "/",
            }
        )
    return cookies


def _open_url_system_browser(url: str) -> bool:
    """回退方案：调用系统浏览器以无痕模式打开"""
    platform = sys.platform
    try:
        if platform == "win32":
            for browser, flag in [("chrome", "--incognito"), ("msedge", "--inprivate")]:
                executable = shutil.which(browser)
                if not executable:
                    continue
                try:
                    subprocess.Popen([executable, flag, url])
                    return True
                except Exception:
                    continue
            os.startfile(url)  # type: ignore[attr-defined]
            return True
        elif platform == "darwin":
            subprocess.Popen(
                ["open", "-a", "Google Chrome", "--args", "--incognito", url]
            )
            return True
        else:
            for binary in ["google-chrome", "chromium-browser", "chromium"]:
                try:
                    subprocess.Popen([binary, "--incognito", url])
                    return True
                except FileNotFoundError:
                    continue
    except Exception as e:
        logger.warning(f"系统浏览器无痕打开失败: {e}")
    return False


def generate_plus_link(
    account: Any,
    proxy: Optional[str] = None,
    country: str = "SG",
) -> str:
    """生成 Plus 支付链接(尽量伪装成浏览器 SPA 请求,争取拿到 trial promo)。

    跟之前版本的差异:
      - 新增 entry_point=all_plans_pricing_modal (浏览器 SPA 调用必带)
      - 新增 Referer 含 ?promo_campaign=plus-1-month-free (识别 promo 入口的关键)
      - 新增 x-oai-is header (同步 __Secure-oai-is cookie)
      - 新增 SPA build/version/UA/sec-ch-ua 等 client 标识
    缺这些字段时,OpenAI 后端可能创建无 promo 的 checkout session ($20/月正价)。
    """
    if not account.access_token:
        raise ValueError("账号缺少 access_token")

    currency = _COUNTRY_CURRENCY_MAP.get(country, "USD")
    promo_id = "plus-1-month-free"
    headers = _build_checkout_headers(account.access_token, account.cookies or "", promo_id)

    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {"country": country, "currency": currency},
        "promo_campaign": {
            "promo_campaign_id": promo_id,
            "is_coupon_from_query_param": False,
        },
        "checkout_ui_mode": "custom",
    }

    resp = cffi_requests.post(
        PAYMENT_CHECKOUT_URL,
        headers=headers,
        json=payload,
        proxies=_build_proxies(proxy),
        timeout=30,
        impersonate="chrome110",
    )
    resp.raise_for_status()
    data = resp.json()
    if "checkout_session_id" in data:
        return TEAM_CHECKOUT_BASE_URL + data["checkout_session_id"]
    raise ValueError(data.get("detail", "API 未返回 checkout_session_id"))


def generate_team_link(
    account: Any,
    workspace_name: str = "MyTeam",
    price_interval: str = "month",
    seat_quantity: int = 5,
    proxy: Optional[str] = None,
    country: str = "SG",
) -> str:
    """生成 Team 支付链接 (同 Plus 一样伪装成浏览器 SPA 请求)"""
    if not account.access_token:
        raise ValueError("账号缺少 access_token")

    currency = _COUNTRY_CURRENCY_MAP.get(country, "USD")
    promo_id = "team-1-month-free"
    headers = _build_checkout_headers(account.access_token, account.cookies or "", promo_id)

    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptteamplan",
        "team_plan_data": {
            "workspace_name": workspace_name,
            "price_interval": price_interval,
            "seat_quantity": seat_quantity,
        },
        "billing_details": {"country": country, "currency": currency},
        "promo_campaign": {
            "promo_campaign_id": promo_id,
            "is_coupon_from_query_param": True,
        },
        "cancel_url": "https://chatgpt.com/#pricing",
        "checkout_ui_mode": "custom",
    }

    resp = cffi_requests.post(
        PAYMENT_CHECKOUT_URL,
        headers=headers,
        json=payload,
        proxies=_build_proxies(proxy),
        timeout=30,
        impersonate="chrome110",
    )
    resp.raise_for_status()
    data = resp.json()
    if "checkout_session_id" in data:
        return TEAM_CHECKOUT_BASE_URL + data["checkout_session_id"]
    raise ValueError(data.get("detail", "API 未返回 checkout_session_id"))


def open_url_incognito(url: str, cookies_str: Optional[str] = None) -> bool:
    """用 Playwright 以无痕模式打开 URL，可注入 cookie"""
    import threading

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("playwright 未安装，回退到系统浏览器")
        return _open_url_system_browser(url)

    def _launch():
        try:
            with sync_playwright() as p:
                ensure_browser_display_available(False)
                browser = p.chromium.launch(headless=False, args=["--incognito"])
                ctx = browser.new_context()
                if cookies_str:
                    ctx.add_cookies(_parse_cookie_str(cookies_str, "chatgpt.com"))
                page = ctx.new_page()
                page.goto(url)
                # 保持窗口打开直到用户关闭
                page.wait_for_timeout(300_000)  # 最多等待 5 分钟
        except Exception as e:
            logger.warning(f"Playwright 无痕打开失败: {e}")

    threading.Thread(target=_launch, daemon=True).start()
    return True


def check_subscription_status(account: Any, proxy: Optional[str] = None) -> str:
    """
    检测账号当前订阅状态。

    Returns:
        'free' / 'plus' / 'team'
    """
    if not account.access_token:
        raise ValueError("账号缺少 access_token")

    headers = {
        "Authorization": f"Bearer {account.access_token}",
        "Content-Type": "application/json",
    }

    resp = cffi_requests.get(
        "https://chatgpt.com/backend-api/me",
        headers=headers,
        proxies=_build_proxies(proxy),
        timeout=20,
        impersonate="chrome110",
    )
    resp.raise_for_status()
    data = resp.json()

    # 解析订阅类型
    plan = data.get("plan_type") or ""
    if "team" in plan.lower():
        return "team"
    if "plus" in plan.lower():
        return "plus"

    # 尝试从 orgs 或 workspace 信息判断
    orgs = data.get("orgs", {}).get("data", [])
    for org in orgs:
        settings_ = org.get("settings", {})
        if settings_.get("workspace_plan_type") in ("team", "enterprise"):
            return "team"

    return "free"
