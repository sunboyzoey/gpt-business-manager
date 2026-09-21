"""smsbower.app SMS 接码 SDK(纯 stdlib).

参考:https://smsbower.app/cn/api?page=client

端点:`https://smsbower.page/stubs/handler_api.php`
所有请求 GET/POST 都行,必带 `api_key`。

服务码(见 getServicesList 表):
  dr = OpenAI (ChatGPT)          ← 默认
  oi = Tinder
  go = Google / Gmail / YouTube
  tg = Telegram
  fb = Facebook
  ig = Instagram
  ...

国家码(见 getCountries 表):
  39  = 阿根廷                    ← 默认
  187 = 美国
  12  = 美国(虚拟)
  175 = 澳大利亚
  ...

激活生命周期:
  1. getNumber 拿到 (activation_id, phone)
  2. 把 phone 提交到目标平台 → 平台发 SMS
  3. setStatus=1(可选,通知已发)
  4. getStatus 轮询 → STATUS_OK:<code>
  5. setStatus=6 完成 / 或 setStatus=3 请求新短信 / setStatus=8 取消
  ⚠ EARLY_CANCEL_DENIED:取号后 2 分钟内禁止 setStatus=8 取消
"""
from __future__ import annotations

import json
import errno
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_BASE_URL = "https://smsbower.page/stubs/handler_api.php"
DEFAULT_SERVICE = "dr"        # OpenAI (ChatGPT)
DEFAULT_COUNTRY = "39"        # Argentina
DEFAULT_MAX_PRICE = "0.08"    # USD ceiling

# setStatus 状态码(语义化)
STATUS_READY = 1              # 通知号码已就绪(SMS 已发到号码)— 可选
STATUS_REQUEST_RETRY = 3      # 请求另一条 SMS(免费)
STATUS_COMPLETE = 6           # 确认 SMS 收到,完成激活 ★
STATUS_CANCEL = 8             # 取消激活(2 分钟后才允许)


_REQUEST_FAILURE_REASONS = {
    "timeout": "网络请求超时",
    "tls": "TLS 握手或证书校验失败",
    "dns": "DNS 解析失败",
    "connection": "网络连接失败或中断",
    "unknown": "网络请求异常，具体类型未确认",
}


def classify_request_failure(exc: BaseException) -> str:
    """Return a fixed diagnostic category, never exception text or request URLs."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(reason, ssl.SSLError):
        return "tls"
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ConnectionError):
        return "connection"
    if isinstance(reason, OSError):
        if reason.errno == errno.ETIMEDOUT:
            return "timeout"
        if reason.errno in {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
                            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPIPE}:
            return "connection"
    return "unknown"


def request_failure_description(kind: str) -> str:
    return _REQUEST_FAILURE_REASONS.get(kind, _REQUEST_FAILURE_REASONS["unknown"])


class SmsbowerError(RuntimeError):
    def __init__(self, code: str, raw: str = "", *, request_failure_kind: str = ""):
        super().__init__(f"smsbower: {code}{(' | ' + raw) if raw and raw != code else ''}")
        self.code = code
        self.raw = raw
        self.request_failure_kind = (request_failure_kind
                                     if request_failure_kind in _REQUEST_FAILURE_REASONS else "unknown")


class SmsbowerClient:
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        proxy: Optional[str] = None,
        timeout: int = 30,
    ):
        if not api_key or not str(api_key).strip():
            raise ValueError("api_key 不能为空")
        self.api_key = str(api_key).strip()
        self.base_url = base_url.rstrip("?")
        self.proxy = (str(proxy or "").strip() or None)
        self.timeout = max(5, int(timeout))

    # ─── 底层 ───────────────────────────────────────────────

    def _request(self, action: str, **params: Any) -> str:
        """通用 GET 包装。返回原始响应文本(去首尾空白)。"""
        query: dict[str, str] = {"api_key": self.api_key, "action": action}
        for k, v in params.items():
            if v is None or v == "":
                continue
            query[k] = str(v)
        url = self.base_url + "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, method="GET", headers={
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 any-auto-register smsbower-client/1.0",
        })
        if self.proxy:
            handler = urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy})
            opener = urllib.request.build_opener(handler)
        else:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            raw = (e.read() or b"").decode("utf-8", errors="replace")
            raise SmsbowerError(f"HTTP_{e.code}", raw)
        except Exception as e:
            kind = classify_request_failure(e)
            # urllib errors may contain the complete query string (api_key),
            # proxy credentials or provider response. Preserve only a closed
            # category; allocation/charging may still have occurred remotely.
            raise SmsbowerError("REQUEST_FAILED", request_failure_description(kind),
                                request_failure_kind=kind) from None

        # 命中已知"裸"错误码
        bare_errors = {
            "BAD_KEY", "BAD_ACTION", "BAD_SERVICE", "BAD_STATUS",
            "NO_BALANCE", "NO_NUMBERS", "NO_ACTIVATION",
            "ERROR_SQL", "WRONG_MAX_PRICE", "EARLY_CANCEL_DENIED",
            "WRONG_SERVICE", "WRONG_COUNTRY", "BANNED",
        }
        head = body.split(":", 1)[0]
        if head in bare_errors:
            raise SmsbowerError(head, body)
        return body

    def _request_json(self, action: str, **params: Any) -> dict:
        body = self._request(action, **params)
        try:
            return json.loads(body)
        except Exception:
            raise SmsbowerError("NOT_JSON", body[:300])

    # ─── 业务 ───────────────────────────────────────────────

    def balance(self) -> float:
        """ACCESS_BALANCE:<余额> → float (USD)。"""
        body = self._request("getBalance")
        if not body.startswith("ACCESS_BALANCE:"):
            raise SmsbowerError("UNEXPECTED", body)
        try:
            return float(body.split(":", 1)[1].strip())
        except Exception:
            raise SmsbowerError("PARSE_BALANCE", body)

    def get_number(
        self,
        *,
        service: str = DEFAULT_SERVICE,
        country: str | int = DEFAULT_COUNTRY,
        max_price: str | float = DEFAULT_MAX_PRICE,
        provider_ids: Optional[str] = None,
        except_provider_ids: Optional[str] = None,
        min_price: Optional[str | float] = None,
        phone_exception: Optional[str] = None,
    ) -> dict:
        """要号。返回 {activation_id, phone, service, country, max_price}。

        失败抛 SmsbowerError(code='NO_NUMBERS' / 'NO_BALANCE' / ...)。
        """
        body = self._request(
            "getNumber",
            service=service,
            country=str(country),
            maxPrice=str(max_price),
            providerIds=provider_ids,
            exceptProviderIds=except_provider_ids,
            minPrice=str(min_price) if min_price is not None else None,
            phoneException=phone_exception,
        )
        # ACCESS_NUMBER:<id>:<phone>
        if not body.startswith("ACCESS_NUMBER:"):
            raise SmsbowerError("UNEXPECTED", body)
        parts = body.split(":")
        if len(parts) < 3:
            raise SmsbowerError("PARSE_NUMBER", body)
        return {
            "activation_id": parts[1].strip(),
            "phone": parts[2].strip(),
            "service": service,
            "country": str(country),
            "max_price": str(max_price),
            "raw": body,
        }

    def get_status(self, activation_id: str) -> dict:
        """轮询当前激活状态。返回 {state, code?}。

        state ∈ {"waiting", "waiting_retry", "ok", "cancel"}
        """
        body = self._request("getStatus", id=str(activation_id))
        if body == "STATUS_WAIT_CODE":
            return {"state": "waiting", "code": None, "raw": body}
        if body == "STATUS_CANCEL":
            return {"state": "cancel", "code": None, "raw": body}
        if body.startswith("STATUS_OK:"):
            return {"state": "ok", "code": body.split(":", 1)[1].strip(), "raw": body}
        if body.startswith("STATUS_WAIT_RETRY:"):
            return {"state": "waiting_retry", "code": body.split(":", 1)[1].strip(), "raw": body}
        raise SmsbowerError("UNEXPECTED", body)

    def set_status(self, activation_id: str, status: int) -> str:
        """改激活状态。1/3/6/8 之一。返回 ACCESS_* 响应字串。"""
        body = self._request("setStatus", id=str(activation_id), status=int(status))
        return body

    # 语义化包装
    def confirm(self, activation_id: str) -> str:
        """status=6 — SMS 已收到、确认完成激活(终态)。"""
        return self.set_status(activation_id, STATUS_COMPLETE)

    def cancel(self, activation_id: str) -> str:
        """status=8 — 取消激活;**取号后 2 分钟内会 EARLY_CANCEL_DENIED**。"""
        return self.set_status(activation_id, STATUS_CANCEL)

    def request_retry(self, activation_id: str) -> str:
        """status=3 — 请求下一条 SMS(免费)。"""
        return self.set_status(activation_id, STATUS_REQUEST_RETRY)

    def notify_sent(self, activation_id: str) -> str:
        """status=1 — 通知"号码已就绪,SMS 已发到号码"。可选。"""
        return self.set_status(activation_id, STATUS_READY)

    def get_countries(self) -> dict:
        """拉 smsbower 完整国家代码表。返回 {code: country_metadata_dict}。

        响应是 dict[str, dict],典型字段:
          {"0": {"id":0, "rus":"Россия", "eng":"Russia", "chn":"俄罗斯", ...},
           "1": {"id":1, "eng":"Ukraine", ...}, ...}
        失败时返回空 dict。
        """
        return self._request_json("getCountries")

    def get_prices(self, country: str | int | None = None,
                   service: str | None = None) -> dict:
        """拉 smsbower 价格/库存表(getPrices)。
        指定 country/service 可缩小范围;不指定返回全量。
        响应结构: {country_id: {service_code: {"cost":..., "count":...}}}
        """
        params: dict[str, Any] = {}
        if country is not None and str(country).strip():
            params["country"] = str(country)
        if service:
            params["service"] = str(service)
        return self._request_json("getPrices", **params)
