"""BUSINESS 子域服务:OpenAI 加域 + CF DNS 配置 + 验证 + 同步

依赖配置项(config_store):
  - cf_api_token              (Cloudflare API Token, Edit Zone DNS 权限)
  - openai_admin_cookies      (粘贴的 admin.openai.com cookie 字符串 / JSON)

Linux 部署友好:纯 HTTP 调用,无浏览器依赖。
"""
from __future__ import annotations

import base64
import json
import random
import re
import socket
import string
import contextlib
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from core.config_store import config_store
from core.db import BusinessDomainModel, engine

OPENAI_HOST = "https://admin.openai.com"

# ─────────────────────────────────────────────────────────────────
# 全局 BUSINESS 域 API 互斥锁 + 限频
#
# 所有走外部 CF/OpenAI API 的 CRUD (create_domain / delete_domain /
# sync_from_openai) 都进这把锁, 保证:
#   1) 同一时刻全进程只有 1 个域名 CRUD 在调外部 API (mutex)
#   2) 上次操作结束到下次开始至少隔 _DOMAIN_API_MIN_INTERVAL 秒 (throttle)
#
# 串行所有路径 — UI 多人点 / rotation 自动 / 业务代码主动调 —
# 避免 CF rate-limit (4 req/s per zone) 和 OpenAI workspace 风控。
# ─────────────────────────────────────────────────────────────────

_DOMAIN_API_LOCK = threading.Lock()
_DOMAIN_API_LAST_AT: float = 0.0
_DOMAIN_API_MIN_INTERVAL = 3.0


@contextlib.contextmanager
def _global_domain_api_throttle(op_label: str = ""):
    """所有调外部 CF/OpenAI API 的入口共用这把锁 + 限频。

    yield 之前: 拿锁 -> 必要时 sleep 到满足最小间隔
    yield 之后(包括异常路径): 更新时间戳 -> 释放锁
    """
    global _DOMAIN_API_LAST_AT
    _DOMAIN_API_LOCK.acquire()
    try:
        delta = time.time() - _DOMAIN_API_LAST_AT
        if delta < _DOMAIN_API_MIN_INTERVAL:
            time.sleep(_DOMAIN_API_MIN_INTERVAL - delta)
        yield
    finally:
        _DOMAIN_API_LAST_AT = time.time()
        _DOMAIN_API_LOCK.release()
CF_HOST = "https://api.cloudflare.com/client/v4"

# 子域 DNS 默认配置(沿用 cgifu.it.com 通配 MX 的值)
DEFAULT_MX = [
    {"server": "route1.mx.cloudflare.net", "priority": 100},
    {"server": "route2.mx.cloudflare.net", "priority": 97},
    {"server": "route3.mx.cloudflare.net", "priority": 44},
]
DEFAULT_SPF = "v=spf1 include:_spf.mx.cloudflare.net ~all"
DEFAULT_SUBDOMAIN_LEN = 8
DNS_POLL_TIMEOUT = 90
VERIFY_RETRIES = 3
VERIFY_RETRY_DELAY = 6
CF_REMOVED_STATUS = "cf_removed"
SYNC_PRESERVED_STATUSES = {CF_REMOVED_STATUS}


class BusinessDomainError(Exception):
    """业务异常,用户能看懂的错误信息"""


class BusinessDomainTransientError(BusinessDomainError):
    """瞬时错误(SSL EOF / TimeoutError / 连接被重置等),应当重试。
    跟 BusinessDomainError 的区别:这里只是网络层抖动,不代表 OpenAI/CF 真的拒绝。
    """


class CookieExpiredError(BusinessDomainError):
    """OpenAI cookie 已过期/无效"""


# ─────────────────────────────────────────────────────────────────
#  Cookie 解析(支持多种粘贴格式)
# ─────────────────────────────────────────────────────────────────

REQUIRED_OPENAI_COOKIES = ["oai-access-token", "__session"]
USEFUL_OPENAI_COOKIES = [
    "oai-access-token", "__session", "oai-tenant", "cf_clearance",
    "__cf_bm", "oai-did", "__cflb", "oai-id-token",
]


_SESSION_JSON_FIELD_MAP = {
    "accessToken": "oai-access-token",
    "sessionToken": "__session",
}


def _try_convert_session_json(parsed: dict) -> dict[str, str] | None:
    """如果是 ChatGPT Session API 响应 JSON，自动映射为 cookie 字段。"""
    if "accessToken" not in parsed and "sessionToken" not in parsed:
        return None
    result: dict[str, str] = {}
    for src, dst in _SESSION_JSON_FIELD_MAP.items():
        val = parsed.get(src)
        if val and isinstance(val, str):
            result[dst] = val
    return result or None


def parse_cookie_blob(blob: str) -> dict[str, str]:
    """智能解析多种 cookie 粘贴格式 → {name: value}

    支持:
      1. JSON 数组(EditThisCookie 导出):[{"name":..., "value":...}, ...]
      2. ChatGPT Session JSON(含 accessToken / sessionToken) → 自动转换
      3. JSON 对象:{"name": "value", ...}
      4. document.cookie 字符串:"a=1; b=2; c=3"
    """
    blob = (blob or "").strip()
    if not blob:
        return {}

    # 尝试 JSON
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list):
            return {c.get("name", ""): c.get("value", "") for c in parsed if c.get("name")}
        if isinstance(parsed, dict):
            converted = _try_convert_session_json(parsed)
            if converted is not None:
                return converted
            return {k: str(v) for k, v in parsed.items()}
    except (json.JSONDecodeError, ValueError):
        pass

    # 字符串格式 a=1; b=2; c=3
    result: dict[str, str] = {}
    for part in blob.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                result[k] = v
    return result


def get_openai_cookies() -> dict[str, str]:
    """从 config_store 读 cookie,失败抛 CookieExpiredError"""
    blob = config_store.get("openai_admin_cookies", "")
    if not blob:
        raise CookieExpiredError(
            "OpenAI 母号 Cookie 未配置。请到设置页粘贴 admin.openai.com 的 Cookie"
        )
    cookies = parse_cookie_blob(blob)
    missing = [k for k in REQUIRED_OPENAI_COOKIES if not cookies.get(k)]
    if missing:
        raise CookieExpiredError(
            f"OpenAI Cookie 缺少关键字段: {missing}。请重新粘贴"
        )

    # 检查 JWT 过期
    jwt = cookies.get("oai-access-token", "")
    if jwt:
        try:
            payload_b64 = jwt.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = int(claims.get("exp", 0))
            if exp and exp - time.time() < 60:
                raise CookieExpiredError(
                    f"OpenAI access_token 已过期({datetime.fromtimestamp(exp)})。请重新粘贴 Cookie"
                )
        except CookieExpiredError:
            raise
        except Exception:
            pass

    return {k: v for k, v in cookies.items() if k in USEFUL_OPENAI_COOKIES}


def cookies_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def cookies_remaining_seconds(cookies: dict[str, str]) -> int:
    """返回 access_token 还剩多少秒,无法解析返回 0"""
    jwt = cookies.get("oai-access-token", "")
    if not jwt:
        return 0
    try:
        payload_b64 = jwt.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        return max(0, int(claims.get("exp", 0)) - int(time.time()))
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────────
#  HTTP 工具(自动绕过 localhost 代理)
# ─────────────────────────────────────────────────────────────────

_NO_PROXY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
)


def _is_localhost(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def http_json(method: str, url: str, body=None, headers=None, timeout: int = 20):
    data = json.dumps(body).encode() if body is not None else b""
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = _NO_PROXY_OPENER.open if _is_localhost(url) else urllib.request.urlopen

    def _decode_response(body_bytes: bytes, content_type: str = "", final_url: str = ""):
        if not body_bytes:
            return {}
        try:
            return json.loads(body_bytes)
        except (json.JSONDecodeError, ValueError):
            preview = body_bytes.decode(errors="ignore").strip()
            return {
                "error": "响应不是 JSON",
                "content_type": content_type,
                "url": final_url,
                "body_preview": preview[:500],
                "_non_json": True,
            }

    try:
        with opener(req, timeout=timeout) as r:
            return r.status, _decode_response(
                r.read() or b"",
                r.headers.get("Content-Type", ""),
                r.geturl(),
            )
    except urllib.error.HTTPError as e:
        body_bytes = e.read() or b""
        return e.code, _decode_response(
            body_bytes,
            e.headers.get("Content-Type", "") if e.headers else "",
            e.geturl(),
        )
    except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
        raise BusinessDomainTransientError(f"HTTP 请求失败: {url} ({e})")


def _body_preview(body: Any) -> str:
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body)
    return text[:500]


def _raise_if_openai_session_lost(action: str, status: int, body: Any) -> None:
    if status in (401, 403):
        raise CookieExpiredError(f"OpenAI 拒绝请求 ({status})，请重新粘贴 admin.openai.com Cookie")

    if isinstance(body, dict) and body.get("_non_json"):
        final_url = str(body.get("url", ""))
        preview = str(body.get("body_preview", ""))
        if "auth.openai.com" in final_url or "auth.openai.com" in preview or "/log-in" in final_url:
            raise CookieExpiredError(
                "OpenAI 母号 Cookie 已失效，或粘贴的不是 admin.openai.com 登录后的 Cookie。"
                "请重新登录 admin.openai.com 后，到设置页粘贴最新 Cookie"
            )
        raise BusinessDomainError(
            f"{action}失败: OpenAI 返回非 JSON 响应 "
            f"({body.get('content_type') or 'unknown content-type'}): {preview[:200]}"
        )


# ─────────────────────────────────────────────────────────────────
#  OpenAI Admin API 客户端
# ─────────────────────────────────────────────────────────────────


def _openai_headers(cookies: dict[str, str]) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Cookie": cookies_header(cookies),
        "Referer": f"{OPENAI_HOST}/identity",
        "Origin": OPENAI_HOST,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    }


def openai_list_domains(cookies: dict[str, str]) -> list[dict]:
    status, body = http_json("GET", f"{OPENAI_HOST}/api/domains",
                              headers=_openai_headers(cookies))
    _raise_if_openai_session_lost("列出 OpenAI 域", status, body)
    if status >= 400:
        raise BusinessDomainError(f"列出 OpenAI 域失败 ({status}): {body}")
    # API 返回 {"domains": [...]} 或裸 list
    if isinstance(body, list):
        return body
    return body.get("domains", body.get("data", body.get("result", [])))


def openai_add_domain(hostname: str, cookies: dict[str, str]) -> dict:
    status, body = http_json("POST", f"{OPENAI_HOST}/api/domains",
                              body={"hostname": hostname},
                              headers=_openai_headers(cookies))
    _raise_if_openai_session_lost("OpenAI 添加域", status, body)
    if status >= 400:
        raise BusinessDomainError(f"OpenAI 添加域失败 ({status}): {body}")
    return body


def openai_verify_domain(domain_id: str, cookies: dict[str, str]) -> tuple[int, dict]:
    return http_json("POST", f"{OPENAI_HOST}/api/domains/{domain_id}/verify",
                     body=None, headers=_openai_headers(cookies))


def openai_delete_domain(domain_id: str, cookies: dict[str, str]) -> tuple[bool, str]:
    status, body = http_json("DELETE", f"{OPENAI_HOST}/api/domains/{domain_id}",
                              headers=_openai_headers(cookies))
    if status in (200, 204):
        return True, ""
    _raise_if_openai_session_lost("OpenAI 删除域", status, body)
    return False, f"HTTP {status}: {body}"


# ─────────────────────────────────────────────────────────────────
#  Cloudflare API 客户端
# ─────────────────────────────────────────────────────────────────


def _cf_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def cf_get_zone_id(base_domain: str, token: str) -> str:
    status, body = http_json("GET", f"{CF_HOST}/zones?name={base_domain}",
                              headers=_cf_headers(token))
    if status != 200 or not body.get("success"):
        raise BusinessDomainError(f"查询 CF zone 失败: {body}")
    result = body.get("result", [])
    if not result:
        raise BusinessDomainError(f"在 Cloudflare 找不到域名 {base_domain}")
    return result[0]["id"]


def cf_list_zones(token: str) -> list[dict]:
    """列出账号下所有 zone,返回 [{name, id}, ...]"""
    status, body = http_json("GET", f"{CF_HOST}/zones?per_page=50",
                              headers=_cf_headers(token))
    if status != 200 or not body.get("success"):
        return []
    return [{"name": z["name"], "id": z["id"]} for z in body.get("result", [])]


def resolve_base_domain(hostname: str, zones: list[dict]) -> tuple[str, str]:
    """从 zone 列表里找出 hostname 的真实 base_domain 和 zone_id。
    用最长后缀匹配。若 hostname 本身就是某个 zone,返回 (hostname, zone_id) 表示根域。
    若都不匹配返回 ("", "")。
    """
    hostname = hostname.lower()
    best_name = ""
    best_id = ""
    for z in zones:
        zname = z["name"].lower()
        if hostname == zname or hostname.endswith("." + zname):
            if len(zname) > len(best_name):
                best_name = zname
                best_id = z["id"]
    return best_name, best_id


def cf_create_records(zone_id: str, full_subdomain: str, dns_token: str, token: str) -> list[str]:
    records = [
        {"type": "TXT", "name": full_subdomain,
         "content": f"openai-domain-verification={dns_token}", "ttl": 1},
        {"type": "TXT", "name": full_subdomain, "content": DEFAULT_SPF, "ttl": 1},
    ]
    for mx in DEFAULT_MX:
        records.append({
            "type": "MX", "name": full_subdomain,
            "content": mx["server"], "priority": mx["priority"], "ttl": 1,
        })

    created_ids: list[str] = []
    for rec in records:
        status, body = http_json(
            "POST", f"{CF_HOST}/zones/{zone_id}/dns_records",
            body=rec, headers=_cf_headers(token))
        if status not in (200, 201) or not body.get("success"):
            # 回滚
            for rid in created_ids:
                try:
                    http_json("DELETE", f"{CF_HOST}/zones/{zone_id}/dns_records/{rid}",
                              headers=_cf_headers(token))
                except Exception:
                    pass
            raise BusinessDomainError(
                f"CF 添加 {rec['type']} 失败: {body.get('errors', body)}")
        created_ids.append(body["result"]["id"])
    return created_ids


def cf_list_records_by_name(zone_id: str, hostname: str, token: str) -> list[dict]:
    """列出某 hostname 当前在 CF zone 的所有 DNS 记录,用于幂等补齐时判断已有哪些。"""
    status, body = http_json(
        "GET",
        f"{CF_HOST}/zones/{zone_id}/dns_records?name={hostname}&per_page=100",
        headers=_cf_headers(token),
    )
    if status != 200 or not body.get("success"):
        return []
    return body.get("result") or []


def cf_delete_records(zone_id: str, record_ids: list[str], token: str) -> int:
    """删除一批 DNS 记录,返回成功数"""
    ok = 0
    for rid in record_ids:
        if not rid:
            continue
        try:
            status, _ = http_json(
                "DELETE", f"{CF_HOST}/zones/{zone_id}/dns_records/{rid}",
                headers=_cf_headers(token))
            if status in (200, 204):
                ok += 1
        except Exception:
            pass
    return ok


def cf_delete_records_checked(zone_id: str, record_ids: list[str], token: str) -> tuple[int, list[str]]:
    """删除一批 DNS 记录,返回 (成功数,错误列表)。

    404 视为已不存在,不算错误,保证“只删 CF 映射”可以幂等重试。
    """
    ok = 0
    errors: list[str] = []
    for rid in record_ids:
        if not rid:
            continue
        try:
            status, body = http_json(
                "DELETE", f"{CF_HOST}/zones/{zone_id}/dns_records/{rid}",
                headers=_cf_headers(token))
            if status in (200, 204):
                ok += 1
            elif status == 404:
                continue
            else:
                errors.append(f"{rid}: HTTP {status} {_body_preview(body)}")
        except Exception as e:
            errors.append(f"{rid}: {e}")
    return ok, errors


def _is_business_cf_record(record: dict[str, Any]) -> bool:
    record_type = str(record.get("type") or "").upper()
    content = str(record.get("content") or "").strip()
    if record_type == "TXT":
        return (
            content.startswith("openai-domain-verification=")
            or content == DEFAULT_SPF
        )
    if record_type == "MX":
        target = content.rstrip(".").lower()
        return target in {item["server"].lower() for item in DEFAULT_MX}
    return False


def cf_business_record_ids_for_hostname(
    zone_id: str,
    hostname: str,
    token: str,
    stored_record_ids: list[str] | None = None,
) -> list[str]:
    """返回应删除的 CF DNS record ids。

    优先包含本地保存的 record id；同时按 hostname 查询当前 CF 记录并补充本系统
    创建的验证 TXT、SPF、默认 MX，处理同步导入或 record id 过期的情况。
    """
    ids: list[str] = []
    seen: set[str] = set()

    def _add(record_id: str):
        record_id = str(record_id or "").strip()
        if record_id and record_id not in seen:
            seen.add(record_id)
            ids.append(record_id)

    for record_id in stored_record_ids or []:
        _add(record_id)

    for record in cf_list_records_by_name(zone_id, hostname, token):
        if _is_business_cf_record(record):
            _add(str(record.get("id") or ""))

    return ids


# ─────────────────────────────────────────────────────────────────
#  工具
# ─────────────────────────────────────────────────────────────────


def random_subdomain_prefix(length: int = DEFAULT_SUBDOMAIN_LEN) -> str:
    chars = string.ascii_lowercase + string.digits
    while True:
        s = "".join(random.choices(chars, k=length))
        if any(c.isalpha() for c in s):
            return s


def wait_dns_propagation(full_subdomain: str, dns_token: str,
                          timeout: int = DNS_POLL_TIMEOUT) -> Optional[float]:
    """轮询 dig 直到 TXT 记录可见。"""
    expected = f"openai-domain-verification={dns_token}"
    start = time.time()
    while time.time() - start < timeout:
        try:
            out = subprocess.check_output(
                ["dig", "TXT", full_subdomain, "+short", "@1.1.1.1"],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode()
            if expected in out:
                return time.time() - start
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        time.sleep(2)
    return None


# ─────────────────────────────────────────────────────────────────
#  Service 主流程
# ─────────────────────────────────────────────────────────────────


def _now():
    return datetime.now(timezone.utc)


def _serialize(model: BusinessDomainModel) -> dict[str, Any]:
    return {
        "id": model.id,
        "hostname": model.hostname,
        "base_domain": model.base_domain,
        "openai_domain_id": model.openai_domain_id,
        "status": model.status,
        "note": model.note,
        "owner_machine_id": getattr(model, "owner_machine_id", "") or "",
        "created_at": model.created_at.isoformat() if model.created_at else "",
        "updated_at": model.updated_at.isoformat() if model.updated_at else "",
    }


def _append_note(existing: str, suffix: str, *, limit: int = 1000) -> str:
    existing = (existing or "").strip()
    suffix = (suffix or "").strip()
    if not suffix:
        return existing[:limit]
    return (existing + ("\n" if existing else "") + suffix)[:limit]


def _json_string_list(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw or "[]")
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip() for item in parsed if str(item or "").strip()]


def list_domains(scope: str = "all") -> list[dict[str, Any]]:
    """列出 BUSINESS 子域。

    scope:
      - "all" (默认): 所有
      - "self": 只本机 owner
      - "public": 只 owner='' (公共/旧数据)
      - "others": 别的机器 owner
    """
    from core.machine_id import current_machine_id
    me = current_machine_id()
    with Session(engine) as session:
        q = select(BusinessDomainModel).order_by(BusinessDomainModel.created_at.desc())
        rows = session.exec(q).all()
        if scope == "self":
            rows = [
                r for r in rows
                if (r.owner_machine_id or "") == me
                and r.status != CF_REMOVED_STATUS
            ]
        elif scope == "public":
            rows = [r for r in rows if not (r.owner_machine_id or "")]
        elif scope == "others":
            rows = [r for r in rows if (r.owner_machine_id or "") and r.owner_machine_id != me]
        return [_serialize(r) for r in rows]


def create_domain(base_domain: str, note: str = "") -> dict[str, Any]:
    """创建一个 Business 子域(全自动:加域 + DNS + 验证)。

    全程持有全局域 API 锁,串行所有路径(UI / rotation / 业务代码),
    防止并发触发 CF rate-limit 或 OpenAI workspace 风控。
    """
    with _global_domain_api_throttle(f"create_domain({base_domain})"):
        cf_token = config_store.get("cf_api_token", "").strip()
        if not cf_token:
            raise BusinessDomainError("CF API Token 未配置")

        cookies = get_openai_cookies()  # 可能抛 CookieExpiredError

        base_domain = base_domain.strip().lower()
        if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", base_domain):
            raise BusinessDomainError(f"根域名格式不正确: {base_domain}")

        zone_id = cf_get_zone_id(base_domain, cf_token)

        prefix = random_subdomain_prefix()
        hostname = f"{prefix}.{base_domain}"

        # 调 OpenAI 加域
        domain_obj = openai_add_domain(hostname, cookies)
        domain_id = domain_obj["id"]
        dns_token = domain_obj["dns_verification_token"]

        # 加 DNS
        try:
            record_ids = cf_create_records(zone_id, hostname, dns_token, cf_token)
        except Exception as e:
            # CF 失败:回滚 OpenAI
            try:
                openai_delete_domain(domain_id, cookies)
            except Exception:
                pass
            raise

        # 入库(先 pending)
        # owner_machine_id = 本机 ID, 让本机后续独占该子域
        from core.machine_id import current_machine_id
        with Session(engine) as session:
            model = BusinessDomainModel(
                hostname=hostname,
                base_domain=base_domain,
                openai_domain_id=domain_id,
                cf_zone_id=zone_id,
                cf_record_ids=json.dumps(record_ids),
                dns_verification_token=dns_token,
                status="pending",
                note=note,
                owner_machine_id=current_machine_id(),
            )
            session.add(model)
            session.commit()
            session.refresh(model)
            model_id = model.id

        # 等 DNS + 验证
        elapsed = wait_dns_propagation(hostname, dns_token)
        if elapsed is None:
            _update_status(model_id, "failed")
            raise BusinessDomainError(f"DNS 传播超时(子域已加但未验证): {hostname}")

        verified = False
        for attempt in range(VERIFY_RETRIES):
            status, body = openai_verify_domain(domain_id, cookies)
            if status < 400 and body.get("status") == "verified":
                verified = True
                break
            time.sleep(VERIFY_RETRY_DELAY)

        _update_status(model_id, "verified" if verified else "failed")

        with Session(engine) as session:
            m = session.get(BusinessDomainModel, model_id)
            return _serialize(m)


def _infer_base_domain(hostname: str) -> str:
    """从 hostname 推断 base_domain。处理 it.com / co.uk 这类两级 TLD。"""
    parts = hostname.strip().lower().split(".")
    if len(parts) < 2:
        return ""
    two_level_tlds = {"it.com", "co.uk", "com.cn", "org.cn", "net.cn"}
    last_two = ".".join(parts[-2:])
    if last_two in two_level_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _retry_on_transient(label: str, fn, *args,
                         max_attempts: int = 3,
                         backoff_seconds: float = 3.0, **kwargs):
    """对 fn(*args, **kwargs) 包装重试:仅 BusinessDomainTransientError 重试;
    其他异常和返回值直传。max_attempts=3, 退避 3s / 6s。"""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fn(*args, **kwargs)
        except BusinessDomainTransientError as e:
            last_exc = e
            if attempt == max_attempts:
                break
            time.sleep(backoff_seconds * attempt)
    raise last_exc if last_exc else BusinessDomainTransientError(f"{label} 重试耗尽")


def ensure_subdomain_verified(hostname: str, *,
                              note: str = "imported_via_migration",
                              dns_propagation_timeout: int = 60,
                              verify_retries: int = 5,
                              verify_retry_delay: int = 3) -> dict[str, Any]:
    """幂等地确保 hostname 在 OpenAI workspace 已 verified + CF DNS 完整。

    用于"导入迁移包"流程的子域校验补齐。
    - 已 verified 直接跳过
    - workspace 有但 pending → 重跑 verify
    - workspace 无 → openai_add_domain + 写缺失的 DNS 记录 + dig + verify
    - 写 DNS 时按 hostname 先 list 现有,只补缺失的(避免重复 MX/TXT)
    - 不写入 BusinessDomainModel(导入校验产生的子域归 note 标识)

    Returns dict: {
        ok: bool,
        hostname: str,
        action: 'no_op' / 'verified_pending' / 'created' / 'failed',
        reason: '' / 'domain_owned_elsewhere' / 'dns_propagation_timeout' /
                'verify_timeout' / 'openai_add_failed' / 'cf_write_failed',
        domain_id: str,
        error: str,  # 详细错误(仅失败时)
    }
    """
    hostname = (hostname or "").strip().lower()
    if not hostname:
        return {"ok": False, "hostname": "", "action": "failed",
                "reason": "empty_hostname", "domain_id": "", "error": ""}

    base_domain = _infer_base_domain(hostname)
    if not base_domain:
        return {"ok": False, "hostname": hostname, "action": "failed",
                "reason": "cannot_infer_base", "domain_id": "", "error": ""}

    with _global_domain_api_throttle(f"ensure_subdomain_verified({hostname})"):
        cf_token = config_store.get("cf_api_token", "").strip()
        if not cf_token:
            return {"ok": False, "hostname": hostname, "action": "failed",
                    "reason": "cf_token_missing", "domain_id": "", "error": ""}

        try:
            cookies = get_openai_cookies()
        except CookieExpiredError as e:
            return {"ok": False, "hostname": hostname, "action": "failed",
                    "reason": "openai_cookie_expired", "domain_id": "",
                    "error": str(e)}

        try:
            try:
                zone_id = _retry_on_transient(
                    "cf_get_zone_id", cf_get_zone_id, base_domain, cf_token,
                )
            except BusinessDomainTransientError as e:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "transient_giveup", "domain_id": "",
                        "error": f"cf_get_zone_id: {e}"}
            except BusinessDomainError as e:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "cf_zone_not_found", "domain_id": "",
                        "error": str(e)}

            try:
                domains = _retry_on_transient(
                    "openai_list_domains", openai_list_domains, cookies,
                )
            except BusinessDomainTransientError as e:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "transient_giveup", "domain_id": "",
                        "error": f"openai_list_domains: {e}"}
            except (BusinessDomainError, CookieExpiredError) as e:
                reason = ("openai_cookie_expired"
                          if isinstance(e, CookieExpiredError) else "openai_list_failed")
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": reason, "domain_id": "", "error": str(e)}

            existing = next(
                (d for d in domains if (d.get("hostname") or "").lower() == hostname),
                None,
            )

            domain_id = ""
            dns_token = ""
            if existing:
                domain_id = existing.get("id") or ""
                dns_token = existing.get("dns_verification_token") or ""
                if (existing.get("status") or "") == "verified":
                    return {"ok": True, "hostname": hostname, "action": "no_op",
                            "reason": "", "domain_id": domain_id, "error": ""}
            else:
                try:
                    result = _retry_on_transient(
                        "openai_add_domain", openai_add_domain, hostname, cookies,
                    )
                except BusinessDomainTransientError as e:
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "transient_giveup", "domain_id": "",
                            "error": f"openai_add_domain: {e}"}
                except CookieExpiredError as e:
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "openai_cookie_expired", "domain_id": "",
                            "error": str(e)}
                except BusinessDomainError as e:
                    err = str(e)
                    lower = err.lower()
                    reason = "openai_add_failed"
                    if any(k in lower for k in ("already", "claimed", "reserved", "in use", "taken")):
                        reason = "domain_owned_elsewhere"
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": reason, "domain_id": "", "error": err}
                domain_id = result.get("id") or ""
                dns_token = result.get("dns_verification_token") or ""

            if not domain_id or not dns_token:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "openai_response_invalid", "domain_id": domain_id,
                        "error": "missing id or dns_verification_token"}

            try:
                existing_records = _retry_on_transient(
                    "cf_list_records_by_name",
                    cf_list_records_by_name, zone_id, hostname, cf_token,
                )
            except BusinessDomainTransientError as e:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "transient_giveup", "domain_id": domain_id,
                        "error": f"cf_list_records_by_name: {e}"}
            existing_mx = {(r.get("content") or "").strip(".").lower()
                           for r in existing_records if r.get("type") == "MX"}
            existing_txt = {(r.get("content") or "")
                            for r in existing_records if r.get("type") == "TXT"}

            mx_targets = [
                ("route1.mx.cloudflare.net", 100),
                ("route2.mx.cloudflare.net", 97),
                ("route3.mx.cloudflare.net", 44),
            ]
            for srv, pri in mx_targets:
                if srv.lower() in existing_mx:
                    continue
                try:
                    status, body = _retry_on_transient(
                        f"cf_write_mx({srv})", http_json,
                        "POST", f"{CF_HOST}/zones/{zone_id}/dns_records",
                        body={"type": "MX", "name": hostname, "content": srv,
                              "priority": pri, "ttl": 1, "comment": note},
                        headers=_cf_headers(cf_token),
                    )
                except BusinessDomainTransientError as e:
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "transient_giveup", "domain_id": domain_id,
                            "error": f"cf_write_mx {srv}: {e}"}
                if not (status in (200, 201) and body.get("success")):
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "cf_write_failed", "domain_id": domain_id,
                            "error": f"MX {srv}: {body.get('errors')}"}

            verification_txt = f"openai-domain-verification={dns_token}"
            if verification_txt not in existing_txt:
                try:
                    status, body = _retry_on_transient(
                        "cf_write_txt_verification", http_json,
                        "POST", f"{CF_HOST}/zones/{zone_id}/dns_records",
                        body={"type": "TXT", "name": hostname, "content": verification_txt,
                              "ttl": 1, "comment": note},
                        headers=_cf_headers(cf_token),
                    )
                except BusinessDomainTransientError as e:
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "transient_giveup", "domain_id": domain_id,
                            "error": f"cf_write_txt_verification: {e}"}
                if not (status in (200, 201) and body.get("success")):
                    return {"ok": False, "hostname": hostname, "action": "failed",
                            "reason": "cf_write_failed", "domain_id": domain_id,
                            "error": f"TXT verification: {body.get('errors')}"}

            spf_txt = "v=spf1 include:_spf.mx.cloudflare.net ~all"
            if spf_txt not in existing_txt:
                try:
                    _retry_on_transient(
                        "cf_write_txt_spf", http_json,
                        "POST", f"{CF_HOST}/zones/{zone_id}/dns_records",
                        body={"type": "TXT", "name": hostname, "content": spf_txt,
                              "ttl": 1, "comment": note},
                        headers=_cf_headers(cf_token),
                    )
                except BusinessDomainTransientError:
                    pass  # SPF 失败不阻断

            elapsed = wait_dns_propagation(hostname, dns_token, timeout=dns_propagation_timeout)
            if elapsed is None:
                return {"ok": False, "hostname": hostname, "action": "failed",
                        "reason": "dns_propagation_timeout", "domain_id": domain_id, "error": ""}

            last_status = ""
            for _ in range(verify_retries):
                try:
                    v_status, v_body = _retry_on_transient(
                        "openai_verify_domain",
                        openai_verify_domain, domain_id, cookies,
                    )
                except BusinessDomainTransientError as e:
                    last_status = f"transient:{e}"
                    time.sleep(verify_retry_delay)
                    continue
                s = (v_body or {}).get("status") if isinstance(v_body, dict) else ""
                last_status = s or ""
                if v_status < 400 and s == "verified":
                    action = "verified_pending" if existing else "created"
                    return {"ok": True, "hostname": hostname, "action": action,
                            "reason": "", "domain_id": domain_id, "error": ""}
                time.sleep(verify_retry_delay)

            return {"ok": False, "hostname": hostname, "action": "failed",
                    "reason": "verify_timeout", "domain_id": domain_id,
                    "error": f"last_status={last_status}"}
        except Exception as e:
            return {"ok": False, "hostname": hostname, "action": "failed",
                    "reason": "exception", "domain_id": "", "error": str(e)[:200]}


def _update_status(model_id: int, status: str):
    with Session(engine) as session:
        m = session.get(BusinessDomainModel, model_id)
        if m:
            m.status = status
            m.updated_at = _now()
            m.last_synced_at = _now()
            session.add(m)
            session.commit()


def claim_domain(domain_id: int) -> dict[str, Any]:
    """把公共域 (owner_machine_id 为空) 认领为本机。

    - 只允许认领 owner_machine_id == "" 的 (strict 模式下不可用的公共池)
    - 已被其他机器认领的不允许抢, 避免误操作
    - 用于 sync_from_openai 导入后 / 旧数据迁移时, 让用户主动归属
    """
    from core.machine_id import current_machine_id
    me = current_machine_id()
    with Session(engine) as session:
        row = session.get(BusinessDomainModel, domain_id)
        if row is None:
            raise BusinessDomainError(f"子域 id={domain_id} 不存在")
        existing_owner = (row.owner_machine_id or "").strip()
        if existing_owner and existing_owner != me:
            raise BusinessDomainError(
                f"子域 {row.hostname} 已归属其他机器 ({existing_owner[:12]}), "
                "不可在本机认领"
            )
        if existing_owner == me:
            return _serialize(row)  # 已是本机的, 直接返回
        row.owner_machine_id = me
        stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
        suffix = f"[{stamp}] claimed by machine {me}"
        existing_note = (row.note or "").strip()
        row.note = (existing_note + ("\n" if existing_note else "") + suffix)[:1000]
        row.updated_at = _now()
        session.add(row)
        session.commit()
        return _serialize(row)


def release_domain(domain_id: int) -> dict[str, Any]:
    """把本机域释放回公共池 (owner_machine_id 清空)。仅允许释放本机所属的。"""
    from core.machine_id import current_machine_id
    me = current_machine_id()
    with Session(engine) as session:
        row = session.get(BusinessDomainModel, domain_id)
        if row is None:
            raise BusinessDomainError(f"子域 id={domain_id} 不存在")
        owner = (row.owner_machine_id or "").strip()
        if owner and owner != me:
            raise BusinessDomainError(
                f"子域 {row.hostname} 归属其他机器 ({owner[:12]}), 不可释放"
            )
        row.owner_machine_id = ""
        stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
        suffix = f"[{stamp}] released to public by machine {me}"
        existing_note = (row.note or "").strip()
        row.note = (existing_note + ("\n" if existing_note else "") + suffix)[:1000]
        row.updated_at = _now()
        session.add(row)
        session.commit()
        return _serialize(row)


def reset_domain_status(domain_id: int) -> dict[str, Any]:
    """手动把 banned/failed 状态的子域改回 verified。

    - 仅 banned / failed 允许重置 (verified/pending 不需要)
    - note 保留历史并追加 [timestamp] manually reset (便于审计)
    - 同步清掉 BusinessRTLoopRunner 内存里的 banned set, 长跑后续可再选
    """
    with Session(engine) as session:
        row = session.get(BusinessDomainModel, domain_id)
        if row is None:
            raise BusinessDomainError(f"子域 id={domain_id} 不存在")
        if row.status not in ("banned", "failed"):
            raise BusinessDomainError(
                f"子域 {row.hostname} 当前状态 '{row.status}', 无需重置"
            )
        old_status = row.status
        row.status = "verified"
        stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
        suffix = f"[{stamp}] manually reset from {old_status} to verified"
        existing = (row.note or "").strip()
        row.note = (existing + ("\n" if existing else "") + suffix)[:1000]
        row.updated_at = _now()
        session.add(row)
        session.commit()
        hostname = row.hostname
        result = _serialize(row)

    # 通知 runner 清掉内存 banned 标记 (runner 没启动时是空操作)
    try:
        from services.business_rt_loop import BusinessRTLoopRunner
        BusinessRTLoopRunner.instance().clear_banned_hostname(hostname)
    except Exception:
        pass
    return result


def delete_domain(model_id: int, mode: str = "full") -> dict[str, Any]:
    """删除 BUSINESS 子域。

    mode=full: 删除 CF DNS + OpenAI 域 + 本地 DB。
    mode=cf_only: 只删除 CF DNS,保留 OpenAI 域,本地标记为 cf_removed。
    """
    mode = (mode or "full").strip().lower()
    if mode not in {"full", "cf_only"}:
        raise BusinessDomainError(f"未知删除模式: {mode}")

    with _global_domain_api_throttle(f"delete_domain(id={model_id}, mode={mode})"):
        cf_token = config_store.get("cf_api_token", "").strip()

        with Session(engine) as session:
            model = session.get(BusinessDomainModel, model_id)
            if not model:
                raise BusinessDomainError("域名不存在")
            record_ids = _json_string_list(model.cf_record_ids)
            zone_id = model.cf_zone_id
            openai_id = model.openai_domain_id
            hostname = model.hostname

        cf_deleted = 0
        if mode == "cf_only" and not cf_token:
            raise BusinessDomainError("CF API Token 未配置,无法只删除 CF 映射")
        if mode == "cf_only" and not zone_id:
            raise BusinessDomainError(f"子域 {hostname} 缺少 CF zone_id,无法只删除 CF 映射")
        if cf_token and zone_id:
            target_record_ids = cf_business_record_ids_for_hostname(
                zone_id, hostname, cf_token, record_ids,
            )
            if target_record_ids:
                if mode == "cf_only":
                    cf_deleted, cf_errors = cf_delete_records_checked(
                        zone_id, target_record_ids, cf_token,
                    )
                    if cf_errors:
                        raise BusinessDomainError(
                            f"CF DNS 记录删除失败: {cf_errors[0]}"
                        )
                else:
                    cf_deleted = cf_delete_records(zone_id, target_record_ids, cf_token)

        openai_deleted = False
        openai_msg = ""
        if mode == "full" and openai_id:
            try:
                cookies = get_openai_cookies()
                openai_deleted, openai_msg = openai_delete_domain(openai_id, cookies)
            except CookieExpiredError as e:
                openai_msg = str(e)
            except Exception as e:
                openai_msg = str(e)

        with Session(engine) as session:
            m = session.get(BusinessDomainModel, model_id)
            if m:
                if mode == "cf_only":
                    stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
                    m.status = CF_REMOVED_STATUS
                    m.cf_record_ids = "[]"
                    m.note = _append_note(
                        m.note,
                        f"[{stamp}] CF DNS records removed; OpenAI domain retained",
                    )
                    m.updated_at = _now()
                    m.last_synced_at = _now()
                    session.add(m)
                else:
                    session.delete(m)
                session.commit()

        return {
            "deleted": mode == "full",
            "mode": mode,
            "hostname": hostname,
            "cf_records_deleted": cf_deleted,
            "openai_deleted": openai_deleted,
            "openai_message": openai_msg,
            "status": CF_REMOVED_STATUS if mode == "cf_only" else "deleted",
            "local_deleted": mode == "full",
        }


def sync_from_openai() -> dict[str, Any]:
    """以 OpenAI 为准:导入远端有的、删除本地多余的孤儿。全程持全局域 API 锁。

    跳过:
      - 根域(hostname 等于 CF zone name)
      - 不属于我们 CF 管辖的任何 zone 的域
    """
    with _global_domain_api_throttle("sync_from_openai"):
        cookies = get_openai_cookies()
        cf_token = config_store.get("cf_api_token", "").strip()
        zones: list[dict] = []
        if cf_token:
            zones = cf_list_zones(cf_token)

        remote = openai_list_domains(cookies)

        remote_by_host: dict[str, dict] = {}
        for d in remote:
            host = (d.get("hostname") or "").lower()
            if not host:
                continue
            remote_by_host[host] = d

        added: list[str] = []
        updated: list[str] = []
        deleted_orphans: list[str] = []
        skipped: list[str] = []

        with Session(engine) as session:
            local = session.exec(select(BusinessDomainModel)).all()
            local_by_host = {l.hostname.lower(): l for l in local}

            for host, remote_d in remote_by_host.items():
                base, zone_id = resolve_base_domain(host, zones)
                # 1) 跳过根域(hostname 本身就是某个 zone 的名字)
                if base and base == host:
                    skipped.append(host)
                    continue
                # 2) 跳过 CF 不管辖的域
                if not base:
                    skipped.append(host)
                    continue

                if host in local_by_host:
                    m = local_by_host[host]
                    new_status = "verified" if remote_d.get("status") == "verified" else "pending"
                    changed = False
                    preserve_local_status = m.status in SYNC_PRESERVED_STATUSES
                    if not preserve_local_status and m.status != new_status:
                        m.status = new_status; changed = True
                    if not m.openai_domain_id and remote_d.get("id"):
                        m.openai_domain_id = remote_d["id"]; changed = True
                    if not m.cf_zone_id and zone_id:
                        m.cf_zone_id = zone_id; changed = True
                    if m.base_domain != base:
                        m.base_domain = base; changed = True
                    m.last_synced_at = _now()
                    m.updated_at = _now()
                    session.add(m)
                    if changed:
                        updated.append(host)
                else:
                    new_model = BusinessDomainModel(
                        hostname=host,
                        base_domain=base,
                        openai_domain_id=remote_d.get("id", ""),
                        cf_zone_id=zone_id,
                        cf_record_ids="[]",
                        dns_verification_token=remote_d.get("dns_verification_token", ""),
                        status="verified" if remote_d.get("status") == "verified" else "imported",
                        note="(同步导入)",
                        last_synced_at=_now(),
                    )
                    session.add(new_model)
                    added.append(host)

            # 本地有、远端无:直接删
            for host, local_m in local_by_host.items():
                if host not in remote_by_host:
                    session.delete(local_m)
                    deleted_orphans.append(host)

            session.commit()

        return {
            "added": added,
            "updated": updated,
            "deleted_orphans": deleted_orphans,
            "skipped": skipped,
            "remote_total": len(remote_by_host),
        }


def get_verified_hostnames(scope: str = "self") -> list[str]:
    """供注册页下拉用:返回 verified hostname。

    默认 strict 模式 (scope="self"): 只返回 owner_machine_id 等于本机的。
    传 scope="all" 可拿到全部 verified (含其他机器的, 仅 UI 展示用,
    不要拿来给 worker 选)。
    """
    from core.machine_id import current_machine_id
    me = current_machine_id()
    with Session(engine) as session:
        rows = session.exec(
            select(BusinessDomainModel)
            .where(BusinessDomainModel.status == "verified")
        ).all()
        if scope == "self":
            rows = [r for r in rows if (r.owner_machine_id or "") == me]
        return [r.hostname for r in rows]


def is_business_hostname(hostname: str) -> bool:
    """判断给定的 hostname 是否是已验证的 Business 域"""
    with Session(engine) as session:
        result = session.exec(
            select(BusinessDomainModel)
            .where(BusinessDomainModel.hostname == hostname)
            .where(BusinessDomainModel.status == "verified")
        ).first()
        return result is not None
