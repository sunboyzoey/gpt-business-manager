"""iCloud Hide-My-Email 原生客户端(纯 Python, 不依赖 Go 服务)。

只需一个 iCloud 网页会话 **Cookie**:
  - dsid   ← 从 Cookie 的 X-APPLE-WEBAUTH-USER(d=...) 取, 或 validate 的 dsInfo.dsid
  - base   ← 调 setup/validate 拿 webservices.mail.url, 把 mailws→maildomainws 派生
             (自动兼容中国区 -china 后缀)
  - clientId ← 随机 UUID; build/mastering ← 固定近版占位

支持: 查(list) / 增(create=generate+reserve) / 停用(deactivate) / 删除(delete) / 恢复(reactivate)。
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests

SETUP_VALIDATE = "https://setup.icloud.com/setup/ws/1/validate"
CLIENT_BUILD = "2413Project28"
CLIENT_MASTERING = "2413B27"
LANG_CODE = "en-us"

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 会话推导缓存: cookie 指纹 -> (dsid, base, client_id, expire_ts)
_SESSION_CACHE: Dict[str, Tuple[str, str, str, float]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 600  # 10 分钟


class IcloudHmeError(Exception):
    pass


def _cookie_from_config() -> str:
    try:
        from core.config_store import config_store
        return str(config_store.get("icloud_cookie", "") or "").strip()
    except Exception:
        return ""


def _headers(cookie: str) -> Dict[str, str]:
    return {
        "Origin": "https://www.icloud.com",
        "Referer": "https://www.icloud.com/",
        "Content-Type": "text/plain",
        "Accept": "*/*",
        "User-Agent": _UA,
        "Cookie": cookie,
    }


def _dsid_from_cookie(cookie: str) -> str:
    m = re.search(r'X-APPLE-WEBAUTH-USER="[^"]*d=(\d+)', cookie or "")
    return m.group(1) if m else ""


def _derive_session(cookie: str) -> Tuple[str, str, str]:
    """返回 (dsid, base_url, client_id)。带缓存。失败抛 IcloudHmeError。"""
    cookie = (cookie or "").strip()
    if not cookie:
        raise IcloudHmeError("未配置 iCloud Cookie")
    key = str(hash(cookie))
    now = time.time()
    with _CACHE_LOCK:
        hit = _SESSION_CACHE.get(key)
        if hit and hit[3] > now:
            return hit[0], hit[1], hit[2]

    client_id = str(uuid.uuid4()).upper()
    try:
        r = requests.post(
            f"{SETUP_VALIDATE}?clientBuildNumber={CLIENT_BUILD}"
            f"&clientMasteringNumber={CLIENT_MASTERING}&clientId={client_id}",
            headers=_headers(cookie), data="{}", timeout=25,
        )
    except Exception as exc:
        raise IcloudHmeError(f"validate 请求失败: {exc}")
    if r.status_code == 421 or r.status_code == 401:
        raise IcloudHmeError("Cookie 已失效(validate 401/421), 请重新抓取 Cookie")
    if r.status_code != 200:
        raise IcloudHmeError(f"validate HTTP {r.status_code}: {r.text[:200]}")
    try:
        data = r.json()
    except Exception:
        raise IcloudHmeError(f"validate 非 JSON: {r.text[:200]}")

    dsid = str((data.get("dsInfo") or {}).get("dsid") or "") or _dsid_from_cookie(cookie)
    ws = data.get("webservices") or {}
    mail_url = (ws.get("mail") or {}).get("url") or ""
    if not mail_url:
        # 兜底: 从任意服务 url 抽 pXX 前缀
        for v in ws.values():
            u = (v or {}).get("url") or ""
            mm = re.search(r"https://(p\d+)-[^./]+(-china)?\.icloud\.com", u)
            if mm:
                mail_url = f"https://{mm.group(1)}-mailws{mm.group(2) or ''}.icloud.com"
                break
    if not (dsid and mail_url):
        raise IcloudHmeError("无法从 Cookie 推导 dsid/base_url(可能账号无 iCloud+ 或 Cookie 不全)")

    base = re.sub(r":\d+$", "", mail_url).replace("-mailws", "-maildomainws").rstrip("/")
    with _CACHE_LOCK:
        _SESSION_CACHE[key] = (dsid, base, client_id, now + _CACHE_TTL)
    return dsid, base, client_id


def invalidate_cache() -> None:
    with _CACHE_LOCK:
        _SESSION_CACHE.clear()


def _url(base: str, path: str, client_id: str, dsid: str) -> str:
    return (f"{base}{path}?clientBuildNumber={CLIENT_BUILD}"
            f"&clientMasteringNumber={CLIENT_MASTERING}&clientId={client_id}&dsid={dsid}")


def _post(cookie: str, base: str, path: str, client_id: str, dsid: str, body: dict) -> dict:
    try:
        r = requests.post(_url(base, path, client_id, dsid), headers=_headers(cookie),
                          data=json.dumps(body), timeout=25)
    except Exception as exc:
        raise IcloudHmeError(f"{path} 请求失败: {exc}")
    return _parse(r, path)


def _get(cookie: str, base: str, path: str, client_id: str, dsid: str) -> dict:
    try:
        r = requests.get(_url(base, path, client_id, dsid), headers=_headers(cookie), timeout=25)
    except Exception as exc:
        raise IcloudHmeError(f"{path} 请求失败: {exc}")
    return _parse(r, path)


def _parse(r, path: str) -> dict:
    if r.status_code in (401, 421):
        invalidate_cache()
        raise IcloudHmeError("Cookie 已失效, 请重新配置 Cookie")
    if r.status_code != 200:
        raise IcloudHmeError(f"{path} HTTP {r.status_code}: {r.text[:200]}")
    try:
        data = r.json()
    except Exception:
        raise IcloudHmeError(f"{path} 非 JSON: {r.text[:200]}")
    if not data.get("success"):
        err = data.get("error") or {}
        raise IcloudHmeError(f"{path} 失败: {err.get('errorMessage') or json.dumps(err, ensure_ascii=False)[:200]}")
    return data.get("result") or {}


# ── 对外 API(cookie 缺省从 config 读) ─────────────────────────

def _sess(cookie: Optional[str]) -> Tuple[str, str, str, str]:
    cookie = (cookie or _cookie_from_config()).strip()
    dsid, base, cid = _derive_session(cookie)
    return cookie, dsid, base, cid


def list_hme(cookie: Optional[str] = None) -> Dict[str, Any]:
    cookie, dsid, base, cid = _sess(cookie)
    res = _get(cookie, base, "/v2/hme/list", cid, dsid)
    return {
        "items": res.get("hmeEmails") or [],
        "forward_to_emails": res.get("forwardToEmails") or [],
        "selected_forward_to": res.get("selectedForwardTo") or "",
    }


def create_hme(label: str = "api", note: str = "", cookie: Optional[str] = None) -> Dict[str, Any]:
    cookie, dsid, base, cid = _sess(cookie)
    gen = _post(cookie, base, "/v1/hme/generate", cid, dsid, {"langCode": LANG_CODE})
    hme = gen.get("hme") or ""
    if not hme:
        raise IcloudHmeError("generate 未返回候选邮箱")
    res = _post(cookie, base, "/v1/hme/reserve", cid, dsid,
                {"hme": hme, "label": label or "api", "note": note or ""})
    return res.get("hme") or {"hme": hme, "label": label}


def deactivate_hme(anonymous_id: str, cookie: Optional[str] = None) -> None:
    cookie, dsid, base, cid = _sess(cookie)
    _post(cookie, base, "/v1/hme/deactivate", cid, dsid, {"anonymousId": anonymous_id})


def reactivate_hme(anonymous_id: str, cookie: Optional[str] = None) -> None:
    cookie, dsid, base, cid = _sess(cookie)
    _post(cookie, base, "/v1/hme/reactivate", cid, dsid, {"anonymousId": anonymous_id})


def delete_hme(anonymous_id: str, cookie: Optional[str] = None) -> None:
    """彻底删除: iCloud 要求先 deactivate 再 delete。"""
    cookie, dsid, base, cid = _sess(cookie)
    try:
        _post(cookie, base, "/v1/hme/deactivate", cid, dsid, {"anonymousId": anonymous_id})
    except IcloudHmeError:
        pass  # 可能已停用
    _post(cookie, base, "/v1/hme/delete", cid, dsid, {"anonymousId": anonymous_id})


def check_cookie(cookie: Optional[str] = None) -> Dict[str, Any]:
    """校验 Cookie 是否可用, 返回推导出的 dsid/base。"""
    cookie, dsid, base, cid = _sess(cookie)
    return {"ok": True, "dsid": dsid, "base_url": base}
