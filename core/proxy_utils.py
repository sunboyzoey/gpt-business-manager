from __future__ import annotations

from typing import Optional
from urllib.parse import quote, unquote, urlsplit, urlunsplit


def normalize_proxy_url(proxy_url: Optional[str]) -> Optional[str]:
    """将 socks5:// 规范化为 socks5h://，避免本地 DNS 泄漏。"""
    if proxy_url is None:
        return None

    value = str(proxy_url).strip()
    if not value:
        return None

    parts = urlsplit(value)
    if (parts.scheme or "").lower() == "socks5":
        parts = parts._replace(scheme="socks5h")
        return urlunsplit(parts)
    return value


def coerce_proxy_url(proxy_url: Optional[str], default_scheme: str = "http") -> Optional[str]:
    """把常见手填代理格式规范化为 URL。

    支持:
      - http://user:pass@host:port
      - socks5://user:pass@host:port
      - user:pass@host:port
      - host:port:user:pass
      - host:port
    """
    if proxy_url is None:
        return None
    value = str(proxy_url).strip()
    if not value:
        return None

    scheme = (default_scheme or "http").strip().lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        scheme = "http"

    if "://" in value:
        return normalize_proxy_url(value)

    if "@" in value:
        return normalize_proxy_url(f"{scheme}://{value}")

    parts = value.split(":")
    if len(parts) >= 4 and parts[1].isdigit():
        host = parts[0].strip()
        port = parts[1].strip()
        username = quote(parts[2].strip(), safe="")
        password = quote(":".join(parts[3:]).strip(), safe="")
        if host and port and username:
            return normalize_proxy_url(f"{scheme}://{username}:{password}@{host}:{port}")

    if len(parts) == 2 and parts[1].isdigit():
        return normalize_proxy_url(f"{scheme}://{value}")

    return normalize_proxy_url(value)


def redact_proxy_url(proxy_url: Optional[str]) -> str:
    """代理日志脱敏：保留协议/主机/端口，不输出用户名密码。"""
    value = str(proxy_url or "").strip()
    if not value:
        return "直连"
    if "://" not in value:
        parts = value.split(":")
        if len(parts) >= 4:
            return f"{parts[0]}:{parts[1]}:***"
        return value
    try:
        parts = urlsplit(value)
        if not parts.hostname:
            return value
        host = parts.hostname
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        if parts.username or parts.password:
            return f"{parts.scheme}://***@{host}"
        return f"{parts.scheme}://{host}"
    except Exception:
        return value


def build_requests_proxy_config(proxy_url: Optional[str]) -> Optional[dict[str, str]]:
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def build_playwright_proxy_config(proxy_url: Optional[str]) -> Optional[dict[str, str]]:
    if not proxy_url:
        return None

    parts = urlsplit(proxy_url)
    if not parts.scheme or not parts.hostname or parts.port is None:
        return {"server": proxy_url}

    config = {"server": f"{parts.scheme}://{parts.hostname}:{parts.port}"}
    if parts.username:
        config["username"] = unquote(parts.username)
    if parts.password:
        config["password"] = unquote(parts.password)
    return config
