"""Gmail app-password transport with exact, read-only plus-address matching.

Only the fixed Gmail TLS endpoints are supported.  SEARCH results are candidates,
never evidence that a message belongs to an alias.  Each available inbox, all-mail
and junk mailbox is examined within its latest 100 messages.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses
from html.parser import HTMLParser
import hashlib
import imaplib
import ipaddress
import json
import re
import secrets
import smtplib
import socket
import ssl
import time
from typing import Any
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

import socks


_IO_TIMEOUT = 15
_MAX_MESSAGES = 100
_MAX_BODY_BYTES = 262144
_MAX_TEXT = 12000
_RECIPIENT_HEADERS = (
    "To", "Cc", "Bcc", "Delivered-To", "X-Original-To", "Envelope-To",
    "X-Envelope-To", "Apparently-To",
)
_DELIVERY_HEADERS = ("Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To")
_SOURCE_RE = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*@gmail\.com\Z")
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}\Z")
_LIST_RE = re.compile(rb'^\(([^)]*)\)\s+(?:"(?:\\.|[^"\\])*"|NIL)\s+(.+)$')
_HEADER_FETCH = "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (" + " ".join(
    (*_RECIPIENT_HEADERS, "From", "Subject", "Date", "Message-ID")
) + ")])"


class GmailTransportError(Exception):
    """A stable code and safe message; server responses are never interpolated."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _proxy_settings(proxy_url: str) -> tuple[int, str, int, bool] | None:
    if not proxy_url:
        return None
    try:
        parsed = urlsplit(str(proxy_url).strip())
        hostname, port = parsed.hostname, parsed.port
        if (parsed.scheme not in {"http", "socks5", "socks5h"} or not hostname or port is None
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or not hostname.isascii() or not re.fullmatch(r"[a-zA-Z0-9.:-]+", hostname)
                or not 1 <= port <= 65535):
            raise ValueError
        return (socks.HTTP if parsed.scheme == "http" else socks.SOCKS5,
                hostname, port, parsed.scheme != "socks5")
    except (ValueError, TypeError):
        raise GmailTransportError("invalid_proxy", "代理必须是无用户名和密码的 http://host:port 或 socks5[h]://host:port 地址。") from None


def _proxy_tls_socket(host, port, timeout, context, proxy):
    proxy_type, proxy_host, proxy_port, rdns = proxy
    raw_socket = socks.create_connection(
        (host, port), timeout=timeout, proxy_type=proxy_type,
        proxy_addr=proxy_host, proxy_port=proxy_port, proxy_rdns=rdns,
    )
    try:
        return context.wrap_socket(raw_socket, server_hostname=host)
    except Exception:
        raw_socket.close()
        raise


def _doh_ipv4_addresses(host: str, timeout: float) -> list[str]:
    """Resolve one fixed Google mail endpoint outside local fake-IP DNS.

    Some system proxy clients answer ``imap.gmail.com`` with a 198.18/15
    synthetic address and then reject non-HTTPS ports.  The authenticated IMAP
    stream is still end-to-end TLS; this fallback obtains public A records over
    verified HTTPS and keeps ``imap.gmail.com`` as the TLS hostname.
    """
    if host not in {"imap.gmail.com", "smtp.gmail.com"}:
        return []
    try:
        request = Request(
            f"https://dns.google/resolve?name={host}&type=A",
            headers={"Accept": "application/dns-json", "User-Agent": "gmail-transport/1"},
        )
        with urlopen(request, timeout=max(1.0, min(float(timeout), 8.0))) as response:
            payload = response.read(65536)
        body = json.loads(payload)
    except Exception:
        return []
    addresses = []
    for answer in body.get("Answer", []) if isinstance(body, dict) else []:
        value = answer.get("data") if isinstance(answer, dict) and answer.get("type") == 1 else None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and address.is_global and str(address) not in addresses:
            addresses.append(str(address))
    return addresses[:6]


def _direct_ip_tls_socket(host: str, connect_ip: str, port: int, timeout: float, context):
    raw_socket = socket.create_connection((connect_ip, port), timeout=timeout)
    try:
        return context.wrap_socket(raw_socket, server_hostname=host)
    except Exception:
        raw_socket.close()
        raise


class _DirectIPIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, *args, connect_ip: str, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(*args, **kwargs)

    def _create_socket(self, timeout):
        return _direct_ip_tls_socket(
            self.host, self._connect_ip, self.port, timeout, self.ssl_context,
        )


class _ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, *args, proxy, **kwargs):
        self._proxy = proxy
        super().__init__(*args, **kwargs)

    def _create_socket(self, timeout):
        return _proxy_tls_socket(self.host, self.port, timeout, self.ssl_context, self._proxy)


class _ProxySMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, *args, proxy, **kwargs):
        self._proxy = proxy
        super().__init__(*args, **kwargs)

    def _get_socket(self, host, port, timeout):
        return _proxy_tls_socket(host, port, timeout, self.context, self._proxy)


class _PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "head"}:
            self.hidden += 1
        elif tag in {"p", "br", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "head"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _addresses(message: EmailMessage, headers: tuple[str, ...]) -> list[str]:
    values = [str(value) for name in headers for value in message.get_all(name, [])]
    try:
        return sorted({address.strip().lower() for _, address in getaddresses(values) if address})
    except (ValueError, TypeError):
        return []


def _body_text(message: EmailMessage) -> str:
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    try:
        content = part.get_content()
    except (LookupError, UnicodeError, ValueError):
        content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
    if not isinstance(content, str):
        return ""
    if part.get_content_type() == "text/html":
        parser = _PlainHTML()
        parser.feed(content)
        content = "".join(parser.parts)
    return content[:_MAX_TEXT]


def _fetch_data(data: list[Any]) -> tuple[bytes, bytes]:
    for item in data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[0] if isinstance(item[0], bytes) else b"", item[1]
    return b"", b""


def _received_at(metadata: bytes) -> str:
    match = re.search(rb'INTERNALDATE "([^"]+)"', metadata)
    if match is None:
        return ""
    try:
        return datetime.strptime(match[1].decode("ascii").strip(), "%d-%b-%Y %H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except (ValueError, UnicodeError):
        return ""


def _close_imap(connection) -> None:
    try:
        if getattr(connection, "sock", None) is not None:
            connection.sock.settimeout(1.0)
        # LOGOUT does not expunge; CLOSE must never be used here.
        connection.logout()
    except Exception:
        pass
    finally:
        # imaplib.logout() calls shutdown only after a successful command.
        # Always release the socket even when LOGOUT itself times out.
        try:
            connection.shutdown()
        except Exception:
            pass


class GmailTransport:
    """One source Gmail account; callers must authorize stored aliases as well."""

    def __init__(self, email: str, app_password: str, proxy_url: str = "", *, deadline: float | None = None):
        self.email = str(email or "").strip().lower()
        if not _SOURCE_RE.fullmatch(self.email):
            raise GmailTransportError("invalid_source", "仅支持不含 + 标签的 @gmail.com 源邮箱。")
        self._password = "".join(str(app_password or "").split())
        if not self._password or not self._password.isascii():
            raise GmailTransportError("invalid_credentials", "请提供 Gmail 应用专用密码。")
        self._proxy = _proxy_settings(proxy_url)
        self._imap = None
        if deadline is not None and (type(deadline) not in {int, float} or not 0 < deadline < float("inf")):
            raise GmailTransportError("invalid_deadline", "Gmail 收件等待时间无效。")
        # The caller may share its monotonic deadline across reconnects. Apply
        # it before __enter__, so connect/login/NOOP also use the remaining time.
        self._deadline: float | None = float(deadline) if deadline is not None else None

    def __enter__(self):
        self.connect_test()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def close(self) -> None:
        connection, self._imap = self._imap, None
        if connection is not None:
            _close_imap(connection)

    def _alias(self, alias: str) -> str:
        alias = str(alias or "").strip().lower()
        local, _, domain = alias.rpartition("@")
        base, separator, tag = local.partition("+")
        if domain != "gmail.com" or base + "@gmail.com" != self.email or not separator or not _TAG_RE.fullmatch(tag):
            raise GmailTransportError("invalid_alias", "别名必须是当前源邮箱的完整 base+tag@gmail.com 地址。")
        return alias

    def _timeout(self) -> float:
        if self._deadline is None:
            return _IO_TIMEOUT
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise GmailTransportError("timeout", "等待 Gmail 响应超时，请稍后重试。")
        return min(_IO_TIMEOUT, remaining)

    @contextmanager
    def _safe_errors(self, authenticating=False):
        try:
            yield
        except GmailTransportError:
            raise
        except (TimeoutError, socket.timeout):
            raise GmailTransportError("timeout", "连接 Gmail 超时，请检查网络后重试。") from None
        except ssl.SSLEOFError:
            # An unexpected EOF means the peer/proxy dropped the TLS stream;
            # it does not prove that certificate verification failed. Keep
            # certificate and other SSL failures in the strict branch below.
            raise GmailTransportError("network_error", "Gmail 网络连接中断，请稍后重试。") from None
        except ssl.SSLError:
            raise GmailTransportError("tls_error", "无法建立安全的 Gmail TLS 连接。") from None
        except smtplib.SMTPAuthenticationError:
            raise GmailTransportError("authentication_failed", "Gmail 认证失败，请检查源邮箱和应用专用密码。") from None
        except (imaplib.IMAP4.abort, OSError):
            raise GmailTransportError("network_error", "Gmail 网络连接中断，请稍后重试。") from None
        except imaplib.IMAP4.error:
            code = "authentication_failed" if authenticating else "imap_error"
            message = "Gmail 认证失败，请检查源邮箱和应用专用密码。" if authenticating else "Gmail 收信请求未能完成，请稍后重试。"
            raise GmailTransportError(code, message) from None
        except smtplib.SMTPException:
            raise GmailTransportError("smtp_error", "Gmail 未能完成测试邮件发送，请稍后重试。") from None

    def _connect(self):
        if self._imap is not None:
            return self._imap
        connection = None
        try:
            context = ssl.create_default_context()
            # An already exhausted caller deadline is a local terminal result,
            # not a network failure eligible for another connection path.
            connection_timeout = self._timeout()
            try:
                with self._safe_errors():
                    factory = _ProxyIMAP4SSL if self._proxy else imaplib.IMAP4_SSL
                    connection = factory(
                        "imap.gmail.com", 993, ssl_context=context, timeout=connection_timeout,
                        **({"proxy": self._proxy} if self._proxy else {}),
                    )
            except GmailTransportError as first_error:
                # An explicit per-source proxy is an operator choice and is
                # never bypassed.  With no such proxy, recover from local
                # fake-IP/TUN routes that accept TCP but drop IMAPS during TLS.
                if self._proxy is not None or first_error.code not in {"network_error", "timeout"}:
                    raise
                connection = None
                for connect_ip in _doh_ipv4_addresses("imap.gmail.com", self._timeout()):
                    try:
                        with self._safe_errors():
                            connection = _DirectIPIMAP4SSL(
                                "imap.gmail.com", 993, connect_ip=connect_ip,
                                ssl_context=context, timeout=self._timeout(),
                            )
                        break
                    except GmailTransportError:
                        connection = None
                if connection is None:
                    raise first_error
            with self._safe_errors(authenticating=True):
                if getattr(connection, "sock", None) is not None:
                    connection.sock.settimeout(self._timeout())
                status, _ = connection.login(self.email, self._password)
                if status != "OK":
                    raise GmailTransportError("authentication_failed", "Gmail 认证失败，请检查源邮箱和应用专用密码。")
            self._imap = connection
            return connection
        except Exception:
            if connection is not None:
                _close_imap(connection)
            raise

    def _command(self, method, *args, **kwargs):
        connection = self._connect()
        timeout = self._timeout()
        with self._safe_errors():
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(timeout)
            status, data = getattr(connection, method)(*args, **kwargs)
            if status != "OK":
                raise GmailTransportError("imap_error", "Gmail 收信请求未能完成，请稍后重试。")
            return data

    def connect_test(self) -> None:
        """Authenticate and check IMAP; never send an email."""
        self._command("noop")

    def _mailboxes(self) -> list[str]:
        rows = self._command("list")
        found: dict[str, str] = {}
        for row in rows or []:
            if not isinstance(row, bytes):
                continue
            match = _LIST_RE.fullmatch(row)
            if match is None:
                continue
            flags = {flag.lower() for flag in match[1].split()}
            if b"\\noselect" in flags:
                continue
            raw_name = match[2]
            if raw_name.startswith(b'"') and raw_name.endswith(b'"'):
                raw_name = re.sub(rb"\\(.)", rb"\1", raw_name[1:-1])
            try:
                # Keep modified UTF-7 as transmitted; IMAP accepts it verbatim.
                name = raw_name.decode("ascii")
            except UnicodeError:
                continue
            if name.upper() == "INBOX" or b"\\inbox" in flags:
                found["inbox"] = name
            if b"\\all" in flags:
                found["all"] = name
            if b"\\junk" in flags:
                found["junk"] = name
        if not found:
            raise GmailTransportError("mailbox_unavailable", "Gmail 未提供可读取的收件箱、所有邮件或垃圾邮件文件夹。")
        # Gmail's \All mailbox already contains every non-spam INBOX message.
        # Scanning both labels downloads the same message twice and can exhaust
        # the OTP polling deadline on an alias with several login attempts.
        # Prefer \All for inbox/archived mail, and inspect \Junk separately.
        primary = found.get("all") or found.get("inbox")
        return list(dict.fromkeys(value for value in (primary, found.get("junk")) if value))

    def _scan(self, alias: str, limit: int) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for mailbox in self._mailboxes():
            quoted = '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'
            counts = self._command("select", quoted, readonly=True)
            try:
                count = int(counts[0])
            except (ValueError, TypeError, IndexError):
                raise GmailTransportError("imap_error", "Gmail 返回了无法识别的文件夹信息。") from None
            if count <= 0:
                continue
            _, validity_rows = self._imap.response("UIDVALIDITY")
            validity = next((value.decode("ascii") for value in validity_rows or [] if isinstance(value, bytes) and value.isdigit()), None)
            if not validity:
                raise GmailTransportError("imap_error", "Gmail 未提供可靠的邮件标识，请重新连接。")
            # This is a sequence-number window, not a UID window (UIDs can have
            # gaps). UID SEARCH returns stable UIDs only for these last messages.
            first = max(1, count - _MAX_MESSAGES + 1)
            terms = [f'{name.upper()} "{alias}"' if name in {"To", "Cc", "Bcc"}
                     else f'HEADER {name} "{alias}"' for name in _RECIPIENT_HEADERS]
            recipient_filter = terms[-1]
            for term in reversed(terms[:-1]):
                recipient_filter = f"OR {term} {recipient_filter}"
            candidates = self._command("uid", "SEARCH", None, f"{first}:{count}", f"({recipient_filter})")
            uids = sorted({uid for row in candidates or [] if isinstance(row, bytes) for uid in row.split() if uid.isdigit()}, key=int)[-_MAX_MESSAGES:]
            for uid in reversed(uids):
                # SEARCH is only a candidate filter. Fetch each candidate once
                # and validate the exact envelope headers on that full message.
                # The former header-then-body pair doubled IMAP round trips;
                # Gmail aliases with repeated OTP attempts routinely exhausted
                # the 30-second scan deadline before reaching the newest mail.
                metadata, raw_message = _fetch_data(self._command(
                    "uid", "FETCH", uid, f"(UID INTERNALDATE BODY.PEEK[]<0.{_MAX_BODY_BYTES}>)"
                ))
                if not raw_message:
                    continue
                message = BytesParser(policy=policy.default).parsebytes(raw_message)
                # Recheck the full message, so inconsistent server responses
                # cannot associate another alias's body with these headers.
                recipients = _addresses(message, _RECIPIENT_HEADERS)
                if alias not in recipients:
                    continue
                row = {
                    "id": f"gmail:{quote(self.email, safe='')}:{quote(mailbox, safe='')}:{validity}:{uid.decode('ascii')}",
                    "from": str(message.get("From", "")),
                    "subject": str(message.get("Subject", "")),
                    "text": _body_text(message),
                    "received_at": _received_at(metadata),
                    "recipients": recipients,
                }
                hits.append({"row": row, "message_id": str(message.get("Message-ID", "")).strip(),
                             "delivery_recipients": _addresses(message, _DELIVERY_HEADERS)})
        hits.sort(key=lambda hit: (hit["row"]["received_at"], hit["row"]["id"]), reverse=True)
        return hits[:limit]

    def list_messages(self, alias: str, limit: int = 20) -> list[dict[str, Any]]:
        alias = self._alias(alias)
        try:
            limit = max(1, min(_MAX_MESSAGES, int(limit)))
        except (ValueError, TypeError, OverflowError):
            raise GmailTransportError("invalid_limit", "邮件数量必须为整数。") from None
        previous_deadline = self._deadline
        self._deadline = min(previous_deadline, time.monotonic() + 45) if previous_deadline is not None else time.monotonic() + 45
        try:
            rows = []
            seen = set()
            # Deduplication happens only for the display list. Delivery tests
            # still inspect every copy, including its inbound envelope headers.
            for hit in self._scan(alias, _MAX_MESSAGES):
                row = hit["row"]
                fingerprint = hashlib.sha256("\0".join((row["from"], row["subject"], row["text"])).encode("utf-8")).hexdigest()
                key = (hit["message_id"], fingerprint)
                if hit["message_id"] and key in seen:
                    continue
                seen.add(key)
                rows.append(row)
                if len(rows) >= limit:
                    break
            return rows
        finally:
            self._deadline = previous_deadline

    def test_delivery(self, alias: str, timeout: int = 30) -> dict[str, Any]:
        """Send one fixed self-test, then confirm its exact inbound copy.

        The application must look up an authorized, stored alias before calling
        this method. This transport additionally enforces source ownership.
        """
        alias = self._alias(alias)
        try:
            wait_seconds = min(60.0, max(1.0, float(timeout)))
        except (ValueError, TypeError, OverflowError):
            raise GmailTransportError("invalid_timeout", "投递测试等待时间必须为数字。") from None
        token = secrets.token_hex(24)
        message_id = f"<gmail-alias-test.{token}@gmail.com>"
        message = EmailMessage()
        message["From"] = self.email
        message["To"] = alias
        message["Subject"] = "Gmail alias delivery test"
        message["Message-ID"] = message_id
        message["Date"] = format_datetime(datetime.now(timezone.utc))
        marker = f"Gmail alias delivery test: {token}"
        message.set_content(marker + "\nThis message only verifies delivery to your own Gmail alias.\n")
        previous_deadline = self._deadline
        self._deadline = time.monotonic() + wait_seconds
        try:
            with self._safe_errors():
                factory = _ProxySMTPSSL if self._proxy else smtplib.SMTP_SSL
                with factory("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=self._timeout(),
                             **({"proxy": self._proxy} if self._proxy else {})) as smtp:
                    smtp.login(self.email, self._password)
                    smtp.sock.settimeout(self._timeout())
                    rejected = smtp.send_message(message, from_addr=self.email, to_addrs=[alias])
                    # Do not let the SMTP QUIT cleanup add another full network
                    # timeout after the delivery deadline has nearly elapsed.
                    smtp.sock.settimeout(1.0)
                    if rejected:
                        raise GmailTransportError("smtp_error", "Gmail 未接受测试邮件的收件地址。")
            while time.monotonic() < self._deadline:
                try:
                    hits = self._scan(alias, _MAX_MESSAGES)
                except GmailTransportError as exc:
                    if exc.code == "timeout":
                        break
                    raise
                for hit in hits:
                    row = hit["row"]
                    # All Mail contains outgoing Sent copies, which do not prove
                    # delivery. Require an exact inbound envelope header too.
                    if (hit["message_id"] == message_id and marker in row["text"].splitlines()
                            and alias in hit["delivery_recipients"]):
                        return {"ok": True, "message": "已确认收到本次投递测试邮件。",
                                "received_at": row["received_at"], "message_id": message_id}
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(2.0, remaining))
            return {"ok": False, "message": "等待时间内未确认收到本次测试邮件；这不代表无法收信，邮件可能延迟或超出最近邮件搜索范围。", "message_id": message_id}
        finally:
            self._deadline = previous_deadline
