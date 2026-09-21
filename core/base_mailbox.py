"""邮箱池基类 - 抽象临时邮箱/收件服务"""

import json
import random
import threading
import time

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any, Callable
from .proxy_utils import build_requests_proxy_config


@dataclass
class MailboxAccount:
    email: str
    account_id: str = ""
    extra: dict = None  # 平台额外信息


def _extract_trusted_chatgpt_password_link(
    *,
    subject: object = "",
    sender: object = "",
    content: object = "",
) -> str:
    """Extract one password action URL without logging or retaining its token."""
    import html
    import quopri
    import re
    import urllib.parse

    raw = " ".join(str(value or "") for value in (subject, content))
    try:
        decoded = quopri.decodestring(raw).decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw
    decoded = html.unescape(decoded).replace(r"\/", "/")
    semantic_text = f"{subject} {decoded}".lower()
    if not any(
        marker in semantic_text
        for marker in (
            "password",
            "passcode settings",
            "set your login",
            "密码",
            "密碼",
        )
    ):
        return ""

    sender_addresses = re.findall(
        r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        str(sender or ""),
    )
    if not sender_addresses or not all(
        domain.lower().rstrip(".") in {"openai.com", "chatgpt.com"}
        or domain.lower().rstrip(".").endswith(".openai.com")
        or domain.lower().rstrip(".").endswith(".chatgpt.com")
        for domain in sender_addresses
    ):
        return ""

    candidates = re.findall(r"https://[^\s<>\"']+", decoded, flags=re.I)
    ranked: list[tuple[int, int, str]] = []
    for candidate in candidates:
        value = candidate.rstrip(".,;:!?)]}>")
        try:
            parsed = urllib.parse.urlsplit(value)
        except (TypeError, ValueError):
            continue
        host = str(parsed.hostname or "").lower().rstrip(".")
        if not (
            parsed.scheme.lower() == "https"
            and parsed.username is None
            and parsed.password is None
            and (
                host in {"openai.com", "chatgpt.com"}
                or host.endswith(".openai.com")
                or host.endswith(".chatgpt.com")
            )
        ):
            continue
        route = urllib.parse.unquote(f"{parsed.path}?{parsed.query}").lower()
        if any(
            marker in route
            for marker in (
                "/assets/",
                "/static/",
                "/cdn/",
                "logo",
                "unsubscribe",
                "privacy",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".webp",
            )
        ):
            continue
        score = 0
        for marker, weight in (
            ("set-password", 10),
            ("reset-password", 10),
            ("password-reset", 10),
            ("/password", 8),
            ("password", 6),
            ("reset", 4),
            ("ticket=", 2),
            ("token=", 2),
            ("state=", 1),
        ):
            if marker in route:
                score += weight
        # A trusted-domain logo/home link in an otherwise relevant email is
        # not a credential action.  Require URL-level password/reset meaning.
        if score < 4:
            continue
        ranked.append((score, -len(value), value))
    return max(ranked, default=(0, 0, ""))[2]


def _mail_time_is_fresh(value: object, not_before: float | None) -> bool:
    """Use mail timestamps as an additional old-mail guard when available."""
    if not not_before:
        return True
    if not value:
        # When the ID snapshot failed/was empty, accepting an undated message
        # could reuse an old password-reset link.  Fail closed instead.
        return False
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime

    text = str(value or "").strip()
    parsed = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        try:
            parsed = parsedate_to_datetime(text)
        except Exception:
            return False
    if parsed is None:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    # Mail infrastructure clocks can differ slightly.  Message-ID baseline is
    # the primary barrier; this timestamp check protects a failed/empty probe.
    return parsed.timestamp() >= float(not_before) - 30.0


class BaseMailbox(ABC):
    def _log(self, message: str) -> None:
        log_fn = getattr(self, "_log_fn", None)
        if callable(log_fn):
            log_fn(message)

    def _checkpoint(self, *, consume_skip: bool = True) -> None:
        task_control = getattr(self, "_task_control", None)
        if task_control is None:
            return
        task_control.checkpoint(
            consume_skip=consume_skip,
            attempt_id=getattr(self, "_task_attempt_token", None),
        )

    def _sleep_with_checkpoint(self, seconds: float) -> None:
        remaining = max(float(seconds or 0), 0.0)
        while remaining > 0:
            self._checkpoint()
            chunk = min(0.25, remaining)
            time.sleep(chunk)
            remaining -= chunk

    def _run_polling_wait(
        self,
        *,
        timeout: int,
        poll_interval: float,
        poll_once: Callable[[], Optional[str]],
        timeout_message: str | None = None,
    ) -> str:
        timeout_seconds = max(int(timeout or 0), 1)
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            self._checkpoint()
            code = poll_once()
            if code:
                return code

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sleep_with_checkpoint(min(float(poll_interval), remaining))

        self._checkpoint()
        raise TimeoutError(timeout_message or f"等待验证码超时 ({timeout_seconds}s)")

    @abstractmethod
    def get_email(self) -> MailboxAccount:
        """获取一个可用邮箱"""
        ...

    @abstractmethod
    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        """等待并返回验证码，code_pattern 为自定义正则（默认匹配6位数字）"""
        ...

    def _safe_extract(self, text: str, pattern: str = None) -> Optional[str]:
        """通用验证码提取逻辑：若有捕获组则返回 group(1)，否则返回 group(0)"""
        import re

        text = str(text or "")
        if not text:
            return None

        # 先去掉所有 URL，避免从追踪链接（SendGrid / Mailgun / unsubscribe）里抽到随机 6 位数。
        text = re.sub(r"https?://\S+", " ", text)

        patterns = []
        if pattern:
            patterns.append(pattern)

        # 先匹配带明显语义的验证码，避免误提取 MIME boundary、时间戳等 6 位数字。
        patterns.extend(
            [
                r"(?is)(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|验证码|校验码|动态码|認證碼|驗證碼)[^0-9]{0,30}(\d{6})",
                r"(?is)\bcode\b[^0-9]{0,12}(\d{6})",
                r"(?<![a-zA-Z0-9])(\d{6})(?![a-zA-Z0-9])",
            ]
        )

        for regex in patterns:
            m = re.search(regex, text)
            if m:
                # 兼容逻辑：若 pattern 中有捕获组则取 group(1)，否则取 group(0)
                return m.group(1) if m.groups() else m.group(0)
        return None

    def _decode_raw_content(self, raw: str) -> str:
        """解析邮件原始文本 (借鉴自 Fugle)，处理 Quoted-Printable 和 HTML 实体"""
        import quopri, html, re

        text = str(raw or "")
        if not text:
            return ""
        # 简单切分 Header 和 Body
        if "\r\n\r\n" in text:
            text = text.split("\r\n\r\n", 1)[1]
        elif "\n\n" in text:
            text = text.split("\n\n", 1)[1]
        try:
            # 处理 Quoted-Printable
            decoded_bytes = quopri.decodestring(text)
            text = decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            pass
        # 清除 HTML 标签并反转义
        text = html.unescape(text)
        text = re.sub(r"(?im)^content-(?:type|transfer-encoding):.*$", " ", text)
        text = re.sub(r"(?im)^--+[_=\w.-]+$", " ", text)
        text = re.sub(r"(?i)----=_part_[\w.]+", " ", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @abstractmethod
    def get_current_ids(self, account: MailboxAccount) -> set:
        """返回当前邮件 ID 集合（用于过滤旧邮件）"""
        ...
    def _yyds_safe_extract(self, text: str, pattern: str = None) -> Optional[str]:
        """通用验证码提取逻辑：若有捕获组则返回 group(1)，否则返回 group(0)"""
        import re

        text = str(text or "")
        if not text:
            return None

        # [修复点 1]：优先过滤掉所有 URL 链接，直接从根源防止提取到追踪链接（如 SendGrid）里的随机数字
        text = re.sub(r"https?://\S+", "", text)

        patterns = []
        if pattern:
            # [修复点 2]：如果外部传入了纯 \d{6} 的粗糙正则，自动为其加上字母数字边界
            if pattern in (r"\d{6}", r"(\d{6})"):
                patterns.append(r"(?<![a-zA-Z0-9#])(\d{6})(?![a-zA-Z0-9])")
            else:
                patterns.append(pattern)

        # 先匹配带明显语义的验证码，避免误提取 MIME boundary、时间戳等 6 位数字。
        patterns.extend(
            [
                r"(?is)(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|验证码|校验码|动态码|認證碼|驗證碼)[^0-9]{0,30}(\d{6})",
                r"(?is)\bcode\b[^0-9]{0,12}(\d{6})",
                # [修复点 3]：修改兜底正则，严格要求 6 位数字前后不能有字母或数字（防止匹配 u20216706）
                r"(?<![a-zA-Z0-9#])(\d{6})(?![a-zA-Z0-9])",
            ]
        )

        for regex in patterns:
            m = re.search(regex, text)
            if m:
                # 兼容逻辑：若 pattern 中有捕获组则取 group(1)，否则取 group(0)
                return m.group(1) if m.groups() else m.group(0)
        return None

    def _yyds_decode_raw_content(self, raw: str) -> str:
        """解析邮件原始文本 (借鉴自 Fugle)，处理 Quoted-Printable 和 HTML 实体"""
        import quopri, html, re

        text = str(raw or "")
        if not text:
            return ""

        # [修复点 4]：只有在明确包含常见邮件 Header 时，才进行 \r\n\r\n 切分。
        # 否则会误删 MaliAPI 等直接返回的已解析 JSON 正文内容（遇到普通的正文换行就错误截断了）
        if re.search(r"(?im)^(?:Return-Path|Received|Date|From|To|Subject|Content-Type):", text):
            if "\r\n\r\n" in text:
                text = text.split("\r\n\r\n", 1)[1]
            elif "\n\n" in text:
                text = text.split("\n\n", 1)[1]

        try:
            # 处理 Quoted-Printable
            decoded_bytes = quopri.decodestring(text)
            text = decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            pass
        # 清除 HTML 标签并反转义
        text = html.unescape(text)
        text = re.sub(r"(?im)^content-(?:type|transfer-encoding):.*$", " ", text)
        text = re.sub(r"(?im)^--+[_=\w.-]+$", " ", text)
        text = re.sub(r"(?i)----=_part_[\w.]+", " ", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

def create_mailbox(
    provider: str, extra: dict = None, proxy: str = None
) -> "BaseMailbox":
    """工厂方法：根据 provider 创建对应的 mailbox 实例"""
    extra = extra or {}
    if provider == "tempmail_lol":
        return TempMailLolMailbox(proxy=proxy)
    elif provider == "skymail":
        return SkyMailMailbox(
            api_base=extra.get("skymail_api_base", "https://api.skymail.ink"),
            auth_token=extra.get("skymail_token", ""),
            domain=extra.get("skymail_domain", ""),
            proxy=proxy,
        )
    elif provider == "cloudmail":
        timeout_raw = extra.get("cloudmail_timeout", extra.get("timeout", 30))
        try:
            timeout_value = int(timeout_raw)
        except (TypeError, ValueError):
            timeout_value = 30
        return CloudMailMailbox(
            api_base=extra.get("cloudmail_api_base")
            or extra.get("base_url")
            or "",
            admin_email=extra.get("cloudmail_admin_email")
            or extra.get("admin_email")
            or "",
            admin_password=extra.get("cloudmail_admin_password")
            or extra.get("admin_password")
            or extra.get("api_key")
            or "",
            domain=extra.get("cloudmail_domain") or extra.get("domain") or "",
            subdomain=extra.get("cloudmail_subdomain")
            or extra.get("subdomain")
            or "",
            timeout=timeout_value,
            proxy=proxy,
        )
    elif provider == "duckmail":
        return DuckMailMailbox(
            api_url=(extra.get("duckmail_api_url") or "https://www.duckmail.sbs"),
            provider_url=(
                extra.get("duckmail_provider_url") or "https://api.duckmail.sbs"
            ),
            bearer=(extra.get("duckmail_bearer") or "kevin273945"),
            domain=extra.get("duckmail_domain", ""),
            api_key=extra.get("duckmail_api_key", ""),
            proxy=proxy,
        )
    elif provider == "freemail":
        return FreemailMailbox(
            api_url=extra.get("freemail_api_url", ""),
            admin_token=extra.get("freemail_admin_token", ""),
            username=extra.get("freemail_username", ""),
            password=extra.get("freemail_password", ""),
            domain=extra.get("freemail_domain", ""),
            proxy=proxy,
        )
    elif provider == "moemail":
        return MoeMailMailbox(
            api_url=extra.get("moemail_api_url", "https://sall.cc"),
            api_key=extra.get("moemail_api_key", ""),
            proxy=proxy,
        )
    elif provider == "maliapi":
        return MaliAPIMailbox(
            api_url=extra.get("maliapi_base_url", "https://maliapi.215.im/v1"),
            api_key=extra.get("maliapi_api_key", ""),
            domain=extra.get("maliapi_domain", ""),
            auto_domain_strategy=extra.get("maliapi_auto_domain_strategy", ""),
            proxy=proxy,
        )
    elif provider == "gptmail":
        return GPTMailMailbox(
            api_url=extra.get("gptmail_base_url", "https://mail.chatgpt.org.uk"),
            api_key=extra.get("gptmail_api_key", ""),
            domain=extra.get("gptmail_domain", ""),
            proxy=proxy,
        )
    elif provider == "applemail":
        return AppleMailMailbox(
            api_url=extra.get("applemail_base_url", "https://www.appleemail.top"),
            pool_file=extra.get("applemail_pool_file", ""),
            pool_dir=extra.get("applemail_pool_dir", "mail"),
            mailboxes=extra.get("applemail_mailboxes", "INBOX,Junk"),
            proxy=proxy,
        )
    elif provider == "opentrashmail":
        return OpenTrashMailMailbox(
            api_url=extra.get("opentrashmail_api_url", ""),
            domain=extra.get("opentrashmail_domain", ""),
            password=extra.get("opentrashmail_password", ""),
            proxy=proxy,
        )
    elif provider == "cfworker":
        return CFWorkerMailbox(
            api_url=extra.get("cfworker_api_url", ""),
            admin_token=extra.get("cfworker_admin_token", ""),
            domain=extra.get("cfworker_domain", ""),
            domain_override=extra.get("cfworker_domain_override", ""),
            domains=extra.get("cfworker_domains", ""),
            enabled_domains=extra.get("cfworker_enabled_domains", ""),
            subdomain=extra.get("cfworker_subdomain", ""),
            force_subdomain=extra.get("cfworker_force_subdomain", False),
            subdomain_strategy=extra.get("cfworker_subdomain_strategy", "counter"),
            subdomain_prefix=extra.get("cfworker_subdomain_prefix", ""),
            subdomain_max_accounts=extra.get("cfworker_subdomain_max_accounts", "100"),
            release_on_delete=extra.get("cfworker_subdomain_release_on_delete", "1"),
            random_subdomain=extra.get("cfworker_random_subdomain", False),
            random_name_subdomain=extra.get("cfworker_random_name_subdomain", False),
            fingerprint=extra.get("cfworker_fingerprint", ""),
            custom_auth=extra.get("cfworker_custom_auth", ""),
            quick_api_url=extra.get("cfworker_quick_api_url", ""),
            proxy=proxy,
        )
    elif provider == "luckmail":
        return LuckMailMailbox(
            base_url=extra.get("luckmail_base_url") or "https://mails.luckyous.com/",
            api_key=extra.get("luckmail_api_key", ""),
            project_code=extra.get("luckmail_project_code", ""),
            email_type=extra.get("luckmail_email_type", ""),
            domain=extra.get("luckmail_domain", ""),
            proxy=proxy,
        )
    elif provider == "gmail":
        from core.gmail_mailbox import GmailMailbox
        return GmailMailbox(extra=extra, proxy=proxy)
    elif provider == "outlook":
        return OutlookMailbox(
            imap_server=extra.get("outlook_imap_server", ""),
            imap_port=extra.get("outlook_imap_port", ""),
            token_endpoint=extra.get("outlook_token_endpoint", ""),
            platform=extra.get("platform", ""),
            proxy=proxy,
        )
    elif provider == "qqmail":
        # iCloud HME 别名收信: 默认走 QQ 邮箱(HME 转发到 QQ);
        # 若 icloud_receive_via=icloud_imap, 改连 iCloud 官方 IMAP(imap.mail.me.com,
        # 用对应的 iCloud 邮箱 + App 专用密码)——适用于把 HME 转发目标改回 iCloud 后。
        via = str(extra.get("icloud_receive_via", "") or "qqmail").strip().lower()
        if via == "icloud_imap":
            user = str(extra.get("icloud_imap_user", "") or "").strip()
            auth = str(extra.get("icloud_imap_password", "")
                       or extra.get("icloud_smtp_app_password", "") or "").strip().replace(" ", "")
            host = str(extra.get("icloud_imap_host", "") or "imap.mail.me.com").strip() or "imap.mail.me.com"
            # iCloud 收件箱本身只装转发来的 HME 邮件, 按 To=别名 搜已足够, 不强制校验 X-ICLOUD-HME
            require_apple = bool(extra.get("icloud_imap_require_apple_header", False))
        else:
            user = extra.get("qqmail_user", "")
            auth = extra.get("qqmail_auth_code", "")
            host = extra.get("qqmail_imap_host", "imap.qq.com")
            require_apple = bool(extra.get("qqmail_require_apple_header", True))
        return QQMailMailbox(
            user=user,
            auth_code=auth,
            host=host,
            port=int(extra.get("qqmail_imap_port") or 993),
            pool_file=extra.get("qqmail_pool_file") or extra.get("icloud_hme_pool_file") or "",
            pool_dir=extra.get("qqmail_pool_dir") or "mail",
            mailbox=extra.get("qqmail_mailbox", "INBOX"),
            require_apple_header=require_apple,
            proxy=proxy,
            platform=str(extra.get("platform", "") or extra.get("_platform", "")).lower(),
        )
    else:  # laoudo
        return LaoudoMailbox(
            auth_token=extra.get("laoudo_auth", ""),
            email=extra.get("laoudo_email", ""),
            account_id=extra.get("laoudo_account_id", ""),
        )


class AppleMailMailbox(BaseMailbox):
    """小苹果取件邮箱服务，基于本地邮箱池文件轮转邮箱账号"""

    def __init__(
        self,
        api_url: str = "https://www.appleemail.top",
        pool_file: str = "",
        pool_dir: str = "mail",
        mailboxes: str = "INBOX,Junk",
        proxy: str = None,
    ):
        self.api = (api_url or "https://www.appleemail.top").rstrip("/")
        self.pool_file = str(pool_file or "").strip()
        self.pool_dir = str(pool_dir or "mail").strip() or "mail"
        self.mailboxes = self._normalize_mailboxes(mailboxes)
        self.proxy = build_requests_proxy_config(proxy)
        self._email = None
        self._selected_record = None
        self._selected_pool_path = None

    @staticmethod
    def _normalize_mailboxes(value: Any) -> list[str]:
        if isinstance(value, (list, tuple, set)):
            items = [str(item or "").strip() for item in value]
        else:
            raw = str(value or "INBOX,Junk").strip() or "INBOX,Junk"
            items = [item.strip() for item in raw.split(",")]

        result = []
        seen = set()
        for item in items:
            if not item:
                continue
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result or ["INBOX", "Junk"]

    def _headers(self) -> dict[str, str]:
        return {"accept": "application/json"}

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any],
        timeout: int = 15,
    ) -> Any:
        import requests

        response = requests.request(
            method,
            f"{self.api}{path}",
            params=payload,
            json=None,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=timeout,
        )
        try:
            data = response.json()
        except Exception as exc:
            preview = (response.text or "")[:200]
            raise RuntimeError(
                f"AppleMail API {path} 返回非 JSON: HTTP {response.status_code} {preview}"
            ) from exc

        if response.status_code >= 400:
            if isinstance(data, dict):
                message = (
                    data.get("detail")
                    or data.get("message")
                    or data.get("error")
                    or response.text
                )
            else:
                message = response.text
            raise RuntimeError(
                f"AppleMail API {path} 失败: {str(message or f'HTTP {response.status_code}').strip()}"
            )

        if isinstance(data, dict) and data.get("success") is False:
            message = (
                data.get("message")
                or data.get("detail")
                or data.get("error")
                or "unknown error"
            )
            raise RuntimeError(f"AppleMail API {path} 失败: {str(message).strip()}")

        return data

    @staticmethod
    def _unwrap_message_payload(payload: Any) -> list[dict[str, Any]]:
        if payload is None:
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("data", "result", "results", "messages", "mails", "emails", "items", "list"):
                if key in payload:
                    nested = AppleMailMailbox._unwrap_message_payload(payload.get(key))
                    if nested:
                        return nested
            if any(
                key in payload
                for key in (
                    "id",
                    "message_id",
                    "uid",
                    "mail_id",
                    "subject",
                    "content",
                    "text",
                    "html",
                    "body",
                    "preview",
                    "verification_code",
                    "code",
                    "otp",
                )
            ):
                return [payload]

            collected = []
            for value in payload.values():
                collected.extend(AppleMailMailbox._unwrap_message_payload(value))
            return collected
        return []

    @staticmethod
    def _resolve_message_id(message: dict[str, Any], mailbox: str) -> str:
        import hashlib

        for key in ("id", "message_id", "uid", "mail_id", "mid", "_id"):
            value = str(message.get(key) or "").strip()
            if value:
                return value

        raw = json.dumps(message, ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha1(
            f"{mailbox}:{raw}".encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        return f"{mailbox}:{digest}"

    def _build_search_text(self, message: dict[str, Any]) -> str:
        parts = []
        for key in (
            "subject",
            "from",
            "from_address",
            "sender",
            "preview",
            "text",
            "content",
            "body",
            "html",
            "html_content",
            "raw",
            "raw_content",
            "mail_text",
        ):
            value = message.get(key)
            if value:
                parts.append(str(value))

        if not parts:
            parts.append(json.dumps(message, ensure_ascii=False))

        text = " ".join(parts).strip()
        return self._decode_raw_content(text) or text

    def _extract_code_from_message(
        self,
        message: dict[str, Any],
        code_pattern: str = None,
    ) -> Optional[str]:
        for key in ("verification_code", "code", "otp", "captcha", "verify_code"):
            value = str(message.get(key) or "").strip()
            if value:
                code = self._safe_extract(value, code_pattern)
                if code:
                    return code
        return self._safe_extract(self._build_search_text(message), code_pattern)

    def _resolve_mailboxes_for_account(self, account: MailboxAccount) -> list[str]:
        account_mailbox = ""
        if isinstance(account.extra, dict):
            account_mailbox = str(account.extra.get("mailbox") or "").strip()

        result = []
        seen = set()
        for mailbox in ([account_mailbox] if account_mailbox else []) + list(self.mailboxes):
            name = str(mailbox or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            result.append(name)
        return result or ["INBOX"]

    def _build_request_payload(self, account: MailboxAccount, mailbox: str) -> dict[str, Any]:
        extra = account.extra or {}
        refresh_token = str(extra.get("refresh_token") or "").strip()
        client_id = str(extra.get("client_id") or "").strip()
        if not refresh_token or not client_id:
            raise RuntimeError("AppleMail 邮箱记录缺少 refresh_token 或 client_id")

        return {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "email": account.email,
            "mailbox": mailbox,
        }

    def _list_messages(self, account: MailboxAccount, mailbox: str) -> list[dict[str, Any]]:
        data = self._request_json(
            "GET",
            "/api/mail-all",
            payload=self._build_request_payload(account, mailbox),
            timeout=15,
        )
        if isinstance(data, dict):
            new_refresh_token = str(data.get("new_refresh_token") or "").strip()
            if new_refresh_token:
                if account.extra is None:
                    account.extra = {}
                account.extra["refresh_token"] = new_refresh_token
        return self._unwrap_message_payload(data)

    def get_email(self) -> MailboxAccount:
        from .applemail_pool import take_next_applemail_record

        pool_path, record = take_next_applemail_record(
            pool_file=self.pool_file,
            pool_dir=self.pool_dir,
        )
        self._selected_pool_path = pool_path
        self._selected_record = record
        self._email = record["email"]
        self._log(f"[AppleMail] 使用邮箱池: {pool_path.name}")
        self._log(f"[AppleMail] 分配邮箱: {record['email']}")
        return MailboxAccount(
            email=record["email"],
            account_id=record["email"],
            extra={
                "provider": "applemail",
                "client_id": record["client_id"],
                "refresh_token": record["refresh_token"],
                "mailbox": record.get("mailbox") or "INBOX",
                "pool_file": pool_path.name,
            },
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        ids = set()
        for mailbox in self._resolve_mailboxes_for_account(account):
            try:
                messages = self._list_messages(account, mailbox)
            except Exception:
                continue
            ids.update(
                self._resolve_message_id(message, mailbox)
                for message in messages
            )
        return ids

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        seen = {str(mid) for mid in (before_ids or set())}
        exclude_codes = {
            str(code).strip()
            for code in (kwargs.get("exclude_codes") or set())
            if str(code or "").strip()
        }

        def poll_once() -> Optional[str]:
            for mailbox in self._resolve_mailboxes_for_account(account):
                try:
                    messages = self._list_messages(account, mailbox)
                except Exception:
                    continue

                for message in messages:
                    message_id = self._resolve_message_id(message, mailbox)
                    if message_id in seen:
                        continue
                    seen.add(message_id)

                    search_text = self._build_search_text(message)
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._extract_code_from_message(message, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        self._log(f"[AppleMail] {mailbox} 收到验证码（内容不写入日志）")
                        return code
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class LaoudoMailbox(BaseMailbox):
    """laoudo.com 邮箱服务"""

    def __init__(self, auth_token: str, email: str, account_id: str):
        self.auth = auth_token
        self._email = email
        self._account_id = account_id
        self.api = "https://laoudo.com/api/email"
        self._ua = "Mozilla/5.0"

    def get_email(self) -> MailboxAccount:
        if not self._email:
            raise RuntimeError(
                "Laoudo 邮箱未配置或已失效，请检查 laoudo_auth、laoudo_email、laoudo_account_id 配置，"
                "或切换到 tempmail_lol（无需配置）"
            )
        return MailboxAccount(email=self._email, account_id=self._account_id)

    def get_current_ids(self, account: MailboxAccount) -> set:
        from curl_cffi import requests as curl_requests

        try:
            r = curl_requests.get(
                f"{self.api}/list",
                params={
                    "accountId": account.account_id,
                    "allReceive": 0,
                    "emailId": 0,
                    "timeSort": 1,
                    "size": 50,
                    "type": 0,
                },
                headers={"authorization": self.auth, "user-agent": self._ua},
                timeout=15,
                impersonate="chrome131",
            )
            if r.status_code == 200:
                mails = r.json().get("data", {}).get("list", []) or []
                return {
                    m.get("id") or m.get("emailId")
                    for m in mails
                    if m.get("id") or m.get("emailId")
                }
        except Exception:
            pass
        return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "trae",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        from curl_cffi import requests as curl_requests

        seen = set(before_ids) if before_ids else set()
        h = {"authorization": self.auth, "user-agent": self._ua}

        def poll_once() -> Optional[str]:
            try:
                r = curl_requests.get(
                    f"{self.api}/list",
                    params={
                        "accountId": account.account_id,
                        "allReceive": 0,
                        "emailId": 0,
                        "timeSort": 1,
                        "size": 50,
                        "type": 0,
                    },
                    headers=h,
                    timeout=15,
                    impersonate="chrome131",
                )
                if r.status_code == 200:
                    mails = r.json().get("data", {}).get("list", []) or []
                    for mail in mails:
                        mid = mail.get("id") or mail.get("emailId")
                        if not mid or mid in seen:
                            continue
                        seen.add(mid)
                        text = (
                            str(mail.get("subject", ""))
                            + " "
                            + str(mail.get("content") or mail.get("html") or "")
                        )
                        if keyword and keyword.lower() not in text.lower():
                            continue
                        code = self._safe_extract(text, code_pattern)
                        if code:
                            return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=4,
            poll_once=poll_once,
        )


class AitreMailbox(BaseMailbox):
    """mail.aitre.cc 临时邮箱"""

    def __init__(self, email: str):
        self._email = email
        self.api = "https://mail.aitre.cc/api/tempmail"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email=self._email)

    def get_current_ids(self, account: MailboxAccount) -> set:
        import requests

        try:
            r = requests.get(
                f"{self.api}/emails", params={"email": account.email}, timeout=10
            )
            emails = r.json().get("emails", [])
            return {str(m["id"]) for m in emails if "id" in m}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "trae",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import requests

        seen = set(before_ids) if before_ids else set()
        last_check = None

        def poll_once() -> Optional[str]:
            nonlocal last_check
            params = {"email": account.email}
            if last_check:
                params["lastCheck"] = last_check
            try:
                r = requests.get(f"{self.api}/poll", params=params, timeout=10)
                data = r.json()
                last_check = data.get("lastChecked")
                if data.get("count", 0) > 0:
                    r2 = requests.get(
                        f"{self.api}/emails",
                        params={"email": account.email},
                        timeout=10,
                    )
                    for mail in r2.json().get("emails", []):
                        mid = str(mail.get("id", ""))
                        if mid in seen:
                            continue
                        seen.add(mid)
                        text = mail.get("preview", "") + mail.get("content", "")
                        if keyword and keyword.lower() not in text.lower():
                            continue
                        code = self._safe_extract(text, code_pattern)
                        if code:
                            return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class TempMailLolMailbox(BaseMailbox):
    """tempmail.lol 免费临时邮箱（无需注册，自动生成）"""

    def __init__(self, proxy: str = None):
        self.api = "https://api.tempmail.lol/v2"
        self.proxy = build_requests_proxy_config(proxy)
        self._token = None
        self._email = None

    def get_email(self) -> MailboxAccount:
        import requests

        r = requests.post(
            f"{self.api}/inbox/create", json={}, proxies=self.proxy, timeout=15
        )
        data = r.json()
        email = data.get("address") or data.get("email", "")
        if not email:
            raise RuntimeError(f"tempmail.lol API 返回空邮箱: {data}")
        self._email = email
        self._token = data.get("token", "")
        print(f"[TempMailLol] 生成邮箱: {self._email}")
        return MailboxAccount(email=self._email, account_id=self._token)

    def get_current_ids(self, account: MailboxAccount) -> set:
        import requests

        try:
            r = requests.get(
                f"{self.api}/inbox",
                params={"token": account.account_id},
                proxies=self.proxy,
                timeout=10,
            )
            return {str(m["id"]) for m in r.json().get("emails", [])}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import requests

        seen = set(before_ids or [])
        otp_sent_at = kwargs.get("otp_sent_at")

        def poll_once() -> Optional[str]:
            try:
                r = requests.get(
                    f"{self.api}/inbox",
                    params={"token": account.account_id},
                    proxies=self.proxy,
                    timeout=10,
                )
                for mail in sorted(
                    r.json().get("emails", []),
                    key=lambda x: x.get("date", 0),
                    reverse=True,
                ):
                    mid = str(mail.get("id", ""))
                    if mid in seen:
                        continue
                    if otp_sent_at and mail.get("date", 0) / 1000 < otp_sent_at:
                        continue
                    seen.add(mid)
                    text = (
                        mail.get("subject", "")
                        + " "
                        + mail.get("body", "")
                        + " "
                        + mail.get("html", "")
                    )
                    if keyword and keyword.lower() not in text.lower():
                        continue
                    code = self._safe_extract(text, code_pattern)
                    if code:
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class SkyMailMailbox(BaseMailbox):
    """SkyMail / CloudMail 自建邮箱服务"""

    def __init__(self, api_base: str, auth_token: str, domain: str, proxy: str = None):
        self.api = (api_base or "").rstrip("/")
        self.auth_token = auth_token or ""
        self.domain = domain or ""
        self.proxy = build_requests_proxy_config(proxy)

    def _headers(self) -> dict:
        return {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": self.auth_token,
        }

    def _ensure_config(self) -> None:
        if not self.api or not self.auth_token or not self.domain:
            raise RuntimeError(
                "SkyMail 未配置完整：请设置 skymail_api_base、skymail_token、skymail_domain"
            )

    def _gen_prefix(self) -> str:
        import random
        import string

        length = random.randint(8, 13)
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def get_email(self) -> MailboxAccount:
        import requests

        self._ensure_config()
        email = f"{self._gen_prefix()}@{self.domain}"
        payload = {"list": [{"email": email}]}
        r = requests.post(
            f"{self.api}/api/public/addUser",
            json=payload,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=15,
        )
        if r.status_code != 200:
            raise RuntimeError(f"SkyMail 创建邮箱失败: {r.status_code} {r.text[:200]}")

        data = r.json()
        if data.get("code") != 200:
            raise RuntimeError(f"SkyMail 创建邮箱失败: {data}")

        self._log(f"[SkyMail] 生成邮箱: {email}")
        return MailboxAccount(email=email, account_id=email)

    def _list_mails(self, email: str) -> list:
        import requests

        payload = {
            "toEmail": email,
            "num": 1,
            "size": 20,
        }
        r = requests.post(
            f"{self.api}/api/public/emailList",
            json=payload,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=15,
        )
        if r.status_code != 200:
            return []
        data = r.json()
        if data.get("code") != 200:
            return []
        return data.get("data") or []

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            mails = self._list_mails(account.account_id or account.email)
            ids = set()
            for i, msg in enumerate(mails):
                mid = msg.get("id") or msg.get("mailId") or msg.get("messageId")
                if mid:
                    ids.add(str(mid))
                else:
                    digest = (
                        str(msg.get("date") or msg.get("time") or "")
                        + "|"
                        + str(msg.get("subject") or "")
                    )
                    ids.add(f"idx-{i}-{digest}")
            return ids
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        target = account.account_id or account.email
        seen = set(before_ids or [])

        def poll_once() -> Optional[str]:
            try:
                mails = self._list_mails(target)
                for i, msg in enumerate(mails):
                    mid = msg.get("id") or msg.get("mailId") or msg.get("messageId")
                    if not mid:
                        digest = (
                            str(msg.get("date") or msg.get("time") or "")
                            + "|"
                            + str(msg.get("subject") or "")
                        )
                        mid = f"idx-{i}-{digest}"
                    mid = str(mid)
                    if mid in seen:
                        continue
                    seen.add(mid)

                    content = " ".join(
                        [
                            str(msg.get("subject") or ""),
                            str(msg.get("content") or ""),
                            str(msg.get("text") or ""),
                            str(msg.get("html") or ""),
                        ]
                    )
                    if keyword and keyword.lower() not in content.lower():
                        continue

                    code = self._safe_extract(content, code_pattern)
                    if code:
                        self._log("[SkyMail] 命中验证码（内容不写入日志）")
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class CloudMailMailbox(BaseMailbox):
    """CloudMail 自建邮箱服务（genToken + emailList）"""

    _token_lock = threading.Lock()
    _token_cache: dict[str, tuple[str, float]] = {}
    _seen_ids_lock = threading.Lock()
    _seen_ids: dict[str, set[str]] = {}

    def __init__(
        self,
        api_base: str,
        admin_email: str,
        admin_password: str,
        domain: Any = "",
        subdomain: str = "",
        timeout: int = 30,
        proxy: str = None,
    ):
        self.api = str(api_base or "").rstrip("/")
        self.admin_email = str(admin_email or "").strip()
        self.admin_password = str(admin_password or "").strip()
        self.domain = domain
        self.subdomain = str(subdomain or "").strip()
        self.timeout = max(int(timeout or 30), 5)
        self.proxy = build_requests_proxy_config(proxy)

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(str(url or ""))
        host = (parsed.netloc or parsed.path.split("/")[0] or "").strip()
        if ":" in host:
            host = host.split(":", 1)[0].strip()
        return host

    @staticmethod
    def _normalize_domain(value: str) -> str:
        domain = str(value or "").strip().lstrip("@")
        if "://" in domain:
            domain = CloudMailMailbox._extract_domain_from_url(domain)
        return domain.strip()

    def _domain_candidates(self) -> list[str]:
        candidates: list[str] = []

        if isinstance(self.domain, (list, tuple, set)):
            iterable = self.domain
        else:
            raw = str(self.domain or "").strip()
            parsed = None
            if raw.startswith("[") and raw.endswith("]"):
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = None
            if isinstance(parsed, list):
                iterable = parsed
            elif raw:
                normalized = (
                    raw.replace(";", "\n")
                    .replace(",", "\n")
                    .replace("|", "\n")
                    .splitlines()
                )
                iterable = [item for item in normalized if item]
            else:
                iterable = []

        for item in iterable:
            normalized = self._normalize_domain(item)
            if normalized:
                candidates.append(normalized)

        if not candidates:
            inferred = self._normalize_domain(self._extract_domain_from_url(self.api))
            if inferred:
                candidates.append(inferred)
        return candidates

    def _resolve_admin_email(self) -> str:
        if self.admin_email:
            return self.admin_email
        domains = self._domain_candidates()
        if domains:
            return f"admin@{domains[0]}"
        return "admin@example.com"

    def _cache_key(self) -> str:
        return f"{self.api}|{self._resolve_admin_email()}|{self.admin_password}"

    def _ensure_config(self) -> None:
        if not self.api or not self.admin_password:
            raise RuntimeError(
                "CloudMail 未配置完整：请设置 cloudmail_api_base 与 cloudmail_admin_password"
            )

    def _headers(self, token: str = "") -> dict:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
        }
        if token:
            headers["authorization"] = token
        return headers

    def _generate_token(self) -> str:
        import requests

        self._ensure_config()
        payload = {
            "email": self._resolve_admin_email(),
            "password": self.admin_password,
        }
        r = requests.post(
            f"{self.api}/api/public/genToken",
            json=payload,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=self.timeout,
        )
        if r.status_code != 200:
            raise RuntimeError(
                f"CloudMail 生成 token 失败: {r.status_code} {str(r.text or '')[:200]}"
            )

        try:
            data = r.json()
        except Exception:
            data = {}
        if data.get("code") != 200:
            raise RuntimeError(f"CloudMail 生成 token 失败: {data}")
        token = ((data.get("data") or {}).get("token") or "").strip()
        if not token:
            raise RuntimeError("CloudMail 生成 token 失败: 响应未返回 token")
        return token

    def _get_token(self, *, force_refresh: bool = False) -> str:
        cache_key = self._cache_key()
        now = time.time()
        with CloudMailMailbox._token_lock:
            if not force_refresh:
                cached = CloudMailMailbox._token_cache.get(cache_key)
                if cached and now < cached[1]:
                    return cached[0]

            token = self._generate_token()
            CloudMailMailbox._token_cache[cache_key] = (token, now + 3600)
            return token

    def _list_mails(self, email: str, *, retry_auth: bool = True) -> list:
        import requests

        token = self._get_token()
        payload = {
            "toEmail": email,
            "timeSort": "desc",
        }
        r = requests.post(
            f"{self.api}/api/public/emailList",
            json=payload,
            headers=self._headers(token),
            proxies=self.proxy,
            timeout=self.timeout,
        )
        if r.status_code == 401 and retry_auth:
            token = self._get_token(force_refresh=True)
            r = requests.post(
                f"{self.api}/api/public/emailList",
                json=payload,
                headers=self._headers(token),
                proxies=self.proxy,
                timeout=self.timeout,
            )
        if r.status_code != 200:
            return []

        try:
            data = r.json()
        except Exception:
            data = {}
        if data.get("code") != 200:
            return []
        return data.get("data") or []

    def _gen_prefix(self) -> str:
        import random
        import string

        first = random.choice(string.ascii_lowercase)
        rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=9))
        return first + rest

    def _build_email(self) -> str:
        domains = self._domain_candidates()
        if not domains:
            raise RuntimeError("CloudMail 未配置可用域名")
        domain = random.choice(domains)
        if self.subdomain:
            domain = f"{self.subdomain}.{domain}"
        return f"{self._gen_prefix()}@{domain}"

    @staticmethod
    def _parse_message_timestamp(message: dict) -> Optional[float]:
        from datetime import datetime

        keys = [
            "time",
            "date",
            "created",
            "createdAt",
            "created_at",
            "receivedAt",
            "received_at",
            "sendTime",
            "timestamp",
        ]
        for key in keys:
            value = message.get(key)
            if value in (None, ""):
                continue
            if isinstance(value, (int, float)):
                numeric = float(value)
                return numeric / 1000 if numeric > 10_000_000_000 else numeric
            text = str(value).strip()
            if not text:
                continue
            try:
                numeric = float(text)
                return numeric / 1000 if numeric > 10_000_000_000 else numeric
            except (TypeError, ValueError):
                pass
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
        return None

    @staticmethod
    def _mail_id(message: dict, index: int = 0) -> str:
        for key in ("emailId", "id", "mailId", "messageId"):
            value = message.get(key)
            if value not in (None, ""):
                return str(value)
        digest = (
            str(message.get("date") or message.get("time") or "")
            + "|"
            + str(message.get("subject") or "")
        )
        return f"idx-{index}-{digest}"

    def _remember_seen_id(self, email: str, message_id: str) -> None:
        with CloudMailMailbox._seen_ids_lock:
            CloudMailMailbox._seen_ids.setdefault(email, set()).add(message_id)

    def _load_seen_ids(self, email: str) -> set[str]:
        with CloudMailMailbox._seen_ids_lock:
            return set(CloudMailMailbox._seen_ids.get(email, set()))

    def get_email(self) -> MailboxAccount:
        self._ensure_config()
        email = self._build_email()
        self._log(f"[CloudMail] 生成邮箱: {email}")
        return MailboxAccount(email=email, account_id=email)

    def get_current_ids(self, account: MailboxAccount) -> set:
        target = account.account_id or account.email
        try:
            mails = self._list_mails(target)
            return {self._mail_id(msg, idx) for idx, msg in enumerate(mails)}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        target = account.account_id or account.email
        seen = set(before_ids or set())
        seen.update(self._load_seen_ids(target))
        otp_sent_at = kwargs.get("otp_sent_at")
        exclude_codes = {
            str(code).strip()
            for code in (kwargs.get("exclude_codes") or set())
            if str(code or "").strip()
        }

        def poll_once() -> Optional[str]:
            try:
                mails = self._list_mails(target)
                for idx, msg in enumerate(mails):
                    mid = self._mail_id(msg, idx)
                    if mid in seen:
                        continue
                    seen.add(mid)
                    self._remember_seen_id(target, mid)

                    msg_ts = self._parse_message_timestamp(msg)
                    if otp_sent_at and msg_ts and msg_ts < float(otp_sent_at):
                        continue

                    content = " ".join(
                        [
                            str(msg.get("subject") or ""),
                            str(msg.get("content") or ""),
                            str(msg.get("text") or ""),
                            str(msg.get("html") or ""),
                        ]
                    )
                    if keyword and keyword.lower() not in content.lower():
                        continue
                    code = self._safe_extract(content, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        self._log("[CloudMail] 命中验证码（内容不写入日志）")
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class DuckMailMailbox(BaseMailbox):
    """DuckMail 自动生成邮箱（随机创建账号）"""

    def __init__(
        self,
        api_url: str = "https://www.duckmail.sbs",
        provider_url: str = "https://api.duckmail.sbs",
        bearer: str = "kevin273945",
        domain: str = "",
        api_key: str = "",
        proxy: str = None,
    ):
        self.api = (api_url or "https://www.duckmail.sbs").rstrip("/")
        self.provider_url = (provider_url or "https://api.duckmail.sbs").rstrip("/")
        self.bearer = bearer or "kevin273945"
        self.domain = str(domain or "").strip()
        self.api_key = str(api_key or "").strip()
        self.proxy = build_requests_proxy_config(proxy)
        self._token = None
        self._address = None
        # 如果配置了 API Key，直接请求 DuckMail API；否则走前端代理
        self._direct = bool(self.api_key)

    def _proxy_headers(self) -> dict:
        return {
            "authorization": f"Bearer {self.bearer}",
            "content-type": "application/json",
            "x-api-provider-base-url": self.provider_url,
        }

    def _direct_headers(self, token: str = "") -> dict:
        auth = token or self.api_key
        return {
            "authorization": f"Bearer {auth}",
            "content-type": "application/json",
        }

    def _request(self, method: str, endpoint: str, token: str = "", **kwargs):
        """统一请求方法，根据模式选择直连或代理"""
        import requests

        if self._direct:
            url = f"{self.provider_url}{endpoint}"
            headers = self._direct_headers(token)
        else:
            from urllib.parse import quote

            url = f"{self.api}/api/mail?endpoint={quote(endpoint, safe='')}"
            headers = (
                self._proxy_headers()
                if not token
                else {
                    "authorization": f"Bearer {token}",
                    "x-api-provider-base-url": self.provider_url,
                }
            )
        r = requests.request(
            method, url, headers=headers, proxies=self.proxy, timeout=15, **kwargs
        )
        return r

    def get_email(self) -> MailboxAccount:
        import random, string

        username = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        password = "Test" + "".join(random.choices(string.digits, k=8)) + "!"
        domain = self.domain or self.provider_url.replace("https://api.", "").replace(
            "https://", ""
        )
        address = f"{username}@{domain}"
        print(f"[DuckMail] 创建账号: {address} direct={self._direct}")
        # 创建账号
        r = self._request(
            "POST", "/accounts", json={"address": address, "password": password}
        )
        if r.status_code >= 400 or not r.text.strip().startswith("{"):
            raise RuntimeError(
                f"[DuckMail] 创建账号失败: HTTP {r.status_code} body={r.text[:300]}"
            )
        data = r.json()
        self._address = data.get("address", address)
        # 登录获取 token
        r2 = self._request(
            "POST", "/token", json={"address": self._address, "password": password}
        )
        if r2.status_code >= 400 or not r2.text.strip().startswith(("{", "[")):
            raise RuntimeError(
                f"[DuckMail] 登录失败: HTTP {r2.status_code} body={r2.text[:300]}"
            )
        self._token = r2.json().get("token", "")
        return MailboxAccount(email=self._address, account_id=self._token)

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            r = self._request("GET", "/messages?page=1", token=account.account_id)
            return {str(m["id"]) for m in r.json().get("hydra:member", [])}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        from datetime import datetime
        import re

        seen = set(before_ids or [])
        exclude_codes = {
            str(code).strip()
            for code in (kwargs.get("exclude_codes") or set())
            if str(code or "").strip()
        }
        otp_sent_at = kwargs.get("otp_sent_at")

        def _parse_message_timestamp(*values) -> Optional[float]:
            for value in values:
                if value in (None, ""):
                    continue
                if isinstance(value, (int, float)):
                    numeric = float(value)
                    return numeric / 1000 if numeric > 10_000_000_000 else numeric
                text = str(value).strip()
                if not text:
                    continue
                try:
                    numeric = float(text)
                    return numeric / 1000 if numeric > 10_000_000_000 else numeric
                except (TypeError, ValueError):
                    pass
                try:
                    normalized = text.replace("Z", "+00:00")
                    return datetime.fromisoformat(normalized).timestamp()
                except ValueError:
                    continue
            return None

        def poll_once() -> Optional[str]:
            try:
                r = self._request("GET", "/messages?page=1", token=account.account_id)
                msgs = r.json().get("hydra:member", [])
                for msg in msgs:
                    mid = str(msg.get("id") or msg.get("msgid") or "")
                    if mid in seen:
                        continue
                    seen.add(mid)
                    # 请求邮件详情获取完整 text
                    try:
                        r2 = self._request(
                            "GET", f"/messages/{mid}", token=account.account_id
                        )
                        detail = r2.json()
                        body = (
                            str(detail.get("text") or "")
                            + " "
                            + str(detail.get("subject") or "")
                        )
                    except Exception:
                        detail = {}
                        body = str(msg.get("subject") or "")
                    message_ts = _parse_message_timestamp(
                        detail.get("createdAt"),
                        detail.get("created_at"),
                        detail.get("receivedAt"),
                        detail.get("received_at"),
                        detail.get("date"),
                        detail.get("created"),
                        msg.get("createdAt"),
                        msg.get("created_at"),
                        msg.get("receivedAt"),
                        msg.get("received_at"),
                        msg.get("date"),
                        msg.get("created"),
                    )
                    if otp_sent_at and message_ts and message_ts < float(otp_sent_at):
                        continue
                    body = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "", body
                    )
                    code = self._safe_extract(body, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class MaliAPIMailbox(BaseMailbox):
    """YYDS Mail / MaliAPI 临时邮箱服务"""

    def __init__(
        self,
        api_url: str = "https://maliapi.215.im/v1",
        api_key: str = "",
        domain: str = "",
        auto_domain_strategy: str = "",
        proxy: str = None,
    ):
        self.api = (api_url or "https://maliapi.215.im/v1").rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.domain = str(domain or "").strip()
        self.auto_domain_strategy = str(auto_domain_strategy or "").strip()
        self.proxy = build_requests_proxy_config(proxy)
        self._email = None
        self._temp_token = None

    def _headers(self, bearer: str = "") -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict = None,
        params: dict = None,
        bearer: str = "",
    ) -> Any:
        import requests

        response = requests.request(
            method,
            f"{self.api}{path}",
            headers=self._headers(bearer),
            json=json_body,
            params=params,
            proxies=self.proxy,
            timeout=15,
        )
        try:
            payload = response.json()
        except Exception:
            payload = {}

        if response.status_code >= 400:
            error = response.text or f"HTTP {response.status_code}"
            error_code = ""
            if isinstance(payload, dict):
                error = str(payload.get("error") or error).strip()
                error_code = str(payload.get("errorCode") or "").strip()
            if error_code:
                raise RuntimeError(f"MaliAPI 请求失败: {error} ({error_code})")
            raise RuntimeError(f"MaliAPI 请求失败: {str(error).strip()}")

        if isinstance(payload, dict):
            if payload.get("success") is False:
                error = str(payload.get("error") or "unknown error").strip()
                error_code = str(payload.get("errorCode") or "").strip()
                if error_code:
                    raise RuntimeError(f"MaliAPI 请求失败: {error} ({error_code})")
                raise RuntimeError(f"MaliAPI 请求失败: {error}")
            if "data" in payload:
                return payload.get("data")
        return payload

    def _ensure_api_key(self) -> None:
        if not self.api_key:
            raise RuntimeError("MaliAPI 未配置：请在全局设置中填写 maliapi_api_key")

    def _list_messages(self, account: MailboxAccount) -> list[dict]:
        data = self._request("GET", "/messages", params={"address": account.email})
        if isinstance(data, dict):
            messages = data.get("messages", [])
        else:
            messages = data
        return [item for item in (messages or []) if isinstance(item, dict)]

    def _get_message_detail(self, message_id: str) -> dict:
        data = self._request("GET", f"/messages/{message_id}")
        if isinstance(data, dict) and isinstance(data.get("message"), dict):
            return data["message"]
        return data if isinstance(data, dict) else {}

    def get_email(self) -> MailboxAccount:
        self._ensure_api_key()
        body = {}
        if self.domain:
            body["domain"] = self.domain
        if self.auto_domain_strategy:
            body["autoDomainStrategy"] = self.auto_domain_strategy

        data = self._request("POST", "/accounts", json_body=body)
        if not isinstance(data, dict):
            raise RuntimeError(f"MaliAPI 返回异常: {data}")

        email = str(data.get("address") or data.get("email") or "").strip()
        temp_token = str(
            data.get("tempToken") or data.get("temp_token") or data.get("token") or ""
        ).strip()
        inbox_id = str(data.get("id") or "").strip()
        if not email:
            raise RuntimeError(f"MaliAPI 返回空邮箱: {data}")

        self._email = email
        self._temp_token = temp_token
        self._log(f"[MaliAPI] 生成邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=temp_token or inbox_id or email,
            extra={
                "provider": "maliapi",
                "temp_token": temp_token,
                "inbox_id": inbox_id,
            },
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        self._ensure_api_key()
        try:
            return {
                str(message.get("id"))
                for message in self._list_messages(account)
                if message.get("id") is not None
            }
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import re

        self._ensure_api_key()
        seen = {str(mid) for mid in (before_ids or set())}

        def poll_once() -> Optional[str]:
            try:
                for message in self._list_messages(account):
                    message_id = str(message.get("id") or "").strip()
                    if not message_id or message_id in seen:
                        continue
                    seen.add(message_id)

                    try:
                        detail = self._get_message_detail(message_id)
                    except Exception:
                        detail = message

                    search_text = " ".join(
                        [
                            str(detail.get("subject") or message.get("subject") or ""),
                            str(detail.get("text") or ""),
                            str(detail.get("html") or ""),
                            str(message.get("subject") or ""),
                            str(message.get("snippet") or ""),
                        ]
                    ).strip()
                    search_text = self._yyds_decode_raw_content(search_text) or search_text
                    search_text = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                        "",
                        search_text,
                    )
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._yyds_safe_extract(search_text, code_pattern)
                    if code:
                        self._log("[MaliAPI] 收到验证码（内容不写入日志）")
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class GPTMailMailbox(BaseMailbox):
    """GPTMail 临时邮箱服务"""

    def __init__(
        self,
        api_url: str = "https://mail.chatgpt.org.uk",
        api_key: str = "",
        domain: str = "",
        proxy: str = None,
    ):
        self.api = (api_url or "https://mail.chatgpt.org.uk").rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.domain = self._normalize_domain(domain)
        self.proxy = build_requests_proxy_config(proxy)
        self._email = None

    @staticmethod
    def _normalize_domain(value: Any) -> str:
        domain = str(value or "").strip().lower()
        if domain.startswith("@"):
            domain = domain[1:]
        return domain

    @staticmethod
    def _generate_local_part() -> str:
        import string

        prefix = "".join(random.choices(string.ascii_lowercase, k=6))
        suffix = "".join(random.choices(string.digits, k=4))
        return f"{prefix}{suffix}"

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: int = 15,
    ) -> Any:
        import requests

        response = requests.request(
            method,
            f"{self.api}{path}",
            params=params,
            json=json_body,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=timeout,
        )
        try:
            payload = response.json()
        except Exception as exc:
            preview = (response.text or "")[:200]
            raise RuntimeError(
                f"GPTMail API {path} 返回非 JSON: HTTP {response.status_code} {preview}"
            ) from exc

        if response.status_code >= 400:
            error = payload.get("error") if isinstance(payload, dict) else ""
            message = str(error or response.text or f"HTTP {response.status_code}").strip()
            raise RuntimeError(f"GPTMail API {path} 失败: {message}")

        if isinstance(payload, dict) and payload.get("success") is False:
            error = str(payload.get("error") or "unknown error").strip()
            raise RuntimeError(f"GPTMail API {path} 失败: {error}")

        if isinstance(payload, dict) and "data" in payload:
            return payload.get("data")
        return payload

    def _list_messages(self, email: str) -> list[dict]:
        data = self._request_json("GET", "/api/emails", params={"email": email}, timeout=10)
        if isinstance(data, dict):
            messages = data.get("emails", [])
        else:
            messages = data
        return [item for item in (messages or []) if isinstance(item, dict)]

    def _get_message_detail(self, message_id: str) -> dict[str, Any]:
        data = self._request_json("GET", f"/api/email/{message_id}", timeout=10)
        return data if isinstance(data, dict) else {}

    def get_email(self) -> MailboxAccount:
        if self.domain:
            email = f"{self._generate_local_part()}@{self.domain}"
            self._email = email
            self._log(f"[GPTMail] 本地拼装邮箱: {email}")
            return MailboxAccount(
                email=email,
                account_id=email,
                extra={"provider": "gptmail", "domain": self.domain, "local_address": True},
            )

        data = self._request_json("GET", "/api/generate-email")
        if not isinstance(data, dict):
            raise RuntimeError(f"GPTMail 返回异常: {data}")

        email = str(data.get("email") or "").strip()
        if not email:
            raise RuntimeError(f"GPTMail 返回空邮箱: {data}")

        self._email = email
        self._log(f"[GPTMail] 生成邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=email,
            extra={"provider": "gptmail"},
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            return {
                str(message.get("id"))
                for message in self._list_messages(account.email)
                if message.get("id") is not None
            }
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import re

        seen = {str(mid) for mid in (before_ids or set())}
        exclude_codes = {
            str(code) for code in (kwargs.get("exclude_codes") or set()) if code
        }

        def poll_once() -> Optional[str]:
            try:
                messages = self._list_messages(account.email)
                for message in messages:
                    message_id = str(message.get("id") or "").strip()
                    if not message_id or message_id in seen:
                        continue
                    seen.add(message_id)

                    try:
                        detail = self._get_message_detail(message_id)
                    except Exception:
                        detail = {}

                    search_text = " ".join(
                        [
                            str(message.get("subject") or ""),
                            str(message.get("from_address") or ""),
                            str(message.get("content") or ""),
                            str(message.get("html_content") or ""),
                            str(detail.get("subject") or ""),
                            str(detail.get("content") or ""),
                            str(detail.get("html_content") or ""),
                            str(detail.get("raw_headers") or ""),
                        ]
                    ).strip()
                    search_text = self._decode_raw_content(search_text) or search_text
                    search_text = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                        "",
                        search_text,
                    )
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._safe_extract(search_text, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        self._log("[GPTMail] 收到验证码（内容不写入日志）")
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class OpenTrashMailMailbox(BaseMailbox):
    """OpenTrashMail 临时邮箱服务"""

    def __init__(
        self,
        api_url: str = "",
        domain: str = "",
        password: str = "",
        proxy: str = None,
    ):
        self.api = str(api_url or "").strip().rstrip("/")
        self.domain = self._normalize_domain(domain)
        self.password = str(password or "").strip()
        self.proxy = build_requests_proxy_config(proxy)

    @staticmethod
    def _normalize_domain(value: Any) -> str:
        domain = str(value or "").strip().lower()
        if domain.startswith("@"):
            domain = domain[1:]
        return domain

    @staticmethod
    def _generate_local_part() -> str:
        import string

        prefix = "".join(random.choices(string.ascii_lowercase, k=8))
        suffix = "".join(random.choices(string.digits, k=2))
        return f"{prefix}{suffix}"

    def _headers(self) -> dict[str, str]:
        return {"accept": "application/json, text/plain, */*"}

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        timeout: int = 15,
    ):
        import requests

        request_params = dict(params or {})
        if self.password and "password" not in request_params:
            request_params["password"] = self.password

        return requests.request(
            method,
            f"{self.api}{path}",
            params=request_params or None,
            json=None,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=timeout,
        )

    def _require_api(self) -> None:
        if not self.api:
            raise RuntimeError(
                "OpenTrashMail 未配置 API URL，请检查 opentrashmail_api_url"
            )

    def _build_email_path(self, email: str) -> str:
        from urllib.parse import quote

        return quote(str(email or "").strip(), safe="@")

    def _parse_random_email(self, html_text: str) -> str:
        import re

        text = str(html_text or "")
        if not text:
            return ""

        match = re.search(r"/address/([^\"'<>\s]+@[^\"'<>\s]+)", text, re.IGNORECASE)
        if match:
            return str(match.group(1) or "").strip()

        match = re.search(
            r"([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})",
            text,
            re.IGNORECASE,
        )
        if match:
            return str(match.group(1) or "").strip()
        return ""

    def _list_messages(self, email: str) -> list[dict[str, Any]]:
        self._require_api()
        response = self._request(
            "GET",
            f"/json/{self._build_email_path(email)}",
            timeout=10,
        )
        if response.status_code == 404:
            return []
        try:
            payload = response.json()
        except Exception as exc:
            preview = (response.text or "")[:200]
            raise RuntimeError(
                f"OpenTrashMail 收件箱返回非 JSON: HTTP {response.status_code} {preview}"
            ) from exc

        if response.status_code >= 400:
            if isinstance(payload, dict) and payload.get("error"):
                error = payload.get("error")
            else:
                error = response.text or f"HTTP {response.status_code}"
            raise RuntimeError(f"OpenTrashMail 收件箱查询失败: {str(error).strip()}")

        if not payload:
            return []

        messages: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            for message_id, item in payload.items():
                if not isinstance(item, dict):
                    continue
                message = dict(item)
                message.setdefault("id", str(message_id))
                messages.append(message)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    messages.append(item)
        return messages

    def _get_message_detail(self, email: str, message_id: str) -> dict[str, Any]:
        self._require_api()
        response = self._request(
            "GET",
            f"/json/{self._build_email_path(email)}/{message_id}",
            timeout=10,
        )
        if response.status_code == 404:
            return {}
        try:
            payload = response.json()
        except Exception as exc:
            preview = (response.text or "")[:200]
            raise RuntimeError(
                f"OpenTrashMail 邮件详情返回非 JSON: HTTP {response.status_code} {preview}"
            ) from exc

        if response.status_code >= 400:
            if isinstance(payload, dict) and payload.get("error"):
                error = payload.get("error")
            else:
                error = response.text or f"HTTP {response.status_code}"
            raise RuntimeError(f"OpenTrashMail 邮件详情查询失败: {str(error).strip()}")

        return payload if isinstance(payload, dict) else {}

    def get_email(self) -> MailboxAccount:
        if self.domain:
            email = f"{self._generate_local_part()}@{self.domain}"
            self._log(f"[OpenTrashMail] 本地拼装邮箱: {email}")
            return MailboxAccount(
                email=email,
                account_id=email,
                extra={
                    "provider": "opentrashmail",
                    "domain": self.domain,
                    "local_address": True,
                },
            )

        self._require_api()
        response = self._request("GET", "/api/random", timeout=15)
        if response.status_code >= 400:
            raise RuntimeError(
                f"OpenTrashMail 随机邮箱生成失败: HTTP {response.status_code}"
            )

        email = self._parse_random_email(response.text)
        if not email:
            preview = (response.text or "")[:200]
            raise RuntimeError(f"OpenTrashMail 未能解析随机邮箱: {preview}")

        self._log(f"[OpenTrashMail] 生成邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=email,
            extra={"provider": "opentrashmail"},
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            return {
                str(message.get("id"))
                for message in self._list_messages(account.email)
                if message.get("id") is not None
            }
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import re

        seen = {str(mid) for mid in (before_ids or set())}
        exclude_codes = {
            str(code) for code in (kwargs.get("exclude_codes") or set()) if code
        }

        def poll_once() -> Optional[str]:
            try:
                messages = self._list_messages(account.email)
                for message in messages:
                    message_id = str(message.get("id") or "").strip()
                    if not message_id or message_id in seen:
                        continue
                    seen.add(message_id)

                    detail = self._get_message_detail(account.email, message_id)
                    parsed = detail.get("parsed") if isinstance(detail, dict) else {}
                    if not isinstance(parsed, dict):
                        parsed = {}

                    decoded_raw = self._decode_raw_content(detail.get("raw") or "")
                    search_text = " ".join(
                        [
                            str(message.get("subject") or ""),
                            str(message.get("from") or ""),
                            str(message.get("body") or ""),
                            str(detail.get("from") or ""),
                            str(parsed.get("subject") or ""),
                            str(parsed.get("body") or ""),
                            str(parsed.get("htmlbody") or ""),
                            decoded_raw,
                        ]
                    ).strip()
                    search_text = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                        "",
                        search_text,
                    )
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._safe_extract(search_text, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        self._log("[OpenTrashMail] 收到验证码（内容不写入日志）")
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class CFWorkerMailbox(BaseMailbox):
    """Cloudflare Worker 自建临时邮箱服务"""

    def __init__(
        self,
        api_url: str,
        admin_token: str = "",
        domain: str = "",
        domain_override: str = "",
        domains: Any = None,
        enabled_domains: Any = None,
        subdomain: str = "",
        force_subdomain: Any = False,
        subdomain_strategy: str = "counter",
        subdomain_prefix: str = "",
        subdomain_max_accounts: Any = 100,
        release_on_delete: Any = True,
        random_subdomain: Any = False,
        random_name_subdomain: Any = False,
        fingerprint: str = "",
        custom_auth: str = "",
        quick_api_url: str = "",
        proxy: str = None,
    ):
        self.api = api_url.rstrip("/")
        self.admin_token = admin_token
        self.domain = self._normalize_domain(domain)
        self.domain_override = self._normalize_domain(domain_override)
        self.domains = self._parse_domains(domains)
        raw_enabled_domains = self._parse_domains(enabled_domains)
        if self.domains:
            allowed = set(self.domains)
            self.enabled_domains = [d for d in raw_enabled_domains if d in allowed]
        else:
            self.enabled_domains = raw_enabled_domains
        self.subdomain = self._normalize_subdomain(subdomain)
        self.force_subdomain = self._to_bool(force_subdomain)
        self.subdomain_strategy = str(subdomain_strategy or "counter").strip().lower()
        self.subdomain_prefix = self._normalize_subdomain(subdomain_prefix) or self.subdomain
        self.subdomain_max_accounts = self._parse_positive_int(
            subdomain_max_accounts, default=100
        )
        self.release_on_delete = self._to_bool(release_on_delete)
        self.random_subdomain = self._to_bool(random_subdomain)
        self.random_name_subdomain = self._to_bool(random_name_subdomain)
        self.fingerprint = fingerprint
        self.custom_auth = custom_auth
        self.quick_api_url = (str(quick_api_url or "").strip().rstrip("/")
                              or "https://temp-api.cursom.shop")
        self.proxy = build_requests_proxy_config(proxy)
        self._token = None
        self._reservations: dict[str, dict[str, Any]] = {}
        self._last_email: Optional[MailboxAccount] = None

    def _headers(self) -> dict:
        h = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "x-admin-auth": self.admin_token,
        }
        if self.fingerprint:
            h["x-fingerprint"] = self.fingerprint
        if self.custom_auth:
            h["x-custom-auth"] = self.custom_auth
        return h

    def _ensure_api_configured(self) -> None:
        if not self.api:
            raise RuntimeError("CF Worker API URL 未配置")

    def _read_json(self, response, action: str):
        try:
            return response.json()
        except Exception:
            raise RuntimeError(
                f"CF Worker {action} 返回非 JSON 响应: HTTP {response.status_code}"
            )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        payload: Optional[dict] = None,
        timeout: int = 15,
    ):
        import requests

        url = f"{self.api}{path}"
        response = requests.request(
            method,
            url,
            params=params,
            json=payload,
            headers=self._headers(),
            proxies=self.proxy,
            timeout=timeout,
        )
        body = (response.text or "").strip()
        if response.status_code >= 400:
            if "private site password" in body.lower():
                raise RuntimeError(
                    "CFWorker API 需要私有站点密码，请配置 cfworker_custom_auth"
                )
            raise RuntimeError(
                f"CFWorker API {path} 失败: HTTP {response.status_code}"
            )

        try:
            return response.json()
        except Exception as e:
            raise RuntimeError(
                f"CFWorker API {path} 返回非 JSON: HTTP {response.status_code}"
            ) from e

    def _create_address(self, payload: dict, timeout: int = 15) -> dict:
        """Create a CFWorker address, supporting both current and legacy APIs."""
        errors: list[str] = []
        for path in ("/api/new_address", "/admin/new_address"):
            try:
                return self._request_json(
                    "POST",
                    path,
                    payload=payload,
                    timeout=timeout,
                )
            except Exception as exc:
                errors.append(str(exc))
        raise RuntimeError("；".join(errors))

    def _generate_local_part(self) -> str:
        import string

        # 避免纯数字开头，提高邮箱格式“像真人”的程度
        prefix = "".join(random.choices(string.ascii_lowercase, k=6))
        suffix = "".join(random.choices(string.digits, k=4))
        return f"{prefix}{suffix}"

    @staticmethod
    def _normalize_domain(domain: Any) -> str:
        value = str(domain or "").strip().lower()
        if value.startswith("@"):
            value = value[1:]
        return value

    @staticmethod
    def _normalize_subdomain(value: Any) -> str:
        sub = str(value or "").strip().lower().strip(".")
        if sub.startswith("@"):
            sub = sub[1:]
        parts = [part for part in sub.split(".") if part]
        return ".".join(parts)

    @staticmethod
    def _to_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        text = str(value or "").strip().lower()
        return text in {"1", "true", "yes", "on"}

    @staticmethod
    def _parse_positive_int(value: Any, default: int = 100) -> int:
        try:
            parsed = int(str(value or "").strip() or default)
        except (TypeError, ValueError):
            parsed = default
        return max(parsed, 1)

    @classmethod
    def _parse_domains(cls, value: Any) -> list[str]:
        if not value:
            return []

        items: list[Any]
        if isinstance(value, (list, tuple, set)):
            items = list(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
            if isinstance(parsed, list):
                items = parsed
            else:
                items = [
                    part for chunk in text.splitlines() for part in chunk.split(",")
                ]
        else:
            items = [value]

        domains: list[str] = []
        seen = set()
        for item in items:
            domain = cls._normalize_domain(item)
            if not domain or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
        return domains

    def _pick_domain(self) -> str:
        if self.domain_override:
            return self.domain_override
        if self.enabled_domains:
            return random.choice(self.enabled_domains)
        return self.domain

    def _generate_subdomain_label(self, length: int = 6) -> str:
        import string

        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choices(alphabet, k=length))

    def _compose_domain(self, base_domain: str) -> str:
        domain = self._normalize_domain(base_domain)
        if not domain:
            return ""

        sub_parts: list[str] = []
        if self.random_name_subdomain:
            try:
                import names
                import random

                name_func = random.choice([names.get_first_name, names.get_last_name])
                sub_parts.append(name_func().lower().replace(" ", ""))
            except ImportError:
                sub_parts.append(self._generate_subdomain_label())
        elif self.random_subdomain:
            sub_parts.append(self._generate_subdomain_label())
        if self.subdomain:
            sub_parts.append(self.subdomain)

        if not sub_parts:
            return domain
        return f"{'.'.join(sub_parts)}.{domain}"

    def _reserve_subdomain_domain(self, base_domain: str) -> dict[str, Any]:
        from core.cfworker_subdomain_allocator import reserve_subdomain

        if not base_domain:
            raise RuntimeError("没有可用的 CF Worker 根域名")

        prefix = self.subdomain_prefix or self.subdomain or "acc"
        if self.random_name_subdomain:
            try:
                import names

                prefix = random.choice(
                    [names.get_first_name, names.get_last_name]
                )().lower().replace(" ", "")
            except ImportError:
                prefix = prefix or "acc"
        elif self.random_subdomain:
            prefix = self._generate_subdomain_label()

        return reserve_subdomain(
            base_domain,
            prefix=prefix,
            strategy=self.subdomain_strategy,
            max_accounts=self.subdomain_max_accounts,
        )

    def finalize_account(self, email: str) -> None:
        reservation = self._reservations.pop(str(email or "").strip().lower(), None)
        if not reservation:
            return
        from core.cfworker_subdomain_allocator import finalize_reservation

        finalize_reservation(reservation.get("id"))

    def release_account(self, email: str) -> None:
        reservation = self._reservations.pop(str(email or "").strip().lower(), None)
        if not reservation:
            return
        from core.cfworker_subdomain_allocator import release_reservation

        release_reservation(reservation.get("id"))

    def get_email(self) -> MailboxAccount:
        self._ensure_api_configured()
        name = self._generate_local_part()
        payload = {"enablePrefix": True, "name": name}
        selected_root_domain = self._pick_domain()
        selected_domain = ""
        extra: dict[str, Any] = {}
        reservation: dict[str, Any] | None = None

        if self.random_subdomain or self.random_name_subdomain:
            payload["domain"] = selected_root_domain
            payload["enableRandomSubdomain"] = True
            self._log(f"[CFWorker] 使用随机子域名模式, 根域名: {selected_root_domain}")
        elif self.force_subdomain:
            reservation = self._reserve_subdomain_domain(selected_root_domain)
            selected_domain = reservation.get("full_domain", "")
            extra.update(
                {
                    "cfworker_root_domain": reservation.get("root_domain", ""),
                    "cfworker_subdomain_label": reservation.get("subdomain_label", ""),
                    "cfworker_subdomain_id": reservation.get("id", 0),
                }
            )
        else:
            selected_domain = self._compose_domain(selected_root_domain)

        if selected_domain:
            payload["domain"] = selected_domain
            self._log(f"[CFWorker] 本次使用域名: {selected_domain}")
        elif self.force_subdomain and not (self.random_subdomain or self.random_name_subdomain):
            # random_subdomain 分支已经在 payload 里把 domain 设好了 (走 API 端随机)，
            # 此时 force_subdomain 也为真 (常见于全局配置同时勾上两项) 不应该再 raise。
            raise RuntimeError("未能为本次注册分配 CF Worker 二级域名")
        try:
            data = self._create_address(payload, timeout=15)
        except Exception:
            if self.force_subdomain and reservation:
                from core.cfworker_subdomain_allocator import release_reservation

                release_reservation(reservation.get("id"))
            raise
        email = data.get("email", data.get("address", ""))
        token = data.get("token", data.get("jwt", ""))
        if not email or not token:
            if self.force_subdomain:
                from core.cfworker_subdomain_allocator import release_reservation

                release_reservation((reservation or {}).get("id"))
            raise RuntimeError("CFWorker API new_address 返回缺少 email/jwt")
        self._token = token
        print(f"[CFWorker] 生成邮箱: {email}（邮箱令牌不写入日志）")
        extra["cfworker_domain"] = selected_domain
        mail_account = MailboxAccount(
            email=email,
            account_id=token,
            extra=extra or None,
        )
        self._last_email = mail_account
        if self.force_subdomain and reservation:
            self._reservations[email.strip().lower()] = dict(reservation)
        return mail_account

    def _get_mails(self, email: str) -> list:
        import requests

        response = requests.get(
            f"{self.quick_api_url}/open_api/quick_mails",
            params={"limit": 20, "offset": 0, "address": email},
            timeout=15,
            proxies=self.proxy,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"CFWorker Quick API 失败: HTTP {response.status_code}"
            )
        data = self._read_json(response, "Quick API")
        return data.get("results", data) if isinstance(data, dict) else data

    @staticmethod
    def _stringify_mail_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            return " ".join(CFWorkerMailbox._stringify_mail_value(v) for v in value)
        if isinstance(value, dict):
            try:
                return json.dumps(value, ensure_ascii=False)
            except Exception:
                return str(value)
        return str(value)

    @classmethod
    def _mail_field_text(cls, mail: dict, keys: list[str]) -> str:
        parts: list[str] = []
        for key in keys:
            if key in mail:
                text = cls._stringify_mail_value(mail.get(key)).strip()
                if text:
                    parts.append(text)
        return " ".join(parts)

    @classmethod
    def _mail_sender_text(cls, mail: dict, raw: str) -> str:
        """Read From from structured fields, then RFC822 headers only."""
        sender = cls._mail_field_text(
            mail,
            ["from", "sender", "from_email", "fromEmail"],
        )
        if sender:
            return sender
        try:
            from email.parser import Parser
            from email.policy import default as email_default_policy

            message = Parser(policy=email_default_policy).parsestr(
                str(raw or ""),
                headersonly=True,
            )
            return str(message.get("From") or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _extract_emails(text: str) -> set[str]:
        import re

        return {
            match.group(0).lower()
            for match in re.finditer(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                str(text or ""),
            )
        }

    @classmethod
    def _mail_recipient_matches(cls, mail: dict, raw: str, target_email: str) -> bool:
        import re

        target = str(target_email or "").strip().lower()
        if not target:
            return True

        recipient_text = cls._mail_field_text(
            mail,
            [
                "to",
                "to_email",
                "toEmail",
                "recipient",
                "recipient_email",
                "mail_to",
                "mailTo",
                "rcpt_to",
                "envelope_to",
                "delivered_to",
                "original_to",
            ],
        )
        header_values = [
            match.group(1)
            for match in re.finditer(
                r"(?im)^(?:to|delivered-to|x-original-to|envelope-to):\s*(.+)$",
                str(raw or ""),
            )
        ]
        emails = cls._extract_emails(" ".join([recipient_text, *header_values]))
        return not emails or target in emails

    @classmethod
    def _mail_brief(cls, mail: dict) -> str:
        import re

        subject = cls._stringify_mail_value(mail.get("subject")).strip()
        # OTP providers frequently put the code directly in the subject.  This
        # helper is used only for diagnostics, so redact numeric OTPs and URLs
        # before the summary can reach task logs.
        subject = re.sub(r"https?://\S+", "[link hidden]", subject)
        subject = re.sub(r"(?<!\d)\d{6}(?!\d)", "[code hidden]", subject)
        sender = cls._mail_field_text(mail, ["from", "sender", "from_email", "fromEmail"])
        recipient = cls._mail_field_text(
            mail,
            ["to", "to_email", "toEmail", "recipient", "recipient_email"],
        )
        pieces = []
        if subject:
            pieces.append(f"subject={subject[:80]}")
        if sender:
            pieces.append(f"from={sender[:80]}")
        if recipient:
            pieces.append(f"to={recipient[:80]}")
        return " ".join(pieces) or "no-summary"

    @staticmethod
    def _parse_cfworker_created_at(created_at: str) -> Optional[float]:
        from datetime import datetime, timezone

        value = str(created_at or "").strip()
        if not value:
            return None

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return (
                    datetime.strptime(value[:19], fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except Exception:
                pass

        try:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except Exception:
            return None

    def _extract_cfworker_code(self, text: str, pattern: str = None) -> Optional[str]:
        import re

        cleaned = str(text or "")
        if not cleaned:
            return None

        cleaned = re.sub(r"https?://[^\s\"'<>)]*", " ", cleaned)
        cleaned = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            " ",
            cleaned,
        )
        cleaned = re.sub(r"m=\+\d+\.\d+", " ", cleaned)
        cleaned = re.sub(r"\bt=\d+\b", " ", cleaned)

        patterns: list[str] = []
        if pattern:
            patterns.append(pattern)
        patterns.extend(
            [
                r"(?is)(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|验证码|校验码|动态码|認證碼|驗證碼)[^0-9]{0,80}(\d{6})",
                r"(?is)\bcode\b[^0-9]{0,40}(\d{6})",
            ]
        )

        for regex in patterns:
            match = re.search(regex, cleaned)
            if match:
                return match.group(1) if match.groups() else match.group(0)

        candidates = list(
            dict.fromkeys(
                re.findall(r"(?<![a-zA-Z0-9#])(\d{6})(?![a-zA-Z0-9])", cleaned)
            )
        )
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            self._log("[CFWorker] 邮件包含多个无语义验证码候选，已跳过")
        return None

    def get_action_link_baseline(self, account: MailboxAccount) -> set:
        """Strict snapshot for credential-action mail; errors must propagate."""
        mails = self._get_mails(account.email)
        if not isinstance(mails, list):
            raise RuntimeError("CFWorker 密码邮件基线响应格式错误")
        return {
            str(mail.get("id"))
            for mail in mails
            if isinstance(mail, dict) and mail.get("id") not in (None, "")
        }

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            return self.get_action_link_baseline(account)
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import re

        seen = set(before_ids or [])
        exclude_codes = {str(code) for code in (kwargs.get("exclude_codes") or set()) if code}
        otp_sent_at = kwargs.get("otp_sent_at")
        otp_cutoff = float(otp_sent_at) - 2 if otp_sent_at else None

        def poll_once() -> Optional[str]:
            try:
                mails = self._get_mails(account.email)
                for mail in sorted(mails, key=lambda x: x.get("id", 0), reverse=True):
                    mid = str(mail.get("id", ""))
                    if not mid or mid in seen:
                        continue

                    created_at = str(mail.get("created_at", "") or "").strip()
                    if otp_cutoff and created_at:
                        mail_ts = self._parse_cfworker_created_at(created_at)
                        if mail_ts and mail_ts < otp_cutoff:
                            seen.add(mid)
                            self._log(
                                f"[CFWorker] 跳过旧邮件 id={mid} created_at={created_at}"
                            )
                            continue

                    # 仅在通过时间边界筛选后再标记为已处理，避免边界邮件被过早加入 seen。
                    seen.add(mid)

                    raw = str(mail.get("raw", ""))
                    if not self._mail_recipient_matches(mail, raw, account.email):
                        self._log(
                            f"[CFWorker] 跳过收件人不匹配邮件 id={mid} "
                            f"created_at={created_at} {self._mail_brief(mail)}"
                        )
                        continue

                    subject = str(mail.get("subject", ""))
                    search_text = f"{subject} {self._decode_raw_content(raw)}".strip()
                    search_text = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                        "",
                        search_text,
                    )
                    search_text = re.sub(r"m=\+\d+\.\d+", "", search_text)
                    search_text = re.sub(r"\bt=\d+\b", "", search_text)
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._extract_cfworker_code(search_text, code_pattern)
                    if code and code in exclude_codes:
                        self._log(
                            f"[CFWorker] 跳过已用验证码 id={mid} created_at={created_at}"
                        )
                        continue
                    if code:
                        self._log(
                            f"[CFWorker] 命中新验证码 id={mid} created_at={created_at} "
                            "（验证码内容不写入日志）"
                        )
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
            timeout_message=f"\u7b49\u5f85\u9a8c\u8bc1\u7801\u8d85\u65f6 ({timeout}s)",
        )

    def wait_for_action_link(
        self,
        account: MailboxAccount,
        *,
        timeout: int = 120,
        before_ids: set = None,
        not_before: float | None = None,
    ) -> str:
        """Wait for a new, trusted OpenAI/ChatGPT password action email."""
        seen = {str(mid) for mid in (before_ids or set())}

        def poll_once() -> Optional[str]:
            try:
                mails = self._get_mails(account.email)
            except Exception:
                return None
            for mail in sorted(
                (item for item in mails if isinstance(item, dict)),
                key=lambda item: str(item.get("id", "")),
                reverse=True,
            ):
                mid = str(mail.get("id", "") or "")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                created_at = mail.get("created_at") or mail.get("received_at")
                if not _mail_time_is_fresh(created_at, not_before):
                    continue
                raw = self._mail_field_text(
                    mail,
                    ["raw", "body", "html", "text", "content", "preview"],
                )
                if not self._mail_recipient_matches(mail, raw, account.email):
                    continue
                link = _extract_trusted_chatgpt_password_link(
                    subject=mail.get("subject"),
                    sender=self._mail_sender_text(mail, raw),
                    content=raw,
                )
                if link:
                    self._log(
                        "[CFWorker] 已取得新的 OpenAI 密码设置邮件"
                        "（链接内容不写入日志）"
                    )
                    return link
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
            timeout_message=f"等待 OpenAI 密码设置邮件超时 ({timeout}s)",
        )


class MoeMailMailbox(BaseMailbox):
    """MoeMail (sall.cc) 邮箱服务 - 自动注册账号并生成临时邮箱"""

    def __init__(
        self, api_url: str = "https://sall.cc", api_key: str = "", proxy: str = None
    ):
        self.api = api_url.rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.proxy = build_requests_proxy_config(proxy)
        self._session_token = None
        self._email = None

    def _api_headers(self) -> dict:
        if not self.api_key:
            return {}
        return {"X-API-Key": self.api_key}

    def _register_and_login(self) -> str:
        import requests, random, string

        s = requests.Session()
        s.proxies = self.proxy
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        s.headers.update(
            {"user-agent": ua, "origin": self.api, "referer": f"{self.api}/zh-CN/login"}
        )
        s.headers.update(self._api_headers())
        # 注册
        username = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        password = "Test" + "".join(random.choices(string.digits, k=8)) + "!"
        print(f"[MoeMail] 注册账号: {username}（密码内容不写入日志）")
        r_reg = s.post(
            f"{self.api}/api/auth/register",
            json={"username": username, "password": password, "turnstileToken": ""},
            timeout=15,
        )
        print(f"[MoeMail] 注册结果: {r_reg.status_code} {r_reg.text[:80]}")
        # 获取 CSRF
        csrf_r = s.get(f"{self.api}/api/auth/csrf", timeout=10)
        csrf = csrf_r.json().get("csrfToken", "")
        # 登录
        s.post(
            f"{self.api}/api/auth/callback/credentials",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=f"username={username}&password={password}&csrfToken={csrf}&redirect=false&callbackUrl={self.api}",
            allow_redirects=True,
            timeout=15,
        )
        self._session = s
        for cookie in s.cookies:
            if "session-token" in cookie.name:
                self._session_token = cookie.value
                print(f"[MoeMail] 登录成功")
                return cookie.value
        print(f"[MoeMail] 登录失败，cookies: {[c.name for c in s.cookies]}")
        return ""

    def get_email(self) -> MailboxAccount:
        # 每次调用都重新注册新账号，保证邮箱唯一
        self._session_token = None
        self._register_and_login()
        import random, string

        name = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        # 获取可用域名列表，随机选一个
        domain = "sall.cc"
        try:
            cfg_r = self._session.get(
                f"{self.api}/api/config", headers=self._api_headers(), timeout=10
            )
            domains = [
                d.strip()
                for d in cfg_r.json().get("emailDomains", "sall.cc").split(",")
                if d.strip()
            ]
            if domains:
                domain = random.choice(domains)
        except Exception:
            pass
        r = self._session.post(
            f"{self.api}/api/emails/generate",
            headers=self._api_headers(),
            json={"name": name, "domain": domain, "expiryTime": 86400000},
            timeout=15,
        )
        data = r.json()
        self._email = data.get("email", data.get("address", ""))
        email_id = data.get("id", "")
        print(
            f"[MoeMail] 生成邮箱: {self._email} id={email_id} domain={domain} status={r.status_code}"
        )
        if not email_id:
            print(f"[MoeMail] 生成失败: {data}")
        if email_id:
            self._email_count = getattr(self, "_email_count", 0) + 1
        return MailboxAccount(email=self._email, account_id=str(email_id))

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            r = self._session.get(
                f"{self.api}/api/emails/{account.account_id}",
                headers=self._api_headers(),
                timeout=10,
            )
            return {str(m.get("id", "")) for m in r.json().get("messages", [])}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import re

        seen = set(before_ids or [])

        def poll_once() -> Optional[str]:
            try:
                r = self._session.get(
                    f"{self.api}/api/emails/{account.account_id}",
                    headers=self._api_headers(),
                    timeout=10,
                )
                msgs = r.json().get("messages", [])
                for msg in msgs:
                    mid = str(msg.get("id", ""))
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    body = (
                        str(
                            msg.get("content")
                            or msg.get("text")
                            or msg.get("body")
                            or msg.get("html")
                            or ""
                        )
                        + " "
                        + str(msg.get("subject") or "")
                    )
                    body = re.sub(
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "", body
                    )
                    code = self._safe_extract(body, code_pattern)
                    if code:
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class LuckMailMailbox(BaseMailbox):
    """LuckMail 混合模式：ChatGPT 走购买邮箱，其他平台走订单接码"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        project_code: str = "",
        email_type: str = "",
        domain: str = "",
        proxy: str = None,
    ):
        if not base_url or not api_key:
            raise RuntimeError(
                "LuckMail 未配置：请在全局设置中填写 luckmail_base_url 和 luckmail_api_key"
            )
        from .luckmail import LuckMailClient

        self._client = LuckMailClient(
            base_url=base_url,
            api_key=api_key,
            proxy_url=proxy,
        )
        self._project_code = project_code
        self._email_type = email_type or None
        self._domain = domain or None
        self._order_no = None
        self._token = None
        self._email = None

    def _use_purchase_mode(self, account: MailboxAccount = None) -> bool:
        if (
            account
            and account.account_id
            and str(account.account_id).startswith("tok_")
        ):
            return True
        if self._token:
            return True
        return self._project_code == "openai"

    def _resolve_token(self, account: MailboxAccount = None) -> str:
        token = (account.account_id if account else "") or self._token
        if token:
            self._token = token
            return token

        email = (account.email if account else "") or self._email
        if not email:
            return ""

        try:
            purchases = self._client.user.get_purchases(
                page=1,
                page_size=100,
                keyword=email,
            )
        except Exception:
            return ""

        email_lower = str(email).strip().lower()
        for item in purchases.list:
            if str(item.email_address).strip().lower() == email_lower and item.token:
                self._token = item.token
                self._email = item.email_address
                return item.token
        return ""

    def _cancel_order_silently(self, order_no: str) -> None:
        if not order_no:
            return
        try:
            self._client.user.cancel_order(order_no)
            self._log(f"[LuckMail] 已取消订单: {order_no}")
        except Exception:
            pass

    def _extract_code_from_token_mails(
        self,
        token: str,
        code_pattern: str = None,
        before_ids: set = None,
        exclude_codes: set = None,
    ) -> Optional[str]:
        try:
            mail_list = self._client.user.get_token_mails(token)
        except Exception:
            return None

        seen = {str(mid) for mid in (before_ids or set())}
        excluded = {str(code) for code in (exclude_codes or set()) if code}
        for mail in mail_list.mails:
            message_id = str(mail.message_id or "")
            if message_id and message_id in seen:
                continue
            body = " ".join(
                [
                    str(mail.subject or ""),
                    str(mail.body or ""),
                    str(mail.html_body or ""),
                ]
            )
            code = self._safe_extract(body, code_pattern)
            if code and code in excluded:
                continue
            if code:
                return code
        return None

    def get_email(self) -> MailboxAccount:
        if not self._project_code:
            raise RuntimeError("LuckMail 未设置 project_code，无法创建邮箱")

        if self._use_purchase_mode():
            self._log(
                f"[LuckMail] 分支: ChatGPT + LuckMail -> 购买邮箱接口 "
                f"(project_code={self._project_code}, email_type={self._email_type or '-'}, domain={self._domain or '-'})"
            )
            try:
                result = self._client.user.purchase_emails(
                    project_code=self._project_code,
                    quantity=1,
                    email_type=self._email_type,
                    domain=self._domain,
                )
            except Exception as e:
                raise RuntimeError(f"LuckMail 购买邮箱失败: {e}") from e

            purchases = (result or {}).get("purchases") or []
            if not purchases:
                raise RuntimeError(f"LuckMail 购买邮箱返回为空: {result}")

            item = purchases[0]
            email = str(item.get("email_address") or "").strip()
            token = str(item.get("token") or "").strip()
            if not email or not token:
                raise RuntimeError(f"LuckMail 返回缺少 email/token: {item}")

            self._email = email
            self._token = token
            self._log(f"[LuckMail] 已购邮箱: {email}")
            if item.get("warranty_until"):
                self._log(f"[LuckMail] 质保到期: {item.get('warranty_until')}")
            return MailboxAccount(
                email=email,
                account_id=token,
                extra={
                    "provider": "luckmail",
                    "token": token,
                    "project_code": self._project_code,
                },
            )

        self._log(
            f"[LuckMail] 分支: 其他平台 + LuckMail -> 创建订单/订单接码 "
            f"(project_code={self._project_code}, email_type={self._email_type or '-'})"
        )
        try:
            body = {"project_code": self._project_code}
            if self._email_type:
                body["email_type"] = self._email_type
            order = self._client.user._sync_create_order(body)
        except Exception as e:
            raise RuntimeError(f"LuckMail 创建订单失败: {e}") from e
        self._order_no = order.order_no
        email = order.email_address
        self._email = email
        self._log(f"[LuckMail] 订单 {order.order_no} 分配邮箱: {email}")
        self._log(f"[LuckMail] 超时时间: {order.expired_at}")
        return MailboxAccount(email=email, account_id=order.order_no)

    def get_current_ids(self, account: MailboxAccount) -> set:
        if not self._use_purchase_mode(account):
            return set()
        token = self._resolve_token(account)
        if not token:
            return set()
        try:
            mail_list = self._client.user.get_token_mails(token)
            return {str(m.message_id) for m in (mail_list.mails or []) if m.message_id}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        if not self._use_purchase_mode(account):
            self._log("[LuckMail] 等验证码分支: 订单接码")
            order_no = account.account_id or self._order_no
            if not order_no:
                raise RuntimeError("LuckMail 未创建订单，无法等待验证码")

            def on_poll_order(result):
                self._log(f"[LuckMail] 轮询中... 状态: {result.status}")

            deadline = time.monotonic() + max(int(timeout or 0), 1)
            last_status = "pending"
            try:
                while time.monotonic() < deadline:
                    self._checkpoint()
                    remaining = max(1, int(deadline - time.monotonic()))
                    slice_timeout = min(remaining, 6)
                    try:
                        code_result = self._client.user._sync_wait_for_code(
                            order_no=order_no,
                            timeout=slice_timeout,
                            interval=3.0,
                            on_poll=on_poll_order,
                        )
                    except Exception as e:
                        raise TimeoutError(f"LuckMail 等待验证码失败: {e}") from e

                    last_status = str(code_result.status or "pending")
                    if code_result.status == "success" and code_result.verification_code:
                        code = code_result.verification_code
                        self._log("[LuckMail] 收到验证码（内容不写入日志）")
                        return code
                    if code_result.status in {"cancelled", "timeout"}:
                        break
            except Exception:
                self._cancel_order_silently(order_no)
                raise

            self._cancel_order_silently(order_no)
            raise TimeoutError(
                f"LuckMail 等待验证码超时 ({timeout}s)，最终状态: {last_status}"
            )

        token = self._resolve_token(account)
        if not token:
            raise RuntimeError("LuckMail 未找到已购邮箱 Token，无法等待验证码")
        self._log("[LuckMail] 等验证码分支: 已购邮箱 Token 收码")

        exclude_codes = {
            str(code) for code in (kwargs.get("exclude_codes") or set()) if code
        }
        seen_message_ids = {str(mid) for mid in (before_ids or set()) if mid}
        if before_ids is None:
            seen_message_ids = self.get_current_ids(account)
            if seen_message_ids:
                self._log(
                    f"[LuckMail] 已建立旧邮件基线，先跳过 {len(seen_message_ids)} 封历史邮件"
                )

        saw_new_mail = False

        def poll_once() -> Optional[str]:
            nonlocal saw_new_mail
            found_new_mail = False
            try:
                mail_list = self._client.user.get_token_mails(token)
            except Exception as e:
                raise TimeoutError(f"LuckMail 等待验证码失败: {e}") from e

            for mail in mail_list.mails:
                message_id = str(mail.message_id or "").strip()
                if message_id and message_id in seen_message_ids:
                    continue

                found_new_mail = True
                saw_new_mail = True
                if message_id:
                    seen_message_ids.add(message_id)

                body = " ".join(
                    [
                        str(mail.subject or ""),
                        str(mail.body or ""),
                        str(mail.html_body or ""),
                    ]
                )
                code = self._safe_extract(body, code_pattern)
                if code and code in exclude_codes:
                    self._log(
                        f"[LuckMail] 跳过已使用验证码 message_id={message_id or '-'} code={code}"
                    )
                    continue
                if code:
                    self._log("[LuckMail] 收到验证码（内容不写入日志）")
                    return code

            self._log(
                f"[LuckMail] 轮询中... 新邮件: {'是' if found_new_mail else '否'}"
            )

            if found_new_mail:
                self._log("[LuckMail] 新邮件还不是可用验证码，继续等下一封...")
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
            timeout_message=(
                f"LuckMail 等待验证码超时 ({timeout}s)，最终状态: "
                f"has_new_mail={saw_new_mail}"
            ),
        )


# Outlook IMAP 搜索的文件夹: 收件箱 + 垃圾箱 (Adobe 等验证码常进 Junk)
_OUTLOOK_IMAP_FOLDERS = ("INBOX", "Junk")


class OutlookMailbox(BaseMailbox):
    """Outlook 本地账号池（IMAP / OAuth）"""

    # 全局锁：防止并发线程取到同一个账号
    _global_pop_lock = threading.Lock()

    def __init__(
        self,
        imap_server: str = "",
        imap_port: int | str = 993,
        token_endpoint: str = "",
        platform: str = "",
        proxy: str = None,
    ):
        self._lock = threading.Lock()
        self._proxy = build_requests_proxy_config(proxy)
        self.platform = str(platform or "").strip()
        self._imap_servers = []
        if imap_server:
            self._imap_servers.append(str(imap_server).strip())
        else:
            try:
                from platforms.chatgpt.constants import OUTLOOK_IMAP_SERVERS

                self._imap_servers.extend(
                    [
                        str(OUTLOOK_IMAP_SERVERS.get("NEW") or "").strip(),
                        str(OUTLOOK_IMAP_SERVERS.get("OLD") or "").strip(),
                    ]
                )
            except Exception:
                self._imap_servers.extend(
                    ["outlook.live.com", "outlook.office365.com"]
                )
        self._imap_servers = [
            host for host in self._imap_servers if isinstance(host, str) and host
        ]
        try:
            self._imap_port = int(imap_port or 993)
        except (TypeError, ValueError):
            self._imap_port = 993
        self._token_endpoint = str(token_endpoint or "").strip()

    def _status_field(self) -> str:
        return {
            "chatgpt": "gpt_register_status",
            "grok": "grok_register_status",
            "trae": "trae_register_status",
            "kiro": "kiro_register_status",
            "openblocklabs": "obl_register_status",
            "cursor": "cursor_register_status",
            "adobe": "adobe_register_status",
        }.get(self.platform, "")

    def _pop_account(self) -> dict:
        """预留制：标记为禁用而非直接删除，注册失败后可归还"""
        from sqlmodel import Session, select
        from core.db import engine, OutlookAccountModel
        from datetime import datetime, timezone

        with OutlookMailbox._global_pop_lock:
            with Session(engine) as session:
                query = (
                    select(OutlookAccountModel)
                    .where(OutlookAccountModel.enabled == True)
                    .order_by(OutlookAccountModel.id)
                )
                status_field = self._status_field()
                status_col = getattr(OutlookAccountModel, status_field, None) if status_field else None
                if status_col is not None:
                    query = query.where(status_col != "已注册")
                account = (
                    session.exec(query)
                    .first()
                )
                if not account:
                    raise RuntimeError("Outlook 账号池为空，请先在设置页批量导入")

                payload = {
                    "id": account.id,
                    "email": account.email,
                    "password": account.password,
                    "client_id": account.client_id,
                    "refresh_token": account.refresh_token,
                    "mail_access_type": account.mail_access_type or "",
                }
                # 预留：标记为禁用而非删除
                account.enabled = False
                account.updated_at = datetime.now(timezone.utc)
                session.add(account)
                session.commit()
                return payload

    @staticmethod
    def return_account(account_id: int):
        """注册失败时归还邮箱（重新启用）"""
        from sqlmodel import Session
        from core.db import engine, OutlookAccountModel
        from datetime import datetime, timezone
        try:
            with Session(engine) as session:
                acc = session.get(OutlookAccountModel, account_id)
                if acc and not acc.enabled:
                    acc.enabled = True
                    acc.updated_at = datetime.now(timezone.utc)
                    session.add(acc)
                    session.commit()
        except Exception:
            pass

    @staticmethod
    def restore_all_reserved():
        """服务重启时：将中断预留的邮箱归还（已注册的不归还）"""
        from sqlmodel import Session, select
        from core.db import engine, OutlookAccountModel
        from datetime import datetime, timezone
        try:
            with Session(engine) as session:
                reserved = session.exec(
                    select(OutlookAccountModel).where(OutlookAccountModel.enabled == False)
                ).all()
                count = 0
                for acc in reserved:
                    # 跳过各平台已注册的账号，保持 disabled
                    if acc.gpt_register_status == "已注册":
                        continue
                    acc.enabled = True
                    acc.updated_at = datetime.now(timezone.utc)
                    session.add(acc)
                    count += 1
                if count:
                    session.commit()
                    print(f"[Outlook] 已归还 {count} 个中断预留的邮箱")
        except Exception:
            pass

    def get_email(self) -> MailboxAccount:
        payload = self._pop_account()
        email = str(payload.get("email") or "").strip()
        if not email:
            raise RuntimeError("Outlook 账号邮箱为空")
        self._log(f"[Outlook] 取出账号: {email}（已从本地池移除）")
        account = MailboxAccount(
            email=email,
            account_id=str(payload.get("id") or ""),
            extra={
                "provider": "outlook",
                "password": payload.get("password") or "",
                "client_id": payload.get("client_id") or "",
                "refresh_token": payload.get("refresh_token") or "",
                "mail_access_type": payload.get("mail_access_type") or "",
            },
        )
        self._last_email = account
        return account

    @staticmethod
    def _mail_credentials(account: MailboxAccount) -> dict[str, str]:
        """Resolve persisted namespaced mail credentials before legacy keys."""
        extra = dict(account.extra or {})
        legacy_refresh_token = str(extra.get("refresh_token") or "").strip()
        legacy_looks_microsoft = legacy_refresh_token.startswith(("M.", "0."))
        chatgpt_rt_owned = bool(
            extra.get("chatgpt_has_refresh_token_solution")
            or str(extra.get("chatgpt_registration_mode") or "").strip().lower()
            in {"rt", "refresh_token", "oauth"}
            or str(extra.get("chatgpt_token_source") or "").strip().lower()
            in {"oauth", "register", "refresh"}
        )
        allow_legacy_refresh = not chatgpt_rt_owned or legacy_looks_microsoft
        return {
            "password": str(
                extra.get("outlook_mail_password")
                or extra.get("outlook_password")
                or extra.get("password")
                or ""
            ).strip(),
            "client_id": str(
                extra.get("outlook_mail_client_id")
                or extra.get("outlook_client_id")
                or extra.get("client_id")
                or ""
            ).strip(),
            "refresh_token": str(
                extra.get("outlook_mail_refresh_token")
                or extra.get("outlook_refresh_token")
                or (legacy_refresh_token if allow_legacy_refresh else "")
                or ""
            ).strip(),
            "mail_access_type": str(
                extra.get("outlook_mail_access_type")
                or extra.get("mail_access_type")
                or ""
            ).strip().lower(),
        }

    def _token_endpoints(self) -> list[str]:
        if self._token_endpoint:
            return [self._token_endpoint]
        try:
            from platforms.chatgpt.constants import MICROSOFT_TOKEN_ENDPOINTS

            return [
                MICROSOFT_TOKEN_ENDPOINTS.get("CONSUMERS", ""),
                MICROSOFT_TOKEN_ENDPOINTS.get("LIVE", ""),
                MICROSOFT_TOKEN_ENDPOINTS.get("COMMON", ""),
            ]
        except Exception:
            return [
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                "https://login.live.com/oauth20_token.srf",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            ]

    def _fetch_oauth_token(self, *, email: str, client_id: str, refresh_token: str, scope: str = "") -> str:
        if not client_id or not refresh_token:
            return ""
        import requests

        if not scope:
            try:
                from platforms.chatgpt.constants import MICROSOFT_SCOPES
                scope = str(MICROSOFT_SCOPES.get("IMAP_NEW") or "").strip()
            except Exception:
                scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

        for endpoint in self._token_endpoints():
            endpoint = str(endpoint or "").strip()
            if not endpoint:
                continue
            payload = {
                "client_id": client_id,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
            if scope:
                payload["scope"] = scope
            try:
                resp = requests.post(
                    endpoint,
                    data=payload,
                    timeout=20,
                    proxies=self._proxy,
                )
                if resp.status_code >= 400:
                    continue
                data = resp.json() if resp.content else {}
                access_token = str(data.get("access_token") or "").strip()
                if access_token:
                    return access_token
            except Exception:
                continue
        return ""

    def _fetch_graph_messages(self, account: MailboxAccount, top: int = 15) -> list[dict]:
        """通过 Microsoft Graph API 获取最近邮件（Inbox + Junk Email）"""
        import requests

        extra = account.extra or {}
        credentials = self._mail_credentials(account)
        client_id = credentials["client_id"]
        refresh_token = credentials["refresh_token"]
        email_addr = str(account.email or "").strip()

        access_token = self._fetch_oauth_token(
            email=email_addr, client_id=client_id, refresh_token=refresh_token,
            scope="https://graph.microsoft.com/.default",
        )
        if not access_token:
            raise RuntimeError(f"[Outlook] Graph API: 获取 access_token 失败: {email_addr}")

        all_messages = []
        folder_errors = []
        graph_headers = {"Authorization": f"Bearer {access_token}"}
        if bool(extra.get("graph_immutable_ids")):
            # Default Graph IDs change when a message moves between folders.
            # This is opt-in because legacy monitors persist default IDs and
            # need their own explicit identity cutover before switching.
            graph_headers["Prefer"] = 'IdType="ImmutableId"'

        # 搜索 Inbox + Junk Email 两个文件夹
        for folder in ["inbox", "junkemail"]:
            try:
                resp = requests.get(
                    f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages",
                    headers=graph_headers,
                    params={
                        "$top": top,
                        "$orderby": "receivedDateTime desc",
                        "$select": (
                            "id,internetMessageId,subject,from,bodyPreview,"
                            "body,receivedDateTime"
                        ),
                    },
                    timeout=20,
                    proxies=self._proxy,
                )
                if resp.status_code == 200:
                    messages = resp.json().get("value", [])
                    all_messages.extend([
                        {
                            "id": m.get("id", ""),
                            "subject": m.get("subject", ""),
                            "from": (m.get("from") or {}).get("emailAddress", {}).get("address", ""),
                            "preview": m.get("bodyPreview", ""),
                            "body": (m.get("body") or {}).get("content", ""),
                            "time": m.get("receivedDateTime", ""),
                            "message_id": m.get("internetMessageId", ""),
                            "folder": folder,
                        }
                        for m in messages
                    ])
                else:
                    folder_errors.append(
                        f"{folder}: HTTP {resp.status_code}"
                    )
            except Exception as exc:
                folder_errors.append(f"{folder}: {exc}")

        if folder_errors:
            raise RuntimeError(
                "[Outlook] Graph API 文件夹取件失败: "
                + "; ".join(folder_errors)
            )

        return all_messages

    def _imap_auth_oauth(self, imap_conn, *, email: str, access_token: str) -> None:
        auth_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
        imap_conn.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))

    def _open_imap(self, account: MailboxAccount):
        import imaplib

        email_addr = str(account.email or "").strip()
        credentials = self._mail_credentials(account)
        password = credentials["password"]
        client_id = credentials["client_id"]
        refresh_token = credentials["refresh_token"]

        access_token = ""
        if client_id and refresh_token:
            access_token = self._fetch_oauth_token(
                email=email_addr,
                client_id=client_id,
                refresh_token=refresh_token,
            )

        last_error = None
        for host in self._imap_servers:
            if not host:
                continue
            if access_token:
                try:
                    imap_conn = imaplib.IMAP4_SSL(host, self._imap_port, timeout=30)
                    self._imap_auth_oauth(
                        imap_conn, email=email_addr, access_token=access_token
                    )
                    return imap_conn
                except Exception as exc:
                    last_error = exc
                    try:
                        imap_conn.logout()
                    except Exception:
                        pass
            if password:
                try:
                    imap_conn = imaplib.IMAP4_SSL(host, self._imap_port, timeout=30)
                    imap_conn.login(email_addr, password)
                    return imap_conn
                except Exception as exc:
                    last_error = exc
                    try:
                        imap_conn.logout()
                    except Exception:
                        pass

        raise RuntimeError(f"Outlook IMAP 登录失败: {last_error}")

    def _decode_header_value(self, value: str) -> str:
        from email.header import decode_header

        if not value:
            return ""
        parts = decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                try:
                    decoded.append(part.decode(charset or "utf-8", errors="ignore"))
                except Exception:
                    decoded.append(part.decode("utf-8", errors="ignore"))
            else:
                decoded.append(str(part))
        return "".join(decoded)

    def _extract_message_text(self, message) -> str:
        subject = self._decode_header_value(message.get("Subject", ""))
        body_chunks = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                content_type = part.get_content_type()
                if content_type not in ("text/plain", "text/html"):
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    body_chunks.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    body_chunks.append(payload.decode("utf-8", errors="ignore"))
        else:
            payload = message.get_payload(decode=True)
            if payload is None:
                payload = message.get_payload()
            if isinstance(payload, bytes):
                try:
                    body_chunks.append(payload.decode("utf-8", errors="ignore"))
                except Exception:
                    body_chunks.append(payload.decode("latin1", errors="ignore"))
            elif payload:
                body_chunks.append(str(payload))

        combined = (subject + " " + " ".join(body_chunks)).strip()
        return self._decode_raw_content(combined)

    def _is_graph_account(self, account: MailboxAccount) -> bool:
        return self._mail_credentials(account)["mail_access_type"] == "graph"

    def get_action_link_baseline(self, account: MailboxAccount) -> set:
        """Strict snapshot used before password mail can be triggered."""
        if self._is_graph_account(account):
            messages = self._fetch_graph_messages(account, top=20)
            if not isinstance(messages, list):
                raise RuntimeError("Outlook Graph 密码邮件基线响应格式错误")
            return {str(m.get("id", "")) for m in messages if m.get("id")}

        imap_conn = None
        try:
            imap_conn = self._open_imap(account)
            result: set = set()
            selected_folder = False
            for folder in _OUTLOOK_IMAP_FOLDERS:
                status, _ = imap_conn.select(folder, readonly=True)
                if status != "OK":
                    continue
                selected_folder = True
                status, data = imap_conn.uid("search", None, "ALL")
                if status != "OK":
                    raise RuntimeError("Outlook IMAP 密码邮件基线查询失败")
                ids = data[0].split() if data and data[0] else []
                for uid in ids:
                    uid_str = uid.decode("utf-8", errors="ignore")
                    if uid_str:
                        result.add(f"{folder}:{uid_str}")
            if not selected_folder:
                raise RuntimeError("Outlook IMAP 无法读取密码邮件文件夹")
            return result
        finally:
            try:
                if imap_conn:
                    imap_conn.logout()
            except Exception:
                pass

    def get_current_ids(self, account: MailboxAccount, *, strict: bool = False) -> set:
        try:
            return self.get_action_link_baseline(account)
        except Exception:
            if strict:
                raise RuntimeError("Outlook 邮件基线读取失败") from None
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        seen = {str(mid) for mid in (before_ids or set())}
        exclude_codes = {
            str(code).strip()
            for code in (kwargs.get("exclude_codes") or set())
            if str(code or "").strip()
        }
        keyword_lower = str(keyword or "").strip().lower()

        if self._is_graph_account(account):
            return self._wait_for_code_graph(
                account, seen=seen, exclude_codes=exclude_codes,
                keyword_lower=keyword_lower, code_pattern=code_pattern,
                timeout=timeout,
            )
        return self._wait_for_code_imap(
            account, seen=seen, exclude_codes=exclude_codes,
            keyword_lower=keyword_lower, code_pattern=code_pattern,
            timeout=timeout,
        )

    def _wait_for_code_graph(
        self, account: MailboxAccount, *, seen: set, exclude_codes: set,
        keyword_lower: str, code_pattern: str | None, timeout: int,
    ) -> str:
        def poll_once() -> Optional[str]:
            try:
                messages = self._fetch_graph_messages(account, top=15)
                for m in messages:
                    mid = str(m.get("id", ""))
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    text = f"{m.get('subject', '')} {m.get('preview', '')} {m.get('body', '')}"
                    text = self._decode_raw_content(text)
                    if keyword_lower and keyword_lower not in text.lower():
                        continue
                    code = self._safe_extract(text, code_pattern)
                    if code and code in exclude_codes:
                        continue
                    if code:
                        self._log("[Outlook/Graph] 收到验证码（内容不写入日志）")
                        return code
            except Exception as e:
                self._log(f"[Outlook/Graph] 轮询异常: {e}")
            return None

        return self._run_polling_wait(
            timeout=timeout, poll_interval=5, poll_once=poll_once,
        )

    def _wait_for_code_imap(
        self, account: MailboxAccount, *, seen: set, exclude_codes: set,
        keyword_lower: str, code_pattern: str | None, timeout: int,
    ) -> str:
        from email import message_from_bytes
        from email.policy import default as email_default_policy

        def poll_once() -> Optional[str]:
            imap_conn = None
            try:
                imap_conn = self._open_imap(account)
                # Adobe 验证码常落在垃圾箱,INBOX + Junk 都搜;UID 按文件夹命名空间隔离避免跨夹串号
                for folder in _OUTLOOK_IMAP_FOLDERS:
                    status, _ = imap_conn.select(folder, readonly=True)
                    if status != "OK":
                        continue
                    status, data = imap_conn.uid("search", None, "ALL")
                    if status != "OK":
                        continue
                    ids = data[0].split() if data and data[0] else []
                    if len(ids) > 50:
                        ids = ids[-50:]
                    for uid in ids:
                        uid_str = (
                            uid.decode("utf-8", errors="ignore")
                            if isinstance(uid, bytes)
                            else str(uid)
                        )
                        if not uid_str:
                            continue
                        seen_key = f"{folder}:{uid_str}"
                        if seen_key in seen or uid_str in seen:
                            continue
                        seen.add(seen_key)
                        status, msg_data = imap_conn.uid("fetch", uid, "(RFC822)")
                        if status != "OK":
                            continue
                        raw = None
                        for item in msg_data or []:
                            if isinstance(item, tuple) and item[1]:
                                raw = item[1]
                                break
                        if not raw:
                            continue
                        msg = message_from_bytes(raw, policy=email_default_policy)
                        text = self._extract_message_text(msg)
                        if keyword_lower and keyword_lower not in text.lower():
                            continue
                        code = self._safe_extract(text, code_pattern)
                        if code:
                            if code in exclude_codes:
                                continue
                            self._log(
                                f"[Outlook/IMAP] 收到验证码 ({folder})"
                                "（内容不写入日志）"
                            )
                            return code
            except Exception:
                return None
            finally:
                try:
                    if imap_conn:
                        imap_conn.logout()
                except Exception:
                    pass
            return None

        return self._run_polling_wait(
            timeout=timeout, poll_interval=5, poll_once=poll_once,
        )

    def wait_for_action_link(
        self,
        account: MailboxAccount,
        *,
        timeout: int = 120,
        before_ids: set = None,
        not_before: float | None = None,
    ) -> str:
        """Wait only for a new trusted OpenAI/ChatGPT password-action email."""
        seen = {str(mid) for mid in (before_ids or set())}
        if self._is_graph_account(account):
            return self._wait_for_action_link_graph(
                account,
                seen=seen,
                timeout=timeout,
                not_before=not_before,
            )
        return self._wait_for_action_link_imap(
            account,
            seen=seen,
            timeout=timeout,
            not_before=not_before,
        )

    def _wait_for_action_link_graph(
        self,
        account: MailboxAccount,
        *,
        seen: set,
        timeout: int,
        not_before: float | None,
    ) -> str:
        def poll_once() -> Optional[str]:
            try:
                messages = self._fetch_graph_messages(account, top=20)
            except Exception:
                return None
            for message in messages:
                mid = str(message.get("id") or "")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                if not _mail_time_is_fresh(message.get("time"), not_before):
                    continue
                link = _extract_trusted_chatgpt_password_link(
                    subject=message.get("subject"),
                    sender=message.get("from"),
                    content=(
                        f"{message.get('preview', '')} "
                        f"{message.get('body', '')}"
                    ),
                )
                if link:
                    self._log(
                        "[Outlook/Graph] 已取得新的 OpenAI 密码设置邮件"
                        "（链接内容不写入日志）"
                    )
                    return link
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=5,
            poll_once=poll_once,
            timeout_message=f"等待 OpenAI 密码设置邮件超时 ({timeout}s)",
        )

    def _wait_for_action_link_imap(
        self,
        account: MailboxAccount,
        *,
        seen: set,
        timeout: int,
        not_before: float | None,
    ) -> str:
        from email import message_from_bytes
        from email.policy import default as email_default_policy

        def poll_once() -> Optional[str]:
            imap_conn = None
            try:
                imap_conn = self._open_imap(account)
                for folder in _OUTLOOK_IMAP_FOLDERS:
                    status, _ = imap_conn.select(folder, readonly=True)
                    if status != "OK":
                        continue
                    status, data = imap_conn.uid("search", None, "ALL")
                    if status != "OK":
                        continue
                    ids = data[0].split() if data and data[0] else []
                    for uid in reversed(ids[-50:]):
                        uid_text = (
                            uid.decode("utf-8", errors="ignore")
                            if isinstance(uid, bytes)
                            else str(uid)
                        )
                        seen_key = f"{folder}:{uid_text}"
                        if not uid_text or seen_key in seen or uid_text in seen:
                            continue
                        seen.add(seen_key)
                        status, msg_data = imap_conn.uid("fetch", uid, "(RFC822)")
                        if status != "OK":
                            continue
                        raw_message = next(
                            (
                                item[1]
                                for item in (msg_data or [])
                                if isinstance(item, tuple) and item[1]
                            ),
                            None,
                        )
                        if not raw_message:
                            continue
                        message = message_from_bytes(
                            raw_message,
                            policy=email_default_policy,
                        )
                        if not _mail_time_is_fresh(
                            message.get("Date", ""),
                            not_before,
                        ):
                            continue
                        subject = self._decode_header_value(
                            message.get("Subject", "")
                        )
                        sender = self._decode_header_value(message.get("From", ""))
                        # RFC822 bytes retain HTML href targets which the OTP
                        # text normaliser intentionally strips.
                        link = _extract_trusted_chatgpt_password_link(
                            subject=subject,
                            sender=sender,
                            content=raw_message.decode("utf-8", errors="ignore"),
                        )
                        if link:
                            self._log(
                                "[Outlook/IMAP] 已取得新的 OpenAI 密码设置邮件"
                                "（链接内容不写入日志）"
                            )
                            return link
            except Exception:
                return None
            finally:
                try:
                    if imap_conn:
                        imap_conn.logout()
                except Exception:
                    pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=5,
            poll_once=poll_once,
            timeout_message=f"等待 OpenAI 密码设置邮件超时 ({timeout}s)",
        )


class FreemailMailbox(BaseMailbox):
    """
    Freemail 自建邮箱服务（基于 Cloudflare Worker）
    项目: https://github.com/idinging/freemail
    支持管理员令牌或账号密码两种认证方式
    """

    def __init__(
        self,
        api_url: str,
        admin_token: str = "",
        username: str = "",
        password: str = "",
        domain: str = "",
        proxy: str = None,
    ):
        self.api = api_url.rstrip("/")
        self.admin_token = admin_token
        self.username = username
        self.password = password
        self.domain = str(domain or "").strip().lstrip("@")
        self.proxy = build_requests_proxy_config(proxy)
        self._session = None
        self._email = None
        self._domains = None

    def _get_session(self):
        import requests

        s = requests.Session()
        s.proxies = self.proxy
        if self.admin_token:
            s.headers.update({"Authorization": f"Bearer {self.admin_token}"})
        elif self.username and self.password:
            s.post(
                f"{self.api}/api/login",
                json={"username": self.username, "password": self.password},
                timeout=15,
            )
        self._session = s
        return s

    def get_email(self) -> MailboxAccount:
        if not self._session:
            self._get_session()

        target_domain = self.domain
        domain_index = 0
        if target_domain:
            domains = self._ensure_domains()
            if domains:
                lookup = str(target_domain).lower()
                for idx, domain in enumerate(domains):
                    if str(domain or "").strip().lower() == lookup:
                        domain_index = idx
                        break

        params = {"domainIndex": domain_index} if target_domain else {}
        r = self._session.get(f"{self.api}/api/generate", params=params, timeout=15)
        data = r.json()
        email = str(data.get("email", "") or "")
        if target_domain and email and "@" in email:
            actual_domain = email.split("@", 1)[1].strip().lower()
            if actual_domain != target_domain.lower():
                self._log(
                    f"[Freemail] 指定域名 {target_domain} 未命中，实际返回 {actual_domain}"
                )

        self._email = email
        print(f"[Freemail] 生成邮箱: {email}")
        return MailboxAccount(email=email, account_id=email)

    def _ensure_domains(self) -> list:
        if self._domains is not None:
            return self._domains
        self._domains = []
        if not self._session:
            self._get_session()
        try:
            r = self._session.get(f"{self.api}/api/domains", timeout=15)
            payload = r.json()
            normalized = []
            def _append_domain(value):
                domain = str(value or "").strip().lstrip("@")
                if domain and domain not in normalized:
                    normalized.append(domain)
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        _append_domain(
                            item.get("domain")
                            or item.get("name")
                            or item.get("value")
                        )
                    else:
                        _append_domain(item)
            elif isinstance(payload, dict):
                candidates = payload.get("domains") or payload.get("data") or []
                if isinstance(candidates, list):
                    for item in candidates:
                        if isinstance(item, dict):
                            _append_domain(
                                item.get("domain")
                                or item.get("name")
                                or item.get("value")
                            )
                        else:
                            _append_domain(item)
            self._domains = normalized
        except Exception:
            self._domains = []
        return self._domains

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            r = self._session.get(
                f"{self.api}/api/emails",
                params={"mailbox": account.email, "limit": 50},
                timeout=10,
            )
            return {str(m["id"]) for m in r.json() if "id" in m}
        except Exception:
            return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        seen = set(before_ids or [])
        exclude_codes = {
            str(code).strip()
            for code in (kwargs.get("exclude_codes") or set())
            if str(code or "").strip()
        }

        def poll_once() -> Optional[str]:
            try:
                r = self._session.get(
                    f"{self.api}/api/emails",
                    params={"mailbox": account.email, "limit": 20},
                    timeout=10,
                )
                for msg in r.json():
                    mid = str(msg.get("id", ""))
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    # 直接用 verification_code 字段
                    code = str(msg.get("verification_code") or "").strip()
                    if code and code != "None":
                        if code in exclude_codes:
                            continue
                        return code
                    # 兜底：从 preview 提取
                    text = (
                        str(msg.get("preview", "")) + " " + str(msg.get("subject", ""))
                    )
                    code = self._safe_extract(text, code_pattern)
                    if code:
                        if code in exclude_codes:
                            continue
                        return code
            except Exception:
                pass
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=3,
            poll_once=poll_once,
        )


class QQMailMailbox(BaseMailbox):
    """QQ 邮箱 IMAP 收信，专为 iCloud Hide-My-Email 转发场景设计。

    实现策略:
      1. 从 pool 文件取下一个 HME 别名 (复用 applemail_pool.py 的轮转游标)
      2. 用 IMAP SEARCH TO "<alias>" 精确过滤,Apple 转发邮件 100% 保留 To 头
      3. 通过 X-ICLOUD-HME 头做二次校验,确保是 Apple 真实转发而非伪造邮件
      4. 验证码提取走基类 _yyds_safe_extract,兼容主流平台 6 位数字
    """

    DEFAULT_HOST = "imap.qq.com"
    DEFAULT_PORT = 993

    def __init__(
        self,
        user: str,
        auth_code: str,
        host: str = "",
        port: int = 0,
        pool_file: str = "",
        pool_dir: str = "mail",
        mailbox: str = "INBOX",
        require_apple_header: bool = True,
        proxy: str = None,
        platform: str = "",        # 注册平台,用于 tracker 查"该平台未注册"的 alias
        use_tracker: bool = True,   # 是否启用 DB tracker (有 platform 时默认 True)
    ):
        self.user = str(user or "").strip()
        self.auth_code = str(auth_code or "").strip()
        self.host = str(host or "").strip() or self.DEFAULT_HOST
        self.port = int(port) if port else self.DEFAULT_PORT
        self.pool_file = str(pool_file or "").strip()
        self.pool_dir = str(pool_dir or "mail").strip() or "mail"
        self.mailbox = str(mailbox or "INBOX").strip() or "INBOX"
        self.require_apple_header = bool(require_apple_header)
        self._proxy_raw = proxy  # imaplib SSL 直连,proxy 暂未启用
        self.platform = str(platform or "").strip().lower()
        self.use_tracker = bool(use_tracker)

        self._account_email = None
        self._account_record = None
        self._last_email = None

    # 简易轮转游标 (与 applemail_pool 不同:本池子每行就是一个 HME 邮箱地址)
    _QQ_POOL_CURSORS: dict = {}
    _QQ_POOL_LOCK = threading.Lock()

    def _resolve_pool_path(self) -> str:
        from pathlib import Path

        if self.pool_file:
            p = Path(self.pool_file)
            if p.is_absolute():
                return str(p)
            root = Path(__file__).resolve().parent.parent
            return str(root / p)
        # 用 pool_dir 兜底
        root = Path(__file__).resolve().parent.parent
        d = root / (self.pool_dir or "mail")
        if d.is_dir():
            for c in sorted(d.glob("*.txt")):
                if c.stat().st_size > 0:
                    return str(c)
        raise RuntimeError("未找到 HME 邮箱池子文件 (pool_file/pool_dir 都没指对)")

    def _load_pool(self):
        from pathlib import Path
        path = self._resolve_pool_path()
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        emails = []
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # 兼容 "email" / "email\tlabel" / "email,xxx" 等格式
            candidate = line.split()[0].split(",")[0].split("\t")[0]
            if "@" in candidate:
                emails.append(candidate)
        if not emails:
            raise RuntimeError(f"邮箱池 {path} 为空")
        return path, emails

    def get_email(self) -> MailboxAccount:
        if not self.user or not self.auth_code:
            raise RuntimeError("QQMail provider 未配置 user / auth_code")

        # 优先走 tracker:找一个 (该 platform 未注册) 的 alias,自动跳过用过的
        if self.use_tracker and self.platform:
            try:
                from services.icloud_hme_tracker import claim_alias_for_platform
                claimed = claim_alias_for_platform(self.platform)
            except Exception as exc:
                self._log(f"[QQMail] tracker 查询失败,回退到池子文件: {exc}")
                claimed = None
            if claimed and claimed.get("email"):
                email_addr = claimed["email"]
                self._account_email = email_addr
                self._log(f"[QQMail] tracker 分配 ({self.platform} 未注册): {email_addr}")
                account = MailboxAccount(
                    email=email_addr,
                    account_id=claimed.get("anonymous_id", ""),
                    extra={
                        "qq_owner": self.user,
                        "icloud_hme_anonymous_id": claimed.get("anonymous_id", ""),
                        "platform": self.platform,
                    },
                )
                self._last_email = account
                return account
            elif self.use_tracker and self.platform:
                self._log(f"[QQMail] tracker 中 {self.platform} 没有未注册的 alias,回退到池子文件")

        # 池子文件 fallback:简单 round-robin
        path, emails = self._load_pool()
        with QQMailMailbox._QQ_POOL_LOCK:
            idx = QQMailMailbox._QQ_POOL_CURSORS.get(path, 0)
            email_addr = emails[idx % len(emails)]
            QQMailMailbox._QQ_POOL_CURSORS[path] = idx + 1

        self._account_email = email_addr
        from pathlib import Path
        self._log(f"[QQMail] 从池子 {Path(path).name} 取邮箱 (#{idx+1}/{len(emails)}): {email_addr}")
        account = MailboxAccount(
            email=email_addr,
            account_id="",
            extra={"qq_owner": self.user, "platform": self.platform},
        )
        self._last_email = account
        return account

    # 注册结束时由 task runtime 调用 (参考 api/tasks.py:524 finalize_account)
    def finalize_account(self, email: str) -> None:
        if self.use_tracker and self.platform and email:
            try:
                from services.icloud_hme_tracker import mark_register_status
                mark_register_status(email, self.platform, "已注册")
                self._log(f"[QQMail] tracker 标记 {email} 在 {self.platform} = 已注册")
            except Exception as exc:
                self._log(f"[QQMail] finalize_account 失败: {exc}")

    # 注册失败/中断时把 "进行中" 重置回 "未注册"
    def release_account(self, email: str) -> None:
        email = str(email or self._account_email or getattr(self._last_email, "email", "") or "").strip()
        if self.use_tracker and self.platform and email:
            try:
                from services.icloud_hme_tracker import release_alias
                release_alias(email, self.platform)
                self._log(f"[QQMail] tracker 释放 {email} 回 未注册")
            except Exception as exc:
                self._log(f"[QQMail] release_account 失败: {exc}")

    def _connect(self):
        import imaplib
        M = imaplib.IMAP4_SSL(self.host, self.port, timeout=30)
        try:
            typ, _ = M.login(self.user, self.auth_code)
            if typ != "OK":
                raise RuntimeError(f"IMAP 登录失败: {typ}")
        except Exception:
            try:
                M.logout()
            except Exception:
                pass
            raise
        return M

    def _select(self, M, readonly: bool = True):
        typ, _ = M.select(self.mailbox, readonly=readonly)
        if typ != "OK":
            raise RuntimeError(f"SELECT {self.mailbox} 失败: {typ}")

    def _search_to(self, M, alias: str, *, strict: bool = False):
        typ, data = M.uid("SEARCH", None, "TO", f'"{alias}"')
        if strict and typ != "OK":
            raise RuntimeError("QQ 邮箱邮件基线查询失败")
        if typ != "OK" or not data or not data[0]:
            return set()
        return set(data[0].split())

    def _is_apple_forwarded(self, msg, alias: str) -> bool:
        x_icloud = msg.get("X-ICLOUD-HME", "") or ""
        if not x_icloud:
            return False
        return alias.lower() in str(x_icloud).lower()

    def _decode_header(self, value):
        if value is None:
            return ""
        try:
            from email.header import decode_header, make_header
            return str(make_header(decode_header(str(value))))
        except Exception:
            return str(value)

    def _normalize_message_part_text(self, text: str, content_type: str = "") -> str:
        import html
        import re

        raw = str(text or "")
        if not raw:
            return ""
        ctype = str(content_type or "").lower()
        if "html" in ctype or "<" in raw:
            raw = re.sub(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", raw)
            raw = re.sub(r"(?is)<!--.*?-->", " ", raw)
            raw = re.sub(r"(?is)<[^>]+>", " ", raw)
        raw = html.unescape(raw)
        return re.sub(r"\s+", " ", raw).strip()

    def _extract_body_text(self, msg) -> str:
        chunks = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = (part.get_content_type() or "").lower()
                if ctype.startswith("text/"):
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        chunks.append(
                            self._normalize_message_part_text(
                                payload.decode(charset, errors="ignore"),
                                ctype,
                            )
                        )
                    except LookupError:
                        chunks.append(
                            self._normalize_message_part_text(
                                payload.decode("utf-8", errors="ignore"),
                                ctype,
                            )
                        )
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    chunks.append(
                        self._normalize_message_part_text(
                            payload.decode(charset, errors="ignore"),
                            msg.get_content_type() or "",
                        )
                    )
                except LookupError:
                    chunks.append(
                        self._normalize_message_part_text(
                            payload.decode("utf-8", errors="ignore"),
                            msg.get_content_type() or "",
                        )
                    )
        subject = self._decode_header(msg.get("Subject", ""))
        if subject:
            chunks.insert(0, subject)
        return "\n".join(chunks)

    def _extract_body_html(self, msg) -> str:
        """返回邮件里 text/html part 的**原始 HTML**(不删标签),供前端 iframe 渲染排版。
        没有 HTML part 则返回 ""(调用方回退到纯文本)。"""
        def _decode(part) -> str:
            payload = part.get_payload(decode=True)
            if not payload:
                return ""
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="ignore")
            except LookupError:
                return payload.decode("utf-8", errors="ignore")

        if msg.is_multipart():
            for part in msg.walk():
                if (part.get_content_type() or "").lower() == "text/html":
                    html_raw = _decode(part)
                    if html_raw.strip():
                        return html_raw
        elif (msg.get_content_type() or "").lower() == "text/html":
            return _decode(msg)
        return ""

    def get_current_ids(self, account: MailboxAccount, *, strict: bool = False):
        alias = account.email
        try:
            M = self._connect()
        except Exception as exc:
            if strict:
                raise RuntimeError("QQ 邮箱邮件基线连接失败") from None
            self._log(f"[QQMail] 连接失败 (get_current_ids): {exc}")
            return set()
        try:
            self._select(M, readonly=True)
            uids = (
                self._search_to(M, alias, strict=True)
                if strict else self._search_to(M, alias)
            )
            self._log(f"[QQMail] snapshot before-ids ({alias}): {len(uids)} 封")
            return uids
        except Exception:
            if strict:
                raise RuntimeError("QQ 邮箱邮件基线读取失败") from None
            raise
        finally:
            try:
                M.close()
            except Exception:
                pass
            try:
                M.logout()
            except Exception:
                pass

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        import email as email_pkg

        alias = account.email
        before = before_ids or set()
        keyword_lower = (keyword or "").lower().strip()
        self._log(f"[QQMail] 等待 {alias} 的验证码 (timeout={timeout}s, 已有 {len(before)} 封)")

        def poll_once():
            try:
                M = self._connect()
            except Exception as exc:
                self._log(f"[QQMail] IMAP 连接失败: {exc}")
                return None
            try:
                self._select(M, readonly=True)
                uids = self._search_to(M, alias)
                new_uids = sorted(uids - before, key=lambda x: int(x))
                if not new_uids:
                    return None
                for uid in reversed(new_uids):
                    typ, data = M.uid("FETCH", uid, "(BODY.PEEK[])")
                    if typ != "OK" or not data:
                        continue
                    raw = b""
                    for item in data:
                        if isinstance(item, tuple) and len(item) >= 2:
                            raw = item[1]
                            break
                    if not raw:
                        continue
                    msg = email_pkg.message_from_bytes(raw)
                    if self.require_apple_header and not self._is_apple_forwarded(msg, alias):
                        self._log(f"[QQMail] UID={uid.decode()} 没有 X-ICLOUD-HME(可能伪造或非转发邮件),跳过")
                        continue
                    body = self._extract_body_text(msg)
                    if keyword_lower and keyword_lower not in body.lower():
                        continue
                    code = self._yyds_safe_extract(body, code_pattern)
                    if code:
                        self._log(f"[QQMail] ✅ UID={uid.decode()} 提取到验证码（内容不写入日志）")
                        return code
                return None
            finally:
                try:
                    M.close()
                except Exception:
                    pass
                try:
                    M.logout()
                except Exception:
                    pass

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=5,
            poll_once=poll_once,
            timeout_message=f"QQMail 等待 {alias} 验证码超时 ({timeout}s)",
        )

    def list_recent(self, account, limit: int = 15) -> list:
        """列出发给该别名的最近 limit 封邮件, 返回标准 message dict 列表。

        用于 GPT PRO 收件箱监控/取件(封禁/退款检测)。字段与 Outlook 取件对齐:
        {id, from, subject, preview, body, is_html, time, folder}。
        """
        import email as email_pkg
        import re as _re
        from datetime import timezone as _tz
        from email.utils import parsedate_to_datetime

        alias = getattr(account, "email", None) or str(account or "")
        out: list = []
        self._last_list_recent_metadata = {}
        try:
            M = self._connect()
        except Exception as exc:
            raise RuntimeError(f"QQMail IMAP 连接失败: {exc}")
        try:
            self._select(M, readonly=True)
            uidvalidity = ""
            try:
                response_name, response_data = M.response("UIDVALIDITY")
                response_text = " ".join(
                    (
                        item.decode("ascii", errors="ignore")
                        if isinstance(item, bytes)
                        else str(item or "")
                    )
                    for item in [response_name, *(response_data or [])]
                )
                matched = _re.search(
                    r"UIDVALIDITY\D+(\d+)",
                    response_text,
                    _re.IGNORECASE,
                )
                if matched:
                    uidvalidity = matched.group(1)
            except Exception:
                uidvalidity = ""
            if not uidvalidity:
                try:
                    status_name, status_data = M.status(
                        self.mailbox,
                        "(UIDVALIDITY)",
                    )
                    status_text = " ".join(
                        (
                            item.decode("ascii", errors="ignore")
                            if isinstance(item, bytes)
                            else str(item or "")
                        )
                        for item in [status_name, *(status_data or [])]
                    )
                    matched = _re.search(
                        r"UIDVALIDITY\D+(\d+)",
                        status_text,
                        _re.IGNORECASE,
                    )
                    if matched:
                        uidvalidity = matched.group(1)
                except Exception:
                    uidvalidity = ""
            if not uidvalidity:
                raise RuntimeError("QQMail IMAP 未返回 UIDVALIDITY")
            self._last_list_recent_metadata = {
                "identity_scheme": "imap_uidvalidity",
                "identity_version": 3,
                "uidvalidity_verified": True,
            }
            uids = self._search_to(M, alias)
            uids_sorted = sorted(uids, key=lambda x: int(x), reverse=True)[: max(1, int(limit))]
            for uid in uids_sorted:
                typ, data = M.uid(
                    "FETCH",
                    uid,
                    "(BODY.PEEK[] INTERNALDATE)",
                )
                if typ != "OK":
                    typ, data = M.uid("FETCH", uid, "(BODY.PEEK[])")
                if typ != "OK" or not data:
                    raise RuntimeError(
                        f"QQMail UID {uid!r} FETCH 失败: {typ}"
                    )
                raw = b""
                metadata_chunks = []
                for item in data:
                    if isinstance(item, tuple) and len(item) >= 2:
                        raw = item[1]
                        metadata_chunks.append(item[0])
                    elif isinstance(item, (bytes, str)):
                        metadata_chunks.append(item)
                if not raw:
                    raise RuntimeError(
                        f"QQMail UID {uid!r} FETCH 响应缺少正文"
                    )
                msg = email_pkg.message_from_bytes(raw)
                if self.require_apple_header and not self._is_apple_forwarded(msg, alias):
                    continue
                subject = self._decode_header(msg.get("Subject", ""))
                frm = self._decode_header(msg.get("From", ""))
                try:
                    dt = parsedate_to_datetime(msg.get("Date", "") or "")
                    time_iso = dt.astimezone(_tz.utc).isoformat() if dt else ""
                except Exception:
                    time_iso = ""
                metadata_text = " ".join(
                    (
                        item.decode("ascii", errors="ignore")
                        if isinstance(item, bytes)
                        else str(item or "")
                    )
                    for item in metadata_chunks
                )
                internaldate_iso = ""
                internaldate_match = _re.search(
                    r'INTERNALDATE\s+"([^"]+)"',
                    metadata_text,
                    _re.IGNORECASE,
                )
                if internaldate_match:
                    try:
                        internaldate = parsedate_to_datetime(
                            internaldate_match.group(1)
                        )
                        if internaldate is not None:
                            if internaldate.tzinfo is None:
                                internaldate = internaldate.replace(tzinfo=_tz.utc)
                            internaldate_iso = internaldate.astimezone(
                                _tz.utc
                            ).isoformat()
                    except Exception:
                        internaldate_iso = ""
                if not internaldate_iso:
                    raise RuntimeError(
                        f"QQMail UID {uid!r} 缺少可验证的 INTERNALDATE"
                    )
                body_text = self._extract_body_text(msg) or ""
                body_html = self._extract_body_html(msg) or ""
                uid_text = uid.decode() if isinstance(uid, bytes) else str(uid)
                legacy_folder_uid = f"imap:{self.mailbox}:{uid_text}"
                encoded_folder = (
                    str(self.mailbox)
                    .replace("%", "%25")
                    .replace(":", "%3A")
                )
                stable_id = (
                    f"imap:{encoded_folder}:{uidvalidity}:{uid_text}"
                )
                identity_scheme = "imap_uidvalidity"
                identity_version = 3
                out.append({
                    "id": stable_id,
                    "legacy_id": uid_text,
                    "legacy_ids": [legacy_folder_uid, uid_text],
                    "from": frm,
                    "subject": subject,
                    "message_id": (msg.get("Message-ID", "") or "").strip(),  # 回复线程用
                    "preview": body_text[:300],          # 预览仍用拍平的纯文本
                    "body": body_html or body_text,      # 有 HTML 就给原始 HTML(前端 iframe 渲染排版)
                    "is_html": bool(body_html),
                    "time": time_iso,
                    "received_at": internaldate_iso,
                    "received_time_trusted": bool(internaldate_iso),
                    "received_at_source": "imap_INTERNALDATE",
                    "identity_scheme": identity_scheme,
                    "identity_version": identity_version,
                    "folder": self.mailbox,
                })
            received_values = [
                str(row.get("received_at") or "")
                for row in out
                if row.get("received_at")
            ]
            self._last_list_recent_metadata["folder_coverage"] = {
                str(self.mailbox): {
                    "complete": len(uids_sorted) >= len(uids),
                    "oldest_received_at": min(received_values)
                    if received_values
                    else "",
                }
            }
            return out
        finally:
            try:
                M.close()
            except Exception:
                pass
            try:
                M.logout()
            except Exception:
                pass

    def list_recent_batch(self, last_uid: int = 0, max_fetch: int = 300) -> tuple:
        """一次连接, 增量拉取 QQ 收件箱新邮件(UID>last_uid), 解析每封的收件别名。

        供 iCloud 批量监控: 一个 QQ 箱一轮只连一次、只取新增, 本地按别名分发给各账号。
        返回 (messages, max_uid); message 含 {id(uid), recipients:[...], from, subject,
        preview, body, is_html, time}。
        """
        import email as email_pkg
        import re as _re
        from datetime import timezone as _tz
        from email.utils import parsedate_to_datetime

        out: list = []
        max_uid = int(last_uid or 0)
        try:
            M = self._connect()
        except Exception as exc:
            raise RuntimeError(f"QQMail IMAP 连接失败: {exc}")
        try:
            self._select(M, readonly=True)
            if last_uid and int(last_uid) > 0:
                typ, data = M.uid("SEARCH", None, f"UID {int(last_uid) + 1}:*")
            else:
                typ, data = M.uid("SEARCH", None, "ALL")
            if typ != "OK" or not data or not data[0]:
                return [], max_uid
            uids = [u for u in data[0].split()]
            # UID {n}:* 在无新邮件时会回退返回最后一封, 过滤掉 <= last_uid 的
            uids = [u for u in uids if int(u) > int(last_uid or 0)]
            uids.sort(key=lambda x: int(x))
            uids = uids[-int(max_fetch):]  # 保护: 首次/大量时只取最近 max_fetch 封
            for uid in uids:
                iu = int(uid)
                if iu > max_uid:
                    max_uid = iu
                typ, d = M.uid("FETCH", uid, "(BODY.PEEK[])")
                if typ != "OK" or not d:
                    continue
                raw = b""
                for item in d:
                    if isinstance(item, tuple) and len(item) >= 2:
                        raw = item[1]; break
                if not raw:
                    continue
                msg = email_pkg.message_from_bytes(raw)
                # 收件别名: To / Delivered-To / X-Original-To / X-ICLOUD-HME 里抽 email
                hdr_blob = " ".join(str(msg.get(h) or "") for h in
                                    ("To", "Delivered-To", "X-Original-To", "X-ICLOUD-HME", "Cc"))
                recipients = [e.lower() for e in _re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+", hdr_blob)]
                body_text = self._extract_body_text(msg) or ""
                body_html = self._extract_body_html(msg) or ""
                try:
                    dt = parsedate_to_datetime(msg.get("Date", "") or "")
                    time_iso = dt.astimezone(_tz.utc).isoformat() if dt else ""
                except Exception:
                    time_iso = ""
                out.append({
                    "id": uid.decode() if isinstance(uid, bytes) else str(uid),
                    "recipients": list(dict.fromkeys(recipients)),
                    "from": self._decode_header(msg.get("From", "")),
                    "subject": self._decode_header(msg.get("Subject", "")),
                    "preview": body_text[:300],          # 预览用纯文本
                    "body": body_html or body_text,      # 有 HTML 给原始 HTML
                    "is_html": bool(body_html),
                    "time": time_iso,
                    "folder": self.mailbox,
                })
            return out, max_uid
        finally:
            try:
                M.close()
            except Exception:
                pass
            try:
                M.logout()
            except Exception:
                pass
