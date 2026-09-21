"""Grok (x.ai) 平台插件"""

from datetime import datetime, timezone
from typing import Callable, Optional

from core.base_platform import BasePlatform, Account, AccountStatus, RegisterConfig
from core.base_mailbox import BaseMailbox
from core.registry import register


DEFAULT_PAYMENT_PROXY_NODE = "🇯🇵 日本A11 | IEPL"


def _resolve_payment_proxy(
    extra: dict | None,
    *,
    fallback_proxy: Optional[str] = None,
    log_fn: Callable[[str], None] | None = None,
) -> tuple[Optional[str], str]:
    """Resolve the preferred proxy for Grok payment-link requests."""
    from core.config_store import config_store
    from core.proxy_utils import normalize_proxy_url

    values = extra or {}
    preferred_proxy = str(
        values.get("grok_payment_proxy")
        or config_store.get("grok_payment_proxy", "")
        or ""
    ).strip()
    if preferred_proxy:
        proxy = normalize_proxy_url(preferred_proxy)
        if proxy:
            return proxy, "优先支付代理"

    preferred_node = str(
        values.get("grok_payment_proxy_node")
        or config_store.get("grok_payment_proxy_node", "")
        or DEFAULT_PAYMENT_PROXY_NODE
    ).strip()
    if preferred_node:
        try:
            from services.proxy_pool import resolve_node_proxy

            node_proxy = resolve_node_proxy(preferred_node)
            proxy = normalize_proxy_url((node_proxy or {}).get("addr"))
            if proxy:
                return proxy, f"优先支付节点: {(node_proxy or {}).get('name') or preferred_node}"
            if log_fn:
                log_fn(f"[Payment] 优先支付节点不可用，回退当前代理: {preferred_node}")
        except Exception as exc:
            if log_fn:
                log_fn(f"[Payment] 解析优先支付节点失败，回退当前代理: {exc}")

    proxy = normalize_proxy_url(fallback_proxy)
    return proxy, "当前注册代理" if proxy else ""


def _parse_positive_int(value, default: int) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        parsed = default
    return max(1, parsed)


def _parse_bool_text(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _build_refresh_patch(result: dict, refreshed_at: str) -> dict:
    subscription = result.get("sso_subscription")
    if not isinstance(subscription, dict):
        subscription = {}
    account_type = str(
        result.get("sso_account_type")
        or subscription.get("account_type")
        or "unknown"
    )
    account_type_label = str(
        result.get("sso_account_type_label")
        or subscription.get("account_type_label")
        or "未知"
    )
    return {
        "sso": result.get("sso", ""),
        "sso_rw": result.get("sso_rw", ""),
        "cookies": result.get("cookies", {}),
        "cookie_file": result.get("cookie_file", ""),
        "sso_refreshed_at": refreshed_at,
        "sso_source": "login_refresh",
        "sso_account_type": account_type,
        "sso_account_type_label": account_type_label,
        "sso_subscription": subscription,
    }


@register
class GrokPlatform(BasePlatform):
    name = "grok"
    display_name = "Grok"
    version = "1.0.0"

    # Grok 支持纯协议和浏览器模式
    supported_executors: list = ["protocol", "headless"]

    def __init__(
        self,
        config: Optional[RegisterConfig] = None,
        mailbox: Optional[BaseMailbox] = None,
    ):
        super().__init__(config or RegisterConfig())
        self.mailbox = mailbox

    def register(self, email: str, password: Optional[str] = None) -> Account:
        executor = getattr(self.config, "executor_type", "protocol") or "protocol"
        if executor in ("headless", "headed"):
            return self._register_drission(email, password, headless=(executor == "headless"))
        return self._register_protocol(email, password)

    def _should_skip_payment_link(self) -> bool:
        extra = self.config.extra or {}
        if _parse_bool_text(extra.get("grok_skip_payment_link"), default=False):
            return True
        return str(extra.get("_sync_device_type") or "").strip().lower() == "grok2api"

    def _register_drission(self, email: str, password: Optional[str], headless: bool) -> Account:
        from platforms.grok.drission_register import GrokDrissionRegister
        from core.config_store import config_store

        log = getattr(self, "_log_fn", print)
        yescaptcha_key = self.config.extra.get("yescaptcha_key") or config_store.get("yescaptcha_key", "")
        reg = GrokDrissionRegister(
            proxy=self.config.proxy,
            log_fn=log,
            headless=headless,
            captcha_solver=self.config.captcha_solver,
            yescaptcha_key=yescaptcha_key,
            solver_url=self.config.extra.get("solver_url"),
        )
        mailbox_attempts = (
            1 if email else int(self.config.extra.get("grok_mailbox_attempts", 8))
        )
        otp_timeout = self.get_mailbox_otp_timeout()
        last_error = None

        for attempt in range(1, mailbox_attempts + 1):
            mail_acct = None
            current_email = email
            if self.mailbox and not current_email:
                mail_acct = self.mailbox.get_email()
                current_email = mail_acct.email if mail_acct else None
            log(f"邮箱: {current_email}")
            before_ids = (
                self.mailbox.get_current_ids(mail_acct)
                if (self.mailbox and mail_acct)
                else set()
            )

            def otp_cb():
                log("等待验证码...")
                if not self.mailbox or not mail_acct:
                    return ""
                code = self.mailbox.wait_for_code(
                    mail_acct,
                    keyword="",
                    timeout=otp_timeout,
                    before_ids=before_ids,
                    code_pattern=r"[A-Z0-9]{3}-[A-Z0-9]{3}",
                )
                if code:
                    code = code.replace("-", "").replace(" ", "")
                    log(f"验证码: {code}")
                return code

            try:
                if not current_email:
                    raise RuntimeError("未获取到可用邮箱")
                result = reg.register(
                    email=current_email,
                    password=password,
                    otp_callback=otp_cb if self.mailbox else None,
                )
                break
            except Exception as e:
                last_error = e
                msg = str(e)
                if attempt < mailbox_attempts and "邮箱域名被拒绝" in msg:
                    log(f"Grok 邮箱域名被拒绝，切换新邮箱重试 {attempt + 1}/{mailbox_attempts}")
                    continue
                raise
        else:
            raise last_error if last_error else RuntimeError("Grok 注册失败")

        payment_link = ""
        if self._should_skip_payment_link():
            log("[Payment] 设备同步任务，跳过支付链接获取")
        elif result.get("sso"):
            try:
                from platforms.grok.protocol import GrokProtocolRegister

                payment_proxy, payment_proxy_label = _resolve_payment_proxy(
                    self.config.extra,
                    fallback_proxy=self.config.proxy,
                    log_fn=log,
                )
                pay_reg = GrokProtocolRegister(
                    proxy=self.config.proxy,
                    payment_proxy=payment_proxy,
                    payment_proxy_label=payment_proxy_label,
                    log_fn=log,
                )
                payment_link = pay_reg.get_payment_link(
                    result["email"],
                    result["sso"],
                    result.get("sso_rw", ""),
                )
            except Exception as e:
                log(f"[Payment] 获取支付链接失败: {e}")
        result["cashier_url"] = payment_link

        return Account(
            platform="grok",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra={
                "sso": result["sso"],
                "sso_rw": result.get("sso_rw", ""),
                "cookies": result.get("cookies", {}),
                "cookie_file": result.get("cookie_file", ""),
                "given_name": result["given_name"],
                "family_name": result["family_name"],
                "cashier_url": result.get("cashier_url", ""),
                "register_mode": "drission",
            },
        )

    def _register_protocol(self, email: str, password: Optional[str] = None) -> Account:
        from platforms.grok.protocol import GrokProtocolRegister
        from core.config_store import config_store

        log = getattr(self, "_log_fn", print)
        yescaptcha_key = self.config.extra.get("yescaptcha_key") or config_store.get(
            "yescaptcha_key", ""
        )
        skip_payment_link = self._should_skip_payment_link()
        payment_proxy = None
        payment_proxy_label = ""
        if not skip_payment_link:
            payment_proxy, payment_proxy_label = _resolve_payment_proxy(
                self.config.extra,
                fallback_proxy=self.config.proxy,
                log_fn=log,
            )

        reg = GrokProtocolRegister(
            proxy=self.config.proxy,
            payment_proxy=payment_proxy,
            payment_proxy_label=payment_proxy_label,
            log_fn=log,
            yescaptcha_key=yescaptcha_key,
            captcha_solver=self.config.captcha_solver,
            solver_url=self.config.extra.get("solver_url"),
            cookie_dir=self.config.extra.get("grok_cookie_json_dir", "cookies/grok"),
        )
        mailbox_attempts = (
            1 if email else int(self.config.extra.get("grok_mailbox_attempts", 8))
        )
        otp_timeout = self.get_mailbox_otp_timeout()
        last_error = None

        for attempt in range(1, mailbox_attempts + 1):
            mail_acct = None
            current_email = email
            if self.mailbox and not current_email:
                mail_acct = self.mailbox.get_email()
                current_email = mail_acct.email if mail_acct else None
            log(f"邮箱: {current_email}")
            before_ids = (
                self.mailbox.get_current_ids(mail_acct)
                if (self.mailbox and mail_acct)
                else set()
            )

            def otp_cb():
                log("等待验证码...")
                if not self.mailbox or not mail_acct:
                    return ""
                code = self.mailbox.wait_for_code(
                    mail_acct,
                    keyword="",
                    timeout=otp_timeout,
                    before_ids=before_ids,
                    code_pattern=r"[A-Z0-9]{3}-[A-Z0-9]{3}",
                )
                if code:
                    code = code.replace("-", "").replace(" ", "")
                    log(f"验证码: {code}")
                return code

            try:
                if not current_email:
                    raise RuntimeError("未获取到可用邮箱")
                result = reg.register(
                    email=current_email,
                    password=password,
                    otp_callback=otp_cb if self.mailbox else None,
                    skip_payment_link=skip_payment_link,
                )
                break
            except Exception as e:
                last_error = e
                msg = str(e)
                if attempt < mailbox_attempts and "邮箱域名被拒绝" in msg:
                    log(
                        f"Grok 邮箱域名被拒绝，切换新邮箱重试 {attempt + 1}/{mailbox_attempts}"
                    )
                    continue
                raise
        else:
            raise last_error if last_error else RuntimeError("Grok 注册失败")

        return Account(
            platform="grok",
            email=result["email"],
            password=result["password"],
            status=AccountStatus.REGISTERED,
            extra={
                "sso": result["sso"],
                "sso_rw": result["sso_rw"],
                "cookies": result.get("cookies", {}),
                "cookie_file": result.get("cookie_file", ""),
                "given_name": result["given_name"],
                "family_name": result["family_name"],
                "cashier_url": result.get("cashier_url", ""),
            },
        )

    def check_valid(self, account: Account) -> bool:
        return bool((account.extra or {}).get("sso"))

    def get_platform_actions(self) -> list:
        return [
            {"id": "upload_grok2api", "label": "导入 grok2api", "params": []},
            {"id": "payment_link", "label": "获取支付链接", "params": []},
            {"id": "refresh_cookies", "label": "重新登录获取 Cookie", "params": []},
        ]

    def execute_action(self, action_id: str, account: Account, params: dict) -> dict:
        config_values = getattr(self.config, "extra", {}) if self.config else {}
        proxy = self.config.proxy if self.config else None
        if not proxy:
            from core.config_store import config_store
            proxy = config_store.get("default_proxy", "") or "http://127.0.0.1:7890"

        if action_id == "upload_grok2api":
            from platforms.grok.grok2api_upload import resolve_grok2api_pool, upload_to_grok2api
            from core.config_store import config_store
            from platforms.grok.protocol import GrokProtocolRegister

            pool_name = resolve_grok2api_pool(account)
            status_value = str(getattr(account.status, "value", account.status) or "").strip()
            if status_value != "completed":
                return {
                    "ok": False,
                    "error": "只有已完成状态的 Grok 账号才能同步到 Grok2API",
                    "data": {"message": "只有已完成状态的 Grok 账号才能同步到 Grok2API", "grok2api_pool": pool_name},
                }
            if not account.password:
                return {"ok": False, "error": "缺少账号密码，无法刷新 SSO 后同步到 Grok2API"}

            max_attempts = _parse_positive_int(params.get("max_attempts", 2), 2)
            captcha_solver = str(
                config_values.get("default_captcha_solver")
                or config_values.get("captcha_solver")
                or getattr(self.config, "captcha_solver", "yescaptcha")
                or "yescaptcha"
            )
            yescaptcha_key = str(
                config_values.get("yescaptcha_key") or config_store.get("yescaptcha_key", "") or ""
            )
            reg = GrokProtocolRegister(
                proxy=proxy,
                log_fn=getattr(self, "_log_fn", print),
                yescaptcha_key=yescaptcha_key,
                captcha_solver=captcha_solver,
                solver_url=config_values.get("solver_url"),
                cookie_dir=config_values.get("grok_cookie_json_dir", "cookies/grok"),
            )
            refreshed_at = datetime.now(timezone.utc).isoformat()
            refresh_result = reg.login_and_save_cookies(
                account.email,
                account.password,
                max_attempts=max_attempts,
            )
            refresh_patch = _build_refresh_patch(refresh_result, refreshed_at)
            account.extra = {**(account.extra or {}), **refresh_patch}
            subscription = refresh_patch.get("sso_subscription") if isinstance(refresh_patch.get("sso_subscription"), dict) else {}
            if not subscription.get("subscription_active"):
                failed_at = datetime.now(timezone.utc).isoformat()
                sync_patch = {
                    "status": "failed",
                    "status_label": "同步失败",
                    "client_id": "grok-ui",
                    "remote_id": "",
                    "note": f"刷新后 SSO 不是付费账号：{refresh_patch.get('sso_account_type_label', '未知')}",
                    "updated_at": failed_at,
                    "pool": pool_name,
                    "sso_refreshed_at": refreshed_at,
                    "sso_account_type": refresh_patch.get("sso_account_type", "unknown"),
                    "sso_account_type_label": refresh_patch.get("sso_account_type_label", "未知"),
                }
                msg = (
                    f"刷新后 SSO 不是付费账号：{refresh_patch.get('sso_account_type_label', '未知')}，"
                    "未同步到 Grok2API"
                )
                return {
                    "ok": False,
                    "error": msg,
                    "data": {
                        "message": msg,
                        "grok2api_pool": pool_name,
                        "sso_account_type": refresh_patch.get("sso_account_type"),
                        "sso_account_type_label": refresh_patch.get("sso_account_type_label"),
                    },
                    "account_extra_patch": {**refresh_patch, "grok_sync": sync_patch},
                }
            ok, msg = upload_to_grok2api(account)
            if not ok:
                return {
                    "ok": False,
                    "error": msg,
                    "data": {
                        "message": msg,
                        "grok2api_pool": pool_name,
                        "sso_account_type": refresh_patch.get("sso_account_type"),
                        "sso_account_type_label": refresh_patch.get("sso_account_type_label"),
                    },
                    "account_extra_patch": refresh_patch,
                }

            synced_at = datetime.now(timezone.utc).isoformat()
            sync_patch = {
                "status": "synced",
                "status_label": "已同步",
                "client_id": "grok-ui",
                "remote_id": "",
                "note": msg,
                "synced_at": synced_at,
                "updated_at": synced_at,
                "pool": pool_name,
                "sso_refreshed_at": refreshed_at,
                "sso_account_type": refresh_patch.get("sso_account_type", "unknown"),
                "sso_account_type_label": refresh_patch.get("sso_account_type_label", "未知"),
            }
            return {
                "ok": True,
                "data": {
                    "message": f"{msg}，SSO={refresh_patch.get('sso_account_type_label', '未知')}",
                    "grok2api_pool": pool_name,
                    "sync": sync_patch,
                    "sso_account_type": refresh_patch.get("sso_account_type"),
                    "sso_account_type_label": refresh_patch.get("sso_account_type_label"),
                },
                "account_extra_patch": {**refresh_patch, "grok_sync": sync_patch},
            }

        if action_id == "refresh_cookies":
            from core.config_store import config_store
            from platforms.grok.protocol import GrokProtocolRegister

            if not account.password:
                return {"ok": False, "error": "缺少账号密码，无法重新登录获取 Cookie"}

            max_attempts = _parse_positive_int(params.get("max_attempts", 2), 2)

            captcha_solver = str(
                config_values.get("default_captcha_solver")
                or config_values.get("captcha_solver")
                or getattr(self.config, "captcha_solver", "yescaptcha")
                or "yescaptcha"
            )
            yescaptcha_key = str(
                config_values.get("yescaptcha_key") or config_store.get("yescaptcha_key", "") or ""
            )
            reg = GrokProtocolRegister(
                proxy=proxy,
                log_fn=getattr(self, "_log_fn", print),
                yescaptcha_key=yescaptcha_key,
                captcha_solver=captcha_solver,
                solver_url=config_values.get("solver_url"),
                cookie_dir=config_values.get("grok_cookie_json_dir", "cookies/grok"),
            )
            result = reg.login_and_save_cookies(
                account.email,
                account.password,
                max_attempts=max_attempts,
            )
            cookie_file = result.get("cookie_file", "")
            cookie_count = int(result.get("cookie_count") or len(result.get("cookies") or {}))
            refreshed_at = datetime.now(timezone.utc).isoformat()
            refresh_patch = _build_refresh_patch(result, refreshed_at)
            return {
                "ok": True,
                "data": {
                    "message": f"Cookie/SSO 已刷新，共 {cookie_count} 个，SSO={refresh_patch.get('sso_account_type_label', '未知')}",
                    "cookie_file": cookie_file,
                    "cookie_count": cookie_count,
                    "sso_account_type": refresh_patch.get("sso_account_type"),
                    "sso_account_type_label": refresh_patch.get("sso_account_type_label"),
                },
                "account_extra_patch": refresh_patch,
            }

        if action_id == "payment_link":
            from platforms.grok.protocol import GrokProtocolRegister

            extra = account.extra or {}
            sso = extra.get("sso", "")
            sso_rw = extra.get("sso_rw", "")
            if not sso:
                return {
                    "ok": False,
                    "error": "缺少 SSO cookie，无法获取支付链接，已清空旧支付链接",
                    "account_extra_patch": {"cashier_url": ""},
                }

            payment_proxy, payment_proxy_label = _resolve_payment_proxy(
                getattr(self.config, "extra", {}) if self.config else {},
                fallback_proxy=proxy,
                log_fn=getattr(self, "_log_fn", print),
            )
            reg = GrokProtocolRegister(
                proxy=proxy,
                payment_proxy=payment_proxy,
                payment_proxy_label=payment_proxy_label,
                log_fn=getattr(self, "_log_fn", print),
            )
            try:
                max_attempts = int(params.get("max_attempts", 5) or 5)
            except (TypeError, ValueError):
                max_attempts = 5
            url = reg.get_payment_link(account.email, sso, sso_rw, max_attempts=max_attempts)
            if url:
                return {
                    "ok": True,
                    "data": {"url": url, "cashier_url": url, "message": f"支付链接已获取"},
                    "account_extra_patch": {"cashier_url": url},
                }
            error = str(getattr(reg, "last_payment_error", "") or "获取支付链接失败").strip()
            message = f"{error}，已清空旧支付链接"
            return {
                "ok": False,
                "error": message,
                "data": {"message": message, "detail": error},
                "account_extra_patch": {"cashier_url": ""},
            }

        raise NotImplementedError(f"未知操作: {action_id}")
