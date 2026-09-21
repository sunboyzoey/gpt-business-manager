"""Read-only Gmail web-login verification using an exclusively owned profile.

Credentials stay in memory.  This verifier neither changes recovery/security
settings nor sends mail, and a Google sign-in redirect alone is not success.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import os
import re
import struct
import time
from urllib.parse import urlsplit

from core.browser_startup import BrowserInitializationError, start_local_browser


_OVERALL_SECONDS = 145
_GMAIL_URL = "https://mail.google.com/mail/u/0/"
_PASSKEY_ENROLLMENT_PATH = "/v3/signin/speedbump/passkeyenrollment"
_OPTIONAL_SKIP_LABEL = re.compile(r"^(?:Not now|Skip|以后再说|暂不|稍后再说|跳过|暫不|稍後再說|略過)$", re.IGNORECASE)
_OPTIONAL_PAGE_SECONDS = 8
_MESSAGES = {
    "verified": "已通过 Google 登录验证，并成功打开 Gmail 收件箱",
    "invalid_credentials": "登录资料不完整或格式无效，未开始验证",
    "invalid_proxy": "邮箱代理配置无效，未开始验证",
    "invalid_email": "Google 未找到该账号，或账号地址无效",
    "invalid_password": "Google 拒绝了登录密码，请更新密码后重新验证",
    "password_changed": "Google 提示登录密码已更改，当前密码无法登录",
    "totp_required": "Google 要求 Authenticator 验证，但未提供有效的 2FA 密钥",
    "totp_rejected": "Google 拒绝了 Authenticator 验证码，未通过可用性验证",
    "recovery_rejected": "Google 拒绝了辅助邮箱验证，未通过可用性验证",
    "captcha_required": "Google 要求人机验证，暂未通过可用性验证",
    "device_verification_required": "Google 要求手机、短信或设备确认，暂未通过可用性验证",
    "account_disabled": "Google 提示账号已停用，无法使用 Gmail",
    "unsafe_browser": "Google 拒绝当前浏览器登录，暂未通过可用性验证",
    "unexpected_page": "登录跳转到未支持的页面，已停止填写登录资料",
    "gmail_not_ready": "Google 登录尚未打开可用的 Gmail 收件箱，验证超时",
    "network_timeout": "Google 登录页面连接超时，暂未通过可用性验证",
    "navigation_error": "Google 登录页面跳转未完成，暂未通过可用性验证",
    "browser_closed": "验证浏览器意外关闭，暂未通过可用性验证",
    "browser_init_failed": "验证浏览器启动失败，请稍后重新验证",
    "browser_cleanup_failed": "验证浏览器资源清理未完成，本次未确认可用",
    "verification_failed": "Gmail 可用性验证未完成，请稍后重新验证",
    "cancelled": "已取消本次 Gmail 可用性验证",
}


class _Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _result(code, diagnostic=""):
    result = {"ok": code == "verified", "code": code,
              "message": _MESSAGES[code], "method": "web",
              "checked_at": datetime.now(timezone.utc).isoformat()}
    if diagnostic:
        result["diagnostic"] = diagnostic
    return result


def _exception_category(exc):
    """Inspect known browser markers locally; return only a fixed safe category."""
    description = str(exc).lower()
    if any(marker in description for marker in (
            "execution context was destroyed", "cannot find context with specified id",
            "cannot find execution context", "frame was detached", "frame has been detached")):
        return "navigation_in_progress"
    if any(marker in description for marker in (
            "target page, context or browser has been closed", "browser has been closed",
            "target closed", "page has been closed")):
        return "browser_closed"
    if type(exc).__name__ == "TimeoutError":
        return "timeout"
    # Never include a dynamically generated type name or raw exception message.
    return {"TypeError": "type_error", "AttributeError": "attribute_error",
            "RuntimeError": "runtime_error", "ValueError": "value_error",
            "Error": "browser_error"}.get(type(exc).__name__, "unknown_error")


def _progress(callback, step, message):
    if callable(callback):
        try:
            callback(step, message)
        except Exception:
            pass


def _check_cancel(should_stop, deadline):
    if callable(should_stop) and should_stop():
        raise _Failure("cancelled")
    if time.monotonic() >= deadline:
        raise _Failure("gmail_not_ready")


def _timeout_ms(deadline, maximum=10000):
    return max(1, min(maximum, int((deadline - time.monotonic()) * 1000)))


def _totp(secret, at=None):
    secret = re.sub(r"\s+", "", str(secret or "")).upper().rstrip("=")
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        if not key:
            raise ValueError
        digest = hmac.new(key, struct.pack(">Q", int(time.time() if at is None else at) // 30),
                          hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return f"{value % 1000000:06d}"
    except (ValueError, TypeError, base64.binascii.Error):
        raise _Failure("totp_required") from None


def _fresh_totp_window(secret, should_stop, deadline, used_windows=None):
    # Leave time for browser input and the request. Waiting is cancellable and
    # does not submit/retry an old code against Google.
    while True:
        _check_cancel(should_stop, deadline)
        now = time.time()
        remaining = 30 - now % 30
        window = int(now) // 30
        if remaining >= 15 and (used_windows is None or window not in used_windows):
            return _totp(secret, at=now), window
        time.sleep(min(0.25, remaining))


def _fresh_totp(secret, should_stop, deadline):
    return _fresh_totp_window(secret, should_stop, deadline)[0]


def _submit_totp(page, secret, progress, should_stop, deadline, *, step="totp",
                 message="正在验证 Authenticator 2FA", used_windows=None):
    """Prepare controls before generating, then submit exactly once.

    Filling an expired, not-yet-submitted value may be repeated. The real click
    is outside that loop, so a timeout or navigation can never resubmit a code.
    """
    _check_cancel(should_stop, deadline)
    # Persistence/progress callbacks can be slow. Run them before generating
    # the time-sensitive value rather than consuming its validity window.
    _progress(progress, step, message)

    def check_origin():
        parsed = urlsplit(page.url)
        if (parsed.scheme != "https" or parsed.hostname != "accounts.google.com"
                or parsed.username or parsed.password or parsed.port not in {None, 443}):
            raise _Failure("unexpected_page")

    check_origin()
    control = page.locator(':is(#totpPin,input[name="totpPin"]):visible').first
    button = page.locator(':is(#totpNext):visible').first
    control.wait_for(state="visible", timeout=_timeout_ms(deadline))
    button.wait_for(state="visible", timeout=_timeout_ms(deadline))
    while not control.is_editable() or not button.is_enabled():
        _check_cancel(should_stop, deadline)
        check_origin()
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    # Playwright trial checks visibility, stability and event interception but
    # does not click; no credential is generated until these waits finish.
    button.click(trial=True, timeout=_timeout_ms(deadline))
    while True:
        _check_cancel(should_stop, deadline)
        check_origin()
        value, window = _fresh_totp_window(secret, should_stop, deadline, used_windows)
        control.fill(value, timeout=_timeout_ms(deadline))
        _check_cancel(should_stop, deadline)
        check_origin()
        now = time.time()
        if int(now) // 30 == window and 30 - now % 30 >= 5:
            break
        # Only the local input was filled. Wait for a fresh code if browser
        # work crossed the window or consumed nearly all of its remaining time.
    if used_windows is not None:
        # A click can reach Google even when the browser disconnects before its
        # acknowledgement. Record the window at the mutation boundary, once.
        used_windows.add(window)
    button.click(timeout=_timeout_ms(deadline, 3000))


def _validate(email, password, proxy_url):
    if not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9]+)*@gmail\.com", email) or not password:
        raise _Failure("invalid_credentials")
    if not proxy_url:
        return
    try:
        parsed = urlsplit(proxy_url)
        if (parsed.scheme not in {"http", "socks5", "socks5h"} or not parsed.hostname
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or re.search(r"\s", proxy_url)):
            raise ValueError
    except (ValueError, TypeError):
        raise _Failure("invalid_proxy") from None


def _start_browser(proxy_url, deadline):
    from DrissionPage import ChromiumOptions

    def options():
        value = ChromiumOptions(read_file=False)
        value.headless(os.getenv("GMAIL_VERIFY_HEADLESS", "1").lower() in {"1", "true", "yes"})
        value.set_argument("--no-first-run")
        value.set_argument("--no-default-browser-check")
        value.set_argument("--lang=en-US")
        value.set_argument("--window-size=1280,900")
        if proxy_url:
            value.set_proxy(proxy_url.replace("socks5h://", "socks5://", 1))
        return value

    return start_local_browser(options, max_attempts=1,
                               timeout=min(25, max(0.1, deadline - time.monotonic())))


def _start_playwright():
    from playwright.sync_api import sync_playwright
    return sync_playwright().start()


# Return only fixed state flags.  Page text, email contents and cookies are never
# returned to Python, persisted, logged, or included in progress/error messages.
_OBSERVE_JS = r"""() => {
  const visible = el => !!el && !!(el.getClientRects().length) &&
    getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
  const find = selector => Array.from(document.querySelectorAll(selector)).find(visible);
  const hasText = (selector, rx) => Array.from(document.querySelectorAll(selector))
    .some(el => visible(el) && rx.test((el.innerText || el.getAttribute('aria-label') || '').trim()));
  const state = {};
  if (location.hostname === 'mail.google.com') {
    state.main = !!find('[role="main"]');
    state.compose = hasText('[role="button"],button', /^(compose|撰写|写邮件|撰寫)$/i);
    state.inbox = !!find('a[href$="#inbox"]') ||
      hasText('[role="navigation"] [role="link"],[role="navigation"] a', /^(inbox|收件箱|收件匣)(\s|$)/i);
    return state;
  }
  if (location.hostname !== 'accounts.google.com') return state;
  const text = (document.body && document.body.innerText) || '';
  const email = find('#identifierId,input[name="identifier"]');
  const password = find('input[name="Passwd"],input[type="password"]');
  const totp = find('#totpPin,input[name="totpPin"]');
  const recovery = find('input[name="knowledgePreregisteredEmailResponse"],#knowledge-preregistered-email-response');
  state.email = !!email;
  state.password = !!password;
  state.totp = !!totp;
  state.recovery = !!recovery;
  state.email_invalid = !!email && email.getAttribute('aria-invalid') === 'true';
  state.password_invalid = !!password && password.getAttribute('aria-invalid') === 'true';
  state.totp_invalid = !!totp && totp.getAttribute('aria-invalid') === 'true';
  state.recovery_invalid = !!recovery && recovery.getAttribute('aria-invalid') === 'true';
  state.password_changed = /password was changed|密码.{0,12}(已更改|已修改|更改了|修改了)|密碼.{0,12}(已變更|已修改)/i.test(text);
  state.wrong_password = /wrong password|incorrect password|密码错误|密码不正确|密碼錯誤/i.test(text);
  state.unknown_account = /couldn.t find your google account|找不到您的 Google (帐户|账号|帐号)|無法找到你的 Google 帳戶/i.test(text);
  state.disabled = /account (has been |is )disabled|账号已停用|帐户已停用|帳戶已停用|帳戶遭到停用/i.test(text);
  state.unsafe_browser = /browser or app may not be secure|couldn.t sign you in|浏览器或应用可能不安全|瀏覽器或應用程式可能不安全/i.test(text);
  state.captcha = !!find('iframe[src*="recaptcha"],input[name="ca"],#captchaimg') ||
    /verify (that )?you.re not a robot|confirm you.re not a robot|证明您不是机器人|验证您不是机器人|證明你不是機器人/i.test(text);
  state.device = !!find('#idvPin,input[name="idvPin"]') ||
    (!totp && !!find('input[type="tel"]')) ||
    /check your (phone|device)|tap yes on|sent a notification|查看您的手机|查看你的手机|向您的手机发送|輕觸.*是/i.test(text);
  state.authenticator_choice = !!find('[data-challengetype="6"]');
  state.recovery_choice = !!find('[data-challengetype="12"]');
  state.optional_skip = location.pathname.replace(/\/$/, '') === '/v3/signin/speedbump/passkeyenrollment' &&
    hasText('button,[role="button"]', /^(Not now|Skip|以后再说|暂不|稍后再说|跳过|暫不|稍後再說|略過)$/i);
  return state;
}"""


def _observe(page):
    parsed = urlsplit(page.url)
    if parsed.scheme != "https" or parsed.hostname not in {
            "accounts.google.com", "mail.google.com", "gds.google.com"}:
        raise _Failure("unexpected_page")
    state = page.evaluate(_OBSERVE_JS)
    if parsed.hostname == "accounts.google.com" and "/challenge/recaptcha" in parsed.path:
        state["captcha"] = True
    return parsed.hostname, parsed.path, state


def _failure_state(state):
    for flag, code in (
        ("disabled", "account_disabled"), ("password_changed", "password_changed"),
        ("captcha", "captcha_required"), ("unsafe_browser", "unsafe_browser"),
        ("unknown_account", "invalid_email"), ("email_invalid", "invalid_email"),
        ("wrong_password", "invalid_password"), ("password_invalid", "invalid_password"),
        ("totp_invalid", "totp_rejected"), ("recovery_invalid", "recovery_rejected"),
    ):
        if state.get(flag):
            return code
    return None


def _fill_submit(page, selector, value, next_selector, deadline):
    # Recheck the origin immediately before sending any credential.
    parsed = urlsplit(page.url)
    if parsed.scheme != "https" or parsed.hostname != "accounts.google.com":
        raise _Failure("unexpected_page")
    control = page.locator(f":is({selector}):visible").first
    control.fill(value, timeout=_timeout_ms(deadline))
    button = page.locator(f":is({next_selector}):visible").first if next_selector else None
    if button is not None and button.count():
        button.click(timeout=_timeout_ms(deadline))
    else:
        control.press("Enter", timeout=_timeout_ms(deadline))


def _navigate(page, url, deadline):
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=_timeout_ms(deadline, 20000))
    except PlaywrightTimeoutError:
        # A partially loaded Google page may still be usable; the state loop
        # checks its exact origin and visible controls before doing anything.
        pass


def _skip_optional_passkey(page, deadline):
    # Only decline a known, optional enrollment offer.  Never follow a generic
    # Continue/Create/Agree button or mutate the account's security settings.
    parsed = urlsplit(page.url)
    if (parsed.scheme != "https" or parsed.hostname != "accounts.google.com"
            or parsed.path.rstrip("/") != _PASSKEY_ENROLLMENT_PATH):
        raise _Failure("unexpected_page")
    # Role locators exclude hidden elements by default (supported since the
    # project's oldest Playwright version); clicking also requires visibility.
    page.get_by_role("button", name=_OPTIONAL_SKIP_LABEL).first.click(
        timeout=_timeout_ms(deadline, 5000))


def _run_login(page, email, password, recovery_email, secret, progress, should_stop, deadline, used_windows=None):
    if used_windows is None:
        used_windows = set()
    _check_cancel(should_stop, deadline)
    _navigate(page, _GMAIL_URL, deadline)
    submitted = set()
    recovery_redirected = False
    optional_until = None
    while True:
        _check_cancel(should_stop, deadline)
        try:
            host, path, state = _observe(page)
        except Exception as exc:
            if _exception_category(exc) != "navigation_in_progress":
                raise
            # Read-only DOM evaluation commonly races the successful TOTP
            # redirect. Reobserve within the same deadline, preserving the
            # submitted-step set; never fill or submit a credential again.
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            continue
        if host == "mail.google.com" and all(state.get(key) for key in ("main", "compose", "inbox")):
            _progress(progress, "inbox", "已确认 Gmail 收件箱可用")
            return "verified"
        failure = _failure_state(state)
        if failure:
            raise _Failure(failure)
        if host == "accounts.google.com" and "/speedbump/" in path:
            if path.rstrip("/") != _PASSKEY_ENROLLMENT_PATH:
                raise _Failure("unexpected_page")
            if optional_until is None:
                optional_until = time.monotonic() + _OPTIONAL_PAGE_SECONDS
            if state.get("optional_skip") and "passkey_skip" not in submitted:
                _progress(progress, "inbox", "正在跳过可选的通行密钥设置，继续打开 Gmail")
                _skip_optional_passkey(page, deadline)
                submitted.add("passkey_skip")
                optional_until = time.monotonic() + _OPTIONAL_PAGE_SECONDS
            elif time.monotonic() >= optional_until:
                raise _Failure("unexpected_page")
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            continue
        if host == "gds.google.com":
            if not path.startswith("/web/recoveryoptions") or recovery_redirected:
                raise _Failure("unexpected_page")
            recovery_redirected = True
            _progress(progress, "inbox", "登录已通过，正在直接打开 Gmail 收件箱")
            _navigate(page, _GMAIL_URL, deadline)
            continue
        action = None
        if state.get("email") and "email" not in submitted:
            action = ("email", "正在验证 Google 账号", '#identifierId,input[name="identifier"]', email, "#identifierNext")
        elif state.get("password") and "password" not in submitted:
            action = ("password", "正在验证登录密码", 'input[name="Passwd"],input[type="password"]', password, "#passwordNext")
        elif state.get("totp") and "totp" not in submitted:
            submitted.add("totp")
            _submit_totp(page, secret, progress, should_stop, deadline, used_windows=used_windows)
        elif state.get("recovery") and "recovery" not in submitted and recovery_email:
            action = ("recovery", "正在确认已配置的辅助邮箱", 'input[name="knowledgePreregisteredEmailResponse"],#knowledge-preregistered-email-response', recovery_email, "")
        elif state.get("authenticator_choice") and "authenticator_choice" not in submitted and secret:
            page.locator('[data-challengetype="6"]:visible').first.click(timeout=_timeout_ms(deadline))
            submitted.add("authenticator_choice")
        elif state.get("recovery_choice") and "recovery_choice" not in submitted and recovery_email:
            page.locator('[data-challengetype="12"]:visible').first.click(timeout=_timeout_ms(deadline))
            submitted.add("recovery_choice")
        elif not state.get("totp") and (state.get("device") or (host == "accounts.google.com" and any(
                part in path for part in ("/challenge/dp", "/challenge/ipp", "/challenge/iap", "/challenge/idv")))):
            raise _Failure("device_verification_required")
        if action:
            step, message, selector, value, next_selector = action
            _progress(progress, step, message)
            _fill_submit(page, selector, value, next_selector, deadline)
            submitted.add(step)
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def verify_login(email, login_password, recovery_email, totp_secret, proxy_url="", progress=None, should_stop=None):
    """Return a credential-free result; never mark a mere login redirect usable."""
    native = playwright = None
    code = "verification_failed"
    diagnostic = ""
    deadline = time.monotonic() + _OVERALL_SECONDS
    try:
        email = str(email or "").strip().lower()
        proxy_url = str(proxy_url or "").strip()
        _validate(email, login_password, proxy_url)
        _check_cancel(should_stop, deadline)
        _progress(progress, "browser", "正在启动独立浏览器验证 Gmail 可用性")
        native = _start_browser(proxy_url, deadline)
        _check_cancel(should_stop, deadline)
        playwright = _start_playwright()
        browser = playwright.chromium.connect_over_cdp(
            f"http://{native.address}", timeout=_timeout_ms(deadline, 15000))
        _check_cancel(should_stop, deadline)
        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.pages[0] if context.pages else context.new_page()
        page.set_default_timeout(10000)
        code = _run_login(page, email, login_password, recovery_email, totp_secret,
                          progress, should_stop, deadline)
    except _Failure as exc:
        code = exc.code
    except BrowserInitializationError:
        code = "browser_init_failed"
    except Exception as exc:
        # Known exception markers are inspected only locally. The response
        # contains fixed categories, never messages, selectors or page values.
        diagnostic = _exception_category(exc)
        code = {"timeout": "network_timeout", "navigation_in_progress": "navigation_error",
                "browser_closed": "browser_closed"}.get(diagnostic, "verification_failed")
    finally:
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass
        if native is not None:
            try:
                if native.quit() is False:
                    code = "browser_cleanup_failed"
            except Exception:
                code = "browser_cleanup_failed"
    result = _result(code, diagnostic)
    _progress(progress, "completed" if result["ok"] else "failed", result["message"])
    return result
