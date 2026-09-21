"""
DrissionPage 浏览器自动化 ChatGPT 注册引擎
参考 Chrome 扩展 10 步流程 + chatgpt_register.py 浏览器启动方式
仅执行注册流程（Step 1-5 + 获取 Session），不含 OAuth 登录
"""

import json
import math
import os
import random
import re
import secrets
import string
import sys
import time
from contextvars import ContextVar
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

from DrissionPage import ChromiumOptions, ChromiumPage

# ── 常量 ──────────────────────────────────────────────────────────
CHATGPT_URL = "https://chatgpt.com/"
AUTH_URLS = {
    "password": "https://auth.openai.com/create-account/password",
    "email_verification": "https://auth.openai.com/email-verification",
    "about_you": "https://auth.openai.com/about-you",
}
WAIT_TIMEOUT = 30
CODE_TIMEOUT = 90
POLL_INTERVAL = 3
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Results_ChatGPT")


# ``register_chatgpt`` may be running for several task threads at once.  A
# process-global callback would mix one account's browser logs into another
# task.  ContextVar keeps the sink scoped to the current execution context and
# also restores an outer caller correctly when registrations are nested.
_REGISTER_LOG_FN: ContextVar[Optional[Callable[[str], None]]] = ContextVar(
    "chatgpt_drission_register_log_fn",
    default=None,
)


@contextmanager
def registration_log_context(log_fn: Optional[Callable[[str], None]]):
    """Scope direct ``do_register`` logs to this task, restoring any outer sink.

    Enter this context in the worker that owns the page.  Context variables
    are task-local; callers starting another thread must enter it there too.
    This context neither opens nor closes the caller's browser page.
    """
    token = _REGISTER_LOG_FN.set(log_fn if callable(log_fn) else None)
    try:
        yield
    finally:
        _REGISTER_LOG_FN.reset(token)


def _log(tag: str, msg: str, level: str = "INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] [{tag}] {msg}", flush=True)

    log_fn = _REGISTER_LOG_FN.get()
    if not callable(log_fn):
        return

    # The task logger already adds its own timestamp.  Do not forward the
    # terminal timestamp, otherwise the UI shows two different time prefixes.
    level_text = "" if level == "INFO" else f"[{level}] "
    try:
        log_fn(f"[DrissionPage] {level_text}[{tag}] {msg}")
    except Exception as exc:
        # Logging must never abort account registration.  Only the exception
        # type is emitted so a callback cannot leak credentials in its error.
        print(
            f"[{ts}] [WARN] [Logger] 任务日志转发失败 "
            f"({type(exc).__name__})",
            flush=True,
        )


# ── 工具函数 ──────────────────────────────────────────────────────

def generate_password(length: int = 16) -> str:
    if length < 4:
        raise ValueError("密码长度不能小于 4")
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%"),
    ]
    pwd += [secrets.choice(chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def generate_name() -> dict:
    first_names = ["James", "Emma", "Liam", "Olivia", "Noah", "Ava", "William", "Sophia", "Lucas", "Mia"]
    last_names = ["Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson"]
    return {"first": random.choice(first_names), "last": random.choice(last_names)}

def generate_birthday() -> dict:
    year = random.randint(1985, 2000)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return {"year": year, "month": month, "day": day}


def _is_browser_closed(page) -> bool:
    if page is None:
        return True
    try:
        _ = page.url
        return False
    except Exception:
        return True


def _live_page_url(page) -> str:
    """Read the SPA's live URL before falling back to DrissionPage's cache."""
    try:
        value = page.run_js("return window.location.href")
        if isinstance(value, str) and value.startswith(("https://", "http://")):
            return value
    except Exception:
        pass
    try:
        return str(page.url or "")
    except Exception:
        return ""


def _wait_for_url(page, url_part: str, timeout: int = 15) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if _is_browser_closed(page):
            return False
        if url_part in _live_page_url(page):
            return True
        time.sleep(0.5)
    return False


def _wait_for_url_any(page, url_parts, timeout: int = 20) -> str:
    """等待落到多个候选 URL 片段任一个, 返回命中的片段(超时返回 '')。"""
    start = time.time()
    while time.time() - start < timeout:
        if _is_browser_closed(page):
            return ""
        cur = _live_page_url(page)
        for part in url_parts:
            if part in cur:
                return part
        time.sleep(0.5)
    return ""


def _capture_debug_snapshot(page, name: str) -> str:
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        path = os.path.join(
            RESULTS_DIR,
            f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
        )
        page.get_screenshot(path=path, full_page=True)
        return path
    except Exception:
        return ""


def _collect_page_diagnostics(page) -> dict:
    try:
        return page.run_js(
            """
            return (() => {
              const pick = (sel) => Array.from(document.querySelectorAll(sel)).slice(0, 8).map(el => ({
                tag: el.tagName,
                type: el.getAttribute('type'),
                name: el.getAttribute('name'),
                placeholder: el.getAttribute('placeholder'),
                text: el.matches('input[type="password"], input[autocomplete="one-time-code"], input[name="code"]')
                  ? '[已隐藏]'
                  : (el.innerText || el.value || '').trim().slice(0, 80),
              }));
              return {
                url: location.href,
                title: document.title,
                bodyPreview: (document.body?.innerText || '').trim().slice(0, 600),
                inputs: pick('input'),
                buttons: pick('button'),
              };
            })()
            """
        ) or {}
    except Exception:
        return {"url": getattr(page, "url", ""), "title": "", "bodyPreview": ""}


def _extract_page_errors(page) -> list[str]:
    try:
        errors = page.run_js(
            """
            return (() => {
              const values = [];
              document.querySelectorAll('[class*="error"], [role="alert"], .react-aria-FieldError').forEach(el => {
                const text = (el.textContent || '').trim();
                if (text) values.push(text);
              });
              return values;
            })()
            """
        )
        if isinstance(errors, list):
            return [str(item).strip() for item in errors if str(item).strip()]
    except Exception:
        pass
    return []


def _has_existing_account_auth_error(page) -> bool:
    """Recognize the explicit auth error field, never URL/text substrings.

    Bind visible error text to the same live HTTPS auth document.  A stale
    diagnostic, an external page or an ordinary error message is not evidence
    that the target account already exists.
    """
    try:
        live_url = str(page.url or "")
        origin = urlsplit(live_url)
        if (origin.scheme != "https"
                or origin.hostname not in {"auth.openai.com", "auth0.openai.com"}
                or origin.port not in {None, 443}
                or origin.username is not None or origin.password is not None):
            return False
        diagnostic = _collect_page_diagnostics(page)
        if (not isinstance(diagnostic, dict)
                or diagnostic.get("url") != live_url
                or str(page.url or "") != live_url):
            return False
        visible_text = str(diagnostic.get("bodyPreview") or "")
        return re.search(
            r"(?m)^[ \t]*(?:(?i:error[ \t]+code)|错误代码|錯誤代碼)"
            r"[ \t]*[:：][ \t]*(?:\r?\n[ \t]*)?user_already_exists[ \t]*\r?$",
            visible_text,
        ) is not None
    except Exception:
        return False


def _existing_account_auth_failure() -> dict:
    return {
        "success": False,
        "existing_account": True,
        "error_code": "user_already_exists",
        "error": "认证服务已确认该邮箱存在 ChatGPT 账号，请使用登录流程",
    }


def _element_is_interactable(element) -> bool:
    """Return True only for a live, visible, enabled element with a box.

    ChatGPT keeps hidden copies of auth controls in the homepage DOM.  Calling
    ``click()`` on the first selector match therefore raises DrissionPage's
    ``NoRectError`` ("the element has no location or size").  Use the state
    object provided by DrissionPage 4.x instead of treating DOM existence as
    interactability.  The attribute based fallback keeps lightweight test
    doubles compatible without weakening the real browser check.
    """
    if not element:
        return False

    try:
        states = element.states
    except AttributeError:
        # Test doubles and older wrapper objects may not expose ``states``.
        return True
    except Exception:
        return False

    try:
        if not bool(states.is_alive):
            return False
    except AttributeError:
        pass
    except Exception:
        return False

    try:
        clickable = states.is_clickable
    except AttributeError:
        clickable = None
    except Exception:
        return False
    if clickable is not None:
        return bool(clickable)

    try:
        if not bool(states.is_displayed) or not bool(states.is_enabled):
            return False
    except Exception:
        return False

    try:
        has_rect = states.has_rect
    except AttributeError:
        try:
            size = element.rect.size
            return bool(size and len(size) >= 2 and size[0] > 0 and size[1] > 0)
        except Exception:
            return False
    except Exception:
        return False
    return bool(has_rect)


def _first_interactable(page, selectors, *, timeout: float = 0.5):
    """Find the first interactable match, including later DOM duplicates."""
    for selector in selectors:
        matches = []
        try:
            finder = getattr(page, "eles", None)
            if callable(finder):
                matches = list(finder(selector, timeout=timeout) or [])
            else:
                found = page.ele(selector, timeout=timeout)
                matches = [found] if found else []
        except Exception:
            matches = []
        for element in matches:
            if _element_is_interactable(element):
                try:
                    if bool(element.property("readOnly")):
                        continue
                except (AttributeError, TypeError):
                    pass
                except Exception:
                    continue
                return element
    return None


def _check_registration_guard(guard) -> None:
    """Invoke the owner/cancellation guard without swallowing its exception."""
    if callable(guard):
        guard()


def _fill_interactable_input(page, element, value: str, *, retries: int = 3, guard=None) -> bool:
    """Fill a visible React-controlled input and verify that the value sticks."""
    expected = str(value or "")
    for _ in range(max(1, retries)):
        if not _element_is_interactable(element):
            return False
        _check_registration_guard(guard)
        try:
            element.click()
        except Exception:
            return False
        _check_registration_guard(guard)
        try:
            element.clear(by_js=True)
        except TypeError:
            _check_registration_guard(guard)
            try:
                element.clear()
            except Exception:
                pass
        except Exception:
            _check_registration_guard(guard)
            try:
                element.clear()
            except Exception:
                pass
        _check_registration_guard(guard)
        try:
            element.input(expected, clear=False)
        except TypeError:
            _check_registration_guard(guard)
            try:
                element.input(expected)
            except Exception:
                continue
        except Exception:
            continue

        # Dispatch React-compatible events on the exact visible element.  This
        # avoids document.querySelector() selecting a hidden duplicate.
        _check_registration_guard(guard)
        try:
            page.run_js(
                """
                const input = arguments[0];
                const value = arguments[1];
                if (!input) return false;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value'
                )?.set;
                if (setter && input.value !== value) setter.call(input, value);
                input.dispatchEvent(new Event('input', {bubbles: true}));
                input.dispatchEvent(new Event('change', {bubbles: true}));
                return input.value;
                """,
                element,
                expected,
            )
        except Exception:
            pass
        time.sleep(0.5)

        try:
            actual = element.property("value")
        except Exception:
            actual = getattr(element, "value", expected)
        if str(actual or "") == expected:
            return True
    return False


def _click_visible_form_submit(page, *, guard=None, before_submit=None) -> bool:
    """Click Continue/submit in the form containing the visible auth input."""
    guarded = callable(guard) or callable(before_submit)

    def click_resolved(button) -> bool:
        # Hooks deliberately sit outside the browser-exception handler.  A
        # lost owner or failed persistence must stop this submission entirely.
        _check_registration_guard(guard)
        if callable(before_submit):
            before_submit()
            _check_registration_guard(guard)
        try:
            button.click()
            return True
        except Exception:
            return False

    clicked = False
    resolved_button = None
    try:
        result = page.run_js(
            """
            const resolveOnly = Boolean(arguments[0]);
            return (() => {
              const usable = (el) => {
                if (!el || el.disabled || el.readOnly || el.closest('[inert]')) return false;
                if (el.getAttribute('aria-disabled') === 'true' || el.getAttribute('aria-hidden') === 'true') return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                  && style.pointerEvents !== 'none' && Number(style.opacity || 1) > 0
                  && rect.width > 0 && rect.height > 0;
              };
              const authInputs = Array.from(document.querySelectorAll(
                'input[type="email"], input[name="email"], input[name="username"], '
                + 'input[autocomplete="email"], input[autocomplete="username"], '
                + 'input[type="password"], input[autocomplete="one-time-code"], input[name="code"], '
                + 'input[maxlength="1"], input[name="name"], input[autocomplete="name"], input[name="age"]'
              ));
              const activeInput = authInputs.find(usable);
              if (!activeInput) return false;
              const form = activeInput.closest('form');
              if (!form) return false;
              const buttons = Array.from(form.querySelectorAll('button, input[type="submit"], [role="button"]'))
                .filter(usable);
              const exact = ['continue', '继续', '繼續', '続行', '続ける', 'next', 'verify', '确认', '確認'];
              const label = (el) => (el.innerText || el.value || el.textContent || '').trim().toLowerCase();
              const formBtn = buttons.find((button) => exact.includes(label(button)))
                || buttons.find((button) => button.type === 'submit');
              if (formBtn) {
                if (resolveOnly) return formBtn;
                formBtn.click(); return true;
              }
              return false;
            })();
            """,
            *((True,) if guarded else ()),
        )
        if guarded:
            resolved_button = result if callable(getattr(result, "click", None)) else None
        else:
            clicked = bool(result)
    except Exception:
        clicked = False
    if resolved_button is not None:
        return click_resolved(resolved_button)
    if clicked:
        return True

    # ChromiumPage always provides ``eles``.  If the form-scoped JS path did
    # not find a submit control, do not fall back to an unrelated submit button
    # elsewhere on the ChatGPT page.  The fallback below exists only for small
    # legacy page adapters/test doubles that cannot execute the scoped script.
    if callable(getattr(page, "eles", None)):
        return False

    # Native fallback for legacy page adapters without ``eles``.
    button = _first_interactable(
        page,
        (
            'xpath://button[normalize-space()="Continue" or normalize-space()="继续" '
            'or normalize-space()="繼續" or normalize-space()="続行" '
            'or normalize-space()="Next" or normalize-space()="确认"]',
            'css:button[data-testid="continue-button"]',
            'css:button[type="submit"]',
        ),
        timeout=0.5,
    )
    if not button:
        return False
    return click_resolved(button)


def _registration_state(page) -> str:
    """Classify the current auth page without relying on URL alone."""
    # DrissionPage's Python-side URL can lag behind a React navigation even
    # while the page DOM already belongs to /about-you.  The OTP worker must
    # not click that next form or report a successful verification as stalled.
    url = _live_page_url(page).lower()
    if _has_existing_account_auth_error(page):
        return "existing_account"
    # This route is unambiguously an existing-account password challenge; do
    # not let its visible password field masquerade as signup.
    if "/log-in/password" in url:
        return "existing_login"
    # A successful OTP submission updates the SPA route before React removes
    # the old code input.  These destinations are unambiguous, so prefer them
    # over a briefly stale verification node or a rerender race will turn a
    # successful signup into an OTP timeout/failure.
    if "/about-you" in url:
        return "about_you"
    if "/create-account/password" in url:
        return "password"
    if _first_interactable(
        page, ('css:input[autocomplete="current-password"]',), timeout=0.2,
    ):
        return "existing_login"
    # The auth UI is a SPA.  Prefer the currently-visible form over a URL that
    # can lag behind the React transition by several seconds.
    if _first_interactable(
        page, ('css:input[autocomplete="new-password"]',), timeout=0.2,
    ):
        return "password"
    if _first_interactable(
        page,
        (
            'css:input[type="password"]',
            'css:input[name="password"]',
            'css:input[autocomplete="new-password"]',
        ),
        timeout=0.2,
    ):
        # An arbitrary password input is not evidence of account creation.
        # A login SPA may expose it before updating its URL.
        if "/create-account" in url:
            return "password"
        return "existing_login" if "/log-in" in url else "unknown"
    if _first_interactable(
        page,
        (
            'css:input[autocomplete="one-time-code"]',
            'css:input[name="code"]',
            'css:input[inputmode="numeric"]',
        ),
        timeout=0.2,
    ):
        return "verification"
    if _first_interactable(
        page,
        ('css:input[name="name"]', 'css:input[autocomplete="name"]'),
        timeout=0.2,
    ):
        return "about_you"
    if _wait_email_input_once(page):
        return "email"

    if "/create-account/password" in url:
        return "password"
    if "/email-verification" in url or "/log-in/code" in url:
        return "verification"
    if "/about-you" in url:
        return "about_you"
    if "chatgpt.com" in url and "auth.openai.com" not in url:
        if "/auth/login" in url:
            return "email"
        return "home"
    if _extract_page_errors(page):
        return "error"
    return "unknown"


def _wait_registration_state(page, expected: set[str], *, timeout: float = 20) -> str:
    deadline = time.time() + timeout
    last_state = "unknown"
    while time.time() < deadline:
        if _is_browser_closed(page):
            return "closed"
        last_state = _registration_state(page)
        if last_state in expected:
            return last_state
        time.sleep(0.4)
    return last_state


def _fail_with_page_diagnostics(page, tag: str, message: str, snapshot_name: str) -> dict:
    if _has_existing_account_auth_error(page):
        return _existing_account_auth_failure()
    browser_error = _detect_browser_error(page)
    diag = _collect_page_diagnostics(page)
    page_errors = _extract_page_errors(page)
    if page_errors:
        diag["errors"] = page_errors[:5]
    snap = _capture_debug_snapshot(page, snapshot_name)
    _log(tag, f"{message}, 诊断: {json.dumps(diag, ensure_ascii=False)[:900]}", "WARN")
    if snap:
        _log(tag, f"诊断截图已保存: {snap}", "WARN")
    if browser_error:
        return {"success": False, "error": browser_error}
    # Read the live property first; a diagnostic snapshot can be stale when a
    # navigation races with collection.
    try:
        live_url = getattr(page, "url", "")
    except Exception:
        live_url = ""
    url = str(live_url or diag.get("url") or "")[:240]
    detail = str(page_errors[0])[:240] if page_errors else ""
    suffix = f"; 当前 URL: {url}" if url else ""
    if detail:
        suffix += f"; 页面提示: {detail}"
    return {"success": False, "error": f"{message}{suffix}"}


def _detect_browser_error(page) -> str:
    diag = _collect_page_diagnostics(page)
    haystack = " ".join(
        [
            str(diag.get("title") or ""),
            str(diag.get("bodyPreview") or ""),
            str(diag.get("url") or ""),
        ]
    ).lower()

    if "err_proxy_connection_failed" in haystack:
        return "代理连接失败"
    if "something wrong with the proxy server" in haystack:
        return "代理连接失败"
    if "checking the proxy address" in haystack:
        return "代理连接失败"
    if "err_tunnel_connection_failed" in haystack:
        return "代理隧道连接失败"
    if "err_connection_refused" in haystack:
        return "目标连接被拒绝"
    if "err_name_not_resolved" in haystack:
        return "DNS 解析失败"
    if "no internet" in haystack:
        return "网络连接失败"
    return ""


def _open_signup_entry(page) -> bool:
    """Open the visible auth entry on the hydrated ChatGPT homepage.

    Newer homepage variants expose only a Login button; entering an unused
    email in that flow still starts signup.  Prefer Sign up, then fall back to
    Login, but never click a hidden duplicate.
    """
    try:
        clicked = page.run_js(
            """
            return (() => {
              const usable = (el) => {
                if (!el || el.disabled || el.closest('[inert]')) return false;
                if (el.getAttribute('aria-disabled') === 'true' || el.getAttribute('aria-hidden') === 'true') return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                if (style.display === 'none' || style.visibility === 'hidden'
                    || style.pointerEvents === 'none' || Number(style.opacity || 1) <= 0
                    || rect.width <= 0 || rect.height <= 0) return false;
                const x = Math.min(Math.max(rect.left + rect.width / 2, 0), innerWidth - 1);
                const y = Math.min(Math.max(rect.top + rect.height / 2, 0), innerHeight - 1);
                const top = document.elementFromPoint(x, y);
                return !top || top === el || el.contains(top) || top.contains(el);
              };
              const all = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                .filter(usable);
              const text = (el) => (el.innerText || el.textContent || '').trim().toLowerCase();
              const testid = (el) => (el.getAttribute('data-testid') || '').toLowerCase();
              let target = all.find((el) => testid(el) === 'signup-button')
                || all.find((el) => ['sign up for free', 'sign up', 'get started', '免费注册', '注册'].includes(text(el)));
              if (!target) {
                target = all.find((el) => testid(el) === 'login-button')
                  || all.find((el) => ['log in', 'login', 'sign in', '登录', '登入'].includes(text(el)));
              }
              if (!target) return false;
              target.scrollIntoView({block: 'center'});
              target.click();
              return true;
            })();
            """
        )
        if clicked:
            return True
    except Exception:
        pass

    selectors = (
        "css:button[data-testid='signup-button']",
        "css:a[data-testid='signup-button']",
        "text:Sign up for free",
        "text:Sign up",
        "text:Get started",
        "text:免费注册",
        "text:注册",
        "css:button[data-testid='login-button']",
        "css:a[data-testid='login-button']",
        "text:Log in",
        "text:登录",
    )
    for selector in selectors:
        button = _first_interactable(page, (selector,), timeout=0.6)
        if not button:
            continue
        try:
            button.click()
            return True
        except Exception:
            continue
    return False


_EMAIL_INPUT_SELECTORS = (
    'css:input[type="email"]',
    'css:input[name="email"]',
    'css:input[name="username"]',
    'css:input[placeholder*="Email"]',
    'css:input[placeholder*="email"]',
    'css:input[placeholder*="电子邮件"]',
    'css:input[autocomplete="email"]',
    'css:input[autocomplete="username"]',
)


def _wait_email_input_once(page):
    return _first_interactable(page, _EMAIL_INPUT_SELECTORS, timeout=0.25)


def _wait_email_input(page, timeout: int = 20):
    start = time.time()
    reopened = False
    while time.time() - start < timeout:
        if _is_browser_closed(page):
            return None
        found = _wait_email_input_once(page)
        if found:
            return found
        now = time.time()
        # One guarded retry covers a click that happened before React hydrated.
        # Repeatedly clicking the page behind an open modal can close or reset it.
        if (
            not reopened
            and now - start >= 4.0
            and "chatgpt.com" in str(page.url or "")
        ):
            _open_signup_entry(page)
            reopened = True
        time.sleep(0.5)
    return None


def _resolve_browser_executable() -> str:
    candidates: list[str] = []

    for env_key in (
        "DRISSION_BROWSER_PATH",
        "CHROME_PATH",
        "CHROMIUM_PATH",
        "GOOGLE_CHROME_SHIM",
    ):
        value = str(os.getenv(env_key, "") or "").strip()
        if value:
            candidates.append(value)

    candidates.extend(
        [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/opt/google/chrome/chrome",
        ]
    )

    ms_playwright_root = Path.home() / ".cache" / "ms-playwright"
    if ms_playwright_root.exists():
        for pattern in ("chromium-*/chrome-linux*/chrome", "chromium-*/chrome-linux/chrome"):
            for path in sorted(ms_playwright_root.glob(pattern), reverse=True):
                candidates.append(str(path))

    seen = set()
    for candidate in candidates:
        value = str(candidate or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        if os.path.isfile(value) and os.access(value, os.X_OK):
            return value
    return ""


# ── 浏览器创建 ────────────────────────────────────────────────────

def create_browser(proxy: str = "", headless: bool = False,
                   incognito: bool = True) -> ChromiumPage:
    """Create an owned blank browser, or raise typed BrowserInitializationError."""
    from core.browser_startup import start_local_browser

    def options():
        co = ChromiumOptions()
        if incognito:
            co.incognito()

        if sys.platform.startswith("linux"):
            browser_path = _resolve_browser_executable()
            if browser_path:
                co.set_browser_path(browser_path)
                _log("Browser", "Linux 已选择可用的本地浏览器")

        co.headless(headless)

        co.set_argument("--disable-blink-features=AutomationControlled")
        co.set_argument("--disable-dev-shm-usage")
        co.set_argument("--no-sandbox")
        co.set_argument("--disable-gpu")
        co.set_argument("--no-first-run")
        co.set_argument("--no-default-browser-check")
        co.set_argument("--lang=en-US")
        co.set_argument("--window-size=1920,1080")

        if proxy:
            co.set_proxy(proxy)

        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        co.set_user_agent(ua)
        return co

    def initialize(page):
        # 注入反检测
        page.run_js("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'platform', { get: () => 'MacIntel' });
            Object.defineProperty(navigator, 'language', { get: () => 'en-US' });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
        """)

    page = start_local_browser(options, page_factory=ChromiumPage, initialize=initialize,
                               log=lambda message: _log("Browser", message))
    _log("Browser", f"浏览器已创建 (代理={'已配置' if proxy else '无'}, headless={headless})")
    return page


# ── CF Worker 邮箱验证码获取 ──────────────────────────────────────

def _cfworker_get_code(
    api_url: str,
    admin_token: str,
    email: str,
    custom_auth: str = "",
    quick_api_url: str = "",
    timeout: int = CODE_TIMEOUT,
    exclude_codes: set = None,
) -> dict:
    """从 Quick Mails API 轮询验证码并返回无敏感信息的诊断。

    过去这里只返回验证码或 ``None``，因此 HTTP 非 200、接口异常、空邮箱
    和邮件存在但没有验证码最终都会变成同一句“验证码超时”。 结构化结果
    让上层可以在任务日志与最终错误中说明实际等待的对象，同时不记录邮件
    正文、验证码或认证信息。
    """
    import re
    import requests

    quick_base = str(quick_api_url or "").strip().rstrip("/") or "https://temp-api.cursom.shop"
    exclude = exclude_codes or set()
    start = time.time()

    attempts = 0
    successful_responses = 0
    http_error_count = 0
    request_error_count = 0
    invalid_payload_count = 0
    last_http_status = None
    last_error_type = ""
    max_message_count = 0
    saw_six_digit_code = False
    saw_excluded_code = False

    while time.time() - start < timeout:
        attempts += 1
        try:
            resp = requests.get(
                f"{quick_base}/open_api/quick_mails",
                params={"limit": 20, "offset": 0, "address": email},
                timeout=10,
            )
            last_http_status = int(resp.status_code)
            if resp.status_code != 200:
                http_error_count += 1
                time.sleep(POLL_INTERVAL)
                continue

            successful_responses += 1
            try:
                data = resp.json()
            except Exception:
                invalid_payload_count += 1
                time.sleep(POLL_INTERVAL)
                continue
            mails = data.get("results", data) if isinstance(data, dict) else data
            if not isinstance(mails, list):
                invalid_payload_count += 1
                time.sleep(POLL_INTERVAL)
                continue

            max_message_count = max(max_message_count, len(mails))

            for mail in sorted(
                (item for item in mails if isinstance(item, dict)),
                key=lambda item: item.get("id", 0),
                reverse=True,
            ):
                subject = str(mail.get("subject", ""))
                text = str(mail.get("text", "") or mail.get("raw", ""))
                source = f"{subject} {text}"

                codes = re.findall(r"\b(\d{6})\b", source)
                if codes:
                    saw_six_digit_code = True
                for code in codes:
                    if code not in exclude:
                        return {
                            "code": code,
                            "reason": "ok",
                            "source": "quick_api",
                            "attempts": attempts,
                            "last_http_status": last_http_status,
                            "message_count": max_message_count,
                            "terminal": False,
                        }
                    saw_excluded_code = True
        except Exception as e:
            request_error_count += 1
            last_error_type = type(e).__name__
            _log(
                "CFWorker",
                f"Quick API 轮询异常 ({last_error_type})，稍后重试",
                "WARN",
            )

        time.sleep(POLL_INTERVAL)

    if successful_responses:
        if invalid_payload_count >= successful_responses:
            reason = "invalid_payload"
        elif max_message_count == 0:
            reason = "no_messages"
        elif saw_excluded_code:
            reason = "excluded_code_only"
        elif saw_six_digit_code:
            reason = "code_not_usable"
        else:
            reason = "no_valid_code"
    elif http_error_count:
        reason = "http_error"
    elif request_error_count:
        reason = "request_error"
    else:
        reason = "not_polled"

    return {
        "code": None,
        "reason": reason,
        "source": "quick_api",
        "attempts": attempts,
        "last_http_status": last_http_status,
        "message_count": max_message_count,
        "http_error_count": http_error_count,
        "request_error_count": request_error_count,
        "invalid_payload_count": invalid_payload_count,
        "last_error_type": last_error_type,
        "terminal": False,
    }


# ── Outlook Graph API 验证码获取 ──────────────────────────────────

def _outlook_get_access_token(client_id: str, refresh_token: str) -> str:
    """用 refresh_token 换取 Graph API access_token"""
    import requests

    endpoints = [
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "https://login.live.com/oauth20_token.srf",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    ]

    for endpoint in endpoints:
        try:
            resp = requests.post(
                endpoint,
                data={
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=20,
            )
            if resp.status_code >= 400:
                continue
            data = resp.json()
            token = data.get("access_token", "")
            if token:
                return token
        except Exception:
            continue
    return ""


_OUTLOOK_OPENAI_SENDERS = {
    "noreply@tm.openai.com",
    "noreply@openai.com",
    "noreply@email.openai.com",
}
_OUTLOOK_OPENAI_SUBJECT_KEYWORDS = {"openai", "chatgpt"}


def _parse_graph_datetime(value: str) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _is_invalid_otp_candidate(code: str) -> bool:
    value = str(code or "").strip()
    if len(value) != 6 or not value.isdigit():
        return True
    if value == "000000":
        return True
    if len(set(value)) == 1:
        return True
    return False


def _pick_outlook_openai_code(
    messages: list[dict],
    *,
    exclude_codes: set[str],
    received_after_ts: float = 0.0,
) -> tuple[str | None, dict | None]:
    for message in messages or []:
        sender = str(
            ((message.get("from") or {}).get("emailAddress") or {}).get("address", "")
        ).strip().lower()
        subject = str(message.get("subject", "") or "")
        subject_lower = subject.lower()
        if sender not in _OUTLOOK_OPENAI_SENDERS:
            continue
        if not any(keyword in subject_lower for keyword in _OUTLOOK_OPENAI_SUBJECT_KEYWORDS):
            continue

        received_ts = _parse_graph_datetime(message.get("receivedDateTime", ""))
        if received_after_ts and received_ts and received_ts < received_after_ts:
            continue

        preview = str(message.get("bodyPreview", "") or "")
        body = str((message.get("body") or {}).get("content", "") or "")
        text = f"{subject} {preview} {body}"
        codes = re.findall(r"\b(\d{6})\b", text)
        for code in codes:
            if code in exclude_codes or _is_invalid_otp_candidate(code):
                continue
            return code, {
                "sender": sender,
                "subject": subject,
                "received_ts": received_ts,
                "received_at": message.get("receivedDateTime", ""),
            }
    return None, None


def _summarize_outlook_message(message: dict) -> dict:
    sender = str(
        ((message.get("from") or {}).get("emailAddress") or {}).get("address", "")
    ).strip().lower()
    return {
        "sender": sender,
        "subject": str(message.get("subject", "") or "")[:120],
        "received_at": str(message.get("receivedDateTime", "") or ""),
    }


def _outlook_get_code(
    client_id: str,
    refresh_token: str,
    email: str,
    timeout: int = CODE_TIMEOUT,
    exclude_codes: set = None,
    received_after_ts: float = 0.0,
) -> dict:
    """从 Outlook Graph API 轮询获取 OpenAI 验证码"""
    import requests

    exclude = exclude_codes or set()
    access_token = _outlook_get_access_token(client_id, refresh_token)
    if not access_token:
        _log("Outlook", "获取 Graph API access_token 失败", "ERROR")
        return {
            "code": None,
            "reason": "access_token_failed",
            "recent_messages": [],
        }

    start = time.time()
    seen_ids = set()
    logged_waiting = False
    saw_openai_message = False
    saw_openai_message_without_valid_code = False
    recent_messages: list[dict] = []
    folders = ["inbox", "junkemail", "archive", "deleteditems"]

    while time.time() - start < timeout:
        try:
            batch_recent_messages: list[dict] = []
            for folder in folders:
                resp = requests.get(
                    f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={
                        "$top": 10,
                        "$orderby": "receivedDateTime desc",
                        "$select": "id,subject,from,bodyPreview,body,receivedDateTime",
                    },
                    timeout=15,
                )
                if resp.status_code != 200:
                    continue

                messages = resp.json().get("value", [])
                for message in messages[:2]:
                    summary = _summarize_outlook_message(message)
                    if summary not in batch_recent_messages:
                        batch_recent_messages.append(summary)
                for message in messages:
                    sender = str(
                        ((message.get("from") or {}).get("emailAddress") or {}).get("address", "")
                    ).strip().lower()
                    subject_lower = str(message.get("subject", "") or "").lower()
                    if sender in _OUTLOOK_OPENAI_SENDERS and any(
                        keyword in subject_lower for keyword in _OUTLOOK_OPENAI_SUBJECT_KEYWORDS
                    ):
                        received_ts = _parse_graph_datetime(message.get("receivedDateTime", ""))
                        if not received_after_ts or not received_ts or received_ts >= received_after_ts:
                            saw_openai_message = True

                for m in messages:
                    mid = m.get("id", "")
                    if not mid or mid in seen_ids:
                        continue
                    seen_ids.add(mid)
                    code, meta = _pick_outlook_openai_code(
                        [m],
                        exclude_codes=exclude,
                        received_after_ts=received_after_ts,
                    )
                    if code:
                        _log(
                            "Outlook",
                            "已收到验证码（内容不写入日志） "
                            f"(from={meta.get('sender')}, at={meta.get('received_at')})",
                        )
                        return {
                            "code": code,
                            "reason": "ok",
                            "recent_messages": batch_recent_messages[:5],
                            "meta": meta,
                        }
                    sender = str(
                        ((m.get("from") or {}).get("emailAddress") or {}).get("address", "")
                    ).strip().lower()
                    subject_lower = str(m.get("subject", "") or "").lower()
                    if sender in _OUTLOOK_OPENAI_SENDERS and any(
                        keyword in subject_lower for keyword in _OUTLOOK_OPENAI_SUBJECT_KEYWORDS
                    ):
                        received_ts = _parse_graph_datetime(m.get("receivedDateTime", ""))
                        if not received_after_ts or not received_ts or received_ts >= received_after_ts:
                            saw_openai_message_without_valid_code = True
            if batch_recent_messages:
                recent_messages = batch_recent_messages[:5]
            if not logged_waiting:
                _log("Outlook", "未发现符合条件的 OpenAI 新验证码邮件，继续轮询...")
                logged_waiting = True
        except Exception as e:
            _log("Outlook", f"轮询异常: {e}", "WARN")

        time.sleep(POLL_INTERVAL)

    reason = "no_openai_mail"
    if saw_openai_message_without_valid_code:
        reason = "openai_mail_without_valid_code"
    elif saw_openai_message:
        reason = "openai_mail_seen_but_not_ready"
    return {
        "code": None,
        "reason": reason,
        "recent_messages": recent_messages,
    }


def _format_outlook_code_failure(result: dict) -> str:
    reason = str((result or {}).get("reason", "") or "").strip()
    if reason == "access_token_failed":
        return "Outlook Graph API access_token 获取失败"
    if reason == "openai_mail_without_valid_code":
        return "Outlook 已收到 OpenAI 验证邮件，但未提取到有效验证码"
    if reason == "openai_mail_seen_but_not_ready":
        return "Outlook 已收到 OpenAI 验证邮件，但验证码尚未就绪"
    if reason == "no_openai_mail":
        return "Outlook 未收到 OpenAI 验证邮件"
    if reason == "mailbox_timeout":
        return "Outlook 等待验证码超时"
    if reason == "mailbox_access_failed":
        return "Outlook 邮箱读取失败，请检查邮箱凭证与连接"
    return "验证码超时"


def _read_outlook_code(
    mail_config: dict,
    *,
    email: str,
    timeout: int,
    exclude_codes: set[str],
    received_after_ts: float,
) -> dict:
    """Read one Outlook OTP through the caller's mailbox abstraction.

    The application mailbox pool knows whether an imported Outlook account is
    backed by Graph or IMAP/POP.  Keep that decision at the mailbox boundary;
    the browser registrar must not reinterpret every Microsoft refresh token
    as a Graph credential.  The legacy Graph reader remains as a CLI fallback
    for direct callers that do not provide ``code_reader``.
    """
    reader = mail_config.get("code_reader")
    if callable(reader):
        try:
            raw_result = reader(
                timeout=max(1, int(timeout or 0)),
                exclude_codes=set(exclude_codes or set()),
                received_after_ts=float(received_after_ts or 0.0),
            )
        except TimeoutError:
            return {
                "code": None,
                "reason": "mailbox_timeout",
                "recent_messages": [],
                "terminal": False,
            }
        except Exception as exc:
            # Mailbox errors can contain server responses or credential
            # fragments.  Preserve only the exception type in diagnostics.
            _log(
                "Outlook",
                f"邮箱适配器读取失败 ({type(exc).__name__})",
                "ERROR",
            )
            return {
                "code": None,
                "reason": "mailbox_access_failed",
                "recent_messages": [],
                "terminal": True,
            }

        if isinstance(raw_result, dict):
            result = dict(raw_result)
            result.setdefault("recent_messages", [])
            result.setdefault("terminal", False)
            return result
        code = str(raw_result or "").strip()
        return {
            "code": code or None,
            "reason": "ok" if code else "no_openai_mail",
            "recent_messages": [],
            "terminal": False,
        }

    result = _outlook_get_code(
        client_id=mail_config.get("client_id", ""),
        refresh_token=mail_config.get("refresh_token", ""),
        email=email,
        timeout=timeout,
        exclude_codes=exclude_codes,
        received_after_ts=received_after_ts,
    )
    # A rejected Graph refresh token cannot recover by making the same token
    # request six more times.  End immediately with a precise public error.
    if result.get("reason") == "access_token_failed":
        result["terminal"] = True
    return result


def _read_cfworker_code(
    mail_config: dict,
    *,
    email: str,
    timeout: int,
    exclude_codes: set[str],
    received_after_ts: float,
) -> dict:
    """Read one CF Worker OTP through an injected mailbox or Quick API.

    Application registrations inject the mailbox reader so its immutable
    account and pre-send Message-ID baseline remain authoritative.  Direct
    callers (including the CLI) retain the Quick API implementation as a
    fallback and receive the same structured diagnostics.
    """
    reader = mail_config.get("code_reader")
    if callable(reader):
        try:
            raw_result = reader(
                timeout=max(1, int(timeout or 0)),
                exclude_codes=set(exclude_codes or set()),
                received_after_ts=float(received_after_ts or 0.0),
            )
        except TimeoutError:
            return {
                "code": None,
                "reason": "mailbox_timeout",
                "source": "mailbox_reader",
                "terminal": False,
            }
        except Exception as exc:
            # Mailbox exceptions can contain URLs, tokens or response bodies.
            # Only expose the exception class to the task log.
            _log(
                "CFWorker" if mail_config.get("provider", "cfworker") == "cfworker" else "Mailbox",
                f"邮箱适配器读取失败 ({type(exc).__name__})",
                "ERROR",
            )
            return {
                "code": None,
                "reason": "mailbox_access_failed",
                "source": "mailbox_reader",
                "error_type": type(exc).__name__,
                "terminal": True,
            }

        if isinstance(raw_result, dict):
            result = dict(raw_result)
            result.setdefault("source", "mailbox_reader")
            result.setdefault("terminal", False)
            return result
        code = str(raw_result or "").strip()
        return {
            "code": code or None,
            "reason": "ok" if code else "no_new_message",
            "source": "mailbox_reader",
            "terminal": False,
        }

    if mail_config.get("provider", "cfworker") != "cfworker":
        return {
            "code": None, "reason": "mailbox_reader_missing",
            "source": "mailbox_reader", "terminal": True,
        }

    direct_result = _cfworker_get_code(
        api_url=mail_config.get("api_url", ""),
        admin_token=mail_config.get("admin_token", ""),
        email=email,
        custom_auth=mail_config.get("custom_auth", ""),
        quick_api_url=mail_config.get("quick_api_url", ""),
        timeout=max(1, int(timeout or 0)),
        exclude_codes=exclude_codes,
    )
    if isinstance(direct_result, dict):
        return direct_result
    # Backwards-compatible normalization for third-party monkey patches of
    # this private helper and older embedded callers.
    code = str(direct_result or "").strip()
    return {
        "code": code or None,
        "reason": "ok" if code else "unknown",
        "source": "quick_api",
        "terminal": False,
    }


def _describe_cfworker_poll(result: dict) -> str:
    """Return a concise, credential-free heartbeat description."""
    poll = result or {}
    reason = str(poll.get("reason") or "").strip()
    if reason in {"mailbox_timeout", "no_new_message"}:
        return "基线之后尚未发现新验证码邮件"
    if reason == "mailbox_access_failed":
        error_type = str(poll.get("error_type") or "读取异常")
        return f"邮箱读取失败（{error_type}）"
    if reason == "no_messages":
        status = poll.get("last_http_status") or 200
        return f"Quick API HTTP {status}，当前返回 0 封邮件"
    if reason == "no_valid_code":
        count = int(poll.get("message_count") or 0)
        return f"Quick API 返回 {count} 封邮件，但未找到有效验证码"
    if reason == "excluded_code_only":
        return "只发现发送前已有或已经使用过的验证码"
    if reason == "code_not_usable":
        return "邮件中发现验证码候选，但没有可使用的新验证码"
    if reason == "invalid_payload":
        status = poll.get("last_http_status") or 200
        return f"Quick API HTTP {status}，但响应格式不是邮件列表"
    if reason == "http_error":
        status = poll.get("last_http_status")
        return f"Quick API 返回 HTTP {status or '非 200'}"
    if reason == "request_error":
        error_type = str(poll.get("last_error_type") or "请求异常")
        return f"Quick API 请求失败（{error_type}）"
    if reason == "not_polled":
        return "尚未完成第一次邮箱查询"
    return "尚未取得新验证码"


def _format_cfworker_code_failure(result: dict, timeout_seconds: int) -> str:
    detail = _describe_cfworker_poll(result)
    if str((result or {}).get("reason") or "") == "mailbox_access_failed":
        return f"CF Worker 邮箱读取失败：{detail}"
    timeout_value = max(float(timeout_seconds or 0), 0.0)
    timeout_text = (
        str(int(timeout_value))
        if timeout_value.is_integer()
        else f"{timeout_value:g}"
    )
    return f"CF Worker 验证码等待超时（{timeout_text} 秒）：{detail}"


def _run_email_verification(page, mail_config: dict, email: str, *, log_prefix: str = "Step4") -> dict:
    """轮询邮箱验证码并填写提交, 直到离开 /email-verification 页(进入 about-you / password / chatgpt.com)或超时。

    兼容两种注册顺序: 先密码后验证(验证成功 → about-you) 和 先验证后密码(验证成功 → password 页)。
    返回 {"success": True} 或 {"success": False, "error": ...}。
    """
    def _left_verification() -> bool:
        return _registration_state(page) in {"about_you", "password", "home", "existing_login", "existing_account"}

    provider = mail_config.get("provider", "cfworker")
    guard = mail_config.get("guard")
    generic_mailbox = provider not in {"outlook", "cfworker"}
    if generic_mailbox and not callable(mail_config.get("code_reader")):
        return {"success": False, "error": "固定邮箱注册需要绑定本次邮箱的 code_reader"}
    mailbox_label = "邮箱" if generic_mailbox else "CF Worker"
    _log(log_prefix, f"从 {provider} 轮询验证码...")
    used_codes: set = set()
    start_code = time.time()
    verification_started_at = time.time()
    received_after_ts = verification_started_at - 5
    if provider == "mailbox":
        # A bound reader owns an immutable pre-send Message-ID baseline.  Its
        # matching timestamp must precede email submission too: completing a
        # password form can take longer than the old five-second tolerance.
        not_before = mail_config.get("not_before")
        try:
            candidate = float(not_before)
        except (TypeError, ValueError, OverflowError):
            candidate = 0.0
        if not isinstance(not_before, bool) and math.isfinite(candidate) and candidate > 0:
            received_after_ts = candidate
    last_outlook_poll: dict = {}
    last_cfworker_poll: dict = {}
    cfworker_poll_count = 0

    while time.time() - start_code < CODE_TIMEOUT:
        if _is_browser_closed(page):
            return {"success": False, "error": "浏览器已关闭"}
        if _left_verification():
            _log(log_prefix, "验证码已通过")
            return {"success": True}

        if provider == "outlook":
            remaining = max(1, int(CODE_TIMEOUT - (time.time() - start_code)))
            poll_result = _read_outlook_code(
                mail_config,
                email=email,
                timeout=min(15, remaining),
                exclude_codes=used_codes,
                received_after_ts=received_after_ts,
            )
            last_outlook_poll = poll_result
            code = poll_result.get("code")
            if not code and poll_result.get("terminal"):
                return {
                    "success": False,
                    "error": _format_outlook_code_failure(poll_result),
                }
        else:
            remaining = max(1, int(CODE_TIMEOUT - (time.time() - start_code)))
            cfworker_poll_count += 1
            if cfworker_poll_count == 1:
                _log(
                    log_prefix,
                    f"开始等待{mailbox_label}新验证码，最长 {CODE_TIMEOUT} 秒",
                )
            poll_started_at = time.time()
            poll_result = _read_cfworker_code(
                mail_config,
                email=email,
                timeout=min(15, remaining),
                exclude_codes=used_codes,
                received_after_ts=received_after_ts,
            )
            last_cfworker_poll = poll_result
            code = poll_result.get("code")
            if not code:
                elapsed = min(
                    CODE_TIMEOUT,
                    max(0, int(time.time() - start_code)),
                )
                _log(
                    log_prefix,
                    f"等待{mailbox_label}验证码：已等待约 {elapsed}/{CODE_TIMEOUT} 秒；"
                    f"{_describe_cfworker_poll(poll_result)}",
                    "WARN" if poll_result.get("terminal") else "INFO",
                )
                if poll_result.get("terminal"):
                    return {
                        "success": False,
                        "error": _format_cfworker_code_failure(
                            poll_result,
                            CODE_TIMEOUT,
                        ).replace("CF Worker", mailbox_label),
                    }

                # Injected readers and test doubles can return immediately.
                # Avoid a hot loop while retaining frequent, bounded task
                # heartbeats.  The direct Quick API reader normally consumes
                # most of this interval itself.
                poll_elapsed = time.time() - poll_started_at
                if poll_elapsed < 0.5:
                    time.sleep(min(POLL_INTERVAL, max(0, remaining)))

        if not code:
            continue

        _log(log_prefix, "已获取验证码（内容不写入日志）")
        used_codes.add(code)

        # Filling the final digit can submit automatically; checking only the
        # explicit Continue button would be too late.
        _check_registration_guard(guard)
        fill_result = (_fill_verification_code(page, code, guard=guard)
                       if callable(guard) else _fill_verification_code(page, code))
        if not fill_result:
            _log(log_prefix, "验证码填写失败", "WARN")
            time.sleep(2)
            continue
        _log(log_prefix, "验证码已填写，正在确认提交结果")

        # Current OTP pages commonly submit as soon as the sixth digit is
        # entered.  Check that transition before looking for a button, or we
        # may click the next page's form and then wait for a code needlessly.
        auto_deadline = time.time() + 2.5
        while time.time() < auto_deadline:
            if _left_verification():
                _log(log_prefix, "验证码已自动提交并通过")
                return {"success": True}
            time.sleep(0.25)

        _check_registration_guard(guard)
        clicked_submit = (_click_visible_form_submit(page, guard=guard)
                          if callable(guard) else _click_visible_form_submit(page))
        if clicked_submit:
            _log(log_prefix, "已点击验证码提交按钮")
            # The auth SPA may update its form before DrissionPage observes
            # the new top-frame route. A single read after two seconds raced
            # with /about-you in real registrations and falsely reported a
            # successful OTP as stalled. Keep this read-only transition wait
            # bounded and never click another form while it is in progress.
            submit_deadline = time.time() + 6
            while time.time() < submit_deadline:
                if _left_verification():
                    _log(log_prefix, "验证码已通过")
                    return {"success": True}
                time.sleep(0.25)
        else:
            # Some builds have neither a submit button nor an immediate route
            # change while React validates the code.  Give that transition a
            # short bounded wait instead of burning the entire OTP timeout.
            no_button_deadline = time.time() + 3
            while time.time() < no_button_deadline:
                if _left_verification():
                    _log(log_prefix, "验证码已通过")
                    return {"success": True}
                time.sleep(0.25)
            _log(log_prefix, "验证码已填写，但页面未自动提交且无可交互按钮", "WARN")

        if _left_verification():
            _log(log_prefix, "验证码已通过")
            return {"success": True}

        # Once a fresh code has been entered, silently waiting for another
        # message hides the real browser failure behind a misleading mailbox
        # timeout.  Stop here with the live URL, page alert and screenshot so
        # the next UI change is diagnosable and one code cannot be retried on
        # an unrelated screen.
        return _fail_with_page_diagnostics(
            page,
            log_prefix,
            "验证码已填写，但页面未进入下一步",
            "chatgpt_step4_otp_stalled",
        )

    if _left_verification():
        _log(log_prefix, "验证码已通过")
        return {"success": True}

    if provider == "outlook":
        recent_messages = (last_outlook_poll or {}).get("recent_messages") or []
        if recent_messages:
            _log("Outlook", f"最终超时前最近邮件样本: {json.dumps(recent_messages, ensure_ascii=False)[:500]}", "WARN")
        return {"success": False, "error": _format_outlook_code_failure(last_outlook_poll)}
    timeout_message = _format_cfworker_code_failure(
        last_cfworker_poll,
        CODE_TIMEOUT,
    ).replace("CF Worker", mailbox_label)
    return _fail_with_page_diagnostics(
        page,
        log_prefix,
        timeout_message,
        "chatgpt_step4_otp_timeout",
    )


def _wait_first_interactable(page, selectors, *, timeout: float = 12):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _is_browser_closed(page):
            return None
        element = _first_interactable(page, selectors, timeout=0.3)
        if element:
            return element
        time.sleep(0.35)
    return None


def _wait_after_state(page, previous: str, *, timeout: float = 25) -> str:
    """Wait until an auth form actually advances to a different state."""
    deadline = time.time() + timeout
    last_state = previous
    while time.time() < deadline:
        if _is_browser_closed(page):
            return "closed"
        state = _registration_state(page)
        last_state = state
        if state not in {previous, "unknown", "email"}:
            return state
        time.sleep(0.4)
    return last_state


def _click_signup_password_entry(page) -> bool:
    """Click a real, visible password alternative; never invent a destination.

    The caller is on the email OTP step.  A password-login destination is
    intentionally not treated as signup and is classified again after click.
    """
    try:
        current_url = str(page.url or "")
        current = urlsplit(current_url)
        if current.hostname != "auth.openai.com" or "/log-in/password" in current.path:
            return False
        candidates = list(page.eles('css:button, a, [role="button"]', timeout=0.3) or [])
    except Exception:
        return False

    labels = {
        "continue with password", "use password", "use a password",
        "使用密码继续", "使用密碼繼續", "使用密码", "使用密碼",
        "パスワードで続行", "パスワードを使用する",
    }
    for element in candidates:
        if not _element_is_interactable(element):
            continue
        try:
            if str(element.attr("aria-disabled") or "").lower() == "true":
                continue
            href = str(element.attr("href") or "").strip()
            signup_link = False
            if href:
                destination = urlsplit(urljoin(current_url, href))
                # Even a matching caption must not click an external IdP,
                # login-password, reset-password or script URL.
                signup_link = (
                    destination.scheme == "https"
                    and destination.hostname == "auth.openai.com"
                    and destination.path.rstrip("/") == "/create-account/password"
                )
                if not signup_link:
                    continue
            caption = " ".join(str(element.text or "").split()).casefold()
            aria_label = " ".join(str(element.attr("aria-label") or "").split()).casefold()
            if not signup_link and caption not in labels and aria_label not in labels:
                continue
            element.click()
            return True
        except Exception:
            # A rerender can remove this candidate before click.  Leave the
            # existing OTP route intact if no remaining real control works.
            continue
    return False


def _submit_signup_password(page, password: str, *, guard=None, before_password_submit=None) -> dict:
    state = _registration_state(page)
    if state == "existing_account":
        return _existing_account_auth_failure()
    if state == "existing_login":
        return {
            "success": False, "existing_account": True,
            "error": "该邮箱已注册过 ChatGPT，进入了登录密码页",
        }
    if state != "password":
        return {"success": False, "error": "当前页面不是可确认的注册密码步骤"}
    selectors = (
        'css:input[type="password"]',
        'css:input[name="password"]',
        'css:input[autocomplete="new-password"]',
    )
    password_input = _wait_first_interactable(page, selectors, timeout=10)
    if not password_input:
        return _fail_with_page_diagnostics(
            page,
            "Step3",
            "已进入密码步骤，但未找到可交互的密码输入框",
            "chatgpt_step3_password_missing",
        )

    for attempt in range(1, 4):
        _check_registration_guard(guard)
        if not _fill_interactable_input(page, password_input, password):
            # React rerender may replace the input node.  Re-resolve once per
            # attempt instead of retrying a stale element.
            password_input = _wait_first_interactable(page, selectors, timeout=3)
            if not password_input or not _fill_interactable_input(page, password_input, password):
                continue

        _check_registration_guard(guard)
        submitted = (_click_visible_form_submit(page, guard=guard, before_submit=before_password_submit)
                     if callable(guard) or callable(before_password_submit)
                     else _click_visible_form_submit(page))
        if not submitted:
            return _fail_with_page_diagnostics(
                page,
                "Step3",
                "密码已填写，但未找到可交互的提交按钮",
                "chatgpt_step3_password_submit_missing",
            )
        _log("Step3", f"密码已提交，正在确认页面状态（第 {attempt}/3 次）")
        state = _wait_after_state(page, "password", timeout=18)
        if state in {"verification", "about_you", "home"}:
            return {"success": True, "state": state}
        if state == "existing_account":
            return _existing_account_auth_failure()
        if state == "existing_login":
            return {"success": False, "existing_account": True, "error": "该邮箱已注册过 ChatGPT，进入了登录密码页"}
        if state == "closed":
            return {"success": False, "error": "浏览器已关闭"}

        page_errors = _extract_page_errors(page)
        page_text = str(page.html or "").lower()
        retryable = any(
            marker in page_text
            for marker in ("timed out", "something went wrong", "糟糕", "出错了")
        )
        if page_errors and not retryable:
            return _fail_with_page_diagnostics(
                page,
                "Step3",
                "注册密码提交被页面拒绝",
                "chatgpt_step3_password_rejected",
            )
        if attempt < 3:
            _log("Step3", "密码提交后页面未推进，重新定位表单后重试", "WARN")
            password_input = _wait_first_interactable(page, selectors, timeout=4)

    return _fail_with_page_diagnostics(
        page,
        "Step3",
        "密码提交后页面状态未推进",
        "chatgpt_step3_password_stalled",
    )


def _collect_registration_session(
    page,
    *,
    email: str,
    password: str,
    full_name: str,
    password_set_proven: bool,
    guard=None,
) -> dict:
    _log("Step6", "等待进入已登录页面...")
    start_session = time.time()
    expected_email = str(email or "").strip().casefold()
    while time.time() - start_session < 30:
        if _is_browser_closed(page):
            return {"success": False, "error": "浏览器已关闭"}
        _check_registration_guard(guard)
        if _has_existing_account_auth_error(page):
            return _existing_account_auth_failure()

        current_url = str(page.url or "")
        if "chatgpt.com" in current_url and "auth.openai.com" not in current_url:
            if "/api/auth/callback/" in current_url:
                time.sleep(5)
            _check_registration_guard(guard)
            session = _get_session(page)
            if session:
                access_token = str(session.get("access_token") or "").strip()
                actual_email = str(
                    session.get("authenticated_email")
                    or session.get("email")
                    or ((session.get("user") or {}).get("email") if isinstance(session.get("user"), dict) else "")
                    or ""
                ).strip()
                if access_token and actual_email and actual_email.casefold() != expected_email:
                    return _fail_with_page_diagnostics(
                        page,
                        "Step6",
                        f"注册会话邮箱不匹配：目标 {email}，实际 {actual_email}",
                        "chatgpt_step6_identity_mismatch",
                    )
                if not access_token or not actual_email:
                    time.sleep(1)
                    continue
                session["email"] = email
                session["password"] = password
                session["password_set_proven"] = bool(password_set_proven)
                session["name"] = full_name
                session["success"] = True
                _log("Step6", "注册成功，已获取 Session")
                return session
        time.sleep(1)

    return _fail_with_page_diagnostics(
        page,
        "Step6",
        "注册后未取得可验证身份的 Session 凭证",
        "chatgpt_step6_session_missing",
    )


# ── 注册流程 ──────────────────────────────────────────────────────

def do_register(
    page: ChromiumPage,
    email: str,
    password: str,
    mail_config: dict,
) -> dict:
    """
    在调用方持有的 page 中注册并取得同邮箱 Session；不创建、关闭浏览器。

    可用 ``with registration_log_context(log_fn):`` 绑定当前任务日志。
    成功返回 password_set_proven，仅确认提交注册密码并推进后为 True。
    已有账号分支返回 success=False, existing_account=True。

    mail_config: {
        "provider": "cfworker" | "outlook" | "mailbox",
        # 固定邮箱（包括 Gmail/iCloud）使用 mailbox + 绑定该邮箱的 reader。
        # reader(*, timeout, exclude_codes, received_after_ts) -> str | dict
        # dict: {code, reason, terminal}; reader 须保留发送前邮件 ID 基线，
        # 严格核对收件人、发件人和时间，不切换账号或退回历史验证码。
        "code_reader": callable,
        # mailbox 专用：调用方在发送邮箱前取得的有限正数时间戳。
        # 无有效值时沿用进入验证码步骤前 5 秒的筛选窗口。
        "not_before": float,
        # 零参回调；guard 必须通过抛异常阻止已失去任务归属的页面动作。
        "guard": callable,
        # 真实密码提交控件定位后、点击前调用；每次重试都会调用，异常阻止提交。
        "before_password_submit": callable,
        # CF Worker:
        "api_url": str,
        "admin_token": str,
        "custom_auth": str,
        # Outlook:
        "client_id": str,
        "refresh_token": str,
    }
    """
    name = generate_name()
    birthday = generate_birthday()
    full_name = f"{name['first']} {name['last']}"
    guard = mail_config.get("guard")

    try:
        # ── Step 1: 打开 ChatGPT ──
        _log("Step1", f"打开 ChatGPT 官网（最长等待 {WAIT_TIMEOUT} 秒）...")
        navigation_started_at = time.time()
        try:
            # DrissionPage defaults to three internal retries.  Combined with
            # a 30-second timeout that can leave a task apparently frozen for
            # more than two minutes before our state machine regains control.
            # The registration worker owns the retry policy, so keep this
            # first navigation to one bounded attempt.
            navigation_ok = page.get(
                CHATGPT_URL,
                timeout=WAIT_TIMEOUT,
                retry=0,
            )
        except TypeError:
            # Lightweight test doubles and older DrissionPage builds may not
            # expose the ``retry`` keyword.  They still retain the hard page
            # timeout passed here.
            navigation_ok = page.get(CHATGPT_URL, timeout=WAIT_TIMEOUT)
        navigation_elapsed = time.time() - navigation_started_at
        if navigation_ok is False:
            return _fail_with_page_diagnostics(
                page,
                "Step1",
                f"打开 ChatGPT 官网超时（{navigation_elapsed:.1f} 秒）",
                "chatgpt_step1_navigation_timeout",
            )
        time.sleep(4)

        if _is_browser_closed(page):
            return {"success": False, "error": "浏览器已关闭"}

        browser_error = _detect_browser_error(page)
        if browser_error:
            return {"success": False, "error": browser_error}
        if _has_existing_account_auth_error(page):
            return _existing_account_auth_failure()

        _log("Step1", f"页面已加载: {page.url}")

        # ── Step 2: 点击注册 → 填写邮箱 ──
        _log("Step2", f"填写邮箱: {email}")

        # 查找注册入口。入口打不开时不能继续扫描主页中的隐藏邮箱框。
        if "auth.openai.com" not in page.url:
            if _open_signup_entry(page):
                time.sleep(3)
            else:
                return _fail_with_page_diagnostics(
                    page,
                    "Step2",
                    "未找到可交互的注册入口",
                    "chatgpt_step2_signup_entry_missing",
                )

        # 填写邮箱
        email_input = _wait_email_input(page, timeout=20)

        if not email_input:
            return _fail_with_page_diagnostics(
                page,
                "Step2",
                "注册入口已打开，但未找到可交互的邮箱输入框",
                "chatgpt_step2_email_missing",
            )

        email_filled = _fill_interactable_input(page, email_input, email)
        if not email_filled:
            email_input = _wait_email_input(page, timeout=4)
            email_filled = bool(
                email_input and _fill_interactable_input(page, email_input, email)
            )
        if not email_filled:
            return _fail_with_page_diagnostics(
                page,
                "Step2",
                "邮箱输入框不可交互或填写后被页面清空",
                "chatgpt_step2_email_fill_failed",
            )
        time.sleep(0.3)

        # 点击继续
        _check_registration_guard(guard)
        submitted = (_click_visible_form_submit(page, guard=guard)
                     if callable(guard) else _click_visible_form_submit(page))
        if not submitted:
            return _fail_with_page_diagnostics(
                page,
                "Step2",
                "邮箱已填写，但未找到可交互的提交按钮",
                "chatgpt_step2_email_submit_failed",
            )
        time.sleep(3)
        _log("Step2", "邮箱已提交，正在确认注册页面状态")

        # ── Step 2.5-4: 状态机处理 Password / OTP 的 A/B 顺序 ──
        # 可能顺序：
        #   A: email → password → OTP → about-you
        #   B: email → OTP → password → about-you
        #   C: email → OTP → about-you（无密码注册，稍后由账号安全流程设置）
        state = _wait_registration_state(
            page,
            {"password", "verification", "about_you", "existing_login", "existing_account", "home", "error"},
            timeout=20,
        )
        if state in {"closed", "email", "unknown", "error"}:
            return _fail_with_page_diagnostics(
                page,
                "Step2.5",
                "邮箱提交后页面状态异常，未进入密码、验证码或资料步骤",
                "chatgpt_step2_state_unknown",
            )

        password_set_proven = False
        email_verified = False
        password_entry_attempted = False
        for _ in range(4):
            if state == "existing_account":
                return _existing_account_auth_failure()
            if state == "existing_login":
                return {"success": False, "existing_account": True, "error": "该邮箱已注册过 ChatGPT，进入了登录密码页"}

            if state == "verification":
                if email_verified:
                    return _fail_with_page_diagnostics(
                        page,
                        "Step4",
                        "验证码提交后仍返回验证码步骤",
                        "chatgpt_step4_verification_loop",
                    )
                if not password_set_proven and not password_entry_attempted:
                    password_entry_attempted = True
                    _check_registration_guard(guard)
                    if _click_signup_password_entry(page):
                        _log("Step3", "已选择页面上的密码注册入口，正在确认下一步")
                        state = _wait_after_state(page, "verification", timeout=8)
                        if state != "verification":
                            continue
                _log("Step4", "进入邮箱验证码步骤")
                verification_result = _run_email_verification(
                    page,
                    mail_config,
                    email,
                    log_prefix="Step4",
                )
                if not verification_result.get("success"):
                    return verification_result
                email_verified = True
                state = _wait_registration_state(
                    page,
                    {"password", "about_you", "home", "existing_login", "existing_account", "error"},
                    timeout=20,
                )
                continue

            if state == "password":
                if password_set_proven:
                    return _fail_with_page_diagnostics(
                        page,
                        "Step3",
                        "密码提交后仍返回密码步骤",
                        "chatgpt_step3_password_loop",
                    )
                _log("Step3", "进入注册密码步骤")
                password_result = _submit_signup_password(
                    page, password, guard=guard,
                    before_password_submit=mail_config.get("before_password_submit"),
                )
                if not password_result.get("success"):
                    return password_result
                password_set_proven = True
                state = str(password_result.get("state") or "unknown")
                continue

            break

        if state == "home" and not password_set_proven:
            # OTP 后直接回到首页通常表示这个邮箱已有账号；不能把一次
            # 登录误记为新注册成功。
            return {"success": False, "existing_account": True, "error": "该邮箱已注册过 ChatGPT，验证码后直接进入已有账号"}
        if state not in {"about_you", "home"}:
            return _fail_with_page_diagnostics(
                page,
                "Step4",
                "注册认证步骤结束后未进入资料页或已登录页面",
                "chatgpt_step4_unexpected_final_state",
            )
        if state == "home":
            _log("Step5", "认证完成后已直接进入 ChatGPT，跳过资料页")
            return _collect_registration_session(
                page,
                email=email,
                password=password,
                full_name=full_name,
                password_set_proven=password_set_proven,
                guard=guard,
            )

        # ── Step 5: 填写姓名和生日 ──
        _log("Step5", f"填写资料: {full_name}")
        if not _wait_for_url(page, "/about-you", timeout=12):
            if "/about-you" not in page.url:
                _log("Step5", f"未进入资料页, 当前: {page.url}", "WARN")

        # 填写姓名
        name_input = _wait_first_interactable(
            page,
            ('css:input[name="name"]', 'css:input[autocomplete="name"]'),
            timeout=8,
        )
        name_filled = bool(
            name_input and _fill_interactable_input(page, name_input, full_name)
        )
        if not name_filled:
            name_input = _wait_first_interactable(
                page,
                ('css:input[name="name"]', 'css:input[autocomplete="name"]'),
                timeout=3,
            )
            name_filled = bool(
                name_input and _fill_interactable_input(page, name_input, full_name)
            )
        if not name_filled:
            return _fail_with_page_diagnostics(
                page,
                "Step5",
                "资料页姓名输入框不可交互",
                "chatgpt_step5_name_input_failed",
            )
        time.sleep(0.3)

        # 填写生日 (spinbutton 方式)
        year = str(birthday["year"])
        month = str(birthday["month"]).zfill(2)
        day = str(birthday["day"]).zfill(2)

        fill_birthday_js = f"""
        return (async function() {{
            const sleep = (ms) => new Promise(r => setTimeout(r, ms));
            const usable = (el) => {{
                if (!el || el.disabled || el.readOnly || el.closest('[inert]')) return false;
                if (el.getAttribute('aria-disabled') === 'true' || el.getAttribute('aria-hidden') === 'true') return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                    && style.pointerEvents !== 'none' && Number(style.opacity || 1) > 0
                    && rect.width > 0 && rect.height > 0;
            }};
            // The current React-Aria build no longer guarantees that the
            // DateField group's generated id contains "birthday".  Resolve
            // it from the semantic year/month/day segments first, then keep
            // the old id selector as a compatibility fallback.
            const visibleSegments = Array.from(
                document.querySelectorAll('[role="spinbutton"][data-type]')
            ).filter(usable);
            const segmentGroup = visibleSegments
                .find(el => el.getAttribute('data-type') === 'year')
                ?.closest('[role="group"]');
            const dateField = segmentGroup || Array.from(
                document.querySelectorAll('[role="group"][id*="birthday"]')
            ).find(usable);
            if (!dateField) {{
                // 尝试年龄输入
                const ageInput = Array.from(
                    document.querySelectorAll('input[name="age"]')
                ).find(usable);
                if (ageInput) {{
                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value').set;
                    nativeInputValueSetter.call(ageInput, '{datetime.now().year - birthday["year"]}');
                    ageInput.dispatchEvent(new Event('input', {{bubbles: true}}));
                    ageInput.dispatchEvent(new Event('change', {{bubbles: true}}));
                    return 'age';
                }}
                // 尝试 React Aria Select
                const selects = Array.from(
                    document.querySelectorAll('.react-aria-Select')
                ).filter(usable);
                if (selects.length >= 3) {{
                    const setSelect = (root, value) => {{
                        const container = root.closest('[class*="selectItem"]') || root.parentElement;
                        const select = container?.querySelector('[data-testid="hidden-select-container"] select');
                        if (select) {{
                            select.value = value;
                            Array.from(select.options).forEach(o => o.selected = (o.value === value));
                            select.dispatchEvent(new Event('input', {{bubbles: true}}));
                            select.dispatchEvent(new Event('change', {{bubbles: true}}));
                        }}
                    }};
                    setSelect(selects[0], '{year}');
                    await sleep(200);
                    setSelect(selects[1], '{birthday["month"]}');
                    await sleep(200);
                    setSelect(selects[2], '{birthday["day"]}');
                    return 'select';
                }}
                return false;
            }}

            const fillSpinbutton = async (segment, valueStr) => {{
                if (!segment) return;
                segment.focus();
                segment.click();
                await sleep(100);
                for (const char of valueStr) {{
                    segment.dispatchEvent(new KeyboardEvent('keydown', {{key: char, code: 'Digit'+char, bubbles: true}}));
                    segment.dispatchEvent(new InputEvent('beforeinput', {{inputType: 'insertText', data: char, bubbles: true}}));
                    segment.dispatchEvent(new InputEvent('input', {{inputType: 'insertText', data: char, bubbles: true}}));
                    await sleep(50);
                }}
                segment.dispatchEvent(new FocusEvent('blur', {{bubbles: true}}));
                await sleep(100);
            }};

            const yearSeg = dateField.querySelector('[role="spinbutton"][data-type="year"]');
            const monthSeg = dateField.querySelector('[role="spinbutton"][data-type="month"]');
            const daySeg = dateField.querySelector('[role="spinbutton"][data-type="day"]');
            if (![yearSeg, monthSeg, daySeg].every(usable)) return false;
            await fillSpinbutton(yearSeg, '{year}');
            await sleep(150);
            await fillSpinbutton(monthSeg, '{month}');
            await sleep(150);
            await fillSpinbutton(daySeg, '{day}');
            return 'spinbutton';
        }})();
        """
        birthday_mode = page.run_js(fill_birthday_js)
        if not birthday_mode:
            return _fail_with_page_diagnostics(
                page,
                "Step5",
                "资料页未找到可交互的生日或年龄控件",
                "chatgpt_step5_birthday_missing",
            )
        time.sleep(1)

        # 勾选同意复选框（韩国 IP 等场景）
        page.run_js("""
            const cb = Array.from(document.querySelectorAll(
                'input[name="allCheckboxes"][type="checkbox"]'
            )).find((el) => {
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                const label = el.closest('label');
                const labelRect = label?.getBoundingClientRect();
                return !el.disabled && !el.closest('[inert]')
                    && style.visibility !== 'hidden'
                    && ((rect.width > 0 && rect.height > 0)
                        || (labelRect && labelRect.width > 0 && labelRect.height > 0));
            });
            if (cb && !cb.checked) {
                const label = cb.closest('label');
                if (label) label.click(); else cb.click();
            }
        """)
        time.sleep(0.5)

        # 点击完成，只操作当前可见资料表单。
        submitted = False
        submit_deadline = time.time() + 6
        while time.time() < submit_deadline and not submitted:
            _check_registration_guard(guard)
            submitted = (_click_visible_form_submit(page, guard=guard)
                         if callable(guard) else _click_visible_form_submit(page))
            if not submitted:
                time.sleep(0.5)
        if not submitted:
            return _fail_with_page_diagnostics(
                page,
                "Step5",
                "资料已填写，但未找到可交互的完成按钮",
                "chatgpt_step5_submit_missing",
            )

        time.sleep(3)
        _log("Step5", "资料已提交")

        # ── Step 6: 获取 Session ──
        return _collect_registration_session(
            page,
            email=email,
            password=password,
            full_name=full_name,
            password_set_proven=password_set_proven,
            guard=guard,
        )

    except Exception as e:
        err = str(e)
        if _is_browser_closed(page):
            return {"success": False, "error": "浏览器已关闭"}
        _log("Register", f"异常: {e}", "ERROR")
        diagnosed = _fail_with_page_diagnostics(
            page,
            "Register",
            f"注册浏览器操作异常: {err}",
            "chatgpt_register_exception",
        )
        return diagnosed


def _fill_verification_code(page, code: str, *, guard=None) -> bool:
    """填写 6 位验证码（兼容单输入框和分离输入框）"""
    normalized = str(code or "").strip()
    if not normalized:
        return False

    single = _first_interactable(
        page,
        (
            'css:input[name="code"]',
            'css:input[autocomplete="one-time-code"]',
            'css:input[type="text"][maxlength="6"]',
            'css:input[inputmode="numeric"]',
            'css:input[data-testid="code-input"]',
        ),
        timeout=0.5,
    )
    if single:
        filled = (_fill_interactable_input(page, single, normalized, retries=2, guard=guard)
                  if callable(guard) else _fill_interactable_input(page, single, normalized, retries=2))
        if filled:
            return True

    _check_registration_guard(guard)
    try:
        # 分离的单字符输入框。遍历全部节点并过滤隐藏/禁用副本，不能
        # 使用 querySelector()，否则会再次命中零尺寸的第一个节点。
        result = page.run_js("""
            const code = String(arguments[0] || '');
            const usable = (el) => {
                if (!el || el.disabled || el.readOnly || el.closest('[inert]')) return false;
                if (el.getAttribute('aria-disabled') === 'true' || el.getAttribute('aria-hidden') === 'true') return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                    && style.pointerEvents !== 'none' && Number(style.opacity || 1) > 0
                    && rect.width > 0 && rect.height > 0;
            };
            const singles = Array.from(document.querySelectorAll('input[maxlength="1"]'))
                .filter(usable);
            if (singles.length >= code.length && code.length > 0) {
                for (let i = 0; i < code.length; i++) {
                    const nativeSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value').set;
                    nativeSetter.call(singles[i], code[i]);
                    singles[i].dispatchEvent(new Event('input', {bubbles: true}));
                    singles[i].dispatchEvent(new Event('change', {bubbles: true}));
                }
                return true;
            }
            return false;
        """, normalized)
        return bool(result)
    except Exception:
        return False


def _session_cookie_from_browser_map(cookies: dict) -> str:
    for base in (
        "__Secure-authjs.session-token",
        "__Secure-next-auth.session-token",
    ):
        direct = str(cookies.get(base) or "")
        if direct:
            return direct
        prefix = f"{base}."
        chunks = sorted(
            (
                (int(str(name)[len(prefix):]), str(value))
                for name, value in cookies.items()
                if str(name).startswith(prefix)
                and str(name)[len(prefix):].isdigit()
                and str(value or "")
            ),
            key=lambda item: item[0],
        )
        if chunks and [index for index, _ in chunks] == list(range(len(chunks))):
            return "".join(value for _, value in chunks)
    return ""


def _get_session(page) -> Optional[dict]:
    """从浏览器获取 Session 信息（含完整 CDP cookies）"""
    try:
        cookies_kv = {}
        cdp_cookies_raw = []
        try:
            cdp_result = page.run_cdp("Network.getAllCookies")
            if cdp_result and cdp_result.get("cookies"):
                cdp_cookies_raw = cdp_result["cookies"]
                for c in cdp_cookies_raw:
                    name = c.get("name", "")
                    value = c.get("value", "")
                    if name and value:
                        cookies_kv[name] = value
        except Exception:
            for c in page.cookies():
                name = c.get("name", "")
                value = c.get("value", "")
                if name and value:
                    cookies_kv[name] = value

        session_token = _session_cookie_from_browser_map(cookies_kv)
        access_token = ""
        authenticated_email = ""
        session_user = {}
        session_response_ok = False

        # 从服务端 Session 同时确认凭证和账号身份。仅有 chatgpt.com URL
        # 或匿名 cookie 不能证明注册成功。
        try:
            resp = page.run_js("""
                return fetch('/api/auth/session', {
                    credentials: 'include', cache: 'no-store'
                }).then(async (r) => {
                    let body = null;
                    try { body = await r.json(); } catch (_) {}
                    return {ok: r.ok, status: r.status, body};
                }).catch(() => null);
            """)
            if resp and isinstance(resp, dict):
                body = resp.get("body") if isinstance(resp.get("body"), dict) else {}
                session_response_ok = bool(resp.get("ok"))
                access_token = str(body.get("accessToken") or "")
                session_user = body.get("user") if isinstance(body.get("user"), dict) else {}
                authenticated_email = str(session_user.get("email") or body.get("email") or "")
        except Exception:
            pass

        return {
            "session_token": session_token,
            "access_token": access_token,
            "authenticated": bool(access_token),
            "authenticated_email": authenticated_email,
            "email": authenticated_email,
            "user": session_user,
            "session_response_ok": session_response_ok,
            "cookies": cookies_kv,
            "cdp_cookies": cdp_cookies_raw,
        }
    except Exception:
        return None


def save_cookies(result: dict, output_path: str = "") -> dict:
    """
    保存注册结果的 cookies 到 JSON 文件

    result: do_register / register_chatgpt 的返回值
    output_path: 指定保存路径，留空则自动生成到 Results_ChatGPT/
    """
    if not result.get("success"):
        return {"success": False, "error": "注册未成功，无 cookies 可保存"}

    cookies = result.get("cookies", {})
    cdp_cookies = result.get("cdp_cookies", [])
    email = result.get("email", "unknown")

    if not cookies and not cdp_cookies:
        return {"success": False, "error": "cookies 为空"}

    try:
        if output_path:
            cookie_path = output_path
            if not os.path.isabs(cookie_path):
                cookie_path = os.path.join(os.getcwd(), cookie_path)
        else:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            ts = int(time.time() * 1000)
            safe_email = email.replace("@", "_at_").replace(".", "_")
            cookie_path = os.path.join(RESULTS_DIR, f"cookie_{safe_email}_{ts}.json")

        payload = {
            "email": email,
            "password": result.get("password", ""),
            "name": result.get("name", ""),
            "session_token": result.get("session_token", ""),
            "access_token": result.get("access_token", ""),
            "cookies": cookies,
            "cdp_cookies": cdp_cookies,
            "saved_at": datetime.now().isoformat(),
            "source": "drission_register",
        }

        # 确保目标目录存在
        os.makedirs(os.path.dirname(cookie_path), exist_ok=True)

        with open(cookie_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        _log("Save", f"Cookies 已保存: {cookie_path}")
        return {"success": True, "path": cookie_path}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── 主入口 ────────────────────────────────────────────────────────

def register_chatgpt(
    email: str = "",
    password: str = "",
    proxy: str = "",
    headless: bool = False,
    cfworker_api_url: str = "",
    cfworker_admin_token: str = "",
    cfworker_custom_auth: str = "",
    cfworker_domain: str = "",
    cfworker_quick_api_url: str = "",
    save_cookie_path: str = "",
    mail_provider: str = "cfworker",
    cfworker_code_reader: Optional[Callable] = None,
    outlook_client_id: str = "",
    outlook_refresh_token: str = "",
    outlook_code_reader: Optional[Callable] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    一键注册 ChatGPT 账号

    mail_provider: "cfworker" 或 "outlook"
    cfworker_*: CF Worker 参数（mail_provider=cfworker 时使用）
    outlook_*: Outlook 参数（mail_provider=outlook 时使用）
    *_code_reader: 应用注入的、绑定本次邮箱及发送前基线的取码器
    log_fn: 当前注册任务的日志回调（使用 ContextVar 做并发隔离）
    """
    import requests

    log_token = _REGISTER_LOG_FN.set(log_fn if callable(log_fn) else None)
    page = None
    try:
        # 根据 mail_provider 确定邮箱来源
        if mail_provider == "outlook":
            # Outlook: 邮箱由外部传入，必须提供 email
            if not email:
                return {"success": False, "error": "Outlook 模式需要提供邮箱地址"}
            _log("Main", f"Outlook 邮箱: {email}")

        elif not email:
            # CF Worker: 自动生成邮箱
            if not cfworker_api_url:
                return {"success": False, "error": "未提供邮箱且 CF Worker 未配置"}

            headers = {
                "accept": "application/json, text/plain, */*",
                "content-type": "application/json",
                "x-admin-auth": cfworker_admin_token,
            }
            if cfworker_custom_auth:
                headers["x-custom-auth"] = cfworker_custom_auth

            name_part = "".join(random.choices(string.ascii_lowercase, k=6)) + "".join(random.choices(string.digits, k=4))
            payload = {"enablePrefix": True, "name": name_part}
            if cfworker_domain:
                payload["domain"] = cfworker_domain

            api_base = cfworker_api_url.rstrip("/")
            resp = requests.post(
                f"{api_base}/api/new_address",
                headers=headers,
                json=payload,
                timeout=15,
            )
            if resp.status_code >= 400:
                resp = requests.post(
                    f"{api_base}/admin/new_address",
                    headers=headers,
                    json=payload,
                    timeout=15,
                )
            if resp.status_code != 200:
                return {"success": False, "error": f"CF Worker 创建邮箱失败: HTTP {resp.status_code}"}

            data = resp.json()
            email = data.get("email", data.get("address", ""))
            if not email:
                return {"success": False, "error": "CF Worker 未返回邮箱地址"}

            _log("Main", f"已生成邮箱: {email}")

        if not password:
            password = generate_password()
            _log("Main", f"已生成随机密码（长度 {len(password)}，内容不写入日志）")

        # 构建 mail_config
        if mail_provider == "outlook":
            mail_config = {
                "provider": "outlook",
                "client_id": outlook_client_id,
                "refresh_token": outlook_refresh_token,
                "code_reader": outlook_code_reader,
            }
        else:
            mail_config = {
                "provider": "cfworker",
                "api_url": cfworker_api_url.rstrip("/") if cfworker_api_url else "",
                "admin_token": cfworker_admin_token,
                "custom_auth": cfworker_custom_auth,
                "code_reader": cfworker_code_reader,
                "quick_api_url": (
                    str(cfworker_quick_api_url or "").strip().rstrip("/")
                    or "https://temp-api.cursom.shop"
                ),
            }

        # 创建浏览器
        page = create_browser(proxy=proxy, headless=headless)
        if not page:
            return {"success": False, "error": "浏览器创建失败"}

        # 执行注册
        result = do_register(
            page=page,
            email=email,
            password=password,
            mail_config=mail_config,
        )

        # 注册成功后自动保存 Cookies
        if result.get("success"):
            # Preserve the proof produced by the state machine.  Passwordless
            # signup variants intentionally remain unproven so the post-
            # registration security workflow can set a password afterwards.
            result["password_set_proven"] = bool(
                result.get("password_set_proven", False)
            )
            save_result = save_cookies(result, output_path=save_cookie_path)
            if save_result.get("success"):
                result["cookie_file"] = save_result["path"]
            else:
                result["cookie_save_error"] = save_result.get("error", "")

        return result

    finally:
        if page:
            try:
                page.quit(force=True)
            except Exception:
                pass
        _REGISTER_LOG_FN.reset(log_token)


# ── CLI ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DrissionPage ChatGPT 注册")
    parser.add_argument("--email", default="", help="注册邮箱（留空自动生成）")
    parser.add_argument("--password", default="", help="密码（留空自动生成）")
    parser.add_argument("--proxy", default="", help="代理")
    parser.add_argument("--headless", action="store_true", help="无头模式")
    parser.add_argument("--output", "-o", default="", help="Cookie 保存路径（留空自动生成）")
    parser.add_argument("--cfworker-api", default="", help="CF Worker API URL")
    parser.add_argument("--cfworker-token", default="", help="CF Worker Admin Token")
    parser.add_argument("--cfworker-auth", default="", help="CF Worker Custom Auth")
    parser.add_argument("--cfworker-domain", default="", help="CF Worker 域名")
    parser.add_argument("--cfworker-quick-api", default="", help="Quick Mails API URL")
    parser.add_argument("--mail-provider", default="cfworker", choices=["cfworker", "outlook"], help="邮箱服务")
    parser.add_argument("--outlook-client-id", default="", help="Outlook Client ID")
    parser.add_argument("--outlook-refresh-token", default="", help="Outlook Refresh Token")
    args = parser.parse_args()

    result = register_chatgpt(
        email=args.email,
        password=args.password,
        proxy=args.proxy,
        headless=args.headless,
        cfworker_api_url=args.cfworker_api,
        cfworker_admin_token=args.cfworker_token,
        cfworker_custom_auth=args.cfworker_auth,
        cfworker_domain=args.cfworker_domain,
        cfworker_quick_api_url=args.cfworker_quick_api,
        save_cookie_path=args.output,
        mail_provider=args.mail_provider,
        outlook_client_id=args.outlook_client_id,
        outlook_refresh_token=args.outlook_refresh_token,
    )

    print("\n" + "=" * 60)
    if result.get("success"):
        print("注册成功!")
        print(f"  邮箱: {result.get('email')}")
        print("  密码: 已设置（内容不写入终端）")
        print(f"  姓名: {result.get('name')}")
        if result.get("session_token"):
            print("  Session Token: 已获取（内容不写入终端）")
        if result.get("access_token"):
            print("  Access Token: 已获取（内容不写入终端）")
        if result.get("cookie_file"):
            print(f"  Cookie 文件: {result['cookie_file']}")
    else:
        print(f"注册失败: {result.get('error')}")
    print("=" * 60)
