"""Create one Google app password in an exclusively owned browser.

The generated credential is passed directly to the persistence callback. Neither
page text nor credentials are returned, logged, or included in failure messages.
An uncertain create is terminal: a caller must not retry it as a fresh creation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from urllib.parse import urlsplit

from services import gmail_verifier as verifier


_ACCOUNT_URL = "https://myaccount.google.com/"
_APP_PASSWORDS_URL = "https://myaccount.google.com/apppasswords"
_OVERALL_SECONDS = 240
_PAGE_SECONDS = 25
_APP_NAME_LABEL = re.compile(r"^(App name|应用名称|应用名|應用程式名稱)(?:\s+\1)?$", re.I)
_MESSAGES = {
    **verifier._MESSAGES,
    "app_password_created": "已创建应用专用密码并安全保存，接下来验证 Gmail 收件授权",
    "invalid_app_name": "应用名称为空、过长或包含不支持的字符，未创建应用专用密码",
    "missing_persistence_callbacks": "缺少创建前持久校验或凭证保存回调，未创建应用专用密码",
    "account_mismatch": "当前 Google 账号与目标邮箱不一致，未继续创建应用专用密码",
    "account_identity_unconfirmed": "未能从 Google 账号页面确认目标邮箱，未创建应用专用密码",
    "app_passwords_unavailable": "该 Google 账号当前不支持应用专用密码；未修改两步验证或安全设置",
    "unsupported_app_password_page": "未识别到应用名称输入框和创建按钮，未创建应用专用密码",
    "app_name_already_exists": "此应用名称已存在，未重复创建应用专用密码",
    "create_guard_failed": "创建前持久校验未通过，未提交应用专用密码创建",
    "create_result_unknown": "应用专用密码创建已提交，但结果未能确认；不会自动重复创建",
    "credential_persist_failed": "应用专用密码已生成，但安全保存未完成；不会自动重复创建",
    "provision_failed": "应用专用密码配置未完成，请查看失败步骤后重试",
    "provision_timeout": "应用专用密码配置页面等待超时，未提交创建",
}


# Account identity comes exclusively from the active Google-account avatar,
# never from arbitrary body text or the account-switcher list. These helpers are
# also executed inside the create/extract evaluations, avoiding a navigation
# race between checking the origin and touching a sensitive control.
_DOM_HELPERS = r"""
  const visible = el => !!el && !!el.getClientRects().length &&
    getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
  const official = location.origin === 'https://myaccount.google.com';
  const appPath = /^\/(?:u\/\d+\/)?apppasswords\/?$/.test(location.pathname);
  const exactAppLabel = /^(App name|应用名称|应用名|應用程式名稱)(?:\s+\1)?$/i;
  const exactCreateLabel = /^(?:Create|创建|建立)$/i;
  const controls = selector => Array.from(document.querySelectorAll(selector)).filter(visible);
  const identity = () => {
    const emails = new Set();
    for (const el of controls('a[aria-label],button[aria-label],[role="button"][aria-label]')) {
      const label = (el.getAttribute('aria-label') || '').trim();
      if (!/^(?:Google Account|Google (?:账号|帐号|帐户|帳戶|帳號))\s*[:：]/i.test(label)) continue;
      for (const email of label.match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}/ig) || []) {
        emails.add(email.toLowerCase());
      }
    }
    if (!emails.size) return 'unknown';
    return emails.size === 1 && emails.has(expectedEmail) ? 'match' : 'mismatch';
  };
  const inputName = el => [el.getAttribute('aria-label') || '',
    ...Array.from(el.labels || []).map(label => label.innerText || ''),
    ...(el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
      .map(id => document.getElementById(id)?.innerText || '')];
  const appInputs = () => controls('input').filter(el => el.type === 'text')
    .filter(el => inputName(el).some(name => exactAppLabel.test(name.trim())));
  const createButtons = () => controls('button,[role="button"]').filter(el =>
    exactCreateLabel.test((el.getAttribute('aria-label') || el.innerText || '').trim()) &&
    !el.disabled && el.getAttribute('aria-disabled') !== 'true');
  const appExists = () => controls('tr,[role="listitem"],[role="row"]')
    .some(row => Array.from(row.querySelectorAll('span,div,td')).some(el =>
      visible(el) && (el.innerText || '').trim() === appName));
  const generatedDialogs = () => controls('[role="dialog"],dialog').filter(dialog => {
    const heading = [dialog.getAttribute('aria-label') || '',
      ...(dialog.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
        .map(id => document.getElementById(id)?.innerText || ''),
      ...Array.from(dialog.querySelectorAll('h1,h2,h3,[role="heading"]')).filter(visible)
        .map(el => el.innerText || '')];
    return heading.some(text => /^(?:Generated app password|Your app password(?: for your device)?|已生成的应用专用密码|您的应用专用密码|你的应用专用密码|產生的應用程式密碼|您的應用程式密碼)$/i.test(text.trim()));
  });
"""

_OBSERVE_JS = "([expectedEmail, appName]) => {" + _DOM_HELPERS + r"""
  if (!official) return {official: false};
  const text = (document.body && document.body.innerText) || '';
  return {official: true, identity: identity(), app_path: appPath,
    app_input: appInputs().length === 1, create_button: createButtons().length === 1,
    generated_dialog: generatedDialogs().length === 1, existing_app: appExists(),
    unavailable: /setting you are looking for is not available for your account|app passwords (?:are|is) not available|(?:此|这项|該)设置不适用于您的(?:账号|帐号|帐户)|您的(?:账号|帐号|帐户)无法使用(?:此设置|应用专用密码)|這項設定不適用於你的帳戶/i.test(text)};
}"""

_CREATE_JS = "([expectedEmail, appName]) => {" + _DOM_HELPERS + r"""
  if (!official || !appPath) return 'unexpected_page';
  const who = identity();
  if (who !== 'match') return who === 'mismatch' ? 'account_mismatch' : 'account_identity_unconfirmed';
  if (appExists()) return 'app_name_already_exists';
  const inputs = appInputs(), buttons = createButtons();
  if (inputs.length !== 1 || inputs[0].value !== appName || buttons.length !== 1)
    return 'unsupported_app_password_page';
  buttons[0].click();
  return 'clicked';
}"""

_EXTRACT_JS = "([expectedEmail, appName]) => {" + _DOM_HELPERS + r"""
  if (!official || !appPath || identity() !== 'match') return '';
  const dialogs = generatedDialogs();
  if (dialogs.length !== 1) return '';
  const values = new Set();
  for (const el of Array.from(dialogs[0].querySelectorAll('span,code,samp,output,div,strong,p')).filter(visible)) {
    const text = (el.innerText || '').trim();
    if (/^(?:[a-z]{16}|[a-z]{4}(?:\s+[a-z]{4}){3})$/.test(text)) values.add(text.replace(/\s/g, ''));
  }
  return values.size === 1 ? Array.from(values)[0] : '';
}"""


class _Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _check_cancel(should_stop, deadline):
    if callable(should_stop) and should_stop():
        raise _Failure("cancelled")
    if time.monotonic() >= deadline:
        raise _Failure("provision_timeout")


def _official_url(page):
    parsed = urlsplit(page.url)
    if (parsed.scheme != "https" or parsed.hostname not in {
            "accounts.google.com", "mail.google.com", "gds.google.com", "myaccount.google.com"}
            or parsed.username or parsed.password or parsed.port not in {None, 443}):
        raise _Failure("unexpected_page")
    return parsed


def _observe_account(page, email, app_name):
    parsed = _official_url(page)
    if parsed.hostname != "myaccount.google.com":
        raise _Failure("unexpected_page")
    state = page.evaluate(_OBSERVE_JS, [email, app_name])
    if not state.get("official"):
        raise _Failure("unexpected_page")
    return state


class _OriginCheckedPage:
    """Apply strict ports/userinfo checks to the reused read-only login flow."""
    def __init__(self, page):
        self._page = page

    @property
    def url(self):
        _official_url(self._page)
        return self._page.url

    def __getattr__(self, name):
        if name in {"evaluate", "locator", "get_by_role"}:
            _official_url(self._page)
        return getattr(self._page, name)


def _reauth_step(page, password, recovery_email, secret, submitted, progress, should_stop, deadline, used_windows=None):
    """Handle existing verification factors only; no enroll/consent actions."""
    host, path, state = verifier._observe(page)
    if host != "accounts.google.com":
        raise _Failure("unexpected_page")
    failure = verifier._failure_state(state)
    if failure:
        raise _Failure(failure)
    if "/speedbump/" in path:
        if path.rstrip("/") != verifier._PASSKEY_ENROLLMENT_PATH or "skip" in submitted:
            raise _Failure("unexpected_page")
        if state.get("optional_skip"):
            verifier._skip_optional_passkey(page, deadline)
            submitted.add("skip")
        return
    action = None
    if state.get("password") and "password" not in submitted:
        action = ("password", "正在再次验证 Google 登录密码", 'input[name="Passwd"],input[type="password"]', password, "#passwordNext")
    elif state.get("totp") and "totp" not in submitted:
        submitted.add("totp")
        verifier._submit_totp(page, secret, progress, should_stop, deadline,
                              step="reauth_totp", message="正在再次验证 Authenticator 2FA", used_windows=used_windows)
    elif state.get("recovery") and "recovery" not in submitted and recovery_email:
        action = ("recovery", "正在确认已配置的辅助邮箱", 'input[name="knowledgePreregisteredEmailResponse"],#knowledge-preregistered-email-response', recovery_email, "")
    elif state.get("authenticator_choice") and "authenticator_choice" not in submitted and secret:
        page.locator('[data-challengetype="6"]:visible').first.click(timeout=verifier._timeout_ms(deadline))
        submitted.add("authenticator_choice")
    elif state.get("recovery_choice") and "recovery_choice" not in submitted and recovery_email:
        page.locator('[data-challengetype="12"]:visible').first.click(timeout=verifier._timeout_ms(deadline))
        submitted.add("recovery_choice")
    elif not state.get("totp") and (state.get("device") or any(part in path for part in (
            "/challenge/dp", "/challenge/ipp", "/challenge/iap", "/challenge/idv"))):
        raise _Failure("device_verification_required")
    elif state.get("email"):
        # An app-password reauth must retain the already confirmed account.
        # Returning to a new account picker is not permission to switch users.
        raise _Failure("account_identity_unconfirmed")
    if action:
        step, message, selector, value, next_selector = action
        verifier._progress(progress, "reauth_" + step, message)
        submitted.add(step)
        verifier._fill_submit(page, selector, value, next_selector, deadline)


def _wait_account(page, email, password, recovery_email, secret, app_name, progress, should_stop, deadline, *, app_page, used_windows=None):
    submitted = set()
    reauth_started = False
    app_identity_reported = False
    wait_until = min(deadline, time.monotonic() + _PAGE_SECONDS)
    while True:
        _check_cancel(should_stop, deadline)
        observed_host = None
        try:
            parsed = _official_url(page)
            observed_host = parsed.hostname
            if parsed.hostname == "accounts.google.com":
                if not reauth_started:
                    # Google may reject a TOTP reused from initial login. Allow
                    # the next 30-second window plus navigation, without ever
                    # extending this flow's overall deadline.
                    wait_until = min(deadline, max(wait_until, time.monotonic() + 60))
                    reauth_started = True
                _reauth_step(page, password, recovery_email, secret, submitted, progress, should_stop, deadline, used_windows)
            elif parsed.hostname == "myaccount.google.com":
                state = _observe_account(page, email, app_name)
                if state.get("identity") == "mismatch":
                    raise _Failure("account_mismatch")
                if state.get("unavailable"):
                    raise _Failure("app_passwords_unavailable")
                if state.get("identity") == "match":
                    if not app_page:
                        return state
                    if not app_identity_reported:
                        app_identity_reported = True
                        verifier._progress(progress, "app_password", "已确认目标 Google 账号，正在等待应用专用密码表单")
                    if state.get("app_path") and state.get("existing_app"):
                        raise _Failure("app_name_already_exists")
                    if state.get("app_path") and state.get("app_input"):
                        return state
            else:
                raise _Failure("unexpected_page")
        except (verifier._Failure, _Failure) as exc:
            # The outer URL read can race a successful verification redirect.
            # Retry only a verified transition between these two Google hosts;
            # an unchanged unsupported page or any other origin stays fatal.
            transition_hosts = {"accounts.google.com", "myaccount.google.com"}
            if exc.code != "unexpected_page" or observed_host not in transition_hosts:
                raise
            current_host = _official_url(page).hostname
            if current_host not in transition_hosts or current_host == observed_host:
                raise
        except Exception as exc:
            if verifier._exception_category(exc) != "navigation_in_progress":
                raise
        if time.monotonic() >= wait_until:
            raise _Failure("unsupported_app_password_page" if app_page else "account_identity_unconfirmed")
        time.sleep(0.25)


def _wait_create_ready(page, email, app_name, should_stop, deadline):
    """Wait for Google's asynchronous name validation before marking create."""
    wait_until = min(deadline, time.monotonic() + _PAGE_SECONDS)
    while True:
        _check_cancel(should_stop, deadline)
        state = _observe_account(page, email, app_name)
        if state.get("identity") != "match":
            raise _Failure("account_mismatch" if state.get("identity") == "mismatch" else "account_identity_unconfirmed")
        if not state.get("app_path") or not state.get("app_input"):
            raise _Failure("unsupported_app_password_page")
        if state.get("existing_app"):
            raise _Failure("app_name_already_exists")
        if state.get("create_button"):
            return
        if time.monotonic() >= wait_until:
            raise _Failure("unsupported_app_password_page")
        time.sleep(0.25)


def _run_provision(page, email, password, recovery_email, secret, app_name, progress, should_stop, deadline,
                   before_create, on_created, outcome):
    # This tracker belongs only to this browser flow/account, never global state.
    used_windows = set()
    verifier._run_login(_OriginCheckedPage(page), email, password, recovery_email, secret, progress, should_stop,
                        deadline, used_windows=used_windows)
    _check_cancel(should_stop, deadline)
    verifier._progress(progress, "account", "正在核对 Google 账号身份")
    verifier._navigate(page, _ACCOUNT_URL, deadline)
    _wait_account(page, email, password, recovery_email, secret, app_name, progress, should_stop, deadline,
                  app_page=False, used_windows=used_windows)
    verifier._progress(progress, "app_password", "正在打开应用专用密码设置")
    verifier._navigate(page, _APP_PASSWORDS_URL, deadline)
    _wait_account(page, email, password, recovery_email, secret, app_name, progress, should_stop, deadline,
                  app_page=True, used_windows=used_windows)
    _check_cancel(should_stop, deadline)
    # Only the exact, visible and uniquely named input is eligible for filling.
    _observe_account(page, email, app_name)
    page.get_by_role("textbox", name=_APP_NAME_LABEL).fill(app_name, timeout=verifier._timeout_ms(deadline))
    _wait_create_ready(page, email, app_name, should_stop, deadline)
    _check_cancel(should_stop, deadline)
    verifier._progress(progress, "creating", "正在持久记录创建操作并生成应用专用密码")
    try:
        if before_create() is False:
            raise _Failure("create_guard_failed")
    except Exception:
        raise _Failure("create_guard_failed") from None
    # This is the sole mutation boundary. Any transport failure here is unknown,
    # even if Playwright cannot tell whether its evaluation reached the browser.
    outcome["creation_attempted"] = True
    result = page.evaluate(_CREATE_JS, [email, app_name])
    if result != "clicked":
        # A returned refusal proves the JS did not call the create control.
        outcome["creation_attempted"] = False
        raise _Failure(result if result in _MESSAGES else "unsupported_app_password_page")
    wait_until = min(deadline, time.monotonic() + _PAGE_SECONDS)
    while True:
        # A cancellation after submission cannot undo a remote create. Try the
        # read-only extraction first so a just-generated secret is not lost.
        try:
            _official_url(page)
            password_value = page.evaluate(_EXTRACT_JS, [email, app_name])
        except Exception as exc:
            if verifier._exception_category(exc) != "navigation_in_progress":
                raise
            password_value = ""
        if isinstance(password_value, str) and re.fullmatch(r"[a-z]{16}", password_value):
            try:
                if on_created(password_value) is False:
                    raise _Failure("credential_persist_failed")
                outcome["credential_saved"] = True
            except Exception:
                raise _Failure("credential_persist_failed") from None
            finally:
                password_value = None
            return "app_password_created"
        _check_cancel(should_stop, deadline)
        if time.monotonic() >= wait_until:
            raise _Failure("create_result_unknown")
        time.sleep(0.25)


def provision_app_password(email, login_password, recovery_email, totp_secret, proxy_url="", app_name="",
                           progress=None, should_stop=None, before_create=None, on_created=None):
    """Create at most once; pass the credential only to ``on_created``.

    Both callbacks must exist before starting. ``before_create`` must persist a
    compare-and-set submission marker and may return False to reject. A callback
    exception is always redacted. ``on_created`` must encrypt/persist before it
    returns; False means failure. Neither callback is automatically retried.
    """
    native = playwright = None
    deadline = time.monotonic() + _OVERALL_SECONDS
    outcome = {"creation_attempted": False, "credential_saved": False}
    code = "provision_failed"
    cleanup_complete = True
    try:
        email = str(email or "").strip().lower()
        proxy_url = str(proxy_url or "").strip()
        app_name = str(app_name or "Gmail IMAP").strip()
        verifier._validate(email, login_password, proxy_url)
        if not app_name or len(app_name) > 100 or any(ord(char) < 32 or ord(char) == 127 for char in app_name):
            raise _Failure("invalid_app_name")
        if not callable(before_create) or not callable(on_created):
            raise _Failure("missing_persistence_callbacks")
        _check_cancel(should_stop, deadline)
        verifier._progress(progress, "browser", "正在启动独立浏览器配置 Gmail 收件授权")
        native = verifier._start_browser(proxy_url, deadline)
        _check_cancel(should_stop, deadline)
        playwright = verifier._start_playwright()
        browser = playwright.chromium.connect_over_cdp(
            f"http://{native.address}", timeout=verifier._timeout_ms(deadline, 15000))
        _check_cancel(should_stop, deadline)
        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.pages[0] if context.pages else context.new_page()
        page.set_default_timeout(10000)
        code = _run_provision(page, email, login_password, recovery_email, totp_secret, app_name,
                              progress, should_stop, deadline, before_create, on_created, outcome)
    except (_Failure, verifier._Failure) as exc:
        code = exc.code if exc.code in _MESSAGES else "provision_failed"
    except verifier.BrowserInitializationError:
        code = "browser_init_failed"
    except Exception as exc:
        code = {"timeout": "network_timeout", "navigation_in_progress": "navigation_error",
                "browser_closed": "browser_closed"}.get(verifier._exception_category(exc), "provision_failed")
    finally:
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                cleanup_complete = False
        if native is not None:
            try:
                if native.quit() is False:
                    cleanup_complete = False
            except Exception:
                cleanup_complete = False
    if outcome["creation_attempted"] and not outcome["credential_saved"] and code != "credential_persist_failed":
        code = "create_result_unknown"
    # A saved credential remains a committed success even if browser shutdown
    # fails. Losing that distinction would encourage unsafe duplicate creation.
    if outcome["credential_saved"]:
        code = "app_password_created"
    elif not cleanup_complete and not outcome["creation_attempted"]:
        code = "browser_cleanup_failed"
    result = {"ok": outcome["credential_saved"], "code": code, "message": _MESSAGES[code],
              **outcome, "cleanup_complete": cleanup_complete,
              "checked_at": datetime.now(timezone.utc).isoformat()}
    verifier._progress(progress, "completed" if result["ok"] else "failed", result["message"])
    return result
