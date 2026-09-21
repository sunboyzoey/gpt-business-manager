"""Bounded callers can inspect password-login transitions without credentials.

This module neither fills fields nor retries. ``snapshot`` is read-only;
``guarded_continue`` can submit the one current email form once after an
in-script exact readback. Route ``advanced`` is never proof of authentication.
"""
from __future__ import annotations

import json
from typing import Any


_ROUTES = frozenset({"email", "password", "email_otp", "authenticator", "advanced", "unknown"})
_ERRORS = frozenset({"", "network", "captcha", "rate_limited", "auth_rejected", "invalid_email", "unknown", "unreadable"})
_READY_STATES = frozenset({"loading", "interactive", "complete", "unknown"})
_PAGE_KINDS = frozenset({
    "chatgpt_home", "chatgpt_login", "chatgpt_chat", "chatgpt_other", "auth_login",
    "auth_password", "auth_email_otp", "auth_authenticator", "auth_advanced",
    "auth_other", "browser_error", "untrusted", "unknown",
})
_CONTINUE_RESULTS = frozenset({
    "clicked", "not_ready", "busy", "wrong_page", "wrong_route", "ambiguous",
    "email_mismatch", "no_submit", "error",
})

# These are locators, not a second email-input implementation. The caller
# continues to use gpt_pro_login._fill_email_react for native/React filling.
_DOM_SELECTORS = {
    "email": 'input[type="email"],input[name="email"],input[autocomplete="email"],input[autocomplete="username"],input[name="username"],input[placeholder*="电子邮件"],input[placeholder*="Email"],input[placeholder*="email"]',
    "password": 'input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]',
    "otp": 'input[autocomplete="one-time-code"],input[name="code"],input[name="otp"],input[inputmode="numeric"],input[data-testid="code-input"],input[maxlength="6"]',
    "dialogs": '[role="dialog"],dialog,[role="alertdialog"]',
    "headings": 'h1,h2,h3,[role="heading"]',
    "errors": '[role="alert"],[aria-live="assertive"],.error,[data-testid*="error" i],#main-message,.error-code',
    "explicit_errors": '[role="alert"],.error,[data-testid*="error" i],#main-message,.error-code',
    "captcha": 'iframe[src*="challenges.cloudflare.com"],iframe[src*="recaptcha"],iframe[src*="hcaptcha"],[data-testid*="captcha" i],#challenge-running,#cf-challenge-running',
    "busy": '[aria-busy="true"],[role="progressbar"],[data-state="loading"]',
    "buttons": 'button,input[type="submit"],[role="button"]',
    "advanced": 'button[data-testid="user-menu-button"],button[data-testid="profile-button"]',
}


_TRANSITION_DOM_JS = r"""
const options = arguments[0] || {};
const selectors = __SELECTORS__;
const norm = value => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
const text = el => typeof el.innerText === 'string' ? el.innerText : String(el.textContent || '');
const visible = el => {
  if (!el || !el.isConnected || el.closest('[data-message-author-role],[data-testid^="conversation-turn"]')) return false;
  for (let node = el; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (node.hidden || node.hasAttribute('inert') || node.getAttribute('aria-hidden') === 'true' ||
        (node.tagName === 'DIALOG' && !node.hasAttribute('open')) || style.display === 'none' ||
        /hidden|collapse/.test(style.visibility) || style.opacity === '0') return false;
  }
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
};
const usable = el => visible(el) && !el.disabled && el.getAttribute('aria-disabled') !== 'true' && !el.closest('fieldset[disabled]');
const all = key => [...document.querySelectorAll(selectors[key])].filter(visible);
const ready = ['loading','interactive','complete'].includes(document.readyState) ? document.readyState : 'unknown';
const state = {route:'unknown', error:'', ready_state:ready, page_kind:'unknown',
  email_count:0, password_count:0, continue_count:0, busy:false};
const host = location.hostname;
const path = String(location.pathname || '/').replace(/\/+$/, '') || '/';
const trusted = location.protocol === 'https:' && ['chatgpt.com','auth.openai.com'].includes(host) &&
  (!location.port || location.port === '443');
if (!trusted) {
  state.page_kind = location.protocol === 'chrome-error:' ? 'browser_error' : 'untrusted';
} else if (host === 'chatgpt.com') {
  state.page_kind = path === '/' ? 'chatgpt_home' : ['/auth/login','/auth/login_with'].includes(path)
    ? 'chatgpt_login' : /^\/c\/[^/]+$/.test(path) ? 'chatgpt_chat' : 'chatgpt_other';
} else {
  state.page_kind = ['/log-in','/login'].includes(path) ? 'auth_login'
    : ['/log-in/password','/login/password'].includes(path) ? 'auth_password'
    : ['/email-verification','/email-otp','/email-code','/log-in/verification'].includes(path) ? 'auth_email_otp'
    : ['/mfa','/mfa/otp','/mfa-challenge','/authenticator','/u/mfa-otp-challenge'].includes(path) ? 'auth_authenticator'
    : ['/workspace','/consent','/about-you'].includes(path) ? 'auth_advanced' : 'auth_other';
}
if (!trusted && state.page_kind !== 'browser_error') return options.action === 'continue' ? 'wrong_page' : state;
const dialogs = all('dialogs');
const currentDialog = dialogs[dialogs.length - 1] || null;
const scope = currentDialog || document.body;
const inScope = el => Boolean(scope && scope.contains(el));
const headings = all('headings').filter(inScope).map(text).join(' ');
const dialogTitle = currentDialog ? norm([currentDialog.getAttribute('aria-label') || '', headings].join(' ')) : '';
const homeLogin = state.page_kind === 'chatgpt_home' && Boolean(currentDialog) &&
  /log in|login|sign in|welcome back|登录|登入/.test(dialogTitle);
const emailPage = ['chatgpt_login','auth_login'].includes(state.page_kind) || homeLogin;
const loginSurface = emailPage || ['auth_password','auth_email_otp','auth_authenticator'].includes(state.page_kind);
const signals = all('errors').filter(inScope).map(text).map(norm).filter(Boolean);
const explicitError = all('explicit_errors').filter(inScope).map(text).some(value => Boolean(norm(value)));
const errorText = signals.join(' ');
const errorHeadings = norm(headings);
// Classifications never return the matching string. Unknown text is not
// silently promoted to a retryable network failure.
const knownError = errorText + ' ' + errorHeadings;
if (all('captcha').filter(inScope).length || /verif(?:y|ying) (?:that )?you are human|captcha|人机验证|验证您是人类|人機驗證/.test(knownError)) state.error = 'captcha';
else if (/too many (?:requests|attempts)|rate[- ]limit|请求过于频繁|操作过于频繁|尝试次数过多/.test(knownError)) state.error = 'rate_limited';
else if (/invalid email|email (?:address )?is (?:not valid|invalid)|enter a valid email|邮箱格式|邮箱地址无效|电子邮件地址无效/.test(knownError)) state.error = 'invalid_email';
else if (/invalid credentials|incorrect password|wrong password|incorrect email or password|email or password (?:is |are )?(?:incorrect|invalid)|account (?:does not exist|not found)|access denied|密码错误|密码不正确|邮箱或密码不正确|账户不存在|访问被拒绝/.test(knownError)) state.error = 'auth_rejected';
else if (/network error|network request failed|failed to fetch|connection (?:lost|failed|reset|timed out)|err_network_changed|err_internet_disconnected|err_name_not_resolved|err_connection|网络错误|网络连接失败|无法连接服务器|连接已重置|连接超时/.test(knownError)) state.error = 'network';
else if (explicitError || /something went wrong|an error occurred|unable to log in|发生错误|出现错误|出了点问题/.test(knownError)) state.error = 'unknown';
state.busy = Boolean(scope && (scope.getAttribute('aria-busy') === 'true' || all('busy').some(inScope)));
let emails = [], passwords = [], otp = [], form = null, continues = [];
if (loginSurface) {
  // Stage blockers intentionally inspect all visible controls, even when a
  // second form/dialog owns them. No password or OTP value is ever read.
  passwords = all('password');
  otp = all('otp');
  emails = all('email').filter(el => ['','text','email'].includes(norm(el.getAttribute('type'))) &&
    !['current-password','new-password','one-time-code'].includes(norm(el.getAttribute('autocomplete'))));
  state.email_count = Math.min(emails.length, 1000);
  state.password_count = Math.min(passwords.length, 1000);
  const authenticator = state.page_kind === 'auth_authenticator' ||
    /authenticator|authentication app|verification app|身份验证器|验证器应用|身份验证应用|認証アプリ/.test(norm(headings));
  const phoneChallenge = /text message|sms|phone number|短信|手机号码|電話番号/.test(norm(headings));
  if (authenticator) state.route = 'authenticator';
  else if ((otp.length || state.page_kind === 'auth_email_otp') && !phoneChallenge) state.route = 'email_otp';
  else if (passwords.length || state.page_kind === 'auth_password') state.route = 'password';
  else if (emails.length && !otp.length && emails.some(inScope)) state.route = 'email';
  if (emails.length === 1 && inScope(emails[0])) {
    form = emails[0].form || emails[0].closest('form');
    if (form && visible(form) && inScope(form)) {
      continues = all('buttons').filter(el => usable(el) && inScope(el) &&
        (el.form ? el.form === form : form.contains(el)) &&
        !['switch','checkbox','radio'].includes(el.getAttribute('role'))).filter(el => {
          const label = norm(el.tagName === 'INPUT' ? el.value : text(el) || el.getAttribute('aria-label'));
          if (/google|apple|microsoft|phone|sign up|signup|register|create account|consent|workspace|password|verification|captcha|同意|注册|工作区|密码|验证码|验证|手机/.test(label)) return false;
          return /^(?:continue|next|sign in|log in|login|继续|繼續|下一步|登录|登入|続行|続ける|次へ|다음|계속)$/.test(label) ||
            (!label && el.getAttribute('data-testid') === 'continue-button');
        });
    }
  }
  state.continue_count = Math.min(continues.length, 1000);
} else if (state.page_kind === 'auth_advanced' || state.page_kind === 'chatgpt_chat' ||
           (state.page_kind === 'chatgpt_home' && !currentDialog && all('advanced').length)) state.route = 'advanced';
if (options.action !== 'continue') return state;
if (!trusted || !emailPage) return 'wrong_page';
if (state.error) return 'error';
if (state.ready_state !== 'complete') return 'not_ready';
if (state.busy) return 'busy';
if (passwords.length || otp.length || ['password','email_otp','authenticator','advanced'].includes(state.route)) return 'wrong_route';
if (emails.length > 1) return 'ambiguous';
if (state.route !== 'email' || emails.length !== 1) return 'wrong_route';
if (!usable(emails[0])) return 'not_ready';
// This is the only email-value read, in the same synchronous turn as click.
// The caller supplies the already-filled address; no text is returned.
if (typeof options.expected_email !== 'string' || !options.expected_email || emails[0].value !== options.expected_email) return 'email_mismatch';
if (continues.length > 1) return 'ambiguous';
if (!form || continues.length !== 1 || !usable(continues[0])) return 'no_submit';
const trustedAction = raw => {
  if (!raw) return true;
  try {
    // Deliberately build a base without location.search/hash or href.
    const base = location.protocol + '//' + host + (location.port ? ':' + location.port : '') + String(location.pathname || '/');
    const target = new URL(raw, base);
    return target.protocol === 'https:' && ['chatgpt.com','auth.openai.com'].includes(target.hostname) &&
      (!target.port || target.port === '443') && !target.username && !target.password;
  } catch (_) { return false; }
};
if (!trustedAction(form.getAttribute('action')) || !trustedAction(continues[0].getAttribute('formaction'))) return 'wrong_page';
continues[0].click();
return 'clicked';
""".replace("__SELECTORS__", json.dumps(_DOM_SELECTORS))


def _unreadable_snapshot() -> dict[str, Any]:
    return {"route": "unknown", "error": "unreadable", "ready_state": "unknown", "page_kind": "unknown",
            "email_count": 0, "password_count": 0, "continue_count": 0, "busy": False}


def snapshot(page: Any) -> dict[str, Any]:
    """Return only fixed classifications, visible-control counts and flags."""
    try:
        value = page.run_js(_TRANSITION_DOM_JS, {"action": "snapshot"})
        if not isinstance(value, dict):
            return _unreadable_snapshot()
        for key, allowed in (("route", _ROUTES), ("error", _ERRORS), ("ready_state", _READY_STATES), ("page_kind", _PAGE_KINDS)):
            if not isinstance(value.get(key), str) or value[key] not in allowed:
                return _unreadable_snapshot()
        for key in ("email_count", "password_count", "continue_count"):
            if type(value.get(key)) is not int or not 0 <= value[key] <= 1000:
                return _unreadable_snapshot()
        if type(value.get("busy")) is not bool:
            return _unreadable_snapshot()
        return {key: value[key] for key in _unreadable_snapshot()}
    except Exception:
        # Browser exceptions can contain DOM, URLs and credentials.
        return _unreadable_snapshot()


def guarded_continue(page: Any, expected_email: str) -> str:
    """Submit the current email form once, or return a fixed refusal enum."""
    if not isinstance(expected_email, str) or not expected_email:
        return "email_mismatch"
    try:
        value = page.run_js(_TRANSITION_DOM_JS, {"action": "continue", "expected_email": expected_email})
        return value if isinstance(value, str) and value in _CONTINUE_RESULTS else "error"
    except Exception:
        return "error"
