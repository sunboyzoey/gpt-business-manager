"""Isolated, existing-password-only BUSINESS login recovery.

Private credentials cross only stdin/stdout pipes of one short-lived worker.
No OTP registration, security setup, credential writes, or retained browser.
Executable guards are retained from the offline-tested child-health audit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

WORKER_TIMEOUT = 240
REASONS = {"unsafe_route", "unsafe_form", "unsafe_navigation", "guard_unavailable",
           "credentials_missing", "email_verification_required", "mfa_unavailable",
           "login_failed", "rate_limited", "timeout", "cleanup_failed"}


class AuditStopped(BaseException):
    def __init__(self, code):
        self.code = code if code in REASONS else "login_failed"


GUARD_JS = r"""
(() => {
  const KEY = '__childHealthAuditGuardV1';
  if (window[KEY]) return;
  const visible = e => {
    if (!e || !e.isConnected || e.closest('[hidden],[inert],[aria-hidden="true"],dialog:not([open])')) return false;
    const r=e.getBoundingClientRect(),s=getComputedStyle(e);
    return r.width>0 && r.height>0 && s.display!=='none' && !/hidden|collapse/.test(s.visibility);
  };
  const forbidden = /sign[-_ ]?up|register|registration|create[-_ ]?(?:account|password)|about-you|reset|forgot|new[-_ ]?password|change[-_ ]?password|set[-_ ]?password/i;
  const pathOf = u => {try{return decodeURIComponent(u.pathname).replace(/\/+$/,'') || '/';}catch(_){return '__invalid__';}};
  const trusted = u => u.protocol==='https:' && ['auth.openai.com','chatgpt.com'].includes(u.hostname)
    && (!u.port || u.port==='443') && !u.username && !u.password;
  const safeURL = raw => {
    try {
      const u=new URL(raw,location.href),p=pathOf(u);
      if(!trusted(u) || forbidden.test(p)) return false;
      if(u.hostname==='chatgpt.com') return p==='/' || /^\/auth\/(?:login|login_with|callback(?:\/[^/]+)?)$/.test(p);
      return /^\/(?:log-in(?:\/(?:password|code|verification))?|login(?:\/password)?|email-verification|email-otp|email-code|mfa(?:\/otp)?|mfa-challenge(?:\/[^/]+)?|authenticator|u\/mfa-otp-challenge|workspace(?:\/[^/]+)?)$/.test(p);
    } catch(_){return false;}
  };
  const sameAction = (raw,base) => {
    if(!raw) return true;
    try {
      const u=new URL(raw,base.href);
      return trusted(u) && u.origin===base.origin && pathOf(u)===pathOf(base) && !forbidden.test(pathOf(u));
    }catch(_){return false;}
  };
  // Observed logged-out home modal: the "登录或注册" heading wraps an email-
  // only GET login entry, not a password/profile registration form. Admit only
  // this exact surface; all subsequent auth routes keep the original guard.
  const observedEmailEntry = form => {
    if(!form) return false;
    const u=new URL(location.href);
    if(!trusted(u) || u.hostname!=='chatgpt.com' || pathOf(u)!=='/'
       || String(form.getAttribute('method')||'').toLowerCase()!=='get') return false;
    const actionOK = raw => {
      try {const a=new URL(raw,u.href);return trusted(a) && a.origin===u.origin
        && a.pathname==='/auth/login_with' && !a.search && !a.hash;}catch(_){return false;}
    };
    if(!form.getAttribute('action') || !actionOK(form.getAttribute('action'))) return false;
    if(form.querySelectorAll('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]').length) return false;
    if([...form.querySelectorAll('textarea,select,[contenteditable="true"]')].some(visible)) return false;
    const inputs=[...form.querySelectorAll('input')].filter(visible);
    if(inputs.length!==1 || inputs[0].getAttribute('type')!=='email'
       || inputs[0].getAttribute('name')!=='login_hint' || inputs[0].getAttribute('autocomplete')!=='email') return false;
    return [...form.querySelectorAll('button,input[type="submit"]')].filter(visible).every(b=>{
      const action=b.getAttribute('formaction'),method=b.getAttribute('formmethod');
      return (!action || actionOK(action)) && (!method || method.toLowerCase()==='get');
    });
  };
  const badForm = form => {
    if(!form) return true;
    if(observedEmailEntry(form)) return false;
    const u=new URL(location.href);
    if(!sameAction(form.getAttribute('action'),u)) return true;
    return [...form.querySelectorAll('button,input[type="submit"]')].filter(visible)
      .some(b=>!sameAction(b.getAttribute('formaction'),u));
  };
  const check = (mode='read') => {
    if(!safeURL(location.href)) return 'unsafe_route';
    const passwords=[...document.querySelectorAll('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]')].filter(visible);
    if(passwords.some(e=>/new|confirm|create|reset/i.test([e.autocomplete,e.name,e.id].join(' ')))) return 'unsafe_form';
    const observedEmailModal=passwords.length===0 && [...document.querySelectorAll('form')].some(observedEmailEntry);
    if([...document.querySelectorAll('h1,h2,[role="heading"]')].filter(visible)
      .some(e=>{
        const title=(e.innerText||'').trim().toLowerCase();
        if(observedEmailModal && title==='登录或注册') return false;
        return /create (?:an? )?account|sign up|new password|reset (?:your )?password|创建账户|创建账号|设置密码|重设密码|重置密码|注册/.test(title);
      })) return 'unsafe_form';
    const fields=[...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[type="password"],input[autocomplete="current-password"]')].filter(visible);
    if(fields.some(e=>badForm(e.form || e.closest('form')))) return 'unsafe_form';
    if(mode==='password') {
      const u=new URL(location.href);
      if(u.hostname!=='auth.openai.com' || !['/log-in/password','/login/password'].includes(pathOf(u))) return 'unsafe_route';
      if(passwords.length!==1 || badForm(passwords[0].form || passwords[0].closest('form'))) return 'unsafe_form';
    }
    return 'ok';
  };
  const guard={check,visible,safeURL,badForm,blocked:''};
  window[KEY]=guard;
  const block = (event,code) => {guard.blocked=code;event.preventDefault();event.stopImmediatePropagation();};
  for(const name of ['beforeinput','keydown','click','submit']) document.addEventListener(name,event=>{
    const code=check();
    if(code!=='ok') {block(event,code);return;}
    const target=event.target && event.target.closest ? event.target.closest('button,a,input,form,[role="button"]') : null;
    if(!target) return;
    if(name==='click') {
      const label=(target.innerText||target.value||target.getAttribute('aria-label')||'').trim();
      const href=target.getAttribute('href');
      if(forbidden.test(label) || /注册|重置密码|忘记密码|设置密码/.test(label)
         || (href && href!=='#' && !safeURL(href))) {block(event,'unsafe_navigation');return;}
    }
    const form=target.tagName==='FORM' ? target : target.form;
    if(form && badForm(form)) block(event,'unsafe_form');
  },true);
})();
"""
GUARD_READ_JS = "return window.__childHealthAuditGuardV1 ? (window.__childHealthAuditGuardV1.blocked || window.__childHealthAuditGuardV1.check(arguments[0] || 'read')) : 'guard_unavailable';"
# This is an observation-only eligibility test, not permission to execute. A
# temporarily unmounted/missing form attribute may settle; an explicit unsafe
# attribute, registration/reset surface, or blocked native action never may.
PASSIVE_OPENING_WAIT_JS = r"""
const g=window.__childHealthAuditGuardV1;
if(!g || g.blocked!=='') return false;
const complete=arguments[0]===true;
const u=new URL(location.href);
if(u.protocol!=='https:' || u.hostname!=='chatgpt.com' || (u.port && u.port!=='443')
   || u.username || u.password || u.pathname!=='/' || u.search || u.hash) return false;
const all=s=>[...document.querySelectorAll(s)].filter(g.visible);
if(document.querySelectorAll('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]').length) return false;
const headings=all('h1,h2,[role="heading"]').map(e=>(e.innerText||'').trim().toLowerCase());
if(!headings.includes('登录或注册') || headings.some(t=>t!=='登录或注册' &&
   /create (?:an? )?account|sign[-_ ]?up|register|new password|reset|forgot|创建账户|创建账号|设置密码|重设密码|重置密码|忘记密码|注册/.test(t))) return false;
const editable=all('input,textarea,select,[contenteditable="true"]').filter(e=>
  !(e.tagName==='INPUT' && /^(?:hidden|button|submit|reset)$/i.test(e.getAttribute('type')||'')));
if(editable.length!==1) return false;
const email=editable[0];
const attrOK=(raw,expected)=>raw===expected || (!complete && (raw===null || raw===''));
if(email.tagName!=='INPUT' || email.getAttribute('type')!=='email'
   || !attrOK(email.getAttribute('name'),'login_hint') || !attrOK(email.getAttribute('autocomplete'),'email')
   || String(email.value||'').trim()) return false;
const actionOK=raw=>{
  if(raw===null || raw==='') return !complete;
  try{const a=new URL(raw,u.href);return a.protocol==='https:' && a.origin===u.origin
    && !a.username && !a.password && a.pathname==='/auth/login_with' && !a.search && !a.hash;}catch(_){return false;}
};
const methodOK=raw=>(!complete && (raw===null || raw==='')) || (typeof raw==='string' && raw.toLowerCase()==='get');
const form=email.form || email.closest('form');
if(complete && !form) return false;
if(form && (!actionOK(form.getAttribute('action')) || !methodOK(form.getAttribute('method')))) return false;
if(form && all('button,input[type="submit"]').filter(b=>b.form===form || b.closest('form')===form)
  .some(b=>{
    const action=b.getAttribute('formaction'),method=b.getAttribute('formmethod');
    return (action!==null && action!=='' && !actionOK(action))
      || (method!==null && method!=='' && method.toLowerCase()!=='get');
  })) return false;
return true;
"""
OPENING_READY_JS = r"""
const g=window.__childHealthAuditGuardV1;
return g && [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"]')].filter(g.visible).length===1 ? 'ready':'waiting';
"""
STRICT_OPEN_JS = r"""
const g=window.__childHealthAuditGuardV1;
if(!g || g.check()!=='ok') return 'blocked';
const emails=[...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"]')].filter(g.visible);
if(emails.length===1) return 'ready';
const u=new URL(location.href);
if(u.hostname!=='chatgpt.com') return 'missing';
const controls=[...document.querySelectorAll('button,a,[role="button"]')].filter(g.visible).filter(e=>{
  const t=(e.innerText||e.getAttribute('aria-label')||'').trim();
  const href=e.getAttribute('href');
  return /^(?:log\s?in|sign\s?in|登录|登入|ログイン)$/i.test(t) && (!href || g.safeURL(href));
});
if(!controls.length) return 'missing';
// A logged-out home can expose the same explicit login in its header and
// sidebar. Both already passed the exact-label and safe-destination checks.
// Pick one, never click all, and never use a generic header/signup fallback.
const chosen=controls.find(e=>e.closest('#conversation-header-actions,header,[role="banner"]')) || controls[0];
chosen.click();return 'clicked';
"""

def wait_for_login_opening(raw_js,recorder,opening_state,deadline):
    """Bounded read-only settling; every eventual action keeps the old guard."""
    stable_ready=0
    passive_seen=False
    credential_flags=("email_input_started","password_input_started","email_confirmed",
                      "email_submitted","password_submitted")
    def read(source,*args):
        remaining=deadline-time.monotonic()
        if remaining<=0:return None
        return raw_js(source,*args,timeout=min(5,remaining))
    while time.monotonic()<deadline:
        code=read(GUARD_READ_JS,"read")
        if code is None:return False
        if code!="ok":
            stable_ready=0
            if (code!="unsafe_form" or not opening_state["clicked"]
                    or any(recorder.data.get(key) for key in credential_flags)
                    or read(PASSIVE_OPENING_WAIT_JS) is not True):
                raise AuditStopped(code if code in REASONS else "guard_unavailable")
            passive_seen=True
        else:
            # Stay on the exact, empty entry modal after any settling episode.
            # No action is allowed on a replacement page which merely passed
            # a generic guard after the original incomplete modal disappeared.
            if passive_seen:
                if (any(recorder.data.get(key) for key in credential_flags)
                        or read(PASSIVE_OPENING_WAIT_JS) is not True):
                    raise AuditStopped("unsafe_form")
                if read(PASSIVE_OPENING_WAIT_JS,True) is not True:
                    stable_ready=0
                    remaining=deadline-time.monotonic()
                    if remaining>0:time.sleep(min(0.5,remaining))
                    continue
            state=read(OPENING_READY_JS if opening_state["clicked"] else STRICT_OPEN_JS)
            if state=="blocked":raise AuditStopped("unsafe_navigation")
            if state=="clicked":opening_state["clicked"]=True
            stable_ready=stable_ready+1 if state=="ready" else 0
            if stable_ready>=2 and time.monotonic()<deadline:return True
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(0.5,remaining))
    return False


# Fetches have their own deadlines in addition to the browser call and process
# deadline. The access token is private worker output, never a public DTO.
SESSION_JS = r"""
return (async()=>{
 if(location.protocol!=='https:' || location.hostname!=='chatgpt.com' || (location.port && location.port!=='443')) return {};
 async function get(url,headers={}) {
   const c=new AbortController(),timer=setTimeout(()=>c.abort(),8000);
   try {const r=await fetch(url,{credentials:'include',cache:'no-store',redirect:'error',headers,signal:c.signal});
     let body=null;try{body=await r.json();}catch(_){}return {status:r.status,body};}
   finally{clearTimeout(timer);}
 }
 try {
   const session=await get('https://chatgpt.com/api/auth/session');
   if(session.status===429) return {rate_limited:true};
   if(session.status!==200 || typeof session.body?.accessToken!=='string') return {};
   const token=session.body.accessToken,email=session.body?.user?.email;
   if(typeof email!=='string' || email.trim().toLowerCase()!==String(arguments[0]).trim().toLowerCase()) return {};
   const backend=await get('https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27', {Authorization:'Bearer '+token});
   if(backend.status===429) return {rate_limited:true};
   const accounts=backend.body?.accounts;
   if(backend.status!==200 || !accounts || typeof accounts!=='object' || !Object.keys(accounts).length || backend.body?.error) return {};
   return {authenticated:true,email,access_token:token,session_expires_at:typeof session.body.expires==='string'?session.body.expires:''};
 } catch(_){return {};}
})();
"""


def _install_guards(page, login, security, rt, email, evidence):
    """Only called in the disposable child process; never patches API threads."""
    raw = page.run_js
    page.add_init_js(GUARD_JS)
    raw(GUARD_JS, timeout=5)
    def check(mode="read"):
        code = raw(GUARD_READ_JS, mode, timeout=5)
        if code != "ok":
            raise AuditStopped(code)
    def guarded_js(source, *args, **kwargs):
        check()
        kwargs["timeout"] = min(float(kwargs.get("timeout") or 20), 20)
        return raw(source, *args, **kwargs)
    page.run_js = guarded_js
    original_get = page.get
    def get(url, *args, **kwargs):
        if url != "https://chatgpt.com/":
            raise AuditStopped("unsafe_route")
        value = original_get(url, *args, **kwargs)
        check()
        return value
    page.get = get
    error_reader = security._auth_login_page_error
    # Read-only terminal classification must not be hidden by executable-route
    # guards. No click or input is permitted on an error/deactivation page.
    security._auth_login_page_error = lambda current: error_reader(SimpleNamespace(run_js=raw))
    def open_login(current, log, attempts=4):
        return wait_for_login_opening(raw, SimpleNamespace(data=evidence), {"clicked": False}, time.monotonic()+15)
    login._open_login_modal = open_login
    fill = login._fill_email_react
    def fill_email(current, box, target, *args, **kwargs):
        check()
        if str(target).strip().lower() != email:
            raise AuditStopped("unsafe_form")
        evidence["email_input_started"] = True
        result = fill(current, box, target, *args, **kwargs)
        if result is True:
            evidence["email_confirmed"] = True
        return result
    login._fill_email_react = fill_email
    click_continue = login._click_continue
    def email_continue(current, *args, **kwargs):
        check()
        result = click_continue(current, *args, **kwargs)
        if result is True and evidence.get("email_confirmed"):
            evidence["email_submitted"] = True
        return result
    login._click_continue = email_continue
    needle = "function passwordForm(expectedForm=null) {"
    for name in tuple(vars(rt)):
        value = getattr(rt, name)
        if name.startswith("_PASSWORD_LOGIN_") and name.endswith("_JS") and isinstance(value, str):
            setattr(rt, name, value.replace(needle, needle + "\n if(!window.__childHealthAuditGuardV1 || window.__childHealthAuditGuardV1.check('password')!=='ok') return null;"))
    password_login = rt._try_password_login
    def password(current, secret, log_fn, **kwargs):
        check("password")
        evidence["password_input_started"] = True
        original = kwargs.get("diagnostic_fn")
        def diagnostic(value):
            if isinstance(value, dict) and value.get("code") == "password_login_submitted":
                evidence["password_submitted"] = True
            if callable(original):
                original(value)
        kwargs["diagnostic_fn"] = diagnostic
        return password_login(current, secret, log_fn, **kwargs)
    rt._try_password_login = password
    def session_identity(current):
        check()
        result = raw(SESSION_JS, email, timeout=20)
        result = result if isinstance(result, dict) else {}
        if result.get("rate_limited") is True:
            raise AuditStopped("rate_limited")
        return result
    security._session_identity = session_identity
    return raw, session_identity


def _failure(reason="login_failed"):
    return {"status": "unavailable", "reason": reason if reason in REASONS else "login_failed"}


def _classify(error):
    # Generic text, HTTP status and missing session never grant Dead.
    text = str(error or "")
    if "过于频繁" in text or "次数过多" in text or "rate limit" in text.lower():
        return "rate_limited"
    if "邮箱验证码" in text:
        return "email_verification_required"
    if "没有对应密钥" in text or "没有原密钥" in text:
        return "mfa_unavailable"
    return "login_failed"


def _worker(payload):
    page = raw = security = None
    email = str(payload.get("email") or "").strip().lower()
    evidence = {}
    result = _failure()
    def interrupt(*_):
        raise AuditStopped("timeout")
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, WORKER_TIMEOUT-15)
    try:
        from DrissionPage import ChromiumOptions, ChromiumPage
        from platforms.chatgpt import account_security as security, gpt_pro_login as login, drission_rt_acquirer as rt
        from services.business_session_health import _COOKIE_NAME, _safe_value
        # No inherited security tracker can write password/MFA state here.
        security._SECURITY_PROGRESS.set(None)
        options = ChromiumOptions().auto_port().new_env().incognito()
        options.headless(payload.get("browser_mode") != "headed")
        options.set_retry(times=0, interval=0)
        options.set_timeouts(base=5, page_load=30, script=20)
        for argument in ("--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage"):
            options.set_argument(argument)
        if payload.get("proxy"):
            options.set_proxy(payload["proxy"])
        page = ChromiumPage(addr_or_opts=options)
        raw, identity = _install_guards(page, login, security, rt, email, evidence)
        authenticated, error, _ = security._reauthenticate_with_password(
            page, email, payload["password"], payload.get("totp_secret", ""), lambda _: None)
        if authenticated:
            session = identity(page)
            if session.get("authenticated") is True and str(session.get("email", "")).strip().lower() == email:
                cookies = {}
                for cookie in page.cookies(all_domains=False, all_info=True) or []:
                    if not isinstance(cookie, dict) or str(cookie.get("domain") or "").lstrip(".") != "chatgpt.com":
                        continue
                    name, value = str(cookie.get("name") or ""), str(cookie.get("value") or "")
                    if _COOKIE_NAME.fullmatch(name) and _safe_value(value):
                        cookies[name] = value
                cookies["oai-access-token"] = session["access_token"]
                result = {"status": "valid", "cookie_blob": "; ".join(f"{k}={v}" for k,v in cookies.items()),
                          "session_expires_at": session.get("session_expires_at", "")}
        else:
            result = _failure(_classify(error))
    except AuditStopped as exc:
        result = _failure(exc.code)
    except Exception:
        result = _failure()
    finally:
        if (security is not None and raw is not None and evidence.get("email_confirmed") is True
                and evidence.get("email_submitted") is True and result.get("reason") != "timeout"):
            try:
                if security._auth_login_page_error(page) == "account_deactivated":
                    result = {"status": "deactivated", "evidence": "trusted_auth_error_page",
                              "email_confirmed": True, "email_submitted": True}
            except BaseException:
                pass
        signal.setitimer(signal.ITIMER_REAL, 7)
        if page is not None:
            try:
                page.quit(timeout=5, force=True)
            except BaseException:
                pass
        signal.setitimer(signal.ITIMER_REAL, 0)
    return result


def _cleanup_process(process, descendants, psutil):
    """Terminate only this invocation's process group and captured descendants."""
    clean = True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception:
        clean = False
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    for child in descendants.values():
        try:
            if child.is_running():
                child.terminate()
        except psutil.NoSuchProcess:
            pass
        except Exception:
            clean = False
    _, alive = psutil.wait_procs(list(descendants.values()), timeout=2)
    for child in alive:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
        except Exception:
            clean = False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        clean = False
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        clean = False
    _, alive = psutil.wait_procs(alive, timeout=2)
    return clean and not alive and process.poll() is not None


def _run_isolated(payload):
    process = None
    descendants = {}
    result = _failure()
    cleanup_ok = True
    try:
        import psutil
        process = subprocess.Popen(
            [sys.executable, "-m", "services.business_session_recovery", "--worker"],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        deadline = time.monotonic() + WORKER_TIMEOUT
        pending = json.dumps(payload).encode()
        while time.monotonic() < deadline:
            try:
                for child in psutil.Process(process.pid).children(recursive=True):
                    descendants[(child.pid, child.create_time())] = child
            except psutil.NoSuchProcess:
                pass
            output = None
            try:
                output, _ = process.communicate(input=pending, timeout=min(.5, max(.01, deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                pending = None
                continue
            if process.returncode == 0 and len(output or b"") <= 512 * 1024:
                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    result = parsed
            break
        else:
            result = _failure("timeout")
    except Exception:
        result = _failure()
    finally:
        if process is not None:
            try:
                cleanup_ok = _cleanup_process(process, descendants, psutil)
            except Exception:
                cleanup_ok = False
    return result if cleanup_ok else _failure("cleanup_failed")


def recover_password_session(email, *, proxy="", browser_mode="headless"):
    """Caller must hold mother-session, plan-login and email-security leases."""
    try:
        from services.chatgpt_security_store import get_chatgpt_security_status, get_chatgpt_security_secrets
        status = get_chatgpt_security_status(email)
        if status.get("password_state") != "configured" or status.get("credentials_readable") is not True:
            return _failure("credentials_missing")
        secrets = get_chatgpt_security_secrets(email)
        if str(secrets.get("email") or "").strip().lower() != str(email).strip().lower() or not secrets.get("password"):
            return _failure("credentials_missing")
        if status.get("mfa_state") == "enabled" and not secrets.get("totp_secret"):
            return _failure("mfa_unavailable")
        return _run_isolated({"email": str(email).strip().lower(), "password": secrets["password"],
                              "totp_secret": secrets.get("totp_secret", ""), "proxy": proxy,
                              "browser_mode": browser_mode})
    except Exception:
        return _failure("credentials_missing")


def _main():
    if sys.argv[1:] != ["--worker"]:
        return 2
    # Keep third-party stdout/stderr away from IPC and from task/server logs.
    output_fd = os.dup(1)
    with open(os.devnull, "w") as silent:
        os.dup2(silent.fileno(), 1)
        os.dup2(silent.fileno(), 2)
        try:
            raw = sys.stdin.buffer.read(128 * 1024)
            payload = json.loads(raw)
            result = _worker(payload) if isinstance(payload, dict) else _failure()
        except BaseException:
            result = _failure()
        with os.fdopen(output_fd, "w") as output:
            json.dump(result, output, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
