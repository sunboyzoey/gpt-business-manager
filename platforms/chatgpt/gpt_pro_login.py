"""GPT PRO 账号自动登录(DrissionPage 实现)。

走 OpenAI 邮箱 OTP 登录链(amr=otp_email,无密码):
  1. 打开 auth.openai.com/log-in
  2. 填邮箱 → 点继续
  3. 等待跳转到 OTP 页 (/log-in/code 等)
  4. 从 Mailbox(OutlookMailbox 等)取 6 位验证码
  5. 提交 OTP → 等待跳转到 chatgpt.com
  6. 调 /api/auth/session 拉 access_token / session_token / planType,
     再调 /backend-api/me 兜底
  7. 返回 GptProLoginResult 给调用方写回 GptProAccountModel

调用方: api.gpt_plan_operations 的套餐账号登录操作触发。
"""
from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse


LOGIN_URL = "https://chatgpt.com/"          # 开主页 → 点「登录」弹窗 → 填邮箱(原行为)。
# 注: 之前"首页点登录不弹邮箱框"其实是 eager 加载的锅(React 未 hydrate,点击空操作);
# 用 normal 加载(见 _create_browser)后首页方式正常, 无需改成 /auth/login。
CHATGPT_HOME = "https://chatgpt.com/"

_NAV_TIMEOUT = 60
_DEFAULT_OTP_TIMEOUT = 180
_DEFAULT_LANDING_TIMEOUT = 60
_OTP_RE = re.compile(r"\b(\d{6})\b")

# Only these local verdicts may cross a login boundary. Never carry a remote
# body, exception message, URL, account identifier or credential in this DTO.
_LOGIN_FAILURES = {
    "session_read_failed": ("extract_session", True, "登录会话读取暂时失败，尚未确认登录成功"),
    "session_request_timeout": ("extract_session", True, "登录会话请求超时，尚未取得完整响应"),
    "session_network_failed": ("extract_session", True, "登录会话请求发生网络错误，尚未取得完整响应"),
    "session_browser_timeout": ("extract_session", True, "浏览器执行会话读取超时，尚未取得结果"),
    "session_context_lost": ("extract_session", True, "页面跳转或刷新导致会话读取中断"),
    "session_browser_disconnected": ("extract_session", True, "浏览器连接已中断，无法读取登录会话"),
    "session_read_unconfirmed": ("extract_session", False, "登录会话读取异常，原因尚未确认"),
    "session_http_transient": ("extract_session", True, "登录会话服务暂时不可用，尚未确认登录成功"),
    "session_http_rejected": ("extract_session", False, "登录会话请求被拒绝，尚未确认登录成功"),
    "session_http_unconfirmed": ("extract_session", False, "登录会话请求未成功，原因尚未确认"),
    "session_empty": ("extract_session", False, "登录会话响应为空，尚未确认登录成功"),
    "session_invalid": ("extract_session", False, "登录会话格式未通过校验，尚未确认登录成功"),
    "session_identity_missing": ("extract_session", False, "登录会话未返回可核验的账号邮箱，未确认登录成功"),
    "session_token_missing": ("extract_session", False, "登录会话未返回有效访问凭据，未确认登录成功"),
    "session_state_error": ("extract_session", False, "登录会话仍有错误状态，未确认登录成功"),
    "session_identity_mismatch": ("extract_session", False, "登录后的账号身份与目标账号不一致，已停止后续操作"),
    "session_origin_untrusted": ("extract_session", False, "登录会话不在可信 ChatGPT 页面，已停止后续操作"),
    "login_page_unready": ("wait_otp_page", True, "登录页面暂未进入邮箱验证码阶段，已停止本次推进"),
    "login_transport_unavailable": ("wait_otp_page", True, "登录页面网络暂时不可用，已停止本次推进"),
    "login_rate_limited": ("wait_otp_page", True, "登录服务暂时限制请求，已停止本次推进"),
    "login_page_challenge": ("wait_otp_page", True, "登录页面校验暂未完成，已停止本次推进"),
    "login_page_unconfirmed": ("wait_otp_page", False, "登录页面状态未确认，未继续提交登录"),
    "login_origin_untrusted": ("wait_otp_page", False, "登录页面来源不可信，已停止登录"),
    "login_auth_rejected": ("wait_otp_page", False, "登录请求已被明确拒绝，已停止登录"),
    "login_existing_account_context": ("about_you", True, "账号已存在，但当前进入了注册上下文；已停止资料提交，等待从登录入口重试"),
    "login_profile_unconfirmed": ("about_you", True, "账号资料提交尚未确认，已停止等待登录落地，将从当前状态重试"),
    "account_deactivated": ("account_deactivated", False, "账号已停用（account_deactivated），已停止登录"),
}


def _login_failure(code: str, *, http_status: int | None = None) -> dict:
    stage, retryable, _ = _LOGIN_FAILURES[code]
    return {"code": code, "stage": stage, "http_status": http_status,
            "retryable": retryable, "remote_dead": code == "account_deactivated"}


def normalize_login_failure(value: Any) -> dict | None:
    """Validate closed, typed evidence; unknown/contradictory DTOs grant nothing."""
    if (type(value) is not dict or set(value) != {"code", "stage", "http_status", "retryable", "remote_dead"}
            or type(value.get("code")) is not str or value["code"] not in _LOGIN_FAILURES):
        return None
    code, status = value["code"], value["http_status"]
    expected = _login_failure(code, http_status=status)
    if (type(value["retryable"]) is not bool or type(value["remote_dead"]) is not bool
            or value != expected or status is not None and (type(status) is not int or not 100 <= status <= 599)):
        return None
    if code.startswith("session_http_"):
        if status is None:
            return None
        actual_code = ("session_http_transient" if status in {408, 425, 429} or status >= 500 else
                       "session_http_rejected" if status in {401, 403} else "session_http_unconfirmed")
        if code != actual_code or 200 <= status < 300:
            return None
    elif status is not None and (not code.startswith("session_") or not 200 <= status < 300):
        return None
    return dict(expected)


def login_failure_reason(value: Any) -> str:
    failure = normalize_login_failure(value)
    if failure is None:
        return "登录结果未确认，未继续操作"
    reason = _LOGIN_FAILURES[failure["code"]][2]
    return reason + (f"（HTTP {failure['http_status']}）" if failure["http_status"] is not None else "")


class _LoginFlowRejected(RuntimeError):
    def __init__(self, code: str):
        self.failure = _login_failure(code)
        super().__init__(login_failure_reason(self.failure))


def _stop_existing_account_context(page) -> None:
    # Reuse the registration reader's strict live-origin + explicit error-code
    # check. A generic error or a URL/text substring cannot prove this state.
    from platforms.chatgpt.drission_register import _has_existing_account_auth_error

    if _has_existing_account_auth_error(page):
        raise _LoginFlowRejected("login_existing_account_context")

# 默认账单地址: 美国俄勒冈州 Salem (Oregon 是美国 5 个无消费税州之一).
# 所有升级 PRO 流程都用这个地址回填 Stripe 账单字段, 卡导入时不再需要填地址。
# 改这个常量等于一键改全员账单地址, 慎重: 必须用真实存在的免税州地址。
_DEFAULT_BILLING_ADDRESS = {
    "country": "US",
    "state": "Oregon",
    "city": "Salem",
    "postal_code": "97317",
    "address_line1": "3478 Boone Road Southeast",
    "address_line2": "",
}

_DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)


@dataclass
class GptProLoginResult:
    ok: bool
    email: str
    user_id: str = ""
    account_id: str = ""
    plan_type: str = ""
    is_pro: bool = False
    access_token: str = ""
    session_token: str = ""
    cookies: dict = field(default_factory=dict)
    error: str = ""
    stage: str = ""
    # 登录成功后跑的 post_login_action 返回值 (例如升级 PRO 的 checkout 信息)
    action_result: Optional[dict] = None
    login_failure: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "email": self.email,
            "user_id": self.user_id,
            "account_id": self.account_id,
            "plan_type": self.plan_type,
            "is_pro": self.is_pro,
            "access_token": self.access_token,
            "session_token": self.session_token,
            "cookies": self.cookies,
            "error": self.error,
            "stage": self.stage,
            "action_result": self.action_result,
            **({"login_failure": normalize_login_failure(self.login_failure)}
               if not self.ok and normalize_login_failure(self.login_failure) is not None else {}),
        }


def _make_logger(log_fn: Optional[Callable[[str], None]]):
    if callable(log_fn):
        return log_fn
    return lambda msg: print(msg, flush=True)


def _create_roxy_browser(*, log, proxy=None):
    """用 RoxyBrowser 指纹浏览器新建一个带指定代理的窗口并交给 DrissionPage 接管。

    proxy: 应用侧代理 dict(host/port/protocol/username/password/note/roxy_module_id),
           None 表示无代理。窗口用完后 close()+delete() 自动清理。

    给返回的 page 包一层 quit: 现有所有 page.quit() 调用点(登录 finally / phase2 结束 /
    kill 旧任务)都会自动关掉 RoxyBrowser 窗口, 实现「处理完一个自动退出」, 无需改这些调用点。
    """
    from core.roxy_browser import RoxyBrowserSession

    session = RoxyBrowserSession(proxy=proxy, log=log)
    page = session.open()

    _orig_quit = page.quit

    def _quit_via_roxy(*args, **kwargs):
        try:
            session.close()   # 走 RoxyBrowser /browser/close 干净关窗
        except Exception:
            try:
                _orig_quit(*args, **kwargs)
            except Exception:
                pass

    try:
        page.quit = _quit_via_roxy  # type: ignore[assignment]
    except Exception:
        # 某些 DrissionPage 版本 page.quit 只读, 退回到会话对象手动关(仍能工作,只是不自动)
        pass
    return page


def _create_browser(*, proxy: str, headless: bool, log):
    from DrissionPage import ChromiumOptions, ChromiumPage
    from core.browser_startup import start_local_browser

    def options():
        co = ChromiumOptions()
        co.incognito()
        # 不用 eager：normal 等整页 load，让 React hydration 完成后再填邮箱。
        # eager 可能在 hydration 前点击，触发原生 GET 提交并清空邮箱。
        co.headless(headless)
        co.set_argument("--disable-blink-features=AutomationControlled")
        co.set_argument("--disable-dev-shm-usage")
        co.set_argument("--no-sandbox")
        co.set_argument("--disable-gpu")
        co.set_argument("--no-first-run")
        co.set_argument("--no-default-browser-check")
        co.set_argument("--lang=en-US")
        co.set_argument("--window-size=1280,900")
        if proxy:
            co.set_proxy(proxy)
        co.set_user_agent(_DEFAULT_UA)
        return co

    def initialize(page):
        page.run_js(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
            "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});"
            "Object.defineProperty(navigator,'language',{get:()=>'en-US'});"
            "Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});"
            "window.chrome={runtime:{}};"
        )
    page = start_local_browser(options, page_factory=ChromiumPage, initialize=initialize, log=log)
    log(f"[GPT PRO 登录] 浏览器已创建 (代理={'已配置' if proxy else '无'}, headless={headless})")
    return page


def run_ms_web_login(email: str, password: str, *, proxy: str = "",
                     headless: bool = False, log_fn=None) -> dict:
    """打开可见浏览器, 自动登录 outlook.com 网页版邮箱, 登录后停在邮箱页保持打开。
    专供"不支持 API 发信(imap_pop)"的号: 登录后可在网页里手动发信。
    遇到验证码/两步验证等挑战时, 不强行处理, 直接停在页面让人工接管。
    返回 {ok, stage, url}; 浏览器**不关闭**(由人工使用后手动关)。"""
    log = log_fn or (lambda m: print(m, flush=True))
    page = _create_browser(proxy=proxy, headless=headless, log=log)

    def _find(selectors, timeout=8):
        for sel in selectors:
            try:
                el = page.ele(sel, timeout=timeout)
                if el:
                    return el
            except Exception:
                continue
        return None

    def _click(selectors, timeout=6):
        el = _find(selectors, timeout=timeout)
        if el:
            try:
                el.click()
                return True
            except Exception:
                try:
                    page.run_js("arguments[0].click();", el)
                    return True
                except Exception:
                    return False
        return False

    try:
        log(f"[MS登录] 打开 outlook.live.com, 账号 {email}")
        page.get("https://login.live.com/")
        time.sleep(3)

        # 1) 填邮箱 → Next
        email_el = _find(('css:input[type="email"]', 'css:input[name="loginfmt"]', '#i0116'), timeout=15)
        if email_el:
            try:
                email_el.clear(); email_el.input(email)
            except Exception:
                page.run_js("arguments[0].value=arguments[1];"
                            "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));", email_el, email)
            log("[MS登录] 已填邮箱, 点 下一步")
            _click(('#idSIButton9', 'css:input[type="submit"]', 'css:button[type="submit"]'))
            time.sleep(3)
        else:
            log("[MS登录] ⚠ 未找到邮箱输入框(可能已登录/跳到别的页), 继续")

        # 2) 若默认走"发验证码到备用邮箱"(该号绑了其他邮箱)→ 先按文字点"使用密码"切到密码登录
        def _click_by_text(texts) -> bool:
            """按可见文字精确/包含匹配点击(新版 login UI 的'使用密码'不是标准 a/button, 用 JS 找)。"""
            try:
                js = """
                var wants = arguments[0];
                function clickable(e){
                    if(!e) return false;
                    if(e.tagName==='A'||e.tagName==='BUTTON') return true;
                    if((e.getAttribute&&e.getAttribute('role'))==='button') return true;
                    var c=(e.className||'').toString();
                    if(/link|button/i.test(c)) return true;
                    try{ if(getComputedStyle(e).cursor==='pointer') return true; }catch(x){}
                    return false;
                }
                var els = document.querySelectorAll('button,a,span,div,[role=button]');
                var fb=null;
                for (var i=0;i<els.length;i++){
                    var t=(els[i].innerText||els[i].textContent||'').trim();
                    var hit=false;
                    for (var j=0;j<wants.length;j++){
                        if (t===wants[j] || (t.length<=12 && t.indexOf(wants[j])>=0)){ hit=true; break; }
                    }
                    if(!hit) continue;
                    if(clickable(els[i])){ els[i].click(); return true; }
                    if(!fb) fb=els[i];
                }
                if(fb){ var p=fb; for(var k=0;k<4&&p;k++){ if(clickable(p)){p.click(); return true;} p=p.parentElement; } fb.click(); return true; }
                return false;
                """
                return bool(page.run_js(js, texts))
            except Exception:
                return False

        pw_el = _find(('css:input[type="password"]', 'css:input[name="passwd"]', '#i0118'), timeout=8)
        if not pw_el:
            log("[MS登录] 未直接出现密码框(默认走验证码), 按文字点「使用密码」切换")
            ok = _click_by_text(["使用密码", "改用密码", "输入密码", "Use your password", "Use password"])
            if not ok:
                # 落到"选择登录方式"页: 先点"其他登录方式", 再点"密码"
                _click_by_text(["其他登录方式", "其他验证方式", "Other ways to sign in", "Sign-in options"])
                time.sleep(2)
                _click_by_text(["使用密码", "密码", "Password", "Use your password"])
            log(f"[MS登录] 切换'使用密码' {'已点' if ok else '(兜底路径)'}")
            time.sleep(3)
            pw_el = _find(('css:input[type="password"]', 'css:input[name="passwd"]', '#i0118'), timeout=10)

        # 填密码 → 登录
        if pw_el:
            try:
                pw_el.clear(); pw_el.input(password)
            except Exception:
                page.run_js("arguments[0].value=arguments[1];"
                            "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));", pw_el, password)
            log("[MS登录] 已填密码, 点 登录")
            _click(('#idSIButton9', 'css:input[type="submit"]', 'css:button[type="submit"]'))
            time.sleep(4)
        else:
            log("[MS登录] ⚠ 未找到密码输入框(可能遇到验证/passkey页), 停在页面人工接管")

        # 3) 常见插页: "改用无密码/passkey?" → 跳过; "保持登录?" → 是
        # 跳过 passkey/加强保护 提示
        _click(('#iShowSkip', 'css:a#iShowSkip', 'xpath://*[normalize-space()="Skip for now" or normalize-space()="以后再说" or normalize-space()="暂时跳过"]'), timeout=4)
        time.sleep(1)
        # "保持登录状态?" → 是 (idSIButton9 = 是)
        _click(('#idSIButton9', 'xpath://input[@value="Yes" or @value="是"]'), timeout=4)
        time.sleep(3)

        # 4) 进邮箱
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if "outlook" not in cur.lower():
            log("[MS登录] 导航到 outlook.live.com/mail")
            try:
                page.get("https://outlook.live.com/mail/0/")
                time.sleep(4)
                cur = page.url or ""
            except Exception:
                pass

        cl = (cur or "").lower()
        logged = ("outlook.live.com/mail" in cl) or ("outlook.office.com/mail" in cl) or ("outlook.office365.com/mail" in cl)
        log(f"[MS登录] {'✅ 已进入邮箱' if logged else '⚠ 未确认进入邮箱(可能有验证挑战), 浏览器保留请人工完成'} URL={cur}")
        return {"ok": True, "stage": "logged_in" if logged else "needs_manual",
                "url": cur, "note": "浏览器已保留打开, 可在网页里手动发信/完成验证。"}
    except Exception as exc:
        log(f"[MS登录] 异常(浏览器保留): {exc}")
        return {"ok": False, "stage": "exception", "error": str(exc)}


_EMAIL_CSS_SELECTORS = (
    'input[type="email"]',
    'input[name="email"]',
    'input[autocomplete="email"]',
    'input[autocomplete="username"]',
    'input[name="username"]',
    'input[placeholder*="电子邮件"]',
    'input[placeholder*="Email"]',
    'input[placeholder*="email"]',
)
_EMAIL_SELECTORS = tuple(f"css:{selector}" for selector in _EMAIL_CSS_SELECTORS)
_EMAIL_CSS_QUERY = ",".join(_EMAIL_CSS_SELECTORS)

# 注意顺序: chatgpt.com 登录弹窗盖在聊天首页上, 页面有很多 button[type=submit]
# (关侧栏/登录/注册/语音…), "继续"排在最后。若先取 button[type=submit] 会点错第一个 →
# 以为点了继续其实没提交邮箱 → 卡在"点不到继续"。所以**精确文本"继续"必须放最前**。
_CONTINUE_SELECTORS = (
    # 精确文本匹配(不能用 text:继续 包含匹配, 否则会命中「使用 Google 账户继续」等社交按钮)
    'xpath://button[normalize-space()="继续" or normalize-space()="Continue" '
    'or normalize-space()="続行" or normalize-space()="続ける" or normalize-space()="繼續" '
    'or normalize-space()="次へ" or normalize-space()="다음" or normalize-space()="계속"]',
    'css:button[data-testid="continue-button"]',
    'css:button[type="submit"]',   # 最后兜底
)

# The home page may preload hidden login forms.  DOM existence (including a
# successful click() on a hidden button) is not evidence of a submitted form.
_CONTINUE_CLICK_JS = r"""
return (function(){
  if(location.protocol!=='https:' || !['chatgpt.com','auth.openai.com'].includes(location.hostname)
     || (location.port && location.port!=='443')) return false;
  function displayed(e){
    if(!e || !e.isConnected)return false;
    if(e.closest('dialog:not([open]),[inert],[hidden],[aria-hidden="true"]'))return false;
    var r=e.getBoundingClientRect(),s=getComputedStyle(e);
    return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden' && s.visibility!=='collapse';
  }
  function visible(e){return displayed(e) && !e.disabled && e.getAttribute('aria-disabled')!=='true' && !e.closest('fieldset[disabled]');}
  function txt(b){return (b.innerText||b.value||'').trim();}
  // This helper submits email only.  Recheck inside the same script: a route
  // observed by Python may already have become a password/OTP challenge.
  var nextStage='input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"],'
    + 'input[autocomplete="one-time-code"],input[name="code"],input[inputmode="numeric"],input[data-testid="code-input"]';
  if(Array.from(document.querySelectorAll(nextStage)).some(displayed))return false;
  if(Array.from(document.querySelectorAll('h1,h2,h3,[role="heading"],label')).some(e=>displayed(e)
    && /authenticator|authentication code|身份验证器|身份验证应用|验证器|認証アプリ/i.test(e.innerText||e.textContent||'')))return false;
  var path=location.pathname.replace(/\/+$/,'') || '/';
  if(/(?:password|code|verify|verification|consent|phone|mfa|authenticator|about-you|workspace)/i.test(path))return false;
  var controls=Array.from(document.querySelectorAll(EMAIL_QUERY)).filter(visible);
  var roots=[...new Set(controls.map(e=>e.form || e.closest('form') || e.closest('dialog,[role="dialog"]')))];
  if(roots.length>1 || (roots.length===1 && !roots[0]))return false;
  var root=roots[0] || null;
  // A no-input interstitial may offer one explicit Continue.  A public home
  // page or an unknown route must not submit an unrelated composer/form.
  var loginRoute=location.hostname==='chatgpt.com'
    ? ['/auth/login','/auth/login_with'].includes(path)
    : ['/log-in','/login'].includes(path);
  if(!root && !loginRoute)return false;
  var btns=Array.from(document.querySelectorAll('button,input[type=submit],[role=button]'))
    .filter(b=>visible(b) && (!root || root.contains(b) || b.form===root));
  var exact=['继续','繼續','Continue','続行','続ける','次へ','다음','계속'];
  var candidates=btns.filter(b=>exact.includes(txt(b)));
  if(!candidates.length)candidates=btns.filter(b=>b.getAttribute('data-testid')==='continue-button');
  if(!candidates.length && root)candidates=btns.filter(function(b){
    if(b.tagName!=='BUTTON' || b.type!=='submit')return false;
    var tid=(b.getAttribute('data-testid')||'').toLowerCase();
    if(/login|signup|close|composer|model|sidebar|speech|profile|switcher|voice/.test(tid))return false;
    return !/google|apple|电话|phone|微软|microsoft|登录|免费注册|sign\s?in|sign\s?up|log\s?in|忘记|forgot/i.test(txt(b));
  });
  if(candidates.length!==1)return false;
  var target=candidates[0];
  try{target.scrollIntoView({block:'center'});}catch(e){}
  if(!visible(target))return false;
  target.click();
  return true;
})();
""".replace("EMAIL_QUERY", json.dumps(_EMAIL_CSS_QUERY))

_OTP_SELECTORS = (
    'css:input[autocomplete="one-time-code"]',
    'css:input[name="code"]',
    'css:input[inputmode="numeric"]',
    'css:input[data-testid="code-input"]',
)

# 回读 OTP 输入框当前值(校验键入是否被 React 接受)。
_OTP_READBACK_JS = r"""
return (function(){
    const el = document.querySelector(
        'input[autocomplete="one-time-code"], input[name="code"], '
        + 'input[inputmode="numeric"], input[data-testid="code-input"]');
    return { value: el ? (el.value || '') : '', found: !!el };
})();
"""

# 检测 OTP 页「续行/Continue」按钮是否存在且可点。
_OTP_SUBMIT_READY_JS = r"""
return (function(){
    let btn = document.querySelector(
        'button[type="submit"], button[data-testid="continue-button"]');
    if (!btn) {
        const btns = [...document.querySelectorAll('button')];
        btn = btns.find(b => /続行|続ける|継続|继续|繼續|continue|verify|確認|확인|다음|次へ/i
            .test((b.textContent||'').trim()));
    }
    if (!btn) return {found:false, enabled:false, text:''};
    return {found:true, enabled: !btn.disabled, text:(btn.textContent||'').trim().slice(0,40)};
})();
"""

# 注册流的 about-you (姓名+生日) 备选随机数据
_RANDOM_FIRST_NAMES = (
    "James", "Emma", "Liam", "Olivia", "Noah", "Ava",
    "William", "Sophia", "Lucas", "Mia", "Henry", "Charlotte",
)
_RANDOM_LAST_NAMES = (
    "Smith", "Johnson", "Brown", "Davis", "Wilson",
    "Moore", "Taylor", "Anderson", "Thomas", "Jackson",
)


def _gen_random_name() -> str:
    return f"{random.choice(_RANDOM_FIRST_NAMES)} {random.choice(_RANDOM_LAST_NAMES)}"


def _gen_random_birthday() -> dict:
    return {
        "year": random.randint(1985, 2000),
        "month": random.randint(1, 12),
        "day": random.randint(1, 28),
    }


# 填生日的 JS, 直接复用 drission_register.py 同款逻辑 (Spinbutton / Age input / React Aria Select 三种 fallback)
_BIRTHDAY_JS_TEMPLATE = """
(async function() {{
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
    // The current React-Aria page generates an opaque id for the birthday
    // group. Resolve it from semantic date segments first.
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
        const ageInput = Array.from(
            document.querySelectorAll('input[name="age"]')
        ).find(usable);
        if (ageInput) {{
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
            nativeInputValueSetter.call(ageInput, '{age}');
            ageInput.dispatchEvent(new Event('input', {{bubbles: true}}));
            ageInput.dispatchEvent(new Event('change', {{bubbles: true}}));
            return 'age';
        }}
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
            setSelect(selects[1], '{month_num}');
            await sleep(200);
            setSelect(selects[2], '{day_num}');
            return 'select';
        }}
        return false;
    }}
    const fillSpinbutton = async (segment, valueStr) => {{
        if (!usable(segment)) return false;
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
        return true;
    }};
    const yearSeg = dateField.querySelector('[role="spinbutton"][data-type="year"]');
    const monthSeg = dateField.querySelector('[role="spinbutton"][data-type="month"]');
    const daySeg = dateField.querySelector('[role="spinbutton"][data-type="day"]');
    if (![yearSeg, monthSeg, daySeg].every(usable)) return false;
    await fillSpinbutton(yearSeg, '{year_str}');
    await sleep(150);
    await fillSpinbutton(monthSeg, '{month_str}');
    await sleep(150);
    await fillSpinbutton(daySeg, '{day_str}');
    return 'spinbutton';
}})();
"""

_ABOUT_YOU_CHECKBOX_JS = """
const cb = document.querySelector('input[name="allCheckboxes"][type="checkbox"]');
if (cb && !cb.checked) {
    const label = cb.closest('label');
    if (label) label.click(); else cb.click();
}
"""

# 用 React 原生 setter + 事件可靠清空已标记(data-gp-fill)的输入框, 并回读清空后的值。
# 修复: DrissionPage el.clear() 对 React 受控组件不可靠(DOM 清了但 React state 没清),
# 重填时旧值回流成"旧值+新值"。这里发 input/change 事件让 React 同步把 state 也清空。
_ABOUT_YOU_CLEAR_JS = r"""
return (function(){
    const setter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value').set;
    const out = {};
    document.querySelectorAll('[data-gp-fill]').forEach(function(el){
        const k = el.getAttribute('data-gp-fill');
        try {
            el.focus();
            if (el._valueTracker) el._valueTracker.setValue('x');
            setter.call(el, '');
            el.dispatchEvent(new InputEvent('input',
                {inputType:'deleteContentBackward', bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
        } catch(e) {}
        out[k] = el.value || '';
    });
    return out;
})();
"""

# 回读已标记输入框的当前值, 用于校验键入是否被 React 接受。
_ABOUT_YOU_READBACK_JS = r"""
return (function(){
    const out = {};
    document.querySelectorAll('[data-gp-fill]').forEach(function(el){
        out[el.getAttribute('data-gp-fill')] = el.value || '';
    });
    return out;
})();
"""

# 检测提交按钮是否存在且可点(未 disabled)。
_ABOUT_YOU_SUBMIT_READY_JS = r"""
return (function(){
    let btn = document.querySelector('button[type="submit"]');
    if (!btn) {
        const btns = [...document.querySelectorAll('button')];
        btn = btns.find(b => /完了|完成|続ける|続行|continue|次へ|create|作成|아카운트|완료|아이디/i
            .test((b.textContent||'').trim()));
    }
    if (!btn) return {found:false, enabled:false, text:''};
    return {found:true, enabled: !btn.disabled, text:(btn.textContent||'').trim().slice(0,40)};
})();
"""


def _wait_about_you_or_landed(page, *, timeout: int = 15) -> str:
    """OTP 提交后等待: 进 /about-you → 返回 'about_you'; 直接到 chatgpt.com → 返回 'landed'."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _stop_existing_account_context(page)
        url = page.url or ""
        if "/about-you" in url:
            return "about_you"
        if "chatgpt.com" in url and "/auth/" not in url and "/log-in" not in url:
            return "landed"
        time.sleep(0.4)
    return ""


# about-you: 只负责「定位姓名/年龄输入框并打 data-gp-fill 标记」(多语言标签: 氏名/名前/name,
# 年齢/age/年龄; 年龄兼容 numeric)。实际填值交给 DrissionPage 原生键入(真实 key 事件, React 才认)。
_ABOUT_YOU_TAG_JS = r"""
return (function() {
    const visible = (el) => el && el.offsetParent !== null && !el.disabled && !el.readOnly;
    const inputs = [...document.querySelectorAll('input')].filter(visible);
    const label = (i) => ((i.placeholder||'') + ' ' + (i.getAttribute('aria-label')||'') + ' ' + (i.name||'') + ' ' + (i.autocomplete||''));
    let ageInput = document.querySelector('input[name="age"]')
        || inputs.find(i => /age|年齢|年龄|나이|edad|âge/i.test(label(i)))
        || inputs.find(i => i.type === 'number' || i.getAttribute('inputmode') === 'numeric');
    let nameInput = document.querySelector('input[name="name"]')
        || document.querySelector('input[autocomplete="name"]')
        || inputs.find(i => /name|氏名|名前|姓名|이름|nombre|nom/i.test(label(i)))
        || inputs.find(i => i !== ageInput && (i.type === 'text' || i.type === ''));
    document.querySelectorAll('[data-gp-fill]').forEach(e => e.removeAttribute('data-gp-fill'));
    if (nameInput) nameInput.setAttribute('data-gp-fill', 'name');
    if (ageInput && ageInput !== nameInput) ageInput.setAttribute('data-gp-fill', 'age');
    return {name: !!nameInput, age: !!(ageInput && ageInput !== nameInput), count: inputs.length,
        dump: inputs.map(i => ({name:i.name||'', type:i.type||'', ph:i.placeholder||'', aria:i.getAttribute('aria-label')||''}))};
})();
"""


def _fill_about_you(page, full_name: str, birthday: dict, log) -> None:
    """注册流第 5 步: 填姓名 + 年龄/生日 + 同意复选框 + 提交(多语言 + 多布局健壮匹配)。

    姓名/年龄用标签语义匹配(氏名/名前/name, 年齢/age); 生日 DOM 三种布局 JS fallback 全覆盖:
      1. spinbutton (新版日期选择器)  2. input[name="age"] (年龄输入)  3. React Aria Select×3。
    """
    log(f"[GPT PRO 注册] 填资料: name={full_name} birthday={birthday['year']}-{birthday['month']:02d}-{birthday['day']:02d}")

    # 等表单就绪(重试/慢代理后 DOM 可能刚 render): 轮询直到出现可见 input(最多 12s)
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            if page.run_js("return [...document.querySelectorAll('input')].some(i => i.offsetParent !== null);"):
                break
        except Exception:
            pass
        time.sleep(0.5)

    try:
        from datetime import datetime as _dt
        age = max(18, _dt.now().year - int(birthday["year"]))
    except Exception:
        age = 2025 - int(birthday["year"])

    # 1) JS 定位并标记姓名/年龄输入框(多语言)
    try:
        res = page.run_js(_ABOUT_YOU_TAG_JS) or {}
    except Exception as exc:
        res = {}
        log(f"[GPT PRO 注册] 定位输入框 JS 异常(忽略): {exc}")
    log(f"[GPT PRO 注册] 定位: 姓名框={res.get('name')} 年龄框={res.get('age')} 可见input={res.get('count')}")
    if not res.get("name"):
        log(f"[GPT PRO 注册] ⚠ 未匹配到姓名框, 表单 input 结构: {res.get('dump')}")

    # 1.5) 键入前先用 React 原生事件可靠清空旧值(重填场景防止旧值回流拼接)
    try:
        cleared = page.run_js(_ABOUT_YOU_CLEAR_JS) or {}
        if any((cleared or {}).values()):
            log(f"[GPT PRO 注册] ⚠ 清空后仍有残值: {cleared}(继续键入)")
    except Exception as exc:
        log(f"[GPT PRO 注册] 清空输入框 JS 异常(忽略): {exc}")

    # 2) 用 DrissionPage 原生键入(真实 key 事件, React 受控组件才会更新状态)
    if res.get("name"):
        el = _safe_ele(page, 'css:[data-gp-fill="name"]', timeout=4)
        if el:
            try:
                el.input(full_name, clear=False)
                time.sleep(0.3)
            except Exception as exc:
                log(f"[GPT PRO 注册] 姓名键入异常(忽略): {exc}")

    age_typed = False
    if res.get("age"):
        el = _safe_ele(page, 'css:[data-gp-fill="age"]', timeout=2)
        if el:
            try:
                el.input(str(age), clear=False)
                age_typed = True
                time.sleep(0.3)
            except Exception as exc:
                log(f"[GPT PRO 注册] 年龄键入异常(忽略): {exc}")

    # 3) 生日/日期选择器布局(spinbutton / react-aria) — 仅当没有简单年龄输入框时才用 JS
    if not age_typed:
        js = _BIRTHDAY_JS_TEMPLATE.format(
            year=birthday["year"],
            month_num=birthday["month"],
            day_num=birthday["day"],
            year_str=str(birthday["year"]),
            month_str=str(birthday["month"]).zfill(2),
            day_str=str(birthday["day"]).zfill(2),
            age=age,
        )
        try:
            page.run_js(js)
            time.sleep(1)
        except Exception as exc:
            log(f"[GPT PRO 注册] 生日 JS 异常(忽略): {exc}")

    # 同意复选框 (韩国/欧盟等 IP 场景必填)
    try:
        page.run_js(_ABOUT_YOU_CHECKBOX_JS)
        time.sleep(0.4)
    except Exception:
        pass

    # 回读校验: 确认姓名/年龄真的被 React 接受(否则按钮会一直 disabled)
    try:
        vals = page.run_js(_ABOUT_YOU_READBACK_JS) or {}
        log(f"[GPT PRO 注册] 回读输入框: {vals}")
    except Exception:
        pass

    # 点提交前轮询等按钮变可点(最多 8s); 值没被接受 → 按钮 disabled, 早暴露原因
    ready = {}
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            ready = page.run_js(_ABOUT_YOU_SUBMIT_READY_JS) or {}
        except Exception:
            ready = {}
        if ready.get("enabled"):
            break
        time.sleep(0.5)
    if not ready.get("enabled"):
        try:
            vals = page.run_js(_ABOUT_YOU_READBACK_JS) or {}
        except Exception:
            vals = {}
        log(f"[GPT PRO 注册] ⚠ 提交按钮仍不可点 (found={ready.get('found')} text={ready.get('text')!r}); 当前输入值={vals} — 仍尝试点击兜底")

    # 只点击当前资料表单里的可见提交按钮。页面可能同时保留隐藏的旧
    # React 节点，按全局 selector 点击会命中错误按钮并一直留在本页。
    try:
        from platforms.chatgpt.drission_register import _click_visible_form_submit
        if _click_visible_form_submit(page):
            log("[GPT PRO 注册] 已点击「完成/继续」提交资料")
            return
    except Exception as exc:
        log(f"[GPT PRO 注册] 表单提交定位异常(转兼容路径): {exc}")

    # 小型测试适配器和旧页面对象没有 ``eles``，保留原生兼容路径；
    # ChromiumPage 不再退回全局按钮，避免误点页面外的操作。
    if not callable(getattr(page, "eles", None)):
        for sel in _CONTINUE_SELECTORS + ('css:button[type="submit"]',):
            ele = _safe_ele(page, sel, timeout=1.5)
            if ele:
                try:
                    ele.click()
                    log("[GPT PRO 注册] 已点击「完成/继续」提交资料")
                    return
                except Exception:
                    continue
    log("[GPT PRO 注册] ⚠ 没找到提交按钮")


def _about_you_submission_advanced(page, *, allow_existing_login_context: bool = False) -> bool:
    """An error/login page is not proof that profile submission succeeded."""
    if not allow_existing_login_context:
        _stop_existing_account_context(page)
    try:
        current = urlparse(str(page.url or ""))
        if (current.scheme != "https" or current.port not in (None, 443)
                or current.username is not None or current.password is not None):
            return False
        if (page.run_js(_OPENAI_ERROR_PAGE_JS) or {}).get("isError"):
            return False
        if current.hostname == "chatgpt.com":
            return not re.match(r"^/(?:auth|log-in)(?:/|$)", current.path)
        return bool(current.hostname == "auth.openai.com" and re.match(
            r"^/(?:workspace|consent|phone-verification|phone|add-phone|authorize|callback)(?:/|$)", current.path))
    except Exception:
        return False


def _submit_about_you_with_retry(page, full_name: str, birthday: dict, log,
                                 *, max_attempts: int = 3,
                                 leave_timeout: float = 15.0,
                                 allow_existing_login_context: bool = False) -> bool:
    """填 about-you 并确认提交成功(离开 /about-you), 失败自动重填。

    修复场景: 第一次提交撞上 OpenAI 报错页/超时, 页面刷新后表单被清空,
    旧逻辑只填一次不回头 → 空表单挂到 landing 超时。
    返回 True=已离开 about-you; False=重试 max_attempts 次后仍停留。
    """
    for attempt in range(1, max_attempts + 1):
        # 每轮先处理报错页(点「重试」会重新加载 about-you 空表单)
        if not _recover_openai_error_page(
            page, log_fn=log,
            allow_existing_login_context=allow_existing_login_context,
        ):
            return False
        if "/about-you" not in (page.url or ""):
            return _about_you_submission_advanced(
                page, allow_existing_login_context=allow_existing_login_context,
            )
        if attempt > 1:
            log(f"[GPT PRO 注册] 仍在 /about-you, 第 {attempt}/{max_attempts} 次重填资料…")
        _fill_about_you(page, full_name, birthday, log)
        # 提交后等待离开 about-you (成功会跳 phone/consent/chatgpt.com 等)
        deadline = time.time() + leave_timeout
        while time.time() < deadline:
            if not allow_existing_login_context:
                _stop_existing_account_context(page)
            if "/about-you" not in (page.url or ""):
                advanced = _about_you_submission_advanced(
                    page, allow_existing_login_context=allow_existing_login_context,
                )
                if advanced:
                    log("[GPT PRO 注册] ✅ about-you 提交成功, 已进入后续页面")
                return advanced
            time.sleep(0.8)
        log(f"[GPT PRO 注册] ⚠ 提交后 {int(leave_timeout)}s 仍停留在 /about-you (第 {attempt}/{max_attempts} 次)")
    return _about_you_submission_advanced(
        page, allow_existing_login_context=allow_existing_login_context,
    )


# Only explicit login controls are eligible; header primary buttons may be signup.
_LOGIN_BTN_SELECTORS = (
    'css:button[data-testid="login-button"]',
    'css:a[data-testid="login-button"]',
    'css:[role="button"][data-testid="login-button"]',
    'xpath://*[self::button or self::a or @role="button"][normalize-space()="Log in" '
    'or normalize-space()="Login" or normalize-space()="Sign in" or normalize-space()="登录" '
    'or normalize-space()="登入" or normalize-space()="登入帳戶" or normalize-space()="ログイン" '
    'or normalize-space()="サインイン" or normalize-space()="로그인"]',
)

# JS 兜底:用完整鼠标事件序列触发(纯 .click() 有时不触发 React 弹窗)。
_CLICK_LOGIN_BTN_JS = r"""
return (function(){
  if(location.protocol!=='https:' || !['chatgpt.com','auth.openai.com'].includes(location.hostname)
     || (location.port && location.port!=='443'))return false;
  const vis=(e)=>{if(!e || !e.isConnected || e.disabled || e.getAttribute('aria-disabled')==='true'
    || e.closest('dialog:not([open]),[inert],[hidden],[aria-hidden="true"],fieldset[disabled]'))return false;
    const r=e.getBoundingClientRect(),s=getComputedStyle(e);
    return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden'&&s.visibility!=='collapse';};
  const norm=(t)=>(t||'').replace(/\s+/g,' ').trim();
  const RE=/^(?:log\s?in|sign\s?in|登录|登入|登入帳戶|ログイン|サインイン|로그인)$/i;
  const isLogin=(e)=>e.getAttribute('data-testid')==='login-button'
    || RE.test(norm(e.innerText||e.textContent||e.value)) || RE.test(norm(e.getAttribute('aria-label')));
  const fire=(el)=>{
    const b=(el.closest&&el.closest('button,a,[role=button]'))||el;
    const r=b.getBoundingClientRect();
    const o={bubbles:true,cancelable:true,clientX:r.x+r.width/2,clientY:r.y+r.height/2,button:0};
    try{b.dispatchEvent(new PointerEvent('pointerdown',o));}catch(_){}
    b.dispatchEvent(new MouseEvent('mousedown',o));
    try{b.dispatchEvent(new PointerEvent('pointerup',o));}catch(_){}
    b.dispatchEvent(new MouseEvent('mouseup',o));
    b.click();
    return true;
  };
  const btns=[...document.querySelectorAll('button, a, [role=button]')].filter(vis).filter(isLogin);
  const el=btns.find(b=>b.getAttribute('data-testid')==='login-button') || btns[0];
  if(el) return fire(el);
  return false;
})();
"""


def _pass_cf_challenge(page, log, *, max_refresh: int = 3, wait_each: float = 4.0) -> bool:
    """首屏命中 Cloudflare 人机校验(或登录按钮迟迟不出现)时自动刷新几次让其通过,
    等同用户手动刷新。返回 True=已就绪(能看到登录按钮/邮箱框)。"""
    for i in range(max_refresh + 1):
        # 已能看到登录按钮或邮箱框 → 已就绪
        if _safe_ele(page, _LOGIN_BTN_SELECTORS[0], timeout=1) or _refind_email_input(page):
            return True
        url = ""
        body = ""
        try:
            url = page.url or ""
            body = page.run_js("return (document.body&&document.body.innerText||'').slice(0,200)") or ""
        except Exception:
            pass
        cf = ("__cf_chl" in url) or any(
            k in body for k in ("Just a moment", "Verifying you are human",
                                "Enable JavaScript", "正在验证", "请稍候")
        )
        if i == 0 and not cf:
            time.sleep(wait_each)   # 无明显挑战: 给 SPA 首屏多一点渲染时间
            continue
        if i < max_refresh:
            log(f"[GPT PRO 登录] 首屏未就绪{'(Cloudflare 校验)' if cf else ''}, 自动刷新第 {i + 1} 次")
            try:
                page.refresh()
            except Exception:
                pass
            time.sleep(wait_each)
    return False


def _open_login_modal(page, log, *, attempts: int = 8) -> bool:
    """新版主页需先点「登录」打开登录弹窗;弹窗里才有 Email 输入框。

    优先用 DrissionPage 原生点击(CDP 可信点击, 能触发 React onClick);
    登录按钮有稳定属性 data-testid="login-button"。JS 合成事件仅作兜底。
    只有真实可交互的邮箱框才能证明弹窗已开；主页可预加载零尺寸隐藏表单。
    """
    for _ in range(attempts):
        if _refind_email_input(page):
            return True
        # JS 优先点登录按钮(比原生选择器更快更稳命中; 原生 _safe_ele 检测时机太挑, 常超时)
        clicked = False
        try:
            if page.run_js(_CLICK_LOGIN_BTN_JS):
                clicked = True
                log("[GPT PRO 登录] 已用 JS 点登录按钮打开登录弹窗")
        except Exception:
            pass
        if not clicked:
            # JS 没命中 → 原生点击兜底
            for sel in _LOGIN_BTN_SELECTORS:
                ele = _safe_ele(page, sel, timeout=0.6)
                if ele:
                    try:
                        ele.click()
                        log(f"[GPT PRO 登录] 已点登录按钮({sel})打开登录弹窗")
                        break
                    except Exception:
                        continue
        time.sleep(1.2)
    return bool(_refind_email_input(page))


def _find_email_input(page, *, timeout: float = 15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ele = _refind_email_input(page)
        if ele:
            return ele
        time.sleep(0.4)
    return None


def _wait_page_ready(page, *, timeout: float = 18.0, min_wait: float = 3.0) -> None:
    """等页面完全加载 + React hydration 就绪再点「继续」。

    eager 加载模式下 page.get 在 DOMContentLoaded 就返回, 此时 React 还没 hydrate
    (事件处理器没挂上); 这时点提交按钮会退回**原生表单 GET 提交**(URL 变 ?email=…)、
    不触发 React 的跳转 → 刷回登录页, 一直循环。等 readyState=complete 且至少 min_wait 秒,
    让 hydration 完成。"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            rs = page.run_js("return document.readyState")
        except Exception:
            rs = ""
        if rs == "complete" and (time.time() - start) >= min_wait:
            return
        time.sleep(0.5)
    remain = min_wait - (time.time() - start)
    if remain > 0:
        time.sleep(remain)


_EMAIL_RESOLVE_JS = (
    "var selector=" + json.dumps(_EMAIL_CSS_QUERY) + ";"
    "function interactionStatus(e){if(!e)return 'missing';if(!e.isConnected)return 'detached';"
    "if(e.disabled)return 'disabled';if(e.readOnly)return 'readonly';"
    "if(e.closest('dialog:not([open]),[inert],[hidden],[aria-hidden=\"true\"],fieldset[disabled]'))return 'blocked';"
    "var r=e.getBoundingClientRect(),s=getComputedStyle(e);"
    "if(r.width<=0 || r.height<=0)return 'zero_rect';"
    "if(s.display==='none' || s.visibility==='hidden' || s.visibility==='collapse')return 'hidden';"
    "return 'usable';}"
    "function emailStatus(e){var status=interactionStatus(e);"
    "return status==='usable' && !e.matches(selector)?'selector_mismatch':status;}"
    "function usable(e){return emailStatus(e)==='usable';}"
    "function resolve(preferred){if(usable(preferred))return preferred;"
    "var candidates=Array.from(document.querySelectorAll(selector)).filter(usable);"
    "return candidates.length===1?candidates[0]:null;}"
)
_EMAIL_CANDIDATE_STATUS_JS = _EMAIL_RESOLVE_JS + "return emailStatus(arguments[0]);"
_EMAIL_INPUT_DIAGNOSTICS_JS = (
    _EMAIL_RESOLVE_JS + "var candidates=Array.from(document.querySelectorAll(selector));"
    "return {preferred_status:emailStatus(arguments[0]),match_count:candidates.length,"
    "usable_count:candidates.filter(usable).length,"
    "zero_rect_count:candidates.filter(e=>emailStatus(e)==='zero_rect').length,"
    "blocked_count:candidates.filter(e=>emailStatus(e)==='blocked').length,ready_state:document.readyState};"
)
_EMAIL_READBACK_JS = (
    _EMAIL_RESOLVE_JS + "var e=resolve(arguments[0]);"
    "return e?e.value:'__noinput__';"
)
_EMAIL_SET_JS = (
    _EMAIL_RESOLVE_JS + "var em=arguments[0];var e=resolve(arguments[1]);"
    "if(!e)return '__noinput__';"
    "var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');"
    "d.set.call(e, em);"
    "e.dispatchEvent(new Event('input',{bubbles:true}));"
    "e.dispatchEvent(new Event('change',{bubbles:true}));"
    "return e.value;"
)

# Only an anti-resubmission guard, never authentication proof. A public home
# URL is insufficient: the ChatGPT login modal lives on that same URL.
_EMAIL_ENTRY_STATE_JS = (
    "/* email_entry_state */" + _EMAIL_RESOLVE_JS +
    "var host=location.hostname;if(host!=='chatgpt.com' && host!=='auth.openai.com')return 'unknown';"
    "function visible(e){var r=e.getBoundingClientRect(),s=getComputedStyle(e);"
    "return e.isConnected && !e.closest('dialog:not([open]),[inert],[hidden],[aria-hidden=\"true\"]')"
    "&& r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden' && s.visibility!=='collapse';}"
    "if(Array.from(document.querySelectorAll('input[autocomplete=one-time-code],input[name=code],input[data-testid=code-input]')).some(visible))return 'otp';"
    "if(Array.from(document.querySelectorAll('input[type=password]')).some(visible))return 'password';"
    "if(Array.from(document.querySelectorAll(selector)).some(usable))return 'email';"
    "if(Array.from(document.querySelectorAll('button[data-testid=user-menu-button],button[data-testid=profile-button]')).some(visible))return 'advanced';"
    "if(host==='auth.openai.com' && /^\\/(?:about-you|workspace|consent)(?:\\/|$)/.test(location.pathname))return 'advanced';"
    "if(host==='chatgpt.com' && /^\\/c\\//.test(location.pathname))return 'advanced';"
    "return 'unknown';"
)


class _EmailInputConfirmationError(RuntimeError):
    """A fixed substep failure, never an input value or raw browser exception."""

    def __init__(self):
        super().__init__("邮箱输入框填写未通过回读确认，未提交登录")


class _EmailEntryAdvanced(RuntimeError):
    def __init__(self):
        super().__init__("页面已进入后续登录阶段，未重复提交邮箱；登录结果仍需核对")


def _email_entry_state(page) -> str:
    try:
        value = page.run_js(_EMAIL_ENTRY_STATE_JS)
        return value if isinstance(value, str) and value in {"email", "otp", "password", "advanced"} else "unknown"
    except Exception:
        return "unknown"


_EMAIL_CONTROL_STATUSES = frozenset({
    "usable", "missing", "detached", "disabled", "readonly", "blocked", "zero_rect", "hidden", "selector_mismatch",
})


def _email_candidate_status(page, candidate) -> str:
    try:
        result = page.run_js(_EMAIL_CANDIDATE_STATUS_JS, *([candidate] if candidate else []))
        return result if isinstance(result, str) and result in _EMAIL_CONTROL_STATUSES else "unreadable"
    except Exception:
        return "unreadable"


def _email_input_diagnostics(page, box=None) -> dict:
    """Only fixed enums/counts; never input values, text, URLs or exceptions."""
    safe = {"preferred_status": "unreadable", "match_count": None, "usable_count": None,
            "zero_rect_count": None, "blocked_count": None, "ready_state": "unknown"}
    try:
        result = page.run_js(_EMAIL_INPUT_DIAGNOSTICS_JS, *([box] if box else []))
        if not isinstance(result, dict):
            return safe
        status = result.get("preferred_status")
        if isinstance(status, str) and status in _EMAIL_CONTROL_STATUSES:
            safe["preferred_status"] = status
        for key in ("match_count", "usable_count", "zero_rect_count", "blocked_count"):
            if type(result.get(key)) is int and 0 <= result[key] <= 10000:
                safe[key] = result[key]
        if result.get("ready_state") in ("loading", "interactive", "complete"):
            safe["ready_state"] = result["ready_state"]
    except Exception:
        pass
    return safe


def _refind_email_input(page):
    # One bounded selector pass per local retry; no refresh or submit action.
    for selector in _EMAIL_SELECTORS:
        try:
            candidates = page.eles(selector, timeout=0.15)
        except (AttributeError, TypeError):
            # Preserve simple page adapters that expose only ele().
            candidates = [_safe_ele(page, selector, timeout=0.15)]
        except Exception:
            continue
        for candidate in candidates:
            try:
                # Drission returns a falsy NoneElement, not Python None.
                if not candidate:
                    continue
                states = getattr(candidate, "states", None)
                if any(getattr(states, name, None) is False for name in ("is_alive", "is_displayed", "is_enabled")):
                    continue
                # Drission may report a preloaded hidden form as displayed.
                # Share the setter/readback's real geometry and ancestor checks.
                if _email_candidate_status(page, candidate) == "usable":
                    return candidate
            except Exception:
                continue
    return None


def _fill_email_react(page, box, email, log=lambda m: None, *, retries: int = 5,
                      settle: float = 1.6) -> bool:
    """把 email 稳稳填进 React 受控输入并**确认没被清掉**。

    关键: chatgpt.com 是 Next.js 受控输入。若在 React hydrate 之前填, onChange 没挂上、
    值进不了 React state; 几秒后 React 重渲染会把输入框恢复成空(用户现象: 填进去几秒又空了)。
    这里循环: 键入 → 原生 setter + input 事件 → 等 settle 秒 → 回读; 若被清空则重填,
    直到值稳定停留(React 已接住) 或重试用尽。返回 True=最终确实填住。"""
    for attempt in range(1, retries + 1):
        if _email_entry_state(page) in {"otp", "password", "advanced"}:
            return False
        if attempt > 1 or _email_candidate_status(page, box) != "usable":
            box = _refind_email_input(page)
        native_status, setter_status = "跳过", "未执行"
        try:
            if box:
                try:
                    box.clear(by_js=True)
                except Exception:
                    pass
                box.input(email)
                native_status = "已输入"
        except Exception:
            native_status = "控件操作异常"
        if _email_entry_state(page) in {"otp", "password", "advanced"}:
            return False
        try:
            # Drission's argument serializer accepts elements but not None.
            set_result = page.run_js(_EMAIL_SET_JS, email, *([box] if box else []))
            setter_status = "未找到可用框" if set_result == "__noinput__" else "已执行"
        except Exception:
            setter_status = "脚本执行异常"
        time.sleep(settle)   # 给 React 一点时间; 若它此刻 hydrate 并清空, 下面就能发现
        state = _email_entry_state(page)
        if state in {"otp", "password", "advanced"}:
            return False
        try:
            val = page.run_js(_EMAIL_READBACK_JS, *([box] if box else []))
        except Exception:
            val = "__unreadable__"
        if str(val) == email:
            return True      # 值稳定停留 → React 已接住
        if val == "__noinput__":
            log("[GPT PRO 登录] ⚠ 邮箱填后又空/不符(__noinput__)：邮箱输入框定位与回读不一致，正在重新定位")
        else:
            log(f"[GPT PRO 登录] 邮箱填写未通过回读确认，正在重新定位（第 {attempt}/{retries} 次）")
        diagnostic = _email_input_diagnostics(page, box)
        labels = {"usable": "可用", "missing": "未定位", "detached": "已替换", "disabled": "已禁用",
                  "readonly": "只读", "blocked": "祖先隐藏或弹框未打开", "zero_rect": "尺寸为零",
                  "hidden": "不可见", "selector_mismatch": "不再匹配", "unreadable": "无法读取"}
        state_label = {"email": "邮箱页", "otp": "验证码页", "password": "密码页", "advanced": "后续页面", "unknown": "未确认"}[state]
        read_label = "未找到可用框" if val == "__noinput__" else ("脚本读取异常" if val == "__unreadable__" else "未稳定匹配")
        log(f"[GPT PRO 登录] 邮箱控件诊断：页面={state_label}，控件={labels[diagnostic['preferred_status']]}，"
            f"匹配数={diagnostic['match_count']}，可用数={diagnostic['usable_count']}，"
            f"零尺寸={diagnostic['zero_rect_count']}，隐藏祖先或未开弹框={diagnostic['blocked_count']}，"
            f"原生输入={native_status}，补填={setter_status}，回读={read_label}（第 {attempt}/{retries} 次）")
    return False


def _click_continue(page):
    # The script is authoritative for visibility, active form and ambiguity.
    # Do not downgrade a refusal/error to the first DOM selector: that can
    # click a preloaded hidden form, or resend an action whose reply was lost.
    try:
        return page.run_js(_CONTINUE_CLICK_JS) is True
    except Exception:
        return False


def _wait_for_otp_page(page, *, timeout: float = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for sel in _OTP_SELECTORS:
            ele = _safe_ele(page, sel, timeout=0.6)
            if ele:
                return ele
        time.sleep(0.5)
    return None


def _login_page_problem(page) -> dict | None:
    """Inspect fixed visible error categories; never return text or URL data."""
    try:
        _stop_existing_account_context(page)
    except _LoginFlowRejected as exc:
        return dict(exc.failure)
    try:
        code = page.run_js(r"""
          if(location.protocol!=='https:' || !['chatgpt.com','auth.openai.com'].includes(location.hostname)
             || (location.port && location.port!=='443'))return 'login_origin_untrusted';
          const route=location.pathname.replace(/\/+$/,'');
          const loginRoute=location.hostname==='chatgpt.com'
            ? /^\/auth\/(?:login|login_with)$/.test(route)
            : /^\/(?:log-in|login|email-verification|error)(?:\/|$)/.test(route);
          if(!loginRoute)return '';
          const text=(document.body?.innerText || '').slice(0,12000);
          if(/account_deactivated|account_deleted|account has been deactivated|account is deactivated/i.test(text))return 'account_deactivated';
          if(/invalid_otp|invalid_totp|incorrect_password|invalid_credentials|incorrect password|验证码错误|验证码无效/i.test(text))return 'login_auth_rejected';
          if(/too many requests|rate_limit_exceeded|请求过于频繁|请求过多/i.test(text))return 'login_rate_limited';
          if(/ERR_CONNECTION|ERR_NETWORK|ERR_NAME_NOT_RESOLVED|network error|网络连接错误/i.test(text))return 'login_transport_unavailable';
          if(/just a moment|verifying you are human|checking your browser|正在验证您|验证您是真人/i.test(text))return 'login_page_challenge';
          return '';
        """)
        if type(code) is str and code in {
            "login_origin_untrusted", "account_deactivated", "login_auth_rejected",
            "login_rate_limited", "login_transport_unavailable", "login_page_challenge",
        }:
            return _login_failure(code)
    except Exception:
        pass
    return None


def _advance_to_otp(page, email: str, log, *, timeout: float = 75,
                    resubmit_interval: float = 10.0, failure_out: dict | None = None):
    """等 OTP 输入页;期间若停在「邮箱输入/选择登录方式」中转页
    (新版 chatgpt.com/auth/login?email=… 带 Google/Apple/电话/邮箱+続行),
    自动(重新)填邮箱并点続行推进,直到 OTP 框出现或超时。

    修复:新版登录多了这个中转页,旧逻辑只等 OTP 框 → 一直等不到 → 超时退出。
    """
    deadline = time.time() + timeout
    last_submit = 0.0
    observed_login_control = False
    if failure_out is not None:
        failure_out.clear()

    def stopped(failure):
        if failure_out is not None:
            failure_out.update(failure)
        log("[GPT PRO 登录] " + login_failure_reason(failure))
        return None

    while time.time() < deadline:
        problem = _login_page_problem(page)
        if problem:
            return stopped(problem)
        # 1) OTP 框出现 → 成功
        for sel in _OTP_SELECTORS:
            ele = _safe_ele(page, sel, timeout=0.6)
            if ele:
                return ele
        if _email_entry_state(page) in {"password", "advanced"}:
            raise _EmailEntryAdvanced()
        url = page.url or ""
        # 2) 未到验证码页、但页面上有邮箱输入框(登录弹窗/选择方式中转页)→ 节流地重填邮箱 + 点続行
        on_verification = any(seg in url for seg in ("/code", "email-verification", "verification"))
        if not on_verification and (time.time() - last_submit > resubmit_interval):
            email_box = _refind_email_input(page)
            if email_box:
                observed_login_control = True
                # 关键: 等 React hydrate 就绪再点, 否则点「继续」退回原生 GET 提交、
                # 刷回 ?email= 登录页 → 每次重点都重置 hydration → 死循环。
                _wait_page_ready(page)
                filled = _fill_email_react(page, email_box, email, log)
                state = _email_entry_state(page)
                if state in {"password", "advanced"}:
                    raise _EmailEntryAdvanced()
                if state == "otp":
                    continue
                if not filled:
                    raise _EmailInputConfirmationError()
                time.sleep(0.8)   # 给 React 时间接受输入, 免得 continue 按钮还 disabled
                state = _email_entry_state(page)
                if state in {"password", "advanced"}:
                    raise _EmailEntryAdvanced()
                if state == "otp":
                    continue
                clicked = _click_continue(page)
                last_submit = time.time()
                log(f"[GPT PRO 登录] 检测到邮箱输入框(登录弹窗/中转页), 已(重新)填邮箱并点続行 "
                    f"(clicked={clicked})")
            else:
                # 兜底: 没有邮箱框、也没到 OTP 页(如「欢迎回来/选择登录方式/确认继续」等
                # 中转/注册落地页) → 只要有「继续」按钮就点它推进, 否则会一直等 OTP 卡死。
                if _click_continue(page):
                    observed_login_control = True
                    last_submit = time.time()
                    log("[GPT PRO 登录] 无邮箱框, 检测到「继续」按钮并点击推进")
        time.sleep(0.6)
    problem = _login_page_problem(page)
    if problem:
        return stopped(problem)
    # Timeout alone does not authorize another login on an unknown page.
    try:
        current = urlparse(page.url or "")
        login_route = (current.scheme == "https" and current.port in (None, 443)
                       and current.username is None and current.password is None and (
                           current.hostname == "chatgpt.com" and current.path.rstrip("/") in {"/auth/login", "/auth/login_with"}
                           or current.hostname == "auth.openai.com" and current.path.rstrip("/") in {"/log-in", "/login"}))
    except Exception:
        login_route = False
    return stopped(_login_failure("login_page_unready" if observed_login_control and login_route
                                  else "login_page_unconfirmed"))



def _safe_ele(page, sel: str, *, timeout: float = 1):
    try:
        return page.ele(sel, timeout=timeout)
    except Exception:
        return None


def _still_on_otp_page(page) -> bool:
    url = page.url or ""
    return "email-verification" in url or "/log-in/code" in url


# 账号被停用/删除的报错检测: 输入 OTP 后页面停在 /email-verification 并显示
# "错误代码：account_deactivated" —— 表示该账号已被 OpenAI 停用/删除, 再重试也没用。
_ACCOUNT_DEACTIVATED_JS = r"""
const t = (document.body && document.body.innerText) || "";
return /account_deactivated|account_deleted|account has been deactivated|account is deactivated/i.test(t);
"""


def _detect_account_deactivated(page) -> str:
    """检测账号已停用/删除(account_deactivated)。命中返回 'account_deactivated', 否则 ''。"""
    try:
        url = page.url or ""
    except Exception:
        url = ""
    if "account_deactivated" in url or "account_deleted" in url:
        return "account_deactivated"
    try:
        if page.run_js(_ACCOUNT_DEACTIVATED_JS):
            return "account_deactivated"
    except Exception:
        pass
    return ""


def _submit_otp_and_confirm(page, otp_input, code, log,
                            *, max_attempts: int = 3, leave_timeout: float = 12.0) -> bool:
    """填 OTP 并确认提交成功(离开 email-verification 页), 失败自动重试。

    修复卡死场景: 旧逻辑 input 后立刻点 button[type=submit], 但此刻按钮常因 React 仍在
    校验刚键入的值而 disabled, 点击是 no-op → OTP 永不提交, 卡在 /email-verification
    (截图: 验证码已填但页面不动)。这里改为先等按钮 enabled 再点, 点后确认已离开, 否则重试。
    返回 True=已离开验证码页; False=重试 max_attempts 次仍停留。
    """
    for attempt in range(1, max_attempts + 1):
        if not _still_on_otp_page(page):
            return True
        # 1) 确认值已在框里(空则重新定位并键入)
        cur = ""
        try:
            cur = (page.run_js(_OTP_READBACK_JS) or {}).get("value", "")
        except Exception:
            pass
        if not cur:
            el = otp_input or _safe_ele(page, 'css:input[autocomplete="one-time-code"]', timeout=2)
            if el:
                try:
                    el.clear(by_js=True)
                except Exception:
                    pass
                try:
                    el.input(code)
                except Exception as exc:
                    log(f"[GPT PRO 登录] OTP 重新键入异常(忽略): {exc}")
            time.sleep(0.4)
        # 2) 轮询等提交按钮变可点(最多 6s)再点
        ready = {}
        deadline = time.time() + 6
        while time.time() < deadline:
            try:
                ready = page.run_js(_OTP_SUBMIT_READY_JS) or {}
            except Exception:
                ready = {}
            if ready.get("enabled"):
                break
            time.sleep(0.4)
        clicked = False
        for sel in _CONTINUE_SELECTORS:
            ele = _safe_ele(page, sel, timeout=1)
            if ele:
                try:
                    ele.click()
                    clicked = True
                    break
                except Exception:
                    continue
        log(f"[GPT PRO 登录] OTP 提交 第 {attempt}/{max_attempts} 次 "
            f"(按钮 found={ready.get('found')} enabled={ready.get('enabled')} 已点={clicked})")
        # 3) 等离开验证码页
        deadline = time.time() + leave_timeout
        while time.time() < deadline:
            if not _still_on_otp_page(page):
                log("[GPT PRO 登录] ✅ OTP 提交成功, 已离开验证码页")
                return True
            if _detect_account_deactivated(page):
                log("[GPT PRO 登录] ✗ 检测到 account_deactivated(账号已停用/删除), 停止重试")
                return False
            time.sleep(0.6)
        log(f"[GPT PRO 登录] ⚠ OTP 提交后 {int(leave_timeout)}s 仍停留验证码页 (第 {attempt}/{max_attempts} 次)")
    return not _still_on_otp_page(page)


def _snapshot_mail_ids(mailbox, mailbox_account, log) -> set:
    """点继续之前 snapshot 邮箱当前所有 message id, 这样 wait_for_code
    只把之后到达的真新邮件当 OTP, 不会误用残留的旧验证码邮件。
    """
    try:
        ids = mailbox.get_current_ids(mailbox_account)
        log(f"[GPT PRO 登录]   邮箱已有 {len(ids)} 封邮件 baseline,后续只接受新到的 OTP")
        return ids
    except Exception as exc:
        log(f"[GPT PRO 登录]   邮箱 baseline snapshot 失败(忽略): {exc}")
        return set()


def _fetch_otp_from_mailbox(mailbox, mailbox_account, *,
                             before_ids: set, timeout: int, log) -> str:
    if not mailbox or not mailbox_account:
        raise RuntimeError("没有提供 mailbox + mailbox_account")
    log(f"[GPT PRO 登录]   从 Mailbox 取 OTP (timeout={timeout}s)...")
    # keyword 用 "ChatGPT"——OpenAI 给所有 locale 的验证码邮件 subject 都带 ChatGPT
    # (中文: "你的临时 ChatGPT 登录代码", EN: "Your ChatGPT code is XXXXXX")。
    # code_pattern 留空,让 _safe_extract 用内置语义模式 (verification_code / 验证码 / 校验码 …)
    # 优先抓"验证码:\n123456"这种带上下文的真码,避免误抓邮件里的随机 6 位数字。
    code = mailbox.wait_for_code(
        mailbox_account,
        keyword="ChatGPT",
        timeout=timeout,
        before_ids=before_ids or set(),
    )
    code = (code or "").strip()
    if not _OTP_RE.fullmatch(code):
        raise RuntimeError("Mailbox 取到的不是 6 位 OTP（内容已隐藏）")
    return code


# 重试按钮文案匹配(多语言: 中/英/日/韩/西/法), 覆盖 OpenAI 各本地化报错页的「重试」按钮。
# 例: 日文报错页按钮「もう一度試す」→ 命中「もう一度」。
_RETRY_TEXT_RE = r"もう一度|再試|やり直|다시|reintentar|réessayer|重试|重新尝试|重新加载|再试一次|retry|try again|reload"

_RETRY_BTN_JS = r"""
const els = [...document.querySelectorAll('button, a, [role=button]')];
const el = els.find(e => /__RE__/i.test((e.textContent||e.value||'').trim()));
if (el) { el.click(); return true; }
return false;
""".replace("__RE__", _RETRY_TEXT_RE)

# 检测 OpenAI 通用报错页(不明なエラー / Operation timed out / Something went wrong ...)
_OPENAI_ERROR_PAGE_JS = r"""
const t = (document.body && document.body.innerText) || "";
const isError = /不明なエラー|エラーが発生|問題が発生|Operation timed out|Something went wrong|went wrong|出错了|出现错误|发生错误/i.test(t);
const els = [...document.querySelectorAll('button, a, [role=button]')];
const hasRetry = els.some(e => /__RE__/i.test((e.textContent||e.value||'').trim()));
return { isError: !!isError, hasRetry: !!hasRetry };
""".replace("__RE__", _RETRY_TEXT_RE)


def _recover_openai_error_page(page, *, attempts: int = 4, wait_each: float = 3.0, log_fn=None,
                               allow_existing_login_context: bool = False) -> bool:
    """检测 OpenAI 通用报错页(不明なエラー / Operation timed out / Something went wrong)并自动点「重试」。

    返回 True=无错误或已恢复; False=多次点重试仍是报错页。检测异常一律放行(不阻断主流程)。
    """
    log = log_fn or (lambda m: print(m, flush=True))
    for i in range(1, attempts + 1):
        if not allow_existing_login_context:
            _stop_existing_account_context(page)
        try:
            state = page.run_js(_OPENAI_ERROR_PAGE_JS) or {}
        except Exception:
            return True
        if not state.get("isError"):
            return True
        log(f"[GPT PRO 登录] ⚠ 命中 OpenAI 报错页(第 {i}/{attempts} 次), 自动点「重试」…")
        try:
            page.run_js(_RETRY_BTN_JS)
        except Exception:
            pass
        time.sleep(wait_each)
    if not allow_existing_login_context:
        _stop_existing_account_context(page)
    try:
        recovered = not (page.run_js(_OPENAI_ERROR_PAGE_JS) or {}).get("isError")
    except Exception:
        recovered = True
    log("[GPT PRO 登录] ✅ 报错页已恢复" if recovered else "[GPT PRO 登录] ✗ 报错页多次重试仍未恢复")
    return recovered


# 部分账号验证码通过后会跳到 auth.openai.com/workspace 让选工作空间(个人/团队各一行)。
# 需求: 空间名不固定, 选「第一个(最上面)」即可。这里点选第一行工作空间以继续落地。
_WORKSPACE_CHOOSER_CANDIDATES_JS = r"""
if (location.protocol !== 'https:' || location.hostname !== 'auth.openai.com' ||
    (location.port && location.port !== '443') || !/^\/workspace(?:\/|$)/.test(location.pathname)) return '__NOT_CHOOSER__';
// A click may have been sent even when its JS response was lost during SPA
// navigation. Do not dispatch another selection in this document.
const pending = window.__chatgptWorkspaceSelectionPendingV1;
if (pending) {
  const age = Date.now() - pending.startedAt;
  return Number.isFinite(age) && age >= 0 && age <= 45000 ? '__PENDING__' : '__PENDING_EXPIRED__';
}
const bad = /使用条款|隐私政策|terms of use|terms of service|privacy/i;
const cand = [...document.querySelectorAll('a,button,[role="button"],[role="link"]')].filter(el => {
  if (!el.isConnected || el.disabled || el.getAttribute('aria-disabled') === 'true' ||
      el.closest('dialog:not([open]),[inert],[hidden],[aria-hidden="true"],fieldset[disabled]')) return false;
  const r = el.getBoundingClientRect();
  const s = getComputedStyle(el);
  if (s.visibility === 'hidden' || s.visibility === 'collapse' || s.display === 'none') return false;
  // 工作空间是一整行: 宽而不太高; 排除页脚小链接和整页大容器
  if (r.width < 150 || r.height < 36 || r.height > 220) return false;
  const t = (el.innerText || el.textContent || '').trim();
  if (!t || bad.test(t)) return false;
  return true;
});
cand.sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top);
"""
_WORKSPACE_CHOOSER_JS = _WORKSPACE_CHOOSER_CANDIDATES_JS + r"""
if (!cand.length) return '';
const el = cand[0];
try { el.scrollIntoView({block: 'center'}); } catch (e) {}
window.__chatgptWorkspaceSelectionPendingV1 = {startedAt:Date.now()};
el.click();
return '__CLICKED__';
"""


# 只用于「退款」流程:在工作空间选择页优先选「个人空间」(而非第一个/团队)。
# 退款要在个人号语境下走客服流程,选到 team 空间会退错对象。
_WORKSPACE_CHOOSER_PERSONAL_JS = _WORKSPACE_CHOOSER_CANDIDATES_JS + r"""
const personalRe = /personal|个人/i;
const businessRe = /business|team|enterprise|团队|企业|工作区|workspace/i;
if (!cand.length) return '';
// 1) 明确标注 personal/个人 的行优先
let el = cand.find(e => personalRe.test((e.innerText || e.textContent || '')));
// 2) 否则选不含 business/team/工作区 标记的那一行(个人空间通常没有这些字样)
if (!el) el = cand.find(e => !businessRe.test((e.innerText || e.textContent || '')));
if (!el) return '__NO_PERSONAL__';
try { el.scrollIntoView({block: 'center'}); } catch (e) {}
window.__chatgptWorkspaceSelectionPendingV1 = {startedAt:Date.now()};
el.click();
return '__CLICKED__';
"""
_WORKSPACE_CHOOSER_STATE_JS = _WORKSPACE_CHOOSER_CANDIDATES_JS + "return cand.length ? 'ready' : 'loading';"


def _on_workspace_chooser(page) -> bool:
    try:
        current = urlparse(page.url or "")
        return bool(current.scheme == "https" and current.hostname == "auth.openai.com"
                    and current.port in (None, 443) and current.username is None and current.password is None
                    and (current.path == "/workspace" or current.path.startswith("/workspace/")))
    except Exception:
        return False


def _workspace_chooser_state(page) -> str:
    """Read-only routing hint, never session/password/MFA proof."""
    if not _on_workspace_chooser(page):
        return "not_chooser"
    try:
        value = page.run_js(_WORKSPACE_CHOOSER_STATE_JS)
        if value == "__PENDING__":
            return "pending"
        if value == "__NOT_CHOOSER__":
            return "not_chooser"
        if value == "__PENDING_EXPIRED__":
            return "timed_out"
        return value if value in ("ready", "loading") else "unknown"
    except Exception:
        return "unknown"


def _handle_workspace_chooser(page, log_fn=None, prefer_personal: bool = False) -> bool:
    """Select once per document; True means dispatched/pending, NOT logged in.

    False can mean loading, navigation raced, or no usable row; callers must
    wait within their own deadline and independently verify the final session.
    prefer_personal=True(仅退款流程用): 优先选「个人空间」, 找不到再退回第一个。"""
    if not _on_workspace_chooser(page):
        return False
    if prefer_personal:
        try:
            picked = page.run_js(_WORKSPACE_CHOOSER_PERSONAL_JS)
        except Exception:
            if log_fn:
                log_fn("[退款/工作空间] 选择请求结果暂未确认，等待页面状态；未重复点击")
            return False
        if picked == "__PENDING__":
            return True
        if picked in ("__NOT_CHOOSER__", "__PENDING_EXPIRED__"):
            return False
        if picked and picked != "__NO_PERSONAL__":
            if log_fn:
                log_fn("[退款/工作空间] 个人空间选择已提交，等待页面跳转")
            return True
        if log_fn:
            log_fn("[退款/工作空间] 未找到个人空间, 退回选第一个空间")
        # 落到下面选第一个
    try:
        picked = page.run_js(_WORKSPACE_CHOOSER_JS)
    except Exception:
        if log_fn:
            log_fn("[BUSINESS AT] 工作空间选择请求结果暂未确认，等待页面状态；未重复点击")
        return False
    if picked == "__PENDING__":
        return True
    if picked in ("__NOT_CHOOSER__", "__PENDING_EXPIRED__"):
        return False
    if picked:
        if log_fn:
            log_fn("[BUSINESS AT] 第一个工作空间选择已提交，等待页面跳转")
        return True
    return False


def _wait_for_chatgpt_home(page, *, timeout: int = _DEFAULT_LANDING_TIMEOUT, log_fn=None,
                           on_about_you=None, prefer_personal_workspace: bool = False) -> bool:
    # OTP 提交后偶尔卡在 auth.openai.com/email-verification 报 400, 页面带"重试"按钮;
    # 自动点重试再继续等落地 chatgpt.com。
    # on_about_you: 等待期间发现又回到 /about-you(报错页点重试后表单被清空的典型状态)时
    # 的重填回调; 有冷却时间且最多触发 2 次, 防止和页面自身跳转互相打架。
    deadline = time.time() + timeout
    last_retry = 0.0
    last_refill = 0.0
    last_ws = 0.0
    refills = 0
    while time.time() < deadline:
        _stop_existing_account_context(page)
        url = page.url or ""
        if "chatgpt.com" in url and "/auth/" not in url and "/log-in" not in url:
            return True
        # 工作空间选择页: 选空间继续(退款流程优先选个人空间)
        if _on_workspace_chooser(page) and time.time() - last_ws > 3:
            if _handle_workspace_chooser(page, log_fn, prefer_personal=prefer_personal_workspace):
                last_ws = time.time()
                time.sleep(1.5)
                continue
        if (on_about_you and "/about-you" in url and refills < 2
                and time.time() - last_refill > 20):
            if log_fn:
                log_fn(f"[GPT PRO 登录] 等落地期间回到 /about-you, 触发重填 ({refills + 1}/2)")
            try:
                if on_about_you() is False:
                    return False
            except _LoginFlowRejected:
                raise
            except Exception as exc:
                if log_fn:
                    log_fn(f"[GPT PRO 登录] about-you 重填回调异常(忽略): {exc}")
            refills += 1
            last_refill = time.time()
            continue
        if ("auth.openai.com" in url or "/auth/" in url) and time.time() - last_retry > 5:
            try:
                if page.run_js(_RETRY_BTN_JS):
                    if log_fn:
                        log_fn(f"[GPT PRO 登录] 检测到错误/重试按钮, 已自动点重试 (URL={url})")
                    last_retry = time.time()
            except Exception:
                pass
        time.sleep(0.5)
    return False


def _session_driver_failure(exc) -> str:
    """Classify known local exceptions without retaining their sensitive text."""
    if isinstance(exc, TimeoutError):
        return "session_browser_timeout"
    if isinstance(exc, ConnectionError):
        return "session_browser_disconnected"
    if type(exc).__module__ == "DrissionPage.errors":
        return {
            "ContextLostError": "session_context_lost",
            "PageDisconnectedError": "session_browser_disconnected",
            "BrowserConnectError": "session_browser_disconnected",
            "WaitTimeoutError": "session_browser_timeout",
        }.get(type(exc).__name__, "session_read_unconfirmed")
    return "session_read_unconfirmed"


def _session_origin_failure(page, *, timeout=2):
    """Read the top-frame origin without page.url's document-load wait."""
    try:
        cdp = getattr(page, "_run_cdp", None)
        if callable(cdp):
            frame_tree = cdp("Page.getFrameTree", _timeout=max(0.1, min(2, timeout)))
            value = frame_tree["frameTree"]["frame"]["url"]
        else:
            # Compatibility for lightweight adapters and isolated test pages.
            value = page.url
        origin = urlparse(value or "")
        trusted = (origin.scheme == "https" and origin.hostname == "chatgpt.com"
                   and origin.port in (None, 443) and origin.username is None and origin.password is None)
    except Exception as exc:
        return _login_failure(_session_driver_failure(exc))
    return None if trusted else _login_failure("session_origin_untrusted")


def _extract_session(page, log, *, timeout: float = 10, failure_out: dict | None = None) -> dict:
    """Read the session, preserving only fixed failure categories outside it."""
    started = time.monotonic()
    request_timeout = max(0.1, min(10, timeout))

    def failed(code, status=None):
        failure = _login_failure(code, http_status=status)
        if failure_out is not None:
            failure_out.clear()
            failure_out.update(failure)
        log("[GPT PRO 登录] " + login_failure_reason(failure)
            + f"；类型={code}，本次耗时 {max(0, time.monotonic() - started):.1f} 秒")
        return {}

    if failure_out is not None:
        failure_out.clear()
    try:
        js = (
            "return (async()=>{"
            "if(location.protocol!=='https:' || location.hostname!=='chatgpt.com'"
            " || (location.port && location.port!=='443'))return {kind:'untrusted'};"
            "const controller=new AbortController();"
            "let status=null;"
            f"const timer=setTimeout(()=>controller.abort(),{int(request_timeout * 1000)});"
            "try{const r=await fetch('/api/auth/session',{credentials:'include',cache:'no-store',signal:controller.signal});"
            "status=r.status;"
            "const destination=new URL(r.url);"
            "if(destination.origin!=='https://chatgpt.com')return {kind:'untrusted'};"
            "const body=await (r.ok ? r.text() : '');"
            "return {kind:'response',status:r.status,body};"
            "}catch(e){return {kind:['AbortError','TimeoutError'].includes(e?.name)?'fetch_timeout':"
            "e?.name==='TypeError'?'fetch_network':'unknown',status};}"
            "finally{clearTimeout(timer);}})();"
        )
        # Allow the browser to deliver the abort result instead of inheriting
        # its unrelated 30-second script timeout. Driver/root-context setup
        # can still overrun; the caller re-checks its budget after every call.
        response = page.run_js(js, timeout=request_timeout + 2)
    except Exception as exc:
        return failed(_session_driver_failure(exc))
    status = None
    if isinstance(response, dict):
        kind = response.get("kind")
        if kind == "untrusted":
            return failed("session_origin_untrusted")
        if kind in {"transport", "unknown", "fetch_timeout", "fetch_network"}:
            status = response.get("status")
            # Keep a known successful HTTP status if reading its body failed.
            status = status if type(status) is int and 200 <= status < 300 else None
            code = {"transport": "session_read_failed", "unknown": "session_read_unconfirmed",
                    "fetch_timeout": "session_request_timeout", "fetch_network": "session_network_failed"}[kind]
            return failed(code, status)
        status = response.get("status")
        if kind != "response" or type(status) is not int or not 100 <= status <= 599:
            return failed("session_read_unconfirmed")
        if not 200 <= status < 300:
            code = ("session_http_transient" if status in {408, 425, 429} or status >= 500 else
                    "session_http_rejected" if status in {401, 403} else "session_http_unconfirmed")
            return failed(code, status)
        text = response.get("body")
    else:
        # Compatibility for existing page adapters returning response text.
        text = response
    if not text:
        return failed("session_empty", status)
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
    except Exception:
        pass
    return failed("session_invalid", status)


def _verified_login_session(page, target_email: str, log, *, failure_out: dict | None = None,
                            retry_forbidden: bool = False) -> tuple[dict, str]:
    """A landing/workspace hint is never authentication or identity proof."""
    started = time.monotonic()
    deadline = started + (60 if retry_forbidden else 45)
    max_attempts = 4 if retry_forbidden else 3
    attempts = 0
    failure = _login_failure("session_identity_missing")
    if failure_out is not None:
        failure_out.clear()

    def stopped(current):
        if failure_out is not None:
            failure_out.update(current)
        log(f"[GPT PRO 登录] 会话核验已停止：实际尝试 {attempts}/{max_attempts} 次，"
            f"总耗时 {max(0, time.monotonic() - started):.1f} 秒，类型={current['code']}")
        return {}, login_failure_reason(current)

    for attempt in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining < 3:
            break
        attempts += 1
        log(f"[GPT PRO 登录] 开始核验登录会话（第 {attempts}/{max_attempts} 次，剩余预算 {remaining:.1f} 秒）")
        origin_failure = _session_origin_failure(page, timeout=min(2, remaining))
        if origin_failure and origin_failure["code"] == "session_origin_untrusted":
            return stopped(origin_failure)
        read_failure = {}
        remaining = deadline - time.monotonic()
        if origin_failure:
            session, read_failure = {}, origin_failure
        elif remaining < 3:
            failure = _login_failure("session_browser_timeout")
            break
        else:
            session = _extract_session(page, log, timeout=min(10, remaining - 2), failure_out=read_failure)
        session = session if isinstance(session, dict) else {}
        read_failure = normalize_login_failure(read_failure)
        if read_failure and read_failure["code"] in {"session_origin_untrusted", "session_http_rejected"}:
            # Interactive login may see a temporary 403 immediately after the browser
            # lands. Only re-read this exact page; never resubmit login or
            # payment, accept an unverified identity, or retry a 401 here.
            if not (retry_forbidden and read_failure["code"] == "session_http_rejected"
                    and read_failure["http_status"] == 403):
                return stopped(read_failure)
        user = session.get("user") if isinstance(session.get("user"), dict) else {}
        actual_email = user.get("email")
        actual_email = actual_email.strip().casefold() if isinstance(actual_email, str) else ""
        if actual_email and actual_email != target_email.strip().casefold():
            return stopped(_login_failure("session_identity_mismatch"))
        access_token = session.get("accessToken")
        token_ready = isinstance(access_token, str) and bool(access_token.strip())
        if actual_email and token_ready and not session.get("error") and not read_failure:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return stopped(_login_failure("session_browser_timeout"))
            current_failure = _session_origin_failure(page, timeout=min(2, remaining))
            if current_failure:
                if current_failure["code"] == "session_origin_untrusted":
                    return stopped(current_failure)
                # Discard this read if navigation/context verification failed.
                # A remaining attempt must obtain and verify a fresh session.
                read_failure = current_failure
            else:
                log(f"[GPT PRO 登录] 会话核验通过：实际尝试 {attempts}/{max_attempts} 次，"
                    f"总耗时 {max(0, time.monotonic() - started):.1f} 秒")
                return session, ""
        if read_failure:
            failure = read_failure
        elif session.get("error"):
            failure = _login_failure("session_state_error")
        elif actual_email:
            failure = _login_failure("session_token_missing")
        else:
            failure = _login_failure("session_identity_missing")
        # Fast failures still get a useful bounded read window. These reads
        # never click login, request another OTP, or trust an empty identity.
        delay = 3.0 if retry_forbidden else 2.0
        if attempt < max_attempts - 1:
            if deadline - time.monotonic() < delay + 3:
                break
            log(f"[GPT PRO 登录] 当前会话尚未通过核验，将在 {delay:g} 秒后只读复核")
            time.sleep(delay)
    return stopped(failure)


def _retain_checkout_session_failure(result, page, *, enabled, headless, keep_open, log):
    """Retain a visible interactive failure, never identity drift or a lost browser."""
    failure = normalize_login_failure(result.login_failure)
    if (not enabled or headless or not keep_open or page is None or not failure
            or failure["stage"] != "extract_session"
            or failure["code"] in {"session_origin_untrusted", "session_identity_mismatch",
                                   "session_browser_disconnected"}):
        return False
    # Private handle is deliberately excluded from result.to_dict() and APIs.
    result._retained_session_page = page
    log("[GPT PRO 登录] 登录后的会话读取未通过，已保留浏览器窗口；未执行后续操作")
    return True


def _is_business_workspace_text(value: Any) -> bool:
    """Return whether visible workspace text represents a non-personal workspace."""
    text = " ".join(str(value or "").strip().lower().split())
    if not text:
        return False
    personal_markers = ("personal", "个人空间", "个人工作区", "个人账户", "个人账号")
    if any(marker in text for marker in personal_markers):
        return False
    command_markers = (
        "settings", "setting", "create", "new workspace", "manage", "switch workspace",
        "设置", "创建", "新建", "管理", "切换工作区", "workspace switcher",
    )
    if any(marker in text for marker in command_markers):
        return False
    return any(marker in text for marker in (
        "business", "team", "enterprise", "workspace", "工作区", "团队", "企业",
    ))


def _parse_business_session_payload(payload: Any) -> dict:
    """Normalize `/api/auth/session` after a Business workspace is active."""
    if not isinstance(payload, dict):
        raise RuntimeError("/api/auth/session 响应不是 JSON 对象")
    access_token = str(payload.get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("/api/auth/session 未返回 accessToken")
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    expires_at = ""
    try:
        from datetime import datetime, timezone
        from platforms.chatgpt.utils import decode_jwt_payload

        jwt_payload = decode_jwt_payload(access_token) or {}
        exp = int(jwt_payload.get("exp") or 0)
        if exp > 0:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
    except Exception:
        expires_at = ""
    return {
        "access_token": access_token,
        "session_token": str(payload.get("sessionToken") or "").strip(),
        "account_id": str(account.get("id") or "").strip(),
        "plan_type": str(account.get("planType") or account.get("plan_type") or "").strip().lower(),
        "expires_at": expires_at,
    }


def _redact_action_result_for_log(value: Any) -> Any:
    """Return a log-safe action result without credential material."""
    if not isinstance(value, dict):
        return value
    sensitive = {"access_token", "session_token", "accessToken", "sessionToken", "raw_session"}
    out = {}
    for key, item in value.items():
        if str(key) in sensitive:
            out[str(key)] = "<redacted>" if item else ""
        elif isinstance(item, dict):
            out[str(key)] = _redact_action_result_for_log(item)
        else:
            out[str(key)] = item
    return out


def _select_first_business_workspace_and_extract_session(page, log) -> dict:
    """Choose the first visible Business workspace, then fetch its NextAuth session."""
    initial = _extract_session(page, log)
    initial_parsed = None
    try:
        initial_parsed = _parse_business_session_payload(initial)
    except Exception:
        pass
    initial_account_id = str((initial_parsed or {}).get("account_id") or "")
    try:
        initial_url = str(page.url or "")
    except Exception:
        initial_url = ""

    # Open the profile/workspace menu. The exact ChatGPT markup changes often,
    # so use accessible labels plus visible text rather than brittle CSS paths.
    try:
        page.run_js("""
        const nodes = [...document.querySelectorAll('button,[role="button"]')];
        const score = (el) => {
          const s = [el.innerText, el.getAttribute('aria-label'), el.getAttribute('title')]
            .filter(Boolean).join(' ').toLowerCase();
          if (s.includes('workspace') || s.includes('工作区')) return 3;
          if (s.includes('profile') || s.includes('account') || s.includes('账户')) return 2;
          return 0;
        };
        const target = nodes.map(el => [score(el), el]).sort((a,b) => b[0]-a[0])[0];
        if (target && target[0] > 0) { target[1].click(); return true; }
        return false;
        """)
    except Exception as exc:
        log(f"[BUSINESS AT] 打开空间菜单异常: {exc}")
    time.sleep(1)

    clicked: dict[str, Any] = {}
    for _ in range(10):
        try:
            raw_clicked = page.run_js("""
            const personal = ['personal','个人空间','个人工作区','个人账户','个人账号'];
            const business = ['business','team','enterprise','workspace','工作区','团队','企业'];
            const commands = ['settings','setting','create','new workspace','manage','switch workspace',
              '设置','创建','新建','管理','切换工作区','workspace switcher'];
            const visible = (el) => {
              const r = el.getBoundingClientRect();
              const s = getComputedStyle(el);
              return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
            };
            const nodes = [...document.querySelectorAll(
              '[role="menuitem"],[role="option"],[data-testid*="workspace-item"],'
              + '[data-testid*="account-item"],[data-workspace-id],[data-account-id]')]
              .filter(visible);
            for (const el of nodes) {
              const text = (el.innerText || el.textContent || '').trim();
              const low = text.toLowerCase();
              if (!text || personal.some(x => low.includes(x))) continue;
              if (commands.some(x => low.includes(x))) continue;
              if (business.some(x => low.includes(x))) {
                const workspaceId = el.getAttribute('data-workspace-id')
                  || el.getAttribute('data-account-id') || el.getAttribute('data-id') || '';
                const isCurrent = el.getAttribute('aria-current') === 'true'
                  || el.getAttribute('aria-checked') === 'true'
                  || el.getAttribute('data-state') === 'checked'
                  || el.getAttribute('data-active') === 'true';
                el.click();
                return {text, workspaceId, isCurrent};
              }
            }
            return null;
            """)
            clicked = raw_clicked if isinstance(raw_clicked, dict) else {}
        except Exception:
            clicked = {}
        if clicked:
            log(f"[BUSINESS AT] 已选择第一个 Business 空间: {str(clicked.get('text') or '')[:120]}")
            break
        time.sleep(0.5)

    # If no selector is available but the currently active account is already a
    # Business plan, it is safe to use the active workspace.
    business_plans = {"business", "team", "enterprise"}
    if not clicked and initial_parsed and initial_parsed.get("plan_type") in business_plans:
        log("[BUSINESS AT] 当前已处于 Business 空间,直接读取 session")
        return initial_parsed
    if not clicked:
        raise RuntimeError("未找到可选择的 Business 空间")
    if clicked.get("isCurrent") and initial_parsed and initial_parsed.get("plan_type") in business_plans:
        log("[BUSINESS AT] 第一个 Business 空间已是当前空间")
        return initial_parsed

    last_error = ""
    clicked_workspace_id = str(clicked.get("workspaceId") or "")
    for _ in range(30):
        time.sleep(1)
        try:
            parsed = _parse_business_session_payload(_extract_session(page, log))
            try:
                current_url = str(page.url or "")
            except Exception:
                current_url = ""
            parsed_account_id = str(parsed.get("account_id") or "")
            transition_confirmed = bool(
                (clicked_workspace_id and parsed_account_id == clicked_workspace_id)
                or (initial_account_id and parsed_account_id and parsed_account_id != initial_account_id)
                or (initial_url and current_url and current_url != initial_url)
                or ((initial_parsed or {}).get("plan_type") not in business_plans)
            )
            if parsed.get("plan_type") in business_plans and transition_confirmed:
                return parsed
            last_error = (
                f"当前 planType={parsed.get('plan_type') or '(空)'},"
                f"account_id={parsed_account_id or '(空)'},空间切换尚未确认"
            )
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"切换 Business 空间后未获取到有效 AT: {last_error}")


def acquire_business_at_via_login(
    email: str,
    *,
    email_adapter: Any,
    headless: bool,
    proxy: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict:
    """Login with OTP, choose the first Business workspace and return session AT."""
    log = _make_logger(log_fn)
    try:
        from platforms.chatgpt.drission_rt_acquirer import _snapshot_existing_mail_ids

        _snapshot_existing_mail_ids(email_adapter, log)
    except Exception as exc:
        log(f"[BUSINESS AT] OTP 邮件基线快照失败(继续): {exc}")

    def otp_callback() -> str:
        return str(email_adapter.wait_for_verification_code(
            email=email, timeout=_DEFAULT_OTP_TIMEOUT, otp_sent_at=time.time(),
        ) or "").strip()

    result = login_with_email_otp(
        email,
        otp_callback=otp_callback,
        headless=headless,
        proxy=proxy,
        log_fn=log,
        keep_browser_open=False,
        post_login_action=lambda page, _result: _select_first_business_workspace_and_extract_session(page, log),
    )
    if not result.ok:
        raise RuntimeError(result.error or f"AT 登录失败(stage={result.stage})")
    if not isinstance(result.action_result, dict):
        raise RuntimeError("登录成功但未返回 Business session")
    if result.action_result.get("ok") is False:
        raise RuntimeError(str(result.action_result.get("error") or "Business session 获取失败"))
    return dict(result.action_result)


# chatgpt.com 上的关键 cookie(注册时已保存)。用它们直接登录, 免走验证码。
_CHATGPT_COOKIE_DOMAIN = "chatgpt.com"


def _inject_saved_cookies(page, cookies: dict, log) -> int:
    """把注册时保存的 name->value cookie 注入浏览器(chatgpt.com 域)。返回成功注入数。

    只有 name/value(没存 domain), 因此统一按 chatgpt.com 注入 —— 真正决定登录态的
    __Secure-next-auth.session-token 就在 chatgpt.com 域。__Host- 前缀必须 host-only。
    """
    ok = 0
    for name, value in (cookies or {}).items():
        name = str(name)
        value = str(value)
        if not name:
            continue
        ck = {
            "name": name,
            "value": value,
            "path": "/",
            "secure": True,
            "domain": _CHATGPT_COOKIE_DOMAIN,
        }
        # __Host- 前缀的 cookie 规范要求 host-only(不带 domain)。
        if name.startswith("__Host-"):
            ck["domain"] = _CHATGPT_COOKIE_DOMAIN
            ck["hostOnly"] = True
        try:
            page.set.cookies(ck)
            ok += 1
        except Exception:
            continue
    log(f"[BUSINESS AT cookie] 已注入 {ok}/{len(cookies or {})} 个 cookie")
    return ok


def _looks_logged_out(page) -> bool:
    url = ""
    try:
        url = page.url or ""
    except Exception:
        return True
    return (
        "auth.openai.com" in url
        or "/login" in url
        or "/log-in" in url
        or "/auth/" in url
    )


def acquire_business_at_via_cookies(
    email: str,
    *,
    cookies: dict,
    headless: bool,
    proxy: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict:
    """用注册时保存的 Cookie 直接登录 chatgpt.com, 选第一个工作空间并取 Business AT。

    免验证码登录。若 Cookie 失效(仍是登出态), 抛异常让上层回退到验证码登录。
    """
    log = _make_logger(log_fn)
    if not cookies:
        raise RuntimeError("没有可用的已保存 Cookie")
    page = _create_browser(proxy=proxy, headless=headless, log=log)
    try:
        # 先访问一次拿到域上下文(此时多半是登出态), 再注入 cookie 后重载。
        try:
            page.get("https://chatgpt.com/")
        except Exception as exc:
            log(f"[BUSINESS AT cookie] 首次访问 chatgpt.com 异常(继续): {exc}")
        time.sleep(1.5)
        injected = _inject_saved_cookies(page, cookies, log)
        if injected == 0:
            raise RuntimeError("Cookie 注入失败(0 个成功)")
        try:
            page.get("https://chatgpt.com/")
        except Exception as exc:
            log(f"[BUSINESS AT cookie] 重载 chatgpt.com 异常: {exc}")
        time.sleep(2)

        # 若跳到工作空间选择页, 选第一个空间
        deadline = time.time() + 8
        while time.time() < deadline:
            if _on_workspace_chooser(page):
                _handle_workspace_chooser(page, log)
                time.sleep(2)
                break
            time.sleep(0.5)

        if _looks_logged_out(page) and not _on_workspace_chooser(page):
            raise RuntimeError("Cookie 已失效(仍是登出态), 需要验证码登录")

        log("[BUSINESS AT cookie] Cookie 登录成功, 选择第一个 Business 空间并取 AT")
        session = _select_first_business_workspace_and_extract_session(page, log)
        if not isinstance(session, dict) or not session.get("access_token"):
            raise RuntimeError("Cookie 登录后未取到有效 AT")
        return session
    finally:
        try:
            page.quit()
        except Exception:
            pass


def _collect_cookies(page) -> dict:
    try:
        cookies = page.cookies() or []
    except Exception:
        return {}
    out: dict[str, str] = {}
    for c in cookies:
        try:
            name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
            value = c.get("value") if isinstance(c, dict) else getattr(c, "value", None)
        except Exception:
            continue
        if name:
            out[str(name)] = str(value or "")
    return out


def build_cookie_blob_from_result(result):
    """从登录结果(GptProLoginResult)构造 chatgpt.com 会话 cookie_blob(注入 oai-access-token)
    + 从 access_token JWT 解析过期时间。返回 (cookie_blob:str, expires_at:datetime|None)。
    供 GPT PRO / GPT BUSINESS 登录成功后统一保存/更新 cookie。"""
    from datetime import datetime as _dt, timezone as _tz
    from platforms.chatgpt.utils import decode_jwt_payload

    ck = dict(getattr(result, "cookies", {}) or {})
    at = str(getattr(result, "access_token", "") or "")
    if at:
        # The access token returned by this login is authoritative.  A browser
        # cookie snapshot can still contain an empty or older token under the
        # same key; keeping it would make a successful login persist a stale
        # local session.
        ck["oai-access-token"] = at
    else:
        # Some login paths capture the AT only in the cookie snapshot. Expiry
        # must describe the token actually persisted, not an empty result field.
        at = str(ck.get("oai-access-token") or "")
    blob = "; ".join(f"{k}={v}" for k, v in ck.items() if v)
    exp = None
    if at:
        try:
            claims = decode_jwt_payload(at) or {}
            e = int(claims.get("exp") or 0)
            if e:
                exp = _dt.fromtimestamp(e, tz=_tz.utc)
        except Exception:
            exp = None
    return blob, exp


def _login_with_password_totp(
    email: str,
    password: str,
    totp_secret: str,
    *,
    headless: bool = False,
    proxy: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
    landing_timeout: int = _DEFAULT_LANDING_TIMEOUT,
    keep_browser_open: bool = True,
    post_login_action: Optional[Callable[[Any, "GptProLoginResult"], dict]] = None,
    browser_backend: str = "local",
    roxy_proxy: Optional[dict] = None,
    prefer_personal_workspace: bool = False,
    checkout_session_recovery: bool = False,
) -> GptProLoginResult:
    """Log in with an encrypted saved password and optional Authenticator seed."""
    log = _make_logger(log_fn)
    page = None
    login_ok = False
    retained_session_page = False
    result = GptProLoginResult(
        ok=False,
        email=email,
        stage="password_totp_login" if totp_secret else "password_login",
    )
    try:
        if str(browser_backend or "local").strip().lower() == "roxybrowser":
            log("[GPT PRO 登录] 使用 RoxyBrowser 指纹浏览器接管已保存密码登录")
            page = _create_roxy_browser(log=log, proxy=roxy_proxy)
        else:
            page = _create_browser(proxy=proxy, headless=headless, log=log)

        # Reuse the independently tested security-login primitive.  It fills
        # the password, completes an Authenticator challenge when one appears,
        # and verifies the exact account through an authenticated backend request.
        from platforms.chatgpt.account_security import (
            ACCOUNT_DEACTIVATED_LOGIN_ERROR,
            _raise_for_auth_login_page_error,
            _reauthenticate_with_password,
            _safe_error,
        )

        log("[GPT PRO 登录] 使用已保存密码登录" + ("，需要时完成 Authenticator 验证" if totp_secret else ""))
        gmail_code_provider = _optional_gmail_login_code_provider(email, proxy=proxy, log_fn=log)
        auth_kwargs = {"email_code_provider": gmail_code_provider} if gmail_code_provider is not None else {}
        authenticated, error, totp_verified = _reauthenticate_with_password(
            page,
            email,
            password,
            totp_secret,
            log,
            prefer_personal_workspace=prefer_personal_workspace,
            **auth_kwargs,
        )
        if not authenticated:
            result.error = error or ("密码 + Authenticator 登录失败" if totp_secret else "密码登录失败；如出现额外验证，请补充对应收件授权或 2FA 密钥")
            if result.error == ACCOUNT_DEACTIVATED_LOGIN_ERROR:
                result.stage = "account_deactivated"
                result.login_failure = _login_failure("account_deactivated")
            return result
        _raise_for_auth_login_page_error(page)
        totp_verified = bool(totp_verified and totp_secret)
        if totp_secret and not totp_verified:
            # Authentication and proof of this particular seed are independent.
            # The primitive requires a real password submission plus exact
            # identity/protected-session proof, but the server may admit the
            # login without a fresh challenge.  Do not invent MFA proof or
            # promote a pending seed in that case; still verify the final session.
            log("[GPT PRO 登录] 目标账号已通过登录核验；本次未观察到 Authenticator 挑战，保留原 2FA 状态")
        auth_label = "密码 + Authenticator" if totp_verified else "密码"

        # Keep workspace handling aligned with the legacy OTP path.  This is
        # relevant to refund and BUSINESS callers that pass a post-login action.
        if _on_workspace_chooser(page):
            _handle_workspace_chooser(
                page,
                log,
                prefer_personal=prefer_personal_workspace,
            )
            time.sleep(1.0)
        result.stage = "wait_landing"
        if not _wait_for_chatgpt_home(
            page,
            timeout=max(1, int(landing_timeout or _DEFAULT_LANDING_TIMEOUT)),
            log_fn=log,
            prefer_personal_workspace=prefer_personal_workspace,
        ):
            _raise_for_auth_login_page_error(page)
            result.error = f"{auth_label}已通过，但未能进入 ChatGPT 主页"
            return result

        result.stage = "extract_session"
        time.sleep(1.2)
        session_failure = {}
        session, session_error = _verified_login_session(
            page, email, log, failure_out=session_failure,
            **({"retry_forbidden": True} if checkout_session_recovery else {}))
        _raise_for_auth_login_page_error(page)
        if session_error:
            result.error = f"{auth_label}已通过，但未取得有效登录会话：" + session_error
            result.login_failure = normalize_login_failure(session_failure)
            retained_session_page = _retain_checkout_session_failure(
                result, page, enabled=checkout_session_recovery, headless=headless,
                keep_open=keep_browser_open, log=log)
            return result
        user = session.get("user") or {}
        account = session.get("account") if isinstance(session.get("account"), dict) else {}
        access_token = session["accessToken"]
        plan_type = str(account.get("planType") or "").strip().lower()
        result = GptProLoginResult(
            ok=True,
            email=email,
            user_id=str(user.get("id") or ""),
            account_id=str(account.get("id") or ""),
            plan_type=plan_type,
            is_pro=plan_type == "pro",
            access_token=access_token,
            session_token=str(session.get("sessionToken") or ""),
            cookies=_collect_cookies(page),
            stage="done",
        )
        login_ok = True

        # Password-only imports may confirm the password but can never promote MFA.
        if totp_verified or not totp_secret:
            try:
                from services.chatgpt_security_store import (
                    update_chatgpt_security_state,
                )

                updates = {"password_state": "configured", "last_error": ""}
                if totp_verified:
                    updates["mfa_state"] = "enabled"
                update_chatgpt_security_state(email, **updates)
            except Exception:
                log("[GPT PRO 登录] 登录凭据已通过，但安全状态写回暂时失败")

        log(
            f"[GPT PRO 登录] ✅ {auth_label}登录完成: "
            f"user={result.user_id} plan_type={result.plan_type or '(空)'} "
            "access_token=已获取（内容不写入日志）"
        )
        if post_login_action is not None:
            try:
                action_data = post_login_action(page, result)
                result.action_result = action_data
                log(
                    f"[GPT PRO 登录] post_login_action 返回: "
                    f"{_redact_action_result_for_log(action_data)}"
                )
            except Exception as exc:
                safe_error = _safe_error(
                    exc,
                    known_secrets=(password, totp_secret),
                )
                log("[GPT PRO 登录] ⚠ post_login_action 执行失败（敏感信息已隐藏）")
                result.action_result = {
                    "ok": False,
                    "error": safe_error or "post_login_action 执行失败",
                }
        return result
    except _LoginFlowRejected as exc:
        result.ok = False
        result.stage = exc.failure["stage"]
        result.error = str(exc)
        result.login_failure = exc.failure
        return result
    except Exception as exc:
        from core.browser_startup import BrowserInitializationError
        if page is None and isinstance(exc, BrowserInitializationError):
            result.stage = "init"
            result.error = str(exc)
            return result
        try:
            from platforms.chatgpt.account_security import (
                AccountDeactivatedLoginError,
                _safe_error,
            )

            safe_error = _safe_error(
                exc,
                known_secrets=(password, totp_secret),
            )
            if isinstance(exc, AccountDeactivatedLoginError):
                result.stage = "account_deactivated"
                result.login_failure = _login_failure("account_deactivated")
        except Exception:
            safe_error = "密码 + Authenticator 登录异常"
        result.error = safe_error or "密码 + Authenticator 登录异常"
        return result
    finally:
        refund_done = bool(
            isinstance(result.action_result, dict)
            and result.action_result.get("refund_success")
        )
        should_close = ((not login_ok) and not retained_session_page) or (not keep_browser_open) or refund_done
        if should_close:
            try:
                if page is not None:
                    page.quit()
            except Exception:
                pass
        else:
            log("[GPT PRO 登录] 浏览器已留窗,请手动关闭")


def login_with_account_auth(
    email: str,
    *,
    mailbox: Any = None,
    mailbox_account: Any = None,
    otp_callback: Optional[Callable[[], str]] = None,
    headless: bool = False,
    proxy: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
    otp_timeout: int = _DEFAULT_OTP_TIMEOUT,
    landing_timeout: int = _DEFAULT_LANDING_TIMEOUT,
    keep_browser_open: bool = True,
    is_signup: bool = False,
    full_name: str = "",
    birthday: Optional[dict] = None,
    post_login_action: Optional[Callable[[Any, "GptProLoginResult"], dict]] = None,
    browser_backend: str = "local",
    roxy_proxy: Optional[dict] = None,
    prefer_personal_workspace: bool = False,
    checkout_session_recovery: bool = False,
) -> GptProLoginResult:
    """Dispatch one ChatGPT browser login without exposing stored secrets.

    Accounts with a stored TOTP seed, or whose public MFA state is ``pending``,
    ``enabled`` or ``unmanaged``, must use the encrypted password +
    Authenticator path.  Any missing/unreadable managed credential fails
    closed and never calls the mailbox.  Accounts without managed MFA keep the
    existing email-OTP flow.

    The arguments intentionally mirror :func:`login_with_email_otp`, so API
    callers only need to replace the imported function name.
    """
    try:
        from services.chatgpt_security_store import (
            get_chatgpt_security_secrets,
            get_chatgpt_security_status,
        )

        security_status = get_chatgpt_security_status(email)
    except Exception:
        return GptProLoginResult(
            ok=False,
            email=email,
            stage="security_state_unavailable",
            error="账号安全状态读取失败，已停止登录",
        )

    mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
    managed_mfa = bool(security_status.get("has_totp")) or mfa_state in {
        "pending",
        "enabled",
        "unmanaged",
    }
    saved_password_login = not is_signup and bool(security_status.get("has_password"))
    if managed_mfa or saved_password_login:
        if not bool(security_status.get("credentials_readable", True)):
            return GptProLoginResult(
                ok=False,
                email=email,
                stage="security_credentials_unavailable",
                error="账号登录凭据无法解密，已停止登录",
            )
        try:
            secrets = get_chatgpt_security_secrets(email)
        except Exception:
            return GptProLoginResult(
                ok=False,
                email=email,
                stage="security_credentials_unavailable",
                error="账号安全凭据无法解密，已停止登录",
            )
        password = str(secrets.get("password") or "")
        totp_secret = str(secrets.get("totp_secret") or "") if managed_mfa else ""
        if not password or (managed_mfa and not totp_secret):
            return GptProLoginResult(
                ok=False,
                email=email,
                stage="security_credentials_incomplete",
                error="账号已启用 Authenticator，但本地密码或 TOTP 密钥不完整，已停止登录" if managed_mfa else "账号已保存的密码不可用，已停止登录",
            )
        return _login_with_password_totp(
            email,
            password,
            totp_secret,
            headless=headless,
            proxy=proxy,
            log_fn=log_fn,
            landing_timeout=landing_timeout,
            keep_browser_open=keep_browser_open,
            post_login_action=post_login_action,
            browser_backend=browser_backend,
            roxy_proxy=roxy_proxy,
            prefer_personal_workspace=prefer_personal_workspace,
            checkout_session_recovery=checkout_session_recovery,
        )

    return _login_with_email_otp(
        email,
        mailbox=mailbox,
        mailbox_account=mailbox_account,
        otp_callback=otp_callback,
        headless=headless,
        proxy=proxy,
        log_fn=log_fn,
        otp_timeout=otp_timeout,
        landing_timeout=landing_timeout,
        keep_browser_open=keep_browser_open,
        is_signup=is_signup,
        full_name=full_name,
        birthday=birthday,
        post_login_action=post_login_action,
        browser_backend=browser_backend,
        roxy_proxy=roxy_proxy,
        prefer_personal_workspace=prefer_personal_workspace,
        checkout_session_recovery=checkout_session_recovery,
    )


def _login_with_email_otp(
    email: str,
    *,
    mailbox: Any = None,
    mailbox_account: Any = None,
    otp_callback: Optional[Callable[[], str]] = None,
    headless: bool = False,
    proxy: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
    otp_timeout: int = _DEFAULT_OTP_TIMEOUT,
    landing_timeout: int = _DEFAULT_LANDING_TIMEOUT,
    keep_browser_open: bool = True,
    is_signup: bool = False,
    full_name: str = "",
    birthday: Optional[dict] = None,
    post_login_action: Optional[Callable[[Any, "GptProLoginResult"], dict]] = None,
    browser_backend: str = "local",
    roxy_proxy: Optional[dict] = None,
    prefer_personal_workspace: bool = False,
    checkout_session_recovery: bool = False,
) -> GptProLoginResult:
    """Raw GPT PRO email-OTP login / registration implementation.

    流程:
      1. 打开 chatgpt.com/auth/login
      2. 填邮箱 → 点继续 (登录/注册都走同一入口)
      3. 等 OTP 输入页, mailbox 拉 OTP, 填入提交
      4a. 登录: 等到 chatgpt.com 主页
      4b. 注册: 多一步 — 等到 /about-you, 填姓名+生日+同意复选框, 再等 chatgpt.com 主页
      5. 调 /api/auth/session 拿 access_token / plan_type, 返回 GptProLoginResult

    keep_browser_open=True (默认): 成功后**不退出浏览器**,人工手动关闭;失败仍 quit。
    is_signup=True: 触发注册分支, full_name / birthday 不传时自动随机生成。
    """
    log = _make_logger(log_fn)
    page = None
    stage = "init"
    login_ok = False
    retained_session_page = False
    # 耗时计量: 每步结束输出本步秒数 + 累计秒数, 方便排查"哪一步慢"
    _ts = {"t0": time.perf_counter(), "last": time.perf_counter()}

    def _step_done(label: str) -> None:
        now = time.perf_counter()
        log(
            f"[GPT PRO 登录] ⏱ {label} (本步 {now - _ts['last']:.1f}s, "
            f"累计 {now - _ts['t0']:.1f}s)"
        )
        _ts["last"] = now

    try:
        if str(browser_backend or "local").strip().lower() == "roxybrowser":
            log("[GPT PRO 登录] 使用 RoxyBrowser 指纹浏览器接管")
            page = _create_roxy_browser(log=log, proxy=roxy_proxy)
        else:
            page = _create_browser(proxy=proxy, headless=headless, log=log)
        _step_done("浏览器创建")

        stage = "open_login_page"
        log(f"[GPT PRO 登录] 1/5 打开 {LOGIN_URL}")
        page.get(LOGIN_URL, timeout=_NAV_TIMEOUT)
        time.sleep(5)   # 开页后固定等 5 秒让 SPA 首屏渲染(不再靠"就绪判断+反复刷新", 那会白等 ~12s)
        # 直接(JS 优先)点登录按钮打开弹窗
        _open_login_modal(page, log)
        # 邮箱框仍没出现 → 可能真命中 Cloudflare 校验 → 才回退到刷新几次再试
        if not _find_email_input(page, timeout=2):
            log("[GPT PRO 登录] 邮箱框未出现, 回退: 刷新过 Cloudflare 后重试")
            _pass_cf_challenge(page, log)
            _open_login_modal(page, log)
        _step_done("1/5 打开登录页")

        stage = "fill_email"
        log(f"[GPT PRO 登录] 2/5 填邮箱 {email}")
        email_box = _find_email_input(page)
        if not email_box:
            # 兜底:弹窗可能没弹出来,再点一次登录按钮
            _open_login_modal(page, log)
            email_box = _find_email_input(page)
        if not email_box:
            return GptProLoginResult(ok=False, email=email, error="找不到邮箱输入框", stage=stage)
        # 等 React hydrate 就绪再填/点, 否则点「继续」会退回原生 GET 提交、不跳 OTP
        _wait_page_ready(page)
        # Snapshot before *any* email input: some forms can advance during
        # native input itself. Never baseline after such an OTP challenge.
        baseline_ids = (
            _snapshot_mail_ids(mailbox, mailbox_account, log)
            if (mailbox and mailbox_account and otp_callback is None)
            else set()
        )
        filled = _fill_email_react(page, email_box, email, log)
        state = _email_entry_state(page)
        if state in {"password", "advanced"}:
            raise _EmailEntryAdvanced()
        if not filled and state != "otp":
            raise _EmailInputConfirmationError()
        time.sleep(0.4)
        state = _email_entry_state(page)
        if state in {"password", "advanced"}:
            raise _EmailEntryAdvanced()
        if state != "otp" and not _click_continue(page):
            return GptProLoginResult(ok=False, email=email, error="找不到/点不到「继续」按钮", stage=stage)
        _step_done("2/5 填邮箱 + 点继续")

        stage = "wait_otp_page"
        log("[GPT PRO 登录] 3/5 等待 OTP 输入页")
        otp_failure = {}
        otp_input = _advance_to_otp(page, email, log, timeout=60, failure_out=otp_failure)
        if not otp_input:
            failure = normalize_login_failure(otp_failure) or _login_failure("login_page_unconfirmed")
            return GptProLoginResult(
                ok=False, email=email,
                error=login_failure_reason(failure),
                stage=failure["stage"], login_failure=failure,
            )
        _step_done("3/5 等到 OTP 输入页")

        stage = "fetch_otp"
        log("[GPT PRO 登录] 4/5 取 OTP 验证码")
        if otp_callback is not None:
            code = (otp_callback() or "").strip()
            if not _OTP_RE.fullmatch(code):
                return GptProLoginResult(
                    ok=False, email=email,
                    error="otp_callback 返回非法 OTP（内容已隐藏）",
                    stage=stage,
                )
        else:
            code = _fetch_otp_from_mailbox(
                mailbox, mailbox_account,
                before_ids=baseline_ids,
                timeout=otp_timeout, log=log,
            )
        log("[GPT PRO 登录]   OTP 已获取（验证码不写入日志）")
        _step_done("4/5a 取到 OTP")

        try:
            otp_input.clear(by_js=True)
        except Exception:
            pass
        otp_input.input(code)
        time.sleep(0.4)
        # 填 OTP + 提交 (带失败重试: 等按钮可点再点, 点后确认离开验证码页)
        submit_ok = _submit_otp_and_confirm(page, otp_input, code, log)
        # 账号被停用/删除时页面会停在 /email-verification 报 account_deactivated,
        # 这里立即识别并短路返回, 不再空等 about-you / landing 超时。
        if _detect_account_deactivated(page):
            log("[GPT PRO 登录] ✗ 账号已被停用或删除 (account_deactivated), 终止登录")
            return GptProLoginResult(
                ok=False, email=email,
                error="account_deactivated: 账号已被停用或删除",
                stage="account_deactivated",
                login_failure=_login_failure("account_deactivated"),
            )
        if not submit_ok:
            log("[GPT PRO 登录] ⚠ OTP 多次提交仍未离开验证码页, 继续走后续兜底流程")
        _step_done("4/5b 填 OTP + 提交")

        # 验证码通过后部分账号会跳到 auth.openai.com/workspace 选工作空间(个人/团队),
        # 选空间继续, 避免在后续 about-you/landing 等待里空耗。
        # 退款流程(prefer_personal_workspace=True): 优先选个人空间。
        _ws_deadline = time.time() + 6
        while time.time() < _ws_deadline:
            if _on_workspace_chooser(page):
                _handle_workspace_chooser(page, log, prefer_personal=prefer_personal_workspace)
                time.sleep(2)
                break
            time.sleep(0.5)

        # OTP 提交后 **始终** 检查是否进 about-you (新账号→需填资料) 或直接落地 (老账号→已登陆)
        # 这样不依赖 is_signup 标志位, 自动兼容:
        #   - 本地标 is_pro=False 但 OpenAI 已存在的号 (外部手动注册过) → 直接落地 chatgpt.com
        #   - 本地标 is_pro=True 但 OpenAI 实际没注册过的号 → 弹 about-you 我们也能处理
        stage = "about_you"
        log("[GPT PRO 登录] 等 /about-you (新账号) 或直接落地 chatgpt.com (老账号)")
        next_state = _wait_about_you_or_landed(page, timeout=20)
        resolved_name = (full_name or "").strip() or _gen_random_name()
        resolved_birthday = birthday or _gen_random_birthday()
        if next_state == "about_you":
            # about-you 页偶发 OpenAI 报错页(不明なエラー / Operation timed out)→ 自动点「重试」
            if not _recover_openai_error_page(page, log_fn=log):
                raise _LoginFlowRejected("login_profile_unconfirmed")
            if "/about-you" in (page.url or ""):
                log("[GPT PRO 登录] 检测到 /about-you → 新账号注册路径, 填资料(带失败重填)")
                if not _submit_about_you_with_retry(page, resolved_name, resolved_birthday, log):
                    raise _LoginFlowRejected("login_profile_unconfirmed")
            else:
                log("[GPT PRO 登录] 重试后已离开 about-you, 转落地流程")
        elif next_state == "landed":
            log("[GPT PRO 登录] 已直接落地 chatgpt.com → 老账号登陆路径, 无需填资料")
        else:
            log(f"[GPT PRO 登录] ⚠ 既没进 about-you 也没落地, 继续等 landing (URL={page.url})")
        _step_done("4/5c 处理 about-you / landed 分支")

        stage = "wait_landing"
        log("[GPT PRO 登录] 5/5 等待跳转到 chatgpt.com")
        # 兜底: 等落地期间若又被打回 /about-you 空表单(报错页点重试后的典型状态), 再走重填
        _refill = lambda: _submit_about_you_with_retry(  # noqa: E731
            page, resolved_name, resolved_birthday, log, max_attempts=2)
        if not _wait_for_chatgpt_home(page, timeout=landing_timeout, log_fn=log,
                                      on_about_you=_refill,
                                      prefer_personal_workspace=prefer_personal_workspace):
            return GptProLoginResult(
                ok=False, email=email,
                error=f"未跳转到 chatgpt.com (当前 URL: {page.url})",
                stage=stage,
            )
        _step_done("5/5 跳转到 chatgpt.com")

        stage = "extract_session"
        time.sleep(1.2)  # 让 next-auth 写入 session cookie
        session_failure = {}
        session, session_error = _verified_login_session(
            page, email, log, failure_out=session_failure,
            **({"retry_forbidden": True} if checkout_session_recovery else {}))
        if session_error:
            result = GptProLoginResult(ok=False, email=email, error=session_error, stage=stage,
                                       login_failure=normalize_login_failure(session_failure))
            retained_session_page = _retain_checkout_session_failure(
                result, page, enabled=checkout_session_recovery, headless=headless,
                keep_open=keep_browser_open, log=log)
            return result
        user = session.get("user") or {}
        account = session.get("account") if isinstance(session.get("account"), dict) else {}
        plan_type = str(account.get("planType") or "").strip().lower()
        result = GptProLoginResult(
            ok=True,
            email=email,
            user_id=str(user.get("id") or ""),
            account_id=str(account.get("id") or ""),
            plan_type=plan_type,
            is_pro=plan_type == "pro",
            access_token=str(session.get("accessToken") or ""),
            session_token=str(session.get("sessionToken") or ""),
            cookies=_collect_cookies(page),
            stage="done",
        )
        log(
            f"[GPT PRO 登录] ✅ 完成: user={result.user_id} "
            f"plan_type={result.plan_type or '(空)'} "
            "access_token=已获取（内容不写入日志）"
        )
        login_ok = True
        # 登录成功后的额外动作 (例如升级 PRO 跑 checkout JS)
        if post_login_action is not None:
            stage = "post_login_action"
            try:
                action_data = post_login_action(page, result)
                result.action_result = action_data
                log(
                    f"[GPT PRO 登录] post_login_action 返回: "
                    f"{_redact_action_result_for_log(action_data)}"
                )
            except Exception as exc:
                log(f"[GPT PRO 登录] ⚠ post_login_action 异常: {exc}")
                result.action_result = {"ok": False, "error": f"post_login_action 异常: {exc}"}
        return result
    except _LoginFlowRejected as exc:
        return GptProLoginResult(ok=False, email=email, error=str(exc),
                                 stage=exc.failure["stage"], login_failure=exc.failure)
    except _EmailInputConfirmationError as exc:
        return GptProLoginResult(ok=False, email=email, error=str(exc), stage="fill_email")
    except _EmailEntryAdvanced as exc:
        error = str(exc)
        if _email_entry_state(page) == "password":
            error = "登录已进入密码页，当前邮箱验证码流程无法继续，请核对已保存的 ChatGPT 密码"
        return GptProLoginResult(ok=False, email=email, error=error, stage="wait_landing")
    except Exception as exc:
        return GptProLoginResult(
            ok=False, email=email, error=f"登录异常: {exc}", stage=stage,
        )
    finally:
        # 成功 + keep_browser_open=True → 留给人工手动关闭浏览器
        # 其余情况(失败 / 调用方明确要求关闭 / 退款已成功) → quit
        refund_done = False
        try:
            if isinstance(result.action_result, dict):
                refund_done = bool(result.action_result.get("refund_success"))
        except Exception:
            refund_done = False
        should_close = ((not login_ok) and not retained_session_page) or (not keep_browser_open) or refund_done
        if should_close:
            try:
                if page is not None:
                    page.quit()
            except Exception:
                pass
            if refund_done:
                log("[退款] ✅ 退款成功, 已自动关闭浏览器")
        else:
            log("[GPT PRO 登录] 浏览器已留窗,请手动关闭")


# Backward-compatible public entry point.  Existing API modules and tests keep
# importing ``login_with_email_otp``, but every *login* now first consults the
# canonical account-security dispatcher.  Accounts without managed MFA still
# reach the raw OTP implementation above unchanged; MFA accounts can never
# silently fall back to mailbox OTP.
login_with_email_otp = login_with_account_auth


# ── 升级 PRO: 登录成功后在同一个 page 内创建 ChatGPT Pro 的 Stripe checkout ──

_UPGRADE_PRO_JS_TMPL = """
return (async function(){
    let stage = "session";
    try {
        // 登录成功后 session cookie/accessToken 可能还在同一页面的异步
        // 写入队列中。只请求一次会把“登录成功”误判成 checkout 失败。
        // 短暂重试不会重复付款，因为此时尚未发起 checkout。
        let sess = null;
        let lastSessionError = "";
        for (let attempt = 0; attempt < 5; attempt++) {
            try {
                const sr = await fetch("/api/auth/session", {credentials: "include", cache: "no-store"});
                sess = await sr.json();
                if (sess && sess.accessToken) break;
                lastSessionError = "无 accessToken";
            } catch (e) {
                lastSessionError = String(e);
            }
            await new Promise(resolve => setTimeout(resolve, 900));
        }
        if (!sess || !sess.accessToken) {
            return {ok: false, stage: "session", error: "登录已完成但 session 尚未就绪: " + lastSessionError};
        }
        const payload = {
            entry_point: "all_plans_pricing_modal",
            plan_name: __CB_PLAN__,
            billing_details: { country: __CB_COUNTRY__, currency: __CB_CURRENCY__ },
            checkout_ui_mode: "custom"
        };
        stage = "checkout";
        const r = await fetch("/backend-api/payments/checkout", {
            method: "POST",
            credentials: "include",
            headers: {
                Authorization: "Bearer " + sess.accessToken,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        // Response 的正文只能读一次；先读文本再 JSON.parse，避免 HTML
        // 错误页触发 body stream already read 并遮住真正的 HTTP 状态。
        const raw = await r.text();
        let body;
        try { body = JSON.parse(raw); } catch {
            return {ok: false, stage, status: r.status,
                error: "结账接口返回非 JSON 响应（HTTP " + r.status + "），未能创建结账会话"};
        }
        if (r.status < 200 || r.status >= 300) {
            const detail = body && (body.detail || body.error || body.message);
            const reason = typeof detail === "string" ? detail : JSON.stringify(detail || "请求被拒绝");
            return {ok: false, stage, status: r.status, error: "结账接口 HTTP " + r.status + ": " + reason};
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
            return {ok: false, stage, status: r.status, error: "结账接口响应格式异常（HTTP " + r.status + "）"};
        }
        if (!body.checkout_session_id && !(body.url || body.stripe_hosted_url || body.checkout_url)) {
            return {ok: false, stage, status: r.status, error: "结账接口未返回 checkout_session_id 或支付地址（HTTP " + r.status + "）"};
        }
        return {
            ok: true,
            checkout_session_id: body.checkout_session_id,
            // 新接口可能直接返回支付长链接；调用方应优先使用它，
            // 只有旧接口没有 url 时才根据 processor_entity 回退构造。
            url: body.url || body.stripe_hosted_url || body.checkout_url || "",
            publishable_key: body.publishable_key || "",
            checkout_ui_mode: body.checkout_ui_mode || "",
            processor_entity: body.processor_entity || ""
        };
    } catch (e) {
        return {ok: false, stage, error: String(e)};
    }
})();
"""


def _build_upgrade_pro_js(country: str = "PH", currency: str = "PHP",
                          plan_name: str = "chatgptpro") -> str:
    """按配置的结账区域(国家/币种)+ 套餐名生成 checkout JS。
    plan_name: "chatgptpro"(PRO) | "chatgptgo"(Go, 菲律宾先订 Go 再升 PRO 用)。
    账单地址不在此处,保持 _DEFAULT_BILLING_ADDRESS 不变。"""
    import json as _json
    return (
        _UPGRADE_PRO_JS_TMPL
        .replace("__CB_PLAN__", _json.dumps(str(plan_name or "chatgptpro").strip() or "chatgptpro"))
        .replace("__CB_COUNTRY__", _json.dumps(str(country or "PH").strip().upper() or "PH"))
        .replace("__CB_CURRENCY__", _json.dumps(str(currency or "PHP").strip().upper() or "PHP"))
    )


def _checkout_navigation_url(result: dict, session_id: str) -> str:
    """Return a validated checkout URL from the payment response.

    OpenAI has returned both a hosted URL and a ``processor_entity`` over
    time.  PRO used to discard both and always hard-code ``openai_llc``;
    that can open the wrong checkout page for PRO 5X.  Keep the URL returned
    by the API when present and only construct the legacy form as fallback.
    """
    from urllib.parse import urljoin, urlparse

    candidate = str(
        result.get("url")
        or result.get("stripe_hosted_url")
        or result.get("checkout_url")
        or ""
    ).strip()
    if candidate:
        parsed = urlparse(urljoin("https://chatgpt.com/", candidate))
        if (parsed.scheme == "https" and parsed.hostname in {
            "chatgpt.com", "pay.openai.com", "checkout.stripe.com",
        } and parsed.port in (None, 443) and not parsed.username and not parsed.password):
            return parsed.geturl()
        raise ValueError("checkout 接口返回了非预期支付地址")
    sid = str(session_id or "").strip()
    if not re.fullmatch(r"cs_[A-Za-z0-9_-]+", sid):
        raise ValueError("checkout 接口返回的 session_id 格式异常")
    entity = str(result.get("processor_entity") or "openai_llc").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", entity):
        raise ValueError("checkout 接口返回的 processor_entity 格式异常")
    return f"https://chatgpt.com/checkout/{entity}/{sid}"


# 已登录 page 上拉当前订阅状态, 用来判断账号当前是 free / go / pro / plus。
_DETECT_PLAN_JS = r"""
return (async function(){
    try {
        const sess = await (await fetch("/api/auth/session", {credentials:"include"})).json();
        if (!sess || !sess.accessToken) return {ok:false, error:"无 accessToken (未登录)"};
        const h = {Authorization:"Bearer "+sess.accessToken};
        const eps = ["/backend-api/payments/subscription", "/backend-api/me"];
        const raw = {};
        for (const ep of eps) {
            try {
                const r = await fetch(ep, {credentials:"include", headers:h});
                let b; try { b = await r.json(); } catch(e) { b = String(e); }
                raw[ep] = {status: r.status, body: b};
            } catch(e) { raw[ep] = {error: String(e)}; }
        }
        return {ok:true, raw:raw};
    } catch(e) { return {ok:false, error:String(e)}; }
})();
"""


def _detect_current_plan(page, log_fn=None) -> dict:
    """在已登录 page 上探测账号当前套餐。

    返回 {ok, plan, is_pro, is_go, is_plus, has_active, raw}。
    plan ∈ {"pro","go","plus","active","free","unknown"}。
    判定基于对订阅接口原始响应的 token 扫描('chatgptgoplan'/'chatgptpro' 等我们
    已知的 plan_name 通常也出现在 plan_type 里),原始响应会打到日志便于校准。
    """
    log_fn = log_fn or (lambda m: print(m, flush=True))
    import json as _json
    try:
        res = page.run_js(_DETECT_PLAN_JS) or {}
    except Exception as exc:
        log_fn(f"[GPT PRO 套餐检测] JS 异常: {exc}")
        return {"ok": False, "error": f"检测 JS 异常: {exc}"}
    if not isinstance(res, dict) or not res.get("ok"):
        log_fn(f"[GPT PRO 套餐检测] 失败: {res}")
        return {"ok": False, "raw": res}

    raw = res.get("raw") or {}
    text = _json.dumps(raw, ensure_ascii=False).lower()
    log_fn(f"[GPT PRO 套餐检测] 原始订阅响应(截断): {text[:800]}")

    is_pro = ("chatgptpro" in text) or ("proplan" in text) or ('"plan_type":"pro' in text)
    is_go = ("chatgptgoplan" in text) or ("chatgptgo" in text) or ('"plan_type":"go' in text)
    is_plus = ("chatgptplus" in text) or ("plusplan" in text) or ('"plan_type":"plus' in text)
    has_active = (
        is_pro or is_go or is_plus
        or '"has_active_subscription":true' in text
        or '"has_paid_subscription":true' in text
        or '"is_paid":true' in text
        or '"plan_type":"chatgpt' in text
        or "goplan" in text
    )
    if is_pro:
        plan = "pro"
    elif is_go:
        plan = "go"
    elif is_plus:
        plan = "plus"
    elif has_active:
        plan = "active"
    else:
        plan = "free"
    log_fn(f"[GPT PRO 套餐检测] 判定 plan={plan} "
           f"(is_pro={is_pro} is_go={is_go} is_plus={is_plus} has_active={has_active})")
    return {"ok": True, "plan": plan, "is_pro": is_pro, "is_go": is_go,
            "is_plus": is_plus, "has_active": has_active, "raw": raw}


# ── BUSINESS(Team)hosted checkout 支付长链接 ──
_TEAM_CHECKOUT_JS_TMPL = r"""
return (async function(){
    let stage = "session";
    let status = 0;
    function failure(message) {
        return {ok:false, stage:stage, status:status,
            error:message + (status ? "（HTTP " + status + "）" : "")};
    }
    async function readJson(response, label) {
        status = response.status;
        const contentType = (response.headers.get("content-type") || "").toLowerCase();
        // Read the body once, and never return response content in diagnostics.
        const raw = await response.text();
        let body;
        try { body = JSON.parse(raw); }
        catch { return failure(label + "返回非 JSON 响应"); }
        if (contentType && !/^(application|text)\/([a-z0-9.+-]+\+)?json(?:\s*;|$)/.test(contentType)) {
            return failure(label + "返回非 JSON 响应");
        }
        if (status < 200 || status >= 300) {
            if (stage === "checkout" && status === 400 && body && typeof body === "object") {
                const couponErrors = new Set([
                    "discount code is not eligible", "discount_code_not_eligible",
                    "coupon_not_eligible", "invalid_coupon", "coupon_invalid", "invalid_promo_code"
                ]);
                const fields = [body, body.detail, body.error].flatMap(function(value) {
                    return value && typeof value === "object" ? [value.message, value.code] : [value];
                });
                if (fields.some(function(value) {
                    return typeof value === "string" && couponErrors.has(value.trim().toLowerCase());
                })) return failure("优惠码不适用于当前账号/套餐");
            }
            return failure(label + "拒绝请求");
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
            return failure(label + "响应格式异常");
        }
        return {ok:true, body:body};
    }
    try {
        if (typeof location === "undefined" || location.origin !== "https://chatgpt.com") {
            return failure("当前页面不是可信 ChatGPT 页面，已停止创建支付链接");
        }
        const verifiedSession = __VERIFIED_SESSION__;
        let s = null;
        let accessToken = verifiedSession.accessToken;
        let accountId = accessToken ? verifiedSession.accountId : "";
        if (!accessToken) {
            const sessionResponse = await fetch("/api/auth/session", {
                credentials:"include", cache:"no-store", headers:{Accept:"application/json"}
            });
            const sessionResult = await readJson(sessionResponse, "登录会话接口");
            if (!sessionResult.ok) return sessionResult;
            s = sessionResult.body;
            accessToken = typeof s.accessToken === "string" ? s.accessToken.trim() : "";
        }
        if (!accessToken) return failure("无 accessToken(未登录)");
        const payload = __PAYLOAD__;
        const headers = {Authorization:"Bearer "+accessToken, "Content-Type":"application/json"};
        __PROLITE_HEADERS__
        stage = "checkout";
        status = 0;
        const r = await fetch("https://chatgpt.com/backend-api/payments/checkout", {
            method:"POST", mode:"cors", credentials:"include", headers:headers,
            body: JSON.stringify(payload)
        });
        const checkoutResult = await readJson(r, "结账接口");
        if (!checkoutResult.ok) return checkoutResult;
        const body = checkoutResult.body;
        let url = body && (body.url || body.stripe_hosted_url || body.checkout_url);
        const checkoutSessionId = (body && body.checkout_session_id) || "";
        const processorEntity = (body && body.processor_entity) || "";
        if (checkoutSessionId && (typeof checkoutSessionId !== "string" ||
            !/^cs_[A-Za-z0-9_-]+$/.test(checkoutSessionId))) {
            return failure("接口返回的 checkout 标识格式异常");
        }
        if (!url && checkoutSessionId && processorEntity) {
            if (typeof processorEntity !== "string" ||
                !/^[A-Za-z0-9_-]+$/.test(processorEntity)) {
                return failure("接口返回的 checkout 标识格式异常");
            }
            url = "https://chatgpt.com/checkout/" + encodeURIComponent(processorEntity) +
                  "/" + encodeURIComponent(checkoutSessionId);
        }
        if (!url) return failure("未返回支付长链接");
        if (typeof url !== "string") return failure("接口返回的支付链接格式异常");
        let parsedUrl;
        try { parsedUrl = new URL(url, "https://chatgpt.com/"); }
        catch { return failure("接口返回的支付链接格式异常"); }
        const allowedHosts = new Set(["chatgpt.com", "pay.openai.com", "checkout.stripe.com"]);
        if (parsedUrl.protocol !== "https:" || !allowedHosts.has(parsedUrl.hostname) ||
            parsedUrl.username || parsedUrl.password) {
            return failure("接口返回了非预期付款地址");
        }
        return {ok:true, url:parsedUrl.href, checkout_session_id:checkoutSessionId};
    } catch (e) {
        return failure(stage === "session" ? "登录会话校验请求失败" : "结账请求失败");
    }
})();
"""


def _build_team_checkout_payload(workspace_name: str, coupon: str, seat_quantity: int = 2,
                                 country: str = "US", currency: str = "USD", *,
                                 seat_type: str = "default") -> dict:
    """构造 Team checkout 请求体；高级模式固定为 1 个普通 + 1 个 prolite。"""
    normalized_seat_type = str(seat_type or "default").strip().lower()
    if normalized_seat_type not in {"default", "prolite"}:
        raise ValueError("seat_type 必须是 default 或 prolite")

    seats = 2 if normalized_seat_type == "prolite" else max(2, int(seat_quantity or 2))
    team_plan_data = {
        "workspace_name": str(workspace_name or "").strip(),
        "price_interval": "month",
        "seat_quantity": seats,
    }
    if normalized_seat_type == "prolite":
        team_plan_data["seat_quantities"] = [
            {"seat_type": "default", "quantity": 1},
            {"seat_type": "prolite", "quantity": 1},
        ]

    return {
        "plan_name": "chatgptteamplan",
        "team_plan_data": team_plan_data,
        "billing_details": {
            "country": str(country or "US").strip().upper() or "US",
            "currency": str(currency or "USD").strip().upper() or "USD",
        },
        "cancel_url": "https://chatgpt.com/",
        "promo_code": str(coupon or "").strip(),
        "checkout_ui_mode": "hosted",
    }


def _build_team_checkout_js(workspace_name: str, coupon: str, seat_quantity: int = 2,
                            country: str = "US", currency: str = "USD", *,
                            seat_type: str = "default", verified_access_token: str = "",
                            verified_account_id: str = "") -> str:
    """生成 BUSINESS checkout JS；优先复用本次登录刚验证过的凭据。"""
    import json as _json
    payload = _build_team_checkout_payload(
        workspace_name, coupon, seat_quantity, country, currency, seat_type=seat_type)
    prolite_headers = ""
    if str(seat_type or "default").strip().lower() == "prolite":
        # 与浏览器抓包脚本一致：混合席位 checkout 显式携带当前账号 ID 和路由头。
        prolite_headers = r'''
        if (!accountId) {
            try {
                const tokenParts = String(accessToken).split(".");
                if (tokenParts.length === 3) {
                    let encodedPayload = tokenParts[1].replace(/-/g, "+").replace(/_/g, "/");
                    encodedPayload += "=".repeat((4 - encodedPayload.length % 4) % 4);
                    const binary = atob(encodedPayload);
                    const bytes = Uint8Array.from(binary, function(ch){ return ch.charCodeAt(0); });
                    const jwtPayload = JSON.parse(new TextDecoder().decode(bytes));
                    const authInfo = jwtPayload["https://api.openai.com/auth"] || {};
                    accountId = authInfo.chatgpt_account_id || "";
                }
            } catch (e) { /* Fall back to the account in the same session. */ }
            accountId = accountId || (s && s.account && s.account.id) || "";
        }
        if (typeof accountId !== "string" || !accountId.trim()) {
            return failure("无法取得 chatgpt-account-id");
        }
        headers["Accept"] = "*/*";
        headers["chatgpt-account-id"] = accountId;
        headers["oai-language"] = "zh-CN";
        headers["x-openai-target-path"] = "/backend-api/payments/checkout";
        headers["x-openai-target-route"] = "/backend-api/payments/checkout";
        '''
    replacements = {
        "__VERIFIED_SESSION__": _json.dumps({
            "accessToken": str(verified_access_token or "").strip(),
            "accountId": str(verified_account_id or "").strip(),
        }, ensure_ascii=False),
        "__PAYLOAD__": _json.dumps(payload, ensure_ascii=False),
        "__PROLITE_HEADERS__": prolite_headers,
    }
    return re.sub(
        r"__VERIFIED_SESSION__|__PAYLOAD__|__PROLITE_HEADERS__",
        lambda match: replacements[match.group(0)],
        _TEAM_CHECKOUT_JS_TMPL,
    )


def _fill_stripe_hosted_checkout(page, card: dict, log_fn=None, email: str = "",
                                 auto_submit: bool = False) -> dict:
    """填 Stripe **hosted** 付款页(pay.openai.com / checkout.stripe.com)。

    与 PRO 的内嵌 custom checkout(_fill_stripe_iframes_with_card)是完全不同的页面,
    此函数独立适配, 不影响 PRO 回填。用真实键入(.input())填卡要素(masked input 需要模拟输入)。
    地址字段有 Google/Stripe 自动完成下拉 → 填完 blur 关掉, 避免遮挡/改写邮编。
    勾选同意条款; auto_submit=True 才点「订阅/付款」按钮(真实扣款, 默认不点)。

    返回 {ok, log:[...], submit_found, submitted}。
    """
    log = log_fn or (lambda m: print(m, flush=True))
    rep: list = []

    def _fill(selectors, value, label):
        value = str(value or "")
        if not value:
            rep.append(f"{label}:空值跳过")
            return False
        for sel in selectors:
            try:
                el = page.ele(sel, timeout=3)
            except Exception:
                el = None
            if el:
                try:
                    el.input(value)      # 模拟真实键入(masked 卡号/到期/CVC 才认)
                    rep.append(f"{label}:已填")
                    return True
                except Exception as exc:
                    rep.append(f"{label}:填入异常 {exc}")
                    return False
        rep.append(f"{label}:未找到")
        return False

    def _select(selectors, value, label):
        """给 <select> 选值: 先按 value(国家/州代码), 再按可见文本(全名)。"""
        value = str(value or "").strip()
        if not value:
            rep.append(f"{label}:空值跳过")
            return False
        el = None
        for sel in selectors:
            try:
                el = page.ele(sel, timeout=2)
            except Exception:
                el = None
            if el:
                break
        if not el:
            rep.append(f"{label}:未找到")
            return False
        for meth in ("by_value", "by_text"):
            try:
                getattr(el.select, meth)(value)
                rep.append(f"{label}:已选({meth})")
                return True
            except Exception:
                continue
        rep.append(f"{label}:选值失败")
        return False

    def _blur():
        try:
            page.run_js("document.activeElement && document.activeElement.blur();")
        except Exception:
            pass

    time.sleep(3)  # 等 Stripe 页渲染
    number = "".join(ch for ch in str(card.get("number") or "") if ch.isdigit())
    # 到期日只打 4 位数字(MMYY),让 Stripe 自己格式化成 "MM / YY";直接打带分隔符易被掩码逻辑打乱
    exp = f"{int(card.get('exp_month') or 0):02d}{str(card.get('exp_year') or '')[-2:]}"

    # email: 结账会话有时预填/有时空; 空则填账号邮箱
    if email:
        try:
            cur = page.run_js("var e=document.getElementById('email'); return e? e.value : null;")
            if cur is None:
                rep.append("email:框未找到")
            elif str(cur).strip():
                rep.append("email:已预填")
            else:
                e = page.ele('#email', timeout=2)
                if e:
                    e.input(email)
                    rep.append("email:已填")
        except Exception as exc:
            rep.append(f"email异常:{exc}")

    # 卡要素: autocomplete 命中率最高, 再退回 id/name(实测 pay.openai.com 用这些 id)
    _fill(['css:input[autocomplete="cc-number"]', '#cardNumber', 'css:input[name="cardNumber"]'], number, '卡号')
    _fill(['css:input[autocomplete="cc-exp"]', '#cardExpiry', 'css:input[name="cardExpiry"]'], exp, '到期')
    _fill(['css:input[autocomplete="cc-csc"]', '#cardCvc', 'css:input[name="cardCvc"]'], card.get('cvc'), 'CVC')
    _fill(['css:input[autocomplete="cc-name"]', '#billingName', 'css:input[name="billingName"]'], card.get('holder_name'), '持卡人')
    _select(['#billingCountry', 'css:select[name="billingCountry"]'], card.get('country') or 'US', '国家')
    # 先填 邮编/城市/州(在地址自动完成下拉出现之前, 避免下拉遮挡导致邮编填不上)
    _fill(['#billingPostalCode', 'css:input[name="billingPostalCode"]'], card.get('postal_code'), '邮编')
    _fill(['#billingLocality', 'css:input[name="billingLocality"]'], card.get('city'), '城市')
    _select(['#billingAdministrativeArea', 'css:select[name="billingAdministrativeArea"]'], card.get('state'), '州/省')
    # 地址最后填, 填完立刻 blur 关掉自动完成下拉(不选建议项, 保留手打文本)
    _fill(['#billingAddressLine1', 'css:input[name="billingAddressLine1"]'], card.get('address_line1'), '地址')
    _blur()
    time.sleep(0.6)

    # 勾选同意条款(termsOfServiceConsentCheckbox);JS click 触发 React
    try:
        r = page.run_js(
            "var c=document.getElementById('termsOfServiceConsentCheckbox');"
            "if(!c){return 'none';} if(!c.checked){c.click();} return c.checked?'checked':'failed';")
        rep.append(f"同意条款:{r}")
    except Exception as exc:
        rep.append(f"同意条款异常:{exc}")

    # 定位「订阅/付款」提交按钮
    submit_found = False
    submitted = False
    try:
        found = page.run_js(
            "var b=document.querySelector('button[type=\"submit\"].SubmitButton')||"
            "document.querySelector('.SubmitButton')||"
            "[...document.querySelectorAll('button')].find(x=>/订阅|立即|subscribe|pay|付款|start/i.test((x.innerText||'')));"
            "return b? (b.innerText||b.textContent||'').trim().slice(0,30):'';")
        submit_found = bool(found)
        rep.append(f"提交按钮:{found or '未找到'}")
    except Exception:
        pass
    if auto_submit and submit_found:
        try:
            time.sleep(1.0)
            page.run_js(
                "var b=document.querySelector('button[type=\"submit\"].SubmitButton')||"
                "document.querySelector('.SubmitButton')||"
                "[...document.querySelectorAll('button')].find(x=>/订阅|立即|subscribe|pay|付款|start/i.test((x.innerText||'')));"
                "if(b && !b.disabled){b.click();}")
            submitted = True
            rep.append("提交:已点击(auto_submit)")
        except Exception as exc:
            rep.append(f"提交异常:{exc}")

    log(f"[Team付款] 自动填卡结果: {rep}")
    return {"ok": True, "log": rep, "submit_found": submit_found, "submitted": submitted}


# 卡选择浮动 panel + 自动填表的核心 JS
# - 接收 window.__GPT_PRO_CARDS__ (Python 注入,数组)
# - 渲染右下角紫色 panel,列出卡片(label / brand / 后4位 / 国家)
# - 点击卡片 → 主页面字段批量填: holder_name / country / state / city / address_line1 /
#                                  address_line2 / postal_code (复用 AI填卡助手 v1.4 的 selector 优先级)
# - 字段写入用 nativeInputValueSetter + reset _valueTracker, React 才会感知
# - 卡号/到期/CVC 在 Stripe iframe 内, 主页面 JS 无法跨域写, 这部分由后端 DrissionPage
#   的 frame.run_js 单独处理 (本 JS 把所选卡的 number/exp/cvc 暴露到 window.__GPT_PRO_SELECTED_CARD__
#   供后端轮询取走)
_CARD_PANEL_JS_TEMPLATE = """
(function(){
    if (window.__GPT_PRO_PANEL_INJECTED__) return;
    window.__GPT_PRO_PANEL_INJECTED__ = true;
    window.__GPT_PRO_CARDS__ = __CARDS_JSON__;
    window.__GPT_PRO_SELECTED_CARD__ = null;

    // ── 样式 ──
    const style = document.createElement('style');
    style.textContent = `
        #gp-card-panel {
            position: fixed; right: 20px; bottom: 20px; z-index: 999999;
            width: 320px; max-height: 70vh;
            background: linear-gradient(135deg, #1e3a5f 0%, #0f2744 100%);
            border: 1px solid rgba(124,58,237,0.5); border-radius: 12px;
            box-shadow: 0 8px 32px rgba(88,86,214,0.3);
            font: 14px -apple-system,BlinkMacSystemFont,sans-serif;
            color:#fff; overflow:hidden; display:flex; flex-direction:column;
        }
        #gp-card-panel header {
            padding: 12px 14px; background: linear-gradient(135deg,#5856D6,#7C3AED);
            display:flex; justify-content:space-between; align-items:center;
            font-weight:600; font-size:14px;
        }
        #gp-card-panel header .close { cursor:pointer; opacity:0.8; }
        #gp-card-panel header .close:hover { opacity:1; }
        #gp-card-panel .body { padding: 8px; overflow-y:auto; flex:1; }
        .gp-card-item {
            padding: 10px 12px; margin-bottom: 6px; border-radius: 8px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.08);
            cursor: pointer; transition: all 0.15s;
        }
        .gp-card-item:hover {
            background: rgba(124,58,237,0.25);
            border-color: rgba(124,58,237,0.6);
        }
        .gp-card-item .row1 { font-weight:600; display:flex; justify-content:space-between; }
        .gp-card-item .row2 {
            font-family: monospace; font-size: 13px;
            color: #a5b4fc; margin: 4px 0;
        }
        .gp-card-item .row3 { font-size: 12px; color: rgba(255,255,255,0.55); }
        .gp-card-item.selected {
            background: rgba(16,185,129,0.18);
            border-color: rgba(16,185,129,0.7);
        }
        #gp-card-panel .empty {
            padding: 20px; text-align:center; color: rgba(255,255,255,0.55);
        }
        #gp-card-toast {
            position: fixed; right: 20px; bottom: calc(70vh + 30px); z-index:999999;
            background:#10b981; color:#fff; padding: 10px 16px; border-radius: 8px;
            font: 13px -apple-system; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            opacity:0; transition: opacity .25s; pointer-events:none;
        }
        #gp-card-toast.show { opacity: 1; pointer-events: auto; }
    `;
    document.head.appendChild(style);

    // ── DOM ──
    const panel = document.createElement('div');
    panel.id = 'gp-card-panel';
    panel.innerHTML = `
        <header>
            <span>💳 银行卡 (__CARD_COUNT__)</span>
            <span class="close" title="收起">−</span>
        </header>
        <div class="body" id="gp-card-body"></div>
    `;
    document.body.appendChild(panel);
    const toast = document.createElement('div');
    toast.id = 'gp-card-toast';
    document.body.appendChild(toast);

    function showToast(msg) {
        toast.textContent = msg;
        toast.classList.add('show');
        clearTimeout(toast._t);
        toast._t = setTimeout(() => toast.classList.remove('show'), 2200);
    }

    const closeBtn = panel.querySelector('.close');
    closeBtn.addEventListener('click', () => {
        const body = panel.querySelector('.body');
        body.style.display = body.style.display === 'none' ? 'block' : 'none';
        closeBtn.textContent = body.style.display === 'none' ? '+' : '−';
    });

    const cards = window.__GPT_PRO_CARDS__;
    const body = panel.querySelector('#gp-card-body');
    if (!cards || cards.length === 0) {
        body.innerHTML = '<div class="empty">没有可用卡片<br>请到「支付卡池」页面添加</div>';
        return;
    }

    // ── 渲染卡片 ──
    cards.forEach((c, idx) => {
        const item = document.createElement('div');
        item.className = 'gp-card-item';
        item.dataset.idx = idx;
        item.innerHTML = `
            <div class="row1"><span>${c.label || '(无备注)'}</span><span style="color:#fbbf24">${c.brand || c.country || ''}</span></div>
            <div class="row2">${c.number_masked || '****'} · ${String(c.exp_month).padStart(2,'0')}/${String(c.exp_year).slice(-2)}</div>
            <div class="row3">${c.holder_name || ''} · ${c.country || ''} ${c.state || ''} ${c.city || ''}</div>
        `;
        item.addEventListener('click', () => onPickCard(idx, item));
        body.appendChild(item);
    });

    // ── 填表逻辑 ──
    const FIELD_SELECTORS = {
        fullName: [
            'input[name="billingName"]', 'input[name="name"]',
            'input[autocomplete="cc-name"]', 'input[id^="Field-name"]',
            'input[autocomplete="name"]',
            'input[placeholder*="Name"]', 'input[placeholder*="name"]',
            'input[placeholder*="姓名"]'
        ],
        country: [
            'select[name="billingCountry"]', 'select[name="country"]',
            'select[id^="Field-country"]', 'select[autocomplete="country"]'
        ],
        state: [
            'select[name="billingAdministrativeArea"]', 'select[name="state"]',
            'select[id^="Field-administrative_area"]', 'select[autocomplete="address-level1"]',
            'input[name="billingAdministrativeArea"]', 'input[name="state"]',
            'input[id^="Field-administrative_area"]'
        ],
        city: [
            'input[name="billingLocality"]', 'input[name="city"]',
            'input[id^="Field-locality"]', 'input[autocomplete="address-level2"]'
        ],
        addressLine1: [
            'input[name="billingAddressLine1"]', 'input[name="addressLine1"]',
            'input[id^="Field-line1"]', 'input[autocomplete="address-line1"]'
        ],
        addressLine2: [
            'input[name="billingAddressLine2"]', 'input[name="addressLine2"]',
            'input[id^="Field-line2"]', 'input[autocomplete="address-line2"]'
        ],
        postalCode: [
            'input[name="billingPostalCode"]', 'input[name="postalCode"]',
            'input[id^="Field-postal_code"]', 'input[autocomplete="postal-code"]'
        ]
    };

    function fillOneField(selectors, value, fieldName) {
        if (!value) return false;
        for (const sel of selectors) {
            const els = document.querySelectorAll(sel);
            for (const el of els) {
                if (!el || !el.offsetParent) continue;
                if (el.tagName.toLowerCase() === 'select') {
                    // 精确 + 模糊
                    let matched = null;
                    for (const opt of el.options) {
                        if (opt.value === value) { matched = opt.value; break; }
                    }
                    if (!matched) {
                        const v = value.toLowerCase();
                        for (const opt of el.options) {
                            if (opt.value.toLowerCase() === v ||
                                opt.textContent.toLowerCase().includes(v)) {
                                matched = opt.value; break;
                            }
                        }
                    }
                    if (matched) {
                        el.value = matched;
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        return true;
                    }
                } else {
                    const setter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value').set;
                    const tracker = el._valueTracker;
                    if (tracker) tracker.setValue('');
                    setter.call(el, '');
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.focus();
                    setter.call(el, value);
                    if (tracker) tracker.setValue('');
                    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType:'insertText', data: value }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    el.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
                    return true;
                }
            }
        }
        return false;
    }

    function onPickCard(idx, itemDiv) {
        // 取消其它高亮
        body.querySelectorAll('.gp-card-item').forEach(d => d.classList.remove('selected'));
        itemDiv.classList.add('selected');
        const c = cards[idx];
        window.__GPT_PRO_SELECTED_CARD__ = c;
        // 主页面填表
        let filled = 0, missed = [];
        const map = [
            ['fullName',     c.holder_name],
            ['country',      c.country],
            ['state',        c.state],
            ['city',         c.city],
            ['addressLine1', c.address_line1],
            ['addressLine2', c.address_line2],
            ['postalCode',   c.postal_code]
        ];
        for (const [field, value] of map) {
            if (!value) continue;
            if (fillOneField(FIELD_SELECTORS[field], value, field)) filled++;
            else missed.push(field);
        }
        console.log('[GPT PRO 填卡] 主页面字段填入 ' + filled + ' 个,缺失:', missed);
        showToast(`已选 ${c.label || c.number_masked}, 主页字段 ${filled} 个已填, Stripe iframe 待自动写入`);
    }
})();
"""


_IFRAME_RECURSIVE_DUMP_JS = """
return (function(){
    function meta(i){
        return {
            tag: i.tagName.toLowerCase(),
            type: i.type || '',
            name: i.name || '',
            ac: i.autocomplete || '',
            stable: i.getAttribute('data-elements-stable-field-name') || '',
            aria: i.getAttribute('aria-label') || '',
            placeholder: i.placeholder || '',
            id: i.id || '',
        };
    }
    function ifmeta(f){
        return {
            name: f.name || '',
            src: (f.src || '').slice(0, 90),
            id: f.id || '',
        };
    }
    const allInputs = Array.from(document.querySelectorAll('input, select, textarea'));
    const allIframes = Array.from(document.querySelectorAll('iframe'));
    return {
        url: (location.href || '').slice(0, 120),
        title: document.title || '',
        inputs: allInputs.map(meta),
        iframes: allIframes.map(ifmeta),
    };
})();
"""


def _recursive_dump_iframes(scope, log_fn, *, depth=0, max_depth=4) -> dict:
    """递归遍历 scope (page 或 frame) 下所有 iframe, 在每个 iframe 内 run dump JS。

    返回嵌套字典 {url, inputs, iframes, children}, children 是该 frame 的所有 nested
    frame 的 dump 结果。日志同时打印, 便于排查账单字段隐藏在哪一级。
    """
    indent = "  " * depth
    out = {"depth": depth, "frames": []}
    try:
        sub_frames = scope.get_frames("css:iframe")
    except Exception as exc:
        log_fn(f"{indent}❌ get_frames 异常: {exc}")
        return out
    log_fn(f"{indent}── depth={depth} 共 {len(sub_frames)} 个 iframe ──")
    for i, frame in enumerate(sub_frames):
        try:
            res = frame.run_js(_IFRAME_RECURSIVE_DUMP_JS)
        except Exception as exc:
            log_fn(f"{indent}frame#{i} run_js 异常: {exc}")
            out["frames"].append({"i": i, "error": str(exc)})
            continue
        if not isinstance(res, dict):
            log_fn(f"{indent}frame#{i} 返回非 dict: {res!r}")
            continue
        url = res.get("url", "")
        inputs = res.get("inputs") or []
        sub_iframes_meta = res.get("iframes") or []
        log_fn(
            f"{indent}frame#{i} url={url[:100]} title={res.get('title','')[:40]} "
            f"inputs={len(inputs)} subframes={len(sub_iframes_meta)}"
        )
        for inp in inputs:
            log_fn(f"{indent}  INPUT  {inp}")
        for sub in sub_iframes_meta:
            log_fn(f"{indent}  CHILD_IFRAME {sub}")
        frame_dump = {"i": i, "url": url, "title": res.get("title"),
                      "inputs": inputs, "iframes_meta": sub_iframes_meta}
        # 递归
        if depth < max_depth:
            frame_dump["children"] = _recursive_dump_iframes(
                frame, log_fn, depth=depth + 1, max_depth=max_depth,
            )
        out["frames"].append(frame_dump)
    return out


def open_pro_checkout_phase1(page, login_result: "GptProLoginResult",
                              *, dump_only: bool = False,
                              country: str = "PH", currency: str = "PHP",
                              plan_name: str = "chatgptpro",
                              card_loader=None) -> dict:
    """phase1 (同步): 已登录 page 上跑 checkout JS → 跳到 checkout 页 → 注入卡选择 panel。

    不等用户选卡 / 不填卡 / 不点订阅。后续步骤交给 run_checkout_phase2。
    country/currency 为结账区域(可在界面配置;默认 PH/PHP)。账单地址不变。
    plan_name: 首个 checkout 的套餐; 菲律宾「先 Go 后 PRO」时这里传 "chatgptgo"。

    返回 {ok, checkout_session_id, pay_url, region, card_picker?, dump_only?, ...}
    """
    country = (country or "PH").strip().upper() or "PH"
    currency = (currency or "PHP").strip().upper() or "PHP"
    region = f"{country}/{currency}"
    log_fn = getattr(login_result, "_log_fn", None) or (lambda m: print(m, flush=True))
    plan_label = "Go" if "go" in str(plan_name).strip().lower() else "PRO"
    try:
        log_fn(f"[GPT PRO 升级 PRO] phase1: 在已登录 page 上发起 {plan_label} checkout ({region})...")
        res = page.run_js(_build_upgrade_pro_js(country, currency, plan_name=plan_name)) or {}
    except Exception as exc:
        return {"ok": False, "error": f"checkout JS 执行异常: {exc}"}

    if not isinstance(res, dict):
        return {"ok": False, "error": f"checkout JS 返回非 dict: {res!r}"}
    if not res.get("ok"):
        log_fn(f"[GPT PRO 升级 PRO] ❌ checkout 失败: {res}")
        return res

    sid = str(res.get("checkout_session_id") or "").strip()
    try:
        pay_url = _checkout_navigation_url(res, sid)
    except ValueError as exc:
        return {"ok": False, "stage": "checkout", "error": str(exc), "raw": res}
    log_fn(f"[GPT PRO 升级 PRO] ✅ checkout_session_id={sid},导航到 {pay_url}")
    # OpenAI 后端给 checkout_session 传播时间, 不然 React loader 拿 HTML 报 400 Invalid content type
    time.sleep(1.5)
    import json as _json
    try:
        page.run_js(f"window.location.href = {_json.dumps(pay_url)};")
        time.sleep(0.5)
    except Exception as exc:
        log_fn(f"[GPT PRO 升级 PRO] ⚠ 导航 JS 异常,尝试 page.get 兜底: {exc}")
        try:
            page.get(pay_url, timeout=_NAV_TIMEOUT)
        except Exception as exc2:
            log_fn(f"[GPT PRO 升级 PRO] ⚠ 导航 checkout 失败(URL 已返回): {exc2}")
            return {"ok": False, "stage": "checkout_navigation",
                    "error": "结账链接已创建，但浏览器未能打开付款页面",
                    "checkout_session_id": sid, "pay_url": pay_url}

    # ── dump_only 模式: 跳过 panel, 直接递归 dump iframe 树, 返回 ──
    if dump_only:
        log_fn("[GPT PRO 升级 PRO] dump_only=True, 递归 dump 所有 iframe...")
        time.sleep(4)
        dump_tree = _recursive_dump_iframes(page, log_fn, depth=0, max_depth=4)
        return {
            "ok": True,
            "checkout_session_id": sid,
            "pay_url": pay_url,
            "region": region,
            "dump_only": True,
            "iframe_tree": dump_tree,
        }

    # 注入卡选择 panel (不等选)
    panel_result = _inject_card_picker_panel(
        page,
        log_fn,
        card_loader=card_loader,
    )
    return {
        "ok": True,
        "checkout_session_id": sid,
        "pay_url": pay_url,
        "publishable_key": res.get("publishable_key", ""),
        "checkout_ui_mode": res.get("checkout_ui_mode", ""),
        "processor_entity": res.get("processor_entity", ""),
        "region": region,
        "card_picker": panel_result,
    }


def _attempt_subscribe(page, card: dict, stage, log_fn, *, redirect_timeout: int = 80) -> tuple:
    """对单张卡:填 Stripe iframe → 点订阅 → 等跳转。返回 (success, result_dict)。
    供 run_checkout_phase2 在失败换卡时循环调用。"""
    stage("filling_card")
    time.sleep(1.2)  # 给 country select / iframe re-mount 稳定时间
    stripe_result = _fill_stripe_iframes_with_card(page, card, log_fn)
    stripe_result["picked_card"] = {
        "id": card.get("id"),
        "label": card.get("label"),
        "number_masked": card.get("number_masked"),
    }

    # 卡要素(卡号/到期/CVC)或账单(国家/姓名/邮编)没就绪就别点订阅 —
    # 空/错表单点提交只会撞 Stripe 校验红字, 白白消耗一次尝试
    if not stripe_result.get("card_ok"):
        log_fn(f"[GPT PRO 订阅] ⚠ 卡要素未填全 (filled={stripe_result.get('filled')}), 跳过点击订阅, 判为本卡失败")
        return False, {"subscription_success": False, "stripe_fill": stripe_result,
                       "subscribe": {"clicked": False,
                                     "click_error": "card fields incomplete",
                                     "redirect": {"ok": False, "reason": "卡要素未填全, 未点订阅"}}}
    if not stripe_result.get("billing_ok", True):
        log_fn(f"[GPT PRO 订阅] ⚠ 账单未就绪 (国家/姓名/邮编不匹配, filled={stripe_result.get('filled')}), 跳过点击订阅, 判为本卡失败")
        return False, {"subscription_success": False, "stripe_fill": stripe_result,
                       "subscribe": {"clicked": False,
                                     "click_error": "billing incomplete",
                                     "redirect": {"ok": False, "reason": "账单未就绪, 未点订阅"}}}

    stage("clicking_subscribe")
    time.sleep(1.5)  # 等 Stripe validation,否则订阅按钮 disabled
    log_fn("[GPT PRO 订阅] 查找 + 点击订阅按钮...")
    try:
        click_res = page.run_js(_SUBSCRIBE_CLICK_JS)
    except Exception as exc:
        log_fn(f"[GPT PRO 订阅] ⚠ click JS 异常: {exc}")
        return False, {"subscription_success": False, "stripe_fill": stripe_result,
                       "subscribe": {"clicked": False, "click_error": str(exc),
                                     "redirect": {"ok": False, "reason": "click 失败"}}}
    if not isinstance(click_res, dict) or not click_res.get("ok"):
        log_fn(f"[GPT PRO 订阅] ⚠ 未点到订阅按钮: {click_res}")
        return False, {"subscription_success": False, "stripe_fill": stripe_result,
                       "subscribe": {"clicked": False,
                                     "click_error": (click_res or {}).get("error"),
                                     "redirect": {"ok": False, "reason": "click 失败"}}}
    log_fn(f"[GPT PRO 订阅] ✅ 已点击订阅按钮 ({click_res.get('button_text')!r}), 等待跳转...")
    time.sleep(2.0)

    stage("waiting_redirect")
    redirect = _wait_for_subscription_redirect(page, timeout=redirect_timeout, log_fn=log_fn)
    success = bool(redirect.get("ok"))
    if success:
        log_fn(f"[GPT PRO 订阅] 🎉 订阅成功! 最终落地 {redirect.get('final_url')}")
    else:
        log_fn(f"[GPT PRO 订阅] ⚠ 本张卡订阅未确认: {redirect.get('reason')} "
               f"(最后 URL: {redirect.get('final_url')})")
    return success, {
        "subscription_success": success,
        "stripe_fill": stripe_result,
        "subscribe": {"clicked": True, "button_text": click_res.get("button_text"),
                      "redirect": redirect},
    }


def _build_direct_card(card: dict) -> dict:
    """把外部传入的 {number, exp_month, exp_year, cvc[, holder_name]} 规范成填卡用完整 dict。

    账单地址硬覆盖为 _DEFAULT_BILLING_ADDRESS(与卡池卡一致), 调用方只需给卡号/到期/CVC。
    """
    number = "".join(ch for ch in str(card.get("number") or "") if ch.isdigit())
    return {
        "id": None,
        "label": "手动卡 " + (number[-4:] if len(number) >= 4 else number),
        "priority": 0,
        "number": number,
        "number_masked": ("**** **** **** " + number[-4:]) if len(number) >= 4 else number,
        "exp_month": int(card.get("exp_month") or 0),
        "exp_year": int(card.get("exp_year") or 0),
        "cvc": str(card.get("cvc") or ""),
        "holder_name": str(card.get("holder_name") or ""),
        "country": _DEFAULT_BILLING_ADDRESS["country"],
        "state": _DEFAULT_BILLING_ADDRESS["state"],
        "city": _DEFAULT_BILLING_ADDRESS["city"],
        "address_line1": _DEFAULT_BILLING_ADDRESS["address_line1"],
        "address_line2": _DEFAULT_BILLING_ADDRESS["address_line2"],
        "postal_code": _DEFAULT_BILLING_ADDRESS["postal_code"],
        "brand": "",
    }


def _subscribe_pro_confirm_only(page, country: str, currency: str, log_fn,
                                 *, stage_cb: Optional[Callable[[str], None]] = None,
                                 redirect_timeout: int = 90,
                                 pre_wait: int = 60,
                                 plan_name: str = "chatgptpro") -> dict:
    """菲律宾「先 Go 后 PRO」第二步: Go 已订阅成功、卡已在档,在同一 page 发起 PRO
    checkout(升级)并只点「订阅/确认」按钮(不再填卡),等跳转回 chatgpt.com。

    pre_wait: Go 订成后先等这么多秒(默认 60)再发 PRO checkout —— 等后端把
      Go 套餐 / 卡在档状态传播完, 否则 PRO 升级页可能就绪不了。

    返回 {ok, checkout_session_id?, pay_url?, button_text?, redirect?, reason?}
    """
    import json as _json

    def _stage(s: str) -> None:
        if callable(stage_cb):
            try:
                stage_cb(s)
            except Exception:
                pass

    # Go 订阅刚落地,plan/卡在档状态还在后端传播 → 先等 pre_wait 秒再发 PRO checkout
    pre_wait = max(0, int(pre_wait or 0))
    if pre_wait > 0:
        _stage("go_subscribed_wait")
        log_fn(f"[GPT PRO 升级 PRO] Go 已订阅,等待 {pre_wait}s 让后端传播套餐/卡在档状态,再升级 PRO...")
        time.sleep(pre_wait)
    _stage("creating_pro_checkout")
    try:
        res = page.run_js(_build_upgrade_pro_js(country, currency, plan_name=plan_name or "chatgptpro")) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"PRO checkout JS 异常: {exc}"}
    if not isinstance(res, dict) or not res.get("ok"):
        return {"ok": False, "reason": f"PRO checkout 创建失败: {res}"}

    sid = str(res.get("checkout_session_id") or "").strip()
    try:
        pay_url = _checkout_navigation_url(res, sid)
    except ValueError as exc:
        return {"ok": False, "reason": str(exc), "stage": "checkout",
                "raw": res}
    log_fn(f"[GPT PRO 升级 PRO] Go→PRO: PRO checkout_session_id={sid},导航到 {pay_url}")
    time.sleep(1.5)
    try:
        page.run_js(f"window.location.href = {_json.dumps(pay_url)};")
    except Exception as exc:
        log_fn(f"[GPT PRO 升级 PRO] ⚠ 导航 PRO checkout 异常,page.get 兜底: {exc}")
        try:
            page.get(pay_url, timeout=_NAV_TIMEOUT)
        except Exception:
            pass

    # 卡已在档 → 不填卡, 只等结账页把「订阅/确认」按钮渲染出来再点(轮询直到点到或超时)
    _stage("clicking_subscribe_pro")
    deadline = time.time() + 60
    clicked = None
    while time.time() < deadline:
        time.sleep(1.5)
        try:
            click_res = page.run_js(_SUBSCRIBE_CLICK_JS)
        except Exception as exc:
            log_fn(f"[GPT PRO 升级 PRO] ⚠ PRO 订阅 click JS 异常: {exc}")
            continue
        if isinstance(click_res, dict) and click_res.get("ok"):
            clicked = click_res
            log_fn(f"[GPT PRO 升级 PRO] ✅ 已点 PRO 订阅/确认按钮 ({click_res.get('button_text')!r})")
            break
    if not clicked:
        return {"ok": False,
                "reason": "PRO 结账页 60s 内未找到可点的订阅/确认按钮(卡可能未在档或页面未加载)",
                "checkout_session_id": sid, "pay_url": pay_url}

    _stage("waiting_pro_redirect")
    time.sleep(2.0)
    redirect = _wait_for_subscription_redirect(page, timeout=redirect_timeout, log_fn=log_fn)
    ok = bool(redirect.get("ok"))
    if ok:
        log_fn(f"[GPT PRO 升级 PRO] 🎉 Go→PRO 升级成功! 最终落地 {redirect.get('final_url')}")
    else:
        log_fn(f"[GPT PRO 升级 PRO] ⚠ Go 已订阅但 PRO 升级未确认跳转: {redirect.get('reason')}")
    return {
        "ok": ok,
        "checkout_session_id": sid,
        "pay_url": pay_url,
        "button_text": clicked.get("button_text"),
        "redirect": redirect,
        "reason": None if ok else redirect.get("reason"),
    }


def run_checkout_phase2(page, *, timeout: int = 300,
                         auto_pick_seconds: int = 0,
                         direct_card: Optional[dict] = None,
                         go_then_pro: bool = False,
                         pro_only: bool = False,
                         country: str = "PH", currency: str = "PHP",
                         go_to_pro_wait: int = 60,
                         pro_plan_name: str = "chatgptpro",
                         stage_cb: Optional[Callable[[str], None]] = None,
                         log_fn: Optional[Callable[[str], None]] = None,
                         card_loader=None) -> dict:
    """phase2 (供后台 thread 调用): 等选卡(timeout 秒) → 填 Stripe iframe → 点订阅 → 等订阅跳转。

    auto_pick_seconds>0: 等待该秒数后自动点第 1 张卡(全自动补号用); 0=纯人工。

    go_then_pro=True (菲律宾结账区): 选中的卡先订阅 Go 套餐, 成功后在同一 page 发起
      PRO checkout(升级, 卡已在档只点确认), 二者都成功才算 subscription_success。

    stage_cb(stage_str): 每进入新阶段时回调,用于异步任务暴露进度。
      阶段: awaiting_card_pick / filling_card / clicking_subscribe / waiting_redirect
            / creating_pro_checkout / clicking_subscribe_pro / waiting_pro_redirect
            / success / failed / pro_failed / timeout

    返回 {subscription_success, picked_card_id?, stripe_fill, subscribe, timeout?, pro_step?}
    """
    log_fn = log_fn or (lambda m: print(m, flush=True))

    def _stage(s: str) -> None:
        if callable(stage_cb):
            try:
                stage_cb(s)
            except Exception:
                pass

    def _maybe_pro_after_go(result: dict, ok: bool) -> tuple:
        """Go 订阅成功且 go_then_pro 时,继续跑 PRO 升级(卡在档只点确认)。
        返回 (result, overall_ok): overall_ok 以 PRO 步骤为准。"""
        if not (ok and go_then_pro):
            return result, ok
        result["go_subscription_success"] = True
        log_fn("[GPT PRO 升级 PRO] Go 套餐订阅成功,继续升级 PRO(卡已在档)...")
        pro = _subscribe_pro_confirm_only(page, country, currency, log_fn,
                                          stage_cb=stage_cb, pre_wait=go_to_pro_wait,
                                          plan_name=pro_plan_name)
        result["pro_step"] = pro
        pro_ok = bool(pro.get("ok"))
        result["subscription_success"] = pro_ok
        if not pro_ok:
            _stage("pro_failed")
        return result, pro_ok

    # pro_only: 账号已在 Go 套餐, 跳过订 Go / 跳过选卡, 只跑后半段(卡已在档只点确认)
    if pro_only:
        log_fn("[GPT PRO 升级 PRO] pro_only 模式: 账号已在 Go, 直接升级 PRO(不订 Go、不填卡)...")
        pro = _subscribe_pro_confirm_only(page, country, currency, log_fn,
                                          stage_cb=stage_cb, pre_wait=go_to_pro_wait,
                                          plan_name=pro_plan_name)
        return {
            "subscription_success": bool(pro.get("ok")),
            "pro_only": True,
            "pro_step": pro,
            "picked_card_id": None,
            "stripe_fill": {"skipped": True, "reason": "pro_only"},
            "subscribe": {"skipped": True, "reason": "pro_only",
                          "redirect": pro.get("redirect")},
        }

    # 手动指定银行卡: 跳过卡池/选卡面板, 直接填这张卡(点升级时粘贴的卡)
    if direct_card:
        full = _build_direct_card(direct_card)
        log_fn(f"[GPT PRO 升级 PRO] 使用手动指定银行卡直接填卡: {full.get('number_masked')} "
               f"{full.get('exp_month')}/{full.get('exp_year')}")
        _stage("filling_card")
        ok, last_result = _attempt_subscribe(page, full, _stage, log_fn)
        last_result = last_result or {}
        last_result, ok = _maybe_pro_after_go(last_result, ok)
        last_result["subscription_success"] = bool(ok)
        last_result["picked_card_id"] = None
        last_result["manual_card"] = True
        last_result["failed_card_ids"] = [] if ok else ["manual"]
        if not ok:
            _stage("failed")
        return last_result

    # 优先级顺序的卡列表(data-idx 与此一致),用于失败后自动换下一张
    load_cards = card_loader or _fetch_local_bank_cards
    all_cards = load_cards(log_fn)

    # phase1 注入的面板可能在 checkout 页 re-render 后被冲掉 → 选卡前确认/重注,带重试
    if not _panel_present(page):
        log_fn("[GPT PRO 升级 PRO] 选卡面板缺失(页面可能已 re-render),重新注入…")
        _inject_card_picker_panel(page, log_fn, card_loader=load_cards)

    _stage("awaiting_card_pick")
    picked = _wait_for_card_selection(
        page,
        timeout=timeout,
        auto_pick_after=int(auto_pick_seconds or 0),
        log_fn=log_fn,
        card_loader=load_cards,
    )
    if not picked:
        _stage("timeout")
        return {
            "subscription_success": False,
            "stripe_fill": {"skipped": True, "reason": "user_did_not_pick"},
            "subscribe": {"skipped": True, "reason": "no_card_picked"},
            "timeout": True,
        }

    # 从用户/自动选中的那张开始,按优先级依次尝试;失败则同页换下一张重填
    def _idx_of(cid) -> int:
        for i, c in enumerate(all_cards):
            if str(c.get("id")) == str(cid):
                return i
        return -1
    start = _idx_of(picked.get("id"))
    if start < 0:
        sequence = [(-1, picked)]            # picked 不在池里,只试它一张
    else:
        sequence = [(i, all_cards[i]) for i in range(start, len(all_cards))]

    failed_card_ids: list = []
    last_result: dict = {}
    for n, (idx, card) in enumerate(sequence):
        if n > 0:
            # 上一张失败 → 程序化点 panel 第 idx 张(会重填账单地址 + 重置 selected)
            _stage("filling_card")
            log_fn(f"[GPT PRO 订阅] 💳 支付失败,自动换下一张卡(优先级 {card.get('priority')}): "
                   f"{card.get('number_masked')}")
            try:
                page.run_js(
                    f"const it=document.querySelector('.gp-card-item[data-idx=\"{idx}\"]');"
                    "if(it){it.click(); return true;} return false;"
                )
            except Exception as exc:
                log_fn(f"[GPT PRO 订阅] ⚠ 切换下一张卡异常: {exc}")
            time.sleep(1.5)

        ok, last_result = _attempt_subscribe(page, card, _stage, log_fn)
        last_result, ok = _maybe_pro_after_go(last_result, ok)
        if ok:
            last_result["picked_card_id"] = card.get("id")
            last_result["failed_card_ids"] = failed_card_ids
            return last_result
        # Go 已订成但 PRO 升级失败: 卡已扣款/账号已在 Go, 绝不能换卡重订 Go(会重复扣款)
        if last_result.get("go_subscription_success"):
            last_result["picked_card_id"] = card.get("id")
            last_result["failed_card_ids"] = failed_card_ids
            last_result["go_but_pro_failed"] = True
            log_fn("[GPT PRO 升级 PRO] ✗ Go 已订阅但 PRO 升级失败,停止换卡(避免重复扣款),浏览器留窗人工处理")
            return last_result
        if card.get("id") is not None:
            failed_card_ids.append(card.get("id"))

    # 全部尝试过仍失败
    _stage("failed")
    last_result["subscription_success"] = False
    last_result["picked_card_id"] = sequence[-1][1].get("id") if sequence else picked.get("id")
    last_result["failed_card_ids"] = failed_card_ids
    last_result["all_cards_exhausted"] = True
    log_fn(f"[GPT PRO 订阅] ✗ 已尝试 {len(sequence)} 张卡均支付失败")
    return last_result


def open_pro_checkout_in_page(page, login_result: "GptProLoginResult",
                              *, dump_only: bool = False) -> dict:
    """旧的一站式同步流程 (phase1 + phase2 串行)。

    保留供旧调用方使用; 新的异步任务模型应直接调 open_pro_checkout_phase1 +
    run_checkout_phase2。
    """
    phase1 = open_pro_checkout_phase1(page, login_result, dump_only=dump_only)
    if not phase1.get("ok") or dump_only:
        return phase1
    panel_result = phase1.get("card_picker") or {}
    if not (panel_result.get("ok") and panel_result.get("cards_count", 0) > 0):
        # 没卡可填,跑到注入 panel 就停
        phase1.update({
            "stripe_fill": {"skipped": True, "reason": "no_local_cards"},
            "subscribe": {"skipped": True, "reason": "no_local_cards"},
            "subscription_success": False,
        })
        return phase1
    phase2 = run_checkout_phase2(page, timeout=60)
    phase1.update(phase2)
    return phase1


def _fetch_local_bank_cards(log_fn) -> list[dict]:
    """从本地后端拉所有 enabled+unused 的卡,序列化为 JS 注入用的数组。"""
    try:
        from sqlmodel import Session, select
        from core.db import CardModel, engine
        # 每张卡最多成功购买次数 (达到则不再选), 可配 gpt_pro_card_max_uses, 默认 6
        try:
            from core.config_store import config_store as _cs
            max_uses = int(str(_cs.get("gpt_pro_card_max_uses", "") or 6) or 6)
        except Exception:
            max_uses = 6
        cards: list[dict] = []
        with Session(engine) as s:
            # 被停用的支付账号(其下 U卡 不参与升级填卡)
            disabled_pa_ids: set = set()
            try:
                from core.db import PaymentAccountModel
                disabled_pa_ids = {
                    int(p.id) for p in s.exec(
                        select(PaymentAccountModel).where(PaymentAccountModel.enabled == False)  # noqa: E712
                    ).all()
                }
            except Exception:
                disabled_pa_ids = set()
            rows = s.exec(
                select(CardModel)
                .where(CardModel.enabled == True)  # noqa: E712
                # 优先级数字越小越先用(自动选卡按此顺序),同优先级按 id 倒序
                .order_by(CardModel.priority.asc(), CardModel.id.desc())
            ).all()
            for c in rows:
                # 所属支付账号被停用 → 跳过
                if int(getattr(c, "payment_account_id", 0) or 0) in disabled_pa_ids:
                    continue
                # 可被升级 PRO 使用的卡:
                #   - status ∈ {unused, ""}: 还没用过 → 可用
                #   - status == "used" 且 single_use == False: 复用型 → 仍可用
                #   - failed(失败已关) / in_use / used+single_use / disabled → 不显示
                #   - use_count >= max_uses(已用满)→ 不显示
                if (getattr(c, "use_count", 0) or 0) >= max_uses:
                    continue
                if c.status not in ("unused", ""):
                    if not (c.status == "used" and not c.single_use):
                        continue
                # 账单地址硬覆盖为 _DEFAULT_BILLING_ADDRESS (免税州 Oregon Salem),
                # 卡里的 country/state/city/postal_code/address_line* 字段被忽略。
                # 这样卡导入时不用填地址,只填卡号/CVC/到期/持卡人即可。
                cards.append({
                    "id": c.id,
                    "label": c.label or "",
                    "priority": getattr(c, "priority", 100) or 100,
                    "number": c.number or "",                  # 完整, 给 Stripe iframe 填
                    "number_masked": c.masked(),
                    "exp_month": c.exp_month,
                    "exp_year": c.exp_year,
                    "cvc": c.cvc or "",
                    "holder_name": c.holder_name or "",
                    "country": _DEFAULT_BILLING_ADDRESS["country"],
                    "state": _DEFAULT_BILLING_ADDRESS["state"],
                    "city": _DEFAULT_BILLING_ADDRESS["city"],
                    "address_line1": _DEFAULT_BILLING_ADDRESS["address_line1"],
                    "address_line2": _DEFAULT_BILLING_ADDRESS["address_line2"],
                    "postal_code": _DEFAULT_BILLING_ADDRESS["postal_code"],
                    "brand": "",                               # 留给未来扩展
                })
        log_fn(f"[GPT PRO 升级 PRO] 注入卡选择 panel: 拉到 {len(cards)} 张可用卡")
        return cards
    except Exception as exc:
        log_fn(f"[GPT PRO 升级 PRO] ⚠ 拉本地卡列表异常: {exc}")
        return []


_MAIN_PAGE_INPUT_DUMP_JS = """
return (function(){
    function meta(el) {
        return {
            tag: el.tagName.toLowerCase(),
            type: el.type || '',
            name: el.name || '',
            ac: el.autocomplete || '',
            id: el.id || '',
            aria: el.getAttribute('aria-label') || '',
            placeholder: el.placeholder || '',
            label: (function(){
                if (el.id) {
                    const l = document.querySelector('label[for="'+el.id+'"]');
                    if (l) return (l.textContent || '').trim().slice(0,40);
                }
                const closest = el.closest('label');
                if (closest) return (closest.textContent || '').trim().slice(0,40);
                return '';
            })(),
        };
    }
    const inputs = Array.from(document.querySelectorAll('input'))
        .filter(el => el.offsetParent || getComputedStyle(el).visibility !== 'hidden');
    const selects = Array.from(document.querySelectorAll('select'))
        .filter(el => el.offsetParent || getComputedStyle(el).visibility !== 'hidden');
    return {
        url: location.href.slice(0, 100),
        inputs_count: inputs.length,
        selects_count: selects.length,
        inputs: inputs.slice(0, 30).map(meta),
        selects: selects.slice(0, 10).map(meta),
    };
})();
"""


def _panel_present(page) -> bool:
    try:
        return bool(page.run_js("return !!document.getElementById('gp-card-panel');"))
    except Exception:
        return False


def _inject_card_picker_panel(
    page,
    log_fn,
    *,
    max_attempts: int = 6,
    card_loader=None,
) -> dict:
    """checkout 页跳转完成后注入卡选择浮动 panel。

    checkout 页常在加载/re-render,DrissionPage 注入时可能抛"页面被刷新"或注入后被冲掉,
    故重试到面板元素真正挂上为止。返回 {ok, cards_count, error?}.
    """
    cards = (card_loader or _fetch_local_bank_cards)(log_fn)
    import json as _json
    # 注入前先重置标记 + 移除旧面板,保证 re-render 后能重新创建(模板有 __GPT_PRO_PANEL_INJECTED__ 守卫)
    reset = ("try{window.__GPT_PRO_PANEL_INJECTED__=false;"
             "const o=document.getElementById('gp-card-panel');if(o)o.remove();}catch(e){}\n")
    js = reset + (
        _CARD_PANEL_JS_TEMPLATE
        .replace("__CARDS_JSON__", _json.dumps(cards))
        .replace("__CARD_COUNT__", str(len(cards)))
    )
    dump = None
    last_err = ""
    for attempt in range(1, max_attempts + 1):
        time.sleep(2.0)  # 给 checkout 页 loader/React 渲染时间
        try:
            page.run_js(js)
            if _panel_present(page):
                log_fn(f"[GPT PRO 升级 PRO] ✅ 卡选择 panel 已注入 ({len(cards)} 张, 第 {attempt} 次)")
                try:
                    dump = page.run_js(_MAIN_PAGE_INPUT_DUMP_JS)
                except Exception:
                    dump = None
                return {"ok": True, "cards_count": len(cards), "input_dump": dump}
            last_err = "注入后未找到面板元素(页面可能正在 re-render)"
        except Exception as exc:
            last_err = str(exc) or "page refreshed"
        log_fn(f"[GPT PRO 升级 PRO] ⚠ panel 注入第 {attempt}/{max_attempts} 次未成({last_err[:50]}),重试…")
    return {"ok": False, "cards_count": len(cards), "error": last_err, "input_dump": dump}


# ── Phase 2: Stripe iframe 内填 卡号 / 到期 / CVC ──
#
# Stripe Payment Element 把卡号 / 到期 / CVC 渲染在 <iframe name="__privateStripeFrame*">
# 里, 跨域, 主 frame 的 JS 写不进去。DrissionPage 通过 CDP 拿到所有 frame 对象后,
# 在每个 iframe 的 JS 环境里跑下面这段: 自动检测当前 iframe 持有哪个字段 (按 input
# 的 data-elements-stable-field-name / autocomplete / aria-label 联合判断), 填对应值。
#
# 写入用 nativeInputValueSetter + _valueTracker reset + 逐字符 keydown/input/keyup,
# 让 React/Stripe 把它当真实键盘输入处理(否则 Stripe 会校验失败)。
_STRIPE_IFRAME_FILL_JS_TEMPLATE = """
return (function(card, passKinds){
    // passKinds: kind 白名单数组 (例如 ['country']), 只填这些 kind 的字段; null = 全填
    const allowSet = passKinds ? new Set(passKinds) : null;
    const allInputs = document.querySelectorAll('input');
    const allIframes = document.querySelectorAll('iframe');
    const out = {
        url: (location.href || '').slice(0, 120),
        pass_kinds: passKinds || 'all',
        inputs_count: allInputs.length,
        iframes_in_this_frame: allIframes.length,
        handled: [],
        skipped: 0,
        inputs_meta: []
    };
    function fill(input, value) {
        if (!value) return false;
        const setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value').set;
        const tracker = input._valueTracker;

        // 1) 清空已有值 (focus → Ctrl+A → Backspace + 直接清)
        input.focus();
        input.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
        if (input.value) {
            input.dispatchEvent(new KeyboardEvent('keydown',
                {key:'a', code:'KeyA', ctrlKey:true, bubbles:true}));
            if (input.select) input.select();
            input.dispatchEvent(new KeyboardEvent('keydown',
                {key:'Backspace', code:'Backspace', keyCode:8, bubbles:true}));
            if (tracker) tracker.setValue('x');
            setter.call(input, '');
            input.dispatchEvent(new InputEvent('input',
                {data:'', inputType:'deleteContentBackward', bubbles:true}));
            input.dispatchEvent(new Event('change', {bubbles:true}));
        }

        // 2) 逐字符敲入
        for (const ch of String(value)) {
            input.dispatchEvent(new KeyboardEvent('keydown', {
                key: ch, code: 'Key' + ch.toUpperCase(),
                charCode: ch.charCodeAt(0), keyCode: ch.charCodeAt(0),
                which: ch.charCodeAt(0), bubbles: true, cancelable: true
            }));
            input.dispatchEvent(new KeyboardEvent('keypress', {
                key: ch, charCode: ch.charCodeAt(0),
                keyCode: ch.charCodeAt(0), which: ch.charCodeAt(0),
                bubbles: true, cancelable: true
            }));
            const next = input.value + ch;
            if (tracker) tracker.setValue(input.value);
            setter.call(input, next);
            input.dispatchEvent(new InputEvent('input', {
                data: ch, inputType: 'insertText', bubbles: true, cancelable: true
            }));
            input.dispatchEvent(new KeyboardEvent('keyup', {
                key: ch, bubbles: true, cancelable: true
            }));
        }

        // 3) blur 触发验证
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        return input.value && input.value.length > 0;
    }

    function classify(input) {
        const name = (input.getAttribute('name') || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const ac = (input.getAttribute('autocomplete') || '').toLowerCase();
        const aria = (input.getAttribute('aria-label') || '').toLowerCase();
        const ph = (input.getAttribute('placeholder') || '').toLowerCase();
        const stable = (input.getAttribute('data-elements-stable-field-name') || '').toLowerCase();
        const attrs = [name, id, ac, aria, ph, stable].join(' ');
        // 卡相关 (第 1 pass 填)
        if (attrs.includes('cardnumber') || attrs.includes('cc-number') ||
            name === 'number' || id.includes('numberinput') ||
            attrs.includes('card number') || attrs.includes('卡号')) return 'number';
        if (attrs.includes('cardexpiry') || attrs.includes('cc-exp') ||
            name === 'expiry' || id.includes('expiryinput') ||
            attrs.includes('expir') || attrs.includes('有效期') ||
            attrs.includes('到期')) return 'expiry';
        if (attrs.includes('cardcvc') || attrs.includes('cc-csc') ||
            name === 'cvc' || id.includes('cvcinput') ||
            attrs.includes('cvv') || attrs.includes('security') ||
            attrs.includes('安全码')) return 'cvc';
        // 账单相关 (第 2 pass 填, 卡号填完 Stripe BIN 检测后才动态出现)
        if (attrs.includes('billingname') || attrs.includes('cc-name') ||
            name === 'name' || id.includes('nameinput') ||
            attrs.includes('holder') || attrs.includes('持卡人') ||
            attrs.includes('姓名') || ac === 'name') return 'holder';
        if (attrs.includes('billingcountry') || attrs.includes('country') ||
            name === 'country' || id.includes('countryinput') ||
            attrs.includes('国家')) return 'country';
        if (attrs.includes('billingadministrativearea') ||
            name === 'state' || name === 'administrativearea' ||
            attrs.includes('address-level1') ||
            attrs.includes('province') || attrs.includes('州') ||
            attrs.includes('省')) return 'state';
        if (attrs.includes('billinglocality') || name === 'locality' ||
            name === 'city' || attrs.includes('address-level2') ||
            attrs.includes('城市')) return 'city';
        if (attrs.includes('billingaddressline1') || name === 'addressline1' ||
            name === 'line1' || id.includes('line1') ||
            attrs.includes('address-line1') ||
            attrs.includes('address1') ||
            attrs.includes('街道') || attrs.includes('地址')) return 'address1';
        if (attrs.includes('billingaddressline2') || name === 'addressline2' ||
            name === 'line2' || id.includes('line2') ||
            attrs.includes('address-line2') ||
            attrs.includes('address2')) return 'address2';
        if (attrs.includes('billingpostalcode') || attrs.includes('postal') ||
            attrs.includes('postcode') || name === 'postalcode' ||
            name === 'zip' || attrs.includes('postal-code') ||
            attrs.includes('邮编') || attrs.includes('zip')) return 'postal';
        if (name === 'network' || id.includes('networkinput') ||
            aria.includes('卡组织') || aria.includes('card network')) return 'network';
        return null;
    }

    function valueFor(kind) {
        if (kind === 'number') return String(card.number || '').replace(/\\s+/g, '');
        if (kind === 'expiry') {
            const mm = String(card.exp_month || '').padStart(2, '0');
            const yy = String(card.exp_year || '').slice(-2);
            return mm + yy;
        }
        if (kind === 'cvc') return String(card.cvc || '');
        if (kind === 'holder') return String(card.holder_name || '');
        if (kind === 'country') return String(card.country || '');
        if (kind === 'state') return String(card.state || '');
        if (kind === 'city') return String(card.city || '');
        if (kind === 'address1') return String(card.address_line1 || '');
        if (kind === 'address2') return String(card.address_line2 || '');
        if (kind === 'postal') return String(card.postal_code || '');
        return '';
    }

    function fillSelect(el, value) {
        if (!value) return false;
        const want = value.toLowerCase();
        for (const opt of el.options) {
            if (opt.value === value || opt.value.toLowerCase() === want ||
                opt.textContent.toLowerCase().includes(want) ||
                want.includes(opt.textContent.toLowerCase().trim())) {
                // 已经选中目标值 → 不重复派发 change, 避免无谓 React re-render / re-mount
                if (el.value === opt.value) return 'noop';
                el.value = opt.value;
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
            }
        }
        return false;
    }

    const selects = document.querySelectorAll('select');
    const all = [
        ...Array.from(allInputs).map(el => ({el, tag: 'input'})),
        ...Array.from(selects).map(el => ({el, tag: 'select'})),
    ];
    out.selects_count = selects.length;
    for (const item of all) {
        const inp = item.el;
        const attrs = {
            tag: item.tag,
            type: inp.type || '',
            name: inp.name || '',
            ac: inp.autocomplete || '',
            stable: inp.getAttribute('data-elements-stable-field-name') || '',
            aria: inp.getAttribute('aria-label') || '',
            placeholder: inp.placeholder || '',
            id: inp.id || ''
        };
        if (out.inputs_meta.length < 20) out.inputs_meta.push(attrs);
        const kind = classify(inp);
        if (!kind) { out.skipped++; continue; }
        if (allowSet && !allowSet.has(kind)) { out.skipped++; continue; }
        const value = valueFor(kind);
        if (!value) { out.skipped++; continue; }
        const ok = item.tag === 'select' ? fillSelect(inp, value) : fill(inp, value);
        out.handled.push({ kind, ok, len: value.length, tag: item.tag });
    }
    return out;
})(__CARD_JSON__, __PASS_KINDS_JSON__);
"""


def _wait_for_card_selection(page, *, timeout: int = 60, auto_pick_after: int = 8,
                              poll_interval: float = 1.0,
                              log_fn=None,
                              card_loader=None) -> Optional[dict]:
    """轮询 window.__GPT_PRO_SELECTED_CARD__ 直到用户在 panel 上点了一张卡;
    用户 auto_pick_after 秒内没点的话, 自动点 panel 的第 0 张卡 (用 JS 模拟点击,
    会触发同样的主页面填表 + 设置 selected card)。

    timeout: 总超时秒数 (含自动点击后的等待)
    auto_pick_after: 多少秒后自动点第 0 张 (None / 0 = 永远不自动点)
    """
    log_fn = log_fn or (lambda m: print(m, flush=True))
    log_fn(
        f"[GPT PRO 升级 PRO] 等待 panel 选卡 "
        f"(手动 {auto_pick_after}s, 超时自动点第 1 张, 总 {timeout}s)..."
    )
    start = time.time()
    deadline = start + timeout
    auto_clicked = False
    poll_errors = 0
    while time.time() < deadline:
        try:
            picked = page.run_js("return window.__GPT_PRO_SELECTED_CARD__ || null;")
            poll_errors = 0
        except Exception as exc:
            # 页面刷新/导航会让 run_js 短暂失败 → 不致命,稍后重试(此前是直接返回 None 放弃)
            poll_errors += 1
            if poll_errors <= 3 or poll_errors % 5 == 0:
                log_fn(f"[GPT PRO 升级 PRO] 轮询 selected card 异常(第 {poll_errors} 次,继续等): {exc}")
            time.sleep(poll_interval)
            continue
        if isinstance(picked, dict) and picked.get("number"):
            tag = "用户手动" if not auto_clicked else "自动"
            log_fn(
                f"[GPT PRO 升级 PRO] ✅ {tag}选卡: "
                f"{picked.get('label') or picked.get('number_masked', '')}"
            )
            return picked
        # 面板没了(页面 re-render 冲掉)→ 重新注入,否则自动点击无元素可点
        if not _panel_present(page):
            log_fn("[GPT PRO 升级 PRO] 选卡面板丢失,重新注入…")
            _inject_card_picker_panel(
                page,
                log_fn,
                card_loader=card_loader,
            )
            auto_clicked = False  # 重注后允许重新自动点
        # 到了 auto_pick_after 还没人点 → JS 模拟点 panel 第一张(优先级最高)
        if (not auto_clicked
                and auto_pick_after
                and (time.time() - start) >= auto_pick_after):
            try:
                clicked = page.run_js(
                    'const item = document.querySelector(\'.gp-card-item[data-idx="0"]\');'
                    'if (item) { item.click(); return true; } return false;'
                )
                if clicked:
                    auto_clicked = True
                    log_fn("[GPT PRO 升级 PRO] 用户未操作,自动按优先级点第 1 张卡")
            except Exception as exc:
                log_fn(f"[GPT PRO 升级 PRO] 自动点击异常: {exc}")
        time.sleep(poll_interval)
    log_fn("[GPT PRO 升级 PRO] ⚠ 等待 panel 选卡超时,跳过 Stripe iframe 自动填卡")
    return None


def _enumerate_stripe_iframes(page, log_fn):
    """拿到 checkout 页内所有 Stripe iframe 对象。

    DrissionPage 几个候选 API 顺序尝试:
      page.get_frames(loc)
      page.iframes()
      page.eles('css:iframe')  → 再 .frame
    优先匹配 `__privateStripeFrame*` 命名,匹不到时退化为全部 iframe。
    """
    candidates = []
    try:
        # DrissionPage 4.x: get_frames(loc)
        candidates = list(page.get_frames(
            'css:iframe[name^="__privateStripeFrame"]'
        ))
    except Exception:
        candidates = []
    if not candidates:
        try:
            candidates = list(page.get_frames('css:iframe[src*="stripe"]'))
        except Exception:
            candidates = []
    if not candidates:
        try:
            candidates = list(page.get_frames('css:iframe'))
        except Exception:
            candidates = []
    log_fn(f"[GPT PRO 升级 PRO] 检测到 {len(candidates)} 个 iframe (含 Stripe)")
    return candidates


_SUBSCRIBE_CLICK_JS = """
return (function(){
    // 复用 AI填卡助手 v1.4.1 的订阅按钮定位逻辑
    function findSubscribeButton() {
        const sels = [
            'button[aria-label="订阅"]',
            'button[aria-label="Subscribe"]',
            'button.btn-primary[type="submit"]',
            'button[type="submit"][form]',
            'button[data-testid="hosted-payment-submit-button"]',
            'button[aria-label*="Purchase ChatGPT"]',
            'button[aria-label*="Subscribe"]'
        ];
        for (const s of sels) {
            const b = document.querySelector(s);
            if (b && !b.disabled) return b;
        }
        // 文本兜底
        const buttons = document.querySelectorAll('button');
        for (const b of buttons) {
            if (b.disabled) continue;
            const t = ((b.innerText || b.textContent || '') + '').trim().toLowerCase();
            if (t.includes('subscribe') || t.includes('订阅') ||
                t.includes('purchase')) {
                return b;
            }
        }
        return null;
    }
    const btn = findSubscribeButton();
    if (!btn) {
        return {ok: false, error: '未找到订阅按钮'};
    }
    btn.scrollIntoView({block: 'center'});
    btn.click();
    return {ok: true, button_text: ((btn.innerText || btn.textContent || '') + '').trim().slice(0, 40)};
})();
"""


def _wait_for_subscription_redirect(page, *, timeout: int = 90,
                                     log_fn=None) -> dict:
    """点订阅后等浏览器跳转。

    判定订阅成功的条件:
      - URL 以 https://chatgpt.com/ 开头
      - 且 URL **不再** 包含 /checkout/ 子路径
      - (e.g., 跳到 chatgpt.com/, chatgpt.com/?upgraded=true, chatgpt.com/settings 等都 ok)

    返回: {ok, final_url, elapsed_seconds, reason?}
    """
    log_fn = log_fn or (lambda m: print(m, flush=True))
    start = time.time()
    deadline = start + timeout
    last_url = ""
    while time.time() < deadline:
        try:
            url = page.url or ""
        except Exception as exc:
            return {"ok": False, "final_url": last_url,
                    "reason": f"page.url 异常: {exc}",
                    "elapsed_seconds": int(time.time() - start)}
        if url != last_url:
            log_fn(f"[GPT PRO 订阅] URL 变化: {url}")
            last_url = url
        # 成功判定
        if (url.startswith("https://chatgpt.com/")
                and "/checkout/" not in url):
            return {
                "ok": True,
                "final_url": url,
                "elapsed_seconds": int(time.time() - start),
            }
        time.sleep(0.6)
    return {
        "ok": False,
        "final_url": last_url,
        "reason": f"等待 {timeout}s 未跳转到 chatgpt.com/ (非 /checkout)",
        "elapsed_seconds": int(time.time() - start),
    }


# 探测某个 iframe 内是否已挂载卡号输入框(Stripe Payment Element 渲染完成的标志)
_STRIPE_CARD_PROBE_JS = r"""
return (function(){
    const sel = 'input[name="number"], input#payment-numberInput, '
        + 'input[autocomplete="cc-number"], input[data-elements-stable-field-name="cardNumber"]';
    const el = document.querySelector(sel);
    return { hasCard: !!(el && el.offsetParent !== null) };
})();
"""


def _wait_for_stripe_card_iframe(page, log_fn, *, timeout: float = 20.0) -> bool:
    """轮询等待"含卡号输入框的 Stripe iframe"真正挂载完成。

    修复: 日本区等慢代理下, pass1 执行时 iframe 常常还没渲染(日志"检测到 0 个 iframe"),
    卡号只有 pass1 一次填写机会 → 错过就再也不填。改为先等卡号框出现再开填。
    返回 True=已就绪; False=超时(仍继续尝试填, 交给后续补填兜底)。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        frames = _enumerate_stripe_iframes(page, log_fn)
        for frame in frames:
            try:
                res = frame.run_js(_STRIPE_CARD_PROBE_JS)
            except Exception:
                continue
            if isinstance(res, dict) and res.get("hasCard"):
                log_fn("[GPT PRO 升级 PRO] ✅ 卡号输入框已就绪, 开始填卡")
                return True
        time.sleep(0.8)
    log_fn(f"[GPT PRO 升级 PRO] ⚠ 等 {int(timeout)}s 仍未探测到卡号输入框, 仍尝试填卡")
    return False


# 跨 iframe 读取账单 country 下拉框的当前值(校验是否真的设成了目标国;
# 代理出口在别国时 Stripe 常按 IP 把 country 重置回当地 → US 地址与之不匹配)。
_STRIPE_COUNTRY_VALUE_JS = r"""
return (function(){
    const sels = document.querySelectorAll('select');
    for (const s of sels) {
        const n = (s.name||'').toLowerCase();
        const id = (s.id||'').toLowerCase();
        const stable = (s.getAttribute('data-elements-stable-field-name')||'').toLowerCase();
        if (n.includes('country') || id.includes('country') || stable.includes('country'))
            return {found:true, value: s.value || ''};
    }
    return {found:false, value:''};
})();
"""


def _verify_stripe_country(page, want, log_fn) -> bool:
    """检查账单 country 下拉框当前值是否 == 目标国(want, 如 'US')。
    找不到 country 下拉框时返回 True(不阻断, 可能是不收 country 的布局)。
    """
    if not want:
        return True
    want_up = str(want).strip().upper()
    for frame in _enumerate_stripe_iframes(page, log_fn):
        try:
            r = frame.run_js(_STRIPE_COUNTRY_VALUE_JS)
        except Exception:
            continue
        if isinstance(r, dict) and r.get("found"):
            cur = str(r.get("value") or "").strip().upper()
            return cur == want_up
    return True


def _fill_stripe_iframes_with_card(page, card: dict, log_fn) -> dict:
    """3 遍 pass:
       pass1 卡号/到期/CVC        (Stripe BIN 检测触发账单字段挂载)
       sleep 2.5s
       pass2 country              (单独改 country, Stripe 会 re-mount 账单子表单)
       sleep 1.5s
       pass3 holder/address/city/state/postal/address2  (在 re-mount 后的字段上填)

    为什么不把 country 放最后?  Stripe Payment Element 在 country 变化时会
    unmount → remount **整个账单子表单**, 导致已填的 city/postal/state/address1
    被 React 清空。把 country 单独提到中间, 等 re-mount 完成再填其余字段。
    """
    import json as _json
    # holder_name 为空 → Stripe 账单「Full name」必填校验会报 "Please provide your full name",
    # 且值为空时填卡逻辑直接 skip 该字段。手动卡常不带持卡人名, 这里兜底生成一个。
    if not str(card.get("holder_name") or "").strip():
        card = dict(card)
        card["holder_name"] = _gen_random_name()
        log_fn(f"[GPT PRO 升级 PRO] 持卡人姓名为空, 自动生成: {card['holder_name']}")
    card_json = _json.dumps(card)

    def _make_js(pass_kinds: Optional[list]) -> str:
        return (
            _STRIPE_IFRAME_FILL_JS_TEMPLATE
            .replace("__CARD_JSON__", card_json)
            .replace("__PASS_KINDS_JSON__",
                     _json.dumps(pass_kinds) if pass_kinds else "null")
        )

    def _run_one_pass(pass_label: str, pass_kinds: Optional[list]) -> dict:
        js = _make_js(pass_kinds)
        frames = _enumerate_stripe_iframes(page, log_fn)
        pass_sum = {"frames_total": len(frames), "frames_handled": 0,
                    "filled": {}, "errors": []}
        for i, frame in enumerate(frames):
            try:
                res = frame.run_js(js)
            except Exception as exc:
                pass_sum["errors"].append({"i": i, "error": str(exc)})
                log_fn(f"  [{pass_label}] iframe#{i} ⚠ run_js 异常: {exc}")
                continue
            if not isinstance(res, dict):
                log_fn(f"  [{pass_label}] iframe#{i} ⚠ 返回非 dict: {res!r}")
                continue
            for h in (res.get("handled") or []):
                kind = h.get("kind")
                # ok 可以是 True / 'noop' / False / '' — 真值都算填上 (noop = 已经对了)
                if kind and h.get("ok"):
                    pass_sum["filled"][kind] = pass_sum["filled"].get(kind, 0) + 1
            if res.get("handled"):
                pass_sum["frames_handled"] += 1
            handled_str = res.get("handled") or "none"
            skipped = res.get("skipped", 0)
            inputs_count = res.get("inputs_count", 0)
            selects_count = res.get("selects_count", 0)
            log_fn(
                f"  [{pass_label}] iframe#{i} url={(res.get('url') or '')[:80]} "
                f"inputs={inputs_count} selects={selects_count} "
                f"handled={handled_str} skipped={skipped}"
            )
            # 只在 handled 为空时把 inputs_meta 打出来, 避免日志过长
            if not res.get("handled"):
                meta = res.get("inputs_meta") or []
                for m in meta[:8]:
                    log_fn(f"    [{pass_label}] iframe#{i} META {m}")
        return pass_sum

    # ── pass1: 填 卡号/到期/CVC ──
    # 先等含卡号框的 Stripe iframe 挂载完成(慢代理下 pass1 常撞上 0 个 iframe)
    _wait_for_stripe_card_iframe(page, log_fn, timeout=20.0)
    log_fn("[GPT PRO 升级 PRO] === pass1: 填卡号/到期/CVC ===")
    pass1 = _run_one_pass("pass1", ["number", "expiry", "cvc"])

    # ── 等待 Stripe BIN 识别 + 账单字段动态挂载 ──
    log_fn("[GPT PRO 升级 PRO] 等待 2.5s 让 Stripe 根据 BIN 渲染账单字段...")
    time.sleep(2.5)

    # ── pass2: 只填 country (会触发账单子表单 re-mount) ──
    log_fn("[GPT PRO 升级 PRO] === pass2: 只填 country (触发账单 re-mount) ===")
    pass2 = _run_one_pass("pass2", ["country"])

    # ── 等账单字段在新 country 下 re-mount 完成 ──
    log_fn("[GPT PRO 升级 PRO] 等待 1.5s 让 Stripe 在新 country 下 re-mount 账单字段...")
    time.sleep(1.5)

    # ── pass3: 填其余账单字段 (re-mount 后这些字段值不会再被清空) ──
    log_fn("[GPT PRO 升级 PRO] === pass3: 填账单字段 (姓名/地址/城市/州/邮编) ===")
    pass3 = _run_one_pass(
        "pass3",
        ["holder", "address1", "address2", "city", "state", "postal"],
    )

    # ── 合并 ──
    all_kinds = set(pass1["filled"]) | set(pass2["filled"]) | set(pass3["filled"])
    merged_filled = {
        k: max(pass1["filled"].get(k, 0), pass2["filled"].get(k, 0),
                pass3["filled"].get(k, 0))
        for k in all_kinds
    }

    # ── 卡号/到期/CVC 是支付必填三要素; 若 pass1 撞上 iframe 未挂载而漏填, 补填最多 2 轮 ──
    ESSENTIAL = ("number", "expiry", "cvc")
    supplement_rounds = 0
    for _ in range(2):
        missing = [k for k in ESSENTIAL if not merged_filled.get(k)]
        if not missing:
            break
        supplement_rounds += 1
        log_fn(f"[GPT PRO 升级 PRO] ⚠ 卡要素缺失 {missing}, 补填第 {supplement_rounds} 轮…")
        _wait_for_stripe_card_iframe(page, log_fn, timeout=12.0)
        supp = _run_one_pass(f"supp{supplement_rounds}", list(ESSENTIAL))
        for k, v in supp["filled"].items():
            merged_filled[k] = max(merged_filled.get(k, 0), v)

    card_ok = all(merged_filled.get(k) for k in ESSENTIAL)

    # ── 账单地址校验: country 常被 Stripe 按代理 IP 重置成当地(如澳洲), 导致 US 地址/邮编/州
    #    不匹配报错。检测 country 实际值; 不对或姓名/邮编缺失 → 重设 country + 重填地址, 最多 2 轮 ──
    want_country = str(card.get("country") or "").strip()
    BILLING = ("holder", "postal")
    billing_rounds = 0
    for _ in range(2):
        country_ok = _verify_stripe_country(page, want_country, log_fn)
        missing_b = [k for k in BILLING if not merged_filled.get(k)]
        if country_ok and not missing_b:
            break
        billing_rounds += 1
        log_fn(f"[GPT PRO 升级 PRO] ⚠ 账单未就绪 (country_ok={country_ok} 缺={missing_b}), "
               f"重设国家+重填地址 第 {billing_rounds} 轮…")
        _run_one_pass(f"bill_country{billing_rounds}", ["country"])
        time.sleep(1.5)  # 等 country 变化触发的账单子表单 re-mount
        b = _run_one_pass(
            f"bill_addr{billing_rounds}",
            ["holder", "address1", "address2", "city", "state", "postal"],
        )
        for k, v in b["filled"].items():
            merged_filled[k] = max(merged_filled.get(k, 0), v)

    billing_ok = (_verify_stripe_country(page, want_country, log_fn)
                  and all(merged_filled.get(k) for k in BILLING))

    summary = {
        "frames_total": max(pass1["frames_total"], pass2["frames_total"],
                             pass3["frames_total"]),
        "frames_handled": max(pass1["frames_handled"], pass2["frames_handled"],
                               pass3["frames_handled"]),
        "filled": merged_filled,
        "card_ok": card_ok,
        "billing_ok": billing_ok,
        "supplement_rounds": supplement_rounds,
        "billing_rounds": billing_rounds,
        "errors": pass1["errors"] + pass2["errors"] + pass3["errors"],
        "pass1_filled": pass1["filled"],
        "pass2_filled": pass2["filled"],
        "pass3_filled": pass3["filled"],
    }
    log_fn(
        f"[GPT PRO 升级 PRO] 填卡汇总: pass1={pass1['filled']} "
        f"pass2={pass2['filled']} pass3={pass3['filled']} merged={merged_filled} "
        f"card_ok={card_ok} billing_ok={billing_ok}"
    )
    return summary


# ── 退款流程: help.openai.com 自动化 ──────────────────────────
# 流程已在浏览器中手动跑通, 见 manual debug:
#   1. page.get help.openai.com/zh-hans-cn?chat=true
#   2. 点 button._Trigger_12slx_83 (右下角对话框 trigger)
#   3. 点 widget panel 内 "登录" 按钮 (a._Button_6dmow_1 in [class*=Panel_12slx])
#   4. 跳到 auth.openai.com/choose-an-account, 找含 email 的 button + 点
#   5. 跳回 help.openai.com, 再次点 trigger
#   6. iframe[name=chatkit] 内 [contenteditable=true] 输入退款诉求
#   7. 点 iframe 内 button[aria-label="发送消息"]

_HELP_URL = "https://help.openai.com/zh-hans-cn?chat=true"
_TRIGGER_CSS = "button._Trigger_12slx_83"
_PANEL_LOGIN_JS = """
return (function(){
    const p = document.querySelector("[class*=Panel_12slx]");
    if (!p) return {ok: false, reason: "no panel"};
    const b = p.querySelector("a._Button_6dmow_1, a[aria-label=\\"Log in for support\\"]");
    if (!b) return {ok: false, reason: "no login btn in panel"};
    const r = b.getBoundingClientRect();
    const o = {bubbles:true, cancelable:true,
               clientX: r.x + r.width/2, clientY: r.y + r.height/2, button: 0};
    b.dispatchEvent(new PointerEvent("pointerdown", o));
    b.dispatchEvent(new MouseEvent("mousedown", o));
    b.dispatchEvent(new PointerEvent("pointerup", o));
    b.dispatchEvent(new MouseEvent("mouseup", o));
    b.dispatchEvent(new MouseEvent("click", o));
    return {ok: true, href: b.getAttribute("href") || ""};
})();
"""
_CLICK_TRIGGER_JS = """
return (function(){
    const t = document.querySelector("button._Trigger_12slx_83");
    if (!t) return {ok: false, reason: "no trigger"};
    const r = t.getBoundingClientRect();
    const o = {bubbles:true, cancelable:true,
               clientX: r.x + 25, clientY: r.y + 25, button: 0};
    t.dispatchEvent(new PointerEvent("pointerdown", o));
    t.dispatchEvent(new MouseEvent("mousedown", o));
    t.dispatchEvent(new PointerEvent("pointerup", o));
    t.dispatchEvent(new MouseEvent("mouseup", o));
    t.dispatchEvent(new MouseEvent("click", o));
    return {ok: true};
})();
"""


def _click_account_in_choose_page(page, email: str, log_fn) -> bool:
    """auth.openai.com/choose-an-account 页面找含 email 的 button + 点。"""
    js = """
    return (function(needle){
        const btns = Array.from(document.querySelectorAll("button"));
        const acc = btns.find(b => {
            const t = (b.innerText || "").toLowerCase();
            return t.includes(needle) && !t.includes("移除");
        });
        if (!acc) return {ok: false, reason: "no matching button"};
        const r = acc.getBoundingClientRect();
        const o = {bubbles:true, cancelable:true,
                   clientX: r.x + r.width/2, clientY: r.y + r.height/2, button: 0};
        acc.dispatchEvent(new PointerEvent("pointerdown", o));
        acc.dispatchEvent(new MouseEvent("mousedown", o));
        acc.dispatchEvent(new PointerEvent("pointerup", o));
        acc.dispatchEvent(new MouseEvent("mouseup", o));
        acc.dispatchEvent(new MouseEvent("click", o));
        return {ok: true};
    })(arguments[0]);
    """
    try:
        res = page.run_js(js, (email or "").lower()) or {}
    except Exception as exc:
        log_fn(f"[退款] choose-an-account JS 异常: {exc}")
        return False
    if not res.get("ok"):
        log_fn(f"[退款] choose-an-account 找不到账号: {res.get('reason')}")
        return False
    return True


def _wait_for_url_contains(page, *, contains: str, timeout: int = 30, log_fn=None) -> bool:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            url = page.url or ""
        except Exception:
            url = ""
        if url != last:
            if log_fn:
                log_fn(f"[退款] URL 变化: {url}")
            last = url
        if contains in url:
            return True
        time.sleep(0.5)
    return False


def _wait_for_chatkit_frame(page, *, timeout: int = 20, log_fn=None):
    """等 iframe[name=chatkit] 出现并可用。返回 frame 或 None。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            frames = list(page.get_frames("css:iframe[name=chatkit]"))
        except Exception:
            frames = []
        if frames:
            return frames[0]
        time.sleep(0.4)
    if log_fn:
        log_fn("[退款] ⚠ 等 chatkit iframe 超时")
    return None


_CHATKIT_TYPE_AND_SEND_JS_TEMPLATE = """
return (function(text){
    const ed = document.querySelector("[contenteditable=true]");
    if (!ed) return {ok: false, stage: "no_editor"};
    ed.focus();
    const sel = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(ed);
    range.collapse(false);
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand("insertText", false, text);
    ed.dispatchEvent(new InputEvent("input",
        {bubbles:true, inputType: "insertText", data: text}));
    const after = ed.innerText || "";
    if (!after.includes(text)) {
        return {ok: false, stage: "input_failed", after};
    }
    return {ok: true, stage: "typed", after};
})(__MESSAGE_JSON__);
"""


_CHATKIT_CLICK_SEND_JS = """
return (function(){
    const btn = document.querySelector("button[aria-label=\\"发送消息\\"]")
              || document.querySelector("button[aria-label=\\"Send message\\"]");
    if (!btn) return {ok: false, stage: "no_send_btn"};
    if (btn.disabled) return {ok: false, stage: "send_btn_disabled"};
    const r = btn.getBoundingClientRect();
    const o = {bubbles:true, cancelable:true,
               clientX: r.x + r.width/2, clientY: r.y + r.height/2, button: 0};
    btn.dispatchEvent(new PointerEvent("pointerdown", o));
    btn.dispatchEvent(new MouseEvent("mousedown", o));
    btn.dispatchEvent(new PointerEvent("pointerup", o));
    btn.dispatchEvent(new MouseEvent("mouseup", o));
    btn.dispatchEvent(new MouseEvent("click", o));
    return {ok: true, stage: "clicked"};
})();
"""


# 读 ChatKit 输入区状态: AI 流式回复时会出现"停止"按钮(aria-label 含 停止/Stop),
# 回复结束后恢复"发送消息"按钮。用它判断 AI 是否还在生成 / 是否可以再次发送。
_CHATKIT_COMPOSER_STATE_JS = """
return (function(){
    var btns = Array.prototype.slice.call(document.querySelectorAll("button[aria-label]"));
    var stop = btns.find(function(b){
        return /停止|stop/i.test(b.getAttribute("aria-label") || "");
    });
    var send = document.querySelector("button[aria-label=\\"发送消息\\"]")
             || document.querySelector("button[aria-label=\\"Send message\\"]");
    return {
        hasStop: !!stop,
        hasSend: !!send,
        sendDisabled: send ? !!send.disabled : true,
    };
})();
"""


# 点 ChatKit 右上角"新对话"(铅笔/撰写图标)按钮, 开一段全新的客服对话。
# 客服拒绝后会说"请开启新的支持对话"——同一对话里再发没用, 必须新开对话。
# aria-label 未知/可能多语言, 多候选匹配; 匹配不到时回传所有按钮 aria-label 便于排查。
_CHATKIT_NEW_CONVERSATION_JS = """
return (function(){
    var pats = [/新对话/,/新聊天/,/新建对话/,/新的?对话/,/开启新/,/新会话/,
                /撰写/,/编辑/,
                /new\\s*chat/i,/new\\s*conversation/i,/start\\s*new/i,
                /compose/i,/write/i];
    var btns = Array.prototype.slice.call(document.querySelectorAll("button[aria-label]"));
    var target = null;
    for (var i=0;i<btns.length;i++){
        var al = btns[i].getAttribute("aria-label") || "";
        for (var j=0;j<pats.length;j++){
            if (pats[j].test(al)) { target = btns[i]; break; }
        }
        if (target) break;
    }
    if (!target) {
        return {ok:false, stage:"no_new_btn",
                labels: btns.map(function(b){return b.getAttribute("aria-label");})};
    }
    var r = target.getBoundingClientRect();
    var o = {bubbles:true, cancelable:true,
             clientX: r.x + r.width/2, clientY: r.y + r.height/2, button: 0};
    target.dispatchEvent(new PointerEvent("pointerdown", o));
    target.dispatchEvent(new MouseEvent("mousedown", o));
    target.dispatchEvent(new PointerEvent("pointerup", o));
    target.dispatchEvent(new MouseEvent("mouseup", o));
    target.dispatchEvent(new MouseEvent("click", o));
    return {ok:true, clicked: target.getAttribute("aria-label")};
})();
"""


# help.openai.com 偶发错误页: "UH OH. SOMETHING WENT WRONG." + "Go back home" 链接。
# 该链接选择器就是用户实测的 body > div > a。命中则点它恢复(点不动兜底重新导航)。
_HELP_ERROR_CHECK_JS = """
return (function(){
    var bodyText = (document.body && document.body.innerText) || "";
    var wrong = /SOMETHING WENT WRONG/i.test(bodyText);
    var link = document.querySelector("body > div > a");
    var linkText = link ? (link.innerText || link.textContent || "").trim() : "";
    var isHome = /go back home/i.test(linkText) || /返回(首页|主页)|回到首页/.test(linkText);
    return {
        error: !!(wrong || isHome),
        hasLink: !!link,
        linkText: linkText,
        href: link ? link.href : ""
    };
})();
"""

_HELP_ERROR_CLICK_HOME_JS = """
return (function(){
    var link = document.querySelector("body > div > a");
    if (!link) return {ok: false, reason: "no link"};
    link.click();
    return {ok: true, href: link.href};
})();
"""


def _recover_help_error_page(page, *, attempts: int = 3, log_fn=None) -> bool:
    """检测并恢复 help.openai.com 的 "UH OH. SOMETHING WENT WRONG" 错误页。

    命中错误页 → 点 "Go back home" (body > div > a) 恢复;点不动则兜底重新导航
    _HELP_URL。返回 True = 页面正常(无错误页 / 已恢复), False = 多次尝试仍卡在错误页。
    非错误页 / 检测异常一律返回 True(视为正常, 不阻断主流程)。
    """
    log = log_fn or (lambda m: print(m, flush=True))
    for i in range(1, attempts + 1):
        try:
            check = page.run_js(_HELP_ERROR_CHECK_JS) or {}
        except Exception as exc:
            log(f"[退款] ⚠ 错误页检测 JS 异常 (视为正常继续): {exc}")
            return True
        if not check.get("error"):
            return True
        log(f"[退款] ⚠ 命中 help 错误页 (SOMETHING WENT WRONG), "
            f"第 {i}/{attempts} 次恢复: 点 '{check.get('linkText') or 'Go back home'}'")
        clicked = False
        if check.get("hasLink"):
            try:
                res = page.run_js(_HELP_ERROR_CLICK_HOME_JS) or {}
                clicked = bool(res.get("ok"))
            except Exception as exc:
                log(f"[退款] ⚠ 点 Go back home 异常: {exc}")
        if not clicked:
            log("[退款] Go back home 不可点, 兜底重新导航 help")
            try:
                page.get(_HELP_URL, timeout=_NAV_TIMEOUT)
            except Exception as exc:
                log(f"[退款] ⚠ 重新导航 help 异常: {exc}")
        time.sleep(4)
    try:
        final = page.run_js(_HELP_ERROR_CHECK_JS) or {}
        recovered = not final.get("error")
    except Exception:
        recovered = True
    if recovered:
        log("[退款] ✅ help 错误页已恢复")
    else:
        log("[退款] ✗ help 错误页多次恢复失败")
    return recovered


def run_help_refund_flow(page, email: str, *,
                          message_text: str = "误订阅 请退款",
                          escalate_text: str = "联系客服专员",
                          auto_confirm: bool = True,
                          confirm_text: str = "同意",
                          observe_seconds: int = 240,
                          reply_timeout: int = 120,
                          wait_min_seconds: int = 3600,
                          wait_max_seconds: int = 7200,
                          max_rounds: int = 4,
                          refund_arrived=None,
                          manual_only: bool = False,
                          stop_on_escalation: bool = False,
                          log_fn=None) -> dict:
    """登陆后跳到 help.openai.com 并完成 SSO + 自动发送退款诉求。

    流程 (跟 manual debug 相同):
      1. page.get help URL
      2. 点 widget trigger (打开 panel)
      3. 点 panel 内"登录"按钮 → SSO 跳 choose-an-account
      4. 选已登陆账号 → 跳回 help
      5. 再次点 trigger (widget 重新展开)
      6. ChatKit iframe 输入 message_text + 点发送
      7. 兜底: 如果首次发送后 AI 没回, 刷新页 + 重发 (manual 测试过这套路能让 streaming 同步出来)

    返回:
      {ok, stage, sent_text, refreshed: bool, error?}
    """
    log = log_fn or (lambda m: print(m, flush=True))

    # Step 1: 跳 help
    log(f"[退款] 跳到 {_HELP_URL}")
    try:
        page.get(_HELP_URL, timeout=_NAV_TIMEOUT)
    except Exception as exc:
        return {"ok": False, "stage": "nav_help_failed",
                "error": f"page.get help URL 异常: {exc}"}
    time.sleep(4)

    # Step 1b: help 偶发错误页 (UH OH. SOMETHING WENT WRONG) → 点 "Go back home" 恢复
    if not _recover_help_error_page(page, log_fn=log):
        return {"ok": False, "stage": "help_error_page",
                "error": "help.openai.com 反复停在错误页 (Go back home 恢复失败)"}

    # Step 2: 点 widget trigger
    log("[退款] 点 widget trigger 打开 panel")
    try:
        page.run_js(_CLICK_TRIGGER_JS)
    except Exception as exc:
        log(f"[退款] ⚠ trigger 点击异常 (继续): {exc}")
    time.sleep(2)

    # Step 3: 点 panel 内登录按钮
    log("[退款] 点 widget panel 内登录按钮 → SSO")
    try:
        login_res = page.run_js(_PANEL_LOGIN_JS) or {}
    except Exception as exc:
        return {"ok": False, "stage": "sso_login_click_failed",
                "error": f"panel 登录按钮 JS 异常: {exc}"}
    if not login_res.get("ok"):
        return {"ok": False, "stage": "sso_login_click_failed",
                "error": f"找不到 panel 登录按钮: {login_res}"}

    # Step 4: 等 choose-an-account → 选账号
    log("[退款] 等待跳到 choose-an-account")
    if not _wait_for_url_contains(page, contains="choose-an-account",
                                   timeout=30, log_fn=log):
        # 可能已经直接跳回 help (cookie 完整时无需选账号), 检查是否回到 help
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if "help.openai.com" not in cur:
            return {"ok": False, "stage": "sso_redirect_failed",
                    "error": f"未跳到 choose-an-account, 也不在 help (URL={cur})"}
        log("[退款] 已直接跳回 help (无需选账号)")
    else:
        time.sleep(2)
        log(f"[退款] 选账号 {email}")
        if not _click_account_in_choose_page(page, email, log):
            return {"ok": False, "stage": "sso_account_pick_failed",
                    "error": "choose-an-account 页找不到账号按钮"}

    # Step 5: 等回到 help
    log("[退款] 等回到 help.openai.com")
    if not _wait_for_url_contains(page, contains="help.openai.com",
                                   timeout=30, log_fn=log):
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        return {"ok": False, "stage": "sso_back_to_help_failed",
                "error": f"SSO 后未回 help (URL={cur})"}
    time.sleep(4)

    # Step 5b: SSO 跳回后 help 同样可能出现错误页 → 点 "Go back home" 恢复
    if not _recover_help_error_page(page, log_fn=log):
        return {"ok": False, "stage": "help_error_page",
                "error": "SSO 回 help 后反复停在错误页 (Go back home 恢复失败)"}

    # Step 6: 再点 trigger 打开 widget (已登陆态)
    log("[退款] 再点 trigger, widget 应该带登陆态")
    try:
        page.run_js(_CLICK_TRIGGER_JS)
    except Exception as exc:
        log(f"[退款] ⚠ 再次 trigger 点击异常 (继续): {exc}")
    time.sleep(3)

    # Step 7: 拿 ChatKit iframe
    log("[退款] 等 ChatKit iframe")
    frame = _wait_for_chatkit_frame(page, timeout=20, log_fn=log)
    if frame is None:
        return {"ok": False, "stage": "no_chatkit_frame",
                "error": "ChatKit iframe 未找到 (widget 可能未打开)"}

    # 手动模式: 只把客服对话界面打开好, 不自动发文案, 浏览器保留供人工手动发送。
    if manual_only:
        # 多个手动退款窗口时难分清哪个是哪个号: 顶部注入橙色横幅显示账号邮箱 + 设置窗口标题。
        # 挂在 <html> 直属子节点(而非 body), React 重渲染不易清掉; 每秒补挂一次防被覆盖。
        try:
            page.run_js("""
            (function(email){
              function ensure(){
                try { if (!/^【/.test(document.title)) document.title = '【'+email+'】手动退款'; } catch(e){}
                var id='__acct_badge__';
                if(!document.getElementById(id)){
                  var d=document.createElement('div'); d.id=id;
                  d.textContent='🟠 手动退款账号: '+email;
                  d.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;'
                    +'background:#fa8c16;color:#fff;font:bold 15px system-ui,sans-serif;'
                    +'padding:6px 12px;text-align:center;letter-spacing:.5px;'
                    +'box-shadow:0 2px 10px rgba(0,0,0,.35);';
                  document.documentElement.appendChild(d);
                }
              }
              ensure(); setInterval(ensure, 1000);
            })(arguments[0]);
            """, email)
        except Exception as exc:
            log(f"[退款] 手动模式: 账号标识注入失败(忽略): {exc}")
        log(f"[退款] 手动模式: 已打开客服对话界面(顶部橙条标注 {email}), 不自动发送, 浏览器保留请人工手动发送")
        return {"ok": True, "stage": "manual_opened", "manual": True,
                "sent_text": "", "refund_success": False,
                "note": "已跳到客服对话界面(未发送文案), 请人工手动发送。"}

    # Step 8-9: 脚本化两轮对话 + 无退款邮件则点"新对话"重开客服对话重试
    #   第 1 句: message_text        (默认 "误订阅 请退款")  → 客服一般回"不支持"
    #   第 2 句: escalate_text       (默认 "申请人工客服介入 误订阅 请退款") → 客服回"已升级人工"
    #   之后窗口保持打开, 随机等待 [wait_min_seconds, wait_max_seconds] (默认 1~2 小时随机),
    #   期间轮询 refund_arrived(); 若仍没退款邮件 → 点铅笔"新对话"重开一段客服对话再走一轮,
    #   最多 max_rounds 轮 (直到退款成功)。
    import json as _json
    import re as _re
    import random as _random

    def _frame():
        try:
            fs = list(page.get_frames("css:iframe[name=chatkit]"))
            if fs:
                return fs[0]
        except Exception:
            pass
        return frame

    def _read(fr) -> str:
        try:
            return str(fr.run_js("return (document.body && document.body.innerText) || '';") or "")
        except Exception:
            return ""

    def _composer_state(fr) -> dict:
        try:
            return fr.run_js(_CHATKIT_COMPOSER_STATE_JS) or {}
        except Exception:
            return {}

    def _wait_idle(*, timeout: int) -> bool:
        """等 AI 空闲(无"停止"按钮 = 没在生成)。返回 True 表示已空闲。"""
        start = time.time()
        while time.time() - start < timeout:
            if not _composer_state(_frame()).get("hasStop"):
                return True
            time.sleep(2)
        return False

    def _log_new_transcript(text: str) -> None:
        if text and text != transcript_ref["v"]:
            new_part = text[len(transcript_ref["v"]):] if text.startswith(transcript_ref["v"]) else text
            if new_part.strip():
                log(f"[退款][对话]\n{new_part[-1200:]}")
            transcript_ref["v"] = text

    def _send(fr, t: str) -> bool:
        """先等 AI 空闲, 再输入 + 点发送; 发送按钮此刻可能仍是'停止'按钮 → 重试几次。"""
        _wait_idle(timeout=90)  # AI 还在回上一条时不要抢发
        tj = _CHATKIT_TYPE_AND_SEND_JS_TEMPLATE.replace("__MESSAGE_JSON__", _json.dumps(t))
        for _ in range(6):
            try:
                if not (fr.run_js(tj) or {}).get("ok"):
                    time.sleep(2)
                    continue
                time.sleep(0.8)
                if (fr.run_js(_CHATKIT_CLICK_SEND_JS) or {}).get("ok"):
                    return True
            except Exception:
                pass
            time.sleep(3)  # 没点到发送按钮(可能仍在生成)→ 稍等重试
            fr = _frame()
        return False

    def _wait_ai_reply(*, timeout: int) -> str:
        """发消息后等 AI 回复完成: 先等出现'停止'按钮(开始生成), 再等它消失(生成结束)。
        若一直没出现'停止'按钮(AI 秒回/无回复), 则退化为文本稳定判断。"""
        start = time.time()
        # 1) 等 AI 开始生成 (最多 18s 出现'停止'按钮)
        started = False
        while time.time() - start < 18:
            _log_new_transcript(_read(_frame()))
            if _composer_state(_frame()).get("hasStop"):
                started = True
                break
            time.sleep(1.5)
        # 2) 等 AI 生成结束 ('停止'按钮消失)
        last_text = _read(_frame())
        last_change = time.time()
        while time.time() - start < timeout:
            text = _read(_frame())
            _log_new_transcript(text)
            if text != last_text:
                last_text = text
                last_change = time.time()
            busy = _composer_state(_frame()).get("hasStop")
            if started and not busy:
                time.sleep(2)  # 生成刚结束, 让 innerText 落定
                final = _read(_frame())
                _log_new_transcript(final)
                return final
            # 从未进入生成态: 文本连续 8s 不变即视为回复完成
            if (not started) and (time.time() - last_change >= 8):
                return text
            time.sleep(2)
        return _read(_frame())

    SUCCESS_RE = _re.compile(
        r"已获得.{0,4}(全额)?退款|已.{0,2}全额退款|订阅已取消|已取消.{0,4}订阅|"
        r"退款将在.{0,6}工作日|refunded|will be refunded"
    )
    # 实测"已升级人工"类回复: "已升级给支持专员;您预计会在未来几天内收到回复"
    #   期望新文案回复: "已为您联系客服专员 / 已联系支持专员 / 已升级给客服专员"
    HUMAN_RE = _re.compile(
        r"人工客服|人工.{0,4}介入|(客服|支持).{0,2}专员|已.{0,6}联系.{0,6}(客服|支持|专员)|"
        r"已.{0,4}(为你|为您).{0,6}(转|升级|提交|申请|联系)|已.{0,4}(转接|转交|升级|上报)|"
        r"(转|升级).{0,6}人工|human (agent|support|team)|escalat|specialist|our team will"
    )
    # 实测客服"不支持"回复: "我们无法通过这次支持对话处理此退款请求。尚未进行任何退款或
    # 订阅更改。如果您需要帮助处理其他问题,请开启新的支持对话。"
    REFUSAL_RE = _re.compile(
        r"无法.{0,10}(处理|完成|办理).{0,10}退款|无法通过.{0,12}支持对话|"
        r"尚未.{0,6}(进行|做|发生).{0,8}退款|开启新的?支持?对话|另起.{0,4}对话|"
        r"cannot (process|handle|complete).{0,24}refund|unable to.{0,24}refund|"
        r"start a new (support )?(conversation|chat)"
    )

    transcript_ref = {"v": ""}

    def _run_round(idx: int) -> dict:
        """单轮: 发第一句(误订阅退款) → 等回复 → 发第二句(联系客服专员) → 等回复。返回本轮结论。"""
        fr = _frame()
        log(f"[退款][第{idx}轮] 发第一句 {message_text!r}")
        if not _send(fr, message_text):
            return {"ok": False, "stage": "send_first_failed",
                    "error": f"第一句发送失败: {message_text}"}
        log("[退款] 已发第一句, 等客服回复(预期'不支持/无法处理'类) ...")
        r1 = _wait_ai_reply(timeout=reply_timeout)
        if REFUSAL_RE.search(r1 or ""):
            log("[退款] ✓ 已收到客服'不支持/无法处理退款'回复(符合预期), 升级人工介入")
        elif (r1 or "").strip():
            log("[退款] ℹ 已收到客服回复(非典型'不支持'话术), 仍按流程升级人工")
        else:
            log("[退款] ⚠ 未读到客服回复文本(可能仍在渲染), 仍继续发第二句")

        fr = _frame()
        log(f"[退款][第{idx}轮] 发第二句 {escalate_text!r}")
        if not _send(fr, escalate_text):
            return {"ok": False, "stage": "send_escalate_failed",
                    "error": f"第二句发送失败: {escalate_text}"}
        log("[退款] 已发第二句, 等客服回复(预期'已联系客服专员'类) ...")
        r2 = _wait_ai_reply(timeout=reply_timeout)

        full = (r1 or "") + "\n" + (r2 or "")
        human = bool(HUMAN_RE.search(full))
        success = bool(SUCCESS_RE.search(full))
        if human:
            log("[退款] ✅ 检测到'已联系/升级客服专员'类回复")
        elif success:
            log("[退款] ✅ 检测到退款成功提示")
        else:
            log("[退款] ⚠ 未识别到人工/成功话术 (话术可能变化, 仍按已发送处理)")
        return {"ok": True, "stage": "escalated" if (human or success) else "sent",
                "human_escalated": human, "refund_success": success}

    def _wait_for_email(interval: int) -> bool:
        """等 interval 秒, 期间每 60s 调 refund_arrived() 检查退款邮件是否到。到了返回 True。"""
        if refund_arrived is None:
            # 无邮件回调 → 只按固定时长干等
            slept = 0
            while slept < interval:
                time.sleep(min(60, interval - slept))
                slept += 60
            return False
        waited = 0
        while waited < interval:
            step = min(60, interval - waited)
            time.sleep(step)
            waited += step
            try:
                if refund_arrived():
                    return True
            except Exception as exc:
                log(f"[退款] ⚠ 退款邮件检查异常(忽略): {exc}")
        return False

    def _new_conversation() -> bool:
        """点 ChatKit 右上角'新对话'(铅笔)按钮, 开一段全新客服对话。成功返回 True。"""
        for _ in range(3):
            fr = _frame()
            try:
                res = fr.run_js(_CHATKIT_NEW_CONVERSATION_JS) or {}
            except Exception as exc:
                log(f"[退款] ⚠ 点'新对话'JS 异常: {exc}")
                res = {}
            if res.get("ok"):
                log(f"[退款] 已点'新对话'按钮 (aria-label={res.get('clicked')!r})")
                time.sleep(3)
                # 清空 transcript 基线, 让新对话的回复能被识别为"新增"
                transcript_ref["v"] = _read(_frame())
                return True
            labels = res.get("labels")
            if labels is not None:
                log(f"[退款] ⚠ 没找到'新对话'按钮, 当前按钮 aria-label 列表: {labels}")
            time.sleep(2)
        return False

    rounds_done = 0
    last_round = {}
    email_ok = False
    for idx in range(1, int(max_rounds) + 1):
        if idx > 1:
            # 上一轮 30 分钟没等到邮件 → 点铅笔开新对话再走一轮 (同一窗口, 不重登录)
            if not _new_conversation():
                log("[退款] ⚠ 开新对话失败, 兜底: 重新点 widget trigger")
                try:
                    page.run_js(_CLICK_TRIGGER_JS)
                    time.sleep(3)
                    _wait_for_chatkit_frame(page, timeout=20, log_fn=log)
                    transcript_ref["v"] = _read(_frame())
                except Exception as exc:
                    log(f"[退款] ⚠ 兜底重开 widget 也失败: {exc}")

        last_round = _run_round(idx)
        rounds_done = idx
        if not last_round.get("ok"):
            return {**last_round, "sent_text": message_text,
                    "escalate_text": escalate_text, "rounds": rounds_done,
                    "transcript_tail": transcript_ref["v"][-3000:]}
        if last_round.get("refund_success"):
            email_ok = True
            break
        # 已升级人工客服(AI 回复"已升级给客服专员/请等待")→ 认为"等待即可",
        # 不再长时间轮询/重开对话。直接结束,退款状态标为"已升级人工·等待退款"。
        if stop_on_escalation and last_round.get("human_escalated"):
            log("[退款] ✅ 已升级人工客服, 按「等待即可」处理: 结束流程(不再重试轮询), 状态标为等待人工退款")
            break
        if idx >= int(max_rounds):
            log(f"[退款] 已达最大轮数 {max_rounds}, 仍未收到退款邮件, 结束")
            break
        lo = int(wait_min_seconds)
        hi = int(max(wait_max_seconds, wait_min_seconds))
        interval = _random.randint(lo, hi) if hi > lo else lo
        mins = interval / 60.0
        log(f"[退款] 已升级人工, 窗口保持打开, 随机等待 {mins:.0f} 分钟看退款邮件 (第 {idx} 轮) ...")
        if _wait_for_email(interval):
            log("[退款] ✅ 等待期内收到退款邮件, 结束")
            email_ok = True
            break
        log(f"[退款] {mins:.0f} 分钟内仍无退款邮件 → 点'新对话'重开一段客服对话重试")

    return {
        "ok": True,
        "stage": "refunded" if email_ok else last_round.get("stage", "sent"),
        "sent_text": message_text,
        "escalate_text": escalate_text,
        "human_escalated": bool(last_round.get("human_escalated")),
        "refund_success": email_ok,
        "rounds": rounds_done,
        "transcript_tail": (transcript_ref["v"][-3000:] if transcript_ref["v"] else ""),
        "note": "两轮脚本(误订阅请退款 → 申请人工客服介入); 每轮后窗口不关等 30 分钟看退款邮件, "
                "没到则点'新对话'重开一段客服对话重试, 直到退款成功或达最大轮数 (详见日志)。",
    }


def build_outlook_mailbox(account_extra: dict, *, proxy: str = ""):
    """便捷构造: 把 GptProAccountModel 的字段映射成 (OutlookMailbox, MailboxAccount).

    mail_access_type 兜底:
      - DB 里若已打标 'graph' / 'imap_pop' 就照用
      - 空但有完整 OAuth 凭证 (client_id + refresh_token) → 当 'graph' 走
        (outlook.live.com 不再支持 IMAP basic auth, 没标签时默认 OAuth/Graph 更对)
    """
    from core.base_mailbox import MailboxAccount, OutlookMailbox

    legacy_refresh_token = str(account_extra.get("refresh_token") or "").strip()
    legacy_looks_microsoft = legacy_refresh_token.startswith(("M.", "0."))
    chatgpt_rt_owned = bool(
        account_extra.get("chatgpt_has_refresh_token_solution")
        or str(account_extra.get("chatgpt_registration_mode") or "").strip().lower()
        in {"rt", "refresh_token", "oauth"}
        or str(account_extra.get("chatgpt_token_source") or "").strip().lower()
        in {"oauth", "register", "refresh"}
    )
    allow_legacy_refresh = not chatgpt_rt_owned or legacy_looks_microsoft
    mail_client_id = str(
        account_extra.get("outlook_mail_client_id")
        or account_extra.get("outlook_client_id")
        or account_extra.get("client_id")
        or ""
    ).strip()
    mail_refresh_token = str(
        account_extra.get("outlook_mail_refresh_token")
        or account_extra.get("outlook_refresh_token")
        or (legacy_refresh_token if allow_legacy_refresh else "")
        or ""
    ).strip()
    mail_access_type = str(
        account_extra.get("outlook_mail_access_type")
        or account_extra.get("mail_access_type")
        or ""
    ).strip().lower()
    if not mail_access_type:
        if mail_client_id and mail_refresh_token:
            mail_access_type = "graph"

    mailbox = OutlookMailbox(platform="chatgpt", proxy=proxy or None)
    mb_account = MailboxAccount(
        email=str(account_extra.get("email") or ""),
        extra={
            "password": (
                account_extra.get("outlook_mail_password")
                or account_extra.get("outlook_password")
                or account_extra.get("password")
                or ""
            ),
            "client_id": mail_client_id,
            "refresh_token": mail_refresh_token,
            "mail_access_type": mail_access_type,
            "graph_immutable_ids": bool(
                account_extra.get("graph_immutable_ids")
            ),
        },
    )
    return mailbox, mb_account


def _optional_gmail_login_code_provider(email: str, *, proxy: str = "", log_fn=None):
    """Attach a bound Gmail alias only for an additional password-login mail challenge.

    Resolution is local. Preparing or reading mail is deferred to the login
    primitive, which can continue a password/TOTP login if email is unavailable.
    No Google credentials enter the GPT password/TOTP path.
    """
    from services.gmail_registration import resolve_fixed_alias
    try:
        alias = resolve_fixed_alias(email)
    except Exception:
        return None
    snapshot = {"email": alias["email"], "mail_provider": "gmail",
                "gmail_source_id": alias["source_id"], "gmail_alias_id": alias["id"]}
    adapter = None

    def code_provider(*, email: str, timeout: int = 120, prepare: bool = False, exclude_codes=None):
        nonlocal adapter
        if email.strip().lower() != snapshot["email"].strip().lower():
            raise RuntimeError("Gmail 登录验证码请求与当前子号不一致")
        if prepare:
            mailbox, account = build_mailbox_for_account(snapshot, proxy=proxy)
            adapter = GptProEmailAdapterForCodexOAuth(mailbox, account, log_fn=log_fn)
            if not adapter.prepare_for_verification():
                adapter = None
                raise RuntimeError("Gmail 新邮件基线准备失败")
            return ""
        if adapter is None or not adapter.prepare_for_verification():
            raise RuntimeError("Gmail 新邮件基线尚未准备")
        return adapter.wait_for_verification_code(email=email, timeout=timeout,
                                                  exclude_codes=exclude_codes or set())

    return code_provider


def build_mailbox_for_account(account_extra: dict, *, proxy: str = ""):
    """按 mail_provider 分发构造 (mailbox, mb_account)。取码接口 wait_for_code 各 provider 统一。

    - outlook(默认): OutlookMailbox(graph/imap) —— 沿用 build_outlook_mailbox。
    - gmail: 仅从已绑定的母号收件，固定读取当前子号，不参与注册选号。
    - icloud: QQMailMailbox —— 用**全局** qqmail 配置(qqmail_user/qqmail_auth_code/host/port/
      pool_file)登 imap.qq.com; 账号 email 即 iCloud 别名, wait_for_code 按 To 头精确过滤。
      不走 tracker 的"挑未注册别名"逻辑(那是注册时用的), 这里读指定别名。
    """
    from services.gmail_plan_support import account_mail_provider, gmail_binding_extra
    provider = account_mail_provider(account_extra)
    if provider == "gmail":
        from core.gmail_mailbox import GmailMailbox
        cfg = {"email": str(account_extra.get("email") or ""),
               "gmail_fixed_account": True, **gmail_binding_extra(account_extra)}
        # The browser proxy only carries HTTPS traffic and commonly rejects
        # IMAPS port 993. Gmail sources already own an optional dedicated mail
        # proxy in their persisted snapshot; leaving this fallback empty lets
        # the transport use that source setting or its verified direct-IP TLS
        # recovery instead of accidentally routing mail through Clash HTTP.
        mailbox = GmailMailbox(extra=cfg, proxy=None)
        return mailbox, mailbox.fixed_account()
    if provider in ("icloud", "qqmail"):
        from core.base_mailbox import MailboxAccount, create_mailbox
        try:
            from core.config_store import config_store
            cfg = dict(config_store.get_all() or {})
        except Exception:
            cfg = {}
        cfg["platform"] = "chatgpt"
        cfg["_platform"] = "chatgpt"
        # 读指定别名, 关掉 tracker 自动挑号
        cfg["qqmail_use_tracker"] = False
        mailbox = create_mailbox(provider="qqmail", extra=cfg, proxy=None)
        mb_account = MailboxAccount(
            email=str(account_extra.get("email") or ""),
            extra={"provider": "qqmail", "platform": "chatgpt"},
        )
        return mailbox, mb_account
    return build_outlook_mailbox(account_extra, proxy=proxy)


class GptProEmailAdapterForCodexOAuth:
    """适配 platforms/chatgpt/drission_rt_acquirer.acquire_rt_via_drission 需要的 email_adapter 接口。

    包装 OutlookMailbox.wait_for_code, 暴露 wait_for_verification_code(email, timeout, otp_sent_at, exclude_codes)。
    OutlookMailbox 自己不需要 otp_sent_at, 这里参数被忽略 (排重靠 before_ids + exclude_codes)。
    """

    def __init__(self, mailbox, mb_account, *, log_fn=None):
        self._mailbox = mailbox
        self._mb_account = mb_account
        self._log_fn = log_fn or (lambda m: print(m, flush=True))
        # 在构造时 snapshot 当前邮件 id 作为 baseline, 之后只接受新邮件
        self._verification_baseline_ready = False
        try:
            import inspect
            from core.base_mailbox import OutlookMailbox, QQMailMailbox

            snapshot = mailbox.get_current_ids
            # Built-in providers historically hide failures as an empty inbox;
            # strict mode must distinguish the two.  Other adapters/test doubles
            # opt in only with an explicit supported keyword, never by retrying
            # a TypeError without strict mode after the snapshot has failed.
            use_strict = isinstance(mailbox, (OutlookMailbox, QQMailMailbox))
            if not use_strict:
                strict_parameter = inspect.signature(snapshot).parameters.get("strict")
                use_strict = strict_parameter is not None and strict_parameter.kind in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            ids = snapshot(mb_account, strict=True) if use_strict else snapshot(mb_account)
            if not isinstance(ids, (set, frozenset, list, tuple)):
                raise ValueError("邮箱基线响应不是有效的邮件 ID 集合")
            self._before_ids = set(ids)
            self._verification_baseline_ready = True
            self._log_fn(
                f"[codex OAuth email adapter] baseline {len(self._before_ids)} 封邮件",
            )
        except Exception as exc:
            self._verification_baseline_ready = False
            self._log_fn(
                "[codex OAuth email adapter] 邮件基线准备失败 "
                f"({type(exc).__name__})",
            )
            self._before_ids = set()

    def prepare_for_verification(self) -> bool:
        """Report the pre-navigation baseline, never resnapshot after sending OTP.

        An empty mailbox is a valid baseline.  A snapshot failure is distinct
        and must not allow a managed-MFA follow-up challenge to reuse old mail.
        """
        return self._verification_baseline_ready is True

    def wait_for_verification_code(self, email: str, timeout: int = 120,
                                    otp_sent_at: Optional[float] = None,
                                    exclude_codes: Optional[set] = None) -> str:
        # email / otp_sent_at 忽略 (我们用 before_ids 做基线)
        _ = email, otp_sent_at
        try:
            return self._mailbox.wait_for_code(
                self._mb_account,
                keyword="",  # codex CLI OAuth 邮件 subject 不固定, 不加 keyword 限制
                timeout=int(timeout),
                before_ids=self._before_ids,
                exclude_codes=(exclude_codes or set()),
            )
        except Exception as exc:
            self._log_fn(
                "[codex OAuth email adapter] 邮箱取码异常 "
                f"({type(exc).__name__})",
            )
            return ""
