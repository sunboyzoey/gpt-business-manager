"""
Grok 浏览器注册引擎 — 基于 DrissionPage + turnstilePatch 扩展。

Turnstile 通过 Chrome 扩展 + 真人化点击自动解决，无需 YesCaptcha。
"""

from __future__ import annotations

import os
import re
import secrets
import time
from typing import Callable, Optional

from DrissionPage import Chromium, ChromiumOptions

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
EXTENSION_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "turnstilePatch"))


def _find_chrome_binary() -> str:
    import glob
    candidates = [
        *glob.glob("/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return ""


def _rand_name():
    firsts = ["James", "John", "Robert", "Emma", "Olivia", "Liam", "Noah", "Ethan",
              "Grace", "Chloe", "Alex", "Jordan", "Taylor", "Morgan", "Casey"]
    lasts = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Davis", "Miller",
             "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White"]
    import random
    return random.choice(firsts), random.choice(lasts)


def _rand_password():
    return "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)


class GrokDrissionRegister:
    TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"

    def __init__(
        self,
        proxy: str = "",
        log_fn: Optional[Callable] = None,
        headless: bool = True,
        cookie_dir: str = "cookies/grok",
        captcha_solver: str = "",
        yescaptcha_key: str = "",
        solver_url: str = "",
    ):
        self.proxy = proxy
        self.log = log_fn or print
        self.headless = headless
        self.cookie_dir = cookie_dir
        self.captcha_solver = captcha_solver
        self.yescaptcha_key = yescaptcha_key
        self.solver_url = solver_url
        self.browser: Optional[Chromium] = None
        self.page = None

    def _start_browser(self):
        if self.headless:
            try:
                from pyvirtualdisplay import Display
                self._display = Display(visible=0, size=(1920, 1080))
                self._display.start()
                self.log("Xvfb 虚拟显示器已启动")
            except ImportError:
                try:
                    import subprocess
                    self._xvfb_proc = subprocess.Popen(
                        ["Xvfb", ":99", "-screen", "0", "1920x1080x24"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                    os.environ["DISPLAY"] = ":99"
                    import time; time.sleep(1)
                    self.log("Xvfb 进程已启动 (:99)")
                except Exception as e:
                    self.log(f"Xvfb 启动失败，回退 headless: {e}")

        co = ChromiumOptions()
        co.auto_port()
        co.set_timeouts(base=1)
        co.add_extension(EXTENSION_PATH)
        chrome_bin = _find_chrome_binary()
        if chrome_bin:
            co.set_browser_path(chrome_bin)
        if self.proxy:
            if "socks" in self.proxy.lower():
                co.set_argument(f"--proxy-server={self.proxy}")
            else:
                co.set_proxy(self.proxy)
        co.set_argument("--no-sandbox")
        co.set_argument("--disable-gpu")
        co.set_argument("--disable-dev-shm-usage")
        co.set_argument("--disable-software-rasterizer")
        co.set_argument("--disable-blink-features=AutomationControlled")
        co.set_argument("--window-size=1920,1080")
        self.browser = Chromium(co)
        self.page = self.browser.latest_tab
        self.log("浏览器已启动")

    def _stop_browser(self):
        if self.browser:
            try:
                self.browser.quit()
            except Exception:
                pass
            self.browser = None
            self.page = None
        if hasattr(self, "_display") and self._display:
            try:
                self._display.stop()
            except Exception:
                pass
            self._display = None
        if hasattr(self, "_xvfb_proc") and self._xvfb_proc:
            try:
                self._xvfb_proc.terminate()
            except Exception:
                pass
            self._xvfb_proc = None

    def _click_email_signup(self, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            clicked = self.page.run_js(r"""
const targets = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = targets.find(el => {
    const text = (el.innerText || el.textContent || '').toLowerCase().replace(/\s+/g, ' ').trim();
    return text.includes('email') || text.includes('sign up with email') || text.includes('邮箱');
});
if (!target) return false;
target.click();
return true;
            """)
            if clicked:
                self.log("点击了邮箱注册按钮")
                return True
            time.sleep(0.5)
        raise RuntimeError("未找到邮箱注册按钮")

    def _fill_email_and_submit(self, email: str, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.page.run_js("""
const email = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const input = Array.from(document.querySelectorAll(
    'input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"]'
)).find(n => isVisible(n) && !n.disabled && !n.readOnly);
if (!input) return 'not-ready';
input.focus();
input.click();
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
const tracker = input._valueTracker;
if (tracker) tracker.setValue('');
if (nativeSetter) { nativeSetter.call(input, ''); nativeSetter.call(input, email); }
else { input.value = ''; input.value = email; }
input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, cancelable: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
input.dispatchEvent(new Event('blur', { bubbles: true }));
return String(input.value || '') === String(email || '') ? 'filled' : 'fill-failed';
            """, email)
            if result == "not-ready":
                time.sleep(0.5)
                continue
            if result != "filled":
                time.sleep(0.5)
                continue
            self.log(f"邮箱已填入: {email}")
            time.sleep(0.5)
            self.page.run_js(r"""
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button'));
const btn = buttons.find(n => {
    const text = (n.innerText || n.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase();
    const rect = n.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;
    return text === 'sign up' || text.includes('continue') || text.includes('next')
           || text.includes('submit') || text.includes('send code')
           || text === '继续' || text === '下一步' || text === '注册';
});
if (btn && !btn.disabled) btn.click();
            """)
            self.log("已提交邮箱")
            return
        raise RuntimeError("邮箱输入超时")

    def _fill_code_and_submit(self, code: str, timeout=30):
        code_clean = code.strip().replace("-", "")
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.page.run_js("""
const code = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const inputs = Array.from(document.querySelectorAll(
    'input[data-testid="code"], input[name="code"], input[autocomplete="one-time-code"], ' +
    'input[inputmode="numeric"], input[type="text"][maxlength="6"]'
)).filter(n => isVisible(n) && !n.disabled && !n.readOnly);
if (inputs.length === 0) return 'not-ready';
const input = inputs[0];
input.focus();
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) { nativeSetter.call(input, code); } else { input.value = code; }
input.dispatchEvent(new InputEvent('input', { bubbles: true, data: code, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
return String(input.value || '').replace(/-/g, '') === code ? 'filled' : 'fill-failed';
            """, code_clean)
            if result == "not-ready":
                time.sleep(0.5)
                continue
            if result == "filled":
                self.log(f"验证码已填入: {code_clean}")
                time.sleep(0.5)
                self.page.run_js(r"""
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button'));
const btn = buttons.find(n => {
    const text = (n.innerText || n.textContent || '').replace(/\s+/g, '').toLowerCase();
    return text.includes('verify') || text.includes('continue') || text.includes('submit')
           || text.includes('验证') || text.includes('确认');
});
if (btn && !btn.disabled) btn.click();
                """)
                self.log("已提交验证码")
                return
            time.sleep(0.5)
        raise RuntimeError("验证码输入超时")

    def _get_turnstile_token(self, timeout=60):
        self.log("等待 Turnstile 验证...")
        try:
            self.page.run_js("try { turnstile.reset() } catch(e) { }")
        except Exception:
            pass

        # Phase 1: 尝试浏览器真人点击（15秒）
        click_deadline = time.time() + 30
        clicked_count = 0
        while time.time() < click_deadline:
            try:
                token = self.page.run_js("try { return turnstile.getResponse() } catch(e) { return null }")
                if token:
                    self.log(f"Turnstile 浏览器点击通过: {str(token)[:40]}...")
                    return token
            except Exception:
                pass
            try:
                challenge = self.page.ele("@name=cf-turnstile-response", timeout=1)
                wrapper = challenge.parent()
                iframe = wrapper.shadow_root.ele("tag:iframe", timeout=1)
                if clicked_count == 0:
                    iframe.run_js("""
window.dtp = 1;
let sx = Math.floor(Math.random()*400)+800, sy = Math.floor(Math.random()*200)+400;
Object.defineProperty(MouseEvent.prototype, 'screenX', { value: sx });
Object.defineProperty(MouseEvent.prototype, 'screenY', { value: sy });
                    """)
                body = iframe.ele("tag:body", timeout=1).shadow_root
                btn = body.ele("tag:input", timeout=1)
                btn.click()
                clicked_count += 1
            except Exception:
                pass
            time.sleep(2)

        # Phase 2: Fallback 到 API Solver
        self.log("浏览器点击未通过，尝试 API Solver...")
        api_token = self._solve_turnstile_api()
        if api_token:
            self._inject_turnstile_token(api_token)
            return api_token

        raise RuntimeError("Turnstile 验证失败（浏览器点击 + API Solver 均未通过）")

    def _solve_turnstile_api(self) -> str:
        """使用 YesCaptcha API 解决 Turnstile。"""
        if not self.yescaptcha_key:
            self.log("[Turnstile] 未配置 YesCaptcha key")
            return ""

        page_url = "https://accounts.x.ai/sign-up"
        try:
            import requests
            self.log("[Turnstile] 调用 YesCaptcha 创建任务...")
            create_resp = requests.post(
                "https://api.yescaptcha.com/createTask",
                json={
                    "clientKey": self.yescaptcha_key,
                    "task": {
                        "type": "TurnstileTaskProxylessM1",
                        "websiteURL": page_url,
                        "websiteKey": self.TURNSTILE_SITEKEY,
                    },
                },
                timeout=30,
            ).json()
            task_id = create_resp.get("taskId")
            if not task_id:
                self.log(f"[Turnstile] YesCaptcha 创建任务失败: {create_resp}")
                return ""
            self.log(f"[Turnstile] 任务已创建: {task_id}")

            for _ in range(60):
                time.sleep(3)
                result_resp = requests.post(
                    "https://api.yescaptcha.com/getTaskResult",
                    json={"clientKey": self.yescaptcha_key, "taskId": task_id},
                    timeout=30,
                ).json()
                status = result_resp.get("status", "")
                if status == "ready":
                    token = result_resp.get("solution", {}).get("token", "")
                    if token:
                        self.log(f"[Turnstile] YesCaptcha 成功: {token[:40]}...")
                        return token
                elif status == "failed" or result_resp.get("errorId"):
                    self.log(f"[Turnstile] YesCaptcha 失败: {result_resp}")
                    return ""
        except Exception as e:
            self.log(f"[Turnstile] YesCaptcha 异常: {e}")
        return ""

    def _inject_turnstile_token(self, token: str):
        """将 API Solver 获取的 token 注入到页面表单。"""
        self.page.run_js("""
const token = arguments[0];
const ci = document.querySelector('input[name="cf-turnstile-response"]');
if (ci) {
    const ns = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value')?.set;
    if(ns) ns.call(ci, token); else ci.value = token;
    ci.dispatchEvent(new Event('input',{bubbles:true}));
    ci.dispatchEvent(new Event('change',{bubbles:true}));
}
        """, token)
        self.log("Turnstile token 已注入页面")

    def _fill_profile_and_submit(self, given_name, family_name, password, timeout=120):
        deadline = time.time() + timeout

        while time.time() < deadline:
            ready = self.page.run_js(
                "return !!document.querySelector('input[name=\"givenName\"],input[autocomplete=\"given-name\"]')"
            )
            if ready:
                break
            time.sleep(0.5)

        try:
            gi = self.page.ele('@name=givenName', timeout=5)
            gi.clear()
            gi.input(given_name)
            time.sleep(0.3)
            fi = self.page.ele('@name=familyName', timeout=5)
            fi.clear()
            fi.input(family_name)
            time.sleep(0.3)
            pi = self.page.ele('@type=password', timeout=5)
            pi.clear()
            pi.input(password)
            time.sleep(0.3)
            self.log(f"资料已填入: {given_name} {family_name}")
        except Exception as e:
            raise RuntimeError(f"填写资料失败: {e}")

        ts_state = self.page.run_js("""
const ci = document.querySelector('input[name="cf-turnstile-response"]');
if (!ci) return 'none';
return String(ci.value||'').trim() ? 'solved' : 'pending';
        """)
        if ts_state == "pending":
            self.log("检测到 Turnstile，开始自动解决...")
            token = self._get_turnstile_token()
            if token:
                self._inject_turnstile_token(token)

        time.sleep(1)
        # 完成注册按钮文案随 x.ai 界面语言变化: 中文"完成注册" / 英文"Complete sign up"。
        # 之前只匹配英文, 中文界面下按钮找不到、JS fallback 静默 no-op(if(btn) 为假),
        # 导致表单从未提交、拿不到 SSO cookie —— 这里改成中英双语 + 真正校验点到没点。
        res = self.page.run_js("""
const norm = s => (s||'').trim();
const btns = Array.from(document.querySelectorAll('button, input[type="submit"], [role="button"]'));
const bad = /cookie|隐私|返回|\\bback\\b|cancel|取消|拒绝|reject|设置|filter|clear|apply|allow|接受|允许|确认我的选择/i;
// 1) 精确匹配完成注册按钮
let target = btns.find(b => {
    const t = norm(b.innerText||b.value).toLowerCase();
    return t === '完成注册' || t === 'complete sign up' || t === 'complete signup' || t === '注册';
});
// 2) 兜底: submit 按钮且含"完成/注册/sign up", 排除 cookie/导航等干扰
if (!target) target = btns.find(b => {
    const t = norm(b.innerText||b.value).toLowerCase();
    if (!t || bad.test(t)) return false;
    return (b.type === 'submit') && (t.includes('完成') || t.includes('注册') || t.includes('sign up') || t.includes('signup'));
});
if (!target) return JSON.stringify({ok:false, reason:'not-found'});
try { target.scrollIntoView({block:'center'}); } catch(e){}
target.click();
return JSON.stringify({ok:true, text: norm(target.innerText||target.value), type: target.type||''});
        """)
        import json as _json
        try:
            info = _json.loads(res) if isinstance(res, str) else (res or {})
        except Exception:
            info = {}
        if info.get("ok"):
            self.log(f"已点击完成注册按钮: {info.get('text')!r}")
        else:
            # 兜底: 用 DrissionPage 原生点第一个含"完成注册/Complete"的 submit 按钮
            clicked = False
            for kw in ("完成注册", "Complete sign up", "注册"):
                try:
                    btn = self.page.ele(f'tag:button@@text():{kw}', timeout=3)
                    if btn:
                        btn.click()
                        self.log(f"已点击完成注册按钮(原生: {kw})")
                        clicked = True
                        break
                except Exception:
                    continue
            if not clicked:
                raise RuntimeError("未找到完成注册按钮(界面文案可能又变了,请人工确认)")
        time.sleep(3)


    def _wait_for_sso_cookie(self, timeout=30):
        self.log("等待 SSO cookie...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                cookies = self.page.cookies(all_domains=True, all_info=True) or []
                for item in cookies:
                    name = str(item.get("name", "") if isinstance(item, dict) else getattr(item, "name", "")).strip()
                    value = str(item.get("value", "") if isinstance(item, dict) else getattr(item, "value", "")).strip()
                    if name == "sso" and value:
                        self.log(f"SSO cookie 已获取: {value[:30]}...")
                        return value
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError("未获取到 SSO cookie")

    def _extract_sso_rw(self):
        try:
            cookies = self.page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                name = str(item.get("name", "") if isinstance(item, dict) else getattr(item, "name", "")).strip()
                value = str(item.get("value", "") if isinstance(item, dict) else getattr(item, "value", "")).strip()
                if name in ("sso-rw", "sso_rw") and value:
                    return value
        except Exception:
            pass
        return ""

    def _extract_all_cookies(self) -> dict:
        result = {}
        try:
            cookies = self.page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                name = str(item.get("name", "") if isinstance(item, dict) else getattr(item, "name", "")).strip()
                value = str(item.get("value", "") if isinstance(item, dict) else getattr(item, "value", "")).strip()
                if name and value:
                    result[name] = value
        except Exception:
            pass
        return result

    def _save_cookie_json(self, email: str, cookie_dict: dict, *, sso: str = "", sso_rw: str = "") -> str:
        import json
        from datetime import datetime, timezone

        if sso and "sso" not in cookie_dict:
            cookie_dict["sso"] = sso
        if sso_rw and "sso-rw" not in cookie_dict:
            cookie_dict["sso-rw"] = sso_rw

        cookie_list = [
            {"name": k, "value": v, "domain": ".grok.com", "path": "/", "secure": True, "httpOnly": True}
            for k, v in cookie_dict.items()
        ]
        payload = {
            "platform": "grok",
            "email": str(email or "").strip(),
            "cookies": cookie_dict,
            "cookie_list": cookie_list,
            "cookie_header": "; ".join(f"{k}={v}" for k, v in cookie_dict.items()),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        os.makedirs(self.cookie_dir, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(email or "grok").strip())
        file_path = os.path.abspath(os.path.join(self.cookie_dir, f"{safe_name}.json"))
        with open(file_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2)
        return file_path

    def register(
        self,
        email: str,
        password: Optional[str] = None,
        otp_callback: Optional[Callable[[], str]] = None,
    ) -> dict:
        if not password:
            password = _rand_password()
        given_name, family_name = _rand_name()

        try:
            self._start_browser()

            self.log("Step 1: 打开注册页...")
            self.page.get(SIGNUP_URL)
            time.sleep(2)

            self.log("Step 2: 点击邮箱注册...")
            self._click_email_signup()
            time.sleep(1)

            self.log("Step 3: 输入邮箱...")
            self._fill_email_and_submit(email)
            time.sleep(2)

            self.log("Step 4: 等待验证码...")
            if not otp_callback:
                raise RuntimeError("需要 otp_callback 获取验证码")
            code = otp_callback() or ""
            if not code:
                raise RuntimeError("未获取到验证码")

            self.log("Step 5: 输入验证码...")
            self._fill_code_and_submit(code)
            time.sleep(2)

            self.log("Step 6: 填写资料 + 解决 Turnstile + 提交...")
            self._fill_profile_and_submit(given_name, family_name, password)

            self.log("Step 7: 获取 SSO...")
            sso = self._wait_for_sso_cookie()
            sso_rw = self._extract_sso_rw()

            all_cookies = self._extract_all_cookies()
            cookie_file = ""
            try:
                cookie_file = self._save_cookie_json(email, all_cookies, sso=sso, sso_rw=sso_rw)
                self.log(f"Cookie 已保存: {cookie_file}")
            except Exception as e:
                self.log(f"Cookie 保存失败: {e}")

            self.log(f"注册成功! email={email}")
            return {
                "email": email,
                "password": password,
                "given_name": given_name,
                "family_name": family_name,
                "sso": sso,
                "sso_rw": sso_rw,
                "cookies": all_cookies,
                "cookie_file": cookie_file,
            }
        finally:
            self._stop_browser()
