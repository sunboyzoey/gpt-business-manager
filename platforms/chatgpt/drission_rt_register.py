"""DrissionPage 全程跑 Codex OAuth signup 拿 RT。

跟 platforms/chatgpt/drission_rt_acquirer.acquire_rt_via_drission 的关系:
- acquirer 处理「已有账号 → 登录 → 拿 RT」(用密码或 passwordless 都行)
- 本模块处理「新邮箱 → 注册 + 拿 RT」一气呵成:
    Codex OAuth URL(screen_hint=signup) → 填邮箱 → /create-account/password 填密码
    → /email-verification OTP → /about-you 填资料 → consent/callback → POST /oauth/token

强制 signup:本模块**自己构造** OAuth URL(`screen_hint=signup`),
不复用 drission_rt_acquirer._build_codex_oauth_url(那个是 login_or_signup,
服务端可能误判已存在账号走 /log-in/password)。

复用:
- drission_rt_acquirer 常量(CODEX_CLIENT_ID 等) + 通用 helper(PKCE / email / OTP / code 交换)
- drission_register.create_browser / _is_browser_closed / generate_name / generate_birthday / generate_password

调用方:services.rt_register_runner.RTRegisterRunner(browser_mode=headless|headed)
"""
from __future__ import annotations

import secrets
import time
import urllib.parse
import uuid
from typing import Any, Callable

from platforms.chatgpt.drission_rt_acquirer import (
    CODEX_CLIENT_ID,
    CODEX_REDIRECT_URI,
    CODEX_SCOPE,
    OAUTH_ISSUER,
    _exchange_code_for_tokens,
    _extract_code_from_url,
    _fill_email,
    _fill_otp,
    _generate_pkce,
    _snapshot_existing_mail_ids,
    _wait_url_contains,
)
from platforms.chatgpt.drission_register import (
    _is_browser_closed,
    create_browser,
    generate_birthday,
    generate_name,
    generate_password,
)


DEFAULT_TOTAL_TIMEOUT = 240
DEFAULT_NAV_TIMEOUT = 30
DEFAULT_PASSWORD_WAIT = 15
DEFAULT_OTP_PAGE_WAIT = 20
DEFAULT_OTP_TIMEOUT = 120
DEFAULT_ABOUT_YOU_WAIT = 20
DEFAULT_CALLBACK_WAIT = 45


def _capture_chatgpt_session(page: Any, email: str, log_fn: Callable) -> tuple[dict, str]:
    """Best-effort capture of the fresh ChatGPT web session.

    Codex OAuth proves the identity but its token response is not a ChatGPT
    Session Cookie.  Visiting ChatGPT in the same browser profile can establish
    that session; only return cookies after `/api/auth/session` confirms the
    exact registration email.
    """
    try:
        from platforms.chatgpt.account_security import (
            _collect_page_cookies,
            _session_cookie_from_map,
            _session_identity,
        )

        page.get("https://chatgpt.com/", timeout=DEFAULT_NAV_TIMEOUT)
        time.sleep(1.2)
        identity = _session_identity(page)
        actual = str(identity.get("email") or "").strip().casefold()
        expected = str(email or "").strip().casefold()
        if not identity.get("authenticated") or actual != expected:
            log_fn("  [drission] ChatGPT Web 会话未能确认，2FA 将保留为待重试")
            return {}, ""
        cookies = _collect_page_cookies(page)
        session_token = _session_cookie_from_map(cookies)
        log_fn("  [drission] 已确认并保存注册账号的 ChatGPT Web 会话")
        return cookies, session_token
    except Exception:
        log_fn("  [drission] ChatGPT Web 会话捕获失败，2FA 将保留为待重试")
        return {}, ""


def _build_signup_oauth_url(code_challenge: str, state: str, device_id: str) -> str:
    """构造**强制 signup** 的 Codex OAuth URL。

    与 drission_rt_acquirer._build_codex_oauth_url 的差异:
    - `screen_hint=signup`(强制走 /create-account/password,不让 OpenAI 自动判定为
      "邮箱已存在" 而路由到 /log-in/password)
    - 加上 captured 浏览器流里的全套 Codex CLI 扩展参数(audience、ext-oai-did、
      auth_session_logging_id、ext-passkey-client-capabilities 等),让 OpenAI 把
      请求当成正版 Codex CLI 发起,signup 流程走完整链路。
    """
    params = {
        "response_type": "code",
        "client_id": CODEX_CLIENT_ID,
        "audience": "https://api.openai.com/v1",
        "redirect_uri": CODEX_REDIRECT_URI,
        "scope": CODEX_SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "prompt": "login",
        "screen_hint": "signup",
        "ext-oai-did": device_id,
        "auth_session_logging_id": str(uuid.uuid4()),
        "ext-passkey-client-capabilities": "1111",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
    }
    return f"{OAUTH_ISSUER}/oauth/authorize?" + urllib.parse.urlencode(params)


def register_via_drission(
    *,
    email: str,
    proxy: str | None,
    extra_config: dict,
    log_fn: Callable[[str], None],
    email_adapter: Any,
    headless: bool = True,
    total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
) -> dict[str, Any]:
    """DrissionPage 全流程 Codex OAuth signup → 拿 RT。

    email: 新邮箱(BUSINESS 子域)
    email_adapter: _BusinessOAuthEmailAdapter,需要 wait_for_verification_code(email, timeout, ...)
    返回: {email, password, name, birthdate, access_token, refresh_token, id_token, code_verifier}
    """
    if not email:
        raise RuntimeError("email 不能为空")
    if email_adapter is None:
        raise RuntimeError("email_adapter 未提供")

    password = generate_password()
    name = generate_name()
    birthday = generate_birthday()
    full_name = f"{name['first']} {name['last']}".strip()
    birthdate_iso = f"{birthday['year']:04d}-{birthday['month']:02d}-{birthday['day']:02d}"

    code_verifier, code_challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)
    device_id = str(uuid.uuid4())
    oauth_url = _build_signup_oauth_url(code_challenge, state, device_id)

    # snapshot 当前邮件 baseline,避免读到 OTP 之前的残留邮件
    try:
        _snapshot_existing_mail_ids(email_adapter, log_fn)
    except Exception as exc:
        log_fn(f"  [drission] snapshot baseline 失败(忽略): {exc}")

    log_fn(f"  [drission] 启动 Chromium (headless={headless}, proxy={'set' if proxy else 'none'})")
    page = create_browser(proxy=proxy or "", headless=headless)
    if page is None:
        raise RuntimeError("DrissionPage 启动 Chromium 失败")

    deadline = time.time() + total_timeout
    password_set_proven = False
    try:
        log_fn("  [drission] 1/6 打开 OAuth 授权页 (screen_hint=signup,强制 signup 流程)")
        try:
            page.get(oauth_url, timeout=DEFAULT_NAV_TIMEOUT)
        except Exception as exc:
            raise RuntimeError(f"OAuth 授权页加载失败: {exc}")

        log_fn(f"  [drission] 2/6 填邮箱: {email}")
        if not _fill_email(page, email, log_fn):
            raise RuntimeError("DrissionPage 填邮箱失败")

        # 等服务端决定路由 — screen_hint=signup 应当强制 /create-account/password
        log_fn("  [drission] 2.5/6 等待 /create-account/password")
        route_deadline = time.time() + DEFAULT_PASSWORD_WAIT
        route = ""
        while time.time() < route_deadline:
            if _is_browser_closed(page):
                raise RuntimeError("浏览器已关闭")
            cur = ""
            try:
                cur = page.url or ""
            except Exception:
                cur = ""
            if "/create-account/password" in cur:
                route = "signup_password"
                break
            if "/log-in/password" in cur:
                route = "login_password_unexpected"
                break
            if "/email-verification" in cur or "/log-in/code" in cur:
                # screen_hint=signup 下不应当出现,但服务端有 ABTest,留个兜底
                route = "otp_direct"
                break
            if "/about-you" in cur:
                route = "about_you_direct"
                break
            time.sleep(0.4)

        if route == "login_password_unexpected":
            # screen_hint=signup 仍被路由到 login = OpenAI 把该邮箱/子域判已存在,
            # 按用户要求:不切 OTP 登录,直接硬失败,提示换子域/代理
            raise RuntimeError(
                "screen_hint=signup 下 OpenAI 仍把邮箱判已存在,路由到 /log-in/password。"
                "BUSINESS 子域可能被识别为 wildcard catch-all 或 IP 已被风控,请更换子域或代理 IP。"
            )
        if not route:
            try:
                cur = page.url or ""
            except Exception:
                cur = ""
            raise RuntimeError(f"邮箱提交后未识别页面路由,当前 URL={cur[:200]}")

        log_fn(f"  [drission] 路由判定: {route}")

        if route == "signup_password":
            log_fn(f"  [drission] 3/6 填注册密码并提交 (password 长度 {len(password)})")
            _signup_fill_password(page, password, log_fn)

            log_fn("  [drission] 等待跳到 email-verification 页")
            ok = _wait_url_contains(page, "/email-verification", DEFAULT_OTP_PAGE_WAIT) or \
                 _wait_url_contains(page, "/log-in/code", DEFAULT_OTP_PAGE_WAIT)
            if not ok:
                try:
                    cur = page.url or ""
                except Exception:
                    cur = ""
                if "/about-you" in cur:
                    route = "about_you_direct"
                else:
                    raise RuntimeError(f"密码提交后未跳到 OTP 页,当前 URL={cur[:200]}")
            # Only this branch submitted a signup password, and reaching an
            # OTP/about-you page proves the password page accepted it.  The
            # otp_direct/about_you_direct A/B routes must remain unproven.
            try:
                current_url = page.url or ""
            except Exception:
                current_url = ""
            if "/create-account/password" in current_url:
                raise RuntimeError("密码提交后仍停留在密码页，无法确认密码已设置")
            password_set_proven = True

        if route != "about_you_direct":
            log_fn("  [drission] 4/6 等 OTP 邮件并提交")
            _grab_and_fill_otp(page, email_adapter, email, log_fn, deadline)

        log_fn("  [drission] 5/6 等待 /about-you 页")
        if not _wait_url_contains(page, "/about-you", DEFAULT_ABOUT_YOU_WAIT):
            try:
                cur = page.url or ""
            except Exception:
                cur = ""
            if CODEX_REDIRECT_URI[:20] in cur or "?code=" in cur:
                log_fn("  [drission] 跳过 about-you,服务端直接回调")
            else:
                raise RuntimeError(f"OTP 通过后未跳到 /about-you,当前 URL={cur[:200]}")
        else:
            log_fn(f"  [drission] 填资料: name={full_name}, birthdate={birthdate_iso}")
            _fill_about_you(page, full_name, birthday, log_fn)

        log_fn("  [drission] 6/6 等回调 URL with code=")
        callback_url = _wait_for_callback(page, deadline, log_fn)
        code = _extract_code_from_url(callback_url)
        if not code:
            raise RuntimeError(f"未能从回调 URL 抠出 code: {callback_url[:200]}")

        log_fn(f"  [drission] 交换 code → access_token / refresh_token")
        tokens = _exchange_code_for_tokens(code, code_verifier, proxy, log_fn)
        cookies, session_token = _capture_chatgpt_session(page, email, log_fn)

        return {
            "email": email,
            "password": password,
            "password_set_proven": password_set_proven,
            "name": full_name,
            "birthdate": birthdate_iso,
            "access_token": tokens.get("access_token", "") or "",
            "refresh_token": tokens.get("refresh_token", "") or "",
            "id_token": tokens.get("id_token", "") or "",
            "session_token": session_token,
            "cookies": cookies,
            "workspace_id": "",
            "device_id": device_id,
            "code_verifier": code_verifier,
        }
    finally:
        try:
            page.quit(force=True)
        except Exception:
            try:
                page.close()
            except Exception:
                pass


# ───────── 内部 helper ─────────

def _signup_fill_password(page, password: str, log_fn: Callable) -> None:
    """在 /create-account/password 页面填密码并提交。逻辑取自 drission_register.do_register Step 3。"""
    pwd_input = None
    for sel in ('css:input[type="password"]',):
        try:
            inp = page.ele(sel, timeout=8)
            if inp:
                pwd_input = inp
                break
        except Exception:
            continue

    if not pwd_input:
        # 检查邮箱已存在错误
        try:
            page_text = (page.html or "").lower()
        except Exception:
            page_text = ""
        if "already exists" in page_text or "已存在" in page_text:
            raise RuntimeError("该邮箱已注册(create-account 页报 already_exists)")
        raise RuntimeError("/create-account/password 上未找到密码输入框")

    try:
        page.run_js('arguments[0].scrollIntoView({behavior:"instant",block:"center"})', pwd_input)
    except Exception:
        pass
    time.sleep(0.2)
    try:
        page.run_js('arguments[0].click(); arguments[0].focus()', pwd_input)
    except Exception:
        pass
    time.sleep(0.2)
    try:
        pwd_input.clear()
    except Exception:
        pass
    pwd_input.input(password, clear=False)
    try:
        page.run_js('arguments[0].dispatchEvent(new Event("blur", {bubbles: true}))', pwd_input)
    except Exception:
        pass
    time.sleep(0.4)

    submitted = page.run_js("""
        const btn = document.querySelector('button[type="submit"]');
        if (btn) { btn.click(); return 'clicked'; }
        const form = document.querySelector('form');
        if (form) { form.submit(); return 'form_submit'; }
        return false;
    """)
    log_fn(f"    密码提交方式: {submitted}")
    time.sleep(2)

    # 简单的 retry 处理「超时/出错了」错误页
    for retry in range(2):
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if "/create-account/password" not in cur:
            return
        is_timeout = False
        try:
            is_timeout = bool(page.run_js("""
                const text = document.body?.innerText || '';
                return /timed\\s*out|出错了|something\\s+went\\s+wrong/i.test(text);
            """))
        except Exception:
            pass
        if not is_timeout:
            break
        log_fn(f"    密码页疑似超时,点击重试 ({retry + 1})")
        try:
            page.run_js("""
                const btns = document.querySelectorAll('button, [role="button"]');
                for (const b of btns) {
                    const t = (b.textContent || '').trim();
                    if (/重试|try\\s*again/i.test(t)) { b.click(); return true; }
                }
                return false;
            """)
        except Exception:
            pass
        time.sleep(2)


def _grab_and_fill_otp(page, email_adapter, email: str, log_fn: Callable, deadline: float) -> None:
    """收 OTP 并填入。"""
    tried_codes: set[str] = set()
    for attempt in range(4):
        remaining = max(30, int(deadline - time.time()))
        log_fn(f"    [drission] 等待 OTP 邮件 (attempt {attempt + 1}, max {min(DEFAULT_OTP_TIMEOUT, remaining)}s)")
        try:
            code = email_adapter.wait_for_verification_code(
                email=email,
                timeout=min(DEFAULT_OTP_TIMEOUT, remaining),
                exclude_codes=tried_codes,
            )
        except TypeError:
            # 兼容老接口
            code = email_adapter.wait_for_verification_code(timeout=min(DEFAULT_OTP_TIMEOUT, remaining))

        if not code:
            raise RuntimeError("超时未收到 OTP 邮件")
        tried_codes.add(code)
        log_fn(f"    [drission] 已提交第 {attempt + 1} 个 OTP（内容不写入日志）")
        if not _fill_otp(page, code, log_fn):
            raise RuntimeError("DrissionPage 填 OTP 失败")
        # 等 URL 跳离
        time.sleep(2)
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if "/email-verification" not in cur and "/log-in/code" not in cur:
            return
        # 等多几秒看是不是慢
        end = time.time() + 8
        while time.time() < end:
            time.sleep(0.5)
            try:
                cur = page.url or ""
            except Exception:
                cur = ""
            if "/email-verification" not in cur and "/log-in/code" not in cur:
                return
        log_fn("    [drission] OTP 似乎没通过，重试")

    raise RuntimeError("OTP 多次尝试均未通过")


def _fill_about_you(page, full_name: str, birthday: dict, log_fn: Callable) -> None:
    """填 /about-you 页(姓名 + 生日)。逻辑取自 drission_register.do_register Step 5。"""
    # 填姓名
    name_input = None
    for sel in ('css:input[name="name"]', 'css:input[autocomplete="name"]'):
        try:
            inp = page.ele(sel, timeout=5)
            if inp:
                name_input = inp
                break
        except Exception:
            continue
    if name_input:
        try:
            name_input.click()
            name_input.clear()
            name_input.input(full_name, clear=False)
            time.sleep(0.3)
        except Exception as exc:
            log_fn(f"    填姓名异常(忽略): {exc}")

    year = str(birthday["year"])
    month = str(birthday["month"]).zfill(2)
    day = str(birthday["day"]).zfill(2)

    fill_birthday_js = f"""
    (async function() {{
        const sleep = (ms) => new Promise(r => setTimeout(r, ms));
        const dateField = document.querySelector('div[role="group"][id*="birthday"]');
        if (!dateField) {{
            const ageInput = document.querySelector('input[name="age"]');
            if (ageInput) {{
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(ageInput, '{2025 - birthday["year"]}');
                ageInput.dispatchEvent(new Event('input', {{bubbles: true}}));
                ageInput.dispatchEvent(new Event('change', {{bubbles: true}}));
                return 'age';
            }}
            const selects = document.querySelectorAll('.react-aria-Select');
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
            for (const ch of valueStr) {{
                segment.dispatchEvent(new KeyboardEvent('keydown', {{key: ch, code: 'Digit'+ch, bubbles: true}}));
                segment.dispatchEvent(new InputEvent('beforeinput', {{inputType: 'insertText', data: ch, bubbles: true}}));
                segment.dispatchEvent(new InputEvent('input', {{inputType: 'insertText', data: ch, bubbles: true}}));
                await sleep(50);
            }}
            segment.dispatchEvent(new FocusEvent('blur', {{bubbles: true}}));
            await sleep(100);
        }};

        const yearSeg = dateField.querySelector('[role="spinbutton"][data-type="year"]');
        const monthSeg = dateField.querySelector('[role="spinbutton"][data-type="month"]');
        const daySeg = dateField.querySelector('[role="spinbutton"][data-type="day"]');
        await fillSpinbutton(yearSeg, '{year}');
        await sleep(150);
        await fillSpinbutton(monthSeg, '{month}');
        await sleep(150);
        await fillSpinbutton(daySeg, '{day}');
        return 'spinbutton';
    }})();
    """
    try:
        page.run_js(fill_birthday_js)
    except Exception as exc:
        log_fn(f"    填生日 JS 异常(忽略): {exc}")
    time.sleep(0.8)

    # 勾「我同意」复选框(有些国家会出现)
    try:
        page.run_js("""
            const cb = document.querySelector('input[name="allCheckboxes"][type="checkbox"]');
            if (cb && !cb.checked) {
                const label = cb.closest('label');
                if (label) label.click(); else cb.click();
            }
        """)
    except Exception:
        pass
    time.sleep(0.3)

    # 提交
    try:
        btn = page.ele('css:button[type="submit"]', timeout=5)
        if btn:
            btn.click()
    except Exception as exc:
        log_fn(f"    点击 about-you 提交按钮异常(忽略): {exc}")
    time.sleep(2)


def _wait_for_callback(page, deadline: float, log_fn: Callable) -> str:
    """等 page.url 跳到 localhost:1455/auth/callback?code=... 或任意带 code= 的 URL。

    途中若停在 /sign-in-with-chatgpt/codex/consent 页(form 含 workspace_id +
    单个「继续」submit 按钮),自动点 submit 触发 workspace_select → 302 链 → callback。
    """
    consent_clicked = False
    last_url = ""
    while time.time() < deadline:
        if _is_browser_closed(page):
            raise RuntimeError("浏览器已关闭")
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if cur and cur != last_url:
            log_fn(f"    [drission] URL → {cur[:200]}")
            last_url = cur
        if "code=" in cur and ("localhost" in cur or "callback" in cur):
            return cur
        if "code=" in cur and "/oauth/" not in cur:
            return cur
        # consent 页:第一次见到时点「继续」按钮
        if not consent_clicked and "/codex/consent" in cur:
            log_fn("    [drission] 命中 consent 页,点「继续」")
            if _click_consent_continue(page, log_fn):
                consent_clicked = True
                time.sleep(1.0)
            else:
                # 点不到 → 留给下次循环再试一次
                pass
        time.sleep(0.5)
    raise RuntimeError(f"等回调 URL 超时,最后 URL={last_url[:200]}")


def _click_consent_continue(page, log_fn: Callable) -> bool:
    """consent 页 form 只有一个 submit「继续」(英文 build 是 Continue)。直接点。"""
    selectors = (
        'css:form[action*="/codex/consent"] button[type="submit"]',
        'css:button[type="submit"]',
        'text:继续',
        'text:Continue',
        'text:Allow',
        'text:允许',
    )
    for sel in selectors:
        try:
            el = page.ele(sel, timeout=2)
            if el:
                try:
                    el.click()
                    log_fn(f"    ✓ consent 继续按钮命中 selector: {sel}")
                    return True
                except Exception as exc:
                    log_fn(f"    consent 点击异常 ({sel}): {exc}")
                    continue
        except Exception:
            continue
    # JS form submit 兜底
    try:
        ok = page.run_js("""
            const f = document.querySelector('form[action*="codex/consent"]');
            if (f) { f.submit(); return true; }
            return false;
        """)
        if ok:
            log_fn("    ✓ consent JS form.submit() 兜底")
            return True
    except Exception:
        pass
    return False
