"""DrissionPage 全程接管的 codex OAuth 补 RT 实现。

为什么需要这个:
- 原 protocol(curl_cffi) 模式在 OpenAI 新流程下卡 workspace_select bug:
  workspace/select 200 后 continue_url 跑去 /codex/organization 死路
- OAuthClient(browser_mode='headless') 只用 Camoufox 解 Sentinel 反爬,
  主 OAuth flow 仍走 curl_cffi → 死循环依然
- 这里用 DrissionPage 启动 Chromium 全程接管:浏览器自己跑完整 OAuth,
  OpenAI 看到的就是"真浏览器",workspace_select / consent / callback
  redirect 全部 JS 自动处理

流程:
  1. 启动 Chromium(可 headed/headless)
  2. 注入 codex CLI 风格的 OAuth start URL(自带 PKCE)
  3. 未启用 2FA:填邮箱 → 等邮箱 OTP → 填 OTP
     已启用 2FA:填邮箱 → ChatGPT 密码 → 按页面完成追加邮箱验证 / Authenticator TOTP
  4. 浏览器自动跑完 consent / workspace_select / callback redirect
  5. 拦截 redirect 到 localhost:1455/auth/callback?code=... 的 URL
  6. 用 code + code_verifier 走 HTTP POST /oauth/token 换 access_token / refresh_token
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable

from services.chatgpt_oauth_failure import OAuthAttemptFailure, normalize_oauth_failure
from platforms.chatgpt.sms_timeout import SmsWaitProgress, resolve_sms_timeout

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid email profile offline_access"
OAUTH_ISSUER = "https://auth.openai.com"
TOKEN_ENDPOINT = f"{OAUTH_ISSUER}/oauth/token"

DEFAULT_BROWSER_TIMEOUT = 180          # 总流程超时
DEFAULT_OTP_TIMEOUT = 90               # 等 OTP 邮件超时
DEFAULT_NAV_TIMEOUT = 30               # 单次页面跳转超时
_DRISSION_CLEANUP_INTERVAL_SECONDS = 10 * 60
_DRISSION_CLEANUP_MIN_AGE_SECONDS = 30 * 60
_DRISSION_CLEANUP_MAX_DELETE = 1000
_DRISSION_CLEANUP_LOCK = threading.Lock()
_DRISSION_CLEANUP_LAST_AT = 0.0


def _drission_auto_port_data_dir() -> Path:
    """返回 DrissionPage 默认临时 Chrome profile 目录。"""
    return Path(tempfile.gettempdir()) / "DrissionPage" / "autoPortData"


def _extract_active_drission_user_data_dirs_from_ps_output(output: str) -> set[str]:
    """从 ps 命令输出里提取正在运行的 DrissionPage Chrome user-data-dir。"""
    active: set[str] = set()
    pattern = re.compile(r"--user-data-dir=(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))")
    for match in pattern.finditer(output or ""):
        raw = match.group(1) or match.group(2) or match.group(3) or ""
        normalized = raw.strip()
        if not normalized:
            continue
        if "/DrissionPage/autoPortData/" in normalized.replace("\\", "/"):
            active.add(normalized)
    return active


def _active_drission_user_data_dirs() -> set[str]:
    """列出当前仍被 Chrome 使用的 DrissionPage profile 目录。"""
    if os.name == "nt":
        return set()
    try:
        proc = subprocess.run(
            ["ps", "axo", "command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return _extract_active_drission_user_data_dirs_from_ps_output(proc.stdout or "")
    except Exception:
        return set()


def _cleanup_stale_drission_user_dirs(
    *,
    base_dir: Path,
    active_dirs: set[str],
    min_age_seconds: int,
    max_delete: int,
    log_fn: Callable,
    now: float | None = None,
) -> dict[str, int]:
    """删除旧的非活跃 DrissionPage 临时 profile。

    只删除 autoPortData 下的数字端口目录；正在被 Chrome 使用或刚创建的目录保留。
    """
    now = time.time() if now is None else float(now)
    result = {
        "total": 0,
        "deleted": 0,
        "skipped_active": 0,
        "skipped_recent": 0,
        "skipped_other": 0,
        "failed": 0,
    }
    if not base_dir.exists():
        return result

    try:
        candidates = [p for p in base_dir.iterdir() if p.is_dir()]
    except Exception as exc:
        try:
            log_fn(f"  [DrissionPage cleanup] 扫描失败: {exc}")
        except Exception:
            pass
        result["failed"] += 1
        return result

    result["total"] = len(candidates)
    # 先删最旧的,避免一次扫描阻塞太久。
    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else now)
    active_norm = {str(Path(p)) for p in active_dirs}
    for path in candidates:
        if result["deleted"] >= max_delete:
            break
        if not path.name.isdigit():
            result["skipped_other"] += 1
            continue
        if str(path) in active_norm:
            result["skipped_active"] += 1
            continue
        try:
            age = now - path.stat().st_mtime
        except FileNotFoundError:
            continue
        except Exception:
            result["failed"] += 1
            continue
        if age < min_age_seconds:
            result["skipped_recent"] += 1
            continue
        try:
            shutil.rmtree(path)
            result["deleted"] += 1
        except FileNotFoundError:
            continue
        except Exception:
            result["failed"] += 1
    return result


def _cleanup_stale_drission_user_dirs_if_due(log_fn: Callable) -> None:
    """限频清理 DrissionPage 历史 profile，避免 autoPortData 无限膨胀。"""
    global _DRISSION_CLEANUP_LAST_AT
    now = time.time()
    with _DRISSION_CLEANUP_LOCK:
        if now - _DRISSION_CLEANUP_LAST_AT < _DRISSION_CLEANUP_INTERVAL_SECONDS:
            return
        _DRISSION_CLEANUP_LAST_AT = now
    base_dir = _drission_auto_port_data_dir()
    active = _active_drission_user_data_dirs()
    result = _cleanup_stale_drission_user_dirs(
        base_dir=base_dir,
        active_dirs=active,
        min_age_seconds=_DRISSION_CLEANUP_MIN_AGE_SECONDS,
        max_delete=_DRISSION_CLEANUP_MAX_DELETE,
        log_fn=log_fn,
        now=now,
    )
    if result["deleted"] or result["failed"] or result["total"] >= 50:
        try:
            log_fn(
                "  [DrissionPage cleanup] "
                f"目录={base_dir}, 总数={result['total']}, 删除={result['deleted']}, "
                f"活跃跳过={result['skipped_active']}, 新目录跳过={result['skipped_recent']}, "
                f"失败={result['failed']}"
            )
        except Exception:
            pass


def _snapshot_existing_mail_ids(email_adapter, log_fn: Callable) -> int:
    """触发新 OTP 之前,把 CF Worker D1 当前邮件 mid 加入 adapter._seen_ids。

    防止 wait_for_verification_code 拉到该邮箱"注册时残留的旧 OTP"被 OpenAI 拒。
    单号测试时 D1 一般干净所以没暴露这个 bug,大批量并发跑老号(D1 有历史邮件)时
    会大概率拉到旧 OTP → OpenAI 拒 → 0% 成功率。

    返回快照入 baseline 的邮件数。
    """
    try:
        import requests
        api = str(getattr(email_adapter, "_api", "") or "").strip().rstrip("/")
        email = str(getattr(email_adapter, "_email", "") or "")
        admin = str(getattr(email_adapter, "_admin_token", "") or "")
        custom = str(getattr(email_adapter, "_custom_auth", "") or "")
        seen = getattr(email_adapter, "_seen_ids", None)
        if not api or not email or seen is None:
            return 0
        headers = {"x-admin-auth": admin} if admin else {}
        if custom:
            headers["x-custom-auth"] = custom
        resp = requests.get(
            f"{api}/admin/mails",
            params={"limit": 100, "offset": 0, "address": email},
            headers=headers, timeout=10,
        )
        if resp.status_code != 200:
            log_fn(f"  [baseline] snapshot HTTP {resp.status_code}, 跳过")
            return 0
        added = 0
        for m in (resp.json() or {}).get("results") or []:
            mid = m.get("id")
            if mid is not None and mid not in seen:
                seen.add(mid)
                added += 1
        if added:
            log_fn(f"  [baseline] CF D1 已有 {added} 条历史邮件,seen_ids 已预填(后续只读新邮件)")
        return added
    except Exception as e:
        log_fn(f"  [baseline] snapshot 异常(忽略): {e}")
        return 0


def _prepare_oauth_email_baseline(email_adapter: Any, log_fn: Callable) -> bool:
    """Prepare optional step-up mail before navigation, without fetching a code.

    An empty mailbox is a valid baseline, but a failed/unsupported snapshot is
    not. Never lazily snapshot after OpenAI has already sent the challenge.
    """
    if email_adapter is None:
        return False
    try:
        prepare = getattr(email_adapter, "prepare_for_verification", None)
        return bool(callable(prepare) and prepare() is True)
    except Exception:
        # Provider exceptions may contain access tokens and mailbox passwords.
        log_fn("  [DrissionPage] 邮箱验证准备失败；若后续要求邮箱验证，将明确停止")
        return False


def _is_oauth_email_challenge(page: Any) -> bool:
    """Only an explicit email challenge on the trusted auth origin is eligible."""
    from platforms.chatgpt.account_security import (
        _is_email_verification_challenge,
        is_authenticator_challenge,
    )

    try:
        parsed = urllib.parse.urlsplit(str(page.url or ""))
        if (
            parsed.scheme != "https"
            or parsed.hostname != "auth.openai.com"
            or parsed.port not in (None, 443)
            or parsed.path.rstrip("/") not in {"/email-verification", "/log-in/code"}
        ):
            return False
    except (AttributeError, TypeError, ValueError):
        return False
    return not is_authenticator_challenge(page) and _is_email_verification_challenge(page)


def _oauth_email_step_pending(page: Any) -> bool:
    """Do not confuse a transient hidden OTP form with successful validation."""
    from platforms.chatgpt.account_security import is_authenticator_challenge

    try:
        parsed = urllib.parse.urlsplit(str(page.url or ""))
        if not parsed.hostname:
            return True
        if parsed.path.rstrip("/") not in {"/email-verification", "/log-in/code"}:
            return False
    except (AttributeError, TypeError, ValueError):
        return True
    # The following TOTP may share a SPA URL but is a separate challenge. Its
    # visible MFA controls must be handled by the outer state machine instead.
    return not is_authenticator_challenge(page)


def _complete_oauth_email_challenge(
    page: Any,
    email: str,
    email_adapter: Any,
    baseline_ready: bool,
    log_fn: Callable,
    *,
    otp_sent_at: float,
    deadline: float,
    tried_codes: set[str],
) -> None:
    """Complete a mailbox step-up, never treating it as Authenticator proof."""
    from platforms.chatgpt.account_security import _submit_password_verification_code

    waiter = getattr(email_adapter, "wait_for_verification_code", None)
    if not callable(waiter):
        raise RuntimeError("OpenAI 要求追加邮箱验证码，但该账号没有可用的邮箱读取能力")
    if not baseline_ready:
        raise RuntimeError("OpenAI 要求追加邮箱验证码，但登录前的新邮件基线未准备成功；已停止，避免使用旧验证码")
    log_fn("  [DrissionPage] 4/5 OpenAI 要求追加邮箱验证，正在读取本次新验证码")
    last_reason = "未收到本次新验证码"
    for attempt in range(1, 4):
        remaining = min(DEFAULT_OTP_TIMEOUT, int(deadline - time.time()))
        if remaining <= 0:
            break
        code = ""
        try:
            code = str(waiter(
                email=email,
                timeout=remaining,
                otp_sent_at=otp_sent_at,
                exclude_codes=set(tried_codes),
            ) or "").strip()
        except Exception:
            raise RuntimeError("追加邮箱验证失败：读取新邮件验证码异常，请检查邮箱连接") from None
        if not re.fullmatch(r"\d{6}", code):
            last_reason = "未取得有效的六位新验证码"
            log_fn(f"    ↳ 第 {attempt}/3 次未取得有效的新邮件验证码")
            continue
        if code in tried_codes:
            last_reason = "邮箱重复返回已使用的验证码"
            log_fn("    ↳ 邮箱返回已尝试的验证码，已跳过，未重复提交")
            continue
        tried_codes.add(code)
        # The browser can advance while the mailbox request is outstanding.
        # Never fill an email code into a new Authenticator/password form.
        if not _is_oauth_email_challenge(page):
            raise RuntimeError("读取邮箱验证码期间认证页面已变化，未提交验证码，请重新获取 RT")
        log_fn(f"    ✓ 已取得新邮件验证码，正在提交（第 {attempt}/3 次，内容不写入日志）")
        try:
            submitted, error_kind = _submit_password_verification_code(
                page,
                code,
                timeout=min(20, max(1, int(deadline - time.time()))),
                challenge_active=_oauth_email_step_pending,
            )
        except Exception:
            raise RuntimeError("追加邮箱验证失败：验证码填写或提交异常") from None
        finally:
            code = ""
        if submitted:
            log_fn("    ✓ 邮箱验证页面已进入下一步，继续检查 Authenticator 与 OAuth 授权")
            return
        reasons = {
            "input_missing": "邮箱验证码输入框不可用",
            "submit_unavailable": "邮箱验证码确认按钮不可用",
            "invalid": "邮箱验证码被拒绝",
            "expired": "邮箱验证码已过期",
            "rate_limited": "邮箱验证码验证过于频繁，请稍后重试",
            "transition_timeout": "提交邮箱验证码后页面未进入下一步",
        }
        last_reason = reasons.get(str(error_kind), "邮箱验证码验证未完成")
        log_fn(f"    ✗ {last_reason}")
        if error_kind not in {"invalid", "expired"}:
            raise RuntimeError(f"追加邮箱验证失败：{last_reason}")
    raise RuntimeError(f"追加邮箱验证失败：{last_reason}；已停止，未重复提交旧验证码")


def _generate_pkce() -> tuple[str, str]:
    """生成 PKCE code_verifier + code_challenge (S256)。"""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def _build_codex_oauth_url(code_challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CODEX_CLIENT_ID,
        "redirect_uri": CODEX_REDIRECT_URI,
        "scope": CODEX_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "prompt": "login",
    }
    return f"{OAUTH_ISSUER}/oauth/authorize?" + urllib.parse.urlencode(params)


def _wait_url_contains(page, marker: str, timeout: int) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if marker in (page.url or ""):
                return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def _wait_element(page, locator: str, timeout: int):
    """等元素出现并返回。返回 None 表示超时。"""
    try:
        elem = page.ele(locator, timeout=timeout)
        return elem if elem else None
    except Exception:
        return None


def _safe_url_for_log(value: object, limit: int = 200) -> str:
    """Return only a URL's origin/path; query and fragment may hold credentials."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            port = parsed.port
            authority = host + (f":{port}" if port is not None else "")
            clean = urllib.parse.urlunsplit(
                (parsed.scheme.lower(), authority, parsed.path or "", "", "")
            )
        else:
            clean = raw.split("?", 1)[0].split("#", 1)[0]
    except Exception:
        clean = raw.split("?", 1)[0].split("#", 1)[0]
    return clean[:max(0, int(limit))]


def _dump_page_diagnostic(page, label: str, log_fn: Callable) -> None:
    """Record credential-safe page metadata and a private screenshot."""
    try:
        url = page.url or ""
        log_fn(f"    [diag {label}] url={_safe_url_for_log(url)}")
    except Exception as e:
        log_fn(f"    [diag {label}] page.url 异常: {type(e).__name__}")
    try:
        html = page.html or ""
        # HTML commonly contains hidden CSRF/session values and can echo the
        # callback query.  Its length plus the challenge classification below
        # is useful diagnostically without persisting page contents.
        log_fn(f"    [diag {label}] html_len={len(html)}")
        # 检测常见反爬页面 (排除 OpenAI 登录页里 challenge-platform 这个误报关键字)
        lower = html.lower()
        if ("just a moment" in lower
                or "请稍候" in html
                or "请耐心等待" in html
                or (("cf-chl" in lower or "cf-mitigated" in lower) and "log-in" not in (page.url or ""))):
            log_fn(f"    [diag {label}] ⚠ 疑似 Cloudflare/反爬挑战页")
    except Exception as e:
        log_fn(f"    [diag {label}] page.html 异常: {type(e).__name__}")
    screenshot_path = ""
    try:
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(label or "page"))[:40]
        fd, screenshot_path = tempfile.mkstemp(
            prefix=f"drission_rt_debug_{safe_label}_",
            suffix=".png",
        )
        os.close(fd)
        page.get_screenshot(path=screenshot_path, full_page=True)
        os.chmod(screenshot_path, 0o600)
        log_fn(f"    [diag {label}] 截图已保存: {screenshot_path}")
    except Exception as e:
        if screenshot_path:
            try:
                os.unlink(screenshot_path)
            except OSError:
                pass
        log_fn(f"    [diag {label}] 截图失败: {type(e).__name__}")


_EMAIL_SELECTORS = [
    "css:input[type='email']",
    "css:input[name='email']",
    "css:input[name='username']",
    "css:input[autocomplete='email']",
    "css:input[autocomplete='username']",
    "css:input[autocomplete='username webauthn']",
    "css:input[inputmode='email']",
    "xpath://input[@placeholder='电子邮件地址']",
    "xpath://input[@placeholder='Email address']",
    "xpath://label[contains(., '电子邮件') or contains(., 'Email')]/following::input[1]",
    # 最宽兜底:form 里第一个 type 不是 hidden/submit/button 的 input
    "xpath://form//input[not(@type) or @type='text' or @type='email']",
]
_SUBMIT_SELECTORS = [
    "css:button[type='submit']",
    "xpath://button[contains(., '继续') or contains(., 'Continue')]",
    "xpath://button[normalize-space(text())='继续' or normalize-space(text())='Continue']",
    "css:form button",
]

# consent 授权按钮(codex CLI 第三方授权页要点)
_CONSENT_SELECTORS = [
    "xpath://button[normalize-space(text())='继续']",
    "xpath://button[normalize-space(text())='Continue']",
    "xpath://button[normalize-space(text())='授权']",
    "xpath://button[normalize-space(text())='Authorize']",
    "xpath://button[normalize-space(text())='允许']",
    "xpath://button[normalize-space(text())='Allow']",
    "xpath://button[contains(., '继续') or contains(., 'Continue') or contains(., '授权') or contains(., 'Authorize')]",
    "css:button[type='submit']",
    "css:form button",
]


def _try_selectors(page, selectors: list[str], per_timeout: int):
    """逐个尝试 selector,返回 (元素, 匹配到的 selector)。"""
    for sel in selectors:
        try:
            elem = page.ele(sel, timeout=per_timeout)
            if elem:
                return elem, sel
        except Exception:
            continue
    return None, ""


def _fill_email(page, email: str, log_fn: Callable) -> bool:
    # 多 selector 轮询(每个 2 秒,最长 ~25 秒)
    inp, hit_sel = _try_selectors(page, _EMAIL_SELECTORS, per_timeout=2)
    if not inp:
        log_fn("    ✗ DrissionPage: 邮箱输入框未出现,尝试 dump 页面所有 input")
        try:
            inputs_info = page.run_js("""
                return Array.from(document.querySelectorAll('input')).map(i => ({
                    type: i.type, name: i.name, id: i.id,
                    placeholder: i.placeholder, autocomplete: i.autocomplete,
                    visible: i.offsetParent !== null
                }));
            """)
            log_fn(f"    [diag inputs] {inputs_info}")
        except Exception as e:
            log_fn(f"    [diag inputs] run_js 异常: {e}")
        _dump_page_diagnostic(page, "fill_email_fail", log_fn)
        return False
    log_fn(f"    ✓ 邮箱输入框命中 selector: {hit_sel}")
    try:
        inp.input(email)
    except Exception as e:
        log_fn(f"    ✗ DrissionPage: 填邮箱异常 {e}")
        return False
    btn, btn_sel = _try_selectors(page, _SUBMIT_SELECTORS, per_timeout=2)
    if not btn:
        log_fn("    ✗ DrissionPage: 提交按钮未出现")
        _dump_page_diagnostic(page, "fill_email_submit_fail", log_fn)
        return False
    log_fn(f"    ✓ 提交按钮命中 selector: {btn_sel}")
    # OpenAI 的 React form 经常在 input 后 ~100ms 内 rerender,旧 button DOM 引用变成孤儿
    # → btn.click() 抛"元素对象已失效"。重抓 selector 再点最多 2 次。
    for click_attempt in range(3):
        try:
            btn.click()
            return True
        except Exception as e:
            msg = str(e)
            is_stale = ("失效" in msg) or ("stale" in msg.lower()) or ("无效" in msg)
            if click_attempt >= 2 or not is_stale:
                log_fn(f"    ✗ DrissionPage: 点击提交异常 {e}")
                return False
            log_fn(f"    ⚠ 提交按钮失效,重抓 selector 重试 ({click_attempt + 1}/2)")
            time.sleep(0.5)
            btn, btn_sel = _try_selectors(page, _SUBMIT_SELECTORS, per_timeout=2)
            if not btn:
                log_fn("    ✗ DrissionPage: 重抓后提交按钮消失")
                return False
            log_fn(f"    ✓ 重抓命中 selector: {btn_sel}")
    return False


_OTP_SELECTORS = [
    "css:input[autocomplete='one-time-code']",
    "css:input[name='code']",
    "css:input[name='otp']",
    "css:input[inputmode='numeric']",
    "css:input[type='text'][maxlength='6']",
    "xpath://input[@placeholder='验证码' or contains(@placeholder, 'verification')]",
    "xpath://form//input[not(@type) or @type='text' or @type='tel']",
]

# 老号/已有密码的号:OpenAI 邮箱提交后会路由到 /log-in/password 而不是 OTP 页。
# 页面上一般有一个"改用验证码登录"链接(href=/log-in/code 或 button),点了就切回 OTP 流程。
_SWITCH_TO_CODE_SELECTORS = [
    "css:a[href='/log-in/code']",
    "css:a[href*='/log-in/code']",
    "xpath://a[contains(., '改用验证码') or contains(., '用验证码') or contains(., '验证码登录') or contains(., '一次性验证码') or contains(., '一次性代码')]",
    "xpath://button[contains(., '改用验证码') or contains(., '用验证码') or contains(., '一次性验证码') or contains(., '一次性代码')]",
    "xpath://a[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'email me a code') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use a code') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'one-time code') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login code')]",
    "xpath://button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'email me a code') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use a code') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'one-time code')]",
]

# Authenticator 管理账号必须回到密码登录，不能为了绕过本地缺失或错误的
# ChatGPT 密码而降级到邮箱 OTP。OpenAI 的登录页有时默认展示邮箱验证码，
# 所以同时兼容链接、按钮以及中英文文案。
_SWITCH_TO_PASSWORD_SELECTORS = [
    "css:a[href='/log-in/password']",
    "css:a[href*='/log-in/password']",
    "xpath://a[contains(., '使用密码') or contains(., '改用密码') or contains(., '输入密码') or contains(., '密码继续')]",
    "xpath://button[contains(., '使用密码') or contains(., '改用密码') or contains(., '输入密码') or contains(., '密码继续')]",
    "xpath://*[@role='button' and (contains(., '使用密码') or contains(., '改用密码') or contains(., '输入密码') or contains(., '密码继续'))]",
    "xpath://a[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use your password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in with password')]",
    "xpath://button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use your password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in with password')]",
    "xpath://*[@role='button' and (contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'use password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue with password') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in with password'))]",
]

_PASSWORD_INPUT_SELECTORS = [
    "css:input[type='password']",
    "css:input[name='password']",
    "css:input[autocomplete='current-password']",
]


def _fill_otp(page, code: str, log_fn: Callable) -> bool:
    inp, hit_sel = _try_selectors(page, _OTP_SELECTORS, per_timeout=3)
    if not inp:
        log_fn("    ✗ DrissionPage: OTP 输入框未出现")
        _dump_page_diagnostic(page, "fill_otp_fail", log_fn)
        return False
    log_fn(f"    ✓ OTP 输入框命中 selector: {hit_sel}")
    try:
        # 先清空再填(防止追加到上一次错的 OTP 后面)
        try:
            inp.clear()
        except Exception:
            pass
        inp.input(code)
    except Exception as e:
        log_fn(f"    ✗ DrissionPage: 填 OTP 异常 {e}")
        return False
    btn, _ = _try_selectors(page, _SUBMIT_SELECTORS, per_timeout=2)
    if btn:
        try:
            btn.click()
        except Exception:
            pass  # 部分页面 6 位自动提交
    return True


def _wait_url_left(page, current_marker: str, timeout: int) -> tuple[bool, str]:
    """等当前 URL 跳离 current_marker。返回 (是否跳走, 当前 URL)。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            url = page.url or ""
        except Exception:
            url = ""
        if current_marker not in url:
            return True, url
        time.sleep(0.4)
    try:
        return False, page.url or ""
    except Exception:
        return False, ""


def _wait_url_left_codepage(page, timeout: int) -> tuple[bool, str]:
    """等当前 URL 跳离任意 OTP 输入页。

    OpenAI 在不同入口/分支会落到不同的 OTP 页:
      - 老 OAuth 直连流程 → /email-verification
      - 从 /log-in/password 切换"改用验证码" → /log-in/code
      - 新 SPA 只替换表单，URL 仍为 /log-in/password
    OTP 验证通过后两者都会跳到 /codex/consent 或类似页面。
    """
    end = time.time() + timeout
    while time.time() < end:
        try:
            url = page.url or ""
        except Exception:
            url = ""
        on_code_page = any(
            marker in url
            for marker in ("/email-verification", "/log-in/code", "/log-in/password")
        )
        if not on_code_page and url:
            return True, url
        time.sleep(0.4)
    try:
        return False, page.url or ""
    except Exception:
        return False, ""


_PASSWORD_LOGIN_DOM_JS = r"""
    function usable(e, editable=false) {
        if (!e || !e.isConnected || e.disabled || (editable && e.readOnly) ||
            e.getAttribute('aria-disabled') === 'true' ||
            e.closest('dialog:not([open]),[inert],[hidden],[aria-hidden="true"],fieldset[disabled]')) return false;
        const r=e.getBoundingClientRect(), s=getComputedStyle(e);
        return r.width>0 && r.height>0 && s.display!=='none' &&
            s.visibility!=='hidden' && s.visibility!=='collapse';
    }
    function passwordForm(expectedForm=null) {
        if (expectedForm && !expectedForm.isConnected) return null;
        const inputs=[...document.querySelectorAll('input[type="password"],input[name="password"],input[autocomplete="current-password"]')]
            .filter(e=>usable(e,true));
        if (inputs.length!==1) return null;
        const input=inputs[0], form=input.form || input.closest('form');
        if (!form || !form.isConnected || (expectedForm && expectedForm!==form)) return null;
        return {input,form};
    }
    function submitButton(state) {
        if (!state || state.form.getAttribute('aria-busy')==='true') return null;
        const buttons=[...state.form.querySelectorAll('button,input[type="submit"]')]
            .filter(e=>usable(e) && e.type==='submit' &&
                (e.form || e.closest('form'))===state.form && e.getAttribute('aria-busy')!=='true');
        return buttons.length===1 ? buttons[0] : null;
    }
    function sameInput(input,form) {
        const state=passwordForm(form);
        return !!state && state.input===input && state.form===form;
    }
"""
_PASSWORD_LOGIN_INPUT_JS = _PASSWORD_LOGIN_DOM_JS + "const s=passwordForm(arguments[0]);return s ? s.input : null;"
_PASSWORD_LOGIN_FORM_JS = _PASSWORD_LOGIN_DOM_JS + "const s=passwordForm();return s && s.input===arguments[0] ? s.form : null;"
_PASSWORD_LOGIN_TARGET_JS = _PASSWORD_LOGIN_DOM_JS + "return sameInput(arguments[0],arguments[1]);"
_PASSWORD_LOGIN_READBACK_JS = _PASSWORD_LOGIN_DOM_JS + """
    const [input,form,expected]=arguments;
    if (!sameInput(input,form) || typeof input.value!=='string' || typeof expected!=='string') return null;
    return input.value===expected;
"""
_PASSWORD_LOGIN_SET_JS = _PASSWORD_LOGIN_DOM_JS + """
    const [input,form,expected]=arguments;
    if (!sameInput(input,form) || typeof expected!=='string') return false;
    const descriptor=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
    if (!descriptor || typeof descriptor.set!=='function') return false;
    descriptor.set.call(input,expected);
    input.dispatchEvent(new Event('input',{bubbles:true}));
    input.dispatchEvent(new Event('change',{bubbles:true}));
    return true;
"""
_PASSWORD_LOGIN_BUTTON_JS = _PASSWORD_LOGIN_DOM_JS + """
    const s=passwordForm(arguments[1]);
    return s && s.input===arguments[0] ? submitButton(s) : null;
"""
_PASSWORD_LOGIN_SUBMIT_READY_JS = _PASSWORD_LOGIN_DOM_JS + """
    const [input,form,button,expected,url]=arguments, s=passwordForm(form);
    return location.href===url && !!s && s.input===input && submitButton(s)===button &&
        typeof input.value==='string' && input.value===expected;
"""


def _password_login_route_after_stale(page, original_url: str, *, form=None) -> str:
    """Only a stable, idle password form authorizes re-locating stale controls.

    A changed route means the caller must observe the next challenge, never
    submit again. Missing/ambiguous DOM evidence is not permission to retry.
    """
    if not original_url:
        return "unknown"
    try:
        for _ in range(2):
            current_url = str(page.url or "")
            if current_url and current_url != original_url:
                return "advanced"
            state = page.run_js(_PASSWORD_LOGIN_DOM_JS + r"""
                const s=passwordForm(arguments[0]);
                return {url:location.href, ready:document.readyState === 'complete',
                    password:!!s, idle:!!submitButton(s)};
            """, *((form,) if form is not None else ()))
            if not isinstance(state, dict):
                return "unknown"
            if state.get("url") and state["url"] != original_url:
                return "advanced"
            if not (
                current_url == original_url
                and state.get("url") == original_url
                and state.get("ready") is True
                and state.get("password") is True
                and state.get("idle") is True
            ):
                return "unknown"
            time.sleep(0.2)
        return "password"
    except Exception:
        return "unknown"


def _try_password_login(
    page, password: str, log_fn: Callable, *, diagnostic_fn: Callable | None = None,
) -> bool:
    """Verify the exact password field before one submission, with bounded refills.

    True only means this call filled and submitted the password, not that the
    password or identity has been verified. Diagnostics contain fixed text only.
    """
    def report(code: str, reason: str, attempt: int, status: str = "failed") -> None:
        log_fn(f"    [routing] {reason}")
        if callable(diagnostic_fn):
            try:
                diagnostic_fn({"code": code, "reason": reason, "status": status,
                               "retry_attempt": attempt, "retry_limit": 2})
            except Exception:
                pass

    def is_stale(exc: Exception) -> bool:
        return any(marker in (type(exc).__name__ + " " + str(exc)).lower()
                   for marker in ("elementlost", "staleelement", "stale element", "元素对象已失效"))

    class RefillRequired(Exception):
        pass

    if not isinstance(password, str) or not password:
        report("password_login_input_failed", "密码验证登录没有可用的密码", 0)
        return False
    try:
        original_url = str(page.url or "")
    except Exception:
        original_url = ""
    if not original_url:
        report("password_login_route_uncertain", "密码验证登录页面状态无法确认，已停止提交", 0)
        return False
    form = None
    for attempt in range(3):
        phase = "input"
        try:
            if str(page.url or "") != original_url:
                report("password_login_route_advanced", "密码验证登录页面已前进，但本次未确认密码提交", attempt)
                return False
            inp = None
            end = time.time() + (9 if attempt == 0 else 2)
            while time.time() < end:
                # DrissionPage 4.1 rejects Python None as a JS argument. With
                # no locked form, omit it so JavaScript receives undefined.
                inp = page.run_js(_PASSWORD_LOGIN_INPUT_JS, *((form,) if form is not None else ()))
                if inp:
                    break
                time.sleep(0.4)
            if not inp:
                report("password_login_input_missing", "密码验证登录未找到唯一可用的密码输入框", attempt)
                return False
            if form is None:
                form = page.run_js(_PASSWORD_LOGIN_FORM_JS, inp)
                if not form:
                    report("password_login_input_failed", "密码验证登录未能确认密码输入框所属表单", attempt)
                    return False
            if str(page.url or "") != original_url:
                report("password_login_route_advanced", "密码验证登录页面已前进，但本次未确认密码提交", attempt)
                return False
            inp.clear()
            if page.run_js(_PASSWORD_LOGIN_TARGET_JS, inp, form) is not True:
                raise RefillRequired()
            cleared = page.run_js(_PASSWORD_LOGIN_READBACK_JS, inp, form, "")
            if cleared is False:
                page.run_js(_PASSWORD_LOGIN_SET_JS, inp, form, "")
                cleared = page.run_js(_PASSWORD_LOGIN_READBACK_JS, inp, form, "")
            if cleared is not True:
                report("password_login_input_failed", "密码验证登录未能确认密码输入框已清空", attempt)
                return False
            inp.input(password)
            if page.run_js(_PASSWORD_LOGIN_TARGET_JS, inp, form) is not True:
                raise RefillRequired()
            # Only booleans leave the browser: never expose a password or length.
            matched = page.run_js(_PASSWORD_LOGIN_READBACK_JS, inp, form, password)
            if matched is False:
                page.run_js(_PASSWORD_LOGIN_SET_JS, inp, form, password)
                if page.run_js(_PASSWORD_LOGIN_TARGET_JS, inp, form) is not True:
                    raise RefillRequired()
                matched = page.run_js(_PASSWORD_LOGIN_READBACK_JS, inp, form, password)
            if matched is False:
                raise RefillRequired()
            if matched is not True:
                report("password_login_input_failed", "密码验证登录无法可靠回读密码输入状态", attempt)
                return False
            btn = page.run_js(_PASSWORD_LOGIN_BUTTON_JS, inp, form)
            if not btn:
                report("password_login_submit_missing", "密码验证登录已填写密码，但没有可用的提交按钮", attempt)
                return False
            ready = page.run_js(_PASSWORD_LOGIN_SUBMIT_READY_JS, inp, form, btn, password, original_url)
            if ready is False:
                raise RefillRequired()
            if ready is not True:
                report("password_login_route_uncertain", "密码验证登录提交前状态无法确认，已停止提交", attempt)
                return False
            # Once click starts, any error could hide an accepted request. Never
            # retry it, even when the old URL/form remains visible or reports idle.
            phase = "submit"
            # DrissionPage shares this budget between movement/scroll readiness
            # and the actual click; its 1.5s default can expire before dispatch.
            if btn.click(timeout=8) is False:
                report("password_login_submit_failed", "密码验证登录点击未完成（click_result_false），未确认密码提交", attempt)
                return False
        except Exception as exc:
            stale = is_stale(exc)
            if phase == "submit" or not (stale or isinstance(exc, RefillRequired)):
                reason = "密码验证登录填写密码失败" if phase == "input" else f"密码验证登录提交失败（异常类型：{type(exc).__name__}），未确认请求结果"
                suffix = "stale" if stale else "failed"
                report(f"password_login_{phase}_{suffix}", reason, attempt)
                return False
            time.sleep(0.35)
            route = _password_login_route_after_stale(page, original_url, form=form)
            if route == "advanced":
                report("password_login_route_advanced", "密码验证登录页面已前进，但本次未确认密码提交", attempt)
                return False
            if route != "password":
                report("password_login_route_uncertain", "密码验证登录控件失效且页面状态无法确认，已停止重复提交", attempt)
                return False
            if attempt >= 2:
                code = "password_login_input_stale" if stale else "password_login_input_failed"
                report(code, "密码验证登录未能可靠填入密码，局部重新定位已达 2 次上限", attempt)
                return False
            code = "password_login_input_stale" if stale else "password_login_input_retry"
            report(code, "密码验证登录尚未提交；已确认原密码表单空闲，正在重新定位并填写", attempt + 1, "retrying")
            continue
        report("password_login_submitted", "密码验证登录已填写密码并提交，等待远端验证", attempt, "running")
        return True
    return False


def _switch_to_password_and_login(
    page,
    password: str,
    log_fn: Callable,
    *,
    timeout: int = 10,
) -> bool:
    """从邮箱验证码页切到密码页并提交已安全保存的 ChatGPT 密码。

    该函数只服务于已管理的 Authenticator OAuth 路径。调用方已经在安全
    仓库边界验证密码与 TOTP 均存在，因此这里绝不触发或读取邮箱 OTP。
    """
    if not password:
        return False

    password_input, _ = _try_selectors(
        page,
        _PASSWORD_INPUT_SELECTORS,
        per_timeout=1,
    )
    if password_input is not None:
        return _try_password_login(page, password, log_fn)

    switch, switch_selector = _try_selectors(
        page,
        _SWITCH_TO_PASSWORD_SELECTORS,
        per_timeout=2,
    )
    if switch is None:
        log_fn("    [2FA] ✗ 当前验证页没有提供‘使用密码’入口")
        return False
    try:
        switch.click()
        log_fn(f"    [2FA] ✓ 已切换到密码登录 (selector={switch_selector})")
    except Exception as exc:
        log_fn(f"    [2FA] ✗ 切换密码登录失败 ({type(exc).__name__})")
        return False

    deadline = time.time() + max(1, int(timeout))
    while time.time() < deadline:
        password_input, _ = _try_selectors(
            page,
            _PASSWORD_INPUT_SELECTORS,
            per_timeout=1,
        )
        if password_input is not None:
            return _try_password_login(page, password, log_fn)
        time.sleep(0.4)
    log_fn("    [2FA] ✗ 切换后密码输入框未出现")
    return False


def _handle_password_page(page, email: str, password: str, log_fn: Callable) -> str:
    """OpenAI 把邮箱提交后路由到了 /log-in/password (老号/已设密码的号)。

    顺序 (有密码的号:平台子号都有密码,密码登录最稳且不会破坏表单):
      0. 有 password → 先直接密码登录
      1. 点"改用验证码"链接 → 切 OTP (URL 可能不变,改检测 OTP 输入框)
      2. fetch /passwordless/send-otp 触发 OTP
      3. 兜底:再试一次密码登录 (前面切 OTP 可能把表单弄乱)

    返回值:
      "otp"            — 已切回 OTP 流程,调用方进 OTP 输入循环
      "password_login" — 走了密码登录,调用方跳过 OTP,直接等 consent/callback
      "fail"           — 都不行,调用方应 raise
    """
    log_fn("    [routing] ⚠ 落到 /log-in/password")

    # 方案 0 (首选): 有密码就直接密码登录。不先碰"改用验证码",避免把密码表单切走。
    if password:
        log_fn(f"    [routing] ↳ 优先密码登录 (password len={len(password)})")
        if _try_password_login(page, password, log_fn):
            return "password_login"
        log_fn("    [routing] ⚠ 密码登录未成,改试切 OTP")

    # 方案 1: 点 "改用验证码" 链接 (新版 OpenAI 客户端切换、URL 不变,检测 OTP 输入框出现)
    link, link_sel = _try_selectors(page, _SWITCH_TO_CODE_SELECTORS, per_timeout=2)
    if link:
        try:
            link.click()
            log_fn(f"    [routing] ✓ 命中切换链接 (selector={link_sel}),已点击")
            end = time.time() + 8
            while time.time() < end:
                try:
                    cur = page.url or ""
                except Exception:
                    cur = ""
                if "/log-in/code" in cur or "/email-verification" in cur:
                    log_fn(f"    [routing] ✓ 已切到 OTP 页: {_safe_url_for_log(cur, 140)}")
                    return "otp"
                otp_inp, _ = _try_selectors(page, _OTP_SELECTORS, per_timeout=1)
                if otp_inp:
                    log_fn("    [routing] ✓ 表单已客户端切到 OTP 输入框 (URL 未变)")
                    return "otp"
                time.sleep(0.4)
            log_fn(
                f"    [routing] ⚠ 点击后未进入 OTP: "
                f"{_safe_url_for_log(page.url or '', 140)}"
            )
        except Exception as e:
            log_fn(f"    [routing] ⚠ 点击切换链接异常: {e}")
    else:
        log_fn("    [routing] ↳ 未找到 '改用验证码' 链接")

    # 方案 2: fetch /passwordless/send-otp 触发 OTP。新接口不再接受 email 参数,
    # 故先试不带 body(从会话取),再退回带 email(兼容老接口)。
    try:
        log_fn("    [routing] ↳ 尝试 fetch /passwordless/send-otp 触发 OTP")
        import json as _json
        for body_js in ("undefined", "JSON.stringify({email: " + _json.dumps(email) + "})"):
            js = (
                "return (async () => {\n"
                "  try {\n"
                "    const opt = {method:'POST', credentials:'include',\n"
                "      headers:{'Content-Type':'application/json','Accept':'application/json'}};\n"
                "    const b = " + body_js + ";\n"
                "    if (b !== undefined) opt.body = b;\n"
                "    const r = await fetch('/api/accounts/passwordless/send-otp', opt);\n"
                "    const body = (await r.text()).substring(0, 300);\n"
                "    return {status: r.status, body: body};\n"
                "  } catch (e) { return {error: String(e)}; }\n"
                "})();"
            )
            result = page.run_js(js)
            if isinstance(result, dict):
                status = result.get("status")
                outcome = f"HTTP {status}" if status is not None else "请求异常"
            else:
                outcome = f"无效响应({type(result).__name__})"
            log_fn(f"    [routing] /passwordless/send-otp → {outcome}")
            if isinstance(result, dict) and 200 <= (result.get("status") or 0) < 400:
                try:
                    page.get("https://auth.openai.com/log-in/code", timeout=DEFAULT_NAV_TIMEOUT)
                except Exception as e:
                    log_fn(f"    [routing] 导航到 /log-in/code 异常: {e}")
                try:
                    cur = page.url or ""
                except Exception:
                    cur = ""
                if "/log-in/code" in cur or "/email-verification" in cur:
                    log_fn(f"    [routing] ✓ fetch+导航成功: {_safe_url_for_log(cur, 140)}")
                    return "otp"
                break
    except Exception as e:
        log_fn(f"    [routing] ⚠ fetch send-otp 异常: {e}")

    # 方案 3: 兜底再试一次密码登录 (切 OTP 失败可能把表单弄乱了,重试一次)
    if password:
        log_fn("    [routing] ↳ 最后兜底:再试密码登录")
        if _try_password_login(page, password, log_fn):
            return "password_login"
        log_fn("    [routing] ✗ 密码登录兜底仍失败")
        _dump_page_diagnostic(page, "password_login_no_input", log_fn)
        return "fail"

    log_fn("    [routing] ✗ 无 password 可兜底,放弃")
    _dump_page_diagnostic(page, "password_page_no_fallback", log_fn)
    return "fail"


def _detect_otp_error_text(page, *, strict: bool = False) -> str:
    """从页面 DOM 检测 OTP 错误提示文字,返回错误简述或空串。"""
    try:
        text = page.run_js(
            """
            const candidates = [
              ...document.querySelectorAll('[role="alert"]'),
              ...document.querySelectorAll('.error, .text-error, [class*="error"]'),
              ...document.querySelectorAll('p, span, div'),
            ];
            for (const el of candidates) {
              const t = (el.innerText || '').trim();
              if (!t || t.length > 300) continue;
              if (/代码不正确|invalid code|incorrect code|wrong code|expired|过期|错误|account_deactivated|account_deleted|deactivated|deleted|账号已停用|账户已停用|已被停用|已删除/i.test(t)) {
                return t.substring(0, 250);
              }
            }
            return '';
            """
        )
        if strict and not isinstance(text, str):
            raise RuntimeError("unconfirmed error text")
        return str(text or "").strip()
    except Exception:
        if strict:
            raise RuntimeError("OAuth 登录页面错误提示读取失败，不能确认页面无报错") from None
        return ""


def _detect_visible_error_text(page, *, strict: bool = False) -> str:
    """抓页面上任意可见的报错/提示文案(不限关键词),用于密码页等暴露 OpenAI 真实信息。"""
    try:
        text = page.run_js(
            """
            const els = [
              ...document.querySelectorAll('[role="alert"]'),
              ...document.querySelectorAll('[aria-live]'),
              ...document.querySelectorAll('.error, .text-error, [class*="error" i], [class*="danger" i]'),
            ];
            for (const el of els) {
              const t = (el.innerText||'').trim();
              if (t && t.length <= 250) return t;
            }
            return '';
            """
        )
        if strict and not isinstance(text, str):
            raise RuntimeError("unconfirmed error text")
        return str(text or "").strip()
    except Exception:
        if strict:
            raise RuntimeError("OAuth 登录页面错误提示读取失败，不能确认页面无报错") from None
        return ""


def _is_trusted_oauth_password_page(url: str) -> bool:
    """Only the provider's exact password route can prove a login-page wait."""
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        return (
            parsed.scheme == "https"
            and parsed.hostname == "auth.openai.com"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and parsed.path.rstrip("/") == "/log-in/password"
        )
    except (TypeError, ValueError):
        return False


def _page_text_snippet(page, limit: int = 400) -> str:
    """返回当前页可见文本前若干字符,用于诊断卡住时页面到底显示了什么。"""
    try:
        t = page.run_js("return (document.body && document.body.innerText || '').trim();")
        t = " ".join(str(t or "").split())
        return t[:limit]
    except Exception:
        return ""


def _parse_oauth_callback(url: str, expected_state: str) -> tuple[bool, str, str]:
    """Return ``(is_callback, code, error)`` after strict redirect/state checks."""
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        expected = urllib.parse.urlsplit(CODEX_REDIRECT_URI)
        actual_endpoint = (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port,
            parsed.path,
        )
        expected_endpoint = (
            expected.scheme.lower(),
            (expected.hostname or "").lower(),
            expected.port,
            expected.path,
        )
    except Exception:
        return False, "", ""
    if (
        actual_endpoint != expected_endpoint
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False, "", ""
    if parsed.fragment:
        return True, "", "redirect URL 含非预期 fragment"
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return True, "", "callback query 无法解析"
    if "error" in query:
        # A provider denial remains an error even if the redirect also carries
        # code/state. Never copy error_description (untrusted, possibly secret)
        # into the task log.
        return True, "", "callback 返回授权错误"
    codes = query.get("code") or []
    states = query.get("state") or []
    if len(codes) != 1 or not str(codes[0]):
        return True, "", "callback 缺少唯一授权码"
    if len(states) != 1 or not str(states[0]):
        return True, "", "callback 缺少唯一 state"
    try:
        state_matches = secrets.compare_digest(
            str(states[0]).encode("utf-8"),
            str(expected_state or "").encode("utf-8"),
        )
    except (TypeError, ValueError):
        state_matches = False
    if not state_matches:
        return True, "", "callback state 不匹配"
    return True, str(codes[0]), ""


def _extract_code_from_url(url: str) -> str:
    """Compatibility helper for the signup module; enforce the redirect shape.

    New flows must use :func:`_parse_oauth_callback` with the state saved before
    navigation.  The legacy signup caller cannot supply that value yet, but it
    still benefits from exact endpoint, unique-code and fragment checks.
    """
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        expected = urllib.parse.urlsplit(CODEX_REDIRECT_URI)
        endpoint_matches = (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port,
            parsed.path,
        ) == (
            expected.scheme.lower(),
            (expected.hostname or "").lower(),
            expected.port,
            expected.path,
        )
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        codes = query.get("code") or []
    except Exception:
        return ""
    if (
        not endpoint_matches
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or len(codes) != 1
        or not str(codes[0])
    ):
        return ""
    return str(codes[0])


def _exchange_code_for_tokens(code: str, code_verifier: str, proxy: str | None,
                              log_fn: Callable) -> dict:
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CODEX_REDIRECT_URI,
        "client_id": CODEX_CLIENT_ID,
        "code_verifier": code_verifier,
    }).encode("ascii")
    def _do_request(use_proxy: str | None) -> str:
        req = urllib.request.Request(
            TOKEN_ENDPOINT,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if use_proxy:
            handler = urllib.request.ProxyHandler({"http": use_proxy, "https": use_proxy})
        else:
            handler = urllib.request.ProxyHandler({})   # 显式禁用环境代理 = 直连
        opener = urllib.request.build_opener(handler)
        with opener.open(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    # 换 token 走代理时偶发 SSL EOF / IncompleteRead(代理 CONNECT 隧道把响应体掐断)。
    # authorization code 几分钟内有效, 所以: 先走代理重试 2 次; 仍是连接/读取类错误就
    # 回退直连再试 2 次(/oauth/token 一般不绑 IP, 直连常能成)。HTTP 4xx = code 失效, 不重试;
    # 502/503/504/407 属网关/代理问题, 视作可重试并触发直连兜底。
    if proxy:
        plan: list[tuple[str, str | None]] = [
            ("proxy", proxy), ("proxy", proxy), ("direct", None), ("direct", None),
        ]
    else:
        plan = [("direct", None)] * 4

    raw = None
    last_exc: Exception | None = None
    for attempt, (mode, use_proxy) in enumerate(plan, 1):
        try:
            raw = _do_request(use_proxy)
            if mode == "direct" and proxy:
                log_fn(f"    ✓ /oauth/token 直连兜底成功 (第 {attempt} 次)")
            break
        except urllib.error.HTTPError as e:
            # 网关/代理级错误当作瞬时, 继续按 plan 回退; 其余 4xx/业务错误直接抛。
            if e.code in (407, 502, 503, 504):
                last_exc = e
                log_fn(f"    ⚠ /oauth/token 第 {attempt}/{len(plan)} 次[{mode}] 网关错误 HTTP {e.code}, 2s 后重试…")
                time.sleep(2)
                continue
            # Token endpoint error bodies may still carry bearer credentials.
            # Never copy any portion of the response body into an exception/log.
            raise RuntimeError(f"/oauth/token HTTP {e.code}") from None
        except Exception as e:
            last_exc = e
            nxt = plan[attempt] if attempt < len(plan) else None
            hint = (",下次改直连" if nxt and nxt[0] == "direct" and mode == "proxy" else "")
            # Exception text is untrusted: HTTP/client libraries can embed a raw
            # response (including AT/RT/IDT/session values) in it.  The exception
            # class preserves enough diagnostic signal without exposing secrets.
            log_fn(
                f"    ⚠ /oauth/token 第 {attempt}/{len(plan)} 次[{mode}]请求异常"
                f"({type(e).__name__}){hint}, 2s 后重试…"
            )
            time.sleep(2)
    if raw is None:
        exc_type = type(last_exc).__name__ if last_exc is not None else "unknown"
        raise RuntimeError(
            f"/oauth/token 请求异常(代理+直连共重试 {len(plan)} 次仍失败; {exc_type})"
        ) from None
    import json
    try:
        data = json.loads(raw)
    except Exception:
        raise RuntimeError("/oauth/token 响应非 JSON") from None
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError("/oauth/token 返回授权错误")
    refresh_token = data.get("refresh_token") if isinstance(data, dict) else None
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise RuntimeError("/oauth/token 响应缺 refresh_token")
    return data


def acquire_rt_via_drission(
    email: str,
    password: str,
    proxy: str,
    extra_config: dict,
    log_fn: Callable,
    *,
    email_adapter: Any,
    headless: bool = True,
    total_timeout: int = DEFAULT_BROWSER_TIMEOUT,
    allow_phone_verification: bool = True,
) -> dict:
    """DrissionPage 全程跑 codex OAuth,返回 {access_token, refresh_token, id_token, session_token}。

    email_adapter: 需提供 wait_for_verification_code 和可选的
                   prepare_for_verification（安全的新邮件基线准备）。
                   Authenticator 账号允许传 None；只有页面要求追加邮箱
                   验证时才必须具备邮箱能力；远端要求 TOTP 时仍必须处理。
    """
    from platforms.chatgpt.drission_register import create_browser, _is_browser_closed

    if type(allow_phone_verification) is not bool:
        raise ValueError("allow_phone_verification must be a boolean")

    # This function is also called directly by GPT PRO / 套餐 / BUSINESS
    # modules, bypassing ChatGPTPlatform._action_acquire_rt.  Resolve the
    # encrypted credentials here as the single login boundary so every caller
    # can complete password and Authenticator challenges consistently.
    effective_config = dict(extra_config or {})
    # Only this concrete browser boundary may receive decrypted TOTP material.
    # Discard legacy caller injection so a broad config object cannot be used as
    # an alternate plaintext credential channel.
    effective_config.pop("chatgpt_totp_secret", None)
    stored_password_loaded = False
    stored_totp_loaded = False
    try:
        from services.chatgpt_security_store import (
            get_chatgpt_security_secrets,
            get_chatgpt_security_status,
        )

        security_status = get_chatgpt_security_status(email)
    except Exception:
        raise RuntimeError(
            "账号安全状态读取失败，已停止浏览器 OAuth 登录"
        ) from None

    mfa_state = str(security_status.get("mfa_state") or "").strip().lower()
    has_stored_totp = bool(security_status.get("has_totp"))
    requires_stored_totp = has_stored_totp or mfa_state in {
        "pending",
        "enabled",
        "unmanaged",
    }
    has_stored_password = bool(security_status.get("has_password"))
    if requires_stored_totp and not bool(
        security_status.get("credentials_readable", True)
    ):
        raise RuntimeError(
            "账号 Authenticator 凭据无法解密，请检查加密密钥配置"
        )

    stored_security: dict[str, Any] = {}
    if has_stored_password or has_stored_totp:
        try:
            stored_security = get_chatgpt_security_secrets(email)
        except Exception:
            raise RuntimeError(
                "账号 Authenticator 凭据无法解密，请检查加密密钥配置"
                if requires_stored_totp
                else "账号安全凭据无法解密，请检查加密密钥配置"
            ) from None
    stored_password = str(stored_security.get("password") or "")
    if stored_password:
        password = stored_password
        stored_password_loaded = True
    if stored_security.get("totp_secret"):
        effective_config["chatgpt_totp_secret"] = str(
            stored_security["totp_secret"]
        )
        stored_totp_loaded = True
    if requires_stored_totp and (
        not stored_password_loaded or not stored_totp_loaded
    ):
        missing_parts: list[str] = []
        if not stored_password_loaded:
            missing_parts.append("ChatGPT 登录密码")
        if not stored_totp_loaded:
            missing_parts.append("Authenticator TOTP 密钥")
        raise RuntimeError(
            "账号已启用 Authenticator，但本地缺少"
            + "和".join(missing_parts)
            + "，已停止 OAuth 登录"
        )

    # 未开启 2FA 的账号继续兼容 passwordless 邮箱 OTP。已管理的 2FA
    # 账号使用安全仓库中的 ChatGPT 密码及按需 TOTP，不能误用调用方传入
    # 的邮箱密码，也不能在远端要求 TOTP 时用邮箱 OTP 代替。

    code_verifier, code_challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)
    oauth_url = _build_codex_oauth_url(code_challenge, state)

    # 0. A managed MFA account may still receive an email step-up after its
    # password. Prepare the optional mailbox before any code can be sent;
    # failure only blocks that extra challenge, not ordinary password + TOTP.
    email_baseline_ready = _prepare_oauth_email_baseline(email_adapter, log_fn)
    if not requires_stored_totp:
        _snapshot_existing_mail_ids(email_adapter, log_fn)

    _cleanup_stale_drission_user_dirs_if_due(log_fn)

    log_fn(f"  [DrissionPage] 启动浏览器 (headless={headless}, proxy={'set' if proxy else 'none'})")
    browser_start = time.perf_counter()
    page = create_browser(proxy=proxy or "", headless=headless)
    if page is None:
        raise OAuthAttemptFailure("browser_start_failed")
    log_fn(f"  [DrissionPage] 浏览器启动耗时 {time.perf_counter() - browser_start:.1f}s")
    profile_path = ""
    try:
        profile_path = str(getattr(getattr(page, "browser", None), "user_data_path", "") or "")
    except Exception:
        profile_path = ""

    deadline = time.time() + total_timeout
    callback_received = False
    exchange_started = False
    charge_possible = False
    attempt_failure = None

    try:
        # 1. 打开 codex OAuth start URL
        log_fn("  [DrissionPage] 1/5 导航到 OAuth 授权页")
        nav_start = time.perf_counter()
        try:
            page.get(oauth_url, timeout=DEFAULT_NAV_TIMEOUT)
        except Exception as e:
            # Browser exceptions may echo the authorize URL (state/challenge).
            raise RuntimeError(
                f"DrissionPage 导航 OAuth URL 失败 ({type(e).__name__})"
            ) from None
        log_fn(f"  [DrissionPage] OAuth 授权页打开耗时 {time.perf_counter() - nav_start:.1f}s")

        # 2. 填邮箱。Retain the pre-submit timestamp for adapters that also
        # enforce freshness by delivery time, not just their captured IDs.
        auth_started_at = time.time()
        log_fn("  [DrissionPage] 2/5 填邮箱")
        if not _fill_email(page, email, log_fn):
            raise RuntimeError("DrissionPage 填邮箱失败")

        # 2.5 OpenAI 路由分支。未启用 2FA 的账号保留邮箱 OTP 兼容；
        # Authenticator 管理账号即使被默认送到验证码页，也必须切回密码页。
        log_fn(
            "  [DrissionPage] 2.5/5 检测认证路由 "
            + (
                "(ChatGPT 密码 + Authenticator)"
                if requires_stored_totp
                else "(邮箱 OTP / 密码兼容)"
            )
        )
        from platforms.chatgpt.account_security import is_authenticator_challenge

        route_end = time.time() + 12
        route = ""
        while time.time() < route_end:
            try:
                cur = page.url or ""
            except Exception:
                cur = ""
            if "/log-in/password" in cur:
                route = "password"
                break
            if requires_stored_totp and (
                "/mfa" in cur.lower()
                or "/totp" in cur.lower()
                or is_authenticator_challenge(page)
            ):
                route = "authenticator"
                break
            if "/email-verification" in cur or "/log-in/code" in cur:
                route = "otp"
                break
            time.sleep(0.4)
        try:
            cur_after = page.url or ""
        except Exception:
            cur_after = ""
        log_fn(
            f"    ↳ 邮箱提交后 URL: {_safe_url_for_log(cur_after, 160)} "
            f"(route={route or 'unknown'})"
        )

        # This flag only skips the initial passwordless email flow; submitting
        # a password is not proof that the remaining authentication succeeded.
        password_login_done = False
        password_submitted = False
        if requires_stored_totp:
            log_fn("  [DrissionPage] 3/5 使用已保存的 ChatGPT 密码登录")
            if route == "password":
                if not _try_password_login(page, password, log_fn):
                    raise RuntimeError(
                        "账号已启用 Authenticator，但 OAuth 密码页提交失败"
                    )
                password_login_done = True
                password_submitted = True
            elif route == "otp":
                if not _switch_to_password_and_login(page, password, log_fn):
                    raise RuntimeError(
                        "账号已启用 Authenticator，但 OpenAI 当前验证页无法切换到密码登录；"
                        "已停止 OAuth，未降级使用邮箱验证码"
                    )
                password_login_done = True
                password_submitted = True
            elif route == "authenticator":
                # 某些 OpenAI 登录会话会直接恢复到第二因素页面。后续循环仍
                # 必须实际完成 TOTP，并在拿到 token 后才能确认成功。
                password_login_done = True
            else:
                password_input, _ = _try_selectors(
                    page,
                    _PASSWORD_INPUT_SELECTORS,
                    per_timeout=1,
                )
                if password_input is not None and _try_password_login(
                    page,
                    password,
                    log_fn,
                ):
                    password_login_done = True
                    password_submitted = True
                elif is_authenticator_challenge(page):
                    password_login_done = True
                else:
                    raise RuntimeError(
                        "登录路由识别失败：提交邮箱后等待 12 秒，仍未识别到可操作的密码或 Authenticator 页面；"
                        "尚未确认密码或 2FA 验证完成，无法据此判定账号停用或密码错误"
                    )
        elif route == "password":
            handled = _handle_password_page(page, email, password or "", log_fn)
            if handled == "otp":
                route = "otp"  # 切到 OTP 流程
            elif handled == "password_login":
                password_login_done = True
                password_submitted = True
            else:
                raise RuntimeError(
                    "DrissionPage 落到 /log-in/password 但既切不到 OTP 也没法降级密码登录 "
                    f"(password={'set' if password else 'empty'})"
                )

        # 3. 等 OTP 邮件 → 填 → 检测是否通过;失败重试 (密码登录路径跳过)
        tried_codes: set[str] = set()
        if not password_login_done:
            log_fn("  [DrissionPage] 3/5 等待 OTP + 填入 + 重试")
            otp_sent_at = time.time()
            otp_passed = False
            for otp_attempt in range(1, 4):  # 最多 3 次
                otp_remaining = max(15, int(deadline - time.time()))
                otp_remaining = min(otp_remaining, DEFAULT_OTP_TIMEOUT)
                code = ""
                try:
                    code = email_adapter.wait_for_verification_code(
                        email=email,
                        timeout=otp_remaining,
                        otp_sent_at=otp_sent_at,
                        exclude_codes=set(tried_codes),
                    ) or ""
                except Exception as e:
                    log_fn(f"    ↳ email_adapter 异常: {e}")
                if not code:
                    log_fn(f"    ✗ 第 {otp_attempt} 次等 OTP 超时({otp_remaining}s)")
                    continue
                if code in tried_codes:
                    log_fn("    ↳ adapter 重复返回已尝试的 OTP,跳过")
                    continue
                tried_codes.add(code)
                log_fn(f"  [DrissionPage] 填入已获取 OTP (第 {otp_attempt} 次)")
                if not _fill_otp(page, code, log_fn):
                    continue
                # 等 URL 跳离任意 OTP 输入页 (/email-verification 或 /log-in/code)
                left, cur_url = _wait_url_left_codepage(page, timeout=10)
                if left:
                    log_fn(f"    ✓ OTP 通过,URL → {_safe_url_for_log(cur_url, 140)}")
                    otp_passed = True
                    break
                # 还在 OTP 输入页 → 看页面有没有错误提示
                err_text = _detect_otp_error_text(page)
                if err_text:
                    log_fn(f"    ✗ OpenAI 拒绝本次 OTP: {err_text}")
                    # ★ 识别 account_deactivated:OpenAI 在 OTP 验证响应里直接报账号停用
                    # 立刻 raise(message 含 account_deactivated 关键字),
                    # 让 _fixup_one_rt 的 _is_account_deactivated_error 命中,触发删账号
                    err_lower = err_text.lower()
                    if any(k in err_lower for k in (
                        "account_deactivated", "account_deleted",
                        "deleted or deactivated", "deactivated account",
                    )) or any(k in err_text for k in (
                        "账号已停用", "账户已停用", "账号已被停用", "已被停用", "已删除或停用",
                    )):
                        raise OAuthAttemptFailure("account_deactivated", terminal=False)
                    # ★ max_check_attempts / 限流:OpenAI 已锁定本邮箱的验证码校验次数,
                    # 继续重试只会越撞越死 → 立刻停止,提示冷却后再试(不可重试错误)
                    if any(k in err_lower for k in (
                        "max_check_attempts", "too many attempts", "too many requests",
                        "rate_limit", "rate limit", "max_attempts", "尝试次数过多", "次数过多",
                    )):
                        raise RuntimeError(
                            "otp_rate_limited: OpenAI 限流(max_check_attempts)——该邮箱短时间内验证码"
                            "校验次数已用满,请勿连续重试;等 30-60 分钟冷却后再跑此账号 "
                            f"({err_text[:120]})"
                        )
                else:
                    log_fn(f"    ✗ URL 仍在 {_safe_url_for_log(cur_url, 120)},OTP 可能被拒")
            if not otp_passed:
                raise RuntimeError(
                    f"DrissionPage OTP 重试 {len(tried_codes)} 次仍失败"
                )

        # 4. Follow the challenges actually presented by the provider. Local
        # MFA enrollment means we can answer TOTP, not that every authorization
        # must display it. A valid callback plus PKCE token exchange establishes
        # OAuth success; proving the saved TOTP secret is a separate concern.
        log_fn("  [DrissionPage] 4/5 检查后续认证页面（邮箱验证 / Authenticator）")
        nav_remaining = max(30, int(deadline - time.time()))
        callback_code = ""
        consent_clicks = 0
        mfa_candidate_passed = False
        post_password_email_completed = False
        phone_transition_window_granted = False
        authorization_announced = False
        loop_end = time.time() + nav_remaining
        last_logged_url = ""
        last_heartbeat = 0.0
        pwd_page_since = 0.0
        email_page_since = 0.0
        while time.time() < loop_end:
            try:
                cur_url = page.url or ""
            except Exception:
                cur_url = ""
            # 心跳:URL 变化立刻打,否则每 6s 打一次当前页,避免"静默卡住"看不到停在哪
            now = time.time()
            if cur_url != last_logged_url:
                log_fn(f"    ↳ 当前页: {_safe_url_for_log(cur_url, 160)}")
                last_logged_url = cur_url
                last_heartbeat = now
            elif now - last_heartbeat >= 6:
                log_fn(f"    ⏳ 等待认证或授权页面推进… 当前仍在: {_safe_url_for_log(cur_url, 160)}")
                last_heartbeat = now

            is_callback, candidate_code, callback_error = _parse_oauth_callback(
                cur_url,
                state,
            )
            if is_callback:
                callback_received = True
                if callback_error:
                    log_fn(f"OAuth callback 校验失败: {callback_error}")
                    raise OAuthAttemptFailure("callback_invalid", callback_received=True, terminal=False)
                if requires_stored_totp and not mfa_candidate_passed:
                    log_fn(
                        "    ✓ 授权回调校验通过；本次未确认 Authenticator 动态码验证，"
                        "继续兑换 RT，保留原有 2FA 状态"
                    )
                if not authorization_announced:
                    log_fn("  [DrissionPage] 5/5 已进入 OAuth 回调，正在校验并换取 RT")
                    authorization_announced = True
                callback_code = candidate_code
                break

            # Complete Authenticator when the provider presents that challenge.
            # Do not infer it solely from the local enrollment flag. The secret
            # is injected only in memory by the account-security store; it is
            # never written to task logs.
            from platforms.chatgpt.account_security import (
                choose_authenticator_login_method,
                complete_authenticator_challenge,
                is_authenticator_challenge,
            )
            if choose_authenticator_login_method(page):
                log_fn("    ✓ 已选择 Authenticator App 验证方式")
                time.sleep(1)
                continue
            if is_authenticator_challenge(page):
                log_fn("  [DrissionPage] 4/5 正在完成 Authenticator 动态码验证")
                completed_mfa = complete_authenticator_challenge(
                    page,
                    str(effective_config.get("chatgpt_totp_secret") or ""),
                    log_fn,
                )
                if completed_mfa and stored_totp_loaded:
                    # Do not promote yet: an error/deactivation page also no
                    # longer looks like an MFA challenge.  Token exchange below
                    # is the independent proof that the whole login succeeded.
                    mfa_candidate_passed = True
                time.sleep(1)
                continue
            if "/email-verification" in cur_url or "/log-in/code" in cur_url:
                if not (password_submitted or mfa_candidate_passed):
                    raise RuntimeError("OAuth 再次进入邮箱验证，但尚未确认密码提交或 Authenticator 验证；已停止")
                if post_password_email_completed:
                    raise RuntimeError("邮箱验证后再次回到邮箱验证码页；已停止，避免重复提交")
                if _is_oauth_email_challenge(page):
                    _complete_oauth_email_challenge(
                        page,
                        email,
                        email_adapter,
                        email_baseline_ready,
                        log_fn,
                        otp_sent_at=auth_started_at,
                        deadline=loop_end,
                        tried_codes=tried_codes,
                    )
                    post_password_email_completed = True
                    # Delivery may consume most of the original budget. Allow
                    # one bounded transition window for the remaining TOTP /
                    # consent steps, never an unbounded per-loop extension.
                    loop_end = max(loop_end, time.time() + 45)
                    email_page_since = 0.0
                    time.sleep(0.5)
                    continue
                if email_page_since == 0.0:
                    email_page_since = now
                    log_fn("    ⏳ 已进入邮箱验证页，正在等待可交互的验证码表单")
                elif now - email_page_since >= 15:
                    raise OAuthAttemptFailure("control_timeout", terminal=False)
                time.sleep(0.5)
                continue
            email_page_since = 0.0
            # A submitted password is not proof of login or rejection. A bounded
            # wait without a visible error on the exact trusted route is a
            # recoverable login timeout, never an inferred wrong/dead account.
            if "/log-in/password" in cur_url:
                if pwd_page_since == 0.0:
                    pwd_page_since = now
                elif now - pwd_page_since >= 6:
                    err_text = _detect_visible_error_text(page, strict=True) or _detect_otp_error_text(page, strict=True)
                    snippet = _page_text_snippet(page, 400)
                    log_fn(f"    [diag] 密码页可见文本: {snippet}")
                    _dump_page_diagnostic(page, "password_submit_stuck", log_fn)
                    trusted_password_page = _is_trusted_oauth_password_page(cur_url)
                    if trusted_password_page and re.search(r"incorrect password|wrong password|invalid password|密码错误|密码不正确", err_text or "", re.I):
                        raise OAuthAttemptFailure("password_rejected", terminal=False)
                    if trusted_password_page and password_submitted and not err_text:
                        raise OAuthAttemptFailure("password_page_timeout", terminal=False)
                    raise RuntimeError(
                        "密码登录后仍停在 /log-in/password"
                        + (f" · OpenAI 提示: {err_text[:160]}" if err_text
                           else " · 页面无报错元素(见上方 [diag] 可见文本/截图判断是密码错/验证/captcha)")
                    )
                time.sleep(1)
                continue
            else:
                pwd_page_since = 0.0
            # ★ /add-phone:OpenAI 要求老号添加手机号才放过 OAuth。
            # 先尝试用 smsbower 自动过手机验证;失败再 fallback 到原硬抛
            if "/add-phone" in cur_url or "/add_phone" in cur_url:
                if not allow_phone_verification:
                    # Per-attempt authority cannot be overridden by global SMS
                    # configuration. Stop before constructing a rental client.
                    raise OAuthAttemptFailure("phone_verification_not_authorized", terminal=False)
                previous_charge_possible = charge_possible
                charge_possible = True  # Entering a rental flow may spend, even if its response is lost.
                failures = []
                passed = _handle_add_phone_via_smsbower(page, log_fn, extra_config, failures.append)
                if passed:
                    # SMS waiting has its own configured 60–300 s budget. It
                    # may consume the earlier navigation deadline; retain one
                    # bounded window to finish consent/callback after success.
                    if not phone_transition_window_granted:
                        phone_transition_window_granted = True
                        loop_end = max(loop_end, time.time() + 60)
                    log_fn("  [DrissionPage] add_phone 已通过 smsbower 自动验证,继续等回调")
                    time.sleep(2)
                    continue
                failure = normalize_oauth_failure(failures[-1]) if failures else None
                if failure:
                    charge_possible = previous_charge_possible or failure["charge_possible"]
                    raise OAuthAttemptFailure(failure["code"], charge_possible=charge_possible, terminal=False)
                raise OAuthAttemptFailure("sms_provider_error", charge_possible=True, terminal=False)
            # 还在 consent / sign-in-with-chatgpt 页面 → 找继续按钮点
            if ("/codex/consent" in cur_url
                    or "/codex/organization" in cur_url
                    or "/sign-in-with-chatgpt" in cur_url):
                if not authorization_announced:
                    log_fn("  [DrissionPage] 5/5 登录验证页面已结束，正在处理 OAuth 授权")
                    authorization_announced = True
                btn, btn_sel = _try_selectors(page, _CONSENT_SELECTORS, per_timeout=1)
                if btn:
                    try:
                        btn.click()
                        consent_clicks += 1
                        log_fn(f"    ✓ 点击 consent 继续 #{consent_clicks} (selector={btn_sel})")
                        time.sleep(2)  # 给 OpenAI 处理时间
                        continue
                    except Exception as e:
                        log_fn(f"    ⚠ 点击 consent 按钮异常: {e}")
            time.sleep(1)
        if not callback_code:
            current = ""
            try:
                current = page.url or ""
            except Exception:
                pass
            _dump_page_diagnostic(page, "callback_timeout", log_fn)
            parsed = urllib.parse.urlsplit(current)
            if parsed.scheme == "https" and parsed.hostname == "auth.openai.com" and not _detect_visible_error_text(page):
                raise OAuthAttemptFailure("browser_timeout", charge_possible=charge_possible, terminal=False)
            raise RuntimeError(
                f"DrissionPage 未等到 callback URL (超时 {nav_remaining}s,"
                f"consent 已点 {consent_clicks} 次,当前: {_safe_url_for_log(current, 160)})"
            )
        log_fn(f"    ✓ 拿到 authorization code (len={len(callback_code)})")

        # 5. 换 token
        exchange_started = True
        try:
            tokens = _exchange_code_for_tokens(callback_code, code_verifier, proxy, log_fn)
        except Exception as exc:
            log_fn(f"OAuth 授权兑换失败: {exc}")
            raise OAuthAttemptFailure("exchange_failed", callback_received=True,
                                      exchange_started=True, charge_possible=charge_possible, terminal=False) from None
        if not isinstance(tokens, dict) or any(not isinstance(tokens.get(key), str) or not tokens[key].strip()
                                              for key in ("access_token", "refresh_token", "id_token")):
            raise OAuthAttemptFailure("partial_credentials", callback_received=True,
                                      exchange_started=True, charge_possible=charge_possible, terminal=False)
        log_fn(f"    ✓ 换到 RT len={len(tokens.get('refresh_token') or '')}")
        if mfa_candidate_passed and stored_totp_loaded:
            # Fresh challenge + successful OAuth token exchange proves that
            # the locally stored candidate is the active remote key.
            try:
                from services.chatgpt_security_store import (
                    update_chatgpt_security_state,
                )

                update_chatgpt_security_state(
                    email,
                    mfa_state="enabled",
                    last_error="",
                )
            except Exception:
                log_fn("    ⚠ 2FA 已通过，但本地确认状态暂时写入失败")

        # 6. 尝试拿 session cookie
        session_token = ""
        try:
            session_cookies = {}
            for c in page.cookies():
                name = c.get("name") if isinstance(c, dict) else ""
                value = c.get("value") if isinstance(c, dict) else ""
                if name and value:
                    session_cookies[str(name)] = str(value)
            from platforms.chatgpt.account_security import _session_cookie_from_map

            session_token = _session_cookie_from_map(session_cookies)
        except Exception:
            pass

        return {
            "access_token": tokens.get("access_token", ""),
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens.get("id_token", ""),
            "session_token": session_token,
        }
    except OAuthAttemptFailure as exc:
        attempt_failure = exc
        try:
            observed_callback, _, _ = _parse_oauth_callback(page.url or "", state)
        except Exception:
            # Unknown is not proof of either receiving or not receiving a callback.
            exc = OAuthAttemptFailure("oauth_unknown", callback_received=callback_received,
                                      exchange_started=exchange_started, charge_possible=True, terminal=False)
            attempt_failure = exc
            observed_callback = False
        exc.set_attempt_evidence(callback_received=callback_received or observed_callback,
                                 exchange_started=exchange_started, charge_possible=charge_possible,
                                 terminal=False)
        raise exc from None
    finally:
        browser_closed = False
        try:
            # URL read failures also mean "closed" to the legacy convenience
            # probe. They cannot prove an OAuth browser terminal for retries.
            browser_closed = (_oauth_browser_closed(page) if attempt_failure is not None
                              else not page or _is_browser_closed(page))
            if not browser_closed:
                try:
                    page.quit(force=True)
                except TypeError:
                    page.quit()
                browser_closed = _oauth_browser_closed(page) if attempt_failure is not None else _is_browser_closed(page)
        except Exception as exc:
            try:
                log_fn(f"  [DrissionPage] 关闭浏览器异常(忽略): {exc}")
            except Exception:
                pass
        if attempt_failure is not None:
            attempt_failure.set_attempt_evidence(terminal=browser_closed)
        if profile_path:
            try:
                from platforms.chatgpt.drission_temp import cleanup_profile_path
                cleanup = cleanup_profile_path(profile_path, wait_seconds=5)
                if cleanup.get("deleted"):
                    log_fn(
                        "  [DrissionPage] 已清理临时 profile "
                        f"({cleanup.get('freed_human') or '0B'})"
                    )
                elif cleanup.get("reason") not in {"missing"}:
                    log_fn(
                        "  [DrissionPage] 临时 profile 暂未清理: "
                        f"{cleanup.get('reason') or 'unknown'}"
                    )
            except Exception as cleanup_exc:
                log_fn(f"  [DrissionPage] 清理临时 profile 异常: {cleanup_exc}")


# ─── DrissionPage 路径下的 add_phone 自动接管(smsbower) ──────

def _oauth_browser_closed(page) -> bool:
    """Strict DrissionPage browser-driver terminal evidence, never URL heuristics."""
    if page is None:
        return True
    try:
        return page.browser.states.is_alive is False
    except Exception:
        return False

_PHONE_INPUT_SELECTORS = [
    "css:input[type='tel']",
    "css:input[name='phone_number']",
    "css:input[name='phoneNumber']",
    "css:input[name='phone']",
    "css:input[autocomplete='tel']",
    "css:input[autocomplete='tel-national']",
]
_PHONE_OTP_SELECTORS = [
    "css:input[autocomplete='one-time-code']",
    "css:input[name='code']",
    "css:input[name='otp']",
    "css:input[inputmode='numeric']",
]
_PHONE_SUBMIT_SELECTORS = [
    "css:button[type='submit']",
    "css:form button[type='submit']",
    "text:继续",
    "text:Continue",
    "text:Verify",
    "text:验证",
]


def _refresh_add_phone_page(page, log_fn) -> bool:
    """硬刷 /add-phone 清掉上一次失败号码留下的 React form state。

    OpenAI 的 PhoneNumberInput 是受控组件,inp.clear() + inp.input() 模拟键盘
    不会重置 React 内部 state — 上次拒收的号码状态会让新国家的号也被卡。
    重新 GET 当前 URL 比 page.refresh() 更稳(后者 DrissionPage 各版本 API 不一)。
    """
    try:
        cur = page.url or ""
    except Exception:
        cur = ""
    if "/add-phone" not in cur and "/add_phone" not in cur:
        log_fn(f"  [smsbower] 当前不在 /add-phone (url={_safe_url_for_log(cur, 120)}), 跳过刷新")
        return False
    log_fn("  [smsbower] 刷新 /add-phone 页面 (清掉上次拒收号的 React state)")
    try:
        page.get(cur, timeout=DEFAULT_NAV_TIMEOUT)
    except Exception as e:
        log_fn(f"  [smsbower] 刷新页面异常 (继续往下): {e}")
        return False
    # 等输入框重新就绪 (最多 10s)
    for _ in range(10):
        try:
            new_url = page.url or ""
        except Exception:
            new_url = ""
        # 刷新过程中 OpenAI 偶尔会直接放过 /add-phone (session 已经过) → 不算失败
        if new_url and "/add-phone" not in new_url and "/add_phone" not in new_url:
            log_fn(
                "  [smsbower] 刷新后离开 /add-phone "
                f"(url={_safe_url_for_log(new_url, 120)}), 看似已过 phone"
            )
            return True
        try:
            inp, _ = _try_selectors(page, _PHONE_INPUT_SELECTORS, per_timeout=1)
            if inp:
                log_fn("  [smsbower] 刷新完成, 输入框已就绪")
                return True
        except Exception:
            pass
        time.sleep(1)
    log_fn("  [smsbower] 刷新后 10s 内输入框未就绪, 继续尝试 (可能仍能填)")
    return True


def _fill_phone_on_add_phone_page(page, phone_e164: str, log_fn) -> bool:
    """在 /add-phone 页填手机号(已带 + 的 E.164)并提交。"""
    inp, sel = _try_selectors(page, _PHONE_INPUT_SELECTORS, per_timeout=3)
    if not inp:
        log_fn("    ✗ /add-phone 没找到手机号输入框")
        return False
    log_fn(f"    ✓ 手机号输入框命中: {sel}")
    try:
        try: inp.clear()
        except Exception: pass
        # OpenAI 的 PhoneNumberInput 通常已根据 country picker 锁了前缀,
        # 我们试两种填法:先连前缀,失败 fallback 到无前缀
        inp.input(phone_e164)
    except Exception as e:
        log_fn(f"    ✗ 填手机号异常: {type(e).__name__}")
        return False
    # 提交
    btn, btn_sel = _try_selectors(page, _PHONE_SUBMIT_SELECTORS, per_timeout=2)
    if not btn:
        log_fn("    ✗ /add-phone 没找到提交按钮")
        return False
    try:
        btn.click()
        log_fn(f"    ✓ 已点击 add-phone 提交按钮: {btn_sel}")
    except Exception as e:
        log_fn(f"    ✗ 点击 add-phone 提交异常: {type(e).__name__}")
        return False
    return True


def _fill_phone_otp_on_phone_verification(page, code: str, log_fn) -> bool:
    """在 /phone-verification 页填短信验证码并提交。"""
    inp, sel = _try_selectors(page, _PHONE_OTP_SELECTORS, per_timeout=3)
    if not inp:
        log_fn("    ✗ /phone-verification 没找到 OTP 输入框")
        return False
    log_fn(f"    ✓ phone OTP 输入框命中: {sel}")
    try:
        try: inp.clear()
        except Exception: pass
        inp.input(code)
    except Exception as e:
        log_fn(f"    ✗ 填 phone OTP 异常: {type(e).__name__}")
        return False
    # 一般 6 位会自动提交;留个保险 click
    btn, _ = _try_selectors(page, _PHONE_SUBMIT_SELECTORS, per_timeout=2)
    if btn:
        try:
            btn.click()
        except Exception:
            pass
    return True


def _classify_sms_page_rejection(visible_error: str, *, otp: bool = False) -> str:
    """Classify only explicit page rejection; do not expose its raw text.

    A rate/attempt limit is not an unsupported number. It must stop the current
    rental loop so retrying another country cannot turn an account restriction
    into repeated paid requests.
    """
    text = str(visible_error or "")
    if re.search(
        r"too many (?:requests|attempts|(?:phone )?verification|(?:phone )?numbers|times|accounts)|rate[ _-]?limit|"
        r"max(?:imum)?[ _-]?(?:check[ _-]?)?attempts|"
        r"(?:phone|verification|account)[^\n]*(?:limit (?:reached|exceeded)|maximum number)|"
        r"(?:验证|尝试|请求|使用).{0,12}(?:过于频繁|次数过多|次数上限|达到上限)|"
        r"(?:次数过多|请求过于频繁)", text, re.I,
    ):
        return "sms_account_restricted"
    if otp:
        if re.search(r"(?:invalid|incorrect|wrong|expired)[^\n]{0,40}code|"
                     r"code[^\n]{0,40}(?:invalid|incorrect|expired)|"
                     r"验证码.{0,12}(?:错误|无效|不正确|过期)", text, re.I):
            return "sms_code_rejected"
    elif re.search(r"invalid phone|(?:phone|mobile) number[^\n]{0,80}(?:not supported|unsupported|invalid)|"
                   r"(?:手机号|号码).{0,12}(?:无效|不支持)", text, re.I):
        return "sms_phone_rejected"
    return ""


def _handle_add_phone_via_smsbower(page, log_fn, extra_config: dict, failure_fn: Callable | None = None) -> bool:
    """DrissionPage 真浏览器路径下,用 smsbower 自动过 /add-phone 验证。

    成功返回 True(页面应已离开 /add-phone 和 /phone-verification);
    smsbower 未配置 / 全部失败返回 False(由调用方抛原 add_phone 错误)。

    国家轮换:
      读 smsbower_countries(CSV, 如 "187,175,12") 多国轮换;
      没配 → 落回 smsbower_country(单值);
      仍没配 → 用 ["187","12","175"](美/美虚/澳, 注释里确认存在的几个号段)
      每个国家试 smsbower_max_attempts 次, 全失败换下一个国家
    """
    outcomes: list[str] = []
    charge_possible = False

    def failed(code: str) -> None:
        outcomes.append(code)

    def finish_failure() -> bool:
        # Preserve substantive failures when a later country merely has no stock.
        priority = ("sms_configuration_error", "sms_provider_error", "sms_cancelled",
                    "sms_number_request_failed", "sms_phone_rejected", "sms_code_rejected",
                    "sms_rejected", "control_timeout", "sms_timeout", "sms_no_inventory")
        if "sms_account_restricted" in outcomes:
            code = "sms_account_restricted"
        elif "sms_balance_insufficient" in outcomes:
            # A balance response only describes this rental request. Mixed
            # allocation/verification results must retain their prior fence.
            code = ("sms_balance_insufficient" if all(item in {"sms_balance_insufficient", "sms_no_inventory"}
                    for item in outcomes) else "sms_provider_error")
        elif outcomes and all(item == "sms_number_http_502" for item in outcomes):
            code = "sms_number_http_502"
        elif "sms_number_http_502" in outcomes:
            # A number-allocation 502 is precise only when every outcome agrees.
            # Mixed rental/page/poll failures retain the conservative boundary.
            code = "sms_provider_error"
        else:
            code = next((item for item in priority if item in outcomes), "sms_provider_error")
        failure = OAuthAttemptFailure(code, charge_possible=charge_possible, terminal=False)
        log_fn(f"  [smsbower] {failure}")
        if failure_fn is not None:
            failure_fn(failure.oauth_failure)
        return False

    api_key = str((extra_config or {}).get("smsbower_api_key") or "").strip()
    if not api_key:
        log_fn("  [smsbower] 未配置 smsbower_api_key,无法自动过 add_phone")
        failed("sms_configuration_error")
        return finish_failure()

    try:
        from platforms.chatgpt.smsbower_client import (
            DEFAULT_COUNTRY as _SB_DEF_COUNTRY,
            DEFAULT_MAX_PRICE as _SB_DEF_MAX_PRICE,
            DEFAULT_SERVICE as _SB_DEF_SERVICE,
            SmsbowerClient,
            SmsbowerError,
            classify_request_failure,
            request_failure_description,
        )
    except Exception as exc:
        log_fn(f"  [smsbower] 模块加载失败: {type(exc).__name__}")
        failed("sms_configuration_error")
        return finish_failure()

    cfg = extra_config or {}
    service = str(cfg.get("smsbower_service") or _SB_DEF_SERVICE).strip() or _SB_DEF_SERVICE

    # 解析国家列表(优先级: 多国 CSV > 单国 > 默认轮换)
    # 默认列表按 smsbower 实测 "dr" (OpenAI) 服务库存 + 价格升序排,
    # 通常 maxPrice=0.08 时只有前 5 个能买到; 想用 187/175 这种贵号段
    # 请把 smsbower_max_price 调到 0.6 以上。
    # 想自定义可在 Settings 配 smsbower_countries=36,16,5 之类。
    raw_countries = str(cfg.get("smsbower_countries") or "").strip()
    if raw_countries:
        country_list = [c.strip() for c in raw_countries.split(",") if c.strip()]
    else:
        single = str(cfg.get("smsbower_country") or "").strip()
        if single:
            country_list = [single]
        else:
            # 默认精简列表:全部 ≤ 默认 maxPrice 0.08,按对 OpenAI 的接受率排序。
            # 想用真实美国(187)/澳洲(175) 等高接受率号段,把 smsbower_max_price
            # 调到 0.6+ 再用 smsbower_countries 自定义。
            country_list = [
                "16",   # United Kingdom          $0.067  真实号, 接受率较好
                "36",   # Canada                  $0.032
                "12",   # United States (virtual) $0.004  最便宜, 虚拟号易被拒但先快速试
                "5",    # Myanmar                 $0.054  兜底
            ]
    # 兜底
    if not country_list:
        country_list = [_SB_DEF_COUNTRY]

    max_price = str(cfg.get("smsbower_max_price") or _SB_DEF_MAX_PRICE).strip() or _SB_DEF_MAX_PRICE
    proxy = str(cfg.get("smsbower_proxy") or "").strip() or None
    # 每个国家试几次。默认 1 — 实测大多 OpenAI 拒收是号段级而非单号级,多试浪费时间。
    # 若想保留老语义可设 smsbower_attempts_per_country=3
    try:
        attempts_per_country = max(1, min(10, int(
            cfg.get("smsbower_attempts_per_country")
            or cfg.get("smsbower_max_attempts")  # 旧 key 兼容
            or 1
        )))
    except Exception:
        attempts_per_country = 1
    otp_timeout = resolve_sms_timeout(cfg)
    try:
        poll_interval = max(2, min(15, int(cfg.get("smsbower_poll_interval_seconds") or 5)))
    except Exception:
        poll_interval = 5

    # 自定义 base_url: 接入兼容 sms-activate 协议的其他平台(如 GrizzlySMS:
    # https://api.grizzlysms.com/stubs/handler_api.php)。留空走默认 smsbower。
    base_url = str(cfg.get("smsbower_base_url") or "").strip()
    try:
        client = (SmsbowerClient(api_key=api_key, base_url=base_url, proxy=proxy)
                  if base_url else SmsbowerClient(api_key=api_key, proxy=proxy))
    except Exception as exc:
        log_fn(f"  [smsbower] 客户端构造失败: {type(exc).__name__}")
        failed("sms_configuration_error")
        return finish_failure()
    if base_url:
        log_fn("  [smsbower] 使用自定义接码服务地址")

    log_fn(
        f"  [smsbower] add_phone 启动 (service={service}, countries=[{','.join(country_list)}],"
        f" maxPrice={max_price}, attempts_per_country={attempts_per_country}, 短信等待上限={otp_timeout}秒)"
    )

    # 收集每国结局,最后给出准确总结
    country_results: list[tuple[str, str]] = []

    for country_idx, country in enumerate(country_list, start=1):
        log_fn(f"  [smsbower] >>> 国家 {country_idx}/{len(country_list)}: {country}")
        # 第二个及之后的国家:先刷一遍 /add-phone, 清掉上次拒收号留下的 React state
        if country_idx > 1:
            _refresh_add_phone_page(page, log_fn)
        skip_remaining_countries = False
        country_outcome = "unconfirmed"
        for attempt in range(1, attempts_per_country + 1):
            # 同一国家第 2 次及之后:也刷一遍页面 (上一号刚被拒,form state 同样脏)
            if attempt > 1:
                _refresh_add_phone_page(page, log_fn)
            # 1) 取号
            try:
                rented = client.get_number(service=service, country=country, max_price=max_price)
            except SmsbowerError as e:
                log_fn(f"  [smsbower {country}/{attempt}/{attempts_per_country}] 取号失败: {e.code}")
                if e.code == "REQUEST_FAILED":
                    log_fn("  [smsbower] 网络原因：" + request_failure_description(e.request_failure_kind))
                if e.code in ("BAD_KEY", "NO_BALANCE", "BAD_SERVICE", "WRONG_SERVICE", "WRONG_COUNTRY", "WRONG_MAX_PRICE", "BANNED"):
                    # 账号级问题,换国家也救不了,直接终止
                    log_fn(f"  [smsbower] {e.code} 属账号级问题, 终止全部尝试")
                    country_outcome = e.code
                    failed("sms_balance_insufficient" if e.code == "NO_BALANCE" else "sms_configuration_error")
                    skip_remaining_countries = True
                    break
                if e.code == "NO_NUMBERS":
                    log_fn(f"  [smsbower] {country} 号池空 (NO_NUMBERS), 切换下一国家")
                    country_outcome = "NO_NUMBERS"
                    failed("sms_no_inventory")
                    break
                country_outcome = e.code
                charge_possible = True
                failed("sms_number_http_502" if e.code == "HTTP_502" else
                       "sms_number_request_failed" if e.code == "REQUEST_FAILED" else "sms_provider_error")
                continue
            except Exception as e:
                log_fn(f"  [smsbower {country}/{attempt}/{attempts_per_country}] 取号异常: {type(e).__name__}")
                country_outcome = f"get_number_exc:{type(e).__name__}"
                charge_possible = True
                kind = classify_request_failure(e)
                log_fn("  [smsbower] 网络原因：" + request_failure_description(kind))
                failed("sms_number_request_failed" if kind != "unknown" else "sms_provider_error")
                continue

            charge_possible = True
            if not isinstance(rented, dict):
                country_outcome = "provider_response_invalid"
                failed("sms_provider_error")
                continue
            activation_id = str(rented.get("activation_id") or "")
            phone_raw = str(rented.get("phone") or "")
            if not activation_id or not phone_raw:
                country_outcome = "provider_response_invalid"
                failed("sms_provider_error")
                continue
            phone_e164 = phone_raw if phone_raw.startswith("+") else f"+{phone_raw}"
            log_fn(
                f"  [smsbower {country}/{attempt}/{attempts_per_country}] "
                f"取号成功 (号码已脱敏,id 已脱敏)"
            )

            # 2) 填入 /add-phone 并提交
            if not _fill_phone_on_add_phone_page(page, phone_e164, log_fn):
                try: client.cancel(activation_id)
                except Exception: pass
                country_outcome = "phone_controls_unconfirmed"
                failed("sms_provider_error")
                continue

            # 3) 等跳到 /phone-verification(或已经直接过 phone)
            moved_to_verify = _wait_url_contains(page, "/phone-verification", 15)
            if not moved_to_verify:
                try:
                    cur = page.url or ""
                except Exception:
                    cur = ""
                if not isinstance(cur, str):
                    cur = ""
                if "/codex/consent" in cur or "?code=" in cur or "/auth/callback" in cur:
                    log_fn(f"  [smsbower] 提交后直接进入 {_safe_url_for_log(cur, 120)}, 跳过 OTP")
                    try: client.cancel(activation_id)
                    except Exception: pass
                    return True
                visible_error = _detect_visible_error_text(page) or _detect_otp_error_text(page)
                rejection_code = _classify_sms_page_rejection(visible_error)
                url_readable = bool(cur)
                try:
                    parsed_phone_url = urllib.parse.urlsplit(cur)
                    controlled_wait = parsed_phone_url.scheme == "https" and parsed_phone_url.hostname == "auth.openai.com" and parsed_phone_url.path in {"/add-phone", "/add_phone"}
                except ValueError:
                    url_readable = False
                    controlled_wait = False
                # An unfamiliar visible error is not a plain navigation timeout.
                transition_failure = rejection_code or ("control_timeout" if controlled_wait and not visible_error else "sms_provider_error")
                if rejection_code == "sms_account_restricted":
                    country_outcome = rejection_code
                    transition_reason = "OpenAI 已限制验证次数，停止本次取号轮换"
                elif rejection_code == "sms_phone_rejected":
                    country_outcome = rejection_code
                    transition_reason = "OpenAI 明确提示号码无效或不支持"
                elif visible_error:
                    country_outcome = "phone_transition_unrecognized_error"
                    transition_reason = "短信验证页面未确认：页面出现未识别错误，需人工核对"
                elif controlled_wait:
                    country_outcome = "phone_transition_timeout"
                    transition_reason = "等待短信验证页面超时：仍在已知手机号输入页，未检测到页面错误"
                elif url_readable:
                    country_outcome = "phone_transition_unknown_page"
                    transition_reason = "短信验证页面未确认：当前为未知页面，需人工核对"
                else:
                    country_outcome = "phone_transition_url_unreadable"
                    transition_reason = "短信验证页面未确认：当前页面 URL 不可读取或无法解析，需人工核对"
                failed(transition_failure)
                # Closed categories keep URL parameters, phone numbers, OTPs,
                # and unfamiliar page error text out of diagnostics.
                log_fn(f"  [smsbower] {transition_reason}")
                try: client.cancel(activation_id)
                except Exception: pass
                if rejection_code == "sms_account_restricted":
                    skip_remaining_countries = True
                    break
                continue

            # 4) 轮询 SMS
            log_fn(f"  [smsbower] 等 SMS (max {otp_timeout}s, 轮询 {poll_interval}s)")
            code = ""
            poll_failure = ""
            sms_wait = SmsWaitProgress(otp_timeout, log_fn, clock=time.time, prefix="  [smsbower] ")
            while sms_wait.remaining() > 0:
                sms_wait.report()
                try:
                    st = client.get_status(activation_id)
                except SmsbowerError as e:
                    log_fn(f"  [smsbower] getStatus 异常 (忽略): {e.code}")
                    poll_failure = "sms_provider_error"
                    time.sleep(min(poll_interval, sms_wait.remaining()))
                    continue
                except Exception as e:
                    log_fn(f"  [smsbower] getStatus 异常: {type(e).__name__}")
                    poll_failure = "sms_provider_error"
                    break
                state = st.get("state", "") if isinstance(st, dict) else ""
                if state == "ok":
                    code = str(st.get("code") or "").strip()
                    if not code:
                        poll_failure = "sms_provider_error"
                    log_fn("  [smsbower] 收到 SMS 验证码（内容不写入日志）")
                    break
                if state == "cancel":
                    log_fn("  [smsbower] 激活被取消")
                    poll_failure = "sms_cancelled"
                    break
                if state not in {"waiting", "waiting_retry"}:
                    poll_failure = "sms_provider_error"
                    break
                time.sleep(min(poll_interval, sms_wait.remaining()))
            sms_wait.report(force=True)
            if not code:
                country_outcome = poll_failure or "sms_timeout"
                failed(country_outcome)
                log_fn(f"  [smsbower] 等 SMS 超时（本次等待上限 {otp_timeout} 秒）" if not poll_failure else "  [smsbower] 短信激活已取消或读取未确认，非短信等待超时")
                try: client.cancel(activation_id)
                except Exception: pass
                continue

            # 5) 填 OTP
            if not _fill_phone_otp_on_phone_verification(page, code, log_fn):
                try: client.cancel(activation_id)
                except Exception: pass
                country_outcome = "phone_otp_controls_unconfirmed"
                failed("sms_provider_error")
                continue

            # 6) 等离开 /phone-verification
            left, final_url = _wait_url_left(page, "/phone-verification", 15)
            if left and "/phone-verification" not in (final_url or ""):
                log_fn(
                    f"  [smsbower] phone OTP 通过 → {_safe_url_for_log(final_url, 120)}, "
                    "确认激活(扣费)"
                )
                try: client.confirm(activation_id)
                except Exception as e: log_fn(f"  [smsbower] confirm 失败 (忽略): {type(e).__name__}")
                return True

            log_fn("  [smsbower] 填 OTP 后未离开 /phone-verification, 验证可能失败")
            try: client.cancel(activation_id)
            except Exception: pass
            visible_error = _detect_visible_error_text(page) or _detect_otp_error_text(page)
            rejection_code = _classify_sms_page_rejection(visible_error, otp=True)
            country_outcome = rejection_code or "phone_otp_unconfirmed"
            failed(rejection_code or "sms_provider_error")
            if rejection_code == "sms_account_restricted":
                log_fn("  [smsbower] OpenAI 已限制验证次数，停止本次取号轮换")
                skip_remaining_countries = True
                break

        country_results.append((country, country_outcome))
        if skip_remaining_countries:
            break
        # NO_NUMBERS 不打"用尽"的话术,因为本就 0 次尝试
        if country_outcome == "NO_NUMBERS":
            continue
        log_fn(
            f"  [smsbower] 国家 {country} 失败 ({country_outcome}, "
            f"试了 {attempts_per_country} 次), 进入下一国家"
        )

    # 总结每国结局,帮用户判断是号段问题还是别的
    summary = ", ".join(f"{c}={o}" for c, o in country_results) or "(无可用尝试)"
    log_fn(f"  [smsbower] 全部国家轮换结束: {summary}")
    return finish_failure()
