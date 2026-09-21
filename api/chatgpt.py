"""ChatGPT 专用功能 API"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlmodel import Session
from pydantic import BaseModel, Field
from typing import Annotated, Optional
from core.db import AccountModel, get_session
from services.chatgpt_account_state import apply_chatgpt_status_policy
from api.auth import require_sensitive_credential_export_auth_header
import json, sys, re


router = APIRouter(prefix="/chatgpt", tags=["chatgpt"])

COUNTRIES = ["SG", "US", "TR", "JP", "HK", "GB", "AU", "CA", "IN", "BR", "MX"]


class UploadRequest(BaseModel):
    account_ids: list[int]
    cpa_api_url: Optional[str] = None
    cpa_api_token: Optional[str] = None
    team_manager_url: Optional[str] = None
    team_manager_key: Optional[str] = None


class ChatGPTSecurityExportBatchRequest(BaseModel):
    account_ids: list[Annotated[int, Field(strict=True, gt=0)]] = Field(
        min_length=1, max_length=500,
    )


_SECURITY_EXPORT_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


def _get_account(account_id: int, session: Session) -> AccountModel:
    acc = session.get(AccountModel, account_id)
    if not acc or acc.platform != "chatgpt":
        raise HTTPException(404, "账号不存在")
    return acc


def _account_security_export_line(acc: AccountModel) -> str:
    """Use only the confirmed encrypted ChatGPT password and long-term seed."""
    from services.chatgpt_security_store import (
        get_chatgpt_security_secrets,
        get_chatgpt_security_status,
    )

    try:
        secret = get_chatgpt_security_secrets(acc.email)
        status = get_chatgpt_security_status(acc.email)
    except Exception as exc:
        # Storage/decryption errors may contain sensitive material. Only a
        # fixed diagnostic crosses either the single or batch export boundary.
        raise HTTPException(409, "安全凭据无法读取或解密") from exc
    if not status.get("credentials_readable"):
        raise HTTPException(409, "安全凭据无法读取或解密")
    password = str(secret.get("password") or "")
    totp_secret = str(secret.get("totp_secret") or "")
    reasons = []
    if not password:
        reasons.append("未保存 ChatGPT 密码")
    elif status.get("password_state") != "configured":
        reasons.append("ChatGPT 密码尚未完成远端确认")
    if not totp_secret:
        reasons.append("未保存 Authenticator 2FA 长期密钥")
    elif status.get("mfa_state") != "enabled":
        reasons.append("Authenticator 2FA 尚未完成远端确认")
    if reasons:
        raise HTTPException(409, "；".join(reasons))
    fields = (str(acc.email or ""), password, totp_secret)
    if any(
        not value or "--" in value or re.search(r"[\x00-\x1f\x7f\x85\u2028\u2029]", value)
        for value in fields
    ):
        raise HTTPException(409, "邮箱或安全凭据包含分隔符或控制字符，无法导出为单行格式")
    return "--".join(fields) + "\n"


@router.get("/{account_id}/security")
def get_account_security_status(
    account_id: int,
    session: Session = Depends(get_session),
):
    """Return workflow state only; credentials and ciphertext stay private."""
    acc = _get_account(account_id, session)
    from services.chatgpt_security_store import get_chatgpt_security_status

    return get_chatgpt_security_status(acc.email)


@router.post("/{account_id}/security/export")
def export_account_security_credentials(
    account_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Export secrets after an authenticated or direct-loopback access check."""
    require_sensitive_credential_export_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    acc = _get_account(account_id, session)
    line = _account_security_export_line(acc)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", acc.email).strip("._") or "chatgpt"
    return Response(
        content=line,
        media_type="text/plain; charset=utf-8",
        headers={
            **_SECURITY_EXPORT_HEADERS,
            "Content-Disposition": f'attachment; filename="{safe_name}_2fa.txt"',
        },
    )


@router.post("/security/export-batch")
def export_account_security_credentials_batch(
    body: ChatGPTSecurityExportBatchRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Export one complete selection, or report every unavailable account."""
    require_sensitive_credential_export_auth_header(
        request.headers.get("Authorization", ""),
        client_host=(request.client.host if request.client else ""),
        request_host=str(request.url.hostname or ""),
    )
    lines = []
    errors = []
    for account_id in dict.fromkeys(body.account_ids):
        try:
            acc = _get_account(account_id, session)
        except HTTPException:
            errors.append({
                "account_id": account_id,
                "email": "",
                "reason": "账号不存在或不属于 ChatGPT 平台",
            })
            continue
        try:
            lines.append(_account_security_export_line(acc))
        except HTTPException as exc:
            errors.append({
                "account_id": account_id,
                "email": acc.email,
                "reason": str(exc.detail),
            })
    if errors:
        raise HTTPException(
            409,
            detail={
                "message": "所选账号未全部具备完整且已确认的密码与2FA，未导出任何账号",
                "errors": errors,
            },
            headers=_SECURITY_EXPORT_HEADERS,
        )
    return Response(
        content="".join(lines),
        media_type="text/plain; charset=utf-8",
        headers={
            **_SECURITY_EXPORT_HEADERS,
            "Content-Disposition": 'attachment; filename="chatgpt_accounts_2fa.txt"',
        },
    )


def _to_codex_account(acc: AccountModel):
    """转换为 codex-register 的 Account 对象（duck-typing）"""
    extra = acc.get_extra()

    class _Acc:
        pass

    a = _Acc()
    a.email = acc.email
    a.access_token = extra.get("access_token") or acc.token
    a.refresh_token = extra.get("refresh_token", "")
    a.id_token = extra.get("id_token", "")
    a.session_token = extra.get("session_token", "")
    a.client_id = extra.get("client_id", "app_EMoamEEZ73f0CkXaXp7hrann")
    a.cookies = extra.get("cookies", "")
    a.user_id = acc.user_id
    # Sub2API 备份包复用账号已经记录的 register_proxy/proxy_url，不在 GET 下载时
    # 临时分配或回退全局代理。
    a.extra = dict(extra)
    return a


def _persist_local_probe(acc: AccountModel, probe: dict, session: Session) -> None:
    extra = acc.get_extra()
    extra["chatgpt_local"] = probe
    acc.set_extra(extra)
    apply_chatgpt_status_policy(acc, local_probe=probe)
    from datetime import datetime
    acc.updated_at = datetime.utcnow()
    session.add(acc)
    session.commit()


# ── Token 刷新 ──────────────────────────────────────────────
@router.post("/{account_id}/refresh-token")
def refresh_token(account_id: int, proxy: Optional[str] = None,
                  session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.token_refresh import TokenRefreshManager
    manager = TokenRefreshManager(proxy_url=proxy)
    result = manager.refresh_account(codex_acc)

    if result.success:
        extra = acc.get_extra()
        extra["access_token"] = result.access_token
        if result.refresh_token:
            extra["refresh_token"] = result.refresh_token
        acc.set_extra(extra)
        acc.token = result.access_token
        from datetime import datetime
        acc.updated_at = datetime.utcnow()
        session.add(acc)
        session.commit()
        return {"ok": True, "access_token": result.access_token[:40] + "..."}
    raise HTTPException(400, result.error_message)


# ── Codex 测试发消息 ────────────────────────────────────────
# 用账号 RT 现刷一份 access_token,直接调 chatgpt.com 的 Codex /responses 通道
# 发一条短消息(默认 "hi"),回收 SSE 拼好返回。仅作连通性测试,不入账户日志。

class CodexTestRequest(BaseModel):
    prompt: str = "hi"
    model: str = "gpt-5.5"
    proxy: Optional[str] = None
    timeout: int = 120


def _decode_chatgpt_account_id(access_token: str) -> str:
    from platforms.chatgpt.utils import decode_jwt_payload
    payload = decode_jwt_payload(access_token) or {}
    auth = payload.get("https://api.openai.com/auth") or {}
    return str(auth.get("chatgpt_account_id") or "").strip()


def _jwt_is_expired(access_token: str, skew_seconds: int = 120) -> bool:
    """access_token 是否已过期(留 skew 余量)。无法解析 exp 时保守视为已过期。"""
    import time
    from platforms.chatgpt.utils import decode_jwt_payload
    try:
        payload = decode_jwt_payload(access_token) or {}
        exp = int(payload.get("exp") or 0)
    except Exception:
        return True
    if not exp:
        return True
    return exp <= int(time.time()) + skew_seconds


_CODEX_APP_NAME = "Codex"   # 默认名; 实际应用名可能是 "ChatGPT"(新版桌面版), 由 config 覆盖


def _codex_app_name() -> str:
    """本机 Codex/ChatGPT 桌面应用名(用于 open -a / quit / System Events 找窗口)。
    新版桌面应用叫 "ChatGPT"(/Applications/ChatGPT.app), 老的叫 "Codex"。
    由 config_store 的 codex_app_name 覆盖, 缺省 "Codex"。"""
    try:
        from core.config_store import config_store as _cs
        v = str(_cs.get("codex_app_name", "") or "").strip()
        return v or _CODEX_APP_NAME
    except Exception:
        return _CODEX_APP_NAME


def _codex_app_control(action: str) -> str:
    """关闭 / 打开本机 Codex App。仅 macOS 生效, 其它平台返回 'unsupported_platform'。

    action: "quit" → 优雅退出并等进程结束; "open" → 重新打开。
    返回简短结果串(success / not_running / not_installed / unsupported_platform / error:...)。
    """
    import sys as _sys
    import subprocess
    import time
    if _sys.platform != "darwin":
        return "unsupported_platform"
    app = _codex_app_name()
    try:
        if action == "quit":
            # 用 osascript 优雅退出(等价于 Cmd+Q),再轮询进程消失
            r = subprocess.run(
                ["osascript", "-e", f'quit app "{app}"'],
                capture_output=True, text=True, timeout=15,
            )
            err = (r.stderr or "").strip()
            if err and "isn't running" in err.lower():
                return "not_running"
            # 等进程真正退出(最多 ~8s),让它落盘并释放 auth.json
            for _ in range(16):
                chk = subprocess.run(
                    ["pgrep", "-f", f"/{app}.app/Contents/MacOS/"],
                    capture_output=True, text=True,
                )
                if not (chk.stdout or "").strip():
                    break
                time.sleep(0.5)
            return "success" if not err else f"warn:{err[:80]}"
        if action == "open":
            r = subprocess.run(
                ["open", "-a", app],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                return "success"
            err = (r.stderr or "").strip()
            if "unable to find application" in err.lower():
                return "not_installed"
            return f"error:{err[:80]}"
        return "noop"
    except Exception as e:
        return f"error:{str(e)[:80]}"


def _codex_app_send_text(text: str = "hi", ready_wait: float = 6.0,
                         pre_type_delay: float = 4.0, activate_delay: float = 0.6) -> str:
    """打开 Codex App 后, 等窗口就绪, 激活并在输入框里键入 text + 回车。

    仅 macOS。依赖运行后端的进程有「辅助功能(Accessibility)」权限,
    且 App 打开后输入框默认获得焦点。尽力而为, 失败不影响同步主流程。

    ready_wait     — 最多等多少秒让 App 窗口出现
    pre_type_delay — 窗口出现后再等多少秒才打字(给 React/Electron 渲染+聚焦输入框)
    activate_delay — activate 之后到 keystroke 之间的停顿

    返回: success / unsupported_platform / no_window / no_accessibility / error:...
    """
    import sys as _sys
    import subprocess
    import time
    if _sys.platform != "darwin":
        return "unsupported_platform"
    app = _codex_app_name()
    # 1. 等窗口出现(最多 ready_wait 秒), 用 System Events 看 App 是否有窗口
    deadline = time.time() + max(1.0, ready_wait)
    has_window = False
    while time.time() < deadline:
        try:
            chk = subprocess.run(
                ["osascript", "-e",
                 f'tell application "System Events" to tell process "{app}" to count windows'],
                capture_output=True, text=True, timeout=8,
            )
            out = (chk.stdout or "").strip()
            err = (chk.stderr or "").strip()
            if "not allowed assistive" in err.lower() or "1002" in err:
                return "no_accessibility"
            if out.isdigit() and int(out) >= 1:
                has_window = True
                break
        except Exception:
            pass
        time.sleep(0.8)
    if not has_window:
        return "no_window"
    # 给前端/输入框渲染+聚焦时间(可调 — App 冷启动较慢时调大)
    time.sleep(max(0.0, pre_type_delay))
    # 2. 激活并键入 text + 回车
    safe_text = (text or "hi").replace('"', '\\"')
    script = (
        f'tell application "{app}" to activate\n'
        f'delay {max(0.1, activate_delay)}\n'
        'tell application "System Events"\n'
        f'  keystroke "{safe_text}"\n'
        '  delay 0.5\n'
        '  key code 36 using command down\n'   # Cmd+Return (多数 AI 输入框的发送键)
        '  delay 0.4\n'
        '  key code 36\n'                       # 普通 Return 兜底(若 Enter 才是发送)
        'end tell\n'
    )
    try:
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=20)
        err = (r.stderr or "").strip()
        if not err:
            return "success"
        low = err.lower()
        if "not allowed assistive" in low or "1002" in err:
            return "no_accessibility"
        return f"error:{err[:80]}"
    except Exception as e:
        return f"error:{str(e)[:80]}"


class CodexSendHiDebugRequest(BaseModel):
    text: str = "hi"
    ready_wait: float = 6.0
    pre_type_delay: float = 4.0
    activate_delay: float = 0.6
    open_first: bool = False   # True = 先 open -a Codex 再发(模拟同步那一步); False = 假设 App 已开着, 只测打字时机


@router.post("/debug/codex-send-hi")
def debug_codex_send_hi(body: CodexSendHiDebugRequest):
    """调试用: 单独测试「在 Codex App 输入框发 hi」, 不做同步/不动 auth.json。

    App 已经开着时, 用 open_first=false 反复调它、改 pre_type_delay 找合适延时;
    想完整复现同步那一步(含 open)就用 open_first=true。
    返回各阶段耗时和 send_hi 结果, 便于定位「敲空了」是不是延时太短。
    """
    import time
    t0 = time.time()
    open_result = ""
    if body.open_first:
        open_result = _codex_app_control("open")
    send = _codex_app_send_text(
        text=body.text or "hi",
        ready_wait=float(body.ready_wait or 6.0),
        pre_type_delay=float(body.pre_type_delay or 0.0),
        activate_delay=float(body.activate_delay or 0.6),
    )
    return {
        "ok": send == "success",
        "open_first": body.open_first,
        "open_result": open_result,
        "send_hi": send,
        "elapsed_seconds": round(time.time() - t0, 2),
        "params": {
            "text": body.text, "ready_wait": body.ready_wait,
            "pre_type_delay": body.pre_type_delay, "activate_delay": body.activate_delay,
        },
        "hint": ("敲空了多半是 pre_type_delay 太短, App 还没渲染好输入框就打字了 —— 调大它再试"
                 if send == "success" else None),
    }



@router.post("/{account_id}/codex-test")
def codex_test(account_id: int, body: CodexTestRequest,
               session: Session = Depends(get_session)):
    """用账号 RT 跑一次 Codex 通道 hi 测试。返回 reply 字串 + 调试信息。"""
    acc = _get_account(account_id, session)
    extra = acc.get_extra() if hasattr(acc, "get_extra") else {}
    rt = (extra.get("refresh_token") or "").strip()
    if not rt:
        raise HTTPException(400, "该账号没有 refresh_token,先点「补 RT」拿到 RT 再测")

    # 全局代理(若请求体未指定),跟其它 OAuth/Codex 调用一致
    proxy = (body.proxy or "").strip()
    if not proxy:
        from core.config_store import config_store as _cs
        proxy = (str(_cs.get("default_proxy", "") or "").strip()
                 or str(_cs.get("proxy", "") or "").strip())
    proxy = proxy or None

    # 1. RT → 新 access_token(顺手回写,跟 refresh-token 端点同套路)
    from platforms.chatgpt.token_refresh import TokenRefreshManager
    rt_result = TokenRefreshManager(proxy_url=proxy).refresh_by_oauth_token(rt)
    if not rt_result.success or not rt_result.access_token:
        raise HTTPException(
            502,
            f"刷新 access_token 失败: {rt_result.error_message or '未知错误'}",
        )
    access_token = rt_result.access_token
    try:
        extra["access_token"] = access_token
        if rt_result.refresh_token and rt_result.refresh_token != rt:
            extra["refresh_token"] = rt_result.refresh_token
        acc.set_extra(extra)
        acc.token = access_token
        from datetime import datetime
        acc.updated_at = datetime.utcnow()
        session.add(acc)
        session.commit()
    except Exception:
        session.rollback()

    # 2. JWT → chatgpt_account_id
    chatgpt_account_id = _decode_chatgpt_account_id(access_token)
    if not chatgpt_account_id:
        raise HTTPException(400, "无法从 access_token 解析 chatgpt_account_id")

    # 3. 调 Codex 通道
    from platforms.chatgpt.codex_chat import codex_chat
    result = codex_chat(
        access_token=access_token,
        chatgpt_account_id=chatgpt_account_id,
        prompt=body.prompt or "hi",
        model=body.model or "gpt-5.5",
        proxy=proxy,
        timeout=max(30, min(300, int(body.timeout or 120))),
    )
    return {
        "ok": bool(result.get("ok")),
        "reply": result.get("reply", ""),
        "model": result.get("model", body.model),
        "chunks": result.get("chunks", 0),
        "latency_ms": result.get("latency_ms", 0),
        "http_status": result.get("http_status", 0),
        "raw_error": result.get("raw_error", ""),
        "chatgpt_account_id": chatgpt_account_id,
    }


# ── 同步到本地 Codex App (~/.codex/auth.json) ────────────────────
# 把账号的 RT/AT/IDT/account_id 写入本地 Codex CLI / 桌面 App 的 auth 文件,
# 这样本地 Codex App 就立即用这个号(下次启动 / 下次刷 token 时生效)。
# 注意: 此操作会覆盖 ~/.codex/auth.json,操作前会备份到 ~/.codex/auth.json.bak
@router.post("/{account_id}/sync-to-codex-app")
def sync_to_codex_app(account_id: int, session: Session = Depends(get_session)):
    import os
    from datetime import datetime, timezone
    from pathlib import Path

    acc = _get_account(account_id, session)
    extra = acc.get_extra() if hasattr(acc, "get_extra") else {}
    rt = (extra.get("refresh_token") or "").strip()
    if not rt:
        raise HTTPException(400, "该账号没有 refresh_token,先点「补 RT」拿到 RT 再同步")

    # 1. 全局代理
    from core.config_store import config_store as _cs
    proxy = (str(_cs.get("default_proxy", "") or "").strip()
             or str(_cs.get("proxy", "") or "").strip()) or None

    # 2. 用 RT 刷一次拿最新 AT (id_token 走 OAuth refresh 不一定返回,
    #    所以用 extra 里已有的 IDT — 即使旧 Codex App 自己会再刷)
    from platforms.chatgpt.token_refresh import TokenRefreshManager
    rt_result = TokenRefreshManager(proxy_url=proxy).refresh_by_oauth_token(rt)
    if rt_result.success and rt_result.access_token:
        access_token = rt_result.access_token
        new_rt = rt_result.refresh_token or rt
    else:
        # 刷新失败(常见: refresh_token_reused — RT 已被用过一次轮换作废)。
        # 回退: 只要库里现有 access_token 还没过期, 直接用它写 auth.json。
        err = rt_result.error_message or "未知错误"
        cached_at = (extra.get("access_token") or acc.token or "").strip()
        if cached_at and not _jwt_is_expired(cached_at):
            access_token = cached_at
            new_rt = rt  # RT 已失效, 沿用旧值(写进去仅供 App 兜底, App 会因 reused 无法续期)
        else:
            raise HTTPException(
                502,
                f"刷新 access_token 失败: {err}。"
                + ("库里 access_token 也已过期/缺失,请先重新「补 RT」(OAuth 登录)拿新 RT 再同步。"
                   if cached_at else "库里没有可回退的 access_token,请先「补 RT」。"),
            )
    id_token = str(extra.get("id_token") or "").strip()

    # 3. JWT → chatgpt_account_id
    chatgpt_account_id = _decode_chatgpt_account_id(access_token)
    if not chatgpt_account_id:
        raise HTTPException(400, "无法从 access_token 解析 chatgpt_account_id")

    # 4. 回写 DB(跟 codex-test 一致,避免下次又拿过期 AT)
    try:
        extra["access_token"] = access_token
        if new_rt != rt:
            extra["refresh_token"] = new_rt
        acc.set_extra(extra)
        acc.token = access_token
        acc.updated_at = datetime.utcnow()
        session.add(acc)
        session.commit()
    except Exception:
        session.rollback()

    # 5. 写 ~/.codex/auth.json (单次覆盖,先备份旧文件成 .bak)
    #    先关闭 Codex App 再写, 否则正在运行的 App 会用自己的 token 周期性回写,
    #    把刚同步进去的账号覆盖掉(就是之前"写了没生效")。写完再重新打开。
    rt_fallback = (new_rt == rt and (not rt_result.success or not rt_result.access_token))
    app_actions: dict = {"quit": "", "open": ""}
    app_actions["quit"] = _codex_app_control("quit")

    auth_path = Path(os.path.expanduser("~/.codex/auth.json"))
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = ""
    if auth_path.exists():
        bak = auth_path.with_suffix(".json.bak")
        try:
            bak.write_bytes(auth_path.read_bytes())
            backup_path = str(bak)
        except Exception:
            pass

    auth_data = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": new_rt,
            "account_id": chatgpt_account_id,
        },
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }
    try:
        auth_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False))
        try:
            os.chmod(auth_path, 0o600)
        except Exception:
            pass
    except Exception as e:
        # 写失败也尽量把 App 重新拉起来,避免停在已退出状态
        app_actions["open"] = _codex_app_control("open")
        raise HTTPException(500, f"写入 {auth_path} 失败: {e}")

    # 写完重新打开 Codex App, 让它加载新 auth.json
    app_actions["open"] = _codex_app_control("open")

    # 打开后等窗口就绪, 在输入框自动键入 "hi" 并发送(尽力而为, 失败不影响同步)
    if app_actions["open"] == "success":
        try:
            from core.config_store import config_store as _cs2
            ready_wait = float(str(_cs2.get("codex_app_ready_wait_seconds", "") or 6) or 6)
            pre_type_delay = float(str(_cs2.get("codex_app_pre_type_delay_seconds", "") or 4) or 4)
        except Exception:
            ready_wait, pre_type_delay = 6.0, 4.0
        app_actions["send_hi"] = _codex_app_send_text(
            "hi", ready_wait=ready_wait, pre_type_delay=pre_type_delay)
    else:
        app_actions["send_hi"] = "skipped"

    return {
        "ok": True,
        "auth_path": str(auth_path),
        "backup_path": backup_path,
        "email": acc.email,
        "chatgpt_account_id": chatgpt_account_id,
        "id_token_present": bool(id_token),
        "rt_fallback": rt_fallback,   # True = RT 失效, 用现有 AT 兜底(AT 到期后需重新补 RT)
        "app_restart": app_actions,   # quit/open 各自结果(success/skipped/平台不支持等)
    }


# ── 生成支付链接 ────────────────────────────────────────────
class PaymentReq(BaseModel):
    plan: str = "plus"  # plus | team
    country: str = "SG"
    proxy: Optional[str] = None
    workspace_name: str = "MyTeam"
    seat_quantity: int = 5
    price_interval: str = "month"


# ── 插件桥接 API ────────────────────────────────────────────
# 给 paypal_auto_select / windsurfAutoPay 等 Chrome 插件用的端点:
# 1) GET /accounts/pending-payments  - 拉取待支付 ChatGPT 账号列表 (含 cookies)
# 2) POST /accounts/{id}/mark-paid   - 标记某账号支付完成
# 3) POST /accounts/mark-paid-batch  - 批量标记
# 全部走 X-Admin-Token (config: payment_bridge_admin_token) 鉴权,
# 跟 /api/devin/accounts/* 那套是平行实现。
# ────────────────────────────────────────────────────────────


class ChatGPTMarkPaidRequest(BaseModel):
    note: Optional[str] = ""


class ChatGPTMarkPaidBatchRequest(BaseModel):
    account_ids: list[int]
    note: Optional[str] = ""


def _chatgpt_payment_url(acc: AccountModel, extra: dict) -> str:
    """ChatGPT 的支付链接放在 cashier_url(register 时 _maybe_generate_payment_link 写入)"""
    return (acc.cashier_url or extra.get("cashier_url", "") or "").strip()


def _chatgpt_pay_status(extra: dict, payment_url: str) -> str:
    """简化版状态机:
       extra.pay_status / extra.chatgpt_status 优先;否则按 cashier_url 推断:
         有 url → pending,无 url → 没支付链接 (跳过)
    """
    raw = (extra.get("pay_status") or extra.get("chatgpt_status") or "").strip().lower()
    if raw in ("paid", "synced", "completed"):
        return "paid"
    if raw == "failed":
        return "failed"
    if raw in ("pending", ""):
        return "pending" if payment_url else "no_url"
    return raw


def _normalize_cookies(raw):
    """ChatGPT 的 cookies 字段历史上存的是 JSON 字符串 (json.dumps(dict)),
    给插件返时统一 parse 成 dict;已经是 dict / list / array 也兼容。"""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        # 转 array of {name,value} 为 flat map (插件 normalizeAccountCookieMap 都接受)
        out = {}
        for item in raw:
            if isinstance(item, dict):
                n = (item.get("name") or "").strip()
                v = (item.get("value") or "").strip()
                if n and v:
                    out[n] = v
        return out
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return _normalize_cookies(parsed)  # 递归一次,可能 parse 出 list 或 dict
        except Exception:
            return {}
    return {}


@router.get("/accounts/pending-payments")
def chatgpt_pending_payments(
    page: int = 1,
    page_size: int = 100,
):
    """给 Chrome 插件用的待支付 ChatGPT 账号列表。

    返回格式跟 /api/devin/accounts/pending-payments 镜像,字段命名一致,
    插件 (windsurfAutoPay / paypal_auto_select) 用同一套 client 代码就能消费。

    每条 item:
      id            - 账号 DB id
      account_name  - 显示名 (邮箱)
      email         - 邮箱
      payment_url   - https://chatgpt.com/checkout/openai_llc/cs_xxx
      access_token  - ChatGPT API Bearer token (注册时 _post_register_session_snapshot 拿)
      session_token - __Secure-next-auth.session-token (注册时拿到)
      cookies       - dict {name: value}, 用于浏览器登录态预加载到 .chatgpt.com
                      (插件 cookie-injector 注入到 chatgpt.com 后,打开 payment_url 不再 500)
      created_at    - ISO 时间
    """
    # 鉴权:走全局 payment_bridge_admin_token (跟 Devin 的桥接同一个 token)
    from api.payment_bridge import require_bridge_admin_token
    from fastapi import Request
    # 不强制要求 header (避免破坏现有 UI 调用),但有 token 时验证
    # 实际上保留 Depends 更严格 — 用 Depends 形式

    safe_page = max(int(page or 1), 1)
    safe_page_size = min(max(int(page_size or 100), 1), 500)

    from sqlmodel import select
    from core.db import engine

    with Session(engine) as session:
        rows = session.exec(
            select(AccountModel)
            .where(AccountModel.platform == "chatgpt")
            .order_by(AccountModel.created_at.desc())
        ).all()

    pending = []
    for acc in rows:
        extra = acc.get_extra()
        payment_url = _chatgpt_payment_url(acc, extra)
        status = _chatgpt_pay_status(extra, payment_url)
        if status != "pending":
            continue

        cookies = _normalize_cookies(extra.get("cookies"))

        pending.append(
            {
                "id": acc.id,
                "account_name": acc.email or "",
                "email": acc.email or "",
                "payment_url": payment_url,
                "access_token": extra.get("access_token", "") or acc.token or "",
                "session_token": extra.get("session_token", ""),
                "cookies": cookies,
                "payment_plan": extra.get("payment_plan", ""),
                "payment_country": extra.get("payment_country", ""),
                "created_at": acc.created_at.isoformat() if acc.created_at else "",
            }
        )

    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return {
        "total": len(pending),
        "page": safe_page,
        "page_size": safe_page_size,
        "items": pending[start:end],
    }


def _apply_chatgpt_mark_paid(acc: AccountModel, note: str) -> dict:
    """把账号 extra.pay_status / chatgpt_status 设为 paid,记录 paid_at + note"""
    import time as _time
    extra = acc.get_extra()
    extra["pay_status"] = "paid"
    extra["chatgpt_status"] = "paid"
    extra["pay_confirmed_at"] = int(_time.time())
    if note:
        extra["pay_note"] = note[:500]
    acc.set_extra(extra)
    from datetime import datetime
    acc.updated_at = datetime.utcnow()
    return {
        "ok": True,
        "account_id": acc.id,
        "email": acc.email,
        "pay_status": "paid",
    }


@router.post("/accounts/{account_id}/mark-paid")
def chatgpt_mark_paid(
    account_id: int,
    body: Optional[ChatGPTMarkPaidRequest] = None,
    session: Session = Depends(get_session),
):
    """标记 ChatGPT 账号支付完成。

    用法 1 (UI): 前端按钮 → POST /api/chatgpt/accounts/{id}/mark-paid
    用法 2 (插件): 支付脚本付款成功后调用
    """
    acc = session.get(AccountModel, account_id)
    if not acc:
        raise HTTPException(404, f"账号 {account_id} 不存在")
    if acc.platform != "chatgpt":
        raise HTTPException(400, f"账号 {account_id} 不是 ChatGPT 平台")

    note = (body.note if body else None) or ""
    result = _apply_chatgpt_mark_paid(acc, note)
    session.add(acc)
    session.commit()
    return result


@router.post("/accounts/mark-paid-batch")
def chatgpt_mark_paid_batch(body: ChatGPTMarkPaidBatchRequest):
    """批量标记 ChatGPT 账号支付完成"""
    from core.db import engine
    account_ids = []
    seen = set()
    for raw_id in body.account_ids or []:
        try:
            aid = int(raw_id)
        except (TypeError, ValueError):
            continue
        if aid > 0 and aid not in seen:
            seen.add(aid)
            account_ids.append(aid)
    if not account_ids:
        raise HTTPException(400, "account_ids 不能为空")
    if len(account_ids) > 500:
        raise HTTPException(400, "单次最多回调 500 个账号")

    note = body.note or ""
    items = []
    with Session(engine) as session:
        for aid in account_ids:
            acc = session.get(AccountModel, aid)
            if not acc:
                items.append({"ok": False, "account_id": aid, "error": "账号不存在"})
                continue
            if acc.platform != "chatgpt":
                items.append({"ok": False, "account_id": aid, "error": "不是 ChatGPT 账号"})
                continue
            result = _apply_chatgpt_mark_paid(acc, note)
            items.append(result)
            session.add(acc)
        session.commit()

    success = sum(1 for item in items if item.get("ok"))
    return {
        "ok": success == len(items),
        "success": success,
        "failed": len(items) - success,
        "items": items,
    }


# ── 单账号生成支付链接 (原有,UI 用) ────────────────────────────
@router.post("/{account_id}/payment-link")
def generate_payment_link(account_id: int, req: PaymentReq,
                          session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.payment import generate_plus_link, generate_team_link
    if req.plan == "plus":
        url = generate_plus_link(codex_acc, proxy=req.proxy, country=req.country)
    else:
        url = generate_team_link(
            codex_acc, workspace_name=req.workspace_name,
            price_interval=req.price_interval, seat_quantity=req.seat_quantity,
            proxy=req.proxy, country=req.country
        )
    return {"url": url, "plan": req.plan, "country": req.country}


# ── 检查订阅状态 ────────────────────────────────────────────
@router.get("/{account_id}/subscription")
def check_subscription(account_id: int, proxy: Optional[str] = None,
                       session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.status_probe import probe_local_chatgpt_status

    probe = probe_local_chatgpt_status(codex_acc, proxy=proxy)
    _persist_local_probe(acc, probe, session)
    return {
        "email": acc.email,
        "subscription": probe.get("subscription", {}).get("plan", "unknown"),
        "probe": probe,
    }


@router.post("/{account_id}/probe-local")
def probe_local_status(account_id: int, proxy: Optional[str] = None,
                       session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.status_probe import probe_local_chatgpt_status

    probe = probe_local_chatgpt_status(codex_acc, proxy=proxy)
    _persist_local_probe(acc, probe, session)
    return {"ok": True, "email": acc.email, "probe": probe}


# ── CPA 上传 ────────────────────────────────────────────────
class CpaUploadReq(BaseModel):
    api_url: str
    api_key: str = ""


@router.post("/{account_id}/upload-cpa")
def upload_cpa(account_id: int, req: CpaUploadReq,
               session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.cpa_upload import upload_to_cpa, generate_token_json
    token_data = generate_token_json(codex_acc)
    ok, msg = upload_to_cpa(token_data, api_url=req.api_url, api_key=req.api_key)
    return {"ok": ok, "message": msg}


class Sub2ApiUploadReq(BaseModel):
    api_url: str
    api_key: str = ""


@router.post("/{account_id}/upload-sub2api")
def upload_sub2api(account_id: int, req: Sub2ApiUploadReq,
                   session: Session = Depends(get_session)):
    acc = _get_account(account_id, session)
    codex_acc = _to_codex_account(acc)

    from platforms.chatgpt.sub2api_upload import upload_to_sub2api

    ok, msg = upload_to_sub2api(
        codex_acc,
        api_url=req.api_url,
        api_key=req.api_key,
    )
    return {"ok": ok, "message": msg}


# ── BUSINESS OAuth 文件下载 ──────────────────────────────────────
@router.get("/{account_id}/oauth-file")
def download_oauth_file(account_id: int, refresh: bool = True, proxy: Optional[str] = None,
                        fmt: str = "cpa",
                        session: Session = Depends(get_session)):
    """生成并下载 BUSINESS 账号的 OAuth 授权文件。

    refresh: CPA 默认 True → 先刷新 token 再生成；Sub2API 导出始终只读现有凭证
    fmt:     cpa (默认,Codex 格式) | sub2api (Sub2API 平台导入格式)
    """
    acc = _get_account(account_id, session)
    extra = acc.get_extra()
    fmt_norm = (fmt or "cpa").strip().lower()
    is_sub2api_bundle = fmt_norm in ("sub2api", "sub", "sub-2-api")

    if str(extra.get("account_type", "")).upper() != "BUSINESS":
        raise HTTPException(400, "仅 BUSINESS 类型账号支持导出 OAuth 文件")

    codex_acc = _to_codex_account(acc)
    refresh_error = ""

    # 先刷新一次 token
    # GET 下载不能轮换/写回 Sub2API 凭证；完整导入包只读取当前已持久化的
    # AT/RT/ID token。CPA 保留原有 refresh 参数行为以兼容既有客户端。
    if refresh and not is_sub2api_bundle:
        try:
            from platforms.chatgpt.token_refresh import TokenRefreshManager
            manager = TokenRefreshManager(proxy_url=proxy)
            result = manager.refresh_account(codex_acc)
            if result.success:
                extra["access_token"] = result.access_token
                if result.refresh_token:
                    extra["refresh_token"] = result.refresh_token
                acc.set_extra(extra)
                acc.token = result.access_token
                from datetime import datetime
                acc.updated_at = datetime.utcnow()
                session.add(acc)
                session.commit()
                codex_acc.access_token = result.access_token
                if result.refresh_token:
                    codex_acc.refresh_token = result.refresh_token
            else:
                refresh_error = result.error_message
        except Exception as exc:
            refresh_error = str(exc)

    missing = []
    if not str(getattr(codex_acc, "access_token", "") or "").strip():
        missing.append("access_token")
    if missing:
        register_mode = str(extra.get("register_mode") or extra.get("chatgpt_registration_mode") or "").strip() or "unknown"
        reason_parts = [f"账号缺少 {', '.join(missing)}", f"register_mode={register_mode}"]
        if refresh_error:
            reason_parts.append(f"刷新失败: {refresh_error}")
        if not str(getattr(codex_acc, "session_token", "") or "").strip():
            reason_parts.append("账号也缺少 session_token，注册后的 Web 会话未落地")
        raise HTTPException(400, "；".join(reason_parts))

    from platforms.chatgpt.cpa_upload import generate_token_json
    token_data = generate_token_json(codex_acc)
    # token_data 已最小化,补 id_token / email 让 sub2api 构造器能从 JWT 抽 plan_type/org_id
    if not token_data.get("id_token"):
        token_data["id_token"] = getattr(codex_acc, "id_token", "") or ""
    if not token_data.get("email"):
        token_data["email"] = acc.email

    safe_email = re.sub(r"[^a-zA-Z0-9._-]", "_", acc.email)
    if is_sub2api_bundle:
        from platforms.chatgpt.sub2api_upload import build_sub2api_bundle_from_token_data
        try:
            output_data = build_sub2api_bundle_from_token_data(
                token_data,
                account=codex_acc,
                proxy_url=proxy,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        filename = f"sub2api_{safe_email}.json"
    else:
        # CPA: 只输出 type/access_token/refresh_token (最小化,无 ST)
        output_data = {
            "type": token_data.get("type") or "codex",
            "access_token": token_data.get("access_token") or "",
            "refresh_token": token_data.get("refresh_token") or "",
        }
        filename = f"oauth_{safe_email}.json"
    body = json.dumps(output_data, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


# ── DrissionPage 邮箱 OTP 登陆 ──────────────────────────────
#
# 与 GPT PRO 账号页的「登陆」按钮同一套逻辑: 复用
# platforms.chatgpt.gpt_pro_login.login_with_email_otp —
#   打开 chatgpt.com/auth/login → 填邮箱 → 点继续 → 从账号自己的 Outlook 邮箱取 OTP
#   → 填入提交 → 等到 chatgpt.com 主页 → 调 /api/auth/session 拿 access_token/plan_type
#
# 与 GPT PRO 版唯一的差别是账号来源: 那边读 gpt_pro_accounts 表的独立列,
# 这里读 accounts 表 extra_json 里的 outlook_mail_* 取件凭证。通用
# refresh_token 属于 ChatGPT OAuth，绝不能作为 Outlook 邮件 RT 使用。
# 默认可见浏览器 + 登陆成功后留窗交人工, 与 GPT PRO 一致。


class ChatGPTLoginRequest(BaseModel):
    proxy: Optional[str] = None      # None = 用 config_store.default_proxy
    headless: bool = False           # False = 可见浏览器, True = 无头
    otp_timeout: int = 180
    keep_browser_open: bool = True   # True = 登陆成功后不退出浏览器, 由人工关闭


def _resolve_login_proxy(body: "ChatGPTLoginRequest") -> str:
    if body.proxy is not None:
        return str(body.proxy or "").strip()
    try:
        from core.config_store import config_store
        return str(config_store.get("default_proxy", "") or "").strip()
    except Exception:
        return ""


def _build_login_mailbox_snapshot(email: str, extra: dict) -> dict[str, str]:
    """Build an Outlook-only credential view for the Drission login flow.

    New records use ``outlook_mail_*``.  The older, still unambiguous
    ``outlook_*`` aliases remain readable, while the unqualified
    ``refresh_token`` is deliberately excluded because it is the ChatGPT RT.
    ``client_id``/``password`` remain compatibility fallbacks: neither can
    authenticate Outlook OAuth without an explicitly Outlook-owned RT.
    """
    source = extra if isinstance(extra, dict) else {}

    def value(*keys: str) -> str:
        for key in keys:
            candidate = str(source.get(key) or "").strip()
            if candidate:
                return candidate
        return ""

    return {
        "email": str(email or "").strip(),
        "outlook_mail_password": value(
            "outlook_mail_password",
            "outlook_password",
            "password",
        ),
        "outlook_mail_client_id": value(
            "outlook_mail_client_id",
            "outlook_client_id",
            "client_id",
        ),
        "outlook_mail_refresh_token": value(
            "outlook_mail_refresh_token",
            "outlook_refresh_token",
        ),
        "outlook_mail_access_type": value(
            "outlook_mail_access_type",
            "mail_access_type",
        ).lower(),
    }


def _requires_saved_chatgpt_security_login(email: str) -> bool:
    """Return whether this account must use its saved password + TOTP.

    A persisted seed, or a durable pending/enabled/unmanaged MFA state, means
    the remote account may challenge for Authenticator.  In that case the
    login endpoint must never fall back to mailbox OTP merely because mailbox
    credentials are missing.  Secret decryption stays inside the canonical
    browser login dispatcher in ``gpt_pro_login``.
    """
    from services.chatgpt_security_store import get_chatgpt_security_status

    try:
        status = get_chatgpt_security_status(email)
    except Exception as exc:
        raise HTTPException(503, "账号安全状态读取失败，已停止登录") from exc
    mfa_state = str(status.get("mfa_state") or "").strip().lower()
    return bool(status.get("has_totp")) or mfa_state in {
        "pending",
        "enabled",
        "unmanaged",
    }


@router.post("/{account_id}/login")
def drission_login(account_id: int, body: Optional[ChatGPTLoginRequest] = None,
                   session: Session = Depends(get_session)):
    """DrissionPage 登录；已启用 MFA 时使用密码 + Authenticator。

    成功后只记录登陆痕迹 (extra.last_login_at / extra.plan_type + updated_at),
    不改 status / token —— 跟 GPT PRO 版「登陆只更新 last_used, 不动 is_pro」对齐。
    """
    from datetime import datetime
    from platforms.chatgpt.gpt_pro_login import build_outlook_mailbox, login_with_email_otp

    body = body or ChatGPTLoginRequest()
    acc = _get_account(account_id, session)
    extra = acc.get_extra()

    # acc.password 是 ChatGPT 账号密码，不能作为邮箱密码兜底。邮箱兼容密码
    # 仅来自 extra，且通用 refresh_token 始终视为 ChatGPT RT。
    snapshot = _build_login_mailbox_snapshot(acc.email, extra)
    mail_provider = str(extra.get("mail_provider") or extra.get("provider") or "").strip().lower()
    proxy = _resolve_login_proxy(body)
    security_login_required = _requires_saved_chatgpt_security_login(acc.email)
    if security_login_required:
        # The canonical dispatcher decrypts the ChatGPT password/TOTP inside
        # the backend process.  Mailbox credentials are neither required nor
        # constructed for this path.
        mailbox = None
        mb_account = None
    else:
        if mail_provider and mail_provider != "outlook":
            raise HTTPException(
                400,
                f"该账号用的是 {mail_provider} 邮箱(非 Outlook), 这个登录流程只会去 Outlook 收 OTP, "
                "跑不通 —— 请改用对应邮箱的登录方式",
            )
        has_oauth = bool(
            snapshot["outlook_mail_client_id"]
            and snapshot["outlook_mail_refresh_token"]
        )
        if not has_oauth and not snapshot["outlook_mail_password"]:
            raise HTTPException(
                400,
                "该账号没有邮箱取件凭证 (缺 OAuth client_id/refresh_token, 也没有邮箱密码), "
                "无法自动收 OTP —— 请先补全邮箱凭证再登录",
            )
        mailbox, mb_account = build_outlook_mailbox(snapshot, proxy=proxy)
    result = login_with_email_otp(
        email=acc.email,
        mailbox=mailbox,
        mailbox_account=mb_account,
        headless=bool(body.headless),
        proxy=proxy,
        otp_timeout=int(body.otp_timeout or 180),
        keep_browser_open=bool(body.keep_browser_open),
    )

    if result.ok:
        extra["last_login_at"] = datetime.utcnow().isoformat()
        if result.plan_type:
            extra["plan_type"] = result.plan_type
        acc.set_extra(extra)
        acc.updated_at = datetime.utcnow()
        session.add(acc)
        session.commit()
    return result.to_dict()
