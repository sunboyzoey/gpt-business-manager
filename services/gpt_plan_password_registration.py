"""Password-first registration for an already selected, leased invitation child.

The caller owns selection and the plan-operation lease. This adapter never
allocates an email, exports credentials, invites a member, or acquires RT.
"""
from __future__ import annotations

import time
from types import SimpleNamespace


def should_register(account, security: dict) -> bool:
    """Missing cookies alone do not make a known account a new registration."""
    return not any((
        getattr(account, "chatgpt_user_id", ""), getattr(account, "chatgpt_account_id", ""),
        getattr(account, "last_login_at", None), getattr(account, "cookie_updated_at", None),
        getattr(account, "cookie_blob", ""), security.get("has_totp") is True,
        security.get("password_state") == "configured",
        security.get("mfa_state") in {"enabled", "pending", "unmanaged"},
    ))


def needs_saved_password_login(status: dict) -> bool:
    """Use the saved password while MFA is still absent.

    A completed profile can make the password durable before the surrounding
    browser callback manages to save a usable Cookie.  Falling back to the
    generic email-OTP login at that point needlessly depends on Gmail again
    and breaks the password -> same-session MFA continuation.
    """
    from platforms.chatgpt.account_security import _unsubmitted_password_candidate
    return (status.get("credentials_readable") is True and status.get("has_password") is True
            and status.get("password_state") in {"pending", "unknown", "configured"}
            and status.get("has_totp") is not True
            and status.get("mfa_state") not in {"pending", "enabled", "unmanaged"}
            and not _unsubmitted_password_candidate(status))


def login_saved_password_in_session(*, email, proxy, headless, assert_owned, on_authenticated, emit):
    """Verify a saved password, then keep that same page for 2FA."""
    from services import chatgpt_security_store as store
    from platforms.chatgpt import gpt_pro_login as login
    from platforms.chatgpt.account_security import _fresh_in_session_identity
    lease = None
    password = ""
    callback_error = None
    try:
        assert_owned()
        lease = store.acquire_chatgpt_security_lease(email)
        if not lease:
            raise RuntimeError("busy")
        snapshot = store.get_chatgpt_security_status(email)
        if not needs_saved_password_login(snapshot):
            raise RuntimeError("state changed")
        password = str(store.get_chatgpt_security_secrets(email).get("password") or "")
        if not password:
            raise RuntimeError("unreadable")

        def authenticated(page, result):
            nonlocal lease, callback_error
            try:
                assert_owned()
                if not store.renew_chatgpt_security_lease(email, lease):
                    raise RuntimeError("lease changed")
                _fresh_in_session_identity(page, email, emit)
                current = store.get_chatgpt_security_status(email)
                fields = ("updated_at", "password_updated_at", "mfa_updated_at", "password_state", "mfa_state")
                if (any(current.get(k) != snapshot.get(k) for k in fields)
                        or store.get_chatgpt_security_secrets(email).get("password") != password):
                    raise RuntimeError("credentials changed")
                # This helper has submitted the stored password in a clean
                # login and verified the protected identity. OTP alone cannot
                # reach this callback through the password-login primitive.
                store.update_chatgpt_security_state(email, password_state="configured", last_error="")
                store.release_chatgpt_security_lease(email, lease)
                lease = None
                emit("已保存密码登录成功，继续在当前窗口设置 2FA")
                return on_authenticated(page, result)
            except Exception:
                callback_error = "旧密码登录结果无法保存，已保留原凭据等待重试"
                return {"ok": False, "error": callback_error}

        result = login._login_with_password_totp(email, password, "", proxy=proxy,
            headless=headless, keep_browser_open=False, post_login_action=authenticated,
            checkout_session_recovery=True,
            log_fn=lambda message: emit(str(message).replace(
                "检测到已管理的 Authenticator 2FA，使用密码 + Authenticator 登录",
                "恢复上次保存的密码，使用密码登录")))
        if callback_error:
            result.ok = False
            result.error = callback_error
        if not result.ok and result.error == (
                "登录页面停在邮箱验证码页，等待期限内未出现密码登录入口；未用邮箱验证码替代密码核验"):
            # This permits recovery of the session only. It never proves the
            # candidate password or permits replacing an existing password.
            result.email_session_recovery = True
        return result
    except Exception:
        return SimpleNamespace(ok=False, email=email, stage="password_totp_login",
            error="旧密码登录恢复未完成，已保留原凭据等待自动重试")
    finally:
        if lease:
            try:
                store.release_chatgpt_security_lease(email, lease)
            except Exception:
                pass
        password = ""


def register_in_session(*, email, mailbox, mailbox_account, proxy, headless,
                        assert_owned, on_authenticated, emit, browser_started):
    """Return a login-shaped outcome; continue on the page before closing it.

    ``existing_account`` is an explicit registrar route result, never guessed
    from an arbitrary exception. The caller can then use the existing login
    workflow. A staged password is reused after interruption, never replaced.
    """
    from platforms.chatgpt import drission_register as register
    from platforms.chatgpt.account_security import (
        _session_identity_with_retry, _unsubmitted_password_candidate,
        VerifiedUnsubmittedPasswordEvidence, _UNSUBMITTED_PASSWORD_PREFIX,
    )
    from services import chatgpt_security_store as security

    candidate_snapshot = {}
    submission_started = False

    def unsubmitted_evidence():
        if submission_started or not _unsubmitted_password_candidate(candidate_snapshot):
            return None
        return VerifiedUnsubmittedPasswordEvidence(
            email=email, security_updated_at=candidate_snapshot["updated_at"],
            password_updated_at=candidate_snapshot["password_updated_at"],
            mfa_updated_at=candidate_snapshot["mfa_updated_at"],
        )

    def failed(reason, *, existing=False, error_code=""):
        return SimpleNamespace(ok=False, email=email, stage="password_registration",
                               error=reason, error_code=error_code, existing_account=existing, cookies={},
                               access_token="", session_token="", action_result=None,
                               unsubmitted_password_evidence=unsubmitted_evidence() if existing else None)

    page = None
    lease = None
    password = ""
    phase = "ownership"
    try:
        assert_owned()
        if mailbox is None or mailbox_account is None or str(mailbox_account.email).strip().casefold() != email:
            return failed("注册收件账号与选中的子号不一致")
        # Capture a strict baseline before the form can send its first email.
        # Do not use the legacy helper, which may downgrade failed reads to [].
        phase = "mailbox_baseline"
        emit("注册前检查收件连接，建立验证码邮件基线")
        not_before = time.time()
        before_ids = mailbox.get_current_ids(mailbox_account, strict=True)
        if not isinstance(before_ids, (set, frozenset, list, tuple)):
            return failed("注册前邮件基线未确认，尚未提交注册")
        before_ids = set(before_ids)
        assert_owned()
        phase = "credential_preparation"
        lease = security.acquire_chatgpt_security_lease(email)
        if not lease:
            return failed("账号安全设置正在由其他任务处理，尚未提交注册")
        status = security.get_chatgpt_security_status(email)
        if (status.get("credentials_readable") is not True or status.get("has_totp") is True
                or status.get("password_state") == "configured"):
            return failed("账号安全状态已变化，等待重新读取后继续")
        if status.get("has_password"):
            password = str(security.get_chatgpt_security_secrets(email).get("password") or "")
        else:
            password = register.generate_password()
            security.stage_chatgpt_password(email, password, state="pending")
            security.update_chatgpt_security_state(email, password_state="pending",
                last_error=_UNSUBMITTED_PASSWORD_PREFIX + "等待密码注册页面")
        candidate_snapshot = security.get_chatgpt_security_status(email)
        if not password:
            return failed("注册密码无法读取，尚未提交注册")

        def still_owned():
            assert_owned()
            if not security.renew_chatgpt_security_lease(email, lease):
                raise RuntimeError("registration lease changed")
            current = security.get_chatgpt_security_secrets(email)
            if str(current.get("password") or "") != password:
                raise RuntimeError("registration credential changed")

        def read_code(*, timeout, exclude_codes, received_after_ts):
            still_owned()
            code = mailbox.wait_for_code(
                mailbox_account, timeout=timeout, before_ids=before_ids,
                not_before=not_before, otp_sent_at=not_before,
                exclude_codes=exclude_codes,
            )
            still_owned()
            return code

        def before_password_submit():
            nonlocal submission_started
            still_owned()
            # Durable uncertainty precedes the remote write; a crash here can
            # never mislabel a submitted password as an unused candidate.
            security.update_chatgpt_security_state(email, password_state="pending",
                last_error="注册密码已提交，等待远端结果")
            submission_started = True
            still_owned()

        stages = set()
        def registration_log(message):
            # Legacy diagnostics may include URL/query or account data. Only
            # fixed stage labels can enter the invitation job's public logs.
            labels = {"Step2": "填写注册邮箱", "Step2.5": "选择密码注册",
                      "Step3": "设置注册密码", "Step4": "验证注册邮箱",
                      "Step5": "完成注册资料", "Step6": "保存注册会话"}
            for key, label in labels.items():
                if f"[{key}]" in str(message) and key not in stages:
                    stages.add(key)
                    emit("密码注册：" + label)

        phase = "browser_start"
        browser_started()
        page = register.create_browser(proxy=proxy, headless=headless)
        if page is None:
            return failed("注册浏览器启动失败")
        phase = "registration"
        with register.registration_log_context(registration_log):
            result = register.do_register(page=page, email=email, password=password,
                mail_config={"provider": "mailbox", "code_reader": read_code,
                             "not_before": not_before, "guard": still_owned,
                             "before_password_submit": before_password_submit})
        still_owned()
        if not isinstance(result, dict) or result.get("success") is not True:
            if isinstance(result, dict) and result.get("error_code") == "user_already_exists":
                # Preserve only the registrar's explicit, trusted remote code.
                # A generic existing-login route is not source-exhaustion proof.
                return failed("认证服务明确返回 user_already_exists", existing=True,
                              error_code="user_already_exists")
            if isinstance(result, dict) and result.get("existing_account") is True:
                return failed("该邮箱已有 GPT 账号，转入已有账号登录", existing=True)
            return failed("密码注册未完成，保留原子号与已保存密码，稍后从当前状态重试")
        phase = "session_check"
        identity = _session_identity_with_retry(page, emit)
        if not (identity.get("authenticated") is True and identity.get("status") == 200
                and identity.get("backend_status") == 200
                and str(identity.get("email") or "").strip().casefold() == email):
            return failed("注册后的目标账号会话尚未确认，保留账号等待重试")
        still_owned()
        phase = "save_credentials"
        if result.get("password_set_proven") is True and submission_started:
            # Exact signup password submission + authenticated target session
            # establishes the newly created password without a second login.
            security.update_chatgpt_security_state(email, password_state="configured", last_error="")
        security.release_chatgpt_security_lease(email, lease)
        lease = None
        assert_owned()
        logged = SimpleNamespace(ok=True, email=email, stage="done", error="",
            existing_account=False, user_id=str(result.get("user_id") or ""),
            account_id=str(result.get("account_id") or ""), plan_type="free",
            access_token="", session_token="", cookies={}, action_result=None)
        logged.unsubmitted_password_evidence = unsubmitted_evidence()
        phase = "security_continuation"
        logged.action_result = on_authenticated(page, logged)
        return logged
    except Exception as exc:
        # Never expose mailbox/network response bodies or staged credentials.
        reason = {
            "ownership": "注册任务归属检查失败，尚未提交注册",
            "mailbox_baseline": "注册前收件连接或邮件基线读取失败，尚未提交注册",
            "credential_preparation": "注册凭据准备失败，尚未提交注册",
            "browser_start": "注册浏览器启动失败，尚未提交注册",
            "registration": "密码注册页面处理未完成，已保留原账号与凭据",
            "session_check": "注册后的登录会话检查失败，已保留原账号与凭据",
            "save_credentials": "注册结果保存未完成，已保留原账号与凭据",
            "security_continuation": "注册后密码或 2FA 设置未完成，已保留原账号与凭据",
        }[phase]
        if phase == "mailbox_baseline":
            from core.gmail_mailbox import GmailMailboxReadError
            if isinstance(exc, GmailMailboxReadError):
                return failed(f"{reason}：{exc.reason}，等待自动重试")
        category = type(exc).__name__
        category = category if category in {"TimeoutError", "ConnectionError", "OSError", "RuntimeError", "ValueError"} else "步骤异常"
        return failed(f"{reason}（{category}），等待自动重试")
    finally:
        if lease:
            try:
                security.release_chatgpt_security_lease(email, lease)
            except Exception:
                pass
        if page is not None:
            try:
                page.quit()
            except Exception:
                pass
        password = ""
