"""Durable Gmail alias claims and GPT account bindings (no mailbox credentials)."""
from __future__ import annotations

from datetime import timedelta, timezone
import json
import secrets

from sqlalchemy import func, inspect, or_, update
from sqlmodel import Session, select

from core.db import AccountModel, ChatGptAccountSecurityModel, GptPlanAccountModel
from services import gmail_store as store

LEASE_SECONDS = 1800
CLAIMABLE = ("unregistered", "retry_pending", "paused")
SECURITY_RESUME_STAGES = frozenset({"security", "security_pending", "security_paused", "resume_login", "registering", "pool_sync"})


def _tables_available() -> bool:
    return {"accounts", "gpt_plan_accounts", "chatgpt_account_security"}.issubset(inspect(store.engine).get_table_names())


def _ready(source):
    return bool(source and source.enabled and source.usability_status == "usable"
                and source.receive_verified and source.app_password_ciphertext)


def _registration_allowed(session, alias, source):
    from services.gmail_production_policy import can_start
    if alias.registration_stage == "source_exhausted":
        return False
    if _tables_available():
        account, plan = _existing(session, alias)
        if _has_registered_identity(account, plan) and _security_confirmed(session, alias.email):
            return False
    # Existing children may finish security and keep receiving mail.
    if alias.registered_at is not None or alias.registered_account_id:
        return True
    if _tables_available() and _has_registered_identity(*_existing(session, alias)):
        return True
    return can_start(session, alias, source)


def block_source_for_claim(alias_id: int, token: str):
    from services.gmail_production_policy import mark_source_exhausted
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        mark_source_exhausted(session, alias)
        session.commit()


def block_source_for_plan(account_id: int, email: str, token: str):
    from core.db import GptPlanAccountOperationLeaseModel
    from services.gmail_production_policy import mark_source_exhausted
    with Session(store.engine) as session:
        # Same plan lease fences invitation preparation and manual pool workers.
        session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
        lease = session.get(GptPlanAccountOperationLeaseModel, account_id)
        plan = session.get(GptPlanAccountModel, account_id)
        alias = session.exec(select(store.GmailAlias).where(store.GmailAlias.email == email.lower())).first()
        if (not lease or lease.token != token or lease.expires_at.replace(tzinfo=timezone.utc) <= store.utcnow()
                or not plan or plan.email.lower() != email.lower() or not alias
                or alias.gpt_plan_account_id not in {None, account_id}):
            raise store.GmailStoreError("stale_registration", "Gmail 注册身份已变化，等待自动重新检查", 409)
        mark_source_exhausted(session, alias)
        session.commit()


def require_receive_ready(alias_id: int) -> dict:
    with Session(store.engine) as session:
        alias = store._alias(session, alias_id)
        source = store._source(session, alias.source_id)
        if not _ready(source):
            raise store.GmailStoreError("receive_not_ready", "Gmail 母号须启用、验证可用并配置有效的应用专用密码后才能收件或注册", 409)
        return store._alias_dto(alias)


def resolve_fixed_alias(email: str = "", source_id: int | None = None, alias_id: int | None = None) -> dict:
    with Session(store.engine) as session:
        normalized = str(email or "").strip().lower()
        row = session.get(store.GmailAlias, alias_id) if alias_id else session.exec(
            select(store.GmailAlias).where(store.GmailAlias.email == normalized)).first()
        if row is None:
            raise store.GmailStoreError("alias_not_found", "未找到该 Gmail 子号，请先在 Gmail 管理中生成并关联", 404)
        if (normalized and normalized != row.email) or (source_id and source_id != row.source_id):
            raise store.GmailStoreError("alias_mismatch", "Gmail 子号与母号关联不一致", 409)
        return store._alias_dto(row)


def _existing(session, alias):
    account = session.exec(select(AccountModel).where(AccountModel.platform == "chatgpt",
        func.lower(AccountModel.email) == alias.email).order_by(AccountModel.id.desc())).first()
    plan = session.exec(select(GptPlanAccountModel).where(func.lower(GptPlanAccountModel.email) == alias.email)).first()
    return account, plan


def _security_confirmed(session, email: str) -> bool:
    """Only durable password and Authenticator state completes recovery."""
    from services.chatgpt_security_store import _status
    if not inspect(session.connection()).has_table(ChatGptAccountSecurityModel.__tablename__):
        return False
    row = session.get(ChatGptAccountSecurityModel, email)
    if row is None or row.password_state != "configured" or row.mfa_state != "enabled":
        return False
    try:
        state = _status(row, email)
    except Exception:
        return False
    return (state.get("credentials_readable") is True and state.get("has_password") is True
            and state.get("has_totp") is True)


def _finish_security_recovery(session, alias):
    alias.registration_status = "registered"
    alias.registration_stage = "registered"
    alias.registration_error = ""
    alias.registration_retry_at = None
    alias.registration_updated_at = store.utcnow()
    session.add(alias)



def _has_registered_identity(account, plan) -> bool:
    if account is not None:
        known_states = {"registered", "trial", "subscribed", "completed", "expired", "invalid",
                        "pending_invite", "pending_activate", "pending_seat_change", "pending_rt",
                        "pending_seat_switch", "ready_for_export", "rt_unreachable"}
        if account.status in known_states or account.user_id or account.token:
            return True
    return bool(plan is not None and (plan.chatgpt_user_id or plan.chatgpt_account_id
        or plan.cookie_blob or plan.last_login_at
        or plan.codex_refresh_token or plan.plan_checked_at))

def _sync(session, alias, account=None, plan=None):
    """One transaction binds alias + plan + encrypted GPT credential, preserving paid state."""
    if alias.registration_stage in {"account_deactivated", "source_exhausted"}:
        return False
    if account is None and plan is None:
        account, plan = _existing(session, alias)
    if not _has_registered_identity(account, plan):
        return False
    now = store.utcnow()
    new_plan = plan is None
    if plan is None:
        plan = GptPlanAccountModel(email=alias.email, mail_provider="gmail", mail_access_type="imap",
                                  catalog_category="regular", source_state="regular", created_at=now, updated_at=now)
    try:
        extra = json.loads(plan.extra_json or "{}")
    except (ValueError, TypeError):
        extra = {}
    if not isinstance(extra, dict):
        extra = {}
    if account is not None:
        try:
            account_extra = account.get_extra()
        except (ValueError, TypeError):
            account_extra = {}
        if not isinstance(account_extra, dict):
            account_extra = {}
        # Only fill missing local session material. A later plan login or sale owns
        # existing tokens and every billing/lifecycle field.
        from types import SimpleNamespace
        from platforms.chatgpt.gpt_pro_login import build_cookie_blob_from_result
        cookies = account_extra.get("cookies") or {}
        if isinstance(cookies, str):
            try:
                cookies = json.loads(cookies)
            except (ValueError, TypeError):
                cookies = {}
        if isinstance(cookies, list):
            cookies = {item["name"]: item.get("value", "") for item in cookies
                       if isinstance(item, dict) and isinstance(item.get("name"), str)}
        if not isinstance(cookies, dict):
            cookies = {}
        cookies = {key: value for key, value in cookies.items()
                   if isinstance(key, str) and isinstance(value, str)}
        session_token = str(account_extra.get("session_token") or "")
        if session_token and not any("session-token" in key for key in cookies):
            cookies["__Secure-next-auth.session-token"] = session_token
        access_token = str(account_extra.get("access_token") or account.token or "")
        if not plan.cookie_blob and (cookies or access_token):
            plan.cookie_blob, plan.cookie_expires_at = build_cookie_blob_from_result(
                SimpleNamespace(cookies=cookies, access_token=access_token))
            plan.cookie_updated_at = now
            plan.last_login_at = now
        for destination, value in {
            "chatgpt_user_id": account.user_id or account_extra.get("user_id"),
            "chatgpt_account_id": account_extra.get("chatgpt_account_id") or account_extra.get("account_id"),
            "codex_refresh_token": account_extra.get("codex_refresh_token") or account_extra.get("refresh_token"),
            "codex_access_token": account_extra.get("codex_access_token") or (access_token if account_extra.get("refresh_token") else ""),
            "codex_id_token": account_extra.get("codex_id_token") or account_extra.get("id_token"),
            "codex_session_token": account_extra.get("codex_session_token"),
        }.items():
            if not getattr(plan, destination) and isinstance(value, str) and value:
                setattr(plan, destination, value)
        if plan.codex_refresh_token and plan.codex_rt_acquired_at is None:
            plan.codex_rt_acquired_at = now
        if new_plan and isinstance(account_extra.get("chatgpt_security"), dict):
            extra["chatgpt_security"] = account_extra["chatgpt_security"]
    extra.update(mail_provider="gmail", gmail_source_id=alias.source_id, gmail_alias_id=alias.id)
    plan.extra_json = json.dumps(extra, ensure_ascii=False)
    plan.mail_provider = "gmail"
    plan.mail_access_type = "imap"
    # All billing, enabled, dead, refund, plan type and parent fields remain owned by the plan pool.
    session.add(plan)
    session.flush()
    if account:
        alias.registered_account_id = account.id
        try:
            account_extra = account.get_extra()
        except (ValueError, TypeError):
            account_extra = {}
        if not isinstance(account_extra, dict):
            account_extra = {}
        # Only a new Gmail registration's positively identified GPT credential can seed security.
        trusted_password = (account_extra.get("mail_provider") == "gmail"
                            and account_extra.get("gmail_alias_id") == alias.id
                            and account_extra.get("password_set_proven") is True)
        security = session.get(ChatGptAccountSecurityModel, alias.email)
        if trusted_password and account.password and (security is None or security.password_state != "configured"):
            from core.credential_crypto import encrypt_credential
            security = security or ChatGptAccountSecurityModel(email=alias.email)
            security.password_ciphertext = encrypt_credential(alias.email, "password", account.password)
            security.password_state = "configured"
            security.password_updated_at = now
            security.updated_at = now
            security.last_error = ""
            session.add(security)
    alias.gpt_plan_account_id = plan.id
    alias.registered_at = alias.registered_at or now
    alias.registration_status = "registered"
    alias.registration_stage = "registered"
    alias.registration_error = ""
    alias.registration_retry_at = None
    alias.registration_updated_at = now
    session.add(alias)
    return True


def recover_registration_state(*, startup: bool = False) -> dict:
    """Recover local evidence; uncertain attempts always resume via login."""
    if not _tables_available():
        return {"synced": 0, "recovered": 0}
    synced = recovered = 0
    with Session(store.engine) as session:
        session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
        rows = session.exec(select(store.GmailAlias)).all()
        now = store.utcnow()
        for alias in rows:
            if alias.registration_stage == "source_exhausted":
                continue
            if alias.production_job_id:
                from services.nv_gmail_production import recover_owner
                recover_owner(session, alias)
                # NV owns recovery while active; ended production remains paused
                # until explicitly selected again, including across app restart.
                continue
            from services.nv_gmail_production import quarantine_deactivated
            if quarantine_deactivated(session, alias):
                continue
            active = bool(alias.registration_lease_token)
            expires = alias.registration_lease_expires_at
            expired = expires is None or expires.replace(tzinfo=timezone.utc) <= now
            if active and not startup and not expired:
                continue
            account, plan = _existing(session, alias)
            confirmed = _has_registered_identity(account, plan) and _security_confirmed(session, alias.email)
            if confirmed and alias.registration_stage in SECURITY_RESUME_STAGES:
                _finish_security_recovery(session, alias)
            if _has_registered_identity(account, plan):
                prior_stage = alias.registration_stage
                prior_retry = alias.registration_retry_at
                prior_error = alias.registration_error
                # Finished and bound rows need no repeated writes, and preserving
                # retry timestamps prevents every scheduler tick delaying recovery.
                bindings_match = (plan and alias.gpt_plan_account_id == plan.id
                    and (account is None or alias.registered_account_id == account.id))
                if not active and bindings_match and alias.registration_status == "registered":
                    continue
                try:
                    with session.begin_nested():
                        if _sync(session, alias, account, plan):
                            synced += 1
                            if prior_stage in SECURITY_RESUME_STAGES:
                                pending = (_security_incomplete(account, alias, session=session)
                                           if prior_stage == "pool_sync" else not confirmed)
                                if pending:
                                    alias.registration_stage = "security_paused" if prior_stage == "security_paused" else "security_pending"
                                    alias.registration_retry_at = None if prior_stage == "security_paused" else (prior_retry or now)
                                    alias.registration_error = prior_error
                except Exception:
                    alias.registration_status = "sync_pending"
                    alias.registration_error = "GPT 已注册，普通号池同步暂时失败，将自动重试"
                    if account:
                        alias.registered_account_id = account.id
                    alias.registration_retry_at = now + timedelta(seconds=60)
            elif alias.registration_status in {"reserved", "registering"}:
                untouched = alias.registration_status == "reserved" and alias.registration_stage == "selected"
                alias.registration_status = "unregistered" if untouched else "retry_pending"
                alias.registration_stage = "" if untouched else "resume_login"
                alias.registration_error = "" if untouched else "上次任务已中断，将从登录核对阶段自动恢复"
                alias.registration_retry_at = None if untouched else now
                recovered += 1
            if active:
                alias.registration_lease_token = ""
                alias.registration_lease_expires_at = None
            session.add(alias)
        session.commit()
    return {"synced": synced, "recovered": recovered}


def _selection_ids(alias_ids):
    if alias_ids is None:
        return None
    if not isinstance(alias_ids, (list, tuple)) or not 1 <= len(alias_ids) <= 1000:
        raise store.GmailStoreError("invalid_alias_ids", "请选择有效的 Gmail 子号")
    if any(type(value) is not int or value < 1 for value in alias_ids):
        raise store.GmailStoreError("invalid_alias_ids", "请选择有效的 Gmail 子号")
    return list(dict.fromkeys(alias_ids))


def validate_registration_request(source_id=None, alias_ids=None, count=1, include_retries=False) -> dict:
    """Read-only preflight; allocation still performs a transactional CAS."""
    ids = _selection_ids(alias_ids)
    if source_id is not None and (type(source_id) is not int or source_id < 1):
        raise store.GmailStoreError("invalid_source_id", "请选择有效的 Gmail 母号")
    if type(count) is not int or not 1 <= count <= 1000:
        raise store.GmailStoreError("invalid_count", "Gmail 注册数量须为 1 至 1000")
    states = CLAIMABLE if include_retries else ("unregistered",)
    with Session(store.engine) as session:
        if source_id is not None and not _ready(store._source(session, source_id)):
            raise store.GmailStoreError("receive_not_ready", "所选 Gmail 母号尚未完成收件授权或未启用", 409)
        query = select(store.GmailAlias, store.GmailSource).join(store.GmailSource,
            store.GmailAlias.source_id == store.GmailSource.id)
        if source_id is not None:
            query = query.where(store.GmailAlias.source_id == source_id)
        if ids is not None:
            query = query.where(store.GmailAlias.id.in_(ids))
        eligible_ids = []
        check_existing = _tables_available()
        for alias, source in session.exec(query).all():
            security_resume = include_retries and alias.registration_stage in {"security_pending", "security_paused"}
            if (not _ready(source) or not _registration_allowed(session, alias, source)
                    or alias.registration_lease_token or alias.production_job_id
                    or (alias.registration_status not in states and not security_resume)):
                continue
            if check_existing and not security_resume and _has_registered_identity(*_existing(session, alias)):
                continue
            eligible_ids.append(alias.id)
        if ids is not None and set(ids) != set(eligible_ids):
            raise store.GmailStoreError("invalid_registration_selection", "所选 Gmail 子号已注册、被任务占用、需选择重试，或收件授权不可用，请刷新后重选", 409)
        if count > len(eligible_ids):
            raise store.GmailStoreError("insufficient_registration_candidates", "可用 Gmail 子号不足，请减少数量或完成母号收件授权", 409)
        return {"available": len(eligible_ids), "count": count}


def list_candidates(source_id: int | None = None) -> list[dict]:
    recover_registration_state()
    with Session(store.engine) as session:
        query = select(store.GmailAlias, store.GmailSource).join(store.GmailSource,
            store.GmailAlias.source_id == store.GmailSource.id).where(
                or_(store.GmailAlias.registration_status.in_(CLAIMABLE),
                    store.GmailAlias.registration_stage.in_(("security_pending", "security_paused"))),
                store.GmailAlias.registration_lease_token == "",
                store.GmailAlias.production_job_id == "")
        if source_id:
            query = query.where(store.GmailAlias.source_id == source_id)
        result = []
        for alias, source in session.exec(query.order_by(store.GmailAlias.id)).all():
            if not _ready(source) or not _registration_allowed(session, alias, source):
                continue
            row = store._alias_dto(alias)
            row.update(can_register=True, registration_resume=alias.registration_status != "unregistered")
            result.append(row)
        return result


def _options(extra):
    if not isinstance(extra, dict):
        return {}
    allowed = {"chatgpt_registration_mode", "chatgpt_security_after_register", "executor_type", "registration_proxy_key"}
    return {key: value for key, value in (extra or {}).items()
            if key in allowed and isinstance(value, (str, bool))
            and len(str(value)) <= (512 if key == "registration_proxy_key" else 80)}


def defer_registration_for_proxy(alias_id: int, reason: str, *, delay_seconds: int = 60):
    """Expose a local pre-enqueue proxy failure without taking a mailbox lease."""
    now = store.utcnow()
    with Session(store.engine) as session:
        session.execute(update(store.GmailAlias).where(
            store.GmailAlias.id == alias_id,
            store.GmailAlias.registration_lease_token == "",
            store.GmailAlias.production_job_id == "",
            or_(store.GmailAlias.registration_status == "retry_pending",
                store.GmailAlias.registration_stage == "security_pending"),
            or_(store.GmailAlias.registration_retry_at.is_(None),
                store.GmailAlias.registration_retry_at <= now),
        ).values(registration_error=str(reason)[:300],
                 registration_retry_at=now + timedelta(seconds=max(15, delay_seconds)),
                 registration_updated_at=now))
        session.commit()


def claim_alias(*, task_id: str = "", source_id: int | None = None, alias_ids=None,
                allow_retry: bool = False, options: dict | None = None) -> dict:
    recover_registration_state()
    ids = _selection_ids(alias_ids)
    states = CLAIMABLE if allow_retry else ("unregistered",)
    eligible = store.GmailAlias.registration_status.in_(states)
    if allow_retry:
        eligible = or_(eligible, store.GmailAlias.registration_stage.in_(("security_pending", "security_paused")))
    with Session(store.engine) as session:
        # The write-first transaction serializes SQLite workers; conditional updates fence all DBs.
        session.execute(update(store.GmailAlias).where(store.GmailAlias.id == -1).values(registration_stage=""))
        query = select(store.GmailAlias, store.GmailSource).join(store.GmailSource,
            store.GmailAlias.source_id == store.GmailSource.id).where(
                eligible, store.GmailAlias.registration_lease_token == "",
                store.GmailAlias.production_job_id == "")
        if source_id:
            query = query.where(store.GmailAlias.source_id == int(source_id))
        if ids is not None:
            query = query.where(store.GmailAlias.id.in_(ids))
        for alias, source in session.exec(query.order_by(store.GmailAlias.id)).all():
            if not _ready(source) or not _registration_allowed(session, alias, source):
                continue
            if _tables_available():
                account, plan = _existing(session, alias)
                if _has_registered_identity(account, plan) and alias.registration_stage not in {"security_pending", "security_paused"}:
                    _sync(session, alias, account, plan)
                    continue
            token = secrets.token_urlsafe(24)
            now = store.utcnow()
            resume = alias.registration_status != "unregistered"
            result = session.execute(update(store.GmailAlias).where(store.GmailAlias.id == alias.id,
                eligible, store.GmailAlias.registration_lease_token == "",
                store.GmailAlias.production_job_id == "").values(
                    registration_status="reserved", registration_stage="security" if alias.registered_account_id else ("resume_login" if resume else "selected"),
                    registration_task_id=str(task_id or "")[:128], registration_lease_token=token,
                    registration_lease_expires_at=now + timedelta(seconds=LEASE_SECONDS), registration_error="",
                    registration_retry_at=None, registration_updated_at=now,
                    registration_attempts=store.GmailAlias.registration_attempts + 1,
                    registration_options_json=json.dumps(_options(options), ensure_ascii=False)))
            if result.rowcount != 1:
                continue
            session.commit()
            session.refresh(alias)
            row = store._alias_dto(alias)
            row.update(lease_token=token, registration_resume=resume)
            return row
        session.commit()
    raise store.GmailStoreError("no_registration_candidate", "没有可注册的 Gmail 子号：请检查母号收件授权、已注册状态或任务占用", 409)


def _owned(session, alias_id, token):
    # Updating first serializes lifecycle writes and fences stale callbacks after restart.
    result = session.execute(update(store.GmailAlias).where(store.GmailAlias.id == alias_id,
        store.GmailAlias.registration_lease_token == token, store.GmailAlias.registration_lease_token != "",
        store.GmailAlias.production_job_id == "",
        store.GmailAlias.registration_stage != "account_deactivated",
        store.GmailAlias.registration_lease_expires_at > store.utcnow()).values(
            registration_updated_at=store.utcnow(), registration_lease_expires_at=store.utcnow() + timedelta(seconds=LEASE_SECONDS)))
    if result.rowcount != 1:
        raise store.GmailStoreError("stale_registration", "Gmail 注册任务已变化，本次旧任务结果未覆盖当前状态", 409)
    return store._alias(session, alias_id)


def mark_started(alias_id: int, token: str, *, stage: str = "registering", password: str = ""):
    stage = stage if stage in {"registering", "resume_login", "verification", "security", "oauth"} else "registering"
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        alias.registration_status = "registering"
        alias.registration_stage = ("security" if alias.registered_account_id else
            "resume_login" if stage == "registering" and alias.registration_stage == "resume_login" else stage)
        if password:
            security = session.get(ChatGptAccountSecurityModel, alias.email)
            if security is None or not security.password_ciphertext:
                from core.credential_crypto import encrypt_credential
                security = security or ChatGptAccountSecurityModel(email=alias.email)
                security.password_ciphertext = encrypt_credential(alias.email, "password", password)
                security.password_state = "pending"
                security.password_updated_at = store.utcnow()
                session.add(security)
        session.add(alias)
        session.commit()


def heartbeat(alias_id: int, token: str):
    with Session(store.engine) as session:
        _owned(session, alias_id, token)
        session.commit()


def require_registration_work(alias_id: int, token: str):
    """Stop a stale recovery immediately before it reads the mailbox."""
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        if (_tables_available() and _has_registered_identity(*_existing(session, alias))
                and _security_confirmed(session, alias.email)):
            raise store.GmailStoreError("registration_already_complete", "账号注册及密码、2FA 已完成，无需重复恢复", 409)
        session.commit()


def persist_registration_account(alias_id: int, token: str, account):
    """Save only while owning the alias; stale workers cannot overwrite credentials."""
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        if str(getattr(account, "email", "")).strip().lower() != alias.email or account.platform != "chatgpt":
            raise store.GmailStoreError("account_mismatch", "注册结果与当前 Gmail 子号不一致", 409)
        extra = dict(account.extra or {})
        extra.update(mail_provider="gmail", gmail_source_id=alias.source_id, gmail_alias_id=alias.id)
        row, _ = _existing(session, alias)
        row = row or AccountModel(platform="chatgpt", email=alias.email, password="")
        row.password = account.password or ""
        row.user_id = account.user_id or ""
        row.region = account.region or ""
        row.token = account.token or ""
        row.status = getattr(account.status, "value", account.status)
        row.extra_json = json.dumps(extra, ensure_ascii=False)
        row.cashier_url = str(extra.get("cashier_url") or "")
        row.updated_at = store.utcnow()
        session.add(row)
        session.flush()
        # Account evidence and ownership reference commit together.
        alias.registered_account_id = row.id
        alias.registered_at = alias.registered_at or store.utcnow()
        alias.registration_status = "sync_pending"
        alias.registration_stage = "pool_sync"
        session.add(alias)
        session.commit()
        session.refresh(row)
        return row


def _security_incomplete(account, alias, *, session=None) -> bool:
    if session is not None and _security_confirmed(session, alias.email):
        return False
    try:
        extra = account.get_extra() if account is not None else {}
    except (ValueError, TypeError):
        extra = {}
    security = extra.get("chatgpt_security") if isinstance(extra, dict) else None
    try:
        options = _options(json.loads(alias.registration_options_json or "{}"))
    except (ValueError, TypeError):
        options = {}
    enabled = options.get("chatgpt_security_after_register", True)
    if enabled is False or (isinstance(enabled, str) and enabled.lower() in {"false", "0", "off", "no"}):
        return False
    if not isinstance(security, dict):
        return True
    if security.get("mfa_state") == "not_attempted_existing_account":
        return False
    return security.get("ok") is not True


def complete_registration(alias_id: int, token: str, account, *, final: bool = True):
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        if str(getattr(account, "email", "") or "").strip().lower() != alias.email:
            raise store.GmailStoreError("account_mismatch", "注册结果与当前 Gmail 子号不一致", 409)
        saved = session.get(AccountModel, getattr(account, "id", None)) if getattr(account, "id", None) else None
        if saved is None or saved.platform != "chatgpt" or saved.email.lower() != alias.email:
            raise store.GmailStoreError("account_not_saved", "GPT 注册结果尚未持久化，将自动重试入库", 409)
        alias.registered_account_id = saved.id
        alias.registered_at = alias.registered_at or store.utcnow()
        alias.registration_status = "sync_pending"
        alias.registration_stage = "pool_sync"
        session.add(alias)
        session.commit()
    # A durable account reference is recorded before sync, so failure only retries local persistence.
    with Session(store.engine) as session:
        alias = _owned(session, alias_id, token)
        saved = session.get(AccountModel, alias.registered_account_id)
        _, plan = _existing(session, alias)
        _sync(session, alias, saved, plan)
        if final:
            if _security_incomplete(saved, alias, session=session):
                alias.registration_stage = "security_pending"
                alias.registration_retry_at = store.utcnow() + timedelta(seconds=60)
                alias.registration_error = "已注册，后续密码或 2FA 设置未完成，将自动重试"
            alias.registration_lease_token = ""
            alias.registration_lease_expires_at = None
        else:
            alias.registration_stage = "security"
        session.add(alias)
        session.commit()
        return store._alias_dto(alias)



def _failure_reason(error, stage: str) -> str:
    """Classify fixed reasons only; arbitrary exceptions can contain credentials."""
    code = str(getattr(error, "code", "") or "").lower()
    text = str(error or "").lower()
    if code in {"receive_not_ready", "auth_required", "authentication_failed"} or any(
            value in text for value in ("应用专用密码", "收件授权", "gmail 授权", "imap authentication")):
        return "Gmail 收件授权不可用，等待有效授权后继续"
    if any(value in text for value in ("等待新的 gpt 验证码超时", "验证码超时", "otp timeout", "等待验证码超时")):
        return "等待 GPT 邮件验证码超时"
    if any(value in text for value in ("密码邮件超时", "password link timeout")):
        return "等待 GPT 密码设置邮件超时"
    if code in {"account_not_saved", "crypto_error"} or any(
            value in text for value in ("写回", "持久化", "入库", "database", "sqlite", "credentialkeyerror")):
        return "本地账号或凭证保存暂时失败"
    if any(value in text for value in ("timeout", "timed out", "超时", "connection", "network", "连接失败", "网络")):
        return "网络连接或页面响应超时"
    if any(value in text for value in ("2fa", "totp", "authenticator", "安全设置")):
        return "密码或 Authenticator 设置尚未完成"
    phase = {"verification": "验证码验证", "resume_login": "登录核对", "security": "密码与 2FA 设置",
             "pool_sync": "普通号池同步", "oauth": "OAuth 授权"}.get(stage, "GPT 注册")
    return phase + "未完成"


def release_alias(alias_id: int, token: str, *, cancelled: bool = False, error: str = ""):
    with Session(store.engine) as session:
        try:
            alias = _owned(session, alias_id, token)
        except store.GmailStoreError as exc:
            if exc.code == "stale_registration":
                return
            raise
        reason = _failure_reason(error, alias.registration_stage)
        # An NV candidate may have an email-only plan shell before any GPT
        # signup succeeds. A local foreign key alone is not registration proof.
        if _has_registered_identity(*_existing(session, alias)):
            if _security_confirmed(session, alias.email):
                _finish_security_recovery(session, alias)
            else:
                if alias.registration_status != "sync_pending":
                    alias.registration_status = "registered"
                alias.registration_stage = "security_paused" if cancelled else "security_pending"
                alias.registration_error = "已注册，后续设置已暂停" if cancelled else reason + "；已注册，后续设置将自动重试"
                alias.registration_retry_at = None if cancelled else store.utcnow() + timedelta(seconds=60)
        elif cancelled:
            alias.registration_retry_at = None
            alias.registration_status = "paused"
            alias.registration_error = "任务已取消；再次选择该子号时将先核对登录状态"
        elif alias.registration_status == "reserved" and alias.registration_stage == "selected":
            alias.registration_retry_at = None
            alias.registration_status = "unregistered"
            alias.registration_error = ""
        else:
            alias.registration_status = "retry_pending"
            alias.registration_error = reason + "；将从登录核对阶段自动重试"
            alias.registration_retry_at = store.utcnow() + timedelta(seconds=min(900, 30 * 2 ** min(alias.registration_attempts, 5)))
        alias.registration_lease_token = ""
        alias.registration_lease_expires_at = None
        session.add(alias)
        session.commit()


def list_due_registration_retries(limit: int = 20) -> list[dict]:
    recover_registration_state()
    with Session(store.engine) as session:
        rows = session.exec(select(store.GmailAlias, store.GmailSource).join(store.GmailSource,
            store.GmailAlias.source_id == store.GmailSource.id).where(
                or_(store.GmailAlias.registration_status == "retry_pending", store.GmailAlias.registration_stage == "security_pending"),
                store.GmailAlias.registration_lease_token == "",
                store.GmailAlias.production_job_id == "",
                store.GmailSource.enabled.is_(True), store.GmailSource.usability_status == "usable",
                store.GmailSource.receive_verified.is_(True), store.GmailSource.app_password_ciphertext != "",
                or_(store.GmailAlias.registration_retry_at.is_(None), store.GmailAlias.registration_retry_at <= store.utcnow()))
                .order_by(store.GmailAlias.id)).all()
        result = []
        limit = max(1, min(int(limit), 100))
        for alias, source in rows:
            if _ready(source) and _registration_allowed(session, alias, source):
                try:
                    options = _options(json.loads(alias.registration_options_json or "{}"))
                except (ValueError, TypeError):
                    options = {}
                result.append({"alias_id": alias.id, "source_id": alias.source_id, "email": alias.email,
                    "task_id": alias.registration_task_id, "stage": alias.registration_stage, "options": options})
                if len(result) >= limit:
                    break
        return result
