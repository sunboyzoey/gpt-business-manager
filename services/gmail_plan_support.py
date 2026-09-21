"""Credential-free Gmail bindings used by GPT plan DTOs and mailbox routing."""
from __future__ import annotations

import json


def account_extra(account) -> dict:
    if isinstance(account, dict):
        nested = account.get("extra")
        if not isinstance(nested, dict):
            try:
                nested = json.loads(account.get("extra_json") or "{}")
            except (TypeError, ValueError):
                nested = {}
        return {**(nested if isinstance(nested, dict) else {}), **account}
    raw = getattr(account, "extra_json", "")
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def account_mail_provider(account) -> str:
    extra = account_extra(account)
    column = str(account.get("mail_provider", "") if isinstance(account, dict)
                 else getattr(account, "mail_provider", "") or "").strip().lower()
    if isinstance(account, dict) and ("extra" in account or "extra_json" in account):
        nested = account.get("extra")
        if not isinstance(nested, dict):
            try:
                nested = json.loads(account.get("extra_json") or "{}")
            except (TypeError, ValueError):
                nested = {}
        extra = nested if isinstance(nested, dict) else {}
    legacy = str(extra.get("mail_provider") or extra.get("provider") or "").strip().lower()
    # Old rows may retain the schema's Outlook default while the typed marker
    # survives in extra_json. Never infer a mailbox provider from a password.
    if column in {"", "outlook"} and legacy in {"gmail", "icloud", "qqmail"}:
        column = legacy
    return "icloud" if column in {"icloud", "qqmail"} else "gmail" if column == "gmail" else "outlook"


def mail_provider_expression(model):
    """SQLite filter matching the typed/legacy classification used by DTOs."""
    from sqlalchemy import case, func
    column = func.lower(func.trim(func.coalesce(model.mail_provider, "")))
    valid_extra = case((func.json_valid(model.extra_json), model.extra_json), else_="{}")
    legacy = func.lower(func.trim(func.coalesce(
        func.nullif(func.json_extract(valid_extra, "$.mail_provider"), ""),
        func.json_extract(valid_extra, "$.provider"), "")))
    effective = case((column.in_(("", "outlook")) & legacy.in_(("gmail", "icloud", "qqmail")), legacy), else_=column)
    return case((effective.in_(("icloud", "qqmail")), "icloud"),
                (effective == "gmail", "gmail"), else_="outlook")


def gmail_binding_extra(account) -> dict:
    extra = account_extra(account)
    refs = {}
    for name in ("gmail_source_id", "gmail_alias_id"):
        value = extra.get(name)
        if type(value) is int and value > 0:
            refs[name] = value
        elif isinstance(value, str) and value.isdecimal() and int(value) > 0:
            refs[name] = int(value)
    return refs


def gmail_receive_metadata(account) -> dict:
    """Local checks only; no Gmail password, TOTP or network calls enter DTOs."""
    refs = gmail_binding_extra(account)
    result = {"gmail_source_id": refs.get("gmail_source_id"),
              "gmail_alias_id": refs.get("gmail_alias_id"), "gmail_receive_ready": False}
    if account_mail_provider(account) != "gmail":
        return result
    email = str(account.get("email", "") if isinstance(account, dict)
                else getattr(account, "email", "") or "").strip()
    try:
        from services.gmail_registration import resolve_fixed_alias, require_receive_ready
        alias = resolve_fixed_alias(email, source_id=refs.get("gmail_source_id"), alias_id=refs.get("gmail_alias_id"))
        alias_id = int(alias.get("id") or alias.get("gmail_alias_id") or 0)
        if alias_id <= 0:
            return result
        require_receive_ready(alias_id)
        result.update(gmail_source_id=alias.get("source_id") or alias.get("gmail_source_id"),
                      gmail_alias_id=alias_id, gmail_receive_ready=True)
    except Exception:
        pass
    return result


def gmail_receive_ready(account) -> bool:
    return gmail_receive_metadata(account)["gmail_receive_ready"]


def gmail_registration_ready(account) -> bool:
    """Admit new Gmail invitation stock only with durable GPT identity evidence.

    Mailbox authorization alone is sufficient for ordinary login/reading, but
    an email-only plan import or a historical alias status is not registration
    proof. Re-read authoritative records instead of trusting a caller's DTO.
    Existing bound-account recovery deliberately continues using receive_ready.
    """
    if account_mail_provider(account) != "gmail":
        return False
    metadata = gmail_receive_metadata(account)
    if metadata.get("gmail_receive_ready") is not True:
        return False
    email = str(account.get("email", "") if isinstance(account, dict)
                else getattr(account, "email", "") or "").strip().lower()
    provided_id = account.get("id") if isinstance(account, dict) else getattr(account, "id", None)
    try:
        from sqlmodel import Session
        from core.db import AccountModel
        from services import gmail_registration as registration, gmail_store as store
        with Session(store.engine) as session:
            alias = session.get(store.GmailAlias, metadata["gmail_alias_id"])
            if (alias is None or alias.email != email
                    or alias.source_id != metadata["gmail_source_id"]
                    or alias.registration_stage in {"account_deactivated", "source_exhausted"}):
                return False
            if alias.registration_lease_token:
                from datetime import timezone
                expires = alias.registration_lease_expires_at
                if expires is None or expires.replace(tzinfo=timezone.utc) > store.utcnow():
                    return False
            if alias.production_job_id:
                from services.nv_gmail_production import owner_active
                if owner_active(session, alias):
                    return False
            registered, plan = registration._existing(session, alias)
            # The candidate must be the same durable ordinary-pool identity.
            if plan is None or (provided_id is not None and (type(provided_id) is not int or provided_id != plan.id)):
                return False
            if alias.gpt_plan_account_id is not None and alias.gpt_plan_account_id != plan.id:
                return False
            if alias.registered_account_id is not None:
                registered = session.get(AccountModel, alias.registered_account_id)
                if (registered is None or registered.platform != "chatgpt"
                        or str(registered.email or "").strip().lower() != email):
                    return False
            return registration._has_registered_identity(registered, plan)
    except Exception:
        # Missing migration tables, invalid linkage and local read failures
        # cannot turn unverified stock into an invitation candidate.
        return False
