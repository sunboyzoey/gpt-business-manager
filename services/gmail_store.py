"""Local Gmail sources and immutable plus aliases, isolated from account pools."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import threading
from contextlib import contextmanager, nullcontext
from typing import Optional
from urllib.parse import urlsplit

from sqlalchemy import UniqueConstraint, func, inspect, text, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Field, Session, SQLModel, select

from core.db import engine

MAX_ALIASES_PER_SOURCE = 3


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GmailSource(SQLModel, table=True):
    __tablename__ = "gmail_sources"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(max_length=254, index=True, sa_column_kwargs={"unique": True})
    app_password_ciphertext: str = ""
    login_password_ciphertext: str = ""
    recovery_email: str = Field(default="", max_length=254)
    totp_secret_ciphertext: str = ""
    verification_url_ciphertext: str = ""
    proxy_url: str = ""
    enabled: bool = True
    status: str = "unchecked"
    usability_status: str = "unverified"
    usability_method: str = ""
    usability_checked_at: Optional[datetime] = None
    usability_error: str = ""
    receive_verified: bool = False
    production_blocked: bool = False
    production_block_reason: str = ""
    production_blocked_at: Optional[datetime] = None
    last_error: str = ""
    last_checked_at: Optional[datetime] = None
    next_alias_sequence: int = 1
    generated_alias_count: int = 0
    credential_revision: int = 1
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class GmailAlias(SQLModel, table=True):
    __tablename__ = "gmail_aliases"
    __table_args__ = (UniqueConstraint("source_id", "tag"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    source_id: int = Field(foreign_key="gmail_sources.id", index=True)
    tag: str = Field(max_length=64)
    email: str = Field(max_length=254, index=True, sa_column_kwargs={"unique": True})
    last_test_at: Optional[datetime] = None
    last_test_status: str = "untested"
    last_error: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    registration_status: str = "unregistered"
    registration_stage: str = ""
    registration_task_id: str = ""
    registration_lease_token: str = ""
    registration_lease_expires_at: Optional[datetime] = None
    registration_error: str = ""
    registration_attempts: int = 0
    registration_retry_at: Optional[datetime] = None
    registration_options_json: str = "{}"
    # Durable NV production ownership is independent of a registration worker lease.
    production_job_id: str = ""
    registered_account_id: Optional[int] = None
    gpt_plan_account_id: Optional[int] = None
    registered_at: Optional[datetime] = None
    registration_updated_at: Optional[datetime] = None


class GmailStoreError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def init_tables(engine_override=None) -> None:
    """Create Gmail tables and add login-material columns without rewriting data."""
    target = engine_override if engine_override is not None else engine
    SQLModel.metadata.create_all(
        target,
        tables=[GmailSource.__table__, GmailAlias.__table__],
    )
    with target.begin() as connection:
        existing = {column["name"] for column in inspect(connection).get_columns("gmail_sources")}
        # These identifiers and types are fixed, never derived from an import.
        for column, sql_type in (
            ("login_password_ciphertext", "TEXT"), ("recovery_email", "VARCHAR(254)"),
            ("totp_secret_ciphertext", "TEXT"), ("verification_url_ciphertext", "TEXT"),
            ("usability_method", "TEXT"), ("usability_error", "TEXT"),
        ):
            if column not in existing:
                connection.execute(text(
                    f"ALTER TABLE gmail_sources ADD COLUMN {column} {sql_type} NOT NULL DEFAULT ''"
                ))

        for column, declaration in (
            ("usability_status", "VARCHAR NOT NULL DEFAULT 'unverified'"),
            ("usability_checked_at", "DATETIME"),
            ("receive_verified", "BOOLEAN NOT NULL DEFAULT 0"),
            ("production_blocked", "BOOLEAN NOT NULL DEFAULT 0"),
            ("production_block_reason", "VARCHAR NOT NULL DEFAULT ''"),
            ("production_blocked_at", "DATETIME"),
        ):
            if column not in existing:
                connection.execute(text(f"ALTER TABLE gmail_sources ADD COLUMN {column} {declaration}"))
        # 历史版本可能把已耗尽的 Gmail 母号仍保持为启用状态。启动时统一
        # 修正，避免注册选择器再次选中已经返回 user_already_exists 的母号。
        connection.execute(text(
            "UPDATE gmail_sources SET enabled = 0 "
            "WHERE production_blocked = 1 AND enabled != 0"
        ))
        alias_columns = {column["name"] for column in inspect(connection).get_columns("gmail_aliases")}
        for column, declaration in (
            ("registration_status", "VARCHAR NOT NULL DEFAULT 'unregistered'"),
            ("registration_stage", "VARCHAR NOT NULL DEFAULT ''"),
            ("registration_task_id", "VARCHAR NOT NULL DEFAULT ''"),
            ("registration_lease_token", "VARCHAR NOT NULL DEFAULT ''"),
            ("registration_lease_expires_at", "DATETIME"),
            ("registration_error", "VARCHAR NOT NULL DEFAULT ''"),
            ("registration_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("registration_retry_at", "DATETIME"),
            ("registration_options_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("production_job_id", "VARCHAR NOT NULL DEFAULT ''"),
            ("registered_account_id", "INTEGER"),
            ("gpt_plan_account_id", "INTEGER"),
            ("registered_at", "DATETIME"),
            ("registration_updated_at", "DATETIME"),
        ):
            if column not in alias_columns:
                connection.execute(text(f"ALTER TABLE gmail_aliases ADD COLUMN {column} {declaration}"))
        if "generated_alias_count" not in existing:
            connection.execute(text(
                "ALTER TABLE gmail_sources ADD COLUMN generated_alias_count INTEGER NOT NULL DEFAULT 0"
            ))
            # Preserve lifetime usage even when a historical alias was removed.
            connection.execute(text("""UPDATE gmail_sources SET generated_alias_count =
                CASE WHEN next_alias_sequence - 1 >
                    (SELECT COUNT(*) FROM gmail_aliases WHERE source_id = gmail_sources.id)
                THEN next_alias_sequence - 1 ELSE
                    (SELECT COUNT(*) FROM gmail_aliases WHERE source_id = gmail_sources.id) END
            """))


# A bounded set of striped locks avoids retaining every imported address forever.
_verification_locks = [threading.RLock() for _ in range(64)]


@contextmanager
def verification_guard(email: str):
    lock = _verification_locks[hash(email) % len(_verification_locks)]
    if not lock.acquire(blocking=False):
        raise GmailStoreError("source_busy", "此 Gmail 母号正在验证，请等待本次验证完成", 409)
    try:
        yield
    finally:
        lock.release()


def normalize_source_email(value: str) -> str:
    if not isinstance(value, str):
        raise GmailStoreError("invalid_email", "请输入不含 + 别名的 Gmail 源邮箱")
    email = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9]+)*@gmail\.com", email):
        raise GmailStoreError("invalid_email", "请输入不含 + 别名的 @gmail.com 源邮箱")
    local = email.split("@", 1)[0].replace(".", "")
    if not 1 <= len(local) <= 64:
        raise GmailStoreError("invalid_email", "Gmail 源邮箱地址长度无效")
    return f"{local}@gmail.com"


def normalize_app_password(value: str) -> str:
    password = re.sub(r"\s+", "", value) if isinstance(value, str) else ""
    if not re.fullmatch(r"[a-zA-Z]{16}", password):
        raise GmailStoreError("invalid_password", "请输入 Google 生成的 16 位应用专用密码（可含分组空格）")
    return password


def normalize_proxy_url(value: str) -> str:
    message = "代理须为 http://host:port 或 socks5[h]://host:port，不得包含用户名、密码或路径"
    if not isinstance(value, str):
        raise GmailStoreError("invalid_proxy", message)
    value = value.strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "socks5", "socks5h"} or not parsed.hostname
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or re.search(r"\s", value) or len(value) > 2048):
            raise ValueError
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme}://{host}:{parsed.port}"
    except ValueError:
        raise GmailStoreError("invalid_proxy", message) from None


def _encrypt(email: str, password: str) -> str:
    from core.gmail_crypto import encrypt_gmail_password
    try:
        return encrypt_gmail_password(email, password)
    except Exception:
        raise GmailStoreError("crypto_error", "应用密码加密不可用，请检查服务器凭证密钥配置", 503) from None


def _source_dto(source: GmailSource, alias_count: int = 0) -> dict:
    has_app_password = bool(source.app_password_ciphertext)
    has_login_password = bool(source.login_password_ciphertext)
    generated_count = max(source.generated_alias_count, alias_count)
    remaining = max(0, MAX_ALIASES_PER_SOURCE - generated_count)
    return {
        "id": source.id, "email": source.email, "enabled": source.enabled,
        "proxy_url": source.proxy_url,
        "has_password": has_app_password, "has_app_password": has_app_password,
        "has_login_password": has_login_password,
        "has_totp_secret": bool(source.totp_secret_ciphertext),
        "has_verification_url": bool(source.verification_url_ciphertext),
        "recovery_email": source.recovery_email,
        "receive_ready": source.enabled and has_app_password and source.receive_verified,
        "usability_status": source.usability_status,
        "usability_method": source.usability_method,
        "usability_checked_at": source.usability_checked_at,
        "usability_error": source.usability_error,
        "can_generate_aliases": source.enabled and source.usability_status == "usable" and not source.production_blocked and remaining > 0,
        "production_blocked": source.production_blocked,
        "production_block_reason": source.production_block_reason,
        "production_blocked_at": source.production_blocked_at,
        "credential_format": "five_field" if has_login_password else "app_password",
        "status": source.status,
        "last_error": source.last_error, "last_checked_at": source.last_checked_at,
        "alias_count": alias_count, "generated_alias_count": generated_count,
        "alias_limit": MAX_ALIASES_PER_SOURCE, "remaining_alias_count": remaining,
        "created_at": source.created_at,
    }


def _alias_dto(alias: GmailAlias, plan=None) -> dict:
    declared = alias.registration_stage == "imported_registered_unverified"
    verified = bool(plan and (plan.chatgpt_user_id or plan.chatgpt_account_id or plan.cookie_blob
                    or (plan.last_login_at and not plan.last_login_error) or plan.codex_refresh_token or plan.plan_checked_at))
    return {
        "registration_verification": "verified" if verified else "declared" if declared else
            "verified" if alias.registered_at else "unregistered",
        "source_production_blocked": False, "source_production_block_reason": "",
        "id": alias.id, "source_id": alias.source_id, "email": alias.email,
        "created_at": alias.created_at, "last_test_at": alias.last_test_at,
        "last_test_status": alias.last_test_status, "last_error": alias.last_error,
        "registration_status": alias.registration_status,
        "registration_stage": alias.registration_stage,
        "registration_task_id": alias.registration_task_id,
        "production_job_id": alias.production_job_id,
        "alias_limit_exceeded": False,
        "registration_error": alias.registration_error,
        "registration_lease_expires_at": alias.registration_lease_expires_at,
        "registration_retry_at": alias.registration_retry_at,
        "registration_attempts": alias.registration_attempts,
        "registration_updated_at": alias.registration_updated_at,
        "registration_busy": bool(alias.registration_lease_token or alias.production_job_id),
        "registered_account_id": alias.registered_account_id,
        "gpt_plan_account_id": alias.gpt_plan_account_id,
        **_plan_link_dto(plan),
        "registered_at": alias.registered_at,
    }



def _plan_link_dto(plan) -> dict:
    """Keep navigation accurate after a registered account is upgraded/refunded."""
    if plan is None:
        return {"gpt_plan_account_type": None, "gpt_plan_member_plan": None}
    plan_type = str(plan.plan_type or "").strip().lower()
    category = ("refunded" if plan.catalog_category == "refunded" else
                "regular" if plan_type in {"", "free", "chatgptfreeplan"} else "member")
    aliases = {
        "go": {"go", "chatgptgo", "chatgptgoplan", "chatgpt_go", "self_serve_go"},
        "plus": {"plus", "chatgptplusplan", "self_serve_plus"},
        "pro": {"pro", "chatgptproplan", "self_serve_pro", "pro_20x", "pro_5x"},
        "team": {"team", "business", "chatgptteamplan", "chatgptbusinessplan", "self_serve_business", "self_serve_business_prolite", "business_master"},
    }
    member = next((key for key, values in aliases.items() if plan_type in values), "") if category == "member" else ""
    return {"gpt_plan_account_type": category, "gpt_plan_member_plan": member}


def _source(session: Session, source_id: int) -> GmailSource:
    source = session.get(GmailSource, source_id)
    if source is None:
        raise GmailStoreError("not_found", "Gmail 源邮箱不存在", 404)
    return source


def _alias(session: Session, alias_id: int) -> GmailAlias:
    alias = session.get(GmailAlias, alias_id)
    if alias is None:
        raise GmailStoreError("not_found", "Gmail 别名不存在", 404)
    return alias


def _alias_count(session: Session, source_id: int) -> int:
    return session.exec(select(func.count(GmailAlias.id)).where(GmailAlias.source_id == source_id)).one()


def list_sources() -> list[dict]:
    with Session(engine) as session:
        rows = session.exec(
            select(GmailSource, func.count(GmailAlias.id))
            .outerjoin(GmailAlias, GmailAlias.source_id == GmailSource.id)
            .group_by(GmailSource.id).order_by(GmailSource.id.desc())
        ).all()
        counts = session.exec(select(GmailAlias.source_id, GmailAlias.registration_status,
            func.count(GmailAlias.id)).group_by(GmailAlias.source_id, GmailAlias.registration_status)).all()
        grouped = {}
        for source_id, state, count in counts:
            grouped.setdefault(source_id, {})[state] = count
        registered_counts = dict(session.exec(select(GmailAlias.source_id, func.count(GmailAlias.id)).where(
            GmailAlias.registered_at.is_not(None)).group_by(GmailAlias.source_id)).all())
        security_counts = dict(session.exec(select(GmailAlias.source_id, func.count(GmailAlias.id)).where(
            GmailAlias.registration_status == "registered",
            GmailAlias.registration_stage.in_(("security_pending", "security_paused"))).group_by(GmailAlias.source_id)).all())
        result = []
        for source, count in rows:
            item = _source_dto(source, count)
            states = grouped.get(source.id, {})
            item.update(registration_counts=states, unregistered_count=states.get("unregistered", 0),
                        registered_count=registered_counts.get(source.id, 0),
                        registration_pending_count=sum(states.get(key, 0) for key in ("reserved", "registering", "retry_pending", "paused")) + security_counts.get(source.id, 0))
            result.append(item)
        return result


def _check_app_password(email: str, password: str, proxy_url: str) -> None:
    """Check only fixed Gmail IMAP endpoints, before opening a write transaction."""
    from services.gmail_transport import GmailTransport, GmailTransportError
    messages = {
        "authentication_failed": "Gmail 应用专用密码验证失败，未保存本次资料",
        "auth_required": "Gmail 应用专用密码验证失败，未保存本次资料",
        "timeout": "连接 Gmail 超时，未保存本次资料，请检查网络或代理后重试",
        "invalid_proxy": "Gmail 代理配置不可用，未保存本次资料",
        "tls_error": "Gmail 安全连接失败，未保存本次资料",
    }
    transport = None
    try:
        transport = GmailTransport(email, password, proxy_url=proxy_url)
        transport.connect_test()
    except GmailTransportError as exc:
        raise GmailStoreError("verification_failed", messages.get(exc.code, "Gmail 收件验证失败，未保存本次资料，请检查网络后重试"), 400) from None
    except Exception:
        raise GmailStoreError("verification_failed", "Gmail 收件验证未完成，未保存本次资料，请稍后重试", 503) from None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def create_source(email: str, app_password: str, proxy_url: str = "") -> dict:
    email = normalize_source_email(email)
    password = normalize_app_password(app_password)
    proxy_url = normalize_proxy_url(proxy_url)
    with verification_guard(email):
        if source_identity(email) is not None:
            raise GmailStoreError("duplicate_source", "此 Gmail 源邮箱已存在（大小写和点号视为同一邮箱）", 409)
        _check_app_password(email, password, proxy_url)
        ciphertext = _encrypt(email, password)
        now = utcnow()
        with Session(engine) as session:
            source = GmailSource(email=email, app_password_ciphertext=ciphertext, proxy_url=proxy_url,
                                 status="ok", usability_status="usable", usability_method="imap",
                                 usability_checked_at=now, last_checked_at=now, receive_verified=True)
            session.add(source)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                raise GmailStoreError("duplicate_source", "验证期间此 Gmail 源邮箱已被添加，请重新读取最新列表", 409) from None
            session.refresh(source)
            return _source_dto(source)


@dataclass(frozen=True)
class _ImportedCredentials:
    email: str
    login_password: str = field(repr=False)
    recovery_email: str
    totp_secret: str = field(repr=False)
    verification_url: str = field(repr=False)
    auto_authorize: bool = False


def _parse_import_line(line: str) -> _ImportedCredentials:
    # A line uses a consistent delimiter; passwords remain otherwise unmodified.
    separator = "----" if "----" in line else "---"
    parts = line.split(separator)
    if len(parts) not in {3, 4, 5}:
        raise GmailStoreError("invalid_format", "每行须为 --- 或 ---- 分隔的三至五段资料")
    auto_authorize = len(parts) == 3
    if auto_authorize:
        # 供应商常用格式：Gmail / 登录密码 / TOTP。该格式在同一次浏览器
        # 会话中完成登录、应用专用密码创建和收件验证。
        parts = [parts[0], parts[1], "", parts[2], ""]
    if len(parts) == 4:
        parts.append("")
    email, password, recovery, totp, url = (part.strip() for part in parts)
    email = normalize_source_email(email)
    if not password or len(password) > 1024 or re.search(r"[\x00-\x1f\x7f]", password):
        raise GmailStoreError("invalid_login_password", "登录密码不能为空、包含控制字符或超过 1024 位")
    recovery = recovery.lower()
    if recovery and (len(recovery) > 254 or not re.fullmatch(
            r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", recovery)):
        raise GmailStoreError("invalid_recovery_email", "辅助邮箱格式无效")
    totp = re.sub(r"\s+", "", totp).upper()
    if not re.fullmatch(r"[A-Z2-7]{2,256}={0,6}", totp):
        raise GmailStoreError("invalid_totp_secret", "2FA 密钥须为有效的 Base32 字符串")
    unpadded_totp = totp.rstrip("=")
    padded_totp = unpadded_totp + "=" * (-len(unpadded_totp) % 8)
    try:
        decoded = base64.b32decode(padded_totp)
        if (("=" in totp and totp != padded_totp)
                or base64.b32encode(decoded).decode("ascii").rstrip("=") != unpadded_totp):
            raise ValueError
    except (ValueError, binascii.Error):
        raise GmailStoreError("invalid_totp_secret", "2FA 密钥须为有效的 Base32 字符串") from None
    try:
        parsed = urlsplit(url)
        if url and (len(url) > 8192 or parsed.scheme not in {"http", "https"}
                or not parsed.hostname or re.search(r"[\s\x00-\x1f\x7f\\]", url)
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
    except ValueError:
        raise GmailStoreError("invalid_verification_url", "取码链接须为有效的 http 或 https 地址") from None
    return _ImportedCredentials(email, password, recovery, unpadded_totp, url, auto_authorize)


def source_identity(email: str) -> Optional[tuple[int, int]]:
    with Session(engine) as session:
        source = session.exec(select(GmailSource).where(GmailSource.email == email)).first()
        return (source.id, source.credential_revision) if source else None



def source_proxy(source_id: int) -> str:
    with Session(engine) as session:
        return _source(session, source_id).proxy_url


def _save_imported_credentials(credentials: _ImportedCredentials, *, expected_identity: Optional[tuple[int, int]],
                               verification: dict, proxy_url: Optional[str] = None) -> tuple[str, dict]:
    """Persist ONLY credentials checked by the verifier; stale results never win."""
    from core.gmail_crypto import decrypt_gmail_secret, encrypt_gmail_secret
    if verification.get("ok") is not True or verification.get("method") != "web":
        raise GmailStoreError("verification_required", "登录验证未通过，未保存资料", 409)
    checked_at = utcnow()
    with Session(engine) as session:
        session.execute(update(GmailSource).where(GmailSource.email == credentials.email).values(email=GmailSource.email))
        source = session.exec(select(GmailSource).where(GmailSource.email == credentials.email)).first()
        identity = (source.id, source.credential_revision) if source else None
        if identity != expected_identity:
            raise GmailStoreError("stale_verification", "验证期间母号配置已变化，未覆盖最新资料，请重新验证", 409)
        is_new = source is None
        if is_new:
            source = GmailSource(email=credentials.email, status="credentials_imported", proxy_url=proxy_url or "")
        changed = source.recovery_email != credentials.recovery_email
        for name in ("login_password", "totp_secret", "verification_url"):
            attribute = f"{name}_ciphertext"
            ciphertext, plaintext = getattr(source, attribute), getattr(credentials, name)
            if name == "verification_url" and not plaintext:
                continue  # An omitted optional link must not erase saved recovery material.
            try:
                if ciphertext and decrypt_gmail_secret(source.email, name, ciphertext) == plaintext:
                    continue
                if not ciphertext and not plaintext:
                    continue
                setattr(source, attribute, encrypt_gmail_secret(source.email, name, plaintext) if plaintext else "")
                if name == "login_password":
                    source.receive_verified = False
            except Exception:
                raise GmailStoreError("crypto_error", "登录资料加解密不可用，请检查服务器凭证密钥配置", 503) from None
            changed = True
        if proxy_url is not None and proxy_url != source.proxy_url:
            source.proxy_url = proxy_url
            source.receive_verified = False
            changed = True
        source.recovery_email = credentials.recovery_email
        source.usability_status = "usable"
        source.usability_method = "web"
        source.usability_checked_at = checked_at
        source.usability_error = ""
        source.credential_revision += 1
        source.updated_at = checked_at
        session.add(source)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise GmailStoreError("stale_verification", "验证期间母号已被添加，未覆盖最新资料，请重新验证", 409) from None
        session.refresh(source)
        outcome = "created" if is_new else ("updated" if changed else "skipped")
        return outcome, _source_dto(source, _alias_count(session, source.id))


def parse_import(data: str) -> list[tuple[int, Optional[_ImportedCredentials], str]]:
    if not isinstance(data, str) or not data.strip():
        raise GmailStoreError("empty_import", "请输入需要验证导入的 Gmail 资料")
    if len(data) > 10_000_000:
        raise GmailStoreError("import_too_large", "导入资料过大，请分批导入")
    lines = data.splitlines()
    if len(lines) > 1000:
        raise GmailStoreError("import_too_large", "每次最多导入 1000 行资料")
    parsed = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            parsed.append((number, _parse_import_line(line), ""))
        except GmailStoreError as exc:
            parsed.append((number, None, exc.message))
    return parsed


def import_sources(data: str, proxy_url: Optional[str] = None) -> dict:
    """Compatibility entry point; verification is asynchronous, never save unchecked."""
    from services.gmail_import_jobs import manager
    return manager.start_import(data, proxy_url=proxy_url)


@dataclass(frozen=True)
class VerificationSnapshot:
    source_id: int
    email: str
    revision: int
    enabled: bool
    proxy_url: str
    login_password_ciphertext: str = field(repr=False)
    totp_secret_ciphertext: str = field(repr=False)
    verification_url_ciphertext: str = field(repr=False)
    app_password_ciphertext: str = field(repr=False)
    recovery_email: str = ""


def verification_snapshot(source_id: int) -> VerificationSnapshot:
    with Session(engine) as session:
        source = _source(session, source_id)
        if not source.login_password_ciphertext and not source.app_password_ciphertext:
            raise GmailStoreError("verification_credentials_missing", "母号未保存可验证的登录资料，请重新导入", 400)
        return VerificationSnapshot(source.id, source.email, source.credential_revision, source.enabled,
                                    source.proxy_url, source.login_password_ciphertext, source.totp_secret_ciphertext,
                                    source.verification_url_ciphertext, source.app_password_ciphertext, source.recovery_email)


def decrypt_verification_credentials(snapshot: VerificationSnapshot) -> _ImportedCredentials:
    from core.gmail_crypto import decrypt_gmail_secret
    try:
        return _ImportedCredentials(snapshot.email,
            decrypt_gmail_secret(snapshot.email, "login_password", snapshot.login_password_ciphertext),
            snapshot.recovery_email,
            decrypt_gmail_secret(snapshot.email, "totp_secret", snapshot.totp_secret_ciphertext),
            decrypt_gmail_secret(snapshot.email, "verification_url", snapshot.verification_url_ciphertext)
                if snapshot.verification_url_ciphertext else "")
    except Exception:
        raise GmailStoreError("crypto_error", "已保存登录资料解密失败，请检查服务器密钥或重新导入", 503) from None


def record_verification_result(snapshot: VerificationSnapshot, *, ok: bool, method: str, message: str) -> dict:
    now = utcnow()
    values = dict(usability_status="usable" if ok else "unavailable", usability_method=method,
                  usability_checked_at=now, usability_error="" if ok else message, updated_at=now,
                  credential_revision=GmailSource.credential_revision + 1)
    if method == "imap":
        values.update(receive_verified=ok, status="ok" if ok else "auth_required",
                      last_checked_at=now, last_error="" if ok else message)
    with Session(engine) as session:
        result = session.execute(update(GmailSource).where(GmailSource.id == snapshot.source_id,
            GmailSource.credential_revision == snapshot.revision).values(**values))
        if result.rowcount != 1:
            raise GmailStoreError("stale_verification", "验证期间母号配置已变化，未覆盖最新状态，请重新验证", 409)
        session.commit()
        source = _source(session, snapshot.source_id)
        return _source_dto(source, _alias_count(session, source.id))


def update_source(source_id: int, *, app_password: Optional[str] = None, enabled: Optional[bool] = None,
                  proxy_url: Optional[str] = None) -> dict:
    if app_password is None and enabled is None and proxy_url is None:
        raise GmailStoreError("empty_update", "请提供新的应用密码、代理或启用状态")
    if enabled is not None and not isinstance(enabled, bool):
        raise GmailStoreError("invalid_enabled", "启用状态必须为布尔值")
    password = normalize_app_password(app_password) if app_password is not None else None
    proxy = normalize_proxy_url(proxy_url) if proxy_url is not None else None
    with Session(engine) as session:
        source = _source(session, source_id)
        snapshot = dict(email=source.email, revision=source.credential_revision, proxy=source.proxy_url,
                        ciphertext=source.app_password_ciphertext)
    target_proxy = proxy if proxy is not None else snapshot["proxy"]
    must_verify_imap = password is not None or (proxy is not None and bool(snapshot["ciphertext"]))
    with verification_guard(snapshot["email"]) if must_verify_imap else nullcontext():
        if must_verify_imap:
            if password is None:
                from core.gmail_crypto import decrypt_gmail_password
                try:
                    password = decrypt_gmail_password(snapshot["email"], snapshot["ciphertext"])
                except Exception:
                    raise GmailStoreError("crypto_error", "应用密码解密失败，请重新保存应用密码", 503) from None
            _check_app_password(snapshot["email"], password, target_proxy)
        now = utcnow()
        values = dict(updated_at=now, credential_revision=GmailSource.credential_revision + 1)
        if password is not None:
            values.update(app_password_ciphertext=_encrypt(snapshot["email"], password), status="ok",
                          usability_status="usable", usability_method="imap", usability_checked_at=now,
                          usability_error="", receive_verified=True, last_checked_at=now, last_error="")
        elif proxy is not None and proxy != snapshot["proxy"]:
            values.update(usability_status="unverified", usability_method="", usability_checked_at=None,
                          usability_error="代理已更改，请重新验证母号", receive_verified=False)
        if enabled is not None:
            values["enabled"] = enabled
        if proxy is not None:
            values["proxy_url"] = proxy
        with Session(engine) as session:
            result = session.execute(update(GmailSource).where(GmailSource.id == source_id,
                GmailSource.credential_revision == snapshot["revision"]).values(**values))
            if result.rowcount != 1:
                raise GmailStoreError("stale_verification", "验证期间母号配置已变化，未覆盖最新资料，请重试", 409)
            session.commit()
            source = _source(session, source_id)
            return _source_dto(source, _alias_count(session, source_id))


def list_aliases(source_id: Optional[int] = None) -> list[dict]:
    with Session(engine) as session:
        query = select(GmailAlias)
        if source_id is not None:
            _source(session, source_id)
            query = query.where(GmailAlias.source_id == source_id)
        rows = session.exec(query.order_by(GmailAlias.id.desc())).all()
        plans = {}
        if "gpt_plan_accounts" in inspect(engine).get_table_names():
            from core.db import GptPlanAccountModel
            plan_ids = {row.gpt_plan_account_id for row in rows if row.gpt_plan_account_id}
            if plan_ids:
                plans = {plan.id: plan for plan in session.exec(select(GptPlanAccountModel).where(GptPlanAccountModel.id.in_(plan_ids))).all()}
        # Older imports can contain more than three aliases. Keep their records,
        # but expose only the earliest three as eligible for new registration.
        rank_by_source: dict[int, int] = {}
        over_limit_ids = set()
        for row in reversed(rows):
            rank_by_source[row.source_id] = rank_by_source.get(row.source_id, 0) + 1
            if rank_by_source[row.source_id] > MAX_ALIASES_PER_SOURCE:
                over_limit_ids.add(row.id)
        sources = {row.id: row for row in session.exec(select(GmailSource)).all()}
        return [{**_alias_dto(row, plans.get(row.gpt_plan_account_id)),
                 "alias_limit_exceeded": row.id in over_limit_ids,
                 "source_production_blocked": bool(sources.get(row.source_id) and sources[row.source_id].production_blocked),
                 "source_production_block_reason": sources[row.source_id].production_block_reason if row.source_id in sources else "",
                 } for row in rows]


def generate_aliases(source_id: int, *, count: int, prefix: str) -> list[dict]:
    with Session(engine) as session:
        created = generate_aliases_in_session(session, source_id, count=count, prefix=prefix)
        session.commit()
        return [_alias_dto(alias) for alias in created]


def generate_aliases_in_session(session: Session, source_id: int, *, count: int, prefix: str) -> list[GmailAlias]:
    """Reserve lifetime capacity and aliases in the caller's transaction.

    The source write serializes manual/API and NV generation across processes.
    Caller owns commit/rollback, so an abandoned candidate consumes no capacity.
    """
    if type(count) is not int or not 1 <= count <= MAX_ALIASES_PER_SOURCE:
        raise GmailStoreError("invalid_count", f"每个 Gmail 母号最多生成 {MAX_ALIASES_PER_SOURCE} 个子号")
    if not isinstance(prefix, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", prefix):
        raise GmailStoreError("invalid_prefix", "前缀限 1 至 32 位小写字母、数字和短横线")
    # Write first: SQLite obtains its writer lock, PostgreSQL locks this source.
    row = session.execute(
        update(GmailSource).where(GmailSource.id == source_id, GmailSource.enabled.is_(True),
                                  GmailSource.usability_status == "usable", GmailSource.production_blocked.is_(False))
        .values(next_alias_sequence=GmailSource.next_alias_sequence)
        .returning(GmailSource.email, GmailSource.next_alias_sequence, GmailSource.generated_alias_count)
    ).first()
    if row is None:
        source = _source(session, source_id)
        if source.production_blocked:
            raise GmailStoreError("source_production_blocked", "此 Gmail 母号已停止新号生产：注册返回 user_already_exists，请使用其他母号", 409)
        if not source.enabled:
            raise GmailStoreError("source_disabled", "源邮箱已停用，请启用后再生成别名", 409)
        raise GmailStoreError("source_unverified", "母号尚未通过可用性验证，请验证成功后再生成子号", 409)
    source_email, sequence, lifetime_count = row
    if _source(session, source_id).production_blocked:
        raise GmailStoreError("source_production_blocked", "此 Gmail 母号已停止新号生产：注册返回 user_already_exists，请使用其他母号", 409)
    generated_count = max(lifetime_count, _alias_count(session, source_id))
    remaining = max(0, MAX_ALIASES_PER_SOURCE - generated_count)
    if count > remaining:
        raise GmailStoreError("source_alias_limit", f"每个 Gmail 母号最多生成 {MAX_ALIASES_PER_SOURCE} 个子号，当前还可生成 {remaining} 个", 409)
    local, domain = source_email.split("@", 1)
    created: list[GmailAlias] = []
    while len(created) < count:
        tag = f"{prefix}{sequence}"
        sequence += 1
        email = f"{local}+{tag}@{domain}"
        if len(tag) > 64 or len(email) > 254:
            raise GmailStoreError("alias_limit", "别名编号已超过长度限制，请使用更短的前缀", 409)
        # Different numeric prefixes can yield the same tag; skip those values.
        if session.exec(select(GmailAlias.id).where(GmailAlias.email == email)).first() is not None:
            continue
        alias = GmailAlias(source_id=source_id, tag=tag, email=email)
        session.add(alias)
        created.append(alias)
    session.execute(update(GmailSource).where(GmailSource.id == source_id).values(
        next_alias_sequence=sequence, generated_alias_count=generated_count + count, updated_at=utcnow(),
    ))
    session.flush()
    return created


def alias_source_id(alias_id: int) -> int:
    with Session(engine) as session:
        return _alias(session, alias_id).source_id


@dataclass(frozen=True)
class NetworkSnapshot:
    source_id: int
    email: str
    revision: int
    password_ciphertext: str = field(repr=False)
    proxy_url: str = ""
    alias_id: Optional[int] = None
    alias_email: Optional[str] = None


def network_snapshot(source_id: int, alias_id: Optional[int] = None) -> NetworkSnapshot:
    with Session(engine) as session:
        source = _source(session, source_id)
        if not source.enabled:
            raise GmailStoreError("source_disabled", "源邮箱已停用，请启用后再操作", 409)
        if not source.app_password_ciphertext:
            raise GmailStoreError("receive_auth_required", "已保存登录资料，尚未配置 Gmail 收件授权；普通密码/2FA 不是应用专用密码", 400)
        alias = _alias(session, alias_id) if alias_id is not None else None
        if alias is not None and alias.source_id != source_id:
            raise GmailStoreError("alias_mismatch", "别名不属于此 Gmail 源邮箱", 409)
        if alias is not None and alias.email != f"{source.email.split('@', 1)[0]}+{alias.tag}@gmail.com":
            raise GmailStoreError("alias_mismatch", "别名地址与保存的源邮箱不一致", 409)
        return NetworkSnapshot(
            source_id=source_id, email=source.email, revision=source.credential_revision,
            password_ciphertext=source.app_password_ciphertext,
            proxy_url=source.proxy_url,
            alias_id=alias.id if alias else None, alias_email=alias.email if alias else None,
        )


def decrypt_snapshot_password(snapshot: NetworkSnapshot) -> str:
    from core.gmail_crypto import decrypt_gmail_password
    try:
        return decrypt_gmail_password(snapshot.email, snapshot.password_ciphertext)
    except Exception:
        raise GmailStoreError("crypto_error", "应用密码解密失败，请检查服务器凭证密钥或重新保存应用密码", 503) from None


def record_network_result(snapshot: NetworkSnapshot, *, status: str, message: str,
                          checked_at: datetime, test_receive: bool = False) -> bool:
    """Fence stale requests after credentials or enabled state change."""
    values = dict(status=status, last_error=message if status != "ok" else "",
                  last_checked_at=checked_at, updated_at=checked_at)
    if status == "ok":
        values.update(receive_verified=True, usability_status="usable", usability_method="imap",
                      usability_checked_at=checked_at, usability_error="")
    elif status in {"auth_required", "authentication_failed"}:
        values["receive_verified"] = False
    with Session(engine) as session:
        result = session.execute(update(GmailSource).where(
            GmailSource.id == snapshot.source_id,
            GmailSource.credential_revision == snapshot.revision,
            GmailSource.enabled.is_(True),
        ).values(**values))
        if status in {"auth_required", "authentication_failed"}:
            session.execute(update(GmailSource).where(GmailSource.id == snapshot.source_id,
                GmailSource.credential_revision == snapshot.revision, GmailSource.usability_method == "imap"
            ).values(usability_status="unavailable", usability_error=message, usability_checked_at=checked_at))
        if result.rowcount != 1:
            session.rollback()
            return False
        if test_receive and snapshot.alias_id is not None:
            session.execute(update(GmailAlias).where(
                GmailAlias.id == snapshot.alias_id, GmailAlias.source_id == snapshot.source_id,
            ).values(last_test_at=checked_at, last_test_status=status,
                     last_error=message if status != "ok" else ""))
        session.commit()
        return True
