"""Authentication API: password login, JWT session, TOTP 2FA."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json as _json
import os
import secrets
import struct
import threading
import time
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)
_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
SESSION_COOKIE = "gbm_session"
SESSION_MAX_AGE = 86400 * 7


# ── Config helpers ─────────────────────────────────────────────────────────────

def _cfg():
    from core.config_store import config_store
    return config_store


# ── JWT (HS256, stdlib only) ───────────────────────────────────────────────────

def _jwt_secret() -> str:
    env_secret = os.getenv("APP_JWT_SECRET", "")
    if env_secret:
        return env_secret
    stored = _cfg().get("auth_jwt_secret", "")
    if not stored:
        stored = secrets.token_hex(32)
        _cfg().set("auth_jwt_secret", stored)
    return stored


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def create_token(expire_seconds: int = 86400 * 7) -> str:
    header = _b64url_encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(_json.dumps({
        "sub": "admin",
        "exp": int(time.time()) + expire_seconds,
        "iat": int(time.time()),
        "ver": str(_cfg().get("auth_token_version", "") or ""),
    }).encode())
    sig = _b64url_encode(
        hmac.new(_jwt_secret().encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict:
    try:
        header, payload, sig = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="无效的令牌")
    expected = _b64url_encode(
        hmac.new(_jwt_secret().encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="令牌签名无效")
    try:
        data = _json.loads(_b64url_decode(payload))
    except Exception:
        raise HTTPException(status_code=401, detail="令牌格式错误")
    if data.get("exp", 0) < time.time():
        raise HTTPException(status_code=401, detail="令牌已过期，请重新登录")
    current_version = str(_cfg().get("auth_token_version", "") or "")
    if current_version and not hmac.compare_digest(
        str(data.get("ver") or ""),
        current_version,
    ):
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return data


def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> None:
    token = credentials.credentials if credentials is not None else request_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="未认证")
    verify_token(token)


def require_configured_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> None:
    """Require an initialized admin password and a valid bearer session.

    Ordinary APIs preserve the application's first-run/no-password behavior.
    Secret export uses this stricter guard because it returns plaintext to the
    caller.  Secret-producing mutations use the separate loopback bootstrap
    guard below, while their durable values remain encrypted independently.
    """
    if not _cfg().get("auth_password_hash", ""):
        raise HTTPException(status_code=403, detail="请先设置后台登录密码")
    require_auth(request, credentials)


def require_configured_auth_header(authorization: str) -> None:
    """Non-dependency variant for a conditional route action."""
    if not _cfg().get("auth_password_hash", ""):
        raise HTTPException(status_code=403, detail="请先设置后台登录密码")
    value = str(authorization or "").strip()
    if not value.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="未认证")
    verify_token(value.split(None, 1)[1])


def _is_loopback_host(value: str) -> bool:
    """Return whether an already-parsed host identifies this machine.

    Callers must pass the transport peer and request URL host separately.  We
    deliberately do not trust ``X-Forwarded-For`` here: an installation that
    exposes the application through a reverse proxy must initialize normal
    administrator authentication before it can mutate remote account security.
    """
    host = str(value or "").strip().strip("[]").split("%", 1)[0]
    if host.casefold() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def require_sensitive_mutation_auth_header(
    authorization: str,
    *,
    client_host: str,
    request_host: str,
) -> None:
    """Authorize a secret-producing mutation without conflating two passwords.

    When administrator login protection is enabled, a valid bearer session is
    mandatory.  The application's documented no-password mode has no bearer
    session to present, so the narrow bootstrap alternative is restricted to a
    direct loopback peer *and* a loopback URL.  Remote/reverse-proxied callers
    must first initialize the backend administrator password.

    This controls who may start the workflow.  ChatGPT credentials themselves
    remain protected by the independent AES-GCM credential-store key.
    """
    if _cfg().get("auth_password_hash", ""):
        value = str(authorization or "").strip()
        if not value.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="未认证")
        verify_token(value.split(None, 1)[1])
        return

    if not (
        _is_loopback_host(client_host)
        and _is_loopback_host(request_host)
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "后台登录密码未设置时，ChatGPT 密码与 2FA 设置仅允许从本机 "
                "localhost 访问；远程操作请先在设置中初始化后台登录密码"
            ),
        )


def require_sensitive_credential_export_auth_header(
    authorization: str,
    *,
    client_host: str,
    request_host: str,
) -> None:
    """Authorize plaintext ChatGPT credential export.

    An installation protected by an administrator password always requires a
    valid bearer session.  In the documented no-password mode, export is only
    available to a browser connected directly through a loopback peer *and* a
    loopback URL.  Checking both values prevents a reverse proxy on localhost
    from accidentally turning this bootstrap path into a remote export API.
    """
    if _cfg().get("auth_password_hash", ""):
        value = str(authorization or "").strip()
        if not value.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="未认证")
        verify_token(value.split(None, 1)[1])
        return

    if not (
        _is_loopback_host(client_host)
        and _is_loopback_host(request_host)
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "后台登录密码未设置时，ChatGPT 安全凭据导出仅允许从本机 "
                "localhost 访问；远程导出请先在设置中初始化后台登录密码"
            ),
        )


# ── Password ───────────────────────────────────────────────────────────────────

def _legacy_hash_pw(password: str) -> str:
    """Read-only compatibility for installations created before Argon2id."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _hash_pw(password: str) -> str:
    return _password_hasher.hash(password)


def _verify_pw(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("$argon2id$"):
        try:
            return bool(_password_hasher.verify(stored, password))
        except (VerifyMismatchError, InvalidHashError):
            return False
    # Migrate the old unsalted SHA-256 hash only after a successful login.
    if hmac.compare_digest(_legacy_hash_pw(password), stored):
        _cfg().set("auth_password_hash", _hash_pw(password))
        return True
    return False


def _set_session_cookie(response: Response, token: str) -> None:
    secure = str(os.getenv("GBM_COOKIE_SECURE", "auto")).strip().lower()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=secure in {"1", "true", "yes", "on"},
        samesite="strict",
        path="/",
    )


def request_token(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header.split(None, 1)[1].strip()
    return str(request.cookies.get(SESSION_COOKIE) or "").strip()


def _rotate_token_version() -> None:
    """Invalidate all previously issued admin sessions."""
    _cfg().set("auth_token_version", secrets.token_hex(16))


# ── TOTP (RFC 6238, stdlib only) ───────────────────────────────────────────────

def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_uri(secret: str, issuer: str = "AccountManager") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}?secret={secret}&issuer={quote(issuer)}"


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def verify_totp(secret: str, code: str) -> bool:
    counter = int(time.time()) // 30
    user_code = str(code).strip().zfill(6)
    for delta in (-1, 0, 1):
        if hmac.compare_digest(_totp_at(secret, counter + delta), user_code):
            return True
    return False


# ── Pending 2FA sessions (in-memory) ──────────────────────────────────────────

_pending_2fa: dict[str, float] = {}  # temp_token -> expires_at
_login_failures: dict[str, list[float]] = {}
_login_lock = threading.Lock()
_LOGIN_WINDOW = 15 * 60
_LOGIN_LIMIT = 8


def _client_key(request: Request) -> str:
    # Deliberately use the transport peer. Deployments that trust a reverse
    # proxy should apply an additional rate limit at that proxy.
    return str(request.client.host if request.client else "unknown")


def _check_login_rate(request: Request) -> None:
    now = time.time()
    key = _client_key(request)
    with _login_lock:
        recent = [stamp for stamp in _login_failures.get(key, []) if now - stamp < _LOGIN_WINDOW]
        _login_failures[key] = recent
        if len(recent) >= _LOGIN_LIMIT:
            raise HTTPException(status_code=429, detail="登录失败次数过多，请稍后再试")


def _record_login_failure(request: Request) -> None:
    with _login_lock:
        _login_failures.setdefault(_client_key(request), []).append(time.time())


def _clear_login_failures(request: Request) -> None:
    with _login_lock:
        _login_failures.pop(_client_key(request), None)


def _totp_secret() -> str:
    value = str(_cfg().get("auth_totp_secret", "") or "")
    if not value:
        return ""
    from core.credential_crypto import decrypt_credential, encrypt_credential
    if value.startswith("aesgcm:v1:"):
        return decrypt_credential("admin@localhost", "totp_secret", value)
    # Transparently protect pre-open-source plaintext records.
    _cfg().set("auth_totp_secret", encrypt_credential("admin@localhost", "totp_secret", value))
    return value


def _store_totp_secret(value: str) -> None:
    if not value:
        _cfg().set("auth_totp_secret", "")
        return
    from core.credential_crypto import encrypt_credential
    _cfg().set(
        "auth_totp_secret",
        encrypt_credential("admin@localhost", "totp_secret", value),
    )


# ── Schemas ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    password: str


class TotpVerifyRequest(BaseModel):
    temp_token: str
    code: str


class SetupPasswordRequest(BaseModel):
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class EnableTotpRequest(BaseModel):
    secret: str
    code: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/status")
def auth_status(request: Request):
    cfg = _cfg()
    authenticated = False
    token = request_token(request)
    if token:
        try:
            verify_token(token)
            authenticated = True
        except HTTPException:
            pass
    return {
        "has_password": bool(cfg.get("auth_password_hash", "")),
        "has_totp": bool(cfg.get("auth_totp_secret", "")),
        "authenticated": authenticated,
    }


@router.post("/setup")
def setup_password(
    body: SetupPasswordRequest,
    response: Response,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
):
    """Set initial password, or update it only when the caller is already authenticated."""
    if not body.password or len(body.password) < 8:
        raise HTTPException(status_code=400, detail="密码至少需要 8 位")
    cfg = _cfg()
    if cfg.get("auth_password_hash", ""):
        token = credentials.credentials if credentials is not None else request_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="未认证")
        verify_token(token)
    elif not (
        _is_loopback_host(request.client.host if request.client else "")
        and _is_loopback_host(request.url.hostname or "")
    ):
        raise HTTPException(
            status_code=403,
            detail="首次管理员初始化仅允许通过服务器本机 127.0.0.1 访问",
        )
    cfg.set("auth_password_hash", _hash_pw(body.password))
    _rotate_token_version()
    token = create_token()
    _set_session_cookie(response, token)
    return {"ok": True, "access_token": token, "token_type": "bearer"}


@router.post("/disable")
def disable_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
):
    """Disable password protection. Requires auth only if a password is currently set."""
    cfg = _cfg()
    if cfg.get("auth_password_hash", ""):
        token = credentials.credentials if credentials is not None else request_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="未认证")
        verify_token(token)
    cfg.set("auth_password_hash", "")
    cfg.set("auth_totp_secret", "")
    _rotate_token_version()
    return {"ok": True}


@router.post("/login")
def login(body: LoginRequest, response: Response, request: Request):
    _check_login_rate(request)
    cfg = _cfg()
    stored = cfg.get("auth_password_hash", "")
    if not stored:
        raise HTTPException(status_code=403, detail="no_password_set")
    if not _verify_pw(body.password, stored):
        _record_login_failure(request)
        raise HTTPException(status_code=401, detail="密码错误")
    _clear_login_failures(request)
    totp_secret = _totp_secret()
    if totp_secret:
        temp = secrets.token_hex(24)
        _pending_2fa[temp] = time.time() + 300  # 5 min expiry
        return {"requires_2fa": True, "temp_token": temp}
    token = create_token()
    _set_session_cookie(response, token)
    return {"requires_2fa": False, "access_token": token, "token_type": "bearer"}


@router.post("/verify-totp")
def verify_totp_route(body: TotpVerifyRequest, response: Response, request: Request):
    _check_login_rate(request)
    expiry = _pending_2fa.get(body.temp_token)
    if not expiry or time.time() > expiry:
        raise HTTPException(status_code=401, detail="临时令牌无效或已过期，请重新登录")
    cfg = _cfg()
    secret = _totp_secret()
    if not secret:
        raise HTTPException(status_code=400, detail="2FA 未启用")
    if not verify_totp(secret, body.code):
        _record_login_failure(request)
        raise HTTPException(status_code=400, detail="验证码错误")
    _pending_2fa.pop(body.temp_token, None)
    _clear_login_failures(request)
    token = create_token()
    _set_session_cookie(response, token)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.post("/change-password", dependencies=[Depends(require_auth)])
def change_password(body: ChangePasswordRequest):
    cfg = _cfg()
    stored = cfg.get("auth_password_hash", "")
    if stored and not _verify_pw(body.current_password, stored):
        raise HTTPException(status_code=400, detail="当前密码错误")
    if not body.new_password or len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少需要 8 位")
    cfg.set("auth_password_hash", _hash_pw(body.new_password))
    _rotate_token_version()
    return {
        "ok": True,
        "access_token": create_token(),
        "token_type": "bearer",
    }


@router.get("/2fa/setup", dependencies=[Depends(require_auth)])
def setup_2fa():
    secret = generate_totp_secret()
    return {"secret": secret, "uri": totp_uri(secret)}


@router.post("/2fa/enable", dependencies=[Depends(require_auth)])
def enable_2fa(body: EnableTotpRequest):
    if not body.secret or len(body.secret) < 16:
        raise HTTPException(status_code=400, detail="无效的密钥")
    if not verify_totp(body.secret, body.code):
        raise HTTPException(status_code=400, detail="验证码错误，请重试")
    _store_totp_secret(body.secret)
    return {"ok": True}


@router.post("/2fa/disable", dependencies=[Depends(require_auth)])
def disable_2fa():
    _store_totp_secret("")
    return {"ok": True}
