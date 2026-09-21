"""TOTP 生成（标准库实现，无第三方依赖）。"""
import base64
import hashlib
import hmac
import struct
import time


def _normalize_secret(secret: str) -> bytes:
    cleaned = (secret or "").strip().replace(" ", "").upper()
    if not cleaned:
        raise ValueError("空的 TOTP 密钥")
    padding = "=" * ((-len(cleaned)) % 8)
    return base64.b32decode(cleaned + padding)


def generate_totp(secret: str, period: int = 30, digits: int = 6, at: float = None) -> str:
    """根据 base32 密钥生成当前 TOTP 验证码。"""
    key = _normalize_secret(secret)
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)
