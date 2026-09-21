"""Recover local authentication leases only when their owner has stopped.

Login tokens remain opaque to callers. Recording process identity in the token
lets a new backend distinguish an interrupted login from a live worker without
clearing unrelated payment/security operations or needing a database migration.
"""

import hashlib
import math
import os
import re
import socket
import uuid

import psutil


_PREFIX = "plan-login-v1"
_PREPARATION_PREFIX = "plan-preparation-v1"


def _host_id() -> str:
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:24]


def new_login_lease_token() -> str:
    return _new_owner_token(_PREFIX)


def new_preparation_lease_token() -> str:
    """Use a distinct namespace; a login token cannot release preparation."""
    return _new_owner_token(_PREPARATION_PREFIX)


def _new_owner_token(prefix: str) -> str:
    nonce = uuid.uuid4().hex
    try:
        pid = os.getpid()
        born = psutil.Process(pid).create_time()
        if not math.isfinite(born) or born <= 0:
            return nonce
        return f"{prefix}:{_host_id()}:{pid}:{born:.6f}:{nonce}"
    except (psutil.Error, OSError, RuntimeError):
        # Restricted process inspection must not prevent a normal login.
        # A legacy-format token still has the ordinary expiry/release path.
        return nonce


def login_lease_owner_stopped(token: str) -> bool:
    return _lease_owner_stopped(token, _PREFIX)


def preparation_lease_owner_stopped(token: str) -> bool:
    return _lease_owner_stopped(token, _PREPARATION_PREFIX)


def _lease_owner_stopped(token: str, prefix: str) -> bool:
    fields = str(token or "").split(":")
    if len(fields) != 5 or fields[0] != prefix:
        return False
    _, host, raw_pid, raw_born, nonce = fields
    try:
        if host != _host_id() or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            return False
        pid, born = int(raw_pid), float(raw_born)
        if pid <= 0 or not math.isfinite(born) or born <= 0:
            return False
    except (ValueError, OSError):
        return False

    try:
        process = psutil.Process(pid)
        observed_born = process.create_time()
        if not math.isfinite(observed_born) or observed_born <= 0:
            return False
        # The OS may reuse a PID after restart; creation time identifies the
        # original owner. A live process with that new PID does not own this lock.
        if f"{observed_born:.6f}" != f"{born:.6f}":
            return True
        return process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}
    except psutil.NoSuchProcess:
        return True
    except (psutil.Error, OSError, RuntimeError):
        # Lack of permission or unknown liveness is not proof of a stopped job.
        return False
