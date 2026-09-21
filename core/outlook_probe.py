"""Outlook 邮箱取码类型探测 — Graph / IMAP / POP"""

import base64
import contextlib
import imaplib
import poplib
from typing import Optional

import requests

# ── 常量 ──────────────────────────────────────────────────────

_TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

_GRAPH_TOKEN_SCOPE = "https://graph.microsoft.com/.default"
_IMAP_TOKEN_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
_POP_TOKEN_SCOPE = "https://outlook.office.com/POP.AccessAsUser.All offline_access"

_GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"

_IMAP_HOSTS = (
    ("outlook.office365.com", 993),
    ("imap-mail.outlook.com", 993),
)
_POP_HOSTS = (
    ("outlook.office365.com", 995),
    ("pop-mail.outlook.com", 995),
)

MAIL_ACCESS_META = {
    "graph": ("Graph API", "success"),
    "imap_pop": ("IMAP/POP", "warning"),
}


# ── 内部辅助 ──────────────────────────────────────────────────

def _exchange_access_token(refresh_token: str, client_id: str, scope: str) -> str:
    refresh_token = str(refresh_token or "").strip()
    client_id = str(client_id or "").strip()
    scope = str(scope or "").strip()
    if not refresh_token or not client_id or not scope:
        return ""
    try:
        resp = requests.post(
            _TOKEN_ENDPOINT,
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": scope,
            },
            timeout=20,
        )
        resp.raise_for_status()
        return str((resp.json() or {}).get("access_token") or "").strip()
    except Exception:
        return ""


def _xoauth2_bytes(email: str, access_token: str) -> bytes:
    return f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")


# ── 探测 ──────────────────────────────────────────────────────

def probe_graph(email: str, refresh_token: str, client_id: str) -> bool:
    access_token = _exchange_access_token(refresh_token, client_id, _GRAPH_TOKEN_SCOPE)
    if not access_token:
        return False
    try:
        resp = requests.get(
            _GRAPH_MESSAGES_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"$top": 1, "$orderby": "receivedDateTime desc", "$select": "id,subject"},
            timeout=20,
        )
        return int(resp.status_code or 0) == 200
    except Exception:
        return False


def probe_imap(email: str, refresh_token: str, client_id: str) -> bool:
    access_token = _exchange_access_token(refresh_token, client_id, _IMAP_TOKEN_SCOPE)
    if not access_token:
        return False
    auth_bytes = _xoauth2_bytes(email, access_token)
    for host, port in _IMAP_HOSTS:
        conn: Optional[imaplib.IMAP4_SSL] = None
        try:
            conn = imaplib.IMAP4_SSL(host=host, port=port, timeout=20)
            conn.authenticate("XOAUTH2", lambda _: auth_bytes)
            conn.select("INBOX")
            return True
        except Exception:
            continue
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.logout()
    return False


def probe_pop(email: str, refresh_token: str, client_id: str) -> bool:
    access_token = _exchange_access_token(refresh_token, client_id, _POP_TOKEN_SCOPE)
    if not access_token:
        return False
    auth_b64 = base64.b64encode(_xoauth2_bytes(email, access_token)).decode("ascii")
    for host, port in _POP_HOSTS:
        conn: Optional[poplib.POP3_SSL] = None
        try:
            conn = poplib.POP3_SSL(host=host, port=port, timeout=20)
            conn._shortcmd(f"AUTH XOAUTH2 {auth_b64}")
            return True
        except Exception:
            continue
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.quit()
    return False


# ── 公开接口 ──────────────────────────────────────────────────

def classify_mail_access_type(
    email: str,
    refresh_token: str,
    client_id: str,
) -> Optional[str]:
    """
    探测 Outlook 邮箱的取码类型。
    返回 "graph" / "imap_pop" / None（不可达）。
    """
    email = str(email or "").strip()
    refresh_token = str(refresh_token or "").strip()
    client_id = str(client_id or "").strip()
    if not email or not refresh_token or not client_id:
        return None
    if probe_graph(email, refresh_token, client_id):
        return "graph"
    if probe_imap(email, refresh_token, client_id):
        return "imap_pop"
    if probe_pop(email, refresh_token, client_id):
        return "imap_pop"
    return None
