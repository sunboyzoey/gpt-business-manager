"""Peer-to-peer pending_rt 同步 (Producer 侧)。

替代原 PostgreSQL 中心库:RT 机直接 HTTP 拉注册机。
- 本机角色由配置 peer_sync_role = producer | consumer | off 决定
- pull 接口单事务: SELECT N pending_rt → 安全状态校验 → DELETE → 返回 rows,无 claim/TTL,无鉴权
- consumer 拉走即删除;网络中断时会丢这一批 (用户接受的权衡,内网信任前提)
- 加 INFO 日志记录每次 pull 的 (peer 来源 ip, ids) 以便事后排查

当前无认证协议不传输 ChatGPT Authenticator 凭据。只要候选账号存在
pending/enabled/unmanaged MFA 状态,整批 pull 必须 fail-closed 并保留所有源记录。
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select, func
from sqlalchemy import text

from core.config_store import config_store
from core.db import AccountModel, engine as sqlite_engine, _utcnow
from core.base_platform import AccountStatus


_PLATFORM = "chatgpt"
_DELETE_CHUNK = 500
_pull_lock = threading.Lock()

_log = logging.getLogger(__name__)

_TOTP_MIGRATION_BLOCKED_ERROR = (
    "检测到待 RT 账号已启用或正在确认 ChatGPT Authenticator 2FA；"
    "当前 peer sync 不传输安全凭据，为防目标机无法登录，"
    "已取消本次拉取且未删除任何源记录"
)
_TOTP_STATUS_UNAVAILABLE_ERROR = (
    "无法核验待 RT 账号的 ChatGPT TOTP 安全状态；"
    "为防迁移后丢失登录凭据，已取消本次拉取且未删除任何源记录"
)


# ─────────────────────────────────────────────────────────────
#  角色读取
# ─────────────────────────────────────────────────────────────


def get_role() -> str:
    """peer_sync_role: producer | consumer | off。默认 off。"""
    role = str(config_store.get("peer_sync_role", "off") or "off").strip().lower()
    if role not in ("producer", "consumer", "off"):
        return "off"
    return role


def is_producer() -> bool:
    return get_role() == "producer"


def is_consumer() -> bool:
    return get_role() == "consumer"


# ─────────────────────────────────────────────────────────────
#  状态
# ─────────────────────────────────────────────────────────────


def pending_rt_count() -> int:
    """本机当前 pending_rt 总数。"""
    with Session(sqlite_engine) as s:
        n = s.exec(
            select(func.count()).select_from(AccountModel)
            .where(AccountModel.platform == _PLATFORM)
            .where(AccountModel.status == AccountStatus.PENDING_RT.value)
        ).one()
        return int(n or 0)


def status_snapshot() -> Dict[str, Any]:
    return {
        "role": get_role(),
        "pending_rt": pending_rt_count(),
    }


# ─────────────────────────────────────────────────────────────
#  Pull (Producer 处理 consumer 的拉取请求)
# ─────────────────────────────────────────────────────────────


def producer_pull(*, limit: int, peer_label: str = "") -> Dict[str, Any]:
    """单事务原子操作: SELECT N pending_rt → DELETE → 返回 rows。

    被 api/peer_sync.py 调用响应 consumer 的 POST /peer-sync/pull 请求。
    """
    if not is_producer():
        return {"ok": False, "rows": [], "error": "本机 peer_sync_role != producer"}

    limit = max(1, min(int(limit or 0), 5000))

    rows: List[Dict[str, Any]] = []
    with _pull_lock:
        with Session(sqlite_engine) as s:
            selected = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.status == AccountStatus.PENDING_RT.value)
                .order_by(AccountModel.id)
                .limit(limit)
            ).all()
            if not selected:
                return {"ok": True, "rows": [], "count": 0}

            try:
                from services.chatgpt_security_store import (
                    get_chatgpt_totp_protected_emails,
                )

                protected_emails = get_chatgpt_totp_protected_emails(
                    acc.email for acc in selected
                )
            except Exception as exc:
                # Do not reflect DB/crypto exception text through this
                # unauthenticated endpoint; it may contain implementation or
                # credential details.
                _log.warning(
                    "[PeerSync.Producer] TOTP status check failed; pull denied (%s)",
                    type(exc).__name__,
                )
                return {
                    "ok": False,
                    "rows": [],
                    "count": 0,
                    "deleted_local": 0,
                    "error": _TOTP_STATUS_UNAVAILABLE_ERROR,
                }
            if protected_emails:
                _log.warning(
                    "[PeerSync.Producer] denied credential-free migration for %d "
                    "TOTP-protected pending_rt account(s)",
                    len(protected_emails),
                )
                return {
                    "ok": False,
                    "rows": [],
                    "count": 0,
                    "deleted_local": 0,
                    "blocked_count": len(protected_emails),
                    "error": _TOTP_MIGRATION_BLOCKED_ERROR,
                }

            account_ids: List[int] = []
            for acc in selected:
                extra = acc.get_extra()
                account_ids.append(int(acc.id))
                rows.append({
                    "id": int(acc.id),
                    "email": acc.email,
                    "password": acc.password or "",
                    "user_id": acc.user_id or "",
                    "region": acc.region or "",
                    "token": acc.token or "",
                    "status": acc.status,
                    "trial_end_time": int(acc.trial_end_time or 0),
                    "cashier_url": acc.cashier_url or "",
                    "extra": extra,
                })

            # 同事务删除 (id 是 int,直接拼字符串安全)
            deleted = 0
            for i in range(0, len(account_ids), _DELETE_CHUNK):
                chunk = account_ids[i:i + _DELETE_CHUNK]
                ids_csv = ",".join(str(x) for x in chunk)
                r = s.exec(text(f"""
                  DELETE FROM accounts
                  WHERE id IN ({ids_csv})
                    AND platform = '{_PLATFORM}'
                    AND status = '{AccountStatus.PENDING_RT.value}'
                """))
                deleted += r.rowcount or 0
            s.commit()

            _log.info(
                "[PeerSync.Producer] pulled %d/%d pending_rt by peer=%s ids=%s",
                deleted,
                len(account_ids),
                peer_label or "-",
                ",".join(str(x) for x in account_ids[:50]),
            )
            return {
                "ok": True,
                "rows": rows,
                "count": len(rows),
                "deleted_local": deleted,
            }


# ─────────────────────────────────────────────────────────────
#  Consumer 写本机 (供 puller 调用)
# ─────────────────────────────────────────────────────────────


def consumer_write_local(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """consumer 把从 peer 拉到的 rows 写本机 SQLite。同 email 已存在 → 覆盖为 pending_rt。"""
    if not rows:
        return {"ok": True, "written": 0, "updated": 0, "inserted": 0}

    inserted = 0
    updated = 0
    with Session(sqlite_engine) as s:
        for r in rows:
            extra = r.get("extra") or {}
            if not isinstance(extra, dict):
                try:
                    extra = json.loads(extra)
                except Exception:
                    extra = {}
            extra["_pulled_from_peer_id"] = r.get("id")
            extra["_pulled_at"] = int(_utcnow().timestamp())

            email = (r.get("email") or "").strip()
            if not email:
                continue

            existing = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == _PLATFORM)
                .where(AccountModel.email == email)
            ).first()
            if existing:
                existing.password = r.get("password") or existing.password
                existing.status = AccountStatus.PENDING_RT.value
                existing.set_extra(extra)
                existing.updated_at = _utcnow()
                s.add(existing)
                updated += 1
            else:
                acc = AccountModel(
                    platform=_PLATFORM,
                    email=email,
                    password=r.get("password") or "",
                    user_id=r.get("user_id") or "",
                    region=r.get("region") or "",
                    token=r.get("token") or "",
                    status=AccountStatus.PENDING_RT.value,
                    trial_end_time=int(r.get("trial_end_time") or 0),
                    cashier_url=r.get("cashier_url") or "",
                    extra_json=json.dumps(extra, ensure_ascii=False),
                )
                s.add(acc)
                inserted += 1
        s.commit()

    return {
        "ok": True,
        "written": inserted + updated,
        "inserted": inserted,
        "updated": updated,
    }
