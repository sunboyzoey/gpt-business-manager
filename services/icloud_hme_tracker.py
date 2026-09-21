"""iCloud HME 邮箱别名注册状态追踪。

职责:
  1. sync_from_remote()         — 从本机 Go 服务拉 list,upsert 到 DB
  2. claim_alias_for_platform() — 找一个该平台未注册的别名
  3. mark_register_status()     — 注册结果回写 (成功/失败/进行中)
  4. get_status_by_emails()     — 批量查状态

与 OutlookAccountModel 的设计对齐,字段命名共用 _PLATFORM_STATUS_FIELD_MAP。
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx
from sqlmodel import Session, select, or_, col

from core.db import IcloudHmeAliasModel, engine
from core.config_store import config_store


_CLAIM_LOCK = threading.Lock()
_TRACKER_LOCK = threading.Lock()

# 与 api/tasks.py 里的 _PLATFORM_STATUS_FIELD_MAP 保持一致
PLATFORM_STATUS_FIELDS = {
    "chatgpt": ("gpt_register_status", "gpt_account_id"),
    "grok": ("grok_register_status", "grok_account_id"),
    "trae": ("trae_register_status", "trae_account_id"),
    "kiro": ("kiro_register_status", "kiro_account_id"),
    "openblocklabs": ("obl_register_status", "obl_account_id"),
    "cursor": ("cursor_register_status", "cursor_account_id"),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _icloud_settings() -> tuple[str, str]:
    base = (config_store.get("icloud_hme_base_url") or "http://127.0.0.1:8787").rstrip("/")
    key = config_store.get("icloud_hme_api_key") or ""
    return base, key


# ── 远端同步 ─────────────────────────────────────────────────────────


def sync_from_remote() -> dict:
    """拉所有 HME 别名,upsert 到 DB。返回 {synced, inserted, updated, skipped}。

    优先用**原生客户端**(只需 icloud_cookie);未配 Cookie 时回退到旧 Go 服务。
    """
    items: list = []
    try:
        from core.config_store import config_store as _cs
        if str(_cs.get("icloud_cookie", "") or "").strip():
            from services import icloud_hme_client as hc
            res = hc.list_hme()
            # 归一成 {hme, anonymousId, label, forwardToEmail, isActive} 结构
            items = [
                {
                    "hme": it.get("hme"),
                    "anonymousId": it.get("anonymousId"),
                    "label": it.get("label"),
                    "forwardToEmail": it.get("forwardToEmail"),
                    "isActive": it.get("isActive", True),
                    "note": it.get("note", ""),
                }
                for it in (res.get("items") or [])
            ]
    except Exception as exc:
        raise RuntimeError(f"原生 HME 拉取失败: {exc}")

    if not items:
        # 回退旧 Go 服务
        base, key = _icloud_settings()
        if not key:
            raise RuntimeError("未配置 icloud_cookie(原生)也未配置 icloud_hme_api_key(Go)")
        with httpx.Client(timeout=30.0, trust_env=False) as client:
            resp = client.get(f"{base}/api/emails", headers={"X-API-Key": key})
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error") or resp.text
            except Exception:
                err = resp.text
            raise RuntimeError(f"Go 服务返回 {resp.status_code}: {err}")
        items = resp.json().get("items") or []

    inserted = 0
    updated = 0
    with _TRACKER_LOCK, Session(engine) as session:
        existing_map = {
            row.email: row
            for row in session.exec(select(IcloudHmeAliasModel)).all()
        }
        for it in items:
            email = (it.get("hme") or "").strip()
            if not email:
                continue
            row = existing_map.get(email)
            if row is None:
                row = IcloudHmeAliasModel(
                    email=email,
                    anonymous_id=it.get("anonymousId") or "",
                    label=it.get("label") or "",
                    forward_to=it.get("forwardToEmail") or "",
                    is_active=bool(it.get("isActive", True)),
                    note=it.get("note") or "",
                )
                session.add(row)
                inserted += 1
            else:
                # 只把 iCloud 端的属性同步过来,注册状态由本地管理不动
                row.anonymous_id = it.get("anonymousId") or row.anonymous_id
                row.label = it.get("label") or row.label
                row.forward_to = it.get("forwardToEmail") or row.forward_to
                row.is_active = bool(it.get("isActive", True))
                row.updated_at = _utcnow()
                session.add(row)
                updated += 1
        session.commit()
    return {
        "ok": True,
        "synced": len(items),
        "inserted": inserted,
        "updated": updated,
    }


# ── 注册流程使用 ─────────────────────────────────────────────────────


def claim_alias_for_platform(platform: str) -> Optional[dict]:
    """找一个 (该平台 == 未注册) 且 enabled && is_active 的别名,
    返回 {email, anonymous_id, ...} 或 None (池子用尽)。

    并发安全:借助 _CLAIM_LOCK 串行化,把"查找+标记进行中"放进同一事务,
    避免两个任务同时拿到同一个别名。
    """
    fields = PLATFORM_STATUS_FIELDS.get(platform)
    if not fields:
        return None
    status_col, _ = fields

    with _CLAIM_LOCK, Session(engine) as session:
        stmt = (
            select(IcloudHmeAliasModel)
            .where(IcloudHmeAliasModel.enabled == True)
            .where(IcloudHmeAliasModel.is_active == True)
            .where(getattr(IcloudHmeAliasModel, status_col) == "未注册")
            .order_by(col(IcloudHmeAliasModel.last_used).asc().nulls_first(),
                      col(IcloudHmeAliasModel.created_at).asc())
            .limit(1)
        )
        row = session.exec(stmt).first()
        if not row:
            return None
        # 立即标记进行中,占位防并发
        setattr(row, status_col, "进行中")
        row.last_used = _utcnow()
        row.updated_at = _utcnow()
        session.add(row)
        session.commit()
        session.refresh(row)
        return {
            "email": row.email,
            "anonymous_id": row.anonymous_id,
            "label": row.label,
            "forward_to": row.forward_to,
        }


def mark_register_status(
    email: str,
    platform: str,
    status: str,
    account_id: str = "",
) -> bool:
    """注册结束后回写状态。status 取 "已注册" / "未注册" / "进行中" / "失败"。
    """
    fields = PLATFORM_STATUS_FIELDS.get(platform)
    if not fields:
        return False
    status_col, account_id_col = fields

    with Session(engine) as session:
        row = session.exec(
            select(IcloudHmeAliasModel).where(IcloudHmeAliasModel.email == email)
        ).first()
        if not row:
            return False
        setattr(row, status_col, status)
        if account_id:
            setattr(row, account_id_col, account_id)
        row.updated_at = _utcnow()
        if status == "已注册":
            row.last_used = _utcnow()
        session.add(row)
        session.commit()
        return True


def release_alias(email: str, platform: str) -> bool:
    """注册失败/中断时把 "进行中" 重置回 "未注册",让别人可以继续用。"""
    fields = PLATFORM_STATUS_FIELDS.get(platform)
    if not fields:
        return False
    status_col, _ = fields
    with Session(engine) as session:
        row = session.exec(
            select(IcloudHmeAliasModel).where(IcloudHmeAliasModel.email == email)
        ).first()
        if not row:
            return False
        current = getattr(row, status_col, "")
        if current == "进行中":
            setattr(row, status_col, "未注册")
            row.updated_at = _utcnow()
            session.add(row)
            session.commit()
        return True


# ── 查询 ────────────────────────────────────────────────────────────


def get_status_by_emails(emails: Iterable[str]) -> dict[str, dict]:
    """批量查若干 alias 的注册状态,返回 {email: {field: value, ...}}。
    给前端展示用。
    """
    emails = list(emails)
    if not emails:
        return {}
    with Session(engine) as session:
        rows = session.exec(
            select(IcloudHmeAliasModel).where(col(IcloudHmeAliasModel.email).in_(emails))
        ).all()
        out: dict[str, dict] = {}
        for r in rows:
            d = {
                "email": r.email,
                "anonymous_id": r.anonymous_id,
                "enabled": r.enabled,
                "is_active": r.is_active,
                "last_used": r.last_used.isoformat() if r.last_used else None,
            }
            for plat, (status_field, account_field) in PLATFORM_STATUS_FIELDS.items():
                d[status_field] = getattr(r, status_field, "未注册")
                d[account_field] = getattr(r, account_field, "")
            out[r.email] = d
        return out


def list_all_with_status(
    platform: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """列出 DB 里所有 alias + 状态,可选按 platform/status 过滤"""
    with Session(engine) as session:
        stmt = select(IcloudHmeAliasModel)
        if platform and status:
            field = PLATFORM_STATUS_FIELDS.get(platform)
            if field:
                stmt = stmt.where(getattr(IcloudHmeAliasModel, field[0]) == status)
        rows = session.exec(stmt.order_by(col(IcloudHmeAliasModel.email))).all()
        result = []
        for r in rows:
            d = {
                "id": r.id,
                "email": r.email,
                "anonymous_id": r.anonymous_id,
                "label": r.label,
                "forward_to": r.forward_to,
                "is_active": r.is_active,
                "enabled": r.enabled,
                "note": r.note,
                "last_used": r.last_used.isoformat() if r.last_used else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for plat, (status_field, account_field) in PLATFORM_STATUS_FIELDS.items():
                d[status_field] = getattr(r, status_field, "未注册")
                d[account_field] = getattr(r, account_field, "")
            result.append(d)
        return result
