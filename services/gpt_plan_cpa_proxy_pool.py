"""GPT 套餐管理专属 CPA 文件代理 IP 池。

职责(仅此一项): 给 GPT 套餐账号分配一个代理 IP, 把 proxy_url 写进生成的 CPA
凭证文件。**不做任何实际网络请求 / 浏览器代理 / 取码**, 纯数据标签。

规则:
- 导入格式: socks5://用户名:密码@IP:端口 (每行一个)。
- 1 个代理最多绑定 max_accounts(默认 3) 个账号。
- 账号绑定关系存在 GptPlanAccountModel.extra_json["cpa_proxy_id"]。
- 名额按"仍有效引用它的账号数"**动态计算**: 退款(refund_status 非空) / 危险封禁
  (dangerous=True) / 账号被删 的账号都不计入 → 名额自动释放, 无需事件挂钩。
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select

from core.db import engine, GptPlanCpaProxyModel, GptPlanAccountModel


# socks5://user:pass@host:port  (也放行 socks5h/http/https 前缀, 但默认按 socks5)
_PROXY_RE = re.compile(
    r"^(?P<scheme>socks5h?|https?)://"
    r"(?:(?P<user>[^:@/]+):(?P<pw>[^@/]+)@)?"
    r"(?P<host>[^:@/\s]+):(?P<port>\d{1,5})$",
    re.IGNORECASE,
)


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def normalize_proxy_line(line: str) -> Optional[str]:
    """校验并规范化一行代理; 不合法返回 None。"""
    s = (line or "").strip()
    if not s:
        return None
    m = _PROXY_RE.match(s)
    if not m:
        return None
    port = int(m.group("port"))
    if not (1 <= port <= 65535):
        return None
    return s


# ── 账号绑定 helper ─────────────────────────────────────────

def _acc_extra(acc: GptPlanAccountModel) -> Dict[str, Any]:
    try:
        return json.loads(acc.extra_json) if acc.extra_json else {}
    except Exception:
        return {}


def _is_active_binding(acc: GptPlanAccountModel) -> bool:
    """该账号是否仍"有效占用"代理名额: 未退款 且 未被标记危险。"""
    if getattr(acc, "dangerous", False):
        return False
    if str(getattr(acc, "refund_status", "") or "").strip():
        return False
    return True


def _usage_map(session: Session) -> Dict[int, int]:
    """proxy_id -> 有效占用数(排除退款/危险账号; 已删账号天然不在表里)。"""
    usage: Dict[int, int] = {}
    accounts = session.exec(select(GptPlanAccountModel)).all()
    for acc in accounts:
        pid = _acc_extra(acc).get("cpa_proxy_id")
        if not pid:
            continue
        if not _is_active_binding(acc):
            continue
        usage[int(pid)] = usage.get(int(pid), 0) + 1
    return usage


# ── 对外 API ─────────────────────────────────────────────────

def import_proxies(text: str) -> Dict[str, Any]:
    added, skipped_dup, invalid = 0, 0, 0
    seen_invalid: List[str] = []
    with Session(engine) as session:
        existing = {p.proxy_url for p in session.exec(select(GptPlanCpaProxyModel)).all()}
        batch_seen = set()
        for raw in (text or "").splitlines():
            norm = normalize_proxy_line(raw)
            if norm is None:
                if raw.strip():
                    invalid += 1
                    if len(seen_invalid) < 10:
                        seen_invalid.append(raw.strip()[:80])
                continue
            if norm in existing or norm in batch_seen:
                skipped_dup += 1
                continue
            batch_seen.add(norm)
            session.add(GptPlanCpaProxyModel(proxy_url=norm))
            added += 1
        session.commit()
    return {"added": added, "skipped_duplicate": skipped_dup, "invalid": invalid,
            "invalid_samples": seen_invalid}


def list_proxies() -> List[Dict[str, Any]]:
    with Session(engine) as session:
        proxies = session.exec(select(GptPlanCpaProxyModel)).all()
        usage = _usage_map(session)
        out = []
        for p in proxies:
            used = usage.get(int(p.id), 0)
            out.append({
                "id": p.id,
                "proxy_url": p.proxy_url,
                "max_accounts": p.max_accounts,
                "used": used,
                "available": max(0, p.max_accounts - used),
                "enabled": p.enabled,
                "note": p.note or "",
                "created_at": p.created_at.isoformat() if p.created_at else "",
            })
        # 可用名额多的排前面, 便于查看
        out.sort(key=lambda x: (-x["available"], x["id"]))
        return out


def stats() -> Dict[str, Any]:
    items = list_proxies()
    total = len(items)
    enabled = sum(1 for x in items if x["enabled"])
    capacity = sum(x["max_accounts"] for x in items if x["enabled"])
    used = sum(x["used"] for x in items)
    return {"total": total, "enabled": enabled, "capacity": capacity,
            "used": used, "available": max(0, capacity - used)}


def delete_proxy(proxy_id: int) -> bool:
    with Session(engine) as session:
        p = session.get(GptPlanCpaProxyModel, proxy_id)
        if not p:
            return False
        session.delete(p)
        session.commit()
        return True


def update_proxy(proxy_id: int, *, enabled: Optional[bool] = None,
                 note: Optional[str] = None, max_accounts: Optional[int] = None) -> bool:
    with Session(engine) as session:
        p = session.get(GptPlanCpaProxyModel, proxy_id)
        if not p:
            return False
        if enabled is not None:
            p.enabled = enabled
        if note is not None:
            p.note = note
        if max_accounts is not None:
            p.max_accounts = max(1, min(100, int(max_accounts)))
        p.updated_at = _utcnow()
        session.add(p)
        session.commit()
        return True


def get_account_proxy_url(account_id: int) -> str:
    """返回账号已绑定代理的 proxy_url; 未绑定 / 绑定的代理已删 → ""。不做分配。"""
    with Session(engine) as session:
        acc = session.get(GptPlanAccountModel, account_id)
        if not acc:
            return ""
        pid = _acc_extra(acc).get("cpa_proxy_id")
        if not pid:
            return ""
        p = session.get(GptPlanCpaProxyModel, int(pid))
        return p.proxy_url if p else ""


def assign_proxy(account_id: int) -> str:
    """给账号分配代理并返回 proxy_url(供写进 CPA 文件)。

    - 已绑定且代理仍存在 → 返回原代理(幂等)。
    - 未绑定 → 从池里挑一个 enabled 且名额<max 的代理(可用名额多者优先)绑定并返回。
    - 无可用代理 → 返回 ""(调用方不写 proxy_url)。
    """
    with Session(engine) as session:
        acc = session.get(GptPlanAccountModel, account_id)
        if not acc:
            return ""
        extra = _acc_extra(acc)
        pid = extra.get("cpa_proxy_id")
        if pid:
            p = session.get(GptPlanCpaProxyModel, int(pid))
            if p:
                return p.proxy_url
            # 绑定的代理已被删 → 清掉, 走重新分配
            extra.pop("cpa_proxy_id", None)

        usage = _usage_map(session)
        candidates = [
            p for p in session.exec(select(GptPlanCpaProxyModel)).all()
            if p.enabled and usage.get(int(p.id), 0) < p.max_accounts
        ]
        if not candidates:
            return ""
        # 可用名额多者优先, 均衡使用; 再按 id 稳定
        candidates.sort(key=lambda p: (-(p.max_accounts - usage.get(int(p.id), 0)), p.id))
        chosen = candidates[0]
        extra["cpa_proxy_id"] = int(chosen.id)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()
        return chosen.proxy_url


def release_account(account_id: int) -> bool:
    """手动解绑某账号的代理(清 cpa_proxy_id)。名额本就动态计算, 这里仅用于显式解绑。"""
    with Session(engine) as session:
        acc = session.get(GptPlanAccountModel, account_id)
        if not acc:
            return False
        extra = _acc_extra(acc)
        if "cpa_proxy_id" not in extra:
            return False
        extra.pop("cpa_proxy_id", None)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()
        return True
