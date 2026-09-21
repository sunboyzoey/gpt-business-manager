"""独立的 GPT PRO 账号池管理 API。

本模块只读写 ``gpt_pro_accounts`` 与
``gpt_pro_account_operation_leases``。GPT 套餐管理使用自己的账号表和
操作模块；两套界面之间不做账号同步、回查或双写。
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import re
import threading
import time
import uuid as _operation_uuid
from typing import Any, Callable, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete, update as sa_update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlmodel import Session, select, func, col

from core.db import (
    engine,
    GptBusinessAccountModel,
    GptBusinessAutomationPolicyModel,
    GptBusinessChildMembershipModel,
    GptProAccountModel,
    GptProAccountOperationLeaseModel,
    RoxyProxyModel,
    SyncDeviceModel,
)

router = APIRouter(prefix="/gpt-pro", tags=["gpt-pro"])
shared_upgrade_config_router = APIRouter(prefix="/gpt-pro", tags=["gpt-upgrade-config"])
MAX_FINISHED_IMPORT_TASKS = 20
GPT_PRO_OPERATION_LEASE_HOURS = 24
BUSINESS_ROTATION_OAUTH_LEASE_MINUTES = 30
# CPA upload currently has a 30-second transport timeout.  A stale sync intent
# must remain quarantined beyond that window before remote absence is accepted;
# otherwise an old POST can arrive immediately after a replacement POST.
CPA_SYNC_REMOTE_TIMEOUT_SECONDS = 30
CPA_SYNC_REMOTE_QUARANTINE_SECONDS = 60


def _utcnow():
    return datetime.now(timezone.utc)


def _extra_of(acc) -> dict:
    """安全解析账号 extra_json。"""
    try:
        return json.loads(acc.extra_json) if getattr(acc, "extra_json", None) else {}
    except Exception:
        return {}


def _mail_provider_of(acc) -> str:
    """账号的邮箱 provider；旧 PRO 表将它保存在 ``extra_json``。"""
    p = str((_extra_of(acc) or {}).get("mail_provider") or "outlook").strip().lower()
    return "icloud" if p in ("icloud", "qqmail") else "outlook"


def _iso_utc(value: Optional[datetime]) -> str:
    """带 UTC 标记的 ISO 字符串。

    库里存的是 naive UTC(_utcnow() 写入时丢了 tzinfo), 直接 isoformat() 出去没有
    时区后缀, 前端 new Date() 会按**本地时间**解析 → 界面时间比真实时刻差一个时区
    (北京 8 小时)。这里显式补上 +00:00, 前端才能正确换算成本地时间显示。
    """
    if not value:
        return ""
    dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_expires_at(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        raise HTTPException(400, f"无法解析过期时间: {value}")


# ── 请求 / 响应模型 ──────────────────────────────────────────

class GptProBatchImportRequest(BaseModel):
    data: str
    enabled: bool = True
    mark_pro: bool = True               # 导入时是否直接标记为 PRO


class GptProAccountUpdateRequest(BaseModel):
    password: Optional[str] = None
    client_id: Optional[str] = None
    refresh_token: Optional[str] = None
    mail_access_type: Optional[str] = None
    is_pro: Optional[bool] = None
    pro_expires_at: Optional[str] = None
    subscribed_at: Optional[str] = None    # 空字符串表示清空
    payment_card_last4: Optional[str] = None
    refund_status: Optional[str] = None    # "" / "refund_pending" / "refunded_pending_credit"
    note: Optional[str] = None
    enabled: Optional[bool] = None
    mail_provider: Optional[str] = None    # outlook / icloud (存 extra_json)


class GptProBatchDeleteRequest(BaseModel):
    ids: List[int]


class GptProBatchUpdateRequest(BaseModel):
    ids: List[int]
    is_pro: Optional[bool] = None
    pro_expires_at: Optional[str] = None  # 空字符串表示清空
    note: Optional[str] = None
    enabled: Optional[bool] = None


@dataclass
class GptProImportTaskRecord:
    id: str
    total: int
    status: str = "pending"
    progress: str = "0/0"
    processed: int = 0
    success: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "processed": self.processed,
            "success": self.success,
            "failed": self.failed,
            "errors": list(self.errors),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class GptProImportTaskStore:
    def __init__(self, *, max_finished_tasks: int = MAX_FINISHED_IMPORT_TASKS):
        self._lock = threading.Lock()
        self._records: Dict[str, GptProImportTaskRecord] = {}
        self.max_finished_tasks = max_finished_tasks

    def create(self, task_id: str, *, total: int) -> GptProImportTaskRecord:
        with self._lock:
            record = GptProImportTaskRecord(
                id=task_id,
                total=total,
                progress=f"0/{total}",
            )
            self._records[task_id] = record
            return record

    def exists(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._records

    def snapshot(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            return self._records[task_id].to_dict()

    def list_snapshots(self) -> list[Dict[str, Any]]:
        with self._lock:
            records = list(self._records.values())
            records.sort(key=lambda r: r.updated_at, reverse=True)
            return [r.to_dict() for r in records]

    def mark_running(self, task_id: str) -> None:
        with self._lock:
            r = self._records[task_id]
            r.status = "running"
            r.updated_at = time.time()

    def update(
        self,
        task_id: str,
        *,
        processed: Optional[int] = None,
        success: Optional[int] = None,
        failed: Optional[int] = None,
        append_error: Optional[str] = None,
    ) -> None:
        with self._lock:
            r = self._records[task_id]
            if processed is not None:
                r.processed = processed
                r.progress = f"{processed}/{r.total}"
            if success is not None:
                r.success = success
            if failed is not None:
                r.failed = failed
            if append_error:
                r.errors.append(append_error)
            r.updated_at = time.time()

    def finish(self, task_id: str, *, status: str = "done") -> None:
        with self._lock:
            r = self._records[task_id]
            r.status = status
            r.progress = f"{r.processed}/{r.total}"
            r.updated_at = time.time()
            self._cleanup_finished_locked()

    def fail(self, task_id: str, message: str) -> None:
        with self._lock:
            r = self._records[task_id]
            r.status = "failed"
            r.errors.append(message)
            r.updated_at = time.time()
            self._cleanup_finished_locked()

    def _cleanup_finished_locked(self) -> None:
        finished = [rid for rid, r in self._records.items() if r.status in {"done", "failed"}]
        overflow = len(finished) - self.max_finished_tasks
        if overflow <= 0:
            return
        finished.sort(key=lambda rid: self._records[rid].updated_at)
        for rid in finished[:overflow]:
            self._records.pop(rid, None)


_import_task_store = GptProImportTaskStore()


def _count_import_lines(data: str) -> int:
    total = 0
    for raw_line in (data or "").splitlines():
        line = str(raw_line or "").strip()
        if line and not line.startswith("#"):
            total += 1
    return total


def _ensure_import_task_exists(task_id: str) -> None:
    if not _import_task_store.exists(task_id):
        raise HTTPException(404, "导入任务不存在")


# ── 列表 & 统计 ──────────────────────────────────────────────

def _backfill_referral_remaining() -> None:
    """待重置次数兜底:referral_remaining 为空的账号(含老账号),
    按 3 - 已邀请邮箱数 回填(下限 0)。一次性、幂等(回填后不再为空)。"""
    try:
        with Session(engine) as s:
            rows = s.exec(
                select(GptProAccountModel).where(GptProAccountModel.referral_remaining.is_(None))  # type: ignore
            ).all()
            changed = 0
            for r in rows:
                try:
                    invited = json.loads(r.referral_invited_emails_json or "[]")
                    n = len(invited) if isinstance(invited, list) else 0
                except Exception:
                    n = 0
                r.referral_remaining = max(0, 3 - n)
                s.add(r)
                changed += 1
            if changed:
                s.commit()
    except Exception:
        pass


@router.get("/payment-account-summary")
def gpt_pro_payment_account_summary():
    """按支付账号统计:各支付账号付了多少个 PRO 账号(供列表筛选下拉 + 统计)。"""
    from collections import Counter
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel)).all()
    cnt: Counter = Counter()
    types: dict = {}
    unassigned = 0
    for r in rows:
        ex = _extra_of(r)
        name = ex.get("payment_account_name")
        if name:
            cnt[name] += 1
            types[name] = ex.get("payment_account_type")
        else:
            unassigned += 1
    items = [{"name": n, "type": types.get(n), "pro_count": c} for n, c in cnt.most_common()]
    return {"items": items, "unassigned": unassigned}


@router.get("/accounts")
def list_gpt_pro_accounts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    keyword: Optional[str] = Query(None),
    card_last4: Optional[str] = Query(None, description="按支付卡尾号模糊搜索"),
    payment_account: Optional[str] = Query(None, description="按支付账号名过滤(哪个支付账号付的)"),
    mail_access_type: Optional[str] = Query(None),
    mail_provider: Optional[str] = Query(None, description="邮箱类型: outlook / icloud"),
    is_pro: Optional[bool] = Query(None),
    enabled: Optional[bool] = Query(None),
    pro_status: Optional[str] = Query(
        None,
        description="PRO 订阅生命周期: subscribed/unsubscribed/expiring_soon/expired",
    ),
    view: Optional[str] = Query(
        None,
        description="主分类 Tab: pro (订阅中含已申请退款但未到账) / regular (未订阅) / refunded (已到账退款)",
    ),
    risk: Optional[str] = Query(
        None,
        description="风险筛选: dead (已停用/dangerous) / policy (用量政策违规&停用警告) / any (两者任一)",
    ),
):
    _backfill_referral_remaining()
    with Session(engine) as session:
        # 已成功分配给 BUSINESS 母号的普通账号由 BUSINESS 展开区管理，
        # 不再出现在 GPT PRO 的 PRO/普通/退款 Tab。
        query = select(GptProAccountModel).where(
            GptProAccountModel.business_parent_id.is_(None)  # type: ignore
        )
        if keyword:
            query = query.where(col(GptProAccountModel.email).contains(keyword))
        if card_last4:
            query = query.where(
                col(GptProAccountModel.payment_card_last4).contains(card_last4.strip())
            )
        if payment_account:
            query = query.where(
                func.json_extract(GptProAccountModel.extra_json, "$.payment_account_name")
                == payment_account.strip()
            )
        if mail_access_type is not None:
            query = query.where(GptProAccountModel.mail_access_type == mail_access_type)
        if mail_provider is not None:
            mp = str(mail_provider or "").strip().lower()
            prov_expr = func.lower(
                func.coalesce(
                    func.json_extract(GptProAccountModel.extra_json, "$.mail_provider"),
                    "outlook",
                )
            )
            if mp in ("icloud", "qqmail"):
                query = query.where(prov_expr == "icloud")
            elif mp == "outlook":
                query = query.where(prov_expr != "icloud")
        if is_pro is not None:
            query = query.where(GptProAccountModel.is_pro == is_pro)
        if enabled is not None:
            query = query.where(GptProAccountModel.enabled == enabled)
        # view: 3 类主 Tab 过滤 (跟前端 Tab 一一对应)
        # 已到账 (refund_credited) = 终态, 默认 3 个 Tab 都不显示
        if view == "pro":
            query = query.where(GptProAccountModel.is_pro == True)  # noqa: E712
            # PRO Tab 排除"已退款 未到账"和"已到账" (它们有专属 Tab / 已归档)
            query = query.where(
                GptProAccountModel.refund_status.not_in(  # type: ignore
                    ("refunded_pending_credit", "refund_credited"),
                )
            )
        elif view == "regular":
            query = query.where(GptProAccountModel.is_pro == False)  # noqa: E712
            # "普通账号" Tab 也排除"已退款 未到账"和"已到账" (跟 PRO Tab 同款,
            # 它们已在专属 Tab "refunded_pending_credit" / 归档里, 不该重复出现)
            query = query.where(
                GptProAccountModel.refund_status.not_in(  # type: ignore
                    ("refunded_pending_credit", "refund_credited"),
                )
            )
        elif view == "refunded_pending_credit":
            query = query.where(
                GptProAccountModel.refund_status == "refunded_pending_credit",
            )
        elif view:
            raise HTTPException(
                400,
                f"view 不支持的值: {view} "
                f"(应为 pro/regular/refunded_pending_credit)",
            )
        # risk: 风险筛选 (dead=停用 / policy=政策告警 / any=两者任一)
        if risk == "dead":
            query = query.where(GptProAccountModel.dangerous == True)  # noqa: E712
        elif risk == "policy":
            query = query.where(GptProAccountModel.policy_warning == True)  # noqa: E712
        elif risk == "any":
            from sqlalchemy import or_ as _or
            query = query.where(_or(
                GptProAccountModel.dangerous == True,        # noqa: E712
                GptProAccountModel.policy_warning == True,   # noqa: E712
            ))
        elif risk:
            raise HTTPException(400, f"risk 不支持的值: {risk} (应为 dead/policy/any)")
        # pro_status: 4 类 PRO 生命周期状态过滤
        # subscribed     = is_pro=True (含无到期 / 未过期 / 即将过期, 即所有 PRO)
        # unsubscribed   = is_pro=False
        # expiring_soon  = is_pro=True AND 7 天内到期
        # expired        = is_pro=True AND 已过期
        if pro_status:
            from datetime import timedelta
            now = _utcnow()
            if pro_status == "subscribed":
                query = query.where(GptProAccountModel.is_pro == True)  # noqa: E712
            elif pro_status == "unsubscribed":
                query = query.where(GptProAccountModel.is_pro == False)  # noqa: E712
            elif pro_status == "expiring_soon":
                window = now + timedelta(days=7)
                query = (
                    query.where(GptProAccountModel.is_pro == True)  # noqa: E712
                    .where(GptProAccountModel.pro_expires_at.is_not(None))  # type: ignore
                    .where(GptProAccountModel.pro_expires_at >= now)
                    .where(GptProAccountModel.pro_expires_at <= window)
                )
            elif pro_status == "expired":
                query = (
                    query.where(GptProAccountModel.is_pro == True)  # noqa: E712
                    .where(GptProAccountModel.pro_expires_at.is_not(None))  # type: ignore
                    .where(GptProAccountModel.pro_expires_at < now)
                )
            else:
                raise HTTPException(
                    400,
                    f"pro_status 不支持的值: {pro_status} "
                    f"(应为 subscribed/unsubscribed/expiring_soon/expired)",
                )

        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        # 排序:
        #   PRO Tab          → 订阅日期升序 (早的在前) + NULL 排最后
        #   已退款 未到账 Tab → 退款检测时间倒序 (最近退款的在上) + NULL 排最后
        #   其他 view        → id desc (新增的在上)
        if view == "pro":
            items_query = query.order_by(
                col(GptProAccountModel.subscribed_at).is_(None),  # NULL → True (1) 排后
                col(GptProAccountModel.subscribed_at).asc(),
                col(GptProAccountModel.id).asc(),
            )
        elif view == "refunded_pending_credit":
            items_query = query.order_by(
                col(GptProAccountModel.refund_detected_at).is_(None),  # NULL 排后
                col(GptProAccountModel.refund_detected_at).desc(),
                col(GptProAccountModel.id).desc(),
            )
        else:
            items_query = query.order_by(col(GptProAccountModel.id).desc())
        items_query = items_query.offset((page - 1) * page_size).limit(page_size)
        items = session.exec(items_query).all()
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": [_serialize(acc) for acc in items],
        }


@router.get("/accounts/stats")
def gpt_pro_stats():
    with Session(engine) as session:
        visible = GptProAccountModel.business_parent_id.is_(None)  # type: ignore
        total = session.exec(
            select(func.count()).select_from(GptProAccountModel).where(visible)
        ).one()
        enabled_count = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.enabled == True)
        ).one()
        pro_count = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.is_pro == True)
        ).one()
        graph_count = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.mail_access_type == "graph")
        ).one()
        imap_pop_count = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.mail_access_type == "imap_pop")
        ).one()

        from datetime import timedelta
        now = _utcnow()
        window = now + timedelta(days=7)
        expiring_soon = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.is_pro == True)
            .where(GptProAccountModel.pro_expires_at.is_not(None))  # type: ignore
            .where(GptProAccountModel.pro_expires_at >= now)
            .where(GptProAccountModel.pro_expires_at <= window)
        ).one()
        expired = session.exec(
            select(func.count()).select_from(GptProAccountModel)
            .where(visible)
            .where(GptProAccountModel.is_pro == True)
            .where(GptProAccountModel.pro_expires_at.is_not(None))  # type: ignore
            .where(GptProAccountModel.pro_expires_at < now)
        ).one()

        return {
            "total": total,
            "enabled": enabled_count,
            "disabled": total - enabled_count,
            "pro": pro_count,
            "non_pro": total - pro_count,
            "mail_access_type": {
                "graph": graph_count,
                "imap_pop": imap_pop_count,
                "unknown": total - graph_count - imap_pop_count,
            },
            "expiring_soon": expiring_soon,  # 7 天内到期
            "expired": expired,
        }


# ── 导出 ─────────────────────────────────────────────────────

@router.get("/accounts/export")
def export_gpt_pro_accounts(
    mail_access_type: Optional[str] = Query(None),
    is_pro: Optional[bool] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    with Session(engine) as session:
        query = select(GptProAccountModel).where(
            GptProAccountModel.business_parent_id.is_(None)  # type: ignore
        )
        if mail_access_type is not None:
            query = query.where(GptProAccountModel.mail_access_type == mail_access_type)
        if is_pro is not None:
            query = query.where(GptProAccountModel.is_pro == is_pro)
        if enabled is not None:
            query = query.where(GptProAccountModel.enabled == enabled)
        accounts = session.exec(query.order_by(col(GptProAccountModel.id))).all()

    lines = []
    for acc in accounts:
        parts = [acc.email, acc.password]
        if acc.refresh_token or acc.client_id:
            parts.extend([acc.refresh_token, acc.client_id, acc.mail_access_type or ""])
        lines.append("----".join(parts))
    return {"total": len(lines), "data": "\n".join(lines)}


# ── 单条操作 ─────────────────────────────────────────────────

def is_managed_business_child_account(acc: GptProAccountModel) -> bool:
    """账号是否当前归属 GPT BUSINESS 母号。

    这个判定函数不更改状态，可供 CPA、邮件监控以及 BUSINESS
    子号代理接口共用。
    """
    return getattr(acc, "business_parent_id", None) is not None


def _ensure_not_managed_business_child(acc: GptProAccountModel) -> None:
    """已挂到 BUSINESS 母号的行只能先从对应工作区移除/撤邀后再改动。"""
    parent_id = getattr(acc, "business_parent_id", None)
    if is_managed_business_child_account(acc):
        raise HTTPException(
            409,
            f"账号已归属 GPT BUSINESS 母号 {parent_id}，请先在该母号下移除或撤销邀请",
        )


def _aware_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _claim_gpt_pro_account_operation(
    account_id: int,
    operation: str,
    *,
    token: str = "",
    ttl_hours: int = GPT_PRO_OPERATION_LEASE_HOURS,
    allow_managed_business_child: bool = False,
) -> str:
    """为不可并行的远端账号动作取得持久租约。

    BUSINESS 分配也使用同一张表，所以退款/升级和邀请之间不再只依赖某个
    Python 进程里的锁。过期行可回收；有效行会明确返回 409。
    """
    lease_token = str(token or _operation_uuid.uuid4().hex)
    now = _utcnow()
    expires_at = now + timedelta(hours=max(1, int(ttl_hours or 1)))
    try:
        with Session(engine) as session:
            is_sqlite = session.get_bind().dialect.name == "sqlite"
            if is_sqlite:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            acc = session.get(GptProAccountModel, int(account_id))
            if not acc:
                raise HTTPException(404, "账号不存在")
            if not allow_managed_business_child:
                _ensure_not_managed_business_child(acc)
            if is_sqlite:
                current = session.get(
                    GptProAccountOperationLeaseModel,
                    int(account_id),
                )
            else:
                current = session.exec(
                    select(GptProAccountOperationLeaseModel)
                    .where(GptProAccountOperationLeaseModel.account_id == int(account_id))
                    .with_for_update()
                ).first()
            if current and (_aware_utc(current.expires_at) or now) <= now:
                session.delete(current)
                session.flush()
                current = None
            if current:
                if current.token == lease_token and current.operation == operation:
                    current.expires_at = expires_at
                    current.updated_at = now
                    session.add(current)
                    session.commit()
                    return lease_token
                raise HTTPException(
                    409,
                    {
                        "code": "gpt_pro_account_busy",
                        "message": f"账号正在执行 {current.operation}，暂不能执行 {operation}",
                        "operation": current.operation,
                        "expires_at": _iso_utc(current.expires_at),
                    },
                )
            session.add(GptProAccountOperationLeaseModel(
                account_id=int(account_id),
                operation=str(operation or "account_operation"),
                token=lease_token,
                expires_at=expires_at,
                created_at=now,
                updated_at=now,
            ))
            session.commit()
    except IntegrityError as exc:
        raise HTTPException(
            409,
            {
                "code": "gpt_pro_account_busy",
                "message": "账号刚被其他流程占用，请稍后重试",
            },
        ) from exc
    return lease_token


def _release_gpt_pro_account_operation(account_id: int, token: str) -> None:
    """只释放自己持有的账号租约；旧任务不能误删新任务的租约。"""
    if not token:
        return
    with Session(engine) as session:
        session.execute(
            sa_delete(GptProAccountOperationLeaseModel)
            .where(GptProAccountOperationLeaseModel.account_id == int(account_id))
            .where(GptProAccountOperationLeaseModel.token == token)
        )
        session.commit()


def _gpt_pro_account_operation_is_current(
    session: Session,
    account_id: int,
    token: str,
    operation: str,
) -> bool:
    current = session.get(GptProAccountOperationLeaseModel, int(account_id))
    return bool(
        current
        and current.token == token
        and current.operation == operation
        and (_aware_utc(current.expires_at) or _utcnow()) > _utcnow()
    )


def _gpt_pro_account_operation_token_is_current(
    account_id: int,
    token: str,
) -> bool:
    """校验任意同表操作租约的 owner token，不要求 operation 名相同。"""
    if not token:
        return False
    with Session(engine) as session:
        current = session.get(GptProAccountOperationLeaseModel, int(account_id))
        return bool(
            current
            and current.token == token
            and (_aware_utc(current.expires_at) or _utcnow()) > _utcnow()
        )

@router.get("/accounts/{account_id}")
def get_gpt_pro_account(account_id: int):
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        return _serialize(acc)


@router.put("/accounts/{account_id}")
def update_gpt_pro_account(account_id: int, body: GptProAccountUpdateRequest):
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        _ensure_not_managed_business_child(acc)
        for field_name in (
            "password", "client_id", "refresh_token", "mail_access_type",
            "is_pro", "note", "enabled", "payment_card_last4",
        ):
            value = getattr(body, field_name, None)
            if value is not None:
                setattr(acc, field_name, value)
        # refund_status 单独处理: 翻 refund_credited 时自动写 refund_credited_at
        if body.refund_status is not None:
            new_status = str(body.refund_status or "").strip()
            if new_status == "refund_credited" and acc.refund_status != "refund_credited":
                acc.refund_credited_at = _utcnow()
            acc.refund_status = new_status
        if body.pro_expires_at is not None:
            acc.pro_expires_at = _parse_expires_at(body.pro_expires_at) if body.pro_expires_at else None
        if body.subscribed_at is not None:
            acc.subscribed_at = _parse_expires_at(body.subscribed_at) if body.subscribed_at else None
        if body.mail_provider is not None:
            p = str(body.mail_provider or "").strip().lower()
            p = "icloud" if p in ("icloud", "qqmail") else "outlook"
            try:
                extra = json.loads(acc.extra_json) if acc.extra_json else {}
            except Exception:
                extra = {}
            extra["mail_provider"] = p
            acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()
        session.refresh(acc)
        return _serialize(acc)


def _apply_refunded_to_pro_migration(acc, migrated_at: Optional[datetime] = None) -> datetime:
    """把“已退款未到账”记录原子迁回 PRO 视图，并刷新本次升级时间。"""
    if str(getattr(acc, "refund_status", "") or "").strip() != "refunded_pending_credit":
        raise ValueError("仅“已退款未到账”账号可以迁移到 GPT PRO")
    now = migrated_at or _utcnow()
    acc.refund_status = ""
    acc.is_pro = True
    acc.subscribed_at = now
    acc.updated_at = now
    return now


@router.post("/accounts/{account_id}/migrate-to-pro")
def migrate_refunded_account_to_pro(account_id: int):
    """已退款未到账 → PRO：清退款状态、标记 PRO、升级时间写服务端当前时间。"""
    operation_token = _claim_gpt_pro_account_operation(
        account_id,
        "migrate_refunded_to_pro",
    )
    try:
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            if not acc:
                raise HTTPException(404, "账号不存在")
            if not _gpt_pro_account_operation_is_current(
                session,
                account_id,
                operation_token,
                "migrate_refunded_to_pro",
            ):
                raise HTTPException(409, "迁移操作租约已失效，请重试")
            try:
                migrated_at = _apply_refunded_to_pro_migration(acc)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
            session.add(acc)
            session.commit()
            session.refresh(acc)
            return {
                "ok": True,
                "id": acc.id,
                "email": acc.email,
                "is_pro": bool(acc.is_pro),
                "refund_status": acc.refund_status or "",
                "subscribed_at": _iso_utc(migrated_at),
            }
    finally:
        _release_gpt_pro_account_operation(account_id, operation_token)


@router.delete("/accounts/{account_id}")
def delete_gpt_pro_account(account_id: int):
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        _ensure_not_managed_business_child(acc)
        session.delete(acc)
        session.commit()
        return {"ok": True}


@router.post("/accounts/{account_id}/convert-to-business")
def convert_to_business(account_id: int):
    """把该 PRO 账号迁移到 GPT BUSINESS 池:复制账号(邮箱/密码/OAuth/Codex/邮件监控状态等)
    到 gpt_business_accounts,再删除本 PRO 记录。目标已存在同邮箱则拒绝。"""
    from core.db import GptBusinessAccountModel
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        _ensure_not_managed_business_child(acc)
        email = acc.email
        exists = session.exec(
            select(GptBusinessAccountModel).where(GptBusinessAccountModel.email == email)
        ).first()
        if exists:
            raise HTTPException(409, f"GPT BUSINESS 已存在同邮箱账号: {email}(未迁移)")
        biz = GptBusinessAccountModel(
            email=acc.email,
            password=acc.password or "",
            client_id=acc.client_id or "",
            refresh_token=acc.refresh_token or "",
            mail_access_type=acc.mail_access_type or "",
            dangerous=bool(acc.dangerous),
            dangerous_detected_at=acc.dangerous_detected_at,
            policy_warning=bool(acc.policy_warning),
            policy_warning_detected_at=acc.policy_warning_detected_at,
            codex_access_token=acc.codex_access_token or "",
            codex_refresh_token=acc.codex_refresh_token or "",
            codex_id_token=acc.codex_id_token or "",
            codex_session_token=acc.codex_session_token or "",
            codex_rt_acquired_at=acc.codex_rt_acquired_at,
            note=acc.note or "",
            extra_json=acc.extra_json or "{}",
            business_upgraded_at=_utcnow(),
            seen_mail_ids_json=acc.seen_mail_ids_json or "[]",
            pending_alerts_json=acc.pending_alerts_json or "[]",
            pending_inbox_json=acc.pending_inbox_json or "[]",
            enabled=bool(acc.enabled),
        )
        session.add(biz)
        session.delete(acc)
        session.commit()
        session.refresh(biz)
        return {"ok": True, "business_id": biz.id, "email": email}


class GptProBusinessLinkRequest(BaseModel):
    workspace_name: str
    coupon: str = ""
    seat_quantity: int = 2
    seat_type: Literal["default", "prolite"] = "default"
    country: str = "US"
    currency: str = "USD"
    auto_fill: bool = True             # 生成链接后, 导航到付款页并自动填卡(留窗人工付款)
    auto_submit: bool = False          # 自动填完点「订阅/付款」提交(真实扣款! 默认不点, 留人工)
    checkout_card: Optional[str] = None  # 手动指定卡文本(有则用它, 否则取卡池第一张)
    proxy: Optional[str] = None
    headless: bool = False
    browser_backend: str = "local"
    roxy_proxy_id: Optional[int] = None


@router.post("/accounts/{account_id}/business-checkout-link")
def business_checkout_link(account_id: int, body: GptProBusinessLinkRequest):
    """登录该账号 → 建 ChatGPT Team(BUSINESS)hosted checkout → 返回 Stripe 支付长链接。
    auto_fill=True: 顺带把浏览器导航到付款页并**自动填卡**(卡池第一张 / 手动卡),留窗人工核对付款。
    该付款页(pay.openai.com)与 PRO 内嵌 checkout 不同, 用独立填卡逻辑, 不影响 PRO。"""
    from platforms.chatgpt.gpt_pro_login import (
        _build_team_checkout_js, _fill_stripe_hosted_checkout,
        _fetch_local_bank_cards, _build_direct_card)

    ws = (body.workspace_name or "").strip()
    if not ws:
        raise HTTPException(400, "请填写空间名称(workspace_name)")
    coupon = (body.coupon or "").strip()
    seat_type = str(body.seat_type or "default").strip().lower()
    if seat_type not in {"default", "prolite"}:
        raise HTTPException(400, "seat_type 必须是 default 或 prolite")
    seats = 2 if seat_type == "prolite" else max(2, int(body.seat_quantity or 2))
    auto_fill = bool(body.auto_fill)
    auto_submit = bool(getattr(body, "auto_submit", False))
    direct_card = _parse_card_text(getattr(body, "checkout_card", "") or "")

    with Session(engine) as session:
        _acc0 = session.get(GptProAccountModel, account_id)
        acct_email = _acc0.email if _acc0 else ""

    captured: dict = {}

    def _action(page, login_result):
        captured["page"] = page
        _lf = getattr(login_result, "_log_fn", None) or (lambda m: print(m, flush=True))
        js = _build_team_checkout_js(
            ws, coupon, seats, body.country, body.currency, seat_type=seat_type)
        try:
            res = page.run_js(js) or {}
        except Exception as exc:
            return {"ok": False, "error": f"checkout JS 执行异常: {exc}"}
        if not res.get("ok"):
            return res
        url = str(res.get("url") or "")
        if auto_fill and url:
            _lf(f"[Team付款] 导航到付款页并自动填卡: {url[:80]}...")
            try:
                page.get(url, timeout=60)      # 秒; 之前误用了本模块没有的 _NAV_TIMEOUT
                time.sleep(1)
            except Exception as exc:
                res["fill"] = {"ok": False, "error": f"导航付款页失败: {exc}"}
                return res
            card = _build_direct_card(direct_card) if direct_card else None
            if card is None:
                cards = _fetch_local_bank_cards(_lf)
                card = cards[0] if cards else None
            if card:
                res["fill"] = _fill_stripe_hosted_checkout(
                    page, card, log_fn=_lf, email=acct_email, auto_submit=auto_submit)
                res["filled_card"] = card.get("number_masked") or ""
            else:
                res["fill"] = {"ok": False, "error": "本地卡池为空, 未自动填卡(链接仍可用)"}
        return res

    login_body = GptProActionRequest(
        proxy=body.proxy, headless=bool(body.headless),
        browser_backend=body.browser_backend, roxy_proxy_id=body.roxy_proxy_id,
        # auto_fill 时留窗(填好的付款页交人工核对付款); 否则拿链接即关
        keep_browser_open=auto_fill,
    )
    login_result = _run_drission_login(account_id, login_body, is_signup=False, post_login_action=_action)

    res = login_result.get("action_result") or {}
    ok_checkout = bool(res.get("ok"))
    # 不 auto_fill 时关掉浏览器; auto_fill 成功则留窗
    page = captured.get("page")
    if page is not None and (not auto_fill or not ok_checkout):
        try:
            page.quit()
        except Exception:
            pass

    if not login_result.get("ok"):
        return {"ok": False, "stage": "login_failed",
                "error": (login_result.get("error") or "登录失败"), "login": login_result}
    if not ok_checkout:
        return {"ok": False, "stage": "checkout_failed",
                "error": res.get("error") or "生成支付链接失败", "detail": res}
    return {
        "ok": True, "url": res.get("url"),
        "checkout_session_id": res.get("checkout_session_id") or "",
        "auto_fill": auto_fill,
        "fill": res.get("fill"),
        "filled_card": res.get("filled_card") or "",
        "workspace_name": ws, "seat_quantity": seats, "seat_type": seat_type,
        "country": (body.country or "US").upper(), "currency": (body.currency or "USD").upper(),
        "coupon": coupon,
    }


# ── iCloud / QQ 配置 + 导入 (所有配置都在 GPT PRO 界面完成) ─────────────

# GPT PRO 界面管理的 iCloud/QQ 配置键(存 config_store, 与全局 Settings 同一份)
_ICLOUD_CONFIG_KEYS = (
    "qqmail_user", "qqmail_auth_code", "qqmail_imap_host", "qqmail_imap_port",
    "qqmail_pool_file", "qqmail_require_apple_header",
    "icloud_hme_base_url", "icloud_hme_api_key", "icloud_hme_pool_file",
)
_ICLOUD_SECRET_KEYS = {"qqmail_auth_code", "icloud_hme_api_key"}


class IcloudConfigUpdate(BaseModel):
    values: Dict[str, str]


class IcloudPasteImport(BaseModel):
    data: str                       # 每行: 别名 或 别名----ChatGPT密码
    enabled: bool = True


@router.get("/icloud-config")
def get_icloud_config():
    """读 GPT PRO 界面用的 iCloud/QQ 配置(secret 只回显是否已设置)。"""
    from core.config_store import config_store as _cs
    out: Dict[str, Any] = {}
    for k in _ICLOUD_CONFIG_KEYS:
        v = str(_cs.get(k, "") or "")
        if k in _ICLOUD_SECRET_KEYS:
            out[k] = ""            # 不回显明文
            out[k + "_set"] = bool(v)
        else:
            out[k] = v
    return out


@router.put("/icloud-config")
def put_icloud_config(body: IcloudConfigUpdate):
    """写 iCloud/QQ 配置。secret 传空字符串 = 不改(保留原值)。"""
    from core.config_store import config_store as _cs
    for k, v in (body.values or {}).items():
        if k not in _ICLOUD_CONFIG_KEYS:
            continue
        if k in _ICLOUD_SECRET_KEYS and str(v or "") == "":
            continue               # 空 secret 视为不修改
        _cs.set(k, str(v if v is not None else ""))
    return {"ok": True}


def _create_icloud_account(session, email: str, password: str = "") -> str:
    """建一个 mail_provider=icloud 的 GPT PRO 账号; 已存在则跳过。返回 'created'/'exists'/'skip'。"""
    email = str(email or "").strip()
    if not email or "@" not in email:
        return "skip"
    exist = session.exec(
        select(GptProAccountModel).where(GptProAccountModel.email == email)
    ).first()
    if exist:
        return "exists"
    acc = GptProAccountModel(
        email=email,
        password=str(password or ""),
        mail_provider="icloud",
        extra_json=json.dumps({"mail_provider": "icloud"}, ensure_ascii=False),
    )
    session.add(acc)
    return "created"


@router.post("/icloud/import-from-hme")
def import_icloud_from_hme():
    """从 iCloud HME 别名池(Go 服务)同步别名, 建成 mail_provider=icloud 的 GPT PRO 账号。"""
    from services.icloud_hme_tracker import sync_from_remote
    try:
        sync_res = sync_from_remote()
    except Exception as exc:
        raise HTTPException(400, f"同步 HME 别名失败: {exc}")
    from core.db import IcloudHmeAliasModel
    created = exists = skipped = 0
    with Session(engine) as session:
        rows = session.exec(select(IcloudHmeAliasModel)).all()
        for r in rows:
            if not getattr(r, "is_active", True):
                skipped += 1
                continue
            res = _create_icloud_account(session, r.email)
            created += res == "created"
            exists += res == "exists"
            skipped += res == "skip"
        session.commit()
    return {"ok": True, "synced": sync_res.get("synced", 0),
            "created": created, "exists": exists, "skipped": skipped}


@router.post("/icloud/import")
def import_icloud_paste(body: IcloudPasteImport):
    """手动粘贴导入 iCloud 账号。每行: 别名  或  别名----ChatGPT密码。"""
    created = exists = skipped = 0
    with Session(engine) as session:
        for raw in (body.data or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split("----")
            email = parts[0].strip()
            password = parts[1].strip() if len(parts) > 1 else ""
            res = _create_icloud_account(session, email, password)
            created += res == "created"
            exists += res == "exists"
            skipped += res == "skip"
        session.commit()
    return {"ok": True, "created": created, "exists": exists, "skipped": skipped}


# ── Codex 推荐邀请(「重置」)─────────────────────────────────
# 每个 PRO 账号都有自己的 codex_refresh_token,先用它刷出新的 access_token,
# 再从 access_token (JWT) 解码出 chatgpt_account_id,调 codex 推荐 API。

class GptProReferralInviteRequest(BaseModel):
    email: str


def _rt_dead_error(msg: str) -> bool:
    """判断刷新错误是否=「RT 真的失效」(需要重新 OAuth),而非瞬时网络/TLS 错误。"""
    m = (msg or "").lower()
    return any(k in m for k in (
        "invalid_grant", "refresh_token_reused", "reused", "已被使用",
        # 会话被服务端终止(退款/登出/改密/风控)→ RT 被吊销, 需重新 OAuth 登录
        "refresh_token_invalidated", "invalidated", "session has ended",
        "sign in again", "log in again", "请重新登录", "重新登录",
    ))


def _reacquire_parent_codex_rt(acc: GptProAccountModel, log=None) -> bool:
    """母号 codex RT 失效时,重新跑 OAuth login 拿新 codex RT,落库。返回是否成功。

    - Outlook 母号: 需要密码(OpenAI 路由到密码页才能登录);
    - iCloud 母号: 登录走**邮箱 OTP**(验证码从 QQ 读, 见 build_mailbox_for_account),
      **不需要密码** —— 所以 iCloud 号无密码也放行。
    """
    _log = log or (lambda m: None)
    _provider = _mail_provider_of(acc)
    if _provider != "icloud" and not (acc.password or "").strip():
        _log("✗ 母号无密码,无法自动重新 OAuth 拿 RT(请人工重置该母号 RT)")
        return False
    from platforms.chatgpt.plugin import ChatGPTPlatform
    from core.base_platform import RegisterConfig, Account, AccountStatus
    from core.config_store import config_store as _cs
    proxy = _gpt_pro_codex_proxy()
    _log(f"🔁 母号 RT 已失效,用 {acc.email} + 密码重新 OAuth 拿新 RT…")
    try:
        platform = ChatGPTPlatform(
            config=RegisterConfig(executor_type="protocol", proxy=proxy, extra=_cs.get_all()),
        )
        try:
            platform._log_fn = _log
        except Exception:
            pass
        account_obj = Account(
            platform="chatgpt", email=acc.email, password=acc.password,
            user_id=getattr(acc, "user_id", "") or "", token="",
            status=AccountStatus.REGISTERED, extra={},
        )
        # 母号是 outlook:OTP 进的是 outlook 自己的收件箱(不是 CF Worker)。
        # 复用单账号 OAuth 同款的 outlook 收件箱适配器,否则补 RT 会一直等 CF Worker 而超时。
        params = {"browser_mode": "headless", "_log_fn": _log}
        try:
            from platforms.chatgpt.gpt_pro_login import (
                build_mailbox_for_account, GptProEmailAdapterForCodexOAuth,
            )
            _prov = _mail_provider_of(acc)
            snapshot = {
                "email": acc.email, "password": acc.password or "",
                "client_id": acc.client_id or "", "refresh_token": acc.refresh_token or "",
                "mail_access_type": acc.mail_access_type or "",
                "mail_provider": _prov,
            }
            mailbox, mb_account = build_mailbox_for_account(snapshot, proxy=proxy)
            params["_otp_email_adapter"] = GptProEmailAdapterForCodexOAuth(mailbox, mb_account, log_fn=_log)
            _log(f"[补 RT] 已挂载 {'iCloud/QQ' if _prov == 'icloud' else 'outlook'} 收件箱 OTP 适配器(从账号邮箱读验证码)")
        except Exception as exc:
            _log(f"[补 RT] outlook OTP 适配器构造失败(回退 CF Worker): {exc}")
        res = platform._action_acquire_rt(account_obj, params, proxy)
    except Exception as e:
        _log(f"✗ 母号重新 OAuth 异常: {e}")
        return False
    if not res.get("ok"):
        _log(f"✗ 母号重新 OAuth 失败: {res.get('error')}")
        return False
    patch = res.get("account_extra_patch") or res.get("data") or {}
    new_rt = str(patch.get("refresh_token") or "").strip()
    new_at = str(patch.get("access_token") or "").strip()
    new_id = str(patch.get("id_token") or "").strip()   # ← 之前漏存, 导致同步 Codex App 缺 id_token
    if not new_rt:
        _log("✗ 母号重新 OAuth 完成但未拿到 refresh_token")
        return False
    with Session(engine) as s:
        row = s.get(GptProAccountModel, acc.id)
        if row:
            row.codex_refresh_token = new_rt
            if new_at:
                row.codex_access_token = new_at
            if new_id:
                row.codex_id_token = new_id
            row.updated_at = _utcnow()
            s.add(row)
            s.commit()
    _log(f"✓ 母号已重新拿到 codex RT (len={len(new_rt)}, id_token len={len(new_id)}),已落库,继续操作")
    return True


def _gpt_pro_resolve_codex_credentials(acc: GptProAccountModel, log=None,
                                       _allow_reauth: bool = True,
                                       _require_persist: bool = False) -> tuple[str, str]:
    """返回 (fresh access_token, chatgpt_account_id)。失败抛 HTTPException。

    每次调用都用 codex_refresh_token 刷一遍 → 避免维护过期状态。
    RT 真失效(invalid_grant/refresh_token_reused)时,自动用母号邮箱+密码重新 OAuth 拿新 RT 再刷。
    ``_require_persist`` 用于即将上传到外部设备的路径：AT/轮换 RT
    未成功落库时 fail closed，保证外部文件不会携带半旧凭证组合。
    """
    from platforms.chatgpt.token_refresh import TokenRefreshManager
    from platforms.chatgpt.utils import decode_jwt_payload

    if not (acc.codex_refresh_token or "").strip():
        raise HTTPException(400, "该账号没有 codex_refresh_token,无法调用推荐接口")

    from core.config_store import config_store as _cs
    proxy = (str(_cs.get("default_proxy", "") or "").strip()
             or str(_cs.get("proxy", "") or "").strip()
             or None)

    mgr = TokenRefreshManager(proxy_url=proxy)
    result = mgr.refresh_by_oauth_token(acc.codex_refresh_token)
    if not result.success or not result.access_token:
        err = result.error_message or "未知错误"
        # RT 真死 → 用母号邮箱+密码重新 OAuth 拿新 RT,再刷一次(只重试一轮防死循环)
        if _allow_reauth and _rt_dead_error(err):
            if _reacquire_parent_codex_rt(acc, log):
                with Session(engine) as s:
                    fresh = s.get(GptProAccountModel, acc.id)
                return _gpt_pro_resolve_codex_credentials(
                    fresh or acc,
                    log=log,
                    _allow_reauth=False,
                    _require_persist=_require_persist,
                )
            raise HTTPException(502, f"母号 RT 失效且自动重拿失败: {err}")
        raise HTTPException(502, f"刷新 access_token 失败: {err}")

    # 同步落盘新的 token(如果服务端轮换了 RT,也一并更新)
    try:
        with Session(engine) as s:
            row = s.get(GptProAccountModel, acc.id)
            if not row:
                raise RuntimeError("OAuth 凭证对应的账号已不存在")
            row.codex_access_token = result.access_token
            if result.refresh_token and result.refresh_token != row.codex_refresh_token:
                row.codex_refresh_token = result.refresh_token
            row.updated_at = _utcnow()
            s.add(row)
            s.commit()
    except Exception as exc:
        if _require_persist:
            # CPA 上传必须携带与刚刷新 AT 配套的最新 RT。若轮换结果没有
            # 原子落库，宁可在任何远端写入前中止，也不能上传一组半旧凭证。
            raise HTTPException(
                500,
                "OAuth 凭证已刷新但持久化失败，已中止 CPA 同步",
            ) from exc

    payload = decode_jwt_payload(result.access_token) or {}
    auth = payload.get("https://api.openai.com/auth") or {}
    chatgpt_account_id = str(auth.get("chatgpt_account_id") or "").strip()
    if not chatgpt_account_id:
        raise HTTPException(400, "无法从 access_token 解析 chatgpt_account_id")

    return result.access_token, chatgpt_account_id


def _codex_invite_with_refresh(acc: GptProAccountModel, emails: list, proxy,
                               log=None) -> tuple:
    """用母号 AT 调 Codex 邀请接口;若 AT 过期/被拒(401/403),自动用 RT 重刷一个 AT 再重试。

    返回 (status, data)。invite() 抛 CodexReferralError 时原样抛出由调用方处理。
    """
    from platforms.chatgpt.codex_referral import invite
    _log = log or (lambda m: None)
    status, data = None, None
    for attempt in range(1, 3):
        # _gpt_pro_resolve_codex_credentials 每次都用 RT 刷新 AT;重试前重读最新 acc(RT 可能已轮换)
        if attempt > 1:
            try:
                with Session(engine) as s:
                    fresh = s.get(GptProAccountModel, acc.id)
                    if fresh:
                        acc = fresh
            except Exception:
                pass
        access_token, chatgpt_account_id = _gpt_pro_resolve_codex_credentials(acc, log=_log)
        status, data = invite(emails=emails, token=access_token,
                              account_id=chatgpt_account_id, proxy=proxy)
        if status not in (401, 403):
            return status, data
        if attempt < 2:
            _log(f"⚠ 邀请接口返回 {status}(母号 AT 过期/被拒),用 RT 重刷 access_token 后重试…")
            time.sleep(2)
    return status, data


def _gpt_pro_codex_proxy() -> Optional[str]:
    from core.config_store import config_store as _cs
    proxy = (str(_cs.get("default_proxy", "") or "").strip()
             or str(_cs.get("proxy", "") or "").strip())
    return proxy or None


_REFERRAL_CF_DOMAIN_KEY = "gpt_pro_referral_cf_domain"               # 老:单值(兼容)
_REFERRAL_CF_DOMAINS_KEY = "gpt_pro_referral_cf_domains_json"        # 新:清单 JSON


def _load_cf_domains() -> List[str]:
    """加载 CF 邀请域名清单。兼容旧的单值 key:首次发现旧 key,自动迁移进清单。"""
    from core.config_store import config_store
    raw = str(config_store.get(_REFERRAL_CF_DOMAINS_KEY, "") or "").strip()
    domains: List[str] = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                domains = [str(x).strip().lower() for x in parsed if str(x or "").strip()]
        except Exception:
            domains = []
    # 兼容:老的单值 key 自动并入
    legacy = str(config_store.get(_REFERRAL_CF_DOMAIN_KEY, "") or "").strip().lower()
    if legacy and legacy not in domains:
        domains.insert(0, legacy)
        try:
            config_store.set(_REFERRAL_CF_DOMAINS_KEY, json.dumps(domains, ensure_ascii=False))
        except Exception:
            pass
    # 去重保留顺序
    seen: set[str] = set()
    deduped: List[str] = []
    for d in domains:
        d2 = d.strip().lower()
        if d2 and "." in d2 and d2 not in seen:
            seen.add(d2)
            deduped.append(d2)
    return deduped


def _save_cf_domains(domains: List[str]) -> List[str]:
    from core.config_store import config_store
    clean: List[str] = []
    seen: set[str] = set()
    for d in domains:
        v = str(d or "").strip().lower()
        if v and "." in v and v not in seen:
            seen.add(v)
            clean.append(v)
    config_store.set(_REFERRAL_CF_DOMAINS_KEY, json.dumps(clean, ensure_ascii=False))
    return clean


def _promote_cf_domain(domain: str) -> List[str]:
    """把 domain 提到清单最前(下次默认选它)。"""
    domain = str(domain or "").strip().lower()
    if not domain:
        return _load_cf_domains()
    domains = [d for d in _load_cf_domains() if d != domain]
    domains.insert(0, domain)
    return _save_cf_domains(domains)


def _append_referral_invited(account_id: int, email: str) -> List[str]:
    """把 email 追加到 referral_invited_emails_json,去重,按时间顺序保留。返回更新后的清单。"""
    email = (email or "").strip().lower()
    if not email:
        return []
    with Session(engine) as s:
        row = s.get(GptProAccountModel, account_id)
        if not row:
            return []
        try:
            lst = json.loads(row.referral_invited_emails_json or "[]")
            if not isinstance(lst, list):
                lst = []
        except Exception:
            lst = []
        lst = [str(x).strip().lower() for x in lst if str(x or "").strip()]
        if email not in lst:
            lst.append(email)
        row.referral_invited_emails_json = json.dumps(lst, ensure_ascii=False)
        row.updated_at = _utcnow()
        s.add(row)
        s.commit()
        return lst


def _mark_referral_confirmed(account_id: int, email: str) -> List[str]:
    """把 email 加入母号的 referral_confirmed_emails_json (= 已邀请邮箱列里打绿勾)。
    跟 /referral-confirm 端点同语义,供自动重置流程收到 reward 邮件后调用。"""
    email = (email or "").strip().lower()
    if not email:
        return []
    with Session(engine) as s:
        row = s.get(GptProAccountModel, account_id)
        if not row:
            return []
        try:
            lst = json.loads(row.referral_confirmed_emails_json or "[]")
            if not isinstance(lst, list):
                lst = []
        except Exception:
            lst = []
        lst = [str(x).strip().lower() for x in lst if str(x or "").strip()]
        newly_added = email not in lst
        if newly_added:
            lst.append(email)
        row.referral_confirmed_emails_json = json.dumps(lst, ensure_ascii=False)
        row.updated_at = _utcnow()
        s.add(row)
        s.commit()
    # 奖励真的到手(被邀请号发 hi 成功 + 母号收到 reward 邮件)→ 母号"可拿"-1。
    # 幂等: 只在首次确认该邮箱时扣, 重复确认不重复扣。
    if newly_added:
        _dec_referral_capacity(account_id, reward=1)
    return lst


def _write_codex_auth_json(access_token: str, refresh_token: str, id_token: str,
                           chatgpt_account_id: str, log) -> str:
    """同步 Codex App — 与「平台管理 ChatGPT → 同步 Codex App」按钮完全一致:
      1. quit Codex App  (避免运行中的 App 用自己 token 周期性回写覆盖)
      2. 写 ~/.codex/auth.json (备份旧文件成 .bak)
      3. open Codex App  (让它加载新 auth.json)
      4. 在输入框自动键入 "hi" 并发送 (尽力而为, 失败不影响同步)
    返回写入路径。缺 AT/RT 抛异常。"""
    import os
    from pathlib import Path
    access_token = (access_token or "").strip()
    refresh_token = (refresh_token or "").strip()
    if not access_token or not refresh_token:
        raise RuntimeError("缺 access_token / refresh_token,无法写 ~/.codex/auth.json")
    chatgpt_account_id = (chatgpt_account_id or "").strip()
    if not chatgpt_account_id:
        from platforms.chatgpt.utils import decode_jwt_payload as _dj
        _p = _dj(access_token) or {}
        chatgpt_account_id = str(
            (_p.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id") or ""
        ).strip()

    # 复用 ChatGPT 界面同步按钮的 App 控制 helper(quit / open / send hi)
    try:
        from api.chatgpt import _codex_app_control, _codex_app_send_text
    except Exception as _imp_exc:
        _codex_app_control = None
        _codex_app_send_text = None
        log(f"  [codex-app] 控制 helper 不可用(仅写文件): {_imp_exc}")

    # 1. 先 quit App
    if _codex_app_control:
        try:
            log(f"  [codex-app] quit → {_codex_app_control('quit')}")
        except Exception as exc:
            log(f"  [codex-app] quit 异常(继续): {exc}")

    # 2. 写 auth.json
    auth_path = Path(os.path.expanduser("~/.codex/auth.json"))
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    if auth_path.exists():
        try:
            auth_path.with_suffix(".json.bak").write_bytes(auth_path.read_bytes())
        except Exception:
            pass
    data = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": id_token or "",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_id": chatgpt_account_id,
        },
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }
    auth_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    try:
        os.chmod(auth_path, 0o600)
    except Exception:
        pass

    # 3. open App + 4. send hi
    if _codex_app_control:
        try:
            open_res = _codex_app_control("open")
            log(f"  [codex-app] open → {open_res}")
            if open_res == "success" and _codex_app_send_text:
                from core.config_store import config_store as _cs_app
                try:
                    ready_wait = float(str(_cs_app.get("codex_app_ready_wait_seconds", "") or 6) or 6)
                    pre_type_delay = float(str(_cs_app.get("codex_app_pre_type_delay_seconds", "") or 4) or 4)
                except Exception:
                    ready_wait, pre_type_delay = 6.0, 4.0
                log(f"  [codex-app] send hi → "
                    f"{_codex_app_send_text('hi', ready_wait=ready_wait, pre_type_delay=pre_type_delay)}")
        except Exception as exc:
            log(f"  [codex-app] open/send 异常(继续): {exc}")

    return str(auth_path)


# reward 邮件主题关键字 (母号收到 = 被邀请号完成激活, 触发推荐奖励)
def _is_reward_mail(subject: str, body: str = "") -> bool:
    """识别推荐奖励(reward)邮件。OpenAI 已改版:不再是固定主题 'Your Codex referral reward is ready',
    新版正文(中文)为:「你推荐的用户已在 ChatGPT 桌面版发送第一条消息,因此我们已向你们每人的账户添加 N 额度」
    额度值不固定 → 只按内容特征匹配(不匹配数字),中英文都覆盖,搜「主题+正文」。"""
    import re as _re
    raw = f"{subject or ''}\n{body or ''}"
    txt = _re.sub(r"<[^>]+>", " ", raw)          # 去 HTML 标签
    txt = _re.sub(r"\s+", " ", txt)
    low = txt.lower()
    # 中文新版:发送第一条消息 + 额度/积分
    if "第一条消息" in txt and ("额度" in txt or "积分" in txt or "credit" in low):
        return True
    if "每人的账户" in txt and ("额度" in txt or "积分" in txt):
        return True
    # 英文新版:sent (their/his/her) first message ... credits
    if "first message" in low and "credit" in low:
        return True
    # 旧版兜底(仍可能出现的英文奖励邮件)
    if "referral reward" in low:
        return True
    return False


def _parse_mail_time(s: Any) -> Optional[datetime]:
    """解析邮件时间字段, 兼容 Graph (ISO 8601) 与 IMAP (RFC 2822)。返回 aware UTC datetime。"""
    text = str(s or "").strip()
    if not text:
        return None
    # ISO 8601 (Graph: 2026-06-15T14:24:30Z / +00:00)
    try:
        t = text[:-1] + "+00:00" if text.endswith("Z") else text
        dt = datetime.fromisoformat(t)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    # RFC 2822 (IMAP Date 头: Sun, 15 Jun 2026 14:24:30 +0000)
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(text)
        if dt:
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _snapshot_reward_baseline(account_id: int, log) -> dict:
    """触发 reward 之前快照基线: 记录(a)收件箱已有 message id, (b)触发时刻 since。
    之后只认 id 不在基线 且 时间晚于 since 的 reward 邮件 → 避免匹配历史 reward。"""
    ids: set = set()
    since = _utcnow()
    try:
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, account_id)
        if acc:
            msgs = _fetch_recent_for_account(acc, 15)
            ids = {str(m.get("id") or "") for m in msgs if m.get("id")}
            n_reward = sum(
                1 for m in msgs
                if _is_reward_mail(str(m.get("subject") or ""), str(m.get("body") or m.get("preview") or ""))
            )
            log(f"  📋 reward 基线: 已有 {len(ids)} 封 (含 {n_reward} 封历史 reward),"
                f"基线时刻 {since.strftime('%H:%M:%S')},之后只认更新到达的")
    except Exception as exc:
        log(f"  ⚠ reward 基线取件失败(仅按时间判,可能误判): {exc}")
    return {"ids": ids, "since": since}


def _wait_for_reward_email(account_id: int, timeout_seconds: int, log,
                           baseline: Optional[dict] = None,
                           poll_interval: int = 20) -> bool:
    """轮询母号收件箱等 reward 邮件。判定为"新到达"需同时满足:
      - subject 命中 reward 关键字
      - id 不在基线里 (不是快照时已存在的邮件)
      - 邮件时间晚于基线时刻 since (容忍 60s 时钟偏差)
    固定时长内没等到返回 False。"""
    from datetime import timedelta
    baseline = baseline or {}
    base_ids = set(baseline.get("ids") or set())
    since = baseline.get("since")
    skew = timedelta(seconds=60)
    deadline = time.time() + max(30, int(timeout_seconds or 0))
    rounds = 0
    while time.time() < deadline:
        rounds += 1
        try:
            with Session(engine) as s:
                acc = s.get(GptProAccountModel, account_id)
            if acc:
                msgs = _fetch_recent_for_account(acc, 15)
                for m in msgs:
                    if not _is_reward_mail(str(m.get("subject") or ""),
                                           str(m.get("body") or m.get("preview") or "")):
                        continue
                    mid = str(m.get("id") or "")
                    if mid and mid in base_ids:
                        continue  # 快照时已存在 = 历史邮件
                    mtime = _parse_mail_time(m.get("time"))
                    if since is not None and mtime is not None and mtime < since - skew:
                        continue  # 时间早于触发时刻 = 历史邮件 (即使被挤出 id 基线也能识别)
                    log(f"  📬 收到新的 reward 邮件: {m.get('subject')} (time={m.get('time')})")
                    return True
                log(f"  📭 reward 轮询第 {rounds} 轮: 暂无新 reward ({len(msgs)} 封最近邮件)")
        except Exception as exc:
            log(f"  ⚠ reward 取件异常(继续重试): {exc}")
        if time.time() + poll_interval < deadline:
            time.sleep(poll_interval)
        else:
            break
    return False


class GptProReferralConfirmRequest(BaseModel):
    email: str
    confirmed: bool = True


@router.post("/accounts/{account_id}/referral-confirm")
def gpt_pro_referral_confirm(account_id: int, body: GptProReferralConfirmRequest):
    """人工确认/取消确认某个被邀请邮箱。confirmed=True 加入 referral_confirmed_emails_json,
    False 移除。返回更新后的已确认清单。"""
    email = (body.email or "").strip().lower()
    if not email:
        raise HTTPException(400, "email 不能为空")
    with Session(engine) as s:
        row = s.get(GptProAccountModel, account_id)
        if not row:
            raise HTTPException(404, "账号不存在")
        try:
            lst = json.loads(row.referral_confirmed_emails_json or "[]")
            if not isinstance(lst, list):
                lst = []
        except Exception:
            lst = []
        lst = [str(x).strip().lower() for x in lst if str(x or "").strip()]
        was_present = email in lst
        if body.confirmed:
            if not was_present:
                lst.append(email)
        else:
            lst = [x for x in lst if x != email]
        row.referral_confirmed_emails_json = json.dumps(lst, ensure_ascii=False)
        row.updated_at = _utcnow()
        s.add(row)
        s.commit()
    # 手动打绿勾(新增)→ 可拿-1;手动取消勾(移除)→ 可拿+1 还回去。保持本地计数对称。
    if body.confirmed and not was_present:
        _dec_referral_capacity(account_id, reward=1)
    elif (not body.confirmed) and was_present:
        _dec_referral_capacity(account_id, reward=-1)
    return {"ok": True, "referral_confirmed_emails": lst}


# ── 点击已邀请邮箱: OAuth(如缺) → 同步 Codex App → 等母号 reward → 打绿勾 ──
class GptProReferralCompleteRequest(BaseModel):
    email: str
    browser_mode: str = "headless"   # headless | headed (OAuth 补 RT 浏览器模式)


@router.post("/accounts/{account_id}/referral-complete")
def gpt_pro_referral_complete(account_id: int, body: GptProReferralCompleteRequest):
    """对一个已邀请邮箱跑"完成"流程(后台任务):
      1. 找该邮箱对应的 ChatGPT 账号
      2. 缺 RT → 先 OAuth 拿 RT
      3. 同步 Codex App (写 ~/.codex/auth.json)
      4. codex_chat("hi") 触发 reward
      5. 等母号收件箱收到 reward 邮件 → 收到则把该邮箱打绿勾
    复用 GET /referral-invite-auto/{task_id}?since=N 轮询进度+日志。"""
    email = (body.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "邮箱无效")
    with Session(engine) as s:
        pro = s.get(GptProAccountModel, account_id)
        if not pro:
            raise HTTPException(404, "母号不存在")
        try:
            confirmed = json.loads(pro.referral_confirmed_emails_json or "[]")
        except Exception:
            confirmed = []
        if email in [str(x).strip().lower() for x in confirmed]:
            raise HTTPException(400, "该邮箱已确认完成(绿色),无需重复处理")
    browser_mode = (body.browser_mode or "headless").strip().lower()
    if browser_mode not in ("headless", "headed", "protocol"):
        browser_mode = "headless"
    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_referral_complete,
        args=(task_id, account_id, email),
        kwargs={"browser_mode": browser_mode},
        name=f"gpt-pro-refcomplete-{task_id[:8]}",
        daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id}


def _run_referral_complete(task_id: str, pro_account_id: int, email: str,
                           browser_mode: str = "headless") -> None:
    """点击已邀请邮箱触发的"完成"流程。失败/超时都转 task 状态。"""
    log = lambda m: _invite_task_log(task_id, m)
    try:
        from core.db import AccountModel
        # 1. 找被邀请邮箱对应的账号:先 AccountModel(chatgpt),再回退 GptProAccountModel
        #    (iCloud 邀请候选来自 GptProAccountModel, 不在 AccountModel 里)
        with Session(engine) as s:
            acc_row = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == "chatgpt")
                .where(func.lower(AccountModel.email) == email)
            ).first()
            gp_row = None
            if not acc_row:
                gp_row = s.exec(
                    select(GptProAccountModel).where(func.lower(GptProAccountModel.email) == email)
                ).first()
        if not acc_row and not gp_row:
            raise RuntimeError(f"找不到 {email} 对应的账号记录(ChatGPT / GPT PRO 表均无),无法 OAuth")

        proxy = _gpt_pro_codex_proxy()
        new_rt = new_at = new_id_token = fresh_at = acc_id = ""

        if gp_row is not None:
            # ── GPT PRO 账号(如 iCloud 邀请候选):用 GPT PRO 自己的 OAuth/凭证基础设施 ──
            gp_id = gp_row.id
            if not (gp_row.codex_refresh_token or "").strip():
                log(f"🔐 {email} (GPT PRO/{_mail_provider_of(gp_row)}) 无 codex RT,先跑 OAuth…")
                if not _reacquire_parent_codex_rt(gp_row, log):
                    raise RuntimeError("OAuth 拿 codex RT 失败(见上方日志)")
                with Session(engine) as s:
                    gp_row = s.get(GptProAccountModel, gp_id)
            else:
                log(f"✓ {email} 已有 codex RT (len={len(gp_row.codex_refresh_token or '')}),跳过 OAuth")
            # 刷 fresh AT + account_id(内部轮换/落库 RT, RT 死自动重登)
            fresh_at, acc_id = _gpt_pro_resolve_codex_credentials(gp_row, log=log)
            with Session(engine) as s:
                fresh = s.get(GptProAccountModel, gp_id)
                new_rt = (fresh.codex_refresh_token or "").strip()
                new_id_token = (fresh.codex_id_token or "").strip()
                new_at = (fresh.codex_access_token or "").strip()
            _run_referral_complete_after(
                task_id, pro_account_id, email, proxy,
                new_rt, new_at, new_id_token, fresh_at, acc_id, log)
            return

        acc_db_id = acc_row.id
        extra = acc_row.get_extra()
        new_rt = (extra.get("refresh_token") or "").strip()
        new_at = (extra.get("access_token") or "").strip()
        new_id_token = (extra.get("id_token") or "").strip()

        # 2. 缺 RT → OAuth (复用「补 RT」action)
        if not new_rt:
            log(f"🔐 {email} 无 OAuth RT,先跑 OAuth ({browser_mode})…")
            if not (acc_row.password or ""):
                raise RuntimeError("账号缺密码,无法 OAuth login")
            from platforms.chatgpt.plugin import ChatGPTPlatform
            from core.base_platform import RegisterConfig as _RegCfg, Account, AccountStatus
            from core.config_store import config_store as _cs
            platform = ChatGPTPlatform(
                config=_RegCfg(executor_type="protocol", proxy=proxy, extra=_cs.get_all()),
            )
            try:
                platform._log_fn = log
            except Exception:
                pass
            account_obj = Account(
                platform=acc_row.platform, email=acc_row.email, password=acc_row.password,
                user_id=acc_row.user_id, token=acc_row.token,
                status=AccountStatus(acc_row.status), extra=acc_row.get_extra(),
            )
            res = platform._action_acquire_rt(
                account_obj, {"browser_mode": browser_mode, "_log_fn": log}, proxy,
            )
            if not res.get("ok"):
                raise RuntimeError(f"OAuth 拿 RT 失败: {res.get('error')}")
            patch = res.get("account_extra_patch") or res.get("data") or {}
            new_rt = str(patch.get("refresh_token") or "").strip()
            new_at = str(patch.get("access_token") or "").strip()
            new_id_token = str(patch.get("id_token") or "").strip()
            if not new_rt:
                raise RuntimeError("OAuth 完成但未拿到 refresh_token")
            # 落库
            try:
                with Session(engine) as s:
                    row = s.get(AccountModel, acc_db_id)
                    if row:
                        e2 = row.get_extra()
                        e2.update({
                            "access_token": new_at or e2.get("access_token", ""),
                            "refresh_token": new_rt,
                            "id_token": new_id_token or e2.get("id_token", ""),
                            "chatgpt_registration_mode": "refresh_token",
                            "chatgpt_has_refresh_token_solution": True,
                        })
                        row.set_extra(e2)
                        if new_at:
                            row.token = new_at
                        s.add(row)
                        s.commit()
                log("✓ RT 已回写账号")
            except Exception as exc:
                log(f"⚠ RT 落库失败(继续): {exc}")
        else:
            log(f"✓ {email} 已有 RT (len={len(new_rt)}),跳过 OAuth")

        # 刷一次拿 fresh AT + chatgpt_account_id
        fresh_at = ""
        acc_id = ""
        try:
            from platforms.chatgpt.token_refresh import TokenRefreshManager as _TRM
            from platforms.chatgpt.utils import decode_jwt_payload as _dj
            r = _TRM(proxy_url=proxy).refresh_by_oauth_token(new_rt)
            if r.success and r.access_token:
                fresh_at = r.access_token
                p = _dj(fresh_at) or {}
                acc_id = str((p.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id") or "").strip()
        except Exception as exc:
            log(f"⚠ RT 刷新异常(用旧 AT 兜底): {exc}")

        _run_referral_complete_after(
            task_id, pro_account_id, email, proxy,
            new_rt, new_at, new_id_token, fresh_at, acc_id, log)
    except HTTPException as exc:
        log(f"✗ 失败: {exc.detail}")
        _invite_task_finish(task_id, error=str(exc.detail))
    except Exception as exc:
        log(f"✗ 失败: {exc}")
        _invite_task_finish(task_id, error=str(exc))


def _referral_complete_core(pro_account_id, email, proxy,
                            new_rt, new_at, new_id_token, fresh_at, acc_id, log) -> bool:
    """完成流程核心(不 finish task, 供单个/批量共用):换凭证→打开App→发hi→等回复→codex_chat兜底→等母号 reward。
    收到 reward 则给母号该邮箱打绿勾并返回 True;否则返回 False。"""
    # reward 基线: 触发 reward 之前先记母号收件箱已有邮件,避免匹配历史 reward
    reward_baseline = _snapshot_reward_baseline(pro_account_id, log)

    # 3. 换凭证 → 打开 ChatGPT/Codex App → 在 App 里发 hi(需本机装了对应桌面应用, 名字由 codex_app_name 配)
    _write_codex_auth_json(fresh_at or new_at, new_rt, new_id_token, acc_id, log)
    log("✓ 已同步到本地 Codex App (~/.codex/auth.json)")

    # 3.5 在 App 发 hi 后, 等 App 收到并回复(给桌面版时间产生"第一条消息"的回复, 再去等 reward)
    try:
        from core.config_store import config_store as _csr
        reply_wait = max(0, min(300, int(_csr.get("gpt_pro_app_reply_wait_seconds", 25) or 25)))
    except Exception:
        reply_wait = 25
    if reply_wait:
        log(f"⏳ 已在 App 发 hi,等回复 {reply_wait}s…")
        time.sleep(reply_wait)

    # 4. codex_chat hi 兜底(App 窗口没打开/发失败时, 用 HTTP 再发一次确保有"第一条消息")
    if fresh_at and acc_id:
        log("💬 发 codex_chat('hi') 触发 reward…")
        try:
            from platforms.chatgpt.codex_chat import codex_chat as _cc
            c = _cc(access_token=fresh_at, chatgpt_account_id=acc_id,
                    prompt="hi", model="gpt-5.5", proxy=proxy, timeout=60)
            log(f"💬 codex {'✓' if c.get('ok') else '✗'} HTTP {c.get('http_status')}")
        except Exception as exc:
            log(f"⚠ codex 测试异常: {exc}")
    else:
        log("⊘ 无 fresh AT,跳过 codex 测试")

    # 5. 等母号 reward 邮件
    from core.config_store import config_store as _cs2
    try:
        reward_timeout = max(30, min(1800, int(_cs2.get("gpt_pro_reward_wait_seconds", 300) or 300)))
    except Exception:
        reward_timeout = 300
    with Session(engine) as s:
        pro = s.get(GptProAccountModel, pro_account_id)
        pro_email = pro.email if pro else f"#{pro_account_id}"
    log(f"📬 等母号 {pro_email} 收 reward 邮件(推荐奖励/发送第一条消息+额度)(最多 {reward_timeout}s)…")
    if _wait_for_reward_email(pro_account_id, reward_timeout, log, baseline=reward_baseline):
        _mark_referral_confirmed(pro_account_id, email)
        log(f"🎉 reward 收到 → {email} 已打绿勾,完成")
        return True
    log(f"⚠ reward 未在 {reward_timeout}s 内到达,未打勾,需人工确认")
    return False


def _run_referral_complete_after(task_id, pro_account_id, email, proxy,
                                 new_rt, new_at, new_id_token, fresh_at, acc_id, log) -> None:
    """单个「完成」流程后半段:调核心 + finish task。"""
    confirmed = _referral_complete_core(
        pro_account_id, email, proxy, new_rt, new_at, new_id_token, fresh_at, acc_id, log)
    _invite_task_finish(task_id, result={"confirmed": confirmed, "email": email})


@router.get("/accounts/{account_id}/referral-quota")
def gpt_pro_referral_quota(account_id: int):
    """返回本地存的待重置次数(referral_remaining)。
    按新策略:不再实时去 ChatGPT 查询配额 —— 升级 PRO 时默认 3,重置成功才 -1。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        left = acc.referral_remaining
        checked = acc.referral_quota_checked_at
    return {
        "remaining": left,
        "checked_at": checked.isoformat() if checked else None,
        "source": "local",
    }


def _cache_referral_reward(account_id: int, info: dict) -> dict:
    """把邀请积分查询结果落库到 extra_json.referral_reward, 供后续本地读取/计数(不再实时查)。"""
    payload = {
        "per_invite_reward": info.get("per_invite_reward"),
        "grant_type": info.get("grant_type"),
        "remaining_send_capacity": int(info.get("remaining_send_capacity") or 0),
        "remaining_reward_capacity": int(info.get("remaining_reward_capacity") or 0),
        "title": info.get("title"),
        "description": info.get("description"),
        "offer_id": info.get("offer_id"),
        "has_reward_offer": bool(info.get("has_reward_offer")),
        "checked_at": _utcnow().isoformat(),
    }
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if acc:
            try:
                extra = json.loads(acc.extra_json) if acc.extra_json else {}
            except Exception:
                extra = {}
            extra["referral_reward"] = payload
            acc.extra_json = json.dumps(extra, ensure_ascii=False)
            acc.updated_at = _utcnow()
            s.add(acc)
            s.commit()
    return payload


def _dec_referral_capacity(account_id: int, *, send: int = 0, reward: int = 0) -> None:
    """本地扣减邀请额度(发一次邀请 send-1;确认拿到奖励 reward-1)。不再实时查。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return
        try:
            extra = json.loads(acc.extra_json) if acc.extra_json else {}
        except Exception:
            extra = {}
        rr = extra.get("referral_reward")
        if isinstance(rr, dict):
            if send:
                rr["remaining_send_capacity"] = max(0, int(rr.get("remaining_send_capacity") or 0) - send)
            if reward:
                rr["remaining_reward_capacity"] = max(0, int(rr.get("remaining_reward_capacity") or 0) - reward)
            extra["referral_reward"] = rr
            acc.extra_json = json.dumps(extra, ensure_ascii=False)
            acc.updated_at = _utcnow()
            s.add(acc)
            s.commit()


# ── 手动 CPA 同步目标(独立于自动"CPA 号池"维护;纯手动:选一台 → 立即推凭证)──
_CPA_SYNC_TARGETS_KEY = "gpt_pro_cpa_sync_targets"
_CPA_SYNC_TARGETS_REVISION_KEY = "gpt_pro_cpa_sync_targets_revision"
_CPA_CONFIG_DOMAIN_MANUAL = "manual_targets"
_CPA_CONFIG_DOMAIN_AUTO_POOL = "auto_pool"
_CPA_CONFIG_WRITE_LOCK = threading.RLock()


def _begin_cpa_config_write(session: Session) -> None:
    """Serialize target edits with sync-intent writes across workers.

    The production store is SQLite, where ``BEGIN IMMEDIATE`` takes the writer
    reservation before either side reads account linkage.  The process lock is
    still useful for non-SQLite/test engines and makes the critical section
    explicit; the durable pending intent is the recovery record after a crash.
    """
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _write_cpa_targets_in_session(session: Session, targets: List[dict]) -> int:
    from core.config_store import ConfigItem

    payload = json.dumps(targets, ensure_ascii=False)
    item = session.get(ConfigItem, _CPA_SYNC_TARGETS_KEY)
    if item:
        item.value = payload
    else:
        item = ConfigItem(key=_CPA_SYNC_TARGETS_KEY, value=payload)
    session.add(item)

    revision = session.get(ConfigItem, _CPA_SYNC_TARGETS_REVISION_KEY)
    try:
        next_revision = int(revision.value or 0) + 1 if revision else 1
    except (TypeError, ValueError):
        next_revision = 1
    if revision:
        revision.value = str(next_revision)
    else:
        revision = ConfigItem(
            key=_CPA_SYNC_TARGETS_REVISION_KEY,
            value=str(next_revision),
        )
    session.add(revision)
    return next_revision


def _cpa_sync_targets_snapshot() -> tuple[List[dict], int]:
    """Read targets and revision from one database snapshot for UI CAS."""
    from core.config_store import ConfigItem

    with Session(engine) as session:
        target_item = session.get(ConfigItem, _CPA_SYNC_TARGETS_KEY)
        revision_item = session.get(ConfigItem, _CPA_SYNC_TARGETS_REVISION_KEY)
        try:
            targets = json.loads(target_item.value) if target_item and target_item.value else []
        except Exception:
            targets = []
        if not isinstance(targets, list):
            targets = []
        try:
            revision = int(revision_item.value or 0) if revision_item else 0
        except (TypeError, ValueError):
            revision = 0
    # Preserve environment/legacy ConfigStore fallback until the first write.
    if target_item is None:
        targets = _get_cpa_sync_targets()
    return targets, revision


def _get_cpa_sync_targets() -> List[dict]:
    """读手动同步目标列表 [{id, name, api_url, api_key}]。"""
    from core.config_store import config_store as _cs
    raw = _cs.get(_CPA_SYNC_TARGETS_KEY, "")
    if isinstance(raw, list):
        return raw
    try:
        v = json.loads(raw) if raw else []
        return v if isinstance(v, list) else []
    except Exception:
        return []


def _cpa_sync_target_by_id(target_id: int) -> Optional[dict]:
    try:
        wanted = int(target_id)
    except (TypeError, ValueError):
        return None
    for target in _get_cpa_sync_targets():
        if not isinstance(target, dict):
            continue
        try:
            current = int(target.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if current == wanted:
            return target
    return None


def _business_master_cpa_reference_ids(raw_extra: Any) -> set[int]:
    """Strictly parse direct BUSINESS mother CPA link/pending target ids.

    A malformed namespaced state cannot be treated as unreferenced while the
    shared target registry is being deleted or repointed.  The caller converts
    ``ValueError`` into a fail-closed service error before writing config.
    """
    raw = str(raw_extra or "{}").strip() or "{}"
    try:
        extra = json.loads(raw)
    except Exception as exc:
        raise ValueError("invalid BUSINESS extra_json") from exc
    if not isinstance(extra, dict):
        raise ValueError("BUSINESS extra_json must be an object")
    if "business_master_cpa" not in extra:
        return set()
    state = extra.get("business_master_cpa")
    if not isinstance(state, dict):
        raise ValueError("business_master_cpa must be an object")

    references: set[int] = set()
    for field_name in ("link", "pending"):
        if field_name not in state:
            continue
        value = state.get(field_name)
        if not isinstance(value, dict):
            raise ValueError(f"business_master_cpa.{field_name} must be an object")
        raw_target_id = value.get("target_id")
        if (
            isinstance(raw_target_id, bool)
            or not isinstance(raw_target_id, (int, str))
            or not str(raw_target_id).strip().isdigit()
        ):
            raise ValueError(
                f"business_master_cpa.{field_name}.target_id is invalid"
            )
        parsed_target_id = int(str(raw_target_id).strip())
        if parsed_target_id <= 0:
            raise ValueError(
                f"business_master_cpa.{field_name}.target_id is invalid"
            )
        references.add(parsed_target_id)
    return references


def _save_cpa_sync_targets(
    targets: List[dict],
    *,
    expected_revision: Optional[int] = None,
    return_revision: bool = False,
):
    """规范化(补 id、去空)后落库,返回规范化后的列表。

    id 与 URL 都是 linkage 身份的一部分，必须唯一；否则同一个账号可能因
    列表顺序变化而取到另一把 key。已有账号只保存 target id，key 始终在
    这份 ConfigStore 配置里读取。
    """
    cleaned: List[dict] = []
    supplied_ids = [
        int(t.get("id"))
        for t in targets
        if isinstance(t, dict)
        and str(t.get("id") or "").strip().isdigit()
        and int(t.get("id") or 0) > 0
    ]
    if len(supplied_ids) != len(set(supplied_ids)):
        raise HTTPException(409, "CPA 同步目标 id 不能重复")
    used_ids = set(supplied_ids)
    next_id = (max(used_ids) + 1) if used_ids else 1
    used_urls: set[str] = set()
    for t in targets:
        if not isinstance(t, dict):
            continue
        url = str(t.get("api_url") or "").strip().rstrip("/")
        if not url:
            continue  # 没地址的目标丢弃
        normalized_url = url.lower()
        if normalized_url in used_urls:
            raise HTTPException(409, f"CPA 同步目标地址不能重复: {url}")
        used_urls.add(normalized_url)
        tid = int(t["id"]) if str(t.get("id") or "").strip().isdigit() else 0
        if not tid:
            while next_id in used_ids:
                next_id += 1
            tid = next_id
            used_ids.add(tid)
            next_id += 1
        cleaned.append({
            "id": tid,
            "name": str(t.get("name") or "").strip() or url,
            "api_url": url,
            "api_key": str(t.get("api_key") or "").strip(),
        })
    # The target snapshot, linkage scan, and write are one serialized database
    # transaction.  A first sync writes ``cpa_sync_pending_target_id`` through
    # the same guard before any remote mutation, closing the former scan/write
    # TOCTOU window.
    with _CPA_CONFIG_WRITE_LOCK:
        with Session(engine) as session:
            _begin_cpa_config_write(session)
            from core.config_store import ConfigItem
            revision_item = session.get(ConfigItem, _CPA_SYNC_TARGETS_REVISION_KEY)
            try:
                current_revision = int(revision_item.value or 0) if revision_item else 0
            except (TypeError, ValueError):
                current_revision = 0
            if (
                expected_revision is not None
                and int(expected_revision) != current_revision
            ):
                raise HTTPException(
                    409,
                    {
                        "code": "cpa_sync_targets_revision_conflict",
                        "message": "CPA 设备配置已被其他页面更新，请刷新后重试",
                        "expected_revision": int(expected_revision),
                        "current_revision": current_revision,
                    },
                )
            old_by_id: Dict[int, dict] = {}
            for item in _get_cpa_sync_targets():
                if not isinstance(item, dict):
                    continue
                try:
                    old_id = int(item.get("id") or 0)
                except (TypeError, ValueError):
                    continue
                if old_id > 0:
                    old_by_id[old_id] = item
            new_by_id = {int(item["id"]): item for item in cleaned}
            protected_ids: set[int] = set()
            for account in session.exec(select(GptProAccountModel)).all():
                state = _extra_of(account)
                protected_candidates = []
                for field_name in (
                    "cpa_synced_to_id",
                    "cpa_sync_pending_target_id",
                    "cpa_migration_target_id",
                ):
                    try:
                        value = int(state.get(field_name) or 0)
                    except (TypeError, ValueError):
                        value = 0
                    if value:
                        protected_candidates.append((field_name, value))
                linked_id = next(
                    (value for field_name, value in protected_candidates
                     if field_name == "cpa_synced_to_id"),
                    0,
                )
                if linked_id and (
                    (bool(state.get("cpa_synced")) and not bool(state.get("cpa_disabled")))
                    or bool(state.get("cpa_disable_pending"))
                    or bool(state.get("cpa_cleanup_pending"))
                    or bool(state.get("cpa_migration_pending"))
                ):
                    protected_ids.add(linked_id)
                if bool(state.get("cpa_sync_pending")):
                    protected_ids.update(
                        value for field_name, value in protected_candidates
                        if field_name == "cpa_sync_pending_target_id"
                    )
                if bool(state.get("cpa_migration_pending")):
                    protected_ids.update(
                        value for field_name, value in protected_candidates
                        if field_name == "cpa_migration_target_id"
                    )
            # BUSINESS parent automation references the same shared target
            # registry by stable id.  Never delete/repoint an enabled policy's
            # target while a scheduler may be about to upload a replacement.
            try:
                from core.db import GptBusinessAutomationPolicyModel
                for policy in session.exec(
                    select(GptBusinessAutomationPolicyModel).where(
                        GptBusinessAutomationPolicyModel.cpa_target_id.is_not(None)  # type: ignore[union-attr]
                    )
                ).all():
                    if bool(policy.auto_rotation_enabled) and policy.cpa_target_id:
                        protected_ids.add(int(policy.cpa_target_id))
            except Exception:
                # Older deployments/tests may use metadata without the new table.
                # create_all installs it in production; compatibility fixtures
                # should not make unrelated target editing fail.
                pass
            # A BUSINESS master may also own a direct credential linkage that
            # is deliberately separate from child-rotation policy state.  Both
            # a committed link and an uncertain upload intent protect the
            # shared target id from deletion/repointing.
            try:
                for parent in session.exec(select(GptBusinessAccountModel)).all():
                    protected_ids.update(
                        _business_master_cpa_reference_ids(parent.extra_json)
                    )
            except ValueError as exc:
                raise HTTPException(
                    503,
                    "BUSINESS 母号 CPA 直连状态损坏，暂不能修改设备配置",
                ) from exc
            except OperationalError as exc:
                # Narrow compatibility databases may not include the BUSINESS
                # account table.  Every other database failure must fail closed
                # or a referenced target could be deleted behind the linkage.
                if "no such table" not in str(exc).lower():
                    raise HTTPException(
                        503,
                        "BUSINESS 母号 CPA 关联状态暂不可读取，请稍后重试",
                    ) from exc
            for target_id in sorted(protected_ids):
                old = old_by_id.get(target_id)
                new = new_by_id.get(target_id)
                if old and not new:
                    raise HTTPException(
                        409,
                        f"CPA 目标 {target_id} 仍有关联或进行中的账号操作，需先完成清理",
                    )
                if old and new and (
                    str(old.get("api_url") or "").strip().rstrip("/").lower()
                    != str(new.get("api_url") or "").strip().rstrip("/").lower()
                ):
                    raise HTTPException(
                        409,
                        f"CPA 目标 {target_id} 仍有关联账号，不能原地更换地址；请新增目标并逐账号迁移",
                    )
            new_revision = _write_cpa_targets_in_session(session, cleaned)
            session.commit()
    if return_revision:
        return cleaned, new_revision
    return cleaned


def _resolve_cpa_endpoint(ex: dict) -> tuple:
    """解析账号所属 CPA 设备的 ``(api_url, api_key)``。

    手动同步域以共享 target id 为唯一权威来源。目标被删除时 fail closed，
    绝不退回账号 ``extra_json`` 中的陈旧 key；目标更换 URL/key 时则立即使用
    ConfigStore 当前值。自动 CPA 号池是另一配置域，仍保留它自己的 endpoint
    linkage。没有 domain/id 的旧数据按兼容规则处理。
    """
    api_url = str(ex.get("cpa_api_url") or "").strip()
    try:
        manual_tid = int(ex.get("cpa_synced_to_id") or 0)
    except (TypeError, ValueError):
        manual_tid = 0
    domain = str(ex.get("cpa_config_domain") or "").strip().lower()
    targets = _get_cpa_sync_targets()
    if domain == _CPA_CONFIG_DOMAIN_MANUAL or manual_tid:
        if not manual_tid:
            return "", ""
        tgt = _cpa_sync_target_by_id(manual_tid)
        if not tgt:
            return "", ""
        return (
            str(tgt.get("api_url") or "").strip(),
            str(tgt.get("api_key") or "").strip(),
        )

    if domain == _CPA_CONFIG_DOMAIN_AUTO_POOL:
        try:
            device_id = int(ex.get("cpa_device_id") or 0)
        except (TypeError, ValueError):
            device_id = 0
        if device_id:
            from services.gpt_pro_cpa_manager import _auto_pool_endpoint_by_device_id
            return _auto_pool_endpoint_by_device_id(device_id)
        # Legacy records created before stable device ids existed keep their
        # copied endpoint.  New device-bound records fail closed if the shared
        # device disappears; they never fall back to a stale account-level key.
        return api_url, str(ex.get("cpa_api_key") or "").strip()

    # 兼容无 domain 的旧记录：若 URL 仍存在于共享手动目标，只使用共享配置
    # 中的当前 key；否则视作历史自动号池 linkage，保持原行为。新手动同步
    # 永远写 domain + target id，因此目标删除后不会走到这个 fallback。
    if api_url:
        norm = api_url.rstrip("/").lower()
        tgt = next(
            (
                t for t in targets
                if str(t.get("api_url") or "").strip().rstrip("/").lower() == norm
            ),
            None,
        )
        if tgt:
            return (
                str(tgt.get("api_url") or "").strip(),
                str(tgt.get("api_key") or "").strip(),
            )
    try:
        legacy_device_id = int(ex.get("cpa_device_id") or 0)
    except (TypeError, ValueError):
        legacy_device_id = 0
    if legacy_device_id:
        from services.gpt_pro_cpa_manager import _auto_pool_endpoint_by_device_id
        return _auto_pool_endpoint_by_device_id(legacy_device_id)
    return api_url, str(ex.get("cpa_api_key") or "").strip()


def _cpa_safe_email_key(email: str) -> str:
    """账号邮箱转成 CPA 文件名里用的"安全格式"(与下载/生成文件同规则: 非字母数字._- 换成 _)。"""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", (email or "")).lower()


def _cpa_file_identifies(f: dict, email_lower: str, safe_lower: str) -> bool:
    """判断一份 CPA auth-file 是否对应某账号。
    优先 email/account 字段精确匹配;这两个为空时(如最小三字段文件)退化到用文件名(name)匹配,
    邮箱在文件名里可能是 @ 原样或被换成 _(safe 格式),两种都试。"""
    fe = str(f.get("email") or f.get("account") or "").strip().lower()
    if fe:
        return fe == email_lower
    nm = str(f.get("name") or "").strip().lower()
    if nm.endswith(".json"):
        nm = nm[:-5]
    if not nm:
        return False
    return (bool(email_lower) and email_lower in nm) or (bool(safe_lower) and safe_lower in nm)


def _disable_cpa_email_at_endpoint(
    email: str,
    api_url: str,
    api_key: str,
    *,
    before_mutation=None,
    initial_files: Optional[List[dict]] = None,
) -> dict:
    """停用某 endpoint 上该邮箱的全部凭据并重新读取确认。

    这是 A→B 手动迁移与 durable disable 共用的远端原语；不修改本地
    linkage，也不接收账号 extra 中的 fallback endpoint。
    """
    if not str(api_url or "").strip():
        return {"ok": False, "error": "CPA 设备地址为空"}
    from services.cpa_manager import list_auth_files, set_auth_file_disabled

    if initial_files is None:
        try:
            files = list_auth_files(api_url=api_url, api_key=api_key)
        except Exception as exc:
            return {"ok": False, "error": f"CPA 凭据列表读取失败: {str(exc)[:240]}"}
    else:
        files = initial_files

    email_lower = str(email or "").strip().lower()
    safe_email = _cpa_safe_email_key(email)

    def _matching(rows: List[dict]) -> List[dict]:
        return [
            item for item in rows
            if _cpa_file_identifies(item, email_lower, safe_email)
            and str(item.get("name") or "").strip()
        ]

    matches = _matching(files)
    request_errors: List[str] = []
    for item in matches:
        if _cpa_auth_file_is_disabled(item):
            continue
        if before_mutation is not None and not bool(before_mutation()):
            return {"ok": False, "cancelled": True, "error": "CPA 生命周期已变化，取消旧停用任务"}
        name = str(item.get("name") or "").strip()
        try:
            set_auth_file_disabled(
                name,
                True,
                api_url=api_url,
                api_key=api_key,
            )
        except Exception as exc:
            request_errors.append(f"{name}: {str(exc)[:180]}")

    if before_mutation is not None and not bool(before_mutation()):
        return {"ok": False, "cancelled": True, "error": "CPA 生命周期已变化，取消旧停用确认"}
    try:
        confirmed_files = list_auth_files(api_url=api_url, api_key=api_key)
    except Exception as exc:
        detail = f"停用后状态确认失败: {str(exc)[:240]}"
        if request_errors:
            detail += "; 请求错误: " + "; ".join(request_errors)
        return {"ok": False, "error": detail}

    confirmed_matches = _matching(confirmed_files)
    active_names = [
        str(item.get("name") or "").strip()
        for item in confirmed_matches
        if not _cpa_auth_file_is_disabled(item)
    ]
    if active_names:
        detail = "远端仍有未停用凭据: " + ", ".join(active_names[:20])
        if request_errors:
            detail += "; 请求错误: " + "; ".join(request_errors)
        return {"ok": False, "error": detail}
    return {
        "ok": True,
        "disabled": len(confirmed_matches),
        "missing": not bool(confirmed_matches),
    }


def _cpa_usage_payload(usage: dict) -> dict:
    """把 _fetch_account_usage 的原始 dict 转成对外/落库的额度 payload(带查询时间)。"""
    return {
        "usage_5h_percent": usage.get("p5_used_percent"),
        "usage_5h_reset_at": usage.get("p5_reset_at"),
        "usage_5h_window_seconds": usage.get("p5_window_seconds"),
        "usage_week_percent": usage.get("week_used_percent"),
        "usage_week_reset_at": usage.get("week_reset_at"),
        "usage_week_window_seconds": usage.get("week_window_seconds"),
        "limit_reached": usage.get("limit_reached"),
        "credit_balance": usage.get("credit_balance"),
        "checked_at": _utcnow().isoformat(),
    }


def _cache_cpa_usage(account_id: int, usage: dict) -> dict:
    """把 CPA 额度查询结果落库到 extra_json.cpa_usage(前端直接读, 整点任务定时刷新)。"""
    payload = _cpa_usage_payload(usage)
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if acc:
            try:
                extra = json.loads(acc.extra_json) if acc.extra_json else {}
            except Exception:
                extra = {}
            extra["cpa_usage"] = payload
            acc.extra_json = json.dumps(extra, ensure_ascii=False)
            acc.updated_at = _utcnow()
            s.add(acc)
            s.commit()
    return payload


def _cpa_synced_to_of(acc: GptProAccountModel) -> Optional[dict]:
    """从 extra_json 读该账号已同步到的 CPA 信息(供前端列展示)。未同步返回 None。"""
    ex = _extra_of(acc)
    if not ex.get("cpa_synced"):
        return None
    return {
        "target_id": int(ex.get("cpa_synced_to_id") or ex.get("cpa_device_id") or 0),
        "name": ex.get("cpa_synced_to_name") or ex.get("cpa_api_url") or "",
        "auth_name": ex.get("cpa_auth_name") or "",
        "synced_at": ex.get("cpa_synced_at") or "",
    }


def serialize_gpt_pro_cpa_status(acc: GptProAccountModel) -> dict:
    """序列化可对前端暴露的 CPA 状态，不包含 RT / AT / API key。

    GPT PRO 列表与 BUSINESS managed-child DTO 应共用此函数，避免
    BUSINESS 子号为了展示状态而把 ``extra_json`` 中的密钥原样返回。
    """
    ex = _extra_of(acc)
    raw_alert = ex.get("cpa_monitor_alert")
    alert = None
    if isinstance(raw_alert, dict):
        # 白名单序列化，防止历史/异常 extra_json 把任意嵌套字段带给前端。
        alert = {
            "code": str(raw_alert.get("code") or ""),
            "message": str(raw_alert.get("message") or "")[:500],
            "detected_at": str(raw_alert.get("detected_at") or ""),
        }
    raw_usage = ex.get("cpa_usage")
    usage = None
    if isinstance(raw_usage, dict):
        usage = {
            key: raw_usage.get(key)
            for key in (
                "usage_5h_percent",
                "usage_5h_reset_at",
                "usage_5h_window_seconds",
                "usage_week_percent",
                "usage_week_reset_at",
                "usage_week_window_seconds",
                "limit_reached",
                "credit_balance",
                "checked_at",
            )
        }
    membership_stale = bool(ex.get("cpa_business_membership_stale"))
    try:
        disable_attempts = max(0, int(ex.get("cpa_disable_attempts") or 0))
    except (TypeError, ValueError):
        disable_attempts = 0
    try:
        cleanup_attempts = max(0, int(ex.get("cpa_cleanup_attempts") or 0))
    except (TypeError, ValueError):
        cleanup_attempts = 0
    return {
        "cpa_synced_to": _cpa_synced_to_of(acc),
        "cpa_disabled": bool(ex.get("cpa_disabled")),
        "cpa_disabled_at": str(ex.get("cpa_disabled_at") or ""),
        "cpa_disabled_reason": str(ex.get("cpa_disabled_reason") or ""),
        "cpa_disable_pending": bool(ex.get("cpa_disable_pending")),
        "cpa_disable_reason": str(ex.get("cpa_disable_reason") or ""),
        "cpa_disable_requested_at": str(ex.get("cpa_disable_requested_at") or ""),
        "cpa_disable_last_attempt_at": str(ex.get("cpa_disable_last_attempt_at") or ""),
        "cpa_disable_last_error": str(ex.get("cpa_disable_last_error") or "")[:500],
        "cpa_disable_attempts": disable_attempts,
        "cpa_cleanup_pending": bool(ex.get("cpa_cleanup_pending")),
        "cpa_cleanup_requested_at": str(ex.get("cpa_cleanup_requested_at") or ""),
        "cpa_cleanup_last_attempt_at": str(ex.get("cpa_cleanup_last_attempt_at") or ""),
        "cpa_cleanup_last_error": str(ex.get("cpa_cleanup_last_error") or "")[:500],
        "cpa_cleanup_attempts": cleanup_attempts,
        "cpa_sync_pending": bool(ex.get("cpa_sync_pending")),
        "cpa_sync_compensation_pending": bool(
            ex.get("cpa_sync_compensation_pending")
        ),
        "cpa_sync_compensation_target_id": (
            int(ex.get("cpa_sync_compensation_target_id") or 0) or None
        ),
        "cpa_sync_compensation_last_error": str(
            ex.get("cpa_sync_compensation_last_error") or ""
        )[:500],
        "cpa_auto_upload_pending": bool(ex.get("cpa_auto_upload_pending")),
        "cpa_account_kind": (
            "business_child"
            if membership_stale
            else str(ex.get("cpa_account_kind") or "")
        ),
        "cpa_lifecycle_state": str(
            ex.get("cpa_lifecycle_state")
            or ("business_child_released" if membership_stale else "")
        ),
        "cpa_membership_stale": membership_stale,
        "cpa_monitor_suppressed": bool(
            ex.get("cpa_monitor_suppressed") or membership_stale
        ),
        "cpa_monitor_alert": alert,
        "cpa_usage": usage,
    }


_SUB2API_LINK_FIELDS = (
    "sub2api_device_id",
    "sub2api_device_name",
    "sub2api_remote_account_id",
    "sub2api_synced_at",
    "sub2api_account_kind",
    "sub2api_business_parent_id",
)
_SUB2API_PENDING_FIELDS = (
    "sub2api_sync_pending",
    "sub2api_sync_pending_device_id",
    "sub2api_sync_pending_device_name",
    "sub2api_sync_pending_started_at",
    "sub2api_sync_pending_remote_account_id",
    "sub2api_sync_pending_operation_token",
    "sub2api_sync_pending_business_parent_id",
)
_SUB2API_RUNTIME_FIELDS = (
    "sub2api_usage",
    "sub2api_last_error",
    "sub2api_last_error_at",
    "sub2api_monitor_alert",
)
_SUB2API_AUTO_REMOVE_CONFIG_KEY = "gpt_pro_sub2api_auto_remove"
_SUB2API_PUBLIC_ALERT_MESSAGES = {
    "sub2api_limit_reached": "Sub2API 账号额度已耗尽",
    "sub2api_remote_missing": "Sub2API 远端账号不存在",
    "sub2api_usage_error": "Sub2API 额度查询失败",
    "sub2api_sync_pending": "Sub2API 同步结果待核对",
    "sub2api_remove_failed": "Sub2API 远端删除未确认，已保留关联",
    "sub2api_remote_retained": "仅解除本地关联；Sub2API 远端账号仍保留",
    "sub2api_device_unavailable": "Sub2API 设备暂不可用",
}


def _sub2api_device_type(value: Any) -> str:
    """Canonicalize legacy ``sub`` rows without importing the API router."""
    normalized = str(value or "").strip().lower()
    return "sub2api" if normalized in {"sub", "sub2api", "sub-2-api"} else normalized


def _sub2api_link_of(acc: GptProAccountModel) -> Optional[dict]:
    """Return the credential-free active Sub2API linkage stored on an account."""
    extra = _extra_of(acc)
    try:
        device_id = int(extra.get("sub2api_device_id") or 0)
    except (TypeError, ValueError):
        device_id = 0
    remote_id = str(extra.get("sub2api_remote_account_id") or "").strip()
    if device_id <= 0 or not remote_id:
        return None
    return {
        "device_id": device_id,
        "name": str(extra.get("sub2api_device_name") or ""),
        "remote_account_id": remote_id,
        "synced_at": str(extra.get("sub2api_synced_at") or ""),
    }


def _sub2api_pending_of(acc: GptProAccountModel) -> Optional[dict]:
    extra = _extra_of(acc)
    if not bool(extra.get("sub2api_sync_pending")):
        return None
    try:
        device_id = int(extra.get("sub2api_sync_pending_device_id") or 0)
    except (TypeError, ValueError):
        device_id = 0
    return {
        "device_id": device_id or None,
        "name": str(extra.get("sub2api_sync_pending_device_name") or ""),
        "remote_account_id": str(
            extra.get("sub2api_sync_pending_remote_account_id") or ""
        ) or None,
        "started_at": str(extra.get("sub2api_sync_pending_started_at") or ""),
    }


def serialize_gpt_pro_sub2api_status(acc: GptProAccountModel) -> dict:
    """Serialize only safe Sub2API linkage/usage fields for account DTOs.

    The cached payload already comes from the strict allow-list in
    ``services.sub2api_admin``.  It is sanitized again here so malformed or
    legacy ``extra_json`` can never turn the account list into a credential
    disclosure endpoint.
    """
    from services.sub2api_admin import sanitize_admin_payload

    extra = _extra_of(acc)
    link = _sub2api_link_of(acc)
    pending = _sub2api_pending_of(acc)
    status = str(extra.get("sub2api_status") or "").strip().lower()
    if status not in {"unlinked", "linked", "ok", "limit_reached", "error"}:
        status = "linked" if link else "unlinked"

    usage = None
    raw_usage = extra.get("sub2api_usage")
    if isinstance(raw_usage, dict):
        source = str(raw_usage.get("source") or "passive").strip().lower()
        if source not in {"passive", "active"}:
            source = "passive"
        raw_limit = raw_usage.get("limit_reached")
        limit_reached = raw_limit if isinstance(raw_limit, bool) else None
        payload = sanitize_admin_payload(raw_usage.get("payload"))
        usage = {
            "source": source,
            "payload": payload,
            "limit_reached": limit_reached,
            "checked_at": str(raw_usage.get("checked_at") or ""),
        }
        # Preserve the last successful payload when a later refresh fails.  The
        # error is overlaid from separate state instead of replacing ``payload``.
        if extra.get("sub2api_last_error"):
            # Never echo a historical/free-form transport exception; it may
            # contain a URL credential, Bearer token, or an upstream body.
            usage["error"] = "Sub2API 最近一次刷新失败，已保留上次成功额度"

    alert = None
    raw_alert = extra.get("sub2api_monitor_alert")
    if isinstance(raw_alert, dict):
        code = str(raw_alert.get("code") or "sub2api_error")
        alert = {
            "code": code,
            # Use a closed message vocabulary.  The stored text is useful for
            # server-side diagnosis but is not trusted as an API value.
            "message": _SUB2API_PUBLIC_ALERT_MESSAGES.get(
                code,
                "Sub2API 状态异常，请重试或检查设备",
            ),
            "detected_at": str(raw_alert.get("detected_at") or ""),
        }
    return {
        "sub2api_synced_to": link,
        "sub2api_status": status,
        "sub2api_usage": usage,
        "sub2api_monitor_alert": alert,
        "sub2api_sync_pending": bool(pending),
        "sub2api_pending_to": pending,
    }


def _sub2api_limit_reached(payload: Any) -> Optional[bool]:
    """Conservatively infer exhaustion from a sanitized quota payload."""
    saw_false = False

    def _walk(value: Any, depth: int = 0) -> Optional[bool]:
        nonlocal saw_false
        if depth > 12:
            return None
        if isinstance(value, list):
            for item in value:
                result = _walk(item, depth + 1)
                if result is True:
                    return True
            return None
        if not isinstance(value, dict):
            return None
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized == "limit_reached" and isinstance(item, bool):
                if item:
                    return True
                saw_false = True
            if normalized in {"status", "subscription_status"}:
                state = str(item or "").strip().lower()
                if state in {"limit_reached", "quota_exceeded", "exhausted", "depleted"}:
                    return True
            if normalized in {"used_percent", "usage_percent", "percentage", "percent", "utilization"}:
                if isinstance(item, (int, float)) and not isinstance(item, bool) and float(item) >= 100:
                    return True
            nested = _walk(item, depth + 1)
            if nested is True:
                return True
        return None

    reached = _walk(payload)
    if reached is True:
        return True
    return False if saw_false else None


def _sub2api_monitor_alert(code: str, message: str) -> dict:
    return {
        "code": str(code or "sub2api_error"),
        "message": str(message or "Sub2API 状态异常")[:500],
        "detected_at": _utcnow().isoformat(),
    }


def _cache_sub2api_usage(
    account_id: int,
    payload: Any,
    *,
    source: str,
    operation_token: str = "",
    expected_business_parent_id: Optional[int] = None,
    expected_device_id: Optional[int] = None,
    expected_remote_account_id: Optional[str] = None,
) -> Optional[dict]:
    """Persist one successful, already-sanitized Sub2API usage snapshot."""
    from services.sub2api_admin import sanitize_admin_payload

    safe_payload = sanitize_admin_payload(payload)
    limit_reached = _sub2api_limit_reached(safe_payload)
    cached = {
        "source": "active" if str(source).lower() == "active" else "passive",
        "payload": safe_payload,
        "limit_reached": limit_reached,
        "checked_at": _utcnow().isoformat(),
    }
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        link = _sub2api_link_of(account) if account else None
        if not account or not link or not _sub2api_parent_scope_matches(
            account,
            expected_business_parent_id,
        ):
            return None
        if expected_business_parent_id is not None and not operation_token:
            return None
        if operation_token and not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            return None
        if (
            expected_device_id is not None
            and int(link["device_id"]) != int(expected_device_id)
        ) or (
            expected_remote_account_id is not None
            and str(link["remote_account_id"])
            != str(expected_remote_account_id)
        ):
            return None
        extra = _extra_of(account)
        extra["sub2api_usage"] = cached
        extra["sub2api_status"] = "limit_reached" if limit_reached is True else "ok"
        extra.pop("sub2api_last_error", None)
        extra.pop("sub2api_last_error_at", None)
        if limit_reached is True:
            extra["sub2api_monitor_alert"] = _sub2api_monitor_alert(
                "sub2api_limit_reached",
                "Sub2API 账号额度已耗尽",
            )
        else:
            previous = extra.get("sub2api_monitor_alert")
            if isinstance(previous, dict) and str(previous.get("code") or "").startswith("sub2api_"):
                extra.pop("sub2api_monitor_alert", None)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        return serialize_gpt_pro_sub2api_status(account)


def _cache_sub2api_error(
    account_id: int,
    code: str,
    message: str,
    *,
    operation_token: str = "",
    expected_business_parent_id: Optional[int] = None,
    expected_device_id: Optional[int] = None,
    expected_remote_account_id: Optional[str] = None,
) -> Optional[dict]:
    """Persist an error without destroying the last successful usage payload."""
    safe_message = str(message or "Sub2API 查询失败")[:500]
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        link = _sub2api_link_of(account) if account else None
        if not account or not link or not _sub2api_parent_scope_matches(
            account,
            expected_business_parent_id,
        ):
            return None
        if expected_business_parent_id is not None and not operation_token:
            return None
        if operation_token and not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            return None
        if (
            expected_device_id is not None
            and int(link["device_id"]) != int(expected_device_id)
        ) or (
            expected_remote_account_id is not None
            and str(link["remote_account_id"])
            != str(expected_remote_account_id)
        ):
            return None
        extra = _extra_of(account)
        extra["sub2api_status"] = "error"
        extra["sub2api_last_error"] = safe_message
        extra["sub2api_last_error_at"] = _utcnow().isoformat()
        extra["sub2api_monitor_alert"] = _sub2api_monitor_alert(code, safe_message)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        return serialize_gpt_pro_sub2api_status(account)


def _patch_gpt_pro_extra(account_id: int, patch: dict, *, remove: tuple = ()) -> None:
    """合并写入 GPT PRO extra_json；供 CPA 同步/监控/释放路径共用。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return
        extra = _extra_of(acc)
        for key in remove:
            extra.pop(key, None)
        extra.update(patch)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        s.add(acc)
        s.commit()


def _record_cpa_monitor_alert(account_id: int, code: str, message: str) -> dict:
    """记录可展示的 CPA 告警，不在文本中包含凭证或 API key。"""
    alert = {
        "code": str(code or "cpa_error"),
        "message": str(message or "CPA 状态异常")[:500],
        "detected_at": _utcnow().isoformat(),
    }
    _patch_gpt_pro_extra(account_id, {"cpa_monitor_alert": alert})
    return alert


def _require_cpa_account_scope(
    account_id: int,
    *,
    expected_business_parent_id: Optional[int] = None,
) -> GptProAccountModel:
    """加载 CPA 操作账号并校验 GPT PRO / BUSINESS 调用边界。

    ``expected_business_parent_id`` 为 None 时表示 GPT PRO 页面的普通调用，
    已归属 BUSINESS 的子号会被拒绝。BUSINESS 代理路由传入预期母号，
    防止只凭可猜测的 child id 跨母号操作。
    """
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        parent_id = getattr(acc, "business_parent_id", None)
        if expected_business_parent_id is None:
            if parent_id is not None:
                raise HTTPException(
                    409,
                    f"账号已归属 GPT BUSINESS 母号 {parent_id}，请从母号子号接口操作",
                )
        elif parent_id != int(expected_business_parent_id):
            # 不暴露该 child 是否存在于其他母号。
            raise HTTPException(404, "该母号下不存在这个可管理子号")
        if not bool(acc.enabled):
            raise HTTPException(409, "账号已被禁用，不能操作 CPA")
        if bool(acc.dangerous):
            raise HTTPException(409, "账号已标记 dead/停用，不能操作 CPA")
        return acc


def serialize_gpt_pro_mail_monitor_status(acc: GptProAccountModel) -> dict:
    """BUSINESS managed-child DTO 可复用的邮件健康状态，不暴露邮箱凭证。"""
    is_child = is_managed_business_child_account(acc)
    configured = _extra_of(acc).get("business_child_monitor_enabled", True)
    if isinstance(configured, str):
        child_monitor_enabled = configured.strip().lower() not in {
            "", "0", "false", "no", "off",
        }
    else:
        child_monitor_enabled = bool(configured)
    return {
        "monitor_enabled": bool(
            acc.enabled
            and (child_monitor_enabled if is_child else bool(acc.is_pro))
        ),
        "last_mail_check_at": _iso_utc(getattr(acc, "last_mail_check_at", None)),
        "last_mail_check_error": str(getattr(acc, "last_mail_check_error", "") or ""),
        "unread_count": len(_safe_json_list(getattr(acc, "pending_alerts_json", "[]"))),
        "inbox_unread_count": len(_safe_json_list(getattr(acc, "pending_inbox_json", "[]"))),
    }


def _safe_json_list(raw: str) -> list:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except Exception:
        return []


def set_managed_business_child_monitoring(
    account_id: int,
    expected_business_parent_id: int,
    enabled: bool,
) -> dict:
    """BUSINESS 代理路由使用的子号邮件监控 setter。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc or getattr(acc, "business_parent_id", None) != int(expected_business_parent_id):
            raise HTTPException(404, "该母号下不存在这个可管理子号")
        extra = _extra_of(acc)
        extra["business_child_monitor_enabled"] = bool(enabled)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        s.add(acc)
        s.commit()
        s.refresh(acc)
        return {"ok": True, **serialize_gpt_pro_mail_monitor_status(acc)}


class GptProSyncCpaRequest(BaseModel):
    target_id: int


@router.get("/cpa-sync-targets")
def gpt_pro_cpa_sync_targets():
    """手动 CPA 同步目标列表。"""
    targets, revision = _cpa_sync_targets_snapshot()
    return {"targets": targets, "revision": revision}


class CpaSyncTargetsPutRequest(BaseModel):
    targets: List[dict]
    expected_revision: Optional[int] = None


@router.put("/cpa-sync-targets")
def gpt_pro_put_cpa_sync_targets(body: CpaSyncTargetsPutRequest):
    """整表替换手动 CPA 同步目标(新目标自动补 id)。"""
    targets, revision = _save_cpa_sync_targets(
        body.targets or [],
        expected_revision=body.expected_revision,
        return_revision=True,
    )
    return {"targets": targets, "revision": revision}


class CpaTestConnRequest(BaseModel):
    api_url: str
    api_key: str = ""


@router.post("/cpa-sync-targets/test")
def gpt_pro_test_cpa_target(body: CpaTestConnRequest):
    """测试一台 CPA 设备连通性(OPTIONS 探活 /v0/management/auth-files)。"""
    api_url = str(body.api_url or "").strip().rstrip("/")
    if not api_url:
        raise HTTPException(400, "CPA 地址不能为空")
    from platforms.chatgpt.cpa_upload import test_cpa_connection
    ok, message = test_cpa_connection(api_url, str(body.api_key or "").strip())
    return {"ok": ok, "message": message}


def _parse_cpa_sync_timestamp(value: Any) -> Optional[datetime]:
    try:
        return _parse_expires_at(value)
    except HTTPException:
        return None


def _promote_stale_cpa_sync_pending(
    account_id: int,
    *,
    operation_token: str,
) -> dict:
    """Atomically turn an abandoned upload intent into exact compensation.

    A caller may only promote an intent after it owns the account lease.  An
    intent still owned by that same live lease is treated as an in-flight
    request and is never reconciled or overwritten by a second invocation.
    """
    now = _utcnow()
    with Session(engine) as session:
        is_sqlite = session.get_bind().dialect.name == "sqlite"
        if is_sqlite:
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            account = session.get(GptProAccountModel, int(account_id))
        else:
            account = session.exec(
                select(GptProAccountModel)
                .where(GptProAccountModel.id == int(account_id))
                .with_for_update()
            ).first()
        if not account:
            raise HTTPException(404, "账号不存在")
        lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
        if not (
            lease
            and str(lease.token or "") == str(operation_token or "")
            and (_aware_utc(lease.expires_at) or now) > now
        ):
            raise HTTPException(409, "CPA 同步操作租约已失效，请重试")
        extra = _extra_of(account)
        if not bool(extra.get("cpa_sync_pending")):
            return {"pending": False, "promoted": False}

        pending_token = str(extra.get("cpa_sync_pending_token") or "")
        if pending_token == str(operation_token or ""):
            # This token may currently be inside upload_to_cpa. A duplicate
            # invocation must not list/disable or issue another POST.
            return {
                "pending": True,
                "promoted": False,
                "active": True,
            }
        try:
            target_id = int(extra.get("cpa_sync_pending_target_id") or 0)
        except (TypeError, ValueError):
            target_id = 0
        target_url = str(extra.get("cpa_sync_pending_target_url") or "").rstrip("/")
        auth_name = str(
            extra.get("cpa_sync_pending_auth_name")
            or f"{str(account.email or '').strip()}.json"
        ).strip()
        had_compensation = bool(extra.get("cpa_sync_compensation_pending"))
        if had_compensation:
            try:
                compensation_target_id = int(
                    extra.get("cpa_sync_compensation_target_id") or 0
                )
            except (TypeError, ValueError):
                compensation_target_id = 0
            same_compensation = bool(
                str(extra.get("cpa_sync_compensation_token") or "") == pending_token
                and compensation_target_id == target_id
                and str(extra.get("cpa_sync_compensation_target_url") or "")
                .rstrip("/").lower() == target_url.lower()
                and str(extra.get("cpa_sync_compensation_auth_name") or "") == auth_name
            )
            if not same_compensation:
                raise HTTPException(
                    409,
                    "CPA 同步存在不同身份的未完成补偿，拒绝覆盖",
                )

        quarantine_until = _parse_cpa_sync_timestamp(
            extra.get("cpa_sync_compensation_quarantine_until")
            if had_compensation
            else extra.get("cpa_sync_pending_quarantine_until")
        )
        if quarantine_until is None:
            if had_compensation:
                # Explicit compensation is only written after a successful
                # upload response, so no unknown in-flight POST remains.
                quarantine_until = now
            else:
                anchor = (
                    _parse_cpa_sync_timestamp(extra.get("cpa_sync_pending_remote_started_at"))
                    or _parse_cpa_sync_timestamp(extra.get("cpa_sync_pending_started_at"))
                    or now
                )
                quarantine_until = anchor + timedelta(
                    seconds=CPA_SYNC_REMOTE_QUARANTINE_SECONDS
                )
        started_at = str(
            extra.get("cpa_sync_compensation_started_at")
            or now.isoformat()
        )
        extra.update({
            "cpa_sync_compensation_pending": True,
            "cpa_sync_compensation_token": pending_token,
            "cpa_sync_compensation_target_id": target_id,
            "cpa_sync_compensation_target_url": target_url,
            "cpa_sync_compensation_auth_name": auth_name,
            "cpa_sync_compensation_reason": "恢复未完成的 CPA 上传 intent",
            "cpa_sync_compensation_started_at": started_at,
            "cpa_sync_compensation_quarantine_until": quarantine_until.isoformat(),
            "cpa_sync_compensation_last_error": "等待旧 CPA 上传隔离期结束并精确核对",
            "cpa_lifecycle_state": "sync_compensation_pending",
            "cpa_monitor_suppressed": True,
        })
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = now
        session.add(account)
        session.commit()
        return {
            "pending": True,
            "promoted": True,
            "active": False,
            "quarantine_until": quarantine_until.isoformat(),
        }


def _mark_cpa_sync_remote_write_started(
    account_id: int,
    *,
    operation_token: str,
    target_id: int,
    auth_name: str,
) -> bool:
    """Durably timestamp the bounded in-flight window immediately before POST."""
    now = _utcnow()
    with Session(engine) as session:
        is_sqlite = session.get_bind().dialect.name == "sqlite"
        if is_sqlite:
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            account = session.get(GptProAccountModel, int(account_id))
        else:
            account = session.exec(
                select(GptProAccountModel)
                .where(GptProAccountModel.id == int(account_id))
                .with_for_update()
            ).first()
        lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
        if not account or not (
            lease
            and str(lease.token or "") == str(operation_token or "")
            and (_aware_utc(lease.expires_at) or now) > now
        ):
            return False
        extra = _extra_of(account)
        try:
            pending_target_id = int(extra.get("cpa_sync_pending_target_id") or 0)
        except (TypeError, ValueError):
            return False
        if (
            not bool(extra.get("cpa_sync_pending"))
            or str(extra.get("cpa_sync_pending_token") or "")
            != str(operation_token or "")
            or pending_target_id != int(target_id)
            or bool(extra.get("cpa_sync_compensation_pending"))
        ):
            return False
        extra.update({
            "cpa_sync_pending_auth_name": str(auth_name or ""),
            "cpa_sync_pending_remote_started_at": now.isoformat(),
            "cpa_sync_pending_quarantine_until": (
                now + timedelta(seconds=CPA_SYNC_REMOTE_QUARANTINE_SECONDS)
            ).isoformat(),
        })
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = now
        session.add(account)
        session.commit()
        return True


def _prepare_cpa_sync_intent(
    account_id: int,
    target_id: int,
    *,
    expected_business_parent_id: Optional[int],
    operation_token: str,
) -> dict:
    """Persist the remote-write intent while holding the target-config guard."""
    with _CPA_CONFIG_WRITE_LOCK:
        with Session(engine) as session:
            _begin_cpa_config_write(session)
            target = _cpa_sync_target_by_id(target_id)
            if not target:
                raise HTTPException(404, "指定的 CPA 同步目标不存在")
            api_url = str(target.get("api_url") or "").strip()
            if not api_url:
                raise HTTPException(400, "该 CPA 目标未配置地址")
            account = session.get(GptProAccountModel, int(account_id))
            if not account:
                raise HTTPException(404, "账号不存在")
            parent_id = getattr(account, "business_parent_id", None)
            if expected_business_parent_id is None:
                if parent_id is not None:
                    raise HTTPException(
                        409,
                        f"账号已归属 GPT BUSINESS 母号 {parent_id}，请从母号子号接口操作",
                    )
            elif parent_id != int(expected_business_parent_id):
                raise HTTPException(404, "该母号下不存在这个可管理子号")
            if not bool(account.enabled) or bool(account.dangerous):
                raise HTTPException(409, "账号安全状态已变化，不能同步 CPA")
            lease = session.get(
                GptProAccountOperationLeaseModel,
                int(account_id),
            )
            if not (
                lease
                and lease.token == operation_token
                and (_aware_utc(lease.expires_at) or _utcnow()) > _utcnow()
            ):
                raise HTTPException(409, "CPA 同步操作租约已失效，请重试")
            extra = _extra_of(account)
            if extra.get("cpa_cleanup_pending"):
                raise HTTPException(409, "退款后的 CPA 凭据仍在清理中，暂不能重新同步")
            if extra.get("cpa_auto_upload_pending"):
                raise HTTPException(409, "自动号池上传结果仍待核对，暂不能手动同步")
            if extra.get("cpa_sync_pending") or extra.get("cpa_sync_compensation_pending"):
                raise HTTPException(409, "已有 CPA 同步或补偿 intent 未完成，拒绝覆盖")
            now = _utcnow()
            extra.update({
                "cpa_sync_pending": True,
                "cpa_sync_pending_target_id": int(target["id"]),
                "cpa_sync_pending_target_url": api_url.rstrip("/"),
                "cpa_sync_pending_token": operation_token,
                "cpa_sync_pending_auth_name": f"{str(account.email or '').strip()}.json",
                "cpa_sync_pending_started_at": now.isoformat(),
                "cpa_sync_pending_lease_expires_at": _iso_utc(lease.expires_at),
                "cpa_sync_pending_quarantine_until": (
                    now + timedelta(seconds=CPA_SYNC_REMOTE_QUARANTINE_SECONDS)
                ).isoformat(),
                "cpa_sync_pending_last_error": "",
            })
            account.extra_json = json.dumps(extra, ensure_ascii=False)
            account.updated_at = _utcnow()
            session.add(account)
            session.commit()
            return dict(target)


def _mark_cpa_sync_intent_error(
    account_id: int,
    message: str,
    *,
    operation_token: str,
) -> None:
    """Fence stale workers; the pre-written intent needs no stale overwrite."""
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
        if not account or not (
            lease
            and lease.token == operation_token
            and (_aware_utc(lease.expires_at) or _utcnow()) > _utcnow()
        ):
            return
        extra = _extra_of(account)
        extra.update({
            "cpa_sync_pending": True,
            "cpa_sync_pending_last_error": str(message or "CPA 同步失败")[:500],
            "cpa_sync_pending_last_attempt_at": _utcnow().isoformat(),
            "cpa_monitor_suppressed": True,
        })
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()


def _require_cpa_delivery_guard(
    delivery_guard: Optional[Callable[[], Any]],
    stage: str,
) -> None:
    """Run an optional BUSINESS delivery heartbeat immediately before mutation."""
    if delivery_guard is None:
        return
    result = delivery_guard()
    if result is False:
        raise HTTPException(409, f"CPA delivery guard 在{stage}阶段拒绝远端操作")


def _persist_cpa_sync_compensation_intent(
    account_id: int,
    *,
    operation_token: str,
    target_id: int,
    target_url: str,
    auth_name: str,
    reason: str,
) -> bool:
    """Durably bind cleanup to the exact credential uploaded by this worker.

    This deliberately accepts an expired operation lease: expiry is precisely
    why compensation can be required.  The existing sync-intent token and an
    extra_json CAS prevent an old worker from overwriting a newer operation.
    """
    # Unrelated monitor state may legitimately update ``extra_json`` between
    # our read and CAS. Retry from the newest row instead of losing the only
    # durable cleanup record after a confirmed remote upload.
    for _attempt in range(5):
        with Session(engine) as session:
            account = session.get(GptProAccountModel, int(account_id))
            if not account:
                return False
            extra = _extra_of(account)
            try:
                pending_target_id = int(extra.get("cpa_sync_pending_target_id") or 0)
            except (TypeError, ValueError):
                return False
            if (
                not bool(extra.get("cpa_sync_pending"))
                or str(extra.get("cpa_sync_pending_token") or "") != str(operation_token or "")
                or pending_target_id != int(target_id)
            ):
                return False
            if bool(extra.get("cpa_sync_compensation_pending")):
                try:
                    existing_target_id = int(
                        extra.get("cpa_sync_compensation_target_id") or 0
                    )
                except (TypeError, ValueError):
                    return False
                if not (
                    str(extra.get("cpa_sync_compensation_token") or "")
                    == str(operation_token or "")
                    and existing_target_id == int(target_id)
                    and str(extra.get("cpa_sync_compensation_target_url") or "")
                    .rstrip("/").lower()
                    == str(target_url or "").rstrip("/").lower()
                    and str(extra.get("cpa_sync_compensation_auth_name") or "")
                    == str(auth_name or "")
                ):
                    return False
            observed = account.extra_json
            now = _utcnow().isoformat()
            compensation_started_at = str(
                extra.get("cpa_sync_compensation_started_at") or now
            )
            # This helper is called only after the old worker received a
            # successful upload response, so its own in-flight window is over.
            # It may safely shorten a promotion quarantine for the same exact
            # token/target/name and start compensation immediately.
            quarantine_until = now
            extra.update({
                "cpa_sync_compensation_pending": True,
                "cpa_sync_compensation_token": str(operation_token or ""),
                "cpa_sync_compensation_target_id": int(target_id),
                "cpa_sync_compensation_target_url": str(target_url or "").rstrip("/"),
                "cpa_sync_compensation_auth_name": str(auth_name or ""),
                "cpa_sync_compensation_reason": str(reason or "delivery fence changed")[:500],
                "cpa_sync_compensation_started_at": compensation_started_at,
                "cpa_sync_compensation_quarantine_until": quarantine_until,
                "cpa_sync_compensation_last_attempt_at": now,
                "cpa_sync_compensation_last_error": "",
                "cpa_lifecycle_state": "sync_compensation_pending",
                "cpa_monitor_suppressed": True,
            })
            try:
                attempts = int(extra.get("cpa_sync_compensation_attempts") or 0)
            except (TypeError, ValueError):
                attempts = 0
            extra["cpa_sync_compensation_attempts"] = attempts + 1
            changed = session.exec(
                sa_update(GptProAccountModel)
                .where(GptProAccountModel.id == int(account_id))
                .where(GptProAccountModel.extra_json == observed)
                .values(extra_json=json.dumps(extra, ensure_ascii=False), updated_at=_utcnow())
            )
            if int(getattr(changed, "rowcount", 0) or 0) == 1:
                session.commit()
                return True
            session.rollback()
    return False


def _cpa_sync_compensation_is_current(account_id: int, snapshot: dict) -> bool:
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            return False
        extra = _extra_of(account)
    return bool(
        extra.get("cpa_sync_compensation_pending")
        and str(extra.get("cpa_sync_compensation_token") or "")
        == str(snapshot.get("token") or "")
        and int(extra.get("cpa_sync_compensation_target_id") or 0)
        == int(snapshot.get("target_id") or 0)
        and str(extra.get("cpa_sync_compensation_target_url") or "").rstrip("/").lower()
        == str(snapshot.get("target_url") or "").rstrip("/").lower()
        and str(extra.get("cpa_sync_compensation_auth_name") or "")
        == str(snapshot.get("auth_name") or "")
    )


def _disable_exact_cpa_auth_name(
    auth_name: str,
    api_url: str,
    api_key: str,
    *,
    before_request: Optional[Callable[[], bool]] = None,
) -> dict:
    """Disable and confirm one exact auth-file name; never use email substring matching."""
    from services.cpa_manager import list_auth_files, set_auth_file_disabled

    name = str(auth_name or "").strip()
    if not name or not str(api_url or "").strip():
        return {"ok": False, "error": "CPA 补偿目标或凭据名为空"}

    def _guard() -> bool:
        return before_request is None or bool(before_request())

    if not _guard():
        return {"ok": False, "cancelled": True, "error": "CPA 补偿 intent 已被接管"}
    try:
        rows = list_auth_files(api_url=api_url, api_key=api_key)
    except Exception as exc:
        return {"ok": False, "error": f"CPA 补偿列表读取失败: {str(exc)[:240]}"}
    exact = [item for item in rows if str(item.get("name") or "").strip() == name]
    if any(not _cpa_auth_file_is_disabled(item) for item in exact):
        if not _guard():
            return {"ok": False, "cancelled": True, "error": "CPA 补偿 intent 已被接管"}
        try:
            set_auth_file_disabled(name, True, api_url=api_url, api_key=api_key)
        except Exception as exc:
            return {"ok": False, "error": f"CPA 精确补偿停用失败: {str(exc)[:240]}"}
    if not _guard():
        return {"ok": False, "cancelled": True, "error": "CPA 补偿 intent 已被接管"}
    try:
        confirmed = list_auth_files(api_url=api_url, api_key=api_key)
    except Exception as exc:
        return {"ok": False, "error": f"CPA 补偿确认失败: {str(exc)[:240]}"}
    active = [
        item for item in confirmed
        if str(item.get("name") or "").strip() == name
        and not _cpa_auth_file_is_disabled(item)
    ]
    if active:
        return {"ok": False, "error": f"CPA 凭据 {name} 补偿后仍为启用状态"}
    return {"ok": True, "disabled": bool(exact), "missing": not bool(exact)}


def _attempt_cpa_sync_compensation(account_id: int) -> dict:
    """Retry an exact pending post-upload compensation before any new upload."""
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            return {"ok": False, "error": "CPA 补偿账号不存在"}
        extra = _extra_of(account)
    if not bool(extra.get("cpa_sync_compensation_pending")):
        return {"ok": True, "needed": False}
    snapshot = {
        "token": str(extra.get("cpa_sync_compensation_token") or ""),
        "target_id": int(extra.get("cpa_sync_compensation_target_id") or 0),
        "target_url": str(extra.get("cpa_sync_compensation_target_url") or "").rstrip("/"),
        "auth_name": str(extra.get("cpa_sync_compensation_auth_name") or ""),
        "quarantine_until": str(
            extra.get("cpa_sync_compensation_quarantine_until") or ""
        ),
    }
    quarantine_until = _parse_cpa_sync_timestamp(snapshot["quarantine_until"])
    now = _utcnow()
    if quarantine_until and quarantine_until > now:
        remaining = max(1, int((quarantine_until - now).total_seconds()))
        return {
            "ok": False,
            "needed": True,
            "quarantined": True,
            "quarantine_until": quarantine_until.isoformat(),
            "error": f"旧 CPA 上传仍在 {remaining} 秒安全隔离期内，尚不能确认远端缺失",
        }

    def _matches(current: dict) -> bool:
        return bool(
            current.get("cpa_sync_compensation_pending")
            and str(current.get("cpa_sync_compensation_token") or "")
            == snapshot["token"]
            and int(current.get("cpa_sync_compensation_target_id") or 0)
            == snapshot["target_id"]
            and str(current.get("cpa_sync_compensation_target_url") or "").rstrip("/").lower()
            == snapshot["target_url"].lower()
            and str(current.get("cpa_sync_compensation_auth_name") or "")
            == snapshot["auth_name"]
        )

    target = _cpa_sync_target_by_id(snapshot["target_id"])
    if (
        not target
        or str(target.get("api_url") or "").strip().rstrip("/").lower()
        != snapshot["target_url"].lower()
    ):
        result = {"ok": False, "error": "CPA 补偿目标已不存在或地址变化"}
    else:
        result = _disable_exact_cpa_auth_name(
            snapshot["auth_name"],
            snapshot["target_url"],
            str(target.get("api_key") or ""),
            before_request=lambda: _cpa_sync_compensation_is_current(account_id, snapshot),
        )
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            return result
        current = _extra_of(account)
        if not _matches(current):
            return {"ok": False, "error": "CPA 补偿 intent 已被其他操作接管"}
        observed = account.extra_json
        now = _utcnow().isoformat()
        current["cpa_sync_compensation_last_attempt_at"] = now
        if result.get("ok"):
            current["cpa_sync_compensation_pending"] = False
            current["cpa_sync_compensation_completed_at"] = now
            current["cpa_sync_compensation_last_error"] = ""
            current["cpa_lifecycle_state"] = "sync_compensated_disabled"
            # The exact file written by this sync is now confirmed disabled (or
            # absent).  It must never remain advertised as an active linkage.
            # This also covers same-target re-sync, where the failed upload
            # replaced the previously active filename in place.
            current["cpa_synced"] = False
            current["cpa_disabled"] = True
            current["cpa_disabled_at"] = now
            current["cpa_disabled_reason"] = str(
                current.get("cpa_sync_compensation_reason")
                or "CPA 上传后安全补偿已完成"
            )[:500]
            for key in (
                "cpa_synced_to_id",
                "cpa_synced_to_name",
                "cpa_synced_at",
                "cpa_auth_name",
                "cpa_device_id",
                "cpa_config_domain",
                "cpa_api_url",
                "cpa_api_key",
                "cpa_business_parent_id",
            ):
                current.pop(key, None)
            # Remote absence is confirmed, so the original delivery intent no
            # longer needs to pin its target. Keep the compensation audit fields
            # but release the pending target/token before any later fresh sync.
            current["cpa_sync_pending"] = False
            for key in (
                "cpa_sync_pending_target_id",
                "cpa_sync_pending_target_url",
                "cpa_sync_pending_token",
                "cpa_sync_pending_auth_name",
                "cpa_sync_pending_started_at",
                "cpa_sync_pending_lease_expires_at",
                "cpa_sync_pending_remote_started_at",
                "cpa_sync_pending_quarantine_until",
                "cpa_sync_pending_last_error",
                "cpa_sync_pending_last_attempt_at",
            ):
                current.pop(key, None)
        else:
            current["cpa_sync_compensation_last_error"] = str(
                result.get("error") or "CPA 补偿未确认"
            )[:500]
            current["cpa_lifecycle_state"] = "sync_compensation_pending"
        changed = session.exec(
            sa_update(GptProAccountModel)
            .where(GptProAccountModel.id == int(account_id))
            .where(GptProAccountModel.extra_json == observed)
            .values(extra_json=json.dumps(current, ensure_ascii=False), updated_at=_utcnow())
        )
        if int(getattr(changed, "rowcount", 0) or 0) != 1:
            session.rollback()
            return {"ok": False, "error": "CPA 补偿状态被其他操作接管"}
        session.commit()
    return {**result, "needed": True}


def retry_cpa_sync_compensation(account_id: int) -> dict:
    """Internal BUSINESS retry hook; performs cleanup only and never uploads."""
    return _attempt_cpa_sync_compensation(int(account_id))


def _probe_uploaded_cpa_credential(
    *,
    auth_name: str,
    chatgpt_account_id: str,
    api_url: str,
    api_key: str,
) -> dict:
    """Run an exact post-upload health probe and return only safe diagnostics."""
    from services.cliproxyapi_sync import probe_uploaded_auth_file

    try:
        result = probe_uploaded_auth_file(
            auth_name,
            chatgpt_account_id,
            api_url=api_url,
            api_key=api_key,
        )
    except Exception:
        result = {
            "remote_state": "unreachable",
            "last_probe_status_code": 0,
            "last_probe_error_code": "",
        }
    state = str(result.get("remote_state") or "unknown").strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{1,64}", state):
        state = "unknown"
    try:
        status_code = int(result.get("last_probe_status_code") or 0)
    except (TypeError, ValueError):
        status_code = 0
    error_code = str(result.get("last_probe_error_code") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", error_code):
        error_code = ""
    return {
        "ok": state == "usable" and status_code == 200,
        "remote_state": state,
        "status_code": status_code,
        "error_code": error_code,
    }


def _cpa_health_failure_reason(probe: dict) -> str:
    """Format a bounded diagnostic without forwarding upstream bodies/tokens."""
    state = str(probe.get("remote_state") or "unknown")
    try:
        status_code = int(probe.get("status_code") or 0)
    except (TypeError, ValueError):
        status_code = 0
    error_code = str(probe.get("error_code") or "")
    parts = [f"state={state}"]
    if status_code:
        parts.append(f"HTTP {status_code}")
    if error_code:
        parts.append(f"code={error_code}")
    return "CPA 凭证健康检查失败（" + "，".join(parts) + "）"


def _upload_plan_account_to_cpa(
    account_id: int,
    api_url: str,
    api_key: str,
    *,
    expected_business_parent_id: Optional[int],
    operation_token: str,
    credential_bundle: dict[str, str],
    before_remote_mutation: Optional[Callable[[], Any]] = None,
) -> tuple[bool, str]:
    """Upload one plan-owned credential without consulting the retired pool.

    The surrounding orchestration owns the durable intent, exact health probe,
    compensation, linkage and lease lifecycle.  This helper deliberately does
    only the fenced remote write; the retired CPA auto-pool orchestration must
    not become the repository owner of this plan/device flow again.
    """
    account = _require_cpa_account_scope(
        int(account_id),
        expected_business_parent_id=expected_business_parent_id,
    )
    if not _gpt_pro_account_operation_token_is_current(
        int(account_id), str(operation_token or ""),
    ):
        return False, "CPA 上传操作租约已失效"
    access_token = str(credential_bundle.get("access_token") or "").strip()
    refresh_token = str(credential_bundle.get("refresh_token") or "").strip()
    if not access_token or not refresh_token:
        return False, "OAuth 凭证不完整，拒绝上传 CPA"
    if before_remote_mutation is not None:
        try:
            if before_remote_mutation() is False:
                return False, "CPA delivery guard 拒绝远端上传"
        except HTTPException:
            raise
        except Exception as exc:
            return False, f"CPA delivery guard 失败: {exc}"
    if not _gpt_pro_account_operation_token_is_current(
        int(account_id), str(operation_token or ""),
    ):
        return False, "CPA 上传前操作租约已失效"
    # Re-read scope after the callback because it may yield while another
    # BUSINESS workflow changes child ownership.
    _require_cpa_account_scope(
        int(account_id),
        expected_business_parent_id=expected_business_parent_id,
    )
    from platforms.chatgpt.cpa_upload import upload_to_cpa

    try:
        return upload_to_cpa(
            {
                "type": "codex",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "email": str(account.email or "").strip(),
            },
            api_url=api_url,
            api_key=api_key,
            filename=f"{str(account.email or '').strip()}.json",
        )
    except Exception as exc:
        return False, f"CPA 上传结果无法确认: {exc}"


def _sync_account_to_cpa_claimed(
    account_id: int,
    target_id: int,
    *,
    expected_business_parent_id: Optional[int] = None,
    operation_token: str = "",
    delivery_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    """把 GPT PRO 记录的 Codex 凭证安全同步到现有 CPA 目标。

    BUSINESS 子号代理接口必须传 ``expected_business_parent_id``；不传时
    仅允许未归属 BUSINESS 的 GPT PRO 账号。CPA 目标完全复用
    ``gpt_pro_cpa_sync_targets``，调用方不能传任意 URL / API key。
    """
    recovery = _promote_stale_cpa_sync_pending(
        account_id,
        operation_token=operation_token,
    )
    if bool(recovery.get("active")):
        raise HTTPException(
            409,
            "已有相同租约的 CPA 上传 intent 正在执行，拒绝重复请求",
        )
    compensation = _attempt_cpa_sync_compensation(account_id)
    if not bool(compensation.get("ok")):
        raise HTTPException(
            502,
            "上次 CPA 上传的精确停用补偿尚未确认，拒绝再次上传: "
            + str(compensation.get("error") or "未知错误")[:500],
        )
    _require_cpa_delivery_guard(delivery_guard, "同步准备")
    tgt = _cpa_sync_target_by_id(target_id)
    if not tgt:
        raise HTTPException(404, "指定的 CPA 同步目标不存在")
    api_url = str(tgt.get("api_url") or "").strip()
    api_key = str(tgt.get("api_key") or "").strip()
    if not api_url:
        raise HTTPException(400, "该 CPA 目标未配置地址")

    acc = _require_cpa_account_scope(
        account_id,
        expected_business_parent_id=expected_business_parent_id,
    )
    # 无 codex RT → 先补(启浏览器 + 读邮箱验证码, 约 1~2 分钟)
    if not (acc.codex_refresh_token or "").strip():
        _rt_logs: List[str] = []
        if not _reacquire_parent_codex_rt(acc, lambda m: _rt_logs.append(str(m))):
            tail = " / ".join(_rt_logs[-3:]) if _rt_logs else "未知原因"
            raise HTTPException(400, f"该账号无 codex RT 且自动补 RT 失败: {tail}")

    # 与 Sub2API 同步保持一致：每次远端上传前都用 RT 换取新 AT，并要求
    # 轮换后的 AT/RT 已可靠落库。这个动作发生在 durable upload intent 和
    # 旧设备停用之前，因此刷新失败不会留下任何 CPA 侧副作用。
    acc = _require_cpa_account_scope(
        account_id,
        expected_business_parent_id=expected_business_parent_id,
    )
    _require_cpa_delivery_guard(delivery_guard, "OAuth 凭证刷新")
    _fresh_access_token, chatgpt_account_id = _gpt_pro_resolve_codex_credentials(
        acc,
        _require_persist=True,
    )

    # OAuth/自动补 RT 可能耗时较长；上传前重读并再次校验归属和租约，
    # 避免期间子号已被释放/移到另一个母号却仍把凭证推送到 CPA。
    refreshed_acc = _require_cpa_account_scope(
        account_id,
        expected_business_parent_id=expected_business_parent_id,
    )
    refreshed_rt = str(refreshed_acc.codex_refresh_token or "").strip()
    if not refreshed_rt:
        raise HTTPException(
            500,
            "OAuth 凭证刷新后 refresh_token 未持久化，已中止 CPA 同步",
        )
    credential_bundle = {
        "access_token": str(_fresh_access_token or "").strip(),
        "refresh_token": refreshed_rt,
        "chatgpt_account_id": chatgpt_account_id,
    }

    if operation_token and not _gpt_pro_account_operation_token_is_current(
        account_id, operation_token,
    ):
        raise HTTPException(409, "CPA 同步操作租约已失效，请重试")
    _require_cpa_delivery_guard(delivery_guard, "同步 intent")

    # This durable intent is written before disabling an old target or uploading
    # the first credential.  Target deletion/repointing scans the same row in a
    # serialized config transaction and therefore cannot race this upload.
    tgt = _prepare_cpa_sync_intent(
        account_id,
        int(tgt["id"]),
        expected_business_parent_id=expected_business_parent_id,
        operation_token=operation_token,
    )
    api_url = str(tgt.get("api_url") or "").strip()
    api_key = str(tgt.get("api_key") or "").strip()

    # A→B 重同步先安全停用并重新确认 A，再上传 B。旧设备停用失败时
    # 不会触碰 B，更不会覆盖旧 linkage。共享 target 已删除则 fail closed，
    # 不能退回 extra_json 里的历史 key。
    with Session(engine) as s:
        current = s.get(GptProAccountModel, account_id)
        current_extra = _extra_of(current) if current else {}
        current_email = str(getattr(current, "email", "") or "").strip()
    old_manual_target_id = 0
    try:
        old_manual_target_id = int(current_extra.get("cpa_synced_to_id") or 0)
    except (TypeError, ValueError):
        old_manual_target_id = 0
    current_domain = str(current_extra.get("cpa_config_domain") or "").strip().lower()
    old_api_url, old_api_key = _resolve_cpa_endpoint(current_extra)
    same_manual_target = bool(
        current_extra.get("cpa_synced")
        and old_manual_target_id
        and old_manual_target_id == int(tgt["id"])
        and current_domain in {"", _CPA_CONFIG_DOMAIN_MANUAL}
    )
    same_legacy_endpoint = bool(
        current_extra.get("cpa_synced")
        and not old_manual_target_id
        and str(old_api_url or "").rstrip("/").lower()
        == str(api_url or "").rstrip("/").lower()
    )
    switching_target = bool(
        current_extra.get("cpa_synced")
        and not same_manual_target
        and not same_legacy_endpoint
    )
    if switching_target:
        if not old_api_url:
            message = "旧 CPA 共享目标已删除或无法解析；拒绝使用账号历史 key 自动迁移"
            _patch_gpt_pro_extra(account_id, {
                "cpa_migration_pending": True,
                "cpa_migration_target_id": int(tgt["id"]),
                "cpa_migration_last_error": message,
                "cpa_lifecycle_state": "migration_blocked",
                "cpa_monitor_suppressed": True,
            })
            _record_cpa_monitor_alert(account_id, "cpa_migration_blocked", message)
            raise HTTPException(409, message)
        if operation_token and not _gpt_pro_account_operation_token_is_current(
            account_id, operation_token,
        ):
            raise HTTPException(409, "CPA 同步操作租约已失效，请重试")
        def _before_old_target_mutation():
            _require_cpa_delivery_guard(delivery_guard, "旧 CPA 目标停用")
            return (
                not operation_token
                or _gpt_pro_account_operation_token_is_current(account_id, operation_token)
            )

        _require_cpa_delivery_guard(delivery_guard, "旧 CPA 目标停用准备")
        disabled = _disable_cpa_email_at_endpoint(
            current_email,
            old_api_url,
            old_api_key,
            before_mutation=_before_old_target_mutation,
        )
        if not disabled.get("ok"):
            message = str(disabled.get("error") or "旧 CPA 凭据停用失败")[:500]
            if _gpt_pro_account_operation_token_is_current(account_id, operation_token):
                _patch_gpt_pro_extra(account_id, {
                    "cpa_migration_pending": True,
                    "cpa_migration_target_id": int(tgt["id"]),
                    "cpa_migration_last_error": message,
                    "cpa_lifecycle_state": "migration_blocked",
                    "cpa_monitor_suppressed": True,
                })
                _record_cpa_monitor_alert(account_id, "cpa_migration_blocked", message)
            raise HTTPException(502, f"切换 CPA 设备失败，旧设备尚未确认停用: {message}")
        _patch_gpt_pro_extra(account_id, {
            "cpa_migration_pending": True,
            "cpa_migration_target_id": int(tgt["id"]),
            "cpa_migration_source_disabled": True,
            "cpa_migration_started_at": _utcnow().isoformat(),
            "cpa_lifecycle_state": "migration_source_disabled",
            "cpa_monitor_suppressed": True,
            "cpa_disabled": True,
            "cpa_disabled_reason": "正在切换 CPA 共享目标",
        })

    def _before_target_upload():
        # Persist the bounded in-flight window first. If another process steals
        # the lease immediately afterwards, its recovery must quarantine this
        # exact request before accepting remote absence or issuing a new POST.
        if not _mark_cpa_sync_remote_write_started(
            account_id,
            operation_token=operation_token,
            target_id=int(tgt["id"]),
            auth_name=f"{current_email}.json",
        ):
            raise HTTPException(409, "CPA 上传 intent 或账号租约已变化")
        _require_cpa_delivery_guard(delivery_guard, "CPA 目标上传")
        return True

    ok, msg = _upload_plan_account_to_cpa(
        account_id,
        api_url,
        api_key,
        expected_business_parent_id=expected_business_parent_id,
        operation_token=operation_token,
        credential_bundle=credential_bundle,
        before_remote_mutation=_before_target_upload,
    )
    if not ok:
        _mark_cpa_sync_intent_error(
            account_id,
            str(msg or "新 CPA 目标上传失败"),
            operation_token=operation_token,
        )
        if switching_target:
            migration_error = str(msg or "新 CPA 目标上传失败")[:500]
            if _gpt_pro_account_operation_token_is_current(account_id, operation_token):
                _patch_gpt_pro_extra(account_id, {
                    "cpa_migration_pending": True,
                    "cpa_migration_target_id": int(tgt["id"]),
                    "cpa_migration_last_error": migration_error,
                    "cpa_lifecycle_state": "migration_source_disabled",
                    "cpa_monitor_suppressed": True,
                })
                _record_cpa_monitor_alert(
                    account_id,
                    "cpa_migration_upload_failed",
                    f"旧 CPA 目标已停用，新目标上传失败：{migration_error}",
                )
        raise HTTPException(502, f"同步到 CPA 失败: {msg}")
    # The remote write is now known to have succeeded.  A failed delivery fence
    # can no longer be handled as a normal retry: persist an exact compensation
    # intent first, then best-effort disable only the file just uploaded.
    try:
        if not _gpt_pro_account_operation_token_is_current(
            account_id, operation_token,
        ):
            raise HTTPException(409, "CPA 上传后操作租约已失效")
        _require_cpa_account_scope(
            account_id,
            expected_business_parent_id=expected_business_parent_id,
        )
        _require_cpa_delivery_guard(delivery_guard, "CPA 上传后确认")
    except Exception as guard_exc:
        auth_name = f"{current_email}.json"
        reason = f"CPA 上传成功后 delivery fence 失效: {guard_exc}"
        persisted = _persist_cpa_sync_compensation_intent(
            account_id,
            operation_token=operation_token,
            target_id=int(tgt["id"]),
            target_url=api_url,
            auth_name=auth_name,
            reason=reason,
        )
        compensated = (
            _attempt_cpa_sync_compensation(account_id)
            if persisted else {"ok": False, "error": "补偿 intent CAS 失败"}
        )
        if compensated.get("ok"):
            raise HTTPException(409, reason + "；已确认精确停用刚上传的凭据")
        raise HTTPException(
            502,
            reason + "；补偿未确认，已持久化等待重试: "
            + str(compensated.get("error") or "未知错误")[:500],
        )

    # A successful upload response only confirms the management write.  Verify
    # the exact filename through CPA's own token substitution before publishing
    # local linkage.  Invalidated/stale ATs are immediately compensated and can
    # therefore never become a seemingly healthy ``cpa_synced`` record.
    auth_name = f"{current_email}.json"
    probe = _probe_uploaded_cpa_credential(
        auth_name=auth_name,
        chatgpt_account_id=chatgpt_account_id,
        api_url=api_url,
        api_key=api_key,
    )
    if not bool(probe.get("ok")):
        reason = _cpa_health_failure_reason(probe)
        persisted = _persist_cpa_sync_compensation_intent(
            account_id,
            operation_token=operation_token,
            target_id=int(tgt["id"]),
            target_url=api_url,
            auth_name=auth_name,
            reason=reason,
        )
        compensated = (
            _attempt_cpa_sync_compensation(account_id)
            if persisted else {"ok": False, "error": "补偿 intent CAS 失败"}
        )
        if switching_target and _gpt_pro_account_operation_token_is_current(
            account_id, operation_token,
        ):
            _patch_gpt_pro_extra(account_id, {
                "cpa_migration_pending": True,
                "cpa_migration_target_id": int(tgt["id"]),
                "cpa_migration_last_error": reason,
                "cpa_lifecycle_state": (
                    "migration_source_disabled"
                    if compensated.get("ok")
                    else "sync_compensation_pending"
                ),
                "cpa_monitor_suppressed": True,
            })
        _record_cpa_monitor_alert(
            account_id,
            "cpa_upload_health_failed",
            reason,
        )
        if compensated.get("ok"):
            raise HTTPException(
                502,
                reason + "；已确认精确停用刚上传的无效凭据",
            )
        raise HTTPException(
            502,
            reason + "；精确停用尚未确认，已持久化等待补偿: "
            + str(compensated.get("error") or "未知错误")[:500],
        )
    # 上传完成后再校验一次。若网络请求期间归属发生变化，立即把新凭证
    # 归入 BUSINESS 安全生命周期并停用，不能继续以 GPT PRO 凭证运行。
    try:
        _require_cpa_account_scope(
            account_id,
            expected_business_parent_id=expected_business_parent_id,
        )
    except HTTPException:
        if _gpt_pro_account_operation_token_is_current(account_id, operation_token):
            _patch_gpt_pro_extra(account_id, {
                "cpa_account_kind": "business_child",
                "cpa_lifecycle_state": "assignment_changed_during_sync",
                "cpa_monitor_suppressed": True,
            })
            disable_released_business_child_cpa(
                account_id,
                reason="assignment_changed_during_cpa_sync",
                operation_token=operation_token,
            )
        raise
    # Revalidate the shared target under the same config guard before making
    # linkage active.  A stale worker cannot silently bind to a deleted/repointed
    # target after its remote request returns.
    with _CPA_CONFIG_WRITE_LOCK:
        with Session(engine) as s:
            _require_cpa_delivery_guard(delivery_guard, "CPA linkage 提交")
            _begin_cpa_config_write(s)
            current_target = _cpa_sync_target_by_id(int(tgt["id"]))
            if (
                not current_target
                or str(current_target.get("api_url") or "").strip().rstrip("/").lower()
                != api_url.rstrip("/").lower()
            ):
                message = "CPA 目标在上传期间被删除或更换地址；保留同步 pending 等待人工核对"
                row = s.get(GptProAccountModel, account_id)
                if row:
                    pending_extra = _extra_of(row)
                    pending_extra.update({
                        "cpa_sync_pending": True,
                        "cpa_sync_pending_last_error": message,
                        "cpa_sync_pending_last_attempt_at": _utcnow().isoformat(),
                        "cpa_monitor_suppressed": True,
                    })
                    row.extra_json = json.dumps(pending_extra, ensure_ascii=False)
                    row.updated_at = _utcnow()
                    s.add(row)
                    s.commit()
                raise HTTPException(409, message)
            row = s.get(GptProAccountModel, account_id)
            if row:
                lease = s.get(
                    GptProAccountOperationLeaseModel,
                    int(account_id),
                )
                if not (
                    lease
                    and lease.token == operation_token
                    and (_aware_utc(lease.expires_at) or _utcnow()) > _utcnow()
                ):
                    raise HTTPException(409, "CPA 同步操作租约已失效，请重试")
            try:
                extra = json.loads(row.extra_json) if row.extra_json else {}
            except Exception:
                extra = {}
            extra["cpa_synced_to_id"] = int(tgt["id"])
            extra["cpa_synced_to_name"] = tgt.get("name") or api_url
            extra["cpa_device_id"] = int(tgt["id"])
            extra["cpa_config_domain"] = _CPA_CONFIG_DOMAIN_MANUAL
            extra["cpa_synced"] = True
            extra["cpa_auth_name"] = f"{row.email}.json"
            extra["cpa_synced_at"] = _utcnow().isoformat()
            extra["cpa_account_kind"] = (
                "business_child"
                if expected_business_parent_id is not None
                else "gpt_pro"
            )
            if expected_business_parent_id is not None:
                extra["cpa_business_parent_id"] = int(expected_business_parent_id)
            else:
                extra.pop("cpa_business_parent_id", None)
            extra["cpa_lifecycle_state"] = "active"
            extra["cpa_monitor_suppressed"] = False
            extra["cpa_disabled"] = False
            extra.pop("cpa_disabled_at", None)
            extra.pop("cpa_disabled_reason", None)
            extra.pop("cpa_monitor_alert", None)
            try:
                generation = int(extra.get("cpa_lifecycle_generation") or 0)
            except (TypeError, ValueError):
                generation = 0
            extra["cpa_lifecycle_generation"] = generation + 1
            for key in _CPA_DISABLE_PENDING_FIELDS:
                extra.pop(key, None)
            for key in (
                "cpa_disable_token",
                "cpa_api_url",
                "cpa_api_key",
                "cpa_migration_pending",
                "cpa_migration_target_id",
                "cpa_migration_source_disabled",
                "cpa_migration_started_at",
                "cpa_migration_last_error",
                "cpa_sync_pending",
                "cpa_sync_pending_target_id",
                "cpa_sync_pending_target_url",
                "cpa_sync_pending_token",
                "cpa_sync_pending_auth_name",
                "cpa_sync_pending_started_at",
                "cpa_sync_pending_lease_expires_at",
                "cpa_sync_pending_remote_started_at",
                "cpa_sync_pending_quarantine_until",
                "cpa_sync_pending_last_error",
                "cpa_sync_pending_last_attempt_at",
                "cpa_sync_compensation_pending",
                "cpa_sync_compensation_token",
                "cpa_sync_compensation_target_id",
                "cpa_sync_compensation_target_url",
                "cpa_sync_compensation_auth_name",
                "cpa_sync_compensation_reason",
                "cpa_sync_compensation_started_at",
                "cpa_sync_compensation_quarantine_until",
                "cpa_sync_compensation_last_attempt_at",
                "cpa_sync_compensation_last_error",
                "cpa_sync_compensation_attempts",
                "cpa_sync_compensation_completed_at",
                "cpa_rotation_ready_at",
                "cpa_rotation_reason",
            ):
                extra.pop(key, None)
            row.extra_json = json.dumps(extra, ensure_ascii=False)
            row.updated_at = _utcnow()
            s.add(row)
            s.commit()
            return {"ok": True, **serialize_gpt_pro_cpa_status(row)}
    return {"ok": True}


def sync_account_to_cpa(
    account_id: int,
    target_id: int,
    *,
    expected_business_parent_id: Optional[int] = None,
    operation_token: str = "",
    delivery_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    """Claim the shared account lease when called outside an already leased route."""
    owned_token = ""
    if not operation_token:
        owned_token = _claim_gpt_pro_account_operation(
            account_id,
            "cpa_sync",
            allow_managed_business_child=expected_business_parent_id is not None,
        )
        operation_token = owned_token
    try:
        return _sync_account_to_cpa_claimed(
            account_id,
            target_id,
            expected_business_parent_id=expected_business_parent_id,
            operation_token=operation_token,
            delivery_guard=delivery_guard,
        )
    finally:
        if owned_token:
            _release_gpt_pro_account_operation(account_id, owned_token)


@router.post("/accounts/{account_id}/sync-cpa")
def gpt_pro_sync_cpa(account_id: int, body: GptProSyncCpaRequest):
    """把该 PRO 账号的 Codex 凭证推送到指定 CPA 设备。

    GPT BUSINESS 子号必须走 BUSINESS 母号下的代理路由，以校验当前归属。
    """
    operation_token = _claim_gpt_pro_account_operation(account_id, "cpa_sync")
    try:
        return sync_account_to_cpa(
            account_id,
            body.target_id,
            operation_token=operation_token,
        )
    finally:
        _release_gpt_pro_account_operation(account_id, operation_token)


@router.post("/cpa-reconcile-synced")
def gpt_pro_reconcile_cpa_synced():
    """核对已配置的 CPA 设备上实际存在的凭证, 把匹配到的 GPT PRO 账号回填标记为"已同步"(处理老数据)。

    对每台同步目标设备 list_auth_files → 按邮箱匹配账号 → 写 extra 的 cpa_* 字段。
    只认 active 凭证；同一邮箱在多台设备 active 时报告冲突，绝不按列表
    顺序覆盖。写回前会重新读取远端并使用账号租约 + extra_json CAS。
    """
    targets, reconcile_revision = _cpa_sync_targets_snapshot()
    if not targets:
        raise HTTPException(400, "未配置任何 CPA 同步目标(设备),请先在「CPA设备」里添加")
    from services.cpa_manager import list_auth_files
    # 先拉每台设备的文件
    dev_files: List[tuple] = []   # [(tgt, [files])]
    device_summ: List[dict] = []
    errors: List[str] = []
    for tgt in targets:
        url = str(tgt.get("api_url") or "").strip()
        key = str(tgt.get("api_key") or "").strip()
        if not url:
            continue
        try:
            files = list_auth_files(api_url=url, api_key=key)
        except Exception as e:
            errors.append(f"{tgt.get('name') or url}: {e}")
            continue
        dev_files.append((tgt, files))
        device_summ.append({"name": tgt.get("name") or url, "files": len(files)})

    marked: List[dict] = []
    with Session(engine) as s:
        account_refs = []
        for account in s.exec(select(GptProAccountModel)).all():
            state = _extra_of(account)
            if any(state.get(key) for key in (
                "cpa_sync_pending",
                "cpa_migration_pending",
                "cpa_cleanup_pending",
                "cpa_disable_pending",
                "cpa_auto_upload_pending",
            )):
                continue
            if account.id is not None and str(account.email or "").strip():
                account_refs.append((int(account.id), str(account.email or "")))

    for account_id, email in account_refs:
        em = email.strip().lower()
        safe = _cpa_safe_email_key(email)
        cached_candidates = [
            (tgt, f)
            for tgt, files in dev_files
            for f in files
            if not bool(f.get("disabled")) and _cpa_file_identifies(f, em, safe)
        ]
        cached_target_ids = {int(tgt.get("id") or 0) for tgt, _ in cached_candidates}
        if len(cached_target_ids) > 1:
            errors.append(f"{email}: 多个 active CPA 目标命中，未覆盖本地 linkage")
            continue
        if not cached_candidates:
            continue

        try:
            lease_token = _claim_gpt_pro_account_operation(
                account_id,
                "cpa_reconcile",
                allow_managed_business_child=True,
            )
        except HTTPException as exc:
            errors.append(f"{email}: reconcile 账号忙 ({exc.detail})")
            continue
        try:
            # Cached snapshots may be stale by the time we own the account.
            # Re-list every configured target and require exactly one active
            # target before any database write.
            fresh_candidates: List[tuple] = []
            for target in targets:
                url = str(target.get("api_url") or "").strip()
                key = str(target.get("api_key") or "").strip()
                if not url:
                    continue
                try:
                    fresh_files = list_auth_files(api_url=url, api_key=key)
                except Exception as exc:
                    errors.append(f"{email}: {target.get('name') or url} 复核失败: {exc}")
                    fresh_candidates = []
                    break
                fresh_candidates.extend(
                    (target, item)
                    for item in fresh_files
                    if not bool(item.get("disabled"))
                    and _cpa_file_identifies(item, em, safe)
                )
            fresh_target_ids = {
                int(target.get("id") or 0)
                for target, _ in fresh_candidates
            }
            if len(fresh_target_ids) > 1:
                errors.append(f"{email}: 多个 active CPA 目标命中，未覆盖本地 linkage")
                continue
            if len(fresh_target_ids) != 1 or not fresh_candidates:
                continue
            target, auth_file = fresh_candidates[0]
            target_id = int(target.get("id") or 0)
            with _CPA_CONFIG_WRITE_LOCK:
                with Session(engine) as s:
                    _begin_cpa_config_write(s)
                    from core.config_store import ConfigItem
                    revision_item = s.get(
                        ConfigItem,
                        _CPA_SYNC_TARGETS_REVISION_KEY,
                    )
                    try:
                        current_revision = (
                            int(revision_item.value or 0)
                            if revision_item else 0
                        )
                    except (TypeError, ValueError):
                        current_revision = 0
                    if current_revision != reconcile_revision:
                        errors.append(
                            f"{email}: CPA 目标配置在 reconcile 期间变化，未写回"
                        )
                        continue
                    current_target = _cpa_sync_target_by_id(target_id)
                    if (
                        not current_target
                        or str(current_target.get("api_url") or "").strip().rstrip("/").lower()
                        != str(target.get("api_url") or "").strip().rstrip("/").lower()
                    ):
                        errors.append(f"{email}: CPA 目标配置在 reconcile 期间变化，未写回")
                        continue
                    account = s.get(GptProAccountModel, account_id)
                    if not account:
                        continue
                    observed_extra_json = str(account.extra_json or "{}")
                    extra = _extra_of(account)
                    if (
                        extra.get("cpa_synced")
                        and int(extra.get("cpa_synced_to_id") or 0) == target_id
                        and extra.get("cpa_config_domain") == _CPA_CONFIG_DOMAIN_MANUAL
                        and "cpa_api_key" not in extra
                        and "cpa_api_url" not in extra
                    ):
                        continue
                    if not _gpt_pro_account_operation_is_current(
                        s,
                        account_id,
                        lease_token,
                        "cpa_reconcile",
                    ):
                        errors.append(f"{email}: reconcile 租约已失效，未写回")
                        continue
                    extra["cpa_synced"] = True
                    extra["cpa_auth_name"] = auth_file.get("name") or f"{email}.json"
                    extra["cpa_device_id"] = target_id
                    extra["cpa_synced_to_id"] = target_id
                    extra["cpa_synced_to_name"] = target.get("name") or target.get("api_url")
                    extra["cpa_config_domain"] = _CPA_CONFIG_DOMAIN_MANUAL
                    extra.pop("cpa_api_url", None)
                    extra.pop("cpa_api_key", None)
                    extra["cpa_synced_at"] = extra.get("cpa_synced_at") or _utcnow().isoformat()
                    new_extra_json = json.dumps(extra, ensure_ascii=False)
                    now = _utcnow()
                    result = s.execute(
                        sa_update(GptProAccountModel)
                        .where(GptProAccountModel.id == account_id)
                        .where(GptProAccountModel.extra_json == observed_extra_json)
                        .values(extra_json=new_extra_json, updated_at=now)
                    )
                    if result.rowcount != 1:
                        s.rollback()
                        errors.append(f"{email}: 账号版本在 reconcile 期间变化，未覆盖")
                        continue
                    s.commit()
                    marked.append({
                        "id": account_id,
                        "email": email,
                        "device": target.get("name") or target.get("api_url"),
                    })
        finally:
            _release_gpt_pro_account_operation(account_id, lease_token)
    return {"ok": True, "marked": len(marked), "accounts": marked,
            "devices": device_summ, "errors": errors}


def get_account_cpa_usage(
    account_id: int,
    *,
    expected_business_parent_id: Optional[int] = None,
) -> dict:
    """安全查询账号在已同步 CPA 设备上的真实额度。

    经 CPA 的 /v0/management/api-call 中转打 chatgpt wham/usage(用 CPA 存的 token, 不本地碰 RT)。
    BUSINESS 子号调用时必须传 ``expected_business_parent_id``。
    """
    acc = _require_cpa_account_scope(
        account_id,
        expected_business_parent_id=expected_business_parent_id,
    )
    email = acc.email
    ex = _extra_of(acc)
    if not ex.get("cpa_synced"):
        raise HTTPException(400, "该账号尚未同步到任何 CPA 设备,无法查额度")
    if (ex.get("cpa_monitor_suppressed")
            or ex.get("cpa_business_membership_stale")):
        raise HTTPException(409, "该账号 CPA 监控已停止(可能已从 BUSINESS 母号释放)")
    api_url, api_key = _resolve_cpa_endpoint(ex)   # 优先用目标列表当前 key
    if not api_url:
        raise HTTPException(400, "找不到该账号所属的 CPA 设备地址")

    from services.cpa_manager import list_auth_files
    from services.gpt_pro_cpa_manager import _fetch_account_usage
    try:
        files = list_auth_files(api_url=api_url, api_key=api_key)
    except Exception as e:
        raise HTTPException(502, f"读取 CPA auth-files 失败: {e}")
    el = (email or "").lower()
    safe = _cpa_safe_email_key(email)
    match = next((f for f in files if _cpa_file_identifies(f, el, safe)), None)
    if not match:
        raise HTTPException(404, f"CPA 设备上找不到 {email} 的凭证(未同步成功或已被删)")
    idt = match.get("id_token") or {}
    usage = _fetch_account_usage(api_url, api_key, match.get("auth_index"), idt.get("chatgpt_account_id"))
    if usage is None:
        raise HTTPException(502, "CPA 中转查额度失败(token 可能已失效或被限流)")
    payload = _cache_cpa_usage(account_id, usage)   # 落库, 前端直接读, 整点任务刷新
    return {"ok": True, **payload}


@router.get("/accounts/{account_id}/cpa-usage")
def gpt_pro_cpa_usage(account_id: int):
    """GPT PRO 页面的 CPA 额度查询入口。"""
    return get_account_cpa_usage(account_id)


class GptProSyncSub2ApiRequest(BaseModel):
    device_id: int


class GptProSub2ApiAutoRemoveRequest(BaseModel):
    enabled: bool


def _sub2api_auto_remove_enabled() -> bool:
    from core.config_store import config_store

    raw = config_store.get(_SUB2API_AUTO_REMOVE_CONFIG_KEY, "false")
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


@router.get("/sub2api-auto-remove")
def gpt_pro_get_sub2api_auto_remove():
    """Read the destructive quota-exhaustion policy (disabled by default)."""
    return {"enabled": _sub2api_auto_remove_enabled()}


@router.put("/sub2api-auto-remove")
def gpt_pro_put_sub2api_auto_remove(body: GptProSub2ApiAutoRemoveRequest):
    """Explicitly opt in/out of confirmed remote deletion after exhaustion."""
    from core.config_store import config_store

    config_store.set(_SUB2API_AUTO_REMOVE_CONFIG_KEY, "true" if body.enabled else "false")
    return {"ok": True, "enabled": bool(body.enabled)}


def _sub2api_device_or_error(device_id: int, *, require_enabled: bool = True) -> dict:
    with Session(engine) as session:
        device = session.get(SyncDeviceModel, int(device_id))
        if not device:
            raise HTTPException(404, "指定的 Sub2API 设备不存在")
        if _sub2api_device_type(device.type) != "sub2api":
            raise HTTPException(400, "指定设备不是 Sub2API 类型")
        if str(device.platform or "chatgpt").strip().lower() not in {"", "chatgpt"}:
            raise HTTPException(400, "指定 Sub2API 设备不属于 ChatGPT 平台")
        if require_enabled and not bool(device.enabled):
            raise HTTPException(409, "指定 Sub2API 设备已停用")
        api_url = str(device.api_url or "").strip().rstrip("/")
        api_key = str(device.api_key or "").strip()
        if not api_url or not api_key:
            raise HTTPException(400, "Sub2API 设备地址或 API Key 未配置")
        return {
            "id": int(device.id or 0),
            "name": str(device.name or api_url),
            "api_url": api_url,
            "api_key": api_key,
            "group_ids": str(device.sub_group_ids or "2"),
            "enabled": bool(device.enabled),
        }


def _require_sub2api_account_scope(
    account_id: int,
    *,
    require_healthy: bool = True,
    expected_business_parent_id: Optional[int] = None,
) -> GptProAccountModel:
    """Load one account within the explicit GPT PRO / BUSINESS boundary.

    A normal GPT PRO caller omits ``expected_business_parent_id`` and therefore
    cannot operate a managed BUSINESS child.  A BUSINESS proxy/worker must pass
    the exact current parent id; a child attached to another parent is exposed
    as not-found rather than leaking its assignment.
    """
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        parent_id = getattr(account, "business_parent_id", None)
        if expected_business_parent_id is None:
            if parent_id is not None:
                raise HTTPException(
                    409,
                    f"账号已归属 GPT BUSINESS 母号 {parent_id}，请从母号子号接口操作",
                )
        elif parent_id != int(expected_business_parent_id):
            raise HTTPException(404, "该母号下不存在这个可管理子号")
        if require_healthy:
            if not bool(account.enabled):
                raise HTTPException(409, "账号已被禁用，不能操作 Sub2API")
            if bool(account.dangerous):
                raise HTTPException(409, "账号已标记 dead，不能操作 Sub2API")
            if str(account.refund_status or "").strip():
                raise HTTPException(409, "退款流程中的账号不能同步或刷新 Sub2API")
        return account


def _sub2api_parent_scope_matches(
    account: GptProAccountModel,
    expected_business_parent_id: Optional[int],
) -> bool:
    parent_id = getattr(account, "business_parent_id", None)
    if expected_business_parent_id is None:
        return parent_id is None
    return parent_id == int(expected_business_parent_id)


def _sub2api_operation_fence_is_current(
    session: Session,
    account: GptProAccountModel,
    *,
    operation_token: str,
    expected_business_parent_id: Optional[int],
) -> bool:
    """Check lease ownership and parent assignment in the same DB session."""
    if not operation_token or not _sub2api_parent_scope_matches(
        account,
        expected_business_parent_id,
    ):
        return False
    lease = session.get(GptProAccountOperationLeaseModel, int(account.id))
    now = _utcnow()
    return bool(
        lease
        and str(lease.token or "") == str(operation_token)
        and (_aware_utc(lease.expires_at) or now) > now
    )


def _require_sub2api_operation_fence(
    account_id: int,
    *,
    operation_token: str,
    expected_business_parent_id: Optional[int],
    require_healthy: bool = True,
) -> GptProAccountModel:
    """Fail closed when an external BUSINESS or locally-owned lease is stale."""
    account = _require_sub2api_account_scope(
        account_id,
        require_healthy=require_healthy,
        expected_business_parent_id=expected_business_parent_id,
    )
    if not _gpt_pro_account_operation_token_is_current(account_id, operation_token):
        raise HTTPException(409, "Sub2API 操作租约已失效")
    return account


def _require_sub2api_guard(
    guard: Optional[Callable[[], Any]],
    stage: str,
) -> None:
    """Run an optional BUSINESS delivery/deletion fence at a named boundary."""
    if guard is None:
        return
    if guard() is False:
        raise HTTPException(409, f"Sub2API guard 在{stage}阶段拒绝操作")


def _sub2api_identity_matches_email(identity: dict, email: str) -> bool:
    expected = str(email or "").strip().casefold()
    actual_email = str(identity.get("email") or "").strip().casefold()
    actual_name = str(identity.get("name") or "").strip().casefold()
    return bool(expected and expected in {actual_email, actual_name})


def _persist_sub2api_link(
    account_id: int,
    *,
    device: dict,
    remote_account_id: str,
    operation_token: str,
    expected_business_parent_id: Optional[int] = None,
    delivery_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    """Activate a link only while the account lease and device identity hold."""
    _require_sub2api_guard(delivery_guard, "linkage 提交")
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            raise HTTPException(409, "Sub2API 同步租约或 BUSINESS 子号归属已变化")
        if (
            not bool(account.enabled)
            or bool(account.dangerous)
            or bool(str(account.refund_status or "").strip())
        ):
            raise HTTPException(409, "账号状态已变化，拒绝提交 Sub2API 关联")
        current_device = session.get(SyncDeviceModel, int(device["id"]))
        if (
            not current_device
            or _sub2api_device_type(current_device.type) != "sub2api"
            or str(current_device.api_url or "").strip().rstrip("/").lower()
            != str(device["api_url"]).strip().rstrip("/").lower()
        ):
            raise HTTPException(409, "Sub2API 设备在上传期间被删除或更换地址")
        extra = _extra_of(account)
        existing = _sub2api_link_of(account)
        if existing and (
            int(existing["device_id"]) != int(device["id"])
            or str(existing["remote_account_id"]) != str(remote_account_id)
        ):
            raise HTTPException(409, "账号已关联其他 Sub2API 远端账号，请先显式删除或解绑")
        now = _utcnow().isoformat()
        extra.update({
            "sub2api_device_id": int(device["id"]),
            "sub2api_device_name": str(device["name"]),
            "sub2api_remote_account_id": str(remote_account_id),
            "sub2api_synced_at": str(extra.get("sub2api_synced_at") or now),
            "sub2api_status": "linked",
            "sub2api_account_kind": (
                "business_child"
                if expected_business_parent_id is not None
                else "gpt_pro"
            ),
        })
        if expected_business_parent_id is not None:
            extra["sub2api_business_parent_id"] = int(expected_business_parent_id)
        else:
            extra.pop("sub2api_business_parent_id", None)
        for key in _SUB2API_PENDING_FIELDS + (
            "sub2api_last_error",
            "sub2api_last_error_at",
            "sub2api_monitor_alert",
        ):
            extra.pop(key, None)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        return serialize_gpt_pro_sub2api_status(account)


def _mark_sub2api_sync_pending(
    account_id: int,
    device: dict,
    *,
    operation_token: str,
    expected_business_parent_id: Optional[int] = None,
) -> None:
    """Durably write the upload intent only for the current lease/assignment."""
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            raise HTTPException(409, "Sub2API 同步 intent 的租约或子号归属已变化")
        extra = _extra_of(account)
        extra.update({
            "sub2api_sync_pending": True,
            "sub2api_sync_pending_device_id": int(device["id"]),
            "sub2api_sync_pending_device_name": str(device["name"]),
            "sub2api_sync_pending_started_at": _utcnow().isoformat(),
            "sub2api_sync_pending_operation_token": str(operation_token),
            "sub2api_status": "error",
        })
        if expected_business_parent_id is not None:
            extra["sub2api_sync_pending_business_parent_id"] = int(
                expected_business_parent_id
            )
        else:
            extra.pop("sub2api_sync_pending_business_parent_id", None)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()


def _record_sub2api_sync_error(
    account_id: int,
    message: str,
    *,
    operation_token: str,
    expected_business_parent_id: Optional[int] = None,
    remote_account_id: str = "",
    pending: bool = True,
) -> bool:
    """Record an error only if this worker still owns the account operation."""
    safe_message = str(message or "Sub2API 同步失败")[:500]
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account or not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            return False
        extra = _extra_of(account)
        extra.update({
            "sub2api_status": "error",
            "sub2api_last_error": safe_message,
            "sub2api_last_error_at": _utcnow().isoformat(),
            "sub2api_monitor_alert": _sub2api_monitor_alert(
                "sub2api_sync_pending",
                safe_message,
            ),
        })
        if pending:
            extra["sub2api_sync_pending"] = True
            extra["sub2api_sync_pending_operation_token"] = str(operation_token)
            if expected_business_parent_id is not None:
                extra["sub2api_sync_pending_business_parent_id"] = int(
                    expected_business_parent_id
                )
            else:
                extra.pop("sub2api_sync_pending_business_parent_id", None)
            if remote_account_id:
                extra["sub2api_sync_pending_remote_account_id"] = str(
                    remote_account_id
                )
        else:
            for key in _SUB2API_PENDING_FIELDS:
                extra.pop(key, None)
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        return True


def _resolve_existing_sub2api_identity(device: dict, email: str) -> Optional[dict]:
    from services.sub2api_admin import Sub2ApiAccountNotFound, find_account_exact

    try:
        return find_account_exact(
            device["api_url"],
            device["api_key"],
            email=email,
        )
    except Sub2ApiAccountNotFound:
        return None


def sync_account_to_sub2api(
    account_id: int,
    device_id: int,
    *,
    expected_business_parent_id: Optional[int] = None,
    operation_token: str = "",
    delivery_guard: Optional[Callable[[], Any]] = None,
    replace_invalid_remote_id: str = "",
) -> dict:
    """Idempotently upload/adopt one GPT PRO or managed BUSINESS child.

    BUSINESS callers pass the exact parent id and their already-owned account
    lease token.  Supplying an external token never attempts to claim or release
    that lease; the caller remains its owner for the surrounding rotation job.
    """
    from services.sub2api_admin import (
        Sub2ApiAccountAmbiguous,
        Sub2ApiAdminError,
        get_account_by_id,
    )

    owned_token = ""
    if not operation_token:
        owned_token = _claim_gpt_pro_account_operation(
            account_id,
            "sub2api_sync",
            allow_managed_business_child=expected_business_parent_id is not None,
        )
        operation_token = owned_token
    try:
        _require_sub2api_guard(delivery_guard, "同步准备")
        device = _sub2api_device_or_error(device_id)
        account = _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        email = str(account.email or "").strip()
        current_link = _sub2api_link_of(account)
        current_pending = _sub2api_pending_of(account)
        if current_link and int(current_link["device_id"]) != int(device_id):
            raise HTTPException(
                409,
                "账号已关联其他 Sub2API 设备；请先显式删除远端账号或解绑，不能静默覆盖",
            )
        if current_pending and int(current_pending.get("device_id") or 0) != int(device_id):
            raise HTTPException(
                409,
                "账号存在另一台 Sub2API 设备的待核对同步；请先显式清理 pending，不能切换设备",
            )

        replacement_credentials: Optional[tuple[str, str]] = None
        requested_replacement_id = str(replace_invalid_remote_id or "").strip()
        if requested_replacement_id:
            # This path is internal to the unified device monitor.  It is only
            # authorized for an exact managed BUSINESS child whose two quota
            # probes returned 401.  Delete the immutable linked remote id first
            # and require confirmed absence; a normal sync/adoption must never
            # silently replace an existing Sub2API account.
            if expected_business_parent_id is None or not current_link:
                raise HTTPException(409, "Sub2API 失效凭证修复缺少精确 BUSINESS 关联")
            if (
                int(current_link["device_id"]) != int(device_id)
                or str(current_link["remote_account_id"])
                != requested_replacement_id
            ):
                raise HTTPException(409, "Sub2API 失效凭证修复目标已变化")
            # Prove the newly acquired RT can mint a durable fresh AT before
            # deleting the invalid remote account.  This keeps a failed OAuth
            # refresh entirely side-effect free.
            replacement_credentials = _gpt_pro_resolve_codex_credentials(
                account,
                _require_persist=True,
            )
            _require_sub2api_guard(delivery_guard, "失效凭证删除准备")
            deleted = _delete_linked_sub2api_remote(
                account_id,
                reason="credential_401_repair",
                expected_business_parent_id=expected_business_parent_id,
                operation_token=operation_token,
                deletion_guard=delivery_guard,
            )
            if not bool(deleted.get("ok")):
                raise HTTPException(502, "Sub2API 失效凭证删除未确认")
            account = _require_sub2api_operation_fence(
                account_id,
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
            )
            current_link = _sub2api_link_of(account)
            current_pending = _sub2api_pending_of(account)
            if current_link:
                raise HTTPException(409, "Sub2API 失效凭证删除后关联仍存在")

        # A verified existing linkage is the strongest idempotency signal.
        if current_link:
            try:
                identity = get_account_by_id(
                    device["api_url"],
                    device["api_key"],
                    current_link["remote_account_id"],
                )
                if not _sub2api_identity_matches_email(identity, email):
                    raise HTTPException(409, "Sub2API 远端账号身份与本地邮箱不一致")
                status = _persist_sub2api_link(
                    account_id,
                    device=device,
                    remote_account_id=str(identity["id"]),
                    operation_token=operation_token,
                    expected_business_parent_id=expected_business_parent_id,
                    delivery_guard=delivery_guard,
                )
                return {"ok": True, "message": "账号已同步，无需重复创建", "idempotent": True, **status}
            except Sub2ApiAdminError as exc:
                if int(exc.status_code or 0) != 404:
                    raise HTTPException(502, "验证 Sub2API 已有关联失败") from exc
                # Authoritative 404: retry by exact email resolution/create.
                _clear_sub2api_link_after_confirmed_delete(
                    account_id,
                    expected_device_id=int(current_link["device_id"]),
                    expected_remote_account_id=str(current_link["remote_account_id"]),
                    reason="remote_missing_before_resync",
                    remote_deleted=True,
                    operation_token=operation_token,
                    expected_business_parent_id=expected_business_parent_id,
                    state_guard=delivery_guard,
                )
                current_link = None

        try:
            identity = _resolve_existing_sub2api_identity(device, email)
        except Sub2ApiAccountAmbiguous as exc:
            _record_sub2api_sync_error(
                account_id,
                "Sub2API 存在多个同邮箱账号，拒绝自动选择",
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                pending=bool(current_pending),
            )
            raise HTTPException(409, "Sub2API 存在多个同邮箱账号，请先在设备端去重") from exc
        except Sub2ApiAdminError as exc:
            _record_sub2api_sync_error(
                account_id,
                "读取 Sub2API 账号列表失败",
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                pending=bool(current_pending),
            )
            raise HTTPException(502, "读取 Sub2API 账号列表失败") from exc
        if identity:
            status = _persist_sub2api_link(
                account_id,
                device=device,
                remote_account_id=str(identity["id"]),
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                delivery_guard=delivery_guard,
            )
            return {"ok": True, "message": "已关联设备中现有的同邮箱账号", "idempotent": True, **status}
        if current_pending:
            # ``find_account_exact`` exhaustively paginated and returned an
            # authoritative not-found.  The old uncertain write is now known
            # absent, so its recovery intent can be closed before a new POST.
            _clear_sub2api_pending(
                account_id,
                expected_device_id=(
                    int(current_pending["device_id"])
                    if current_pending.get("device_id") else None
                ),
                expected_remote_account_id=(
                    str(current_pending["remote_account_id"])
                    if current_pending.get("remote_account_id") else None
                ),
                reason="pending_remote_absent_before_resync",
                remote_deleted=True,
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                state_guard=delivery_guard,
            )
            current_pending = None

        # Existing OAuth infrastructure is intentionally reused.  The browser
        # flow runs only when RT is missing; a fresh AT is minted before upload.
        if not str(account.codex_refresh_token or "").strip():
            rt_logs: List[str] = []
            if not _reacquire_parent_codex_rt(account, lambda msg: rt_logs.append(str(msg))):
                tail = " / ".join(rt_logs[-3:]) if rt_logs else "未知原因"
                _record_sub2api_sync_error(
                    account_id,
                    "自动获取 OAuth RT 失败",
                    operation_token=operation_token,
                    expected_business_parent_id=expected_business_parent_id,
                    pending=False,
                )
                raise HTTPException(400, f"账号缺少 codex RT，自动补 RT 失败: {tail}")
        account = _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        if replacement_credentials is not None:
            fresh_access_token, _chatgpt_account_id = replacement_credentials
        else:
            fresh_access_token, _chatgpt_account_id = _gpt_pro_resolve_codex_credentials(account)
        account = _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )

        from platforms.chatgpt.cpa_upload import generate_token_json
        from platforms.chatgpt.sub2api_upload import upload_token_data_to_sub2api_result

        codex_account = _pro_to_codex_account(account)
        codex_account.access_token = fresh_access_token
        token_data = generate_token_json(codex_account)
        token_data["email"] = email
        token_data["id_token"] = str(account.codex_id_token or "")
        if account.pro_expires_at:
            token_data["subscription_expires_at"] = account.pro_expires_at

        _require_sub2api_guard(delivery_guard, "before remote upload intent")
        _mark_sub2api_sync_pending(
            account_id,
            device,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        _require_sub2api_guard(delivery_guard, "before remote upload")
        upload = upload_token_data_to_sub2api_result(
            token_data,
            api_url=device["api_url"],
            api_key=device["api_key"],
            group_ids=device["group_ids"],
            account=codex_account,
        )
        try:
            _require_sub2api_operation_fence(
                account_id,
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
            )
            _require_sub2api_guard(delivery_guard, "after remote upload")
        except Exception:
            _record_sub2api_sync_error(
                account_id,
                "远端请求返回后操作租约失效，保留 pending 等待精确核对",
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                remote_account_id=upload.remote_account_id,
            )
            raise

        remote_id = str(upload.remote_account_id or "").strip()
        # A timeout or a success response without an id may still have created
        # the account.  Resolve exact identity before deciding success/failure.
        try:
            identity = _resolve_existing_sub2api_identity(device, email)
        except Sub2ApiAccountAmbiguous as exc:
            _record_sub2api_sync_error(
                account_id,
                "上传后出现多个同邮箱账号，无法确定远端 ID",
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
            )
            raise HTTPException(409, "Sub2API 上传后出现多个同邮箱账号，请先去重") from exc
        except Sub2ApiAdminError as exc:
            identity = None
            lookup_error = exc
        else:
            lookup_error = None
        identity_confirmed = bool(identity)
        if identity:
            resolved_id = str(identity.get("id") or "").strip()
            if remote_id and resolved_id != remote_id:
                _record_sub2api_sync_error(
                    account_id,
                    "上传返回 ID 与精确邮箱查询结果不一致",
                    operation_token=operation_token,
                    expected_business_parent_id=expected_business_parent_id,
                )
                raise HTTPException(409, "Sub2API 上传返回 ID 与远端身份不一致")
            remote_id = resolved_id
        if not upload.ok and not identity_confirmed:
            _record_sub2api_sync_error(
                account_id,
                str(upload.message or "Sub2API 上传失败"),
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                remote_account_id=remote_id,
            )
            raise HTTPException(502, "同步到 Sub2API 失败；已保留 pending 供重试核对")
        if not remote_id:
            message = (
                "Sub2API 创建成功但未返回 remote_account_id，且无法按邮箱唯一解析"
                if lookup_error is None
                else "Sub2API 创建结果无法确认，且远端账号查询失败"
            )
            _record_sub2api_sync_error(
                account_id,
                message,
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
            )
            raise HTTPException(502, message + "；未标记为已同步")

        status = _persist_sub2api_link(
            account_id,
            device=device,
            remote_account_id=remote_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            delivery_guard=delivery_guard,
        )
        return {"ok": True, "message": "同步到 Sub2API 成功", "idempotent": False, **status}
    finally:
        if owned_token:
            _release_gpt_pro_account_operation(account_id, owned_token)


@router.post("/accounts/{account_id}/sync-sub2api")
def gpt_pro_sync_sub2api(account_id: int, body: GptProSyncSub2ApiRequest):
    return sync_account_to_sub2api(account_id, body.device_id)


def get_account_sub2api_usage(
    account_id: int,
    *,
    active: bool = False,
    expected_business_parent_id: Optional[int] = None,
    operation_token: str = "",
) -> dict:
    """Refresh/cache usage within an owned GPT PRO or BUSINESS lease."""
    from services.sub2api_admin import (
        Sub2ApiAdminError,
        get_account_usage,
        query_openai_quota,
    )

    owned_token = ""
    if not operation_token:
        owned_token = _claim_gpt_pro_account_operation(
            account_id,
            "sub2api_usage",
            allow_managed_business_child=expected_business_parent_id is not None,
        )
        operation_token = owned_token
    try:
        account = _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        link = _sub2api_link_of(account)
        if not link:
            raise HTTPException(400, "该账号尚未关联 Sub2API，无法查额度")
        device = _sub2api_device_or_error(int(link["device_id"]))
        try:
            if active:
                payload = query_openai_quota(
                    device["api_url"],
                    device["api_key"],
                    link["remote_account_id"],
                )
                source = "active"
            else:
                payload = get_account_usage(
                    device["api_url"],
                    device["api_key"],
                    link["remote_account_id"],
                    source="passive",
                    force=False,
                )
                source = "passive"
        except Sub2ApiAdminError as exc:
            status_code = int(exc.status_code or 0)
            message = "Sub2API 远端账号不存在" if status_code == 404 else "Sub2API 额度查询失败"
            _cache_sub2api_error(
                account_id,
                "sub2api_remote_missing" if status_code == 404 else "sub2api_usage_error",
                message,
                operation_token=operation_token,
                expected_business_parent_id=expected_business_parent_id,
                expected_device_id=int(link["device_id"]),
                expected_remote_account_id=str(link["remote_account_id"]),
            )
            raise HTTPException(404 if status_code == 404 else 502, message) from exc
        _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        )
        cached = _cache_sub2api_usage(
            account_id,
            payload,
            source=source,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            expected_device_id=int(link["device_id"]),
            expected_remote_account_id=str(link["remote_account_id"]),
        )
        if cached is None:
            raise HTTPException(409, "Sub2API 关联在查询期间发生变化")
        return {"ok": True, "mode": source, **cached}
    finally:
        if owned_token:
            _release_gpt_pro_account_operation(account_id, owned_token)


@router.get("/accounts/{account_id}/sub2api-usage")
def gpt_pro_sub2api_usage(account_id: int, active: bool = Query(False)):
    """``active=true`` may refresh credentials/contact OpenAI; default is passive."""
    return get_account_sub2api_usage(account_id, active=active)


def _clear_sub2api_link_after_confirmed_delete(
    account_id: int,
    *,
    expected_device_id: int,
    expected_remote_account_id: str,
    reason: str,
    remote_deleted: bool,
    operation_token: str,
    expected_business_parent_id: Optional[int] = None,
    state_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    _require_sub2api_guard(state_guard, "local linkage clear")
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            raise HTTPException(409, "Sub2API 解除租约或 BUSINESS 子号归属已变化")
        current = _sub2api_link_of(account)
        if not current:
            return serialize_gpt_pro_sub2api_status(account)
        if (
            int(current["device_id"]) != int(expected_device_id)
            or str(current["remote_account_id"]) != str(expected_remote_account_id)
        ):
            raise HTTPException(409, "Sub2API 关联已变化，拒绝清除新关联")
        extra = _extra_of(account)
        audit_at = _utcnow().isoformat()
        audit = {
            "device_id": int(current["device_id"]),
            "device_name": str(current.get("name") or ""),
            "remote_account_id": str(current["remote_account_id"]),
            "removed_at": audit_at,
            "reason": str(reason or "manual_unlink")[:200],
            "remote_deleted": bool(remote_deleted),
        }
        for key in _SUB2API_LINK_FIELDS + _SUB2API_RUNTIME_FIELDS:
            extra.pop(key, None)
        extra["sub2api_status"] = "unlinked"
        extra["sub2api_last_removed"] = audit
        if not remote_deleted:
            extra["sub2api_monitor_alert"] = _sub2api_monitor_alert(
                "sub2api_remote_retained",
                "仅解除本地关联；Sub2API 远端账号仍保留",
            )
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        return serialize_gpt_pro_sub2api_status(account)


def _delete_linked_sub2api_remote(
    account_id: int,
    *,
    reason: str,
    require_auto_remove_enabled: bool = False,
    expected_business_parent_id: Optional[int] = None,
    operation_token: str = "",
    deletion_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    """Delete one exact remote identity, fenced by lease + parent + guard."""
    from services.sub2api_admin import Sub2ApiAdminError, delete_account

    owned_token = ""
    if not operation_token:
        owned_token = _claim_gpt_pro_account_operation(
            account_id,
            "sub2api_unlink",
            allow_managed_business_child=expected_business_parent_id is not None,
        )
        operation_token = owned_token
    try:
        account = _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            require_healthy=False,
        )
        link = _sub2api_link_of(account)
        if not link:
            return {
                "ok": True,
                "deleted": False,
                "idempotent": True,
                **serialize_gpt_pro_sub2api_status(account),
            }
        device = _sub2api_device_or_error(
            int(link["device_id"]),
            require_enabled=False,
        )
        if require_auto_remove_enabled and not _sub2api_auto_remove_enabled():
            return {
                "ok": True,
                "deleted": False,
                "skipped": True,
                "reason": "auto_remove_disabled",
                **serialize_gpt_pro_sub2api_status(account),
            }
        _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            require_healthy=False,
        )
        _require_sub2api_guard(deletion_guard, "before remote delete")
        try:
            confirmation = delete_account(
                device["api_url"],
                device["api_key"],
                link["remote_account_id"],
                expected_email=str(account.email or ""),
            )
            remote_deleted = bool(confirmation.get("deleted"))
        except Sub2ApiAdminError as exc:
            if int(exc.status_code or 0) == 404:
                # Authoritative absence is equivalent to a confirmed delete.
                remote_deleted = True
                confirmation = {"deleted": False, "absence_confirmed": True}
            else:
                _cache_sub2api_error(
                    account_id,
                    "sub2api_remove_failed",
                    "Sub2API 远端删除未确认，保留关联等待重试",
                    operation_token=operation_token,
                    expected_business_parent_id=expected_business_parent_id,
                    expected_device_id=int(link["device_id"]),
                    expected_remote_account_id=str(link["remote_account_id"]),
                )
                raise HTTPException(502, "Sub2API 远端删除未确认，未解除本地关联") from exc
        _require_sub2api_operation_fence(
            account_id,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            require_healthy=False,
        )
        _require_sub2api_guard(deletion_guard, "after remote delete")
        status = _clear_sub2api_link_after_confirmed_delete(
            account_id,
            expected_device_id=int(link["device_id"]),
            expected_remote_account_id=str(link["remote_account_id"]),
            reason=reason,
            remote_deleted=True,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
            state_guard=deletion_guard,
        )
        return {
            "ok": True,
            "deleted": remote_deleted,
            "absence_confirmed": True,
            **status,
        }
    finally:
        if owned_token:
            _release_gpt_pro_account_operation(account_id, owned_token)


def delete_managed_business_child_from_sub2api(
    account_id: int,
    *,
    expected_business_parent_id: int,
    operation_token: str,
    deletion_guard: Optional[Callable[[], Any]] = None,
    reason: str = "business_child_rotation",
) -> dict:
    """BUSINESS-safe exact delete hook; the caller must already own the lease."""
    if not str(operation_token or ""):
        raise HTTPException(409, "BUSINESS Sub2API 删除缺少外部操作租约")
    return _delete_linked_sub2api_remote(
        account_id,
        reason=reason,
        expected_business_parent_id=int(expected_business_parent_id),
        operation_token=str(operation_token),
        deletion_guard=deletion_guard,
    )


def _clear_sub2api_pending(
    account_id: int,
    *,
    expected_device_id: Optional[int],
    expected_remote_account_id: Optional[str],
    reason: str,
    remote_deleted: bool,
    operation_token: str,
    expected_business_parent_id: Optional[int] = None,
    state_guard: Optional[Callable[[], Any]] = None,
) -> dict:
    """Clear one exact recovery intent and retain a non-secret audit record."""
    _require_sub2api_guard(state_guard, "local pending clear")
    with Session(engine) as session:
        account = session.get(GptProAccountModel, int(account_id))
        if not account:
            raise HTTPException(404, "账号不存在")
        if not _sub2api_operation_fence_is_current(
            session,
            account,
            operation_token=operation_token,
            expected_business_parent_id=expected_business_parent_id,
        ):
            raise HTTPException(409, "Sub2API pending 租约或 BUSINESS 子号归属已变化")
        pending = _sub2api_pending_of(account)
        if not pending:
            return serialize_gpt_pro_sub2api_status(account)
        if (
            (pending.get("device_id") or None) != (expected_device_id or None)
            or (pending.get("remote_account_id") or None)
            != (expected_remote_account_id or None)
        ):
            raise HTTPException(409, "Sub2API 待核对状态已变化，拒绝清除新任务")
        extra = _extra_of(account)
        audit = {
            "device_id": pending.get("device_id"),
            "device_name": str(pending.get("name") or ""),
            "remote_account_id": pending.get("remote_account_id"),
            "removed_at": _utcnow().isoformat(),
            "reason": str(reason or "manual_pending_unlink")[:200],
            "remote_deleted": bool(remote_deleted),
            "was_pending": True,
        }
        for key in _SUB2API_PENDING_FIELDS + _SUB2API_RUNTIME_FIELDS:
            extra.pop(key, None)
        extra["sub2api_status"] = "unlinked"
        extra["sub2api_last_removed"] = audit
        if not remote_deleted:
            extra["sub2api_monitor_alert"] = _sub2api_monitor_alert(
                "sub2api_remote_retained",
                "已清除本地待核对状态；远端结果未确认",
            )
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        return serialize_gpt_pro_sub2api_status(account)


@router.delete("/accounts/{account_id}/sub2api-link")
def gpt_pro_unlink_sub2api(
    account_id: int,
    delete_remote: bool = Query(False),
):
    """Explicit cleanup.  Remote deletion is opt-in and identity-confirmed."""
    operation_token = _claim_gpt_pro_account_operation(account_id, "sub2api_unlink")
    try:
        account = _require_sub2api_account_scope(account_id, require_healthy=False)
        link = _sub2api_link_of(account)
        if not link:
            pending = _sub2api_pending_of(account)
            if not pending:
                return {"ok": True, "deleted": False, "idempotent": True, **serialize_gpt_pro_sub2api_status(account)}
            pending_device_id = pending.get("device_id")
            pending_remote_id = pending.get("remote_account_id")
            if delete_remote:
                if not pending_device_id or not pending_remote_id:
                    raise HTTPException(
                        409,
                        "待核对同步没有可确认的 remote_account_id；请先在设备端按邮箱核对，不能假定已删除",
                    )
                from services.sub2api_admin import Sub2ApiAdminError, delete_account

                device = _sub2api_device_or_error(
                    int(pending_device_id),
                    require_enabled=False,
                )
                _require_sub2api_operation_fence(
                    account_id,
                    operation_token=operation_token,
                    expected_business_parent_id=None,
                    require_healthy=False,
                )
                try:
                    confirmation = delete_account(
                        device["api_url"],
                        device["api_key"],
                        str(pending_remote_id),
                        expected_email=str(account.email or ""),
                    )
                    deleted = bool(confirmation.get("deleted"))
                except Sub2ApiAdminError as exc:
                    if int(exc.status_code or 0) == 404:
                        deleted = False
                    else:
                        raise HTTPException(
                            502,
                            "Sub2API 待核对远端账号删除未确认，未清除 pending",
                        ) from exc
                status = _clear_sub2api_pending(
                    account_id,
                    expected_device_id=int(pending_device_id),
                    expected_remote_account_id=str(pending_remote_id),
                    reason="manual_pending_remote_delete",
                    remote_deleted=True,
                    operation_token=operation_token,
                )
                return {"ok": True, "deleted": deleted, "absence_confirmed": True, **status}
            status = _clear_sub2api_pending(
                account_id,
                expected_device_id=(int(pending_device_id) if pending_device_id else None),
                expected_remote_account_id=(str(pending_remote_id) if pending_remote_id else None),
                reason="manual_pending_local_unlink",
                remote_deleted=False,
                operation_token=operation_token,
            )
            return {"ok": True, "deleted": False, "remote_retained": True, **status}
        if delete_remote:
            return _delete_linked_sub2api_remote(
                account_id,
                reason="manual_remote_delete",
                operation_token=operation_token,
            )
        status = _clear_sub2api_link_after_confirmed_delete(
            account_id,
            expected_device_id=int(link["device_id"]),
            expected_remote_account_id=str(link["remote_account_id"]),
            reason="manual_local_unlink",
            remote_deleted=False,
            operation_token=operation_token,
        )
        return {"ok": True, "deleted": False, "remote_retained": True, **status}
    finally:
        _release_gpt_pro_account_operation(account_id, operation_token)


def refresh_all_sub2api_usage(*, active: bool = False) -> dict:
    """Refresh every healthy GPT PRO account linked to a Sub2API device.

    The scheduled path is passive by default.  It never touches BUSINESS
    children, disabled/dead/refund accounts, or unlinked rows.  One transport
    failure opens a per-run circuit for that device so an outage cannot multiply
    a 20-second timeout by every linked account.
    """
    from services.sub2api_admin import (
        Sub2ApiAdminError,
        get_account_usage,
        query_openai_quota,
    )

    with Session(engine) as session:
        rows = session.exec(select(GptProAccountModel)).all()
        jobs = []
        for account in rows:
            link = _sub2api_link_of(account)
            if link:
                jobs.append({
                    "account_id": int(account.id or 0),
                    "business_parent_id": int(getattr(account, "business_parent_id", None) or 0),
                    "enabled": bool(account.enabled),
                    "dangerous": bool(account.dangerous),
                    "refund_status": str(account.refund_status or "").strip(),
                    "link": link,
                })

    summary = {
        "ok": True,
        "total": len(jobs),
        "updated": 0,
        "limited": 0,
        "errors": 0,
        "skipped": 0,
        "removed": 0,
        "remove_failed": 0,
        "active": bool(active),
        "auto_remove_enabled": _sub2api_auto_remove_enabled(),
        "error_items": [],
    }
    blocked_devices: set[int] = set()
    for job in jobs:
        account_id = int(job["account_id"])
        link = dict(job["link"])
        device_id = int(link["device_id"])
        if (
            job["business_parent_id"] > 0
            or not job["enabled"]
            or job["dangerous"]
            or bool(job["refund_status"])
        ):
            summary["skipped"] += 1
            continue
        try:
            operation_token = _claim_gpt_pro_account_operation(
                account_id,
                "sub2api_usage",
            )
        except HTTPException:
            summary["skipped"] += 1
            continue
        try:
            if device_id in blocked_devices:
                summary["skipped"] += 1
                _cache_sub2api_error(
                    account_id,
                    "sub2api_device_unavailable",
                    "Sub2API 设备本轮已触发连接熔断",
                    operation_token=operation_token,
                    expected_device_id=device_id,
                    expected_remote_account_id=str(link["remote_account_id"]),
                )
                continue
            # Re-read inside the lease; old scheduled snapshots may have been
            # unlinked or moved while waiting for another account.
            try:
                account = _require_sub2api_operation_fence(
                    account_id,
                    operation_token=operation_token,
                    expected_business_parent_id=None,
                )
                current_link = _sub2api_link_of(account)
                if not current_link or (
                    int(current_link["device_id"]) != device_id
                    or str(current_link["remote_account_id"])
                    != str(link["remote_account_id"])
                ):
                    summary["skipped"] += 1
                    continue
                device = _sub2api_device_or_error(device_id)
            except HTTPException as exc:
                summary["skipped"] += 1
                if int(exc.status_code or 0) not in {404, 409}:
                    summary["errors"] += 1
                continue

            try:
                if active:
                    payload = query_openai_quota(
                        device["api_url"],
                        device["api_key"],
                        current_link["remote_account_id"],
                    )
                    source = "active"
                else:
                    payload = get_account_usage(
                        device["api_url"],
                        device["api_key"],
                        current_link["remote_account_id"],
                        source="passive",
                        force=False,
                    )
                    source = "passive"
            except Sub2ApiAdminError as exc:
                remote_status = int(exc.status_code or 0)
                if remote_status in {0, 408, 429, 500, 502, 503, 504}:
                    blocked_devices.add(device_id)
                public_message = (
                    "Sub2API 远端账号不存在"
                    if remote_status == 404
                    else "Sub2API 额度查询失败"
                )
                _cache_sub2api_error(
                    account_id,
                    "sub2api_remote_missing" if remote_status == 404 else "sub2api_usage_error",
                    public_message,
                    operation_token=operation_token,
                    expected_device_id=device_id,
                    expected_remote_account_id=str(current_link["remote_account_id"]),
                )
                summary["errors"] += 1
                summary["error_items"].append({
                    "account_id": account_id,
                    "device_id": device_id,
                    "code": "remote_missing" if remote_status == 404 else "usage_error",
                })
                continue

            cached = _cache_sub2api_usage(
                account_id,
                payload,
                source=source,
                operation_token=operation_token,
                expected_device_id=device_id,
                expected_remote_account_id=str(current_link["remote_account_id"]),
            )
            if cached is None:
                summary["skipped"] += 1
                continue
            summary["updated"] += 1
            usage = cached.get("sub2api_usage") or {}
            if usage.get("limit_reached") is True:
                summary["limited"] += 1
                # Re-read the destructive policy immediately before every
                # remote delete.  Turning the switch off while a long refresh
                # is running fences all subsequent accounts in that run.
                if (
                    summary["auto_remove_enabled"]
                    and _sub2api_auto_remove_enabled()
                ):
                    try:
                        removed = _delete_linked_sub2api_remote(
                            account_id,
                            reason="quota_exhausted_auto_remove",
                            require_auto_remove_enabled=True,
                            operation_token=operation_token,
                        )
                    except HTTPException:
                        # Deletion is fail-closed: keep linkage + warning so the
                        # next scheduler run can retry the exact remote id.
                        summary["errors"] += 1
                        summary["remove_failed"] += 1
                        summary["error_items"].append({
                            "account_id": account_id,
                            "device_id": device_id,
                            "code": "auto_remove_failed",
                        })
                    else:
                        if removed.get("ok") and not removed.get("skipped"):
                            summary["removed"] += 1
        except Exception as exc:
            # Never place exception text in persisted/browser-visible state.
            _cache_sub2api_error(
                account_id,
                "sub2api_usage_error",
                "Sub2API 定时监控异常",
                operation_token=operation_token,
                expected_device_id=device_id,
                expected_remote_account_id=str(link["remote_account_id"]),
            )
            summary["errors"] += 1
            summary["error_items"].append({
                "account_id": account_id,
                "device_id": device_id,
                "code": type(exc).__name__,
            })
        finally:
            _release_gpt_pro_account_operation(account_id, operation_token)
    return summary


@router.post("/sub2api-usage-refresh-all")
def gpt_pro_refresh_all_sub2api_usage(active: bool = Query(False)):
    """Retired compatibility endpoint; unified devices own quota scans."""
    raise HTTPException(410, "请刷新 /delivery-devices 中的指定设备")


_CPA_DISABLE_PENDING_FIELDS = (
    "cpa_disable_pending",
    "cpa_disable_reason",
    "cpa_disable_requested_at",
    "cpa_disable_last_attempt_at",
    "cpa_disable_last_error",
    "cpa_disable_attempts",
)
_CPA_DISABLE_FAILURE_ALERT_CODES = {
    "business_child_release_disable_failed",
    "business_child_release_disable_partial",
    "business_child_release_credential_missing",
    "business_child_quota_disable_failed",
    "cpa_health_disable_failed",
    "cpa_disable_retry_failed",
    "cpa_refund_cleanup_blocked",
    "cpa_migration_blocked",
}
_CPA_ROTATION_DELETE_CONFIRM_FIELDS = (
    "cpa_rotation_delete_confirmed",
    "cpa_rotation_delete_confirmed_at",
    "cpa_rotation_delete_confirmed_target_id",
    "cpa_rotation_delete_confirmed_auth_name",
    "cpa_rotation_delete_confirmed_ready_at",
)


def _set_cpa_disable_pending(
    account_id: int,
    *,
    reason: str,
    error: str = "",
    increment_attempt: bool = False,
    expected_token: str = "",
) -> dict:
    """持久化“远端 CPA 凭据仍待确认停用”的状态。"""
    now = _utcnow().isoformat()
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return {"ok": False, "missing": True}
        extra = _extra_of(acc)
        if expected_token and (
            not bool(extra.get("cpa_disable_pending"))
            or str(extra.get("cpa_disable_token") or "") != expected_token
        ):
            return {"ok": False, "cancelled": True}
        token = str(extra.get("cpa_disable_token") or "")
        if not token:
            token = _operation_uuid.uuid4().hex
        try:
            generation = int(extra.get("cpa_lifecycle_generation") or 0)
        except (TypeError, ValueError):
            generation = 0
        extra["cpa_disable_pending"] = True
        extra["cpa_disable_token"] = token
        extra["cpa_disable_reason"] = str(reason or "CPA 凭据待停用")[:500]
        extra["cpa_disable_requested_at"] = str(
            extra.get("cpa_disable_requested_at") or now
        )
        extra["cpa_monitor_suppressed"] = True
        if increment_attempt:
            try:
                attempts = int(extra.get("cpa_disable_attempts") or 0)
            except (TypeError, ValueError):
                attempts = 0
            extra["cpa_disable_attempts"] = attempts + 1
            extra["cpa_disable_last_attempt_at"] = now
        if error:
            extra["cpa_disable_last_error"] = str(error)[:500]
        else:
            extra.pop("cpa_disable_last_error", None)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        s.add(acc)
        s.commit()
        return {"ok": True, "token": token, "generation": generation}


def _complete_cpa_disable(
    account_id: int,
    *,
    reason: str,
    expected_token: str = "",
    expected_generation: Optional[int] = None,
) -> bool:
    """远端确认后以 fence 条件落 disabled；旧 worker 不能覆盖新生命周期。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return False
        extra = _extra_of(acc)
        if expected_token and (
            not bool(extra.get("cpa_disable_pending"))
            or str(extra.get("cpa_disable_token") or "") != expected_token
        ):
            return False
        try:
            generation = int(extra.get("cpa_lifecycle_generation") or 0)
        except (TypeError, ValueError):
            generation = 0
        if expected_generation is not None and generation != int(expected_generation):
            return False
        extra["cpa_disabled"] = True
        extra["cpa_disabled_at"] = _utcnow().isoformat()
        extra["cpa_disabled_reason"] = str(reason or "")[:500]
        for key in _CPA_DISABLE_PENDING_FIELDS:
            extra.pop(key, None)
        extra.pop("cpa_disable_token", None)
        extra["cpa_disable_completed_at"] = _utcnow().isoformat()
        normalized_reason = str(reason or "")
        if "BUSINESS 子号" in normalized_reason and "额度用满" in normalized_reason:
            # Keep rotation authorization in the same local transaction as the
            # confirmed remote disable.  A crash after this commit can never
            # leave a permanently disabled child without a rotation-ready fact.
            extra["cpa_lifecycle_state"] = "business_child_quota_disabled"
            extra["cpa_rotation_ready_at"] = extra["cpa_disable_completed_at"]
            extra["cpa_rotation_reason"] = "quota_exhausted"
            if bool(extra.get("cpa_rotation_delete_required")):
                # A manual device refresh owns an exact auth-file deletion.
                # Invalidate every older confirmation in the same transaction
                # as the new rotation-ready epoch; the scanner must not start
                # until this epoch's DELETE is re-list-confirmed.
                for key in _CPA_ROTATION_DELETE_CONFIRM_FIELDS:
                    extra.pop(key, None)
        alert = extra.get("cpa_monitor_alert")
        if (
            isinstance(alert, dict)
            and str(alert.get("code") or "") in _CPA_DISABLE_FAILURE_ALERT_CODES
        ):
            extra.pop("cpa_monitor_alert", None)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        s.add(acc)
        s.commit()
        return True


def _cpa_auth_file_is_disabled(item: dict) -> bool:
    return bool(item.get("disabled")) or str(
        item.get("status") or ""
    ).strip().lower() == "disabled"


def _disable_account_cpa_credentials_durably(
    account_id: int,
    *,
    reason: str,
    alert_code: str = "cpa_disable_retry_failed",
    require_business_lifecycle: bool = False,
    require_existing_pending: bool = False,
    allow_upload_intent: bool = False,
    initial_files: Optional[List[dict]] = None,
    operation_token: str = "",
) -> dict:
    """停用账号全部 CPA 凭据，并以重新读取的远端状态作为完成条件。

    失败只保留 durable pending 与告警；绝不删除凭据、绝不触发退款。
    ``initial_files`` 仅用于复用调用方刚读取的设备快照，最终确认始终重新读取。
    """
    safe_reason = str(reason or "CPA 凭据待停用")[:500]
    owned_lease_token = ""
    lease_token = str(operation_token or "")
    if lease_token:
        if not _gpt_pro_account_operation_token_is_current(account_id, lease_token):
            return {
                "ok": False,
                "skipped": False,
                "pending": True,
                "cancelled": True,
                "error": "CPA 停用操作租约已失效",
            }
    else:
        try:
            owned_lease_token = _claim_gpt_pro_account_operation(
                account_id,
                "cpa_disable",
                allow_managed_business_child=True,
            )
            lease_token = owned_lease_token
        except HTTPException as exc:
            return {
                "ok": False,
                "skipped": False,
                "pending": True,
                "busy": True,
                "error": str(exc.detail)[:500],
            }

    try:
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, account_id)
            if not acc:
                return {"ok": False, "skipped": True, "error": "账号不存在"}
            email = str(acc.email or "").strip()
            extra = _extra_of(acc)
            is_business_lifecycle = bool(
                getattr(acc, "business_parent_id", None) is not None
                or extra.get("cpa_account_kind") == "business_child"
                or extra.get("cpa_business_membership_stale")
            )

        if require_business_lifecycle and not is_business_lifecycle:
            return {
                "ok": False,
                "skipped": True,
                "error": "账号不属于 BUSINESS 子号 CPA 生命周期，拒绝停用",
            }
        if require_existing_pending and not bool(extra.get("cpa_disable_pending")):
            return {
                "ok": True,
                "skipped": True,
                "cancelled": True,
                "pending": False,
                "reason": "停用任务已取消或账号已重新进入 active 生命周期",
            }
        if not extra.get("cpa_synced") and not (
            allow_upload_intent and extra.get("cpa_auto_upload_pending")
        ):
            if extra.get("cpa_disable_pending"):
                message = "CPA 停用任务缺少同步关联，无法定位远端设备"
                _set_cpa_disable_pending(account_id, reason=safe_reason, error=message)
                _record_cpa_monitor_alert(account_id, alert_code, message)
                return {"ok": False, "skipped": False, "pending": True, "error": message}
            return {"ok": True, "skipped": True, "reason": "not_synced"}

        fence = _set_cpa_disable_pending(
            account_id,
            reason=safe_reason,
            increment_attempt=True,
        )
        if not fence.get("ok"):
            return {
                "ok": False,
                "skipped": False,
                "cancelled": True,
                "pending": False,
                "error": "CPA 生命周期已变化，取消旧停用任务",
            }
        fence_token = str(fence.get("token") or "")
        fence_generation = int(fence.get("generation") or 0)

        def _fence_is_current() -> bool:
            if not _gpt_pro_account_operation_token_is_current(account_id, lease_token):
                return False
            with Session(engine) as session:
                current = session.get(GptProAccountModel, account_id)
                if not current:
                    return False
                state = _extra_of(current)
                try:
                    generation = int(state.get("cpa_lifecycle_generation") or 0)
                except (TypeError, ValueError):
                    generation = 0
                if (
                    not bool(state.get("cpa_disable_pending"))
                    or str(state.get("cpa_disable_token") or "") != fence_token
                    or generation != fence_generation
                ):
                    return False
                if require_business_lifecycle and not bool(
                    getattr(current, "business_parent_id", None) is not None
                    or state.get("cpa_account_kind") == "business_child"
                    or state.get("cpa_business_membership_stale")
                ):
                    return False
                return True

        def _failed(message: str, *, code: str = alert_code) -> dict:
            safe_message = str(message or "CPA 凭据停用失败")[:500]
            updated = _set_cpa_disable_pending(
                account_id,
                reason=safe_reason,
                error=safe_message,
                expected_token=fence_token,
            )
            if not updated.get("ok"):
                return {
                    "ok": False,
                    "skipped": False,
                    "cancelled": True,
                    "pending": False,
                    "error": "CPA 生命周期已变化，旧停用结果已丢弃",
                }
            _record_cpa_monitor_alert(account_id, code, safe_message)
            return {
                "ok": False,
                "skipped": False,
                "pending": True,
                "error": safe_message,
            }

        api_url, api_key = _resolve_cpa_endpoint(extra)
        if not api_url:
            return _failed("找不到 CPA 设备地址；已保留停用重试状态")
        if not _fence_is_current():
            return {
                "ok": False,
                "skipped": False,
                "cancelled": True,
                "pending": False,
                "error": "CPA 生命周期已变化，取消旧停用任务",
            }

        remote = _disable_cpa_email_at_endpoint(
            email,
            api_url,
            api_key,
            before_mutation=_fence_is_current,
            initial_files=initial_files,
        )
        if remote.get("cancelled"):
            return {
                "ok": False,
                "skipped": False,
                "cancelled": True,
                "pending": False,
                "error": str(remote.get("error") or "CPA 生命周期已变化")[:500],
            }
        if not remote.get("ok"):
            return _failed(str(remote.get("error") or "CPA 凭据停用失败"))
        if not _fence_is_current() or not _complete_cpa_disable(
            account_id,
            reason=(
                f"{safe_reason}；远端已无匹配凭据"
                if remote.get("missing") else safe_reason
            ),
            expected_token=fence_token,
            expected_generation=fence_generation,
        ):
            return {
                "ok": False,
                "skipped": False,
                "cancelled": True,
                "pending": False,
                "error": "CPA 生命周期已变化，旧停用结果未写入",
            }
        return {
            "ok": True,
            "skipped": False,
            "pending": False,
            "disabled": int(remote.get("disabled") or 0),
            "missing": bool(remote.get("missing")),
            "failed": 0,
        }
    finally:
        if owned_lease_token:
            _release_gpt_pro_account_operation(account_id, owned_lease_token)


def disable_released_business_child_cpa(
    account_id: int,
    *,
    reason: str = "business_child_released",
    operation_token: str = "",
) -> dict:
    """BUSINESS 子号释放时尽力停用 CPA 凭证，绝不删除凭证。

    这是给 BUSINESS 移除/撤邀路径调用的安全 helper：任何远端失败
    都保留 durable ``cpa_disable_pending`` 与告警，不抛异常、不阻断子号
    从 BUSINESS 工作区释放。整点刷新会持续重试，直到重新读取远端并
    确认该邮箱全部凭据均已 disabled。
    """
    safe_reason = str(reason or "business_child_released")[:300]
    owned_lease_token = ""
    lease_token = str(operation_token or "")
    try:
        if lease_token:
            if not _gpt_pro_account_operation_token_is_current(account_id, lease_token):
                return {
                    "ok": False,
                    "skipped": False,
                    "pending": True,
                    "cancelled": True,
                    "error": "子号释放 CPA 停用租约已失效",
                }
        else:
            try:
                owned_lease_token = _claim_gpt_pro_account_operation(
                    account_id,
                    "cpa_disable",
                    allow_managed_business_child=True,
                )
                lease_token = owned_lease_token
            except HTTPException as exc:
                return {
                    "ok": False,
                    "skipped": False,
                    "pending": True,
                    "busy": True,
                    "error": str(exc.detail)[:500],
                }
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, account_id)
            if not acc:
                return {"ok": False, "skipped": True, "error": "账号不存在"}
            email = str(acc.email or "").strip()
            ex = _extra_of(acc)

        is_business_lifecycle = bool(
            getattr(acc, "business_parent_id", None) is not None
            or ex.get("cpa_account_kind") == "business_child"
            or ex.get("cpa_business_membership_stale")
        )
        if not is_business_lifecycle:
            return {
                "ok": False,
                "skipped": True,
                "error": "账号不属于 BUSINESS 子号 CPA 生命周期，拒绝停用",
            }
        current_parent_id = getattr(acc, "business_parent_id", None)
        if (
            current_parent_id is not None
            and not bool(ex.get("cpa_disable_pending"))
            and str(ex.get("cpa_lifecycle_state") or "")
            != "assignment_changed_during_sync"
        ):
            return {
                "ok": False,
                "skipped": True,
                "error": "子号当前仍在 BUSINESS 工作区且没有待停用任务，拒绝按旧释放操作停用",
            }

        _patch_gpt_pro_extra(account_id, {
            "cpa_account_kind": "business_child",
            "cpa_lifecycle_state": "business_child_released",
            "cpa_monitor_suppressed": True,
            "cpa_disabled_reason": safe_reason,
        })
        _set_cpa_disable_pending(account_id, reason=safe_reason)
        return _disable_account_cpa_credentials_durably(
            account_id,
            reason=safe_reason,
            alert_code="business_child_release_disable_failed",
            require_business_lifecycle=True,
            require_existing_pending=True,
            operation_token=lease_token,
        )
    except Exception as exc:
        # 这个 helper 必须保证“失败不阻断释放”；尽力写告警后吞掉异常。
        message = f"子号释放后停用 CPA 异常: {str(exc)[:300]}"
        try:
            _set_cpa_disable_pending(
                account_id,
                reason=safe_reason,
                error=message,
            )
            _record_cpa_monitor_alert(account_id, "business_child_release_disable_failed", message)
        except Exception:
            pass
        return {"ok": False, "skipped": False, "error": message}
    finally:
        if owned_lease_token:
            _release_gpt_pro_account_operation(account_id, owned_lease_token)


def _clear_plan_auto_upload_linkage_after_compensation(
    account_id: int,
    operation_token: str,
) -> bool:
    """Fence and clear a legacy upload intent on the authoritative plan row."""
    with Session(engine) as session:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        account = session.get(GptProAccountModel, int(account_id))
        lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
        if not account or not lease or str(lease.token or "") != str(operation_token or ""):
            return False
        expires_at = lease.expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not expires_at or expires_at <= _utcnow():
            return False
        extra = _extra_of(account)
        for key in (
            "cpa_auto_upload_pending",
            "cpa_auto_upload_pending_token",
            "cpa_auto_upload_pending_started_at",
            "cpa_auto_upload_pending_last_error",
            "cpa_auth_name",
            "cpa_device_id",
            "cpa_api_url",
            "cpa_api_key",
            "cpa_config_domain",
            "cpa_disable_token",
        ):
            extra.pop(key, None)
        extra.update({
            "cpa_synced": False,
            "cpa_monitor_suppressed": True,
            "cpa_disable_pending": False,
            "cpa_lifecycle_state": "upload_compensated_disabled",
        })
        account.extra_json = json.dumps(extra, ensure_ascii=False)
        account.updated_at = _utcnow()
        session.add(account)
        session.commit()
        return True


def refresh_all_cpa_usage(
    *,
    eligible_business_parent_ids: Optional[set[int]] = None,
) -> dict:
    """给所有已同步到 CPA 的账号刷新额度并落库缓存(供整点定时任务调用)。

    按设备分组: 每台 CPA 只 list_auth_files 一次, 再逐账号经 api-call 中转查 wham/usage。
    已禁用、dangerous 或已进入退款状态的账号不会再查询用量；若远端凭据仍在，
    全量刷新会将其停用并保留文件，避免健康状态已不允许的账号继续被 CPA 路由。
    """
    from services.cpa_manager import list_auth_files
    from services.gpt_pro_cpa_manager import _fetch_account_usage

    # BUSINESS child usage refresh is work on behalf of its parent. Build a
    # local-only allow-list before touching any CPA endpoint. Normal GPT PRO
    # accounts and released-child cleanup remain independent of this guard.
    if eligible_business_parent_ids is None:
        eligible_business_parent_ids = set()
        try:
            from api.gpt_business import _business_account_team_session_status
            with Session(engine) as parent_session:
                parents = parent_session.exec(select(GptBusinessAccountModel)).all()
            eligible_business_parent_ids = {
                int(parent.id)
                for parent in parents
                if parent.id is not None
                and bool(parent.enabled)
                and not bool(parent.dangerous)
                and not str(parent.refund_status or "").strip()
                and bool(
                    _business_account_team_session_status(parent).get("usable")
                )
            }
        except Exception:
            # Missing rolling-deployment tables or malformed local state must
            # fail closed for managed BUSINESS children.
            eligible_business_parent_ids = set()
    else:
        eligible_business_parent_ids = {
            int(value) for value in eligible_business_parent_ids if int(value) > 0
        }

    # Refund is already final when cleanup_pending is present.  Retry deletion
    # first and never route those rows through usage/disable/refund logic, which
    # would otherwise risk issuing a second refund after a transient CPA outage.
    cleanup_ids: List[int] = []
    with Session(engine) as session:
        for account in session.exec(select(GptProAccountModel)).all():
            if bool(_extra_of(account).get("cpa_cleanup_pending")):
                cleanup_ids.append(int(account.id))
    cleanup_completed = cleanup_failed = 0
    for cleanup_id in cleanup_ids:
        try:
            cleaned = _delete_cpa_credential_on_refund(cleanup_id)
        except Exception as exc:
            cleaned = False
            print(f"[GPTPRO/CPA] CPA cleanup pending 重试异常 account={cleanup_id}: {exc}")
        if cleaned:
            cleanup_completed += 1
        else:
            cleanup_failed += 1

    # 1) 收集需要刷新的账号 + 其设备端点
    # (..., is_business_child_cpa, health_block_reason, was_disable_pending,
    #  disable_reason)。pending 任务即使 monitor_suppressed 也必须进入重试。
    jobs: List[tuple] = []
    business_children_session_blocked = 0
    unified_business_children_skipped = 0
    with Session(engine) as s:
        unified_cpa_targets = {
            int(policy.business_account_id): int(policy.cpa_target_id or 0)
            for policy in s.exec(
                select(GptBusinessAutomationPolicyModel).where(
                    GptBusinessAutomationPolicyModel.auto_rotation_enabled
                    == True,  # noqa: E712
                    GptBusinessAutomationPolicyModel.delivery_type == "cpa",
                    GptBusinessAutomationPolicyModel.cpa_target_id.is_not(None),  # type: ignore[union-attr]
                )
            ).all()
            if int(policy.business_account_id or 0) > 0
            and int(policy.cpa_target_id or 0) > 0
        }
        rows = s.exec(select(GptProAccountModel)).all()
        for acc in rows:
            ex = _extra_of(acc)
            current_business_parent_id = int(
                getattr(acc, "business_parent_id", None) or 0
            )
            if (
                current_business_parent_id > 0
                and current_business_parent_id not in eligible_business_parent_ids
            ):
                business_children_session_blocked += 1
                continue
            if ex.get("cpa_cleanup_pending"):
                continue
            unified_target_id = int(
                unified_cpa_targets.get(current_business_parent_id) or 0
            )
            try:
                linked_target_id = int(
                    ex.get("cpa_synced_to_id")
                    or ex.get("cpa_device_id")
                    or 0
                )
            except (TypeError, ValueError):
                linked_target_id = 0
            if (
                current_business_parent_id > 0
                and unified_target_id > 0
                and bool(ex.get("cpa_synced"))
                and linked_target_id == unified_target_id
            ):
                # The unified per-device worker owns probe, 401 repair,
                # exhaustion cleanup and replacement for this exact child.
                # The legacy hourly poller must not pre-disable it and erase
                # the literal limit signal before the durable saga is created.
                unified_business_children_skipped += 1
                continue
            auto_upload_pending = bool(ex.get("cpa_auto_upload_pending"))
            disable_pending = bool(ex.get("cpa_disable_pending"))
            needs_disable = disable_pending or auto_upload_pending
            if not ex.get("cpa_synced") and not needs_disable:
                continue
            if (ex.get("cpa_monitor_suppressed")
                    or ex.get("cpa_business_membership_stale")) and not needs_disable:
                continue
            health_reasons: List[str] = []
            if not bool(acc.enabled):
                health_reasons.append("账号已禁用")
            if bool(acc.dangerous):
                health_reasons.append("账号已标记 dangerous/dead")
            refund_status = str(acc.refund_status or "").strip()
            if refund_status:
                health_reasons.append(f"退款状态={refund_status}")
            health_block_reason = "；".join(health_reasons)
            disable_reason = str(
                ex.get("cpa_disable_reason")
                or health_block_reason
                or ("CPA 上传结果待安全核对" if auto_upload_pending else "")
                or ("CPA 凭据停用重试" if disable_pending else "")
            )[:500]
            api_url, api_key = _resolve_cpa_endpoint(ex)   # 用目标列表里的当前 key(账号存的可能过期)
            if api_url or disable_reason:
                jobs.append((
                    acc.id,
                    acc.email,
                    api_url,
                    api_key,
                    bool(
                        getattr(acc, "business_parent_id", None) is not None
                        or ex.get("cpa_account_kind") == "business_child"
                        or ex.get("cpa_business_membership_stale")
                    ),
                    health_block_reason,
                    disable_pending,
                    disable_reason,
                    auto_upload_pending,
                ))

    if not jobs:
        return {
            "ok": True,
            "updated": 0,
            "failed": 0,
            "stale": 0,
            "business_children_disabled": 0,
            "health_blocked": 0,
            "health_disabled": 0,
            "health_disable_failed": 0,
            "disable_pending_retried": 0,
            "disable_pending_completed": 0,
            "disable_pending_failed": 0,
            "cleanup_pending_retried": len(cleanup_ids),
            "cleanup_pending_completed": cleanup_completed,
            "cleanup_pending_failed": cleanup_failed,
            "business_children_session_blocked": business_children_session_blocked,
            "unified_business_children_skipped": unified_business_children_skipped,
            "total": 0,
        }

    # 2) 每台设备只拉一次 auth-files
    # 同 URL 在 key 轮换期间不能复用另一身份的快照；target 配置已保证 URL
    # 唯一，这里仍把 key 纳入缓存身份以避免并发配置切换时串用。
    files_cache: Dict[tuple[str, str], list] = {}
    def _files(url: str, key: str) -> list:
        cache_key = (str(url or "").rstrip("/"), str(key or ""))
        if cache_key in files_cache:
            return files_cache[cache_key]
        try:
            files_cache[cache_key] = list_auth_files(api_url=url, api_key=key)
        except Exception:
            files_cache[cache_key] = []
        return files_cache[cache_key]

    updated = failed = stale = business_children_disabled = 0
    health_blocked = health_disabled = health_disable_failed = 0
    disable_pending_retried = disable_pending_completed = disable_pending_failed = 0
    made_query = False
    for (
        account_id,
        email,
        api_url,
        api_key,
        is_business_child_cpa,
        health_block_reason,
        was_disable_pending,
        disable_reason,
        was_auto_upload_pending,
    ) in jobs:
        try:
            if disable_reason:
                if health_block_reason:
                    health_blocked += 1
                if was_disable_pending:
                    disable_pending_retried += 1
                auto_reconcile_token = ""
                try:
                    if was_auto_upload_pending:
                        auto_reconcile_token = _claim_gpt_pro_account_operation(
                            account_id,
                            "cpa_auto_upload_reconcile",
                            allow_managed_business_child=True,
                        )
                    disable_result = _disable_account_cpa_credentials_durably(
                        account_id,
                        reason=disable_reason,
                        alert_code=(
                            "cpa_disable_retry_failed"
                            if was_disable_pending
                            else "cpa_health_disable_failed"
                        ),
                        require_existing_pending=was_disable_pending,
                        allow_upload_intent=was_auto_upload_pending,
                        operation_token=auto_reconcile_token,
                    )
                    if disable_result.get("ok") and was_auto_upload_pending:
                        _clear_plan_auto_upload_linkage_after_compensation(
                            account_id,
                            auto_reconcile_token,
                        )
                except HTTPException as exc:
                    disable_result = {
                        "ok": False,
                        "pending": True,
                        "error": f"账号操作占用: {exc.detail}",
                    }
                finally:
                    if auto_reconcile_token:
                        _release_gpt_pro_account_operation(
                            account_id,
                            auto_reconcile_token,
                        )
                if disable_result.get("ok"):
                    if health_block_reason:
                        health_disabled += 1
                    if was_disable_pending:
                        disable_pending_completed += 1
                    print(
                        f"[GPTPRO/CPA] {email} {disable_reason} "
                        "→ 已确认 CPA 凭据全部停用 (不退款、不删除)"
                    )
                else:
                    failed += 1
                    if health_block_reason:
                        health_disable_failed += 1
                    if was_disable_pending:
                        disable_pending_failed += 1
                continue

            files = _files(api_url, api_key)
            el = (email or "").lower()
            safe = _cpa_safe_email_key(email)
            matches = [
                f for f in files
                if _cpa_file_identifies(f, el, safe)
            ]
            match = matches[0] if matches else None
            if not match:
                stale += 1   # 已标同步但设备上已无该文件(号被删/退)→ 快速跳过, 不发网络请求
                continue
            if match.get("disabled"):
                stale += 1   # 已停用的凭证 CPA 不会路由, 查不到用量 → 跳过, 不浪费请求
                continue
            # 真正发查询前稍作间隔, 避免连打 wham/usage 被限流
            if made_query:
                time.sleep(0.5)
            made_query = True
            idt = match.get("id_token") or {}
            usage = _fetch_account_usage(api_url, api_key, match.get("auth_index"), idt.get("chatgpt_account_id"))
            if usage is None:
                failed += 1
                continue
            _cache_cpa_usage(account_id, usage)
            updated += 1
            # 周额度用满(周已用=100% 或被限流):
            #   自动退款【开】→ 登记退款(退款成功后删 CPA 凭证);
            #   自动退款【关】→ 停用该号在 CPA 上的凭证(不删, 停止路由, 保留可日后重启)。
            try:
                week_exhausted = float(usage.get("week_used_percent")) >= 100
            except (TypeError, ValueError):
                week_exhausted = False
            try:
                short_percent_exhausted = (
                    float(usage.get("p5_used_percent")) >= 100
                )
            except (TypeError, ValueError):
                short_percent_exhausted = False
            literal_limit_reached = usage.get("limit_reached") is True
            # A device-bound BUSINESS child follows a single automatic rule:
            # any provider window at 100% (or a literal limit flag) is terminal
            # for this child lifecycle.  Persist/confirm the CPA disable first;
            # the BUSINESS rotation worker then removes the exact member,
            # records history, invites a same-seat replacement, gets RT and
            # delivers it back to this same device.
            exhausted = week_exhausted or literal_limit_reached or (
                is_business_child_cpa and short_percent_exhausted
            )
            if exhausted:
                reason = (
                    "额度用满("
                    f"5h={usage.get('p5_used_percent')}%, "
                    f"week={usage.get('week_used_percent')}%, "
                    f"limit_reached={usage.get('limit_reached')})"
                )
                # BUSINESS 池选子号不拥有独立 GPT PRO 订阅，绝不能进入
                # PRO 自动退款队列。无论全局自动退款开关如何，都只停用
                # CPA 凭证并写入可展示告警。
                if is_business_child_cpa:
                    disable_result = _disable_account_cpa_credentials_durably(
                        account_id,
                        reason=f"BUSINESS 子号{reason}；停用 CPA，禁止 PRO 退款",
                        alert_code="business_child_quota_disable_failed",
                        initial_files=files,
                    )
                    if disable_result.get("ok"):
                        _record_cpa_monitor_alert(
                            account_id,
                            "business_child_quota_exhausted",
                            f"{reason}；CPA 凭证已停用，不会进入 GPT PRO 自动退款",
                        )
                        business_children_disabled += 1
                        print(
                            f"[GPTPRO/CPA] BUSINESS 子号 {email} {reason} "
                            f"→ 已停用 CPA 凭证 {match.get('name')} (禁止 PRO 退款)"
                        )
                    else:
                        failed += 1
                        print(
                            f"[GPTPRO/CPA] BUSINESS 子号停用 CPA 凭证失败 {email}: "
                            f"{disable_result.get('error') or '待整点重试'}"
                        )
                elif _auto_refund_enabled():
                    _enqueue_auto_refund(account_id, email, reason)
                elif not match.get("disabled"):
                    disable_result = _disable_account_cpa_credentials_durably(
                        account_id,
                        reason=reason,
                        alert_code="cpa_disable_retry_failed",
                        initial_files=files,
                    )
                    if disable_result.get("ok"):
                        print(f"[GPTPRO/CPA] {email} {reason} + 自动退款关 → 已停用 CPA 凭证 {match.get('name')}")
                    else:
                        failed += 1
                        print(
                            f"[GPTPRO/CPA] 停用 CPA 凭证失败 {email}: "
                            f"{disable_result.get('error') or '待整点重试'}"
                        )
        except Exception:
            failed += 1
    return {
        "ok": True,
        "updated": updated,
        "failed": failed,
        "stale": stale,
        "business_children_disabled": business_children_disabled,
        "health_blocked": health_blocked,
        "health_disabled": health_disabled,
        "health_disable_failed": health_disable_failed,
        "disable_pending_retried": disable_pending_retried,
        "disable_pending_completed": disable_pending_completed,
        "disable_pending_failed": disable_pending_failed,
        "cleanup_pending_retried": len(cleanup_ids),
        "cleanup_pending_completed": cleanup_completed,
        "cleanup_pending_failed": cleanup_failed,
        "business_children_session_blocked": business_children_session_blocked,
        "unified_business_children_skipped": unified_business_children_skipped,
        "total": len(jobs),
    }


def _mark_cpa_disabled(account_id: int, disabled: bool, *, reason: str = "") -> None:
    """本地记录该号在 CPA 上是否被停用(供前端/排查用)。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return
        try:
            extra = json.loads(acc.extra_json) if acc.extra_json else {}
        except Exception:
            extra = {}
        if disabled:
            extra["cpa_disabled"] = True
            extra["cpa_disabled_at"] = _utcnow().isoformat()
            if reason:
                extra["cpa_disabled_reason"] = str(reason)[:500]
        else:
            extra.pop("cpa_disabled", None)
            extra.pop("cpa_disabled_at", None)
            extra.pop("cpa_disabled_reason", None)
        acc.extra_json = json.dumps(extra, ensure_ascii=False)
        acc.updated_at = _utcnow()
        s.add(acc)
        s.commit()


# ── 周额度用满自动退款(退款成功=删 CPA 凭证;失败每 1 分钟重试, 最多 3 次)──
_REFUND_RETRY_MAX_ATTEMPTS = 3        # 失败后最多重试 3 次(加初次共 4 次尝试)
_REFUND_RETRY_INTERVAL = 60           # 秒
_refund_retry_lock = threading.Lock()
_REFUND_RETRY: Dict[int, dict] = {}   # account_id -> {attempts, next_at, email, reason}
_refund_worker_active = False


def _auto_refund_enabled() -> bool:
    from core.config_store import config_store as _cs
    return str(_cs.get("gpt_pro_cpa_auto_refund_enabled", "1")).strip().lower() not in ("0", "false", "no", "off", "")


def _business_parent_id_for_pro_account(account_id: int) -> Optional[int]:
    """读取 GPT PRO 记录的 BUSINESS 归属，用于自动退款防御性校验。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return None
        parent_id = getattr(acc, "business_parent_id", None)
        return int(parent_id) if parent_id is not None else None


def _is_business_child_cpa_lifecycle(account_id: int) -> bool:
    """当前在 BUSINESS 中，或 CPA 凭证本身来自 BUSINESS 子号生命周期。"""
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return False
        return bool(
            is_managed_business_child_account(acc)
            or _extra_of(acc).get("cpa_account_kind") == "business_child"
            or _extra_of(acc).get("cpa_business_membership_stale")
        )


def _enqueue_auto_refund(account_id: int, email: str, reason: str) -> None:
    """Retired: quota exhaustion is handled by the delivery-device saga."""
    return None


def _process_due_refunds() -> None:
    """Retired legacy auto-refund queue; discard stale in-memory entries."""
    with _refund_retry_lock:
        _REFUND_RETRY.clear()


_CPA_CLEANUP_PENDING_FIELDS = (
    "cpa_cleanup_pending",
    "cpa_cleanup_reason",
    "cpa_cleanup_requested_at",
    "cpa_cleanup_last_attempt_at",
    "cpa_cleanup_last_error",
    "cpa_cleanup_attempts",
)


def _set_cpa_cleanup_pending(
    account_id: int,
    *,
    error: str,
    increment_attempt: bool = True,
) -> None:
    """Keep endpoint linkage until remote absence has been confirmed."""
    with _CPA_CONFIG_WRITE_LOCK:
        with Session(engine) as session:
            _begin_cpa_config_write(session)
            account = session.get(GptProAccountModel, int(account_id))
            if not account:
                return
            extra = _extra_of(account)
            try:
                attempts = int(extra.get("cpa_cleanup_attempts") or 0)
            except (TypeError, ValueError):
                attempts = 0
            if increment_attempt:
                attempts += 1
            now = _utcnow().isoformat()
            extra.update({
                "cpa_cleanup_pending": True,
                "cpa_cleanup_reason": "refund_credential_cleanup",
                "cpa_cleanup_requested_at": extra.get("cpa_cleanup_requested_at") or now,
                "cpa_cleanup_last_attempt_at": now,
                "cpa_cleanup_last_error": str(error or "")[:500],
                "cpa_cleanup_attempts": attempts,
                "cpa_lifecycle_state": "refund_cleanup_pending",
                "cpa_monitor_suppressed": True,
            })
            account.extra_json = json.dumps(extra, ensure_ascii=False)
            account.updated_at = _utcnow()
            session.add(account)
            session.commit()


def _delete_cpa_credential_on_refund(
    account_id: int,
    *,
    operation_token: str = "",
) -> bool:
    """Delete and re-list-confirm a refunded account's CPA credentials.

    Refund success is independent from this cleanup.  Any endpoint, delete, or
    confirmation failure is recorded durably and keeps the full linkage so the
    hourly refresh can retry without ever issuing the refund again.
    """
    owned_token = ""
    if not operation_token:
        try:
            owned_token = _claim_gpt_pro_account_operation(
                account_id,
                "cpa_cleanup",
                allow_managed_business_child=True,
            )
        except HTTPException as exc:
            return False
        operation_token = owned_token
    try:
        with Session(engine) as session:
            account = session.get(GptProAccountModel, int(account_id))
            if not account:
                return True
            extra = _extra_of(account)
            email = str(account.email or "")
        if not (
            extra.get("cpa_synced")
            or extra.get("cpa_cleanup_pending")
            or extra.get("cpa_auto_upload_pending")
            or extra.get("cpa_sync_pending")
        ):
            return True
        if not _gpt_pro_account_operation_token_is_current(account_id, operation_token):
            return False
        # Intent-before-delete makes a crash after the remote mutation
        # recoverable and also prevents the shared target from being removed.
        _set_cpa_cleanup_pending(account_id, error="")
        with Session(engine) as session:
            refreshed = session.get(GptProAccountModel, int(account_id))
            if not refreshed:
                return True
            extra = _extra_of(refreshed)
        endpoints: List[tuple[str, str]] = []
        unresolved_pending_target = False
        primary_url, primary_key = _resolve_cpa_endpoint(extra)
        if primary_url:
            endpoints.append((primary_url, primary_key))
        # A crashed first sync or A→B migration can leave a remote write on
        # the pending target while the active linkage still points at A.  A
        # refund must confirm absence on both endpoints before clearing either.
        for field_name in ("cpa_sync_pending_target_id", "cpa_migration_target_id"):
            try:
                pending_target_id = int(extra.get(field_name) or 0)
            except (TypeError, ValueError):
                pending_target_id = 0
            if not pending_target_id:
                continue
            pending_target = _cpa_sync_target_by_id(pending_target_id)
            if not pending_target:
                unresolved_pending_target = True
                continue
            candidate = (
                str(pending_target.get("api_url") or "").strip(),
                str(pending_target.get("api_key") or "").strip(),
            )
            if candidate[0] and candidate not in endpoints:
                endpoints.append(candidate)
        if not endpoints or unresolved_pending_target:
            message = "退款后无法解析 CPA 当前设备配置；已保留 linkage 等待恢复"
            _set_cpa_cleanup_pending(
                account_id,
                error=message,
                increment_attempt=False,
            )
            _record_cpa_monitor_alert(account_id, "cpa_refund_cleanup_blocked", message)
            return False
        try:
            from services.gpt_pro_cpa_manager import _delete_account_files_by_email
            removed = _delete_account_files_by_email(
                email,
                endpoints,
                before_mutation=lambda: _gpt_pro_account_operation_token_is_current(
                    account_id,
                    operation_token,
                ),
            )
        except Exception as exc:
            message = str(exc or "CPA 远端删除未确认")[:500]
            _set_cpa_cleanup_pending(
                account_id,
                error=message,
                increment_attempt=False,
            )
            _record_cpa_monitor_alert(account_id, "cpa_refund_cleanup_pending", message)
            print(f"[GPTPRO/CPA] 退款已成功，CPA 清理待重试 {email}: {message}")
            return False
        if not _gpt_pro_account_operation_token_is_current(account_id, operation_token):
            return False

        with _CPA_CONFIG_WRITE_LOCK:
            with Session(engine) as session:
                _begin_cpa_config_write(session)
                account = session.get(GptProAccountModel, int(account_id))
                if not account:
                    return True
                lease = session.get(
                    GptProAccountOperationLeaseModel,
                    int(account_id),
                )
                if not (
                    lease
                    and lease.token == operation_token
                    and (_aware_utc(lease.expires_at) or _utcnow()) > _utcnow()
                ):
                    return False
                current = _extra_of(account)
                for key in _CPA_SYNC_EXTRA_KEYS:
                    current.pop(key, None)
                for key in _CPA_CLEANUP_PENDING_FIELDS:
                    current.pop(key, None)
                for key in _CPA_DISABLE_PENDING_FIELDS:
                    current.pop(key, None)
                current.pop("cpa_disable_token", None)
                current.pop("cpa_monitor_alert", None)
                current["cpa_lifecycle_state"] = "refund_cleanup_complete"
                current["cpa_monitor_suppressed"] = True
                account.extra_json = json.dumps(current, ensure_ascii=False)
                account.updated_at = _utcnow()
                session.add(account)
                session.commit()
        print(f"[GPTPRO/CPA] 退款成功 → 已确认删除 {email} 的 CPA 凭证({removed} 份)")
        return True
    finally:
        if owned_token:
            _release_gpt_pro_account_operation(account_id, owned_token)


def process_auto_refunds() -> None:
    """Compatibility no-op; the scheduler no longer dispatches this task."""
    _process_due_refunds()


@router.post("/cpa-usage-refresh-all")
def gpt_pro_cpa_usage_refresh_all():
    """Retired compatibility endpoint; unified devices own quota scans."""
    raise HTTPException(410, "请刷新 /delivery-devices 中的指定设备")


@router.post("/accounts/{account_id}/sync-codex-app")
def gpt_pro_sync_codex_app(account_id: int):
    """把该账号同步到本地 Codex App —— 逻辑与「平台管理 ChatGPT → 同步 Codex App」完全一致:
    用 codex RT 刷最新 AT(RT 死了自动重新 OAuth) → 写 ~/.codex/auth.json → quit/open Codex App → 发 hi。
    """
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        if not (acc.codex_refresh_token or "").strip():
            raise HTTPException(400, "该账号没有 codex_refresh_token,无法同步 Codex App(先补 RT)")
    logs: List[str] = []
    _log = lambda m: logs.append(str(m))
    # 刷最新 AT + chatgpt_account_id(内部用 RT 刷新并落库轮换后的 RT)
    access_token, chatgpt_account_id = _gpt_pro_resolve_codex_credentials(acc, log=_log)
    # 重读拿落库后的最新 codex RT / id_token
    with Session(engine) as s:
        fresh = s.get(GptProAccountModel, account_id)
        rt = (fresh.codex_refresh_token or "").strip()
        id_token = (fresh.codex_id_token or "").strip()
        email = fresh.email
    try:
        auth_path = _write_codex_auth_json(access_token, rt, id_token, chatgpt_account_id, _log)
    except Exception as e:
        raise HTTPException(500, f"同步 Codex App 失败: {e}")
    # 从日志里提取 App 控制的**真实结果**(open/send hi),供前端如实展示
    app_open = next((l.split("open →", 1)[1].strip() for l in logs if "open →" in l), "skipped")
    app_send_hi = next((l.split("send hi →", 1)[1].strip() for l in logs if "send hi →" in l), "skipped")
    return {
        "ok": True, "email": email, "auth_path": auth_path,
        "app_open": app_open, "app_send_hi": app_send_hi, "logs": logs,
    }


_CPA_SYNC_EXTRA_KEYS = (
    "cpa_synced", "cpa_synced_to_id", "cpa_synced_to_name", "cpa_auth_name",
    "cpa_device_id", "cpa_api_url", "cpa_api_key", "cpa_synced_at", "cpa_usage",
    "cpa_config_domain", "cpa_migration_pending", "cpa_migration_target_id",
    "cpa_migration_source_disabled", "cpa_migration_started_at",
    "cpa_migration_last_error",
    "cpa_auto_upload_pending", "cpa_auto_upload_pending_token",
    "cpa_auto_upload_pending_started_at", "cpa_auto_upload_pending_last_error",
    "cpa_sync_pending", "cpa_sync_pending_target_id",
    "cpa_sync_pending_target_url", "cpa_sync_pending_token",
    "cpa_sync_pending_auth_name", "cpa_sync_pending_started_at",
    "cpa_sync_pending_lease_expires_at", "cpa_sync_pending_remote_started_at",
    "cpa_sync_pending_quarantine_until", "cpa_sync_pending_last_error",
    "cpa_sync_pending_last_attempt_at",
    "cpa_sync_compensation_pending", "cpa_sync_compensation_token",
    "cpa_sync_compensation_target_id", "cpa_sync_compensation_target_url",
    "cpa_sync_compensation_auth_name", "cpa_sync_compensation_reason",
    "cpa_sync_compensation_started_at", "cpa_sync_compensation_quarantine_until",
    "cpa_sync_compensation_last_attempt_at",
    "cpa_sync_compensation_last_error", "cpa_sync_compensation_attempts",
    "cpa_sync_compensation_completed_at",
)


_CPA_TARGET_DELETE_PENDING_FLAGS = (
    "cpa_sync_pending",
    "cpa_sync_compensation_pending",
    "cpa_auto_upload_pending",
    "cpa_disable_pending",
    "cpa_cleanup_pending",
    "cpa_migration_pending",
    "cpa_rotation_delete_required",
)


def _manual_cpa_target_delete_account_state(
    account: GptProAccountModel,
    target_id: int,
) -> dict:
    """Classify one account before deleting an empty manual CPA target.

    This intentionally accepts only a committed, exact ``cpa_synced_to_id``
    linkage as an auto-clear candidate.  Every uncertain lifecycle flag is a
    blocker even when a live target listing is empty: a crashed worker may
    still own a remote mutation which has not yet been reconciled.
    """
    extra = _extra_of(account)

    def _int(name: str) -> int:
        try:
            return int(extra.get(name) or 0)
        except (TypeError, ValueError):
            return 0

    linked_target_id = _int("cpa_synced_to_id")
    references_target = bool(
        linked_target_id == int(target_id)
        or (
            bool(extra.get("cpa_sync_pending"))
            and _int("cpa_sync_pending_target_id") == int(target_id)
        )
        or (
            bool(extra.get("cpa_sync_compensation_pending"))
            and _int("cpa_sync_compensation_target_id") == int(target_id)
        )
        or (
            bool(extra.get("cpa_migration_pending"))
            and _int("cpa_migration_target_id") == int(target_id)
        )
    )
    pending = [
        name for name in _CPA_TARGET_DELETE_PENDING_FLAGS
        if bool(extra.get(name))
    ]
    business_lifecycle = bool(
        account.business_parent_id is not None
        or extra.get("cpa_account_kind") == "business_child"
        or extra.get("cpa_business_membership_stale")
    )
    domain = str(extra.get("cpa_config_domain") or "").strip().lower()
    scope_conflict = bool(
        linked_target_id == int(target_id)
        and domain not in {"", _CPA_CONFIG_DOMAIN_MANUAL}
    )
    committed = bool(
        extra.get("cpa_synced")
        and linked_target_id == int(target_id)
    )
    return {
        "references_target": references_target,
        "committed": committed,
        "pending": pending,
        "business_lifecycle": business_lifecycle,
        "scope_conflict": scope_conflict,
        "linked_target_id": linked_target_id,
        "auth_name": str(extra.get("cpa_auth_name") or "").strip(),
        "observed_extra_json": str(account.extra_json or "{}"),
    }


def _clear_manual_cpa_link_after_confirmed_target_absence(
    session: Session,
    account: GptProAccountModel,
    *,
    target_id: int,
    target_name: str,
    confirmed_at: datetime,
) -> dict:
    """CAS-clear one stale committed link after a live empty-target listing.

    The caller owns the target registry writer lock and database writer fence.
    Only CPA delivery/linkage fields are removed; PRO/refund/mail/business
    state is deliberately left untouched.  The audit record is retained so a
    later operator can distinguish a verified target deletion from an
    unconfirmed local reset.
    """
    state = _manual_cpa_target_delete_account_state(account, int(target_id))
    if not state["committed"]:
        raise HTTPException(409, {
            "code": "cpa_target_delete_link_changed",
            "message": "CPA 本地关联已变化，拒绝清除新关联",
            "account_id": int(account.id or 0),
            "target_id": int(target_id),
        })
    if state["pending"] or state["business_lifecycle"] or state["scope_conflict"]:
        raise HTTPException(409, {
            "code": "cpa_target_delete_link_not_stale",
            "message": "CPA 本地关联仍处于受保护生命周期，拒绝自动清除",
            "account_id": int(account.id or 0),
            "target_id": int(target_id),
            "pending": list(state["pending"]),
        })

    observed = str(state["observed_extra_json"])
    extra = _extra_of(account)
    auth_name = str(extra.get("cpa_auth_name") or "").strip()
    removed_at = (
        confirmed_at if confirmed_at.tzinfo
        else confirmed_at.replace(tzinfo=timezone.utc)
    ).isoformat()
    # Reuse the canonical sync/disable/cleanup field groups instead of
    # maintaining an incomplete ad-hoc list in the device API.
    for key in _CPA_SYNC_EXTRA_KEYS:
        extra.pop(key, None)
    for key in _CPA_DISABLE_PENDING_FIELDS:
        extra.pop(key, None)
    for key in _CPA_CLEANUP_PENDING_FIELDS:
        extra.pop(key, None)
    for key in (
        "cpa_disable_token",
        "cpa_disabled",
        "cpa_disabled_at",
        "cpa_disabled_reason",
        "cpa_disable_completed_at",
        "cpa_lifecycle_state",
        "cpa_monitor_suppressed",
        "cpa_monitor_alert",
        "cpa_rotation_delete_required",
        "cpa_rotation_delete_required_target_id",
        "cpa_rotation_delete_required_auth_name",
        "cpa_rotation_delete_requested_at",
        "cpa_rotation_ready_at",
        "cpa_rotation_reason",
        *_CPA_ROTATION_DELETE_CONFIRM_FIELDS,
    ):
        extra.pop(key, None)
    extra["cpa_last_removed"] = {
        "target_id": int(target_id),
        "target_name": str(target_name or "")[:200],
        "auth_name": auth_name[:500],
        "removed_at": removed_at,
        "reason": "target_delete_remote_absent",
        "remote_absence_confirmed": True,
    }
    encoded = json.dumps(extra, ensure_ascii=False)
    changed = session.exec(
        sa_update(GptProAccountModel)
        .where(GptProAccountModel.id == int(account.id or 0))
        .where(GptProAccountModel.extra_json == observed)
        .values(extra_json=encoded, updated_at=_utcnow())
        .execution_options(synchronize_session=False)
    )
    if int(getattr(changed, "rowcount", 0) or 0) != 1:
        raise HTTPException(409, {
            "code": "cpa_target_delete_link_changed",
            "message": "CPA 本地关联在删除期间发生变化，请刷新后重试",
            "account_id": int(account.id or 0),
            "target_id": int(target_id),
        })
    return {
        "account_id": int(account.id or 0),
    }


@router.post("/cpa-clear-stale-synced")
def gpt_pro_clear_stale_cpa_synced():
    """审计旧 CPA linkage，不再凭本地健康状态直接清除。

    dangerous/退款账号可能仍有远端凭据，``disable_pending`` 更必须依赖
    linkage 定位设备并重试；未经过远端确认就清除 cpa_synced/api_url 会造成
    永久失联。因此该兼容路由只报告受保护记录，停用由全量刷新闭环处理。
    """
    protected: List[dict] = []
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel)).all()
        for acc in rows:
            extra = _extra_of(acc)
            if not extra.get("cpa_synced"):
                continue
            refund_status = str(acc.refund_status or "").strip()
            pending = bool(extra.get("cpa_disable_pending"))
            if not (refund_status or bool(acc.dangerous) or pending):
                continue
            protected.append({
                "id": acc.id,
                "email": acc.email,
                "refund_status": refund_status,
                "dangerous": bool(acc.dangerous),
                "disable_pending": pending,
            })
    return {
        "ok": True,
        "cleared": 0,
        "accounts": [],
        "protected": len(protected),
        "protected_accounts": protected,
        "message": "已保留 CPA linkage；请通过全量刷新确认远端停用状态",
    }


@router.get("/accounts/{account_id}/referral-reward")
def gpt_pro_referral_reward(account_id: int):
    """实时查该 PRO 账号邀请能拿的**积分数目**(rate_limit_reset_credit)+ 剩余可发/可拿额度。

    调新接口 GET /referrals/invite/eligibility(program_id=codex_referral_consumer)。
    """
    from platforms.chatgpt.codex_referral import reward_info, CodexReferralError
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
    # 无 codex RT → 先跑 OAuth login 拿一个再查(iCloud 走邮箱 OTP 无需密码;outlook 需密码)。
    # 这一步会启浏览器 + 等验证码, 可能耗时 1~2 分钟。
    if not (acc.codex_refresh_token or "").strip():
        _rt_logs: List[str] = []
        if not _reacquire_parent_codex_rt(acc, lambda m: _rt_logs.append(str(m))):
            tail = " / ".join(_rt_logs[-3:]) if _rt_logs else "未知原因"
            raise HTTPException(400, f"该账号无 codex RT 且自动补 RT 失败: {tail}")
        with Session(engine) as s:
            fresh = s.get(GptProAccountModel, account_id)
            if fresh:
                acc = fresh
    proxy = _gpt_pro_codex_proxy()
    for attempt in range(1, 3):
        if attempt > 1:
            with Session(engine) as s:
                fresh = s.get(GptProAccountModel, account_id)
                if fresh:
                    acc = fresh
        try:
            access_token, chatgpt_account_id = _gpt_pro_resolve_codex_credentials(acc)
            info = reward_info(token=access_token, account_id=chatgpt_account_id, proxy=proxy)
            cached = _cache_referral_reward(account_id, info)   # 落库, 后续本地读, 不再查
            return {"ok": True, **cached}
        except CodexReferralError as e:
            if getattr(e, "status", None) in (401, 403) and attempt == 1:
                continue
            raise HTTPException(502, f"查询邀请积分失败: {e}")
        except Exception as e:
            raise HTTPException(500, f"查询邀请积分异常: {e}")


def _icloud_invite_candidate_pool(exclude_email: str = "") -> List[dict]:
    """可作邀请目标的 iCloud 邮箱候选池(单个/批量共用)。
    取自:已退款未到账·未封号 / 普通账号(未订阅)里的 iCloud 邮箱;
    排除:非 iCloud、危险号、已被任何母号邀请过的邮箱、以及 exclude_email。退款号排前面。"""
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel)).all()
    invited: set = set()
    for r in rows:
        try:
            for e in json.loads(r.referral_invited_emails_json or "[]"):
                if str(e).strip():
                    invited.add(str(e).strip().lower())
        except Exception:
            pass
    excl = (exclude_email or "").strip().lower()
    refunded_states = ("refunded_pending_credit", "refund_credited")
    out: List[dict] = []
    for r in rows:
        if _mail_provider_of(r) != "icloud" or r.dangerous:
            continue
        el = (r.email or "").strip().lower()
        if not el or el == excl or el in invited:
            continue
        rs = (r.refund_status or "").strip()
        is_refunded_pending = rs == "refunded_pending_credit"
        is_regular = (not r.is_pro) and rs not in refunded_states
        if not (is_refunded_pending or is_regular):
            continue
        out.append({"id": r.id, "email": r.email,
                    "source": "refunded" if is_refunded_pending else "regular"})
    out.sort(key=lambda x: (x["source"] != "refunded", x["email"].lower()))
    return out


@router.get("/icloud-invite-candidates")
def gpt_pro_icloud_invite_candidates(exclude_account_id: int = 0):
    """可作邀请目标的 iCloud 邮箱候选(供邀请弹窗的「iCloud 邮箱」下拉)。"""
    excl_email = ""
    if exclude_account_id:
        with Session(engine) as s:
            excl = s.get(GptProAccountModel, exclude_account_id)
            excl_email = (excl.email or "") if excl else ""
    out = _icloud_invite_candidate_pool(exclude_email=excl_email)
    return {"candidates": out, "total": len(out)}


@router.post("/accounts/{account_id}/referral-invite")
def gpt_pro_referral_invite(account_id: int, body: GptProReferralInviteRequest):
    """用该 PRO 账号给一个邮箱发推荐邀请;成功后 referral_remaining -= 1 落库。"""
    from platforms.chatgpt.codex_referral import invite, CodexReferralError
    target = (body.email or "").strip()
    if not target or "@" not in target:
        raise HTTPException(400, "目标邮箱无效")

    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")

    proxy = _gpt_pro_codex_proxy()
    try:
        # 母号 AT 过期(401/403)会自动用 RT 重刷 access_token 再重试
        status, data = _codex_invite_with_refresh(acc, [target], proxy)
    except CodexReferralError as e:
        raise HTTPException(502, f"ChatGPT 接口失败: {e}")
    except Exception as e:
        raise HTTPException(500, f"发送邀请异常: {e}")
    if status != 200:
        raise HTTPException(status, f"ChatGPT 拒绝邀请: {data}")

    # 成功 — referral_remaining-- 落库(如果还没查过额度,先按 0 兜底防止变负)
    new_remaining: Optional[int] = None
    try:
        with Session(engine) as s:
            row = s.get(GptProAccountModel, account_id)
            if row:
                base = row.referral_remaining if row.referral_remaining is not None else 0
                new_remaining = max(0, int(base) - 1)
                row.referral_remaining = new_remaining
                row.referral_quota_checked_at = _utcnow()
                row.updated_at = _utcnow()
                s.add(row)
                s.commit()
    except Exception:
        pass

    # 本地扣减邀请积分缓存里的"可发次数"(不再实时查)
    try:
        _dec_referral_capacity(account_id, send=1)
    except Exception:
        pass

    invited = _append_referral_invited(account_id, target)

    return {
        "ok": True,
        "referral_id": (data or {}).get("referral_id"),
        "remaining": new_remaining,
        "invited_emails": invited,
        "raw": data,
    }


# ── Codex 邀请 — 自动注册新邮箱 + 自动邀请 ─────────────────────
# 走 platforms.chatgpt.drission_rt_register.register_via_drission(默认 protocol)
# 用一个全局可配置的 CF 邀请域名(`gpt_pro_referral_cf_domain` config key),
# 生成随机 local_part,跑完 Codex OAuth signup,然后立即用 PRO 号给它发邀请。

class GptProReferralConfigRequest(BaseModel):
    cf_domains: List[str]


@router.get("/referral-config")
def gpt_pro_referral_config_get():
    """读全局「CF 邀请域名」清单。"""
    domains = _load_cf_domains()
    return {
        "cf_domains": domains,
        "default_cf_domain": domains[0] if domains else "",
    }


@router.put("/referral-config")
def gpt_pro_referral_config_put(body: GptProReferralConfigRequest):
    """保存全局「CF 邀请域名」清单。先删后写,顺序就是优先级(第 0 个 = 默认)。"""
    saved = _save_cf_domains(body.cf_domains or [])
    return {"ok": True, "cf_domains": saved}


# ── 升级 PRO 结账区域(国家/币种)── 可在界面配置;账单地址不变 ──
_CHECKOUT_COUNTRY_KEY = "gpt_pro_checkout_country"
_CHECKOUT_CURRENCY_KEY = "gpt_pro_checkout_currency"


def _get_checkout_region() -> tuple[str, str]:
    from core.config_store import config_store
    c = str(config_store.get(_CHECKOUT_COUNTRY_KEY, "") or "").strip().upper() or "PH"
    cur = str(config_store.get(_CHECKOUT_CURRENCY_KEY, "") or "").strip().upper() or "PHP"
    return c, cur


# 国家(2位)→ 币种(3位)。用于「结账区跟随代理国家」。表里没有的国家回退全局配置。
_COUNTRY_CURRENCY = {
    "US": "USD", "JP": "JPY", "GB": "GBP", "CA": "CAD", "AU": "AUD", "NZ": "NZD",
    "DE": "EUR", "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR", "IE": "EUR",
    "AT": "EUR", "BE": "EUR", "FI": "EUR", "PT": "EUR", "GR": "EUR",
    "CH": "CHF", "SE": "SEK", "NO": "NOK", "DK": "DKK", "PL": "PLN", "CZ": "CZK",
    "HU": "HUF", "RO": "RON",
    "PH": "PHP", "IN": "INR", "SG": "SGD", "HK": "HKD", "TW": "TWD", "KR": "KRW",
    "MY": "MYR", "TH": "THB", "VN": "VND", "ID": "IDR",
    "BR": "BRL", "MX": "MXN", "AR": "ARS", "CL": "CLP", "CO": "COP", "PE": "PEN",
    "NG": "NGN", "ZA": "ZAR", "EG": "EGP", "KE": "KES", "MA": "MAD",
    "AE": "AED", "SA": "SAR", "IL": "ILS", "TR": "TRY", "QA": "QAR", "KW": "KWD",
    "RU": "RUB", "UA": "UAH", "CN": "CNY", "PK": "PKR", "BD": "BDT", "LK": "LKR",
}


def _checkout_region_for_upgrade(body: Optional["GptProActionRequest"]) -> tuple[str, str]:
    """升级结账区: 指纹模式选了代理且已知其国家 → 跟代理国家一致; 否则用全局配置。"""
    try:
        pid = int(getattr(body, "roxy_proxy_id", None) or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid > 0:
        with Session(engine) as s:
            p = s.get(RoxyProxyModel, pid)
        country = str(getattr(p, "last_country", "") or "").strip().upper() if p else ""
        cur = _COUNTRY_CURRENCY.get(country)
        if country and cur:
            return country, cur
    return _get_checkout_region()


def _parse_card_text(text: str) -> Optional[dict]:
    """从粘贴的银行卡文本解析 {number, exp_month, exp_year, cvc}。兼容多种标签/格式:

        Card Number: 4937242023477384 / Valid Thru: 07/29 / CVV: 819
        卡號: 5371007327201449 / 有效期: 07/2029 / CVV: 161

    解析失败返回 None。
    """
    t = str(text or "")
    if not t.strip():
        return None
    number = ""
    m = re.search(r"(?:card\s*number|card\s*no|卡号|卡號|number|卡片号码)\s*[:：]?\s*([\d][\d\s\-]{11,25})", t, re.I)
    if m:
        number = re.sub(r"\D", "", m.group(1))
    if not (13 <= len(number) <= 19):
        for cand in re.findall(r"\d[\d\s\-]{11,23}\d", t):
            d = re.sub(r"\D", "", cand)
            if 13 <= len(d) <= 19:
                number = d
                break
    if not (13 <= len(number) <= 19):
        return None
    em = re.search(r"(\d{1,2})\s*[/\-.]\s*(\d{2,4})", t)
    if not em:
        return None
    mm = int(em.group(1))
    if not (1 <= mm <= 12):
        return None
    year = int(em.group(2))
    if year < 100:
        year += 2000
    cm = re.search(r"(?:cvv|cvc|cvn|安全码|安全碼|校验码)\s*[:：]?\s*(\d{3,4})", t, re.I)
    if not cm:
        return None
    return {"number": number, "exp_month": mm, "exp_year": year, "cvc": cm.group(1)}


class GptProCheckoutRegionRequest(BaseModel):
    country: str
    currency: str


class GptUpgradeBrowserConfigRequest(BaseModel):
    """GPT PRO / GPT 套餐升级共用的浏览器策略。"""

    browser_backend: Optional[Literal["local", "roxybrowser"]] = None
    roxy_proxy_id: Optional[int] = None
    # 供只展示开关的调用方使用；与 browser_backend 同传时两者必须一致。
    use_roxy: Optional[bool] = None


@shared_upgrade_config_router.get("/upgrade-browser-config")
def gpt_upgrade_browser_config_get():
    """读取两套账号池共用的升级浏览器配置；缺省为 local / 无代理。"""
    from core.gpt_upgrade_browser_config import load_upgrade_browser_config

    return load_upgrade_browser_config()


@shared_upgrade_config_router.put("/upgrade-browser-config")
def gpt_upgrade_browser_config_put(body: GptUpgradeBrowserConfigRequest):
    """保存共享策略；Roxy 代理必须仍存在且启用，切 local 会清空代理。"""
    from core.gpt_upgrade_browser_config import (
        UpgradeBrowserConfigError,
        load_upgrade_browser_config,
        save_upgrade_browser_config,
    )

    current = load_upgrade_browser_config()
    backend = body.browser_backend
    if body.use_roxy is not None:
        switch_backend = "roxybrowser" if body.use_roxy else "local"
        if backend is not None and backend != switch_backend:
            raise HTTPException(400, "use_roxy 与 browser_backend 不一致")
        backend = switch_backend
    backend = backend or current["browser_backend"]

    fields_set = getattr(body, "model_fields_set", None)
    if fields_set is None:  # Pydantic v1 compatibility
        fields_set = getattr(body, "__fields_set__", set())
    if "roxy_proxy_id" in set(fields_set or set()):
        proxy_id = body.roxy_proxy_id
    else:
        proxy_id = current["roxy_proxy_id"]

    try:
        saved = save_upgrade_browser_config(
            browser_backend=backend,
            roxy_proxy_id=proxy_id,
            db_engine=engine,
        )
    except UpgradeBrowserConfigError as exc:
        raise HTTPException(exc.status_code, str(exc))
    return {"ok": True, **saved}


@router.get("/checkout-region")
def gpt_pro_checkout_region_get():
    """读升级 PRO 的结账区域(国家/币种)。默认 PH/PHP(菲律宾,最便宜区)。"""
    c, cur = _get_checkout_region()
    return {"country": c, "currency": cur}


@router.put("/checkout-region")
def gpt_pro_checkout_region_put(body: GptProCheckoutRegionRequest):
    """保存升级 PRO 的结账区域。只影响 checkout 的 billing_details.country/currency,账单地址不变。"""
    from core.config_store import config_store
    country = (body.country or "").strip().upper()
    currency = (body.currency or "").strip().upper()
    if not country or len(country) != 2:
        raise HTTPException(400, "country 必须是 2 位国家代码(如 PH/US/NG)")
    if not currency or len(currency) != 3:
        raise HTTPException(400, "currency 必须是 3 位币种代码(如 PHP/USD/NGN)")
    config_store.set(_CHECKOUT_COUNTRY_KEY, country)
    config_store.set(_CHECKOUT_CURRENCY_KEY, currency)
    return {"ok": True, "country": country, "currency": currency}


class GptProReferralInviteAutoRequest(BaseModel):
    cf_domain: str                          # 必填:从清单里选一个
    browser_mode: str = "protocol"          # protocol | headless | headed


def _generate_referral_local_part(length: int = 16) -> str:
    import secrets, string
    alphabet = string.ascii_lowercase + string.digits
    return "um1" + "".join(secrets.choice(alphabet) for _ in range(max(8, length - 3)))


@router.post("/accounts/{account_id}/referral-invite-auto")
def gpt_pro_referral_invite_auto(account_id: int, body: GptProReferralInviteAutoRequest):
    """启动一个「注册新 CF 邮箱 + 自动邀请」后台任务,立即返回 task_id;
    前端用 GET /referral-invite-auto/{task_id}?since=N 轮询进度。"""
    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_invite_auto,
        args=(task_id, account_id, body),
        name=f"gpt-pro-invite-{task_id[:8]}",
        daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id}


@router.get("/referral-invite-auto/{task_id}")
def gpt_pro_referral_invite_auto_status(task_id: str, since: int = Query(0, ge=0)):
    """轮询任务状态 + 增量日志。前端每秒拉一次,直到 status != 'running'。"""
    snapshot = _snapshot_invite_task(task_id, since=since)
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


# ── 后台任务存储(自动注册+邀请专用,跟 RegisterTaskStore 解耦)──────
_AUTO_INVITE_TASKS: Dict[str, Dict[str, Any]] = {}
_AUTO_INVITE_LOCK = threading.Lock()
# Starting a BUSINESS rotation OAuth task requires coordinating one durable DB
# binding with the in-memory task store.  The ordinary task lock cannot cover
# database I/O (and _create_invite_task acquires it itself), so use a narrow
# outer lock for this launch/reuse decision.
_BUSINESS_ROTATION_OAUTH_LOCK = threading.Lock()
# User-triggered BUSINESS child OAuth has no durable rotation job.  This lock
# still makes double-clicks in one API process reuse one browser task, while the
# task metadata below binds status polling to the exact parent/child pair.
_MANAGED_BUSINESS_OAUTH_LOCK = threading.Lock()
_AUTO_INVITE_MAX_LINES = 800           # 单任务最多保留多少行日志
_AUTO_INVITE_RETAIN_SECONDS = 2 * 60 * 60  # 完成后 2 小时仍可查(避免后台标签轮询被节流时任务过早过期)
import uuid as _invite_uuid


def _create_invite_task() -> str:
    task_id = _invite_uuid.uuid4().hex
    with _AUTO_INVITE_LOCK:
        _AUTO_INVITE_TASKS[task_id] = {
            "status": "running",
            "logs": [],
            "result": None,
            "error": None,
            "progress": None,
            "started_at": _utcnow().isoformat(),
            "finished_at": "",
        }
        # 顺手清理超过保留期的旧任务
        cutoff = time.time() - _AUTO_INVITE_RETAIN_SECONDS
        stale = []
        for tid, t in _AUTO_INVITE_TASKS.items():
            if tid == task_id:
                continue
            fin = t.get("finished_at") or ""
            if not fin:
                continue
            try:
                ts = datetime.fromisoformat(fin).timestamp()
            except Exception:
                ts = 0
            if ts and ts < cutoff:
                stale.append(tid)
        for tid in stale:
            _AUTO_INVITE_TASKS.pop(tid, None)
    return task_id


def _sanitize_background_task_text(value: Any) -> str:
    """后台浏览器日志会被前端轮询，统一阻止一次性验证码、
    OAuth code、token 和手机号进入内存任务快照/服务日志。
    """
    text = str(value or "")
    text = re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [redacted]",
        text,
    )
    text = re.sub(
        r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b",
        "[jwt-redacted]",
        text,
    )
    text = re.sub(
        r"(?i)([?&](?:code|authorization_code|oauth_code|otp|sms_code|verification_code|"
        r"token|access_token|refresh_token|id_token|session_token)=)"
        r"[^&#\s\"'<>]+",
        r"\1[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|session[_ -]?token|"
        r"authorization[_ -]?code|oauth[_ -]?code|token)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+",
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:otp|sms)(?:[\s_-]+(?:otp|code|verification(?:[\s_-]+code)?))?|"
        r"\bverification(?:[\s_-]+code)?|\u77ed\u4fe1(?:\u9a8c\u8bc1\u7801|\u7801)?|\u9a8c\u8bc1\u7801)"
        r"\s*(?:is|\u4e3a|\u662f)?\s*[:=\uff1a]?\s*[\"']?\d{4,8}\b",
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:phone|mobile)(?:[_ -]?(?:number|no))?|\u624b\u673a\u53f7|\u624b\u673a\u53f7\u7801|\u7535\u8bdd)"
        r"\s*[\"']?\s*[:=\uff1a]?\s*[\"']?\+?[\d()\s-]{7,20}\d",
        lambda match: f"{match.group(1)}=[phone-redacted]",
        text,
    )
    text = re.sub(r"(?<!\w)\+\d{7,15}\b", "[phone-redacted]", text)
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[phone-redacted]", text)
    text = re.sub(
        r"(?i)(activation(?:_id)?|\bid)\s*[:=]\s*[A-Za-z0-9_-]{6,}",
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    return text


def _save_new_registered_account_or_fail(account, save_fn, log) -> None:
    """Persist the first durable copy before RT/invite work may continue.

    Once remote registration has succeeded, retrying the registration branch
    with a new email would orphan the first account.  Convert persistence
    failures to an HTTPException so the surrounding retry loop stops on this
    exact account and the background task remains visibly recoverable.
    """
    try:
        save_fn(account)
    except Exception as exc:
        email = str(getattr(account, "email", "") or "").strip()
        # SQL exceptions may echo bound password/token/extra_json values.  Log
        # only the exception class and a fixed remediation message.
        log(
            f"✗ 新账号本地入库失败 ({type(exc).__name__})；"
            "已停止后续 RT/邀请"
        )
        account_label = f"「{email}」" if email else ""
        raise HTTPException(
            status_code=503,
            detail=(
                f"远端账号{account_label}已注册，但本地入库失败；"
                "本次流程已停止且未继续邀请，请保留该邮箱并重试恢复入库"
            ),
        ) from None


def _invite_task_log(task_id: str, msg: str) -> None:
    safe_msg = _sanitize_background_task_text(msg)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {safe_msg}"
    with _AUTO_INVITE_LOCK:
        t = _AUTO_INVITE_TASKS.get(task_id)
        if not t:
            return
        t["logs"].append(line)
        if len(t["logs"]) > _AUTO_INVITE_MAX_LINES:
            t["logs"] = t["logs"][-_AUTO_INVITE_MAX_LINES:]
    try:
        print(f"[gpt-pro-invite {task_id[:8]}] {safe_msg}", flush=True)
    except Exception:
        pass


def _invite_task_finish(task_id: str, *, result: Optional[Dict[str, Any]] = None,
                        error: Optional[str] = None) -> None:
    with _AUTO_INVITE_LOCK:
        t = _AUTO_INVITE_TASKS.get(task_id)
        if not t:
            return
        t["status"] = "failed" if error else "done"
        t["result"] = result
        t["error"] = _sanitize_background_task_text(error) if error else error
        t["finished_at"] = _utcnow().isoformat()


def _set_invite_progress(task_id: str, progress: Optional[Dict[str, Any]]) -> None:
    with _AUTO_INVITE_LOCK:
        t = _AUTO_INVITE_TASKS.get(task_id)
        if not t:
            return
        t["progress"] = progress


def _snapshot_invite_task(task_id: str, *, since: int) -> Optional[Dict[str, Any]]:
    with _AUTO_INVITE_LOCK:
        t = _AUTO_INVITE_TASKS.get(task_id)
        if not t:
            return None
        all_logs = list(t["logs"])
        tail = all_logs[max(0, int(since or 0)):]
        return {
            "status": t["status"],
            "logs": tail,
            "since": len(all_logs),     # 前端下一轮把 since 设成这个
            "result": t["result"],
            "error": t["error"],
            "progress": t.get("progress"),
            "started_at": t["started_at"],
            "finished_at": t["finished_at"],
        }


def _run_invite_auto(task_id: str, account_id: int, body: GptProReferralInviteAutoRequest) -> None:
    """实际执行注册 + 邀请。所有异常都吃掉,转成 task 状态。"""
    log = lambda m: _invite_task_log(task_id, m)
    try:
        result = _do_invite_auto(task_id, account_id, body, log)
        _invite_task_finish(task_id, result=result)
        log(f"✓ 全部完成: {result.get('registered_email')} · 剩余 {result.get('remaining')}")
    except HTTPException as exc:
        log(f"✗ 失败: {exc.detail}")
        _invite_task_finish(task_id, error=str(exc.detail))
    except Exception as exc:
        log(f"✗ 异常: {exc}")
        _invite_task_finish(task_id, error=str(exc))


def _phase_register_sub(account_id: int, body: GptProReferralInviteAutoRequest, log) -> Dict[str, Any]:
    """阶段1:注册子号(含 3 次换邮箱重试)。返回 ctx 供后续 RT/邀请阶段使用;失败抛 HTTPException。"""
    from core.config_store import config_store
    from platforms.chatgpt.codex_referral import invite, CodexReferralError
    from platforms.chatgpt.plugin import _BusinessOAuthEmailAdapter

    # 域名:只允许来自配置清单
    available = _load_cf_domains()
    cf_domain = (body.cf_domain or "").strip().lower()
    if not cf_domain:
        raise HTTPException(400, "请选择 CF 邀请域名")
    if cf_domain not in available:
        raise HTTPException(400, f"CF 域名「{cf_domain}」不在已配置的清单内,请先在「管理域名」里添加")

    browser_mode = (body.browser_mode or "protocol").strip().lower()
    if browser_mode not in ("protocol", "headless", "headed"):
        browser_mode = "protocol"

    # 校验 PRO 号有 codex_rt
    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "PRO 账号不存在")
        if not (acc.codex_refresh_token or "").strip():
            raise HTTPException(400, "该 PRO 账号没有 codex_refresh_token")

    log(f"开始 · PRO=#{account_id} {acc.email}")

    # 1. 生成新邮箱(临时,protocol 路径下 CFWorkerMailbox 会再分配)
    local_part = _generate_referral_local_part()
    new_email = f"{local_part}@{cf_domain}"
    log(f"目标 CF 域名: {cf_domain}")

    # 2. 准备 CF Worker 邮箱适配器(沿用全局 CF Worker 配置)
    cfworker_api_url = str(config_store.get("cfworker_api_url", "") or "").strip()
    cfworker_admin_token = str(config_store.get("cfworker_admin_token", "") or "").strip()
    cfworker_custom_auth = str(config_store.get("cfworker_custom_auth", "") or "").strip()
    if not cfworker_api_url or not cfworker_admin_token:
        raise HTTPException(400, "CF Worker 配置不完整(缺 cfworker_api_url / cfworker_admin_token)")

    # 3. 代理 — 复用 BUSINESS RT 长跑的代理选取链(全局.proxy → 动态住宅 → 池 → default_proxy)
    extra_config = {
        "cfworker_api_url": cfworker_api_url,
        "cfworker_admin_token": cfworker_admin_token,
        "cfworker_custom_auth": cfworker_custom_auth,
        "register_auto_use_proxy": "1",
    }
    try:
        from services.business_rt_loop import BusinessRTLoopRunner
        proxy, proxy_source = BusinessRTLoopRunner.instance()._pick_proxy_with_source(extra_config)
    except Exception:
        proxy, proxy_source = None, ""
    if not proxy:
        proxy = _gpt_pro_codex_proxy()
        proxy_source = "全局配置"
    if not proxy:
        raise HTTPException(400, "未配置任何可用代理")
    log(f"代理: {proxy} (来源: {proxy_source})")
    log(f"执行方式: {body.browser_mode}")

    # 4. 跑注册 — protocol 模式走「平台管理 ChatGPT 注册」同款链路(chatgpt.com NextAuth + CFWorker 邮箱),
    #    headless 模式走 DrissionPage Codex OAuth signup(给新号也拿 RT,更慢但更"完整")
    new_account_obj = None
    new_email_actual = new_email
    reg_result: Optional[dict] = None  # headless 路径下 register_via_drission 会赋值;protocol 路径保持 None
    # 注册失败(含 Sentinel/TLS 崩、registration_disallowed)→ 换新邮箱自动重试
    for _reg_attempt in range(1, 4):
        try:
            if browser_mode in ("headless", "headed"):
                # 自带 _BusinessOAuthEmailAdapter 收件 + register_via_drission
                from platforms.chatgpt.drission_rt_register import register_via_drission
                mail_adapter = _BusinessOAuthEmailAdapter(
                    email=new_email,
                    api_url=cfworker_api_url,
                    admin_token=cfworker_admin_token,
                    custom_auth=cfworker_custom_auth,
                    log_fn=log,
                )
                reg_result = register_via_drission(
                    email=new_email,
                    proxy=proxy,
                    extra_config=extra_config,
                    log_fn=log,
                    email_adapter=mail_adapter,
                    headless=(browser_mode == "headless"),
                )
                if not reg_result.get("refresh_token"):
                    raise RuntimeError("DrissionPage 流程结束但未拿到 refresh_token")

                from core.base_platform import Account, AccountStatus
                from core.db import save_account as _save_acc
                new_account_obj = Account(
                    platform="chatgpt",
                    email=reg_result.get("email") or new_email,
                    password=reg_result.get("password", "") or "",
                    token=reg_result.get("access_token", ""),
                    status=AccountStatus.READY_FOR_EXPORT,
                    extra={
                        "access_token": reg_result.get("access_token", ""),
                        "refresh_token": reg_result.get("refresh_token", ""),
                        "id_token": reg_result.get("id_token", ""),
                        "workspace_id": reg_result.get("workspace_id", ""),
                        "name": reg_result.get("name", ""),
                        "birthdate": reg_result.get("birthdate", ""),
                        "device_id": reg_result.get("device_id", ""),
                        "business_domain": cf_domain,
                        "mail_provider": "cfworker",
                        "mailbox_token": new_email,
                        "chatgpt_registration_mode": "refresh_token",
                        "chatgpt_has_refresh_token_solution": True,
                        "register_mode": "rt_only_passwordless",
                        "rt_register_browser_mode": browser_mode,
                        "register_source": "gpt_pro_referral_invite_auto",
                        "referrer_pro_account_id": account_id,
                        "password_set_proven": bool(
                            reg_result.get("password_set_proven", False)
                        ),
                        "chatgpt_token_source": "register",
                        "session_token": reg_result.get("session_token", ""),
                        "cookies": reg_result.get("cookies") or {},
                    },
                )
                from platforms.chatgpt.account_security import (
                    finalize_registered_platform_account,
                )

                security_config = dict(extra_config)
                security_config["chatgpt_security_after_register"] = (
                    config_store.get("chatgpt_security_after_register", "1")
                )
                new_account_obj = finalize_registered_platform_account(
                    new_account_obj,
                    config=security_config,
                    proxy=proxy,
                    browser_mode=browser_mode,
                    log_fn=log,
                )
                _save_new_registered_account_or_fail(
                    new_account_obj,
                    _save_acc,
                    log,
                )
                new_email_actual = new_account_obj.email or new_email
            else:
                # protocol 模式:**完全复刻**「平台管理 ChatGPT 注册」链路
                # 不再走 OAuth /oauth/authorize(403 重灾区),走 chatgpt.com NextAuth + CFWorker mailbox
                from core.config_store import config_store as _cs
                from core.base_mailbox import create_mailbox
                from core.base_platform import RegisterConfig
                from platforms.chatgpt.plugin import ChatGPTPlatform
                from core.db import save_account as _save_acc

                merged_extra = _cs.get_all().copy()
                # 强制使用本次选的 CF 父域(让 CFWorkerMailbox 在这里下生成邮箱)
                merged_extra["mail_provider"] = "cfworker"
                merged_extra["cfworker_domain"] = cf_domain
                merged_extra["cfworker_domain_override"] = cf_domain
                # 透传我们已选好的代理(否则 ChatGPTPlatform 内部还会再选一次)
                merged_extra["proxy"] = proxy
                merged_extra["register_auto_use_proxy"] = "1"
                # 让 mailbox 不要再用注册代理(跟 api/tasks.py 一致)
                merged_extra.setdefault("cfworker_use_register_proxy", "0")

                mailbox = create_mailbox(
                    provider="cfworker",
                    extra=merged_extra,
                    proxy=None,
                )

                platform = ChatGPTPlatform(
                    config=RegisterConfig(
                        executor_type="protocol",
                        proxy=proxy,
                        extra=merged_extra,
                    ),
                    mailbox=mailbox,
                )
                try:
                    platform._log_fn = log
                except Exception:
                    pass

                log("启动「平台管理 ChatGPT 注册」同款链路:chatgpt.com NextAuth + CFWorker")
                new_account_obj = platform.register(email=None, password=None)
                if not new_account_obj or not new_account_obj.email:
                    raise RuntimeError("注册流程结束但未返回账号")
                new_email_actual = new_account_obj.email
                # 标记一下来源,便于后续排查 / 统计;不动 register_mode 让现有列表筛选不受影响
                try:
                    extra_d = dict(new_account_obj.extra or {})
                    extra_d["register_source"] = "gpt_pro_referral_invite_auto"
                    extra_d["referrer_pro_account_id"] = account_id
                    extra_d["referral_target_cf_domain"] = cf_domain
                    new_account_obj.extra = extra_d
                except Exception:
                    pass
                _save_new_registered_account_or_fail(
                    new_account_obj,
                    _save_acc,
                    log,
                )
                log(f"✓ 新账号已注册: {new_email_actual}")

            break
        except HTTPException:
            raise
        except Exception as exc:
            if _reg_attempt < 3:
                log(f"⚠ 注册失败(第 {_reg_attempt}/3 次): {str(exc)[:160]} → 换新邮箱重试")
                local_part = _generate_referral_local_part()
                new_email = f"{local_part}@{cf_domain}"
                new_email_actual = new_email
                time.sleep(3)
                continue
            hint = ""
            msg_lower = str(exc).lower()
            if "login_session" in msg_lower and browser_mode == "protocol":
                hint = " 建议切换为 headless 模式重试(或检查代理 IP 信誉)。"
            raise HTTPException(502, f"注册新邮箱失败(重试 3 次): {exc}.{hint}")

    if not new_email_actual:
        raise HTTPException(502, "注册成功但未拿到新邮箱地址")

    return {
        "account_id": account_id,
        "acc_email": acc.email,
        "cf_domain": cf_domain,
        "browser_mode": browser_mode,
        "proxy": proxy,
        "proxy_source": proxy_source,
        "extra_config": extra_config,
        "new_email_actual": new_email_actual,
        "new_account_obj": new_account_obj,
        "reg_result": reg_result,
    }


def _phase_acquire_sub_rt(ctx: Dict[str, Any], log) -> None:
    """阶段2:等 propagate + 拿子号 RT(优先操作)。拿不到 RT 抛 HTTPException —
    此时尚未发邀请,母号配额不会被浪费。成功则把 RT/AT 等写回 ctx。"""
    browser_mode = ctx["browser_mode"]
    proxy = ctx["proxy"]
    extra_config = ctx["extra_config"]
    new_email_actual = ctx["new_email_actual"]
    new_account_obj = ctx["new_account_obj"]
    reg_result = ctx["reg_result"]

    verify: dict[str, Any] = {
        "rt_acquired": False,
        "rt_source": "skipped",
        "codex_test_ok": False,
        "codex_test_http": 0,
        "codex_test_reply": "",
        "codex_test_model": "",
        "codex_test_error": "",
        "synced_codex_app": False,
        "reward_confirmed": False,
    }

    log("⏳ 等 60 秒让 OpenAI propagate 新号…")
    time.sleep(60)

    # 拿新号 RT
    new_rt = ""
    new_at = ""
    new_id_token = ""
    if browser_mode in ("headless", "headed") and isinstance(reg_result, dict):
        new_rt = str(reg_result.get("refresh_token") or "").strip()
        new_at = str(reg_result.get("access_token") or "").strip()
        new_id_token = str(reg_result.get("id_token") or "").strip()
        if new_rt:
            verify["rt_source"] = "headless_direct"
            log(f"🔐 复用注册阶段已拿到的 RT (len={len(new_rt)})")

    if not new_rt:
        # 复用「平台管理 ChatGPT → 补 RT」action 完全相同链路 (退避重试 + add_phone + 席位切换)
        log(f"🔐 复用「补 RT」action 给新号 {new_email_actual} 拿 RT (browser_mode=headless)")
        try:
            from platforms.chatgpt.plugin import ChatGPTPlatform
            from core.base_platform import RegisterConfig as _RegCfg
            rt_platform = ChatGPTPlatform(
                config=_RegCfg(executor_type="protocol", proxy=proxy, extra=dict(extra_config)),
            )
            try:
                rt_platform._log_fn = log
            except Exception:
                pass
            if not (new_account_obj and (new_account_obj.password or "")):
                raise RuntimeError("新号缺密码,无法跑 OAuth login")
            action_result = rt_platform._action_acquire_rt(
                new_account_obj, {"browser_mode": "headless", "_log_fn": log}, proxy,
            )
            if action_result.get("ok"):
                patch = action_result.get("account_extra_patch") or action_result.get("data") or {}
                new_rt = str(patch.get("refresh_token") or "").strip()
                new_at = str(patch.get("access_token") or "").strip()
                new_id_token = str(patch.get("id_token") or "").strip()
                if new_rt:
                    verify["rt_source"] = "action_acquire_rt"
                    log(f"✓ 补 RT action 拿到 RT (len={len(new_rt)})")
            else:
                log(f"⚠ 补 RT action 失败: {action_result.get('error')}")
        except Exception as exc:
            log(f"⚠ 补 RT 异常: {exc}")

    verify["rt_acquired"] = bool(new_rt)

    # RT 失败 → 本次重置失败。此时【尚未发邀请】,母号配额不会被浪费。
    # 抛出让 batch 计 failed + 继续下一个。
    if not new_rt:
        raise HTTPException(
            502,
            f"新号 {new_email_actual} RT 获取失败 — 本次重置失败(子号已注册,但未发邀请、未消耗母号配额)",
        )

    # 9. 回写新号 accounts 表
    if new_account_obj is not None:
        try:
            from core.db import save_account as _save_acc2
            _extra = dict(new_account_obj.extra or {})
            _extra.update({
                "access_token": new_at or _extra.get("access_token", ""),
                "refresh_token": new_rt,
                "id_token": new_id_token or _extra.get("id_token", ""),
                "chatgpt_registration_mode": "refresh_token",
                "chatgpt_has_refresh_token_solution": True,
            })
            new_account_obj.extra = _extra
            if new_at:
                new_account_obj.token = new_at
            _save_acc2(new_account_obj)
            log("✓ 新号 RT/AT 已回写 accounts 表")
        except Exception as exc:
            log(f"⚠ 新号 RT 落库失败(继续): {exc}")

    # 刷一次 RT 拿最新 AT + chatgpt_account_id (供 同步Codex App + codex_chat 共用)
    fresh_at = ""
    fresh_chatgpt_acc_id = ""
    try:
        from platforms.chatgpt.token_refresh import TokenRefreshManager as _TRM
        from platforms.chatgpt.utils import decode_jwt_payload as _decode_jwt
        _rt_res = _TRM(proxy_url=proxy).refresh_by_oauth_token(new_rt)
        if _rt_res.success and _rt_res.access_token:
            fresh_at = _rt_res.access_token
            _payload = _decode_jwt(fresh_at) or {}
            _auth = _payload.get("https://api.openai.com/auth") or {}
            fresh_chatgpt_acc_id = str(_auth.get("chatgpt_account_id") or "").strip()
        else:
            log(f"⚠ RT 刷新失败 (后续用注册阶段 AT 兜底): {_rt_res.error_message}")
    except Exception as exc:
        log(f"⚠ RT 刷新异常 (后续用注册阶段 AT 兜底): {exc}")

    ctx["verify"] = verify
    ctx["new_rt"] = new_rt
    ctx["new_at"] = new_at
    ctx["new_id_token"] = new_id_token
    ctx["fresh_at"] = fresh_at
    ctx["fresh_chatgpt_acc_id"] = fresh_chatgpt_acc_id


def _phase_invite_and_reward(ctx: Dict[str, Any], log) -> Dict[str, Any]:
    """阶段3:母号即时刷 AT 发邀请 → 扣配额 → 同步 Codex → codex_chat → 等 reward。
    仅在子号已拿到 RT 后调用,保证配额不被浪费。"""
    from platforms.chatgpt.codex_referral import CodexReferralError
    account_id = ctx["account_id"]
    cf_domain = ctx["cf_domain"]
    browser_mode = ctx["browser_mode"]
    proxy = ctx["proxy"]
    proxy_source = ctx["proxy_source"]
    new_email_actual = ctx["new_email_actual"]
    new_account_obj = ctx["new_account_obj"]
    verify = ctx["verify"]
    new_rt = ctx["new_rt"]
    new_at = ctx["new_at"]
    new_id_token = ctx["new_id_token"]
    fresh_at = ctx["fresh_at"]
    fresh_chatgpt_acc_id = ctx["fresh_chatgpt_acc_id"]

    with Session(engine) as s:
        acc = s.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "PRO 账号不存在")

    # 5. 用 PRO 号发邀请(母号 AT 即时刷新:过期会自动用 RT 重刷再重试)
    log(f"用本 PRO 号给 {new_email_actual} 发邀请…")
    invite_proxy = _gpt_pro_codex_proxy()
    try:
        status, data = _codex_invite_with_refresh(acc, [new_email_actual], invite_proxy, log=log)
    except CodexReferralError as e:
        raise HTTPException(502, f"子号已就绪但母号邀请失败: {e}")
    except Exception as e:
        raise HTTPException(500, f"子号已就绪但母号邀请异常: {e}")
    if status != 200:
        raise HTTPException(status, f"子号已就绪但 ChatGPT 拒绝邀请: {data}")
    log(f"✓ 邀请已发出,referral_id={(data or {}).get('referral_id', '?')}")

    # 6. PRO 账号 referral_remaining-- 落库 + 追加 invited_emails
    new_remaining: Optional[int] = None
    try:
        with Session(engine) as s:
            row = s.get(GptProAccountModel, account_id)
            if row:
                base = row.referral_remaining if row.referral_remaining is not None else 0
                new_remaining = max(0, int(base) - 1)
                row.referral_remaining = new_remaining
                row.referral_quota_checked_at = _utcnow()
                row.updated_at = _utcnow()
                s.add(row)
                s.commit()
    except Exception:
        pass

    invited = _append_referral_invited(account_id, new_email_actual)
    # 把这次用的域名置顶 — 下次默认选它
    try:
        _promote_cf_domain(cf_domain)
    except Exception:
        pass

    # reward 基线: 在触发 reward (后面发 hi) 之前先记下母号收件箱已有邮件,
    # 避免后面匹配到上次推荐留下的历史 reward 邮件而误判成功
    reward_baseline = _snapshot_reward_baseline(account_id, log)

    # 10. 同步 Codex App — 把新号 token 写入 ~/.codex/auth.json
    try:
        path = _write_codex_auth_json(
            fresh_at or new_at, new_rt, new_id_token, fresh_chatgpt_acc_id, log,
        )
        verify["synced_codex_app"] = True
        log(f"✓ 已同步到本地 Codex App: {path}")
    except Exception as exc:
        log(f"⚠ 同步 Codex App 失败(继续): {exc}")

    # 11. 用新号 RT 发 codex_chat("hi") 触发 reward
    if fresh_at and fresh_chatgpt_acc_id:
        log("💬 用新号发 codex_chat('hi') 触发 reward…")
        try:
            from platforms.chatgpt.codex_chat import codex_chat as _codex_chat
            _chat = _codex_chat(
                access_token=fresh_at,
                chatgpt_account_id=fresh_chatgpt_acc_id,
                prompt="hi",
                model="gpt-5.5",
                proxy=proxy,
                timeout=60,
            )
            verify["codex_test_ok"] = bool(_chat.get("ok"))
            verify["codex_test_http"] = int(_chat.get("http_status") or 0)
            verify["codex_test_reply"] = str(_chat.get("reply") or "")[:600]
            verify["codex_test_model"] = str(_chat.get("model") or "gpt-5.5")
            if not verify["codex_test_ok"]:
                verify["codex_test_error"] = str(_chat.get("raw_error") or "")[:400]
            log(
                f"💬 codex 测试 {'✓' if verify['codex_test_ok'] else '✗'} "
                f"HTTP {verify['codex_test_http']} reply={verify['codex_test_reply'][:80]}"
            )
        except Exception as exc:
            verify["codex_test_error"] = f"codex 测试异常: {exc}"
            log(f"⚠ codex 测试异常: {exc}")
    else:
        log("⊘ 无 fresh AT / chatgpt_account_id,跳过 codex 测试")

    # 12. 等母号收件箱收到 reward 邮件 (固定超时), 收到则打绿勾
    from core.config_store import config_store as _cs_reward
    try:
        reward_timeout = max(30, min(1800, int(_cs_reward.get("gpt_pro_reward_wait_seconds", 300) or 300)))
    except Exception:
        reward_timeout = 300
    log(f"📬 等母号 {acc.email} 收 reward 邮件(推荐奖励/发送第一条消息+额度)(最多 {reward_timeout}s)…")
    if _wait_for_reward_email(account_id, reward_timeout, log, baseline=reward_baseline):
        _mark_referral_confirmed(account_id, new_email_actual)
        verify["reward_confirmed"] = True
        log(f"🎉 reward 邮件已收到 → {new_email_actual} 已打勾(绿色),本次重置完成")
    else:
        log(f"⚠ reward 邮件未在 {reward_timeout}s 内到达 → 未打勾,需人工确认 (RT/同步均已完成)")

    return {
        "ok": True,
        "registered_email": new_email_actual,
        "cf_domain": cf_domain,
        "browser_mode": browser_mode,
        "proxy_source": proxy_source or "",
        "referral_id": (data or {}).get("referral_id"),
        "remaining": new_remaining,
        "invited_emails": invited,
        "raw_invite": data,
        # 自动验证结果
        **verify,
    }


def _do_invite_auto(task_id: str, account_id: int,
                    body: GptProReferralInviteAutoRequest,
                    log) -> Dict[str, Any]:
    """单账号自动邀请:注册子号 → 拿子号 RT(优先) → 母号邀请+reward。
    顺序保证 RT 拿不到就不发邀请、不浪费母号配额。"""
    ctx = _phase_register_sub(account_id, body, log)
    _phase_acquire_sub_rt(ctx, log)
    return _phase_invite_and_reward(ctx, log)


def _phase_probe_parent(account_id: int, log) -> tuple[bool, str]:
    """阶段0 母号 OAuth 预检:走完整恢复链路 _gpt_pro_resolve_codex_credentials —
    先用 codex_refresh_token 刷一次 AT;遇到 refresh_token_reused/invalid_grant 等真死时,
    自动用母号邮箱+密码重新 OAuth login 拿新 RT 落库,再刷一次。只有连重拿都失败才判不可用。
    成功会顺带把轮换后的新 RT/AT 落库。返回 (可用, 不可用原因)。"""
    try:
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, account_id)
        if not acc:
            return False, "母号不存在"
        if not (acc.codex_refresh_token or "").strip():
            return False, "母号无 codex_refresh_token"
        # _allow_reauth=True → refresh_token_reused 时自动重新 OAuth(密码登录)拿新 RT
        _gpt_pro_resolve_codex_credentials(acc, log=log, _allow_reauth=True)
        return True, ""
    except HTTPException as exc:
        return False, str(getattr(exc, "detail", None) or exc)
    except Exception as exc:
        return False, str(exc)


# ── 一键批量重置 ─────────────────────────────────────────────
class BatchResetItem(BaseModel):
    account_id: int
    count: int = 1                  # 该账号重置几次


class GptProBatchResetRequest(BaseModel):
    cf_domain: str                          # 必填:从清单里选一个
    browser_mode: str = "protocol"          # protocol | headless | headed
    # items 非空 → 只重置这些账号(各自 count 次);
    # items 为空 → 默认全部:对所有有 RT 的账号, 按各自 referral_remaining 次数重置
    items: List[BatchResetItem] = []


@router.post("/accounts/batch-reset")
def gpt_pro_batch_reset(body: GptProBatchResetRequest):
    """启动一键批量重置后台任务, 立即返回 task_id;
    前端用 GET /accounts/batch-reset/{task_id}?since=N 轮询进度+日志。

    单线程串行: 遍历每个账号, 按指定次数(或剩余次数)依次重置。
    每次重置 = 注册新号 → 邀请 → 等 60s → 拿新号 RT → 验证。
    一个子号完成后等 5s; 同账号重置多次之间也等 5s。失败跳过继续。
    """
    cf_domain = (body.cf_domain or "").strip().lower()
    if not cf_domain:
        raise HTTPException(400, "请选择 CF 邀请域名")
    if cf_domain not in _load_cf_domains():
        raise HTTPException(400, f"CF 域名「{cf_domain}」不在已配置清单内")

    # 解析待重置计划: [(account_id, count), ...]
    plan: List[tuple] = []
    if body.items:
        for it in body.items:
            cnt = max(0, int(it.count or 0))
            if cnt > 0:
                plan.append((int(it.account_id), cnt))
    else:
        # 默认全部: 所有有 codex_rt 的账号, 按各自剩余次数(referral_remaining)
        with Session(engine) as s:
            rows = s.exec(select(GptProAccountModel)).all()
            for r in rows:
                if not r.enabled:
                    continue
                if not (r.codex_refresh_token or "").strip():
                    continue
                cnt = int(r.referral_remaining or 0)
                if cnt > 0:
                    plan.append((int(r.id), cnt))

    if not plan:
        raise HTTPException(400, "没有可重置的账号(选中的账号次数为 0, 或默认全部时无任何有 RT 且剩余次数>0 的账号)")

    total_resets = sum(c for _, c in plan)
    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_batch_reset,
        args=(task_id, cf_domain, body.browser_mode or "protocol", plan, total_resets),
        name=f"gpt-pro-batchreset-{task_id[:8]}",
        daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id, "total_accounts": len(plan), "total_resets": total_resets}


@router.get("/accounts/batch-reset/{task_id}")
def gpt_pro_batch_reset_status(task_id: str, since: int = Query(0, ge=0)):
    """轮询批量重置任务状态 + 增量日志 + 进度(iCloud 批量邀请也用这个查)。"""
    snapshot = _snapshot_invite_task(task_id, since=since)
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


class GptProBatchInviteIcloudRequest(BaseModel):
    browser_mode: str = "headless"
    # items 非空 → 只用这些母号(各自 count 次);空 → 所有有 codex RT 的号按 referral_remaining
    items: List[BatchResetItem] = []


@router.post("/accounts/batch-invite-icloud")
def gpt_pro_batch_invite_icloud(body: GptProBatchInviteIcloudRequest):
    """批量邀请(iCloud 邮箱源):从 iCloud 候选池挑现成号,给选中的母号依次邀请+完成。
    子号走 iCloud 邮箱 OTP OAuth。前端用 GET /accounts/batch-reset/{task_id} 轮询(共用任务存储)。"""
    plan: List[tuple] = []
    if body.items:
        for it in body.items:
            cnt = max(0, int(it.count or 0))
            if cnt > 0:
                plan.append((int(it.account_id), cnt))
    else:
        with Session(engine) as s:
            rows = s.exec(select(GptProAccountModel)).all()
            for r in rows:
                if not r.enabled or not (r.codex_refresh_token or "").strip():
                    continue
                cnt = int(r.referral_remaining or 0)
                if cnt > 0:
                    plan.append((int(r.id), cnt))
    if not plan:
        raise HTTPException(400, "没有可邀请的母号(选中次数为 0,或无有 codex RT 且剩余次数>0 的号)")
    pool_n = len(_icloud_invite_candidate_pool())
    if pool_n == 0:
        raise HTTPException(400, "iCloud 候选池为空(无可邀请的 iCloud 邮箱)")
    total = min(sum(c for _, c in plan), pool_n)
    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_batch_invite_icloud,
        args=(task_id, body.browser_mode or "headless", plan, total),
        name=f"gpt-pro-batchinvite-{task_id[:8]}", daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id, "total": total, "pool": pool_n}


def _run_batch_invite_icloud(task_id: str, browser_mode: str, plan: List[tuple], total: int) -> None:
    """批量 iCloud 邀请后台任务:逐母号、逐候选 邀请+完成。失败跳过继续。"""
    log = lambda m: _invite_task_log(task_id, m)
    proxy = _gpt_pro_codex_proxy()
    done = ok = failed = 0
    try:
        _set_invite_progress(task_id, {"total": total, "done": 0, "ok": 0, "failed": 0, "phase": "start"})
        pool = _icloud_invite_candidate_pool()
        used: set = set()
        log(f"批量 iCloud 邀请启动: {len(plan)} 个母号, 计划 {total} 次, 候选池 {len(pool)} 个")
        for parent_id, count in plan:
            with Session(engine) as s:
                parent = s.get(GptProAccountModel, parent_id)
            if not parent or not (parent.codex_refresh_token or "").strip():
                log(f"⊘ 母号 #{parent_id} 不存在或无 codex RT, 跳过")
                continue
            pemail = parent.email
            for _ in range(count):
                cand = next((c for c in pool
                             if c["email"].lower() not in used
                             and c["email"].lower() != (pemail or "").lower()), None)
                if not cand:
                    log("候选池已耗尽, 结束批量邀请")
                    _invite_task_finish(task_id, result={"total": total, "ok": ok, "failed": failed})
                    return
                used.add(cand["email"].lower())
                _set_invite_progress(task_id, {"total": total, "done": done, "ok": ok, "failed": failed,
                                               "current_account": f"{pemail} → {cand['email']}", "phase": "invite"})
                log(f"[{done + 1}/{total}] 母号 {pemail} 邀请 {cand['email']} ({cand['source']})…")
                try:
                    with Session(engine) as s:
                        parent = s.get(GptProAccountModel, parent_id)   # 重读, RT 可能轮换
                    status, data = _codex_invite_with_refresh(parent, [cand["email"]], proxy, log=log)
                    if status != 200:
                        raise RuntimeError(f"邀请被拒 HTTP {status}: {data}")
                    _append_referral_invited(parent_id, cand["email"])
                    try:
                        with Session(engine) as s:
                            row = s.get(GptProAccountModel, parent_id)
                            if row:
                                row.referral_remaining = max(0, int(row.referral_remaining or 0) - 1)
                                row.referral_quota_checked_at = _utcnow()
                                row.updated_at = _utcnow()
                                s.add(row)
                                s.commit()
                    except Exception:
                        pass
                    _dec_referral_capacity(parent_id, send=1)
                    log(f"  ✓ 邀请已发 referral_id={(data or {}).get('referral_id', '?')}")
                    # 子号(GptProAccountModel)拿凭证:无 codex RT → iCloud OTP OAuth
                    child_id = cand["id"]
                    with Session(engine) as s:
                        child = s.get(GptProAccountModel, child_id)
                    if not (child.codex_refresh_token or "").strip():
                        log(f"  🔐 子号 {cand['email']} 无 codex RT, OAuth(iCloud OTP)…")
                        if not _reacquire_parent_codex_rt(child, log):
                            raise RuntimeError("子号 OAuth 拿 codex RT 失败")
                        with Session(engine) as s:
                            child = s.get(GptProAccountModel, child_id)
                    fresh_at, acc_id = _gpt_pro_resolve_codex_credentials(child, log=log)
                    with Session(engine) as s:
                        c2 = s.get(GptProAccountModel, child_id)
                        c_rt = (c2.codex_refresh_token or "").strip()
                        c_id = (c2.codex_id_token or "").strip()
                        c_at = (c2.codex_access_token or "").strip()
                    confirmed = _referral_complete_core(
                        parent_id, cand["email"], proxy, c_rt, c_at, c_id, fresh_at, acc_id, log)
                    ok += 1
                    log(f"  {'🎉 已确认' if confirmed else '⚠ 邀请成功但 reward 未到, 需人工确认'}")
                except Exception as exc:
                    failed += 1
                    log(f"  ✗ 失败: {exc}")
                done += 1
                _set_invite_progress(task_id, {"total": total, "done": done, "ok": ok, "failed": failed, "phase": "running"})
                time.sleep(5)
        _invite_task_finish(task_id, result={"total": total, "ok": ok, "failed": failed})
    except Exception as exc:
        _invite_task_finish(task_id, error=str(exc), result={"total": total, "ok": ok, "failed": failed})


def _run_batch_reset(task_id: str, cf_domain: str, browser_mode: str,
                     plan: List[tuple], total_resets: int) -> None:
    """分阶段批量重置(单线程串行):
      Phase0 母号 OAuth 预检 → 死号整体跳过(不浪费子号注册)
      Phase1 统一注册子号
      Phase2 统一拿子号 RT(优先;拿不到不发邀请 → 不浪费母号配额)
      Phase3 统一母号邀请 + reward
    逐账号结果实时写进 progress.report,结束写进 result.report。失败跳过继续。"""
    log = lambda m: _invite_task_log(task_id, m)

    # 把 plan 展开成"重置单元":每个母号 × 次数
    units: List[Dict[str, Any]] = []
    for account_id, count in plan:
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, account_id)
            pro_email = acc.email if acc else f"#{account_id}"
        for rep in range(1, count + 1):
            units.append({
                "pro_id": account_id,
                "pro_email": pro_email,
                "rep_label": f"{rep}/{count}",
                "status": "pending",   # pending|ok|failed|skipped
                "reason": "",
                "sub_email": "",
                "rt": False,
                "reward": False,
                "ctx": None,
            })

    def _counts() -> tuple:
        ok = sum(1 for u in units if u["status"] == "ok")
        failed = sum(1 for u in units if u["status"] == "failed")
        skipped = sum(1 for u in units if u["status"] == "skipped")
        return ok, failed, skipped

    def _report() -> List[Dict[str, Any]]:
        return [{k: u[k] for k in ("pro_id", "pro_email", "rep_label", "status", "reason", "sub_email", "rt", "reward")}
                for u in units]

    def _emit(phase: str = "", current: str = "") -> None:
        ok, failed, skipped = _counts()
        _set_invite_progress(task_id, {
            "total": total_resets,
            "done": ok + failed + skipped,
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "current_account": current,
            "phase": phase,
            "report": _report(),
        })

    def _err_detail(exc: Exception) -> str:
        return str(getattr(exc, "detail", None) or exc)

    log(f"批量重置启动: {len(plan)} 个母号, 共 {total_resets} 次重置 (域名={cf_domain}, 模式={browser_mode})")
    _emit("启动")

    # 整个批量期间暂停调度器后台任务,避免后台 curl_cffi 与本任务并发触碰 BoringSSL
    # 句柄导致 TLS 崩(curl 35 OPENSSL_internal:invalid library)。
    from core.scheduler import scheduler as _scheduler
    _scheduler.pause()
    log("⏸ 已暂停调度器后台任务(批量结束后自动恢复)")

    try:
        # ── Phase0: 母号 OAuth 预检(每个母号只探一次,结果套用到它的所有单元)──
        log("━━ Phase0 母号 OAuth 预检 ━━")
        probe_cache: Dict[int, tuple] = {}
        for pid in {u["pro_id"] for u in units}:
            pemail = next((u["pro_email"] for u in units if u["pro_id"] == pid), f"#{pid}")
            _emit("Phase0 预检", pemail)
            ok_probe, reason = _phase_probe_parent(pid, log)
            probe_cache[pid] = (ok_probe, reason)
            if ok_probe:
                log(f"  ✓ {pemail} OAuth 可用(已刷新母号 AT/RT)")
            else:
                log(f"  ✗ {pemail} OAuth 不可用 → 跳过其全部单元: {reason}")
                for u in units:
                    if u["pro_id"] == pid:
                        u["status"] = "skipped"
                        u["reason"] = f"母号 OAuth 预检失败: {reason}"
        _emit("Phase0 预检")

        alive = [u for u in units if u["status"] == "pending"]

        # ── Phase1: 统一注册子号 ──
        log(f"━━ Phase1 统一注册子号({len(alive)} 个)━━")
        for i, u in enumerate(alive, 1):
            if u["status"] != "pending":
                continue
            _emit("Phase1 注册", f"{u['pro_email']} [{u['rep_label']}]")
            log(f"  ▶ 注册 {i}/{len(alive)} (母号 {u['pro_email']} {u['rep_label']})")
            try:
                body = GptProReferralInviteAutoRequest(cf_domain=cf_domain, browser_mode=browser_mode)
                ctx = _phase_register_sub(u["pro_id"], body, log)
                u["ctx"] = ctx
                u["sub_email"] = ctx.get("new_email_actual", "")
                log(f"  ✓ 注册成功: {u['sub_email']}")
            except Exception as exc:
                u["status"] = "failed"
                u["reason"] = f"注册失败: {_err_detail(exc)}"
                log(f"  ✗ 注册失败(跳过): {_err_detail(exc)}")
            _emit("Phase1 注册")
            if i < len(alive):
                time.sleep(5)

        # ── Phase2: 统一拿子号 RT(优先;拿不到不发邀请)──
        reg_ok = [u for u in units if u["status"] == "pending" and u["ctx"]]
        log(f"━━ Phase2 统一拿子号 RT({len(reg_ok)} 个)━━")
        for i, u in enumerate(reg_ok, 1):
            _emit("Phase2 拿RT", f"{u['sub_email']}")
            log(f"  ▶ 拿 RT {i}/{len(reg_ok)}: {u['sub_email']}")
            try:
                _phase_acquire_sub_rt(u["ctx"], log)
                u["rt"] = True
                log(f"  ✓ RT 已拿到: {u['sub_email']}")
            except Exception as exc:
                u["status"] = "failed"
                u["reason"] = f"拿 RT 失败(未发邀请、未扣配额): {_err_detail(exc)}"
                log(f"  ✗ 拿 RT 失败(跳过,未扣配额): {_err_detail(exc)}")
            _emit("Phase2 拿RT")

        # ── Phase3: 统一母号邀请 + reward ──
        rt_ok = [u for u in units if u["status"] == "pending" and u["rt"]]
        log(f"━━ Phase3 统一邀请 + reward({len(rt_ok)} 个)━━")
        for i, u in enumerate(rt_ok, 1):
            _emit("Phase3 邀请", f"{u['pro_email']} → {u['sub_email']}")
            log(f"  ▶ 邀请 {i}/{len(rt_ok)}: {u['pro_email']} → {u['sub_email']}")
            try:
                res = _phase_invite_and_reward(u["ctx"], log)
                u["status"] = "ok"
                u["reward"] = bool(res.get("reward_confirmed"))
                rt_s = "✓RT" if res.get("rt_acquired") else "✗RT"
                chat_s = "✓chat" if res.get("codex_test_ok") else "✗chat"
                rw_s = "✓reward打勾" if res.get("reward_confirmed") else "⚠reward待人工"
                log(f"  ✓ 完成: {res.get('registered_email')} [{rt_s} {chat_s} {rw_s}] 剩余={res.get('remaining')}")
            except Exception as exc:
                u["status"] = "failed"
                u["reason"] = f"邀请/reward 失败(配额可能已消耗): {_err_detail(exc)}"
                log(f"  ✗ 邀请失败(跳过): {_err_detail(exc)}")
            _emit("Phase3 邀请")
            if i < len(rt_ok):
                time.sleep(5)

        # 收尾:仍为 pending 的(理论上不该有)按失败计
        for u in units:
            if u["status"] == "pending":
                u["status"] = "failed"
                u["reason"] = u["reason"] or "未知(未进入任何阶段)"

        ok_count, fail_count, skip_count = _counts()
        _emit("完成")
        _invite_task_finish(task_id, result={
            "total": total_resets,
            "ok": ok_count,
            "failed": fail_count,
            "skipped": skip_count,
            "accounts": len(plan),
            "report": _report(),
        })
        log(f"✓ 批量重置全部完成: 成功 {ok_count} / 失败 {fail_count} / 跳过 {skip_count} / 共 {total_resets}")
    except Exception as exc:
        ok_count, fail_count, skip_count = _counts()
        log(f"✗ 批量重置任务异常: {exc}")
        _invite_task_finish(task_id, error=str(exc), result={
            "total": total_resets, "ok": ok_count, "failed": fail_count,
            "skipped": skip_count, "accounts": len(plan), "report": _report(),
        })
    finally:
        _scheduler.resume()
        log("▶ 已恢复调度器后台任务")


# ── 批量操作 ─────────────────────────────────────────────────

@router.post("/accounts/batch-delete")
def batch_delete_gpt_pro(body: GptProBatchDeleteRequest):
    deleted = 0
    skipped_business = 0
    with Session(engine) as session:
        for aid in body.ids:
            acc = session.get(GptProAccountModel, aid)
            if not acc:
                continue
            if getattr(acc, "business_parent_id", None) is not None:
                skipped_business += 1
                continue
            session.delete(acc)
            deleted += 1
        session.commit()
    return {"deleted": deleted, "skipped_business": skipped_business}


class GptProCleanupDeadRequest(BaseModel):
    days: int = 30          # 只处理「订阅时间早于这么多天」的账号(默认一个月)
    dry_run: bool = True    # True=仅预览(不删除), False=真删


@router.post("/accounts/cleanup-dead-refunded")
def cleanup_dead_refunded(body: Optional[GptProCleanupDeadRequest] = None):
    """清理「已退款 + 已 dead(dangerous)+ 订阅早于 N 天」的账号。
    dead 判据: dangerous=True(收到 OpenAI "Access Deactivated / 访问权限已停用" 邮件)。
    退款是退到卡, 与账号无关, 删死号不影响退款到账。默认 dry_run 只预览。"""
    from datetime import timedelta
    body = body or GptProCleanupDeadRequest()
    days = max(0, int(body.days or 0))
    cutoff = _utcnow() - timedelta(days=days)

    def _aware(dt):
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    targets = []
    with Session(engine) as session:
        rows = session.exec(select(GptProAccountModel)).all()
        for a in rows:
            if a.refund_status != "refunded_pending_credit":
                continue
            if not a.dangerous:
                continue
            ref = _aware(a.subscribed_at) or _aware(getattr(a, "created_at", None))
            if ref is not None and ref > cutoff:
                continue  # 太新(订阅不足 N 天), 保护性跳过
            targets.append(a)

        preview = [{
            "id": a.id, "email": a.email,
            "subscribed_at": a.subscribed_at.isoformat() if a.subscribed_at else None,
            "dead_at": a.dangerous_detected_at.isoformat() if getattr(a, "dangerous_detected_at", None) else None,
        } for a in targets]

        if body.dry_run:
            return {"dry_run": True, "days": days, "count": len(targets), "accounts": preview}

        deleted = 0
        for a in targets:
            session.delete(a)
            deleted += 1
        session.commit()
    return {"dry_run": False, "days": days, "deleted": deleted, "accounts": preview}


class GptProRescanDangerRequest(BaseModel):
    fetch: int = 50               # 每账号深挖多少封邮件(默认 50, 覆盖监控的 15 窗口漏检)
    only_undetected: bool = True  # True=只扫尚未标 dangerous 的账号(更快)


@router.post("/accounts/rescan-dangerous")
def rescan_dangerous(body: Optional[GptProRescanDangerRequest] = None):
    """深度重扫: 对每个账号拉更大邮件窗口(默认 50 封), 重新识别 "Access Deactivated" 停用
    与政策告警邮件, 补标 dangerous / policy_warning。修监控 15 封窗口漏掉的老停用邮件。
    后台任务, 立即返回 task_id; 前端用 GET /accounts/rescan-dangerous/{task_id}?since=N 轮询。"""
    body = body or GptProRescanDangerRequest()
    fetch_n = max(15, min(200, int(body.fetch or 50)))
    only_undetected = bool(body.only_undetected)

    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel).where(
            GptProAccountModel.is_pro == True)).all()  # noqa: E712
        targets = [(a.id, a.email) for a in rows if not (only_undetected and a.dangerous)]

    task_id = _create_invite_task()

    def _worker():
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from services.chatgpt_mail_common import (
            DANGEROUS_SUBJECT_KEYWORDS, POLICY_WARNING_SUBJECT_KEYWORDS)
        new_dead: List[str] = []
        new_policy: List[str] = []
        new_appeal: List[str] = []
        done = 0

        def _scan(job):
            aid, email = job
            try:
                # 短事务取账号 → expunge → 慢速取件不占连接(避免 QueuePool 打满)
                with Session(engine) as s0:
                    a = s0.get(GptProAccountModel, aid)
                    if not a:
                        return None
                    had_appeal = bool((getattr(a, "appeal_url", "") or "").strip())
                    s0.expunge(a)
                msgs = _fetch_recent_for_account(a, fetch_n)
                subs = [str(m.get("subject") or "") for m in msgs]
                hit_d = any(any(k in sj for k in DANGEROUS_SUBJECT_KEYWORDS) for sj in subs)
                hit_p = any(any(k in sj for k in POLICY_WARNING_SUBJECT_KEYWORDS) for sj in subs)
                appeal_url = None
                if hit_d and not had_appeal:
                    appeal_url = _extract_appeal_url_from_messages(msgs)
                # 短事务写回
                tag = None
                got_appeal = False
                with Session(engine) as s2:
                    a2 = s2.get(GptProAccountModel, aid)
                    if not a2:
                        return None
                    changed = False
                    if hit_d and not a2.dangerous:
                        a2.dangerous = True
                        if not a2.dangerous_detected_at:
                            a2.dangerous_detected_at = _utcnow()
                        changed = True
                        tag = "dead"
                    if hit_p and not a2.policy_warning:
                        a2.policy_warning = True
                        if not a2.policy_warning_detected_at:
                            a2.policy_warning_detected_at = _utcnow()
                        changed = True
                        tag = tag or "policy"
                    if appeal_url and not (getattr(a2, "appeal_url", "") or "").strip():
                        a2.appeal_url = appeal_url
                        changed = True
                        got_appeal = True
                    if changed:
                        a2.updated_at = _utcnow()
                        s2.add(a2)
                        s2.commit()
                return (email, tag, got_appeal)
            except Exception as exc:
                return (email, f"err:{str(exc)[:40]}", False)

        try:
            _invite_task_log(task_id, f"深度重扫开始: {len(targets)} 个账号, 每号拉 {fetch_n} 封")
            with ThreadPoolExecutor(max_workers=16) as ex:
                futs = [ex.submit(_scan, j) for j in targets]
                for fut in as_completed(futs):
                    done += 1
                    r = fut.result()
                    if r:
                        email, tag, got_appeal = r
                        if tag == "dead":
                            new_dead.append(email)
                            _invite_task_log(task_id, f"🔴 补标 dead: {email}")
                        elif tag == "policy":
                            new_policy.append(email)
                        if got_appeal:
                            new_appeal.append(email)
                            _invite_task_log(task_id, f"🔗 补申诉链接: {email}")
                    if done % 25 == 0 or done == len(targets):
                        _set_invite_progress(task_id, {"done": done, "total": len(targets),
                                                       "new_dead": len(new_dead), "new_policy": len(new_policy),
                                                       "new_appeal": len(new_appeal)})
            _invite_task_finish(task_id, result={
                "scanned": len(targets), "new_dangerous": len(new_dead),
                "new_policy": len(new_policy), "new_appeal": len(new_appeal),
                "dead_emails": new_dead,
            })
            _invite_task_log(task_id, f"完成: 新补标 dead {len(new_dead)} 个, policy {len(new_policy)} 个, "
                                      f"补申诉链接 {len(new_appeal)} 个")
        except Exception as exc:
            _invite_task_finish(task_id, error=str(exc))

    threading.Thread(target=_worker, daemon=True, name=f"rescan-danger-{task_id[:8]}").start()
    return {"task_id": task_id, "targets": len(targets), "fetch": fetch_n}


@router.get("/accounts/rescan-dangerous/{task_id}")
def rescan_dangerous_status(task_id: str, since: int = Query(0, ge=0)):
    snapshot = _snapshot_invite_task(task_id, since=since)
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


@router.post("/accounts/backfill-appeal-url")
def backfill_appeal_url(fetch: int = Query(50, ge=15, le=200)):
    """给「已标 dangerous 但还没有申诉链接」的账号补申诉链接:
    每号拉 fetch 封邮件, 找 "Access Deactivated / 访问权限已停用" 邮件, 从正文提取"提出申诉"链接。
    后台任务, 立即返回 task_id; 复用 rescan-dangerous 的轮询接口 GET /accounts/rescan-dangerous/{task_id}。"""
    fetch_n = max(15, min(200, int(fetch or 50)))
    with Session(engine) as s:
        rows = s.exec(select(GptProAccountModel).where(
            GptProAccountModel.dangerous == True)).all()  # noqa: E712
        targets = [(a.id, a.email) for a in rows
                   if not (getattr(a, "appeal_url", "") or "").strip()]

    task_id = _create_invite_task()

    def _worker():
        from concurrent.futures import ThreadPoolExecutor, as_completed
        new_appeal: List[str] = []
        done = 0

        def _scan(job):
            aid, email = job
            try:
                # 1) 短事务取出账号后立刻 expunge + 关会话, 不在慢速取件期间占用 DB 连接
                #    (否则 16 并发各持一条连接跨网络取件 → QueuePool 打满 timeout)
                with Session(engine) as s0:
                    a = s0.get(GptProAccountModel, aid)
                    if not a:
                        return (email, False)
                    if (getattr(a, "appeal_url", "") or "").strip():
                        return (email, False)
                    s0.expunge(a)
                # 2) 慢速取件(不占 DB 连接)
                msgs = _fetch_recent_for_account(a, fetch_n)
                url = _extract_appeal_url_from_messages(msgs)
                if url:
                    # 3) 短事务写回
                    with Session(engine) as s2:
                        a2 = s2.get(GptProAccountModel, aid)
                        if a2 and not (getattr(a2, "appeal_url", "") or "").strip():
                            a2.appeal_url = url
                            a2.updated_at = _utcnow()
                            s2.add(a2)
                            s2.commit()
                    return (email, url)
                # 没提到 → 附上诊断(有无停用邮件 / 邮件里都有哪些链接)
                return (email, {"diag": _appeal_diag(msgs)})
            except Exception as exc:
                return (email, f"err:{str(exc)[:60]}")

        try:
            _invite_task_log(task_id, f"补申诉链接开始: {len(targets)} 个 dangerous 账号缺链接, 每号拉 {fetch_n} 封")
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = [ex.submit(_scan, j) for j in targets]
                for fut in as_completed(futs):
                    done += 1
                    email, got = fut.result()
                    if isinstance(got, str) and got.startswith("err:"):
                        _invite_task_log(task_id, f"⚠ {email}: {got}")
                    elif isinstance(got, str) and got:
                        new_appeal.append(email)
                        _invite_task_log(task_id, f"🔗 {email} → {got}")
                    elif isinstance(got, dict) and got.get("diag"):
                        d = got["diag"]
                        if not d.get("found"):
                            _invite_task_log(task_id, f"✗ {email}: {fetch_n} 封里没找到停用邮件"
                                                      f"(近期主题: {d.get('subjects')})")
                        else:
                            _invite_task_log(task_id, f"✗ {email}: 有停用邮件但没匹配到申诉链接 "
                                                      f"(is_html={d.get('is_html')} body_len={d.get('body_len')} "
                                                      f"链接{d.get('n_links')}条)")
                            for lk in (d.get("links") or []):
                                _invite_task_log(task_id, f"    · {lk}")
                            if not d.get("links") and d.get("urls"):
                                _invite_task_log(task_id, f"    裸URL: {d.get('urls')}")
                    if done % 25 == 0 or done == len(targets):
                        _set_invite_progress(task_id, {"done": done, "total": len(targets),
                                                       "new_appeal": len(new_appeal)})
            _invite_task_finish(task_id, result={
                "scanned": len(targets), "new_appeal": len(new_appeal),
                "appeal_emails": new_appeal,
            })
            _invite_task_log(task_id, f"完成: 补申诉链接 {len(new_appeal)}/{len(targets)} 个")
        except Exception as exc:
            _invite_task_finish(task_id, error=str(exc))

    threading.Thread(target=_worker, daemon=True, name=f"backfill-appeal-{task_id[:8]}").start()
    return {"task_id": task_id, "targets": len(targets), "fetch": fetch_n}


@router.get("/accounts/{account_id}/appeal-diag")
def appeal_diag(account_id: int, fetch: int = Query(100, ge=15, le=200)):
    """单账号诊断: 拉 fetch 封邮件, 找停用邮件, 返回它里面所有链接(锚文本+href)与裸 URL。
    用来看真实申诉链接长啥样、或确认根本没抓到停用邮件。直接浏览器打开即可。
    也顺带尝试用当前规则提取一次(extracted)。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        email = acc.email
        try:
            msgs = _fetch_recent_for_account(acc, max(15, min(200, int(fetch or 100))))
        except Exception as exc:
            return {"email": email, "error": f"取件失败: {exc}"}
    diag = _appeal_diag(msgs)
    extracted = _extract_appeal_url_from_messages(msgs)
    return {"email": email, "fetched": len(msgs), "extracted": extracted, "diag": diag}


@router.post("/accounts/{account_id}/open-appeal")
def open_appeal(account_id: int, dump_only: bool = Query(False),
                use_proxy: bool = Query(False)):
    """开浏览器打开该账号的申诉链接并自动填写(product=Codex / reason=My usage did not /
    Activity 起=订阅时间 止=封号时间), **不自动提交**, 留窗人工核对。
    dump_only=true 只回传表单控件清单(供校准选择器)。同步执行(要等浏览器开+填, ~10-15s)。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        appeal_url = (getattr(acc, "appeal_url", "") or "").strip()
        if not appeal_url:
            raise HTTPException(400, "该账号还没有申诉链接, 请先「补申诉链接」")
        email = acc.email
        sub = acc.subscribed_at
        ban = acc.dangerous_detected_at
    proxy = _resolve_action_proxy(None) if use_proxy else ""

    def _ymd_mdy(dt):
        if not dt:
            return "", ""
        d = dt.date() if hasattr(dt, "date") else dt
        return d.isoformat(), f"{d.month:02d}/{d.day:02d}/{d.year}"

    s_ymd, s_mdy = _ymd_mdy(sub)
    e_ymd, e_mdy = _ymd_mdy(ban)
    vals = {
        "email": email, "case_id": "",
        "start_ymd": s_ymd, "start_mdy": s_mdy,
        "end_ymd": e_ymd, "end_mdy": e_mdy,
    }
    from platforms.chatgpt.appeal_form import open_appeal_form
    res = open_appeal_form(appeal_url, vals, dump_only=dump_only, proxy=proxy, headless=False)
    res["account"] = email
    res["dates"] = {"start": s_ymd, "end": e_ymd}
    return res


@router.get("/accounts/{account_id}/appeal-script")
def appeal_script(account_id: int):
    """返回在【真实浏览器】申诉页里跑的自动填表脚本(不新开浏览器, 绕过 Cloudflare Turnstile)。
    值按账号 baked: product=Codex / reason=My usage did not / Activity 起=订阅 止=封号。
    前端弹窗给出脚本 + 书签版 + 申诉链接, 用户在已打开的申诉页控制台粘贴运行 / 或点书签。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        appeal_url = (getattr(acc, "appeal_url", "") or "").strip()
        if not appeal_url:
            raise HTTPException(400, "该账号还没有申诉链接, 请先「补申诉链接」")
        email = acc.email
        sub = acc.subscribed_at
        ban = acc.dangerous_detected_at

    def _ymd_mdy(dt):
        if not dt:
            return "", ""
        d = dt.date() if hasattr(dt, "date") else dt
        return d.isoformat(), f"{d.month:02d}/{d.day:02d}/{d.year}"

    s_ymd, s_mdy = _ymd_mdy(sub)
    e_ymd, e_mdy = _ymd_mdy(ban)
    vals = {
        "email": email, "case_id": "",
        "start_ymd": s_ymd, "start_mdy": s_mdy,
        "end_ymd": e_ymd, "end_mdy": e_mdy,
    }
    from platforms.chatgpt.appeal_form import build_appeal_fill_snippet
    snip = build_appeal_fill_snippet(vals)
    return {
        "ok": True,
        "account": email,
        "appeal_url": appeal_url,
        "dates": {"start": s_ymd or "(无订阅时间)", "end": e_ymd or "(无封号时间)"},
        "script": snip["script"],
        "bookmarklet": snip["bookmarklet"],
    }


@router.post("/accounts/{account_id}/mark-appealed")
def mark_appealed(account_id: int, done: bool = Query(True)):
    """点了申诉链接后打勾/取消勾。done=true → 记 appeal_done_at=now; done=false → 清空。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        acc.appeal_done_at = _utcnow() if done else None
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()
        return {"ok": True, "appeal_done_at": _iso_utc(acc.appeal_done_at)}


@router.post("/accounts/batch-update")
def batch_update_gpt_pro(body: GptProBatchUpdateRequest):
    updated = 0
    skipped_business = 0
    new_expires = None
    clear_expires = False
    if body.pro_expires_at is not None:
        if body.pro_expires_at == "":
            clear_expires = True
        else:
            new_expires = _parse_expires_at(body.pro_expires_at)

    with Session(engine) as session:
        for aid in body.ids:
            acc = session.get(GptProAccountModel, aid)
            if not acc:
                continue
            if getattr(acc, "business_parent_id", None) is not None:
                skipped_business += 1
                continue
            if body.is_pro is not None:
                acc.is_pro = body.is_pro
            if clear_expires:
                acc.pro_expires_at = None
            elif new_expires is not None:
                acc.pro_expires_at = new_expires
            if body.note is not None:
                acc.note = body.note
            if body.enabled is not None:
                acc.enabled = body.enabled
            acc.updated_at = _utcnow()
            session.add(acc)
            updated += 1
        session.commit()
    return {"updated": updated, "skipped_business": skipped_business}


@router.post("/accounts/delete-all")
def delete_all_gpt_pro(
    mail_access_type: Optional[str] = Query(None),
    is_pro: Optional[bool] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    with Session(engine) as session:
        query = select(GptProAccountModel).where(
            GptProAccountModel.business_parent_id.is_(None)  # type: ignore
        )
        if mail_access_type is not None:
            query = query.where(GptProAccountModel.mail_access_type == mail_access_type)
        if is_pro is not None:
            query = query.where(GptProAccountModel.is_pro == is_pro)
        if enabled is not None:
            query = query.where(GptProAccountModel.enabled == enabled)
        accounts = session.exec(query).all()
        deleted = len(accounts)
        for acc in accounts:
            session.delete(acc)
        session.commit()
    return {"deleted": deleted}


# ── 批量导入(后台任务) ────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _execute_gpt_pro_batch_import(task_id: str, request: GptProBatchImportRequest) -> None:
    _import_task_store.mark_running(task_id)

    lines = (request.data or "").splitlines()
    processed = 0
    success = 0
    failed = 0

    try:
        for idx, raw_line in enumerate(lines, start=1):
            line = str(raw_line or "").strip()
            if not line or line.startswith("#"):
                continue

            error_message = ""
            parts = [p.strip() for p in line.split("----")]

            email = ""
            password = ""
            refresh_token = ""
            client_id = ""

            if len(parts) == 2:
                email, password = parts
            elif len(parts) >= 4:
                email, password, third, fourth = parts[0], parts[1], parts[2], parts[3]
                if _UUID_RE.match(third) and not _UUID_RE.match(fourth):
                    client_id, refresh_token = third, fourth
                else:
                    refresh_token, client_id = third, fourth
            else:
                failed += 1
                error_message = (
                    f"行 {idx}: 格式错误,应为 邮箱----密码 或 "
                    f"邮箱----密码----refresh_token----client_id"
                )

            if not error_message:
                if not email or "@" not in email:
                    failed += 1
                    error_message = f"行 {idx}: 无效的邮箱地址: {email}"
                else:
                    try:
                        # 入库 + 自动 probe mail_access_type (有 OAuth 凭证时)
                        # probe 失败不影响入库 success, 只是 mail_access_type 留空
                        probed_type = ""
                        if client_id and refresh_token:
                            try:
                                from core.outlook_probe import classify_mail_access_type
                                probed_type = classify_mail_access_type(
                                    email, refresh_token, client_id,
                                ) or ""
                            except Exception:
                                probed_type = ""
                        with Session(engine) as session:
                            existing = session.exec(
                                select(GptProAccountModel)
                                .where(GptProAccountModel.email == email)
                            ).first()
                            if existing:
                                existing.password = password or existing.password
                                if refresh_token:
                                    existing.refresh_token = refresh_token
                                if client_id:
                                    existing.client_id = client_id
                                if probed_type and not existing.mail_access_type:
                                    existing.mail_access_type = probed_type
                                existing.enabled = bool(request.enabled)
                                if request.mark_pro:
                                    existing.is_pro = True
                                    if existing.referral_remaining is None:
                                        existing.referral_remaining = 3
                                existing.updated_at = _utcnow()
                                session.add(existing)
                            else:
                                account = GptProAccountModel(
                                    email=email,
                                    password=password,
                                    refresh_token=refresh_token,
                                    client_id=client_id,
                                    mail_access_type=probed_type,
                                    enabled=bool(request.enabled),
                                    is_pro=bool(request.mark_pro),
                                    # 新导入即标记 PRO 的账号:待重置次数默认 3
                                    referral_remaining=(3 if request.mark_pro else None),
                                    created_at=_utcnow(),
                                    updated_at=_utcnow(),
                                )
                                session.add(account)
                            session.commit()
                        success += 1
                    except Exception as e:
                        failed += 1
                        error_message = f"行 {idx}: 入库失败: {e}"

            processed += 1
            _import_task_store.update(
                task_id,
                processed=processed,
                success=success,
                failed=failed,
                append_error=error_message or None,
            )

        _import_task_store.finish(task_id, status="done")
    except Exception as e:
        _import_task_store.fail(task_id, f"导入任务异常: {e}")


@router.post("/batch-import")
def batch_import_gpt_pro(request: GptProBatchImportRequest):
    """批量导入 GPT PRO 账号。

    格式(每行一个,字段用 ---- 分隔):
        邮箱----密码
      或
        邮箱----密码----refresh_token----client_id
      或
        邮箱----密码----client_id----refresh_token  (UUID 自动识别)

    可通过 mark_pro=false 关闭"导入即标记为 PRO"的默认行为。
    """
    total = _count_import_lines(request.data)
    task_id = f"gpt_pro_import_{int(time.time() * 1000)}"
    _import_task_store.create(task_id, total=total)
    thread = threading.Thread(
        target=_execute_gpt_pro_batch_import,
        args=(task_id, request),
        daemon=True,
        name=f"gpt-pro-import-{task_id}",
    )
    thread.start()
    return {"task_id": task_id, "total": total}


@router.get("/import-tasks/{task_id}")
def get_import_task(task_id: str):
    _ensure_import_task_exists(task_id)
    return _import_task_store.snapshot(task_id)


@router.get("/import-tasks")
def list_import_tasks(limit: int = Query(20, ge=1, le=100)):
    items = _import_task_store.list_snapshots()[:limit]
    return {"total": len(items), "items": items}


# ── 取码类型探测 ─────────────────────────────────────────────

class GptProProbeRequest(BaseModel):
    ids: List[int]


@router.post("/accounts/probe")
def probe_mail_access_type(body: GptProProbeRequest):
    """对指定账号探测/刷新取码类型(复用 Outlook 探测逻辑)。"""
    from core.outlook_probe import classify_mail_access_type

    results: List[Dict[str, Any]] = []
    with Session(engine) as session:
        for aid in body.ids:
            acc = session.get(GptProAccountModel, aid)
            if not acc:
                results.append({"id": aid, "ok": False, "error": "不存在"})
                continue
            if not (acc.refresh_token and acc.client_id):
                results.append({"id": aid, "ok": False, "email": acc.email, "error": "缺少 OAuth 信息"})
                continue
            mail_type = classify_mail_access_type(acc.email, acc.refresh_token, acc.client_id)
            if mail_type:
                acc.mail_access_type = mail_type
                acc.updated_at = _utcnow()
                session.add(acc)
                results.append({"id": aid, "ok": True, "email": acc.email, "mail_access_type": mail_type})
            else:
                results.append({"id": aid, "ok": False, "email": acc.email, "error": "不可达"})
        session.commit()

    ok_count = sum(1 for r in results if r.get("ok"))
    return {"total": len(results), "ok": ok_count, "failed": len(results) - ok_count, "results": results}


@router.post("/accounts/probe-untyped")
def probe_untyped_accounts():
    """一键探测所有 mail_access_type 为空且有 OAuth 凭证的账号。

    使用 ThreadPoolExecutor 并发跑 (max_workers=8), 每个账号探测大约 2-5s。
    总耗时 ≈ ceil(N/8) * 5s。返回 {total, ok, failed, items}.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from core.outlook_probe import classify_mail_access_type

    # 1. 拉所有候选: mail_access_type 空 + 有 client_id + refresh_token
    with Session(engine) as session:
        rows = session.exec(
            select(GptProAccountModel)
            .where(
                (GptProAccountModel.mail_access_type == None)  # noqa: E711
                | (GptProAccountModel.mail_access_type == "")
            )
            .where(col(GptProAccountModel.client_id) != "")
            .where(col(GptProAccountModel.refresh_token) != "")
        ).all()
        candidates = [
            (acc.id, acc.email, acc.refresh_token, acc.client_id) for acc in rows
        ]
    if not candidates:
        return {"total": 0, "ok": 0, "failed": 0, "items": []}

    # 2. 并发 probe
    def _probe(item):
        aid, email, rt, cid = item
        try:
            return aid, email, classify_mail_access_type(email, rt, cid)
        except Exception as exc:
            return aid, email, None  # noqa: BLE001 — 容错

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_probe, c) for c in candidates]
        for fut in as_completed(futures):
            aid, email, mt = fut.result()
            results.append({
                "id": aid,
                "email": email,
                "mail_access_type": mt or "",
                "ok": bool(mt),
            })

    # 3. 写库 (聚合一次性 commit)
    ok_count = 0
    with Session(engine) as session:
        for r in results:
            if not r["ok"]:
                continue
            acc = session.get(GptProAccountModel, r["id"])
            if not acc:
                continue
            acc.mail_access_type = r["mail_access_type"]
            acc.updated_at = _utcnow()
            session.add(acc)
            ok_count += 1
        session.commit()

    return {
        "total": len(results),
        "ok": ok_count,
        "failed": len(results) - ok_count,
        "items": results,
    }


# ── 取件(读取最新邮件) ───────────────────────────────────────

class GptProFetchMailRequest(BaseModel):
    limit: int = 10
    folder: Optional[str] = None  # 仅 IMAP: None=INBOX+Junk; 也可指定 INBOX / Junk
    refresh_oauth: bool = True    # 预留


class GptProSendMailRequest(BaseModel):
    to: str = ""                        # 新建/自定义收件人; 回复(带 reply_message_id)时可空,默认回原发件人
    subject: str = ""
    body: str = ""
    in_reply_to: Optional[str] = None   # iCloud 回复时: 原邮件 Message-ID (RFC header)
    references: Optional[str] = None
    reply_message_id: Optional[str] = None  # Outlook/Graph 收件箱回复: 原邮件的 Graph 消息 id
    body_html: bool = False             # body 是否按 HTML 发送 (默认纯文本)


def _send_via_icloud_smtp(from_addr: str, to_addr: str, subject: str, body_text: str,
                          *, in_reply_to: str = "", references: str = "") -> None:
    """以 iCloud 别名(from_addr)为发件人, 经 iCloud SMTP 发信/回复。
    认证用全局配置的 Apple ID + App 专用密码; From 必须是该 Apple ID 名下的地址/别名。"""
    import smtplib
    import ssl
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid
    from core.config_store import config_store as _cs

    apple_id = str(_cs.get("icloud_smtp_apple_id", "") or "").strip()
    app_pw = str(_cs.get("icloud_smtp_app_password", "") or "").strip().replace(" ", "")
    host = str(_cs.get("icloud_smtp_host", "") or "smtp.mail.me.com").strip() or "smtp.mail.me.com"
    try:
        port = int(str(_cs.get("icloud_smtp_port", "") or "587") or "587")
    except Exception:
        port = 587
    if not apple_id or not app_pw:
        raise RuntimeError("未配置 iCloud SMTP:请到设置页填 icloud_smtp_apple_id(Apple ID)+ "
                           "icloud_smtp_app_password(App 专用密码)")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=True)
    domain = from_addr.split("@")[-1] if "@" in from_addr else "icloud.com"
    msg["Message-ID"] = make_msgid(domain=domain)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (f"{references} {in_reply_to}".strip() if references else in_reply_to)
    msg.set_content(body_text or "")

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.ehlo()
        smtp.login(apple_id, app_pw)
        smtp.send_message(msg)


def _graph_token_for_account(acc: GptProAccountModel) -> str:
    """给 Outlook 账号取一个 Graph access_token(.default scope)。失败抛错。"""
    from core.base_mailbox import OutlookMailbox
    mailbox = OutlookMailbox(platform="")
    tok = mailbox._fetch_oauth_token(
        email=(acc.email or "").strip(),
        client_id=(acc.client_id or "").strip(),
        refresh_token=(acc.refresh_token or "").strip(),
        scope="https://graph.microsoft.com/.default",
    )
    if not tok:
        raise RuntimeError("Graph 取 access_token 失败(client_id/refresh_token 可能失效)")
    return tok


def _send_via_outlook_graph(acc: GptProAccountModel, to_addr: str, subject: str, body: str,
                            *, reply_message_id: str = "", body_html: bool = False) -> None:
    """用 Outlook 账号自身(Graph)发信/回复。
      - reply_message_id 有值 → POST /me/messages/{id}/reply (回原发件人, 自动串联会话)
      - 否则 → POST /me/sendMail (发给自定义收件人 to_addr)
    需要该号 OAuth 应用含 Mail.Send 权限 (实测 9e5f94bc-… 批量 client 含此权限)。"""
    import requests as _rq
    token = _graph_token_for_account(acc)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    ctype = "HTML" if body_html else "Text"

    if (reply_message_id or "").strip():
        # 收件箱回复: comment 作为回复正文, Graph 自动填收件人/主题(Re:)并串联会话
        url = f"https://graph.microsoft.com/v1.0/me/messages/{reply_message_id.strip()}/reply"
        payload: Dict[str, Any] = {"comment": body or ""}
        # 若还想覆盖收件人(自定义回复对象), 允许传 to_addr
        if (to_addr or "").strip():
            payload["message"] = {"toRecipients": [{"emailAddress": {"address": to_addr.strip()}}]}
    else:
        if not (to_addr or "").strip():
            raise RuntimeError("发送新邮件必须填收件人")
        url = "https://graph.microsoft.com/v1.0/me/sendMail"
        payload = {
            "message": {
                "subject": subject or "",
                "body": {"contentType": ctype, "content": body or ""},
                "toRecipients": [{"emailAddress": {"address": to_addr.strip()}}],
            },
            "saveToSentItems": True,
        }

    resp = _rq.post(url, headers=headers, json=payload, timeout=30)
    if resp.status_code not in (200, 202):
        raise RuntimeError(f"Graph 发信失败 HTTP {resp.status_code}: {(resp.text or '')[:300]}")


@router.post("/accounts/{account_id}/send-mail")
def send_account_mail(account_id: int, body: GptProSendMailRequest):
    """以该账号为发件人发信/回复。两条通道:
      - iCloud 别名号 → iCloud SMTP(以别名为发件人)
      - Outlook(graph 类型)→ Microsoft Graph(该号自身发信/收件箱回复)
    收件箱回复: 传 reply_message_id(Graph 消息 id, Outlook)或 in_reply_to(iCloud)。
    发送新邮件: 传 to(可自定义任意收件人)。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        from_addr = (acc.email or "").strip()
        provider = _mail_provider_of(acc)
        mail_type = (acc.mail_access_type or "").strip().lower()
        has_oauth = bool(acc.client_id and acc.refresh_token)
    to_addr = (body.to or "").strip()
    reply_mid = (body.reply_message_id or "").strip()

    if provider == "icloud":
        if not to_addr:
            raise HTTPException(400, "收件人不能为空")
        try:
            _send_via_icloud_smtp(from_addr, to_addr, body.subject or "", body.body or "",
                                  in_reply_to=(body.in_reply_to or ""), references=(body.references or ""))
        except Exception as exc:
            raise HTTPException(502, str(exc))
    elif mail_type == "graph" or (mail_type == "" and has_oauth):
        # Outlook / Graph: 发新邮件需 to; 收件箱回复需 reply_message_id
        if not to_addr and not reply_mid:
            raise HTTPException(400, "发送新邮件请填收件人;收件箱回复请传 reply_message_id")
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            try:
                _send_via_outlook_graph(acc, to_addr, body.subject or "", body.body or "",
                                        reply_message_id=reply_mid, body_html=bool(body.body_html))
            except Exception as exc:
                raise HTTPException(502, str(exc))
    else:
        raise HTTPException(400, "该账号不支持发信(仅 iCloud 别名号 或 Outlook graph 类型号可发;"
                                 "imap_pop 类型缺 SMTP.Send 权限)")

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if acc:
            acc.last_used = _utcnow()
            session.add(acc)
            session.commit()
    return {"ok": True, "from": from_addr, "to": to_addr or "(回复原发件人)",
            "subject": body.subject or "", "mode": "reply" if reply_mid else "new"}


class GptProMsLoginRequest(BaseModel):
    proxy: Optional[str] = None   # None = 用 config_store.default_proxy
    headless: bool = False


@router.post("/accounts/{account_id}/ms-web-login")
def ms_web_login(account_id: int, body: Optional[GptProMsLoginRequest] = None):
    """打开可见浏览器自动登录该号的 outlook.com 网页版邮箱, 登录后保持打开供人工发信。
    专供不支持 API 发信(imap_pop)的 Outlook 号。后台线程执行, 立即返回。"""
    import threading
    body = body or GptProMsLoginRequest()
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        email = (acc.email or "").strip()
        password = (acc.password or "").strip()
        provider = _mail_provider_of(acc)
    if provider == "icloud":
        raise HTTPException(400, "iCloud 号无需微软登录")
    if not password:
        raise HTTPException(400, "该账号没有保存密码, 无法自动登录网页版")
    proxy = _resolve_action_proxy(body)

    def _worker():
        from platforms.chatgpt.gpt_pro_login import run_ms_web_login
        try:
            run_ms_web_login(email, password, proxy=proxy,
                             headless=bool(body.headless),
                             log_fn=lambda m: print(m, flush=True))
        except Exception as exc:
            print(f"[MS登录] 线程异常: {exc}", flush=True)

    threading.Thread(target=_worker, daemon=True).start()
    return {"ok": True, "email": email, "note": "已在后台打开浏览器登录微软网页版邮箱, 请在弹出的窗口里使用/完成验证。"}


def _build_mailbox_account(acc: GptProAccountModel):
    """把 GptProAccountModel 转成 OutlookMailbox 使用的 MailboxAccount。"""
    from core.base_mailbox import MailboxAccount

    return MailboxAccount(
        email=acc.email,
        account_id=str(acc.id or ""),
        extra={
            "provider": "outlook",
            "password": acc.password or "",
            "client_id": acc.client_id or "",
            "refresh_token": acc.refresh_token or "",
            "mail_access_type": acc.mail_access_type or "",
        },
    )


def _looks_like_html(s: str) -> bool:
    low = (s or "")[:2000].lower()
    return any(t in low for t in ("<!doctype html", "<html", "<body", "<table", "<div", "<p>", "<br", "<span"))


def _html_to_text_preview(s: str, n: int = 200) -> str:
    """把 HTML(或纯文本)压成一行可读预览: 去 script/style、去标签、还原常见实体、合并空白。"""
    if not s:
        return ""
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", s)
    t = re.sub(r"<[^>]+>", " ", t)
    for a, b in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&#39;", "'"), ("&quot;", '"'), ("&rsquo;", "’")):
        t = t.replace(a, b)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:n]


def _fetch_via_graph(mailbox, mb_account, limit: int) -> List[Dict[str, Any]]:
    """复用 OutlookMailbox._fetch_graph_messages,返回最近 limit 封。"""
    messages = mailbox._fetch_graph_messages(mb_account, top=max(1, min(limit, 50)))
    out: List[Dict[str, Any]] = []
    for m in messages:
        body = str(m.get("body") or "")
        is_html = _looks_like_html(body)
        # 预览: 优先 Graph 的 bodyPreview(纯文本); 若空或含标签则从正文压
        raw_preview = str(m.get("preview") or "")
        preview = raw_preview if (raw_preview and "<" not in raw_preview) else _html_to_text_preview(body)
        out.append({
            "id": str(m.get("id") or ""),
            "from": str(m.get("from") or ""),
            "subject": str(m.get("subject") or ""),
            "preview": preview,
            "body": body,
            "is_html": is_html,
            "time": str(m.get("time") or ""),
            "folder": "",
        })
    # 按时间倒序
    out.sort(key=lambda x: x.get("time", ""), reverse=True)
    return out[:limit]


def _fetch_via_imap(mailbox, mb_account, limit: int, folders: List[str]) -> List[Dict[str, Any]]:
    """通过 IMAP 读取 INBOX / Junk 最近 limit 封邮件。"""
    from email import message_from_bytes
    from email.policy import default as email_default_policy
    from email.utils import parseaddr

    imap_conn = mailbox._open_imap(mb_account)
    out: List[Dict[str, Any]] = []
    try:
        for folder in folders:
            try:
                status, _ = imap_conn.select(folder, readonly=True)
                if status != "OK":
                    continue
                status, data = imap_conn.uid("search", None, "ALL")
                if status != "OK":
                    continue
                ids = data[0].split() if data and data[0] else []
                ids = ids[-max(1, min(limit, 200)):]
                for uid in reversed(ids):
                    uid_str = uid.decode("utf-8", errors="ignore") if isinstance(uid, bytes) else str(uid)
                    status, msg_data = imap_conn.uid("fetch", uid, "(RFC822)")
                    if status != "OK":
                        continue
                    raw = None
                    for item in msg_data or []:
                        if isinstance(item, tuple) and item[1]:
                            raw = item[1]
                            break
                    if not raw:
                        continue
                    msg = message_from_bytes(raw, policy=email_default_policy)
                    subject = mailbox._decode_header_value(msg.get("Subject", ""))
                    sender_name, sender_addr = parseaddr(str(msg.get("From", "")))
                    date_str = str(msg.get("Date", ""))

                    plain_chunks: List[str] = []
                    html_chunks: List[str] = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            if ctype not in ("text/plain", "text/html"):
                                continue
                            payload = part.get_payload(decode=True)
                            if payload is None:
                                continue
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                text = payload.decode(charset, errors="ignore")
                            except Exception:
                                text = payload.decode("utf-8", errors="ignore")
                            if ctype == "text/html":
                                html_chunks.append(text)
                            else:
                                plain_chunks.append(text)
                    else:
                        # 单 part 邮件: 按 Content-Type 判 html/plain(很多停用/申诉邮件是单 part text/html,
                        # 之前一律塞进 plain → is_html=False → 前端把 HTML 当纯文本原样显示)
                        payload = msg.get_payload(decode=True)
                        single_text = ""
                        if isinstance(payload, bytes):
                            charset = msg.get_content_charset() or "utf-8"
                            try:
                                single_text = payload.decode(charset, errors="ignore")
                            except Exception:
                                single_text = payload.decode("latin1", errors="ignore")
                        elif payload:
                            single_text = str(payload)
                        ctype = (msg.get_content_type() or "").lower()
                        if ctype == "text/html" or _looks_like_html(single_text):
                            html_chunks.append(single_text)
                        else:
                            plain_chunks.append(single_text)

                    body_html = "\n".join(html_chunks).strip()
                    body_text = "\n".join(plain_chunks).strip()
                    body = body_html or body_text
                    is_html = bool(body_html) or _looks_like_html(body)
                    preview = _html_to_text_preview(body_text or body)

                    out.append({
                        "id": uid_str,
                        "from": sender_addr or sender_name,
                        "subject": subject,
                        "preview": preview,
                        "body": body,
                        "is_html": is_html,
                        "time": date_str,
                        "folder": folder,
                    })
            except Exception:
                continue
    finally:
        try:
            imap_conn.logout()
        except Exception:
            pass

    return out[:limit]


def _fetch_icloud_recent(acc: GptProAccountModel, limit: int) -> List[Dict[str, Any]]:
    """iCloud 账号取件: 用全局 QQ 配置建 QQMailMailbox, 按账号别名(email)列最近邮件。"""
    from core.base_mailbox import MailboxAccount, create_mailbox
    from core.config_store import config_store as _cs
    cfg = dict(_cs.get_all() or {})
    cfg["platform"] = "chatgpt"
    cfg["qqmail_use_tracker"] = False
    mailbox = create_mailbox(provider="qqmail", extra=cfg, proxy=None)
    mb_account = MailboxAccount(email=acc.email, extra={"provider": "qqmail"})
    return mailbox.list_recent(mb_account, limit=limit)


def _fetch_recent_for_account(acc: GptProAccountModel, limit: int) -> List[Dict[str, Any]]:
    """按 provider 分发取件: icloud → QQ 邮箱(按别名); 否则 → Outlook(graph/imap)。"""
    if _mail_provider_of(acc) == "icloud":
        return _fetch_icloud_recent(acc, limit)
    from core.base_mailbox import OutlookMailbox
    mailbox = OutlookMailbox(platform="")
    mb_account = _build_mailbox_account(acc)
    mail_type = (acc.mail_access_type or "").strip().lower()
    if mail_type == "graph" or (mail_type == "" and acc.client_id and acc.refresh_token):
        try:
            return _fetch_via_graph(mailbox, mb_account, limit)
        except Exception as exc:
            if mail_type == "graph":
                raise RuntimeError(f"Graph: {exc}") from exc
    if mail_type in ("imap_pop", "") and (acc.password or (acc.client_id and acc.refresh_token)):
        return _fetch_via_imap(mailbox, mb_account, limit, ["INBOX", "Junk"])
    raise RuntimeError("无可用取件方式(缺少 OAuth/密码)")


# 从收据/订阅邮件里提取支付卡尾号: 命中「付款方式 Visa-3099」「Visa - 3099」「Visa •••• 3099」「ending in 3099」
_CARD_BRAND_RE = re.compile(
    r"(?:Visa|Master\s?card|Amex|American\s?Express|Discover|JCB|Union\s?Pay|Maestro)"
    r"\s*[-–—•·.*\s]{0,6}(\d{4})\b", re.I)
_CARD_ENDING_RE = re.compile(r"ending in\s*(\d{4})\b", re.I)


def _extract_card_last4_from_messages(messages: List[Dict[str, Any]]) -> Optional[str]:
    """从一组邮件里提取支付卡尾号,**以最新一封为准**。找不到返回 None。

    账号可能多次订阅/退款(老套餐、新套餐用不同卡),不能用最高频(老卡出现次数多会赢),
    应取**最近一封订阅/收据邮件里的卡**。优先「新套餐/收据」类,其次任意付款语境。"""
    def _card_in(blob: str) -> Optional[str]:
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", blob))
        m = _CARD_BRAND_RE.search(text) or _CARD_ENDING_RE.search(text)
        return m.group(1) if m else None

    # 按时间倒序(最新在前);无 time 字段则保持取件顺序(取件本身已是最新在前)
    def _t(m):
        return str(m.get("time") or m.get("date") or m.get("received") or "")
    ordered = (sorted(messages, key=_t, reverse=True)
               if any(m.get("time") or m.get("date") for m in messages) else list(messages))

    # 语境: 强(订阅确认/收据) > 弱(任意付款/退款语境)
    sub_kw = re.compile(r"新套餐|订阅|receipt|your new plan|subscription", re.I)
    any_kw = re.compile(r"付款方式|套餐|receipt|invoice|credit note|payment method|subscription|refund|退款", re.I)

    # 1) 最新的一封「订阅/收据」邮件里的卡
    for m in ordered:
        blob = str(m.get("subject") or "") + "\n" + str(m.get("body") or m.get("preview") or "")
        if sub_kw.search(blob):
            l4 = _card_in(blob)
            if l4:
                return l4
    # 2) 兜底: 最新的任意付款语境邮件里的卡
    for m in ordered:
        blob = str(m.get("subject") or "") + "\n" + str(m.get("body") or m.get("preview") or "")
        if any_kw.search(blob):
            l4 = _card_in(blob)
            if l4:
                return l4
    return None


# ── 从 "Access Deactivated / 访问权限已停用" 邮件里提取申诉链接 ──
# 锚文本/URL 命中这些关键词的链接优先当作申诉链接
_APPEAL_TEXT_KW = (
    "申诉", "提出申诉", "提交申诉", "上诉", "复审", "重新审核", "填写此表单", "此表单", "表单",
    "appeal", "request a review", "request a re-review", "submit a request",
    "let us know", "contact us", "believe this", "believe that", "was a mistake",
    "in error", "dispute", "this form", "fill out",
)
# URL 里命中这些片段的更可能是申诉表单
_APPEAL_URL_KW = (
    "appeal", "form", "review", "request", "dispute", "typeform", "survey",
    "help.openai.com/en/requests", "openai.com/form",
)
# 明确排除的非申诉链接(退订/隐私/条款/社媒/通用帮助文章/mailto)
_APPEAL_EXCLUDE = (
    "unsubscribe", "退订", "/privacy", "隐私", "/terms", "条款", "mailto:",
    "twitter.com", "x.com/openai", "linkedin.com", "facebook.com", "instagram.com",
    "youtube.com", "help.openai.com/en/articles", "openai.com/policies",
    "openai.com/blog", "list-manage", "campaign-archive",
)
_HREF_RE = re.compile(r'<a\b[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
_URL_RE = re.compile(r'https?://[^\s<>"\'\)\]]+')


def _extract_appeal_url(body: str, is_html: bool = True) -> Optional[str]:
    """从停用邮件正文里提取"提出申诉"的链接。找不到返回 None。

    策略:
    1) HTML: 遍历所有 <a href>, 按锚文本 / href 是否含申诉关键词打分, 取最高分(且排除退订等)。
    2) 纯文本 / 无锚: 找 URL 里含 appeal/form/review 等关键词的链接。
    OpenAI 偶尔改模板, 关键词表在上面 _APPEAL_* 里维护。
    """
    if not body:
        return None

    def _bad(url: str) -> bool:
        ul = url.lower()
        return (not url.lower().startswith("http")) or any(x in ul for x in _APPEAL_EXCLUDE)

    candidates: List[tuple] = []  # (score, url)
    if is_html or "<a" in body.lower():
        for m in _HREF_RE.finditer(body):
            href = (m.group(1) or "").strip()
            if _bad(href):
                continue
            text = re.sub(r"<[^>]+>", " ", m.group(2) or "")
            text = re.sub(r"\s+", " ", text).strip().lower()
            hl = href.lower()
            score = 0
            if any(k in text for k in _APPEAL_TEXT_KW):
                score += 10
            if any(k in hl for k in _APPEAL_URL_KW):
                score += 5
            if ("openai.com" in hl) or ("chatgpt.com" in hl):
                score += 1
            if score > 0:
                candidates.append((score, href))
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

    # 纯文本兜底: URL 里含申诉关键词
    for m in _URL_RE.finditer(body):
        url = (m.group(0) or "").rstrip('.,);]>"\'')
        if _bad(url):
            continue
        if any(k in url.lower() for k in _APPEAL_URL_KW):
            return url
    return None


def _extract_appeal_url_from_messages(messages: List[Dict[str, Any]]) -> Optional[str]:
    """在一组邮件里找停用邮件(主题命中停用关键词)并提取申诉链接。取最新一封。"""
    def _t(m):
        return str(m.get("time") or m.get("date") or "")
    ordered = sorted(messages, key=_t, reverse=True) if any(m.get("time") for m in messages) else list(messages)
    dead_kw = ("Access Deactivated", "访问权限已停用")
    for m in ordered:
        subj = str(m.get("subject") or "")
        if any(kw in subj for kw in dead_kw):
            url = _extract_appeal_url(str(m.get("body") or ""), bool(m.get("is_html")))
            if url:
                return url
    return None


def _appeal_diag(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """诊断为什么没提取到申诉链接: 找停用邮件, 列出它里面所有链接(锚文本+href)与裸 URL。
    没找到停用邮件则返回 found=False。供批量补链接失败时打日志、校准关键词用。"""
    dead_kw = ("Access Deactivated", "访问权限已停用")

    def _t(m):
        return str(m.get("time") or m.get("date") or "")
    ordered = sorted(messages, key=_t, reverse=True) if any(m.get("time") for m in messages) else list(messages)
    for m in ordered:
        subj = str(m.get("subject") or "")
        if any(kw in subj for kw in dead_kw):
            body = str(m.get("body") or "")
            links = []
            for mm in _HREF_RE.finditer(body):
                txt = re.sub(r"<[^>]+>", " ", mm.group(2) or "")
                txt = re.sub(r"\s+", " ", txt).strip()[:24]
                links.append(f"{txt}|{mm.group(1)}")
            urls = _URL_RE.findall(body)
            return {"found": True, "subject": subj[:60], "time": str(m.get("time") or ""),
                    "is_html": bool(m.get("is_html")), "body_len": len(body),
                    "n_links": len(links), "links": links[:12], "urls": urls[:12]}
    return {"found": False, "n_msgs": len(messages),
            "subjects": [str(m.get("subject") or "")[:40] for m in ordered[:8]]}


def _apply_payment_account_by_last4(session, acc: GptProAccountModel, last4: str) -> Optional[str]:
    """按卡尾号在卡池里找唯一匹配的卡, 把其所属支付账号(id/name/type)写进账号 extra_json。
    返回支付账号名(成功)或 None(无匹配/多张同尾号歧义/该卡无支付账号)。"""
    l4 = (last4 or "").strip()[-4:]
    if not l4:
        return None
    from core.db import CardModel as _Card, PaymentAccountModel as _PA
    cards = [c for c in session.exec(select(_Card)).all() if (c.number or "").endswith(l4)]
    pa_ids = {int(getattr(c, "payment_account_id", 0) or 0) for c in cards if getattr(c, "payment_account_id", 0)}
    if len(pa_ids) != 1:
        return None                       # 无匹配, 或不同支付账号有同尾号卡 → 不猜
    pa = session.get(_PA, next(iter(pa_ids)))
    if not pa:
        return None
    try:
        _ex = json.loads(acc.extra_json) if acc.extra_json else {}
    except Exception:
        _ex = {}
    _ex["payment_account_id"] = pa.id
    _ex["payment_account_name"] = pa.name
    _ex["payment_account_type"] = pa.account_type
    acc.extra_json = json.dumps(_ex, ensure_ascii=False)
    return pa.name


@router.post("/accounts/{account_id}/backfill-card-last4-from-mail")
def backfill_one_card_last4_from_mail(account_id: int, limit: int = 50):
    """对单个账号取邮件解析卡尾号并回填(供 PRO 列表里逐个「补尾号」用)。"""
    lim = max(1, min(int(limit or 50), 50))
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
    try:
        msgs = _fetch_recent_for_account(acc, lim)
    except Exception as exc:
        raise HTTPException(400, f"取件失败: {exc}")
    last4 = _extract_card_last4_from_messages(msgs)
    if not last4:
        return {"ok": False, "account_id": account_id, "last4": None,
                "message": "邮件里没解析到卡尾号(收据邮件可能已不在收件箱)"}
    with Session(engine) as s2:
        row = s2.get(GptProAccountModel, account_id)
        row.payment_card_last4 = last4
        row.last_used = _utcnow()
        pa_name = _apply_payment_account_by_last4(s2, row, last4)
        s2.add(row)
        s2.commit()
    msg = f"已回填卡尾号 ****{last4}" + (f",支付账号「{pa_name}」" if pa_name else "(无匹配卡池账号)")
    return {"ok": True, "account_id": account_id, "last4": last4,
            "payment_account_name": pa_name, "message": msg}


@router.post("/accounts/backfill-card-last4-from-mail")
def backfill_card_last4_from_mail(limit_per_account: int = 50):
    """对「已付费(is_pro)但缺 payment_card_last4」的账号, 取邮件解析卡尾号并回填。
    返回逐账号结果。best-effort: 单个账号取件/解析失败不影响其他。"""
    with Session(engine) as session:
        targets = [
            a for a in session.exec(select(GptProAccountModel)).all()
            if getattr(a, "is_pro", False) and not (a.payment_card_last4 or "").strip()
        ]
    scanned = filled = not_found = errors = 0
    details: List[Dict[str, Any]] = []
    lim = max(1, min(int(limit_per_account or 50), 50))
    for acc in targets:
        scanned += 1
        try:
            msgs = _fetch_recent_for_account(acc, lim)
        except Exception as exc:
            errors += 1
            details.append({"email": acc.email, "status": "error", "error": str(exc)[:120]})
            continue
        last4 = _extract_card_last4_from_messages(msgs)
        if not last4:
            not_found += 1
            details.append({"email": acc.email, "status": "not_found"})
            continue
        pa_name = None
        with Session(engine) as s2:
            row = s2.get(GptProAccountModel, acc.id)
            if row:
                row.payment_card_last4 = last4
                row.last_used = _utcnow()
                pa_name = _apply_payment_account_by_last4(s2, row, last4)
                s2.add(row)
                s2.commit()
        filled += 1
        details.append({"email": acc.email, "status": "filled", "last4": last4, "payment_account_name": pa_name})
    return {"ok": True, "scanned": scanned, "filled": filled,
            "not_found": not_found, "errors": errors, "details": details}


@router.post("/accounts/{account_id}/fetch-mail")
def fetch_account_mail(account_id: int, body: Optional[GptProFetchMailRequest] = None):
    """读取指定账号最近 N 封邮件(Inbox + Junk)。

    根据 mail_access_type 自动选择 Graph API 或 IMAP:
    - graph: 调用 Microsoft Graph
    - imap_pop: 走 IMAP (XOAUTH2 优先,密码兜底)
    - "": 有 OAuth 时尝试 Graph,失败回退 IMAP
    """
    from core.base_mailbox import OutlookMailbox

    body = body or GptProFetchMailRequest()
    limit = max(1, min(int(body.limit or 10), 50))

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")

        # iCloud 账号: 走 QQ 邮箱按别名取件
        if _mail_provider_of(acc) == "icloud":
            try:
                messages = _fetch_icloud_recent(acc, limit)
            except Exception as exc:
                raise HTTPException(400, f"iCloud/QQ 取件失败: {exc}")
            acc.last_used = _utcnow()
            session.add(acc)
            session.commit()
            return {"email": acc.email, "mail_access_type": "icloud",
                    "method": "qqmail", "count": len(messages), "messages": messages}

        mailbox = OutlookMailbox(platform="")
        mb_account = _build_mailbox_account(acc)
        mail_type = (acc.mail_access_type or "").strip().lower()

        attempted: List[str] = []
        last_error = ""

        # 1) Graph 路径
        if mail_type == "graph" or (mail_type == "" and acc.client_id and acc.refresh_token):
            attempted.append("graph")
            try:
                messages = _fetch_via_graph(mailbox, mb_account, limit)
                acc.last_used = _utcnow()
                session.add(acc)
                session.commit()
                return {
                    "email": acc.email,
                    "mail_access_type": mail_type or "graph",
                    "method": "graph",
                    "count": len(messages),
                    "messages": messages,
                }
            except Exception as exc:
                last_error = f"Graph 取件失败: {exc}"

        # 2) IMAP 路径
        if mail_type == "imap_pop" or mail_type == "" or last_error:
            attempted.append("imap")
            folders = [body.folder] if body.folder else ["INBOX", "Junk"]
            try:
                messages = _fetch_via_imap(mailbox, mb_account, limit, folders)
                acc.last_used = _utcnow()
                session.add(acc)
                session.commit()
                return {
                    "email": acc.email,
                    "mail_access_type": mail_type or "imap_pop",
                    "method": "imap",
                    "count": len(messages),
                    "messages": messages,
                }
            except Exception as exc:
                last_error = f"{last_error + '; ' if last_error else ''}IMAP 取件失败: {exc}"

        raise HTTPException(400, last_error or f"无可用取件方式 (尝试: {','.join(attempted) or '无'})")


# ── 邮件监控提醒(PRO 账号) ───────────────────────────────────

class DismissAlertsRequest(BaseModel):
    alert_ids: Optional[List[str]] = None  # 为 None 或空列表 = 清空全部


@router.get("/alerts/summary")
def alerts_summary():
    """前端轮询用:返回每个有未读邮件的账号的 unread 数量。

    同时返回两个通道:
      - bell (pending_alerts_json): 仅"封禁报警" 白名单命中
      - inbox (pending_inbox_json): 所有新邮件 (除退款,退款走 refund_status)
    """
    with Session(engine) as session:
        accounts = session.exec(
            select(GptProAccountModel).where(GptProAccountModel.is_pro == True)  # noqa: E712
        ).all()
        items = []
        total_unread = 0
        total_inbox = 0
        inbox_accounts = 0
        for acc in accounts:
            try:
                pending = json.loads(acc.pending_alerts_json or "[]")
            except Exception:
                pending = []
            try:
                inbox = json.loads(acc.pending_inbox_json or "[]")
            except Exception:
                inbox = []
            bell_count = len(pending)
            inbox_count = len(inbox)
            if bell_count:
                total_unread += bell_count
            if inbox_count:
                total_inbox += inbox_count
                inbox_accounts += 1
            if not bell_count and not inbox_count:
                continue
            items.append({
                "id": acc.id,
                "email": acc.email,
                "unread_count": bell_count,
                "inbox_unread_count": inbox_count,
                "latest_subject": (pending[0].get("subject") if pending
                                   else (inbox[0].get("subject") if inbox else "")),
                "latest_time": (pending[0].get("time") if pending
                                else (inbox[0].get("time") if inbox else "")),
            })
        return {
            "total_unread": total_unread,
            "account_count": sum(1 for it in items if it["unread_count"]),
            "total_inbox_unread": total_inbox,
            "inbox_account_count": inbox_accounts,
            "items": items,
        }


@router.get("/accounts/{account_id}/alerts")
def list_account_alerts(account_id: int):
    """获取指定账号的未读 alerts(已按时间倒序)。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        try:
            alerts = json.loads(acc.pending_alerts_json or "[]")
        except Exception:
            alerts = []
        return {
            "email": acc.email,
            "unread_count": len(alerts),
            "alerts": alerts,
            "last_mail_check_at": acc.last_mail_check_at.isoformat() if acc.last_mail_check_at else "",
            "last_mail_check_error": acc.last_mail_check_error or "",
        }


@router.post("/accounts/{account_id}/alerts/dismiss")
def dismiss_account_alerts(account_id: int, body: Optional[DismissAlertsRequest] = None):
    """清除提醒。alert_ids 为空 = 清空全部;否则仅移除指定 id。"""
    body = body or DismissAlertsRequest()
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")

        try:
            pending = json.loads(acc.pending_alerts_json or "[]")
        except Exception:
            pending = []

        removed = 0
        if not body.alert_ids:
            removed = len(pending)
            pending = []
        else:
            keep_ids = set(body.alert_ids)
            new_pending = [a for a in pending if a.get("id") not in keep_ids]
            removed = len(pending) - len(new_pending)
            pending = new_pending

        acc.pending_alerts_json = json.dumps(pending, ensure_ascii=False)
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()

        return {
            "ok": True,
            "removed": removed,
            "remaining": len(pending),
        }


# ── 收件箱 (所有新邮件, 跟铃铛 alerts 平行的通道) ─────────────
class DismissInboxRequest(BaseModel):
    inbox_ids: Optional[List[str]] = None  # None 或空 = 清空全部


@router.get("/accounts/{account_id}/inbox")
def list_account_inbox(account_id: int):
    """该账号未清空的全部新邮件 (按时间倒序)。跟 /alerts 平行,内容更宽。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        try:
            inbox = json.loads(acc.pending_inbox_json or "[]")
        except Exception:
            inbox = []
        return {
            "email": acc.email,
            "inbox_unread_count": len(inbox),
            "items": inbox,
            "last_mail_check_at": acc.last_mail_check_at.isoformat() if acc.last_mail_check_at else "",
            "last_mail_check_error": acc.last_mail_check_error or "",
        }


@router.post("/accounts/{account_id}/inbox/dismiss")
def dismiss_account_inbox(account_id: int, body: Optional[DismissInboxRequest] = None):
    """清除收件箱条目。inbox_ids 为空 = 清空全部;否则仅移除指定 id。"""
    body = body or DismissInboxRequest()
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")

        try:
            inbox = json.loads(acc.pending_inbox_json or "[]")
        except Exception:
            inbox = []

        removed = 0
        if not body.inbox_ids:
            removed = len(inbox)
            inbox = []
        else:
            keep = set(body.inbox_ids)
            new_inbox = [a for a in inbox if a.get("id") not in keep]
            removed = len(inbox) - len(new_inbox)
            inbox = new_inbox

        acc.pending_inbox_json = json.dumps(inbox, ensure_ascii=False)
        acc.updated_at = _utcnow()
        session.add(acc)
        session.commit()

        return {"ok": True, "removed": removed, "remaining": len(inbox)}


@router.post("/accounts/{account_id}/check-mail-now")
def check_account_mail_now(account_id: int):
    """立即对指定账号执行一轮监控(不等 5 分钟轮询)。"""
    from services.gpt_pro_mail_monitor import run_monitor_round

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")

    return run_monitor_round(account_id=account_id)


# ── DrissionPage 自动化操作 (注册 / 登陆 / 升级PRO / 退款) ──────


# 浏览器会话 store: 登陆后 page 引用存这里, 后续可通过 /browser/{sid}/* 接口控制。
# 用于退款流程探索 / 手动调试 等需要"持久控制浏览器"的场景。
_BROWSER_SESSIONS: Dict[str, dict] = {}
_BROWSER_SESSIONS_LOCK = threading.Lock()


def _create_browser_session(account_id: int, page) -> str:
    import uuid
    sid = uuid.uuid4().hex[:16]
    with _BROWSER_SESSIONS_LOCK:
        _BROWSER_SESSIONS[sid] = {
            "session_id": sid,
            "account_id": account_id,
            "page": page,
            "created_at": _utcnow().isoformat(),
        }
    return sid


def _get_browser_session(sid: str) -> dict:
    with _BROWSER_SESSIONS_LOCK:
        sess = _BROWSER_SESSIONS.get(sid)
        if not sess:
            raise HTTPException(404, f"session {sid} 不存在或已被关闭")
        return sess


class GptProActionRequest(BaseModel):
    """4 个 DrissionPage 操作通用入参。"""
    proxy: Optional[str] = None     # None = 用 config_store.default_proxy
    headless: bool = False          # False = 可见浏览器, True = 无头
    otp_timeout: int = 180
    # True (默认): 登录成功后**不退出浏览器**, 由人工手动关闭
    # False: 流程结束自动 quit
    keep_browser_open: bool = True
    # 仅 /register 路由用: 填 about-you 页用的姓名+生日; 不传则随机
    full_name: Optional[str] = None
    birthday: Optional[Dict[str, int]] = None  # {year, month, day}
    # 仅 /upgrade-pro 路由用: dump_only=True 时跳过卡选择/填表/等待用户,
    # 只做 "登录 → 创建 checkout → 导航 → 递归 dump 所有 iframe 结构" 后立刻返回。
    # 用来诊断 checkout 页表单结构 (例如确认账单字段在不在嵌套 iframe 里)。
    dump_only: bool = False
    # 仅 /refund 路由用: 覆盖默认退款诉求文案 "误订阅 请退款"
    refund_message: Optional[str] = None
    # 仅 /refund 路由用: True = 手动模式, 只登录+跳到客服对话界面, 不自动发文案(人工手动发)
    refund_manual: bool = False
    # 仅 /refund 路由用: 升级人工后, 窗口保持打开等退款邮件的随机时长区间(秒)
    # 每轮在 [min, max] 内随机取一个值等待, 默认 3600~7200s (1~2 小时随机)
    refund_wait_min_seconds: int = 3600
    refund_wait_max_seconds: int = 7200
    # 仅 /refund 路由用: 无退款邮件则点"新对话"重开一段客服对话重试的最大轮数
    # (默认 4; 直到退款成功或用完。同一浏览器窗口内, 点铅笔"新对话"按钮而非新开窗口)
    refund_max_rounds: int = 4
    # 仅 /upgrade-pro 路由用: 等这么多秒人工没选就自动按优先级选卡(默认 8s;0=纯人工不自动)
    auto_pick_seconds: int = 8
    # 浏览器后端: local(默认, DrissionPage 自建 Chromium) / roxybrowser(指纹浏览器接管)
    # 仅「升级 PRO」按钮暴露此选项; 每次新建带所选代理的窗口, 处理完自动关窗+删除。
    # None = /upgrade-pro 使用服务端统一配置；普通登录等链路仍回退 local。
    # 显式 local/roxybrowser 永远优先，兼容旧调用方。
    browser_backend: Optional[str] = None
    # 仅 roxybrowser 后端用: 选中的代理 id(RoxyProxyModel.id); 0/None 表示不指定代理
    roxy_proxy_id: Optional[int] = None
    # 仅升级 PRO 用: 手动粘贴的银行卡文本(有则跳过卡池, 直接填这张卡); 支持多种格式, 见 _parse_card_text
    checkout_card: Optional[str] = None
    # 仅升级 PRO 用: pro_only=True 表示账号已在 Go 套餐, 跳过订 Go / 跳过选卡, 只跑后半段
    # (发 PRO 升级 checkout → 点确认 → 等跳转), 卡已在档不再填卡。用于「Go 已成功但 PRO 失败」补跑。
    pro_only: bool = False


def _resolve_action_proxy(body: Optional["GptProActionRequest"]) -> str:
    if body and body.proxy is not None:
        return str(body.proxy or "").strip()
    try:
        from core.config_store import config_store
        return str(config_store.get("default_proxy", "") or "").strip()
    except Exception:
        return ""


def _refresh_roxy_proxy_from_roxy(pid: int) -> str:
    """升级前从 RoxyBrowser /proxy/list 拉该代理最新配置, 覆盖库里缓存。

    RoxyBrowser 的代理 id/端口会随编辑/轮换变化, 故按多重键匹配:
        module_id → 备注(remark, 唯一时) → host:port
    匹配到后连 module_id 一起自愈更新(下次就能直接按 id 命中)。

    返回:
      "updated" 已找到并刷新
      "deleted" RoxyBrowser 里已彻底删除(三种键都匹配不到)→ 已同步从应用删除
      "kept"    RoxyBrowser 未启动 / 拉取异常 → 保留库里缓存(不误删)
    """
    with Session(engine) as s:
        p = s.get(RoxyProxyModel, pid)
        if not p:
            return "deleted"
        app_module_id = str(p.roxy_module_id or "").strip()
        app_note = str(p.note or "").strip()
        app_host = str(p.host or "").strip()
        app_port = str(p.port or "").strip()
    try:
        from core.roxy_browser import RoxyBrowserClient, load_roxy_config, resolve_workspace_id
        ws = resolve_workspace_id()
        cfg = load_roxy_config()
        rows = RoxyBrowserClient(cfg["api_host"], cfg["token"]).list_proxies(ws)
    except Exception as exc:
        print(f"[gpt-pro] ⚠ 升级 PRO: 从 RoxyBrowser 刷新代理失败(保留库存, 不删): {exc}", flush=True)
        return "kept"

    match = None
    if app_module_id:
        match = next((r for r in rows if str(r.get("id")) == app_module_id), None)
    if not match and app_note:
        same = [r for r in rows if str(r.get("remark") or "").strip() == app_note]
        if len(same) == 1:
            match = same[0]
    if not match and app_host and app_port:
        match = next(
            (r for r in rows
             if str(r.get("host") or "").strip() == app_host and str(r.get("port") or "").strip() == app_port),
            None,
        )
    if not match:
        # 拉取成功但三种键都匹配不到 → 该代理已从 RoxyBrowser 彻底删除 → 同步从应用删除
        with Session(engine) as s:
            dbp = s.get(RoxyProxyModel, pid)
            if dbp:
                s.delete(dbp)
                s.commit()
        print(f"[gpt-pro] 升级 PRO: 代理已从 RoxyBrowser 删除(module_id={app_module_id} 备注={app_note}), 已同步从应用移除", flush=True)
        return "deleted"

    host = str(match.get("host") or "").strip()
    port = str(match.get("port") or "").strip()
    proto = str(match.get("protocol") or "").strip().upper()
    with Session(engine) as s:
        dbp = s.get(RoxyProxyModel, pid)
        if not dbp:
            return
        if host:
            dbp.host = host
        if port:
            dbp.port = port
        if proto in ("HTTP", "HTTPS", "SOCKS5"):
            dbp.protocol = proto
        dbp.username = str(match.get("proxyUserName") or "")
        dbp.password = str(match.get("proxyPassword") or "")
        if match.get("id"):
            dbp.roxy_module_id = str(match.get("id"))   # 自愈: 同步最新 module_id
        if match.get("lastIp"):
            dbp.last_ip = str(match.get("lastIp"))
        if match.get("lastCountry"):
            dbp.last_country = str(match.get("lastCountry"))
        dbp.updated_at = _utcnow()
        s.add(dbp)
        s.commit()
    print(f"[gpt-pro] 升级 PRO: 已从 RoxyBrowser 刷新代理 id={pid} → {host}:{port} "
          f"(module_id={match.get('id')}) 出口={match.get('lastIp') or '-'}", flush=True)
    return "updated"


def _roxy_proxy_dict(proxy_id: Any) -> Optional[dict]:
    """按 RoxyProxyModel.id 取代理 → RoxyBrowserSession 需要的 dict。None=不指定。

    每次调用(即每次升级)都先从 RoxyBrowser 拉一次该代理的最新配置覆盖库里缓存, 再返回。
    """
    try:
        pid = int(proxy_id)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    # 注: 代理的 RoxyBrowser 刷新/删除已在 upgrade_pro_account 升级前置统一处理, 这里只读库
    with Session(engine) as s:
        p = s.get(RoxyProxyModel, pid)
        if not p:
            return None
        return {
            "id": p.id,
            "host": p.host,
            "port": p.port,
            "protocol": p.protocol,
            "username": p.username,
            "password": p.password,
            "note": p.note,
            "roxy_module_id": p.roxy_module_id,
        }


def _run_drission_login(
    account_id: int,
    body: "GptProActionRequest",
    *,
    is_signup: bool = False,
    post_login_action: Optional[Any] = None,
    log_fn: Optional[Any] = None,
) -> Dict[str, Any]:
    """对 GPT PRO 账号执行一次 DrissionPage 邮箱 OTP 登录/注册,成功后翻 is_pro=True.

    is_signup=True: 走注册分支,OTP 提交后会处理 about-you 页 (姓名+生日)。
    post_login_action: 登录成功后在 page 上跑的额外动作 callable (page, result) -> dict
                      例如 upgrade-pro 跑 checkout JS。
    """
    from platforms.chatgpt.gpt_pro_login import build_mailbox_for_account, login_with_email_otp

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        if not acc.enabled:
            raise HTTPException(409, "账号已被禁用")
        snapshot = {
            "email": acc.email,
            "password": acc.password or "",
            "client_id": acc.client_id or "",
            "refresh_token": acc.refresh_token or "",
            "mail_access_type": acc.mail_access_type or "",
            "mail_provider": _mail_provider_of(acc),
        }

    proxy = _resolve_action_proxy(body)
    mailbox, mb_account = build_mailbox_for_account(snapshot, proxy=proxy)
    result = login_with_email_otp(
        email=snapshot["email"],
        mailbox=mailbox,
        mailbox_account=mb_account,
        headless=bool(body.headless),
        proxy=proxy,
        otp_timeout=int(body.otp_timeout or 180),
        keep_browser_open=bool(body.keep_browser_open),
        is_signup=is_signup,
        full_name=(body.full_name or ""),
        birthday=body.birthday,
        post_login_action=post_login_action,
        log_fn=log_fn,
        browser_backend=str(getattr(body, "browser_backend", "local") or "local"),
        roxy_proxy=_roxy_proxy_dict(getattr(body, "roxy_proxy_id", None)),
    )

    # 登录时若检测到账号已停用(account_deactivated)→ 只标 dead, **绝不自动删除**。
    # (曾因登录自动删除误删了有价值的 PRO/已退款账号,故取消登录时删除;
    #  要清理死号请用【批量清理 dead 已退款】那条带 dry-run 的入口,更可控。)
    # 可用 config gpt_pro_auto_delete_dead_on_login=1 且账号非 is_pro 时才允许删除(默认关闭)。
    _login_dead = (getattr(result, "stage", "") == "account_deactivated"
                   or "account_deactivated" in (getattr(result, "error", "") or ""))
    if _login_dead:
        _log = log_fn or (lambda m: print(m, flush=True))
        try:
            from core.config_store import config_store as _cs
            # 默认改为 0(关闭): 登录检测到停用只标 dead, 不删。
            auto_del = str(_cs.get("gpt_pro_auto_delete_dead_on_login", "0") or "0").strip().lower() in ("1", "true", "yes")
        except Exception:
            auto_del = False
        deleted = False
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            if acc:
                acc.dangerous = True
                if not acc.dangerous_detected_at:
                    acc.dangerous_detected_at = _utcnow()
                acc.updated_at = _utcnow()
                session.add(acc)
                session.commit()
                # 双保险: 即便配置开了自动删除, is_pro 账号也永不在登录时删除
                if (
                    auto_del
                    and not acc.is_pro
                    and not is_managed_business_child_account(acc)
                ):
                    session.delete(acc)
                    session.commit()
                    deleted = True
        _log(f"[登录] ✗ 账号已停用(account_deactivated) → 已标 dead"
             f"{'并自动删除' if deleted else '(未删,登录时不再自动删除,仅标 dead)'}")
        d = result.to_dict()
        d["dead"] = True
        d["dead_deleted"] = deleted
        return d

    if result.ok:
        # 语义: is_pro = 已订阅 (subscribed); 只有 upgrade-pro 全链路跑完且最终跳转到
        # chatgpt.com/ (非 /checkout/) 才置 True + 落 subscribed_at。
        # 单纯 login / register 只更新 last_used,不动 is_pro。
        action_result = result.action_result or {}
        sub_success = bool(action_result.get("subscription_success"))
        # 登录成功 → 抓取并保存/更新 chatgpt.com 会话 cookie(含 oai-access-token)
        try:
            from platforms.chatgpt.gpt_pro_login import build_cookie_blob_from_result
            cookie_blob, cookie_exp = build_cookie_blob_from_result(result)
        except Exception:
            cookie_blob, cookie_exp = "", None
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            if acc:
                acc.last_used = _utcnow()
                acc.updated_at = _utcnow()
                if cookie_blob:
                    acc.cookie_blob = cookie_blob
                    acc.cookie_updated_at = _utcnow()
                    acc.cookie_expires_at = cookie_exp
                if sub_success:
                    acc.is_pro = True
                    acc.subscribed_at = _utcnow()
                    # 新升级到 PRO 的账号:待重置次数默认 3(仅当还没设过,不覆盖已计数的)
                    if acc.referral_remaining is None:
                        acc.referral_remaining = 3
                session.add(acc)
                session.commit()
    return result.to_dict()


@router.post("/accounts/{account_id}/login")
def login_account(account_id: int, body: Optional[GptProActionRequest] = None):
    """登录:DrissionPage + 邮箱 OTP,成功后 is_pro 自动置 True。"""
    return _run_drission_login(account_id, body or GptProActionRequest())


@router.post("/accounts/{account_id}/register")
def register_account(account_id: int, body: Optional[GptProActionRequest] = None):
    """注册:OpenAI 的 sign-up / sign-in 共用同一入口,本路由走 is_signup=True
    分支 —— OTP 提交后会自动等待 /about-you 页,填姓名+生日+同意复选框后提交。

    full_name / birthday 不传则随机生成。成功后翻 is_pro=True(已注册),
    前端按钮组切换为「登陆/升级 PRO/退款」。
    """
    return _run_drission_login(
        account_id, body or GptProActionRequest(), is_signup=True,
    )


# ── 升级 PRO 异步任务 ──────────────────────────────────────
#
# upgrade-pro 改造为两阶段:
#   phase1 (同步): 登录 → 跑 checkout JS → 跳到 /checkout/openai_llc/{sid} → 注入卡选择 panel
#   phase2 (后台 thread): 等人工选卡(5 分钟) → 填 Stripe iframe → 点订阅 → 等跳转
#
# POST /upgrade-pro 同步完成 phase1 后立刻 return task_id + pay_url,
# phase2 在 daemon thread 里跑, 通过 _UPGRADE_PRO_TASKS 暴露进度。
# GET /upgrade-pro/status/{task_id} 给前端轮询用。
#
# 同账号重复点「升级 PRO」时杀掉旧 task + 关掉旧浏览器再起新的。
# 进程重启后内存 store 丢失 (升级 PRO 是交互态, 重启就该重来)。
_UPGRADE_PRO_TASKS: Dict[str, dict] = {}
_UPGRADE_PRO_BY_ACCOUNT: Dict[int, str] = {}
_UPGRADE_PRO_LOCK = threading.Lock()


def _kill_existing_upgrade_task(account_id: int) -> None:
    operation_token = ""
    page = None
    worker_done = False
    with _UPGRADE_PRO_LOCK:
        old_task_id = _UPGRADE_PRO_BY_ACCOUNT.pop(account_id, None)
        if not old_task_id:
            return
        old = _UPGRADE_PRO_TASKS.get(old_task_id)
        if not old:
            return
        old["stage"] = "cancelled"
        old["cancelled"] = True
        old["finished_at"] = _utcnow().isoformat()
        page = old.pop("page", None)
        operation_token = str(old.get("operation_token") or "")
        worker_done = bool(old.get("worker_done"))
        old["manual_window_open"] = False
    if page is not None:
        try:
            page.quit()
        except Exception:
            pass
    # worker 仍可能正在点击订阅/等待 Stripe 响应。只有已经退出的
    # worker 才能在这里立即释放；运行中 worker 由其 finally 释放。
    # 这样新任务不会在旧付款线程尚未确认停止时重复扣款。
    if worker_done:
        _release_gpt_pro_account_operation(account_id, operation_token)


def _set_upgrade_stage(task_id: str, stage: str, **extra) -> bool:
    """更新 task 阶段, 返回 True 继续 / False 已被取消, 调用方应停。"""
    with _UPGRADE_PRO_LOCK:
        t = _UPGRADE_PRO_TASKS.get(task_id)
        if not t or t.get("cancelled"):
            return False
        t["stage"] = stage
        t["stage_at"] = _utcnow().isoformat()
        for k, v in extra.items():
            t[k] = v
        return True


def _upgrade_pro_phase2_thread_impl(task_id: str, account_id: int, page,
                                     pick_timeout: int, auto_pick_seconds: int = 0,
                                     direct_card: Optional[dict] = None,
                                     is_roxy: bool = False,
                                     go_then_pro: bool = False,
                                     country: str = "PH", currency: str = "PHP",
                                     go_to_pro_wait: int = 60,
                                     pro_only: bool = False,
                                     operation_token: str = "") -> None:
    """后台跑 phase2: 等选卡 → 填卡 → 点订阅 → 等跳转 → 写库。

    5 分钟人工选卡超时后浏览器**保持不关**, 让用户继续手动付款; 只是不会回写 is_pro。

    is_roxy=True (RoxyBrowser 指纹浏览器接管): 支付失败时**不做任何自动善后** —
    不把卡标记为 failed/禁用, 浏览器保持不关, 完全交人工处理。
    """
    from platforms.chatgpt.gpt_pro_login import run_checkout_phase2
    from core.db import CardModel

    def _stage_cb(stage: str) -> None:
        _set_upgrade_stage(task_id, stage)

    try:
        phase2 = run_checkout_phase2(
            page, timeout=pick_timeout, auto_pick_seconds=auto_pick_seconds,
            direct_card=direct_card, stage_cb=_stage_cb,
            go_then_pro=go_then_pro, country=country, currency=currency,
            go_to_pro_wait=go_to_pro_wait, pro_only=pro_only,
        )
    except Exception as exc:
        with _UPGRADE_PRO_LOCK:
            t = _UPGRADE_PRO_TASKS.get(task_id)
            if t and not t.get("cancelled"):
                t["stage"] = "failed"
                t["error"] = f"phase2 异常: {exc}"
                t["finished_at"] = _utcnow().isoformat()
                # 保留 page 供人工检查时必须同时保留账号租约。
                t["manual_window_open"] = True
        return

    # 取消的话不要再写库 (浏览器在 _kill_existing_upgrade_task 已经被关)
    with _UPGRADE_PRO_LOCK:
        t = _UPGRADE_PRO_TASKS.get(task_id)
        if not t or t.get("cancelled"):
            return

    subscription_success = bool(phase2.get("subscription_success"))
    picked_card_id = phase2.get("picked_card_id")
    final_stage = "success" if subscription_success else (
        "timeout" if phase2.get("timeout") else "failed"
    )
    error_msg = ""
    if not subscription_success:
        if phase2.get("timeout"):
            error_msg = "人工选卡超时,浏览器已留窗,可继续手动付款"
        elif is_roxy:
            error_msg = "支付失败,已保留 RoxyBrowser 窗口交人工处理(未自动封卡/未关窗)"
        else:
            sub = phase2.get("subscribe") or {}
            error_msg = (sub.get("redirect", {}).get("reason")
                          or sub.get("click_error")
                          or "订阅未确认")

    if subscription_success:
        # 付款期间账号不应被迁入 BUSINESS。落库前再验证租约和归属，避免一个
        # 过期/被取消的旧线程覆盖新流程的状态。
        with Session(engine) as session:
            guarded_account = session.get(GptProAccountModel, account_id)
            guard_ok = bool(
                guarded_account
                and not is_managed_business_child_account(guarded_account)
                and _gpt_pro_account_operation_is_current(
                    session, account_id, operation_token, "upgrade_pro",
                )
            )
        if not guard_ok:
            subscription_success = False
            final_stage = "failed"
            error_msg = "付款完成后账号操作租约或 BUSINESS 归属已变化，已拒绝覆盖本地 PRO 状态"

    if subscription_success:
        # 卡尾号: phase2.stripe_fill.picked_card 里有 number_masked, 取后 4 位
        picked_card_info = (phase2.get("stripe_fill") or {}).get("picked_card") or {}
        masked = str(picked_card_info.get("number_masked") or "").replace("*", "").replace(" ", "")
        last4 = masked[-4:] if len(masked) >= 4 else ""
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            now = _utcnow()
            if acc:
                acc.is_pro = True
                acc.subscribed_at = now
                acc.last_used = now
                acc.updated_at = now
                if last4:
                    acc.payment_card_last4 = last4
                session.add(acc)
            if picked_card_id:
                card = session.get(CardModel, int(picked_card_id))
                if card:
                    # 每张卡最多成功购买 max_uses 次(默认6),记一次成功;达上限置 used 不再选。
                    try:
                        from core.config_store import config_store as _cs
                        max_uses = int(str(_cs.get("gpt_pro_card_max_uses", "") or 6) or 6)
                    except Exception:
                        max_uses = 6
                    card.use_count = (card.use_count or 0) + 1
                    card.used_at = now
                    card.reserved_by_account_id = account_id
                    card.updated_at = now
                    if card.use_count >= max_uses:
                        card.status = "used"  # 用满,后续不再被 panel 选中
                    session.add(card)
                    # 记录这张卡所属的支付账号(名称 + 类型 Y卡/E卡)到 PRO 账号, 供界面追溯
                    if acc and getattr(card, "payment_account_id", 0):
                        try:
                            from core.db import PaymentAccountModel as _PA
                            pa = session.get(_PA, int(card.payment_account_id))
                        except Exception:
                            pa = None
                        if pa:
                            try:
                                _ex = json.loads(acc.extra_json) if acc.extra_json else {}
                            except Exception:
                                _ex = {}
                            _ex["payment_account_id"] = pa.id
                            _ex["payment_account_name"] = pa.name
                            _ex["payment_account_type"] = pa.account_type   # "Y" | "E"
                            acc.extra_json = json.dumps(_ex, ensure_ascii=False)
                            session.add(acc)
            session.commit()
    # 支付失败时**不修改卡的状态**(不封卡、不禁用),让卡可继续被复用。
    # 仅在失败卡上记一条 last_error 便于排查, 但保留 status/enabled 不动。
    failed_ids = phase2.get("failed_card_ids") or []
    if (not failed_ids) and (not subscription_success) and (not phase2.get("timeout")) and picked_card_id:
        failed_ids = [picked_card_id]
    if not is_roxy and not phase2.get("timeout") and failed_ids and error_msg:
        with Session(engine) as session:
            for fid in failed_ids:
                if subscription_success and str(fid) == str(picked_card_id):
                    continue
                try:
                    card = session.get(CardModel, int(fid))
                except (TypeError, ValueError):
                    card = None
                if card:
                    # 只记错误, 不改 status / enabled
                    card.last_error = (error_msg or "支付失败")[:200]
                    card.updated_at = _utcnow()
                    session.add(card)
            session.commit()

    with _UPGRADE_PRO_LOCK:
        t = _UPGRADE_PRO_TASKS.get(task_id)
        if t:
            t["stage"] = final_stage
            t["finished_at"] = _utcnow().isoformat()
            t["result"] = phase2
            if error_msg:
                t["error"] = error_msg
            t["manual_window_open"] = not subscription_success
            # 只有成功关闭后才释放 page 引用。失败/超时的手工
            # 留窗由下一次明确取消来关闭，关闭前租约始终占用。
            if subscription_success:
                t.pop("page", None)

    # 升级成功 → 自动关闭浏览器; 超时/失败 → 留窗供用户手动继续付款。
    if subscription_success:
        try:
            page.quit()
        except Exception:
            pass


def _upgrade_pro_phase2_thread(task_id: str, account_id: int, page,
                                pick_timeout: int, auto_pick_seconds: int = 0,
                                direct_card: Optional[dict] = None,
                                is_roxy: bool = False,
                                go_then_pro: bool = False,
                                country: str = "PH", currency: str = "PHP",
                                go_to_pro_wait: int = 60,
                                pro_only: bool = False,
                                operation_token: str = "") -> None:
    """保证 phase2 的租约与真实可付款窗口同生共死。"""
    keep_manual_lease = False
    try:
        _upgrade_pro_phase2_thread_impl(
            task_id,
            account_id,
            page,
            pick_timeout,
            auto_pick_seconds,
            direct_card=direct_card,
            is_roxy=is_roxy,
            go_then_pro=go_then_pro,
            country=country,
            currency=currency,
            go_to_pro_wait=go_to_pro_wait,
            pro_only=pro_only,
            operation_token=operation_token,
        )
    except Exception as exc:
        # impl 之外的未预期异常也不能在仍可手工付款时释放。
        with _UPGRADE_PRO_LOCK:
            t = _UPGRADE_PRO_TASKS.get(task_id)
            if t and not t.get("cancelled"):
                t["stage"] = "failed"
                t["error"] = f"phase2 异常: {exc}"
                t["finished_at"] = _utcnow().isoformat()
                t["manual_window_open"] = True
    finally:
        with _UPGRADE_PRO_LOCK:
            t = _UPGRADE_PRO_TASKS.get(task_id)
            if t:
                t["worker_done"] = True
                keep_manual_lease = bool(
                    t.get("manual_window_open") and not t.get("cancelled")
                )
        if not keep_manual_lease:
            _release_gpt_pro_account_operation(account_id, operation_token)


def _upgrade_pro_account_claimed(
    account_id: int,
    body: Optional[GptProActionRequest],
    operation_token: str,
):
    """升级 PRO (异步任务模型):

    1. 杀掉同账号旧 task + 关掉旧浏览器
    2. **同步** 跑 phase1: 登录 → 创建 checkout → 跳页 → 注入卡选择 panel
    3. spawn daemon thread 跑 phase2: 等人工选卡 (5 分钟) → 填卡 → 点订阅 → 等跳转
    4. 立刻 return task_id + pay_url, 前端轮询
       GET /accounts/{id}/upgrade-pro/status/{task_id} 拿阶段

    成功条件: phase2 跳转回 chatgpt.com/ (非 /checkout/) →
      GptProAccountModel.is_pro=True + subscribed_at=now,
      CardModel.status='used' + used_at=now + reserved_by_account_id=account_id

    checkout region 写死 PH/PHP (菲律宾, ChatGPT Pro 全球最便宜的区);
    账单地址用 _DEFAULT_BILLING_ADDRESS (美国 Oregon Salem 免税地址, 跨区填卡)。
    """
    from platforms.chatgpt.gpt_pro_login import open_pro_checkout_phase1
    import uuid

    body = body or GptProActionRequest()

    # 1. 决定 register / login 分支（旧 task 已由路由入口取消）
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        is_signup = not bool(acc.is_pro)
    stage_label = "注册" if is_signup else "登陆"

    # 升级前先从 RoxyBrowser 刷新所选代理(地址可能已变/轮换); 若已被彻底删除 → 同步删除并中止
    if getattr(body, "roxy_proxy_id", None):
        _proxy_status = _refresh_roxy_proxy_from_roxy(int(body.roxy_proxy_id))
        if _proxy_status == "deleted":
            return {
                "ok": False,
                "stage": "proxy_deleted",
                "error": "所选代理已从 RoxyBrowser 删除, 已同步移除, 请重新选择代理再升级",
            }
    # 结账区域: 指纹模式选了代理 → 跟代理国家一致(读刷新后的国家); 否则用全局配置。账单地址不变
    _ck_country, _ck_currency = _checkout_region_for_upgrade(body)
    # 菲律宾结账区「先 Go 后 PRO」: phase1 先发 Go checkout, phase2 订 Go 成功后再升级 PRO。
    # 可用配置 gpt_pro_ph_go_first=0 关掉回到直接 PRO。
    try:
        from core.config_store import config_store as _cs
        _ph_go_first_cfg = str(_cs.get("gpt_pro_ph_go_first", "") or "1").strip() != "0"
        _go_plan_name = str(_cs.get("gpt_pro_go_plan_name", "") or "chatgptgoplan").strip() or "chatgptgoplan"
        _go_to_pro_wait = int(str(_cs.get("gpt_pro_go_to_pro_wait_seconds", "") or 60) or 60)
    except Exception:
        _ph_go_first_cfg = True
        _go_plan_name = "chatgptgoplan"
        _go_to_pro_wait = 60
    _is_ph = _ck_country.strip().upper() == "PH"
    # 菲律宾结账区: 登录后自动探测当前套餐, 决定走哪条:
    #   free   → go_first  (先订 Go 再升 PRO)
    #   go     → pro_only  (跳过订 Go, 只补跑 PRO 升级)
    #   pro    → already_pro (已是 PRO, 直接标记, 不再付款)
    #   plus/active/检测失败 → pro_only (保守: 有活跃订阅就绝不重复订 Go, 避免重复扣款)
    # 非 PH → direct_pro (直接 PRO, 行为不变)。
    # body.pro_only=True 为手动覆盖(「仅升PRO」按钮), 跳过检测直接 pro_only。
    _go_first_candidate = _ph_go_first_cfg and _is_ph
    _pro_only_manual = bool(getattr(body, "pro_only", False))
    # 手动粘贴的银行卡(有则升级时跳过卡池直接填这张)
    _direct_card = _parse_card_text(getattr(body, "checkout_card", "") or "")
    if getattr(body, "checkout_card", "") and not _direct_card:
        print("[gpt-pro] ⚠ 升级 PRO: 粘贴的银行卡文本无法解析, 将回退到卡池", flush=True)

    # post_login_action 闭包: 探测套餐 + 决定模式 + 跑对应 phase1, 并把 page 引用"漏"到外层 captured
    captured: dict = {}

    def _action(page, login_result):
        from platforms.chatgpt.gpt_pro_login import _detect_current_plan
        captured["page"] = page
        _lf = getattr(login_result, "_log_fn", None) or (lambda m: print(m, flush=True))

        # 决定模式
        if _pro_only_manual:
            mode = "pro_only"
            _lf("[gpt-pro] 手动「仅升PRO」: 跳过检测, 直接补跑 PRO 升级")
        elif not _go_first_candidate:
            mode = "direct_pro"          # 非菲律宾: 直接 PRO
        else:
            det = _detect_current_plan(page, _lf)
            captured["plan_detect"] = det
            if not det.get("ok"):
                mode = "pro_only"        # 检测失败: 保守不重复订 Go
                _lf("[gpt-pro] ⚠ 套餐检测失败, 保守走 pro_only(不重复订 Go);若本是 free 号 PRO 会无害失败, 重试即可")
            elif det.get("is_pro"):
                mode = "already_pro"
            elif det.get("is_go") or det.get("has_active"):
                mode = "pro_only"
            else:
                mode = "go_first"
            _lf(f"[gpt-pro] 菲律宾结账区: 检测 plan={det.get('plan')} → 模式={mode}")
        captured["mode"] = mode

        if mode == "already_pro":
            return {"ok": True, "already_pro": True, "plan_detect": captured.get("plan_detect")}
        if mode == "pro_only":
            # 已在 Go(或保守): 登录成功即可, 后半段在 phase2 thread 里发 PRO checkout
            return {"ok": True, "pro_only": True, "plan_detect": captured.get("plan_detect")}
        # go_first(菲律宾 free) → 先发 Go checkout; direct_pro(非 PH) → 直接 PRO checkout
        plan_name = _go_plan_name if mode == "go_first" else "chatgptpro"
        return open_pro_checkout_phase1(
            page, login_result, dump_only=bool(body.dump_only),
            country=_ck_country, currency=_ck_currency, plan_name=plan_name,
        )

    login_result = _run_drission_login(
        account_id, body, is_signup=is_signup, post_login_action=_action,
    )

    def _quit_captured_page():
        page = captured.get("page")
        if page is not None:
            try:
                page.quit()
            except Exception:
                pass

    if not login_result.get("ok"):
        _quit_captured_page()
        return {
            "ok": False,
            "stage": f"{stage_label}_failed",
            "login": login_result,
        }

    phase1 = login_result.get("action_result") or {}
    if not phase1.get("ok"):
        _quit_captured_page()
        return {
            "ok": False,
            "stage": "checkout_failed",
            "error": phase1.get("error") or "phase1 失败",
            "checkout": phase1,
            "login": login_result,
        }

    # _action 里已按检测结果定好模式
    mode = captured.get("mode") or ("pro_only" if _pro_only_manual else "direct_pro")
    _run_pro_only = (mode == "pro_only")
    _run_go_first = (mode == "go_first")

    # already_pro: 检测到账号已是 PRO → 直接标记为 PRO, 不再付款/不起 phase2
    if mode == "already_pro":
        _quit_captured_page()
        with Session(engine) as session:
            acc2 = session.get(GptProAccountModel, account_id)
            if not acc2:
                raise HTTPException(404, "账号不存在")
            _ensure_not_managed_business_child(acc2)
            if not _gpt_pro_account_operation_is_current(
                session, account_id, operation_token, "upgrade_pro",
            ):
                raise HTTPException(409, "升级 PRO 账号操作租约已失效，请重新执行")
            if not acc2.is_pro:
                now = _utcnow()
                acc2.is_pro = True
                acc2.subscribed_at = acc2.subscribed_at or now
                acc2.updated_at = now
                session.add(acc2)
                session.commit()
        return {
            "ok": True,
            "already_pro": True,
            "stage": "success",
            "region": phase1.get("region") or f"{_ck_country}/{_ck_currency}",
            "plan_detect": captured.get("plan_detect"),
            "message": "账号已是 PRO 套餐, 已直接标记为 PRO(未再付款)",
        }

    # dump_only 诊断模式: phase1 已 dump iframe 树, 不起 phase2
    if body.dump_only:
        return {
            "ok": True,
            "dump_only": True,
            "pay_url": phase1.get("pay_url"),
            "checkout": phase1,
            "login": login_result,
        }

    page = captured.get("page")
    if page is None:
        return {
            "ok": False,
            "stage": "internal_error",
            "error": "phase1 完成但 page 引用丢失",
        }

    cards_count = (phase1.get("card_picker") or {}).get("cards_count", 0)
    if cards_count <= 0 and not _direct_card and not _run_pro_only:
        # 没卡可填: 浏览器**留窗**, 跟 5 分钟选卡超时一致的体验
        # 用户可以手动加卡或者把 used 卡 status 重置回 unused 后再来一遍
        return {
            "ok": False,
            "stage": "no_cards",
            "error": "本地卡池为空 (或所有卡都是 used+single_use=True), 浏览器已留窗; "
                     "请去【银行卡】页加卡或重置 used 卡 status,再点升级 PRO",
            "pay_url": phase1.get("pay_url"),
            "checkout_session_id": phase1.get("checkout_session_id"),
            "checkout": phase1,
            "login": login_result,
        }

    # 3. 起后台 thread 跑 phase2
    task_id = uuid.uuid4().hex[:16]
    pick_timeout = 300  # 5 分钟人工选卡窗口
    now_iso = _utcnow().isoformat()
    task_state = {
        "task_id": task_id,
        "account_id": account_id,
        "stage": "creating_pro_checkout" if _run_pro_only else "awaiting_card_pick",
        "stage_at": now_iso,
        "started_at": now_iso,
        "pay_url": phase1.get("pay_url"),
        "checkout_session_id": phase1.get("checkout_session_id"),
        "auth_stage": stage_label,
        "cards_count": cards_count,
        "pick_timeout": pick_timeout,
        "cancelled": False,
        "worker_done": False,
        "manual_window_open": False,
        "page": page,
        "direct_card": _direct_card,
        "operation_token": operation_token,
    }
    with _UPGRADE_PRO_LOCK:
        _UPGRADE_PRO_TASKS[task_id] = task_state
        _UPGRADE_PRO_BY_ACCOUNT[account_id] = task_id

    th = threading.Thread(
        target=_upgrade_pro_phase2_thread,
        args=(task_id, account_id, page, pick_timeout, int(getattr(body, "auto_pick_seconds", 0) or 0)),
        kwargs={"direct_card": _direct_card,
                "is_roxy": str(getattr(body, "browser_backend", "local") or "local").strip().lower() == "roxybrowser",
                "go_then_pro": _run_go_first, "country": _ck_country, "currency": _ck_currency,
                "go_to_pro_wait": (5 if _run_pro_only else _go_to_pro_wait),
                "pro_only": _run_pro_only,
                "operation_token": operation_token},
        daemon=True,
    )
    th.start()

    return {
        "ok": True,
        "task_id": task_id,
        "pay_url": phase1.get("pay_url"),
        "checkout_session_id": phase1.get("checkout_session_id"),
        "region": phase1.get("region") or "PH/PHP",
        "go_then_pro": _run_go_first,
        "pro_only": _run_pro_only,
        "detected_plan": (captured.get("plan_detect") or {}).get("plan"),
        "auth_stage": stage_label,
        "stage": "creating_pro_checkout" if _run_pro_only else "awaiting_card_pick",
        "cards_count": cards_count,
        "pick_timeout": pick_timeout,
    }


@router.post("/accounts/{account_id}/upgrade-pro")
def upgrade_pro_account(account_id: int, body: Optional[GptProActionRequest] = None):
    """升级全程占用账号；完成 phase1 后由后台 phase2 继续持有并最终释放。"""
    from core.gpt_upgrade_browser_config import (
        UpgradeBrowserConfigError,
        apply_upgrade_browser_selection,
    )

    body = body or GptProActionRequest()
    try:
        # 在启动任务前冻结共享策略；后续配置变化不会改变正在运行的任务。
        apply_upgrade_browser_selection(body, db_engine=engine)
    except UpgradeBrowserConfigError as exc:
        raise HTTPException(exc.status_code, str(exc))
    _kill_existing_upgrade_task(account_id)
    operation_token = _claim_gpt_pro_account_operation(account_id, "upgrade_pro")
    handed_to_phase2 = False
    try:
        result = _upgrade_pro_account_claimed(account_id, body, operation_token)
        handed_to_phase2 = bool(result.get("task_id"))
        return result
    finally:
        if not handed_to_phase2:
            _release_gpt_pro_account_operation(account_id, operation_token)


@router.get("/accounts/{account_id}/upgrade-pro/status/{task_id}")
def upgrade_pro_status(account_id: int, task_id: str):
    """前端轮询用: 返回 task 当前阶段。

    阶段:
      awaiting_card_pick  等人工选卡 (浏览器 panel 上点一张)
      filling_card        填 Stripe iframe 中
      clicking_subscribe  自动点击订阅按钮
      waiting_redirect    等订阅跳转
      success / failed / timeout / cancelled
    """
    with _UPGRADE_PRO_LOCK:
        t = _UPGRADE_PRO_TASKS.get(task_id)
        if not t or t.get("account_id") != account_id:
            raise HTTPException(404, "task 不存在或已被新任务替换")

        # 任务内存中含有 page、租约 token、手动卡的完整 PAN/CVC
        # 以及 phase2 的原始 result。状态轮询只允许返回前端进度展示
        # 实际使用的字段，不能通过“排除几个已知密钥”来序列化整个任务。
        def _safe_text(value: Any, *, limit: int = 1000) -> str:
            text = _sanitize_background_task_text(value)
            text = re.sub(
                r"(?i)\b(cookie|set-cookie|cookies?|password|passwd)\s*[:=]\s*[^\s,;]+",
                lambda match: f"{match.group(1)}=[redacted]",
                text,
            )
            text = re.sub(
                r"(?i)\b(cvc|cvv|cvn|security[ _-]?code|\u5b89\u5168\u7801|\u6821\u9a8c\u7801)"
                r"\s*[:=\uff1a]?\s*\d{3,4}\b",
                lambda match: f"{match.group(1)}=[redacted]",
                text,
            )

            # PAN 可能被空格或连字符分隔；只对去除分隔符后
            # 为 13~19 位的候选串做脱敏，避免在 error/pay_url 中泄漏卡号。
            pan_candidate = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

            def _redact_pan(match: re.Match) -> str:
                digits = re.sub(r"\D", "", match.group(0))
                return "[card-redacted]" if 13 <= len(digits) <= 19 else match.group(0)

            return pan_candidate.sub(_redact_pan, text)[:limit]

        checkout_session_id = str(t.get("checkout_session_id") or "")
        if checkout_session_id and not re.fullmatch(r"cs_[A-Za-z0-9_-]+", checkout_session_id):
            checkout_session_id = ""

        out = {
            "task_id": str(t.get("task_id") or task_id),
            "account_id": int(t.get("account_id") or account_id),
            "stage": _safe_text(t.get("stage") or "", limit=100),
            "stage_at": _safe_text(t.get("stage_at") or "", limit=100),
            "started_at": _safe_text(t.get("started_at") or "", limit=100),
            "finished_at": _safe_text(t.get("finished_at") or "", limit=100),
            "pay_url": _safe_text(t.get("pay_url") or "", limit=2000),
            "checkout_session_id": checkout_session_id,
            "auth_stage": _safe_text(t.get("auth_stage") or "", limit=100),
            "cards_count": int(t.get("cards_count") or 0),
            "pick_timeout": int(t.get("pick_timeout") or 0),
            "error": _safe_text(t.get("error") or "", limit=1000),
            "manual_window_open": bool(t.get("manual_window_open")),
        }
    return out


def _do_refund_one_impl(account_id: int, body: Optional[GptProActionRequest] = None,
                        log=None, operation_token: str = "") -> Dict[str, Any]:
    """对单个 PRO 账号跑一次退款流程(可复用:单账号端点 + 批量退款 runner)。
       1. DrissionPage + OTP 登陆 chatgpt.com
       2. 跳到 help.openai.com → 完成 SSO → 打开 ChatKit 客服框
       3. 两轮脚本对话: "误订阅 请退款" → 等回复 → "联系客服专员";
          半小时内没收到退款邮件则重复对话 (最多 max_rounds 轮)。
    成功后按 AI 是否确认全额退款翻 refund_status。返回结果 dict。"""
    from platforms.chatgpt.gpt_pro_login import run_help_refund_flow

    body = body or GptProActionRequest()
    message_text = (getattr(body, "refund_message", "") or "").strip() or "误订阅 请退款"
    # 批量传入 log → 详细日志进任务面板;单账号端点无 log → 打到 stdout(进 backend.log)
    _log = log or (lambda m: print(m, flush=True))

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        # BUSINESS 池选子号仍复用本表的登录/邮箱凭证，但它不是
        # 当前可退款的 GPT PRO 订阅。单条和批量退款都最终走这个入口，
        # 因此在真实登录/客服动作之前做最后一层归属校验。
        _ensure_not_managed_business_child(acc)
        email = acc.email

    # 退款邮件到达检测: 半小时轮询时用它判断是否已收到退款邮件, 到了就不再重复对话。
    from services.chatgpt_mail_common import (
        REFUND_SUBJECT_PATTERNS,
        parse_message_time,
    )
    flow_start = _utcnow()

    def _refund_arrived() -> bool:
        try:
            with Session(engine) as s2:
                fresh = s2.get(GptProAccountModel, account_id)
                if not fresh:
                    return False
                if fresh.refund_status == "refunded_pending_credit":
                    return True  # 邮件监控已先一步标记
                msgs = _fetch_recent_for_account(fresh, 15)
            for m in msgs:
                subj = str(m.get("subject") or "")
                if any(pat in subj for pat in REFUND_SUBJECT_PATTERNS):
                    rt = parse_message_time(m.get("time"))
                    if rt is None or rt >= flow_start:
                        return True
            return False
        except Exception as exc:
            _log(f"[退款] 退款邮件检查异常(忽略): {exc}")
            return False

    wait_min = int(getattr(body, "refund_wait_min_seconds", 3600) or 3600)
    wait_max = int(getattr(body, "refund_wait_max_seconds", 7200) or 7200)
    max_rounds = int(getattr(body, "refund_max_rounds", 4) or 4)

    manual = bool(getattr(body, "refund_manual", False))
    if manual:
        # 手动模式必须留窗, 供人工手动发送
        try:
            body.keep_browser_open = True
        except Exception:
            pass

    def _action(page, login_result):
        return run_help_refund_flow(
            page, email=email, message_text=message_text,
            wait_min_seconds=wait_min, wait_max_seconds=wait_max, max_rounds=max_rounds,
            refund_arrived=_refund_arrived, manual_only=manual, log_fn=_log,
        )

    login_result = _run_drission_login(
        account_id, body, post_login_action=_action, log_fn=_log,
    )
    if not login_result.get("ok"):
        return {
            "ok": False,
            "stage": "login_failed",
            "refund_success": False,
            "email": email,
            "error": login_result.get("error") or "登陆失败",
            "login": login_result,
        }

    flow = login_result.get("action_result") or {}
    ok = bool(flow.get("ok"))
    refund_success = bool(flow.get("refund_success"))
    manual_opened = bool(flow.get("manual")) or flow.get("stage") == "manual_opened"
    human_escalated = bool(flow.get("human_escalated"))

    # 手动模式: 只打开客服界面, 不改 refund_status; 记录 refund_manual_at(清除"可再次手动退款"提示)。
    if ok and manual_opened:
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            if acc:
                _ensure_not_managed_business_child(acc)
                acc.refund_manual_at = _utcnow()
                acc.updated_at = _utcnow()
                session.add(acc)
                session.commit()

    # 自动模式: AI 已确认全额退款 → refunded_pending_credit; 否则 → refund_pending。
    #           且若本轮升级到了人工 → 记录 human_review_requested_at。
    if ok and not manual_opened:
        with Session(engine) as session:
            acc = session.get(GptProAccountModel, account_id)
            if acc:
                # 退款流程可能持续很久；落库前再次校验，防止期间归属变化。
                _ensure_not_managed_business_child(acc)
                changed = False
                if refund_success and acc.refund_status != "refunded_pending_credit":
                    acc.refund_status = "refunded_pending_credit"
                    if not acc.refund_detected_at:
                        acc.refund_detected_at = _utcnow()
                    changed = True
                elif (not refund_success) and acc.refund_status not in (
                    "refund_pending", "refunded_pending_credit",
                ):
                    acc.refund_status = "refund_pending"
                    changed = True
                if human_escalated:
                    acc.human_review_requested_at = _utcnow()
                    changed = True
                if changed:
                    acc.updated_at = _utcnow()
                    session.add(acc)
                    session.commit()

        # 退款成功 且 该号已同步到 CPA → 删除 CPA 对应凭证 + 清同步标记
        if refund_success:
            try:
                with Session(engine) as session:
                    fresh = session.get(GptProAccountModel, account_id)
                    if fresh:
                        _ensure_not_managed_business_child(fresh)
                _delete_cpa_credential_on_refund(
                    account_id,
                    operation_token=operation_token,
                )
            except Exception as _e:
                print(f"[GPTPRO/CPA] 退款后删凭证失败(忽略): {_e}")

    return {
        "ok": ok,
        "stage": flow.get("stage") or "unknown",
        "sent_text": flow.get("sent_text") or "",
        "escalate_text": flow.get("escalate_text") or "",
        "human_escalated": bool(flow.get("human_escalated")),
        "rounds": flow.get("rounds") or 0,
        "refund_success": refund_success,
        "email": email,
        "note": flow.get("note") or "",
        "error": flow.get("error") or "",
        "login": login_result,
    }


def _do_refund_one(account_id: int, body: Optional[GptProActionRequest] = None,
                   log=None) -> Dict[str, Any]:
    """退款全程持有账号租约，防止客服流程中途被 BUSINESS 或升级流程选中。"""
    operation_token = _claim_gpt_pro_account_operation(account_id, "refund")
    try:
        return _do_refund_one_impl(
            account_id,
            body,
            log,
            operation_token=operation_token,
        )
    finally:
        _release_gpt_pro_account_operation(account_id, operation_token)


@router.post("/accounts/{account_id}/refund")
def refund_account(account_id: int, body: Optional[GptProActionRequest] = None):
    """退款 (自动化版):DrissionPage + OTP 登陆 → help.openai.com 客服框 → 发退款诉求。
    body.refund_message 可覆盖默认文案;body.refund_manual=True 只打开界面不发送(人工手动发);
    keep_browser_open=True 时浏览器留窗。"""
    return _do_refund_one(account_id, body or GptProActionRequest())


@router.post("/accounts/{account_id}/mark-human-review")
def mark_human_review(account_id: int):
    """人工确认「已申请人工审核(联系客服专员)」→ 记录当前时间(用于手动退款后确认)。"""
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        now = _utcnow()
        acc.human_review_requested_at = now
        acc.updated_at = now
        session.add(acc)
        session.commit()
    return {"ok": True, "human_review_requested_at": now.isoformat()}


# ── 批量退款 ─────────────────────────────────────────────────
class GptProBatchRefundRequest(BaseModel):
    ids: List[int] = []                      # 要退款的账号 id;空 → 报错
    refund_message: Optional[str] = None     # 覆盖默认退款文案


@router.post("/accounts/batch-refund")
def gpt_pro_batch_refund(body: GptProBatchRefundRequest):
    """启动批量退款后台任务,立即返回 task_id;前端用 GET /accounts/batch-refund/{task_id}?since=N 轮询。
    单线程串行:逐个账号跑退款流程,失败跳过继续。"""
    ids = [int(i) for i in (body.ids or []) if i]
    if not ids:
        raise HTTPException(400, "未选择任何账号")
    message_text = (body.refund_message or "").strip() or "误订阅 请退款"
    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_batch_refund,
        args=(task_id, ids, message_text),
        name=f"gpt-pro-batchrefund-{task_id[:8]}",
        daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id, "total": len(ids)}


@router.get("/accounts/batch-refund/{task_id}")
def gpt_pro_batch_refund_status(task_id: str, since: int = Query(0, ge=0)):
    """轮询批量退款任务状态 + 增量日志 + 进度。"""
    snapshot = _snapshot_invite_task(task_id, since=since)
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


def _run_batch_refund(task_id: str, account_ids: List[int], message_text: str) -> None:
    """单线程串行批量退款。逐个账号跑退款,失败跳过继续,逐账号 report 写进进度。"""
    log = lambda m: _invite_task_log(task_id, m)

    items: List[Dict[str, Any]] = []
    for aid in account_ids:
        with Session(engine) as s:
            acc = s.get(GptProAccountModel, aid)
            email = acc.email if acc else f"#{aid}"
        items.append({
            "account_id": aid, "email": email,
            "status": "pending", "refund_success": False, "reason": "",
        })
    total = len(items)

    def _counts() -> tuple:
        ok = sum(1 for u in items if u["status"] == "ok")
        failed = sum(1 for u in items if u["status"] == "failed")
        return ok, failed

    def _report() -> List[Dict[str, Any]]:
        return [{k: u[k] for k in ("account_id", "email", "status", "refund_success", "reason")} for u in items]

    def _emit(phase: str = "", current: str = "") -> None:
        ok, failed = _counts()
        _set_invite_progress(task_id, {
            "total": total, "done": ok + failed, "ok": ok, "failed": failed,
            "current_account": current, "phase": phase, "report": _report(),
        })

    log(f"批量退款启动: {total} 个账号")
    _emit("启动")

    from core.scheduler import scheduler as _scheduler
    _scheduler.pause()
    log("⏸ 已暂停调度器后台任务(批量结束后自动恢复)")

    try:
        for i, u in enumerate(items, 1):
            _emit("退款中", u["email"])
            log(f"  ▶ {i}/{total} 退款: {u['email']}")
            try:
                body = GptProActionRequest(
                    refund_message=message_text, headless=True, keep_browser_open=False,
                )
                res = _do_refund_one(u["account_id"], body, log)
                if res.get("ok"):
                    u["status"] = "ok"
                    u["refund_success"] = bool(res.get("refund_success"))
                    u["reason"] = res.get("note") or (
                        "AI 已确认全额退款" if u["refund_success"] else "已发送退款诉求,待确认/邮件检测"
                    )
                    log(f"  ✓ {u['email']} 退款流程完成 [{'全额已确认' if u['refund_success'] else '已发送待确认'}]")
                else:
                    u["status"] = "failed"
                    u["reason"] = res.get("error") or res.get("stage") or "未知失败"
                    log(f"  ✗ {u['email']} 退款失败(跳过): {u['reason']}")
            except HTTPException as exc:
                u["status"] = "failed"
                u["reason"] = str(getattr(exc, "detail", None) or exc)
                log(f"  ✗ {u['email']} 退款异常(跳过): {u['reason']}")
            except Exception as exc:
                u["status"] = "failed"
                u["reason"] = str(exc)
                log(f"  ✗ {u['email']} 退款异常(跳过): {exc}")
            _emit("退款中", u["email"])
            if i < total:
                log("  ⏳ 等 5 秒后继续…")
                time.sleep(5)

        ok_count, fail_count = _counts()
        _emit("完成")
        _invite_task_finish(task_id, result={
            "total": total, "ok": ok_count, "failed": fail_count, "report": _report(),
        })
        log(f"✓ 批量退款全部完成: 成功 {ok_count} / 失败 {fail_count} / 共 {total}")
    except Exception as exc:
        ok_count, fail_count = _counts()
        log(f"✗ 批量退款任务异常: {exc}")
        _invite_task_finish(task_id, error=str(exc), result={
            "total": total, "ok": ok_count, "failed": fail_count, "report": _report(),
        })
    finally:
        _scheduler.resume()
        log("▶ 已恢复调度器后台任务")


# ── RoxyBrowser 代理池(升级 PRO 指纹浏览器用) ──────────────────
class RoxyProxyBatchIn(BaseModel):
    # 每行一个: host:port 或 host:port:user:pass; 可 protocol://host:port[:user:pass];
    # 末尾可用 " # 备注" / " | 备注" / tab 追加备注
    data: str = ""
    protocol: str = "SOCKS5"   # 行内未指定协议时的默认


class RoxyProxyUpdate(BaseModel):
    host: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class RoxyProxyImportIn(BaseModel):
    # prune=True: RoxyBrowser 侧已删除的代理(本地有 roxy_module_id 的行)同步删除;
    # 手动批量添加的(无 roxy_module_id)不受影响
    prune: bool = False


def _roxy_proxy_out(p: RoxyProxyModel) -> dict:
    return {
        "id": p.id, "host": p.host, "port": p.port, "protocol": p.protocol,
        "username": p.username, "password": p.password, "note": p.note,
        "roxy_module_id": p.roxy_module_id, "last_ip": p.last_ip,
        "last_country": p.last_country, "enabled": p.enabled,
        "check_status": getattr(p, "check_status", -1),
        "checked_at": p.checked_at.isoformat() if getattr(p, "checked_at", None) else "",
        "created_at": p.created_at.isoformat() if p.created_at else "",
        "updated_at": p.updated_at.isoformat() if p.updated_at else "",
    }


def _parse_roxy_proxy_lines(data: str, *, default_protocol: str = "SOCKS5") -> list[dict]:
    """解析批量代理文本 → [{host,port,protocol,username,password,note}]。"""
    default_proto = str(default_protocol or "SOCKS5").strip().upper()
    if default_proto not in ("HTTP", "HTTPS", "SOCKS5"):
        default_proto = "SOCKS5"
    out: list[dict] = []
    for raw in str(data or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        note = ""
        for sep in (" #", "\t", " | ", "|"):
            if sep in line:
                line, note_part = line.split(sep, 1)
                line, note = line.strip(), note_part.strip().lstrip("#").strip()
                break
        proto = default_proto
        m = re.match(r"^(https?|socks5)://(.+)$", line, re.I)
        if m:
            proto = m.group(1).upper()
            line = m.group(2)
        parts = [x.strip() for x in line.split(":")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        out.append({
            "host": parts[0],
            "port": parts[1],
            "protocol": proto,
            "username": parts[2] if len(parts) >= 3 else "",
            "password": parts[3] if len(parts) >= 4 else "",
            "note": note,
        })
    return out


@router.get("/roxy/proxies")
def list_roxy_proxies():
    with Session(engine) as s:
        rows = s.exec(select(RoxyProxyModel).order_by(RoxyProxyModel.id.desc())).all()  # type: ignore[attr-defined]
    return {"total": len(rows), "items": [_roxy_proxy_out(p) for p in rows]}


@router.post("/roxy/proxies")
def add_roxy_proxies(body: RoxyProxyBatchIn):
    parsed = _parse_roxy_proxy_lines(body.data, default_protocol=body.protocol)
    if not parsed:
        raise HTTPException(400, "没有解析到有效代理行(格式: host:port 或 host:port:user:pass, 末尾可加 备注)")
    now = _utcnow()
    with Session(engine) as s:
        for item in parsed:
            s.add(RoxyProxyModel(created_at=now, updated_at=now, **item))
        s.commit()
    return {"ok": True, "added": len(parsed)}


@router.put("/roxy/proxies/{proxy_id}")
def update_roxy_proxy(proxy_id: int, body: RoxyProxyUpdate):
    with Session(engine) as s:
        p = s.get(RoxyProxyModel, proxy_id)
        if not p:
            raise HTTPException(404, "代理不存在")
        for field in ("host", "port", "protocol", "username", "password", "note", "enabled"):
            v = getattr(body, field)
            if v is not None:
                setattr(p, field, v)
        p.updated_at = _utcnow()
        s.add(p)
        s.commit()
        return {"ok": True, "item": _roxy_proxy_out(p)}


@router.delete("/roxy/proxies/{proxy_id}")
def delete_roxy_proxy(proxy_id: int):
    with Session(engine) as s:
        p = s.get(RoxyProxyModel, proxy_id)
        if not p:
            raise HTTPException(404, "代理不存在")
        s.delete(p)
        s.commit()
    return {"ok": True}


@router.post("/roxy/proxies/import")
def import_roxy_proxies(body: Optional[RoxyProxyImportIn] = None):
    """从 RoxyBrowser /proxy/list 导入代理(分页拉全量)。

    备注取 RoxyBrowser 的 remark 字段; 按 host:port upsert:
    已存在的会刷新出口IP/国家/moduleId, 并在应用侧备注为空时回填 remark(不覆盖已手填备注)。
    prune=True 时, 本地来源于 RoxyBrowser 的行(roxy_module_id 非空)若已不在
    RoxyBrowser 列表中, 会被同步删除; 手动添加的行不动。
    """
    from core.roxy_browser import (
        RoxyBrowserClient, RoxyBrowserError, load_roxy_config, resolve_workspace_id,
    )
    prune = bool(body.prune) if body is not None else False
    try:
        ws = resolve_workspace_id()
        cfg = load_roxy_config()
        client = RoxyBrowserClient(cfg["api_host"], cfg["token"])
        rows: list = []
        page = 1
        while True:
            batch = client.list_proxies(ws, page_index=page, page_size=200)
            rows.extend(batch)
            if len(batch) < 200 or page >= 50:
                break
            page += 1
    except RoxyBrowserError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"从 RoxyBrowser 导入失败: {exc}")
    now = _utcnow()
    imported = updated = skipped = removed = 0
    with Session(engine) as s:
        by_key = {
            (str(p.host).strip().lower(), str(p.port).strip()): p
            for p in s.exec(select(RoxyProxyModel)).all()
        }
        for r in rows:
            host = str(r.get("host") or "").strip()
            port = str(r.get("port") or "").strip()
            if not host or not port:
                continue
            proto = str(r.get("protocol") or r.get("proxyCategory") or "SOCKS5").strip().upper()
            if proto not in ("HTTP", "HTTPS", "SOCKS5"):
                proto = "SOCKS5"
            remark = str(r.get("remark") or "").strip()
            module_id = str(r.get("id") or "")
            last_ip = str(r.get("lastIp") or "")
            last_country = str(r.get("lastCountry") or "")
            user = str(r.get("proxyUserName") or r.get("username") or "")
            pwd = str(r.get("proxyPassword") or r.get("password") or "")
            key = (host.lower(), port)
            p = by_key.get(key)
            if p is not None:
                changed = False
                if remark and not str(p.note or "").strip():
                    p.note = remark; changed = True
                if module_id and p.roxy_module_id != module_id:
                    p.roxy_module_id = module_id; changed = True
                if last_ip and p.last_ip != last_ip:
                    p.last_ip = last_ip; changed = True
                if last_country and p.last_country != last_country:
                    p.last_country = last_country; changed = True
                if user and not str(p.username or "").strip():
                    p.username = user; changed = True
                if pwd and not str(p.password or "").strip():
                    p.password = pwd; changed = True
                if changed:
                    p.updated_at = now
                    s.add(p)
                    updated += 1
                else:
                    skipped += 1
                continue
            p = RoxyProxyModel(
                host=host, port=port, protocol=proto,
                username=user, password=pwd, note=remark,
                roxy_module_id=module_id, last_ip=last_ip, last_country=last_country,
                created_at=now, updated_at=now,
            )
            s.add(p)
            by_key[key] = p
            imported += 1
        if prune:
            fetched_keys = {
                (str(r.get("host") or "").strip().lower(), str(r.get("port") or "").strip())
                for r in rows
            }
            for key, p in list(by_key.items()):
                if str(p.roxy_module_id or "").strip() and key not in fetched_keys:
                    s.delete(p)
                    del by_key[key]
                    removed += 1
        s.commit()
    return {
        "ok": True, "imported": imported, "updated": updated,
        "skipped": skipped, "removed": removed, "total_fetched": len(rows),
    }


@router.post("/roxy/cleanup-windows")
def cleanup_roxy_windows():
    """手动清理: 删除所有已关闭的、本工具创建(windowName=gptpro-upgrade)的 RoxyBrowser 窗口记录。

    后台每 45s 自动清扫(升级用过指纹后启动); 此端点用于立即触发一次。
    """
    from core.roxy_browser import cleanup_closed_gptpro_windows
    n = cleanup_closed_gptpro_windows(log=lambda m: print(m, flush=True))
    return {"ok": True, "deleted": n}


class RoxyProxyDetectIn(BaseModel):
    ids: List[int] = []   # 空 = 全部(仅检测有 roxy_module_id 的)


@router.post("/roxy/proxies/detect")
def detect_roxy_proxies(body: RoxyProxyDetectIn):
    """检测代理可用性: 触发 RoxyBrowser /proxy/detect, 等结果写回后读 /proxy/list 更新 check_status/出口IP。

    仅能检测有 roxy_module_id 的代理(从 RoxyBrowser 导入/同步过的)。
    """
    from core.roxy_browser import (
        RoxyBrowserClient, RoxyBrowserError, load_roxy_config, resolve_workspace_id,
    )
    id_set = set(body.ids or [])
    with Session(engine) as s:
        rows = s.exec(select(RoxyProxyModel)).all()
    targets = [p for p in rows if (not id_set or p.id in id_set) and str(p.roxy_module_id or "").strip()]
    skipped = [p.id for p in rows if (not id_set or p.id in id_set) and not str(p.roxy_module_id or "").strip()]
    if not targets:
        raise HTTPException(400, "没有可检测的代理(需先从 RoxyBrowser 导入, 取得代理ID)")
    try:
        ws = resolve_workspace_id()
        cfg = load_roxy_config()
        client = RoxyBrowserClient(cfg["api_host"], cfg["token"])
        for p in targets:
            try:
                client.detect_proxy(ws, int(p.roxy_module_id))
            except Exception:
                pass
        time.sleep(6)  # 等 RoxyBrowser 异步检测写回结果
        fresh = client.list_proxies(ws)
    except RoxyBrowserError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"检测失败: {exc}")
    by_id = {str(r.get("id")): r for r in fresh}
    now = _utcnow()
    results = []
    alive = 0
    with Session(engine) as s:
        for p in targets:
            r = by_id.get(str(p.roxy_module_id)) or {}
            cs = r.get("checkStatus")
            ok = 1 if cs == 1 else (0 if cs is not None else -1)
            last_ip = str(r.get("lastIp") or "")
            last_country = str(r.get("lastCountry") or "")
            dbp = s.get(RoxyProxyModel, p.id)
            if dbp:
                dbp.check_status = ok
                dbp.checked_at = now
                if last_ip:
                    dbp.last_ip = last_ip
                if last_country:
                    dbp.last_country = last_country
                dbp.updated_at = now
                s.add(dbp)
            if ok == 1:
                alive += 1
            results.append({"id": p.id, "check_status": ok, "last_ip": last_ip, "last_country": last_country})
        s.commit()
    return {"ok": True, "checked": len(targets), "alive": alive, "skipped_no_module": skipped, "results": results}


# ── GPT PRO ⇄ CPA 号池自动维护 ──────────────────────────────
class CpaConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    auto_buy: Optional[bool] = None
    refund_days: Optional[int] = None
    interval_minutes: Optional[int] = None
    max_per_run: Optional[int] = None
    card_max_uses: Optional[int] = None
    recycle_hour: Optional[int] = None   # 每天几点跑退款回收(0-23)
    devices: Optional[list] = None   # [{device_id, threshold, api_url?, api_key?, refund_enabled, replenish_enabled, auto_buy, refund_days}]


class SchedulerTogglesRequest(BaseModel):
    cpa_maintenance: Optional[bool] = None
    device_maintenance: Optional[bool] = None
    gpt_pro_cpa: Optional[bool] = None


@router.get("/scheduler-toggles")
def get_scheduler_toggles():
    """后台维护开关；旧 GPT PRO CPA worker 已永久退役。"""
    from core.scheduler import task_enabled
    return {
        "cpa_maintenance": task_enabled("cpa_maintenance"),
        "device_maintenance": task_enabled("device_maintenance"),
        "gpt_pro_cpa": False,
    }


@router.put("/scheduler-toggles")
def put_scheduler_toggles(body: SchedulerTogglesRequest):
    from core.config_store import config_store
    from core.scheduler import TASK_TOGGLE_KEYS, task_enabled
    for name, val in body.dict().items():
        if val is None:
            continue
        key = TASK_TOGGLE_KEYS.get(name)
        if key:
            config_store.set(key, "1" if val else "0")
    return {
        "cpa_maintenance": task_enabled("cpa_maintenance"),
        "device_maintenance": task_enabled("device_maintenance"),
        "gpt_pro_cpa": False,
    }


class CpaAutoRefundToggleRequest(BaseModel):
    enabled: bool


@router.get("/cpa-auto-refund")
def get_cpa_auto_refund():
    """旧额度自动退款已退役；耗尽账号由设备 saga 处理。"""
    return {"enabled": False, "retired": True}


@router.put("/cpa-auto-refund")
def put_cpa_auto_refund(body: CpaAutoRefundToggleRequest):
    if body.enabled:
        raise HTTPException(410, "GPT PRO 自动退款已退役，请使用设备耗尽处理")
    return {"enabled": False, "retired": True}


@router.get("/cpa-config")
def get_cpa_config():
    from services import gpt_pro_cpa_manager as m
    return m.get_config()


@router.put("/cpa-config")
def put_cpa_config(body: CpaConfigRequest):
    from services import gpt_pro_cpa_manager as m
    return m.set_config({k: v for k, v in body.dict().items() if v is not None})


@router.get("/cpa-status")
def get_cpa_status():
    return {"running": False, "retired": True}


@router.post("/cpa-maintain-now")
def cpa_maintain_now():
    raise HTTPException(410, "GPT PRO CPA 号池已退役，请刷新 CPA/SUB 设备")


@router.post("/cpa-recycle-now")
def cpa_recycle_now():
    """手动跑一轮退款回收。"""
    raise HTTPException(410, "GPT PRO CPA 退款回收已退役")


@router.post("/cpa-replenish-now")
def cpa_replenish_now():
    """手动跑一轮补充(含救急重置)。"""
    raise HTTPException(410, "GPT PRO CPA 补充已退役，请使用母号调度")


@router.post("/cpa-dedupe-now")
def cpa_dedupe_now():
    """按邮箱去重:同一账号的多份 auth-file 只保留一份。"""
    raise HTTPException(410, "GPT PRO CPA 号池去重已退役")


@router.get("/cpa-accounts")
def get_cpa_accounts(force: bool = False):
    """CPA 真实账号列表 + 5h/周用量(15 分钟缓存; force=1 强制刷新)。"""
    raise HTTPException(410, "请使用 /delivery-devices 查看设备账号与额度")


@router.post("/accounts/{account_id}/oauth")
def oauth_account(account_id: int, body: Optional[GptProActionRequest] = None):
    """启动 codex OAuth 后台任务, 立即返回 task_id;
    前端用 GET /accounts/{account_id}/oauth/{task_id}?since=N 轮询实时日志。

    用 DrissionPage 浏览器全程接管, 拿 Codex access/refresh/session token 写回
    codex_* 字段。命中 /add-phone 时用注入的 smsbower 配置自动过手机验证。
    """
    body = body or GptProActionRequest()

    with Session(engine) as session:
        acc = session.get(GptProAccountModel, account_id)
        if not acc:
            raise HTTPException(404, "账号不存在")
        if not acc.enabled:
            raise HTTPException(409, "账号已被禁用")
        if not (acc.email or "").strip():
            raise HTTPException(400, "账号缺 email")

    task_id = _create_invite_task()
    th = threading.Thread(
        target=_run_oauth_task,
        args=(task_id, account_id, body),
        name=f"gpt-pro-oauth-{task_id[:8]}",
        daemon=True,
    )
    th.start()
    return {"ok": True, "task_id": task_id}


def _assert_business_rotation_oauth_owner(
    session: Session,
    account_id: int,
    parent_id: int,
    operation_id: str,
    *,
    allow_stale_binding: bool = False,
    expected_task_id: str = "",
    lock_for_update: bool = False,
) -> GptProAccountModel:
    """Fail closed before an automatic OAuth task snapshots or writes tokens."""
    from core.db import GptBusinessChildMembershipModel

    if lock_for_update and session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    account_query = select(GptProAccountModel).where(
        GptProAccountModel.id == int(account_id)
    )
    if lock_for_update and session.get_bind().dialect.name != "sqlite":
        account_query = account_query.with_for_update()
    acc = session.exec(account_query).first()
    if not acc:
        raise RuntimeError("OAuth 子号不存在")
    if (
        not bool(acc.enabled)
        or bool(acc.dangerous)
        or bool(str(acc.refund_status or "").strip())
        or int(getattr(acc, "business_parent_id", None) or 0) != int(parent_id)
    ):
        raise RuntimeError("OAuth 子号健康状态或 BUSINESS 归属已变化")
    membership_query = (
        select(GptBusinessChildMembershipModel)
        .where(GptBusinessChildMembershipModel.business_account_id == int(parent_id))
        .where(GptBusinessChildMembershipModel.pro_account_id == int(account_id))
        .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
    )
    if lock_for_update and session.get_bind().dialect.name != "sqlite":
        membership_query = membership_query.with_for_update()
    membership = session.exec(membership_query).first()
    if not membership:
        raise RuntimeError("OAuth 子号已不再是该母号的活跃成员")
    extra = _extra_of(acc)
    bound_operation = str(extra.get("business_rotation_oauth_operation_id") or "")
    bound_task_id = str(extra.get("business_rotation_oauth_task_id") or "")
    required_task_id = str(expected_task_id or "").strip()
    if required_task_id and (
        bound_operation != str(operation_id or "")
        or bound_task_id != required_task_id
    ):
        raise RuntimeError("OAuth 任务已被新的 CPA 轮换任务接管")
    if bound_operation and bound_operation != str(operation_id or ""):
        if (
            not allow_stale_binding
            or _business_rotation_oauth_binding_active(extra)
        ):
            raise RuntimeError("OAuth 子号已绑定其他 CPA 轮换任务")
    return acc


def _assert_managed_business_oauth_owner(
    session: Session,
    account_id: int,
    parent_id: int,
    *,
    require_remote_member: bool = False,
    lock_for_update: bool = False,
) -> GptProAccountModel:
    """Fence a user-triggered BUSINESS child OAuth against stale ownership.

    Unlike CPA rotation OAuth this path has no durable rotation operation/lease.
    Its authority is the exact active pool membership.  The composite launcher
    may initially accept a pending invite, but the OAuth worker and token
    writeback both require a confirmed remote member.
    """
    if lock_for_update and session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    account_query = select(GptProAccountModel).where(
        GptProAccountModel.id == int(account_id)
    )
    if lock_for_update and session.get_bind().dialect.name != "sqlite":
        account_query = account_query.with_for_update()
    acc = session.exec(account_query).first()
    if not acc:
        raise RuntimeError("OAuth 子号不存在")
    if (
        not bool(acc.enabled)
        or bool(acc.dangerous)
        or bool(acc.policy_warning)
        or bool(str(acc.refund_status or "").strip())
        or int(getattr(acc, "business_parent_id", None) or 0) != int(parent_id)
    ):
        raise RuntimeError("OAuth 子号健康状态或 BUSINESS 归属已变化")

    normalized_email = str(acc.email or "").strip().lower()
    if not normalized_email:
        raise RuntimeError("OAuth 子号缺少邮箱")
    membership_query = (
        select(GptBusinessChildMembershipModel)
        .where(GptBusinessChildMembershipModel.business_account_id == int(parent_id))
        .where(GptBusinessChildMembershipModel.pro_account_id == int(account_id))
        .where(GptBusinessChildMembershipModel.ended_at.is_(None))  # type: ignore[union-attr]
        .where(func.lower(GptBusinessChildMembershipModel.email) == normalized_email)
        .where(func.lower(GptBusinessChildMembershipModel.source) == "pool")
    )
    if lock_for_update and session.get_bind().dialect.name != "sqlite":
        membership_query = membership_query.with_for_update()
    membership = session.exec(membership_query).first()
    if not membership:
        raise RuntimeError("OAuth 子号已不再是该母号的活跃池选子号")
    if require_remote_member and not str(membership.remote_user_id or "").strip():
        raise RuntimeError("OAuth 子号尚未确认加入 BUSINESS 工作区")
    if not (
        str(membership.remote_user_id or "").strip()
        or str(membership.remote_invite_id or "").strip()
    ):
        raise RuntimeError("OAuth 子号缺少可确认的 BUSINESS 邀请或成员绑定")
    return acc


def oauth_account_for_managed_business_child(
    account_id: int,
    parent_id: int,
    body: Optional[GptProActionRequest] = None,
    *,
    allow_workspace_login: bool = True,
    expected_operation_token: str = "",
) -> dict:
    """Start login/join/OAuth for one active managed BUSINESS pool child.

    A pending invitation may create the composite task, but OAuth itself starts
    only after the target workspace reports the child as a member.
    """
    body = body or GptProActionRequest()
    with Session(engine) as session:
        try:
            _assert_managed_business_oauth_owner(
                session,
                int(account_id),
                int(parent_id),
                require_remote_member=False,
            )
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    join_mode = (
        "login_allowed" if bool(allow_workspace_login)
        else "existing_session_only"
    )
    required_operation_token = str(expected_operation_token or "").strip()
    if required_operation_token and not _gpt_pro_account_operation_token_is_current(
        int(account_id), required_operation_token,
    ):
        raise HTTPException(409, "BUSINESS 子号凭证修复租约已失效")
    with _MANAGED_BUSINESS_OAUTH_LOCK:
        with _AUTO_INVITE_LOCK:
            for existing_task_id, task in _AUTO_INVITE_TASKS.items():
                if (
                    str(task.get("status") or "") == "running"
                    and str(task.get("task_kind") or "") == "managed_business_oauth"
                    and int(task.get("business_parent_id") or 0) == int(parent_id)
                    and int(task.get("account_id") or 0) == int(account_id)
                ):
                    existing_mode = str(
                        task.get("managed_business_join_mode")
                        or "login_allowed"
                    )
                    if existing_mode != join_mode:
                        raise HTTPException(
                            409,
                            "该子号已有不同登录策略的 RT 任务正在执行",
                        )
                    existing_operation_token = str(
                        task.get("managed_business_operation_token") or ""
                    )
                    if existing_operation_token != required_operation_token:
                        raise HTTPException(
                            409,
                            "该子号已有不同操作租约的 RT 任务正在执行",
                        )
                    return {
                        "ok": True,
                        "task_id": existing_task_id,
                        "idempotent": True,
                    }

        task_id = _create_invite_task()
        with _AUTO_INVITE_LOCK:
            task = _AUTO_INVITE_TASKS.get(task_id)
            if task is None:
                raise HTTPException(500, "OAuth 任务初始化失败")
            task.update({
                "task_kind": "managed_business_oauth",
                "business_parent_id": int(parent_id),
                "account_id": int(account_id),
                "managed_business_join_mode": join_mode,
                "managed_business_operation_token": required_operation_token,
            })
        th = threading.Thread(
            target=_run_managed_business_child_oauth_task,
            args=(
                task_id,
                int(account_id),
                int(parent_id),
                body,
                bool(allow_workspace_login),
                required_operation_token,
            ),
            name=f"gpt-pro-business-child-oauth-{task_id[:8]}",
            daemon=True,
        )
        try:
            th.start()
        except Exception as exc:
            _invite_task_finish(task_id, error=f"OAuth 后台线程启动失败: {exc}")
            raise HTTPException(500, f"OAuth 后台线程启动失败: {exc}")
    return {"ok": True, "task_id": task_id, "idempotent": False}


def _run_managed_business_child_oauth_task(
    task_id: str,
    account_id: int,
    parent_id: int,
    body: GptProActionRequest,
    allow_workspace_login: bool = True,
    expected_operation_token: str = "",
) -> None:
    """Composite worker: login/join the exact workspace, then run OAuth."""

    def _log(message: Any) -> None:
        _invite_task_log(task_id, str(message))

    try:
        required_operation_token = str(expected_operation_token or "").strip()
        if required_operation_token and not _gpt_pro_account_operation_token_is_current(
            int(account_id), required_operation_token,
        ):
            raise RuntimeError("BUSINESS 子号凭证修复租约已失效")
        _log(
            "步骤 1/2：检查子号现有会话与目标 BUSINESS 工作区成员状态"
            if not allow_workspace_login
            else "步骤 1/2：检查子号登录状态与目标 BUSINESS 工作区成员状态"
        )
        # Runtime import avoids the gpt_business -> gpt_pro router import cycle.
        from api.gpt_business import _ensure_managed_business_child_joined_for_oauth

        join_kwargs: Dict[str, Any] = {"log_fn": _log}
        # Preserve the pre-existing normal-path callable contract; the new
        # history-child mode alone explicitly disables OTP login.
        if not allow_workspace_login:
            join_kwargs["allow_otp_login"] = False
        joined = _ensure_managed_business_child_joined_for_oauth(
            int(parent_id),
            int(account_id),
            **join_kwargs,
        )
        if not bool(joined.get("ok")):
            stage = str(joined.get("stage") or "workspace_join_failed")
            error = str(joined.get("error") or "子号未能进入目标 BUSINESS 工作区")
            _log(f"✗ 登录/进入工作区失败: {error}")
            _invite_task_finish(
                task_id,
                error=error,
                result={"stage": stage},
            )
            return

        _log("步骤 2/2：工作区成员状态已确认，开始 Codex OAuth")
        if required_operation_token and not _gpt_pro_account_operation_token_is_current(
            int(account_id), required_operation_token,
        ):
            raise RuntimeError("BUSINESS 子号凭证修复租约已失效")
        _run_oauth_task(
            task_id,
            int(account_id),
            body,
            expected_managed_business_parent_id=int(parent_id),
            expected_managed_operation_token=required_operation_token,
        )
    except Exception as exc:
        error = str(getattr(exc, "detail", exc))
        _log(f"✗ 登录/进入工作区任务异常: {error}")
        _invite_task_finish(
            task_id,
            error=error,
            result={"stage": "workspace_join_failed"},
        )


def oauth_account_status_for_managed_business_child(
    account_id: int,
    parent_id: int,
    task_id: str,
    since: int = 0,
) -> dict:
    """Return task state only when its immutable parent/child binding matches."""
    with _AUTO_INVITE_LOCK:
        task = _AUTO_INVITE_TASKS.get(str(task_id or ""))
        if not task:
            raise HTTPException(404, "任务不存在或已过期")
        if (
            str(task.get("task_kind") or "") != "managed_business_oauth"
            or int(task.get("business_parent_id") or 0) != int(parent_id)
            or int(task.get("account_id") or 0) != int(account_id)
        ):
            raise HTTPException(404, "任务不存在或不属于该 BUSINESS 子号")
    snapshot = _snapshot_invite_task(str(task_id), since=max(0, int(since or 0)))
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


def _business_rotation_oauth_binding_active(
    extra: dict,
    *,
    now: Optional[datetime] = None,
) -> bool:
    """A durable running binding remains authoritative across process restarts."""
    if str(extra.get("business_rotation_oauth_status") or "").lower() != "running":
        return False
    try:
        deadline = _parse_expires_at(
            extra.get("business_rotation_oauth_lease_expires_at")
        )
    except HTTPException:
        deadline = None
    return bool(deadline and deadline > (_aware_utc(now) or _utcnow()))


def _record_business_rotation_oauth_terminal(
    account_id: int,
    parent_id: int,
    operation_id: str,
    task_id: str,
    status: str,
) -> None:
    """Record terminal state only while the exact durable binding still owns it."""
    if not operation_id:
        return
    with Session(engine) as session:
        acc = session.get(GptProAccountModel, int(account_id))
        if (
            not acc
            or int(getattr(acc, "business_parent_id", None) or 0) != int(parent_id)
        ):
            return
        extra = _extra_of(acc)
        if (
            str(extra.get("business_rotation_oauth_operation_id") or "") != str(operation_id)
            or str(extra.get("business_rotation_oauth_task_id") or "") != str(task_id)
        ):
            return
        extra["business_rotation_oauth_status"] = str(status or "failed")
        extra["business_rotation_oauth_finished_at"] = _utcnow().isoformat()
        extra.pop("business_rotation_oauth_lease_expires_at", None)
        observed_extra_json = acc.extra_json
        result = session.exec(
            sa_update(GptProAccountModel)
            .where(GptProAccountModel.id == int(account_id))
            .where(GptProAccountModel.extra_json == observed_extra_json)
            .where(GptProAccountModel.business_parent_id == int(parent_id))
            .values(
                extra_json=json.dumps(extra, ensure_ascii=False),
                updated_at=_utcnow(),
            )
        )
        if int(getattr(result, "rowcount", 0) or 0) != 1:
            session.rollback()
            return
        session.commit()


def oauth_account_for_business_rotation(
    account_id: int,
    parent_id: int,
    operation_id: str,
    operation_token: str,
) -> dict:
    """Start or reuse one guarded OAuth task for a durable CPA rotation job."""
    op_id = str(operation_id or "").strip()
    if not op_id:
        raise HTTPException(400, "CPA 轮换 OAuth 缺 operation_id")
    with _BUSINESS_ROTATION_OAUTH_LOCK:
        with Session(engine) as session:
            acc = _assert_business_rotation_oauth_owner(
                session,
                account_id,
                parent_id,
                op_id,
                allow_stale_binding=True,
                lock_for_update=True,
            )
            lease = session.get(GptProAccountOperationLeaseModel, int(account_id))
            if (
                not lease
                or str(lease.token or "") != str(operation_token or "")
                or (_aware_utc(lease.expires_at) or _utcnow()) <= _utcnow()
            ):
                raise HTTPException(409, "CPA 轮换 OAuth 子号操作租约已失效")
            extra = _extra_of(acc)
            existing_task_id = str(extra.get("business_rotation_oauth_task_id") or "")
            existing_operation = str(extra.get("business_rotation_oauth_operation_id") or "")
            # The token row and the durable OAuth binding are read while holding
            # the same account-row lock used by the guarded task writeback.  If
            # the previous task won that race and already stored an RT, the
            # rotation is ready for CPA delivery: do not replace its terminal
            # binding and, most importantly, do not start a second browser flow.
            if str(acc.codex_refresh_token or "").strip():
                return {
                    "ok": True,
                    "task_id": existing_task_id,
                    "idempotent": True,
                    "already_ready": True,
                    "status": "done",
                }
            if (
                existing_task_id
                and existing_operation == op_id
                and _business_rotation_oauth_binding_active(extra)
            ):
                return {
                    "ok": True,
                    "task_id": existing_task_id,
                    "idempotent": True,
                    "durable_running": True,
                    "lease_expires_at": str(
                        extra.get("business_rotation_oauth_lease_expires_at") or ""
                    ),
                }

            # A missing in-memory task after restart, or a terminal task from a
            # prior attempt, is a stale checkpoint rather than a permanent
            # reservation.  Persist the replacement task ID before starting it.
            task_id = _create_invite_task()
            now = _utcnow()
            lease_expires_at = now + timedelta(
                minutes=BUSINESS_ROTATION_OAUTH_LEASE_MINUTES
            )
            extra["business_rotation_oauth_task_id"] = task_id
            extra["business_rotation_oauth_operation_id"] = op_id
            extra["business_rotation_oauth_parent_id"] = int(parent_id)
            extra["business_rotation_oauth_status"] = "running"
            extra["business_rotation_oauth_started_at"] = now.isoformat()
            extra["business_rotation_oauth_lease_expires_at"] = lease_expires_at.isoformat()
            extra.pop("business_rotation_oauth_finished_at", None)
            observed_extra_json = acc.extra_json
            claimed = session.exec(
                sa_update(GptProAccountModel)
                .where(GptProAccountModel.id == int(account_id))
                .where(GptProAccountModel.extra_json == observed_extra_json)
                .where(GptProAccountModel.business_parent_id == int(parent_id))
                .where(GptProAccountModel.enabled == True)  # noqa: E712
                .where(GptProAccountModel.dangerous == False)  # noqa: E712
                .where(func.coalesce(GptProAccountModel.refund_status, "") == "")
                .values(
                    extra_json=json.dumps(extra, ensure_ascii=False),
                    updated_at=now,
                )
            )
            if int(getattr(claimed, "rowcount", 0) or 0) != 1:
                session.rollback()
                with _AUTO_INVITE_LOCK:
                    _AUTO_INVITE_TASKS.pop(task_id, None)
                raise HTTPException(409, "CPA 轮换 OAuth 持久租约已被其他进程接管")
            session.commit()
    th = threading.Thread(
        target=_run_oauth_task,
        args=(task_id, account_id, GptProActionRequest()),
        kwargs={
            "expected_business_parent_id": int(parent_id),
            "expected_operation_id": op_id,
        },
        name=f"gpt-pro-oauth-{task_id[:8]}",
        daemon=True,
    )
    try:
        th.start()
    except Exception as exc:
        # The durable claim was committed before Thread.start().  Roll back that
        # exact task binding on launch failure so a retry does not observe a
        # phantom 30-minute running lease.  CAS ownership in the helper prevents
        # an older failed launch from clearing a newer task's binding.
        _record_business_rotation_oauth_terminal(
            account_id,
            int(parent_id),
            op_id,
            task_id,
            "failed",
        )
        _invite_task_finish(task_id, error=f"OAuth 后台线程启动失败: {exc}")
        raise HTTPException(500, f"OAuth 后台线程启动失败: {exc}")
    return {"ok": True, "task_id": task_id, "idempotent": False}


@router.get("/accounts/{account_id}/oauth/{task_id}")
def oauth_account_status(account_id: int, task_id: str, since: int = Query(0, ge=0)):
    """轮询 codex OAuth 任务状态 + 增量日志。前端每秒拉一次, 直到 status != 'running'。"""
    snapshot = _snapshot_invite_task(task_id, since=since)
    if snapshot is None:
        raise HTTPException(404, "任务不存在或已过期")
    return snapshot


def _run_oauth_task(
    task_id: str,
    account_id: int,
    body: GptProActionRequest,
    *,
    expected_business_parent_id: Optional[int] = None,
    expected_operation_id: str = "",
    expected_managed_business_parent_id: Optional[int] = None,
    expected_managed_operation_token: str = "",
) -> None:
    """codex OAuth 后台执行体, 日志实时写入任务 store 供前端轮询。

    跟 BUSINESS RT 长跑用的 acquire_rt_via_drission 完全一套, 区别只是 email
    adapter 包装的是 OutlookMailbox。命中 /add-phone 时用注入的 smsbower 配置自动过。
    """
    from platforms.chatgpt.drission_rt_acquirer import acquire_rt_via_drission
    from platforms.chatgpt.gpt_pro_login import (
        build_mailbox_for_account,
        GptProEmailAdapterForCodexOAuth,
    )

    def _log(msg: str) -> None:
        _invite_task_log(task_id, str(msg))

    try:
        required_managed_operation_token = str(
            expected_managed_operation_token or ""
        ).strip()
        if (
            required_managed_operation_token
            and not _gpt_pro_account_operation_token_is_current(
                int(account_id), required_managed_operation_token,
            )
        ):
            raise RuntimeError("BUSINESS 子号凭证修复租约已失效")
        with Session(engine) as session:
            acc = (
                _assert_managed_business_oauth_owner(
                    session,
                    account_id,
                    int(expected_managed_business_parent_id),
                    require_remote_member=True,
                    lock_for_update=True,
                )
                if expected_managed_business_parent_id is not None
                else _assert_business_rotation_oauth_owner(
                    session,
                    account_id,
                    int(expected_business_parent_id),
                    expected_operation_id,
                    expected_task_id=task_id,
                    lock_for_update=True,
                )
                if expected_business_parent_id is not None
                else session.get(GptProAccountModel, account_id)
            )
            if not acc:
                _invite_task_finish(task_id, error="账号不存在")
                return
            snapshot = {
                "email": acc.email,
                "password": acc.password or "",
                "client_id": acc.client_id or "",
                "refresh_token": acc.refresh_token or "",
                "mail_access_type": acc.mail_access_type or "",
                "mail_provider": _mail_provider_of(acc),
            }

        proxy = _resolve_action_proxy(body)
        _log(f"OAuth 启动: {snapshot['email']} (proxy={'有' if proxy else '无'})")

        # 注入 add_phone 阶段所需的 phone/SMS 全局配置(smsbower 等)。
        # 不注入的话, /add-phone 命中时 _handle_add_phone_via_smsbower 读不到
        # smsbower_api_key, 老号会直接抛 "smsbower 未配置" 失败。
        # 与 platforms/chatgpt/plugin.py 的 _action_acquire_rt 注入逻辑保持一致。
        extra_config: dict[str, Any] = {}
        try:
            from core.config_store import config_store as _cs
            all_cfg = _cs.get_all() or {}
            for key, val in all_cfg.items():
                sk = str(key)
                if (sk.startswith("smstome_")
                        or sk.startswith("smsbower_")
                        or sk.startswith("chatgpt_add_phone_")
                        or sk.startswith("chatgpt_phone_")
                        or sk in ("openai_phone_number", "phone_number")):
                    extra_config[sk] = val
            if (not extra_config.get("chatgpt_phone_number")
                    and extra_config.get("chatgpt_add_phone_number")):
                extra_config["chatgpt_phone_number"] = extra_config["chatgpt_add_phone_number"]
        except Exception as exc:
            _log(f"⚠ 加载 phone/SMS 全局配置失败, add_phone 阶段可能无法自动过: {exc}")

        if extra_config.get("smsbower_api_key"):
            _log(
                "已注入 smsbower 配置 "
                f"(countries={extra_config.get('smsbower_countries') or extra_config.get('smsbower_country') or '默认轮换'}, "
                f"service={extra_config.get('smsbower_service') or 'dr'})"
            )
        else:
            _log("⚠ 未配置 smsbower_api_key, 若命中 /add-phone 将无法自动过手机验证")

        try:
            from services.chatgpt_security_store import get_chatgpt_security_status

            oauth_security = get_chatgpt_security_status(snapshot["email"])
        except Exception:
            raise RuntimeError(
                "账号安全状态读取失败，已停止 OAuth 登录"
            ) from None
        oauth_mfa_state = str(
            oauth_security.get("mfa_state") or ""
        ).strip().lower()
        oauth_managed_mfa = bool(oauth_security.get("has_totp")) or (
            oauth_mfa_state in {"pending", "enabled", "unmanaged"}
        )
        if oauth_managed_mfa:
            _log(
                "检测到 Authenticator 2FA：使用 ChatGPT 密码 + 动态码，"
                "仅在页面追加邮箱验证时读取新验证码"
            )
        email_adapter = None
        try:
            mailbox, mb_account = build_mailbox_for_account(snapshot, proxy=proxy)
            email_adapter = GptProEmailAdapterForCodexOAuth(
                mailbox,
                mb_account,
                log_fn=_log,
            )
        except Exception as exc:
            if not oauth_managed_mfa:
                raise RuntimeError(
                    f"邮箱适配器准备失败（{type(exc).__name__}），无法继续邮箱验证码登录"
                ) from None
            _log(
                f"⚠ 邮箱适配器准备失败（{type(exc).__name__}）；"
                "继续密码 + Authenticator，若页面追加邮箱验证将明确停止"
            )

        try:
            tokens = acquire_rt_via_drission(
                email=snapshot["email"],
                password=snapshot["password"],
                proxy=proxy or "",
                extra_config=extra_config,
                log_fn=_log,
                email_adapter=email_adapter,
                headless=True,
            )
        except Exception as exc:
            _log(f"✗ OAuth 失败: {exc}")
            if expected_business_parent_id is not None:
                _record_business_rotation_oauth_terminal(
                    account_id,
                    int(expected_business_parent_id),
                    expected_operation_id,
                    task_id,
                    "failed",
                )
            _invite_task_finish(task_id, error=str(exc), result={"stage": "oauth_failed"})
            return

        rt = str(tokens.get("refresh_token") or "").strip()
        at = str(tokens.get("access_token") or "").strip()
        idt = str(tokens.get("id_token") or "").strip()
        sess = str(tokens.get("session_token") or "").strip()

        if not rt:
            _log("✗ 流程跑完但没拿到 refresh_token")
            if expected_business_parent_id is not None:
                _record_business_rotation_oauth_terminal(
                    account_id,
                    int(expected_business_parent_id),
                    expected_operation_id,
                    task_id,
                    "failed",
                )
            _invite_task_finish(
                task_id,
                error="OAuth 流程跑完但没拿到 refresh_token",
                result={"stage": "no_refresh_token"},
            )
            return

        with Session(engine) as session:
            if (
                required_managed_operation_token
                and not _gpt_pro_account_operation_token_is_current(
                    int(account_id), required_managed_operation_token,
                )
            ):
                raise RuntimeError("BUSINESS 子号凭证修复租约已失效")
            acc = (
                _assert_managed_business_oauth_owner(
                    session,
                    account_id,
                    int(expected_managed_business_parent_id),
                    require_remote_member=True,
                    lock_for_update=True,
                )
                if expected_managed_business_parent_id is not None
                else _assert_business_rotation_oauth_owner(
                    session,
                    account_id,
                    int(expected_business_parent_id),
                    expected_operation_id,
                    expected_task_id=task_id,
                    lock_for_update=True,
                )
                if expected_business_parent_id is not None
                else session.get(GptProAccountModel, account_id)
            )
            if acc:
                completed_at = _utcnow()
                if expected_business_parent_id is not None:
                    extra = _extra_of(acc)
                    extra["business_rotation_oauth_completed_at"] = completed_at.isoformat()
                    extra["business_rotation_oauth_status"] = "done"
                    extra["business_rotation_oauth_finished_at"] = completed_at.isoformat()
                    extra.pop("business_rotation_oauth_lease_expires_at", None)
                    observed_extra_json = acc.extra_json
                    written = session.exec(
                        sa_update(GptProAccountModel)
                        .where(GptProAccountModel.id == int(account_id))
                        .where(GptProAccountModel.extra_json == observed_extra_json)
                        .where(
                            GptProAccountModel.business_parent_id
                            == int(expected_business_parent_id)
                        )
                        .where(GptProAccountModel.enabled == True)  # noqa: E712
                        .where(GptProAccountModel.dangerous == False)  # noqa: E712
                        .where(func.coalesce(GptProAccountModel.refund_status, "") == "")
                        .values(
                            codex_access_token=at,
                            codex_refresh_token=rt,
                            codex_id_token=idt,
                            codex_session_token=sess,
                            codex_rt_acquired_at=completed_at,
                            extra_json=json.dumps(extra, ensure_ascii=False),
                            updated_at=completed_at,
                        )
                    )
                    if int(getattr(written, "rowcount", 0) or 0) != 1:
                        session.rollback()
                        raise RuntimeError("OAuth 任务写回时已被新任务接管")
                else:
                    acc.codex_access_token = at
                    acc.codex_refresh_token = rt
                    acc.codex_id_token = idt
                    acc.codex_session_token = sess
                    acc.codex_rt_acquired_at = completed_at
                    acc.updated_at = completed_at
                    session.add(acc)
                session.commit()

        _log(f"✓ OAuth 成功: RT {len(rt)} 字符 / AT {len(at)} 字符")
        _invite_task_finish(task_id, result={
            "stage": "done",
            "codex_refresh_token_len": len(rt),
            "codex_access_token_len": len(at),
            "codex_id_token_len": len(idt),
            "codex_session_token_len": len(sess),
            "acquired_at": _utcnow().isoformat(),
        })
    except Exception as exc:
        _log(f"✗ 任务异常: {exc}")
        if expected_business_parent_id is not None:
            _record_business_rotation_oauth_terminal(
                account_id,
                int(expected_business_parent_id),
                expected_operation_id,
                task_id,
                "failed",
            )
        _invite_task_finish(task_id, error=str(exc))


def _pro_to_codex_account(acc: GptProAccountModel):
    """把 GptProAccountModel 的 codex_* 字段映射成 duck-typed codex Account 对象,
    给 cpa_upload.generate_token_json / sub2api_upload.build_sub2api_account_payload_from_token_data 用。

    跟 api/chatgpt._to_codex_account (BUSINESS 用) 结构一致, 但字段从 codex_* 而非 extra dict 读。
    """

    class _Acc:
        pass

    a = _Acc()
    a.email = acc.email
    a.access_token = acc.codex_access_token or ""
    a.refresh_token = acc.codex_refresh_token or ""
    a.id_token = acc.codex_id_token or ""
    a.session_token = acc.codex_session_token or ""
    # codex CLI 默认 client_id (跟 BUSINESS 一致)
    a.client_id = "app_EMoamEEZ73f0CkXaXp7hrann"
    a.cookies = ""
    a.user_id = ""
    try:
        a.extra = json.loads(acc.extra_json or "{}")
    except Exception:
        a.extra = {}
    a.subscription_expires_at = acc.pro_expires_at
    return a


def _download_pro_oauth_file(
    account_id: int,
    fmt: str = "cpa",
    *,
    expected_business_parent_id: Optional[int] = None,
    require_refresh_token: bool = False,
):
    """生成 PRO/受管 BUSINESS 子号的 OAuth 授权文件响应。

    fmt:
      - cpa     (默认): {type, access_token, refresh_token}
      - sub2api: 完整 Sub2API 平台导入格式 (含 plan_type/org_id 从 id_token JWT 解析)

    依赖账号已经跑过 /accounts/{id}/oauth 拿到 codex_refresh_token。
    """
    with Session(engine) as session:
        if expected_business_parent_id is None:
            acc = session.get(GptProAccountModel, account_id)
        else:
            try:
                acc = _assert_managed_business_oauth_owner(
                    session,
                    int(account_id),
                    int(expected_business_parent_id),
                    require_remote_member=True,
                )
            except RuntimeError as exc:
                raise HTTPException(409, str(exc)) from exc
        if not acc:
            raise HTTPException(404, "账号不存在")
        if require_refresh_token and not str(acc.codex_refresh_token or "").strip():
            raise HTTPException(400, "子号尚未取得 codex refresh token，无法下载授权文件")
        if not (acc.codex_access_token or acc.codex_refresh_token):
            raise HTTPException(
                400,
                "账号未完成 codex OAuth, 请先点 OAuth 按钮跑 DrissionPage 流程拿 token",
            )

    codex_acc = _pro_to_codex_account(acc)

    from platforms.chatgpt.cpa_upload import generate_token_json
    token_data = generate_token_json(codex_acc)
    # 跟 BUSINESS 路径对齐: token_data 已最小化, 补 id_token / email 让 sub2api 能从 JWT 抽 plan_type
    if not token_data.get("id_token"):
        token_data["id_token"] = codex_acc.id_token or ""
    if not token_data.get("email"):
        token_data["email"] = acc.email
    if acc.pro_expires_at:
        token_data["subscription_expires_at"] = acc.pro_expires_at

    safe_email = re.sub(r"[^a-zA-Z0-9._-]", "_", acc.email)
    fmt_norm = (fmt or "cpa").strip().lower()
    # CPA 与 Sub2API 下载都应可独立生成完整文件。首次下载时为账号
    # 分配代理，后续两种格式复用同一个地址，避免 SUB 必须先下载 CPA。
    assigned_proxy_url = ""
    try:
        from services.cpa_proxy_pool import assign_proxy

        assigned_proxy_url = str(assign_proxy(account_id) or "").strip()
    except Exception:
        pass
    if fmt_norm in ("sub2api", "sub", "sub-2-api"):
        from platforms.chatgpt.sub2api_upload import build_sub2api_bundle_from_token_data
        try:
            output_data = build_sub2api_bundle_from_token_data(
                token_data,
                account=codex_acc,
                proxy_url=assigned_proxy_url or None,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        filename = f"sub2api_{safe_email}.json"
    else:
        # CPA: 最小化 type/access_token/refresh_token(+ 代理池分配的 proxy_url,和上传路径一致)
        output_data = {
            "type": token_data.get("type") or "codex",
            "access_token": token_data.get("access_token") or "",
            "refresh_token": token_data.get("refresh_token") or "",
        }
        # 跟 _upload_account_to_cpa 同源: 分配/复用 CPA 代理池里的一个 IP 写进文件(幂等)。
        # 无可用代理则不写(与上传行为一致)。
        if assigned_proxy_url:
            output_data["proxy_url"] = assigned_proxy_url
        filename = f"oauth_{safe_email}.json"

    body = json.dumps(output_data, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@router.get("/accounts/{account_id}/oauth-file")
def download_pro_oauth_file(account_id: int, fmt: str = "cpa"):
    """下载 GPT PRO 账号的 CPA/Sub2API OAuth 授权文件。"""
    return _download_pro_oauth_file(account_id, fmt)


# ── 浏览器 Session 接口 ─────────────────────────────────────
# 用法:
#   POST /accounts/{id}/browser/open         → 登陆 + 拿 session_id
#   POST /browser/{sid}/navigate {url}        → page.get(url)
#   POST /browser/{sid}/eval {js}             → page.run_js(js) 返回结果
#   GET  /browser/{sid}                       → 当前 url + title + page status
#   GET  /browser/{sid}/snapshot              → DOM 简易快照 (body innerText 前 N 字符)
#   DELETE /browser/{sid}                     → page.quit() 关浏览器
#
# eval 是万能口: 可以 click 元素 / 抓 selector / 填表 / 跑任何 JS。
# Stripe customer portal / OpenAI 设置页 / help.openai.com 上点退款都用 eval。


class BrowserSessionEval(BaseModel):
    js: str          # 完整 JS 代码,返回值会通过 page.run_js 回传 (必须是 JSON-safe)


class BrowserSessionEvalInFrame(BaseModel):
    js: str
    frame_selector: str = "iframe"   # CSS selector 找 iframe; 多个匹配时用 frame_index
    frame_index: int = 0             # 第几个匹配的 frame (0 起)


class BrowserSessionNavigate(BaseModel):
    url: str
    timeout: int = 30  # page.get 超时秒


@router.post("/accounts/{account_id}/browser/open")
def open_browser_session(account_id: int, body: Optional[GptProActionRequest] = None):
    """登陆账号后**保留 page 引用**到全局 session store, 返回 session_id。

    后续可通过 POST/GET/DELETE /browser/{sid}/* 操作这个浏览器。

    跟 /accounts/{id}/login 区别: login 路由跑完就释放 page (Python GC),
    本路由把 page 引用塞进 _BROWSER_SESSIONS, 浏览器全程可控。
    """
    body = body or GptProActionRequest()
    captured: dict = {}

    def _action(page, login_result):
        # post_login_action 钩子: 把 page 引用"漏"到外层 captured
        captured["page"] = page
        return {"ok": True, "captured_page_ref": True}

    login_result = _run_drission_login(account_id, body, post_login_action=_action)
    if not login_result.get("ok"):
        return {"ok": False, "stage": "login_failed", "login": login_result}

    page = captured.get("page")
    if page is None:
        return {"ok": False, "stage": "internal_error", "error": "page 引用丢失"}

    sid = _create_browser_session(account_id, page)
    return {
        "ok": True,
        "session_id": sid,
        "account_id": account_id,
        "current_url": page.url,
        "login": login_result,
    }


@router.get("/browser/{session_id}")
def get_browser_session(session_id: str):
    sess = _get_browser_session(session_id)
    page = sess["page"]
    try:
        url = page.url
    except Exception as exc:
        url = f"<page.url 异常: {exc}>"
    try:
        title = page.title
    except Exception as exc:
        title = f"<page.title 异常: {exc}>"
    return {
        "session_id": session_id,
        "account_id": sess["account_id"],
        "created_at": sess["created_at"],
        "current_url": url,
        "title": title,
    }


@router.post("/browser/{session_id}/navigate")
def navigate_browser_session(session_id: str, body: BrowserSessionNavigate):
    sess = _get_browser_session(session_id)
    page = sess["page"]
    try:
        page.get(body.url, timeout=int(body.timeout or 30))
    except Exception as exc:
        return {"ok": False, "error": f"page.get 异常: {exc}", "current_url": page.url}
    return {"ok": True, "current_url": page.url, "title": page.title}


@router.post("/browser/{session_id}/eval")
def eval_browser_session(session_id: str, body: BrowserSessionEval):
    sess = _get_browser_session(session_id)
    page = sess["page"]
    try:
        result = page.run_js(body.js)
    except Exception as exc:
        return {"ok": False, "error": f"page.run_js 异常: {exc}"}
    return {"ok": True, "result": result, "current_url": page.url}


@router.post("/browser/{session_id}/eval-in-frame")
def eval_browser_session_in_frame(session_id: str, body: BrowserSessionEvalInFrame):
    """跨域 iframe 里跑 JS。DrissionPage 用 CDP 拿 frame, 绕过 same-origin。

    例如 ChatKit / Stripe iframe / Google Maps 等都用这个接口。
    """
    sess = _get_browser_session(session_id)
    page = sess["page"]
    try:
        frames = list(page.get_frames(f"css:{body.frame_selector}"))
    except Exception as exc:
        return {"ok": False, "error": f"page.get_frames 异常: {exc}"}
    if not frames:
        return {"ok": False, "error": f"找不到 iframe: {body.frame_selector!r}"}
    idx = max(0, int(body.frame_index or 0))
    if idx >= len(frames):
        return {"ok": False, "error": f"frame_index {idx} 越界 (共 {len(frames)} 个)"}
    frame = frames[idx]
    try:
        result = frame.run_js(body.js)
    except Exception as exc:
        return {"ok": False, "error": f"frame.run_js 异常: {exc}"}
    return {
        "ok": True,
        "result": result,
        "frame_count": len(frames),
        "frame_index": idx,
    }


@router.get("/browser/{session_id}/snapshot")
def snapshot_browser_session(session_id: str, max_text: int = Query(2000, ge=100, le=20000)):
    """抓当前页可见文本 (body innerText) + 所有可点击元素的简易列表。

    给探索 UI 用 — 看到页面上有什么按钮/链接, 文本是啥, 方便决定 eval 写什么。
    """
    sess = _get_browser_session(session_id)
    page = sess["page"]
    js = """
return (function(maxText){
    function visible(el) {
        if (!el || !el.offsetParent) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    }
    function brief(el) {
        const tag = el.tagName.toLowerCase();
        const text = (el.innerText || el.textContent || '').trim().slice(0, 80);
        const aria = el.getAttribute('aria-label') || '';
        const cls = (el.className || '').toString().slice(0, 60);
        const id = el.id || '';
        const href = el.getAttribute('href') || '';
        return { tag, text, aria, cls, id, href };
    }
    const text = (document.body && document.body.innerText || '').slice(0, maxText);
    const clickables = [];
    const sels = ['button', 'a', '[role="button"]', '[role="link"]', 'input[type="submit"]', 'input[type="button"]'];
    for (const sel of sels) {
        for (const el of document.querySelectorAll(sel)) {
            if (!visible(el)) continue;
            clickables.push(brief(el));
            if (clickables.length >= 60) break;
        }
        if (clickables.length >= 60) break;
    }
    return {
        url: location.href,
        title: document.title,
        text_preview: text,
        text_length: (document.body && document.body.innerText || '').length,
        clickables: clickables,
    };
})(arguments[0] || 2000);
"""
    try:
        result = page.run_js(js, max_text)
    except Exception as exc:
        return {"ok": False, "error": f"snapshot JS 异常: {exc}"}
    return {"ok": True, "snapshot": result}


@router.delete("/browser/{session_id}")
def close_browser_session(session_id: str):
    with _BROWSER_SESSIONS_LOCK:
        sess = _BROWSER_SESSIONS.pop(session_id, None)
    if not sess:
        raise HTTPException(404, f"session {session_id} 不存在")
    page = sess.get("page")
    if page is not None:
        try:
            page.quit()
        except Exception:
            pass
    return {"ok": True, "closed": session_id}


@router.get("/browser")
def list_browser_sessions():
    """列出所有活跃 session, 方便 debug。"""
    with _BROWSER_SESSIONS_LOCK:
        items = [
            {
                "session_id": sid,
                "account_id": s["account_id"],
                "created_at": s["created_at"],
            }
            for sid, s in _BROWSER_SESSIONS.items()
        ]
    return {"total": len(items), "items": items}


# ── 辅助 ─────────────────────────────────────────────────────

_MAIL_ACCESS_TYPE_META = {
    "graph": ("Graph API", "success"),
    "imap_pop": ("IMAP/POP", "warning"),
    "": ("未检测", "default"),
}


def _safe_invited_list(raw: Optional[str]) -> List[str]:
    """parse referral_invited_emails_json to list[str],对脏数据宽容。"""
    try:
        lst = json.loads(raw or "[]")
        if not isinstance(lst, list):
            return []
        return [str(x).strip() for x in lst if str(x or "").strip()]
    except Exception:
        return []


def _serialize(acc: GptProAccountModel) -> Dict[str, Any]:
    mail_type = str(acc.mail_access_type or "").strip()
    mail_label, mail_color = _MAIL_ACCESS_TYPE_META.get(mail_type, ("未知", "default"))

    expires_iso = acc.pro_expires_at.isoformat() if acc.pro_expires_at else ""
    expires_status = ""
    if acc.is_pro and acc.pro_expires_at:
        now = _utcnow()
        if acc.pro_expires_at < now:
            expires_status = "expired"
        else:
            from datetime import timedelta
            if acc.pro_expires_at <= now + timedelta(days=7):
                expires_status = "expiring_soon"
            else:
                expires_status = "valid"

    try:
        pending_alerts = json.loads(acc.pending_alerts_json or "[]")
    except Exception:
        pending_alerts = []
    try:
        pending_inbox = json.loads(acc.pending_inbox_json or "[]")
    except Exception:
        pending_inbox = []
    cpa_status = serialize_gpt_pro_cpa_status(acc)
    sub2api_status = serialize_gpt_pro_sub2api_status(acc)

    return {
        "id": acc.id,
        "email": acc.email,
        "mail_provider": _mail_provider_of(acc),
        "password": acc.password,
        "client_id": acc.client_id or "",
        "refresh_token": acc.refresh_token or "",
        "mail_access_type": mail_type,
        "mail_access_type_label": mail_label,
        "mail_access_type_color": mail_color,
        # has_oauth = 该账号"能否读邮件取 OTP": Outlook 靠 client_id+refresh_token;
        # iCloud 靠全局 QQ + Cookie(不需要账号自身凭证), 故 iCloud 恒为 True。
        "has_oauth": True if _mail_provider_of(acc) == "icloud" else bool(acc.client_id and acc.refresh_token),
        # 邀请积分缓存(查过一次就落库, 前端直接读, 不再实时查)
        "referral_reward": _extra_of(acc).get("referral_reward"),
        # 最近一次申请人工审核(联系客服专员)时间
        "human_review_requested_at": _iso_utc(getattr(acc, "human_review_requested_at", None)),
        # 退款被拒(订阅费用不予退款)时间 / 最近手动退款时间 → 前端算"可再次手动退款"提示
        "refund_rejected_at": _iso_utc(getattr(acc, "refund_rejected_at", None)),
        "refund_manual_at": _iso_utc(getattr(acc, "refund_manual_at", None)),
        # 只暴露 CPA 设备/用量/告警状态，不暴露 extra 中的 API key。
        **cpa_status,
        # Sub2API 同样只暴露稳定 linkage 与经过 allow-list 的额度缓存。
        **sub2api_status,
        "is_pro": bool(acc.is_pro),
        "subscribed_at": _iso_utc(acc.subscribed_at),
        "pro_expires_at": expires_iso,
        "pro_expires_status": expires_status,
        "payment_card_last4": acc.payment_card_last4 or "",
        # 支付成功用的那张卡所属的支付账号(名称 + 类型 Y/E),供追溯
        "payment_account_name": _extra_of(acc).get("payment_account_name") or "",
        "payment_account_type": _extra_of(acc).get("payment_account_type") or "",
        "refund_status": acc.refund_status or "",
        "refund_detected_at": _iso_utc(acc.refund_detected_at),
        "refund_credited_at": _iso_utc(acc.refund_credited_at),
        "dangerous": bool(acc.dangerous),
        "dangerous_detected_at": acc.dangerous_detected_at.isoformat() if acc.dangerous_detected_at else "",
        "appeal_url": getattr(acc, "appeal_url", "") or "",
        "appeal_done_at": _iso_utc(getattr(acc, "appeal_done_at", None)),
        "has_cookie": bool((getattr(acc, "cookie_blob", "") or "").strip()),
        "cookie_updated_at": _iso_utc(getattr(acc, "cookie_updated_at", None)),
        "cookie_expires_at": _iso_utc(getattr(acc, "cookie_expires_at", None)),
        "cookie_valid": bool(getattr(acc, "cookie_expires_at", None)
                             and _aware(acc.cookie_expires_at) > _utcnow()),
        "policy_warning": bool(acc.policy_warning),
        "policy_warning_detected_at": acc.policy_warning_detected_at.isoformat() if acc.policy_warning_detected_at else "",
        # codex OAuth (DrissionPage acquire_rt_via_drission 拿到的); 不暴露完整 token
        "has_codex_rt": bool(acc.codex_refresh_token),
        "codex_refresh_token_len": len(acc.codex_refresh_token or ""),
        "codex_rt_acquired_at": acc.codex_rt_acquired_at.isoformat() if acc.codex_rt_acquired_at else "",
        # 推荐邀请额度缓存(每次查询/邀请后会更新)。NULL → 未查询过
        "referral_remaining": acc.referral_remaining if acc.referral_remaining is not None else None,
        "referral_quota_checked_at": acc.referral_quota_checked_at.isoformat() if acc.referral_quota_checked_at else "",
        "referral_invited_emails": _safe_invited_list(acc.referral_invited_emails_json),
        "referral_confirmed_emails": _safe_invited_list(acc.referral_confirmed_emails_json),
        "note": acc.note or "",
        "enabled": acc.enabled,
        "unread_count": len(pending_alerts),
        "inbox_unread_count": len(pending_inbox),
        "last_mail_check_at": acc.last_mail_check_at.isoformat() if acc.last_mail_check_at else "",
        "last_mail_check_error": acc.last_mail_check_error or "",
        "created_at": acc.created_at.isoformat() if acc.created_at else "",
        "updated_at": acc.updated_at.isoformat() if acc.updated_at else "",
        "last_used": acc.last_used.isoformat() if acc.last_used else "",
    }
