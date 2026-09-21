"""GPT PRO / BUSINESS 池选子号邮件健康监控。

每 5 分钟(由 core.scheduler 触发)扫描启用的 GPT PRO 账号，以及当前已归属
BUSINESS 母号的受管子号。BUSINESS 子号只处理封禁、
政策告警和收件箱健康，不执行 GPT PRO 订阅退款状态语义。

监控通过 Graph / IMAP 取最近邮件,与上次见过的 message id 对比,
新增邮件写入 `pending_alerts_json`(前端 Badge 提醒),并更新 `seen_mail_ids_json`。

设计:
- 第一次扫描某账号时把现有邮件全部视为「已见」,避免历史邮件一次性涌入 alert;
- 每个账号独立 try/except,任一账号异常不影响其他账号;
- 串行执行 + 单账号短超时,N=100 账号最多约 200s 完成(在 5min 窗口内)。
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import threading
import time
from typing import Any, Dict, List

from sqlmodel import Session, select

from core.db import engine, GptProAccountModel


MAX_SEEN_IDS = 100               # 每账号保留的 seen id 上限
MAX_ALERTS_PER_ACCOUNT = 20      # 单账号 pending_alerts 累积上限
MAX_INBOX_PER_ACCOUNT = 100      # 单账号 pending_inbox 累积上限 (所有新邮件,不止白名单)
MAX_FETCH_PER_ROUND = 15         # 每轮每账号拉取邮件数
MONITOR_INTERVAL_SECONDS = 300   # 5 分钟

# 铃铛白名单: 只有 subject 含这些关键字的新邮件才推到 pending_alerts (触发前端 Badge)。
# 其他普通新邮件继续 marks seen 但不打扰用户。
# Access Deactivated 邮件还会顺手把账号标 dangerous=True (账号被 OpenAI 封禁/受限)。
# 封号(账号已停用)主题关键词 — 中英双语(OpenAI 2026 起对中文用户发中文封号邮件,
# 主题如 "OpenAI - 访问权限已停用 [C-xxxx]")。
DANGEROUS_SUBJECT_KEYWORDS = ("Access Deactivated", "访问权限已停用")
# 政策告警(封号前警告)主题关键词 — 中英双语。
POLICY_WARNING_SUBJECT_KEYWORDS = (
    "Usage Policy Violation", "Deactivation Warning", "使用政策", "停用警告",
)
BELL_SUBJECT_KEYWORDS = DANGEROUS_SUBJECT_KEYWORDS

# 退款邮件主题模式 — 这些不进 pending_inbox 也不进 pending_alerts,
# 它们已被 refund_status 字段 + 专属 Tag 表达,避免重复打扰。
REFUND_SUBJECT_PATTERNS = (
    "Your refund from OpenAI",        # 老版
    "OpenAI OpCo, LLC refund",        # 新版(按法律主体起的标题,2026 起出现)
)

# 客服"拒绝退款"回复正文话术(命中 → 提示"可再次手动退款")。
# 实测: "…ChatGPT 订阅费用不予退款…" / 英文 non-refundable / "无法批准这笔费用的退款"。
# 注意: AI 的"无法通过这次支持对话处理此退款请求 / 重复工单"不算拒绝, 不匹配。
_REFUND_REJECT_RE = re.compile(
    r"订阅费用不予退款|订阅费用不可退款|订阅.{0,4}不予退款|无法批准.{0,8}退款|"
    r"不予退款|subscription.{0,20}non-refundable|payments are non-refundable|"
    r"unable to (issue|provide|approve).{0,24}refund",
    re.I,
)


_monitor_lock = threading.Lock()  # 防止重叠执行


def is_managed_business_child(account: GptProAccountModel) -> bool:
    """这个 GPT PRO 池记录是否当前归属某个 BUSINESS 母号。"""
    return getattr(account, "business_parent_id", None) is not None


def is_business_child_mail_health_account(account: GptProAccountModel) -> bool:
    """Only an active BUSINESS child uses non-PRO mail semantics."""
    return is_managed_business_child(account)


def business_child_mail_monitor_enabled(account: GptProAccountModel) -> bool:
    """BUSINESS 池选子号的邮件健康监控开关。

    旧数据没有 ``business_child_monitor_enabled`` 时默认开启；只有显式
    写入 false / 0 / off 才停止定时监控。普通 GPT PRO 账号不受此开关影响。
    """
    if not is_business_child_mail_health_account(account):
        return False
    extra = _safe_json_loads(getattr(account, "extra_json", ""), {})
    value = extra.get("business_child_monitor_enabled", True)
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off", "")
    return bool(value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_msg_time(val) -> "datetime | None":
    """把邮件的 time 字段(通常 ISO)解析成 tz-aware datetime。失败返回 None。"""
    s = str(val or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(s)
            return dt if (dt and dt.tzinfo) else (dt.replace(tzinfo=timezone.utc) if dt else None)
        except Exception:
            return None


def _aware(dt) -> "datetime | None":
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _safe_json_loads(text: str, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _fetch_recent(account: GptProAccountModel) -> List[Dict[str, Any]]:
    """按 provider 分发取件(outlook / icloud), 返回标准化 message list。"""
    from api.gpt_pro import _fetch_recent_for_account
    return _fetch_recent_for_account(account, MAX_FETCH_PER_ROUND)


def _make_alert(msg: Dict[str, Any]) -> Dict[str, Any]:
    """从邮件 dict 中抽出 alert 元数据(不存正文,正文在 fetch-mail 时获取)。"""
    return {
        "id": str(msg.get("id") or ""),
        "from": str(msg.get("from") or ""),
        "subject": str(msg.get("subject") or ""),
        "preview": str(msg.get("preview") or "")[:300],
        "time": str(msg.get("time") or ""),
        "folder": str(msg.get("folder") or ""),
        "is_html": bool(msg.get("is_html")),
        "detected_at": _utcnow().isoformat(),
    }


def _process_account(account: GptProAccountModel) -> Dict[str, Any]:
    """对单个账号执行一轮监控(取件 + 处理),返回该账号本轮的统计。"""
    messages = _fetch_recent(account)
    return _process_messages(account, messages)


def _process_messages(account: GptProAccountModel, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """对**给定**邮件列表做检测(封号/退款/告警)+ 更新 inbox/alert/seen。不取件。

    供两条路径复用: 单账号(_process_account 先取件再调) 与 iCloud 批量(一次取件、分发后调)。
    """
    seen_ids: List[str] = _safe_json_loads(account.seen_mail_ids_json, [])
    seen_set = set(seen_ids)
    pending: List[Dict[str, Any]] = _safe_json_loads(account.pending_alerts_json, [])
    inbox: List[Dict[str, Any]] = _safe_json_loads(account.pending_inbox_json, [])
    # Released historical children continue health monitoring while waiting
    # for reuse.  They remain non-PRO for mail semantics, so refund messages
    # must never mutate the GPT PRO refund state machine.
    business_child = is_business_child_mail_health_account(account)

    fresh_ids = [str(m.get("id") or "") for m in messages if m.get("id")]

    # 退款邮件检测: subject 命中任一已知退款模板 → 标记退款已到账
    # 不受 first_scan 限制, 历史邮件也算 (避免漏检账号导入时已存在的退款邮件)
    # 注意: 不进 pending_alerts 也不进 pending_inbox
    # (退款由 refund_status 字段 + 专属 Tag 体现, 不重复打扰)
    # OpenAI 会偶尔改邮件模板,新格式追加到上面 REFUND_SUBJECT_PATTERNS 即可。
    if not business_child and account.refund_status != "refunded_pending_credit":
        sub_at = _aware(account.subscribed_at)
        for msg in messages:
            subj = str(msg.get("subject") or "")
            if any(pat in subj for pat in REFUND_SUBJECT_PATTERNS):
                # 只在退款邮件比「最近一次订阅」更新时才标记退款。
                # 否则是旧退款(账号已重新订阅/被手动恢复), 不再翻旧账重复标记
                # ——修复「恢复普通后过一会又被扫回已退款」的根因。
                r_time = _parse_msg_time(msg.get("time"))
                if sub_at and r_time and r_time <= sub_at:
                    continue
                account.refund_status = "refunded_pending_credit"
                account.refund_detected_at = _utcnow()
                break

    # 退款被拒检测(放宽): 只要**没有退款邮件**, 且邮箱里有 support@openai.com 发来的邮件
    # (或命中"订阅费用不予退款"话术)→ 视为客服已拒, 取**最新**一封该类邮件时间记 refund_rejected_at。
    # 已退款/已到账的号不检测。比现有值更新才更新(手动退款后又来新的 support 回复 → 重新点亮"可再手动退款")。
    # 与退款检测同一套逻辑: 只认「订阅时间之后」的 support 邮件 —— 号重新订阅过后, 旧周期的拒绝不再算,
    # 且若现有 refund_rejected_at 比最新订阅还早(旧周期遗留), 清空它。
    if not business_child and account.refund_status not in ("refunded_pending_credit", "refund_credited"):
        sub_at = _aware(account.subscribed_at)
        # 只有「订阅之后」的退款邮件才算"已退款"、才短路拒绝检测。
        # 否则旧周期(重新订阅前)的退款邮件会挡住当前周期新来的"不予退款", 导致标不上"客服已拒"。
        has_refund_mail = False
        for m in messages:
            if any(pat in str(m.get("subject") or "") for pat in REFUND_SUBJECT_PATTERNS):
                rt = _parse_msg_time(m.get("time"))
                if sub_at is None or (rt is not None and rt > sub_at):
                    has_refund_mail = True
                    break
        newest_reject = None
        if not has_refund_mail:
            for msg in messages:
                frm = str(msg.get("from") or "").lower()
                # iCloud 转发会把 @ 变成 _at_(support_at_openai_com), 两种都认
                is_support = ("support@openai.com" in frm) or ("support_at_openai_com" in frm)
                blob = str(msg.get("subject") or "") + "\n" + str(msg.get("body") or msg.get("preview") or "")
                if is_support or _REFUND_REJECT_RE.search(blob):
                    rt = _parse_msg_time(msg.get("time")) or _utcnow()
                    if sub_at and rt <= sub_at:      # 订阅之前的旧拒绝, 跳过
                        continue
                    if newest_reject is None or rt > newest_reject:
                        newest_reject = rt
        # 清掉比最新订阅还早的旧周期遗留拒绝标记
        cur_rej = _aware(account.refund_rejected_at)
        if cur_rej is not None and sub_at is not None and cur_rej <= sub_at:
            account.refund_rejected_at = None
            cur_rej = None
        if newest_reject is not None:
            cur = cur_rej
            if cur is None or newest_reject > cur:
                account.refund_rejected_at = newest_reject

    # 危险账号检测: subject 命中封号关键词(中英)→ dangerous=True
    # 跟退款一样不受 first_scan 限制。命中停用邮件时顺手提取"提出申诉"链接。
    # 条件放宽: 只要"还没标危险" 或 "已危险但没申诉链接" 都扫一遍(后者用于自动补链接)。
    if (not account.dangerous) or not (getattr(account, "appeal_url", "") or "").strip():
        for msg in messages:
            subj = str(msg.get("subject") or "")
            if any(kw in subj for kw in DANGEROUS_SUBJECT_KEYWORDS):
                if not account.dangerous:
                    account.dangerous = True
                    account.dangerous_detected_at = _utcnow()
                # 提取申诉链接(标危险当场提取;已危险但缺链接也补)
                if not (getattr(account, "appeal_url", "") or "").strip():
                    try:
                        from api.gpt_pro import _extract_appeal_url
                        _url = _extract_appeal_url(str(msg.get("body") or ""), bool(msg.get("is_html")))
                        if _url:
                            account.appeal_url = _url
                    except Exception:
                        pass
                break

    # 政策告警检测: subject 命中政策告警关键词(中英)→ policy_warning=True
    # (封禁前的警告;同样不受 first_scan 限制)
    if not account.policy_warning:
        for msg in messages:
            subj = str(msg.get("subject") or "")
            if any(kw in subj for kw in POLICY_WARNING_SUBJECT_KEYWORDS):
                account.policy_warning = True
                account.policy_warning_detected_at = _utcnow()
                break

    # 首次扫描：普通 PRO 建立全量基线；BUSINESS 子号只把邀请前邮件归入基线。
    first_scan = not seen_ids
    new_alerts: List[Dict[str, Any]] = []
    new_inbox: List[Dict[str, Any]] = []
    new_messages: List[Dict[str, Any]] = []
    if not first_scan:
        new_messages = [
            msg for msg in messages
            if str(msg.get("id") or "")
            and str(msg.get("id") or "") not in seen_set
        ]
    elif business_child:
        # A regular pool row is usually first monitored only after a confirmed
        # BUSINESS invitation.  Baseline mail older than that invitation, but
        # preserve post-invite mail (especially the workspace invite) as new.
        invited_at = _aware(getattr(account, "business_invited_at", None))
        if invited_at is not None:
            for msg in messages:
                message_at = _parse_msg_time(msg.get("time"))
                if (
                    str(msg.get("id") or "")
                    and message_at is not None
                    and message_at > invited_at
                ):
                    new_messages.append(msg)

    for msg in new_messages:
        subj = str(msg.get("subject") or "")
        # GPT PRO 退款邮件走 refund_status 通道；BUSINESS 子号不能触发
        # PRO 退款语义，因此把这类邮件当普通收件箱消息保留。
        if (not business_child
                and any(pat in subj for pat in REFUND_SUBJECT_PATTERNS)):
            continue
        alert = _make_alert(msg)
        # 铃铛: 仅白名单命中 (封禁报警专用)
        if any(kw in subj for kw in BELL_SUBJECT_KEYWORDS):
            new_alerts.append(alert)
        # 收件箱: 所有其他新邮件 (封禁邮件也算 — 让两个通道都能看到)
        new_inbox.append(alert)

    if new_alerts:
        existing_keys = {a.get("id") for a in pending if a.get("id")}
        for alert in new_alerts:
            if alert.get("id") not in existing_keys:
                pending.insert(0, alert)
                existing_keys.add(alert.get("id"))
        if len(pending) > MAX_ALERTS_PER_ACCOUNT:
            pending = pending[:MAX_ALERTS_PER_ACCOUNT]

    if new_inbox:
        existing_inbox_keys = {a.get("id") for a in inbox if a.get("id")}
        for alert in new_inbox:
            if alert.get("id") not in existing_inbox_keys:
                inbox.insert(0, alert)
                existing_inbox_keys.add(alert.get("id"))
        if len(inbox) > MAX_INBOX_PER_ACCOUNT:
            inbox = inbox[:MAX_INBOX_PER_ACCOUNT]

    # 更新 seen: 把本轮 id 全部并入,保留最近 MAX_SEEN_IDS 个
    merged_seen = list(dict.fromkeys(fresh_ids + seen_ids))[:MAX_SEEN_IDS]

    account.seen_mail_ids_json = json.dumps(merged_seen, ensure_ascii=False)
    account.pending_alerts_json = json.dumps(pending, ensure_ascii=False)
    account.pending_inbox_json = json.dumps(inbox, ensure_ascii=False)
    account.last_mail_check_at = _utcnow()
    account.last_mail_check_error = ""

    return {
        "email": account.email,
        "fetched": len(messages),
        "new_alerts": len(new_alerts),
        "new_inbox": len(new_inbox),
        "first_scan": first_scan,
        "pending_total": len(pending),
        "inbox_total": len(inbox),
    }


def _is_icloud(account: GptProAccountModel) -> bool:
    try:
        extra = json.loads(account.extra_json) if account.extra_json else {}
    except Exception:
        extra = {}
    return str((extra or {}).get("mail_provider") or "").strip().lower() in ("icloud", "qqmail")


_HME_LAST_UID_KEY = "qqmail_hme_last_uid"


def run_icloud_batch_round(accounts: List[GptProAccountModel], session) -> Dict[str, Any]:
    """iCloud 账号批量监控: QQ 收件箱**一轮只连一次**、UID 增量拉取, 本地按别名分发处理。

    accounts: 本轮要处理的 iCloud 账号(已 is_pro+enabled 过滤)。
    """
    from core.config_store import config_store
    from core.base_mailbox import create_mailbox

    result = {"icloud_scanned": len(accounts), "icloud_new": 0, "fetched": 0}
    if not accounts:
        return result

    # 别名 → [账号]
    alias_map: Dict[str, List[GptProAccountModel]] = {}
    for a in accounts:
        alias_map.setdefault(str(a.email or "").strip().lower(), []).append(a)

    cfg = dict(config_store.get_all() or {})
    cfg["qqmail_use_tracker"] = False
    mailbox = create_mailbox(provider="qqmail", extra=cfg, proxy=None)

    # UID 水位按收件来源分别存: QQ 和 iCloud IMAP 是不同服务器/不同 UID 空间,
    # 混用会导致「UID > 上个源的大水位」永远搜不到新邮件(定时监控收不到新邮件的根因)。
    via = str(config_store.get("icloud_receive_via", "qqmail") or "qqmail").strip().lower()
    uid_key = _HME_LAST_UID_KEY if via == "qqmail" else f"{_HME_LAST_UID_KEY}_{via}"
    try:
        last_uid = int(str(config_store.get(uid_key, "0") or "0") or "0")
    except Exception:
        last_uid = 0

    messages, max_uid = mailbox.list_recent_batch(last_uid=last_uid, max_fetch=300)
    result["fetched"] = len(messages)

    # 按别名分组新邮件
    by_alias: Dict[str, List[Dict[str, Any]]] = {}
    for m in messages:
        for r in (m.get("recipients") or []):
            if r in alias_map:
                by_alias.setdefault(r, []).append(m)

    now = _utcnow()
    for alias, accs in alias_map.items():
        msgs = by_alias.get(alias) or []
        for acc in accs:
            if msgs:
                try:
                    detail = _process_messages(acc, msgs)
                    result["icloud_new"] += detail.get("new_inbox", 0)
                except Exception as exc:
                    acc.last_mail_check_error = f"{exc}"[:300]
            else:
                # 无新邮件也刷新"最近检查"时间, 界面显示准确
                acc.last_mail_check_at = now
                acc.last_mail_check_error = ""
            session.add(acc)
    session.commit()

    # 推进水位(按来源各存各的)
    if max_uid and max_uid > last_uid:
        config_store.set(uid_key, str(max_uid))
    return result


def run_monitor_round(*, account_id: int | None = None) -> Dict[str, Any]:
    """执行一轮监控。

    - account_id 为 None: 扫描 enabled PRO，以及当前活动 BUSINESS 池选子号
    - account_id 指定: 只扫描该账号(用于「立即检查」按钮)
    """
    if not _monitor_lock.acquire(blocking=False):
        return {"skipped": True, "reason": "上一轮尚未结束"}

    started_at = time.time()
    summary: Dict[str, Any] = {
        "started_at": _utcnow().isoformat(),
        "scanned": 0,
        "success": 0,
        "failed": 0,
        "total_new_alerts": 0,
        "details": [],
        "errors": [],
    }

    try:
        with Session(engine) as session:
            query = select(GptProAccountModel)
            if account_id is not None:
                query = query.where(GptProAccountModel.id == account_id)
            else:
                query = query.where(GptProAccountModel.enabled == True)  # noqa: E712
            accounts = session.exec(query).all()
            if account_id is None:
                accounts = [
                    account for account in accounts
                    if (
                        business_child_mail_monitor_enabled(account)
                        if is_business_child_mail_health_account(account)
                        else bool(account.is_pro)
                    )
                ]

            # 全量轮: iCloud 走批量(QQ 一轮一次连接), Outlook 走逐账号。
            # 单账号(account_id 指定, 如"立即检查")一律走逐账号(定向拉自己别名的历史)。
            per_account = accounts
            if account_id is None:
                icloud_accs = [a for a in accounts if _is_icloud(a)]
                per_account = [a for a in accounts if not _is_icloud(a)]
                if icloud_accs:
                    try:
                        r = run_icloud_batch_round(icloud_accs, session)
                        summary["scanned"] += r["icloud_scanned"]
                        summary["success"] += r["icloud_scanned"]
                        summary["icloud_batch"] = r
                    except Exception as exc:
                        summary["errors"].append({"email": "icloud-batch", "error": str(exc)})
                        summary["failed"] += len(icloud_accs)

            for account in per_account:
                summary["scanned"] += 1
                try:
                    detail = _process_account(account)
                    session.add(account)
                    session.commit()
                    summary["success"] += 1
                    summary["total_new_alerts"] += detail["new_alerts"]
                    summary["details"].append(detail)
                except Exception as exc:
                    session.rollback()
                    try:
                        # 写入错误状态,但不阻塞其他账号
                        fresh = session.get(GptProAccountModel, account.id)
                        if fresh:
                            fresh.last_mail_check_at = _utcnow()
                            fresh.last_mail_check_error = f"{exc}"[:300]
                            session.add(fresh)
                            session.commit()
                    except Exception:
                        session.rollback()
                    summary["failed"] += 1
                    summary["errors"].append({"email": account.email, "error": str(exc)})
    finally:
        _monitor_lock.release()

    summary["duration_seconds"] = round(time.time() - started_at, 2)
    return summary
