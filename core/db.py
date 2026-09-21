"""数据库模型 - SQLite via SQLModel"""
from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select
from sqlalchemy import Index, event, text
import json
from core.business_invite_policy import BUSINESS_INVITE_WINDOW_HOURS


def _utcnow():
    return datetime.now(timezone.utc)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///account_manager.db")


def _sqlite_connect_args() -> dict:
    if not DATABASE_URL.startswith("sqlite"):
        return {}
    try:
        timeout = float(os.getenv("SQLITE_BUSY_TIMEOUT", "30"))
    except Exception:
        timeout = 30.0
    return {
        # 多线程 runner / FastAPI 线程池会共享同一个 SQLAlchemy Engine。
        # SQLite 默认 5s busy timeout 在 BUSINESS RT 高并发写入时太短,
        # 容易让只读接口偶发 database is locked。
        "timeout": max(1.0, timeout),
        "check_same_thread": False,
    }


engine = create_engine(DATABASE_URL, connect_args=_sqlite_connect_args())


if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
            except Exception:
                # 某些 sqlite URL（如 :memory: / 只读连接）不支持 WAL。
                pass
            try:
                busy_ms = int(float(os.getenv("SQLITE_BUSY_TIMEOUT", "30")) * 1000)
            except Exception:
                busy_ms = 30000
            cursor.execute(f"PRAGMA busy_timeout={max(1000, busy_ms)}")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


class AccountModel(SQLModel, table=True):
    __tablename__ = "accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    platform: str = Field(index=True)
    email: str = Field(index=True)
    password: str
    user_id: str = ""
    region: str = ""
    token: str = ""
    status: str = "registered"
    trial_end_time: int = 0
    cashier_url: str = ""
    extra_json: str = "{}"   # JSON 存储平台自定义字段
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    @property
    def extra(self) -> dict:
        return json.loads(self.extra_json or "{}")

    def get_extra(self) -> dict:
        return json.loads(self.extra_json or "{}")

    def set_extra(self, d: dict):
        self.extra_json = json.dumps(d, ensure_ascii=False)


class ChatGptAccountSecurityModel(SQLModel, table=True):
    """Encrypted ChatGPT login material, isolated from public account DTOs.

    ``email`` is always the normalized (trimmed, case-folded) address.  The
    service layer is the only writer and is responsible for enforcing that
    invariant.  Ciphertext columns contain versioned AES-GCM envelopes, never
    plaintext credentials.

    This table deliberately does not mirror or backfill ``AccountModel.password``.
    That legacy column has platform-dependent semantics and remains untouched;
    post-registration ChatGPT security setup must opt in to this store.
    """

    __tablename__ = "chatgpt_account_security"

    email: str = Field(primary_key=True, max_length=320)
    password_ciphertext: str = ""
    totp_secret_ciphertext: str = ""
    recovery_codes_ciphertext: str = ""
    password_state: str = "not_configured"
    mfa_state: str = "not_configured"
    last_error: str = ""
    password_updated_at: Optional[datetime] = None
    mfa_updated_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class ChatGptSecurityOperationLeaseModel(SQLModel, table=True):
    """Cross-process fence for one ChatGPT account security mutation.

    The normalized email is the sole resource key.  ``owner_token`` is an
    opaque fencing value: an expired owner must not be able to release a lease
    that has subsequently been claimed by another worker.
    """

    __tablename__ = "chatgpt_security_operation_leases"

    email: str = Field(primary_key=True, max_length=320)
    owner_token: str = Field(index=True, max_length=128)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class TaskLog(SQLModel, table=True):
    __tablename__ = "task_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    platform: str
    email: str
    status: str        # success | failed
    error: str = ""
    detail_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)


class OutlookAccountModel(SQLModel, table=True):
    __tablename__ = "outlook_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str
    client_id: str = ""
    refresh_token: str = ""
    mail_access_type: str = ""          # graph | imap_pop | ""
    gpt_register_status: str = "未注册"  # 未注册 | 进行中 | 已注册
    grok_register_status: str = "未注册" # 未注册 | 进行中 | 已注册
    trae_register_status: str = "未注册"
    kiro_register_status: str = "未注册"
    obl_register_status: str = "未注册"  # OpenBlockLabs
    cursor_register_status: str = "未注册"
    adobe_register_status: str = "未注册"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class GptProAccountModel(SQLModel, table=True):
    """GPT PRO 账号池（导入格式与 Outlook 邮箱一致）。

    与 outlook_accounts 完全独立:这里存储的是已经购买了 GPT PRO 订阅
    (或将被标记为 PRO)的账号,不参与普通注册流水。
    """
    __tablename__ = "gpt_pro_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    mail_access_type: str = ""          # graph | imap_pop | ""

    is_pro: bool = False                 # 是否已成功订阅 PRO (订阅成功后置 True, 决定是否隐藏「升级 PRO」按钮)
    pro_expires_at: Optional[datetime] = None  # PRO 订阅到期时间
    subscribed_at: Optional[datetime] = None   # 实际订阅成功时间 (浏览器从 checkout 页跳到 chatgpt.com 主页那一刻)
    payment_card_last4: str = ""               # 升级 PRO 时使用的卡尾号 (回显, 也能手动改)
    # 退款状态机:
    #   ""                        = 未发起退款
    #   "refund_pending"          = 已通过 help 客服发了退款诉求, 等 OpenAI 处理
    #   "refunded_pending_credit" = 收到 "Your refund from OpenAI" 邮件, 已退款但银行卡未到账
    #   "refund_credited"         = 人工确认已到账 (终态)
    refund_status: str = ""
    refund_detected_at: Optional[datetime] = None  # 退款邮件检测到时间
    refund_credited_at: Optional[datetime] = None  # 人工标记到账时间
    human_review_requested_at: Optional[datetime] = None  # 最近一次申请人工审核(联系客服专员)时间
    refund_rejected_at: Optional[datetime] = None  # 检测到"订阅费用不予退款"拒绝邮件的时间
    refund_manual_at: Optional[datetime] = None    # 最近一次点手动退款的时间(用于清除拒绝提示)
    # 危险账号: 收到 "Access Deactivated" 邮件 → True (账号被 OpenAI 封禁/受限)
    dangerous: bool = False
    dangerous_detected_at: Optional[datetime] = None
    # 从 "Access Deactivated / 访问权限已停用" 邮件里提取的申诉链接 (标危险时自动提取, 可批量补)
    appeal_url: str = ""
    # 登录时自动抓取的 chatgpt.com 会话 cookie(含 oai-access-token / cf_clearance 等),每次登录自动更新
    cookie_blob: str = ""
    cookie_updated_at: Optional[datetime] = None
    cookie_expires_at: Optional[datetime] = None
    appeal_done_at: Optional[datetime] = None  # 点了申诉链接后打勾标记的时间 (已申诉)
    # 政策告警: 收到 "Usage Policy Violation & Deactivation Warning" 邮件 → True (封禁前的警告)
    policy_warning: bool = False
    policy_warning_detected_at: Optional[datetime] = None
    # Codex OAuth (DrissionPage 跑 codex CLI OAuth flow 拿到的)
    # 跟 client_id/refresh_token (Outlook OAuth, 取邮件用) 完全独立
    codex_access_token: str = ""
    codex_refresh_token: str = ""
    codex_id_token: str = ""
    codex_session_token: str = ""
    codex_rt_acquired_at: Optional[datetime] = None
    # Codex 推荐邀请(「重置」)缓存:
    #   referral_remaining=NULL → 还没查过
    #   = 整数 → 上次查询/邀请后的剩余配额(每月自动重置)
    referral_remaining: Optional[int] = None
    referral_quota_checked_at: Optional[datetime] = None
    # 已用本号邀请过的邮箱清单(按邀请时间顺序追加,去重)。手动 + 自动注册路径都会写进来。
    referral_invited_emails_json: str = "[]"
    # 已人工确认完成的被邀请邮箱清单(referral_invited_emails 的子集)。前端打勾后写入。
    referral_confirmed_emails_json: str = "[]"
    # 从 GPT BUSINESS 母号展开区选择并邀请成功后写入。非空时从 GPT PRO 各账号 Tab
    # 隐藏，但保留本行凭证，以便子号继续复用 GPT PRO 的 Codex OAuth/取 RT 流程。
    business_parent_id: Optional[int] = Field(default=None, index=True)
    business_invited_at: Optional[datetime] = None
    note: str = ""                       # 自由备注/标签
    extra_json: str = "{}"               # 杂项 JSON(如 CPA 同步标记 cpa_synced / 所属设备 cpa_api_url 等)

    # 邮件监控状态
    last_mail_check_at: Optional[datetime] = None       # 上次轮询时间
    last_mail_check_error: str = ""                     # 上次轮询失败原因
    seen_mail_ids_json: str = "[]"                      # 最近见过的 message id (限 100)
    pending_alerts_json: str = "[]"                     # 小铃铛: 仅 BELL_SUBJECT_KEYWORDS 命中的 (封禁报警)
    pending_inbox_json: str = "[]"                      # 收件箱: 所有新邮件 (除退款,退款走 refund_status)

    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class GptProAccountOperationLeaseModel(SQLModel, table=True):
    """GPT PRO 账号上的跨流程互斥租约。

    退款、升级 PRO 和迁入 BUSINESS 都会触发不可回滚的远端动作。它们必须争用
    同一个 ``account_id`` 主键，避免一个长任务进行到一半时账号又被另一个流程
    选中。租约带过期时间，进程异常退出后可由后续操作安全回收。
    """

    __tablename__ = "gpt_pro_account_operation_leases"

    account_id: int = Field(primary_key=True)
    operation: str = Field(index=True)
    token: str = Field(index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptPlanAccountModel(SQLModel, table=True):
    """GPT 套餐识别账号池。

    这是套餐管理的权威账号表：导入、登录、邮件、套餐、退款、
    OAuth 与设备同步状态都由它持有。付款升级的展示摘要仍单独放在
    ``gpt_plan_account_upgrades``，但账号生命周期不再依赖 ``gpt_pro_accounts``。

    ``password``、邮箱 OAuth 凭证和 ``cookie_blob`` 都是服务端秘密；API
    序列化只能返回对应的 ``has_*`` 状态，不能返回原值。
    """

    __tablename__ = "gpt_plan_accounts"
    __table_args__ = (
        Index(
            "ux_gpt_plan_accounts_source",
            "source_pool",
            "source_account_id",
            unique=True,
        ),
        # A deleted BUSINESS child id is retained in terminal audit rows.  SQLite's
        # default INTEGER PRIMARY KEY allocator may reuse the current maximum id,
        # which would make those immutable rows point at an unrelated future
        # account.  AUTOINCREMENT is therefore an identity-safety requirement,
        # not a throughput optimization.
        {"sqlite_autoincrement": True},
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    mail_access_type: str = ""          # graph | imap_pop | ""
    mail_provider: str = "outlook"      # outlook | icloud

    # 登录后从 ChatGPT session/JWT 识别出的套餐及稳定账号标识。
    plan_type: str = ""
    plan_checked_at: Optional[datetime] = None
    chatgpt_account_id: str = ""
    chatgpt_user_id: str = ""

    # 旧版目录来源元数据仅供一次性脱钩迁移识别。迁移完成后
    # source_pool/source_account_id 被清空，不能再用它们做持续同步。
    source_pool: str = ""               # ""(人工) | gpt_pro | gpt_business
    source_account_id: Optional[int] = None
    catalog_category: str = ""           # ""(按 plan_type 推断) | regular | member | refunded
    source_state: str = ""               # regular/pro/refunded_pending_credit/logged/never_logged
    source_synced_at: Optional[datetime] = None
    # BUSINESS 母号的人工用途标签。空字符串表示尚未标注；该字段属于
    # 套餐目录自身，不回写到旧 BUSINESS 来源表。
    business_usage_type: str = Field(default="", index=True)  # "" | sale | self_use | transit

    # 付费、退款与申诉状态。GPT 套餐管理是这些字段的唯一业务
    # owner；它们留在本表而不再运行时回查 ``gpt_pro_accounts``。
    is_pro: bool = False
    pro_expires_at: Optional[datetime] = None
    subscribed_at: Optional[datetime] = None
    payment_card_last4: str = ""
    refund_status: str = ""
    refund_detected_at: Optional[datetime] = None
    refund_credited_at: Optional[datetime] = None
    human_review_requested_at: Optional[datetime] = None
    refund_rejected_at: Optional[datetime] = None
    refund_manual_at: Optional[datetime] = None

    # Dead / 政策告警 / 申诉也是本地权威状态。
    dangerous: bool = False
    dangerous_detected_at: Optional[datetime] = None
    appeal_url: str = ""
    appeal_done_at: Optional[datetime] = None

    # 登录时抓取的 ChatGPT 会话，仅供后端查询套餐和后续自动化使用。
    cookie_blob: str = ""
    cookie_updated_at: Optional[datetime] = None
    cookie_expires_at: Optional[datetime] = None

    # 人工登录/取件的最近结果。错误只保存经过脱敏的短消息，不能写凭据或 Cookie。
    last_login_at: Optional[datetime] = None
    last_login_error: str = ""
    last_mail_fetch_at: Optional[datetime] = None
    last_mail_error: str = ""

    # 邮件定时监控的本地权威队列。
    last_mail_check_at: Optional[datetime] = None
    last_mail_check_error: str = ""
    seen_mail_ids_json: str = "[]"
    pending_alerts_json: str = "[]"
    pending_inbox_json: str = "[]"
    policy_warning: bool = False
    policy_warning_detected_at: Optional[datetime] = None

    # ChatGPT/Codex OAuth 凭据，与用于取邮件的 Outlook OAuth 分开。
    codex_access_token: str = ""
    codex_refresh_token: str = ""
    codex_id_token: str = ""
    codex_session_token: str = ""
    codex_rt_acquired_at: Optional[datetime] = None

    # PRO 推荐状态及 BUSINESS 子号归属。迁移后字段随账号本身存续，
    # 不再依赖旧 GPT PRO 表。
    referral_remaining: Optional[int] = None
    referral_quota_checked_at: Optional[datetime] = None
    referral_invited_emails_json: str = "[]"
    referral_confirmed_emails_json: str = "[]"
    business_parent_id: Optional[int] = Field(default=None, index=True)
    business_invited_at: Optional[datetime] = None

    # 设备绑定、CPA/SUB 同步摘要等扩展状态。
    extra_json: str = "{}"

    note: str = ""
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class GptPlanAccountOperationLeaseModel(SQLModel, table=True):
    """GPT 套餐账号的不可并行远程操作租约。

    这张表刻意与 ``gpt_pro_account_operation_leases`` 分开。两个
    账号池的整数 id 可能相同，如果共用租约表会让一个池的升级
    误阻塞（甚至误释放）另一个池的付款任务。
    """

    __tablename__ = "gpt_plan_account_operation_leases"

    account_id: int = Field(primary_key=True)
    operation: str = Field(index=True)
    token: str = Field(index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptPlanAccountUpgradeModel(SQLModel, table=True):
    """GPT 套餐账号的结账/升级摘要（一个账号一行）。

    付款字段不放进最小的 ``GptPlanAccountModel``，避免套餐识别池
    被 PRO 退款/CPA 状态污染。这里也不保存卡号、CVC、Cookie 或
    完整付款链接，只保存可安全回显的追溯摘要。
    """

    __tablename__ = "gpt_plan_account_upgrades"

    account_id: int = Field(primary_key=True, index=True)

    # 只有付款后复核到付费套餐，或后续登录首次检测到付费
    # 套餐时才写入。checkout 创建/点击付款不能直接当成升级成功。
    plan_upgraded_at: Optional[datetime] = None
    payment_card_last4: str = ""
    payment_account_id: int = 0
    payment_account_name: str = ""
    payment_account_type: str = ""

    checkout_created_at: Optional[datetime] = None
    checkout_target: str = ""          # pro | business
    # created | submitted | confirmation_pending | manual_confirmation_pending
    # | manual_not_upgraded | success | failed
    checkout_status: str = ""
    checkout_session_id: str = ""
    checkout_country: str = ""
    checkout_currency: str = ""
    workspace_name: str = ""
    seat_type: str = ""
    seat_quantity: int = 0

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptProToPlanAccountCrosswalkModel(SQLModel, table=True):
    """Immutable identity map produced by the one-time GPT PRO detachment.

    Historical BUSINESS/device rows may need to explain which old identifier
    they used even after their live foreign-key-like columns point at
    ``gpt_plan_accounts``.  Keeping the crosswalk makes that audit possible
    without treating the old GPT PRO table as a runtime dependency.
    """

    __tablename__ = "gpt_pro_to_plan_account_crosswalk"

    old_pro_account_id: int = Field(primary_key=True)
    plan_account_id: int = Field(index=True, sa_column_kwargs={"unique": True})
    email: str = Field(index=True)
    migrated_at: datetime = Field(default_factory=_utcnow)


class GptBusinessAccountModel(SQLModel, table=True):
    """GPT BUSINESS 账号池（导入格式与 Outlook 邮箱一致）。

    与 gpt_pro_accounts 完全独立的一套账号集。精简版账号管理:
    只保留导入 / 邮件监控(收件箱+封禁报警) / 登录 / OAuth 取 RT / 导出 /
    批量删除重置等核心能力,不含 PRO 专属的升级/标记/退款/推荐/CPA/银行卡逻辑。
    """
    __tablename__ = "gpt_business_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    mail_access_type: str = ""          # graph | imap_pop | ""

    # 危险账号: 收到 "Access Deactivated" 邮件 → True (账号被 OpenAI 封禁/受限)
    dangerous: bool = False
    dangerous_detected_at: Optional[datetime] = None
    # 政策告警: 收到 "Usage Policy Violation & Deactivation Warning" 邮件 → True
    policy_warning: bool = False
    policy_warning_detected_at: Optional[datetime] = None
    # Codex OAuth (DrissionPage 跑 codex CLI OAuth flow 拿到的), 与取邮件用的
    # client_id/refresh_token 完全独立。
    codex_access_token: str = ""
    codex_refresh_token: str = ""
    codex_id_token: str = ""
    codex_session_token: str = ""
    codex_rt_acquired_at: Optional[datetime] = None

    note: str = ""                       # 自由备注/标签
    extra_json: str = "{}"               # 杂项 JSON
    business_upgraded_at: Optional[datetime] = None     # 手动升级为 BUSINESS 的时间(可人工编辑)
    # 登录时自动抓取的 chatgpt.com 会话 cookie(含 oai-access-token / cf_clearance 等),
    # 供母号/成员/计费接口直接调用; 每次登录自动更新。
    cookie_blob: str = ""
    cookie_updated_at: Optional[datetime] = None
    cookie_expires_at: Optional[datetime] = None        # 从 access_token JWT 解析的过期时间
    # 母号(team 订阅)退款状态机, 与 GPT PRO 同款:
    #   "" 未退款 / "refund_pending" 已发退款诉求 / "refunded_pending_credit" 已退款未到账 / "refund_credited" 已到账
    refund_status: str = ""
    refund_detected_at: Optional[datetime] = None       # 检测到退款邮件时间
    refund_credited_at: Optional[datetime] = None       # 人工标记到账时间
    refund_manual_at: Optional[datetime] = None         # 最近一次手动退款(打开客服界面)时间
    human_review_requested_at: Optional[datetime] = None  # 最近一次联系客服专员时间

    # BUSINESS 子号邀请固定窗口。周期从首个服务端确认成功的
    # 邀请开始，按 BUSINESS_INVITE_WINDOW_HOURS（30 小时）整体重置；
    # 结果不确定的请求会保守预留名额。
    # 这两个旧字段保留兼容审计；完成迁移后由下方各席位账本强制限制。
    invite_quota_window_started_at: Optional[datetime] = Field(default=None, index=True)
    invite_quota_used: int = 0
    # Per-seat invitation ledgers. The legacy fields above remain a compatibility
    # audit mirror; unclassified pre-upgrade debt is tracked explicitly below.
    invite_quota_typed_initialized: bool = False
    invite_quota_default_window_started_at: Optional[datetime] = None
    invite_quota_default_used: int = 0
    invite_quota_prolite_window_started_at: Optional[datetime] = None
    invite_quota_prolite_used: int = 0
    invite_quota_legacy_window_started_at: Optional[datetime] = None
    invite_quota_legacy_used: int = 0

    # 母号邀请接口失败后的独立退避。它与上面的固定窗口邀请
    # 额度同时生效：任一限制激活都不再发起新邀请。
    # 请求失败退避 10 分钟，明确拒绝按独立拒绝策略处理。
    invite_cooldown_started_at: Optional[datetime] = Field(default=None, index=True)
    invite_cooldown_until: Optional[datetime] = Field(default=None, index=True)
    invite_cooldown_reason: str = ""

    # 邮件监控状态
    last_mail_check_at: Optional[datetime] = None       # 上次轮询时间
    last_mail_check_error: str = ""                     # 上次轮询失败原因
    seen_mail_ids_json: str = "[]"                      # 最近见过的 message id (限 100)
    pending_alerts_json: str = "[]"                     # 小铃铛: 封禁/告警邮件
    pending_inbox_json: str = "[]"                      # 收件箱: 所有新邮件

    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class GptBusinessChildMembershipModel(SQLModel, table=True):
    """GPT BUSINESS 子号的一次邀请归属记录。

    ``ended_at IS NULL`` 表示当前仍在该母号；结束后的行永久作为历史保留。
    同一套餐子号释放后可在另一个母号创建新记录，因此历史是多对多。
    列名 ``pro_account_id`` / ``replacement_pro_account_id`` 因数据库兼容保留，
    一次性脱钩后其值均是 ``GptPlanAccountModel.id``。
    """
    __tablename__ = "gpt_business_child_memberships"

    id: Optional[int] = Field(default=None, primary_key=True)
    business_account_id: int = Field(index=True)
    pro_account_id: Optional[int] = Field(default=None, index=True)
    email: str = Field(index=True)
    source: str = "pool"                 # pool / manual
    # 席位类型属于这次 BUSINESS 邀请/归属，而不是 GPT PRO 子号的固有属性。
    # 旧流水无法可靠反推时保留空字符串，由界面明确显示“未知”。
    seat_type: str = ""                  # default / prolite / ""(unknown)
    invited_at: datetime = Field(default_factory=_utcnow, index=True)
    # 出售/质保属于“一次母号邀请关系”，而不是可在不同母号间复用的
    # 子号账号本身。子号被释放并再次邀请时，新 membership 会自然开始
    # 一个独立的销售与质保周期。
    sale_status: str = Field(default="unlisted", index=True)  # unlisted / listed / sold
    sold_at: Optional[datetime] = Field(default=None, index=True)
    warranty_hours: int = 0
    # NexusVault 对账元数据。网页会话只保存在加密配置中；归属流水只保存
    # 不具备授权能力的远端标识和时间，用于避免历史订单误匹配。
    nv_listed_at: Optional[datetime] = Field(default=None, index=True)
    # 独立记录真实 NV 上架成功或远端核实的时间。人工销售标记和迁移
    # 不能以 sale_status / nv_listed_at 推断或补写这份远端上架证明。
    nv_listing_confirmed_at: Optional[datetime] = Field(default=None, index=True)
    # NV Team 5x 上架时明确提交的绝对质保截止时间；旧流水不反推、不回填。
    nv_team5x_warranty_until: Optional[datetime] = None
    nv_last_synced_at: Optional[datetime] = Field(default=None, index=True)
    nv_remote_card_id: str = ""
    nv_remote_order_id: str = ""
    ended_at: Optional[datetime] = Field(default=None, index=True)
    end_reason: str = ""                 # removed / revoked / replaced / parent_deleted
    # 每次实际成功移除/撤邀只在这里记一次，保留旧版滚动 48h / 4 次审计。
    quota_counted_at: Optional[datetime] = Field(default=None, index=True)
    operation_id: Optional[str] = Field(
        default=None,
        index=True,
        sa_column_kwargs={"unique": True},
    )
    replacement_pro_account_id: Optional[int] = None
    replacement_email: str = ""
    replacement_completed_at: Optional[datetime] = None
    # remove/revoke/replace 在远端调用前写入的完整、不可变恢复请求。
    # 页面刷新或进程重启后可直接重放同一个 operation_id，不依赖前端内存。
    intent_payload_json: str = "{}"
    # 在 DELETE 发送前持久化。若进程在远端响应与本地结束流水之间崩溃，
    # 恢复只能对账，不能再次发送破坏性请求。
    intent_remote_started: bool = False
    remote_user_id: str = ""
    remote_invite_id: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptBusinessRotationReservationModel(SQLModel, table=True):
    """BUSINESS 母号跨进程操作预留/审计行。

    ``operation_id`` 是唯一主键。invite/pro_refund_burn 行用于强制
    独立的各席位固定邀请窗口（30 小时）内按配置限制新邀请；remove/revoke/replace 行仍为
    旧版破坏性操作幂等和审计记录。``reserved`` 在远端结果不确定时
    保守占位，避免并发重试突破邀请上限。
    """

    __tablename__ = "gpt_business_rotation_reservations"

    operation_id: str = Field(primary_key=True)
    business_account_id: int = Field(index=True)
    action: str = Field(default="", index=True)  # invite / pro_refund_burn / remove / revoke / replace
    seat_type: str = ""  # immutable invitation binding; empty = legacy shared debt
    state: str = Field(default="reserved", index=True)  # reserved / consumed / released
    reserved_at: datetime = Field(default_factory=_utcnow, index=True)
    resolved_at: Optional[datetime] = None
    resolution_reason: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptBusinessInviteUsageAdjustmentModel(SQLModel, table=True):
    """Local correction scoped to one mother's original typed invite window."""

    __tablename__ = "business_invite_usage_adjustments"

    source_account_id: int = Field(primary_key=True)
    seat_type: str = Field(primary_key=True)
    window_started_at: datetime = Field(primary_key=True)
    source_identity: str = ""
    adjustment: int = 0
    revision: int = 1
    updated_at: datetime = Field(default_factory=_utcnow)


class GptBusinessInviteUsageAuditModel(SQLModel, table=True):
    """Immutable administrative correction; request id also fences retries."""

    __tablename__ = "business_invite_usage_audits"

    request_id: str = Field(primary_key=True)
    source_account_id: int = Field(index=True)
    source_identity: str = Field(default="", index=True)
    seat_type: str
    window_started_at: datetime
    window_ends_at: datetime
    request_hash: str
    recorded_typed_used: int
    previous_adjustment: int
    target_used: int
    adjustment: int
    revision: int
    reserved: int
    legacy_shared_used: int
    legacy_shared_reserved: int
    limit: int
    actor: str
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow, index=True)


class GptBusinessInviteOperationModel(SQLModel, table=True):
    """Legacy schema retained only so existing databases remain readable.

    Direct BUSINESS invitations no longer read, write, resume, or expose rows
    from this table.  Keeping the mapping avoids an implicit destructive schema
    migration for installations that still contain historical audit rows.
    """

    __tablename__ = "gpt_business_invite_operations"

    operation_id: str = Field(primary_key=True)
    business_account_id: int = Field(index=True)
    request_hash: str = ""
    request_json: str = "{}"
    state: str = Field(default="prepared", index=True)
    stage: str = "prepared"
    worker_token: str = Field(default="", index=True)
    lease_expires_at: Optional[datetime] = Field(default=None, index=True)
    attempt_count: int = 0
    remote_started: bool = False
    result_json: str = "{}"
    error: str = ""
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    completed_at: Optional[datetime] = None


class GptBusinessAutomationPolicyModel(SQLModel, table=True):
    """Per-workspace controls for BUSINESS child invitations and delivery rotation.

    ``cpa_target_id`` references the shared GPT PRO manual-target registry.  API
    keys and URLs deliberately remain in that registry and are never copied to
    a parent policy row.  Sub2API uses ``SyncDeviceModel`` instead, so its id is
    kept in a separate namespace and can never be confused with a CPA target id.
    """

    __tablename__ = "gpt_business_automation_policies"

    business_account_id: int = Field(primary_key=True)
    auto_rotation_enabled: bool = False
    manual_invite_enabled: bool = True
    delivery_type: str = ""  # "" | cpa | sub2api
    cpa_target_id: Optional[int] = Field(default=None, index=True)
    sub2api_device_id: Optional[int] = Field(default=None, index=True)
    trigger_mode: str = "long_window_exhausted"
    rotate_default: bool = True
    rotate_prolite: bool = False
    revision: int = 0
    last_scan_at: Optional[datetime] = None
    last_error: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


def resolve_business_delivery_binding(row) -> tuple[str, Optional[int]]:
    """Return the one canonical provider/id represented by a policy row.

    Legacy rows may contain a stale ``delivery_type`` next to only the other
    provider's id.  Every CRUD and deletion fence must resolve those malformed
    rows identically, otherwise a device could be deleted while one screen
    still presents the mother as bound to it.
    """
    if row is None:
        return "", None

    def positive_int(value) -> Optional[int]:
        if isinstance(value, bool):
            return None
        try:
            parsed = int(value or 0)
        except (TypeError, ValueError):
            return None
        return parsed if 0 < parsed <= 2_147_483_647 else None

    provider = str(getattr(row, "delivery_type", "") or "").strip().lower()
    cpa_id = positive_int(getattr(row, "cpa_target_id", None))
    sub2api_id = positive_int(getattr(row, "sub2api_device_id", None))
    if provider == "cpa" and cpa_id is not None:
        return "cpa", cpa_id
    if provider == "sub2api" and sub2api_id is not None:
        return "sub2api", sub2api_id
    # Deterministic compatibility for malformed legacy rows.  Prefer SUB when
    # both stale ids exist, matching the historical device-page resolver.
    if sub2api_id is not None:
        return "sub2api", sub2api_id
    if cpa_id is not None:
        return "cpa", cpa_id
    return "", None


class GptBusinessAllocationJobModel(SQLModel, table=True):
    """一次 BUSINESS 子号自动分配编排。

    外部 OpenAI 邀请/移除接口不具备事务语义，所以作业必须先持久化，再按阶段推进。
    ``idempotency_key`` 绑定完整请求，客户端重试时返回同一作业；``operation_id``
    会继续传给现有 replace/remove 流程，保证“已释放、待补邀请”不会重复扣配额。
    """

    __tablename__ = "gpt_business_allocation_jobs"

    id: str = Field(primary_key=True)
    idempotency_key: str = Field(index=True, sa_column_kwargs={"unique": True})
    request_hash: str = ""
    request_json: str = "{}"

    requested_business_account_id: Optional[int] = Field(default=None, index=True)
    requested_pro_account_id: Optional[int] = Field(default=None, index=True)
    selected_business_account_id: Optional[int] = Field(default=None, index=True)
    selected_pro_account_id: Optional[int] = Field(default=None, index=True)
    selected_email: str = ""
    allocation_mode: str = ""          # direct / replace
    seat_type: str = "default"          # default / prolite

    old_kind: str = ""                  # member / invite（replace 时）
    old_user_id: str = ""
    old_email: str = ""
    old_pro_account_id: Optional[int] = None

    state: str = "queued"               # queued/running/pending_acceptance/action_required/partial/completed/failed
    stage: str = "planned"
    worker_token: str = Field(default="", index=True)
    attempt_count: int = 0
    retryable: bool = True
    remote_mutated: bool = False
    error: str = ""
    selection_json: str = "{}"
    result_json: str = "{}"
    action_state_json: str = "{}"

    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class GptBusinessAllocationLeaseModel(SQLModel, table=True):
    """跨线程/进程的自动分配资源租约。

    parent 租约避免两个 worker 同时把同一空席位分配给不同子号；child 租约避免
    同一子号在远端邀请完成、本地归属提交前被另一个母号抢走。租约超时后可恢复。
    """

    __tablename__ = "gpt_business_allocation_leases"

    resource_key: str = Field(primary_key=True)  # parent:<id> / child:<id>
    job_id: str = Field(index=True)
    owner_token: str = Field(default="", index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CpaProxyModel(SQLModel, table=True):
    """CPA 文件专用代理 IP 池。

    仅用于把 proxy_url 写进生成的 CPA 凭证文件, **不参与任何实际网络请求**。
    每个代理最多绑定 max_accounts(默认3) 个 GPT PRO 账号; 账号退款/删除/封禁后
    名额自动释放(名额按"仍有效引用它的账号数"动态计算, 见 services/cpa_proxy_pool)。
    """
    __tablename__ = "cpa_proxy_pool"

    id: Optional[int] = Field(default=None, primary_key=True)
    # socks5://用户名:密码@IP:端口
    proxy_url: str = Field(index=True, sa_column_kwargs={"unique": True})
    max_accounts: int = 3
    enabled: bool = True
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptPlanCpaProxyModel(SQLModel, table=True):
    """GPT 套餐管理专属的凭证文件代理池。"""

    __tablename__ = "gpt_plan_cpa_proxy_pool"

    id: Optional[int] = Field(default=None, primary_key=True)
    proxy_url: str = Field(index=True, sa_column_kwargs={"unique": True})
    max_accounts: int = 3
    enabled: bool = True
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class ClaudeAccountModel(SQLModel, table=True):
    """Claude 账号池:导入 Google 账号 → 用 Google 登录 claude.ai 完成注册。

    与其它平台完全独立。Google 凭证(邮箱/密码/辅助邮箱/2FA)存本表,
    注册成功后回写 claude.ai 的 sessionKey / org_id。
    """
    __tablename__ = "claude_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})   # Google 邮箱
    password: str = ""
    recovery_email: str = ""            # Google 辅助邮箱(风控验证用)
    totp_secret: str = ""              # Google 2FA (TOTP) 密钥
    code_api_url: str = ""             # 取码 URL(预留)

    registered: bool = False           # 是否已成功注册/登录 claude.ai
    registered_at: Optional[datetime] = None
    session_key: str = ""             # claude.ai sessionKey cookie
    org_id: str = ""                  # claude.ai lastActiveOrg

    # 注册成功后保留的 RoxyBrowser 指纹窗口(供「登录 Claude」重开,同一 profile=同一代理)
    roxy_dir_id: str = ""             # 保留的 profile dirId(注册成功不删窗)
    roxy_proxy_id: Optional[int] = None  # 注册用的代理 id(RoxyProxyModel.id)
    proxy_label: str = ""             # 注册用代理的展示文案(host:port + 备注)

    note: str = ""
    extra_json: str = "{}"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class IcloudHmeAliasModel(SQLModel, table=True):
    """iCloud Hide-My-Email 别名注册状态追踪。

    每个 HME 别名一行,记录在各平台上是否已经被用过(防止重复注册到同一平台)。
    同一别名可以在不同平台都使用一次(各平台之间独立)。
    """
    __tablename__ = "icloud_hme_aliases"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    anonymous_id: str = ""              # iCloud HME 的 anonymousId,用于回调
    label: str = ""                     # iCloud HME 的 label
    forward_to: str = ""                # 转发到的真实邮箱(通常是你 Apple ID)
    is_active: bool = True              # 与 iCloud 一致:激活/停用
    note: str = ""

    # 各平台注册状态(字段名与 OutlookAccountModel 对齐,_PLATFORM_STATUS_FIELD_MAP 复用)
    gpt_register_status: str = "未注册"
    grok_register_status: str = "未注册"
    trae_register_status: str = "未注册"
    kiro_register_status: str = "未注册"
    obl_register_status: str = "未注册"
    cursor_register_status: str = "未注册"

    # 注册成功时记录对应的 account_id,便于反查
    gpt_account_id: str = ""
    grok_account_id: str = ""
    trae_account_id: str = ""
    kiro_account_id: str = ""
    obl_account_id: str = ""
    cursor_account_id: str = ""

    enabled: bool = True                # 软停用:不参与 claim 但保留记录
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class ProxyModel(SQLModel, table=True):
    __tablename__ = "proxies"

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    region: str = ""
    success_count: int = 0
    fail_count: int = 0
    is_active: bool = True
    last_checked: Optional[datetime] = None


class RoxyProxyModel(SQLModel, table=True):
    """GPT PRO「升级 PRO」指纹浏览器用的代理池(带备注)。

    应用侧管理: GPT PRO 界面批量录入 host/port/账号密码 + 备注; 也可从 RoxyBrowser
    /proxy/list 导入。升级时选一个 → RoxyBrowser /browser/create 用 proxyInfo(custom)
    新建一个带此代理的全新窗口, 用完即删。
    """
    __tablename__ = "roxy_proxies"

    id: Optional[int] = Field(default=None, primary_key=True)
    host: str = ""
    port: str = ""
    protocol: str = "SOCKS5"          # HTTP | HTTPS | SOCKS5
    username: str = ""
    password: str = ""
    note: str = ""                    # 备注(仅应用侧, RoxyBrowser 代理列表无此字段)
    roxy_module_id: str = ""          # 从 RoxyBrowser 导入时记下的代理 id(choose 绑定备用; 空则走 custom)
    last_ip: str = ""
    last_country: str = ""
    check_status: int = -1            # 可用性: -1 未检测 | 1 可用 | 0 不可用
    checked_at: Optional[datetime] = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptPlanRoxyProxyModel(SQLModel, table=True):
    """套餐侧（含 Claude 自动化）的 RoxyBrowser 代理目录。

    旧 GPT PRO 页面仍使用 ``roxy_proxies``。两套界面允许在脱钩时拥有
    相同的初始内容，但此表创建后不再从旧目录同步，避免任一页面的增删改
    影响另一套业务。
    """

    __tablename__ = "gpt_plan_roxy_proxies"

    id: Optional[int] = Field(default=None, primary_key=True)
    host: str = ""
    port: str = ""
    protocol: str = "SOCKS5"
    username: str = ""
    password: str = ""
    note: str = ""
    roxy_module_id: str = ""
    last_ip: str = ""
    last_country: str = ""
    check_status: int = -1
    checked_at: Optional[datetime] = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class AdobeAdminAccountModel(SQLModel, table=True):
    """Adobe 管理员账号池。导入后可登录 Admin Console、把子号邀请进组织(授 Firefly 席位)。

    导入格式与 Outlook 邮箱一致(email----password----refresh_token----client_id),
    登录撞 MFA 时用 refresh_token/client_id 从邮箱自动取码。
    """
    __tablename__ = "adobe_admin_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str = ""                  # Adobe 登录密码 (用于 Admin Console 登录)
    mail_password: str = ""             # Hotmail/邮箱密码 (读邮件/IMAP 兜底用)
    # 取 MFA 验证码用(复用 Outlook OAuth 格式)
    client_id: str = ""
    refresh_token: str = ""
    mail_access_type: str = ""          # graph | imap_pop | ""
    # 登录后落库
    access_token: str = ""              # Admin Console IMS access_token (调 JIL API 用)
    susi_token: str = ""
    cookie_json: str = "{}"
    # discover 后落库
    org_id: str = ""
    product_id: str = ""
    license_group_id: str = ""
    org_name: str = ""
    product_name: str = ""
    product_credits: int = 0            # 选中产品的 Firefly 生成积分上限 (子号能拿多少, 4000=付费/10=免费)
    status: str = "未登录"               # 未登录 | 已登录 | 失效
    last_login_at: Optional[datetime] = None
    last_error: str = ""
    # 已邀请子号清单(按邀请顺序追加,去重)
    invited_emails_json: str = "[]"
    note: str = ""
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class TeamParentSession(SQLModel, table=True):
    __tablename__ = "team_parent_sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    user_name: str = ""
    account_id: str = ""
    plan_type: str = ""
    organization_id: str = ""
    access_token: str = ""
    session_token: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class ScheduledJobModel(SQLModel, table=True):
    """定时注册计划"""
    __tablename__ = "scheduled_jobs"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = ""                        # "每日注册 ChatGPT ×5"
    platform: str = Field(index=True)     # chatgpt / grok / trae / kiro / openblocklabs
    cron_hour: int = 9                    # 0-23 每天几点执行
    cron_minute: int = 0                  # 0-59 分钟
    count: int = 1                        # 每次注册数量
    concurrency: int = 1                  # 并发数
    mail_provider: str = "outlook"        # outlook / cfworker
    proxy: str = ""
    config_json: str = "{}"               # 额外配置 JSON
    enabled: bool = True
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class BusinessDomainModel(SQLModel, table=True):
    """BUSINESS 类型子域(在 OpenAI 母号工作区下验证的子域)"""
    __tablename__ = "business_domains"

    id: Optional[int] = Field(default=None, primary_key=True)
    hostname: str = Field(index=True, sa_column_kwargs={"unique": True})  # x7k9m3z2.cgifu.it.com
    base_domain: str = Field(index=True)                                   # cgifu.it.com
    openai_domain_id: str = ""                                             # dom-xxx
    cf_zone_id: str = ""                                                   # CF zone id
    cf_record_ids: str = "[]"                                              # JSON list of created CF DNS record ids
    dns_verification_token: str = ""                                       # dv-xxx
    status: str = "pending"                                                # pending | verified | failed | imported | banned
    note: str = ""                                                         # 用户备注
    # 机器隔离: 哪台机器创建/认领的这个子域;空 = 公共(strict 模式下任何机器都不会选)
    # 多机协作时避免同一子域被多台机器并发用而撞邮箱/抢码/互删
    owner_machine_id: str = Field(default="", index=True)
    last_synced_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class TaskQueueModel(SQLModel, table=True):
    """持久化任务队列"""
    __tablename__ = "task_queue"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: Optional[int] = None          # 关联 scheduled_jobs (手动任务为 None)
    task_id: str = Field(index=True)      # 兼容 RegisterTaskStore 的 task_id
    platform: str = Field(index=True)
    source: str = "manual"                # manual / scheduled / cpa_replenish
    status: str = "pending"               # pending → running → done / failed / interrupted
    total: int = 1
    success: int = 0
    failed: int = 0
    skipped: int = 0
    progress: str = "0/0"
    config_json: str = "{}"               # 注册配置快照
    error: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class SyncDeviceModel(SQLModel, table=True):
    __tablename__ = "sync_devices"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    type: str = "cpa"                         # cpa | sub | gpt2web | grok2api
    api_url: str
    api_key: str = ""
    platform: str = "chatgpt"
    target_count: int = 10
    concurrency: int = 1
    register_delay_seconds: float = 0
    executor_type: str = "protocol"
    mail_provider: str = "cfworker"
    domain_rules_json: str = "{}"
    business_domains: str = "[]"          # JSON 数组,选中的 BUSINESS 子域;非空时设备只产 BUSINESS 账号
    sub_group_ids: str = ""
    # CPA/SUB 设备绑了 BUSINESS 域名时,此开关 ON 走 RT 链路(协议注册→拿 RT→上传)
    # 是否切 Codex 由业务参数 business_switch_to_codex 控制。
    # OFF 走旧链路(协议注册,无 RT,上传通常会失败因为缺 RT)
    # 默认 ON: CPA/SUB + BUSINESS 域名 上传必须要 refresh_token
    wants_refresh_token: bool = True
    priority: int = 0
    sync_batch_size: int = 5
    auto_replenish_batch_size: int = 0
    default_proxy_id: int = -1
    current_count: int = 0
    last_check_at: Optional[datetime] = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def get_domain_rules(self) -> dict:
        return json.loads(self.domain_rules_json or "{}")

    def set_domain_rules(self, d: dict):
        self.domain_rules_json = json.dumps(d, ensure_ascii=False)


class DeliveryDeviceMonitorStateModel(SQLModel, table=True):
    """Last credential-free refresh result for one CPA/Sub2API device.

    CPA targets are configured by the owning workspace while Sub2API devices
    live in the shared physical ``sync_devices`` registry. ``device_key`` gives
    the monitor one collision-free physical identity without creating a third
    device registry.
    """

    __tablename__ = "delivery_device_monitor_states"

    device_key: str = Field(primary_key=True)       # cpa:1 / sub2api:7
    provider: str = Field(index=True)
    provider_id: int = Field(index=True)
    account_count: int = 0
    refreshed_at: Optional[datetime] = None
    refresh_error: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class DeliveryDeviceAccountSnapshotModel(SQLModel, table=True):
    """One sanitized remote account row shown by the unified device page.

    ``payload_json`` is produced from an explicit allowlist.  It must never
    contain an access/refresh token, API key, raw auth file, or credentials.
    """

    __tablename__ = "delivery_device_account_snapshots"

    snapshot_id: str = Field(primary_key=True)
    device_key: str = Field(index=True)
    remote_id: str = Field(index=True)
    payload_json: str = "{}"
    checked_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class DeliveryDeviceTeam401BatchModel(SQLModel, table=True):
    """One operator-created, mother-scoped TEAM 401 correction batch.

    The batch is deliberately separate from the device refresh task.  It only
    stores credential-free identities and aggregate state; every child owns
    its own durable checkpoint row below.
    """

    __tablename__ = "delivery_device_team401_batches"

    id: str = Field(primary_key=True)
    idempotency_key: str = Field(
        index=True,
        sa_column_kwargs={"unique": True},
    )
    operation_id: str = Field(
        index=True,
        sa_column_kwargs={"unique": True},
    )
    provider: str = Field(index=True)
    provider_id: int = Field(index=True)
    business_parent_id: int = Field(index=True)
    device_epoch: str = ""

    state: str = Field(default="prepared", index=True)
    total_count: int = 0
    completed_count: int = 0
    failed_count: int = 0
    error_code: str = ""

    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    completed_at: Optional[datetime] = None


class DeliveryDeviceTeam401TaskModel(SQLModel, table=True):
    """Durable per-child TEAM 401 correction with step checkpoints.

    ``request_json`` contains only the immutable provider/device/remote and
    parent/child/membership identities captured from one authoritative
    device-link snapshot.  Tokens, API keys, remote response bodies and raw
    exceptions are never persisted here.
    """

    __tablename__ = "delivery_device_team401_tasks"

    id: str = Field(primary_key=True)
    batch_id: str = Field(index=True)
    idempotency_key: str = Field(
        index=True,
        sa_column_kwargs={"unique": True},
    )
    request_hash: str = ""
    request_json: str = "{}"

    provider: str = Field(index=True)
    provider_id: int = Field(index=True)
    remote_id: str = Field(index=True)
    source_email: str = Field(index=True)
    business_parent_id: int = Field(index=True)
    child_id: int = Field(index=True)
    membership_id: int = Field(index=True)

    branch: str = "checking"             # checking / repair / replace
    state: str = Field(default="prepared", index=True)
    stage: str = "queued"
    result: str = ""
    error_code: str = ""
    logs_json: str = "[]"

    device_delete_confirmed: bool = False
    account_checked: bool = False
    oauth_confirmed: bool = False
    device_upload_confirmed: bool = False
    device_verify_confirmed: bool = False
    cleanup_job_id: str = Field(default="", index=True)
    replenishment_demand_id: str = Field(default="", index=True)
    fill_job_id: str = Field(default="", index=True)
    replacement_child_id: Optional[int] = Field(default=None, index=True)
    replacement_membership_id: Optional[int] = Field(default=None, index=True)
    replacement_email: str = ""

    worker_token: str = Field(default="", index=True)
    lease_expires_at: Optional[datetime] = Field(default=None, index=True)
    next_check_at: Optional[datetime] = Field(default=None, index=True)
    attempt_count: int = 0

    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    completed_at: Optional[datetime] = None


class DeliveryDeviceExhaustionCleanupModel(SQLModel, table=True):
    """Durable cleanup for one exactly-mapped exhausted delivery account.

    Device cleanup is intentionally not an allocation job: refreshing a CPA or
    Sub2API device may remove an exhausted credential (and, for a BUSINESS
    child, remove/revoke that exact child), but it must never select or invite a
    replacement.  The immutable request contains credential-free identities
    only.  ``stage`` lets a later scheduler run reconcile a crash on either
    side of the device DELETE or BUSINESS remove/revoke boundary.
    """

    __tablename__ = "delivery_device_exhaustion_cleanups"

    id: str = Field(primary_key=True)
    idempotency_key: str = Field(
        index=True,
        sa_column_kwargs={"unique": True},
    )
    request_hash: str = ""
    request_json: str = "{}"

    provider: str = Field(index=True)       # cpa / sub2api
    provider_id: int = Field(index=True)
    account_id: int = Field(index=True)
    business_parent_id: Optional[int] = Field(default=None, index=True)
    membership_id: Optional[int] = Field(default=None, index=True)
    remote_id: str = Field(index=True)
    manual_operation_id: Optional[str] = Field(
        default=None,
        index=True,
        sa_column_kwargs={"unique": True},
    )

    state: str = Field(default="prepared", index=True)
    stage: str = "device_delete_pending"
    worker_token: str = Field(default="", index=True)
    lease_expires_at: Optional[datetime] = Field(default=None, index=True)
    # Quota-gated TEAM replacement is a durable due-time wait rather than a
    # failed cleanup.  The scheduler uses this timestamp to avoid claiming the
    # same row every minute while preserving automatic continuation after a
    # restart.
    resume_at: Optional[datetime] = Field(default=None, index=True)
    attempt_count: int = 0
    business_remove_confirmed: bool = False
    device_delete_confirmed: bool = False
    local_snapshot_persisted: bool = False
    business_operation_id: str = ""
    error: str = ""

    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    completed_at: Optional[datetime] = None


class DeliveryDeviceReplenishmentDemandModel(SQLModel, table=True):
    """Durable request to refill the exact BUSINESS seat freed by cleanup.

    A demand is created only after an exactly-mapped BUSINESS child has been
    removed successfully.  The device refresh path never consumes the demand;
    the BUSINESS scheduler owns all invitation/OAuth/delivery work.  Binding
    the row to ``cleanup_job_id`` makes the cleanup -> demand handoff
    idempotent across process crashes.
    """

    __tablename__ = "delivery_device_replenishment_demands"

    id: str = Field(primary_key=True)
    cleanup_job_id: str = Field(
        index=True,
        sa_column_kwargs={"unique": True},
    )
    provider: str = Field(index=True)       # cpa / sub2api
    device_id: int = Field(index=True)
    business_parent_id: int = Field(index=True)
    seat_type: str = ""                    # default / prolite

    state: str = Field(default="pending", index=True)
    stage: str = "queued"
    next_check_at: Optional[datetime] = Field(default=None, index=True)
    resume_at: Optional[datetime] = None
    last_checked_at: Optional[datetime] = None
    attempt_count: int = 0
    fill_job_id: str = Field(default="", index=True)
    worker_token: str = Field(default="", index=True)
    lease_expires_at: Optional[datetime] = Field(default=None, index=True)
    error: str = ""

    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
    completed_at: Optional[datetime] = None


class CFWorkerSubdomainModel(SQLModel, table=True):
    __tablename__ = "cfworker_subdomains"

    id: Optional[int] = Field(default=None, primary_key=True)
    root_domain: str = Field(index=True)
    subdomain_label: str = Field(index=True)
    full_domain: str = Field(
        index=True, sa_column_kwargs={"unique": True}
    )
    max_accounts: int = 100
    used_count: int = 0
    inflight_count: int = 0
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CardModel(SQLModel, table=True):
    """虚拟卡 / 支付卡卡池。Devin / Windsurf 等平台自动支付时从池里 reserve 一张。

    状态机:
      unused   ← 新导入,可被 reserve
      in_use   ← 已被某个账号 reserve,未完成支付(reserved_by_account_id 指向账号)
      used     ← 支付成功,可永久占用 / 也可标 single_use=False 回收
      failed   ← 支付失败,last_error 记录原因;可手动改回 unused 重试
    """

    __tablename__ = "cards"

    id: Optional[int] = Field(default=None, primary_key=True)
    payment_account_id: int = Field(default=0, index=True)  # 归属的支付账号(U卡挂在支付账号下);0=未归属
    opened_at: Optional[datetime] = None            # 开卡时间(同步/新增时记;E卡 24h 冷却按最新一张算)
    label: str = ""                                 # 用户备注,例如"卡商A-7月"
    number: str = Field(index=True, sa_column_kwargs={"unique": True})  # 完整卡号
    exp_month: int = 0                              # 1-12
    exp_year: int = 0                               # 4位年份,例如 2028
    cvc: str = ""
    holder_name: str = ""                           # 持卡人姓名
    # 账单地址
    country: str = "US"                             # ISO-2 国家码
    state: str = ""                                 # 州/省
    city: str = ""
    address_line1: str = ""
    address_line2: str = ""
    postal_code: str = ""
    # 状态
    status: str = Field(default="unused", index=True)   # unused | in_use | used | failed | disabled
    reserved_by_account_id: int = 0                 # in_use 时指向 accounts.id
    reserved_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    last_error: str = ""
    # 配置
    single_use: bool = True                         # True: used 后不可再 reserve
    enabled: bool = True                            # 软停用
    use_count: int = 0                              # 成功购买次数;达到上限(默认6)后置 used 不再选
    priority: int = 100                             # 升级 PRO 自动选卡优先级,数字越小越先用
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def masked(self) -> str:
        """卡号脱敏,用于日志/API 返回"""
        n = (self.number or "").replace(" ", "")
        if len(n) < 8:
            return n
        return f"{n[:6]}******{n[-4:]}"


class PaymentAccountModel(SQLModel, table=True):
    """支付账号(卡的父级)。一个支付账号有类型 Y卡/E卡,下挂最多 5 张 U卡(支付卡)。
    只填名称即可;U卡(CardModel)通过 payment_account_id 归属到它。"""

    __tablename__ = "payment_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)                    # 账号名称(必填)
    account_type: str = Field(default="Y", index=True)   # Y = Y卡, E = E卡
    enabled: bool = True                             # 停用后其下 U卡 不参与升级填卡
    is_default: bool = False                         # 迁移旧卡用的默认账号(不受 5 张上限)
    roxy_dir_id: str = ""                            # 指纹浏览器(RoxyBrowser)profile ID, 可一键打开
    last_card_opened_at: Optional[datetime] = None   # E卡上次开卡时间(24h 只能开一张 → 倒计时)
    balance_usd: float = 0.0                          # 账号余额(ether.fi Saldo total, USD)
    balance_text: str = ""                            # 余额明细文本, 如 "USDC $32.00 · USDT $7.77"
    balance_updated_at: Optional[datetime] = None     # 余额上次刷新时间
    paid_count: int = 0                               # 支付笔数(交易记录里 -$200)
    refunded_count: int = 0                            # 成功退款笔数(+$200 且非 pending)
    pending_refund_count: int = 0                     # 待退款笔数(交易记录里 +$200 且 pending)
    card_open_count: int = 0                           # 开卡数量(交易记录里 Pedido de tarjeta $10 扣款)
    unrefunded_dates_json: str = "[]"                  # 未发起退款(支付−已退−待退)的支付日期列表 JSON
    pending_refund_updated_at: Optional[datetime] = None  # 交易统计上次刷新时间
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class GptPlanCardModel(SQLModel, table=True):
    """GPT 套餐管理专属支付卡。

    ``reserved_by_account_id`` 只允许引用 ``gpt_plan_accounts.id``，从根本上
    消除旧 GPT PRO 与套餐账号整数 ID 相同造成的误占用/误释放。
    """

    __tablename__ = "gpt_plan_cards"

    id: Optional[int] = Field(default=None, primary_key=True)
    payment_account_id: int = Field(default=0, index=True)
    opened_at: Optional[datetime] = None
    label: str = ""
    number: str = Field(index=True, sa_column_kwargs={"unique": True})
    exp_month: int = 0
    exp_year: int = 0
    cvc: str = ""
    holder_name: str = ""
    country: str = "US"
    state: str = ""
    city: str = ""
    address_line1: str = ""
    address_line2: str = ""
    postal_code: str = ""
    status: str = Field(default="unused", index=True)
    reserved_by_account_id: int = 0
    reserved_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    last_error: str = ""
    single_use: bool = True
    enabled: bool = True
    use_count: int = 0
    priority: int = 100
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def masked(self) -> str:
        number = (self.number or "").replace(" ", "")
        if len(number) < 8:
            return number
        return f"{number[:6]}******{number[-4:]}"


class GptPlanPaymentAccountModel(SQLModel, table=True):
    """GPT 套餐管理专属支付账号；其卡只存在于 ``gpt_plan_cards``。"""

    __tablename__ = "gpt_plan_payment_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    account_type: str = Field(default="Y", index=True)
    enabled: bool = True
    is_default: bool = False
    roxy_dir_id: str = ""
    last_card_opened_at: Optional[datetime] = None
    balance_usd: float = 0.0
    balance_text: str = ""
    balance_updated_at: Optional[datetime] = None
    paid_count: int = 0
    refunded_count: int = 0
    pending_refund_count: int = 0
    card_open_count: int = 0
    unrefunded_dates_json: str = "[]"
    pending_refund_updated_at: Optional[datetime] = None
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class BusinessMasterModel(SQLModel, table=True):
    """BUSINESS 母号(团队 workspace 的管理员账号)。存 admin.openai.com 的 Cookie,
    用于直接调 OpenAI 邀请接口批量邀请子号(不经过 CSV 上传)。以母号为维度批量邀请。"""

    __tablename__ = "business_masters"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)                      # 母号名称/邮箱/备注(必填)
    cookie_blob: str = ""                              # admin.openai.com 完整 Cookie 串(含 oai-access-token)
    workspace_id: str = ""                             # 解析出的 workspace/account id(缓存)
    enabled: bool = True
    invited_count: int = 0                             # 通过该母号累计邀请成功的子号数
    last_invite_at: Optional[datetime] = None
    cookie_expires_at: Optional[datetime] = None       # 从 JWT 解析的过期时间(展示有效性)
    stats_json: str = ""                               # 缓存的空间解析结果(成员/待接受/下期账单等)
    stats_updated_at: Optional[datetime] = None        # 空间解析上次刷新时间
    # 计费防护: plan_seats=免费/计划席位阈值(0=未设, 自动用下期账单席位数); 溢出=计费席位>阈值
    plan_seats: int = 0
    billing_paused_until: Optional[datetime] = None    # 计费防护暂停邀请/轮换到该时间(自动恢复); 空=未暂停
    note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


def list_accounts_paginated(platform: str, status: str | None,
                            page: int = 1, page_size: int = 50) -> dict:
    """按 platform/status 过滤、分页返回 AccountModel 列表。

    status=None 时不过滤状态。按 updated_at 倒序，方便看最近变化的账号。
    返回 {"total": int, "items": list[AccountModel]}。
    """
    from sqlmodel import func
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 50)))
    offset = (page - 1) * page_size
    with Session(engine) as session:
        count_stmt = select(func.count(AccountModel.id)).where(
            AccountModel.platform == platform
        )
        rows_stmt = select(AccountModel).where(
            AccountModel.platform == platform
        )
        if status:
            count_stmt = count_stmt.where(AccountModel.status == status)
            rows_stmt = rows_stmt.where(AccountModel.status == status)
        total = session.exec(count_stmt).one()
        rows = session.exec(
            rows_stmt.order_by(AccountModel.updated_at.desc())
            .offset(offset)
            .limit(page_size)
        ).all()
        return {"total": int(total or 0), "items": list(rows)}


def count_accounts_by_status(platform: str, statuses: list[str]) -> dict[str, int]:
    """批量获取每个 status 的账号数量，用于前端 tab 角标。"""
    from sqlmodel import func
    normalized = [str(st) for st in (statuses or [])]
    out: dict[str, int] = {st: 0 for st in normalized}
    if not normalized:
        return out
    with Session(engine) as session:
        rows = session.exec(
            select(AccountModel.status, func.count(AccountModel.id))
            .where(AccountModel.platform == platform)
            .where(AccountModel.status.in_(normalized))
            .group_by(AccountModel.status)
        ).all()
        for st, n in rows:
            out[str(st)] = int(n or 0)
    return out


def save_account(account) -> 'AccountModel':
    """从 base_platform.Account 存入数据库（同平台同邮箱则更新）"""
    with Session(engine) as session:
        existing = session.exec(
            select(AccountModel)
            .where(AccountModel.platform == account.platform)
            .where(AccountModel.email == account.email)
        ).first()
        if existing:
            existing.password = account.password
            existing.user_id = account.user_id or ""
            existing.region = account.region or ""
            existing.token = account.token or ""
            existing.status = account.status.value
            existing.extra_json = json.dumps(account.extra or {}, ensure_ascii=False)
            existing.cashier_url = (account.extra or {}).get("cashier_url", "")
            existing.updated_at = _utcnow()
            session.add(existing)
            session.commit()
            session.refresh(existing)
            return existing
        m = AccountModel(
            platform=account.platform,
            email=account.email,
            password=account.password,
            user_id=account.user_id or "",
            region=account.region or "",
            token=account.token or "",
            status=account.status.value,
            extra_json=json.dumps(account.extra or {}, ensure_ascii=False),
            cashier_url=(account.extra or {}).get("cashier_url", ""),
        )
        session.add(m)
        session.commit()
        session.refresh(m)
        return m


def init_db():
    # GPT PRO remains a separately visible legacy workspace until its eventual
    # retirement.  Its account/lease tables are therefore still created, but
    # GPT 套餐管理 never reads or writes them after the one-time detach copy.
    SQLModel.metadata.create_all(engine)
    if DATABASE_URL.startswith("sqlite"):
        # BUSINESS RT 页面会频繁按 platform/status 计数和分页。
        # 旧库没有组合索引时,大库轮询会放大 SQLite 锁等待。
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_accounts_platform_status_updated "
                    "ON accounts(platform, status, updated_at)"
                ))
        except Exception:
            pass
    _migrate_proxies_allow_duplicate_urls()
    _migrate_outlook_accounts()
    _migrate_sync_devices()
    _migrate_cfworker_subdomains()
    _migrate_business_domains()
    _migrate_gpt_pro_accounts()
    _migrate_gpt_plan_accounts()
    # The account migration backfills invite audit rows into this table, so
    # older development schemas must gain its columns before the backfill runs.
    _migrate_gpt_business_rotation_reservations()
    _migrate_gpt_business_accounts()
    _migrate_gpt_business_automation_policies()
    _migrate_gpt_business_child_memberships()
    _migrate_gpt_business_typed_invite_quota()
    _migrate_gpt_business_allocation_fencing()
    _migrate_delivery_device_replenishments()
    _migrate_delivery_device_team401_corrections()
    _retire_delivery_team_automation()
    _migrate_adobe_admin_accounts()
    _migrate_cards()
    _migrate_payment_accounts()
    _migrate_business_masters()
    _migrate_roxy_proxies()
    _detach_gpt_plan_support_inventory()
    _cleanup_gpt_plan_mail_cutover_false_positives()
    _migrate_stale_dead_gpt_plan_business_children()
    _migrate_claude_accounts()


def _cleanup_gpt_plan_mail_cutover_false_positives() -> dict:
    """Remove only the two proven Plan-mail cutover batches locally.

    This runs after the one-time Plan detach copy and does not contact any
    mailbox provider, so accounts with expired Graph/IMAP credentials receive
    the same narrow, idempotent queue repair as accounts whose next scan works.
    The local import avoids a module cycle while ``core.db`` is initialized.
    """
    from services.gpt_plan_mail_monitor import (
        cleanup_known_cutover_false_positives,
    )

    return cleanup_known_cutover_false_positives(database_engine=engine)


_GPT_PLAN_SUPPORT_INVENTORY_MIGRATION = "gpt_plan_support_inventory_detach_v1"


_DELIVERY_TEAM_AUTOMATION_RETIREMENT = "delivery_team_automation_retirement_v1"


def _retire_delivery_team_automation() -> dict:
    """Retire persisted CPA/Sub2API TEAM-child orchestration state once.

    The unified delivery-device page keeps local BUSINESS mother bindings but
    no longer owns TEAM-child orchestration.  Replacement/replenishment rows
    remain audit history, while no non-terminal row may keep a worker lease or
    make an old binding look like an enabled automation policy after restart.

    This migration deliberately does *not* alter GPT plan accounts, BUSINESS
    memberships, remote devices, remote credentials, or saved quota snapshots.
    """
    summary = {
        "policies_unbound": 0,
        "policies_automation_disabled": 0,
        "allocation_jobs_cancelled": 0,
        "allocation_leases_released": 0,
        "rotation_reservations_released": 0,
        "operation_leases_released": 0,
        "cleanups_cancelled": 0,
        "replenishments_cancelled": 0,
        "team401_tasks_cancelled": 0,
        "team401_batches_cancelled": 0,
    }
    if not DATABASE_URL.startswith("sqlite"):
        return {"applied": False, "reason": "non_sqlite", **summary}

    now = _utcnow().isoformat()
    retired_job_kinds = {
        "cpa_rotation",
        "sub2api_rotation",
        "initial_fill",
        "master_dispatch_fill",
        "master_dispatch",
        "device_binding_migration",
    }
    retired_operations = {
        "quota_exhausted_cleanup",
        "delivery_exhaustion_cleanup",
        "refunded_parent_device_cleanup",
        "credential_invalid_replacement",
        "credential_upload",
        "credential_repair",
        "business_fill",
        "business_allocation",
        "business_cpa_sync",
        "business_sub2api_sync",
        "business_sub2api_usage",
    }

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS app_data_migrations ("
            "name TEXT PRIMARY KEY, completed_at DATETIME NOT NULL, "
            "details_json TEXT NOT NULL DEFAULT '{}')"
        )
        previous = conn.exec_driver_sql(
            "SELECT details_json FROM app_data_migrations WHERE name = ?",
            (_DELIVERY_TEAM_AUTOMATION_RETIREMENT,),
        ).fetchone()
        if previous is not None:
            try:
                details = json.loads(str(previous[0] or "{}"))
            except Exception:
                details = {}
            return {
                "applied": False,
                **summary,
                **(details if isinstance(details, dict) else {}),
            }

        tables = {
            str(row[0])
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if "gpt_business_automation_policies" in tables:
            result = conn.exec_driver_sql(
                "UPDATE gpt_business_automation_policies SET "
                "auto_rotation_enabled = 0, "
                "rotate_default = 0, rotate_prolite = 0, "
                "last_scan_at = NULL, last_error = '', "
                "revision = coalesce(revision, 0) + 1, updated_at = ? "
                "WHERE auto_rotation_enabled != 0 "
                "OR rotate_default != 0 OR rotate_prolite != 0",
                (now,),
            )
            summary["policies_automation_disabled"] = max(
                0, int(result.rowcount or 0)
            )

        cancelled_job_ids: list[str] = []
        if "gpt_business_allocation_jobs" in tables:
            jobs = conn.exec_driver_sql(
                "SELECT id, state, request_json "
                "FROM gpt_business_allocation_jobs"
            ).fetchall()
            for job_id, state, raw_request in jobs:
                try:
                    request = json.loads(str(raw_request or "{}"))
                except Exception:
                    continue
                if not isinstance(request, dict):
                    continue
                kind = str(request.get("job_kind") or "").strip().lower()
                if kind not in retired_job_kinds:
                    continue
                if str(state or "").strip().lower() in {
                    "completed", "failed", "cancelled",
                }:
                    continue
                conn.exec_driver_sql(
                    "UPDATE gpt_business_allocation_jobs SET state = 'cancelled', "
                    "stage = 'feature_retired', worker_token = '', retryable = 0, "
                    "error = 'feature_retired', updated_at = ?, completed_at = ? "
                    "WHERE id = ?",
                    (now, now, str(job_id)),
                )
                cancelled_job_ids.append(str(job_id))
            summary["allocation_jobs_cancelled"] = len(cancelled_job_ids)

        if cancelled_job_ids and "gpt_business_allocation_leases" in tables:
            for job_id in cancelled_job_ids:
                result = conn.exec_driver_sql(
                    "DELETE FROM gpt_business_allocation_leases WHERE job_id = ?",
                    (job_id,),
                )
                summary["allocation_leases_released"] += max(
                    0, int(result.rowcount or 0)
                )

        if cancelled_job_ids and "gpt_business_rotation_reservations" in tables:
            for job_id in cancelled_job_ids:
                result = conn.exec_driver_sql(
                    "UPDATE gpt_business_rotation_reservations SET "
                    "state = 'released', resolution_reason = 'feature_retired', "
                    "resolved_at = ?, updated_at = ? "
                    "WHERE operation_id = ? AND state = 'reserved'",
                    (now, now, job_id),
                )
                summary["rotation_reservations_released"] += max(
                    0, int(result.rowcount or 0)
                )

        retired_operation_tokens: list[str] = []
        if "gpt_plan_account_operation_leases" in tables:
            placeholders = ",".join("?" for _ in retired_operations)
            retired_operation_tokens = [
                str(row[0])
                for row in conn.exec_driver_sql(
                    "SELECT token FROM gpt_plan_account_operation_leases "
                    f"WHERE operation IN ({placeholders})",
                    tuple(sorted(retired_operations)),
                ).fetchall()
                if str(row[0] or "").strip()
            ]
            result = conn.exec_driver_sql(
                "DELETE FROM gpt_plan_account_operation_leases "
                f"WHERE operation IN ({placeholders})",
                tuple(sorted(retired_operations)),
            )
            summary["operation_leases_released"] = max(
                0, int(result.rowcount or 0)
            )
        if retired_operation_tokens and "gpt_business_allocation_leases" in tables:
            for token in sorted(set(retired_operation_tokens)):
                result = conn.exec_driver_sql(
                    "DELETE FROM gpt_business_allocation_leases "
                    "WHERE owner_token = ?",
                    (token,),
                )
                summary["allocation_leases_released"] += max(
                    0, int(result.rowcount or 0)
                )

        retired_durable_ids: set[str] = set()
        if "delivery_device_exhaustion_cleanups" in tables:
            retired_durable_ids.update(
                str(row[0])
                for row in conn.exec_driver_sql(
                    "SELECT id FROM delivery_device_exhaustion_cleanups "
                    "WHERE lower(trim(coalesce(state, ''))) "
                    "NOT IN ('completed', 'superseded', 'cancelled')"
                ).fetchall()
                if str(row[0] or "").strip()
            )
            result = conn.exec_driver_sql(
                "UPDATE delivery_device_exhaustion_cleanups SET "
                "state = 'cancelled', stage = 'feature_retired', "
                "worker_token = '', lease_expires_at = NULL, resume_at = NULL, "
                "error = 'feature_retired', updated_at = ?, completed_at = ? "
                "WHERE lower(trim(coalesce(state, ''))) "
                "NOT IN ('completed', 'superseded', 'cancelled')",
                (now, now),
            )
            summary["cleanups_cancelled"] = max(0, int(result.rowcount or 0))

        if "delivery_device_replenishment_demands" in tables:
            retired_durable_ids.update(
                str(row[0])
                for row in conn.exec_driver_sql(
                    "SELECT id FROM delivery_device_replenishment_demands "
                    "WHERE lower(trim(coalesce(state, ''))) "
                    "NOT IN ('completed', 'cancelled')"
                ).fetchall()
                if str(row[0] or "").strip()
            )
            result = conn.exec_driver_sql(
                "UPDATE delivery_device_replenishment_demands SET "
                "state = 'cancelled', stage = 'feature_retired', "
                "worker_token = '', lease_expires_at = NULL, "
                "next_check_at = NULL, resume_at = NULL, "
                "error = 'feature_retired', updated_at = ?, completed_at = ? "
                "WHERE lower(trim(coalesce(state, ''))) "
                "NOT IN ('completed', 'cancelled')",
                (now, now),
            )
            summary["replenishments_cancelled"] = max(
                0, int(result.rowcount or 0)
            )

        if "delivery_device_team401_tasks" in tables:
            retired_durable_ids.update(
                str(row[0])
                for row in conn.exec_driver_sql(
                    "SELECT id FROM delivery_device_team401_tasks "
                    "WHERE lower(trim(coalesce(state, ''))) "
                    "NOT IN ('completed', 'failed', 'cancelled')"
                ).fetchall()
                if str(row[0] or "").strip()
            )
            result = conn.exec_driver_sql(
                "UPDATE delivery_device_team401_tasks SET "
                "state = 'cancelled', stage = 'feature_retired', "
                "result = 'cancelled', error_code = 'feature_retired', "
                "worker_token = '', lease_expires_at = NULL, "
                "next_check_at = NULL, updated_at = ?, completed_at = ? "
                "WHERE lower(trim(coalesce(state, ''))) "
                "NOT IN ('completed', 'failed', 'cancelled')",
                (now, now),
            )
            summary["team401_tasks_cancelled"] = max(
                0, int(result.rowcount or 0)
            )

        if "delivery_device_team401_batches" in tables:
            retired_durable_ids.update(
                str(row[0])
                for row in conn.exec_driver_sql(
                    "SELECT id FROM delivery_device_team401_batches "
                    "WHERE lower(trim(coalesce(state, ''))) "
                    "NOT IN ('completed', 'failed', 'cancelled')"
                ).fetchall()
                if str(row[0] or "").strip()
            )
            result = conn.exec_driver_sql(
                "UPDATE delivery_device_team401_batches SET "
                "state = 'cancelled', error_code = 'feature_retired', "
                "updated_at = ?, completed_at = ? "
                "WHERE lower(trim(coalesce(state, ''))) "
                "NOT IN ('completed', 'failed', 'cancelled')",
                (now, now),
            )
            summary["team401_batches_cancelled"] = max(
                0, int(result.rowcount or 0)
            )

        if retired_durable_ids and "gpt_business_allocation_leases" in tables:
            for durable_id in sorted(retired_durable_ids):
                result = conn.exec_driver_sql(
                    "DELETE FROM gpt_business_allocation_leases WHERE job_id = ?",
                    (durable_id,),
                )
                summary["allocation_leases_released"] += max(
                    0, int(result.rowcount or 0)
                )

        conn.exec_driver_sql(
            "INSERT INTO app_data_migrations(name, completed_at, details_json) "
            "VALUES (?, ?, ?)",
            (
                _DELIVERY_TEAM_AUTOMATION_RETIREMENT,
                now,
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
            ),
        )
    return {"applied": True, **summary}


def _detach_gpt_plan_support_inventory() -> dict:
    """One-time copy of legacy UI inventory into Plan-owned tables.

    This deliberately uses a durable marker instead of an ``if empty`` check:
    deleting every Plan card/proxy later must not cause a restart to repopulate
    it from the GPT PRO workspace.  Integer ids are preserved so existing Plan
    upgrade summaries and ``extra_json`` references remain valid.
    """

    summary = {
        "payment_accounts": 0,
        "cards": 0,
        "roxy_proxies": 0,
        "cpa_proxies": 0,
        "config_keys": 0,
        "plan_card_reservations": 0,
        "legacy_cards_were_plan_keyed": False,
    }
    if not DATABASE_URL.startswith("sqlite"):
        return {"applied": False, "reason": "non_sqlite", **summary}

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS app_data_migrations ("
            "name TEXT PRIMARY KEY, completed_at DATETIME NOT NULL, "
            "details_json TEXT NOT NULL DEFAULT '{}')"
        )
        previous = conn.exec_driver_sql(
            "SELECT details_json FROM app_data_migrations WHERE name = ?",
            (_GPT_PLAN_SUPPORT_INVENTORY_MIGRATION,),
        ).fetchone()
        if previous is not None:
            try:
                details = json.loads(str(previous[0] or "{}"))
            except Exception:
                details = {}
            return {
                "applied": False,
                **summary,
                **(details if isinstance(details, dict) else {}),
            }

        tables = {
            str(row[0])
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        def copy_table(source: str, target: str, summary_key: str) -> None:
            if source not in tables or target not in tables:
                return
            source_columns = {
                str(row[1])
                for row in conn.exec_driver_sql(
                    f"PRAGMA table_info({source})"
                ).fetchall()
            }
            target_columns = [
                str(row[1])
                for row in conn.exec_driver_sql(
                    f"PRAGMA table_info({target})"
                ).fetchall()
            ]
            columns = [name for name in target_columns if name in source_columns]
            if not columns:
                return
            quoted = ", ".join(f'"{name}"' for name in columns)
            result = conn.exec_driver_sql(
                f"INSERT OR IGNORE INTO {target} ({quoted}) "
                f"SELECT {quoted} FROM {source}"
            )
            summary[summary_key] = max(0, int(result.rowcount or 0))

        copy_table("payment_accounts", "gpt_plan_payment_accounts", "payment_accounts")
        copy_table("cards", "gpt_plan_cards", "cards")
        copy_table("roxy_proxies", "gpt_plan_roxy_proxies", "roxy_proxies")
        copy_table("cpa_proxy_pool", "gpt_plan_cpa_proxy_pool", "cpa_proxies")

        # detach_v2 in early deployments rewrote the shared legacy card owner
        # to a Plan id.  Its transaction marker tells us whether the source rows
        # are already Plan-keyed.  Preserve that value in the Plan copy without
        # trying to guess an inverse mapping in the legacy table: integer-id
        # collisions make such a guess unsafe, so deployed databases restore
        # the legacy owner from their pre-resource backup.  New deployments
        # never mutate legacy cards and rekey only the Plan copy below.
        detach_details: dict = {}
        detach_marker = conn.exec_driver_sql(
            "SELECT details_json FROM app_data_migrations WHERE name = ?",
            (_GPT_PLAN_PRO_DETACH_MIGRATION,),
        ).fetchone()
        if detach_marker is not None:
            try:
                parsed = json.loads(str(detach_marker[0] or "{}"))
                detach_details = parsed if isinstance(parsed, dict) else {}
            except Exception:
                detach_details = {}
        legacy_cards_were_rekeyed = int(
            detach_details.get("card_reservations") or 0
        ) > 0
        summary["legacy_cards_were_plan_keyed"] = legacy_cards_were_rekeyed
        can_rekey_cards = {
            "accounts",
            "cards",
            "gpt_plan_cards",
            "gpt_pro_accounts",
            "gpt_pro_to_plan_account_crosswalk",
        }.issubset(tables)
        if can_rekey_cards and legacy_cards_were_rekeyed:
            summary["plan_card_reservations"] = int(
                detach_details.get("card_reservations") or 0
            )
        elif can_rekey_cards:
            rekeyed = conn.exec_driver_sql(
                "UPDATE gpt_plan_cards SET reserved_by_account_id = ("
                "SELECT x.plan_account_id FROM "
                "gpt_pro_to_plan_account_crosswalk x "
                "WHERE x.old_pro_account_id = "
                "gpt_plan_cards.reserved_by_account_id) "
                "WHERE EXISTS (SELECT 1 FROM "
                "gpt_pro_to_plan_account_crosswalk x "
                "JOIN gpt_pro_accounts p ON p.id = x.old_pro_account_id "
                "WHERE x.old_pro_account_id = "
                "gpt_plan_cards.reserved_by_account_id "
                "AND (NOT EXISTS (SELECT 1 FROM accounts a "
                "WHERE a.id = x.old_pro_account_id) "
                "OR (trim(coalesce(p.payment_card_last4, '')) != '' "
                "AND substr(replace(gpt_plan_cards.number, ' ', ''), -4) = "
                "trim(p.payment_card_last4))))"
            )
            summary["plan_card_reservations"] = max(
                0,
                int(rekeyed.rowcount or 0),
            )

        if "configs" in tables:
            config_keys = {
                "gpt_upgrade_browser_backend": "gpt_plan_upgrade_browser_backend",
                "gpt_upgrade_roxy_proxy_id": "gpt_plan_upgrade_roxy_proxy_id",
                "gpt_pro_checkout_country": "gpt_plan_checkout_country",
                "gpt_pro_checkout_currency": "gpt_plan_checkout_currency",
                "gpt_pro_card_max_uses": "gpt_plan_card_max_uses",
                "gpt_pro_ph_go_first": "gpt_plan_ph_go_first",
                "gpt_pro_go_plan_name": "gpt_plan_go_plan_name",
                "gpt_pro_go_to_pro_wait_seconds": "gpt_plan_go_to_pro_wait_seconds",
                "gpt_pro_app_reply_wait_seconds": "gpt_plan_app_reply_wait_seconds",
                "gpt_pro_auto_delete_dead_on_login": "gpt_plan_auto_delete_dead_on_login",
                "gpt_pro_cpa_api_key": "gpt_plan_cpa_api_key",
                "gpt_pro_cpa_api_url": "gpt_plan_cpa_api_url",
                "gpt_pro_cpa_auto_buy": "gpt_plan_cpa_auto_buy",
                "gpt_pro_cpa_auto_refund_enabled": "gpt_plan_cpa_auto_refund_enabled",
                "gpt_pro_cpa_device_id": "gpt_plan_cpa_device_id",
                "gpt_pro_cpa_devices": "gpt_plan_cpa_devices",
                "gpt_pro_cpa_enabled": "gpt_plan_cpa_enabled",
                "gpt_pro_cpa_interval_minutes": "gpt_plan_cpa_interval_minutes",
                "gpt_pro_cpa_max_per_run": "gpt_plan_cpa_max_per_run",
                "gpt_pro_cpa_recycle_hour": "gpt_plan_cpa_recycle_hour",
                "gpt_pro_cpa_refund_days": "gpt_plan_cpa_refund_days",
                "gpt_pro_cpa_threshold": "gpt_plan_cpa_threshold",
                "gpt_pro_cpa_sync_targets": "gpt_plan_cpa_sync_targets",
                "gpt_pro_cpa_sync_targets_revision": "gpt_plan_cpa_sync_targets_revision",
                "gpt_pro_referral_cf_domain": "gpt_plan_referral_cf_domain",
                "gpt_pro_referral_cf_domains_json": "gpt_plan_referral_cf_domains_json",
                "gpt_pro_reward_wait_seconds": "gpt_plan_reward_wait_seconds",
                "gpt_pro_sub2api_auto_remove": "gpt_plan_sub2api_auto_remove",
            }
            for old_key, plan_key in config_keys.items():
                result = conn.exec_driver_sql(
                    "INSERT OR IGNORE INTO configs(key, value) "
                    "SELECT ?, value FROM configs WHERE key = ?",
                    (plan_key, old_key),
                )
                summary["config_keys"] += max(0, int(result.rowcount or 0))

        conn.exec_driver_sql(
            "INSERT INTO app_data_migrations(name, completed_at, details_json) "
            "VALUES (?, ?, ?)",
            (
                _GPT_PLAN_SUPPORT_INVENTORY_MIGRATION,
                _utcnow().isoformat(),
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
            ),
        )
    return {"applied": True, **summary}


def _migrate_delivery_device_replenishments():
    """Forward-compatible indexes for the durable replenishment queue.

    ``create_all`` creates the new table on both fresh and existing databases.
    Keeping the index creation explicit makes deployments which already ran an
    early development version of the table converge on the scheduler query
    shape as well.
    """
    try:
        with engine.begin() as conn:
            if conn.dialect.name == "sqlite":
                columns = {
                    str(row[1]).lower()
                    for row in conn.exec_driver_sql(
                        "PRAGMA table_info(delivery_device_exhaustion_cleanups)"
                    ).fetchall()
                }
                if columns and "business_remove_confirmed" not in columns:
                    conn.exec_driver_sql(
                        "ALTER TABLE delivery_device_exhaustion_cleanups "
                        "ADD COLUMN business_remove_confirmed BOOLEAN NOT NULL DEFAULT 0"
                    )
                if columns and "manual_operation_id" not in columns:
                    conn.exec_driver_sql(
                        "ALTER TABLE delivery_device_exhaustion_cleanups "
                        "ADD COLUMN manual_operation_id VARCHAR"
                    )
                if columns and "resume_at" not in columns:
                    conn.exec_driver_sql(
                        "ALTER TABLE delivery_device_exhaustion_cleanups "
                        "ADD COLUMN resume_at DATETIME"
                    )
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "ux_delivery_cleanup_manual_operation "
                    "ON delivery_device_exhaustion_cleanups(manual_operation_id)"
                ))
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS "
                    "ix_delivery_cleanup_due "
                    "ON delivery_device_exhaustion_cleanups"
                    "(state, resume_at, updated_at)"
                ))
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_delivery_replenishment_cleanup_job "
                "ON delivery_device_replenishment_demands(cleanup_job_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS "
                "ix_delivery_replenishment_due "
                "ON delivery_device_replenishment_demands"
                "(state, next_check_at, updated_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS "
                "ix_delivery_replenishment_parent_time "
                "ON delivery_device_replenishment_demands"
                "(business_parent_id, created_at)"
            ))
    except Exception:
        # Migrations in this legacy module are intentionally best effort.  A
        # missing table is still surfaced by the API/runner instead of making
        # application startup destructive.
        pass


def _migrate_delivery_device_team401_corrections():
    """Converge indexes used by the durable TEAM 401 recovery scheduler."""
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_delivery_team401_batch_scope "
                "ON delivery_device_team401_batches"
                "(provider, provider_id, business_parent_id, state, updated_at)"
            ))
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_delivery_team401_batch_operation "
                "ON delivery_device_team401_batches(operation_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_delivery_team401_task_due "
                "ON delivery_device_team401_tasks"
                "(state, next_check_at, updated_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_delivery_team401_task_batch "
                "ON delivery_device_team401_tasks(batch_id, created_at)"
            ))
    except Exception:
        # ``create_all`` owns table creation.  Keep legacy startup best-effort
        # and let an API query surface an unavailable table explicitly.
        pass


def _migrate_claude_accounts():
    """给 claude_accounts 补新增列(新表由 create_all 建全, 此处仅为已有库前向兼容)。"""
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    conn = None
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "claude_accounts" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(claude_accounts)").fetchall()
        }
        for col_name, col_ddl in (
            ("recovery_email", "VARCHAR NOT NULL DEFAULT ''"),
            ("totp_secret", "VARCHAR NOT NULL DEFAULT ''"),
            ("code_api_url", "VARCHAR NOT NULL DEFAULT ''"),
            ("registered", "BOOLEAN NOT NULL DEFAULT 0"),
            ("registered_at", "TIMESTAMP"),
            ("session_key", "VARCHAR NOT NULL DEFAULT ''"),
            ("org_id", "VARCHAR NOT NULL DEFAULT ''"),
            ("roxy_dir_id", "VARCHAR NOT NULL DEFAULT ''"),
            ("roxy_proxy_id", "INTEGER"),
            ("proxy_label", "VARCHAR NOT NULL DEFAULT ''"),
        ):
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE claude_accounts ADD COLUMN {col_name} {col_ddl}")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_roxy_proxies():
    """给 roxy_proxies 加 check_status / checked_at 字段(可用性检测)。空表/旧表都安全。"""
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    conn = None
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "roxy_proxies" not in tables:
            conn.close()
            return
        existing = {row[1].lower() for row in conn.execute("PRAGMA table_info(roxy_proxies)").fetchall()}
        for col_name, col_ddl in (
            ("check_status", "INTEGER NOT NULL DEFAULT -1"),
            ("checked_at", "TIMESTAMP"),
        ):
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE roxy_proxies ADD COLUMN {col_name} {col_ddl}")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_business_domains():
    """加 owner_machine_id 字段 (机器隔离)。空表 / 旧表都安全。"""
    new_columns = [
        ("owner_machine_id", "VARCHAR NOT NULL DEFAULT ''"),
    ]
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "business_domains" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(business_domains)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(
                    f"ALTER TABLE business_domains ADD COLUMN {col_name} {col_ddl}"
                )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_proxies_allow_duplicate_urls():
    """允许同一代理网关 URL 重复入库。

    轮换代理常见表现是 URL 完全一致，但每次连接/每个 session 出口 IP 不同。
    旧表有 UNIQUE(url)，会导致运营无法按并发容量添加多行。SQLite 不能直接
    DROP UNIQUE CONSTRAINT，这里在检测到 url 唯一索引时重建 proxies 表。
    """
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "proxies" not in tables:
            conn.close()
            return

        create_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='proxies'"
        ).fetchone()
        create_sql = str(create_sql_row[0] if create_sql_row else "")
        index_rows = conn.execute("PRAGMA index_list(proxies)").fetchall()
        has_url_unique = "UNIQUE (URL)" in create_sql.upper()
        if not has_url_unique:
            for row in index_rows:
                # PRAGMA index_list: seq, name, unique, origin, partial
                if not row[2]:
                    continue
                index_name = str(row[1]).replace('"', '""')
                cols = [
                    info[2]
                    for info in conn.execute(f'PRAGMA index_info("{index_name}")').fetchall()
                ]
                if cols == ["url"]:
                    has_url_unique = True
                    break
        if not has_url_unique:
            conn.close()
            return

        conn.execute("ALTER TABLE proxies RENAME TO proxies_old_unique_url")
        conn.execute(
            """
            CREATE TABLE proxies (
                id INTEGER NOT NULL,
                url VARCHAR NOT NULL,
                region VARCHAR NOT NULL,
                success_count INTEGER NOT NULL,
                fail_count INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL,
                last_checked DATETIME,
                PRIMARY KEY (id)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO proxies (
                id, url, region, success_count, fail_count, is_active, last_checked
            )
            SELECT id, url, region, success_count, fail_count, is_active, last_checked
            FROM proxies_old_unique_url
            """
        )
        conn.execute("DROP TABLE proxies_old_unique_url")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_gpt_pro_accounts():
    """Prepare the legacy table only for its single detach transaction."""
    new_columns = [
        ("last_mail_check_at", "DATETIME"),
        ("last_mail_check_error", "VARCHAR NOT NULL DEFAULT ''"),
        ("seen_mail_ids_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("pending_alerts_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("pending_inbox_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("subscribed_at", "DATETIME"),
        ("payment_card_last4", "VARCHAR NOT NULL DEFAULT ''"),
        ("refund_status", "VARCHAR NOT NULL DEFAULT ''"),
        ("refund_detected_at", "DATETIME"),
        ("refund_credited_at", "DATETIME"),
        ("human_review_requested_at", "DATETIME"),
        ("refund_rejected_at", "DATETIME"),
        ("refund_manual_at", "DATETIME"),
        ("dangerous", "BOOLEAN NOT NULL DEFAULT 0"),
        ("dangerous_detected_at", "DATETIME"),
        ("appeal_url", "VARCHAR NOT NULL DEFAULT ''"),
        ("appeal_done_at", "DATETIME"),
        ("cookie_blob", "TEXT NOT NULL DEFAULT ''"),
        ("cookie_updated_at", "DATETIME"),
        ("cookie_expires_at", "DATETIME"),
        ("policy_warning", "BOOLEAN NOT NULL DEFAULT 0"),
        ("policy_warning_detected_at", "DATETIME"),
        ("codex_access_token", "TEXT NOT NULL DEFAULT ''"),
        ("codex_refresh_token", "TEXT NOT NULL DEFAULT ''"),
        ("codex_id_token", "TEXT NOT NULL DEFAULT ''"),
        ("codex_session_token", "TEXT NOT NULL DEFAULT ''"),
        ("codex_rt_acquired_at", "DATETIME"),
        ("referral_remaining", "INTEGER"),
        ("referral_quota_checked_at", "DATETIME"),
        ("referral_invited_emails_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("referral_confirmed_emails_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("business_parent_id", "INTEGER"),
        ("business_invited_at", "DATETIME"),
        ("extra_json", "TEXT NOT NULL DEFAULT '{}'"),
    ]
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "app_data_migrations" in tables and conn.execute(
            "SELECT 1 FROM app_data_migrations WHERE name = ?",
            (_GPT_PLAN_PRO_DETACH_MIGRATION,),
        ).fetchone() is not None:
            # After cutover, startup may not inspect or evolve the retired
            # authority.  It remains untouched solely as preserved user data.
            conn.close()
            return
        if "gpt_pro_accounts" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(gpt_pro_accounts)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE gpt_pro_accounts ADD COLUMN {col_name} {col_ddl}")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_pro_accounts_business_parent_id "
            "ON gpt_pro_accounts(business_parent_id)"
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


_GPT_PLAN_PRO_DETACH_MIGRATION = "gpt_plan_detach_gpt_pro_v2"
_GPT_PLAN_STALE_DEAD_CHILD_CLEANUP_MIGRATION = (
    "gpt_plan_stale_dead_business_children_v1"
)


def _sqlite_ddl_parenthesis_bounds(create_sql: str) -> tuple[int, int]:
    """Return the outer column-list bounds of one SQLite CREATE TABLE DDL."""
    quote = ""
    opening = -1
    depth = 0
    index = 0
    while index < len(create_sql):
        char = create_sql[index]
        if quote:
            closing = "]" if quote == "[" else quote
            if char == closing:
                if closing != "]" and index + 1 < len(create_sql) \
                        and create_sql[index + 1] == closing:
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`", "["}:
            quote = char
            index += 1
            continue
        if char == "(":
            if opening < 0:
                opening = index
            depth += 1
        elif char == ")" and opening >= 0:
            depth -= 1
            if depth == 0:
                return opening, index
        index += 1
    raise RuntimeError("GPT Plan AUTOINCREMENT migration found invalid table DDL")


def _sqlite_split_top_level_csv(value: str) -> list[str]:
    """Split a SQLite definition list without splitting defaults/constraints."""
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ""
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            closing = "]" if quote == "[" else quote
            if char == closing:
                if closing != "]" and index + 1 < len(value) \
                        and value[index + 1] == closing:
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`", "["}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
        index += 1
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def _sqlite_definition_identifier(definition: str) -> str:
    stripped = definition.lstrip()
    if not stripped:
        return ""
    if stripped[0] in {'"', "`", "["}:
        opening = stripped[0]
        closing = "]" if opening == "[" else opening
        index = 1
        identifier = ""
        while index < len(stripped):
            char = stripped[index]
            if char == closing:
                if closing != "]" and index + 1 < len(stripped) \
                        and stripped[index + 1] == closing:
                    identifier += closing
                    index += 2
                    continue
                return identifier
            identifier += char
            index += 1
        return ""
    return re.split(r"\s+", stripped, maxsplit=1)[0]


def _gpt_plan_autoincrement_create_sql(create_sql: str) -> str:
    """Rewrite the existing Plan DDL without dropping unknown columns/options."""
    if re.search(r"\bAUTOINCREMENT\b", create_sql, flags=re.IGNORECASE):
        return create_sql
    opening, closing = _sqlite_ddl_parenthesis_bounds(create_sql)
    suffix = create_sql[closing + 1:]
    if re.search(r"\bWITHOUT\s+ROWID\b", suffix, flags=re.IGNORECASE):
        raise RuntimeError("GPT Plan AUTOINCREMENT cannot upgrade WITHOUT ROWID")

    definitions = _sqlite_split_top_level_csv(create_sql[opening + 1:closing])
    rewritten: list[str] = []
    id_column_found = False
    table_primary_key_found = False
    table_primary_key = re.compile(
        r"^\s*(?:CONSTRAINT\s+(?:\[[^]]+\]|`[^`]+`|\"(?:\"\"|[^\"])+\"|\S+)\s+)?"
        r"PRIMARY\s+KEY\s*\(\s*(?:\[id\]|`id`|\"id\"|id)\s*\)"
        r"(?:\s+ON\s+CONFLICT\s+\w+)?\s*$",
        flags=re.IGNORECASE,
    )
    any_table_primary_key = re.compile(
        r"^\s*(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY\s*\(",
        flags=re.IGNORECASE,
    )
    inline_primary_key = re.compile(
        r"\bPRIMARY\s+KEY(?:\s+(?:ASC|DESC))?"
        r"(?:\s+ON\s+CONFLICT\s+\w+)?",
        flags=re.IGNORECASE,
    )
    for definition in definitions:
        if table_primary_key.fullmatch(definition):
            table_primary_key_found = True
            continue
        if any_table_primary_key.search(definition):
            raise RuntimeError(
                "GPT Plan AUTOINCREMENT found an unsupported primary key"
            )
        if _sqlite_definition_identifier(definition).lower() != "id":
            rewritten.append(definition)
            continue
        id_column_found = True
        primary_match = inline_primary_key.search(definition)
        if primary_match is None:
            definition = f"{definition.rstrip()} PRIMARY KEY AUTOINCREMENT"
        else:
            definition = (
                f"{definition[:primary_match.end()]} AUTOINCREMENT"
                f"{definition[primary_match.end():]}"
            )
        rewritten.append(definition)
    if not id_column_found:
        raise RuntimeError("GPT Plan AUTOINCREMENT migration found no id column")
    if not table_primary_key_found and not any(
        inline_primary_key.search(part)
        for part in definitions
        if _sqlite_definition_identifier(part).lower() == "id"
    ):
        raise RuntimeError("GPT Plan AUTOINCREMENT migration found no id primary key")
    body = ",\n\t".join(rewritten)
    return f"{create_sql[:opening + 1]}\n\t{body}\n{create_sql[closing:]}"


def _sqlite_quote_identifier(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _ensure_gpt_plan_accounts_autoincrement(conn) -> dict:
    """Atomically rebuild an existing Plan table with non-reusable identities.

    The rebuild derives its DDL from ``sqlite_master`` rather than current ORM
    metadata so deployment-local forward-compatible columns, constraints,
    indexes and triggers survive unchanged.  A savepoint makes every DDL and
    data-copy step rollback together with the caller's startup transaction.
    """
    table_name = "gpt_plan_accounts"
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    if row is None:
        return {"applied": False, "reason": "table_missing", "rows": 0}
    create_sql = str(row[0] or "")
    if re.search(r"\bAUTOINCREMENT\b", create_sql, flags=re.IGNORECASE):
        count = int(conn.execute(
            f"SELECT count(*) FROM {_sqlite_quote_identifier(table_name)}"
        ).fetchone()[0] or 0)
        return {"applied": False, "reason": "already_autoincrement", "rows": count}

    table_info = conn.execute(
        f"PRAGMA table_xinfo({_sqlite_quote_identifier(table_name)})"
    ).fetchall()
    primary = [info for info in table_info if int(info[5] or 0) > 0]
    if len(primary) != 1 or str(primary[0][1]).lower() != "id" \
            or str(primary[0][2]).strip().upper() != "INTEGER":
        raise RuntimeError(
            "GPT Plan AUTOINCREMENT requires one INTEGER PRIMARY KEY id"
        )
    visible_columns = [str(info[1]) for info in table_info if int(info[6] or 0) == 0]
    if not visible_columns:
        raise RuntimeError("GPT Plan AUTOINCREMENT found no copyable columns")

    index_rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
        "AND tbl_name = ? AND sql IS NOT NULL ORDER BY name",
        (table_name,),
    ).fetchall()
    trigger_rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
        "AND tbl_name = ? AND sql IS NOT NULL ORDER BY name",
        (table_name,),
    ).fetchall()
    rebuilt_sql = _gpt_plan_autoincrement_create_sql(create_sql)
    backup_name = "gpt_plan_accounts__autoincrement_v1_old"
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name = ?", (backup_name,),
    ).fetchone() is not None:
        raise RuntimeError("GPT Plan AUTOINCREMENT backup table already exists")

    quoted_table = _sqlite_quote_identifier(table_name)
    quoted_backup = _sqlite_quote_identifier(backup_name)
    quoted_columns = ", ".join(
        _sqlite_quote_identifier(column) for column in visible_columns
    )
    before_count = int(conn.execute(
        f"SELECT count(*) FROM {quoted_table}"
    ).fetchone()[0] or 0)
    before_max_id = int(conn.execute(
        f"SELECT coalesce(max(id), 0) FROM {quoted_table}"
    ).fetchone()[0] or 0)
    previous_legacy_alter = int(
        conn.execute("PRAGMA legacy_alter_table").fetchone()[0] or 0
    )
    conn.execute("PRAGMA legacy_alter_table = ON")
    conn.execute("SAVEPOINT gpt_plan_autoincrement_rebuild")
    try:
        conn.execute(f"ALTER TABLE {quoted_table} RENAME TO {quoted_backup}")
        conn.execute(rebuilt_sql)
        conn.execute(
            f"INSERT INTO {quoted_table} ({quoted_columns}) "
            f"SELECT {quoted_columns} FROM {quoted_backup}"
        )
        missing = conn.execute(
            f"SELECT 1 FROM (SELECT {quoted_columns} FROM {quoted_backup} "
            f"EXCEPT SELECT {quoted_columns} FROM {quoted_table}) LIMIT 1"
        ).fetchone()
        extra = conn.execute(
            f"SELECT 1 FROM (SELECT {quoted_columns} FROM {quoted_table} "
            f"EXCEPT SELECT {quoted_columns} FROM {quoted_backup}) LIMIT 1"
        ).fetchone()
        if missing is not None or extra is not None:
            raise RuntimeError("GPT Plan AUTOINCREMENT data copy mismatch")

        conn.execute(f"DROP TABLE {quoted_backup}")
        for _name, index_sql in index_rows:
            conn.execute(str(index_sql))
        for _name, trigger_sql in trigger_rows:
            conn.execute(str(trigger_sql))

        after_info = conn.execute(
            f"PRAGMA table_xinfo({quoted_table})"
        ).fetchall()
        before_signature = [
            (str(info[1]), str(info[2]), int(info[3]), info[4], int(info[5]), int(info[6]))
            for info in table_info
        ]
        after_signature = [
            (str(info[1]), str(info[2]), int(info[3]), info[4], int(info[5]), int(info[6]))
            for info in after_info
        ]
        if before_signature != after_signature:
            raise RuntimeError("GPT Plan AUTOINCREMENT schema copy mismatch")
        after_count = int(conn.execute(
            f"SELECT count(*) FROM {quoted_table}"
        ).fetchone()[0] or 0)
        if after_count != before_count:
            raise RuntimeError("GPT Plan AUTOINCREMENT row count mismatch")
        for index_name, _index_sql in index_rows:
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ? "
                "AND tbl_name = ?",
                (str(index_name), table_name),
            ).fetchone() is None:
                raise RuntimeError(
                    f"GPT Plan AUTOINCREMENT lost index {index_name}"
                )
        for trigger_name, _trigger_sql in trigger_rows:
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ? "
                "AND tbl_name = ?",
                (str(trigger_name), table_name),
            ).fetchone() is None:
                raise RuntimeError(
                    f"GPT Plan AUTOINCREMENT lost trigger {trigger_name}"
                )
        sequence = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = ?", (table_name,),
        ).fetchone()
        if before_max_id > 0 and (
            sequence is None or int(sequence[0] or 0) < before_max_id
        ):
            raise RuntimeError("GPT Plan AUTOINCREMENT sequence was not preserved")
        conn.execute("RELEASE SAVEPOINT gpt_plan_autoincrement_rebuild")
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT gpt_plan_autoincrement_rebuild")
        conn.execute("RELEASE SAVEPOINT gpt_plan_autoincrement_rebuild")
        raise
    finally:
        conn.execute(
            f"PRAGMA legacy_alter_table = {1 if previous_legacy_alter else 0}"
        )
    return {"applied": True, "rows": before_count, "max_id": before_max_id}

_GPT_PLAN_CHILD_ID_JSON_KEYS = frozenset({
    "pro_account_id",
    "old_pro_account_id",
    "new_pro_account_id",
    "replacement_pro_account_id",
    "requested_pro_account_id",
    "selected_pro_account_id",
    "managed_pro_account_id",
    "auto_selected_pro_account_id",
    "resolved_new_pro_account_id",
    "referrer_pro_account_id",
    "child_id",
    "old_child_id",
    "rt_child_id",
    "selected_child_id",
})
_GPT_PLAN_CHILD_ID_LIST_JSON_KEYS = frozenset({
    "pro_account_ids",
    "managed_child_ids",
    "eligible_history_pro_account_ids",
    "prelogin_pro_account_ids",
    "prelogin_completed_pro_account_ids",
})


def _mapped_plan_account_id(value: object, crosswalk: dict[int, int]) -> object:
    if value is None or isinstance(value, bool):
        return value
    try:
        old_id = int(value)
    except (TypeError, ValueError):
        return value
    return crosswalk.get(old_id, value)


def _rekey_gpt_plan_child_json(
    value: object,
    crosswalk: dict[int, int],
    *,
    parent_key: str = "",
    root_account_id: bool = False,
    id_keys: frozenset[str] = _GPT_PLAN_CHILD_ID_JSON_KEYS,
    id_list_keys: frozenset[str] = _GPT_PLAN_CHILD_ID_LIST_JSON_KEYS,
) -> object:
    """Re-key only keys whose persisted contract denotes a managed child.

    A generic ``account_id`` is intentionally *not* rewritten: nested quota
    responses use that name for OpenAI UUIDs and other records use it for a
    BUSINESS parent.  The delivery-cleanup root is the sole explicit exception.
    """
    if isinstance(value, list):
        if parent_key in id_list_keys:
            return [_mapped_plan_account_id(item, crosswalk) for item in value]
        return [
            _rekey_gpt_plan_child_json(
                item,
                crosswalk,
                parent_key=parent_key,
                root_account_id=False,
                id_keys=id_keys,
                id_list_keys=id_list_keys,
            )
            for item in value
        ]
    if not isinstance(value, dict):
        return value

    rewritten: dict = {}
    for key, item in value.items():
        normalized_key = str(key)
        if normalized_key in id_keys:
            rewritten[key] = _mapped_plan_account_id(item, crosswalk)
        elif normalized_key in id_list_keys \
                and isinstance(item, list):
            rewritten[key] = [
                _mapped_plan_account_id(child_id, crosswalk)
                for child_id in item
            ]
        elif root_account_id and normalized_key == "account_id":
            rewritten[key] = _mapped_plan_account_id(item, crosswalk)
        elif parent_key == "children" and normalized_key.isdigit():
            mapped_key = _mapped_plan_account_id(int(normalized_key), crosswalk)
            rewritten[str(mapped_key)] = _rekey_gpt_plan_child_json(
                item,
                crosswalk,
                parent_key=normalized_key,
                id_keys=id_keys,
                id_list_keys=id_list_keys,
            )
        else:
            rewritten[key] = _rekey_gpt_plan_child_json(
                item,
                crosswalk,
                parent_key=normalized_key,
                id_keys=id_keys,
                id_list_keys=id_list_keys,
            )
    return rewritten


def _rewrite_gpt_plan_json_column(
    conn,
    table: str,
    column: str,
    crosswalk: dict[int, int],
    *,
    root_account_id: bool = False,
    refresh_request_hash: bool = False,
    id_keys: frozenset[str] = _GPT_PLAN_CHILD_ID_JSON_KEYS,
    id_list_keys: frozenset[str] = _GPT_PLAN_CHILD_ID_LIST_JSON_KEYS,
) -> int:
    changed = 0
    primary_keys = [
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        if int(row[5] or 0) > 0
    ]
    if len(primary_keys) != 1:
        return 0
    primary_key = primary_keys[0]
    for row in conn.execute(
        f"SELECT {primary_key}, {column} FROM {table}"
    ).fetchall():
        raw = str(row[column] or "")
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except Exception:
            # Historical corrupt JSON remains untouched; guessing at a textual
            # replacement could mutate unrelated UUIDs or parent ids.
            continue
        rewritten = _rekey_gpt_plan_child_json(
            parsed,
            crosswalk,
            root_account_id=root_account_id,
            id_keys=id_keys,
            id_list_keys=id_list_keys,
        )
        encoded = json.dumps(
            rewritten,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        canonical_before = json.dumps(
            parsed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if encoded == canonical_before:
            continue
        if refresh_request_hash and column == "request_json":
            conn.execute(
                f"UPDATE {table} SET {column} = ?, request_hash = ? "
                f"WHERE {primary_key} = ?",
                (
                    encoded,
                    hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                    row[primary_key],
                ),
            )
        else:
            conn.execute(
                f"UPDATE {table} SET {column} = ? WHERE {primary_key} = ?",
                (encoded, row[primary_key]),
            )
        changed += 1
    return changed


def _migration_datetime(value: object) -> Optional[datetime]:
    """Parse SQLite datetime values for deterministic one-time merges."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(
                raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            )
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _newer_migration_value(left: object, right: object) -> object:
    """Return the value representing the later timestamp, without reformatting it."""
    left_dt = _migration_datetime(left)
    right_dt = _migration_datetime(right)
    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt >= right_dt else right


def _older_migration_value(left: object, right: object) -> object:
    """Return the value representing the earlier timestamp, without reformatting it."""
    left_dt = _migration_datetime(left)
    right_dt = _migration_datetime(right)
    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt <= right_dt else right


def _json_identity(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return repr(value)


def _merge_migration_json_lists(
    current_raw: object,
    source_raw: object,
) -> str:
    """Union two persisted JSON arrays without dropping either side's entries.

    Mail objects primarily identify themselves with ``id``.  Historical rows
    without an id (and the simple string arrays used for seen mail ids) are
    de-duplicated by their canonical JSON value instead.
    """
    def load(raw: object) -> list:
        try:
            value = json.loads(str(raw or "[]"))
        except Exception:
            return []
        return value if isinstance(value, list) else []

    merged: list = []
    identities: dict[str, int] = {}
    for item in [*load(current_raw), *load(source_raw)]:
        if isinstance(item, dict) and item.get("id") not in (None, ""):
            item_id = str(item.get("id"))
            folder = str(item.get("folder") or "").strip()
            # Before the v3 IMAP cutover a UID was stored as a bare number and
            # was only unique inside its folder.  Preserve INBOX/Junk rows with
            # the same UID as distinct messages during Plan detach.  Modern
            # namespaced identities already contain their folder/epoch.
            if folder and not item_id.startswith("imap:"):
                identity = f"folder:{folder}:id:{item_id}"
            else:
                identity = "id:" + item_id
        else:
            identity = "value:" + _json_identity(item)
        previous = identities.get(identity)
        if previous is None:
            identities[identity] = len(merged)
            merged.append(item)
        elif isinstance(merged[previous], dict) and isinstance(item, dict):
            # The legacy monitor can have more fields while a newer Plan row
            # has fresher presentation data.  Fill missing keys only, keeping
            # the already-local Plan value on conflicts.
            combined = dict(item)
            combined.update(merged[previous])
            merged[previous] = combined
    return json.dumps(merged, ensure_ascii=False, separators=(",", ":"))


def _merge_migration_json_objects(
    source_raw: object,
    target_raw: object,
) -> str:
    """Merge extension objects while keeping live Plan-local state.

    Legacy source keys fill gaps, but the already-live Plan object wins on
    ordinary conflicts.  Namespaced mail migration versions are monotonic so a
    stale detach source can never roll back an identity/cleanup marker.
    """
    def load(raw: object) -> dict:
        try:
            value = json.loads(str(raw or "{}"))
        except Exception:
            return {}
        return value if isinstance(value, dict) else {}

    source = load(source_raw)
    target = load(target_raw)
    merged = dict(source)
    merged.update(target)
    for key in (
        "mail_imap_identity_version",
        "mail_graph_cutover_cleanup_version",
        "mail_legacy_imap_cutover_cleanup_version",
    ):
        candidates = []
        for value in (source.get(key), target.get(key)):
            try:
                candidates.append(int(value))
            except (TypeError, ValueError):
                continue
        if candidates:
            merged[key] = max(candidates)
    return json.dumps(merged, ensure_ascii=False, separators=(",", ":"))


def _merge_gpt_plan_account_values(
    source: dict,
    target: dict,
    *,
    pro_columns: set[str],
    plan_columns: set[str],
) -> dict[str, object]:
    """Merge an old PRO row into an already-live Plan row without regressions.

    The old pool remains authoritative for its credentials, refund/OAuth and
    BUSINESS-parent state.  Timestamped browser/mail state may have advanced
    independently in the Plan UI before cutover, so those fields are merged
    instead of blindly overwritten.
    """
    direct_fields = (
        "password",
        "client_id",
        "refresh_token",
        "mail_access_type",
        "is_pro",
        "pro_expires_at",
        "subscribed_at",
        "payment_card_last4",
        "refund_status",
        "refund_detected_at",
        "refund_credited_at",
        "human_review_requested_at",
        "refund_rejected_at",
        "refund_manual_at",
        "dangerous",
        "dangerous_detected_at",
        "appeal_url",
        "appeal_done_at",
        "cookie_blob",
        "cookie_updated_at",
        "cookie_expires_at",
        "policy_warning",
        "policy_warning_detected_at",
        "codex_access_token",
        "codex_refresh_token",
        "codex_id_token",
        "codex_session_token",
        "codex_rt_acquired_at",
        "referral_remaining",
        "referral_quota_checked_at",
        "referral_invited_emails_json",
        "referral_confirmed_emails_json",
        "business_parent_id",
        "business_invited_at",
        "enabled",
    )
    assignments = {
        field: source.get(field)
        for field in direct_fields
        if field in pro_columns and field in plan_columns
    }
    if "extra_json" in plan_columns:
        assignments["extra_json"] = _merge_migration_json_objects(
            source.get("extra_json"),
            target.get("extra_json"),
        )

    # A cookie is one atomic credential bundle.  Select all three values from
    # the side whose observation is newer; mixing them can create an unusable
    # session.  A timestamp-less non-empty bundle is used only if the other side
    # has no cookie at all.
    source_cookie_at = _migration_datetime(source.get("cookie_updated_at"))
    target_cookie_at = _migration_datetime(target.get("cookie_updated_at"))
    use_target_cookie = bool(
        target_cookie_at is not None
        and (source_cookie_at is None or target_cookie_at > source_cookie_at)
    ) or bool(
        target.get("cookie_blob")
        and not source.get("cookie_blob")
        and source_cookie_at is None
    )
    if use_target_cookie:
        for field in ("cookie_blob", "cookie_updated_at", "cookie_expires_at"):
            if field in plan_columns:
                assignments[field] = target.get(field)

    for field in (
        "last_used",
        "updated_at",
        "last_mail_check_at",
        "dangerous_detected_at",
        "policy_warning_detected_at",
        "appeal_done_at",
        "referral_quota_checked_at",
        "business_invited_at",
        "codex_rt_acquired_at",
    ):
        if field in plan_columns:
            assignments[field] = _newer_migration_value(
                source.get(field), target.get(field)
            )
    if "created_at" in plan_columns:
        assignments["created_at"] = _older_migration_value(
            source.get("created_at"), target.get("created_at")
        )

    for field in ("dangerous", "policy_warning"):
        if field in plan_columns:
            assignments[field] = bool(source.get(field)) or bool(target.get(field))

    for field in (
        "seen_mail_ids_json",
        "pending_alerts_json",
        "pending_inbox_json",
        "referral_invited_emails_json",
        "referral_confirmed_emails_json",
    ):
        if field in plan_columns:
            assignments[field] = _merge_migration_json_lists(
                target.get(field), source.get(field)
            )

    # Keep the error belonging to the newer check.  On an exact tie the legacy
    # source wins because it was the pre-cutover owner.
    if "last_mail_check_error" in plan_columns:
        target_check = _migration_datetime(target.get("last_mail_check_at"))
        source_check = _migration_datetime(source.get("last_mail_check_at"))
        assignments["last_mail_check_error"] = (
            target.get("last_mail_check_error") or ""
            if target_check is not None
            and (source_check is None or target_check > source_check)
            else source.get("last_mail_check_error") or ""
        )

    return assignments


def _rekey_gpt_pro_relations_to_plan(conn, crosswalk: dict[int, int]) -> dict:
    """Atomically move every audited child-id relation to GPT Plan ids."""
    if not crosswalk:
        return {
            "relational_rows": 0,
            "json_rows": 0,
            "card_reservations": 0,
            "ambiguous_card_reservations": 0,
            "leases_copied": 0,
        }
    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    relational_rows = 0
    relation_columns = {
        "gpt_business_child_memberships": (
            "pro_account_id",
            "replacement_pro_account_id",
        ),
        "gpt_business_allocation_jobs": (
            "requested_pro_account_id",
            "selected_pro_account_id",
            "old_pro_account_id",
        ),
        "delivery_device_exhaustion_cleanups": ("account_id",),
        # Compatibility with development schemas which briefly stored these as
        # first-class columns rather than only in request_json.
        "gpt_business_invite_operations": (
            "pro_account_id",
            "old_pro_account_id",
            "new_pro_account_id",
        ),
        "delivery_device_replenishments": (
            "pro_account_id",
            "old_pro_account_id",
            "new_pro_account_id",
            "account_id",
        ),
        "delivery_device_replenishment_demands": (
            "pro_account_id",
            "old_pro_account_id",
            "new_pro_account_id",
            "account_id",
        ),
    }
    for table, candidates in relation_columns.items():
        if table not in tables:
            continue
        columns = {
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for column in candidates:
            if column not in columns:
                continue
            cursor = conn.execute(
                f"UPDATE {table} SET {column} = ("
                "SELECT plan_account_id FROM gpt_pro_to_plan_account_crosswalk "
                f"WHERE old_pro_account_id = {table}.{column}) "
                "WHERE EXISTS (SELECT 1 FROM "
                "gpt_pro_to_plan_account_crosswalk x "
                f"WHERE x.old_pro_account_id = {table}.{column})"
            )
            relational_rows += max(0, int(cursor.rowcount or 0))

    # Legacy card reservations belong to the still-visible GPT PRO workspace.
    # Do not mutate them during account detachment.  The later support-inventory
    # migration copies cards into ``gpt_plan_cards`` and rekeys only that copy.
    # Keeping the legacy owner id here is what makes both workspaces independent.
    card_reservations = 0
    ambiguous_card_reservations = 0
    if "cards" in tables:
        card_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(cards)").fetchall()
        }
        if {"reserved_by_account_id", "number"}.issubset(card_columns):
            ambiguous_card_reservations = int(conn.execute(
                "SELECT count(*) FROM cards "
                "JOIN gpt_pro_to_plan_account_crosswalk x "
                "ON x.old_pro_account_id = cards.reserved_by_account_id "
                "JOIN accounts a ON a.id = cards.reserved_by_account_id "
                "LEFT JOIN gpt_pro_accounts p "
                "ON p.id = cards.reserved_by_account_id "
                "WHERE trim(coalesce(p.payment_card_last4, '')) = '' "
                "OR substr(replace(cards.number, ' ', ''), -4) != "
                "trim(p.payment_card_last4)"
            ).fetchone()[0] or 0)

    # Allocation leases encode child identity in their primary key.  Move via
    # a temporary namespace so an old id which equals another row's new Plan id
    # cannot cause an order-dependent UNIQUE violation.
    if "gpt_business_allocation_leases" in tables:
        conflicts = conn.execute(
            "SELECT l.resource_key FROM gpt_business_allocation_leases l "
            "JOIN gpt_pro_to_plan_account_crosswalk x "
            "ON l.resource_key = 'child:' || x.old_pro_account_id "
            "JOIN gpt_business_allocation_leases occupied "
            "ON occupied.resource_key = 'child:' || x.plan_account_id "
            "WHERE occupied.resource_key != l.resource_key "
            "AND NOT EXISTS (SELECT 1 FROM gpt_pro_to_plan_account_crosswalk y "
            "WHERE occupied.resource_key = 'child:' || y.old_pro_account_id)"
        ).fetchall()
        if conflicts:
            raise RuntimeError("GPT Plan migration allocation-lease identity conflict")
        conn.execute(
            "UPDATE gpt_business_allocation_leases SET resource_key = "
            "'child:migrating:' || (SELECT x.plan_account_id FROM "
            "gpt_pro_to_plan_account_crosswalk x WHERE resource_key = "
            "'child:' || x.old_pro_account_id) WHERE resource_key IN ("
            "SELECT 'child:' || old_pro_account_id FROM "
            "gpt_pro_to_plan_account_crosswalk)"
        )
        conn.execute(
            "UPDATE gpt_business_allocation_leases SET resource_key = "
            "'child:' || substr(resource_key, length('child:migrating:') + 1) "
            "WHERE resource_key LIKE 'child:migrating:%'"
        )

    json_rows = 0
    json_columns = {
        # Referral registration stores the parent Plan identity on a normal
        # ChatGPT account.  Only that explicit key is safe to rewrite here;
        # generic account extra may use ``child_id`` for unrelated platforms.
        "accounts": (("extra_json", False),),
        "gpt_plan_accounts": (("extra_json", False),),
        "gpt_business_child_memberships": (("intent_payload_json", False),),
        "gpt_business_invite_operations": (
            ("request_json", True),
            ("result_json", False),
        ),
        "gpt_business_allocation_jobs": (
            ("request_json", True),
            ("selection_json", False),
            ("result_json", False),
            ("action_state_json", False),
        ),
        "delivery_device_exhaustion_cleanups": (("request_json", True),),
    }
    for table, candidates in json_columns.items():
        if table not in tables:
            continue
        columns = {
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for column, refresh_hash in candidates:
            if column not in columns:
                continue
            json_rows += _rewrite_gpt_plan_json_column(
                conn,
                table,
                column,
                crosswalk,
                root_account_id=(
                    table == "delivery_device_exhaustion_cleanups"
                    and column == "request_json"
                ),
                refresh_request_hash=(refresh_hash and "request_hash" in columns),
                id_keys=(
                    frozenset({"referrer_pro_account_id"})
                    if table in {"accounts", "gpt_plan_accounts"}
                    else _GPT_PLAN_CHILD_ID_JSON_KEYS
                ),
                id_list_keys=(
                    frozenset()
                    if table in {"accounts", "gpt_plan_accounts"}
                    else _GPT_PLAN_CHILD_ID_LIST_JSON_KEYS
                ),
            )

    leases_copied = 0
    if {
        "gpt_pro_account_operation_leases",
        "gpt_plan_account_operation_leases",
    }.issubset(tables):
        cursor = conn.execute(
            "INSERT OR IGNORE INTO gpt_plan_account_operation_leases "
            "(account_id, operation, token, expires_at, created_at, updated_at) "
            "SELECT x.plan_account_id, l.operation, l.token, l.expires_at, "
            "l.created_at, l.updated_at FROM gpt_pro_account_operation_leases l "
            "JOIN gpt_pro_to_plan_account_crosswalk x "
            "ON x.old_pro_account_id = l.account_id"
        )
        leases_copied = max(0, int(cursor.rowcount or 0))

    return {
        "relational_rows": relational_rows,
        "json_rows": json_rows,
        "card_reservations": card_reservations,
        "ambiguous_card_reservations": ambiguous_card_reservations,
        "leases_copied": leases_copied,
    }


def _gpt_plan_pro_category(source: dict) -> tuple[str, str, str]:
    """Return the standalone plan/category/state for one legacy PRO row."""
    refund_status = str(source.get("refund_status") or "").strip()
    if refund_status in {"refunded_pending_credit", "refund_credited"}:
        return "pro_20x", "refunded", refund_status
    if source.get("business_parent_id") is not None:
        return "team", "member", "business_child"
    if bool(source.get("is_pro")):
        return "pro_20x", "member", "pro"
    return "", "regular", "regular"


def _gpt_plan_mail_provider(extra_json: object) -> str:
    try:
        extra = json.loads(str(extra_json or "{}"))
    except Exception:
        extra = {}
    provider = str(extra.get("mail_provider") or "outlook").strip().lower() \
        if isinstance(extra, dict) else "outlook"
    return "icloud" if provider in {"icloud", "qqmail"} else "outlook"


def _detach_gpt_pro_plan_mirrors(conn) -> dict:
    """Copy legacy GPT PRO mirrors once, then sever their source pointers.

    This is deliberately a *data migration*, not a synchronizer.  Its durable
    marker is inserted in the same SQLite transaction as the copies.  A later
    process restart therefore cannot overwrite state subsequently edited in
    GPT 套餐管理.  The old PRO rows are retained temporarily so other migration
    work (membership/device re-keying) can be performed separately.
    """
    conn.row_factory = __import__("sqlite3").Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS app_data_migrations ("
        "name TEXT PRIMARY KEY, completed_at DATETIME NOT NULL, "
        "details_json TEXT NOT NULL DEFAULT '{}')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS gpt_pro_to_plan_account_crosswalk ("
        "old_pro_account_id INTEGER PRIMARY KEY, "
        "plan_account_id INTEGER NOT NULL UNIQUE, "
        "email VARCHAR NOT NULL, migrated_at DATETIME NOT NULL)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS "
        "ix_gpt_pro_to_plan_account_crosswalk_plan_account_id "
        "ON gpt_pro_to_plan_account_crosswalk(plan_account_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_gpt_pro_to_plan_account_crosswalk_email "
        "ON gpt_pro_to_plan_account_crosswalk(email)"
    )
    existing_marker = conn.execute(
        "SELECT details_json FROM app_data_migrations WHERE name = ?",
        (_GPT_PLAN_PRO_DETACH_MIGRATION,),
    ).fetchone()
    if existing_marker is not None:
        try:
            previous = json.loads(str(existing_marker["details_json"] or "{}"))
        except Exception:
            previous = {}
        return {"applied": False, **(previous if isinstance(previous, dict) else {})}

    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    summary = {
        "migrated": 0,
        "created": 0,
        "upgrade_summaries": 0,
        "relational_rows": 0,
        "json_rows": 0,
        "card_reservations": 0,
        "ambiguous_card_reservations": 0,
        "leases_copied": 0,
    }
    if "gpt_pro_accounts" not in tables or "gpt_plan_accounts" not in tables:
        conn.execute(
            "INSERT INTO app_data_migrations(name, completed_at, details_json) "
            "VALUES (?, ?, ?)",
            (
                _GPT_PLAN_PRO_DETACH_MIGRATION,
                _utcnow().isoformat(),
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
            ),
        )
        return {"applied": True, **summary}

    pro_columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(gpt_pro_accounts)").fetchall()
    }
    plan_schema = {
        str(row[1]): row
        for row in conn.execute("PRAGMA table_info(gpt_plan_accounts)").fetchall()
    }
    plan_columns = set(plan_schema)
    upgrade_schema = (
        {
            str(row[1]): row
            for row in conn.execute(
                "PRAGMA table_info(gpt_plan_account_upgrades)"
            ).fetchall()
        }
        if "gpt_plan_account_upgrades" in tables
        else {}
    )
    upgrade_columns = set(upgrade_schema)

    now = _utcnow().isoformat()
    source_rows = conn.execute(
        "SELECT * FROM gpt_pro_accounts ORDER BY id"
    ).fetchall()
    for raw_source in source_rows:
        source = dict(raw_source)
        source_id = int(source.get("id") or 0)
        email = str(source.get("email") or "").strip().lower()
        if source_id <= 0 or not email:
            raise RuntimeError("GPT Plan migration found an invalid GPT PRO identity")

        linked = conn.execute(
            "SELECT * FROM gpt_plan_accounts "
            "WHERE source_pool = 'gpt_pro' AND source_account_id = ?",
            (source_id,),
        ).fetchone()
        email_owner = conn.execute(
            "SELECT * FROM gpt_plan_accounts WHERE lower(trim(email)) = ?",
            (email,),
        ).fetchone()
        if linked is not None and email_owner is not None \
                and int(linked["id"]) != int(email_owner["id"]):
            raise RuntimeError(
                "GPT Plan migration identity conflict for PRO account "
                f"{source_id} ({email})"
            )
        if linked is None and email_owner is not None:
            owner_pool = str(email_owner["source_pool"] or "").strip() \
                if "source_pool" in plan_columns else ""
            owner_source_id = int(email_owner["source_account_id"] or 0) \
                if "source_account_id" in plan_columns else 0
            if owner_pool not in {"", "gpt_pro"} or (
                owner_pool == "gpt_pro" and owner_source_id != source_id
            ):
                raise RuntimeError(
                    "GPT Plan migration email is owned by another source for "
                    f"PRO account {source_id} ({email})"
                )
        target = linked or email_owner
        if target is None:
            insert_data: dict[str, object] = {"email": email}
            for column, schema_row in plan_schema.items():
                if column in {"id", "email"}:
                    continue
                source_value = source.get(column) if column in pro_columns else None
                if source_value is not None:
                    insert_data[column] = source_value
                    continue
                if not bool(schema_row[3]):  # nullable
                    continue
                if column == "mail_provider":
                    insert_data[column] = _gpt_plan_mail_provider(
                        source.get("extra_json")
                    )
                elif column == "extra_json":
                    insert_data[column] = "{}"
                elif column.endswith("_json"):
                    insert_data[column] = "[]"
                elif column in {"created_at", "updated_at"}:
                    insert_data[column] = source.get(column) or now
                elif "INT" in str(schema_row[2]).upper() \
                        or "BOOL" in str(schema_row[2]).upper():
                    insert_data[column] = 0
                else:
                    insert_data[column] = ""
            insert_columns = list(insert_data)
            insert_values = list(insert_data.values())
            placeholders = ", ".join("?" for _ in insert_columns)
            conn.execute(
                f"INSERT INTO gpt_plan_accounts ({', '.join(insert_columns)}) "
                f"VALUES ({placeholders})",
                tuple(insert_values),
            )
            target = conn.execute(
                "SELECT * FROM gpt_plan_accounts WHERE lower(trim(email)) = ?",
                (email,),
            ).fetchone()
            summary["created"] += 1
        elif str(target["email"] or "").strip().lower() != email:
            conn.execute(
                "UPDATE gpt_plan_accounts SET email = ? WHERE id = ?",
                (email, int(target["id"])),
            )

        target_id = int(target["id"])
        old_mapping = conn.execute(
            "SELECT plan_account_id, email FROM "
            "gpt_pro_to_plan_account_crosswalk WHERE old_pro_account_id = ?",
            (source_id,),
        ).fetchone()
        plan_mapping = conn.execute(
            "SELECT old_pro_account_id FROM "
            "gpt_pro_to_plan_account_crosswalk WHERE plan_account_id = ?",
            (target_id,),
        ).fetchone()
        if old_mapping is not None and int(old_mapping["plan_account_id"]) != target_id:
            raise RuntimeError("GPT Plan migration crosswalk changed for an old PRO id")
        if plan_mapping is not None and int(plan_mapping["old_pro_account_id"]) != source_id:
            raise RuntimeError("GPT Plan migration crosswalk maps two PRO ids to one Plan id")
        conn.execute(
            "INSERT OR IGNORE INTO gpt_pro_to_plan_account_crosswalk "
            "(old_pro_account_id, plan_account_id, email, migrated_at) "
            "VALUES (?, ?, ?, ?)",
            (source_id, target_id, email, now),
        )
        # ``target`` may already have been edited or refreshed in the Plan UI
        # while the legacy page was still available.  Merge both owners before
        # detaching instead of treating the old row as a blind last writer.
        target = conn.execute(
            "SELECT * FROM gpt_plan_accounts WHERE id = ?",
            (target_id,),
        ).fetchone()
        target_values = dict(target)
        assignments = _merge_gpt_plan_account_values(
            source,
            target_values,
            pro_columns=pro_columns,
            plan_columns=plan_columns,
        )

        plan_type, category, source_state = _gpt_plan_pro_category(source)
        computed = {
            "email": email,
            "mail_provider": _gpt_plan_mail_provider(source.get("extra_json")),
            "plan_type": plan_type,
            "catalog_category": category,
            "source_state": source_state,
            "source_pool": "",
            "source_account_id": None,
            "source_synced_at": None,
            "last_login_at": _newer_migration_value(
                _newer_migration_value(
                    source.get("cookie_updated_at"),
                    target_values.get("cookie_updated_at"),
                ),
                target_values.get("last_login_at"),
            ),
        }
        source_fetch_at = source.get("last_mail_check_at")
        target_fetch_at = target_values.get("last_mail_fetch_at")
        computed["last_mail_fetch_at"] = _newer_migration_value(
            source_fetch_at, target_fetch_at
        )
        source_fetch_dt = _migration_datetime(source_fetch_at)
        target_fetch_dt = _migration_datetime(target_fetch_at)
        computed["last_mail_error"] = (
            target_values.get("last_mail_error") or ""
            if target_fetch_dt is not None
            and (source_fetch_dt is None or target_fetch_dt > source_fetch_dt)
            else source.get("last_mail_check_error") or ""
        )

        # Login-detected Plan state is newer domain knowledge than a legacy
        # ``is_pro=False`` mirror.  Only an affirmative old lifecycle state
        # (paid PRO, refund, or BUSINESS child) may replace it.
        legacy_has_lifecycle_state = source_state != "regular"
        target_has_plan_state = bool(
            str(target_values.get("plan_type") or "").strip()
            or str(target_values.get("catalog_category") or "").strip().lower()
            == "member"
            or target_values.get("plan_checked_at") is not None
        )
        if not legacy_has_lifecycle_state and target_has_plan_state:
            for field in ("plan_type", "catalog_category", "source_state"):
                computed[field] = target_values.get(field)
            # A locally detected PRO must not be downgraded solely because the
            # old Boolean mirror had not yet been refreshed.
            target_plan_type = str(
                target_values.get("plan_type") or ""
            ).strip().lower()
            if bool(target_values.get("is_pro")) or target_plan_type in {
                "pro",
                "pro_20x",
                "chatgptpro",
            }:
                assignments["is_pro"] = True
            if target_values.get("pro_expires_at") is not None:
                assignments["pro_expires_at"] = _newer_migration_value(
                    source.get("pro_expires_at"),
                    target_values.get("pro_expires_at"),
                )
        computed["plan_checked_at"] = _newer_migration_value(
            source.get("subscribed_at"), target_values.get("plan_checked_at")
        )
        for field, value in computed.items():
            if field in plan_columns:
                assignments[field] = value

        # A non-empty Plan note is an operator edit and wins.  The old note is
        # only a backfill for mirrors which were never annotated in Plan.
        if "note" in plan_columns:
            assignments["note"] = (
                target_values.get("note")
                if str(target_values.get("note") or "").strip()
                else source.get("note") or ""
            )

        if assignments:
            set_sql = ", ".join(f"{name} = ?" for name in assignments)
            conn.execute(
                f"UPDATE gpt_plan_accounts SET {set_sql} WHERE id = ?",
                (*assignments.values(), target_id),
            )
        summary["migrated"] += 1

        # Existing checkout history belongs to GPT Plan and is never replaced.
        # Only fill a missing summary/field from the legacy authoritative row.
        has_paid_history = bool(
            source.get("is_pro")
            or str(source.get("refund_status") or "").strip()
            or source.get("subscribed_at")
            or str(source.get("payment_card_last4") or "").strip()
        )
        if not has_paid_history or not upgrade_columns:
            continue
        extra = {}
        try:
            parsed_extra = json.loads(str(source.get("extra_json") or "{}"))
            extra = parsed_extra if isinstance(parsed_extra, dict) else {}
        except Exception:
            extra = {}
        existing_upgrade = conn.execute(
            "SELECT * FROM gpt_plan_account_upgrades WHERE account_id = ?",
            (target_id,),
        ).fetchone()
        upgrade_values = {
            "plan_upgraded_at": source.get("subscribed_at"),
            "payment_card_last4": source.get("payment_card_last4") or "",
            "payment_account_id": int(extra.get("payment_account_id") or 0),
            "payment_account_name": str(extra.get("payment_account_name") or ""),
            "payment_account_type": str(extra.get("payment_account_type") or ""),
        }
        if existing_upgrade is None:
            insert_values = {"account_id": target_id}
            insert_values.update({
                key: value
                for key, value in upgrade_values.items()
                if key in upgrade_columns
            })
            if "created_at" in upgrade_columns:
                insert_values["created_at"] = now
            if "updated_at" in upgrade_columns:
                insert_values["updated_at"] = now
            for column, schema_row in upgrade_schema.items():
                if column in insert_values or not bool(schema_row[3]):
                    continue
                if column in {"created_at", "updated_at"}:
                    insert_values[column] = now
                elif "INT" in str(schema_row[2]).upper() \
                        or "BOOL" in str(schema_row[2]).upper():
                    insert_values[column] = 0
                else:
                    insert_values[column] = ""
            placeholders = ", ".join("?" for _ in insert_values)
            conn.execute(
                f"INSERT INTO gpt_plan_account_upgrades "
                f"({', '.join(insert_values)}) VALUES ({placeholders})",
                tuple(insert_values.values()),
            )
            summary["upgrade_summaries"] += 1
        else:
            missing_values = {
                key: value
                for key, value in upgrade_values.items()
                if key in upgrade_columns
                and value not in (None, "", 0)
                and existing_upgrade[key] in (None, "", 0)
            }
            if missing_values:
                if "updated_at" in upgrade_columns:
                    missing_values["updated_at"] = now
                set_sql = ", ".join(f"{key} = ?" for key in missing_values)
                conn.execute(
                    f"UPDATE gpt_plan_account_upgrades SET {set_sql} "
                    "WHERE account_id = ?",
                    (*missing_values.values(), target_id),
                )

    crosswalk = {
        int(row["old_pro_account_id"]): int(row["plan_account_id"])
        for row in conn.execute(
            "SELECT old_pro_account_id, plan_account_id FROM "
            "gpt_pro_to_plan_account_crosswalk"
        ).fetchall()
    }
    relation_summary = _rekey_gpt_pro_relations_to_plan(conn, crosswalk)
    summary.update(relation_summary)
    conn.execute(
        "INSERT INTO app_data_migrations(name, completed_at, details_json) "
        "VALUES (?, ?, ?)",
        (
            _GPT_PLAN_PRO_DETACH_MIGRATION,
            now,
            json.dumps(summary, ensure_ascii=False, sort_keys=True),
        ),
    )
    return {"applied": True, **summary}


def _migrate_gpt_plan_accounts():
    """补齐 GPT 套餐表，并一次性将旧 GPT PRO 镜像转为独立账号。"""
    if not DATABASE_URL.startswith("sqlite"):
        return
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    conn = None
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "gpt_plan_accounts" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(gpt_plan_accounts)").fetchall()
        }
        for col_name, col_ddl in (
            ("is_pro", "BOOLEAN NOT NULL DEFAULT 0"),
            ("pro_expires_at", "DATETIME"),
            ("subscribed_at", "DATETIME"),
            ("payment_card_last4", "VARCHAR NOT NULL DEFAULT ''"),
            ("refund_status", "VARCHAR NOT NULL DEFAULT ''"),
            ("refund_detected_at", "DATETIME"),
            ("refund_credited_at", "DATETIME"),
            ("human_review_requested_at", "DATETIME"),
            ("refund_rejected_at", "DATETIME"),
            ("refund_manual_at", "DATETIME"),
            ("dangerous", "BOOLEAN NOT NULL DEFAULT 0"),
            ("dangerous_detected_at", "DATETIME"),
            ("appeal_url", "VARCHAR NOT NULL DEFAULT ''"),
            ("appeal_done_at", "DATETIME"),
            ("source_pool", "VARCHAR NOT NULL DEFAULT ''"),
            ("source_account_id", "INTEGER"),
            ("catalog_category", "VARCHAR NOT NULL DEFAULT ''"),
            ("source_state", "VARCHAR NOT NULL DEFAULT ''"),
            ("source_synced_at", "DATETIME"),
            ("business_usage_type", "VARCHAR NOT NULL DEFAULT ''"),
            ("last_mail_check_at", "DATETIME"),
            ("last_mail_check_error", "VARCHAR NOT NULL DEFAULT ''"),
            ("seen_mail_ids_json", "VARCHAR NOT NULL DEFAULT '[]'"),
            ("pending_alerts_json", "VARCHAR NOT NULL DEFAULT '[]'"),
            ("pending_inbox_json", "VARCHAR NOT NULL DEFAULT '[]'"),
            ("policy_warning", "BOOLEAN NOT NULL DEFAULT 0"),
            ("policy_warning_detected_at", "DATETIME"),
            ("codex_access_token", "TEXT NOT NULL DEFAULT ''"),
            ("codex_refresh_token", "TEXT NOT NULL DEFAULT ''"),
            ("codex_id_token", "TEXT NOT NULL DEFAULT ''"),
            ("codex_session_token", "TEXT NOT NULL DEFAULT ''"),
            ("codex_rt_acquired_at", "DATETIME"),
            ("referral_remaining", "INTEGER"),
            ("referral_quota_checked_at", "DATETIME"),
            ("referral_invited_emails_json", "VARCHAR NOT NULL DEFAULT '[]'"),
            ("referral_confirmed_emails_json", "VARCHAR NOT NULL DEFAULT '[]'"),
            ("business_parent_id", "INTEGER"),
            ("business_invited_at", "DATETIME"),
            ("extra_json", "TEXT NOT NULL DEFAULT '{}'"),
        ):
            if col_name not in existing:
                conn.execute(
                    f"ALTER TABLE gpt_plan_accounts ADD COLUMN {col_name} {col_ddl}"
                )
        # NULL source_account_id 允许任意数量人工导入账号；一旦记录被来源同步
        # 认领，同一源账号只能对应一条套餐目录记录。
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_gpt_plan_accounts_source "
            "ON gpt_plan_accounts(source_pool, source_account_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_plan_accounts_catalog_category "
            "ON gpt_plan_accounts(catalog_category)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_plan_accounts_business_parent_id "
            "ON gpt_plan_accounts(business_parent_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_plan_accounts_business_usage_type "
            "ON gpt_plan_accounts(business_usage_type)"
        )
        _ensure_gpt_plan_accounts_autoincrement(conn)
        _detach_gpt_pro_plan_mirrors(conn)
        conn.commit()
        conn.close()
    except Exception:
        if conn is not None:
            try:
                conn.rollback()
            finally:
                conn.close()
        # This migration changes durable identity references.  Starting with a
        # half-detached database is less safe than failing fast and retrying the
        # same idempotent transaction after the conflict is resolved.
        raise


def _cleanup_stale_dead_gpt_plan_business_children(conn) -> dict:
    """Delete only detached, dead legacy BUSINESS children in one transaction.

    Terminal allocation/device rows intentionally remain immutable audit.  The
    AUTOINCREMENT upgrade above guarantees that their positive account id can
    never bind to a future Plan row.  Membership ids are different: runtime
    selection queries them directly, so ended history is detached while its
    email/parent/seat/timestamps remain intact.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS app_data_migrations ("
        "name TEXT PRIMARY KEY, completed_at DATETIME NOT NULL, "
        "details_json TEXT NOT NULL DEFAULT '{}')"
    )
    existing = conn.execute(
        "SELECT details_json FROM app_data_migrations WHERE name = ?",
        (_GPT_PLAN_STALE_DEAD_CHILD_CLEANUP_MIGRATION,),
    ).fetchone()
    if existing is not None:
        try:
            previous = json.loads(str(existing[0] or "{}"))
        except Exception:
            previous = {}
        return {
            "applied": False,
            "complete": True,
            **(previous if isinstance(previous, dict) else {}),
        }

    tables = {
        str(row[0]) for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    required = {
        "gpt_plan_accounts",
        "gpt_pro_to_plan_account_crosswalk",
        "gpt_business_child_memberships",
    }
    summary = {
        "candidates": 0,
        "deleted": 0,
        "memberships_detached": 0,
        "replacement_memberships_detached": 0,
        "upgrades_deleted": 0,
        "operation_leases_deleted": 0,
        "allocation_leases_deleted": 0,
        "crosswalks_deleted": 0,
        "card_reservations_cleared": 0,
        "safe_candidates": 0,
        "blocked_candidates": 0,
        "blocked_reasons": {},
    }
    if not required.issubset(tables):
        summary["reason"] = "required_tables_missing"
        conn.execute(
            "INSERT INTO app_data_migrations(name, completed_at, details_json) "
            "VALUES (?, ?, ?)",
            (
                _GPT_PLAN_STALE_DEAD_CHILD_CLEANUP_MIGRATION,
                _utcnow().isoformat(),
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
            ),
        )
        return {"applied": True, "complete": True, **summary}

    plan_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'gpt_plan_accounts'"
    ).fetchone()
    if plan_sql is None or not re.search(
        r"\bAUTOINCREMENT\b", str(plan_sql[0] or ""), flags=re.IGNORECASE,
    ):
        raise RuntimeError(
            "stale BUSINESS child cleanup requires GPT Plan AUTOINCREMENT"
        )

    candidate_table = "gpt_plan_stale_dead_child_candidates_v1"
    quoted_candidates = _sqlite_quote_identifier(candidate_table)
    conn.execute(
        f"CREATE TEMP TABLE {quoted_candidates} (id INTEGER PRIMARY KEY)"
    )
    conn.execute(
        f"INSERT INTO {quoted_candidates}(id) "
        "SELECT DISTINCT a.id FROM gpt_plan_accounts a "
        "JOIN gpt_pro_to_plan_account_crosswalk x "
        "ON x.plan_account_id = a.id "
        "WHERE lower(trim(coalesce(a.plan_type, ''))) = 'team' "
        "AND lower(trim(coalesce(a.catalog_category, ''))) = 'member' "
        "AND lower(trim(coalesce(a.source_state, ''))) = 'business_child' "
        "AND trim(coalesce(a.source_pool, '')) = '' "
        "AND a.source_account_id IS NULL "
        "AND coalesce(a.is_pro, 0) = 0 "
        "AND coalesce(a.dangerous, 0) = 1 "
        "AND a.dangerous_detected_at IS NOT NULL "
        "AND a.business_parent_id IS NULL "
        "AND a.business_invited_at IS NULL "
        "AND EXISTS ("
        "SELECT 1 FROM gpt_business_child_memberships history "
        "WHERE history.ended_at IS NOT NULL "
        "AND lower(trim(coalesce(history.source, ''))) = 'pool' "
        "AND (history.pro_account_id = a.id OR "
        "lower(trim(coalesce(history.email, ''))) = "
        "lower(trim(coalesce(a.email, '')))))"
    )
    candidate_count = int(conn.execute(
        f"SELECT count(*) FROM {quoted_candidates}"
    ).fetchone()[0] or 0)
    summary["candidates"] = candidate_count

    candidate_ids = {
        int(row[0]) for row in conn.execute(
            f"SELECT id FROM {quoted_candidates}"
        ).fetchall()
    }
    blocked_by_id: dict[int, set[str]] = {}

    def block_candidate_ids(name: str, sql: str, params: tuple = ()) -> None:
        for row in conn.execute(sql, params).fetchall():
            candidate_id = int(row[0])
            if candidate_id in candidate_ids:
                blocked_by_id.setdefault(candidate_id, set()).add(name)

    if candidate_count:
        block_candidate_ids(
            "active_membership",
            f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
            "JOIN gpt_plan_accounts a ON a.id = c.id "
            "JOIN gpt_business_child_memberships m ON ("
            "m.pro_account_id = c.id OR m.replacement_pro_account_id = c.id OR "
            "lower(trim(coalesce(m.email, ''))) = "
            "lower(trim(coalesce(a.email, '')))) WHERE m.ended_at IS NULL",
        )
        if "gpt_plan_account_operation_leases" in tables:
            block_candidate_ids(
                "active_operation_lease",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_plan_account_operation_leases l ON l.account_id = c.id "
                "WHERE l.expires_at IS NULL OR julianday(l.expires_at) IS NULL "
                "OR julianday(l.expires_at) > julianday(?)",
                (_utcnow().isoformat(),),
            )
        if "gpt_business_allocation_leases" in tables:
            block_candidate_ids(
                "active_allocation_lease",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_business_allocation_leases l "
                "ON l.resource_key = 'child:' || c.id "
                "WHERE l.expires_at IS NULL OR julianday(l.expires_at) IS NULL "
                "OR julianday(l.expires_at) > julianday(?)",
                (_utcnow().isoformat(),),
            )
        if "gpt_business_allocation_jobs" in tables:
            block_candidate_ids(
                "active_allocation_job",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_business_allocation_jobs j ON ("
                "j.requested_pro_account_id = c.id OR "
                "j.selected_pro_account_id = c.id OR j.old_pro_account_id = c.id) "
                "WHERE lower(trim(coalesce(j.state, ''))) NOT IN "
                "('completed', 'failed', 'cancelled')",
            )

            def allocation_json_ids(raw_value: object) -> tuple[set[int], bool]:
                raw_text = str(raw_value or "").strip()
                if not raw_text:
                    return set(), False
                try:
                    parsed = json.loads(raw_text)
                except Exception:
                    return set(), True
                found: set[int] = set()

                def normalized_id(value: object) -> Optional[int]:
                    if value is None or isinstance(value, bool):
                        return None
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        return None

                def visit(value: object, parent_key: str = "") -> None:
                    if isinstance(value, list):
                        if parent_key in _GPT_PLAN_CHILD_ID_LIST_JSON_KEYS:
                            for item in value:
                                child_id = normalized_id(item)
                                if child_id in candidate_ids:
                                    found.add(int(child_id))
                            return
                        for item in value:
                            visit(item, parent_key)
                        return
                    if not isinstance(value, dict):
                        return
                    for key, item in value.items():
                        normalized_key = str(key)
                        if normalized_key in _GPT_PLAN_CHILD_ID_JSON_KEYS:
                            child_id = normalized_id(item)
                            if child_id in candidate_ids:
                                found.add(int(child_id))
                        if normalized_key in _GPT_PLAN_CHILD_ID_LIST_JSON_KEYS \
                                and isinstance(item, list):
                            for child_value in item:
                                child_id = normalized_id(child_value)
                                if child_id in candidate_ids:
                                    found.add(int(child_id))
                        if parent_key == "children":
                            keyed_id = normalized_id(normalized_key)
                            if keyed_id in candidate_ids:
                                found.add(int(keyed_id))
                        visit(item, normalized_key)

                visit(parsed)
                return found, False

            active_json_rows = conn.execute(
                "SELECT request_json, selection_json, result_json, "
                "action_state_json FROM gpt_business_allocation_jobs "
                "WHERE lower(trim(coalesce(state, ''))) NOT IN "
                "('completed', 'failed', 'cancelled')"
            ).fetchall()
            invalid_active_json = False
            for active_row in active_json_rows:
                referenced_ids: set[int] = set()
                for raw_json in active_row:
                    json_ids, invalid_json = allocation_json_ids(raw_json)
                    referenced_ids.update(json_ids)
                    invalid_active_json = invalid_active_json or invalid_json
                for candidate_id in referenced_ids:
                    blocked_by_id.setdefault(candidate_id, set()).add(
                        "active_allocation_job_json"
                    )
            if invalid_active_json:
                # Corrupt non-terminal orchestration JSON may be the only durable
                # reference to any candidate.  Its ownership cannot be attributed
                # safely, so retain every candidate and retry after repair.
                for candidate_id in candidate_ids:
                    blocked_by_id.setdefault(candidate_id, set()).add(
                        "active_allocation_job_json_invalid"
                    )
        if "delivery_device_exhaustion_cleanups" in tables:
            block_candidate_ids(
                "active_device_cleanup",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN delivery_device_exhaustion_cleanups d "
                "ON d.account_id = c.id WHERE "
                "lower(trim(coalesce(d.state, ''))) NOT IN "
                "('completed', 'superseded', 'cancelled')",
            )
        if "delivery_device_team401_tasks" in tables:
            block_candidate_ids(
                "active_team401_task",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN delivery_device_team401_tasks t ON ("
                "t.child_id = c.id OR t.replacement_child_id = c.id) WHERE "
                "lower(trim(coalesce(t.state, ''))) NOT IN "
                "('completed', 'failed', 'cancelled')",
            )
        if {
            "delivery_device_replenishment_demands",
            "delivery_device_exhaustion_cleanups",
        }.issubset(tables):
            fill_clause = ""
            if "gpt_business_allocation_jobs" in tables:
                fill_clause = (
                    " OR demand.fill_job_id IN (SELECT job.id FROM "
                    "gpt_business_allocation_jobs job WHERE "
                    "job.requested_pro_account_id = c.id OR "
                    "job.selected_pro_account_id = c.id OR "
                    "job.old_pro_account_id = c.id)"
                )
            block_candidate_ids(
                "active_replenishment_demand",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c WHERE EXISTS ("
                "SELECT 1 FROM delivery_device_replenishment_demands demand "
                "WHERE (demand.cleanup_job_id IN (SELECT cleanup.id FROM "
                "delivery_device_exhaustion_cleanups cleanup "
                "WHERE cleanup.account_id = c.id)"
                f"{fill_clause}) AND lower(trim(coalesce(demand.state, ''))) "
                "NOT IN ('completed', 'cancelled'))",
            )
        if "gpt_business_rotation_reservations" in tables:
            block_candidate_ids(
                "active_rotation_reservation",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_business_child_memberships m ON ("
                "m.pro_account_id = c.id OR m.replacement_pro_account_id = c.id) "
                "JOIN gpt_business_rotation_reservations r "
                "ON r.operation_id = m.operation_id WHERE "
                "lower(trim(coalesce(r.state, ''))) = 'reserved'",
            )
        if "gpt_plan_account_upgrades" in tables:
            block_candidate_ids(
                "active_upgrade",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_plan_account_upgrades u ON u.account_id = c.id WHERE "
                "lower(trim(coalesce(u.checkout_status, ''))) NOT IN "
                "('', 'success', 'failed', 'manual_not_upgraded', "
                "'cancelled', 'completed')",
            )
        if "gpt_plan_cards" in tables:
            block_candidate_ids(
                "active_card_reservation",
                f"SELECT DISTINCT c.id FROM {quoted_candidates} c "
                "JOIN gpt_plan_cards card ON card.reserved_by_account_id = c.id "
                "WHERE lower(trim(coalesce(card.status, ''))) = 'in_use'",
            )

    blocked_ids = set(blocked_by_id)
    safe_ids = candidate_ids - blocked_ids
    blocked_reasons: dict[str, int] = {}
    for reasons in blocked_by_id.values():
        for reason in reasons:
            blocked_reasons[reason] = blocked_reasons.get(reason, 0) + 1
    summary["blocked_candidates"] = len(blocked_ids)
    summary["safe_candidates"] = len(safe_ids)
    summary["blocked_reasons"] = dict(sorted(blocked_reasons.items()))

    safe_table = "gpt_plan_stale_dead_child_safe_v1"
    quoted_safe = _sqlite_quote_identifier(safe_table)
    conn.execute(f"CREATE TEMP TABLE {quoted_safe} (id INTEGER PRIMARY KEY)")
    if safe_ids:
        conn.executemany(
            f"INSERT INTO {quoted_safe}(id) VALUES (?)",
            [(candidate_id,) for candidate_id in sorted(safe_ids)],
        )

    now = _utcnow().isoformat()
    if safe_ids:
        cursor = conn.execute(
            "UPDATE gpt_business_child_memberships SET pro_account_id = NULL, "
            "updated_at = ? WHERE ended_at IS NOT NULL "
            f"AND pro_account_id IN (SELECT id FROM {quoted_safe})",
            (now,),
        )
        summary["memberships_detached"] = max(0, int(cursor.rowcount or 0))
        cursor = conn.execute(
            "UPDATE gpt_business_child_memberships "
            "SET replacement_pro_account_id = NULL, updated_at = ? "
            "WHERE ended_at IS NOT NULL AND replacement_pro_account_id "
            f"IN (SELECT id FROM {quoted_safe})",
            (now,),
        )
        summary["replacement_memberships_detached"] = max(
            0, int(cursor.rowcount or 0)
        )
        if "gpt_plan_account_upgrades" in tables:
            cursor = conn.execute(
                "DELETE FROM gpt_plan_account_upgrades WHERE account_id "
                f"IN (SELECT id FROM {quoted_safe})"
            )
            summary["upgrades_deleted"] = max(0, int(cursor.rowcount or 0))
        if "gpt_plan_account_operation_leases" in tables:
            cursor = conn.execute(
                "DELETE FROM gpt_plan_account_operation_leases WHERE account_id "
                f"IN (SELECT id FROM {quoted_safe})"
            )
            summary["operation_leases_deleted"] = max(
                0, int(cursor.rowcount or 0)
            )
        if "gpt_business_allocation_leases" in tables:
            cursor = conn.execute(
                "DELETE FROM gpt_business_allocation_leases WHERE resource_key "
                f"IN (SELECT 'child:' || id FROM {quoted_safe})"
            )
            summary["allocation_leases_deleted"] = max(
                0, int(cursor.rowcount or 0)
            )
        if "gpt_plan_cards" in tables:
            cursor = conn.execute(
                "UPDATE gpt_plan_cards SET reserved_by_account_id = 0, "
                "reserved_at = NULL, updated_at = ? WHERE reserved_by_account_id "
                f"IN (SELECT id FROM {quoted_safe})",
                (now,),
            )
            summary["card_reservations_cleared"] = max(
                0, int(cursor.rowcount or 0)
            )
        cursor = conn.execute(
            "DELETE FROM gpt_pro_to_plan_account_crosswalk WHERE plan_account_id "
            f"IN (SELECT id FROM {quoted_safe})"
        )
        summary["crosswalks_deleted"] = max(0, int(cursor.rowcount or 0))
        cursor = conn.execute(
            "DELETE FROM gpt_plan_accounts WHERE id "
            f"IN (SELECT id FROM {quoted_safe})"
        )
        summary["deleted"] = max(0, int(cursor.rowcount or 0))
        if summary["deleted"] != len(safe_ids):
            raise RuntimeError("stale BUSINESS child cleanup delete count mismatch")
        dangling_memberships = int(conn.execute(
            "SELECT count(*) FROM gpt_business_child_memberships WHERE "
            f"pro_account_id IN (SELECT id FROM {quoted_safe}) OR "
            f"replacement_pro_account_id IN (SELECT id FROM {quoted_safe})"
        ).fetchone()[0] or 0)
        if dangling_memberships:
            raise RuntimeError(
                "stale BUSINESS child cleanup left membership id references"
            )

    conn.execute(f"DROP TABLE {quoted_safe}")
    conn.execute(f"DROP TABLE {quoted_candidates}")
    complete = not blocked_ids
    if complete:
        conn.execute(
            "INSERT INTO app_data_migrations(name, completed_at, details_json) "
            "VALUES (?, ?, ?)",
            (
                _GPT_PLAN_STALE_DEAD_CHILD_CLEANUP_MIGRATION,
                now,
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
            ),
        )
    return {"applied": True, "complete": complete, **summary}


def _migrate_stale_dead_gpt_plan_business_children() -> dict:
    """Run the one-time stale-child cleanup after all dependent schemas exist."""
    if not DATABASE_URL.startswith("sqlite"):
        return {"applied": False, "reason": "non_sqlite"}
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    conn = None
    try:
        conn = _sqlite3.connect(raw_url)
        conn.execute("BEGIN IMMEDIATE")
        result = _cleanup_stale_dead_gpt_plan_business_children(conn)
        conn.commit()
        return result
    except Exception:
        if conn is not None:
            conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()


def _migrate_gpt_business_accounts():
    """为已有的 gpt_business_accounts 表补齐新增列(如 business_upgraded_at)。"""
    new_columns = [
        ("business_upgraded_at", "DATETIME"),
        ("cookie_blob", "TEXT NOT NULL DEFAULT ''"),
        ("cookie_updated_at", "DATETIME"),
        ("cookie_expires_at", "DATETIME"),
        ("refund_status", "VARCHAR NOT NULL DEFAULT ''"),
        ("refund_detected_at", "DATETIME"),
        ("refund_credited_at", "DATETIME"),
        ("refund_manual_at", "DATETIME"),
        ("human_review_requested_at", "DATETIME"),
        ("invite_quota_window_started_at", "DATETIME"),
        ("invite_quota_used", "INTEGER NOT NULL DEFAULT 0"),
        ("invite_quota_typed_initialized", "BOOLEAN NOT NULL DEFAULT 0"),
        ("invite_quota_default_window_started_at", "DATETIME"),
        ("invite_quota_default_used", "INTEGER NOT NULL DEFAULT 0"),
        ("invite_quota_prolite_window_started_at", "DATETIME"),
        ("invite_quota_prolite_used", "INTEGER NOT NULL DEFAULT 0"),
        ("invite_quota_legacy_window_started_at", "DATETIME"),
        ("invite_quota_legacy_used", "INTEGER NOT NULL DEFAULT 0"),
        ("invite_cooldown_started_at", "DATETIME"),
        ("invite_cooldown_until", "DATETIME"),
        ("invite_cooldown_reason", "VARCHAR NOT NULL DEFAULT ''"),
    ]
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "gpt_business_accounts" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(gpt_business_accounts)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE gpt_business_accounts ADD COLUMN {col_name} {col_ddl}")
        # One-time conservative backfill from server-reconciled membership rows.
        # Permanent PRO-burn markers are deliberately ignored: they have no
        # reliable invitation-window provenance.  Each backfilled membership also gets an
        # immutable consumed audit row so the aggregate is not an unexplained
        # integer and future operations remain target-idempotent.
        if {
            "gpt_business_child_memberships",
            "gpt_business_rotation_reservations",
        }.issubset(tables):
            now = datetime.now(timezone.utc)
            def _parsed(value):
                if isinstance(value, datetime):
                    parsed = value
                else:
                    text_value = str(value or "").strip()
                    if not text_value:
                        return None
                    try:
                        parsed = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
                    except Exception:
                        return None
                return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)

            parent_rows = conn.execute(
                "SELECT id FROM gpt_business_accounts "
                "WHERE invite_quota_window_started_at IS NULL "
                "AND COALESCE(invite_quota_used, 0) = 0 "
                "AND COALESCE(invite_quota_typed_initialized, 0) = 0"
            ).fetchall()
            for (parent_id,) in parent_rows:
                membership_rows = conn.execute(
                    "SELECT id, invited_at FROM gpt_business_child_memberships "
                    "WHERE business_account_id = ? AND invited_at IS NOT NULL "
                    "ORDER BY invited_at, id",
                    (int(parent_id),),
                ).fetchall()
                events = sorted([
                    (int(row_id), parsed)
                    for row_id, raw_time in membership_rows
                    for parsed in [_parsed(raw_time)]
                    if parsed is not None and parsed <= now
                ], key=lambda item: (item[1], item[0]))
                if not events:
                    continue
                cycle: list[tuple[int, datetime]] = []
                cycle_started_at = None
                for event in events:
                    if (
                        cycle_started_at is None
                        or event[1] >= cycle_started_at + timedelta(hours=BUSINESS_INVITE_WINDOW_HOURS)
                    ):
                        cycle_started_at = event[1]
                        cycle = [event]
                    else:
                        cycle.append(event)
                if (
                    cycle_started_at is None
                    or now >= cycle_started_at + timedelta(hours=BUSINESS_INVITE_WINDOW_HOURS)
                ):
                    continue
                started_at = cycle_started_at
                # Preserve all confirmed uses; the configured limit must not
                # cap or erase historical consumption during a backfill.
                started_db = started_at.replace(tzinfo=None).isoformat(sep=" ")
                conn.execute(
                    "UPDATE gpt_business_accounts SET "
                    "invite_quota_window_started_at = ?, invite_quota_used = ? "
                    "WHERE id = ? AND invite_quota_window_started_at IS NULL",
                    (started_db, len(cycle), int(parent_id)),
                )
                for membership_id, invited_at in cycle:
                    timestamp = invited_at.replace(tzinfo=None).isoformat(sep=" ")
                    conn.execute(
                        "INSERT OR IGNORE INTO gpt_business_rotation_reservations "
                        "(operation_id, business_account_id, action, seat_type, state, reserved_at, "
                        "resolved_at, resolution_reason, created_at, updated_at) "
                        "VALUES (?, ?, 'invite', '', 'consumed', ?, ?, "
                        "'membership_history_backfill', ?, ?)",
                        (
                            f"invite-quota-backfill-membership-{membership_id}",
                            int(parent_id),
                            timestamp,
                            timestamp,
                            timestamp,
                            timestamp,
                        ),
                    )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_accounts_invite_quota_window "
            "ON gpt_business_accounts(invite_quota_window_started_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_accounts_invite_cooldown_until "
            "ON gpt_business_accounts(invite_cooldown_until)"
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_gpt_business_automation_policies():
    """Keep CPA and Sub2API delivery target ids in separate namespaces.

    Existing installations only have ``cpa_target_id``.  Backfilling its
    provider is deterministic and does not enable any policy which was
    previously disabled.
    """
    if not DATABASE_URL.startswith("sqlite"):
        return
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "gpt_business_automation_policies" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute(
                "PRAGMA table_info(gpt_business_automation_policies)"
            ).fetchall()
        }
        if "delivery_type" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_automation_policies "
                "ADD COLUMN delivery_type VARCHAR NOT NULL DEFAULT ''"
            )
        if "sub2api_device_id" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_automation_policies "
                "ADD COLUMN sub2api_device_id INTEGER"
            )
        conn.execute(
            "UPDATE gpt_business_automation_policies "
            "SET delivery_type = 'cpa' "
            "WHERE cpa_target_id IS NOT NULL "
            "AND TRIM(COALESCE(delivery_type, '')) = ''"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS "
            "ix_gpt_business_automation_policies_sub2api_device_id "
            "ON gpt_business_automation_policies(sub2api_device_id)"
        )
        conn.commit()
        conn.close()
    except Exception:
        # Keep startup behavior consistent with the repository's additive
        # SQLite migrations; create_all handles fresh databases.
        pass


def _migrate_gpt_business_child_memberships():
    """为 BUSINESS 子号归属流水补充“当前归属”唯一约束。

    历史行允许同一子号/邮箱在不同母号重复出现；只有 ``ended_at IS NULL`` 的
    当前归属需要唯一。SQLite 的部分索引正好表达这个约束，并能兜住多进程下
    两个母号同时选择同一子号的竞态。
    """
    if not DATABASE_URL.startswith("sqlite"):
        return
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "gpt_business_child_memberships" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute(
                "PRAGMA table_info(gpt_business_child_memberships)"
            ).fetchall()
        }
        if "intent_payload_json" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN intent_payload_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "intent_remote_started" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN intent_remote_started BOOLEAN NOT NULL DEFAULT 0"
            )
        if "seat_type" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN seat_type TEXT NOT NULL DEFAULT ''"
            )
        if "sold_at" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN sold_at DATETIME"
            )
        if "sale_status" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN sale_status VARCHAR NOT NULL DEFAULT 'unlisted'"
            )
            # 旧数据已有出售时间时必须保留其真实业务含义；没有出售时间的
            # 当前子号尚未经过人工上架，因此从“未上架”开始。
            conn.execute(
                "UPDATE gpt_business_child_memberships "
                "SET sale_status='sold' WHERE sold_at IS NOT NULL"
            )
        if "warranty_hours" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN warranty_hours INTEGER NOT NULL DEFAULT 0"
            )
        if "nv_listed_at" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_listed_at DATETIME"
            )
        if "nv_listing_confirmed_at" not in existing:
            # Existing sale labels/timestamps can be operator-owned legacy
            # metadata; only a real NV confirmation may populate this field.
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_listing_confirmed_at DATETIME"
            )
        if "nv_team5x_warranty_until" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_team5x_warranty_until DATETIME"
            )
        if "nv_last_synced_at" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_last_synced_at DATETIME"
            )
        if "nv_remote_card_id" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_remote_card_id TEXT NOT NULL DEFAULT ''"
            )
        if "nv_remote_order_id" not in existing:
            conn.execute(
                "ALTER TABLE gpt_business_child_memberships "
                "ADD COLUMN nv_remote_order_id TEXT NOT NULL DEFAULT ''"
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_gpt_business_active_pro_child "
            "ON gpt_business_child_memberships(pro_account_id) "
            "WHERE ended_at IS NULL AND pro_account_id IS NOT NULL"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_gpt_business_active_parent_email "
            "ON gpt_business_child_memberships(business_account_id, lower(email)) "
            "WHERE ended_at IS NULL"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_gpt_business_active_child_email "
            "ON gpt_business_child_memberships(lower(email)) "
            "WHERE ended_at IS NULL"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_child_memberships_sold_at "
            "ON gpt_business_child_memberships(sold_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_child_memberships_sale_status "
            "ON gpt_business_child_memberships(sale_status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_child_memberships_nv_listed_at "
            "ON gpt_business_child_memberships(nv_listed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_child_memberships_nv_listing_confirmed_at "
            "ON gpt_business_child_memberships(nv_listing_confirmed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_gpt_business_child_memberships_nv_last_synced_at "
            "ON gpt_business_child_memberships(nv_last_synced_at)"
        )
        conn.commit()
        conn.close()
    except Exception:
        # 与现有迁移保持一致：启动阶段不能因为旧库的非关键索引阻塞服务。
        pass


def _migrate_gpt_business_rotation_reservations():
    """补齐滚动配额预留表在开发期演进过的列和组合索引。

    新表由 ``SQLModel.metadata.create_all`` 创建；这里只保证旧库在
    按母号 + 状态 + 预留时间做 48h 窗口计数时不会全表扫描。
    """
    if not DATABASE_URL.startswith("sqlite"):
        return
    try:
        with engine.begin() as conn:
            columns = {
                str(row[1]).lower()
                for row in conn.execute(text(
                    "PRAGMA table_info(gpt_business_rotation_reservations)"
                )).fetchall()
            }
            if not columns:
                return
            additions = [
                ("action", "VARCHAR NOT NULL DEFAULT ''"),
                ("seat_type", "VARCHAR NOT NULL DEFAULT ''"),
                ("state", "VARCHAR NOT NULL DEFAULT 'reserved'"),
                ("reserved_at", "DATETIME"),
                ("resolved_at", "DATETIME"),
                ("resolution_reason", "VARCHAR NOT NULL DEFAULT ''"),
                ("created_at", "DATETIME"),
                ("updated_at", "DATETIME"),
            ]
            for column_name, ddl in additions:
                if column_name not in columns:
                    conn.execute(text(
                        "ALTER TABLE gpt_business_rotation_reservations "
                        f"ADD COLUMN {column_name} {ddl}"
                    ))
            # Early development schemas may have rows predating the timestamp
            # columns.  Normalize them before the quota reader orders the window.
            conn.execute(text(
                "UPDATE gpt_business_rotation_reservations SET "
                "reserved_at = COALESCE(reserved_at, CURRENT_TIMESTAMP), "
                "created_at = COALESCE(created_at, reserved_at, CURRENT_TIMESTAMP), "
                "updated_at = COALESCE(updated_at, created_at, reserved_at, CURRENT_TIMESTAMP)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_gpt_business_rotation_parent_state_time "
                "ON gpt_business_rotation_reservations"
                "(business_account_id, state, reserved_at)"
            ))
    except Exception:
        pass


def _migrate_gpt_business_typed_invite_quota():
    """Split provable historical usage, retaining all unknown debt and deadlines.

    Serialized with normal quota admission; failures propagate rather than
    silently starting an empty ledger on an existing installation.
    """
    from services.business_invite_quota import initialize_locked, quota_rows

    with Session(engine) as session:
        if str(engine.url).startswith("sqlite"):
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        parents = session.exec(select(GptBusinessAccountModel).where(
            GptBusinessAccountModel.invite_quota_typed_initialized == False
        ).with_for_update()).all()
        for parent in parents:
            initialize_locked(session, parent, quota_rows(session, int(parent.id)), _utcnow())
        session.commit()


def _migrate_gpt_business_allocation_fencing():
    """为已创建过的自动分配表补充 worker fencing 字段。"""
    if not DATABASE_URL.startswith("sqlite"):
        return
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "gpt_business_allocation_jobs" in tables:
            job_columns = {
                row[1].lower()
                for row in conn.execute(
                    "PRAGMA table_info(gpt_business_allocation_jobs)"
                ).fetchall()
            }
            if "worker_token" not in job_columns:
                conn.execute(
                    "ALTER TABLE gpt_business_allocation_jobs "
                    "ADD COLUMN worker_token VARCHAR NOT NULL DEFAULT ''"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_gpt_business_allocation_jobs_worker_token "
                "ON gpt_business_allocation_jobs(worker_token)"
            )
        if "gpt_business_allocation_leases" in tables:
            lease_columns = {
                row[1].lower()
                for row in conn.execute(
                    "PRAGMA table_info(gpt_business_allocation_leases)"
                ).fetchall()
            }
            if "owner_token" not in lease_columns:
                conn.execute(
                    "ALTER TABLE gpt_business_allocation_leases "
                    "ADD COLUMN owner_token VARCHAR NOT NULL DEFAULT ''"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_gpt_business_allocation_leases_owner_token "
                "ON gpt_business_allocation_leases(owner_token)"
            )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_adobe_admin_accounts():
    """为已有的 adobe_admin_accounts 表补齐新增字段(新库由 create_all 直接建好)。"""
    new_columns = [
        ("password", "VARCHAR NOT NULL DEFAULT ''"),
        ("mail_password", "VARCHAR NOT NULL DEFAULT ''"),
        ("client_id", "VARCHAR NOT NULL DEFAULT ''"),
        ("refresh_token", "VARCHAR NOT NULL DEFAULT ''"),
        ("mail_access_type", "VARCHAR NOT NULL DEFAULT ''"),
        ("access_token", "TEXT NOT NULL DEFAULT ''"),
        ("susi_token", "TEXT NOT NULL DEFAULT ''"),
        ("cookie_json", "TEXT NOT NULL DEFAULT '{}'"),
        ("org_id", "VARCHAR NOT NULL DEFAULT ''"),
        ("product_id", "VARCHAR NOT NULL DEFAULT ''"),
        ("license_group_id", "VARCHAR NOT NULL DEFAULT ''"),
        ("org_name", "VARCHAR NOT NULL DEFAULT ''"),
        ("product_name", "VARCHAR NOT NULL DEFAULT ''"),
        ("product_credits", "INTEGER NOT NULL DEFAULT 0"),
        ("status", "VARCHAR NOT NULL DEFAULT '未登录'"),
        ("last_login_at", "DATETIME"),
        ("last_error", "VARCHAR NOT NULL DEFAULT ''"),
        ("invited_emails_json", "VARCHAR NOT NULL DEFAULT '[]'"),
        ("note", "VARCHAR NOT NULL DEFAULT ''"),
        ("enabled", "BOOLEAN NOT NULL DEFAULT 1"),
    ]
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "adobe_admin_accounts" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(adobe_admin_accounts)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE adobe_admin_accounts ADD COLUMN {col_name} {col_ddl}")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_cards():
    """为已有的 cards 表补齐 use_count 字段。"""
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "cards" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(cards)").fetchall()
        }
        if "use_count" not in existing:
            conn.execute("ALTER TABLE cards ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0")
        if "priority" not in existing:
            conn.execute("ALTER TABLE cards ADD COLUMN priority INTEGER NOT NULL DEFAULT 100")
        if "payment_account_id" not in existing:
            conn.execute("ALTER TABLE cards ADD COLUMN payment_account_id INTEGER NOT NULL DEFAULT 0")
        if "opened_at" not in existing:
            conn.execute("ALTER TABLE cards ADD COLUMN opened_at DATETIME")
        conn.commit()
        conn.close()
    except Exception:
        pass
    _migrate_orphan_cards_to_default_account()


def _migrate_payment_accounts():
    """给已有的 payment_accounts 表补齐新增列(roxy_dir_id / last_card_opened_at)。"""
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "payment_accounts" not in tables:
            conn.close()
            return
        existing = {r[1].lower() for r in conn.execute("PRAGMA table_info(payment_accounts)").fetchall()}
        if "roxy_dir_id" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN roxy_dir_id VARCHAR NOT NULL DEFAULT ''")
        if "last_card_opened_at" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN last_card_opened_at DATETIME")
        if "balance_usd" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN balance_usd FLOAT NOT NULL DEFAULT 0")
        if "balance_text" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN balance_text VARCHAR NOT NULL DEFAULT ''")
        if "balance_updated_at" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN balance_updated_at DATETIME")
        if "pending_refund_count" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN pending_refund_count INTEGER NOT NULL DEFAULT 0")
        if "pending_refund_updated_at" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN pending_refund_updated_at DATETIME")
        if "paid_count" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN paid_count INTEGER NOT NULL DEFAULT 0")
        if "refunded_count" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN refunded_count INTEGER NOT NULL DEFAULT 0")
        if "card_open_count" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN card_open_count INTEGER NOT NULL DEFAULT 0")
        if "unrefunded_dates_json" not in existing:
            conn.execute("ALTER TABLE payment_accounts ADD COLUMN unrefunded_dates_json VARCHAR NOT NULL DEFAULT '[]'")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_business_masters():
    """给已有 business_masters 表补新增列(新库由 create_all 建全)。"""
    if not DATABASE_URL.startswith("sqlite"):
        return
    import sqlite3
    try:
        conn = sqlite3.connect(DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", ""))
        existing = {r[1].lower() for r in conn.execute("PRAGMA table_info(business_masters)").fetchall()}
        if not existing:      # 表还不存在(create_all 会建), 跳过
            conn.close()
            return
        if "stats_json" not in existing:
            conn.execute("ALTER TABLE business_masters ADD COLUMN stats_json VARCHAR NOT NULL DEFAULT ''")
        if "stats_updated_at" not in existing:
            conn.execute("ALTER TABLE business_masters ADD COLUMN stats_updated_at DATETIME")
        if "plan_seats" not in existing:
            conn.execute("ALTER TABLE business_masters ADD COLUMN plan_seats INTEGER NOT NULL DEFAULT 0")
        if "billing_paused_until" not in existing:
            conn.execute("ALTER TABLE business_masters ADD COLUMN billing_paused_until DATETIME")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_orphan_cards_to_default_account():
    """把未归属(payment_account_id=0)的旧卡迁移到一个默认支付账号下(类型 Y卡, is_default=True)。"""
    try:
        with Session(engine) as s:
            orphans = s.exec(select(CardModel).where(CardModel.payment_account_id == 0)).all()
            if not orphans:
                return
            default = s.exec(
                select(PaymentAccountModel).where(PaymentAccountModel.is_default == True)  # noqa: E712
            ).first()
            if not default:
                default = PaymentAccountModel(
                    name="默认(旧卡迁移)", account_type="Y", is_default=True,
                    note="系统自动创建, 收纳重构前已有的卡, 不受 5 张上限",
                )
                s.add(default)
                s.commit()
                s.refresh(default)
            for c in orphans:
                c.payment_account_id = default.id
                s.add(c)
            s.commit()
            print(f"[DB] 已把 {len(orphans)} 张旧卡迁移到默认支付账号(id={default.id})")
    except Exception as exc:
        print(f"[DB] 旧卡迁移失败(忽略): {exc}")


def _migrate_outlook_accounts():
    """为已有的 outlook_accounts 表补齐新增字段。"""
    new_columns = [
        ("mail_access_type", "VARCHAR NOT NULL DEFAULT ''"),
        ("gpt_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("grok_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("trae_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("kiro_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("obl_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("cursor_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
        ("adobe_register_status", "VARCHAR NOT NULL DEFAULT '未注册'"),
    ]
    import sqlite3 as _sqlite3
    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(outlook_accounts)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(f"ALTER TABLE outlook_accounts ADD COLUMN {col_name} {col_ddl}")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_cfworker_subdomains():
    """为已有的 cfworker_subdomains 表补齐新增字段。"""
    new_columns = [
        ("max_accounts", "INTEGER NOT NULL DEFAULT 100"),
        ("used_count", "INTEGER NOT NULL DEFAULT 0"),
        ("inflight_count", "INTEGER NOT NULL DEFAULT 0"),
        ("enabled", "BOOLEAN NOT NULL DEFAULT 1"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
    ]
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "cfworker_subdomains" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(cfworker_subdomains)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(
                    f"ALTER TABLE cfworker_subdomains ADD COLUMN {col_name} {col_ddl}"
                )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _migrate_sync_devices():
    new_columns = [
        ("priority", "INTEGER NOT NULL DEFAULT 0"),
        ("sync_batch_size", "INTEGER NOT NULL DEFAULT 5"),
        ("auto_replenish_batch_size", "INTEGER NOT NULL DEFAULT 0"),
        ("default_proxy_id", "INTEGER NOT NULL DEFAULT -1"),
        ("business_domains", "VARCHAR NOT NULL DEFAULT '[]'"),  # BUSINESS 域名 JSON 数组
        ("wants_refresh_token", "BOOLEAN NOT NULL DEFAULT 1"),  # 走 RT 链路开关(CPA/SUB+BUSINESS)
    ]
    import sqlite3 as _sqlite3

    raw_url = str(DATABASE_URL).replace("sqlite:///", "", 1)
    try:
        conn = _sqlite3.connect(raw_url)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "sync_devices" not in tables:
            conn.close()
            return
        existing = {
            row[1].lower()
            for row in conn.execute("PRAGMA table_info(sync_devices)").fetchall()
        }
        for col_name, col_ddl in new_columns:
            if col_name.lower() not in existing:
                conn.execute(
                    f"ALTER TABLE sync_devices ADD COLUMN {col_name} {col_ddl}"
                )
        # 一次性 backfill: 把现有 CPA/SUB 设备的 wants_refresh_token 都设为 1。
        # 用 config_store 里的标记保证只跑一次,避免覆盖运营之后手动关闭的选择。
        if "wants_refresh_token" in existing or any(
            n == "wants_refresh_token" for n, _ in new_columns
        ):
            try:
                from core.config_store import config_store
                if config_store.get("_wants_rt_backfill_v1", "") != "done":
                    conn.execute(
                        "UPDATE sync_devices SET wants_refresh_token = 1 "
                        "WHERE LOWER(type) IN ('cpa', 'sub')"
                    )
                    config_store.set("_wants_rt_backfill_v1", "done")
            except Exception:
                pass
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_session():
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# 卡池操作 (CardModel)
# ---------------------------------------------------------------------------


def reserve_card(account_id: int) -> Optional['CardModel']:
    """从卡池中取一张 unused 的卡并标记为 in_use,绑定到指定 account_id。

    单事务内 SELECT + UPDATE,避免并发取同一张卡。返回卡对象;池空返回 None。
    """
    with Session(engine) as session:
        card = session.exec(
            select(CardModel)
            .where(CardModel.status == "unused")
            .where(CardModel.enabled == True)  # noqa: E712
            .order_by(CardModel.id.asc())
        ).first()
        if not card:
            return None
        card.status = "in_use"
        card.reserved_by_account_id = account_id
        card.reserved_at = _utcnow()
        card.updated_at = _utcnow()
        session.add(card)
        session.commit()
        session.refresh(card)
        return card


def release_card(card_id: int) -> None:
    """把一张 in_use 卡回滚到 unused(取消支付时调)"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card or card.status != "in_use":
            return
        card.status = "unused"
        card.reserved_by_account_id = 0
        card.reserved_at = None
        card.updated_at = _utcnow()
        session.add(card)
        session.commit()


def mark_card_used(card_id: int) -> None:
    """支付成功后标记卡为 used"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            return
        card.status = "used"
        card.used_at = _utcnow()
        card.last_error = ""
        card.updated_at = _utcnow()
        session.add(card)
        session.commit()


def mark_card_failed(card_id: int, error: str) -> None:
    """支付失败时记录原因,卡留在 failed 状态等人工干预"""
    with Session(engine) as session:
        card = session.get(CardModel, card_id)
        if not card:
            return
        card.status = "failed"
        card.last_error = (error or "")[:500]
        card.updated_at = _utcnow()
        session.add(card)
        session.commit()
