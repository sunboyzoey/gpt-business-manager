from datetime import datetime, timezone
import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from core.business_invite_mail_provider import (
    BUSINESS_INVITE_MAIL_PROVIDER_KEYS,
    get_business_invite_mail_providers,
    validate_business_invite_mail_provider,
)
from core.config_store import ConfigItem, config_store
from core.secret_store import has_secret, set_secret
from sqlmodel import Session, select
from core.db import CFWorkerSubdomainModel, engine

router = APIRouter(prefix="/config", tags=["config"])

SECRET_CONFIG_KEYS = frozenset({
    "smsbower_api_key", "sms_smsbower_api_key", "sms_grizzly_api_key",
})

CONFIG_KEYS = [
    "laoudo_auth",
    "laoudo_email",
    "laoudo_account_id",
    "yescaptcha_key",
    "twocaptcha_key",
    "default_executor",
    "default_captcha_solver",
    "default_proxy",
    "register_auto_use_proxy",
    "chatgpt_security_after_register",
    "duckmail_api_url",
    "duckmail_provider_url",
    "duckmail_bearer",
    "duckmail_domain",
    "duckmail_api_key",
    "freemail_api_url",
    "freemail_admin_token",
    "freemail_username",
    "freemail_password",
    "freemail_domain",
    "moemail_api_url",
    "moemail_api_key",
    "skymail_api_base",
    "skymail_token",
    "skymail_domain",
    "cloudmail_api_base",
    "cloudmail_admin_email",
    "cloudmail_admin_password",
    "cloudmail_domain",
    "cloudmail_subdomain",
    "cloudmail_timeout",
    "mail_provider",
    "mailbox_otp_timeout_seconds",
    "maliapi_base_url",
    "maliapi_api_key",
    "maliapi_domain",
    "maliapi_auto_domain_strategy",
    "applemail_base_url",
    "applemail_pool_dir",
    "applemail_pool_file",
    "applemail_mailboxes",
    # iCloud HME (本地 Go 服务, 旧方案)
    "icloud_hme_base_url",
    "icloud_hme_api_key",
    "icloud_hme_pool_file",
    # iCloud HME (原生 Python 客户端, 只需一个 iCloud 网页会话 Cookie)
    "icloud_cookie",
    # QQ 邮箱 (IMAP 收 iCloud HME 转发邮件)
    "qqmail_user",
    "qqmail_auth_code",
    "qqmail_imap_host",
    "qqmail_imap_port",
    "qqmail_pool_file",
    "qqmail_mailbox",
    "qqmail_require_apple_header",
    # iCloud 收件方式切换: qqmail(默认, HME 转发到 QQ) | icloud_imap(HME 转发到 iCloud, 直读 iCloud IMAP)
    "icloud_receive_via",
    "icloud_imap_host",
    "icloud_imap_user",
    "icloud_imap_password",
    # iCloud 别名发信(SMTP): 以 HME 别名为 From 发件/回复
    "icloud_smtp_apple_id",
    "icloud_smtp_app_password",
    "icloud_smtp_host",
    "icloud_smtp_port",
    "gptmail_base_url",
    "gptmail_api_key",
    "gptmail_domain",
    "opentrashmail_api_url",
    "opentrashmail_domain",
    "opentrashmail_password",
    "cfworker_api_url",
    "cfworker_admin_token",
    "cfworker_custom_auth",
    "cfworker_domain",
    "cfworker_domains",
    "cfworker_enabled_domains",
    "cfworker_subdomain",
    "cfworker_force_subdomain",
    "cfworker_subdomain_strategy",
    "cfworker_subdomain_prefix",
    "cfworker_subdomain_max_accounts",
    "cfworker_subdomain_release_on_delete",
    "cfworker_random_subdomain",
    "cfworker_random_name_subdomain",
    "cfworker_fingerprint",
    "cfworker_quick_api_url",
    "smstome_cookie",
    "smstome_country_slugs",
    "smstome_phone_attempts",
    "smstome_otp_timeout_seconds",
    "smstome_poll_interval_seconds",
    "smstome_sync_max_pages_per_country",
    "smsbower_api_key",
    "smsbower_base_url",
    "smsbower_service",
    "smsbower_country",
    "smsbower_countries",
    "smsbower_max_price",
    "smsbower_proxy",
    "smsbower_max_attempts",
    "smsbower_otp_timeout_seconds",
    "smsbower_poll_interval_seconds",
    "luckmail_base_url",
    "luckmail_api_key",
    "luckmail_email_type",
    "luckmail_domain",
    "cpa_api_url",
    "cpa_api_key",
    "cpa_cleanup_enabled",
    "cpa_cleanup_interval_minutes",
    "cpa_cleanup_threshold",
    "cpa_cleanup_concurrency",
    "cpa_cleanup_register_delay_seconds",
    "sub2api_api_url",
    "sub2api_api_key",
    "sub2api_group_ids",
    "team_manager_url",
    "team_manager_key",
    "team_manager_business_team_id",
    "team_manager_business_verify",
    "team_manager_business_stop_on_error",
    "chatgpt_oauth_output_dir",
    "chatgpt_oauth_otp_wait_seconds",
    "chatgpt_rt_allow_phone_verification",
    "codex_app_ready_wait_seconds",
    "codex_app_pre_type_delay_seconds",
    "codex_app_name",
    "gpt_pro_app_reply_wait_seconds",
    "codex_proxy_url",
    "codex_proxy_key",
    "codex_proxy_upload_type",
    "cliproxyapi_base_url",
    "cliproxyapi_management_key",
    "payment_bridge_admin_token",
    "grok2api_url",
    "grok2api_app_key",
    "grok2api_pool",
    "grok2api_quota",
    "grok_payment_proxy_node",
    "grok_payment_proxy",
    "kiro_manager_path",
    "kiro_manager_exe",
    "kiro_manager_api_url",
    "kiro_manager_api_key",
    "proxy_subscription_url",
    # Devin / WindsurfAPI 自动上号（内部测试）—— 邮箱走全局 mail_provider
    "devin_server_url",
    "devin_api_key",
    "devin_dashboard_password",
    "devin_auth_base",
    "windsurf_post_auth_url",
    "windsurf_auth_output_dir",
    "windsurf_pool_api_base_url",
    "windsurf_pool_auto_import",
    "windsurf_pool_import_required",
    "windsurf_pricing_url",
    "windsurf_http_timeout",
    "windsurf_password_length",
    "windsurf_display_name_length",
    "windsurf_user_agent",
    # BUSINESS 子域
    "cf_api_token",
    "openai_admin_cookies",
    "business_default_base_domain",
    "business_email_machine_prefix",
    "business_machine_id",  # 多机隔离: 本机 BUSINESS 子域归属标识 (空 = 自动用 hostname 哈希)
    "business_invite_default_mail_provider", "business_invite_prolite_mail_provider",
    "business_rt_submit_interval_ms",  # BUSINESS RT worker 补位间隔,默认 800ms; 0=关闭节流
    "business_rt_otp_timeout_streak_threshold",  # 连续 OTP 超时 N 次记 1 次域名失败,默认 5
    "business_rt_domain_failure_limit",          # 域名失败累计 N 次后拉黑,默认 20
    "business_rt_domain_failure_pause_seconds",  # 每次域名失败后的短暂停顿,默认 60s
    "business_rt_auto_delete_banned_domains",    # '1' 自动删除已拉黑子域并按默认根域补新,默认关闭
    "cpa_sync_business_only",
    # 动态住宅代理 (711proxy 风格 rotating API)
    "dynamic_proxy_enabled",       # '1' 启用; 启用后注册时优先用动态 IP
    "dynamic_proxy_api_url",       # 完整 URL, 如 http://global.rotgbapi.711proxy.com:8089/gen?zone=...&sessType=rotating
    "dynamic_proxy_api_via",       # 调 711proxy /gen 接口时走的代理, 空=直连
    "dynamic_proxy_force_sessid",  # '1' 每次调 /gen 追加 &sessid=随机 强制换 IP (默认开)
    # OAuth 阶段自动 add_phone(BUSINESS 子号事后补拉 RT 时用)
    "chatgpt_add_phone_number",
    "chatgpt_add_phone_sms_api_url",
    "chatgpt_add_phone_sms_timeout",
    # BUSINESS 注册成功后自动切 Codex 席位的限速
    "business_codex_switch_interval_ms",
    # 母号管理的 BUSINESS workspace id (chatgpt_account_id).
    # 不配的话, 会自动调 /accounts/check 发现; 多 workspace 场景必须显式指定。
    "openai_business_account_id",
    # BUSINESS 新流程(注册→邀请→激活→切席位→RT)开关与参数
    "business_new_flow_enabled",                     # '1' 默认; '0' 回到旧 4 阶段一站式
    "business_invite_batch_size",                    # 默认 6
    "business_invite_batch_interval_seconds",        # 默认 10
    "business_invite_max_retries",                   # 默认 5
    "business_activate_concurrency",                 # 默认 5
    "business_activate_seat_wait_seconds",           # 默认 10
    "business_seat_switch_retry_count",              # 默认 3
    "business_seat_switch_retry_interval_seconds",   # 默认 5
    "business_seat_target",                          # 默认 'default' (ChatGPT 席位), 可选 'usage_based'
    # Peer-to-peer 待 RT 同步(多机协作,替代原 pg_dsn 方案)
    "peer_sync_role",                  # producer / consumer / off
    "peer_sources",                    # JSON: [{"name":"reg-a","base_url":"http://10.0.0.1:8000"}, ...]
    "peer_pull_batch",                 # 单次每个 peer 最多拉多少条 (默认 20)
    "peer_pull_local_threshold",       # 本机 pending_rt < 阈值才向 peer 要 (默认 5)
    "peer_pull_timeout_seconds",       # HTTP 拉取超时 (默认 20)
    # 补 RT 时的 OAuth 浏览器模式:protocol / headless / headed
    # 默认 headless(绕过 OpenAI 新流程的 workspace_select 死循环 bug)
    "business_rt_oauth_browser_mode",
    # RoxyBrowser 服务连接是本机基础设施；两个业务界面的升级策略、代理
    # 库和选中项分别持久化，互不覆盖。
    # 本地 API 打开固定 profile 供 DrissionPage 接管, 抗 DrissionPage 自建 Chromium 被封控
    "roxybrowser_api_host",        # 默认 http://127.0.0.1:50000
    "roxybrowser_api_token",       # RoxyBrowser -> API -> API Key
    "roxybrowser_workspace_id",    # 工作区 id
    "roxybrowser_dir_id",          # 固定复用的浏览器窗口 dirId
    "roxybrowser_clear_cookie",    # '1'(默认) 每次接管前清 cookie/缓存, 避免账号串号
    # 旧 GPT PRO 升级浏览器策略（专用接口管理）。
    "gpt_upgrade_browser_backend",  # local(默认) | roxybrowser
    "gpt_upgrade_roxy_proxy_id",   # roxy_proxies.id；local 时为空
    # GPT 套餐管理专属升级浏览器策略；代理 id 指向 gpt_plan_roxy_proxies。
    "gpt_plan_upgrade_browser_backend",
    "gpt_plan_upgrade_roxy_proxy_id",
    # GPT 套餐管理专属升级/支付/设备自动化参数。虽然由通用 KV 配置服务
    # 承载，但 key namespace 完全独立，删除 GPT PRO 功能不会影响它们。
    "gpt_plan_checkout_country",
    "gpt_plan_checkout_currency",
    "gpt_plan_business_coupon",  # BUSINESS 支付链接默认优惠码
    "gpt_plan_card_max_uses",
    "gpt_plan_ph_go_first",
    "gpt_plan_go_plan_name",
    "gpt_plan_go_to_pro_wait_seconds",
    "gpt_plan_app_reply_wait_seconds",
    "gpt_plan_auto_delete_dead_on_login",
    "gpt_plan_cpa_api_key",
    "gpt_plan_cpa_api_url",
    "gpt_plan_cpa_auto_buy",
    "gpt_plan_cpa_auto_refund_enabled",
    "gpt_plan_cpa_device_id",
    "gpt_plan_cpa_devices",
    "gpt_plan_cpa_enabled",
    "gpt_plan_cpa_interval_minutes",
    "gpt_plan_cpa_max_per_run",
    "gpt_plan_cpa_recycle_hour",
    "gpt_plan_cpa_refund_days",
    "gpt_plan_cpa_threshold",
    "gpt_plan_cpa_sync_targets",
    "gpt_plan_cpa_sync_targets_revision",
    "gpt_plan_referral_cf_domain",
    "gpt_plan_referral_cf_domains_json",
    "gpt_plan_reward_wait_seconds",
    "gpt_plan_sub2api_auto_remove",
    # GPT PRO 停用申诉「自动填」的两段文案 + 是否自动提交(界面可配)
    "gpt_pro_appeal_why_text",       # "Why the warning or deactivation should be reversed"
    "gpt_pro_appeal_context_text",   # "Additional supporting context"
    "gpt_pro_appeal_auto_submit",    # '1'(默认) 填好自动点 Submit Appeal; '0' 只填不提交
]

DEVIN_CONFIG_KEYS = [
    "mail_provider",
    "devin_server_url",
    "devin_api_key",
    "devin_dashboard_password",
    "devin_auth_base",
    "windsurf_post_auth_url",
]

EXPORT_CONFIG_KEYS = sorted(set(CONFIG_KEYS + DEVIN_CONFIG_KEYS))
PORTABLE_CONFIG_KEYS = frozenset(
    key for key in EXPORT_CONFIG_KEYS if not key.startswith("auth_")
)


class ConfigUpdate(BaseModel):
    data: dict


class ConfigImportRequest(BaseModel):
    configs: dict | None = None
    data: dict | None = None


class BusinessInviteMailProvidersUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    default: Literal["icloud", "gmail", "outlook"]
    prolite: Literal["icloud", "gmail", "outlook"]


@router.get("/business-invite-mail-providers")
def get_business_invite_mail_providers_config():
    with Session(engine) as session:
        return get_business_invite_mail_providers(session)


@router.put("/business-invite-mail-providers")
def update_business_invite_mail_providers_config(body: BusinessInviteMailProvidersUpdate):
    values = body.model_dump()
    with Session(engine) as session:
        for seat, key in BUSINESS_INVITE_MAIL_PROVIDER_KEYS.items():
            item = session.get(ConfigItem, key) or ConfigItem(key=key)
            item.value = validate_business_invite_mail_provider(values[seat])
            session.add(item)
        session.commit()
    return values


class AppleMailImportRequest(BaseModel):
    content: str
    filename: str = ""
    pool_dir: str = ""
    bind_to_config: bool = True


def _is_portable_config_key(key: object) -> bool:
    normalized = str(key or "")
    # The old implementation accepted every syntactically valid database key,
    # which could export/import auth_jwt_secret and auth_password_hash.  A
    # portable package is now a strict allowlist of user-facing settings.
    return normalized in PORTABLE_CONFIG_KEYS


@router.get("")
def get_config():
    all_cfg = config_store.get_all()
    with Session(engine) as session:
        providers = get_business_invite_mail_providers(session)
        all_cfg.update({BUSINESS_INVITE_MAIL_PROVIDER_KEYS[kind]: value for kind, value in providers.items()})
    if not all_cfg.get("register_auto_use_proxy"):
        all_cfg["register_auto_use_proxy"] = "1"
    if not all_cfg.get("chatgpt_security_after_register"):
        all_cfg["chatgpt_security_after_register"] = "1"
    if not all_cfg.get("mail_provider"):
        all_cfg["mail_provider"] = "luckmail"
    if not all_cfg.get("applemail_base_url"):
        all_cfg["applemail_base_url"] = "https://www.appleemail.top"
    if not all_cfg.get("applemail_pool_dir"):
        all_cfg["applemail_pool_dir"] = "mail"
    if not all_cfg.get("applemail_mailboxes"):
        all_cfg["applemail_mailboxes"] = "INBOX,Junk"
    if not all_cfg.get("icloud_hme_base_url"):
        all_cfg["icloud_hme_base_url"] = "http://127.0.0.1:8787"
    if not all_cfg.get("icloud_hme_pool_file"):
        all_cfg["icloud_hme_pool_file"] = "mail/icloud_hme.txt"
    if not all_cfg.get("qqmail_imap_host"):
        all_cfg["qqmail_imap_host"] = "imap.qq.com"
    if not all_cfg.get("qqmail_imap_port"):
        all_cfg["qqmail_imap_port"] = "993"
    if not all_cfg.get("qqmail_pool_file"):
        all_cfg["qqmail_pool_file"] = "mail/icloud_hme.txt"
    if not all_cfg.get("qqmail_mailbox"):
        all_cfg["qqmail_mailbox"] = "INBOX"
    if not all_cfg.get("qqmail_require_apple_header"):
        all_cfg["qqmail_require_apple_header"] = "1"
    if not all_cfg.get("gptmail_base_url"):
        all_cfg["gptmail_base_url"] = "https://mail.chatgpt.org.uk"
    if not all_cfg.get("luckmail_base_url"):
        all_cfg["luckmail_base_url"] = "https://mails.luckyous.com/"
    if not all_cfg.get("cfworker_force_subdomain"):
        all_cfg["cfworker_force_subdomain"] = "1"
    if not all_cfg.get("cfworker_subdomain_strategy"):
        all_cfg["cfworker_subdomain_strategy"] = "counter"
    if not all_cfg.get("cfworker_subdomain_prefix"):
        all_cfg["cfworker_subdomain_prefix"] = "acc"
    if not all_cfg.get("cfworker_subdomain_max_accounts"):
        all_cfg["cfworker_subdomain_max_accounts"] = "100"
    if not all_cfg.get("cfworker_subdomain_release_on_delete"):
        all_cfg["cfworker_subdomain_release_on_delete"] = "1"
    if not all_cfg.get("cfworker_quick_api_url"):
        all_cfg["cfworker_quick_api_url"] = "https://temp-api.cursom.shop"
    if not all_cfg.get("grok_payment_proxy_node"):
        all_cfg["grok_payment_proxy_node"] = "🇯🇵 日本A11 | IEPL"
    if not all_cfg.get("team_manager_business_team_id"):
        all_cfg["team_manager_business_team_id"] = "1"
    if not all_cfg.get("team_manager_business_verify"):
        all_cfg["team_manager_business_verify"] = "0"
    if not all_cfg.get("team_manager_business_stop_on_error"):
        all_cfg["team_manager_business_stop_on_error"] = "0"
    if not all_cfg.get("chatgpt_oauth_output_dir"):
        all_cfg["chatgpt_oauth_output_dir"] = "oauth_out"
    if not all_cfg.get("windsurf_auth_output_dir"):
        all_cfg["windsurf_auth_output_dir"] = "data/windsurf/auth_output"
    if not all_cfg.get("windsurf_pool_api_base_url"):
        all_cfg["windsurf_pool_api_base_url"] = "http://localhost:3003"
    if not all_cfg.get("windsurf_pool_auto_import"):
        all_cfg["windsurf_pool_auto_import"] = "0"
    if not all_cfg.get("windsurf_pricing_url"):
        all_cfg["windsurf_pricing_url"] = "https://windsurf.com/pricing"
    if not all_cfg.get("windsurf_http_timeout"):
        all_cfg["windsurf_http_timeout"] = "30"
    if not all_cfg.get("windsurf_password_length"):
        all_cfg["windsurf_password_length"] = "12"
    if not all_cfg.get("windsurf_display_name_length"):
        all_cfg["windsurf_display_name_length"] = "10"
    if not all_cfg.get("roxybrowser_api_host"):
        all_cfg["roxybrowser_api_host"] = "http://127.0.0.1:50000"
    if not all_cfg.get("roxybrowser_clear_cookie"):
        all_cfg["roxybrowser_clear_cookie"] = "1"
    # 申诉文案默认值(未配置时回显内置默认, 供界面编辑)
    if not all_cfg.get("gpt_pro_appeal_auto_submit"):
        all_cfg["gpt_pro_appeal_auto_submit"] = "1"
    if not all_cfg.get("gpt_pro_appeal_why_text") or not all_cfg.get("gpt_pro_appeal_context_text"):
        try:
            from platforms.chatgpt.appeal_form import APPEAL_WHY_TEXT, APPEAL_CONTEXT_TEXT
            if not all_cfg.get("gpt_pro_appeal_why_text"):
                all_cfg["gpt_pro_appeal_why_text"] = APPEAL_WHY_TEXT
            if not all_cfg.get("gpt_pro_appeal_context_text"):
                all_cfg["gpt_pro_appeal_context_text"] = APPEAL_CONTEXT_TEXT
        except Exception:
            pass
    # 只返回已知 key，未设置的返回空字符串
    result = {k: all_cfg.get(k, "") for k in CONFIG_KEYS}
    for key in SECRET_CONFIG_KEYS:
        if key in result:
            result[key] = ""
    result["smsbower_api_key_configured"] = "1" if (
        has_secret("sms_smsbower_api_key") or has_secret("smsbower_api_key")
    ) else "0"
    return result


@router.put("")
def update_config(body: ConfigUpdate):
    # 只允许更新已知 key
    safe = {k: v for k, v in body.data.items() if k in CONFIG_KEYS}
    for key in SECRET_CONFIG_KEYS.intersection(safe):
        value = str(safe.pop(key) or "").strip()
        # Blank input means "keep current" so password fields never need to
        # round-trip a secret. The dedicated provider API can rotate it.
        if value:
            set_secret(key, value)
    _validate_business_invite_config(safe)
    config_store.set_many(safe)
    # 如果改了 business_machine_id, 清缓存让下次读到新值
    if "business_machine_id" in safe:
        try:
            from core.machine_id import invalidate_machine_id_cache
            invalidate_machine_id_cache()
        except Exception:
            pass
    return {"ok": True, "updated": list(safe.keys())}


def _validate_business_invite_config(values: dict):
    _validate_business_invite_mail_config(values)


def _validate_business_invite_mail_config(values: dict):
    for key in BUSINESS_INVITE_MAIL_PROVIDER_KEYS.values():
        if key in values:
            try:
                values[key] = validate_business_invite_mail_provider(values[key])
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc


@router.get("/export")
def export_config():
    all_cfg = config_store.get_all()
    configs = {
        key: str(all_cfg.get(key, "") or "")
        for key in PORTABLE_CONFIG_KEYS
        if key not in SECRET_CONFIG_KEYS and str(all_cfg.get(key, "") or "").strip()
    }
    with Session(engine) as session:
        db_items = session.exec(select(ConfigItem)).all()
    for item in db_items:
        if (_is_portable_config_key(item.key) and item.key not in SECRET_CONFIG_KEYS
                and str(item.value or "").strip()):
            configs[item.key] = str(item.value or "")
    return {
        "schema": "any-auto-register.config",
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "configs": configs,
        "excluded": ["accounts", "outlook_accounts", "icloud_hme_aliases", "sync_devices", "task_logs", "task_queue"],
    }


@router.get("/export-file")
def export_config_file():
    data = export_config()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=json.dumps(data, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="any-auto-register-config-{stamp}.json"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/import")
def import_config(body: ConfigImportRequest):
    raw = body.configs if body.configs is not None else body.data
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="配置包格式错误: 缺少 configs")

    # Validate before legacy import stringification; booleans, lists and other
    # non-string values must not bypass the dedicated setting's strict schema.
    _validate_business_invite_mail_config(raw)
    safe = {
        str(key): "" if value is None else str(value)
        for key, value in raw.items()
        if _is_portable_config_key(key)
    }
    ignored = sorted(str(key) for key in raw.keys() if not _is_portable_config_key(key))
    _validate_business_invite_config(safe)
    if safe:
        config_store.set_many(safe)
    return {
        "ok": True,
        "updated": sorted(safe.keys()),
        "updated_count": len(safe),
        "ignored": ignored,
        "ignored_count": len(ignored),
    }


class CFWorkerTestRequest(BaseModel):
    api_url: str = ""
    admin_token: str = ""
    custom_auth: str = ""


class CFWorkerSubdomainUpdateRequest(BaseModel):
    enabled: bool


@router.post("/cfworker/test")
def test_cfworker_connection(body: CFWorkerTestRequest):
    """测试 CF Worker 连接，并自动获取全部可用域名"""
    import requests as _requests
    import secrets

    api_url = str(body.api_url or config_store.get("cfworker_api_url", "")).strip().rstrip("/")
    admin_token = str(body.admin_token or config_store.get("cfworker_admin_token", "")).strip()
    custom_auth = str(body.custom_auth or config_store.get("cfworker_custom_auth", "")).strip()

    if not api_url:
        return {"ok": False, "error": "API URL 未配置"}

    # ── Step 1: 调用 /open_api/settings 获取全部域名（公开接口，无需认证）──
    all_domains: list[str] = []
    worker_version = ""
    try:
        resp_settings = _requests.get(f"{api_url}/open_api/settings", timeout=15)
        if resp_settings.status_code == 200:
            settings_data = resp_settings.json() if resp_settings.content else {}
            raw_domains = settings_data.get("domains") or settings_data.get("defaultDomains") or []
            if isinstance(raw_domains, list):
                all_domains = [str(d).strip() for d in raw_domains if str(d).strip()]
            worker_version = str(settings_data.get("version", "")).strip()
    except Exception:
        pass

    # ── Step 2: 验证 Admin 认证（创建测试邮箱）──
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
    }
    if admin_token:
        headers["x-admin-auth"] = admin_token
    if custom_auth:
        headers["x-custom-auth"] = custom_auth

    auth_ok = False
    warning = ""
    detected_domain = ""

    def _post_new_address(req_headers: dict):
        payload = {"enablePrefix": True, "name": test_name}
        responses = []
        for path in ("/api/new_address", "/admin/new_address"):
            resp = _requests.post(
                f"{api_url}{path}",
                headers=req_headers,
                json=payload,
                timeout=15,
            )
            responses.append(resp)
            if resp.status_code == 200:
                return resp
        return responses[0] if responses else None

    try:
        test_name = f"_conntest_{secrets.token_hex(4)}"
        resp = _post_new_address(headers)

        if resp.status_code == 200:
            auth_ok = True
            data = resp.json() if resp.content else {}
            test_email = str(data.get("email") or data.get("address") or "")
            if "@" in test_email:
                detected_domain = test_email.split("@", 1)[1]
        elif resp.status_code in (401, 403):
            # 自动交换 admin_token ↔ custom_auth 重试
            retry_headers = dict(headers)
            if admin_token and custom_auth:
                retry_headers["x-admin-auth"] = custom_auth
                retry_headers["x-custom-auth"] = admin_token
            elif admin_token:
                retry_headers["x-custom-auth"] = admin_token
            elif custom_auth:
                retry_headers["x-admin-auth"] = custom_auth

            resp2 = _post_new_address(retry_headers)
            if resp2.status_code == 200:
                auth_ok = True
                data2 = resp2.json() if resp2.content else {}
                test_email = str(data2.get("email") or data2.get("address") or "")
                if "@" in test_email:
                    detected_domain = test_email.split("@", 1)[1]
                warning = "Admin Token 和站点密码可能填反了，建议检查"
            else:
                # 即使 admin 认证失败，如果域名已经通过 open_api 获取到，也算部分成功
                if all_domains:
                    return {
                        "ok": True,
                        "message": f"已获取 {len(all_domains)} 个域名（Admin 认证未通过，注册时可能失败）",
                        "detected_domains": all_domains,
                        "warning": "Admin Token 或站点密码不正确，域名已通过公开接口获取",
                        "version": worker_version,
                    }
                return {
                    "ok": False,
                    "error": "认证失败，请检查 Admin Token 和站点密码",
                }
        else:
            return {"ok": False, "error": f"请求失败 (HTTP {resp.status_code})"}

    except _requests.exceptions.ConnectTimeout:
        return {"ok": False, "error": "连接超时，请检查 API URL"}
    except _requests.exceptions.SSLError as e:
        return {"ok": False, "error": f"SSL 错误: {str(e)[:100]}"}
    except _requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "NameResolutionError" in msg or "getaddrinfo" in msg:
            return {"ok": False, "error": "域名解析失败，请检查 API URL"}
        return {"ok": False, "error": f"无法连接: {msg[:150]}"}
    except Exception as e:
        return {"ok": False, "error": f"请求异常: {str(e)[:150]}"}

    # ── 合并结果 ──
    # 如果 open_api 没有获取到域名，至少用 detected_domain
    if not all_domains and detected_domain:
        all_domains = [detected_domain]
    elif detected_domain and detected_domain not in all_domains:
        all_domains.insert(0, detected_domain)

    result = {
        "ok": True,
        "message": f"连接成功，共 {len(all_domains)} 个可用域名",
        "detected_domains": all_domains,
    }
    if worker_version:
        result["version"] = worker_version
    if warning:
        result["warning"] = warning
    return result


@router.post("/applemail/import")
def import_applemail_pool(body: AppleMailImportRequest):
    from core.applemail_pool import load_applemail_pool_snapshot, save_applemail_pool_json

    pool_dir = str(body.pool_dir or config_store.get("applemail_pool_dir", "mail")).strip() or "mail"
    result = save_applemail_pool_json(
        body.content,
        pool_dir=pool_dir,
        filename=body.filename,
    )

    if body.bind_to_config:
        config_store.set_many(
            {
                "applemail_pool_dir": pool_dir,
                "applemail_pool_file": result["filename"],
            }
        )

    snapshot = load_applemail_pool_snapshot(
        pool_file=result["filename"],
        pool_dir=pool_dir,
    )

    return {
        **result,
        "pool_dir": pool_dir,
        "bound_to_config": body.bind_to_config,
        "items": snapshot["items"],
        "truncated": snapshot["truncated"],
    }


@router.get("/cfworker/domains")
def get_cfworker_domains():
    """返回 CF Worker 的可用域名列表（优先从 Worker 实时获取，兜底读全局配置）"""
    import json
    import requests as _requests

    api_url = config_store.get("cfworker_api_url", "").strip().rstrip("/")
    configured = bool(api_url)

    # 优先从 Worker 实时获取
    live_domains: list[str] = []
    if api_url:
        try:
            resp = _requests.get(f"{api_url}/open_api/settings", timeout=10)
            if resp.status_code == 200:
                data = resp.json() if resp.content else {}
                raw = data.get("domains") or data.get("defaultDomains") or []
                if isinstance(raw, list):
                    live_domains = [str(d).strip() for d in raw if str(d).strip()]
        except Exception:
            pass

    if live_domains:
        return {"configured": configured, "api_url": api_url, "domains": live_domains, "source": "live"}

    # 兜底：从全局配置读取
    raw = config_store.get("cfworker_enabled_domains", "")
    domains = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                domains = [str(d).strip() for d in parsed if str(d).strip()]
        except (json.JSONDecodeError, TypeError):
            domains = [d.strip() for d in raw.split(",") if d.strip()]

    return {"configured": configured, "api_url": api_url, "domains": domains, "source": "config"}


@router.get("/cfworker/subdomains")
def get_cfworker_subdomains():
    """返回 CF Worker 二级域名配额占用情况。"""
    with Session(engine) as session:
        rows = session.exec(
            select(CFWorkerSubdomainModel).order_by(
                CFWorkerSubdomainModel.root_domain,
                CFWorkerSubdomainModel.id,
            )
        ).all()

    items = []
    roots: dict[str, dict] = {}
    total_used = 0
    total_inflight = 0
    total_capacity = 0

    for row in rows:
        capacity = max(int(row.max_accounts or 0), 1)
        used = int(row.used_count or 0)
        inflight = int(row.inflight_count or 0)
        available = max(capacity - used - inflight, 0)

        item = {
            "id": row.id,
            "root_domain": row.root_domain,
            "subdomain_label": row.subdomain_label,
            "full_domain": row.full_domain,
            "max_accounts": capacity,
            "used_count": used,
            "inflight_count": inflight,
            "available_count": available,
            "enabled": bool(row.enabled),
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        }
        items.append(item)

        root = roots.setdefault(
            row.root_domain,
            {
                "root_domain": row.root_domain,
                "subdomain_count": 0,
                "max_accounts": 0,
                "used_count": 0,
                "inflight_count": 0,
                "available_count": 0,
            },
        )
        root["subdomain_count"] += 1
        root["max_accounts"] += capacity
        root["used_count"] += used
        root["inflight_count"] += inflight
        root["available_count"] += available

        total_used += used
        total_inflight += inflight
        total_capacity += capacity

    return {
        "items": items,
        "roots": list(roots.values()),
        "summary": {
            "subdomain_count": len(items),
            "root_domain_count": len(roots),
            "max_accounts": total_capacity,
            "used_count": total_used,
            "inflight_count": total_inflight,
            "available_count": max(total_capacity - total_used - total_inflight, 0),
        },
    }


@router.patch("/cfworker/subdomains/{subdomain_id}")
def update_cfworker_subdomain(subdomain_id: int, body: CFWorkerSubdomainUpdateRequest):
    with Session(engine) as session:
        row = session.get(CFWorkerSubdomainModel, subdomain_id)
        if not row:
            return {"ok": False, "error": "子域名不存在"}
        row.enabled = bool(body.enabled)
        session.add(row)
        session.commit()
        session.refresh(row)
        return {
            "ok": True,
            "item": {
                "id": row.id,
                "root_domain": row.root_domain,
                "subdomain_label": row.subdomain_label,
                "full_domain": row.full_domain,
                "enabled": bool(row.enabled),
                "max_accounts": int(row.max_accounts or 0),
                "used_count": int(row.used_count or 0),
                "inflight_count": int(row.inflight_count or 0),
            },
        }


@router.get("/kiro-manager/ping")
def ping_kiro_manager(url: str = "", key: str = ""):
    """检查 Kiro Manager API 是否可达"""
    import requests as _requests

    api_url = str(url or config_store.get("kiro_manager_api_url", "")).strip().rstrip("/")
    api_key = str(key or config_store.get("kiro_manager_api_key", "")).strip()
    if not api_url:
        return {"ok": False, "error": "未配置 Kiro Manager API 地址"}
    if not api_key:
        return {"ok": False, "error": "未配置 Kiro Manager API Key"}
    try:
        r = _requests.get(
            f"{api_url}/api/admin/credentials",
            headers={"x-api-key": api_key},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json() if r.content else []
            count = len(data) if isinstance(data, list) else 0
            return {"ok": True, "message": f"连接成功，当前 {count} 个凭据", "count": count}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except _requests.exceptions.ConnectionError:
        return {"ok": False, "error": "无法连接，请检查地址"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:150]}


@router.get("/applemail/pool")
def get_applemail_pool_snapshot(
    pool_dir: str = "",
    pool_file: str = "",
):

    from core.applemail_pool import load_applemail_pool_snapshot

    resolved_pool_dir = str(pool_dir or config_store.get("applemail_pool_dir", "mail")).strip() or "mail"
    resolved_pool_file = str(pool_file or config_store.get("applemail_pool_file", "")).strip()
    try:
        snapshot = load_applemail_pool_snapshot(
            pool_file=resolved_pool_file,
            pool_dir=resolved_pool_dir,
        )
    except Exception:
        snapshot = {
            "filename": resolved_pool_file,
            "path": "",
            "count": 0,
            "items": [],
            "truncated": False,
        }
    return {
        **snapshot,
        "pool_dir": resolved_pool_dir,
    }
