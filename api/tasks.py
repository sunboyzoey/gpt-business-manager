from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select, col
from typing import Any, Literal, Optional
from copy import deepcopy
from core.db import TaskLog, engine
from core.task_runtime import (
    AttemptOutcome,
    AttemptResult,
    RegisterTaskStore,
    SkipCurrentAttemptRequested,
    StopTaskRequested,
)
import os, re, time, json, asyncio, threading, logging, zipfile
import shutil

router = APIRouter(prefix="/tasks", tags=["tasks"])
logger = logging.getLogger(__name__)

MAX_FINISHED_TASKS = 200
CLEANUP_THRESHOLD = 250
REGISTER_TASK_MAX_CONCURRENCY = 10
OAUTH_BUNDLE_MAX_CONCURRENCY = 20
TASK_ARTIFACT_ROOT = os.path.abspath(os.path.join("data", "task_artifacts"))
OAUTH_BUNDLE_SOURCE = "oauth_bundle"
OAUTH_BUNDLE_MANIFEST_NAME = "oauth_bundle_task.json"
_task_store = RegisterTaskStore(
    max_finished_tasks=MAX_FINISHED_TASKS,
    cleanup_threshold=CLEANUP_THRESHOLD,
)
_oauth_bundle_history_loaded = False
_oauth_bundle_history_lock = threading.Lock()


class RegisterTaskRequest(BaseModel):
    platform: str
    email: Optional[str] = None
    password: Optional[str] = None
    count: int = 1
    concurrency: int = 1
    register_delay_seconds: float = 0
    proxy: Optional[str] = None
    proxy_node: Optional[str] = None
    proxy_key: Optional[str] = Field(default=None, max_length=512)
    executor_type: Literal["protocol", "headless", "headed"] = "headless"
    captcha_solver: str = "yescaptcha"
    extra: dict = Field(default_factory=dict)


class TaskLogBatchDeleteRequest(BaseModel):
    ids: list[int]


class OAuthBundleTaskBatchDeleteRequest(BaseModel):
    ids: list[str]


class OAuthBundleTaskCreateRequest(BaseModel):
    task_name: str = ""
    platform: str = "chatgpt"
    auth_file_format: str = "cpa"
    count: int = Field(default=1, ge=1)
    concurrency: int = Field(default=1, ge=1)
    register_delay_seconds: float = Field(default=0, ge=0)
    executor_type: str = "protocol"
    captcha_solver: str = "yescaptcha"
    mail_provider: str = "cfworker"
    rule_domains: list[str] = Field(default_factory=list)
    rule_strategy: str = "counter"
    rule_prefix: str = "acc"
    rule_max_per_sub: int = Field(default=100, ge=1)
    business_domains: list[str] = Field(default_factory=list)
    business_domain_max_accounts: int = Field(default=0, ge=0)


def _ensure_task_exists(task_id: str) -> None:
    if not _task_store.exists(task_id):
        raise HTTPException(404, "任务不存在")


def _ensure_task_mutable(task_id: str) -> None:
    _ensure_task_exists(task_id)
    snapshot = _task_store.snapshot(task_id)
    if snapshot.get("status") in {"done", "failed", "stopped"}:
        raise HTTPException(409, "任务已结束，无法再执行控制操作")


def _prepare_register_request(req: RegisterTaskRequest) -> RegisterTaskRequest:
    from core.config_store import config_store

    req_data = req.model_dump()
    req_data["extra"] = deepcopy(req_data.get("extra") or {})
    prepared = RegisterTaskRequest(**req_data)

    if prepared.platform == "devin":
        prepared.executor_type = "protocol"

    # This standalone workspace registers only its own Gmail children. Reject
    # alternate providers before any worker or mailbox allocation can start.
    mail_provider = prepared.extra.get("mail_provider") or "gmail"
    if mail_provider != "gmail" or prepared.platform != "chatgpt":
        raise HTTPException(400, "此独立项目仅支持 Gmail 子号注册 GPT")
    if mail_provider == "gmail":
        if prepared.platform != "chatgpt":
            raise HTTPException(400, "Gmail 子号目前仅支持 GPT 注册")
        if prepared.email:
            raise HTTPException(400, "Gmail 注册请从子号列表选择邮箱")
        if prepared.extra.get("business_domain") or prepared.extra.get("business_domains"):
            raise HTTPException(400, "Gmail 子号不能与 BUSINESS 域名注册混用")
        from services.gmail_registration import validate_registration_request
        from services.gmail_store import GmailStoreError
        try:
            validate_registration_request(
                source_id=prepared.extra.get("gmail_source_id"),
                alias_ids=prepared.extra.get("gmail_alias_ids"),
                count=prepared.count,
                include_retries=bool(prepared.extra.get("_gmail_retry")),
            )
        except GmailStoreError as exc:
            raise HTTPException(exc.status_code, exc.message) from None
        prepared.extra["mail_provider"] = "gmail"
    if mail_provider == "luckmail":
        platform = prepared.platform
        if platform in ("tavily", "openblocklabs"):
            raise HTTPException(400, f"LuckMail 渠道暂时不支持 {platform} 项目注册")

        mapping = {
            "trae": "trae",
            "cursor": "cursor",
            "grok": "grok",
            "kiro": "kiro",
            "chatgpt": "openai",
        }
        prepared.extra["luckmail_project_code"] = mapping.get(platform, platform)

    # Resolve only a managed, successfully checked selection before enqueue.
    # Never silently inherit a raw URL, an unchecked pool or direct networking.
    if prepared.proxy or prepared.proxy_node:
        raise HTTPException(400, "注册请从代理管理选择已检测可用的代理")
    from services.registration_proxy import resolve_registration_proxy
    try:
        selection = resolve_registration_proxy(prepared.proxy_key or "")
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    prepared.proxy_key = selection["key"]
    prepared.extra["registration_proxy_key"] = selection["key"]
    return prepared


def _create_task_record(
    task_id: str, req: RegisterTaskRequest, source: str, meta: dict | None = None
):
    _task_store.create(
        task_id,
        platform=req.platform,
        total=req.count,
        source=source,
        meta=meta,
    )


def enqueue_register_task(
    req: RegisterTaskRequest,
    *,
    background_tasks: BackgroundTasks | None = None,
    source: str = "manual",
    meta: dict | None = None,
) -> str:
    prepared = _prepare_register_request(req)
    task_id = f"task_{int(time.time() * 1000)}"
    if prepared.extra.get("mail_provider") == "gmail":
        task_id += "_" + os.urandom(4).hex()
    _create_task_record(task_id, prepared, source, meta)
    if background_tasks is None:
        thread = threading.Thread(
            target=_run_register, args=(task_id, prepared), daemon=True
        )
        thread.start()
    else:
        background_tasks.add_task(_run_register, task_id, prepared)
    return task_id


def has_active_register_task(
    *,
    platform: str | None = None,
    source: str | None = None,
    meta: dict | None = None,
) -> bool:
    return _task_store.has_active(platform=platform, source=source, meta=meta)


def _log(task_id: str, msg: str):
    """向任务追加一条日志"""
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    _task_store.append_log(task_id, entry)
    print(entry)


def _parse_bool_text(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _merge_register_runtime_extra(
    persisted: dict[str, Any],
    request_extra: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge form overrides while preserving one intentional empty value.

    Most empty form fields mean "inherit the saved setting".  The CF Worker
    domain override is different: empty explicitly means randomly choose from
    enabled root domains, so it must be able to clear a saved fixed suffix.
    """
    request_values = dict(request_extra or {})
    merged = dict(persisted or {})
    merged.update(
        {
            key: value
            for key, value in request_values.items()
            if value is not None and value != ""
        }
    )
    if "cfworker_domain_override" in request_values:
        merged["cfworker_domain_override"] = str(
            request_values.get("cfworker_domain_override") or ""
        ).strip()
    return merged


def _is_oauth_bundle_task(req: RegisterTaskRequest) -> bool:
    if req.platform != "chatgpt":
        return False
    extra = req.extra or {}
    mode = str(extra.get("task_mode") or "").strip().lower()
    if mode in {"oauth_bundle", "oauth_zip", "oauth"}:
        return True
    return _parse_bool_text(
        extra.get("oauth_bundle_task") or extra.get("_oauth_bundle_task"),
        default=False,
    )


def _safe_artifact_name(value: str, fallback: str = "item") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", str(value or "").strip())
    safe = safe.strip("._-")
    return safe or fallback


def _normalize_task_name(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) > 80:
        text = text[:80].strip()
    return text


def _task_artifact_dir(task_id: str) -> str:
    safe_task_id = _safe_artifact_name(task_id, "task")
    return os.path.join(TASK_ARTIFACT_ROOT, safe_task_id)


def _oauth_bundle_output_dir(task_id: str) -> str:
    return os.path.join(_task_artifact_dir(task_id), "oauth_files")


def _normalize_business_hostname_list(raw: Any) -> list[str]:
    try:
        from services.device_manager import normalize_business_domain_entries

        entries = normalize_business_domain_entries(raw)
    except Exception:
        entries = []
    hosts: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        host = str(entry.get("hostname") or "").strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _as_non_negative_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _select_oauth_bundle_business_domain(
    domains: list[str],
    account_index: int,
    max_accounts_per_domain: int,
) -> str:
    if not domains:
        return ""
    max_accounts = _as_non_negative_int(max_accounts_per_domain)
    if max_accounts > 0:
        domain_index = max(0, int(account_index)) // max_accounts
        if domain_index >= len(domains):
            raise RuntimeError("OAuth 文件个数超过 BUSINESS 域名总上限")
        return domains[domain_index]
    return domains[max(0, int(account_index)) % len(domains)]


def _normalize_oauth_bundle_file_format(value: Any) -> str:
    text = str(value or "cpa").strip().lower()
    if text in {"sub", "sub2api"}:
        return "sub2api"
    return "cpa"


def _read_account_extra(account) -> dict:
    if account is None:
        return {}
    get_extra = getattr(account, "get_extra", None)
    if callable(get_extra):
        try:
            extra = get_extra()
            return extra if isinstance(extra, dict) else {}
        except Exception:
            return {}
    extra = getattr(account, "extra", None)
    if isinstance(extra, dict):
        return dict(extra)
    extra_json = getattr(account, "extra_json", "")
    if extra_json:
        try:
            parsed = json.loads(extra_json)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _write_account_extra_patch(account, patch: dict) -> None:
    if not account or not patch:
        return
    account_id = getattr(account, "id", None)
    if not account_id:
        return
    try:
        from core.db import AccountModel

        with Session(engine) as s:
            db_account = s.get(AccountModel, account_id)
            if not db_account:
                return
            extra = db_account.get_extra()
            extra.update(patch)
            db_account.set_extra(extra)
            s.add(db_account)
            s.commit()
    except Exception:
        pass


_BUSINESS_CSV_MARKER_KEYS = (
    "business_csv_status",
    "business_csv_role",
    "business_csv_seat_type",
    "business_csv_created_at",
    "business_csv_register_task",
)


def _apply_business_csv_markers_to_account(account, merged_extra: dict) -> None:
    """Propagate BUSINESS CSV markers from a CHATGPT register task.

    Platform-specific register implementations intentionally do not copy every
    task `extra` key into account extras.  BUSINESS CSV needs its own marker
    after using the normal `/tasks/register` path, so copy only the explicit
    marker allowlist.  Gated on `business_csv_register_task` (批次概念已移除).
    """
    if not account or not isinstance(merged_extra, dict):
        return
    if str(merged_extra.get("business_csv_register_task") or "").strip() != "1":
        return
    if not isinstance(getattr(account, "extra", None), dict):
        account.extra = {}
    for key in _BUSINESS_CSV_MARKER_KEYS:
        if key in merged_extra and merged_extra.get(key) not in (None, ""):
            account.extra[key] = merged_extra[key]
    account.extra.setdefault("business_csv_status", "registered")


def _unique_file_path(directory: str, filename: str) -> str:
    os.makedirs(directory, exist_ok=True)
    base, ext = os.path.splitext(filename)
    if not ext:
        ext = ".json"
    path = os.path.join(directory, f"{base}{ext}")
    index = 2
    while os.path.exists(path):
        path = os.path.join(directory, f"{base}_{index}{ext}")
        index += 1
    return path


def _ensure_oauth_file_for_account(
    task_id: str,
    account,
    saved_account,
    output_dir: str,
    file_format: str = "cpa",
    sequence_index: int | None = None,
) -> str:
    """生成授权文件 (CPA / SUB2)。

    要求账号必须含 refresh_token (与注册界面下载的文件格式一致)。
    缺 RT 视为本账号注册失败 → 返回空字符串 → 调用方计入 AttemptResult.failed。

    输出格式严格对齐 RegisterTaskPage 下载文件:
      - CPA:  {type: "codex", access_token, refresh_token}
      - SUB2: {exported_at, proxies: [...], accounts: [<single account>]}
        有账号既有代理时写入 proxy + proxy_key；没有时 proxies 为空。
    """
    account_extra = _read_account_extra(account)
    saved_extra = _read_account_extra(saved_account)
    combined_extra = {**account_extra, **saved_extra}
    normalized_format = _normalize_oauth_bundle_file_format(file_format)

    access_token = (
        str(combined_extra.get("access_token") or "").strip()
        or str(getattr(saved_account, "token", "") or "").strip()
        or str(getattr(account, "token", "") or "").strip()
    )
    refresh_token = str(combined_extra.get("refresh_token") or "").strip()
    if not access_token:
        _log(task_id, "  [OAuth] 跳过授权文件生成: 当前账号缺少 access_token (注册失败)")
        return ""
    if not refresh_token:
        _log(task_id, "  [OAuth] 跳过授权文件生成: 当前账号缺少 refresh_token (RT 获取失败,视为注册失败)")
        return ""

    # 已有缓存的 oauth_file 必须同时含 RT 才能复用 (避免使用旧 AT-only 文件)
    existing_file = str(combined_extra.get("oauth_file") or "").strip()
    if existing_file and os.path.isfile(existing_file):
        try:
            with open(existing_file, "r", encoding="utf-8") as fh:
                cached = json.load(fh)
            cached_has_rt = False
            if isinstance(cached, dict):
                if str(cached.get("refresh_token") or "").strip():
                    cached_has_rt = True
                elif isinstance(cached.get("accounts"), list) and cached["accounts"]:
                    creds = (cached["accounts"][0] or {}).get("credentials") or {}
                    cached_has_rt = bool(str(creds.get("refresh_token") or "").strip())
            if cached_has_rt:
                # 命中的文件已是 RT 格式,且格式匹配本次请求 → 直接复用
                if normalized_format == "cpa" and "accounts" not in cached:
                    return os.path.abspath(existing_file)
                if normalized_format == "sub2api" and isinstance(cached, dict) and "accounts" in cached:
                    from platforms.chatgpt.sub2api_upload import is_current_sub2api_bundle

                    if is_current_sub2api_bundle(cached):
                        return os.path.abspath(existing_file)
        except Exception:
            pass  # 缓存文件损坏,重新生成

    email = (
        str(getattr(saved_account, "email", "") or "").strip()
        or str(getattr(account, "email", "") or "").strip()
    )
    try:
        from types import SimpleNamespace

        token_account = SimpleNamespace(
            email=email,
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=str(combined_extra.get("id_token") or "").strip(),
            client_id=str(combined_extra.get("client_id") or "").strip(),
            extra=dict(combined_extra),
        )
        # token_data 仅供 sub2api builder 抽 id_token/email; CPA 直接构造最小输出
        if normalized_format == "sub2api":
            from platforms.chatgpt.sub2api_upload import (
                build_sub2api_bundle_from_token_data,
            )

            inner_token_data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": token_account.id_token,
                "email": email,
                "client_id": token_account.client_id,
            }
            output_data = build_sub2api_bundle_from_token_data(
                inner_token_data,
                account=token_account,
            )
            filename_prefix = "sub2api"
        else:
            # CPA 最小化: 仅 type/access_token/refresh_token
            output_data = {
                "type": "codex",
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
            filename_prefix = "oauth"

        safe_email = _safe_artifact_name(email, "oauth_account")
        file_path = _unique_file_path(output_dir, f"{filename_prefix}_{safe_email}.json")
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        abs_path = os.path.abspath(file_path)
        if normalized_format == "cpa" and isinstance(getattr(account, "extra", None), dict):
            account.extra["oauth_file"] = abs_path
        if normalized_format == "cpa":
            _write_account_extra_patch(saved_account, {"oauth_file": abs_path})
        return abs_path
    except Exception as exc:
        _log(task_id, f"  [OAuth] 授权文件生成失败: {exc}")
        return ""


def _build_oauth_zip(task_id: str, oauth_files: list[str]) -> tuple[str, int]:
    artifact_dir = _task_artifact_dir(task_id)
    os.makedirs(artifact_dir, exist_ok=True)
    zip_path = os.path.join(artifact_dir, "oauth_files.zip")
    seen_names: set[str] = set()
    written = 0

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for raw_path in oauth_files:
            file_path = os.path.abspath(str(raw_path or "").strip())
            if not file_path or not os.path.isfile(file_path):
                continue
            base = os.path.basename(file_path) or f"oauth_{written + 1}.json"
            name, ext = os.path.splitext(base)
            ext = ext or ".json"
            arcname = f"{name}{ext}"
            suffix = 2
            while arcname in seen_names:
                arcname = f"{name}_{suffix}{ext}"
                suffix += 1
            seen_names.add(arcname)
            zf.write(file_path, arcname)
            written += 1

    if written <= 0:
        try:
            os.remove(zip_path)
        except OSError:
            pass
        raise RuntimeError("没有可打包的 OAuth 授权文件")

    return os.path.abspath(zip_path), written


def _extract_access_token_from_oauth_payload(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""

    for key in ("access_token", "accessToken"):
        token = str(payload.get(key) or "").strip()
        if token:
            return token

    credentials = payload.get("credentials")
    if isinstance(credentials, dict):
        for key in ("access_token", "accessToken"):
            token = str(credentials.get(key) or "").strip()
            if token:
                return token

    for value in payload.values():
        if isinstance(value, dict):
            token = _extract_access_token_from_oauth_payload(value)
            if token:
                return token
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    token = _extract_access_token_from_oauth_payload(item)
                    if token:
                        return token
    return ""


def _build_oauth_access_tokens_txt(task_id: str, zip_path: str) -> tuple[str, int]:
    abs_zip_path = os.path.abspath(str(zip_path or "").strip())
    if not abs_zip_path or not os.path.isfile(abs_zip_path):
        raise RuntimeError("OAuth 压缩包文件不存在")

    tokens: list[str] = []
    with zipfile.ZipFile(abs_zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".json"):
                continue
            try:
                with zf.open(info) as fh:
                    payload = json.loads(fh.read().decode("utf-8"))
            except Exception:
                continue
            token = _extract_access_token_from_oauth_payload(payload)
            if token:
                tokens.append(token)

    if not tokens:
        raise RuntimeError("没有从授权文件中解析到 AccessToken")

    artifact_dir = _task_artifact_dir(task_id)
    os.makedirs(artifact_dir, exist_ok=True)
    txt_path = os.path.join(artifact_dir, "access_tokens.txt")
    tmp_path = f"{txt_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(tokens))
        fh.write("\n")
    os.replace(tmp_path, txt_path)
    return os.path.abspath(txt_path), len(tokens)


def _oauth_bundle_manifest_path(task_id: str) -> str:
    return os.path.join(_task_artifact_dir(task_id), OAUTH_BUNDLE_MANIFEST_NAME)


def _remove_oauth_bundle_artifacts(task_id: str) -> bool:
    task_dir = os.path.abspath(_task_artifact_dir(task_id))
    artifact_root = os.path.abspath(TASK_ARTIFACT_ROOT)
    try:
        common = os.path.commonpath([artifact_root, task_dir])
    except ValueError:
        return False
    if common != artifact_root or task_dir == artifact_root:
        return False
    if not os.path.exists(task_dir):
        return False
    shutil.rmtree(task_dir)
    return True


def _delete_oauth_bundle_task(task_id: str) -> dict[str, Any]:
    normalized_id = str(task_id or "").strip()
    if not normalized_id:
        return {"id": task_id, "deleted": False, "reason": "empty_id"}
    if not _task_store.exists(normalized_id):
        return {"id": normalized_id, "deleted": False, "reason": "not_found"}

    snapshot = _task_store.snapshot(normalized_id)
    if not (
        snapshot.get("source") == OAUTH_BUNDLE_SOURCE
        or (snapshot.get("meta") or {}).get("task_mode") == "oauth_bundle"
    ):
        return {"id": normalized_id, "deleted": False, "reason": "not_oauth_bundle"}
    if snapshot.get("status") in {"pending", "running"}:
        return {"id": normalized_id, "deleted": False, "reason": "active"}

    try:
        removed_artifacts = _remove_oauth_bundle_artifacts(normalized_id)
    except OSError as exc:
        return {
            "id": normalized_id,
            "deleted": False,
            "reason": "artifact_delete_failed",
            "error": str(exc),
        }
    _task_store.delete(normalized_id)
    return {
        "id": normalized_id,
        "deleted": True,
        "removed_artifacts": removed_artifacts,
    }


def _count_oauth_zip_files(zip_path: str) -> int:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            return sum(1 for info in zf.infolist() if not info.is_dir())
    except Exception:
        return 0


def _build_oauth_bundle_history_snapshot_from_artifact(
    task_id: str,
    zip_path: str,
) -> dict[str, Any] | None:
    abs_zip_path = os.path.abspath(zip_path)
    if not os.path.isfile(abs_zip_path):
        return None
    file_count = _count_oauth_zip_files(abs_zip_path)
    if file_count <= 0:
        return None
    filename = os.path.basename(abs_zip_path) or "oauth_files.zip"
    auth_file_format = "sub2api" if "sub2api" in filename.lower() else "cpa"
    artifact = {
        "type": "oauth_zip",
        "format": auth_file_format,
        "path": abs_zip_path,
        "count": file_count,
        "target_count": file_count,
        "filename": filename,
        "download_url": f"/tasks/{task_id}/artifact/oauth-zip",
    }
    return {
        "id": task_id,
        "status": "done",
        "platform": "chatgpt",
        "source": OAUTH_BUNDLE_SOURCE,
        "total": file_count,
        "progress": f"OAuth文件 {file_count}/{file_count} · 历史恢复",
        "success": file_count,
        "skipped": 0,
        "errors": [],
        "meta": {
            "task_mode": "oauth_bundle",
            "auth_file_format": auth_file_format,
            "target_oauth_file_count": file_count,
            "artifact": artifact,
            "oauth_bundle": {
                "status": "ready",
                "output_dir": os.path.join(os.path.dirname(abs_zip_path), "oauth_files"),
                "zip_path": abs_zip_path,
                "target_count": file_count,
                "count": file_count,
            },
            "restored_from_artifact": True,
        },
        "logs": ["[历史] 服务重启后从本地授权文件压缩包恢复任务索引"],
    }


def _persist_oauth_bundle_history(task_id: str) -> None:
    try:
        snapshot = _task_store.snapshot(task_id)
    except Exception:
        return
    meta = snapshot.get("meta") if isinstance(snapshot, dict) else {}
    artifact = (meta or {}).get("artifact") if isinstance(meta, dict) else {}
    if not isinstance(artifact, dict) or artifact.get("type") != "oauth_zip":
        return
    manifest = {
        "version": 1,
        "id": task_id,
        "status": snapshot.get("status", "done"),
        "platform": snapshot.get("platform", "chatgpt"),
        "source": snapshot.get("source", OAUTH_BUNDLE_SOURCE),
        "total": snapshot.get("total", 0),
        "progress": snapshot.get("progress", ""),
        "success": snapshot.get("success", 0),
        "skipped": snapshot.get("skipped", 0),
        "errors": snapshot.get("errors", []),
        "meta": meta if isinstance(meta, dict) else {},
        "updated_at": time.time(),
    }
    path = _oauth_bundle_manifest_path(task_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp_path, path)
    except Exception as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        logger.warning("OAuth 授权文件任务历史持久化失败: %s", exc)


def _load_oauth_bundle_history_manifest(task_id: str) -> dict[str, Any] | None:
    path = _oauth_bundle_manifest_path(task_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("id", task_id)
    data.setdefault("platform", "chatgpt")
    data.setdefault("source", OAUTH_BUNDLE_SOURCE)
    data.setdefault("status", "done")
    data.setdefault("success", 0)
    data.setdefault("skipped", 0)
    data.setdefault("errors", [])
    data.setdefault("meta", {})
    meta = data.get("meta")
    if isinstance(meta, dict):
        artifact = meta.get("artifact")
        if isinstance(artifact, dict):
            artifact.setdefault(
                "download_url",
                f"/tasks/{task_id}/artifact/oauth-zip",
            )
    return data


def _restore_oauth_bundle_history_record(snapshot: dict[str, Any]) -> bool:
    task_id = str(snapshot.get("id") or "").strip()
    if not task_id or _task_store.exists(task_id):
        return False
    total = max(0, int(snapshot.get("total") or snapshot.get("success") or 0))
    if total <= 0:
        total = 1
    status = str(snapshot.get("status") or "done").strip() or "done"
    if status in {"pending", "running"}:
        status = "stopped"
    success = max(0, int(snapshot.get("success") or 0))
    skipped = max(0, int(snapshot.get("skipped") or 0))
    errors = snapshot.get("errors") if isinstance(snapshot.get("errors"), list) else []
    meta = snapshot.get("meta") if isinstance(snapshot.get("meta"), dict) else {}
    _task_store.create(
        task_id,
        platform=str(snapshot.get("platform") or "chatgpt"),
        total=total,
        source=str(snapshot.get("source") or OAUTH_BUNDLE_SOURCE),
        meta=meta,
    )
    progress = str(snapshot.get("progress") or "").strip()
    if progress:
        _task_store.set_progress(task_id, progress)
    for line in snapshot.get("logs") or []:
        if isinstance(line, str) and line.strip():
            _task_store.append_log(task_id, line)
    _task_store.finish(
        task_id,
        status=status,
        success=success,
        skipped=skipped,
        errors=[str(item) for item in errors],
    )
    return True


def _restore_oauth_bundle_history_from_artifacts() -> int:
    if not os.path.isdir(TASK_ARTIFACT_ROOT):
        return 0
    restored = 0
    for name in sorted(os.listdir(TASK_ARTIFACT_ROOT)):
        if not name.startswith("task_"):
            continue
        task_id = _safe_artifact_name(name, "")
        if not task_id or _task_store.exists(task_id):
            continue
        task_dir = os.path.join(TASK_ARTIFACT_ROOT, name)
        if not os.path.isdir(task_dir):
            continue
        snapshot = _load_oauth_bundle_history_manifest(task_id)
        if snapshot is None:
            snapshot = _build_oauth_bundle_history_snapshot_from_artifact(
                task_id,
                os.path.join(task_dir, "oauth_files.zip"),
            )
        if snapshot and _restore_oauth_bundle_history_record(snapshot):
            restored += 1
    return restored


def _ensure_oauth_bundle_history_loaded() -> None:
    global _oauth_bundle_history_loaded
    if _oauth_bundle_history_loaded:
        return
    with _oauth_bundle_history_lock:
        if _oauth_bundle_history_loaded:
            return
        restored = _restore_oauth_bundle_history_from_artifacts()
        if restored:
            logger.info("已恢复授权文件任务历史: %s 条", restored)
        _oauth_bundle_history_loaded = True


def _build_oauth_bundle_request(
    req: OAuthBundleTaskCreateRequest,
) -> tuple[RegisterTaskRequest, dict[str, Any]]:
    from core.config_store import config_store

    platform = str(req.platform or "chatgpt").strip().lower() or "chatgpt"
    if platform != "chatgpt":
        raise HTTPException(400, "授权文件任务仅支持 ChatGPT")

    auth_file_format = _normalize_oauth_bundle_file_format(req.auth_file_format)
    task_name = _normalize_task_name(req.task_name)
    count = max(1, int(req.count or 1))
    concurrency = min(
        max(1, int(req.concurrency or 1)),
        OAUTH_BUNDLE_MAX_CONCURRENCY,
    )
    register_delay_seconds = max(float(req.register_delay_seconds or 0), 0)
    executor_type = str(req.executor_type or "protocol").strip() or "protocol"
    captcha_solver = str(req.captcha_solver or "yescaptcha").strip() or "yescaptcha"
    mail_provider = str(req.mail_provider or "cfworker").strip() or "cfworker"
    rule_domains = _normalize_business_hostname_list(req.rule_domains)
    rule_strategy = str(req.rule_strategy or "counter").strip() or "counter"
    rule_prefix = str(req.rule_prefix or "acc").strip() or "acc"
    rule_max_per_sub = max(1, int(req.rule_max_per_sub or 100))
    business_domain_max_accounts = _as_non_negative_int(
        req.business_domain_max_accounts
    )
    explicit_business_domains = _normalize_business_hostname_list(
        req.business_domains
    )

    extra = config_store.get_all().copy()

    business_domains = explicit_business_domains
    if business_domains and business_domain_max_accounts > 0:
        business_domain_capacity = len(business_domains) * business_domain_max_accounts
        if count > business_domain_capacity:
            raise HTTPException(
                400,
                f"OAuth 文件个数超过 BUSINESS 域名总上限: {business_domain_capacity}",
            )
    if business_domains:
        extra["mail_provider"] = "cfworker"
        extra["oauth_bundle_business_domains"] = business_domains
        extra["oauth_bundle_business_domain_max_accounts"] = str(
            business_domain_max_accounts
        )
    else:
        extra["mail_provider"] = mail_provider
        if rule_domains:
            extra["cfworker_domain_override"] = rule_domains[0]
        if rule_strategy:
            extra["cfworker_subdomain_strategy"] = rule_strategy
        if rule_prefix:
            extra["cfworker_subdomain_prefix"] = rule_prefix
        if rule_max_per_sub:
            extra["cfworker_subdomain_max_accounts"] = str(rule_max_per_sub)

    for key in (
        "_sync_device_business_domains",
        "_sync_device_id",
        "_sync_device_type",
        "_sync_batch_size",
        "sub2api_group_ids",
        "cpa_api_url",
        "cpa_api_key",
    ):
        extra.pop(key, None)

    extra.update(
        {
            "task_mode": "oauth_bundle",
            "oauth_bundle_task": "1",
            "oauth_bundle_file_format": auth_file_format,
            "oauth_bundle_target_count": str(count),
            # 强制走 "有 RT" 一站式链路: 注册 → 拿 RT → 切 Codex 席位。
            # 任一阶段失败时 _register_business_oauth 抛错,本账号计为注册失败。
            "chatgpt_registration_mode": "refresh_token",
            "chatgpt_has_refresh_token_solution": "1",
            "business_switch_to_codex": "1",
        }
    )

    task_req = RegisterTaskRequest(
        platform=platform,
        count=count,
        concurrency=concurrency,
        register_delay_seconds=register_delay_seconds,
        executor_type=executor_type,
        captcha_solver=captcha_solver,
        extra=extra,
    )
    meta = {
        "task_mode": "oauth_bundle",
        "task_name": task_name,
        "business_domains": business_domains,
        "business_domain_max_accounts": business_domain_max_accounts,
        "auth_file_format": auth_file_format,
        "target_oauth_file_count": count,
        "executor_type": executor_type,
        "mail_provider": extra.get("mail_provider", mail_provider),
        "concurrency": concurrency,
        "register_delay_seconds": register_delay_seconds,
    }
    return task_req, meta


def _should_auto_use_proxy() -> bool:
    from core.config_store import config_store

    return _parse_bool_text(
        config_store.get("register_auto_use_proxy", "1"),
        default=True,
    )


def _save_task_log(
    platform: str, email: str, status: str, error: str = "", detail: dict = None
):
    """Write a TaskLog record to the database."""
    with Session(engine) as s:
        log = TaskLog(
            platform=platform,
            email=email,
            status=status,
            error=error,
            detail_json=json.dumps(detail or {}, ensure_ascii=False),
        )
        s.add(log)
        s.commit()


def _auto_upload_integrations(task_id: str, account):
    """注册成功后自动导入外部系统。"""
    try:
        from services.external_sync import sync_account

        for result in sync_account(account):
            name = result.get("name", "Auto Upload")
            ok = bool(result.get("ok"))
            msg = result.get("msg", "")
            _log(task_id, f"  [{name}] {'[OK] ' + msg if ok else '[FAIL] ' + msg}")
            if ok and "kiro" in name.lower():
                _mark_kiro_manager_synced(account)
            if ok and "设备#" in name:
                _delete_local_account(task_id, account)
    except Exception as e:
        _log(task_id, f"  [Auto Upload] 自动导入异常: {e}")


def _delete_local_account(task_id: str, account) -> bool:
    try:
        from core.db import engine, AccountModel
        account_id = getattr(account, "id", None)
        email = getattr(account, "email", "")
        platform = getattr(account, "platform", "")
        if not email and not account_id:
            return False
        with Session(engine) as s:
            acc = None
            try:
                if account_id:
                    acc = s.get(AccountModel, int(account_id))
            except (TypeError, ValueError):
                acc = None
            if not acc and email:
                query = select(AccountModel).where(AccountModel.email == email)
                if platform:
                    query = query.where(AccountModel.platform == platform)
                acc = s.exec(query).first()
            if acc:
                s.delete(acc)
                s.commit()
                _log(task_id, f"  [清理] 已删除本地账号: {email}")
                return True
            _log(task_id, f"  [清理] 本地账号不存在,跳过删除: {email or account_id}")
            return False
    except Exception as e:
        _log(task_id, f"  [清理] 删除本地账号失败: {e}")
        return False


def _mark_kiro_manager_synced(account):
    try:
        from core.db import engine, AccountModel
        with Session(engine) as s:
            db_acc = s.exec(
                select(AccountModel)
                .where(AccountModel.platform == "kiro")
                .where(AccountModel.email == account.email)
            ).first()
            if db_acc:
                extra = json.loads(db_acc.extra_json or "{}")
                extra["kiro_manager_synced"] = True
                db_acc.extra_json = json.dumps(extra, ensure_ascii=False)
                s.add(db_acc)
                s.commit()
    except Exception:
        pass


_PLATFORM_STATUS_FIELD_MAP = {
    "chatgpt": "gpt_register_status",
    "grok": "grok_register_status",
    "trae": "trae_register_status",
    "kiro": "kiro_register_status",
    "openblocklabs": "obl_register_status",
    "cursor": "cursor_register_status",
    "adobe": "adobe_register_status",
}


def _update_outlook_register_status(email: str, platform: str, status: str):
    """注册成功后回写 Outlook 邮箱的对应平台注册状态。"""
    field = _PLATFORM_STATUS_FIELD_MAP.get(platform)
    if not field:
        return
    try:
        from core.db import engine, OutlookAccountModel
        from datetime import datetime, timezone

        with Session(engine) as session:
            # 查找该邮箱（可能已被 _pop_account 删除，也可能还在池里）
            existing = session.exec(
                select(OutlookAccountModel).where(OutlookAccountModel.email == email)
            ).first()
            if existing:
                setattr(existing, field, status)
                existing.updated_at = datetime.now(timezone.utc)
                session.add(existing)
                session.commit()
    except Exception:
        pass


def _update_icloud_hme_register_status(email: str, platform: str, status: str, account_id: str = ""):
    """注册成功/失败时回写 iCloud HME alias 的对应平台状态。"""
    try:
        from services.icloud_hme_tracker import mark_register_status
        mark_register_status(email, platform, status, account_id)
    except Exception:
        pass


def _release_icloud_hme_register(email: str, platform: str):
    """注册失败时把 '进行中' 复位为 '未注册'"""
    try:
        from services.icloud_hme_tracker import release_alias
        release_alias(email, platform)
    except Exception:
        pass


def _return_outlook_if_needed(mailbox, email: str, platform: str = ""):
    """注册失败时归还 Outlook 预留邮箱（最近一个禁用的邮箱）"""
    try:
        from core.db import engine, OutlookAccountModel
        from datetime import datetime, timezone
        field = _PLATFORM_STATUS_FIELD_MAP.get(str(platform or "").strip())

        def _already_registered(acc) -> bool:
            return bool(field and str(getattr(acc, field, "") or "") == "已注册")

        with Session(engine) as session:
            # 优先按邮箱地址精确匹配
            acc = None
            if email:
                acc = session.exec(
                    select(OutlookAccountModel)
                    .where(OutlookAccountModel.email == email)
                    .where(OutlookAccountModel.enabled == False)
                ).first()
                if acc and _already_registered(acc):
                    return
            # 兜底：归还最近被禁用的一个
            if not acc:
                reserved = session.exec(
                    select(OutlookAccountModel)
                    .where(OutlookAccountModel.enabled == False)
                    .order_by(col(OutlookAccountModel.updated_at).desc())
                ).all()
                for item in reserved:
                    if not _already_registered(item):
                        acc = item
                        break
            if acc:
                acc.enabled = True
                acc.updated_at = datetime.now(timezone.utc)
                session.add(acc)
                session.commit()
    except Exception:
        pass


def _run_register(task_id: str, req: RegisterTaskRequest):
    from core.registry import get
    from core.base_platform import RegisterConfig
    from core.db import save_account
    from core.base_mailbox import create_mailbox
    from core.proxy_utils import normalize_proxy_url, redact_proxy_url

    control = _task_store.control_for(task_id)
    _task_store.mark_running(task_id)
    success = 0
    skipped = 0
    errors = []
    start_gate_lock = threading.Lock()
    next_start_time = time.time()
    oauth_bundle_mode = _is_oauth_bundle_task(req)
    # CPA/SUB + BUSINESS + RT 模式: phase 2/3 失败不算 task 失败,持续跑到 target_count 个真上传成功
    business_long_run_mode = str(
        req.extra.get("_business_long_run_mode") or ""
    ).strip() == "1" if req.extra else False
    business_long_run_success_count = 0
    business_long_run_success_emails: set[str] = set()
    business_long_run_lock = threading.Lock()
    # 进程内防同一 ready_for_export 账号被多 worker 同时抢
    business_long_run_inflight_ids: set[int] = set()
    business_long_run_inflight_lock = threading.Lock()
    business_long_run_ready_retry_cooldown_seconds = 120
    oauth_output_dir = _oauth_bundle_output_dir(task_id) if oauth_bundle_mode else ""
    oauth_file_format = _normalize_oauth_bundle_file_format(
        (req.extra or {}).get("oauth_bundle_file_format")
    )
    effective_executor_type = req.executor_type
    oauth_files: list[str] = []
    oauth_file_set: set[str] = set()
    oauth_files_lock = threading.Lock()
    oauth_stats_lock = threading.Lock()
    oauth_registration_success = 0
    oauth_domain_lock = threading.Lock()
    oauth_domain_file_counts: dict[str, int] = {}
    oauth_domain_inflight_counts: dict[str, int] = {}
    oauth_domain_round_robin_index = 0
    artifact_error = ""

    if oauth_bundle_mode:
        os.makedirs(oauth_output_dir, exist_ok=True)
        _task_store.update_meta(
            task_id,
            {
                "task_mode": "oauth_bundle",
                "oauth_bundle": {
                    "status": "running",
                    "output_dir": oauth_output_dir,
                    "target_count": req.count,
                    "count": 0,
                    "attempts": 0,
                    "registration_success": 0,
                },
            },
        )
        format_label = "SUB2API" if oauth_file_format == "sub2api" else "CPA"
        _log(
            task_id,
            f"[OAuth] 已启用授权文件打包任务: 注册完成后生成 {format_label} 格式 ZIP，不同步外部系统",
        )
        _log(task_id, f"[OAuth] 目标授权文件数: {req.count} 个")

    def _current_oauth_file_count() -> int:
        with oauth_files_lock:
            return len(oauth_files)

    def _increment_oauth_registration_success() -> int:
        nonlocal oauth_registration_success
        with oauth_stats_lock:
            oauth_registration_success += 1
            return oauth_registration_success

    def _current_oauth_registration_success() -> int:
        with oauth_stats_lock:
            return oauth_registration_success

    def _bump_business_long_run_success(email: str = "") -> int:
        nonlocal business_long_run_success_count
        normalized_email = str(email or "").strip().lower()
        with business_long_run_lock:
            if normalized_email:
                if normalized_email in business_long_run_success_emails:
                    return business_long_run_success_count
                business_long_run_success_emails.add(normalized_email)
            business_long_run_success_count += 1
            return business_long_run_success_count

    def _current_business_long_run_success() -> int:
        with business_long_run_lock:
            return business_long_run_success_count

    def _update_oauth_bundle_running_meta(attempts: int) -> None:
        if not oauth_bundle_mode:
            return
        _task_store.update_meta(
            task_id,
            {
                "oauth_bundle": {
                    "status": "running",
                    "output_dir": oauth_output_dir,
                    "target_count": req.count,
                    "count": _current_oauth_file_count(),
                    "attempts": attempts,
                    "registration_success": _current_oauth_registration_success(),
                }
            },
        )

    def _reserve_oauth_bundle_business_domain_for_attempt(
        domains: list[str],
        max_accounts_per_domain: int,
    ) -> str:
        nonlocal oauth_domain_round_robin_index
        normalized_domains = _normalize_business_hostname_list(domains)
        if not normalized_domains:
            return ""
        max_accounts = _as_non_negative_int(max_accounts_per_domain)
        with oauth_domain_lock:
            if max_accounts > 0:
                for domain in normalized_domains:
                    reserved = oauth_domain_inflight_counts.get(domain, 0)
                    collected = oauth_domain_file_counts.get(domain, 0)
                    if collected + reserved < max_accounts:
                        oauth_domain_inflight_counts[domain] = reserved + 1
                        return domain
                raise RuntimeError("BUSINESS 域名 OAuth 文件额度不足")

            domain = normalized_domains[
                oauth_domain_round_robin_index % len(normalized_domains)
            ]
            oauth_domain_round_robin_index += 1
            oauth_domain_inflight_counts[domain] = (
                oauth_domain_inflight_counts.get(domain, 0) + 1
            )
            return domain

    def _finish_oauth_bundle_business_domain_attempt(
        domain: str,
        *,
        oauth_file_created: bool,
    ) -> None:
        domain = str(domain or "").strip().lower()
        if not domain:
            return
        with oauth_domain_lock:
            inflight = max(0, oauth_domain_inflight_counts.get(domain, 0) - 1)
            if inflight:
                oauth_domain_inflight_counts[domain] = inflight
            else:
                oauth_domain_inflight_counts.pop(domain, None)
            if oauth_file_created:
                oauth_domain_file_counts[domain] = (
                    oauth_domain_file_counts.get(domain, 0) + 1
                )

    def _sleep_with_control(
        wait_seconds: float,
        *,
        attempt_id: int | None = None,
    ) -> None:
        remaining = max(float(wait_seconds or 0), 0.0)
        while remaining > 0:
            control.checkpoint(attempt_id=attempt_id)
            chunk = min(0.25, remaining)
            time.sleep(chunk)
            remaining -= chunk

    try:
        PlatformCls = get(req.platform)

        def _apply_runtime_defaults(extra: dict) -> dict:
            extra.setdefault("cfworker_force_subdomain", "1")
            extra.setdefault("cfworker_subdomain_strategy", "counter")
            extra.setdefault("cfworker_subdomain_prefix", "acc")
            extra.setdefault("cfworker_subdomain_max_accounts", "100")
            extra.setdefault("cfworker_subdomain_release_on_delete", "1")
            extra.setdefault("cfworker_quick_api_url", "https://temp-api.cursom.shop")
            return extra

        def _apply_cfworker_subdomain_mode(extra: dict) -> dict:
            mode = str(extra.get("cfworker_subdomain_mode") or "").strip().lower()
            if mode in {"", "global"}:
                return extra
            if mode == "root":
                extra["cfworker_force_subdomain"] = "0"
                extra["cfworker_random_subdomain"] = "0"
                extra["cfworker_random_name_subdomain"] = "0"
                extra["cfworker_subdomain"] = ""
            elif mode == "random":
                extra["cfworker_force_subdomain"] = "0"
                extra["cfworker_random_subdomain"] = "1"
                extra["cfworker_random_name_subdomain"] = "0"
                extra["cfworker_subdomain"] = ""
            elif mode == "fixed":
                extra["cfworker_force_subdomain"] = "0"
                extra["cfworker_random_subdomain"] = "0"
                extra["cfworker_random_name_subdomain"] = "0"
            elif mode == "managed":
                extra["cfworker_force_subdomain"] = "1"
                extra["cfworker_random_subdomain"] = "0"
                extra["cfworker_random_name_subdomain"] = "0"
                extra["cfworker_subdomain"] = ""
            return extra

        def _build_mailbox(proxy: Optional[str]):
            from core.config_store import config_store

            merged_extra = _merge_register_runtime_extra(
                config_store.get_all(),
                req.extra,
            )
            merged_extra = _apply_runtime_defaults(merged_extra)
            merged_extra = _apply_cfworker_subdomain_mode(merged_extra)
            mail_provider = str(merged_extra.get("mail_provider", "luckmail") or "luckmail").strip()
            if mail_provider == "gmail":
                # Selection and ownership are task-local, never inherited from defaults.
                for key in ("email", "gmail_fixed_account", "gmail_fixed_email", "gmail_alias_id", "gmail_allow_retry"):
                    merged_extra.pop(key, None)
                for key in ("gmail_source_id", "gmail_alias_ids", "_gmail_retry"):
                    merged_extra[key] = req.extra.get(key)
                merged_extra["gmail_task_id"] = task_id
                merged_extra["executor_type"] = req.executor_type
                merged_extra["registration_proxy_key"] = req.proxy_key or ""
            mailbox_proxy = proxy
            if mail_provider == "cfworker" and not _parse_bool_text(
                merged_extra.get("cfworker_use_register_proxy")
                or merged_extra.get("mailbox_use_register_proxy"),
                default=False,
            ):
                mailbox_proxy = None
            # 把当前平台塞进 extra,让 qqmail 等 provider 用来按平台筛选未注册的别名
            try:
                merged_extra.setdefault("platform", req.platform)
            except Exception:
                pass
            return create_mailbox(
                provider=mail_provider,
                extra=merged_extra,
                proxy=mailbox_proxy,
            )

        _sync_batch_size = max(1, int(req.extra.get("_sync_batch_size", "1") or "1"))
        _pending_sync: list = []
        _pending_sync_lock = threading.Lock()

        def _flush_pending_sync():
            with _pending_sync_lock:
                batch = list(_pending_sync)
                _pending_sync.clear()
            if batch:
                emails = [getattr(a, "email", "?") for a in batch]
                _log(task_id, f"[同步] 批量同步 {len(batch)} 个账号到设备: {', '.join(emails)}")
                device_id_raw = req.extra.get("_sync_device_id")
                try:
                    device_id = int(device_id_raw or 0)
                except (TypeError, ValueError):
                    device_id = 0
                if device_id > 0:
                    from services.device_manager import upload_accounts_to_device

                    device_type = str(req.extra.get("_sync_device_type") or "cpa").upper()
                    for acct, ok, msg in upload_accounts_to_device(batch, device_id):
                        status_msg = "[OK] " + msg if ok else "[FAIL] " + msg
                        _log(task_id, f"  [设备#{device_id}({device_type})] {status_msg}")
                        if ok:
                            _delete_local_account(task_id, acct)
                else:
                    for acct in batch:
                        _auto_upload_integrations(task_id, acct)

        def _retry_existing_ready_for_export_account(device_id: int) -> tuple[str, str] | None:
            """长跑感模式下,补号前先把上次失败留在 DB 的 ready_for_export 账号传一次。

            返回值:
              ("success", email)   → 拿到一个号并成功上传(本次 attempt 不再注册新号)
              ("fail_kept", email) → 拿到一个号但上传仍失败(本次 attempt 不再注册新号,留 DB)
              None           → 队列里没有该设备的待重传号,继续注册新号
            """
            from core.db import AccountModel as _AM

            def _mark_ready_retry_failure(account_id: int, msg: str) -> None:
                try:
                    from datetime import datetime, timezone

                    with Session(engine) as s:
                        acc = s.get(_AM, account_id)
                        if not acc or acc.status != "ready_for_export":
                            return
                        extra = acc.get_extra()
                        retry_count = int(extra.get("ready_for_export_retry_count") or 0) + 1
                        extra["ready_for_export_retry_count"] = retry_count
                        extra["ready_for_export_last_error"] = str(msg or "")[:500]
                        extra["ready_for_export_next_retry_at"] = (
                            time.time() + business_long_run_ready_retry_cooldown_seconds
                        )
                        acc.set_extra(extra)
                        acc.updated_at = datetime.now(timezone.utc)
                        s.add(acc)
                        s.commit()
                except Exception as e:
                    _log(task_id, f"  [长跑] 更新重传冷却失败: {e}")

            try:
                with Session(engine) as s:
                    # 找属于本设备 + status=ready_for_export 的最早一个
                    now_ts = time.time()
                    candidates = s.exec(
                        select(_AM)
                        .where(_AM.platform == req.platform)
                        .where(_AM.status == "ready_for_export")
                        .order_by(_AM.updated_at.asc())
                        .limit(20)
                    ).all()
                    target = None
                    for acc in candidates:
                        acc_extra = acc.get_extra()
                        if str(acc_extra.get("assigned_device_id") or "") != str(device_id):
                            continue
                        try:
                            next_retry_at = float(acc_extra.get("ready_for_export_next_retry_at") or 0)
                        except (TypeError, ValueError):
                            next_retry_at = 0
                        if next_retry_at > now_ts:
                            continue
                        with business_long_run_inflight_lock:
                            if acc.id in business_long_run_inflight_ids:
                                continue
                            business_long_run_inflight_ids.add(acc.id)
                        target = acc
                        break
                    if not target:
                        return None
                    target_id = target.id
                    target_email = target.email
                    target_extra = target.get_extra()
            except Exception as e:
                _log(task_id, f"  [长跑] 查待重传号异常: {e}")
                return None

            try:
                from services.device_manager import upload_accounts_to_device
                _log(task_id, f"  [长跑] 重传待发账号: {target_email}")

                class _StubAccount:
                    pass
                stub = _StubAccount()
                stub.email = target_email
                stub.platform = req.platform
                stub.extra = target_extra
                stub.token = target_extra.get("access_token", "") or ""
                stub.id = target_id
                results = list(upload_accounts_to_device([stub], device_id))
                ok = False
                msg = ""
                for _, ok_flag, m in results:
                    ok = ok_flag
                    msg = m
                    break
                if ok:
                    if _delete_local_account(task_id, stub):
                        _log(task_id, f"  [长跑] 重传成功并删除: {target_email}")
                        return ("success", target_email)
                    _log(
                        task_id,
                        f"  [长跑] 重传上传返回成功,但本地账号未删除,不计成功: {target_email}",
                    )
                    _mark_ready_retry_failure(target_id, "上传成功但本地账号未删除")
                    return ("fail_kept", target_email)
                _mark_ready_retry_failure(target_id, msg)
                _log(task_id, f"  [长跑] 重传仍失败,留 DB: {target_email}: {msg}")
                return ("fail_kept", target_email)
            except Exception as e:
                _mark_ready_retry_failure(target_id, str(e))
                _log(task_id, f"  [长跑] 重传异常,留 DB: {target_email}: {e}")
                return ("fail_kept", target_email)
            finally:
                with business_long_run_inflight_lock:
                    business_long_run_inflight_ids.discard(target_id)

        def _do_one(i: int):
            nonlocal next_start_time
            proxy_pool_obj = None
            _proxy = None
            registration_proxy_selection = None
            proxy_source = ""
            _mailbox = None
            gmail_attempt = False
            gmail_completed = False
            gmail_cancelled = False
            gmail_error = ""
            current_email = req.email or ""
            _pre_email = ""
            attempt_id: int | None = None
            _proxy_disable_addr = ""
            reserved_business_device_id = 0
            reserved_business_domain = ""
            business_reservation_counted = False
            task_oauth_business_domain = ""
            task_oauth_business_domain_reserved = False
            oauth_file_added = False
            try:
                control.checkpoint()
                attempt_id = control.start_attempt()
                control.checkpoint(attempt_id=attempt_id)
                # 长跑感模式:先消费 ready_for_export 队列里属于本设备、上次上传失败的号
                if business_long_run_mode:
                    _dev_id_raw = req.extra.get("_sync_device_id") if req.extra else 0
                    try:
                        _dev_id = int(_dev_id_raw or 0)
                    except (TypeError, ValueError):
                        _dev_id = 0
                    if _dev_id > 0:
                        retry_result = _retry_existing_ready_for_export_account(_dev_id)
                        retry_status = retry_result[0] if retry_result else ""
                        retry_email = retry_result[1] if retry_result else ""
                        if retry_status == "success":
                            _bump_business_long_run_success(retry_email)
                            return AttemptResult.success()
                        if retry_status == "fail_kept":
                            return AttemptResult.skipped("上传失败,留 DB 待下次重传")
                _proxy = normalize_proxy_url(_proxy)
                explicit_proxy = normalize_proxy_url(req.proxy)
                explicit_proxy_node = str(req.proxy_node or "").strip()
                if req.platform == "chatgpt" and req.extra.get("mail_provider") == "gmail":
                    # Re-read the selected proxy immediately before this attempt.
                    # A deletion/disable/check failure since enqueue must stop
                    # before allocating an alias or submitting a remote request.
                    from services.registration_proxy import resolve_registration_proxy
                    selection = resolve_registration_proxy(req.proxy_key or "")
                    registration_proxy_selection = selection
                    _proxy = selection["url"]
                    proxy_source = "已检测代理: " + selection["label"]
                elif explicit_proxy_node:
                    if req.platform == "chatgpt" and effective_executor_type == "protocol":
                        from services.proxy_pool import resolve_chatgpt_protocol_proxy

                        node_proxy = resolve_chatgpt_protocol_proxy(explicit_proxy_node)
                    else:
                        from services.proxy_pool import resolve_node_proxy

                        node_proxy = resolve_node_proxy(
                            explicit_proxy_node,
                            use_mixed_port=False,
                        )
                    if node_proxy:
                        _proxy = normalize_proxy_url(node_proxy.get("addr"))
                        proxy_source = f"Clash节点: {node_proxy.get('name') or explicit_proxy_node}"
                        if node_proxy.get("protocol_fallback"):
                            _log(
                                task_id,
                                "  [代理] "
                                f"{node_proxy.get('fallback_from') or explicit_proxy_node} "
                                f"协议预检失败（{node_proxy.get('fallback_reason') or 'unknown'}），"
                                f"自动切换到 {node_proxy.get('name') or _proxy}",
                            )
                        else:
                            probe = node_proxy.get("protocol_probe")
                            if isinstance(probe, dict) and not probe.get("ok"):
                                _log(
                                    task_id,
                                    "  [代理] "
                                    f"{explicit_proxy_node} 协议预检未通过"
                                    f"（{probe.get('error') or 'unknown'}），"
                                    "未找到可用同地区节点，停止本次尝试",
                                )
                                raise RuntimeError(
                                    "代理协议预检失败: "
                                    f"{explicit_proxy_node}: {probe.get('error') or 'unknown'}"
                                )
                    elif explicit_proxy:
                        _proxy = explicit_proxy
                        proxy_source = f"Clash节点端口: {explicit_proxy_node}"
                    else:
                        raise RuntimeError(f"指定 Clash 节点不存在或无监听端口: {explicit_proxy_node}")
                elif explicit_proxy:
                    _proxy = explicit_proxy
                    proxy_source = "手动指定"
                elif _should_auto_use_proxy():
                    from core.proxy_pool import proxy_pool
                    from core.config_store import config_store as _cs

                    proxy_pool_obj = proxy_pool
                    if req.platform == "chatgpt" and effective_executor_type == "protocol":
                        try:
                            from services.proxy_pool import next_chatgpt_protocol_proxy

                            _proto_p = next_chatgpt_protocol_proxy()
                            if _proto_p:
                                _proxy = normalize_proxy_url(_proto_p.get("addr"))
                                _proxy_disable_addr = _proto_p.get("addr") or ""
                                node_name = _proto_p.get("name")
                                latency = _proto_p.get("latency")
                                proxy_source = (
                                    f"ChatGPT协议预检池: {node_name}"
                                    if node_name
                                    else "ChatGPT协议预检池"
                                )
                                extra_msg = f",延迟 {latency}ms" if latency else ""
                                _log(
                                    task_id,
                                    "  [代理] 注册前已选择 ChatGPT 预检代理: "
                                    f"{redact_proxy_url(_proxy)} (来源: {proxy_source}{extra_msg})",
                                )
                        except Exception:
                            pass
                    if not _proxy:
                        _proxy = normalize_proxy_url(
                            proxy_pool_obj.get_next() if proxy_pool_obj else None
                        )
                        if _proxy:
                            proxy_source = "代理池"
                    if not _proxy:
                        try:
                            from services.proxy_pool import next_proxy as _sub_next
                            _sub_p = _sub_next()
                            if _sub_p:
                                _proxy = normalize_proxy_url(_sub_p.get("addr"))
                                _proxy_disable_addr = (
                                    _sub_p.get("node_addr")
                                    or _sub_p.get("addr")
                                    or ""
                                )
                                node_name = _sub_p.get("name")
                                proxy_source = (
                                    f"订阅代理池: {node_name}"
                                    if node_name
                                    else "订阅代理池"
                                )
                        except Exception:
                            pass
                    if not _proxy:
                        _proxy = normalize_proxy_url(_cs.get("default_proxy", ""))
                        if _proxy:
                            proxy_source = "默认代理"
                if req.register_delay_seconds > 0:
                    with start_gate_lock:
                        control.checkpoint(attempt_id=attempt_id)
                        now = time.time()
                        wait_seconds = max(0.0, next_start_time - now)
                        if wait_seconds > 0:
                            _log(
                                task_id,
                                f"第 {i + 1} 个账号启动前延迟 {wait_seconds:g} 秒",
                            )
                            _sleep_with_control(
                                wait_seconds,
                                attempt_id=attempt_id,
                            )
                        next_start_time = time.time() + req.register_delay_seconds
                control.checkpoint(attempt_id=attempt_id)
                from core.config_store import config_store

                merged_extra = _merge_register_runtime_extra(
                    config_store.get_all(),
                    req.extra,
                )
                merged_extra = _apply_runtime_defaults(merged_extra)
                merged_extra = _apply_cfworker_subdomain_mode(merged_extra)
                if oauth_bundle_mode:
                    merged_extra["chatgpt_oauth_output_dir"] = oauth_output_dir
                    merged_extra["oauth_bundle_task"] = "1"
                if merged_extra.get("_sync_device_business_domains"):
                    try:
                        reserved_business_device_id = int(
                            merged_extra.get("_sync_device_id") or 0
                        )
                    except (TypeError, ValueError):
                        reserved_business_device_id = 0
                    if reserved_business_device_id <= 0:
                        raise RuntimeError("BUSINESS 设备缺少同步设备 ID")
                    from services.device_manager import reserve_business_domain_for_device

                    reservation = reserve_business_domain_for_device(
                        reserved_business_device_id
                    )
                    reserved_business_domain = str(
                        reservation.get("hostname") or ""
                    ).strip().lower()
                    if not reserved_business_domain:
                        raise RuntimeError("BUSINESS 域名分配失败")
                    merged_extra["business_domain"] = reserved_business_domain
                    max_accounts = int(reservation.get("max_accounts") or 0)
                    used_count = int(reservation.get("used_count") or 0)
                    inflight_count = int(reservation.get("inflight_count") or 0)
                    quota_label = (
                        f"{used_count + inflight_count}/{max_accounts}"
                        if max_accounts > 0
                        else "不限"
                    )
                    _log(
                        task_id,
                        f"  [BUSINESS] 使用域名 {reserved_business_domain} "
                        f"(额度 {quota_label})",
                    )
                else:
                    task_business_domains = _normalize_business_hostname_list(
                        merged_extra.get("oauth_bundle_business_domains")
                        or merged_extra.get("business_domains")
                    )
                    current_business_domain = str(
                        merged_extra.get("business_domain") or ""
                    ).strip().lower()
                    if task_business_domains and not current_business_domain:
                        task_business_domain_max_accounts = _as_non_negative_int(
                            merged_extra.get(
                                "oauth_bundle_business_domain_max_accounts"
                            )
                        )
                        if oauth_bundle_mode:
                            selected_business_domain = (
                                _reserve_oauth_bundle_business_domain_for_attempt(
                                    task_business_domains,
                                    task_business_domain_max_accounts,
                                )
                            )
                            task_oauth_business_domain = selected_business_domain
                            task_oauth_business_domain_reserved = bool(
                                selected_business_domain
                            )
                        else:
                            selected_business_domain = (
                                _select_oauth_bundle_business_domain(
                                    task_business_domains,
                                    i,
                                    task_business_domain_max_accounts,
                                )
                            )
                        merged_extra["business_domain"] = selected_business_domain
                        merged_extra["mail_provider"] = "cfworker"
                        cap_label = (
                            f"，每域上限 {task_business_domain_max_accounts}"
                            if task_business_domain_max_accounts > 0
                            else ""
                        )
                        _log(
                            task_id,
                            f"  [BUSINESS] 使用域名 {selected_business_domain} "
                            f"(授权文件任务，不计入设备额度{cap_label})",
                        )

                _config = RegisterConfig(
                    executor_type=effective_executor_type,
                    captcha_solver=req.captcha_solver,
                    proxy=_proxy,
                    extra=merged_extra,
                )
                gmail_attempt = merged_extra.get("mail_provider") == "gmail"
                _mailbox = _build_mailbox(_proxy)
                _platform = PlatformCls(config=_config, mailbox=_mailbox)
                _platform._task_attempt_token = attempt_id
                _platform._log_fn = lambda msg: _log(task_id, msg)
                _platform.bind_task_control(control)
                if getattr(_platform, "mailbox", None) is not None:
                    _platform.mailbox._task_attempt_token = attempt_id
                    _platform.mailbox._log_fn = _platform._log_fn
                if oauth_bundle_mode:
                    oauth_count = _current_oauth_file_count()
                    _task_store.set_progress(
                        task_id,
                        f"OAuth文件 {oauth_count}/{req.count} · 尝试 {i + 1}",
                    )
                    _log(
                        task_id,
                        f"开始第 {i + 1} 次注册，目标 OAuth 文件 {oauth_count}/{req.count}",
                    )
                else:
                    _task_store.set_progress(task_id, f"{i + 1}/{req.count}")
                    _log(task_id, f"开始注册第 {i + 1}/{req.count} 个账号")
                if _proxy:
                    suffix = f" ({proxy_source})" if proxy_source else ""
                    _log(
                        task_id,
                        f"使用代理: {redact_proxy_url(_proxy)}{suffix}；"
                        "本次注册及后续 OAuth/RT 步骤复用该代理",
                    )
                # 尝试提前获取邮箱地址（用于失败归还）
                _pre_email = getattr(getattr(_mailbox, '_last_email', None), 'email', '') or ''
                if merged_extra.get("mail_provider") == "gmail":
                    selected_mailbox = _mailbox.get_email()
                    current_email = _pre_email = selected_mailbox.email
                    merged_extra.update(selected_mailbox.extra or {})
                    _mailbox.registration_started()
                    saved_gmail_account = _mailbox.load_registered_account()
                    if saved_gmail_account is not None:
                        from core.base_platform import Account, AccountStatus
                        account = _platform.resume_gmail_registration(Account(
                            platform="chatgpt", email=saved_gmail_account.email,
                            password=saved_gmail_account.password or "",
                            user_id=saved_gmail_account.user_id or "",
                            token=saved_gmail_account.token or "",
                            status=AccountStatus.REGISTERED,
                            extra=saved_gmail_account.get_extra(),
                        ))
                    else:
                        account = _platform.register(
                            email=current_email,
                            password=req.password or _mailbox.get_registration_password() or None,
                        )
                else:
                    account = _platform.register(
                        email=req.email or None,
                        password=req.password,
                    )
                # 长跑感模式: phase 2/3 失败时 account.status 是 PENDING_RT / PENDING_SEAT_SWITCH,
                # 账号已入库到 RT 长跑队列由运营手动救援,本次 attempt 视为 SKIPPED 不算失败
                if business_long_run_mode and account is not None:
                    try:
                        from core.base_platform import AccountStatus as _AS
                        _st = (
                            account.status.value
                            if isinstance(account.status, _AS)
                            else str(account.status or "")
                        )
                    except Exception:
                        _st = str(getattr(account, "status", "") or "")
                    _pending_st = (_AS.PENDING_RT.value, _AS.PENDING_SEAT_SWITCH.value)
                    if _st in _pending_st:
                        # 账号已在 OpenAI 侧创建,BUSINESS 域名配额必须计为 used(否则下次会超额)
                        if (
                            reserved_business_device_id
                            and reserved_business_domain
                            and not business_reservation_counted
                        ):
                            try:
                                from services.device_manager import finish_business_domain_reservation
                                finish_business_domain_reservation(
                                    reserved_business_device_id,
                                    reserved_business_domain,
                                    success=True,
                                )
                                business_reservation_counted = True
                            except Exception:
                                pass
                        if isinstance(account.extra, dict):
                            dev_id = str(
                                merged_extra.get("_sync_device_id")
                                or reserved_business_device_id
                                or ""
                            ).strip()
                            if dev_id:
                                account.extra.setdefault("assigned_device_id", dev_id)
                            for _dk in ("_sync_device_id", "_sync_device_type"):
                                if merged_extra.get(_dk):
                                    account.extra.setdefault(_dk, merged_extra[_dk])
                            try:
                                save_account(account)
                            except Exception as save_exc:
                                _log(task_id, f"  [长跑] 保存待救援账号归属失败: {save_exc}")
                        if _st == _AS.PENDING_RT.value:
                            _log(
                                task_id,
                                f"  [长跑] {account.email} 卡在 RT,已入「待 RT」队列(本次 attempt 不计失败)",
                            )
                            return AttemptResult.skipped("已入待 RT 队列")
                        _log(
                            task_id,
                            f"  [长跑] {account.email} 卡在席位切换,已入「待改席位」队列(本次 attempt 不计失败)",
                        )
                        return AttemptResult.skipped("已入待改席位队列")
                current_email = account.email or current_email
                # 更新 _pre_email
                if not _pre_email:
                    _pre_email = current_email
                if isinstance(account.extra, dict):
                    mail_provider = merged_extra.get("mail_provider", "")
                    if mail_provider:
                        account.extra.setdefault("mail_provider", mail_provider)
                    if mail_provider == "luckmail" and req.platform == "chatgpt":
                        mailbox_token = getattr(_mailbox, "_token", "") or ""
                        if mailbox_token:
                            account.extra.setdefault("mailbox_token", mailbox_token)
                        if merged_extra.get("luckmail_project_code"):
                            account.extra.setdefault(
                                "luckmail_project_code",
                                merged_extra.get("luckmail_project_code"),
                            )
                        if merged_extra.get("luckmail_email_type"):
                            account.extra.setdefault(
                                "luckmail_email_type",
                                merged_extra.get("luckmail_email_type"),
                            )
                        if merged_extra.get("luckmail_domain"):
                            account.extra.setdefault(
                                "luckmail_domain", merged_extra.get("luckmail_domain")
                            )
                        if merged_extra.get("luckmail_base_url"):
                            account.extra.setdefault(
                                "luckmail_base_url",
                                merged_extra.get("luckmail_base_url"),
                            )
                for _dk in ("_sync_device_id", "_sync_device_type"):
                    if merged_extra.get(_dk):
                        if isinstance(account.extra, dict):
                            account.extra.setdefault(_dk, merged_extra[_dk])
                _apply_business_csv_markers_to_account(account, merged_extra)
                saved_account = (_mailbox.save_account(account)
                                 if merged_extra.get("mail_provider") == "gmail"
                                 else save_account(account))
                if merged_extra.get("mail_provider") == "gmail":
                    _mailbox.complete_registration(saved_account)
                    gmail_completed = True
                else:
                    finalize_account = getattr(_mailbox, "finalize_account", None)
                    if callable(finalize_account):
                        finalize_account(account.email)
                if _proxy and proxy_source == "代理池" and proxy_pool_obj is not None:
                    proxy_pool_obj.report_success(_proxy)
                _log(task_id, f"[OK] 注册成功: {account.email}")
                if oauth_bundle_mode:
                    _increment_oauth_registration_success()
                _save_task_log(req.platform, account.email, "success")
                _update_outlook_register_status(account.email, req.platform, "已注册")
                _update_icloud_hme_register_status(account.email, req.platform, "已注册", getattr(saved_account, "user_id", "") or getattr(account, "user_id", ""))
                if reserved_business_device_id and reserved_business_domain:
                    from services.device_manager import finish_business_domain_reservation

                    finish_business_domain_reservation(
                        reserved_business_device_id,
                        reserved_business_domain,
                        success=True,
                    )
                    business_reservation_counted = True
                _sync_target = saved_account or account
                if oauth_bundle_mode:
                    with oauth_files_lock:
                        bundle_seq_idx = len(oauth_files) + 1
                    oauth_file = _ensure_oauth_file_for_account(
                        task_id,
                        account,
                        saved_account,
                        oauth_output_dir,
                        oauth_file_format,
                        sequence_index=bundle_seq_idx,
                    )
                    if oauth_file:
                        with oauth_files_lock:
                            if (
                                oauth_file not in oauth_file_set
                                and len(oauth_files) < req.count
                            ):
                                oauth_file_set.add(oauth_file)
                                oauth_files.append(oauth_file)
                                oauth_file_added = True
                        _log(task_id, f"  [OAuth] 已收集授权文件: {oauth_file}")
                    if not oauth_file_added:
                        message = f"注册成功但未生成可打包授权文件: {account.email}"
                        _log(task_id, f"  [OAuth] {message}，继续补注册")
                        _log(task_id, "  [OAuth] 打包任务模式: 已跳过外部同步")
                        return AttemptResult.failed(message)
                    _log(task_id, "  [OAuth] 打包任务模式: 已跳过外部同步")
                elif merged_extra.get("mail_provider") == "gmail":
                    _log(task_id, "[Gmail] 已关联 GPT 套餐管理账号池")
                elif business_long_run_mode and merged_extra.get("_sync_device_id"):
                    # 长跑感:同步上传 + 用结果决定 attempt 是 SUCCESS 还是 SKIPPED(账号留 DB)
                    try:
                        _dev_id = int(merged_extra.get("_sync_device_id") or 0)
                    except (TypeError, ValueError):
                        _dev_id = 0
                    upload_ok = False
                    upload_msg = ""
                    if _dev_id > 0:
                        try:
                            from services.device_manager import upload_accounts_to_device
                            for _acct, _ok, _msg in upload_accounts_to_device(
                                [_sync_target], _dev_id
                            ):
                                upload_ok = _ok
                                upload_msg = _msg
                                if _ok:
                                    if not _delete_local_account(task_id, _acct):
                                        upload_ok = False
                                        upload_msg = f"{_msg}; 本地账号未删除,不计成功"
                                break
                        except Exception as _up_exc:
                            upload_msg = str(_up_exc)
                    if upload_ok:
                        _bump_business_long_run_success(account.email)
                        _log(
                            task_id,
                            f"  [长跑] {account.email} 上传成功并清理本地 "
                            f"({_current_business_long_run_success()}/{req.count})",
                        )
                    else:
                        _log(
                            task_id,
                            f"  [长跑] {account.email} 上传失败,留 DB 状态 ready_for_export 等下次重传: {upload_msg}",
                        )
                        return AttemptResult.skipped(f"上传失败,留 DB: {upload_msg}")
                elif _sync_batch_size <= 1 or not merged_extra.get("_sync_device_id"):
                    _auto_upload_integrations(task_id, _sync_target)
                else:
                    _do_flush = False
                    with _pending_sync_lock:
                        _pending_sync.append(_sync_target)
                        if len(_pending_sync) >= _sync_batch_size:
                            _do_flush = True
                    if _do_flush:
                        _flush_pending_sync()
                cashier_url = (account.extra or {}).get("cashier_url", "")
                if cashier_url:
                    _log(task_id, f"  [升级链接] {cashier_url}")
                    _task_store.add_cashier_url(task_id, cashier_url)
                return AttemptResult.success()
            except SkipCurrentAttemptRequested as e:
                gmail_cancelled = True
                _log(task_id, f"[SKIP] 已跳过当前账号: {e}")
                _save_task_log(
                    req.platform,
                    current_email,
                    "skipped",
                    error=str(e),
                )
                return AttemptResult.skipped(str(e))
            except StopTaskRequested as e:
                gmail_cancelled = True
                _log(task_id, f"[STOP] {e}")
                return AttemptResult.stopped(str(e))
            except Exception as e:
                gmail_error = str(e)
                if registration_proxy_selection and _proxy:
                    from services.proxy_pool import is_proxy_error, disable_proxy
                    if is_proxy_error(gmail_error):
                        # Account/OTP errors do not invalidate a proxy. Network
                        # failures revoke availability until it passes a check.
                        try:
                            if registration_proxy_selection.get("kind") == "manual":
                                from core.proxy_pool import proxy_pool
                                proxy_pool.report_fail(_proxy, proxy_id=registration_proxy_selection["proxy_id"])
                            elif registration_proxy_selection.get("kind") == "subscription":
                                disable_proxy(_proxy)
                        except Exception:
                            _log(task_id, "代理连接失败，检测状态暂未写回，请重新检测代理")
                if (
                    _proxy
                    and proxy_source == "代理池"
                    and proxy_pool_obj is not None
                ):
                    proxy_pool_obj.report_fail(_proxy)
                if _proxy and proxy_source.startswith("订阅代理池"):
                    from services.proxy_pool import is_proxy_error, disable_proxy
                    if is_proxy_error(str(e)):
                        failed_proxy = _proxy_disable_addr or _proxy
                        if disable_proxy(failed_proxy):
                            _log(task_id, f"  [代理] 已禁用失败节点: {failed_proxy}")
                _log(task_id, f"[FAIL] 注册失败: {e}")
                # 归还 Outlook 预留邮箱
                if not gmail_attempt:
                    _return_outlook_if_needed(_mailbox, current_email, req.platform)
                release_account = getattr(_mailbox, "release_account", None)
                release_email = current_email or _pre_email
                if callable(release_account) and release_email and not gmail_attempt:
                    try:
                        release_account(release_email)
                    except Exception:
                        pass
                _save_task_log(
                    req.platform,
                    current_email,
                    "failed",
                    error=str(e),
                )
                return AttemptResult.failed(str(e))
            finally:
                if gmail_attempt and _mailbox is not None:
                    try:
                        if not gmail_completed:
                            _mailbox.release_account(
                                current_email or _pre_email,
                                cancelled=gmail_cancelled,
                                error=gmail_error,
                            )
                    except Exception:
                        _log(task_id, "[Gmail] 任务状态写回暂未完成，后台将根据持久记录恢复")
                    finally:
                        close_mailbox = getattr(_mailbox, "close", None)
                        if callable(close_mailbox):
                            try:
                                close_mailbox()
                            except Exception:
                                pass
                if (
                    reserved_business_device_id
                    and reserved_business_domain
                    and not business_reservation_counted
                ):
                    try:
                        from services.device_manager import finish_business_domain_reservation

                        finish_business_domain_reservation(
                            reserved_business_device_id,
                            reserved_business_domain,
                            success=False,
                        )
                    except Exception:
                        pass
                if task_oauth_business_domain_reserved:
                    _finish_oauth_bundle_business_domain_attempt(
                        task_oauth_business_domain,
                        oauth_file_created=oauth_file_added,
                    )
                control.finish_attempt(attempt_id)

        from concurrent.futures import (
            FIRST_COMPLETED,
            CancelledError,
            ThreadPoolExecutor,
            as_completed,
            wait,
        )

        worker_cap = (
            OAUTH_BUNDLE_MAX_CONCURRENCY
            if oauth_bundle_mode
            else REGISTER_TASK_MAX_CONCURRENCY
        )
        requested_workers = max(1, int(req.concurrency or 1))
        max_workers = min(requested_workers, req.count, worker_cap)
        _log(task_id, f"任务并发: {max_workers}/{requested_workers}")
        if requested_workers > worker_cap:
            _log(task_id, f"任务并发超过上限 {worker_cap}，已自动限制")
        elif req.count < requested_workers:
            _log(task_id, f"任务数量小于请求并发，实际并发按任务数量 {req.count} 执行")
        stopped = False
        attempts_completed = 0
        # 长跑感水位告警:每 20 个 attempt 检查一次,若期间 success_count 没涨
        # → 打告警让运营注意是否风控,不强行 stop。
        _BIZ_LONG_RUN_WARN_WINDOW = 20
        biz_long_run_last_success_seen = 0
        biz_long_run_attempts_at_last_check = 0

        def _record_future_result(future) -> None:
            nonlocal attempts_completed, skipped, stopped, success
            nonlocal biz_long_run_last_success_seen, biz_long_run_attempts_at_last_check
            try:
                result = future.result()
            except CancelledError:
                return
            except Exception as e:
                attempts_completed += 1
                _log(task_id, f"[ERROR] 任务线程异常: {e}")
                errors.append(str(e))
            else:
                attempts_completed += 1
                if result.outcome == AttemptOutcome.SUCCESS:
                    if oauth_bundle_mode:
                        success = _current_oauth_file_count()
                    else:
                        success += 1
                elif result.outcome == AttemptOutcome.SKIPPED:
                    skipped += 1
                elif result.outcome == AttemptOutcome.STOPPED:
                    stopped = True
                else:
                    errors.append(result.message)

            if oauth_bundle_mode:
                success = _current_oauth_file_count()
                _task_store.set_progress(
                    task_id,
                    f"OAuth文件 {success}/{req.count} · 尝试 {attempts_completed}",
                )
                _update_oauth_bundle_running_meta(attempts_completed)
            if business_long_run_mode:
                cur = _current_business_long_run_success()
                # 用 runner 自己的 success_count 覆盖默认 success(后者只数 AttemptResult.success())
                success = cur
                # 每 N 次 attempt 检查一次水位:无新增 success → 告警
                if (
                    attempts_completed - biz_long_run_attempts_at_last_check
                    >= _BIZ_LONG_RUN_WARN_WINDOW
                ):
                    if cur == biz_long_run_last_success_seen:
                        _log(
                            task_id,
                            f"⚠ [长跑] 最近 {_BIZ_LONG_RUN_WARN_WINDOW} 次 attempt 一个号"
                            f"都没成功上传到远端(success_count={cur}/{req.count}),"
                            "可能命中风控或代理不可用。已注册的号都在「待 RT」/「待改席位」"
                            "队列保留,建议手动停止任务后排查。",
                        )
                    biz_long_run_last_success_seen = cur
                    biz_long_run_attempts_at_last_check = attempts_completed
                _task_store.set_progress(
                    task_id,
                    f"{cur}/{req.count} · 尝试 {attempts_completed}",
                )
            _task_store.update_counts(
                task_id,
                success=success,
                skipped=skipped,
                errors=errors,
            )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            if business_long_run_mode:
                next_attempt_index = 0
                active_futures: dict = {}

                def _submit_business_long_run_attempts() -> None:
                    nonlocal next_attempt_index
                    while not stopped and not control.is_stop_requested():
                        remaining = req.count - _current_business_long_run_success()
                        if remaining <= 0:
                            break
                        allowed_active = min(max_workers, remaining)
                        if len(active_futures) >= allowed_active:
                            break
                        future = pool.submit(_do_one, next_attempt_index)
                        active_futures[future] = next_attempt_index
                        next_attempt_index += 1

                _submit_business_long_run_attempts()
                while active_futures:
                    done, _pending = wait(
                        active_futures, return_when=FIRST_COMPLETED,
                    )
                    for f in done:
                        active_futures.pop(f, None)
                        _record_future_result(f)
                    if stopped or control.is_stop_requested():
                        stopped = True
                        for pending in active_futures:
                            pending.cancel()
                        break
                    _submit_business_long_run_attempts()
                # 长跑感 success_count 走自己的计数器,覆盖默认的 success 显示
                success = _current_business_long_run_success()
            elif oauth_bundle_mode:
                next_attempt_index = 0
                active_futures = {}

                def _submit_oauth_attempts() -> None:
                    nonlocal next_attempt_index
                    while not stopped and not control.is_stop_requested():
                        remaining = req.count - _current_oauth_file_count()
                        if remaining <= 0:
                            break
                        allowed_active = min(max_workers, remaining)
                        if len(active_futures) >= allowed_active:
                            break
                        future = pool.submit(_do_one, next_attempt_index)
                        active_futures[future] = next_attempt_index
                        next_attempt_index += 1

                _submit_oauth_attempts()
                while active_futures:
                    done, _pending = wait(
                        active_futures,
                        return_when=FIRST_COMPLETED,
                    )
                    for f in done:
                        active_futures.pop(f, None)
                        _record_future_result(f)
                    if stopped or control.is_stop_requested():
                        stopped = True
                        for pending in active_futures:
                            pending.cancel()
                        break
                    _submit_oauth_attempts()
            else:
                futures = [pool.submit(_do_one, i) for i in range(req.count)]
                for f in as_completed(futures):
                    _record_future_result(f)
                    if stopped or control.is_stop_requested():
                        stopped = True
                        for pending in futures:
                            if pending is not f:
                                pending.cancel()
        if not oauth_bundle_mode:
            _flush_pending_sync()
    except Exception as e:
        _log(task_id, f"致命错误: {e}")
        _task_store.finish(
            task_id,
            status="failed",
            success=success,
            skipped=skipped,
            errors=errors,
            error=str(e),
        )
        _task_store.cleanup()
        return

    if oauth_bundle_mode:
        with oauth_files_lock:
            files_to_zip = list(oauth_files)[: req.count]
        if files_to_zip:
            try:
                zip_path, file_count = _build_oauth_zip(task_id, files_to_zip)
                success = file_count
                artifact = {
                    "type": "oauth_zip",
                    "format": oauth_file_format,
                    "path": zip_path,
                    "count": file_count,
                    "target_count": req.count,
                    "attempts": attempts_completed,
                    "registration_success": _current_oauth_registration_success(),
                    "filename": f"{task_id}_{oauth_file_format}_oauth_files.zip",
                    "download_url": f"/tasks/{task_id}/artifact/oauth-zip",
                }
                _task_store.update_meta(
                    task_id,
                    {
                        "artifact": artifact,
                        "oauth_bundle": {
                            "status": "ready",
                            "output_dir": oauth_output_dir,
                            "zip_path": zip_path,
                            "target_count": req.count,
                            "count": file_count,
                            "attempts": attempts_completed,
                            "registration_success": _current_oauth_registration_success(),
                        },
                    },
                )
                _log(
                    task_id,
                    f"[OAuth] 授权文件压缩包已生成: {zip_path} ({file_count} 个文件)",
                )
                if (
                    file_count < req.count
                    and not stopped
                    and not control.is_stop_requested()
                ):
                    artifact_error = (
                        f"OAuth 文件数量未达标: {file_count}/{req.count}"
                    )
                    errors.append(artifact_error)
                    _task_store.update_counts(
                        task_id,
                        success=success,
                        skipped=skipped,
                        errors=errors,
                    )
                    _log(task_id, f"[OAuth] {artifact_error}")
            except Exception as exc:
                artifact_error = f"OAuth 压缩包生成失败: {exc}"
                errors.append(artifact_error)
                _task_store.update_counts(
                    task_id,
                    success=success,
                    skipped=skipped,
                    errors=errors,
                )
                _log(task_id, f"[OAuth] {artifact_error}")
        elif not stopped and not control.is_stop_requested():
            artifact_error = "OAuth 压缩包生成失败: 没有收集到授权文件"
            errors.append(artifact_error)
            _task_store.update_counts(
                task_id,
                success=success,
                skipped=skipped,
                errors=errors,
            )
            _log(task_id, f"[OAuth] {artifact_error}")

    if control.is_stop_requested() or stopped:
        final_status = "stopped"
    elif artifact_error:
        final_status = "failed"
    else:
        final_status = "done"
    if oauth_bundle_mode:
        registration_success = _current_oauth_registration_success()
        prefix = "任务已停止" if final_status == "stopped" else "完成"
        summary = (
            f"{prefix}: OAuth 文件 {success}/{req.count} 个, "
            f"注册成功 {registration_success} 次, 跳过 {skipped} 次, "
            f"失败尝试 {len(errors)} 次"
        )
    elif final_status == "stopped":
        summary = (
            f"任务已停止: 成功 {success} 个, 跳过 {skipped} 个, 失败 {len(errors)} 个"
        )
    else:
        summary = f"完成: 成功 {success} 个, 跳过 {skipped} 个, 失败 {len(errors)} 个"
    _log(task_id, summary)
    _task_store.finish(
        task_id,
        status=final_status,
        success=success,
        skipped=skipped,
        errors=errors,
    )
    if oauth_bundle_mode:
        _persist_oauth_bundle_history(task_id)
    _task_store.cleanup()


@router.post("/register")
def create_register_task(
    req: RegisterTaskRequest,
    background_tasks: BackgroundTasks,
):
    task_id = enqueue_register_task(req, background_tasks=background_tasks)
    return {"task_id": task_id}


@router.post("/oauth-bundle")
def create_oauth_bundle_task(req: OAuthBundleTaskCreateRequest):
    task_req, meta = _build_oauth_bundle_request(req)
    task_id = enqueue_register_task(
        task_req,
        source=OAUTH_BUNDLE_SOURCE,
        meta=meta,
    )
    return {
        "ok": True,
        "task_id": task_id,
        "task_name": meta.get("task_name", ""),
        "count": task_req.count,
        "concurrency": task_req.concurrency,
        "register_delay_seconds": task_req.register_delay_seconds,
        "executor_type": meta.get("executor_type", task_req.executor_type),
        "mail_provider": meta.get("mail_provider", ""),
        "auth_file_format": meta.get("auth_file_format", "cpa"),
        "business_domains": meta.get("business_domains", []),
        "business_domain_max_accounts": meta.get("business_domain_max_accounts", 0),
        "template_device_id": meta.get("template_device_id"),
        "template_device_name": meta.get("template_device_name", ""),
    }


@router.post("/oauth-bundle/batch-delete")
def batch_delete_oauth_bundle_tasks(body: OAuthBundleTaskBatchDeleteRequest):
    _ensure_oauth_bundle_history_loaded()
    unique_ids = [
        task_id
        for task_id in dict.fromkeys(str(item or "").strip() for item in body.ids)
        if task_id
    ]
    if not unique_ids:
        raise HTTPException(400, "授权文件任务 ID 列表不能为空")
    if len(unique_ids) > 100:
        raise HTTPException(400, "单次最多删除 100 个授权文件任务")

    results = [_delete_oauth_bundle_task(task_id) for task_id in unique_ids]
    deleted = [item for item in results if item.get("deleted")]
    blocked = [item for item in results if not item.get("deleted")]
    return {
        "deleted": len(deleted),
        "blocked": blocked,
        "total_requested": len(unique_ids),
    }


@router.post("/{task_id}/skip-current")
def skip_current_account(task_id: str):
    _ensure_task_mutable(task_id)
    control = _task_store.request_skip_current(task_id)
    _log(task_id, "收到手动跳过当前账号请求")
    return {"ok": True, "task_id": task_id, "control": control}


@router.post("/{task_id}/stop")
def stop_task(task_id: str):
    _ensure_task_mutable(task_id)
    control = _task_store.request_stop(task_id)
    _log(task_id, "收到手动停止任务请求")
    return {"ok": True, "task_id": task_id, "control": control}


@router.get("/logs")
def get_logs(platform: str = None, page: int = 1, page_size: int = 50):
    with Session(engine) as s:
        q = select(TaskLog)
        if platform:
            q = q.where(TaskLog.platform == platform)
        q = q.order_by(TaskLog.id.desc())
        total = len(s.exec(q).all())
        items = s.exec(q.offset((page - 1) * page_size).limit(page_size)).all()
    return {"total": total, "items": items}


@router.post("/logs/batch-delete")
def batch_delete_logs(body: TaskLogBatchDeleteRequest):
    if not body.ids:
        raise HTTPException(400, "任务历史 ID 列表不能为空")

    unique_ids = list(dict.fromkeys(body.ids))
    if len(unique_ids) > 1000:
        raise HTTPException(400, "单次最多删除 1000 条任务历史")

    with Session(engine) as s:
        try:
            logs = s.exec(select(TaskLog).where(TaskLog.id.in_(unique_ids))).all()
            found_ids = {log.id for log in logs if log.id is not None}

            for log in logs:
                s.delete(log)

            s.commit()
            deleted_count = len(found_ids)
            not_found_ids = [log_id for log_id in unique_ids if log_id not in found_ids]
            logger.info("批量删除任务历史成功: %s 条", deleted_count)

            return {
                "deleted": deleted_count,
                "not_found": not_found_ids,
                "total_requested": len(unique_ids),
            }
        except Exception as e:
            s.rollback()
            logger.exception("批量删除任务历史失败")
            raise HTTPException(500, f"批量删除任务历史失败: {str(e)}")


@router.get("/summary")
def list_task_summaries():
    _ensure_oauth_bundle_history_loaded()
    return _task_store.list_summaries()


@router.get("/{task_id}/logs/stream")
async def stream_logs(task_id: str, since: int = 0, tail: Optional[int] = None):
    """SSE 实时日志流"""
    _ensure_oauth_bundle_history_loaded()
    _ensure_task_exists(task_id)

    async def event_generator():
        sent = max(0, int(since or 0))
        while True:
            logs, status = _task_store.log_state(task_id)
            if tail is not None and sent <= 0:
                limit = max(0, min(int(tail or 0), 1000))
                sent = max(len(logs) - limit, 0) if limit > 0 else len(logs)
            while sent < len(logs):
                yield f"data: {json.dumps({'line': logs[sent]})}\n\n"
                sent += 1
            if status in ("done", "failed", "stopped"):
                yield f"data: {json.dumps({'done': True, 'status': status})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{task_id}/artifact/oauth-zip")
def download_oauth_zip_artifact(task_id: str):
    _ensure_oauth_bundle_history_loaded()
    _ensure_task_exists(task_id)
    snapshot = _task_store.snapshot(task_id)
    meta = snapshot.get("meta") if isinstance(snapshot, dict) else {}
    artifact = (meta or {}).get("artifact") if isinstance(meta, dict) else {}
    if not isinstance(artifact, dict) or artifact.get("type") != "oauth_zip":
        raise HTTPException(404, "任务没有可下载的 OAuth 压缩包")

    file_path = str(artifact.get("path") or "").strip()
    if not file_path or not os.path.isfile(file_path):
        raise HTTPException(404, "OAuth 压缩包文件不存在")

    filename = str(artifact.get("filename") or "").strip() or f"{task_id}_oauth_files.zip"
    return FileResponse(
        file_path,
        media_type="application/zip",
        filename=filename,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@router.get("/{task_id}/artifact/access-tokens-txt")
def download_oauth_access_tokens_txt_artifact(task_id: str):
    _ensure_oauth_bundle_history_loaded()
    _ensure_task_exists(task_id)
    snapshot = _task_store.snapshot(task_id)
    meta = snapshot.get("meta") if isinstance(snapshot, dict) else {}
    artifact = (meta or {}).get("artifact") if isinstance(meta, dict) else {}
    if not isinstance(artifact, dict) or artifact.get("type") != "oauth_zip":
        raise HTTPException(404, "任务没有可转换的 OAuth 压缩包")

    zip_path = str(artifact.get("path") or "").strip()
    try:
        txt_path, token_count = _build_oauth_access_tokens_txt(task_id, zip_path)
    except RuntimeError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"AccessToken TXT 生成失败: {exc}") from exc

    filename = f"{task_id}_access_tokens_{token_count}.txt"
    _task_store.update_meta(
        task_id,
        {
            "access_tokens_txt": {
                "path": txt_path,
                "count": token_count,
                "filename": filename,
                "download_url": f"/tasks/{task_id}/artifact/access-tokens-txt",
                "updated_at": time.time(),
            }
        },
    )
    _persist_oauth_bundle_history(task_id)
    return FileResponse(
        txt_path,
        media_type="text/plain; charset=utf-8",
        filename=filename,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@router.get("/{task_id}")
def get_task(task_id: str, tail: Optional[int] = None):
    _ensure_oauth_bundle_history_loaded()
    _ensure_task_exists(task_id)
    snapshot = _task_store.snapshot(task_id)
    logs = snapshot.get("logs")
    if tail is not None and isinstance(logs, list):
        total = len(logs)
        limit = max(0, min(int(tail or 0), 1000))
        offset = max(total - limit, 0) if limit > 0 else total
        snapshot["logs"] = logs[offset:] if limit > 0 else []
        snapshot["logs_total"] = total
        snapshot["logs_offset"] = offset
    return snapshot


@router.get("")
def list_tasks():
    _ensure_oauth_bundle_history_loaded()
    return _task_store.list_snapshots()
