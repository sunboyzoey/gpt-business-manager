"""Gmail management API. Public DTOs never expose source credentials."""
from __future__ import annotations

from functools import wraps
import threading
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from services import gmail_store as store


class _SafeValidationRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                # FastAPI's default errors include input values, potentially the password.
                errors = [{key: item[key] for key in ("loc", "msg", "type")} for item in exc.errors()]
                raise HTTPException(422, detail=errors) from None
        return handler


router = APIRouter(prefix="/gmail", tags=["gmail"], route_class=_SafeValidationRoute)
_source_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _safe_errors(callback):
    @wraps(callback)
    def wrapped(*args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except HTTPException:
            raise
        except store.GmailStoreError as exc:
            raise HTTPException(exc.status_code, detail=exc.message) from None
        except Exception:
            raise HTTPException(503, detail="Gmail 管理暂时不可用，请稍后重试") from None
    return wrapped


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateSourceRequest(_Request):
    email: str
    app_password: SecretStr
    proxy_url: str = ""


class UpdateSourceRequest(_Request):
    app_password: Optional[SecretStr] = None
    enabled: Optional[bool] = None
    proxy_url: Optional[str] = None


class ImportSourcesRequest(_Request):
    data: SecretStr
    proxy_url: Optional[str] = None


class GenerateAliasesRequest(_Request):
    count: int = Field(1, ge=1, le=store.MAX_ALIASES_PER_SOURCE)
    prefix: str = "alias"


def _public_setup_job(job):
    if not job:
        return None
    result = {key: job.get(key) for key in (
        "id", "source_id", "email", "status", "stage", "message", "error_code",
        "can_retry", "has_pending_password", "created_at", "updated_at", "attempts", "next_retry_at",
    )}
    result.update(code=result.get("error_code") or "", retryable=result.get("can_retry") is True,
                  credential_saved=result.get("has_pending_password") is True)
    return result


def _source_with_setup(item, job=None):
    source = dict(item)
    reason = ""
    if not source.get("enabled"):
        reason = "母号已停用，请先启用"
    elif source.get("has_app_password"):
        reason = "已配置应用专用密码" if source.get("receive_ready") else "已有应用专用密码，请先测试收件授权"
    elif not source.get("has_login_password"):
        reason = "未保存 Google 登录密码，请先导入登录资料"
    elif job and job.get("status") in {"queued", "running"}:
        reason = "应用专用密码配置任务正在处理"
    elif job and job.get("status") != "succeeded":
        reason = job.get("message") or "请从原配置任务继续处理"
    source.update(app_password_setup=_public_setup_job(job),
                  can_auto_setup_app_password=not bool(reason), auto_setup_disabled_reason=reason)
    return source


def _setup_response(job):
    return {"job": _public_setup_job(job)}


@router.get("/sources")
@_safe_errors
def get_sources():
    from services.gmail_app_password_store import latest_jobs_by_source
    latest = {job["source_id"]: job for job in latest_jobs_by_source()}
    return {"items": [_source_with_setup(item, latest.get(item["id"])) for item in store.list_sources()]}


@router.post("/sources")
@_safe_errors
def post_source(body: CreateSourceRequest):
    return {"item": store.create_source(body.email, body.app_password.get_secret_value(), body.proxy_url)}


@router.post("/sources/import", status_code=202)
@_safe_errors
def import_sources(body: ImportSourcesRequest):
    return store.import_sources(body.data.get_secret_value(), proxy_url=body.proxy_url)


@router.get("/imports/{job_id}")
@_safe_errors
def get_import(job_id: str):
    from services.gmail_import_jobs import manager
    return manager.get(job_id)


@router.post("/imports/{job_id}/cancel")
@_safe_errors
def cancel_import(job_id: str):
    from services.gmail_import_jobs import manager
    return manager.cancel(job_id)


@router.post("/sources/{source_id}/verify", status_code=202)
@_safe_errors
def verify_source(source_id: int):
    from services.gmail_import_jobs import manager
    return manager.start_verify(source_id)


@router.patch("/sources/{source_id}")
@_safe_errors
def patch_source(source_id: int, body: UpdateSourceRequest):
    if any(getattr(body, field) is None for field in body.model_fields_set):
        raise HTTPException(422, "应用密码、代理和启用状态不能为 null")
    password = body.app_password.get_secret_value() if body.app_password is not None else None
    return {"item": store.update_source(source_id, app_password=password, enabled=body.enabled, proxy_url=body.proxy_url)}


@router.post("/sources/{source_id}/app-password/setup", status_code=202)
@_safe_errors
def setup_source_app_password(source_id: int, body: _Request = _Request()):
    from services import gmail_app_password_store as jobs
    from services.gmail_app_password_runtime import gmail_app_password_runtime
    job = jobs.begin(source_id)
    if job["status"] == "queued":
        gmail_app_password_runtime.wake()
    return _setup_response(job)


@router.get("/app-password/jobs")
@_safe_errors
def list_app_password_jobs(source_id: Optional[int] = Query(None, gt=0)):
    from services.gmail_app_password_store import list_jobs
    return {"items": [_public_setup_job(job) for job in list_jobs(source_id=source_id)]}


@router.get("/app-password/jobs/{job_id}")
@_safe_errors
def get_app_password_job(job_id: str):
    from services.gmail_app_password_store import get_job
    return _setup_response(get_job(job_id))


@router.post("/app-password/jobs/{job_id}/retry", status_code=202)
@_safe_errors
def retry_app_password_job(job_id: str, body: _Request = _Request()):
    from services.gmail_app_password_store import retry
    from services.gmail_app_password_runtime import gmail_app_password_runtime
    job = retry(job_id)
    if job["status"] == "queued":
        gmail_app_password_runtime.wake()
    return _setup_response(job)


@router.get("/aliases")
@_safe_errors
def get_aliases(source_id: Optional[int] = Query(None, gt=0)):
    return {"items": store.list_aliases(source_id)}


@router.get("/registration-candidates")
@_safe_errors
def registration_candidates(source_id: Optional[int] = Query(None, gt=0)):
    from services.gmail_registration import list_candidates
    return {"items": list_candidates(source_id)}


@router.post("/sources/{source_id}/aliases")
@_safe_errors
def post_aliases(source_id: int, body: GenerateAliasesRequest):
    return {"items": store.generate_aliases(source_id, count=body.count, prefix=body.prefix)}


_ERROR_MESSAGES = {
    "auth_required": "Gmail 授权失败，请确认两步验证已开启并重新保存应用专用密码",
    "network_error": "无法连接 Gmail，请检查网络后重试",
    "timeout": "Gmail 请求超时，请稍后重试",
    "delivery_timeout": "尚未确认收到测试邮件，发送可能已成功，可稍后查看收件",
    "send_failed": "测试邮件发送失败，请检查 Gmail 发信权限后重试",
    "imap_unavailable": "Gmail IMAP 不可用，请确认账户允许 IMAP 访问",
    "invalid_alias": "此别名不属于当前 Gmail 源邮箱",
    "protocol_error": "Gmail 返回了无法读取的响应，请稍后重试",
    "crypto_error": "应用密码解密失败，请检查服务器凭证密钥或重新保存应用密码",
    "tls_error": "Gmail 安全连接失败，请检查网络和代理配置后重试",
    "imap_error": "Gmail IMAP 操作失败，请稍后重试",
    "smtp_error": "Gmail 测试邮件发送失败，请检查发信权限后重试",
    "mailbox_unavailable": "Gmail 收件箱暂时不可用，请稍后重试",
    "invalid_proxy": "代理配置无效，请检查代理协议、主机和端口",
}


def _run_network(source_id: int, operation: str, *, alias_id: Optional[int] = None, limit: int = 20):
    from services.gmail_transport import GmailTransport, GmailTransportError

    with _locks_guard:
        source_lock = _source_locks.setdefault(source_id, threading.Lock())
    if not source_lock.acquire(blocking=False):
        raise HTTPException(409, "此源邮箱正在执行邮件操作，请稍后重试")
    try:
        snapshot = store.network_snapshot(source_id, alias_id)
        result = None
        transport = None
        error_status = ""
        try:
            password = store.decrypt_snapshot_password(snapshot)
            transport = GmailTransport(snapshot.email, password, proxy_url=snapshot.proxy_url)
            if operation == "connect":
                transport.connect_test()
            elif operation == "messages":
                result = transport.list_messages(snapshot.alias_email, limit=limit)
            else:
                result = transport.test_delivery(snapshot.alias_email, timeout=30)
                if not isinstance(result, dict) or result.get("ok") is not True:
                    error_status = "delivery_timeout"
        except GmailTransportError as exc:
            error_status = exc.code
        except store.GmailStoreError as exc:
            error_status = exc.code
        except Exception:
            error_status = "network_error"
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
        if error_status == "authentication_failed":
            error_status = "auth_required"
        if error_status == "timeout" and operation == "receive":
            error_status = "delivery_timeout"
        if error_status and error_status not in _ERROR_MESSAGES:
            error_status = "network_error"
        checked_at = store.utcnow()
        status = error_status or "ok"
        success_message = {"connect": "Gmail 连接正常", "messages": "邮件已读取", "receive": "测试邮件已收到"}[operation]
        message = _ERROR_MESSAGES.get(error_status, success_message)
        if not store.record_network_result(snapshot, status=status, message=message,
                                           checked_at=checked_at, test_receive=operation == "receive"):
            raise HTTPException(409, "源邮箱授权或启用状态已变化，请按最新配置重试")
        if operation == "connect":
            return {"ok": not bool(error_status), "status": status, "message": message, "checked_at": checked_at}
        if operation == "receive":
            response = {"ok": not bool(error_status), "message": message}
            if not error_status and isinstance(result, dict):
                response.update({key: result[key] for key in ("received_at", "message_id") if key in result})
            return response
        if error_status:
            raise HTTPException(400 if error_status == "auth_required" else 502, message)
        # Whitelist message fields, including plain text only; no HTML body crosses the API.
        items = [{key: item.get(key) for key in ("id", "from", "subject", "text", "received_at", "recipients")}
                 for item in (result or [])]
        return {"items": items, "checked_at": checked_at}
    finally:
        source_lock.release()


@router.post("/sources/{source_id}/test")
@_safe_errors
def test_source(source_id: int):
    return _run_network(source_id, "connect")


@router.get("/aliases/{alias_id}/messages")
@_safe_errors
def get_messages(alias_id: int, limit: int = Query(20, ge=1, le=100)):
    return _run_network(store.alias_source_id(alias_id), "messages", alias_id=alias_id, limit=limit)


@router.post("/aliases/{alias_id}/test-receive")
@_safe_errors
def test_receive(alias_id: int):
    return _run_network(store.alias_source_id(alias_id), "receive", alias_id=alias_id)
