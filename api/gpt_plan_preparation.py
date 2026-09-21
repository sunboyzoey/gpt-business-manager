"""Explicit preparation controls. GETs never start browsers or create tasks."""
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from services import gpt_plan_preparation_store as store
from services.gpt_plan_preparation import preparation_runtime

router = APIRouter(prefix="/gpt-plans/preparation", tags=["gpt-plans"])


class SettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: StrictBool = False
    interval_minutes: int = Field(default=5, ge=1, le=1440)
    batch_size: int = Field(default=5, ge=1, le=100)
    target_ready: int = Field(default=20, ge=1, le=10000)
    mail_provider: Literal["auto", "icloud", "outlook", "gmail"] = "icloud"
    browser_mode: Literal["headed", "headless"] = "headless"
    max_attempts: int = Field(default=3, ge=1, le=5)

    @model_validator(mode="before")
    @classmethod
    def ignore_removed_daily_limit(cls, values):
        # Compatibility only: old cached clients can submit the retired key,
        # but it is not a model field, effective setting, or stored limit.
        if isinstance(values, dict):
            return {key: value for key, value in values.items() if key != "daily_limit"}
        return values


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    count: int = Field(default=1, ge=1, le=100)
    browser_mode: Literal["headed", "headless"] | None = None


class RetryFailedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    browser_mode: Literal["headed", "headless"] | None = None

    @field_validator("browser_mode", mode="before")
    @classmethod
    def explicit_mode_is_not_null(cls, value):
        if value is None:
            raise ValueError("浏览器模式只能是 headed 或 headless")
        return value


def _authorize(request):
    from api.gpt_plans import _require_plan_security_setup_access
    _require_plan_security_setup_access(request)


def _mutate(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    preparation_runtime.wake()
    return result


@router.get("/status")
def status():
    value = store.snapshot()
    value["runtime"].update(preparation_runtime.status())
    return value


@router.put("/settings")
def settings(body: SettingsRequest, request: Request):
    _authorize(request)
    return _mutate(store.save_settings, body.model_dump())


@router.post("/run")
def run(body: RunRequest, request: Request):
    _authorize(request)
    return _mutate(store.enqueue, body.count, browser_mode=body.browser_mode)


@router.get("/accounts")
def accounts(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), keyword: str | None = None):
    return store.list_accounts(page, page_size, keyword)


@router.get("/jobs")
def jobs(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), status: str | None = None, keyword: str | None = None):
    return store.list_jobs(page, page_size, status, keyword)


@router.post("/jobs/retry-failed")
def retry_failed(body: RetryFailedRequest, request: Request):
    _authorize(request)
    return _mutate(store.retry_failed_jobs, browser_mode=body.browser_mode)


@router.get("/jobs/{job_id}")
def job(job_id: str):
    result = store.get_job(job_id)
    if result is None:
        raise HTTPException(404, "准备任务不存在")
    return result


@router.post("/jobs/{job_id}/retry")
def retry(job_id: str, request: Request):
    _authorize(request)
    return _mutate(store.retry_job, job_id)


@router.post("/accounts/{account_id}/check-cookie")
def check_cookie(account_id: int, request: Request):
    _authorize(request)
    return _mutate(store.enqueue_cookie_check, account_id)
