"""smsbower 测试 API 路由(供前端 / curl 验证用)。

config_store 里读取 `smsbower_api_key`(必填) 和 `smsbower_proxy`(可选);
也允许通过请求体 / query 临时覆盖 api_key 和 proxy。

端点(全部挂 /api/smsbower):
  GET  /balance                              查余额
  GET  /balance-status                       读取后台定时查询的余额缓存
  POST /get-number   {service?,country?,max_price?,api_key?,proxy?}
  POST /status      {id}                    查 SMS 状态
  POST /cancel-number {id}                  取消(2 分钟内会拒)
  POST /confirm     {id}                    确认完成(终态)
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.config_store import config_store
from core.secret_store import get_secret
from platforms.chatgpt.smsbower_client import (
    DEFAULT_COUNTRY,
    DEFAULT_MAX_PRICE,
    DEFAULT_SERVICE,
    SmsbowerClient,
    SmsbowerError,
)


router = APIRouter(prefix="/smsbower", tags=["smsbower"])


def _build_client(api_key_override: Optional[str] = None,
                  proxy_override: Optional[str] = None) -> SmsbowerClient:
    api_key = (api_key_override or "").strip() or get_secret("sms_smsbower_api_key") or get_secret("smsbower_api_key")
    if not api_key:
        raise HTTPException(400, "未配置 smsbower_api_key,请在全局配置里填或 body 里传 api_key")
    proxy = (proxy_override or "").strip() or str(
        config_store.get("smsbower_proxy", "") or ""
    ).strip()
    base_url = str(config_store.get("smsbower_base_url", "") or "").strip()
    if base_url:
        return SmsbowerClient(api_key=api_key, base_url=base_url, proxy=(proxy or None))
    return SmsbowerClient(api_key=api_key, proxy=(proxy or None))


def _err_to_http(exc: SmsbowerError) -> HTTPException:
    code = exc.code
    if code == "BAD_KEY":
        return HTTPException(401, f"api_key 不正确: {exc.raw}")
    if code == "NO_BALANCE":
        return HTTPException(402, "smsbower 余额不足")
    if code == "NO_NUMBERS":
        return HTTPException(404, "该 service+country+maxPrice 当前没有可用号码")
    if code == "NO_ACTIVATION":
        return HTTPException(404, "activation id 不存在或已过期")
    if code == "EARLY_CANCEL_DENIED":
        return HTTPException(409, "取号后 2 分钟内不允许取消")
    if code == "BANNED":
        return HTTPException(403, f"账号被封禁: {exc.raw}")
    return HTTPException(502, f"smsbower {code}: {exc.raw}")


class GetNumberRequest(BaseModel):
    service: Optional[str] = Field(default=None, description="服务码,默认走全局配置 → dr=OpenAI(ChatGPT)")
    country: Optional[str] = Field(default=None, description="国家码,默认走全局配置 → 39=Argentina")
    max_price: Optional[str] = Field(default=None, description="最高价(USD),默认走全局配置 → 0.08")
    api_key: Optional[str] = None
    proxy: Optional[str] = None


class IdOnlyRequest(BaseModel):
    id: str
    api_key: Optional[str] = None
    proxy: Optional[str] = None


def _resolve_defaults(body: GetNumberRequest) -> tuple[str, str, str]:
    service = (body.service or "").strip() or str(
        config_store.get("smsbower_service", "") or ""
    ).strip() or DEFAULT_SERVICE
    country = (body.country or "").strip() or str(
        config_store.get("smsbower_country", "") or ""
    ).strip() or DEFAULT_COUNTRY
    max_price = (body.max_price or "").strip() or str(
        config_store.get("smsbower_max_price", "") or ""
    ).strip() or DEFAULT_MAX_PRICE
    return service, country, max_price


@router.get("/balance")
def smsbower_balance(api_key: Optional[str] = None, proxy: Optional[str] = None):
    client = _build_client(api_key, proxy)
    try:
        return {"balance": client.balance()}
    except SmsbowerError as e:
        raise _err_to_http(e)


@router.get("/balance-status")
def smsbower_balance_status():
    from services.sms_balance_monitor import sms_balance_monitor
    return sms_balance_monitor.snapshot()


@router.post("/get-number")
def smsbower_get_number(body: GetNumberRequest):
    client = _build_client(body.api_key, body.proxy)
    service, country, max_price = _resolve_defaults(body)
    try:
        return client.get_number(
            service=service,
            country=country,
            max_price=max_price,
        )
    except SmsbowerError as e:
        raise _err_to_http(e)


@router.post("/status")
def smsbower_status(body: IdOnlyRequest):
    client = _build_client(body.api_key, body.proxy)
    try:
        return client.get_status(body.id)
    except SmsbowerError as e:
        raise _err_to_http(e)


@router.post("/cancel-number")
def smsbower_cancel_number(body: IdOnlyRequest):
    client = _build_client(body.api_key, body.proxy)
    try:
        result = client.cancel(body.id)
        return {"ok": True, "raw": result}
    except SmsbowerError as e:
        raise _err_to_http(e)


@router.post("/confirm")
def smsbower_confirm(body: IdOnlyRequest):
    client = _build_client(body.api_key, body.proxy)
    try:
        result = client.confirm(body.id)
        return {"ok": True, "raw": result}
    except SmsbowerError as e:
        raise _err_to_http(e)
