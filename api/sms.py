"""Provider-neutral SMS configuration and activation API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services import sms_gateway

router = APIRouter(prefix="/sms", tags=["sms"])


class ProviderConfig(BaseModel):
    api_key: str | None = None
    base_url: str = ""
    proxy: str = ""


class AcquireRequest(BaseModel):
    provider: str
    service: str = "dr"
    country: str = "187"
    max_price: str = Field(default="0.16", pattern=r"^\d+(?:\.\d{1,4})?$")


@router.get("/providers")
def list_providers():
    return {"items": sms_gateway.providers()}


@router.put("/providers/{code}")
def save_provider(code: str, body: ProviderConfig):
    try:
        return sms_gateway.configure_provider(
            code, api_key=body.api_key, base_url=body.base_url, proxy=body.proxy
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.post("/providers/{code}/test")
def test_provider(code: str):
    try:
        return {"ok": True, "balance": sms_gateway.provider(code).balance()}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        raise HTTPException(502, "短信供应商连接或鉴权失败") from None


@router.post("/activations")
def acquire_number(body: AcquireRequest):
    try:
        return sms_gateway.acquire(
            body.provider, service=body.service, country=body.country, max_price=body.max_price
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        raise HTTPException(502, "取号失败，请检查供应商余额、库存和连接") from None


@router.get("/activations")
def activations(limit: int = 100):
    return {"items": sms_gateway.list_activations(limit)}


@router.post("/activations/{activation_id}/refresh")
def refresh_activation(activation_id: int):
    try:
        return sms_gateway.refresh(activation_id)
    except KeyError:
        raise HTTPException(404, "短信激活记录不存在") from None
    except Exception:
        raise HTTPException(502, "短信状态查询失败") from None


@router.post("/activations/{activation_id}/{action}")
def finish_activation(activation_id: int, action: str):
    try:
        return sms_gateway.finish(activation_id, action)
    except KeyError:
        raise HTTPException(404, "短信激活记录不存在") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        raise HTTPException(502, "短信终态提交失败") from None
