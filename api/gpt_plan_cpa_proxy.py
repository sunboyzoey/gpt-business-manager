"""GPT 套餐管理专属的 CPA/SUB 凭证代理池 API。"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import gpt_plan_cpa_proxy_pool as pool


router = APIRouter(prefix="/cpa-proxy", tags=["gpt-plan-cpa-proxy"])


class ImportRequest(BaseModel):
    data: str


class UpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    note: Optional[str] = None
    max_accounts: Optional[int] = None


@router.get("/proxies")
def list_proxies():
    return {"items": pool.list_proxies(), "stats": pool.stats()}


@router.get("/stats")
def stats():
    return pool.stats()


@router.post("/proxies/import")
def import_proxies(body: ImportRequest):
    if not (body.data or "").strip():
        raise HTTPException(400, "导入内容为空")
    return pool.import_proxies(body.data)


@router.put("/proxies/{proxy_id}")
def update_proxy(proxy_id: int, body: UpdateRequest):
    if not pool.update_proxy(
        proxy_id,
        enabled=body.enabled,
        note=body.note,
        max_accounts=body.max_accounts,
    ):
        raise HTTPException(404, "代理不存在")
    return {"ok": True}


@router.delete("/proxies/{proxy_id}")
def delete_proxy(proxy_id: int):
    if not pool.delete_proxy(proxy_id):
        raise HTTPException(404, "代理不存在")
    return {"ok": True}
