from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlmodel import Session, select
from pydantic import BaseModel
from typing import Optional
from core.db import ProxyModel, get_session
from core.proxy_pool import ProxyHealth, proxy_health_fields, proxy_pool, validate_proxy_url

router = APIRouter(prefix="/proxies", tags=["proxies"])


class ProxyCreate(BaseModel):
    url: str
    region: str = ""


class ProxyBulkCreate(BaseModel):
    proxies: list[str]
    region: str = ""


@router.get("")
def list_proxies(session: Session = Depends(get_session)):
    items = session.exec(select(ProxyModel)).all()
    health = {row.proxy_id: row for row in session.exec(select(ProxyHealth)).all()}
    return [{**item.model_dump(), **proxy_health_fields(item, health.get(item.id))} for item in items]


@router.get("/registration-options")
def registration_proxy_options():
    from services.registration_proxy import list_registration_proxy_options
    return list_registration_proxy_options()


@router.post("")
def add_proxy(body: ProxyCreate, session: Session = Depends(get_session)):
    try:
        url = validate_proxy_url(body.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    p = ProxyModel(url=url, region=body.region)
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


@router.post("/bulk")
def bulk_add_proxies(body: ProxyBulkCreate, session: Session = Depends(get_session)):
    added = 0
    skipped = 0
    for url in body.proxies:
        try:
            url = validate_proxy_url(url)
        except ValueError:
            skipped += 1
            continue
        session.add(ProxyModel(url=url, region=body.region))
        added += 1
    session.commit()
    return {"added": added, "skipped": skipped}


@router.delete("/{proxy_id}")
def delete_proxy(proxy_id: int, session: Session = Depends(get_session)):
    p = session.get(ProxyModel, proxy_id)
    if not p:
        raise HTTPException(404, "代理不存在")
    health = session.get(ProxyHealth, proxy_id)
    if health:
        session.delete(health)
    session.delete(p)
    session.commit()
    return {"ok": True}


@router.patch("/{proxy_id}/toggle")
def toggle_proxy(proxy_id: int, session: Session = Depends(get_session)):
    p = session.get(ProxyModel, proxy_id)
    if not p:
        raise HTTPException(404, "代理不存在")
    p.is_active = not p.is_active
    session.add(p)
    session.commit()
    return {"is_active": p.is_active}


@router.post("/check")
def check_proxies(background_tasks: BackgroundTasks):
    status = proxy_pool.prepare_check()
    if status.pop("started"):
        background_tasks.add_task(proxy_pool.check_all, job_id=status["job_id"])
    return {**status, "message": "检测任务已启动"}


@router.get("/check-status")
def check_status():
    return proxy_pool.get_check_status()


# ── 代理订阅池管理 (mihomo) ──

@router.get("/subscription/status")
def subscription_status():
    from services.proxy_pool import (
        is_mihomo_installed, is_mihomo_running, get_pool, get_nodes, get_test_status,
    )
    return {
        "installed": is_mihomo_installed(),
        "running": is_mihomo_running(),
        "pool": get_pool(),
        "pool_size": len(get_pool()),
        "nodes": get_nodes(),
        "test": get_test_status(),
    }


class SubscriptionUpdateRequest(BaseModel):
    url: str = ""


@router.post("/subscription/update")
def subscription_update(body: SubscriptionUpdateRequest):
    from services.proxy_pool import update_subscription
    url = body.url.strip() if body.url else ""
    if url:
        from core.config_store import config_store
        config_store.set_many({"proxy_subscription_url": url})
    result = update_subscription(url)
    return result


@router.post("/subscription/setup")
def subscription_setup():
    from services.proxy_pool import ensure_mihomo
    return ensure_mihomo()


@router.post("/subscription/test-nodes")
def subscription_test_nodes():
    from services.proxy_pool import test_nodes_async
    return test_nodes_async()


@router.get("/subscription/test-status")
def subscription_test_status():
    from services.proxy_pool import get_test_status
    return get_test_status()


@router.get("/subscription/pool")
def subscription_pool():
    from services.proxy_pool import get_pool
    return {"pool": get_pool()}


@router.post("/subscription/test-chatgpt-protocol-nodes")
def subscription_test_chatgpt_protocol_nodes():
    from services.proxy_pool import test_chatgpt_protocol_nodes_async
    return test_chatgpt_protocol_nodes_async()


@router.get("/subscription/chatgpt-protocol-status")
def subscription_chatgpt_protocol_status():
    from services.proxy_pool import get_chatgpt_protocol_test_status
    return get_chatgpt_protocol_test_status()


@router.get("/subscription/chatgpt-protocol-pool")
def subscription_chatgpt_protocol_pool(
    refresh: bool = Query(False),
    max_age_seconds: int = Query(600, ge=0, le=86400),
):
    from services.proxy_pool import get_chatgpt_protocol_pool
    return get_chatgpt_protocol_pool(
        refresh=refresh,
        max_age_seconds=max_age_seconds,
    )
