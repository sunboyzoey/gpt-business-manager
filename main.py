"""Standalone Gmail child accounts and BUSINESS workspace manager."""
from bootstrap import ROOT, configure

RUNTIME = configure()

import asyncio
import importlib
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


@asynccontextmanager
async def lifespan(app):
    from core.db import engine
    from sqlmodel import SQLModel
    from services.gmail_store import init_tables as gmail_tables
    from services.gmail_app_password_store import init_tables as password_tables
    from services.nv_automation_store import init_tables as nv_tables
    from services.gpt_plan_preparation_store import init_tables as preparation_tables
    from services.device_hosting_store import init_tables as hosting_tables
    from services.nv_price_batch import init_tables as pricing_tables
    from services.prepared_batch_invite_store import init_tables as prepared_batch_tables
    from services.business_child_batch_action_store import init_tables as child_batch_action_tables
    from services.sms_gateway import init_tables as sms_tables
    from core.config_store import config_store
    from core.proxy_pool import init_proxy_health
    # This project begins with the current schema. Parent-project historical
    # cutover migrations are deliberately not replayed against this database.
    SQLModel.metadata.create_all(engine)
    init_proxy_health()
    for init in (gmail_tables, password_tables, nv_tables, preparation_tables, hosting_tables, pricing_tables, prepared_batch_tables, child_batch_action_tables, sms_tables):
        init()
    # Only defaults for this empty installation; no parent config/database is read.
    for key, value in {
        "mail_provider": "gmail", "business_invite_default_mail_provider": "gmail",
        "business_invite_prolite_mail_provider": "gmail", "chatgpt_security_after_register": "true",
        "scheduler_cpa_maintenance_enabled": "0", "scheduler_device_maintenance_enabled": "0",
        "default_executor": "headless",
    }.items():
        if not config_store.get(key, ""):
            config_store.set(key, value)
    importlib.import_module("platforms.chatgpt.plugin")
    from services.gmail_registration_runtime import gmail_registration_runtime
    from services.gmail_app_password_runtime import gmail_app_password_runtime
    from services.sms_balance_monitor import sms_balance_monitor
    gmail_registration_runtime.start()
    gmail_app_password_runtime.start()
    sms_balance_monitor.start()
    from api.gpt_plans import resume_prepared_business_batch_invite_tasks
    resume_prepared_business_batch_invite_tasks()
    from api.gpt_plans import resume_business_child_batch_action_tasks
    resume_business_child_batch_action_tasks()
    app.state.ready = True
    yield
    app.state.ready = False
    gmail_registration_runtime.stop()
    sms_balance_monitor.stop()
    await asyncio.to_thread(gmail_app_password_runtime.stop, 20)
    from services.gmail_import_jobs import shutdown_jobs
    await asyncio.to_thread(shutdown_jobs, 40)


api_docs_enabled = str(os.getenv("GBM_ENABLE_API_DOCS", "0")).strip().lower() in {
    "1", "true", "yes", "on",
}
app = FastAPI(
    title="Gmail BUSINESS Manager",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if api_docs_enabled else None,
    redoc_url="/redoc" if api_docs_enabled else None,
    openapi_url="/openapi.json" if api_docs_enabled else None,
)


@app.middleware("http")
async def authentication(request: Request, call_next):
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/auth/"):
        from core.config_store import config_store
        if not config_store.get("auth_password_hash", ""):
            return JSONResponse(
                {"detail": "请先初始化管理员密码", "code": "admin_setup_required"},
                status_code=403,
            )
        from api.auth import request_token, verify_token
        token = request_token(request)
        try:
            verify_token(token)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "object-src 'none'; form-action 'self'; img-src 'self' data:; "
        "font-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'"
    )
    if str(os.getenv("GBM_COOKIE_SECURE", "")).strip().lower() in {"1", "true", "yes", "on"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Bundled implementations run against this project's database. No HTTP calls to
# the old manager are used. Compatibility reads support the mature mother UI.
for module in (
    "auth", "gmail", "gpt_plans", "tasks", "config", "proxies", "gpt_plan_preparation",
    "workspace", "workspace_mothers",
    "business_manager_transfer",
    "sms", "smsbower",
):
    app.include_router(importlib.import_module("api." + module).router, prefix="/api")
from api.gpt_pro import shared_upgrade_config_router
app.include_router(shared_upgrade_config_router, prefix="/api")


@app.get("/healthz")
def health():
    return {"ok": bool(getattr(app.state, "ready", False)), "project": "gmail-business-manager"}


static = ROOT / "static"
if (static / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str):
    if path == "api" or path.startswith("api/"):
        raise HTTPException(404, "API endpoint not found")
    if not api_docs_enabled and path in {"docs", "redoc", "openapi.json"}:
        raise HTTPException(404, "API documentation is disabled")
    index = static / "index.html"
    if not index.exists():
        raise HTTPException(503, "请先执行前端构建：cd frontend && npm ci && npm run build")
    return FileResponse(index, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("GBM_HOST", "127.0.0.1"),
                port=int(os.getenv("GBM_PORT", "8011")), reload=os.getenv("GBM_RELOAD") == "1")
