"""CyberGuard FastAPI entry point.

Run locally:
    uvicorn app.main:app --reload

Run on Render:
    uvicorn app.main:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .core.config import settings
from .core.errors import register_exception_handlers
from .core.logging import configure_logging
from .routers import headers as headers_router
from .routers import health as health_router
from .routers import password as password_router
from .routers import phishing as phishing_router
from .routers import report as report_router
from .routers import url as url_router

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=settings.description,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# --- Middleware -----------------------------------------------------------
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=86400,
)

# --- Error handlers -------------------------------------------------------
register_exception_handlers(app)

# --- Routes ---------------------------------------------------------------
app.include_router(health_router.router)
app.include_router(url_router.router)
app.include_router(password_router.router)
app.include_router(headers_router.router)
app.include_router(phishing_router.router)
app.include_router(report_router.router)


@app.get("/", tags=["meta"])
def root() -> dict:
    return {
        "service": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
        "health": "/api/health",
        "endpoints": [
            "POST /api/url-check",
            "POST /api/password-strength",
            "POST /api/security-headers",
            "POST /api/phishing-detect",
            "POST /api/report",
            "GET  /api/health",
        ],
    }


@app.on_event("startup")
async def _on_startup() -> None:
    logger.info(
        "%s v%s starting (env=%s, cors=%s)",
        settings.app_name,
        settings.version,
        settings.environment,
        settings.cors_origins,
    )