from __future__ import annotations

from fastapi import APIRouter

from ..core.config import settings
from ..schemas.responses import HealthResponse

router = APIRouter(tags=["meta"])


@router.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.version,
        environment=settings.environment,
    )