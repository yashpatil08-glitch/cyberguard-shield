from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.services.url_analyzer import URLAnalyzer

from ..core.dependencies import get_url_analyzer
from ..schemas.requests import URLRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["url"])


@router.post("/url-check")
def analyze_url(
    payload: URLRequest,
    analyzer: URLAnalyzer = Depends(get_url_analyzer),
) -> dict:
    try:
        return analyzer.analyze(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("URL analysis failed")
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {e}")