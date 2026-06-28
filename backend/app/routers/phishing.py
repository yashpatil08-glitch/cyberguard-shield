from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.services.phishing_detector import PhishingDetector

from ..core.dependencies import get_phishing_detector
from ..schemas.requests import PhishingRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["phishing"])


@router.post("/phishing-detect")
def detect_phishing(
    payload: PhishingRequest,
    detector: PhishingDetector = Depends(get_phishing_detector),
) -> dict:
    try:
        return detector.detect(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("Phishing detection failed")
        raise HTTPException(status_code=500, detail=f"Phishing detection failed: {e}")