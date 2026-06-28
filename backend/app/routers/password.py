from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.services.password_strength import PasswordStrengthAnalyzer

from ..core.dependencies import get_password_analyzer
from ..schemas.requests import PasswordRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["password"])


@router.post("/password-strength")
def analyze_password(
    payload: PasswordRequest,
    analyzer: PasswordStrengthAnalyzer = Depends(get_password_analyzer),
) -> dict:
    try:
        return analyzer.analyze(payload.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("Password analysis failed")
        raise HTTPException(status_code=500, detail=f"Password analysis failed: {e}")