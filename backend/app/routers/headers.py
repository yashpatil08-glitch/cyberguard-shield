from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.services.security_headers import SecurityHeadersChecker

from ..core.dependencies import get_headers_checker
from ..schemas.requests import HeadersRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["headers"])


@router.post("/security-headers")
def check_headers(
    payload: HeadersRequest,
    checker: SecurityHeadersChecker = Depends(get_headers_checker),
) -> dict:
    try:
        return checker.check(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("Headers check failed")
        raise HTTPException(status_code=500, detail=f"Headers check failed: {e}")