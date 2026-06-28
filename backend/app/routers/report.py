from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from backend.services.pdf_generator import PDFGenerator

from ..core.dependencies import get_pdf_generator
from ..schemas.requests import ReportRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["report"])

_TITLES = {
    "url": "URL Security Report",
    "password": "Password Strength Report",
    "headers": "Security Headers Report",
    "phishing": "Phishing Risk Report",
}


@router.post(
    "/report",
    responses={200: {"content": {"application/pdf": {}}}},
)
def generate_report(
    payload: ReportRequest,
    generator: PDFGenerator = Depends(get_pdf_generator),
) -> Response:
    try:
        pdf_bytes = generator.generate(
            scan_data=payload.data,
            report_type=payload.kind,
            title=payload.title or _TITLES.get(payload.kind, "Security Report"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("PDF generation failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"cyberguard-{payload.kind}-{stamp}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )