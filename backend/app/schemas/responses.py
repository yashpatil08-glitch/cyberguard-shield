"""Loose response envelopes. Analyser outputs are passed through verbatim
as ``dict`` so the existing Python schemas remain the source of truth."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str


class AnalysisResponse(BaseModel):
    """Wrapper that simply forwards the analyser dict."""

    result: dict[str, Any]