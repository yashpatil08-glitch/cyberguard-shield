"""Pydantic request models. Lightweight — heavy validation lives in
backend.utils.validators and runs inside each analyser."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyse")


class PasswordRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=4096)


class HeadersRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class PhishingRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


ReportType = Literal["url", "password", "headers", "phishing"]


class ReportRequest(BaseModel):
    kind: ReportType = Field(default="url", description="Report flavour")
    title: str | None = Field(default=None, max_length=200)
    target: str | None = Field(default=None, max_length=4096)
    data: dict[str, Any] = Field(..., description="Raw analyser output dict")