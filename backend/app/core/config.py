"""Runtime configuration for the CyberGuard FastAPI service."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "CyberGuard API"
    version: str = "1.0.0"
    description: str = (
        "FastAPI wrapper around the CyberGuard Python security modules: "
        "URL analysis, password strength, security headers, phishing detection, "
        "and PDF report generation."
    )
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "production"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    # Comma-separated origins; "*" allows any (use a specific origin in prod).
    cors_origins: list[str] = field(
        default_factory=lambda: _csv_env("CORS_ORIGINS", "*")
    )
    request_timeout: int = field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "10")))


settings = Settings()