"""Dependency-injection providers for the analyser services.

Each analyser is a stateless object — we cache one instance per process and
hand it out via FastAPI's `Depends(...)` so routers stay thin and testable.
The uploaded Python business logic is NOT modified; we only wrap it.
"""
from __future__ import annotations

from functools import lru_cache

from backend.services.password_strength import PasswordStrengthAnalyzer
from backend.services.pdf_generator import PDFGenerator
from backend.services.phishing_detector import PhishingDetector
from backend.services.security_headers import SecurityHeadersChecker
from backend.services.url_analyzer import URLAnalyzer


@lru_cache(maxsize=1)
def get_url_analyzer() -> URLAnalyzer:
    return URLAnalyzer()


@lru_cache(maxsize=1)
def get_password_analyzer() -> PasswordStrengthAnalyzer:
    return PasswordStrengthAnalyzer()


@lru_cache(maxsize=1)
def get_headers_checker() -> SecurityHeadersChecker:
    return SecurityHeadersChecker()


@lru_cache(maxsize=1)
def get_phishing_detector() -> PhishingDetector:
    return PhishingDetector()


@lru_cache(maxsize=1)
def get_pdf_generator() -> PDFGenerator:
    return PDFGenerator()