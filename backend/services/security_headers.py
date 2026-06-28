"""
backend/services/security_headers.py

HTTP Security Headers Checker for CyberGuard.
Fetches response headers from a URL and evaluates the presence,
correctness, and strength of all major security headers.
"""

import logging
import urllib.request
from urllib.error import URLError, HTTPError

from backend.utils.constants import (
    SECURITY_HEADER_WEIGHTS,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
)
from backend.utils.validators import validate_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Header analysis configuration
# ---------------------------------------------------------------------------

# Expected / recommended values for quick correctness checks.
# `check_fn` is stored as a function name (string) and resolved lazily in
# `check()` to avoid forward-reference NameErrors at import time.
_HEADER_GUIDANCE: dict[str, dict] = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections for a specified duration.",
        "recommended": "max-age=31536000; includeSubDomains",
        "check_fn": "_check_hsts",
    },
    "Content-Security-Policy": {
        "description": "Restricts sources for scripts, styles, and other resources.",
        "recommended": "default-src 'self'",
        "check_fn": "_check_csp",
    },
    "X-Frame-Options": {
        "description": "Prevents the page from being embedded in an iframe (clickjacking).",
        "recommended": "DENY or SAMEORIGIN",
        "check_fn": "_check_x_frame",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing by the browser.",
        "recommended": "nosniff",
        "check_fn": "_check_xcto",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is included in requests.",
        "recommended": "strict-origin-when-cross-origin",
        "check_fn": "_check_referrer",
    },
    "Permissions-Policy": {
        "description": "Controls access to browser features like camera, microphone, geolocation.",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "check_fn": "_check_permissions",
    },
}


class SecurityHeadersChecker:
    """
    Checks HTTP security response headers for a given URL.

    Usage:
        checker = SecurityHeadersChecker()
        result = checker.check("https://example.com")
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, url: str) -> dict:
        """
        Fetch the URL and evaluate its security headers.

        Args:
            url: Full URL string (http/https).

        Returns:
            JSON-compatible dict with keys:
                - url          (str)
                - score        (int): 0–100
                - risk_level   (str): "Low" | "Medium" | "High" | "Critical"
                - grade        (str): A–F letter grade
                - headers_found(dict): raw header values from the response
                - findings     (list[dict]): per-header analysis results
                - recommendations(list[str])
                - error        (str | None)
        """
        result: dict = {
            "url": url,
            "score": 0,
            "risk_level": "Critical",
            "grade": "F",
            "headers_found": {},
            "findings": [],
            "recommendations": [],
            "error": None,
        }

        # Validate URL
        validation = validate_url(url)
        if not validation["valid"]:
            result["error"] = validation["error"]
            return result

        # Fetch headers
        raw_headers, error = _fetch_headers(url, self.timeout)
        if error:
            result["error"] = error
            return result

        # Normalise to lowercase keys for case-insensitive matching
        lower_headers = {k.lower(): v for k, v in raw_headers.items()}
        result["headers_found"] = dict(raw_headers)

        # Evaluate each security header
        total_score = 0
        findings: list[dict] = []
        recommendations: list[str] = []

        for header_name, weight in SECURITY_HEADER_WEIGHTS.items():
            lower_key = header_name.lower()
            value = lower_headers.get(lower_key)
            guidance = _HEADER_GUIDANCE.get(header_name, {})
            _fn_name = guidance.get("check_fn")
            check_fn = globals().get(_fn_name) if isinstance(_fn_name, str) else _fn_name

            if value is None:
                # Header missing
                finding = {
                    "header": header_name,
                    "present": False,
                    "value": None,
                    "score": 0,
                    "max_score": weight,
                    "status": "missing",
                    "note": f"{header_name} is not set.",
                    "description": guidance.get("description", ""),
                    "recommended": guidance.get("recommended", ""),
                }
                rec = f"Add the '{header_name}' header. Recommended: {guidance.get('recommended', 'see OWASP guidelines')}."
                recommendations.append(rec)
            else:
                # Header present — check value quality
                quality_score, note = check_fn(value, weight) if check_fn else (weight, "Present.")
                total_score += quality_score
                finding = {
                    "header": header_name,
                    "present": True,
                    "value": value,
                    "score": quality_score,
                    "max_score": weight,
                    "status": "good" if quality_score >= weight else "weak",
                    "note": note,
                    "description": guidance.get("description", ""),
                    "recommended": guidance.get("recommended", ""),
                }
                if quality_score < weight:
                    recommendations.append(
                        f"Strengthen '{header_name}': {note} Recommended value: {guidance.get('recommended', '')}."
                    )

            findings.append(finding)

        result["score"] = total_score
        result["risk_level"] = _score_to_risk(total_score)
        result["grade"] = _score_to_grade(total_score)
        result["findings"] = findings
        result["recommendations"] = recommendations
        return result


# ---------------------------------------------------------------------------
# Header-Specific Check Functions
# ---------------------------------------------------------------------------

def _check_hsts(value: str, max_score: int) -> tuple[int, str]:
    """Validate Strict-Transport-Security value."""
    value_lower = value.lower()
    score = 0
    notes = []

    if "max-age" in value_lower:
        try:
            max_age = int(re.search(r'max-age=(\d+)', value_lower).group(1))
            if max_age >= 31536000:
                score += int(max_score * 0.6)
                notes.append("max-age is sufficient (≥1 year).")
            elif max_age >= 86400:
                score += int(max_score * 0.3)
                notes.append(f"max-age={max_age} is set but less than 1 year.")
            else:
                notes.append(f"max-age={max_age} is very short.")
        except (AttributeError, ValueError):
            notes.append("max-age could not be parsed.")
    else:
        notes.append("max-age is missing.")

    if "includesubdomains" in value_lower:
        score += int(max_score * 0.3)
        notes.append("includeSubDomains is set.")
    else:
        notes.append("includeSubDomains is not set.")

    if "preload" in value_lower:
        score += int(max_score * 0.1)

    return min(score, max_score), " ".join(notes)


def _check_csp(value: str, max_score: int) -> tuple[int, str]:
    """Validate Content-Security-Policy value."""
    value_lower = value.lower()
    score = 0
    notes = []

    if "default-src" in value_lower:
        score += int(max_score * 0.4)
        notes.append("default-src is defined.")
    else:
        notes.append("default-src is missing — a fallback directive should be set.")

    if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
        notes.append("'unsafe-inline' or 'unsafe-eval' weakens the CSP significantly.")
    else:
        score += int(max_score * 0.4)
        notes.append("No unsafe-inline/eval detected.")

    if "script-src" in value_lower:
        score += int(max_score * 0.2)
        notes.append("script-src is defined.")

    return min(score, max_score), " ".join(notes)


def _check_x_frame(value: str, max_score: int) -> tuple[int, str]:
    """Validate X-Frame-Options value."""
    value_upper = value.strip().upper()
    if value_upper in ("DENY", "SAMEORIGIN"):
        return max_score, f"X-Frame-Options is set to '{value_upper}' — correct."
    if "ALLOW-FROM" in value_upper:
        return int(max_score * 0.5), "ALLOW-FROM is deprecated; prefer CSP frame-ancestors."
    return int(max_score * 0.2), f"Unrecognised value '{value}'. Use DENY or SAMEORIGIN."


def _check_xcto(value: str, max_score: int) -> tuple[int, str]:
    """Validate X-Content-Type-Options value."""
    if value.strip().lower() == "nosniff":
        return max_score, "X-Content-Type-Options: nosniff — correct."
    return int(max_score * 0.2), f"Unexpected value '{value}'. Should be 'nosniff'."


def _check_referrer(value: str, max_score: int) -> tuple[int, str]:
    """Validate Referrer-Policy value."""
    safe_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
    }
    unsafe_values = {"unsafe-url", ""}
    value_lower = value.strip().lower()
    if value_lower in safe_values:
        return max_score, f"Referrer-Policy '{value}' is acceptable."
    if value_lower in unsafe_values:
        return 0, f"Referrer-Policy '{value}' leaks full URLs — change immediately."
    return int(max_score * 0.5), f"Referrer-Policy '{value}' may need review."


def _check_permissions(value: str, max_score: int) -> tuple[int, str]:
    """Validate Permissions-Policy value."""
    # A non-empty value is better than nothing
    if not value.strip():
        return 0, "Permissions-Policy is empty."
    restrictive_features = ["geolocation=()", "microphone=()", "camera=()"]
    count = sum(1 for feat in restrictive_features if feat in value.lower())
    score = int(max_score * (count / len(restrictive_features)))
    note = f"{count}/{len(restrictive_features)} key features restricted."
    return score, note


# ---------------------------------------------------------------------------
# Network Helper
# ---------------------------------------------------------------------------

import re  # noqa: E402  (needed inside check functions above)


def _fetch_headers(url: str, timeout: int) -> tuple[dict, str | None]:
    """
    Perform an HTTP HEAD request and return the response headers.

    Falls back to a GET request if HEAD is not allowed (405).

    Args:
        url:     Target URL.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (headers_dict, error_string_or_None).
    """
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return dict(resp.headers), None
        except HTTPError as exc:
            if exc.code == 405 and method == "HEAD":
                continue  # retry with GET
            return {}, f"HTTP {exc.code}: {exc.reason}"
        except URLError as exc:
            return {}, f"Connection error: {exc.reason}"
        except Exception as exc:
            return {}, f"Unexpected error: {exc}"

    return {}, "Failed to retrieve headers via HEAD and GET."


# ---------------------------------------------------------------------------
# Score Helpers
# ---------------------------------------------------------------------------

def _score_to_risk(score: int) -> str:
    if score >= 80:
        return "Low"
    if score >= 50:
        return "Medium"
    if score >= 25:
        return "High"
    return "Critical"


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
