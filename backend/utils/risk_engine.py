"""
backend/utils/risk_engine.py

Reusable risk scoring engine for CyberGuard.
Every analyser module (URL, phishing, headers, etc.) must use this engine
to produce consistent, normalised risk scores and recommendations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from backend.utils.constants import RISK_MAX_SCORE, RISK_THRESHOLDS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class RiskFinding:
    """A single risk finding contributed by an analyser."""
    label: str          # Short identifier, e.g. "ip_in_url"
    description: str    # Human-readable explanation
    score: int          # Risk score contribution (0–100)
    severity: str = ""  # Populated automatically by the engine


# ---------------------------------------------------------------------------
# Risk Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Accumulates risk findings, calculates a normalised score (0–100),
    assigns a risk level, and produces ordered recommendations.

    Usage:
        engine = RiskEngine()
        engine.add_risk("ip_in_url", "IP address used instead of domain", 30)
        engine.add_risk("missing_https", "No HTTPS encryption", 10)
        result = engine.calculate_score()
    """

    def __init__(self) -> None:
        self._findings: list[RiskFinding] = []
        self._recommendations: list[str] = []
        self._raw_score: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_risk(self, label: str, description: str, score: int) -> None:
        """
        Register a risk finding.

        Args:
            label:       Short machine-readable identifier.
            description: Human-readable explanation of the risk.
            score:       Raw score contribution (clamped to 0–100).
        """
        score = max(0, min(score, RISK_MAX_SCORE))
        severity = _score_to_severity(score)
        finding = RiskFinding(
            label=label,
            description=description,
            score=score,
            severity=severity,
        )
        self._findings.append(finding)
        self._raw_score += score
        logger.debug("Risk added: %s (+%d) → raw total %d", label, score, self._raw_score)

    def add_recommendation(self, recommendation: str) -> None:
        """
        Add a human-readable recommendation string.

        Args:
            recommendation: Recommendation text to include in the report.
        """
        if recommendation and recommendation not in self._recommendations:
            self._recommendations.append(recommendation)

    def calculate_score(self) -> dict:
        """
        Compute the final normalised risk score and return a full result dict.

        Returns:
            dict with keys:
                - score       (int):   Normalised score 0–100
                - raw_score   (int):   Accumulated raw score (may exceed 100)
                - risk_level  (str):   "Low" | "Medium" | "High" | "Critical"
                - findings    (list):  List of RiskFinding dicts
                - recommendations (list): Ordered recommendation strings
        """
        normalised = min(self._raw_score, RISK_MAX_SCORE)
        risk_level = get_risk_level(normalised)

        # Sort findings by score descending (highest risk first)
        sorted_findings = sorted(
            self._findings, key=lambda f: f.score, reverse=True
        )

        return {
            "score": normalised,
            "raw_score": self._raw_score,
            "risk_level": risk_level,
            "findings": [_finding_to_dict(f) for f in sorted_findings],
            "recommendations": list(self._recommendations),
        }

    def reset(self) -> None:
        """Clear all accumulated findings and recommendations."""
        self._findings.clear()
        self._recommendations.clear()
        self._raw_score = 0

    @property
    def finding_labels(self) -> set[str]:
        """Return the set of registered finding labels."""
        return {f.label for f in self._findings}

    @property
    def current_raw_score(self) -> int:
        """Current accumulated raw score before normalisation."""
        return self._raw_score


# ---------------------------------------------------------------------------
# Standalone Helper Functions (usable without instantiating RiskEngine)
# ---------------------------------------------------------------------------

def get_risk_level(score: int) -> str:
    """
    Map a normalised score (0–100) to a human-readable risk level.

    Args:
        score: Normalised risk score.

    Returns:
        "Low", "Medium", "High", or "Critical".
    """
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "Critical"


def generate_recommendations(findings: list[dict]) -> list[str]:
    """
    Generate a de-duplicated list of recommendations from a list of finding
    dicts (as returned by RiskEngine.calculate_score).

    This is a convenience function for modules that build recommendations
    from a pre-computed findings list rather than via the engine directly.

    Args:
        findings: List of finding dicts with at least a "label" key.

    Returns:
        List of recommendation strings.
    """
    mapping: dict[str, str] = {
        "ip_in_url":            "Use a domain name instead of a raw IP address.",
        "punycode_detected":    "Avoid Punycode/IDN domains; verify domain authenticity.",
        "url_shortener":        "Expand shortened URLs before visiting; use a URL expander tool.",
        "fake_login_keywords":  "Verify the site's legitimacy before entering credentials.",
        "suspicious_tld":       "Be cautious of domains with high-risk TLDs.",
        "too_many_subdomains":  "Excessive subdomains can indicate spoofing; verify the root domain.",
        "too_many_hyphens":     "Multiple hyphens in a domain are a common phishing indicator.",
        "excessive_dots":       "Too many dots in a URL often indicate a deceptive subdomain trick.",
        "long_url":             "Unusually long URLs may be designed to hide the real destination.",
        "missing_https":        "Ensure the site uses HTTPS before submitting any sensitive data.",
        "at_symbol_in_url":     "The @ symbol in a URL can mask the true destination.",
        "double_slash_redirect":"Double slashes in the path may indicate an open redirect attack.",
        "hex_encoding":         "Percent-encoded characters in the host/path may conceal malicious URLs.",
        "unicode_characters":   "Non-ASCII characters can be used in IDN homograph attacks.",
        "ssl_expired":          "The SSL certificate has expired; do not trust this site.",
        "ssl_expiring_soon":    "Renew the SSL certificate before it expires.",
        "ssl_self_signed":      "Self-signed certificates are not trusted by browsers.",
        "deprecated_tls":       "Upgrade to TLS 1.2 or TLS 1.3 immediately.",
        "missing_hsts":         "Enable HTTP Strict Transport Security (HSTS).",
        "missing_csp":          "Implement a Content Security Policy (CSP) header.",
        "missing_x_frame":      "Add X-Frame-Options to prevent clickjacking.",
        "missing_xcto":         "Set X-Content-Type-Options: nosniff.",
        "missing_referrer":     "Define a Referrer-Policy header.",
        "missing_permissions":  "Add a Permissions-Policy header to restrict browser features.",
        "newly_registered":     "Domain was registered very recently — high risk of phishing.",
        "expiring_soon":        "Domain registration is expiring soon; verify ownership.",
    }

    seen: set[str] = set()
    recommendations: list[str] = []
    for finding in findings:
        label = finding.get("label", "")
        rec = mapping.get(label)
        if rec and rec not in seen:
            recommendations.append(rec)
            seen.add(rec)
    return recommendations


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _score_to_severity(score: int) -> str:
    """Map an individual finding score to a severity label."""
    if score >= 25:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


def _finding_to_dict(finding: RiskFinding) -> dict:
    """Serialise a RiskFinding to a plain dictionary."""
    return {
        "label": finding.label,
        "description": finding.description,
        "score": finding.score,
        "severity": finding.severity,
    }
