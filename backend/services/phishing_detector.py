"""
backend/services/phishing_detector.py

Rule-based Phishing Detector for CyberGuard.
Evaluates a URL against a comprehensive set of heuristic rules
and produces a risk score, findings, explanation, and recommendations.
"""

import logging
import re

from backend.utils.constants import (
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    PHISHING_INDICATORS,
)
from backend.utils.validators import validate_url
from backend.utils.url_utils import (
    get_hostname,
    get_tld,
    is_ip_url,
    is_shortener,
    contains_punycode,
    has_unicode_characters,
    has_at_symbol,
    has_hex_encoding,
    has_double_slash_redirect,
    count_subdomains,
    count_hyphens,
    count_dots,
    get_url_length,
)
from backend.utils.risk_engine import RiskEngine, get_risk_level, generate_recommendations

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection Thresholds
# ---------------------------------------------------------------------------
_MAX_SAFE_URL_LENGTH: int = 75
_MAX_SAFE_SUBDOMAINS: int = 3
_MAX_SAFE_HYPHENS: int = 4
_MAX_SAFE_DOTS: int = 5
_MIN_SUSPICIOUS_KEYWORD_COUNT: int = 1

# Regex for detecting common login-form paths
_LOGIN_PATH_RE = re.compile(
    r'/(login|signin|sign[-_]in|log[-_]in|logon|auth|verify|secure|account|update|confirm)',
    re.IGNORECASE,
)


class PhishingDetector:
    """
    Rule-based phishing URL detector.

    Usage:
        detector = PhishingDetector()
        result = detector.detect("http://paypa1-secure.login.tk/verify")
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, url: str) -> dict:
        """
        Analyse the URL for phishing indicators.

        Args:
            url: URL string to evaluate.

        Returns:
            JSON-compatible dict with keys:
                - url              (str)
                - valid            (bool)
                - score            (int): 0–100 phishing likelihood score
                - risk_level       (str): "Low" | "Medium" | "High" | "Critical"
                - is_phishing      (bool): True if score ≥ 50
                - confidence       (str): "Low" | "Medium" | "High"
                - findings         (list[dict]): triggered rules with details
                - explanation      (str): human-readable summary
                - recommendations  (list[str])
                - checks_performed (list[str])
                - error            (str | None)
        """
        engine = RiskEngine()
        checks_performed: list[str] = []

        result: dict = {
            "url": url,
            "valid": False,
            "score": 0,
            "risk_level": "Low",
            "is_phishing": False,
            "confidence": "Low",
            "findings": [],
            "explanation": "",
            "recommendations": [],
            "checks_performed": [],
            "error": None,
        }

        # Validate URL
        validation = validate_url(url)
        if not validation["valid"]:
            result["error"] = validation["error"]
            return result

        result["valid"] = True
        url_lower = url.lower()

        # --- Rule 1: IP-based URL ---
        checks_performed.append("ip_url_check")
        if is_ip_url(url):
            engine.add_risk(
                "ip_in_url",
                "URL uses a raw IP address instead of a domain name — strong phishing indicator.",
                PHISHING_INDICATORS["ip_in_url"],
            )

        # --- Rule 2: Punycode / IDN homograph ---
        checks_performed.append("punycode_check")
        if contains_punycode(url):
            engine.add_risk(
                "punycode_detected",
                "Hostname uses Punycode (xn--) encoding — common in IDN homograph attacks.",
                PHISHING_INDICATORS["punycode_detected"],
            )

        # --- Rule 3: Unicode characters ---
        checks_performed.append("unicode_check")
        if has_unicode_characters(url):
            engine.add_risk(
                "unicode_characters",
                "URL contains non-ASCII characters that may visually impersonate legitimate domains.",
                PHISHING_INDICATORS["unicode_characters"],
            )

        # --- Rule 4: URL shortener ---
        checks_performed.append("shortener_check")
        if is_shortener(url):
            engine.add_risk(
                "url_shortener",
                "URL uses a known URL shortening service — hides the real destination.",
                PHISHING_INDICATORS["url_shortener"],
            )

        # --- Rule 5: Suspicious keywords in URL ---
        checks_performed.append("keyword_check")
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if len(found_keywords) >= _MIN_SUSPICIOUS_KEYWORD_COUNT:
            engine.add_risk(
                "fake_login_keywords",
                f"URL contains phishing keywords: {', '.join(found_keywords[:6])}.",
                PHISHING_INDICATORS["fake_login_keywords"],
            )

        # --- Rule 6: Login/auth path patterns ---
        checks_performed.append("login_path_check")
        if _LOGIN_PATH_RE.search(url):
            engine.add_risk(
                "login_path_pattern",
                "URL path matches a common credential-harvesting pattern.",
                15,
            )

        # --- Rule 7: Long URL ---
        checks_performed.append("url_length_check")
        url_len = get_url_length(url)
        if url_len > _MAX_SAFE_URL_LENGTH:
            engine.add_risk(
                "long_url",
                f"URL is unusually long ({url_len} characters) — may be designed to hide the destination.",
                PHISHING_INDICATORS["long_url"],
            )

        # --- Rule 8: Too many dots ---
        checks_performed.append("dot_count_check")
        dot_count = count_dots(url)
        if dot_count > _MAX_SAFE_DOTS:
            engine.add_risk(
                "excessive_dots",
                f"URL contains {dot_count} dots — subdomain trick to impersonate trusted domains.",
                PHISHING_INDICATORS["excessive_dots"],
            )

        # --- Rule 9: Too many hyphens ---
        checks_performed.append("hyphen_count_check")
        hyphen_count = count_hyphens(url)
        if hyphen_count > _MAX_SAFE_HYPHENS:
            engine.add_risk(
                "too_many_hyphens",
                f"Hostname contains {hyphen_count} hyphens — common in spoofed domains.",
                PHISHING_INDICATORS["too_many_hyphens"],
            )

        # --- Rule 10: Suspicious TLD ---
        checks_performed.append("tld_check")
        tld = get_tld(url)
        if tld in SUSPICIOUS_TLDS:
            engine.add_risk(
                "suspicious_tld",
                f"TLD '{tld}' is frequently used in phishing campaigns.",
                PHISHING_INDICATORS["suspicious_tld"],
            )

        # --- Rule 11: @ symbol in URL ---
        checks_performed.append("at_symbol_check")
        if has_at_symbol(url):
            engine.add_risk(
                "at_symbol_in_url",
                "URL contains '@' in the authority component — masks the real destination.",
                PHISHING_INDICATORS["at_symbol_in_url"],
            )

        # --- Rule 12: Hex/percent encoding in host or path ---
        checks_performed.append("hex_encoding_check")
        if has_hex_encoding(url):
            engine.add_risk(
                "hex_encoding",
                "URL host/path contains suspicious percent-encoded characters.",
                PHISHING_INDICATORS["hex_encoding"],
            )

        # --- Rule 13: Double-slash redirect ---
        checks_performed.append("double_slash_check")
        if has_double_slash_redirect(url):
            engine.add_risk(
                "double_slash_redirect",
                "URL path contains '//' — may indicate an open redirect attempt.",
                PHISHING_INDICATORS["double_slash_redirect"],
            )

        # --- Rule 14: Too many subdomains ---
        checks_performed.append("subdomain_count_check")
        subdomain_count = count_subdomains(url)
        if subdomain_count > _MAX_SAFE_SUBDOMAINS:
            engine.add_risk(
                "too_many_subdomains",
                f"URL has {subdomain_count} subdomain levels — common tactic to embed legitimate-looking names.",
                PHISHING_INDICATORS["too_many_subdomains"],
            )

        # --- Finalise ---
        risk = engine.calculate_score()
        score = risk["score"]
        risk_level = get_risk_level(score)
        recommendations = generate_recommendations(risk["findings"])

        result.update({
            "score": score,
            "risk_level": risk_level,
            "is_phishing": score >= 50,
            "confidence": _confidence(score),
            "findings": risk["findings"],
            "explanation": _build_explanation(score, risk_level, risk["findings"]),
            "recommendations": recommendations,
            "checks_performed": checks_performed,
        })

        return result


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _confidence(score: int) -> str:
    """Map phishing score to a confidence label."""
    if score >= 75:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _build_explanation(score: int, risk_level: str, findings: list[dict]) -> str:
    """
    Build a concise human-readable explanation of the phishing verdict.

    Args:
        score:    Overall phishing score.
        risk_level: Risk level string.
        findings: List of triggered findings.

    Returns:
        Plain-text explanation string.
    """
    if not findings:
        return (
            f"No phishing indicators were detected. The URL scored {score}/100 "
            f"and is considered {risk_level} risk."
        )

    top_findings = [f["description"] for f in findings[:3]]
    finding_text = "; ".join(top_findings)

    if score >= 75:
        verdict = "This URL exhibits multiple strong phishing indicators and is likely malicious."
    elif score >= 50:
        verdict = "This URL shows several suspicious characteristics consistent with phishing."
    elif score >= 25:
        verdict = "This URL contains some suspicious elements that warrant caution."
    else:
        verdict = "This URL has minor suspicious characteristics but appears relatively safe."

    return (
        f"{verdict} Overall phishing score: {score}/100 ({risk_level} risk). "
        f"Key indicators: {finding_text}."
    )
