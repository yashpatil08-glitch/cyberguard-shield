"""
backend/services/url_analyzer.py

URL Security Analyser for CyberGuard.
Combines URL structure inspection, SSL, DNS, WHOIS, redirect
detection, and risk scoring into a single JSON-compatible report.
"""

import logging
import urllib.parse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from backend.utils.constants import (
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    PHISHING_INDICATORS,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    MAX_REDIRECTS,
)
from backend.utils.validators import validate_url
from backend.utils.url_utils import (
    normalize_url,
    get_hostname,
    extract_domain,
    count_subdomains,
    is_ip_url,
    is_shortener,
    contains_punycode,
    get_url_length,
    count_hyphens,
    count_dots,
    is_https,
    has_at_symbol,
    has_hex_encoding,
    has_double_slash_redirect,
    has_unicode_characters,
    get_tld,
)
from backend.utils.risk_engine import RiskEngine, generate_recommendations
from backend.utils.ssl_checker import SSLChecker
from backend.utils.dns_lookup import DNSLookup
from backend.utils.whois_lookup import WHOISLookup

logger = logging.getLogger(__name__)

# Thresholds for URL structure checks
_MAX_SAFE_URL_LENGTH = 75
_MAX_SAFE_SUBDOMAINS = 3
_MAX_SAFE_HYPHENS = 4
_MAX_SAFE_DOTS = 5


class URLAnalyzer:
    """
    Performs a comprehensive security analysis of a URL.

    Usage:
        analyzer = URLAnalyzer()
        report = analyzer.analyze("https://example.com")
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        check_ssl: bool = True,
        check_dns: bool = True,
        check_whois: bool = True,
        follow_redirects: bool = True,
    ) -> None:
        self.timeout = timeout
        self.check_ssl = check_ssl
        self.check_dns = check_dns
        self.check_whois = check_whois
        self.follow_redirects = follow_redirects

        self._ssl_checker = SSLChecker(timeout=timeout)
        self._dns_lookup = DNSLookup(timeout=float(timeout))
        self._whois_lookup = WHOISLookup()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, url: str) -> dict:
        """
        Perform a full security analysis of the given URL.

        Args:
            url: URL string to analyse.

        Returns:
            JSON-compatible dict with keys:
                - url             (str): normalised URL
                - valid           (bool)
                - https           (bool)
                - ssl             (dict | None)
                - dns             (dict | None)
                - whois           (dict | None)
                - redirects       (list[str])
                - final_url       (str | None)
                - url_length      (int)
                - subdomain_count (int)
                - hyphen_count    (int)
                - dot_count       (int)
                - is_ip_url       (bool)
                - is_shortener    (bool)
                - has_punycode    (bool)
                - has_unicode     (bool)
                - has_at_symbol   (bool)
                - has_hex_encoding(bool)
                - suspicious_tld  (bool)
                - tld             (str)
                - suspicious_keywords (list[str])
                - risk            (dict): score, level, findings, recommendations
                - error           (str | None)
        """
        engine = RiskEngine()
        report: dict = {
            "url": url,
            "valid": False,
            "https": False,
            "ssl": None,
            "dns": None,
            "whois": None,
            "redirects": [],
            "final_url": None,
            "url_length": 0,
            "subdomain_count": 0,
            "hyphen_count": 0,
            "dot_count": 0,
            "is_ip_url": False,
            "is_shortener": False,
            "has_punycode": False,
            "has_unicode": False,
            "has_at_symbol": False,
            "has_hex_encoding": False,
            "suspicious_tld": False,
            "tld": "",
            "suspicious_keywords": [],
            "risk": {},
            "error": None,
        }

        # --- Step 1: Validate URL ---
        validation = validate_url(url)
        if not validation["valid"]:
            report["error"] = validation["error"]
            report["risk"] = engine.calculate_score()
            return report

        url = normalize_url(url)
        report["url"] = url
        report["valid"] = True

        # --- Step 2: Basic structural checks ---
        report["https"] = is_https(url)
        if not report["https"]:
            engine.add_risk(
                "missing_https",
                "URL does not use HTTPS encryption.",
                PHISHING_INDICATORS["missing_https"],
            )
            engine.add_recommendation("Switch to HTTPS to protect data in transit.")

        url_len = get_url_length(url)
        report["url_length"] = url_len
        if url_len > _MAX_SAFE_URL_LENGTH:
            engine.add_risk(
                "long_url",
                f"URL length ({url_len} chars) exceeds safe threshold ({_MAX_SAFE_URL_LENGTH}).",
                PHISHING_INDICATORS["long_url"],
            )

        hostname = get_hostname(url)
        subdomain_count = count_subdomains(url)
        report["subdomain_count"] = subdomain_count
        if subdomain_count > _MAX_SAFE_SUBDOMAINS:
            engine.add_risk(
                "too_many_subdomains",
                f"URL has {subdomain_count} subdomain levels (threshold: {_MAX_SAFE_SUBDOMAINS}).",
                PHISHING_INDICATORS["too_many_subdomains"],
            )

        hyphen_count = count_hyphens(url)
        report["hyphen_count"] = hyphen_count
        if hyphen_count > _MAX_SAFE_HYPHENS:
            engine.add_risk(
                "too_many_hyphens",
                f"Hostname contains {hyphen_count} hyphens.",
                PHISHING_INDICATORS["too_many_hyphens"],
            )

        dot_count = count_dots(url)
        report["dot_count"] = dot_count
        if dot_count > _MAX_SAFE_DOTS:
            engine.add_risk(
                "excessive_dots",
                f"URL contains {dot_count} dots.",
                PHISHING_INDICATORS["excessive_dots"],
            )

        # --- Step 3: IP URL ---
        ip_url = is_ip_url(url)
        report["is_ip_url"] = ip_url
        if ip_url:
            engine.add_risk(
                "ip_in_url",
                "URL uses a raw IP address instead of a domain name.",
                PHISHING_INDICATORS["ip_in_url"],
            )

        # --- Step 4: URL shortener ---
        shortener = is_shortener(url)
        report["is_shortener"] = shortener
        if shortener:
            engine.add_risk(
                "url_shortener",
                "URL uses a known URL shortening service.",
                PHISHING_INDICATORS["url_shortener"],
            )

        # --- Step 5: Punycode / Unicode ---
        punycode = contains_punycode(url)
        report["has_punycode"] = punycode
        if punycode:
            engine.add_risk(
                "punycode_detected",
                "Hostname contains Punycode (xn--) encoding — possible IDN homograph attack.",
                PHISHING_INDICATORS["punycode_detected"],
            )

        unicode_chars = has_unicode_characters(url)
        report["has_unicode"] = unicode_chars
        if unicode_chars:
            engine.add_risk(
                "unicode_characters",
                "URL contains non-ASCII Unicode characters.",
                PHISHING_INDICATORS["unicode_characters"],
            )

        # --- Step 6: @ symbol / hex encoding ---
        at_sym = has_at_symbol(url)
        report["has_at_symbol"] = at_sym
        if at_sym:
            engine.add_risk(
                "at_symbol_in_url",
                "URL contains @ symbol in authority — can be used to mask the real destination.",
                PHISHING_INDICATORS["at_symbol_in_url"],
            )

        hex_enc = has_hex_encoding(url)
        report["has_hex_encoding"] = hex_enc
        if hex_enc:
            engine.add_risk(
                "hex_encoding",
                "URL host/path contains percent-encoded characters.",
                PHISHING_INDICATORS["hex_encoding"],
            )

        # --- Step 7: TLD check ---
        tld = get_tld(url)
        report["tld"] = tld
        susp_tld = tld in SUSPICIOUS_TLDS
        report["suspicious_tld"] = susp_tld
        if susp_tld:
            engine.add_risk(
                "suspicious_tld",
                f"TLD '{tld}' is commonly associated with phishing or spam.",
                PHISHING_INDICATORS["suspicious_tld"],
            )

        # --- Step 8: Suspicious keywords ---
        url_lower = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        report["suspicious_keywords"] = found_keywords
        if found_keywords:
            engine.add_risk(
                "fake_login_keywords",
                f"URL contains suspicious keywords: {', '.join(found_keywords[:5])}.",
                PHISHING_INDICATORS["fake_login_keywords"],
            )

        # --- Step 9: Redirects ---
        if self.follow_redirects:
            redirects, final_url = _follow_redirects(url, self.timeout)
            report["redirects"] = redirects
            report["final_url"] = final_url
        else:
            report["final_url"] = url

        # --- Step 10: SSL ---
        if self.check_ssl and report["https"] and not ip_url:
            ssl_result = self._ssl_checker.check(hostname)
            report["ssl"] = ssl_result
            _apply_ssl_risks(ssl_result, engine)
        elif not report["https"]:
            report["ssl"] = {"valid": False, "error": "Not an HTTPS URL."}

        # --- Step 11: DNS ---
        if self.check_dns and hostname and not ip_url:
            dns_result = self._dns_lookup.lookup_all(hostname)
            report["dns"] = dns_result
            if dns_result["summary"]["total_found"] == 0:
                engine.add_risk(
                    "no_dns_records",
                    "No DNS records found for this domain.",
                    20,
                )

        # --- Step 12: WHOIS ---
        if self.check_whois and hostname and not ip_url:
            domain = extract_domain(url)
            whois_result = self._whois_lookup.query(domain)
            report["whois"] = whois_result
            _apply_whois_risks(whois_result, engine)

        # --- Final risk calculation ---
        risk = engine.calculate_score()
        risk["recommendations"] = generate_recommendations(risk["findings"])
        report["risk"] = risk

        return report


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _follow_redirects(url: str, timeout: int) -> tuple[list[str], str]:
    """
    Follow HTTP redirects and return the chain and final URL.

    Args:
        url:     Starting URL.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (redirect_chain, final_url).
    """
    chain: list[str] = []
    current = url

    for _ in range(MAX_REDIRECTS):
        try:
            req = Request(current, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urlopen(req, timeout=timeout) as resp:
                final = resp.url
                if final and final != current:
                    chain.append(final)
                    current = final
                break
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                location = exc.headers["Location"]
                location = urllib.parse.urljoin(current, location)
                chain.append(location)
                current = location
            else:
                break
        except (URLError, Exception):
            break

    return chain, current


def _apply_ssl_risks(ssl_result: dict, engine: RiskEngine) -> None:
    """Apply SSL-related risks to the engine based on the SSL check result."""
    if not ssl_result.get("valid"):
        engine.add_risk("ssl_invalid", "SSL certificate is invalid or could not be verified.", 30)
        return

    expiry_status = ssl_result.get("expiry_status", "")
    if expiry_status == "expired":
        engine.add_risk("ssl_expired", "SSL certificate has expired.", 35)
    elif expiry_status == "critical":
        days = ssl_result.get("days_remaining", 0)
        engine.add_risk("ssl_expiring_soon", f"SSL certificate expires in {days} days (critical).", 20)
    elif expiry_status == "warning":
        days = ssl_result.get("days_remaining", 0)
        engine.add_risk("ssl_expiring_soon", f"SSL certificate expires in {days} days.", 10)

    if not ssl_result.get("tls_trusted", True):
        tls = ssl_result.get("tls_version", "unknown")
        engine.add_risk("deprecated_tls", f"Deprecated TLS version in use: {tls}.", 20)


def _apply_whois_risks(whois_result: dict, engine: RiskEngine) -> None:
    """Apply WHOIS-related risks to the engine."""
    if not whois_result.get("found"):
        engine.add_risk("no_whois_data", "No WHOIS data found for this domain.", 15)
        return

    if whois_result.get("newly_registered"):
        age = whois_result.get("age_days", 0)
        engine.add_risk(
            "newly_registered",
            f"Domain was registered only {age} day(s) ago.",
            25,
        )

    if whois_result.get("expiring_soon"):
        days = whois_result.get("days_until_expiry", 0)
        engine.add_risk(
            "expiring_soon",
            f"Domain registration expires in {days} day(s).",
            10,
        )
