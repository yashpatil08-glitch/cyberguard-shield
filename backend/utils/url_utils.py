"""
backend/utils/url_utils.py

Reusable URL helper functions for CyberGuard.
All functions are pure/stateless and accept a URL string as input.
"""

import re
import urllib.parse
from urllib.parse import urlparse

from backend.utils.constants import URL_SHORTENER_DOMAINS


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """
    Normalise a URL by stripping whitespace and lowercasing the scheme/host.

    Args:
        url: Raw URL string.

    Returns:
        Normalised URL string.
    """
    url = url.strip()
    parsed = urlparse(url)
    # Lowercase scheme and netloc; preserve path case
    normalised = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
    )
    return urllib.parse.urlunparse(normalised)


# ---------------------------------------------------------------------------
# Domain / Hostname Extraction
# ---------------------------------------------------------------------------

def get_hostname(url: str) -> str:
    """
    Return the bare hostname (without port) from a URL.

    Args:
        url: Full URL string.

    Returns:
        Hostname string, or empty string on failure.
    """
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def extract_domain(url: str) -> str:
    """
    Extract the registered domain (eTLD+1) from a URL.
    Uses a simple heuristic: last two labels of the hostname.

    Args:
        url: Full URL string.

    Returns:
        Domain string (e.g. "example.com"), or empty string.
    """
    hostname = get_hostname(url)
    if not hostname:
        return ""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


# ---------------------------------------------------------------------------
# Subdomain Counting
# ---------------------------------------------------------------------------

def count_subdomains(url: str) -> int:
    """
    Count the number of subdomain labels in the URL's hostname.

    e.g. "http://a.b.example.com" → 2 subdomains ("a", "b")

    Args:
        url: Full URL string.

    Returns:
        Number of subdomain labels (0 if none).
    """
    hostname = get_hostname(url)
    if not hostname:
        return 0
    parts = hostname.rstrip(".").split(".")
    # Subtract the registered domain (2 labels)
    subdomain_count = max(0, len(parts) - 2)
    return subdomain_count


# ---------------------------------------------------------------------------
# IP URL Detection
# ---------------------------------------------------------------------------

_IPV4_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)
_IPV6_BRACKETS = re.compile(r'^\[.*\]$')


def is_ip_url(url: str) -> bool:
    """
    Return True if the URL's host is a raw IP address (v4 or v6).

    Args:
        url: Full URL string.

    Returns:
        True if the host is an IP address.
    """
    hostname = get_hostname(url)
    if not hostname:
        return False
    if _IPV4_PATTERN.match(hostname):
        return True
    if _IPV6_BRACKETS.match(hostname):
        return True
    return False


# ---------------------------------------------------------------------------
# URL Shortener Detection
# ---------------------------------------------------------------------------

def is_shortener(url: str) -> bool:
    """
    Return True if the URL belongs to a known URL shortener service.

    Args:
        url: Full URL string.

    Returns:
        True if the domain is a known shortener.
    """
    hostname = get_hostname(url).lower()
    for shortener in URL_SHORTENER_DOMAINS:
        if hostname == shortener or hostname.endswith("." + shortener):
            return True
    return False


# ---------------------------------------------------------------------------
# Punycode Detection
# ---------------------------------------------------------------------------

def contains_punycode(url: str) -> bool:
    """
    Return True if any part of the URL's hostname uses Punycode encoding
    (ACE prefix "xn--"), which is often used in IDN homograph attacks.

    Args:
        url: Full URL string.

    Returns:
        True if Punycode labels are present.
    """
    hostname = get_hostname(url).lower()
    return "xn--" in hostname


# ---------------------------------------------------------------------------
# URL Length
# ---------------------------------------------------------------------------

def get_url_length(url: str) -> int:
    """
    Return the total character length of the URL string.

    Args:
        url: URL string.

    Returns:
        Integer length.
    """
    return len(url)


# ---------------------------------------------------------------------------
# Hyphen Count
# ---------------------------------------------------------------------------

def count_hyphens(url: str) -> int:
    """
    Count the number of hyphens in the URL's hostname.

    Args:
        url: Full URL string.

    Returns:
        Number of hyphens in the hostname.
    """
    hostname = get_hostname(url)
    return hostname.count("-")


# ---------------------------------------------------------------------------
# Dot Count
# ---------------------------------------------------------------------------

def count_dots(url: str) -> int:
    """
    Count the number of dots in the full URL string.
    High dot counts can indicate phishing (e.g. "paypal.com.evil.xyz").

    Args:
        url: Full URL string.

    Returns:
        Number of dots.
    """
    return url.count(".")


# ---------------------------------------------------------------------------
# HTTPS Check
# ---------------------------------------------------------------------------

def is_https(url: str) -> bool:
    """
    Return True if the URL uses the HTTPS scheme.

    Args:
        url: URL string.

    Returns:
        True if scheme is "https".
    """
    return urlparse(url).scheme.lower() == "https"


# ---------------------------------------------------------------------------
# @ Symbol Detection
# ---------------------------------------------------------------------------

def has_at_symbol(url: str) -> bool:
    """
    Return True if the URL contains an @ symbol in the authority section,
    which can be used to deceive users about the actual destination.

    Args:
        url: Full URL string.

    Returns:
        True if @ is present before the hostname.
    """
    netloc = urlparse(url).netloc
    return "@" in netloc


# ---------------------------------------------------------------------------
# Hex / Percent Encoding Detection
# ---------------------------------------------------------------------------

_HEX_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')


def has_hex_encoding(url: str) -> bool:
    """
    Return True if the URL contains suspicious percent-encoded characters
    in the netloc or path (excluding standard query encoding).

    Args:
        url: Full URL string.

    Returns:
        True if hex-encoded characters are found in host/path.
    """
    parsed = urlparse(url)
    target = parsed.netloc + parsed.path
    return bool(_HEX_PATTERN.search(target))


# ---------------------------------------------------------------------------
# Double-Slash Redirect Detection
# ---------------------------------------------------------------------------

def has_double_slash_redirect(url: str) -> bool:
    """
    Detect if the URL path contains "//" which can indicate an open redirect
    attempt (e.g. "https://legit.com//evil.com").

    Args:
        url: Full URL string.

    Returns:
        True if a double-slash is present in the path.
    """
    path = urlparse(url).path
    return "//" in path


# ---------------------------------------------------------------------------
# Unicode / Non-ASCII Character Detection
# ---------------------------------------------------------------------------

def has_unicode_characters(url: str) -> bool:
    """
    Return True if the URL contains non-ASCII (Unicode) characters,
    which may indicate an IDN homograph attack.

    Args:
        url: Full URL string.

    Returns:
        True if non-ASCII characters are detected.
    """
    try:
        url.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


# ---------------------------------------------------------------------------
# TLD Extraction
# ---------------------------------------------------------------------------

def get_tld(url: str) -> str:
    """
    Extract the top-level domain from a URL (e.g. ".com", ".tk").

    Args:
        url: Full URL string.

    Returns:
        TLD string including the leading dot, or empty string.
    """
    hostname = get_hostname(url).lower()
    parts = hostname.rstrip(".").split(".")
    if parts:
        return "." + parts[-1]
    return ""
