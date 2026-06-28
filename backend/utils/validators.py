"""
backend/utils/validators.py

Reusable input validation functions for CyberGuard.
Provides URL, password, domain, IP, and input sanitization utilities.
"""

import re
import ipaddress
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------

def validate_url(url: str) -> dict:
    """
    Validate a URL string.

    Args:
        url: The URL string to validate.

    Returns:
        dict with keys:
            - valid (bool)
            - error (str | None)
            - parsed (dict | None): scheme, netloc, path, query if valid
    """
    if not url or not isinstance(url, str):
        return {"valid": False, "error": "URL must be a non-empty string.", "parsed": None}

    url = url.strip()

    # Must start with http:// or https://
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return {"valid": False, "error": "URL must begin with http:// or https://.", "parsed": None}

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return {"valid": False, "error": f"URL parse error: {exc}", "parsed": None}

    if not parsed.netloc:
        return {"valid": False, "error": "URL is missing a valid hostname.", "parsed": None}

    # Basic character safety check
    if re.search(r'[\s<>\'"]', url):
        return {"valid": False, "error": "URL contains illegal characters.", "parsed": None}

    return {
        "valid": True,
        "error": None,
        "parsed": {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
        },
    }


# ---------------------------------------------------------------------------
# Password Validation
# ---------------------------------------------------------------------------

_MIN_PASSWORD_LENGTH = 8
_MAX_PASSWORD_LENGTH = 128


def validate_password(password: str) -> dict:
    """
    Validate a password for minimum security requirements.

    Args:
        password: The password string to validate.

    Returns:
        dict with keys:
            - valid (bool)
            - errors (list[str]): list of violated requirements
    """
    errors = []

    if not isinstance(password, str):
        return {"valid": False, "errors": ["Password must be a string."]}

    if len(password) < _MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters long.")

    if len(password) > _MAX_PASSWORD_LENGTH:
        errors.append(f"Password must not exceed {_MAX_PASSWORD_LENGTH} characters.")

    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")

    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
        errors.append("Password must contain at least one special character.")

    return {"valid": len(errors) == 0, "errors": errors}


# ---------------------------------------------------------------------------
# Domain Validation
# ---------------------------------------------------------------------------

# RFC 1035 / RFC 1123 compliant domain regex
_DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'           # First character of the domain
    r'(?:[a-zA-Z0-9\-]{0,61}'    # Middle characters
    r'[a-zA-Z0-9])?'             # Last character of a label
    r'\.)*'                       # Repeat for subdomains
    r'[a-zA-Z]{2,63}$'           # TLD
)


def validate_domain(domain: str) -> dict:
    """
    Validate a domain name (without scheme).

    Args:
        domain: Domain string, e.g. "example.com".

    Returns:
        dict with keys:
            - valid (bool)
            - error (str | None)
    """
    if not domain or not isinstance(domain, str):
        return {"valid": False, "error": "Domain must be a non-empty string."}

    domain = domain.strip().lower()

    if len(domain) > 253:
        return {"valid": False, "error": "Domain exceeds maximum length of 253 characters."}

    if not _DOMAIN_REGEX.match(domain):
        return {"valid": False, "error": "Domain contains invalid characters or format."}

    return {"valid": True, "error": None}


# ---------------------------------------------------------------------------
# IP Address Validation
# ---------------------------------------------------------------------------

def validate_ip(ip: str) -> dict:
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string.

    Returns:
        dict with keys:
            - valid (bool)
            - version (int | None): 4 or 6
            - error (str | None)
    """
    if not ip or not isinstance(ip, str):
        return {"valid": False, "version": None, "error": "IP must be a non-empty string."}

    ip = ip.strip()

    try:
        obj = ipaddress.ip_address(ip)
        return {"valid": True, "version": obj.version, "error": None}
    except ValueError:
        return {"valid": False, "version": None, "error": f"'{ip}' is not a valid IPv4 or IPv6 address."}


# ---------------------------------------------------------------------------
# Input Sanitization
# ---------------------------------------------------------------------------

# Characters that must be stripped from free-form inputs
_DANGEROUS_PATTERN = re.compile(r'[<>\'";&|`$\\]')


def sanitize_input(value: str, max_length: int = 2048) -> dict:
    """
    Sanitize a free-form string input to remove dangerous characters.

    Args:
        value:      Raw input string.
        max_length: Maximum allowed length after stripping (default 2048).

    Returns:
        dict with keys:
            - sanitized (str): cleaned string
            - was_modified (bool): True if the original string was changed
            - error (str | None): set if input is completely invalid
    """
    if not isinstance(value, str):
        return {"sanitized": "", "was_modified": True, "error": "Input must be a string."}

    original = value
    value = value.strip()

    # Remove dangerous characters
    value = _DANGEROUS_PATTERN.sub('', value)

    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length]

    return {
        "sanitized": value,
        "was_modified": value != original,
        "error": None,
    }
