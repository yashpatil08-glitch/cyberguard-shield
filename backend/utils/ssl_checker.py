"""
backend/utils/ssl_checker.py

Real SSL/TLS certificate inspection for CyberGuard.
Retrieves certificate details, expiry, issuer, subject, and TLS version
using Python's built-in ssl module — no third-party dependencies required.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone

from backend.utils.constants import (
    SSL_EXPIRY_CRITICAL_DAYS,
    SSL_EXPIRY_WARNING_DAYS,
    TRUSTED_TLS_VERSIONS,
    DEPRECATED_TLS_VERSIONS,
    DEFAULT_TIMEOUT,
)

logger = logging.getLogger(__name__)


class SSLChecker:
    """
    Inspects the SSL/TLS configuration of a hostname.

    Usage:
        checker = SSLChecker()
        result = checker.check("example.com")
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, hostname: str, port: int = 443) -> dict:
        """
        Connect to the host on the given port and inspect its SSL certificate.

        Args:
            hostname: Bare hostname, e.g. "example.com".
            port:     TCP port (default 443).

        Returns:
            dict with keys:
                - valid         (bool)
                - issuer        (dict | None)
                - subject       (dict | None)
                - not_before    (str | None)  ISO-8601
                - not_after     (str | None)  ISO-8601
                - days_remaining(int | None)
                - expiry_status (str): "valid" | "warning" | "critical" | "expired"
                - tls_version   (str | None)
                - tls_trusted   (bool)
                - serial_number (str | None)
                - san           (list[str])
                - error         (str | None)
        """
        result: dict = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "expiry_status": "unknown",
            "tls_version": None,
            "tls_trusted": False,
            "serial_number": None,
            "san": [],
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    tls_version = tls_sock.version()

            result["valid"] = True
            result["tls_version"] = tls_version
            result["tls_trusted"] = tls_version in TRUSTED_TLS_VERSIONS

            result["issuer"] = _parse_rdn(cert.get("issuer", ()))
            result["subject"] = _parse_rdn(cert.get("subject", ()))
            result["serial_number"] = str(cert.get("serialNumber", ""))
            result["san"] = _parse_san(cert.get("subjectAltName", ()))

            not_before_str = cert.get("notBefore", "")
            not_after_str = cert.get("notAfter", "")

            not_before = _parse_ssl_date(not_before_str)
            not_after = _parse_ssl_date(not_after_str)

            if not_before:
                result["not_before"] = not_before.isoformat()
            if not_after:
                result["not_after"] = not_after.isoformat()
                now = datetime.now(tz=timezone.utc)
                days_remaining = (not_after - now).days
                result["days_remaining"] = days_remaining
                result["expiry_status"] = _classify_expiry(days_remaining)

        except ssl.SSLCertVerificationError as exc:
            result["error"] = f"Certificate verification failed: {exc}"
            logger.warning("SSL verification error for %s: %s", hostname, exc)

        except ssl.SSLError as exc:
            result["error"] = f"SSL error: {exc}"
            logger.warning("SSL error for %s: %s", hostname, exc)

        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout}s."
            logger.warning("Timeout connecting to %s:%d", hostname, port)

        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}."
            logger.warning("Connection refused: %s:%d", hostname, port)

        except OSError as exc:
            result["error"] = f"Network error: {exc}"
            logger.error("Network error for %s: %s", hostname, exc)

        return result


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _parse_rdn(rdn_seq: tuple) -> dict:
    """
    Convert an ssl module RDN sequence to a flat dictionary.

    Args:
        rdn_seq: Tuple of RDN tuples as returned by getpeercert().

    Returns:
        dict, e.g. {"commonName": "example.com", "organizationName": "Example Inc."}
    """
    result: dict = {}
    for rdn in rdn_seq:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_san(san_seq: tuple) -> list[str]:
    """
    Extract Subject Alternative Names from the SAN sequence.

    Args:
        san_seq: Tuple of (type, value) pairs.

    Returns:
        List of SAN strings (e.g. ["DNS:example.com", "DNS:www.example.com"]).
    """
    return [f"{san_type}:{san_value}" for san_type, san_value in san_seq]


def _parse_ssl_date(date_str: str) -> datetime | None:
    """
    Parse an SSL certificate date string into a timezone-aware datetime.

    Args:
        date_str: Date string in the format "%b %d %H:%M:%S %Y %Z".

    Returns:
        Timezone-aware datetime or None on failure.
    """
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        logger.debug("Could not parse SSL date string: %s", date_str)
        return None


def _classify_expiry(days_remaining: int) -> str:
    """
    Classify the certificate expiry status.

    Args:
        days_remaining: Days until the certificate expires.

    Returns:
        "expired" | "critical" | "warning" | "valid"
    """
    if days_remaining < 0:
        return "expired"
    if days_remaining <= SSL_EXPIRY_CRITICAL_DAYS:
        return "critical"
    if days_remaining <= SSL_EXPIRY_WARNING_DAYS:
        return "warning"
    return "valid"
