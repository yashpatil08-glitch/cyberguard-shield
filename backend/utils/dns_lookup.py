"""
backend/utils/dns_lookup.py

DNS record lookup utility for CyberGuard.
Supports A, AAAA, MX, TXT, and NS record types.
Uses the dnspython library for structured resolution.
"""

import logging
from typing import Any

import dns.exception
import dns.name
import dns.resolver

from backend.utils.constants import SUPPORTED_DNS_RECORD_TYPES

logger = logging.getLogger(__name__)


class DNSLookup:
    """
    Perform DNS lookups for a given hostname.

    Usage:
        dns = DNSLookup()
        result = dns.lookup_all("example.com")
    """

    def __init__(self, timeout: float = 5.0, lifetime: float = 10.0) -> None:
        """
        Initialise the DNS resolver with custom timeouts.

        Args:
            timeout:  Per-query timeout in seconds.
            lifetime: Total query lifetime in seconds.
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, hostname: str, record_type: str) -> dict:
        """
        Resolve a single DNS record type for the given hostname.

        Args:
            hostname:    Domain to query, e.g. "example.com".
            record_type: One of "A", "AAAA", "MX", "TXT", "NS".

        Returns:
            dict with keys:
                - hostname    (str)
                - record_type (str)
                - records     (list)
                - found       (bool)
                - error       (str | None)
        """
        record_type = record_type.upper()
        if record_type not in SUPPORTED_DNS_RECORD_TYPES:
            return {
                "hostname": hostname,
                "record_type": record_type,
                "records": [],
                "found": False,
                "error": f"Unsupported record type: {record_type}. "
                         f"Supported: {SUPPORTED_DNS_RECORD_TYPES}",
            }

        try:
            answers = self.resolver.resolve(hostname, record_type)
            records = _parse_answers(record_type, answers)
            return {
                "hostname": hostname,
                "record_type": record_type,
                "records": records,
                "found": True,
                "error": None,
            }

        except dns.resolver.NXDOMAIN:
            return _not_found(hostname, record_type, "Domain does not exist (NXDOMAIN).")

        except dns.resolver.NoAnswer:
            return _not_found(hostname, record_type, f"No {record_type} records found.")

        except dns.resolver.NoNameservers:
            return _not_found(hostname, record_type, "No nameservers available for this domain.")

        except dns.exception.Timeout:
            return _not_found(hostname, record_type, "DNS query timed out.")

        except Exception as exc:
            logger.error("Unexpected DNS error for %s %s: %s", hostname, record_type, exc)
            return _not_found(hostname, record_type, f"Unexpected error: {exc}")

    def lookup_all(self, hostname: str) -> dict:
        """
        Resolve all supported DNS record types for the given hostname.

        Args:
            hostname: Domain to query.

        Returns:
            dict with keys:
                - hostname (str)
                - results  (dict): keyed by record type, each value is a lookup result dict
                - summary  (dict): quick stats (total_found, types_with_records)
        """
        results: dict[str, Any] = {}
        for record_type in SUPPORTED_DNS_RECORD_TYPES:
            results[record_type] = self.lookup(hostname, record_type)

        types_with_records = [
            rt for rt, res in results.items() if res["found"]
        ]

        return {
            "hostname": hostname,
            "results": results,
            "summary": {
                "total_found": len(types_with_records),
                "types_with_records": types_with_records,
            },
        }

    def domain_exists(self, hostname: str) -> bool:
        """
        Quick check: does the domain resolve to at least one A or AAAA record?

        Args:
            hostname: Domain to check.

        Returns:
            True if at least one A or AAAA record is found.
        """
        a_result = self.lookup(hostname, "A")
        if a_result["found"]:
            return True
        aaaa_result = self.lookup(hostname, "AAAA")
        return aaaa_result["found"]


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _parse_answers(record_type: str, answers: dns.resolver.Answer) -> list[dict]:
    """
    Convert dnspython answer objects to structured dictionaries.

    Args:
        record_type: The DNS record type string.
        answers:     dnspython Answer object.

    Returns:
        List of structured record dicts.
    """
    records: list[dict] = []

    for rdata in answers:
        if record_type == "A":
            records.append({"address": str(rdata)})

        elif record_type == "AAAA":
            records.append({"address": str(rdata)})

        elif record_type == "MX":
            records.append({
                "preference": int(rdata.preference),
                "exchange": str(rdata.exchange).rstrip("."),
            })

        elif record_type == "TXT":
            # TXT records can have multiple strings; join them
            txt_value = "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            records.append({"value": txt_value})

        elif record_type == "NS":
            records.append({"nameserver": str(rdata.target).rstrip(".")})

        else:
            records.append({"raw": str(rdata)})

    return records


def _not_found(hostname: str, record_type: str, error: str) -> dict:
    """Build a consistent 'not found' result dictionary."""
    logger.debug("DNS %s lookup failed for %s: %s", record_type, hostname, error)
    return {
        "hostname": hostname,
        "record_type": record_type,
        "records": [],
        "found": False,
        "error": error,
    }
