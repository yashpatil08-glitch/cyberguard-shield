"""
backend/utils/whois_lookup.py

WHOIS lookup utility for CyberGuard.
Returns registrar, creation/expiry dates, organisation, country,
and flags for newly registered or expiring domains.
"""

import logging
from datetime import datetime, timezone

import whois  # python-whois

from backend.utils.constants import (
    WHOIS_NEWLY_REGISTERED_DAYS,
    WHOIS_EXPIRING_SOON_DAYS,
)

logger = logging.getLogger(__name__)


class WHOISLookup:
    """
    Perform WHOIS lookups for a given domain.

    Usage:
        lookup = WHOISLookup()
        result = lookup.query("example.com")
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, domain: str) -> dict:
        """
        Retrieve WHOIS information for the given domain.

        Args:
            domain: Bare domain string, e.g. "example.com".

        Returns:
            dict with keys:
                - domain           (str)
                - registrar        (str | None)
                - creation_date    (str | None)  ISO-8601
                - expiry_date      (str | None)  ISO-8601
                - updated_date     (str | None)  ISO-8601
                - organization     (str | None)
                - country          (str | None)
                - name_servers     (list[str])
                - status           (list[str])
                - emails           (list[str])
                - dnssec           (str | None)
                - age_days         (int | None)
                - days_until_expiry(int | None)
                - newly_registered (bool)
                - expiring_soon    (bool)
                - found            (bool)
                - error            (str | None)
        """
        result: dict = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "organization": None,
            "country": None,
            "name_servers": [],
            "status": [],
            "emails": [],
            "dnssec": None,
            "age_days": None,
            "days_until_expiry": None,
            "newly_registered": False,
            "expiring_soon": False,
            "found": False,
            "error": None,
        }

        try:
            w = whois.whois(domain)

            if w is None or not w.domain_name:
                result["error"] = "No WHOIS data returned for this domain."
                return result

            result["found"] = True
            result["registrar"] = _first_str(w.registrar)
            result["organization"] = _first_str(w.org)
            result["country"] = _first_str(w.country)
            result["dnssec"] = _first_str(w.dnssec)

            # Name servers — normalise to lowercase list
            ns_raw = w.name_servers or []
            if isinstance(ns_raw, str):
                ns_raw = [ns_raw]
            result["name_servers"] = sorted({ns.lower().rstrip(".") for ns in ns_raw})

            # Status
            status_raw = w.status or []
            if isinstance(status_raw, str):
                status_raw = [status_raw]
            result["status"] = list(status_raw)

            # Emails
            emails_raw = w.emails or []
            if isinstance(emails_raw, str):
                emails_raw = [emails_raw]
            result["emails"] = list(set(emails_raw))

            # Dates
            creation = _extract_date(w.creation_date)
            expiry = _extract_date(w.expiration_date)
            updated = _extract_date(w.updated_date)

            now = datetime.now(tz=timezone.utc)

            if creation:
                result["creation_date"] = creation.isoformat()
                age_days = (now - creation).days
                result["age_days"] = max(0, age_days)
                result["newly_registered"] = age_days < WHOIS_NEWLY_REGISTERED_DAYS

            if expiry:
                result["expiry_date"] = expiry.isoformat()
                days_until_expiry = (expiry - now).days
                result["days_until_expiry"] = days_until_expiry
                result["expiring_soon"] = 0 < days_until_expiry <= WHOIS_EXPIRING_SOON_DAYS

            if updated:
                result["updated_date"] = updated.isoformat()

        except whois.parser.PywhoisError as exc:
            result["error"] = f"WHOIS parse error: {exc}"
            logger.warning("WHOIS parse error for %s: %s", domain, exc)

        except ConnectionError as exc:
            result["error"] = f"WHOIS connection failed: {exc}"
            logger.error("WHOIS connection error for %s: %s", domain, exc)

        except Exception as exc:
            result["error"] = f"Unexpected WHOIS error: {exc}"
            logger.error("Unexpected WHOIS error for %s: %s", domain, exc)

        return result


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

def _extract_date(value: object) -> datetime | None:
    """
    Extract a single timezone-aware datetime from a WHOIS date field,
    which may be a datetime, a list of datetimes, or None.

    Args:
        value: Raw WHOIS date value.

    Returns:
        Timezone-aware datetime or None.
    """
    if value is None:
        return None

    if isinstance(value, list):
        # python-whois sometimes returns a list; take the first valid entry
        for item in value:
            dt = _to_aware(item)
            if dt:
                return dt
        return None

    return _to_aware(value)


def _to_aware(value: object) -> datetime | None:
    """
    Convert a datetime to a UTC-aware datetime.

    Args:
        value: A datetime object (naive or aware), or unknown type.

    Returns:
        UTC-aware datetime or None.
    """
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _first_str(value: object) -> str | None:
    """
    Return the first non-empty string from a value that may be a string,
    list, or None.

    Args:
        value: Raw WHOIS field value.

    Returns:
        Stripped string or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            if item and isinstance(item, str):
                return item.strip()
        return None
    if isinstance(value, str):
        return value.strip() or None
    return str(value).strip() or None
