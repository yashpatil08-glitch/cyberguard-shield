"""
backend/utils/constants.py

Project-wide constants for CyberGuard.
Covers suspicious keywords, TLDs, URL shorteners, phishing indicators,
password scoring, and risk thresholds.
"""

# ---------------------------------------------------------------------------
# Suspicious Keywords (used in URL & phishing analysis)
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS: list[str] = [
    # Account / credential harvesting
    "login", "signin", "sign-in", "log-in", "logon", "log_in",
    "verify", "verification", "validate", "validation",
    "authenticate", "auth", "authorization",
    "account", "accounts", "myaccount", "account-update",
    "update", "confirm", "confirmation",
    "password", "passwd", "pwd", "reset", "recover", "recovery",

    # Financial / payment
    "banking", "bank", "secure-bank", "netbanking",
    "payment", "pay", "checkout", "billing", "invoice",
    "credit", "creditcard", "card", "debit",
    "wallet", "transfer", "wire", "refund",
    "paypal", "paytm", "gpay", "phonepay",

    # Identity / personal info
    "ssn", "social-security", "dob", "identity",
    "kyc", "aadhar", "aadhaar", "pan-card",
    "passport", "license",

    # Urgency / social engineering
    "urgent", "immediately", "alert", "warning",
    "suspended", "locked", "blocked", "limited",
    "action-required", "action_required", "required",
    "claim", "prize", "winner", "reward", "bonus",
    "free", "offer", "deal",

    # Support / helpdesk spoofs
    "support", "helpdesk", "helpcenter", "customer-service",
    "service-center", "live-chat",

    # Brand impersonation keywords
    "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "instagram", "twitter", "whatsapp", "telegram",
    "youtube", "linkedin", "dropbox", "icloud",
    "chase", "wellsfargo", "citibank", "barclays", "hsbc",
]

# ---------------------------------------------------------------------------
# Suspicious TLDs
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: list[str] = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs — heavily abused
    ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".space", ".fun",
    ".info", ".biz",
    ".icu", ".vip", ".loan", ".win",
    ".click", ".link", ".download",
    ".zip", ".mov",                        # New gTLDs misused for phishing
    ".review", ".trade", ".stream",
    ".work", ".party", ".racing",
    ".gdn", ".bid", ".accountant",
]

# ---------------------------------------------------------------------------
# URL Shortener Domains
# ---------------------------------------------------------------------------

URL_SHORTENER_DOMAINS: list[str] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lnkd.in",
    "db.tt", "qr.ae", "ow.ly", "su.pr", "twit.ac",
    "ity.im", "q.gs", "po.st", "bc.vc", "u.to",
    "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org",
    "x.co", "prettylinkpro.com", "viralurl.com",
    "cli.gs", "ff.im", "mcaf.ee", "dwarfurl.com",
    "vzturl.com", "qr.net", "1url.com", "tweez.me",
    "v.gd", "tr.im", "link.zip.net", "rb.gy", "shorturl.at",
]

# ---------------------------------------------------------------------------
# Phishing Indicators (weighted)
# Each entry: (indicator_label, risk_score_contribution)
# ---------------------------------------------------------------------------

PHISHING_INDICATORS: dict[str, int] = {
    "ip_in_url": 30,
    "punycode_detected": 25,
    "url_shortener": 20,
    "fake_login_keywords": 20,
    "suspicious_tld": 20,
    "too_many_subdomains": 15,
    "too_many_hyphens": 15,
    "excessive_dots": 15,
    "long_url": 10,
    "missing_https": 10,
    "at_symbol_in_url": 25,
    "double_slash_redirect": 15,
    "hex_encoding": 20,
    "unicode_characters": 15,
}

# ---------------------------------------------------------------------------
# Password Scoring Constants
# ---------------------------------------------------------------------------

# Minimum character class requirements
PASSWORD_MIN_LENGTH: int = 8
PASSWORD_GOOD_LENGTH: int = 12
PASSWORD_STRONG_LENGTH: int = 16

# Score weights
PASSWORD_SCORE_WEIGHTS: dict[str, int] = {
    "length_min": 10,           # Meets minimum length
    "length_good": 15,          # Meets good length
    "length_strong": 20,        # Meets strong length
    "has_uppercase": 10,
    "has_lowercase": 10,
    "has_digit": 10,
    "has_special": 15,
    "no_repeated_chars": 10,
    "no_sequential_chars": 10,
}

# Strength tiers (based on total score 0–100)
PASSWORD_STRENGTH_TIERS: dict[str, tuple[int, int]] = {
    "Very Weak":  (0, 19),
    "Weak":       (20, 39),
    "Fair":       (40, 59),
    "Strong":     (60, 79),
    "Very Strong":(80, 100),
}

# Crack time labels (seconds → label)
CRACK_TIME_LABELS: list[tuple[float, str]] = [
    (1e0,   "Less than a second"),
    (1e1,   "A few seconds"),
    (6e1,   "Less than a minute"),
    (3.6e3, "Less than an hour"),
    (8.64e4,"Less than a day"),
    (2.59e6,"Less than a month"),
    (3.15e7,"Less than a year"),
    (3.15e9,"A few years"),
    (float("inf"), "Centuries"),
]

# ---------------------------------------------------------------------------
# Risk Score Thresholds
# ---------------------------------------------------------------------------

RISK_THRESHOLDS: dict[str, tuple[int, int]] = {
    "Low":      (0, 25),
    "Medium":   (26, 50),
    "High":     (51, 75),
    "Critical": (76, 100),
}

# Maximum raw risk score before normalisation
RISK_MAX_SCORE: int = 100

# ---------------------------------------------------------------------------
# Security Header Scores
# ---------------------------------------------------------------------------

SECURITY_HEADER_WEIGHTS: dict[str, int] = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy":   20,
    "X-Frame-Options":           15,
    "X-Content-Type-Options":    15,
    "Referrer-Policy":           15,
    "Permissions-Policy":        15,
}

# ---------------------------------------------------------------------------
# SSL / TLS Constants
# ---------------------------------------------------------------------------

SSL_EXPIRY_WARNING_DAYS: int = 30      # Warn if cert expires within 30 days
SSL_EXPIRY_CRITICAL_DAYS: int = 7     # Critical if expires within 7 days

TRUSTED_TLS_VERSIONS: list[str] = ["TLSv1.2", "TLSv1.3"]
DEPRECATED_TLS_VERSIONS: list[str] = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

# ---------------------------------------------------------------------------
# HTTP Request Settings
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 10          # seconds
DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (compatible; CyberGuard/1.0; +https://cyberguard.app)"
)
MAX_REDIRECTS: int = 10

# ---------------------------------------------------------------------------
# DNS Record Types
# ---------------------------------------------------------------------------

SUPPORTED_DNS_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "NS"]

# ---------------------------------------------------------------------------
# WHOIS Constants
# ---------------------------------------------------------------------------

WHOIS_NEWLY_REGISTERED_DAYS: int = 30   # Flag domains < 30 days old
WHOIS_EXPIRING_SOON_DAYS: int = 60      # Flag if expiring within 60 days
