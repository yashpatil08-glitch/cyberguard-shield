"""
backend/services/password_strength.py

Password Strength Analyser for CyberGuard.
Calculates entropy, detects common patterns, estimates crack time,
and provides actionable improvement suggestions.
"""

import math
import logging
import re
import string

from backend.utils.constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_GOOD_LENGTH,
    PASSWORD_STRONG_LENGTH,
    PASSWORD_SCORE_WEIGHTS,
    PASSWORD_STRENGTH_TIERS,
    CRACK_TIME_LABELS,
)

logger = logging.getLogger(__name__)

# Common passwords / dictionary words (subset for lightweight detection)
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "admin", "welcome", "login", "test",
    "hello", "charlie", "donald", "password2", "qwerty123", "admin123",
})

# Sequential character sequences to detect
_SEQUENCES: list[str] = [
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnm",  # keyboard row
    "0123456789",
]

# Attacker guess rate (bcrypt-level, conservative)
_GUESSES_PER_SECOND: float = 1e4


class PasswordStrengthAnalyzer:
    """
    Analyses password strength using entropy, pattern detection,
    and heuristic scoring.

    Usage:
        analyser = PasswordStrengthAnalyzer()
        result = analyser.analyze("MyP@ssw0rd!")
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> dict:
        """
        Perform a full strength analysis of the given password.

        Args:
            password: The password string to analyse.

        Returns:
            JSON-compatible dict with keys:
                - length              (int)
                - entropy             (float): bits of entropy
                - charset_size        (int): size of the character pool used
                - has_uppercase       (bool)
                - has_lowercase       (bool)
                - has_digits          (bool)
                - has_special         (bool)
                - has_repeated_chars  (bool)
                - has_sequential_chars(bool)
                - is_common_password  (bool)
                - score               (int): 0–100
                - strength            (str): "Very Weak" … "Very Strong"
                - crack_time_estimate (str): human-readable
                - crack_seconds       (float)
                - suggestions         (list[str])
        """
        if not isinstance(password, str):
            return {"error": "Password must be a string."}

        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        repeated = _has_repeated_chars(password)
        sequential = _has_sequential_chars(password)
        is_common = password.lower() in _COMMON_PASSWORDS

        charset_size = _compute_charset_size(has_upper, has_lower, has_digits, has_special)
        entropy = _compute_entropy(length, charset_size)
        crack_seconds = _estimate_crack_seconds(entropy)
        crack_label = _crack_time_label(crack_seconds)
        score = _compute_score(
            length, has_upper, has_lower, has_digits, has_special,
            repeated, sequential, is_common
        )
        strength = _get_strength_tier(score)
        suggestions = _build_suggestions(
            length, has_upper, has_lower, has_digits, has_special,
            repeated, sequential, is_common
        )

        return {
            "length": length,
            "entropy": round(entropy, 2),
            "charset_size": charset_size,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digits,
            "has_special": has_special,
            "has_repeated_chars": repeated,
            "has_sequential_chars": sequential,
            "is_common_password": is_common,
            "score": score,
            "strength": strength,
            "crack_time_estimate": crack_label,
            "crack_seconds": crack_seconds,
            "suggestions": suggestions,
        }


# ---------------------------------------------------------------------------
# Private Functions
# ---------------------------------------------------------------------------

def _compute_charset_size(upper: bool, lower: bool, digits: bool, special: bool) -> int:
    """Calculate the effective character pool size."""
    size = 0
    if upper:
        size += 26
    if lower:
        size += 26
    if digits:
        size += 10
    if special:
        size += 32  # printable ASCII special chars
    return max(size, 1)


def _compute_entropy(length: int, charset: int) -> float:
    """
    Calculate Shannon entropy in bits.

    H = L × log2(N)  where L = length, N = charset size.
    """
    if length == 0 or charset == 0:
        return 0.0
    return length * math.log2(charset)


def _estimate_crack_seconds(entropy: float) -> float:
    """
    Estimate offline brute-force crack time in seconds.

    Assumes the attacker tries at _GUESSES_PER_SECOND.
    On average, half the keyspace must be searched.

    Args:
        entropy: Entropy in bits.

    Returns:
        Estimated crack time in seconds.
    """
    if entropy <= 0:
        return 0.0
    total_combinations = 2 ** entropy
    return total_combinations / (2 * _GUESSES_PER_SECOND)


def _crack_time_label(seconds: float) -> str:
    """Convert crack time in seconds to a human-readable label."""
    for threshold, label in CRACK_TIME_LABELS:
        if seconds < threshold:
            return label
    return "Centuries"


def _has_repeated_chars(password: str) -> bool:
    """
    Return True if the password contains 3 or more consecutive identical characters.

    e.g. "aaab" → True
    """
    return bool(re.search(r'(.)\1{2,}', password))


def _has_sequential_chars(password: str, min_len: int = 4) -> bool:
    """
    Return True if the password contains a sequential run of min_len or more
    characters from a known sequence (alphabet, numbers, keyboard rows).

    Args:
        password: Password string.
        min_len:  Minimum sequential run length to flag (default 4).

    Returns:
        True if a sequential run is detected.
    """
    lower = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i:i + min_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def _compute_score(
    length: int,
    upper: bool,
    lower: bool,
    digits: bool,
    special: bool,
    repeated: bool,
    sequential: bool,
    is_common: bool,
) -> int:
    """
    Compute a 0–100 strength score using defined weights and penalties.

    Args:
        All password properties as booleans / int.

    Returns:
        Integer score clamped to 0–100.
    """
    score = 0
    w = PASSWORD_SCORE_WEIGHTS

    # Length bonuses
    if length >= PASSWORD_MIN_LENGTH:
        score += w["length_min"]
    if length >= PASSWORD_GOOD_LENGTH:
        score += w["length_good"]
    if length >= PASSWORD_STRONG_LENGTH:
        score += w["length_strong"]

    # Character class bonuses
    if upper:
        score += w["has_uppercase"]
    if lower:
        score += w["has_lowercase"]
    if digits:
        score += w["has_digit"]
    if special:
        score += w["has_special"]

    # Pattern penalties
    if not repeated:
        score += w["no_repeated_chars"]
    if not sequential:
        score += w["no_sequential_chars"]

    # Common password hard penalty
    if is_common:
        score = max(0, score - 40)

    return max(0, min(score, 100))


def _get_strength_tier(score: int) -> str:
    """Map a score to a strength tier label."""
    for tier, (low, high) in PASSWORD_STRENGTH_TIERS.items():
        if low <= score <= high:
            return tier
    return "Very Weak"


def _build_suggestions(
    length: int,
    upper: bool,
    lower: bool,
    digits: bool,
    special: bool,
    repeated: bool,
    sequential: bool,
    is_common: bool,
) -> list[str]:
    """Build an ordered list of improvement suggestions."""
    suggestions: list[str] = []

    if is_common:
        suggestions.append("This is a very common password. Choose something unique immediately.")

    if length < PASSWORD_MIN_LENGTH:
        suggestions.append(f"Use at least {PASSWORD_MIN_LENGTH} characters.")
    elif length < PASSWORD_GOOD_LENGTH:
        suggestions.append(f"Increase length to at least {PASSWORD_GOOD_LENGTH} characters for better security.")
    elif length < PASSWORD_STRONG_LENGTH:
        suggestions.append(f"Consider using {PASSWORD_STRONG_LENGTH}+ characters for maximum strength.")

    if not upper:
        suggestions.append("Add uppercase letters (A–Z).")
    if not lower:
        suggestions.append("Add lowercase letters (a–z).")
    if not digits:
        suggestions.append("Include numbers (0–9).")
    if not special:
        suggestions.append("Include special characters (e.g. @, #, $, !).")
    if repeated:
        suggestions.append("Avoid repeating the same character 3 or more times in a row.")
    if sequential:
        suggestions.append("Avoid sequential patterns like 'abcd' or '1234'.")

    if not suggestions:
        suggestions.append("Great password! Consider using a password manager to store it securely.")

    return suggestions
