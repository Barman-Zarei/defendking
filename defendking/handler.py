"""
DefendKing - Defensive Security Toolkit
=========================================

A professional, purely DEFENSIVE security toolkit for Python.

Scope (important):
    Every function in this file is designed to PROTECT, DETECT, or REPORT.
    None of them attack, exploit, brute-force, or gain unauthorized access
    to any system. Functions that need a "target" (e.g. TLS check, header
    check) are meant to be run against systems you own or are authorized
    to assess.

Error-handling convention (added in 2.5.1):
    - Programmer errors (wrong argument type, empty required value, value
      out of range) raise `InvalidInputError` immediately (see
      `defendking.exceptions`). These are bugs in the calling code and are
      never silently swallowed.
    - External-world failures (network down, DNS lookup failed, file
      missing/unreadable, third-party API error):
        * For functions that already return a dict, the failure is caught
          and reported inline as part of that dict, e.g.
          `{"error": "...", "error_type": "ExternalServiceError"}`,
          alongside whatever partial result makes sense (the function
          does not raise).
        * For functions whose normal return type is a plain scalar (a
          hash string, a bool, a list) wrapping the result in a dict just
          to carry an error would silently change the API's shape on
          every call site, which is worse than raising. These instead
          raise `ExternalServiceError` with the original exception
          chained via `from exc`, so callers can do a single
          `except ExternalServiceError:` regardless of whether the
          underlying failure was a `socket.error`, `OSError`, or a
          `requests` exception.
    Each function's docstring says explicitly which of the two applies.

Known limitations (read before relying on this in production):
    - Several checks (XSS/SQLi/phishing detection) are regex-based
      heuristics. Heuristics are fast and dependency-free, but they are
      NOT a substitute for a real parser/AST-based tool (e.g. an ORM with
      parameterized queries for SQLi, or a proper HTML sanitizer such as
      `bleach` for XSS). Use these functions as an extra signal, not as
      your only line of defense.
    - The bundled common-password list is intentionally small (a top-N
      sample). For real breach coverage, `check_password_breached` calls
      the Have I Been Pwned API by default; the local list is only a
      fallback when that API is unavailable.
    - `detect_anomalous_login_location` falls back to a conservative fixed
      distance when no real coordinates are supplied. Pass real
      latitude/longitude pairs (via `distance_km_between`) for an accurate
      "impossible travel" calculation.

Optional third-party dependencies (only needed for a few functions):
    pip install requests cryptography pyjwt

Author: Barman
License: MIT
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import socket
import ssl
import string
import threading
import time
import unicodedata
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .exceptions import ExternalServiceError, InvalidInputError

# --------------------------------------------------------------------------
# Module-level logger. Consumers of the package can configure handlers;
# we only attach a NullHandler so importing this module is silent by default.
# --------------------------------------------------------------------------
logger = logging.getLogger("defendking")
logger.addHandler(logging.NullHandler())


def _require_type(value: Any, expected_type: type | tuple, name: str) -> None:
    """Internal helper: raise InvalidInputError with a clear message if the type is wrong."""
    if not isinstance(value, expected_type):
        type_name = expected_type.__name__ if isinstance(expected_type, type) else " or ".join(t.__name__ for t in expected_type)
        raise InvalidInputError(f"{name} must be a {type_name}, got {type(value).__name__}")


def _require_nonempty_str(value: Any, name: str) -> None:
    """Internal helper: raise InvalidInputError if `value` isn't a non-empty string."""
    _require_type(value, str, name)
    if not value.strip():
        raise InvalidInputError(f"{name} must not be empty")


# Functions that run a battery of regex patterns against caller-supplied
# text (XSS/SQLi/URL/email/password scanning) cap the input length before
# scanning. This isn't about "how long is realistic" - it's a ReDoS
# mitigation: several of the patterns below use bounded-but-nested
# quantifiers (e.g. repeated-group detection), and worst-case backtracking
# cost grows with input length. Capping input size bounds the worst case
# regardless of which specific pattern a future edit might introduce.
_MAX_SCANNED_TEXT_LENGTH = 20_000
# Email bodies/free text blocks are legitimately much longer than a URL or
# password, so they get a separate, higher cap rather than sharing the
# tighter limit above.
_MAX_LONG_TEXT_LENGTH = 200_000


def _require_scannable_text(value: Any, name: str, max_length: int = _MAX_SCANNED_TEXT_LENGTH) -> None:
    """Internal helper: validate a string that's about to be run through
    multiple regexes (ReDoS mitigation - see _MAX_SCANNED_TEXT_LENGTH)."""
    _require_type(value, str, name)
    if len(value) > max_length:
        raise InvalidInputError(
            f"{name} is {len(value)} characters, which exceeds the {max_length}-character "
            f"limit for regex-based scanning functions (this limit exists to bound worst-case regex cost - "
            f"split large input into chunks if you need to scan more)"
        )


def _luhn_checksum_valid(digits: str) -> bool:
    """
    Internal helper: validate a digit string against the Luhn algorithm
    (used by real card numbers). Used to avoid flagging arbitrary
    13-19-digit numbers (phone numbers, IDs, timestamps) as credit card
    numbers - only numbers that actually pass the checksum are redacted
    as a "card number", which cuts down on false positives substantially.
    """
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _with_retry(func, retries: int = 2, backoff_seconds: float = 0.5):
    """
    Internal helper: call `func()` and retry on transient network errors
    (timeouts, connection resets, temporary DNS failures) with a short
    linear backoff between attempts. Used by the network-facing functions
    in sections 2/6 so a single dropped packet doesn't get reported as a
    hard failure - the underlying exception is re-raised unchanged after
    the final attempt so callers see the real error, not a wrapper.
    """
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return func()
        except (TimeoutError, ConnectionError, socket.gaierror, socket.timeout, OSError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff_seconds * (attempt + 1))
    assert last_exc is not None
    raise last_exc


# ==========================================================================
# SECTION 1 - PASSWORDS & AUTHENTICATION
# ==========================================================================

# NOTE: this is a small illustrative sample, not a real breach corpus.
# `check_password_breached` should be your primary check (it queries the
# HIBP Pwned Passwords API); this list is only the offline fallback.
_COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "696969", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "password1", "iloveyou", "admin", "welcome", "monkey123", "login",
    "princess", "solo", "starwars", "freedom", "whatever", "trustno1",
    "sunshine", "superman", "hello", "charlie", "aa123456", "donald",
    "michael", "jennifer", "jordan23", "hunter2", "letmein1", "passw0rd",
    "qazwsx", "zaq1zaq1", "1qaz2wsx", "abcd1234", "asdf1234", "changeme",
    "default", "guest123", "temp1234", "test1234", "root123", "admin123",
    "user1234", "ninja", "batman", "121212", "654321", "000000",
    "1q2w3e4r", "7777777", "1qazxsw2", "google", "access", "flower",
    "hottie", "loveme", "biteme", "chelsea", "matrix", "harley",
    "iloveu", "computer", "corvette", "buster", "thomas", "robert",
    # --- expanded for 2.5.1: broader top-breached-password coverage ---
    "123123123", "1234512345", "111111111", "aaaaaaaa", "asdfghjkl",
    "password123", "passw0rd1", "p@ssw0rd", "iloveyou1", "welcome1",
    "welcome123", "abcdefgh", "abcdefg", "qwerty123", "qwerty1234",
    "letme1n", "trustno1a", "starwars1", "michael1", "shadow1",
    "baseball1", "dragon1", "master1", "sunshine1", "football1",
    "1qaz2wsx3edc", "zxcvbnm", "poiuytrewq", "mynoob", "654321a",
    "121212a", "qwe123", "qwe12345", "asd123", "asd12345", "test123",
    "demo1234", "changeme123", "temppass", "temppass123", "newpass123",
    "spring2024", "summer2024", "winter2024", "autumn2024", "january1",
    "iloveyou2", "whatever1", "freedom1", "superman1", "batman1",
    "ninja123", "princess1", "solo123", "corvette1", "cheese123",
    "letmeinnow", "opensesame", "sesame123", "unicorn1", "pokemon123",
    "minecraft1", "fortnite1", "roblox123", "discord123", "spotify123",
    "netflix123", "amazon123", "google123", "facebook1", "instagram1",
    "twitter123", "yahoo123", "hotmail123", "gmail123", "outlook123",
}



def check_password_strength(password: str) -> dict[str, Any]:
    """
    Score a password's strength on a 0-100 scale using length, character-
    class diversity, estimated entropy, and known weak-pattern detection
    (NOT a substitute for a breach check - see `check_password_breached`).

    Note on `entropy_bits`: this is a charset-size-based estimate
    (log2(charset_size) * length), which assumes characters are drawn
    uniformly at random from whatever classes are present. A real
    dictionary-and-pattern-aware estimator (e.g. zxcvbn) will score
    something like "Password1!" far lower than this formula alone would,
    because it recognizes "Password" as a dictionary word - this function
    covers part of that gap via `detect_common_password_patterns` (whose
    findings reduce `score` directly), but the `entropy_bits` number
    itself does not account for dictionary words on its own. Treat
    `entropy_bits` as a rough signal, and `score`/`label` (which combine
    it with pattern detection) as the more reliable overall verdict.

    Raises `InvalidInputError` if `password` isn't a string.
    Returns a dict with `score`, `label`, `entropy_bits`, and `suggestions`.
    """
    _require_type(password, str, "password")
    if password == "":
        return {"score": 0, "label": "weak", "entropy_bits": 0.0, "suggestions": ["Password is empty."]}
    if len(password) > _MAX_SCANNED_TEXT_LENGTH:
        raise InvalidInputError(f"password is unreasonably long ({len(password)} chars) for a strength check")

    length = len(password)
    classes = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^\w\s]", password)),
        "space": bool(re.search(r"\s", password)),
    }
    class_count = sum(v for k, v in classes.items() if k != "space")

    # Estimate charset size actually used, for a rough log2-based entropy
    # figure (bits) - a more information-theoretic signal than just class
    # counting, and it scales properly with length.
    charset_size = 0
    charset_size += 26 if classes["lower"] else 0
    charset_size += 26 if classes["upper"] else 0
    charset_size += 10 if classes["digit"] else 0
    charset_size += 32 if classes["symbol"] else 0
    charset_size += 1 if classes["space"] else 0
    entropy_bits = round(length * math.log2(max(charset_size, 2)), 1)

    score = min(length * 4, 40)          # up to 40 points for length
    score += class_count * 12            # up to 48 points for diversity
    score += 12 if length >= 12 else 0   # bonus for solid length
    score = min(score, 100)

    suggestions = []
    if length < 12:
        suggestions.append("Increase the password length to at least 12 characters.")
    if not classes["upper"]:
        suggestions.append("Add at least one uppercase letter.")
    if not classes["digit"]:
        suggestions.append("Add at least one digit.")
    if not classes["symbol"]:
        suggestions.append("Add at least one special symbol (!@#...).")
    if entropy_bits < 28:
        suggestions.append(f"Estimated entropy is low (~{entropy_bits} bits) - this is crackable offline in a short time.")

    # Cross-check against the pattern detector so a password that merely
    # "looks" diverse (e.g. "Qwerty123!") doesn't score as strong.
    pattern_issues = detect_common_password_patterns(password)
    score -= min(len(pattern_issues) * 15, score)  # never go below 0 here
    suggestions.extend(pattern_issues)

    if password.lower() in _COMMON_PASSWORDS:
        score = min(score, 10)

    label = "weak" if score < 40 else "medium" if score < 70 else "strong"
    return {"score": score, "label": label, "entropy_bits": entropy_bits, "suggestions": suggestions}


def check_password_breached(password: str, use_api: bool = True) -> dict[str, Any]:
    """
    Check whether a password appears in known breach corpora using the
    "k-anonymity" model of the Have I Been Pwned Pwned Passwords API
    (only the first 5 chars of the SHA-1 hash are ever sent - the real
    password / full hash never leaves this machine).

    Raises `InvalidInputError` if `password` isn't a string.
    If `use_api` is False, or the network request fails, falls back to
    checking against the small local common-password list; a network
    failure is reported via `error`/`error_type` in the returned dict
    rather than raised, since falling back is the expected behavior.
    """
    _require_type(password, str, "password")

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    api_error = None

    if use_api:
        try:
            import requests  # optional dependency

            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5,
                headers={"User-Agent": "DefendKing-Security-Tool"},
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return {"breached": True, "times_seen": int(count), "source": "hibp"}
            return {"breached": False, "times_seen": 0, "source": "hibp"}
        except Exception as exc:  # network / dependency issues -> fall back
            api_error = ExternalServiceError(f"HIBP lookup failed: {exc}")
            logger.warning("HIBP lookup failed, falling back to local list: %s", exc)

    breached = password.lower() in _COMMON_PASSWORDS
    result = {"breached": breached, "times_seen": None, "source": "local_list"}
    if api_error is not None:
        result["error"] = str(api_error)
        result["error_type"] = "ExternalServiceError"
    return result


def generate_strong_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    Generate a cryptographically secure random password.
    Raises `InvalidInputError` if `length` isn't an int >= 8.
    """
    _require_type(length, int, "length")
    if length < 8:
        raise InvalidInputError("length must be at least 8")

    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"

    # Guarantee at least one char from each required class.
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        password_chars.append(secrets.choice("!@#$%^&*()-_=+"))

    password_chars += [secrets.choice(alphabet) for _ in range(length - len(password_chars))]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def hash_password(password: str) -> str:
    """
    Hash a password for storage using PBKDF2-HMAC-SHA256 with a random salt.
    Returns a single string: "pbkdf2_sha256$iterations$salt_b64$hash_b64".
    Raises `InvalidInputError` if `password` isn't a string.

    (For production systems prefer a maintained library like `argon2-cffi`
    or Django's built-in password hashers - this is a dependency-free,
    from-scratch reference implementation.)
    """
    _require_type(password, str, "password")
    iterations = 260_000
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a hash produced by `hash_password`.
    Raises `InvalidInputError` if either argument isn't a string, or if
    `stored_hash` isn't in the expected "pbkdf2_sha256$..." format (a
    malformed stored hash is a caller/data bug, not a recoverable runtime
    condition, so this raises rather than silently returning False).
    """
    _require_type(password, str, "password")
    _require_type(stored_hash, str, "stored_hash")
    try:
        algo, iterations_s, salt_b64, hash_b64 = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            raise ValueError("unsupported hash algorithm")
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError) as exc:
        raise InvalidInputError("stored_hash has an invalid format") from exc

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)  # timing-safe comparison


_LEET_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def detect_common_password_patterns(password: str) -> list[str]:
    """
    Flag common weak patterns: keyboard walks, repeats, sequences, dates,
    leetspeak substitutions of common words, and short repeated blocks.
    Raises `InvalidInputError` if `password` isn't a string.
    """
    _require_scannable_text(password, "password")
    issues = []
    lowered = password.lower()
    de_leeted = lowered.translate(_LEET_SUBSTITUTIONS)

    if lowered in _COMMON_PASSWORDS:
        issues.append("Appears in the common-password list")
    elif de_leeted in _COMMON_PASSWORDS:
        issues.append("Is a common password with characters substituted (leetspeak), e.g. p@ssw0rd")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains a repeated character run (e.g. aaa)")
    if re.search(r"(.{2,4})\1{1,}", lowered):
        issues.append("Contains a repeated multi-character block (e.g. abcabc)")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", password):
        issues.append("Contains a simple numeric sequence")
    if re.search(r"(abcd|bcde|cdef|defg|efgh|wxyz|zyxw|dcba)", lowered):
        issues.append("Contains a simple alphabetic sequence")
    if re.search(r"(qwerty|qwertz|azerty|asdf|asdfg|zxcv|qazwsx|1qaz|2wsx|poiuy|lkjh|741852|123qwe|qweasd)", lowered):
        issues.append("Contains a keyboard-walk pattern")
    if re.search(r"(19|20)\d{2}", password):
        issues.append("Likely contains a birth year or date")
    if re.search(r"(0[1-9]|1[0-2])[/\-.](0[1-9]|[12]\d|3[01])", password):
        issues.append("Likely contains a date (MM/DD or similar)")
    if re.fullmatch(r"\d+", password):
        issues.append("Consists entirely of digits (very low entropy)")
    if re.fullmatch(r"[a-zA-Z]+", password) and len(set(lowered)) <= 4:
        issues.append("Consists entirely of letters with very few distinct characters")
    if re.search(r"\d{1,4}$", password) and re.match(r"^[a-zA-Z]+", password) and lowered.rstrip(string.digits) in _COMMON_PASSWORDS:
        issues.append("A common word with a short numeric suffix appended (e.g. word123)")

    return issues


def check_two_factor_status(is_enabled_flag: bool, backup_codes_count: int = 0) -> dict[str, Any]:
    """
    Evaluate a user's 2FA posture given data already fetched from your own
    service's API/database (this function does not contact any service
    itself - it only interprets flags you already have).
    Raises `InvalidInputError` if `backup_codes_count` is negative.
    """
    _require_type(backup_codes_count, int, "backup_codes_count")
    if backup_codes_count < 0:
        raise InvalidInputError("backup_codes_count cannot be negative")
    return {
        "enabled": bool(is_enabled_flag),
        "has_backup_codes": backup_codes_count > 0,
        "low_on_backup_codes": 0 < backup_codes_count <= 2,
        "recommendation": (
            "Good posture" if is_enabled_flag and backup_codes_count > 0
            else "Enabling 2FA and saving backup codes is recommended"
        ),
    }


def check_password_expiry(last_changed: datetime, max_age_days: int = 90) -> dict[str, Any]:
    """
    Determine whether a password is past its recommended rotation age.
    Raises `InvalidInputError` if `last_changed` isn't a `datetime` or
    `max_age_days` isn't a positive int.
    """
    _require_type(last_changed, datetime, "last_changed")
    _require_type(max_age_days, int, "max_age_days")
    if max_age_days <= 0:
        raise InvalidInputError("max_age_days must be positive")
    if last_changed.tzinfo is None:
        last_changed = last_changed.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - last_changed).days
    expired = age_days > max_age_days
    return {
        "age_days": age_days,
        "max_age_days": max_age_days,
        "expired": expired,
        "nearing_expiry": not expired and age_days > max_age_days * 0.9,
        "days_remaining": max(max_age_days - age_days, 0),
    }


def validate_password_policy_compliance(password: str, policy: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Check a password against an organizational policy dict, e.g.:
        {"min_length": 12, "require_upper": True, "require_digit": True,
         "require_symbol": True, "disallow_common": True, "max_length": 128}
    Raises `InvalidInputError` if `password` isn't a string or `policy`
    isn't a dict/None.
    """
    _require_type(password, str, "password")
    if policy is not None:
        _require_type(policy, dict, "policy")
    policy = policy or {
        "min_length": 12,
        "require_upper": True,
        "require_digit": True,
        "require_symbol": True,
        "disallow_common": True,
    }
    violations = []

    if len(password) < policy.get("min_length", 12):
        violations.append(f"Length must be at least {policy.get('min_length', 12)}")
    if "max_length" in policy and len(password) > policy["max_length"]:
        violations.append(f"Length must not exceed {policy['max_length']}")
    if policy.get("require_upper") and not re.search(r"[A-Z]", password):
        violations.append("An uppercase letter is required")
    if policy.get("require_lower") and not re.search(r"[a-z]", password):
        violations.append("A lowercase letter is required")
    if policy.get("require_digit") and not re.search(r"\d", password):
        violations.append("A digit is required")
    if policy.get("require_symbol") and not re.search(r"[^\w\s]", password):
        violations.append("A special symbol is required")
    if policy.get("disallow_common", True) and password.lower() in _COMMON_PASSWORDS:
        violations.append("Password is in the common-password list")
    if policy.get("disallow_common_patterns", True) and detect_common_password_patterns(password):
        violations.append("Password contains a common weak pattern (sequence, keyboard walk, or repeat)")

    return {"compliant": len(violations) == 0, "violations": violations}


def check_default_credentials(username: str, password: str) -> bool:
    """
    Check a username/password pair against a known list of factory-default
    credentials (e.g. admin/admin) so you can flag devices/accounts that
    were never reconfigured after install.
    Raises `InvalidInputError` if either argument isn't a string.
    """
    _require_type(username, str, "username")
    _require_type(password, str, "password")
    known_defaults = {
        ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
        ("admin", "1234"), ("admin", "1234567"), ("admin", "pass"),
        ("admin", "admin123"), ("admin", "letmein"), ("admin", "changeme"),
        ("root", "root"), ("root", "toor"), ("root", "admin"),
        ("root", "password"), ("root", "raspberry"),
        ("administrator", "administrator"), ("administrator", "password"),
        ("user", "user"), ("guest", "guest"), ("guest", ""),
        ("pi", "raspberry"), ("ubnt", "ubnt"), ("cisco", "cisco"),
        ("service", "service"), ("support", "support"),
        ("admin", ""), ("", "admin"), ("default", "default"),
        ("operator", "operator"), ("manager", "manager"), ("tech", "tech"),
        ("supervisor", "supervisor"), ("admin", "1qaz2wsx"),
    }
    return (username.lower(), password.lower()) in known_defaults


# ==========================================================================
# SECTION 2 - PHISHING & URL / EMAIL SAFETY
# ==========================================================================

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id", "lnkd.in",
}
_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click",
    "link", "support", "men", "review", "loan", "download", "stream", "info",
    "biz", "icu", "cam", "monster",
}
_HIGH_VALUE_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "bankofamerica", "wellsfargo", "chase", "irs", "dhl", "fedex",
}


_OPEN_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl", "return_url", "goto", "dest", "destination", "continue", "target", "u"}


def _has_mixed_script_homograph(netloc: str) -> bool:
    """
    Detect a domain that mixes Latin characters with look-alike characters
    from another script (e.g. Cyrillic 'а' U+0430 instead of Latin 'a') -
    a classic homograph/IDN spoofing technique. Flags mixing of scripts
    within a single label, which legitimate domains essentially never do.
    """
    labels = netloc.split(".")
    for label in labels:
        scripts = set()
        for ch in label:
            if ch.isalpha():
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    continue
                if "LATIN" in name:
                    scripts.add("LATIN")
                elif "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
        if len(scripts) > 1:
            return True
    return False


def check_suspicious_url(url: str) -> dict[str, Any]:
    """
    Heuristic scan of a URL for common phishing red flags. Raises
    `InvalidInputError` if `url` isn't a non-empty string.

    NOTE: this is a regex/rule-based heuristic, not a real classifier -
    it will miss novel phishing techniques and can flag legitimate URLs.
    Use it as one signal among several (e.g. combine with
    `check_domain_similarity` and a reputation/block-list API).

    Returns a `risk_score` (0-100, weighted sum of the triggered signals,
    capped at 100) in addition to the plain `suspicious` boolean, so
    callers can rank multiple URLs by severity instead of only a yes/no.
    """
    _require_nonempty_str(url, "url")
    _require_scannable_text(url, "url")
    # weight, reason-builder pairs accumulate into a 0-100 risk score
    weighted_reasons: list[tuple[int, str]] = []
    lowered = url.lower()
    netloc = lowered.split("//")[-1].split("/")[0]

    if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", lowered):
        weighted_reasons.append((25, "Uses a raw IP address instead of a domain name"))
    if re.search(r"://0x[0-9a-f]+", lowered) or re.search(r"://\d{8,10}(?:[:/]|$)", lowered):
        weighted_reasons.append((25, "Uses a hex/decimal-encoded IP address (obfuscation technique)"))
    if "@" in url.split("//")[-1]:
        weighted_reasons.append((25, "Contains an '@' character in the URL (used to hide the real destination)"))
    if any(short in lowered for short in _URL_SHORTENERS):
        weighted_reasons.append((10, "Uses a link-shortening service"))
    if not lowered.startswith("https://"):
        weighted_reasons.append((10, "Connection is not encrypted (HTTPS)"))
    if "xn--" in netloc:
        weighted_reasons.append((20, "Uses punycode (xn--) - can hide look-alike/homograph domains"))
    if _has_mixed_script_homograph(netloc):
        weighted_reasons.append((30, "Domain mixes multiple alphabets (e.g. Latin + Cyrillic look-alikes) - homograph spoofing"))
    tld = lowered.rstrip("/").rsplit(".", 1)[-1].split("/")[0].split("?")[0]
    if tld in _SUSPICIOUS_TLDS:
        weighted_reasons.append((10, f"Suspicious top-level domain (.{tld})"))
    if lowered.count("-") > 4:
        weighted_reasons.append((10, "Unusually many hyphens in the domain (common in spoofed domains)"))
    if netloc.count(".") >= 4:
        weighted_reasons.append((10, "Unusually deep subdomain nesting (can hide the real domain)"))
    if re.search(r":\d{2,5}(?:/|$)", netloc) and not re.search(r":(?:80|443)(?:/|$)", netloc):
        weighted_reasons.append((10, "Uses a non-standard port number"))
    brand_in_text = [b for b in _HIGH_VALUE_BRANDS if b in netloc]
    if brand_in_text and not any(netloc == b + tld_suffix for b in brand_in_text for tld_suffix in (".com", ".org", ".net")):
        if "-" in netloc or netloc.count(".") >= 2:
            weighted_reasons.append((30, f"Mentions a well-known brand ({brand_in_text[0]}) in a domain that isn't its official one"))
    redirect_match = re.search(r"[?&](\w+)=(https?(?:%3a|:)[^&]*)", lowered)
    if redirect_match and redirect_match.group(1) in _OPEN_REDIRECT_PARAMS:
        weighted_reasons.append((15, f"Query parameter '{redirect_match.group(1)}' points to another URL (possible open-redirect abuse)"))

    reasons = [r for _, r in weighted_reasons]
    risk_score = min(sum(w for w, _ in weighted_reasons), 100)
    return {"url": url, "suspicious": len(reasons) > 0, "risk_score": risk_score, "reasons": reasons}


# Common visual look-alike substitutions used in homograph/typosquat domains
# (e.g. "paypa1.com" or "rnicrosoft.com"). Normalizing these before computing
# edit distance catches lookalikes that a raw character-diff would miss.
_HOMOGLYPH_NORMALIZATION = [
    ("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("5", "s"), ("3", "e"),
    ("!", "i"), ("|", "l"),
]


def _normalize_homoglyphs(text: str) -> str:
    normalized = text
    for pattern, replacement in _HOMOGLYPH_NORMALIZATION:
        normalized = normalized.replace(pattern, replacement)
    return normalized


def check_domain_similarity(domain: str, trusted_domains: Iterable[str]) -> dict[str, Any]:
    """
    Detect typosquatting by computing Levenshtein distance between `domain`
    and each trusted domain, both as written and after normalizing common
    homoglyph substitutions (rn->m, 1->l, 0->o, ...). A small distance (1-2)
    with a different domain is a strong phishing signal. Also flags the
    trusted brand name appearing as a *substring* inside a longer domain
    (e.g. "paypal-secure-verify.com"), which plain edit distance misses,
    and flags a trusted brand name combined with a different TLD (e.g.
    "paypal.net" when only "paypal.com" is trusted).
    Raises `InvalidInputError` if `domain` isn't a non-empty string.
    """
    _require_nonempty_str(domain, "domain")
    trusted_domains = list(trusted_domains)

    def levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
            prev = curr
        return prev[-1]

    domain_lower = domain.lower()
    domain_normalized = _normalize_homoglyphs(domain_lower)
    domain_root = domain_lower.split(".")[0]

    closest, best_dist, matched_as_homoglyph = None, float("inf"), False
    substring_match = None
    tld_swap_match = None
    for trusted in trusted_domains:
        trusted_lower = trusted.lower()
        trusted_root = trusted_lower.split(".")[0]

        raw_dist = levenshtein(domain_lower, trusted_lower)
        homoglyph_dist = levenshtein(domain_normalized, _normalize_homoglyphs(trusted_lower))
        dist = min(raw_dist, homoglyph_dist)
        if dist < best_dist:
            closest, best_dist = trusted, dist
            matched_as_homoglyph = homoglyph_dist < raw_dist

        if (
            substring_match is None
            and domain_lower != trusted_lower
            and len(trusted_root) >= 4
            and trusted_root in domain_lower
        ):
            substring_match = trusted

        if tld_swap_match is None and domain_root == trusted_root and domain_lower != trusted_lower:
            tld_swap_match = trusted

    is_typosquat = (
        (closest is not None and best_dist <= 2 and domain_lower != closest.lower())
        or substring_match is not None
        or tld_swap_match is not None
    )
    return {
        "domain": domain,
        "closest_trusted": substring_match or tld_swap_match or closest,
        "distance": best_dist,
        "likely_typosquat": is_typosquat,
        "matched_via_homoglyph_normalization": matched_as_homoglyph,
        "matched_via_substring": substring_match is not None,
        "matched_via_tld_swap": tld_swap_match is not None,
    }


def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """
    Connect to a host you are authorized to check and report on its TLS
    certificate validity and expiry. Read-only / informational.
    Raises `InvalidInputError` if `hostname` isn't a non-empty string.
    Network/TLS failures are reported inline (`valid: False`, `error`,
    `error_type: "ExternalServiceError"`) rather than raised, since a
    host being unreachable is an expected outcome of this check, not a
    bug in the caller.
    """
    _require_nonempty_str(hostname, "hostname")
    context = ssl.create_default_context()
    try:
        def _connect_and_get_cert():
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()

        # Transient network hiccups (a dropped packet, a momentary DNS
        # blip) shouldn't be reported as "certificate invalid" - retry a
        # couple of times before giving up.
        cert = _with_retry(_connect_and_get_cert)
        if not cert:
            raise ExternalServiceError(f"no certificate returned by {hostname}:{port}")
        # `datetime.utcnow()` is deprecated (and naive); build an
        # explicit timezone-aware UTC datetime instead. `ssl`'s cert dict
        # is loosely typed (str | tuple[...] per field), so cast the two
        # date fields to str explicitly before parsing.
        not_after = datetime.strptime(str(cert["notAfter"]), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        not_before = datetime.strptime(str(cert["notBefore"]), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer_fields: tuple = cert.get("issuer", ())
        subject_fields: tuple = cert.get("subject", ())
        return {
            "hostname": hostname,
            "valid": True,
            "issuer": dict(x[0] for x in issuer_fields),
            "subject": dict(x[0] for x in subject_fields),
            "issued": not_before.isoformat(),
            "expires": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expiring_soon": days_left < 30,
            "already_expired": days_left < 0,
        }
    except Exception as exc:
        wrapped = ExternalServiceError(f"could not verify TLS certificate for {hostname}:{port}: {exc}")
        logger.warning(str(wrapped))
        return {"hostname": hostname, "valid": False, "error": str(wrapped), "error_type": "ExternalServiceError"}


def scan_email_for_phishing_signs(email_text: str) -> dict[str, Any]:
    """
    Scan raw email body text for common social-engineering red flags.
    Raises `InvalidInputError` if `email_text` isn't a string.
    Returns a weighted `risk_score` (0-100) alongside the `suspicious`
    boolean so multiple emails can be ranked/triaged instead of only
    yes/no.
    """
    _require_type(email_text, str, "email_text")
    _require_scannable_text(email_text, "email_text", max_length=_MAX_LONG_TEXT_LENGTH)
    weighted_reasons: list[tuple[int, str]] = []
    lowered = email_text.lower()

    urgency_terms = [
        "urgent", "act now", "immediately", "within 24 hours", "right now",
        "final notice", "account suspended", "account will be closed",
        "your account has been limited", "expires today", "last chance",
        "unusual activity", "verify immediately", "action required",
        "immediate attention", "failure to comply", "legal action",
        "your account will be permanently", "response required",
    ]
    if any(term in lowered for term in urgency_terms):
        weighted_reasons.append((15, "Uses urgency/pressure language"))

    credential_terms = [
        "enter your password", "verify your account", "confirm your password",
        "click here", "update your billing", "confirm your identity",
        "reactivate your account", "unlock your account", "provide your ssn",
        "confirm your card", "re-enter your login", "security check required",
        "verify your identity", "confirm your details", "update your payment",
        "enter your pin", "enter your otp", "enter your cvv",
    ]
    if any(term in lowered for term in credential_terms):
        weighted_reasons.append((25, "Asks the reader to enter sensitive credentials"))

    if re.search(r"\b(wire transfer|gift card|bitcoin|crypto(?:currency)?|western union)\b.{0,40}\b(send|pay|purchase|transfer)\b", lowered) or \
       re.search(r"\b(send|pay|purchase|transfer)\b.{0,40}\b(wire transfer|gift card|bitcoin|crypto(?:currency)?|western union)\b", lowered):
        weighted_reasons.append((25, "Requests an unusual/hard-to-trace payment method (gift cards, wire transfer, crypto)"))

    attachment_terms = [".exe", ".scr", ".zip", ".js", ".vbs", ".jar", ".hta", ".iso", ".docm", ".xlsm"]
    if re.search(r"(open|download|see|review)\s+the\s+attach", lowered) and any(ext in lowered for ext in attachment_terms):
        weighted_reasons.append((20, "Encourages opening an attachment with a potentially dangerous extension"))

    if re.search(r"\b(ceo|cfo|director|manager|boss)\b.{0,30}\b(urgent|favor|request|need you to)\b", lowered):
        weighted_reasons.append((20, "Impersonates an executive making an urgent request (\"CEO fraud\" / BEC pattern)"))

    urls = re.findall(r"https?://\S+", email_text)
    suspicious_urls = [u for u in urls if check_suspicious_url(u)["suspicious"]]
    if suspicious_urls:
        weighted_reasons.append((20, f"{len(suspicious_urls)} suspicious link(s) found in the email"))

    # Brand mentioned in the body but none of the links actually point to
    # that brand's real domain - a classic spoofing pattern.
    mentioned_brands = [b for b in _HIGH_VALUE_BRANDS if b in lowered]
    if mentioned_brands and urls:
        official_domain_seen = any(
            re.search(rf"://(?:www\.)?{re.escape(b)}\.(?:com|org|net)(?:/|$)", u.lower())
            for b in mentioned_brands for u in urls
        )
        if not official_domain_seen:
            weighted_reasons.append((25, f"Mentions {mentioned_brands[0]} but no link actually points to its real domain"))

    if re.search(r"dear (customer|user|sir/madam|valued member|account holder)", lowered):
        weighted_reasons.append((10, "Generic greeting instead of a real name (common in mass phishing)"))

    if re.search(r"[!]{2,}|[$]{2,}", email_text):
        weighted_reasons.append((5, "Excessive punctuation/formatting often used for emphasis in scam emails"))

    if re.search(r"\bdo not (reply|respond|forward)\b|\bthis is an automated message\b", lowered) and any(term in lowered for term in credential_terms):
        weighted_reasons.append((10, "Discourages replying/verifying while also requesting credentials - prevents the reader from double-checking"))

    reasons = [r for _, r in weighted_reasons]
    risk_score = min(sum(w for w, _ in weighted_reasons), 100)
    return {
        "suspicious": len(reasons) > 0,
        "risk_score": risk_score,
        "reasons": reasons,
        "suspicious_urls": suspicious_urls,
    }


def extract_and_check_links(text: str) -> list[dict[str, Any]]:
    """
    Extract every URL from a block of text and run `check_suspicious_url`
    on each. Raises `InvalidInputError` if `text` isn't a string.
    """
    _require_type(text, str, "text")
    _require_scannable_text(text, "text", max_length=_MAX_LONG_TEXT_LENGTH)
    urls = re.findall(r"https?://\S+", text)
    return [check_suspicious_url(u) for u in urls]


def validate_email_format_and_mx(email: str, check_mx: bool = True) -> dict[str, Any]:
    """
    Validate email syntax and, optionally, that the domain has an MX
    record. Raises `InvalidInputError` if `email` isn't a string.
    A DNS lookup failure during the MX check is reported inline
    (`has_mx_record: False`, `error`, `error_type`) rather than raised,
    since a domain simply not resolving is an expected outcome here.
    """
    _require_type(email, str, "email")
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    valid_format = bool(re.match(pattern, email))
    disposable_domains = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com", "trashmail.com"}
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    result = {
        "email": email,
        "valid_format": valid_format,
        "has_mx_record": None,
        "is_disposable_domain": domain in disposable_domains,
    }

    if valid_format and check_mx:
        try:
            import dns.resolver  # optional dependency: dnspython
            answers = dns.resolver.resolve(domain, "MX")
            result["has_mx_record"] = len(answers) > 0
        except ImportError:
            logger.info("dnspython is not installed; skipping MX check")
        except Exception as exc:
            wrapped = ExternalServiceError(f"MX lookup failed for {domain}: {exc}")
            logger.warning(str(wrapped))
            result["has_mx_record"] = False
            result["error"] = str(wrapped)
            result["error_type"] = "ExternalServiceError"

    return result


# ==========================================================================
# SECTION 3 - BRUTE-FORCE / ABUSE PROTECTION
# ==========================================================================

class RateLimiter:
    """
    Simple in-memory sliding-window rate limiter, e.g. for login endpoints.
    Thread-safe: a single internal lock guards all state, so one
    RateLimiter instance can safely be shared across threads (e.g. worker
    threads in a WSGI server). For multi-*process*/production deployments,
    back this with Redis instead - an in-process lock doesn't help across
    process boundaries.
    Raises `InvalidInputError` on construction if `max_attempts` or
    `window_seconds` aren't positive.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        _require_type(max_attempts, int, "max_attempts")
        _require_type(window_seconds, (int, float), "window_seconds")
        if max_attempts <= 0:
            raise InvalidInputError("max_attempts must be positive")
        if window_seconds <= 0:
            raise InvalidInputError("window_seconds must be positive")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Return True if `key` (e.g. IP or username) is still within limits."""
        _require_nonempty_str(key, "key")
        now = time.time()
        with self._lock:
            window = self._attempts[key]
            while window and now - window[0] > self.window_seconds:
                window.popleft()
            if len(window) >= self.max_attempts:
                return False
            window.append(now)
            return True

    def remaining(self, key: str) -> int:
        _require_nonempty_str(key, "key")
        with self._lock:
            return max(self.max_attempts - len(self._attempts[key]), 0)

    def reset(self, key: str) -> None:
        """Clear all tracked attempts for `key` (e.g. after a successful login)."""
        _require_nonempty_str(key, "key")
        with self._lock:
            self._attempts.pop(key, None)


def rate_limiter(key: str, store: dict[str, deque], max_attempts: int = 5, window_seconds: int = 300) -> bool:
    """
    Functional variant of RateLimiter.allow() for callers who want to manage
    their own storage dict (e.g. persisted externally between calls).
    Raises `InvalidInputError` for invalid arguments.
    """
    _require_nonempty_str(key, "key")
    _require_type(store, dict, "store")
    if max_attempts <= 0 or window_seconds <= 0:
        raise InvalidInputError("max_attempts and window_seconds must be positive")
    now = time.time()
    window = store.setdefault(key, deque())
    while window and now - window[0] > window_seconds:
        window.popleft()
    if len(window) >= max_attempts:
        return False
    window.append(now)
    return True


def detect_brute_force_attempt(failed_timestamps: list[float], threshold: int = 5, window_seconds: float = 60) -> bool:
    """
    Given a list of failed-login unix timestamps, detect a brute-force
    burst (threshold-many failures within window_seconds of each other).
    Raises `InvalidInputError` if `failed_timestamps` isn't a list of
    numbers, or `threshold`/`window_seconds` aren't positive.
    """
    _require_type(failed_timestamps, list, "failed_timestamps")
    if not all(isinstance(t, (int, float)) for t in failed_timestamps):
        raise InvalidInputError("failed_timestamps must contain only numbers")
    if threshold <= 0 or window_seconds <= 0:
        raise InvalidInputError("threshold and window_seconds must be positive")
    if len(failed_timestamps) < threshold:
        return False
    sorted_ts = sorted(failed_timestamps)
    for i in range(len(sorted_ts) - threshold + 1):
        if sorted_ts[i + threshold - 1] - sorted_ts[i] <= window_seconds:
            return True
    return False


class IPBlocklist:
    """
    In-memory temporary IP blocklist with automatic expiry. Thread-safe:
    a single internal lock guards all state, so one instance can safely
    be shared across threads.
    """

    def __init__(self):
        self._blocked: dict[str, float] = {}
        self._lock = threading.Lock()

    def block(self, ip: str, duration_seconds: int = 900) -> None:
        """
        Raises `InvalidInputError` if `ip` isn't a syntactically valid
        IPv4/IPv6 address, or `duration_seconds` isn't positive - both are
        caller mistakes, not something to silently ignore.
        """
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError) as exc:
            raise InvalidInputError(f"'{ip}' is not a valid IP address") from exc
        if duration_seconds <= 0:
            raise InvalidInputError("duration_seconds must be positive")
        with self._lock:
            self._blocked[ip] = time.time() + duration_seconds
        logger.info("IP blocked: %s for %s seconds", ip, duration_seconds)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            expiry = self._blocked.get(ip)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self._blocked[ip]
                return False
            return True

    def unblock(self, ip: str) -> bool:
        """Manually lift a block early. Returns True if the IP was blocked."""
        with self._lock:
            return self._blocked.pop(ip, None) is not None


def block_ip_temporarily(ip: str, blocklist: IPBlocklist, duration_seconds: int = 900) -> None:
    """Convenience wrapper around IPBlocklist.block for a functional call style."""
    _require_type(blocklist, IPBlocklist, "blocklist")
    blocklist.block(ip, duration_seconds)


def implement_captcha_trigger(
    failed_attempts: int,
    threshold: int = 3,
    window_seconds: Optional[float] = None,
    failed_timestamps: Optional[list[float]] = None,
) -> bool:
    """
    Return True if a CAPTCHA challenge should now be shown to the user.

    By default this is a plain counter comparison (`failed_attempts >=
    threshold`), which is intentionally simple as a building block. Pass
    `window_seconds` together with `failed_timestamps` (unix timestamps of
    recent failures) to instead require that `threshold` failures happened
    within a rolling time window - this avoids triggering a CAPTCHA for a
    handful of failures spread out over weeks.
    Raises `InvalidInputError` if `failed_attempts` is negative.
    """
    _require_type(failed_attempts, int, "failed_attempts")
    if failed_attempts < 0:
        raise InvalidInputError("failed_attempts cannot be negative")
    if window_seconds is not None and failed_timestamps is not None:
        return detect_brute_force_attempt(failed_timestamps, threshold=threshold, window_seconds=window_seconds)
    return failed_attempts >= threshold


def log_failed_login_attempt(username: str, ip: str, log_path: str = "failed_logins.csv") -> dict[str, Any]:
    """
    Append a structured record of a failed login attempt to a CSV audit
    log. Returns `{"success": True, "path": ...}` on success.
    Raises `InvalidInputError` if `username`/`ip` aren't strings.
    If the file can't be written (permissions, missing directory, full
    disk), returns `{"success": False, "error": ..., "error_type":
    "ExternalServiceError"}` instead of raising, since a logging sink
    being temporarily unavailable shouldn't be able to crash the caller's
    login flow.
    """
    _require_type(username, str, "username")
    _require_type(ip, str, "ip")
    try:
        file_exists = os.path.exists(log_path)
        with open(log_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "username", "ip"])
            writer.writerow([datetime.now(timezone.utc).isoformat(), username, ip])
        return {"success": True, "path": log_path}
    except OSError as exc:
        wrapped = ExternalServiceError(f"could not write to log file '{log_path}': {exc}")
        logger.error(str(wrapped))
        return {"success": False, "error": str(wrapped), "error_type": "ExternalServiceError"}


def distance_km_between(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-circle distance in kilometers between two lat/lon points
    (haversine formula). Use this to give `detect_anomalous_login_location`
    an accurate distance instead of relying on its conservative default.
    Raises `InvalidInputError` if any coordinate is out of its valid range
    (latitude -90..90, longitude -180..180) or isn't a number.
    """
    for name, value, bound in (("lat1", lat1, 90), ("lat2", lat2, 90), ("lon1", lon1, 180), ("lon2", lon2, 180)):
        _require_type(value, (int, float), name)
        if not -bound <= value <= bound:
            raise InvalidInputError(f"{name} must be between -{bound} and {bound}, got {value}")

    r = 6371.0  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


def detect_anomalous_login_location(
    previous_country: str,
    new_country: str,
    previous_time: datetime,
    new_time: datetime,
    max_plausible_kmh: float = 900.0,
    approx_distance_km: Optional[float] = None,
    previous_coords: Optional[tuple[float, float]] = None,
    new_coords: Optional[tuple[float, float]] = None,
) -> dict[str, Any]:
    """
    Simple "impossible travel" detector: flags a login as anomalous if the
    implied travel speed between two countries/times exceeds what's
    physically plausible (e.g. faster than a commercial flight).

    For an accurate distance, pass `previous_coords`/`new_coords` as
    (latitude, longitude) tuples - these are run through
    `distance_km_between` (haversine). Only fall back to
    `approx_distance_km` / the fixed default when real coordinates aren't
    available; a flat "4000 km for every country pair" estimate is a rough
    approximation and can both over- and under-flag depending on how close
    the two countries actually are.
    Raises `InvalidInputError` if `previous_time`/`new_time` aren't
    `datetime` objects, or `new_time` is before `previous_time`.
    """
    _require_type(previous_time, datetime, "previous_time")
    _require_type(new_time, datetime, "new_time")
    if new_time < previous_time:
        raise InvalidInputError("new_time cannot be before previous_time")

    elapsed_hours = max((new_time - previous_time).total_seconds() / 3600, 1e-6)
    if previous_country == new_country:
        return {"anomalous": False, "reason": "same country"}

    if previous_coords is not None and new_coords is not None:
        approx_distance_km = distance_km_between(*previous_coords, *new_coords)
        distance_source = "coordinates"
    elif approx_distance_km is None:
        approx_distance_km = 4000.0  # conservative default when distance unknown
        distance_source = "default_estimate"
    else:
        distance_source = "provided_estimate"

    implied_speed = approx_distance_km / elapsed_hours
    anomalous = implied_speed > max_plausible_kmh
    # A speed above ~2x commercial-flight cruising speed is essentially
    # never legitimate (VPN/proxy hops aside) - flag it as high confidence.
    high_confidence = implied_speed > max_plausible_kmh * 2
    return {
        "anomalous": anomalous,
        "high_confidence": anomalous and high_confidence,
        "implied_speed_kmh": round(implied_speed, 1),
        "elapsed_hours": round(elapsed_hours, 2),
        "distance_km": round(approx_distance_km, 1),
        "distance_source": distance_source,
    }


def detect_privilege_escalation_attempt(role_before: str, role_after: str, allowed_transitions: dict[str, set[str]]) -> bool:
    """
    Given a permission-change event, check it against an allow-list of
    legitimate role transitions to catch unauthorized privilege escalation.
    Raises `InvalidInputError` if `allowed_transitions` isn't a dict.
    """
    _require_type(allowed_transitions, dict, "allowed_transitions")
    allowed = allowed_transitions.get(role_before, set())
    return role_after not in allowed and role_after != role_before


# ==========================================================================
# SECTION 4 - FILE / MALWARE HYGIENE
# ==========================================================================

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".ps1", ".msi", ".dll", ".hta", ".wsf", ".wsh", ".lnk",
    ".msc", ".reg", ".vbe", ".jse", ".ws", ".msp", ".scf", ".cpl",
    ".gadget", ".apk", ".app", ".jsp", ".sh", ".bin", ".iso", ".ps1xml",
}


def compute_file_hash(filepath: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash of a file in a memory-efficient, chunked manner.
    Raises `InvalidInputError` if `filepath` isn't a string or `algorithm`
    isn't a hash name known to `hashlib`. Raises `ExternalServiceError`
    (chained from the original `OSError`) if the file can't be opened/read
    - this returns a plain string on success, so wrapping errors in a
    dict here would silently change the return type on every call site;
    raising a single well-known exception type is safer.
    """
    _require_nonempty_str(filepath, "filepath")
    try:
        h = hashlib.new(algorithm)
    except ValueError as exc:
        raise InvalidInputError(f"'{algorithm}' is not a supported hash algorithm") from exc
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as exc:
        raise ExternalServiceError(f"could not read file '{filepath}': {exc}") from exc
    return h.hexdigest()


def scan_file_hash_virustotal(filepath: str, api_key: str) -> dict[str, Any]:
    """
    Look up a file's SHA-256 hash against VirusTotal's database (does not
    upload the file itself - just checks if the hash is already known-bad).
    Requires a VirusTotal API key.
    Raises `InvalidInputError` if `api_key` is empty, or `ExternalServiceError`
    if the file itself can't be read (see `compute_file_hash`). A failed
    network call to VirusTotal is reported inline instead of raised, since
    that's an expected/recoverable outcome of an external lookup.
    """
    _require_nonempty_str(api_key, "api_key")
    file_hash = compute_file_hash(filepath, "sha256")
    try:
        import requests

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if resp.status_code == 404:
            return {"hash": file_hash, "known": False}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {"hash": file_hash, "known": True, "stats": stats, "malicious": stats.get("malicious", 0) > 0}
    except Exception as exc:
        wrapped = ExternalServiceError(f"VirusTotal lookup failed: {exc}")
        logger.warning(str(wrapped))
        return {"hash": file_hash, "error": str(wrapped), "error_type": "ExternalServiceError"}


def detect_suspicious_file_extension(filename: str) -> dict[str, Any]:
    """
    Flag potentially dangerous file extensions, including double
    extensions, RTL-override tricks, and unusually long extensions.
    Raises `InvalidInputError` if `filename` isn't a non-empty string.
    """
    _require_nonempty_str(filename, "filename")
    lowered = filename.lower()
    ext = os.path.splitext(lowered)[1]
    is_dangerous = ext in _DANGEROUS_EXTENSIONS
    double_ext = bool(re.search(
        r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|csv|zip|rar)\."
        r"(exe|scr|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|com|pif|msi)$",
        lowered,
    ))
    # Right-to-left override character (U+202E) is used to visually flip a
    # filename so a hidden dangerous extension appears to be something safe.
    rtlo_trick = "\u202e" in filename
    # A large number of consecutive spaces before the real extension is a
    # classic trick to push the visible (fake) extension past what a
    # narrow file-list column shows.
    padded_extension_trick = bool(re.search(r" {6,}\.\w+$", filename))
    return {
        "filename": filename,
        "extension": ext,
        "dangerous_extension": is_dangerous,
        "double_extension_trick": double_ext,
        "rtl_override_trick": rtlo_trick,
        "padded_extension_trick": padded_extension_trick,
        "flagged": is_dangerous or double_ext or rtlo_trick or padded_extension_trick,
    }


def check_file_integrity(filepath: str, known_good_hash: str, algorithm: str = "sha256") -> bool:
    """
    Compare a file's current hash against a previously recorded good hash.
    Raises `InvalidInputError` if `known_good_hash` isn't a string, or
    `ExternalServiceError` if the file can't be read (see `compute_file_hash`).
    """
    _require_type(known_good_hash, str, "known_good_hash")
    current_hash = compute_file_hash(filepath, algorithm)
    return hmac.compare_digest(current_hash, known_good_hash)


def scan_directory_for_malware_signatures(directory: str, signatures: dict[str, str]) -> list[dict[str, Any]]:
    """
    Walk a directory you own/manage and flag files whose SHA-256 hash matches
    a provided dict of {hash: label} known-malware signatures.

    Important limitation: exact-hash matching is inherently brittle -
    changing a single byte of a malicious file (repacking, a different
    compiler flag, appended junk data) produces a completely different
    hash and silently evades this check entirely. This is a property of
    hash-based detection in general, not a bug fixable within this
    function; exact-hash matching is still useful for catching *known,
    unmodified* malware samples (e.g. from a threat-intel feed), but it
    is not a substitute for real AV/EDR, which use fuzzy hashing (e.g.
    ssdeep/TLSH) and behavioral analysis to catch variants. If you need
    that, pair this function with a real scanning engine rather than
    relying on it alone.

    Raises `InvalidInputError` if `directory` doesn't exist or `signatures`
    isn't a dict. Per-file read errors (permissions, broken symlinks) are
    silently skipped, since one unreadable file shouldn't abort scanning
    the rest of the directory tree.
    """
    _require_nonempty_str(directory, "directory")
    _require_type(signatures, dict, "signatures")
    if not os.path.isdir(directory):
        raise InvalidInputError(f"'{directory}' is not a directory")

    findings = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            try:
                file_hash = compute_file_hash(path)
            except (ExternalServiceError, OSError, PermissionError):
                continue
            if file_hash in signatures:
                findings.append({"path": path, "hash": file_hash, "label": signatures[file_hash]})
    return findings


def quarantine_suspicious_file(filepath: str, quarantine_dir: str = "./quarantine") -> str:
    """
    Move a suspicious file into an isolated quarantine directory (rename,
    no execution). Raises `InvalidInputError` if `filepath` isn't a
    non-empty string, or `ExternalServiceError` if the move fails
    (permissions, file missing, cross-device rename issues).
    """
    _require_nonempty_str(filepath, "filepath")
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        dest = os.path.join(quarantine_dir, f"{int(time.time())}_{filename}.quarantined")
        os.replace(filepath, dest)
    except OSError as exc:
        raise ExternalServiceError(f"could not quarantine '{filepath}': {exc}") from exc
    logger.warning("Suspicious file quarantined: %s -> %s", filepath, dest)
    return dest


def verify_backup_integrity(backup_path: str, expected_hash: str) -> bool:
    """
    Verify a backup archive hasn't been corrupted or tampered with.
    Raises `InvalidInputError`/`ExternalServiceError` per `check_file_integrity`.
    """
    return check_file_integrity(backup_path, expected_hash)


# ==========================================================================
# SECTION 5 - WEB APPLICATION SECURITY
# ==========================================================================

def sanitize_user_input(user_input: str) -> str:
    """
    Escape characters that are dangerous in HTML contexts, reducing XSS risk
    for any user input that will be rendered back into a page.
    Raises `InvalidInputError` if `user_input` isn't a string.

    For anything beyond simple text escaping (e.g. allowing a safe subset
    of HTML), prefer a real sanitizer library such as `bleach` instead of
    hand-rolled escaping.
    """
    _require_type(user_input, str, "user_input")
    replacements = {
        "&": "&amp;", "<": "&lt;", ">": "&gt;",
        '"': "&quot;", "'": "&#x27;", "/": "&#x2F;",
        "`": "&#x60;", "=": "&#x3D;",
    }
    return "".join(replacements.get(ch, ch) for ch in user_input)


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def check_csrf_token_validity(request_token: str, session_token: str) -> bool:
    """
    Timing-safe comparison of a submitted CSRF token against the session's
    token. Returns False (rather than raising) for missing/empty/
    non-string tokens, since "no token" is a normal, expected way for
    CSRF validation to fail - not a programmer error in this function.
    """
    if not isinstance(request_token, str) or not isinstance(session_token, str):
        return False
    if not request_token or not session_token:
        return False
    if len(request_token) != len(session_token):
        return False
    return hmac.compare_digest(request_token, session_token)


def validate_cors_policy(allowed_origins: list[str], request_origin: str) -> dict[str, Any]:
    """
    Check whether a request's Origin header is allowed under your CORS
    policy. Raises `InvalidInputError` if `allowed_origins` isn't a list.
    """
    _require_type(allowed_origins, list, "allowed_origins")
    _require_type(request_origin, str, "request_origin")
    wildcard = "*" in allowed_origins
    allowed = wildcard or request_origin in allowed_origins
    warnings = []
    if wildcard:
        warnings.append("Using '*' together with credentials is a security risk")
    if request_origin == "null":
        warnings.append("Origin 'null' can come from sandboxed iframes/data URIs and is often spoofable")
    if allowed and request_origin != "*" and re.match(r"^https?://localhost", request_origin) and not any("localhost" in o for o in allowed_origins if o != "*"):
        warnings.append("Allowed only via wildcard match, not an explicit localhost entry - double check this is intentional")
    return {"allowed": allowed, "origin": request_origin, "warning": warnings[0] if warnings else None, "warnings": warnings}


def detect_xss_patterns(input_text: str) -> list[str]:
    """
    Heuristically detect common XSS payload patterns in a string. Raises
    `InvalidInputError` if `input_text` isn't a string.

    Regex-based detection is inherently incomplete - it is easy to construct
    payloads (encoding tricks, unusual tag/attribute combinations) that
    slip past a fixed pattern list. Treat this as a quick triage signal,
    not a guarantee of safety; the real defense is contextual output
    encoding (e.g. `sanitize_user_input`) plus a strict CSP
    (`verify_csp_header`).
    """
    _require_type(input_text, str, "input_text")
    _require_scannable_text(input_text, "input_text")
    patterns = {
        r"<script.*?>": "<script> tag",
        r"on\w+\s*=": "inline event handler (onerror, onclick, onload, ...)",
        r"javascript:": "javascript: protocol",
        r"vbscript:": "vbscript: protocol",
        r"data:text/html": "data: URI with HTML payload",
        r"<iframe": "<iframe> tag",
        r"<img[^>]+onerror": "<img> tag with onerror handler",
        r"<svg[^>]*onload": "<svg> tag with onload handler",
        r"<body[^>]*onload": "<body> tag with onload handler",
        r"<details[^>]*ontoggle": "<details> tag with ontoggle handler (auto-fires without a click)",
        r"<marquee[^>]*onstart": "<marquee> tag with onstart handler",
        r"<input[^>]*onfocus": "<input> tag with onfocus handler (autofocus + onfocus = auto-fire)",
        r"<video[^>]*onerror": "<video> tag with onerror handler",
        r"<audio[^>]*onerror": "<audio> tag with onerror handler",
        r"<select[^>]*onfocus": "<select> tag with onfocus handler",
        r"document\.cookie": "access to document.cookie",
        r"document\.location": "redirect via document.location",
        r"document\.write": "document.write() call (can inject arbitrary markup)",
        r"window\.location\s*=": "redirect via window.location",
        r"<object[^>]*data\s*=": "<object> tag with data attribute",
        r"<embed[^>]+src\s*=": "<embed> tag with src attribute",
        r"expression\s*\(": "CSS expression() (legacy IE XSS vector)",
        r"formaction\s*=": "formaction attribute (can hijack form submission)",
        r"srcdoc\s*=": "srcdoc attribute on an iframe-like element",
        r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh": "meta refresh redirect",
        r"&#x[0-9a-f]+;|&#\d+;": "HTML entity-encoded characters (can hide a payload from simple filters)",
        r"\\u00[0-9a-f]{2}": "unicode-escaped characters (can hide a payload from simple filters)",
        r"%3c\s*script|%3cscript": "URL-encoded <script> tag",
        r"eval\s*\(": "use of eval()",
        r"settimeout\s*\(\s*[\"']": "setTimeout() called with a string argument (implicit eval)",
        r"setinterval\s*\(\s*[\"']": "setInterval() called with a string argument (implicit eval)",
        r"new\s+function\s*\(": "new Function() constructor (dynamic code execution)",
        r"\$\{.*?\}": "template-literal expression (can execute code in some sinks/frameworks)",
        r"\bfetch\s*\(\s*[\"'][^\"']*[\"']\s*\)\s*\.then": "fetch()-based data-exfiltration pattern",
        r"<\s*style[^>]*>.*?expression": "CSS expression() inside a <style> block",
    }
    found = [label for pattern, label in patterns.items() if re.search(pattern, input_text, re.IGNORECASE | re.DOTALL)]
    return found


def check_secure_cookie_flags(set_cookie_header: str) -> dict[str, Any]:
    """
    Parse a Set-Cookie header string and check for the key security flags.
    Raises `InvalidInputError` if `set_cookie_header` isn't a string.
    """
    _require_type(set_cookie_header, str, "set_cookie_header")
    lowered = set_cookie_header.lower()
    samesite_match = re.search(r"samesite\s*=\s*(\w+)", lowered)
    return {
        "httponly": "httponly" in lowered,
        "secure": "secure" in lowered,
        "samesite": samesite_match is not None,
        "samesite_value": samesite_match.group(1) if samesite_match else None,
        "samesite_none_without_secure": bool(samesite_match and samesite_match.group(1) == "none" and "secure" not in lowered),
    }


def validate_input_against_sql_injection(user_input: str) -> dict[str, Any]:
    """
    Heuristically flag strings that look like SQL injection payloads.
    Raises `InvalidInputError` if `user_input` isn't a string.

    (Defense-in-depth only - the real fix is always parameterized queries /
    an ORM, never string concatenation into SQL. A determined attacker can
    craft payloads that don't match any fixed pattern list, so a "not
    flagged" result here must never be treated as "safe to concatenate".)

    Returns `matched_patterns` (count) and a `severity` classification
    (none/low/medium/high) based on how many independent signals fired,
    in addition to the plain `suspicious` boolean.
    """
    _require_type(user_input, str, "user_input")
    _require_scannable_text(user_input, "user_input")
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"union[^\n]*select",
        r"union\s+all\s+select",
        r"select[^\n]*from",
        r"drop\s+table",
        r"drop\s+database",
        r"insert\s+into",
        r"update\s+\w+\s+set",
        r"delete\s+from",
        r"truncate\s+table",
        r"alter\s+table",
        r"exec(\s|\()",
        r"exec(?:ute)?\s+xp_cmdshell",
        r"exec(?:ute)?\s+sp_",
        r"information_schema",
        r"sleep\s*\(\s*\d+\s*\)",
        r"pg_sleep\s*\(",
        r"waitfor\s+delay",
        r"benchmark\s*\(",
        r";\s*--",
        r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",       # ' or '1'='1 / ' or 1=1
        r"'\s*or\s*''\s*=\s*''",              # ' or ''=''
        r"\bor\s+1\s*=\s*1\b",
        r"\band\s+1\s*=\s*1\b",
        r"having\s+1\s*=\s*1",
        r"group_concat\s*\(",
        r"load_file\s*\(",
        r"into\s+outfile",
        r"into\s+dumpfile",
        r"0x[0-9a-f]{6,}",                     # long hex literal (common in blind SQLi)
        r"/\*.*?\*/",                          # inline SQL comment used to break up keywords
        r"cast\s*\([^)]*as\s+\w+\)",
        r"convert\s*\([^)]*,\s*\w+\)",
        r"@@version",
        r"declare\s+@\w+",
        r"select\s+@@\w+",
        r"\bxor\b.{0,10}\bselect\b",
    ]
    matched = [p for p in patterns if re.search(p, user_input, re.IGNORECASE)]
    count = len(matched)
    severity = "none" if count == 0 else "low" if count == 1 else "medium" if count <= 3 else "high"
    return {"suspicious": count > 0, "matched_patterns": count, "severity": severity}


def check_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Check a dict of HTTP response headers (from your own site) against
    security best-practice headers. Raises `InvalidInputError` if
    `headers` isn't a dict.
    """
    _require_type(headers, dict, "headers")
    lowered = {k.lower(): v for k, v in headers.items()}
    checklist = {
        "content-security-policy": lowered.get("content-security-policy") is not None,
        "x-frame-options": lowered.get("x-frame-options") is not None,
        "x-content-type-options": lowered.get("x-content-type-options") == "nosniff",
        "strict-transport-security": lowered.get("strict-transport-security") is not None,
        "referrer-policy": lowered.get("referrer-policy") is not None,
        "permissions-policy": lowered.get("permissions-policy") is not None,
        "cross-origin-opener-policy": lowered.get("cross-origin-opener-policy") is not None,
        "cross-origin-resource-policy": lowered.get("cross-origin-resource-policy") is not None,
        "cross-origin-embedder-policy": lowered.get("cross-origin-embedder-policy") is not None,
    }
    missing = [k for k, present in checklist.items() if not present]

    weak = []
    hsts = lowered.get("strict-transport-security")
    if hsts and "max-age=0" in hsts.replace(" ", "").lower():
        weak.append("strict-transport-security has max-age=0 (effectively disabled)")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts.lower())
        if max_age_match and int(max_age_match.group(1)) < 15552000:  # < 180 days
            weak.append("strict-transport-security max-age is under 180 days - browsers recommend at least 6 months")
        if "includesubdomains" not in hsts.lower():
            weak.append("strict-transport-security is missing includeSubDomains")
    xfo = lowered.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        weak.append(f"x-frame-options has a non-standard value: {xfo}")
    server_header = lowered.get("server", "")
    if re.search(r"/\d", server_header):
        weak.append(f"Server header discloses a version number ({server_header}) - useful info for an attacker fingerprinting your stack")

    return {
        "checklist": checklist,
        "missing": missing,
        "weak_configurations": weak,
        "score": round(100 * (len(checklist) - len(missing)) / len(checklist)),
    }


def verify_csp_header(csp_header: str) -> dict[str, Any]:
    """
    Flag overly permissive Content-Security-Policy directives.
    Raises `InvalidInputError` if `csp_header` isn't a non-empty string.
    """
    _require_nonempty_str(csp_header, "csp_header")
    issues = []
    lowered = csp_header.lower()

    if "unsafe-inline" in lowered:
        issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "unsafe-eval" in lowered:
        issues.append("'unsafe-eval' allows the use of eval()")
    if "data:" in lowered and re.search(r"script-src[^;]*data:", lowered):
        issues.append("script-src allows 'data:' URIs, which can smuggle inline scripts")
    if re.search(r"(default|script)-src\s+\*(?!\S)", lowered):
        issues.append("default-src/script-src * allows almost any source")
    if "object-src" not in lowered and "default-src" not in lowered:
        issues.append("No object-src or default-src fallback - Flash/plugin-based vectors aren't restricted")
    if "frame-ancestors" not in lowered:
        issues.append("No frame-ancestors directive - clickjacking isn't mitigated by this policy alone")
    if "base-uri" not in lowered:
        issues.append("No base-uri directive - a <base> tag injection could redirect relative URLs")
    if re.search(r"script-src[^;]*https:(?!\S*\.)(?:\s|;|$)", lowered):
        issues.append("script-src allows the bare 'https:' scheme, which permits scripts from any HTTPS origin")
    if "report-uri" not in lowered and "report-to" not in lowered:
        issues.append("No report-uri/report-to directive - CSP violations won't be reported for monitoring")

    return {"issues": issues, "safe": len(issues) == 0}


# ==========================================================================
# SECTION 6 - NETWORK-LEVEL DEFENSE (own systems / local network only)
# ==========================================================================

def check_tls_version_support(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """
    Report which TLS protocol version a server (that you manage)
    negotiates. Raises `InvalidInputError` if `hostname` isn't a non-empty
    string. Connection failures are reported inline (`error`,
    `error_type: "ExternalServiceError"`) rather than raised.
    """
    _require_nonempty_str(hostname, "hostname")
    context = ssl.create_default_context()
    try:
        def _connect_and_get_info():
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.version(), ssock.cipher()

        version, cipher = _with_retry(_connect_and_get_info)
        outdated = version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
        cipher_name = cipher[0] if cipher else None
        weak_cipher = cipher_name is not None and any(term in cipher_name for term in ("RC4", "DES", "MD5", "NULL", "EXPORT"))
        return {
            "hostname": hostname,
            "tls_version": version,
            "outdated": outdated,
            "cipher_suite": cipher_name,
            "weak_cipher": weak_cipher,
        }
    except Exception as exc:
        wrapped = ExternalServiceError(f"could not negotiate TLS with {hostname}:{port}: {exc}")
        logger.warning(str(wrapped))
        return {"hostname": hostname, "error": str(wrapped), "error_type": "ExternalServiceError"}


def check_firewall_rules_status(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Audit a locally-provided list of firewall rule dicts (e.g. parsed from
    `iptables -L` or a cloud security-group export) for overly permissive
    entries such as 0.0.0.0/0 on sensitive ports, or any rule spanning an
    entire port range on an open source.
    Raises `InvalidInputError` if `rules` isn't a list.
    """
    _require_type(rules, list, "rules")
    sensitive_ports = {
        21, 22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017, 27018, 27019,
    }
    open_sources = {"0.0.0.0/0", "any", "*", "::/0"}
    risky = []
    for rule in rules:
        source = rule.get("source", "")
        port = rule.get("port")
        port_range = rule.get("port_range")  # optional: (start, end) tuple
        is_open_source = source in open_sources
        hits_sensitive_port = port in sensitive_ports
        hits_wide_range = port_range is not None and (port_range[1] - port_range[0]) >= 100
        if is_open_source and (hits_sensitive_port or hits_wide_range):
            risky.append(rule)
    return {"total_rules": len(rules), "risky_rules": risky, "risky_count": len(risky)}


def detect_arp_spoofing(arp_table: dict[str, str], known_good_mappings: dict[str, str]) -> list[dict[str, Any]]:
    """
    Compare a current IP->MAC ARP table snapshot against a known-good mapping
    (e.g. your gateway's real MAC) to flag possible ARP spoofing on your LAN.
    Raises `InvalidInputError` if either argument isn't a dict.
    Also flags the reverse conflict: two different IPs claiming the same
    MAC address, which is likewise a spoofing/duplication signal.
    """
    _require_type(arp_table, dict, "arp_table")
    _require_type(known_good_mappings, dict, "known_good_mappings")
    conflicts: list[dict[str, Any]] = []
    for ip, mac in arp_table.items():
        expected_mac = known_good_mappings.get(ip)
        if expected_mac and mac.lower() != expected_mac.lower():
            conflicts.append({"ip": ip, "seen_mac": mac, "expected_mac": expected_mac, "reason": "mac_mismatch"})

    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for ip, mac in arp_table.items():
        mac_to_ips[mac.lower()].append(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            conflicts.append({"ip": ips, "seen_mac": mac, "expected_mac": None, "reason": "duplicate_mac_multiple_ips"})

    return conflicts


def validate_dns_response(hostname: str, resolved_ip: str, expected_ips: Iterable[str]) -> dict[str, Any]:
    """
    Check a DNS resolution result against a known-good set of IPs for that
    hostname. Raises `InvalidInputError` if `resolved_ip` isn't a
    syntactically valid IP address.
    """
    _require_nonempty_str(hostname, "hostname")
    try:
        ipaddress.ip_address(resolved_ip)
    except (ValueError, TypeError) as exc:
        raise InvalidInputError(f"'{resolved_ip}' is not a valid IP address") from exc
    expected = set(expected_ips)
    valid = resolved_ip in expected
    is_private = ipaddress.ip_address(resolved_ip).is_private
    return {
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "expected": list(expected),
        "valid": valid,
        "resolved_to_private_ip": is_private,
    }


def check_vpn_connection_security(public_ip_before: str, public_ip_after: str, dns_servers_after: list[str], expected_vpn_dns: list[str]) -> dict[str, Any]:
    """
    Sanity-check that a VPN connection is actually routing traffic and DNS
    (catches "VPN connected but leaking real IP/DNS" scenarios) using values
    you've already collected from your own client.
    Raises `InvalidInputError` if `dns_servers_after`/`expected_vpn_dns`
    aren't lists.
    """
    _require_type(dns_servers_after, list, "dns_servers_after")
    _require_type(expected_vpn_dns, list, "expected_vpn_dns")
    ip_changed = public_ip_before != public_ip_after
    dns_leak = not set(dns_servers_after).issubset(set(expected_vpn_dns))
    no_dns_configured = len(dns_servers_after) == 0
    return {
        "ip_changed": ip_changed,
        "dns_leak_detected": dns_leak,
        "no_dns_servers_reported": no_dns_configured,
        "secure": ip_changed and not dns_leak and not no_dns_configured,
    }


def audit_server_config(config: dict[str, Any]) -> list[str]:
    """
    Audit a dict of server configuration values (e.g. loaded from a JSON/YAML
    config file you own) against basic hardening expectations.
    Raises `InvalidInputError` if `config` isn't a dict.
    """
    _require_type(config, dict, "config")
    issues = []
    if config.get("debug") is True:
        issues.append("Debug mode is on - must not be enabled in production")
    if config.get("root_login_allowed") is True:
        issues.append("Direct root/admin login is allowed")
    if not config.get("firewall_enabled", False):
        issues.append("Firewall is disabled")
    if config.get("default_admin_password_changed") is False:
        issues.append("Default admin password has not been changed")
    if config.get("password_auth_enabled") is True and config.get("key_auth_enabled") is not True:
        issues.append("Password authentication is enabled without key-based authentication as an alternative")
    if config.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        issues.append(f"Server is configured to allow an outdated TLS version: {config.get('tls_version')}")
    if config.get("directory_listing_enabled") is True:
        issues.append("Directory listing is enabled - can expose files not meant to be browsable")
    if config.get("verbose_errors_enabled") is True:
        issues.append("Verbose error messages are enabled - can leak stack traces/internal paths to users")
    if config.get("cors_allow_all") is True:
        issues.append("CORS is configured to allow all origins ('*')")
    return issues


# ==========================================================================
# SECTION 7 - CRYPTOGRAPHY & SECRETS MANAGEMENT
# ==========================================================================

def generate_secure_token(length_bytes: int = 32) -> str:
    """
    Generate a cryptographically secure, URL-safe random token (e.g. for
    API keys, session IDs). Raises `InvalidInputError` if `length_bytes`
    isn't a positive int.
    """
    _require_type(length_bytes, int, "length_bytes")
    if length_bytes <= 0:
        raise InvalidInputError("length_bytes must be positive")
    return secrets.token_urlsafe(length_bytes)


@dataclass
class ApiKeyRecord:
    key: str
    created_at: datetime
    active: bool = True


def rotate_api_key(current: ApiKeyRecord, grace_period_seconds: int = 3600) -> tuple[ApiKeyRecord, ApiKeyRecord]:
    """
    Issue a new API key while keeping the old one valid for a grace period,
    so dependent services have time to switch over without downtime.
    Raises `InvalidInputError` if `current` isn't an `ApiKeyRecord`.
    """
    _require_type(current, ApiKeyRecord, "current")
    current.active = True  # remains active during grace period
    new_key = ApiKeyRecord(key=generate_secure_token(), created_at=datetime.now(timezone.utc))
    logger.info("New API key issued; the old key remains valid for %s more seconds", grace_period_seconds)
    return current, new_key


_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_\-]{20,}")


def mask_sensitive_data_in_logs(log_line: str, fields_to_mask: Iterable[str] = ("password", "token", "api_key", "secret", "authorization", "cookie", "ssn", "credit_card")) -> str:
    """
    Redact values of known-sensitive fields (key=value or key: value
    style) in a log line. Raises `InvalidInputError` if `log_line` isn't
    a string. Also redacts common bare-pattern secrets even without a
    "field=" prefix: bearer tokens, and 13-19-digit runs that pass the
    Luhn checksum (i.e. are plausibly real card numbers, not just any
    long number - a plain digit-count regex would also flag phone
    numbers, order IDs, and timestamps, which is a lot of noisy
    over-redaction for something that isn't actually a card number).
    """
    _require_type(log_line, str, "log_line")
    _require_scannable_text(log_line, "log_line", max_length=_MAX_LONG_TEXT_LENGTH)
    masked = log_line
    for field_name in fields_to_mask:
        masked = re.sub(
            rf"({re.escape(field_name)}[\"']?\s*[:=]\s*[\"']?)([^\s,\"'&]+)",
            r"\1***REDACTED***",
            masked,
            flags=re.IGNORECASE,
        )
    masked = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.]{16,}", r"\1***REDACTED***", masked)

    def _redact_if_luhn_valid(match: re.Match) -> str:
        digits_only = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits_only) <= 19 and _luhn_checksum_valid(digits_only):
            return "***REDACTED-CARD***"
        return match.group(0)

    masked = re.sub(r"\b(?:\d[ -]?){13,19}\b", _redact_if_luhn_valid, masked)
    return masked


def encrypt_sensitive_data(plaintext: str, key: bytes) -> str:
    """
    Encrypt a string using AES-GCM (authenticated encryption). `key` must be
    32 random bytes (use `secrets.token_bytes(32)` and store it safely).
    Returns base64(nonce + ciphertext + tag).
    Requires: pip install cryptography

    Raises `InvalidInputError` if `plaintext` isn't a string or `key`
    isn't exactly 32 bytes.
    """
    _require_type(plaintext, str, "plaintext")
    _require_type(key, bytes, "key")
    if len(key) != 32:
        raise InvalidInputError(f"key must be exactly 32 bytes for AES-256-GCM, got {len(key)}")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_sensitive_data(token: str, key: bytes) -> str:
    """
    Decrypt a value produced by `encrypt_sensitive_data`.
    Raises `InvalidInputError` if `token`/`key` are malformed (bad base64,
    wrong key length). A wrong key or a tampered ciphertext fails the
    GCM authentication tag check, which is also reported as
    `InvalidInputError` (a corrupt/forged ciphertext is a data-integrity
    problem, not a transient external failure).
    """
    _require_type(token, str, "token")
    _require_type(key, bytes, "key")
    if len(key) != 32:
        raise InvalidInputError(f"key must be exactly 32 bytes for AES-256-GCM, got {len(key)}")

    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        raw = base64.b64decode(token, validate=True)
    except Exception as exc:
        raise InvalidInputError("token is not valid base64") from exc
    if len(raw) < 13:
        raise InvalidInputError("token is too short to contain a nonce and ciphertext")

    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except InvalidTag as exc:
        raise InvalidInputError("decryption failed - wrong key or the ciphertext was tampered with") from exc


def validate_jwt_token(token: str, secret: str, algorithms: Optional[list[str]] = None) -> dict[str, Any]:
    """
    Validate a JWT's signature and expiry. Requires: pip install pyjwt
    Returns the decoded payload if valid, or an error description.
    Raises `InvalidInputError` if `token`/`secret` aren't strings.
    A missing PyJWT install or a signature/expiry failure is reported
    inline (`valid: False`) rather than raised, since "this token doesn't
    validate" is the normal, expected outcome this function exists to
    detect - not a bug in the caller.
    """
    _require_type(token, str, "token")
    _require_type(secret, str, "secret")
    try:
        import jwt  # PyJWT

        header = jwt.get_unverified_header(token)
        if header.get("alg") == "none":
            return {"valid": False, "error": "token declares alg=none, which bypasses signature verification entirely"}
        payload = jwt.decode(token, secret, algorithms=algorithms or ["HS256"])
        return {"valid": True, "payload": payload, "header": header}
    except ImportError:
        return {"valid": False, "error": "PyJWT is not installed (pip install pyjwt)"}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


_SECRET_LIKE_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Possible AWS Access Key ID"),
    (r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']", "Possible AWS Secret Access Key"),
    (r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", "Hardcoded API key"),
    (r"(?i)secret[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", "Hardcoded secret"),
    (r"(?i)(auth[_-]?token|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{16,}[\"']", "Hardcoded auth/access token"),
    (r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----", "Private key embedded in code"),
    (r"gh[pousr]_[A-Za-z0-9]{36}", "Possible GitHub personal access / OAuth token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Possible Slack token"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Possible Google API key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Possible Stripe live secret key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Possible Stripe live publishable key"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "Possible SendGrid API key"),
    (r"AC[a-f0-9]{32}", "Possible Twilio Account SID"),
    (r"key-[a-f0-9]{32}", "Possible Mailgun API key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "Hardcoded JWT token"),
    (r"(?i)(db|database)[_-]?(password|pwd)[\"']?\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']", "Hardcoded database password"),
    (r"(?i)npm_[A-Za-z0-9]{36}", "Possible npm access token"),
    (r"(?i)ya29\.[A-Za-z0-9_\-]+", "Possible Google OAuth access token"),
    (r"(?i)heroku[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"'][0-9a-f\-]{36}[\"']", "Possible Heroku API key"),
    (r"(?i)-----BEGIN CERTIFICATE-----", "Embedded certificate (verify this is meant to be public)"),
    (r"(?i)mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@", "MongoDB connection string with embedded credentials"),
    (r"(?i)postgres(?:ql)?://[^:\s]+:[^@\s]+@", "PostgreSQL connection string with embedded credentials"),
    (r"(?i)mysql://[^:\s]+:[^@\s]+@", "MySQL connection string with embedded credentials"),
]


def check_secrets_in_codebase(directory: str, file_extensions: tuple[str, ...] = (".py", ".js", ".env", ".json", ".yml", ".yaml")) -> list[dict[str, Any]]:
    """
    Scan a codebase you own for accidentally hardcoded secrets/keys before
    a commit or release (a lightweight local alternative to tools like
    truffleHog / gitleaks).
    Raises `InvalidInputError` if `directory` doesn't exist. Per-file read
    errors (permissions, broken symlinks, binary files) are silently
    skipped so one bad file doesn't abort scanning the rest of the tree.
    """
    _require_nonempty_str(directory, "directory")
    if not os.path.isdir(directory):
        raise InvalidInputError(f"'{directory}' is not a directory")

    findings = []
    for root, dirs, files in os.walk(directory):
        # Skip common directories that are noisy and never worth scanning.
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build")]
        for name in files:
            if not name.endswith(file_extensions):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read(_MAX_LONG_TEXT_LENGTH * 5)  # cap per-file read; see _MAX_LONG_TEXT_LENGTH
            except (OSError, PermissionError):
                continue
            for pattern, label in _SECRET_LIKE_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_no = content[: match.start()].count("\n") + 1
                    findings.append({"file": path, "line": line_no, "type": label})
    return findings


# ==========================================================================
# SECTION 8 - MONITORING, RISK SCORING & REPORTING
# ==========================================================================

@dataclass
class SecurityFinding:
    category: str
    description: str
    severity: str  # "low" | "medium" | "high" | "critical"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if self.severity not in _SEVERITY_WEIGHTS:
            raise InvalidInputError(f"severity must be one of {sorted(_SEVERITY_WEIGHTS)}, got {self.severity!r}")


_SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 15}


def calculate_risk_score(findings: list[SecurityFinding]) -> dict[str, Any]:
    """
    Aggregate a list of findings into a single 0-100 style risk score.
    Raises `InvalidInputError` if `findings` isn't a list.
    Also breaks the score down by severity count and flags whether any
    single critical finding is present, since a report with one critical
    issue deserves attention even if the aggregate score looks moderate.
    """
    _require_type(findings, list, "findings")
    if not findings:
        return {"score": 0, "level": "no known risk", "finding_count": 0, "by_severity": {}}

    by_severity: dict[str, int] = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1

    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    score = min(raw * 2, 100)
    level = "low" if score < 25 else "medium" if score < 50 else "high" if score < 80 else "critical"
    return {
        "score": score,
        "level": level,
        "finding_count": len(findings),
        "by_severity": dict(by_severity),
        "has_critical_finding": by_severity.get("critical", 0) > 0,
    }


def generate_security_report(findings: list[SecurityFinding], target_name: str = "system") -> str:
    """
    Produce a human-readable Markdown security report from a list of
    findings. Raises `InvalidInputError` if `findings` isn't a list.
    """
    _require_type(findings, list, "findings")
    risk = calculate_risk_score(findings)
    lines = [
        f"# Security Report - {target_name}",
        f"Date: {datetime.now(timezone.utc).isoformat()}",
        f"Overall risk score: {risk['score']} / 100 ({risk['level']})",
        f"Findings by severity: {risk.get('by_severity', {})}",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("No findings recorded.")
    for f in sorted(findings, key=lambda x: _SEVERITY_WEIGHTS.get(x.severity, 0), reverse=True):
        lines.append(f"- **[{f.severity.upper()}]** ({f.category}) {f.description}")
    return "\n".join(lines)


def export_findings_to_json(findings: list[SecurityFinding], output_path: str) -> dict[str, Any]:
    """
    Serialize findings to a JSON file for machine consumption / dashboards.
    Returns `{"success": True, "path": ...}` on success.
    Raises `InvalidInputError` if `findings` isn't a list.
    If the file can't be written (permissions, missing directory), returns
    `{"success": False, "error": ..., "error_type": "ExternalServiceError"}`
    instead of raising.
    """
    _require_type(findings, list, "findings")
    data = [
        {
            "category": f.category,
            "description": f.description,
            "severity": f.severity,
            "timestamp": f.timestamp.isoformat(),
        }
        for f in findings
    ]
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        return {"success": True, "path": output_path}
    except OSError as exc:
        wrapped = ExternalServiceError(f"could not write to '{output_path}': {exc}")
        logger.error(str(wrapped))
        return {"success": False, "error": str(wrapped), "error_type": "ExternalServiceError"}


def generate_incident_response_report(
    incident_title: str,
    detected_at: datetime,
    affected_systems: list[str],
    actions_taken: list[str],
) -> str:
    """
    Produce a structured incident-response summary document.
    Raises `InvalidInputError` if `detected_at` isn't a `datetime`, or
    `affected_systems`/`actions_taken` aren't lists.
    """
    _require_nonempty_str(incident_title, "incident_title")
    _require_type(detected_at, datetime, "detected_at")
    _require_type(affected_systems, list, "affected_systems")
    _require_type(actions_taken, list, "actions_taken")
    lines = [
        f"# Incident Response Report: {incident_title}",
        f"Detected at: {detected_at.isoformat()}",
        f"Status: {'Contained' if actions_taken else 'Response in progress - no actions logged yet'}",
        "",
        "## Affected Systems",
        *([f"- {s}" for s in affected_systems] or ["- None recorded"]),
        "",
        "## Actions Taken",
        *([f"{i+1}. {a}" for i, a in enumerate(actions_taken)] or ["No actions recorded yet."]),
    ]
    return "\n".join(lines)


def audit_user_permissions(users: list[dict[str, Any]], expected_max_role: dict[str, str]) -> list[dict[str, Any]]:
    """
    Flag users whose current role exceeds what's expected for their
    department/position, based on a mapping you supply.
    Raises `InvalidInputError` if `users` isn't a list or
    `expected_max_role` isn't a dict.
    """
    _require_type(users, list, "users")
    _require_type(expected_max_role, dict, "expected_max_role")
    role_rank = {"viewer": 0, "editor": 1, "admin": 2, "superadmin": 3}
    over_privileged = []
    for user in users:
        dept = user.get("department") or ""
        max_allowed = expected_max_role.get(dept, "viewer")
        if role_rank.get(user.get("role", "viewer"), 0) > role_rank.get(max_allowed, 0):
            over_privileged.append(user)
    return over_privileged


def notify_admin_dashboard(finding: SecurityFinding, webhook_url: str) -> dict[str, Any]:
    """
    POST a finding to an internal dashboard/webhook (e.g. Slack, Telegram
    bot endpoint). Raises `InvalidInputError` if `finding` isn't a
    `SecurityFinding` or `webhook_url` doesn't look like an http(s) URL.
    A failed network call is reported inline (`sent: False`, `error`,
    `error_type`) rather than raised.
    """
    _require_type(finding, SecurityFinding, "finding")
    if not re.match(r"^https?://", webhook_url or ""):
        raise InvalidInputError("webhook_url must start with http:// or https://")
    try:
        import requests

        resp = requests.post(
            webhook_url,
            json={
                "category": finding.category,
                "description": finding.description,
                "severity": finding.severity,
                "timestamp": finding.timestamp.isoformat(),
            },
            timeout=5,
        )
        return {"sent": resp.ok, "status_code": resp.status_code}
    except Exception as exc:
        wrapped = ExternalServiceError(f"webhook POST failed: {exc}")
        logger.warning(str(wrapped))
        return {"sent": False, "error": str(wrapped), "error_type": "ExternalServiceError"}


def send_security_alert(message: str, telegram_bot_token: str, chat_id: str) -> dict[str, Any]:
    """
    Send a security alert message via Telegram Bot API (bring your own
    bot token). Raises `InvalidInputError` if `message`/`telegram_bot_token`/
    `chat_id` are empty. A failed network call is reported inline
    (`sent: False`, `error`, `error_type`) rather than raised.
    """
    _require_nonempty_str(message, "message")
    _require_nonempty_str(telegram_bot_token, "telegram_bot_token")
    _require_nonempty_str(chat_id, "chat_id")
    try:
        import requests

        resp = requests.post(
            f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": f"🛡 DefendKing Alert:\n{message}"},
            timeout=5,
        )
        return {"sent": resp.ok}
    except Exception as exc:
        wrapped = ExternalServiceError(f"Telegram API call failed: {exc}")
        logger.warning(str(wrapped))
        return {"sent": False, "error": str(wrapped), "error_type": "ExternalServiceError"}


def schedule_periodic_scan(interval_seconds: int, scan_function, max_runs: Optional[int] = None) -> None:
    """
    Minimal blocking scheduler that calls `scan_function()` on a fixed
    interval. For production use, prefer `APScheduler` or a system cron job -
    this exists for simple scripts/demos.
    Raises `InvalidInputError` if `interval_seconds` isn't positive or
    `scan_function` isn't callable. Exceptions raised by `scan_function`
    itself are caught and logged (not re-raised), so one bad run doesn't
    kill the whole scheduling loop.
    """
    if interval_seconds <= 0:
        raise InvalidInputError("interval_seconds must be positive")
    if not callable(scan_function):
        raise InvalidInputError("scan_function must be callable")

    runs = 0
    while max_runs is None or runs < max_runs:
        try:
            scan_function()
        except Exception as exc:
            logger.error("Periodic scan failed: %s", exc)
        runs += 1
        if max_runs is None or runs < max_runs:
            time.sleep(interval_seconds)


def generate_security_checklist(system_type: str) -> list[str]:
    """
    Return a baseline hardening checklist for a given system type
    ("web", "server", "network", "cloud", or "mobile").
    """
    _require_type(system_type, str, "system_type")
    checklists = {
        "web": [
            "HTTPS is enabled with a valid certificate",
            "Security headers (CSP, HSTS, X-Frame-Options) are configured",
            "User input is sanitized",
            "Cookies have HttpOnly and Secure flags set",
            "Rate limiting is enabled on login forms",
            "Dependencies are kept up to date and scanned for known vulnerabilities",
        ],
        "server": [
            "The default admin password has been changed",
            "Firewall is enabled with a minimal rule set",
            "Security updates are installed",
            "SSH login uses keys (not passwords)",
            "Backups run periodically and are tested",
            "Unnecessary services/ports are disabled",
        ],
        "network": [
            "Legacy protocols (SSLv3, TLS 1.0/1.1) are disabled",
            "Network devices don't use default passwords",
            "DNS uses trusted resolvers",
            "Network segmentation is in place for sensitive systems",
            "Wireless networks use WPA3 (or WPA2 at minimum)",
        ],
        "cloud": [
            "IAM follows least-privilege (no wildcard '*' permissions)",
            "Storage buckets are not publicly readable/writable by default",
            "MFA is required for privileged/root accounts",
            "Audit logging (e.g. CloudTrail) is enabled and retained",
            "Secrets are stored in a secrets manager, not environment variables in plaintext",
        ],
        "mobile": [
            "Sensitive data is not stored in plaintext on-device",
            "Certificate pinning is used for API calls",
            "Biometric/PIN lock is required to open the app",
            "App does not log sensitive data to system logs",
            "Deep links are validated before acting on them",
        ],
    }
    return checklists.get(system_type, ["Unknown system type"])


# ==========================================================================
# SECTION 9 - API & SESSION SECURITY
# ==========================================================================

def validate_api_request_signature(
    payload: str,
    timestamp: str,
    signature: str,
    secret: str,
    tolerance_seconds: int = 300,
) -> dict[str, Any]:
    """
    Verify an HMAC-SHA256 request signature - the common "sign the payload +
    timestamp with a shared secret" pattern used by many REST/exchange/
    trading APIs. Also rejects requests whose timestamp is too far in the
    past or future, which shrinks the replay window even before
    `detect_replay_attack` is involved.

    The expected signature is computed as:
        HMAC_SHA256(secret, f"{timestamp}{payload}")
    (match this construction on the signing side too).

    Raises `InvalidInputError` if `secret` is empty (a caller mistake - an
    empty secret makes the signature check meaningless). A malformed or
    expired `timestamp`, or a mismatched `signature`, are the expected
    everyday outcomes this function exists to catch, so those are reported
    inline via `valid: False` rather than raised.
    """
    _require_nonempty_str(secret, "secret")
    _require_type(payload, str, "payload")
    _require_type(signature, str, "signature")

    try:
        request_time = float(timestamp)
    except (TypeError, ValueError):
        return {"valid": False, "reason": "timestamp is not a valid number"}

    now = time.time()
    if abs(now - request_time) > tolerance_seconds:
        return {"valid": False, "reason": "timestamp is outside the allowed tolerance window"}

    expected_sig = hmac.new(
        secret.encode("utf-8"), f"{timestamp}{payload}".encode(), hashlib.sha256
    ).hexdigest()
    if len(expected_sig) != len(signature):
        return {"valid": False, "reason": "signature mismatch"}
    valid = hmac.compare_digest(expected_sig, signature)
    return {"valid": valid, "reason": None if valid else "signature mismatch"}


def detect_replay_attack(nonce: str, seen_nonces: set, max_stored: int = 100_000) -> bool:
    """
    Track previously-seen request nonces (a fresh unique id sent with every
    request) to catch replayed requests. Mutates `seen_nonces` in place.

    This plain-set version is intentionally simple, but has two real
    limitations worth knowing about: it's not thread-safe (concurrent
    callers can race on the same set), and entries never expire by time,
    only by count (`max_stored`, evicted arbitrarily). If either of those
    matters for your use case, use `ReplayGuard` instead - it adds a lock
    and real per-nonce TTL expiry while keeping the same in-memory
    approach. For a multi-*process* service, back it with a real
    TTL-based store (e.g. Redis SETEX) regardless, since neither of these
    in-process options helps across process boundaries.

    Returns True if `nonce` is a replay (the caller should reject the
    request), False if it's new (and it's recorded for next time).
    Raises `InvalidInputError` if `nonce` isn't a non-empty string or
    `seen_nonces` isn't a set.
    """
    _require_nonempty_str(nonce, "nonce")
    _require_type(seen_nonces, set, "seen_nonces")
    if nonce in seen_nonces:
        return True
    seen_nonces.add(nonce)
    if len(seen_nonces) > max_stored:
        # Bound memory growth; this evicts an arbitrary entry, so in
        # production prefer a real TTL-based store instead.
        seen_nonces.pop()
    return False


class ReplayGuard:
    """
    Thread-safe, TTL-based nonce tracker for replay-attack detection - the
    stateful, production-friendlier sibling of `detect_replay_attack`.
    A single internal lock guards all state, and each nonce is
    automatically forgotten after `ttl_seconds` (rather than only being
    evicted once a size cap is hit), so memory doesn't grow unbounded and
    old nonces can't collide with a legitimately reused ID scheme long
    after the fact.

    For a multi-*process* deployment, back this with Redis (`SET nonce 1
    EX ttl_seconds NX`) instead - an in-process lock/dict doesn't
    coordinate across separate processes or machines.
    """

    def __init__(self, ttl_seconds: float = 300):
        _require_type(ttl_seconds, (int, float), "ttl_seconds")
        if ttl_seconds <= 0:
            raise InvalidInputError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _evict_expired(self, now: float) -> None:
        expired = [n for n, expiry in self._seen.items() if expiry <= now]
        for n in expired:
            del self._seen[n]

    def check(self, nonce: str) -> bool:
        """Returns True if `nonce` is a replay (reject the request), False if it's new."""
        _require_nonempty_str(nonce, "nonce")
        now = time.time()
        with self._lock:
            self._evict_expired(now)
            if nonce in self._seen:
                return True
            self._seen[nonce] = now + self.ttl_seconds
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


def check_session_fixation(pre_login_session_id: str, post_login_session_id: str) -> dict[str, Any]:
    """
    Verify that the session ID was rotated after a successful login. If the
    ID is unchanged, the application is vulnerable to session fixation: an
    attacker who plants a known session ID on a victim before login can
    reuse that same ID to hijack the session after the victim authenticates.
    Raises `InvalidInputError` if either argument isn't a non-empty string.
    """
    _require_nonempty_str(pre_login_session_id, "pre_login_session_id")
    _require_nonempty_str(post_login_session_id, "post_login_session_id")
    rotated = pre_login_session_id != post_login_session_id
    # Rotating to a *shorter or lower-entropy-looking* ID is also weak even
    # though technically "rotated" - flag a suspiciously short new ID too.
    weak_new_id = len(post_login_session_id) < 16
    return {
        "rotated": rotated,
        "vulnerable_to_fixation": not rotated,
        "new_session_id_looks_weak": weak_new_id,
    }


def generate_scoped_api_key(scopes: list[str], prefix: str = "sk") -> dict[str, Any]:
    """
    Generate a new API key that carries an associated scope list, e.g.
    "sk_<random>". Returns both the full token (hand this to the caller
    exactly once) and a SHA-256 hash of it (store only this server-side -
    never store the raw key, so a database leak doesn't leak usable keys).
    Raises `InvalidInputError` if `scopes` isn't a list or `prefix`
    contains characters unsafe for a token prefix.
    """
    _require_type(scopes, list, "scopes")
    _require_nonempty_str(prefix, "prefix")
    if not re.match(r"^[A-Za-z0-9_]+$", prefix):
        raise InvalidInputError("prefix must contain only letters, digits, and underscores")

    random_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}_{random_part}"
    key_hash = hashlib.sha256(full_key.encode("utf-8")).hexdigest()
    return {
        "api_key": full_key,
        "stored_hash": key_hash,
        "scopes": list(scopes),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def check_api_rate_limit_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Parse standard-ish rate-limit response headers (X-RateLimit-Limit /
    -Remaining / -Reset, or the IETF-draft RateLimit-* form) from a response
    your own client received, so it can back off before hitting a 429 -
    handy for anything polling an exchange/trading API on a schedule.
    Raises `InvalidInputError` if `headers` isn't a dict.
    Also computes a suggested backoff (seconds until `reset`, when present)
    so the caller doesn't have to do that arithmetic itself.
    """
    _require_type(headers, dict, "headers")
    lowered = {k.lower(): v for k, v in headers.items()}

    def _get_int(*keys: str) -> Optional[int]:
        for key in keys:
            if key in lowered:
                try:
                    return int(lowered[key])
                except ValueError:
                    continue
        return None

    limit = _get_int("x-ratelimit-limit", "ratelimit-limit")
    remaining = _get_int("x-ratelimit-remaining", "ratelimit-remaining")
    reset = _get_int("x-ratelimit-reset", "ratelimit-reset")
    retry_after = _get_int("retry-after")

    suggested_backoff_seconds = None
    if retry_after is not None:
        suggested_backoff_seconds = retry_after
    elif reset is not None:
        # Some APIs send an absolute unix timestamp, others a relative
        # seconds-from-now value; a huge number is almost certainly the
        # former.
        suggested_backoff_seconds = max(reset - int(time.time()), 0) if reset > 10_000_000_000 else reset

    return {
        "limit": limit,
        "remaining": remaining,
        "reset": reset,
        "should_back_off": remaining is not None and remaining <= 0,
        "has_rate_limit_headers": limit is not None or remaining is not None,
        "suggested_backoff_seconds": suggested_backoff_seconds,
    }


# ==========================================================================
# Quick self-test when run directly (not part of the public API)
# ==========================================================================

if __name__ == "__main__":
    print("DefendKing loaded OK.")
    print(check_password_strength("Barman!2026Secure"))
    print(generate_strong_password())
    print(check_suspicious_url("http://192.168.1.1@paypal-login.tk/verify"))
    print(generate_security_checklist("web"))