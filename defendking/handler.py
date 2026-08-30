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
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------
# Module-level logger. Consumers of the package can configure handlers;
# we only attach a NullHandler so importing this module is silent by default.
# --------------------------------------------------------------------------
logger = logging.getLogger("defendking")
logger.addHandler(logging.NullHandler())


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
}


def check_password_strength(password: str) -> dict[str, Any]:
    """
    Score a password's strength on a 0-100 scale based on length and
    character-class diversity (NOT a substitute for a breach check).

    Returns a dict with `score`, `label`, and `suggestions`.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    classes = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^\w\s]", password)),
    }
    class_count = sum(classes.values())

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

    # Cross-check against the pattern detector so a password that merely
    # "looks" diverse (e.g. "Qwerty123!") doesn't score as strong.
    pattern_issues = detect_common_password_patterns(password)
    score -= min(len(pattern_issues) * 15, score)  # never go below 0 here
    suggestions.extend(pattern_issues)

    if password.lower() in _COMMON_PASSWORDS:
        score = min(score, 10)

    label = "weak" if score < 40 else "medium" if score < 70 else "strong"
    return {"score": score, "label": label, "suggestions": suggestions}


def check_password_breached(password: str, use_api: bool = True) -> dict[str, Any]:
    """
    Check whether a password appears in known breach corpora using the
    "k-anonymity" model of the Have I Been Pwned Pwned Passwords API
    (only the first 5 chars of the SHA-1 hash are ever sent - the real
    password / full hash never leaves this machine).

    If `use_api` is False, or the request fails, falls back to checking
    against the small local common-password list.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

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
            logger.warning("HIBP lookup failed, falling back to local list: %s", exc)

    breached = password.lower() in _COMMON_PASSWORDS
    return {"breached": breached, "times_seen": None, "source": "local_list"}


def generate_strong_password(length: int = 16, use_symbols: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    if length < 8:
        raise ValueError("length must be at least 8")

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

    (For production systems prefer a maintained library like `argon2-cffi`
    or Django's built-in password hashers - this is a dependency-free,
    from-scratch reference implementation.)
    """
    iterations = 260_000
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a hash produced by `hash_password`."""
    try:
        algo, iterations_s, salt_b64, hash_b64 = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            raise ValueError("unsupported hash algorithm")
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError) as exc:
        raise ValueError("stored_hash has an invalid format") from exc

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)  # timing-safe comparison


_LEET_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def detect_common_password_patterns(password: str) -> list[str]:
    """
    Flag common weak patterns: keyboard walks, repeats, sequences, dates,
    leetspeak substitutions of common words, and short repeated blocks.
    """
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
    if re.search(r"(qwerty|qwertz|azerty|asdf|asdfg|zxcv|qazwsx|1qaz|2wsx|poiuy|lkjh)", lowered):
        issues.append("Contains a keyboard-walk pattern")
    if re.search(r"(19|20)\d{2}", password):
        issues.append("Likely contains a birth year or date")
    if re.search(r"(0[1-9]|1[0-2])[/\-.](0[1-9]|[12]\d|3[01])", password):
        issues.append("Likely contains a date (MM/DD or similar)")

    return issues


def check_two_factor_status(is_enabled_flag: bool, backup_codes_count: int = 0) -> dict[str, Any]:
    """
    Evaluate a user's 2FA posture given data already fetched from your own
    service's API/database (this function does not contact any service
    itself - it only interprets flags you already have).
    """
    return {
        "enabled": is_enabled_flag,
        "has_backup_codes": backup_codes_count > 0,
        "recommendation": (
            "Good posture" if is_enabled_flag and backup_codes_count > 0
            else "Enabling 2FA and saving backup codes is recommended"
        ),
    }


def check_password_expiry(last_changed: datetime, max_age_days: int = 90) -> dict[str, Any]:
    """Determine whether a password is past its recommended rotation age."""
    if last_changed.tzinfo is None:
        last_changed = last_changed.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - last_changed).days
    expired = age_days > max_age_days
    return {
        "age_days": age_days,
        "max_age_days": max_age_days,
        "expired": expired,
        "days_remaining": max(max_age_days - age_days, 0),
    }


def validate_password_policy_compliance(password: str, policy: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Check a password against an organizational policy dict, e.g.:
        {"min_length": 12, "require_upper": True, "require_digit": True,
         "require_symbol": True, "disallow_common": True}
    """
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
    if policy.get("require_upper") and not re.search(r"[A-Z]", password):
        violations.append("An uppercase letter is required")
    if policy.get("require_digit") and not re.search(r"\d", password):
        violations.append("A digit is required")
    if policy.get("require_symbol") and not re.search(r"[^\w\s]", password):
        violations.append("A special symbol is required")
    if policy.get("disallow_common") and password.lower() in _COMMON_PASSWORDS:
        violations.append("Password is in the common-password list")

    return {"compliant": len(violations) == 0, "violations": violations}


def check_default_credentials(username: str, password: str) -> bool:
    """
    Check a username/password pair against a known list of factory-default
    credentials (e.g. admin/admin) so you can flag devices/accounts that
    were never reconfigured after install.
    """
    known_defaults = {
        ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
        ("admin", "1234"), ("admin", "1234567"), ("admin", "pass"),
        ("root", "root"), ("root", "toor"), ("root", "admin"),
        ("administrator", "administrator"), ("administrator", "password"),
        ("user", "user"), ("guest", "guest"), ("guest", ""),
        ("pi", "raspberry"), ("ubnt", "ubnt"), ("cisco", "cisco"),
        ("service", "service"), ("support", "support"),
        ("admin", ""), ("", "admin"), ("default", "default"),
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


def check_suspicious_url(url: str) -> dict[str, Any]:
    """
    Heuristic scan of a URL for common phishing red flags.

    NOTE: this is a regex/rule-based heuristic, not a real classifier -
    it will miss novel phishing techniques and can flag legitimate URLs.
    Use it as one signal among several (e.g. combine with
    `check_domain_similarity` and a reputation/block-list API).
    """
    reasons = []
    lowered = url.lower()
    netloc = lowered.split("//")[-1].split("/")[0]

    if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", lowered):
        reasons.append("Uses a raw IP address instead of a domain name")
    if re.search(r"://0x[0-9a-f]+", lowered) or re.search(r"://\d{8,10}(?:[:/]|$)", lowered):
        reasons.append("Uses a hex/decimal-encoded IP address (obfuscation technique)")
    if "@" in url.split("//")[-1]:
        reasons.append("Contains an '@' character in the URL (used to hide the real destination)")
    if any(short in lowered for short in _URL_SHORTENERS):
        reasons.append("Uses a link-shortening service")
    if not lowered.startswith("https://"):
        reasons.append("Connection is not encrypted (HTTPS)")
    if "xn--" in netloc:
        reasons.append("Uses punycode (xn--) - can hide look-alike/homograph domains")
    tld = lowered.rstrip("/").rsplit(".", 1)[-1].split("/")[0].split("?")[0]
    if tld in _SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious top-level domain (.{tld})")
    if lowered.count("-") > 4:
        reasons.append("Unusually many hyphens in the domain (common in spoofed domains)")
    if netloc.count(".") >= 4:
        reasons.append("Unusually deep subdomain nesting (can hide the real domain)")
    if re.search(r":\d{2,5}(?:/|$)", netloc) and not re.search(r":(?:80|443)(?:/|$)", netloc):
        reasons.append("Uses a non-standard port number")
    brand_in_text = [b for b in _HIGH_VALUE_BRANDS if b in netloc]
    if brand_in_text and not any(netloc == b + tld_suffix for b in brand_in_text for tld_suffix in (".com", ".org", ".net")):
        if "-" in netloc or netloc.count(".") >= 2:
            reasons.append(f"Mentions a well-known brand ({brand_in_text[0]}) in a domain that isn't its official one")

    return {"url": url, "suspicious": len(reasons) > 0, "reasons": reasons}


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
    (e.g. "paypal-secure-verify.com"), which plain edit distance misses.
    """
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

    closest, best_dist, matched_as_homoglyph = None, float("inf"), False
    substring_match = None
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

    is_typosquat = (
        (closest is not None and best_dist <= 2 and domain_lower != closest.lower())
        or substring_match is not None
    )
    return {
        "domain": domain,
        "closest_trusted": substring_match or closest,
        "distance": best_dist,
        "likely_typosquat": is_typosquat,
        "matched_via_homoglyph_normalization": matched_as_homoglyph,
        "matched_via_substring": substring_match is not None,
    }


def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """
    Connect to a host you are authorized to check and report on its TLS
    certificate validity and expiry. Read-only / informational.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        # `datetime.utcnow()` is deprecated (and naive); build an
        # explicit timezone-aware UTC datetime instead.
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        return {
            "hostname": hostname,
            "valid": True,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "expires": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expiring_soon": days_left < 30,
        }
    except Exception as exc:
        return {"hostname": hostname, "valid": False, "error": str(exc)}


def scan_email_for_phishing_signs(email_text: str) -> dict[str, Any]:
    """Scan raw email body text for common social-engineering red flags."""
    reasons = []
    lowered = email_text.lower()

    urgency_terms = [
        "urgent", "act now", "immediately", "within 24 hours", "right now",
        "final notice", "account suspended", "account will be closed",
        "your account has been limited", "expires today", "last chance",
        "unusual activity", "verify immediately", "action required",
    ]
    if any(term in lowered for term in urgency_terms):
        reasons.append("Uses urgency/pressure language")

    credential_terms = [
        "enter your password", "verify your account", "confirm your password",
        "click here", "update your billing", "confirm your identity",
        "reactivate your account", "unlock your account", "provide your ssn",
        "confirm your card", "re-enter your login", "security check required",
    ]
    if any(term in lowered for term in credential_terms):
        reasons.append("Asks the reader to enter sensitive credentials")

    if re.search(r"\b(wire transfer|gift card|bitcoin|crypto(?:currency)?|western union)\b.{0,40}\b(send|pay|purchase|transfer)\b", lowered) or \
       re.search(r"\b(send|pay|purchase|transfer)\b.{0,40}\b(wire transfer|gift card|bitcoin|crypto(?:currency)?|western union)\b", lowered):
        reasons.append("Requests an unusual/hard-to-trace payment method (gift cards, wire transfer, crypto)")

    attachment_terms = [".exe", ".scr", ".zip", ".js", ".vbs", ".jar", ".hta", ".iso"]
    if re.search(r"(open|download|see|review)\s+the\s+attach", lowered) and any(ext in lowered for ext in attachment_terms):
        reasons.append("Encourages opening an attachment with a potentially dangerous extension")

    urls = re.findall(r"https?://\S+", email_text)
    suspicious_urls = [u for u in urls if check_suspicious_url(u)["suspicious"]]
    if suspicious_urls:
        reasons.append(f"{len(suspicious_urls)} suspicious link(s) found in the email")

    # Brand mentioned in the body but none of the links actually point to
    # that brand's real domain - a classic spoofing pattern.
    mentioned_brands = [b for b in _HIGH_VALUE_BRANDS if b in lowered]
    if mentioned_brands and urls:
        official_domain_seen = any(
            re.search(rf"://(?:www\.)?{re.escape(b)}\.(?:com|org|net)(?:/|$)", u.lower())
            for b in mentioned_brands for u in urls
        )
        if not official_domain_seen:
            reasons.append(f"Mentions {mentioned_brands[0]} but no link actually points to its real domain")

    if re.search(r"dear (customer|user|sir/madam|valued member|account holder)", lowered):
        reasons.append("Generic greeting instead of a real name (common in mass phishing)")

    if re.search(r"[!]{2,}|[$]{2,}", email_text):
        reasons.append("Excessive punctuation/formatting often used for emphasis in scam emails")

    return {"suspicious": len(reasons) > 0, "reasons": reasons, "suspicious_urls": suspicious_urls}


def extract_and_check_links(text: str) -> list[dict[str, Any]]:
    """Extract every URL from a block of text and run `check_suspicious_url` on each."""
    urls = re.findall(r"https?://\S+", text)
    return [check_suspicious_url(u) for u in urls]


def validate_email_format_and_mx(email: str, check_mx: bool = True) -> dict[str, Any]:
    """Validate email syntax and, optionally, that the domain has an MX record."""
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    valid_format = bool(re.match(pattern, email))
    result = {"email": email, "valid_format": valid_format, "has_mx_record": None}

    if valid_format and check_mx:
        domain = email.rsplit("@", 1)[-1]
        try:
            import dns.resolver  # optional dependency: dnspython
            answers = dns.resolver.resolve(domain, "MX")
            result["has_mx_record"] = len(answers) > 0
        except ImportError:
            logger.info("dnspython is not installed; skipping MX check")
        except Exception:
            result["has_mx_record"] = False

    return result


# ==========================================================================
# SECTION 3 - BRUTE-FORCE / ABUSE PROTECTION
# ==========================================================================

class RateLimiter:
    """
    Simple in-memory sliding-window rate limiter, e.g. for login endpoints.
    For multi-process/production deployments back this with Redis instead.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """Return True if `key` (e.g. IP or username) is still within limits."""
        now = time.time()
        window = self._attempts[key]
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.max_attempts:
            return False
        window.append(now)
        return True

    def remaining(self, key: str) -> int:
        return max(self.max_attempts - len(self._attempts[key]), 0)


def rate_limiter(key: str, store: dict[str, deque], max_attempts: int = 5, window_seconds: int = 300) -> bool:
    """
    Functional variant of RateLimiter.allow() for callers who want to manage
    their own storage dict (e.g. persisted externally between calls).
    """
    now = time.time()
    window = store.setdefault(key, deque())
    while window and now - window[0] > window_seconds:
        window.popleft()
    if len(window) >= max_attempts:
        return False
    window.append(now)
    return True


def detect_brute_force_attempt(failed_timestamps: list[float], threshold: int = 5, window_seconds: int = 60) -> bool:
    """Given a list of failed-login unix timestamps, detect a brute-force burst."""
    if len(failed_timestamps) < threshold:
        return False
    sorted_ts = sorted(failed_timestamps)
    for i in range(len(sorted_ts) - threshold + 1):
        if sorted_ts[i + threshold - 1] - sorted_ts[i] <= window_seconds:
            return True
    return False


class IPBlocklist:
    """In-memory temporary IP blocklist with automatic expiry."""

    def __init__(self):
        self._blocked: dict[str, float] = {}

    def block(self, ip: str, duration_seconds: int = 900) -> None:
        ipaddress.ip_address(ip)  # validates format, raises if malformed
        self._blocked[ip] = time.time() + duration_seconds
        logger.info("IP blocked: %s for %s seconds", ip, duration_seconds)

    def is_blocked(self, ip: str) -> bool:
        expiry = self._blocked.get(ip)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._blocked[ip]
            return False
        return True


def block_ip_temporarily(ip: str, blocklist: IPBlocklist, duration_seconds: int = 900) -> None:
    """Convenience wrapper around IPBlocklist.block for a functional call style."""
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
    """
    if window_seconds is not None and failed_timestamps is not None:
        return detect_brute_force_attempt(failed_timestamps, threshold=threshold, window_seconds=window_seconds)
    return failed_attempts >= threshold


def log_failed_login_attempt(username: str, ip: str, log_path: str = "failed_logins.csv") -> None:
    """Append a structured record of a failed login attempt to a CSV audit log."""
    file_exists = os.path.exists(log_path)
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "username", "ip"])
        writer.writerow([datetime.now(timezone.utc).isoformat(), username, ip])


def distance_km_between(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-circle distance in kilometers between two lat/lon points
    (haversine formula). Use this to give `detect_anomalous_login_location`
    an accurate distance instead of relying on its conservative default.
    """
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
    """
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
    return {
        "anomalous": anomalous,
        "implied_speed_kmh": round(implied_speed, 1),
        "elapsed_hours": round(elapsed_hours, 2),
        "distance_km": round(approx_distance_km, 1),
        "distance_source": distance_source,
    }


def detect_privilege_escalation_attempt(role_before: str, role_after: str, allowed_transitions: dict[str, set[str]]) -> bool:
    """
    Given a permission-change event, check it against an allow-list of
    legitimate role transitions to catch unauthorized privilege escalation.
    """
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
    """Compute the hash of a file in a memory-efficient, chunked manner."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file_hash_virustotal(filepath: str, api_key: str) -> dict[str, Any]:
    """
    Look up a file's SHA-256 hash against VirusTotal's database (does not
    upload the file itself - just checks if the hash is already known-bad).
    Requires a VirusTotal API key.
    """
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
        return {"hash": file_hash, "error": str(exc)}


def detect_suspicious_file_extension(filename: str) -> dict[str, Any]:
    """Flag potentially dangerous file extensions, including double extensions."""
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
    return {
        "filename": filename,
        "extension": ext,
        "dangerous_extension": is_dangerous,
        "double_extension_trick": double_ext,
        "rtl_override_trick": rtlo_trick,
        "flagged": is_dangerous or double_ext or rtlo_trick,
    }


def check_file_integrity(filepath: str, known_good_hash: str, algorithm: str = "sha256") -> bool:
    """Compare a file's current hash against a previously recorded good hash."""
    current_hash = compute_file_hash(filepath, algorithm)
    return hmac.compare_digest(current_hash, known_good_hash)


def scan_directory_for_malware_signatures(directory: str, signatures: dict[str, str]) -> list[dict[str, Any]]:
    """
    Walk a directory you own/manage and flag files whose SHA-256 hash matches
    a provided dict of {hash: label} known-malware signatures.
    """
    findings = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            try:
                file_hash = compute_file_hash(path)
            except (OSError, PermissionError):
                continue
            if file_hash in signatures:
                findings.append({"path": path, "hash": file_hash, "label": signatures[file_hash]})
    return findings


def quarantine_suspicious_file(filepath: str, quarantine_dir: str = "./quarantine") -> str:
    """Move a suspicious file into an isolated quarantine directory (rename, no execution)."""
    os.makedirs(quarantine_dir, exist_ok=True)
    filename = os.path.basename(filepath)
    dest = os.path.join(quarantine_dir, f"{int(time.time())}_{filename}.quarantined")
    os.replace(filepath, dest)
    logger.warning("Suspicious file quarantined: %s -> %s", filepath, dest)
    return dest


def verify_backup_integrity(backup_path: str, expected_hash: str) -> bool:
    """Verify a backup archive hasn't been corrupted or tampered with."""
    return check_file_integrity(backup_path, expected_hash)


# ==========================================================================
# SECTION 5 - WEB APPLICATION SECURITY
# ==========================================================================

def sanitize_user_input(user_input: str) -> str:
    """
    Escape characters that are dangerous in HTML contexts, reducing XSS risk
    for any user input that will be rendered back into a page.

    For anything beyond simple text escaping (e.g. allowing a safe subset
    of HTML), prefer a real sanitizer library such as `bleach` instead of
    hand-rolled escaping.
    """
    replacements = {
        "&": "&amp;", "<": "&lt;", ">": "&gt;",
        '"': "&quot;", "'": "&#x27;", "/": "&#x2F;",
    }
    return "".join(replacements.get(ch, ch) for ch in user_input)


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def check_csrf_token_validity(request_token: str, session_token: str) -> bool:
    """Timing-safe comparison of a submitted CSRF token against the session's token."""
    if not request_token or not session_token:
        return False
    return hmac.compare_digest(request_token, session_token)


def validate_cors_policy(allowed_origins: list[str], request_origin: str) -> dict[str, Any]:
    """Check whether a request's Origin header is allowed under your CORS policy."""
    wildcard = "*" in allowed_origins
    allowed = wildcard or request_origin in allowed_origins
    warning = "Using '*' together with credentials is a security risk" if wildcard else None
    return {"allowed": allowed, "origin": request_origin, "warning": warning}


def detect_xss_patterns(input_text: str) -> list[str]:
    """
    Heuristically detect common XSS payload patterns in a string.

    Regex-based detection is inherently incomplete - it is easy to construct
    payloads (encoding tricks, unusual tag/attribute combinations) that
    slip past a fixed pattern list. Treat this as a quick triage signal,
    not a guarantee of safety; the real defense is contextual output
    encoding (e.g. `sanitize_user_input`) plus a strict CSP
    (`verify_csp_header`).
    """
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
        r"document\.cookie": "access to document.cookie",
        r"document\.location": "redirect via document.location",
        r"window\.location\s*=": "redirect via window.location",
        r"<object[^>]*data\s*=": "<object> tag with data attribute",
        r"<embed[^>]+src\s*=": "<embed> tag with src attribute",
        r"expression\s*\(": "CSS expression() (legacy IE XSS vector)",
        r"formaction\s*=": "formaction attribute (can hijack form submission)",
        r"srcdoc\s*=": "srcdoc attribute on an iframe-like element",
        r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh": "meta refresh redirect",
        r"&#x[0-9a-f]+;|&#\d+;": "HTML entity-encoded characters (can hide a payload from simple filters)",
        r"\\u00[0-9a-f]{2}": "unicode-escaped characters (can hide a payload from simple filters)",
        r"eval\s*\(": "use of eval()",
        r"settimeout\s*\(\s*[\"']": "setTimeout() called with a string argument (implicit eval)",
    }
    found = [label for pattern, label in patterns.items() if re.search(pattern, input_text, re.IGNORECASE)]
    return found


def check_secure_cookie_flags(set_cookie_header: str) -> dict[str, bool]:
    """Parse a Set-Cookie header string and check for the key security flags."""
    lowered = set_cookie_header.lower()
    return {
        "httponly": "httponly" in lowered,
        "secure": "secure" in lowered,
        "samesite": "samesite" in lowered,
    }


def validate_input_against_sql_injection(user_input: str) -> dict[str, Any]:
    """
    Heuristically flag strings that look like SQL injection payloads.

    (Defense-in-depth only - the real fix is always parameterized queries /
    an ORM, never string concatenation into SQL. A determined attacker can
    craft payloads that don't match any fixed pattern list, so a "not
    flagged" result here must never be treated as "safe to concatenate".)
    """
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
        r"exec(\s|\()",
        r"exec(?:ute)?\s+xp_cmdshell",
        r"information_schema",
        r"sleep\s*\(\s*\d+\s*\)",
        r"waitfor\s+delay",
        r"benchmark\s*\(",
        r";\s*--",
        r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",       # ' or '1'='1 / ' or 1=1
        r"'\s*or\s*''\s*=\s*''",              # ' or ''=''
        r"\bor\s+1\s*=\s*1\b",
        r"having\s+1\s*=\s*1",
        r"group_concat\s*\(",
        r"load_file\s*\(",
        r"into\s+outfile",
        r"into\s+dumpfile",
        r"0x[0-9a-f]{6,}",                     # long hex literal (common in blind SQLi)
        r"/\*.*?\*/",                          # inline SQL comment used to break up keywords
        r"cast\s*\([^)]*as\s+\w+\)",
        r"convert\s*\([^)]*,\s*\w+\)",
    ]
    matched = [p for p in patterns if re.search(p, user_input, re.IGNORECASE)]
    return {"suspicious": len(matched) > 0, "matched_patterns": len(matched)}


def check_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Check a dict of HTTP response headers (from your own site) against
    security best-practice headers.
    """
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
    }
    missing = [k for k, present in checklist.items() if not present]

    weak = []
    hsts = lowered.get("strict-transport-security")
    if hsts and "max-age=0" in hsts.replace(" ", "").lower():
        weak.append("strict-transport-security has max-age=0 (effectively disabled)")
    xfo = lowered.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        weak.append(f"x-frame-options has a non-standard value: {xfo}")

    return {
        "checklist": checklist,
        "missing": missing,
        "weak_configurations": weak,
        "score": round(100 * (len(checklist) - len(missing)) / len(checklist)),
    }


def verify_csp_header(csp_header: str) -> dict[str, Any]:
    """Flag overly permissive Content-Security-Policy directives."""
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

    return {"issues": issues, "safe": len(issues) == 0}


# ==========================================================================
# SECTION 6 - NETWORK-LEVEL DEFENSE (own systems / local network only)
# ==========================================================================

def check_tls_version_support(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Report which TLS protocol version a server (that you manage) negotiates."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
        outdated = version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
        return {"hostname": hostname, "tls_version": version, "outdated": outdated}
    except Exception as exc:
        return {"hostname": hostname, "error": str(exc)}


def check_firewall_rules_status(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Audit a locally-provided list of firewall rule dicts (e.g. parsed from
    `iptables -L` or a cloud security-group export) for overly permissive
    entries such as 0.0.0.0/0 on sensitive ports.
    """
    sensitive_ports = {
        21, 22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017, 27018, 27019,
    }
    open_sources = {"0.0.0.0/0", "any", "*", "::/0"}
    risky = []
    for rule in rules:
        source = rule.get("source", "")
        port = rule.get("port")
        if source in open_sources and port in sensitive_ports:
            risky.append(rule)
    return {"total_rules": len(rules), "risky_rules": risky, "risky_count": len(risky)}


def detect_arp_spoofing(arp_table: dict[str, str], known_good_mappings: dict[str, str]) -> list[dict[str, str]]:
    """
    Compare a current IP->MAC ARP table snapshot against a known-good mapping
    (e.g. your gateway's real MAC) to flag possible ARP spoofing on your LAN.
    """
    conflicts = []
    for ip, mac in arp_table.items():
        expected_mac = known_good_mappings.get(ip)
        if expected_mac and mac.lower() != expected_mac.lower():
            conflicts.append({"ip": ip, "seen_mac": mac, "expected_mac": expected_mac})
    return conflicts


def validate_dns_response(hostname: str, resolved_ip: str, expected_ips: Iterable[str]) -> dict[str, Any]:
    """Check a DNS resolution result against a known-good set of IPs for that hostname."""
    expected = set(expected_ips)
    valid = resolved_ip in expected
    return {"hostname": hostname, "resolved_ip": resolved_ip, "expected": list(expected), "valid": valid}


def check_vpn_connection_security(public_ip_before: str, public_ip_after: str, dns_servers_after: list[str], expected_vpn_dns: list[str]) -> dict[str, Any]:
    """
    Sanity-check that a VPN connection is actually routing traffic and DNS
    (catches "VPN connected but leaking real IP/DNS" scenarios) using values
    you've already collected from your own client.
    """
    ip_changed = public_ip_before != public_ip_after
    dns_leak = not set(dns_servers_after).issubset(set(expected_vpn_dns))
    return {
        "ip_changed": ip_changed,
        "dns_leak_detected": dns_leak,
        "secure": ip_changed and not dns_leak,
    }


def audit_server_config(config: dict[str, Any]) -> list[str]:
    """
    Audit a dict of server configuration values (e.g. loaded from a JSON/YAML
    config file you own) against basic hardening expectations.
    """
    issues = []
    if config.get("debug") is True:
        issues.append("Debug mode is on - must not be enabled in production")
    if config.get("root_login_allowed") is True:
        issues.append("Direct root/admin login is allowed")
    if not config.get("firewall_enabled", False):
        issues.append("Firewall is disabled")
    if config.get("default_admin_password_changed") is False:
        issues.append("Default admin password has not been changed")
    return issues


# ==========================================================================
# SECTION 7 - CRYPTOGRAPHY & SECRETS MANAGEMENT
# ==========================================================================

def generate_secure_token(length_bytes: int = 32) -> str:
    """Generate a cryptographically secure, URL-safe random token (e.g. for API keys, session IDs)."""
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
    """
    current.active = True  # remains active during grace period
    new_key = ApiKeyRecord(key=generate_secure_token(), created_at=datetime.now(timezone.utc))
    logger.info("New API key issued; the old key remains valid for %s more seconds", grace_period_seconds)
    return current, new_key


_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_\-]{20,}")


def mask_sensitive_data_in_logs(log_line: str, fields_to_mask: Iterable[str] = ("password", "token", "api_key", "secret")) -> str:
    """Redact values of known-sensitive fields (key=value or key: value style) in a log line."""
    masked = log_line
    for field_name in fields_to_mask:
        masked = re.sub(
            rf"({field_name}[\"']?\s*[:=]\s*[\"']?)([^\s,\"'&]+)",
            r"\1***REDACTED***",
            masked,
            flags=re.IGNORECASE,
        )
    return masked


def encrypt_sensitive_data(plaintext: str, key: bytes) -> str:
    """
    Encrypt a string using AES-GCM (authenticated encryption). `key` must be
    32 random bytes (use `secrets.token_bytes(32)` and store it safely).
    Returns base64(nonce + ciphertext + tag).
    Requires: pip install cryptography
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_sensitive_data(token: str, key: bytes) -> str:
    """Decrypt a value produced by `encrypt_sensitive_data`."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(token)
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def validate_jwt_token(token: str, secret: str, algorithms: Optional[list[str]] = None) -> dict[str, Any]:
    """
    Validate a JWT's signature and expiry. Requires: pip install pyjwt
    Returns the decoded payload if valid, or an error description.
    """
    try:
        import jwt  # PyJWT

        payload = jwt.decode(token, secret, algorithms=algorithms or ["HS256"])
        return {"valid": True, "payload": payload}
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
]


def check_secrets_in_codebase(directory: str, file_extensions: tuple[str, ...] = (".py", ".js", ".env", ".json", ".yml", ".yaml")) -> list[dict[str, Any]]:
    """
    Scan a codebase you own for accidentally hardcoded secrets/keys before
    a commit or release (a lightweight local alternative to tools like
    truffleHog / gitleaks).
    """
    findings = []
    for root, _dirs, files in os.walk(directory):
        if ".git" in root:
            continue
        for name in files:
            if not name.endswith(file_extensions):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
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


_SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 15}


def calculate_risk_score(findings: list[SecurityFinding]) -> dict[str, Any]:
    """Aggregate a list of findings into a single 0-100 style risk score."""
    if not findings:
        return {"score": 0, "level": "no known risk"}

    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    score = min(raw * 2, 100)
    level = "low" if score < 25 else "medium" if score < 50 else "high" if score < 80 else "critical"
    return {"score": score, "level": level, "finding_count": len(findings)}


def generate_security_report(findings: list[SecurityFinding], target_name: str = "system") -> str:
    """Produce a human-readable Markdown security report from a list of findings."""
    risk = calculate_risk_score(findings)
    lines = [
        f"# Security Report - {target_name}",
        f"Date: {datetime.now(timezone.utc).isoformat()}",
        f"Overall risk score: {risk['score']} / 100 ({risk['level']})",
        "",
        "## Findings",
    ]
    for f in sorted(findings, key=lambda x: _SEVERITY_WEIGHTS.get(x.severity, 0), reverse=True):
        lines.append(f"- **[{f.severity.upper()}]** ({f.category}) {f.description}")
    return "\n".join(lines)


def export_findings_to_json(findings: list[SecurityFinding], output_path: str) -> str:
    """Serialize findings to a JSON file for machine consumption / dashboards."""
    data = [
        {
            "category": f.category,
            "description": f.description,
            "severity": f.severity,
            "timestamp": f.timestamp.isoformat(),
        }
        for f in findings
    ]
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)
    return output_path


def generate_incident_response_report(
    incident_title: str,
    detected_at: datetime,
    affected_systems: list[str],
    actions_taken: list[str],
) -> str:
    """Produce a structured incident-response summary document."""
    lines = [
        f"# Incident Response Report: {incident_title}",
        f"Detected at: {detected_at.isoformat()}",
        "",
        "## Affected Systems",
        *[f"- {s}" for s in affected_systems],
        "",
        "## Actions Taken",
        *[f"{i+1}. {a}" for i, a in enumerate(actions_taken)],
    ]
    return "\n".join(lines)


def audit_user_permissions(users: list[dict[str, Any]], expected_max_role: dict[str, str]) -> list[dict[str, Any]]:
    """
    Flag users whose current role exceeds what's expected for their
    department/position, based on a mapping you supply.
    """
    role_rank = {"viewer": 0, "editor": 1, "admin": 2, "superadmin": 3}
    over_privileged = []
    for user in users:
        dept = user.get("department")
        max_allowed = expected_max_role.get(dept, "viewer")
        if role_rank.get(user.get("role", "viewer"), 0) > role_rank.get(max_allowed, 0):
            over_privileged.append(user)
    return over_privileged


def notify_admin_dashboard(finding: SecurityFinding, webhook_url: str) -> dict[str, Any]:
    """POST a finding to an internal dashboard/webhook (e.g. Slack, Telegram bot endpoint)."""
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
        return {"sent": False, "error": str(exc)}


def send_security_alert(message: str, telegram_bot_token: str, chat_id: str) -> dict[str, Any]:
    """Send a security alert message via Telegram Bot API (bring your own bot token)."""
    try:
        import requests

        resp = requests.post(
            f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": f"🛡 DefendKing Alert:\n{message}"},
            timeout=5,
        )
        return {"sent": resp.ok}
    except Exception as exc:
        return {"sent": False, "error": str(exc)}


def schedule_periodic_scan(interval_seconds: int, scan_function, max_runs: Optional[int] = None) -> None:
    """
    Minimal blocking scheduler that calls `scan_function()` on a fixed
    interval. For production use, prefer `APScheduler` or a system cron job -
    this exists for simple scripts/demos.
    """
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
    """Return a baseline hardening checklist for a given system type."""
    checklists = {
        "web": [
            "HTTPS is enabled with a valid certificate",
            "Security headers (CSP, HSTS, X-Frame-Options) are configured",
            "User input is sanitized",
            "Cookies have HttpOnly and Secure flags set",
            "Rate limiting is enabled on login forms",
        ],
        "server": [
            "The default admin password has been changed",
            "Firewall is enabled with a minimal rule set",
            "Security updates are installed",
            "SSH login uses keys (not passwords)",
            "Backups run periodically and are tested",
        ],
        "network": [
            "Legacy protocols (SSLv3, TLS 1.0/1.1) are disabled",
            "Network devices don't use default passwords",
            "DNS uses trusted resolvers",
            "Network segmentation is in place for sensitive systems",
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
    """
    try:
        request_time = float(timestamp)
    except (TypeError, ValueError):
        return {"valid": False, "reason": "timestamp is not a valid number"}

    now = time.time()
    if abs(now - request_time) > tolerance_seconds:
        return {"valid": False, "reason": "timestamp is outside the allowed tolerance window"}

    expected_sig = hmac.new(
        secret.encode("utf-8"), f"{timestamp}{payload}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    valid = hmac.compare_digest(expected_sig, signature)
    return {"valid": valid, "reason": None if valid else "signature mismatch"}


def detect_replay_attack(nonce: str, seen_nonces: set, max_stored: int = 100_000) -> bool:
    """
    Track previously-seen request nonces (a fresh unique id sent with every
    request) to catch replayed requests. Mutates `seen_nonces` in place -
    for a real multi-process service, back this with a TTL-based store
    (e.g. Redis SETEX) instead of an in-memory set.

    Returns True if `nonce` is a replay (the caller should reject the
    request), False if it's new (and it's recorded for next time).
    """
    if nonce in seen_nonces:
        return True
    seen_nonces.add(nonce)
    if len(seen_nonces) > max_stored:
        # Bound memory growth; this evicts an arbitrary entry, so in
        # production prefer a real TTL-based store instead.
        seen_nonces.pop()
    return False


def check_session_fixation(pre_login_session_id: str, post_login_session_id: str) -> dict[str, Any]:
    """
    Verify that the session ID was rotated after a successful login. If the
    ID is unchanged, the application is vulnerable to session fixation: an
    attacker who plants a known session ID on a victim before login can
    reuse that same ID to hijack the session after the victim authenticates.
    """
    rotated = pre_login_session_id != post_login_session_id
    return {"rotated": rotated, "vulnerable_to_fixation": not rotated}


def generate_scoped_api_key(scopes: list[str], prefix: str = "sk") -> dict[str, Any]:
    """
    Generate a new API key that carries an associated scope list, e.g.
    "sk_<random>". Returns both the full token (hand this to the caller
    exactly once) and a SHA-256 hash of it (store only this server-side -
    never store the raw key, so a database leak doesn't leak usable keys).
    """
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
    """
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

    return {
        "limit": limit,
        "remaining": remaining,
        "reset": reset,
        "should_back_off": remaining is not None and remaining <= 0,
        "has_rate_limit_headers": limit is not None or remaining is not None,
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
