# DefendKing

A defensive-only Python security toolkit (~70 functions across 9 sections)
covering passwords, phishing/URL safety, brute-force protection, file
hygiene, web-app security, network checks, cryptography, monitoring/
reporting, and API/session security.

Every function protects, detects, or reports — none of them attack, exploit,
or access systems you don't own/manage.

**Author:** Barman
**License:** MIT
**Current version:** 3.6.17

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [Error handling (read this first)](#error-handling)
- [1. Passwords & authentication](#1-passwords--authentication)
- [2. Phishing & URL/email safety](#2-phishing--urlemail-safety)
- [3. Brute-force / abuse protection](#3-brute-force--abuse-protection)
- [4. File / malware hygiene](#4-file--malware-hygiene)
- [5. Web application security](#5-web-application-security)
- [6. Network-level defense](#6-network-level-defense)
- [7. Cryptography & secrets management](#7-cryptography--secrets-management)
- [8. Monitoring, risk scoring & reporting](#8-monitoring-risk-scoring--reporting)
- [9. API & session security](#9-api--session-security)
- [Known limitations](#known-limitations)
- [Changelog](#changelog)

---

## Install

```bash
pip install defendking                # core package, no third-party deps required
pip install "defendking[full]"        # adds requests / cryptography / pyjwt for the
                                       # functions that call external APIs or do AES/JWT
pip install "defendking[dev]"         # adds pytest for running the test suite
```

For local development (editable install from a clone):
```bash
pip install -e ".[full,dev]"
python -m pytest test/ -v
ruff check .
mypy defendking/
```

## CI/CD

Every push to `main` runs:
- **test** — the full test suite on Python 3.9-3.12
- **lint** — `ruff` and `mypy`

Pushing a version tag (e.g. `v3.6.16`) additionally triggers **publish**,
which builds and uploads the package to PyPI via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) —
no API token is stored anywhere. See `.github/workflows/ci.yml`.

## Quick start

```python
import defendking as dk

result = dk.check_password_strength("Tr0ub4dor&3")
print(result)
# {'score': 64, 'label': 'medium', 'entropy_bits': 65.4, 'suggestions': [...]}

url_check = dk.check_suspicious_url("http://192.168.1.1@paypal-login.tk/verify")
print(url_check["suspicious"], url_check["risk_score"])
# True 85
```

Everything is also importable by name:
```python
from defendking import check_password_strength, generate_strong_password
```

## Error handling

DefendKing follows one consistent rule everywhere (see `defendking.exceptions`):

- **Programmer errors** (wrong argument type, empty required value, value
  out of range) raise `InvalidInputError` immediately. Catch it like:
  ```python
  from defendking import InvalidInputError
  try:
      dk.generate_strong_password(length=2)
  except InvalidInputError as e:
      print("bad input:", e)
  ```
- **External-world failures** (network down, DNS failed, file missing):
  - Functions that already return a dict report the failure *inside* that
    dict — `error` / `error_type: "ExternalServiceError"` — and do not raise.
    ```python
    result = dk.check_ssl_certificate("unreachable-host.example")
    if not result["valid"]:
        print(result["error"])
    ```
  - Functions whose normal return is a plain scalar (a hash string, a
    bool) raise `ExternalServiceError` instead, since silently turning
    their return type into a dict would break every call site.
    ```python
    from defendking import ExternalServiceError
    try:
        dk.compute_file_hash("missing.txt")
    except ExternalServiceError as e:
        print("could not hash file:", e)
    ```

Every function's docstring says explicitly which behavior applies to it.

---

## 1. Passwords & authentication

### `check_password_strength(password: str) -> dict`
Scores a password 0-100 using length, character diversity, estimated
entropy (bits), and known weak-pattern detection.
```python
dk.check_password_strength("correct horse battery staple 42!")
# {'score': 100, 'label': 'strong', 'entropy_bits': 112.8, 'suggestions': []}
```

### `check_password_breached(password: str, use_api: bool = True) -> dict`
Checks a password against Have I Been Pwned (k-anonymity model — only a
hash prefix is sent) with a local-list fallback.
```python
dk.check_password_breached("123456")
# {'breached': True, 'times_seen': 37810483, 'source': 'hibp'}
```

### `generate_strong_password(length: int = 16, use_symbols: bool = True) -> str`
```python
dk.generate_strong_password(20)
# 'xQ2!kP9$mZr7@vLwT4nB'
```

### `hash_password(password: str) -> str` / `verify_password(password, stored_hash) -> bool`
PBKDF2-HMAC-SHA256 password hashing with a random salt.
```python
stored = dk.hash_password("my secret password")
dk.verify_password("my secret password", stored)   # True
dk.verify_password("wrong guess", stored)           # False
```

### `detect_common_password_patterns(password: str) -> list[str]`
Flags keyboard walks, sequences, repeats, dates, and leetspeak substitutions.
```python
dk.detect_common_password_patterns("Qwerty123")
# ['Contains a keyboard-walk pattern', 'Likely contains a birth year or date']
```

### `check_two_factor_status(is_enabled_flag: bool, backup_codes_count: int = 0) -> dict`
```python
dk.check_two_factor_status(True, backup_codes_count=1)
# {'enabled': True, 'has_backup_codes': True, 'low_on_backup_codes': True, 'recommendation': 'Good posture'}
```

### `check_password_expiry(last_changed: datetime, max_age_days: int = 90) -> dict`
```python
from datetime import datetime, timedelta, timezone
dk.check_password_expiry(datetime.now(timezone.utc) - timedelta(days=95))
# {'age_days': 95, 'max_age_days': 90, 'expired': True, ...}
```

### `validate_password_policy_compliance(password: str, policy: dict = None) -> dict`
```python
dk.validate_password_policy_compliance("alllowercase")
# {'compliant': False, 'violations': ['An uppercase letter is required', ...]}
```

### `check_default_credentials(username: str, password: str) -> bool`
```python
dk.check_default_credentials("admin", "admin")   # True
```

---

## 2. Phishing & URL/email safety

### `check_suspicious_url(url: str) -> dict`
Regex/heuristic phishing signal detection with a weighted `risk_score`
(0-100): raw IPs, punycode, homograph domains, open-redirect params,
brand impersonation, and more.
```python
dk.check_suspicious_url("http://192.168.1.1@paypal-login.tk/verify")
# {'suspicious': True, 'risk_score': 100, 'reasons': [...]}
```

### `check_domain_similarity(domain: str, trusted_domains: list[str]) -> dict`
Typosquat detection via Levenshtein distance, homoglyph normalization
(`rn`→`m`, `1`→`l`, ...), substring spoofing, and TLD-swap detection.
```python
dk.check_domain_similarity("paypa1.com", ["paypal.com"])
# {'likely_typosquat': True, 'matched_via_homoglyph_normalization': True, ...}
```

### `check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> dict`
```python
dk.check_ssl_certificate("example.com")
# {'valid': True, 'expires': '...', 'days_until_expiry': 62, 'expiring_soon': False}
```

### `scan_email_for_phishing_signs(email_text: str) -> dict`
Weighted-score scan for urgency language, credential harvesting, unusual
payment requests, BEC/executive-impersonation patterns, and more.
```python
dk.scan_email_for_phishing_signs("Dear customer, act now and click here to verify your account: http://bit.ly/xyz")
# {'suspicious': True, 'risk_score': 60, 'reasons': [...]}
```

### `extract_and_check_links(text: str) -> list[dict]`
```python
dk.extract_and_check_links("Check this out: http://bit.ly/xyz")
# [{'url': 'http://bit.ly/xyz', 'suspicious': True, ...}]
```

### `validate_email_format_and_mx(email: str, check_mx: bool = True) -> dict`
```python
dk.validate_email_format_and_mx("test@example.com", check_mx=False)
# {'email': 'test@example.com', 'valid_format': True, 'has_mx_record': None, 'is_disposable_domain': False}
```

---

## 3. Brute-force / abuse protection

### `RateLimiter(max_attempts=5, window_seconds=300)`
```python
limiter = dk.RateLimiter(max_attempts=3, window_seconds=60)
limiter.allow("1.2.3.4")   # True, True, True, then False on the 4th call
limiter.reset("1.2.3.4")   # clear after a successful login
```

### `rate_limiter(key, store, max_attempts=5, window_seconds=300) -> bool`
Functional variant for callers managing their own storage dict.

### `detect_brute_force_attempt(failed_timestamps: list[float], threshold=5, window_seconds=60) -> bool`
```python
dk.detect_brute_force_attempt([t, t+1, t+2, t+3, t+4], threshold=5, window_seconds=60)
# True
```

### `IPBlocklist()`
```python
blocklist = dk.IPBlocklist()
blocklist.block("10.0.0.1", duration_seconds=900)
blocklist.is_blocked("10.0.0.1")   # True
blocklist.unblock("10.0.0.1")
```

### `implement_captcha_trigger(failed_attempts, threshold=3, window_seconds=None, failed_timestamps=None) -> bool`
```python
dk.implement_captcha_trigger(failed_attempts=3, threshold=3)   # True
```

### `log_failed_login_attempt(username, ip, log_path="failed_logins.csv") -> dict`
```python
dk.log_failed_login_attempt("baduser", "1.2.3.4")
# {'success': True, 'path': 'failed_logins.csv'}
```

### `distance_km_between(lat1, lon1, lat2, lon2) -> float`
Haversine great-circle distance.
```python
dk.distance_km_between(35.6892, 51.3890, 40.7128, -74.0060)
# 9877.5 (Tehran to New York, km)
```

### `detect_anomalous_login_location(previous_country, new_country, previous_time, new_time, previous_coords=None, new_coords=None) -> dict`
"Impossible travel" detector.
```python
dk.detect_anomalous_login_location(
    "IR", "US", t1, t2,
    previous_coords=(35.6892, 51.3890), new_coords=(40.7128, -74.0060),
)
# {'anomalous': True, 'high_confidence': True, 'implied_speed_kmh': 118530.0, ...}
```

### `detect_privilege_escalation_attempt(role_before, role_after, allowed_transitions: dict) -> bool`
```python
dk.detect_privilege_escalation_attempt("viewer", "admin", {"viewer": {"editor"}})
# True (not an allowed transition)
```

---

## 4. File / malware hygiene

### `compute_file_hash(filepath, algorithm="sha256") -> str`
```python
dk.compute_file_hash("report.pdf")
# 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3...'
```

### `scan_file_hash_virustotal(filepath, api_key) -> dict`
Looks up a file's hash on VirusTotal (does not upload the file).

### `detect_suspicious_file_extension(filename: str) -> dict`
Flags dangerous extensions, double extensions, RTL-override tricks, and
padded/hidden extensions.
```python
dk.detect_suspicious_file_extension("invoice.pdf.exe")
# {'flagged': True, 'double_extension_trick': True, ...}
```

### `check_file_integrity(filepath, known_good_hash, algorithm="sha256") -> bool`
```python
dk.check_file_integrity("backup.zip", "a94a8fe5...")
```

### `scan_directory_for_malware_signatures(directory, signatures: dict) -> list[dict]`
```python
dk.scan_directory_for_malware_signatures("/downloads", {"a94a8f...": "known_trojan_x"})
```

### `quarantine_suspicious_file(filepath, quarantine_dir="./quarantine") -> str`
```python
dk.quarantine_suspicious_file("suspicious.exe")
# './quarantine/1735689600_suspicious.exe.quarantined'
```

### `verify_backup_integrity(backup_path, expected_hash) -> bool`

---

## 5. Web application security

### `sanitize_user_input(user_input: str) -> str`
```python
dk.sanitize_user_input("<script>alert(1)</script>")
# '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;'
```

### `generate_csrf_token() -> str` / `check_csrf_token_validity(request_token, session_token) -> bool`

### `validate_cors_policy(allowed_origins: list[str], request_origin: str) -> dict`
```python
dk.validate_cors_policy(["*"], "https://example.com")
# {'allowed': True, 'warning': "Using '*' together with credentials is a security risk", ...}
```

### `detect_xss_patterns(input_text: str) -> list[str]`
Covers `<script>`, event handlers, `javascript:`/`vbscript:`, `data:`
URIs, meta-refresh, entity/unicode encoding, template-literal injection,
and more.
```python
dk.detect_xss_patterns("<img src=x onerror=alert(1)>")
# ['inline event handler (...)', '<img> tag with onerror handler']
```

### `check_secure_cookie_flags(set_cookie_header: str) -> dict`
```python
dk.check_secure_cookie_flags("session=abc; SameSite=None")
# {'httponly': False, 'secure': False, 'samesite': True, 'samesite_none_without_secure': True}
```

### `validate_input_against_sql_injection(user_input: str) -> dict`
Returns a `severity` classification (none/low/medium/high) in addition to
the boolean.
```python
dk.validate_input_against_sql_injection("' UNION ALL SELECT username, password FROM users--")
# {'suspicious': True, 'matched_patterns': 4, 'severity': 'high'}
```

### `check_security_headers(headers: dict) -> dict`
```python
dk.check_security_headers({"Content-Security-Policy": "default-src 'self'"})
# {'checklist': {...}, 'missing': [...], 'weak_configurations': [...], 'score': 33}
```

### `verify_csp_header(csp_header: str) -> dict`
```python
dk.verify_csp_header("default-src 'self'; script-src 'unsafe-inline'")
# {'issues': [...], 'safe': False}
```

---

## 6. Network-level defense

*(Run these only against systems you own or are authorized to assess.)*

### `check_tls_version_support(hostname, port=443, timeout=5.0) -> dict`
```python
dk.check_tls_version_support("example.com")
# {'tls_version': 'TLSv1.3', 'outdated': False, 'cipher_suite': '...', 'weak_cipher': False}
```

### `check_firewall_rules_status(rules: list[dict]) -> dict`
```python
dk.check_firewall_rules_status([{"source": "0.0.0.0/0", "port": 22}])
# {'total_rules': 1, 'risky_count': 1, ...}
```

### `detect_arp_spoofing(arp_table: dict, known_good_mappings: dict) -> list[dict]`
```python
dk.detect_arp_spoofing({"192.168.1.1": "AA:BB:CC:DD:EE:FF"}, {"192.168.1.1": "11:22:33:44:55:66"})
```

### `validate_dns_response(hostname, resolved_ip, expected_ips) -> dict`

### `check_vpn_connection_security(public_ip_before, public_ip_after, dns_servers_after, expected_vpn_dns) -> dict`

### `audit_server_config(config: dict) -> list[str]`
```python
dk.audit_server_config({"debug": True, "firewall_enabled": False})
# ['Debug mode is on - must not be enabled in production', 'Firewall is disabled']
```

---

## 7. Cryptography & secrets management

### `generate_secure_token(length_bytes=32) -> str`

### `ApiKeyRecord` / `rotate_api_key(current, grace_period_seconds=3600) -> tuple`

### `mask_sensitive_data_in_logs(log_line, fields_to_mask=(...)) -> str`
```python
dk.mask_sensitive_data_in_logs('login attempt password="hunter2" user=barman')
# 'login attempt password=***REDACTED*** user=barman'
```

### `encrypt_sensitive_data(plaintext, key: bytes) -> str` / `decrypt_sensitive_data(token, key: bytes) -> str`
AES-256-GCM. Requires `pip install "defendking[full]"`.
```python
import secrets
key = secrets.token_bytes(32)
token = dk.encrypt_sensitive_data("top secret", key)
dk.decrypt_sensitive_data(token, key)   # 'top secret'
```

### `validate_jwt_token(token, secret, algorithms=None) -> dict`
Also rejects `alg: none` tokens explicitly.

### `check_secrets_in_codebase(directory, file_extensions=(...)) -> list[dict]`
Detects AWS/GitHub/Slack/Google/Stripe/SendGrid/Twilio/Mailgun keys, JWTs,
private keys, and DB connection strings with embedded credentials.
```python
dk.check_secrets_in_codebase("./src")
# [{'file': './src/config.py', 'line': 4, 'type': 'Possible GitHub personal access / OAuth token'}]
```

---

## 8. Monitoring, risk scoring & reporting

### `SecurityFinding(category, description, severity, timestamp=now)`
`severity` must be one of `low`/`medium`/`high`/`critical`.

### `calculate_risk_score(findings: list[SecurityFinding]) -> dict`
```python
findings = [dk.SecurityFinding("auth", "weak password policy", "high")]
dk.calculate_risk_score(findings)
# {'score': 14, 'level': 'low', 'finding_count': 1, 'by_severity': {'high': 1}, 'has_critical_finding': False}
```

### `generate_security_report(findings, target_name="system") -> str`
Markdown report.

### `export_findings_to_json(findings, output_path) -> dict`
```python
dk.export_findings_to_json(findings, "report.json")
# {'success': True, 'path': 'report.json'}
```

### `generate_incident_response_report(incident_title, detected_at, affected_systems, actions_taken) -> str`

### `audit_user_permissions(users: list[dict], expected_max_role: dict) -> list[dict]`

### `notify_admin_dashboard(finding, webhook_url) -> dict` / `send_security_alert(message, telegram_bot_token, chat_id) -> dict`

### `schedule_periodic_scan(interval_seconds, scan_function, max_runs=None) -> None`

### `generate_security_checklist(system_type) -> list[str]`
`system_type` is one of `web`/`server`/`network`/`cloud`/`mobile`.
```python
dk.generate_security_checklist("cloud")
```

---

## 9. API & session security

### `validate_api_request_signature(payload, timestamp, signature, secret, tolerance_seconds=300) -> dict`
HMAC-SHA256 request signing/verification (the pattern used by most
REST/exchange/trading APIs).
```python
import time, hmac, hashlib
secret = "shared-secret"
ts = str(time.time())
sig = hmac.new(secret.encode(), f"{ts}{payload}".encode(), hashlib.sha256).hexdigest()
dk.validate_api_request_signature(payload, ts, sig, secret)
# {'valid': True, 'reason': None}
```

### `detect_replay_attack(nonce, seen_nonces: set, max_stored=100_000) -> bool`
```python
seen = set()
dk.detect_replay_attack("req-123", seen)   # False (new)
dk.detect_replay_attack("req-123", seen)   # True (replay!)
```
Not thread-safe and has no time-based expiry (only a size cap) - for
those, use `ReplayGuard` below instead.

### `ReplayGuard(ttl_seconds=300)`
Thread-safe, TTL-based replay detector - each nonce is automatically
forgotten after `ttl_seconds` instead of only being evicted once a size
cap is hit.
```python
guard = dk.ReplayGuard(ttl_seconds=300)
guard.check("req-123")   # False (new)
guard.check("req-123")   # True (replay!)
```

### `check_session_fixation(pre_login_session_id, post_login_session_id) -> dict`
```python
dk.check_session_fixation("sess-abc", "sess-abc")
# {'rotated': False, 'vulnerable_to_fixation': True, ...}
```

### `generate_scoped_api_key(scopes: list[str], prefix="sk") -> dict`
```python
dk.generate_scoped_api_key(["read", "trade"])
# {'api_key': 'sk_...', 'stored_hash': '...', 'scopes': ['read', 'trade'], ...}
```

### `check_api_rate_limit_headers(headers: dict) -> dict`
```python
dk.check_api_rate_limit_headers({"X-RateLimit-Remaining": "0", "Retry-After": "30"})
# {'should_back_off': True, 'suggested_backoff_seconds': 30, ...}
```

---

## Known limitations

- **Heuristic detection still isn't a real classifier.** `detect_xss_patterns`,
  `validate_input_against_sql_injection`, and `check_suspicious_url` are
  regex-based signals, not a guarantee of safety. A determined attacker can
  craft a payload that slips past a fixed pattern list. Always pair them
  with the real defenses: parameterized queries/ORM for SQL, contextual
  output encoding + a strict CSP for XSS, and a reputation/block-list
  service for URLs.
- **The local common-password list is a sample**, not a real breach corpus.
  `check_password_breached` queries the Have I Been Pwned API by default —
  the local list is only an offline fallback.
- **`detect_anomalous_login_location`** gives an accurate result only when
  you pass real `previous_coords`/`new_coords` (haversine distance via
  `distance_km_between`). Without coordinates it falls back to a
  conservative fixed-distance estimate.
- **`entropy_bits` in `check_password_strength`** is a charset-size-based
  estimate, not a dictionary-aware one (see the function's own docstring
  for detail) - `score`/`label` combine it with pattern detection for a
  more reliable overall verdict.
- **`scan_directory_for_malware_signatures`** does exact-hash matching
  only, which a single changed byte evades entirely - this is a property
  of hash-based detection in general (see the function's docstring), not
  something fixable within the function; pair it with a real AV/EDR
  engine if you need resilience to modified variants.
- **`detect_replay_attack`'s in-memory `seen_nonces` set** isn't
  thread-safe and doesn't expire entries by time, only by count
  (`max_stored`) - use `ReplayGuard` instead if either matters to you.
- **`RateLimiter`/`IPBlocklist`/`ReplayGuard` are in-process only.** Their
  internal locks make them safe to share across *threads*, but not across
  separate *processes* or machines - back them with Redis (or similar)
  for a multi-process/multi-instance deployment.
- **`schedule_periodic_scan`** is a simple blocking loop for scripts/demos,
  not a production scheduler — use `APScheduler` or a system cron job for
  real deployments.

## Changelog

### 3.6.17
- **Fixed the CI pipeline itself** (the previous release's workflow had
  two bugs, caught only after the first real run on GitHub):
  - The test job ran `pytest tests/` but the actual test directory is
    named `test/` (no "s") - every test job failed immediately with a
    "no tests collected" error regardless of the code being tested.
    Fixed by aligning the workflow, `pyproject.toml`'s mypy config, and
    the README's documented commands to the real `test/` directory name.
  - `requires-python` was set to `>=3.9`, which made the `Test (Python
    3.8)` matrix job fail at the `pip install` step before any test
    could even run, since this project intentionally supports 3.8.
    Reverted to `>=3.8` (verified via AST inspection that the codebase
    uses no 3.9+-only syntax - no walrus operator, no `match` statements).
- No functional changes to `defendking/handler.py` in this release - this
  is a CI/tooling-only fix.

### 3.6.16
- **Fixed every weakness identified in a self-review of 2.5.1:**
  - **ReDoS mitigation:** all regex-heavy scanning functions now cap
    input length (`_MAX_SCANNED_TEXT_LENGTH` / `_MAX_LONG_TEXT_LENGTH`)
    before running pattern matching, bounding worst-case regex cost
    regardless of which specific pattern might be added later.
  - **Thread-safety:** `RateLimiter` and `IPBlocklist` now use an
    internal lock and are safe to share across threads. Added
    `ReplayGuard`, a thread-safe, TTL-based replacement for
    `detect_replay_attack`'s plain-set approach.
  - **Fewer false positives:** `mask_sensitive_data_in_logs` now
    Luhn-validates digit runs before redacting them as "card numbers,"
    instead of flagging any 13-19-digit sequence (phone numbers, order
    IDs, timestamps included).
  - **Network retry/backoff:** `check_ssl_certificate` and
    `check_tls_version_support` now retry transient connection failures
    with a short backoff instead of reporting a single dropped packet as
    a hard failure.
  - **Honest documentation for two inherent limitations** that aren't
    fixable within the function itself: `entropy_bits`' charset-based
    (not dictionary-aware) estimate, and exact-hash malware matching's
    single-byte-change blind spot.
- **Added CI/CD** (`.github/workflows/ci.yml`): test matrix (Python
  3.9-3.12), `ruff` + `mypy` lint job, and an automated PyPI publish job
  (via Trusted Publishing/OIDC) triggered by pushing a version tag.
- No new user-facing functions were added in this release - the focus was
  entirely on hardening the ~70 functions that already existed.

### 2.5.1
- Added `defendking.exceptions` (`DefendKingError`, `InvalidInputError`,
  `ExternalServiceError`) and applied a consistent error-handling
  convention across every function (see [Error handling](#error-handling)).
- Substantially deepened detection accuracy across every section:
  password entropy scoring, homoglyph/TLD-swap domain-similarity checks,
  weighted risk scoring for URLs and phishing emails, SQLi severity
  classification, more secret-scanning patterns, more security-header/CSP
  checks, "high confidence" flagging for impossible-travel detection, and
  more.
- Full README rewrite with per-function documentation and examples.
- No new functions were added in this release — the focus was entirely on
  robustness and detection depth of the existing ~65 functions plus the
  five functions the 1.5.0 API-security section already introduced.

### 1.5.0
- New section: API & session security (`validate_api_request_signature`,
  `detect_replay_attack`, `check_session_fixation`,
  `generate_scoped_api_key`, `check_api_rate_limit_headers`).
- First pass at sharpening detection across passwords, URLs/phishing,
  XSS/SQLi, file extensions, secret-scanning, security headers/CSP, and
  firewall/default-credential checks.

### 1.0.0
- Initial public release: 8 sections, ~65 functions.

## Versioning

Following semantic-ish convention: first digit = structural changes, second
= new features, third = bug fixes.
