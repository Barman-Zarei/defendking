# DefendKing

A defensive-only Python security toolkit (~70 functions) covering:

1. Passwords & authentication
2. Phishing & URL/email safety
3. Brute-force / abuse protection
4. File / malware hygiene
5. Web application security (XSS, CSRF, SQLi heuristics, headers)
6. Network-level defense (TLS, firewall rules, ARP/DNS checks)
7. Cryptography & secrets management
8. Monitoring, risk scoring & reporting
9. API & session security (request signing, replay protection, session fixation)

Every function protects, detects, or reports — none of them attack, exploit,
or access systems you don't own/manage.

**Author:** Barman
**License:** MIT

## Structure

```
defendking/
├── pyproject.toml
├── README.md
├── tests/
│   └── test_defendking.py
└── defendking/            ← the actual package
    ├── __init__.py        ← re-exports everything from handler.py
    └── handler.py         ← all ~70 functions live here
```

## Install

```bash
pip install -e .            # core package, no third-party deps required
pip install -e ".[full]"    # adds requests / cryptography / pyjwt for the
                             # functions that call external APIs or do AES/JWT
pip install -e ".[dev]"     # adds pytest for running the test suite
```

```python
import defendking
defendking.check_password_strength("...")

# or
from defendking import check_password_strength
```

## Run the tests

```bash
python -m pytest tests/ -v
```

## What's new in 1.5.0

- **New section: API & session security** —
  `validate_api_request_signature` (HMAC request signing/verification,
  useful for exchange/trading-bot APIs), `detect_replay_attack` (nonce
  tracking), `check_session_fixation` (session-ID rotation check),
  `generate_scoped_api_key`, `check_api_rate_limit_headers`.
- **Sharper detection across existing heuristics:**
  - Password checks now catch leetspeak substitutions of common passwords
    (`P@ssw0rd`), repeated multi-character blocks, alphabetic sequences,
    and date-like patterns, and factor all of that into the strength score.
  - URL/phishing checks now catch punycode domains, hex/decimal-encoded
    IPs, deep subdomain nesting, non-standard ports, more shorteners/TLDs,
    and a well-known brand name appearing in a domain that isn't its real
    one.
  - Domain-similarity checks now normalize common homoglyph substitutions
    (`rn`→`m`, `1`→`l`, `0`→`o`, ...) before computing edit distance, and
    separately flag a trusted brand name appearing as a *substring* of a
    longer spoofed domain.
  - Email phishing scanning adds unusual-payment-method detection (gift
    cards, wire transfers, crypto), dangerous-attachment prompts, and a
    "brand mentioned but no link points to its real domain" check.
  - XSS/SQLi heuristics cover more payload shapes (vbscript:, data: URIs,
    meta-refresh redirects, entity/unicode-encoded payloads, WAITFOR
    DELAY, UNION ALL SELECT, GROUP_CONCAT, hex literals, and more).
  - File-extension checks cover more dangerous extensions (.hta, .lnk,
    .wsf, .apk, ...) plus a right-to-left-override filename trick.
  - Secret-scanning covers more token formats (GitHub, Slack, Google,
    Stripe, SendGrid, Twilio, JWTs, AWS secret keys, DB passwords).
  - Security-header and CSP checks cover more headers/directives
    (Permissions-Policy, COOP/CORP, frame-ancestors, base-uri, object-src).
  - Firewall-rule and default-credential checks cover more ports and more
    known factory-default username/password pairs.

## Known limitations

- **Heuristic detection still isn't a real classifier.** `detect_xss_patterns`,
  `validate_input_against_sql_injection`, and `check_suspicious_url` are
  regex-based signals, not a guarantee of safety — 1.5.0 widens their
  coverage, but a determined attacker can still craft a payload that slips
  past a fixed pattern list. Always pair them with the real defenses:
  parameterized queries/ORM for SQL, contextual output encoding + a strict
  CSP for XSS, and a reputation/block-list service for URLs.
- **The local common-password list is a small sample**, not a real breach
  corpus. `check_password_breached` queries the Have I Been Pwned API by
  default — the local list is only an offline fallback.
- **`detect_anomalous_login_location`** gives an accurate result only when
  you pass real `previous_coords` / `new_coords` (it then uses haversine
  distance via `distance_km_between`). Without coordinates it falls back to
  a conservative fixed-distance estimate, which is a rough approximation.
- **`detect_replay_attack`'s in-memory `seen_nonces` set** doesn't persist
  or expire entries by time (only by count via `max_stored`) — for a real
  multi-process service, back it with a TTL-based store (e.g. Redis).

## Versioning

Following semantic-ish convention: first digit = structural changes, second
= new features, third = bug fixes.
