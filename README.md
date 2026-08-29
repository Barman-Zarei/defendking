# DefendKing

A defensive-only Python security toolkit (~60 functions) covering:

1. Passwords & authentication
2. Phishing & URL/email safety
3. Brute-force / abuse protection
4. File / malware hygiene
5. Web application security (XSS, CSRF, SQLi heuristics, headers)
6. Network-level defense (TLS, firewall rules, ARP/DNS checks)
7. Cryptography & secrets management
8. Monitoring, risk scoring & reporting

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
    └── handler.py         ← all ~60 functions live here
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

## Known limitations

- **Heuristic detection isn't a real classifier.** `detect_xss_patterns`,
  `validate_input_against_sql_injection`, and `check_suspicious_url` are
  regex-based signals, not a guarantee of safety. Always pair them with the
  real defenses: parameterized queries/ORM for SQL, contextual output
  encoding + a strict CSP for XSS, and a reputation/block-list service for
  URLs.
- **The local common-password list is a small sample**, not a real breach
  corpus. `check_password_breached` queries the Have I Been Pwned API by
  default — the local list is only an offline fallback.
- **`detect_anomalous_login_location`** gives an accurate result only when
  you pass real `previous_coords` / `new_coords` (it then uses haversine
  distance via `distance_km_between`). Without coordinates it falls back to
  a conservative fixed-distance estimate, which is a rough approximation.

## Versioning

Following semantic-ish convention: first digit = structural changes, second
= new features, third = bug fixes.
