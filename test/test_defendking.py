"""
Unit tests for DefendKing.

Run with:  python -m pytest test/ -v
or:        python -m unittest discover -s test

These tests avoid real network calls (breach API, VirusTotal, Telegram,
etc.) by either testing pure-logic functions directly or by passing
use_api=False / mocking the `requests` calls where relevant.
"""

import os
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import defendking as dk


class TestPasswordFunctions(unittest.TestCase):
    def test_check_password_strength_weak(self):
        result = dk.check_password_strength("abc")
        self.assertEqual(result["label"], "weak")
        self.assertTrue(len(result["suggestions"]) > 0)

    def test_check_password_strength_strong(self):
        result = dk.check_password_strength("Tr0ub4dor&3XyZ!")
        self.assertEqual(result["label"], "strong")

    def test_check_password_strength_rejects_non_string(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.check_password_strength(12345678)

    def test_check_password_strength_flags_common_password(self):
        result = dk.check_password_strength("password")
        self.assertLessEqual(result["score"], 10)

    def test_check_password_breached_local_fallback(self):
        result = dk.check_password_breached("123456", use_api=False)
        self.assertTrue(result["breached"])
        self.assertEqual(result["source"], "local_list")

    def test_check_password_breached_local_fallback_not_breached(self):
        result = dk.check_password_breached("Xk9$mQ2!vLpZ", use_api=False)
        self.assertFalse(result["breached"])

    def test_generate_strong_password_length_and_classes(self):
        pw = dk.generate_strong_password(length=20)
        self.assertEqual(len(pw), 20)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_generate_strong_password_rejects_short_length(self):
        with self.assertRaises(ValueError):
            dk.generate_strong_password(length=4)

    def test_hash_and_verify_password_roundtrip(self):
        stored = dk.hash_password("correct horse battery staple")
        self.assertTrue(dk.verify_password("correct horse battery staple", stored))
        self.assertFalse(dk.verify_password("wrong password", stored))

    def test_verify_password_rejects_malformed_hash(self):
        with self.assertRaises(ValueError):
            dk.verify_password("whatever", "not-a-valid-hash")

    def test_detect_common_password_patterns(self):
        issues = dk.detect_common_password_patterns("aaa1234qwerty2020")
        self.assertTrue(len(issues) >= 3)

    def test_check_two_factor_status(self):
        good = dk.check_two_factor_status(True, backup_codes_count=5)
        self.assertEqual(good["recommendation"], "Good posture")
        bad = dk.check_two_factor_status(False, backup_codes_count=0)
        self.assertNotEqual(bad["recommendation"], "Good posture")

    def test_check_password_expiry(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=200)
        result = dk.check_password_expiry(old_date, max_age_days=90)
        self.assertTrue(result["expired"])

    def test_validate_password_policy_compliance(self):
        result = dk.validate_password_policy_compliance("alllowercase")
        self.assertFalse(result["compliant"])
        self.assertTrue(len(result["violations"]) > 0)

    def test_check_default_credentials(self):
        self.assertTrue(dk.check_default_credentials("admin", "admin"))
        self.assertFalse(dk.check_default_credentials("barman", "S3cur3!"))


class TestPhishingFunctions(unittest.TestCase):
    def test_check_suspicious_url_flags_ip_and_at_symbol(self):
        result = dk.check_suspicious_url("http://192.168.1.1@paypal-login.tk/verify")
        self.assertTrue(result["suspicious"])
        self.assertTrue(len(result["reasons"]) >= 3)

    def test_check_suspicious_url_clean_url(self):
        result = dk.check_suspicious_url("https://www.python.org/downloads/")
        self.assertFalse(result["suspicious"])

    def test_check_domain_similarity_detects_typosquat(self):
        result = dk.check_domain_similarity("paypa1.com", ["paypal.com", "google.com"])
        self.assertTrue(result["likely_typosquat"])

    def test_check_domain_similarity_trusted_domain_not_flagged(self):
        result = dk.check_domain_similarity("paypal.com", ["paypal.com", "google.com"])
        self.assertFalse(result["likely_typosquat"])

    def test_scan_email_for_phishing_signs(self):
        email = "Dear customer, act now and click here to verify your account: http://bit.ly/xyz"
        result = dk.scan_email_for_phishing_signs(email)
        self.assertTrue(result["suspicious"])

    def test_validate_email_format_and_mx_without_mx_check(self):
        result = dk.validate_email_format_and_mx("test@example.com", check_mx=False)
        self.assertTrue(result["valid_format"])
        self.assertIsNone(result["has_mx_record"])

    def test_validate_email_format_and_mx_invalid_format(self):
        result = dk.validate_email_format_and_mx("not-an-email", check_mx=False)
        self.assertFalse(result["valid_format"])


class TestBruteForceProtection(unittest.TestCase):
    def test_rate_limiter_allows_within_limit(self):
        limiter = dk.RateLimiter(max_attempts=3, window_seconds=60)
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("1.2.3.4"))

    def test_rate_limiter_blocks_over_limit(self):
        limiter = dk.RateLimiter(max_attempts=2, window_seconds=60)
        limiter.allow("1.2.3.4")
        limiter.allow("1.2.3.4")
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_detect_brute_force_attempt_true(self):
        now = time.time()
        timestamps = [now, now + 1, now + 2, now + 3, now + 4]
        self.assertTrue(dk.detect_brute_force_attempt(timestamps, threshold=5, window_seconds=60))

    def test_detect_brute_force_attempt_false_spread_out(self):
        now = time.time()
        timestamps = [now, now + 100, now + 200, now + 300, now + 400]
        self.assertFalse(dk.detect_brute_force_attempt(timestamps, threshold=5, window_seconds=60))

    def test_ip_blocklist_expiry(self):
        blocklist = dk.IPBlocklist()
        blocklist.block("10.0.0.1", duration_seconds=1)
        self.assertTrue(blocklist.is_blocked("10.0.0.1"))
        time.sleep(1.1)
        self.assertFalse(blocklist.is_blocked("10.0.0.1"))

    def test_implement_captcha_trigger_simple_counter(self):
        self.assertFalse(dk.implement_captcha_trigger(2, threshold=3))
        self.assertTrue(dk.implement_captcha_trigger(3, threshold=3))

    def test_implement_captcha_trigger_time_windowed(self):
        now = time.time()
        burst = [now, now + 1, now + 2]
        self.assertTrue(
            dk.implement_captcha_trigger(
                failed_attempts=len(burst), threshold=3,
                window_seconds=60, failed_timestamps=burst,
            )
        )
        spread = [now, now + 500, now + 1000]
        self.assertFalse(
            dk.implement_captcha_trigger(
                failed_attempts=len(spread), threshold=3,
                window_seconds=60, failed_timestamps=spread,
            )
        )

    def test_distance_km_between_known_cities(self):
        # Tehran to Mashhad is roughly 750-800 km in a straight line.
        tehran = (35.6892, 51.3890)
        mashhad = (36.2605, 59.6168)
        km = dk.distance_km_between(*tehran, *mashhad)
        self.assertTrue(700 <= km <= 850)

    def test_detect_anomalous_login_location_same_country(self):
        now = datetime.now(timezone.utc)
        result = dk.detect_anomalous_login_location("IR", "IR", now, now + timedelta(hours=1))
        self.assertFalse(result["anomalous"])

    def test_detect_anomalous_login_location_with_real_coords(self):
        t1 = datetime.now(timezone.utc)
        t2 = t1 + timedelta(minutes=5)
        tehran = (35.6892, 51.3890)
        new_york = (40.7128, -74.0060)
        result = dk.detect_anomalous_login_location(
            "IR", "US", t1, t2,
            previous_coords=tehran, new_coords=new_york,
        )
        self.assertTrue(result["anomalous"])
        self.assertEqual(result["distance_source"], "coordinates")

    def test_detect_privilege_escalation_attempt(self):
        allowed = {"viewer": {"editor"}, "editor": {"admin"}}
        self.assertTrue(dk.detect_privilege_escalation_attempt("viewer", "admin", allowed))
        self.assertFalse(dk.detect_privilege_escalation_attempt("viewer", "editor", allowed))


class TestFileHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp_path = "test_tmp_file.txt"
        with open(self.tmp_path, "w") as f:
            f.write("hello world")

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)
        if os.path.exists("./quarantine"):
            for name in os.listdir("./quarantine"):
                os.remove(os.path.join("./quarantine", name))
            os.rmdir("./quarantine")

    def test_compute_file_hash_is_deterministic(self):
        h1 = dk.compute_file_hash(self.tmp_path)
        h2 = dk.compute_file_hash(self.tmp_path)
        self.assertEqual(h1, h2)

    def test_check_file_integrity(self):
        good_hash = dk.compute_file_hash(self.tmp_path)
        self.assertTrue(dk.check_file_integrity(self.tmp_path, good_hash))
        self.assertFalse(dk.check_file_integrity(self.tmp_path, "0" * 64))

    def test_detect_suspicious_file_extension(self):
        result = dk.detect_suspicious_file_extension("invoice.pdf.exe")
        self.assertTrue(result["flagged"])
        self.assertTrue(result["double_extension_trick"])

    def test_detect_suspicious_file_extension_safe_file(self):
        result = dk.detect_suspicious_file_extension("report.pdf")
        self.assertFalse(result["flagged"])

    def test_quarantine_suspicious_file(self):
        dest = dk.quarantine_suspicious_file(self.tmp_path)
        self.assertTrue(os.path.exists(dest))
        self.assertFalse(os.path.exists(self.tmp_path))
        self.tmp_path = dest  # let tearDown-adjacent cleanup handle it via quarantine dir


class TestWebAppSecurity(unittest.TestCase):
    def test_sanitize_user_input_escapes_script_tag(self):
        result = dk.sanitize_user_input("<script>alert(1)</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_check_csrf_token_validity(self):
        token = dk.generate_csrf_token()
        self.assertTrue(dk.check_csrf_token_validity(token, token))
        self.assertFalse(dk.check_csrf_token_validity(token, "different-token"))
        self.assertFalse(dk.check_csrf_token_validity("", token))

    def test_validate_cors_policy_wildcard_warns(self):
        result = dk.validate_cors_policy(["*"], "https://example.com")
        self.assertTrue(result["allowed"])
        self.assertIsNotNone(result["warning"])

    def test_detect_xss_patterns(self):
        found = dk.detect_xss_patterns("<img src=x onerror=alert(1)>")
        self.assertTrue(len(found) > 0)

    def test_check_secure_cookie_flags(self):
        result = dk.check_secure_cookie_flags("session=abc; HttpOnly; Secure; SameSite=Strict")
        self.assertTrue(result["httponly"])
        self.assertTrue(result["secure"])
        self.assertTrue(result["samesite"])

    def test_validate_input_against_sql_injection(self):
        result = dk.validate_input_against_sql_injection("' OR '1'='1")
        self.assertTrue(result["suspicious"])
        clean = dk.validate_input_against_sql_injection("regular search term")
        self.assertFalse(clean["suspicious"])

    def test_check_security_headers(self):
        headers = {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff"}
        result = dk.check_security_headers(headers)
        self.assertIn("x-frame-options", result["missing"])

    def test_verify_csp_header_flags_unsafe_inline(self):
        result = dk.verify_csp_header("default-src 'self'; script-src 'unsafe-inline'")
        self.assertFalse(result["safe"])


class TestNetworkDefense(unittest.TestCase):
    def test_check_firewall_rules_status(self):
        rules = [
            {"source": "0.0.0.0/0", "port": 22},
            {"source": "10.0.0.0/8", "port": 22},
        ]
        result = dk.check_firewall_rules_status(rules)
        self.assertEqual(result["risky_count"], 1)

    def test_detect_arp_spoofing(self):
        arp_table = {"192.168.1.1": "AA:BB:CC:DD:EE:FF"}
        known_good = {"192.168.1.1": "11:22:33:44:55:66"}
        conflicts = dk.detect_arp_spoofing(arp_table, known_good)
        self.assertEqual(len(conflicts), 1)

    def test_validate_dns_response(self):
        result = dk.validate_dns_response("example.com", "93.184.216.34", ["93.184.216.34"])
        self.assertTrue(result["valid"])

    def test_check_vpn_connection_security_detects_leak(self):
        result = dk.check_vpn_connection_security(
            "1.2.3.4", "5.6.7.8", ["8.8.8.8"], ["10.0.0.1"],
        )
        self.assertTrue(result["dns_leak_detected"])
        self.assertFalse(result["secure"])

    def test_audit_server_config(self):
        issues = dk.audit_server_config({"debug": True, "firewall_enabled": False})
        self.assertTrue(len(issues) >= 2)


class TestCryptoAndSecrets(unittest.TestCase):
    def test_generate_secure_token_is_unique(self):
        t1 = dk.generate_secure_token()
        t2 = dk.generate_secure_token()
        self.assertNotEqual(t1, t2)

    def test_mask_sensitive_data_in_logs(self):
        line = 'login attempt password="hunter2" user=barman'
        masked = dk.mask_sensitive_data_in_logs(line)
        self.assertNotIn("hunter2", masked)
        self.assertIn("REDACTED", masked)

    def test_encrypt_decrypt_roundtrip(self):
        import secrets as _secrets
        key = _secrets.token_bytes(32)
        ciphertext = dk.encrypt_sensitive_data("top secret plan", key)
        plaintext = dk.decrypt_sensitive_data(ciphertext, key)
        self.assertEqual(plaintext, "top secret plan")


class TestMonitoringAndReporting(unittest.TestCase):
    def test_calculate_risk_score_empty(self):
        result = dk.calculate_risk_score([])
        self.assertEqual(result["score"], 0)

    def test_calculate_risk_score_with_findings(self):
        findings = [
            dk.SecurityFinding(category="auth", description="weak password policy", severity="high"),
            dk.SecurityFinding(category="network", description="open port", severity="critical"),
        ]
        result = dk.calculate_risk_score(findings)
        self.assertGreater(result["score"], 0)
        self.assertEqual(result["finding_count"], 2)

    def test_generate_security_report_contains_findings(self):
        findings = [dk.SecurityFinding(category="auth", description="test finding", severity="low")]
        report = dk.generate_security_report(findings, target_name="TestSystem")
        self.assertIn("TestSystem", report)
        self.assertIn("test finding", report)

    def test_audit_user_permissions(self):
        users = [{"department": "support", "role": "admin"}]
        expected = {"support": "viewer"}
        over_privileged = dk.audit_user_permissions(users, expected)
        self.assertEqual(len(over_privileged), 1)

    def test_generate_security_checklist_known_type(self):
        checklist = dk.generate_security_checklist("web")
        self.assertTrue(len(checklist) > 0)

    def test_generate_security_checklist_unknown_type(self):
        checklist = dk.generate_security_checklist("mainframe")
        self.assertEqual(checklist, ["Unknown system type"])


class TestApiAndSessionSecurity(unittest.TestCase):
    def test_validate_api_request_signature_valid(self):
        secret = "shared-secret"
        timestamp = str(time.time())
        payload = '{"symbol":"BTCUSDT","side":"buy"}'
        import hashlib as _hashlib
        import hmac as _hmac
        sig = _hmac.new(secret.encode(), f"{timestamp}{payload}".encode(), _hashlib.sha256).hexdigest()
        result = dk.validate_api_request_signature(payload, timestamp, sig, secret)
        self.assertTrue(result["valid"])

    def test_validate_api_request_signature_bad_signature(self):
        result = dk.validate_api_request_signature(
            "payload", str(time.time()), "deadbeef", "secret"
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "signature mismatch")

    def test_validate_api_request_signature_stale_timestamp(self):
        old_ts = str(time.time() - 10_000)
        result = dk.validate_api_request_signature("payload", old_ts, "whatever", "secret")
        self.assertFalse(result["valid"])
        self.assertIn("tolerance", result["reason"])

    def test_detect_replay_attack_first_time_not_replay(self):
        seen = set()
        self.assertFalse(dk.detect_replay_attack("nonce-1", seen))
        self.assertIn("nonce-1", seen)

    def test_detect_replay_attack_second_time_is_replay(self):
        seen = {"nonce-1"}
        self.assertTrue(dk.detect_replay_attack("nonce-1", seen))

    def test_check_session_fixation_rotated(self):
        result = dk.check_session_fixation("session-a", "session-b")
        self.assertTrue(result["rotated"])
        self.assertFalse(result["vulnerable_to_fixation"])

    def test_check_session_fixation_not_rotated(self):
        result = dk.check_session_fixation("session-a", "session-a")
        self.assertFalse(result["rotated"])
        self.assertTrue(result["vulnerable_to_fixation"])

    def test_generate_scoped_api_key(self):
        result = dk.generate_scoped_api_key(["read", "trade"], prefix="sk")
        self.assertTrue(result["api_key"].startswith("sk_"))
        self.assertEqual(result["scopes"], ["read", "trade"])
        expected_hash = __import__("hashlib").sha256(result["api_key"].encode()).hexdigest()
        self.assertEqual(result["stored_hash"], expected_hash)

    def test_check_api_rate_limit_headers_should_back_off(self):
        headers = {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "60"}
        result = dk.check_api_rate_limit_headers(headers)
        self.assertTrue(result["should_back_off"])
        self.assertEqual(result["limit"], 100)

    def test_check_api_rate_limit_headers_no_headers(self):
        result = dk.check_api_rate_limit_headers({})
        self.assertFalse(result["has_rate_limit_headers"])
        self.assertFalse(result["should_back_off"])


class TestStrengthenedDetection(unittest.TestCase):
    """Sanity checks for the tightened heuristics across existing sections."""

    def test_leetspeak_common_password_detected(self):
        issues = dk.detect_common_password_patterns("L3tM3in")
        self.assertTrue(any("leetspeak" in issue.lower() for issue in issues))

    def test_check_suspicious_url_flags_punycode(self):
        result = dk.check_suspicious_url("https://xn--pypal-4ve.com/login")
        self.assertTrue(result["suspicious"])

    def test_check_domain_similarity_flags_substring_spoof(self):
        result = dk.check_domain_similarity("paypal-secure-login.com", ["paypal.com"])
        self.assertTrue(result["likely_typosquat"])
        self.assertTrue(result["matched_via_substring"])

    def test_detect_xss_patterns_flags_meta_refresh(self):
        found = dk.detect_xss_patterns('<meta http-equiv="refresh" content="0;url=http://evil.com">')
        self.assertTrue(len(found) > 0)

    def test_validate_input_against_sql_injection_flags_waitfor_delay(self):
        result = dk.validate_input_against_sql_injection("'; WAITFOR DELAY '0:0:5'--")
        self.assertTrue(result["suspicious"])

    def test_detect_suspicious_file_extension_flags_hta(self):
        result = dk.detect_suspicious_file_extension("invoice.hta")
        self.assertTrue(result["flagged"])

    def test_check_secrets_in_codebase_detects_github_token(self):
        tmp_dir = "test_tmp_secrets_dir"
        os.makedirs(tmp_dir, exist_ok=True)
        try:
            with open(os.path.join(tmp_dir, "config.py"), "w") as f:
                f.write('GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n')
            findings = dk.check_secrets_in_codebase(tmp_dir)
            self.assertTrue(any("GitHub" in f["type"] for f in findings))
        finally:
            for name in os.listdir(tmp_dir):
                os.remove(os.path.join(tmp_dir, name))
            os.rmdir(tmp_dir)


class TestExceptionHierarchy(unittest.TestCase):
    """2.5.1: verify the InvalidInputError / ExternalServiceError convention."""

    def test_invalid_input_error_is_a_value_error(self):
        self.assertTrue(issubclass(dk.InvalidInputError, ValueError))
        self.assertTrue(issubclass(dk.InvalidInputError, dk.DefendKingError))

    def test_external_service_error_is_a_defendking_error(self):
        self.assertTrue(issubclass(dk.ExternalServiceError, dk.DefendKingError))

    def test_programmer_error_raises_invalid_input_error(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.generate_strong_password(length=2)
        with self.assertRaises(dk.InvalidInputError):
            dk.check_domain_similarity(123, ["example.com"])
        with self.assertRaises(dk.InvalidInputError):
            dk.RateLimiter(max_attempts=-1)
        with self.assertRaises(dk.InvalidInputError):
            IPB = dk.IPBlocklist()
            IPB.block("not-an-ip")

    def test_external_failure_returns_error_dict_not_raise(self):
        # check_ssl_certificate against an unreachable/invalid host should
        # report the failure inline rather than raise.
        result = dk.check_ssl_certificate("this-host-should-not-exist.invalid", timeout=1)
        self.assertFalse(result["valid"])
        self.assertEqual(result.get("error_type"), "ExternalServiceError")

    def test_compute_file_hash_raises_external_service_error_for_missing_file(self):
        with self.assertRaises(dk.ExternalServiceError):
            dk.compute_file_hash("this/path/does/not/exist.txt")

    def test_log_failed_login_attempt_returns_dict(self):
        path = "test_tmp_login_log.csv"
        try:
            result = dk.log_failed_login_attempt("baduser", "1.2.3.4", log_path=path)
            self.assertTrue(result["success"])
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_export_findings_to_json_returns_dict(self):
        findings = [dk.SecurityFinding(category="test", description="x", severity="low")]
        path = "test_tmp_findings.json"
        try:
            result = dk.export_findings_to_json(findings, path)
            self.assertTrue(result["success"])
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_security_finding_rejects_invalid_severity(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.SecurityFinding(category="x", description="y", severity="apocalyptic")


class TestFurtherStrengthenedDetection(unittest.TestCase):
    """2.5.1: spot-check the deepened detection logic across sections."""

    def test_check_password_strength_has_entropy_field(self):
        result = dk.check_password_strength("correct horse battery staple 42!")
        self.assertIn("entropy_bits", result)
        self.assertGreater(result["entropy_bits"], 0)

    def test_check_suspicious_url_has_risk_score(self):
        result = dk.check_suspicious_url("http://192.168.1.1@fake-paypal-login.tk/verify")
        self.assertIn("risk_score", result)
        self.assertGreater(result["risk_score"], 0)

    def test_scan_email_for_phishing_signs_has_risk_score(self):
        email = "Dear customer, act now and click here to verify your account: http://bit.ly/xyz"
        result = dk.scan_email_for_phishing_signs(email)
        self.assertIn("risk_score", result)
        self.assertGreater(result["risk_score"], 0)

    def test_validate_input_against_sql_injection_has_severity(self):
        result = dk.validate_input_against_sql_injection("' UNION ALL SELECT username, password FROM users--")
        self.assertIn("severity", result)
        self.assertIn(result["severity"], ("low", "medium", "high"))

    def test_detect_anomalous_login_location_high_confidence(self):
        t1 = datetime.now(timezone.utc)
        t2 = t1 + timedelta(minutes=1)
        tehran = (35.6892, 51.3890)
        new_york = (40.7128, -74.0060)
        result = dk.detect_anomalous_login_location("IR", "US", t1, t2, previous_coords=tehran, new_coords=new_york)
        self.assertTrue(result["anomalous"])
        self.assertTrue(result["high_confidence"])

    def test_check_domain_similarity_tld_swap(self):
        result = dk.check_domain_similarity("paypal.net", ["paypal.com"])
        self.assertTrue(result["likely_typosquat"])
        self.assertTrue(result["matched_via_tld_swap"])

    def test_check_secure_cookie_flags_samesite_none_without_secure(self):
        result = dk.check_secure_cookie_flags("session=abc; SameSite=None")
        self.assertTrue(result["samesite_none_without_secure"])

    def test_calculate_risk_score_by_severity_breakdown(self):
        findings = [
            dk.SecurityFinding(category="a", description="x", severity="critical"),
            dk.SecurityFinding(category="b", description="y", severity="low"),
        ]
        result = dk.calculate_risk_score(findings)
        self.assertTrue(result["has_critical_finding"])
        self.assertEqual(result["by_severity"]["critical"], 1)


class TestWeaknessFixes(unittest.TestCase):
    """3.6.16: verify the specific weaknesses called out in the code review are fixed."""

    def test_redos_guard_rejects_oversized_password(self):
        huge = "a" * 25_000
        with self.assertRaises(dk.InvalidInputError):
            dk.check_password_strength(huge)

    def test_redos_guard_rejects_oversized_url(self):
        huge_url = "https://example.com/" + ("a" * 25_000)
        with self.assertRaises(dk.InvalidInputError):
            dk.check_suspicious_url(huge_url)

    def test_redos_guard_allows_normal_sized_input(self):
        # Sanity check the guard doesn't get in the way of real usage.
        result = dk.detect_xss_patterns("<script>alert(1)</script>" * 10)
        self.assertTrue(len(result) > 0)

    def test_mask_sensitive_data_no_false_positive_on_phone_number(self):
        # A phone-number-shaped 13-19 digit run that does NOT pass Luhn
        # should NOT be redacted as a card number.
        line = "called customer at 1234567890123 regarding order"
        masked = dk.mask_sensitive_data_in_logs(line)
        self.assertIn("1234567890123", masked)
        self.assertNotIn("REDACTED-CARD", masked)

    def test_mask_sensitive_data_redacts_valid_luhn_card_number(self):
        # 4111111111111111 is the standard Luhn-valid Visa test number.
        line = "charged card 4111111111111111 for order #5521"
        masked = dk.mask_sensitive_data_in_logs(line)
        self.assertNotIn("4111111111111111", masked)
        self.assertIn("REDACTED-CARD", masked)

    def test_rate_limiter_is_thread_safe(self):
        limiter = dk.RateLimiter(max_attempts=100, window_seconds=60)
        errors = []

        def hammer():
            try:
                for _ in range(50):
                    limiter.allow("shared-key")
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        # Exactly 100 of the 500 total attempts should have been let through.
        self.assertEqual(100 - limiter.remaining("shared-key"), 100)

    def test_ip_blocklist_is_thread_safe(self):
        blocklist = dk.IPBlocklist()
        errors = []

        def hammer(i):
            try:
                blocklist.block(f"10.0.0.{i % 255}", duration_seconds=5)
                blocklist.is_blocked(f"10.0.0.{i % 255}")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_replay_guard_detects_replay(self):
        guard = dk.ReplayGuard(ttl_seconds=60)
        self.assertFalse(guard.check("req-1"))
        self.assertTrue(guard.check("req-1"))

    def test_replay_guard_expires_after_ttl(self):
        guard = dk.ReplayGuard(ttl_seconds=0.05)
        self.assertFalse(guard.check("req-1"))
        time.sleep(0.1)
        self.assertFalse(guard.check("req-1"))  # expired, so treated as new

    def test_replay_guard_rejects_invalid_ttl(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.ReplayGuard(ttl_seconds=0)

    def test_replay_guard_is_thread_safe(self):
        guard = dk.ReplayGuard(ttl_seconds=60)
        results = []

        def hammer():
            results.append(guard.check("shared-nonce"))

        threads = [threading.Thread(target=hammer) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Exactly one thread should have seen it as "new" (False).
        self.assertEqual(results.count(False), 1)

    def test_scan_directory_for_malware_signatures_docstring_mentions_limitation(self):
        self.assertIn("exact-hash", dk.scan_directory_for_malware_signatures.__doc__.lower())

    def test_check_password_strength_entropy_docstring_mentions_limitation(self):
        self.assertIn("dictionary", dk.check_password_strength.__doc__.lower())


if __name__ == "__main__":
    unittest.main()
    