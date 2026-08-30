"""
DefendKing - Defensive Security Toolkit
=========================================

This package keeps all logic in a single module (`handler.py`) for
simplicity, and re-exports everything here so consumers can just do:

    import defendking
    defendking.check_password_strength("...")

or:

    from defendking import check_password_strength

Author: Barman
License: MIT
"""

from .handler import (
    # Section 1 - Passwords & authentication
    check_password_strength,
    check_password_breached,
    generate_strong_password,
    hash_password,
    verify_password,
    detect_common_password_patterns,
    check_two_factor_status,
    check_password_expiry,
    validate_password_policy_compliance,
    check_default_credentials,

    # Section 2 - Phishing & URL / email safety
    check_suspicious_url,
    check_domain_similarity,
    check_ssl_certificate,
    scan_email_for_phishing_signs,
    extract_and_check_links,
    validate_email_format_and_mx,

    # Section 3 - Brute-force / abuse protection
    RateLimiter,
    rate_limiter,
    detect_brute_force_attempt,
    IPBlocklist,
    block_ip_temporarily,
    implement_captcha_trigger,
    log_failed_login_attempt,
    distance_km_between,
    detect_anomalous_login_location,
    detect_privilege_escalation_attempt,

    # Section 4 - File / malware hygiene
    compute_file_hash,
    scan_file_hash_virustotal,
    detect_suspicious_file_extension,
    check_file_integrity,
    scan_directory_for_malware_signatures,
    quarantine_suspicious_file,
    verify_backup_integrity,

    # Section 5 - Web application security
    sanitize_user_input,
    generate_csrf_token,
    check_csrf_token_validity,
    validate_cors_policy,
    detect_xss_patterns,
    check_secure_cookie_flags,
    validate_input_against_sql_injection,
    check_security_headers,
    verify_csp_header,

    # Section 6 - Network-level defense
    check_tls_version_support,
    check_firewall_rules_status,
    detect_arp_spoofing,
    validate_dns_response,
    check_vpn_connection_security,
    audit_server_config,

    # Section 7 - Cryptography & secrets management
    generate_secure_token,
    ApiKeyRecord,
    rotate_api_key,
    mask_sensitive_data_in_logs,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    validate_jwt_token,
    check_secrets_in_codebase,

    # Section 8 - Monitoring, risk scoring & reporting
    SecurityFinding,
    calculate_risk_score,
    generate_security_report,
    export_findings_to_json,
    generate_incident_response_report,
    audit_user_permissions,
    notify_admin_dashboard,
    send_security_alert,
    schedule_periodic_scan,
    generate_security_checklist,

    # Section 9 - API & session security
    validate_api_request_signature,
    detect_replay_attack,
    check_session_fixation,
    generate_scoped_api_key,
    check_api_rate_limit_headers,

    # module logger, in case a consumer wants to attach their own handler
    logger,
)

__all__ = [
    "check_password_strength", "check_password_breached", "generate_strong_password",
    "hash_password", "verify_password", "detect_common_password_patterns",
    "check_two_factor_status", "check_password_expiry", "validate_password_policy_compliance",
    "check_default_credentials",
    "check_suspicious_url", "check_domain_similarity", "check_ssl_certificate",
    "scan_email_for_phishing_signs", "extract_and_check_links", "validate_email_format_and_mx",
    "RateLimiter", "rate_limiter", "detect_brute_force_attempt", "IPBlocklist",
    "block_ip_temporarily", "implement_captcha_trigger", "log_failed_login_attempt",
    "distance_km_between", "detect_anomalous_login_location", "detect_privilege_escalation_attempt",
    "compute_file_hash", "scan_file_hash_virustotal", "detect_suspicious_file_extension",
    "check_file_integrity", "scan_directory_for_malware_signatures", "quarantine_suspicious_file",
    "verify_backup_integrity",
    "sanitize_user_input", "generate_csrf_token", "check_csrf_token_validity",
    "validate_cors_policy", "detect_xss_patterns", "check_secure_cookie_flags",
    "validate_input_against_sql_injection", "check_security_headers", "verify_csp_header",
    "check_tls_version_support", "check_firewall_rules_status", "detect_arp_spoofing",
    "validate_dns_response", "check_vpn_connection_security", "audit_server_config",
    "generate_secure_token", "ApiKeyRecord", "rotate_api_key", "mask_sensitive_data_in_logs",
    "encrypt_sensitive_data", "decrypt_sensitive_data", "validate_jwt_token",
    "check_secrets_in_codebase",
    "SecurityFinding", "calculate_risk_score", "generate_security_report",
    "export_findings_to_json", "generate_incident_response_report", "audit_user_permissions",
    "notify_admin_dashboard", "send_security_alert", "schedule_periodic_scan",
    "generate_security_checklist",
    "validate_api_request_signature", "detect_replay_attack", "check_session_fixation",
    "generate_scoped_api_key", "check_api_rate_limit_headers",
    "logger",
]

__version__ = "1.5.0"
__author__ = "Barman"
