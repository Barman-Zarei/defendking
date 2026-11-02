"""Coverage reporting uses owned files and mocked network failures only."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import defendking as dk


class TestCheckCoverage(unittest.TestCase):
    def report_and_export(self, findings, checks):
        report = dk.generate_security_report(findings, "fixture", checks=checks)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            result = dk.export_findings_to_json(findings, str(output), checks=checks)
            self.assertTrue(result["success"])
            document = json.loads(output.read_text(encoding="utf-8"))
        return report, document

    def test_success_plus_missing_file_keeps_coverage_incomplete_without_findings(self):
        checks = [dk.SecurityCheckResult.from_result("password", {"score": 100})]
        with tempfile.TemporaryDirectory() as directory:
            try:
                dk.compute_file_hash(str(Path(directory) / "PRIVATE_MISSING_FILE"))
            except dk.ExternalServiceError as error:
                checks.append(dk.SecurityCheckResult.from_exception("file", error))
        report, document = self.report_and_export([], checks)
        self.assertEqual(document["coverage"], {
            "status": "incomplete", "total": 2, "completed": 1, "failed": 1, "skipped": 0,
        })
        self.assertEqual(document["risk"], {"score": None, "level": "undetermined"})
        self.assertEqual(document["checks"][1]["reason"], "missing-file")
        self.assertIn("Overall risk: undetermined", report)
        self.assertIn("Coverage: incomplete (1/2 completed; 1 failed; 0 skipped)", report)
        self.assertNotIn("PRIVATE_MISSING_FILE", report + json.dumps(document))

    def test_mocked_network_failure_is_not_a_zero_risk_result(self):
        with patch("defendking.handler.socket.create_connection", side_effect=TimeoutError("PRIVATE_NETWORK_TOKEN")), \
                patch("defendking.handler.time.sleep"):
            result = dk.check_ssl_certificate("example.invalid", timeout=1)
        checks = [dk.SecurityCheckResult("local", "completed"), dk.SecurityCheckResult.from_result("tls", result)]
        finding = dk.SecurityFinding("fixture", "known finding", "low")
        report, document = self.report_and_export([finding], checks)
        self.assertEqual(document["coverage"]["failed"], 1)
        self.assertEqual(document["risk"]["level"], "undetermined")
        self.assertEqual(document["recorded_findings_risk"]["finding_count"], 1)
        self.assertIn("known finding", report)
        self.assertNotIn("PRIVATE_NETWORK_TOKEN", report + json.dumps(document))
        self.assertNotIn("example.invalid", json.dumps(document["checks"]))

    def test_complete_and_skipped_required_checks_have_distinct_outcomes(self):
        _, complete = self.report_and_export([], [dk.SecurityCheckResult("local", "completed")])
        self.assertEqual(complete["coverage"]["status"], "complete")
        self.assertEqual(complete["risk"]["score"], 0)
        report, skipped = self.report_and_export([], [dk.SecurityCheckResult("local", "skipped", "disabled")])
        self.assertEqual(skipped["coverage"]["status"], "incomplete")
        self.assertIsNone(skipped["risk"]["score"])
        self.assertIn("local: skipped (disabled)", report)

    def test_empty_coverage_and_duplicate_ids_cannot_claim_complete(self):
        _, empty = self.report_and_export([], [])
        self.assertEqual(empty["coverage"]["status"], "incomplete")
        with self.assertRaises(dk.InvalidInputError):
            self.report_and_export([], [dk.SecurityCheckResult("same", "completed")] * 2)

    def test_raw_error_text_cannot_be_used_as_a_reason(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.SecurityCheckResult("local", "failed", "PRIVATE_EXCEPTION_TEXT")
        result = dk.SecurityCheckResult.from_exception("tls", TimeoutError("PRIVATE_EXCEPTION_TEXT"))
        self.assertEqual(result.reason, "network-error")

    def test_programmer_errors_and_invalid_records_are_rejected(self):
        with self.assertRaises(dk.InvalidInputError):
            dk.SecurityCheckResult.from_exception("local", dk.InvalidInputError("bad input"))
        for check_id, status, reason in [
            ("tls\nPRIVATE", "completed", None),
            ("local", "unknown", None),
            ("local", "completed", "network-error"),
            ("local", "skipped", None),
        ]:
            with self.subTest(check_id=check_id, status=status, reason=reason), self.assertRaises(dk.InvalidInputError):
                dk.SecurityCheckResult(check_id, status, reason)
        with self.assertRaises(dk.InvalidInputError):
            self.report_and_export([], [{"check_id": "local", "status": "completed"}])

    def test_negative_security_outcome_is_completed_without_an_operational_error(self):
        check = dk.SecurityCheckResult.from_result("tls", {"valid": False})
        finding = dk.SecurityFinding("tls", "expired certificate", "high")
        report, document = self.report_and_export([finding], [check])
        self.assertEqual(document["coverage"]["status"], "complete")
        self.assertEqual(document["risk"], dk.calculate_risk_score([finding]))
        self.assertIn("expired certificate", report)

    def test_legacy_export_shape_remains_a_list_when_no_coverage_is_supplied(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "legacy.json"
            self.assertTrue(dk.export_findings_to_json([], str(output))["success"])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
