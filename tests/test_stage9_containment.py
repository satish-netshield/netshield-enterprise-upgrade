"""Tests for Stage 9 controlled containment automation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.response.stage9_containment import (
    APPROVAL_REQUIRED,
    run_containment,
    sha256_file,
    simulated_action_result,
)


class Stage9ContainmentTests(unittest.TestCase):
    """Verify Stage 9 simulated containment behaviour."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.stage8_summary = (
            cls.project_root
            / "tests"
            / "fixtures"
            / "phase3_outputs"
            / "stage8_incident_summary.json"
        )
        cls.stage7_report = (
            cls.project_root
            / "tests"
            / "fixtures"
            / "phase3_outputs"
            / "stage7_correlation_report.json"
        )

    def test_automatic_blocklist_action_succeeds_without_approval(self) -> None:
        result, details = simulated_action_result(
            "add_to_simulated_blocklist",
            approval_granted=False,
        )

        self.assertEqual(result, "succeeded")
        self.assertIn("completed", details)

    def test_disruptive_action_fails_without_approval(self) -> None:
        for action in APPROVAL_REQUIRED:
            result, details = simulated_action_result(
                action,
                approval_granted=False,
            )

            self.assertEqual(result, "failed")
            self.assertIn("Approval is required", details)

    def test_approved_disruptive_action_succeeds(self) -> None:
        for action in APPROVAL_REQUIRED:
            result, details = simulated_action_result(
                action,
                approval_granted=True,
            )

            self.assertEqual(result, "succeeded")
            self.assertIn("completed", details)

    def test_unknown_action_is_denied(self) -> None:
        result, details = simulated_action_result(
            "delete_database",
            approval_granted=True,
        )

        self.assertEqual(result, "failed")
        self.assertIn("not defined", details)

    def test_containment_creates_six_action_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                Path(temporary_directory),
            )

            self.assertEqual(report["actions_attempted"], 6)
            self.assertEqual(report["actions_succeeded"], 5)
            self.assertEqual(report["actions_failed"], 1)

    def test_every_action_preserves_evidence_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                Path(temporary_directory),
            )

            for action in report["actions"]:
                self.assertTrue(
                    action["evidence_preserved_before_action"]
                )
                self.assertEqual(
                    action["evidence_sha256"],
                    report["evidence"]["sha256"],
                )

    def test_failed_wifi_rejection_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                Path(temporary_directory),
            )

            wifi_actions = [
                action
                for action in report["actions"]
                if action["action"] == "reject_wifi_connection"
            ]

            self.assertEqual(len(wifi_actions), 1)
            self.assertEqual(wifi_actions[0]["result"], "failed")
            self.assertTrue(wifi_actions[0]["approval_required"])
            self.assertFalse(wifi_actions[0]["approval_granted"])

    def test_approved_actions_are_recorded_as_successful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                Path(temporary_directory),
            )

            approved_actions = [
                action
                for action in report["actions"]
                if action["approval_granted"]
            ]

            self.assertEqual(len(approved_actions), 4)
            self.assertTrue(
                all(
                    action["result"] == "succeeded"
                    for action in approved_actions
                )
            )

    def test_audit_trail_contains_one_entry_per_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_root = Path(temporary_directory)

            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                output_root,
            )

            audit_path = output_root / "containment_audit.jsonl"
            audit_lines = [
                line
                for line in audit_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]

            self.assertEqual(len(audit_lines), 6)
            self.assertEqual(
                len(report["actions"]),
                len(audit_lines),
            )

            audit_entries = [
                json.loads(line) for line in audit_lines
            ]

            self.assertTrue(
                all(entry["incident_id"] for entry in audit_entries)
            )
            self.assertTrue(
                all(entry["result"] in {"succeeded", "failed"}
                    for entry in audit_entries)
            )

    def test_evidence_hash_matches_preserved_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_root = Path(temporary_directory)

            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                output_root,
            )

            evidence_path = Path(report["evidence"]["path"])

            self.assertTrue(evidence_path.exists())
            self.assertEqual(
                report["evidence"]["sha256"],
                sha256_file(evidence_path),
            )

    def test_real_world_boundaries_remain_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = run_containment(
                self.stage8_summary,
                self.stage7_report,
                Path(temporary_directory),
            )

            self.assertFalse(report["automatic_containment"])
            self.assertFalse(report["external_targets_used"])
            self.assertFalse(report["real_accounts_used"])


if __name__ == "__main__":
    unittest.main()
