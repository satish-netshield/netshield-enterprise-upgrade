"""Tests for Stage 10 eradication and recovery."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.response.stage10_eradication import (
    build_action_plan,
    run_eradication,
    sha256_file,
)


class Stage10EradicationTests(unittest.TestCase):
    """Verify simulated eradication and recovery."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.stage9_report = (
            cls.project_root
            / "lab"
            / "sql_injection"
            / "outputs"
            / "stage9"
            / "stage9_containment_report.json"
        )

    def test_ten_eradication_actions_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_eradication(
                self.stage9_report,
                Path(directory),
            )

            self.assertEqual(report["actions_attempted"], 10)
            self.assertEqual(report["actions_succeeded"], 10)
            self.assertEqual(report["actions_failed"], 0)

    def test_evidence_is_preserved_before_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_eradication(
                self.stage9_report,
                Path(directory),
            )

            evidence_path = Path(report["evidence"]["path"])

            self.assertTrue(evidence_path.exists())
            self.assertEqual(
                report["evidence"]["sha256"],
                sha256_file(evidence_path),
            )

            self.assertTrue(
                all(
                    action["evidence_preserved_before_action"]
                    for action in report["actions"]
                )
            )

    def test_requested_actions_are_present(self) -> None:
        action_names = {
            item["action"] for item in build_action_plan()
        }

        expected = {
            "reset_compromised_credentials",
            "remove_unauthorised_privileges",
            "register_unknown_device",
            "correct_wpa3_configuration",
            "remove_rogue_access_point",
            "remove_suspicious_process",
            "replace_vulnerable_sql",
            "restore_account",
            "restore_services",
            "increase_post_recovery_monitoring",
        }

        self.assertEqual(action_names, expected)

    def test_threat_retests_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_eradication(
                self.stage9_report,
                Path(directory),
            )

            self.assertTrue(report["all_original_threats_blocked"])
            self.assertTrue(
                all(
                    item["result"] == "blocked"
                    for item in report["threat_retests"]
                )
            )

    def test_lifecycle_progresses_after_containment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_eradication(
                self.stage9_report,
                Path(directory),
            )

            self.assertEqual(
                report["incident_status_transition"],
                [
                    "Contained",
                    "Eradicated",
                    "Recovered",
                    "Closed",
                ],
            )

    def test_audit_trail_records_actions_and_retests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            report = run_eradication(
                self.stage9_report,
                output_root,
            )

            audit_path = Path(report["audit_trail"])
            entries = [
                json.loads(line)
                for line in audit_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]

            self.assertEqual(len(entries), 14)
            self.assertEqual(
                sum(
                    entry["result"] == "succeeded"
                    for entry in entries[:10]
                ),
                10,
            )
            self.assertTrue(
                all(
                    entry["result"] == "blocked"
                    for entry in entries[10:]
                )
            )

    def test_real_world_boundaries_remain_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_eradication(
                self.stage9_report,
                Path(directory),
            )

            self.assertFalse(report["automatic_real_world_actions"])
            self.assertFalse(report["external_targets_used"])
            self.assertFalse(report["real_accounts_used"])


if __name__ == "__main__":
    unittest.main()
