"""Tests for Stage 8 incident management and evidence handling."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.incident_management.stage8_manager import (
    STATUS_ORDER,
    create_incident_records,
    sha256_file,
    validate_transition,
)


class Stage8IncidentManagementTests(unittest.TestCase):
    """Verify Stage 8 incident records and evidence handling."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.stage7_report = (
            cls.project_root
            / "tests"
            / "fixtures"
            / "phase3_outputs"
            / "stage7_correlation_report.json"
        )

    def create_output(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary_directory = tempfile.TemporaryDirectory()
        output_root = Path(temporary_directory.name) / "stage8"
        return temporary_directory, output_root

    def test_creates_one_record_for_each_stage7_incident(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            summary = create_incident_records(
                self.stage7_report,
                output_root,
            )

            self.assertEqual(summary["incidents_created"], 3)

            incident_files = sorted(
                (output_root / "incidents").glob("*.json")
            )
            report_files = sorted(
                (output_root / "reports").glob("*.md")
            )

            self.assertEqual(len(incident_files), 3)
            self.assertEqual(len(report_files), 3)
        finally:
            temporary_directory.cleanup()

    def test_incident_ids_are_unique_and_status_starts_new(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            create_incident_records(
                self.stage7_report,
                output_root,
            )

            incident_files = sorted(
                (output_root / "incidents").glob("*.json")
            )
            records = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in incident_files
            ]

            incident_ids = [record["incident_id"] for record in records]

            self.assertEqual(len(set(incident_ids)), 3)
            self.assertTrue(
                all(record["status"] == "New" for record in records)
            )
        finally:
            temporary_directory.cleanup()

    def test_stage7_severity_and_risk_are_preserved(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            create_incident_records(
                self.stage7_report,
                output_root,
            )

            first_record_path = sorted(
                (output_root / "incidents").glob("*.json")
            )[0]
            first_record = json.loads(
                first_record_path.read_text(encoding="utf-8")
            )

            self.assertEqual(first_record["severity"], "Critical")
            self.assertEqual(first_record["risk_score"], 30)
            self.assertEqual(first_record["event_count"], 4)
        finally:
            temporary_directory.cleanup()

    def test_evidence_is_preserved_and_hash_matches(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            summary = create_incident_records(
                self.stage7_report,
                output_root,
            )

            evidence_path = (
                output_root
                / "evidence"
                / "stage7_correlation_report.json"
            )

            self.assertTrue(evidence_path.exists())
            self.assertEqual(
                summary["evidence_sha256"],
                sha256_file(evidence_path),
            )

            incident_path = sorted(
                (output_root / "incidents").glob("*.json")
            )[0]
            incident = json.loads(
                incident_path.read_text(encoding="utf-8")
            )

            self.assertEqual(
                incident["evidence"]["sha256"],
                sha256_file(evidence_path),
            )
        finally:
            temporary_directory.cleanup()

    def test_reports_contain_investigation_and_evidence_sections(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            create_incident_records(
                self.stage7_report,
                output_root,
            )

            report_path = sorted(
                (output_root / "reports").glob("*.md")
            )[0]
            report = report_path.read_text(encoding="utf-8")

            self.assertIn("## Investigation Note", report)
            self.assertIn("## Analyst Decision", report)
            self.assertIn("## False-Positive Classification", report)
            self.assertIn("## IoCs", report)
            self.assertIn("## Evidence", report)
            self.assertIn("## Timeline", report)
        finally:
            temporary_directory.cleanup()

    def test_iocs_and_behaviours_are_preserved_separately(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            create_incident_records(
                self.stage7_report,
                output_root,
            )

            first_record_path = sorted(
                (output_root / "incidents").glob("*.json")
            )[0]
            first_record = json.loads(
                first_record_path.read_text(encoding="utf-8")
            )

            ioc_types = {
                item["type"] for item in first_record["iocs"]
            }

            self.assertEqual(len(first_record["iocs"]), 4)
            self.assertIn("ip_address", ioc_types)
            self.assertIn("mac_address", ioc_types)
            self.assertIn("hostname", ioc_types)
            self.assertIn("process_name", ioc_types)
            self.assertIn("Repeated Failed Logins", first_record["behaviours"])

            self.assertNotIn(
                "username",
                ioc_types,
            )
        finally:
            temporary_directory.cleanup()

    def test_timeline_and_analyst_decision_are_recorded(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            create_incident_records(
                self.stage7_report,
                output_root,
                analyst_name="analyst01",
            )

            incident_path = sorted(
                (output_root / "incidents").glob("*.json")
            )[0]
            incident = json.loads(
                incident_path.read_text(encoding="utf-8")
            )

            timeline_actions = {
                item["action"] for item in incident["timeline"]
            }

            self.assertIn(
                "Incident created from Stage 7 correlation output",
                timeline_actions,
            )
            self.assertIn(
                "Stage 7 evidence preserved and SHA-256 hash calculated",
                timeline_actions,
            )
            self.assertIn(
                "Initial evidence preserved.",
                incident["analyst_decision"],
            )
            self.assertFalse(incident["false_positive"])
        finally:
            temporary_directory.cleanup()

    def test_audit_trail_contains_three_entries_per_incident(self) -> None:
        temporary_directory, output_root = self.create_output()

        try:
            summary = create_incident_records(
                self.stage7_report,
                output_root,
            )

            audit_path = output_root / "audit_trail.jsonl"
            audit_lines = [
                line
                for line in audit_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]

            self.assertEqual(len(audit_lines), 9)
            self.assertEqual(summary["audit_entries"], 9)

            audit_entries = [
                json.loads(line) for line in audit_lines
            ]
            actions = {entry["action"] for entry in audit_entries}

            self.assertEqual(
                actions,
                {
                    "incident_created",
                    "evidence_preserved",
                    "analyst_decision_recorded",
                },
            )
        finally:
            temporary_directory.cleanup()

    def test_valid_status_lifecycle_transition_is_allowed(self) -> None:
        for current, new in zip(STATUS_ORDER, STATUS_ORDER[1:]):
            validate_transition(current, new)

    def test_invalid_status_transition_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_transition("New", "Contained")

        with self.assertRaises(ValueError):
            validate_transition("Closed", "Investigating")

        with self.assertRaises(ValueError):
            validate_transition("Unknown", "Investigating")


if __name__ == "__main__":
    unittest.main()
