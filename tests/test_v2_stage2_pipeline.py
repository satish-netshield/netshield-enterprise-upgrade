"""Test the Phase 3A V2 extended event pipeline."""
from src.utils.sqlite_connection import managed_connection

import unittest
from pathlib import Path

from src.collectors.event_normalizer import (
    ALLOWED_SOURCE_TYPES,
    normalise_event,
)
from src.collectors.jsonl_collector import identify_source_type
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage2PipelineTests(unittest.TestCase):
    """Test new sources, schemas and enterprise fields."""

    def test_compound_source_types_are_identified(self) -> None:
        self.assertEqual(
            identify_source_type(
                Path("identity_risk_v2_events.jsonl")
            ),
            "identity_risk",
        )
        self.assertEqual(
            identify_source_type(
                Path("access_policy_v2_events.jsonl")
            ),
            "access_policy",
        )

    def test_v2_enterprise_fields_are_normalised(self) -> None:
        event = normalise_event(
            {
                "event_id": "TEST-V2-001",
                "schema_version": "2.0",
                "event_time": "2026-09-07T10:00:00+12:00",
                "source_type": "access_policy",
                "source_system": "policy_engine",
                "event_type": "access_denied",
                "severity": "high",
                "risk_score": 82,
                "decision": "deny",
                "device_id": "CYOD-003",
                "application_id": "APP-001",
            }
        )

        self.assertEqual(event["schema_version"], "2.0")
        self.assertEqual(event["severity"], "High")
        self.assertEqual(event["risk_score"], 82.0)
        self.assertEqual(event["decision"], "deny")
        self.assertEqual(
            event["event_time"],
            "2026-09-06T22:00:00+00:00",
        )

    def test_unsupported_schema_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalise_event(
                {
                    "event_id": "TEST-V2-002",
                    "schema_version": "3.0",
                    "event_time": "2026-09-07T10:00:00+12:00",
                    "source_type": "incident",
                    "event_type": "incident_created",
                }
            )

    def test_invalid_risk_score_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalise_event(
                {
                    "event_id": "TEST-V2-003",
                    "schema_version": "2.0",
                    "event_time": "2026-09-07T10:00:00+12:00",
                    "source_type": "identity_risk",
                    "event_type": "risky_sign_in",
                    "risk_score": 101,
                }
            )

    def test_invalid_decision_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalise_event(
                {
                    "event_id": "TEST-V2-004",
                    "schema_version": "2.0",
                    "event_time": "2026-09-07T10:00:00+12:00",
                    "source_type": "access_policy",
                    "event_type": "access_decision",
                    "decision": "permit",
                }
            )

    def test_config_and_normaliser_sources_match(self) -> None:
        settings = load_json(PROJECT_ROOT / "config/settings.json")
        self.assertEqual(
            set(settings["pipeline"]["allowed_source_types"]),
            ALLOWED_SOURCE_TYPES,
        )


    def test_unreadable_event_file_records_failed_batch(self) -> None:
        import sqlite3
        import tempfile

        from src.collectors.jsonl_collector import import_jsonl_file
        from src.utils.database import initialise_database

        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            database_path = temporary / "test.db"
            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            source_file = temporary / "database_failure.jsonl"
            source_file.write_bytes(b"\xff\xfe\x00")

            with self.assertRaises(UnicodeError):
                import_jsonl_file(database_path, source_file)

            with managed_connection(database_path) as connection:
                status = connection.execute(
                    """
                    SELECT status
                    FROM import_batches
                    WHERE source_file = ?
                    """,
                    (source_file.name,),
                ).fetchone()[0]

            self.assertEqual(status, "failed")



if __name__ == "__main__":
    unittest.main()
