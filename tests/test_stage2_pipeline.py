"""Test the Stage 2 JSONL event-import pipeline."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.database import initialise_database


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Stage2PipelineTests(unittest.TestCase):
    """Verify event acceptance, rejection and duplicate handling."""

    def setUp(self) -> None:
        """Create an isolated temporary database and event file."""
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.test_directory = Path(self.temporary_directory.name)
        self.database_path = self.test_directory / "test.db"
        self.source_file = (
            self.test_directory / "authentication_events.jsonl"
        )

        initialise_database(
            self.database_path,
            PROJECT_ROOT / "database/schema.sql",
        )

    def tearDown(self) -> None:
        """Remove the isolated test directory."""
        self.temporary_directory.cleanup()

    def write_lines(self, lines: list[str]) -> None:
        """Write complete JSONL test lines."""
        self.source_file.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

    def valid_event(self) -> dict[str, object]:
        """Return one valid authentication event."""
        return {
            "event_id": "TEST-AUTH-001",
            "event_time": "2026-08-20T09:00:00+12:00",
            "source_type": "authentication",
            "event_type": "login_success",
            "username": "test-user",
            "ip_address": "127.0.0.1",
            "status": "success",
        }

    def count_rows(self, table_name: str) -> int:
        """Return the number of records in an approved test table."""
        allowed_tables = {
            "import_batches",
            "security_events",
            "rejected_events",
        }

        if table_name not in allowed_tables:
            raise ValueError("Unsupported test table")

        with managed_connection(self.database_path) as connection:
            result = connection.execute(
                f"SELECT COUNT(*) FROM {table_name}"
            ).fetchone()

        return int(result[0])

    def test_valid_event_is_imported(self) -> None:
        self.write_lines([json.dumps(self.valid_event())])

        summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        self.assertEqual(summary["accepted_records"], 1)
        self.assertEqual(summary["rejected_records"], 0)
        self.assertEqual(self.count_rows("security_events"), 1)

    def test_invalid_json_is_rejected(self) -> None:
        self.write_lines(['{"event_id": invalid-json}'])

        summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        self.assertEqual(summary["accepted_records"], 0)
        self.assertEqual(summary["rejected_records"], 1)
        self.assertEqual(self.count_rows("rejected_events"), 1)

    def test_missing_required_field_is_rejected(self) -> None:
        event = self.valid_event()
        del event["event_id"]
        self.write_lines([json.dumps(event)])

        summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        self.assertEqual(summary["rejected_records"], 1)
        self.assertEqual(self.count_rows("security_events"), 0)

    def test_source_type_mismatch_is_rejected(self) -> None:
        event = self.valid_event()
        event["source_type"] = "network"
        self.write_lines([json.dumps(event)])

        summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        self.assertEqual(summary["rejected_records"], 1)
        self.assertEqual(self.count_rows("security_events"), 0)

    def test_duplicate_event_is_rejected(self) -> None:
        line = json.dumps(self.valid_event())
        self.write_lines([line])

        first_summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )
        second_summary = import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        self.assertEqual(first_summary["accepted_records"], 1)
        self.assertEqual(second_summary["accepted_records"], 0)
        self.assertEqual(second_summary["rejected_records"], 1)
        self.assertEqual(self.count_rows("security_events"), 1)

    def test_batch_totals_are_recorded(self) -> None:
        self.write_lines(
            [
                json.dumps(self.valid_event()),
                '{"broken": invalid-json}',
            ]
        )

        import_jsonl_file(
            self.database_path,
            self.source_file,
        )

        with managed_connection(self.database_path) as connection:
            result = connection.execute(
                """
                SELECT
                    total_records,
                    accepted_records,
                    rejected_records,
                    status
                FROM import_batches
                """
            ).fetchone()

        self.assertEqual(
            result,
            (2, 1, 1, "completed_with_rejections"),
        )


if __name__ == "__main__":
    unittest.main()
