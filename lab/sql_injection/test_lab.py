"""Tests for the isolated Stage 6 SQL injection lab."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lab.sql_injection.app import (
    initialise_database,
    safe_login,
    vulnerable_login,
)


class SQLInjectionLabTests(unittest.TestCase):
    """Verify vulnerable behaviour and parameterised remediation."""

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_directory.name)
        self.database_path = self.root / "lab.db"
        self.log_path = self.root / "events.jsonl"

        initialise_database(self.database_path)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_normal_login_succeeds_in_vulnerable_mode(self) -> None:
        result = vulnerable_login(
            "analyst01",
            "LabPassword-Only",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        self.assertTrue(result.authenticated)
        self.assertEqual(result.query_mode, "vulnerable")
        self.assertIsNone(result.error)

    def test_authentication_bypass_succeeds_in_vulnerable_mode(self) -> None:
        result = vulnerable_login(
            "' OR 1=1 --",
            "wrong-password",
            source_ip="10.0.2.25",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        self.assertTrue(result.authenticated)
        self.assertEqual(result.query_mode, "vulnerable")

    def test_authentication_bypass_fails_after_remediation(self) -> None:
        result = safe_login(
            "' OR 1=1 --",
            "wrong-password",
            source_ip="10.0.2.25",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        self.assertFalse(result.authenticated)
        self.assertEqual(result.rows, [])
        self.assertIsNone(result.error)
        self.assertEqual(result.query_mode, "parameterised")

    def test_quotes_are_handled_as_data(self) -> None:
        result = safe_login(
            "analyst'01",
            "wrong-password",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        self.assertFalse(result.authenticated)
        self.assertIsNone(result.error)

    def test_database_remains_intact(self) -> None:
        safe_login(
            "' OR 1=1 --",
            "wrong-password",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        with sqlite3.connect(self.database_path) as connection:
            table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name = 'users'
                """
            ).fetchone()

        self.assertEqual(table, ("users",))

    def test_log_records_source_ip_and_event_type(self) -> None:
        safe_login(
            "' OR 1=1 --",
            "wrong-password",
            source_ip="192.0.2.44",
            database_path=self.database_path,
            log_path=self.log_path,
        )

        records = [
            json.loads(line)
            for line in self.log_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source_ip"], "192.0.2.44")
        self.assertEqual(
            records[0]["event_type"],
            "suspicious_input_blocked",
        )
        self.assertEqual(
            records[0]["query_mode"],
            "parameterised",
        )

    def test_repeated_abnormal_requests_are_logged(self) -> None:
        for _ in range(3):
            safe_login(
                "' OR 1=1 --",
                "wrong-password",
                source_ip="198.51.100.10",
                database_path=self.database_path,
                log_path=self.log_path,
            )

        records = [
            json.loads(line)
            for line in self.log_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

        matching_records = [
            record
            for record in records
            if record["source_ip"] == "198.51.100.10"
            and record["event_type"]
            == "suspicious_input_blocked"
        ]

        self.assertEqual(len(matching_records), 3)


if __name__ == "__main__":
    unittest.main()
