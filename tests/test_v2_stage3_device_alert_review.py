"""Test Phase 3A V2 Stage 3 device alert review workflow."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.review_v2_stage3_device_alert import update_device_alert
from src.utils.database import initialise_database


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage3DeviceAlertReviewTests(unittest.TestCase):
    """Test controlled review of Stage 3 device alerts."""

    def create_test_alert(
        self,
        database_path: Path,
    ) -> int:
        """Create one temporary Stage 3 device alert."""
        with sqlite3.connect(database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO device_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    device_id,
                    hostname,
                    username,
                    source_event_ids,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "TEST-DEVICE-ALERT-001",
                    "2026-09-07T06:00:00+00:00",
                    "Inventory Mismatch",
                    "Medium",
                    "CYOD-TEST-001",
                    "Test-Laptop",
                    "viewer01",
                    '["TEST-EVENT-001"]',
                    '{"reason":"Controlled review test"}',
                ),
            )

            return cursor.lastrowid

    def test_alert_can_be_marked_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            alert_id = self.create_test_alert(
                database_path
            )

            update_device_alert(
                database_path=database_path,
                alert_id=alert_id,
                status="False Positive",
                classification="Expected device variation",
                notes=(
                    "Hostname difference was confirmed "
                    "as approved test activity."
                ),
                actor="test-analyst",
            )

            with sqlite3.connect(database_path) as connection:
                row = connection.execute(
                    """
                    SELECT
                        status,
                        classification,
                        investigation_notes
                    FROM device_alerts
                    WHERE alert_id = ?
                    """,
                    (alert_id,),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    "False Positive",
                    "Expected device variation",
                    (
                        "Hostname difference was confirmed "
                        "as approved test activity."
                    ),
                ),
            )

    def test_alert_review_creates_audit_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            alert_id = self.create_test_alert(
                database_path
            )

            update_device_alert(
                database_path=database_path,
                alert_id=alert_id,
                status="Investigating",
                classification="Needs review",
                notes="Device context requires confirmation.",
                actor="test-analyst",
            )

            with sqlite3.connect(database_path) as connection:
                row = connection.execute(
                    """
                    SELECT
                        actor,
                        action,
                        target,
                        result
                    FROM audit_events
                    WHERE actor = ?
                      AND action = ?
                      AND target = ?
                      AND result = ?
                    """,
                    (
                        "test-analyst",
                        "review_v2_stage3_device_alert",
                        f"device_alert:{alert_id}",
                        "success",
                    ),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    "test-analyst",
                    "review_v2_stage3_device_alert",
                    f"device_alert:{alert_id}",
                    "success",
                ),
            )

    def test_missing_alert_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            with self.assertRaises(ValueError):
                update_device_alert(
                    database_path=database_path,
                    alert_id=999,
                    status="False Positive",
                    classification="Test",
                    notes="Alert does not exist.",
                    actor="test-analyst",
                )


if __name__ == "__main__":
    unittest.main()
