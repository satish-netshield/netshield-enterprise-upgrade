"""Test V2 Stage 4 identity-alert review."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.initialize_v2_stage4_5 import SCHEMA
from scripts.review_v2_stage4_identity_alert import (
    review_identity_alert,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage4IdentityReviewTests(unittest.TestCase):
    """Verify controlled identity-alert investigation."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temporary_directory.name) / "test.db"
        )
        self.rbac_config = load_json(
            PROJECT_ROOT / "config/rbac.json"
        )

        with managed_connection(self.database_path) as connection:
            connection.executescript(
                """
                CREATE TABLE user_roles (
                    username TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details TEXT
                );
                """
            )
            connection.executescript(SCHEMA)
            connection.executemany(
                """
                INSERT INTO user_roles (
                    username,
                    role,
                    active
                )
                VALUES (?, ?, 1)
                """,
                [
                    ("analyst01", "analyst"),
                    ("viewer01", "viewer"),
                ],
            )
            connection.execute(
                """
                INSERT INTO v2_identity_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    confidence,
                    username,
                    device_id,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    ip_address,
                    location,
                    risk_score,
                    reason_codes,
                    mitre_techniques,
                    evidence
                )
                VALUES (
                    'TEST-ALERT-KEY',
                    '2026-09-09T10:00:00+00:00',
                    'Abnormal Access Time',
                    'Medium',
                    60,
                    'viewer01',
                    'CYOD-001',
                    '2026-09-09T23:00:00+00:00',
                    '2026-09-09T23:00:00+00:00',
                    '["TEST-EVENT-001"]',
                    '["authentication"]',
                    '192.0.2.10',
                    'Auckland, NZ',
                    NULL,
                    '["ACCESS_OUTSIDE_NORMAL_UTC_HOURS"]',
                    '["T1078"]',
                    '{}'
                )
                """
            )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_analyst_can_classify_false_positive(self) -> None:
        result = review_identity_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="False Positive",
            notes="Verified controlled test activity.",
        )

        self.assertEqual(
            result["classification"],
            "False Positive",
        )
        self.assertEqual(result["status"], "Closed")
        self.assertEqual(result["role"], "analyst")

        with managed_connection(
            self.database_path
        ) as connection:
            stored = connection.execute(
                """
                SELECT
                    status,
                    classification,
                    investigation_notes
                FROM v2_identity_alerts
                WHERE alert_id = 1
                """
            ).fetchone()

        self.assertEqual(
            stored,
            (
                "Closed",
                "False Positive",
                "Verified controlled test activity.",
            ),
        )

    def test_confirmed_alert_uses_confirmed_status(self) -> None:
        result = review_identity_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="Confirmed",
            notes="Evidence confirms suspicious activity.",
        )

        self.assertEqual(
            result["classification"],
            "Confirmed",
        )
        self.assertEqual(result["status"], "Confirmed")

    def test_viewer_cannot_review_alert(self) -> None:
        with self.assertRaises(PermissionError):
            review_identity_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="viewer01",
                classification="False Positive",
                notes="Viewer attempted a review.",
            )

    def test_empty_notes_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            review_identity_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="analyst01",
                classification="False Positive",
                notes="   ",
            )

    def test_unknown_classification_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            review_identity_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="analyst01",
                classification="Ignored",
                notes="Unsupported classification.",
            )

    def test_unknown_alert_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            review_identity_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=999,
                actor="analyst01",
                classification="Confirmed",
                notes="Alert does not exist.",
            )

    def test_successful_review_is_audited(self) -> None:
        review_identity_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="False Positive",
            notes="Verified controlled test activity.",
        )

        with managed_connection(
            self.database_path
        ) as connection:
            audit_record = connection.execute(
                """
                SELECT actor, action, target, result
                FROM audit_events
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertEqual(
            audit_record,
            (
                "analyst01",
                "review_v2_stage4_identity_alert",
                "v2_identity_alert:1",
                "success",
            ),
        )


if __name__ == "__main__":
    unittest.main()
