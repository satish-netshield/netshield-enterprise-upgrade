"""Test Phase 3A V2 Stage 6 network-alert review."""

import tempfile
import unittest
from pathlib import Path

from scripts.initialize_v2_stage6 import SCHEMA
from scripts.review_v2_stage6_network_alert import (
    review_network_alert,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage6NetworkAlertReviewTests(unittest.TestCase):
    """Verify controlled Stage 6 network-alert investigation."""

    def setUp(self) -> None:
        """Create an isolated database with one network alert."""
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
                INSERT INTO v2_network_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    confidence,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    device_id,
                    asset_id,
                    username,
                    ip_address,
                    mac_address,
                    hostname,
                    location,
                    connection_type,
                    destination_ip,
                    destination_port,
                    service,
                    reason_codes,
                    evidence
                )
                VALUES (
                    'TEST-STAGE6-ALERT',
                    '2026-09-10T08:00:00+00:00',
                    'Suspicious IP Address',
                    'High',
                    95,
                    '2026-09-10T08:01:00+00:00',
                    '2026-09-10T08:01:00+00:00',
                    '["TEST-NETWORK-001"]',
                    '["network"]',
                    'CYOD-001',
                    'AST-001',
                    'netshield01',
                    '198.51.100.66',
                    '08:00:27:cf:49:71',
                    'Ubuntu-NetShield',
                    'External Test Network',
                    'wired',
                    '192.0.2.100',
                    443,
                    'https',
                    '["IP_BLOCKLIST_MATCH"]',
                    '{}'
                )
                """
            )

    def tearDown(self) -> None:
        """Remove the isolated test database."""
        self.temporary_directory.cleanup()

    def test_analyst_can_classify_false_positive(self) -> None:
        """An analyst can close a verified false positive."""
        result = review_network_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="False Positive",
            notes=(
                "Verified as controlled network test activity. "
                "No unauthorised connection occurred."
            ),
        )

        self.assertEqual(
            result["classification"],
            "False Positive",
        )
        self.assertEqual(result["status"], "Closed")
        self.assertEqual(result["role"], "analyst")
        self.assertTrue(result["reviewed_at"])

        with managed_connection(
            self.database_path
        ) as connection:
            stored = connection.execute(
                """
                SELECT
                    status,
                    classification,
                    investigation_notes,
                    reviewed_by,
                    reviewed_at
                FROM v2_network_alerts
                WHERE alert_id = 1
                """
            ).fetchone()

        self.assertEqual(stored[0], "Closed")
        self.assertEqual(stored[1], "False Positive")
        self.assertEqual(
            stored[2],
            (
                "Verified as controlled network test activity. "
                "No unauthorised connection occurred."
            ),
        )
        self.assertEqual(stored[3], "analyst01")
        self.assertTrue(stored[4])

    def test_confirmed_alert_uses_confirmed_status(self) -> None:
        """Confirmed suspicious activity remains available for response."""
        result = review_network_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="Confirmed",
            notes="Blocklist evidence confirms suspicious activity.",
        )

        self.assertEqual(
            result["classification"],
            "Confirmed",
        )
        self.assertEqual(result["status"], "Confirmed")
        self.assertEqual(result["previous_status"], "New")

    def test_viewer_cannot_review_network_alert(self) -> None:
        """A Viewer does not have investigation permissions."""
        with self.assertRaises(PermissionError):
            review_network_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="viewer01",
                classification="False Positive",
                notes="Viewer attempted to review the alert.",
            )

    def test_actor_without_active_role_is_rejected(self) -> None:
        """An actor without an active role cannot review alerts."""
        with self.assertRaises(PermissionError):
            review_network_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="unknown01",
                classification="Confirmed",
                notes="Unknown actor attempted a review.",
            )

    def test_empty_notes_are_rejected(self) -> None:
        """Every classification requires investigation notes."""
        with self.assertRaises(ValueError):
            review_network_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="analyst01",
                classification="False Positive",
                notes="   ",
            )

    def test_unknown_classification_is_rejected(self) -> None:
        """Only established investigation classifications are accepted."""
        with self.assertRaises(ValueError):
            review_network_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=1,
                actor="analyst01",
                classification="Ignored",
                notes="Unsupported classification.",
            )

    def test_unknown_alert_is_rejected(self) -> None:
        """A review cannot be recorded for a missing alert."""
        with self.assertRaises(ValueError):
            review_network_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=999,
                actor="analyst01",
                classification="Confirmed",
                notes="Alert does not exist.",
            )

    def test_successful_review_is_audited(self) -> None:
        """A successful network-alert review creates an audit record."""
        review_network_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=1,
            actor="analyst01",
            classification="False Positive",
            notes="Verified controlled network test activity.",
        )

        with managed_connection(
            self.database_path
        ) as connection:
            audit_record = connection.execute(
                """
                SELECT
                    actor,
                    action,
                    target,
                    result,
                    details
                FROM audit_events
                ORDER BY event_id DESC
                LIMIT 1
                """
            ).fetchone()

        self.assertEqual(audit_record[0], "analyst01")
        self.assertEqual(
            audit_record[1],
            "review_v2_stage6_network_alert",
        )
        self.assertEqual(
            audit_record[2],
            "v2_network_alert:1",
        )
        self.assertEqual(audit_record[3], "success")
        self.assertIn(
            "classification=False Positive",
            audit_record[4],
        )
        self.assertIn("status=Closed", audit_record[4])


if __name__ == "__main__":
    unittest.main()
