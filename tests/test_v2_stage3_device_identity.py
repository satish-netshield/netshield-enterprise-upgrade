"""Test the Phase 3A V2 Stage 3 device identity foundation and workflow."""

import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.initialize_v2_stage3 import (
    load_inventory_rows,
    sync_inventory,
    validate_inventory_values,
)
from src.assets.device_identity import (
    DETECTION_MISMATCH,
    DETECTION_STALE,
    DETECTION_UNKNOWN,
    DETECTION_UNREGISTERED,
    determine_identity_status,
    evaluate_device_event,
)
from src.assets.device_registry import (
    load_inventory,
    register_device,
    remove_device,
)
from src.utils.config_loader import load_json
from src.utils.database import initialise_database


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage3DeviceIdentityTests(unittest.TestCase):
    """Test inventory, detections and registration workflow."""

    def setUp(self) -> None:
        self.config = load_json(
            PROJECT_ROOT / "config/device_identity.json"
        )
        self.inventory_path = (
            PROJECT_ROOT / self.config["inventory_path"]
        )

    def test_inventory_has_unique_asset_and_device_ids(self) -> None:
        rows = load_inventory_rows(self.inventory_path)

        device_ids = [row["device_id"] for row in rows]
        asset_ids = [row["asset_id"] for row in rows]

        self.assertEqual(len(device_ids), len(set(device_ids)))
        self.assertEqual(len(asset_ids), len(set(asset_ids)))

    def test_inventory_contains_two_approved_devices(self) -> None:
        rows = load_inventory_rows(self.inventory_path)

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["device_id"] for row in rows},
            {"CYOD-001", "CYOD-002"},
        )
        self.assertTrue(
            all(
                row["registration_status"] == "registered"
                for row in rows
            )
        )

    def test_inventory_values_match_controlled_configuration(
        self,
    ) -> None:
        rows = load_inventory_rows(self.inventory_path)
        validate_inventory_values(rows, self.config)

    def test_stage3_tables_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            with sqlite3.connect(database_path) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        """
                        SELECT name
                        FROM sqlite_master
                        WHERE type = 'table'
                        """
                    )
                }

            self.assertIn("device_inventory", tables)
            self.assertIn("device_alerts", tables)
            self.assertIn(
                "device_registration_history",
                tables,
            )

    def test_inventory_sync_is_repeatable(self) -> None:
        rows = load_inventory_rows(self.inventory_path)

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            sync_inventory(database_path, rows)
            sync_inventory(database_path, rows)

            with sqlite3.connect(database_path) as connection:
                count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM device_inventory
                    """
                ).fetchone()[0]

            self.assertEqual(count, 2)

    def test_mac_is_configured_as_supporting_evidence_only(
        self,
    ) -> None:
        self.assertEqual(
            self.config["mac_address_identity"],
            "supporting_evidence_only",
        )

    def test_unknown_device_is_detected(self) -> None:
        event = {
            "source_event_id": "TEST-UNKNOWN-001",
            "device_id": "CYOD-999",
            "asset_id": None,
            "hostname": "Unknown-Laptop",
            "username": "viewer01",
            "ip_address": "192.0.2.99",
            "mac_address": "02:00:00:00:00:99",
            "location": "Auckland-NZ",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=None,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["detection_type"],
            DETECTION_UNKNOWN,
        )

    def test_unregistered_device_is_detected(self) -> None:
        event = {
            "source_event_id": "TEST-UNREGISTERED-001",
            "device_id": "CYOD-003",
            "asset_id": "AST-003",
            "hostname": "Unknown-Test-Device",
            "username": None,
            "ip_address": "192.0.2.30",
            "mac_address": "02:00:00:00:00:03",
            "location": "Auckland-NZ",
        }

        inventory_record = {
            "asset_id": "AST-003",
            "device_id": "CYOD-003",
            "hostname": "Unknown-Test-Device",
            "assigned_user": None,
            "registration_status": "unregistered",
            "mac_address": "02:00:00:00:00:03",
            "ip_address": "192.0.2.30",
            "location": "Auckland-NZ",
            "last_seen": "2026-09-07T00:00:00+00:00",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=inventory_record,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        detection_types = {
            finding["detection_type"]
            for finding in findings
        }

        self.assertIn(
            DETECTION_UNREGISTERED,
            detection_types,
        )

    def test_stale_device_is_detected(self) -> None:
        event = {
            "source_event_id": "TEST-STALE-001",
            "device_id": "CYOD-002",
            "asset_id": "AST-002",
            "hostname": "Analyst-Laptop",
            "username": "analyst01",
            "ip_address": "192.0.2.20",
            "mac_address": "02:00:00:00:00:02",
            "location": "Auckland-NZ",
        }

        inventory_record = {
            "asset_id": "AST-002",
            "device_id": "CYOD-002",
            "hostname": "Analyst-Laptop",
            "assigned_user": "analyst01",
            "registration_status": "registered",
            "mac_address": "02:00:00:00:00:02",
            "ip_address": "192.0.2.20",
            "location": "Auckland-NZ",
            "last_seen": "2026-07-01T00:00:00+00:00",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=inventory_record,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        detection_types = {
            finding["detection_type"]
            for finding in findings
        }

        self.assertIn(DETECTION_STALE, detection_types)

    def test_inventory_mismatch_is_detected(self) -> None:
        event = {
            "source_event_id": "TEST-MISMATCH-001",
            "device_id": "CYOD-002",
            "asset_id": "AST-002",
            "hostname": "Finance-PC",
            "username": "analyst01",
            "ip_address": "192.0.2.20",
            "mac_address": "02:00:00:00:00:02",
            "location": "Auckland-NZ",
        }

        inventory_record = {
            "asset_id": "AST-002",
            "device_id": "CYOD-002",
            "hostname": "Analyst-Laptop",
            "assigned_user": "analyst01",
            "registration_status": "registered",
            "mac_address": "02:00:00:00:00:02",
            "ip_address": "192.0.2.20",
            "location": "Auckland-NZ",
            "last_seen": "2026-09-07T00:00:00+00:00",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=inventory_record,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        detection_types = {
            finding["detection_type"]
            for finding in findings
        }

        self.assertIn(
            DETECTION_MISMATCH,
            detection_types,
        )

    def test_mac_mismatch_does_not_create_unknown_device(self) -> None:
        event = {
            "source_event_id": "TEST-MAC-001",
            "device_id": "CYOD-002",
            "asset_id": "AST-002",
            "hostname": "Analyst-Laptop",
            "username": "analyst01",
            "ip_address": "192.0.2.20",
            "mac_address": "02:00:00:00:00:88",
            "location": "Auckland-NZ",
        }

        inventory_record = {
            "asset_id": "AST-002",
            "device_id": "CYOD-002",
            "hostname": "Analyst-Laptop",
            "assigned_user": "analyst01",
            "registration_status": "registered",
            "mac_address": "02:00:00:00:00:02",
            "ip_address": "192.0.2.20",
            "location": "Auckland-NZ",
            "last_seen": "2026-09-07T00:00:00+00:00",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=inventory_record,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        detection_types = {
            finding["detection_type"]
            for finding in findings
        }

        self.assertNotIn(
            DETECTION_UNKNOWN,
            detection_types,
        )
        self.assertIn(
            DETECTION_MISMATCH,
            detection_types,
        )

    def test_known_compliant_device_has_no_findings(self) -> None:
        event = {
            "source_event_id": "TEST-CLEAN-001",
            "device_id": "CYOD-002",
            "asset_id": "AST-002",
            "hostname": "Analyst-Laptop",
            "username": "analyst01",
            "ip_address": "192.0.2.20",
            "mac_address": "02:00:00:00:00:02",
            "location": "Auckland-NZ",
        }

        inventory_record = {
            "asset_id": "AST-002",
            "device_id": "CYOD-002",
            "hostname": "Analyst-Laptop",
            "assigned_user": "analyst01",
            "registration_status": "registered",
            "mac_address": "02:00:00:00:00:02",
            "ip_address": "192.0.2.20",
            "location": "Auckland-NZ",
            "last_seen": "2026-09-07T00:00:00+00:00",
        }

        findings = determine_identity_status(
            event=event,
            inventory_record=inventory_record,
            stale_device_days=30,
            reference_time=datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(findings, [])

    def test_alert_storage_is_duplicate_safe(self) -> None:
        rows = load_inventory_rows(self.inventory_path)

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )
            sync_inventory(database_path, rows)

            event = {
                "source_event_id": "TEST-UNKNOWN-STORAGE-001",
                "device_id": "CYOD-999",
                "asset_id": None,
                "hostname": "Unknown-Laptop",
                "username": "viewer01",
                "ip_address": "192.0.2.99",
                "mac_address": "02:00:00:00:00:99",
                "location": "Auckland-NZ",
            }

            evaluate_device_event(
                database_path=database_path,
                event=event,
                stale_device_days=30,
                reference_time=datetime(
                    2026,
                    9,
                    7,
                    tzinfo=timezone.utc,
                ),
            )

            evaluate_device_event(
                database_path=database_path,
                event=event,
                stale_device_days=30,
                reference_time=datetime(
                    2026,
                    9,
                    7,
                    tzinfo=timezone.utc,
                ),
            )

            with sqlite3.connect(database_path) as connection:
                count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM device_alerts
                    """
                ).fetchone()[0]

            self.assertEqual(count, 1)

    def test_device_registration_preserves_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_path = Path(directory)
            database_path = temp_path / "test.db"
            inventory_path = temp_path / "cyod_devices.csv"

            shutil.copy(
                self.inventory_path,
                inventory_path,
            )

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            rows = load_inventory_rows(inventory_path)
            sync_inventory(database_path, rows)

            device = {
                "asset_id": "AST-TEST-004",
                "device_id": "CYOD-TEST-004",
                "hostname": "Stage3-Test-Laptop",
                "assigned_user": "viewer01",
                "ownership": "organisation",
                "device_type": "Laptop",
                "manufacturer": "Simulated",
                "operating_system": "Ubuntu",
                "os_version": "26.04",
                "mac_address": "02:00:00:00:00:44",
                "ip_address": "192.0.2.44",
                "location": "Auckland-NZ",
                "connection_type": "Enterprise LAN",
                "compliance_status": "compliant",
                "risk_status": "low",
                "criticality": "medium",
                "last_seen": "2026-09-07T06:00:00+00:00",
            }

            register_device(
                database_path=database_path,
                inventory_path=inventory_path,
                device=device,
                actor="test-analyst",
                reason="Controlled Stage 3 registration test",
            )

            inventory = load_inventory(inventory_path)

            registered = next(
                row
                for row in inventory
                if row["device_id"] == "CYOD-TEST-004"
            )

            self.assertEqual(
                registered["approval_status"],
                "approved",
            )
            self.assertEqual(
                registered["registration_status"],
                "registered",
            )

            with sqlite3.connect(database_path) as connection:
                row = connection.execute(
                    """
                    SELECT
                        action,
                        previous_status,
                        new_status,
                        actor
                    FROM device_registration_history
                    WHERE device_id = ?
                    """,
                    ("CYOD-TEST-004",),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    "register",
                    None,
                    "registered",
                    "test-analyst",
                ),
            )

    def test_device_removal_preserves_record_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_path = Path(directory)
            database_path = temp_path / "test.db"
            inventory_path = temp_path / "cyod_devices.csv"

            shutil.copy(
                self.inventory_path,
                inventory_path,
            )

            initialise_database(
                database_path,
                PROJECT_ROOT / "database/schema.sql",
            )

            rows = load_inventory_rows(inventory_path)
            sync_inventory(database_path, rows)

            remove_device(
                database_path=database_path,
                inventory_path=inventory_path,
                device_id="CYOD-002",
                actor="test-responder",
                reason="Controlled Stage 3 removal test",
            )

            inventory = load_inventory(inventory_path)

            removed = next(
                row
                for row in inventory
                if row["device_id"] == "CYOD-002"
            )

            self.assertEqual(
                removed["approval_status"],
                "removed",
            )
            self.assertEqual(
                removed["registration_status"],
                "removed",
            )

            with sqlite3.connect(database_path) as connection:
                inventory_row = connection.execute(
                    """
                    SELECT registration_status
                    FROM device_inventory
                    WHERE device_id = ?
                    """,
                    ("CYOD-002",),
                ).fetchone()

                history_row = connection.execute(
                    """
                    SELECT
                        action,
                        previous_status,
                        new_status,
                        actor
                    FROM device_registration_history
                    WHERE device_id = ?
                    """,
                    ("CYOD-002",),
                ).fetchone()

            self.assertEqual(
                inventory_row[0],
                "removed",
            )
            self.assertEqual(
                history_row,
                (
                    "remove",
                    "registered",
                    "removed",
                    "test-responder",
                ),
            )


if __name__ == "__main__":
    unittest.main()
