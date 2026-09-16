"""Test Phase 3A V2 Stage 7 endpoint monitoring and controls."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.approve_v2_stage7_endpoint_isolation import (
    approve_simulated_isolation,
)
from scripts.initialize_v2_stage7_8 import SCHEMA
from scripts.review_v2_stage7_endpoint_alert import (
    review_endpoint_alert,
)
from src.collectors.event_normalizer import normalise_event
from src.detectors.v2_endpoint_monitor import (
    build_isolation_requests,
    detect_endpoint_activity,
    is_approved_exception,
    load_device_inventory,
    load_stage7_events,
    save_activity_timeline,
    save_endpoint_alerts,
    save_isolation_requests,
)
from src.utils.config_loader import load_json
from src.utils.database import (
    assign_role,
    initialise_database,
    save_security_event,
    start_import_batch,
)
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage7EndpointMonitoringTests(unittest.TestCase):
    """Verify endpoint detection, investigation and isolation controls."""

    def setUp(self) -> None:
        """Create an isolated Stage 7 database and controlled event set."""
        self.temporary_directory = TemporaryDirectory()
        self.database_path = (
            Path(self.temporary_directory.name)
            / "stage7_test.db"
        )

        initialise_database(
            self.database_path,
            PROJECT_ROOT / "database/schema.sql",
        )

        with managed_connection(
            self.database_path
        ) as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                """
                INSERT INTO device_inventory (
                    asset_id,
                    device_id,
                    hostname,
                    assigned_user,
                    ownership,
                    device_type,
                    manufacturer,
                    operating_system,
                    os_version,
                    mac_address,
                    ip_address,
                    location,
                    connection_type,
                    registration_status,
                    compliance_status,
                    risk_status,
                    criticality,
                    registered_date,
                    last_seen
                )
                VALUES (
                    'AST-002',
                    'CYOD-002',
                    'Analyst-Laptop',
                    'analyst01',
                    'organisation',
                    'Laptop',
                    'Simulated',
                    'Windows',
                    '11',
                    '02:00:00:00:00:02',
                    '192.0.2.20',
                    'Auckland-NZ',
                    'Enterprise LAN',
                    'registered',
                    'compliant',
                    'low',
                    'medium',
                    '2026-09-07',
                    '2026-09-11T08:00:00+00:00'
                )
                """
            )

        assign_role(
            self.database_path,
            "viewer01",
            "viewer",
        )
        assign_role(
            self.database_path,
            "analyst01",
            "analyst",
        )
        assign_role(
            self.database_path,
            "responder01",
            "responder",
        )
        assign_role(
            self.database_path,
            "admin01",
            "administrator",
        )

        self.configuration = load_json(
            PROJECT_ROOT
            / "config/v2_endpoint_monitoring.json"
        )
        self.rbac_config = load_json(
            PROJECT_ROOT / "config/rbac.json"
        )
        self.automation_acl = load_json(
            PROJECT_ROOT / "config/automation_acl.json"
        )

        self.source_file = next(
            source_file
            for source_file
            in self.configuration["source_files"]
            if "endpoint" in source_file
        )
        source_path = (
            PROJECT_ROOT
            / "data/raw/v2/stage7_8"
            / Path(self.source_file).name
        )

        raw_events = [
            json.loads(line)
            for line in source_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]

        start_import_batch(
            database_path=self.database_path,
            batch_id="stage7-test-batch",
            source_file=self.source_file,
            source_type="endpoint",
        )

        for raw_event in raw_events:
            stored = save_security_event(
                database_path=self.database_path,
                event=normalise_event(raw_event),
                source_file=self.source_file,
                batch_id="stage7-test-batch",
                raw_event=raw_event,
            )
            self.assertTrue(stored)

        self.events = load_stage7_events(
            self.database_path,
            self.configuration["source_files"],
        )
        self.inventory = load_device_inventory(
            self.database_path
        )
        self.alerts = detect_endpoint_activity(
            self.events,
            self.configuration,
            self.inventory,
        )

    def tearDown(self) -> None:
        """Remove the isolated test database."""
        self.temporary_directory.cleanup()

    def store_isolation_request(self) -> int:
        """Store and return the consolidated isolation request ID."""
        requests = build_isolation_requests(
            self.alerts,
            self.configuration,
            self.automation_acl,
        )
        created, existing = save_isolation_requests(
            self.database_path,
            requests,
        )

        self.assertEqual(created, 1)
        self.assertEqual(existing, 0)

        with managed_connection(
            self.database_path
        ) as connection:
            row = connection.execute(
                """
                SELECT isolation_id
                FROM v2_endpoint_isolation_actions
                """
            ).fetchone()

        self.assertIsNotNone(row)
        return row[0]

    def store_alerts_and_find(
        self,
        detection_type: str,
    ) -> int:
        """Store alerts and return one ID for a detection type."""
        created, existing = save_endpoint_alerts(
            self.database_path,
            self.alerts,
        )

        self.assertEqual(created, 26)
        self.assertEqual(existing, 0)

        with managed_connection(
            self.database_path
        ) as connection:
            row = connection.execute(
                """
                SELECT alert_id
                FROM v2_endpoint_alerts
                WHERE detection_type = ?
                ORDER BY alert_id
                LIMIT 1
                """,
                (detection_type,),
            ).fetchone()

        self.assertIsNotNone(row)
        return row[0]

    def test_controlled_endpoint_event_set_is_complete(
        self,
    ) -> None:
        """The tracked Stage 7 source contains 26 endpoint events."""
        self.assertEqual(len(self.events), 26)
        self.assertEqual(
            len(
                {
                    event["source_event_id"]
                    for event in self.events
                }
            ),
            26,
        )

    def test_expected_endpoint_alerts_are_created(
        self,
    ) -> None:
        """The controlled event set produces 26 endpoint alerts."""
        self.assertEqual(len(self.alerts), 26)

        severity_counts = {
            severity: sum(
                alert["severity"] == severity
                for alert in self.alerts
            )
            for severity in {
                "Critical",
                "High",
                "Medium",
                "Low",
            }
        }

        self.assertEqual(severity_counts["Critical"], 10)
        self.assertEqual(severity_counts["High"], 13)
        self.assertEqual(severity_counts["Medium"], 3)
        self.assertEqual(severity_counts["Low"], 0)

    def test_all_required_detection_types_are_represented(
        self,
    ) -> None:
        """Every required Stage 7 endpoint rule is exercised."""
        expected_types = {
            "Endpoint Health State",
            "Device Compliance State",
            "Device Risk State",
            "Suspicious Process",
            "Unknown or Unapproved Process",
            "Unexpected Process Owner",
            (
                "Suspicious Parent-Child "
                "Process Relationship"
            ),
            "High CPU Activity",
            "Repeated Process Crash or Restart",
            "Suspicious Command Activity",
            "Possible Persistence Indicator",
            "Unexpected File-Hash Change",
            "Post-Isolation Endpoint Activity",
        }

        actual_types = {
            alert["detection_type"]
            for alert in self.alerts
        }

        self.assertEqual(actual_types, expected_types)

    def test_crash_restart_rule_uses_eight_minutes(
        self,
    ) -> None:
        """Three crash or restart events within eight minutes alert."""
        matching_alerts = [
            alert
            for alert in self.alerts
            if alert["detection_type"]
            == "Repeated Process Crash or Restart"
        ]

        self.assertEqual(len(matching_alerts), 1)
        alert = matching_alerts[0]

        self.assertEqual(
            alert["source_event_ids"],
            [
                "S78-END-017",
                "S78-END-018",
                "S78-END-019",
            ],
        )
        self.assertEqual(
            alert["evidence"]["observations"][
                "configured_window_minutes"
            ],
            8,
        )
        self.assertEqual(
            alert["evidence"]["observations"][
                "observed_window_minutes"
            ],
            7.0,
        )
        self.assertEqual(
            alert["evidence"]["observations"][
                "event_count"
            ],
            3,
        )

    def test_approved_exceptions_do_not_create_alerts(
        self,
    ) -> None:
        """Approved administrative and testing activity is suppressed."""
        exception_event_ids = {
            event["source_event_id"]
            for event in self.events
            if is_approved_exception(
                event,
                self.configuration,
            )
        }
        alert_event_ids = {
            event_id
            for alert in self.alerts
            for event_id in alert["source_event_ids"]
        }

        self.assertEqual(
            exception_event_ids,
            {
                "S78-END-ADMIN-001",
                "S78-END-TEST-001",
            },
        )
        self.assertTrue(
            exception_event_ids.isdisjoint(
                alert_event_ids
            )
        )

    def test_endpoint_alerts_are_traceable(
        self,
    ) -> None:
        """Every alert retains reasons, events and evidence."""
        for alert in self.alerts:
            self.assertTrue(alert["alert_key"])
            self.assertTrue(alert["source_event_ids"])
            self.assertTrue(alert["reason_codes"])
            self.assertIsInstance(
                alert["evidence"],
                dict,
            )
            self.assertIn(
                "source_events",
                alert["evidence"],
            )

    def test_post_isolation_activity_is_detected(
        self,
    ) -> None:
        """Activity after simulated isolation remains monitored."""
        matching_alerts = [
            alert
            for alert in self.alerts
            if alert["detection_type"]
            == "Post-Isolation Endpoint Activity"
        ]

        self.assertEqual(len(matching_alerts), 1)
        self.assertEqual(
            matching_alerts[0]["source_event_ids"],
            ["S78-END-024"],
        )
        self.assertEqual(
            matching_alerts[0]["severity"],
            "Critical",
        )

    def test_timeline_storage_is_duplicate_safe(
        self,
    ) -> None:
        """Repeated timeline storage does not duplicate events."""
        first_created, first_existing = (
            save_activity_timeline(
                self.database_path,
                self.events,
            )
        )
        second_created, second_existing = (
            save_activity_timeline(
                self.database_path,
                self.events,
            )
        )

        self.assertEqual(
            (first_created, first_existing),
            (26, 0),
        )
        self.assertEqual(
            (second_created, second_existing),
            (0, 26),
        )

        with managed_connection(
            self.database_path
        ) as connection:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM v2_endpoint_activity_timeline
                """
            ).fetchone()[0]

        self.assertEqual(count, 26)

    def test_alert_storage_is_duplicate_safe(
        self,
    ) -> None:
        """Repeated alert storage preserves the original records."""
        first_created, first_existing = (
            save_endpoint_alerts(
                self.database_path,
                self.alerts,
            )
        )
        second_created, second_existing = (
            save_endpoint_alerts(
                self.database_path,
                self.alerts,
            )
        )

        self.assertEqual(
            (first_created, first_existing),
            (26, 0),
        )
        self.assertEqual(
            (second_created, second_existing),
            (0, 26),
        )

        with managed_connection(
            self.database_path
        ) as connection:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM v2_endpoint_alerts
                """
            ).fetchone()[0]

        self.assertEqual(count, 26)

    def test_isolation_request_is_consolidated(
        self,
    ) -> None:
        """Ten Critical alerts create one request for the device."""
        critical_alerts = [
            alert
            for alert in self.alerts
            if alert["severity"] == "Critical"
        ]
        requests = build_isolation_requests(
            self.alerts,
            self.configuration,
            self.automation_acl,
        )

        self.assertEqual(len(critical_alerts), 10)
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            requests[0]["device_id"],
            "CYOD-002",
        )
        self.assertEqual(
            requests[0]["evidence"]["alert_count"],
            10,
        )
        self.assertEqual(
            len(
                requests[0]["evidence"]["alert_keys"]
            ),
            10,
        )

    def test_isolation_remains_simulated_and_controlled(
        self,
    ) -> None:
        """Isolation requires approval and cannot change the network."""
        requests = build_isolation_requests(
            self.alerts,
            self.configuration,
            self.automation_acl,
        )
        request = requests[0]

        self.assertEqual(
            request["action"],
            "quarantine_device",
        )
        self.assertEqual(
            request["acl_control_level"],
            "approval_required",
        )
        self.assertEqual(
            request["status"],
            "approval_required",
        )
        self.assertEqual(
            request["network_state_changed"],
            0,
        )
        self.assertEqual(
            request["real_action_executed"],
            0,
        )

    def test_isolation_storage_is_duplicate_safe(
        self,
    ) -> None:
        """Repeated storage does not duplicate an isolation request."""
        requests = build_isolation_requests(
            self.alerts,
            self.configuration,
            self.automation_acl,
        )

        first_created, first_existing = (
            save_isolation_requests(
                self.database_path,
                requests,
            )
        )
        second_created, second_existing = (
            save_isolation_requests(
                self.database_path,
                requests,
            )
        )

        self.assertEqual(
            (first_created, first_existing),
            (1, 0),
        )
        self.assertEqual(
            (second_created, second_existing),
            (0, 1),
        )

        with managed_connection(
            self.database_path
        ) as connection:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM v2_endpoint_isolation_actions
                """
            ).fetchone()[0]

        self.assertEqual(count, 1)

    def test_analyst_cannot_approve_isolation(
        self,
    ) -> None:
        """An Analyst cannot approve endpoint containment."""
        isolation_id = self.store_isolation_request()

        with self.assertRaises(PermissionError):
            approve_simulated_isolation(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                automation_acl=self.automation_acl,
                isolation_id=isolation_id,
                actor="analyst01",
                notes="Permission-boundary test.",
            )

    def test_responder_can_approve_simulated_isolation(
        self,
    ) -> None:
        """A Responder can approve only the simulated record."""
        isolation_id = self.store_isolation_request()

        result = approve_simulated_isolation(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            automation_acl=self.automation_acl,
            isolation_id=isolation_id,
            actor="responder01",
            notes=(
                "Reviewed the Critical endpoint alerts and "
                "approved the simulated isolation record."
            ),
        )

        self.assertEqual(
            result["status"],
            "simulated_isolated",
        )
        self.assertEqual(
            result["approved_by"],
            "responder01",
        )
        self.assertFalse(
            result["network_state_changed"]
        )
        self.assertFalse(
            result["real_action_executed"]
        )

        with self.assertRaises(ValueError):
            approve_simulated_isolation(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                automation_acl=self.automation_acl,
                isolation_id=isolation_id,
                actor="responder01",
                notes="Repeated approval test.",
            )

        with managed_connection(
            self.database_path
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    approved_by,
                    network_state_changed,
                    real_action_executed
                FROM v2_endpoint_isolation_actions
                WHERE isolation_id = ?
                """,
                (isolation_id,),
            ).fetchone()
            audit_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM audit_events
                WHERE action =
                    'approve_v2_stage7_endpoint_isolation'
                """
            ).fetchone()[0]

        self.assertEqual(
            row,
            (
                "simulated_isolated",
                "responder01",
                0,
                0,
            ),
        )
        self.assertEqual(audit_count, 1)

    def test_administrator_can_approve_simulated_isolation(
        self,
    ) -> None:
        """An Administrator can approve the simulated record."""
        isolation_id = self.store_isolation_request()

        result = approve_simulated_isolation(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            automation_acl=self.automation_acl,
            isolation_id=isolation_id,
            actor="admin01",
            notes=(
                "Administrator approval test for the "
                "simulated isolation record."
            ),
        )

        self.assertEqual(
            result["status"],
            "simulated_isolated",
        )
        self.assertEqual(
            result["approved_by"],
            "admin01",
        )
        self.assertFalse(
            result["network_state_changed"]
        )
        self.assertFalse(
            result["real_action_executed"]
        )

    def test_viewer_cannot_review_endpoint_alert(
        self,
    ) -> None:
        """A Viewer cannot classify an endpoint alert."""
        alert_id = self.store_alerts_and_find(
            "Repeated Process Crash or Restart"
        )

        with self.assertRaises(PermissionError):
            review_endpoint_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=alert_id,
                actor="viewer01",
                classification="False Positive",
                notes="Permission-boundary test.",
            )

    def test_analyst_can_record_false_positive(
        self,
    ) -> None:
        """An Analyst can close a supported false positive."""
        alert_id = self.store_alerts_and_find(
            "Repeated Process Crash or Restart"
        )
        notes = (
            "The approved process produced three crash and "
            "restart events. The registered device is "
            "compliant and has a low-risk state."
        )

        result = review_endpoint_alert(
            database_path=self.database_path,
            rbac_config=self.rbac_config,
            alert_id=alert_id,
            actor="analyst01",
            classification="False Positive",
            notes=notes,
        )

        self.assertEqual(
            result["status"],
            "Closed",
        )
        self.assertEqual(
            result["classification"],
            "False Positive",
        )
        self.assertEqual(
            result["reviewed_by"],
            "analyst01",
        )

        with self.assertRaises(ValueError):
            review_endpoint_alert(
                database_path=self.database_path,
                rbac_config=self.rbac_config,
                alert_id=alert_id,
                actor="analyst01",
                classification="False Positive",
                notes="Repeated review test.",
            )

        created, existing = save_endpoint_alerts(
            self.database_path,
            self.alerts,
        )

        self.assertEqual(created, 0)
        self.assertEqual(existing, 26)

        with managed_connection(
            self.database_path
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    classification,
                    reviewed_by,
                    investigation_notes
                FROM v2_endpoint_alerts
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
            audit_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM audit_events
                WHERE action =
                    'review_v2_stage7_endpoint_alert'
                """
            ).fetchone()[0]

        self.assertEqual(row[0], "Closed")
        self.assertEqual(
            row[1],
            "False Positive",
        )
        self.assertEqual(row[2], "analyst01")
        self.assertEqual(row[3], notes)
        self.assertEqual(audit_count, 1)


if __name__ == "__main__":
    unittest.main()
