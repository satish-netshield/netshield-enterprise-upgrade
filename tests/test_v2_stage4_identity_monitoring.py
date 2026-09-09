"""Test V2 Stage 4 enterprise identity monitoring."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage4_5 import SCHEMA
from src.detectors.v2_identity_monitor import (
    detect_context_anomalies,
    detect_failure_patterns,
    detect_identity_activity,
    detect_impossible_travel,
    detect_mfa_activity,
    detect_privilege_changes,
    detect_risky_identity_events,
    detect_shared_source_patterns,
    save_identity_alerts,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_event(
    event_id: str,
    event_time: str,
    event_type: str,
    username: str,
    ip_address: str = "203.0.113.50",
    device_id: str = "CYOD-002",
    location: str = "Auckland, NZ",
    source_type: str = "authentication",
    risk_score: float | None = None,
    **raw_fields: Any,
) -> dict[str, Any]:
    """Build one normalised event for a unit test."""
    raw_event = {
        "event_id": event_id,
        "event_time": event_time,
        "event_type": event_type,
        "source_type": source_type,
        "username": username,
        "ip_address": ip_address,
        "device_id": device_id,
        "location": location,
    }
    raw_event.update(raw_fields)

    return {
        "source_event_id": event_id,
        "source_type": source_type,
        "source_system": f"simulated_v2_{source_type}",
        "event_time": event_time,
        "event_type": event_type,
        "severity": None,
        "risk_score": risk_score,
        "device_id": device_id,
        "username": username,
        "ip_address": ip_address,
        "hostname": raw_fields.get(
            "hostname",
            "Test-Device",
        ),
        "location": location,
        "status": raw_fields.get("status"),
        "raw": raw_event,
    }


class V2Stage4IdentityMonitoringTests(unittest.TestCase):
    """Verify Stage 4 detection and duplicate behaviour."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.configuration = load_json(
            PROJECT_ROOT
            / "config/v2_identity_monitoring.json"
        )
        cls.locations = load_json(
            PROJECT_ROOT / "config/identity_detection.json"
        )["locations"]

    def test_repeated_failures_and_brute_force_are_detected(
        self,
    ) -> None:
        events = [
            build_event(
                f"TEST-FAIL-{number}",
                f"2026-09-09T08:0{number}:00+00:00",
                "login_failure",
                "analyst01",
            )
            for number in range(1, 6)
        ]

        alerts = detect_failure_patterns(
            events,
            self.configuration,
        )
        detection_types = {
            alert["detection_type"]
            for alert in alerts
        }

        self.assertIn(
            "Repeated Failed Logins",
            detection_types,
        )
        self.assertIn(
            "Possible Brute Force",
            detection_types,
        )

    def test_success_after_failures_is_detected(self) -> None:
        events = [
            build_event(
                f"TEST-SUCCESS-{number}",
                f"2026-09-09T08:0{number}:00+00:00",
                "login_failure",
                "analyst01",
            )
            for number in range(1, 4)
        ]
        events.append(
            build_event(
                "TEST-SUCCESS-4",
                "2026-09-09T08:04:00+00:00",
                "login_success",
                "analyst01",
            )
        )

        alerts = detect_failure_patterns(
            events,
            self.configuration,
        )

        self.assertTrue(
            any(
                alert["detection_type"]
                == "Successful Login After Failures"
                for alert in alerts
            )
        )

    def test_password_spray_and_shared_source_are_detected(
        self,
    ) -> None:
        events = [
            build_event(
                f"TEST-SPRAY-{number}",
                f"2026-09-09T08:0{number}:00+00:00",
                "login_failure",
                username,
                ip_address="198.51.100.90",
            )
            for number, username in enumerate(
                (
                    "viewer01",
                    "responder01",
                    "admin01",
                ),
                1,
            )
        ]

        alerts = detect_shared_source_patterns(
            events,
            self.configuration,
        )
        detection_types = {
            alert["detection_type"]
            for alert in alerts
        }

        self.assertEqual(
            detection_types,
            {
                "Password Spraying Pattern",
                "Multiple Accounts From One Source",
            },
        )

    def test_mfa_failure_pattern_is_detected(self) -> None:
        events = [
            build_event(
                f"TEST-MFA-{number}",
                f"2026-09-09T09:0{number}:00+00:00",
                "mfa_failure",
                "analyst01",
            )
            for number in range(1, 4)
        ]

        alerts = detect_mfa_activity(
            events,
            self.configuration,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "MFA Failure or Fatigue Pattern",
        )

    def test_new_device_and_unusual_location_are_detected(
        self,
    ) -> None:
        event = build_event(
            "TEST-CONTEXT-1",
            "2026-09-09T10:00:00+00:00",
            "login_success",
            "viewer01",
            device_id="CYOD-003",
            location="Sydney, Australia",
        )

        alerts, vpn_exceptions, testing_exceptions = (
            detect_context_anomalies(
                [event],
                self.configuration,
                set(),
            )
        )
        detection_types = {
            alert["detection_type"]
            for alert in alerts
        }

        self.assertIn("New-Device Sign-In", detection_types)
        self.assertIn(
            "Unusual Sign-In Location",
            detection_types,
        )
        self.assertEqual(vpn_exceptions, 0)
        self.assertEqual(testing_exceptions, 0)

    def test_abnormal_access_time_is_detected(self) -> None:
        event = build_event(
            "TEST-TIME-1",
            "2026-09-09T23:00:00+00:00",
            "login_success",
            "viewer01",
            device_id="CYOD-001",
        )

        alerts, _, _ = detect_context_anomalies(
            [event],
            self.configuration,
            set(),
        )

        self.assertTrue(
            any(
                alert["detection_type"]
                == "Abnormal Access Time"
                for alert in alerts
            )
        )

    def test_vpn_and_approved_testing_exceptions_apply(
        self,
    ) -> None:
        vpn_event = build_event(
            "TEST-VPN-1",
            "2026-09-09T10:00:00+00:00",
            "login_success",
            "analyst01",
            ip_address="203.0.113.10",
            device_id="CYOD-999",
            location="London, UK",
        )
        testing_event = build_event(
            "TEST-APPROVED-1",
            "2026-09-09T10:01:00+00:00",
            "login_success",
            "trainee01",
            device_id="CYOD-999",
            location="Restricted Test Location",
            approved_test_activity=True,
        )

        alerts, vpn_exceptions, testing_exceptions = (
            detect_context_anomalies(
                [vpn_event, testing_event],
                self.configuration,
                {"203.0.113.10"},
            )
        )

        self.assertEqual(alerts, [])
        self.assertEqual(vpn_exceptions, 1)
        self.assertEqual(testing_exceptions, 1)

    def test_impossible_travel_is_detected(self) -> None:
        events = [
            build_event(
                "TEST-TRAVEL-1",
                "2026-09-09T08:00:00+00:00",
                "login_success",
                "analyst01",
                location="Auckland, NZ",
            ),
            build_event(
                "TEST-TRAVEL-2",
                "2026-09-09T08:30:00+00:00",
                "login_success",
                "analyst01",
                location="London, UK",
            ),
        ]

        alerts, vpn_exceptions = detect_impossible_travel(
            events,
            self.configuration,
            self.locations,
            set(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Impossible Travel",
        )
        self.assertEqual(vpn_exceptions, 0)

    def test_privilege_change_is_detected(self) -> None:
        event = build_event(
            "TEST-ROLE-1",
            "2026-09-09T10:00:00+00:00",
            "role_change",
            "viewer01",
            previous_role="viewer",
            new_role="administrator",
            changed_by="admin01",
        )

        alerts = detect_privilege_changes(
            [event],
            self.configuration,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "Critical")
        self.assertEqual(alerts[0]["confidence"], 95)

    def test_dormant_and_service_accounts_are_detected(
        self,
    ) -> None:
        events = [
            build_event(
                "TEST-DORMANT-1",
                "2026-09-09T10:00:00+00:00",
                "login_success",
                "dormant01",
                device_id="CYOD-001",
            ),
            build_event(
                "TEST-SERVICE-1",
                "2026-09-09T10:01:00+00:00",
                "login_success",
                "svc_ingestion01",
                device_id="CYOD-001",
                interactive=True,
            ),
        ]

        alerts, _, _ = detect_context_anomalies(
            events,
            self.configuration,
            set(),
        )
        detection_types = {
            alert["detection_type"]
            for alert in alerts
        }

        self.assertIn(
            "Dormant-Account Activity",
            detection_types,
        )
        self.assertIn(
            "Service-Account Interactive Login",
            detection_types,
        )

    def test_high_risk_identity_events_are_detected(
        self,
    ) -> None:
        event = build_event(
            "TEST-RISK-1",
            "2026-09-09T11:00:00+00:00",
            "risky_sign_in",
            "analyst01",
            source_type="identity_risk",
            risk_score=88,
            risk_state="at_risk",
        )

        alerts = detect_risky_identity_events(
            [event],
            self.configuration,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["reason_codes"],
            ["HIGH_RISK_SIGN_IN"],
        )
        self.assertEqual(
            alerts[0]["mitre_techniques"],
            ["T1078"],
        )

    def test_alert_storage_is_duplicate_safe(self) -> None:
        event = build_event(
            "TEST-DUPLICATE-1",
            "2026-09-09T23:00:00+00:00",
            "login_success",
            "viewer01",
            device_id="CYOD-001",
        )
        alerts, _ = detect_identity_activity(
            [event],
            self.configuration,
            self.locations,
            set(),
        )

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            with managed_connection(database_path) as connection:
                connection.executescript(SCHEMA)

            first_created, first_existing = (
                save_identity_alerts(
                    database_path,
                    alerts,
                )
            )
            second_created, second_existing = (
                save_identity_alerts(
                    database_path,
                    alerts,
                )
            )

        self.assertEqual(first_created, len(alerts))
        self.assertEqual(first_existing, 0)
        self.assertEqual(second_created, 0)
        self.assertEqual(second_existing, len(alerts))


if __name__ == "__main__":
    unittest.main()
