"""Tests for Stage 5 endpoint and wired-access detection."""

import unittest

from src.detectors.endpoint_detector import (
    detect_cpu_activity,
    detect_mac_reuse,
    detect_wired_access,
)


def event(
    event_id,
    event_time,
    source_type="endpoint",
    event_type="cpu_spike",
    mac_address="02:42:ac:11:00:25",
    hostname="Analyst-Laptop",
    username="analyst01",
    location="Lab Zone A",
    process_name="unknown_worker",
    cpu_percent=98.0,
    status="observed",
    raw=None,
):
    """Create a small test event."""
    return {
        "source_event_id": event_id,
        "event_time": event_time,
        "source_type": source_type,
        "event_type": event_type,
        "mac_address": mac_address,
        "hostname": hostname,
        "username": username,
        "location": location,
        "process_name": process_name,
        "cpu_percent": cpu_percent,
        "status": status,
        "raw": raw or {},
    }


def configuration():
    """Return the Stage 5 test configuration."""
    return {
        "thresholds": {
            "cpu_warning_percent": 80,
            "cpu_critical_percent": 95,
            "cpu_window_minutes": 2,
            "repeated_cpu_events": 3,
            "lan_access_window_minutes": 2,
            "mac_reuse_overlap_minutes": 2,
        },
        "simulated_user_roles": {
            "analyst01": "analyst",
            "responder01": "responder",
        },
        "endpoint_policy": {
            "approved_stress_test_ids": [
                "CPU-TEST-APPROVED-001"
            ],
            "approved_processes": [
                "stress-ng",
                "controlled_cpu_test",
            ],
            "unknown_process_severity": "High",
            "unexpected_cpu_severity": "High",
            "critical_cpu_severity": "Critical",
        },
        "wired_access_policy": {
            "restricted_zones": [
                "Server Room"
            ],
            "approved_roles_by_zone": {
                "Server Room": [
                    "responder",
                    "administrator",
                ]
            },
        },
        "correlation": {
            "mac_reuse_requires_conflicting_hostname_or_user": True
        },
    }


class Stage5EndpointDetectorTests(unittest.TestCase):
    """Test Stage 5 endpoint and wired-access rules."""

    def test_approved_stress_test_is_not_alerted(self):
        events = [
            event(
                "END-001",
                "2026-08-24T09:01:00+12:00",
                event_type="cpu_stress_test",
                process_name="controlled_cpu_test",
                cpu_percent=91.7,
                status="approved",
                raw={
                    "stress_test_id": "CPU-TEST-APPROVED-001"
                },
            )
        ]

        alerts = detect_cpu_activity(
            events,
            configuration(),
        )

        self.assertEqual(alerts, [])

    def test_unapproved_stress_test_is_detected(self):
        events = [
            event(
                "END-002",
                "2026-08-24T09:01:00+12:00",
                event_type="cpu_stress_test",
                process_name="stress-ng",
                cpu_percent=88.5,
                status="unapproved",
                raw={
                    "stress_test_id": "CPU-TEST-UNAPPROVED-001"
                },
            )
        ]

        alerts = detect_cpu_activity(
            events,
            configuration(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Unauthorised CPU Stress Test",
        )

    def test_critical_cpu_activity_is_detected(self):
        events = [
            event(
                "END-003",
                "2026-08-24T09:10:00+12:00",
                cpu_percent=97.8,
            )
        ]

        alerts = detect_cpu_activity(
            events,
            configuration(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Unexpected CPU Activity",
        )
        self.assertEqual(
            alerts[0]["severity"],
            "Critical",
        )

    def test_repeated_high_cpu_activity_is_grouped(self):
        events = [
            event(
                "END-004",
                "2026-08-24T09:10:00+12:00",
                cpu_percent=97.8,
            ),
            event(
                "END-005",
                "2026-08-24T09:11:00+12:00",
                cpu_percent=98.4,
            ),
            event(
                "END-006",
                "2026-08-24T09:12:00+12:00",
                cpu_percent=99.1,
            ),
        ]

        alerts = detect_cpu_activity(
            events,
            configuration(),
        )

        repeated = [
            alert
            for alert in alerts
            if alert["detection_type"]
            == "Repeated High CPU Activity"
        ]

        self.assertEqual(len(repeated), 1)
        self.assertEqual(
            repeated[0]["source_event_ids"],
            ["END-004", "END-005", "END-006"],
        )

    def test_analyst_server_room_access_is_detected(self):
        events = [
            event(
                "LAN-001",
                "2026-08-24T09:45:00+12:00",
                source_type="network",
                event_type="wired_connection",
                location="Server Room",
                status="observed",
                raw={
                    "connection_type": "wired",
                    "switch_port": "SRV-PORT-04",
                    "vlan": "SERVER-200",
                },
            )
        ]

        alerts = detect_wired_access(
            events,
            configuration(),
            {"analyst01": "analyst"},
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Restricted Wired Access",
        )

    def test_responder_server_room_access_is_allowed(self):
        events = [
            event(
                "LAN-002",
                "2026-08-24T09:50:00+12:00",
                source_type="network",
                event_type="wired_connection",
                username="responder01",
                location="Server Room",
                status="approved",
                raw={
                    "connection_type": "wired",
                    "switch_port": "SRV-PORT-02",
                    "vlan": "SERVER-200",
                },
            )
        ]

        alerts = detect_wired_access(
            events,
            configuration(),
            {"responder01": "responder"},
        )

        self.assertEqual(alerts, [])

    def test_mac_reuse_requires_conflicting_hostname_or_user(self):
        events = [
            event(
                "MAC-001",
                "2026-08-24T10:00:00+12:00",
                hostname="Analyst-Laptop",
                username="analyst01",
                location="Lab Zone A",
            ),
            event(
                "MAC-002",
                "2026-08-24T10:01:00+12:00",
                hostname="Copied-MAC-Laptop",
                username="unknown01",
                location="Lab Zone B",
            ),
        ]

        alerts = detect_mac_reuse(
            events,
            configuration(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "MAC Reuse or Possible Spoofing",
        )

    def test_location_change_alone_does_not_create_mac_reuse(self):
        events = [
            event(
                "MAC-003",
                "2026-08-24T10:00:00+12:00",
                hostname="Analyst-Laptop",
                username="analyst01",
                location="Lab Zone A",
            ),
            event(
                "MAC-004",
                "2026-08-24T10:01:00+12:00",
                hostname="Analyst-Laptop",
                username="analyst01",
                location="Server Room",
            ),
        ]

        alerts = detect_mac_reuse(
            events,
            configuration(),
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
