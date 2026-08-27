"""Tests for Stage 7 correlation, risk scoring and IoCs."""

from __future__ import annotations

import unittest

from src.correlation.stage7_engine import (
    correlate_events,
)


class Stage7CorrelationTests(unittest.TestCase):
    """Verify Stage 7 decisions."""

    def setUp(self) -> None:
        self.configuration = {
            "correlation": {
                "time_window_minutes": 10,
                "minimum_shared_fields": 1,
                "primary_fields": [
                    "username",
                    "ip_address",
                    "mac_address",
                    "hostname",
                ],
                "approved_device_reduces_risk": True,
                "known_vpn_reduces_network_risk": True,
            },
            "risk_scoring": {
                "base_score": 0,
                "points": {
                    "low_detection": 1,
                    "medium_detection": 2,
                    "high_detection": 4,
                    "critical_detection": 6,
                    "multiple_sources": 2,
                    "authentication_bypass": 6,
                    "database_error": 3,
                    "repeated_abnormal_requests": 3,
                    "unknown_process": 3,
                    "restricted_location": 3,
                    "suspicious_ip": 2,
                    "known_vpn_exception": -2,
                    "approved_device_exception": -2,
                },
                "severity_bands": {
                    "Low": {"minimum": 0, "maximum": 3},
                    "Medium": {"minimum": 4, "maximum": 7},
                    "High": {"minimum": 8, "maximum": 11},
                    "Critical": {"minimum": 12, "maximum": 999},
                },
            },
            "ioc_fields": [
                "ip_address",
                "mac_address",
                "hostname",
                "process_name",
                "username",
            ],
            "behaviour_types": [
                "Repeated Failed Logins",
                "Repeated Connection Attempts",
            ],
        }

    def test_related_events_form_one_incident(self) -> None:
        events = [
            {
                "source_event_id": "A-001",
                "event_time": "2026-08-27T10:00:00+00:00",
                "source_type": "authentication",
                "detection_type": "Repeated Failed Logins",
                "severity": "Medium",
                "username": "analyst01",
                "ip_address": "192.0.2.44",
                "mac_address": "02:42:ac:11:00:25",
                "hostname": "Analyst-Laptop",
            },
            {
                "source_event_id": "N-001",
                "event_time": "2026-08-27T10:05:00+00:00",
                "source_type": "network",
                "detection_type": "Suspicious IP Address",
                "severity": "Medium",
                "username": "analyst01",
                "ip_address": "192.0.2.44",
                "mac_address": "02:42:ac:11:00:25",
                "hostname": "Analyst-Laptop",
            },
        ]

        incidents = correlate_events(
            events,
            self.configuration,
        )

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 2)
        self.assertEqual(
            incidents[0]["source_types"],
            ["authentication", "network"],
        )

    def test_multiple_indicators_raise_severity(self) -> None:
        events = [
            {
                "source_event_id": "A-002",
                "event_time": "2026-08-27T10:00:00+00:00",
                "source_type": "authentication",
                "detection_type": "Authentication Bypass Attempt",
                "severity": "Critical",
                "username": "analyst01",
                "ip_address": "192.0.2.44",
                "mac_address": "02:42:ac:11:00:25",
                "hostname": "Analyst-Laptop",
            },
            {
                "source_event_id": "E-002",
                "event_time": "2026-08-27T10:03:00+00:00",
                "source_type": "endpoint",
                "detection_type": "Unknown Endpoint Process",
                "severity": "High",
                "username": "analyst01",
                "ip_address": "192.0.2.44",
                "mac_address": "02:42:ac:11:00:25",
                "hostname": "Analyst-Laptop",
                "process_name": "unknown_loader",
            },
        ]

        incident = correlate_events(
            events,
            self.configuration,
        )[0]

        self.assertEqual(incident["severity"], "Critical")
        self.assertGreaterEqual(incident["risk_score"], 12)

    def test_approved_device_and_vpn_reduce_risk(self) -> None:
        events = [
            {
                "source_event_id": "V-001",
                "event_time": "2026-08-27T11:00:00+00:00",
                "source_type": "authentication",
                "detection_type": "Login From New Device",
                "severity": "Medium",
                "username": "vpnuser01",
                "ip_address": "10.0.2.15",
                "mac_address": "08:00:27:cf:49:71",
                "hostname": "VPN-Laptop",
                "device_approved": True,
                "known_vpn": True,
            }
        ]

        incident = correlate_events(
            events,
            self.configuration,
        )[0]

        self.assertEqual(incident["severity"], "Low")
        self.assertIn(
            "Approved-device exception applied",
            incident["risk_reasons"],
        )
        self.assertIn(
            "Known VPN exception applied",
            incident["risk_reasons"],
        )

    def test_username_is_context_not_ioc(self) -> None:
        events = [
            {
                "source_event_id": "E-003",
                "event_time": "2026-08-27T10:00:00+00:00",
                "source_type": "endpoint",
                "detection_type": "Unknown Endpoint Process",
                "severity": "High",
                "username": "analyst01",
                "ip_address": "192.0.2.44",
                "mac_address": "02:42:ac:11:00:25",
                "hostname": "Analyst-Laptop",
                "process_name": "unknown_loader",
            }
        ]

        incident = correlate_events(
            events,
            self.configuration,
        )[0]

        ioc_types = {
            indicator["type"]
            for indicator in incident["iocs"]
        }

        self.assertNotIn("username", ioc_types)
        self.assertIn("process_name", ioc_types)
        self.assertIn("ip_address", ioc_types)

    def test_isolated_medium_event_is_reduced_to_low(self) -> None:
        events = [
            {
                "source_event_id": "N-004",
                "event_time": "2026-08-27T12:00:00+00:00",
                "source_type": "network",
                "detection_type": "Repeated Connection Attempts",
                "severity": "Medium",
                "username": "unknown01",
                "ip_address": "198.51.100.77",
                "mac_address": "02:42:ac:11:00:77",
                "hostname": "Unknown-Device",
            }
        ]

        incident = correlate_events(
            events,
            self.configuration,
        )[0]

        self.assertEqual(incident["severity"], "Low")
        self.assertIn(
            "Isolated low-value alert risk reduced",
            incident["risk_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
