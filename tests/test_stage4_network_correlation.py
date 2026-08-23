import unittest

from src.detectors.network_correlation import (
    aggregate_device_alerts,
    correlate_network_alerts,
    detect_mac_reuse,
)


CONFIGURATION = {
    "thresholds": {
        "mac_reuse_overlap_minutes": 2,
    },
    "severity": {
        "MAC Address Reuse or Possible Spoofing": "High",
    },
}


def alert(
    detection_type,
    severity,
    event_ids,
    mac_address="02:42:ac:11:00:99",
):
    return {
        "alert_key": f"{detection_type}-{','.join(event_ids)}",
        "detection_type": detection_type,
        "severity": severity,
        "first_event_time": "2026-08-23T09:00:00+00:00",
        "last_event_time": "2026-08-23T09:01:00+00:00",
        "source_event_ids": event_ids,
        "source_types": ["network"],
        "ip_address": "192.0.2.50",
        "mac_address": mac_address,
        "hostname": "Unknown-CYOD",
        "username": None,
        "location": "Lab Zone B",
        "evidence": {
            "test": True,
        },
    }


def event(
    event_id,
    event_time,
    hostname,
    location,
    ip_address,
    mac_address="08:00:27:cf:49:71",
):
    return {
        "source_event_id": event_id,
        "event_time": event_time,
        "source_type": "wifi",
        "event_type": "device_observed",
        "hostname": hostname,
        "location": location,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "username": "unknown-user",
        "raw": {},
    }


class Stage4NetworkCorrelationTests(unittest.TestCase):
    def test_related_device_alerts_are_grouped_by_mac(self):
        alerts = [
            alert(
                "Unregistered MAC Address",
                "High",
                ["E1"],
            ),
            alert(
                "Suspicious IP Address",
                "Medium",
                ["E1"],
            ),
            alert(
                "Wi-Fi Zone Violation",
                "Medium",
                ["E1"],
            ),
        ]

        result = aggregate_device_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["detection_type"],
            "MAC Device Investigation",
        )
        self.assertEqual(result[0]["severity"], "High")
        self.assertEqual(
            result[0]["mac_address"],
            "02:42:ac:11:00:99",
        )

    def test_mac_reuse_is_detected_for_conflicting_identities(self):
        events = [
            event(
                "E1",
                "2026-08-23T09:00:00+00:00",
                "Ubuntu-NetShield",
                "Lab Zone A",
                "10.0.2.15",
            ),
            event(
                "E2",
                "2026-08-23T09:01:00+00:00",
                "Copied-MAC-Laptop",
                "Lab Zone B",
                "192.0.2.50",
            ),
        ]

        alerts = detect_mac_reuse(events, CONFIGURATION)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "MAC Address Reuse or Possible Spoofing",
        )
        self.assertEqual(alerts[0]["severity"], "High")

    def test_mac_reuse_is_not_created_for_one_consistent_device(self):
        events = [
            event(
                "E1",
                "2026-08-23T09:00:00+00:00",
                "Ubuntu-NetShield",
                "Lab Zone A",
                "10.0.2.15",
            ),
            event(
                "E2",
                "2026-08-23T09:01:00+00:00",
                "Ubuntu-NetShield",
                "Lab Zone A",
                "10.0.2.15",
            ),
        ]

        alerts = detect_mac_reuse(events, CONFIGURATION)

        self.assertEqual(alerts, [])

    def test_mac_reuse_requires_time_overlap(self):
        events = [
            event(
                "E1",
                "2026-08-23T09:00:00+00:00",
                "Ubuntu-NetShield",
                "Lab Zone A",
                "10.0.2.15",
            ),
            event(
                "E2",
                "2026-08-23T09:10:00+00:00",
                "Copied-MAC-Laptop",
                "Lab Zone B",
                "192.0.2.50",
            ),
        ]

        alerts = detect_mac_reuse(events, CONFIGURATION)

        self.assertEqual(alerts, [])

    def test_correlator_preserves_high_impact_alerts(self):
        alerts = [
            alert(
                "Port Scanning",
                "High",
                ["P1", "P2"],
                mac_address="02:42:ac:11:00:25",
            ),
            alert(
                "Unregistered MAC Address",
                "High",
                ["P1"],
                mac_address="02:42:ac:11:00:25",
            ),
        ]

        events = [
            event(
                "P1",
                "2026-08-23T09:00:00+00:00",
                "Test-Scanner",
                "Lab Zone A",
                "198.51.100.25",
                mac_address="02:42:ac:11:00:25",
            ),
            event(
                "P2",
                "2026-08-23T09:01:00+00:00",
                "Test-Scanner",
                "Lab Zone A",
                "198.51.100.25",
                mac_address="02:42:ac:11:00:25",
            ),
        ]

        result = correlate_network_alerts(
            alerts,
            events,
            CONFIGURATION,
        )
        detection_types = {
            item["detection_type"]
            for item in result
        }

        self.assertIn("Port Scanning", detection_types)
        self.assertIn(
            "MAC Device Investigation",
            detection_types,
        )


if __name__ == "__main__":
    unittest.main()
