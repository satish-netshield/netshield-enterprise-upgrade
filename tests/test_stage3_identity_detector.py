import unittest

from src.detectors.identity_detector import (
    detect_baseline_anomalies,
    detect_failure_activity,
    detect_identity_activity,
    detect_impossible_travel,
    detect_mfa_anomalies,
    detect_role_changes,
    distance_km,
    find_window,
)


THRESHOLDS = {
    "repeated_failures": 3,
    "brute_force_failures": 5,
    "failure_window_minutes": 5,
    "success_after_failures": 3,
    "mfa_failures": 3,
    "mfa_window_minutes": 5,
    "impossible_travel_speed_kmh": 900,
}


BASELINES = {
    "analyst01": {
        "approved_devices": ["Analyst-Laptop"],
        "usual_locations": ["Auckland, NZ"],
        "expected_role": "analyst",
    },
    "vpnuser01": {
        "approved_devices": ["VPN-Laptop"],
        "usual_locations": ["Auckland, NZ"],
        "expected_role": "analyst",
    },
    "trainee01": {
        "approved_devices": ["Trainee-Laptop"],
        "usual_locations": ["Auckland, NZ"],
        "expected_role": "viewer",
    },
}


LOCATIONS = {
    "Auckland, NZ": {
        "latitude": -36.8509,
        "longitude": 174.7645,
    },
    "Sydney, Australia": {
        "latitude": -33.8688,
        "longitude": 151.2093,
    },
}


def event(
    event_id,
    event_time,
    event_type,
    username="analyst01",
    ip_address="198.51.100.45",
    hostname="Analyst-Laptop",
    location="Auckland, NZ",
    raw=None,
):
    return {
        "source_event_id": event_id,
        "event_time": event_time,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
        "hostname": hostname,
        "location": location,
        "raw": raw or {},
    }


class Stage3IdentityDetectorTests(unittest.TestCase):
    def test_find_window_reaches_threshold(self):
        events = [
            event("E1", "2026-08-19T08:00:00+00:00", "login_failure"),
            event("E2", "2026-08-19T08:01:00+00:00", "login_failure"),
            event("E3", "2026-08-19T08:02:00+00:00", "login_failure"),
        ]

        result = find_window(events, threshold=3, minutes=5)

        self.assertEqual(len(result), 3)

    def test_find_window_returns_empty_below_threshold(self):
        events = [
            event("E1", "2026-08-19T08:00:00+00:00", "login_failure"),
            event("E2", "2026-08-19T08:01:00+00:00", "login_failure"),
        ]

        result = find_window(events, threshold=3, minutes=5)

        self.assertEqual(result, [])

    def test_distance_between_different_locations_is_positive(self):
        result = distance_km(LOCATIONS["Auckland, NZ"], LOCATIONS["Sydney, Australia"])

        self.assertGreater(result, 0)

    def test_repeated_and_brute_force_alerts_are_created(self):
        events = [
            event(
                f"E{i}",
                f"2026-08-19T08:0{i}:00+00:00",
                "login_failure",
            )
            for i in range(1, 6)
        ]

        alerts = detect_failure_activity(events, THRESHOLDS)
        detection_types = {alert["detection_type"] for alert in alerts}

        self.assertIn("Repeated Failed Logins", detection_types)
        self.assertIn("Possible Brute Force", detection_types)

    def test_success_after_failures_is_detected(self):
        events = [
            event("E1", "2026-08-19T08:00:00+00:00", "login_failure"),
            event("E2", "2026-08-19T08:01:00+00:00", "login_failure"),
            event("E3", "2026-08-19T08:02:00+00:00", "login_failure"),
            event("E4", "2026-08-19T08:03:00+00:00", "login_success"),
        ]

        alerts = detect_failure_activity(events, THRESHOLDS)
        detection_types = {alert["detection_type"] for alert in alerts}

        self.assertIn("Successful Login After Failures", detection_types)

    def test_mfa_failure_anomaly_is_detected(self):
        events = [
            event(
                f"M{i}",
                f"2026-08-19T09:0{i}:00+00:00",
                "mfa_failure",
            )
            for i in range(1, 4)
        ]

        alerts = detect_mfa_anomalies(events, THRESHOLDS)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "MFA Failure Anomaly",
        )

    def test_new_device_and_unusual_location_are_detected(self):
        events = [
            event(
                "D1",
                "2026-08-19T10:00:00+00:00",
                "login_success",
                hostname="Replacement-Laptop",
                location="Sydney, Australia",
            )
        ]

        alerts, exceptions = detect_baseline_anomalies(
            events,
            BASELINES,
            set(),
        )
        detection_types = {alert["detection_type"] for alert in alerts}

        self.assertEqual(exceptions, 0)
        self.assertIn("Login From New Device", detection_types)
        self.assertIn("Login From Unusual Location", detection_types)

    def test_known_vpn_address_creates_exception(self):
        events = [
            event(
                "V1",
                "2026-08-19T10:00:00+00:00",
                "login_success",
                ip_address="203.0.113.10",
                hostname="Unknown-Laptop",
                location="Sydney, Australia",
            )
        ]

        alerts, exceptions = detect_baseline_anomalies(
            events,
            BASELINES,
            {"203.0.113.10"},
        )

        self.assertEqual(alerts, [])
        self.assertEqual(exceptions, 1)

    def test_impossible_travel_is_detected(self):
        events = [
            event(
                "T1",
                "2026-08-19T08:00:00+00:00",
                "login_success",
                location="Auckland, NZ",
            ),
            event(
                "T2",
                "2026-08-19T09:00:00+00:00",
                "login_success",
                location="Sydney, Australia",
            ),
        ]

        alerts, exceptions = detect_impossible_travel(
            events,
            LOCATIONS,
            set(),
            maximum_speed=900,
        )

        self.assertEqual(exceptions, 0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Impossible Travel",
        )

    def test_suspicious_role_change_is_detected(self):
        events = [
            event(
                "R1",
                "2026-08-19T11:00:00+00:00",
                "role_change",
                username="trainee01",
                hostname="Trainee-Laptop",
                raw={
                    "previous_role": "viewer",
                    "new_role": "administrator",
                    "changed_by": "trainee01",
                },
            )
        ]

        alerts = detect_role_changes(events, BASELINES)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["detection_type"],
            "Suspicious Role Change",
        )
        self.assertEqual(alerts[0]["severity"], "Critical")

    def test_combined_identity_activity_returns_alerts_and_exceptions(self):
        events = [
            event("F1", "2026-08-19T08:00:00+00:00", "login_failure"),
            event("F2", "2026-08-19T08:01:00+00:00", "login_failure"),
            event("F3", "2026-08-19T08:02:00+00:00", "login_failure"),
            event("S1", "2026-08-19T08:03:00+00:00", "login_success"),
            event(
                "V1",
                "2026-08-19T08:04:00+00:00",
                "login_success",
                username="vpnuser01",
                ip_address="203.0.113.10",
                hostname="VPN-Laptop",
                location="London, UK",
            ),
        ]

        configuration = {
            "thresholds": THRESHOLDS,
            "user_baselines": BASELINES,
            "locations": LOCATIONS,
        }

        alerts, exceptions = detect_identity_activity(
            events,
            configuration,
            {"203.0.113.10"},
        )
        detection_types = {alert["detection_type"] for alert in alerts}

        self.assertGreaterEqual(len(alerts), 2)
        self.assertIn("Repeated Failed Logins", detection_types)
        self.assertIn(
            "Successful Login After Failures",
            detection_types,
        )
        self.assertEqual(exceptions, 1)


if __name__ == "__main__":
    unittest.main()
