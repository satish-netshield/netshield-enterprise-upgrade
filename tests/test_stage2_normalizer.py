"""Test Stage 2 security-event validation and normalisation."""

import unittest

from src.collectors.event_normalizer import normalise_event


class Stage2NormalizerTests(unittest.TestCase):
    """Verify accepted and rejected security-event formats."""

    def setUp(self) -> None:
        """Create one valid authentication event."""
        self.valid_event = {
            "event_id": "AUTH-001",
            "event_time": "2026-08-20T08:30:00+12:00",
            "source_type": "authentication",
            "event_type": "login_failure",
            "username": "analyst01",
            "ip_address": "10.0.2.15",
            "hostname": "Ubuntu-NetShield",
            "status": "failed",
        }

    def test_valid_event_is_normalised(self) -> None:
        result = normalise_event(self.valid_event)

        self.assertEqual(result["source_event_id"], "AUTH-001")
        self.assertEqual(result["source_type"], "authentication")
        self.assertEqual(result["event_type"], "login_failure")

    def test_timestamp_is_converted_to_utc(self) -> None:
        result = normalise_event(self.valid_event)

        self.assertEqual(
            result["event_time"],
            "2026-08-19T20:30:00+00:00",
        )

    def test_mac_address_is_normalised(self) -> None:
        self.valid_event["mac_address"] = "08-00-27-CF-49-71"

        result = normalise_event(self.valid_event)

        self.assertEqual(
            result["mac_address"],
            "08:00:27:cf:49:71",
        )

    def test_valid_cpu_percent_is_accepted(self) -> None:
        self.valid_event["source_type"] = "endpoint"
        self.valid_event["cpu_percent"] = 92.5

        result = normalise_event(self.valid_event)

        self.assertEqual(result["cpu_percent"], 92.5)

    def test_missing_required_field_is_rejected(self) -> None:
        del self.valid_event["event_id"]

        with self.assertRaisesRegex(
            ValueError,
            "Required field 'event_id'",
        ):
            normalise_event(self.valid_event)

    def test_invalid_timestamp_is_rejected(self) -> None:
        self.valid_event["event_time"] = "not-a-timestamp"

        with self.assertRaisesRegex(
            ValueError,
            "valid ISO 8601 timestamp",
        ):
            normalise_event(self.valid_event)

    def test_timestamp_without_timezone_is_rejected(self) -> None:
        self.valid_event["event_time"] = "2026-08-20T08:30:00"

        with self.assertRaisesRegex(
            ValueError,
            "must include a timezone",
        ):
            normalise_event(self.valid_event)

    def test_unsupported_source_type_is_rejected(self) -> None:
        self.valid_event["source_type"] = "unknown_source"

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported source_type",
        ):
            normalise_event(self.valid_event)

    def test_invalid_ip_address_is_rejected(self) -> None:
        self.valid_event["ip_address"] = "999.10.10.10"

        with self.assertRaisesRegex(
            ValueError,
            "valid IP address",
        ):
            normalise_event(self.valid_event)

    def test_invalid_mac_address_is_rejected(self) -> None:
        self.valid_event["mac_address"] = "invalid-mac"

        with self.assertRaisesRegex(
            ValueError,
            "valid MAC address",
        ):
            normalise_event(self.valid_event)

    def test_cpu_above_100_is_rejected(self) -> None:
        self.valid_event["source_type"] = "endpoint"
        self.valid_event["cpu_percent"] = 120

        with self.assertRaisesRegex(
            ValueError,
            "between 0 and 100",
        ):
            normalise_event(self.valid_event)


if __name__ == "__main__":
    unittest.main()
