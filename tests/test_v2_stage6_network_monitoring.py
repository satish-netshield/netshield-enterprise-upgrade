"""Test Phase 3A V2 Stage 6 network monitoring."""

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scripts.initialize_v2_stage6 import SCHEMA
from src.network.v2_network_monitor import (
    build_access_decisions,
    detect_network_activity,
    load_address_list,
    save_access_decisions,
    save_connection_timeline,
    save_network_alerts,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage6NetworkMonitoringTests(unittest.TestCase):
    """Test Stage 6 detections, decisions and storage."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the controlled Stage 6 configuration and events."""
        cls.configuration = load_json(
            PROJECT_ROOT / "config/v2_network_monitoring.json"
        )
        cls.automation_acl = load_json(
            PROJECT_ROOT / "config/automation_acl.json"
        )

        cls.allowlist = load_address_list(
            PROJECT_ROOT
            / cls.configuration["ip_controls"]["allowlist_path"]
        )
        cls.blocklist = load_address_list(
            PROJECT_ROOT
            / cls.configuration["ip_controls"]["blocklist_path"]
        )
        cls.vpn_addresses = load_address_list(
            PROJECT_ROOT
            / cls.configuration["ip_controls"]["vpn_allowlist_path"]
        )

        cls.inventory = [
            {
                "asset_id": "AST-001",
                "device_id": "CYOD-001",
                "hostname": "Ubuntu-NetShield",
                "assigned_user": "netshield01",
                "mac_address": "08:00:27:cf:49:71",
                "ip_address": "192.0.2.10",
                "location": "Auckland-NZ",
                "connection_type": "Virtual NAT",
                "registration_status": "registered",
                "compliance_status": "compliant",
                "risk_status": "low",
                "criticality": "high",
            },
            {
                "asset_id": "AST-002",
                "device_id": "CYOD-002",
                "hostname": "Analyst-Laptop",
                "assigned_user": "analyst01",
                "mac_address": "02:00:00:00:00:02",
                "ip_address": "192.0.2.20",
                "location": "Auckland-NZ",
                "connection_type": "Enterprise LAN",
                "registration_status": "registered",
                "compliance_status": "compliant",
                "risk_status": "low",
                "criticality": "medium",
            },
        ]

        cls.events = cls.load_controlled_events()
        cls.alerts = detect_network_activity(
            cls.events,
            cls.configuration,
            cls.inventory,
            cls.allowlist,
            cls.blocklist,
            cls.vpn_addresses,
        )
        cls.decisions = build_access_decisions(
            cls.events,
            cls.alerts,
            cls.configuration,
            cls.inventory,
            cls.allowlist,
            cls.vpn_addresses,
            cls.automation_acl,
        )

    @classmethod
    def load_controlled_events(cls) -> list[dict]:
        """Load tracked Stage 6 JSONL records as detector events."""
        events = []
        source_directory = (
            PROJECT_ROOT / cls.configuration["source_directory"]
        )

        for source_file in cls.configuration["source_files"]:
            file_path = source_directory / source_file

            for line in file_path.read_text(
                encoding="utf-8"
            ).splitlines():
                if not line.strip():
                    continue

                raw_event = json.loads(line)
                event = dict(raw_event)
                event["source_event_id"] = raw_event["event_id"]
                event["source_file"] = source_file
                event["raw"] = raw_event
                events.append(event)

        return sorted(
            events,
            key=lambda event: (
                event["event_time"],
                event["source_event_id"],
            ),
        )

    def decisions_by_event(self) -> dict[str, dict]:
        """Return decisions indexed by source event ID."""
        return {
            decision["source_event_id"]: decision
            for decision in self.decisions
        }

    def alert_types(self) -> Counter:
        """Return the number of alerts for each detection type."""
        return Counter(
            alert["detection_type"]
            for alert in self.alerts
        )

    def test_controlled_event_set_is_complete(self) -> None:
        """The tracked test set contains all expected Stage 6 events."""
        source_counts = Counter(
            event["source_type"]
            for event in self.events
        )
        event_ids = {
            event["source_event_id"]
            for event in self.events
        }

        self.assertEqual(len(self.events), 34)
        self.assertEqual(len(event_ids), 34)
        self.assertEqual(source_counts["network"], 27)
        self.assertEqual(source_counts["wifi"], 7)

    def test_expected_network_alerts_are_created(self) -> None:
        """All controlled Stage 6 detection types are represented."""
        expected_counts = {
            "Suspicious IP Address": 3,
            "Port Scanning": 1,
            "Repeated Connection Attempts": 1,
            "Abnormal Connection Pattern": 1,
            "Restricted Port or Service": 4,
            "Unknown CYOD Device": 1,
            "MAC Address Reuse or Possible Spoofing": 1,
            "WPA3 Policy Violation": 1,
            "WPA2 Downgrade Attempt": 1,
            "Rogue Access Point": 1,
            "Wi-Fi Zone Violation": 1,
            "Unknown Wired Device": 1,
            "Restricted Wired Access": 1,
        }

        self.assertEqual(len(self.alerts), 18)
        self.assertEqual(
            dict(self.alert_types()),
            expected_counts,
        )

    def test_suspicious_ip_controls_are_applied(self) -> None:
        """Blocklist, restricted-network and unapproved-IP rules work."""
        reason_codes = {
            reason
            for alert in self.alerts
            if alert["detection_type"] == "Suspicious IP Address"
            for reason in alert["reason_codes"]
        }

        self.assertEqual(
            reason_codes,
            {
                "IP_BLOCKLIST_MATCH",
                "RESTRICTED_NETWORK",
                "IP_NOT_APPROVED",
            },
        )

    def test_connection_patterns_are_detected(self) -> None:
        """Port scanning, repeated activity and abnormal volume are found."""
        alert_types = self.alert_types()

        self.assertEqual(alert_types["Port Scanning"], 1)
        self.assertEqual(
            alert_types["Repeated Connection Attempts"],
            1,
        )
        self.assertEqual(
            alert_types["Abnormal Connection Pattern"],
            1,
        )

    def test_restricted_ports_and_services_are_detected(self) -> None:
        """Restricted ports and named services create alerts."""
        alerts = [
            alert
            for alert in self.alerts
            if alert["detection_type"]
            == "Restricted Port or Service"
        ]
        reason_codes = {
            reason
            for alert in alerts
            for reason in alert["reason_codes"]
        }

        self.assertEqual(len(alerts), 4)
        self.assertIn("RESTRICTED_PORT", reason_codes)
        self.assertIn("RESTRICTED_SERVICE", reason_codes)

    def test_unknown_and_restricted_wired_devices_are_detected(
        self,
    ) -> None:
        """Unknown wired devices and restricted wired zones are separate."""
        alert_types = self.alert_types()

        self.assertEqual(alert_types["Unknown Wired Device"], 1)
        self.assertEqual(alert_types["Restricted Wired Access"], 1)

    def test_mac_reuse_uses_primary_device_identity(self) -> None:
        """A shared MAC is evidence only when primary identities differ."""
        alerts = [
            alert
            for alert in self.alerts
            if alert["detection_type"]
            == "MAC Address Reuse or Possible Spoofing"
        ]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "High")
        self.assertEqual(alerts[0]["confidence"], 85)
        self.assertIn(
            "MAC_SHARED_BY_DIFFERENT_DEVICE_IDENTITIES",
            alerts[0]["reason_codes"],
        )

    def test_wifi_security_rules_are_detected(self) -> None:
        """Controlled Wi-Fi events exercise each wireless rule."""
        alert_types = self.alert_types()

        self.assertEqual(alert_types["Unknown CYOD Device"], 1)
        self.assertEqual(alert_types["WPA3 Policy Violation"], 1)
        self.assertEqual(alert_types["WPA2 Downgrade Attempt"], 1)
        self.assertEqual(alert_types["Rogue Access Point"], 1)
        self.assertEqual(alert_types["Wi-Fi Zone Violation"], 1)

    def test_approved_exceptions_do_not_create_alerts(self) -> None:
        """Approved VPN and controlled-testing evidence are preserved."""
        exception_event_ids = {
            "S6-NET-025",
            "S6-WIFI-007",
        }
        alerted_event_ids = {
            event_id
            for alert in self.alerts
            for event_id in alert["source_event_ids"]
        }

        self.assertTrue(
            exception_event_ids.isdisjoint(alerted_event_ids)
        )

        decisions = self.decisions_by_event()

        self.assertEqual(
            decisions["S6-NET-025"]["decision"],
            "allow",
        )
        self.assertEqual(
            decisions["S6-NET-025"]["reason_codes"],
            ["APPROVED_VPN_EXCEPTION"],
        )
        self.assertEqual(
            decisions["S6-WIFI-007"]["decision"],
            "allow",
        )
        self.assertEqual(
            decisions["S6-WIFI-007"]["reason_codes"],
            ["APPROVED_TESTING_EXCEPTION"],
        )

    def test_one_decision_exists_for_every_event(self) -> None:
        """Every connection event receives one explainable decision."""
        decision_keys = {
            decision["decision_key"]
            for decision in self.decisions
        }
        decision_event_ids = {
            decision["source_event_id"]
            for decision in self.decisions
        }
        source_event_ids = {
            event["source_event_id"]
            for event in self.events
        }

        self.assertEqual(len(self.decisions), 34)
        self.assertEqual(len(decision_keys), 34)
        self.assertEqual(
            decision_event_ids,
            source_event_ids,
        )

    def test_all_four_network_decisions_are_supported(self) -> None:
        """The controlled events produce every configured outcome."""
        decision_counts = Counter(
            decision["decision"]
            for decision in self.decisions
        )

        self.assertEqual(
            decision_counts,
            {
                "allow": 4,
                "deny": 18,
                "challenge": 11,
                "restrict": 1,
            },
        )

    def test_decision_precedence_is_restrictive(self) -> None:
        """Deny wins when one event matches deny and restrict rules."""
        decisions = self.decisions_by_event()
        scan_decision = decisions["S6-NET-SCAN-003"]

        self.assertIn(
            "port_scanning",
            scan_decision["matching_rules"],
        )
        self.assertIn(
            "suspicious_ip_address",
            scan_decision["matching_rules"],
        )
        self.assertEqual(scan_decision["decision"], "deny")

    def test_acl_controls_automated_responses(self) -> None:
        """Challenge and restrict responses follow the existing ACL."""
        decisions = self.decisions_by_event()

        challenge = decisions["S6-NET-026"]
        self.assertEqual(challenge["decision"], "challenge")
        self.assertEqual(
            challenge["response_action"],
            "increase_monitoring",
        )
        self.assertEqual(
            challenge["acl_control_level"],
            "automatic",
        )
        self.assertEqual(
            challenge["response_status"],
            "simulated_automatic",
        )

        restrict = decisions["S6-WIFI-005"]
        self.assertEqual(restrict["decision"], "restrict")
        self.assertEqual(
            restrict["response_action"],
            "apply_ubuntu_firewall_rule",
        )
        self.assertEqual(
            restrict["acl_control_level"],
            "approval_required",
        )
        self.assertEqual(
            restrict["response_status"],
            "approval_required",
        )

    def test_alerts_and_decisions_are_traceable(self) -> None:
        """Stored objects retain evidence and reason information."""
        for alert in self.alerts:
            self.assertTrue(alert["alert_key"])
            self.assertTrue(alert["source_event_ids"])
            self.assertTrue(alert["reason_codes"])
            self.assertTrue(alert["evidence"])
            self.assertIn(
                alert["severity"],
                {"Low", "Medium", "High", "Critical"},
            )
            self.assertGreaterEqual(alert["confidence"], 0)
            self.assertLessEqual(alert["confidence"], 100)

        for decision in self.decisions:
            self.assertTrue(decision["decision_key"])
            self.assertTrue(decision["source_event_id"])
            self.assertTrue(decision["matching_rules"])
            self.assertTrue(decision["reason_codes"])
            self.assertTrue(decision["evidence"])

    def test_storage_is_duplicate_safe(self) -> None:
        """Repeated storage does not duplicate Stage 6 records."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = (
                Path(temporary_directory) / "stage6_test.db"
            )

            with managed_connection(database_path) as connection:
                connection.executescript(SCHEMA)

            first_timeline = save_connection_timeline(
                database_path,
                self.events,
            )
            first_alerts = save_network_alerts(
                database_path,
                self.alerts,
            )
            first_decisions = save_access_decisions(
                database_path,
                self.decisions,
            )

            second_timeline = save_connection_timeline(
                database_path,
                self.events,
            )
            second_alerts = save_network_alerts(
                database_path,
                self.alerts,
            )
            second_decisions = save_access_decisions(
                database_path,
                self.decisions,
            )

            self.assertEqual(first_timeline, (34, 0))
            self.assertEqual(first_alerts, (18, 0))
            self.assertEqual(first_decisions, (34, 0))

            self.assertEqual(second_timeline, (0, 34))
            self.assertEqual(second_alerts, (0, 18))
            self.assertEqual(second_decisions, (0, 34))

            with managed_connection(database_path) as connection:
                stored_alerts = connection.execute(
                    """
                    SELECT
                        COUNT(*),
                        COUNT(DISTINCT alert_key)
                    FROM v2_network_alerts
                    """
                ).fetchone()
                stored_decisions = connection.execute(
                    """
                    SELECT
                        COUNT(*),
                        COUNT(DISTINCT decision_key)
                    FROM v2_network_access_decisions
                    """
                ).fetchone()
                stored_timeline = connection.execute(
                    """
                    SELECT
                        COUNT(*),
                        COUNT(DISTINCT source_event_id)
                    FROM v2_network_connection_timeline
                    """
                ).fetchone()

            self.assertEqual(stored_alerts, (18, 18))
            self.assertEqual(stored_decisions, (34, 34))
            self.assertEqual(stored_timeline, (34, 34))


if __name__ == "__main__":
    unittest.main()
