"""Validate Stage 1 access-control and inventory decisions."""

import json
import unittest
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.security_controls import (
    action_control_level,
    classify_ip,
    is_cyod_device_approved,
    role_has_permission,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Stage1ControlTests(unittest.TestCase):
    """Test authorised, denied and unknown security decisions."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rbac = load_json(PROJECT_ROOT / "config/rbac.json")
        cls.acl = load_json(PROJECT_ROOT / "config/automation_acl.json")
        cls.cyod_inventory = (
            PROJECT_ROOT / "data/allowlists/cyod_devices.csv"
        )
        cls.ip_allowlist = (
            PROJECT_ROOT / "data/allowlists/ip_allowlist.txt"
        )
        cls.ip_blocklist = (
            PROJECT_ROOT / "data/blocklists/ip_blocklist.txt"
        )

    def test_administrator_has_management_permission(self) -> None:
        self.assertTrue(
            role_has_permission(
                self.rbac,
                "administrator",
                "manage_configuration",
            )
        )

    def test_viewer_is_denied_management_permission(self) -> None:
        self.assertFalse(
            role_has_permission(
                self.rbac,
                "viewer",
                "manage_configuration",
            )
        )

    def test_unknown_role_is_denied(self) -> None:
        self.assertFalse(
            role_has_permission(
                self.rbac,
                "unknown_role",
                "view_alerts",
            )
        )

    def test_automatic_action(self) -> None:
        self.assertEqual(
            action_control_level(self.acl, "create_alert"),
            "automatic",
        )

    def test_disruptive_action_requires_approval(self) -> None:
        self.assertEqual(
            action_control_level(self.acl, "terminate_process"),
            "approval_required",
        )

    def test_unknown_action_is_denied(self) -> None:
        self.assertEqual(
            action_control_level(self.acl, "undefined_action"),
            "deny",
        )

    def test_registered_cyod_device_is_approved(self) -> None:
        self.assertTrue(
            is_cyod_device_approved(
                self.cyod_inventory,
                "08:00:27:cf:49:71",
            )
        )

    def test_unknown_cyod_device_is_not_approved(self) -> None:
        self.assertFalse(
            is_cyod_device_approved(
                self.cyod_inventory,
                "AA:BB:CC:DD:EE:FF",
            )
        )

    def test_local_ip_is_allowed(self) -> None:
        self.assertEqual(
            classify_ip(
                "10.0.2.15",
                self.ip_allowlist,
                self.ip_blocklist,
            ),
            "allowed",
        )

    def test_unlisted_ip_is_unknown(self) -> None:
        self.assertEqual(
            classify_ip(
                "203.0.113.45",
                self.ip_allowlist,
                self.ip_blocklist,
            ),
            "unknown",
        )

    def test_malformed_ip_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            classify_ip(
                "not-an-ip",
                self.ip_allowlist,
                self.ip_blocklist,
            )


if __name__ == "__main__":
    unittest.main()
