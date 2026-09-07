"""Validate the Phase 3A V2 enterprise foundation."""

import unittest
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.data_protection import apply_configured_masking


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage1FoundationTests(unittest.TestCase):
    """Test enterprise context, protection and compatibility."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = load_json(
            PROJECT_ROOT / "config/settings.json"
        )
        cls.context = load_json(
            PROJECT_ROOT / "config/enterprise_context.json"
        )
        cls.rbac = load_json(PROJECT_ROOT / "config/rbac.json")

    def test_upgrade_extends_phase3(self) -> None:
        upgrade = self.settings["upgrade"]
        self.assertEqual(upgrade["phase"], "3A V2")
        self.assertEqual(upgrade["extends"], "NetShield Automation")

    def test_all_enterprise_entities_are_simulated(self) -> None:
        self.assertTrue(self.context["simulation_only"])
        for category in ("users", "devices", "applications", "services"):
            self.assertGreater(len(self.context[category]), 0)

    def test_simulated_user_roles_exist_in_rbac(self) -> None:
        valid_roles = self.rbac["roles"]
        for user in self.context["users"]:
            self.assertIn(user["role"], valid_roles)

    def test_retention_periods_are_positive(self) -> None:
        periods = self.settings["data_protection"]["retention_days"]
        self.assertTrue(all(days > 0 for days in periods.values()))

    def test_nested_sensitive_fields_are_masked(self) -> None:
        event = {
            "username": "analyst01",
            "password": "test-password",
            "session": {
                "session_id": "session-123",
                "status": "active",
            },
        }

        protected = apply_configured_masking(event, self.settings)

        self.assertEqual(protected["password"], "[REDACTED]")
        self.assertEqual(
            protected["session"]["session_id"],
            "[REDACTED]",
        )
        self.assertEqual(protected["username"], "analyst01")
        self.assertEqual(protected["session"]["status"], "active")


    def test_registered_devices_exist_in_cyod_inventory(self) -> None:
        import csv

        inventory_path = (
            PROJECT_ROOT / "data/allowlists/cyod_devices.csv"
        )
        with inventory_path.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as csv_file:
            approved_ids = {
                row["device_id"]
                for row in csv.DictReader(csv_file)
                if row["approval_status"] == "approved"
            }

        registered_ids = {
            device["device_id"]
            for device in self.context["devices"]
            if device["registration_status"] == "registered"
        }

        self.assertTrue(registered_ids.issubset(approved_ids))



if __name__ == "__main__":
    unittest.main()
