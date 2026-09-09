"""Test the V2 Stage 5 local access-policy engine."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage4_5 import SCHEMA
from src.policy.v2_access_policy import (
    create_decision,
    evaluate_access_requests,
    save_access_decisions,
    select_winning_policy,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_request(
    event_id: str,
    username: str = "analyst01",
    device_id: str = "CYOD-002",
    application_id: str = "APP-001",
    asset_id: str = "AST-002",
    ip_address: str = "192.0.2.20",
    location: str = "Auckland, NZ",
    sign_in_risk: float = 20,
    user_risk: float = 15,
    mfa_satisfied: bool = True,
    **raw_fields: Any,
) -> dict[str, Any]:
    """Build one access request for a unit test."""
    raw_event = {
        "event_id": event_id,
        "schema_version": "2.0",
        "event_time": "2026-09-09T11:00:00+00:00",
        "source_type": "access_policy",
        "source_system": "simulated_v2_access_policy",
        "event_type": "access_request",
        "username": username,
        "device_id": device_id,
        "application_id": application_id,
        "asset_id": asset_id,
        "ip_address": ip_address,
        "location": location,
        "risk_score": sign_in_risk,
        "sign_in_risk": sign_in_risk,
        "user_risk": user_risk,
        "mfa_satisfied": mfa_satisfied,
    }
    raw_event.update(raw_fields)

    return {
        "source_event_id": event_id,
        "event_time": raw_event["event_time"],
        "source_system": raw_event["source_system"],
        "username": username,
        "device_id": device_id,
        "application_id": application_id,
        "asset_id": asset_id,
        "ip_address": ip_address,
        "location": location,
        "risk_score": sign_in_risk,
        "raw": raw_event,
    }


class V2Stage5AccessPolicyTests(unittest.TestCase):
    """Verify Stage 5 policy decisions and audit context."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.policy_config = load_json(
            PROJECT_ROOT / "config/v2_access_policy.json"
        )
        cls.rbac_config = load_json(
            PROJECT_ROOT / "config/rbac.json"
        )
        cls.automation_acl = load_json(
            PROJECT_ROOT / "config/automation_acl.json"
        )
        cls.enterprise_context = load_json(
            PROJECT_ROOT / "config/enterprise_context.json"
        )

        cls.user_roles = {
            "viewer01": {
                "role": "viewer",
                "active": True,
            },
            "analyst01": {
                "role": "analyst",
                "active": True,
            },
            "responder01": {
                "role": "responder",
                "active": True,
            },
            "admin01": {
                "role": "administrator",
                "active": True,
            },
        }
        cls.devices = {
            "CYOD-001": {
                "asset_id": "AST-001",
                "device_id": "CYOD-001",
                "hostname": "Ubuntu-NetShield",
                "assigned_user": "netshield01",
                "registration_status": "registered",
                "compliance_status": "compliant",
                "risk_status": "low",
                "criticality": "high",
                "last_seen": "2026-09-09T08:00:00+00:00",
            },
            "CYOD-002": {
                "asset_id": "AST-002",
                "device_id": "CYOD-002",
                "hostname": "Analyst-Laptop",
                "assigned_user": "analyst01",
                "registration_status": "registered",
                "compliance_status": "compliant",
                "risk_status": "low",
                "criticality": "medium",
                "last_seen": "2026-09-09T08:00:00+00:00",
            },
        }

    def evaluate(
        self,
        request: dict[str, Any],
        restricted_users: set[str] | None = None,
        vpn_addresses: set[str] | None = None,
    ) -> dict[str, Any]:
        """Evaluate one request with standard test evidence."""
        return create_decision(
            request=request,
            policy_config=self.policy_config,
            rbac_config=self.rbac_config,
            automation_acl=self.automation_acl,
            enterprise_context=self.enterprise_context,
            role_record=self.user_roles.get(
                request.get("username")
            ),
            device=self.devices.get(
                request.get("device_id")
            ),
            restricted_users=restricted_users or set(),
            vpn_addresses=vpn_addresses or set(),
        )

    def test_verified_access_is_allowed(self) -> None:
        decision = self.evaluate(
            build_request("TEST-POLICY-001")
        )

        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-011",
        )
        self.assertEqual(
            decision["reason_codes"],
            ["ACCESS_REQUIREMENTS_SATISFIED"],
        )

    def test_missing_role_permission_is_denied(self) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-002",
                username="viewer01",
                device_id="CYOD-001",
                asset_id="AST-001",
                ip_address="192.0.2.10",
            )
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-003",
        )
        self.assertIn(
            "ROLE_PERMISSION_MISSING",
            decision["reason_codes"],
        )

    def test_unregistered_device_is_challenged(self) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-003",
                device_id="CYOD-003",
                asset_id="AST-003",
                ip_address="203.0.113.80",
            )
        )

        self.assertEqual(decision["decision"], "challenge")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-007",
        )
        self.assertIn(
            "DEVICE_NOT_REGISTERED",
            decision["reason_codes"],
        )
        self.assertIn(
            "DEVICE_NOT_COMPLIANT",
            decision["reason_codes"],
        )

    def test_critical_identity_risk_is_restricted(
        self,
    ) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-004",
                username="responder01",
                device_id="CYOD-001",
                asset_id="AST-001",
                ip_address="192.0.2.10",
                sign_in_risk=92,
                user_risk=88,
            )
        )

        self.assertEqual(decision["decision"], "restrict")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-006",
        )
        self.assertEqual(
            decision["response_action"],
            "restrict_account",
        )
        self.assertEqual(
            decision["acl_control_level"],
            "approval_required",
        )
        self.assertEqual(
            decision["response_status"],
            "approval_required",
        )

    def test_restricted_network_is_denied(self) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-005",
                username="admin01",
                device_id="CYOD-001",
                asset_id="AST-001",
                ip_address="198.51.100.25",
            )
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-005",
        )
        self.assertIn(
            "RESTRICTED_NETWORK",
            decision["reason_codes"],
        )

    def test_missing_mfa_is_challenged(self) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-006",
                mfa_satisfied=False,
            )
        )

        self.assertEqual(decision["decision"], "challenge")
        self.assertIn(
            "MFA_REQUIRED",
            decision["reason_codes"],
        )
        self.assertEqual(
            decision["response_action"],
            "increase_monitoring",
        )
        self.assertEqual(
            decision["acl_control_level"],
            "automatic",
        )
        self.assertEqual(
            decision["response_status"],
            "simulated_automatic",
        )

    def test_restricted_location_is_denied(self) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-007",
                username="admin01",
                device_id="CYOD-001",
                asset_id="AST-001",
                ip_address="192.0.2.10",
                location="Restricted Test Location",
            )
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-004",
        )

    def test_vpn_exception_bypasses_network_restriction(
        self,
    ) -> None:
        request = build_request(
            "TEST-POLICY-008",
            ip_address="198.51.100.25",
            location="Restricted Test Location",
        )

        decision = self.evaluate(
            request,
            vpn_addresses={"198.51.100.25"},
        )

        self.assertEqual(decision["decision"], "allow")
        self.assertTrue(
            decision["risk_evidence"]["vpn_exception"]
        )
        self.assertNotIn(
            "RESTRICTED_NETWORK",
            decision["reason_codes"],
        )
        self.assertNotIn(
            "RESTRICTED_LOCATION",
            decision["reason_codes"],
        )

    def test_temporary_restriction_has_highest_priority(
        self,
    ) -> None:
        request = build_request(
            "TEST-POLICY-009",
            username="responder01",
            device_id="CYOD-001",
            application_id="APP-002",
            asset_id="AST-001",
            ip_address="198.51.100.25",
            sign_in_risk=92,
            user_risk=88,
        )

        decision = self.evaluate(
            request,
            restricted_users={"responder01"},
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(
            decision["winning_policy_id"],
            "POL-001",
        )
        self.assertIn(
            "TEMPORARY_ACCESS_RESTRICTION",
            decision["reason_codes"],
        )
        self.assertIn(
            "CRITICAL_IDENTITY_RISK",
            decision["reason_codes"],
        )
        self.assertIn(
            "RESTRICTED_NETWORK",
            decision["reason_codes"],
        )

    def test_unknown_application_follows_default_deny(
        self,
    ) -> None:
        decision = self.evaluate(
            build_request(
                "TEST-POLICY-010",
                application_id="APP-UNKNOWN",
            )
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertIn(
            "ROLE_PERMISSION_MISSING",
            decision["reason_codes"],
        )

    def test_same_priority_uses_restrictive_precedence(
        self,
    ) -> None:
        policies = [
            {
                "policy_id": "TEST-ALLOW",
                "priority": 10,
                "decision": "allow",
            },
            {
                "policy_id": "TEST-DENY",
                "priority": 10,
                "decision": "deny",
            },
        ]

        winner = select_winning_policy(
            policies,
            self.policy_config,
        )

        self.assertIsNotNone(winner)
        self.assertEqual(
            winner["policy_id"],
            "TEST-DENY",
        )

    def test_all_four_decision_outcomes_are_supported(
        self,
    ) -> None:
        requests = [
            build_request("TEST-OUTCOME-ALLOW"),
            build_request(
                "TEST-OUTCOME-DENY",
                username="viewer01",
                device_id="CYOD-001",
                asset_id="AST-001",
                ip_address="192.0.2.10",
            ),
            build_request(
                "TEST-OUTCOME-CHALLENGE",
                device_id="CYOD-003",
                asset_id="AST-003",
            ),
            build_request(
                "TEST-OUTCOME-RESTRICT",
                username="responder01",
                device_id="CYOD-001",
                asset_id="AST-001",
                sign_in_risk=92,
                user_risk=88,
            ),
        ]

        decisions = evaluate_access_requests(
            requests=requests,
            policy_config=self.policy_config,
            rbac_config=self.rbac_config,
            automation_acl=self.automation_acl,
            enterprise_context=self.enterprise_context,
            user_roles=self.user_roles,
            devices=self.devices,
            restricted_users=set(),
            vpn_addresses=set(),
        )

        self.assertEqual(
            {
                decision["decision"]
                for decision in decisions
            },
            {
                "allow",
                "deny",
                "challenge",
                "restrict",
            },
        )

    def test_decision_storage_is_duplicate_safe(self) -> None:
        decision = self.evaluate(
            build_request("TEST-POLICY-DUPLICATE")
        )

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            with managed_connection(database_path) as connection:
                connection.executescript(SCHEMA)

            first_created, first_existing = (
                save_access_decisions(
                    database_path,
                    [decision],
                )
            )
            second_created, second_existing = (
                save_access_decisions(
                    database_path,
                    [decision],
                )
            )

        self.assertEqual(first_created, 1)
        self.assertEqual(first_existing, 0)
        self.assertEqual(second_created, 0)
        self.assertEqual(second_existing, 1)


if __name__ == "__main__":
    unittest.main()
