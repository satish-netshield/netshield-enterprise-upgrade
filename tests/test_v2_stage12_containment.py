"""Tests for Phase 3A V2 Stage 12 containment and response."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.initialize_v2_stage12 import SCHEMA_SQL
from src.response.v2_containment_response import (
    decide_action,
    execute_action,
    request_action,
    rollback_action,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


FOUNDATION_SQL = """
CREATE TABLE user_roles (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
        CHECK (active IN (0, 1))
);

CREATE TABLE audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    details TEXT
);

CREATE TABLE v2_incidents (
    managed_incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL UNIQUE,
    source_incident_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    detection_sources TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    risk_score REAL,
    risk_record_key TEXT,
    risk_assessed_at TEXT,
    identity_context TEXT NOT NULL,
    device_context TEXT NOT NULL,
    asset_context TEXT NOT NULL,
    network_context TEXT NOT NULL,
    incident_owner TEXT,
    status TEXT NOT NULL,
    investigation_notes TEXT NOT NULL,
    analyst_decisions TEXT NOT NULL,
    closure_reason TEXT,
    false_positive_classification TEXT,
    source_first_evidence_time TEXT NOT NULL,
    source_last_evidence_time TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE v2_incident_evidence (
    incident_evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_link_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_evidence_key TEXT NOT NULL,
    evidence_time TEXT NOT NULL,
    relationship TEXT NOT NULL,
    contribution_status TEXT NOT NULL,
    evidence_reference TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, source_evidence_key)
);
"""


class V2Stage12ContainmentTests(unittest.TestCase):
    """Validate evidence-backed and approval-controlled containment."""

    def setUp(self) -> None:
        """Create an isolated Stage 12 database for each test."""
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temporary_directory.name) / "stage12.db"
        )
        self.configuration = load_json(
            ROOT / "config/v2_containment_response.json"
        )
        self.automation_acl = load_json(
            ROOT / "config/automation_acl.json"
        )
        self.rbac = load_json(ROOT / "config/rbac.json")

        with managed_connection(self.database_path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(FOUNDATION_SQL)
            connection.executescript(SCHEMA_SQL)
            connection.executemany(
                """
                INSERT INTO user_roles(username, role, active)
                VALUES (?, ?, 1)
                """,
                (
                    ("viewer01", "viewer"),
                    ("analyst01", "analyst"),
                    ("responder01", "responder"),
                    ("admin01", "administrator"),
                    ("netshield01", "administrator"),
                ),
            )
            connection.execute(
                """
                INSERT INTO v2_incidents (
                    incident_id,
                    source_incident_key,
                    title,
                    detection_sources,
                    severity,
                    confidence,
                    risk_score,
                    identity_context,
                    device_context,
                    asset_context,
                    network_context,
                    incident_owner,
                    status,
                    investigation_notes,
                    analyst_decisions,
                    source_first_evidence_time,
                    source_last_evidence_time,
                    created_at,
                    updated_at,
                    original_evidence_preserved
                )
                VALUES (
                    'INC-V2-12-TEST',
                    'test-source-incident',
                    'Stage 12 containment test incident',
                    '["identity","endpoint"]',
                    'High',
                    90,
                    75.0,
                    '{"usernames":["responder01"]}',
                    '{"device_ids":["CYOD-001"]}',
                    '{"asset_ids":["AST-001"]}',
                    '{"ip_addresses":["192.0.2.10"]}',
                    'analyst01',
                    'Investigating',
                    '[]',
                    '[]',
                    '2026-09-20T08:00:00+00:00',
                    '2026-09-20T08:05:00+00:00',
                    '2026-09-20T08:10:00+00:00',
                    '2026-09-20T08:10:00+00:00',
                    1
                )
                """
            )
            evidence_json = json.dumps(
                {
                    "detection": "Risky Sign-In Behaviour",
                    "username": "responder01",
                    "ip_address": "192.0.2.10",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            evidence_hash = hashlib.sha256(
                evidence_json.encode("utf-8")
            ).hexdigest()
            connection.execute(
                """
                INSERT INTO v2_incident_evidence (
                    evidence_link_key,
                    incident_id,
                    source_type,
                    source_record_id,
                    source_evidence_key,
                    evidence_time,
                    relationship,
                    contribution_status,
                    evidence_reference,
                    evidence_json,
                    evidence_sha256,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "test-evidence-link-001",
                    "INC-V2-12-TEST",
                    "identity",
                    "test-record-001",
                    "identity:test-record-001",
                    "2026-09-20T08:05:00+00:00",
                    "shared_context",
                    "active",
                    "v2_incident_evidence:test-record-001",
                    evidence_json,
                    evidence_hash,
                    "2026-09-20T08:10:00+00:00",
                ),
            )

    def tearDown(self) -> None:
        """Remove the isolated database."""
        self.temporary_directory.cleanup()

    def request(
        self,
        action_type: str,
        target_type: str,
        target_value: str,
        request_id: str,
        actor: str = "responder01",
        references: list[str] | None = None,
    ) -> dict[str, object]:
        """Create one test containment request."""
        return request_action(
            self.database_path,
            self.configuration,
            self.automation_acl,
            self.rbac,
            incident_id="INC-V2-12-TEST",
            action_type=action_type,
            target_type=target_type,
            target_value=target_value,
            requested_by=actor,
            request_reason="Evidence-backed Stage 12 unit test.",
            evidence_references=(
                references
                if references is not None
                else ["identity:test-record-001"]
            ),
            request_id=request_id,
        )

    def approve(self, action_id: int) -> dict[str, object]:
        """Approve one request as a separate administrator."""
        return decide_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=action_id,
            decided_by="admin01",
            decision="approved",
            notes="Approved from preserved evidence.",
        )

    def fetchone(
        self,
        query: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Row:
        """Return one row from the test database."""
        with managed_connection(self.database_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(query, parameters).fetchone()
        self.assertIsNotNone(row)
        return row

    def test_configuration_and_acl_cover_ten_actions(self) -> None:
        """All configured actions match the established default-deny ACL."""
        actions = self.configuration["actions"]
        self.assertEqual(len(actions), 10)
        self.assertEqual(self.configuration["default_action"], "deny")
        for action, policy in actions.items():
            self.assertIn(
                action,
                self.automation_acl[policy["control_level"]],
            )
        self.assertFalse(self.configuration["allow_real_actions"])
        self.assertFalse(self.configuration["allow_external_targets"])

    def test_automatic_action_preserves_evidence_first(self) -> None:
        """An automatic simulated action succeeds with preserved evidence."""
        result = self.request(
            "add_to_simulated_blocklist",
            "ip_address",
            "192.0.2.10",
            "automatic-001",
        )
        self.assertEqual(result["status"], "successful")
        self.assertTrue(result["evidence_preserved"])
        self.assertFalse(result["real_action_executed"])
        evidence = self.fetchone(
            """
            SELECT preserved_before_action, captured_at
            FROM v2_containment_evidence
            WHERE containment_action_id = ?
            """,
            (result["containment_action_id"],),
        )
        action = self.fetchone(
            """
            SELECT executed_at
            FROM v2_containment_actions
            WHERE containment_action_id = ?
            """,
            (result["containment_action_id"],),
        )
        self.assertEqual(evidence["preserved_before_action"], 1)
        self.assertLessEqual(evidence["captured_at"], action["executed_at"])

    def test_all_disruptive_actions_wait_for_approval(self) -> None:
        """Every configured disruptive action stops before execution."""
        targets = {
            "restrict_account": ("username", "responder01"),
            "revoke_session": ("session_id", "SESSION-001"),
            "quarantine_device": ("device_id", "CYOD-001"),
            "isolate_endpoint": ("endpoint_id", "CYOD-001"),
            "terminate_process": ("process_name", "test-process"),
            "suspend_process": ("process_name", "test-process"),
            "quarantine_file": ("file_hash", "a" * 64),
            "reject_non_compliant_connection": (
                "connection_id",
                "CONNECTION-001",
            ),
        }
        for number, (action, target) in enumerate(
            targets.items(),
            start=1,
        ):
            with self.subTest(action=action):
                result = self.request(
                    action,
                    target[0],
                    target[1],
                    f"approval-{number}",
                )
                self.assertEqual(result["status"], "approval_required")
                self.assertIsNone(result["executed_by"])
                self.assertFalse(result["real_action_executed"])

    def test_undefined_action_is_denied_and_audited(self) -> None:
        """An action outside the ACL fails closed and enters the audit trail."""
        with self.assertRaises(PermissionError):
            self.request(
                "delete_enterprise_account",
                "username",
                "responder01",
                "undefined-001",
            )
        audit = self.fetchone(
            """
            SELECT result, details
            FROM audit_events
            WHERE action = 'request_v2_stage12_containment'
            ORDER BY event_id DESC
            LIMIT 1
            """
        )
        self.assertEqual(audit["result"], "denied")
        self.assertIn("default_action=deny", audit["details"])

    def test_unauthorised_role_cannot_request_containment(self) -> None:
        """A viewer cannot request a defined containment action."""
        with self.assertRaises(PermissionError):
            self.request(
                "restrict_account",
                "username",
                "responder01",
                "viewer-001",
                actor="viewer01",
            )

    def test_wrong_target_type_is_rejected(self) -> None:
        """The target type must match the action configuration."""
        with self.assertRaises(ValueError):
            self.request(
                "restrict_account",
                "device_id",
                "CYOD-001",
                "wrong-target-001",
            )

    def test_missing_or_unrelated_evidence_is_rejected(self) -> None:
        """A request requires evidence owned by the named incident."""
        with self.assertRaises(ValueError):
            self.request(
                "restrict_account",
                "username",
                "responder01",
                "missing-evidence-001",
                references=[],
            )
        with self.assertRaises(ValueError):
            self.request(
                "restrict_account",
                "username",
                "responder01",
                "unrelated-evidence-001",
                references=["identity:not-owned"],
            )

    def test_duplicate_request_is_idempotent(self) -> None:
        """Repeating one request ID does not duplicate action or evidence."""
        first = self.request(
            "restrict_account",
            "username",
            "responder01",
            "duplicate-001",
        )
        second = self.request(
            "restrict_account",
            "username",
            "responder01",
            "duplicate-001",
        )
        self.assertTrue(first["new"])
        self.assertFalse(second["new"])
        self.assertEqual(
            first["containment_action_id"],
            second["containment_action_id"],
        )
        counts = self.fetchone(
            """
            SELECT
                (SELECT COUNT(*) FROM v2_containment_actions) AS actions,
                (SELECT COUNT(*) FROM v2_containment_evidence) AS evidence,
                (SELECT COUNT(*) FROM v2_containment_approvals) AS approvals
            """
        )
        self.assertEqual(tuple(counts), (1, 1, 1))

    def test_repeated_evidence_reference_is_stored_once(self) -> None:
        """Repeated evidence cannot inflate a containment snapshot."""
        result = self.request(
            "restrict_account",
            "username",
            "responder01",
            "repeat-evidence-001",
            references=[
                "identity:test-record-001",
                "identity:test-record-001",
            ],
        )
        evidence = self.fetchone(
            """
            SELECT evidence_references, evidence_payload
            FROM v2_containment_evidence
            WHERE containment_action_id = ?
            """,
            (result["containment_action_id"],),
        )
        self.assertEqual(
            json.loads(evidence["evidence_references"]),
            ["identity:test-record-001"],
        )
        self.assertEqual(
            len(json.loads(evidence["evidence_payload"])["evidence"]),
            1,
        )

    def test_evidence_snapshot_hash_verifies(self) -> None:
        """The saved SHA-256 digest matches the preserved snapshot."""
        result = self.request(
            "increase_monitoring",
            "incident_id",
            "INC-V2-12-TEST",
            "hash-001",
        )
        evidence = self.fetchone(
            """
            SELECT evidence_payload, evidence_sha256
            FROM v2_containment_evidence
            WHERE containment_action_id = ?
            """,
            (result["containment_action_id"],),
        )
        calculated = hashlib.sha256(
            evidence["evidence_payload"].encode("utf-8")
        ).hexdigest()
        self.assertEqual(calculated, evidence["evidence_sha256"])
        self.assertEqual(
            calculated,
            result["evidence_snapshot_sha256"],
        )

    def test_requester_cannot_self_approve(self) -> None:
        """A requester cannot approve their own disruptive action."""
        result = self.request(
            "restrict_account",
            "username",
            "responder01",
            "self-approval-001",
        )
        with self.assertRaises(PermissionError):
            decide_action(
                self.database_path,
                self.configuration,
                self.rbac,
                containment_action_id=result["containment_action_id"],
                decided_by="responder01",
                decision="approved",
                notes="Self-approval control test.",
            )
        approval = self.fetchone(
            """
            SELECT decision_status, self_approval_blocked
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (result["containment_action_id"],),
        )
        self.assertEqual(approval["decision_status"], "approval_required")
        self.assertEqual(approval["self_approval_blocked"], 1)

    def test_approval_does_not_execute_action(self) -> None:
        """Approval changes status but does not claim execution."""
        request = self.request(
            "quarantine_device",
            "device_id",
            "CYOD-001",
            "approval-only-001",
        )
        result = self.approve(request["containment_action_id"])
        self.assertEqual(result["status"], "approved")
        self.assertIsNone(result["executed_by"])
        approval = self.fetchone(
            """
            SELECT action_occurred
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (request["containment_action_id"],),
        )
        self.assertEqual(approval["action_occurred"], 0)

    def test_requester_cannot_execute_own_request(self) -> None:
        """The original requester cannot execute an approved action."""
        request = self.request(
            "restrict_account",
            "username",
            "responder01",
            "self-execution-001",
        )
        self.approve(request["containment_action_id"])
        with self.assertRaises(PermissionError):
            execute_action(
                self.database_path,
                self.configuration,
                self.rbac,
                containment_action_id=request["containment_action_id"],
                executed_by="responder01",
            )

    def test_authorised_execution_is_simulated(self) -> None:
        """A separate authorised actor records a simulated success."""
        request = self.request(
            "isolate_endpoint",
            "endpoint_id",
            "CYOD-001",
            "execute-001",
        )
        self.approve(request["containment_action_id"])
        result = execute_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            executed_by="admin01",
        )
        self.assertEqual(result["status"], "successful")
        self.assertEqual(result["executed_by"], "admin01")
        self.assertFalse(result["real_action_executed"])
        approval = self.fetchone(
            """
            SELECT action_occurred
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (request["containment_action_id"],),
        )
        self.assertEqual(approval["action_occurred"], 1)

    def test_denied_action_does_not_execute(self) -> None:
        """A denial is retained and cannot be executed."""
        request = self.request(
            "quarantine_device",
            "device_id",
            "CYOD-001",
            "denied-001",
        )
        result = decide_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            decided_by="admin01",
            decision="denied",
            notes="Insufficient justification for disruption.",
        )
        self.assertEqual(result["status"], "denied")
        with self.assertRaises(PermissionError):
            execute_action(
                self.database_path,
                self.configuration,
                self.rbac,
                containment_action_id=request["containment_action_id"],
                executed_by="admin01",
            )

    def test_failed_action_is_recorded_without_real_execution(self) -> None:
        """A simulated failure retains its actor and safe boundaries."""
        request = self.request(
            "revoke_session",
            "session_id",
            "SESSION-001",
            "failed-001",
        )
        self.approve(request["containment_action_id"])
        result = execute_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            executed_by="admin01",
            simulate_failure=True,
        )
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["real_action_executed"])
        audit = self.fetchone(
            """
            SELECT result
            FROM audit_events
            WHERE action = 'execute_v2_stage12_containment'
            ORDER BY event_id DESC
            LIMIT 1
            """
        )
        self.assertEqual(audit["result"], "failed")

    def test_supported_rollback_is_duplicate_safe(self) -> None:
        """A supported rollback succeeds once and remains idempotent."""
        request = self.request(
            "suspend_process",
            "process_name",
            "test-process",
            "rollback-action-001",
        )
        self.approve(request["containment_action_id"])
        execute_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            executed_by="admin01",
        )
        first = rollback_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            requested_by="netshield01",
            rollback_reason="Restore the simulated process state.",
            rollback_id="rollback-001",
        )
        second = rollback_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            requested_by="netshield01",
            rollback_reason="Restore the simulated process state.",
            rollback_id="rollback-001",
        )
        self.assertEqual(first["status"], "successful")
        self.assertTrue(first["new"])
        self.assertFalse(second["new"])
        action = self.fetchone(
            """
            SELECT status, real_action_executed
            FROM v2_containment_actions
            WHERE containment_action_id = ?
            """,
            (request["containment_action_id"],),
        )
        self.assertEqual(action["status"], "rolled_back")
        self.assertEqual(action["real_action_executed"], 0)

    def test_irreversible_action_rejects_rollback(self) -> None:
        """An action without a safe rollback cannot invent one."""
        request = self.request(
            "terminate_process",
            "process_name",
            "test-process",
            "no-rollback-001",
        )
        self.approve(request["containment_action_id"])
        execute_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            executed_by="admin01",
        )
        with self.assertRaises(ValueError):
            rollback_action(
                self.database_path,
                self.configuration,
                self.rbac,
                containment_action_id=request["containment_action_id"],
                requested_by="netshield01",
                rollback_reason="Unsupported rollback test.",
                rollback_id="no-rollback-001",
            )

    def test_failed_rollback_is_recorded(self) -> None:
        """A rollback failure remains explicit and simulation-only."""
        request = self.request(
            "quarantine_file",
            "file_hash",
            "a" * 64,
            "rollback-failure-action-001",
        )
        self.approve(request["containment_action_id"])
        execute_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            executed_by="admin01",
        )
        result = rollback_action(
            self.database_path,
            self.configuration,
            self.rbac,
            containment_action_id=request["containment_action_id"],
            requested_by="netshield01",
            rollback_reason="Controlled rollback failure test.",
            rollback_id="rollback-failure-001",
            simulate_failure=True,
        )
        self.assertEqual(result["status"], "failed")
        action = self.fetchone(
            """
            SELECT status, real_action_executed
            FROM v2_containment_actions
            WHERE containment_action_id = ?
            """,
            (request["containment_action_id"],),
        )
        self.assertEqual(action["status"], "rollback_failed")
        self.assertEqual(action["real_action_executed"], 0)

    def test_database_integrity_remains_valid(self) -> None:
        """Stage 12 operations preserve SQLite integrity and foreign keys."""
        self.request(
            "increase_monitoring",
            "incident_id",
            "INC-V2-12-TEST",
            "integrity-001",
        )
        with managed_connection(self.database_path) as connection:
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            foreign_keys = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
        self.assertEqual(integrity, "ok")
        self.assertEqual(foreign_keys, [])


if __name__ == "__main__":
    unittest.main()
