"""Tests for Phase 3A V2 Stage 13 eradication and recovery."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.initialize_v2_stage13 import INDEX_NAMES, SCHEMA_SQL, TABLE_NAMES
from src.response.v2_eradication_recovery import (
    RecoveryError,
    canonical_json,
    close_after_review,
    complete_eradication,
    complete_recovery,
    confirm_containment,
    decide_action,
    execute_action,
    record_retest,
    request_action,
    sha256_text,
    utc_now,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_REFERENCE = "identity:stage13-test-evidence"


class V2Stage13EradicationRecoveryTests(unittest.TestCase):
    """Exercise Stage 13 controls using a fresh database per test."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "stage13.db"
        self.configuration = load_json(
            ROOT / "config/v2_eradication_recovery.json"
        )
        self.acl = load_json(ROOT / "config/automation_acl.json")
        self.rbac = load_json(ROOT / "config/rbac.json")

        with managed_connection(self.database) as connection:
            connection.executescript(
                (ROOT / "database/schema.sql").read_text(
                    encoding="utf-8"
                )
            )
            connection.executescript(SCHEMA_SQL)
            connection.executemany(
                "INSERT INTO user_roles VALUES (?, ?, 1)",
                (
                    ("analyst01", "analyst"),
                    ("responder01", "responder"),
                    ("admin01", "administrator"),
                    ("viewer01", "viewer"),
                ),
            )
            now = utc_now()
            connection.execute(
                """
                INSERT INTO v2_incidents (
                    incident_id, source_incident_key, title,
                    detection_sources, severity, confidence,
                    identity_context, device_context, asset_context,
                    network_context, incident_owner, status,
                    source_first_evidence_time,
                    source_last_evidence_time, created_at, updated_at
                ) VALUES (
                    'INC-TEST-001', 'SOURCE-TEST-001',
                    'Stage 13 test incident', '["identity"]',
                    'High', 90, '{"usernames":["viewer01"]}',
                    '{"device_ids":["CYOD-001"]}',
                    '{"asset_ids":["AST-001"]}',
                    '{"ip_addresses":["192.0.2.10"]}',
                    'analyst01', 'Investigating', ?, ?, ?, ?
                )
                """,
                (now, now, now, now),
            )
            evidence_json = canonical_json(
                {
                    "detection_type": "Suspicious Privilege Change",
                    "severity": "Critical",
                    "evidence": {
                        "username": "viewer01",
                        "previous_role": "viewer",
                        "new_role": "administrator",
                    },
                }
            )
            connection.execute(
                """
                INSERT INTO v2_incident_evidence (
                    evidence_link_key, incident_id, source_type,
                    source_record_id, source_evidence_key,
                    evidence_time, relationship, contribution_status,
                    evidence_reference, evidence_json,
                    evidence_sha256, created_at
                ) VALUES (
                    'TEST-LINK-001', 'INC-TEST-001', 'identity',
                    'TEST-RECORD-001', ?, ?, 'shared_context',
                    'active', 'TEST-EVIDENCE-REFERENCE', ?, ?, ?
                )
                """,
                (
                    EVIDENCE_REFERENCE,
                    now,
                    evidence_json,
                    sha256_text(evidence_json),
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO v2_containment_actions (
                    action_key, incident_id, action_type, target_type,
                    target_value, control_level, requested_by,
                    requested_at, request_reason, status,
                    evidence_preserved, evidence_references,
                    executed_by, executed_at, result_details,
                    rollback_supported, simulation_only,
                    real_action_executed, external_target_used,
                    original_evidence_preserved, created_at, updated_at
                ) VALUES (
                    'TEST-CONTAINMENT-001', 'INC-TEST-001',
                    'add_to_simulated_blocklist', 'ip_address',
                    '192.0.2.10', 'automatic', 'responder01', ?,
                    'Test containment', 'successful', 1,
                    '["TEST-EVIDENCE-REFERENCE"]', 'responder01', ?,
                    '{"simulation_only":true}', 1, 1, 0, 0, 1, ?, ?
                )
                """,
                (now, now, now, now),
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def confirm(self) -> dict[str, object]:
        return confirm_containment(
            self.database,
            self.configuration,
            self.rbac,
            incident_id="INC-TEST-001",
            actor="responder01",
            notes="Containment verified.",
            request_id="confirm-001",
        )

    def request(
        self,
        action: str,
        target_type: str,
        target: str,
        request_id: str,
    ) -> dict[str, object]:
        return request_action(
            self.database,
            self.configuration,
            self.acl,
            self.rbac,
            incident_id="INC-TEST-001",
            action_type=action,
            target_type=target_type,
            target_value=target,
            requested_by="responder01",
            request_reason="Evidence-backed test action.",
            evidence_references=[EVIDENCE_REFERENCE],
            request_id=request_id,
        )

    def approve_and_execute(
        self,
        result: dict[str, object],
    ) -> dict[str, object]:
        action_id = int(result["recovery_action_id"])
        if result["control_level"] != "automatic":
            decide_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=action_id,
                decided_by="admin01",
                decision="approved",
                notes="Approved test action.",
            )
            return execute_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=action_id,
                executed_by="admin01",
                details="Simulated test action completed.",
            )
        return result

    def reach_eradicated(self) -> None:
        self.confirm()
        action = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "eradicate-001",
        )
        self.approve_and_execute(action)
        complete_eradication(
            self.database,
            self.configuration,
            self.rbac,
            incident_id="INC-TEST-001",
            actor="responder01",
            notes="Eradication verified.",
            request_id="eradication-complete-001",
        )

    def prepare_verified_recovery(self) -> None:
        self.reach_eradicated()
        recovery = self.request(
            "restore_account",
            "username",
            "viewer01",
            "recover-001",
        )
        self.approve_and_execute(recovery)
        self.request(
            "increase_post_recovery_monitoring",
            "incident_id",
            "INC-TEST-001",
            "monitor-001",
        )
        for retest_type, request_id in (
            ("original_threat", "retest-threat-001"),
            ("original_vulnerability", "retest-finding-001"),
        ):
            record_retest(
                self.database,
                self.configuration,
                self.rbac,
                incident_id="INC-TEST-001",
                retest_type=retest_type,
                target_type="username",
                target_value="viewer01",
                description="Verify the original condition is blocked.",
                observed_result="blocked",
                evidence_references=[EVIDENCE_REFERENCE],
                tested_by="responder01",
                request_id=request_id,
            )

    def test_configuration_preserves_scope_and_safety(self) -> None:
        self.assertEqual(self.configuration["stage"], 13)
        self.assertEqual(len(self.configuration["actions"]), 19)
        self.assertTrue(self.configuration["simulation_only"])
        self.assertFalse(self.configuration["allow_real_actions"])
        self.assertTrue(
            self.configuration["lifecycle"][
                "close_only_after_verification"
            ]
        )

    def test_schema_contains_required_tables_and_indexes(self) -> None:
        with managed_connection(self.database) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
        self.assertTrue(TABLE_NAMES <= tables)
        self.assertTrue(INDEX_NAMES <= indexes)

    def test_containment_confirmation_requires_success(self) -> None:
        with managed_connection(self.database) as connection:
            connection.execute(
                "UPDATE v2_containment_actions SET status='failed'"
            )
        with self.assertRaises(RecoveryError):
            self.confirm()

    def test_containment_confirmation_is_duplicate_safe(self) -> None:
        self.assertTrue(self.confirm()["new"])
        self.assertFalse(self.confirm()["new"])

    def test_undefined_action_is_denied_and_audited(self) -> None:
        self.confirm()
        with self.assertRaises(RecoveryError):
            self.request("destroy_account", "username", "viewer01", "x")
        with managed_connection(self.database) as connection:
            result = connection.execute(
                """
                SELECT result FROM audit_events
                WHERE action='request_v2_stage13_action'
                ORDER BY event_id DESC LIMIT 1
                """
            ).fetchone()[0]
        self.assertEqual(result, "denied")

    def test_wrong_target_type_is_rejected(self) -> None:
        self.confirm()
        with self.assertRaises(RecoveryError):
            self.request(
                "remove_unauthorised_privileges",
                "device_id",
                "CYOD-001",
                "wrong-target-001",
            )

    def test_unrelated_evidence_is_rejected(self) -> None:
        self.confirm()
        with self.assertRaises(ValueError):
            request_action(
                self.database,
                self.configuration,
                self.acl,
                self.rbac,
                incident_id="INC-TEST-001",
                action_type="remove_unauthorised_privileges",
                target_type="username",
                target_value="viewer01",
                requested_by="responder01",
                request_reason="Test.",
                evidence_references=["missing-evidence"],
                request_id="missing-evidence-001",
            )

    def test_duplicate_request_is_idempotent(self) -> None:
        self.confirm()
        first = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "duplicate-001",
        )
        second = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "duplicate-001",
        )
        self.assertTrue(first["new"])
        self.assertFalse(second["new"])
        with managed_connection(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM v2_recovery_actions"
                ).fetchone()[0],
                1,
            )

    def test_evidence_snapshot_hash_verifies(self) -> None:
        self.confirm()
        self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "hash-001",
        )
        with managed_connection(self.database) as connection:
            payload, digest = connection.execute(
                """
                SELECT evidence_payload, evidence_sha256
                FROM v2_recovery_evidence
                """
            ).fetchone()
        self.assertEqual(sha256_text(payload), digest)

    def test_requester_cannot_self_approve_and_flag_persists(self) -> None:
        self.confirm()
        result = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "self-approve-001",
        )
        with self.assertRaises(PermissionError):
            decide_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=int(result["recovery_action_id"]),
                decided_by="responder01",
                decision="approved",
                notes="Not allowed.",
            )
        with managed_connection(self.database) as connection:
            flag = connection.execute(
                "SELECT self_approval_blocked FROM v2_recovery_approvals"
            ).fetchone()[0]
        self.assertEqual(flag, 1)

    def test_manual_action_requires_administrator(self) -> None:
        self.confirm()
        result = self.request(
            "reset_credentials",
            "username",
            "viewer01",
            "manual-001",
        )
        with self.assertRaises(PermissionError):
            decide_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=int(result["recovery_action_id"]),
                decided_by="analyst01",
                decision="approved",
                notes="Not authorised.",
            )

    def test_requester_cannot_execute_own_action(self) -> None:
        self.confirm()
        result = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "self-execute-001",
        )
        action_id = int(result["recovery_action_id"])
        decide_action(
            self.database,
            self.configuration,
            self.rbac,
            recovery_action_id=action_id,
            decided_by="admin01",
            decision="approved",
            notes="Approved.",
        )
        with self.assertRaises(PermissionError):
            execute_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=action_id,
                executed_by="responder01",
            )

    def test_denied_action_cannot_execute(self) -> None:
        self.confirm()
        result = self.request(
            "disable_compromised_account",
            "username",
            "viewer01",
            "deny-001",
        )
        action_id = int(result["recovery_action_id"])
        decide_action(
            self.database,
            self.configuration,
            self.rbac,
            recovery_action_id=action_id,
            decided_by="admin01",
            decision="denied",
            notes="Not required.",
        )
        with self.assertRaises(RecoveryError):
            execute_action(
                self.database,
                self.configuration,
                self.rbac,
                recovery_action_id=action_id,
                executed_by="admin01",
            )

    def test_successful_action_remains_simulation_only(self) -> None:
        self.confirm()
        result = self.request(
            "remove_unauthorised_privileges",
            "username",
            "viewer01",
            "success-001",
        )
        completed = self.approve_and_execute(result)
        self.assertEqual(completed["status"], "successful")
        self.assertTrue(completed["simulation_only"])
        self.assertFalse(completed["real_action_executed"])

    def test_eradication_requires_successful_action(self) -> None:
        self.confirm()
        with self.assertRaises(RecoveryError):
            complete_eradication(
                self.database,
                self.configuration,
                self.rbac,
                incident_id="INC-TEST-001",
                actor="responder01",
                notes="Too early.",
                request_id="early-eradication-001",
            )

    def test_retest_requires_successful_recovery_action(self) -> None:
        self.reach_eradicated()
        with self.assertRaises(RecoveryError):
            record_retest(
                self.database,
                self.configuration,
                self.rbac,
                incident_id="INC-TEST-001",
                retest_type="original_threat",
                target_type="username",
                target_value="viewer01",
                description="Too early.",
                observed_result="blocked",
                evidence_references=[EVIDENCE_REFERENCE],
                tested_by="responder01",
                request_id="early-retest-001",
            )

    def test_failed_retest_blocks_recovery(self) -> None:
        self.reach_eradicated()
        recovery = self.request(
            "restore_account",
            "username",
            "viewer01",
            "failed-retest-recovery-001",
        )
        self.approve_and_execute(recovery)
        record_retest(
            self.database,
            self.configuration,
            self.rbac,
            incident_id="INC-TEST-001",
            retest_type="original_threat",
            target_type="username",
            target_value="viewer01",
            description="Threat still succeeds.",
            observed_result="succeeded",
            evidence_references=[EVIDENCE_REFERENCE],
            tested_by="responder01",
            request_id="failed-retest-001",
        )
        with self.assertRaises(RecoveryError):
            complete_recovery(
                self.database,
                self.configuration,
                self.rbac,
                incident_id="INC-TEST-001",
                actor="responder01",
                notes="Must remain blocked.",
                request_id="blocked-recovery-001",
            )

    def test_retest_is_duplicate_safe(self) -> None:
        self.reach_eradicated()
        recovery = self.request(
            "restore_account",
            "username",
            "viewer01",
            "retest-recovery-001",
        )
        self.approve_and_execute(recovery)
        arguments = dict(
            incident_id="INC-TEST-001",
            retest_type="original_threat",
            target_type="username",
            target_value="viewer01",
            description="Threat is blocked.",
            observed_result="blocked",
            evidence_references=[EVIDENCE_REFERENCE],
            tested_by="responder01",
            request_id="duplicate-retest-001",
        )
        first = record_retest(
            self.database, self.configuration, self.rbac, **arguments
        )
        second = record_retest(
            self.database, self.configuration, self.rbac, **arguments
        )
        self.assertTrue(first["new"])
        self.assertFalse(second["new"])

    def test_recovery_requires_both_retests_and_monitoring(self) -> None:
        self.prepare_verified_recovery()
        result = complete_recovery(
            self.database,
            self.configuration,
            self.rbac,
            incident_id="INC-TEST-001",
            actor="responder01",
            notes="Recovery verified.",
            request_id="recovery-complete-001",
        )
        self.assertEqual(result["status"], "Recovered")

    def test_closure_requires_recovered_status(self) -> None:
        self.prepare_verified_recovery()
        with self.assertRaises(RecoveryError):
            close_after_review(
                self.database,
                self.configuration,
                self.rbac,
                incident_id="INC-TEST-001",
                actor="analyst01",
                lessons_learned="Lesson.",
                detection_improvements="Detection improvement.",
                policy_improvements="Policy improvement.",
                closure_reason="Verified.",
                request_id="early-close-001",
            )

    def test_verified_closure_records_review_and_is_duplicate_safe(self) -> None:
        self.prepare_verified_recovery()
        complete_recovery(
            self.database,
            self.configuration,
            self.rbac,
            incident_id="INC-TEST-001",
            actor="responder01",
            notes="Recovery verified.",
            request_id="close-recovery-001",
        )
        arguments = dict(
            incident_id="INC-TEST-001",
            actor="analyst01",
            lessons_learned="Evidence and retesting are both required.",
            detection_improvements="Prioritise linked identity evidence.",
            policy_improvements="Retain approval separation.",
            closure_reason="Verified recovery completed.",
            request_id="verified-close-001",
        )
        first = close_after_review(
            self.database, self.configuration, self.rbac, **arguments
        )
        second = close_after_review(
            self.database, self.configuration, self.rbac, **arguments
        )
        self.assertTrue(first["new"])
        self.assertFalse(second["new"])
        with managed_connection(self.database) as connection:
            row = connection.execute(
                """
                SELECT review_status, closure_authorised
                FROM v2_post_incident_reviews
                """
            ).fetchone()
            status = connection.execute(
                "SELECT status FROM v2_incidents"
            ).fetchone()[0]
        self.assertEqual(row, ("complete", 1))
        self.assertEqual(status, "Closed")

    def test_database_integrity_and_foreign_keys_remain_valid(self) -> None:
        self.prepare_verified_recovery()
        with managed_connection(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall(),
                [],
            )
            self.assertEqual(
                connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0],
                "ok",
            )


if __name__ == "__main__":
    unittest.main()
