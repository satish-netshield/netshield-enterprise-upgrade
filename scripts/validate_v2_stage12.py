"""Validate Phase 3A V2 Stage 12 containment and response."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage12 import INDEX_NAMES, TABLE_NAMES
from src.utils.config_loader import load_json


ROOT = Path(__file__).resolve().parents[1]
CHECKS_PASSED = 0


def require(condition: bool, message: str) -> None:
    """Record a passing validation or raise an assertion error."""
    global CHECKS_PASSED
    if not condition:
        raise AssertionError(message)
    CHECKS_PASSED += 1
    print(f"PASS: {message}")


def object_names(
    connection: sqlite3.Connection,
    object_type: str,
) -> set[str]:
    """Return SQLite object names for a specified type."""
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        )
    }


def parse_json_list(value: str, field_name: str) -> list[Any]:
    """Parse and validate a stored JSON list."""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"{field_name} contains invalid JSON"
        ) from error
    if not isinstance(parsed, list):
        raise AssertionError(f"{field_name} is not a JSON list")
    return parsed


def load_action(
    actions: list[sqlite3.Row],
    action_type: str,
) -> sqlite3.Row | None:
    """Return one live action by type."""
    return next(
        (
            action
            for action in actions
            if action["action_type"] == action_type
        ),
        None,
    )


def main() -> None:
    """Run the Stage 12 live validation."""
    required_files = (
        ROOT / "config/automation_acl.json",
        ROOT / "config/v2_containment_response.json",
        ROOT / "database/schema.sql",
        ROOT / "scripts/initialize_v2_stage12.py",
        ROOT / "scripts/manage_v2_stage12_containment.py",
        ROOT / "src/response/v2_containment_response.py",
        ROOT / "tests/test_v2_stage12_containment.py",
    )
    require(
        all(path.is_file() for path in required_files),
        "Stage 12 files exist",
    )

    settings = load_json(ROOT / "config/settings.json")
    configuration = load_json(
        ROOT / "config/v2_containment_response.json"
    )
    automation_acl = load_json(
        ROOT / "config/automation_acl.json"
    )
    database_path = ROOT / settings["database"]["path"]

    require(
        configuration["stage"] == 12
        and configuration["environment"] == "sandbox"
        and configuration["simulation_only"] is True
        and configuration["allow_real_actions"] is False
        and configuration["allow_external_targets"] is False
        and configuration["default_action"] == "deny"
        and configuration["approval_policy"][
            "requester_cannot_approve_own_request"
        ]
        is True
        and configuration["approval_policy"][
            "requester_cannot_execute_own_request"
        ]
        is True
        and configuration["evidence_policy"][
            "preserve_before_action"
        ]
        is True,
        "Stage 12 configuration preserves scope and safety",
    )

    configured_actions = configuration["actions"]
    acl_actions = {
        action: level
        for level in (
            "automatic",
            "approval_required",
            "manual_only",
        )
        for action in automation_acl[level]
    }
    require(
        len(configured_actions) == 10
        and automation_acl["default_action"] == "deny"
        and all(
            acl_actions.get(action) == policy["control_level"]
            for action, policy in configured_actions.items()
        ),
        "Ten configured actions match the default-deny ACL",
    )

    tracked_schema = (
        ROOT / "database/schema.sql"
    ).read_text(encoding="utf-8")
    require(
        all(
            f"CREATE TABLE IF NOT EXISTS {name}" in tracked_schema
            for name in TABLE_NAMES
        )
        and all(
            f"CREATE INDEX IF NOT EXISTS {name}" in tracked_schema
            for name in INDEX_NAMES
        ),
        "Tracked schema contains four Stage 12 tables and 20 indexes",
    )

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        tables = object_names(connection, "table")
        indexes = object_names(connection, "index")
        require(
            TABLE_NAMES <= tables and INDEX_NAMES <= indexes,
            "Stage 12 database tables and named indexes exist",
        )

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
        foreign_key_issues = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        require(
            integrity == "ok" and not foreign_key_issues,
            "SQLite integrity and foreign keys are valid",
        )

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage_12_status'
            """
        ).fetchone()
        initialisation_audit = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'initialize_v2_stage12'
              AND result = 'success'
            """
        ).fetchone()[0]
        require(
            metadata is not None
            and metadata["value"]
            == "containment_response_foundation_ready"
            and initialisation_audit >= 1,
            "Stage 12 foundation status and initialisation are audited",
        )

        actions = connection.execute(
            """
            SELECT *
            FROM v2_containment_actions
            ORDER BY containment_action_id
            """
        ).fetchall()
        expected_action_types = {
            "add_to_simulated_blocklist",
            "restrict_account",
            "quarantine_device",
            "revoke_session",
        }
        require(
            len(actions) == 4
            and {row["action_type"] for row in actions}
            == expected_action_types
            and len({row["action_key"] for row in actions}) == 4,
            "Four evidence-backed live actions are duplicate-safe",
        )

        automatic = load_action(
            actions,
            "add_to_simulated_blocklist",
        )
        require(
            automatic is not None
            and automatic["control_level"] == "automatic"
            and automatic["status"] == "successful"
            and automatic["executed_by"] == "responder01"
            and automatic["evidence_preserved"] == 1,
            "Automatic simulated blocklist action completed safely",
        )

        restrict = load_action(actions, "restrict_account")
        require(
            restrict is not None
            and restrict["control_level"] == "approval_required"
            and restrict["requested_by"] == "responder01"
            and restrict["approved_by"] == "admin01"
            and restrict["executed_by"] == "admin01"
            and restrict["status"] == "rolled_back",
            "Account restriction used separate approval and execution",
        )

        self_approval = connection.execute(
            """
            SELECT decision_status, self_approval_blocked, action_occurred
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (restrict["containment_action_id"],),
        ).fetchone()
        self_approval_audit = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE actor = 'responder01'
              AND action = 'decide_v2_stage12_containment'
              AND target = ?
              AND result = 'denied'
            """,
            (
                "containment_action:"
                f"{restrict['containment_action_id']}",
            ),
        ).fetchone()[0]
        require(
            self_approval is not None
            and self_approval["decision_status"] == "approved"
            and self_approval["self_approval_blocked"] == 1
            and self_approval["action_occurred"] == 1
            and self_approval_audit >= 1,
            "Requester self-approval was blocked and recorded",
        )

        quarantine = load_action(actions, "quarantine_device")
        quarantine_approval = connection.execute(
            """
            SELECT decision_status, action_occurred
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (quarantine["containment_action_id"],),
        ).fetchone()
        require(
            quarantine is not None
            and quarantine["status"] == "denied"
            and quarantine["denied_by"] == "admin01"
            and quarantine["executed_by"] is None
            and quarantine_approval["decision_status"] == "denied"
            and quarantine_approval["action_occurred"] == 0,
            "Denied quarantine action did not execute",
        )

        session = load_action(actions, "revoke_session")
        session_approval = connection.execute(
            """
            SELECT decision_status, action_occurred
            FROM v2_containment_approvals
            WHERE containment_action_id = ?
            """,
            (session["containment_action_id"],),
        ).fetchone()
        require(
            session is not None
            and session["status"] == "failed"
            and session["approved_by"] == "admin01"
            and session["executed_by"] == "admin01"
            and session_approval["decision_status"] == "approved"
            and session_approval["action_occurred"] == 0,
            "Failed simulated session revocation was recorded",
        )

        evidence_rows = connection.execute(
            """
            SELECT
                evidence.containment_action_id,
                evidence.captured_at,
                evidence.evidence_references,
                evidence.evidence_payload,
                evidence.evidence_sha256,
                evidence.hash_algorithm,
                evidence.preserved_before_action,
                evidence.original_evidence_preserved,
                actions.requested_at,
                actions.evidence_snapshot_sha256
            FROM v2_containment_evidence AS evidence
            JOIN v2_containment_actions AS actions
              ON actions.containment_action_id =
                 evidence.containment_action_id
            ORDER BY evidence.containment_action_id
            """
        ).fetchall()
        require(
            len(evidence_rows) == len(actions)
            and all(
                row["preserved_before_action"] == 1
                and row["original_evidence_preserved"] == 1
                and row["hash_algorithm"] == "sha256"
                and row["captured_at"] <= row["requested_at"]
                for row in evidence_rows
            ),
            "One evidence snapshot was preserved before every action",
        )

        require(
            all(
                hashlib.sha256(
                    row["evidence_payload"].encode("utf-8")
                ).hexdigest()
                == row["evidence_sha256"]
                == row["evidence_snapshot_sha256"]
                for row in evidence_rows
            ),
            "All Stage 12 evidence SHA-256 hashes verify",
        )

        references_valid = True
        for evidence in evidence_rows:
            references = parse_json_list(
                evidence["evidence_references"],
                "evidence_references",
            )
            if not references or len(references) != len(set(references)):
                references_valid = False
                break
            for reference in references:
                match = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM v2_incident_evidence
                    WHERE evidence_reference = ?
                       OR source_evidence_key = ?
                    """,
                    (reference, reference),
                ).fetchone()[0]
                if match != 1:
                    references_valid = False
                    break
        require(
            references_valid,
            "Containment snapshots retain valid original evidence links",
        )

        action_count = connection.execute(
            "SELECT COUNT(DISTINCT action_key) FROM v2_containment_actions"
        ).fetchone()[0]
        snapshot_count = connection.execute(
            """
            SELECT COUNT(DISTINCT evidence_snapshot_key)
            FROM v2_containment_evidence
            """
        ).fetchone()[0]
        approval_count = connection.execute(
            """
            SELECT COUNT(DISTINCT approval_key)
            FROM v2_containment_approvals
            """
        ).fetchone()[0]
        require(
            action_count == 4
            and snapshot_count == 4
            and approval_count == 3,
            "Requests, evidence and approvals remain duplicate-safe",
        )

        rollbacks = connection.execute(
            "SELECT * FROM v2_containment_rollbacks"
        ).fetchall()
        require(
            len(rollbacks) == 1
            and rollbacks[0]["containment_action_id"]
            == restrict["containment_action_id"]
            and rollbacks[0]["rollback_action"]
            == "restore_account_access"
            and rollbacks[0]["rollback_status"] == "successful"
            and rollbacks[0]["simulation_only"] == 1
            and rollbacks[0]["real_action_executed"] == 0,
            "Safe rollback was successful and duplicate-safe",
        )

        required_audit_results = {
            ("request_v2_stage12_containment", "success"),
            ("request_v2_stage12_containment", "denied"),
            ("decide_v2_stage12_containment", "success"),
            ("decide_v2_stage12_containment", "denied"),
            ("execute_v2_stage12_containment", "success"),
            ("execute_v2_stage12_containment", "failed"),
            ("execute_v2_stage12_containment", "denied"),
            ("rollback_v2_stage12_containment", "success"),
        }
        recorded_audit_results = {
            (row["action"], row["result"])
            for row in connection.execute(
                """
                SELECT action, result
                FROM audit_events
                WHERE action LIKE '%v2_stage12_containment%'
                """
            )
        }
        require(
            required_audit_results <= recorded_audit_results,
            "Requested, approved, denied, successful and failed work is audited",
        )

        denied_controls = connection.execute(
            """
            SELECT actor, target, details
            FROM audit_events
            WHERE action = 'request_v2_stage12_containment'
              AND result = 'denied'
            """
        ).fetchall()
        require(
            any(
                row["actor"] == "viewer01"
                and "required permission" in row["details"]
                for row in denied_controls
            )
            and any(
                "delete_enterprise_account" in row["target"]
                and "default_action=deny" in row["details"]
                for row in denied_controls
            ),
            "Unauthorised and undefined actions were denied",
        )

        stage11_evidence_count = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_evidence"
        ).fetchone()[0]
        require(
            stage11_evidence_count == 65
            and all(
                row["simulation_only"] == 1
                and row["real_action_executed"] == 0
                and row["external_target_used"] == 0
                and row["original_evidence_preserved"] == 1
                for row in actions
            ),
            "Stage 11 evidence remains intact and no real action occurred",
        )

    if CHECKS_PASSED != 21:
        raise AssertionError(
            f"Expected 21 validation checks, received {CHECKS_PASSED}"
        )
    print("\nV2 STAGE 12 VALIDATION: PASS (21/21)")


if __name__ == "__main__":
    main()
