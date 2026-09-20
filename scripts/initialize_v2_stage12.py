"""Initialise Phase 3A V2 Stage 12 containment and response storage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TABLE_NAMES = {
    "v2_containment_actions",
    "v2_containment_evidence",
    "v2_containment_approvals",
    "v2_containment_rollbacks",
}

INDEX_NAMES = {
    "idx_v2_containment_actions_incident",
    "idx_v2_containment_actions_type",
    "idx_v2_containment_actions_target",
    "idx_v2_containment_actions_status",
    "idx_v2_containment_actions_requested",
    "idx_v2_containment_actions_requester",
    "idx_v2_containment_actions_approver",
    "idx_v2_containment_actions_executor",
    "idx_v2_containment_evidence_action",
    "idx_v2_containment_evidence_incident",
    "idx_v2_containment_evidence_hash",
    "idx_v2_containment_evidence_created",
    "idx_v2_containment_approvals_action",
    "idx_v2_containment_approvals_status",
    "idx_v2_containment_approvals_requester",
    "idx_v2_containment_approvals_decider",
    "idx_v2_containment_rollbacks_action",
    "idx_v2_containment_rollbacks_status",
    "idx_v2_containment_rollbacks_requested",
    "idx_v2_containment_rollbacks_actor",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS v2_containment_actions (
    containment_action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    control_level TEXT NOT NULL
        CHECK (
            control_level IN (
                'automatic',
                'approval_required',
                'manual_only'
            )
        ),
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    request_reason TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'requested',
                'approval_required',
                'approved',
                'denied',
                'successful',
                'failed',
                'rolled_back',
                'rollback_failed'
            )
        ),
    evidence_preserved INTEGER NOT NULL DEFAULT 0
        CHECK (evidence_preserved IN (0, 1)),
    evidence_snapshot_sha256 TEXT,
    evidence_references TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    denied_by TEXT,
    denied_at TEXT,
    executed_by TEXT,
    executed_at TEXT,
    result_details TEXT,
    rollback_supported INTEGER NOT NULL
        CHECK (rollback_supported IN (0, 1)),
    rollback_action TEXT,
    simulation_only INTEGER NOT NULL DEFAULT 1
        CHECK (simulation_only = 1),
    real_action_executed INTEGER NOT NULL DEFAULT 0
        CHECK (real_action_executed = 0),
    external_target_used INTEGER NOT NULL DEFAULT 0
        CHECK (external_target_used = 0),
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS v2_containment_evidence (
    containment_evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_snapshot_key TEXT NOT NULL UNIQUE,
    containment_action_id INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    captured_by TEXT NOT NULL,
    evidence_references TEXT NOT NULL,
    evidence_payload TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL
        CHECK (hash_algorithm = 'sha256'),
    preserved_before_action INTEGER NOT NULL DEFAULT 1
        CHECK (preserved_before_action = 1),
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    FOREIGN KEY (containment_action_id)
        REFERENCES v2_containment_actions(containment_action_id),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (containment_action_id, evidence_sha256)
);

CREATE TABLE IF NOT EXISTS v2_containment_approvals (
    containment_approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_key TEXT NOT NULL UNIQUE,
    containment_action_id INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_status TEXT NOT NULL
        CHECK (
            decision_status IN (
                'approval_required',
                'approved',
                'denied'
            )
        ),
    decision_notes TEXT,
    self_approval_blocked INTEGER NOT NULL DEFAULT 0
        CHECK (self_approval_blocked IN (0, 1)),
    actor_role TEXT,
    action_occurred INTEGER NOT NULL DEFAULT 0
        CHECK (action_occurred IN (0, 1)),
    evidence_references TEXT NOT NULL,
    FOREIGN KEY (containment_action_id)
        REFERENCES v2_containment_actions(containment_action_id),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS v2_containment_rollbacks (
    containment_rollback_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rollback_key TEXT NOT NULL UNIQUE,
    containment_action_id INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    rollback_action TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    executed_by TEXT,
    executed_at TEXT,
    rollback_status TEXT NOT NULL
        CHECK (
            rollback_status IN (
                'requested',
                'approval_required',
                'approved',
                'denied',
                'successful',
                'failed'
            )
        ),
    rollback_reason TEXT NOT NULL,
    result_details TEXT,
    evidence_references TEXT NOT NULL,
    simulation_only INTEGER NOT NULL DEFAULT 1
        CHECK (simulation_only = 1),
    real_action_executed INTEGER NOT NULL DEFAULT 0
        CHECK (real_action_executed = 0),
    FOREIGN KEY (containment_action_id)
        REFERENCES v2_containment_actions(containment_action_id),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_incident
ON v2_containment_actions(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_type
ON v2_containment_actions(action_type);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_target
ON v2_containment_actions(target_type, target_value);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_status
ON v2_containment_actions(status);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_requested
ON v2_containment_actions(requested_at);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_requester
ON v2_containment_actions(requested_by);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_approver
ON v2_containment_actions(approved_by);

CREATE INDEX IF NOT EXISTS idx_v2_containment_actions_executor
ON v2_containment_actions(executed_by);

CREATE INDEX IF NOT EXISTS idx_v2_containment_evidence_action
ON v2_containment_evidence(containment_action_id);

CREATE INDEX IF NOT EXISTS idx_v2_containment_evidence_incident
ON v2_containment_evidence(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_containment_evidence_hash
ON v2_containment_evidence(evidence_sha256);

CREATE INDEX IF NOT EXISTS idx_v2_containment_evidence_created
ON v2_containment_evidence(captured_at);

CREATE INDEX IF NOT EXISTS idx_v2_containment_approvals_action
ON v2_containment_approvals(containment_action_id);

CREATE INDEX IF NOT EXISTS idx_v2_containment_approvals_status
ON v2_containment_approvals(decision_status);

CREATE INDEX IF NOT EXISTS idx_v2_containment_approvals_requester
ON v2_containment_approvals(requested_by);

CREATE INDEX IF NOT EXISTS idx_v2_containment_approvals_decider
ON v2_containment_approvals(decided_by);

CREATE INDEX IF NOT EXISTS idx_v2_containment_rollbacks_action
ON v2_containment_rollbacks(containment_action_id);

CREATE INDEX IF NOT EXISTS idx_v2_containment_rollbacks_status
ON v2_containment_rollbacks(rollback_status);

CREATE INDEX IF NOT EXISTS idx_v2_containment_rollbacks_requested
ON v2_containment_rollbacks(requested_at);

CREATE INDEX IF NOT EXISTS idx_v2_containment_rollbacks_actor
ON v2_containment_rollbacks(executed_by);
"""


def require(condition: bool, message: str) -> None:
    """Raise an assertion error when a migration condition is not met."""
    if not condition:
        raise AssertionError(message)


def load_configuration() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Load the project, Stage 12 and ACL configurations."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    stage12 = load_json(
        PROJECT_ROOT / "config/v2_containment_response.json"
    )
    acl = load_json(PROJECT_ROOT / "config/automation_acl.json")
    return settings, stage12, acl


def validate_configuration(
    stage12: dict[str, Any],
    acl: dict[str, Any],
) -> None:
    """Validate Stage 12 boundaries against the existing ACL."""
    require(
        stage12["stage"] == 12,
        "Stage 12 configuration has the wrong stage number",
    )
    require(
        stage12["environment"] == "sandbox",
        "Stage 12 must remain inside the sandbox",
    )
    require(
        stage12["simulation_only"] is True,
        "Stage 12 actions must remain simulated",
    )
    require(
        stage12["allow_real_actions"] is False,
        "Stage 12 must not allow real actions",
    )
    require(
        stage12["allow_external_targets"] is False,
        "Stage 12 must not allow external targets",
    )
    require(
        stage12["default_action"] == "deny",
        "Stage 12 must use default deny",
    )
    require(
        acl["default_action"] == "deny",
        "The existing ACL must remain default deny",
    )

    known_actions = {
        action: level
        for level in (
            "automatic",
            "approval_required",
            "manual_only",
        )
        for action in acl[level]
    }

    for action, policy in stage12["actions"].items():
        require(
            action in known_actions,
            f"Stage 12 action is undefined in the ACL: {action}",
        )
        require(
            known_actions[action] == policy["control_level"],
            f"ACL control mismatch for action: {action}",
        )

    required_statuses = {
        "requested",
        "approval_required",
        "approved",
        "denied",
        "successful",
        "failed",
        "rolled_back",
        "rollback_failed",
    }
    require(
        set(stage12["action_statuses"]) == required_statuses,
        "Stage 12 action statuses are incomplete",
    )
    require(
        stage12["approval_policy"][
            "requester_cannot_approve_own_request"
        ]
        is True,
        "Stage 12 must prevent self-approval",
    )
    require(
        stage12["evidence_policy"]["preserve_before_action"]
        is True,
        "Stage 12 must preserve evidence before action",
    )


def object_names(
    connection: sqlite3.Connection,
    object_type: str,
) -> set[str]:
    """Return SQLite object names for one object type."""
    return {
        row[0]
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = ?
            """,
            (object_type,),
        )
    }


def initialise_database(
    database_path: Path,
) -> tuple[int, int]:
    """Create Stage 12 tables and indexes through a repeatable migration."""
    with managed_connection(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        existing_tables = object_names(connection, "table")
        existing_indexes = object_names(connection, "index")

        required_existing_tables = {
            "v2_incidents",
            "v2_incident_evidence",
            "user_roles",
            "audit_events",
            "system_metadata",
        }
        require(
            required_existing_tables <= existing_tables,
            "Required earlier-stage tables are missing",
        )

        connection.executescript(SCHEMA_SQL)

        current_tables = object_names(connection, "table")
        current_indexes = object_names(connection, "index")

        require(
            TABLE_NAMES <= current_tables,
            "Stage 12 tables were not created",
        )
        require(
            INDEX_NAMES <= current_indexes,
            "Stage 12 indexes were not created",
        )

        foreign_key_issues = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        require(
            not foreign_key_issues,
            "Stage 12 migration created a foreign-key problem",
        )

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()
        require(
            integrity is not None and integrity[0] == "ok",
            "SQLite integrity check failed",
        )

        connection.execute(
            """
            INSERT INTO system_metadata(key, value)
            VALUES (?, ?)
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
            """,
            (
                "v2_stage_12_status",
                "containment_response_foundation_ready",
            ),
        )

        tables_created = len(TABLE_NAMES - existing_tables)
        indexes_created = len(INDEX_NAMES - existing_indexes)

    return tables_created, indexes_created


def main() -> None:
    """Validate configuration and initialise Stage 12 storage."""
    settings, stage12, acl = load_configuration()
    validate_configuration(stage12, acl)

    database_path = PROJECT_ROOT / settings["database"]["path"]
    tables_created, indexes_created = initialise_database(
        database_path
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage12",
        target="v2_stage12_containment_response",
        result="success",
        details=(
            f"tables_created={tables_created} "
            f"indexes_created={indexes_created} "
            "simulation_only=true "
            "real_actions=false "
            "external_targets=false "
            "default_action=deny"
        ),
    )

    print("PASS: V2 Stage 12 database migration completed")
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print("Configured actions: 10")
    print("Self-approval: blocked")
    print("Evidence before disruptive action: required")
    print("Undefined actions: denied")
    print("Real actions: false")
    print("External targets: false")


if __name__ == "__main__":
    main()
