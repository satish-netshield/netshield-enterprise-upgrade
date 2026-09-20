"""Initialise Phase 3A V2 Stage 13 eradication and recovery storage."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TABLE_NAMES = {
    "v2_recovery_actions",
    "v2_recovery_evidence",
    "v2_recovery_approvals",
    "v2_recovery_retests",
    "v2_post_incident_reviews",
}

INDEX_NAMES = {
    "idx_v2_recovery_actions_incident",
    "idx_v2_recovery_actions_phase",
    "idx_v2_recovery_actions_type",
    "idx_v2_recovery_actions_target",
    "idx_v2_recovery_actions_status",
    "idx_v2_recovery_actions_requested",
    "idx_v2_recovery_actions_approver",
    "idx_v2_recovery_actions_executor",
    "idx_v2_recovery_evidence_action",
    "idx_v2_recovery_evidence_incident",
    "idx_v2_recovery_evidence_hash",
    "idx_v2_recovery_evidence_created",
    "idx_v2_recovery_approvals_action",
    "idx_v2_recovery_approvals_incident",
    "idx_v2_recovery_approvals_status",
    "idx_v2_recovery_approvals_requester",
    "idx_v2_recovery_approvals_decider",
    "idx_v2_recovery_retests_incident",
    "idx_v2_recovery_retests_type",
    "idx_v2_recovery_retests_status",
    "idx_v2_recovery_retests_time",
    "idx_v2_post_reviews_incident",
    "idx_v2_post_reviews_status",
    "idx_v2_post_reviews_reviewer",
    "idx_v2_post_reviews_completed",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS v2_recovery_actions (
    recovery_action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_key TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    containment_action_id INTEGER,
    phase TEXT NOT NULL
        CHECK (phase IN ('eradication', 'recovery')),
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
    disruptive INTEGER NOT NULL
        CHECK (disruptive IN (0, 1)),
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    request_reason TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'requested',
                'approved',
                'denied',
                'successful',
                'failed'
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
        REFERENCES v2_incidents(incident_id),
    FOREIGN KEY (containment_action_id)
        REFERENCES v2_containment_actions(containment_action_id)
);

CREATE TABLE IF NOT EXISTS v2_recovery_evidence (
    recovery_evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_snapshot_key TEXT NOT NULL UNIQUE,
    recovery_action_id INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    captured_by TEXT NOT NULL,
    evidence_references TEXT NOT NULL,
    evidence_payload TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL
        CHECK (
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    hash_algorithm TEXT NOT NULL
        CHECK (hash_algorithm = 'sha256'),
    preserved_before_action INTEGER NOT NULL DEFAULT 1
        CHECK (preserved_before_action = 1),
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    FOREIGN KEY (recovery_action_id)
        REFERENCES v2_recovery_actions(recovery_action_id),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (recovery_action_id, evidence_sha256)
);

CREATE TABLE IF NOT EXISTS v2_recovery_approvals (
    recovery_approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_key TEXT NOT NULL UNIQUE,
    recovery_action_id INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_status TEXT NOT NULL
        CHECK (
            decision_status IN (
                'requested',
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
    FOREIGN KEY (recovery_action_id)
        REFERENCES v2_recovery_actions(recovery_action_id),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS v2_recovery_retests (
    recovery_retest_id INTEGER PRIMARY KEY AUTOINCREMENT,
    retest_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    recovery_action_id INTEGER,
    retest_type TEXT NOT NULL
        CHECK (
            retest_type IN (
                'original_threat',
                'original_vulnerability'
            )
        ),
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    test_description TEXT NOT NULL,
    expected_result TEXT NOT NULL,
    observed_result TEXT NOT NULL
        CHECK (
            observed_result IN (
                'pending',
                'blocked',
                'succeeded',
                'error'
            )
        ),
    verification_status TEXT NOT NULL
        CHECK (
            verification_status IN (
                'pending',
                'passed',
                'failed'
            )
        ),
    confirmed_no_longer_succeeds INTEGER NOT NULL DEFAULT 0
        CHECK (confirmed_no_longer_succeeds IN (0, 1)),
    evidence_references TEXT NOT NULL,
    evidence_sha256 TEXT
        CHECK (
            evidence_sha256 IS NULL
            OR (
                length(evidence_sha256) = 64
                AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
    tested_by TEXT NOT NULL,
    tested_at TEXT NOT NULL,
    simulation_only INTEGER NOT NULL DEFAULT 1
        CHECK (simulation_only = 1),
    real_action_executed INTEGER NOT NULL DEFAULT 0
        CHECK (real_action_executed = 0),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    FOREIGN KEY (recovery_action_id)
        REFERENCES v2_recovery_actions(recovery_action_id)
);

CREATE TABLE IF NOT EXISTS v2_post_incident_reviews (
    post_incident_review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL UNIQUE,
    review_status TEXT NOT NULL
        CHECK (review_status IN ('draft', 'complete')),
    reviewed_by TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    lessons_learned TEXT NOT NULL,
    detection_improvements TEXT NOT NULL,
    policy_improvements TEXT NOT NULL,
    closure_reason TEXT,
    eradication_verified INTEGER NOT NULL DEFAULT 0
        CHECK (eradication_verified IN (0, 1)),
    recovery_verified INTEGER NOT NULL DEFAULT 0
        CHECK (recovery_verified IN (0, 1)),
    original_threat_blocked INTEGER NOT NULL DEFAULT 0
        CHECK (original_threat_blocked IN (0, 1)),
    original_vulnerability_blocked INTEGER NOT NULL DEFAULT 0
        CHECK (original_vulnerability_blocked IN (0, 1)),
    post_recovery_monitoring_active INTEGER NOT NULL DEFAULT 0
        CHECK (post_recovery_monitoring_active IN (0, 1)),
    closure_authorised INTEGER NOT NULL DEFAULT 0
        CHECK (closure_authorised IN (0, 1)),
    closure_actor TEXT,
    closed_at TEXT,
    evidence_references TEXT NOT NULL,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    CHECK (
        review_status != 'complete'
        OR (
            completed_at IS NOT NULL
            AND length(trim(lessons_learned)) > 2
            AND length(trim(detection_improvements)) > 2
            AND length(trim(policy_improvements)) > 2
        )
    ),
    CHECK (
        closure_authorised = 0
        OR (
            review_status = 'complete'
            AND eradication_verified = 1
            AND recovery_verified = 1
            AND original_threat_blocked = 1
            AND original_vulnerability_blocked = 1
            AND post_recovery_monitoring_active = 1
            AND closure_reason IS NOT NULL
            AND closure_actor IS NOT NULL
            AND closed_at IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_incident
ON v2_recovery_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_phase
ON v2_recovery_actions(phase);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_type
ON v2_recovery_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_target
ON v2_recovery_actions(target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_status
ON v2_recovery_actions(status);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_requested
ON v2_recovery_actions(requested_at);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_approver
ON v2_recovery_actions(approved_by);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_actions_executor
ON v2_recovery_actions(executed_by);

CREATE INDEX IF NOT EXISTS idx_v2_recovery_evidence_action
ON v2_recovery_evidence(recovery_action_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_evidence_incident
ON v2_recovery_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_evidence_hash
ON v2_recovery_evidence(evidence_sha256);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_evidence_created
ON v2_recovery_evidence(captured_at);

CREATE INDEX IF NOT EXISTS idx_v2_recovery_approvals_action
ON v2_recovery_approvals(recovery_action_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_approvals_incident
ON v2_recovery_approvals(incident_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_approvals_status
ON v2_recovery_approvals(decision_status);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_approvals_requester
ON v2_recovery_approvals(requested_by);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_approvals_decider
ON v2_recovery_approvals(decided_by);

CREATE INDEX IF NOT EXISTS idx_v2_recovery_retests_incident
ON v2_recovery_retests(incident_id);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_retests_type
ON v2_recovery_retests(retest_type);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_retests_status
ON v2_recovery_retests(verification_status);
CREATE INDEX IF NOT EXISTS idx_v2_recovery_retests_time
ON v2_recovery_retests(tested_at);

CREATE INDEX IF NOT EXISTS idx_v2_post_reviews_incident
ON v2_post_incident_reviews(incident_id);
CREATE INDEX IF NOT EXISTS idx_v2_post_reviews_status
ON v2_post_incident_reviews(review_status);
CREATE INDEX IF NOT EXISTS idx_v2_post_reviews_reviewer
ON v2_post_incident_reviews(reviewed_by);
CREATE INDEX IF NOT EXISTS idx_v2_post_reviews_completed
ON v2_post_incident_reviews(completed_at);
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
    """Load project, Stage 13 and ACL configurations."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    stage13 = load_json(
        PROJECT_ROOT / "config/v2_eradication_recovery.json"
    )
    acl = load_json(PROJECT_ROOT / "config/automation_acl.json")
    return settings, stage13, acl


def validate_configuration(
    stage13: dict[str, Any],
    acl: dict[str, Any],
) -> None:
    """Validate Stage 13 boundaries against the existing ACL."""
    require(stage13["stage"] == 13, "Invalid Stage 13 number")
    require(
        stage13["environment"] == "sandbox",
        "Stage 13 must remain inside the sandbox",
    )
    require(
        stage13["simulation_only"] is True,
        "Stage 13 actions must remain simulated",
    )
    require(
        stage13["allow_real_actions"] is False,
        "Stage 13 must not allow real actions",
    )
    require(
        stage13["allow_external_targets"] is False,
        "Stage 13 must not allow external targets",
    )
    require(
        stage13["default_action"] == "deny",
        "Stage 13 must use default deny",
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
    require(
        len(known_actions)
        == sum(
            len(acl[level])
            for level in (
                "automatic",
                "approval_required",
                "manual_only",
            )
        ),
        "An ACL action appears in more than one control level",
    )

    for action, policy in stage13["actions"].items():
        require(
            action in known_actions,
            f"Stage 13 action is undefined in the ACL: {action}",
        )
        if policy["disruptive"]:
            require(
                known_actions[action] != "automatic",
                f"Disruptive action cannot be automatic: {action}",
            )

    require(
        set(stage13["action_statuses"])
        == {"requested", "approved", "denied", "successful", "failed"},
        "Stage 13 action statuses are incomplete",
    )
    require(
        set(stage13["verification_statuses"])
        == {"pending", "passed", "failed"},
        "Stage 13 verification statuses are incomplete",
    )
    require(
        stage13["lifecycle"]["successful_containment_required"]
        is True,
        "Stage 13 requires successful containment evidence",
    )
    require(
        stage13["lifecycle"]["close_only_after_verification"]
        is True,
        "Stage 13 closure must require verification",
    )
    require(
        stage13["verification"]["failed_retest_blocks_closure"]
        is True,
        "A failed retest must block incident closure",
    )
    require(
        stage13["safety"]["local_simulated_data_only"] is True,
        "Stage 13 must use local simulated data",
    )
    for safety_name, safety_value in stage13["safety"].items():
        if safety_name != "local_simulated_data_only":
            require(
                safety_value is False,
                f"Unsafe Stage 13 setting enabled: {safety_name}",
            )


def object_names(
    connection: sqlite3.Connection,
    object_type: str,
) -> set[str]:
    """Return SQLite object names for one object type."""
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        )
    }


def initialise_database(database_path: Path) -> tuple[int, int]:
    """Create Stage 13 tables and indexes through a repeatable migration."""
    with managed_connection(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        existing_tables = object_names(connection, "table")
        existing_indexes = object_names(connection, "index")
        required_existing_tables = {
            "v2_incidents",
            "v2_incident_evidence",
            "v2_incident_decisions",
            "v2_incident_timeline",
            "v2_containment_actions",
            "v2_containment_evidence",
            "v2_containment_approvals",
            "user_roles",
            "audit_events",
            "system_metadata",
        }
        require(
            required_existing_tables <= existing_tables,
            "Required Stage 11 or Stage 12 tables are missing",
        )

        connection.executescript(SCHEMA_SQL)

        current_tables = object_names(connection, "table")
        current_indexes = object_names(connection, "index")
        require(
            TABLE_NAMES <= current_tables,
            "Stage 13 tables were not created",
        )
        require(
            INDEX_NAMES <= current_indexes,
            "Stage 13 indexes were not created",
        )

        foreign_key_issues = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        require(
            not foreign_key_issues,
            "Stage 13 migration created a foreign-key problem",
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
                "v2_stage_13_status",
                "eradication_recovery_foundation_ready",
            ),
        )

        tables_created = len(TABLE_NAMES - existing_tables)
        indexes_created = len(INDEX_NAMES - existing_indexes)

    return tables_created, indexes_created


def main() -> None:
    """Validate configuration and initialise Stage 13 storage."""
    settings, stage13, acl = load_configuration()
    validate_configuration(stage13, acl)

    database_path = PROJECT_ROOT / settings["database"]["path"]
    tables_created, indexes_created = initialise_database(database_path)

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage13",
        target="v2_stage13_eradication_recovery",
        result="success",
        details=(
            f"tables_created={tables_created} "
            f"indexes_created={indexes_created} "
            "simulation_only=true "
            "successful_containment_required=true "
            "verified_closure_required=true "
            "real_actions=false external_targets=false"
        ),
    )

    print("PASS: V2 Stage 13 database migration completed")
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print("Configured actions: 19")
    print("Successful containment required: true")
    print("Evidence before action: required")
    print("Closure after verification only: true")
    print("Real actions: false")
    print("External targets: false")


if __name__ == "__main__":
    main()
