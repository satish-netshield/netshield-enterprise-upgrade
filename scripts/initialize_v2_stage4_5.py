"""Initialise the V2 Stage 4 and Stage 5 database components."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata


PROJECT_ROOT = Path(__file__).resolve().parents[1]


SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_identity_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    username TEXT NOT NULL,
    device_id TEXT,
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    ip_address TEXT,
    location TEXT,
    risk_score REAL
        CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 100
        ),
    reason_codes TEXT NOT NULL,
    mitre_techniques TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'False Positive',
                'Closed'
            )
        ),
    classification TEXT,
    investigation_notes TEXT
);

CREATE TABLE IF NOT EXISTS temporary_access_restrictions (
    restriction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    restriction_key TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
        CHECK (active IN (0, 1)),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_policy_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_key TEXT NOT NULL UNIQUE,
    evaluated_at TEXT NOT NULL,
    request_event_id TEXT NOT NULL,
    username TEXT,
    role TEXT,
    device_id TEXT,
    application_id TEXT,
    asset_id TEXT,
    asset_criticality TEXT,
    location TEXT,
    ip_address TEXT,
    sign_in_risk REAL
        CHECK (
            sign_in_risk IS NULL
            OR sign_in_risk BETWEEN 0 AND 100
        ),
    user_risk REAL
        CHECK (
            user_risk IS NULL
            OR user_risk BETWEEN 0 AND 100
        ),
    mfa_satisfied INTEGER NOT NULL
        CHECK (mfa_satisfied IN (0, 1)),
    decision TEXT NOT NULL
        CHECK (
            decision IN (
                'allow',
                'deny',
                'challenge',
                'restrict'
            )
        ),
    reason_codes TEXT NOT NULL,
    matched_policy_ids TEXT NOT NULL,
    winning_policy_id TEXT,
    identity_evidence TEXT NOT NULL,
    device_evidence TEXT NOT NULL,
    risk_evidence TEXT NOT NULL,
    response_action TEXT,
    acl_control_level TEXT,
    response_status TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_type
ON v2_identity_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_username
ON v2_identity_alerts(username);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_device
ON v2_identity_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_severity
ON v2_identity_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_status
ON v2_identity_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_time
ON v2_identity_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_access_restrictions_username
ON temporary_access_restrictions(username);

CREATE INDEX IF NOT EXISTS idx_access_restrictions_active
ON temporary_access_restrictions(active);

CREATE INDEX IF NOT EXISTS idx_access_policy_request
ON access_policy_decisions(request_event_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_username
ON access_policy_decisions(username);

CREATE INDEX IF NOT EXISTS idx_access_policy_device
ON access_policy_decisions(device_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_application
ON access_policy_decisions(application_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_decision
ON access_policy_decisions(decision);

CREATE INDEX IF NOT EXISTS idx_access_policy_time
ON access_policy_decisions(evaluated_at);
"""


def table_names(database_path: Path) -> set[str]:
    """Return the database table names."""
    with managed_connection(database_path) as connection:
        return {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }


def index_names(database_path: Path) -> set[str]:
    """Return the database index names."""
    with managed_connection(database_path) as connection:
        return {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'index'
                """
            )
        }


def main() -> None:
    """Apply the repeatable Stage 4 and Stage 5 migration."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]

    expected_tables = {
        "v2_identity_alerts",
        "temporary_access_restrictions",
        "access_policy_decisions",
    }
    expected_indexes = {
        "idx_v2_identity_alerts_type",
        "idx_v2_identity_alerts_username",
        "idx_v2_identity_alerts_device",
        "idx_v2_identity_alerts_severity",
        "idx_v2_identity_alerts_status",
        "idx_v2_identity_alerts_time",
        "idx_access_restrictions_username",
        "idx_access_restrictions_active",
        "idx_access_policy_request",
        "idx_access_policy_username",
        "idx_access_policy_device",
        "idx_access_policy_application",
        "idx_access_policy_decision",
        "idx_access_policy_time",
    }

    tables_before = table_names(database_path)
    indexes_before = index_names(database_path)

    with managed_connection(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)

    tables_after = table_names(database_path)
    indexes_after = index_names(database_path)

    missing_tables = expected_tables - tables_after
    missing_indexes = expected_indexes - indexes_after

    if missing_tables:
        raise RuntimeError(
            "Stage 4–5 tables were not created: "
            + ", ".join(sorted(missing_tables))
        )

    if missing_indexes:
        raise RuntimeError(
            "Stage 4–5 indexes were not created: "
            + ", ".join(sorted(missing_indexes))
        )

    tables_created = expected_tables - tables_before
    indexes_created = expected_indexes - indexes_before

    save_metadata(
        database_path,
        "v2_stage4_identity_monitoring",
        "initialised",
    )
    save_metadata(
        database_path,
        "v2_stage5_access_policy",
        "initialised",
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage4_5",
        target="identity_monitoring_and_access_policy",
        result="success",
        details=(
            f"tables_created={len(tables_created)} "
            f"indexes_created={len(indexes_created)}"
        ),
    )

    print("PASS: V2 Stage 4 and Stage 5 database migration completed")
    print(f"Tables created: {len(tables_created)}")
    print(f"Indexes created: {len(indexes_created)}")


if __name__ == "__main__":
    main()
