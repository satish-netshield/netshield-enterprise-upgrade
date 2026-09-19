"""Initialise Phase 3A V2 Stage 11 incident-management storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TABLES = {
    "v2_incidents",
    "v2_incident_evidence",
    "v2_incident_iocs",
    "v2_incident_behaviours",
    "v2_incident_attack_references",
    "v2_incident_decisions",
    "v2_incident_timeline",
    "v2_incident_approvals",
    "v2_incident_vulnerability_links",
    "v2_incident_reports",
}

INDEXES = {
    "idx_v2_incidents_source_key",
    "idx_v2_incidents_status",
    "idx_v2_incidents_severity",
    "idx_v2_incidents_owner",
    "idx_v2_incidents_updated",
    "idx_v2_incident_evidence_incident",
    "idx_v2_incident_evidence_source",
    "idx_v2_incident_evidence_reference",
    "idx_v2_incident_evidence_hash",
    "idx_v2_incident_iocs_incident",
    "idx_v2_incident_iocs_type",
    "idx_v2_incident_iocs_value",
    "idx_v2_incident_behaviours_incident",
    "idx_v2_incident_behaviours_name",
    "idx_v2_incident_attack_incident",
    "idx_v2_incident_attack_technique",
    "idx_v2_incident_decisions_incident",
    "idx_v2_incident_decisions_actor",
    "idx_v2_incident_decisions_time",
    "idx_v2_incident_timeline_incident",
    "idx_v2_incident_timeline_time",
    "idx_v2_incident_timeline_type",
    "idx_v2_incident_approvals_incident",
    "idx_v2_incident_approvals_action",
    "idx_v2_incident_approvals_status",
    "idx_v2_incident_vulnerabilities_incident",
    "idx_v2_incident_vulnerabilities_finding",
    "idx_v2_incident_reports_incident",
    "idx_v2_incident_reports_type",
    "idx_v2_incident_reports_hash",
}

REQUIRED_SOURCE_TABLES = {
    "audit_events",
    "system_metadata",
    "user_roles",
    "v2_xdr_incidents",
    "v2_xdr_incident_evidence",
    "v2_xdr_indicators",
    "v2_vulnerability_findings",
    "v2_vulnerability_links",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_incidents (
    managed_incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL UNIQUE,
    source_incident_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    detection_sources TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    risk_score REAL NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    identity_context TEXT NOT NULL,
    device_context TEXT NOT NULL,
    asset_context TEXT NOT NULL,
    network_context TEXT NOT NULL,
    incident_owner TEXT,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Triaged',
                'Investigating',
                'Contained',
                'Eradicated',
                'Recovered',
                'Closed',
                'Closed - False Positive'
            )
        ),
    investigation_notes TEXT NOT NULL DEFAULT '[]',
    analyst_decisions TEXT NOT NULL DEFAULT '[]',
    closure_reason TEXT,
    false_positive_classification TEXT,
    source_first_evidence_time TEXT NOT NULL,
    source_last_evidence_time TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    CHECK (
        status != 'Closed - False Positive'
        OR false_positive_classification = 'False Positive'
    ),
    CHECK (
        status NOT IN ('Closed', 'Closed - False Positive')
        OR closure_reason IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS v2_incident_evidence (
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
    evidence_sha256 TEXT NOT NULL
        CHECK (
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, source_evidence_key)
);

CREATE TABLE IF NOT EXISTS v2_incident_iocs (
    incident_ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL
        CHECK (
            ioc_type IN (
                'ip_address',
                'file_hash',
                'hostname',
                'process_name'
            )
        ),
    ioc_value TEXT NOT NULL,
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    source_evidence_keys TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS v2_incident_behaviours (
    incident_behaviour_id INTEGER PRIMARY KEY AUTOINCREMENT,
    behaviour_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    behaviour_name TEXT NOT NULL,
    detection_types TEXT NOT NULL,
    source_evidence_keys TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, behaviour_name)
);

CREATE TABLE IF NOT EXISTS v2_incident_attack_references (
    incident_attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_reference_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT,
    source_detection_types TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, technique_id)
);

CREATE TABLE IF NOT EXISTS v2_incident_decisions (
    incident_decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    decision_time TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    decision TEXT NOT NULL,
    notes TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    evidence_references TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS v2_incident_timeline (
    incident_timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    event_time TEXT NOT NULL,
    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'incident_created',
                'owner_assigned',
                'investigation_note',
                'analyst_decision',
                'status_changed',
                'approval_recorded',
                'evidence_linked',
                'report_generated'
            )
        ),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    details TEXT NOT NULL,
    evidence_references TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS v2_incident_approvals (
    incident_approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    approval_status TEXT NOT NULL
        CHECK (
            approval_status IN (
                'requested',
                'approved',
                'rejected',
                'not_required'
            )
        ),
    requested_by TEXT,
    requested_at TEXT,
    decided_by TEXT,
    decided_at TEXT,
    related_action_reference TEXT,
    action_occurred INTEGER NOT NULL DEFAULT 0
        CHECK (action_occurred IN (0, 1)),
    evidence_references TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, action_type, approval_key)
);

CREATE TABLE IF NOT EXISTS v2_incident_vulnerability_links (
    incident_vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_link_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    relationship TEXT NOT NULL
        CHECK (
            relationship IN (
                'context_only',
                'attempted_exploitation',
                'successful_exploitation'
            )
        ),
    exploitation_status TEXT NOT NULL,
    evidence_references TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    FOREIGN KEY (finding_key)
        REFERENCES v2_vulnerability_findings(finding_key),
    UNIQUE (incident_id, finding_key)
);

CREATE TABLE IF NOT EXISTS v2_incident_reports (
    incident_report_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_key TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    report_type TEXT NOT NULL
        CHECK (report_type IN ('json', 'text')),
    report_path TEXT NOT NULL,
    report_sha256 TEXT NOT NULL
        CHECK (
            length(report_sha256) = 64
            AND report_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    generated_at TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES v2_incidents(incident_id),
    UNIQUE (incident_id, report_type)
);

CREATE INDEX IF NOT EXISTS idx_v2_incidents_source_key
ON v2_incidents(source_incident_key);

CREATE INDEX IF NOT EXISTS idx_v2_incidents_status
ON v2_incidents(status);

CREATE INDEX IF NOT EXISTS idx_v2_incidents_severity
ON v2_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_v2_incidents_owner
ON v2_incidents(incident_owner);

CREATE INDEX IF NOT EXISTS idx_v2_incidents_updated
ON v2_incidents(updated_at);

CREATE INDEX IF NOT EXISTS idx_v2_incident_evidence_incident
ON v2_incident_evidence(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_evidence_source
ON v2_incident_evidence(source_type);

CREATE INDEX IF NOT EXISTS idx_v2_incident_evidence_reference
ON v2_incident_evidence(evidence_reference);

CREATE INDEX IF NOT EXISTS idx_v2_incident_evidence_hash
ON v2_incident_evidence(evidence_sha256);

CREATE INDEX IF NOT EXISTS idx_v2_incident_iocs_incident
ON v2_incident_iocs(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_iocs_type
ON v2_incident_iocs(ioc_type);

CREATE INDEX IF NOT EXISTS idx_v2_incident_iocs_value
ON v2_incident_iocs(ioc_value);

CREATE INDEX IF NOT EXISTS idx_v2_incident_behaviours_incident
ON v2_incident_behaviours(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_behaviours_name
ON v2_incident_behaviours(behaviour_name);

CREATE INDEX IF NOT EXISTS idx_v2_incident_attack_incident
ON v2_incident_attack_references(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_attack_technique
ON v2_incident_attack_references(technique_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_decisions_incident
ON v2_incident_decisions(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_decisions_actor
ON v2_incident_decisions(actor);

CREATE INDEX IF NOT EXISTS idx_v2_incident_decisions_time
ON v2_incident_decisions(decision_time);

CREATE INDEX IF NOT EXISTS idx_v2_incident_timeline_incident
ON v2_incident_timeline(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_timeline_time
ON v2_incident_timeline(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_incident_timeline_type
ON v2_incident_timeline(event_type);

CREATE INDEX IF NOT EXISTS idx_v2_incident_approvals_incident
ON v2_incident_approvals(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_approvals_action
ON v2_incident_approvals(action_type);

CREATE INDEX IF NOT EXISTS idx_v2_incident_approvals_status
ON v2_incident_approvals(approval_status);

CREATE INDEX IF NOT EXISTS idx_v2_incident_vulnerabilities_incident
ON v2_incident_vulnerability_links(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_vulnerabilities_finding
ON v2_incident_vulnerability_links(source_finding_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_reports_incident
ON v2_incident_reports(incident_id);

CREATE INDEX IF NOT EXISTS idx_v2_incident_reports_type
ON v2_incident_reports(report_type);

CREATE INDEX IF NOT EXISTS idx_v2_incident_reports_hash
ON v2_incident_reports(report_sha256);
"""


def validate_configuration(configuration: dict[str, Any]) -> None:
    """Validate the agreed Stage 11 incident-management controls."""
    if configuration.get("stage") != 11:
        raise ValueError(
            "Incident-management configuration must identify Stage 11"
        )

    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 11 must remain simulation-only")

    source = configuration["incident_source"]
    if source["require_existing_xdr_incident"] is not True:
        raise ValueError("Managed incidents require an XDR incident")
    if source["preserve_source_incident_key"] is not True:
        raise ValueError("The original XDR incident key must be preserved")

    identity = configuration["incident_identity"]
    if not identity["prefix"] or identity["number_width"] < 1:
        raise ValueError("Stage 11 incident ID configuration is invalid")
    if identity["unique_incident_id_required"] is not True:
        raise ValueError("Stage 11 incident IDs must remain unique")

    lifecycle = configuration["lifecycle"]
    expected_path = [
        "New",
        "Triaged",
        "Investigating",
        "Contained",
        "Eradicated",
        "Recovered",
        "Closed",
    ]
    if lifecycle["primary_path"] != expected_path:
        raise ValueError("Stage 11 primary lifecycle is invalid")
    if lifecycle["false_positive_sources"] != [
        "New",
        "Triaged",
        "Investigating",
    ]:
        raise ValueError("Stage 11 false-positive path is invalid")
    if lifecycle["false_positive_target"] != (
        "Closed - False Positive"
    ):
        raise ValueError("Stage 11 false-positive target is invalid")
    if lifecycle["skip_transitions_allowed"] is not False:
        raise ValueError("Stage 11 lifecycle transitions cannot be skipped")
    if lifecycle["closed_incidents_are_immutable"] is not True:
        raise ValueError("Closed Stage 11 incidents must be immutable")

    evidence = configuration["evidence"]
    if evidence["hash_algorithm"] != "sha256":
        raise ValueError("Stage 11 evidence must use SHA-256")
    if evidence["sha256_hex_length"] != 64:
        raise ValueError("Stage 11 SHA-256 hashes must contain 64 hex digits")
    if evidence["preserve_original_evidence"] is not True:
        raise ValueError("Stage 11 must preserve original evidence")
    if evidence["hash_mismatch_rejected"] is not True:
        raise ValueError("Stage 11 must reject evidence hash mismatches")

    ownership = configuration["ownership"]
    if ownership["reuse_existing_rbac"] is not True:
        raise ValueError("Stage 11 must reuse the existing RBAC model")
    if ownership["required_permission"] != "investigate_incidents":
        raise ValueError("Incident owners require investigation permission")

    reporting = configuration["reporting"]
    if reporting["json_output_required"] is not True:
        raise ValueError("Stage 11 requires JSON incident output")
    if reporting["human_readable_report_required"] is not True:
        raise ValueError("Stage 11 requires a readable incident report")

    safety = configuration["safety"]
    if safety["local_simulated_data_only"] is not True:
        raise ValueError("Stage 11 must use local simulated evidence")
    if any(
        safety[key] is not False
        for key in (
            "automatic_containment_allowed",
            "automatic_eradication_allowed",
            "automatic_recovery_allowed",
            "real_account_changes_allowed",
            "real_device_changes_allowed",
            "real_network_changes_allowed",
        )
    ):
        raise ValueError("Stage 11 real or automatic actions are disabled")


def object_names(database_path: Path, object_type: str) -> set[str]:
    """Return SQLite object names for one object type."""
    with managed_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        ).fetchall()

    return {row[0] for row in rows}


def main() -> None:
    """Validate configuration and create or repair Stage 11 storage."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_incident_management.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    validate_configuration(configuration)

    existing_tables = object_names(database_path, "table")
    missing_sources = REQUIRED_SOURCE_TABLES - existing_tables
    if missing_sources:
        names = ", ".join(sorted(missing_sources))
        raise RuntimeError(
            f"Stage 11 source tables are missing: {names}"
        )

    tables_before = existing_tables
    indexes_before = object_names(database_path, "index")

    with managed_connection(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        repaired = False

        if "v2_incident_vulnerability_links" in existing_tables:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(v2_incident_vulnerability_links)"
                )
            }
            if "finding_key" not in columns:
                count = connection.execute(
                    "SELECT COUNT(*) FROM v2_incident_vulnerability_links"
                ).fetchone()[0]
                if count:
                    raise RuntimeError(
                        "Repair stopped: vulnerability links are not empty"
                    )

                connection.execute(
                    "DROP TABLE v2_incident_vulnerability_links"
                )
                repaired = True

        # These fixed schema statements contain no embedded semicolons.
        # Execute individually to keep the repair and checks transactional.
        for statement in SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)

        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(
                "Foreign-key violations: migration rolled back"
            )

        if connection.execute("PRAGMA integrity_check").fetchall() != [
            ("ok",)
        ]:
            raise RuntimeError(
                "Integrity check failed: migration rolled back"
            )

    tables_after = object_names(database_path, "table")
    indexes_after = object_names(database_path, "index")

    missing_tables = TABLES - tables_after
    missing_indexes = INDEXES - indexes_after
    if missing_tables or missing_indexes:
        raise RuntimeError("Stage 11 database migration is incomplete")

    tables_created = len(TABLES - tables_before)
    indexes_created = len(INDEXES - indexes_before)
    details = (
        f"tables_created={tables_created} "
        f"indexes_created={indexes_created} "
        "lifecycle_transitions=controlled "
        "sha256_evidence=true "
        "original_evidence_preserved=true "
        "automatic_actions=false "
        f"vulnerability_link_table_repaired={repaired}"
    )

    # Re-running initialisation must not downgrade later completion metadata.
    with managed_connection(database_path) as connection:
        connection.execute(
            "INSERT INTO system_metadata (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (
                "v2_stage_11_status",
                "incident_management_foundation_ready",
            ),
        )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage11",
        target="incident_management_foundation",
        result="success",
        details=details,
    )

    print("PASS: V2 Stage 11 database migration completed")
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print(
        "Empty vulnerability-link table repaired: "
        f"{str(repaired).lower()}"
    )
    print("Primary lifecycle: New to Closed through controlled transitions")
    print("False-positive closure: New, Triaged or Investigating only")
    print("Evidence hashing: SHA-256")
    print("Original evidence preserved: true")
    print("Automatic response actions: false")


if __name__ == "__main__":
    main()
