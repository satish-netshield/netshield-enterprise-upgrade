"""Initialise Phase 3A V2 Stage 10 XDR-style correlation storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


TABLES = {
    "v2_xdr_incidents",
    "v2_xdr_incident_evidence",
    "v2_xdr_indicators",
}


INDEXES = {
    "idx_v2_xdr_incidents_first_time",
    "idx_v2_xdr_incidents_last_time",
    "idx_v2_xdr_incidents_severity",
    "idx_v2_xdr_incidents_confidence",
    "idx_v2_xdr_incidents_status",
    "idx_v2_xdr_evidence_incident",
    "idx_v2_xdr_evidence_source",
    "idx_v2_xdr_evidence_record",
    "idx_v2_xdr_evidence_contribution",
    "idx_v2_xdr_evidence_time",
    "idx_v2_xdr_indicators_incident",
    "idx_v2_xdr_indicators_type",
    "idx_v2_xdr_indicators_value",
    "idx_v2_xdr_indicators_classification",
}


REQUIRED_SOURCE_TABLES = {
    "v2_identity_alerts",
    "access_policy_decisions",
    "v2_network_alerts",
    "v2_endpoint_alerts",
    "v2_vulnerability_findings",
    "v2_vulnerability_links",
}


SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_xdr_incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    first_evidence_time TEXT NOT NULL,
    last_evidence_time TEXT NOT NULL,
    title TEXT NOT NULL,
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
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'Closed'
            )
        ),
    independent_source_count INTEGER NOT NULL
        CHECK (independent_source_count >= 2),
    evidence_count INTEGER NOT NULL
        CHECK (evidence_count >= 2),
    active_evidence_count INTEGER NOT NULL
        CHECK (active_evidence_count >= 1),
    exception_count INTEGER NOT NULL DEFAULT 0
        CHECK (exception_count >= 0),
    verified_activity_count INTEGER NOT NULL DEFAULT 0
        CHECK (verified_activity_count >= 0),
    usernames TEXT NOT NULL,
    service_accounts TEXT NOT NULL,
    device_ids TEXT NOT NULL,
    asset_ids TEXT NOT NULL,
    ip_addresses TEXT NOT NULL,
    mac_addresses TEXT NOT NULL,
    hostnames TEXT NOT NULL,
    process_names TEXT NOT NULL,
    file_hashes TEXT NOT NULL,
    locations TEXT NOT NULL,
    detection_types TEXT NOT NULL,
    attack_techniques TEXT NOT NULL,
    behaviours TEXT NOT NULL,
    correlation_reasons TEXT NOT NULL,
    vulnerability_context TEXT NOT NULL,
    evidence_keys TEXT NOT NULL,
    evidence TEXT NOT NULL,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1)
);

CREATE TABLE IF NOT EXISTS v2_xdr_incident_evidence (
    evidence_link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_link_key TEXT NOT NULL UNIQUE,
    incident_key TEXT NOT NULL,
    evidence_key TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    event_time TEXT NOT NULL,
    relationship TEXT NOT NULL
        CHECK (
            relationship IN (
                'shared_context',
                'explicit_finding_link',
                'vulnerability_context'
            )
        ),
    contribution_status TEXT NOT NULL
        CHECK (
            contribution_status IN (
                'active',
                'exception',
                'verified',
                'context_only'
            )
        ),
    shared_fields TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    detection_type TEXT,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    correlation_reasons TEXT NOT NULL,
    evidence TEXT NOT NULL,
    UNIQUE (incident_key, evidence_key)
);

CREATE TABLE IF NOT EXISTS v2_xdr_indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_key TEXT NOT NULL UNIQUE,
    incident_key TEXT NOT NULL,
    indicator_type TEXT NOT NULL
        CHECK (
            indicator_type IN (
                'ip_address',
                'file_hash',
                'hostname',
                'process_name',
                'mac_address'
            )
        ),
    indicator_value TEXT NOT NULL,
    classification TEXT NOT NULL
        CHECK (
            classification IN (
                'ioc',
                'supporting_observable'
            )
        ),
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    source_evidence_keys TEXT NOT NULL,
    detection_types TEXT NOT NULL,
    evidence TEXT NOT NULL,
    UNIQUE (
        incident_key,
        indicator_type,
        indicator_value
    )
);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_first_time
ON v2_xdr_incidents(first_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_last_time
ON v2_xdr_incidents(last_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_severity
ON v2_xdr_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_confidence
ON v2_xdr_incidents(confidence);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_status
ON v2_xdr_incidents(status);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_incident
ON v2_xdr_incident_evidence(incident_key);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_source
ON v2_xdr_incident_evidence(source_type);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_record
ON v2_xdr_incident_evidence(source_record_id);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_contribution
ON v2_xdr_incident_evidence(contribution_status);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_time
ON v2_xdr_incident_evidence(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_incident
ON v2_xdr_indicators(incident_key);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_type
ON v2_xdr_indicators(indicator_type);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_value
ON v2_xdr_indicators(indicator_value);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_classification
ON v2_xdr_indicators(classification);
"""


def validate_configuration(configuration: dict[str, Any]) -> None:
    """Validate the agreed Stage 10 correlation controls."""
    if configuration.get("stage") != 10:
        raise ValueError("XDR correlation configuration must identify Stage 10")

    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 10 must remain simulation-only")

    correlation = configuration["correlation"]
    if correlation["time_window_minutes"] <= 0:
        raise ValueError("Stage 10 time window must be positive")
    if correlation["minimum_independent_sources"] < 2:
        raise ValueError("Cross-source correlation requires two sources")
    if correlation["mac_address_is_supporting_only"] is not True:
        raise ValueError("MAC addresses must remain supporting evidence")
    if correlation["require_primary_or_explicit_link"] is not True:
        raise ValueError("Correlation requires strong or explicit evidence")

    confidence = configuration["confidence"]
    if confidence["maximum"] != 100:
        raise ValueError("Stage 10 confidence maximum must be 100")
    if confidence["independent_source_bonus"] <= 0:
        raise ValueError("Independent sources must increase confidence")
    if confidence["validated_exception_reduction"] <= 0:
        raise ValueError("Validated exceptions must reduce confidence")
    if confidence["verified_activity_reduction"] <= 0:
        raise ValueError("Verified activity must reduce confidence")

    vulnerability = configuration["vulnerability_policy"]
    if vulnerability["context_does_not_create_incident"] is not True:
        raise ValueError("Vulnerability context cannot create incidents")
    if vulnerability["preserve_finding_links"] is not True:
        raise ValueError("Finding links must remain preserved")

    duplicates = configuration["duplicate_protection"]
    if not all(duplicates.values()):
        raise ValueError("All Stage 10 duplicate controls must remain enabled")

    evidence = configuration["evidence_policy"]
    if not all(evidence.values()):
        raise ValueError("Stage 10 must preserve correlation evidence")

    sandbox = configuration["sandbox_policy"]
    if sandbox["local_simulated_data_only"] is not True:
        raise ValueError("Stage 10 must use local simulated evidence")
    if any(
        value is not False
        for key, value in sandbox.items()
        if key != "local_simulated_data_only"
    ):
        raise ValueError("Stage 10 real-world actions must remain disabled")


def object_names(database_path: Path, object_type: str) -> set[str]:
    """Return SQLite object names for one object type."""
    with managed_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        ).fetchall()

    return {row[0] for row in rows}


def main() -> None:
    """Validate configuration and create Stage 10 storage."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_xdr_correlation.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    validate_configuration(configuration)

    existing_tables = object_names(database_path, "table")
    missing_sources = REQUIRED_SOURCE_TABLES - existing_tables
    if missing_sources:
        names = ", ".join(sorted(missing_sources))
        raise RuntimeError(
            f"Stage 10 source tables are missing: {names}"
        )

    tables_before = existing_tables
    indexes_before = object_names(database_path, "index")

    with managed_connection(database_path) as connection:
        connection.executescript(SCHEMA)

    tables_after = object_names(database_path, "table")
    indexes_after = object_names(database_path, "index")

    missing_tables = TABLES - tables_after
    missing_indexes = INDEXES - indexes_after
    if missing_tables or missing_indexes:
        raise RuntimeError("Stage 10 database migration is incomplete")

    tables_created = len(TABLES - tables_before)
    indexes_created = len(INDEXES - indexes_before)
    details = (
        f"tables_created={tables_created} "
        f"indexes_created={indexes_created} "
        f"time_window_minutes="
        f"{configuration['correlation']['time_window_minutes']} "
        "mac_supporting_only=true vulnerability_context_only=true "
        "original_evidence_preserved=true automatic_actions=false"
    )

    save_metadata(
        database_path,
        "v2_stage_10_status",
        "xdr_correlation_foundation_ready",
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage10",
        target="xdr_correlation_foundation",
        result="success",
        details=details,
    )

    print("PASS: V2 Stage 10 database migration completed")
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print(
        "Correlation window: "
        f"{configuration['correlation']['time_window_minutes']} minutes"
    )
    print("Minimum independent sources: 2")
    print("MAC addresses: supporting evidence only")
    print("Vulnerability context creates incidents: false")
    print("Original evidence preserved: true")
    print("Automatic response actions: false")


if __name__ == "__main__":
    main()
