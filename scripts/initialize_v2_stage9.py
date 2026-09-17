"""Initialise Phase 3A V2 Stage 9 continuous monitoring storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


TABLES = {
    "v2_monitoring_cycles",
    "v2_continuous_risk_scores",
    "v2_continuous_risk_history",
    "v2_monitoring_alerts",
    "v2_detection_health",
}


INDEXES = {
    "idx_v2_monitoring_cycles_scheduled",
    "idx_v2_monitoring_cycles_status",
    "idx_v2_monitoring_cycles_completed",
    "idx_v2_monitoring_cycles_last_success",
    "idx_v2_risk_scores_entity",
    "idx_v2_risk_scores_level",
    "idx_v2_risk_scores_score",
    "idx_v2_risk_scores_assessed",
    "idx_v2_risk_scores_last_evidence",
    "idx_v2_risk_history_entity",
    "idx_v2_risk_history_cycle",
    "idx_v2_risk_history_time",
    "idx_v2_monitoring_alerts_type",
    "idx_v2_monitoring_alerts_entity",
    "idx_v2_monitoring_alerts_component",
    "idx_v2_monitoring_alerts_status",
    "idx_v2_monitoring_alerts_severity",
    "idx_v2_monitoring_alerts_cooldown",
    "idx_v2_detection_health_component",
    "idx_v2_detection_health_status",
    "idx_v2_detection_health_checked",
    "idx_v2_detection_health_last_success",
}


REQUIRED_SOURCE_TABLES = {
    "device_alerts",
    "v2_identity_alerts",
    "access_policy_decisions",
    "v2_network_alerts",
    "v2_endpoint_alerts",
    "v2_vulnerability_findings",
    "v2_vulnerability_links",
}


SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_monitoring_cycles (
    cycle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_key TEXT NOT NULL UNIQUE,
    scheduled_for TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'running',
                'completed',
                'completed_with_warnings',
                'failed',
                'suppressed_cooldown'
            )
        ),
    ingestion_status TEXT NOT NULL
        CHECK (
            ingestion_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    detection_status TEXT NOT NULL
        CHECK (
            detection_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    risk_status TEXT NOT NULL
        CHECK (
            risk_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    last_successful_run TEXT,
    records_assessed INTEGER NOT NULL DEFAULT 0
        CHECK (records_assessed >= 0),
    entities_scored INTEGER NOT NULL DEFAULT 0
        CHECK (entities_scored >= 0),
    alerts_created INTEGER NOT NULL DEFAULT 0
        CHECK (alerts_created >= 0),
    alerts_suppressed INTEGER NOT NULL DEFAULT 0
        CHECK (alerts_suppressed >= 0),
    metrics TEXT NOT NULL,
    failure_details TEXT
);

CREATE TABLE IF NOT EXISTS v2_continuous_risk_scores (
    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_key TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL
        CHECK (
            entity_type IN (
                'user',
                'device',
                'asset',
                'incident'
            )
        ),
    entity_id TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    risk_score REAL NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL
        CHECK (
            risk_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    severity_component REAL NOT NULL,
    confidence_component REAL NOT NULL,
    asset_criticality_component REAL NOT NULL,
    agreement_adjustment REAL NOT NULL,
    exception_adjustment REAL NOT NULL,
    decay_adjustment REAL NOT NULL,
    independent_source_count INTEGER NOT NULL
        CHECK (independent_source_count >= 0),
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    evidence TEXT NOT NULL,
    last_evidence_time TEXT NOT NULL,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    UNIQUE (entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS v2_continuous_risk_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_key TEXT NOT NULL UNIQUE,
    cycle_key TEXT NOT NULL,
    entity_type TEXT NOT NULL
        CHECK (
            entity_type IN (
                'user',
                'device',
                'asset',
                'incident'
            )
        ),
    entity_id TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    previous_score REAL,
    new_score REAL NOT NULL
        CHECK (new_score BETWEEN 0 AND 100),
    previous_level TEXT,
    new_level TEXT NOT NULL
        CHECK (
            new_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    change_reason TEXT NOT NULL,
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    calculation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_monitoring_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    alert_type TEXT NOT NULL
        CHECK (
            alert_type IN (
                'risk_threshold',
                'risk_escalation',
                'detection_health',
                'pipeline_failure'
            )
        ),
    created_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    component TEXT,
    risk_score REAL
        CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 100
        ),
    threshold REAL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    status TEXT NOT NULL
        CHECK (
            status IN (
                'New',
                'Monitoring',
                'Suppressed',
                'Closed'
            )
        ),
    cooldown_until TEXT,
    suppression_reason TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1
        CHECK (occurrence_count >= 1),
    independent_source_count INTEGER NOT NULL DEFAULT 0
        CHECK (independent_source_count >= 0),
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_detection_health (
    health_id INTEGER PRIMARY KEY AUTOINCREMENT,
    health_key TEXT NOT NULL UNIQUE,
    cycle_key TEXT NOT NULL,
    component TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'healthy',
                'degraded',
                'failed'
            )
        ),
    last_successful_run TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),
    records_processed INTEGER NOT NULL DEFAULT 0
        CHECK (records_processed >= 0),
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_scheduled
ON v2_monitoring_cycles(scheduled_for);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_status
ON v2_monitoring_cycles(status);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_completed
ON v2_monitoring_cycles(completed_at);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_last_success
ON v2_monitoring_cycles(last_successful_run);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_entity
ON v2_continuous_risk_scores(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_level
ON v2_continuous_risk_scores(risk_level);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_score
ON v2_continuous_risk_scores(risk_score);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_assessed
ON v2_continuous_risk_scores(assessed_at);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_last_evidence
ON v2_continuous_risk_scores(last_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_entity
ON v2_continuous_risk_history(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_cycle
ON v2_continuous_risk_history(cycle_key);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_time
ON v2_continuous_risk_history(assessed_at);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_type
ON v2_monitoring_alerts(alert_type);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_entity
ON v2_monitoring_alerts(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_component
ON v2_monitoring_alerts(component);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_status
ON v2_monitoring_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_severity
ON v2_monitoring_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_cooldown
ON v2_monitoring_alerts(cooldown_until);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_component
ON v2_detection_health(component);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_status
ON v2_detection_health(status);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_checked
ON v2_detection_health(checked_at);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_last_success
ON v2_detection_health(last_successful_run);
"""


def validate_configuration(configuration: dict[str, Any]) -> None:
    """Validate the agreed Stage 9 controls and scoring rules."""
    if configuration.get("stage") != 9:
        raise ValueError(
            "Continuous monitoring configuration must identify Stage 9"
        )

    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 9 must remain simulation-only")

    if configuration.get("risk_entities") != [
        "user",
        "device",
        "asset",
        "incident",
    ]:
        raise ValueError("Stage 9 risk entities are invalid")

    schedule = configuration["schedule"]

    if schedule["interval_minutes"] <= 0:
        raise ValueError("Monitoring interval must be positive")

    if schedule["allow_overlapping_cycles"] is not False:
        raise ValueError(
            "Overlapping Stage 9 cycles must remain disabled"
        )

    scoring = configuration["risk_scoring"]
    weights = scoring["weights"]

    if set(weights) != {
        "severity",
        "confidence",
        "asset_criticality",
    } or sum(weights.values()) != 100:
        raise ValueError("Stage 9 risk weights must total 100")

    if scoring["risk_thresholds"] != {
        "Critical": 85,
        "High": 65,
        "Medium": 40,
        "Low": 0,
    }:
        raise ValueError("Stage 9 risk thresholds are invalid")

    agreement = scoring["independent_source_agreement"]

    if agreement["minimum_sources"] < 2:
        raise ValueError(
            "Independent agreement requires at least two sources"
        )

    if agreement["maximum_increase"] < 0:
        raise ValueError("Agreement increase cannot be negative")

    reduction = scoring["validated_exception_reduction"]

    if reduction["require_completed_review"] is not True:
        raise ValueError("Risk reduction requires a completed review")

    if reduction["accepted_classifications"] != ["False Positive"]:
        raise ValueError("Only validated false positives reduce risk")

    decay = scoring["time_decay"]

    if decay["grace_period_hours"] < 0:
        raise ValueError("Risk decay grace period cannot be negative")

    if decay["points_per_24_hours"] < 0:
        raise ValueError("Risk decay cannot increase risk")

    alerting = configuration["alerting"]

    if alerting["risk_alert_threshold"] != 65:
        raise ValueError(
            "Stage 9 alert threshold must remain High"
        )

    if alerting["escalation_threshold"] != 85:
        raise ValueError(
            "Stage 9 escalation threshold must remain Critical"
        )

    if alerting["suppress_during_cooldown"] is not True:
        raise ValueError(
            "Stage 9 cooldown suppression must remain enabled"
        )

    if alerting["preserve_suppressed_evidence"] is not True:
        raise ValueError("Suppressed evidence must remain preserved")

    evidence_policy = configuration["evidence_policy"]

    if evidence_policy["preserve_original_evidence"] is not True:
        raise ValueError("Stage 9 must preserve original evidence")

    if evidence_policy["risk_scores_replace_evidence"] is not False:
        raise ValueError(
            "Risk scores must not replace original evidence"
        )

    if evidence_policy["duplicate_protection"] is not True:
        raise ValueError(
            "Stage 9 duplicate protection must remain enabled"
        )

    sandbox = configuration["sandbox_policy"]

    if any(value is not False for value in sandbox.values()):
        raise ValueError(
            "Stage 9 real-world actions must remain disabled"
        )


def object_names(
    database_path: Path,
    object_type: str,
) -> set[str]:
    """Return SQLite object names for one object type."""
    with managed_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = ?
            """,
            (object_type,),
        ).fetchall()

    return {row[0] for row in rows}


def main() -> None:
    """Validate configuration and create Stage 9 storage."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_continuous_monitoring.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    validate_configuration(configuration)

    existing_tables = object_names(database_path, "table")
    missing_sources = REQUIRED_SOURCE_TABLES - existing_tables

    if missing_sources:
        names = ", ".join(sorted(missing_sources))
        raise RuntimeError(
            f"Stage 9 source tables are missing: {names}"
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
        raise RuntimeError(
            "Stage 9 database migration is incomplete"
        )

    tables_created = len(TABLES - tables_before)
    indexes_created = len(INDEXES - indexes_before)

    details = (
        f"tables_created={tables_created} "
        f"indexes_created={indexes_created} "
        f"interval_minutes="
        f"{configuration['schedule']['interval_minutes']} "
        "entities=user,device,asset,incident "
        "risk_evidence_preserved=true automatic_actions=false"
    )

    save_metadata(
        database_path,
        "v2_stage_9_status",
        "continuous_monitoring_foundation_ready",
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage9",
        target="continuous_monitoring_foundation",
        result="success",
        details=details,
    )

    print("PASS: V2 Stage 9 database migration completed")
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print(
        "Monitoring interval: "
        f"{configuration['schedule']['interval_minutes']} minutes"
    )
    print("Risk entities: user, device, asset, incident")
    print("Original evidence preserved: true")
    print("Risk scores replace evidence: false")
    print("Automatic response actions: false")


if __name__ == "__main__":
    main()
