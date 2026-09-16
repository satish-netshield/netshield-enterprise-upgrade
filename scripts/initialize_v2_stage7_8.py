"""Initialise Phase 3A V2 Stage 7 and Stage 8 storage."""

import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TABLES = {
    "v2_endpoint_alerts",
    "v2_endpoint_activity_timeline",
    "v2_endpoint_isolation_actions",
    "v2_vulnerability_findings",
    "v2_vulnerability_remediation_history",
    "v2_vulnerability_links",
}

INDEXES = {
    "idx_v2_endpoint_alerts_type",
    "idx_v2_endpoint_alerts_severity",
    "idx_v2_endpoint_alerts_status",
    "idx_v2_endpoint_alerts_device",
    "idx_v2_endpoint_alerts_asset",
    "idx_v2_endpoint_alerts_process",
    "idx_v2_endpoint_alerts_time",
    "idx_v2_endpoint_timeline_source",
    "idx_v2_endpoint_timeline_time",
    "idx_v2_endpoint_timeline_device",
    "idx_v2_endpoint_timeline_asset",
    "idx_v2_endpoint_timeline_process",
    "idx_v2_endpoint_timeline_isolation",
    "idx_v2_endpoint_isolation_status",
    "idx_v2_endpoint_isolation_device",
    "idx_v2_endpoint_isolation_requested",
    "idx_v2_vulnerability_findings_source",
    "idx_v2_vulnerability_findings_asset",
    "idx_v2_vulnerability_findings_type",
    "idx_v2_vulnerability_findings_severity",
    "idx_v2_vulnerability_findings_priority",
    "idx_v2_vulnerability_findings_status",
    "idx_v2_vulnerability_findings_updated",
    "idx_v2_vulnerability_history_finding",
    "idx_v2_vulnerability_history_status",
    "idx_v2_vulnerability_history_time",
    "idx_v2_vulnerability_links_finding",
    "idx_v2_vulnerability_links_type",
    "idx_v2_vulnerability_links_record",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_endpoint_alerts (
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
        CHECK (
            confidence BETWEEN 0 AND 100
        ),
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    location TEXT,
    health_state TEXT,
    compliance_state TEXT,
    device_risk_state TEXT,
    process_name TEXT,
    process_id INTEGER,
    process_owner TEXT,
    parent_process_name TEXT,
    command_line TEXT,
    cpu_percent REAL,
    file_path TEXT,
    expected_hash TEXT,
    observed_hash TEXT,
    reason_codes TEXT NOT NULL,
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
    investigation_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS v2_endpoint_activity_timeline (
    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    location TEXT,
    health_state TEXT,
    compliance_state TEXT,
    device_risk_state TEXT,
    process_name TEXT,
    process_id INTEGER,
    process_owner TEXT,
    parent_process_name TEXT,
    command_line TEXT,
    cpu_percent REAL,
    file_path TEXT,
    observed_hash TEXT,
    isolation_state TEXT,
    status TEXT,
    raw_event TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_endpoint_isolation_actions (
    isolation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    isolation_key TEXT NOT NULL UNIQUE,
    alert_key TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    device_id TEXT NOT NULL,
    asset_id TEXT,
    action TEXT NOT NULL
        CHECK (
            action = 'quarantine_device'
        ),
    acl_control_level TEXT NOT NULL
        CHECK (
            acl_control_level = 'approval_required'
        ),
    status TEXT NOT NULL
        CHECK (
            status IN (
                'approval_required',
                'simulated_isolated',
                'rejected'
            )
        ),
    request_reason TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    network_state_changed INTEGER NOT NULL DEFAULT 0
        CHECK (
            network_state_changed = 0
        ),
    real_action_executed INTEGER NOT NULL DEFAULT 0
        CHECK (
            real_action_executed = 0
        ),
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_vulnerability_findings (
    finding_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL UNIQUE,
    source_finding_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    finding_source TEXT NOT NULL,
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
        CHECK (
            confidence BETWEEN 0 AND 100
        ),
    confidence_level TEXT NOT NULL
        CHECK (
            confidence_level IN (
                'Low',
                'Medium',
                'High',
                'Very High'
            )
        ),
    exploitability TEXT NOT NULL
        CHECK (
            exploitability IN (
                'none',
                'low',
                'medium',
                'high',
                'demonstrated'
            )
        ),
    exploitation_status TEXT NOT NULL DEFAULT 'none'
        CHECK (
            exploitation_status IN (
                'none',
                'attempted',
                'successful'
            )
        ),
    exposure_level TEXT NOT NULL
        CHECK (
            exposure_level IN (
                'none',
                'internal',
                'restricted',
                'exposed',
                'internet_facing'
            )
        ),
    exposed_service TEXT,
    asset_criticality TEXT NOT NULL
        CHECK (
            asset_criticality IN (
                'low',
                'medium',
                'high',
                'critical'
            )
        ),
    priority_score REAL NOT NULL
        CHECK (
            priority_score BETWEEN 0 AND 100
        ),
    priority_level TEXT NOT NULL
        CHECK (
            priority_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    component_name TEXT,
    component_version TEXT,
    safe_check TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    reason_codes TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation_status TEXT NOT NULL
        CHECK (
            remediation_status IN (
                'Open',
                'Planned',
                'In Progress',
                'Remediated',
                'Verified',
                'False Positive'
            )
        ),
    verification_status TEXT,
    verified_at TEXT,
    classification TEXT,
    investigation_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS v2_vulnerability_remediation_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_key TEXT NOT NULL UNIQUE,
    finding_key TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    verification_result TEXT,
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_vulnerability_links (
    link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_key TEXT NOT NULL UNIQUE,
    finding_key TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    link_type TEXT NOT NULL
        CHECK (
            link_type IN (
                'alert',
                'incident'
            )
        ),
    linked_record_id TEXT NOT NULL,
    exploitation_status TEXT NOT NULL DEFAULT 'none'
        CHECK (
            exploitation_status IN (
                'none',
                'attempted',
                'successful'
            )
        ),
    created_at TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_type
ON v2_endpoint_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_severity
ON v2_endpoint_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_status
ON v2_endpoint_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_device
ON v2_endpoint_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_asset
ON v2_endpoint_alerts(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_process
ON v2_endpoint_alerts(process_name);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_time
ON v2_endpoint_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_source
ON v2_endpoint_activity_timeline(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_time
ON v2_endpoint_activity_timeline(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_device
ON v2_endpoint_activity_timeline(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_asset
ON v2_endpoint_activity_timeline(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_process
ON v2_endpoint_activity_timeline(process_name);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_isolation
ON v2_endpoint_activity_timeline(isolation_state);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_status
ON v2_endpoint_isolation_actions(status);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_device
ON v2_endpoint_isolation_actions(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_requested
ON v2_endpoint_isolation_actions(requested_at);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_source
ON v2_vulnerability_findings(source_finding_id);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_asset
ON v2_vulnerability_findings(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_type
ON v2_vulnerability_findings(finding_type);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_severity
ON v2_vulnerability_findings(severity);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_priority
ON v2_vulnerability_findings(priority_level, priority_score);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_status
ON v2_vulnerability_findings(remediation_status);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_updated
ON v2_vulnerability_findings(updated_at);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_finding
ON v2_vulnerability_remediation_history(finding_key);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_status
ON v2_vulnerability_remediation_history(new_status);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_time
ON v2_vulnerability_remediation_history(recorded_at);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_finding
ON v2_vulnerability_links(finding_key);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_type
ON v2_vulnerability_links(link_type);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_record
ON v2_vulnerability_links(linked_record_id);
"""


def validate_endpoint_configuration(
    configuration: dict[str, Any],
    settings: dict[str, Any],
    automation_acl: dict[str, Any],
) -> None:
    """Validate approved Stage 7 rules and sandbox boundaries."""
    if configuration.get("stage") != 7:
        raise ValueError(
            "Endpoint configuration must identify Stage 7"
        )

    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 7 must remain simulation-only")

    sandbox = configuration["sandbox_policy"]
    prohibited = (
        "real_external_targets_allowed",
        "real_device_isolation_allowed",
        "real_process_termination_allowed",
        "real_network_changes_allowed",
    )

    if any(sandbox[name] is not False for name in prohibited):
        raise ValueError(
            "Stage 7 real-world actions must remain disabled"
        )

    if (
        settings["security"]["allow_real_external_targets"]
        is not False
    ):
        raise ValueError(
            "Project external targets must remain disabled"
        )

    device_identity = configuration["device_identity"]

    if device_identity["primary_identifiers"] != [
        "device_id",
        "asset_id",
    ]:
        raise ValueError(
            "Stage 7 primary device identities are invalid"
        )

    if (
        device_identity["mac_address_identity"]
        != "supporting_evidence_only"
    ):
        raise ValueError(
            "MAC addresses must remain supporting evidence"
        )

    thresholds = configuration["thresholds"]

    if thresholds["process_crash_restart_events"] != 3:
        raise ValueError(
            "Stage 7 requires three crash or restart events"
        )

    if (
        thresholds["process_crash_restart_window_minutes"]
        != 8
    ):
        raise ValueError(
            "Stage 7 crash or restart window must be 8 minutes"
        )

    if thresholds["cpu_warning_percent"] != 80:
        raise ValueError(
            "Stage 7 CPU warning threshold must remain 80"
        )

    if thresholds["cpu_critical_percent"] != 95:
        raise ValueError(
            "Stage 7 CPU critical threshold must remain 95"
        )

    isolation = configuration["isolation_policy"]

    if isolation["action"] != "quarantine_device":
        raise ValueError(
            "Stage 7 isolation action must use quarantine_device"
        )

    if (
        isolation["action"]
        not in automation_acl["approval_required"]
    ):
        raise ValueError(
            "Stage 7 isolation must remain approval-required"
        )

    if isolation["initial_status"] != "approval_required":
        raise ValueError(
            "Stage 7 isolation initial status is invalid"
        )

    if isolation["real_isolation_allowed"] is not False:
        raise ValueError(
            "Real Stage 7 isolation must remain disabled"
        )

    if isolation["change_network_state"] is not False:
        raise ValueError(
            "Stage 7 must not change real or simulated network state"
        )

    if isolation["post_isolation_monitoring"] is not True:
        raise ValueError(
            "Stage 7 post-isolation monitoring must remain enabled"
        )

    if not all(configuration["detection_rules"].values()):
        raise ValueError(
            "Every approved Stage 7 detection must remain enabled"
        )


def validate_vulnerability_configuration(
    configuration: dict[str, Any],
    settings: dict[str, Any],
    enterprise_context: dict[str, Any],
) -> None:
    """Validate approved Stage 8 scoring and linking boundaries."""
    if configuration.get("stage") != 8:
        raise ValueError(
            "Vulnerability configuration must identify Stage 8"
        )

    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 8 must remain simulation-only")

    if (
        settings["security"]["allow_real_external_targets"]
        is not False
    ):
        raise ValueError(
            "Project external targets must remain disabled"
        )

    sandbox = configuration["sandbox_policy"]

    if sandbox["real_external_targets_allowed"] is not False:
        raise ValueError(
            "Stage 8 external targets must remain disabled"
        )

    if (
        sandbox["automatic_incident_creation_allowed"]
        is not False
    ):
        raise ValueError(
            "Stage 8 must not create incidents automatically"
        )

    if sandbox["automatic_exploitation_allowed"] is not False:
        raise ValueError(
            "Stage 8 must not perform automatic exploitation"
        )

    weights = configuration["priority_scoring"]["weights"]
    expected_weights = {
        "severity": 30,
        "exploitability": 25,
        "asset_criticality": 20,
        "exposed_service": 15,
        "confidence": 10,
    }

    if (
        weights != expected_weights
        or sum(weights.values()) != 100
    ):
        raise ValueError(
            "Stage 8 priority weights are invalid"
        )

    thresholds = configuration["priority_scoring"][
        "priority_thresholds"
    ]

    if thresholds != {
        "Critical": 85,
        "High": 65,
        "Medium": 40,
        "Low": 0,
    }:
        raise ValueError(
            "Stage 8 priority thresholds are invalid"
        )

    linking = configuration["linking_policy"]

    if linking["auto_create_incident"] is not False:
        raise ValueError(
            "A finding must not automatically become an incident"
        )

    if (
        linking["incident_link_requires_exploitation_evidence"]
        is not True
    ):
        raise ValueError(
            "Incident links require exploitation evidence"
        )

    if set(linking["accepted_exploitation_states"]) != {
        "attempted",
        "successful",
    }:
        raise ValueError(
            "Stage 8 exploitation states are invalid"
        )

    lab_policy = configuration["sql_injection_lab"]
    assets = {
        asset["asset_id"]: asset
        for asset in enterprise_context.get("assets", [])
    }
    lab_asset = assets.get(lab_policy["asset_id"])

    if lab_asset is None:
        raise ValueError(
            "The SQL injection lab asset is not registered"
        )

    expected_values = {
        "asset_type": lab_policy["expected_asset_type"],
        "environment": lab_policy["expected_environment"],
        "criticality": lab_policy["expected_criticality"],
        "external_target": False,
    }

    for field, expected in expected_values.items():
        if lab_asset.get(field) != expected:
            raise ValueError(
                f"SQL injection lab asset has invalid {field}"
            )

    report_path = PROJECT_ROOT / lab_policy["report_path"]

    if not report_path.is_file():
        raise ValueError(
            "SQL injection lab report does not exist"
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
    """Validate configuration and create Stage 7 and Stage 8 storage."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    endpoint_configuration = load_json(
        PROJECT_ROOT / "config/v2_endpoint_monitoring.json"
    )
    vulnerability_configuration = load_json(
        PROJECT_ROOT
        / "config/v2_vulnerability_management.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )

    validate_endpoint_configuration(
        endpoint_configuration,
        settings,
        automation_acl,
    )
    validate_vulnerability_configuration(
        vulnerability_configuration,
        settings,
        enterprise_context,
    )

    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )
    tables_before = object_names(
        database_path,
        "table",
    )
    indexes_before = object_names(
        database_path,
        "index",
    )

    with managed_connection(database_path) as connection:
        connection.executescript(SCHEMA)

    tables_after = object_names(
        database_path,
        "table",
    )
    indexes_after = object_names(
        database_path,
        "index",
    )
    tables_created = len(
        (tables_after - tables_before) & TABLES
    )
    indexes_created = len(
        (indexes_after - indexes_before) & INDEXES
    )

    save_metadata(
        database_path,
        "v2_stage_7_status",
        "endpoint_monitoring_foundation_ready",
    )
    save_metadata(
        database_path,
        "v2_stage_8_status",
        "vulnerability_management_foundation_ready",
    )

    details = (
        f"tables_created={tables_created} "
        f"indexes_created={indexes_created} "
        "crash_restart_events=3 "
        "crash_restart_window_minutes=8 "
        "isolation=simulation_only "
        "isolation_acl=approval_required "
        "priority_model=weighted_0_100 "
        "auto_incident_creation=false"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage7_8",
        target="endpoint_and_vulnerability_foundation",
        result="success",
        details=details,
    )

    print(
        "PASS: V2 Stage 7-8 database migration completed"
    )
    print(f"Tables created: {tables_created}")
    print(f"Indexes created: {indexes_created}")
    print(
        "Crash or restart rule: 3 events within 8 minutes"
    )
    print(
        "Isolation: simulation only and approval required"
    )
    print("Network state changes: false")
    print(
        "Vulnerability priority model: weighted 0-100"
    )
    print("Automatic incident creation: false")


if __name__ == "__main__":
    main()
