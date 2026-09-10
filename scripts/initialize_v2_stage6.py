"""Initialise Phase 3A V2 Stage 6 network monitoring storage."""

import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TABLES = {
    "v2_network_alerts",
    "v2_network_access_decisions",
    "v2_network_connection_timeline",
}

INDEXES = {
    "idx_v2_network_alerts_type",
    "idx_v2_network_alerts_severity",
    "idx_v2_network_alerts_status",
    "idx_v2_network_alerts_device",
    "idx_v2_network_alerts_ip",
    "idx_v2_network_alerts_mac",
    "idx_v2_network_alerts_time",
    "idx_v2_network_decisions_source",
    "idx_v2_network_decisions_decision",
    "idx_v2_network_decisions_device",
    "idx_v2_network_decisions_ip",
    "idx_v2_network_decisions_time",
    "idx_v2_network_timeline_source",
    "idx_v2_network_timeline_time",
    "idx_v2_network_timeline_device",
    "idx_v2_network_timeline_ip",
    "idx_v2_network_timeline_mac",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_network_alerts (
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
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
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

CREATE TABLE IF NOT EXISTS v2_network_access_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_key TEXT NOT NULL UNIQUE,
    evaluated_at TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
    decision TEXT NOT NULL
        CHECK (
            decision IN (
                'allow',
                'deny',
                'challenge',
                'restrict'
            )
        ),
    matching_rules TEXT NOT NULL,
    reason_codes TEXT NOT NULL,
    evidence TEXT NOT NULL,
    response_action TEXT,
    acl_control_level TEXT,
    response_status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_network_connection_timeline (
    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
    status TEXT,
    raw_event TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_type
ON v2_network_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_severity
ON v2_network_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_status
ON v2_network_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_device
ON v2_network_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_ip
ON v2_network_alerts(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_mac
ON v2_network_alerts(mac_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_time
ON v2_network_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_source
ON v2_network_access_decisions(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_decision
ON v2_network_access_decisions(decision);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_device
ON v2_network_access_decisions(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_ip
ON v2_network_access_decisions(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_time
ON v2_network_access_decisions(evaluated_at);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_source
ON v2_network_connection_timeline(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_time
ON v2_network_connection_timeline(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_device
ON v2_network_connection_timeline(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_ip
ON v2_network_connection_timeline(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_mac
ON v2_network_connection_timeline(mac_address);
"""


def validate_configuration(
    configuration: dict[str, Any],
    settings: dict[str, Any],
    automation_acl: dict[str, Any],
) -> None:
    """Validate the Stage 6 security boundaries."""
    if configuration.get("simulation_only") is not True:
        raise ValueError("Stage 6 must remain simulation-only")

    if settings["security"]["allow_real_external_targets"] is not False:
        raise ValueError("Real external targets must remain disabled")

    if (
        configuration["device_identity"]["mac_address_identity"]
        != "supporting_evidence_only"
    ):
        raise ValueError("MAC addresses must remain supporting evidence only")

    if configuration["network_policy"]["default_decision"] != "deny":
        raise ValueError("Network access must follow default deny")

    outcomes = set(
        configuration["network_policy"]["decision_outcomes"]
    )

    if outcomes != {"allow", "deny", "challenge", "restrict"}:
        raise ValueError("Stage 6 decision outcomes are invalid")

    wifi_policy = configuration["wifi_policy"]

    if wifi_policy["required_security"] != "WPA3":
        raise ValueError("WPA3 must remain the required Wi-Fi security mode")

    if wifi_policy["allowed_cipher"] != "AES":
        raise ValueError("AES must remain the approved Wi-Fi cipher")

    if wifi_policy["allow_wpa2_downgrade"] is not False:
        raise ValueError("WPA2 downgrade must remain disabled")

    if wifi_policy["allow_open_networks"] is not False:
        raise ValueError("Open Wi-Fi networks must remain disabled")

    mappings = configuration["decision_mapping"]

    if not set(mappings.values()).issubset(outcomes):
        raise ValueError("A Stage 6 decision mapping is invalid")

    known_actions = set(automation_acl["automatic"])
    known_actions.update(automation_acl["approval_required"])
    known_actions.update(automation_acl["manual_only"])

    response_actions = {
        action
        for action in configuration["response_actions"].values()
        if action is not None
    }

    if not response_actions.issubset(known_actions):
        raise ValueError("A Stage 6 response action is not in the ACL")

    if len(configuration["source_files"]) != 2:
        raise ValueError(
            "Stage 6 requires separate network and Wi-Fi source files"
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
    """Create the repeatable Stage 6 database foundation."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_network_monitoring.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )

    validate_configuration(
        configuration,
        settings,
        automation_acl,
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    database_path.parent.mkdir(parents=True, exist_ok=True)

    tables_before = object_names(database_path, "table")
    indexes_before = object_names(database_path, "index")

    with managed_connection(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)

    tables_after = object_names(database_path, "table")
    indexes_after = object_names(database_path, "index")

    created_tables = len(
        TABLES.intersection(tables_after - tables_before)
    )
    created_indexes = len(
        INDEXES.intersection(indexes_after - indexes_before)
    )

    details = (
        f"tables_created={created_tables} "
        f"indexes_created={created_indexes} "
        "simulation_only=true "
        "default_decision=deny "
        "mac_identity=supporting_evidence_only"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage6",
        target="network_monitoring_foundation",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage_6_status",
        "network_monitoring_foundation_ready",
    )

    print("PASS: V2 Stage 6 database migration completed")
    print(f"Tables created: {created_tables}")
    print(f"Indexes created: {created_indexes}")
    print("Simulation only: true")
    print("Default network decision: deny")
    print("MAC identity: supporting_evidence_only")


if __name__ == "__main__":
    main()
