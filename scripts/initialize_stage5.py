"""Initialise the NetShield Stage 5 endpoint-alert foundation."""

import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


CREATE_ENDPOINT_ALERTS = """
CREATE TABLE IF NOT EXISTS endpoint_alerts (
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
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    mac_address TEXT,
    ip_address TEXT,
    hostname TEXT,
    username TEXT,
    location TEXT,
    process_name TEXT,
    cpu_percent REAL,
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
"""


CREATE_INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_type
    ON endpoint_alerts(detection_type);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_severity
    ON endpoint_alerts(severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_status
    ON endpoint_alerts(status);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_mac
    ON endpoint_alerts(mac_address);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_username
    ON endpoint_alerts(username);
    """,
]


def main() -> None:
    """Create Stage 5 endpoint-alert storage and indexes."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    application_log = (
        PROJECT_ROOT / settings["logging"]["application_log"]
    )
    audit_log = (
        PROJECT_ROOT / settings["logging"]["audit_log"]
    )

    app_logger = configure_logger(
        "netshield.application",
        application_log,
    )
    audit_logger = configure_logger(
        "netshield.audit",
        audit_log,
    )

    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_ENDPOINT_ALERTS)

        for statement in CREATE_INDEXES:
            connection.execute(statement)

    save_metadata(
        database_path,
        "stage_5_status",
        "initialised",
    )

    details = (
        "Endpoint-alert storage and indexes initialised"
    )

    app_logger.info(
        "Stage 5 endpoint-alert foundation initialised"
    )
    audit_logger.info(
        "actor=netshield01 action=initialise_stage5 "
        "target=endpoint_detection result=success"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialise_stage5",
        target="endpoint_detection",
        result="success",
        details=details,
    )

    print("PASS: Stage 5 endpoint-alert foundation initialised")
    print("Table: endpoint_alerts")


if __name__ == "__main__":
    main()
