"""Upgrade the NetShield event database for Phase 3A V2."""

import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def add_missing_columns(
    connection: sqlite3.Connection,
    table: str,
    columns: dict[str, str],
) -> list[str]:
    """Add only columns that are absent from an existing table."""
    existing = {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    added: list[str] = []

    for name, definition in columns.items():
        if name not in existing:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
            )
            added.append(name)

    return added


def main() -> None:
    """Apply the backward-compatible V2 pipeline migration."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]

    security_columns = {
        "schema_version": "TEXT NOT NULL DEFAULT '1.0'",
        "source_system": "TEXT NOT NULL DEFAULT 'unknown'",
        "severity": "TEXT",
        "risk_score": "REAL",
        "decision": "TEXT",
        "device_id": "TEXT",
        "asset_id": "TEXT",
        "application_id": "TEXT",
        "service_id": "TEXT",
        "finding_id": "TEXT",
        "incident_id": "TEXT",
        "action_id": "TEXT",
    }
    rejected_columns = {
        "quarantine_status": (
            "TEXT NOT NULL DEFAULT 'quarantined'"
        )
    }

    with sqlite3.connect(database_path) as connection:
        security_added = add_missing_columns(
            connection,
            "security_events",
            security_columns,
        )
        rejected_added = add_missing_columns(
            connection,
            "rejected_events",
            rejected_columns,
        )

        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_events_schema_version
            ON security_events(schema_version);

            CREATE INDEX IF NOT EXISTS
            idx_security_events_source
            ON security_events(source_type, source_system);

            CREATE INDEX IF NOT EXISTS
            idx_security_events_device
            ON security_events(device_id);

            CREATE INDEX IF NOT EXISTS
            idx_security_events_incident
            ON security_events(incident_id);
            """
        )

    save_metadata(database_path, "v2_pipeline_schema", "2.0")
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage2",
        target="security_event_pipeline",
        result="success",
        details=(
            f"security_columns_added={len(security_added)} "
            f"rejected_columns_added={len(rejected_added)}"
        ),
    )

    print("PASS: V2 Stage 2 database migration completed")
    print(f"Security-event columns added: {len(security_added)}")
    print(f"Rejected-event columns added: {len(rejected_added)}")


if __name__ == "__main__":
    main()
