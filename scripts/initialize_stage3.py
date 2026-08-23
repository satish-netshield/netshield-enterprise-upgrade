"""Initialise the NetShield Stage 3 identity-detection foundation."""

import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import (
    initialise_database,
    record_audit_event,
    save_metadata,
)
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def preserve_stage_status(database_path: Path) -> str:
    """Preserve completed status when Stage 3 is reinitialised."""
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'stage_3_status'
            """
        ).fetchone()

    if row and row[0] == "detections_complete":
        return "detections_complete"

    save_metadata(
        database_path,
        "stage_3_status",
        "initialised",
    )
    return "initialised"


def main() -> None:
    """Create Stage 3 storage and record its initialisation."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    schema_path = PROJECT_ROOT / "database/schema.sql"
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

    initialise_database(database_path, schema_path)
    stage_status = preserve_stage_status(database_path)

    app_logger.info(
        "Stage 3 identity-detection foundation initialised"
    )
    audit_logger.info(
        "actor=netshield01 action=initialise_stage3 "
        "target=identity_detection result=success "
        "stage_status=%s",
        stage_status,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialise_stage3",
        target="identity_detection",
        result="success",
        details=(
            "Identity-alert and network-alert storage initialised; "
            f"stage_3_status={stage_status}"
        ),
    )

    print("PASS: Stage 3 identity-detection foundation initialised")
    print("Tables: identity_alerts, network_alerts")
    print(f"Stage 3 status: {stage_status}")


if __name__ == "__main__":
    main()
