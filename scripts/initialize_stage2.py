"""Initialise the NetShield Stage 2 security-data pipeline."""

from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import (
    initialise_database,
    record_audit_event,
    save_metadata,
)
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Create Stage 2 tables and record the pipeline initialisation."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    schema_path = PROJECT_ROOT / "database/schema.sql"
    application_log = (
        PROJECT_ROOT / settings["logging"]["application_log"]
    )
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]

    app_logger = configure_logger(
        "netshield.application",
        application_log,
    )
    audit_logger = configure_logger(
        "netshield.audit",
        audit_log,
    )

    initialise_database(database_path, schema_path)
    save_metadata(
        database_path,
        "project_version",
        settings["project"]["version"],
    )
    save_metadata(
        database_path,
        "stage_2_status",
        "initialised",
    )

    app_logger.info(
        "Stage 2 security-data pipeline initialised successfully"
    )
    audit_logger.info(
        "actor=netshield01 action=initialise_stage2 "
        "target=security_data_pipeline result=success"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialise_stage2",
        target="security_data_pipeline",
        result="success",
        details="Stage 2 database tables and pipeline settings initialised",
    )

    print("PASS: Stage 2 data-pipeline foundation initialised")
    print(f"Database: {database_path}")
    print("Tables: import_batches, security_events, rejected_events")


if __name__ == "__main__":
    main()
