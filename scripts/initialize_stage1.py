"""Initialise and verify the NetShield Stage 1 foundation."""

from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import (
    assign_role,
    initialise_database,
    record_audit_event,
    save_metadata,
)
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Initialise configuration, logs, database and project owner role."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    schema_path = PROJECT_ROOT / "database/schema.sql"
    application_log = PROJECT_ROOT / settings["logging"]["application_log"]
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]

    app_logger = configure_logger("netshield.application", application_log)
    audit_logger = configure_logger("netshield.audit", audit_log)

    initialise_database(database_path, schema_path)
    save_metadata(database_path, "project_name", settings["project"]["name"])
    save_metadata(database_path, "project_version", settings["project"]["version"])
    save_metadata(database_path, "environment", settings["project"]["environment"])
    assign_role(database_path, "netshield01", "administrator")

    app_logger.info("Stage 1 foundation initialised successfully")
    audit_logger.info(
        "actor=netshield01 action=initialise_stage1 "
        "target=project result=success"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialise_stage1",
        target="project",
        result="success",
        details="Configuration, logging and database foundation initialised",
    )

    print("PASS: Stage 1 foundation initialised")
    print(f"Database: {database_path}")
    print(f"Application log: {application_log}")
    print(f"Audit log: {audit_log}")


if __name__ == "__main__":
    main()
