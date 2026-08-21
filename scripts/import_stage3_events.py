"""Import the controlled Stage 3 identity event set."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = (
    PROJECT_ROOT
    / "data/raw/stage3/authentication_stage3_events.jsonl"
)


def main() -> None:
    """Import the Stage 3 authentication events."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
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

    summary = import_jsonl_file(
        database_path,
        SOURCE_FILE,
    )

    details = (
        f"file={summary['source_file']} "
        f"total={summary['total_records']} "
        f"accepted={summary['accepted_records']} "
        f"rejected={summary['rejected_records']}"
    )

    app_logger.info(
        "Stage 3 identity-event import completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 action=import_stage3_events "
        "target=authentication_events result=success %s",
        details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_stage3_events",
        target="authentication_events",
        result="success",
        details=details,
    )

    print(
        f"{summary['source_file']}: "
        f"accepted={summary['accepted_records']} "
        f"rejected={summary['rejected_records']} "
        f"status={summary['status']}"
    )
    print()
    print(
        "STAGE 3 EVENT IMPORT: "
        f"total={summary['total_records']} "
        f"accepted={summary['accepted_records']} "
        f"rejected={summary['rejected_records']}"
    )


if __name__ == "__main__":
    main()
