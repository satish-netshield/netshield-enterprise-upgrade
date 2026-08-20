"""Import all supported Stage 2 security-event files."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Import JSONL event files and report accepted and rejected totals."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    raw_directory = PROJECT_ROOT / settings["pipeline"]["raw_directory"]
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

    source_files = sorted(raw_directory.glob("*.jsonl"))

    if not source_files:
        raise FileNotFoundError(
            f"No JSONL files found in {raw_directory}"
        )

    total_records = 0
    accepted_records = 0
    rejected_records = 0

    for source_file in source_files:
        summary = import_jsonl_file(
            database_path,
            source_file,
        )

        total_records += summary["total_records"]
        accepted_records += summary["accepted_records"]
        rejected_records += summary["rejected_records"]

        print(
            f"{summary['source_file']}: "
            f"accepted={summary['accepted_records']} "
            f"rejected={summary['rejected_records']} "
            f"status={summary['status']}"
        )

    details = (
        f"files={len(source_files)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records}"
    )

    app_logger.info(
        "Stage 2 security-event import completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 action=import_stage2_events "
        "target=security_events result=success %s",
        details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_stage2_events",
        target="security_events",
        result="success",
        details=details,
    )

    print()
    print(
        f"STAGE 2 IMPORT: "
        f"files={len(source_files)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records}"
    )


if __name__ == "__main__":
    main()
