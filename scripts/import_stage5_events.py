"""Import the controlled Stage 5 endpoint and network events."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_FILES = [
    PROJECT_ROOT / "data/raw/stage5/endpoint_stage5_events.jsonl",
    PROJECT_ROOT / "data/raw/stage5/network_stage5_events.jsonl",
]


def main() -> None:
    """Import Stage 5 endpoint and network events."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    application_log = (
        PROJECT_ROOT / settings["logging"]["application_log"]
    )
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]

    configure_logger("netshield.application", application_log)
    configure_logger("netshield.audit", audit_log)

    total_records = 0
    accepted_records = 0
    rejected_records = 0

    for source_file in SOURCE_FILES:
        summary = import_jsonl_file(
            database_path,
            source_file,
        )

        total_records += summary["total_records"]
        accepted_records += summary["accepted_records"]
        rejected_records += summary["rejected_records"]

        details = (
            f"file={summary['source_file']} "
            f"total={summary['total_records']} "
            f"accepted={summary['accepted_records']} "
            f"rejected={summary['rejected_records']}"
        )

        record_audit_event(
            database_path=database_path,
            actor="netshield01",
            action="import_stage5_events",
            target="endpoint_network_events",
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
        "STAGE 5 EVENT IMPORT: "
        f"files={len(SOURCE_FILES)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records}"
    )


if __name__ == "__main__":
    main()
