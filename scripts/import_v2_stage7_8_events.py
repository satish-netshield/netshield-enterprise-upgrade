"""Import controlled Phase 3A V2 Stage 7 and Stage 8 events."""

from pathlib import Path
from typing import Any

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def configured_source_files() -> list[str]:
    """Return the configured Stage 7 and Stage 8 source filenames."""
    endpoint_configuration = load_json(
        PROJECT_ROOT / "config/v2_endpoint_monitoring.json"
    )
    vulnerability_configuration = load_json(
        PROJECT_ROOT / "config/v2_vulnerability_management.json"
    )

    source_files = [
        *endpoint_configuration["source_files"],
        *vulnerability_configuration["source_files"],
    ]

    if len(source_files) != 3:
        raise ValueError("Stage 7-8 requires exactly three source files")

    if len(source_files) != len(set(source_files)):
        raise ValueError("Stage 7-8 source filenames must be unique")

    return source_files


def summary_details(
    totals: dict[str, int],
) -> str:
    """Return one stable summary for logs and the audit trail."""
    return (
        f"files={totals['files']} "
        f"total={totals['total']} "
        f"accepted={totals['accepted']} "
        f"rejected={totals['rejected']} "
        f"failed={totals['failed']}"
    )


def main() -> None:
    """Import the three controlled Stage 7-8 JSONL files."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]
    source_directory = PROJECT_ROOT / "data/raw/v2/stage7_8"
    source_files = configured_source_files()

    totals = {
        "files": len(source_files),
        "total": 0,
        "accepted": 0,
        "rejected": 0,
        "failed": 0,
    }
    failures: list[str] = []

    for filename in source_files:
        source_path = source_directory / filename

        try:
            summary: dict[str, Any] = import_jsonl_file(
                database_path,
                source_path,
            )
        except (OSError, UnicodeError, ValueError) as error:
            totals["failed"] += 1
            failures.append(f"{filename}: {error}")
            print(f"{filename}: failed error={error}")
            continue

        totals["total"] += summary["total_records"]
        totals["accepted"] += summary["accepted_records"]
        totals["rejected"] += summary["rejected_records"]

        print(
            f"{filename}: "
            f"accepted={summary['accepted_records']} "
            f"rejected={summary['rejected_records']} "
            f"status={summary['status']}"
        )

    details = summary_details(totals)
    result = "success" if totals["failed"] == 0 else "failed"

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    app_logger.info(
        "V2 Stage 7-8 event import completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=import_v2_stage7_8_events "
        "target=stage7_8_event_pipeline "
        "result=%s %s",
        result,
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_v2_stage7_8_events",
        target="stage7_8_event_pipeline",
        result=result,
        details=details,
    )

    print()
    print(f"V2 STAGE 7-8 IMPORT: {details}")

    if failures:
        raise SystemExit(
            "Stage 7-8 import failed: " + "; ".join(failures)
        )


if __name__ == "__main__":
    main()
