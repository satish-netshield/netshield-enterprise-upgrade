"""Import controlled Phase 3A V2 Stage 6 network events."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Import the Stage 6 network and Wi-Fi JSONL files."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_network_monitoring.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    source_directory = (
        PROJECT_ROOT / configuration["source_directory"]
    )
    source_files = [
        source_directory / filename
        for filename in configuration["source_files"]
    ]

    missing_files = [
        file_path.name
        for file_path in source_files
        if not file_path.is_file()
    ]

    if missing_files:
        raise FileNotFoundError(
            "Missing Stage 6 source files: "
            + ", ".join(sorted(missing_files))
        )

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    summaries = []
    failures = []

    for source_file in source_files:
        try:
            summary = import_jsonl_file(
                database_path,
                source_file,
            )
            summaries.append(summary)
            print(
                f"{summary['source_file']}: "
                f"accepted={summary['accepted_records']} "
                f"rejected={summary['rejected_records']} "
                f"status={summary['status']}"
            )
        except (OSError, UnicodeError, ValueError) as error:
            failures.append(
                {
                    "source_file": source_file.name,
                    "error": str(error),
                }
            )
            print(
                f"{source_file.name}: "
                "accepted=0 rejected=0 status=failed"
            )

    total = sum(
        summary["total_records"]
        for summary in summaries
    )
    accepted = sum(
        summary["accepted_records"]
        for summary in summaries
    )
    rejected = sum(
        summary["rejected_records"]
        for summary in summaries
    )
    failed = len(failures)

    details = (
        f"files={len(summaries)} "
        f"total={total} "
        f"accepted={accepted} "
        f"rejected={rejected} "
        f"failed={failed}"
    )
    result = (
        "success"
        if failed == 0
        else "partial_failure"
    )

    app_logger.info(
        "V2 Stage 6 event import completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=import_v2_stage6_events "
        "target=network_wifi_events "
        "result=%s %s",
        result,
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_v2_stage6_events",
        target="network_wifi_events",
        result=result,
        details=details,
    )

    if failed == 0:
        save_metadata(
            database_path,
            "v2_stage_6_status",
            "network_events_imported",
        )

    print()
    print(f"V2 STAGE 6 IMPORT: {details}")

    if failures:
        for failure in failures:
            print(
                "FAILED: "
                f"{failure['source_file']} | "
                f"{failure['error']}"
            )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
