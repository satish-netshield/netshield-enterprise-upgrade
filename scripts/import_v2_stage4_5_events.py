"""Import controlled V2 Stage 4 and Stage 5 events."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIRECTORY = PROJECT_ROOT / "data/raw/v2/stage4_5"


def main() -> None:
    """Import Stage 4–5 JSONL files and report totals."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]

    application_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    source_files = sorted(RAW_DIRECTORY.glob("*.jsonl"))

    if not source_files:
        raise FileNotFoundError(
            f"No Stage 4–5 JSONL files found in {RAW_DIRECTORY}"
        )

    summaries = []
    failures = []

    for source_file in source_files:
        try:
            summary = import_jsonl_file(
                database_path=database_path,
                source_file=source_file,
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

    total_records = sum(
        summary["total_records"]
        for summary in summaries
    )
    accepted_records = sum(
        summary["accepted_records"]
        for summary in summaries
    )
    rejected_records = sum(
        summary["rejected_records"]
        for summary in summaries
    )
    failed_files = len(failures)

    details = (
        f"files={len(source_files)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records} "
        f"failed={failed_files}"
    )

    result = (
        "success"
        if failed_files == 0
        else "partial_failure"
    )

    application_logger.info(
        "V2 Stage 4–5 event import completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=import_v2_stage4_5_events "
        "target=security_events "
        "result=%s %s",
        result,
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_v2_stage4_5_events",
        target="security_events",
        result=result,
        details=details,
    )

    print()
    print(f"V2 STAGE 4–5 IMPORT: {details}")

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
