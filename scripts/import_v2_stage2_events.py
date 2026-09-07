"""Import Phase 3A V2 enterprise-style security events."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Import V2 JSONL files and report pipeline totals."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]
    raw_directory = (
        PROJECT_ROOT / settings["pipeline"]["v2_raw_directory"]
    )

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    source_files = sorted(raw_directory.glob("*.jsonl"))
    if not source_files:
        raise FileNotFoundError(
            f"No V2 JSONL files found in {raw_directory}"
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
                f"accepted=0 rejected=0 status=failed"
            )

    total = sum(item["total_records"] for item in summaries)
    accepted = sum(item["accepted_records"] for item in summaries)
    rejected = sum(item["rejected_records"] for item in summaries)
    failed = len(failures)

    details = (
        f"files={len(summaries)} total={total} "
        f"accepted={accepted} rejected={rejected} failed={failed}"
    )

    app_logger.info("V2 Stage 2 import completed: %s", details)
    audit_logger.info(
        "actor=netshield01 action=import_v2_stage2_events "
        "target=security_events result=success %s",
        details,
    )
    record_audit_event(
        database_path,
        "netshield01",
        "import_v2_stage2_events",
        "security_events",
        "success" if failed == 0 else "partial_failure",
        details,
    )

    print()
    print(f"V2 STAGE 2 IMPORT: {details}")

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
