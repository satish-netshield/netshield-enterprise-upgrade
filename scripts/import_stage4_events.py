"""Import all Stage 4 network and Wi-Fi event sets."""

from pathlib import Path

from src.collectors.jsonl_collector import import_jsonl_file
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_FILES = [
    PROJECT_ROOT / "data/raw/stage4/network_stage4_events.jsonl",
    PROJECT_ROOT / "data/raw/stage4/wifi_stage4_events.jsonl",
    PROJECT_ROOT
    / "data/raw/stage4/network_correlation_stage4_events.jsonl",
    PROJECT_ROOT
    / "data/raw/stage4/wifi_correlation_stage4_events.jsonl",
]


def main() -> None:
    """Import all Stage 4 network and Wi-Fi events."""
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

    summaries = []

    for source_file in SOURCE_FILES:
        summary = import_jsonl_file(
            database_path,
            source_file,
        )
        summaries.append(summary)

        details = (
            f"file={summary['source_file']} "
            f"total={summary['total_records']} "
            f"accepted={summary['accepted_records']} "
            f"rejected={summary['rejected_records']}"
        )

        app_logger.info(
            "Stage 4 event import completed: %s",
            details,
        )

        print(
            f"{summary['source_file']}: "
            f"accepted={summary['accepted_records']} "
            f"rejected={summary['rejected_records']} "
            f"status={summary['status']}"
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

    audit_details = (
        f"files={len(summaries)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records}"
    )

    audit_logger.info(
        "actor=netshield01 action=import_stage4_events "
        "target=network_wifi_events result=success %s",
        audit_details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="import_stage4_events",
        target="network_wifi_events",
        result="success",
        details=audit_details,
    )

    print()
    print(
        "STAGE 4 EVENT IMPORT: "
        f"files={len(summaries)} "
        f"total={total_records} "
        f"accepted={accepted_records} "
        f"rejected={rejected_records}"
    )


if __name__ == "__main__":
    main()
