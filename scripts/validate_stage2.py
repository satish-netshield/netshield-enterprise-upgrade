"""Validate the complete NetShield Stage 2 security-data pipeline."""

import json
import sqlite3
from pathlib import Path
from typing import Callable

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = PROJECT_ROOT / "config/settings.json"
SCHEMA_PATH = PROJECT_ROOT / "database/schema.sql"

EXPECTED_SOURCE_FILES = {
    "application_events.jsonl",
    "authentication_events.jsonl",
    "endpoint_events.jsonl",
    "network_events.jsonl",
    "wifi_events.jsonl",
}

EXPECTED_TABLES = {
    "import_batches",
    "rejected_events",
    "security_events",
}

EXPECTED_INDEXES = {
    "idx_security_events_ip",
    "idx_security_events_mac",
    "idx_security_events_time",
    "idx_security_events_type",
    "idx_security_events_username",
}


def database_path() -> Path:
    """Return the configured SQLite database path."""
    settings = load_json(SETTINGS_PATH)
    return PROJECT_ROOT / settings["database"]["path"]


def query_one(sql: str) -> tuple:
    """Run a database query and return one result row."""
    with sqlite3.connect(database_path()) as connection:
        result = connection.execute(sql).fetchone()

    if result is None:
        raise AssertionError("Database query returned no result")

    return result


def query_all(sql: str) -> list[tuple]:
    """Run a database query and return every result row."""
    with sqlite3.connect(database_path()) as connection:
        return connection.execute(sql).fetchall()


def check_required_files() -> None:
    """Confirm that the Stage 2 implementation files exist."""
    required_files = [
        PROJECT_ROOT / "src/collectors/event_normalizer.py",
        PROJECT_ROOT / "src/collectors/jsonl_collector.py",
        PROJECT_ROOT / "scripts/initialize_stage2.py",
        PROJECT_ROOT / "scripts/generate_stage2_events.py",
        PROJECT_ROOT / "scripts/import_stage2_events.py",
        PROJECT_ROOT / "tests/test_stage2_normalizer.py",
        PROJECT_ROOT / "tests/test_stage2_pipeline.py",
        SCHEMA_PATH,
        SETTINGS_PATH,
    ]

    missing_files = [
        str(path.relative_to(PROJECT_ROOT))
        for path in required_files
        if not path.is_file()
    ]

    if missing_files:
        raise AssertionError(
            f"Missing Stage 2 files: {missing_files}"
        )


def check_pipeline_configuration() -> None:
    """Confirm that the Stage 2 pipeline settings are safe."""
    settings = load_json(SETTINGS_PATH)
    pipeline = settings["pipeline"]
    security = settings["security"]

    if settings["project"]["version"] != "0.2.0":
        raise AssertionError("Unexpected project version")

    if pipeline["accepted_extensions"] != [".jsonl"]:
        raise AssertionError("Only JSONL input should be accepted")

    expected_sources = {
        "authentication",
        "network",
        "wifi",
        "endpoint",
        "application",
    }

    if set(pipeline["allowed_source_types"]) != expected_sources:
        raise AssertionError("Unexpected pipeline source types")

    if not pipeline["reject_malformed_events"]:
        raise AssertionError("Malformed events must be rejected")

    if not pipeline["preserve_raw_event"]:
        raise AssertionError("Raw event preservation must remain enabled")

    if security["allow_real_external_targets"]:
        raise AssertionError("Real external targets must remain disabled")


def check_raw_event_files() -> None:
    """Confirm that all five simulated source files exist."""
    raw_directory = PROJECT_ROOT / "data/raw"

    source_files = {
        path.name
        for path in raw_directory.glob("*.jsonl")
        if path.is_file()
    }

    if source_files != EXPECTED_SOURCE_FILES:
        raise AssertionError(
            f"Unexpected source files: {sorted(source_files)}"
        )

    total_lines = sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in raw_directory.glob("*.jsonl")
    )

    if total_lines != 19:
        raise AssertionError(
            f"Expected 19 simulated records, found {total_lines}"
        )


def check_stage2_tables() -> None:
    """Confirm that the Stage 2 database tables exist."""
    rows = query_all(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    )
    table_names = {row[0] for row in rows}

    missing_tables = EXPECTED_TABLES - table_names

    if missing_tables:
        raise AssertionError(
            f"Missing Stage 2 tables: {sorted(missing_tables)}"
        )


def check_security_event_indexes() -> None:
    """Confirm that searchable event indexes exist."""
    rows = query_all(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'index'
        """
    )
    index_names = {row[0] for row in rows}

    missing_indexes = EXPECTED_INDEXES - index_names

    if missing_indexes:
        raise AssertionError(
            f"Missing Stage 2 indexes: {sorted(missing_indexes)}"
        )


def check_import_batch_integrity() -> None:
    """Confirm that batch totals reconcile correctly."""
    rows = query_all(
        """
        SELECT
            total_records,
            accepted_records,
            rejected_records,
            status
        FROM import_batches
        """
    )

    if len(rows) < 5:
        raise AssertionError("Expected at least five import batches")

    valid_statuses = {
        "completed",
        "completed_with_rejections",
    }

    for total, accepted, rejected, status in rows:
        if total != accepted + rejected:
            raise AssertionError(
                "Import-batch totals do not reconcile"
            )

        if status not in valid_statuses:
            raise AssertionError(
                f"Unexpected completed batch status: {status}"
            )


def check_accepted_event_counts() -> None:
    """Confirm that all five event sources were imported."""
    rows = query_all(
        """
        SELECT source_type, COUNT(*)
        FROM security_events
        GROUP BY source_type
        ORDER BY source_type
        """
    )
    source_counts = dict(rows)

    expected_counts = {
        "application": 3,
        "authentication": 3,
        "endpoint": 3,
        "network": 3,
        "wifi": 3,
    }

    if source_counts != expected_counts:
        raise AssertionError(
            f"Unexpected accepted-event counts: {source_counts}"
        )


def check_rejected_event_reasons() -> None:
    """Confirm that malformed inputs were preserved with reasons."""
    rows = query_all(
        """
        SELECT reason
        FROM rejected_events
        """
    )
    reasons = [row[0] for row in rows]

    expected_reason_text = [
        "Invalid JSON",
        "Required field 'event_id'",
        "cpu_percent",
        "ip_address",
    ]

    for expected_text in expected_reason_text:
        if not any(expected_text in reason for reason in reasons):
            raise AssertionError(
                f"Missing rejection reason: {expected_text}"
            )


def check_utc_normalisation() -> None:
    """Confirm that every accepted timestamp is stored in UTC."""
    total_events = query_one(
        "SELECT COUNT(*) FROM security_events"
    )[0]
    utc_events = query_one(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE event_time LIKE '%+00:00'
        """
    )[0]

    if total_events != utc_events:
        raise AssertionError(
            "Not all accepted timestamps are stored in UTC"
        )


def check_field_normalisation() -> None:
    """Confirm representative IP, MAC and CPU values."""
    wifi_row = query_one(
        """
        SELECT mac_address
        FROM security_events
        WHERE source_event_id = 'WIFI-001'
        """
    )

    if wifi_row[0] != "08:00:27:cf:49:71":
        raise AssertionError("MAC address was not normalised")

    endpoint_row = query_one(
        """
        SELECT cpu_percent
        FROM security_events
        WHERE source_event_id = 'END-002'
        """
    )

    if endpoint_row[0] != 91.7:
        raise AssertionError("CPU percentage was not preserved")

    application_row = query_one(
        """
        SELECT ip_address
        FROM security_events
        WHERE source_event_id = 'APP-001'
        """
    )

    if application_row[0] != "127.0.0.1":
        raise AssertionError("IP address was not preserved")


def check_raw_event_preservation() -> None:
    """Confirm that accepted raw events remain valid JSON."""
    rows = query_all(
        """
        SELECT raw_event
        FROM security_events
        """
    )

    if not rows:
        raise AssertionError("No accepted raw events were preserved")

    for row in rows:
        raw_event = json.loads(row[0])

        if not isinstance(raw_event, dict):
            raise AssertionError(
                "Preserved raw event is not a JSON object"
            )


def check_duplicate_protection() -> None:
    """Confirm that the source file and event ID are unique."""
    rows = query_all(
        """
        SELECT source_file, source_event_id, COUNT(*)
        FROM security_events
        GROUP BY source_file, source_event_id
        HAVING COUNT(*) > 1
        """
    )

    if rows:
        raise AssertionError("Duplicate security events were stored")


def check_stage2_metadata() -> None:
    """Confirm that Stage 2 metadata was recorded."""
    version = query_one(
        """
        SELECT value
        FROM system_metadata
        WHERE key = 'project_version'
        """
    )[0]
    stage_status = query_one(
        """
        SELECT value
        FROM system_metadata
        WHERE key = 'stage_2_status'
        """
    )[0]

    if version != "0.2.0":
        raise AssertionError("Stage 2 version metadata is incorrect")

    if stage_status != "initialised":
        raise AssertionError("Stage 2 status metadata is incorrect")


def check_stage2_audit_event() -> None:
    """Confirm that the event import was audited."""
    audit_count = query_one(
        """
        SELECT COUNT(*)
        FROM audit_events
        WHERE action = 'import_stage2_events'
          AND result = 'success'
        """
    )[0]

    if audit_count < 1:
        raise AssertionError("Stage 2 import audit event is missing")


def run_check(
    description: str,
    check_function: Callable[[], None],
) -> bool:
    """Run one validation check and print its result."""
    try:
        check_function()
    except Exception as error:
        print(f"FAIL: {description}")
        print(f"      {error}")
        return False

    print(f"PASS: {description}")
    return True


def main() -> None:
    """Run every Stage 2 validation check."""
    checks = [
        (
            "Required Stage 2 files exist",
            check_required_files,
        ),
        (
            "Pipeline configuration is valid and safe",
            check_pipeline_configuration,
        ),
        (
            "Five simulated raw-event files contain 19 records",
            check_raw_event_files,
        ),
        (
            "Stage 2 SQLite tables exist",
            check_stage2_tables,
        ),
        (
            "Security-event search indexes exist",
            check_security_event_indexes,
        ),
        (
            "Import-batch totals reconcile",
            check_import_batch_integrity,
        ),
        (
            "Five event sources contain accepted records",
            check_accepted_event_counts,
        ),
        (
            "Malformed records preserve rejection reasons",
            check_rejected_event_reasons,
        ),
        (
            "Accepted timestamps are normalised to UTC",
            check_utc_normalisation,
        ),
        (
            "IP, MAC and CPU fields are normalised",
            check_field_normalisation,
        ),
        (
            "Accepted raw events are preserved",
            check_raw_event_preservation,
        ),
        (
            "Duplicate-event protection is active",
            check_duplicate_protection,
        ),
        (
            "Stage 2 metadata is correct",
            check_stage2_metadata,
        ),
        (
            "Stage 2 import has an audit record",
            check_stage2_audit_event,
        ),
    ]

    passed_checks = sum(
        run_check(description, check_function)
        for description, check_function in checks
    )
    total_checks = len(checks)

    print()

    if passed_checks != total_checks:
        print(
            f"STAGE 2 VALIDATION: "
            f"FAIL ({passed_checks}/{total_checks})"
        )
        raise SystemExit(1)

    print(
        f"STAGE 2 VALIDATION: "
        f"PASS ({passed_checks}/{total_checks})"
    )


if __name__ == "__main__":
    main()
