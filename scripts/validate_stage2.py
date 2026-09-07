"""Validate the NetShield Stage 2 security-data pipeline."""

import json
import sqlite3
from pathlib import Path
from typing import Callable

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = PROJECT_ROOT / "config/settings.json"

STAGE2_SOURCE_FILES = {
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


def get_database_path() -> Path:
    """Return the configured database path."""
    settings = load_json(SETTINGS_PATH)
    return PROJECT_ROOT / settings["database"]["path"]


def query_all(
    sql: str,
    parameters: tuple = (),
) -> list[tuple]:
    """Run a database query and return every row."""
    with sqlite3.connect(get_database_path()) as connection:
        return connection.execute(
            sql,
            parameters,
        ).fetchall()


def query_one(
    sql: str,
    parameters: tuple = (),
) -> tuple:
    """Run a database query and return one row."""
    rows = query_all(sql, parameters)

    if not rows:
        raise AssertionError("Database query returned no result")

    return rows[0]


def check_required_files() -> None:
    """Confirm that the Stage 2 implementation files exist."""
    required_files = [
        "config/settings.json",
        "database/schema.sql",
        "scripts/generate_stage2_events.py",
        "scripts/import_stage2_events.py",
        "scripts/initialize_stage2.py",
        "scripts/validate_stage2.py",
        "src/collectors/event_normalizer.py",
        "src/collectors/jsonl_collector.py",
        "tests/test_stage2_normalizer.py",
        "tests/test_stage2_pipeline.py",
    ]

    missing_files = [
        filename
        for filename in required_files
        if not (PROJECT_ROOT / filename).is_file()
    ]

    if missing_files:
        raise AssertionError(
            f"Missing Stage 2 files: {missing_files}"
        )


def check_pipeline_configuration() -> None:
    """Confirm that the pipeline configuration remains safe."""
    settings = load_json(SETTINGS_PATH)
    pipeline = settings["pipeline"]
    security = settings["security"]

    expected_sources = {
        "authentication",
        "network",
        "wifi",
        "endpoint",
        "application",
    }

    if settings["project"]["version"] != "0.2.0":
        raise AssertionError("Unexpected project version")

    if pipeline["accepted_extensions"] != [".jsonl"]:
        raise AssertionError("Only JSONL input should be accepted")

    if not expected_sources.issubset(
        set(pipeline["allowed_source_types"])
    ):
        raise AssertionError(
            "Original pipeline source types must remain enabled"
        )

    if not pipeline["reject_malformed_events"]:
        raise AssertionError("Malformed events must be rejected")

    if not pipeline["preserve_raw_event"]:
        raise AssertionError("Raw events must be preserved")

    if security["allow_real_external_targets"]:
        raise AssertionError("Real external targets must remain disabled")


def check_raw_event_files() -> None:
    """Confirm the original Stage 2 source files and record total."""
    raw_directory = PROJECT_ROOT / "data/raw"

    source_files = {
        path.name
        for path in raw_directory.glob("*.jsonl")
        if path.is_file()
    }

    if source_files != STAGE2_SOURCE_FILES:
        raise AssertionError(
            f"Unexpected Stage 2 source files: {sorted(source_files)}"
        )

    total_lines = sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in raw_directory.glob("*.jsonl")
    )

    if total_lines != 19:
        raise AssertionError(
            f"Expected 19 Stage 2 records, found {total_lines}"
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
    """Confirm that the event search indexes exist."""
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
    """Confirm that every completed batch reconciles."""
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
                f"Unexpected batch status: {status}"
            )


def check_accepted_event_counts() -> None:
    """Confirm the original Stage 2 accepted-event baseline."""
    placeholders = ",".join(
        "?" for _ in STAGE2_SOURCE_FILES
    )
    source_files = tuple(sorted(STAGE2_SOURCE_FILES))

    rows = query_all(
        f"""
        SELECT source_type, COUNT(*)
        FROM security_events
        WHERE source_file IN ({placeholders})
        GROUP BY source_type
        ORDER BY source_type
        """,
        source_files,
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
            f"Unexpected Stage 2 event counts: {source_counts}"
        )


def check_rejected_event_reasons() -> None:
    """Confirm the four deliberate Stage 2 rejection types."""
    rows = query_all(
        """
        SELECT reason
        FROM rejected_events
        WHERE source_file IN (
            'application_events.jsonl',
            'authentication_events.jsonl',
            'endpoint_events.jsonl',
            'network_events.jsonl'
        )
        """
    )
    reasons = [row[0] for row in rows]

    expected_text = [
        "Invalid JSON",
        "Required field 'event_id'",
        "cpu_percent",
        "ip_address",
    ]

    for text in expected_text:
        if not any(text in reason for reason in reasons):
            raise AssertionError(
                f"Missing rejection reason: {text}"
            )


def check_utc_normalisation() -> None:
    """Confirm that all accepted timestamps use UTC."""
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
    """Confirm representative MAC, CPU and IP values."""
    mac_address = query_one(
        """
        SELECT mac_address
        FROM security_events
        WHERE source_event_id = 'WIFI-001'
        """
    )[0]

    if mac_address != "08:00:27:cf:49:71":
        raise AssertionError("MAC address was not normalised")

    cpu_percent = query_one(
        """
        SELECT cpu_percent
        FROM security_events
        WHERE source_event_id = 'END-002'
        """
    )[0]

    if cpu_percent != 91.7:
        raise AssertionError("CPU percentage was not preserved")

    ip_address = query_one(
        """
        SELECT ip_address
        FROM security_events
        WHERE source_event_id = 'APP-001'
        """
    )[0]

    if ip_address != "127.0.0.1":
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
        raise AssertionError("No accepted events were preserved")

    for row in rows:
        raw_event = json.loads(row[0])

        if not isinstance(raw_event, dict):
            raise AssertionError(
                "Preserved raw event is not a JSON object"
            )


def check_duplicate_protection() -> None:
    """Confirm that duplicate accepted events do not exist."""
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
    """Confirm that the Stage 2 metadata remains correct."""
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
    """Confirm that the Stage 2 import was audited."""
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
    """Run one check and print its result."""
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
        ("Required Stage 2 files exist", check_required_files),
        (
            "Pipeline configuration is valid and safe",
            check_pipeline_configuration,
        ),
        (
            "Five simulated raw-event files contain 19 records",
            check_raw_event_files,
        ),
        ("Stage 2 SQLite tables exist", check_stage2_tables),
        (
            "Security-event search indexes exist",
            check_security_event_indexes,
        ),
        (
            "Import-batch totals reconcile",
            check_import_batch_integrity,
        ),
        (
            "Stage 2 source files contain accepted records",
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
        ("Stage 2 metadata is correct", check_stage2_metadata),
        (
            "Stage 2 import has an audit record",
            check_stage2_audit_event,
        ),
    ]

    passed_checks = sum(
        run_check(description, function)
        for description, function in checks
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
