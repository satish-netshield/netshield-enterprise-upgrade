"""Validate the Phase 3A V2 extended security pipeline."""

import json
import sqlite3
from pathlib import Path

from src.collectors.event_normalizer import ALLOWED_SOURCE_TYPES
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
V2_SOURCES = {
    "identity_risk",
    "access_policy",
    "database",
    "vulnerability",
    "incident",
    "response",
}


def print_result(passed: bool, description: str) -> bool:
    """Print and return one validation result."""
    print(f"{'PASS' if passed else 'FAIL'}: {description}")
    return passed


def main() -> None:
    """Run all V2 Stage 2 checks."""
    results: list[bool] = []
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    raw_directory = (
        PROJECT_ROOT / settings["pipeline"]["v2_raw_directory"]
    )
    source_files = sorted(raw_directory.glob("*.jsonl"))

    total_lines = sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in source_files
    )
    results.append(
        print_result(
            len(source_files) == 6 and total_lines == 14,
            "Six V2 JSONL files contain 14 records",
        )
    )

    results.append(
        print_result(
            set(settings["pipeline"]["allowed_source_types"])
            == ALLOWED_SOURCE_TYPES,
            "Configuration and normaliser source types match",
        )
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            )
        }
        rejected_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(rejected_events)"
            )
        }
        indexes = {
            row[1]
            for row in connection.execute(
                "PRAGMA index_list(security_events)"
            )
        }

        accepted_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE schema_version = '2.0'
              AND source_file LIKE '%_v2_events.jsonl'
            """
        ).fetchone()[0]

        source_counts = dict(
            connection.execute(
                """
                SELECT source_type, COUNT(*)
                FROM security_events
                WHERE schema_version = '2.0'
                  AND source_file LIKE '%_v2_events.jsonl'
                GROUP BY source_type
                """
            )
        )

        quarantined = connection.execute(
            """
            SELECT COUNT(
                DISTINCT source_file || '|' || reason || '|' || raw_event
            )
            FROM rejected_events
            WHERE source_file LIKE '%_v2_events.jsonl'
              AND quarantine_status = 'quarantined'
              AND reason NOT LIKE 'Duplicate%'
            """
        ).fetchone()[0]

        utc_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE schema_version = '2.0'
              AND source_file LIKE '%_v2_events.jsonl'
              AND event_time LIKE '%+00:00'
            """
        ).fetchone()[0]

        identified_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE schema_version = '2.0'
              AND source_file LIKE '%_v2_events.jsonl'
              AND source_system != 'unknown'
            """
        ).fetchone()[0]

        raw_rows = connection.execute(
            """
            SELECT raw_event
            FROM security_events
            WHERE schema_version = '2.0'
              AND source_file LIKE '%_v2_events.jsonl'
            """
        ).fetchall()

        completed_batches = connection.execute(
            """
            SELECT COUNT(*)
            FROM import_batches
            WHERE source_file LIKE '%_v2_events.jsonl'
              AND status IN (
                  'completed',
                  'completed_with_rejections'
              )
            """
        ).fetchone()[0]

        audit_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'import_v2_stage2_events'
              AND result = 'success'
            """
        ).fetchone()[0]

    expected_columns = {
        "schema_version",
        "source_system",
        "severity",
        "risk_score",
        "decision",
        "device_id",
        "asset_id",
        "application_id",
        "service_id",
        "finding_id",
        "incident_id",
        "action_id",
    }
    results.append(
        print_result(
            expected_columns.issubset(columns),
            "V2 common event fields exist in SQLite",
        )
    )
    results.append(
        print_result(
            "quarantine_status" in rejected_columns,
            "Rejected events include quarantine status",
        )
    )
    results.append(
        print_result(
            {
                "idx_security_events_schema_version",
                "idx_security_events_source",
                "idx_security_events_device",
                "idx_security_events_incident",
            }.issubset(indexes),
            "V2 investigation indexes exist",
        )
    )
    results.append(
        print_result(
            accepted_count == 12,
            "Twelve valid V2 events are stored",
        )
    )
    results.append(
        print_result(
            set(source_counts) == V2_SOURCES
            and all(count == 2 for count in source_counts.values()),
            "All six V2 sources contain two accepted events",
        )
    )
    results.append(
        print_result(
            quarantined == 2,
            "Two malformed V2 events are quarantined",
        )
    )
    results.append(
        print_result(
            utc_count == 12,
            "All accepted V2 timestamps are stored in UTC",
        )
    )
    results.append(
        print_result(
            identified_count == 12,
            "All accepted V2 events identify their source system",
        )
    )
    results.append(
        print_result(
            len(raw_rows) == 12
            and all(
                json.loads(row[0])["schema_version"] == "2.0"
                for row in raw_rows
            ),
            "Original V2 events are preserved",
        )
    )
    results.append(
        print_result(
            completed_batches >= 6,
            "V2 ingestion batches and statistics are recorded",
        )
    )
    results.append(
        print_result(
            audit_count >= 1,
            "V2 pipeline completion is audited",
        )
    )

    print()
    if all(results):
        print(
            f"V2 STAGE 2 VALIDATION: PASS "
            f"({len(results)}/{len(results)})"
        )
        return

    print(
        "V2 STAGE 2 VALIDATION: FAIL "
        f"({results.count(False)} check(s) failed)"
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
