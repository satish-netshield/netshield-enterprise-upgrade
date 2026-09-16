"""Validate Phase 3A V2 Stage 8 vulnerability management."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage7_8 import (
    validate_vulnerability_configuration,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TABLES = {
    "v2_vulnerability_findings",
    "v2_vulnerability_remediation_history",
    "v2_vulnerability_links",
}
REQUIRED_INDEXES = {
    "idx_v2_vulnerability_findings_source",
    "idx_v2_vulnerability_findings_asset",
    "idx_v2_vulnerability_findings_type",
    "idx_v2_vulnerability_findings_severity",
    "idx_v2_vulnerability_findings_priority",
    "idx_v2_vulnerability_findings_status",
    "idx_v2_vulnerability_findings_updated",
    "idx_v2_vulnerability_history_finding",
    "idx_v2_vulnerability_history_status",
    "idx_v2_vulnerability_history_time",
    "idx_v2_vulnerability_links_finding",
    "idx_v2_vulnerability_links_type",
    "idx_v2_vulnerability_links_record",
}
REQUIRED_FINDING_TYPES = {
    "sql_injection",
    "security_header_configuration",
    "vulnerable_dependency",
    "outdated_package",
    "exposed_service_configuration",
    "version_match_only",
    "local_file_permission_check",
}


def pass_check(message: str) -> None:
    """Print one successful validation result."""
    print(f"PASS: {message}")


def require(condition: bool, message: str) -> None:
    """Raise an assertion when a validation condition fails."""
    if not condition:
        raise AssertionError(message)

    pass_check(message)


def database_objects(
    database_path: Path,
    object_type: str,
) -> set[str]:
    """Return names of one SQLite object type."""
    with managed_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = ?
            """,
            (object_type,),
        ).fetchall()

    return {row[0] for row in rows}


def tracked_schema_objects() -> tuple[set[str], set[str]]:
    """Load table and named-index objects from tracked schema."""
    schema = (PROJECT_ROOT / "database/schema.sql").read_text(
        encoding="utf-8"
    )

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(schema)
        table_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name LIKE 'v2_vulnerability_%'
            """
        ).fetchall()
        index_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
              AND sql IS NOT NULL
              AND tbl_name LIKE 'v2_vulnerability_%'
            """
        ).fetchall()

    return (
        {row[0] for row in table_rows},
        {row[0] for row in index_rows},
    )


def load_raw_events(
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Load the tracked Stage 8 controlled events."""
    events: list[dict[str, Any]] = []

    for source_file in configuration["source_files"]:
        source_path = (
            PROJECT_ROOT
            / "data/raw/v2/stage7_8"
            / source_file
        )

        with source_path.open(encoding="utf-8") as handle:
            events.extend(
                json.loads(line)
                for line in handle
                if line.strip()
            )

    return events


def main() -> None:
    """Run Stage 8 validation checks."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_vulnerability_management.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / configuration["enterprise_context_path"]
    )
    lab_report = load_json(
        PROJECT_ROOT
        / configuration["sql_injection_lab"]["report_path"]
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    required_files = (
        PROJECT_ROOT / "config/v2_vulnerability_management.json",
        PROJECT_ROOT
        / "data/raw/v2/stage7_8"
        / "application_security_v2_stage7_8_events.jsonl",
        PROJECT_ROOT
        / "data/raw/v2/stage7_8"
        / "vulnerability_v2_stage7_8_events.jsonl",
        PROJECT_ROOT
        / "src/detectors/v2_vulnerability_manager.py",
        PROJECT_ROOT
        / "scripts/run_v2_stage8_vulnerability_management.py",
        PROJECT_ROOT
        / "scripts/review_v2_stage8_vulnerability_finding.py",
        PROJECT_ROOT
        / "tests/test_v2_stage8_vulnerability_management.py",
        PROJECT_ROOT
        / configuration["sql_injection_lab"]["report_path"],
    )
    require(
        all(path.is_file() for path in required_files),
        "Stage 8 files exist",
    )

    validate_vulnerability_configuration(
        configuration,
        settings,
        enterprise_context,
    )
    require(
        configuration["simulation_only"] is True
        and configuration["linking_policy"][
            "auto_create_incident"
        ]
        is False
        and configuration["sandbox_policy"][
            "real_external_targets_allowed"
        ]
        is False,
        "Stage 8 configuration preserves the agreed boundaries",
    )

    events = load_raw_events(configuration)
    require(
        len(events) == 16
        and len({event["event_id"] for event in events}) == 16
        and sum(
            event["source_type"] == "application"
            for event in events
        )
        == 6
        and sum(
            event["source_type"] == "vulnerability"
            for event in events
        )
        == 10,
        "Two Stage 8 source files contain 16 unique events",
    )

    tracked_tables, tracked_indexes = tracked_schema_objects()
    require(
        tracked_tables == REQUIRED_TABLES
        and tracked_indexes == REQUIRED_INDEXES,
        "Tracked schema contains three Stage 8 tables and 13 indexes",
    )

    require(
        REQUIRED_TABLES <= database_objects(database_path, "table")
        and REQUIRED_INDEXES <= database_objects(
            database_path,
            "index",
        ),
        "Stage 8 database tables and named indexes exist",
    )

    with managed_connection(database_path) as connection:
        stored_event_rows = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT source_event_id)
            FROM security_events
            WHERE source_file IN (?, ?)
            """,
            tuple(configuration["source_files"]),
        ).fetchone()

        finding_rows = connection.execute(
            """
            SELECT
                source_finding_id,
                finding_key,
                asset_id,
                finding_type,
                severity,
                confidence,
                confidence_level,
                exploitability,
                exploitation_status,
                exposure_level,
                exposed_service,
                asset_criticality,
                priority_score,
                priority_level,
                remediation_status,
                verification_status,
                verified_at,
                classification,
                reviewed_by,
                evidence
            FROM v2_vulnerability_findings
            ORDER BY source_finding_id
            """
        ).fetchall()

        history_rows = connection.execute(
            """
            SELECT
                source_finding_id,
                source_event_id,
                previous_status,
                new_status,
                verification_result,
                history_key
            FROM v2_vulnerability_remediation_history
            ORDER BY history_id
            """
        ).fetchall()

        link_rows = connection.execute(
            """
            SELECT
                source_finding_id,
                link_type,
                linked_record_id,
                exploitation_status,
                evidence,
                link_key
            FROM v2_vulnerability_links
            ORDER BY link_type
            """
        ).fetchall()

        metadata_row = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage_8_status'
            """
        ).fetchone()

        audit_actions = {
            row[0]
            for row in connection.execute(
                """
                SELECT action
                FROM audit_events
                WHERE action IN (
                    'initialize_v2_stage7_8',
                    'import_v2_stage7_8_events',
                    'run_v2_stage8_vulnerability_management',
                    'review_v2_stage8_vulnerability_finding'
                )
                  AND result = 'success'
                """
            ).fetchall()
        }

    require(
        stored_event_rows == (16, 16),
        "Sixteen Stage 8 events are stored once",
    )

    finding_ids = {row[0] for row in finding_rows}
    finding_keys = {row[1] for row in finding_rows}
    finding_types = {row[3] for row in finding_rows}
    authoritative_assets = {
        asset["asset_id"]
        for asset in enterprise_context.get("assets", [])
    }
    require(
        len(finding_rows) == 7
        and len(finding_ids) == 7
        and len(finding_keys) == 7
        and {row[2] for row in finding_rows}
        <= authoritative_assets
        and finding_types == REQUIRED_FINDING_TYPES,
        "Seven duplicate-safe findings use authoritative asset context",
    )

    priority_counts = {
        level: sum(row[13] == level for row in finding_rows)
        for level in ("Critical", "High", "Medium", "Low")
    }
    sql_finding = next(
        row for row in finding_rows if row[0] == "S78-FND-SQL-001"
    )
    require(
        priority_counts
        == {"Critical": 0, "High": 1, "Medium": 4, "Low": 2}
        and sql_finding[4] == "High"
        and sql_finding[7] == "demonstrated"
        and sql_finding[8] == "successful"
        and sql_finding[12] == 71.05
        and sql_finding[13] == "High",
        "Priority scoring preserves original risk evidence",
    )

    status_counts = {
        status: sum(row[14] == status for row in finding_rows)
        for status in (
            "Open",
            "Planned",
            "Verified",
            "False Positive",
        )
    }
    require(
        status_counts
        == {
            "Open": 1,
            "Planned": 2,
            "Verified": 3,
            "False Positive": 1,
        }
        and len(history_rows) == 13
        and len({row[5] for row in history_rows}) == 13,
        "Remediation states and duplicate-safe history are preserved",
    )

    dependency_history = [
        row[3]
        for row in history_rows
        if row[0] == "S78-FND-DEP-001"
    ]
    dependency_finding = next(
        row for row in finding_rows if row[0] == "S78-FND-DEP-001"
    )
    require(
        dependency_history
        == [
            "Open",
            "Planned",
            "In Progress",
            "Remediated",
            "Verified",
        ]
        and dependency_finding[15] == "not_detected_after_update"
        and dependency_finding[16] is not None
        and sql_finding[15] == "blocked"
        and sql_finding[16] is not None,
        "Remediation verification retains later supporting evidence",
    )

    false_positive = next(
        row for row in finding_rows if row[0] == "S78-FND-FP-001"
    )
    require(
        false_positive[14] == "False Positive"
        and false_positive[17] == "False Positive"
        and false_positive[18] == "analyst01"
        and any(
            row[1] == "review:S78-FND-FP-001"
            and row[3] == "False Positive"
            for row in history_rows
        ),
        "False-positive review is recorded without deleting evidence",
    )

    approved_test_ids = {
        event["event_id"]
        for event in events
        if event.get("controlled_testing") is True
    }
    require(
        approved_test_ids
        == {"S78-APPSEC-TEST-001", "S78-VULN-TEST-001"}
        and "S78-FND-TEST-001" not in finding_ids
        and "S78-FND-TEST-002" not in finding_ids
        and all(
            event["external_target"] is False
            for event in events
        ),
        "Approved testing remains evidence and uses no external targets",
    )

    require(
        len(link_rows) == 2
        and len({row[5] for row in link_rows}) == 2
        and {row[1] for row in link_rows}
        == {"alert", "incident"}
        and all(row[3] == "successful" for row in link_rows)
        and all(
            json.loads(row[4]).get("shared_evidence")
            for row in link_rows
        ),
        "Finding-to-alert and finding-to-incident links retain evidence",
    )

    incident_link = next(
        row for row in link_rows if row[1] == "incident"
    )
    incident_evidence = json.loads(incident_link[4])
    require(
        configuration["linking_policy"]["auto_create_incident"]
        is False
        and incident_evidence["automatic_incident_creation"]
        is False
        and incident_link[3]
        in configuration["linking_policy"][
            "accepted_exploitation_states"
        ],
        "A finding does not automatically become an incident",
    )

    sql_evidence = json.loads(sql_finding[19])
    require(
        lab_report["sandbox_boundary"]["external_targets_used"]
        is False
        and lab_report["request_analysis"][
            "vulnerable_authentication_bypasses"
        ]
        == 4
        and lab_report["request_analysis"][
            "parameterised_retests_blocked"
        ]
        == 1
        and "sql_injection_lab_report" in sql_evidence,
        "Controlled SQL injection evidence and blocked retest are preserved",
    )

    require(
        metadata_row == ("vulnerability_management_complete",)
        and audit_actions
        == {
            "initialize_v2_stage7_8",
            "import_v2_stage7_8_events",
            "run_v2_stage8_vulnerability_management",
            "review_v2_stage8_vulnerability_finding",
        },
        "Stage 8 initialisation, import, run and review are audited",
    )

    print()
    print("V2 STAGE 8 VALIDATION: PASS (16/16)")


if __name__ == "__main__":
    main()
