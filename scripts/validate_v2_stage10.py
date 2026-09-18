"""Validate Phase 3A V2 Stage 10 XDR-style correlation."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage10 import (
    INDEXES,
    TABLES,
    validate_configuration,
)
from src.correlation.v2_xdr_engine import (
    build_evidence_groups,
    build_incidents,
    build_indicators,
    evidence_link_rows,
    load_xdr_evidence,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


REQUIRED_FILES = {
    "config/v2_xdr_correlation.json",
    "scripts/initialize_v2_stage10.py",
    "scripts/run_v2_stage10_xdr_correlation.py",
    "src/correlation/v2_xdr_engine.py",
    "tests/test_v2_stage10_xdr_correlation.py",
}


def require(condition: bool, message: str) -> None:
    """Raise a clear validation error when a condition fails."""
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}")


def json_value(value: str) -> Any:
    """Parse one stored JSON value."""
    return json.loads(value)


def tracked_stage10_objects(
    schema_path: Path,
) -> tuple[set[str], set[str]]:
    """Return Stage 10 objects created by the tracked schema."""
    schema = schema_path.read_text(encoding="utf-8")

    with closing(
        sqlite3.connect(":memory:")
    ) as connection:
        connection.executescript(schema)

        table_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name LIKE 'v2_xdr_%'
            """
        ).fetchall()

        index_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
              AND name LIKE 'idx_v2_xdr_%'
              AND sql IS NOT NULL
            """
        ).fetchall()

    return (
        {row[0] for row in table_rows},
        {row[0] for row in index_rows},
    )


def database_objects(
    database_path: Path,
) -> tuple[set[str], set[str]]:
    """Return current Stage 10 database objects."""
    with managed_connection(database_path) as connection:
        table_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name LIKE 'v2_xdr_%'
            """
        ).fetchall()

        index_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
              AND name LIKE 'idx_v2_xdr_%'
              AND sql IS NOT NULL
            """
        ).fetchall()

    return (
        {row[0] for row in table_rows},
        {row[0] for row in index_rows},
    )


def main() -> None:
    """Run the complete Stage 10 validation."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    configuration = load_json(
        PROJECT_ROOT / "config/v2_xdr_correlation.json"
    )
    database_path = (
        PROJECT_ROOT
        / settings["database"]["path"]
    )
    schema_path = PROJECT_ROOT / "database/schema.sql"

    missing_files = sorted(
        relative_path
        for relative_path in REQUIRED_FILES
        if not (
            PROJECT_ROOT / relative_path
        ).is_file()
    )
    require(
        not missing_files,
        "Stage 10 files exist",
    )

    validate_configuration(configuration)

    require(
        configuration["correlation"][
            "minimum_independent_sources"
        ]
        == 2
        and configuration["correlation"][
            "mac_address_is_supporting_only"
        ]
        is True
        and configuration["vulnerability_policy"][
            "context_does_not_create_incident"
        ]
        is True
        and configuration["sandbox_policy"][
            "automatic_response_actions_allowed"
        ]
        is False,
        "Stage 10 configuration preserves scope and safety",
    )

    (
        tracked_tables,
        tracked_indexes,
    ) = tracked_stage10_objects(schema_path)

    require(
        tracked_tables == TABLES
        and tracked_indexes == INDEXES,
        (
            "Tracked schema contains three Stage 10 "
            "tables and 14 indexes"
        ),
    )

    (
        current_tables,
        current_indexes,
    ) = database_objects(database_path)

    require(
        TABLES.issubset(current_tables)
        and INDEXES.issubset(current_indexes),
        (
            "Stage 10 database tables and named "
            "indexes exist"
        ),
    )

    evidence = load_xdr_evidence(
        database_path,
        configuration,
    )
    evidence_keys = [
        record["evidence_key"]
        for record in evidence
    ]

    source_counts: dict[str, int] = {}

    for record in evidence:
        source_type = record["source_type"]
        source_counts[source_type] = (
            source_counts.get(source_type, 0) + 1
        )

    require(
        len(evidence) == 76
        and len(evidence_keys)
        == len(set(evidence_keys))
        and set(source_counts)
        == {
            "identity",
            "access_policy",
            "network",
            "endpoint",
            "application",
            "vulnerability",
        },
        (
            "Seventy-six unique records cover six "
            "correlation sources"
        ),
    )

    groups = build_evidence_groups(
        evidence,
        configuration,
    )
    incidents = build_incidents(
        groups,
        configuration,
    )
    links = evidence_link_rows(
        incidents,
        configuration,
    )
    indicators = build_indicators(
        incidents,
        configuration,
    )

    require(
        len(groups) == 10,
        (
            "Primary anchors keep unrelated evidence "
            "in separate groups"
        ),
    )

    require(
        len(incidents) == 3
        and {
            tuple(incident["device_ids"])
            for incident in incidents
        }
        == {
            ("CYOD-001",),
            ("CYOD-002",),
            ("CYOD-003",),
        },
        (
            "Three context-rich incidents preserve "
            "separate device chains"
        ),
    )

    calculated_keys = {
        incident["incident_key"]
        for incident in incidents
    }

    with managed_connection(database_path) as connection:
        stored_incidents = connection.execute(
            """
            SELECT
                incident_key,
                severity,
                confidence,
                independent_source_count,
                evidence_count,
                active_evidence_count,
                exception_count,
                verified_activity_count,
                device_ids,
                attack_techniques,
                behaviours,
                correlation_reasons,
                vulnerability_context,
                evidence_keys,
                evidence,
                original_evidence_preserved
            FROM v2_xdr_incidents
            ORDER BY incident_key
            """
        ).fetchall()

        stored_links = connection.execute(
            """
            SELECT
                evidence_link_key,
                incident_key,
                evidence_key,
                source_type,
                relationship,
                contribution_status,
                source_event_ids,
                correlation_reasons,
                evidence
            FROM v2_xdr_incident_evidence
            ORDER BY evidence_link_key
            """
        ).fetchall()

        stored_indicators = connection.execute(
            """
            SELECT
                indicator_key,
                incident_key,
                indicator_type,
                indicator_value,
                classification,
                source_evidence_keys,
                detection_types,
                evidence
            FROM v2_xdr_indicators
            ORDER BY indicator_key
            """
        ).fetchall()

    require(
        len(stored_incidents) == 3
        and {
            row[0]
            for row in stored_incidents
        }
        == calculated_keys,
        (
            "Stored incidents match the current "
            "correlation result"
        ),
    )

    severity_counts: dict[str, int] = {}

    for row in stored_incidents:
        severity_counts[row[1]] = (
            severity_counts.get(row[1], 0) + 1
        )

    require(
        severity_counts
        == {
            "Critical": 2,
            "Medium": 1,
        }
        and all(
            0 <= row[2] <= 100
            for row in stored_incidents
        )
        and all(
            row[3] >= 2
            for row in stored_incidents
        ),
        (
            "Incident severity and confidence use "
            "independent-source evidence"
        ),
    )

    require(
        len(stored_links) == 65
        and len(
            {
                row[0]
                for row in stored_links
            }
        )
        == 65
        and len(
            {
                (row[1], row[2])
                for row in stored_links
            }
        )
        == 65,
        (
            "Sixty-five incident evidence links "
            "are duplicate-safe"
        ),
    )

    active_keys = {
        row[2]
        for row in stored_links
        if row[5] == "active"
    }

    source_event_tokens = {
        (
            row[3],
            source_event_id,
        )
        for row in stored_links
        if row[5] == "active"
        for source_event_id
        in json_value(row[6])
    }

    require(
        bool(active_keys)
        and bool(source_event_tokens)
        and all(
            row[5]
            in {
                "active",
                "exception",
                "verified",
                "context_only",
            }
            for row in stored_links
        ),
        (
            "Repeated detections retain evidence "
            "without creating score types"
        ),
    )

    require(
        sum(
            row[6]
            for row in stored_incidents
        )
        == 3
        and sum(
            row[7]
            for row in stored_incidents
        )
        == 4
        and all(
            (
                "validated_exception_"
                "reduced_confidence"
            )
            in json_value(row[11])
            for row in stored_incidents
            if row[6] > 0
        )
        and all(
            (
                "verified_activity_"
                "reduced_confidence"
            )
            in json_value(row[11])
            for row in stored_incidents
            if row[7] > 0
        ),
        (
            "Validated exceptions and verified "
            "activity reduce confidence"
        ),
    )

    context_links = [
        row
        for row in stored_links
        if row[5] == "context_only"
    ]

    explicit_links = [
        row
        for row in stored_links
        if row[4] == "explicit_finding_link"
    ]

    require(
        len(context_links) == 3
        and all(
            "vulnerability_context_only"
            in json_value(row[7])
            for row in context_links
        ),
        (
            "Unexploited vulnerabilities remain "
            "investigation context"
        ),
    )

    require(
        bool(explicit_links)
        and any(
            link["linked_record_id"]
            == "S78-END-020"
            and link["exploitation_status"]
            == "successful"
            for row in stored_incidents
            for finding
            in json_value(row[12])
            for link
            in finding["explicit_links"]
        ),
        (
            "The successful SQL finding retains "
            "its explicit alert link"
        ),
    )

    require(
        all(
            row[15] == 1
            for row in stored_incidents
        )
        and all(
            json_value(row[14])[
                "original_evidence_preserved"
            ]
            is True
            for row in stored_incidents
        )
        and all(
            json_value(row[8])
            for row in stored_links
        ),
        (
            "Incidents and links preserve their "
            "original evidence"
        ),
    )

    classifications: dict[str, int] = {}

    for row in stored_indicators:
        classifications[row[4]] = (
            classifications.get(row[4], 0) + 1
        )

    require(
        len(stored_indicators) == 13
        and len(
            {
                row[0]
                for row in stored_indicators
            }
        )
        == 13
        and classifications
        == {
            "ioc": 10,
            "supporting_observable": 3,
        },
        (
            "Ten IoCs and three supporting "
            "observables are duplicate-safe"
        ),
    )

    require(
        all(
            row[4] == "supporting_observable"
            for row in stored_indicators
            if row[2] == "mac_address"
        )
        and not any(
            row[3]
            in {
                "Suspicious Process",
                "Suspicious Command Activity",
                "Possible Persistence Indicator",
            }
            for row in stored_indicators
        ),
        (
            "MAC addresses stay supporting-only "
            "and behaviours are not IoCs"
        ),
    )

    attack_techniques = {
        technique
        for row in stored_incidents
        for technique in json_value(row[9])
    }

    require(
        {
            "T1110.003",
            "T1547",
            "T1190",
        }.issubset(attack_techniques)
        and all(
            json_value(row[10])
            for row in stored_incidents
        ),
        (
            "Relevant ATT&CK mappings and "
            "behaviours remain separate"
        ),
    )

    with managed_connection(database_path) as connection:
        metadata_row = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage_10_status'
            """
        ).fetchone()

        audit_rows = connection.execute(
            """
            SELECT action, result, details
            FROM audit_events
            WHERE action IN (
                'initialize_v2_stage10',
                'run_v2_stage10_xdr_correlation'
            )
            ORDER BY event_id
            """
        ).fetchall()

        stage7_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM v2_endpoint_alerts
            """
        ).fetchone()[0]

        stage8_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM v2_vulnerability_findings
            """
        ).fetchone()[0]

    require(
        metadata_row
        == ("xdr_correlation_complete",)
        and {
            row[0]
            for row in audit_rows
        }
        == {
            "initialize_v2_stage10",
            "run_v2_stage10_xdr_correlation",
        }
        and all(
            row[1] == "success"
            for row in audit_rows
        )
        and any(
            "incidents_existing=3"
            in row[2]
            for row in audit_rows
            if row[0]
            == "run_v2_stage10_xdr_correlation"
        ),
        (
            "Stage 10 initialisation and repeated "
            "correlation are audited"
        ),
    )

    require(
        stage7_count == 26
        and stage8_count == 7,
        (
            "Stage 7 and Stage 8 evidence "
            "remains available"
        ),
    )

    require(
        configuration["sandbox_policy"][
            "automatic_response_actions_allowed"
        ]
        is False
        and all(
            "automatic_actions"
            not in json_value(row[14])
            for row in stored_incidents
        ),
        (
            "Stage 10 creates no automatic "
            "response action"
        ),
    )

    print()
    print(
        "V2 STAGE 10 VALIDATION: PASS (20/20)"
    )


if __name__ == "__main__":
    main()
