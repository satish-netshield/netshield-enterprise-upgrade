"""Validate Phase 3A V2 Stage 9 continuous monitoring."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from scripts.initialize_v2_stage9 import (
    INDEXES,
    TABLES,
    validate_configuration,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMPONENTS = {
    "ingestion",
    "identity_detection",
    "access_policy",
    "network_detection",
    "endpoint_detection",
    "vulnerability_management",
    "risk_assessment",
}


def require(condition: bool, message: str) -> None:
    """Raise an assertion when a validation condition fails."""
    if not condition:
        raise AssertionError(message)

    print(f"PASS: {message}")


def utc_timestamp(value: str | None) -> bool:
    """Return True when a timestamp is timezone-aware UTC."""
    if not value:
        return False

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (
        parsed.tzinfo is not None
        and parsed.utcoffset() is not None
        and parsed.utcoffset().total_seconds() == 0
    )


def database_objects(
    connection: sqlite3.Connection,
    object_type: str,
) -> set[str]:
    """Return SQLite object names of one type."""
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = ?",
        (object_type,),
    ).fetchall()
    return {row[0] for row in rows}


def valid_json(value: str, expected_type: type) -> bool:
    """Return True when text contains the expected JSON type."""
    try:
        return isinstance(json.loads(value), expected_type)
    except (TypeError, json.JSONDecodeError):
        return False


def main() -> None:
    """Run every Stage 9 validation check."""
    checks = 0

    def check(condition: bool, message: str) -> None:
        nonlocal checks
        require(condition, message)
        checks += 1

    required_files = [
        PROJECT_ROOT / "config/v2_continuous_monitoring.json",
        PROJECT_ROOT / "scripts/initialize_v2_stage9.py",
        PROJECT_ROOT
        / "scripts/run_v2_stage9_continuous_monitoring.py",
        PROJECT_ROOT / "src/monitoring/__init__.py",
        PROJECT_ROOT / "src/monitoring/v2_risk_sources.py",
        PROJECT_ROOT / "src/monitoring/v2_risk_engine.py",
        PROJECT_ROOT / "src/monitoring/v2_monitoring_health.py",
        PROJECT_ROOT
        / "tests/test_v2_stage9_continuous_monitoring.py",
    ]
    check(
        all(path.is_file() for path in required_files),
        "Stage 9 files exist",
    )

    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_continuous_monitoring.json"
    )
    validate_configuration(configuration)
    check(
        configuration["schedule"]["interval_minutes"] == 15
        and configuration["simulation_only"] is True
        and configuration["evidence_policy"]
        ["preserve_original_evidence"]
        is True
        and configuration["evidence_policy"]
        ["risk_scores_replace_evidence"]
        is False
        and not any(
            configuration["sandbox_policy"].values()
        ),
        "Stage 9 configuration preserves scope and safety",
    )

    tracked_schema = (
        PROJECT_ROOT / "database/schema.sql"
    ).read_text(encoding="utf-8")
    check(
        all(name in tracked_schema for name in TABLES)
        and all(name in tracked_schema for name in INDEXES),
        "Tracked schema contains five Stage 9 tables and 22 indexes",
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]

    with managed_connection(database_path) as connection:
        tables = database_objects(connection, "table")
        indexes = database_objects(connection, "index")
        check(
            TABLES <= tables and INDEXES <= indexes,
            "Stage 9 database tables and named indexes exist",
        )

        cycle = connection.execute(
            """
            SELECT
                cycle_key,
                scheduled_for,
                completed_at,
                status,
                ingestion_status,
                detection_status,
                risk_status,
                last_successful_run,
                records_assessed,
                entities_scored,
                alerts_created,
                alerts_suppressed,
                metrics,
                failure_details
            FROM v2_monitoring_cycles
            ORDER BY cycle_id DESC
            LIMIT 1
            """
        ).fetchone()
        check(
            cycle is not None
            and cycle[3:7]
            == ("completed", "healthy", "healthy", "healthy")
            and cycle[8] == 171
            and cycle[9] == 20
            and cycle[13] is None
            and utc_timestamp(cycle[1])
            and utc_timestamp(cycle[2])
            and utc_timestamp(cycle[7]),
            "A healthy scheduled cycle tracks its last successful run",
        )

        score_rows = connection.execute(
            """
            SELECT
                entity_type,
                entity_id,
                assessed_at,
                risk_score,
                risk_level,
                severity_component,
                confidence_component,
                asset_criticality_component,
                agreement_adjustment,
                exception_adjustment,
                decay_adjustment,
                independent_source_count,
                source_types,
                evidence_refs,
                evidence,
                original_evidence_preserved
            FROM v2_continuous_risk_scores
            """
        ).fetchall()
        check(
            len(score_rows) == 20
            and {row[0] for row in score_rows}
            == {"user", "device", "asset", "incident"}
            and all(0 <= row[3] <= 100 for row in score_rows)
            and all(utc_timestamp(row[2]) for row in score_rows),
            "Twenty current scores cover all four risk entity types",
        )

        calculated_correctly = all(
            abs(
                row[3]
                - max(
                    0,
                    min(
                        100,
                        row[5]
                        + row[6]
                        + row[7]
                        + row[8]
                        + row[9]
                        + row[10],
                    ),
                )
            )
            < 0.01
            for row in score_rows
        )
        check(
            calculated_correctly,
            "Risk scores use severity, confidence and criticality weights",
        )

        check(
            any(row[11] >= 2 and row[8] > 0 for row in score_rows),
            "Independent source agreement increases risk",
        )
        check(
            any(row[9] < 0 for row in score_rows)
            and all(row[9] <= 0 for row in score_rows),
            "Validated exceptions reduce risk without adding points",
        )
        check(
            any(row[10] < 0 for row in score_rows)
            and all(row[10] <= 0 for row in score_rows),
            "Time-based decay reduces older risk",
        )

        evidence_is_preserved = all(
            row[15] == 1
            and valid_json(row[12], list)
            and valid_json(row[13], list)
            and valid_json(row[14], list)
            and json.loads(row[13])
            and json.loads(row[14])
            for row in score_rows
        )
        check(
            evidence_is_preserved,
            "Risk scores retain their original evidence references",
        )

        history_count, unique_history = connection.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT history_key)
            FROM v2_continuous_risk_history
            WHERE cycle_key = ?
            """,
            (cycle[0],),
        ).fetchone()
        check(
            history_count == 20
            and unique_history == 20,
            "Risk history is complete and duplicate-safe per cycle",
        )

        alert_rows = connection.execute(
            """
            SELECT
                alert_type,
                entity_type,
                entity_id,
                risk_score,
                severity,
                status,
                occurrence_count,
                suppression_reason,
                cooldown_until,
                evidence_refs,
                evidence
            FROM v2_monitoring_alerts
            ORDER BY alert_type, entity_type, entity_id
            """
        ).fetchall()
        check(
            len(alert_rows) == 4
            and all(row[0] == "risk_threshold" for row in alert_rows)
            and all(row[3] >= 65 for row in alert_rows)
            and all(row[4] == "High" for row in alert_rows),
            "Four High threshold alerts were created from current risk",
        )
        check(
            all(
                row[5] in {"Suppressed", "Monitoring"}
                and row[6] >= 2
                and (
                    row[5] != "Suppressed"
                    or row[7] == "active_cooldown"
                )
                and utc_timestamp(row[8])
                for row in alert_rows
            ),
            "Repeated alerts retain their cooldown state",
        )
        check(
            all(
                valid_json(row[9], list)
                and json.loads(row[9])
                and valid_json(row[10], dict)
                for row in alert_rows
            ),
            "Suppressed alerts preserve supporting evidence",
        )

        health_rows = connection.execute(
            """
            SELECT
                component,
                status,
                last_successful_run,
                consecutive_failures,
                records_processed,
                details
            FROM v2_detection_health
            WHERE cycle_key = ?
            """,
            (cycle[0],),
        ).fetchall()
        check(
            len(health_rows) == 7
            and {row[0] for row in health_rows}
            == EXPECTED_COMPONENTS
            and all(row[1] == "healthy" for row in health_rows)
            and all(row[3] == 0 for row in health_rows)
            and all(utc_timestamp(row[2]) for row in health_rows),
            "Seven monitored components are healthy",
        )

        metrics = json.loads(cycle[12])
        check(
            metrics["evidence_mappings"] == 171
            and metrics["entities_scored"] == 20
            and metrics["risk_alerts"] == 4
            and metrics["health_alerts"] == 0
            and metrics["health_statuses"] == {"healthy": 7},
            "The cycle stores monitoring summaries and metrics",
        )

        cycle_metrics = [
            (row[0], json.loads(row[1]))
            for row in connection.execute(
                """
                SELECT alerts_suppressed, metrics
                FROM v2_monitoring_cycles
                WHERE status = 'completed'
                """
            ).fetchall()
        ]
        check(
            any(
                suppressed >= 4
                and values.get("alert_storage", {}).get(
                    "suppressed",
                    0,
                )
                >= 4
                for suppressed, values in cycle_metrics
            ),
            "A repeated cycle suppressed four alerts during cooldown",
        )

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage_9_status'
            """
        ).fetchone()
        audit_actions = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT action
                FROM audit_events
                WHERE result = 'success'
                  AND action IN (
                      'initialize_v2_stage9',
                      'run_v2_stage9_continuous_monitoring'
                  )
                """
            ).fetchall()
        }
        check(
            metadata == ("continuous_monitoring_complete",)
            and audit_actions
            == {
                "initialize_v2_stage9",
                "run_v2_stage9_continuous_monitoring",
            },
            "Stage 9 initialisation and monitoring cycles are audited",
        )

        endpoint_count = connection.execute(
            "SELECT COUNT(*) FROM v2_endpoint_alerts"
        ).fetchone()[0]
        vulnerability_count = connection.execute(
            "SELECT COUNT(*) FROM v2_vulnerability_findings"
        ).fetchone()[0]
        check(
            endpoint_count == 26 and vulnerability_count == 7,
            "Stage 7 and Stage 8 evidence remains available",
        )

    print()
    print(f"V2 STAGE 9 VALIDATION: PASS ({checks}/{checks})")


if __name__ == "__main__":
    main()
