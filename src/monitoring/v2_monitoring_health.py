"""Monitor Stage 9 ingestion, detection and risk-component health."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.monitoring.v2_risk_engine import (
    json_text,
    stable_key,
)
from src.utils.sqlite_connection import managed_connection


COMPONENT_TABLES = {
    "identity_detection": "v2_identity_alerts",
    "access_policy": "access_policy_decisions",
    "network_detection": "v2_network_alerts",
    "endpoint_detection": "v2_endpoint_alerts",
    "vulnerability_management": (
        "v2_vulnerability_findings"
    ),
}


def previous_component_state(
    database_path: Path,
    component: str,
) -> tuple[str | None, int]:
    """Return last success and previous consecutive failures."""
    with managed_connection(
        database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT
                last_successful_run,
                consecutive_failures
            FROM v2_detection_health
            WHERE component = ?
            ORDER BY checked_at DESC, health_id DESC
            LIMIT 1
            """,
            (component,),
        ).fetchone()

    if row is None:
        return None, 0

    return row[0], row[1]


def result_for_status(
    database_path: Path,
    component: str,
    status: str,
    checked_at: str,
    records_processed: int,
    details: dict[str, Any],
) -> dict[str, Any]:
    """Build health state while retaining failure history."""
    (
        previous_success,
        previous_failures,
    ) = previous_component_state(
        database_path,
        component,
    )

    if status == "healthy":
        last_successful_run = checked_at
        consecutive_failures = 0
    else:
        last_successful_run = previous_success
        consecutive_failures = (
            previous_failures + 1
        )

    return {
        "status": status,
        "last_successful_run": (
            last_successful_run
        ),
        "consecutive_failures": (
            consecutive_failures
        ),
        "records_processed": (
            records_processed
        ),
        "details": details,
    }


def evaluate_ingestion_health(
    database_path: Path,
    checked_at: str,
) -> dict[str, Any]:
    """Evaluate completed and failed import batches."""
    component = "ingestion"

    try:
        with managed_connection(
            database_path
        ) as connection:
            (
                total,
                failures,
                accepted,
            ) = connection.execute(
                """
                SELECT
                    COUNT(*),
                    COALESCE(
                        SUM(
                            CASE
                                WHEN status = 'failed'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),
                    COALESCE(
                        SUM(accepted_records),
                        0
                    )
                FROM import_batches
                """
            ).fetchone()

        if failures:
            status = "failed"
        elif total == 0:
            status = "degraded"
        else:
            status = "healthy"

        return result_for_status(
            database_path,
            component,
            status,
            checked_at,
            accepted,
            {
                "import_batches": total,
                "failed_batches": failures,
                "accepted_records": accepted,
            },
        )
    except Exception as error:
        return result_for_status(
            database_path,
            component,
            "failed",
            checked_at,
            0,
            {
                "error_type": (
                    type(error).__name__
                ),
                "error": str(error),
            },
        )


def evaluate_table_component(
    database_path: Path,
    component: str,
    table_name: str,
    checked_at: str,
) -> dict[str, Any]:
    """Check that a detection table is readable and populated."""
    if (
        table_name
        not in COMPONENT_TABLES.values()
    ):
        raise ValueError(
            f"Unsupported health table: {table_name}"
        )

    try:
        with managed_connection(
            database_path
        ) as connection:
            count = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM {table_name}
                """
            ).fetchone()[0]

        status = (
            "healthy"
            if count > 0
            else "degraded"
        )

        return result_for_status(
            database_path,
            component,
            status,
            checked_at,
            count,
            {
                "table": table_name,
                "records_available": count,
            },
        )
    except Exception as error:
        return result_for_status(
            database_path,
            component,
            "failed",
            checked_at,
            0,
            {
                "table": table_name,
                "error_type": (
                    type(error).__name__
                ),
                "error": str(error),
            },
        )


def evaluate_component_health(
    database_path: Path,
    checked_at: str,
    risk_records: int,
) -> dict[str, dict[str, Any]]:
    """Evaluate every required Stage 9 component."""
    results = {
        "ingestion": evaluate_ingestion_health(
            database_path,
            checked_at,
        )
    }

    for (
        component,
        table_name,
    ) in COMPONENT_TABLES.items():
        results[
            component
        ] = evaluate_table_component(
            database_path,
            component,
            table_name,
            checked_at,
        )

    risk_status = (
        "healthy"
        if risk_records > 0
        else "degraded"
    )
    results[
        "risk_assessment"
    ] = result_for_status(
        database_path,
        "risk_assessment",
        risk_status,
        checked_at,
        risk_records,
        {
            "entities_scored": (
                risk_records
            )
        },
    )

    return results


def save_component_health(
    database_path: Path,
    cycle_key: str,
    checked_at: str,
    results: dict[str, dict[str, Any]],
) -> dict[str, int]:
    """Store one duplicate-safe health row per cycle component."""
    created = 0
    existing = 0

    with managed_connection(
        database_path
    ) as connection:
        for (
            component,
            result,
        ) in sorted(results.items()):
            health_key = stable_key(
                "v2-detection-health",
                cycle_key,
                component,
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO
                    v2_detection_health (
                        health_key,
                        cycle_key,
                        component,
                        checked_at,
                        status,
                        last_successful_run,
                        consecutive_failures,
                        records_processed,
                        details
                    )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    health_key,
                    cycle_key,
                    component,
                    checked_at,
                    result["status"],
                    result[
                        "last_successful_run"
                    ],
                    result[
                        "consecutive_failures"
                    ],
                    result[
                        "records_processed"
                    ],
                    json_text(
                        result["details"]
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return {
        "created": created,
        "existing": existing,
    }


def build_health_alerts(
    results: dict[str, dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create failure or persistent degradation alerts."""
    policy = configuration[
        "health_monitoring"
    ]
    alerts: list[dict[str, Any]] = []

    for (
        component,
        result,
    ) in sorted(results.items()):
        status = result["status"]
        failures = result[
            "consecutive_failures"
        ]

        if (
            status == "failed"
            and failures
            >= policy[
                "pipeline_failure_alert_after"
            ]
        ):
            alert_type = "pipeline_failure"
            severity = "High"
        elif (
            status == "degraded"
            and failures
            >= policy[
                "detection_unhealthy_after_failures"
            ]
        ):
            alert_type = "detection_health"
            severity = "Medium"
        else:
            continue

        alerts.append(
            {
                "alert_key": stable_key(
                    "v2-monitoring-alert",
                    alert_type,
                    component,
                ),
                "alert_type": alert_type,
                "entity_type": None,
                "entity_id": None,
                "component": component,
                "risk_score": None,
                "threshold": None,
                "severity": severity,
                "independent_source_count": 0,
                "source_types": [
                    component
                ],
                "evidence_refs": [
                    component
                ],
                "evidence": {
                    "component": component,
                    "status": status,
                    "consecutive_failures": (
                        failures
                    ),
                    "details": result[
                        "details"
                    ],
                },
            }
        )

    return alerts
