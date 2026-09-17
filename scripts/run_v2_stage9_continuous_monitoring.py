"""Run Phase 3A V2 Stage 9 continuous monitoring."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.monitoring.v2_monitoring_health import (
    build_health_alerts,
    evaluate_component_health,
    save_component_health,
)
from src.monitoring.v2_risk_engine import (
    build_risk_alerts,
    calculate_risk_scores,
    close_resolved_risk_alerts,
    json_text,
    save_risk_alerts,
    save_risk_scores,
    stable_key,
)
from src.monitoring.v2_risk_sources import (
    load_continuous_evidence,
    parse_time,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def arguments() -> argparse.Namespace:
    """Return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run the controlled Stage 9 monitoring cycle.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Repeat the current scheduled cycle for controlled testing.",
    )
    parser.add_argument(
        "--at",
        help="Optional timezone-aware assessment time for testing.",
    )
    return parser.parse_args()


def utc_now() -> str:
    """Return the current UTC time."""
    return datetime.now(timezone.utc).isoformat()


def scheduled_time(
    assessed_at: str,
    interval_minutes: int,
) -> str:
    """Return the UTC start of the assessment interval."""
    current = parse_time(assessed_at)
    minute = (
        current.minute // interval_minutes
    ) * interval_minutes
    scheduled = current.replace(
        minute=minute,
        second=0,
        microsecond=0,
    )
    return scheduled.isoformat()


def last_successful_run(database_path: Path) -> str | None:
    """Return the last completed healthy cycle time."""
    with managed_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT completed_at
            FROM v2_monitoring_cycles
            WHERE status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
            """
        ).fetchone()

    return row[0] if row else None


def start_cycle(
    database_path: Path,
    cycle_key: str,
    scheduled_for: str,
    started_at: str,
    force: bool,
) -> bool:
    """Start a new interval or optionally repeat it."""
    with managed_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT status
            FROM v2_monitoring_cycles
            WHERE cycle_key = ?
            """,
            (cycle_key,),
        ).fetchone()

        if row and not force:
            return False

        if row:
            connection.execute(
                """
                UPDATE v2_monitoring_cycles
                SET started_at = ?,
                    completed_at = NULL,
                    status = 'running',
                    ingestion_status = 'not_started',
                    detection_status = 'not_started',
                    risk_status = 'not_started',
                    metrics = '{}',
                    failure_details = NULL
                WHERE cycle_key = ?
                """,
                (started_at, cycle_key),
            )
        else:
            connection.execute(
                """
                INSERT INTO v2_monitoring_cycles (
                    cycle_key,
                    scheduled_for,
                    started_at,
                    status,
                    ingestion_status,
                    detection_status,
                    risk_status,
                    last_successful_run,
                    metrics
                )
                VALUES (
                    ?, ?, ?, 'running',
                    'not_started', 'not_started', 'not_started',
                    ?, '{}'
                )
                """,
                (
                    cycle_key,
                    scheduled_for,
                    started_at,
                    last_successful_run(database_path),
                ),
            )

    return True


def combined_detection_status(
    health: dict[str, dict[str, Any]],
) -> str:
    """Return the worst detection-component status."""
    components = (
        "identity_detection",
        "access_policy",
        "network_detection",
        "endpoint_detection",
        "vulnerability_management",
    )
    statuses = {
        health[component]["status"]
        for component in components
    }

    if "failed" in statuses:
        return "failed"
    if "degraded" in statuses:
        return "degraded"
    return "healthy"


def complete_cycle(
    database_path: Path,
    cycle_key: str,
    completed_at: str,
    health: dict[str, dict[str, Any]],
    records_assessed: int,
    entities_scored: int,
    alerts_created: int,
    alerts_suppressed: int,
    metrics: dict[str, Any],
) -> str:
    """Complete the cycle and return its final status."""
    ingestion_status = health["ingestion"]["status"]
    detection_status = combined_detection_status(health)
    risk_status = health["risk_assessment"]["status"]
    component_statuses = {
        result["status"]
        for result in health.values()
    }

    if "failed" in component_statuses:
        status = "failed"
        successful_at = last_successful_run(database_path)
    elif "degraded" in component_statuses:
        status = "completed_with_warnings"
        successful_at = last_successful_run(database_path)
    else:
        status = "completed"
        successful_at = completed_at

    with managed_connection(database_path) as connection:
        connection.execute(
            """
            UPDATE v2_monitoring_cycles
            SET completed_at = ?,
                status = ?,
                ingestion_status = ?,
                detection_status = ?,
                risk_status = ?,
                last_successful_run = ?,
                records_assessed = ?,
                entities_scored = ?,
                alerts_created = ?,
                alerts_suppressed = ?,
                metrics = ?,
                failure_details = NULL
            WHERE cycle_key = ?
            """,
            (
                completed_at,
                status,
                ingestion_status,
                detection_status,
                risk_status,
                successful_at,
                records_assessed,
                entities_scored,
                alerts_created,
                alerts_suppressed,
                json_text(metrics),
                cycle_key,
            ),
        )

    return status


def fail_cycle(
    database_path: Path,
    cycle_key: str,
    completed_at: str,
    component: str,
    error: Exception,
) -> None:
    """Record a failed cycle without hiding the exception."""
    details = {
        "component": component,
        "error_type": type(error).__name__,
        "error": str(error),
    }

    with managed_connection(database_path) as connection:
        connection.execute(
            """
            UPDATE v2_monitoring_cycles
            SET completed_at = ?,
                status = 'failed',
                risk_status = 'failed',
                failure_details = ?
            WHERE cycle_key = ?
            """,
            (
                completed_at,
                json_text(details),
                cycle_key,
            ),
        )


def build_pipeline_failure_alert(
    cycle_key: str,
    component: str,
    error: Exception,
) -> dict[str, Any]:
    """Build a controlled alert for a failed monitoring cycle."""
    return {
        "alert_key": stable_key(
            "v2-monitoring-alert",
            "pipeline_failure",
            component,
        ),
        "alert_type": "pipeline_failure",
        "entity_type": None,
        "entity_id": None,
        "component": component,
        "risk_score": None,
        "threshold": None,
        "severity": "High",
        "source_types": [component],
        "evidence_references": [cycle_key],
        "evidence": {
            "cycle_key": cycle_key,
            "component": component,
            "error_type": type(error).__name__,
            "error": str(error),
            "real_action_executed": False,
        },
    }


def print_results(
    records: list[dict[str, Any]],
    risk_alerts: list[dict[str, Any]],
    health: dict[str, dict[str, Any]],
) -> None:
    """Print current scores, alerts and component health."""
    for record in sorted(
        records,
        key=lambda item: (
            -item["risk_score"],
            item["entity_type"],
            item["entity_id"],
        ),
    ):
        print(
            f"[{record['risk_level']}] "
            f"{record['entity_type']}={record['entity_id']} | "
            f"score={record['risk_score']:.2f} | "
            f"sources={record['independent_source_count']} | "
            f"agreement={record['agreement_adjustment']} | "
            f"exceptions={record['exception_adjustment']} | "
            f"decay={record['decay_adjustment']}"
        )

    print()

    for alert in risk_alerts:
        print(
            "[RISK ALERT] "
            f"type={alert['alert_type']} | "
            f"entity={alert['entity_type']}:{alert['entity_id']} | "
            f"score={alert['risk_score']:.2f} | "
            f"severity={alert['severity']}"
        )

    print()

    for component, result in sorted(health.items()):
        print(
            "[HEALTH] "
            f"component={component} | "
            f"status={result['status']} | "
            f"records={result['records_processed']} | "
            f"failures={result['consecutive_failures']}"
        )


def main() -> None:
    """Run one scheduled Stage 9 monitoring interval."""
    options = arguments()
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_continuous_monitoring.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]
    assessed_at = options.at or utc_now()
    parse_time(assessed_at)
    scheduled_for = scheduled_time(
        assessed_at,
        configuration["schedule"]["interval_minutes"],
    )
    cycle_key = stable_key("v2-monitoring-cycle", scheduled_for)

    if not start_cycle(
        database_path,
        cycle_key,
        scheduled_for,
        assessed_at,
        options.force,
    ):
        print(
            "V2 STAGE 9 CONTINUOUS MONITORING: "
            f"cycle={cycle_key} status=suppressed_cooldown "
            f"scheduled_for={scheduled_for}"
        )
        return

    component = "detection"

    try:
        evidence, source_counts = load_continuous_evidence(
            database_path,
            enterprise_context,
        )
        component = "risk_assessment"
        records = calculate_risk_scores(
            evidence,
            configuration,
            assessed_at,
        )
        score_counts = save_risk_scores(
            database_path,
            cycle_key,
            records,
        )
        risk_alerts = build_risk_alerts(
            records,
            configuration,
        )

        component = "health_monitoring"
        health = evaluate_component_health(
            database_path,
            assessed_at,
            len(records),
        )
        health_counts = save_component_health(
            database_path,
            cycle_key,
            assessed_at,
            health,
        )
        health_alerts = build_health_alerts(
            health,
            configuration,
        )
        alert_counts = save_risk_alerts(
            database_path,
            risk_alerts + health_alerts,
            configuration,
            assessed_at,
        )
        alerts_closed = close_resolved_risk_alerts(
            database_path,
            records,
            configuration,
            assessed_at,
        )

        level_counts = Counter(
            record["risk_level"]
            for record in records
        )
        health_status_counts = Counter(
            result["status"]
            for result in health.values()
        )
        metrics = {
            "source_records": source_counts,
            "evidence_mappings": len(evidence),
            "entities_scored": len(records),
            "risk_levels": dict(level_counts),
            "risk_alerts": len(risk_alerts),
            "health_alerts": len(health_alerts),
            "score_storage": score_counts,
            "health_storage": health_counts,
            "alert_storage": alert_counts,
            "alerts_closed": alerts_closed,
            "health_statuses": dict(health_status_counts),
        }
        completed_at = utc_now()
        status = complete_cycle(
            database_path,
            cycle_key,
            completed_at,
            health,
            len(evidence),
            len(records),
            alert_counts["created"],
            alert_counts["suppressed"],
            metrics,
        )

        details = (
            f"cycle={cycle_key} status={status} "
            f"evidence={len(evidence)} "
            f"entities={len(records)} "
            f"risk_alerts={len(risk_alerts)} "
            f"health_alerts={len(health_alerts)} "
            f"alerts_new={alert_counts['created']} "
            f"alerts_suppressed={alert_counts['suppressed']} "
            f"last_successful_run={completed_at if status == 'completed' else last_successful_run(database_path)}"
        )

        application_logger = configure_logger(
            "netshield.application",
            PROJECT_ROOT / settings["logging"]["application_log"],
        )
        audit_logger = configure_logger(
            "netshield.audit",
            PROJECT_ROOT / settings["logging"]["audit_log"],
        )
        application_logger.info(
            "V2 Stage 9 continuous monitoring completed: %s",
            details,
        )
        audit_logger.info(
            "actor=netshield01 "
            "action=run_v2_stage9_continuous_monitoring "
            "target=continuous_monitoring result=success %s",
            details,
        )
        record_audit_event(
            database_path=database_path,
            actor="netshield01",
            action="run_v2_stage9_continuous_monitoring",
            target="continuous_monitoring",
            result="success",
            details=details,
        )
        save_metadata(
            database_path,
            "v2_stage_9_status",
            "continuous_monitoring_complete",
        )

        print_results(records, risk_alerts, health)
        print()
        print(f"V2 STAGE 9 CONTINUOUS MONITORING: {details}")
    except Exception as error:
        completed_at = utc_now()
        fail_cycle(
            database_path,
            cycle_key,
            completed_at,
            component,
            error,
        )
        try:
            save_risk_alerts(
                database_path,
                [
                    build_pipeline_failure_alert(
                        cycle_key,
                        component,
                        error,
                    )
                ],
                configuration,
                completed_at,
            )
        except Exception:
            # Preserve and re-raise the original pipeline failure. A database
            # failure can also prevent its monitoring alert from being stored.
            pass
        record_audit_event(
            database_path=database_path,
            actor="netshield01",
            action="run_v2_stage9_continuous_monitoring",
            target="continuous_monitoring",
            result="failed",
            details=(
                f"cycle={cycle_key} component={component} "
                f"error_type={type(error).__name__} error={error}"
            ),
        )
        raise


if __name__ == "__main__":
    main()
