"""Run Phase 3A V2 Stage 7 endpoint monitoring."""

from collections import Counter
from pathlib import Path
from typing import Any

from src.detectors.v2_endpoint_monitor import (
    build_isolation_requests,
    detect_endpoint_activity,
    is_approved_exception,
    load_device_inventory,
    load_stage7_events,
    save_activity_timeline,
    save_endpoint_alerts,
    save_isolation_requests,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_stored_isolation_records(
    database_path: Path,
    isolation_requests: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Load the current stored state of calculated isolation requests."""
    isolation_keys = [
        request["isolation_key"]
        for request in isolation_requests
    ]

    if not isolation_keys:
        return {}

    placeholders = ", ".join("?" for _ in isolation_keys)

    with managed_connection(database_path) as connection:
        rows = connection.execute(
            f"""
            SELECT
                isolation_key,
                status,
                approved_by,
                approved_at,
                network_state_changed,
                real_action_executed
            FROM v2_endpoint_isolation_actions
            WHERE isolation_key IN ({placeholders})
            """,
            isolation_keys,
        ).fetchall()

    return {
        row[0]: {
            "status": row[1],
            "approved_by": row[2],
            "approved_at": row[3],
            "network_state_changed": row[4],
            "real_action_executed": row[5],
        }
        for row in rows
    }


def main() -> None:
    """Run Stage 7 detections and store controlled results."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    configuration = load_json(
        PROJECT_ROOT / "config/v2_endpoint_monitoring.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )

    events = load_stage7_events(
        database_path,
        configuration["source_files"],
    )
    inventory = load_device_inventory(database_path)
    alerts = detect_endpoint_activity(
        events,
        configuration,
        inventory,
    )
    isolation_requests = build_isolation_requests(
        alerts,
        configuration,
        automation_acl,
    )

    timeline_created, timeline_existing = (
        save_activity_timeline(
            database_path,
            events,
        )
    )
    alerts_created, alerts_existing = (
        save_endpoint_alerts(
            database_path,
            alerts,
        )
    )
    isolation_created, isolation_existing = (
        save_isolation_requests(
            database_path,
            isolation_requests,
        )
    )
    stored_isolation_records = (
        load_stored_isolation_records(
            database_path,
            isolation_requests,
        )
    )

    approved_exceptions = sum(
        1
        for event in events
        if is_approved_exception(
            event,
            configuration,
        )
    )
    severity_counts = Counter(
        alert["severity"]
        for alert in alerts
    )
    detection_counts = Counter(
        alert["detection_type"]
        for alert in alerts
    )

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"device={alert['device_id']} | "
            f"process="
            f"{alert['process_name'] or 'not_applicable'} | "
            f"confidence={alert['confidence']} | "
            f"reasons="
            f"{','.join(alert['reason_codes'])}"
        )

    print()
    for request in isolation_requests:
        stored_record = stored_isolation_records.get(
            request["isolation_key"]
        )

        if stored_record is None:
            raise RuntimeError(
                "Calculated isolation request was not found "
                "after storage"
            )

        print(
            "[ISOLATION RECORD] "
            f"device={request['device_id']} | "
            f"action={request['action']} | "
            f"status={stored_record['status']} | "
            f"approved_by="
            f"{stored_record['approved_by'] or 'not_approved'} | "
            f"real_action="
            f"{bool(stored_record['real_action_executed'])!s} | "
            f"network_change="
            f"{bool(stored_record['network_state_changed'])!s}"
        )

    details = (
        f"events={len(events)} "
        f"alerts={len(alerts)} "
        f"new_alerts={alerts_created} "
        f"existing_alerts={alerts_existing} "
        f"detection_types={len(detection_counts)} "
        f"critical={severity_counts['Critical']} "
        f"high={severity_counts['High']} "
        f"medium={severity_counts['Medium']} "
        f"low={severity_counts['Low']} "
        f"timeline_new={timeline_created} "
        f"timeline_existing={timeline_existing} "
        f"isolation_requests={len(isolation_requests)} "
        f"isolation_new={isolation_created} "
        f"isolation_existing={isolation_existing} "
        f"approved_exceptions={approved_exceptions} "
        "real_actions=0 "
        "network_changes=0"
    )

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT
        / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT
        / settings["logging"]["audit_log"],
    )

    app_logger.info(
        "V2 Stage 7 endpoint monitoring completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=run_v2_stage7_endpoint_monitoring "
        "target=endpoint_monitoring "
        "result=success %s",
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage7_endpoint_monitoring",
        target="endpoint_monitoring",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage_7_status",
        "endpoint_monitoring_complete",
    )

    print()
    print(
        "V2 STAGE 7 ENDPOINT MONITORING: "
        f"{details}"
    )


if __name__ == "__main__":
    main()
