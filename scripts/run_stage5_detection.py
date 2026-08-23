"""Run Stage 5 endpoint, CPU and wired-access detection."""

from datetime import datetime
from pathlib import Path
from typing import Any

from src.detectors.endpoint_detector import (
    detect_endpoint_activity,
    load_stage5_events,
    load_user_roles,
    save_endpoint_alerts,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_time(value: str) -> datetime:
    """Parse a timezone-aware event timestamp."""
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def group_wired_alerts(
    alerts: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Group repeated wired alerts for one MAC and zone."""
    window_minutes = configuration["thresholds"][
        "lan_access_window_minutes"
    ]

    grouped: dict[
        tuple[str | None, str | None],
        list[dict[str, Any]],
    ] = {}
    remaining = []

    for alert in alerts:
        if alert["detection_type"] != "Restricted Wired Access":
            remaining.append(alert)
            continue

        key = (
            alert.get("mac_address"),
            alert.get("location"),
        )
        grouped.setdefault(key, []).append(alert)

    for key, matching_alerts in grouped.items():
        ordered = sorted(
            matching_alerts,
            key=lambda alert: parse_time(
                alert["first_event_time"]
            ),
        )

        current_group = [ordered[0]]
        group_start = parse_time(
            ordered[0]["first_event_time"]
        )

        def save_group(
            group: list[dict[str, Any]],
        ) -> None:
            if len(group) == 1:
                remaining.append(group[0])
                return

            first = group[0]
            last = group[-1]
            event_ids = []

            for item in group:
                event_ids.extend(
                    item["source_event_ids"]
                )

            first["last_event_time"] = (
                last["last_event_time"]
            )
            first["source_event_ids"] = sorted(
                set(event_ids)
            )
            first["evidence"] = {
                **first["evidence"],
                "observation_count": len(event_ids),
                "grouped_by_mac": key[0],
                "grouped_location": key[1],
                "group_window_minutes": window_minutes,
            }
            remaining.append(first)

        for alert in ordered[1:]:
            alert_time = parse_time(
                alert["first_event_time"]
            )

            if (
                alert_time - group_start
            ).total_seconds() <= window_minutes * 60:
                current_group.append(alert)
            else:
                save_group(current_group)
                current_group = [alert]
                group_start = alert_time

        save_group(current_group)

    remaining.sort(
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
        )
    )
    return remaining


def main() -> None:
    """Run Stage 5 detection and save endpoint alerts."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/endpoint_detection.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    application_log = (
        PROJECT_ROOT / settings["logging"]["application_log"]
    )
    audit_log = (
        PROJECT_ROOT / settings["logging"]["audit_log"]
    )

    app_logger = configure_logger(
        "netshield.application",
        application_log,
    )
    audit_logger = configure_logger(
        "netshield.audit",
        audit_log,
    )

    events = load_stage5_events(database_path)
    user_roles = load_user_roles(
        database_path,
        configuration,
    )

    alerts = detect_endpoint_activity(
        events,
        configuration,
        user_roles,
    )
    alerts = group_wired_alerts(
        alerts,
        configuration,
    )

    created, existing = save_endpoint_alerts(
        database_path,
        alerts,
    )

    save_metadata(
        database_path,
        "stage_5_status",
        "detections_complete",
    )

    details = (
        f"events={len(events)} "
        f"detections={len(alerts)} "
        f"new_alerts={created} "
        f"existing_alerts={existing}"
    )

    app_logger.info(
        "Stage 5 endpoint detection completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 action=run_stage5_detection "
        "target=endpoint_detection result=success %s",
        details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_stage5_detection",
        target="endpoint_detection",
        result="success",
        details=details,
    )

    for alert in alerts:
        event_ids = ", ".join(
            alert["source_event_ids"]
        )
        identifier = (
            alert.get("mac_address")
            or alert.get("username")
            or "unknown"
        )

        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"identity={identifier} | "
            f"events={event_ids}"
        )

    print()
    print(
        "STAGE 5 DETECTION: "
        f"events={len(events)} "
        f"detections={len(alerts)} "
        f"new_alerts={created} "
        f"existing_alerts={existing}"
    )


if __name__ == "__main__":
    main()
