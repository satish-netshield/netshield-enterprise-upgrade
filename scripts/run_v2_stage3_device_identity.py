"""Run Phase 3A V2 Stage 3 device identity detection."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
from pathlib import Path
from typing import Any

from src.assets.device_identity import (
    evaluate_device_event,
    load_known_devices,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_device_events(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load normalised events that contain usable device identity context."""

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                source_event_id,
                event_time,
                source_type,
                event_type,
                device_id,
                asset_id,
                username,
                ip_address,
                mac_address,
                hostname,
                location
            FROM security_events
            WHERE schema_version = '2.0'
              AND (
                    device_id IS NOT NULL
                    OR asset_id IN (
                        SELECT asset_id
                        FROM device_inventory
                    )
                  )
            ORDER BY event_time, source_event_id
            """
        ).fetchall()

    return [dict(row) for row in rows]


def main() -> None:
    """Evaluate stored V2 events against enterprise device context."""

    settings = load_json(PROJECT_ROOT / "config/settings.json")
    device_config = load_json(
        PROJECT_ROOT / "config/device_identity.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    stale_device_days = device_config["stale_device_days"]
    known_devices = load_known_devices(enterprise_context)

    events = load_device_events(database_path)

    finding_count = 0
    detection_counts: dict[str, int] = {}

    for event in events:
        findings = evaluate_device_event(
            database_path=database_path,
            event=event,
            stale_device_days=stale_device_days,
            known_devices=known_devices,
        )

        finding_count += len(findings)

        for finding in findings:
            detection_type = finding["detection_type"]
            detection_counts[detection_type] = (
                detection_counts.get(detection_type, 0) + 1
            )

    with managed_connection(database_path) as connection:
        stored_alert_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM device_alerts
            """
        ).fetchone()[0]

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage3_device_identity",
        target="security_events",
        result="success",
        details=(
            f"events_evaluated={len(events)} "
            f"findings={finding_count} "
            f"stored_alerts={stored_alert_count}"
        ),
    )

    print("PASS: V2 Stage 3 device identity detection completed")
    print(f"Events evaluated: {len(events)}")
    print(f"Findings generated: {finding_count}")
    print(f"Stored device alerts: {stored_alert_count}")

    if detection_counts:
        print("Detection summary:")

        for detection_type in sorted(detection_counts):
            print(
                f"  {detection_type}: "
                f"{detection_counts[detection_type]}"
            )
    else:
        print("Detection summary: no device findings")


if __name__ == "__main__":
    main()
