"""Run correlated Stage 4 network, CYOD and Wi-Fi detection."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.detectors.network_correlation import (
    correlate_network_alerts,
)
from src.detectors.network_detector import (
    detect_network_activity_all,
    load_cyod_inventory,
    load_ip_list,
    save_network_alerts,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_FILES = {
    "network_stage4_events.jsonl",
    "wifi_stage4_events.jsonl",
    "network_correlation_stage4_events.jsonl",
    "wifi_correlation_stage4_events.jsonl",
}


def load_stage4_events(
    database_path: Path,
    source_files: set[str],
) -> list[dict[str, Any]]:
    """Load Stage 4 events using a dynamic source-file query."""
    placeholders = ", ".join(
        "?" for _ in source_files
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            f"""
            SELECT *
            FROM security_events
            WHERE source_file IN ({placeholders})
            ORDER BY event_time
            """,
            tuple(sorted(source_files)),
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def main() -> None:
    """Run and save correlated Stage 4 detections."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/network_detection.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]

    inventory = load_cyod_inventory(
        PROJECT_ROOT / "data/allowlists/cyod_devices.csv"
    )
    allowlist = load_ip_list(
        PROJECT_ROOT / "data/allowlists/ip_allowlist.txt"
    )
    blocklist = load_ip_list(
        PROJECT_ROOT / "data/blocklists/ip_blocklist.txt"
    )

    events = load_stage4_events(
        database_path,
        SOURCE_FILES,
    )

    raw_alerts = detect_network_activity_all(
        events,
        configuration,
        inventory,
        allowlist,
        blocklist,
    )

    alerts = correlate_network_alerts(
        raw_alerts,
        events,
        configuration,
    )

    created, existing = save_network_alerts(
        database_path,
        alerts,
    )

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"mac={alert.get('mac_address')} | "
            f"events={', '.join(alert['source_event_ids'])}"
        )

    details = (
        f"events={len(events)} "
        f"raw_detections={len(raw_alerts)} "
        f"correlated_alerts={len(alerts)} "
        f"new_alerts={created} "
        f"existing_alerts={existing}"
    )

    logger = configure_logger(
        "netshield.audit",
        audit_log,
    )
    logger.info(
        "actor=netshield01 action=run_stage4_detection "
        "target=network_wifi_events result=success %s",
        details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_stage4_detection",
        target="network_wifi_events",
        result="success",
        details=details,
    )

    with managed_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO system_metadata (key, value)
            VALUES ('stage_4_status', 'detections_complete')
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
            """
        )

    print()
    print(f"STAGE 4 DETECTION: {details}")


if __name__ == "__main__":
    main()
