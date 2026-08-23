"""Generate additional Stage 4 correlation test events."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = PROJECT_ROOT / "data/raw/stage4"


NETWORK_EVENTS = [
    {
        "event_id": "NET4-REPEAT-001",
        "event_time": "2026-08-23T09:00:00+12:00",
        "event_type": "connection_attempt",
        "hostname": "Rapid-Connector",
        "ip_address": "203.0.113.90",
        "mac_address": "02:42:ac:11:00:55",
        "source_type": "network",
        "status": "observed",
        "connection_type": "wired",
    },
    {
        "event_id": "NET4-REPEAT-002",
        "event_time": "2026-08-23T09:00:20+12:00",
        "event_type": "connection_attempt",
        "hostname": "Rapid-Connector",
        "ip_address": "203.0.113.90",
        "mac_address": "02:42:ac:11:00:55",
        "source_type": "network",
        "status": "observed",
        "connection_type": "wired",
    },
    {
        "event_id": "NET4-REPEAT-003",
        "event_time": "2026-08-23T09:00:40+12:00",
        "event_type": "connection_attempt",
        "hostname": "Rapid-Connector",
        "ip_address": "203.0.113.90",
        "mac_address": "02:42:ac:11:00:55",
        "source_type": "network",
        "status": "observed",
        "connection_type": "wired",
    },
    {
        "event_id": "NET4-REPEAT-004",
        "event_time": "2026-08-23T09:01:00+12:00",
        "event_type": "connection_attempt",
        "hostname": "Rapid-Connector",
        "ip_address": "203.0.113.90",
        "mac_address": "02:42:ac:11:00:55",
        "source_type": "network",
        "status": "observed",
        "connection_type": "wired",
    },
    {
        "event_id": "NET4-REPEAT-005",
        "event_time": "2026-08-23T09:01:20+12:00",
        "event_type": "connection_attempt",
        "hostname": "Rapid-Connector",
        "ip_address": "203.0.113.90",
        "mac_address": "02:42:ac:11:00:55",
        "source_type": "network",
        "status": "observed",
        "connection_type": "wired",
    },
]


WIFI_EVENTS = [
    {
        "event_id": "WIFI4-REUSE-001",
        "event_time": "2026-08-23T09:02:00+12:00",
        "event_type": "device_observed",
        "hostname": "Copied-MAC-Laptop",
        "username": "unknown-user",
        "location": "Lab Zone B",
        "mac_address": "08:00:27:cf:49:71",
        "source_type": "wifi",
        "status": "unknown",
        "ssid": "NetShield-Lab",
        "security_mode": "WPA3",
        "cipher": "AES",
        "access_point_id": "AP-LAB-01",
        "connection_type": "wireless",
    }
]


def write_events(filename: str, events: list[dict]) -> None:
    """Write a source-specific event file."""
    path = OUTPUT_DIRECTORY / filename

    with path.open("w", encoding="utf-8") as event_file:
        for event in events:
            event_file.write(json.dumps(event) + "\n")

    print(
        f"CREATED: {path.relative_to(PROJECT_ROOT)} "
        f"({len(events)} records)"
    )


def main() -> None:
    """Create additional correlation scenarios."""
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    write_events(
        "network_correlation_stage4_events.jsonl",
        NETWORK_EVENTS,
    )
    write_events(
        "wifi_correlation_stage4_events.jsonl",
        WIFI_EVENTS,
    )

    print("PASS: Generated Stage 4 correlation events")
    print(
        "Total records: "
        f"{len(NETWORK_EVENTS) + len(WIFI_EVENTS)}"
    )


if __name__ == "__main__":
    main()
