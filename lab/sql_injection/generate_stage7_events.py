"""Generate controlled Stage 7 correlation events."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = (
    PROJECT_ROOT
    / "lab"
    / "sql_injection"
    / "data"
    / "stage7_correlation_events.jsonl"
)


EVENTS = [
    {
        "source_event_id": "ST7-001",
        "event_time": "2026-08-27T10:00:00+00:00",
        "source_type": "authentication",
        "event_type": "login_failure",
        "detection_type": "Repeated Failed Logins",
        "severity": "Medium",
        "username": "analyst01",
        "ip_address": "192.0.2.44",
        "mac_address": "02:42:ac:11:00:25",
        "hostname": "Analyst-Laptop",
        "location": "Auckland, NZ",
        "device_approved": False,
        "known_vpn": False,
    },
    {
        "source_event_id": "ST7-002",
        "event_time": "2026-08-27T10:02:00+00:00",
        "source_type": "network",
        "event_type": "suspicious_connection",
        "detection_type": "Suspicious IP Address",
        "severity": "Medium",
        "username": "analyst01",
        "ip_address": "192.0.2.44",
        "mac_address": "02:42:ac:11:00:25",
        "hostname": "Analyst-Laptop",
        "location": "Auckland, NZ",
        "device_approved": False,
        "known_vpn": False,
    },
    {
        "source_event_id": "ST7-003",
        "event_time": "2026-08-27T10:04:00+00:00",
        "source_type": "endpoint",
        "event_type": "process_observed",
        "detection_type": "Unknown Endpoint Process",
        "severity": "High",
        "username": "analyst01",
        "ip_address": "192.0.2.44",
        "mac_address": "02:42:ac:11:00:25",
        "hostname": "Analyst-Laptop",
        "process_name": "unknown_loader",
        "location": "Auckland, NZ",
        "device_approved": False,
        "known_vpn": False,
    },
    {
        "source_event_id": "ST7-004",
        "event_time": "2026-08-27T10:06:00+00:00",
        "source_type": "application",
        "event_type": "authentication_bypass_attempt",
        "detection_type": "Authentication Bypass Attempt",
        "severity": "Critical",
        "username": "analyst01",
        "ip_address": "192.0.2.44",
        "mac_address": "02:42:ac:11:00:25",
        "hostname": "Analyst-Laptop",
        "location": "Auckland, NZ",
        "device_approved": False,
        "known_vpn": False,
    },
    {
        "source_event_id": "ST7-005",
        "event_time": "2026-08-27T11:00:00+00:00",
        "source_type": "authentication",
        "event_type": "login_success",
        "detection_type": "Login From New Device",
        "severity": "Medium",
        "username": "vpnuser01",
        "ip_address": "10.0.2.15",
        "mac_address": "08:00:27:cf:49:71",
        "hostname": "VPN-Laptop",
        "location": "Auckland, NZ",
        "device_approved": True,
        "known_vpn": True,
    },
    {
        "source_event_id": "ST7-006",
        "event_time": "2026-08-27T11:03:00+00:00",
        "source_type": "network",
        "event_type": "connection_allowed",
        "detection_type": "Known VPN Activity",
        "severity": "Low",
        "username": "vpnuser01",
        "ip_address": "10.0.2.15",
        "mac_address": "08:00:27:cf:49:71",
        "hostname": "VPN-Laptop",
        "location": "Auckland, NZ",
        "device_approved": True,
        "known_vpn": True,
    },
    {
        "source_event_id": "ST7-007",
        "event_time": "2026-08-27T12:00:00+00:00",
        "source_type": "network",
        "event_type": "connection_attempt",
        "detection_type": "Repeated Connection Attempts",
        "severity": "Medium",
        "username": "unknown01",
        "ip_address": "198.51.100.77",
        "mac_address": "02:42:ac:11:00:77",
        "hostname": "Unknown-Device",
        "location": "Public Area",
        "device_approved": False,
        "known_vpn": False,
    },
]


def main() -> None:
    """Write controlled Stage 7 events to JSONL."""
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as output_file:
        for event in EVENTS:
            output_file.write(
                json.dumps(event, sort_keys=True) + "\n"
            )

    print(
        "PASS: Generated "
        f"{len(EVENTS)} Stage 7 correlation events"
    )
    print(f"OUTPUT_FILE: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
