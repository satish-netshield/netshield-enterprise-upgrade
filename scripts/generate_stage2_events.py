"""Generate safe simulated security events for Stage 2."""

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIRECTORY = PROJECT_ROOT / "data/raw"


def write_jsonl(
    file_path: Path,
    events: list[dict[str, Any] | str],
) -> None:
    """Write simulated events and deliberate malformed records."""
    with file_path.open("w", encoding="utf-8") as output_file:
        for event in events:
            if isinstance(event, str):
                output_file.write(event + "\n")
            else:
                output_file.write(
                    json.dumps(event, sort_keys=True) + "\n"
                )


def main() -> None:
    """Create safe authentication, network and endpoint test logs."""
    RAW_DIRECTORY.mkdir(parents=True, exist_ok=True)

    authentication_events = [
        {
            "event_id": "AUTH-001",
            "event_time": "2026-08-20T08:00:00+12:00",
            "source_type": "authentication",
            "event_type": "login_success",
            "username": "netshield01",
            "ip_address": "10.0.2.15",
            "hostname": "Ubuntu-NetShield",
            "location": "Auckland, NZ",
            "status": "success",
        },
        {
            "event_id": "AUTH-002",
            "event_time": "2026-08-20T08:05:00+12:00",
            "source_type": "authentication",
            "event_type": "login_failure",
            "username": "analyst01",
            "ip_address": "10.0.2.25",
            "hostname": "Analyst-Laptop",
            "location": "Auckland, NZ",
            "status": "failed",
        },
        {
            "event_id": "AUTH-003",
            "event_time": "2026-08-20T08:06:00+12:00",
            "source_type": "authentication",
            "event_type": "mfa_failure",
            "username": "analyst01",
            "ip_address": "10.0.2.25",
            "hostname": "Analyst-Laptop",
            "location": "Auckland, NZ",
            "status": "failed",
        },
        {
            "event_time": "2026-08-20T08:07:00+12:00",
            "source_type": "authentication",
            "event_type": "login_failure",
            "username": "missing-id-user",
        },
    ]

    network_events = [
        {
            "event_id": "NET-001",
            "event_time": "2026-08-20T08:10:00+12:00",
            "source_type": "network",
            "event_type": "connection_allowed",
            "ip_address": "10.0.2.15",
            "hostname": "Ubuntu-NetShield",
            "status": "allowed",
        },
        {
            "event_id": "NET-002",
            "event_time": "2026-08-20T08:11:00+12:00",
            "source_type": "network",
            "event_type": "connection_attempt",
            "ip_address": "192.0.2.50",
            "hostname": "Unknown-Device",
            "status": "observed",
        },
        {
            "event_id": "NET-003",
            "event_time": "2026-08-20T08:12:00+12:00",
            "source_type": "network",
            "event_type": "port_connection",
            "ip_address": "198.51.100.25",
            "hostname": "Test-Scanner",
            "status": "observed",
        },
        {
            "event_id": "NET-004",
            "event_time": "2026-08-20T08:13:00+12:00",
            "source_type": "network",
            "event_type": "connection_attempt",
            "ip_address": "999.10.10.10",
        },
    ]

    wifi_events = [
        {
            "event_id": "WIFI-001",
            "event_time": "2026-08-20T08:15:00+12:00",
            "source_type": "wifi",
            "event_type": "device_connected",
            "username": "netshield01",
            "mac_address": "08:00:27:cf:49:71",
            "hostname": "Ubuntu-NetShield",
            "location": "Lab Zone A",
            "status": "approved",
        },
        {
            "event_id": "WIFI-002",
            "event_time": "2026-08-20T08:16:00+12:00",
            "source_type": "wifi",
            "event_type": "device_observed",
            "mac_address": "02:42:ac:11:00:99",
            "hostname": "Unknown-CYOD",
            "location": "Lab Zone B",
            "status": "unknown",
        },
        {
            "event_id": "WIFI-003",
            "event_time": "2026-08-20T08:17:00+12:00",
            "source_type": "wifi",
            "event_type": "wpa3_policy_check",
            "mac_address": "08:00:27:cf:49:71",
            "hostname": "Ubuntu-NetShield",
            "location": "Lab Zone A",
            "status": "compliant",
        },
    ]

    endpoint_events = [
        {
            "event_id": "END-001",
            "event_time": "2026-08-20T08:20:00+12:00",
            "source_type": "endpoint",
            "event_type": "cpu_observation",
            "username": "netshield01",
            "hostname": "Ubuntu-NetShield",
            "process_name": "python",
            "cpu_percent": 22.5,
            "status": "normal",
        },
        {
            "event_id": "END-002",
            "event_time": "2026-08-20T08:21:00+12:00",
            "source_type": "endpoint",
            "event_type": "cpu_observation",
            "username": "netshield01",
            "hostname": "Ubuntu-NetShield",
            "process_name": "cpu-stress-test",
            "cpu_percent": 91.7,
            "status": "test_activity",
        },
        {
            "event_id": "END-003",
            "event_time": "2026-08-20T08:22:00+12:00",
            "source_type": "endpoint",
            "event_type": "process_started",
            "username": "netshield01",
            "hostname": "Ubuntu-NetShield",
            "process_name": "approved-test-process",
            "status": "observed",
        },
        {
            "event_id": "END-004",
            "event_time": "2026-08-20T08:23:00+12:00",
            "source_type": "endpoint",
            "event_type": "cpu_observation",
            "cpu_percent": 145,
        },
    ]

    application_events = [
        {
            "event_id": "APP-001",
            "event_time": "2026-08-20T08:25:00+12:00",
            "source_type": "application",
            "event_type": "request_received",
            "username": "test-user",
            "ip_address": "127.0.0.1",
            "hostname": "Ubuntu-NetShield",
            "status": "normal",
            "message": "Local application request accepted",
        },
        {
            "event_id": "APP-002",
            "event_time": "2026-08-20T08:26:00+12:00",
            "source_type": "application",
            "event_type": "database_query",
            "username": "test-user",
            "ip_address": "127.0.0.1",
            "hostname": "Ubuntu-NetShield",
            "status": "success",
            "message": "Parameterised local query completed",
        },
        {
            "event_id": "APP-003",
            "event_time": "2026-08-20T08:27:00+12:00",
            "source_type": "application",
            "event_type": "authentication_request",
            "username": "test-user",
            "ip_address": "127.0.0.1",
            "hostname": "Ubuntu-NetShield",
            "status": "success",
            "message": "Local test authentication completed",
        },
        '{"event_id": "APP-BROKEN", invalid-json}',
    ]

    event_files = {
        "authentication_events.jsonl": authentication_events,
        "network_events.jsonl": network_events,
        "wifi_events.jsonl": wifi_events,
        "endpoint_events.jsonl": endpoint_events,
        "application_events.jsonl": application_events,
    }

    total_records = 0

    for filename, events in event_files.items():
        write_jsonl(RAW_DIRECTORY / filename, events)
        total_records += len(events)
        print(f"CREATED: data/raw/{filename} ({len(events)} records)")

    print(f"PASS: Generated {total_records} safe simulated records")


if __name__ == "__main__":
    main()
