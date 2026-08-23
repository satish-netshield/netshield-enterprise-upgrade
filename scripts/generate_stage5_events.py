"""Generate controlled Stage 5 endpoint and wired-LAN events."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "data/raw/stage5"

ENDPOINT_FILE = OUTPUT_DIR / "endpoint_stage5_events.jsonl"
WIRED_FILE = OUTPUT_DIR / "network_stage5_events.jsonl"


ENDPOINT_EVENTS = [
    {
        "event_id": "END5-001",
        "event_time": "2026-08-24T09:00:00+12:00",
        "event_type": "cpu_normal",
        "source_type": "endpoint",
        "hostname": "Ubuntu-NetShield",
        "username": "netshield01",
        "mac_address": "08:00:27:cf:49:71",
        "process_name": "system_monitor",
        "cpu_percent": 32.4,
        "status": "normal",
        "location": "Lab Zone A",
    },
    {
        "event_id": "END5-002",
        "event_time": "2026-08-24T09:01:00+12:00",
        "event_type": "cpu_stress_test",
        "source_type": "endpoint",
        "hostname": "Ubuntu-NetShield",
        "username": "netshield01",
        "mac_address": "08:00:27:cf:49:71",
        "process_name": "controlled_cpu_test",
        "cpu_percent": 91.7,
        "status": "approved",
        "location": "Lab Zone A",
        "stress_test_id": "CPU-TEST-APPROVED-001",
    },
    {
        "event_id": "END5-003",
        "event_time": "2026-08-24T09:02:00+12:00",
        "event_type": "cpu_stress_test",
        "source_type": "endpoint",
        "hostname": "Ubuntu-NetShield",
        "username": "netshield01",
        "mac_address": "08:00:27:cf:49:71",
        "process_name": "controlled_cpu_test",
        "cpu_percent": 93.1,
        "status": "approved",
        "location": "Lab Zone A",
        "stress_test_id": "CPU-TEST-APPROVED-001",
    },
    {
        "event_id": "END5-004",
        "event_time": "2026-08-24T09:10:00+12:00",
        "event_type": "cpu_spike",
        "source_type": "endpoint",
        "hostname": "Analyst-Laptop",
        "username": "analyst01",
        "mac_address": "02:42:ac:11:00:25",
        "process_name": "unknown_worker",
        "cpu_percent": 97.8,
        "status": "observed",
        "location": "Lab Zone A",
    },
    {
        "event_id": "END5-005",
        "event_time": "2026-08-24T09:11:00+12:00",
        "event_type": "cpu_spike",
        "source_type": "endpoint",
        "hostname": "Analyst-Laptop",
        "username": "analyst01",
        "mac_address": "02:42:ac:11:00:25",
        "process_name": "unknown_worker",
        "cpu_percent": 98.4,
        "status": "observed",
        "location": "Lab Zone A",
    },
    {
        "event_id": "END5-006",
        "event_time": "2026-08-24T09:12:00+12:00",
        "event_type": "cpu_spike",
        "source_type": "endpoint",
        "hostname": "Analyst-Laptop",
        "username": "analyst01",
        "mac_address": "02:42:ac:11:00:25",
        "process_name": "unknown_worker",
        "cpu_percent": 99.1,
        "status": "observed",
        "location": "Lab Zone A",
    },
    {
        "event_id": "END5-007",
        "event_time": "2026-08-24T09:20:00+12:00",
        "event_type": "cpu_stress_test",
        "source_type": "endpoint",
        "hostname": "Test-Laptop",
        "username": "trainee01",
        "mac_address": "02:42:ac:11:00:77",
        "process_name": "stress-ng",
        "cpu_percent": 88.5,
        "status": "unapproved",
        "location": "Lab Zone A",
        "stress_test_id": "CPU-TEST-UNAPPROVED-001",
    },
    {
        "event_id": "END5-008",
        "event_time": "2026-08-24T09:21:00+12:00",
        "event_type": "cpu_stress_test",
        "source_type": "endpoint",
        "hostname": "Test-Laptop",
        "username": "trainee01",
        "mac_address": "02:42:ac:11:00:77",
        "process_name": "stress-ng",
        "cpu_percent": 96.2,
        "status": "unapproved",
        "location": "Lab Zone A",
        "stress_test_id": "CPU-TEST-UNAPPROVED-001",
    },
    {
        "event_id": "END5-009",
        "event_time": "2026-08-24T09:30:00+12:00",
        "event_type": "process_observed",
        "source_type": "endpoint",
        "hostname": "Unknown-CYOD",
        "username": "unknown01",
        "mac_address": "02:42:ac:11:00:99",
        "process_name": "remote_loader",
        "cpu_percent": 44.6,
        "status": "unknown",
        "location": "Lab Zone B",
    },
    {
        "event_id": "END5-010",
        "event_time": "2026-08-24T09:31:00+12:00",
        "event_type": "cpu_spike",
        "source_type": "endpoint",
        "hostname": "Unknown-CYOD",
        "username": "unknown01",
        "mac_address": "02:42:ac:11:00:99",
        "process_name": "remote_loader",
        "cpu_percent": 96.8,
        "status": "unknown",
        "location": "Lab Zone B",
    },
]


WIRED_EVENTS = [
    {
        "event_id": "LAN5-001",
        "event_time": "2026-08-24T09:40:00+12:00",
        "event_type": "wired_connection",
        "source_type": "network",
        "hostname": "Ubuntu-NetShield",
        "username": "netshield01",
        "mac_address": "08:00:27:cf:49:71",
        "ip_address": "10.0.2.15",
        "location": "Lab Zone A",
        "connection_type": "wired",
        "switch_port": "LAB-PORT-01",
        "vlan": "LAB-100",
        "status": "approved",
    },
    {
        "event_id": "LAN5-002",
        "event_time": "2026-08-24T09:45:00+12:00",
        "event_type": "wired_connection",
        "source_type": "network",
        "hostname": "Analyst-Laptop",
        "username": "analyst01",
        "mac_address": "02:42:ac:11:00:25",
        "ip_address": "10.0.30.25",
        "location": "Server Room",
        "connection_type": "wired",
        "switch_port": "SRV-PORT-04",
        "vlan": "SERVER-200",
        "status": "observed",
    },
    {
        "event_id": "LAN5-003",
        "event_time": "2026-08-24T09:46:00+12:00",
        "event_type": "wired_connection",
        "source_type": "network",
        "hostname": "Analyst-Laptop",
        "username": "analyst01",
        "mac_address": "02:42:ac:11:00:25",
        "ip_address": "10.0.30.25",
        "location": "Server Room",
        "connection_type": "wired",
        "switch_port": "SRV-PORT-04",
        "vlan": "SERVER-200",
        "status": "observed",
    },
    {
        "event_id": "LAN5-004",
        "event_time": "2026-08-24T09:50:00+12:00",
        "event_type": "wired_connection",
        "source_type": "network",
        "hostname": "Responder-Laptop",
        "username": "responder01",
        "mac_address": "02:42:ac:11:00:55",
        "ip_address": "10.0.30.55",
        "location": "Server Room",
        "connection_type": "wired",
        "switch_port": "SRV-PORT-02",
        "vlan": "SERVER-200",
        "status": "approved",
    },
]


def write_events(file_path: Path, events: list[dict[str, object]]) -> None:
    """Write events as JSON Lines."""
    with file_path.open("w", encoding="utf-8") as output:
        for event in events:
            output.write(json.dumps(event) + "\n")


def main() -> None:
    """Generate the controlled Stage 5 event set."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    write_events(ENDPOINT_FILE, ENDPOINT_EVENTS)
    write_events(WIRED_FILE, WIRED_EVENTS)

    total = len(ENDPOINT_EVENTS) + len(WIRED_EVENTS)

    print(
        f"CREATED: {ENDPOINT_FILE} "
        f"({len(ENDPOINT_EVENTS)} records)"
    )
    print(
        f"CREATED: {WIRED_FILE} "
        f"({len(WIRED_EVENTS)} records)"
    )
    print(f"PASS: Generated safe Stage 5 events ({total} records)")


if __name__ == "__main__":
    main()
