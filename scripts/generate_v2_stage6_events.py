"""Generate controlled Phase 3A V2 Stage 6 network events."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_TIME = datetime(
    2026,
    9,
    10,
    8,
    0,
    tzinfo=timezone.utc,
)


def event_time(
    minutes: int,
    seconds: int = 0,
) -> str:
    """Return a controlled UTC event timestamp."""
    return (
        BASE_TIME
        + timedelta(minutes=minutes, seconds=seconds)
    ).isoformat()


def build_event(
    *,
    event_id: str,
    event_time_value: str,
    source_type: str,
    source_system: str,
    event_type: str,
    severity: str,
    status: str,
    **context: Any,
) -> dict[str, Any]:
    """Create one V2 network or Wi-Fi event."""
    event = {
        "schema_version": "2.0",
        "event_id": event_id,
        "event_time": event_time_value,
        "source_type": source_type,
        "source_system": source_system,
        "event_type": event_type,
        "severity": severity,
        "status": status,
    }
    event.update(context)
    return event


def network_events() -> list[dict[str, Any]]:
    """Return controlled Stage 6 network events."""
    events = [
        build_event(
            event_id="S6-NET-001",
            event_time_value=event_time(0),
            source_type="network",
            source_system="simulated_network_sensor",
            event_type="connection_allowed",
            severity="Low",
            status="allowed",
            device_id="CYOD-001",
            asset_id="AST-001",
            username="netshield01",
            ip_address="10.0.2.15",
            mac_address="08:00:27:cf:49:71",
            hostname="Ubuntu-NetShield",
            location="Lab Zone A",
            connection_type="wired",
            destination_ip="192.0.2.100",
            destination_port=443,
            service="https",
        ),
        build_event(
            event_id="S6-NET-002",
            event_time_value=event_time(5),
            source_type="network",
            source_system="simulated_network_sensor",
            event_type="connection_attempt",
            severity="High",
            status="blocked",
            ip_address="198.51.100.66",
            hostname="Blocked-Test-Source",
            location="External Test Network",
            connection_type="external",
            destination_ip="192.0.2.100",
            destination_port=443,
            service="https",
        ),
    ]

    scan_ports = [21, 22, 23, 80, 445]

    for index, port in enumerate(scan_ports, start=1):
        events.append(
            build_event(
                event_id=f"S6-NET-SCAN-{index:03d}",
                event_time_value=event_time(
                    10,
                    (index - 1) * 10,
                ),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="port_connection",
                severity="High",
                status="observed",
                ip_address="198.51.100.77",
                hostname="Controlled-Port-Scanner",
                location="External Test Network",
                connection_type="external",
                destination_ip="192.0.2.100",
                destination_port=port,
                service=f"test-port-{port}",
            )
        )

    for index in range(1, 6):
        events.append(
            build_event(
                event_id=f"S6-NET-REPEAT-{index:03d}",
                event_time_value=event_time(
                    20,
                    (index - 1) * 20,
                ),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="connection_attempt",
                severity="Medium",
                status="observed",
                ip_address="203.0.113.90",
                hostname="Rapid-Connector",
                location="External Test Network",
                connection_type="external",
                destination_ip="192.0.2.100",
                destination_port=443,
                service="https",
            )
        )

    for index in range(1, 9):
        events.append(
            build_event(
                event_id=f"S6-NET-ABNORMAL-{index:03d}",
                event_time_value=event_time(
                    900,
                    (index - 1) * 70,
                ),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="connection_attempt",
                severity="Medium",
                status="observed",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="192.0.2.20",
                mac_address="02:00:00:00:00:02",
                hostname="Analyst-Laptop",
                location="Lab Zone A",
                connection_type="wired",
                destination_ip="192.0.2.100",
                destination_port=443,
                service="https",
            )
        )

    events.extend(
        [
            build_event(
                event_id="S6-NET-021",
                event_time_value=event_time(40),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="port_connection",
                severity="High",
                status="blocked",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="192.0.2.20",
                mac_address="02:00:00:00:00:02",
                hostname="Analyst-Laptop",
                location="Lab Zone A",
                connection_type="wired",
                destination_ip="192.0.2.100",
                destination_port=23,
                service="telnet",
            ),
            build_event(
                event_id="S6-NET-022",
                event_time_value=event_time(42),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="port_connection",
                severity="High",
                status="blocked",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="192.0.2.20",
                mac_address="02:00:00:00:00:02",
                hostname="Analyst-Laptop",
                location="Lab Zone A",
                connection_type="wired",
                destination_ip="192.0.2.100",
                destination_port=8443,
                service="smb",
            ),
            build_event(
                event_id="S6-NET-023",
                event_time_value=event_time(45),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="wired_connection",
                severity="High",
                status="observed",
                device_id="CYOD-999",
                asset_id="AST-999",
                username="unknown-user",
                ip_address="192.0.2.99",
                mac_address="02:00:00:00:00:99",
                hostname="Unknown-Wired-Device",
                location="Lab Zone A",
                connection_type="wired",
                destination_ip="192.0.2.100",
                destination_port=443,
                service="https",
            ),
            build_event(
                event_id="S6-NET-024",
                event_time_value=event_time(47),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="wired_connection",
                severity="High",
                status="blocked",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="192.0.2.20",
                mac_address="02:00:00:00:00:02",
                hostname="Analyst-Laptop",
                location="Server Room",
                connection_type="wired",
                destination_ip="192.0.2.100",
                destination_port=443,
                service="https",
            ),
            build_event(
                event_id="S6-NET-025",
                event_time_value=event_time(50),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="connection_allowed",
                severity="Low",
                status="allowed",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="203.0.113.10",
                mac_address="02:00:00:00:00:02",
                hostname="Analyst-Laptop",
                location="Approved VPN",
                connection_type="vpn",
                destination_ip="192.0.2.100",
                destination_port=443,
                service="https",
            ),
            build_event(
                event_id="S6-NET-026",
                event_time_value=event_time(55),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="device_observed",
                severity="Low",
                status="approved",
                device_id="CYOD-001",
                asset_id="AST-001",
                username="netshield01",
                ip_address="192.0.2.10",
                mac_address="08:00:27:cf:49:71",
                hostname="Ubuntu-NetShield",
                location="Lab Zone A",
                connection_type="wired",
            ),
            build_event(
                event_id="S6-NET-027",
                event_time_value=event_time(56),
                source_type="network",
                source_system="simulated_network_sensor",
                event_type="device_observed",
                severity="High",
                status="observed",
                device_id="CYOD-002",
                asset_id="AST-002",
                username="analyst01",
                ip_address="192.0.2.20",
                mac_address="08:00:27:cf:49:71",
                hostname="Analyst-Laptop",
                location="Lab Zone A",
                connection_type="wired",
            ),
        ]
    )

    return events


def wifi_events() -> list[dict[str, Any]]:
    """Return controlled Stage 6 Wi-Fi events."""
    return [
        build_event(
            event_id="S6-WIFI-001",
            event_time_value=event_time(60),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="device_connected",
            severity="Low",
            status="allowed",
            device_id="CYOD-001",
            asset_id="AST-001",
            username="netshield01",
            ip_address="192.0.2.10",
            mac_address="08:00:27:cf:49:71",
            hostname="Ubuntu-NetShield",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA3",
            cipher="AES",
        ),
        build_event(
            event_id="S6-WIFI-002",
            event_time_value=event_time(62),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="device_observed",
            severity="High",
            status="unknown",
            device_id="CYOD-998",
            asset_id="AST-998",
            username="unknown-user",
            ip_address="192.0.2.98",
            mac_address="02:00:00:00:00:98",
            hostname="Unknown-CYOD",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA3",
            cipher="AES",
        ),
        build_event(
            event_id="S6-WIFI-003",
            event_time_value=event_time(64),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="wpa3_policy_check",
            severity="High",
            status="violation",
            device_id="CYOD-002",
            asset_id="AST-002",
            username="analyst01",
            ip_address="192.0.2.20",
            mac_address="02:00:00:00:00:02",
            hostname="Analyst-Laptop",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA2",
            cipher="AES",
        ),
        build_event(
            event_id="S6-WIFI-004",
            event_time_value=event_time(66),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="wpa2_downgrade_attempt",
            severity="High",
            status="blocked",
            device_id="CYOD-001",
            asset_id="AST-001",
            username="netshield01",
            ip_address="192.0.2.10",
            mac_address="08:00:27:cf:49:71",
            hostname="Ubuntu-NetShield",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA2",
            cipher="AES",
        ),
        build_event(
            event_id="S6-WIFI-005",
            event_time_value=event_time(68),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="access_point_observed",
            severity="Critical",
            status="unauthorised",
            ip_address="192.0.2.88",
            mac_address="02:00:00:00:00:88",
            hostname="Rogue-AP",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-ROGUE-01",
            ssid="Free-Public-WiFi",
            security_mode="Open",
            cipher="None",
        ),
        build_event(
            event_id="S6-WIFI-006",
            event_time_value=event_time(70),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="device_connected",
            severity="Medium",
            status="blocked",
            device_id="CYOD-002",
            asset_id="AST-002",
            username="analyst01",
            ip_address="192.0.2.20",
            mac_address="02:00:00:00:00:02",
            hostname="Analyst-Laptop",
            location="Parking Lot",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA3",
            cipher="AES",
        ),
        build_event(
            event_id="S6-WIFI-007",
            event_time_value=event_time(72),
            source_type="wifi",
            source_system="simulated_wifi_controller",
            event_type="device_connected",
            severity="Low",
            status="approved_test",
            device_id="CYOD-997",
            asset_id="AST-997",
            username="trainee01",
            ip_address="192.0.2.97",
            mac_address="02:00:00:00:00:97",
            hostname="Approved-Test-Device",
            location="Lab Zone A",
            connection_type="wifi",
            access_point_id="AP-LAB-A-01",
            ssid="NetShield-Lab",
            security_mode="WPA3",
            cipher="AES",
            approved_test=True,
        ),
    ]


def write_events(
    file_path: Path,
    events: list[dict[str, Any]],
) -> None:
    """Write events as JSONL."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        json.dumps(event, sort_keys=True)
        for event in events
    )
    file_path.write_text(
        content + "\n",
        encoding="utf-8",
    )


def main() -> None:
    """Generate the controlled Stage 6 source files."""
    configuration = load_json(
        PROJECT_ROOT / "config/v2_network_monitoring.json"
    )
    source_directory = (
        PROJECT_ROOT / configuration["source_directory"]
    )

    network = network_events()
    wifi = wifi_events()

    source_files = configuration["source_files"]

    write_events(
        source_directory / source_files[0],
        network,
    )
    write_events(
        source_directory / source_files[1],
        wifi,
    )

    print(
        f"PASS: Generated {len(network) + len(wifi)} "
        "Stage 6 events"
    )
    print(f"Network events: {len(network)}")
    print(f"Wi-Fi events: {len(wifi)}")
    print("Source files: 2")
    print("Blocked test address: 198.51.100.66")
    print("Approved VPN test address: 203.0.113.10")
    print("Real external targets used: false")


if __name__ == "__main__":
    main()
