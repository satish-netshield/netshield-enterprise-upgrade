"""Detect suspicious network, CYOD and Wi-Fi activity."""

import csv
import hashlib
import json
import math
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def parse_time(value: str) -> datetime:
    """Parse an ISO timestamp."""
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")

    return parsed.astimezone(timezone.utc)


def load_events(
    database_path: Path,
    source_files: set[str],
) -> list[dict[str, Any]]:
    """Load accepted Stage 4 events from SQLite."""
    events = []

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT *
            FROM security_events
            WHERE source_file IN (?, ?)
            ORDER BY event_time
            """,
            tuple(sorted(source_files)),
        ).fetchall()

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_cyod_inventory(file_path: Path) -> list[dict[str, str]]:
    """Load the approved CYOD inventory."""
    with file_path.open("r", encoding="utf-8", newline="") as inventory_file:
        return list(csv.DictReader(inventory_file))


def load_ip_list(file_path: Path) -> set[str]:
    """Load non-comment IP addresses from a text file."""
    if not file_path.exists():
        return set()

    return {
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def inventory_match(
    event: dict[str, Any],
    inventory: list[dict[str, str]],
) -> dict[str, str] | None:
    """Return the approved inventory record matching the MAC address."""
    event_mac = (event.get("mac_address") or "").lower()

    for device in inventory:
        if device["mac_address"].lower() == event_mac:
            return device

    return None


def alert_key(
    detection_type: str,
    event_ids: list[str],
    identity: str,
) -> str:
    """Create a deterministic key for duplicate protection."""
    value = "|".join(
        [
            detection_type,
            identity,
            ",".join(sorted(event_ids)),
        ]
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_alert(
    detection_type: str,
    severity: str,
    events: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create a network alert structure."""
    first_event = min(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    last_event = max(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    event_ids = [
        event["source_event_id"]
        for event in events
    ]

    identity = (
        last_event.get("mac_address")
        or last_event.get("ip_address")
        or last_event.get("hostname")
        or "unknown"
    )

    return {
        "alert_key": alert_key(
            detection_type,
            event_ids,
            identity,
        ),
        "detection_type": detection_type,
        "severity": severity,
        "first_event_time": first_event["event_time"],
        "last_event_time": last_event["event_time"],
        "source_event_ids": event_ids,
        "source_types": sorted(
            {
                event["source_type"]
                for event in events
            }
        ),
        "ip_address": last_event.get("ip_address"),
        "mac_address": last_event.get("mac_address"),
        "hostname": last_event.get("hostname"),
        "username": last_event.get("username"),
        "location": last_event.get("location"),
        "evidence": evidence,
    }


def detect_device_activity(
    events: list[dict[str, Any]],
    inventory: list[dict[str, str]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect unknown devices and inventory inconsistencies."""
    alerts = []
    severity = configuration["severity"]

    for event in events:
        if event["source_type"] not in {"network", "wifi"}:
            continue

        device = inventory_match(event, inventory)
        event_mac = (event.get("mac_address") or "").lower()

        if event["event_type"] == "device_observed":
            if device is None:
                alerts.append(
                    create_alert(
                        "Unknown CYOD Device",
                        severity["Unknown CYOD Device"],
                        [event],
                        {
                            "observed_mac": event_mac,
                            "observed_hostname": event.get(
                                "hostname"
                            ),
                            "reason": "Device is not in the CYOD inventory",
                        },
                    )
                )

        if event_mac and device is None:
            alerts.append(
                create_alert(
                    "Unregistered MAC Address",
                    severity["Unregistered MAC Address"],
                    [event],
                    {
                        "observed_mac": event_mac,
                        "reason": "MAC address is not registered",
                    },
                )
            )

        if device is not None:
            mismatch_fields = {}

            if (
                event.get("hostname")
                and event["hostname"] != device["hostname"]
            ):
                mismatch_fields["hostname"] = {
                    "observed": event["hostname"],
                    "registered": device["hostname"],
                }

            assigned_user = (
                event.get("username")
                or event["raw"].get("assigned_user")
            )

            if (
                assigned_user
                and assigned_user != device["assigned_user"]
            ):
                mismatch_fields["assigned_user"] = {
                    "observed": assigned_user,
                    "registered": device["assigned_user"],
                }

            if mismatch_fields:
                alerts.append(
                    create_alert(
                        "Device Inventory Mismatch",
                        severity["Device Inventory Mismatch"],
                        [event],
                        {
                            "device_id": device["device_id"],
                            "mismatches": mismatch_fields,
                        },
                    )
                )

        if (
            event["source_type"] == "network"
            and event.get("connection_type") == "wired"
            and device is None
        ):
            alerts.append(
                create_alert(
                    "Unknown Wired Device",
                    severity["Unknown Wired Device"],
                    [event],
                    {
                        "observed_hostname": event.get("hostname"),
                        "observed_mac": event_mac,
                    },
                )
            )

    return alerts


def detect_network_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    allowlist: set[str],
    blocklist: set[str],
) -> list[dict[str, Any]]:
    """Detect suspicious IPs, repeated attempts and port scans."""
    alerts = []
    severity = configuration["severity"]
    thresholds = configuration["thresholds"]

    grouped_attempts: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)
    grouped_ports: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        ip_address = event.get("ip_address")

        if ip_address and ip_address in blocklist:
            alerts.append(
                create_alert(
                    "Suspicious IP Address",
                    severity["Suspicious IP Address"],
                    [event],
                    {
                        "ip_address": ip_address,
                        "reason": "Address is on the simulated blocklist",
                    },
                )
            )

        elif (
            ip_address
            and ip_address not in allowlist
            and event["source_type"] == "network"
        ):
            alerts.append(
                create_alert(
                    "Suspicious IP Address",
                    severity["Suspicious IP Address"],
                    [event],
                    {
                        "ip_address": ip_address,
                        "reason": "Address is not on the approved allowlist",
                    },
                )
            )

        if event["event_type"] == "connection_attempt":
            identity = (
                ip_address or "unknown",
                event.get("hostname") or "unknown",
            )
            grouped_attempts[identity].append(event)

        if event["event_type"] == "port_connection":
            if ip_address:
                grouped_ports[ip_address].append(event)

    for identity, attempts in grouped_attempts.items():
        ordered = sorted(
            attempts,
            key=lambda event: parse_time(event["event_time"]),
        )

        for start_index, start_event in enumerate(ordered):
            end_time = (
                parse_time(start_event["event_time"])
                + timedelta(
                    minutes=thresholds[
                        "connection_window_minutes"
                    ]
                )
            )
            window = [
                event
                for event in ordered[start_index:]
                if parse_time(event["event_time"]) <= end_time
            ]

            if len(window) >= thresholds[
                "repeated_connection_attempts"
            ]:
                alerts.append(
                    create_alert(
                        "Repeated Connection Attempts",
                        severity["Repeated Connection Attempts"],
                        window[
                            : thresholds[
                                "repeated_connection_attempts"
                            ]
                        ],
                        {
                            "attempt_count": len(window),
                            "window_minutes": thresholds[
                                "connection_window_minutes"
                            ],
                            "identity": identity,
                        },
                    )
                )
                break

    for ip_address, port_events in grouped_ports.items():
        unique_ports = {
            event["raw"].get("destination_port")
            for event in port_events
            if event["raw"].get("destination_port") is not None
        }

        if len(unique_ports) >= thresholds["port_scan_unique_ports"]:
            alerts.append(
                create_alert(
                    "Port Scanning",
                    severity["Port Scanning"],
                    port_events,
                    {
                        "ip_address": ip_address,
                        "unique_ports": sorted(unique_ports),
                        "port_count": len(unique_ports),
                    },
                )
            )

    return alerts


def detect_wifi_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect WPA, rogue access-point and Wi-Fi zone violations."""
    alerts = []
    severity = configuration["severity"]
    wifi_policy = configuration["wifi_policy"]
    restricted_zones = set(
        configuration["restricted_zones"]
    )

    for event in events:
        raw = event["raw"]
        event_type = event["event_type"]

        if (
            event_type == "wpa3_policy_check"
            and (
                raw.get("security_mode")
                != wifi_policy["required_security"]
                or raw.get("cipher")
                != wifi_policy["allowed_cipher"]
                or event.get("status") == "violation"
            )
        ):
            alerts.append(
                create_alert(
                    "WPA3 Policy Violation",
                    severity["WPA3 Policy Violation"],
                    [event],
                    {
                        "security_mode": raw.get("security_mode"),
                        "cipher": raw.get("cipher"),
                        "required_security": wifi_policy[
                            "required_security"
                        ],
                    },
                )
            )

        if (
            event_type == "wpa2_downgrade_attempt"
            and not wifi_policy["allow_wpa2_downgrade"]
        ):
            alerts.append(
                create_alert(
                    "WPA2 Downgrade Attempt",
                    severity["WPA2 Downgrade Attempt"],
                    [event],
                    {
                        "security_mode": raw.get("security_mode"),
                        "reason": "WPA2 downgrade is not permitted",
                    },
                )
            )

        if (
            event_type == "access_point_observed"
            and event.get("status") == "unauthorised"
        ):
            alerts.append(
                create_alert(
                    "Rogue Access Point",
                    severity["Rogue Access Point"],
                    [event],
                    {
                        "ssid": raw.get("ssid"),
                        "access_point_id": raw.get(
                            "access_point_id"
                        ),
                        "security_mode": raw.get("security_mode"),
                    },
                )
            )

        if (
            event.get("location") in restricted_zones
            and event_type in {
                "device_connected",
                "device_observed",
            }
        ):
            alerts.append(
                create_alert(
                    "Wi-Fi Zone Violation",
                    severity["Wi-Fi Zone Violation"],
                    [event],
                    {
                        "location": event.get("location"),
                        "restricted_zones": sorted(
                            restricted_zones
                        ),
                    },
                )
            )

    return alerts


def detect_network_activity_all(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    inventory: list[dict[str, str]],
    allowlist: set[str],
    blocklist: set[str],
) -> list[dict[str, Any]]:
    """Run all Stage 4 network and Wi-Fi detections."""
    alerts = []
    alerts.extend(
        detect_device_activity(
            events,
            inventory,
            configuration,
        )
    )
    alerts.extend(
        detect_network_activity(
            events,
            configuration,
            allowlist,
            blocklist,
        )
    )
    alerts.extend(
        detect_wifi_activity(
            events,
            configuration,
        )
    )

    return sorted(
        alerts,
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
        ),
    )


def save_network_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    """Save new network alerts and count existing duplicates."""
    created_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with sqlite3.connect(database_path) as connection:
        for alert in alerts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO network_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    ip_address,
                    mac_address,
                    hostname,
                    username,
                    location,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_key"],
                    created_at,
                    alert["detection_type"],
                    alert["severity"],
                    alert["first_event_time"],
                    alert["last_event_time"],
                    json.dumps(alert["source_event_ids"]),
                    json.dumps(alert["source_types"]),
                    alert["ip_address"],
                    alert["mac_address"],
                    alert["hostname"],
                    alert["username"],
                    alert["location"],
                    json.dumps(alert["evidence"]),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing
