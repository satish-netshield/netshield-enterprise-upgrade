"""Stage 5 endpoint, CPU and wired-access detection."""

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_time(value: str) -> datetime:
    """Parse a timezone-aware event timestamp."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_stage5_events(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load accepted Stage 5 endpoint and network events."""
    source_files = (
        "endpoint_stage5_events.jsonl",
        "network_stage5_events.jsonl",
    )
    placeholders = ", ".join("?" for _ in source_files)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM security_events
            WHERE source_file IN ({placeholders})
            ORDER BY event_time, event_key
            """,
            source_files,
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_user_roles(
    database_path: Path,
    configuration: dict[str, Any],
) -> dict[str, str]:
    """Load database roles and simulated roles for test identities."""
    roles = dict(
        configuration.get("simulated_user_roles", {})
    )

    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT username, role
            FROM user_roles
            WHERE active = 1
            """
        ).fetchall()

    for username, role in rows:
        roles[username] = role.lower()

    return roles


def create_alert(
    detection_type: str,
    severity: str,
    events: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create one endpoint-alert structure."""
    ordered = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    last_event = ordered[-1]

    return {
        "detection_type": detection_type,
        "severity": severity,
        "first_event_time": ordered[0]["event_time"],
        "last_event_time": last_event["event_time"],
        "source_event_ids": [
            event["source_event_id"]
            for event in ordered
        ],
        "source_types": sorted(
            {
                event["source_type"]
                for event in ordered
            }
        ),
        "mac_address": last_event.get("mac_address"),
        "ip_address": last_event.get("ip_address"),
        "hostname": last_event.get("hostname"),
        "username": last_event.get("username"),
        "location": last_event.get("location"),
        "process_name": last_event.get("process_name"),
        "cpu_percent": last_event.get("cpu_percent"),
        "evidence": evidence,
    }


def detect_cpu_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect unexpected CPU activity and unapproved stress tests."""
    alerts = []
    thresholds = configuration["thresholds"]
    policy = configuration["endpoint_policy"]

    warning_limit = thresholds["cpu_warning_percent"]
    critical_limit = thresholds["cpu_critical_percent"]
    approved_tests = set(
        policy["approved_stress_test_ids"]
    )

    endpoint_events = [
        event
        for event in events
        if event["source_type"] == "endpoint"
    ]

    grouped: dict[
        tuple[str | None, str | None],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in endpoint_events:
        grouped[
            (
                event.get("mac_address"),
                event.get("username"),
            )
        ].append(event)

    for identity_events in grouped.values():
        high_cpu_events = [
            event
            for event in identity_events
            if event.get("cpu_percent") is not None
            and float(event["cpu_percent"]) >= warning_limit
        ]

        unapproved_events = []

        for event in high_cpu_events:
            raw = event["raw"]
            stress_test_id = raw.get("stress_test_id")
            approved = (
                stress_test_id in approved_tests
                and event.get("status") == "approved"
            )

            if approved:
                continue

            unapproved_events.append(event)

        for event in unapproved_events:
            raw = event["raw"]
            stress_test_id = raw.get("stress_test_id")

            if (
                event["event_type"] == "cpu_stress_test"
                or stress_test_id
            ):
                alerts.append(
                    create_alert(
                        "Unauthorised CPU Stress Test",
                        policy["unknown_process_severity"],
                        [event],
                        {
                            "cpu_percent": event["cpu_percent"],
                            "process_name": event.get(
                                "process_name"
                            ),
                            "stress_test_id": stress_test_id,
                            "approved_stress_test_ids": sorted(
                                approved_tests
                            ),
                        },
                    )
                )
                continue

            severity = policy["unexpected_cpu_severity"]

            if float(event["cpu_percent"]) >= critical_limit:
                severity = policy["critical_cpu_severity"]

            alerts.append(
                create_alert(
                    "Unexpected CPU Activity",
                    severity,
                    [event],
                    {
                        "cpu_percent": event["cpu_percent"],
                        "warning_threshold": warning_limit,
                        "critical_threshold": critical_limit,
                        "process_name": event.get(
                            "process_name"
                        ),
                    },
                )
            )

        if len(unapproved_events) < thresholds[
            "repeated_cpu_events"
        ]:
            continue

        ordered = sorted(
            unapproved_events,
            key=lambda event: parse_time(event["event_time"]),
        )
        window_end = (
            parse_time(ordered[0]["event_time"])
            + timedelta(
                minutes=thresholds["cpu_window_minutes"]
            )
        )
        window = [
            event
            for event in ordered
            if parse_time(event["event_time"]) <= window_end
        ]

        if len(window) >= thresholds["repeated_cpu_events"]:
            alerts.append(
                create_alert(
                    "Repeated High CPU Activity",
                    policy["unexpected_cpu_severity"],
                    window,
                    {
                        "event_count": len(window),
                        "window_minutes": thresholds[
                            "cpu_window_minutes"
                        ],
                        "cpu_values": [
                            event["cpu_percent"]
                            for event in window
                        ],
                    },
                )
            )

    return alerts


def detect_process_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect unknown endpoint processes in suspicious events."""
    alerts = []
    policy = configuration["endpoint_policy"]
    approved_processes = set(
        policy["approved_processes"]
    )

    for event in events:
        if event["source_type"] != "endpoint":
            continue

        process_name = event.get("process_name")

        if not process_name or process_name in approved_processes:
            continue

        if event.get("status") not in {
            "unknown",
            "unapproved",
        }:
            continue

        alerts.append(
            create_alert(
                "Unknown Endpoint Process",
                policy["unknown_process_severity"],
                [event],
                {
                    "process_name": process_name,
                    "status": event.get("status"),
                    "hostname": event.get("hostname"),
                },
            )
        )

    return alerts


def detect_wired_access(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    user_roles: dict[str, str],
) -> list[dict[str, Any]]:
    """Detect unauthorised wired access to restricted zones."""
    alerts = []
    policy = configuration["wired_access_policy"]
    approved_roles = policy["approved_roles_by_zone"]

    for event in events:
        raw = event["raw"]

        if (
            event["source_type"] != "network"
            or raw.get("connection_type") != "wired"
        ):
            continue

        location = event.get("location")
        username = event.get("username")
        role = user_roles.get(username)

        if location not in policy["restricted_zones"]:
            continue

        allowed_roles = approved_roles.get(location, [])

        if role in allowed_roles and event.get("status") == "approved":
            continue

        alerts.append(
            create_alert(
                "Restricted Wired Access",
                "High",
                [event],
                {
                    "location": location,
                    "username": username,
                    "role": role,
                    "allowed_roles": allowed_roles,
                    "connection_type": raw.get(
                        "connection_type"
                    ),
                    "switch_port": raw.get("switch_port"),
                    "vlan": raw.get("vlan"),
                },
            )
        )

    return alerts


def detect_mac_reuse(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect conflicting device identities for one MAC address."""
    alerts = []
    thresholds = configuration["thresholds"]
    correlation = configuration["correlation"]
    overlap_minutes = thresholds[
        "mac_reuse_overlap_minutes"
    ]

    if not correlation.get(
        "mac_reuse_requires_conflicting_hostname_or_user",
        True,
    ):
        return alerts

    grouped: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        mac_address = event.get("mac_address")

        if mac_address:
            grouped[mac_address].append(event)

    for mac_address, mac_events in grouped.items():
        hostnames = {
            event.get("hostname")
            for event in mac_events
            if event.get("hostname")
        }
        usernames = {
            event.get("username")
            for event in mac_events
            if event.get("username")
        }

        if len(hostnames) < 2 and len(usernames) < 2:
            continue

        ordered = sorted(
            mac_events,
            key=lambda event: parse_time(event["event_time"]),
        )
        overlapping = False

        for index, first in enumerate(ordered):
            first_time = parse_time(first["event_time"])

            for second in ordered[index + 1:]:
                second_time = parse_time(second["event_time"])

                if (
                    second_time - first_time
                ).total_seconds() <= overlap_minutes * 60:
                    overlapping = True
                    break

            if overlapping:
                break

        if not overlapping:
            continue

        alerts.append(
            create_alert(
                "MAC Reuse or Possible Spoofing",
                "High",
                ordered,
                {
                    "mac_address": mac_address,
                    "hostnames": sorted(hostnames),
                    "usernames": sorted(usernames),
                    "overlap_minutes": overlap_minutes,
                },
            )
        )

    return alerts


def detect_endpoint_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    user_roles: dict[str, str],
) -> list[dict[str, Any]]:
    """Run all Stage 5 endpoint and wired-access rules."""
    alerts = []

    alerts.extend(
        detect_cpu_activity(events, configuration)
    )
    alerts.extend(
        detect_process_activity(events, configuration)
    )
    alerts.extend(
        detect_wired_access(
            events,
            configuration,
            user_roles,
        )
    )
    alerts.extend(
        detect_mac_reuse(events, configuration)
    )

    alerts.sort(
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
        )
    )

    return alerts


def save_endpoint_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    """Save endpoint alerts and count duplicate alerts."""
    created_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with sqlite3.connect(database_path) as connection:
        for alert in alerts:
            key_material = {
                "detection_type": alert["detection_type"],
                "source_event_ids": alert["source_event_ids"],
                "mac_address": alert["mac_address"],
            }
            alert_key = hashlib.sha256(
                json.dumps(
                    key_material,
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()

            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO endpoint_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    mac_address,
                    ip_address,
                    hostname,
                    username,
                    location,
                    process_name,
                    cpu_percent,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_key,
                    created_at,
                    alert["detection_type"],
                    alert["severity"],
                    alert["first_event_time"],
                    alert["last_event_time"],
                    json.dumps(
                        alert["source_event_ids"]
                    ),
                    json.dumps(alert["source_types"]),
                    alert["mac_address"],
                    alert["ip_address"],
                    alert["hostname"],
                    alert["username"],
                    alert["location"],
                    alert["process_name"],
                    alert["cpu_percent"],
                    json.dumps(
                        alert["evidence"],
                        sort_keys=True,
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing
