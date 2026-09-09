"""Detect suspicious identity and authentication activity."""
from src.utils.sqlite_connection import managed_connection

import hashlib
import json
import math
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def parse_time(value: str) -> datetime:
    """Return an ISO 8601 timestamp as a datetime."""
    return datetime.fromisoformat(value)


def load_authentication_events(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load accepted authentication events in time order."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                source_event_id,
                event_time,
                event_type,
                username,
                ip_address,
                hostname,
                location,
                status,
                raw_event
            FROM security_events
            WHERE source_type = 'authentication'
            ORDER BY event_time, event_key
            """
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_vpn_allowlist(file_path: Path) -> set[str]:
    """Return approved VPN addresses from a text allowlist."""
    addresses = set()

    for line in file_path.read_text(encoding="utf-8").splitlines():
        value = line.strip()

        if value and not value.startswith("#"):
            addresses.add(value)

    return addresses


def find_window(
    events: list[dict[str, Any]],
    threshold: int,
    minutes: int,
) -> list[dict[str, Any]]:
    """Return the first event window that reaches a threshold."""
    ordered_events = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )

    for start_index, start_event in enumerate(ordered_events):
        end_time = (
            parse_time(start_event["event_time"])
            + timedelta(minutes=minutes)
        )
        window = [
            event
            for event in ordered_events[start_index:]
            if parse_time(event["event_time"]) <= end_time
        ]

        if len(window) >= threshold:
            return window[:threshold]

    return []


def distance_km(
    first_location: dict[str, float],
    second_location: dict[str, float],
) -> float:
    """Calculate approximate distance using the Haversine formula."""
    earth_radius_km = 6371.0

    first_latitude = math.radians(first_location["latitude"])
    second_latitude = math.radians(second_location["latitude"])
    latitude_change = math.radians(
        second_location["latitude"]
        - first_location["latitude"]
    )
    longitude_change = math.radians(
        second_location["longitude"]
        - first_location["longitude"]
    )

    haversine_value = (
        math.sin(latitude_change / 2) ** 2
        + math.cos(first_latitude)
        * math.cos(second_latitude)
        * math.sin(longitude_change / 2) ** 2
    )

    return earth_radius_km * 2 * math.atan2(
        math.sqrt(haversine_value),
        math.sqrt(1 - haversine_value),
    )


def create_alert(
    detection_type: str,
    severity: str,
    username: str,
    events: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create one deterministic identity alert."""
    ordered_events = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    event_ids = [
        event["source_event_id"]
        for event in ordered_events
    ]
    key_source = "|".join(
        [detection_type, username, *event_ids]
    )
    alert_key = hashlib.sha256(
        key_source.encode("utf-8")
    ).hexdigest()

    last_event = ordered_events[-1]

    return {
        "alert_key": alert_key,
        "detection_type": detection_type,
        "severity": severity,
        "username": username,
        "first_event_time": ordered_events[0]["event_time"],
        "last_event_time": last_event["event_time"],
        "source_event_ids": event_ids,
        "ip_address": last_event.get("ip_address"),
        "hostname": last_event.get("hostname"),
        "location": last_event.get("location"),
        "evidence": evidence,
    }


def detect_failure_activity(
    events: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> list[dict[str, Any]]:
    """Detect repeated failures, brute force and later success."""
    alerts = []
    failures_by_identity: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)

    for event in events:
        if event["event_type"] == "login_failure":
            identity = (
                event["username"],
                event["ip_address"],
            )
            failures_by_identity[identity].append(event)

    for (username, ip_address), failures in failures_by_identity.items():
        repeated_window = find_window(
            failures,
            thresholds["repeated_failures"],
            thresholds["failure_window_minutes"],
        )

        if repeated_window:
            alerts.append(
                create_alert(
                    "Repeated Failed Logins",
                    "Medium",
                    username,
                    repeated_window,
                    {
                        "failure_count": len(repeated_window),
                        "window_minutes": thresholds[
                            "failure_window_minutes"
                        ],
                        "ip_address": ip_address,
                    },
                )
            )

        brute_force_window = find_window(
            failures,
            thresholds["brute_force_failures"],
            thresholds["failure_window_minutes"],
        )

        if brute_force_window:
            alerts.append(
                create_alert(
                    "Possible Brute Force",
                    "High",
                    username,
                    brute_force_window,
                    {
                        "failure_count": len(brute_force_window),
                        "window_minutes": thresholds[
                            "failure_window_minutes"
                        ],
                        "ip_address": ip_address,
                    },
                )
            )

    successful_events = [
        event
        for event in events
        if event["event_type"] == "login_success"
    ]

    for success in successful_events:
        success_time = parse_time(success["event_time"])
        start_time = success_time - timedelta(
            minutes=thresholds["failure_window_minutes"]
        )
        earlier_failures = [
            event
            for event in events
            if event["event_type"] == "login_failure"
            and event["username"] == success["username"]
            and event["ip_address"] == success["ip_address"]
            and start_time
            <= parse_time(event["event_time"])
            < success_time
        ]

        if len(earlier_failures) >= thresholds[
            "success_after_failures"
        ]:
            related_events = (
                earlier_failures
                + [success]
            )
            alerts.append(
                create_alert(
                    "Successful Login After Failures",
                    "High",
                    success["username"],
                    related_events,
                    {
                        "failure_count": len(earlier_failures),
                        "ip_address": success["ip_address"],
                    },
                )
            )

    return alerts


def detect_mfa_anomalies(
    events: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> list[dict[str, Any]]:
    """Detect repeated MFA failures."""
    alerts = []
    grouped_events: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)

    for event in events:
        if event["event_type"] == "mfa_failure":
            identity = (
                event["username"],
                event["ip_address"],
            )
            grouped_events[identity].append(event)

    for (username, ip_address), failures in grouped_events.items():
        window = find_window(
            failures,
            thresholds["mfa_failures"],
            thresholds["mfa_window_minutes"],
        )

        if window:
            alerts.append(
                create_alert(
                    "MFA Failure Anomaly",
                    "High",
                    username,
                    window,
                    {
                        "failure_count": len(window),
                        "window_minutes": thresholds[
                            "mfa_window_minutes"
                        ],
                        "ip_address": ip_address,
                    },
                )
            )

    return alerts


def detect_baseline_anomalies(
    events: list[dict[str, Any]],
    baselines: dict[str, Any],
    vpn_addresses: set[str],
) -> tuple[list[dict[str, Any]], int]:
    """Detect new devices and unusual locations."""
    alerts = []
    vpn_exceptions = 0

    for event in events:
        if event["event_type"] != "login_success":
            continue

        baseline = baselines.get(event["username"])

        if not baseline:
            continue

        if event["ip_address"] in vpn_addresses:
            vpn_exceptions += 1
            continue

        if event["hostname"] not in baseline["approved_devices"]:
            alerts.append(
                create_alert(
                    "Login From New Device",
                    "Medium",
                    event["username"],
                    [event],
                    {
                        "observed_device": event["hostname"],
                        "approved_devices": baseline[
                            "approved_devices"
                        ],
                    },
                )
            )

        if event["location"] not in baseline["usual_locations"]:
            alerts.append(
                create_alert(
                    "Login From Unusual Location",
                    "Medium",
                    event["username"],
                    [event],
                    {
                        "observed_location": event["location"],
                        "usual_locations": baseline[
                            "usual_locations"
                        ],
                    },
                )
            )

    return alerts, vpn_exceptions


def detect_impossible_travel(
    events: list[dict[str, Any]],
    locations: dict[str, dict[str, float]],
    vpn_addresses: set[str],
    maximum_speed: int,
) -> tuple[list[dict[str, Any]], int]:
    """Detect travel faster than the configured speed."""
    alerts = []
    vpn_exceptions = 0
    successes_by_user: dict[
        str, list[dict[str, Any]]
    ] = defaultdict(list)

    for event in events:
        if event["event_type"] == "login_success":
            successes_by_user[event["username"]].append(event)

    for username, successes in successes_by_user.items():
        ordered_events = sorted(
            successes,
            key=lambda event: parse_time(event["event_time"]),
        )

        for first_event, second_event in zip(
            ordered_events,
            ordered_events[1:],
        ):
            if (
                first_event["ip_address"] in vpn_addresses
                or second_event["ip_address"] in vpn_addresses
            ):
                vpn_exceptions += 1
                continue

            first_location = locations.get(first_event["location"])
            second_location = locations.get(second_event["location"])

            if (
                first_location is None
                or second_location is None
                or first_event["location"]
                == second_event["location"]
            ):
                continue

            elapsed_hours = (
                parse_time(second_event["event_time"])
                - parse_time(first_event["event_time"])
            ).total_seconds() / 3600

            if elapsed_hours <= 0:
                continue

            travelled_distance = distance_km(
                first_location,
                second_location,
            )
            calculated_speed = travelled_distance / elapsed_hours

            if calculated_speed > maximum_speed:
                alerts.append(
                    create_alert(
                        "Impossible Travel",
                        "High",
                        username,
                        [first_event, second_event],
                        {
                            "from_location": first_event["location"],
                            "to_location": second_event["location"],
                            "distance_km": round(
                                travelled_distance,
                                2,
                            ),
                            "elapsed_hours": round(
                                elapsed_hours,
                                2,
                            ),
                            "speed_kmh": round(
                                calculated_speed,
                                2,
                            ),
                            "maximum_speed_kmh": maximum_speed,
                        },
                    )
                )

    return alerts, vpn_exceptions


def detect_role_changes(
    events: list[dict[str, Any]],
    baselines: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect role changes that differ from the user baseline."""
    alerts = []

    for event in events:
        if event["event_type"] != "role_change":
            continue

        baseline = baselines.get(event["username"])
        expected_role = (
            baseline.get("expected_role")
            if baseline
            else None
        )
        new_role = event["raw"].get("new_role")

        if expected_role is None or new_role != expected_role:
            alerts.append(
                create_alert(
                    "Suspicious Role Change",
                    "Critical",
                    event["username"],
                    [event],
                    {
                        "previous_role": event["raw"].get(
                            "previous_role"
                        ),
                        "new_role": new_role,
                        "expected_role": expected_role,
                        "changed_by": event["raw"].get(
                            "changed_by"
                        ),
                    },
                )
            )

    return alerts


def detect_identity_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    vpn_addresses: set[str],
) -> tuple[list[dict[str, Any]], int]:
    """Run every Stage 3 identity detection."""
    thresholds = configuration["thresholds"]
    baselines = configuration["user_baselines"]

    alerts = detect_failure_activity(events, thresholds)
    alerts.extend(
        detect_mfa_anomalies(events, thresholds)
    )

    baseline_alerts, baseline_exceptions = (
        detect_baseline_anomalies(
            events,
            baselines,
            vpn_addresses,
        )
    )
    alerts.extend(baseline_alerts)

    travel_alerts, travel_exceptions = detect_impossible_travel(
        events,
        configuration["locations"],
        vpn_addresses,
        thresholds["impossible_travel_speed_kmh"],
    )
    alerts.extend(travel_alerts)
    alerts.extend(
        detect_role_changes(events, baselines)
    )

    alerts.sort(
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
        )
    )

    return (
        alerts,
        baseline_exceptions + travel_exceptions,
    )


def save_identity_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    """Save new alerts and count existing duplicates."""
    created_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for alert in alerts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO identity_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    username,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    ip_address,
                    hostname,
                    location,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_key"],
                    created_at,
                    alert["detection_type"],
                    alert["severity"],
                    alert["username"],
                    alert["first_event_time"],
                    alert["last_event_time"],
                    json.dumps(alert["source_event_ids"]),
                    alert["ip_address"],
                    alert["hostname"],
                    alert["location"],
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
