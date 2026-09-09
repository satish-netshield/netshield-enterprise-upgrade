"""Detect V2 enterprise identity and authentication risks."""
from src.utils.sqlite_connection import managed_connection

import hashlib
import json
import math
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


STAGE_SOURCE_PATTERN = "%_v2_stage4_5_events.jsonl"


def parse_time(value: str) -> datetime:
    """Return an ISO 8601 timestamp as a datetime."""
    return datetime.fromisoformat(value)


def load_identity_events(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load Stage 4 authentication and identity-risk events."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                source_event_id,
                source_type,
                source_system,
                event_time,
                event_type,
                severity,
                risk_score,
                device_id,
                username,
                ip_address,
                hostname,
                location,
                status,
                raw_event
            FROM security_events
            WHERE source_file LIKE ?
              AND source_type IN (
                  'authentication',
                  'identity_risk'
              )
            ORDER BY event_time, event_key
            """,
            (STAGE_SOURCE_PATTERN,),
        ).fetchall()

    events: list[dict[str, Any]] = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_vpn_allowlist(file_path: Path) -> set[str]:
    """Load approved VPN addresses."""
    addresses: set[str] = set()

    for raw_line in file_path.read_text(
        encoding="utf-8"
    ).splitlines():
        address = raw_line.strip()

        if address and not address.startswith("#"):
            addresses.add(address)

    return addresses


def find_threshold_window(
    events: list[dict[str, Any]],
    threshold: int,
    minutes: int,
) -> list[dict[str, Any]]:
    """Return the first time window reaching a threshold."""
    ordered_events = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )

    for start_index, start_event in enumerate(ordered_events):
        window_end = (
            parse_time(start_event["event_time"])
            + timedelta(minutes=minutes)
        )
        window = [
            event
            for event in ordered_events[start_index:]
            if parse_time(event["event_time"]) <= window_end
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
    rule_name: str,
    detection_type: str,
    username: str,
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    reason_codes: list[str],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create one deterministic V2 identity alert."""
    ordered_events = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    source_event_ids = [
        event["source_event_id"]
        for event in ordered_events
    ]
    source_types = sorted(
        {
            event["source_type"]
            for event in ordered_events
        }
    )

    rule = configuration["detections"][rule_name]
    key_material = "|".join(
        [
            rule_name,
            username,
            *source_event_ids,
        ]
    )
    alert_key = hashlib.sha256(
        key_material.encode("utf-8")
    ).hexdigest()

    last_event = ordered_events[-1]
    risk_scores = [
        float(event["risk_score"])
        for event in ordered_events
        if event.get("risk_score") is not None
    ]

    return {
        "alert_key": alert_key,
        "detection_type": detection_type,
        "severity": rule["severity"],
        "confidence": int(rule["confidence"]),
        "username": username,
        "device_id": last_event.get("device_id"),
        "first_event_time": ordered_events[0]["event_time"],
        "last_event_time": last_event["event_time"],
        "source_event_ids": source_event_ids,
        "source_types": source_types,
        "ip_address": last_event.get("ip_address"),
        "location": last_event.get("location"),
        "risk_score": max(risk_scores) if risk_scores else None,
        "reason_codes": reason_codes,
        "mitre_techniques": rule["mitre_techniques"],
        "evidence": evidence,
    }


def is_detection_enabled(
    configuration: dict[str, Any],
    rule_name: str,
) -> bool:
    """Return whether a configured detection is enabled."""
    rule = configuration["detections"].get(rule_name, {})
    return bool(rule.get("enabled", False))


def is_approved_test_event(
    event: dict[str, Any],
    configuration: dict[str, Any],
) -> bool:
    """Return whether an event is approved testing activity."""
    approved_users = set(
        configuration["known_exceptions"][
            "approved_testing_users"
        ]
    )

    return (
        event.get("username") in approved_users
        and bool(event["raw"].get("approved_test_activity"))
    )


def detect_failure_patterns(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect repeated failures, brute force and later success."""
    alerts: list[dict[str, Any]] = []
    thresholds = configuration["thresholds"]

    failures = [
        event
        for event in events
        if event["source_type"] == "authentication"
        and event["event_type"] == "login_failure"
    ]

    grouped_failures: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in failures:
        grouped_failures[
            (
                event.get("username") or "unknown",
                event.get("ip_address") or "unknown",
            )
        ].append(event)

    for identity, identity_failures in grouped_failures.items():
        username, ip_address = identity

        if is_detection_enabled(
            configuration,
            "repeated_failed_logins",
        ):
            repeated_window = find_threshold_window(
                identity_failures,
                thresholds["repeated_failed_logins"],
                thresholds["failure_window_minutes"],
            )

            if repeated_window:
                alerts.append(
                    create_alert(
                        "repeated_failed_logins",
                        "Repeated Failed Logins",
                        username,
                        repeated_window,
                        configuration,
                        ["REPEATED_FAILED_LOGINS"],
                        {
                            "failure_count": len(repeated_window),
                            "window_minutes": thresholds[
                                "failure_window_minutes"
                            ],
                            "ip_address": ip_address,
                        },
                    )
                )

        if is_detection_enabled(
            configuration,
            "possible_brute_force",
        ):
            brute_force_window = find_threshold_window(
                identity_failures,
                thresholds["possible_brute_force"],
                thresholds["failure_window_minutes"],
            )

            if brute_force_window:
                alerts.append(
                    create_alert(
                        "possible_brute_force",
                        "Possible Brute Force",
                        username,
                        brute_force_window,
                        configuration,
                        ["POSSIBLE_BRUTE_FORCE"],
                        {
                            "failure_count": len(brute_force_window),
                            "window_minutes": thresholds[
                                "failure_window_minutes"
                            ],
                            "ip_address": ip_address,
                        },
                    )
                )

    if is_detection_enabled(
        configuration,
        "successful_login_after_failures",
    ):
        successful_events = [
            event
            for event in events
            if event["source_type"] == "authentication"
            and event["event_type"] == "login_success"
        ]

        for success in successful_events:
            success_time = parse_time(success["event_time"])
            start_time = success_time - timedelta(
                minutes=thresholds["failure_window_minutes"]
            )
            earlier_failures = [
                event
                for event in failures
                if event.get("username") == success.get("username")
                and event.get("ip_address") == success.get("ip_address")
                and start_time
                <= parse_time(event["event_time"])
                < success_time
            ]

            if len(earlier_failures) >= thresholds[
                "success_after_failures"
            ]:
                related_events = [
                    *earlier_failures,
                    success,
                ]
                alerts.append(
                    create_alert(
                        "successful_login_after_failures",
                        "Successful Login After Failures",
                        success.get("username") or "unknown",
                        related_events,
                        configuration,
                        ["SUCCESS_AFTER_REPEATED_FAILURES"],
                        {
                            "failure_count": len(earlier_failures),
                            "ip_address": success.get("ip_address"),
                        },
                    )
                )

    return alerts


def find_multi_account_window(
    failures: list[dict[str, Any]],
    account_threshold: int,
    minutes: int,
) -> list[dict[str, Any]]:
    """Return the first failure window involving enough accounts."""
    ordered_failures = sorted(
        failures,
        key=lambda event: parse_time(event["event_time"]),
    )

    for start_index, start_event in enumerate(ordered_failures):
        window_end = (
            parse_time(start_event["event_time"])
            + timedelta(minutes=minutes)
        )
        window = [
            event
            for event in ordered_failures[start_index:]
            if parse_time(event["event_time"]) <= window_end
        ]
        usernames = {
            event.get("username")
            for event in window
            if event.get("username")
        }

        if len(usernames) >= account_threshold:
            return window

    return []


def detect_shared_source_patterns(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect password spraying and multiple-account access."""
    alerts: list[dict[str, Any]] = []
    thresholds = configuration["thresholds"]

    failures_by_source: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if (
            event["source_type"] == "authentication"
            and event["event_type"] == "login_failure"
            and event.get("ip_address")
        ):
            failures_by_source[event["ip_address"]].append(event)

    for ip_address, failures in failures_by_source.items():
        spray_window = find_multi_account_window(
            failures,
            thresholds["password_spray_accounts"],
            thresholds["failure_window_minutes"],
        )

        if not spray_window:
            continue

        usernames = sorted(
            {
                event["username"]
                for event in spray_window
                if event.get("username")
            }
        )

        if is_detection_enabled(
            configuration,
            "password_spraying",
        ):
            alerts.append(
                create_alert(
                    "password_spraying",
                    "Password Spraying Pattern",
                    "multiple_accounts",
                    spray_window,
                    configuration,
                    ["PASSWORD_SPRAYING_PATTERN"],
                    {
                        "ip_address": ip_address,
                        "usernames": usernames,
                        "account_count": len(usernames),
                        "window_minutes": thresholds[
                            "failure_window_minutes"
                        ],
                    },
                )
            )

        if (
            len(usernames)
            >= thresholds["multiple_accounts_per_source"]
            and is_detection_enabled(
                configuration,
                "multiple_accounts_from_one_source",
            )
        ):
            alerts.append(
                create_alert(
                    "multiple_accounts_from_one_source",
                    "Multiple Accounts From One Source",
                    "multiple_accounts",
                    spray_window,
                    configuration,
                    ["MULTIPLE_ACCOUNTS_ONE_SOURCE"],
                    {
                        "ip_address": ip_address,
                        "usernames": usernames,
                        "account_count": len(usernames),
                    },
                )
            )

    return alerts


def detect_mfa_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect repeated MFA failures or fatigue behaviour."""
    if not is_detection_enabled(
        configuration,
        "mfa_failure_or_fatigue",
    ):
        return []

    thresholds = configuration["thresholds"]
    grouped_failures: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if (
            event["source_type"] == "authentication"
            and event["event_type"] == "mfa_failure"
        ):
            grouped_failures[
                (
                    event.get("username") or "unknown",
                    event.get("ip_address") or "unknown",
                )
            ].append(event)

    alerts: list[dict[str, Any]] = []

    for identity, failures in grouped_failures.items():
        username, ip_address = identity
        failure_window = find_threshold_window(
            failures,
            thresholds["mfa_failures"],
            thresholds["mfa_window_minutes"],
        )

        if failure_window:
            alerts.append(
                create_alert(
                    "mfa_failure_or_fatigue",
                    "MFA Failure or Fatigue Pattern",
                    username,
                    failure_window,
                    configuration,
                    ["REPEATED_MFA_FAILURES"],
                    {
                        "failure_count": len(failure_window),
                        "window_minutes": thresholds[
                            "mfa_window_minutes"
                        ],
                        "ip_address": ip_address,
                    },
                )
            )

    return alerts


def detect_context_anomalies(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    vpn_addresses: set[str],
) -> tuple[list[dict[str, Any]], int, int]:
    """Detect device, location, time and account anomalies."""
    alerts: list[dict[str, Any]] = []
    vpn_exceptions = 0
    testing_exceptions = 0
    profiles = configuration["identity_profiles"]
    thresholds = configuration["thresholds"]

    successful_events = [
        event
        for event in events
        if event["source_type"] == "authentication"
        and event["event_type"] == "login_success"
    ]

    for event in successful_events:
        if is_approved_test_event(event, configuration):
            testing_exceptions += 1
            continue

        username = event.get("username") or "unknown"
        profile = profiles.get(username)

        if profile is None:
            continue

        vpn_exception = event.get("ip_address") in vpn_addresses

        if vpn_exception:
            vpn_exceptions += 1

        if (
            not vpn_exception
            and is_detection_enabled(
                configuration,
                "new_device_sign_in",
            )
            and event.get("device_id")
            not in profile["approved_devices"]
        ):
            alerts.append(
                create_alert(
                    "new_device_sign_in",
                    "New-Device Sign-In",
                    username,
                    [event],
                    configuration,
                    ["DEVICE_NOT_IN_USER_BASELINE"],
                    {
                        "observed_device": event.get("device_id"),
                        "approved_devices": profile[
                            "approved_devices"
                        ],
                    },
                )
            )

        if (
            not vpn_exception
            and is_detection_enabled(
                configuration,
                "unusual_location",
            )
            and event.get("location")
            not in profile["usual_locations"]
        ):
            alerts.append(
                create_alert(
                    "unusual_location",
                    "Unusual Sign-In Location",
                    username,
                    [event],
                    configuration,
                    ["LOCATION_NOT_IN_USER_BASELINE"],
                    {
                        "observed_location": event.get("location"),
                        "usual_locations": profile[
                            "usual_locations"
                        ],
                    },
                )
            )

        event_hour = parse_time(event["event_time"]).hour
        normal_start = thresholds[
            "normal_access_start_hour_utc"
        ]
        normal_end = thresholds[
            "normal_access_end_hour_utc"
        ]

        if (
            is_detection_enabled(
                configuration,
                "abnormal_access_time",
            )
            and not normal_start <= event_hour < normal_end
        ):
            alerts.append(
                create_alert(
                    "abnormal_access_time",
                    "Abnormal Access Time",
                    username,
                    [event],
                    configuration,
                    ["ACCESS_OUTSIDE_NORMAL_UTC_HOURS"],
                    {
                        "observed_hour_utc": event_hour,
                        "normal_start_hour_utc": normal_start,
                        "normal_end_hour_utc": normal_end,
                    },
                )
            )

        if is_detection_enabled(
            configuration,
            "dormant_account_activity",
        ):
            last_activity = parse_time(
                profile["last_normal_activity"]
            )
            inactive_days = (
                parse_time(event["event_time"])
                - last_activity
            ).days

            if inactive_days >= thresholds[
                "dormant_account_days"
            ]:
                alerts.append(
                    create_alert(
                        "dormant_account_activity",
                        "Dormant-Account Activity",
                        username,
                        [event],
                        configuration,
                        ["DORMANT_ACCOUNT_USED"],
                        {
                            "inactive_days": inactive_days,
                            "dormant_threshold_days": thresholds[
                                "dormant_account_days"
                            ],
                            "last_normal_activity": profile[
                                "last_normal_activity"
                            ],
                        },
                    )
                )

        if (
            is_detection_enabled(
                configuration,
                "service_account_interactive_login",
            )
            and profile["account_type"] == "service"
            and not profile["interactive_login_allowed"]
            and bool(event["raw"].get("interactive", True))
        ):
            alerts.append(
                create_alert(
                    "service_account_interactive_login",
                    "Service-Account Interactive Login",
                    username,
                    [event],
                    configuration,
                    ["SERVICE_ACCOUNT_INTERACTIVE_LOGIN"],
                    {
                        "account_type": profile["account_type"],
                        "interactive_login_allowed": False,
                        "authentication_method": event["raw"].get(
                            "authentication_method"
                        ),
                    },
                )
            )

    return alerts, vpn_exceptions, testing_exceptions


def detect_impossible_travel(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    locations: dict[str, dict[str, float]],
    vpn_addresses: set[str],
) -> tuple[list[dict[str, Any]], int]:
    """Detect travel faster than the configured maximum speed."""
    if not is_detection_enabled(
        configuration,
        "impossible_travel",
    ):
        return [], 0

    successful_by_user: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if (
            event["source_type"] == "authentication"
            and event["event_type"] == "login_success"
            and event.get("username")
        ):
            successful_by_user[event["username"]].append(event)

    alerts: list[dict[str, Any]] = []
    vpn_exceptions = 0
    maximum_speed = configuration["thresholds"][
        "impossible_travel_speed_kmh"
    ]

    for username, successful_events in successful_by_user.items():
        ordered_events = sorted(
            successful_events,
            key=lambda event: parse_time(event["event_time"]),
        )

        for first_event, second_event in zip(
            ordered_events,
            ordered_events[1:],
        ):
            if (
                is_approved_test_event(
                    first_event,
                    configuration,
                )
                or is_approved_test_event(
                    second_event,
                    configuration,
                )
            ):
                continue

            if (
                first_event.get("ip_address") in vpn_addresses
                or second_event.get("ip_address") in vpn_addresses
            ):
                vpn_exceptions += 1
                continue

            first_location = locations.get(
                first_event.get("location")
            )
            second_location = locations.get(
                second_event.get("location")
            )

            if (
                first_location is None
                or second_location is None
                or first_event.get("location")
                == second_event.get("location")
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
                        "impossible_travel",
                        "Impossible Travel",
                        username,
                        [first_event, second_event],
                        configuration,
                        ["IMPOSSIBLE_TRAVEL_SPEED"],
                        {
                            "from_location": first_event.get(
                                "location"
                            ),
                            "to_location": second_event.get(
                                "location"
                            ),
                            "distance_km": round(
                                travelled_distance,
                                2,
                            ),
                            "elapsed_hours": round(
                                elapsed_hours,
                                2,
                            ),
                            "calculated_speed_kmh": round(
                                calculated_speed,
                                2,
                            ),
                            "maximum_speed_kmh": maximum_speed,
                        },
                    )
                )

    return alerts, vpn_exceptions


def detect_privilege_changes(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect privilege changes outside the user baseline."""
    if not is_detection_enabled(
        configuration,
        "suspicious_privilege_change",
    ):
        return []

    alerts: list[dict[str, Any]] = []
    profiles = configuration["identity_profiles"]

    for event in events:
        if (
            event["source_type"] != "authentication"
            or event["event_type"] != "role_change"
        ):
            continue

        username = event.get("username") or "unknown"
        profile = profiles.get(username)
        expected_role = (
            profile.get("expected_role")
            if profile
            else None
        )
        new_role = event["raw"].get("new_role")

        if expected_role is None or new_role != expected_role:
            alerts.append(
                create_alert(
                    "suspicious_privilege_change",
                    "Suspicious Privilege Change",
                    username,
                    [event],
                    configuration,
                    ["ROLE_CHANGE_OUTSIDE_BASELINE"],
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


def detect_risky_identity_events(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect high-risk sign-in and user-risk events."""
    if not is_detection_enabled(
        configuration,
        "risky_sign_in",
    ):
        return []

    high_risk_threshold = configuration["thresholds"][
        "high_sign_in_risk_score"
    ]
    alerts: list[dict[str, Any]] = []

    for event in events:
        if (
            event["source_type"] != "identity_risk"
            or event["event_type"]
            not in {
                "risky_sign_in",
                "user_risk_detected",
            }
            or event.get("risk_score") is None
            or float(event["risk_score"]) < high_risk_threshold
        ):
            continue

        reason_code = (
            "HIGH_RISK_SIGN_IN"
            if event["event_type"] == "risky_sign_in"
            else "HIGH_USER_RISK"
        )

        alerts.append(
            create_alert(
                "risky_sign_in",
                "Risky Sign-In Behaviour",
                event.get("username") or "unknown",
                [event],
                configuration,
                [reason_code],
                {
                    "risk_score": event["risk_score"],
                    "risk_state": event["raw"].get(
                        "risk_state"
                    ),
                    "risk_threshold": high_risk_threshold,
                    "risk_event_type": event["event_type"],
                },
            )
        )

    return alerts


def detect_identity_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    locations: dict[str, dict[str, float]],
    vpn_addresses: set[str],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Run all V2 Stage 4 identity detections."""
    alerts = detect_failure_patterns(
        events,
        configuration,
    )
    alerts.extend(
        detect_shared_source_patterns(
            events,
            configuration,
        )
    )
    alerts.extend(
        detect_mfa_activity(
            events,
            configuration,
        )
    )

    context_alerts, context_vpn, testing_exceptions = (
        detect_context_anomalies(
            events,
            configuration,
            vpn_addresses,
        )
    )
    alerts.extend(context_alerts)

    travel_alerts, travel_vpn = detect_impossible_travel(
        events,
        configuration,
        locations,
        vpn_addresses,
    )
    alerts.extend(travel_alerts)

    alerts.extend(
        detect_privilege_changes(
            events,
            configuration,
        )
    )
    alerts.extend(
        detect_risky_identity_events(
            events,
            configuration,
        )
    )

    alerts.sort(
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
            alert["username"],
        )
    )

    statistics = {
        "events": len(events),
        "detections": len(alerts),
        "vpn_exceptions": context_vpn + travel_vpn,
        "testing_exceptions": testing_exceptions,
    }

    return alerts, statistics


def save_identity_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store new alerts and count existing duplicate alerts."""
    created_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for alert in alerts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO v2_identity_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    confidence,
                    username,
                    device_id,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    ip_address,
                    location,
                    risk_score,
                    reason_codes,
                    mitre_techniques,
                    evidence
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    alert["alert_key"],
                    created_at,
                    alert["detection_type"],
                    alert["severity"],
                    alert["confidence"],
                    alert["username"],
                    alert["device_id"],
                    alert["first_event_time"],
                    alert["last_event_time"],
                    json.dumps(alert["source_event_ids"]),
                    json.dumps(alert["source_types"]),
                    alert["ip_address"],
                    alert["location"],
                    alert["risk_score"],
                    json.dumps(alert["reason_codes"]),
                    json.dumps(alert["mitre_techniques"]),
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
