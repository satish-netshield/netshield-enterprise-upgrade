"""Stage 7 event correlation, risk scoring and IoC extraction."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any


IOC_FIELDS = {
    "ip_address",
    "mac_address",
    "hostname",
    "process_name",
}


def parse_time(value: str) -> datetime:
    """Parse an ISO 8601 timestamp."""
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def shared_fields(
    first: dict[str, Any],
    second: dict[str, Any],
    primary_fields: list[str],
) -> list[str]:
    """Return non-empty identity fields shared by two records."""
    return [
        field
        for field in primary_fields
        if first.get(field)
        and first.get(field) == second.get(field)
    ]


def within_time_window(
    first: dict[str, Any],
    second: dict[str, Any],
    window_minutes: int,
) -> bool:
    """Return whether two events are within the time window."""
    difference = abs(
        (
            parse_time(first["event_time"])
            - parse_time(second["event_time"])
        ).total_seconds()
    )

    return difference <= window_minutes * 60


def build_groups(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[list[dict[str, Any]]]:
    """Group related events using identity and time context."""
    correlation = configuration["correlation"]
    primary_fields = correlation["primary_fields"]
    window_minutes = correlation["time_window_minutes"]
    minimum_shared = correlation["minimum_shared_fields"]

    groups: list[list[dict[str, Any]]] = []

    for event in sorted(
        events,
        key=lambda item: parse_time(item["event_time"]),
    ):
        matches = []

        for group in groups:
            related = any(
                within_time_window(
                    event,
                    existing,
                    window_minutes,
                )
                and len(
                    shared_fields(
                        event,
                        existing,
                        primary_fields,
                    )
                ) >= minimum_shared
                for existing in group
            )

            if related:
                matches.append(group)

        if not matches:
            groups.append([event])
            continue

        selected = matches[0]
        selected.append(event)

        for other in matches[1:]:
            selected.extend(other)
            groups.remove(other)

    return groups


def detection_points(
    event: dict[str, Any],
    configuration: dict[str, Any],
) -> tuple[int, list[str]]:
    """Calculate risk points for one event."""
    points = configuration["risk_scoring"]["points"]
    detection_type = event.get("detection_type", "")
    event_type = event.get("event_type", "")
    severity = event.get("severity", "Low")
    detection_lower = detection_type.lower()
    event_lower = event_type.lower()
    reasons = []

    score = points.get(
        f"{severity.lower()}_detection",
        0,
    )

    if score:
        reasons.append(
            f"{severity} detection: {detection_type}"
        )

    if "bypass" in detection_lower or "bypass" in event_lower:
        score += points["authentication_bypass"]
        reasons.append("Authentication-bypass evidence")

    if (
        "database error" in detection_lower
        or event_lower == "database_error"
    ):
        score += points["database_error"]
        reasons.append("Database-error evidence")

    if "repeated" in detection_lower or "repeated" in event_lower:
        score += points["repeated_abnormal_requests"]
        reasons.append("Repeated abnormal activity")

    if "unknown endpoint process" in detection_lower:
        score += points["unknown_process"]
        reasons.append("Unknown endpoint process")

    if "restricted wired" in detection_lower:
        score += points["restricted_location"]
        reasons.append("Restricted location activity")

    if "suspicious ip" in detection_lower:
        score += points["suspicious_ip"]
        reasons.append("Suspicious source IP")

    return score, reasons


def apply_exceptions(
    group: list[dict[str, Any]],
    score: int,
    reasons: list[str],
    configuration: dict[str, Any],
) -> tuple[int, list[str]]:
    """Apply approved-device and known-VPN exceptions."""
    correlation = configuration["correlation"]
    points = configuration["risk_scoring"]["points"]

    if correlation.get("approved_device_reduces_risk") and any(
        event.get("device_approved") is True
        for event in group
    ):
        score += points["approved_device_exception"]
        reasons.append("Approved-device exception applied")

    if correlation.get("known_vpn_reduces_network_risk") and any(
        event.get("known_vpn") is True
        for event in group
    ):
        score += points["known_vpn_exception"]
        reasons.append("Known VPN exception applied")

    return max(score, 0), reasons


def reduce_isolated_low_value_alert(
    group: list[dict[str, Any]],
    score: int,
    reasons: list[str],
) -> tuple[int, list[str]]:
    """Prevent one isolated low-value event from becoming high risk."""
    if len(group) != 1:
        return score, reasons

    event = group[0]
    severity = event.get("severity", "Low")

    if severity in {"Low", "Medium"}:
        reduced_score = min(score, 3)

        if reduced_score != score:
            reasons.append(
                "Isolated low-value alert risk reduced"
            )

        return reduced_score, reasons

    return score, reasons


def score_to_severity(
    score: int,
    configuration: dict[str, Any],
) -> str:
    """Convert a score into a severity band."""
    bands = configuration["risk_scoring"]["severity_bands"]

    for severity in ("Critical", "High", "Medium", "Low"):
        band = bands[severity]

        if band["minimum"] <= score <= band["maximum"]:
            return severity

    return "Critical"


def extract_indicators(
    group: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Separate observable IoCs from suspicious behaviours."""
    configured_fields = set(
        configuration.get("ioc_fields", [])
    )
    ioc_fields = configured_fields & IOC_FIELDS
    behaviours: set[str] = set()
    indicators: list[dict[str, Any]] = []

    for event in group:
        detection_type = event.get("detection_type", "")
        event_type = event.get("event_type", "")
        detection_lower = detection_type.lower()
        event_lower = event_type.lower()

        is_ioc_event = any(
            phrase in detection_lower
            for phrase in (
                "suspicious ip",
                "port scanning",
                "rogue access point",
                "unknown endpoint process",
                "possible spoofing",
                "authentication bypass",
                "database error",
            )
        )

        if is_ioc_event:
            for field in ioc_fields:
                value = event.get(field)

                if value:
                    indicators.append(
                        {
                            "type": field,
                            "value": value,
                            "source_event_id": event.get(
                                "source_event_id"
                            ),
                        }
                    )

        is_behaviour = (
            "repeated" in detection_lower
            or "unexpected cpu" in detection_lower
            or "unusual location" in detection_lower
            or "impossible travel" in detection_lower
            or "suspicious input" in detection_lower
            or "repeated" in event_lower
        )

        if is_behaviour:
            behaviours.add(detection_type or event_type)

    unique_indicators = []
    seen = set()

    for indicator in indicators:
        key = (
            indicator["type"],
            str(indicator["value"]),
        )

        if key not in seen:
            seen.add(key)
            unique_indicators.append(indicator)

    return unique_indicators, sorted(behaviours)


def create_correlated_incident(
    group: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Create one context-rich correlated incident."""
    ordered = sorted(
        group,
        key=lambda event: parse_time(event["event_time"]),
    )

    score = configuration["risk_scoring"]["base_score"]
    reasons = []

    for event in ordered:
        event_score, event_reasons = detection_points(
            event,
            configuration,
        )
        score += event_score
        reasons.extend(event_reasons)

    source_types = {
        event.get("source_type")
        for event in ordered
        if event.get("source_type")
    }

    if len(source_types) > 1:
        score += configuration["risk_scoring"]["points"][
            "multiple_sources"
        ]
        reasons.append("Evidence from multiple sources")

    score, reasons = apply_exceptions(
        group,
        score,
        reasons,
        configuration,
    )

    score, reasons = reduce_isolated_low_value_alert(
        group,
        score,
        reasons,
    )

    indicators, behaviours = extract_indicators(
        group,
        configuration,
    )

    event_ids = [
        event.get("source_event_id")
        for event in ordered
        if event.get("source_event_id")
    ]

    identity = {
        field: sorted(
            {
                event.get(field)
                for event in ordered
                if event.get(field)
            }
        )
        for field in (
            "username",
            "ip_address",
            "mac_address",
            "hostname",
            "process_name",
            "location",
        )
    }

    key_material = json_key(
        {
            "event_ids": sorted(event_ids),
            "identity": identity,
        }
    )

    return {
        "incident_key": hashlib.sha256(
            key_material.encode("utf-8")
        ).hexdigest(),
        "first_event_time": ordered[0]["event_time"],
        "last_event_time": ordered[-1]["event_time"],
        "source_event_ids": event_ids,
        "source_types": sorted(source_types),
        "identity": identity,
        "detection_types": sorted(
            {
                event.get("detection_type")
                for event in ordered
                if event.get("detection_type")
            }
        ),
        "risk_score": score,
        "severity": score_to_severity(
            score,
            configuration,
        ),
        "risk_reasons": sorted(set(reasons)),
        "iocs": indicators,
        "behaviours": behaviours,
        "event_count": len(ordered),
    }


def json_key(value: Any) -> str:
    """Create stable JSON text for an incident key."""
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def correlate_events(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Correlate events into context-rich incidents."""
    return sorted(
        [
            create_correlated_incident(
                group,
                configuration,
            )
            for group in build_groups(
                events,
                configuration,
            )
        ],
        key=lambda incident: (
            incident["first_event_time"],
            incident["incident_key"],
        ),
    )
