"""Correlate Stage 4 alerts around the primary MAC identity."""

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


DEVICE_ALERT_TYPES = {
    "Unknown CYOD Device",
    "Unregistered MAC Address",
    "Device Inventory Mismatch",
    "Suspicious IP Address",
    "Wi-Fi Zone Violation",
    "Unknown Wired Device",
}


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def parse_time(value: str) -> datetime:
    """Parse an ISO timestamp as UTC."""
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")

    return parsed.astimezone(timezone.utc)


def create_key(
    detection_type: str,
    identity: str,
    event_ids: list[str],
) -> str:
    """Create a deterministic correlation key."""
    value = "|".join(
        [
            detection_type,
            identity,
            ",".join(sorted(event_ids)),
        ]
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def combine_severity(alerts: list[dict[str, Any]]) -> str:
    """Return the highest severity in a group."""
    return max(
        (
            alert["severity"]
            for alert in alerts
        ),
        key=lambda value: SEVERITY_RANK[value],
    )


def aggregate_device_alerts(
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group related device and IP alerts by MAC address."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    remaining = []

    for alert in alerts:
        if alert["detection_type"] not in DEVICE_ALERT_TYPES:
            remaining.append(alert)
            continue

        identity = (
            alert.get("mac_address")
            or alert.get("ip_address")
            or alert.get("hostname")
            or "unknown-device"
        )
        grouped[identity].append(alert)

    for identity, related in grouped.items():
        event_ids = sorted(
            {
                event_id
                for alert in related
                for event_id in alert["source_event_ids"]
            }
        )
        source_types = sorted(
            {
                source_type
                for alert in related
                for source_type in alert["source_types"]
            }
        )
        evidence = [
            {
                "detection_type": alert["detection_type"],
                "severity": alert["severity"],
                "event_ids": alert["source_event_ids"],
                "evidence": alert["evidence"],
            }
            for alert in related
        ]

        first_alert = min(
            related,
            key=lambda alert: parse_time(
                alert["first_event_time"]
            ),
        )
        last_alert = max(
            related,
            key=lambda alert: parse_time(
                alert["last_event_time"]
            ),
        )

        remaining.append(
            {
                "alert_key": create_key(
                    "MAC Device Investigation",
                    identity,
                    event_ids,
                ),
                "detection_type": "MAC Device Investigation",
                "severity": combine_severity(related),
                "first_event_time": first_alert[
                    "first_event_time"
                ],
                "last_event_time": last_alert[
                    "last_event_time"
                ],
                "source_event_ids": event_ids,
                "source_types": source_types,
                "ip_address": last_alert.get("ip_address"),
                "mac_address": last_alert.get("mac_address"),
                "hostname": last_alert.get("hostname"),
                "username": last_alert.get("username"),
                "location": last_alert.get("location"),
                "evidence": {
                    "primary_identity": "mac_address",
                    "identity": identity,
                    "related_detections": evidence,
                },
            }
        )

    return remaining


def detect_mac_reuse(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect the same MAC used by conflicting identities."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        mac_address = event.get("mac_address")

        if mac_address:
            grouped[mac_address.lower()].append(event)

    alerts = []
    overlap_minutes = configuration["thresholds"][
        "mac_reuse_overlap_minutes"
    ]

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
        locations = {
            event.get("location")
            for event in mac_events
            if event.get("location")
        }
        ip_addresses = {
            event.get("ip_address")
            for event in mac_events
            if event.get("ip_address")
        }

        conflicts = (
            len(hostnames) > 1
            or len(usernames) > 1
            or len(locations) > 1
            or len(ip_addresses) > 1
        )

        if not conflicts:
            continue

        ordered_events = sorted(
            mac_events,
            key=lambda event: parse_time(event["event_time"]),
        )

        overlapping = False

        for index, event in enumerate(ordered_events):
            event_time = parse_time(event["event_time"])
            limit = event_time + timedelta(
                minutes=overlap_minutes
            )

            for later_event in ordered_events[index + 1 :]:
                later_time = parse_time(
                    later_event["event_time"]
                )

                if later_time > limit:
                    break

                overlapping = True
                break

            if overlapping:
                break

        if not overlapping:
            continue

        event_ids = [
            event["source_event_id"]
            for event in ordered_events
        ]
        first_event = ordered_events[0]
        last_event = ordered_events[-1]

        alerts.append(
            {
                "alert_key": create_key(
                    "MAC Address Reuse or Possible Spoofing",
                    mac_address,
                    event_ids,
                ),
                "detection_type": (
                    "MAC Address Reuse or Possible Spoofing"
                ),
                "severity": configuration["severity"][
                    "MAC Address Reuse or Possible Spoofing"
                ],
                "first_event_time": first_event["event_time"],
                "last_event_time": last_event["event_time"],
                "source_event_ids": event_ids,
                "source_types": sorted(
                    {
                        event["source_type"]
                        for event in ordered_events
                    }
                ),
                "ip_address": last_event.get("ip_address"),
                "mac_address": mac_address,
                "hostname": last_event.get("hostname"),
                "username": last_event.get("username"),
                "location": last_event.get("location"),
                "evidence": {
                    "hostnames": sorted(hostnames),
                    "usernames": sorted(usernames),
                    "locations": sorted(locations),
                    "ip_addresses": sorted(ip_addresses),
                    "overlap_window_minutes": overlap_minutes,
                },
            }
        )

    return alerts


def correlate_network_alerts(
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return correlated Stage 4 alerts."""
    correlated = aggregate_device_alerts(alerts)
    correlated.extend(
        detect_mac_reuse(
            events,
            configuration,
        )
    )

    return sorted(
        correlated,
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
        ),
    )
