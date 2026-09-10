"""Detect and evaluate Phase 3A V2 Stage 6 network activity."""

import hashlib
import ipaddress
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.utils.sqlite_connection import managed_connection


def parse_time(value: str) -> datetime:
    """Return an ISO 8601 timestamp in UTC."""
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")

    return parsed.astimezone(timezone.utc)


def event_value(
    event: dict[str, Any],
    field_name: str,
) -> Any:
    """Return a normalised field or its raw-event value."""
    value = event.get(field_name)

    if value is not None:
        return value

    return event["raw"].get(field_name)


def load_stage6_events(
    database_path: Path,
    source_files: list[str],
) -> list[dict[str, Any]]:
    """Load accepted Stage 6 network events in time order."""
    placeholders = ", ".join("?" for _ in source_files)

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM security_events
            WHERE source_file IN ({placeholders})
            ORDER BY event_time, source_event_id
            """,
            tuple(source_files),
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_device_inventory(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load the V2 device inventory."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT *
            FROM device_inventory
            ORDER BY device_id
            """
        ).fetchall()

    return [dict(row) for row in rows]


def load_address_list(file_path: Path) -> set[str]:
    """Load non-comment addresses from a text file."""
    if not file_path.is_file():
        return set()

    return {
        line.strip()
        for line in file_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
        and not line.strip().startswith("#")
    }


def inventory_record(
    event: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Match inventory using device ID or asset ID."""
    device_id = event.get("device_id")
    asset_id = event.get("asset_id")

    for record in inventory:
        if device_id and record["device_id"] == device_id:
            return record

        if asset_id and record["asset_id"] == asset_id:
            return record

    return None


def address_in_networks(
    address: str | None,
    networks: list[str],
) -> bool:
    """Return whether an address belongs to a configured network."""
    if not address:
        return False

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return False

    for network_value in networks:
        try:
            network = ipaddress.ip_network(
                network_value,
                strict=False,
            )
        except ValueError:
            continue

        if parsed_address in network:
            return True

    return False


def is_approved_test(
    event: dict[str, Any],
    configuration: dict[str, Any],
) -> bool:
    """Return whether an event matches the testing exception."""
    approved_users = set(
        configuration["approved_exceptions"][
            "approved_testing_users"
        ]
    )

    return (
        event.get("username") in approved_users
        and event_value(event, "approved_test") is True
    )


def is_vpn_exception(
    event: dict[str, Any],
    vpn_addresses: set[str],
) -> bool:
    """Return whether the event uses an approved VPN address."""
    return event.get("ip_address") in vpn_addresses


def is_ip_approved(
    ip_address: str | None,
    configuration: dict[str, Any],
    allowlist: set[str],
    vpn_addresses: set[str],
) -> bool:
    """Return whether an address has approved network evidence."""
    if not ip_address:
        return False

    if ip_address in allowlist or ip_address in vpn_addresses:
        return True

    return address_in_networks(
        ip_address,
        configuration["ip_controls"]["approved_networks"],
    )


def alert_key(
    detection_type: str,
    event_ids: list[str],
    identity: str,
) -> str:
    """Create a deterministic network-alert key."""
    key_source = "|".join(
        [
            detection_type,
            identity,
            *sorted(event_ids),
        ]
    )
    return hashlib.sha256(
        key_source.encode("utf-8")
    ).hexdigest()


def create_alert(
    rule_key: str,
    detection_type: str,
    events: list[dict[str, Any]],
    reason_codes: list[str],
    evidence: dict[str, Any],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Create one traceable Stage 6 network alert."""
    ordered_events = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )
    first_event = ordered_events[0]
    last_event = ordered_events[-1]
    event_ids = [
        event["source_event_id"]
        for event in ordered_events
    ]

    identity = (
        last_event.get("device_id")
        or last_event.get("asset_id")
        or last_event.get("ip_address")
        or last_event.get("mac_address")
        or last_event.get("hostname")
        or "unknown"
    )

    return {
        "rule_key": rule_key,
        "alert_key": alert_key(
            detection_type,
            event_ids,
            str(identity),
        ),
        "detection_type": detection_type,
        "severity": configuration["severity"][detection_type],
        "confidence": configuration["confidence"][
            detection_type
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
        "device_id": last_event.get("device_id"),
        "asset_id": last_event.get("asset_id"),
        "username": last_event.get("username"),
        "ip_address": last_event.get("ip_address"),
        "mac_address": last_event.get("mac_address"),
        "hostname": last_event.get("hostname"),
        "location": last_event.get("location"),
        "connection_type": event_value(
            last_event,
            "connection_type",
        ),
        "destination_ip": event_value(
            last_event,
            "destination_ip",
        ),
        "destination_port": event_value(
            last_event,
            "destination_port",
        ),
        "service": event_value(last_event, "service"),
        "reason_codes": sorted(set(reason_codes)),
        "evidence": evidence,
    }


def first_count_window(
    events: list[dict[str, Any]],
    threshold: int,
    minutes: int,
) -> list[dict[str, Any]]:
    """Return the first event window reaching a count."""
    ordered = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )

    for start_index, start_event in enumerate(ordered):
        end_time = (
            parse_time(start_event["event_time"])
            + timedelta(minutes=minutes)
        )
        window = [
            event
            for event in ordered[start_index:]
            if parse_time(event["event_time"]) <= end_time
        ]

        if len(window) >= threshold:
            return window[:threshold]

    return []


def first_port_scan_window(
    events: list[dict[str, Any]],
    threshold: int,
    minutes: int,
) -> list[dict[str, Any]]:
    """Return the first window reaching a unique-port count."""
    ordered = sorted(
        events,
        key=lambda event: parse_time(event["event_time"]),
    )

    for start_index, start_event in enumerate(ordered):
        end_time = (
            parse_time(start_event["event_time"])
            + timedelta(minutes=minutes)
        )
        window = [
            event
            for event in ordered[start_index:]
            if parse_time(event["event_time"]) <= end_time
        ]

        selected = []
        observed_ports = set()

        for event in window:
            destination_port = event_value(
                event,
                "destination_port",
            )

            if (
                destination_port is not None
                and destination_port not in observed_ports
            ):
                observed_ports.add(destination_port)
                selected.append(event)

        if len(observed_ports) >= threshold:
            return selected[:threshold]

    return []


def detect_suspicious_ips(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    allowlist: set[str],
    blocklist: set[str],
    vpn_addresses: set[str],
) -> list[dict[str, Any]]:
    """Detect blocklisted, restricted and unapproved sources."""
    if not configuration["detection_rules"][
        "suspicious_ip_address"
    ]:
        return []

    grouped_events: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if is_approved_test(event, configuration):
            continue

        ip_address = event.get("ip_address")

        if ip_address:
            grouped_events[ip_address].append(event)

    alerts = []

    for ip_address, related_events in grouped_events.items():
        if ip_address in vpn_addresses:
            continue

        reason_code = None
        match_type = None

        if ip_address in blocklist:
            reason_code = "IP_BLOCKLIST_MATCH"
            match_type = "blocklist"
        elif address_in_networks(
            ip_address,
            configuration["ip_controls"][
                "restricted_networks"
            ],
        ):
            reason_code = "RESTRICTED_NETWORK"
            match_type = "restricted_network"
        elif not is_ip_approved(
            ip_address,
            configuration,
            allowlist,
            vpn_addresses,
        ):
            reason_code = "IP_NOT_APPROVED"
            match_type = "not_allowlisted"

        if reason_code is None:
            continue

        alerts.append(
            create_alert(
                "suspicious_ip_address",
                "Suspicious IP Address",
                related_events,
                [reason_code],
                {
                    "ip_address": ip_address,
                    "match_type": match_type,
                    "event_count": len(related_events),
                },
                configuration,
            )
        )

    return alerts


def detect_connection_patterns(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect repeated, scanning and abnormal connections."""
    thresholds = configuration["thresholds"]
    rules = configuration["detection_rules"]
    alerts = []

    attempts_by_source: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)
    ports_by_source: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)
    abnormal_by_identity: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    normal_hours = configuration["network_policy"][
        "normal_utc_hours"
    ]
    start_hour = normal_hours["start"]
    end_hour = normal_hours["end"]

    for event in events:
        if is_approved_test(event, configuration):
            continue

        ip_address = event.get("ip_address")

        if (
            event["event_type"] == "connection_attempt"
            and ip_address
        ):
            attempts_by_source[ip_address].append(event)

        if (
            event["event_type"] == "port_connection"
            and ip_address
        ):
            ports_by_source[ip_address].append(event)

        event_hour = parse_time(event["event_time"]).hour
        outside_normal_hours = not (
            start_hour <= event_hour < end_hour
        )

        if (
            outside_normal_hours
            and event["event_type"]
            in {
                "connection_allowed",
                "connection_attempt",
                "wired_connection",
            }
        ):
            identity = (
                event.get("device_id")
                or event.get("asset_id")
                or ip_address
                or event.get("hostname")
                or "unknown"
            )
            abnormal_by_identity[str(identity)].append(event)

    if rules["repeated_connection_attempts"]:
        for ip_address, attempts in attempts_by_source.items():
            window = first_count_window(
                attempts,
                thresholds["repeated_connection_attempts"],
                thresholds["connection_window_minutes"],
            )

            if window:
                alerts.append(
                    create_alert(
                        "repeated_connection_attempts",
                        "Repeated Connection Attempts",
                        window,
                        ["REPEATED_CONNECTION_THRESHOLD"],
                        {
                            "ip_address": ip_address,
                            "attempt_count": len(window),
                            "window_minutes": thresholds[
                                "connection_window_minutes"
                            ],
                        },
                        configuration,
                    )
                )

    if rules["port_scanning"]:
        for ip_address, port_events in ports_by_source.items():
            window = first_port_scan_window(
                port_events,
                thresholds["port_scan_unique_ports"],
                thresholds["port_scan_window_minutes"],
            )

            if window:
                unique_ports = sorted(
                    {
                        event_value(
                            event,
                            "destination_port",
                        )
                        for event in window
                    }
                )
                alerts.append(
                    create_alert(
                        "port_scanning",
                        "Port Scanning",
                        window,
                        ["PORT_SCAN_THRESHOLD"],
                        {
                            "ip_address": ip_address,
                            "unique_ports": unique_ports,
                            "port_count": len(unique_ports),
                            "window_minutes": thresholds[
                                "port_scan_window_minutes"
                            ],
                        },
                        configuration,
                    )
                )

    if rules["abnormal_connection_pattern"]:
        for identity, abnormal_events in (
            abnormal_by_identity.items()
        ):
            window = first_count_window(
                abnormal_events,
                thresholds["abnormal_connection_count"],
                thresholds[
                    "abnormal_connection_window_minutes"
                ],
            )

            if window:
                alerts.append(
                    create_alert(
                        "abnormal_connection_pattern",
                        "Abnormal Connection Pattern",
                        window,
                        ["ABNORMAL_TIME_AND_VOLUME"],
                        {
                            "identity": identity,
                            "connection_count": len(window),
                            "window_minutes": thresholds[
                                "abnormal_connection_window_minutes"
                            ],
                            "normal_utc_hours": normal_hours,
                        },
                        configuration,
                    )
                )

    return alerts


def detect_restricted_services(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect connections to restricted ports or services."""
    if not configuration["detection_rules"][
        "restricted_port_or_service"
    ]:
        return []

    restricted_ports = set(
        configuration["network_policy"]["restricted_ports"]
    )
    restricted_services = {
        service.lower()
        for service in configuration["network_policy"][
            "restricted_services"
        ]
    }

    alerts = []

    for event in events:
        if is_approved_test(event, configuration):
            continue

        destination_port = event_value(
            event,
            "destination_port",
        )
        service = event_value(event, "service")
        normalised_service = (
            str(service).lower()
            if service is not None
            else None
        )

        port_match = destination_port in restricted_ports
        service_match = (
            normalised_service in restricted_services
        )

        if not port_match and not service_match:
            continue

        reason_codes = []

        if port_match:
            reason_codes.append("RESTRICTED_PORT")

        if service_match:
            reason_codes.append("RESTRICTED_SERVICE")

        alerts.append(
            create_alert(
                "restricted_port_or_service",
                "Restricted Port or Service",
                [event],
                reason_codes,
                {
                    "destination_port": destination_port,
                    "service": service,
                    "restricted_ports": sorted(
                        restricted_ports
                    ),
                    "restricted_services": sorted(
                        restricted_services
                    ),
                },
                configuration,
            )
        )

    return alerts


def detect_device_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect unknown devices, MAC reuse and wired violations."""
    rules = configuration["detection_rules"]
    alerts = []
    events_by_mac: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    restricted_wired_zones = set(
        configuration["zones"]["restricted_wired_zones"]
    )

    for event in events:
        if is_approved_test(event, configuration):
            continue

        record = inventory_record(event, inventory)
        connection_type = event_value(
            event,
            "connection_type",
        )
        mac_address = (
            event.get("mac_address") or ""
        ).lower()

        if mac_address:
            events_by_mac[mac_address].append(event)

        if (
            rules["unknown_cyod_device"]
            and event["source_type"] == "wifi"
            and event["event_type"]
            in {"device_connected", "device_observed"}
            and record is None
        ):
            alerts.append(
                create_alert(
                    "unknown_cyod_device",
                    "Unknown CYOD Device",
                    [event],
                    ["DEVICE_NOT_IN_INVENTORY"],
                    {
                        "device_id": event.get("device_id"),
                        "asset_id": event.get("asset_id"),
                        "mac_address_role": (
                            "supporting_evidence_only"
                        ),
                    },
                    configuration,
                )
            )

        if (
            rules["unknown_wired_device"]
            and event["source_type"] == "network"
            and connection_type == "wired"
            and record is None
        ):
            alerts.append(
                create_alert(
                    "unknown_wired_device",
                    "Unknown Wired Device",
                    [event],
                    ["WIRED_DEVICE_NOT_IN_INVENTORY"],
                    {
                        "device_id": event.get("device_id"),
                        "asset_id": event.get("asset_id"),
                        "observed_hostname": event.get(
                            "hostname"
                        ),
                        "mac_address_role": (
                            "supporting_evidence_only"
                        ),
                    },
                    configuration,
                )
            )

        if (
            rules["restricted_wired_access"]
            and event["source_type"] == "network"
            and connection_type == "wired"
            and event.get("location") in restricted_wired_zones
        ):
            alerts.append(
                create_alert(
                    "restricted_wired_access",
                    "Restricted Wired Access",
                    [event],
                    ["RESTRICTED_WIRED_ZONE"],
                    {
                        "location": event.get("location"),
                        "restricted_wired_zones": sorted(
                            restricted_wired_zones
                        ),
                    },
                    configuration,
                )
            )

    if rules["mac_reuse_or_possible_spoofing"]:
        overlap = timedelta(
            minutes=configuration["thresholds"][
                "mac_reuse_overlap_minutes"
            ]
        )

        for mac_address, mac_events in events_by_mac.items():
            ordered = sorted(
                mac_events,
                key=lambda event: parse_time(
                    event["event_time"]
                ),
            )
            finding = None

            for first_index, first_event in enumerate(ordered):
                first_identity = (
                    first_event.get("device_id")
                    or first_event.get("asset_id")
                )

                if not first_identity:
                    continue

                for second_event in ordered[first_index + 1:]:
                    time_difference = (
                        parse_time(second_event["event_time"])
                        - parse_time(first_event["event_time"])
                    )

                    if time_difference > overlap:
                        break

                    second_identity = (
                        second_event.get("device_id")
                        or second_event.get("asset_id")
                    )

                    if (
                        second_identity
                        and second_identity != first_identity
                    ):
                        finding = (
                            first_event,
                            second_event,
                            str(first_identity),
                            str(second_identity),
                        )
                        break

                if finding is not None:
                    break

            if finding is None:
                continue

            (
                first_event,
                second_event,
                first_identity,
                second_identity,
            ) = finding

            alerts.append(
                create_alert(
                    "mac_reuse_or_possible_spoofing",
                    "MAC Address Reuse or Possible Spoofing",
                    [first_event, second_event],
                    ["MAC_SHARED_BY_DIFFERENT_DEVICE_IDENTITIES"],
                    {
                        "mac_address": mac_address,
                        "first_identity": first_identity,
                        "second_identity": second_identity,
                        "overlap_minutes": configuration[
                            "thresholds"
                        ]["mac_reuse_overlap_minutes"],
                        "mac_address_role": (
                            "supporting_evidence_only"
                        ),
                    },
                    configuration,
                )
            )

    return alerts


def detect_wifi_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect wireless security and zone violations."""
    rules = configuration["detection_rules"]
    wifi_policy = configuration["wifi_policy"]
    restricted_zones = set(
        configuration["zones"]["restricted_wifi_zones"]
    )
    approved_access_points = {
        access_point["access_point_id"]
        for access_point in wifi_policy[
            "approved_access_points"
        ]
    }
    alerts = []

    for event in events:
        if (
            event["source_type"] != "wifi"
            or is_approved_test(event, configuration)
        ):
            continue

        event_type = event["event_type"]
        security_mode = event_value(
            event,
            "security_mode",
        )
        cipher = event_value(event, "cipher")
        access_point_id = event_value(
            event,
            "access_point_id",
        )

        if (
            rules["wpa3_policy_violation"]
            and event_type == "wpa3_policy_check"
            and (
                security_mode
                != wifi_policy["required_security"]
                or cipher != wifi_policy["allowed_cipher"]
                or event.get("status") == "violation"
            )
        ):
            alerts.append(
                create_alert(
                    "wpa3_policy_violation",
                    "WPA3 Policy Violation",
                    [event],
                    ["WIFI_SECURITY_POLICY_NOT_SATISFIED"],
                    {
                        "observed_security": security_mode,
                        "observed_cipher": cipher,
                        "required_security": wifi_policy[
                            "required_security"
                        ],
                        "required_cipher": wifi_policy[
                            "allowed_cipher"
                        ],
                    },
                    configuration,
                )
            )

        if (
            rules["wpa2_downgrade_attempt"]
            and event_type == "wpa2_downgrade_attempt"
            and not wifi_policy["allow_wpa2_downgrade"]
        ):
            alerts.append(
                create_alert(
                    "wpa2_downgrade_attempt",
                    "WPA2 Downgrade Attempt",
                    [event],
                    ["WPA2_DOWNGRADE_NOT_ALLOWED"],
                    {
                        "observed_security": security_mode,
                        "required_security": wifi_policy[
                            "required_security"
                        ],
                    },
                    configuration,
                )
            )

        if (
            rules["rogue_access_point"]
            and event_type == "access_point_observed"
            and (
                access_point_id not in approved_access_points
                or event.get("status") == "unauthorised"
            )
        ):
            alerts.append(
                create_alert(
                    "rogue_access_point",
                    "Rogue Access Point",
                    [event],
                    ["ACCESS_POINT_NOT_APPROVED"],
                    {
                        "access_point_id": access_point_id,
                        "ssid": event_value(event, "ssid"),
                        "security_mode": security_mode,
                        "approved_access_points": sorted(
                            approved_access_points
                        ),
                    },
                    configuration,
                )
            )

        if (
            rules["wifi_zone_violation"]
            and event_type
            in {"device_connected", "device_observed"}
            and event.get("location") in restricted_zones
        ):
            alerts.append(
                create_alert(
                    "wifi_zone_violation",
                    "Wi-Fi Zone Violation",
                    [event],
                    ["RESTRICTED_WIFI_ZONE"],
                    {
                        "location": event.get("location"),
                        "restricted_wifi_zones": sorted(
                            restricted_zones
                        ),
                    },
                    configuration,
                )
            )

    return alerts


def detect_network_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    inventory: list[dict[str, Any]],
    allowlist: set[str],
    blocklist: set[str],
    vpn_addresses: set[str],
) -> list[dict[str, Any]]:
    """Run all Stage 6 network detections."""
    alerts = []

    alerts.extend(
        detect_suspicious_ips(
            events,
            configuration,
            allowlist,
            blocklist,
            vpn_addresses,
        )
    )
    alerts.extend(
        detect_connection_patterns(
            events,
            configuration,
        )
    )
    alerts.extend(
        detect_restricted_services(
            events,
            configuration,
        )
    )
    alerts.extend(
        detect_device_activity(
            events,
            configuration,
            inventory,
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
            alert["alert_key"],
        ),
    )


def is_approved_connection(
    event: dict[str, Any],
    configuration: dict[str, Any],
    inventory: list[dict[str, Any]],
    allowlist: set[str],
    vpn_addresses: set[str],
) -> bool:
    """Return whether an event has approved connection context."""
    record = inventory_record(event, inventory)

    if record is None:
        return False

    if record["registration_status"] != "registered":
        return False

    if record["compliance_status"] != "compliant":
        return False

    if not is_ip_approved(
        event.get("ip_address"),
        configuration,
        allowlist,
        vpn_addresses,
    ):
        return False

    connection_type = event_value(
        event,
        "connection_type",
    )

    if (
        connection_type == "wired"
        and event.get("location")
        in configuration["zones"]["restricted_wired_zones"]
    ):
        return False

    if event["source_type"] == "wifi":
        approved_access_points = {
            access_point["access_point_id"]
            for access_point in configuration["wifi_policy"][
                "approved_access_points"
            ]
        }

        if (
            event_value(event, "access_point_id")
            not in approved_access_points
        ):
            return False

        if (
            event_value(event, "security_mode")
            != configuration["wifi_policy"][
                "required_security"
            ]
        ):
            return False

        if (
            event_value(event, "cipher")
            != configuration["wifi_policy"]["allowed_cipher"]
        ):
            return False

    return True


def acl_result(
    decision: str,
    configuration: dict[str, Any],
    automation_acl: dict[str, Any],
) -> tuple[str | None, str | None, str]:
    """Return the ACL result for a proposed response."""
    action = configuration["response_actions"][decision]

    if action is None:
        return None, None, "not_required"

    if action in automation_acl["automatic"]:
        return action, "automatic", "simulated_automatic"

    if action in automation_acl["approval_required"]:
        return action, "approval_required", "approval_required"

    if action in automation_acl["manual_only"]:
        return action, "manual_only", "manual_required"

    return action, "default_deny", "denied_by_acl"


def decision_key(
    source_event_id: str,
    decision: str,
    matching_rules: list[str],
) -> str:
    """Create a deterministic network-decision key."""
    key_source = "|".join(
        [
            source_event_id,
            decision,
            *sorted(matching_rules),
        ]
    )
    return hashlib.sha256(
        key_source.encode("utf-8")
    ).hexdigest()


def build_access_decisions(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    configuration: dict[str, Any],
    inventory: list[dict[str, Any]],
    allowlist: set[str],
    vpn_addresses: set[str],
    automation_acl: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create one explainable access decision per event."""
    alerts_by_event: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for alert in alerts:
        for source_event_id in alert["source_event_ids"]:
            alerts_by_event[source_event_id].append(alert)

    precedence = configuration["network_policy"][
        "decision_precedence"
    ]
    precedence_rank = {
        decision: rank
        for rank, decision in enumerate(precedence)
    }
    decisions = []

    for event in events:
        source_event_id = event["source_event_id"]
        related_alerts = alerts_by_event.get(
            source_event_id,
            [],
        )
        matching_rules = sorted(
            {
                alert["rule_key"]
                for alert in related_alerts
            }
        )
        reason_codes = sorted(
            {
                reason_code
                for alert in related_alerts
                for reason_code in alert["reason_codes"]
            }
        )
        exception = None

        if is_approved_test(event, configuration):
            decision = "allow"
            matching_rules = ["approved_testing_exception"]
            reason_codes = ["APPROVED_TESTING_EXCEPTION"]
            exception = "approved_testing"
        elif related_alerts:
            matching_decisions = [
                configuration["decision_mapping"][rule]
                for rule in matching_rules
            ]
            decision = min(
                matching_decisions,
                key=lambda value: precedence_rank[value],
            )
        elif is_vpn_exception(event, vpn_addresses):
            decision = "allow"
            matching_rules = ["approved_vpn_exception"]
            reason_codes = ["APPROVED_VPN_EXCEPTION"]
            exception = "approved_vpn"
        elif is_approved_connection(
            event,
            configuration,
            inventory,
            allowlist,
            vpn_addresses,
        ):
            decision = "allow"
            matching_rules = ["approved_connection"]
            reason_codes = ["APPROVED_CONNECTION"]
        else:
            decision = configuration["network_policy"][
                "default_decision"
            ]
            matching_rules = ["default_deny"]
            reason_codes = [
                "UNVERIFIED_NETWORK_CONTEXT"
            ]

        (
            response_action,
            acl_control_level,
            response_status,
        ) = acl_result(
            decision,
            configuration,
            automation_acl,
        )

        decisions.append(
            {
                "decision_key": decision_key(
                    source_event_id,
                    decision,
                    matching_rules,
                ),
                "source_event_id": source_event_id,
                "event_time": event["event_time"],
                "source_type": event["source_type"],
                "event_type": event["event_type"],
                "device_id": event.get("device_id"),
                "asset_id": event.get("asset_id"),
                "username": event.get("username"),
                "ip_address": event.get("ip_address"),
                "mac_address": event.get("mac_address"),
                "hostname": event.get("hostname"),
                "location": event.get("location"),
                "connection_type": event_value(
                    event,
                    "connection_type",
                ),
                "destination_ip": event_value(
                    event,
                    "destination_ip",
                ),
                "destination_port": event_value(
                    event,
                    "destination_port",
                ),
                "service": event_value(
                    event,
                    "service",
                ),
                "decision": decision,
                "matching_rules": matching_rules,
                "reason_codes": reason_codes,
                "evidence": {
                    "related_alert_keys": [
                        alert["alert_key"]
                        for alert in related_alerts
                    ],
                    "exception": exception,
                    "default_decision": configuration[
                        "network_policy"
                    ]["default_decision"],
                },
                "response_action": response_action,
                "acl_control_level": acl_control_level,
                "response_status": response_status,
            }
        )

    return decisions


def save_network_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store new Stage 6 alerts and count duplicates."""
    created_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for alert in alerts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO v2_network_alerts (
                    alert_key,
                    created_at,
                    detection_type,
                    severity,
                    confidence,
                    first_event_time,
                    last_event_time,
                    source_event_ids,
                    source_types,
                    device_id,
                    asset_id,
                    username,
                    ip_address,
                    mac_address,
                    hostname,
                    location,
                    connection_type,
                    destination_ip,
                    destination_port,
                    service,
                    reason_codes,
                    evidence
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    alert["alert_key"],
                    created_at,
                    alert["detection_type"],
                    alert["severity"],
                    alert["confidence"],
                    alert["first_event_time"],
                    alert["last_event_time"],
                    json.dumps(alert["source_event_ids"]),
                    json.dumps(alert["source_types"]),
                    alert["device_id"],
                    alert["asset_id"],
                    alert["username"],
                    alert["ip_address"],
                    alert["mac_address"],
                    alert["hostname"],
                    alert["location"],
                    alert["connection_type"],
                    alert["destination_ip"],
                    alert["destination_port"],
                    alert["service"],
                    json.dumps(alert["reason_codes"]),
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


def save_access_decisions(
    database_path: Path,
    decisions: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store new access decisions and count duplicates."""
    evaluated_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for decision in decisions:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO
                v2_network_access_decisions (
                    decision_key,
                    evaluated_at,
                    source_event_id,
                    event_time,
                    source_type,
                    event_type,
                    device_id,
                    asset_id,
                    username,
                    ip_address,
                    mac_address,
                    hostname,
                    location,
                    connection_type,
                    destination_ip,
                    destination_port,
                    service,
                    decision,
                    matching_rules,
                    reason_codes,
                    evidence,
                    response_action,
                    acl_control_level,
                    response_status
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    decision["decision_key"],
                    evaluated_at,
                    decision["source_event_id"],
                    decision["event_time"],
                    decision["source_type"],
                    decision["event_type"],
                    decision["device_id"],
                    decision["asset_id"],
                    decision["username"],
                    decision["ip_address"],
                    decision["mac_address"],
                    decision["hostname"],
                    decision["location"],
                    decision["connection_type"],
                    decision["destination_ip"],
                    decision["destination_port"],
                    decision["service"],
                    decision["decision"],
                    json.dumps(decision["matching_rules"]),
                    json.dumps(decision["reason_codes"]),
                    json.dumps(
                        decision["evidence"],
                        sort_keys=True,
                    ),
                    decision["response_action"],
                    decision["acl_control_level"],
                    decision["response_status"],
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing


def save_connection_timeline(
    database_path: Path,
    events: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store the Stage 6 connection timeline."""
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for event in events:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO
                v2_network_connection_timeline (
                    source_event_id,
                    event_time,
                    source_type,
                    event_type,
                    device_id,
                    asset_id,
                    username,
                    ip_address,
                    mac_address,
                    hostname,
                    location,
                    connection_type,
                    destination_ip,
                    destination_port,
                    service,
                    status,
                    raw_event
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    event["source_event_id"],
                    event["event_time"],
                    event["source_type"],
                    event["event_type"],
                    event.get("device_id"),
                    event.get("asset_id"),
                    event.get("username"),
                    event.get("ip_address"),
                    event.get("mac_address"),
                    event.get("hostname"),
                    event.get("location"),
                    event_value(event, "connection_type"),
                    event_value(event, "destination_ip"),
                    event_value(event, "destination_port"),
                    event_value(event, "service"),
                    event.get("status"),
                    json.dumps(
                        event["raw"],
                        sort_keys=True,
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing
