"""Evaluate enterprise device identity against approved and known device context."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DETECTION_UNKNOWN = "Unknown Device"
DETECTION_UNREGISTERED = "Unregistered Device"
DETECTION_STALE = "Stale Device"
DETECTION_MISMATCH = "Inventory Mismatch"


def parse_utc_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and return an aware UTC datetime."""
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    return timestamp.astimezone(timezone.utc)


def normalise_context_value(value: str | None) -> str | None:
    """Normalise simple identity context before comparison."""
    if not value:
        return None

    return value.strip().lower().replace("-", "").replace("_", "").replace(" ", "")


def locations_match(
    expected: str | None,
    observed: str | None,
) -> bool:
    """Allow compatible location labels such as Auckland and Auckland-NZ."""
    if not expected or not observed:
        return True

    expected_value = normalise_context_value(expected)
    observed_value = normalise_context_value(observed)

    if expected_value == observed_value:
        return True

    return (
        expected_value.startswith(observed_value)
        or observed_value.startswith(expected_value)
    )


def load_inventory_record(
    database_path: Path,
    device_id: str | None = None,
    asset_id: str | None = None,
) -> dict[str, Any] | None:
    """Return one approved device inventory record using authoritative IDs."""
    if not device_id and not asset_id:
        return None

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        if device_id:
            row = connection.execute(
                """
                SELECT *
                FROM device_inventory
                WHERE device_id = ?
                """,
                (device_id,),
            ).fetchone()

            if row is not None:
                return dict(row)

        if asset_id:
            row = connection.execute(
                """
                SELECT *
                FROM device_inventory
                WHERE asset_id = ?
                """,
                (asset_id,),
            ).fetchone()

            if row is not None:
                return dict(row)

    return None


def load_known_devices(
    enterprise_context: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return simulated enterprise devices keyed by device ID."""
    devices = enterprise_context.get("devices", [])

    return {
        device["device_id"]: device
        for device in devices
        if device.get("device_id")
    }


def determine_identity_status(
    event: dict[str, Any],
    inventory_record: dict[str, Any] | None,
    stale_device_days: int,
    reference_time: datetime,
    known_device: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return Stage 3 device identity findings for one event."""
    findings: list[dict[str, Any]] = []

    if inventory_record is None:
        if known_device is not None:
            if known_device.get("registration_status") != "registered":
                findings.append(
                    {
                        "detection_type": DETECTION_UNREGISTERED,
                        "severity": "High",
                        "reason": (
                            "Device exists in enterprise context but "
                            "is not registered in the approved inventory"
                        ),
                    }
                )
                return findings

        findings.append(
            {
                "detection_type": DETECTION_UNKNOWN,
                "severity": "High",
                "reason": (
                    "No approved inventory or known enterprise "
                    "device matched the observed device identity"
                ),
            }
        )
        return findings

    if inventory_record["registration_status"] != "registered":
        findings.append(
            {
                "detection_type": DETECTION_UNREGISTERED,
                "severity": "High",
                "reason": "Known device is not currently registered",
            }
        )

    last_seen = inventory_record.get("last_seen")

    if last_seen:
        last_seen_time = parse_utc_timestamp(last_seen)
        stale_before = reference_time - timedelta(
            days=stale_device_days
        )

        if last_seen_time < stale_before:
            findings.append(
                {
                    "detection_type": DETECTION_STALE,
                    "severity": "Medium",
                    "reason": (
                        f"Device last seen more than "
                        f"{stale_device_days} days ago"
                    ),
                }
            )

    mismatches: list[str] = []

    comparison_fields = (
        ("hostname", "hostname"),
        ("assigned_user", "username"),
        ("ip_address", "ip_address"),
    )

    for inventory_field, event_field in comparison_fields:
        expected = inventory_record.get(inventory_field)
        observed = event.get(event_field)

        if (
            expected
            and observed
            and normalise_context_value(expected)
            != normalise_context_value(observed)
        ):
            mismatches.append(
                f"{inventory_field}: expected={expected} "
                f"observed={observed}"
            )

    expected_location = inventory_record.get("location")
    observed_location = event.get("location")

    if not locations_match(expected_location, observed_location):
        mismatches.append(
            f"location: expected={expected_location} "
            f"observed={observed_location}"
        )

    expected_mac = inventory_record.get("mac_address")
    observed_mac = event.get("mac_address")

    if (
        expected_mac
        and observed_mac
        and expected_mac.lower() != observed_mac.lower()
    ):
        mismatches.append(
            "mac_address: supporting evidence differs "
            f"expected={expected_mac.lower()} "
            f"observed={observed_mac.lower()}"
        )

    if mismatches:
        findings.append(
            {
                "detection_type": DETECTION_MISMATCH,
                "severity": "Medium",
                "reason": "; ".join(mismatches),
            }
        )

    return findings


def build_alert_key(
    detection_type: str,
    event: dict[str, Any],
) -> str:
    """Build a repeatable alert key for duplicate protection."""
    device_reference = (
        event.get("device_id")
        or event.get("asset_id")
        or "unknown"
    )

    return (
        f"V2-STAGE3|{detection_type}|"
        f"{device_reference}|{event['source_event_id']}"
    )


def save_device_alert(
    database_path: Path,
    event: dict[str, Any],
    finding: dict[str, Any],
    inventory_record: dict[str, Any] | None,
) -> bool:
    """Save one device alert and return False if already present."""
    alert_key = build_alert_key(
        finding["detection_type"],
        event,
    )

    evidence = {
        "reason": finding["reason"],
        "observed": {
            "device_id": event.get("device_id"),
            "asset_id": event.get("asset_id"),
            "hostname": event.get("hostname"),
            "username": event.get("username"),
            "ip_address": event.get("ip_address"),
            "mac_address": event.get("mac_address"),
            "location": event.get("location"),
        },
        "inventory": inventory_record,
    }

    created_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO device_alerts (
                alert_key,
                created_at,
                detection_type,
                severity,
                device_id,
                asset_id,
                hostname,
                username,
                ip_address,
                mac_address,
                location,
                source_event_ids,
                evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_key,
                created_at,
                finding["detection_type"],
                finding["severity"],
                event.get("device_id"),
                event.get("asset_id"),
                event.get("hostname"),
                event.get("username"),
                event.get("ip_address"),
                event.get("mac_address"),
                event.get("location"),
                json.dumps([event["source_event_id"]]),
                json.dumps(
                    evidence,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

        return cursor.rowcount == 1


def evaluate_device_event(
    database_path: Path,
    event: dict[str, Any],
    stale_device_days: int,
    reference_time: datetime | None = None,
    known_devices: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate one normalised event and persist resulting alerts."""
    reference = (
        reference_time.astimezone(timezone.utc)
        if reference_time
        else datetime.now(timezone.utc)
    )

    inventory_record = load_inventory_record(
        database_path=database_path,
        device_id=event.get("device_id"),
        asset_id=event.get("asset_id"),
    )

    known_device = None

    if known_devices and event.get("device_id"):
        known_device = known_devices.get(event["device_id"])

    findings = determine_identity_status(
        event=event,
        inventory_record=inventory_record,
        stale_device_days=stale_device_days,
        reference_time=reference,
        known_device=known_device,
    )

    for finding in findings:
        save_device_alert(
            database_path=database_path,
            event=event,
            finding=finding,
            inventory_record=inventory_record,
        )

    return findings
