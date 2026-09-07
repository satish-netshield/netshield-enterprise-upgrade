"""Manage controlled device registration and removal."""

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


INVENTORY_FIELDS = [
    "asset_id",
    "device_id",
    "hostname",
    "assigned_user",
    "ownership",
    "device_type",
    "manufacturer",
    "operating_system",
    "os_version",
    "mac_address",
    "ip_address",
    "location",
    "connection_type",
    "approval_status",
    "registration_status",
    "compliance_status",
    "risk_status",
    "criticality",
    "registered_date",
    "last_seen",
]


def utc_now() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def load_inventory(
    inventory_path: Path,
) -> list[dict[str, str]]:
    """Load the CYOD inventory."""
    with inventory_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames != INVENTORY_FIELDS:
            raise ValueError(
                "CYOD inventory header does not match "
                "the Stage 3 inventory structure"
            )

        return list(reader)


def write_inventory(
    inventory_path: Path,
    rows: list[dict[str, str]],
) -> None:
    """Write the complete CYOD inventory."""
    with inventory_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=INVENTORY_FIELDS,
        )
        writer.writeheader()
        writer.writerows(rows)


def record_registration_history(
    database_path: Path,
    device_id: str,
    asset_id: str | None,
    action: str,
    previous_status: str | None,
    new_status: str,
    actor: str,
    reason: str,
) -> None:
    """Preserve one device registration state change."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO device_registration_history (
                event_time,
                device_id,
                asset_id,
                action,
                previous_status,
                new_status,
                actor,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                device_id,
                asset_id,
                action,
                previous_status,
                new_status,
                actor,
                reason,
            ),
        )


def sync_inventory_record(
    database_path: Path,
    row: dict[str, str],
) -> None:
    """Synchronise one inventory record with SQLite."""
    values: list[Any] = [
        row["asset_id"],
        row["device_id"],
        row["hostname"],
        row["assigned_user"] or None,
        row["ownership"],
        row["device_type"],
        row["manufacturer"],
        row["operating_system"],
        row["os_version"] or None,
        row["mac_address"] or None,
        row["ip_address"] or None,
        row["location"] or None,
        row["connection_type"],
        row["registration_status"],
        row["compliance_status"],
        row["risk_status"],
        row["criticality"],
        row["registered_date"] or None,
        row["last_seen"] or None,
    ]

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO device_inventory (
                asset_id,
                device_id,
                hostname,
                assigned_user,
                ownership,
                device_type,
                manufacturer,
                operating_system,
                os_version,
                mac_address,
                ip_address,
                location,
                connection_type,
                registration_status,
                compliance_status,
                risk_status,
                criticality,
                registered_date,
                last_seen
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(device_id) DO UPDATE SET
                hostname = excluded.hostname,
                assigned_user = excluded.assigned_user,
                ownership = excluded.ownership,
                device_type = excluded.device_type,
                manufacturer = excluded.manufacturer,
                operating_system = excluded.operating_system,
                os_version = excluded.os_version,
                mac_address = excluded.mac_address,
                ip_address = excluded.ip_address,
                location = excluded.location,
                connection_type = excluded.connection_type,
                registration_status = excluded.registration_status,
                compliance_status = excluded.compliance_status,
                risk_status = excluded.risk_status,
                criticality = excluded.criticality,
                registered_date = excluded.registered_date,
                last_seen = excluded.last_seen
            """,
            values,
        )


def register_device(
    database_path: Path,
    inventory_path: Path,
    device: dict[str, str],
    actor: str,
    reason: str,
) -> None:
    """Register a new approved device."""
    rows = load_inventory(inventory_path)

    if any(
        row["device_id"] == device["device_id"]
        for row in rows
    ):
        raise ValueError(
            f"Device {device['device_id']} already exists "
            "in the approved inventory"
        )

    if any(
        row["asset_id"] == device["asset_id"]
        for row in rows
    ):
        raise ValueError(
            f"Asset {device['asset_id']} already exists "
            "in the approved inventory"
        )

    registered_date = datetime.now(
        timezone.utc
    ).date().isoformat()

    device_row = {
        field: device.get(field, "")
        for field in INVENTORY_FIELDS
    }

    device_row["approval_status"] = "approved"
    device_row["registration_status"] = "registered"
    device_row["registered_date"] = registered_date

    rows.append(device_row)

    sync_inventory_record(
        database_path,
        device_row,
    )
    write_inventory(
        inventory_path,
        rows,
    )

    record_registration_history(
        database_path=database_path,
        device_id=device_row["device_id"],
        asset_id=device_row["asset_id"],
        action="register",
        previous_status=None,
        new_status="registered",
        actor=actor,
        reason=reason,
    )


def remove_device(
    database_path: Path,
    inventory_path: Path,
    device_id: str,
    actor: str,
    reason: str,
) -> None:
    """Mark a registered device as removed without deleting history."""
    rows = load_inventory(inventory_path)

    target = None

    for row in rows:
        if row["device_id"] == device_id:
            target = row
            break

    if target is None:
        raise ValueError(
            f"Device {device_id} was not found "
            "in the approved inventory"
        )

    previous_status = target["registration_status"]

    if previous_status == "removed":
        raise ValueError(
            f"Device {device_id} is already removed"
        )

    target["approval_status"] = "removed"
    target["registration_status"] = "removed"

    write_inventory(
        inventory_path,
        rows,
    )
    sync_inventory_record(
        database_path,
        target,
    )

    record_registration_history(
        database_path=database_path,
        device_id=target["device_id"],
        asset_id=target["asset_id"],
        action="remove",
        previous_status=previous_status,
        new_status="removed",
        actor=actor,
        reason=reason,
    )
