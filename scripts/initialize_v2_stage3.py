"""Initialise Phase 3A V2 Stage 3 enterprise device identity."""
from src.utils.sqlite_connection import managed_connection

import csv
import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import (
    initialise_database,
    record_audit_event,
    save_metadata,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


REQUIRED_INVENTORY_FIELDS = {
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
    "registration_status",
    "compliance_status",
    "risk_status",
    "criticality",
    "registered_date",
    "last_seen",
}


def load_inventory_rows(inventory_path: Path) -> list[dict[str, str]]:
    """Load and validate the tracked CYOD inventory."""

    with inventory_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as inventory_file:
        reader = csv.DictReader(inventory_file)

        if reader.fieldnames is None:
            raise ValueError("CYOD inventory has no header")

        missing_fields = REQUIRED_INVENTORY_FIELDS - set(reader.fieldnames)
        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(
                f"CYOD inventory is missing required fields: {missing}"
            )

        rows = [
            {
                key: (value or "").strip()
                for key, value in row.items()
            }
            for row in reader
        ]

    if not rows:
        raise ValueError("CYOD inventory contains no devices")

    device_ids = [row["device_id"] for row in rows]
    asset_ids = [row["asset_id"] for row in rows]

    if any(not device_id for device_id in device_ids):
        raise ValueError("Every inventory device requires a device_id")

    if any(not asset_id for asset_id in asset_ids):
        raise ValueError("Every inventory device requires an asset_id")

    if len(device_ids) != len(set(device_ids)):
        raise ValueError("CYOD inventory contains duplicate device_id values")

    if len(asset_ids) != len(set(asset_ids)):
        raise ValueError("CYOD inventory contains duplicate asset_id values")

    return rows


def validate_inventory_values(
    rows: list[dict[str, str]],
    config: dict[str, Any],
) -> None:
    """Validate controlled Stage 3 inventory values."""

    allowed_registration = set(config["registration_statuses"])
    allowed_compliance = set(config["compliance_statuses"])
    allowed_risk = set(config["risk_statuses"])
    allowed_criticality = set(config["criticality_levels"])

    for row in rows:
        if row["registration_status"] not in allowed_registration:
            raise ValueError(
                "Unsupported registration_status for "
                f"{row['device_id']}: {row['registration_status']}"
            )

        if row["compliance_status"] not in allowed_compliance:
            raise ValueError(
                "Unsupported compliance_status for "
                f"{row['device_id']}: {row['compliance_status']}"
            )

        if row["risk_status"] not in allowed_risk:
            raise ValueError(
                "Unsupported risk_status for "
                f"{row['device_id']}: {row['risk_status']}"
            )

        if row["criticality"] not in allowed_criticality:
            raise ValueError(
                "Unsupported criticality for "
                f"{row['device_id']}: {row['criticality']}"
            )


def sync_inventory(
    database_path: Path,
    rows: list[dict[str, str]],
) -> None:
    """Create or update operational device inventory records."""

    columns = (
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
        "registration_status",
        "compliance_status",
        "risk_status",
        "criticality",
        "registered_date",
        "last_seen",
    )

    placeholders = ", ".join("?" for _ in columns)
    column_names = ", ".join(columns)

    update_columns = (
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
        "registration_status",
        "compliance_status",
        "risk_status",
        "criticality",
        "registered_date",
        "last_seen",
    )

    update_clause = ", ".join(
        f"{column} = excluded.{column}"
        for column in update_columns
    )

    with managed_connection(database_path) as connection:
        for row in rows:
            values = tuple(
                row[column] or None
                for column in columns
            )

            connection.execute(
                f"""
                INSERT INTO device_inventory ({column_names})
                VALUES ({placeholders})
                ON CONFLICT(device_id)
                DO UPDATE SET
                    {update_clause}
                """,
                values,
            )


def main() -> None:
    """Initialise the Stage 3 device inventory foundation."""

    settings = load_json(PROJECT_ROOT / "config/settings.json")
    device_config = load_json(
        PROJECT_ROOT / "config/device_identity.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    schema_path = PROJECT_ROOT / "database/schema.sql"
    inventory_path = PROJECT_ROOT / device_config["inventory_path"]

    initialise_database(database_path, schema_path)

    inventory_rows = load_inventory_rows(inventory_path)
    validate_inventory_values(inventory_rows, device_config)

    sync_inventory(
        database_path=database_path,
        rows=inventory_rows,
    )

    save_metadata(
        database_path,
        "v2_stage3_device_identity",
        "initialised",
    )
    save_metadata(
        database_path,
        "v2_stage3_stale_device_days",
        str(device_config["stale_device_days"]),
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialize_v2_stage3",
        target="device_inventory",
        result="success",
        details=(
            f"approved_devices={len(inventory_rows)} "
            f"stale_threshold_days="
            f"{device_config['stale_device_days']}"
        ),
    )

    print("PASS: V2 Stage 3 device identity foundation initialised")
    print(f"Approved devices loaded: {len(inventory_rows)}")
    print(
        "Stale-device threshold: "
        f"{device_config['stale_device_days']} days"
    )
    print(
        "MAC identity handling: "
        f"{device_config['mac_address_identity']}"
    )


if __name__ == "__main__":
    main()
