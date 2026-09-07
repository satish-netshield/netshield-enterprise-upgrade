"""Validate Phase 3A V2 Stage 3 enterprise asset and device identity."""

import csv
import sqlite3
import sys
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_INDEXES = {
    "idx_device_inventory_device",
    "idx_device_inventory_asset",
    "idx_device_inventory_hostname",
    "idx_device_inventory_user",
    "idx_device_inventory_registration",
    "idx_device_inventory_compliance",
    "idx_device_inventory_risk",
    "idx_device_inventory_last_seen",
    "idx_device_alerts_type",
    "idx_device_alerts_device",
    "idx_device_alerts_status",
    "idx_device_registration_device",
}


def pass_check(message: str) -> None:
    """Print one successful validation check."""
    print(f"PASS: {message}")


def fail_check(message: str) -> None:
    """Print one failed validation check."""
    print(f"FAIL: {message}")


def load_csv_rows(
    inventory_path: Path,
) -> list[dict[str, str]]:
    """Load the approved CYOD inventory."""
    with inventory_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        return list(csv.DictReader(handle))


def validate() -> int:
    """Run the complete Stage 3 validation gate."""

    checks = 0
    passed = 0

    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    device_config = load_json(
        PROJECT_ROOT / "config/device_identity.json"
    )

    database_path = (
        PROJECT_ROOT
        / settings["database"]["path"]
    )
    inventory_path = (
        PROJECT_ROOT
        / device_config["inventory_path"]
    )

    def check(
        condition: bool,
        success_message: str,
        failure_message: str,
    ) -> None:
        nonlocal checks, passed

        checks += 1

        if condition:
            passed += 1
            pass_check(success_message)
        else:
            fail_check(failure_message)

    # 1. Stage 3 configuration.
    check(
        device_config.get("stale_device_days") == 30,
        "Stale-device threshold is 30 days",
        "Unexpected stale-device threshold",
    )

    # 2. MAC identity handling.
    check(
        device_config.get("mac_address_identity")
        == "supporting_evidence_only",
        "MAC addresses are supporting evidence only",
        "MAC address identity rule is incorrect",
    )

    inventory_rows = load_csv_rows(inventory_path)

    # 3. Approved inventory size.
    check(
        len(inventory_rows) == 2,
        "Approved CYOD inventory contains 2 devices",
        (
            "Approved CYOD inventory does not contain "
            "the expected 2 devices"
        ),
    )

    device_ids = [
        row["device_id"]
        for row in inventory_rows
    ]
    asset_ids = [
        row["asset_id"]
        for row in inventory_rows
    ]

    # 4. Device IDs unique.
    check(
        len(device_ids) == len(set(device_ids)),
        "Device IDs are unique",
        "Duplicate device IDs found",
    )

    # 5. Asset IDs unique.
    check(
        len(asset_ids) == len(set(asset_ids)),
        "Asset IDs are unique",
        "Duplicate asset IDs found",
    )

    # 6. Expected approved devices.
    check(
        set(device_ids) == {"CYOD-001", "CYOD-002"},
        "Expected approved devices are present",
        "Approved device identities are unexpected",
    )

    # 7. Inventory registration state.
    check(
        all(
            row["approval_status"] == "approved"
            and row["registration_status"] == "registered"
            for row in inventory_rows
        ),
        "Approved inventory devices are registered",
        "Approved inventory contains an invalid registration state",
    )

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }

        # 8. Stage 3 tables.
        expected_tables = {
            "device_inventory",
            "device_alerts",
            "device_registration_history",
        }

        check(
            expected_tables.issubset(tables),
            "Stage 3 database tables exist",
            "One or more Stage 3 database tables are missing",
        )

        indexes = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'index'
                """
            )
        }

        # 9. Stage 3 indexes.
        check(
            EXPECTED_INDEXES.issubset(indexes),
            "Stage 3 database indexes exist",
            "One or more Stage 3 database indexes are missing",
        )

        database_inventory = connection.execute(
            """
            SELECT
                asset_id,
                device_id,
                hostname,
                assigned_user,
                registration_status,
                compliance_status,
                risk_status,
                criticality
            FROM device_inventory
            ORDER BY device_id
            """
        ).fetchall()

        # 10. Database inventory count.
        check(
            len(database_inventory) == 2,
            "SQLite device inventory contains 2 devices",
            "SQLite device inventory count is unexpected",
        )

        csv_by_device = {
            row["device_id"]: row
            for row in inventory_rows
        }

        inventory_matches = True

        for row in database_inventory:
            csv_row = csv_by_device.get(
                row["device_id"]
            )

            if csv_row is None:
                inventory_matches = False
                break

            comparable_fields = (
                "asset_id",
                "hostname",
                "assigned_user",
                "registration_status",
                "compliance_status",
                "risk_status",
                "criticality",
            )

            for field in comparable_fields:
                database_value = (
                    row[field]
                    if row[field] is not None
                    else ""
                )

                if database_value != csv_row[field]:
                    inventory_matches = False
                    break

        # 11. CSV and database consistency.
        check(
            inventory_matches,
            "CSV and SQLite inventory context match",
            "CSV and SQLite inventory context differ",
        )

        device_event_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE schema_version = '2.0'
              AND (
                    device_id IS NOT NULL
                    OR asset_id IN (
                        SELECT asset_id
                        FROM device_inventory
                    )
                  )
            """
        ).fetchone()[0]

        # 12. Relevant stored Stage 2 device events.
        check(
            device_event_count == 3,
            "3 relevant V2 device events are available",
            (
                "Relevant V2 device-event count "
                f"is unexpected: {device_event_count}"
            ),
        )

        alerts = connection.execute(
            """
            SELECT
                detection_type,
                severity,
                device_id,
                asset_id,
                status
            FROM device_alerts
            ORDER BY alert_id
            """
        ).fetchall()

        # 13. Real device alert count.
        check(
            len(alerts) == 1,
            "One meaningful Stage 3 device alert is stored",
            (
                "Unexpected number of Stage 3 device alerts: "
                f"{len(alerts)}"
            ),
        )

        expected_real_alert = (
            len(alerts) == 1
            and alerts[0]["detection_type"]
            == "Unregistered Device"
            and alerts[0]["severity"] == "High"
            and alerts[0]["device_id"] == "CYOD-003"
            and alerts[0]["status"] == "New"
        )

        # 14. CYOD-003 classification.
        check(
            expected_real_alert,
            (
                "CYOD-003 is correctly classified "
                "as an unregistered device"
            ),
            "CYOD-003 alert classification is incorrect",
        )

        false_cyod002_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM device_alerts
            WHERE device_id = 'CYOD-002'
            """
        ).fetchone()[0]

        # 15. No false alert for normal approved device.
        check(
            false_cyod002_alerts == 0,
            "Approved CYOD-002 activity creates no false alert",
            "Unexpected alert exists for approved CYOD-002",
        )

        non_device_asset_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM device_alerts
            WHERE asset_id IN (
                'AST-DB-001',
                'AST-WEB-001'
            )
            """
        ).fetchone()[0]

        # 16. Non-device assets excluded.
        check(
            non_device_asset_alerts == 0,
            "Database and web assets are not treated as devices",
            "Non-device assets created device identity alerts",
        )

        duplicate_alert_keys = connection.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT alert_key
                FROM device_alerts
                GROUP BY alert_key
                HAVING COUNT(*) > 1
            )
            """
        ).fetchone()[0]

        # 17. Duplicate protection.
        check(
            duplicate_alert_keys == 0,
            "Device alert keys are duplicate-safe",
            "Duplicate device alert keys were found",
        )

        initialisation_audit = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'initialize_v2_stage3'
              AND result = 'success'
            """
        ).fetchone()[0]

        # 18. Initialisation audit.
        check(
            initialisation_audit >= 1,
            "Stage 3 initialisation is recorded in the audit trail",
            "Stage 3 initialisation audit record is missing",
        )

        detection_audit = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'run_v2_stage3_device_identity'
              AND result = 'success'
            """
        ).fetchone()[0]

        # 19. Detection audit.
        check(
            detection_audit >= 1,
            "Stage 3 detection runs are recorded in the audit trail",
            "Stage 3 detection audit record is missing",
        )

    print()
    print(
        f"Stage 3 validation: {passed}/{checks} checks passed"
    )

    if passed == checks:
        print(
            "PASS: V2 Stage 3 enterprise asset "
            "and device identity validated"
        )
        return 0

    print(
        "FAIL: V2 Stage 3 validation did not pass completely"
    )
    return 1


if __name__ == "__main__":
    sys.exit(validate())
