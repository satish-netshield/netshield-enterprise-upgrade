"""Validate the Stage 3 identity-detection implementation."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        print(f"PASS: {label}")
        return True

    print(f"FAIL: {label}")
    if detail:
        print(f"      {detail}")
    return False


def main() -> None:
    """Run the Stage 3 validation checks."""
    results = []

    config_path = PROJECT_ROOT / "config/identity_detection.json"
    stage3_events = (
        PROJECT_ROOT
        / "data/raw/stage3/authentication_stage3_events.jsonl"
    )
    database_path = PROJECT_ROOT / "database/netshield.db"

    results.append(
        check(
            "Stage 3 configuration exists",
            config_path.is_file(),
        )
    )

    configuration = json.loads(config_path.read_text(encoding="utf-8"))

    results.append(
        check(
            "Identity thresholds are configured",
            all(
                key in configuration["thresholds"]
                for key in (
                    "repeated_failures",
                    "brute_force_failures",
                    "mfa_failures",
                    "impossible_travel_speed_kmh",
                )
            ),
        )
    )

    results.append(
        check(
            "Stage 3 event file contains 16 records",
            stage3_events.is_file()
            and len(
                stage3_events.read_text(
                    encoding="utf-8"
                ).splitlines()
            )
            == 16,
        )
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        table_exists = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'identity_alerts'
            """
        ).fetchone()

        results.append(
            check(
                "Identity-alert table exists",
                table_exists is not None,
            )
        )

        stage3_import = connection.execute(
            """
            SELECT total_records, accepted_records, rejected_records
            FROM import_batches
            WHERE source_file = 'authentication_stage3_events.jsonl'
            ORDER BY batch_id DESC
            LIMIT 1
            """
        ).fetchone()

        results.append(
            check(
                "Stage 3 import totals are correct",
                stage3_import is not None
                and stage3_import["total_records"] == 16
                and stage3_import["accepted_records"] == 16
                and stage3_import["rejected_records"] == 0,
            )
        )

        alert_count = connection.execute(
            "SELECT COUNT(*) AS count FROM identity_alerts"
        ).fetchone()["count"]

        results.append(
            check(
                "Duplicate protection keeps 11 alerts",
                alert_count == 11,
                f"Observed alert count: {alert_count}",
            )
        )

        detection_types = {
            row["detection_type"]
            for row in connection.execute(
                """
                SELECT DISTINCT detection_type
                FROM identity_alerts
                """
            )
        }

        expected_types = {
            "Repeated Failed Logins",
            "Possible Brute Force",
            "Successful Login After Failures",
            "MFA Failure Anomaly",
            "Login From New Device",
            "Login From Unusual Location",
            "Impossible Travel",
            "Suspicious Role Change",
        }

        results.append(
            check(
                "All identity detection types are present",
                expected_types.issubset(detection_types),
            )
        )

        vpn_alerts = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM identity_alerts
            WHERE username = 'vpnuser01'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Known VPN activity has no identity alert",
                vpn_alerts == 0,
                f"Observed VPN alerts: {vpn_alerts}",
            )
        )

        false_positive = connection.execute(
            """
            SELECT status, classification, investigation_notes
            FROM identity_alerts
            WHERE alert_id = 10
            """
        ).fetchone()

        results.append(
            check(
                "Approved replacement device is classified as false positive",
                false_positive is not None
                and false_positive["status"] == "False Positive"
                and false_positive["classification"] == "False Positive"
                and "approved replacement device"
                in false_positive["investigation_notes"],
            )
        )

        detection_audit = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_events
            WHERE action = 'run_stage3_detection'
              AND result = 'success'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Stage 3 detection audit records exist",
                detection_audit >= 2,
            )
        )

        false_positive_audit = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_events
            WHERE action = 'classify_stage3_false_positive'
              AND result = 'success'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "False-positive audit record exists",
                false_positive_audit >= 1,
            )
        )

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'stage_3_status'
            """
        ).fetchone()

        results.append(
            check(
                "Stage 3 metadata shows detections complete",
                metadata is not None
                and metadata["value"] == "detections_complete",
            )
        )

    passed = sum(results)
    total = len(results)

    print()
    if passed == total:
        print(f"STAGE 3 VALIDATION: PASS ({passed}/{total})")
        return

    print(f"STAGE 3 VALIDATION: FAIL ({passed}/{total})")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
