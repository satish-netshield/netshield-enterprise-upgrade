"""Validate the Stage 4 network, CYOD and Wi-Fi implementation."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def check(label: str, condition: bool, detail: str = "") -> bool:
    """Print and return one validation result."""
    if condition:
        print(f"PASS: {label}")
        return True

    print(f"FAIL: {label}")
    if detail:
        print(f"      {detail}")
    return False


def main() -> None:
    """Run Stage 4 validation checks."""
    results = []

    database_path = PROJECT_ROOT / "database/netshield.db"
    configuration_path = PROJECT_ROOT / "config/network_detection.json"

    required_files = [
        configuration_path,
        PROJECT_ROOT / "scripts/generate_stage4_events.py",
        PROJECT_ROOT / "scripts/generate_stage4_correlation_events.py",
        PROJECT_ROOT / "scripts/import_stage4_events.py",
        PROJECT_ROOT / "scripts/run_stage4_detection.py",
        PROJECT_ROOT / "src/detectors/network_detector.py",
        PROJECT_ROOT / "src/detectors/network_correlation.py",
        PROJECT_ROOT / "tests/test_stage4_network_correlation.py",
    ]

    results.append(
        check(
            "Required Stage 4 files exist",
            all(path.is_file() for path in required_files),
        )
    )

    configuration = json.loads(
        configuration_path.read_text(encoding="utf-8")
    )

    results.append(
        check(
            "Stage 4 configuration is valid and safe",
            configuration["environment"] == "sandbox"
            and configuration["network_policy"][
                "real_external_targets_allowed"
            ] is False
            and configuration["correlation"][
                "primary_device_identity"
            ] == "mac_address",
        )
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        table = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'network_alerts'
            """
        ).fetchone()

        results.append(
            check(
                "Network-alert table exists",
                table is not None,
            )
        )

        event_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE source_file IN (
                'network_stage4_events.jsonl',
                'wifi_stage4_events.jsonl',
                'network_correlation_stage4_events.jsonl',
                'wifi_correlation_stage4_events.jsonl'
            )
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Stage 4 accepted-event count is 23",
                event_count == 23,
                f"Observed accepted events: {event_count}",
            )
        )

        network_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE source_file = 'network_stage4_events.jsonl'
            """
        ).fetchone()["count"]

        wifi_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE source_file = 'wifi_stage4_events.jsonl'
            """
        ).fetchone()["count"]

        correlation_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE source_file IN (
                'network_correlation_stage4_events.jsonl',
                'wifi_correlation_stage4_events.jsonl'
            )
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Stage 4 source counts reconcile",
                network_count == 11
                and wifi_count == 6
                and correlation_count == 6,
            )
        )

        alert_count = connection.execute(
            "SELECT COUNT(*) AS count FROM network_alerts"
        ).fetchone()["count"]

        results.append(
            check(
                "Correlated alert count is 12",
                alert_count == 12,
                f"Observed alerts: {alert_count}",
            )
        )

        detection_types = {
            row["detection_type"]
            for row in connection.execute(
                """
                SELECT DISTINCT detection_type
                FROM network_alerts
                """
            )
        }

        expected_types = {
            "MAC Address Reuse or Possible Spoofing",
            "MAC Device Investigation",
            "Port Scanning",
            "Repeated Connection Attempts",
            "Rogue Access Point",
            "WPA3 Policy Violation",
            "WPA2 Downgrade Attempt",
        }

        results.append(
            check(
                "Expected correlated detection types exist",
                expected_types.issubset(detection_types),
            )
        )

        mac_reuse_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM network_alerts
            WHERE detection_type =
                'MAC Address Reuse or Possible Spoofing'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "MAC reuse detection is present",
                mac_reuse_count == 1,
            )
        )

        repeated_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM network_alerts
            WHERE detection_type =
                'Repeated Connection Attempts'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Rapid repeated connections are grouped",
                repeated_count == 1,
            )
        )

        rogue_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM network_alerts
            WHERE detection_type = 'Rogue Access Point'
              AND severity = 'Critical'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Rogue access point is Critical",
                rogue_count == 1,
            )
        )

        audit_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_events
            WHERE action = 'run_stage4_detection'
              AND result = 'success'
            """
        ).fetchone()["count"]

        results.append(
            check(
                "Stage 4 detection audit records exist",
                audit_count >= 2,
            )
        )

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'stage_4_status'
            """
        ).fetchone()

        results.append(
            check(
                "Stage 4 metadata shows detections complete",
                metadata is not None
                and metadata["value"] == "detections_complete",
            )
        )

    passed = sum(results)
    total = len(results)

    print()
    if passed == total:
        print(f"STAGE 4 VALIDATION: PASS ({passed}/{total})")
        return

    print(f"STAGE 4 VALIDATION: FAIL ({passed}/{total})")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
