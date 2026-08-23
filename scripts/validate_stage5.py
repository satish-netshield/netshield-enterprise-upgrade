"""Validate the NetShield Stage 5 endpoint-detection foundation."""

import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = PROJECT_ROOT / "database/netshield.db"
CONFIG_PATH = PROJECT_ROOT / "config/endpoint_detection.json"

SOURCE_FILES = [
    PROJECT_ROOT / "data/raw/stage5/endpoint_stage5_events.jsonl",
    PROJECT_ROOT / "data/raw/stage5/network_stage5_events.jsonl",
]


def check(condition: bool, passed: str, failed: str) -> bool:
    """Print a validation result."""
    if condition:
        print(f"PASS: {passed}")
        return True

    print(f"FAIL: {failed}")
    return False


def main() -> None:
    """Run Stage 5 validation checks."""
    results = []

    results.append(
        check(
            CONFIG_PATH.exists()
            and all(path.exists() for path in SOURCE_FILES),
            "Required Stage 5 files exist",
            "Required Stage 5 files are missing",
        )
    )

    try:
        configuration = json.loads(
            CONFIG_PATH.read_text(encoding="utf-8")
        )
        config_valid = (
            configuration["stage"] == 5
            and configuration["environment"] == "sandbox"
            and configuration["endpoint_policy"][
                "approved_stress_test_ids"
            ]
            and configuration["wired_access_policy"][
                "restricted_zones"
            ]
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        config_valid = False

    results.append(
        check(
            config_valid,
            "Stage 5 configuration is valid and safe",
            "Stage 5 configuration is invalid",
        )
    )

    with sqlite3.connect(DATABASE_PATH) as connection:
        table_exists = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'endpoint_alerts'
            """
        ).fetchone()

        results.append(
            check(
                table_exists is not None,
                "Endpoint-alert table exists",
                "Endpoint-alert table is missing",
            )
        )

        accepted_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_file IN (
                'endpoint_stage5_events.jsonl',
                'network_stage5_events.jsonl'
            )
            """
        ).fetchone()[0]

        results.append(
            check(
                accepted_count == 14,
                "Stage 5 accepted-event count is 14",
                f"Unexpected Stage 5 accepted-event count: "
                f"{accepted_count}",
            )
        )

        source_counts = dict(
            connection.execute(
                """
                SELECT source_type, COUNT(*)
                FROM security_events
                WHERE source_file IN (
                    'endpoint_stage5_events.jsonl',
                    'network_stage5_events.jsonl'
                )
                GROUP BY source_type
                """
            ).fetchall()
        )

        results.append(
            check(
                source_counts == {
                    "endpoint": 10,
                    "network": 4,
                },
                "Stage 5 source counts reconcile",
                f"Unexpected Stage 5 source counts: {source_counts}",
            )
        )

        alert_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM endpoint_alerts
            """
        ).fetchone()[0]

        results.append(
            check(
                alert_count == 10,
                "Stage 5 endpoint-alert count is 10",
                f"Unexpected endpoint-alert count: {alert_count}",
            )
        )

        detection_types = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT detection_type
                FROM endpoint_alerts
                """
            ).fetchall()
        }

        expected_types = {
            "Repeated High CPU Activity",
            "Unexpected CPU Activity",
            "Unauthorised CPU Stress Test",
            "Unknown Endpoint Process",
            "Restricted Wired Access",
        }

        results.append(
            check(
                expected_types.issubset(detection_types),
                "Expected Stage 5 detection types exist",
                f"Missing Stage 5 detection types: "
                f"{sorted(expected_types - detection_types)}",
            )
        )

        mac_reuse_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM endpoint_alerts
            WHERE detection_type =
                'MAC Reuse or Possible Spoofing'
            """
        ).fetchone()[0]

        results.append(
            check(
                mac_reuse_count == 0,
                "Location change alone did not create MAC reuse",
                "Unexpected MAC-reuse alert is present",
            )
        )

        restricted_wired_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM endpoint_alerts
            WHERE detection_type =
                'Restricted Wired Access'
            """
        ).fetchone()[0]

        results.append(
            check(
                restricted_wired_count == 1,
                "Repeated restricted wired access was grouped",
                f"Unexpected restricted wired-alert count: "
                f"{restricted_wired_count}",
            )
        )

        approved_stress_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM endpoint_alerts
            WHERE detection_type =
                'Unauthorised CPU Stress Test'
              AND source_event_ids LIKE '%END5-002%'
            """
        ).fetchone()[0]

        results.append(
            check(
                approved_stress_alerts == 0,
                "Approved CPU stress testing created no alert",
                "Approved CPU stress testing created an alert",
            )
        )

        audit_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'run_stage5_detection'
              AND result = 'success'
            """
        ).fetchone()[0]

        results.append(
            check(
                audit_count >= 2,
                "Stage 5 detection audit records exist",
                "Stage 5 detection audit records are missing",
            )
        )

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'stage_5_status'
            """
        ).fetchone()

        results.append(
            check(
                metadata is not None
                and metadata[0] == "detections_complete",
                "Stage 5 metadata shows detections complete",
                "Stage 5 metadata is not complete",
            )
        )

    passed = sum(results)
    total = len(results)

    print()
    print(
        f"STAGE 5 VALIDATION: "
        f"{'PASS' if passed == total else 'FAIL'} "
        f"({passed}/{total})"
    )

    raise SystemExit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
