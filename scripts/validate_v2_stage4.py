"""Validate V2 Stage 4 enterprise identity monitoring."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
from pathlib import Path
from typing import Callable

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DETECTIONS = {
    "Repeated Failed Logins",
    "Possible Brute Force",
    "Password Spraying Pattern",
    "Successful Login After Failures",
    "Impossible Travel",
    "New-Device Sign-In",
    "Unusual Sign-In Location",
    "Abnormal Access Time",
    "MFA Failure or Fatigue Pattern",
    "Suspicious Privilege Change",
    "Dormant-Account Activity",
    "Service-Account Interactive Login",
    "Multiple Accounts From One Source",
    "Risky Sign-In Behaviour",
}
EXPECTED_INDEXES = {
    "idx_v2_identity_alerts_type",
    "idx_v2_identity_alerts_username",
    "idx_v2_identity_alerts_device",
    "idx_v2_identity_alerts_severity",
    "idx_v2_identity_alerts_status",
    "idx_v2_identity_alerts_time",
}


def print_result(passed: bool, description: str) -> bool:
    """Print one validation result."""
    prefix = "PASS" if passed else "FAIL"
    print(f"{prefix}: {description}")
    return passed


def run_check(
    description: str,
    check: Callable[[], None],
) -> bool:
    """Run one validation check without stopping later checks."""
    try:
        check()
    except (
        AssertionError,
        KeyError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        print_result(False, description)
        print(f"      {error}")
        return False

    return print_result(True, description)


def database_path() -> Path:
    """Return the configured database path."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    return PROJECT_ROOT / settings["database"]["path"]


def check_required_files() -> None:
    """Confirm Stage 4 source and configuration files exist."""
    required_files = [
        PROJECT_ROOT / "config/v2_identity_monitoring.json",
        PROJECT_ROOT / "src/detectors/v2_identity_monitor.py",
        PROJECT_ROOT
        / "scripts/run_v2_stage4_identity_monitoring.py",
        PROJECT_ROOT
        / "scripts/review_v2_stage4_identity_alert.py",
        PROJECT_ROOT
        / "tests/test_v2_stage4_identity_monitoring.py",
        PROJECT_ROOT
        / "tests/test_v2_stage4_identity_review.py",
    ]

    missing = [
        str(path.relative_to(PROJECT_ROOT))
        for path in required_files
        if not path.is_file()
    ]
    if missing:
        raise AssertionError(
            "Missing files: " + ", ".join(missing)
        )


def check_configuration() -> None:
    """Validate Stage 4 thresholds, profiles and rules."""
    configuration = load_json(
        PROJECT_ROOT / "config/v2_identity_monitoring.json"
    )

    if not configuration["simulation_only"]:
        raise AssertionError(
            "Stage 4 must remain simulation-only"
        )

    if set(configuration["event_sources"]) != {
        "authentication",
        "identity_risk",
    }:
        raise AssertionError(
            "Unexpected Stage 4 event sources"
        )

    thresholds = configuration["thresholds"]
    positive_thresholds = {
        key: value
        for key, value in thresholds.items()
        if key
        not in {
            "normal_access_start_hour_utc",
            "normal_access_end_hour_utc",
        }
    }
    if not all(
        isinstance(value, int) and value > 0
        for value in positive_thresholds.values()
    ):
        raise AssertionError(
            "Detection thresholds must be positive integers"
        )

    if not (
        0
        <= thresholds["normal_access_start_hour_utc"]
        < thresholds["normal_access_end_hour_utc"]
        <= 24
    ):
        raise AssertionError(
            "Normal access hours are invalid"
        )

    configured_rules = configuration["detections"]
    if len(configured_rules) != 14:
        raise AssertionError(
            "Expected 14 Stage 4 detection rules"
        )

    for rule_name, rule in configured_rules.items():
        if not rule["enabled"]:
            raise AssertionError(
                f"Detection is disabled: {rule_name}"
            )
        if not 0 <= rule["confidence"] <= 100:
            raise AssertionError(
                f"Invalid confidence: {rule_name}"
            )
        if not rule["mitre_techniques"]:
            raise AssertionError(
                f"Missing MITRE mapping: {rule_name}"
            )


def check_source_events() -> None:
    """Confirm the controlled Stage 4 event totals."""
    raw_directory = PROJECT_ROOT / "data/raw/v2/stage4_5"
    expected_files = {
        "authentication_v2_stage4_5_events.jsonl": 21,
        "identity_risk_v2_stage4_5_events.jsonl": 3,
    }

    for filename, expected_count in expected_files.items():
        path = raw_directory / filename
        if not path.is_file():
            raise AssertionError(
                f"Missing source file: {filename}"
            )

        records = [
            json.loads(line)
            for line in path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
        if len(records) != expected_count:
            raise AssertionError(
                f"{filename} contains {len(records)} records"
            )

        for record in records:
            if record["schema_version"] != "2.0":
                raise AssertionError(
                    f"Unexpected schema in {filename}"
                )


def check_database_objects() -> None:
    """Confirm the Stage 4 table and indexes exist."""
    with managed_connection(database_path()) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'v2_identity_alerts'
            """
        ).fetchone()
        indexes = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'index'
                """
            )
        }

    if table is None:
        raise AssertionError(
            "v2_identity_alerts table is missing"
        )

    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        raise AssertionError(
            "Missing indexes: "
            + ", ".join(sorted(missing_indexes))
        )


def check_accepted_events() -> None:
    """Confirm 24 Stage 4 source events were accepted."""
    with managed_connection(database_path()) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_file IN (
                'authentication_v2_stage4_5_events.jsonl',
                'identity_risk_v2_stage4_5_events.jsonl'
            )
            """
        ).fetchone()[0]

        utc_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_file IN (
                'authentication_v2_stage4_5_events.jsonl',
                'identity_risk_v2_stage4_5_events.jsonl'
            )
              AND event_time LIKE '%+00:00'
            """
        ).fetchone()[0]

    if count != 24:
        raise AssertionError(
            f"Expected 24 accepted events, found {count}"
        )

    if utc_count != 24:
        raise AssertionError(
            "Not all Stage 4 events are stored in UTC"
        )


def check_alert_results() -> None:
    """Confirm the expected Stage 4 alerts and context."""
    with managed_connection(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                alert_key,
                detection_type,
                severity,
                confidence,
                username,
                device_id,
                source_event_ids,
                reason_codes,
                mitre_techniques,
                evidence
            FROM v2_identity_alerts
            ORDER BY alert_id
            """
        ).fetchall()

    if len(rows) != 16:
        raise AssertionError(
            f"Expected 16 identity alerts, found {len(rows)}"
        )

    detection_types = {
        row["detection_type"]
        for row in rows
    }
    if detection_types != EXPECTED_DETECTIONS:
        missing = EXPECTED_DETECTIONS - detection_types
        unexpected = detection_types - EXPECTED_DETECTIONS
        raise AssertionError(
            f"Missing={sorted(missing)} "
            f"unexpected={sorted(unexpected)}"
        )

    if len({row["alert_key"] for row in rows}) != 16:
        raise AssertionError(
            "Identity alert keys are not unique"
        )

    for row in rows:
        if not 0 <= row["confidence"] <= 100:
            raise AssertionError(
                "Stored confidence is outside 0–100"
            )
        if not json.loads(row["source_event_ids"]):
            raise AssertionError(
                "Alert has no source-event evidence"
            )
        if not json.loads(row["reason_codes"]):
            raise AssertionError(
                "Alert has no reason code"
            )
        if not json.loads(row["mitre_techniques"]):
            raise AssertionError(
                "Alert has no MITRE mapping"
            )
        json.loads(row["evidence"])


def check_specific_detections() -> None:
    """Confirm important identity scenarios were classified."""
    with managed_connection(database_path()) as connection:
        rows = connection.execute(
            """
            SELECT detection_type, username, severity
            FROM v2_identity_alerts
            WHERE detection_type IN (
                'Possible Brute Force',
                'Password Spraying Pattern',
                'Suspicious Privilege Change',
                'Dormant-Account Activity',
                'Service-Account Interactive Login'
            )
            """
        ).fetchall()

    results = {
        (detection_type, username, severity)
        for detection_type, username, severity in rows
    }
    expected = {
        (
            "Possible Brute Force",
            "analyst01",
            "High",
        ),
        (
            "Password Spraying Pattern",
            "multiple_accounts",
            "High",
        ),
        (
            "Suspicious Privilege Change",
            "viewer01",
            "Critical",
        ),
        (
            "Dormant-Account Activity",
            "dormant01",
            "High",
        ),
        (
            "Service-Account Interactive Login",
            "svc_ingestion01",
            "High",
        ),
    }

    if results != expected:
        raise AssertionError(
            "Important detection results do not match"
        )


def check_exceptions() -> None:
    """Confirm VPN and approved-testing exceptions were recorded."""
    with managed_connection(database_path()) as connection:
        row = connection.execute(
            """
            SELECT details
            FROM audit_events
            WHERE action = 'run_v2_stage4_identity_monitoring'
            ORDER BY event_id DESC
            LIMIT 1
            """
        ).fetchone()

    if row is None:
        raise AssertionError(
            "Stage 4 detection audit record is missing"
        )

    details = row[0]
    if "vpn_exceptions=2" not in details:
        raise AssertionError(
            "VPN exception total is not recorded"
        )
    if "testing_exceptions=1" not in details:
        raise AssertionError(
            "Testing exception total is not recorded"
        )


def check_false_positive_review() -> None:
    """Confirm a controlled false positive was investigated."""
    with managed_connection(database_path()) as connection:
        alert = connection.execute(
            """
            SELECT
                status,
                classification,
                investigation_notes
            FROM v2_identity_alerts
            WHERE detection_type = 'Abnormal Access Time'
              AND username = 'viewer01'
            """
        ).fetchone()

        audit = connection.execute(
            """
            SELECT actor, result
            FROM audit_events
            WHERE action = 'review_v2_stage4_identity_alert'
            ORDER BY event_id DESC
            LIMIT 1
            """
        ).fetchone()

    if alert is None:
        raise AssertionError(
            "Reviewed abnormal-time alert is missing"
        )

    if alert[0] != "Closed":
        raise AssertionError(
            "False-positive alert is not closed"
        )
    if alert[1] != "False Positive":
        raise AssertionError(
            "Expected False Positive classification"
        )
    if not alert[2]:
        raise AssertionError(
            "Investigation notes are missing"
        )

    if audit != ("analyst01", "success"):
        raise AssertionError(
            "False-positive review audit is invalid"
        )


def check_duplicate_protection() -> None:
    """Confirm alert keys prevent duplicate storage."""
    with managed_connection(database_path()) as connection:
        total, unique_total = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT alert_key)
            FROM v2_identity_alerts
            """
        ).fetchone()

    if total != unique_total:
        raise AssertionError(
            "Duplicate identity alerts are stored"
        )


def check_initialisation_and_detection_audit() -> None:
    """Confirm Stage 4 initialisation and runs are audited."""
    with managed_connection(database_path()) as connection:
        actions = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT action
                FROM audit_events
                WHERE action IN (
                    'initialize_v2_stage4_5',
                    'run_v2_stage4_identity_monitoring'
                )
                """
            )
        }

    expected = {
        "initialize_v2_stage4_5",
        "run_v2_stage4_identity_monitoring",
    }
    if actions != expected:
        raise AssertionError(
            "Stage 4 audit actions are incomplete"
        )


def check_phase3_compatibility() -> None:
    """Confirm the original identity-alert table remains."""
    with managed_connection(database_path()) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'identity_alerts'
            """
        ).fetchone()

    if table is None:
        raise AssertionError(
            "Original identity_alerts table is missing"
        )


def main() -> None:
    """Run all V2 Stage 4 validation checks."""
    checks = [
        (
            "Stage 4 files exist",
            check_required_files,
        ),
        (
            "Stage 4 configuration is valid",
            check_configuration,
        ),
        (
            "Two Stage 4 source files contain 24 records",
            check_source_events,
        ),
        (
            "Stage 4 database table and indexes exist",
            check_database_objects,
        ),
        (
            "Twenty-four Stage 4 events are stored in UTC",
            check_accepted_events,
        ),
        (
            "Sixteen traceable identity alerts are stored",
            check_alert_results,
        ),
        (
            "Important identity risks are classified correctly",
            check_specific_detections,
        ),
        (
            "VPN and approved-testing exceptions are recorded",
            check_exceptions,
        ),
        (
            "False-positive investigation is recorded",
            check_false_positive_review,
        ),
        (
            "Identity-alert duplicate protection is active",
            check_duplicate_protection,
        ),
        (
            "Stage 4 initialisation and detection are audited",
            check_initialisation_and_detection_audit,
        ),
        (
            "Original Phase 3 identity storage remains compatible",
            check_phase3_compatibility,
        ),
    ]

    results = [
        run_check(description, check)
        for description, check in checks
    ]
    passed = sum(results)
    total = len(results)

    print()
    if passed == total:
        print(
            f"V2 STAGE 4 VALIDATION: PASS ({passed}/{total})"
        )
        return

    failed = total - passed
    print(
        "V2 STAGE 4 VALIDATION: "
        f"FAIL ({failed} check(s) failed)"
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
