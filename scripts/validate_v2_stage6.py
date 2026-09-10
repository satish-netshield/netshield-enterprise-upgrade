"""Validate Phase 3A V2 Stage 6 network monitoring."""

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Callable

from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION_PATH = (
    PROJECT_ROOT / "config/v2_network_monitoring.json"
)
SETTINGS_PATH = PROJECT_ROOT / "config/settings.json"

EXPECTED_ALERT_COUNTS = {
    "Suspicious IP Address": 3,
    "Port Scanning": 1,
    "Repeated Connection Attempts": 1,
    "Abnormal Connection Pattern": 1,
    "Restricted Port or Service": 4,
    "Unknown CYOD Device": 1,
    "MAC Address Reuse or Possible Spoofing": 1,
    "WPA3 Policy Violation": 1,
    "WPA2 Downgrade Attempt": 1,
    "Rogue Access Point": 1,
    "Wi-Fi Zone Violation": 1,
    "Unknown Wired Device": 1,
    "Restricted Wired Access": 1,
}

EXPECTED_DECISION_COUNTS = {
    "allow": 4,
    "deny": 18,
    "challenge": 11,
    "restrict": 1,
}


def database_path() -> Path:
    """Return the configured SQLite database path."""
    settings = load_json(SETTINGS_PATH)
    return PROJECT_ROOT / settings["database"]["path"]


def check_required_files() -> bool:
    """Confirm that the Stage 6 implementation files exist."""
    required_files = [
        CONFIGURATION_PATH,
        PROJECT_ROOT / "data/blocklists/ip_blocklist.txt",
        PROJECT_ROOT
        / "data/raw/v2/stage6/network_v2_stage6_events.jsonl",
        PROJECT_ROOT
        / "data/raw/v2/stage6/wifi_v2_stage6_events.jsonl",
        PROJECT_ROOT / "scripts/generate_v2_stage6_events.py",
        PROJECT_ROOT / "scripts/import_v2_stage6_events.py",
        PROJECT_ROOT / "scripts/initialize_v2_stage6.py",
        PROJECT_ROOT
        / "scripts/review_v2_stage6_network_alert.py",
        PROJECT_ROOT
        / "scripts/run_v2_stage6_network_monitoring.py",
        PROJECT_ROOT / "src/network/__init__.py",
        PROJECT_ROOT / "src/network/v2_network_monitor.py",
        PROJECT_ROOT
        / "tests/test_v2_stage6_network_monitoring.py",
        PROJECT_ROOT
        / "tests/test_v2_stage6_network_alert_review.py",
    ]

    return all(
        file_path.is_file() and file_path.stat().st_size > 0
        for file_path in required_files
    )


def check_configuration() -> bool:
    """Confirm the important Stage 6 security settings."""
    configuration = load_json(CONFIGURATION_PATH)

    return (
        configuration["simulation_only"] is True
        and configuration["network_policy"]["default_decision"]
        == "deny"
        and configuration["network_policy"]["decision_precedence"]
        == ["deny", "restrict", "challenge", "allow"]
        and configuration["device_identity"][
            "mac_address_identity"
        ]
        == "supporting_evidence_only"
        and configuration["wifi_policy"]["required_security"]
        == "WPA3"
        and configuration["wifi_policy"][
            "allow_wpa2_downgrade"
        ]
        is False
        and configuration["response_actions"]["challenge"]
        == "increase_monitoring"
        and configuration["response_actions"]["restrict"]
        == "apply_ubuntu_firewall_rule"
        and set(configuration["detection_rules"])
        == {
            "suspicious_ip_address",
            "port_scanning",
            "repeated_connection_attempts",
            "abnormal_connection_pattern",
            "restricted_port_or_service",
            "unknown_cyod_device",
            "mac_reuse_or_possible_spoofing",
            "wpa3_policy_violation",
            "wpa2_downgrade_attempt",
            "rogue_access_point",
            "wifi_zone_violation",
            "unknown_wired_device",
            "restricted_wired_access",
        }
        and all(configuration["detection_rules"].values())
    )


def load_source_events() -> list[dict]:
    """Load the controlled Stage 6 JSONL source records."""
    configuration = load_json(CONFIGURATION_PATH)
    source_directory = (
        PROJECT_ROOT / configuration["source_directory"]
    )
    events = []

    for source_file in configuration["source_files"]:
        file_path = source_directory / source_file

        for line in file_path.read_text(
            encoding="utf-8"
        ).splitlines():
            if line.strip():
                events.append(json.loads(line))

    return events


def check_source_events() -> bool:
    """Confirm Stage 6 source totals and unique event IDs."""
    events = load_source_events()
    source_counts = Counter(
        event.get("source_type")
        for event in events
    )
    event_ids = {
        event.get("event_id")
        for event in events
    }

    return (
        len(events) == 34
        and len(event_ids) == 34
        and None not in event_ids
        and source_counts
        == {
            "network": 27,
            "wifi": 7,
        }
        and all(
            event.get("schema_version") == "2.0"
            for event in events
        )
    )


def check_tracked_schema() -> bool:
    """Confirm clean databases will contain the Stage 6 schema."""
    schema = (
        PROJECT_ROOT / "database/schema.sql"
    ).read_text(encoding="utf-8")

    required_markers = [
        "CREATE TABLE IF NOT EXISTS v2_network_alerts",
        (
            "CREATE TABLE IF NOT EXISTS "
            "v2_network_access_decisions"
        ),
        (
            "CREATE TABLE IF NOT EXISTS "
            "v2_network_connection_timeline"
        ),
    ]

    return all(
        marker in schema
        for marker in required_markers
    )


def check_database_tables_and_indexes() -> bool:
    """Confirm the Stage 6 tables and indexes exist."""
    expected_tables = {
        "v2_network_alerts",
        "v2_network_access_decisions",
        "v2_network_connection_timeline",
    }

    with managed_connection(database_path()) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                      'v2_network_alerts',
                      'v2_network_access_decisions',
                      'v2_network_connection_timeline'
                  )
                """
            ).fetchall()
        }
        indexes = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'index'
                  AND name LIKE 'idx_v2_network_%'
                """
            ).fetchall()
        }

    return (
        tables == expected_tables
        and len(indexes) == 17
    )


def check_stored_events() -> bool:
    """Confirm all controlled Stage 6 events are stored once in UTC."""
    with managed_connection(database_path()) as connection:
        stored = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT source_event_id),
                SUM(
                    CASE
                        WHEN event_time LIKE '%+00:00'
                        THEN 1
                        ELSE 0
                    END
                )
            FROM security_events
            WHERE source_file IN (
                'network_v2_stage6_events.jsonl',
                'wifi_v2_stage6_events.jsonl'
            )
            """
        ).fetchone()

    return stored == (34, 34, 34)


def check_stored_alerts() -> bool:
    """Confirm the expected duplicate-safe alert total."""
    with managed_connection(database_path()) as connection:
        stored = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT alert_key),
                SUM(
                    CASE
                        WHEN reason_codes IS NOT NULL
                         AND reason_codes <> '[]'
                         AND evidence IS NOT NULL
                         AND evidence <> '{}'
                        THEN 1
                        ELSE 0
                    END
                )
            FROM v2_network_alerts
            """
        ).fetchone()

    return stored == (18, 18, 18)


def check_detection_coverage() -> bool:
    """Confirm every required detection has the expected result."""
    with managed_connection(database_path()) as connection:
        rows = connection.execute(
            """
            SELECT detection_type, COUNT(*)
            FROM v2_network_alerts
            GROUP BY detection_type
            """
        ).fetchall()

    stored_counts = {
        detection_type: count
        for detection_type, count in rows
    }

    return stored_counts == EXPECTED_ALERT_COUNTS


def check_access_decisions() -> bool:
    """Confirm every event has one explainable access decision."""
    with managed_connection(database_path()) as connection:
        rows = connection.execute(
            """
            SELECT decision, COUNT(*)
            FROM v2_network_access_decisions
            GROUP BY decision
            """
        ).fetchall()
        totals = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT decision_key),
                COUNT(DISTINCT source_event_id),
                SUM(
                    CASE
                        WHEN matching_rules IS NOT NULL
                         AND matching_rules <> '[]'
                         AND reason_codes IS NOT NULL
                         AND reason_codes <> '[]'
                         AND evidence IS NOT NULL
                         AND evidence <> '{}'
                        THEN 1
                        ELSE 0
                    END
                )
            FROM v2_network_access_decisions
            """
        ).fetchone()

    decision_counts = {
        decision: count
        for decision, count in rows
    }

    return (
        decision_counts == EXPECTED_DECISION_COUNTS
        and totals == (34, 34, 34, 34)
    )


def check_priority_and_acl() -> bool:
    """Confirm restrictive priority and ACL response controls."""
    with managed_connection(database_path()) as connection:
        scan = connection.execute(
            """
            SELECT
                decision,
                matching_rules
            FROM v2_network_access_decisions
            WHERE source_event_id = 'S6-NET-SCAN-003'
            """
        ).fetchone()
        challenge = connection.execute(
            """
            SELECT
                decision,
                response_action,
                acl_control_level,
                response_status
            FROM v2_network_access_decisions
            WHERE source_event_id = 'S6-NET-026'
            """
        ).fetchone()
        restrict = connection.execute(
            """
            SELECT
                decision,
                response_action,
                acl_control_level,
                response_status
            FROM v2_network_access_decisions
            WHERE source_event_id = 'S6-WIFI-005'
            """
        ).fetchone()

    return (
        scan is not None
        and scan[0] == "deny"
        and "port_scanning" in scan[1]
        and "suspicious_ip_address" in scan[1]
        and challenge
        == (
            "challenge",
            "increase_monitoring",
            "automatic",
            "simulated_automatic",
        )
        and restrict
        == (
            "restrict",
            "apply_ubuntu_firewall_rule",
            "approval_required",
            "approval_required",
        )
    )


def check_approved_exceptions() -> bool:
    """Confirm approved VPN and testing exceptions are recorded."""
    with managed_connection(database_path()) as connection:
        vpn = connection.execute(
            """
            SELECT decision, reason_codes
            FROM v2_network_access_decisions
            WHERE source_event_id = 'S6-NET-025'
            """
        ).fetchone()
        testing = connection.execute(
            """
            SELECT decision, reason_codes
            FROM v2_network_access_decisions
            WHERE source_event_id = 'S6-WIFI-007'
            """
        ).fetchone()

    return (
        vpn is not None
        and vpn[0] == "allow"
        and "APPROVED_VPN_EXCEPTION" in vpn[1]
        and testing is not None
        and testing[0] == "allow"
        and "APPROVED_TESTING_EXCEPTION" in testing[1]
    )


def check_connection_timeline() -> bool:
    """Confirm the complete duplicate-safe connection timeline."""
    with managed_connection(database_path()) as connection:
        stored = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT source_event_id)
            FROM v2_network_connection_timeline
            """
        ).fetchone()

    return stored == (34, 34)


def check_false_positive_review() -> bool:
    """Confirm the controlled false-positive review is preserved."""
    with managed_connection(database_path()) as connection:
        reviewed = connection.execute(
            """
            SELECT
                status,
                classification,
                investigation_notes,
                reviewed_by,
                reviewed_at
            FROM v2_network_alerts
            WHERE detection_type = 'Abnormal Connection Pattern'
            """
        ).fetchone()

    return (
        reviewed is not None
        and reviewed[0] == "Closed"
        and reviewed[1] == "False Positive"
        and reviewed[2]
        == (
            "Verified as controlled after-hours "
            "connection-volume testing. "
            "No unauthorised network activity occurred."
        )
        and reviewed[3] == "analyst01"
        and reviewed[4] is not None
    )


def check_audit_and_metadata() -> bool:
    """Confirm Stage 6 work is represented in the audit trail."""
    required_actions = {
        "initialize_v2_stage6",
        "import_v2_stage6_events",
        "run_v2_stage6_network_monitoring",
        "review_v2_stage6_network_alert",
    }

    with managed_connection(database_path()) as connection:
        actions = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT action
                FROM audit_events
                WHERE action IN (
                    'initialize_v2_stage6',
                    'import_v2_stage6_events',
                    'run_v2_stage6_network_monitoring',
                    'review_v2_stage6_network_alert'
                )
                  AND result = 'success'
                """
            ).fetchall()
        }
        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage_6_status'
            """
        ).fetchone()

    return (
        actions == required_actions
        and metadata is not None
        and metadata[0] == "network_monitoring_complete"
    )


def check_original_phase3_compatibility() -> bool:
    """Confirm the original Phase 3 network storage remains present."""
    with managed_connection(database_path()) as connection:
        original_table = connection.execute(
            """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'network_alerts'
            """
        ).fetchone()
        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

    return (
        original_table == (1,)
        and integrity == ("ok",)
        and foreign_keys == []
    )


def run_check(
    description: str,
    check: Callable[[], bool],
) -> bool:
    """Run one validation check and print its result."""
    try:
        passed = check()
    except Exception as error:
        print(f"FAIL: {description} ({error})")
        return False

    if passed:
        print(f"PASS: {description}")
        return True

    print(f"FAIL: {description}")
    return False


def main() -> None:
    """Run all Stage 6 validation checks."""
    checks = [
        (
            "Stage 6 files exist",
            check_required_files,
        ),
        (
            "Stage 6 configuration is valid",
            check_configuration,
        ),
        (
            "Two Stage 6 source files contain 34 unique events",
            check_source_events,
        ),
        (
            "Tracked schema contains the Stage 6 tables",
            check_tracked_schema,
        ),
        (
            "Stage 6 database tables and indexes exist",
            check_database_tables_and_indexes,
        ),
        (
            "Thirty-four Stage 6 events are stored once in UTC",
            check_stored_events,
        ),
        (
            "Eighteen traceable network alerts are stored",
            check_stored_alerts,
        ),
        (
            "All required network and Wi-Fi detections are represented",
            check_detection_coverage,
        ),
        (
            "Every event has one explainable access decision",
            check_access_decisions,
        ),
        (
            "Decision priority and automation ACL controls are enforced",
            check_priority_and_acl,
        ),
        (
            "Approved VPN and testing exceptions are preserved",
            check_approved_exceptions,
        ),
        (
            "The connection timeline is complete and duplicate-safe",
            check_connection_timeline,
        ),
        (
            "False-positive investigation is recorded",
            check_false_positive_review,
        ),
        (
            "Stage 6 work is recorded in metadata and audit events",
            check_audit_and_metadata,
        ),
        (
            "Original Phase 3 network storage remains compatible",
            check_original_phase3_compatibility,
        ),
    ]

    passed = sum(
        run_check(description, check)
        for description, check in checks
    )
    total = len(checks)

    print()
    print(
        "V2 STAGE 6 VALIDATION: "
        f"{'PASS' if passed == total else 'FAIL'} "
        f"({passed}/{total})"
    )

    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
