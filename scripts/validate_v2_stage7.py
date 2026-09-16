"""Validate Phase 3A V2 Stage 7 endpoint monitoring and investigation."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

from scripts.initialize_v2_stage7_8 import (
    validate_endpoint_configuration,
)
from src.detectors.v2_endpoint_monitor import (
    detect_endpoint_activity,
    is_approved_exception,
    load_device_inventory,
    load_stage7_events,
)
from src.utils.config_loader import load_json
from src.utils.security_controls import role_has_permission
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TABLES = {
    "v2_endpoint_alerts",
    "v2_endpoint_activity_timeline",
    "v2_endpoint_isolation_actions",
}
DETECTION_TYPES = {
    "Endpoint Health State",
    "Device Compliance State",
    "Device Risk State",
    "Suspicious Process",
    "Unknown or Unapproved Process",
    "Unexpected Process Owner",
    "Suspicious Parent-Child Process Relationship",
    "High CPU Activity",
    "Repeated Process Crash or Restart",
    "Suspicious Command Activity",
    "Possible Persistence Indicator",
    "Unexpected File-Hash Change",
    "Post-Isolation Endpoint Activity",
}


def require(condition: bool, message: str) -> None:
    """Reject a validation condition that is not satisfied."""
    if not condition:
        raise ValueError(message)


def is_utc(value: str) -> bool:
    """Check that a timestamp explicitly represents UTC."""
    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )
    return (
        timestamp.tzinfo is not None
        and timestamp.utcoffset() == timedelta(0)
    )


def main() -> None:
    """Validate the existing Stage 7 records without changing them."""
    results = []

    def check(label, operation):
        try:
            operation()
        except Exception as error:
            print(f"FAIL: {label}: {error}")
            results.append(False)
        else:
            print(f"PASS: {label}")
            results.append(True)

    required_files = [
        "config/v2_endpoint_monitoring.json",
        "scripts/initialize_v2_stage7_8.py",
        "scripts/generate_v2_stage7_8_events.py",
        "scripts/import_v2_stage7_8_events.py",
        "scripts/run_v2_stage7_endpoint_monitoring.py",
        "scripts/approve_v2_stage7_endpoint_isolation.py",
        "scripts/review_v2_stage7_endpoint_alert.py",
        "src/detectors/v2_endpoint_monitor.py",
        "tests/test_v2_stage7_endpoint_monitoring.py",
        "database/schema.sql",
        (
            "data/raw/v2/stage7_8/"
            "endpoint_v2_stage7_8_events.jsonl"
        ),
    ]
    check(
        "Stage 7 files exist",
        lambda: require(
            all(
                (PROJECT_ROOT / name).is_file()
                and (PROJECT_ROOT / name).stat().st_size > 0
                for name in required_files
            ),
            "A required Stage 7 file is missing or empty",
        ),
    )

    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    configuration = load_json(
        PROJECT_ROOT / "config/v2_endpoint_monitoring.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    rbac = load_json(
        PROJECT_ROOT / "config/rbac.json"
    )
    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )

    check(
        "Stage 7 configuration preserves the agreed safety rules",
        lambda: validate_endpoint_configuration(
            configuration,
            settings,
            automation_acl,
        ),
    )

    raw_events = []
    for source_file in configuration["source_files"]:
        source_path = (
            PROJECT_ROOT
            / "data/raw/v2/stage7_8"
            / source_file
        )
        raw_events.extend(
            json.loads(line)
            for line in source_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        )

    check(
        "The Stage 7 source contains 26 unique simulated endpoint events",
        lambda: require(
            len(raw_events) == 26
            and len(
                {event["event_id"] for event in raw_events}
            ) == 26
            and all(
                event["source_type"] == "endpoint"
                and event["schema_version"] == "2.0"
                and event["simulation_only"] is True
                for event in raw_events
            ),
            "Controlled endpoint source evidence does not match",
        ),
    )

    tracked_schema = (
        PROJECT_ROOT / "database/schema.sql"
    ).read_text(encoding="utf-8")

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(tracked_schema)
        tracked_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        tracked_indexes = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'index'
                  AND sql IS NOT NULL
                  AND tbl_name LIKE 'v2_endpoint_%'
                """
            )
        }

    check(
        "Tracked schema contains three Stage 7 tables and 16 indexes",
        lambda: require(
            TABLES <= tracked_tables
            and len(tracked_indexes) == 16,
            "Tracked Stage 7 schema is incomplete",
        ),
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        database_tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        database_indexes = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        alerts = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM v2_endpoint_alerts"
            )
        ]
        timeline = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM v2_endpoint_activity_timeline"
            )
        ]
        isolations = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM v2_endpoint_isolation_actions"
            )
        ]
        active_roles = {
            row["username"]: row["role"]
            for row in connection.execute(
                "SELECT username, role FROM user_roles WHERE active = 1"
            )
        }
        audit_actions = {
            row["action"]
            for row in connection.execute(
                "SELECT action FROM audit_events WHERE result = 'success'"
            )
        }
        metadata = dict(
            connection.execute(
                "SELECT key, value FROM system_metadata"
            ).fetchall()
        )

    check(
        "Stage 7 database tables and indexes exist",
        lambda: require(
            TABLES <= database_tables
            and tracked_indexes <= database_indexes,
            "Working Stage 7 schema is incomplete",
        ),
    )

    events = load_stage7_events(
        database_path,
        configuration["source_files"],
    )
    event_ids = {
        event["source_event_id"]
        for event in events
    }
    expected_event_ids = {
        event["event_id"]
        for event in raw_events
    }

    check(
        "Twenty-six Stage 7 events are stored once in UTC",
        lambda: require(
            len(events) == 26
            and event_ids == expected_event_ids
            and all(
                is_utc(event["event_time"])
                for event in events
            ),
            "Stored endpoint events do not match the source",
        ),
    )

    inventory = load_device_inventory(database_path)
    detected_alerts = detect_endpoint_activity(
        events,
        configuration,
        inventory,
    )
    expected_alert_keys = {
        alert["alert_key"]
        for alert in detected_alerts
    }
    stored_alert_keys = {
        alert["alert_key"]
        for alert in alerts
    }

    def validate_alerts():
        require(
            len(alerts) == 26
            and stored_alert_keys == expected_alert_keys,
            "Stored alerts do not match endpoint detection",
        )
        require(
            {
                alert["detection_type"]
                for alert in alerts
            } == DETECTION_TYPES,
            "A required endpoint detection type is missing",
        )
        for alert in alerts:
            source_ids = json.loads(
                alert["source_event_ids"]
            )
            evidence = json.loads(alert["evidence"])
            require(
                bool(source_ids)
                and set(source_ids) <= event_ids
                and bool(json.loads(alert["reason_codes"]))
                and bool(evidence.get("source_events"))
                and 0 <= alert["confidence"] <= 100,
                "An endpoint alert lacks traceable evidence",
            )

    check(
        "Twenty-six traceable alerts cover all 13 detection types",
        validate_alerts,
    )

    def validate_crash_rule():
        matching = [
            alert
            for alert in alerts
            if alert["detection_type"]
            == "Repeated Process Crash or Restart"
        ]
        require(
            len(matching) == 1,
            "Expected one crash or restart finding",
        )
        observations = json.loads(
            matching[0]["evidence"]
        )["observations"]
        require(
            configuration["thresholds"][
                "process_crash_restart_events"
            ] == 3
            and configuration["thresholds"][
                "process_crash_restart_window_minutes"
            ] == 8
            and observations["event_count"] == 3
            and observations["configured_window_minutes"] == 8
            and observations["observed_window_minutes"] == 7.0,
            "Crash or restart evidence does not match the agreed rule",
        )

    check(
        "The crash or restart rule uses three events within eight minutes",
        validate_crash_rule,
    )

    exception_ids = {
        event["source_event_id"]
        for event in events
        if is_approved_exception(
            event,
            configuration,
        )
    }
    alerted_event_ids = {
        event_id
        for alert in alerts
        for event_id in json.loads(
            alert["source_event_ids"]
        )
    }

    check(
        "Approved administrative and testing exceptions create no alerts",
        lambda: require(
            exception_ids == {
                "S78-END-ADMIN-001",
                "S78-END-TEST-001",
            }
            and exception_ids.isdisjoint(
                alerted_event_ids
            ),
            "Approved exception handling does not match",
        ),
    )

    check(
        "The endpoint timeline is complete and duplicate-safe",
        lambda: require(
            len(timeline) == 26
            and {
                row["source_event_id"]
                for row in timeline
            } == event_ids
            and all(
                is_utc(row["event_time"])
                for row in timeline
            ),
            "Endpoint timeline does not match stored events",
        ),
    )

    def validate_isolation():
        require(
            len(isolations) == 1,
            "Expected one consolidated isolation record",
        )
        isolation = isolations[0]
        evidence = json.loads(isolation["evidence"])
        critical_keys = {
            alert["alert_key"]
            for alert in alerts
            if alert["severity"] == "Critical"
        }
        approver_role = active_roles.get(
            isolation["approved_by"]
        )
        require(
            isolation["device_id"] == "CYOD-002"
            and isolation["action"] == "quarantine_device"
            and isolation["acl_control_level"] == "approval_required"
            and isolation["status"] == "simulated_isolated"
            and isolation["network_state_changed"] == 0
            and isolation["real_action_executed"] == 0
            and len(critical_keys) == 10
            and evidence["alert_count"] == 10
            and set(evidence["alert_keys"]) == critical_keys,
            "Simulated isolation or consolidated evidence is incorrect",
        )
        require(
            approver_role
            in configuration["isolation_policy"]["approval_roles"]
            and role_has_permission(
                rbac,
                approver_role,
                "execute_approved_containment",
            )
            and bool(isolation["approved_at"]),
            "Simulated isolation lacks an authorised approval",
        )

    check(
        "One approved simulated isolation preserves all 10 Critical alerts",
        validate_isolation,
    )

    def validate_review():
        matching = [
            alert
            for alert in alerts
            if alert["detection_type"]
            == "Repeated Process Crash or Restart"
        ]
        require(
            len(matching) == 1,
            "Crash or restart review evidence is missing",
        )
        alert = matching[0]
        reviewer_role = active_roles.get(
            alert["reviewed_by"]
        )
        require(
            alert["status"] == "Closed"
            and alert["classification"] == "False Positive"
            and bool(alert["investigation_notes"])
            and bool(alert["reviewed_at"])
            and reviewer_role is not None
            and all(
                role_has_permission(
                    rbac,
                    reviewer_role,
                    permission,
                )
                for permission in {
                    "investigate_incidents",
                    "add_investigation_notes",
                    "classify_false_positives",
                }
            ),
            "False-positive review lacks authorised investigation evidence",
        )

    check(
        "False-positive investigation is recorded without deleting the alert",
        validate_review,
    )

    check(
        "Stage 7 completion, approval and investigation are audited",
        lambda: require(
            metadata.get("v2_stage_7_status")
            == "endpoint_monitoring_complete"
            and {
                "initialize_v2_stage7_8",
                "import_v2_stage7_8_events",
                "run_v2_stage7_endpoint_monitoring",
                "approve_v2_stage7_endpoint_isolation",
                "review_v2_stage7_endpoint_alert",
            } <= audit_actions,
            "Stage 7 metadata or audit records are missing",
        ),
    )

    check(
        "Original Phase 3 endpoint storage remains available",
        lambda: require(
            "endpoint_alerts" in database_tables,
            "Original endpoint alert storage is missing",
        ),
    )

    passed = sum(results)
    total = len(results)
    outcome = "PASS" if passed == total else "FAIL"
    print()
    print(
        f"V2 STAGE 7 VALIDATION: "
        f"{outcome} ({passed}/{total})"
    )

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
