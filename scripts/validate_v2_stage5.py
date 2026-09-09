"""Validate V2 Stage 5 local access-policy decisions."""
from src.utils.sqlite_connection import managed_connection

import json
import sqlite3
from pathlib import Path
from typing import Callable

from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_INDEXES = {
    "idx_access_restrictions_username",
    "idx_access_restrictions_active",
    "idx_access_policy_request",
    "idx_access_policy_username",
    "idx_access_policy_device",
    "idx_access_policy_application",
    "idx_access_policy_decision",
    "idx_access_policy_time",
}
EXPECTED_RESULTS = {
    "S45-POLICY-001": (
        "allow",
        "POL-011",
        "not_required",
    ),
    "S45-POLICY-002": (
        "deny",
        "POL-003",
        "not_required",
    ),
    "S45-POLICY-003": (
        "challenge",
        "POL-007",
        "simulated_automatic",
    ),
    "S45-POLICY-004": (
        "restrict",
        "POL-006",
        "approval_required",
    ),
    "S45-POLICY-005": (
        "deny",
        "POL-005",
        "not_required",
    ),
    "S45-POLICY-006": (
        "challenge",
        "POL-010",
        "simulated_automatic",
    ),
    "S45-POLICY-007": (
        "deny",
        "POL-004",
        "not_required",
    ),
    "S45-POLICY-008": (
        "allow",
        "POL-011",
        "not_required",
    ),
    "S45-POLICY-009": (
        "deny",
        "POL-001",
        "not_required",
    ),
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
    """Run one check without stopping later validation."""
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
    """Confirm Stage 5 source and configuration files exist."""
    required_files = [
        PROJECT_ROOT / "config/v2_access_policy.json",
        PROJECT_ROOT / "src/policy/__init__.py",
        PROJECT_ROOT / "src/policy/v2_access_policy.py",
        PROJECT_ROOT
        / "scripts/run_v2_stage5_access_policy.py",
        PROJECT_ROOT
        / "tests/test_v2_stage5_access_policy.py",
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
    """Validate default deny, outcomes and policy priorities."""
    configuration = load_json(
        PROJECT_ROOT / "config/v2_access_policy.json"
    )

    if not configuration["simulation_only"]:
        raise AssertionError(
            "Stage 5 must remain simulation-only"
        )

    if configuration["default_decision"] != "deny":
        raise AssertionError(
            "Default access decision must be deny"
        )

    expected_outcomes = {
        "allow",
        "deny",
        "challenge",
        "restrict",
    }
    if set(configuration["decision_outcomes"]) != (
        expected_outcomes
    ):
        raise AssertionError(
            "Unexpected access-decision outcomes"
        )

    if configuration["decision_precedence"] != [
        "deny",
        "restrict",
        "challenge",
        "allow",
    ]:
        raise AssertionError(
            "Decision precedence is not restrictive"
        )

    policies = configuration["policies"]
    policy_ids = [
        policy["policy_id"]
        for policy in policies
    ]

    if len(policy_ids) != len(set(policy_ids)):
        raise AssertionError(
            "Policy IDs must be unique"
        )

    if not all(
        isinstance(policy["priority"], int)
        and policy["priority"] > 0
        and policy["reason_code"]
        for policy in policies
    ):
        raise AssertionError(
            "Policy priority or reason code is invalid"
        )


def check_rbac_and_acl_alignment() -> None:
    """Confirm Stage 5 reuses the existing RBAC and ACL."""
    rbac = load_json(PROJECT_ROOT / "config/rbac.json")
    acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    policy = load_json(
        PROJECT_ROOT / "config/v2_access_policy.json"
    )

    expected_roles = {
        "viewer",
        "analyst",
        "responder",
        "administrator",
    }
    if set(rbac["roles"]) != expected_roles:
        raise AssertionError(
            "Expected four existing RBAC roles"
        )

    if acl["default_action"] != "deny":
        raise AssertionError(
            "Automation ACL must remain default deny"
        )

    challenge_action = policy["response_actions"][
        "challenge"
    ]
    restrict_action = policy["response_actions"][
        "restrict"
    ]

    if challenge_action not in acl["automatic"]:
        raise AssertionError(
            "Challenge action is not automatic"
        )

    if restrict_action not in acl["approval_required"]:
        raise AssertionError(
            "Restrict action does not require approval"
        )


def check_source_events() -> None:
    """Confirm the nine controlled access requests."""
    source_path = (
        PROJECT_ROOT
        / "data/raw/v2/stage4_5"
        / "access_policy_v2_stage4_5_events.jsonl"
    )

    records = [
        json.loads(line)
        for line in source_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if len(records) != 9:
        raise AssertionError(
            f"Expected 9 access requests, found {len(records)}"
        )

    for record in records:
        if record["source_type"] != "access_policy":
            raise AssertionError(
                "Unexpected source type"
            )
        if record["event_type"] != "access_request":
            raise AssertionError(
                "Unexpected access-policy event type"
            )
        if record["schema_version"] != "2.0":
            raise AssertionError(
                "Unexpected schema version"
            )


def check_database_objects() -> None:
    """Confirm Stage 5 tables and indexes exist."""
    with managed_connection(database_path()) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }
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

    expected_tables = {
        "access_policy_decisions",
        "temporary_access_restrictions",
    }
    missing_tables = expected_tables - tables
    if missing_tables:
        raise AssertionError(
            "Missing tables: "
            + ", ".join(sorted(missing_tables))
        )

    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        raise AssertionError(
            "Missing indexes: "
            + ", ".join(sorted(missing_indexes))
        )


def check_stored_decisions() -> None:
    """Confirm one unique decision exists per request."""
    with managed_connection(database_path()) as connection:
        total, unique_keys, unique_requests = connection.execute(
            """
            SELECT
                COUNT(*),
                COUNT(DISTINCT decision_key),
                COUNT(DISTINCT request_event_id)
            FROM access_policy_decisions
            """
        ).fetchone()

    if (total, unique_keys, unique_requests) != (9, 9, 9):
        raise AssertionError(
            "Expected 9 unique stored access decisions"
        )


def check_decision_outcomes() -> None:
    """Confirm allow, deny, challenge and restrict results."""
    with managed_connection(database_path()) as connection:
        rows = connection.execute(
            """
            SELECT decision, COUNT(*)
            FROM access_policy_decisions
            GROUP BY decision
            """
        ).fetchall()

    counts = dict(rows)
    expected_counts = {
        "allow": 2,
        "deny": 4,
        "challenge": 2,
        "restrict": 1,
    }

    if counts != expected_counts:
        raise AssertionError(
            f"Unexpected decision counts: {counts}"
        )


def check_expected_policy_results() -> None:
    """Confirm every request received the expected decision."""
    with managed_connection(database_path()) as connection:
        rows = connection.execute(
            """
            SELECT
                request_event_id,
                decision,
                winning_policy_id,
                response_status
            FROM access_policy_decisions
            ORDER BY request_event_id
            """
        ).fetchall()

    stored_results = {
        request_id: (
            decision,
            winning_policy_id,
            response_status,
        )
        for (
            request_id,
            decision,
            winning_policy_id,
            response_status,
        ) in rows
    }

    if stored_results != EXPECTED_RESULTS:
        raise AssertionError(
            "Stored policy results do not match expectations"
        )


def check_reason_codes_and_evidence() -> None:
    """Confirm every decision is explainable."""
    with managed_connection(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                reason_codes,
                matched_policy_ids,
                identity_evidence,
                device_evidence,
                risk_evidence,
                evidence
            FROM access_policy_decisions
            """
        ).fetchall()

    for row in rows:
        if not json.loads(row["reason_codes"]):
            raise AssertionError(
                "Decision has no reason code"
            )
        if not json.loads(row["matched_policy_ids"]):
            raise AssertionError(
                "Decision has no matching policy"
            )

        identity = json.loads(row["identity_evidence"])
        device = json.loads(row["device_evidence"])
        risk = json.loads(row["risk_evidence"])
        evidence = json.loads(row["evidence"])

        if "role" not in identity:
            raise AssertionError(
                "Identity evidence has no role"
            )
        if "registration_status" not in device:
            raise AssertionError(
                "Device evidence has no registration state"
            )
        if "mfa_satisfied" not in risk:
            raise AssertionError(
                "Risk evidence has no MFA result"
            )
        if "conditions" not in evidence:
            raise AssertionError(
                "Policy evidence has no condition results"
            )


def check_acl_results() -> None:
    """Confirm response actions follow the existing ACL."""
    with managed_connection(database_path()) as connection:
        challenge_rows = connection.execute(
            """
            SELECT
                response_action,
                acl_control_level,
                response_status
            FROM access_policy_decisions
            WHERE decision = 'challenge'
            """
        ).fetchall()

        restrict_row = connection.execute(
            """
            SELECT
                response_action,
                acl_control_level,
                response_status
            FROM access_policy_decisions
            WHERE decision = 'restrict'
            """
        ).fetchone()

    if len(challenge_rows) != 2:
        raise AssertionError(
            "Expected two challenged requests"
        )

    if any(
        row
        != (
            "increase_monitoring",
            "automatic",
            "simulated_automatic",
        )
        for row in challenge_rows
    ):
        raise AssertionError(
            "Challenge response did not follow the ACL"
        )

    if restrict_row != (
        "restrict_account",
        "approval_required",
        "approval_required",
    ):
        raise AssertionError(
            "Restrict response bypassed approval"
        )


def check_policy_priority() -> None:
    """Confirm higher-priority restrictions win conflicts."""
    with managed_connection(database_path()) as connection:
        row = connection.execute(
            """
            SELECT
                decision,
                winning_policy_id,
                reason_codes
            FROM access_policy_decisions
            WHERE request_event_id = 'S45-POLICY-009'
            """
        ).fetchone()

    if row is None:
        raise AssertionError(
            "Temporary-restriction decision is missing"
        )

    reasons = json.loads(row[2])

    if row[0] != "deny" or row[1] != "POL-001":
        raise AssertionError(
            "Temporary restriction did not win"
        )

    if "TEMPORARY_ACCESS_RESTRICTION" not in reasons:
        raise AssertionError(
            "Temporary restriction reason is missing"
        )


def check_vpn_exception() -> None:
    """Confirm the approved VPN request retains evidence."""
    with managed_connection(database_path()) as connection:
        row = connection.execute(
            """
            SELECT decision, risk_evidence
            FROM access_policy_decisions
            WHERE request_event_id = 'S45-POLICY-008'
            """
        ).fetchone()

    if row is None:
        raise AssertionError(
            "Approved VPN decision is missing"
        )

    risk_evidence = json.loads(row[1])

    if row[0] != "allow":
        raise AssertionError(
            "Approved VPN request was not allowed"
        )

    if not risk_evidence["vpn_exception"]:
        raise AssertionError(
            "VPN exception evidence is missing"
        )


def check_audit_and_metadata() -> None:
    """Confirm Stage 5 completion is recorded."""
    with managed_connection(database_path()) as connection:
        audit = connection.execute(
            """
            SELECT result, details
            FROM audit_events
            WHERE action = 'run_v2_stage5_access_policy'
            ORDER BY event_id DESC
            LIMIT 1
            """
        ).fetchone()

        metadata = connection.execute(
            """
            SELECT value
            FROM system_metadata
            WHERE key = 'v2_stage5_access_policy'
            """
        ).fetchone()

    if audit is None or audit[0] != "success":
        raise AssertionError(
            "Stage 5 audit record is missing"
        )

    if "decisions=9" not in audit[1]:
        raise AssertionError(
            "Stage 5 audit totals are incorrect"
        )

    if metadata != ("decisions_complete",):
        raise AssertionError(
            "Stage 5 metadata is incorrect"
        )


def check_phase3_compatibility() -> None:
    """Confirm original RBAC and alert tables remain."""
    with managed_connection(database_path()) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                      'user_roles',
                      'identity_alerts',
                      'device_alerts'
                  )
                """
            )
        }

    expected = {
        "user_roles",
        "identity_alerts",
        "device_alerts",
    }
    if tables != expected:
        raise AssertionError(
            "Original access-control tables are incomplete"
        )


def main() -> None:
    """Run all V2 Stage 5 validation checks."""
    checks = [
        (
            "Stage 5 files exist",
            check_required_files,
        ),
        (
            "Default-deny policy configuration is valid",
            check_configuration,
        ),
        (
            "Existing RBAC and automation ACL are reused",
            check_rbac_and_acl_alignment,
        ),
        (
            "Nine controlled access requests are available",
            check_source_events,
        ),
        (
            "Stage 5 database tables and indexes exist",
            check_database_objects,
        ),
        (
            "One duplicate-safe decision exists per request",
            check_stored_decisions,
        ),
        (
            "All four access outcomes are represented",
            check_decision_outcomes,
        ),
        (
            "Every request has the expected winning policy",
            check_expected_policy_results,
        ),
        (
            "Every decision contains reasons and evidence",
            check_reason_codes_and_evidence,
        ),
        (
            "Automated responses follow the ACL",
            check_acl_results,
        ),
        (
            "Policy priority resolves conflicting conditions",
            check_policy_priority,
        ),
        (
            "Approved VPN evidence is preserved",
            check_vpn_exception,
        ),
        (
            "Stage 5 completion is audited",
            check_audit_and_metadata,
        ),
        (
            "Original Phase 3 controls remain compatible",
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
            f"V2 STAGE 5 VALIDATION: PASS ({passed}/{total})"
        )
        return

    failed = total - passed
    print(
        "V2 STAGE 5 VALIDATION: "
        f"FAIL ({failed} check(s) failed)"
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
