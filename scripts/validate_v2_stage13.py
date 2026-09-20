"""Validate V2 Stage 13 eradication, recovery and post-incident review."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.initialize_v2_stage13 import INDEX_NAMES, TABLE_NAMES
from src.response.v2_containment_response import sha256_text
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]
PASSES = 0


def require(condition: bool, message: str) -> None:
    """Record one passed validation or stop on failure."""
    global PASSES
    if not condition:
        raise AssertionError(message)
    PASSES += 1
    print(f"PASS: {message}")


def object_names(connection: Any, object_type: str) -> set[str]:
    """Return the names of SQLite objects of one type."""
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        )
    }


def main() -> None:
    """Run Stage 13 validation against tracked files and live data."""
    required_files = {
        ROOT / "config/v2_eradication_recovery.json",
        ROOT / "scripts/initialize_v2_stage13.py",
        ROOT / "scripts/manage_v2_stage13_recovery.py",
        ROOT / "scripts/validate_v2_stage13.py",
        ROOT / "src/response/v2_eradication_recovery.py",
        ROOT / "tests/test_v2_stage13_eradication_recovery.py",
    }
    require(
        all(path.is_file() for path in required_files),
        "Stage 13 files exist",
    )

    configuration = load_json(
        ROOT / "config/v2_eradication_recovery.json"
    )
    acl = load_json(ROOT / "config/automation_acl.json")
    settings = load_json(ROOT / "config/settings.json")

    require(
        configuration["stage"] == 13
        and configuration["environment"] == "sandbox"
        and configuration["simulation_only"] is True
        and configuration["allow_real_actions"] is False
        and configuration["allow_external_targets"] is False
        and configuration["default_action"] == "deny"
        and configuration["lifecycle"][
            "successful_containment_required"
        ]
        is True
        and configuration["lifecycle"][
            "close_only_after_verification"
        ]
        is True,
        "Stage 13 configuration preserves lifecycle and safety",
    )

    known_actions = {
        action: level
        for level in ("automatic", "approval_required", "manual_only")
        for action in acl[level]
    }
    require(
        acl["default_action"] == "deny"
        and len(configuration["actions"]) == 19
        and set(configuration["actions"]) <= set(known_actions)
        and all(
            not policy["disruptive"]
            or known_actions[action] != "automatic"
            for action, policy in configuration["actions"].items()
        ),
        "Nineteen Stage 13 actions align with the default-deny ACL",
    )

    schema = (ROOT / "database/schema.sql").read_text(
        encoding="utf-8"
    )
    require(
        all(
            f"CREATE TABLE IF NOT EXISTS {table}" in schema
            for table in TABLE_NAMES
        )
        and all(
            f"CREATE INDEX IF NOT EXISTS {index}" in schema
            for index in INDEX_NAMES
        ),
        "Tracked schema contains five Stage 13 tables and 25 indexes",
    )

    database = ROOT / settings["database"]["path"]
    with managed_connection(database) as connection:
        connection.row_factory = __import__("sqlite3").Row
        tables = object_names(connection, "table")
        indexes = object_names(connection, "index")
        require(
            TABLE_NAMES <= tables and INDEX_NAMES <= indexes,
            "Stage 13 database tables and named indexes exist",
        )
        require(
            connection.execute("PRAGMA foreign_key_check").fetchall()
            == []
            and connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            == "ok",
            "SQLite integrity and foreign keys are valid",
        )

        metadata = connection.execute(
            """
            SELECT value FROM system_metadata
            WHERE key = 'v2_stage_13_status'
            """
        ).fetchone()
        initialisation_audit = connection.execute(
            """
            SELECT COUNT(*) FROM audit_events
            WHERE action = 'initialize_v2_stage13'
              AND result = 'success'
            """
        ).fetchone()[0]
        require(
            metadata is not None
            and metadata[0] == "eradication_recovery_foundation_ready"
            and initialisation_audit >= 1,
            "Stage 13 foundation status and initialisation are audited",
        )

        incidents = connection.execute(
            "SELECT incident_id, status FROM v2_incidents ORDER BY incident_id"
        ).fetchall()
        require(
            [(row["incident_id"], row["status"]) for row in incidents]
            == [
                ("INC-V2-11-0001", "Closed"),
                ("INC-V2-11-0002", "New"),
                ("INC-V2-11-0003", "New"),
            ],
            "Only the evidence-backed incident completed the lifecycle",
        )

        lifecycle = [
            row[0]
            for row in connection.execute(
                """
                SELECT new_status
                FROM v2_incident_decisions
                WHERE incident_id = 'INC-V2-11-0001'
                  AND new_status IS NOT NULL
                ORDER BY incident_decision_id
                """
            )
        ]
        require(
            lifecycle
            == [
                "Triaged",
                "Investigating",
                "Contained",
                "Eradicated",
                "Recovered",
                "Closed",
            ],
            "Lifecycle transitions are sequential and evidence-backed",
        )

        containment = connection.execute(
            """
            SELECT COUNT(*)
            FROM v2_containment_actions
            WHERE incident_id = 'INC-V2-11-0001'
              AND status = 'successful'
            """
        ).fetchone()[0]
        require(
            containment >= 1,
            "Successful Stage 12 containment supports Stage 13 entry",
        )

        actions = connection.execute(
            """
            SELECT * FROM v2_recovery_actions
            WHERE incident_id = 'INC-V2-11-0001'
            ORDER BY recovery_action_id
            """
        ).fetchall()
        require(
            len(actions) == 8
            and len({row["request_id"] for row in actions}) == 8,
            "Eight live Stage 13 actions are duplicate-safe",
        )
        require(
            sum(
                row["phase"] == "eradication"
                and row["status"] == "successful"
                for row in actions
            )
            == 4
            and sum(
                row["phase"] == "eradication"
                and row["status"] == "denied"
                for row in actions
            )
            == 1,
            "Four eradication actions succeeded and one denial remained safe",
        )
        require(
            sum(
                row["phase"] == "recovery"
                and row["status"] == "successful"
                for row in actions
            )
            == 3,
            "Account, device and monitoring recovery actions succeeded",
        )
        require(
            all(row["evidence_preserved"] == 1 for row in actions)
            and all(row["real_action_executed"] == 0 for row in actions)
            and all(row["external_target_used"] == 0 for row in actions)
            and all(row["simulation_only"] == 1 for row in actions),
            "All actions preserved evidence and remained local simulations",
        )

        evidence = connection.execute(
            "SELECT * FROM v2_recovery_evidence"
        ).fetchall()
        require(
            len(evidence) == len(actions)
            and len(
                {row["recovery_action_id"] for row in evidence}
            )
            == len(actions),
            "One evidence snapshot was preserved before every action",
        )
        require(
            all(
                sha256_text(row["evidence_payload"])
                == row["evidence_sha256"]
                for row in evidence
            ),
            "All Stage 13 evidence SHA-256 hashes verify",
        )
        require(
            all(
                row["preserved_before_action"] == 1
                and row["original_evidence_preserved"] == 1
                for row in evidence
            ),
            "Original incident evidence remains preserved",
        )

        approvals = connection.execute(
            "SELECT * FROM v2_recovery_approvals"
        ).fetchall()
        require(
            len(approvals) == 7
            and sum(row["decision_status"] == "approved" for row in approvals)
            == 6
            and sum(row["decision_status"] == "denied" for row in approvals)
            == 1,
            "Approval-required and manual actions retain their decisions",
        )
        blocked = {
            row["recovery_action_id"]
            for row in approvals
            if row["self_approval_blocked"] == 1
        }
        require(
            blocked == {1, 5},
            "Requester self-approval denials remain recorded",
        )
        require(
            all(
                row["requested_by"] != row["decided_by"]
                for row in approvals
                if row["decided_by"] is not None
            ),
            "Recorded decisions preserve separation of duties",
        )

        denied_action = connection.execute(
            """
            SELECT status, executed_by, real_action_executed
            FROM v2_recovery_actions
            WHERE action_type = 'disable_compromised_account'
            """
        ).fetchone()
        require(
            denied_action is not None
            and denied_action["status"] == "denied"
            and denied_action["executed_by"] is None
            and denied_action["real_action_executed"] == 0,
            "Denied account action never executed",
        )

        retests = connection.execute(
            "SELECT * FROM v2_recovery_retests ORDER BY recovery_retest_id"
        ).fetchall()
        require(
            len(retests) == 2
            and {row["retest_type"] for row in retests}
            == {"original_threat", "original_vulnerability"}
            and all(row["observed_result"] == "blocked" for row in retests)
            and all(row["verification_status"] == "passed" for row in retests)
            and all(
                row["confirmed_no_longer_succeeds"] == 1
                for row in retests
            ),
            "Original threat and vulnerability retests passed",
        )

        monitoring = connection.execute(
            """
            SELECT COUNT(*) FROM v2_recovery_actions
            WHERE action_type = 'increase_post_recovery_monitoring'
              AND status = 'successful'
            """
        ).fetchone()[0]
        require(
            monitoring == 1,
            "Post-recovery monitoring is active and duplicate-safe",
        )

        review = connection.execute(
            """
            SELECT * FROM v2_post_incident_reviews
            WHERE incident_id = 'INC-V2-11-0001'
            """
        ).fetchone()
        require(
            review is not None
            and review["review_status"] == "complete"
            and review["closure_authorised"] == 1
            and review["eradication_verified"] == 1
            and review["recovery_verified"] == 1
            and review["original_threat_blocked"] == 1
            and review["original_vulnerability_blocked"] == 1
            and review["post_recovery_monitoring_active"] == 1,
            "Post-incident review authorises closure only after verification",
        )
        require(
            len(review["lessons_learned"].strip()) > 10
            and len(review["detection_improvements"].strip()) > 10
            and len(review["policy_improvements"].strip()) > 10,
            "Lessons and measurable improvement recommendations are stored",
        )

        audit_actions = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT action FROM audit_events
                WHERE action LIKE '%v2_stage13%'
                """
            )
        }
        require(
            {
                "initialize_v2_stage13",
                "confirm_v2_stage13_containment",
                "request_v2_stage13_action",
                "decide_v2_stage13_action",
                "execute_v2_stage13_action",
                "record_v2_stage13_retest",
                "complete_v2_stage13_eradication",
                "complete_v2_stage13_recovery",
                "close_v2_stage13_incident",
            }
            <= audit_actions,
            "Stage 13 actions, verification and closure are audited",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) FROM v2_incident_evidence"
            ).fetchone()[0]
            == 65
            and connection.execute(
                "SELECT COUNT(*) FROM v2_containment_actions"
            ).fetchone()[0]
            == 4,
            "Stage 11 evidence and Stage 12 containment remain intact",
        )

    print()
    print(f"V2 STAGE 13 VALIDATION: PASS ({PASSES}/{PASSES})")


if __name__ == "__main__":
    main()
