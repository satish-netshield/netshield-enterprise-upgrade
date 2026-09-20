"""Evidence-backed simulated eradication and recovery for V2 Stage 13."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.response.v2_containment_response import (
    canonical_json,
    clean_references,
    clean_text,
    load_incident,
    load_incident_evidence,
    require_permission,
    sha256_text,
    stable_key,
    utc_now,
)
from src.utils.database import record_audit_event
from src.utils.security_controls import action_control_level
from src.utils.sqlite_connection import managed_connection


class RecoveryError(RuntimeError):
    """Raised when Stage 13 cannot continue safely."""


def validate_safety(configuration: dict[str, Any]) -> None:
    """Fail closed if a Stage 13 safety boundary is weakened."""
    checks = (
        (configuration.get("stage") == 13, "Invalid Stage 13 number"),
        (
            configuration.get("environment") == "sandbox",
            "Stage 13 environment must be sandbox",
        ),
        (
            configuration.get("simulation_only") is True,
            "Stage 13 must remain simulation-only",
        ),
        (
            configuration.get("allow_real_actions") is False,
            "Real Stage 13 actions must remain disabled",
        ),
        (
            configuration.get("allow_external_targets") is False,
            "External targets must remain disabled",
        ),
        (
            configuration.get("default_action") == "deny",
            "Undefined actions must default to deny",
        ),
        (
            configuration["evidence_policy"]["preserve_before_action"]
            is True,
            "Evidence must be preserved before action",
        ),
        (
            configuration["evidence_policy"]["hash_algorithm"]
            == "sha256",
            "Stage 13 evidence must use SHA-256",
        ),
        (
            configuration["lifecycle"]["close_only_after_verification"]
            is True,
            "Incident closure must require verification",
        ),
    )
    for condition, message in checks:
        if not condition:
            raise RecoveryError(message)

    safety = configuration["safety"]
    if safety["local_simulated_data_only"] is not True:
        raise RecoveryError("Only local simulated data is allowed")
    for name, value in safety.items():
        if name != "local_simulated_data_only" and value is not False:
            raise RecoveryError(f"Unsafe Stage 13 setting enabled: {name}")


def audit(
    database_path: Path,
    actor: str,
    action: str,
    target: str,
    result: str,
    details: str,
) -> None:
    """Write a Stage 13 result to the existing audit trail."""
    record_audit_event(
        database_path,
        actor,
        action,
        target,
        result,
        details,
    )


def action_result(row: sqlite3.Row, *, new: bool = False) -> dict[str, Any]:
    """Convert a stored recovery action into a public result."""
    return {
        "recovery_action_id": row["recovery_action_id"],
        "incident_id": row["incident_id"],
        "phase": row["phase"],
        "action_type": row["action_type"],
        "target_type": row["target_type"],
        "target_value": row["target_value"],
        "control_level": row["control_level"],
        "status": row["status"],
        "requested_by": row["requested_by"],
        "approved_by": row["approved_by"],
        "executed_by": row["executed_by"],
        "evidence_preserved": bool(row["evidence_preserved"]),
        "simulation_only": bool(row["simulation_only"]),
        "real_action_executed": bool(row["real_action_executed"]),
        "new": new,
    }


def evidence_snapshot(
    incident: sqlite3.Row,
    evidence_rows: list[sqlite3.Row],
    phase: str,
    action_type: str,
    target_type: str,
    target_value: str,
    captured_at: str,
) -> tuple[str, str]:
    """Build the canonical evidence snapshot saved before an action."""
    evidence: list[dict[str, Any]] = []
    for row in evidence_rows:
        evidence.append(
            {
                "source_type": row["source_type"],
                "source_record_id": row["source_record_id"],
                "source_evidence_key": row["source_evidence_key"],
                "evidence_reference": row["evidence_reference"],
                "evidence_time": row["evidence_time"],
                "relationship": row["relationship"],
                "contribution_status": row["contribution_status"],
                "evidence_sha256": row["evidence_sha256"],
                "evidence": json.loads(row["evidence_json"]),
            }
        )
    snapshot = {
        "captured_at": captured_at,
        "preserved_before_action": True,
        "original_evidence_preserved": True,
        "incident": {
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "severity": incident["severity"],
            "confidence": incident["confidence"],
            "risk_score": incident["risk_score"],
            "status": incident["status"],
        },
        "proposed_action": {
            "phase": phase,
            "action_type": action_type,
            "target_type": target_type,
            "target_value": target_value,
        },
        "evidence": evidence,
    }
    payload = canonical_json(snapshot)
    return payload, sha256_text(payload)


def append_lifecycle_records(
    connection: sqlite3.Connection,
    *,
    incident: sqlite3.Row,
    actor: str,
    role: str,
    new_status: str,
    notes: str,
    decision: str,
    evidence_references: list[str],
    request_id: str,
) -> None:
    """Store one evidence-backed lifecycle transition."""
    previous_status = incident["status"]
    now = utc_now()
    key = stable_key("v2-stage13-transition", incident["incident_id"], request_id)
    references = canonical_json(evidence_references)
    entry = {
        "decision_key": key,
        "event_time": now,
        "actor": actor,
        "actor_role": role,
        "notes": notes,
        "decision": decision,
        "previous_status": previous_status,
        "new_status": new_status,
    }
    histories = connection.execute(
        """
        SELECT investigation_notes, analyst_decisions
        FROM v2_incidents
        WHERE incident_id = ?
        """,
        (incident["incident_id"],),
    ).fetchone()
    if histories is None:
        raise RecoveryError("Incident history is unavailable")
    note_history = json.loads(histories["investigation_notes"])
    decision_history = json.loads(histories["analyst_decisions"])
    note_history.append(entry)
    decision_history.append(entry)
    connection.execute(
        """
        UPDATE v2_incidents
        SET status = ?, updated_at = ?, investigation_notes = ?,
            analyst_decisions = ?
        WHERE incident_id = ?
        """,
        (
            new_status,
            now,
            canonical_json(note_history),
            canonical_json(decision_history),
            incident["incident_id"],
        ),
    )
    connection.execute(
        """
        INSERT INTO v2_incident_decisions (
            decision_key, incident_id, decision_time, actor, actor_role,
            decision, notes, previous_status, new_status,
            evidence_references
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            incident["incident_id"],
            now,
            actor,
            role,
            decision,
            notes,
            previous_status,
            new_status,
            references,
        ),
    )
    connection.execute(
        """
        INSERT INTO v2_incident_timeline (
            timeline_key, incident_id, event_time, event_type, actor,
            action, previous_status, new_status, details,
            evidence_references
        ) VALUES (?, ?, ?, 'status_changed', ?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            incident["incident_id"],
            now,
            actor,
            "manage_v2_stage13_recovery",
            previous_status,
            new_status,
            canonical_json({"notes": notes, "decision": decision}),
            references,
        ),
    )


def confirm_containment(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    actor: str,
    notes: str,
    request_id: str,
) -> dict[str, Any]:
    """Move Investigating to Contained only when a live action succeeded."""
    validate_safety(configuration)
    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            role = require_permission(
                connection,
                rbac,
                actor,
                configuration["permissions"]["perform_recovery"],
            )
            incident = load_incident(connection, incident_id)
            key = stable_key("v2-stage13-transition", incident_id, request_id)
            existing = connection.execute(
                "SELECT new_status FROM v2_incident_decisions WHERE decision_key = ?",
                (key,),
            ).fetchone()
            if existing:
                return {"incident_id": incident_id, "status": existing[0], "new": False}
            if incident["status"] != "Investigating":
                raise RecoveryError("Containment confirmation requires Investigating status")
            containment = connection.execute(
                """
                SELECT containment_action_id
                FROM v2_containment_actions
                WHERE incident_id = ? AND status = 'successful'
                ORDER BY containment_action_id
                LIMIT 1
                """,
                (incident_id,),
            ).fetchone()
            if containment is None:
                raise RecoveryError("No successful active containment action exists")
            references = clean_references(
                [
                    row[0]
                    for row in connection.execute(
                        "SELECT evidence_reference FROM v2_incident_evidence WHERE incident_id = ?",
                        (incident_id,),
                    )
                ]
            )
            append_lifecycle_records(
                connection,
                incident=incident,
                actor=actor,
                role=role,
                new_status="Contained",
                notes=clean_text(notes, "notes"),
                decision="Confirm successful evidence-backed containment",
                evidence_references=references,
                request_id=request_id,
            )
        audit(database_path, actor, "confirm_v2_stage13_containment", incident_id, "success", "status=Contained")
        return {"incident_id": incident_id, "status": "Contained", "new": True}
    except (PermissionError, ValueError, RecoveryError) as error:
        audit(database_path, actor, "confirm_v2_stage13_containment", incident_id, "denied", str(error))
        raise


def request_action(
    database_path: Path,
    configuration: dict[str, Any],
    acl: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    action_type: str,
    target_type: str,
    target_value: str,
    requested_by: str,
    request_reason: str,
    evidence_references: list[str],
    request_id: str,
) -> dict[str, Any]:
    """Request an evidence-backed simulated eradication or recovery action."""
    validate_safety(configuration)
    if action_type not in configuration["actions"]:
        error = RecoveryError(f"Undefined Stage 13 action denied: {action_type}")
        audit(database_path, requested_by, "request_v2_stage13_action", incident_id, "denied", str(error))
        raise error
    policy = configuration["actions"][action_type]
    if target_type != policy["target_type"]:
        raise RecoveryError("Target type does not match the action configuration")
    references = clean_references(evidence_references)
    if not references:
        raise RecoveryError("At least one evidence reference is required")
    control = action_control_level(acl, action_type)
    if control == "denied":
        raise RecoveryError(f"Undefined Stage 13 action denied: {action_type}")
    action_key = stable_key("v2-recovery-action", request_id)
    now = utc_now()
    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            require_permission(
                connection,
                rbac,
                requested_by,
                configuration["permissions"]["perform_recovery"],
            )
            existing = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE action_key = ?",
                (action_key,),
            ).fetchone()
            if existing:
                if (
                    existing["incident_id"] != incident_id
                    or existing["action_type"] != action_type
                    or existing["target_type"] != target_type
                    or existing["target_value"] != target_value
                ):
                    raise RecoveryError("Request ID already belongs to another action")
                return action_result(existing)
            incident = load_incident(connection, incident_id)
            required_status = "Contained" if policy["phase"] == "eradication" else "Eradicated"
            if incident["status"] != required_status:
                raise RecoveryError(
                    f"{policy['phase'].title()} action requires {required_status} status"
                )
            rows = load_incident_evidence(connection, incident_id, references)
            payload, digest = evidence_snapshot(
                incident,
                rows,
                policy["phase"],
                action_type,
                target_type,
                clean_text(target_value, "target_value"),
                now,
            )
            automatic = control == "automatic"
            status = "successful" if automatic else "requested"
            details = (
                canonical_json(
                    {
                        "outcome": "simulated_success",
                        "simulation_only": True,
                        "real_action_executed": False,
                    }
                )
                if automatic
                else None
            )
            cursor = connection.execute(
                """
                INSERT INTO v2_recovery_actions (
                    action_key, request_id, incident_id, phase, action_type,
                    target_type, target_value, control_level, disruptive,
                    requested_by, requested_at, request_reason, status,
                    evidence_preserved, evidence_snapshot_sha256,
                    evidence_references, executed_by, executed_at,
                    result_details, simulation_only, real_action_executed,
                    external_target_used, original_evidence_preserved,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 1, 0, 0, 1, ?, ?)
                """,
                (
                    action_key,
                    request_id,
                    incident_id,
                    policy["phase"],
                    action_type,
                    target_type,
                    target_value,
                    control,
                    int(policy["disruptive"]),
                    requested_by,
                    now,
                    clean_text(request_reason, "request_reason"),
                    status,
                    digest,
                    canonical_json(references),
                    requested_by if automatic else None,
                    now if automatic else None,
                    details,
                    now,
                    now,
                ),
            )
            action_id = cursor.lastrowid
            connection.execute(
                """
                INSERT INTO v2_recovery_evidence (
                    evidence_snapshot_key, recovery_action_id, incident_id,
                    captured_at, captured_by, evidence_references,
                    evidence_payload, evidence_sha256, hash_algorithm,
                    preserved_before_action, original_evidence_preserved
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sha256', 1, 1)
                """,
                (
                    stable_key("v2-recovery-evidence", action_key, digest),
                    action_id,
                    incident_id,
                    now,
                    requested_by,
                    canonical_json(references),
                    payload,
                    digest,
                ),
            )
            if not automatic:
                connection.execute(
                    """
                    INSERT INTO v2_recovery_approvals (
                        approval_key, recovery_action_id, incident_id,
                        requested_by, requested_at, decision_status,
                        self_approval_blocked, action_occurred,
                        evidence_references
                    ) VALUES (?, ?, ?, ?, ?, 'requested', 0, 0, ?)
                    """,
                    (
                        stable_key("v2-recovery-approval", action_key),
                        action_id,
                        incident_id,
                        requested_by,
                        now,
                        canonical_json(references),
                    ),
                )
            result_row = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE recovery_action_id = ?",
                (action_id,),
            ).fetchone()
        audit(database_path, requested_by, "request_v2_stage13_action", f"recovery_action:{action_id}", "success", f"status={status} simulation_only=true")
        return action_result(result_row, new=True)
    except (PermissionError, ValueError, RecoveryError) as error:
        audit(database_path, requested_by, "request_v2_stage13_action", incident_id, "denied", str(error))
        raise


def decide_action(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    recovery_action_id: int,
    decided_by: str,
    decision: str,
    notes: str,
) -> dict[str, Any]:
    """Approve or deny a non-automatic Stage 13 action."""
    validate_safety(configuration)
    if decision not in {"approved", "denied"}:
        raise ValueError("Decision must be approved or denied")
    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            role = require_permission(connection, rbac, decided_by, configuration["permissions"]["perform_recovery"])
            row = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE recovery_action_id = ?",
                (recovery_action_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Unknown Stage 13 action")
            if row["control_level"] == "automatic":
                raise RecoveryError("Automatic action does not accept approval")
            if row["status"] in {"approved", "denied"}:
                return action_result(row)
            if row["status"] != "requested":
                raise RecoveryError("Only requested actions can be decided")
            if row["requested_by"] == decided_by:
                connection.execute(
                    "UPDATE v2_recovery_approvals SET self_approval_blocked = 1 WHERE recovery_action_id = ?",
                    (recovery_action_id,),
                )
                raise PermissionError("Requester cannot approve their own recovery action")
            if row["control_level"] == "manual_only" and role != "administrator":
                raise PermissionError("Manual-only action requires an administrator")
            now = utc_now()
            connection.execute(
                """
                UPDATE v2_recovery_actions
                SET status = ?, approved_by = CASE WHEN ? = 'approved' THEN ? END,
                    approved_at = CASE WHEN ? = 'approved' THEN ? END,
                    denied_by = CASE WHEN ? = 'denied' THEN ? END,
                    denied_at = CASE WHEN ? = 'denied' THEN ? END,
                    updated_at = ?
                WHERE recovery_action_id = ?
                """,
                (decision, decision, decided_by, decision, now, decision, decided_by, decision, now, now, recovery_action_id),
            )
            connection.execute(
                """
                UPDATE v2_recovery_approvals
                SET decided_by = ?, decided_at = ?, decision_status = ?,
                    decision_notes = ?, actor_role = ?
                WHERE recovery_action_id = ?
                """,
                (decided_by, now, decision, clean_text(notes, "notes"), role, recovery_action_id),
            )
            result = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE recovery_action_id = ?",
                (recovery_action_id,),
            ).fetchone()
        audit(database_path, decided_by, "decide_v2_stage13_action", f"recovery_action:{recovery_action_id}", "success", f"decision={decision}")
        return action_result(result)
    except (PermissionError, ValueError, RecoveryError) as error:
        if "own recovery action" in str(error):
            with managed_connection(database_path) as connection:
                connection.execute(
                    """
                    UPDATE v2_recovery_approvals
                    SET self_approval_blocked = 1
                    WHERE recovery_action_id = ?
                    """,
                    (recovery_action_id,),
                )
        audit(database_path, decided_by, "decide_v2_stage13_action", f"recovery_action:{recovery_action_id}", "denied", str(error))
        raise


def execute_action(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    recovery_action_id: int,
    executed_by: str,
    outcome: str = "successful",
    details: str = "Simulated Stage 13 action completed.",
) -> dict[str, Any]:
    """Record a separately authorised simulated action result."""
    validate_safety(configuration)
    if outcome not in {"successful", "failed"}:
        raise ValueError("Outcome must be successful or failed")
    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            role = require_permission(connection, rbac, executed_by, configuration["permissions"]["perform_recovery"])
            row = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE recovery_action_id = ?",
                (recovery_action_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Unknown Stage 13 action")
            if row["status"] in {"successful", "failed"}:
                return action_result(row)
            if row["status"] != "approved":
                raise RecoveryError("Action must be approved before execution")
            if row["requested_by"] == executed_by:
                raise PermissionError("Requester cannot execute their own recovery action")
            if row["control_level"] == "manual_only" and role != "administrator":
                raise PermissionError("Manual-only action requires an administrator")
            evidence = connection.execute(
                "SELECT evidence_payload, evidence_sha256 FROM v2_recovery_evidence WHERE recovery_action_id = ?",
                (recovery_action_id,),
            ).fetchone()
            if evidence is None or sha256_text(evidence["evidence_payload"]) != evidence["evidence_sha256"]:
                raise RecoveryError("Preserved evidence is missing or has changed")
            now = utc_now()
            result_details = canonical_json(
                {
                    "details": clean_text(details, "details"),
                    "outcome": f"simulated_{outcome}",
                    "simulation_only": True,
                    "real_action_executed": False,
                    "external_target_used": False,
                }
            )
            connection.execute(
                """
                UPDATE v2_recovery_actions
                SET status = ?, executed_by = ?, executed_at = ?,
                    result_details = ?, updated_at = ?
                WHERE recovery_action_id = ?
                """,
                (outcome, executed_by, now, result_details, now, recovery_action_id),
            )
            connection.execute(
                "UPDATE v2_recovery_approvals SET action_occurred = ? WHERE recovery_action_id = ?",
                (int(outcome == "successful"), recovery_action_id),
            )
            result = connection.execute(
                "SELECT * FROM v2_recovery_actions WHERE recovery_action_id = ?",
                (recovery_action_id,),
            ).fetchone()
        audit(database_path, executed_by, "execute_v2_stage13_action", f"recovery_action:{recovery_action_id}", outcome, "simulation_only=true real_action_executed=false")
        return action_result(result)
    except (PermissionError, ValueError, RecoveryError) as error:
        audit(database_path, executed_by, "execute_v2_stage13_action", f"recovery_action:{recovery_action_id}", "denied", str(error))
        raise


def complete_eradication(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    actor: str,
    notes: str,
    request_id: str,
) -> dict[str, Any]:
    """Move Contained to Eradicated after successful eradication work."""
    return _complete_phase(
        database_path,
        configuration,
        rbac,
        incident_id=incident_id,
        actor=actor,
        notes=notes,
        request_id=request_id,
        phase="eradication",
        previous_status="Contained",
        new_status="Eradicated",
    )


def _complete_phase(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    actor: str,
    notes: str,
    request_id: str,
    phase: str,
    previous_status: str,
    new_status: str,
) -> dict[str, Any]:
    """Complete one lifecycle phase after verifying stored work."""
    validate_safety(configuration)
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        role = require_permission(connection, rbac, actor, configuration["permissions"]["perform_recovery"])
        incident = load_incident(connection, incident_id)
        key = stable_key("v2-stage13-transition", incident_id, request_id)
        existing = connection.execute(
            "SELECT new_status FROM v2_incident_decisions WHERE decision_key = ?",
            (key,),
        ).fetchone()
        if existing:
            return {"incident_id": incident_id, "status": existing[0], "new": False}
        if incident["status"] != previous_status:
            raise RecoveryError(f"{phase.title()} completion requires {previous_status} status")
        successful = connection.execute(
            "SELECT COUNT(*) FROM v2_recovery_actions WHERE incident_id = ? AND phase = ? AND status = 'successful'",
            (incident_id, phase),
        ).fetchone()[0]
        if successful == 0:
            raise RecoveryError(f"No successful {phase} action is recorded")
        references = clean_references(
            [
                row[0]
                for row in connection.execute(
                    "SELECT evidence_references FROM v2_recovery_actions WHERE incident_id = ? AND phase = ? AND status = 'successful'",
                    (incident_id, phase),
                )
                for item in json.loads(row[0])
            ]
        )
        append_lifecycle_records(
            connection,
            incident=incident,
            actor=actor,
            role=role,
            new_status=new_status,
            notes=clean_text(notes, "notes"),
            decision=f"Confirm successful simulated {phase}",
            evidence_references=references,
            request_id=request_id,
        )
    audit(database_path, actor, f"complete_v2_stage13_{phase}", incident_id, "success", f"status={new_status}")
    return {"incident_id": incident_id, "status": new_status, "new": True}


def record_retest(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    retest_type: str,
    target_type: str,
    target_value: str,
    description: str,
    observed_result: str,
    evidence_references: list[str],
    tested_by: str,
    request_id: str,
) -> dict[str, Any]:
    """Record a duplicate-safe retest of the original threat or finding."""
    validate_safety(configuration)
    if retest_type not in {"original_threat", "original_vulnerability"}:
        raise ValueError("Unsupported retest type")
    if observed_result not in {"blocked", "succeeded", "error"}:
        raise ValueError("Unsupported observed result")
    references = clean_references(evidence_references)
    if not references:
        raise RecoveryError("Retest evidence is required")
    key = stable_key("v2-recovery-retest", request_id)
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        require_permission(connection, rbac, tested_by, configuration["permissions"]["perform_recovery"])
        existing = connection.execute(
            "SELECT * FROM v2_recovery_retests WHERE retest_key = ?",
            (key,),
        ).fetchone()
        if existing:
            return {"recovery_retest_id": existing["recovery_retest_id"], "verification_status": existing["verification_status"], "new": False}
        incident = load_incident(connection, incident_id)
        if incident["status"] != "Eradicated":
            raise RecoveryError("Retesting requires Eradicated status")
        recovery_count = connection.execute(
            "SELECT COUNT(*) FROM v2_recovery_actions WHERE incident_id = ? AND phase = 'recovery' AND status = 'successful'",
            (incident_id,),
        ).fetchone()[0]
        if recovery_count == 0:
            raise RecoveryError("Recovery actions must succeed before retesting")
        load_incident_evidence(connection, incident_id, references)
        passed = observed_result == configuration["verification"]["successful_result"]
        now = utc_now()
        verification_status = "passed" if passed else "failed"
        payload = canonical_json(
            {
                "incident_id": incident_id,
                "retest_type": retest_type,
                "target_type": target_type,
                "target_value": target_value,
                "description": description,
                "observed_result": observed_result,
                "evidence_references": references,
            }
        )
        cursor = connection.execute(
            """
            INSERT INTO v2_recovery_retests (
                retest_key, incident_id, retest_type, target_type,
                target_value, test_description, expected_result,
                observed_result, verification_status,
                confirmed_no_longer_succeeds, evidence_references,
                evidence_sha256, tested_by, tested_at,
                simulation_only, real_action_executed
            ) VALUES (?, ?, ?, ?, ?, ?, 'blocked', ?, ?, ?, ?, ?, ?, ?, 1, 0)
            """,
            (
                key,
                incident_id,
                retest_type,
                clean_text(target_type, "target_type"),
                clean_text(target_value, "target_value"),
                clean_text(description, "description"),
                observed_result,
                verification_status,
                int(passed),
                canonical_json(references),
                sha256_text(payload),
                tested_by,
                now,
            ),
        )
        retest_id = cursor.lastrowid
    audit(database_path, tested_by, "record_v2_stage13_retest", incident_id, verification_status, f"retest_type={retest_type} observed_result={observed_result}")
    return {"recovery_retest_id": retest_id, "verification_status": verification_status, "new": True}


def complete_recovery(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    actor: str,
    notes: str,
    request_id: str,
) -> dict[str, Any]:
    """Move Eradicated to Recovered only after successful retesting."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT retest_type, verification_status FROM v2_recovery_retests WHERE incident_id = ?",
            (incident_id,),
        ).fetchall()
        passed = {row["retest_type"] for row in rows if row["verification_status"] == "passed"}
        if passed != {"original_threat", "original_vulnerability"}:
            raise RecoveryError("Both original threat and vulnerability retests must pass")
        monitoring = connection.execute(
            "SELECT COUNT(*) FROM v2_recovery_actions WHERE incident_id = ? AND action_type = 'increase_post_recovery_monitoring' AND status = 'successful'",
            (incident_id,),
        ).fetchone()[0]
        if monitoring == 0:
            raise RecoveryError("Post-recovery monitoring must be active")
    return _complete_phase(
        database_path,
        configuration,
        rbac,
        incident_id=incident_id,
        actor=actor,
        notes=notes,
        request_id=request_id,
        phase="recovery",
        previous_status="Eradicated",
        new_status="Recovered",
    )


def close_after_review(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    incident_id: str,
    actor: str,
    lessons_learned: str,
    detection_improvements: str,
    policy_improvements: str,
    closure_reason: str,
    request_id: str,
) -> dict[str, Any]:
    """Complete review and close only a fully verified recovered incident."""
    validate_safety(configuration)
    fields = {
        "lessons_learned": lessons_learned,
        "detection_improvements": detection_improvements,
        "policy_improvements": policy_improvements,
        "closure_reason": closure_reason,
    }
    fields = {name: clean_text(value, name) for name, value in fields.items()}
    key = stable_key("v2-post-incident-review", incident_id)
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        role = require_permission(connection, rbac, actor, configuration["permissions"]["close_incident"])
        incident = load_incident(connection, incident_id)
        existing = connection.execute(
            "SELECT * FROM v2_post_incident_reviews WHERE review_key = ?",
            (key,),
        ).fetchone()
        if existing:
            return {"incident_id": incident_id, "status": "Closed", "new": False}
        if incident["status"] != "Recovered":
            raise RecoveryError("Verified closure requires Recovered status")
        retests = connection.execute(
            "SELECT retest_type, verification_status FROM v2_recovery_retests WHERE incident_id = ?",
            (incident_id,),
        ).fetchall()
        passed = {row["retest_type"] for row in retests if row["verification_status"] == "passed"}
        if passed != {"original_threat", "original_vulnerability"}:
            raise RecoveryError("Required verification is incomplete")
        monitoring = connection.execute(
            "SELECT COUNT(*) FROM v2_recovery_actions WHERE incident_id = ? AND action_type = 'increase_post_recovery_monitoring' AND status = 'successful'",
            (incident_id,),
        ).fetchone()[0]
        if monitoring == 0:
            raise RecoveryError("Post-recovery monitoring is not active")
        references = clean_references(
            [
                row[0]
                for row in connection.execute(
                    "SELECT evidence_reference FROM v2_incident_evidence WHERE incident_id = ?",
                    (incident_id,),
                )
            ]
        )
        now = utc_now()
        connection.execute(
            """
            INSERT INTO v2_post_incident_reviews (
                review_key, incident_id, review_status, reviewed_by,
                started_at, completed_at, lessons_learned,
                detection_improvements, policy_improvements,
                closure_reason, eradication_verified, recovery_verified,
                original_threat_blocked, original_vulnerability_blocked,
                post_recovery_monitoring_active, closure_authorised,
                closure_actor, closed_at, evidence_references,
                original_evidence_preserved
            ) VALUES (?, ?, 'complete', ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1, 1, ?, ?, ?, 1)
            """,
            (
                key,
                incident_id,
                actor,
                now,
                now,
                fields["lessons_learned"],
                fields["detection_improvements"],
                fields["policy_improvements"],
                fields["closure_reason"],
                actor,
                now,
                canonical_json(references),
            ),
        )
        connection.execute(
            """
            UPDATE v2_incidents
            SET closure_reason = ?, closed_at = ?
            WHERE incident_id = ?
            """,
            (fields["closure_reason"], now, incident_id),
        )
        append_lifecycle_records(
            connection,
            incident=incident,
            actor=actor,
            role=role,
            new_status="Closed",
            notes="Post-incident review completed after successful verification.",
            decision="Close incident after verified eradication and recovery",
            evidence_references=references,
            request_id=request_id,
        )
    audit(database_path, actor, "close_v2_stage13_incident", incident_id, "success", "status=Closed verification=passed")
    return {"incident_id": incident_id, "status": "Closed", "new": True}
