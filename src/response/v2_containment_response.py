"""Approval-controlled simulated containment for Phase 3A V2 Stage 12."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.database import record_audit_event
from src.utils.security_controls import action_control_level, role_has_permission
from src.utils.sqlite_connection import managed_connection


class ContainmentError(RuntimeError):
    """Raised when a containment operation cannot be completed safely."""


def utc_now() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    """Serialise a value deterministically for storage and hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def stable_key(prefix: str, *parts: object) -> str:
    """Create a deterministic SHA-256-backed record key."""
    payload = "\x1f".join(str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def sha256_text(value: str) -> str:
    """Return the SHA-256 digest of UTF-8 text."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clean_text(value: str, field_name: str) -> str:
    """Return non-empty trimmed text."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    return cleaned


def clean_references(references: list[str]) -> list[str]:
    """Return unique, non-empty evidence references in stable order."""
    cleaned = {
        reference.strip()
        for reference in references
        if isinstance(reference, str) and reference.strip()
    }
    return sorted(cleaned)


def load_active_role(
    connection: sqlite3.Connection,
    actor: str,
) -> str | None:
    """Return an actor's active NetShield role."""
    row = connection.execute(
        """
        SELECT role
        FROM user_roles
        WHERE username = ?
          AND active = 1
        """,
        (actor,),
    ).fetchone()
    return row[0] if row else None


def require_permission(
    connection: sqlite3.Connection,
    rbac: dict[str, Any],
    actor: str,
    permission: str,
) -> str:
    """Require an active role containing the requested permission."""
    role = load_active_role(connection, actor)
    if role is None:
        raise PermissionError(f"Actor has no active role: {actor}")
    if not role_has_permission(rbac, role, permission):
        raise PermissionError(
            f"Actor lacks required permission: {permission}"
        )
    return role


def validate_safety_configuration(configuration: dict[str, Any]) -> None:
    """Fail closed if Stage 12 safety boundaries are weakened."""
    checks = (
        (configuration.get("stage") == 12, "Invalid Stage 12 number"),
        (
            configuration.get("environment") == "sandbox",
            "Containment environment must be sandbox",
        ),
        (
            configuration.get("simulation_only") is True,
            "Containment must remain simulation-only",
        ),
        (
            configuration.get("allow_real_actions") is False,
            "Real containment actions must remain disabled",
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
            "Stage 12 evidence must use SHA-256",
        ),
    )
    for condition, message in checks:
        if not condition:
            raise ContainmentError(message)


def audit_result(
    database_path: Path,
    actor: str,
    action: str,
    target: str,
    result: str,
    details: str,
) -> None:
    """Record a Stage 12 operation in the existing audit trail."""
    record_audit_event(
        database_path=database_path,
        actor=actor,
        action=action,
        target=target,
        result=result,
        details=details,
    )


def load_incident(
    connection: sqlite3.Connection,
    incident_id: str,
) -> sqlite3.Row:
    """Load one managed incident."""
    row = connection.execute(
        """
        SELECT
            incident_id,
            title,
            severity,
            confidence,
            risk_score,
            incident_owner,
            status,
            identity_context,
            device_context,
            asset_context,
            network_context,
            source_first_evidence_time,
            source_last_evidence_time
        FROM v2_incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Incident does not exist: {incident_id}")
    return row


def load_incident_evidence(
    connection: sqlite3.Connection,
    incident_id: str,
    evidence_references: list[str],
) -> list[sqlite3.Row]:
    """Load evidence owned by an incident using either stored reference."""
    placeholders = ",".join("?" for _ in evidence_references)
    rows = connection.execute(
        f"""
        SELECT
            source_type,
            source_record_id,
            source_evidence_key,
            evidence_time,
            relationship,
            contribution_status,
            evidence_reference,
            evidence_json,
            evidence_sha256
        FROM v2_incident_evidence
        WHERE incident_id = ?
          AND (
              evidence_reference IN ({placeholders})
              OR source_evidence_key IN ({placeholders})
          )
        ORDER BY evidence_time, source_type, source_record_id
        """,
        (
            incident_id,
            *evidence_references,
            *evidence_references,
        ),
    ).fetchall()

    matched = {
        value
        for row in rows
        for value in (
            row["evidence_reference"],
            row["source_evidence_key"],
        )
        if value in evidence_references
    }
    missing = sorted(set(evidence_references) - matched)
    if missing:
        raise ValueError(
            "Evidence does not belong to the incident: "
            + ", ".join(missing)
        )
    return rows


def build_evidence_snapshot(
    incident: sqlite3.Row,
    evidence_rows: list[sqlite3.Row],
    action_type: str,
    target_type: str,
    target_value: str,
    captured_at: str,
) -> tuple[str, str]:
    """Build and hash the evidence snapshot taken before containment."""
    evidence = []
    for row in evidence_rows:
        try:
            evidence_json = json.loads(row["evidence_json"])
        except json.JSONDecodeError as error:
            raise ContainmentError(
                "Stored incident evidence contains invalid JSON"
            ) from error
        evidence.append(
            {
                "source_type": row["source_type"],
                "source_record_id": row["source_record_id"],
                "source_evidence_key": row["source_evidence_key"],
                "evidence_time": row["evidence_time"],
                "relationship": row["relationship"],
                "contribution_status": row["contribution_status"],
                "evidence_reference": row["evidence_reference"],
                "evidence_sha256": row["evidence_sha256"],
                "evidence": evidence_json,
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
            "incident_owner": incident["incident_owner"],
            "status": incident["status"],
            "identity_context": json.loads(
                incident["identity_context"]
            ),
            "device_context": json.loads(
                incident["device_context"]
            ),
            "asset_context": json.loads(incident["asset_context"]),
            "network_context": json.loads(
                incident["network_context"]
            ),
            "source_first_evidence_time": incident[
                "source_first_evidence_time"
            ],
            "source_last_evidence_time": incident[
                "source_last_evidence_time"
            ],
        },
        "proposed_action": {
            "action_type": action_type,
            "target_type": target_type,
            "target_value": target_value,
        },
        "evidence": evidence,
    }
    payload = canonical_json(snapshot)
    return payload, sha256_text(payload)


def existing_action_result(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a stored containment action into a public result."""
    return {
        "containment_action_id": row["containment_action_id"],
        "action_key": row["action_key"],
        "incident_id": row["incident_id"],
        "action_type": row["action_type"],
        "target_type": row["target_type"],
        "target_value": row["target_value"],
        "control_level": row["control_level"],
        "status": row["status"],
        "requested_by": row["requested_by"],
        "approved_by": row["approved_by"],
        "executed_by": row["executed_by"],
        "evidence_preserved": bool(row["evidence_preserved"]),
        "evidence_snapshot_sha256": row[
            "evidence_snapshot_sha256"
        ],
        "rollback_supported": bool(row["rollback_supported"]),
        "rollback_action": row["rollback_action"],
        "simulation_only": bool(row["simulation_only"]),
        "real_action_executed": bool(row["real_action_executed"]),
        "new": False,
    }


def simulated_result(
    action_type: str,
    target_type: str,
    target_value: str,
) -> str:
    """Describe the local state change without claiming a real action."""
    return canonical_json(
        {
            "action_type": action_type,
            "target_type": target_type,
            "target_value": target_value,
            "outcome": "simulated_success",
            "simulation_only": True,
            "real_action_executed": False,
            "external_target_used": False,
        }
    )


def request_action(
    database_path: Path,
    configuration: dict[str, Any],
    automation_acl: dict[str, Any],
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
    """Request containment and execute only ACL-defined automatic actions."""
    validate_safety_configuration(configuration)
    incident_id = clean_text(incident_id, "incident_id")
    action_type = clean_text(action_type, "action_type")
    target_type = clean_text(target_type, "target_type")
    target_value = clean_text(target_value, "target_value")
    requested_by = clean_text(requested_by, "requested_by")
    request_reason = clean_text(request_reason, "request_reason")
    request_id = clean_text(request_id, "request_id")
    references = clean_references(evidence_references)

    policy = configuration["actions"].get(action_type)
    acl_level = action_control_level(automation_acl, action_type)
    if policy is None or acl_level == "deny":
        audit_result(
            database_path,
            requested_by,
            "request_v2_stage12_containment",
            f"{incident_id}:{action_type}",
            "denied",
            "undefined_action=true default_action=deny",
        )
        raise PermissionError(
            f"Undefined containment action denied: {action_type}"
        )
    if acl_level != policy["control_level"]:
        raise ContainmentError(
            f"ACL control mismatch for action: {action_type}"
        )
    if target_type != policy["target_type"]:
        raise ValueError(
            f"Action {action_type} requires target type "
            f"{policy['target_type']}"
        )
    minimum = configuration["evidence_policy"][
        "minimum_evidence_references"
    ]
    if len(references) < minimum:
        raise ValueError(
            f"At least {minimum} evidence reference is required"
        )

    requested_at = utc_now()
    action_key = stable_key("v2-containment-action", request_id)

    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            requester_role = require_permission(
                connection,
                rbac,
                requested_by,
                configuration["permissions"]["request"],
            )
            existing = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE action_key = ?
                """,
                (action_key,),
            ).fetchone()
            if existing is not None:
                expected = (
                    incident_id,
                    action_type,
                    target_type,
                    target_value,
                    requested_by,
                )
                actual = (
                    existing["incident_id"],
                    existing["action_type"],
                    existing["target_type"],
                    existing["target_value"],
                    existing["requested_by"],
                )
                if actual != expected:
                    raise ContainmentError(
                        "request_id is already used for another request"
                    )
                return existing_action_result(existing)

            incident = load_incident(connection, incident_id)
            evidence_rows = load_incident_evidence(
                connection,
                incident_id,
                references,
            )
            snapshot_payload, snapshot_sha256 = (
                build_evidence_snapshot(
                    incident,
                    evidence_rows,
                    action_type,
                    target_type,
                    target_value,
                    requested_at,
                )
            )

            cursor = connection.execute(
                """
                INSERT INTO v2_containment_actions (
                    action_key,
                    incident_id,
                    action_type,
                    target_type,
                    target_value,
                    control_level,
                    requested_by,
                    requested_at,
                    request_reason,
                    status,
                    evidence_preserved,
                    evidence_snapshot_sha256,
                    evidence_references,
                    executed_by,
                    executed_at,
                    result_details,
                    rollback_supported,
                    rollback_action,
                    simulation_only,
                    real_action_executed,
                    external_target_used,
                    original_evidence_preserved,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?,
                    ?, ?, 1, 0, 0, 1, ?, ?
                )
                """,
                (
                    action_key,
                    incident_id,
                    action_type,
                    target_type,
                    target_value,
                    acl_level,
                    requested_by,
                    requested_at,
                    request_reason,
                    "requested",
                    snapshot_sha256,
                    canonical_json(references),
                    None,
                    None,
                    None,
                    int(policy["rollback_supported"]),
                    policy["rollback_action"],
                    requested_at,
                    requested_at,
                ),
            )
            action_id = cursor.lastrowid
            snapshot_key = stable_key(
                "v2-containment-evidence",
                action_key,
                snapshot_sha256,
            )
            connection.execute(
                """
                INSERT INTO v2_containment_evidence (
                    evidence_snapshot_key,
                    containment_action_id,
                    incident_id,
                    captured_at,
                    captured_by,
                    evidence_references,
                    evidence_payload,
                    evidence_sha256,
                    hash_algorithm,
                    preserved_before_action,
                    original_evidence_preserved
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sha256', 1, 1)
                """,
                (
                    snapshot_key,
                    action_id,
                    incident_id,
                    requested_at,
                    requested_by,
                    canonical_json(references),
                    snapshot_payload,
                    snapshot_sha256,
                ),
            )

            if acl_level == "automatic":
                connection.execute(
                    """
                    UPDATE v2_containment_actions
                    SET status = 'successful',
                        executed_by = ?,
                        executed_at = ?,
                        result_details = ?,
                        updated_at = ?
                    WHERE containment_action_id = ?
                      AND evidence_preserved = 1
                    """,
                    (
                        requested_by,
                        requested_at,
                        simulated_result(
                            action_type,
                            target_type,
                            target_value,
                        ),
                        requested_at,
                        action_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE v2_containment_actions
                    SET status = 'approval_required',
                        updated_at = ?
                    WHERE containment_action_id = ?
                      AND evidence_preserved = 1
                    """,
                    (requested_at, action_id),
                )
                approval_key = stable_key(
                    "v2-containment-approval",
                    action_key,
                )
                connection.execute(
                    """
                    INSERT INTO v2_containment_approvals (
                        approval_key,
                        containment_action_id,
                        incident_id,
                        requested_by,
                        requested_at,
                        decision_status,
                        self_approval_blocked,
                        actor_role,
                        action_occurred,
                        evidence_references
                    )
                    VALUES (?, ?, ?, ?, ?, 'approval_required', 0, ?, 0, ?)
                    """,
                    (
                        approval_key,
                        action_id,
                        incident_id,
                        requested_by,
                        requested_at,
                        requester_role,
                        canonical_json(references),
                    ),
                )

            stored = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE containment_action_id = ?
                """,
                (action_id,),
            ).fetchone()
    except PermissionError as error:
        audit_result(
            database_path,
            requested_by,
            "request_v2_stage12_containment",
            f"{incident_id}:{action_type}",
            "denied",
            str(error),
        )
        raise

    result = existing_action_result(stored)
    result["new"] = True
    audit_result(
        database_path,
        requested_by,
        "request_v2_stage12_containment",
        f"containment_action:{result['containment_action_id']}",
        "success",
        (
            f"incident_id={incident_id} action={action_type} "
            f"control_level={acl_level} status={result['status']} "
            "evidence_preserved=true simulation_only=true "
            "real_action_executed=false"
        ),
    )
    return result


def decide_action(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    containment_action_id: int,
    decided_by: str,
    decision: str,
    notes: str,
) -> dict[str, Any]:
    """Approve or deny a pending disruptive containment request."""
    validate_safety_configuration(configuration)
    decided_by = clean_text(decided_by, "decided_by")
    notes = clean_text(notes, "decision notes")
    decision = decision.strip().lower()
    if decision not in {"approved", "denied"}:
        raise ValueError("Decision must be approved or denied")
    decided_at = utc_now()

    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            role = require_permission(
                connection,
                rbac,
                decided_by,
                configuration["permissions"]["approve_and_execute"],
            )
            action = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE containment_action_id = ?
                """,
                (containment_action_id,),
            ).fetchone()
            if action is None:
                raise ValueError(
                    f"Containment action does not exist: "
                    f"{containment_action_id}"
                )
            if action["control_level"] != "approval_required":
                raise ValueError(
                    "Automatic containment does not accept approval"
                )
            if action["status"] != "approval_required":
                raise ValueError(
                    "Containment action is not awaiting approval: "
                    f"{action['status']}"
                )
            if (
                configuration["approval_policy"][
                    "requester_cannot_approve_own_request"
                ]
                and action["requested_by"] == decided_by
            ):
                raise PermissionError(
                    "Requester cannot approve their own containment request"
                )

            connection.execute(
                """
                UPDATE v2_containment_approvals
                SET decided_by = ?,
                    decided_at = ?,
                    decision_status = ?,
                    decision_notes = ?,
                    actor_role = ?,
                    action_occurred = 0
                WHERE containment_action_id = ?
                  AND decision_status = 'approval_required'
                """,
                (
                    decided_by,
                    decided_at,
                    decision,
                    notes,
                    role,
                    containment_action_id,
                ),
            )
            if decision == "approved":
                connection.execute(
                    """
                    UPDATE v2_containment_actions
                    SET status = 'approved',
                        approved_by = ?,
                        approved_at = ?,
                        updated_at = ?
                    WHERE containment_action_id = ?
                    """,
                    (
                        decided_by,
                        decided_at,
                        decided_at,
                        containment_action_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE v2_containment_actions
                    SET status = 'denied',
                        denied_by = ?,
                        denied_at = ?,
                        result_details = ?,
                        updated_at = ?
                    WHERE containment_action_id = ?
                    """,
                    (
                        decided_by,
                        decided_at,
                        canonical_json(
                            {
                                "outcome": "denied",
                                "notes": notes,
                                "action_occurred": False,
                            }
                        ),
                        decided_at,
                        containment_action_id,
                    ),
                )
            updated = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE containment_action_id = ?
                """,
                (containment_action_id,),
            ).fetchone()
    except PermissionError as error:
        if "own containment request" in str(error):
            with managed_connection(database_path) as connection:
                connection.execute(
                    """
                    UPDATE v2_containment_approvals
                    SET self_approval_blocked = 1
                    WHERE containment_action_id = ?
                      AND requested_by = ?
                    """,
                    (containment_action_id, decided_by),
                )
        audit_result(
            database_path,
            decided_by,
            "decide_v2_stage12_containment",
            f"containment_action:{containment_action_id}",
            "denied",
            str(error),
        )
        raise

    result = existing_action_result(updated)
    audit_result(
        database_path,
        decided_by,
        "decide_v2_stage12_containment",
        f"containment_action:{containment_action_id}",
        "success" if decision == "approved" else "denied",
        (
            f"decision={decision} actor_role={role} "
            "action_occurred=false simulation_only=true"
        ),
    )
    return result


def execute_action(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    containment_action_id: int,
    executed_by: str,
    simulate_failure: bool = False,
) -> dict[str, Any]:
    """Execute an approved action as a local simulated state change."""
    validate_safety_configuration(configuration)
    executed_by = clean_text(executed_by, "executed_by")
    executed_at = utc_now()

    try:
        with managed_connection(database_path) as connection:
            connection.row_factory = sqlite3.Row
            role = require_permission(
                connection,
                rbac,
                executed_by,
                configuration["permissions"]["approve_and_execute"],
            )
            action = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE containment_action_id = ?
                """,
                (containment_action_id,),
            ).fetchone()
            if action is None:
                raise ValueError(
                    f"Containment action does not exist: "
                    f"{containment_action_id}"
                )
            if action["status"] in {
                "successful",
                "failed",
                "rolled_back",
                "rollback_failed",
            }:
                return existing_action_result(action)
            if action["status"] != "approved":
                raise PermissionError(
                    "Containment action has not been approved"
                )
            if (
                configuration["approval_policy"][
                    "requester_cannot_execute_own_request"
                ]
                and action["requested_by"] == executed_by
            ):
                raise PermissionError(
                    "Requester cannot execute their own containment request"
                )
            evidence_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM v2_containment_evidence
                WHERE containment_action_id = ?
                  AND preserved_before_action = 1
                  AND evidence_sha256 = ?
                """,
                (
                    containment_action_id,
                    action["evidence_snapshot_sha256"],
                ),
            ).fetchone()[0]
            if evidence_count != 1 or action["evidence_preserved"] != 1:
                raise ContainmentError(
                    "Preserved evidence is missing or does not match"
                )

            status = "failed" if simulate_failure else "successful"
            details = canonical_json(
                {
                    "action_type": action["action_type"],
                    "target_type": action["target_type"],
                    "target_value": action["target_value"],
                    "outcome": (
                        "simulated_failure"
                        if simulate_failure
                        else "simulated_success"
                    ),
                    "simulation_only": True,
                    "real_action_executed": False,
                    "external_target_used": False,
                }
            )
            connection.execute(
                """
                UPDATE v2_containment_actions
                SET status = ?,
                    executed_by = ?,
                    executed_at = ?,
                    result_details = ?,
                    real_action_executed = 0,
                    external_target_used = 0,
                    updated_at = ?
                WHERE containment_action_id = ?
                  AND status = 'approved'
                """,
                (
                    status,
                    executed_by,
                    executed_at,
                    details,
                    executed_at,
                    containment_action_id,
                ),
            )
            connection.execute(
                """
                UPDATE v2_containment_approvals
                SET action_occurred = ?
                WHERE containment_action_id = ?
                  AND decision_status = 'approved'
                """,
                (
                    0 if simulate_failure else 1,
                    containment_action_id,
                ),
            )
            updated = connection.execute(
                """
                SELECT *
                FROM v2_containment_actions
                WHERE containment_action_id = ?
                """,
                (containment_action_id,),
            ).fetchone()
    except PermissionError as error:
        audit_result(
            database_path,
            executed_by,
            "execute_v2_stage12_containment",
            f"containment_action:{containment_action_id}",
            "denied",
            str(error),
        )
        raise

    result = existing_action_result(updated)
    audit_result(
        database_path,
        executed_by,
        "execute_v2_stage12_containment",
        f"containment_action:{containment_action_id}",
        "failed" if simulate_failure else "success",
        (
            f"status={result['status']} actor_role={role} "
            "evidence_preserved=true simulation_only=true "
            "real_action_executed=false"
        ),
    )
    return result


def rollback_action(
    database_path: Path,
    configuration: dict[str, Any],
    rbac: dict[str, Any],
    *,
    containment_action_id: int,
    requested_by: str,
    rollback_reason: str,
    rollback_id: str,
    simulate_failure: bool = False,
) -> dict[str, Any]:
    """Apply a supported rollback as a simulated local state change."""
    validate_safety_configuration(configuration)
    requested_by = clean_text(requested_by, "requested_by")
    rollback_reason = clean_text(rollback_reason, "rollback_reason")
    rollback_id = clean_text(rollback_id, "rollback_id")
    rollback_time = utc_now()
    rollback_key = stable_key("v2-containment-rollback", rollback_id)

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        role = require_permission(
            connection,
            rbac,
            requested_by,
            configuration["permissions"]["rollback"],
        )
        action = connection.execute(
            """
            SELECT *
            FROM v2_containment_actions
            WHERE containment_action_id = ?
            """,
            (containment_action_id,),
        ).fetchone()
        if action is None:
            raise ValueError(
                f"Containment action does not exist: "
                f"{containment_action_id}"
            )
        existing = connection.execute(
            """
            SELECT *
            FROM v2_containment_rollbacks
            WHERE rollback_key = ?
            """,
            (rollback_key,),
        ).fetchone()
        if existing is not None:
            if existing["containment_action_id"] != containment_action_id:
                raise ContainmentError(
                    "rollback_id is already used for another action"
                )
            return {
                "containment_rollback_id": existing[
                    "containment_rollback_id"
                ],
                "rollback_key": existing["rollback_key"],
                "containment_action_id": containment_action_id,
                "rollback_action": existing["rollback_action"],
                "status": existing["rollback_status"],
                "new": False,
            }
        if action["status"] != "successful":
            raise ValueError(
                "Only a successful containment action can be rolled back"
            )
        if action["rollback_supported"] != 1:
            raise ValueError(
                f"Rollback is not supported for {action['action_type']}"
            )
        rollback_status = "failed" if simulate_failure else "successful"
        result_details = canonical_json(
            {
                "rollback_action": action["rollback_action"],
                "outcome": (
                    "simulated_failure"
                    if simulate_failure
                    else "simulated_success"
                ),
                "simulation_only": True,
                "real_action_executed": False,
            }
        )
        cursor = connection.execute(
            """
            INSERT INTO v2_containment_rollbacks (
                rollback_key,
                containment_action_id,
                incident_id,
                rollback_action,
                requested_by,
                requested_at,
                executed_by,
                executed_at,
                rollback_status,
                rollback_reason,
                result_details,
                evidence_references,
                simulation_only,
                real_action_executed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
            """,
            (
                rollback_key,
                containment_action_id,
                action["incident_id"],
                action["rollback_action"],
                requested_by,
                rollback_time,
                requested_by,
                rollback_time,
                rollback_status,
                rollback_reason,
                result_details,
                action["evidence_references"],
            ),
        )
        action_status = (
            "rollback_failed" if simulate_failure else "rolled_back"
        )
        connection.execute(
            """
            UPDATE v2_containment_actions
            SET status = ?,
                updated_at = ?
            WHERE containment_action_id = ?
            """,
            (
                action_status,
                rollback_time,
                containment_action_id,
            ),
        )
        rollback_record_id = cursor.lastrowid

    audit_result(
        database_path,
        requested_by,
        "rollback_v2_stage12_containment",
        f"containment_action:{containment_action_id}",
        "failed" if simulate_failure else "success",
        (
            f"rollback_action={action['rollback_action']} "
            f"status={rollback_status} actor_role={role} "
            "simulation_only=true real_action_executed=false"
        ),
    )
    return {
        "containment_rollback_id": rollback_record_id,
        "rollback_key": rollback_key,
        "containment_action_id": containment_action_id,
        "rollback_action": action["rollback_action"],
        "status": rollback_status,
        "new": True,
    }
