"""Record approval for a simulated Phase 3A V2 Stage 7 isolation request."""

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.security_controls import role_has_permission
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ACTION = "quarantine_device"
REQUIRED_CONTROL_LEVEL = "approval_required"
PENDING_STATUS = "approval_required"
APPROVED_STATUS = "simulated_isolated"


def load_active_role(
    database_path: Path,
    username: str,
) -> str | None:
    """Return the active application role assigned to a user."""
    with managed_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT role
            FROM user_roles
            WHERE username = ?
              AND active = 1
            """,
            (username,),
        ).fetchone()

    return row[0] if row else None


def load_evidence(raw_evidence: str) -> dict[str, Any]:
    """Load the existing isolation evidence without discarding it."""
    try:
        evidence = json.loads(raw_evidence)
    except json.JSONDecodeError as error:
        raise ValueError(
            "Isolation request contains invalid evidence JSON"
        ) from error

    if not isinstance(evidence, dict):
        raise ValueError(
            "Isolation request evidence must be a JSON object"
        )

    return evidence


def approve_simulated_isolation(
    database_path: Path,
    rbac_config: dict[str, Any],
    automation_acl: dict[str, Any],
    isolation_id: int,
    actor: str,
    notes: str,
) -> dict[str, Any]:
    """Approve one simulated isolation request after checking access."""
    cleaned_notes = notes.strip()
    if not cleaned_notes:
        raise ValueError("Approval notes must not be empty")

    role = load_active_role(database_path, actor)
    if role is None:
        raise PermissionError(
            f"Actor has no active role: {actor}"
        )

    if not role_has_permission(
        rbac_config,
        role,
        "execute_approved_containment",
    ):
        raise PermissionError(
            "Actor lacks required permission: "
            "execute_approved_containment"
        )

    approval_required_actions = set(
        automation_acl.get("approval_required", [])
    )
    if REQUIRED_ACTION not in approval_required_actions:
        raise PermissionError(
            "The quarantine_device action is not controlled by "
            "the approval-required automation ACL"
        )

    approved_at = datetime.now(timezone.utc).isoformat()

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        isolation = connection.execute(
            """
            SELECT
                isolation_id,
                isolation_key,
                alert_key,
                requested_at,
                device_id,
                asset_id,
                action,
                acl_control_level,
                status,
                request_reason,
                approved_by,
                approved_at,
                network_state_changed,
                real_action_executed,
                evidence
            FROM v2_endpoint_isolation_actions
            WHERE isolation_id = ?
            """,
            (isolation_id,),
        ).fetchone()

        if isolation is None:
            raise ValueError(
                f"Endpoint isolation request does not exist: "
                f"{isolation_id}"
            )

        if isolation["action"] != REQUIRED_ACTION:
            raise ValueError(
                "Unsupported endpoint isolation action: "
                f"{isolation['action']}"
            )

        if (
            isolation["acl_control_level"]
            != REQUIRED_CONTROL_LEVEL
        ):
            raise ValueError(
                "Endpoint isolation request does not use the "
                "approval-required ACL control"
            )

        if isolation["status"] != PENDING_STATUS:
            raise ValueError(
                "Endpoint isolation request is not awaiting approval: "
                f"{isolation['status']}"
            )

        if isolation["network_state_changed"] != 0:
            raise ValueError(
                "Endpoint isolation request unexpectedly records a "
                "network-state change"
            )

        if isolation["real_action_executed"] != 0:
            raise ValueError(
                "Endpoint isolation request unexpectedly records a "
                "real action"
            )

        evidence = load_evidence(isolation["evidence"])
        evidence["simulated_approval"] = {
            "approved_by": actor,
            "approver_role": role,
            "approved_at": approved_at,
            "notes": cleaned_notes,
            "status": APPROVED_STATUS,
            "network_state_changed": False,
            "real_action_executed": False,
        }

        cursor = connection.execute(
            """
            UPDATE v2_endpoint_isolation_actions
            SET status = ?,
                approved_by = ?,
                approved_at = ?,
                network_state_changed = 0,
                real_action_executed = 0,
                evidence = ?
            WHERE isolation_id = ?
              AND status = ?
            """,
            (
                APPROVED_STATUS,
                actor,
                approved_at,
                json.dumps(evidence, sort_keys=True),
                isolation_id,
                PENDING_STATUS,
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "Endpoint isolation request changed before approval "
                "could be recorded"
            )

    details = (
        f"isolation_id={isolation_id} "
        f"device_id={isolation['device_id']} "
        f"action={isolation['action']} "
        f"status={APPROVED_STATUS} "
        "simulation_only=true "
        "network_state_changed=false "
        "real_action_executed=false"
    )
    record_audit_event(
        database_path=database_path,
        actor=actor,
        action="approve_v2_stage7_endpoint_isolation",
        target=f"v2_endpoint_isolation_action:{isolation_id}",
        result="success",
        details=details,
    )

    return {
        "isolation_id": isolation_id,
        "isolation_key": isolation["isolation_key"],
        "alert_key": isolation["alert_key"],
        "device_id": isolation["device_id"],
        "asset_id": isolation["asset_id"],
        "action": isolation["action"],
        "acl_control_level": isolation["acl_control_level"],
        "previous_status": isolation["status"],
        "status": APPROVED_STATUS,
        "request_reason": isolation["request_reason"],
        "approved_by": actor,
        "approver_role": role,
        "approved_at": approved_at,
        "approval_notes": cleaned_notes,
        "network_state_changed": False,
        "real_action_executed": False,
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Record approval for a simulated Phase 3A V2 "
            "Stage 7 endpoint-isolation request"
        )
    )
    parser.add_argument(
        "--isolation-id",
        type=int,
        required=True,
        help="Database ID of the endpoint-isolation request",
    )
    parser.add_argument(
        "--actor",
        required=True,
        help="Responder or Administrator recording the approval",
    )
    parser.add_argument(
        "--notes",
        required=True,
        help="Evidence-based approval notes",
    )
    return parser.parse_args()


def main() -> None:
    """Approve a simulated isolation request from command-line arguments."""
    arguments = parse_arguments()
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    rbac_config = load_json(
        PROJECT_ROOT / "config/rbac.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )

    result = approve_simulated_isolation(
        database_path=database_path,
        rbac_config=rbac_config,
        automation_acl=automation_acl,
        isolation_id=arguments.isolation_id,
        actor=arguments.actor,
        notes=arguments.notes,
    )

    print(
        "PASS: V2 Stage 7 simulated endpoint isolation approved"
    )
    print(f"Isolation ID: {result['isolation_id']}")
    print(f"Device: {result['device_id']}")
    print(f"Action: {result['action']}")
    print(f"ACL control: {result['acl_control_level']}")
    print(f"Status: {result['status']}")
    print(
        "Approved by: "
        f"{result['approved_by']} "
        f"({result['approver_role']})"
    )
    print("Real action executed: false")
    print("Network state changed: false")


if __name__ == "__main__":
    main()
