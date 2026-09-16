"""Review and classify a Phase 3A V2 Stage 7 endpoint alert."""

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.security_controls import role_has_permission
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_CLASSIFICATIONS = {
    "Confirmed",
    "False Positive",
}


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


def review_endpoint_alert(
    database_path: Path,
    rbac_config: dict[str, Any],
    alert_id: int,
    actor: str,
    classification: str,
    notes: str,
) -> dict[str, Any]:
    """Classify one endpoint alert after checking permissions."""
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError(
            f"Unsupported classification: {classification}"
        )

    cleaned_notes = notes.strip()
    if not cleaned_notes:
        raise ValueError(
            "Investigation notes must not be empty"
        )

    role = load_active_role(
        database_path,
        actor,
    )
    if role is None:
        raise PermissionError(
            f"Actor has no active role: {actor}"
        )

    required_permissions = {
        "investigate_incidents",
        "add_investigation_notes",
    }

    if classification == "False Positive":
        required_permissions.add(
            "classify_false_positives"
        )

    missing_permissions = sorted(
        permission
        for permission in required_permissions
        if not role_has_permission(
            rbac_config,
            role,
            permission,
        )
    )

    if missing_permissions:
        raise PermissionError(
            "Actor lacks required permissions: "
            + ", ".join(missing_permissions)
        )

    reviewed_at = datetime.now(timezone.utc).isoformat()
    new_status = (
        "Closed"
        if classification == "False Positive"
        else "Confirmed"
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        alert = connection.execute(
            """
            SELECT
                alert_id,
                alert_key,
                detection_type,
                severity,
                confidence,
                source_event_ids,
                device_id,
                asset_id,
                username,
                hostname,
                process_name,
                status,
                classification,
                evidence
            FROM v2_endpoint_alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

        if alert is None:
            raise ValueError(
                f"Endpoint alert does not exist: {alert_id}"
            )

        if alert["status"] == "Closed":
            raise ValueError(
                f"Endpoint alert is already closed: {alert_id}"
            )

        cursor = connection.execute(
            """
            UPDATE v2_endpoint_alerts
            SET status = ?,
                classification = ?,
                investigation_notes = ?,
                reviewed_by = ?,
                reviewed_at = ?
            WHERE alert_id = ?
              AND status != 'Closed'
            """,
            (
                new_status,
                classification,
                cleaned_notes,
                actor,
                reviewed_at,
                alert_id,
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "Endpoint alert changed before the review "
                "could be recorded"
            )

    details = (
        f"alert_id={alert_id} "
        f"detection_type={alert['detection_type']} "
        f"classification={classification} "
        f"status={new_status}"
    )
    record_audit_event(
        database_path=database_path,
        actor=actor,
        action="review_v2_stage7_endpoint_alert",
        target=f"v2_endpoint_alert:{alert_id}",
        result="success",
        details=details,
    )

    return {
        "alert_id": alert_id,
        "alert_key": alert["alert_key"],
        "detection_type": alert["detection_type"],
        "severity": alert["severity"],
        "confidence": alert["confidence"],
        "source_event_ids": alert["source_event_ids"],
        "device_id": alert["device_id"],
        "asset_id": alert["asset_id"],
        "username": alert["username"],
        "hostname": alert["hostname"],
        "process_name": alert["process_name"],
        "previous_status": alert["status"],
        "status": new_status,
        "classification": classification,
        "investigation_notes": cleaned_notes,
        "reviewed_by": actor,
        "reviewer_role": role,
        "reviewed_at": reviewed_at,
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Review and classify a Phase 3A V2 "
            "Stage 7 endpoint alert"
        )
    )
    parser.add_argument(
        "--alert-id",
        type=int,
        required=True,
        help="Database ID of the endpoint alert",
    )
    parser.add_argument(
        "--actor",
        required=True,
        help="User performing the endpoint investigation",
    )
    parser.add_argument(
        "--classification",
        choices=sorted(ALLOWED_CLASSIFICATIONS),
        required=True,
        help="Investigation classification",
    )
    parser.add_argument(
        "--notes",
        required=True,
        help="Evidence-based investigation notes",
    )
    return parser.parse_args()


def main() -> None:
    """Review an endpoint alert from command-line arguments."""
    arguments = parse_arguments()
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    rbac_config = load_json(
        PROJECT_ROOT / "config/rbac.json"
    )
    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )

    result = review_endpoint_alert(
        database_path=database_path,
        rbac_config=rbac_config,
        alert_id=arguments.alert_id,
        actor=arguments.actor,
        classification=arguments.classification,
        notes=arguments.notes,
    )

    print("PASS: V2 Stage 7 endpoint alert reviewed")
    print(f"Alert ID: {result['alert_id']}")
    print(f"Detection: {result['detection_type']}")
    print(f"Severity: {result['severity']}")
    print(f"Device: {result['device_id']}")
    print(
        "Process: "
        f"{result['process_name'] or 'not_applicable'}"
    )
    print(f"Classification: {result['classification']}")
    print(f"Status: {result['status']}")
    print(
        "Reviewed by: "
        f"{result['reviewed_by']} "
        f"({result['reviewer_role']})"
    )


if __name__ == "__main__":
    main()
