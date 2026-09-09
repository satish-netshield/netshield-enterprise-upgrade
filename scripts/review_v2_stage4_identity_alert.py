"""Review and classify a V2 Stage 4 identity alert."""
from src.utils.sqlite_connection import managed_connection

import argparse
import sqlite3
from pathlib import Path
from typing import Any

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.security_controls import role_has_permission


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_CLASSIFICATIONS = {
    "Confirmed",
    "False Positive",
}


def load_active_role(
    database_path: Path,
    username: str,
) -> str | None:
    """Return an active role assigned to a user."""
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


def review_identity_alert(
    database_path: Path,
    rbac_config: dict[str, Any],
    alert_id: int,
    actor: str,
    classification: str,
    notes: str,
) -> dict[str, Any]:
    """Classify one alert after checking analyst permissions."""
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError(
            f"Unsupported classification: {classification}"
        )

    cleaned_notes = notes.strip()
    if not cleaned_notes:
        raise ValueError("Investigation notes must not be empty")

    role = load_active_role(database_path, actor)
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
                username,
                status
            FROM v2_identity_alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

        if alert is None:
            raise ValueError(
                f"Identity alert does not exist: {alert_id}"
            )

        connection.execute(
            """
            UPDATE v2_identity_alerts
            SET status = ?,
                classification = ?,
                investigation_notes = ?
            WHERE alert_id = ?
            """,
            (
                new_status,
                classification,
                cleaned_notes,
                alert_id,
            ),
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
        action="review_v2_stage4_identity_alert",
        target=f"v2_identity_alert:{alert_id}",
        result="success",
        details=details,
    )

    return {
        "alert_id": alert_id,
        "alert_key": alert["alert_key"],
        "detection_type": alert["detection_type"],
        "username": alert["username"],
        "previous_status": alert["status"],
        "status": new_status,
        "classification": classification,
        "investigation_notes": cleaned_notes,
        "actor": actor,
        "role": role,
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Review and classify a V2 Stage 4 identity alert"
        )
    )
    parser.add_argument(
        "--alert-id",
        type=int,
        required=True,
        help="Database ID of the identity alert",
    )
    parser.add_argument(
        "--actor",
        default="analyst01",
        help="User performing the investigation",
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
    """Review an identity alert from command-line arguments."""
    arguments = parse_arguments()
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    rbac_config = load_json(
        PROJECT_ROOT / "config/rbac.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    result = review_identity_alert(
        database_path=database_path,
        rbac_config=rbac_config,
        alert_id=arguments.alert_id,
        actor=arguments.actor,
        classification=arguments.classification,
        notes=arguments.notes,
    )

    print("PASS: V2 Stage 4 identity alert reviewed")
    print(f"Alert ID: {result['alert_id']}")
    print(f"Detection: {result['detection_type']}")
    print(f"Username: {result['username']}")
    print(f"Classification: {result['classification']}")
    print(f"Status: {result['status']}")
    print(f"Reviewed by: {result['actor']} ({result['role']})")


if __name__ == "__main__":
    main()
