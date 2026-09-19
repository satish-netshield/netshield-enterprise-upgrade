"""Assign an incident owner using existing sandbox RBAC permissions."""

import argparse
import sqlite3
from pathlib import Path

from scripts.import_v2_stage11_incidents import canonical, digest, insert
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, utc_now
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


def investigator(connection, username, rbac, configuration):
    """Require an active role with incident-investigation permission."""
    row = connection.execute(
        "SELECT role, active FROM user_roles WHERE username=?",
        (username,),
    ).fetchone()

    if row is None or row["active"] != 1:
        raise PermissionError(
            f"Inactive or unknown actor/owner: {username}"
        )

    ownership = configuration["ownership"]
    permissions = rbac["roles"].get(row["role"], [])

    if (
        row["role"] not in ownership["permitted_roles"]
        or ownership["required_permission"] not in permissions
    ):
        raise PermissionError(
            f"Investigation permission required: {username}"
        )

    return row["role"]


def assign(
    database,
    rbac,
    configuration,
    incident_id,
    actor,
    owner,
    notes,
):
    """Assign ownership atomically without changing incident status."""
    if not notes.strip():
        raise ValueError("Assignment notes must not be empty")

    try:
        with managed_connection(database) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")

            actor_role = investigator(
                connection, actor, rbac, configuration
            )
            owner_role = investigator(
                connection, owner, rbac, configuration
            )

            incident = connection.execute(
                "SELECT * FROM v2_incidents WHERE incident_id=?",
                (incident_id,),
            ).fetchone()

            if incident is None:
                raise ValueError(f"Unknown incident: {incident_id}")

            if incident["status"] in (
                "Closed",
                "Closed - False Positive",
            ):
                raise ValueError(
                    "Closed incident ownership cannot be changed"
                )

            changed = incident["incident_owner"] != owner
            now = utc_now()
            details = canonical(
                {
                    "previous_owner": incident["incident_owner"],
                    "owner": owner,
                    "owner_role": owner_role,
                    "actor_role": actor_role,
                    "notes": notes.strip(),
                    "changed": changed,
                }
            )

            if changed:
                connection.execute(
                    "UPDATE v2_incidents "
                    "SET incident_owner=?, updated_at=? "
                    "WHERE incident_id=?",
                    (owner, now, incident_id),
                )

                sequence = connection.execute(
                    "SELECT COALESCE(MAX(incident_timeline_id), 0)+1 "
                    "FROM v2_incident_timeline"
                ).fetchone()[0]

                insert(
                    connection,
                    "v2_incident_timeline",
                    {
                        "timeline_key": (
                            "v2-owner-"
                            + digest(
                                canonical(
                                    [
                                        incident_id,
                                        sequence,
                                        actor,
                                        owner,
                                    ]
                                )
                            )
                        ),
                        "incident_id": incident_id,
                        "event_time": now,
                        "event_type": "owner_assigned",
                        "actor": actor,
                        "action": "assign_v2_stage11_incident",
                        "previous_status": incident["status"],
                        "new_status": incident["status"],
                        "details": details,
                        "evidence_references": "[]",
                    },
                )

            insert(
                connection,
                "audit_events",
                {
                    "event_time": now,
                    "actor": actor,
                    "action": "assign_v2_stage11_incident",
                    "target": incident_id,
                    "result": "success",
                    "details": details,
                },
            )

            return changed, incident["status"]

    except PermissionError as error:
        # The rejected transaction has rolled back before auditing denial.
        record_audit_event(
            database,
            actor,
            "assign_v2_stage11_incident",
            incident_id,
            "denied",
            str(error),
        )
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--notes", required=True)
    args = parser.parse_args()

    settings = load_json(ROOT / "config/settings.json")
    configuration = load_json(
        ROOT / "config/v2_incident_management.json"
    )
    rbac = load_json(ROOT / "config/rbac.json")

    try:
        changed, status = assign(
            ROOT / settings["database"]["path"],
            rbac,
            configuration,
            args.incident,
            args.actor,
            args.owner,
            args.notes,
        )
    except PermissionError as error:
        print(f"DENIED: {error}")
        return 2

    print("PASS: Stage 11 incident owner checked and assignment recorded")
    print(f"Incident: {args.incident}")
    print(f"Owner: {args.owner}")
    print(f"Owner changed: {str(changed).lower()}")
    print(f"Status unchanged: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
