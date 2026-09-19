"""Record evidence-backed early incident review in the local sandbox."""

import argparse
import json
import sqlite3
from pathlib import Path

from scripts.assign_v2_stage11_incident import investigator
from scripts.import_v2_stage11_incidents import canonical, digest, insert
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, utc_now
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


def review(
    database,
    rbac,
    config,
    incident_id,
    actor,
    status,
    notes,
    decision,
    request_id,
):
    payload = {
        "incident_id": incident_id,
        "actor": actor,
        "status": status,
        "notes": notes.strip(),
        "decision": decision.strip(),
        "request_id": request_id.strip(),
    }
    if not all(payload.values()):
        raise ValueError("All review fields must be non-empty")

    key = "v2-review-" + digest(
        canonical([incident_id, request_id.strip()])
    )

    try:
        with managed_connection(database) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")

            role = investigator(connection, actor, rbac, config)
            if (
                "add_investigation_notes"
                not in rbac["roles"].get(role, [])
            ):
                raise PermissionError(
                    "Actor lacks add_investigation_notes"
                )

            incident = connection.execute(
                "SELECT * FROM v2_incidents WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            if incident is None:
                raise ValueError("Unknown incident")

            previous = connection.execute(
                "SELECT details FROM v2_incident_timeline "
                "WHERE timeline_key=?",
                (key,),
            ).fetchone()

            if previous:
                if json.loads(previous["details"])["request"] != payload:
                    raise ValueError(
                        "Request ID already used for different review"
                    )
                return False, incident["status"]

            if (incident["status"], status) not in {
                ("New", "Triaged"),
                ("Triaged", "Investigating"),
            }:
                raise ValueError(
                    "This review supports New to Triaged or "
                    "Triaged to Investigating only"
                )

            allowed = config["lifecycle"]["allowed_transitions"].get(
                incident["status"], []
            )
            if status not in allowed:
                raise ValueError(
                    "Transition is not permitted by configuration"
                )

            rows = connection.execute(
                "SELECT * FROM v2_incident_evidence WHERE incident_id=?",
                (incident_id,),
            ).fetchall()

            creation = connection.execute(
                "SELECT details FROM v2_incident_timeline "
                "WHERE timeline_key=?",
                ("v2-incident-created-" + digest(incident_id),),
            ).fetchone()
            if creation is None:
                raise ValueError("Creation snapshot is missing")

            original = json.loads(creation["details"])
            snapshot = original["source_snapshot"]

            if (
                digest(canonical(snapshot))
                != original["source_snapshot_sha256"]
            ):
                raise ValueError("Source snapshot hash mismatch")

            if not rows or {
                row["source_evidence_key"] for row in rows
            } != set(json.loads(snapshot["evidence_keys"])):
                raise ValueError("Incident evidence is incomplete")

            if any(
                digest(row["evidence_json"]) != row["evidence_sha256"]
                for row in rows
            ):
                raise ValueError("Evidence hash mismatch")

            references = canonical(
                sorted(row["evidence_reference"] for row in rows)
            )
            now = utc_now()

            entry = {
                "decision_key": key,
                "event_time": now,
                "actor": actor,
                "actor_role": role,
                "notes": payload["notes"],
                "decision": payload["decision"],
                "previous_status": incident["status"],
                "new_status": status,
            }

            note_history = json.loads(incident["investigation_notes"])
            decision_history = json.loads(incident["analyst_decisions"])
            note_history.append(entry)
            decision_history.append(entry)

            connection.execute(
                "UPDATE v2_incidents "
                "SET status=?, updated_at=?, investigation_notes=?, "
                "analyst_decisions=? WHERE incident_id=?",
                (
                    status,
                    now,
                    canonical(note_history),
                    canonical(decision_history),
                    incident_id,
                ),
            )

            insert(
                connection,
                "v2_incident_decisions",
                {
                    "decision_key": key,
                    "incident_id": incident_id,
                    "decision_time": now,
                    "actor": actor,
                    "actor_role": role,
                    "decision": payload["decision"],
                    "notes": payload["notes"],
                    "previous_status": incident["status"],
                    "new_status": status,
                    "evidence_references": references,
                },
            )

            insert(
                connection,
                "v2_incident_timeline",
                {
                    "timeline_key": key,
                    "incident_id": incident_id,
                    "event_time": now,
                    "event_type": "status_changed",
                    "actor": actor,
                    "action": "review_v2_stage11_incident",
                    "previous_status": incident["status"],
                    "new_status": status,
                    "details": canonical(
                        {"request": payload, "actor_role": role}
                    ),
                    "evidence_references": references,
                },
            )

            insert(
                connection,
                "audit_events",
                {
                    "event_time": now,
                    "actor": actor,
                    "action": "review_v2_stage11_incident",
                    "target": incident_id,
                    "result": "success",
                    "details": canonical(entry),
                },
            )

            return True, status

    except (PermissionError, ValueError) as error:
        record_audit_event(
            database,
            actor,
            "review_v2_stage11_incident",
            incident_id,
            "denied",
            str(error),
        )
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "incident",
        "actor",
        "notes",
        "decision",
        "request-id",
    ):
        parser.add_argument("--" + name, required=True)

    parser.add_argument(
        "--status",
        required=True,
        choices=["Triaged", "Investigating"],
    )
    args = parser.parse_args()

    settings = load_json(ROOT / "config/settings.json")

    try:
        changed, status = review(
            ROOT / settings["database"]["path"],
            load_json(ROOT / "config/rbac.json"),
            load_json(ROOT / "config/v2_incident_management.json"),
            args.incident,
            args.actor,
            args.status,
            args.notes,
            args.decision,
            args.request_id,
        )
    except (PermissionError, ValueError) as error:
        print(f"DENIED: {error}")
        return 2

    print(
        "PASS: Stage 11 review recorded or already present | "
        f"incident={args.incident} | status={status} | "
        f"new={str(changed).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
