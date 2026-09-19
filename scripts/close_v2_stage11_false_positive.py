"""Record an authorised false-positive closure with preserved evidence."""

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


def close_false_positive(
    database,
    rbac,
    config,
    incident_id,
    actor,
    notes,
    reason,
    evidence_keys,
    request_id,
):
    """Close only an eligible incident; never delete its evidence."""
    payload = {
        "incident_id": incident_id,
        "actor": actor,
        "notes": notes.strip(),
        "reason": reason.strip(),
        "evidence_keys": sorted(set(evidence_keys)),
        "request_id": request_id.strip(),
    }

    key = "v2-fp-closure-" + digest(
        canonical([incident_id, request_id.strip()])
    )
    target = "Closed - False Positive"

    try:
        with managed_connection(database) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")

            role = investigator(
                connection,
                actor,
                rbac,
                config,
            )

            if not {
                "classify_false_positives",
                "add_investigation_notes",
            } <= set(rbac["roles"].get(role, [])):
                raise PermissionError(
                    "False-positive review permissions required"
                )

            if not all(payload.values()):
                raise ValueError(
                    "Notes, reason, evidence and request ID are required"
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
                previous_request = json.loads(
                    previous["details"]
                )["request"]

                if previous_request != payload:
                    raise ValueError(
                        "Request ID already used for a different closure"
                    )

            if not previous:
                if incident["status"] not in {
                    "New",
                    "Triaged",
                    "Investigating",
                }:
                    raise ValueError(
                        "False-positive closure is not allowed "
                        "from this status"
                    )

                lifecycle = config["lifecycle"]
                allowed_sources = lifecycle["false_positive_sources"]
                allowed_transitions = lifecycle[
                    "allowed_transitions"
                ].get(incident["status"], [])

                if (
                    target != lifecycle["false_positive_target"]
                    or incident["status"] not in allowed_sources
                    or target not in allowed_transitions
                ):
                    raise ValueError(
                        "Configuration does not permit this closure"
                    )

            creation = connection.execute(
                "SELECT details FROM v2_incident_timeline "
                "WHERE timeline_key=?",
                (
                    "v2-incident-created-" + digest(incident_id),
                ),
            ).fetchone()

            if creation is None:
                raise ValueError("Missing source snapshot")

            original = json.loads(creation["details"])
            snapshot = original["source_snapshot"]

            if (
                digest(canonical(snapshot))
                != original["source_snapshot_sha256"]
            ):
                raise ValueError("Source snapshot hash mismatch")

            evidence_rows = connection.execute(
                "SELECT * FROM v2_incident_evidence "
                "WHERE incident_id=?",
                (incident_id,),
            ).fetchall()

            available = {
                row["source_evidence_key"]: row
                for row in evidence_rows
            }

            expected_keys = set(
                json.loads(snapshot["evidence_keys"])
            )

            if not evidence_rows or set(available) != expected_keys:
                raise ValueError("Incident evidence is incomplete")

            if any(
                digest(row["evidence_json"])
                != row["evidence_sha256"]
                for row in evidence_rows
            ):
                raise ValueError("Evidence hash mismatch")

            if not set(payload["evidence_keys"]) <= set(available):
                raise ValueError(
                    "Closure references evidence outside this incident"
                )

            if previous:
                return False

            references = canonical(
                [
                    available[key]["evidence_reference"]
                    for key in payload["evidence_keys"]
                ]
            )
            now = utc_now()

            entry = {
                "decision_key": key,
                "event_time": now,
                "actor": actor,
                "actor_role": role,
                "decision": "False Positive",
                "notes": payload["notes"],
                "closure_reason": payload["reason"],
                "previous_status": incident["status"],
                "new_status": target,
                "evidence_references": json.loads(references),
            }

            notes_history = json.loads(
                incident["investigation_notes"]
            )
            decisions = json.loads(
                incident["analyst_decisions"]
            )

            notes_history.append(entry)
            decisions.append(entry)

            connection.execute(
                "UPDATE v2_incidents "
                "SET status=?, false_positive_classification=?, "
                "closure_reason=?, closed_at=?, updated_at=?, "
                "investigation_notes=?, analyst_decisions=? "
                "WHERE incident_id=?",
                (
                    target,
                    "False Positive",
                    payload["reason"],
                    now,
                    now,
                    canonical(notes_history),
                    canonical(decisions),
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
                    "decision": "False Positive",
                    "notes": payload["notes"],
                    "previous_status": incident["status"],
                    "new_status": target,
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
                    "action": (
                        "close_v2_stage11_false_positive"
                    ),
                    "previous_status": incident["status"],
                    "new_status": target,
                    "details": canonical(
                        {
                            "request": payload,
                            "actor_role": role,
                        }
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
                    "action": (
                        "close_v2_stage11_false_positive"
                    ),
                    "target": incident_id,
                    "result": "success",
                    "details": canonical(entry),
                },
            )

            return True

    except (ValueError, PermissionError) as error:
        record_audit_event(
            database,
            actor,
            "close_v2_stage11_false_positive",
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
        "reason",
        "request-id",
    ):
        parser.add_argument("--" + name, required=True)

    parser.add_argument(
        "--evidence-key",
        action="append",
        required=True,
    )

    args = parser.parse_args()
    settings = load_json(ROOT / "config/settings.json")

    try:
        changed = close_false_positive(
            ROOT / settings["database"]["path"],
            load_json(ROOT / "config/rbac.json"),
            load_json(
                ROOT / "config/v2_incident_management.json"
            ),
            args.incident,
            args.actor,
            args.notes,
            args.reason,
            args.evidence_key,
            args.request_id,
        )
    except (ValueError, PermissionError) as error:
        print(f"DENIED: {error}")
        return 2

    print(
        "PASS: False-positive closure recorded or already present | "
        f"incident={args.incident} | "
        f"new={str(changed).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
