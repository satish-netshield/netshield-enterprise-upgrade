"""Import incident IoCs, behaviours, ATT&CK references and finding links."""

import json
import sqlite3
from pathlib import Path

from scripts.import_v2_stage11_incidents import canonical, digest, insert
from src.utils.config_loader import load_json
from src.utils.database import utc_now
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


def store(connection, table, key_column, values):
    """Preserve existing records and reject conflicting repeated imports."""
    existing = connection.execute(
        f"SELECT * FROM {table} WHERE {key_column}=?",
        (values[key_column],),
    ).fetchone()

    if existing:
        if any(
            existing[key] != value
            for key, value in values.items()
            if key != "created_at"
        ):
            raise RuntimeError(
                f"Stored context differs: {values[key_column]}"
            )
        return 0

    insert(connection, table, values)
    return 1


def main():
    settings = load_json(ROOT / "config/settings.json")
    now = utc_now()
    counts = {
        "iocs": 0,
        "behaviours": 0,
        "attack": 0,
        "findings": 0,
    }

    with managed_connection(
        ROOT / settings["database"]["path"]
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")

        incidents = connection.execute(
            "SELECT * FROM v2_incidents ORDER BY managed_incident_id"
        ).fetchall()
        if not incidents:
            raise RuntimeError("Import Stage 11 incidents first")

        for incident in incidents:
            incident_id = incident["incident_id"]
            timeline_key = "v2-incident-created-" + digest(incident_id)

            creation = connection.execute(
                "SELECT details FROM v2_incident_timeline "
                "WHERE timeline_key=?",
                (timeline_key,),
            ).fetchone()
            if creation is None:
                raise RuntimeError(
                    f"Missing creation snapshot: {incident_id}"
                )

            details = json.loads(creation["details"])
            source = details["source_snapshot"]
            if (
                digest(canonical(source))
                != details["source_snapshot_sha256"]
            ):
                raise RuntimeError(
                    f"Source snapshot hash mismatch: {incident_id}"
                )

            evidence = []
            for row in connection.execute(
                "SELECT * FROM v2_incident_evidence WHERE incident_id=?",
                (incident_id,),
            ):
                if digest(row["evidence_json"]) != row["evidence_sha256"]:
                    raise RuntimeError(
                        f"Evidence hash mismatch: {incident_id}"
                    )
                evidence.append(json.loads(row["evidence_json"]))

            keys = {row["evidence_key"] for row in evidence}
            if keys != set(json.loads(source["evidence_keys"])):
                raise RuntimeError(
                    f"Incomplete preserved evidence: {incident_id}"
                )

            before = sum(counts.values())

            def save(table, key_column, category, natural_key, fields):
                values = {
                    key_column: (
                        "v2-managed-context-"
                        + digest(
                            canonical(
                                [incident_id, category, natural_key]
                            )
                        )
                    ),
                    "incident_id": incident_id,
                    **fields,
                    "created_at": now,
                }
                counts[category] += store(
                    connection, table, key_column, values
                )

            indicators = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM v2_xdr_indicators "
                    "WHERE incident_key=? ORDER BY indicator_key",
                    (incident["source_incident_key"],),
                )
            ]

            for indicator in indicators:
                if indicator["classification"] == "supporting_observable":
                    continue
                if indicator["classification"] != "ioc":
                    raise RuntimeError(
                        "Unknown indicator classification"
                    )

                references = json.loads(
                    indicator["source_evidence_keys"]
                )
                if not references or not set(references) <= keys:
                    raise RuntimeError(
                        f"IoC lacks incident evidence: {incident_id}"
                    )

                save(
                    "v2_incident_iocs",
                    "ioc_key",
                    "iocs",
                    [
                        indicator["indicator_type"],
                        indicator["indicator_value"],
                    ],
                    {
                        "ioc_type": indicator["indicator_type"],
                        "ioc_value": indicator["indicator_value"],
                        "confidence": indicator["confidence"],
                        "source_evidence_keys": canonical(
                            sorted(set(references))
                        ),
                    },
                )

            for behaviour in sorted(
                set(json.loads(source["behaviours"]))
            ):
                references = sorted(
                    row["evidence_key"]
                    for row in evidence
                    if row["detection_type"] == behaviour
                )

                save(
                    "v2_incident_behaviours",
                    "behaviour_key",
                    "behaviours",
                    behaviour,
                    {
                        "behaviour_name": behaviour,
                        "detection_types": canonical(
                            [behaviour] if references else []
                        ),
                        "source_evidence_keys": canonical(references),
                    },
                )

            for technique in sorted(
                set(json.loads(source["attack_techniques"]))
            ):
                # Preserve the incident-level mapping without inventing
                # a technique name or detection-level attribution.
                save(
                    "v2_incident_attack_references",
                    "attack_reference_key",
                    "attack",
                    technique,
                    {
                        "technique_id": technique,
                        "technique_name": None,
                        "source_detection_types": "[]",
                    },
                )

            for finding in json.loads(source["vulnerability_context"]):
                source_finding_id = finding["source_record_id"]
                matches = connection.execute(
                    "SELECT finding_key FROM v2_vulnerability_findings "
                    "WHERE source_finding_id=?",
                    (source_finding_id,),
                ).fetchall()

                if len(matches) != 1:
                    raise RuntimeError(
                        "Missing or ambiguous finding: "
                        f"{source_finding_id}"
                    )

                finding_key = matches[0]["finding_key"]
                exploitation = finding["exploitation_status"]
                relationships = {
                    "none": "context_only",
                    "attempted": "attempted_exploitation",
                    "successful": "successful_exploitation",
                }
                if exploitation not in relationships:
                    raise RuntimeError(
                        "Unknown exploitation state: "
                        f"{source_finding_id}"
                    )

                save(
                    "v2_incident_vulnerability_links",
                    "vulnerability_link_key",
                    "findings",
                    finding_key,
                    {
                        "finding_key": finding_key,
                        "source_finding_id": source_finding_id,
                        "relationship": relationships[exploitation],
                        "exploitation_status": exploitation,
                        "evidence_references": canonical(
                            [
                                "v2_incident_timeline:" + timeline_key,
                                "v2_vulnerability_findings:" + finding_key,
                            ]
                        ),
                    },
                )

            added = sum(counts.values()) - before
            if added and incident["status"] in (
                "Closed",
                "Closed - False Positive",
            ):
                raise RuntimeError(
                    "Closed incident cannot be enriched; rolled back"
                )

            context_key = "v2-incident-context-" + digest(incident_id)
            existing_timeline = connection.execute(
                "SELECT 1 FROM v2_incident_timeline WHERE timeline_key=?",
                (context_key,),
            ).fetchone()

            if not existing_timeline:
                insert(
                    connection,
                    "v2_incident_timeline",
                    {
                        "timeline_key": context_key,
                        "incident_id": incident_id,
                        "event_time": now,
                        "event_type": "evidence_linked",
                        "actor": "netshield01",
                        "action": "import_v2_stage11_context",
                        "details": canonical(
                            {
                                "indicator_snapshots": indicators,
                                "indicator_snapshots_sha256": digest(
                                    canonical(indicators)
                                ),
                                "source_creation_timeline_key": timeline_key,
                            }
                        ),
                        "evidence_references": canonical(
                            ["v2_incident_timeline:" + timeline_key]
                        ),
                    },
                )

        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(
                "Foreign-key violations; import rolled back"
            )

        insert(
            connection,
            "audit_events",
            {
                "event_time": now,
                "actor": "netshield01",
                "action": "import_v2_stage11_context",
                "target": "v2_incidents",
                "result": "success",
                "details": canonical(counts),
            },
        )

    print("PASS: Stage 11 incident context imported")
    for category, count in counts.items():
        print(f"New {category}: {count}")
    print("Incident lifecycle and risk scores unchanged")


if __name__ == "__main__":
    main()
