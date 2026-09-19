"""Import XDR incident context and hashed evidence without response actions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from scripts.initialize_v2_stage11 import validate_configuration
from src.utils.config_loader import load_json
from src.utils.database import utc_now
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    """Serialize a snapshot deterministically; retain nested original text."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(text):
    """Hash the exact UTF-8 snapshot text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def insert(connection, table, values):
    """Insert using internal table and column names, with bound values."""
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    connection.execute(
        f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
        tuple(values.values()),
    )


def import_incidents(database_path, configuration):
    """Atomically import new snapshots; preserve existing investigations."""
    validate_configuration(configuration)
    results = []
    now = utc_now()

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(v2_incidents)"
            )
        }
        if not {"risk_record_key", "risk_assessed_at"} <= columns:
            raise RuntimeError("Run initialize_v2_stage11_risk first")

        sources = connection.execute(
            "SELECT * FROM v2_xdr_incidents ORDER BY incident_id"
        ).fetchall()
        if not sources:
            raise RuntimeError("No Stage 10 XDR incidents are available")

        for source in sources:
            source_key = source["incident_key"]
            existing = connection.execute(
                "SELECT * FROM v2_incidents WHERE source_incident_key=?",
                (source_key,),
            ).fetchone()

            if existing:
                evidence = connection.execute(
                    "SELECT evidence_json, evidence_sha256 "
                    "FROM v2_incident_evidence WHERE incident_id=?",
                    (existing["incident_id"],),
                ).fetchall()

                if not evidence or any(
                    digest(row["evidence_json"]) != row["evidence_sha256"]
                    for row in evidence
                ):
                    raise RuntimeError(
                        "Stored evidence missing or hash mismatch: "
                        f"{source_key}"
                    )

                results.append(
                    (
                        existing["incident_id"],
                        False,
                        existing["status"],
                        existing["risk_score"],
                        len(evidence),
                    )
                )
                continue

            links = connection.execute(
                "SELECT * FROM v2_xdr_incident_evidence "
                "WHERE incident_key=? ORDER BY evidence_key",
                (source_key,),
            ).fetchall()

            keys = [row["evidence_key"] for row in links]
            if (
                not links
                or len(keys) != len(set(keys))
                or len(keys) != source["evidence_count"]
                or set(keys) != set(json.loads(source["evidence_keys"]))
            ):
                raise RuntimeError(
                    f"Incomplete XDR evidence: {source_key}"
                )

            if source["original_evidence_preserved"] != 1:
                raise RuntimeError(
                    f"Original evidence not preserved: {source_key}"
                )

            number = connection.execute(
                "SELECT COALESCE(MAX(managed_incident_id), 0) + 1 "
                "FROM v2_incidents"
            ).fetchone()[0]

            identity = configuration["incident_identity"]
            incident_id = identity["prefix"] + str(number).zfill(
                identity["number_width"]
            )

            # Only an exact incident-key match supplies incident risk.
            # Device, asset and unrelated legacy incident scores are not used.
            risk_rows = connection.execute(
                "SELECT * FROM v2_continuous_risk_scores "
                "WHERE entity_type='incident' AND entity_id=?",
                (source_key,),
            ).fetchall()
            if len(risk_rows) > 1:
                raise RuntimeError(
                    f"Ambiguous incident risk: {source_key}"
                )
            risk = risk_rows[0] if risk_rows else None

            def context(*fields):
                return canonical(
                    {
                        field: json.loads(source[field])
                        for field in fields
                    }
                )

            insert(
                connection,
                "v2_incidents",
                {
                    "managed_incident_id": number,
                    "incident_id": incident_id,
                    "source_incident_key": source_key,
                    "title": source["title"],
                    "detection_sources": canonical(
                        sorted({row["source_type"] for row in links})
                    ),
                    "severity": source["severity"],
                    "confidence": source["confidence"],
                    "risk_score": risk["risk_score"] if risk else None,
                    "risk_record_key": risk["risk_key"] if risk else None,
                    "risk_assessed_at": (
                        risk["assessed_at"] if risk else None
                    ),
                    "identity_context": context(
                        "usernames", "service_accounts"
                    ),
                    "device_context": context(
                        "device_ids", "hostnames"
                    ),
                    "asset_context": context("asset_ids"),
                    "network_context": context(
                        "ip_addresses", "mac_addresses", "locations"
                    ),
                    "incident_owner": None,
                    "status": "New",
                    "source_first_evidence_time": (
                        source["first_evidence_time"]
                    ),
                    "source_last_evidence_time": (
                        source["last_evidence_time"]
                    ),
                    "created_at": now,
                    "updated_at": now,
                },
            )

            references = []
            for link in links:
                reference = (
                    "v2_xdr_incident_evidence:"
                    + link["evidence_link_key"]
                )
                references.append(reference)
                snapshot = canonical(dict(link))

                insert(
                    connection,
                    "v2_incident_evidence",
                    {
                        "evidence_link_key": (
                            "v2-managed-evidence-"
                            + digest(
                                canonical(
                                    [incident_id, link["evidence_key"]]
                                )
                            )
                        ),
                        "incident_id": incident_id,
                        "source_type": link["source_type"],
                        "source_record_id": link["source_record_id"],
                        "source_evidence_key": link["evidence_key"],
                        "evidence_time": link["event_time"],
                        "relationship": link["relationship"],
                        "contribution_status": (
                            link["contribution_status"]
                        ),
                        "evidence_reference": reference,
                        "evidence_json": snapshot,
                        "evidence_sha256": digest(snapshot),
                        "created_at": now,
                    },
                )

            details = canonical(
                {
                    "source_incident_key": source_key,
                    "source_snapshot": dict(source),
                    "source_snapshot_sha256": digest(
                        canonical(dict(source))
                    ),
                    "risk_snapshot": dict(risk) if risk else None,
                    "evidence_count": len(links),
                }
            )

            insert(
                connection,
                "v2_incident_timeline",
                {
                    "timeline_key": (
                        "v2-incident-created-" + digest(incident_id)
                    ),
                    "incident_id": incident_id,
                    "event_time": now,
                    "event_type": "incident_created",
                    "actor": "netshield01",
                    "action": "import_v2_stage11_incidents",
                    "previous_status": None,
                    "new_status": "New",
                    "details": details,
                    "evidence_references": canonical(references),
                },
            )

            insert(
                connection,
                "audit_events",
                {
                    "event_time": now,
                    "actor": "netshield01",
                    "action": "import_v2_stage11_incident",
                    "target": incident_id,
                    "result": "success",
                    "details": canonical(
                        {
                            "source_incident_key": source_key,
                            "evidence_count": len(links),
                        }
                    ),
                },
            )

            results.append(
                (
                    incident_id,
                    True,
                    "New",
                    risk["risk_score"] if risk else None,
                    len(links),
                )
            )

        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(
                "Foreign-key check failed; import rolled back"
            )

        insert(
            connection,
            "audit_events",
            {
                "event_time": now,
                "actor": "netshield01",
                "action": "import_v2_stage11_incidents",
                "target": "v2_incidents",
                "result": "success",
                "details": canonical(
                    {
                        "assessed": len(results),
                        "created": sum(row[1] for row in results),
                    }
                ),
            },
        )

    return results


def main():
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_incident_management.json"
    )

    results = import_incidents(
        PROJECT_ROOT / settings["database"]["path"],
        configuration,
    )

    for incident_id, created, status, risk, count in results:
        risk_text = (
            "Not yet assessed" if risk is None else f"{risk:.2f}"
        )
        print(
            f"[INCIDENT] id={incident_id} | status={status} | "
            f"risk={risk_text} | evidence={count} | "
            f"new={str(created).lower()}"
        )

    new = sum(row[1] for row in results)
    print(
        f"STAGE 11 INCIDENT IMPORT: incidents={len(results)} "
        f"new={new} existing={len(results) - new} "
        "automatic_actions=0"
    )


if __name__ == "__main__":
    main()
