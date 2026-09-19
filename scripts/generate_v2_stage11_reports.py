"""Generate duplicate-safe JSON and readable reports for Stage 11 incidents."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from scripts.import_v2_stage11_incidents import canonical, digest, insert
from src.utils.config_loader import load_json
from src.utils.database import utc_now
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


def fetch_report(connection, incident_id):
    """Build a report from database records, not recalculated evidence."""
    incident = connection.execute(
        "SELECT * FROM v2_incidents WHERE incident_id=?",
        (incident_id,),
    ).fetchone()

    if incident is None:
        raise ValueError(f"Unknown incident: {incident_id}")

    def rows(table, order):
        return [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} "
                f"WHERE incident_id=? ORDER BY {order}",
                (incident_id,),
            )
        ]

    data = dict(incident)
    data["investigation_notes"] = json.loads(
        data["investigation_notes"]
    )
    data["analyst_decisions"] = json.loads(
        data["analyst_decisions"]
    )
    data["detection_sources"] = json.loads(
        data["detection_sources"]
    )
    data["identity_context"] = json.loads(
        data["identity_context"]
    )
    data["device_context"] = json.loads(
        data["device_context"]
    )
    data["asset_context"] = json.loads(
        data["asset_context"]
    )
    data["network_context"] = json.loads(
        data["network_context"]
    )
    data["risk_display"] = (
        "Not yet assessed"
        if data["risk_score"] is None
        else data["risk_score"]
    )

    evidence = rows(
        "v2_incident_evidence",
        "evidence_time, source_type",
    )
    for row in evidence:
        row["evidence"] = json.loads(
            row.pop("evidence_json")
        )
    data["evidence"] = evidence

    data["iocs"] = rows(
        "v2_incident_iocs",
        "ioc_type, ioc_value",
    )
    data["behaviours"] = rows(
        "v2_incident_behaviours",
        "behaviour_name",
    )
    data["attack_references"] = rows(
        "v2_incident_attack_references",
        "technique_id",
    )
    data["decisions"] = rows(
        "v2_incident_decisions",
        "decision_time",
    )
    data["timeline"] = rows(
        "v2_incident_timeline",
        "event_time, incident_timeline_id",
    )
    data["approvals"] = rows(
        "v2_incident_approvals",
        "incident_approval_id",
    )
    data["vulnerability_links"] = rows(
        "v2_incident_vulnerability_links",
        "source_finding_id",
    )

    for row in data["decisions"]:
        row["evidence_references"] = json.loads(
            row["evidence_references"]
        )

    for row in data["timeline"]:
        row["evidence_references"] = json.loads(
            row["evidence_references"]
        )

    for row in data["vulnerability_links"]:
        row["evidence_references"] = json.loads(
            row["evidence_references"]
        )

    return data


def readable(data):
    """Render a compact report for human review."""
    lines = [
        f"Incident ID: {data['incident_id']}",
        f"Title: {data['title']}",
        f"Status: {data['status']}",
        f"Severity: {data['severity']}",
        f"Confidence: {data['confidence']}",
        f"Risk score: {data['risk_display']}",
        f"Owner: {data['incident_owner'] or 'Unassigned'}",
        "Detection sources: "
        + ", ".join(data["detection_sources"]),
        "",
        "Identity context:",
        json.dumps(
            data["identity_context"],
            sort_keys=True,
        ),
        "Device context:",
        json.dumps(
            data["device_context"],
            sort_keys=True,
        ),
        "Asset context:",
        json.dumps(
            data["asset_context"],
            sort_keys=True,
        ),
        "Network context:",
        json.dumps(
            data["network_context"],
            sort_keys=True,
        ),
        "",
        f"Evidence records: {len(data['evidence'])}",
        f"IoCs: {len(data['iocs'])}",
        f"Behaviours: {len(data['behaviours'])}",
        (
            "ATT&CK references: "
            f"{len(data['attack_references'])}"
        ),
        (
            "Linked vulnerabilities: "
            f"{len(data['vulnerability_links'])}"
        ),
        (
            "Investigation decisions: "
            f"{len(data['decisions'])}"
        ),
        f"Timeline records: {len(data['timeline'])}",
        "",
        "Evidence SHA-256 values:",
    ]

    lines.extend(
        (
            f"- {row['source_evidence_key']}: "
            f"{row['evidence_sha256']}"
        )
        for row in data["evidence"]
    )

    lines.extend(["", "Investigation notes:"])
    lines.extend(
        f"- {note.get('event_time')}: {note.get('notes')}"
        for note in data["investigation_notes"]
    )

    return "\n".join(lines) + "\n"


def generate(database, configuration, incident_id=None):
    """Write both formats once and preserve hashes on repeat runs."""
    json_dir = ROOT / configuration["reporting"][
        "json_output_directory"
    ]
    text_dir = ROOT / configuration["reporting"][
        "text_output_directory"
    ]

    json_dir.mkdir(parents=True, exist_ok=True)
    text_dir.mkdir(parents=True, exist_ok=True)

    with managed_connection(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")

        ids = (
            [incident_id]
            if incident_id
            else [
                row[0]
                for row in connection.execute(
                    "SELECT incident_id FROM v2_incidents "
                    "ORDER BY managed_incident_id"
                )
            ]
        )

        results = []

        for current_id in ids:
            data = fetch_report(connection, current_id)

            json_text = (
                json.dumps(
                    data,
                    sort_keys=True,
                    indent=2,
                    default=str,
                )
                + "\n"
            )
            text = readable(data)

            json_path = json_dir / f"{current_id}.json"
            text_path = text_dir / f"{current_id}.txt"

            values = [
                ("json", json_path, json_text),
                ("text", text_path, text),
            ]

            for report_type, path, content in values:
                content_hash = digest(content)
                report_key = (
                    f"v2-report-{report_type}-"
                    f"{digest(current_id)}"
                )

                existing = connection.execute(
                    "SELECT report_path, report_sha256 "
                    "FROM v2_incident_reports "
                    "WHERE report_key=?",
                    (report_key,),
                ).fetchone()

                if existing:
                    if (
                        existing["report_sha256"] != content_hash
                        or not path.is_file()
                    ):
                        raise RuntimeError(
                            f"Report mismatch: "
                            f"{current_id} {report_type}"
                        )
                    continue

                path.write_text(content, encoding="utf-8")

                insert(
                    connection,
                    "v2_incident_reports",
                    {
                        "report_key": report_key,
                        "incident_id": current_id,
                        "report_type": report_type,
                        "report_path": str(
                            path.relative_to(ROOT)
                        ),
                        "report_sha256": content_hash,
                        "generated_at": utc_now(),
                        "generated_by": "netshield01",
                    },
                )

            timeline_key = (
                "v2-report-generated-" + digest(current_id)
            )

            if not connection.execute(
                "SELECT 1 FROM v2_incident_timeline "
                "WHERE timeline_key=?",
                (timeline_key,),
            ).fetchone():
                insert(
                    connection,
                    "v2_incident_timeline",
                    {
                        "timeline_key": timeline_key,
                        "incident_id": current_id,
                        "event_time": utc_now(),
                        "event_type": "report_generated",
                        "actor": "netshield01",
                        "action": (
                            "generate_v2_stage11_reports"
                        ),
                        "previous_status": data["status"],
                        "new_status": data["status"],
                        "details": canonical(
                            {
                                "json_sha256": digest(json_text),
                                "text_sha256": digest(text),
                            }
                        ),
                        "evidence_references": "[]",
                    },
                )

            results.append(
                (current_id, len(data["evidence"]))
            )

        insert(
            connection,
            "audit_events",
            {
                "event_time": utc_now(),
                "actor": "netshield01",
                "action": "generate_v2_stage11_reports",
                "target": "v2_incidents",
                "result": "success",
                "details": canonical(
                    {"incidents": len(results)}
                ),
            },
        )

    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident")
    args = parser.parse_args()

    settings = load_json(ROOT / "config/settings.json")
    configuration = load_json(
        ROOT / "config/v2_incident_management.json"
    )

    results = generate(
        ROOT / settings["database"]["path"],
        configuration,
        args.incident,
    )

    for incident_id, evidence_count in results:
        print(
            f"[REPORT] incident={incident_id} | "
            f"evidence={evidence_count} | "
            "json=true | text=true"
        )

    print(
        f"STAGE 11 REPORTS: incidents={len(results)} "
        "duplicate_safe=true"
    )


if __name__ == "__main__":
    main()
