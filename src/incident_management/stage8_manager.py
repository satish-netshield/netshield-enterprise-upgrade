"""Stage 8 incident management and evidence handling."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_ORDER = [
    "New",
    "Investigating",
    "Contained",
    "Eradicated",
    "Recovered",
    "Closed",
]

ALLOWED_TRANSITIONS = {
    "New": {"Investigating"},
    "Investigating": {"Contained", "Closed"},
    "Contained": {"Eradicated"},
    "Eradicated": {"Recovered"},
    "Recovered": {"Closed"},
    "Closed": set(),
}


def utc_now() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as evidence_file:
        for block in iter(lambda: evidence_file.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON object from disk."""
    with path.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)

    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")

    return value


def write_json(path: Path, value: Any) -> None:
    """Write formatted JSON to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as output_file:
        json.dump(value, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def write_text(path: Path, value: str) -> None:
    """Write UTF-8 text to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def incident_id(index: int, incident: dict[str, Any]) -> str:
    """Create a stable human-readable incident ID."""
    incident_key = incident.get("incident_key", f"incident-{index}")
    short_key = str(incident_key)[:12].upper()
    return f"INC-ST8-{index:03d}-{short_key}"


def validate_transition(current: str, new: str) -> None:
    """Validate a controlled incident-status transition."""
    if current not in STATUS_ORDER:
        raise ValueError(f"Unknown current status: {current}")

    if new not in STATUS_ORDER:
        raise ValueError(f"Unknown new status: {new}")

    if new not in ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"Invalid incident transition: {current} -> {new}")


def make_timeline() -> list[dict[str, str]]:
    """Create the initial incident timeline."""
    timestamp = utc_now()

    return [
        {
            "action": "Incident created from Stage 7 correlation output",
            "actor": "stage8_system",
            "timestamp": timestamp,
        },
        {
            "action": "Stage 7 evidence preserved and SHA-256 hash calculated",
            "actor": "stage8_system",
            "timestamp": timestamp,
        },
    ]


def make_audit_entry(
    incident_id_value: str,
    action: str,
    actor: str,
    details: str,
) -> dict[str, str]:
    """Create one audit-trail entry."""
    return {
        "incident_id": incident_id_value,
        "action": action,
        "actor": actor,
        "details": details,
        "timestamp": utc_now(),
    }


def build_investigation_note(incident: dict[str, Any]) -> str:
    """Create a short initial investigation note from the evidence."""
    severity = incident.get("severity", "Unknown")
    score = incident.get("risk_score", "Unknown")
    event_count = incident.get("event_count", 0)
    detection_types = ", ".join(incident.get("detection_types", []))
    source_types = ", ".join(incident.get("source_types", []))

    return (
        f"Initial review recorded a {severity} incident with risk score {score}. "
        f"The incident contains {event_count} related event(s) from "
        f"{source_types or 'unknown sources'}. "
        f"Detection types: {detection_types or 'none recorded'}."
    )


def build_human_report(incident: dict[str, Any]) -> str:
    """Create a human-readable incident report."""
    lines = [
        f"# {incident['incident_id']}",
        "",
        "## Incident Summary",
        "",
        f"- Detection name: {incident['detection_name']}",
        f"- Severity: {incident['severity']}",
        f"- Risk score: {incident['risk_score']}",
        f"- Status: {incident['status']}",
        f"- Event count: {incident['event_count']}",
        f"- First event: {incident['first_event_time']}",
        f"- Last event: {incident['last_event_time']}",
        "",
        "## Detection Types",
        "",
    ]

    for detection_type in incident["detection_types"]:
        lines.append(f"- {detection_type}")

    lines.extend(
        [
            "",
            "## Source Types",
            "",
        ]
    )

    for source_type in incident["source_types"]:
        lines.append(f"- {source_type}")

    lines.extend(
        [
            "",
            "## Investigation Note",
            "",
            incident["investigation_note"],
            "",
            "## Analyst Decision",
            "",
            incident["analyst_decision"],
            "",
            "## False-Positive Classification",
            "",
            f"- Classified as false positive: "
            f"{str(incident['false_positive']).lower()}",
            f"- Reason: {incident['false_positive_reason']}",
            "",
            "## IoCs",
            "",
        ]
    )

    if incident["iocs"]:
        for ioc in incident["iocs"]:
            lines.append(
                f"- {ioc.get('type', 'unknown')}: "
                f"{ioc.get('value', 'unknown')} "
                f"(source event {ioc.get('source_event_id', 'unknown')})"
            )
    else:
        lines.append("- None recorded")

    lines.extend(
        [
            "",
            "## Suspicious Behaviours",
            "",
        ]
    )

    if incident["behaviours"]:
        for behaviour in incident["behaviours"]:
            lines.append(f"- {behaviour}")
    else:
        lines.append("- None recorded")

    lines.extend(
        [
            "",
            "## Evidence",
            "",
            f"- Evidence file: {incident['evidence']['path']}",
            f"- SHA-256: {incident['evidence']['sha256']}",
            "",
            "## Timeline",
            "",
        ]
    )

    for entry in incident["timeline"]:
        lines.append(
            f"- {entry['timestamp']} — {entry['actor']}: "
            f"{entry['action']}"
        )

    lines.extend(
        [
            "",
            "## Source Event IDs",
            "",
        ]
    )

    for source_event_id in incident["source_event_ids"]:
        lines.append(f"- {source_event_id}")

    lines.append("")
    return "\n".join(lines)


def create_incident_records(
    stage7_report_path: Path,
    output_root: Path,
    analyst_name: str = "analyst01",
) -> dict[str, Any]:
    """Create Stage 8 incident records from a Stage 7 report."""
    stage7_report = load_json(stage7_report_path)
    source_incidents = stage7_report.get("incidents", [])

    if not isinstance(source_incidents, list):
        raise ValueError("Stage 7 report incidents must be a list")

    evidence_dir = output_root / "evidence"
    incident_dir = output_root / "incidents"
    report_dir = output_root / "reports"

    evidence_dir.mkdir(parents=True, exist_ok=True)
    incident_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    preserved_evidence = evidence_dir / "stage7_correlation_report.json"
    shutil.copy2(stage7_report_path, preserved_evidence)
    evidence_hash = sha256_file(preserved_evidence)

    records: list[dict[str, Any]] = []
    audit_trail: list[dict[str, str]] = []

    for index, source_incident in enumerate(source_incidents, start=1):
        current_incident_id = incident_id(index, source_incident)
        detection_types = source_incident.get("detection_types", [])
        source_types = source_incident.get("source_types", [])
        iocs = source_incident.get("iocs", [])
        behaviours = source_incident.get("behaviours", [])

        record = {
            "incident_id": current_incident_id,
            "detection_name": (
                detection_types[0]
                if detection_types
                else "Correlated security activity"
            ),
            "severity": source_incident.get("severity", "Low"),
            "risk_score": source_incident.get("risk_score", 0),
            "status": "New",
            "event_count": source_incident.get("event_count", 0),
            "first_event_time": source_incident.get(
                "first_event_time",
                "not recorded",
            ),
            "last_event_time": source_incident.get(
                "last_event_time",
                "not recorded",
            ),
            "detection_types": detection_types,
            "source_types": source_types,
            "source_event_ids": source_incident.get("source_event_ids", []),
            "identity": source_incident.get("identity", {}),
            "risk_reasons": source_incident.get("risk_reasons", []),
            "iocs": iocs,
            "behaviours": behaviours,
            "investigation_note": build_investigation_note(source_incident),
            "analyst_decision": (
                "Initial evidence preserved. Investigation required before "
                "any containment decision."
            ),
            "false_positive": False,
            "false_positive_reason": "Not classified as a false positive.",
            "evidence": {
                "path": str(preserved_evidence),
                "sha256": evidence_hash,
                "source_report": str(stage7_report_path),
            },
            "timeline": make_timeline(),
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }

        record_path = incident_dir / f"{current_incident_id}.json"
        report_path = report_dir / f"{current_incident_id}.md"

        write_json(record_path, record)
        write_text(report_path, build_human_report(record))

        audit_trail.append(
            make_audit_entry(
                current_incident_id,
                "incident_created",
                "stage8_system",
                f"Created from Stage 7 incident index {index}.",
            )
        )
        audit_trail.append(
            make_audit_entry(
                current_incident_id,
                "evidence_preserved",
                "stage8_system",
                f"Evidence SHA-256: {evidence_hash}.",
            )
        )
        audit_trail.append(
            make_audit_entry(
                current_incident_id,
                "analyst_decision_recorded",
                analyst_name,
                "Initial investigation required; no containment authorised.",
            )
        )

        records.append(record)

    audit_path = output_root / "audit_trail.jsonl"
    audit_lines = "\n".join(
        json.dumps(entry, sort_keys=True) for entry in audit_trail
    )
    write_text(audit_path, f"{audit_lines}\n" if audit_lines else "")

    summary = {
        "stage": 8,
        "scope": "Incident management and evidence handling",
        "source_report": str(stage7_report_path),
        "incidents_created": len(records),
        "incident_statuses": {
            "New": len(records),
            "Investigating": 0,
            "Contained": 0,
            "Eradicated": 0,
            "Recovered": 0,
            "Closed": 0,
        },
        "evidence_sha256": evidence_hash,
        "audit_entries": len(audit_trail),
        "automatic_containment": False,
        "external_targets_used": False,
        "records": [
            {
                "incident_id": record["incident_id"],
                "severity": record["severity"],
                "risk_score": record["risk_score"],
                "status": record["status"],
                "evidence_sha256": record["evidence"]["sha256"],
            }
            for record in records
        ],
    }

    write_json(output_root / "stage8_incident_summary.json", summary)
    return summary


def main() -> None:
    """Run Stage 8 incident creation."""
    project_root = Path(__file__).resolve().parents[2]
    stage7_report = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage7_correlation_report.json"
    )
    output_root = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage8"
    )

    summary = create_incident_records(stage7_report, output_root)

    print("STAGE 8 INCIDENT MANAGEMENT")
    print(f"STAGE 7 INCIDENTS RECEIVED: {summary['incidents_created']}")
    print(f"INCIDENT RECORDS CREATED: {summary['incidents_created']}")
    print(f"AUDIT ENTRIES: {summary['audit_entries']}")
    print(f"EVIDENCE SHA256: {summary['evidence_sha256']}")
    print(
        "AUTOMATIC CONTAINMENT: "
        f"{str(summary['automatic_containment']).lower()}"
    )
    print(f"OUTPUT: {output_root / 'stage8_incident_summary.json'}")


if __name__ == "__main__":
    main()
