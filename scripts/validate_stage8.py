"""Validate Stage 8 incident management and evidence handling."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = (
    PROJECT_ROOT
    / "lab"
    / "sql_injection"
    / "outputs"
    / "stage8"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)

    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as evidence_file:
        for block in iter(lambda: evidence_file.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}")
        raise SystemExit(1)

    print(f"PASS: {message}")


def main() -> None:
    summary_path = OUTPUT_ROOT / "stage8_incident_summary.json"
    evidence_path = (
        OUTPUT_ROOT
        / "evidence"
        / "stage7_correlation_report.json"
    )
    audit_path = OUTPUT_ROOT / "audit_trail.jsonl"
    incident_dir = OUTPUT_ROOT / "incidents"
    report_dir = OUTPUT_ROOT / "reports"

    check(summary_path.exists(), "Stage 8 summary exists")
    check(evidence_path.exists(), "Preserved Stage 7 evidence exists")
    check(audit_path.exists(), "Complete audit trail exists")

    summary = load_json(summary_path)

    check(
        summary.get("stage") == 8,
        "Stage 8 metadata is correct",
    )
    check(
        summary.get("scope")
        == "Incident management and evidence handling",
        "Stage 8 scope is correct",
    )
    check(
        summary.get("incidents_created") == 3,
        "Three incident records were created",
    )
    check(
        summary.get("automatic_containment") is False,
        "Automatic containment remains disabled",
    )
    check(
        summary.get("external_targets_used") is False,
        "External targets were not used",
    )

    incident_files = sorted(incident_dir.glob("*.json"))
    report_files = sorted(report_dir.glob("*.md"))

    check(
        len(incident_files) == 3,
        "Three incident JSON records exist",
    )
    check(
        len(report_files) == 3,
        "Three human-readable incident reports exist",
    )

    records = [load_json(path) for path in incident_files]
    incident_ids = {record.get("incident_id") for record in records}

    check(
        len(incident_ids) == 3 and None not in incident_ids,
        "Incident IDs are unique",
    )
    check(
        all(record.get("status") == "New" for record in records),
        "All incidents start in New status",
    )
    check(
        all(record.get("detection_name") for record in records),
        "Every incident has a detection name",
    )
    check(
        all("risk_score" in record for record in records),
        "Every incident has a risk score",
    )
    check(
        all("investigation_note" in record for record in records),
        "Investigation notes are recorded",
    )
    check(
        all("analyst_decision" in record for record in records),
        "Analyst decisions are recorded",
    )
    check(
        all("false_positive" in record for record in records),
        "False-positive classification is recorded",
    )
    check(
        all(record.get("timeline") for record in records),
        "Incident timelines contain entries",
    )
    check(
        all(record.get("iocs") is not None for record in records),
        "IoC tables are present",
    )

    expected_hash = sha256_file(evidence_path)

    check(
        summary.get("evidence_sha256") == expected_hash,
        "Summary evidence hash matches the preserved file",
    )
    check(
        all(
            record.get("evidence", {}).get("sha256") == expected_hash
            for record in records
        ),
        "Incident evidence hashes match the preserved file",
    )

    audit_lines = [
        line
        for line in audit_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    check(
        len(audit_lines) == 9,
        "Nine audit entries are recorded",
    )

    audit_entries = [json.loads(line) for line in audit_lines]
    audit_actions = {entry.get("action") for entry in audit_entries}

    check(
        audit_actions
        == {
            "incident_created",
            "evidence_preserved",
            "analyst_decision_recorded",
        },
        "Audit trail contains the required action types",
    )

    first_report = report_files[0].read_text(encoding="utf-8")

    check(
        "## Investigation Note" in first_report,
        "Human report contains investigation notes",
    )
    check(
        "## Analyst Decision" in first_report,
        "Human report contains analyst decisions",
    )
    check(
        "## False-Positive Classification" in first_report,
        "Human report contains false-positive classification",
    )
    check(
        "## IoCs" in first_report,
        "Human report contains the IoC table",
    )
    check(
        "## Evidence" in first_report,
        "Human report contains evidence details",
    )
    check(
        "## Timeline" in first_report,
        "Human report contains the action timeline",
    )

    print()
    print("STAGE 8 VALIDATION: PASS")


if __name__ == "__main__":
    main()
