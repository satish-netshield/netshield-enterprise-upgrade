"""Validate Stage 10 eradication and recovery evidence."""

from __future__ import annotations

import json
from pathlib import Path


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")

    print(f"PASS: {message}")


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    output_root = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage10"
    )

    report_path = output_root / "stage10_eradication_report.json"
    audit_path = output_root / "eradication_audit.jsonl"
    evidence_path = output_root / "evidence" / "stage9_before_eradication.json"

    check(report_path.exists(), "Stage 10 report exists")
    check(audit_path.exists(), "Stage 10 audit trail exists")
    check(evidence_path.exists(), "Pre-eradication evidence exists")

    report = load_json(report_path)

    check(report["stage"] == 10, "Stage 10 metadata is correct")
    check(
        report["scope"] == "Eradication and recovery",
        "Stage 10 scope is correct",
    )
    check(
        report["actions_attempted"] == 10,
        "Ten eradication and recovery actions were attempted",
    )
    check(
        report["actions_succeeded"] == 10,
        "Ten eradication and recovery actions succeeded",
    )
    check(
        report["actions_failed"] == 0,
        "No Stage 10 action failed",
    )
    check(
        report["all_original_threats_blocked"],
        "Original threats no longer succeed",
    )
    check(
        report["incident_status_transition"]
        == ["Contained", "Eradicated", "Recovered", "Closed"],
        "Incident lifecycle reaches closure",
    )
    check(
        all(
            action["evidence_preserved_before_action"]
            for action in report["actions"]
        ),
        "Evidence was preserved before every action",
    )
    check(
        all(
            item["result"] == "blocked"
            for item in report["threat_retests"]
        ),
        "All threat retests were blocked",
    )
    check(
        report["automatic_real_world_actions"] is False,
        "Automatic real-world actions remain disabled",
    )
    check(
        report["external_targets_used"] is False,
        "External targets were not used",
    )
    check(
        report["real_accounts_used"] is False,
        "Real accounts were not used",
    )

    audit_entries = [
        json.loads(line)
        for line in audit_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    check(
        len(audit_entries) == 14,
        "Audit trail records ten actions and four retests",
    )
    check(
        len(report["lessons_recorded"]) == 4,
        "Stage 10 lessons were recorded",
    )

    print("STAGE 10 VALIDATION: PASS")


if __name__ == "__main__":
    main()
