"""Validate Stage 9 controlled containment automation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = (
    PROJECT_ROOT
    / "lab"
    / "sql_injection"
    / "outputs"
    / "stage9"
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
    report_path = OUTPUT_ROOT / "stage9_containment_report.json"
    audit_path = OUTPUT_ROOT / "containment_audit.jsonl"

    check(
        report_path.exists(),
        "Stage 9 containment report exists",
    )
    check(
        audit_path.exists(),
        "Stage 9 containment audit exists",
    )

    report = load_json(report_path)

    check(
        report.get("stage") == 9,
        "Stage 9 metadata is correct",
    )
    check(
        report.get("scope") == "Controlled containment automation",
        "Stage 9 scope is correct",
    )
    check(
        report.get("actions_attempted") == 6,
        "Six containment actions were attempted",
    )
    check(
        report.get("actions_succeeded") == 5,
        "Five containment actions succeeded",
    )
    check(
        report.get("actions_failed") == 1,
        "One containment action failed",
    )
    check(
        report.get("automatic_containment") is False,
        "Automatic real-world containment remains disabled",
    )
    check(
        report.get("external_targets_used") is False,
        "External targets were not used",
    )
    check(
        report.get("real_accounts_used") is False,
        "Real accounts were not used",
    )

    actions = report.get("actions", [])

    check(
        len(actions) == 6,
        "Six action results are recorded",
    )
    check(
        all(
            action.get("evidence_preserved_before_action") is True
            for action in actions
        ),
        "Evidence was preserved before every action",
    )
    check(
        all(
            action.get("result") in {"succeeded", "failed"}
            for action in actions
        ),
        "Every action records succeeded or failed",
    )

    evidence = report.get("evidence", {})
    evidence_path = Path(evidence["path"])

    check(
        evidence_path.exists(),
        "Pre-containment evidence file exists",
    )
    check(
        evidence.get("sha256") == sha256_file(evidence_path),
        "Pre-containment evidence hash is valid",
    )

    blocklist_actions = [
        action
        for action in actions
        if action.get("action") == "add_to_simulated_blocklist"
    ]
    check(
        len(blocklist_actions) == 1
        and blocklist_actions[0]["result"] == "succeeded"
        and blocklist_actions[0]["approval_required"] is False,
        "Simulated blocklist action succeeded automatically",
    )

    disruptive_actions = [
        action
        for action in actions
        if action.get("approval_required") is True
    ]

    check(
        len(disruptive_actions) == 5,
        "Five disruptive actions require approval",
    )

    approved_actions = [
        action
        for action in disruptive_actions
        if action.get("approval_granted") is True
    ]
    failed_actions = [
        action
        for action in disruptive_actions
        if action.get("result") == "failed"
    ]

    check(
        len(approved_actions) == 4,
        "Four disruptive actions received approval",
    )
    check(
        len(failed_actions) == 1,
        "One disruptive action was rejected without approval",
    )
    check(
        failed_actions[0]["action"] == "reject_wifi_connection",
        "Non-compliant Wi-Fi rejection was blocked without approval",
    )

    audit_lines = [
        line
        for line in audit_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    check(
        len(audit_lines) == 6,
        "Audit trail contains one entry per action",
    )

    audit_entries = [json.loads(line) for line in audit_lines]

    check(
        all(
            entry.get("result") in {"succeeded", "failed"}
            for entry in audit_entries
        ),
        "Audit trail records every action result",
    )

    print()
    print("STAGE 9 VALIDATION: PASS")


if __name__ == "__main__":
    main()
