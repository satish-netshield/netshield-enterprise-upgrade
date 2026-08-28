"""Stage 9 controlled containment automation."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APPROVAL_REQUIRED = {
    "restrict_account",
    "revoke_session",
    "terminate_process",
    "quarantine_device",
    "reject_wifi_connection",
}

AUTOMATIC_ACTIONS = {
    "add_to_simulated_blocklist",
    "increase_monitoring",
}

ALLOWED_ACTIONS = APPROVAL_REQUIRED | AUTOMATIC_ACTIONS


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as evidence_file:
        for block in iter(lambda: evidence_file.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)

    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as output_file:
        json.dump(value, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def make_audit_entry(
    incident_id: str,
    action: str,
    actor: str,
    result: str,
    details: str,
) -> dict[str, str]:
    return {
        "incident_id": incident_id,
        "action": action,
        "actor": actor,
        "result": result,
        "details": details,
        "timestamp": utc_now(),
    }


def preserve_evidence(
    source_path: Path,
    evidence_root: Path,
    incident_id: str,
) -> dict[str, str]:
    evidence_root.mkdir(parents=True, exist_ok=True)

    destination = evidence_root / f"{incident_id}_before_containment.json"
    shutil.copy2(source_path, destination)

    return {
        "path": str(destination),
        "sha256": sha256_file(destination),
    }


def simulated_action_result(
    action: str,
    approval_granted: bool,
) -> tuple[str, str]:
    if action not in ALLOWED_ACTIONS:
        return (
            "failed",
            "Action is not defined as an allowed Stage 9 action.",
        )

    if action in APPROVAL_REQUIRED and not approval_granted:
        return (
            "failed",
            "Approval is required before this disruptive action.",
        )

    return (
        "succeeded",
        "Simulated containment action completed inside the sandbox.",
    )


def build_action_plan() -> list[dict[str, Any]]:
    return [
        {
            "action": "add_to_simulated_blocklist",
            "target": "192.0.2.44",
            "approval_granted": False,
            "reason": "Suspicious source IP from the Critical incident.",
        },
        {
            "action": "quarantine_device",
            "target": "02:42:ac:11:00:25",
            "approval_granted": True,
            "reason": "Unknown endpoint evidence requires approved quarantine.",
        },
        {
            "action": "restrict_account",
            "target": "analyst01",
            "approval_granted": True,
            "reason": "Authentication-bypass evidence requires account review.",
        },
        {
            "action": "revoke_session",
            "target": "analyst01-session-stage9",
            "approval_granted": True,
            "reason": "Simulated session is linked to suspicious activity.",
        },
        {
            "action": "terminate_process",
            "target": "unknown_loader",
            "approval_granted": True,
            "reason": "Unknown endpoint process requires approved isolation.",
        },
        {
            "action": "reject_wifi_connection",
            "target": "02:42:ac:11:00:77",
            "approval_granted": False,
            "reason": "Non-compliant Wi-Fi access requires approval.",
        },
    ]


def run_containment(
    stage8_summary_path: Path,
    stage7_report_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    stage8_summary = load_json(stage8_summary_path)
    load_json(stage7_report_path)

    output_root.mkdir(parents=True, exist_ok=True)

    evidence = preserve_evidence(
        stage7_report_path,
        output_root / "evidence",
        "stage8-source",
    )

    incident_records = stage8_summary.get("records", [])
    if not incident_records:
        raise ValueError("Stage 8 summary does not contain incident records")

    incident_id = incident_records[0]["incident_id"]
    action_plan = build_action_plan()

    action_results: list[dict[str, Any]] = []
    audit_entries: list[dict[str, str]] = []

    for item in action_plan:
        action = item["action"]
        approval_granted = item["approval_granted"]
        result, details = simulated_action_result(
            action,
            approval_granted,
        )

        action_result = {
            "action": action,
            "target": item["target"],
            "approval_required": action in APPROVAL_REQUIRED,
            "approval_granted": approval_granted,
            "evidence_preserved_before_action": True,
            "evidence_sha256": evidence["sha256"],
            "result": result,
            "reason": item["reason"],
            "details": details,
            "timestamp": utc_now(),
        }

        action_results.append(action_result)
        audit_entries.append(
            make_audit_entry(
                incident_id,
                action,
                "stage9_system",
                result,
                details,
            )
        )

    audit_path = output_root / "containment_audit.jsonl"
    audit_lines = "\n".join(
        json.dumps(entry, sort_keys=True)
        for entry in audit_entries
    )
    audit_path.write_text(
        f"{audit_lines}\n" if audit_lines else "",
        encoding="utf-8",
    )

    succeeded = sum(
        result["result"] == "succeeded"
        for result in action_results
    )
    failed = sum(
        result["result"] == "failed"
        for result in action_results
    )

    report = {
        "stage": 9,
        "scope": "Controlled containment automation",
        "incident_id": incident_id,
        "actions_attempted": len(action_results),
        "actions_succeeded": succeeded,
        "actions_failed": failed,
        "evidence": evidence,
        "automatic_containment": False,
        "external_targets_used": False,
        "real_accounts_used": False,
        "actions": action_results,
        "audit_trail": str(audit_path),
    }

    write_json(output_root / "stage9_containment_report.json", report)
    return report


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]

    stage8_summary = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage8"
        / "stage8_incident_summary.json"
    )
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
        / "stage9"
    )

    report = run_containment(
        stage8_summary,
        stage7_report,
        output_root,
    )

    print("STAGE 9 CONTROLLED CONTAINMENT")
    print(f"ACTIONS ATTEMPTED: {report['actions_attempted']}")
    print(f"ACTIONS SUCCEEDED: {report['actions_succeeded']}")
    print(f"ACTIONS FAILED: {report['actions_failed']}")
    print(
        "EVIDENCE PRESERVED BEFORE ACTION: "
        f"{report['evidence']['sha256']}"
    )
    print("EXTERNAL TARGETS USED: false")
    print("REAL ACCOUNTS USED: false")
    print(
        "REPORT: "
        f"{output_root / 'stage9_containment_report.json'}"
    )


if __name__ == "__main__":
    main()
