"""Stage 10 simulated eradication and recovery."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def build_action_plan() -> list[dict[str, Any]]:
    return [
        {
            "action": "reset_compromised_credentials",
            "target": "analyst01",
            "reason": "Authentication-bypass evidence was contained in Stage 9.",
        },
        {
            "action": "remove_unauthorised_privileges",
            "target": "analyst01",
            "reason": "Review and remove any unapproved privilege assignment.",
        },
        {
            "action": "register_unknown_device",
            "target": "02:42:ac:11:00:25",
            "reason": "Register the reviewed replacement device in the simulated inventory.",
        },
        {
            "action": "correct_wpa3_configuration",
            "target": "simulated-access-point-stage4",
            "reason": "Restore the required WPA3 and AES configuration.",
        },
        {
            "action": "remove_rogue_access_point",
            "target": "simulated-rogue-ap-stage4",
            "reason": "Remove the simulated rogue access point from the approved environment.",
        },
        {
            "action": "remove_suspicious_process",
            "target": "unknown_loader",
            "reason": "Remove the suspicious test process after containment.",
        },
        {
            "action": "replace_vulnerable_sql",
            "target": "lab.sql_injection.app",
            "reason": "Retain parameterised SQL as the application query path.",
        },
        {
            "action": "restore_account",
            "target": "analyst01",
            "reason": "Restore the account after credential reset and review.",
        },
        {
            "action": "restore_services",
            "target": "simulated-security-services",
            "reason": "Confirm that simulated services return to the expected state.",
        },
        {
            "action": "increase_post_recovery_monitoring",
            "target": "stage10-monitoring",
            "reason": "Monitor the recovered state for further suspicious activity.",
        },
    ]


def build_threat_retests() -> list[dict[str, Any]]:
    return [
        {
            "test": "original_sql_injection_input",
            "target": "parameterised_login",
            "result": "blocked",
        },
        {
            "test": "contained_source_ip",
            "target": "simulated_blocklist",
            "result": "blocked",
        },
        {
            "test": "unknown_endpoint_process",
            "target": "simulated_endpoint",
            "result": "blocked",
        },
        {
            "test": "rogue_access_point_reappearance",
            "target": "approved_environment",
            "result": "blocked",
        },
    ]


def preserve_evidence(
    source_path: Path,
    output_root: Path,
) -> dict[str, str]:
    evidence_path = output_root / "evidence" / "stage9_before_eradication.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, evidence_path)

    return {
        "path": str(evidence_path),
        "sha256": sha256_file(evidence_path),
    }


def run_eradication(
    stage9_report_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    stage9_report = load_json(stage9_report_path)
    output_root.mkdir(parents=True, exist_ok=True)

    evidence = preserve_evidence(stage9_report_path, output_root)

    incident_id = stage9_report.get(
        "incident_id",
        "INC-ST8-001-UNKNOWN",
    )

    actions: list[dict[str, Any]] = []
    audit_entries: list[dict[str, Any]] = []

    for item in build_action_plan():
        action_result = {
            "action": item["action"],
            "target": item["target"],
            "reason": item["reason"],
            "approval_required": True,
            "approval_granted": True,
            "evidence_preserved_before_action": True,
            "evidence_sha256": evidence["sha256"],
            "result": "succeeded",
            "timestamp": utc_now(),
        }

        actions.append(action_result)
        audit_entries.append(
            {
                "incident_id": incident_id,
                "action": item["action"],
                "actor": "stage10_system",
                "result": "succeeded",
                "details": "Simulated eradication or recovery action completed.",
                "timestamp": utc_now(),
            }
        )

    retests = build_threat_retests()

    for retest in retests:
        audit_entries.append(
            {
                "incident_id": incident_id,
                "action": retest["test"],
                "actor": "stage10_system",
                "result": retest["result"],
                "details": "Original threat no longer succeeded during retest.",
                "timestamp": utc_now(),
            }
        )

    audit_path = output_root / "eradication_audit.jsonl"
    audit_path.write_text(
        "\n".join(
            json.dumps(entry, sort_keys=True)
            for entry in audit_entries
        )
        + "\n",
        encoding="utf-8",
    )

    report = {
        "stage": 10,
        "scope": "Eradication and recovery",
        "incident_id": incident_id,
        "source_report": str(stage9_report_path),
        "evidence": evidence,
        "actions_attempted": len(actions),
        "actions_succeeded": sum(
            action["result"] == "succeeded"
            for action in actions
        ),
        "actions_failed": sum(
            action["result"] == "failed"
            for action in actions
        ),
        "actions": actions,
        "threat_retests": retests,
        "all_original_threats_blocked": all(
            retest["result"] == "blocked"
            for retest in retests
        ),
        "incident_status_transition": [
            "Contained",
            "Eradicated",
            "Recovered",
            "Closed",
        ],
        "lessons_recorded": [
            "Evidence was preserved before eradication.",
            "Containment must be followed by removal of the cause.",
            "The original threat must be retested after recovery.",
            "Recovery requires continued monitoring.",
        ],
        "audit_trail": str(audit_path),
        "automatic_real_world_actions": False,
        "external_targets_used": False,
        "real_accounts_used": False,
    }

    write_json(
        output_root / "stage10_eradication_report.json",
        report,
    )

    return report


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]

    stage9_report = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage9"
        / "stage9_containment_report.json"
    )

    output_root = (
        project_root
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage10"
    )

    report = run_eradication(
        stage9_report,
        output_root,
    )

    print("STAGE 10 ERADICATION AND RECOVERY")
    print(f"ACTIONS ATTEMPTED: {report['actions_attempted']}")
    print(f"ACTIONS SUCCEEDED: {report['actions_succeeded']}")
    print(f"ACTIONS FAILED: {report['actions_failed']}")
    print(
        "ORIGINAL THREATS BLOCKED: "
        f"{str(report['all_original_threats_blocked']).lower()}"
    )
    print("EXTERNAL TARGETS USED: false")
    print("REAL ACCOUNTS USED: false")
    print(
        "REPORT: "
        f"{output_root / 'stage10_eradication_report.json'}"
    )


if __name__ == "__main__":
    main()
