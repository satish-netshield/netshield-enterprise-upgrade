"""Manage simulated V2 Stage 13 eradication, recovery and review."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from src.response.v2_eradication_recovery import (
    RecoveryError,
    close_after_review,
    complete_eradication,
    complete_recovery,
    confirm_containment,
    decide_action,
    execute_action,
    record_retest,
    request_action,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_runtime() -> tuple[
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Load the database path and Stage 13 control files."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_eradication_recovery.json"
    )
    acl = load_json(PROJECT_ROOT / "config/automation_acl.json")
    rbac = load_json(PROJECT_ROOT / "config/rbac.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]
    return database_path, configuration, acl, rbac


def add_common_incident_arguments(parser: argparse.ArgumentParser) -> None:
    """Add fields shared by lifecycle commands."""
    parser.add_argument("--incident", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--notes", required=True)
    parser.add_argument("--request-id", required=True)


def build_parser() -> argparse.ArgumentParser:
    """Build the Stage 13 command interface."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    confirm = commands.add_parser(
        "confirm-containment",
        help="Confirm successful active Stage 12 containment.",
    )
    add_common_incident_arguments(confirm)

    request = commands.add_parser(
        "request",
        help="Request an evidence-backed Stage 13 action.",
    )
    request.add_argument("--incident", required=True)
    request.add_argument("--action", required=True)
    request.add_argument("--target-type", required=True)
    request.add_argument("--target", required=True)
    request.add_argument("--actor", required=True)
    request.add_argument("--reason", required=True)
    request.add_argument(
        "--evidence",
        action="append",
        required=True,
        help="Incident evidence reference; repeat for more than one.",
    )
    request.add_argument("--request-id", required=True)

    decide = commands.add_parser(
        "decide",
        help="Approve or deny a requested Stage 13 action.",
    )
    decide.add_argument("--action-id", required=True, type=int)
    decide.add_argument("--actor", required=True)
    decide.add_argument(
        "--decision",
        required=True,
        choices=("approved", "denied"),
    )
    decide.add_argument("--notes", required=True)

    execute = commands.add_parser(
        "execute",
        help="Record an approved simulated action result.",
    )
    execute.add_argument("--action-id", required=True, type=int)
    execute.add_argument("--actor", required=True)
    execute.add_argument(
        "--outcome",
        default="successful",
        choices=("successful", "failed"),
    )
    execute.add_argument("--details", required=True)

    eradicate = commands.add_parser(
        "complete-eradication",
        help="Move a contained incident to Eradicated.",
    )
    add_common_incident_arguments(eradicate)

    retest = commands.add_parser(
        "retest",
        help="Retest an original threat or vulnerability.",
    )
    retest.add_argument("--incident", required=True)
    retest.add_argument(
        "--type",
        required=True,
        choices=("original_threat", "original_vulnerability"),
    )
    retest.add_argument("--target-type", required=True)
    retest.add_argument("--target", required=True)
    retest.add_argument("--description", required=True)
    retest.add_argument(
        "--result",
        required=True,
        choices=("blocked", "succeeded", "error"),
    )
    retest.add_argument(
        "--evidence",
        action="append",
        required=True,
    )
    retest.add_argument("--actor", required=True)
    retest.add_argument("--request-id", required=True)

    recover = commands.add_parser(
        "complete-recovery",
        help="Move a verified incident to Recovered.",
    )
    add_common_incident_arguments(recover)

    close = commands.add_parser(
        "close",
        help="Complete post-incident review and verified closure.",
    )
    close.add_argument("--incident", required=True)
    close.add_argument("--actor", required=True)
    close.add_argument("--lessons", required=True)
    close.add_argument("--detection-improvement", required=True)
    close.add_argument("--policy-improvement", required=True)
    close.add_argument("--closure-reason", required=True)
    close.add_argument("--request-id", required=True)

    return parser


def print_action(result: dict[str, Any]) -> None:
    """Print one concise action result."""
    print(
        "[RECOVERY ACTION] "
        f"id={result['recovery_action_id']} | "
        f"incident={result['incident_id']} | "
        f"phase={result['phase']} | "
        f"action={result['action_type']} | "
        f"target={result['target_type']}:{result['target_value']} | "
        f"control={result['control_level']} | "
        f"status={result['status']} | "
        f"evidence_preserved="
        f"{str(result['evidence_preserved']).lower()} | "
        f"real_action="
        f"{str(result['real_action_executed']).lower()} | "
        f"new={str(result['new']).lower()}"
    )


def run(args: argparse.Namespace) -> None:
    """Execute the selected Stage 13 operation."""
    database, configuration, acl, rbac = load_runtime()

    if args.command == "confirm-containment":
        result = confirm_containment(
            database,
            configuration,
            rbac,
            incident_id=args.incident,
            actor=args.actor,
            notes=args.notes,
            request_id=args.request_id,
        )
        print(
            "[LIFECYCLE] "
            f"incident={result['incident_id']} | "
            f"status={result['status']} | "
            f"new={str(result['new']).lower()}"
        )
        return

    if args.command == "request":
        result = request_action(
            database,
            configuration,
            acl,
            rbac,
            incident_id=args.incident,
            action_type=args.action,
            target_type=args.target_type,
            target_value=args.target,
            requested_by=args.actor,
            request_reason=args.reason,
            evidence_references=args.evidence,
            request_id=args.request_id,
        )
        print_action(result)
        return

    if args.command == "decide":
        result = decide_action(
            database,
            configuration,
            rbac,
            recovery_action_id=args.action_id,
            decided_by=args.actor,
            decision=args.decision,
            notes=args.notes,
        )
        print_action(result)
        return

    if args.command == "execute":
        result = execute_action(
            database,
            configuration,
            rbac,
            recovery_action_id=args.action_id,
            executed_by=args.actor,
            outcome=args.outcome,
            details=args.details,
        )
        print_action(result)
        return

    if args.command == "complete-eradication":
        result = complete_eradication(
            database,
            configuration,
            rbac,
            incident_id=args.incident,
            actor=args.actor,
            notes=args.notes,
            request_id=args.request_id,
        )
        print(
            "[LIFECYCLE] "
            f"incident={result['incident_id']} | "
            f"status={result['status']} | "
            f"new={str(result['new']).lower()}"
        )
        return

    if args.command == "retest":
        result = record_retest(
            database,
            configuration,
            rbac,
            incident_id=args.incident,
            retest_type=args.type,
            target_type=args.target_type,
            target_value=args.target,
            description=args.description,
            observed_result=args.result,
            evidence_references=args.evidence,
            tested_by=args.actor,
            request_id=args.request_id,
        )
        print(
            "[RETEST] "
            f"id={result['recovery_retest_id']} | "
            f"status={result['verification_status']} | "
            f"new={str(result['new']).lower()}"
        )
        return

    if args.command == "complete-recovery":
        result = complete_recovery(
            database,
            configuration,
            rbac,
            incident_id=args.incident,
            actor=args.actor,
            notes=args.notes,
            request_id=args.request_id,
        )
        print(
            "[LIFECYCLE] "
            f"incident={result['incident_id']} | "
            f"status={result['status']} | "
            f"new={str(result['new']).lower()}"
        )
        return

    if args.command == "close":
        result = close_after_review(
            database,
            configuration,
            rbac,
            incident_id=args.incident,
            actor=args.actor,
            lessons_learned=args.lessons,
            detection_improvements=args.detection_improvement,
            policy_improvements=args.policy_improvement,
            closure_reason=args.closure_reason,
            request_id=args.request_id,
        )
        print(
            "[POST-INCIDENT REVIEW] "
            f"incident={result['incident_id']} | "
            f"status={result['status']} | "
            f"new={str(result['new']).lower()}"
        )
        return

    raise ValueError(f"Unsupported command: {args.command}")


def main() -> int:
    """Parse arguments and return a shell-friendly result."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except (PermissionError, RecoveryError, ValueError) as error:
        print(f"DENIED: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
