"""Manage Phase 3A V2 Stage 12 simulated containment actions."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from src.response.v2_containment_response import (
    decide_action,
    execute_action,
    request_action,
    rollback_action,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_project() -> tuple[
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Load the database path and Stage 12 security configuration."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_containment_response.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    rbac = load_json(PROJECT_ROOT / "config/rbac.json")
    database_path = PROJECT_ROOT / settings["database"]["path"]
    return database_path, configuration, automation_acl, rbac


def add_request_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for a containment request."""
    parser.add_argument("--incident", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--target-type", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--evidence-reference",
        action="append",
        required=True,
        dest="evidence_references",
        help="Repeat this option to preserve more than one reference",
    )
    parser.add_argument("--request-id", required=True)


def add_decision_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for an approval or denial decision."""
    parser.add_argument("--action-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument(
        "--decision",
        required=True,
        choices=("approved", "denied"),
    )
    parser.add_argument("--notes", required=True)


def add_execution_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for simulated execution."""
    parser.add_argument("--action-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--simulate-failure", action="store_true")


def add_rollback_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for a safe simulated rollback."""
    parser.add_argument("--action-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--rollback-id", required=True)
    parser.add_argument("--simulate-failure", action="store_true")


def parse_arguments() -> argparse.Namespace:
    """Parse the Stage 12 command and its arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Manage approval-controlled simulated containment and response"
        )
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    request_parser = subparsers.add_parser(
        "request",
        help="Request a defined containment action",
    )
    add_request_arguments(request_parser)

    decision_parser = subparsers.add_parser(
        "decide",
        help="Approve or deny a pending disruptive action",
    )
    add_decision_arguments(decision_parser)

    execution_parser = subparsers.add_parser(
        "execute",
        help="Execute an approved action inside the simulation",
    )
    add_execution_arguments(execution_parser)

    rollback_parser = subparsers.add_parser(
        "rollback",
        help="Roll back a supported successful action",
    )
    add_rollback_arguments(rollback_parser)

    return parser.parse_args()


def print_action(result: dict[str, Any]) -> None:
    """Print a concise containment action result."""
    print(
        "[CONTAINMENT] "
        f"id={result['containment_action_id']} | "
        f"incident={result['incident_id']} | "
        f"action={result['action_type']} | "
        f"target={result['target_type']}:{result['target_value']} | "
        f"control={result['control_level']} | "
        f"status={result['status']} | "
        f"evidence_preserved="
        f"{str(result['evidence_preserved']).lower()} | "
        f"real_action={str(result['real_action_executed']).lower()} | "
        f"new={str(result['new']).lower()}"
    )


def print_rollback(result: dict[str, Any]) -> None:
    """Print a concise rollback result."""
    print(
        "[ROLLBACK] "
        f"id={result['containment_rollback_id']} | "
        f"action_id={result['containment_action_id']} | "
        f"action={result['rollback_action']} | "
        f"status={result['status']} | "
        f"new={str(result['new']).lower()}"
    )


def run(arguments: argparse.Namespace) -> None:
    """Run the requested Stage 12 operation."""
    database_path, configuration, automation_acl, rbac = load_project()

    if arguments.command == "request":
        result = request_action(
            database_path,
            configuration,
            automation_acl,
            rbac,
            incident_id=arguments.incident,
            action_type=arguments.action,
            target_type=arguments.target_type,
            target_value=arguments.target,
            requested_by=arguments.actor,
            request_reason=arguments.reason,
            evidence_references=arguments.evidence_references,
            request_id=arguments.request_id,
        )
        print_action(result)
        return

    if arguments.command == "decide":
        result = decide_action(
            database_path,
            configuration,
            rbac,
            containment_action_id=arguments.action_id,
            decided_by=arguments.actor,
            decision=arguments.decision,
            notes=arguments.notes,
        )
        print_action(result)
        return

    if arguments.command == "execute":
        result = execute_action(
            database_path,
            configuration,
            rbac,
            containment_action_id=arguments.action_id,
            executed_by=arguments.actor,
            simulate_failure=arguments.simulate_failure,
        )
        print_action(result)
        return

    result = rollback_action(
        database_path,
        configuration,
        rbac,
        containment_action_id=arguments.action_id,
        requested_by=arguments.actor,
        rollback_reason=arguments.reason,
        rollback_id=arguments.rollback_id,
        simulate_failure=arguments.simulate_failure,
    )
    print_rollback(result)


def main() -> None:
    """Run the CLI with controlled error reporting."""
    arguments = parse_arguments()
    try:
        run(arguments)
    except PermissionError as error:
        print(f"DENIED: {error}")
        raise SystemExit(2) from error
    except (ValueError, RuntimeError) as error:
        print(f"FAILED: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
