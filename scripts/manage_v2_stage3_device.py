"""Manage Phase 3A V2 Stage 3 device registration and removal."""

import argparse
from pathlib import Path

from src.assets.device_registry import (
    register_device,
    remove_device,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    """Build the Stage 3 device management command parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Manage NetShield V2 Stage 3 "
            "device registration state"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    register = subparsers.add_parser(
        "register",
        help="Register a new approved CYOD device",
    )

    register.add_argument("--asset-id", required=True)
    register.add_argument("--device-id", required=True)
    register.add_argument("--hostname", required=True)
    register.add_argument("--assigned-user", default="")
    register.add_argument(
        "--ownership",
        default="organisation",
    )
    register.add_argument(
        "--device-type",
        required=True,
    )
    register.add_argument(
        "--manufacturer",
        required=True,
    )
    register.add_argument(
        "--operating-system",
        required=True,
    )
    register.add_argument("--os-version", default="")
    register.add_argument("--mac-address", default="")
    register.add_argument("--ip-address", default="")
    register.add_argument("--location", default="")
    register.add_argument(
        "--connection-type",
        required=True,
    )
    register.add_argument(
        "--compliance-status",
        choices=[
            "compliant",
            "non_compliant",
            "unknown",
        ],
        default="unknown",
    )
    register.add_argument(
        "--risk-status",
        choices=[
            "low",
            "medium",
            "high",
            "critical",
            "unknown",
        ],
        default="unknown",
    )
    register.add_argument(
        "--criticality",
        choices=[
            "low",
            "medium",
            "high",
            "critical",
        ],
        required=True,
    )
    register.add_argument("--last-seen", default="")
    register.add_argument(
        "--actor",
        default="netshield01",
    )
    register.add_argument("--reason", required=True)

    remove = subparsers.add_parser(
        "remove",
        help="Mark an approved device as removed",
    )

    remove.add_argument("--device-id", required=True)
    remove.add_argument(
        "--actor",
        default="netshield01",
    )
    remove.add_argument("--reason", required=True)

    return parser


def main() -> None:
    """Run the requested device management action."""
    parser = build_parser()
    args = parser.parse_args()

    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    device_config = load_json(
        PROJECT_ROOT / "config/device_identity.json"
    )

    database_path = (
        PROJECT_ROOT
        / settings["database"]["path"]
    )
    inventory_path = (
        PROJECT_ROOT
        / device_config["inventory_path"]
    )

    if args.command == "register":
        device = {
            "asset_id": args.asset_id,
            "device_id": args.device_id,
            "hostname": args.hostname,
            "assigned_user": args.assigned_user,
            "ownership": args.ownership,
            "device_type": args.device_type,
            "manufacturer": args.manufacturer,
            "operating_system": args.operating_system,
            "os_version": args.os_version,
            "mac_address": args.mac_address,
            "ip_address": args.ip_address,
            "location": args.location,
            "connection_type": args.connection_type,
            "compliance_status": (
                args.compliance_status
            ),
            "risk_status": args.risk_status,
            "criticality": args.criticality,
            "last_seen": args.last_seen,
        }

        register_device(
            database_path=database_path,
            inventory_path=inventory_path,
            device=device,
            actor=args.actor,
            reason=args.reason,
        )

        print(
            "PASS: Device registered: "
            f"{args.device_id}"
        )

    elif args.command == "remove":
        remove_device(
            database_path=database_path,
            inventory_path=inventory_path,
            device_id=args.device_id,
            actor=args.actor,
            reason=args.reason,
        )

        print(
            "PASS: Device removed from active "
            f"registration: {args.device_id}"
        )


if __name__ == "__main__":
    main()
