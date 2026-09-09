"""Generate controlled events for V2 Stage 4 and Stage 5."""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = PROJECT_ROOT / "data/raw/v2/stage4_5"
VPN_ALLOWLIST = (
    PROJECT_ROOT / "data/allowlists/vpn_ip_allowlist.txt"
)


def load_first_vpn_address() -> str:
    """Return the first configured VPN address."""
    for raw_line in VPN_ALLOWLIST.read_text(
        encoding="utf-8"
    ).splitlines():
        address = raw_line.strip()

        if address and not address.startswith("#"):
            return address

    raise ValueError("The VPN allowlist contains no addresses")


def event_time(minutes: int) -> str:
    """Return a fixed UTC event time for controlled testing."""
    start_time = datetime(
        2026,
        9,
        9,
        8,
        0,
        tzinfo=timezone.utc,
    )
    return (start_time + timedelta(minutes=minutes)).isoformat()


def build_event(
    event_id: str,
    minutes: int,
    source_type: str,
    event_type: str,
    **fields: Any,
) -> dict[str, Any]:
    """Build one event using the V2 common event schema."""
    event = {
        "event_id": event_id,
        "schema_version": "2.0",
        "event_time": event_time(minutes),
        "source_type": source_type,
        "source_system": fields.pop(
            "source_system",
            f"simulated_v2_{source_type}",
        ),
        "event_type": event_type,
    }
    event.update(fields)
    return event


def authentication_events(
    vpn_address: str,
) -> list[dict[str, Any]]:
    """Return controlled authentication events."""
    events: list[dict[str, Any]] = []

    for number in range(1, 6):
        events.append(
            build_event(
                f"S45-AUTH-{number:03d}",
                number,
                "authentication",
                "login_failure",
                username="analyst01",
                device_id="CYOD-002",
                hostname="Analyst-Laptop",
                ip_address="203.0.113.50",
                location="Auckland, NZ",
                status="failure",
                authentication_method="password",
            )
        )

    events.append(
        build_event(
            "S45-AUTH-006",
            6,
            "authentication",
            "login_success",
            username="analyst01",
            device_id="CYOD-002",
            hostname="Analyst-Laptop",
            ip_address="203.0.113.50",
            location="Auckland, NZ",
            status="success",
            authentication_method="password",
            mfa_satisfied=True,
        )
    )

    spray_users = (
        ("viewer01", "CYOD-001", "Ubuntu-NetShield"),
        ("responder01", "CYOD-001", "Ubuntu-NetShield"),
        ("admin01", "CYOD-001", "Ubuntu-NetShield"),
    )

    for offset, identity in enumerate(spray_users, 10):
        username, device_id, hostname = identity
        events.append(
            build_event(
                f"S45-AUTH-{offset:03d}",
                offset,
                "authentication",
                "login_failure",
                username=username,
                device_id=device_id,
                hostname=hostname,
                ip_address="198.51.100.90",
                location="Restricted Test Location",
                status="failure",
                authentication_method="password",
            )
        )

    events.extend(
        [
            build_event(
                "S45-AUTH-020",
                20,
                "authentication",
                "login_success",
                username="analyst01",
                device_id="CYOD-002",
                hostname="Analyst-Laptop",
                ip_address="192.0.2.20",
                location="Auckland, NZ",
                status="success",
                authentication_method="password",
                mfa_satisfied=True,
            ),
            build_event(
                "S45-AUTH-021",
                50,
                "authentication",
                "login_success",
                username="analyst01",
                device_id="CYOD-002",
                hostname="Analyst-Laptop",
                ip_address="203.0.113.70",
                location="London, UK",
                status="success",
                authentication_method="password",
                mfa_satisfied=True,
            ),
            build_event(
                "S45-AUTH-022",
                60,
                "authentication",
                "login_success",
                username="viewer01",
                device_id="CYOD-003",
                hostname="Unknown-Test-Device",
                ip_address="203.0.113.80",
                location="Sydney, Australia",
                status="success",
                authentication_method="password",
                mfa_satisfied=False,
            ),
            build_event(
                "S45-AUTH-023",
                900,
                "authentication",
                "login_success",
                username="viewer01",
                device_id="CYOD-001",
                hostname="Ubuntu-NetShield",
                ip_address="192.0.2.10",
                location="Auckland, NZ",
                status="success",
                authentication_method="password",
                mfa_satisfied=True,
            ),
        ]
    )

    for number in range(24, 27):
        events.append(
            build_event(
                f"S45-AUTH-{number:03d}",
                number + 100,
                "authentication",
                "mfa_failure",
                username="analyst01",
                device_id="CYOD-002",
                hostname="Analyst-Laptop",
                ip_address="203.0.113.60",
                location="Auckland, NZ",
                status="failure",
                authentication_method="push_notification",
            )
        )

    events.extend(
        [
            build_event(
                "S45-AUTH-027",
                140,
                "authentication",
                "role_change",
                username="viewer01",
                device_id="CYOD-001",
                hostname="Ubuntu-NetShield",
                ip_address="192.0.2.10",
                location="Auckland, NZ",
                status="success",
                previous_role="viewer",
                new_role="administrator",
                changed_by="admin01",
            ),
            build_event(
                "S45-AUTH-028",
                150,
                "authentication",
                "login_success",
                username="dormant01",
                device_id="CYOD-001",
                hostname="Ubuntu-NetShield",
                ip_address="192.0.2.10",
                location="Auckland, NZ",
                status="success",
                authentication_method="password",
                mfa_satisfied=True,
            ),
            build_event(
                "S45-AUTH-029",
                160,
                "authentication",
                "login_success",
                username="svc_ingestion01",
                device_id="CYOD-001",
                hostname="Ubuntu-NetShield",
                ip_address="192.0.2.10",
                location="Auckland, NZ",
                status="success",
                authentication_method="password",
                interactive=True,
            ),
            build_event(
                "S45-AUTH-030",
                170,
                "authentication",
                "login_success",
                username="analyst01",
                device_id="CYOD-002",
                hostname="Analyst-Laptop",
                ip_address=vpn_address,
                location="London, UK",
                status="success",
                authentication_method="password",
                mfa_satisfied=True,
            ),
            build_event(
                "S45-AUTH-031",
                180,
                "authentication",
                "login_success",
                username="trainee01",
                device_id="CYOD-003",
                hostname="Approved-Test-Device",
                ip_address="203.0.113.99",
                location="Restricted Test Location",
                status="success",
                authentication_method="password",
                approved_test_activity=True,
            ),
        ]
    )

    return events


def identity_risk_events() -> list[dict[str, Any]]:
    """Return controlled identity-risk events."""
    return [
        build_event(
            "S45-RISK-001",
            190,
            "identity_risk",
            "risky_sign_in",
            username="analyst01",
            device_id="CYOD-002",
            hostname="Analyst-Laptop",
            ip_address="203.0.113.60",
            location="Auckland, NZ",
            severity="High",
            risk_score=88,
            risk_state="at_risk",
        ),
        build_event(
            "S45-RISK-002",
            191,
            "identity_risk",
            "user_risk_detected",
            username="responder01",
            device_id="CYOD-001",
            hostname="Ubuntu-NetShield",
            ip_address="192.0.2.10",
            location="Auckland, NZ",
            severity="Critical",
            risk_score=92,
            risk_state="at_risk",
        ),
        build_event(
            "S45-RISK-003",
            192,
            "identity_risk",
            "risk_dismissed",
            username="viewer01",
            device_id="CYOD-001",
            hostname="Ubuntu-NetShield",
            ip_address="192.0.2.10",
            location="Auckland, NZ",
            severity="Low",
            risk_score=12,
            risk_state="dismissed",
            status="reviewed",
        ),
    ]


def access_policy_events(
    vpn_address: str,
) -> list[dict[str, Any]]:
    """Return controlled access-policy requests."""
    return [
        build_event(
            "S45-POLICY-001",
            200,
            "access_policy",
            "access_request",
            username="analyst01",
            device_id="CYOD-002",
            application_id="APP-001",
            asset_id="AST-002",
            ip_address="192.0.2.20",
            location="Auckland, NZ",
            risk_score=20,
            sign_in_risk=20,
            user_risk=15,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-002",
            201,
            "access_policy",
            "access_request",
            username="viewer01",
            device_id="CYOD-001",
            application_id="APP-001",
            asset_id="AST-001",
            ip_address="192.0.2.10",
            location="Auckland, NZ",
            risk_score=15,
            sign_in_risk=15,
            user_risk=10,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-003",
            202,
            "access_policy",
            "access_request",
            username="analyst01",
            device_id="CYOD-003",
            application_id="APP-001",
            asset_id="AST-002",
            ip_address="203.0.113.80",
            location="Auckland, NZ",
            risk_score=35,
            sign_in_risk=35,
            user_risk=20,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-004",
            203,
            "access_policy",
            "access_request",
            username="responder01",
            device_id="CYOD-001",
            application_id="APP-001",
            asset_id="AST-001",
            ip_address="192.0.2.10",
            location="Auckland, NZ",
            risk_score=92,
            sign_in_risk=92,
            user_risk=88,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-005",
            204,
            "access_policy",
            "access_request",
            username="admin01",
            device_id="CYOD-001",
            application_id="APP-001",
            asset_id="AST-001",
            ip_address="198.51.100.25",
            location="Auckland, NZ",
            risk_score=10,
            sign_in_risk=10,
            user_risk=5,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-006",
            205,
            "access_policy",
            "access_request",
            username="analyst01",
            device_id="CYOD-002",
            application_id="APP-001",
            asset_id="AST-002",
            ip_address="192.0.2.20",
            location="Auckland, NZ",
            risk_score=25,
            sign_in_risk=25,
            user_risk=15,
            mfa_satisfied=False,
        ),
        build_event(
            "S45-POLICY-007",
            206,
            "access_policy",
            "access_request",
            username="admin01",
            device_id="CYOD-001",
            application_id="APP-001",
            asset_id="AST-001",
            ip_address="192.0.2.10",
            location="Restricted Test Location",
            risk_score=10,
            sign_in_risk=10,
            user_risk=5,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-008",
            207,
            "access_policy",
            "access_request",
            username="analyst01",
            device_id="CYOD-002",
            application_id="APP-001",
            asset_id="AST-002",
            ip_address=vpn_address,
            location="London, UK",
            risk_score=20,
            sign_in_risk=20,
            user_risk=15,
            mfa_satisfied=True,
        ),
        build_event(
            "S45-POLICY-009",
            208,
            "access_policy",
            "access_request",
            username="responder01",
            device_id="CYOD-001",
            application_id="APP-002",
            asset_id="AST-001",
            ip_address="192.0.2.10",
            location="Auckland, NZ",
            risk_score=30,
            sign_in_risk=30,
            user_risk=25,
            mfa_satisfied=True,
            temporary_restriction=True,
        ),
    ]


def write_events(
    events: list[dict[str, Any]],
) -> tuple[int, int]:
    """Write events to source-specific JSONL files."""
    grouped_events: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        grouped_events[event["source_type"]].append(event)

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    for existing_file in OUTPUT_DIRECTORY.glob("*.jsonl"):
        existing_file.unlink()

    for source_type, source_events in grouped_events.items():
        output_path = (
            OUTPUT_DIRECTORY
            / f"{source_type}_v2_stage4_5_events.jsonl"
        )
        output_path.write_text(
            "".join(
                json.dumps(event, sort_keys=True) + "\n"
                for event in source_events
            ),
            encoding="utf-8",
        )

    return len(events), len(grouped_events)


def main() -> None:
    """Generate the complete controlled Stage 4–5 dataset."""
    vpn_address = load_first_vpn_address()

    events = [
        *authentication_events(vpn_address),
        *identity_risk_events(),
        *access_policy_events(vpn_address),
    ]

    event_count, file_count = write_events(events)

    print(f"PASS: Generated {event_count} Stage 4–5 events")
    print(f"Source files: {file_count}")
    print(
        "Sources: authentication, identity_risk, access_policy"
    )
    print(f"Approved VPN test address: {vpn_address}")


if __name__ == "__main__":
    main()
