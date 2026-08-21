"""Generate safe identity and authentication events for Stage 3."""

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_FILE = (
    PROJECT_ROOT
    / "data/raw/stage3/authentication_stage3_events.jsonl"
)


def authentication_event(
    event_id: str,
    event_time: str,
    event_type: str,
    username: str,
    ip_address: str,
    hostname: str,
    location: str,
    status: str,
    **extra_fields: Any,
) -> dict[str, Any]:
    """Return one controlled authentication event."""
    event = {
        "event_id": event_id,
        "event_time": event_time,
        "source_type": "authentication",
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
        "hostname": hostname,
        "location": location,
        "status": status,
    }
    event.update(extra_fields)
    return event


def build_events() -> list[dict[str, Any]]:
    """Return the complete controlled Stage 3 event set."""
    events = [
        authentication_event(
            "AUTH-300",
            "2026-08-21T07:55:00+12:00",
            "login_success",
            "analyst01",
            "10.0.2.25",
            "Analyst-Laptop",
            "Auckland, NZ",
            "success",
        )
    ]

    for attempt in range(1, 6):
        events.append(
            authentication_event(
                f"AUTH-BF-{attempt:03d}",
                f"2026-08-21T08:0{attempt - 1}:00+12:00",
                "login_failure",
                "analyst01",
                "198.51.100.45",
                "Unknown-Laptop",
                "Sydney, Australia",
                "failed",
            )
        )

    events.append(
        authentication_event(
            "AUTH-BF-006",
            "2026-08-21T08:05:00+12:00",
            "login_success",
            "analyst01",
            "198.51.100.45",
            "Unknown-Laptop",
            "Sydney, Australia",
            "success",
        )
    )

    for attempt in range(1, 4):
        events.append(
            authentication_event(
                f"AUTH-MFA-{attempt:03d}",
                f"2026-08-21T08:{9 + attempt:02d}:00+12:00",
                "mfa_failure",
                "analyst01",
                "10.0.2.25",
                "Analyst-Laptop",
                "Auckland, NZ",
                "failed",
                mfa_method="authenticator_app",
            )
        )

    events.extend(
        [
            authentication_event(
                "AUTH-TRAVEL-001",
                "2026-08-21T09:00:00+12:00",
                "login_success",
                "traveller01",
                "10.0.2.35",
                "Travel-Laptop",
                "Auckland, NZ",
                "success",
            ),
            authentication_event(
                "AUTH-TRAVEL-002",
                "2026-08-21T10:00:00+12:00",
                "login_success",
                "traveller01",
                "192.0.2.80",
                "Travel-Laptop",
                "London, UK",
                "success",
            ),
            authentication_event(
                "AUTH-DEVICE-001",
                "2026-08-21T09:30:00+12:00",
                "login_success",
                "analyst01",
                "10.0.2.45",
                "Replacement-Laptop",
                "Auckland, NZ",
                "success",
                investigation_case="approved_replacement_pending_inventory",
            ),
            authentication_event(
                "AUTH-ROLE-001",
                "2026-08-21T10:15:00+12:00",
                "role_change",
                "trainee01",
                "10.0.2.15",
                "Trainee-Laptop",
                "Auckland, NZ",
                "success",
                previous_role="viewer",
                new_role="administrator",
                changed_by="netshield01",
            ),
            authentication_event(
                "AUTH-VPN-001",
                "2026-08-21T10:30:00+12:00",
                "login_success",
                "vpnuser01",
                "10.0.2.55",
                "VPN-Laptop",
                "Auckland, NZ",
                "success",
            ),
            authentication_event(
                "AUTH-VPN-002",
                "2026-08-21T11:00:00+12:00",
                "login_success",
                "vpnuser01",
                "203.0.113.10",
                "VPN-Laptop",
                "London, UK",
                "success",
                connection_type="approved_vpn",
            ),
        ]
    )

    return events


def main() -> None:
    """Write the Stage 3 event set as JSON Lines."""
    events = build_events()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as output_file:
        for event in events:
            output_file.write(
                json.dumps(event, sort_keys=True) + "\n"
            )

    print(
        "CREATED: "
        "data/raw/stage3/authentication_stage3_events.jsonl "
        f"({len(events)} records)"
    )
    print("PASS: Generated safe Stage 3 identity events")


if __name__ == "__main__":
    main()
