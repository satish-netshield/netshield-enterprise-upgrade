"""Generate controlled enterprise-style events for V2 Stage 2."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = PROJECT_ROOT / "data/raw/v2"


def build_event(
    number: int,
    source_type: str,
    event_type: str,
    **fields: Any,
) -> dict[str, Any]:
    """Create one event using the V2 common schema."""
    event = {
        "event_id": f"V2-{number:03d}",
        "schema_version": "2.0",
        "event_time": f"2026-09-07T09:{number:02d}:00+12:00",
        "source_type": source_type,
        "source_system": fields.pop(
            "source_system",
            f"simulated_{source_type}",
        ),
        "event_type": event_type,
    }
    event.update(fields)
    return event


def main() -> None:
    """Write valid and deliberately malformed JSONL events."""
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    events = [
        build_event(
            1, "identity_risk", "risky_sign_in",
            username="analyst01", device_id="CYOD-002",
            severity="High", risk_score=78,
            location="Auckland",
        ),
        build_event(
            2, "identity_risk", "risk_dismissed",
            username="viewer01", severity="Low", risk_score=15,
            status="reviewed",
        ),
        build_event(
            3, "access_policy", "access_allowed",
            username="analyst01", device_id="CYOD-002",
            application_id="APP-001", decision="allow",
            severity="Low", risk_score=20,
        ),
        build_event(
            4, "access_policy", "access_denied",
            username="viewer01", device_id="CYOD-003",
            application_id="APP-001", decision="deny",
            severity="High", risk_score=82,
        ),
        build_event(
            5, "database", "sql_query",
            username="analyst01", asset_id="AST-DB-001",
            application_id="APP-001", severity="Informational",
        ),
        build_event(
            6, "database", "schema_change",
            username="admin01", asset_id="AST-DB-001",
            severity="Medium", status="approved",
        ),
        build_event(
            7, "vulnerability", "finding_created",
            asset_id="AST-WEB-001", finding_id="FND-001",
            severity="High", risk_score=80,
        ),
        build_event(
            8, "vulnerability", "remediation_verified",
            asset_id="AST-WEB-001", finding_id="FND-002",
            severity="Low", risk_score=18,
            status="remediated",
        ),
        build_event(
            9, "incident", "incident_created",
            incident_id="INC-V2-001", severity="Critical",
            risk_score=94, status="New",
        ),
        build_event(
            10, "incident", "incident_triaged",
            incident_id="INC-V2-001", severity="Critical",
            risk_score=94, status="Investigating",
        ),
        build_event(
            11, "response", "action_requested",
            incident_id="INC-V2-001", action_id="ACT-V2-001",
            decision="restrict", severity="High",
            status="approval_required",
        ),
        build_event(
            12, "response", "action_completed",
            incident_id="INC-V2-001", action_id="ACT-V2-001",
            decision="restrict", severity="High",
            status="success",
        ),
    ]

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[event["source_type"]].append(event)

    grouped["identity_risk"].append(
        build_event(
            13, "identity_risk", "invalid_risk",
            username="analyst01", risk_score=140,
        )
    )
    grouped["access_policy"].append(
        build_event(
            14, "access_policy", "invalid_decision",
            username="viewer01", decision="permit",
        )
    )

    for source_type, source_events in grouped.items():
        output_path = (
            OUTPUT_DIRECTORY / f"{source_type}_v2_events.jsonl"
        )
        output_path.write_text(
            "".join(
                json.dumps(event, sort_keys=True) + "\n"
                for event in source_events
            ),
            encoding="utf-8",
        )

    print(f"PASS: Generated {len(events) + 2} V2 events")
    print(f"Source files: {len(grouped)}")
    print("Expected valid events: 12")
    print("Expected quarantined events: 2")


if __name__ == "__main__":
    main()
