"""Validate Stage 7 correlation, risk scoring and IoC extraction."""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENT_PATH = (
    PROJECT_ROOT
    / "lab/sql_injection/data/stage7_correlation_events.jsonl"
)
REPORT_PATH = (
    PROJECT_ROOT
    / "lab/sql_injection/outputs/stage7_correlation_report.json"
)


def check(condition: bool, message: str) -> tuple[int, int]:
    """Return one validation result."""
    if condition:
        print(f"PASS: {message}")
        return 1, 1

    print(f"FAIL: {message}")
    return 0, 1


def main() -> None:
    """Run Stage 7 validation checks."""
    events = [
        json.loads(line)
        for line in EVENT_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    report = json.loads(
        REPORT_PATH.read_text(encoding="utf-8")
    )

    incidents = report["incidents"]
    passed = 0
    total = 0

    for condition, message in [
        (
            EVENT_PATH.exists(),
            "Stage 7 event evidence exists",
        ),
        (
            REPORT_PATH.exists(),
            "Stage 7 correlation report exists",
        ),
        (
            len(events) == 7,
            "Seven Stage 7 events were analysed",
        ),
        (
            report["events_analysed"] == 7,
            "Report event total is correct",
        ),
        (
            report["incidents_created"] == 3,
            "Three context-rich incidents were created",
        ),
        (
            incidents[0]["severity"] == "Critical",
            "Combined multi-source activity is Critical",
        ),
        (
            incidents[0]["event_count"] == 4,
            "Four related events were combined",
        ),
        (
            len(incidents[0]["source_types"]) == 4,
            "Identity, network, endpoint and application evidence was combined",
        ),
        (
            len(incidents[0]["iocs"]) == 4,
            "Four observable IoCs were extracted",
        ),
        (
            "username"
            not in {
                indicator["type"]
                for indicator in incidents[0]["iocs"]
            },
            "Username remains context rather than an IoC",
        ),
        (
            incidents[1]["severity"] == "Low",
            "Approved-device and VPN exceptions reduce risk",
        ),
        (
            incidents[2]["severity"] == "Low",
            "Isolated low-value activity is reduced to Low",
        ),
        (
            "Repeated Failed Logins"
            in incidents[0]["behaviours"],
            "Suspicious behaviour is separated from IoCs",
        ),
        (
            report["sandbox_boundary"][
                "external_targets_used"
            ] is False,
            "No external targets were used",
        ),
        (
            report["sandbox_boundary"][
                "automatic_containment"
            ] is False,
            "Automatic containment remains disabled",
        ),
    ]:
        result, count = check(condition, message)
        passed += result
        total += count

    print()
    print(
        "STAGE 7 VALIDATION: "
        f"{'PASS' if passed == total else 'FAIL'} "
        f"({passed}/{total})"
    )


if __name__ == "__main__":
    main()
