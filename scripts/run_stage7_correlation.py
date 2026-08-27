"""Run Stage 7 event correlation, risk scoring and IoC extraction."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from src.correlation.stage7_engine import correlate_events
from src.utils.config_loader import load_json


CONFIG_PATH = PROJECT_ROOT / "config/stage7_correlation.json"
EVENT_PATH = (
    PROJECT_ROOT
    / "lab/sql_injection/data/stage7_correlation_events.jsonl"
)
OUTPUT_PATH = (
    PROJECT_ROOT
    / "lab/sql_injection/outputs/stage7_correlation_report.json"
)


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load Stage 7 JSONL events."""
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def main() -> None:
    """Correlate events and write the Stage 7 report."""
    configuration = load_json(CONFIG_PATH)
    events = load_events(EVENT_PATH)
    incidents = correlate_events(events, configuration)

    report = {
        "stage": 7,
        "scope": (
            "Event correlation, risk scoring and IoC extraction"
        ),
        "events_analysed": len(events),
        "incidents_created": len(incidents),
        "incidents": incidents,
        "sandbox_boundary": {
            "simulated_events_only": True,
            "external_targets_used": False,
            "automatic_containment": False,
        },
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("STAGE 7 CORRELATION")
    print(f"EVENTS ANALYSED: {len(events)}")
    print(f"INCIDENTS CREATED: {len(incidents)}")

    for incident in incidents:
        print(
            f"[{incident['severity']}] "
            f"score={incident['risk_score']} "
            f"events={incident['event_count']} "
            f"iocs={len(incident['iocs'])} "
            f"behaviours={len(incident['behaviours'])}"
        )

    print(f"REPORT: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
