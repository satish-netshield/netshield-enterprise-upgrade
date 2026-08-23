"""Generate separate safe Stage 4 network and Wi-Fi event files."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    PROJECT_ROOT
    / "data/raw/stage4/network_wifi_stage4_events.jsonl"
)
OUTPUT_DIRECTORY = PROJECT_ROOT / "data/raw/stage4"


def write_events(filename: str, events: list[dict]) -> Path:
    """Write events to one source-specific JSONL file."""
    output_path = OUTPUT_DIRECTORY / filename

    with output_path.open("w", encoding="utf-8") as event_file:
        for item in events:
            event_file.write(json.dumps(item) + "\n")

    return output_path


def main() -> None:
    """Split mixed Stage 4 input into source-specific files."""
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    source_events = [
        json.loads(line)
        for line in SOURCE_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    network_events = []
    wifi_events = []

    for item in source_events:
        event = dict(item)
        event["event_id"] = f"{event['event_id']}-SPLIT"

        if event["source_type"] == "network":
            network_events.append(event)
        elif event["source_type"] == "wifi":
            wifi_events.append(event)

    network_path = write_events(
        "network_stage4_events.jsonl",
        network_events,
    )
    wifi_path = write_events(
        "wifi_stage4_events.jsonl",
        wifi_events,
    )

    print(
        f"CREATED: {network_path.relative_to(PROJECT_ROOT)} "
        f"({len(network_events)} records)"
    )
    print(
        f"CREATED: {wifi_path.relative_to(PROJECT_ROOT)} "
        f"({len(wifi_events)} records)"
    )
    print(
        "PASS: Split Stage 4 events by source type "
        f"({len(network_events) + len(wifi_events)} records)"
    )


if __name__ == "__main__":
    main()
