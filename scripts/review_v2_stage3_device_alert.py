"""Review Phase 3A V2 Stage 3 device identity alerts."""

import argparse
import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]

VALID_STATUSES = (
    "New",
    "Investigating",
    "Confirmed",
    "False Positive",
    "Closed",
)


def update_device_alert(
    database_path: Path,
    alert_id: int,
    status: str,
    classification: str,
    notes: str,
    actor: str,
) -> None:
    """Update one device alert review state."""

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Unsupported alert status: {status}"
        )

    with sqlite3.connect(database_path) as connection:
        existing = connection.execute(
            """
            SELECT
                alert_id,
                detection_type,
                status
            FROM device_alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

        if existing is None:
            raise ValueError(
                f"Device alert {alert_id} was not found"
            )

        previous_status = existing[2]

        connection.execute(
            """
            UPDATE device_alerts
            SET
                status = ?,
                classification = ?,
                investigation_notes = ?
            WHERE alert_id = ?
            """,
            (
                status,
                classification,
                notes,
                alert_id,
            ),
        )

    record_audit_event(
        database_path=database_path,
        actor=actor,
        action="review_v2_stage3_device_alert",
        target=f"device_alert:{alert_id}",
        result="success",
        details=(
            f"detection_type={existing[1]} "
            f"previous_status={previous_status} "
            f"new_status={status} "
            f"classification={classification}"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the alert review command parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Review a NetShield V2 Stage 3 "
            "device identity alert"
        )
    )

    parser.add_argument(
        "--alert-id",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--status",
        choices=VALID_STATUSES,
        required=True,
    )

    parser.add_argument(
        "--classification",
        required=True,
    )

    parser.add_argument(
        "--notes",
        required=True,
    )

    parser.add_argument(
        "--actor",
        default="netshield01",
    )

    return parser


def main() -> None:
    """Run one device alert review."""

    parser = build_parser()
    args = parser.parse_args()

    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )

    database_path = (
        PROJECT_ROOT
        / settings["database"]["path"]
    )

    update_device_alert(
        database_path=database_path,
        alert_id=args.alert_id,
        status=args.status,
        classification=args.classification,
        notes=args.notes,
        actor=args.actor,
    )

    print(
        "PASS: Device alert reviewed: "
        f"{args.alert_id}"
    )
    print(f"Status: {args.status}")
    print(
        f"Classification: "
        f"{args.classification}"
    )


if __name__ == "__main__":
    main()
