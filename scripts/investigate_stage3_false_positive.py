"""Classify the approved replacement-device alert as a false positive."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import record_audit_event
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Investigate and classify the approved replacement device."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")

    database_path = PROJECT_ROOT / settings["database"]["path"]
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]

    logger = configure_logger("netshield.audit", audit_log)

    investigation_note = (
        "False positive confirmed: Replacement-Laptop was an approved "
        "replacement device. Inventory registration was pending during "
        "the simulated event and should be completed before normal use."
    )

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        alert = connection.execute(
            """
            SELECT alert_id, detection_type, username, hostname, status
            FROM identity_alerts
            WHERE detection_type = 'Login From New Device'
              AND username = 'analyst01'
              AND hostname = 'Replacement-Laptop'
            ORDER BY alert_id
            LIMIT 1
            """
        ).fetchone()

        if alert is None:
            raise RuntimeError(
                "Expected approved replacement-device alert was not found"
            )

        connection.execute(
            """
            UPDATE identity_alerts
            SET status = 'False Positive',
                classification = 'False Positive',
                investigation_notes = ?
            WHERE alert_id = ?
            """,
            (investigation_note, alert["alert_id"]),
        )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="classify_stage3_false_positive",
        target=f"identity_alert:{alert['alert_id']}",
        result="success",
        details=investigation_note,
    )

    logger.info(
        "actor=netshield01 action=classify_stage3_false_positive "
        "target=identity_alert:%s result=success",
        alert["alert_id"],
    )

    print(
        "PASS: Stage 3 false positive classified "
        f"(alert_id={alert['alert_id']})"
    )
    print(f"Classification: False Positive")
    print(f"Reason: {investigation_note}")


if __name__ == "__main__":
    main()
