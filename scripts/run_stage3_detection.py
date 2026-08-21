"""Run the NetShield Stage 3 identity detections."""

from pathlib import Path

from src.detectors.identity_detector import (
    detect_identity_activity,
    load_authentication_events,
    load_vpn_allowlist,
    save_identity_alerts,
)
from src.utils.config_loader import load_json
from src.utils.database import (
    record_audit_event,
    save_metadata,
)
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Run all identity rules and store new alerts."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    detection_config = load_json(
        PROJECT_ROOT / "config/identity_detection.json"
    )

    database_path = (
        PROJECT_ROOT / settings["database"]["path"]
    )
    vpn_allowlist = load_vpn_allowlist(
        PROJECT_ROOT
        / "data/allowlists/vpn_ip_allowlist.txt"
    )
    application_log = (
        PROJECT_ROOT / settings["logging"]["application_log"]
    )
    audit_log = (
        PROJECT_ROOT / settings["logging"]["audit_log"]
    )

    app_logger = configure_logger(
        "netshield.application",
        application_log,
    )
    audit_logger = configure_logger(
        "netshield.audit",
        audit_log,
    )

    events = load_authentication_events(database_path)
    alerts, vpn_exceptions = detect_identity_activity(
        events,
        detection_config,
        vpn_allowlist,
    )
    created, existing = save_identity_alerts(
        database_path,
        alerts,
    )

    for alert in alerts:
        event_ids = ", ".join(alert["source_event_ids"])
        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"user={alert['username']} | "
            f"events={event_ids}"
        )

    details = (
        f"authentication_events={len(events)} "
        f"detections={len(alerts)} "
        f"new_alerts={created} "
        f"existing_alerts={existing} "
        f"vpn_exceptions={vpn_exceptions}"
    )

    app_logger.info(
        "Stage 3 identity detection completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 action=run_stage3_detection "
        "target=identity_alerts result=success %s",
        details,
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_stage3_detection",
        target="identity_alerts",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "stage_3_status",
        "detections_complete",
    )

    print()
    print(
        "STAGE 3 DETECTION: "
        f"events={len(events)} "
        f"detections={len(alerts)} "
        f"new={created} "
        f"existing={existing} "
        f"vpn_exceptions={vpn_exceptions}"
    )


if __name__ == "__main__":
    main()
