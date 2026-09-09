"""Run V2 Stage 4 enterprise identity monitoring."""

from pathlib import Path

from src.detectors.v2_identity_monitor import (
    detect_identity_activity,
    load_identity_events,
    load_vpn_allowlist,
    save_identity_alerts,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Run Stage 4 detections and store identity alerts."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    monitoring_config = load_json(
        PROJECT_ROOT / "config/v2_identity_monitoring.json"
    )
    existing_identity_config = load_json(
        PROJECT_ROOT / "config/identity_detection.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    vpn_allowlist_path = (
        PROJECT_ROOT
        / monitoring_config["known_exceptions"]["vpn_allowlist"]
    )

    application_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    events = load_identity_events(database_path)
    vpn_addresses = load_vpn_allowlist(vpn_allowlist_path)

    alerts, statistics = detect_identity_activity(
        events=events,
        configuration=monitoring_config,
        locations=existing_identity_config["locations"],
        vpn_addresses=vpn_addresses,
    )
    created, existing = save_identity_alerts(
        database_path,
        alerts,
    )

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"user={alert['username']} | "
            f"confidence={alert['confidence']} | "
            f"reasons={','.join(alert['reason_codes'])}"
        )

    details = (
        f"events={statistics['events']} "
        f"detections={statistics['detections']} "
        f"new_alerts={created} "
        f"existing_alerts={existing} "
        f"vpn_exceptions={statistics['vpn_exceptions']} "
        f"testing_exceptions={statistics['testing_exceptions']}"
    )

    application_logger.info(
        "V2 Stage 4 identity monitoring completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=run_v2_stage4_identity_monitoring "
        "target=v2_identity_alerts "
        "result=success %s",
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage4_identity_monitoring",
        target="v2_identity_alerts",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage4_identity_monitoring",
        "detections_complete",
    )

    print()
    print(
        "V2 STAGE 4 IDENTITY MONITORING: "
        f"events={statistics['events']} "
        f"detections={statistics['detections']} "
        f"new={created} "
        f"existing={existing} "
        f"vpn_exceptions={statistics['vpn_exceptions']} "
        f"testing_exceptions={statistics['testing_exceptions']}"
    )


if __name__ == "__main__":
    main()
