"""Run Phase 3A V2 Stage 6 network monitoring."""

from collections import Counter
from pathlib import Path

from src.network.v2_network_monitor import (
    build_access_decisions,
    detect_network_activity,
    is_approved_test,
    is_vpn_exception,
    load_address_list,
    load_device_inventory,
    load_stage6_events,
    save_access_decisions,
    save_connection_timeline,
    save_network_alerts,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Run Stage 6 detections and access decisions."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_network_monitoring.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    source_files = configuration["source_files"]

    allowlist = load_address_list(
        PROJECT_ROOT
        / configuration["ip_controls"]["allowlist_path"]
    )
    blocklist = load_address_list(
        PROJECT_ROOT
        / configuration["ip_controls"]["blocklist_path"]
    )
    vpn_addresses = load_address_list(
        PROJECT_ROOT
        / configuration["ip_controls"]["vpn_allowlist_path"]
    )

    events = load_stage6_events(
        database_path,
        source_files,
    )
    inventory = load_device_inventory(database_path)

    alerts = detect_network_activity(
        events,
        configuration,
        inventory,
        allowlist,
        blocklist,
        vpn_addresses,
    )
    decisions = build_access_decisions(
        events,
        alerts,
        configuration,
        inventory,
        allowlist,
        vpn_addresses,
        automation_acl,
    )

    timeline_created, timeline_existing = (
        save_connection_timeline(
            database_path,
            events,
        )
    )
    alerts_created, alerts_existing = save_network_alerts(
        database_path,
        alerts,
    )
    decisions_created, decisions_existing = (
        save_access_decisions(
            database_path,
            decisions,
        )
    )

    vpn_exceptions = sum(
        1
        for event in events
        if is_vpn_exception(event, vpn_addresses)
    )
    testing_exceptions = sum(
        1
        for event in events
        if is_approved_test(event, configuration)
    )

    decision_counts = Counter(
        decision["decision"]
        for decision in decisions
    )

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['detection_type']} | "
            f"confidence={alert['confidence']} | "
            f"device={alert['device_id']} | "
            f"ip={alert['ip_address']} | "
            f"reasons={','.join(alert['reason_codes'])}"
        )

    print()

    for decision in decisions:
        print(
            f"[{decision['decision'].upper()}] "
            f"event={decision['source_event_id']} | "
            f"device={decision['device_id']} | "
            f"ip={decision['ip_address']} | "
            f"rules={','.join(decision['matching_rules'])} | "
            f"reasons={','.join(decision['reason_codes'])} | "
            f"response={decision['response_status']}"
        )

    details = (
        f"events={len(events)} "
        f"alerts={len(alerts)} "
        f"new_alerts={alerts_created} "
        f"existing_alerts={alerts_existing} "
        f"decisions={len(decisions)} "
        f"new_decisions={decisions_created} "
        f"existing_decisions={decisions_existing} "
        f"timeline_new={timeline_created} "
        f"timeline_existing={timeline_existing} "
        f"allow={decision_counts['allow']} "
        f"deny={decision_counts['deny']} "
        f"challenge={decision_counts['challenge']} "
        f"restrict={decision_counts['restrict']} "
        f"vpn_exceptions={vpn_exceptions} "
        f"testing_exceptions={testing_exceptions}"
    )

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    app_logger.info(
        "V2 Stage 6 network monitoring completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=run_v2_stage6_network_monitoring "
        "target=network_access_monitoring "
        "result=success %s",
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage6_network_monitoring",
        target="network_access_monitoring",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage_6_status",
        "network_monitoring_complete",
    )

    print()
    print(f"V2 STAGE 6 NETWORK MONITORING: {details}")


if __name__ == "__main__":
    main()
