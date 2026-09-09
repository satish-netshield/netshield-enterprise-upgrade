"""Run the V2 Stage 5 local access-policy engine."""

from datetime import datetime, timezone
from pathlib import Path

from src.policy.v2_access_policy import (
    evaluate_access_requests,
    load_access_requests,
    load_active_restrictions,
    load_device_inventory,
    load_user_roles,
    load_vpn_allowlist,
    save_access_decisions,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Evaluate access requests and store explainable decisions."""
    settings = load_json(
        PROJECT_ROOT / "config/settings.json"
    )
    policy_config = load_json(
        PROJECT_ROOT / "config/v2_access_policy.json"
    )
    rbac_config = load_json(
        PROJECT_ROOT / "config/rbac.json"
    )
    automation_acl = load_json(
        PROJECT_ROOT / "config/automation_acl.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    vpn_allowlist_path = (
        PROJECT_ROOT
        / policy_config["known_exceptions"]["vpn_allowlist"]
    )

    application_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    requests = load_access_requests(database_path)
    user_roles = load_user_roles(database_path)
    devices = load_device_inventory(database_path)
    vpn_addresses = load_vpn_allowlist(vpn_allowlist_path)
    restrictions = load_active_restrictions(
        database_path,
        datetime.now(timezone.utc),
    )

    decisions = evaluate_access_requests(
        requests=requests,
        policy_config=policy_config,
        rbac_config=rbac_config,
        automation_acl=automation_acl,
        enterprise_context=enterprise_context,
        user_roles=user_roles,
        devices=devices,
        restricted_users=restrictions,
        vpn_addresses=vpn_addresses,
    )

    created, existing = save_access_decisions(
        database_path,
        decisions,
    )

    outcome_counts = {
        outcome: 0
        for outcome in policy_config["decision_outcomes"]
    }

    for decision in decisions:
        outcome_counts[decision["decision"]] += 1

        print(
            f"[{decision['decision'].upper()}] "
            f"request={decision['request_event_id']} | "
            f"user={decision['username']} | "
            f"device={decision['device_id']} | "
            f"application={decision['application_id']} | "
            f"policy={decision['winning_policy_id']} | "
            f"reasons={','.join(decision['reason_codes'])} | "
            f"response={decision['response_status']}"
        )

    details = (
        f"requests={len(requests)} "
        f"decisions={len(decisions)} "
        f"new_decisions={created} "
        f"existing_decisions={existing} "
        f"allow={outcome_counts['allow']} "
        f"deny={outcome_counts['deny']} "
        f"challenge={outcome_counts['challenge']} "
        f"restrict={outcome_counts['restrict']}"
    )

    application_logger.info(
        "V2 Stage 5 access-policy evaluation completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=run_v2_stage5_access_policy "
        "target=access_policy_decisions "
        "result=success %s",
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage5_access_policy",
        target="access_policy_decisions",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage5_access_policy",
        "decisions_complete",
    )

    print()
    print(
        "V2 STAGE 5 ACCESS POLICY: "
        f"requests={len(requests)} "
        f"decisions={len(decisions)} "
        f"new={created} "
        f"existing={existing} "
        f"allow={outcome_counts['allow']} "
        f"deny={outcome_counts['deny']} "
        f"challenge={outcome_counts['challenge']} "
        f"restrict={outcome_counts['restrict']}"
    )


if __name__ == "__main__":
    main()
