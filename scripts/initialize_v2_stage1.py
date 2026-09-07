"""Initialise the NetShield Phase 3A V2 enterprise foundation."""

from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.database import (
    assign_role,
    record_audit_event,
    save_metadata,
)
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Register the V2 upgrade and simulated enterprise users."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    application_log = PROJECT_ROOT / settings["logging"]["application_log"]
    audit_log = PROJECT_ROOT / settings["logging"]["audit_log"]
    upgrade = settings["upgrade"]

    app_logger = configure_logger(
        "netshield.application",
        application_log,
    )
    audit_logger = configure_logger(
        "netshield.audit",
        audit_log,
    )

    save_metadata(database_path, "active_upgrade", upgrade["name"])
    save_metadata(database_path, "upgrade_phase", upgrade["phase"])
    save_metadata(database_path, "upgrade_version", upgrade["version"])
    save_metadata(database_path, "upgrade_extends", upgrade["extends"])

    for user in context["users"]:
        assign_role(
            database_path,
            user["username"],
            user["role"],
        )

    app_logger.info(
        "Phase 3A V2 enterprise foundation initialised successfully"
    )
    audit_logger.info(
        "actor=netshield01 action=initialise_v2_stage1 "
        "target=enterprise_upgrade result=success"
    )

    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="initialise_v2_stage1",
        target="enterprise_upgrade",
        result="success",
        details=(
            "Upgrade metadata and simulated enterprise roles registered"
        ),
    )

    print("PASS: Phase 3A V2 Stage 1 foundation initialised")
    print(f"Simulated users registered: {len(context['users'])}")
    print(f"Simulated devices available: {len(context['devices'])}")
    print(
        "Applications and services available: "
        f"{len(context['applications']) + len(context['services'])}"
    )


if __name__ == "__main__":
    main()
