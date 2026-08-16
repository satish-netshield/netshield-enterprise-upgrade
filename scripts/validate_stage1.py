"""Validate the complete NetShield Stage 1 foundation."""

import hashlib
import sqlite3
import stat
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.security_controls import (
    action_control_level,
    classify_ip,
    is_cyod_device_approved,
    role_has_permission,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def permission_mode(path: Path) -> int:
    """Return a file or directory permission mode such as 600 or 750."""
    return stat.S_IMODE(path.stat().st_mode)


def print_result(passed: bool, description: str) -> bool:
    """Print one validation result and return its Boolean state."""
    label = "PASS" if passed else "FAIL"
    print(f"{label}: {description}")
    return passed


def main() -> None:
    """Run all Stage 1 foundation checks."""
    results: list[bool] = []

    required_directories = [
        "config",
        "data/allowlists",
        "data/blocklists",
        "database",
        "docs",
        "evidence",
        "logs/application",
        "logs/audit",
        "outputs/alerts",
        "outputs/incidents",
        "outputs/reports",
        "scripts",
        "src",
        "tests",
        "lab/sql_injection",
    ]

    directories_exist = all(
        (PROJECT_ROOT / directory).is_dir()
        for directory in required_directories
    )
    results.append(
        print_result(directories_exist, "Required directories exist")
    )

    settings = load_json(PROJECT_ROOT / "config/settings.json")
    rbac = load_json(PROJECT_ROOT / "config/rbac.json")
    acl = load_json(PROJECT_ROOT / "config/automation_acl.json")
    results.append(print_result(True, "JSON configuration loads correctly"))

    sandbox_is_safe = (
        settings["project"]["environment"] == "sandbox"
        and settings["security"]["default_access"] == "deny"
        and settings["security"]["allow_real_external_targets"] is False
        and settings["security"][
            "require_approval_for_disruptive_actions"
        ] is True
    )
    results.append(
        print_result(sandbox_is_safe, "Safe sandbox boundaries are enabled")
    )

    rbac_is_valid = (
        role_has_permission(
            rbac,
            "administrator",
            "manage_configuration",
        )
        and not role_has_permission(
            rbac,
            "viewer",
            "manage_configuration",
        )
        and not role_has_permission(
            rbac,
            "unknown_role",
            "view_alerts",
        )
    )
    results.append(
        print_result(rbac_is_valid, "RBAC follows least privilege")
    )

    acl_is_valid = (
        action_control_level(acl, "create_alert") == "automatic"
        and action_control_level(
            acl,
            "terminate_process",
        ) == "approval_required"
        and action_control_level(
            acl,
            "undefined_action",
        ) == "deny"
    )
    results.append(
        print_result(acl_is_valid, "Automation ACL follows default deny")
    )

    cyod_is_valid = is_cyod_device_approved(
        PROJECT_ROOT / "data/allowlists/cyod_devices.csv",
        "08:00:27:cf:49:71",
    ) and not is_cyod_device_approved(
        PROJECT_ROOT / "data/allowlists/cyod_devices.csv",
        "AA:BB:CC:DD:EE:FF",
    )
    results.append(
        print_result(cyod_is_valid, "CYOD allowlist decisions are correct")
    )

    ip_is_valid = (
        classify_ip(
            "10.0.2.15",
            PROJECT_ROOT / "data/allowlists/ip_allowlist.txt",
            PROJECT_ROOT / "data/blocklists/ip_blocklist.txt",
        )
        == "allowed"
        and classify_ip(
            "203.0.113.45",
            PROJECT_ROOT / "data/allowlists/ip_allowlist.txt",
            PROJECT_ROOT / "data/blocklists/ip_blocklist.txt",
        )
        == "unknown"
    )
    results.append(
        print_result(ip_is_valid, "IP access-list decisions are correct")
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    expected_tables = {
        "system_metadata",
        "user_roles",
        "audit_events",
    }

    with sqlite3.connect(database_path) as connection:
        actual_tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

    results.append(
        print_result(
            expected_tables.issubset(actual_tables),
            "Required SQLite tables exist",
        )
    )
    results.append(
        print_result(audit_count >= 1, "Database audit trail contains events")
    )

    logs_exist = (
        (PROJECT_ROOT / settings["logging"]["application_log"]).is_file()
        and (PROJECT_ROOT / settings["logging"]["audit_log"]).is_file()
    )
    results.append(
        print_result(logs_exist, "Application and audit logs exist")
    )

    permissions_are_valid = (
        permission_mode(PROJECT_ROOT / "config") == 0o750
        and permission_mode(
            PROJECT_ROOT / "config/settings.json"
        )
        == 0o640
        and permission_mode(PROJECT_ROOT / "database") == 0o700
        and permission_mode(database_path) == 0o600
        and permission_mode(PROJECT_ROOT / "evidence") == 0o700
    )
    results.append(
        print_result(
            permissions_are_valid,
            "Sensitive filesystem permissions are correct",
        )
    )

    evidence_file = (
        PROJECT_ROOT / "evidence/stage1_permission_test.txt"
    )
    hash_file = (
        PROJECT_ROOT / "evidence/stage1_permission_test.sha256"
    )
    expected_hash = hash_file.read_text(encoding="utf-8").split()[0]
    actual_hash = hashlib.sha256(evidence_file.read_bytes()).hexdigest()

    evidence_is_valid = (
        expected_hash == actual_hash
        and permission_mode(evidence_file) == 0o400
    )
    results.append(
        print_result(
            evidence_is_valid,
            "Evidence hash and read-only protection are valid",
        )
    )

    print()
    if all(results):
        print(f"STAGE 1 VALIDATION: PASS ({len(results)}/{len(results)})")
        return

    failed_count = results.count(False)
    print(
        f"STAGE 1 VALIDATION: FAIL "
        f"({failed_count} check(s) failed)"
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
