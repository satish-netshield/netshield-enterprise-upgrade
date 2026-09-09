"""Validate the NetShield Phase 3A V2 enterprise foundation."""
from src.utils.sqlite_connection import managed_connection

import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

from src.utils.config_loader import load_json
from src.utils.data_protection import apply_configured_masking


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def print_result(passed: bool, description: str) -> bool:
    """Print and return one validation result."""
    print(f"{'PASS' if passed else 'FAIL'}: {description}")
    return passed


def permission_mode(path: Path) -> int:
    """Return a filesystem permission mode."""
    return stat.S_IMODE(path.stat().st_mode)


def main() -> None:
    """Run all V2 Stage 1 checks."""
    results: list[bool] = []

    settings = load_json(PROJECT_ROOT / "config/settings.json")
    context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )
    rbac = load_json(PROJECT_ROOT / "config/rbac.json")

    required_files = [
        "config/settings.json",
        "config/rbac.json",
        "config/automation_acl.json",
        "config/enterprise_context.json",
        "database/schema.sql",
        "src/utils/security_controls.py",
        "src/utils/data_protection.py",
        "scripts/initialize_stage1.py",
        "scripts/validate_stage1.py",
    ]
    results.append(
        print_result(
            all((PROJECT_ROOT / item).is_file() for item in required_files),
            "Existing and V2 foundation files exist",
        )
    )

    upgrade = settings["upgrade"]
    results.append(
        print_result(
            upgrade["phase"] == "3A V2"
            and upgrade["extends"] == "NetShield Automation",
            "V2 upgrade extends the existing Phase 3 project",
        )
    )

    categories = ("users", "devices", "applications", "services")
    results.append(
        print_result(
            context["simulation_only"] is True
            and all(context.get(category) for category in categories),
            "Enterprise users, devices, applications and services exist",
        )
    )

    results.append(
        print_result(
            all(
                user["role"] in rbac["roles"]
                for user in context["users"]
            ),
            "Simulated users use valid RBAC roles",
        )
    )

    protection = settings["data_protection"]
    results.append(
        print_result(
            all(
                isinstance(days, int) and days > 0
                for days in protection["retention_days"].values()
            )
            and protection["sensitive_field_masking"]["enabled"] is True,
            "Retention and sensitive-field policies are valid",
        )
    )

    protected = apply_configured_masking(
        {
            "username": "analyst01",
            "password": "example",
            "nested": {"session_id": "session-123"},
        },
        settings,
    )
    results.append(
        print_result(
            protected["username"] == "analyst01"
            and protected["password"] == "[REDACTED]"
            and protected["nested"]["session_id"] == "[REDACTED]",
            "Sensitive fields are masked without changing safe fields",
        )
    )

    safe_boundary = (
        settings["project"]["environment"] == "sandbox"
        and settings["security"]["default_access"] == "deny"
        and settings["security"]["allow_real_external_targets"] is False
        and settings["security"][
            "require_approval_for_disruptive_actions"
        ] is True
        and context["simulation_only"] is True
    )
    results.append(
        print_result(
            safe_boundary,
            "Controlled testing boundaries remain enabled",
        )
    )

    database_path = PROJECT_ROOT / settings["database"]["path"]
    with managed_connection(database_path) as connection:
        metadata = dict(
            connection.execute(
                """
                SELECT key, value
                FROM system_metadata
                WHERE key IN (
                    'active_upgrade',
                    'upgrade_phase',
                    'upgrade_version',
                    'upgrade_extends'
                )
                """
            )
        )
        assigned_roles = dict(
            connection.execute(
                """
                SELECT username, role
                FROM user_roles
                WHERE username IN (
                    'viewer01',
                    'analyst01',
                    'responder01',
                    'admin01'
                )
                """
            )
        )
        audit_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'initialise_v2_stage1'
              AND result = 'success'
            """
        ).fetchone()[0]

    results.append(
        print_result(
            metadata.get("upgrade_phase") == "3A V2"
            and metadata.get("upgrade_extends") == "NetShield Automation",
            "V2 metadata is stored in SQLite",
        )
    )

    expected_roles = {
        user["username"]: user["role"]
        for user in context["users"]
    }
    results.append(
        print_result(
            assigned_roles == expected_roles,
            "Simulated enterprise roles are stored correctly",
        )
    )

    results.append(
        print_result(
            audit_count >= 1,
            "V2 foundation initialisation is audited",
        )
    )

    results.append(
        print_result(
            permission_mode(PROJECT_ROOT / "config") == 0o750
            and permission_mode(
                PROJECT_ROOT / "config/settings.json"
            ) == 0o640
            and permission_mode(
                PROJECT_ROOT / "config/enterprise_context.json"
            ) == 0o640
            and permission_mode(database_path) == 0o600,
            "Sensitive filesystem permissions remain correct",
        )
    )

    phase3_check = subprocess.run(
        [sys.executable, "-m", "scripts.validate_stage1"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    results.append(
        print_result(
            phase3_check.returncode == 0,
            "Original Phase 3 Stage 1 remains compatible",
        )
    )

    print()
    if all(results):
        print(
            f"V2 STAGE 1 VALIDATION: PASS "
            f"({len(results)}/{len(results)})"
        )
        return

    print(
        "V2 STAGE 1 VALIDATION: FAIL "
        f"({results.count(False)} check(s) failed)"
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
