"""Validate the complete NetShield Enterprise Upgrade."""

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import pkgutil
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PASSES = 0


def require(condition: bool, message: str) -> None:
    """Record one passed validation or stop on failure."""
    global PASSES

    if not condition:
        raise AssertionError(message)

    PASSES += 1
    print(f"PASS: {message}")


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON configuration file."""
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for block in iter(lambda: input_file.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def run_command(command: list[str], description: str) -> str:
    """Run one validation command and preserve its real output."""
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    output = "\n".join(
        part.rstrip()
        for part in (result.stdout, result.stderr)
        if part.strip()
    )

    if output:
        print(output)

    require(result.returncode == 0, description)
    return output


def sqlite_objects(
    connection: sqlite3.Connection,
    object_type: str,
) -> set[str]:
    """Return SQLite object names of one type."""
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?",
            (object_type,),
        )
    }


def rebuild_tracked_schema(schema_path: Path) -> tuple[int, int]:
    """Build and remove a temporary database from the tracked schema."""
    schema = schema_path.read_text(encoding="utf-8")
    database_path: Path | None = None
    table_count = 0
    index_count = 0

    with tempfile.TemporaryDirectory(
        prefix="netshield-stage14-"
    ) as temporary_directory:
        database_path = (
            Path(temporary_directory) / "stage14-clean-state.db"
        )
        connection = sqlite3.connect(database_path)

        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(schema)

            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            foreign_key_issues = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            tables = sqlite_objects(connection, "table")
            indexes = {
                name
                for name in sqlite_objects(connection, "index")
                if not name.startswith("sqlite_autoindex")
            }

            required_tables = {
                "security_events",
                "rejected_events",
                "device_alerts",
                "v2_identity_alerts",
                "access_policy_decisions",
                "v2_network_alerts",
                "v2_endpoint_alerts",
                "v2_vulnerability_findings",
                "v2_monitoring_cycles",
                "v2_continuous_risk_scores",
                "v2_xdr_incidents",
                "v2_incidents",
                "v2_containment_actions",
                "v2_recovery_actions",
                "v2_recovery_retests",
                "v2_post_incident_reviews",
                "audit_events",
            }

            require(
                integrity == "ok" and foreign_key_issues == [],
                "Tracked schema creates a clean database with valid integrity",
            )
            require(
                required_tables <= tables,
                "Clean database contains the required enterprise tables",
            )
            require(
                len(indexes) > 0,
                "Clean database contains tracked investigation indexes",
            )

            table_count = len(tables)
            index_count = len(indexes)
        finally:
            connection.close()

    require(
        database_path is not None and not database_path.exists(),
        "Temporary clean-state database was removed safely",
    )

    return table_count, index_count


def compile_python() -> None:
    """Compile tracked Python directories."""
    run_command(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "src",
            "scripts",
            "tests",
            "lab",
        ],
        "Python syntax compilation passed",
    )


def import_source_modules() -> int:
    """Import every module below src."""
    imported_modules = 0
    sys.dont_write_bytecode = True
    source_package = importlib.import_module("src")

    for module in pkgutil.walk_packages(
        source_package.__path__,
        prefix="src.",
    ):
        importlib.import_module(module.name)
        imported_modules += 1

    require(
        imported_modules > 0,
        "All discoverable source modules imported successfully",
    )
    return imported_modules


def check_no_microsoft_dependency() -> None:
    """Confirm source code does not import Microsoft platform SDKs."""
    prohibited_roots = {
        "azure",
        "msal",
        "microsoft",
        "office365",
    }
    prohibited_imports: list[str] = []

    for path in sorted((ROOT / "src").rglob("*.py")):
        tree = ast.parse(
            path.read_text(encoding="utf-8"),
            filename=str(path),
        )

        for node in ast.walk(tree):
            imported_names: list[str] = []

            if isinstance(node, ast.Import):
                imported_names = [
                    alias.name for alias in node.names
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_names = [node.module]

            for imported_name in imported_names:
                if imported_name.split(".", 1)[0] in prohibited_roots:
                    prohibited_imports.append(
                        f"{path.relative_to(ROOT)}:{imported_name}"
                    )

    require(
        prohibited_imports == [],
        "Source modules have no Microsoft platform SDK dependency",
    )


def documentation_is_aligned(
    configuration: dict[str, Any],
) -> bool:
    """Return whether final project documentation is complete and aligned."""
    expected_files = {
        "README.md",
        "docs/workflow.md",
        "docs/security_logic.md",
        "docs/notes.md",
        "docs/commands.md",
        "docs/handbook.md",
    }
    configured_files = set(configuration["documentation_files"])

    if configured_files != expected_files:
        return False

    paths = {
        relative_path: ROOT / relative_path
        for relative_path in expected_files
    }

    if not all(
        path.is_file() and path.stat().st_size > 0
        for path in paths.values()
    ):
        return False

    documents = {
        relative_path: path.read_text(encoding="utf-8")
        for relative_path, path in paths.items()
    }
    combined = "\n".join(documents.values())
    combined_lower = combined.lower()

    required_titles = {
        "README.md": "# NetShield Enterprise Upgrade",
        "docs/workflow.md":
            "# NetShield Enterprise Upgrade Workflow",
        "docs/security_logic.md":
            "# NetShield Enterprise Upgrade Security Logic",
        "docs/notes.md":
            "# NetShield Enterprise Upgrade Engineering Notes",
        "docs/commands.md":
            "# NetShield Enterprise Upgrade Commands",
        "docs/handbook.md":
            "# NetShield Enterprise Upgrade Handbook",
    }

    if not all(
        documents[relative_path].startswith(title)
        for relative_path, title in required_titles.items()
    ):
        return False

    prohibited_wording = {
        "i wrote the python code",
        "i coded this from scratch",
        "i personally wrote the script",
        "i hand-coded the application",
        "i independently authored the source code",
        "ai-generated",
        "ai assistance",
    }

    if any(
        phrase in combined_lower
        for phrase in prohibited_wording
    ):
        return False

    outdated_wording = {
        "stage 15 will",
        "documentation alignment is explicitly deferred",
        "documentation alignment: deferred",
        "documentation alignment remains part of stage 15",
    }

    if any(
        phrase in combined_lower
        for phrase in outdated_wording
    ):
        return False

    readme = documents["README.md"]
    required_readme_sections = {
        "## Architecture",
        "## Concept-to-implementation mapping",
        "## Known limitations",
        "## System Validation",
    }

    if not required_readme_sections <= set(readme.splitlines()):
        return False

    if (
        "151 tests passed with zero unclosed-database warnings."
        not in readme
    ):
        return False

    notes = documents["docs/notes.md"]
    commands = documents["docs/commands.md"]
    reduced_warning_documents = (
        documents["docs/workflow.md"]
        + documents["docs/security_logic.md"]
        + documents["docs/handbook.md"]
    )

    if (
        "ResourceWarning" not in notes
        or "ResourceWarning" not in commands
        or "ResourceWarning" in reduced_warning_documents
    ):
        return False

    handbook = documents["docs/handbook.md"]

    if not all(
        f"## {number}." in handbook
        for number in range(1, 10)
    ):
        return False

    requirements = configuration["documentation_requirements"]

    return (
        configuration["documentation_validation"] is True
        and requirements["alignment_status"] == "completed"
        and requirements[
            "microsoft_references_are_design_concepts"
        ]
        is True
        and requirements[
            "prohibit_personal_code_authorship_claims"
        ]
        is True
        and requirements["require_readme_architecture"] is True
        and requirements["require_readme_concept_mapping"] is True
        and requirements["require_readme_known_limitations"] is True
        and requirements["require_readme_system_validation"] is True
        and requirements[
            "require_handbook_nine_section_structure"
        ]
        is True
    )


def run_complete_test_suite() -> int:
    """Run all tests with resource warnings treated as errors."""
    output = run_command(
        [
            sys.executable,
            "-W",
            "error::ResourceWarning",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test*.py",
        ],
        "Unit, integration and end-to-end tests passed",
    )

    match = re.search(r"Ran (\d+) tests?", output)
    require(
        match is not None,
        "Test runner reported an exact test count",
    )

    test_count = int(match.group(1))
    require(
        test_count >= 279,
        "Full regression retained at least 279 tests",
    )
    return test_count


def run_stage_validators(configuration: dict[str, Any]) -> int:
    """Run every configured V2 validator."""
    completed = 0

    for module_name in configuration["stage_validators"]:
        print(f"RUNNING: {module_name}")
        run_command(
            [sys.executable, "-m", module_name],
            f"Validator passed: {module_name}",
        )
        completed += 1

    require(
        completed == 13,
        "All thirteen earlier V2 stage validators passed",
    )
    return completed


def validate_live_database(
    database_path: Path,
) -> tuple[int, int]:
    """Check integrated live evidence without changing it."""
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    try:
        require(
            connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            == "ok",
            "Live SQLite integrity is valid",
        )
        require(
            connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            == [],
            "Live SQLite foreign keys are valid",
        )

        minimum_records = {
            "security_events": 1,
            "device_alerts": 1,
            "v2_identity_alerts": 1,
            "access_policy_decisions": 1,
            "v2_network_alerts": 1,
            "v2_endpoint_alerts": 1,
            "v2_vulnerability_findings": 1,
            "v2_monitoring_cycles": 1,
            "v2_continuous_risk_scores": 1,
            "v2_xdr_incidents": 3,
            "v2_incidents": 3,
            "v2_containment_actions": 4,
            "v2_recovery_actions": 8,
            "v2_recovery_retests": 2,
            "v2_post_incident_reviews": 1,
            "audit_events": 1,
        }

        for table, minimum in minimum_records.items():
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            require(
                count >= minimum,
                f"Integrated evidence exists: {table}",
            )

        require(
            connection.execute(
                "SELECT COUNT(*) FROM rejected_events"
            ).fetchone()[0]
            >= 1,
            "Malformed input evidence remains quarantined",
        )

        denied_audits = connection.execute(
            "SELECT COUNT(*) FROM audit_events "
            "WHERE result = 'denied'"
        ).fetchone()[0]
        failed_audits = connection.execute(
            "SELECT COUNT(*) FROM audit_events "
            "WHERE result = 'failed'"
        ).fetchone()[0]

        require(
            denied_audits >= 1 and failed_audits >= 1,
            "Denied and failed response actions remain audited",
        )

        require(
            connection.execute(
                "SELECT COUNT(*) FROM v2_containment_rollbacks "
                "WHERE rollback_status = 'successful'"
            ).fetchone()[0]
            >= 1,
            "Successful safe rollback remains recorded",
        )

        incident = connection.execute(
            "SELECT status, closure_reason "
            "FROM v2_incidents "
            "WHERE incident_id = 'INC-V2-11-0001'"
        ).fetchone()

        require(
            incident is not None
            and incident["status"] == "Closed"
            and incident["closure_reason"],
            "Evidence-backed incident reached verified closure",
        )

        require(
            connection.execute(
                "SELECT COUNT(*) FROM v2_recovery_retests "
                "WHERE verification_status = 'passed' "
                "AND confirmed_no_longer_succeeds = 1"
            ).fetchone()[0]
            >= 2,
            "Original threat and vulnerability retests remain passed",
        )

        incident_evidence = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_evidence"
        ).fetchone()[0]
        recovery_evidence = connection.execute(
            "SELECT COUNT(*) FROM v2_recovery_evidence"
        ).fetchone()[0]

        require(
            incident_evidence >= 65 and recovery_evidence >= 8,
            "Incident and recovery evidence remain complete",
        )

        iocs = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_iocs"
        ).fetchone()[0]
        behaviours = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_behaviours"
        ).fetchone()[0]

        require(
            iocs >= 10 and behaviours >= 31,
            "IoC and behaviour extraction remain available",
        )

        audit_count = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

        return (
            audit_count,
            incident_evidence + recovery_evidence,
        )
    finally:
        connection.close()


def validate_safety(configuration: dict[str, Any]) -> None:
    """Validate Stage 14 and response-control boundaries."""
    stage12 = load_json(
        ROOT / "config/v2_containment_response.json"
    )
    stage13 = load_json(
        ROOT / "config/v2_eradication_recovery.json"
    )
    settings = load_json(ROOT / "config/settings.json")

    require(
        configuration["validation_only"] is True
        and configuration["allow_real_actions"] is False
        and configuration["allow_external_targets"] is False
        and configuration["microsoft_services_required"] is False,
        "Stage 14 remains validation-only and platform-independent",
    )

    require(
        stage12["simulation_only"] is True
        and stage12["allow_real_actions"] is False
        and stage12["allow_external_targets"] is False
        and stage13["simulation_only"] is True
        and stage13["allow_real_actions"] is False
        and stage13["allow_external_targets"] is False
        and settings["security"]["allow_real_external_targets"]
        is False,
        "Response controls remain local simulations",
    )

    require(
        configuration["clean_state"]["preserve_live_database"]
        is True
        and configuration["clean_state"]["copy_live_database"]
        is False
        and configuration["clean_state"][
            "rebuild_from_tracked_schema"
        ]
        is True,
        "Clean-state validation protects the live database",
    )

    require(
        documentation_is_aligned(configuration),
        "Documentation alignment is complete",
    )


def main() -> None:
    """Run full Stage 14 enterprise-concept validation."""
    print("V2 STAGE 14 — FULL ENTERPRISE-CONCEPT VALIDATION")

    required_files = {
        ROOT / "config/v2_full_enterprise_validation.json",
        ROOT / "scripts/validate_v2_stage14.py",
        ROOT / "database/schema.sql",
    }

    require(
        all(
            path.is_file() and path.stat().st_size > 0
            for path in required_files
        ),
        "Stage 14 required files exist",
    )

    configuration = load_json(
        ROOT / "config/v2_full_enterprise_validation.json"
    )
    settings = load_json(ROOT / "config/settings.json")
    database_path = ROOT / settings["database"]["path"]

    require(
        configuration["stage"] == 14
        and len(configuration["validation_areas"]) == 33
        and len(configuration["stage_validators"]) == 13,
        "Stage 14 validation contract is complete",
    )

    validate_safety(configuration)
    check_no_microsoft_dependency()

    database_hash_before = sha256_file(database_path)

    clean_tables, clean_indexes = rebuild_tracked_schema(
        ROOT / "database/schema.sql"
    )
    compile_python()
    imported_modules = import_source_modules()
    test_count = run_complete_test_suite()
    validator_count = run_stage_validators(configuration)
    audit_count, evidence_count = validate_live_database(
        database_path
    )

    database_hash_after = sha256_file(database_path)

    require(
        database_hash_before == database_hash_after,
        "Stage 14 validation did not change the live database",
    )

    print()
    print(f"Clean-state tables: {clean_tables}")
    print(f"Clean-state named indexes: {clean_indexes}")
    print(f"Imported source modules: {imported_modules}")
    print(f"Regression tests: {test_count}")
    print(f"V2 validators: {validator_count}")
    print(f"Audit records checked: {audit_count}")
    print(
        "Incident and recovery evidence records: "
        f"{evidence_count}"
    )
    print("Documentation alignment: COMPLETED")
    print(
        f"V2 STAGE 14 VALIDATION: PASS ({PASSES}/{PASSES})"
    )


if __name__ == "__main__":
    main()
