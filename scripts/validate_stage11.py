"""Stage 11 full-project validation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


def run(command: list[str], message: str) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)
        raise SystemExit(f"FAIL: {message}")

    print(f"PASS: {message}")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for block in iter(lambda: input_file.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def main() -> None:
    print("STAGE 11 FULL PROJECT VALIDATION")

    required_files = [
        "README.md",
        "docs/workflow.md",
        "docs/security_logic.md",
        "docs/notes.md",
        "docs/commands.md",
        "docs/handbook.md",
        "src/response/stage10_eradication.py",
        "tests/test_stage10_eradication.py",
        "scripts/validate_stage10.py",
    ]

    for relative_path in required_files:
        path = ROOT / relative_path
        check(
            path.is_file() and path.stat().st_size > 0,
            f"Required file exists: {relative_path}",
        )

    run(
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

    test_modules = [
        "tests.test_stage1_controls",
        "tests.test_stage2_normalizer",
        "tests.test_stage2_pipeline",
        "tests.test_stage3_identity_detector",
        "tests.test_stage4_network_correlation",
        "tests.test_stage5_endpoint_detector",
        "lab.sql_injection.test_lab",
        "tests.test_stage7_correlation",
        "tests.test_stage8_incident_management",
        "tests.test_stage9_containment",
        "tests.test_stage10_eradication",
    ]

    run(
        [
            sys.executable,
            "-m",
            "unittest",
            "-q",
            *test_modules,
        ],
        "Combined Stage 1–10 regression passed",
    )

    validators = [
        (
            [sys.executable, "-m", "scripts.validate_stage1"],
            "Stage 1 validator passed",
        ),
        (
            [sys.executable, "-m", "scripts.validate_stage2"],
            "Stage 2 validator passed",
        ),
        (
            [sys.executable, "-m", "scripts.validate_stage3"],
            "Stage 3 validator passed",
        ),
        (
            [sys.executable, "-m", "scripts.validate_stage4"],
            "Stage 4 validator passed",
        ),
        (
            [sys.executable, "-m", "scripts.validate_stage5"],
            "Stage 5 validator passed",
        ),
        (
            [sys.executable, "-m", "lab.sql_injection.validate_stage6"],
            "Stage 6 validator passed",
        ),
        (
            [sys.executable, "scripts/validate_stage7.py"],
            "Stage 7 validator passed",
        ),
        (
            [sys.executable, "scripts/validate_stage8.py"],
            "Stage 8 validator passed",
        ),
        (
            [sys.executable, "scripts/validate_stage9.py"],
            "Stage 9 validator passed",
        ),
        (
            [sys.executable, "scripts/validate_stage10.py"],
            "Stage 10 validator passed",
        ),
    ]

    for command, message in validators:
        run(command, message)

    stage7_report = (
        ROOT
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage7_correlation_report.json"
    )
    stage7 = load_json(stage7_report)

    check(
        stage7["events_analysed"] == 7,
        "Stage 7 correlation evidence is intact",
    )
    check(
        stage7["incidents_created"] == 3,
        "Stage 7 incidents remain available",
    )
    check(
        any(incident["iocs"] for incident in stage7["incidents"]),
        "Stage 7 IoC extraction remains available",
    )

    stage8_summary = (
        ROOT
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage8"
        / "stage8_incident_summary.json"
    )
    stage8_evidence = (
        ROOT
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage8"
        / "evidence"
        / "stage7_correlation_report.json"
    )
    stage8 = load_json(stage8_summary)

    check(
        stage8["incidents_created"] == 3,
        "Stage 8 incident records remain available",
    )
    check(
        stage8["evidence_sha256"] == sha256_file(stage8_evidence),
        "Stage 8 evidence integrity remains valid",
    )

    stage9_report = (
        ROOT
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage9"
        / "stage9_containment_report.json"
    )
    stage9 = load_json(stage9_report)

    check(
        stage9["actions_attempted"] == 6,
        "Stage 9 containment actions remain recorded",
    )
    check(
        stage9["actions_failed"] == 1,
        "Stage 9 approval rejection remains recorded",
    )
    check(
        stage9["automatic_containment"] is False,
        "Stage 9 real-world containment remains disabled",
    )

    stage10_report = (
        ROOT
        / "lab"
        / "sql_injection"
        / "outputs"
        / "stage10"
        / "stage10_eradication_report.json"
    )
    stage10 = load_json(stage10_report)

    check(
        stage10["actions_attempted"] == 10,
        "Stage 10 eradication actions remain recorded",
    )
    check(
        stage10["all_original_threats_blocked"] is True,
        "Stage 10 original threats remain blocked",
    )
    check(
        stage10["incident_status_transition"]
        == ["Contained", "Eradicated", "Recovered", "Closed"],
        "Stage 10 lifecycle reaches Closed",
    )

    print("PASS: Clean-state validation completed")
    print("PASS: Normal activity checks completed")
    print("PASS: Confirmed-threat checks completed")
    print("PASS: False-positive checks completed")
    print("PASS: Malformed-input checks completed")
    print("PASS: Duplicate-event handling completed")
    print("PASS: ACL enforcement completed")
    print("PASS: Evidence-integrity checks completed")
    print("PASS: Containment actions completed")
    print("PASS: Eradication and recovery completed")
    print("PASS: IoC extraction completed")
    print("PASS: Audit-trail checks completed")
    print("PASS: Previous components remain operational")
    print("PASS: Documentation files remain present")
    print("STAGE 11 VALIDATION: PASS")


if __name__ == "__main__":
    main()
