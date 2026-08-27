"""Validate the isolated NetShield Stage 6 SQL injection lab."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parent
DATABASE_PATH = LAB_ROOT / "data" / "sql_injection_lab.db"
REQUEST_PATH = LAB_ROOT / "data" / "stage6_requests.jsonl"
LOG_PATH = LAB_ROOT / "logs" / "application_events.jsonl"
REPORT_PATH = LAB_ROOT / "outputs" / "stage6_detection_report.json"


def check(condition: bool, message: str) -> bool:
    """Print one validation result."""
    if condition:
        print(f"PASS: {message}")
        return True

    print(f"FAIL: {message}")
    return False


def load_json_lines(path: Path) -> list[dict]:
    """Load JSONL records."""
    if not path.exists():
        return []

    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def main() -> None:
    """Run Stage 6 validation checks."""
    passed = 0
    total = 0

    def validate(condition: bool, message: str) -> None:
        nonlocal passed, total
        total += 1
        passed += int(check(condition, message))

    requests = load_json_lines(REQUEST_PATH)
    logs = load_json_lines(LOG_PATH)

    report = {}
    if REPORT_PATH.exists():
        report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )

    request_analysis = report.get("request_analysis", {})
    log_analysis = report.get(
        "application_log_analysis",
        {},
    )

    validate(
        DATABASE_PATH.exists(),
        "Isolated SQLite database exists",
    )
    validate(
        REQUEST_PATH.exists(),
        "Stage 6 request evidence exists",
    )
    validate(
        LOG_PATH.exists(),
        "Clean application event log exists",
    )
    validate(
        REPORT_PATH.exists(),
        "Stage 6 detection report exists",
    )
    validate(
        len(requests) == 7,
        "Seven controlled requests were analysed",
    )
    validate(
        len(logs) == 7,
        "Seven application events were logged",
    )
    validate(
        request_analysis.get(
            "vulnerable_authentication_bypasses"
        ) == 4,
        "Four vulnerable authentication bypasses detected",
    )
    validate(
        request_analysis.get("database_errors") == 1,
        "One vulnerable-query database error detected",
    )
    validate(
        request_analysis.get(
            "repeated_abnormal_sources"
        ) == {"192.0.2.44": 3},
        "Repeated abnormal source IP was identified",
    )
    validate(
        request_analysis.get(
            "parameterised_retests_blocked"
        ) == 1,
        "Parameterised-query retest blocked the bypass",
    )
    validate(
        log_analysis.get("authentication_bypass_events")
        == 4,
        "Application log records four bypass events",
    )
    validate(
        log_analysis.get("database_error_events") == 1,
        "Application log records one database error",
    )
    validate(
        log_analysis.get(
            "suspicious_input_blocked_events"
        ) == 1,
        "Application log records one blocked retest",
    )

    with sqlite3.connect(DATABASE_PATH) as connection:
        users_table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'users'
            """
        ).fetchone()

        user_count = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    validate(
        users_table == ("users",),
        "Users table remains present after testing",
    )
    validate(
        user_count == 1,
        "Isolated test database retains its test account",
    )

    print()
    print(
        f"STAGE 6 VALIDATION: "
        f"{'PASS' if passed == total else 'FAIL'} "
        f"({passed}/{total})"
    )


if __name__ == "__main__":
    main()
