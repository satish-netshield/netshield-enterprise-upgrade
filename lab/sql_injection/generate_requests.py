"""Generate safe local SQL injection test requests."""

from __future__ import annotations

import json
from pathlib import Path

from lab.sql_injection.app import (
    DATABASE_PATH,
    LOG_PATH,
    initialise_database,
    safe_login,
    vulnerable_login,
)


LAB_ROOT = Path(__file__).resolve().parent
REQUEST_PATH = LAB_ROOT / "data" / "stage6_requests.jsonl"


REQUESTS = [
    {
        "request_id": "SQL6-001",
        "source_ip": "127.0.0.1",
        "username": "analyst01",
        "password": "LabPassword-Only",
        "query_mode": "vulnerable",
        "description": "Normal local login",
    },
    {
        "request_id": "SQL6-002",
        "source_ip": "192.0.2.44",
        "username": "' OR 1=1 --",
        "password": "wrong-password",
        "query_mode": "vulnerable",
        "description": "Authentication-bypass attempt",
    },
    {
        "request_id": "SQL6-003",
        "source_ip": "192.0.2.44",
        "username": "' OR 1=1 --",
        "password": "wrong-password",
        "query_mode": "vulnerable",
        "description": "Repeated abnormal request",
    },
    {
        "request_id": "SQL6-004",
        "source_ip": "192.0.2.44",
        "username": "' OR 1=1 --",
        "password": "wrong-password",
        "query_mode": "vulnerable",
        "description": "Repeated abnormal request",
    },
    {
        "request_id": "SQL6-005",
        "source_ip": "198.51.100.18",
        "username": "admin' UNION SELECT 1,2,3 --",
        "password": "wrong-password",
        "query_mode": "vulnerable",
        "description": "UNION injection attempt",
    },
    {
        "request_id": "SQL6-006",
        "source_ip": "198.51.100.19",
        "username": "analyst01",
        "password": "wrong'password",
        "query_mode": "vulnerable",
        "description": "Quote-handling test",
    },
    {
        "request_id": "SQL6-007",
        "source_ip": "192.0.2.44",
        "username": "' OR 1=1 --",
        "password": "wrong-password",
        "query_mode": "parameterised",
        "description": "Retest after remediation",
    },
]


def run_request(request: dict[str, str]) -> dict[str, object]:
    """Run one local request against the selected query implementation."""
    if request["query_mode"] == "vulnerable":
        result = vulnerable_login(
            request["username"],
            request["password"],
            source_ip=request["source_ip"],
            database_path=DATABASE_PATH,
            log_path=LOG_PATH,
        )
    else:
        result = safe_login(
            request["username"],
            request["password"],
            source_ip=request["source_ip"],
            database_path=DATABASE_PATH,
            log_path=LOG_PATH,
        )

    return {
        **request,
        "authenticated": result.authenticated,
        "returned_rows": len(result.rows),
        "database_error": result.error,
        "actual_query_mode": result.query_mode,
    }


def main() -> None:
    """Generate and execute controlled local requests."""
    initialise_database()
    REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    results = []

    with REQUEST_PATH.open("w", encoding="utf-8") as request_file:
        for request in REQUESTS:
            result = run_request(request)
            request_file.write(
                json.dumps(result, sort_keys=True) + "\n"
            )
            results.append(result)

    bypasses = sum(
        1
        for result in results
        if (
            result["actual_query_mode"] == "vulnerable"
            and result["authenticated"]
            and result["request_id"] != "SQL6-001"
        )
    )

    database_errors = sum(
        1
        for result in results
        if result["database_error"] is not None
    )

    remediation_blocks = sum(
        1
        for result in results
        if (
            result["actual_query_mode"] == "parameterised"
            and not result["authenticated"]
        )
    )

    print(f"PASS: Generated {len(results)} local SQL test requests")
    print(
        "VULNERABLE_AUTHENTICATION_BYPASSES: "
        f"{bypasses}"
    )
    print(f"DATABASE_ERRORS: {database_errors}")
    print(
        "PARAMETERISED_REMEDIATION_BLOCKS: "
        f"{remediation_blocks}"
    )
    print(f"REQUEST_FILE: {REQUEST_PATH}")


if __name__ == "__main__":
    main()
