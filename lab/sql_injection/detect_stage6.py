"""Detect and summarise SQL injection activity in the local lab."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


LAB_ROOT = Path(__file__).resolve().parent
REQUEST_PATH = LAB_ROOT / "data" / "stage6_requests.jsonl"
LOG_PATH = LAB_ROOT / "logs" / "application_events.jsonl"
REPORT_PATH = LAB_ROOT / "outputs" / "stage6_detection_report.json"

REPEATED_REQUEST_THRESHOLD = 3


def load_json_lines(path: Path) -> list[dict[str, Any]]:
    """Load structured JSONL records."""
    if not path.exists():
        return []

    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records


def analyse_requests(
    requests: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyse generated request results."""
    vulnerable_bypasses = [
        request
        for request in requests
        if (
            request["actual_query_mode"] == "vulnerable"
            and request["authenticated"]
            and request["request_id"] != "SQL6-001"
        )
    ]

    database_errors = [
        request
        for request in requests
        if request["database_error"] is not None
    ]

    remediation_retests = [
        request
        for request in requests
        if request["actual_query_mode"] == "parameterised"
    ]

    source_ip_counts = Counter(
        request["source_ip"]
        for request in requests
    )

    abnormal_by_ip: dict[str, int] = defaultdict(int)

    for request in requests:
        suspicious = (
            request["database_error"] is not None
            or (
                request["actual_query_mode"] == "vulnerable"
                and request["authenticated"]
                and request["request_id"] != "SQL6-001"
            )
            or "injection" in request["description"].lower()
            or "bypass" in request["description"].lower()
        )

        if suspicious:
            abnormal_by_ip[request["source_ip"]] += 1

    repeated_sources = {
        source_ip: count
        for source_ip, count in abnormal_by_ip.items()
        if count >= REPEATED_REQUEST_THRESHOLD
    }

    blocked_retests = [
        request
        for request in remediation_retests
        if not request["authenticated"]
        and request["database_error"] is None
    ]

    return {
        "total_requests": len(requests),
        "vulnerable_authentication_bypasses": len(
            vulnerable_bypasses
        ),
        "database_errors": len(database_errors),
        "parameterised_retests": len(remediation_retests),
        "parameterised_retests_blocked": len(
            blocked_retests
        ),
        "source_ip_request_counts": dict(
            sorted(source_ip_counts.items())
        ),
        "abnormal_requests_by_source_ip": dict(
            sorted(abnormal_by_ip.items())
        ),
        "repeated_abnormal_sources": repeated_sources,
        "vulnerable_request_ids": [
            request["request_id"]
            for request in vulnerable_bypasses
        ],
        "database_error_request_ids": [
            request["request_id"]
            for request in database_errors
        ],
        "blocked_retest_request_ids": [
            request["request_id"]
            for request in blocked_retests
        ],
    }


def analyse_logs(
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyse application security events."""
    event_counts = Counter(
        event["event_type"]
        for event in events
    )

    source_ip_counts = Counter(
        event["source_ip"]
        for event in events
    )

    return {
        "total_logged_events": len(events),
        "event_type_counts": dict(
            sorted(event_counts.items())
        ),
        "logged_events_by_source_ip": dict(
            sorted(source_ip_counts.items())
        ),
        "database_error_events": event_counts.get(
            "database_error",
            0,
        ),
        "authentication_bypass_events": event_counts.get(
            "authentication_bypass_attempt",
            0,
        ),
        "suspicious_input_blocked_events": event_counts.get(
            "suspicious_input_blocked",
            0,
        ),
    }


def main() -> None:
    """Generate the Stage 6 detection report."""
    requests = load_json_lines(REQUEST_PATH)
    events = load_json_lines(LOG_PATH)

    request_analysis = analyse_requests(requests)
    log_analysis = analyse_logs(events)

    report = {
        "stage": 6,
        "scope": "SQL injection detection",
        "request_analysis": request_analysis,
        "application_log_analysis": log_analysis,
        "sandbox_boundary": {
            "local_test_application_only": True,
            "external_targets_used": False,
            "real_accounts_used": False,
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("STAGE 6 SQL INJECTION DETECTION")
    print(
        "REQUESTS ANALYSED: "
        f"{request_analysis['total_requests']}"
    )
    print(
        "VULNERABLE BYPASSES: "
        f"{request_analysis['vulnerable_authentication_bypasses']}"
    )
    print(
        "DATABASE ERRORS: "
        f"{request_analysis['database_errors']}"
    )
    print(
        "REMEDIATION RETESTS BLOCKED: "
        f"{request_analysis['parameterised_retests_blocked']}"
    )
    print(
        "REPEATED ABNORMAL SOURCES: "
        f"{len(request_analysis['repeated_abnormal_sources'])}"
    )
    print(
        "LOGGED EVENTS: "
        f"{log_analysis['total_logged_events']}"
    )
    print(f"REPORT: {REPORT_PATH}")


if __name__ == "__main__":
    main()
