"""Detect and store Phase 3A V2 Stage 7 endpoint activity."""

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.sqlite_connection import managed_connection


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_stage7_events(
    database_path: Path,
    source_files: list[str],
) -> list[dict[str, Any]]:
    """Load configured endpoint events with preserved raw evidence."""
    if not source_files:
        return []

    placeholders = ", ".join("?" for _ in source_files)

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT * FROM security_events
            WHERE source_type = 'endpoint'
              AND source_file IN ({placeholders})
            ORDER BY event_time, event_key
            """,
            tuple(source_files),
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_event"))
        events.append(event)

    return events


def load_device_inventory(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load the existing authoritative device inventory."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM device_inventory ORDER BY device_id"
        ).fetchall()

    return [dict(row) for row in rows]


def is_approved_exception(
    event: dict[str, Any],
    configuration: dict[str, Any],
) -> bool:
    """Match only exact approved administrative or testing evidence."""
    event_id = event["source_event_id"]
    raw = event["raw"]
    exceptions = configuration["approved_exceptions"]

    if event_id in exceptions["administrative_event_ids"]:
        return (
            raw.get("administrative_activity") is True
            and raw.get("status") == "approved"
            and bool(raw.get("approval_reference"))
        )

    if event_id in exceptions["testing_ids"]:
        return (
            raw.get("controlled_testing") is True
            and raw.get("testing_id") == event_id
            and raw.get("status") == "approved_testing"
        )

    return False


def _alert_key(
    detection_type: str,
    source_event_ids: list[str],
    device_id: str | None,
) -> str:
    material = "|".join(
        [
            detection_type,
            device_id or "unknown",
            *sorted(source_event_ids),
        ]
    )

    return "v2-endpoint-" + hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


def _inventory_context(
    event: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    record = inventory.get(event.get("device_id"))

    if record is None:
        return None

    fields = (
        "asset_id",
        "device_id",
        "hostname",
        "assigned_user",
        "registration_status",
        "compliance_status",
        "risk_status",
        "criticality",
    )

    return {
        field: record.get(field)
        for field in fields
    }


def _build_alert(
    detection_type: str,
    severity: str,
    confidence: int,
    events: list[dict[str, Any]],
    reason_codes: list[str],
    inventory: dict[str, dict[str, Any]],
    observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered = sorted(
        events,
        key=lambda event: (
            event["event_time"],
            event["event_key"],
        ),
    )
    first = ordered[0]
    last = ordered[-1]
    raw = last["raw"]

    source_ids = [
        event["source_event_id"]
        for event in ordered
    ]

    evidence = {
        "inventory": _inventory_context(
            last,
            inventory,
        ),
        "observations": observations or {},
        "source_events": [
            {
                "event_id": event["source_event_id"],
                "event_time": event["event_time"],
                "event_type": event["event_type"],
                "raw_event": event["raw"],
            }
            for event in ordered
        ],
    }

    return {
        "alert_key": _alert_key(
            detection_type,
            source_ids,
            last.get("device_id"),
        ),
        "created_at": utc_now(),
        "detection_type": detection_type,
        "severity": severity,
        "confidence": confidence,
        "first_event_time": first["event_time"],
        "last_event_time": last["event_time"],
        "source_event_ids": source_ids,
        "source_types": sorted(
            {
                event["source_type"]
                for event in ordered
            }
        ),
        "device_id": last.get("device_id"),
        "asset_id": last.get("asset_id"),
        "username": last.get("username"),
        "hostname": last.get("hostname"),
        "ip_address": last.get("ip_address"),
        "mac_address": last.get("mac_address"),
        "location": last.get("location"),
        "health_state": raw.get("health_state"),
        "compliance_state": raw.get(
            "compliance_state"
        ),
        "device_risk_state": raw.get(
            "device_risk_state"
        ),
        "process_name": raw.get("process_name"),
        "process_id": raw.get("process_id"),
        "process_owner": raw.get("process_owner"),
        "parent_process_name": raw.get(
            "parent_process_name"
        ),
        "command_line": raw.get("command_line"),
        "cpu_percent": raw.get("cpu_percent"),
        "file_path": raw.get("file_path"),
        "expected_hash": raw.get("expected_hash"),
        "observed_hash": raw.get("observed_hash"),
        "reason_codes": reason_codes,
        "evidence": evidence,
        "status": "New",
    }


def _complete_windows(
    events: list[dict[str, Any]],
    required: int,
    minutes: int,
) -> list[list[dict[str, Any]]]:
    ordered = sorted(
        events,
        key=lambda event: (
            event["event_time"],
            event["event_key"],
        ),
    )
    windows = []
    index = 0

    while index + required <= len(ordered):
        candidate = ordered[
            index:index + required
        ]
        duration = (
            parse_time(candidate[-1]["event_time"])
            - parse_time(candidate[0]["event_time"])
        ).total_seconds()

        if duration <= minutes * 60:
            windows.append(candidate)
            index += required
        else:
            index += 1

    return windows


def detect_endpoint_activity(
    events: list[dict[str, Any]],
    configuration: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply all approved Stage 7 detection families."""
    inventory_map = {
        record["device_id"]: record
        for record in inventory
    }
    alerts: list[dict[str, Any]] = []

    def add(
        name: str,
        severity: str,
        confidence: int,
        matched: list[dict[str, Any]],
        reasons: list[str],
        observations: dict[str, Any] | None = None,
    ) -> None:
        alerts.append(
            _build_alert(
                name,
                severity,
                confidence,
                matched,
                reasons,
                inventory_map,
                observations,
            )
        )

    process_policy = configuration[
        "process_policy"
    ]
    suspicious_processes = set(
        process_policy["suspicious_processes"]
    )
    unapproved_statuses = set(
        process_policy["unapproved_statuses"]
    )
    approved_owners = process_policy[
        "approved_owners_by_process"
    ]
    suspicious_pairs = {
        (
            pair["parent"],
            pair["child"],
        )
        for pair in process_policy[
            "suspicious_parent_child_pairs"
        ]
    }
    command_indicators = process_policy[
        "suspicious_command_indicators"
    ]
    persistence_indicators = set(
        process_policy["persistence_indicators"]
    )
    file_policy = configuration[
        "file_integrity"
    ]

    state_rules = (
        (
            "health_state",
            "health_policy",
            "Endpoint Health State",
            "ENDPOINT_HEALTH_STATE",
        ),
        (
            "compliance_state",
            "compliance_policy",
            "Device Compliance State",
            "DEVICE_COMPLIANCE_STATE",
        ),
        (
            "device_risk_state",
            "device_risk_policy",
            "Device Risk State",
            "DEVICE_RISK_STATE",
        ),
    )

    for event in events:
        if is_approved_exception(
            event,
            configuration,
        ):
            continue

        raw = event["raw"]

        for (
            field,
            policy_name,
            name,
            reason,
        ) in state_rules:
            state = raw.get(field)
            policy = configuration[
                policy_name
            ]["alert_states"].get(state)

            if policy:
                add(
                    name,
                    policy["severity"],
                    policy["confidence"],
                    [event],
                    [
                        f"{reason}_"
                        f"{state.upper()}"
                    ],
                    {field: state},
                )

        process = raw.get("process_name")
        process_status = raw.get(
            "process_status"
        )
        owner = raw.get("process_owner")
        parent = raw.get(
            "parent_process_name"
        )

        if process in suspicious_processes:
            add(
                "Suspicious Process",
                "Critical",
                95,
                [event],
                ["SUSPICIOUS_PROCESS_MATCH"],
                {
                    "matched_process": process,
                },
            )

        if process_status in unapproved_statuses:
            add(
                "Unknown or Unapproved Process",
                "High",
                85,
                [event],
                ["PROCESS_NOT_APPROVED"],
                {
                    "process_name": process,
                    "process_status": process_status,
                },
            )

        expected_owners = approved_owners.get(
            process
        )

        if (
            expected_owners
            and owner
            and owner not in expected_owners
        ):
            add(
                "Unexpected Process Owner",
                "High",
                85,
                [event],
                [
                    "PROCESS_OWNER_"
                    "OUTSIDE_BASELINE"
                ],
                {
                    "observed_owner": owner,
                    "approved_owners":
                        expected_owners,
                },
            )

        if (
            parent,
            process,
        ) in suspicious_pairs:
            add(
                (
                    "Suspicious Parent-Child "
                    "Process Relationship"
                ),
                "Critical",
                95,
                [event],
                [
                    "SUSPICIOUS_"
                    "PARENT_CHILD_PAIR"
                ],
                {
                    "parent_process": parent,
                    "child_process": process,
                },
            )

        command = raw.get(
            "command_line"
        ) or ""

        matched_commands = [
            value
            for value in command_indicators
            if value in command
        ]

        if matched_commands:
            add(
                "Suspicious Command Activity",
                "Critical",
                95,
                [event],
                [
                    "SUSPICIOUS_"
                    "COMMAND_INDICATOR"
                ],
                {
                    "matched_indicators":
                        matched_commands,
                },
            )

        persistence = raw.get(
            "persistence_indicator"
        )

        if persistence in persistence_indicators:
            add(
                (
                    "Possible Persistence "
                    "Indicator"
                ),
                "High",
                90,
                [event],
                [
                    "PERSISTENCE_"
                    "INDICATOR_MATCH"
                ],
                {
                    "matched_indicator":
                        persistence,
                },
            )

        file_path = raw.get("file_path")
        expected_hash = file_policy[
            "approved_hashes"
        ].get(file_path)
        observed_hash = raw.get(
            "observed_hash"
        )

        if (
            expected_hash
            and observed_hash
            and expected_hash != observed_hash
        ):
            add(
                "Unexpected File-Hash Change",
                file_policy[
                    "unexpected_change_severity"
                ],
                file_policy[
                    "unexpected_change_confidence"
                ],
                [event],
                [
                    "FILE_HASH_"
                    "OUTSIDE_BASELINE"
                ],
                {
                    "file_path": file_path,
                    "expected_hash":
                        expected_hash,
                    "observed_hash":
                        observed_hash,
                },
            )

        if (
            event["event_type"]
            == "post_isolation_activity_observed"
            and raw.get("isolation_state")
            == "simulated_isolated"
        ):
            add(
                (
                    "Post-Isolation "
                    "Endpoint Activity"
                ),
                "Critical",
                95,
                [event],
                [
                    "ACTIVITY_AFTER_"
                    "SIMULATED_ISOLATION"
                ],
                {
                    "isolation_state":
                        raw.get(
                            "isolation_state"
                        ),
                    "real_isolation_executed":
                        raw.get(
                            "real_isolation_executed"
                        ),
                    "network_state_changed":
                        raw.get(
                            "network_state_changed"
                        ),
                },
            )

    thresholds = configuration["thresholds"]

    cpu_groups: dict[
        tuple[Any, Any],
        list[dict[str, Any]],
    ] = defaultdict(list)

    crash_groups: dict[
        tuple[Any, Any],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if is_approved_exception(
            event,
            configuration,
        ):
            continue

        raw = event["raw"]
        key = (
            event.get("device_id"),
            raw.get("process_name"),
        )
        cpu = raw.get("cpu_percent")

        if (
            cpu is not None
            and float(cpu)
            >= thresholds[
                "cpu_warning_percent"
            ]
        ):
            cpu_groups[key].append(event)

        if event["event_type"] in {
            "process_crashed",
            "process_restarted",
        }:
            crash_groups[key].append(event)

    for group in cpu_groups.values():
        for window in _complete_windows(
            group,
            thresholds[
                "repeated_cpu_events"
            ],
            thresholds[
                "cpu_window_minutes"
            ],
        ):
            maximum = max(
                float(
                    item["raw"]["cpu_percent"]
                )
                for item in window
            )
            severity = (
                "Critical"
                if maximum
                >= thresholds[
                    "cpu_critical_percent"
                ]
                else "High"
            )

            add(
                "High CPU Activity",
                severity,
                90,
                window,
                [
                    "REPEATED_HIGH_"
                    "CPU_ACTIVITY"
                ],
                {
                    "event_count":
                        len(window),
                    "maximum_cpu_percent":
                        maximum,
                    "window_minutes":
                        thresholds[
                            "cpu_window_minutes"
                        ],
                },
            )

    for group in crash_groups.values():
        for window in _complete_windows(
            group,
            thresholds[
                "process_crash_restart_events"
            ],
            thresholds[
                "process_crash_restart_window_minutes"
            ],
        ):
            observed = (
                parse_time(
                    window[-1]["event_time"]
                )
                - parse_time(
                    window[0]["event_time"]
                )
            ).total_seconds() / 60

            add(
                (
                    "Repeated Process "
                    "Crash or Restart"
                ),
                "High",
                90,
                window,
                [
                    "PROCESS_CRASH_"
                    "RESTART_THRESHOLD"
                ],
                {
                    "event_count":
                        len(window),
                    "observed_window_minutes":
                        observed,
                    "configured_window_minutes":
                        thresholds[
                            "process_crash_"
                            "restart_window_minutes"
                        ],
                },
            )

    return sorted(
        alerts,
        key=lambda alert: (
            alert["first_event_time"],
            alert["detection_type"],
            alert["alert_key"],
        ),
    )


def build_isolation_requests(
    alerts: list[dict[str, Any]],
    configuration: dict[str, Any],
    automation_acl: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create one approval-required simulated request per device."""
    policy = configuration[
        "isolation_policy"
    ]
    action = policy["action"]

    if (
        action
        not in automation_acl[
            "approval_required"
        ]
    ):
        raise ValueError(
            "quarantine_device must remain "
            "approval-required"
        )

    if (
        policy["real_isolation_allowed"]
        is not False
    ):
        raise ValueError(
            "Real endpoint isolation "
            "must remain disabled"
        )

    if (
        policy["change_network_state"]
        is not False
    ):
        raise ValueError(
            "Endpoint isolation must not "
            "change network state"
        )

    grouped: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for alert in alerts:
        if (
            alert["severity"]
            in policy["trigger_severities"]
            and alert.get("device_id")
        ):
            grouped[
                alert["device_id"]
            ].append(alert)

    requests = []

    for device_id, device_alerts in sorted(
        grouped.items()
    ):
        ordered = sorted(
            device_alerts,
            key=lambda alert: (
                alert["first_event_time"],
                alert["detection_type"],
                alert["alert_key"],
            ),
        )
        representative = ordered[0]

        digest = hashlib.sha256(
            (
                f"stage7|{device_id}|"
                f"{action}"
            ).encode("utf-8")
        ).hexdigest()

        evidence = {
            "alert_count": len(ordered),
            "alert_keys": [
                alert["alert_key"]
                for alert in ordered
            ],
            "detection_types": sorted(
                {
                    alert["detection_type"]
                    for alert in ordered
                }
            ),
            "reason_codes": sorted(
                {
                    reason
                    for alert in ordered
                    for reason
                    in alert["reason_codes"]
                }
            ),
            "source_event_ids": sorted(
                {
                    event_id
                    for alert in ordered
                    for event_id
                    in alert["source_event_ids"]
                }
            ),
            "simulation_only": True,
            "approval_required": True,
            "real_isolation_allowed": False,
            "network_state_changed": False,
        }

        requests.append(
            {
                "isolation_key":
                    f"v2-isolation-{digest}",
                "alert_key":
                    representative["alert_key"],
                "requested_at": utc_now(),
                "device_id": device_id,
                "asset_id":
                    representative.get(
                        "asset_id"
                    ),
                "action": action,
                "acl_control_level":
                    "approval_required",
                "status":
                    policy["initial_status"],
                "request_reason": (
                    f"{len(ordered)} Critical "
                    "endpoint alerts "
                    f"for device {device_id}"
                ),
                "approved_by": None,
                "approved_at": None,
                "network_state_changed": 0,
                "real_action_executed": 0,
                "evidence": evidence,
            }
        )

    return requests


def _save_records(
    database_path: Path,
    table: str,
    columns: tuple[str, ...],
    records: list[dict[str, Any]],
    json_columns: set[str],
) -> tuple[int, int]:
    created = 0
    existing = 0
    placeholders = ", ".join(
        "?" for _ in columns
    )

    with managed_connection(
        database_path
    ) as connection:
        for record in records:
            values = tuple(
                json.dumps(
                    record.get(column),
                    sort_keys=True,
                )
                if column in json_columns
                else record.get(column)
                for column in columns
            )

            cursor = connection.execute(
                (
                    f"INSERT OR IGNORE INTO "
                    f"{table} "
                    f"({', '.join(columns)}) "
                    f"VALUES ({placeholders})"
                ),
                values,
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing


def save_activity_timeline(
    database_path: Path,
    events: list[dict[str, Any]],
) -> tuple[int, int]:
    columns = (
        "source_event_id",
        "event_time",
        "source_type",
        "event_type",
        "device_id",
        "asset_id",
        "username",
        "hostname",
        "ip_address",
        "mac_address",
        "location",
        "health_state",
        "compliance_state",
        "device_risk_state",
        "process_name",
        "process_id",
        "process_owner",
        "parent_process_name",
        "command_line",
        "cpu_percent",
        "file_path",
        "observed_hash",
        "isolation_state",
        "status",
        "raw_event",
    )
    records = []
    raw_fields = columns[11:24]

    for event in events:
        raw = event["raw"]

        record = {
            field: event.get(field)
            for field in columns[:11]
        }
        record.update(
            {
                field: raw.get(field)
                for field in raw_fields
            }
        )
        record["raw_event"] = raw
        records.append(record)

    return _save_records(
        database_path,
        "v2_endpoint_activity_timeline",
        columns,
        records,
        {"raw_event"},
    )


def save_endpoint_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[int, int]:
    columns = (
        "alert_key",
        "created_at",
        "detection_type",
        "severity",
        "confidence",
        "first_event_time",
        "last_event_time",
        "source_event_ids",
        "source_types",
        "device_id",
        "asset_id",
        "username",
        "hostname",
        "ip_address",
        "mac_address",
        "location",
        "health_state",
        "compliance_state",
        "device_risk_state",
        "process_name",
        "process_id",
        "process_owner",
        "parent_process_name",
        "command_line",
        "cpu_percent",
        "file_path",
        "expected_hash",
        "observed_hash",
        "reason_codes",
        "evidence",
        "status",
    )

    return _save_records(
        database_path,
        "v2_endpoint_alerts",
        columns,
        alerts,
        {
            "source_event_ids",
            "source_types",
            "reason_codes",
            "evidence",
        },
    )


def save_isolation_requests(
    database_path: Path,
    requests: list[dict[str, Any]],
) -> tuple[int, int]:
    columns = (
        "isolation_key",
        "alert_key",
        "requested_at",
        "device_id",
        "asset_id",
        "action",
        "acl_control_level",
        "status",
        "request_reason",
        "approved_by",
        "approved_at",
        "network_state_changed",
        "real_action_executed",
        "evidence",
    )

    return _save_records(
        database_path,
        "v2_endpoint_isolation_actions",
        columns,
        requests,
        {"evidence"},
    )
