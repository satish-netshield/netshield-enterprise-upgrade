"""Correlate Phase 3A V2 evidence using XDR-style context."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from src.utils.database import utc_now
from src.utils.sqlite_connection import managed_connection


SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def parse_time(value: str) -> datetime:
    """Parse an ISO 8601 timestamp."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_json(value: Any, default: Any) -> Any:
    """Parse stored JSON while preserving a safe fallback."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def json_list(value: Any) -> list[str]:
    """Return a sorted list of non-empty strings from stored JSON."""
    parsed = parse_json(value, [])
    if not isinstance(parsed, list):
        parsed = [parsed]
    return sorted(
        {
            str(item)
            for item in parsed
            if item is not None and str(item).strip()
        }
    )


def stable_key(prefix: str, values: Iterable[str]) -> str:
    """Return a deterministic key for duplicate-safe storage."""
    material = "|".join(sorted(str(value) for value in values))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def fetch_rows(
    database_path: Path,
    query: str,
    parameters: tuple[Any, ...] = (),
) -> list[dict[str, Any]]:
    """Return query rows as dictionaries."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def contribution_for_alert(row: dict[str, Any]) -> str:
    """Classify an alert without deleting reviewed evidence."""
    if row.get("classification") == "False Positive":
        return "exception"
    return "active"


def base_evidence(
    *,
    evidence_key: str,
    source_type: str,
    source_record_id: str,
    event_time: str,
    detection_type: str,
    severity: str,
    confidence: int,
    contribution_status: str,
    source_event_ids: list[str],
    reason_codes: list[str],
    original: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    """Build one normalised correlation evidence record."""
    evidence = {
        "evidence_key": evidence_key,
        "source_type": source_type,
        "source_record_id": str(source_record_id),
        "event_time": event_time,
        "detection_type": detection_type,
        "severity": severity,
        "confidence": max(0, min(int(confidence), 100)),
        "contribution_status": contribution_status,
        "source_event_ids": source_event_ids,
        "reason_codes": reason_codes,
        "attack_techniques": [],
        "explicit_links": [],
        "username": None,
        "device_id": None,
        "asset_id": None,
        "ip_address": None,
        "mac_address": None,
        "hostname": None,
        "process_name": None,
        "file_hash": None,
        "location": None,
        "original_evidence": original,
    }
    evidence.update(fields)
    return evidence


def load_identity_evidence(database_path: Path) -> list[dict[str, Any]]:
    """Load Stage 4 identity alerts."""
    rows = fetch_rows(
        database_path,
        """
        SELECT
            alert_key,
            first_event_time,
            detection_type,
            severity,
            confidence,
            username,
            device_id,
            ip_address,
            location,
            source_event_ids,
            reason_codes,
            mitre_techniques,
            evidence,
            status,
            classification
        FROM v2_identity_alerts
        ORDER BY alert_id
        """,
    )

    evidence_records = []

    for row in rows:
        record = base_evidence(
            evidence_key=f"identity:{row['alert_key']}",
            source_type="identity",
            source_record_id=row["alert_key"],
            event_time=row["first_event_time"],
            detection_type=row["detection_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            contribution_status=contribution_for_alert(row),
            source_event_ids=json_list(row["source_event_ids"]),
            reason_codes=json_list(row["reason_codes"]),
            original=parse_json(row["evidence"], {}),
            username=row["username"],
            device_id=row["device_id"],
            ip_address=row["ip_address"],
            location=row["location"],
        )
        record["attack_techniques"] = json_list(
            row["mitre_techniques"]
        )
        evidence_records.append(record)

    return evidence_records


def access_severity(decision: str) -> str:
    """Map an access outcome to investigation severity."""
    return {
        "allow": "Low",
        "challenge": "Medium",
        "deny": "High",
        "restrict": "Critical",
    }[decision]


def load_access_policy_evidence(
    database_path: Path,
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Load Stage 5 access-policy decisions."""
    rows = fetch_rows(
        database_path,
        """
        SELECT
            decision_key,
            evaluated_at,
            request_event_id,
            username,
            role,
            device_id,
            asset_id,
            location,
            ip_address,
            sign_in_risk,
            user_risk,
            decision,
            reason_codes,
            matched_policy_ids,
            evidence
        FROM access_policy_decisions
        ORDER BY decision_id
        """,
    )

    approved = configuration["activity_treatment"][
        "approved_access_decision"
    ]
    evidence_records = []

    for row in rows:
        risk_values = [
            float(value)
            for value in (
                row["sign_in_risk"],
                row["user_risk"],
            )
            if value is not None
        ]
        confidence = round(max(risk_values)) if risk_values else 0
        decision = row["decision"]

        evidence_records.append(
            base_evidence(
                evidence_key=(
                    f"access_policy:{row['decision_key']}"
                ),
                source_type="access_policy",
                source_record_id=row["decision_key"],
                event_time=row["evaluated_at"],
                detection_type=(
                    f"Access Policy {decision.title()}"
                ),
                severity=access_severity(decision),
                confidence=confidence,
                contribution_status=(
                    "verified"
                    if decision == approved
                    else "active"
                ),
                source_event_ids=[row["request_event_id"]],
                reason_codes=json_list(row["reason_codes"]),
                original={
                    "role": row["role"],
                    "decision": decision,
                    "matched_policy_ids": json_list(
                        row["matched_policy_ids"]
                    ),
                    "evidence": parse_json(
                        row["evidence"],
                        {},
                    ),
                },
                username=row["username"],
                device_id=row["device_id"],
                asset_id=row["asset_id"],
                ip_address=row["ip_address"],
                location=row["location"],
            )
        )

    return evidence_records


def load_network_evidence(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load Stage 6 network and Wi-Fi alerts."""
    rows = fetch_rows(
        database_path,
        """
        SELECT
            alert_key,
            first_event_time,
            detection_type,
            severity,
            confidence,
            device_id,
            asset_id,
            username,
            ip_address,
            mac_address,
            hostname,
            location,
            source_event_ids,
            reason_codes,
            evidence,
            status,
            classification
        FROM v2_network_alerts
        ORDER BY alert_id
        """,
    )

    return [
        base_evidence(
            evidence_key=f"network:{row['alert_key']}",
            source_type="network",
            source_record_id=row["alert_key"],
            event_time=row["first_event_time"],
            detection_type=row["detection_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            contribution_status=contribution_for_alert(row),
            source_event_ids=json_list(row["source_event_ids"]),
            reason_codes=json_list(row["reason_codes"]),
            original=parse_json(row["evidence"], {}),
            username=row["username"],
            device_id=row["device_id"],
            asset_id=row["asset_id"],
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            hostname=row["hostname"],
            location=row["location"],
        )
        for row in rows
    ]


def load_endpoint_evidence(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load Stage 7 endpoint alerts."""
    rows = fetch_rows(
        database_path,
        """
        SELECT
            alert_key,
            first_event_time,
            detection_type,
            severity,
            confidence,
            device_id,
            asset_id,
            username,
            hostname,
            ip_address,
            mac_address,
            location,
            process_name,
            observed_hash,
            source_event_ids,
            reason_codes,
            evidence,
            status,
            classification
        FROM v2_endpoint_alerts
        ORDER BY alert_id
        """,
    )

    return [
        base_evidence(
            evidence_key=f"endpoint:{row['alert_key']}",
            source_type="endpoint",
            source_record_id=row["alert_key"],
            event_time=row["first_event_time"],
            detection_type=row["detection_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            contribution_status=contribution_for_alert(row),
            source_event_ids=json_list(row["source_event_ids"]),
            reason_codes=json_list(row["reason_codes"]),
            original=parse_json(row["evidence"], {}),
            username=row["username"],
            device_id=row["device_id"],
            asset_id=row["asset_id"],
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            hostname=row["hostname"],
            process_name=row["process_name"],
            file_hash=row["observed_hash"],
            location=row["location"],
        )
        for row in rows
    ]


def vulnerability_source_type(
    finding_source: str,
    configuration: dict[str, Any],
) -> str:
    """Separate application evidence from vulnerability evidence."""
    if finding_source in configuration[
        "application_finding_sources"
    ]:
        return "application"
    return "vulnerability"


def vulnerability_contribution(
    row: dict[str, Any],
) -> str:
    """Treat a finding as context unless exploitation is evidenced."""
    if row["exploitation_status"] in {
        "attempted",
        "successful",
    }:
        return "active"

    if (
        row["classification"] == "False Positive"
        or row["remediation_status"] == "False Positive"
    ):
        return "exception"

    if row["remediation_status"] == "Verified":
        return "verified"

    return "context_only"


def load_vulnerability_evidence(
    database_path: Path,
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Load Stage 8 application and vulnerability findings."""
    rows = fetch_rows(
        database_path,
        """
        SELECT
            finding_key,
            source_finding_id,
            updated_at,
            asset_id,
            finding_type,
            title,
            finding_source,
            severity,
            confidence,
            exploitability,
            exploitation_status,
            exposure_level,
            exposed_service,
            asset_criticality,
            priority_score,
            priority_level,
            component_name,
            component_version,
            source_event_ids,
            reason_codes,
            evidence,
            remediation_status,
            verification_status,
            classification
        FROM v2_vulnerability_findings
        ORDER BY finding_record_id
        """,
    )

    links = fetch_rows(
        database_path,
        """
        SELECT
            link_key,
            source_finding_id,
            link_type,
            linked_record_id,
            exploitation_status,
            created_at,
            evidence
        FROM v2_vulnerability_links
        ORDER BY link_id
        """,
    )

    links_by_finding: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for link in links:
        links_by_finding[
            link["source_finding_id"]
        ].append(link)

    evidence_records = []

    for row in rows:
        source_type = vulnerability_source_type(
            row["finding_source"],
            configuration,
        )

        record = base_evidence(
            evidence_key=(
                f"{source_type}:{row['finding_key']}"
            ),
            source_type=source_type,
            source_record_id=row["source_finding_id"],
            event_time=row["updated_at"],
            detection_type=row["title"],
            severity=row["severity"],
            confidence=row["confidence"],
            contribution_status=(
                vulnerability_contribution(row)
            ),
            source_event_ids=json_list(row["source_event_ids"]),
            reason_codes=json_list(row["reason_codes"]),
            original={
                "finding_type": row["finding_type"],
                "finding_source": row["finding_source"],
                "exploitability": row["exploitability"],
                "exploitation_status": row[
                    "exploitation_status"
                ],
                "exposure_level": row["exposure_level"],
                "exposed_service": row["exposed_service"],
                "asset_criticality": row[
                    "asset_criticality"
                ],
                "priority_score": row["priority_score"],
                "priority_level": row["priority_level"],
                "component_name": row["component_name"],
                "component_version": row[
                    "component_version"
                ],
                "remediation_status": row[
                    "remediation_status"
                ],
                "verification_status": row[
                    "verification_status"
                ],
                "evidence": parse_json(
                    row["evidence"],
                    {},
                ),
            },
            asset_id=row["asset_id"],
        )

        record["explicit_links"] = links_by_finding.get(
            row["source_finding_id"],
            [],
        )
        evidence_records.append(record)

    return evidence_records


def load_xdr_evidence(
    database_path: Path,
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Load and deduplicate evidence from Stages 4 through 8."""
    records = (
        load_identity_evidence(database_path)
        + load_access_policy_evidence(
            database_path,
            configuration,
        )
        + load_network_evidence(database_path)
        + load_endpoint_evidence(database_path)
        + load_vulnerability_evidence(
            database_path,
            configuration,
        )
    )

    return list(
        {
            record["evidence_key"]: record
            for record in records
        }.values()
    )


def shared_primary_fields(
    first: dict[str, Any],
    second: dict[str, Any],
    primary_fields: list[str],
) -> list[str]:
    """Return strong identifiers shared by two records."""
    return [
        field
        for field in primary_fields
        if first.get(field)
        and first.get(field) == second.get(field)
    ]


def within_window(
    first: dict[str, Any],
    second: dict[str, Any],
    minutes: int,
) -> bool:
    """Return whether two evidence times fall inside the window."""
    difference = abs(
        (
            parse_time(first["event_time"])
            - parse_time(second["event_time"])
        ).total_seconds()
    )
    return difference <= minutes * 60


def explicit_link_targets(
    record: dict[str, Any],
) -> set[str]:
    """Return linked alert identifiers from a finding."""
    return {
        link["linked_record_id"]
        for link in record.get("explicit_links", [])
        if link["link_type"] == "alert"
        and link["exploitation_status"]
        in {"attempted", "successful"}
    }


def evidence_matches_link(
    evidence: dict[str, Any],
    targets: set[str],
) -> bool:
    """Return whether evidence is named by an explicit finding link."""
    return bool(
        evidence["source_record_id"] in targets
        or targets.intersection(
            evidence["source_event_ids"]
        )
    )


def build_evidence_groups(
    evidence: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[list[dict[str, Any]]]:
    """Build groups without bridging unrelated primary identities."""
    anchor_priority = (
        "device_id",
        "asset_id",
        "username",
        "ip_address",
        "hostname",
        "file_hash",
        "process_name",
    )
    window = configuration["correlation"][
        "time_window_minutes"
    ]

    anchor_buckets: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)
    unanchored: list[dict[str, Any]] = []

    for record in evidence:
        anchor = next(
            (
                (field, str(record[field]))
                for field in anchor_priority
                if record.get(field)
            ),
            None,
        )

        if anchor is None:
            unanchored.append(record)
        else:
            anchor_buckets[anchor].append(record)

    groups: list[list[dict[str, Any]]] = []

    for records in anchor_buckets.values():
        ordered = sorted(
            records,
            key=lambda item: parse_time(
                item["event_time"]
            ),
        )
        current: list[dict[str, Any]] = []

        for record in ordered:
            if not current or within_window(
                current[-1],
                record,
                window,
            ):
                current.append(record)
            else:
                groups.append(current)
                current = [record]

        if current:
            groups.append(current)

    groups.extend(
        [record]
        for record in unanchored
    )

    parents = list(range(len(groups)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(
        first_index: int,
        second_index: int,
    ) -> None:
        first_root = find(first_index)
        second_root = find(second_index)

        if first_root != second_root:
            parents[second_root] = first_root

    group_by_evidence_key = {
        record["evidence_key"]: group_index
        for group_index, group in enumerate(groups)
        for record in group
    }

    evidence_by_identifier: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for record in evidence:
        evidence_by_identifier[
            record["source_record_id"]
        ].add(record["evidence_key"])

        for source_event_id in record["source_event_ids"]:
            evidence_by_identifier[source_event_id].add(
                record["evidence_key"]
            )

    for record in evidence:
        source_group = group_by_evidence_key[
            record["evidence_key"]
        ]

        for target in explicit_link_targets(record):
            for target_key in evidence_by_identifier.get(
                target,
                set(),
            ):
                union(
                    source_group,
                    group_by_evidence_key[target_key],
                )

    merged: dict[
        int,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for group_index, group in enumerate(groups):
        merged[find(group_index)].extend(group)

    return [
        sorted(
            {
                record["evidence_key"]: record
                for record in group
            }.values(),
            key=lambda item: item["evidence_key"],
        )
        for group in merged.values()
    ]


def scoring_tokens(
    record: dict[str, Any],
) -> set[str]:
    """Return source-event tokens used once during scoring."""
    source_ids = (
        record["source_event_ids"]
        or [record["source_record_id"]]
    )

    return {
        f"{record['source_type']}:{source_id}"
        for source_id in source_ids
    }


def unique_contribution_records(
    group: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Choose one strongest record for each repeated source event."""
    strongest: dict[str, dict[str, Any]] = {}

    for record in group:
        for token in scoring_tokens(record):
            existing = strongest.get(token)

            if existing is None or (
                record["confidence"],
                SEVERITY_ORDER[record["severity"]],
            ) > (
                existing["confidence"],
                SEVERITY_ORDER[existing["severity"]],
            ):
                strongest[token] = record

    return list(
        {
            item["evidence_key"]: item
            for item in strongest.values()
        }.values()
    )


def values_for(
    group: list[dict[str, Any]],
    field: str,
) -> list[str]:
    """Return sorted unique non-empty values for one field."""
    return sorted(
        {
            str(record[field])
            for record in group
            if record.get(field) is not None
            and str(record[field]).strip()
        }
    )


def group_shared_context(
    group: list[dict[str, Any]],
    primary_fields: list[str],
) -> dict[str, list[str]]:
    """Return primary values present in more than one source."""
    context: dict[str, list[str]] = {}

    for field in primary_fields:
        sources_by_value: dict[
            str,
            set[str],
        ] = defaultdict(set)

        for record in group:
            value = record.get(field)

            if value:
                sources_by_value[str(value)].add(
                    record["source_type"]
                )

        shared = sorted(
            value
            for value, sources in sources_by_value.items()
            if len(sources) >= 2
        )

        if shared:
            context[field] = shared

    return context


def map_attack_techniques(
    group: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[str]:
    """Preserve source mappings and add useful configured mappings."""
    mappings = configuration["attack_mapping"]

    techniques = {
        technique
        for record in group
        for technique in record.get(
            "attack_techniques",
            [],
        )
    }

    for record in group:
        detection = record["detection_type"]
        techniques.update(
            mappings.get(detection, [])
        )

    return sorted(techniques)


def incident_confidence(
    scoring_records: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> tuple[int, int, int]:
    """Calculate confidence from active evidence and reductions."""
    active = [
        record
        for record in scoring_records
        if record["contribution_status"] == "active"
    ]
    exceptions = [
        record
        for record in scoring_records
        if record["contribution_status"] == "exception"
    ]
    verified = [
        record
        for record in scoring_records
        if record["contribution_status"] == "verified"
    ]

    source_count = len(
        {
            record["source_type"]
            for record in active
        }
    )
    confidence_config = configuration["confidence"]

    base = max(
        (
            record["confidence"]
            for record in active
        ),
        default=0,
    )

    bonus = min(
        max(source_count - 1, 0)
        * confidence_config[
            "independent_source_bonus"
        ],
        confidence_config["maximum_source_bonus"],
    )

    reduction = min(
        len(exceptions)
        * confidence_config[
            "validated_exception_reduction"
        ]
        + len(verified)
        * confidence_config[
            "verified_activity_reduction"
        ],
        confidence_config["maximum_reduction"],
    )

    confidence = max(
        0,
        min(
            confidence_config["maximum"],
            base + bonus - reduction,
        ),
    )

    return (
        confidence,
        len(exceptions),
        len(verified),
    )


def incident_severity(
    active: list[dict[str, Any]],
) -> str:
    """Return the highest severity from active evidence."""
    return max(
        (
            record["severity"]
            for record in active
        ),
        key=lambda value: SEVERITY_ORDER[value],
        default="Low",
    )


def correlation_reasons(
    group: list[dict[str, Any]],
    scoring_records: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> tuple[list[str], dict[str, list[str]]]:
    """Explain why an evidence group became an incident."""
    shared = group_shared_context(
        group,
        configuration["correlation"][
            "primary_fields"
        ],
    )

    reasons = [
        f"shared_{field}={value}"
        for field, values in shared.items()
        for value in values
    ]

    sources = sorted(
        {
            record["source_type"]
            for record in group
        }
    )
    reasons.append(
        "independent_sources="
        + ",".join(sources)
    )

    if any(
        record.get("explicit_links")
        for record in group
    ):
        reasons.append(
            "explicit_finding_link_preserved"
        )

    if any(
        record["contribution_status"] == "exception"
        for record in scoring_records
    ):
        reasons.append(
            "validated_exception_reduced_confidence"
        )

    if any(
        record["contribution_status"] == "verified"
        for record in scoring_records
    ):
        reasons.append(
            "verified_activity_reduced_confidence"
        )

    if any(
        record["contribution_status"] == "context_only"
        for record in group
    ):
        reasons.append(
            "vulnerability_retained_as_context"
        )

    return sorted(set(reasons)), shared


def build_title(
    group: list[dict[str, Any]],
) -> str:
    """Build a short, context-based incident title."""
    for field, label in (
        ("device_id", "device"),
        ("username", "user"),
        ("asset_id", "asset"),
        ("ip_address", "IP address"),
        ("hostname", "host"),
    ):
        values = values_for(group, field)

        if values:
            return (
                "Cross-source activity involving "
                f"{label} {values[0]}"
            )

    return "Cross-source correlated security activity"


def evidence_relationship(
    record: dict[str, Any],
) -> str:
    """Describe how one record participates in an incident."""
    if record.get("explicit_links"):
        return "explicit_finding_link"

    if record["contribution_status"] == "context_only":
        return "vulnerability_context"

    return "shared_context"


def build_incidents(
    groups: list[list[dict[str, Any]]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create context-rich incidents from eligible evidence groups."""
    incidents = []
    thresholds = configuration["incident_thresholds"]

    for group in groups:
        source_types = sorted(
            {
                record["source_type"]
                for record in group
            }
        )

        if (
            len(source_types)
            < thresholds[
                "minimum_independent_sources"
            ]
        ):
            continue

        scoring_records = unique_contribution_records(
            group
        )

        active = [
            record
            for record in scoring_records
            if record["contribution_status"] == "active"
        ]

        if (
            len(active)
            < thresholds["minimum_active_evidence"]
        ):
            continue

        (
            confidence,
            exception_count,
            verified_count,
        ) = incident_confidence(
            scoring_records,
            configuration,
        )

        if (
            confidence
            < thresholds["minimum_confidence"]
        ):
            continue

        reasons, shared = correlation_reasons(
            group,
            scoring_records,
            configuration,
        )

        evidence_keys = sorted(
            record["evidence_key"]
            for record in group
        )

        incident_key = stable_key(
            "v2-xdr-incident",
            evidence_keys,
        )

        vulnerability_context = [
            {
                "source_record_id": record[
                    "source_record_id"
                ],
                "detection_type": record[
                    "detection_type"
                ],
                "contribution_status": record[
                    "contribution_status"
                ],
                "exploitation_status": record[
                    "original_evidence"
                ].get("exploitation_status"),
                "remediation_status": record[
                    "original_evidence"
                ].get("remediation_status"),
                "explicit_links": record.get(
                    "explicit_links",
                    [],
                ),
            }
            for record in group
            if record["source_type"]
            in {"application", "vulnerability"}
        ]

        service_accounts = sorted(
            {
                record["username"]
                for record in group
                if record.get("username")
                and record["detection_type"]
                == "Service Account Interactive Login"
            }
        )

        incident = {
            "incident_key": incident_key,
            "created_at": utc_now(),
            "first_evidence_time": min(
                record["event_time"]
                for record in group
            ),
            "last_evidence_time": max(
                record["event_time"]
                for record in group
            ),
            "title": build_title(group),
            "severity": incident_severity(active),
            "confidence": confidence,
            "status": "New",
            "independent_source_count": len(
                source_types
            ),
            "evidence_count": len(group),
            "active_evidence_count": len(active),
            "exception_count": exception_count,
            "verified_activity_count": verified_count,
            "usernames": values_for(
                group,
                "username",
            ),
            "service_accounts": service_accounts,
            "device_ids": values_for(
                group,
                "device_id",
            ),
            "asset_ids": values_for(
                group,
                "asset_id",
            ),
            "ip_addresses": values_for(
                group,
                "ip_address",
            ),
            "mac_addresses": values_for(
                group,
                "mac_address",
            ),
            "hostnames": values_for(
                group,
                "hostname",
            ),
            "process_names": values_for(
                group,
                "process_name",
            ),
            "file_hashes": values_for(
                group,
                "file_hash",
            ),
            "locations": values_for(
                group,
                "location",
            ),
            "detection_types": sorted(
                {
                    record["detection_type"]
                    for record in group
                }
            ),
            "attack_techniques": map_attack_techniques(
                group,
                configuration,
            ),
            "behaviours": sorted(
                {
                    record["detection_type"]
                    for record in active
                }
            ),
            "correlation_reasons": reasons,
            "vulnerability_context": (
                vulnerability_context
            ),
            "evidence_keys": evidence_keys,
            "evidence": {
                "source_types": source_types,
                "shared_primary_context": shared,
                "score_each_source_event_once": True,
                "mac_address_is_supporting_only": True,
                "original_evidence_preserved": True,
            },
            "original_evidence_preserved": 1,
            "evidence_records": group,
        }

        incidents.append(incident)

    return sorted(
        incidents,
        key=lambda item: (
            -SEVERITY_ORDER[item["severity"]],
            -item["confidence"],
            item["incident_key"],
        ),
    )


def suspicious_record(
    record: dict[str, Any],
    configuration: dict[str, Any],
) -> bool:
    """Return whether evidence supports IoC classification."""
    minimum = configuration["ioc_policy"][
        "minimum_severity"
    ]

    if (
        SEVERITY_ORDER[record["severity"]]
        < SEVERITY_ORDER[minimum]
    ):
        return False

    detection = record["detection_type"].lower()

    return any(
        term.lower() in detection
        for term in configuration["ioc_policy"][
            "suspicious_detection_terms"
        ]
    )


def build_indicators(
    incidents: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract IoCs separately from suspicious behaviours."""
    indicators = []

    indicator_types = configuration["ioc_policy"][
        "indicator_types"
    ]
    supporting_types = configuration["ioc_policy"][
        "supporting_observables"
    ]

    for incident in incidents:
        by_indicator: dict[
            tuple[str, str, str],
            list[dict[str, Any]],
        ] = defaultdict(list)

        for record in incident["evidence_records"]:
            if suspicious_record(
                record,
                configuration,
            ):
                for indicator_type in indicator_types:
                    value = record.get(indicator_type)

                    if value:
                        by_indicator[
                            (
                                indicator_type,
                                str(value),
                                "ioc",
                            )
                        ].append(record)

            for indicator_type in supporting_types:
                value = record.get(indicator_type)

                if value:
                    by_indicator[
                        (
                            indicator_type,
                            str(value),
                            "supporting_observable",
                        )
                    ].append(record)

        for (
            indicator_type,
            indicator_value,
            classification,
        ), records in by_indicator.items():
            indicator_key = stable_key(
                "v2-xdr-indicator",
                [
                    incident["incident_key"],
                    indicator_type,
                    indicator_value,
                    classification,
                ],
            )

            indicators.append(
                {
                    "indicator_key": indicator_key,
                    "incident_key": incident[
                        "incident_key"
                    ],
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "classification": classification,
                    "confidence": max(
                        record["confidence"]
                        for record in records
                    ),
                    "source_evidence_keys": sorted(
                        {
                            record["evidence_key"]
                            for record in records
                        }
                    ),
                    "detection_types": sorted(
                        {
                            record["detection_type"]
                            for record in records
                        }
                    ),
                    "evidence": {
                        "classification_basis": (
                            "high_severity_"
                            "suspicious_detection"
                            if classification == "ioc"
                            else (
                                "mac_address_"
                                "supporting_only"
                            )
                        ),
                        "behaviour_is_stored_on_incident": (
                            True
                        ),
                    },
                }
            )

    return indicators


def evidence_link_rows(
    incidents: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build incident-to-evidence rows with explanations."""
    rows = []
    primary_fields = configuration["correlation"][
        "primary_fields"
    ]

    for incident in incidents:
        group = incident["evidence_records"]
        shared = group_shared_context(
            group,
            primary_fields,
        )

        for record in group:
            shared_for_record = {
                field: values
                for field, values in shared.items()
                if record.get(field) in values
            }

            reasons = [
                f"shared_{field}={value}"
                for field, values
                in shared_for_record.items()
                for value in values
            ]

            if record.get("explicit_links"):
                reasons.append(
                    "explicit_finding_link"
                )

            if (
                record["contribution_status"]
                == "context_only"
            ):
                reasons.append(
                    "vulnerability_context_only"
                )

            link_key = stable_key(
                "v2-xdr-evidence-link",
                [
                    incident["incident_key"],
                    record["evidence_key"],
                ],
            )

            rows.append(
                {
                    "evidence_link_key": link_key,
                    "incident_key": incident[
                        "incident_key"
                    ],
                    "evidence_key": record[
                        "evidence_key"
                    ],
                    "source_type": record[
                        "source_type"
                    ],
                    "source_record_id": record[
                        "source_record_id"
                    ],
                    "event_time": record[
                        "event_time"
                    ],
                    "relationship": (
                        evidence_relationship(record)
                    ),
                    "contribution_status": record[
                        "contribution_status"
                    ],
                    "shared_fields": shared_for_record,
                    "source_event_ids": record[
                        "source_event_ids"
                    ],
                    "detection_type": record[
                        "detection_type"
                    ],
                    "severity": record["severity"],
                    "confidence": record[
                        "confidence"
                    ],
                    "correlation_reasons": sorted(
                        set(reasons)
                    ),
                    "evidence": record[
                        "original_evidence"
                    ],
                }
            )

    return rows


def serialise(value: Any) -> str:
    """Serialise evidence deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def save_incidents(
    database_path: Path,
    incidents: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store incidents without replacing investigation status."""
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for incident in incidents:
            before = connection.total_changes

            connection.execute(
                """
                INSERT INTO v2_xdr_incidents (
                    incident_key,
                    created_at,
                    first_evidence_time,
                    last_evidence_time,
                    title,
                    severity,
                    confidence,
                    status,
                    independent_source_count,
                    evidence_count,
                    active_evidence_count,
                    exception_count,
                    verified_activity_count,
                    usernames,
                    service_accounts,
                    device_ids,
                    asset_ids,
                    ip_addresses,
                    mac_addresses,
                    hostnames,
                    process_names,
                    file_hashes,
                    locations,
                    detection_types,
                    attack_techniques,
                    behaviours,
                    correlation_reasons,
                    vulnerability_context,
                    evidence_keys,
                    evidence,
                    original_evidence_preserved
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(incident_key) DO UPDATE SET
                    first_evidence_time =
                        excluded.first_evidence_time,
                    last_evidence_time =
                        excluded.last_evidence_time,
                    title = excluded.title,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    independent_source_count =
                        excluded.independent_source_count,
                    evidence_count =
                        excluded.evidence_count,
                    active_evidence_count =
                        excluded.active_evidence_count,
                    exception_count =
                        excluded.exception_count,
                    verified_activity_count =
                        excluded.verified_activity_count,
                    usernames = excluded.usernames,
                    service_accounts =
                        excluded.service_accounts,
                    device_ids = excluded.device_ids,
                    asset_ids = excluded.asset_ids,
                    ip_addresses =
                        excluded.ip_addresses,
                    mac_addresses =
                        excluded.mac_addresses,
                    hostnames = excluded.hostnames,
                    process_names =
                        excluded.process_names,
                    file_hashes =
                        excluded.file_hashes,
                    locations = excluded.locations,
                    detection_types =
                        excluded.detection_types,
                    attack_techniques =
                        excluded.attack_techniques,
                    behaviours =
                        excluded.behaviours,
                    correlation_reasons =
                        excluded.correlation_reasons,
                    vulnerability_context =
                        excluded.vulnerability_context,
                    evidence_keys =
                        excluded.evidence_keys,
                    evidence = excluded.evidence,
                    original_evidence_preserved = 1
                """,
                (
                    incident["incident_key"],
                    incident["created_at"],
                    incident[
                        "first_evidence_time"
                    ],
                    incident[
                        "last_evidence_time"
                    ],
                    incident["title"],
                    incident["severity"],
                    incident["confidence"],
                    incident["status"],
                    incident[
                        "independent_source_count"
                    ],
                    incident["evidence_count"],
                    incident[
                        "active_evidence_count"
                    ],
                    incident["exception_count"],
                    incident[
                        "verified_activity_count"
                    ],
                    serialise(
                        incident["usernames"]
                    ),
                    serialise(
                        incident["service_accounts"]
                    ),
                    serialise(
                        incident["device_ids"]
                    ),
                    serialise(
                        incident["asset_ids"]
                    ),
                    serialise(
                        incident["ip_addresses"]
                    ),
                    serialise(
                        incident["mac_addresses"]
                    ),
                    serialise(
                        incident["hostnames"]
                    ),
                    serialise(
                        incident["process_names"]
                    ),
                    serialise(
                        incident["file_hashes"]
                    ),
                    serialise(
                        incident["locations"]
                    ),
                    serialise(
                        incident["detection_types"]
                    ),
                    serialise(
                        incident["attack_techniques"]
                    ),
                    serialise(
                        incident["behaviours"]
                    ),
                    serialise(
                        incident[
                            "correlation_reasons"
                        ]
                    ),
                    serialise(
                        incident[
                            "vulnerability_context"
                        ]
                    ),
                    serialise(
                        incident["evidence_keys"]
                    ),
                    serialise(
                        incident["evidence"]
                    ),
                    incident[
                        "original_evidence_preserved"
                    ],
                ),
            )

            if connection.total_changes > before:
                row = connection.execute(
                    """
                    SELECT created_at
                    FROM v2_xdr_incidents
                    WHERE incident_key = ?
                    """,
                    (
                        incident["incident_key"],
                    ),
                ).fetchone()

                if (
                    row
                    and row[0]
                    == incident["created_at"]
                ):
                    created += 1
                else:
                    existing += 1

    return created, existing


def save_evidence_links(
    database_path: Path,
    rows: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store duplicate-safe incident evidence links."""
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for row in rows:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO
                    v2_xdr_incident_evidence (
                        evidence_link_key,
                        incident_key,
                        evidence_key,
                        source_type,
                        source_record_id,
                        event_time,
                        relationship,
                        contribution_status,
                        shared_fields,
                        source_event_ids,
                        detection_type,
                        severity,
                        confidence,
                        correlation_reasons,
                        evidence
                    )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    row["evidence_link_key"],
                    row["incident_key"],
                    row["evidence_key"],
                    row["source_type"],
                    row["source_record_id"],
                    row["event_time"],
                    row["relationship"],
                    row["contribution_status"],
                    serialise(
                        row["shared_fields"]
                    ),
                    serialise(
                        row["source_event_ids"]
                    ),
                    row["detection_type"],
                    row["severity"],
                    row["confidence"],
                    serialise(
                        row["correlation_reasons"]
                    ),
                    serialise(
                        row["evidence"]
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing


def save_indicators(
    database_path: Path,
    indicators: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store duplicate-safe IoCs and supporting observables."""
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for indicator in indicators:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO v2_xdr_indicators (
                    indicator_key,
                    incident_key,
                    indicator_type,
                    indicator_value,
                    classification,
                    confidence,
                    source_evidence_keys,
                    detection_types,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    indicator["indicator_key"],
                    indicator["incident_key"],
                    indicator["indicator_type"],
                    indicator["indicator_value"],
                    indicator["classification"],
                    indicator["confidence"],
                    serialise(
                        indicator[
                            "source_evidence_keys"
                        ]
                    ),
                    serialise(
                        indicator["detection_types"]
                    ),
                    serialise(
                        indicator["evidence"]
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing


def correlate_xdr_evidence(
    database_path: Path,
    configuration: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Load, group and correlate current V2 security evidence."""
    evidence = load_xdr_evidence(
        database_path,
        configuration,
    )
    groups = build_evidence_groups(
        evidence,
        configuration,
    )
    incidents = build_incidents(
        groups,
        configuration,
    )
    links = evidence_link_rows(
        incidents,
        configuration,
    )
    indicators = build_indicators(
        incidents,
        configuration,
    )

    return incidents, links, indicators
