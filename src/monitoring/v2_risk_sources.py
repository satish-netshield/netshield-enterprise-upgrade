"""Load existing NetShield evidence for Stage 9 risk assessment."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.utils.sqlite_connection import managed_connection


Evidence = dict[str, Any]


SOURCE_QUERIES = {
    "identity": """
        SELECT
            alert_key AS record_id,
            last_event_time AS event_time,
            severity,
            confidence,
            username,
            device_id,
            NULL AS asset_id,
            NULL AS incident_id,
            NULL AS asset_criticality,
            status,
            classification,
            source_event_ids AS evidence_refs,
            reason_codes AS details
        FROM v2_identity_alerts
    """,
    "access_policy": """
        SELECT
            decision_key AS record_id,
            evaluated_at AS event_time,
            CASE decision
                WHEN 'restrict' THEN 'Critical'
                WHEN 'deny' THEN 'High'
                ELSE 'Medium'
            END AS severity,
            CASE decision
                WHEN 'restrict' THEN 95
                WHEN 'deny' THEN 80
                ELSE 65
            END AS confidence,
            username,
            device_id,
            asset_id,
            NULL AS incident_id,
            asset_criticality,
            NULL AS status,
            NULL AS classification,
            json_array(request_event_id) AS evidence_refs,
            reason_codes AS details
        FROM access_policy_decisions
        WHERE decision != 'allow'
    """,
    "device_identity": """
        SELECT
            alert_key AS record_id,
            created_at AS event_time,
            severity,
            75 AS confidence,
            username,
            device_id,
            asset_id,
            NULL AS incident_id,
            NULL AS asset_criticality,
            status,
            classification,
            source_event_ids AS evidence_refs,
            json_array(detection_type) AS details
        FROM device_alerts
    """,
    "network": """
        SELECT
            alert_key AS record_id,
            last_event_time AS event_time,
            severity,
            confidence,
            username,
            device_id,
            asset_id,
            NULL AS incident_id,
            NULL AS asset_criticality,
            status,
            classification,
            source_event_ids AS evidence_refs,
            reason_codes AS details
        FROM v2_network_alerts
    """,
    "endpoint": """
        SELECT
            alert_key AS record_id,
            last_event_time AS event_time,
            severity,
            confidence,
            username,
            device_id,
            asset_id,
            NULL AS incident_id,
            NULL AS asset_criticality,
            status,
            classification,
            source_event_ids AS evidence_refs,
            reason_codes AS details
        FROM v2_endpoint_alerts
    """,
    "vulnerability": """
        SELECT
            finding_key AS record_id,
            updated_at AS event_time,
            severity,
            confidence,
            NULL AS username,
            NULL AS device_id,
            asset_id,
            NULL AS incident_id,
            asset_criticality,
            remediation_status AS status,
            classification,
            source_event_ids AS evidence_refs,
            reason_codes AS details
        FROM v2_vulnerability_findings
    """,
    "incident_link": """
        SELECT
            link.link_key AS record_id,
            link.created_at AS event_time,
            finding.severity,
            MAX(
                finding.confidence,
                CASE link.exploitation_status
                    WHEN 'successful' THEN 95
                    ELSE 80
                END
            ) AS confidence,
            NULL AS username,
            NULL AS device_id,
            NULL AS asset_id,
            link.linked_record_id AS incident_id,
            finding.asset_criticality,
            NULL AS status,
            NULL AS classification,
            json_array(link.source_finding_id) AS evidence_refs,
            json_array(link.exploitation_status) AS details
        FROM v2_vulnerability_links AS link
        JOIN v2_vulnerability_findings AS finding
          ON finding.finding_key = link.finding_key
        WHERE link.link_type = 'incident'
    """,
}


SOURCE_ENTITIES = {
    "identity": ("user", "device"),
    "access_policy": ("user", "device", "asset"),
    "device_identity": ("user", "device", "asset"),
    "network": ("user", "device", "asset"),
    "endpoint": ("user", "device", "asset"),
    "vulnerability": ("asset",),
    "incident_link": ("incident",),
}


def parse_time(value: str) -> datetime:
    """Parse an ISO 8601 value and require timezone information."""
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError(
            f"Timestamp is not timezone-aware: {value}"
        )

    return parsed.astimezone(timezone.utc)


def is_false_positive(
    status: str | None,
    classification: str | None,
) -> bool:
    """Return True only for a completed false-positive review."""
    return (
        classification == "False Positive"
        and status in {"Closed", "False Positive"}
    )


def load_asset_context(
    database_path: Path,
    enterprise_context: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return asset criticality and device-to-asset mappings."""
    criticality = {
        asset["asset_id"]: asset.get(
            "criticality",
            "low",
        ).lower()
        for asset in enterprise_context.get("assets", [])
    }
    device_assets: dict[str, str] = {}

    with managed_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT device_id, asset_id, criticality
            FROM device_inventory
            WHERE device_id IS NOT NULL
            """
        ).fetchall()

    for device_id, asset_id, level in rows:
        if asset_id:
            device_assets[device_id] = asset_id
            criticality.setdefault(
                asset_id,
                (level or "low").lower(),
            )

    return criticality, device_assets


def entity_values(
    entity_names: Iterable[str],
    row: sqlite3.Row,
    asset_id: str | None,
) -> list[tuple[str, str]]:
    """Return non-empty entity identifiers for one source record."""
    values = {
        "user": row["username"],
        "device": row["device_id"],
        "asset": asset_id,
        "incident": row["incident_id"],
    }

    return [
        (name, values[name])
        for name in entity_names
        if values[name]
    ]


def load_continuous_evidence(
    database_path: Path,
    enterprise_context: dict[str, Any],
) -> tuple[list[Evidence], dict[str, int]]:
    """Load Stage 3-8 evidence without changing source records."""
    criticality, device_assets = load_asset_context(
        database_path,
        enterprise_context,
    )
    evidence: list[Evidence] = []
    counts: dict[str, int] = {}

    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row

        for source_type, query in SOURCE_QUERIES.items():
            rows = connection.execute(query).fetchall()
            counts[source_type] = len(rows)

            for row in rows:
                parse_time(row["event_time"])

                asset_id = (
                    row["asset_id"]
                    or device_assets.get(row["device_id"])
                )
                asset_level = (
                    row["asset_criticality"]
                    or criticality.get(asset_id, "low")
                ).lower()
                references = json.loads(
                    row["evidence_refs"]
                )
                details = json.loads(row["details"])
                validated_exception = is_false_positive(
                    row["status"],
                    row["classification"],
                )

                for entity_type, entity_id in entity_values(
                    SOURCE_ENTITIES[source_type],
                    row,
                    asset_id,
                ):
                    evidence.append(
                        {
                            "source_type": source_type,
                            "record_id": row["record_id"],
                            "event_time": row["event_time"],
                            "severity": row["severity"],
                            "confidence": int(
                                row["confidence"]
                            ),
                            "asset_criticality": (
                                asset_level
                            ),
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "validated_exception": (
                                validated_exception
                            ),
                            "evidence_refs": sorted(
                                set(references)
                            ),
                            "details": details,
                        }
                    )

    return evidence, counts
