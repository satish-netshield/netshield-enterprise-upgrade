"""Validate and normalise security events into one consistent structure."""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any


REQUIRED_FIELDS = (
    "event_id",
    "event_time",
    "source_type",
    "event_type",
)

ALLOWED_SOURCE_TYPES = {
    "authentication",
    "identity_risk",
    "access_policy",
    "network",
    "wifi",
    "endpoint",
    "application",
    "database",
    "vulnerability",
    "incident",
    "response",
}

SUPPORTED_SCHEMA_VERSIONS = {"1.0", "2.0"}
ALLOWED_SEVERITIES = {
    "Informational",
    "Low",
    "Medium",
    "High",
    "Critical",
}
ALLOWED_DECISIONS = {"allow", "deny", "challenge", "restrict"}

MAC_PATTERN = re.compile(
    r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
)


def require_text(event: dict[str, Any], field: str) -> str:
    """Return a required non-empty text field."""
    value = event.get(field)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Required field '{field}' must contain text"
        )

    return value.strip()


def optional_text(event: dict[str, Any], field: str) -> str | None:
    """Return a cleaned optional text field."""
    value = event.get(field)

    if value is None or value == "":
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"Optional field '{field}' must contain text"
        )

    cleaned_value = value.strip()
    return cleaned_value or None


def normalise_timestamp(value: str) -> str:
    """Return an ISO 8601 timestamp expressed in UTC."""
    timestamp_value = value.replace("Z", "+00:00")

    try:
        timestamp = datetime.fromisoformat(timestamp_value)
    except ValueError as error:
        raise ValueError(
            "Field 'event_time' must contain a valid ISO 8601 timestamp"
        ) from error

    if timestamp.tzinfo is None:
        raise ValueError(
            "Field 'event_time' must include a timezone"
        )

    return timestamp.astimezone(timezone.utc).isoformat()


def normalise_ip_address(value: str | None) -> str | None:
    """Validate and return a canonical IP address."""
    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError(
            "Field 'ip_address' must contain a valid IP address"
        ) from error


def normalise_mac_address(value: str | None) -> str | None:
    """Validate and return a lowercase colon-separated MAC address."""
    if value is None:
        return None

    if not MAC_PATTERN.fullmatch(value):
        raise ValueError(
            "Field 'mac_address' must contain a valid MAC address"
        )

    return value.replace("-", ":").lower()


def normalise_cpu_percent(event: dict[str, Any]) -> float | None:
    """Validate an optional CPU percentage."""
    value = event.get("cpu_percent")

    if value is None or value == "":
        return None

    if isinstance(value, bool):
        raise ValueError(
            "Field 'cpu_percent' must contain a number"
        )

    try:
        cpu_percent = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Field 'cpu_percent' must contain a number"
        ) from error

    if not 0 <= cpu_percent <= 100:
        raise ValueError(
            "Field 'cpu_percent' must be between 0 and 100"
        )

    return cpu_percent



def normalise_schema_version(event: dict[str, Any]) -> str:
    """Validate the event schema version while supporting Phase 3 data."""
    version = optional_text(event, "schema_version") or "1.0"

    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"Unsupported schema_version: {version}"
        )

    return version


def normalise_severity(event: dict[str, Any]) -> str | None:
    """Validate and standardise an optional severity."""
    value = optional_text(event, "severity")

    if value is None:
        return None

    severity = value.title()
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            f"Unsupported severity: {value}"
        )

    return severity


def normalise_risk_score(event: dict[str, Any]) -> float | None:
    """Validate an optional risk score from 0 to 100."""
    value = event.get("risk_score")

    if value is None or value == "":
        return None

    if isinstance(value, bool):
        raise ValueError(
            "Field 'risk_score' must contain a number"
        )

    try:
        score = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Field 'risk_score' must contain a number"
        ) from error

    if not 0 <= score <= 100:
        raise ValueError(
            "Field 'risk_score' must be between 0 and 100"
        )

    return score


def normalise_decision(event: dict[str, Any]) -> str | None:
    """Validate an optional access or response decision."""
    value = optional_text(event, "decision")

    if value is None:
        return None

    decision = value.lower()
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(
            f"Unsupported decision: {value}"
        )

    return decision


def normalise_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate one raw event and return the normalised event."""
    if not isinstance(event, dict):
        raise ValueError("Each security event must be a JSON object")

    for field in REQUIRED_FIELDS:
        require_text(event, field)

    source_type = require_text(event, "source_type").lower()

    if source_type not in ALLOWED_SOURCE_TYPES:
        raise ValueError(
            f"Unsupported source_type: {source_type}"
        )

    return {
        "source_event_id": require_text(event, "event_id"),
        "schema_version": normalise_schema_version(event),
        "source_system": (
            optional_text(event, "source_system") or source_type
        ),
        "severity": normalise_severity(event),
        "risk_score": normalise_risk_score(event),
        "decision": normalise_decision(event),
        "device_id": optional_text(event, "device_id"),
        "asset_id": optional_text(event, "asset_id"),
        "application_id": optional_text(event, "application_id"),
        "service_id": optional_text(event, "service_id"),
        "finding_id": optional_text(event, "finding_id"),
        "incident_id": optional_text(event, "incident_id"),
        "action_id": optional_text(event, "action_id"),
        "event_time": normalise_timestamp(
            require_text(event, "event_time")
        ),
        "source_type": source_type,
        "event_type": require_text(
            event,
            "event_type",
        ).lower(),
        "username": optional_text(event, "username"),
        "ip_address": normalise_ip_address(
            optional_text(event, "ip_address")
        ),
        "mac_address": normalise_mac_address(
            optional_text(event, "mac_address")
        ),
        "hostname": optional_text(event, "hostname"),
        "process_name": optional_text(event, "process_name"),
        "cpu_percent": normalise_cpu_percent(event),
        "location": optional_text(event, "location"),
        "status": optional_text(event, "status"),
        "message": optional_text(event, "message"),
    }
