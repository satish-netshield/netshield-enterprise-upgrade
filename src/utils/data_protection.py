"""Protect sensitive values before logging or reporting."""

from copy import deepcopy
from typing import Any


def mask_sensitive_fields(
    data: Any,
    sensitive_fields: list[str],
    replacement: str = "[REDACTED]",
) -> Any:
    """Return a copy with configured sensitive fields masked."""
    protected_fields = {
        field.strip().casefold()
        for field in sensitive_fields
    }

    if isinstance(data, dict):
        return {
            key: (
                replacement
                if str(key).casefold() in protected_fields
                else mask_sensitive_fields(
                    value,
                    sensitive_fields,
                    replacement,
                )
            )
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [
            mask_sensitive_fields(
                item,
                sensitive_fields,
                replacement,
            )
            for item in data
        ]

    return deepcopy(data)


def apply_configured_masking(
    data: Any,
    settings: dict[str, Any],
) -> Any:
    """Apply the masking policy from NetShield settings."""
    policy = settings["data_protection"]["sensitive_field_masking"]

    if not policy["enabled"]:
        return deepcopy(data)

    return mask_sensitive_fields(
        data,
        policy["fields"],
        policy["replacement"],
    )
