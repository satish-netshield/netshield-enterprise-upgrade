"""Evaluate NetShield roles, actions, devices and IP addresses."""

import csv
import ipaddress
from pathlib import Path
from typing import Any


def role_has_permission(
    rbac_config: dict[str, Any],
    role: str,
    permission: str,
) -> bool:
    """Return True only when the role explicitly has the permission."""
    role_permissions = rbac_config.get("roles", {}).get(role, [])
    return permission in role_permissions


def action_control_level(
    acl_config: dict[str, Any],
    action: str,
) -> str:
    """Return the required control level or deny an unknown action."""
    for level in ("automatic", "approval_required", "manual_only"):
        if action in acl_config.get(level, []):
            return level

    return acl_config.get("default_action", "deny")


def is_cyod_device_approved(
    inventory_path: Path,
    mac_address: str,
) -> bool:
    """Check whether a MAC address belongs to an approved CYOD device."""
    normalised_mac = mac_address.strip().lower()

    with inventory_path.open("r", encoding="utf-8", newline="") as csv_file:
        for device in csv.DictReader(csv_file):
            inventory_mac = device.get("mac_address", "").strip().lower()
            approval = device.get("approval_status", "").strip().lower()

            if inventory_mac == normalised_mac and approval == "approved":
                return True

    return False


def load_ip_entries(file_path: Path) -> set[str]:
    """Load and validate IP addresses while ignoring blank/comment lines."""
    entries: set[str] = set()

    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        entry = raw_line.strip()

        if not entry or entry.startswith("#"):
            continue

        entries.add(str(ipaddress.ip_address(entry)))

    return entries


def classify_ip(
    ip_address: str,
    allowlist_path: Path,
    blocklist_path: Path,
) -> str:
    """Classify an address with blocklist precedence."""
    normalised_ip = str(ipaddress.ip_address(ip_address))
    allowed_ips = load_ip_entries(allowlist_path)
    blocked_ips = load_ip_entries(blocklist_path)

    if normalised_ip in blocked_ips:
        return "blocked"

    if normalised_ip in allowed_ips:
        return "allowed"

    return "unknown"
