"""Evaluate local V2 Zero Trust access-policy decisions."""
from src.utils.sqlite_connection import managed_connection

import hashlib
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.security_controls import action_control_level


STAGE_SOURCE_PATTERN = "%_v2_stage4_5_events.jsonl"

ROLE_ORDER = {
    "viewer": 0,
    "analyst": 1,
    "responder": 2,
    "administrator": 3,
}


def load_access_requests(
    database_path: Path,
) -> list[dict[str, Any]]:
    """Load Stage 5 access requests in event-time order."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                source_event_id,
                event_time,
                source_system,
                username,
                device_id,
                application_id,
                asset_id,
                ip_address,
                location,
                risk_score,
                raw_event
            FROM security_events
            WHERE source_file LIKE ?
              AND source_type = 'access_policy'
              AND event_type = 'access_request'
            ORDER BY event_time, event_key
            """,
            (STAGE_SOURCE_PATTERN,),
        ).fetchall()

    requests: list[dict[str, Any]] = []

    for row in rows:
        request = dict(row)
        request["raw"] = json.loads(request.pop("raw_event"))
        requests.append(request)

    return requests


def load_user_roles(
    database_path: Path,
) -> dict[str, dict[str, Any]]:
    """Load active and inactive role assignments."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT username, role, active
            FROM user_roles
            ORDER BY username
            """
        ).fetchall()

    return {
        row["username"]: {
            "role": row["role"],
            "active": bool(row["active"]),
        }
        for row in rows
    }


def load_device_inventory(
    database_path: Path,
) -> dict[str, dict[str, Any]]:
    """Load registered device and asset evidence."""
    with managed_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                asset_id,
                device_id,
                hostname,
                assigned_user,
                registration_status,
                compliance_status,
                risk_status,
                criticality,
                last_seen
            FROM device_inventory
            ORDER BY device_id
            """
        ).fetchall()

    return {
        row["device_id"]: dict(row)
        for row in rows
    }


def load_active_restrictions(
    database_path: Path,
    evaluated_at: datetime,
) -> set[str]:
    """Load users with active temporary restrictions."""
    with managed_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT username, expires_at
            FROM temporary_access_restrictions
            WHERE active = 1
            """
        ).fetchall()

    restricted_users: set[str] = set()

    for username, expires_at in rows:
        if (
            expires_at is None
            or datetime.fromisoformat(expires_at) > evaluated_at
        ):
            restricted_users.add(username)

    return restricted_users


def load_vpn_allowlist(file_path: Path) -> set[str]:
    """Load approved VPN addresses."""
    addresses: set[str] = set()

    for raw_line in file_path.read_text(
        encoding="utf-8"
    ).splitlines():
        address = raw_line.strip()

        if address and not address.startswith("#"):
            addresses.add(address)

    return addresses


def identity_statuses(
    enterprise_context: dict[str, Any],
) -> dict[str, str]:
    """Return configured enterprise identity statuses."""
    return {
        user["username"]: user["status"]
        for user in enterprise_context["users"]
    }


def address_in_networks(
    address: str | None,
    networks: list[str],
) -> bool:
    """Return whether an address belongs to a configured network."""
    if address is None:
        return False

    ip_value = ipaddress.ip_address(address)

    return any(
        ip_value in ipaddress.ip_network(network)
        for network in networks
    )


def requirement_value(
    application_requirement: bool,
    asset_requirement: bool,
) -> bool:
    """Return the stronger combined access requirement."""
    return application_requirement or asset_requirement


def build_evidence(
    request: dict[str, Any],
    application: dict[str, Any] | None,
    role_record: dict[str, Any] | None,
    device: dict[str, Any] | None,
    identity_status: str | None,
    vpn_exception: bool,
    temporary_restriction: bool,
    required_permission: str | None,
    permission_granted: bool,
    mfa_required: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build identity, device and risk evidence."""
    raw = request["raw"]

    identity_evidence = {
        "username": request.get("username"),
        "configured_status": identity_status,
        "role": (
            role_record.get("role")
            if role_record
            else None
        ),
        "role_active": (
            role_record.get("active")
            if role_record
            else False
        ),
        "required_permission": required_permission,
        "permission_granted": permission_granted,
        "minimum_role": (
            application.get("minimum_role")
            if application
            else None
        ),
        "temporary_restriction": temporary_restriction,
    }

    device_evidence = {
        "device_id": request.get("device_id"),
        "known_device": device is not None,
        "asset_id": (
            device.get("asset_id")
            if device
            else request.get("asset_id")
        ),
        "registration_status": (
            device.get("registration_status")
            if device
            else "unknown"
        ),
        "compliance_status": (
            device.get("compliance_status")
            if device
            else "unknown"
        ),
        "device_risk_status": (
            device.get("risk_status")
            if device
            else "unknown"
        ),
        "asset_criticality": (
            device.get("criticality")
            if device
            else "unknown"
        ),
    }

    risk_evidence = {
        "sign_in_risk": raw.get(
            "sign_in_risk",
            request.get("risk_score"),
        ),
        "user_risk": raw.get("user_risk"),
        "mfa_required": mfa_required,
        "mfa_satisfied": bool(
            raw.get("mfa_satisfied", False)
        ),
        "ip_address": request.get("ip_address"),
        "location": request.get("location"),
        "vpn_exception": vpn_exception,
    }

    return (
        identity_evidence,
        device_evidence,
        risk_evidence,
    )


def match_policy_conditions(
    request: dict[str, Any],
    policy_config: dict[str, Any],
    rbac_config: dict[str, Any],
    enterprise_context: dict[str, Any],
    role_record: dict[str, Any] | None,
    device: dict[str, Any] | None,
    restricted_users: set[str],
    vpn_addresses: set[str],
) -> tuple[
    dict[str, bool],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Evaluate every supported policy condition."""
    username = request.get("username")
    application_id = request.get("application_id")
    application = policy_config["applications"].get(
        application_id
    )
    statuses = identity_statuses(enterprise_context)
    identity_status = statuses.get(username)

    role = (
        role_record.get("role")
        if role_record
        else None
    )
    role_active = bool(
        role_record
        and role_record.get("active")
    )

    required_permission = (
        application.get("required_permission")
        if application
        else None
    )
    permission_granted = bool(
        role
        and required_permission
        and required_permission
        in rbac_config["roles"].get(role, [])
    )

    minimum_role = (
        application.get("minimum_role")
        if application
        else None
    )
    minimum_role_satisfied = bool(
        role in ROLE_ORDER
        and minimum_role in ROLE_ORDER
        and ROLE_ORDER[role] >= ROLE_ORDER[minimum_role]
    )

    device_registered = bool(
        device
        and device.get("registration_status") == "registered"
    )
    device_compliant = bool(
        device
        and device.get("compliance_status") == "compliant"
    )

    asset_criticality = (
        device.get("criticality")
        if device
        else "critical"
    )
    asset_requirements = policy_config[
        "asset_requirements"
    ].get(
        asset_criticality,
        policy_config["asset_requirements"]["critical"],
    )

    if application:
        approved_device_required = requirement_value(
            application["approved_device_required"],
            asset_requirements["approved_device_required"],
        )
        compliant_device_required = requirement_value(
            application["compliant_device_required"],
            asset_requirements["compliant_device_required"],
        )
        mfa_required = requirement_value(
            application["mfa_required"],
            asset_requirements["mfa_required"],
        )
    else:
        approved_device_required = True
        compliant_device_required = True
        mfa_required = True

    raw = request["raw"]
    sign_in_risk = float(
        raw.get(
            "sign_in_risk",
            request.get("risk_score") or 0,
        )
    )
    user_risk = float(raw.get("user_risk", 0))
    highest_identity_risk = max(
        sign_in_risk,
        user_risk,
    )

    risk_thresholds = policy_config["risk_thresholds"]
    vpn_exception = request.get("ip_address") in vpn_addresses
    temporary_restriction = bool(
        username in restricted_users
        or raw.get("temporary_restriction", False)
    )

    restricted_location = bool(
        not vpn_exception
        and request.get("location")
        in policy_config["restricted_locations"]
    )
    restricted_network = bool(
        not vpn_exception
        and address_in_networks(
            request.get("ip_address"),
            policy_config["restricted_networks"],
        )
    )

    conditions = {
        "temporary_restriction_active": temporary_restriction,
        "identity_not_active": bool(
            identity_status != "active"
            or not role_active
        ),
        "required_permission_missing": bool(
            application is None
            or not permission_granted
            or not minimum_role_satisfied
        ),
        "restricted_location": restricted_location,
        "restricted_network": restricted_network,
        "critical_identity_risk": bool(
            highest_identity_risk
            >= risk_thresholds["critical"]
        ),
        "device_not_registered": bool(
            approved_device_required
            and not device_registered
        ),
        "device_not_compliant": bool(
            compliant_device_required
            and not device_compliant
        ),
        "high_identity_risk": bool(
            risk_thresholds["high"]
            <= highest_identity_risk
            < risk_thresholds["critical"]
        ),
        "mfa_required_not_satisfied": bool(
            mfa_required
            and not bool(raw.get("mfa_satisfied", False))
        ),
    }

    conditions["all_access_requirements_satisfied"] = not any(
        conditions.values()
    )

    (
        identity_evidence,
        device_evidence,
        risk_evidence,
    ) = build_evidence(
        request=request,
        application=application,
        role_record=role_record,
        device=device,
        identity_status=identity_status,
        vpn_exception=vpn_exception,
        temporary_restriction=temporary_restriction,
        required_permission=required_permission,
        permission_granted=permission_granted,
        mfa_required=mfa_required,
    )

    return (
        conditions,
        identity_evidence,
        device_evidence,
        risk_evidence,
    )


def matching_policies(
    conditions: dict[str, bool],
    policy_config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return policies whose configured conditions matched."""
    return [
        policy
        for policy in policy_config["policies"]
        if conditions.get(policy["condition"], False)
    ]


def select_winning_policy(
    policies: list[dict[str, Any]],
    policy_config: dict[str, Any],
) -> dict[str, Any] | None:
    """Select a policy by priority and restrictive precedence."""
    if not policies:
        return None

    decision_rank = {
        decision: index
        for index, decision in enumerate(
            policy_config["decision_precedence"]
        )
    }

    return min(
        policies,
        key=lambda policy: (
            int(policy["priority"]),
            decision_rank[policy["decision"]],
            policy["policy_id"],
        ),
    )


def response_result(
    decision: str,
    policy_config: dict[str, Any],
    acl_config: dict[str, Any],
) -> tuple[str | None, str | None, str]:
    """Validate any simulated response against the ACL."""
    response_action = policy_config[
        "response_actions"
    ].get(decision)

    if response_action is None:
        return None, None, "not_required"

    control_level = action_control_level(
        acl_config,
        response_action,
    )

    if control_level == "automatic":
        return (
            response_action,
            control_level,
            "simulated_automatic",
        )

    if control_level == "approval_required":
        return (
            response_action,
            control_level,
            "approval_required",
        )

    if control_level == "manual_only":
        return (
            response_action,
            control_level,
            "manual_only",
        )

    return response_action, control_level, "denied_by_acl"


def create_decision(
    request: dict[str, Any],
    policy_config: dict[str, Any],
    rbac_config: dict[str, Any],
    automation_acl: dict[str, Any],
    enterprise_context: dict[str, Any],
    role_record: dict[str, Any] | None,
    device: dict[str, Any] | None,
    restricted_users: set[str],
    vpn_addresses: set[str],
) -> dict[str, Any]:
    """Create one explainable access decision."""
    (
        conditions,
        identity_evidence,
        device_evidence,
        risk_evidence,
    ) = match_policy_conditions(
        request=request,
        policy_config=policy_config,
        rbac_config=rbac_config,
        enterprise_context=enterprise_context,
        role_record=role_record,
        device=device,
        restricted_users=restricted_users,
        vpn_addresses=vpn_addresses,
    )

    matches = matching_policies(
        conditions,
        policy_config,
    )
    winner = select_winning_policy(
        matches,
        policy_config,
    )

    if winner is None:
        decision = policy_config["default_decision"]
        reason_codes = ["DEFAULT_DENY"]
        winning_policy_id = None
    else:
        decision = winner["decision"]
        reason_codes = sorted(
            {
                policy["reason_code"]
                for policy in matches
            }
        )
        winning_policy_id = winner["policy_id"]

    (
        response_action,
        acl_control_level,
        response_status,
    ) = response_result(
        decision,
        policy_config,
        automation_acl,
    )

    decision_key = hashlib.sha256(
        (
            request["source_event_id"]
            + "|"
            + decision
            + "|"
            + (winning_policy_id or "default")
        ).encode("utf-8")
    ).hexdigest()

    application = policy_config["applications"].get(
        request.get("application_id")
    )

    evidence = {
        "source_system": request.get("source_system"),
        "application_name": (
            application.get("name")
            if application
            else None
        ),
        "application_sensitivity": (
            application.get("sensitivity")
            if application
            else None
        ),
        "conditions": conditions,
        "conflict_handling": policy_config[
            "conflict_handling"
        ],
    }

    return {
        "decision_key": decision_key,
        "request_event_id": request["source_event_id"],
        "username": request.get("username"),
        "role": identity_evidence["role"],
        "device_id": request.get("device_id"),
        "application_id": request.get("application_id"),
        "asset_id": request.get("asset_id"),
        "asset_criticality": device_evidence[
            "asset_criticality"
        ],
        "location": request.get("location"),
        "ip_address": request.get("ip_address"),
        "sign_in_risk": risk_evidence["sign_in_risk"],
        "user_risk": risk_evidence["user_risk"],
        "mfa_satisfied": risk_evidence["mfa_satisfied"],
        "decision": decision,
        "reason_codes": reason_codes,
        "matched_policy_ids": [
            policy["policy_id"]
            for policy in matches
        ],
        "winning_policy_id": winning_policy_id,
        "identity_evidence": identity_evidence,
        "device_evidence": device_evidence,
        "risk_evidence": risk_evidence,
        "response_action": response_action,
        "acl_control_level": acl_control_level,
        "response_status": response_status,
        "evidence": evidence,
    }


def evaluate_access_requests(
    requests: list[dict[str, Any]],
    policy_config: dict[str, Any],
    rbac_config: dict[str, Any],
    automation_acl: dict[str, Any],
    enterprise_context: dict[str, Any],
    user_roles: dict[str, dict[str, Any]],
    devices: dict[str, dict[str, Any]],
    restricted_users: set[str],
    vpn_addresses: set[str],
) -> list[dict[str, Any]]:
    """Evaluate every Stage 5 access request."""
    decisions = [
        create_decision(
            request=request,
            policy_config=policy_config,
            rbac_config=rbac_config,
            automation_acl=automation_acl,
            enterprise_context=enterprise_context,
            role_record=user_roles.get(request.get("username")),
            device=devices.get(request.get("device_id")),
            restricted_users=restricted_users,
            vpn_addresses=vpn_addresses,
        )
        for request in requests
    ]

    decisions.sort(
        key=lambda decision: decision["request_event_id"]
    )
    return decisions


def save_access_decisions(
    database_path: Path,
    decisions: list[dict[str, Any]],
) -> tuple[int, int]:
    """Store decisions and count existing duplicates."""
    evaluated_at = datetime.now(timezone.utc).isoformat()
    created = 0
    existing = 0

    with managed_connection(database_path) as connection:
        for decision in decisions:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO access_policy_decisions (
                    decision_key,
                    evaluated_at,
                    request_event_id,
                    username,
                    role,
                    device_id,
                    application_id,
                    asset_id,
                    asset_criticality,
                    location,
                    ip_address,
                    sign_in_risk,
                    user_risk,
                    mfa_satisfied,
                    decision,
                    reason_codes,
                    matched_policy_ids,
                    winning_policy_id,
                    identity_evidence,
                    device_evidence,
                    risk_evidence,
                    response_action,
                    acl_control_level,
                    response_status,
                    evidence
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    decision["decision_key"],
                    evaluated_at,
                    decision["request_event_id"],
                    decision["username"],
                    decision["role"],
                    decision["device_id"],
                    decision["application_id"],
                    decision["asset_id"],
                    decision["asset_criticality"],
                    decision["location"],
                    decision["ip_address"],
                    decision["sign_in_risk"],
                    decision["user_risk"],
                    int(decision["mfa_satisfied"]),
                    decision["decision"],
                    json.dumps(decision["reason_codes"]),
                    json.dumps(
                        decision["matched_policy_ids"]
                    ),
                    decision["winning_policy_id"],
                    json.dumps(
                        decision["identity_evidence"],
                        sort_keys=True,
                    ),
                    json.dumps(
                        decision["device_evidence"],
                        sort_keys=True,
                    ),
                    json.dumps(
                        decision["risk_evidence"],
                        sort_keys=True,
                    ),
                    decision["response_action"],
                    decision["acl_control_level"],
                    decision["response_status"],
                    json.dumps(
                        decision["evidence"],
                        sort_keys=True,
                    ),
                ),
            )

            if cursor.rowcount == 1:
                created += 1
            else:
                existing += 1

    return created, existing
