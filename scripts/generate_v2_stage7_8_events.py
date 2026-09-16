"""Generate controlled Phase 3A V2 Stage 7 and Stage 8 events."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.collectors.event_normalizer import normalise_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = PROJECT_ROOT / "data/raw/v2/stage7_8"
BASE_TIME = datetime(2026, 9, 11, 8, 0, tzinfo=timezone.utc)

ENDPOINT_FILE = "endpoint_v2_stage7_8_events.jsonl"
APPLICATION_SECURITY_FILE = (
    "application_security_v2_stage7_8_events.jsonl"
)
VULNERABILITY_FILE = "vulnerability_v2_stage7_8_events.jsonl"


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON object from disk."""
    with path.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)

    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")

    return value


def event_time(minutes: int, seconds: int = 0) -> str:
    """Return a deterministic UTC timestamp for controlled evidence."""
    return (
        BASE_TIME + timedelta(minutes=minutes, seconds=seconds)
    ).isoformat()


def endpoint_event(
    event_id: str,
    event_type: str,
    minutes: int,
    *,
    severity: str = "Low",
    device_id: str = "CYOD-002",
    asset_id: str = "AST-002",
    username: str = "analyst01",
    hostname: str = "Analyst-Laptop",
    **details: Any,
) -> dict[str, Any]:
    """Build one controlled endpoint event."""
    event: dict[str, Any] = {
        "event_id": event_id,
        "event_time": event_time(minutes),
        "schema_version": "2.0",
        "source_system": "simulated_endpoint_sensor",
        "source_type": "endpoint",
        "event_type": event_type,
        "severity": severity,
        "device_id": device_id,
        "asset_id": asset_id,
        "username": username,
        "hostname": hostname,
        "ip_address": "192.0.2.20",
        "mac_address": "02:00:00:00:00:02",
        "location": "Auckland-NZ",
        "simulation_only": True,
    }
    event.update(details)
    return event


def finding_event(
    event_id: str,
    event_type: str,
    minutes: int,
    *,
    source_type: str,
    source_system: str,
    finding_id: str,
    finding_type: str,
    title: str,
    finding_source: str,
    severity: str,
    confidence: int,
    exploitability: str,
    exploitation_status: str,
    exposure_level: str,
    remediation_status: str,
    **details: Any,
) -> dict[str, Any]:
    """Build one controlled application-security or vulnerability event."""
    event: dict[str, Any] = {
        "event_id": event_id,
        "event_time": event_time(minutes),
        "schema_version": "2.0",
        "source_system": source_system,
        "source_type": source_type,
        "event_type": event_type,
        "finding_id": finding_id,
        "source_finding_id": finding_id,
        "asset_id": "AST-WEB-001",
        "finding_type": finding_type,
        "title": title,
        "finding_source": finding_source,
        "severity": severity,
        "confidence": confidence,
        "exploitability": exploitability,
        "exploitation_status": exploitation_status,
        "exposure_level": exposure_level,
        "asset_criticality": "medium",
        "remediation_status": remediation_status,
        "simulation_only": True,
        "safe_check": True,
        "external_target": False,
    }
    event.update(details)
    return event


def endpoint_events() -> list[dict[str, Any]]:
    """Return controlled evidence for every approved Stage 7 rule."""
    return [
        endpoint_event(
            "S78-END-001",
            "endpoint_health_observed",
            0,
            health_state="healthy",
            compliance_state="compliant",
            device_risk_state="low",
            process_name="netshield_worker",
            process_status="approved",
            process_owner="netshield01",
            status="normal",
        ),
        endpoint_event(
            "S78-END-002",
            "endpoint_health_observed",
            5,
            severity="Medium",
            health_state="degraded",
            status="degraded",
        ),
        endpoint_event(
            "S78-END-003",
            "endpoint_health_observed",
            10,
            severity="High",
            health_state="unhealthy",
            status="unhealthy",
        ),
        endpoint_event(
            "S78-END-004",
            "endpoint_health_observed",
            15,
            severity="Medium",
            health_state="unknown",
            status="unknown",
        ),
        endpoint_event(
            "S78-END-005",
            "device_compliance_observed",
            20,
            severity="High",
            compliance_state="non_compliant",
            status="non_compliant",
        ),
        endpoint_event(
            "S78-END-006",
            "device_compliance_observed",
            25,
            severity="Medium",
            compliance_state="unknown",
            status="unknown",
        ),
        endpoint_event(
            "S78-END-007",
            "device_risk_observed",
            30,
            severity="High",
            device_risk_state="high",
            risk_score=85,
            status="active",
        ),
        endpoint_event(
            "S78-END-008",
            "device_risk_observed",
            35,
            severity="Critical",
            device_risk_state="critical",
            risk_score=96,
            status="active",
            isolation_action="quarantine_device",
            isolation_status="approval_required",
            real_isolation_executed=False,
            network_state_changed=False,
        ),
        endpoint_event(
            "S78-END-009",
            "process_started",
            40,
            severity="Critical",
            process_name="credential_dump_simulator",
            process_id=7101,
            process_owner="analyst01",
            process_status="unapproved",
            command_line=(
                "credential_dump_simulator "
                "--controlled-evidence-only"
            ),
            status="observed",
        ),
        endpoint_event(
            "S78-END-010",
            "process_started",
            45,
            severity="Medium",
            process_name="unknown_process_simulator",
            process_id=7102,
            process_owner="analyst01",
            process_status="unknown",
            status="observed",
        ),
        endpoint_event(
            "S78-END-011",
            "process_started",
            50,
            severity="High",
            username="viewer01",
            process_name="python3",
            process_id=7103,
            process_owner="viewer01",
            process_status="approved",
            status="observed",
        ),
        endpoint_event(
            "S78-END-012",
            "process_started",
            55,
            severity="High",
            process_name="command_shell_simulator",
            process_id=7104,
            process_owner="analyst01",
            process_status="unapproved",
            parent_process_name="office_simulator",
            parent_process_id=6104,
            status="observed",
        ),
        endpoint_event(
            "S78-END-013",
            "process_started",
            60,
            severity="Critical",
            process_name="unapproved_remote_shell_simulator",
            process_id=7105,
            process_owner="analyst01",
            process_status="unapproved",
            parent_process_name="web_server_simulator",
            parent_process_id=6105,
            status="observed",
        ),
        endpoint_event(
            "S78-END-014",
            "cpu_activity_observed",
            80,
            severity="High",
            process_name="python3",
            process_id=7201,
            process_owner="analyst01",
            cpu_percent=96,
            status="active",
        ),
        endpoint_event(
            "S78-END-015",
            "cpu_activity_observed",
            81,
            severity="High",
            process_name="python3",
            process_id=7201,
            process_owner="analyst01",
            cpu_percent=97,
            status="active",
        ),
        endpoint_event(
            "S78-END-016",
            "cpu_activity_observed",
            82,
            severity="Critical",
            process_name="python3",
            process_id=7201,
            process_owner="analyst01",
            cpu_percent=98,
            status="active",
        ),
        endpoint_event(
            "S78-END-017",
            "process_crashed",
            100,
            severity="Medium",
            process_name="netshield_worker",
            process_id=7301,
            process_owner="netshield01",
            process_status="approved",
            status="crashed",
        ),
        endpoint_event(
            "S78-END-018",
            "process_restarted",
            104,
            severity="Medium",
            process_name="netshield_worker",
            process_id=7302,
            process_owner="netshield01",
            process_status="approved",
            status="restarted",
        ),
        endpoint_event(
            "S78-END-019",
            "process_crashed",
            107,
            severity="High",
            process_name="netshield_worker",
            process_id=7302,
            process_owner="netshield01",
            process_status="approved",
            status="crashed",
        ),
        endpoint_event(
            "S78-END-020",
            "command_activity_observed",
            115,
            severity="Critical",
            process_name="python3",
            process_id=7401,
            process_owner="analyst01",
            command_line="encoded_command_simulation",
            command_indicator="encoded_command_simulation",
            status="observed",
        ),
        endpoint_event(
            "S78-END-021",
            "persistence_activity_observed",
            120,
            severity="High",
            process_name="persistence_simulator",
            process_id=7501,
            process_owner="analyst01",
            process_status="unapproved",
            persistence_indicator="scheduled_task_created",
            status="observed",
        ),
        endpoint_event(
            "S78-END-022",
            "file_hash_observed",
            125,
            severity="High",
            process_name="netshield_worker",
            file_path="/simulated/netshield/agent.py",
            expected_hash=(
                "c972dc732aea55266906c98c978581803"
                "ae2027b0709d9b0b025436381fe9e47"
            ),
            observed_hash=(
                "b6f00f283e247b400f863322cf2c44bf"
                "bcd585280c651fbdc264132ed0e61d82"
            ),
            hash_algorithm="sha256",
            status="changed",
        ),
        endpoint_event(
            "S78-END-ADMIN-001",
            "command_activity_observed",
            130,
            severity="Medium",
            username="admin01",
            process_name="python3",
            process_id=7601,
            process_owner="admin01",
            command_line="approved_inventory_maintenance",
            administrative_activity=True,
            approval_reference="CHG-S78-001",
            status="approved",
        ),
        endpoint_event(
            "S78-END-TEST-001",
            "cpu_activity_observed",
            135,
            severity="High",
            process_name="controlled_cpu_test",
            process_id=7602,
            process_owner="analyst01",
            process_status="approved_testing",
            cpu_percent=99,
            testing_id="S78-END-TEST-001",
            controlled_testing=True,
            status="approved_testing",
        ),
        endpoint_event(
            "S78-END-023",
            "process_started",
            140,
            process_name="python3",
            process_id=7701,
            process_owner="analyst01",
            process_status="approved",
            parent_process_name="systemd",
            status="normal",
        ),
        endpoint_event(
            "S78-END-024",
            "post_isolation_activity_observed",
            145,
            severity="High",
            process_name="unapproved_remote_shell_simulator",
            process_id=7801,
            process_owner="analyst01",
            process_status="unapproved",
            isolation_state="simulated_isolated",
            real_isolation_executed=False,
            network_state_changed=False,
            status="observed_after_simulated_isolation",
        ),
    ]


def application_security_events(
    lab_report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return controlled local application-security evidence."""
    request_analysis = lab_report["request_analysis"]
    return [
        finding_event(
            "S78-APPSEC-001",
            "finding_created",
            200,
            source_type="application",
            source_system="sql_injection_lab",
            finding_id="S78-FND-SQL-001",
            finding_type="sql_injection",
            title="SQL injection authentication bypass",
            finding_source="sql_injection_lab",
            severity="High",
            confidence=98,
            exploitability="demonstrated",
            exploitation_status="successful",
            exposure_level="internal",
            remediation_status="Open",
            application_id="APP-001",
            exposed_service="local_sql_injection_lab",
            component_name="login_query",
            component_version="controlled_lab_v1",
            lab_report_path=(
                "lab/sql_injection/outputs/"
                "stage6_detection_report.json"
            ),
            vulnerable_authentication_bypasses=request_analysis[
                "vulnerable_authentication_bypasses"
            ],
            vulnerable_request_ids=request_analysis[
                "vulnerable_request_ids"
            ],
            status="Open",
        ),
        finding_event(
            "S78-APPSEC-002",
            "finding_link_requested",
            202,
            source_type="application",
            source_system="simulated_application_security",
            finding_id="S78-FND-SQL-001",
            finding_type="sql_injection",
            title="SQL injection finding linked to endpoint alert",
            finding_source="application_security",
            severity="High",
            confidence=90,
            exploitability="demonstrated",
            exploitation_status="successful",
            exposure_level="internal",
            remediation_status="Open",
            link_type="alert",
            linked_record_id="S78-END-020",
            shared_evidence=[
                "AST-WEB-001",
                "controlled_exploitation_activity",
            ],
            status="link_requested",
        ),
        finding_event(
            "S78-APPSEC-003",
            "finding_link_requested",
            204,
            source_type="application",
            source_system="simulated_application_security",
            finding_id="S78-FND-SQL-001",
            finding_type="sql_injection",
            title="SQL injection finding linked to existing incident",
            finding_source="application_security",
            severity="Critical",
            confidence=95,
            exploitability="demonstrated",
            exploitation_status="successful",
            exposure_level="internal",
            remediation_status="Open",
            incident_id="INC-V2-001",
            link_type="incident",
            linked_record_id="INC-V2-001",
            shared_evidence=[
                "AST-WEB-001",
                "successful_controlled_exploitation",
            ],
            automatic_incident_creation=False,
            status="link_requested",
        ),
        finding_event(
            "S78-APPSEC-004",
            "configuration_check_completed",
            210,
            source_type="application",
            source_system="simulated_configuration_check",
            finding_id="S78-FND-CFG-001",
            finding_type="security_header_configuration",
            title="Missing local security header",
            finding_source="configuration_check",
            severity="Medium",
            confidence=88,
            exploitability="low",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Planned",
            component_name="sql_injection_lab",
            component_version="controlled_lab_v1",
            configuration_key="Content-Security-Policy",
            observed_value="missing",
            status="Planned",
        ),
        finding_event(
            "S78-APPSEC-005",
            "remediation_verified",
            230,
            source_type="application",
            source_system="sql_injection_lab",
            finding_id="S78-FND-SQL-001",
            finding_type="sql_injection",
            title="SQL injection parameterised-query retest",
            finding_source="sql_injection_lab",
            severity="Low",
            confidence=99,
            exploitability="none",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Verified",
            component_name="login_query",
            component_version="parameterised_query_v1",
            verification_result="blocked",
            verification_evidence={
                "blocked_retest_request_ids": request_analysis[
                    "blocked_retest_request_ids"
                ],
                "parameterised_retests": request_analysis[
                    "parameterised_retests"
                ],
                "parameterised_retests_blocked": request_analysis[
                    "parameterised_retests_blocked"
                ],
            },
            status="Verified",
        ),
        finding_event(
            "S78-APPSEC-TEST-001",
            "controlled_penetration_test_completed",
            235,
            source_type="application",
            source_system="controlled_penetration_test",
            finding_id="S78-FND-TEST-001",
            finding_type="approved_security_test",
            title="Approved local application-security test",
            finding_source="controlled_penetration_test",
            severity="Low",
            confidence=100,
            exploitability="none",
            exploitation_status="none",
            exposure_level="none",
            remediation_status="Verified",
            testing_id="S78-APPSEC-TEST-001",
            controlled_testing=True,
            target="local_sql_injection_lab",
            test_result="approved_test_completed",
            status="approved_testing",
        ),
    ]


def vulnerability_events() -> list[dict[str, Any]]:
    """Return controlled Stage 8 vulnerability and remediation evidence."""
    return [
        finding_event(
            "S78-VULN-001",
            "finding_created",
            300,
            source_type="vulnerability",
            source_system="simulated_dependency_check",
            finding_id="S78-FND-DEP-001",
            finding_type="vulnerable_dependency",
            title="Outdated local demonstration dependency",
            finding_source="dependency_check",
            severity="High",
            confidence=92,
            exploitability="high",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Open",
            component_name="demo-web-framework",
            component_version="1.4.0-simulated",
            fixed_version="1.4.1-simulated",
            exposed_service="local_web_application",
            status="Open",
        ),
        finding_event(
            "S78-VULN-002",
            "finding_created",
            305,
            source_type="vulnerability",
            source_system="simulated_package_check",
            finding_id="S78-FND-PKG-001",
            finding_type="outdated_package",
            title="Outdated sandbox package",
            finding_source="package_check",
            severity="Medium",
            confidence=86,
            exploitability="medium",
            exploitation_status="none",
            exposure_level="restricted",
            remediation_status="Planned",
            component_name="demo-parser-package",
            component_version="2.1.0-simulated",
            fixed_version="2.1.2-simulated",
            status="Planned",
        ),
        finding_event(
            "S78-VULN-003",
            "finding_created",
            310,
            source_type="vulnerability",
            source_system="simulated_vulnerability_scan",
            finding_id="S78-FND-SVC-001",
            finding_type="exposed_service_configuration",
            title="Restricted service exposed inside the sandbox",
            finding_source="vulnerability_scan",
            severity="High",
            confidence=84,
            exploitability="medium",
            exploitation_status="none",
            exposure_level="exposed",
            remediation_status="Open",
            exposed_service="simulated_admin_service",
            destination_port=8443,
            status="Open",
        ),
        finding_event(
            "S78-VULN-004",
            "finding_created",
            315,
            source_type="vulnerability",
            source_system="simulated_vulnerability_scan",
            finding_id="S78-FND-FP-001",
            finding_type="version_match_only",
            title="Version-only finding requiring analyst review",
            finding_source="vulnerability_scan",
            severity="Medium",
            confidence=45,
            exploitability="low",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Open",
            component_name="demo-utility",
            component_version="3.0.0-simulated",
            review_candidate="false_positive",
            status="Open",
        ),
        finding_event(
            "S78-VULN-005",
            "remediation_status_changed",
            320,
            source_type="vulnerability",
            source_system="simulated_vulnerability_management",
            finding_id="S78-FND-DEP-001",
            finding_type="vulnerable_dependency",
            title="Dependency remediation planned",
            finding_source="dependency_check",
            severity="High",
            confidence=92,
            exploitability="high",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Planned",
            previous_status="Open",
            new_status="Planned",
            remediation_owner="admin01",
            status="Planned",
        ),
        finding_event(
            "S78-VULN-006",
            "remediation_status_changed",
            325,
            source_type="vulnerability",
            source_system="simulated_vulnerability_management",
            finding_id="S78-FND-DEP-001",
            finding_type="vulnerable_dependency",
            title="Dependency remediation in progress",
            finding_source="dependency_check",
            severity="High",
            confidence=92,
            exploitability="high",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="In Progress",
            previous_status="Planned",
            new_status="In Progress",
            remediation_owner="admin01",
            status="In Progress",
        ),
        finding_event(
            "S78-VULN-007",
            "remediation_status_changed",
            330,
            source_type="vulnerability",
            source_system="simulated_vulnerability_management",
            finding_id="S78-FND-DEP-001",
            finding_type="vulnerable_dependency",
            title="Dependency update completed",
            finding_source="dependency_check",
            severity="Low",
            confidence=95,
            exploitability="none",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Remediated",
            previous_status="In Progress",
            new_status="Remediated",
            component_name="demo-web-framework",
            component_version="1.4.1-simulated",
            status="Remediated",
        ),
        finding_event(
            "S78-VULN-008",
            "remediation_verified",
            340,
            source_type="vulnerability",
            source_system="simulated_dependency_check",
            finding_id="S78-FND-DEP-001",
            finding_type="vulnerable_dependency",
            title="Dependency remediation verified",
            finding_source="dependency_check",
            severity="Low",
            confidence=98,
            exploitability="none",
            exploitation_status="none",
            exposure_level="internal",
            remediation_status="Verified",
            previous_status="Remediated",
            new_status="Verified",
            verification_result="not_detected_after_update",
            verification_evidence={
                "installed_version": "1.4.1-simulated",
                "finding_present": False,
            },
            status="Verified",
        ),
        finding_event(
            "S78-VULN-009",
            "safe_local_check_completed",
            345,
            source_type="vulnerability",
            source_system="simulated_configuration_check",
            finding_id="S78-FND-LOCAL-001",
            finding_type="local_file_permission_check",
            title="Sensitive configuration permission check",
            finding_source="configuration_check",
            severity="Low",
            confidence=100,
            exploitability="none",
            exploitation_status="none",
            exposure_level="none",
            remediation_status="Verified",
            checked_path="config/v2_vulnerability_management.json",
            expected_mode="640",
            observed_mode="640",
            verification_result="pass",
            status="Verified",
        ),
        finding_event(
            "S78-VULN-TEST-001",
            "controlled_vulnerability_test_completed",
            350,
            source_type="vulnerability",
            source_system="controlled_penetration_test",
            finding_id="S78-FND-TEST-002",
            finding_type="approved_vulnerability_test",
            title="Approved controlled vulnerability test",
            finding_source="controlled_penetration_test",
            severity="Low",
            confidence=100,
            exploitability="none",
            exploitation_status="none",
            exposure_level="none",
            remediation_status="Verified",
            testing_id="S78-VULN-TEST-001",
            controlled_testing=True,
            target="local_sandbox_only",
            test_result="approved_test_completed",
            status="approved_testing",
        ),
    ]


def load_lab_report(
    vulnerability_configuration: dict[str, Any],
) -> dict[str, Any]:
    """Load and validate the existing controlled SQL injection report."""
    report_path = (
        PROJECT_ROOT
        / vulnerability_configuration["sql_injection_lab"]["report_path"]
    )
    report = load_json(report_path)
    sandbox = report.get("sandbox_boundary", {})

    if sandbox.get("local_test_application_only") is not True:
        raise ValueError("SQL injection evidence must remain local")

    if sandbox.get("external_targets_used") is not False:
        raise ValueError("SQL injection evidence used an external target")

    if sandbox.get("real_accounts_used") is not False:
        raise ValueError("SQL injection evidence used a real account")

    return report


def validate_configuration(
    endpoint_configuration: dict[str, Any],
    vulnerability_configuration: dict[str, Any],
    enterprise_context: dict[str, Any],
) -> None:
    """Validate the approved generation boundaries before writing events."""
    if endpoint_configuration.get("source_files") != [ENDPOINT_FILE]:
        raise ValueError("Stage 7 source-file configuration is invalid")

    if vulnerability_configuration.get("source_files") != [
        APPLICATION_SECURITY_FILE,
        VULNERABILITY_FILE,
    ]:
        raise ValueError("Stage 8 source-file configuration is invalid")

    thresholds = endpoint_configuration["thresholds"]
    if thresholds["process_crash_restart_events"] != 3:
        raise ValueError("Stage 7 requires three crash or restart events")

    if thresholds["process_crash_restart_window_minutes"] != 8:
        raise ValueError("Stage 7 crash or restart window must be 8 minutes")

    isolation = endpoint_configuration["isolation_policy"]
    if isolation["real_isolation_allowed"] is not False:
        raise ValueError("Real endpoint isolation must remain disabled")

    if isolation["change_network_state"] is not False:
        raise ValueError("Endpoint isolation must not change network state")

    sandbox = vulnerability_configuration["sandbox_policy"]
    if sandbox["real_external_targets_allowed"] is not False:
        raise ValueError("Stage 8 external targets must remain disabled")

    if sandbox["automatic_exploitation_allowed"] is not False:
        raise ValueError("Stage 8 automatic exploitation must remain disabled")

    if sandbox["automatic_incident_creation_allowed"] is not False:
        raise ValueError("Stage 8 automatic incidents must remain disabled")

    assets = {
        asset["asset_id"]: asset
        for asset in enterprise_context.get("assets", [])
    }
    lab_asset = assets.get("AST-WEB-001")

    if lab_asset is None:
        raise ValueError("AST-WEB-001 is not registered")

    if lab_asset.get("criticality") != "medium":
        raise ValueError("AST-WEB-001 must have Medium criticality")

    if lab_asset.get("external_target") is not False:
        raise ValueError("AST-WEB-001 must remain a local sandbox asset")


def validate_events(
    files: dict[str, list[dict[str, Any]]],
) -> None:
    """Validate event uniqueness, source mapping, and V2 compatibility."""
    expected_sources = {
        ENDPOINT_FILE: "endpoint",
        APPLICATION_SECURITY_FILE: "application",
        VULNERABILITY_FILE: "vulnerability",
    }
    event_ids: list[str] = []

    for filename, events in files.items():
        if not events:
            raise ValueError(f"No events were generated for {filename}")

        for event in events:
            if event["source_type"] != expected_sources[filename]:
                raise ValueError(f"Invalid source type in {filename}")

            if event.get("simulation_only") is not True:
                raise ValueError("Every Stage 7-8 event must be simulated")

            if event.get("external_target") is True:
                raise ValueError("A Stage 7-8 event uses an external target")

            normalise_event(event)
            event_ids.append(event["event_id"])

    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Stage 7-8 event IDs must be unique")


def write_events(
    filename: str,
    events: list[dict[str, Any]],
) -> None:
    """Write one deterministic JSONL source file."""
    output_path = OUTPUT_DIRECTORY / filename
    with output_path.open("w", encoding="utf-8") as output_file:
        for event in events:
            output_file.write(json.dumps(event, sort_keys=True) + "\n")


def main() -> None:
    """Generate and validate all controlled Stage 7 and Stage 8 events."""
    endpoint_configuration = load_json(
        PROJECT_ROOT / "config/v2_endpoint_monitoring.json"
    )
    vulnerability_configuration = load_json(
        PROJECT_ROOT / "config/v2_vulnerability_management.json"
    )
    enterprise_context = load_json(
        PROJECT_ROOT / "config/enterprise_context.json"
    )

    validate_configuration(
        endpoint_configuration,
        vulnerability_configuration,
        enterprise_context,
    )
    lab_report = load_lab_report(vulnerability_configuration)

    files = {
        ENDPOINT_FILE: endpoint_events(),
        APPLICATION_SECURITY_FILE: application_security_events(lab_report),
        VULNERABILITY_FILE: vulnerability_events(),
    }
    validate_events(files)

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for filename, events in files.items():
        write_events(filename, events)

    total = sum(len(events) for events in files.values())
    print(f"PASS: Generated {total} Stage 7-8 events")
    print(f"Endpoint events: {len(files[ENDPOINT_FILE])}")
    print(
        "Application-security events: "
        f"{len(files[APPLICATION_SECURITY_FILE])}"
    )
    print(f"Vulnerability events: {len(files[VULNERABILITY_FILE])}")
    print(f"Source files: {len(files)}")
    print("Crash or restart pattern: 3 events within 8 minutes")
    print("Real isolation or network changes: false")
    print("Real external targets or actions: false")
    print("SQL injection evidence: controlled local lab only")
    print("Automatic incident creation: false")


if __name__ == "__main__":
    main()
