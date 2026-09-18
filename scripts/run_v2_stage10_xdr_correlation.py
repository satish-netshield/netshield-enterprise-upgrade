"""Run Phase 3A V2 Stage 10 XDR-style correlation."""

from collections import Counter
from pathlib import Path

from src.correlation.v2_xdr_engine import (
    build_evidence_groups,
    build_incidents,
    build_indicators,
    evidence_link_rows,
    load_xdr_evidence,
    save_evidence_links,
    save_incidents,
    save_indicators,
)
from src.utils.config_loader import load_json
from src.utils.database import record_audit_event, save_metadata
from src.utils.logging_setup import configure_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Correlate existing V2 evidence and store explainable incidents."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    configuration = load_json(
        PROJECT_ROOT / "config/v2_xdr_correlation.json"
    )
    database_path = PROJECT_ROOT / settings["database"]["path"]

    evidence = load_xdr_evidence(database_path, configuration)
    groups = build_evidence_groups(evidence, configuration)
    incidents = build_incidents(groups, configuration)
    links = evidence_link_rows(incidents, configuration)
    indicators = build_indicators(incidents, configuration)

    incidents_created, incidents_existing = save_incidents(
        database_path,
        incidents,
    )
    links_created, links_existing = save_evidence_links(
        database_path,
        links,
    )
    indicators_created, indicators_existing = save_indicators(
        database_path,
        indicators,
    )

    severity_counts = Counter(
        incident["severity"] for incident in incidents
    )
    classification_counts = Counter(
        indicator["classification"] for indicator in indicators
    )
    source_types = {
        record["source_type"] for record in evidence
    }
    vulnerability_context_count = sum(
        len(incident["vulnerability_context"])
        for incident in incidents
    )
    exception_count = sum(
        incident["exception_count"] for incident in incidents
    )
    verified_count = sum(
        incident["verified_activity_count"]
        for incident in incidents
    )

    for incident in incidents:
        print(
            f"[{incident['severity']}] XDR Incident | "
            f"title={incident['title']} | "
            f"confidence={incident['confidence']} | "
            f"sources={incident['independent_source_count']} | "
            f"evidence={incident['evidence_count']} | "
            f"active={incident['active_evidence_count']} | "
            f"exceptions={incident['exception_count']} | "
            f"verified={incident['verified_activity_count']}"
        )
        print(
            "  reasons="
            + ",".join(incident["correlation_reasons"])
        )
        print(
            "  detections="
            + ",".join(incident["detection_types"])
        )

    if indicators:
        print()

    for indicator in indicators:
        print(
            "[XDR INDICATOR] "
            f"type={indicator['indicator_type']} | "
            f"value={indicator['indicator_value']} | "
            f"classification={indicator['classification']} | "
            f"confidence={indicator['confidence']}"
        )

    details = (
        f"evidence={len(evidence)} "
        f"source_types={len(source_types)} "
        f"candidate_groups={len(groups)} "
        f"incidents={len(incidents)} "
        f"incidents_new={incidents_created} "
        f"incidents_existing={incidents_existing} "
        f"evidence_links={len(links)} "
        f"links_new={links_created} "
        f"links_existing={links_existing} "
        f"indicators={len(indicators)} "
        f"indicators_new={indicators_created} "
        f"indicators_existing={indicators_existing} "
        f"critical={severity_counts['Critical']} "
        f"high={severity_counts['High']} "
        f"medium={severity_counts['Medium']} "
        f"low={severity_counts['Low']} "
        f"iocs={classification_counts['ioc']} "
        "supporting_observables="
        f"{classification_counts['supporting_observable']} "
        f"vulnerability_context={vulnerability_context_count} "
        f"exceptions={exception_count} "
        f"verified_activity={verified_count} "
        "automatic_actions=0"
    )

    app_logger = configure_logger(
        "netshield.application",
        PROJECT_ROOT / settings["logging"]["application_log"],
    )
    audit_logger = configure_logger(
        "netshield.audit",
        PROJECT_ROOT / settings["logging"]["audit_log"],
    )

    app_logger.info(
        "V2 Stage 10 XDR correlation completed: %s",
        details,
    )
    audit_logger.info(
        "actor=netshield01 "
        "action=run_v2_stage10_xdr_correlation "
        "target=xdr_correlation "
        "result=success %s",
        details,
    )
    record_audit_event(
        database_path=database_path,
        actor="netshield01",
        action="run_v2_stage10_xdr_correlation",
        target="xdr_correlation",
        result="success",
        details=details,
    )
    save_metadata(
        database_path,
        "v2_stage_10_status",
        "xdr_correlation_complete",
    )

    print()
    print(f"V2 STAGE 10 XDR CORRELATION: {details}")


if __name__ == "__main__":
    main()
