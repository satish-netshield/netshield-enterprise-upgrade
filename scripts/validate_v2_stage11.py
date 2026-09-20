"""Validate Phase 3A V2 Stage 11 incident management and evidence."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from scripts.initialize_v2_stage11 import (
    INDEXES,
    TABLES,
    validate_configuration,
)
from src.utils.config_loader import load_json
from src.utils.sqlite_connection import managed_connection


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}")


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def object_names(connection, object_type, pattern):
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = ? AND name LIKE ?",
            (object_type, pattern),
        ).fetchall()
    }


def main():
    settings = load_json(ROOT / "config/settings.json")
    configuration = load_json(
        ROOT / "config/v2_incident_management.json"
    )
    database = ROOT / settings["database"]["path"]

    validate_configuration(configuration)

    required_files = {
        "config/v2_incident_management.json",
        "scripts/initialize_v2_stage11.py",
        "scripts/initialize_v2_stage11_risk.py",
        "scripts/import_v2_stage11_incidents.py",
        "scripts/import_v2_stage11_context.py",
        "scripts/assign_v2_stage11_incident.py",
        "scripts/review_v2_stage11_incident.py",
        "scripts/close_v2_stage11_false_positive.py",
        "scripts/generate_v2_stage11_reports.py",
        "scripts/validate_v2_stage11.py",
    }

    require(
        all((ROOT / path).is_file() for path in required_files),
        "Stage 11 files exist",
    )

    with managed_connection(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchall()
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        require(
            integrity and integrity[0][0] == "ok",
            "SQLite integrity is valid",
        )
        require(
            foreign_keys == [],
            "SQLite foreign keys are valid",
        )

        require(
            TABLES <= object_names(
                connection,
                "table",
                "v2_incident%",
            ),
            "Stage 11 tables exist",
        )
        require(
            INDEXES <= object_names(
                connection,
                "index",
                "idx_v2_incident%",
            ),
            "Stage 11 indexes exist",
        )

        connection.row_factory = sqlite3.Row

        incidents = connection.execute(
            "SELECT * FROM v2_incidents "
            "ORDER BY managed_incident_id"
        ).fetchall()

        require(
            len(incidents) == 3,
            "Three XDR incidents are managed",
        )
        require(
            len({row["incident_id"] for row in incidents}) == 3,
            "Incident IDs are unique",
        )
        require(
            all(row["source_incident_key"] for row in incidents),
            "Source incident keys are preserved",
        )
        require(
            all(
                row["original_evidence_preserved"] == 1
                for row in incidents
            ),
            "Original evidence is preserved",
        )
        lifecycle_statuses = set(
            configuration["lifecycle"]["primary_path"]
        ) | {configuration["lifecycle"]["false_positive_target"]}
        require(
            {row["status"] for row in incidents}
            <= lifecycle_statuses
            and incidents[1]["status"] == "New"
            and incidents[2]["status"] == "New",
            "Current lifecycle states are evidence-backed",
        )
        require(
            incidents[0]["incident_owner"] == "analyst01"
            and incidents[0]["status"]
            in {
                "Investigating",
                "Contained",
                "Eradicated",
                "Recovered",
                "Closed",
            },
            "Investigated incident retains its authorised owner",
        )
        require(
            all(row["risk_score"] is None for row in incidents),
            "Unmatched risk remains explicitly unassessed",
        )

        evidence = connection.execute(
            "SELECT * FROM v2_incident_evidence "
            "ORDER BY incident_id"
        ).fetchall()

        require(
            len(evidence) == 65,
            "Sixty-five evidence links are stored",
        )
        require(
            len(
                {
                    row["evidence_link_key"]
                    for row in evidence
                }
            )
            == 65,
            "Evidence links are duplicate-safe",
        )
        require(
            all(
                sha256_text(row["evidence_json"])
                == row["evidence_sha256"]
                for row in evidence
            ),
            "Evidence SHA-256 hashes verify",
        )

        iocs = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_iocs"
        ).fetchone()[0]
        behaviours = connection.execute(
            "SELECT COUNT(*) FROM v2_incident_behaviours"
        ).fetchone()[0]
        attack = connection.execute(
            "SELECT COUNT(*) "
            "FROM v2_incident_attack_references"
        ).fetchone()[0]
        findings = connection.execute(
            "SELECT COUNT(*) "
            "FROM v2_incident_vulnerability_links"
        ).fetchone()[0]

        require(
            (iocs, behaviours, attack, findings)
            == (10, 31, 12, 6),
            "IoCs, behaviours, ATT&CK references and findings are complete",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) FROM v2_incident_iocs "
                "WHERE ioc_type = 'mac_address'"
            ).fetchone()[0]
            == 0,
            "MAC addresses remain outside the IoC table",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) "
                "FROM v2_incident_vulnerability_links "
                "WHERE relationship = 'successful_exploitation'"
            ).fetchone()[0]
            == 1,
            "Successful exploitation link is preserved",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) "
                "FROM v2_incident_vulnerability_links "
                "WHERE relationship = 'context_only'"
            ).fetchone()[0]
            == 5,
            "Unexploited findings remain context-only",
        )

        decisions = connection.execute(
            "SELECT * FROM v2_incident_decisions "
            "WHERE decision_key LIKE 'v2-review-%' "
            "ORDER BY decision_time"
        ).fetchall()

        require(
            len(decisions) == 2,
            "Triage and investigation decisions are stored",
        )
        require(
            [row["new_status"] for row in decisions]
            == ["Triaged", "Investigating"],
            "Lifecycle transitions are preserved",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) "
                "FROM v2_incident_timeline "
                "WHERE event_type = 'report_generated'"
            ).fetchone()[0]
            == 3,
            "Report generation is recorded once per incident",
        )

        reports = connection.execute(
            "SELECT * FROM v2_incident_reports "
            "ORDER BY incident_id, report_type"
        ).fetchall()

        require(
            len(reports) == 6,
            "JSON and readable reports exist per incident",
        )

        for report in reports:
            path = ROOT / report["report_path"]
            require(
                path.is_file(),
                f"Report exists: {report['report_path']}",
            )
            require(
                sha256_text(
                    path.read_text(encoding="utf-8")
                )
                == report["report_sha256"],
                f"Report hash verifies: {report['report_path']}",
            )

        require(
            connection.execute(
                "SELECT COUNT(*) FROM audit_events "
                "WHERE action IN ("
                "'initialize_v2_stage11',"
                "'import_v2_stage11_incidents',"
                "'import_v2_stage11_context',"
                "'assign_v2_stage11_incident',"
                "'review_v2_stage11_incident',"
                "'generate_v2_stage11_reports'"
                ") AND result = 'success'"
            ).fetchone()[0]
            >= 8,
            "Stage 11 actions are audited",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) FROM audit_events "
                "WHERE action = "
                "'close_v2_stage11_false_positive' "
                "AND result = 'denied'"
            ).fetchone()[0]
            >= 1,
            "Rejected false-positive review is audited",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) FROM v2_incident_approvals "
                "WHERE action_occurred = 1"
            ).fetchone()[0]
            == 0,
            "No unperformed response action is recorded",
        )

    print("V2 STAGE 11 VALIDATION: PASS")


if __name__ == "__main__":
    main()
