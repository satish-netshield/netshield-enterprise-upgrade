"""Test Phase 3A V2 Stage 10 XDR-style correlation."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from scripts.initialize_v2_stage10 import INDEXES, SCHEMA, TABLES
from src.correlation.v2_xdr_engine import (
    build_evidence_groups,
    build_incidents,
    build_indicators,
    evidence_link_rows,
    incident_confidence,
    save_evidence_links,
    save_incidents,
    save_indicators,
    unique_contribution_records,
)
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage10XDRCorrelationTests(unittest.TestCase):
    """Verify the agreed Stage 10 correlation behaviour."""

    def setUp(self) -> None:
        """Create an isolated Stage 10 database for each test."""
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temporary_directory.name) / "stage10.db"
        )
        self.configuration = load_json(
            PROJECT_ROOT / "config/v2_xdr_correlation.json"
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            connection.executescript(SCHEMA)

    def tearDown(self) -> None:
        """Remove the isolated database."""
        self.temporary_directory.cleanup()

    def evidence(
        self,
        key: str,
        source_type: str,
        *,
        event_time: str = "2026-09-11T08:00:00+00:00",
        severity: str = "High",
        confidence: int = 80,
        contribution_status: str = "active",
        source_event_ids: list[str] | None = None,
        detection_type: str = "Controlled Detection",
        username: str | None = None,
        device_id: str | None = None,
        asset_id: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        hostname: str | None = None,
        process_name: str | None = None,
        file_hash: str | None = None,
        location: str | None = None,
        explicit_links: list[dict[str, object]] | None = None,
        original_evidence: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Return one controlled normalised evidence record."""
        return {
            "evidence_key": f"{source_type}:{key}",
            "source_type": source_type,
            "source_record_id": key,
            "event_time": event_time,
            "detection_type": detection_type,
            "severity": severity,
            "confidence": confidence,
            "contribution_status": contribution_status,
            "source_event_ids": (
                source_event_ids or [f"event-{key}"]
            ),
            "reason_codes": ["CONTROLLED_TEST"],
            "attack_techniques": [],
            "explicit_links": explicit_links or [],
            "username": username,
            "device_id": device_id,
            "asset_id": asset_id,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "hostname": hostname,
            "process_name": process_name,
            "file_hash": file_hash,
            "location": location,
            "original_evidence": original_evidence or {},
        }

    def incidents_for(
        self,
        evidence: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Build incidents from controlled evidence."""
        groups = build_evidence_groups(
            evidence,
            self.configuration,
        )
        return build_incidents(
            groups,
            self.configuration,
        )

    def test_configuration_preserves_scope_and_safety(
        self,
    ) -> None:
        """Configuration keeps correlation local and evidence-backed."""
        correlation = self.configuration["correlation"]
        sandbox = self.configuration["sandbox_policy"]
        vulnerability = self.configuration[
            "vulnerability_policy"
        ]

        self.assertEqual(
            correlation["minimum_independent_sources"],
            2,
        )
        self.assertTrue(
            correlation["mac_address_is_supporting_only"]
        )
        self.assertTrue(
            vulnerability[
                "context_does_not_create_incident"
            ]
        )
        self.assertTrue(
            sandbox["local_simulated_data_only"]
        )
        self.assertFalse(
            sandbox["real_external_targets_allowed"]
        )
        self.assertFalse(
            sandbox[
                "automatic_response_actions_allowed"
            ]
        )

    def test_schema_contains_required_tables_and_indexes(
        self,
    ) -> None:
        """The migration creates three tables and 14 indexes."""
        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                ).fetchall()
            }
            indexes = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'index'
                      AND sql IS NOT NULL
                    """
                ).fetchall()
            }

        self.assertTrue(TABLES.issubset(tables))
        self.assertTrue(INDEXES.issubset(indexes))
        self.assertEqual(len(TABLES), 3)
        self.assertEqual(len(INDEXES), 14)

    def test_shared_username_does_not_merge_separate_devices(
        self,
    ) -> None:
        """One username cannot bridge otherwise unrelated devices."""
        evidence = [
            self.evidence(
                "identity-d1",
                "identity",
                username="analyst01",
                device_id="CYOD-001",
            ),
            self.evidence(
                "network-d1",
                "network",
                username="analyst01",
                device_id="CYOD-001",
            ),
            self.evidence(
                "identity-d2",
                "identity",
                username="analyst01",
                device_id="CYOD-002",
            ),
            self.evidence(
                "endpoint-d2",
                "endpoint",
                username="analyst01",
                device_id="CYOD-002",
            ),
        ]

        groups = build_evidence_groups(
            evidence,
            self.configuration,
        )
        incidents = build_incidents(
            groups,
            self.configuration,
        )

        self.assertEqual(
            sorted(len(group) for group in groups),
            [2, 2],
        )
        self.assertEqual(len(incidents), 2)
        self.assertEqual(
            {
                tuple(incident["device_ids"])
                for incident in incidents
            },
            {
                ("CYOD-001",),
                ("CYOD-002",),
            },
        )

    def test_related_device_sources_are_combined(
        self,
    ) -> None:
        """Independent sources for one device form one incident."""
        evidence = [
            self.evidence(
                "identity",
                "identity",
                device_id="CYOD-002",
            ),
            self.evidence(
                "access",
                "access_policy",
                device_id="CYOD-002",
            ),
            self.evidence(
                "network",
                "network",
                device_id="CYOD-002",
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                device_id="CYOD-002",
            ),
        ]

        incidents = self.incidents_for(evidence)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["independent_source_count"],
            4,
        )
        self.assertEqual(
            incidents[0]["device_ids"],
            ["CYOD-002"],
        )

    def test_mac_address_is_not_a_correlation_anchor(
        self,
    ) -> None:
        """A shared MAC address remains supporting evidence only."""
        evidence = [
            self.evidence(
                "network",
                "network",
                mac_address="08:00:27:cf:49:71",
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                mac_address="08:00:27:cf:49:71",
            ),
        ]

        groups = build_evidence_groups(
            evidence,
            self.configuration,
        )

        self.assertEqual(len(groups), 2)
        self.assertEqual(
            self.incidents_for(evidence),
            [],
        )

    def test_location_and_detection_do_not_merge_activity(
        self,
    ) -> None:
        """Supporting context cannot merge unrelated activity."""
        evidence = [
            self.evidence(
                "identity",
                "identity",
                username="viewer01",
                location="Office",
                detection_type="Controlled Detection",
            ),
            self.evidence(
                "network",
                "network",
                username="analyst01",
                location="Office",
                detection_type="Controlled Detection",
            ),
        ]

        self.assertEqual(
            len(
                build_evidence_groups(
                    evidence,
                    self.configuration,
                )
            ),
            2,
        )

    def test_explicit_exploitation_link_overrides_time_and_anchor(
        self,
    ) -> None:
        """A supported finding link joins its named endpoint evidence."""
        link = {
            "link_type": "alert",
            "linked_record_id": "S78-END-020",
            "exploitation_status": "successful",
        }

        evidence = [
            self.evidence(
                "S78-FND-SQL-001",
                "application",
                event_time="2026-09-11T13:00:00+00:00",
                asset_id="AST-WEB-001",
                detection_type=(
                    "SQL injection authentication bypass"
                ),
                explicit_links=[link],
                original_evidence={
                    "exploitation_status": "successful",
                    "remediation_status": "Verified",
                },
            ),
            self.evidence(
                "endpoint-alert",
                "endpoint",
                event_time="2026-09-01T08:00:00+00:00",
                device_id="CYOD-002",
                source_event_ids=["S78-END-020"],
                detection_type=(
                    "Suspicious Command Activity"
                ),
            ),
        ]

        groups = build_evidence_groups(
            evidence,
            self.configuration,
        )
        incidents = build_incidents(
            groups,
            self.configuration,
        )

        self.assertEqual(len(groups), 1)
        self.assertEqual(len(incidents), 1)
        self.assertIn(
            "explicit_finding_link_preserved",
            incidents[0]["correlation_reasons"],
        )

    def test_vulnerability_context_alone_does_not_create_incident(
        self,
    ) -> None:
        """Two findings without exploitation remain prevention context."""
        evidence = [
            self.evidence(
                "application",
                "application",
                asset_id="AST-WEB-001",
                contribution_status="context_only",
            ),
            self.evidence(
                "vulnerability",
                "vulnerability",
                asset_id="AST-WEB-001",
                contribution_status="context_only",
            ),
        ]

        self.assertEqual(
            self.incidents_for(evidence),
            [],
        )

    def test_vulnerability_context_is_preserved_with_activity(
        self,
    ) -> None:
        """A finding supports an incident when activity also exists."""
        evidence = [
            self.evidence(
                "finding",
                "vulnerability",
                asset_id="AST-WEB-001",
                contribution_status="context_only",
                original_evidence={
                    "exploitation_status": "none",
                    "remediation_status": "Open",
                },
            ),
            self.evidence(
                "application",
                "application",
                asset_id="AST-WEB-001",
                contribution_status="active",
            ),
        ]

        incidents = self.incidents_for(evidence)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            len(incidents[0]["vulnerability_context"]),
            2,
        )
        self.assertIn(
            "vulnerability_retained_as_context",
            incidents[0]["correlation_reasons"],
        )

    def test_repeated_source_event_is_scored_once(
        self,
    ) -> None:
        """Multiple detections from one event cannot inflate confidence."""
        evidence = [
            self.evidence(
                "identity-one",
                "identity",
                confidence=70,
                device_id="CYOD-002",
                source_event_ids=["same-event"],
            ),
            self.evidence(
                "identity-two",
                "identity",
                confidence=90,
                device_id="CYOD-002",
                source_event_ids=["same-event"],
            ),
            self.evidence(
                "network",
                "network",
                confidence=80,
                device_id="CYOD-002",
            ),
        ]

        records = unique_contribution_records(
            evidence
        )
        incidents = self.incidents_for(evidence)

        self.assertEqual(len(records), 2)
        self.assertEqual(
            incidents[0]["active_evidence_count"],
            2,
        )
        self.assertEqual(
            incidents[0]["confidence"],
            95,
        )

    def test_independent_sources_increase_confidence(
        self,
    ) -> None:
        """Corroboration adds only the configured source bonus."""
        records = [
            self.evidence(
                "identity",
                "identity",
                confidence=70,
            ),
            self.evidence(
                "network",
                "network",
                confidence=70,
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                confidence=70,
            ),
        ]

        confidence, exceptions, verified = (
            incident_confidence(
                records,
                self.configuration,
            )
        )

        self.assertEqual(confidence, 80)
        self.assertEqual(exceptions, 0)
        self.assertEqual(verified, 0)

    def test_validated_exception_reduces_confidence(
        self,
    ) -> None:
        """A reviewed false positive reduces but does not erase evidence."""
        records = [
            self.evidence(
                "identity",
                "identity",
                confidence=80,
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                confidence=80,
            ),
            self.evidence(
                "network",
                "network",
                confidence=90,
                contribution_status="exception",
            ),
        ]

        confidence, exceptions, verified = (
            incident_confidence(
                records,
                self.configuration,
            )
        )

        self.assertEqual(confidence, 75)
        self.assertEqual(exceptions, 1)
        self.assertEqual(verified, 0)

    def test_verified_activity_reduces_confidence(
        self,
    ) -> None:
        """Approved activity reduces confidence without becoming active."""
        records = [
            self.evidence(
                "identity",
                "identity",
                confidence=80,
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                confidence=80,
            ),
            self.evidence(
                "access",
                "access_policy",
                confidence=60,
                contribution_status="verified",
            ),
        ]

        confidence, exceptions, verified = (
            incident_confidence(
                records,
                self.configuration,
            )
        )

        self.assertEqual(confidence, 80)
        self.assertEqual(exceptions, 0)
        self.assertEqual(verified, 1)

    def test_iocs_are_separate_from_behaviours_and_mac(
        self,
    ) -> None:
        """Suspicious values become IoCs while behaviours remain labels."""
        evidence = [
            self.evidence(
                "endpoint",
                "endpoint",
                severity="Critical",
                confidence=95,
                device_id="CYOD-002",
                ip_address="192.0.2.20",
                mac_address="02:00:00:00:00:02",
                process_name=(
                    "credential_dump_simulator"
                ),
                detection_type="Suspicious Process",
            ),
            self.evidence(
                "network",
                "network",
                device_id="CYOD-002",
                detection_type="Port Scanning",
            ),
        ]

        incidents = self.incidents_for(evidence)
        indicators = build_indicators(
            incidents,
            self.configuration,
        )

        classifications = {
            (
                item["indicator_type"],
                item["classification"],
            )
            for item in indicators
        }

        self.assertIn(
            ("ip_address", "ioc"),
            classifications,
        )
        self.assertIn(
            ("process_name", "ioc"),
            classifications,
        )
        self.assertIn(
            (
                "mac_address",
                "supporting_observable",
            ),
            classifications,
        )
        self.assertIn(
            "Suspicious Process",
            incidents[0]["behaviours"],
        )
        self.assertNotIn(
            "Suspicious Process",
            {
                item["indicator_value"]
                for item in indicators
            },
        )

    def test_attack_mappings_are_preserved(
        self,
    ) -> None:
        """Useful ATT&CK mappings remain attached to the incident."""
        identity = self.evidence(
            "identity",
            "identity",
            device_id="CYOD-002",
            detection_type="Password Spraying",
        )
        identity["attack_techniques"] = [
            "T1110.003"
        ]

        endpoint = self.evidence(
            "endpoint",
            "endpoint",
            device_id="CYOD-002",
            detection_type=(
                "Possible Persistence Indicator"
            ),
        )

        incident = self.incidents_for(
            [identity, endpoint]
        )[0]

        self.assertEqual(
            incident["attack_techniques"],
            ["T1110.003", "T1547"],
        )

    def test_storage_is_duplicate_safe_and_preserves_status(
        self,
    ) -> None:
        """Repeated storage preserves one incident and investigation."""
        evidence = [
            self.evidence(
                "identity",
                "identity",
                device_id="CYOD-002",
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                device_id="CYOD-002",
            ),
        ]

        incidents = self.incidents_for(evidence)
        links = evidence_link_rows(
            incidents,
            self.configuration,
        )
        indicators = build_indicators(
            incidents,
            self.configuration,
        )

        first_incidents = save_incidents(
            self.database_path,
            incidents,
        )
        first_links = save_evidence_links(
            self.database_path,
            links,
        )
        first_indicators = save_indicators(
            self.database_path,
            indicators,
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            connection.execute(
                """
                UPDATE v2_xdr_incidents
                SET status = 'Investigating'
                """
            )
            connection.commit()

        incidents[0]["created_at"] = (
            "2026-09-18T09:00:00+00:00"
        )

        second_incidents = save_incidents(
            self.database_path,
            incidents,
        )
        second_links = save_evidence_links(
            self.database_path,
            links,
        )
        second_indicators = save_indicators(
            self.database_path,
            indicators,
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    original_evidence_preserved,
                    evidence_count
                FROM v2_xdr_incidents
                """
            ).fetchone()

            counts = connection.execute(
                """
                SELECT
                    (
                        SELECT COUNT(*)
                        FROM v2_xdr_incidents
                    ),
                    (
                        SELECT COUNT(*)
                        FROM v2_xdr_incident_evidence
                    ),
                    (
                        SELECT COUNT(*)
                        FROM v2_xdr_indicators
                    )
                """
            ).fetchone()

        self.assertEqual(
            first_incidents,
            (1, 0),
        )
        self.assertEqual(
            second_incidents,
            (0, 1),
        )
        self.assertEqual(
            first_links,
            (2, 0),
        )
        self.assertEqual(
            second_links,
            (0, 2),
        )
        self.assertEqual(
            first_indicators[0],
            0,
        )
        self.assertEqual(
            second_indicators[0],
            0,
        )
        self.assertEqual(
            row,
            ("Investigating", 1, 2),
        )
        self.assertEqual(
            counts,
            (1, 2, 0),
        )

    def test_evidence_links_retain_reasons_and_original_evidence(
        self,
    ) -> None:
        """Stored links retain why evidence was correlated."""
        evidence = [
            self.evidence(
                "identity",
                "identity",
                device_id="CYOD-002",
                original_evidence={
                    "identity_fact": "preserved"
                },
            ),
            self.evidence(
                "endpoint",
                "endpoint",
                device_id="CYOD-002",
                original_evidence={
                    "endpoint_fact": "preserved"
                },
            ),
        ]

        incidents = self.incidents_for(evidence)
        rows = evidence_link_rows(
            incidents,
            self.configuration,
        )

        save_incidents(
            self.database_path,
            incidents,
        )
        save_evidence_links(
            self.database_path,
            rows,
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            stored = connection.execute(
                """
                SELECT
                    shared_fields,
                    correlation_reasons,
                    evidence
                FROM v2_xdr_incident_evidence
                ORDER BY evidence_key
                """
            ).fetchall()

        self.assertEqual(len(stored), 2)
        self.assertTrue(
            all(
                "CYOD-002"
                in json.loads(row[0])["device_id"]
                for row in stored
            )
        )
        self.assertTrue(
            all(
                "shared_device_id=CYOD-002"
                in json.loads(row[1])
                for row in stored
            )
        )
        self.assertEqual(
            {
                next(
                    iter(
                        json.loads(row[2]).values()
                    )
                )
                for row in stored
            },
            {"preserved"},
        )


if __name__ == "__main__":
    unittest.main()
