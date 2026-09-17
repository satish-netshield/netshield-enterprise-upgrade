"""Test Phase 3A V2 Stage 9 continuous monitoring."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from scripts.initialize_v2_stage9 import SCHEMA
from scripts.run_v2_stage9_continuous_monitoring import (
    build_pipeline_failure_alert,
    complete_cycle,
    scheduled_time,
    start_cycle,
)
from src.monitoring.v2_monitoring_health import (
    build_health_alerts,
    evaluate_component_health,
    save_component_health,
)
from src.monitoring.v2_risk_engine import (
    build_risk_alerts,
    calculate_risk_scores,
    close_resolved_risk_alerts,
    save_risk_alerts,
    save_risk_scores,
)
from src.monitoring.v2_risk_sources import is_false_positive
from src.utils.config_loader import load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class V2Stage9ContinuousMonitoringTests(unittest.TestCase):
    """Verify the agreed Stage 9 monitoring behaviour."""

    def setUp(self) -> None:
        """Create an isolated Stage 9 database for each test."""
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temporary_directory.name) / "stage9.db"
        )
        self.configuration = load_json(
            PROJECT_ROOT / "config/v2_continuous_monitoring.json"
        )
        self.assessed_at = "2026-09-17T08:00:00+00:00"

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            connection.executescript(SCHEMA)
            connection.executescript(
                """
                CREATE TABLE import_batches (
                    batch_id INTEGER PRIMARY KEY,
                    status TEXT NOT NULL,
                    accepted_records INTEGER NOT NULL
                );
                CREATE TABLE v2_identity_alerts (
                    alert_id INTEGER PRIMARY KEY
                );
                CREATE TABLE access_policy_decisions (
                    decision_id INTEGER PRIMARY KEY
                );
                CREATE TABLE v2_network_alerts (
                    alert_id INTEGER PRIMARY KEY
                );
                CREATE TABLE v2_endpoint_alerts (
                    alert_id INTEGER PRIMARY KEY
                );
                CREATE TABLE v2_vulnerability_findings (
                    finding_id INTEGER PRIMARY KEY
                );
                """
            )
            connection.execute(
                """
                INSERT INTO import_batches (
                    batch_id,
                    status,
                    accepted_records
                )
                VALUES (1, 'completed', 20)
                """
            )
            for table_name in (
                "v2_identity_alerts",
                "access_policy_decisions",
                "v2_network_alerts",
                "v2_endpoint_alerts",
                "v2_vulnerability_findings",
            ):
                connection.execute(
                    f"INSERT INTO {table_name} VALUES (1)"
                )
            connection.commit()

    def tearDown(self) -> None:
        """Remove the isolated database."""
        self.temporary_directory.cleanup()

    def evidence(
        self,
        source_type: str,
        *,
        severity: str = "High",
        confidence: int = 80,
        criticality: str = "high",
        validated_exception: bool = False,
        event_time: str = "2026-09-17T07:30:00+00:00",
    ) -> dict[str, object]:
        """Return one controlled evidence mapping."""
        return {
            "source_type": source_type,
            "record_id": f"{source_type}-record",
            "event_time": event_time,
            "severity": severity,
            "confidence": confidence,
            "asset_criticality": criticality,
            "entity_type": "user",
            "entity_id": "test-user",
            "validated_exception": validated_exception,
            "evidence_refs": [f"{source_type}-event"],
            "details": ["controlled_test"],
        }

    def risk_records(
        self,
        evidence: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Calculate records from controlled evidence."""
        return calculate_risk_scores(
            evidence,
            self.configuration,
            self.assessed_at,
        )

    def test_configuration_preserves_scope_and_safety(self) -> None:
        """Configuration keeps scoring evidence-backed and simulated."""
        self.assertEqual(
            self.configuration["risk_entities"],
            ["user", "device", "asset", "incident"],
        )
        self.assertEqual(
            sum(
                self.configuration["risk_scoring"]["weights"].values()
            ),
            100,
        )
        self.assertTrue(
            self.configuration["evidence_policy"]
            ["preserve_original_evidence"]
        )
        self.assertFalse(
            self.configuration["evidence_policy"]
            ["risk_scores_replace_evidence"]
        )
        self.assertFalse(
            self.configuration["sandbox_policy"]
            ["automatic_response_actions_allowed"]
        )

    def test_schema_contains_required_tables_and_indexes(self) -> None:
        """The Stage 9 migration creates five tables and 22 indexes."""
        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            tables = connection.execute(
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                      'v2_monitoring_cycles',
                      'v2_continuous_risk_scores',
                      'v2_continuous_risk_history',
                      'v2_monitoring_alerts',
                      'v2_detection_health'
                  )
                """
            ).fetchone()[0]
            indexes = connection.execute(
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'index'
                  AND tbl_name IN (
                      'v2_monitoring_cycles',
                      'v2_continuous_risk_scores',
                      'v2_continuous_risk_history',
                      'v2_monitoring_alerts',
                      'v2_detection_health'
                  )
                  AND sql IS NOT NULL
                """
            ).fetchone()[0]

        self.assertEqual(tables, 5)
        self.assertEqual(indexes, 22)

    def test_schedule_uses_fifteen_minute_intervals(self) -> None:
        """Assessment time is assigned to a deterministic interval."""
        self.assertEqual(
            scheduled_time(
                "2026-09-17T08:13:47+00:00",
                self.configuration["schedule"]["interval_minutes"],
            ),
            "2026-09-17T08:00:00+00:00",
        )

    def test_independent_sources_increase_risk(self) -> None:
        """Independent corroboration adds configured risk points."""
        record = self.risk_records(
            [
                self.evidence("identity"),
                self.evidence("network"),
                self.evidence("endpoint"),
            ]
        )[0]

        self.assertEqual(record["independent_source_count"], 3)
        self.assertEqual(record["agreement_adjustment"], 20)

    def test_validated_exception_reduces_risk(self) -> None:
        """A completed false-positive review reduces the score."""
        record = self.risk_records(
            [
                self.evidence("identity"),
                self.evidence(
                    "endpoint",
                    validated_exception=True,
                ),
            ]
        )[0]

        self.assertEqual(record["exception_adjustment"], -15)
        self.assertEqual(
            record["calculation"]["validated_exceptions"],
            1,
        )

    def test_unreviewed_finding_is_not_an_exception(self) -> None:
        """Only a completed false-positive review reduces risk."""
        self.assertFalse(is_false_positive("New", "False Positive"))
        self.assertTrue(is_false_positive("Closed", "False Positive"))
        self.assertTrue(
            is_false_positive("False Positive", "False Positive")
        )

    def test_time_decay_reduces_older_evidence(self) -> None:
        """Older evidence receives the configured time decay."""
        recent = self.risk_records(
            [self.evidence("identity")]
        )[0]
        old = self.risk_records(
            [
                self.evidence(
                    "identity",
                    event_time="2026-09-14T07:30:00+00:00",
                )
            ]
        )[0]

        self.assertEqual(recent["decay_adjustment"], 0)
        self.assertEqual(old["decay_adjustment"], -10)
        self.assertLess(old["risk_score"], recent["risk_score"])

    def test_unknown_criticality_adds_no_points(self) -> None:
        """Unknown asset criticality is not silently treated as low."""
        record = self.risk_records(
            [self.evidence("access_policy", criticality="unknown")]
        )[0]

        self.assertEqual(record["asset_criticality_component"], 0)

    def test_scores_preserve_evidence_and_duplicate_safe_history(self) -> None:
        """Current scores retain evidence and history is duplicate-safe."""
        records = self.risk_records(
            [self.evidence("identity"), self.evidence("network")]
        )
        first = save_risk_scores(
            self.database_path,
            "cycle-one",
            records,
        )
        second = save_risk_scores(
            self.database_path,
            "cycle-one",
            records,
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    original_evidence_preserved,
                    evidence,
                    evidence_refs
                FROM v2_continuous_risk_scores
                """
            ).fetchone()
            history_count = connection.execute(
                "SELECT COUNT(*) FROM v2_continuous_risk_history"
            ).fetchone()[0]

        self.assertEqual(first["history_new"], 1)
        self.assertEqual(second["history_existing"], 1)
        self.assertEqual(history_count, 1)
        self.assertEqual(row[0], 1)
        self.assertEqual(len(json.loads(row[1])), 2)
        self.assertEqual(len(json.loads(row[2])), 2)

    def test_threshold_and_escalation_alerts(self) -> None:
        """Configured thresholds create High or Critical alerts."""
        high_record = self.risk_records(
            [self.evidence("identity")]
        )[0]
        critical_record = dict(high_record)
        critical_record["entity_id"] = "critical-user"
        critical_record["risk_score"] = 90
        critical_record["risk_level"] = "Critical"

        alerts = build_risk_alerts(
            [high_record, critical_record],
            self.configuration,
        )

        self.assertEqual(
            {alert["alert_type"] for alert in alerts},
            {"risk_threshold", "risk_escalation"},
        )

    def test_alert_cooldown_suppresses_duplicate_detection(self) -> None:
        """A repeated alert is suppressed during its cooldown."""
        records = self.risk_records(
            [
                self.evidence("identity"),
                self.evidence("network"),
            ]
        )
        alerts = build_risk_alerts(records, self.configuration)
        first = save_risk_alerts(
            self.database_path,
            alerts,
            self.configuration,
            self.assessed_at,
        )
        second = save_risk_alerts(
            self.database_path,
            alerts,
            self.configuration,
            "2026-09-17T08:15:00+00:00",
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            row = connection.execute(
                """
                SELECT status, occurrence_count, suppression_reason
                FROM v2_monitoring_alerts
                """
            ).fetchone()

        self.assertEqual(first["created"], 1)
        self.assertEqual(second["suppressed"], 1)
        self.assertEqual(row, ("Suppressed", 2, "active_cooldown"))

    def test_resolved_risk_alert_is_closed(self) -> None:
        """A score below the threshold closes its active risk alert."""
        high = self.risk_records(
            [
                self.evidence("identity"),
                self.evidence("network"),
            ]
        )
        alerts = build_risk_alerts(high, self.configuration)
        save_risk_alerts(
            self.database_path,
            alerts,
            self.configuration,
            self.assessed_at,
        )
        low = [dict(high[0])]
        low[0]["risk_score"] = 20
        low[0]["risk_level"] = "Low"

        closed = close_resolved_risk_alerts(
            self.database_path,
            low,
            self.configuration,
            "2026-09-17T09:00:00+00:00",
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            status = connection.execute(
                "SELECT status FROM v2_monitoring_alerts"
            ).fetchone()[0]

        self.assertEqual(closed, 1)
        self.assertEqual(status, "Closed")

    def test_component_health_tracks_success(self) -> None:
        """All seven populated components report healthy status."""
        health = evaluate_component_health(
            self.database_path,
            self.assessed_at,
            4,
        )
        first = save_component_health(
            self.database_path,
            "cycle-health",
            self.assessed_at,
            health,
        )
        second = save_component_health(
            self.database_path,
            "cycle-health",
            self.assessed_at,
            health,
        )

        self.assertEqual(len(health), 7)
        self.assertEqual(
            {result["status"] for result in health.values()},
            {"healthy"},
        )
        self.assertEqual(first["created"], 7)
        self.assertEqual(second["existing"], 7)

    def test_health_and_pipeline_failures_create_alerts(self) -> None:
        """Persistent degradation and pipeline failure are alertable."""
        results = {
            "endpoint_detection": {
                "status": "degraded",
                "last_successful_run": None,
                "consecutive_failures": 2,
                "records_processed": 0,
                "details": {"records_available": 0},
            },
            "ingestion": {
                "status": "failed",
                "last_successful_run": None,
                "consecutive_failures": 1,
                "records_processed": 0,
                "details": {"failed_batches": 1},
            },
        }
        alerts = build_health_alerts(results, self.configuration)
        direct_failure = build_pipeline_failure_alert(
            "cycle-failed",
            "risk_assessment",
            RuntimeError("controlled failure"),
        )

        self.assertEqual(
            {alert["alert_type"] for alert in alerts},
            {"detection_health", "pipeline_failure"},
        )
        self.assertEqual(
            direct_failure["alert_type"],
            "pipeline_failure",
        )
        self.assertFalse(
            direct_failure["evidence"]["real_action_executed"]
        )

    def test_cycle_suppression_and_last_successful_run(self) -> None:
        """One interval runs once unless a controlled repeat is forced."""
        started = start_cycle(
            self.database_path,
            "cycle-scheduled",
            "2026-09-17T08:00:00+00:00",
            self.assessed_at,
            False,
        )
        repeated = start_cycle(
            self.database_path,
            "cycle-scheduled",
            "2026-09-17T08:00:00+00:00",
            self.assessed_at,
            False,
        )
        health = evaluate_component_health(
            self.database_path,
            self.assessed_at,
            4,
        )
        status = complete_cycle(
            self.database_path,
            "cycle-scheduled",
            "2026-09-17T08:01:00+00:00",
            health,
            10,
            4,
            1,
            0,
            {"controlled_test": True},
        )

        with closing(
            sqlite3.connect(self.database_path)
        ) as connection:
            row = connection.execute(
                """
                SELECT status, last_successful_run, metrics
                FROM v2_monitoring_cycles
                """
            ).fetchone()

        self.assertTrue(started)
        self.assertFalse(repeated)
        self.assertEqual(status, "completed")
        self.assertEqual(
            row[1],
            "2026-09-17T08:01:00+00:00",
        )
        self.assertEqual(
            json.loads(row[2]),
            {"controlled_test": True},
        )


if __name__ == "__main__":
    unittest.main()
