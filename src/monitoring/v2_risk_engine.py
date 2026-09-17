"""Calculate and store Phase 3A V2 Stage 9 risk scores."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.monitoring.v2_risk_sources import (
    Evidence,
    parse_time,
)
from src.utils.sqlite_connection import managed_connection


RiskRecord = dict[str, Any]


def stable_key(prefix: str, *parts: object) -> str:
    """Return a deterministic SHA-256 key."""
    material = "|".join(
        [
            prefix,
            *(str(part) for part in parts),
        ]
    )
    digest = hashlib.sha256(
        material.encode()
    ).hexdigest()

    return f"{prefix}-{digest}"


def json_text(value: object) -> str:
    """Return compact deterministic JSON."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def risk_level(
    score: float,
    thresholds: dict[str, int],
) -> str:
    """Return the configured risk level for a score."""
    for level in (
        "Critical",
        "High",
        "Medium",
        "Low",
    ):
        if score >= thresholds[level]:
            return level

    return "Low"


def decay_adjustment(
    latest_evidence: datetime,
    assessed_at: datetime,
    grace_hours: int,
    points_per_day: int,
) -> tuple[float, int]:
    """Return a non-positive time-decay adjustment and age."""
    age_hours = max(
        0.0,
        (
            assessed_at - latest_evidence
        ).total_seconds()
        / 3600,
    )

    if age_hours <= grace_hours:
        return 0.0, round(age_hours)

    decay_days = (
        int(
            (
                age_hours
                - grace_hours
                - 1
            )
            // 24
        )
        + 1
    )

    return (
        -(decay_days * points_per_day),
        round(age_hours),
    )


def calculate_risk_scores(
    evidence: list[Evidence],
    configuration: dict[str, Any],
    assessed_at: str,
) -> list[RiskRecord]:
    """Calculate entity risk without replacing source evidence."""
    assessment_time = parse_time(assessed_at)
    scoring = configuration["risk_scoring"]
    weights = scoring["weights"]
    severity_values = scoring["severity_values"]
    criticality_values = scoring[
        "asset_criticality_values"
    ]
    agreement = scoring[
        "independent_source_agreement"
    ]
    exceptions = scoring[
        "validated_exception_reduction"
    ]
    decay = scoring["time_decay"]

    grouped: dict[
        tuple[str, str],
        list[Evidence],
    ] = defaultdict(list)

    for item in evidence:
        grouped[
            (
                item["entity_type"],
                item["entity_id"],
            )
        ].append(item)

    records: list[RiskRecord] = []

    for (
        entity_type,
        entity_id,
    ), items in sorted(grouped.items()):
        active = [
            item
            for item in items
            if not item[
                "validated_exception"
            ]
        ]
        reviewed_exceptions = [
            item
            for item in items
            if item[
                "validated_exception"
            ]
        ]

        severity_value = max(
            (
                severity_values[
                    item["severity"]
                ]
                for item in active
            ),
            default=0,
        )
        confidence_value = max(
            (
                item["confidence"]
                for item in active
            ),
            default=0,
        )
        criticality_value = max(
            (
                criticality_values[
                    item[
                        "asset_criticality"
                    ]
                ]
                for item in active
            ),
            default=0,
        )

        severity_component = round(
            severity_value
            * weights["severity"]
            / 100,
            2,
        )
        confidence_component = round(
            confidence_value
            * weights["confidence"]
            / 100,
            2,
        )
        criticality_component = round(
            criticality_value
            * weights[
                "asset_criticality"
            ]
            / 100,
            2,
        )

        source_types = sorted(
            {
                item["source_type"]
                for item in active
            }
        )
        source_count = len(source_types)

        if (
            source_count
            >= agreement[
                "minimum_sources"
            ]
        ):
            qualifying_sources = (
                source_count
                - agreement[
                    "minimum_sources"
                ]
                + 1
            )
            agreement_points = min(
                agreement[
                    "maximum_increase"
                ],
                qualifying_sources
                * agreement[
                    "points_per_additional_source"
                ],
            )
        else:
            agreement_points = 0

        exception_points = -min(
            exceptions[
                "maximum_reduction"
            ],
            len(reviewed_exceptions)
            * exceptions[
                "points_per_exception"
            ],
        )

        time_evidence = active or items
        latest_evidence = max(
            parse_time(
                item["event_time"]
            )
            for item in time_evidence
        )
        (
            decay_points,
            age_hours,
        ) = decay_adjustment(
            latest_evidence,
            assessment_time,
            decay[
                "grace_period_hours"
            ],
            decay[
                "points_per_24_hours"
            ],
        )

        unclamped_score = (
            severity_component
            + confidence_component
            + criticality_component
            + agreement_points
            + exception_points
            + decay_points
        )
        score = round(
            max(
                scoring[
                    "scale"
                ][
                    "minimum"
                ],
                min(
                    scoring[
                        "scale"
                    ][
                        "maximum"
                    ],
                    unclamped_score,
                ),
            ),
            2,
        )

        evidence_refs = sorted(
            {
                reference
                for item in items
                for reference in item[
                    "evidence_refs"
                ]
            }
        )
        calculation = {
            "severity_component": (
                severity_component
            ),
            "confidence_component": (
                confidence_component
            ),
            "asset_criticality_component": (
                criticality_component
            ),
            "agreement_adjustment": (
                agreement_points
            ),
            "exception_adjustment": (
                exception_points
            ),
            "decay_adjustment": (
                decay_points
            ),
            "validated_exceptions": len(
                reviewed_exceptions
            ),
            "age_hours": age_hours,
        }

        records.append(
            {
                "risk_key": stable_key(
                    "v2-risk",
                    entity_type,
                    entity_id,
                ),
                "entity_type": entity_type,
                "entity_id": entity_id,
                "assessed_at": assessed_at,
                "risk_score": score,
                "risk_level": risk_level(
                    score,
                    scoring[
                        "risk_thresholds"
                    ],
                ),
                "severity_component": (
                    severity_component
                ),
                "confidence_component": (
                    confidence_component
                ),
                "asset_criticality_component": (
                    criticality_component
                ),
                "agreement_adjustment": (
                    agreement_points
                ),
                "exception_adjustment": (
                    exception_points
                ),
                "decay_adjustment": (
                    decay_points
                ),
                "independent_source_count": (
                    source_count
                ),
                "source_types": source_types,
                "evidence_refs": (
                    evidence_refs
                ),
                "evidence": items,
                "last_evidence_time": (
                    latest_evidence.isoformat()
                ),
                "calculation": calculation,
            }
        )

    return records


def change_reason(
    previous_score: float | None,
    record: RiskRecord,
) -> str:
    """Explain the current score and its change."""
    reasons: list[str] = []

    if record["agreement_adjustment"]:
        reasons.append(
            "independent_source_agreement"
        )

    if record["exception_adjustment"]:
        reasons.append(
            "validated_exception_reduction"
        )

    if record["decay_adjustment"]:
        reasons.append(
            "time_based_decay"
        )

    if previous_score is None:
        reasons.append(
            "initial_assessment"
        )
    elif (
        record["risk_score"]
        > previous_score
    ):
        reasons.append(
            "risk_increased"
        )
    elif (
        record["risk_score"]
        < previous_score
    ):
        reasons.append(
            "risk_reduced"
        )
    else:
        reasons.append(
            "risk_unchanged"
        )

    return ",".join(reasons)


def save_risk_scores(
    database_path: Path,
    cycle_key: str,
    records: list[RiskRecord],
) -> dict[str, int]:
    """Upsert current scores and preserve cycle history."""
    counts = {
        "current_new": 0,
        "current_updated": 0,
        "history_new": 0,
        "history_existing": 0,
    }

    with managed_connection(
        database_path
    ) as connection:
        for record in records:
            previous = connection.execute(
                """
                SELECT
                    risk_score,
                    risk_level
                FROM v2_continuous_risk_scores
                WHERE risk_key = ?
                """,
                (
                    record["risk_key"],
                ),
            ).fetchone()

            history_key = stable_key(
                "v2-risk-history",
                cycle_key,
                record["entity_type"],
                record["entity_id"],
            )
            history_cursor = (
                connection.execute(
                    """
                    INSERT OR IGNORE INTO
                        v2_continuous_risk_history (
                            history_key,
                            cycle_key,
                            entity_type,
                            entity_id,
                            assessed_at,
                            previous_score,
                            new_score,
                            previous_level,
                            new_level,
                            change_reason,
                            source_types,
                            evidence_refs,
                            calculation
                        )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        history_key,
                        cycle_key,
                        record[
                            "entity_type"
                        ],
                        record[
                            "entity_id"
                        ],
                        record[
                            "assessed_at"
                        ],
                        (
                            previous[0]
                            if previous
                            else None
                        ),
                        record[
                            "risk_score"
                        ],
                        (
                            previous[1]
                            if previous
                            else None
                        ),
                        record[
                            "risk_level"
                        ],
                        change_reason(
                            (
                                previous[0]
                                if previous
                                else None
                            ),
                            record,
                        ),
                        json_text(
                            record[
                                "source_types"
                            ]
                        ),
                        json_text(
                            record[
                                "evidence_refs"
                            ]
                        ),
                        json_text(
                            record[
                                "calculation"
                            ]
                        ),
                    ),
                )
            )

            if (
                history_cursor.rowcount
                == 1
            ):
                counts[
                    "history_new"
                ] += 1
            else:
                counts[
                    "history_existing"
                ] += 1

            connection.execute(
                """
                INSERT INTO
                    v2_continuous_risk_scores (
                        risk_key,
                        entity_type,
                        entity_id,
                        assessed_at,
                        risk_score,
                        risk_level,
                        severity_component,
                        confidence_component,
                        asset_criticality_component,
                        agreement_adjustment,
                        exception_adjustment,
                        decay_adjustment,
                        independent_source_count,
                        source_types,
                        evidence_refs,
                        evidence,
                        last_evidence_time,
                        original_evidence_preserved
                    )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, 1
                )
                ON CONFLICT(risk_key)
                DO UPDATE SET
                    assessed_at =
                        excluded.assessed_at,
                    risk_score =
                        excluded.risk_score,
                    risk_level =
                        excluded.risk_level,
                    severity_component =
                        excluded.severity_component,
                    confidence_component =
                        excluded.confidence_component,
                    asset_criticality_component =
                        excluded.asset_criticality_component,
                    agreement_adjustment =
                        excluded.agreement_adjustment,
                    exception_adjustment =
                        excluded.exception_adjustment,
                    decay_adjustment =
                        excluded.decay_adjustment,
                    independent_source_count =
                        excluded.independent_source_count,
                    source_types =
                        excluded.source_types,
                    evidence_refs =
                        excluded.evidence_refs,
                    evidence =
                        excluded.evidence,
                    last_evidence_time =
                        excluded.last_evidence_time
                """,
                (
                    record["risk_key"],
                    record["entity_type"],
                    record["entity_id"],
                    record["assessed_at"],
                    record["risk_score"],
                    record["risk_level"],
                    record[
                        "severity_component"
                    ],
                    record[
                        "confidence_component"
                    ],
                    record[
                        "asset_criticality_component"
                    ],
                    record[
                        "agreement_adjustment"
                    ],
                    record[
                        "exception_adjustment"
                    ],
                    record[
                        "decay_adjustment"
                    ],
                    record[
                        "independent_source_count"
                    ],
                    json_text(
                        record["source_types"]
                    ),
                    json_text(
                        record["evidence_refs"]
                    ),
                    json_text(
                        record["evidence"]
                    ),
                    record[
                        "last_evidence_time"
                    ],
                ),
            )

            if previous:
                counts[
                    "current_updated"
                ] += 1
            else:
                counts[
                    "current_new"
                ] += 1

    return counts


def build_risk_alerts(
    records: list[RiskRecord],
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build threshold and escalation alerts."""
    alerting = configuration["alerting"]
    alerts: list[dict[str, Any]] = []

    for record in records:
        score = record["risk_score"]

        if (
            score
            < alerting[
                "risk_alert_threshold"
            ]
        ):
            continue

        if (
            score
            >= alerting[
                "escalation_threshold"
            ]
        ):
            alert_type = (
                "risk_escalation"
            )
            severity = "Critical"
            threshold = alerting[
                "escalation_threshold"
            ]
        else:
            alert_type = (
                "risk_threshold"
            )
            severity = "High"
            threshold = alerting[
                "risk_alert_threshold"
            ]

        alerts.append(
            {
                "alert_key": stable_key(
                    "v2-monitoring-alert",
                    alert_type,
                    record[
                        "entity_type"
                    ],
                    record[
                        "entity_id"
                    ],
                ),
                "alert_type": alert_type,
                "entity_type": record[
                    "entity_type"
                ],
                "entity_id": record[
                    "entity_id"
                ],
                "component": (
                    "risk_assessment"
                ),
                "risk_score": score,
                "threshold": threshold,
                "severity": severity,
                "independent_source_count": (
                    record[
                        "independent_source_count"
                    ]
                ),
                "source_types": record[
                    "source_types"
                ],
                "evidence_refs": record[
                    "evidence_refs"
                ],
                "evidence": {
                    "risk_key": record[
                        "risk_key"
                    ],
                    "risk_level": record[
                        "risk_level"
                    ],
                    "calculation": record[
                        "calculation"
                    ],
                },
            }
        )

    return alerts


def save_risk_alerts(
    database_path: Path,
    alerts: list[dict[str, Any]],
    configuration: dict[str, Any],
    observed_at: str,
) -> dict[str, int]:
    """Store alerts and suppress repeats during cooldown."""
    observed_time = parse_time(
        observed_at
    )
    cooldown = timedelta(
        minutes=configuration[
            "alerting"
        ][
            "cooldown_minutes"
        ]
    )
    counts = {
        "created": 0,
        "existing": 0,
        "suppressed": 0,
    }

    with managed_connection(
        database_path
    ) as connection:
        for alert in alerts:
            existing = connection.execute(
                """
                SELECT
                    cooldown_until,
                    evidence_refs,
                    occurrence_count
                FROM v2_monitoring_alerts
                WHERE alert_key = ?
                """,
                (
                    alert["alert_key"],
                ),
            ).fetchone()

            next_cooldown = (
                observed_time + cooldown
            ).isoformat()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO
                        v2_monitoring_alerts (
                            alert_key,
                            alert_type,
                            created_at,
                            last_observed_at,
                            entity_type,
                            entity_id,
                            component,
                            risk_score,
                            threshold,
                            severity,
                            status,
                            cooldown_until,
                            occurrence_count,
                            independent_source_count,
                            source_types,
                            evidence_refs,
                            evidence
                        )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, 'New', ?, 1,
                        ?, ?, ?, ?
                    )
                    """,
                    (
                        alert[
                            "alert_key"
                        ],
                        alert[
                            "alert_type"
                        ],
                        observed_at,
                        observed_at,
                        alert[
                            "entity_type"
                        ],
                        alert[
                            "entity_id"
                        ],
                        alert[
                            "component"
                        ],
                        alert[
                            "risk_score"
                        ],
                        alert[
                            "threshold"
                        ],
                        alert[
                            "severity"
                        ],
                        next_cooldown,
                        alert[
                            "independent_source_count"
                        ],
                        json_text(
                            alert[
                                "source_types"
                            ]
                        ),
                        json_text(
                            alert[
                                "evidence_refs"
                            ]
                        ),
                        json_text(
                            alert[
                                "evidence"
                            ]
                        ),
                    ),
                )
                counts["created"] += 1
                continue

            old_cooldown = (
                parse_time(existing[0])
                if existing[0]
                else datetime.min.replace(
                    tzinfo=timezone.utc
                )
            )
            in_cooldown = (
                configuration[
                    "alerting"
                ][
                    "suppress_during_cooldown"
                ]
                and observed_time
                <= old_cooldown
            )
            combined_refs = sorted(
                set(
                    json.loads(
                        existing[1]
                    )
                )
                | set(
                    alert[
                        "evidence_refs"
                    ]
                )
            )

            if in_cooldown:
                status = "Suppressed"
                suppression_reason = (
                    "active_cooldown"
                )
                cooldown_until = existing[0]
                counts[
                    "suppressed"
                ] += 1
            else:
                status = "Monitoring"
                suppression_reason = None
                cooldown_until = (
                    next_cooldown
                )
                counts[
                    "existing"
                ] += 1

            connection.execute(
                """
                UPDATE v2_monitoring_alerts
                SET last_observed_at = ?,
                    risk_score = ?,
                    threshold = ?,
                    severity = ?,
                    status = ?,
                    cooldown_until = ?,
                    suppression_reason = ?,
                    occurrence_count = ?,
                    independent_source_count = ?,
                    source_types = ?,
                    evidence_refs = ?,
                    evidence = ?
                WHERE alert_key = ?
                """,
                (
                    observed_at,
                    alert[
                        "risk_score"
                    ],
                    alert[
                        "threshold"
                    ],
                    alert[
                        "severity"
                    ],
                    status,
                    cooldown_until,
                    suppression_reason,
                    existing[2] + 1,
                    alert[
                        "independent_source_count"
                    ],
                    json_text(
                        alert[
                            "source_types"
                        ]
                    ),
                    json_text(
                        combined_refs
                    ),
                    json_text(
                        alert[
                            "evidence"
                        ]
                    ),
                    alert[
                        "alert_key"
                    ],
                ),
            )

    return counts


def close_resolved_risk_alerts(
    database_path: Path,
    records: list[RiskRecord],
    configuration: dict[str, Any],
    closed_at: str,
) -> int:
    """Close alerts when current risk falls below High."""
    threshold = configuration[
        "alerting"
    ][
        "risk_alert_threshold"
    ]
    resolved = {
        (
            record["entity_type"],
            record["entity_id"],
        )
        for record in records
        if record["risk_score"] < threshold
    }
    closed = 0

    with managed_connection(
        database_path
    ) as connection:
        for (
            entity_type,
            entity_id,
        ) in resolved:
            cursor = connection.execute(
                """
                UPDATE v2_monitoring_alerts
                SET status = 'Closed',
                    last_observed_at = ?,
                    suppression_reason =
                        'risk_below_threshold'
                WHERE entity_type = ?
                  AND entity_id = ?
                  AND alert_type IN (
                      'risk_threshold',
                      'risk_escalation'
                  )
                  AND status != 'Closed'
                """,
                (
                    closed_at,
                    entity_type,
                    entity_id,
                ),
            )
            closed += cursor.rowcount

    return closed
