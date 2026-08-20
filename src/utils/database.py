"""Create the NetShield database and preserve security records."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    """Return the current time as an ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def initialise_database(database_path: Path, schema_path: Path) -> None:
    """Create the database using the tracked SQL schema."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    schema = schema_path.read_text(encoding="utf-8")

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema)


def save_metadata(database_path: Path, key: str, value: str) -> None:
    """Create or update a project metadata value."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO system_metadata (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def assign_role(database_path: Path, username: str, role: str) -> None:
    """Create or update a local project-role assignment."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO user_roles (username, role, active)
            VALUES (?, ?, 1)
            ON CONFLICT(username)
            DO UPDATE SET role = excluded.role, active = 1
            """,
            (username, role),
        )


def record_audit_event(
    database_path: Path,
    actor: str,
    action: str,
    target: str,
    result: str,
    details: str = "",
) -> None:
    """Write an immutable-style audit event as a new database row."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO audit_events (
                event_time,
                actor,
                action,
                target,
                result,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                actor,
                action,
                target,
                result,
                details,
            ),
        )


def start_import_batch(
    database_path: Path,
    batch_id: str,
    source_file: str,
    source_type: str,
) -> None:
    """Create an import-batch record before processing starts."""
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO import_batches (
                batch_id,
                started_at,
                source_file,
                source_type,
                status
            )
            VALUES (?, ?, ?, ?, 'started')
            """,
            (
                batch_id,
                utc_now(),
                source_file,
                source_type,
            ),
        )


def complete_import_batch(
    database_path: Path,
    batch_id: str,
    total_records: int,
    accepted_records: int,
    rejected_records: int,
    status: str,
) -> None:
    """Finish an import batch with its processing totals."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE import_batches
            SET completed_at = ?,
                total_records = ?,
                accepted_records = ?,
                rejected_records = ?,
                status = ?
            WHERE batch_id = ?
            """,
            (
                utc_now(),
                total_records,
                accepted_records,
                rejected_records,
                status,
                batch_id,
            ),
        )


def save_security_event(
    database_path: Path,
    event: dict[str, Any],
    source_file: str,
    batch_id: str,
    raw_event: dict[str, Any],
) -> bool:
    """Save a normalised event and return False for a duplicate."""
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO security_events (
                source_event_id,
                event_time,
                received_time,
                source_type,
                event_type,
                username,
                ip_address,
                mac_address,
                hostname,
                process_name,
                cpu_percent,
                location,
                status,
                message,
                source_file,
                batch_id,
                raw_event
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                event["source_event_id"],
                event["event_time"],
                utc_now(),
                event["source_type"],
                event["event_type"],
                event["username"],
                event["ip_address"],
                event["mac_address"],
                event["hostname"],
                event["process_name"],
                event["cpu_percent"],
                event["location"],
                event["status"],
                event["message"],
                source_file,
                batch_id,
                json.dumps(
                    raw_event,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

        return cursor.rowcount == 1


def save_rejected_event(
    database_path: Path,
    source_file: str,
    batch_id: str,
    line_number: int,
    reason: str,
    raw_event: str,
) -> None:
    """Preserve a rejected input record and its failure reason."""
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO rejected_events (
                rejected_at,
                source_file,
                batch_id,
                line_number,
                reason,
                raw_event
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                source_file,
                batch_id,
                line_number,
                reason,
                raw_event,
            ),
        )
