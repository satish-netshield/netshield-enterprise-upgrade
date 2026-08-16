"""Create the Stage 1 database and preserve security audit events."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def initialise_database(database_path: Path, schema_path: Path) -> None:
    """Create the database using the tracked SQL schema."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    schema = schema_path.read_text(encoding="utf-8")

    with sqlite3.connect(database_path) as connection:
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
    event_time = datetime.now(timezone.utc).isoformat()

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
            (event_time, actor, action, target, result, details),
        )
