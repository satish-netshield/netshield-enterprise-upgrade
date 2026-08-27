"""Isolated local SQL injection demonstration application."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LAB_ROOT = Path(__file__).resolve().parent
DATABASE_PATH = LAB_ROOT / "data" / "sql_injection_lab.db"
LOG_PATH = LAB_ROOT / "logs" / "application_events.jsonl"

SUSPICIOUS_PATTERNS = (
    r"'(\s*or|\s*and)\s+\d+\s*=\s*\d+",
    r"\bunion\s+select\b",
    r"\bdrop\s+table\b",
    r"\bdelete\s+from\b",
    r"\binsert\s+into\b",
    r"--",
    r"/\*",
    r"\bexec(?:ute)?\b",
)


@dataclass
class QueryResult:
    """Result returned by a login query."""

    authenticated: bool
    rows: list[dict[str, Any]]
    error: str | None
    query_mode: str


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def initialise_database(
    database_path: Path = DATABASE_PATH,
) -> None:
    """Create the isolated lab database and test account."""
    database_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO users
                (user_id, username, password, role)
            VALUES
                (1, 'analyst01', 'LabPassword-Only', 'analyst')
            """
        )


def record_event(
    *,
    source_ip: str,
    username: str,
    query_mode: str,
    event_type: str,
    result: str,
    details: dict[str, Any],
    log_path: Path = LOG_PATH,
) -> None:
    """Write one structured application security event."""
    log_path.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "event_time": utc_now(),
        "source_ip": source_ip,
        "username": username,
        "query_mode": query_mode,
        "event_type": event_type,
        "result": result,
        "details": details,
    }

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, sort_keys=True) + "\n")


def detect_suspicious_input(value: str) -> list[str]:
    """Return the suspicious SQL patterns found in input."""
    lowered = value.lower()
    matches = []

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, lowered):
            matches.append(pattern)

    return matches


def vulnerable_login(
    username: str,
    password: str,
    *,
    source_ip: str = "127.0.0.1",
    database_path: Path = DATABASE_PATH,
    log_path: Path = LOG_PATH,
) -> QueryResult:
    """Run the deliberately vulnerable concatenated query.

    This function exists only for the isolated local demonstration.
    """
    query = (
        "SELECT user_id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    suspicious_matches = (
        detect_suspicious_input(username)
        + detect_suspicious_input(password)
    )

    try:
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = [
                dict(row)
                for row in connection.execute(query).fetchall()
            ]

        authenticated = bool(rows)
        event_type = (
            "authentication_bypass_attempt"
            if authenticated and suspicious_matches
            else "login_attempt"
        )

        record_event(
            source_ip=source_ip,
            username=username,
            query_mode="vulnerable",
            event_type=event_type,
            result="authenticated" if authenticated else "denied",
            details={
                "suspicious_patterns": suspicious_matches,
                "returned_rows": len(rows),
                "query_behaviour": "string_concatenation",
            },
            log_path=log_path,
        )

        return QueryResult(
            authenticated=authenticated,
            rows=rows,
            error=None,
            query_mode="vulnerable",
        )

    except sqlite3.Error as error:
        record_event(
            source_ip=source_ip,
            username=username,
            query_mode="vulnerable",
            event_type="database_error",
            result="error",
            details={
                "error": str(error),
                "suspicious_patterns": suspicious_matches,
            },
            log_path=log_path,
        )

        return QueryResult(
            authenticated=False,
            rows=[],
            error=str(error),
            query_mode="vulnerable",
        )


def safe_login(
    username: str,
    password: str,
    *,
    source_ip: str = "127.0.0.1",
    database_path: Path = DATABASE_PATH,
    log_path: Path = LOG_PATH,
) -> QueryResult:
    """Run the corrected parameterised login query."""
    query = (
        "SELECT user_id, username, role FROM users "
        "WHERE username = ? AND password = ?"
    )

    suspicious_matches = (
        detect_suspicious_input(username)
        + detect_suspicious_input(password)
    )

    try:
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = [
                dict(row)
                for row in connection.execute(
                    query,
                    (username, password),
                ).fetchall()
            ]

        authenticated = bool(rows)
        event_type = (
            "suspicious_input_blocked"
            if suspicious_matches
            else "login_attempt"
        )

        record_event(
            source_ip=source_ip,
            username=username,
            query_mode="parameterised",
            event_type=event_type,
            result="authenticated" if authenticated else "denied",
            details={
                "suspicious_patterns": suspicious_matches,
                "returned_rows": len(rows),
                "query_behaviour": "bound_parameters",
            },
            log_path=log_path,
        )

        return QueryResult(
            authenticated=authenticated,
            rows=rows,
            error=None,
            query_mode="parameterised",
        )

    except sqlite3.Error as error:
        record_event(
            source_ip=source_ip,
            username=username,
            query_mode="parameterised",
            event_type="database_error",
            result="error",
            details={
                "error": str(error),
                "suspicious_patterns": suspicious_matches,
            },
            log_path=log_path,
        )

        return QueryResult(
            authenticated=False,
            rows=[],
            error=str(error),
            query_mode="parameterised",
        )


if __name__ == "__main__":
    initialise_database()
    print(
        "PASS: SQLite lab database ready at "
        f"{DATABASE_PATH}"
    )
