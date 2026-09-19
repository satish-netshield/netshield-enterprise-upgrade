"""Add explicit unassessed risk storage to Stage 11."""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path

from scripts.initialize_v2_stage11 import TABLES
from src.utils.config_loader import load_json
from src.utils.database import utc_now
from src.utils.sqlite_connection import managed_connection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

OLD_RISK = (
    "risk_score REAL NOT NULL\n"
    "        CHECK (risk_score BETWEEN 0 AND 100),"
)

NEW_RISK = """risk_score REAL
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_record_key TEXT,
    risk_assessed_at TEXT,"""

RISK_CHECK = """,
    CHECK (
        (risk_score IS NULL AND risk_record_key IS NULL
            AND risk_assessed_at IS NULL)
        OR
        (risk_score IS NOT NULL AND risk_record_key IS NOT NULL
            AND length(trim(risk_record_key)) > 0
            AND risk_assessed_at IS NOT NULL
            AND length(trim(risk_assessed_at)) > 0)
    )"""


def corrected_table(sql: str) -> str:
    """Change only the recognised original Stage 11 risk definition."""
    if "risk_record_key" in sql:
        return sql

    if sql.count(OLD_RISK) != 1:
        raise RuntimeError(
            "Unrecognised incident schema; no repair applied"
        )

    sql = sql.replace(OLD_RISK, NEW_RISK, 1)
    end = sql.rfind(")")
    return sql[:end].rstrip() + RISK_CHECK + "\n" + sql[end:]


def main() -> None:
    """Repair empty incident storage and update the tracked schema."""
    settings = load_json(PROJECT_ROOT / "config/settings.json")
    database = PROJECT_ROOT / settings["database"]["path"]
    schema_path = PROJECT_ROOT / "database/schema.sql"
    original = schema_path.read_text(encoding="utf-8")

    match = re.search(
        r"CREATE TABLE IF NOT EXISTS v2_incidents\s*\(.*?;",
        original,
        re.DOTALL,
    )
    if match is None:
        raise RuntimeError(
            "Tracked Stage 11 incident table is missing"
        )

    replacement = corrected_table(match.group())
    updated = (
        original[:match.start()]
        + replacement
        + original[match.end():]
    )

    with closing(sqlite3.connect(":memory:")) as check:
        check.execute("PRAGMA foreign_keys = ON")
        check.executescript(updated)

        if check.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(
                "Tracked schema failed foreign-key validation"
            )

        if check.execute("PRAGMA integrity_check").fetchall() != [
            ("ok",)
        ]:
            raise RuntimeError(
                "Tracked schema failed integrity validation"
            )

    with managed_connection(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='v2_incidents'"
        ).fetchone()
        if row is None:
            raise RuntimeError(
                "Run the Stage 11 foundation migration first"
            )

        desired = corrected_table(row[0])
        repaired = desired != row[0]

        if repaired:
            for table in sorted(TABLES):
                # Names come from the existing migration's fixed set.
                count = connection.execute(
                    f'SELECT COUNT(*) FROM "{table}"'
                ).fetchone()[0]
                if count:
                    raise RuntimeError(
                        "Repair stopped: Stage 11 already contains records"
                    )

            indexes = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' "
                "AND tbl_name='v2_incidents' AND sql IS NOT NULL"
            ).fetchall()

            connection.execute("DROP TABLE v2_incidents")
            connection.execute(desired)

            for index in indexes:
                connection.execute(index[0])

        columns = {
            item[1]: item
            for item in connection.execute(
                "PRAGMA table_info(v2_incidents)"
            )
        }

        if columns["risk_score"][3] != 0:
            raise RuntimeError("Risk score is still NOT NULL")

        if not {
            "risk_record_key",
            "risk_assessed_at",
        } <= columns.keys():
            raise RuntimeError("Risk provenance columns are missing")

        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(
                "Foreign-key validation failed; rolled back"
            )

        if connection.execute("PRAGMA integrity_check").fetchall() != [
            ("ok",)
        ]:
            raise RuntimeError(
                "Integrity validation failed; rolled back"
            )

        connection.execute(
            "INSERT INTO audit_events "
            "(event_time, actor, action, target, result, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                utc_now(),
                "netshield01",
                "initialize_v2_stage11_risk",
                "v2_incidents",
                "success",
                (
                    f"repaired={repaired}; "
                    "unassessed=NULL; risk_provenance=true"
                ),
            ),
        )

    # If this write fails, re-running safely finishes the schema update.
    if updated != original:
        schema_path.write_text(updated, encoding="utf-8")

    print("PASS: Stage 11 unassessed risk storage validated")
    print(
        "Empty incident table repaired: "
        f"{str(repaired).lower()}"
    )
    print("Unassessed risk: NULL (Not yet assessed)")
    print("Risk provenance: risk_record_key and risk_assessed_at")
    print(
        "PASS: Tracked schema updated; "
        "foreign keys and integrity checked"
    )


if __name__ == "__main__":
    main()
