"""Test explicit SQLite transaction and close handling."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.utils.sqlite_connection import managed_connection


class SQLiteConnectionTests(unittest.TestCase):
    """Verify commit, rollback and explicit closing."""

    def test_successful_transaction_is_committed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            with managed_connection(database_path) as connection:
                connection.execute(
                    "CREATE TABLE records (value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO records (value) VALUES ('saved')"
                )

            with managed_connection(database_path) as connection:
                value = connection.execute(
                    "SELECT value FROM records"
                ).fetchone()[0]

        self.assertEqual(value, "saved")

    def test_failed_transaction_is_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            with managed_connection(database_path) as connection:
                connection.execute(
                    "CREATE TABLE records (value TEXT NOT NULL)"
                )

            with self.assertRaises(RuntimeError):
                with managed_connection(
                    database_path
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO records (value)
                        VALUES ('not-saved')
                        """
                    )
                    raise RuntimeError("Controlled test failure")

            with managed_connection(database_path) as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM records"
                ).fetchone()[0]

        self.assertEqual(count, 0)

    def test_connection_is_closed_after_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.db"

            with managed_connection(database_path) as connection:
                connection.execute(
                    "CREATE TABLE records (value TEXT NOT NULL)"
                )

            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
