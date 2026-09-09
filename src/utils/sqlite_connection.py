"""Provide SQLite connections with transaction and close handling."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


@contextmanager
def managed_connection(
    database: str | Path,
    *args: Any,
    **kwargs: Any,
) -> Iterator[sqlite3.Connection]:
    """Yield a transactional SQLite connection and always close it."""
    connection = sqlite3.connect(
        database,
        *args,
        **kwargs,
    )

    try:
        with connection:
            yield connection
    finally:
        connection.close()
