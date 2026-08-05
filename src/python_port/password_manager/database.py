"""
SQLite persistence layer.

.. note:: **v2 change.** The table/column names are kept identical to the
    original C++ project's schema for continuity, but what they *hold*
    changed along with :mod:`.models`: the ``Decimal`` column now stores
    real ciphertext (hex-encoded) instead of a plain-text password.

.. code-block:: sql

    CREATE TABLE IF NOT EXISTS Records (
        ID       INTEGER PRIMARY KEY AUTOINCREMENT,
        Password TEXT NOT NULL,   -- binary pattern / encryption key
        Decimal  TEXT NOT NULL    -- hex-encoded ciphertext
    );

.. warning:: **Not compatible with v1 / original C++ databases.** A
    ``database.db`` created by v1 of this port (or by the original C++
    binary) stores a *plain-text* password in the ``Decimal`` column. This
    version will try to hex-decode and decrypt that text, which will fail
    (or silently produce garbage) since it isn't valid ciphertext. Start
    from a fresh database file when switching to this version -- see the
    README's "Migrating from v1" note.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List

from .models import Password

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS Records (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Password TEXT NOT NULL,
    Decimal TEXT NOT NULL
);
"""


@contextmanager
def open_database(path: str = "database.db") -> Iterator[sqlite3.Connection]:
    """Open the SQLite database at ``path``, closing it automatically.

    Args:
        path: Filesystem path to the SQLite database file. Defaults to
            ``"database.db"``.

    Yields:
        An open :class:`sqlite3.Connection`.
    """
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


def create_table(connection: sqlite3.Connection) -> None:
    """Create the ``Records`` table if it does not already exist."""
    try:
        connection.execute(CREATE_TABLE_SQL)
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to create table: {exc}")


def insert_user(connection: sqlite3.Connection, key: str, ciphertext_hex: str) -> None:
    """Insert one ``(key, ciphertext)`` pair as a new row.

    Args:
        connection: Open database connection.
        key: The binary encryption pattern (``Password.key``).
        ciphertext_hex: The hex-encoded ciphertext (``Password.ciphertext``).
    """
    try:
        connection.execute(
            "INSERT INTO Records (Password, Decimal) VALUES (?, ?);",
            (key, ciphertext_hex),
        )
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to insert data: {exc}")


def remove_user(
    connection: sqlite3.Connection, entries: List[Password], entry: Password
) -> None:
    """Delete `entry` from both the database and the in-memory list.

    Matches on both `key` and `ciphertext` together, since neither alone
    is guaranteed unique (e.g. two entries could coincidentally share a
    pattern).

    Args:
        connection: Open database connection.
        entries: The in-memory list of entries to remove `entry` from.
        entry: The entry to remove.
    """
    try:
        connection.execute(
            "DELETE FROM Records WHERE Password = ? AND Decimal = ?;",
            (entry.key, entry.ciphertext),
        )
        connection.commit()
        print(f"Entry (Key: {entry.key}) removed")
    except sqlite3.Error as exc:
        print(f"Failed to delete user: {exc}")

    if entry in entries:
        entries.remove(entry)
        if not entries:
            print("Database is empty now!")


def load_users(connection: sqlite3.Connection) -> List[Password]:
    """Load every row from ``Records`` into a list of :class:`Password`.

    Returns:
        A list of :class:`Password` entries, one per row, in insertion
        order.
    """
    entries: List[Password] = []
    try:
        cursor = connection.execute("SELECT Password, Decimal FROM Records;")
        for key_value, ciphertext_value in cursor.fetchall():
            if key_value is not None and ciphertext_value is not None:
                entries.append(Password(key=key_value, ciphertext=ciphertext_value))
    except sqlite3.Error as exc:
        print(f"Failed to prepare statement: {exc}")
    return entries


def clear_table(connection: sqlite3.Connection) -> None:
    """Delete every row from ``Records``."""
    try:
        connection.execute("DELETE FROM Records;")
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to clear table: {exc}")
