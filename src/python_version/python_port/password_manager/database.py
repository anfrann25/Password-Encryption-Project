"""
SQLite persistence layer, ported from the free functions defined at the
top of the original ``src/main.cpp`` (``createTable``, ``insertUser``,
``RemoveUser``, ``loadUsers``, ``clearTable``).

Schema compatibility
---------------------
The table/column names below are kept **identical** to the C++ version on
purpose, so that a ``database.db`` file created by either implementation
can be read by the other:

.. code-block:: sql

    CREATE TABLE IF NOT EXISTS Records (
        ID       INTEGER PRIMARY KEY AUTOINCREMENT,
        Password TEXT NOT NULL,   -- actually stores the binary "key"
        Decimal  TEXT NOT NULL    -- actually stores the plain-text password
    );

Note the naming is swapped from what you'd expect: the ``Password`` column
holds the randomly generated binary key, and the ``Decimal`` column holds
the actual password text. This mirrors a naming inconsistency already
present in the original C++ code (see ``insertUser`` in ``main.cpp``,
which is called as ``insertUser(DB, p.getKey(), p.getPass())``). It is
preserved here purely for on-disk compatibility with existing
``database.db`` files; the Python-side field names (:class:`.models.Password`
``key`` / ``password``) are named correctly.
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

    Equivalent to ``sqlite3_open`` / ``sqlite3_close`` in ``main.cpp``,
    wrapped as a context manager for safe cleanup (including on errors),
    which the original C++ ``main()`` did not guarantee.

    Args:
        path: Filesystem path to the SQLite database file. Defaults to
            ``"database.db"``, same as the original.

    Yields:
        An open :class:`sqlite3.Connection`.
    """
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


def create_table(connection: sqlite3.Connection) -> None:
    """Create the ``Records`` table if it does not already exist.

    Ported from ``createTable(sqlite3* db)``.
    """
    try:
        connection.execute(CREATE_TABLE_SQL)
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to create table: {exc}")


def insert_user(connection: sqlite3.Connection, key: str, password: str) -> None:
    """Insert one ``(key, password)`` pair as a new row.

    Ported from ``insertUser(sqlite3* db, const string& key, const string& pass)``.
    Note the column mapping described in the module docstring: ``key`` is
    stored in the ``Password`` column and ``password`` in the ``Decimal``
    column, matching the original.

    Args:
        connection: Open database connection.
        key: The binary key string (``Password.key``).
        password: The plain-text password (``Password.password``).
    """
    try:
        connection.execute(
            "INSERT INTO Records (Password, Decimal) VALUES (?, ?);",
            (key, password),
        )
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to insert data: {exc}")


def remove_user(
    connection: sqlite3.Connection, entries: List[Password], entry: Password
) -> None:
    """Delete ``entry`` from both the database and the in-memory list.

    Ported from ``RemoveUser(sqlite3* db, vector<Password>& vectorPass, Password& p)``.

    .. note:: **Deliberate bug fix.** The original C++ ran
        ``DELETE FROM Records WHERE Password = ?`` bound to ``p.getPass()``
        (the password text). Because the ``Password`` column actually
        stores the *key* (see the module docstring), that condition could
        never match, so the C++ version silently failed to delete rows
        from the database, even though it removed the entry from the
        in-memory vector and printed a success message. This Python port
        fixes the query to compare against ``Decimal`` (the column that
        really holds the password) so deletion actually works on disk.
        This is listed in the README under "Differences from the
        original".

    Args:
        connection: Open database connection.
        entries: The in-memory list of entries to remove ``entry`` from.
        entry: The entry to remove.
    """
    try:
        connection.execute(
            "DELETE FROM Records WHERE Decimal = ?;", (entry.password,)
        )
        connection.commit()
        print(f"{entry.password} Removed")
    except sqlite3.Error as exc:
        print(f"Failed to delete user: {exc}")

    if entry in entries:
        entries.remove(entry)
        if not entries:
            print("Database is empty now!")


def load_users(connection: sqlite3.Connection) -> List[Password]:
    """Load every row from ``Records`` into a list of :class:`Password`.

    Ported from ``loadUsers(sqlite3* db, vector<Password>& vectorPass)``.

    Returns:
        A list of :class:`Password` entries, one per row, in insertion
        order.
    """
    entries: List[Password] = []
    try:
        cursor = connection.execute("SELECT Password, Decimal FROM Records;")
        for key_value, password_value in cursor.fetchall():
            if key_value is not None and password_value is not None:
                entries.append(Password(key=key_value, password=password_value))
    except sqlite3.Error as exc:
        print(f"Failed to prepare statement: {exc}")
    return entries


def clear_table(connection: sqlite3.Connection) -> None:
    """Delete every row from ``Records``.

    Ported from ``clearTable(sqlite3* db)``. Used before re-writing the
    full in-memory list back to disk on exit (see :mod:`.cli`).
    """
    try:
        connection.execute("DELETE FROM Records;")
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to clear table: {exc}")
