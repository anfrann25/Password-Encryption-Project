"""
SQLite persistence layer.

.. note:: **v3 change.** Two schema changes from v2:

    1. ``Records`` gained a ``Salt`` column: each entry's own random
       per-entry salt (see :mod:`.master`), required alongside the
       master key to decrypt it.
    2. A new single-row ``Settings`` table stores the master-password
       verification material: the PBKDF2 salt, iteration count, and a
       verifier hash (see :mod:`.master`). **The master password itself
       is never stored** -- only enough to check a re-entered password
       derives the same key.

.. note:: **v4 change.** ``Records`` gained a ``Name`` column: a
    user-chosen, non-secret label per entry (e.g. ``"Gmail"``), so
    entries can be told apart in the list without decrypting anything.

.. code-block:: sql

    CREATE TABLE IF NOT EXISTS Records (
        ID       INTEGER PRIMARY KEY AUTOINCREMENT,
        Name     TEXT NOT NULL,   -- user-chosen label, e.g. "Gmail"
        Password TEXT NOT NULL,   -- binary pattern (algorithm selector)
        Salt     TEXT NOT NULL,   -- per-entry salt (hex)
        Decimal  TEXT NOT NULL    -- hex-encoded ciphertext
    );

    CREATE TABLE IF NOT EXISTS Settings (
        ID         INTEGER PRIMARY KEY CHECK (ID = 1),
        MasterSalt TEXT NOT NULL,   -- PBKDF2 salt (hex)
        Iterations INTEGER NOT NULL,
        Verifier   TEXT NOT NULL    -- keyed-hash verifier (hex)
    );

.. warning:: **Not compatible with v1/v2/v3 databases.** Earlier
    versions either stored a plain-text password (v1), had no ``Salt``
    column and no master password at all (v2), or had no ``Name``
    column (v3). This version expects all of the above. Start from a
    fresh database file when upgrading -- see the README's "Migrating"
    note.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional, Tuple

from .models import Password

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS Records (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Name TEXT NOT NULL DEFAULT '',
    Password TEXT NOT NULL,
    Salt TEXT NOT NULL,
    Decimal TEXT NOT NULL
);
"""

CREATE_SETTINGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS Settings (
    ID INTEGER PRIMARY KEY CHECK (ID = 1),
    MasterSalt TEXT NOT NULL,
    Iterations INTEGER NOT NULL,
    Verifier TEXT NOT NULL
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


def create_settings_table(connection: sqlite3.Connection) -> None:
    """Create the ``Settings`` table if it does not already exist."""
    try:
        connection.execute(CREATE_SETTINGS_TABLE_SQL)
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to create settings table: {exc}")


def get_master_settings(
    connection: sqlite3.Connection,
) -> Optional[Tuple[str, int, str]]:
    """Fetch the stored master-password verification material, if any.

    Returns:
        ``(master_salt_hex, iterations, verifier_hex)`` if a master
        password has already been set up for this database, or
        ``None`` if this is a fresh database (no ``Settings`` row yet).
    """
    try:
        cursor = connection.execute(
            "SELECT MasterSalt, Iterations, Verifier FROM Settings WHERE ID = 1;"
        )
        row = cursor.fetchone()
    except sqlite3.Error as exc:
        print(f"Failed to read settings: {exc}")
        return None
    if row is None:
        return None
    return row[0], row[1], row[2]


def save_master_settings(
    connection: sqlite3.Connection,
    master_salt_hex: str,
    iterations: int,
    verifier_hex: str,
) -> None:
    """Persist master-password verification material (never the password)."""
    try:
        connection.execute(
            "INSERT INTO Settings (ID, MasterSalt, Iterations, Verifier) "
            "VALUES (1, ?, ?, ?);",
            (master_salt_hex, iterations, verifier_hex),
        )
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to save settings: {exc}")


def overwrite_master_settings(
    connection: sqlite3.Connection,
    master_salt_hex: str,
    iterations: int,
    verifier_hex: str,
) -> None:
    """Replace whatever master-password settings this DB currently has.

    Unlike :func:`save_master_settings` (insert-only, for first-time
    setup), this REPLACEs row ``ID = 1``. Used when importing an export
    that includes its source database's master salt/verifier, so a
    fresh destination database derives the *same* master key from the
    *same* typed master password -- otherwise each database's own
    randomly-generated salt would make an identical password derive an
    unrelated key, and none of the imported entries would decrypt.

    .. warning:: Any entries already in this database were encrypted
        under the *old* salt's derived key. After this call they will
        no longer decrypt -- only call this on an empty/fresh database.
    """
    try:
        connection.execute(
            "INSERT OR REPLACE INTO Settings (ID, MasterSalt, Iterations, Verifier) "
            "VALUES (1, ?, ?, ?);",
            (master_salt_hex, iterations, verifier_hex),
        )
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to overwrite settings: {exc}")


def insert_user(
    connection: sqlite3.Connection,
    name: str,
    key: str,
    salt_hex: str,
    ciphertext_hex: str,
) -> None:
    """Insert one ``(name, key, salt, ciphertext)`` row.

    Args:
        connection: Open database connection.
        name: The entry's user-chosen label (``Password.name``).
        key: The binary encryption pattern (``Password.key``).
        salt_hex: The entry's hex-encoded salt (``Password.salt``).
        ciphertext_hex: The hex-encoded ciphertext (``Password.ciphertext``).
    """
    try:
        connection.execute(
            "INSERT INTO Records (Name, Password, Salt, Decimal) VALUES (?, ?, ?, ?);",
            (name, key, salt_hex, ciphertext_hex),
        )
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to insert data: {exc}")


def remove_user(
    connection: sqlite3.Connection, entries: List[Password], entry: Password
) -> None:
    """Delete `entry` from both the database and the in-memory list.

    Matches on `key`, `salt`, and `ciphertext` together (the per-entry
    salt makes this effectively unique even if two entries coincide on
    pattern, plaintext, and name).

    Args:
        connection: Open database connection.
        entries: The in-memory list of entries to remove `entry` from.
        entry: The entry to remove.
    """
    try:
        connection.execute(
            "DELETE FROM Records WHERE Password = ? AND Salt = ? AND Decimal = ?;",
            (entry.key, entry.salt, entry.ciphertext),
        )
        connection.commit()
        label = entry.name if entry.name else "(unnamed)"
        print(f"Entry [{label}] (Key: {entry.key}) removed")
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
        cursor = connection.execute("SELECT Name, Password, Salt, Decimal FROM Records;")
        for name_value, key_value, salt_value, ciphertext_value in cursor.fetchall():
            if key_value is not None and salt_value is not None and ciphertext_value is not None:
                entries.append(
                    Password(
                        key=key_value,
                        salt=salt_value,
                        ciphertext=ciphertext_value,
                        name=name_value or "",
                    )
                )
    except sqlite3.Error as exc:
        print(f"Failed to prepare statement: {exc}")
    return entries


def clear_table(connection: sqlite3.Connection) -> None:
    """Delete every row from ``Records``. Does NOT touch ``Settings`` --
    the master password stays set for the life of the database file.
    """
    try:
        connection.execute("DELETE FROM Records;")
        connection.commit()
    except sqlite3.Error as exc:
        print(f"Failed to clear table: {exc}")
