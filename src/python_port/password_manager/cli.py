"""
Command-line application.

.. note:: **v2 change.** The menu gained a 4th option, **Decrypt an
    Entry**, and "Show List" now displays ciphertext instead of a
    plaintext password (there is no plaintext password stored anymore --
    see :mod:`.models` / :mod:`.crypto`). "Remove Password" now selects
    an entry by its position in the list instead of by typing the
    (no-longer-stored) plaintext password.
"""

from __future__ import annotations

import sys
from typing import List

from . import database
from .functions import decimal_to_binary, get_random_number, read_number, read_password
from .models import Password

MENU = """---------------------------
1. Insert New Password
2. Remove Password
3. Show List (encrypted)
4. Decrypt an Entry
5. Exit
---------------------------"""


def _generate_pattern() -> str | None:
    """Run the "give a number 1-50" flow and return the resulting pattern.

    This is the same number -> binary -> randomized-number -> binary flow
    the original C++ used to build its (cosmetic) key; here the resulting
    pattern is the *real* encryption key/algorithm-selector consumed by
    :mod:`.crypto`.

    Returns:
        The 6-digit binary pattern string, or ``None`` if the user asked
        to exit (entered ``0``) during number entry.
    """
    number = read_number()
    if number == 0:
        return None
    while number == -1:
        number = read_number()
        if number == 0:
            return None

    binary = decimal_to_binary(number)
    print(f"Thats decimal rep for number {number} is: {binary}")

    # Same "shift then clamp" quirk as the original: pick a random offset
    # in [0, number], add it to number, and if that pushes the total
    # above 50, subtract number back off again.
    random_value = get_random_number(number) + number
    if random_value > 50:
        random_value -= number
    pattern = decimal_to_binary(random_value)
    print(f"Thats decimal rep for number {random_value} is: {pattern}")
    return pattern


def _insert_flow(entries: List[Password]) -> bool:
    """Handle menu option 1: read a password, encrypt it, store the entry.

    Returns:
        ``False`` if the user asked to exit mid-flow, ``True`` otherwise.
    """
    pattern = _generate_pattern()
    if pattern is None:
        return False

    plaintext = read_password()
    entry = Password.encrypt(plaintext, pattern)
    print(f"Encrypted password (this is what gets stored): {entry.ciphertext}")

    entries.append(entry)
    print("Password encrypted and stored successfully!")
    return True


def _print_indexed_list(entries: List[Password]) -> None:
    """Print each entry prefixed with a 1-based index, for menu selection."""
    for index, entry in enumerate(entries, start=1):
        print(f"{index}. Key: {entry.key}, Encrypted: {entry.ciphertext}")


def _choose_entry_index(entries: List[Password], prompt: str) -> int | None:
    """Ask the user to pick an entry by its 1-based index.

    Returns:
        A valid 0-based index into `entries`, or ``None`` if the input
        was empty/invalid/out of range (an explanatory message is
        printed in that case).
    """
    raw = input(prompt)
    try:
        choice = int(raw)
    except ValueError:
        print("Invalid selection.")
        return None
    if choice < 1 or choice > len(entries):
        print("Invalid selection.")
        return None
    return choice - 1


def _remove_flow(connection, entries: List[Password]) -> None:
    """Handle menu option 2: remove a password by its list position."""
    if not entries:
        print("Database is empty :(")
        return
    _print_indexed_list(entries)
    index = _choose_entry_index(entries, "Enter the number of the entry to remove: ")
    if index is None:
        return
    database.remove_user(connection, entries, entries[index])


def _show_flow(entries: List[Password]) -> bool:
    """Handle menu option 3: show every stored entry's key + ciphertext.

    Returns:
        ``False`` if the user chose to exit after viewing the list,
        ``True`` to keep the main loop running.
    """
    if not entries:
        print("Database is empty :(")
    else:
        _print_indexed_list(entries)

    raw = input("To continue press 1: ")
    try:
        choice = int(raw)
    except ValueError:
        choice = 0
    return bool(choice)


def _decrypt_flow(entries: List[Password]) -> None:
    """Handle menu option 4: decrypt one entry and show the plaintext."""
    if not entries:
        print("Database is empty :(")
        return
    _print_indexed_list(entries)
    index = _choose_entry_index(entries, "Enter the number of the entry to decrypt: ")
    if index is None:
        return
    entry = entries[index]
    try:
        plaintext = entry.decrypt()
    except ValueError as exc:
        print(f"Could not decrypt entry: {exc}")
        return
    print(f"Decrypted password: {plaintext}")


def main_loop(entries: List[Password], connection) -> bool:
    """Run the interactive menu until the user chooses to exit.

    Args:
        entries: The in-memory list of stored :class:`Password` entries.
            Mutated in place as the user inserts/removes entries.
        connection: Open :class:`sqlite3.Connection`.

    Returns:
        ``False`` in every code path; kept as ``bool`` for symmetry with
        the original C++ signature.
    """
    running = True
    while running:
        print(MENU)
        raw_choice = input("Choose an option: ")
        try:
            choice = int(raw_choice)
        except ValueError:
            print("Invalid option. Please try again.")
            continue

        if choice == 1:
            running = _insert_flow(entries)
            if not running:
                return running
        elif choice == 2:
            _remove_flow(connection, entries)
        elif choice == 3:
            running = _show_flow(entries)
            if not running:
                return running
        elif choice == 4:
            _decrypt_flow(entries)
        elif choice == 5:
            running = False
            return running
        else:
            print("Invalid option. Please try again.")
            continue
    return running


def run(db_path: str = "database.db") -> int:
    """Application entry point.

    Loads existing entries, runs the interactive menu, then persists the
    final in-memory state back to disk (clear-table-then-rewrite).

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        A process exit code (``0`` on success).
    """
    with database.open_database(db_path) as connection:
        database.create_table(connection)
        entries = database.load_users(connection)

        try:
            main_loop(entries, connection)
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")

        database.clear_table(connection)
        database.create_table(connection)
        for entry in entries:
            database.insert_user(connection, entry.key, entry.ciphertext)
        print("Database updated successfully!")

    return 0


def main() -> None:
    """Console-script entry point (see ``main.py``)."""
    sys.exit(run())


if __name__ == "__main__":
    main()
