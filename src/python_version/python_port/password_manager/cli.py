"""
Command-line application, ported from ``mainLoop()`` and ``main()`` in the
original ``src/main.cpp``.

Behaviour is kept intentionally close to the original: same menu, same
prompts, same "insert / remove / list / exit" flow, same
clear-and-rewrite persistence strategy on exit. The few deliberate
deviations from the C++ version are called out explicitly in each
function's docstring and summarised in the README.
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
3. Show List
4. Exit
---------------------------"""


def _insert_flow(entries: List[Password]) -> bool:
    """Handle menu option 1 (insert a new password).

    Ported from the ``case 1`` block of ``mainLoop()``.

    Returns:
        ``False`` if the user asked to exit mid-flow (input ``0``),
        ``True`` otherwise (keep the main loop running).
    """
    number = read_number()
    if number == 0:
        return False
    while number == -1:
        number = read_number()
        if number == 0:
            return False

    binary = decimal_to_binary(number)
    print(f"Thats decimal rep for number {number} is: {binary}")

    # Reproduces the original's slightly unusual "shift then clamp" logic:
    # pick a random offset in [0, number], add it to number, and if that
    # pushes the total above 50, subtract number back off again.
    random_value = get_random_number(number) + number
    if random_value > 50:
        random_value -= number
    binary_random = decimal_to_binary(random_value)
    print(f"Thats decimal rep for number {random_value} is: {binary_random}")

    password = read_password()
    print(f"Password is: {password}")

    entries.append(Password(key=binary_random, password=password))
    print("Password and Key stored successfully!")
    return True


def _remove_flow(connection, entries: List[Password]) -> None:
    """Handle menu option 2 (remove a password).

    Ported from the ``case 2`` block of ``mainLoop()``.
    """
    target = input("Input the password that you want to remove:")
    # Iterate over a copy since remove_user() mutates `entries` in place.
    for entry in list(entries):
        if entry.password == target:
            database.remove_user(connection, entries, entry)


def _show_flow(entries: List[Password]) -> bool:
    """Handle menu option 3 (show the list of stored entries).

    Ported from the ``case 3`` block of ``mainLoop()``.

    Returns:
        ``False`` if the user chose to exit after viewing the list,
        ``True`` to keep the main loop running.
    """
    if not entries:
        print("Database is empty :(")
    for entry in entries:
        entry.display()

    raw = input("To continue press 1: ")
    try:
        choice = int(raw)
    except ValueError:
        choice = 0
    return bool(choice)


def main_loop(entries: List[Password], connection) -> bool:
    """Run the interactive menu until the user chooses to exit.

    Ported from ``bool mainLoop(vector<Password>& vectorPass, sqlite3* db)``.

    .. note:: **Deliberate bug fix.** In the original C++, entering an
        invalid menu option (the ``default`` case) hit a stray
        ``return running`` that silently ended the whole program instead
        of just re-prompting. This port re-prompts instead, which is
        almost certainly what was intended -- see the README's
        "Differences from the original" section.

    Args:
        entries: The in-memory list of stored :class:`Password` entries.
            Mutated in place as the user inserts/removes entries.
        connection: Open :class:`sqlite3.Connection`.

    Returns:
        ``False`` in every code path (kept as ``bool`` for parity with the
        original signature); the loop always ends by choosing to exit.
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
            running = False
            return running
        else:
            print("Invalid option. Please try again.")
            # Deliberately `continue` rather than exit -- see docstring.
            continue
    return running


def run(db_path: str = "database.db") -> int:
    """Application entry point, ported from ``int main()``.

    Loads existing entries, runs the interactive menu, then persists the
    final in-memory state back to disk using the same
    clear-table-then-rewrite strategy as the original.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        A process exit code (``0`` on success, ``1`` on database error),
        matching the ``0`` / ``-1`` convention used by ``main()`` in the
        original (adapted to the standard POSIX convention of non-zero
        meaning failure).
    """
    with database.open_database(db_path) as connection:
        entries = database.load_users(connection)

        try:
            main_loop(entries, connection)
        except (EOFError, KeyboardInterrupt):
            # Graceful exit on Ctrl-D / Ctrl-C instead of an unhandled
            # traceback -- the original C++ has no equivalent, since it
            # never had to handle a piped/non-interactive input stream.
            print("\nExiting...")

        database.clear_table(connection)
        database.create_table(connection)
        for entry in entries:
            database.insert_user(connection, entry.key, entry.password)
        print("Database updated successfully!")

    return 0


def main() -> None:
    """Console-script entry point (see ``main.py`` / ``pyproject.toml``)."""
    sys.exit(run())


if __name__ == "__main__":
    main()
