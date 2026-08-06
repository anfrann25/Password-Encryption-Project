"""
Command-line application.

.. note:: **v3 change.** The app now starts with a master-password
    login/setup step (see :func:`_login_or_setup`) before the menu
    appears at all. Every place that used to encrypt or decrypt an
    entry now threads the resulting `master_key` through. "Show List"
    also now shows each entry's salt alongside its pattern and
    ciphertext.
"""

from __future__ import annotations

import getpass
import sys
from typing import List, Optional

from . import database, master
from .functions import (
    decimal_to_binary,
    get_random_number,
    password_requirements,
    read_number,
    read_password,
)
from .models import Password

MENU = """---------------------------
1. Insert New Password
2. Remove Password
3. Show List (encrypted)
4. Decrypt an Entry
5. Exit
---------------------------"""

MAX_LOGIN_ATTEMPTS = 3


def _login_or_setup(connection) -> Optional[bytes]:
    """Set up a new master password, or verify one entered against an
    existing database.

    Returns:
        The derived master key on success, or ``None`` if the user
        failed to authenticate (caller should abort).
    """
    settings = database.get_master_settings(connection)

    if settings is None:
        print("No master password set for this database yet.")
        while True:
            first = getpass.getpass("Choose a master password: ")
            if not first:
                print("Master password cannot be empty.")
                continue
            second = getpass.getpass("Confirm master password: ")
            if first != second:
                print("Passwords did not match, try again.")
                continue
            break

        salt = master.generate_salt()
        master_key = master.derive_master_key(first, salt)
        verifier = master.make_verifier(master_key)
        database.save_master_settings(
            connection, salt.hex(), master.PBKDF2_ITERATIONS, verifier.hex()
        )
        print("Master password set. Remember it -- it cannot be recovered!")
        return master_key

    salt_hex, iterations, verifier_hex = settings
    salt = bytes.fromhex(salt_hex)
    expected_verifier = bytes.fromhex(verifier_hex)

    for attempt in range(MAX_LOGIN_ATTEMPTS):
        password = getpass.getpass("Master password: ")
        master_key = master.derive_master_key(password, salt, iterations)
        if master.verify(master_key, expected_verifier):
            return master_key
        remaining = MAX_LOGIN_ATTEMPTS - attempt - 1
        if remaining:
            print(f"Incorrect master password ({remaining} attempt(s) left).")
    print("Too many failed attempts. Exiting.")
    return None


def _generate_pattern() -> str | None:
    """Run the "give a number 1-50" flow and return the resulting pattern.

    This is the same number -> binary -> randomized-number -> binary flow
    the original C++ used to build its (cosmetic) key; here the resulting
    pattern still selects the Algorithm A/B chain (see :mod:`.crypto`),
    though the actual secret key material now comes from the master
    password instead of from this pattern alone.

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


def _read_entry_name() -> str:
    """Prompt for a non-empty label to identify this entry later.

    Unlike :func:`.functions.read_password`, this reads the full line
    (spaces allowed) so labels like ``"Bank of Greece"`` work naturally.

    Returns:
        The label as typed, with surrounding whitespace stripped.
    """
    while True:
        name = input("Give a name for this entry (e.g. 'Gmail', 'Bank'): ").strip()
        if name:
            return name
        print("Name cannot be empty.")


def _read_strong_password() -> str:
    """Prompt for a password, retrying until it meets modern strength
    rules (see :func:`.functions.password_requirements`).

    On each failed attempt, prints exactly what's still missing (e.g.
    "a digit (0-9)") rather than just rejecting silently, so the user
    isn't left guessing what to change.

    Returns:
        A password that satisfies every rule in
        :func:`.functions.password_requirements`.
    """
    while True:
        candidate = read_password()
        problems = password_requirements(candidate)
        if not problems:
            return candidate
        print("That password isn't strong enough. It still needs:")
        for problem in problems:
            print(f"  - {problem}")
        print("Please try again.")


def _insert_flow(entries: List[Password], master_key: bytes) -> bool:
    """Handle menu option 1: read a name + strong password, encrypt it,
    store the entry.

    Returns:
        ``False`` if the user asked to exit mid-flow, ``True`` otherwise.
    """
    pattern = _generate_pattern()
    if pattern is None:
        return False

    name = _read_entry_name()
    plaintext = _read_strong_password()
    entry = Password.encrypt(plaintext, pattern, master_key, name)
    print(f"Encrypted password (this is what gets stored): {entry.ciphertext}")

    entries.append(entry)
    print(f"'{name}' encrypted and stored successfully!")
    return True


def _print_indexed_list(entries: List[Password]) -> None:
    """Print each entry prefixed with a 1-based index, for menu selection."""
    for index, entry in enumerate(entries, start=1):
        label = entry.name if entry.name else "(unnamed)"
        print(
            f"{index}. [{label}] Key: {entry.key}, Salt: {entry.salt}, "
            f"Encrypted: {entry.ciphertext}"
        )


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


def _decrypt_flow(entries: List[Password], master_key: bytes) -> None:
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
        plaintext = entry.decrypt(master_key)
    except ValueError as exc:
        print(f"Could not decrypt entry: {exc}")
        return
    print(f"Decrypted password: {plaintext}")


def main_loop(entries: List[Password], connection, master_key: bytes) -> bool:
    """Run the interactive menu until the user chooses to exit.

    Args:
        entries: The in-memory list of stored :class:`Password` entries.
            Mutated in place as the user inserts/removes entries.
        connection: Open :class:`sqlite3.Connection`.
        master_key: The verified master key for this session (see
            :func:`_login_or_setup`), used to encrypt/decrypt entries.

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
            running = _insert_flow(entries, master_key)
            if not running:
                return running
        elif choice == 2:
            _remove_flow(connection, entries)
        elif choice == 3:
            running = _show_flow(entries)
            if not running:
                return running
        elif choice == 4:
            _decrypt_flow(entries, master_key)
        elif choice == 5:
            running = False
            return running
        else:
            print("Invalid option. Please try again.")
            continue
    return running


def run(db_path: str = "database.db") -> int:
    """Application entry point.

    Logs in (or sets up a master password for a fresh database), loads
    existing entries, runs the interactive menu, then persists the
    final in-memory state back to disk (clear-table-then-rewrite).

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        A process exit code (``0`` on success, ``1`` on failed login).
    """
    with database.open_database(db_path) as connection:
        database.create_table(connection)
        database.create_settings_table(connection)

        master_key = _login_or_setup(connection)
        if master_key is None:
            return 1

        entries = database.load_users(connection)

        try:
            main_loop(entries, connection, master_key)
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")

        database.clear_table(connection)
        database.create_table(connection)
        for entry in entries:
            database.insert_user(connection, entry.name, entry.key, entry.salt, entry.ciphertext)
        print("Database updated successfully!")

    return 0


def main() -> None:
    """Console-script entry point (see ``main.py``)."""
    sys.exit(run())


if __name__ == "__main__":
    main()
