"""
Standalone helper functions, ported from ``src/Functions/functions.cpp``.

Each function below is a direct, behaviour-preserving port of its C++
counterpart. Where the original relied on C++-specific quirks (e.g. how
``cin >> int`` behaves on non-numeric input), the Python version uses
idiomatic error handling instead, but the *result* for valid input is
identical.

Original C++ function -> Python function
-----------------------------------------
``getnumber()``          -> :func:`read_number`
``decimalToBinary(int)``  -> :func:`decimal_to_binary`
``getRandomNumber(int)``  -> :func:`get_random_number`
``getpassword()``         -> :func:`read_password`
"""

from __future__ import annotations

import random

MIN_NUMBER = 1
MAX_NUMBER = 50
BINARY_WIDTH = 6  # bitset<6> in the original C++ code


def read_number() -> int:
    """Prompt the user for an integer in ``[1, 50]``.

    Mirrors ``getnumber()`` from ``functions.cpp``:

    * Returns ``0`` if the user wants to exit (input ``0``).
    * Returns ``-1`` if the input is out of the ``1..50`` range.
    * Returns the number itself if it is valid.

    Unlike the C++ version (where a non-numeric ``cin >> input`` leaves the
    stream in a failed state and can loop forever), invalid non-numeric
    input here is treated the same as an out-of-range number: it prints an
    error and returns ``-1`` so the caller's retry loop works correctly.

    Returns:
        The validated number, ``0`` to signal "exit", or ``-1`` on invalid
        input.
    """
    raw = input("Give a number 1-50, if u want to exit give 0:")
    try:
        value = int(raw)
    except ValueError:
        print(f"Error: number out of range ({MIN_NUMBER}\u201350)")
        return -1

    if value == 0:
        return 0
    if value < MIN_NUMBER or value > MAX_NUMBER:
        print(f"Error: number out of range ({MIN_NUMBER}\u201350)")
        return -1
    return value


def decimal_to_binary(number: int) -> str:
    """Return the 6-digit binary representation of ``number``.

    Mirrors ``decimalToBinary(int)``, which used ``bitset<6>(number)``.

    Args:
        number: An integer expected to be in ``[1, 50]``.

    Returns:
        A 6-character string of ``'0'``/``'1'`` digits, e.g. ``5 -> "000101"``.

    Raises:
        ValueError: If ``number`` is outside ``[1, 50]``, matching the
            C++ function's guard clause (which returned an error string;
            raising here is more idiomatic Python and callers already
            validate the range beforehand via :func:`read_number`).
    """
    if number < MIN_NUMBER or number > MAX_NUMBER:
        raise ValueError(f"number out of range ({MIN_NUMBER}\u201350): {number}")
    return format(number, f"0{BINARY_WIDTH}b")


def get_random_number(max_value: int) -> int:
    """Return a random integer in ``[0, max_value]`` inclusive.

    Mirrors ``getRandomNumber(int)``, including the ``max_value < 0``
    guard that returns ``-1``.

    Args:
        max_value: Inclusive upper bound for the random number.

    Returns:
        A random integer in ``[0, max_value]``, or ``-1`` if
        ``max_value`` is negative.
    """
    if max_value < 0:
        return -1
    return random.randint(0, max_value)


def read_password() -> str:
    """Prompt the user for a password and return it as-is.

    Mirrors ``getpassword()``. No validation, hashing, or masking is
    performed, exactly like the original (``cin >> pass`` also stops at
    the first whitespace character, so passwords containing spaces are
    truncated in both versions).

    .. note:: This function itself does not enforce any strength rules
        -- see :func:`password_requirements` / :func:`is_strong_password`
        for that, and :func:`.cli._read_strong_password` for the
        interactive retry loop that uses them.

    Returns:
        The raw string typed by the user (up to the first whitespace).
    """
    raw = input("Give a password: ")
    # cin >> pass stops at the first whitespace character; replicate that
    # so behaviour matches the C++ version exactly.
    return raw.split()[0] if raw.split() else ""


# --- Password strength rules -------------------------------------------
#
# A modern minimum bar for a password: long enough, and a mix of
# character classes so it isn't just a dictionary word or a short
# numeric PIN. This is deliberately simple (no dictionary/breach
# checking, no entropy estimate) -- good enough to stop the obviously
# weak passwords a project like this would otherwise happily accept.

MIN_PASSWORD_LENGTH = 8
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}:;\"'<>,.?/\\|`~"


def password_requirements(password: str) -> list[str]:
    """Check `password` against modern strength rules.

    Args:
        password: The candidate password.

    Returns:
        A list of short, human-readable descriptions of every
        requirement `password` currently fails to meet (in the order
        checked). An empty list means the password meets every
        requirement.
    """
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if not any(c.isupper() for c in password):
        problems.append("an uppercase letter (A-Z)")
    if not any(c.islower() for c in password):
        problems.append("a lowercase letter (a-z)")
    if not any(c.isdigit() for c in password):
        problems.append("a digit (0-9)")
    if not any(c in SPECIAL_CHARACTERS for c in password):
        problems.append("a special character (e.g. ! @ # $ % ^ & *)")
    return problems


def is_strong_password(password: str) -> bool:
    """Return whether `password` meets every rule in
    :func:`password_requirements` (i.e. that function returns an empty
    list for it).
    """
    return not password_requirements(password)
