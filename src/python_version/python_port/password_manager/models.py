"""
Data model for a stored password entry.

Ported from ``src/PasswordClass/password.h`` (the original C++ ``Password``
class). The C++ class was a simple pair of strings (``key``, ``pass``) with
getters/setters and a ``display()`` method; this module reproduces the same
shape using a :mod:`dataclasses` class, which is the idiomatic Python
equivalent.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Password:
    """A single stored entry: a binary "key" paired with a password.

    Attributes:
        key: The 6-digit binary string generated for this entry
            (equivalent to the C++ class's ``key`` field / ``getKey()``).
        password: The plain-text password supplied by the user
            (equivalent to the C++ class's ``pass`` field / ``getPass()``).

    Note:
        As in the original project, the password is stored here exactly as
        the user typed it -- no hashing or encryption is applied. See the
        "Security notes" section of the README for details.
    """

    key: str
    password: str

    def display(self) -> None:
        """Print this entry in the same format as the C++ ``display()``.

        Kept for parity with the original CLI output
        (``Key: <key>, Password: <password>``).
        """
        print(f"Key: {self.key}, Password: {self.password}")
