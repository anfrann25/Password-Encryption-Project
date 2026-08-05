"""
Data model for a stored password entry.

.. note:: **v2 change.** In the original C++ project (and in v1 of this
    port), the ``pass`` field held the *plain-text* password -- no
    encryption was actually applied anywhere in the code, despite the
    project's name. This version fixes that: :attr:`Password.ciphertext`
    now holds the **actual encrypted bytes** (hex-encoded), produced by
    :mod:`.crypto` using :attr:`Password.key` as the encryption pattern.
    See the README's "Differences from the original" section.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crypto


@dataclass
class Password:
    """A single stored entry: an encryption pattern paired with ciphertext.

    Attributes:
        key: The binary pattern (e.g. ``"001000"``) that was used both to
            *select* the Algorithm A/B chain and to *derive* the shift/XOR
            key material for each step -- see :mod:`.crypto`. Required to
            decrypt :attr:`ciphertext`.
        ciphertext: The encrypted password, as a hex string (e.g.
            ``"a1b2c3"``). This is what actually gets stored on disk and
            shown to the user -- the plaintext password itself is never
            stored anywhere.
    """

    key: str
    ciphertext: str

    @classmethod
    def encrypt(cls, plaintext_password: str, pattern: str) -> "Password":
        """Encrypt `plaintext_password` and wrap the result in a `Password`.

        Args:
            plaintext_password: The password as typed by the user. Not
                stored; only used to compute :attr:`ciphertext`.
            pattern: The binary pattern to encrypt with (also stored as
                :attr:`key`, since it's required later to decrypt).

        Returns:
            A new `Password` holding `pattern` and the resulting
            hex-encoded ciphertext.
        """
        cipher_bytes = crypto.encrypt(plaintext_password, pattern)
        return cls(key=pattern, ciphertext=cipher_bytes.hex())

    def decrypt(self) -> str:
        """Decrypt and return the original plaintext password.

        Returns:
            The plaintext password.

        Raises:
            ValueError: If :attr:`key`/:attr:`ciphertext` are inconsistent
                (should not happen for entries created by :meth:`encrypt`
                and left untouched).
        """
        return crypto.decrypt(bytes.fromhex(self.ciphertext), self.key)

    def display(self) -> None:
        """Print this entry's pattern and ciphertext (never the plaintext).

        Format: ``Key: <pattern>, Encrypted: <hex ciphertext>``.
        """
        print(f"Key: {self.key}, Encrypted: {self.ciphertext}")
