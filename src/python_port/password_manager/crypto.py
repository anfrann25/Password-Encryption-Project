"""
Real, working encryption logic: the Algorithm A / Algorithm B chain that
was *described* in the original project's README but never actually
implemented in the C++ source.

Concept
-------
A password is just a sequence of bytes. Given a binary "pattern" string
(e.g. ``"001000"``, produced the same way as before -- see
:mod:`.functions`), the password is transformed once per character of the
pattern, left to right:

* ``'1'`` -> **Algorithm A**: a byte-wise additive (Caesar-style) shift.
* ``'0'`` -> **Algorithm B**: a byte-wise XOR.

Both algorithms use a shift/key value *derived from the pattern itself
and from the position of the step in the chain* -- so no extra secret
needs to be stored anywhere: the pattern alone is both the
algorithm-selector *and* the key material. This is exactly what the
original README promised: "μπορεί να γίνει αποκρυπτογράφηση μόνο από το
ίδιο το σύστημα" (decryption is only possible with the matching
pattern).

Every step has an exact inverse, so running every step's inverse in
**reverse order** recovers the original plaintext byte-for-byte -- see
:func:`decrypt`.

.. warning::
    This is still a toy, educational cipher (an additive shift and an
    XOR are trivially breakable with basic cryptanalysis). It exists to
    make the project's original design idea *actually work end to end*,
    not to provide real security. See the README's "Security notes".
"""

from __future__ import annotations

BYTE_MOD = 256


def _base_value(pattern: str) -> int:
    """Interpret the binary `pattern` string as an integer."""
    return int(pattern, 2)


def _shift_for_step(pattern: str, step: int) -> int:
    """Derive Algorithm A's additive shift for chain position `step`.

    Mixing in the step index means repeated ``'1'`` bits in the pattern
    don't all apply the exact same shift.
    """
    return (_base_value(pattern) + step * 7 + 1) % BYTE_MOD


def _xor_key_for_step(pattern: str, step: int) -> int:
    """Derive Algorithm B's XOR key for chain position `step`."""
    return (_base_value(pattern) * (step + 1) + 13) % BYTE_MOD


def _algorithm_a_encode(data: bytes, shift: int) -> bytes:
    """Algorithm A, forward direction: ``byte -> (byte + shift) mod 256``."""
    return bytes((b + shift) % BYTE_MOD for b in data)


def _algorithm_a_decode(data: bytes, shift: int) -> bytes:
    """Algorithm A, inverse direction: ``byte -> (byte - shift) mod 256``."""
    return bytes((b - shift) % BYTE_MOD for b in data)


def _algorithm_b(data: bytes, key: int) -> bytes:
    """Algorithm B: byte-wise XOR. Self-inverse -- applying it twice with
    the same key returns the original bytes.
    """
    return bytes(b ^ key for b in data)


def encrypt(plaintext: str, pattern: str) -> bytes:
    """Encrypt `plaintext` using the algorithm chain selected by `pattern`.

    Args:
        plaintext: The password to encrypt, exactly as typed by the user.
        pattern: A binary string such as ``"001000"``. Each character
            selects one step of the chain: ``'1'`` -> Algorithm A,
            ``'0'`` -> Algorithm B.

    Returns:
        The ciphertext as raw bytes. Callers typically hex-encode this
        (see :meth:`.models.Password.ciphertext`) for storage/display.

    Raises:
        ValueError: If `pattern` is empty or contains characters other
            than ``'0'``/``'1'``.
    """
    if not pattern or any(bit not in "01" for bit in pattern):
        raise ValueError(f"pattern must be a non-empty binary string, got {pattern!r}")

    data = plaintext.encode("utf-8")
    for step, bit in enumerate(pattern):
        if bit == "1":
            data = _algorithm_a_encode(data, _shift_for_step(pattern, step))
        else:
            data = _algorithm_b(data, _xor_key_for_step(pattern, step))
    return data


def decrypt(ciphertext: bytes, pattern: str) -> str:
    """Decrypt `ciphertext` back to the original plaintext password.

    Applies the exact inverse of each step performed by :func:`encrypt`,
    walking the pattern in reverse.

    Args:
        ciphertext: Bytes produced by :func:`encrypt` using the same
            `pattern`.
        pattern: The same binary pattern that was used to encrypt.

    Returns:
        The original plaintext string.

    Raises:
        ValueError: If `pattern` is invalid, or if `ciphertext` does not
            decode to valid UTF-8 under this pattern (almost always means
            the wrong pattern was supplied).
    """
    if not pattern or any(bit not in "01" for bit in pattern):
        raise ValueError(f"pattern must be a non-empty binary string, got {pattern!r}")

    data = ciphertext
    for step, bit in reversed(list(enumerate(pattern))):
        if bit == "1":
            data = _algorithm_a_decode(data, _shift_for_step(pattern, step))
        else:
            data = _algorithm_b(data, _xor_key_for_step(pattern, step))

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Could not decrypt: wrong pattern/key for this ciphertext"
        ) from exc
