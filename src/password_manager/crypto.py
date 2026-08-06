"""
Encryption logic: the Algorithm A / Algorithm B chain described in the
original project's README, now driven by a real derived key rather than
by the pattern alone.

Concept
-------
A password is just a sequence of bytes. Given a binary "pattern" string
(e.g. ``"001000"``, produced the same way as before -- see
:mod:`.functions`) *and* a secret `key` (bytes derived from the user's
master password -- see :mod:`.master`), the password is transformed
once per character of the pattern, left to right:

* ``'1'`` -> **Algorithm A**: a byte-wise additive (Caesar-style) shift.
* ``'0'`` -> **Algorithm B**: a byte-wise XOR.

.. note:: **v3 change.** In v2, the shift/XOR values for each step were
    derived *only* from the pattern itself -- which meant the pattern
    alone was both the algorithm-selector and all the "key" there was.
    Since the pattern is stored in plaintext right next to the
    ciphertext, and only has 64 possible values, that provided no real
    secrecy. Now the pattern still *selects* Algorithm A vs. B at each
    step (so the original design idea is preserved), but the numeric
    shift/XOR key for each step is derived from `key`: real secret byte
    material that ultimately traces back to the user's master password
    (see :mod:`.master`). Without that key, knowing the pattern and the
    ciphertext is not enough to decrypt.

Every step has an exact inverse, so running every step's inverse in
**reverse order** recovers the original plaintext byte-for-byte -- see
:func:`decrypt`.

.. warning::
    The Algorithm A/B transform itself is still a simple, classical
    cipher (an additive shift and an XOR). Its *security* now rests on
    `key` being secret and unpredictable -- which is true as long as it
    comes from :mod:`.master`'s PBKDF2 + per-entry-salt derivation, and
    the master password is not guessable. This remains an educational
    project, not an audited encryption library.
"""

from __future__ import annotations

BYTE_MOD = 256


def _shift_for_step(key: bytes, step: int) -> int:
    """Derive Algorithm A's additive shift for chain position `step`.

    Cycles through `key`'s bytes and mixes in the step index, so a
    32-byte key can drive a pattern of any length without repeating the
    same shift on every step that happens to reuse the same key byte.
    """
    return (key[step % len(key)] + step * 7 + 1) % BYTE_MOD


def _xor_key_for_step(key: bytes, step: int) -> int:
    """Derive Algorithm B's XOR key for chain position `step`."""
    return (key[(step * 3 + 1) % len(key)] * (step + 1) + 13) % BYTE_MOD


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


def _validate_pattern(pattern: str) -> None:
    if not pattern or any(bit not in "01" for bit in pattern):
        raise ValueError(f"pattern must be a non-empty binary string, got {pattern!r}")


def _validate_key(key: bytes) -> None:
    if not key:
        raise ValueError("key must be non-empty bytes")


def encrypt(plaintext: str, pattern: str, key: bytes) -> bytes:
    """Encrypt `plaintext` using the algorithm chain selected by `pattern`.

    Args:
        plaintext: The password to encrypt, exactly as typed by the user.
        pattern: A binary string such as ``"001000"``. Each character
            selects one step of the chain: ``'1'`` -> Algorithm A,
            ``'0'`` -> Algorithm B.
        key: Secret key bytes the shift/XOR values for each step are
            derived from -- typically the output of
            :func:`.master.derive_entry_key`. Two calls with the same
            `pattern` but different `key` produce unrelated ciphertext.

    Returns:
        The ciphertext as raw bytes. Callers typically hex-encode this
        (see :meth:`.models.Password.ciphertext`) for storage/display.

    Raises:
        ValueError: If `pattern` is empty/invalid, or `key` is empty.
    """
    _validate_pattern(pattern)
    _validate_key(key)

    data = plaintext.encode("utf-8")
    for step, bit in enumerate(pattern):
        if bit == "1":
            data = _algorithm_a_encode(data, _shift_for_step(key, step))
        else:
            data = _algorithm_b(data, _xor_key_for_step(key, step))
    return data


def decrypt(ciphertext: bytes, pattern: str, key: bytes) -> str:
    """Decrypt `ciphertext` back to the original plaintext password.

    Applies the exact inverse of each step performed by :func:`encrypt`,
    walking the pattern in reverse.

    Args:
        ciphertext: Bytes produced by :func:`encrypt` using the same
            `pattern` and `key`.
        pattern: The same binary pattern that was used to encrypt.
        key: The same key bytes that were used to encrypt (see
            :func:`encrypt`).

    Returns:
        The original plaintext string.

    Raises:
        ValueError: If `pattern`/`key` are invalid, or if `ciphertext`
            does not decode to valid UTF-8 under this pattern/key
            (almost always means the wrong pattern or key was supplied).
    """
    _validate_pattern(pattern)
    _validate_key(key)

    data = ciphertext
    for step, bit in reversed(list(enumerate(pattern))):
        if bit == "1":
            data = _algorithm_a_decode(data, _shift_for_step(key, step))
        else:
            data = _algorithm_b(data, _xor_key_for_step(key, step))

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Could not decrypt: wrong pattern/key for this ciphertext"
        ) from exc
