"""
Master-password handling.

.. note:: **v3 change.** Previously the *only* "secret" in this project
    was the 6-bit binary pattern itself -- which is stored right next to
    the ciphertext in the database, and has only 64 possible values, so
    it provided no real secrecy at all. This version introduces a real
    master password:

    * The user chooses a master password the first time they run the
      app against a given database file.
    * A strong key is derived from it with PBKDF2-HMAC-SHA256 (a slow,
      salted key-derivation function -- not a fast general-purpose
      hash), using a random per-database salt and a high iteration
      count, making brute-force/dictionary attacks far more expensive.
    * That derived key -- **never the password itself** -- is what
      encryption actually depends on. Without it, knowing the pattern
      and the ciphertext buys an attacker nothing.
    * A small "verifier" (itself just a keyed hash, not the key or the
      password) is stored so future sessions can check a re-entered
      master password is correct, without ever persisting anything an
      attacker could use to skip straight to the key.
    * Each stored entry additionally gets its own random salt
      (:func:`derive_entry_key`), so two entries -- even with the same
      pattern and the same master password -- never reuse the same
      underlying shift/XOR key material.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

SALT_BYTES = 16
KEY_BYTES = 32
PBKDF2_ITERATIONS = 200_000

# Fixed, non-secret context string. Only used to domain-separate the
# "verifier" derivation from other uses of the master key -- it is not
# a secret and does not need to be stored or kept safe.
_VERIFIER_CONTEXT = b"password-manager-master-verifier-v1"


def generate_salt(n: int = SALT_BYTES) -> bytes:
    """Return `n` cryptographically random bytes, suitable as a salt."""
    return secrets.token_bytes(n)


def derive_master_key(
    password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS
) -> bytes:
    """Derive a :data:`KEY_BYTES`-byte key from a master `password`.

    Uses PBKDF2-HMAC-SHA256, which is intentionally slow (repeated many
    times) and salted, so that guessing the master password requires
    doing the same expensive work for every guess -- unlike hashing the
    password once, which an attacker with a stolen database could brute
    force at billions of guesses per second on cheap hardware.

    Args:
        password: The master password as typed by the user. Never
            stored anywhere -- only this derived key (or, in practice,
            keys further derived *from* it) ever touches disk.
        salt: A random, per-database salt. Must be persisted (it isn't
            secret) so the same key can be re-derived on later logins.
        iterations: PBKDF2 round count. Persisted alongside `salt` so it
            can be increased in the future without invalidating old
            databases (old rows simply keep their original count).

    Returns:
        A :data:`KEY_BYTES`-byte derived key.
    """
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=KEY_BYTES
    )


def make_verifier(master_key: bytes) -> bytes:
    """Derive a value that lets later logins check a password is correct.

    This is a keyed hash of a fixed, non-secret context string -- it
    reveals nothing about the master key itself (HMAC is a one-way
    function), so storing it is safe, but it lets :func:`verify` confirm
    a freshly-entered password derives the *same* master key.
    """
    return hmac.new(master_key, _VERIFIER_CONTEXT, hashlib.sha256).digest()


def verify(master_key: bytes, expected_verifier: bytes) -> bool:
    """Check whether `master_key` matches a previously stored verifier.

    Uses a constant-time comparison (:func:`hmac.compare_digest`) so the
    check itself doesn't leak timing information about how close a
    guess was.
    """
    return hmac.compare_digest(make_verifier(master_key), expected_verifier)


def derive_entry_key(master_key: bytes, entry_salt: bytes) -> bytes:
    """Derive a per-entry encryption key from the master key + a salt.

    Every stored entry gets its own random `entry_salt`
    (:func:`generate_salt`), so this always returns different key
    material even for two entries protected by the same master
    password -- identical plaintexts never produce identical
    ciphertext.

    A single (fast) HMAC is enough here, rather than another full
    PBKDF2 stretch: the expensive, attacker-facing work already
    happened once, in :func:`derive_master_key`, when deriving a
    high-entropy `master_key` from a (potentially weak/guessable) human
    password. Deriving many per-entry keys from that already-strong key
    doesn't need to repeat that cost.
    """
    return hmac.new(master_key, entry_salt, hashlib.sha256).digest()
