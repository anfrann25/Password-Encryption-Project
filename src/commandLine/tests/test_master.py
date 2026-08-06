"""Unit tests for password_manager.master (KDF, verifier, entry keys)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from password_manager import master

# Use a low iteration count in tests so the suite stays fast; production
# code uses master.PBKDF2_ITERATIONS (200_000).
FAST_ITERATIONS = 100


class MasterKeyDerivationTests(unittest.TestCase):
    def test_same_password_and_salt_give_same_key(self):
        salt = master.generate_salt()
        k1 = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        k2 = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        self.assertEqual(k1, k2)

    def test_different_passwords_give_different_keys(self):
        salt = master.generate_salt()
        k1 = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        k2 = master.derive_master_key("hunter3", salt, FAST_ITERATIONS)
        self.assertNotEqual(k1, k2)

    def test_different_salts_give_different_keys(self):
        k1 = master.derive_master_key("hunter2", master.generate_salt(), FAST_ITERATIONS)
        k2 = master.derive_master_key("hunter2", master.generate_salt(), FAST_ITERATIONS)
        self.assertNotEqual(k1, k2)

    def test_key_length(self):
        salt = master.generate_salt()
        key = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        self.assertEqual(len(key), master.KEY_BYTES)

    def test_salts_are_random(self):
        salts = {master.generate_salt() for _ in range(50)}
        self.assertEqual(len(salts), 50)


class VerifierTests(unittest.TestCase):
    def test_correct_key_verifies(self):
        salt = master.generate_salt()
        key = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        verifier = master.make_verifier(key)
        self.assertTrue(master.verify(key, verifier))

    def test_wrong_password_fails_verification(self):
        salt = master.generate_salt()
        real_key = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        verifier = master.make_verifier(real_key)

        wrong_key = master.derive_master_key("wrong-password", salt, FAST_ITERATIONS)
        self.assertFalse(master.verify(wrong_key, verifier))

    def test_verifier_does_not_equal_key(self):
        # Sanity check that we're not accidentally storing the key itself.
        salt = master.generate_salt()
        key = master.derive_master_key("hunter2", salt, FAST_ITERATIONS)
        verifier = master.make_verifier(key)
        self.assertNotEqual(key, verifier)


class EntryKeyDerivationTests(unittest.TestCase):
    def test_same_master_key_and_salt_give_same_entry_key(self):
        master_key = b"\x01" * master.KEY_BYTES
        entry_salt = master.generate_salt()
        e1 = master.derive_entry_key(master_key, entry_salt)
        e2 = master.derive_entry_key(master_key, entry_salt)
        self.assertEqual(e1, e2)

    def test_different_entry_salts_give_different_entry_keys(self):
        master_key = b"\x01" * master.KEY_BYTES
        e1 = master.derive_entry_key(master_key, master.generate_salt())
        e2 = master.derive_entry_key(master_key, master.generate_salt())
        self.assertNotEqual(e1, e2)

    def test_entry_key_differs_from_master_key(self):
        master_key = b"\x01" * master.KEY_BYTES
        entry_key = master.derive_entry_key(master_key, master.generate_salt())
        self.assertNotEqual(master_key, entry_key)


if __name__ == "__main__":
    unittest.main()
