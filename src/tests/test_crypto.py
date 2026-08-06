"""Unit tests for password_manager.crypto."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from password_manager import crypto

KEY_A = bytes(range(32))          # 0,1,2,...,31
KEY_B = bytes(range(200, 232))    # a different, disjoint key


class EncryptDecryptRoundtripTests(unittest.TestCase):
    def test_roundtrip_various_patterns(self):
        patterns = ["000001", "111111", "000000", "010101", "101010", "001000"]
        passwords = ["hunter2", "correct-horse-battery-staple", "", "a", "😀 unicode"]
        for pattern in patterns:
            for password in passwords:
                with self.subTest(pattern=pattern, password=password):
                    ciphertext = crypto.encrypt(password, pattern, KEY_A)
                    self.assertEqual(crypto.decrypt(ciphertext, pattern, KEY_A), password)

    def test_ciphertext_differs_from_plaintext(self):
        ciphertext = crypto.encrypt("hunter2", "001000", KEY_A)
        self.assertNotEqual(ciphertext, b"hunter2")

    def test_different_patterns_give_different_ciphertext(self):
        c1 = crypto.encrypt("hunter2", "000001", KEY_A)
        c2 = crypto.encrypt("hunter2", "100000", KEY_A)
        self.assertNotEqual(c1, c2)

    def test_different_keys_give_different_ciphertext(self):
        # Same pattern, same plaintext, different key -> different
        # ciphertext. This is the whole point of adding a master key:
        # the pattern alone no longer determines the output.
        c1 = crypto.encrypt("hunter2", "001000", KEY_A)
        c2 = crypto.encrypt("hunter2", "001000", KEY_B)
        self.assertNotEqual(c1, c2)

    def test_wrong_pattern_does_not_silently_recover_plaintext(self):
        ciphertext = crypto.encrypt("hunter2", "001000", KEY_A)
        try:
            recovered = crypto.decrypt(ciphertext, "110011", KEY_A)
        except ValueError:
            return
        self.assertNotEqual(recovered, "hunter2")

    def test_wrong_key_does_not_silently_recover_plaintext(self):
        ciphertext = crypto.encrypt("hunter2", "001000", KEY_A)
        try:
            recovered = crypto.decrypt(ciphertext, "001000", KEY_B)
        except ValueError:
            return
        self.assertNotEqual(recovered, "hunter2")

    def test_invalid_pattern_raises(self):
        with self.assertRaises(ValueError):
            crypto.encrypt("hunter2", "", KEY_A)
        with self.assertRaises(ValueError):
            crypto.encrypt("hunter2", "0102", KEY_A)

    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            crypto.encrypt("hunter2", "001000", b"")


if __name__ == "__main__":
    unittest.main()
