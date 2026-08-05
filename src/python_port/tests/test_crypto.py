"""Unit tests for password_manager.crypto."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from password_manager import crypto


class EncryptDecryptRoundtripTests(unittest.TestCase):
    def test_roundtrip_various_patterns(self):
        patterns = ["000001", "111111", "000000", "010101", "101010", "001000"]
        passwords = ["hunter2", "correct-horse-battery-staple", "", "a", "😀 unicode"]
        for pattern in patterns:
            for password in passwords:
                with self.subTest(pattern=pattern, password=password):
                    ciphertext = crypto.encrypt(password, pattern)
                    self.assertEqual(crypto.decrypt(ciphertext, pattern), password)

    def test_ciphertext_differs_from_plaintext(self):
        ciphertext = crypto.encrypt("hunter2", "001000")
        self.assertNotEqual(ciphertext, b"hunter2")

    def test_different_patterns_give_different_ciphertext(self):
        c1 = crypto.encrypt("hunter2", "000001")
        c2 = crypto.encrypt("hunter2", "100000")
        self.assertNotEqual(c1, c2)

    def test_wrong_pattern_does_not_silently_recover_plaintext(self):
        ciphertext = crypto.encrypt("hunter2", "001000")
        # Decrypting with the wrong pattern must not return the original
        # plaintext (it may raise, or return garbage -- either is fine,
        # as long as it isn't the correct password).
        try:
            recovered = crypto.decrypt(ciphertext, "110011")
        except ValueError:
            return
        self.assertNotEqual(recovered, "hunter2")

    def test_invalid_pattern_raises(self):
        with self.assertRaises(ValueError):
            crypto.encrypt("hunter2", "")
        with self.assertRaises(ValueError):
            crypto.encrypt("hunter2", "0102")


if __name__ == "__main__":
    unittest.main()
