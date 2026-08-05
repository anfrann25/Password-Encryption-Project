"""Unit tests for password_manager.functions."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest
from unittest.mock import patch

from password_manager.functions import (
    decimal_to_binary,
    get_random_number,
    read_number,
    read_password,
)


class DecimalToBinaryTests(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(decimal_to_binary(1), "000001")
        self.assertEqual(decimal_to_binary(5), "000101")
        self.assertEqual(decimal_to_binary(50), "110010")

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            decimal_to_binary(0)
        with self.assertRaises(ValueError):
            decimal_to_binary(51)


class GetRandomNumberTests(unittest.TestCase):
    def test_negative_max_returns_minus_one(self):
        self.assertEqual(get_random_number(-5), -1)

    def test_result_within_bounds(self):
        for _ in range(200):
            value = get_random_number(10)
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 10)

    def test_zero_max_returns_zero(self):
        self.assertEqual(get_random_number(0), 0)


class ReadNumberTests(unittest.TestCase):
    @patch("builtins.input", return_value="0")
    def test_zero_means_exit(self, _mock_input):
        self.assertEqual(read_number(), 0)

    @patch("builtins.input", return_value="25")
    def test_valid_number(self, _mock_input):
        self.assertEqual(read_number(), 25)

    @patch("builtins.input", return_value="99")
    def test_out_of_range(self, _mock_input):
        self.assertEqual(read_number(), -1)

    @patch("builtins.input", return_value="not-a-number")
    def test_non_numeric_input(self, _mock_input):
        self.assertEqual(read_number(), -1)


class ReadPasswordTests(unittest.TestCase):
    @patch("builtins.input", return_value="hunter2")
    def test_simple_password(self, _mock_input):
        self.assertEqual(read_password(), "hunter2")

    @patch("builtins.input", return_value="hunter2 ignored-part")
    def test_stops_at_whitespace(self, _mock_input):
        # Matches C++'s `cin >> pass`, which stops at the first whitespace.
        self.assertEqual(read_password(), "hunter2")


if __name__ == "__main__":
    unittest.main()
