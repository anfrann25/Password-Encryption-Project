"""Unit tests for password_manager.database, using a temp SQLite file."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from password_manager import database
from password_manager.models import Password


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmpdir.name) / "test.db")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_insert_load_roundtrip(self):
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, key="000101", password="hunter2")
            database.insert_user(conn, key="010101", password="correct-horse")

            loaded = database.load_users(conn)

        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0], Password(key="000101", password="hunter2"))
        self.assertEqual(
            loaded[1], Password(key="010101", password="correct-horse")
        )

    def test_remove_user_deletes_from_db_and_list(self):
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, key="000101", password="hunter2")
            entries = database.load_users(conn)
            self.assertEqual(len(entries), 1)

            database.remove_user(conn, entries, entries[0])
            self.assertEqual(entries, [])

            remaining = database.load_users(conn)
            self.assertEqual(remaining, [])

    def test_clear_table(self):
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, key="000101", password="hunter2")
            database.clear_table(conn)
            self.assertEqual(database.load_users(conn), [])


if __name__ == "__main__":
    unittest.main()
