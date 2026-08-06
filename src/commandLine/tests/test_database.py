"""Unit tests for password_manager.database, using a temp SQLite file."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from password_manager import database, master
from password_manager.models import Password

# A fixed test master key, standing in for what _login_or_setup would
# derive from a real password -- database/model round-trips don't need
# to repeat the (slow, by design) PBKDF2 stretch on every test.
MASTER_KEY = b"\x42" * master.KEY_BYTES


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmpdir.name) / "test.db")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_insert_load_roundtrip(self):
        entry1 = Password.encrypt("hunter2", "000101", MASTER_KEY)
        entry2 = Password.encrypt("correct-horse", "010101", MASTER_KEY)

        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, entry1.key, entry1.salt, entry1.ciphertext)
            database.insert_user(conn, entry2.key, entry2.salt, entry2.ciphertext)

            loaded = database.load_users(conn)

        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0], entry1)
        self.assertEqual(loaded[1], entry2)
        # And they still decrypt correctly after a round trip through SQLite.
        self.assertEqual(loaded[0].decrypt(MASTER_KEY), "hunter2")
        self.assertEqual(loaded[1].decrypt(MASTER_KEY), "correct-horse")

    def test_remove_user_deletes_from_db_and_list(self):
        entry = Password.encrypt("hunter2", "000101", MASTER_KEY)
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, entry.key, entry.salt, entry.ciphertext)
            entries = database.load_users(conn)
            self.assertEqual(len(entries), 1)

            database.remove_user(conn, entries, entries[0])
            self.assertEqual(entries, [])

            remaining = database.load_users(conn)
            self.assertEqual(remaining, [])

    def test_clear_table(self):
        entry = Password.encrypt("hunter2", "000101", MASTER_KEY)
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.insert_user(conn, entry.key, entry.salt, entry.ciphertext)
            database.clear_table(conn)
            self.assertEqual(database.load_users(conn), [])

    def test_master_settings_roundtrip(self):
        with database.open_database(self.db_path) as conn:
            database.create_settings_table(conn)
            self.assertIsNone(database.get_master_settings(conn))

            database.save_master_settings(conn, "aabb", 100, "ccdd")
            settings = database.get_master_settings(conn)
            self.assertEqual(settings, ("aabb", 100, "ccdd"))

    def test_clear_table_does_not_touch_settings(self):
        with database.open_database(self.db_path) as conn:
            database.create_table(conn)
            database.create_settings_table(conn)
            database.save_master_settings(conn, "aabb", 100, "ccdd")

            database.clear_table(conn)

            self.assertEqual(database.get_master_settings(conn), ("aabb", 100, "ccdd"))


if __name__ == "__main__":
    unittest.main()
