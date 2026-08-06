#!/usr/bin/env python3
"""
Entry point for the Password Manager CLI.

Run with:

    python3 main.py [path/to/database.db]

If no database path is given, ``database.db`` in the current working
directory is used (same default as the original C++ binary).
"""

from __future__ import annotations

import sys

from password_manager.cli import run


def main() -> None:
    db_path = sys.argv[1] if len(sys.argv) > 1 else "database.db"
    sys.exit(run(db_path))


if __name__ == "__main__":
    main()
