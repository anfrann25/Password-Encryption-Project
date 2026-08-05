# Password Manager (Python port)

A Python port of the original **Password-Encryption-Project** (C++). It
keeps the exact same CLI, the exact same on-disk SQLite schema, and — as
much as possible — the exact same behaviour, while adding proper
documentation, type hints, tests, and a couple of small, clearly
documented bug fixes.

> The original C++ project is left completely untouched. This is a
> parallel, standalone implementation living in its own folder — nothing
> in `src/`, the `Makefile`, etc. was modified.

## Table of contents

- [What this actually does](#what-this-actually-does)
- [Project layout](#project-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Database schema](#database-schema)
- [Differences from the original C++ version](#differences-from-the-original-c-version)
- [Security notes](#security-notes)
- [Running the tests](#running-the-tests)

## What this actually does

Despite the project's name, **no encryption algorithm is actually applied
to the password** in either the original C++ code or this port. What the
program really does is:

1. Ask for a number from 1–50.
2. Convert it to a 6-bit binary string (just for display).
3. Generate a second, randomized number/binary string — this becomes the
   entry's `key`.
4. Ask for a password and store it **as plain text**, paired with that
   `key`, in a local SQLite database.

The original README described an aspirational design (a chain of two
swappable encryption algorithms, A/B, selected bit-by-bit by the binary
pattern) that was never implemented in the C++ source — `functions.cpp`
and `main.cpp` contain no cipher of any kind. This port is a faithful
port of **the code that actually exists**, not of the aspirational
description, so it inherits the same "no real encryption" behaviour. See
[Security notes](#security-notes) below.

## Project layout

```
password_manager_python/
├── main.py                     # CLI entry point
├── password_manager/
│   ├── __init__.py
│   ├── functions.py             # ported from src/Functions/functions.cpp
│   ├── models.py                # ported from src/PasswordClass/password.h
│   ├── database.py              # ported from the DB helpers in src/main.cpp
│   └── cli.py                   # ported from mainLoop()/main() in src/main.cpp
├── tests/
│   ├── test_functions.py
│   └── test_database.py
└── README.md
```

Each Python module's docstring says exactly which C++ file/function it
was ported from, so you can cross-reference the two implementations
line by line if needed.

## Requirements

- Python 3.9+
- No third-party dependencies — only the standard library (`sqlite3`,
  `random`, `dataclasses`) is used.

## Installation

```bash
git clone <this-repo-or-copy-the-folder>
cd password_manager_python
# nothing to install — just run it
```

## Usage

```bash
python3 main.py                 # uses ./database.db (same default as the C++ binary)
python3 main.py path/to/other.db  # use a custom database file
```

You'll get the same menu as the original:

```
---------------------------
1. Insert New Password
2. Remove Password
3. Show List
4. Exit
---------------------------
Choose an option:
```

- **1 — Insert New Password**: enter a number 1–50, then a password.
  A random binary "key" is generated and the pair is stored in memory
  (and written to disk when you exit).
- **2 — Remove Password**: enter the exact password text of the entry to
  delete.
- **3 — Show List**: prints every stored `Key: ..., Password: ...` pair.
  Enter `1` to go back to the menu, or `0` to save and exit.
- **4 — Exit**: saves and quits.

On exit, the program clears the `Records` table and re-writes it from
the current in-memory list — identical to the original's
"clear-then-rewrite" persistence strategy.

## How it works

```python
from password_manager.functions import decimal_to_binary, get_random_number

number = 7                                  # user input, 1..50
binary = decimal_to_binary(number)          # "000111"

random_value = get_random_number(number) + number
if random_value > 50:
    random_value -= number
key = decimal_to_binary(random_value)       # the entry's stored "key"
```

```python
from password_manager.models import Password

entry = Password(key="001000", password="hunter2")
entry.display()   # -> "Key: 001000, Password: hunter2"
```

## Database schema

Kept byte-for-byte compatible with the C++ version so a `database.db`
file works with either implementation:

```sql
CREATE TABLE IF NOT EXISTS Records (
    ID       INTEGER PRIMARY KEY AUTOINCREMENT,
    Password TEXT NOT NULL,   -- actually stores the binary "key"
    Decimal  TEXT NOT NULL    -- actually stores the plain-text password
);
```

Yes, the column names are swapped from what you'd expect — `Password`
holds the key and `Decimal` holds the password. That's how the original
C++ named them (see `insertUser(DB, p.getKey(), p.getPass())` in
`main.cpp`), and it's preserved here purely so existing database files
stay readable. The Python-facing `Password` dataclass uses the correct
names (`key`, `password`) internally.

## Differences from the original C++ version

Everything below is called out in detail in the relevant function's
docstring in the code:

1. **Invalid menu choice no longer exits the program.** The C++
   `default:` case in the `switch` had a stray `return running;` that
   silently terminated the whole application on any bad input (e.g.
   typing `9`). This port just re-prompts, which is almost certainly what
   was intended.
2. **"Remove Password" now actually deletes from the database.** The C++
   `DELETE FROM Records WHERE Password = ?` was bound to the password
   text, but the `Password` column stores the *key*, not the password —
   so the condition could never match, and rows were silently never
   deleted from disk (only from the in-memory vector). This port
   compares against `Decimal` (the column that really holds the
   password), so removal works correctly.
3. **Non-numeric menu/number input doesn't hang.** `cin >> int` on
   non-numeric input leaves the C++ stream in a failed state, which can
   loop forever without extra handling. The Python version simply
   catches the `ValueError` and treats it the same as invalid input.
4. **Graceful `Ctrl-C` / `Ctrl-D` handling** — prints a short message and
   still saves before exiting, instead of an unhandled traceback.

Nothing else was changed: prompts, menu text, output formatting, the
random-key generation quirks, and the overall program flow are all
intentionally identical to the original.

## Security notes

This is an educational project, **not** a real password manager:

- Passwords are stored in **plain text** in the SQLite file.
- The "binary key" is cosmetic — it is not used to encrypt or decrypt
  anything.
- There's no master password, no hashing (e.g. bcrypt/argon2), no
  encryption at rest, and no HMAC/integrity check.

If you need an actual password manager, use a well-audited one (e.g.
Bitwarden, 1Password, KeePassXC) instead of this project.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers:

- `functions.py` — binary conversion, random-number bounds, input parsing.
- `database.py` — create/insert/load/remove/clear against a temporary
  SQLite file (nothing touches your real `database.db`).
