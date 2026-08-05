# Password Manager (Python port, v2 — with real encryption)

A Python implementation of the **Password-Encryption-Project** idea. It
keeps the original CLI feel (same menu style, same "give a number 1-50"
key-generation flow) but, unlike the original C++ code, it **actually
encrypts the password** using the Algorithm A / Algorithm B chain the
original README described but never implemented.

> The C++ project (`src/`, `Makefile`, etc.) is completely untouched —
> this is a standalone Python implementation in its own folder.

## Table of contents

- [What changed vs. the original](#what-changed-vs-the-original)
- [Project layout](#project-layout)
- [Requirements](#requirements)
- [Usage](#usage)
- [How the encryption works](#how-the-encryption-works)
- [Example session](#example-session)
- [Database schema](#database-schema)
- [Migrating from v1 / the original C++ database](#migrating-from-v1--the-original-c-database)
- [Security notes](#security-notes)
- [Running the tests](#running-the-tests)

## What changed vs. the original

The original C++ project's README described a design that was never
actually built: a password would be transformed by a chain of two
algorithms (A/B), selected bit-by-bit by a randomly generated binary
pattern. In the real C++ code, no such transformation exists — the
"encrypted" password was just stored as plain text next to a
decorative random binary string.

**This version implements that missing piece for real**, in
[`password_manager/crypto.py`](password_manager/crypto.py):

- You still pick a number 1–50 and get a randomized 6-bit binary
  **pattern**, exactly like before.
- That pattern now does real work: each of its 6 bits selects one step
  of an encryption chain applied to your password —
  `'1'` → **Algorithm A** (a byte-wise additive/Caesar-style shift),
  `'0'` → **Algorithm B** (a byte-wise XOR).
- The resulting **ciphertext** (not the plaintext) is what gets stored
  and shown to you.
- A new **"Decrypt an Entry"** menu option runs the chain in reverse to
  recover the original password from the pattern + ciphertext, proving
  the round trip actually works.

## Project layout

```
python_port/
├── main.py                      # CLI entry point
├── password_manager/
│   ├── __init__.py
│   ├── functions.py              # number/binary/password input helpers
│   ├── crypto.py                 # ★ Algorithm A / Algorithm B chain (new)
│   ├── models.py                 # Password: key (pattern) + ciphertext
│   ├── database.py               # SQLite persistence
│   └── cli.py                    # interactive menu
├── tests/
│   ├── test_functions.py
│   ├── test_crypto.py            # ★ encrypt/decrypt round-trip tests (new)
│   └── test_database.py
└── README.md
```

## Requirements

- Python 3.9+, standard library only (`sqlite3`, `random`, `dataclasses`).

## Usage

```bash
python3 main.py                    # uses ./database.db
python3 main.py path/to/other.db   # custom database file
```

```
---------------------------
1. Insert New Password
2. Remove Password
3. Show List (encrypted)
4. Decrypt an Entry
5. Exit
---------------------------
Choose an option:
```

- **1 — Insert New Password**: enter a number 1–50, then your password.
  The password is encrypted immediately and you're shown the resulting
  ciphertext.
- **2 — Remove Password**: shows the list with index numbers; pick one
  to delete (nothing is ever matched by plaintext anymore, since it
  isn't stored).
- **3 — Show List (encrypted)**: lists every entry's pattern and
  ciphertext — this is genuinely what's on disk, not a re-display of
  something remembered in plaintext.
- **4 — Decrypt an Entry**: pick an entry from the list to decrypt and
  view its original password.
- **5 — Exit**: saves and quits (same clear-then-rewrite persistence
  strategy as before).

## How the encryption works

See [`password_manager/crypto.py`](password_manager/crypto.py) for the
full, heavily-commented implementation. In short:

```python
from password_manager.models import Password

entry = Password.encrypt("hunter2", pattern="001000")
print(entry.ciphertext)   # "52b158b6a1b474" — not "hunter2"!

print(entry.decrypt())    # "hunter2" — recovered using the same pattern
```

For pattern `"001000"`, the password's bytes go through 6 steps, one per
character of the pattern, left to right:

| Step | Bit | Algorithm | Operation |
|------|-----|-----------|-----------|
| 1 | `0` | B | XOR with a key derived from the pattern + step |
| 2 | `0` | B | XOR with a (different) derived key |
| 3 | `1` | A | Add a shift value derived from the pattern + step (mod 256) |
| 4 | `0` | B | XOR |
| 5 | `0` | B | XOR |
| 6 | `0` | B | XOR |

To decrypt, the exact inverse of each step is applied in **reverse**
order (step 6 → step 1). No secret other than the pattern itself is
needed — which matches the original design goal: only the system that
generated (and stored) the pattern can decrypt the entry.

## Example session

```
Choose an option: 1
Give a number 1-50, if u want to exit give 0:7
Thats decimal rep for number 7 is: 000111
Thats decimal rep for number 8 is: 001000
Give a password: mypassword
Encrypted password (this is what gets stored): 59adaaa5b7b7b35bb4a6
Password encrypted and stored successfully!

Choose an option: 4
1. Key: 001000, Encrypted: 59adaaa5b7b7b35bb4a6
Enter the number of the entry to decrypt: 1
Decrypted password: mypassword
```

## Database schema

```sql
CREATE TABLE IF NOT EXISTS Records (
    ID       INTEGER PRIMARY KEY AUTOINCREMENT,
    Password TEXT NOT NULL,   -- binary pattern (the encryption key)
    Decimal  TEXT NOT NULL    -- hex-encoded ciphertext
);
```

## Migrating from v1 / the original C++ database

⚠️ **A `database.db` created by the original C++ binary (or by v1 of
this port) is not compatible with this version.** Those stored a
plain-text password in the `Decimal` column; this version expects that
column to contain hex-encoded ciphertext, and will fail (or raise a
decrypt error) trying to interpret old rows. Start with a fresh database
file (delete `database.db` or point `main.py` at a new path) before
using this version.

## Security notes

This is still an **educational** project, not a production-grade
password manager:

- Algorithm A (additive shift) and Algorithm B (XOR) are both
  classical, easily broken ciphers — there's no real cryptographic
  strength here, just a working, reversible transformation that
  matches the original design brief.
- There's no master password, no key-derivation function, no
  authenticated encryption (no integrity/tamper protection), and no
  protection against someone who has access to the SQLite file and
  knows (or brute-forces) the 6-bit pattern — there are only 64
  possible patterns, so it is trivially brute-forceable.
- For anything real, use an audited tool (Bitwarden, 1Password,
  KeePassXC, or a standard library like `cryptography`'s `Fernet`/AES-GCM)
  instead.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

19 tests covering:
- `functions.py` — binary conversion, random-number bounds, input parsing.
- `crypto.py` — encrypt/decrypt round trips across many patterns and
  passwords (including empty strings and Unicode), and that ciphertext
  actually differs from the plaintext.
- `database.py` — create/insert/load/remove/clear against a temporary
  SQLite file.
