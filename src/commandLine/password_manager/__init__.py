"""
password_manager
=================

A small educational CLI tool that stores passwords together with a
randomly generated "binary key" in a local SQLite database.

This package is a Python port of the original C++ project
(``Password-Encryption-Project``). It reproduces the exact same
behaviour and on-disk database schema as the C++ version, so a
``database.db`` file produced by either implementation can be opened
by the other.

See the top-level ``README.md`` for a full description, usage
instructions and an honest discussion of what this tool does (and
does not) do from a security point of view.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
