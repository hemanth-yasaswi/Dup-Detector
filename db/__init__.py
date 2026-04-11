"""
db package — DDAS v2 database layer (v2: BLAKE3 single-algorithm).

Public API for engine and service modules:

    from db import DatabaseManager, FileRepository, FileRecord
"""

from db.connection import DatabaseManager
from db.repository import FileRepository, FileRecord
from db.schema import SchemaManager, SCHEMA_VERSION

__all__ = [
    "DatabaseManager",
    "FileRepository",
    "FileRecord",
    "SchemaManager",
    "SCHEMA_VERSION",
]
