"""
DDAS v2 — Schema manager (v2: BLAKE3 single-algorithm design).

Changes from v1:
  - Removed: hash_algo, extension, scan_state columns
  - Schema is now minimal and focused entirely on the deduplication pipeline.
  - Migration v1→v2 uses the rename-and-recreate pattern (safe on all SQLite versions).
  - PARTIAL_HASH_BYTES now reflects 128 KB first+last chunk strategy.
"""

from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

SCHEMA_VERSION: int = 2

# ─── Table DDL ────────────────────────────────────────────────────────────────

_CREATE_FILES_TABLE: str = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT    NOT NULL UNIQUE,
    size          INTEGER NOT NULL DEFAULT 0,
    partial_hash  TEXT             DEFAULT NULL,
    full_hash     TEXT             DEFAULT NULL,
    last_modified INTEGER NOT NULL DEFAULT 0,
    indexed_at    INTEGER NOT NULL DEFAULT 0
);
"""

# ─── Index DDL ────────────────────────────────────────────────────────────────

_INDEX_SQLS: list[str] = [
    # Stage 1: size equality lookup — rejects unique files before any hashing
    "CREATE INDEX IF NOT EXISTS idx_size ON files(size);",

    # Stage 2: partial hash filter — partial index keeps it compact
    "CREATE INDEX IF NOT EXISTS idx_partial_hash ON files(partial_hash) "
    "WHERE partial_hash IS NOT NULL;",

    # Stage 3: full hash confirmation + duplicate grouping
    "CREATE INDEX IF NOT EXISTS idx_full_hash ON files(full_hash) "
    "WHERE full_hash IS NOT NULL;",

    # Reconciliation path lookup
    "CREATE INDEX IF NOT EXISTS idx_path ON files(path);",
]


# ─── Migrations ───────────────────────────────────────────────────────────────

def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """
    v1 → v2: Drop hash_algo, extension, scan_state columns.
    Uses rename-and-recreate (safe on SQLite 3.25+, avoids DROP COLUMN quirks).
    Data in valid columns (path, size, partial_hash, full_hash, last_modified,
    indexed_at) is preserved; new rows are re-indexed with reset hashes to
    avoid stale partial/full hashes from a different algorithm.
    """
    log.info("Running migration v1 → v2: removing hash_algo, extension, scan_state")

    conn.executescript("""
        CREATE TABLE files_v2 (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            path          TEXT    NOT NULL UNIQUE,
            size          INTEGER NOT NULL DEFAULT 0,
            partial_hash  TEXT             DEFAULT NULL,
            full_hash     TEXT             DEFAULT NULL,
            last_modified INTEGER NOT NULL DEFAULT 0,
            indexed_at    INTEGER NOT NULL DEFAULT 0
        );

        -- Copy existing data; reset hashes so engine re-hashes with BLAKE3.
        -- Any previously stored SHA-256 hashes would be incompatible.
        INSERT INTO files_v2 (path, size, last_modified, indexed_at)
        SELECT path, size, last_modified, indexed_at FROM files;

        DROP TABLE files;
        ALTER TABLE files_v2 RENAME TO files;
    """)

    # Recreate indexes on the new table
    conn.execute("CREATE INDEX IF NOT EXISTS idx_size ON files(size);")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_partial_hash ON files(partial_hash) "
        "WHERE partial_hash IS NOT NULL;"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_full_hash ON files(full_hash) "
        "WHERE full_hash IS NOT NULL;"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_path ON files(path);")

    log.info("Migration v1 → v2 complete. Hashes reset for BLAKE3 re-index.")


_MIGRATIONS: dict[int, callable] = {
    1: _migrate_v1_to_v2,
}


# ─── Schema Manager ───────────────────────────────────────────────────────────

class SchemaManager:
    """Applies and migrates the DDAS SQLite schema. All methods are class-level."""

    @classmethod
    def apply(cls, conn: sqlite3.Connection) -> None:
        """Idempotently create tables + indexes, then run pending migrations."""
        current_version = cls._get_version(conn)

        if current_version == 0:
            cls._create_schema(conn)
            cls._set_version(conn, SCHEMA_VERSION)
            log.info("Schema v%d created (fresh).", SCHEMA_VERSION)
        elif current_version < SCHEMA_VERSION:
            cls._run_migrations(conn, current_version)
        elif current_version == SCHEMA_VERSION:
            log.debug("Schema already at v%d.", SCHEMA_VERSION)
        else:
            log.warning(
                "DB schema v%d > code v%d. Writes may misbehave.",
                current_version, SCHEMA_VERSION,
            )

    @classmethod
    def _create_schema(cls, conn: sqlite3.Connection) -> None:
        conn.execute(_CREATE_FILES_TABLE)
        for idx_sql in _INDEX_SQLS:
            conn.execute(idx_sql)

    @classmethod
    def _run_migrations(cls, conn: sqlite3.Connection, from_version: int) -> None:
        for v in range(from_version, SCHEMA_VERSION):
            fn = _MIGRATIONS.get(v)
            if fn is None:
                raise RuntimeError(f"No migration for v{v} → v{v+1}.")
            log.info("Migrating schema v%d → v%d …", v, v + 1)
            fn(conn)
            cls._set_version(conn, v + 1)
        log.info("Schema now at v%d.", SCHEMA_VERSION)

    @staticmethod
    def _get_version(conn: sqlite3.Connection) -> int:
        row = conn.execute("PRAGMA user_version").fetchone()
        return row[0] if row else 0

    @staticmethod
    def _set_version(conn: sqlite3.Connection, version: int) -> None:
        conn.execute(f"PRAGMA user_version = {version}")
