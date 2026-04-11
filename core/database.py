"""
SQLite database layer for DDAS.
All DB access goes through DatabaseManager.
Access via singleton: from core.database import db
"""

import sqlite3
import os
import threading
import time
from typing import Optional, List

from utils.logger import get_logger

DB_PATH = "ddas.db"
logger  = get_logger(__name__)


class DatabaseManager:
    """
    Thread-safe SQLite wrapper.

    Connection strategy:
    - Uses check_same_thread=False with a threading.Lock for write serialization.
    - Reads do not acquire the lock (SQLite WAL mode allows concurrent reads).
    - Every write operation acquires self._lock before executing.

    Schema — table: files
      id            INTEGER PRIMARY KEY AUTOINCREMENT
      path          TEXT NOT NULL UNIQUE
      size_bytes    INTEGER NOT NULL
      partial_hash  TEXT
      full_hash     TEXT
      status        TEXT NOT NULL DEFAULT 'normal'
                    -- values: 'normal', 'duplicate', 'error', 'skipped'
      first_seen    REAL NOT NULL   -- Unix timestamp
      last_seen     REAL NOT NULL   -- Unix timestamp
      scan_state    INTEGER NOT NULL DEFAULT 0
                    -- 0=discovered, 1=partial_hashed, 2=full_hashed

    Indexes:
      idx_size         ON files(size_bytes)
      idx_partial_hash ON files(partial_hash)
      idx_full_hash    ON files(full_hash)
      idx_status       ON files(status)
    """

    def __init__(self, db_path: str = DB_PATH) -> None:
        self._db_path   = db_path
        self._lock      = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Create tables and indexes if they do not exist.
        Enable WAL mode: PRAGMA journal_mode=WAL
        Enable foreign keys: PRAGMA foreign_keys=ON
        Called once at application startup before any other DB operation.
        """
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

            with self._lock:
                cur = self._conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS files (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        path         TEXT    NOT NULL UNIQUE,
                        size_bytes   INTEGER NOT NULL,
                        partial_hash TEXT,
                        full_hash    TEXT,
                        status       TEXT    NOT NULL DEFAULT 'normal',
                        first_seen   REAL    NOT NULL,
                        last_seen    REAL    NOT NULL,
                        scan_state   INTEGER NOT NULL DEFAULT 0
                    )
                """)

                cur.execute("CREATE INDEX IF NOT EXISTS idx_size         ON files(size_bytes)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_partial_hash ON files(partial_hash)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_full_hash    ON files(full_hash)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_status       ON files(status)")

                self._conn.commit()
            logger.info("[DB] database initialized at %s", self._db_path)
        except sqlite3.Error as e:
            logger.error("[DB] initialize failed: %s", e)

    def close(self) -> None:
        """Close the database connection cleanly."""
        try:
            if self._conn:
                self._conn.close()
                self._conn = None
                logger.info("[DB] connection closed.")
        except sqlite3.Error as e:
            logger.error("[DB] error closing connection: %s", e)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        """Convert a sqlite3.Row to a plain dict."""
        return dict(row)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def upsert_file(
        self,
        path:         str,
        size_bytes:   int,
        partial_hash: Optional[str] = None,
        full_hash:    Optional[str] = None,
        status:       str           = "normal",
        scan_state:   int           = 0,
    ) -> bool:
        """
        Insert or update a file record.

        Logic:
        - If path does not exist in DB: INSERT with first_seen=now, last_seen=now.
        - If path exists: UPDATE only the provided non-None fields + last_seen=now.

        Does NOT use INSERT OR REPLACE — to preserve first_seen on updates.
        Returns True on success, False on error.
        """
        now = time.time()
        try:
            with self._lock:
                cur = self._conn.cursor()

                # Check existence
                cur.execute("SELECT id FROM files WHERE path = ?", (path,))
                row = cur.fetchone()

                if row is None:
                    # INSERT
                    cur.execute(
                        """
                        INSERT INTO files
                            (path, size_bytes, partial_hash, full_hash, status, first_seen, last_seen, scan_state)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (path, size_bytes, partial_hash, full_hash, status, now, now, scan_state),
                    )
                else:
                    # BUILD UPDATE — only touch provided (non-None) fields
                    set_clauses = ["size_bytes = ?", "last_seen = ?", "status = ?", "scan_state = ?"]
                    params: list = [size_bytes, now, status, scan_state]

                    if partial_hash is not None:
                        set_clauses.append("partial_hash = ?")
                        params.append(partial_hash)

                    if full_hash is not None:
                        set_clauses.append("full_hash = ?")
                        params.append(full_hash)

                    params.append(path)
                    cur.execute(
                        f"UPDATE files SET {', '.join(set_clauses)} WHERE path = ?",
                        params,
                    )

                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("[DB] upsert_file failed for %s: %s", path, e)
            return False
        except Exception as e:
            logger.error("[DB] unexpected error in upsert_file for %s: %s", path, e)
            return False

    def delete_file(self, path: str) -> bool:
        """
        Delete the record for this path.
        Returns True on success (including path not found = no-op).
        Returns False on error.
        """
        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("DELETE FROM files WHERE path = ?", (path,))
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("[DB] delete_file failed for %s: %s", path, e)
            return False
        except Exception as e:
            logger.error("[DB] unexpected error in delete_file for %s: %s", path, e)
            return False

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_file(self, path: str) -> Optional[dict]:
        """Return the record for this path, or None if not found."""
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM files WHERE path = ?", (path,))
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None
        except sqlite3.Error as e:
            logger.error("[DB] get_file failed for %s: %s", path, e)
            return None
        except Exception as e:
            logger.error("[DB] unexpected error in get_file for %s: %s", path, e)
            return None

    def find_by_size(self, size_bytes: int) -> List[dict]:
        """Return all records with matching size_bytes. Returns [] on error."""
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM files WHERE size_bytes = ?", (size_bytes,))
            return [self._row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("[DB] find_by_size failed for size=%d: %s", size_bytes, e)
            return []
        except Exception as e:
            logger.error("[DB] unexpected error in find_by_size for size=%d: %s", size_bytes, e)
            return []

    def find_by_partial_hash(self, partial_hash: str, exclude_path: str) -> List[dict]:
        """
        Return all file records with matching partial_hash,
        excluding the file at exclude_path.
        Returns list of dicts with keys matching column names.
        Returns [] on any error.
        """
        try:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM files WHERE partial_hash = ? AND path != ?",
                (partial_hash, exclude_path),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("[DB] find_by_partial_hash failed: %s", e)
            return []
        except Exception as e:
            logger.error("[DB] unexpected error in find_by_partial_hash: %s", e)
            return []

    def find_by_full_hash(self, full_hash: str, exclude_path: str) -> List[dict]:
        """
        Return all file records with matching full_hash,
        excluding the file at exclude_path.
        Returns list of dicts with keys matching column names.
        Returns [] on any error.
        """
        try:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM files WHERE full_hash = ? AND path != ?",
                (full_hash, exclude_path),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("[DB] find_by_full_hash failed: %s", e)
            return []
        except Exception as e:
            logger.error("[DB] unexpected error in find_by_full_hash: %s", e)
            return []

    def get_all_paths(self) -> List[str]:
        """
        Return list of all file paths in the DB.
        Used by reconciliation to compare against filesystem.
        Returns [] on any error.
        """
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT path FROM files")
            return [row["path"] for row in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("[DB] get_all_paths failed: %s", e)
            return []
        except Exception as e:
            logger.error("[DB] unexpected error in get_all_paths: %s", e)
            return []

    def get_stats(self) -> dict:
        """
        Return a dict with:
          total_files : int — count of all records
          duplicates  : int — count of records with status='duplicate'
          errors      : int — count of records with status='error'
        Returns {"total_files": 0, "duplicates": 0, "errors": 0} on any error.
        """
        empty = {"total_files": 0, "duplicates": 0, "errors": 0}
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) AS cnt FROM files")
            total = cur.fetchone()["cnt"]

            cur.execute("SELECT COUNT(*) AS cnt FROM files WHERE status = 'duplicate'")
            dupes = cur.fetchone()["cnt"]

            cur.execute("SELECT COUNT(*) AS cnt FROM files WHERE status = 'error'")
            errors = cur.fetchone()["cnt"]

            return {"total_files": total, "duplicates": dupes, "errors": errors}
        except sqlite3.Error as e:
            logger.error("[DB] get_stats failed: %s", e)
            return empty
        except Exception as e:
            logger.error("[DB] unexpected error in get_stats: %s", e)
            return empty


# Module-level singleton
db = DatabaseManager()
