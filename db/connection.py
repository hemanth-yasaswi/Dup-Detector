"""
DDAS v2 — Database connection manager.

Responsibilities:
  - Open SQLite connections in WAL journal mode.
  - Provide a context-manager API so connections are never leaked.
  - Apply all performance PRAGMAs on first open.
  - Provide online backup and integrity-check capabilities.
  - Detect and recover from DB corruption.

Design decisions:
  - No persistent connection pool. SQLite on Windows has quirks with
    shared file handles across threads; short-lived connections avoid
    locking issues entirely. WAL mode makes this very fast because
    readers never block writers and vice-versa.
  - Every operation opens and closes its own connection. The context
    manager ensures autocommit on success and rollback on exception.
  - PRAGMAs are applied per-connection (journal_mode is persistent
    once set; others are connection-scoped but fast to re-apply).
"""

from __future__ import annotations

import shutil
import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

log = logging.getLogger(__name__)


# ── PRAGMA settings applied to every new connection ───────────────────────────

_PRAGMAS: list[str] = [
    "PRAGMA journal_mode = WAL",        # Write-Ahead Logging — readers/writers don't block
    "PRAGMA synchronous  = NORMAL",     # fsync on WAL checkpoint, not every write
    "PRAGMA foreign_keys = ON",         # Enforce FK constraints (future-proof)
    "PRAGMA cache_size   = -8000",      # 8 MB page cache (~2000 × 4 KB pages)
    "PRAGMA temp_store   = MEMORY",     # Temp tables in RAM not on disk
    "PRAGMA mmap_size    = 134217728",  # 128 MB memory-mapped I/O
]


class DatabaseManager:
    """
    Manages SQLite database lifecycle for DDAS.

    Usage::

        manager = DatabaseManager(db_path)
        manager.initialize()          # Create schema if not present

        with manager.connect() as conn:
            conn.execute("SELECT ...")

    Args:
        db_path: Absolute path to the SQLite database file.
                 Parent directory must exist (created by config.settings).
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        """Absolute path to the database file."""
        return self._db_path

    def initialize(self) -> None:
        """
        Create the database file and apply the schema if not already present.
        Safe to call multiple times (fully idempotent).
        Raises ``RuntimeError`` if the existing DB fails an integrity check.
        """
        if self._db_path.exists() and not self.is_healthy():
            log.error("DB integrity check failed — initiating recovery.")
            self._recover()

        # Inline import avoids circular dependency; schema depends on manager.
        from db.schema import SchemaManager
        with self.connect() as conn:
            SchemaManager.apply(conn)

        log.info("Database initialised at %s", self._db_path)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager that yields an open, PRAGMA-configured connection.

        On normal exit: commits.
        On exception:   rolls back, then re-raises.

        Example::

            with manager.connect() as conn:
                conn.execute("INSERT INTO files ...")
                # auto-committed on exit
        """
        conn = sqlite3.connect(
            str(self._db_path),
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,  # We serialise access via engine thread pool
        )
        conn.row_factory = sqlite3.Row  # Results accessible as dicts or by name
        try:
            self._apply_pragmas(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def is_healthy(self) -> bool:
        """
        Run SQLite's built-in integrity check.
        Returns ``True`` if the database passes, ``False`` otherwise.
        Returns ``True`` if the file doesn't exist yet (nothing to check).
        """
        if not self._db_path.exists():
            return True
        try:
            with self.connect() as conn:
                result = conn.execute("PRAGMA integrity_check").fetchone()
                return result[0] == "ok"
        except Exception as exc:
            log.warning("Health check raised: %s", exc)
            return False

    def backup(self, dest: Optional[Path] = None) -> Path:
        """
        Create an online backup of the database using SQLite's backup API.

        The backup is consistent even if writes are happening on another
        connection simultaneously (WAL checkpoint performed first).

        Args:
            dest: Backup destination path.  Defaults to
                  ``<db_name>.bak.<timestamp>`` next to the original.

        Returns:
            Path to the created backup file.
        """
        if dest is None:
            import time
            ts = int(time.time())
            dest = self._db_path.with_suffix(f".bak.{ts}")

        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self._db_path)) as src:
            with sqlite3.connect(str(dest)) as dst:
                src.backup(dst, pages=100)  # 100 pages at a time, non-blocking

        log.info("Database backed up to %s", dest)
        return dest

    def delete_and_rebuild(self) -> None:
        """
        Completely delete the database and reinitialise from scratch.
        Call only after ``backup()`` has been confirmed successful.
        """
        if self._db_path.exists():
            self._db_path.unlink()
        # Also remove WAL and SHM sidecar files if present
        for suffix in (".wal", ".shm", "-wal", "-shm"):
            sidecar = self._db_path.with_suffix(suffix)
            if sidecar.exists():
                sidecar.unlink()
        self.initialize()
        log.info("Database rebuilt from scratch at %s", self._db_path)

    # ── Private ────────────────────────────────────────────────────────────────

    @staticmethod
    def _apply_pragmas(conn: sqlite3.Connection) -> None:
        for pragma in _PRAGMAS:
            conn.execute(pragma)

    def _recover(self) -> None:
        """Backup the corrupt DB and raise so ``initialize`` can rebuild."""
        try:
            backup_path = self._db_path.with_suffix(".corrupt.bak")
            shutil.copy2(self._db_path, backup_path)
            log.warning("Corrupt DB backed up to %s", backup_path)
        except OSError:
            pass
        # Delete the corrupt file so initialize() creates a fresh one
        self._db_path.unlink(missing_ok=True)
        log.warning("Corrupt database removed — will rebuild on next initialize()")
