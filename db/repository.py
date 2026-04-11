"""
DDAS v2 — File repository (v2: BLAKE3 single-algorithm design).

Changes from v1:
  - FileRecord no longer has: hash_algo, extension, scan_state
  - get_by_partial_hash / get_by_full_hash no longer take an algo parameter
  - get_duplicate_groups no longer groups by hash_algo
  - get_stats simplified (no scan_state counts, no extension counts)
  - Removed: get_by_extension(), count_by_scan_state(), delete_by_paths() batch

Pipeline: size → partial_hash → full_hash (BLAKE3 exclusively)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from db.connection import DatabaseManager

log = logging.getLogger(__name__)


# ─── Transfer Object ──────────────────────────────────────────────────────────

@dataclass
class FileRecord:
    """
    Represents one row in the ``files`` table (schema v2).

    Mirrors the 7-column schema exactly.
    ``id`` is None for records not yet persisted.
    ``indexed_at`` defaults to the current Unix timestamp.
    """
    path:          str
    size:          int
    partial_hash:  Optional[str]  = field(default=None)
    full_hash:     Optional[str]  = field(default=None)
    last_modified: int            = field(default=0)
    indexed_at:    int            = field(default_factory=lambda: int(time.time()))
    id:            Optional[int]  = field(default=None)

    @classmethod
    def from_path(cls, path: str | Path) -> "FileRecord":
        """
        Construct a minimal FileRecord from a filesystem path.
        Reads size and mtime; leaves hashes as None.
        Raises ``FileNotFoundError`` if the path does not exist.
        """
        p = Path(path)
        stat = p.stat()
        return cls(
            path          = str(p),
            size          = stat.st_size,
            last_modified = int(stat.st_mtime),
        )

    def to_dict(self) -> dict:
        """Serialise to dict, omitting ``id`` (DB-managed)."""
        d = asdict(self)
        d.pop("id", None)
        return d

    @property
    def is_fully_hashed(self) -> bool:
        return self.full_hash is not None

    @property
    def is_partially_hashed(self) -> bool:
        return self.partial_hash is not None and self.full_hash is None


# ─── Repository ───────────────────────────────────────────────────────────────

class FileRepository:
    """
    Typed data access layer for the ``files`` table.

    All SQL is encapsulated here — no other module uses raw SQL.
    Methods map directly to deduplication pipeline stages:

        Stage 1 → get_by_size()
        Stage 2 → get_by_partial_hash()
        Stage 3 → get_by_full_hash()
        UI      → get_duplicate_groups(), get_stats()
        Recon   → get_all_paths(), delete_by_path()

    Args:
        db_manager: An initialised ``DatabaseManager`` instance.
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager

    # ── Write operations ──────────────────────────────────────────────────────

    def upsert(self, record: FileRecord) -> int:
        """
        Insert a new record or replace an existing one (matched on path).
        Returns the row ``id`` of the inserted/replaced record.
        """
        sql = """
            INSERT OR REPLACE INTO files
                (path, size, partial_hash, full_hash, last_modified, indexed_at)
            VALUES
                (:path, :size, :partial_hash, :full_hash, :last_modified, :indexed_at)
        """
        with self._db.connect() as conn:
            cursor = conn.execute(sql, record.to_dict())
            return cursor.lastrowid

    def update_partial_hash(self, path: str, partial_hash: str) -> None:
        """
        Stage 2 completed: store the BLAKE3 partial hash for this file.
        Called after hashing first 128 KB + last 128 KB.
        """
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE files SET partial_hash = ?, indexed_at = ? WHERE path = ?",
                (partial_hash, int(time.time()), path),
            )

    def update_full_hash(self, path: str, full_hash: str) -> None:
        """
        Stage 3 completed: store the BLAKE3 full hash for this file.
        Called only when a Stage 2 collision was found.
        """
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE files SET full_hash = ?, indexed_at = ? WHERE path = ?",
                (full_hash, int(time.time()), path),
            )

    def delete_by_path(self, path: str) -> bool:
        """Remove a stale file record. Returns True if a row was deleted."""
        with self._db.connect() as conn:
            cursor = conn.execute("DELETE FROM files WHERE path = ?", (path,))
            return cursor.rowcount > 0

    # ── Read — single record ──────────────────────────────────────────────────

    def get_by_path(self, path: str) -> Optional[FileRecord]:
        """Look up a single file record by its absolute path."""
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM files WHERE path = ?", (path,)
            ).fetchone()
        return self._to_record(row) if row else None

    # ── Read — Stage 1: size candidates ──────────────────────────────────────

    def get_by_size(self, size: int) -> list[FileRecord]:
        """
        Return all indexed files with the given byte size.
        Stage 1 of the deduplication pipeline.
        """
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM files WHERE size = ?", (size,)
            ).fetchall()
        return [self._to_record(r) for r in rows]

    # ── Read — Stage 2: partial hash candidates ───────────────────────────────

    def get_by_partial_hash(self, partial_hash: str) -> list[FileRecord]:
        """
        Return files whose BLAKE3 partial hash matches.
        Stage 2 — narrows candidates before expensive full hash.
        """
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM files WHERE partial_hash = ?", (partial_hash,)
            ).fetchall()
        return [self._to_record(r) for r in rows]

    # ── Read — Stage 3: full hash confirmation ────────────────────────────────

    def get_by_full_hash(self, full_hash: str) -> list[FileRecord]:
        """
        Return all files sharing this full BLAKE3 hash.
        A result with 2+ records = confirmed duplicate group.
        """
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM files WHERE full_hash = ?", (full_hash,)
            ).fetchall()
        return [self._to_record(r) for r in rows]

    # ── Read — UI / Reconciliation ────────────────────────────────────────────

    def get_all_paths(self) -> list[str]:
        """
        Return every indexed path.
        Used by the reconciler to diff against the live filesystem.
        """
        with self._db.connect() as conn:
            rows = conn.execute("SELECT path FROM files").fetchall()
        return [r[0] for r in rows]

    def get_duplicate_groups(self) -> list[dict]:
        """
        Return all confirmed duplicate groups for the UI Duplicates page.

        Returns a list of dicts, each with:
          full_hash, file_count, total_size, wasted_bytes, files (list[FileRecord])

        Sorted by wasted_bytes descending (largest waste first).
        """
        group_sql = """
            SELECT full_hash, COUNT(*) AS file_count, SUM(size) AS total_size
              FROM files
             WHERE full_hash IS NOT NULL
             GROUP BY full_hash
            HAVING COUNT(*) > 1
             ORDER BY total_size DESC
        """
        with self._db.connect() as conn:
            group_rows = conn.execute(group_sql).fetchall()
            results: list[dict] = []
            for g in group_rows:
                file_rows = conn.execute(
                    "SELECT * FROM files WHERE full_hash = ?", (g["full_hash"],)
                ).fetchall()
                results.append({
                    "full_hash":    g["full_hash"],
                    "file_count":   g["file_count"],
                    "total_size":   g["total_size"],
                    "wasted_bytes": g["total_size"] - (g["total_size"] // g["file_count"]),
                    "files":        [self._to_record(r) for r in file_rows],
                })
        return results

    def count(self) -> int:
        """Total number of indexed files."""
        with self._db.connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM files").fetchone()
        return row[0] if row else 0

    def get_stats(self) -> dict:
        """
        Aggregated statistics for the Overview stat cards and DB Stats tab.

        Keys:
          total_files, duplicate_groups, total_wasted_bytes,
          files_partial_hashed, files_fully_hashed,
          db_path, db_size_bytes
        """
        with self._db.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

            dup_groups = conn.execute("""
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM files WHERE full_hash IS NOT NULL
                    GROUP BY full_hash HAVING COUNT(*) > 1
                )
            """).fetchone()[0]

            wasted = conn.execute("""
                SELECT COALESCE(SUM(wasted), 0) FROM (
                    SELECT (SUM(size) - MAX(size)) AS wasted
                      FROM files
                     WHERE full_hash IS NOT NULL
                     GROUP BY full_hash HAVING COUNT(*) > 1
                )
            """).fetchone()[0]

            partial = conn.execute(
                "SELECT COUNT(*) FROM files WHERE partial_hash IS NOT NULL"
            ).fetchone()[0]

            full = conn.execute(
                "SELECT COUNT(*) FROM files WHERE full_hash IS NOT NULL"
            ).fetchone()[0]

        db_size = self._db.path.stat().st_size if self._db.path.exists() else 0

        return {
            "total_files":          total,
            "duplicate_groups":     dup_groups,
            "total_wasted_bytes":   wasted,
            "files_partial_hashed": partial,
            "files_fully_hashed":   full,
            "db_path":              str(self._db.path),
            "db_size_bytes":        db_size,
        }

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _to_record(row: "sqlite3.Row") -> FileRecord:
        return FileRecord(
            id            = row["id"],
            path          = row["path"],
            size          = row["size"],
            partial_hash  = row["partial_hash"],
            full_hash     = row["full_hash"],
            last_modified = row["last_modified"],
            indexed_at    = row["indexed_at"],
        )
