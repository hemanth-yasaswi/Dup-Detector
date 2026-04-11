"""
DetectionEngine — processes one file event end-to-end.
Called by MonitoringService worker threads.
Emits signals for duplicates and status updates.
"""

import os
import threading
from pathlib import Path
from typing import Optional

from core.signals  import signals
from core.database import db
from core.settings import settings
from services.hasher import compute_partial_hash, compute_full_hash, is_file_stable
from utils.logger  import get_logger

logger = get_logger(__name__)


class DetectionEngine:
    """
    Stateless processor. Each call to process() is independent.
    Thread-safe — multiple worker threads may call process() concurrently.

    Counters (protected by a lock):
      _total_processed  : int — incremented after every process() call
      _total_duplicates : int — incremented when duplicate_found is emitted
    """

    def __init__(self) -> None:
        self._lock             = threading.Lock()
        self._total_processed  = 0
        self._total_duplicates = 0

    def process(self, file_path: str) -> None:
        """
        Full detection pipeline for a single file.

        All steps are wrapped in a top-level try/except to ensure the
        worker thread never dies silently on an unexpected error.
        """
        is_duplicate = False

        try:
            path_obj = Path(file_path)

            # STEP 1 — Existence check
            if not path_obj.is_file():
                logger.debug("[DETECTION] skipped, not a file: %s", file_path)
                return

            # STEP 2 — Extension filter (case-insensitive)
            if path_obj.suffix.lower() in settings.ignore_extensions:
                logger.debug("[DETECTION] skipped extension: %s", file_path)
                return

            # STEP 3 — Directory filter
            for part in path_obj.parent.parts:
                if part.lower() in settings.ignore_directories:
                    logger.debug("[DETECTION] skipped dir (%s): %s", part, file_path)
                    return

            # STEP 4 — Size check
            try:
                size = os.path.getsize(file_path)
            except OSError as e:
                logger.error("[DETECTION] could not stat file %s: %s", file_path, e)
                signals.file_processed.emit(file_path, "error")
                return

            if size == 0:
                logger.debug("[DETECTION] skipped, zero bytes: %s", file_path)
                return

            if size < settings.min_file_size_bytes:
                logger.debug("[DETECTION] skipped, too small (%d bytes): %s", size, file_path)
                return

            # STEP 5 — File stabilization
            if not is_file_stable(file_path, settings.stabilization_interval, settings.stabilization_retries):
                logger.warning("[DETECTION] file unstable, skipping: %s", file_path)
                signals.file_processed.emit(file_path, "skipped")
                return

            # STEP 6 — DB upsert (discovered)
            db.upsert_file(path=file_path, size_bytes=size, scan_state=0)

            # STEP 7 — Size-based pre-filter
            size_matches = db.find_by_size(size)
            # Filter out the current file itself from matches
            other_size_matches = [r for r in size_matches if r["path"] != file_path]

            if not other_size_matches:
                # No same-size candidates — compute partial hash and store, but no duplicate possible
                partial_solo = compute_partial_hash(file_path)
                if partial_solo is not None:
                    db.upsert_file(path=file_path, size_bytes=size, partial_hash=partial_solo, scan_state=1)
                signals.file_processed.emit(file_path, "normal")
                self._increment_counters(is_duplicate=False)
                signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)
                return

            # STEP 8 — Partial hash
            partial = compute_partial_hash(file_path)
            if partial is None:
                logger.error("[DETECTION] partial hash failed for: %s", file_path)
                db.upsert_file(path=file_path, size_bytes=size, status="error", scan_state=0)
                signals.file_processed.emit(file_path, "error")
                self._increment_counters(is_duplicate=False)
                signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)
                return

            db.upsert_file(path=file_path, size_bytes=size, partial_hash=partial, scan_state=1)

            # STEP 9 — Partial hash lookup
            partial_candidates = db.find_by_partial_hash(partial, exclude_path=file_path)
            if not partial_candidates:
                signals.file_processed.emit(file_path, "normal")
                self._increment_counters(is_duplicate=False)
                signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)
                return

            # STEP 10 — Full hash
            full = compute_full_hash(file_path)
            if full is None:
                logger.error("[DETECTION] full hash failed for: %s", file_path)
                db.upsert_file(path=file_path, size_bytes=size, status="error", scan_state=1)
                signals.file_processed.emit(file_path, "error")
                self._increment_counters(is_duplicate=False)
                signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)
                return

            db.upsert_file(path=file_path, size_bytes=size, full_hash=full, scan_state=2)

            # STEP 11 — Full hash lookup
            full_matches = db.find_by_full_hash(full, exclude_path=file_path)
            if not full_matches:
                signals.file_processed.emit(file_path, "normal")
                self._increment_counters(is_duplicate=False)
                signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)
                return

            # STEP 12 — Duplicate confirmed — emit only for first match
            original_path = full_matches[0]["path"]
            db.upsert_file(path=file_path, size_bytes=size, status="duplicate", scan_state=2)
            signals.duplicate_found.emit(original_path, file_path)
            logger.info(
                "[DETECTION] duplicate confirmed: %s matches %s",
                file_path,
                original_path,
            )
            is_duplicate = True
            signals.file_processed.emit(file_path, "duplicate")

            # STEP 13 — Update counters and emit stats
            self._increment_counters(is_duplicate=True)
            signals.scan_stats_updated.emit(self._total_processed, self._total_duplicates)

        except Exception as e:
            logger.error("[DETECTION] unexpected error processing %s: %s", file_path, e)
            signals.file_processed.emit(file_path, "error")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _increment_counters(self, is_duplicate: bool) -> None:
        """Thread-safe counter increment."""
        with self._lock:
            self._total_processed += 1
            if is_duplicate:
                self._total_duplicates += 1

    def get_stats(self) -> dict:
        """Return {"total_processed": int, "total_duplicates": int}."""
        with self._lock:
            return {
                "total_processed":  self._total_processed,
                "total_duplicates": self._total_duplicates,
            }


# Module-level singleton
engine = DetectionEngine()
