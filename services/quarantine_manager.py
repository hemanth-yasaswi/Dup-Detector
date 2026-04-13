"""
QuarantineManager — moves files to a hidden quarantine directory.

Quarantine directory: settings.quarantine_path (default: ~/.ddas_quarantine)
Naming: {original_stem}_{uuid8}{ext} — never overwrites.
Restore: moves file back to a specified destination path.

No signals emitted here — caller (FileExecutor) emits signals.
"""

import os
import uuid
import shutil
from pathlib import Path

from core.settings import settings
from utils.logger  import get_logger

logger = get_logger(__name__)


class QuarantineManager:

    def _ensure_quarantine_dir(self) -> str:
        """
        Ensure the quarantine directory exists.
        Returns the quarantine directory path.
        Raises OSError if it cannot be created.
        """
        q_path = settings.quarantine_path
        os.makedirs(q_path, exist_ok=True)
        return q_path

    def move_to_quarantine(self, src_path: str, original_name: str) -> str:
        """
        Move the file at src_path into the quarantine directory.

        src_path:      current path of the file (may be a .ddas_tmp path)
        original_name: the original filename before any tmp rename
                       (used to construct the quarantine filename)

        Returns the final quarantine path.
        Raises OSError on failure.

        Naming: {stem}_{uuid8[:8]}{ext}
        Guarantees no collision via UUID.
        """
        q_dir = self._ensure_quarantine_dir()
        orig  = Path(original_name)
        uid   = uuid.uuid4().hex[:8]
        q_filename = f"{orig.stem}_{uid}{orig.suffix}"
        q_path = os.path.join(q_dir, q_filename)

        shutil.move(src_path, q_path)
        logger.info("[QUARANTINE] moved %s → %s", src_path, q_path)
        return q_path

    def restore_file(self, quarantine_path: str, destination_path: str) -> bool:
        """
        Restore a quarantined file to destination_path.

        If destination_path already exists, renames with _restored_{uuid8} suffix.
        Returns True on success, False on error.
        """
        if not os.path.isfile(quarantine_path):
            logger.error("[QUARANTINE] restore: not found: %s", quarantine_path)
            return False

        dest = Path(destination_path)
        if dest.exists():
            uid = uuid.uuid4().hex[:8]
            dest = dest.parent / f"{dest.stem}_restored_{uid}{dest.suffix}"

        try:
            shutil.move(quarantine_path, str(dest))
            logger.info("[QUARANTINE] restored %s → %s", quarantine_path, dest)
            return True
        except OSError as e:
            logger.error("[QUARANTINE] restore failed: %s — %s", quarantine_path, e)
            return False

    def list_quarantined(self) -> list[dict]:
        """
        List all files currently in the quarantine directory.
        Returns list of dicts: {filename, path, size_bytes, mtime}
        Returns [] if quarantine dir does not exist or on any error.
        """
        try:
            q_dir = settings.quarantine_path
            if not os.path.isdir(q_dir):
                return []
            result = []
            for fname in os.listdir(q_dir):
                fpath = os.path.join(q_dir, fname)
                if os.path.isfile(fpath):
                    stat = os.stat(fpath)
                    result.append({
                        "filename":   fname,
                        "path":       fpath,
                        "size_bytes": stat.st_size,
                        "mtime":      stat.st_mtime,
                    })
            return result
        except Exception as e:
            logger.error("[QUARANTINE] list failed: %s", e)
            return []
