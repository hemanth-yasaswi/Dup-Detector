"""
FileExecutor — safely executes duplicate resolution actions.

All file operations follow this pattern:
  1. Rename duplicate to .ddas_tmp_{uuid} (safe rename)
  2. Record operation in journal with tmp_path
  3. Execute the chosen action on the tmp file
  4. Commit journal entry
  5. Update DB record
  6. Emit result signal

If any step fails: attempt to restore from tmp_path, mark journal failed.
Never deletes without explicit user instruction.
Never operates on the original file — only on the duplicate.
"""

import os
import uuid
import shutil
import time
from pathlib import Path

from core.signals  import signals
from core.database import db
from core.settings import settings
from resolution.journal import journal
from services.quarantine_manager import QuarantineManager
from utils.logger  import get_logger

logger = get_logger(__name__)

_quarantine = QuarantineManager()


class FileExecutor:
    """
    Executes a user-chosen action on a confirmed duplicate file.
    All methods are called from the main thread (invoked by dialog response).
    All file I/O is synchronous — files are small relative to the operation cost.
    """

    def execute(
        self,
        action:         str,
        original_path:  str,
        duplicate_path: str,
    ) -> bool:
        """
        Dispatch to the appropriate action handler.

        action values:
          "keep_existing"    — rename duplicate to tmp, then delete tmp
          "keep_both"        — rename duplicate to avoid name collision, keep it
          "delete_duplicate" — rename duplicate to tmp, then delete tmp
          "quarantine"       — move duplicate to quarantine folder
          "replace"          — replace original with duplicate content

        Returns True if the action completed successfully, False otherwise.
        Emits signals.action_executed on success.
        Emits signals.action_failed on failure.
        """
        logger.info(
            "[EXECUTOR] executing action=%s original=%s duplicate=%s",
            action, original_path, duplicate_path
        )

        try:
            if action == "keep_existing":
                return self._delete_duplicate(original_path, duplicate_path)
            elif action == "keep_both":
                return self._keep_both(original_path, duplicate_path)
            elif action == "delete_duplicate":
                return self._delete_duplicate(original_path, duplicate_path)
            elif action == "quarantine":
                return self._quarantine(original_path, duplicate_path)
            elif action == "replace":
                return self._replace(original_path, duplicate_path)
            else:
                logger.warning("[EXECUTOR] unknown action: %s", action)
                return False
        except Exception as e:
            logger.error("[EXECUTOR] unexpected error in execute: %s", e)
            signals.action_failed.emit(action, duplicate_path, str(e))
            return False

    def _make_tmp_path(self, duplicate_path: str) -> str:
        """
        Generate a .ddas_tmp path in the same directory as the duplicate.
        Format: {parent_dir}/.ddas_tmp_{uuid8}
        """
        parent = os.path.dirname(duplicate_path)
        tmp_name = f".ddas_tmp_{uuid.uuid4().hex[:8]}"
        return os.path.join(parent, tmp_name)

    def _safe_rename_to_tmp(self, duplicate_path: str) -> str | None:
        """
        Rename duplicate to a tmp path in the same directory.
        Returns the tmp_path on success, None on failure.
        This is Step 1 of every action — makes the operation reversible.
        """
        tmp_path = self._make_tmp_path(duplicate_path)
        try:
            os.rename(duplicate_path, tmp_path)
            logger.debug("[EXECUTOR] renamed to tmp: %s → %s", duplicate_path, tmp_path)
            return tmp_path
        except OSError as e:
            logger.error("[EXECUTOR] failed to rename to tmp: %s — %s", duplicate_path, e)
            return None

    def _restore_from_tmp(self, tmp_path: str, original_name: str) -> None:
        """Attempt to restore a file from its tmp path. Used in rollback."""
        try:
            if os.path.exists(tmp_path):
                os.rename(tmp_path, original_name)
                logger.info("[EXECUTOR] restored from tmp: %s → %s", tmp_path, original_name)
        except OSError as e:
            logger.error("[EXECUTOR] restore failed: %s — %s", tmp_path, e)

    def _delete_duplicate(self, original_path: str, duplicate_path: str) -> bool:
        """
        Delete the duplicate file.
        Safe sequence:
          1. Rename duplicate → .ddas_tmp_{uuid}
          2. Log operation with tmp_path
          3. Delete tmp file
          4. Commit journal
          5. Update DB status
          6. Emit action_executed
        """
        tmp_path = self._safe_rename_to_tmp(duplicate_path)
        if tmp_path is None:
            signals.action_failed.emit("keep_existing", duplicate_path, "could not rename to tmp")
            return False

        op_id = journal.begin(original_path, duplicate_path, "keep_existing", tmp_path)

        try:
            os.remove(tmp_path)
            journal.commit(op_id)
            db.delete_file(duplicate_path)
            signals.action_executed.emit("keep_existing", duplicate_path, original_path)
            logger.info("[EXECUTOR] deleted duplicate: %s", duplicate_path)
            return True
        except OSError as e:
            logger.error("[EXECUTOR] delete failed: %s — %s", tmp_path, e)
            journal.fail(op_id, str(e))
            self._restore_from_tmp(tmp_path, duplicate_path)
            signals.action_failed.emit("keep_existing", duplicate_path, str(e))
            return False

    def _keep_both(self, original_path: str, duplicate_path: str) -> bool:
        """
        Rename the duplicate so both files can coexist.

        Naming strategy:
          Given: report.pdf
          Try:   report_copy.pdf (settings.keep_both_suffix = "_copy")
          If exists: report_copy_2.pdf, report_copy_3.pdf, ...

        The renamed file stays in its current directory.
        No journal entry needed — this is a pure rename, fully reversible.
        """
        p = Path(duplicate_path)
        suffix = settings.keep_both_suffix
        stem   = p.stem
        ext    = p.suffix
        parent = p.parent

        # Find a non-colliding name
        candidate = parent / f"{stem}{suffix}{ext}"
        counter = 2
        while candidate.exists():
            candidate = parent / f"{stem}{suffix}_{counter}{ext}"
            counter += 1
            if counter > 999:
                logger.error("[EXECUTOR] keep_both: could not find free name after 999 tries")
                signals.action_failed.emit(
                    "keep_both", duplicate_path, "no free filename available"
                )
                return False

        try:
            os.rename(duplicate_path, str(candidate))
            # Update DB to reflect new path
            record = db.get_file(duplicate_path)
            if record:
                db.upsert_file(
                    path=str(candidate),
                    size_bytes=record["size_bytes"],
                    partial_hash=record.get("partial_hash"),
                    full_hash=record.get("full_hash"),
                    status="normal",
                    scan_state=record.get("scan_state", 2),
                )
                db.delete_file(duplicate_path)
            signals.action_executed.emit("keep_both", duplicate_path, original_path)
            logger.info("[EXECUTOR] keep_both: renamed %s → %s", duplicate_path, candidate)
            return True
        except OSError as e:
            logger.error("[EXECUTOR] keep_both rename failed: %s — %s", duplicate_path, e)
            signals.action_failed.emit("keep_both", duplicate_path, str(e))
            return False

    def _quarantine(self, original_path: str, duplicate_path: str) -> bool:
        """
        Move the duplicate to the quarantine directory.

        Safe sequence:
          1. Rename duplicate → .ddas_tmp_{uuid}
          2. Log operation
          3. QuarantineManager.quarantine(tmp_path, original_name)
          4. Commit journal
          5. Update DB
          6. Emit file_quarantined
        """
        tmp_path = self._safe_rename_to_tmp(duplicate_path)
        if tmp_path is None:
            signals.action_failed.emit("quarantine", duplicate_path, "could not rename to tmp")
            return False

        op_id = journal.begin(original_path, duplicate_path, "quarantine", tmp_path)

        try:
            quarantine_path = _quarantine.move_to_quarantine(tmp_path, duplicate_path)
            journal.commit(op_id)
            db.delete_file(duplicate_path)

            # Get full_hash for quarantine record (fetch before deleting)
            record = db.get_file(duplicate_path)
            full_hash = record.get("full_hash") if record else None
            size = os.path.getsize(quarantine_path) if os.path.exists(quarantine_path) else 0
            db.log_quarantine(duplicate_path, quarantine_path, size, full_hash)

            signals.file_quarantined.emit(duplicate_path, quarantine_path)
            signals.action_executed.emit("quarantine", duplicate_path, original_path)
            logger.info("[EXECUTOR] quarantined: %s → %s", duplicate_path, quarantine_path)
            return True
        except Exception as e:
            logger.error("[EXECUTOR] quarantine failed: %s — %s", duplicate_path, e)
            journal.fail(op_id, str(e))
            self._restore_from_tmp(tmp_path, duplicate_path)
            signals.action_failed.emit("quarantine", duplicate_path, str(e))
            return False

    def _replace(self, original_path: str, duplicate_path: str) -> bool:
        """
        Replace original file with the duplicate's content.

        Safe sequence:
          1. Rename original → .ddas_tmp_{uuid} (backup of original)
          2. Rename duplicate → original path
          3. Commit journal
          4. Delete original backup (tmp)
          5. Update DB
          6. Emit action_executed

        If any step fails: restore original from tmp, delete moved duplicate.
        """
        if not os.path.isfile(original_path):
            logger.error("[EXECUTOR] replace: original not found: %s", original_path)
            signals.action_failed.emit("replace", duplicate_path, "original file not found")
            return False

        # Backup original
        orig_tmp = self._make_tmp_path(original_path)
        try:
            os.rename(original_path, orig_tmp)
        except OSError as e:
            logger.error("[EXECUTOR] replace: could not backup original: %s", e)
            signals.action_failed.emit("replace", duplicate_path, str(e))
            return False

        op_id = journal.begin(original_path, duplicate_path, "replace", orig_tmp)

        try:
            os.rename(duplicate_path, original_path)
            journal.commit(op_id)

            # Remove the original backup
            try:
                os.remove(orig_tmp)
            except OSError:
                pass  # Not fatal — backup file left behind

            # Update DB: original path now has duplicate's hash
            dup_record = db.get_file(duplicate_path)
            if dup_record:
                db.upsert_file(
                    path=original_path,
                    size_bytes=dup_record["size_bytes"],
                    partial_hash=dup_record.get("partial_hash"),
                    full_hash=dup_record.get("full_hash"),
                    status="normal",
                    scan_state=2,
                )
            db.delete_file(duplicate_path)
            signals.action_executed.emit("replace", duplicate_path, original_path)
            logger.info("[EXECUTOR] replaced: %s with content of %s", original_path, duplicate_path)
            return True

        except OSError as e:
            logger.error("[EXECUTOR] replace failed mid-operation: %s", e)
            journal.fail(op_id, str(e))
            # Restore original
            self._restore_from_tmp(orig_tmp, original_path)
            signals.action_failed.emit("replace", duplicate_path, str(e))
            return False


# Module-level singleton
executor = FileExecutor()
