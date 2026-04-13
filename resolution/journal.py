"""
Operation journal for DDAS Phase 2.

Records every file action before execution and marks it complete/failed after.
On startup, incomplete operations are detected and rolled back.

All methods are synchronous and thread-safe (uses core.database lock).
"""

import os
import time
from utils.logger  import get_logger
from core.database import db

logger = get_logger(__name__)


class OperationJournal:
    """
    Write-ahead log for duplicate resolution actions.

    Usage pattern:
        op_id = journal.begin(original, duplicate, action, tmp_path)
        try:
            # ... perform file operation ...
            journal.commit(op_id)
        except Exception as e:
            journal.fail(op_id, str(e))
    """

    def begin(
        self,
        original_path:  str,
        duplicate_path: str,
        action:         str,
        tmp_path:       str | None = None,
    ) -> int | None:
        """
        Record the start of an operation. Returns op_id or None on DB error.
        Must be called BEFORE any file system change.
        """
        op_id = db.log_operation(original_path, duplicate_path, action, tmp_path)
        if op_id:
            logger.info(
                "[JOURNAL] begin op_id=%d action=%s duplicate=%s",
                op_id, action, duplicate_path
            )
        return op_id

    def commit(self, op_id: int | None) -> None:
        """Mark operation as completed. Safe to call with None op_id."""
        if op_id is None:
            return
        db.complete_operation(op_id, "completed")
        logger.info("[JOURNAL] committed op_id=%d", op_id)

    def fail(self, op_id: int | None, error_msg: str) -> None:
        """Mark operation as failed. Safe to call with None op_id."""
        if op_id is None:
            return
        db.complete_operation(op_id, "failed", error_msg)
        logger.error("[JOURNAL] failed op_id=%d error=%s", op_id, error_msg)

    def recover_pending(self) -> int:
        """
        Called at startup. Finds all pending operations and attempts rollback.

        Rollback strategy for each pending op:
        - If tmp_path is set AND tmp_path exists on disk:
            Rename tmp_path back to duplicate_path (restores the file).
            Mark op as "rolled_back".
        - If tmp_path is None or does not exist:
            Log WARNING — cannot recover, mark as "failed".

        Returns count of operations processed.
        """
        pending = db.get_pending_operations()
        count = 0
        for op in pending:
            tmp_path = op.get("tmp_path")
            dup_path = op.get("duplicate_path")
            op_id    = op.get("id")
            try:
                if tmp_path and os.path.exists(tmp_path) and dup_path:
                    os.rename(tmp_path, dup_path)
                    db.complete_operation(op_id, "rolled_back")
                    logger.warning(
                        "[JOURNAL] rolled back op_id=%d: restored %s from %s",
                        op_id, dup_path, tmp_path
                    )
                else:
                    db.complete_operation(op_id, "failed", "tmp file missing — cannot recover")
                    logger.warning(
                        "[JOURNAL] could not recover op_id=%d — tmp file missing", op_id
                    )
            except Exception as e:
                logger.error("[JOURNAL] recovery error for op_id=%d: %s", op_id, e)
            count += 1

        if count:
            logger.info("[JOURNAL] startup recovery complete. processed=%d", count)
        return count


# Module-level singleton
journal = OperationJournal()
