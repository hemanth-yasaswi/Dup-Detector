"""
Startup reconciliation — run once at app start in a background thread.
Removes DB records for files that no longer exist on disk.
"""

import os
import threading

from core.database import db
from utils.logger  import get_logger

logger = get_logger(__name__)


def run_reconciliation() -> None:
    """
    Reconcile the database against the actual filesystem.

    Steps:
    1. Retrieve all paths from DB: db.get_all_paths()
    2. For each path:
         If not os.path.isfile(path):
           db.delete_file(path)
           log INFO: [RECONCILE] removed stale: {path}
    3. Log INFO: [RECONCILE] complete. checked={total} removed={removed}

    Runs in a daemon thread. Any exception is caught and logged — never propagates.
    """
    try:
        all_paths = db.get_all_paths()
        total   = len(all_paths)
        removed = 0

        for path in all_paths:
            try:
                if not os.path.isfile(path):
                    db.delete_file(path)
                    logger.info("[RECONCILE] removed stale: %s", path)
                    removed += 1
            except Exception as e:
                logger.error("[RECONCILE] error processing path %s: %s", path, e)

        logger.info("[RECONCILE] complete. checked=%d removed=%d", total, removed)

    except Exception as e:
        logger.error("[RECONCILE] reconciliation failed unexpectedly: %s", e)


def start_reconciliation_thread() -> threading.Thread:
    """
    Start reconciliation in a background daemon thread.
    Returns the thread object (caller does not need to join it).
    """
    t = threading.Thread(
        target=run_reconciliation,
        daemon=True,
        name="ddas-reconcile",
    )
    t.start()
    return t
