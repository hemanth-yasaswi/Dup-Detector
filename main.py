"""
DDAS — Duplicate Detection and Analysis System
Entry point.
"""

import sys
import os

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore    import Qt

# Must be imported before anything that uses them
from utils.logger           import get_logger
from core.settings          import settings
from core.database          import db
from startup.reconciliation import start_reconciliation_thread
from ui.tray                import TrayApplication

logger = get_logger(__name__)


def main() -> int:
    """
    Application startup sequence:

    1. Create QApplication with sys.argv.
       Set: app.setQuitOnLastWindowClosed(False)  ← critical for tray-only app

    2. Initialize database: db.initialize()

    3. Run reconciliation in background: start_reconciliation_thread()

    4. Create TrayApplication(app).
       TrayApplication.__init__ handles signal wiring and monitoring start.

    5. Log INFO: [MAIN] DDAS started. watching={settings.watched_directories}

    6. return app.exec()
    """
    app = QApplication(sys.argv)

    # Critical for a tray-only app — prevents exit when dialog closes
    app.setQuitOnLastWindowClosed(False)

    # Initialise DB (creates tables / indexes if needed)
    db.initialize()

    # Reconcile stale DB records against filesystem (background thread)
    start_reconciliation_thread()

    # Build and show tray (also wires signals and starts monitoring)
    _tray_app = TrayApplication(app)  # noqa: kept alive via local reference for Qt ownership

    logger.info("[MAIN] DDAS started. watching=%s", settings.watched_directories)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
