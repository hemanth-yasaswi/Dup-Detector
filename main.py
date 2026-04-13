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
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    # Initialize DB (creates all tables including Phase 2 additions)
    db.initialize()

    # Recover any incomplete operations from a previous crash
    from resolution.journal import journal
    recovered = journal.recover_pending()
    if recovered:
        logger.warning("[MAIN] recovered %d incomplete operations from last session", recovered)

    # Reconcile stale DB records
    start_reconciliation_thread()

    # Build tray
    _tray_app = TrayApplication(app)

    # Build main window and connect to tray
    from ui.main_window import MainWindow
    from ui.theme import apply_theme
    from config.settings import load_user_prefs
    prefs = load_user_prefs()
    _main_window = MainWindow(app)
    apply_theme(app, prefs.get("theme", "dark"))
    _tray_app.set_main_window(_main_window)
    # Do NOT call _main_window.show() here — window opens only on tray click

    logger.info("[MAIN] DDAS started. watching=%s", settings.watched_directories)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
