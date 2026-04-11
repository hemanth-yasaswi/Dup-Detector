"""
DDAS v2 — Main application window.

Responsibilities:
  - Compose the sidebar + stacked-page layout.
  - Wire sidebar page_changed signal → stacked widget.
  - Wire Settings signals → theme/sidebar/daemon adapters.
  - Override closeEvent to hide instead of destroy.
  - Apply the saved theme on first show.

Design notes:
  - The window is created once and reused for the entire app lifetime.
    This is intentional: avoids re-initialising widget state on reopen.
  - No timer, no polling, no thread started here.
    All heavy lifting is done in core/ (Phase 3–5).
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QStackedWidget,
)

from config import settings as cfg
from ui.theme import apply_theme
from ui.sidebar import SidebarWidget
from ui.pages.dashboard  import DashboardPage
from ui.pages.duplicates import DuplicatesPage
from ui.pages.analytics  import AnalyticsPage
from ui.pages.settings   import SettingsPage
from ui.pages.developer  import DeveloperPage


class MainWindow(QMainWindow):
    """
    Central application window.

    Page indices (must match SidebarWidget _NAV_ITEMS ordering):
      0 — Dashboard
      1 — Duplicates
      2 — Analytics
      3 — Settings
      4 — Developer Mode
    """

    def __init__(self, app, parent=None) -> None:
        """
        Args:
            app: The running QApplication instance (needed for theme swaps).
        """
        super().__init__(parent)
        self._app = app
        self._prefs = cfg.load_user_prefs()

        self.setWindowTitle(f"{cfg.APP_NAME} — {cfg.APP_DISPLAY_NAME}")
        self.setMinimumSize(cfg.WINDOW_MIN_WIDTH, cfg.WINDOW_MIN_HEIGHT)

        self._build_ui()
        self._connect_signals()

        # Apply the saved theme immediately.
        apply_theme(self._app, self._prefs.get("theme", cfg.DEFAULT_THEME))

        # Restore developer mode sidebar state.
        dev_enabled = self._prefs.get("developer_mode", False)
        self._sidebar.set_developer_mode_visible(dev_enabled)

    # ── Public API ─────────────────────────────────────────────────────────────

    def show_and_raise(self) -> None:
        """Bring the window to front. Called from TrayManager signal."""
        self.show()
        self.raise_()
        self.activateWindow()

    # ── Private — build ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("ContentArea")
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Sidebar
        self._sidebar = SidebarWidget()
        root_layout.addWidget(self._sidebar)

        # Stacked content area
        self._stack = QStackedWidget()
        self._stack.setObjectName("ContentArea")
        root_layout.addWidget(self._stack, stretch=1)

        # Pages — order must match _NAV_ITEMS in sidebar.py
        self.dashboard_page  = DashboardPage()
        self.duplicates_page = DuplicatesPage()
        self.analytics_page  = AnalyticsPage()
        self.settings_page   = SettingsPage()
        self.developer_page  = DeveloperPage()

        self._stack.addWidget(self.dashboard_page)   # index 0
        self._stack.addWidget(self.duplicates_page)  # index 1
        self._stack.addWidget(self.analytics_page)   # index 2
        self._stack.addWidget(self.settings_page)    # index 3
        self._stack.addWidget(self.developer_page)   # index 4

        self._stack.setCurrentIndex(0)

    def _connect_signals(self) -> None:
        # Sidebar → stack page switch
        self._sidebar.page_changed.connect(self._stack.setCurrentIndex)

        # Settings → theme
        self.settings_page.theme_changed.connect(self._on_theme_changed)

        # Settings → developer mode sidebar toggle
        self.settings_page.developer_mode_changed.connect(
            self._sidebar.set_developer_mode_visible
        )

        # Settings → developer mode page visibility guard
        self.settings_page.developer_mode_changed.connect(
            self._on_developer_mode_changed
        )

    # ── Slots ──────────────────────────────────────────────────────────────────

    @pyqtSlot(str)
    def _on_theme_changed(self, theme: str) -> None:
        apply_theme(self._app, theme)

    @pyqtSlot(bool)
    def _on_developer_mode_changed(self, enabled: bool) -> None:
        """If developer mode is disabled while on that page, return to Dashboard."""
        if not enabled and self._stack.currentIndex() == 4:
            self._stack.setCurrentIndex(0)

    # ── Qt overrides ───────────────────────────────────────────────────────────

    def closeEvent(self, event: QCloseEvent) -> None:
        """
        Override close → hide.
        The daemon continues running. The tray icon remains active.
        Only "Quit DDAS" from the tray actually terminates the process.
        """
        event.ignore()
        self.hide()
