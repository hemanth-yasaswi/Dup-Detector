"""
System tray application.
Provides the tray icon, right-click menu, and duplicate alert QDialog.
This is the ONLY file that imports PyQt6 widgets (QDialog, QSystemTrayIcon, etc.)
besides main.py.
"""

import os

from PyQt6.QtWidgets import (
    QApplication,
    QSystemTrayIcon,
    QMenu,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
)
from PyQt6.QtGui  import QIcon, QPixmap, QColor, QPainter
from PyQt6.QtCore import Qt, QSize, pyqtSlot, QObject

from core.signals  import signals
from core.settings import settings
from services.monitoring_service import monitor
from utils.logger  import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_colored_icon(color: QColor, size: int = 16) -> QIcon:
    """Create a solid-color square QIcon as a tray icon placeholder."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(color)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(0, 0, size, size, 3, 3)
    painter.end()
    return QIcon(pixmap)


def _format_size(path: str) -> str:
    """
    Return human-readable file size string.
    e.g. "2.4 MB", "512 KB", "1.1 GB"
    Returns "unknown" if file is inaccessible.
    """
    try:
        size = os.path.getsize(path)
        if size >= 1024 ** 3:
            return f"{size / (1024 ** 3):.1f} GB"
        if size >= 1024 ** 2:
            return f"{size / (1024 ** 2):.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Duplicate Alert Dialog
# ---------------------------------------------------------------------------

class DuplicateAlertDialog(QDialog):
    """
    Modal dialog shown when a duplicate file is detected.

    Layout:
    ┌──────────────────────────────────────────────┐
    │  Duplicate File Detected                      │
    │                                              │
    │  Original:   /path/to/original/file.txt      │
    │  Duplicate:  /path/to/duplicate/file.txt     │
    │                                              │
    │  Sizes: 2.4 MB each                          │
    │                                              │
    │  [Keep Existing]  [Keep Both]  [Cancel]      │
    └──────────────────────────────────────────────┘

    Properties after exec():
      .chosen_action : str — "keep_existing" | "keep_both" | "cancel"
    """

    def __init__(self, original_path: str, duplicate_path: str, parent=None) -> None:
        super().__init__(parent)
        self.original_path  = original_path
        self.duplicate_path = duplicate_path
        self.chosen_action  = "cancel"
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the dialog layout."""
        self.setWindowTitle("DDAS — Duplicate Detected")
        self.setFixedWidth(520)
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setStyleSheet("""
            QDialog {
                background-color: #f8f9fa;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel#title {
                font-size: 16px;
                font-weight: bold;
                color: #1a1a2e;
                margin-bottom: 4px;
            }
            QLabel#subtitle {
                font-size: 12px;
                color: #6c757d;
                margin-bottom: 12px;
            }
            QLabel.fieldLabel {
                font-size: 11px;
                font-weight: bold;
                color: #495057;
            }
            QLabel.fieldValue {
                font-size: 11px;
                color: #212529;
                background-color: #e9ecef;
                border-radius: 4px;
                padding: 4px 6px;
            }
            QLabel#sizeLabel {
                font-size: 11px;
                color: #6c757d;
                margin-top: 4px;
            }
            QPushButton {
                font-size: 12px;
                font-weight: 600;
                padding: 8px 18px;
                border-radius: 6px;
                border: none;
                min-width: 110px;
            }
            QPushButton#btnKeepExisting {
                background-color: #4682b4;
                color: white;
            }
            QPushButton#btnKeepExisting:hover {
                background-color: #3a6fa0;
            }
            QPushButton#btnKeepBoth {
                background-color: #28a745;
                color: white;
            }
            QPushButton#btnKeepBoth:hover {
                background-color: #218838;
            }
            QPushButton#btnCancel {
                background-color: #e9ecef;
                color: #495057;
            }
            QPushButton#btnCancel:hover {
                background-color: #dee2e6;
            }
        """)

        root_layout = QVBoxLayout(self)
        root_layout.setSpacing(8)
        root_layout.setContentsMargins(20, 20, 20, 16)

        # --- Title ---
        title_lbl = QLabel("🔍  Duplicate File Detected")
        title_lbl.setObjectName("title")
        root_layout.addWidget(title_lbl)

        subtitle_lbl = QLabel("The following file appears to be an exact duplicate.")
        subtitle_lbl.setObjectName("subtitle")
        root_layout.addWidget(subtitle_lbl)

        # --- Separator ---
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setStyleSheet("color: #dee2e6;")
        root_layout.addWidget(sep1)

        # --- Original path ---
        orig_label_lbl = QLabel("Original file:")
        orig_label_lbl.setProperty("class", "fieldLabel")
        orig_label_lbl.setObjectName("origLabel")
        orig_label_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #495057;")
        root_layout.addWidget(orig_label_lbl)

        orig_value_lbl = QLabel(self.original_path)
        orig_value_lbl.setStyleSheet(
            "font-size: 11px; color: #212529; background-color: #e9ecef;"
            " border-radius: 4px; padding: 4px 6px;"
        )
        orig_value_lbl.setWordWrap(True)
        orig_value_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root_layout.addWidget(orig_value_lbl)

        # --- Duplicate path ---
        dup_label_lbl = QLabel("Duplicate file:")
        dup_label_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #c0392b;")
        root_layout.addWidget(dup_label_lbl)

        dup_value_lbl = QLabel(self.duplicate_path)
        dup_value_lbl.setStyleSheet(
            "font-size: 11px; color: #212529; background-color: #fdecea;"
            " border-radius: 4px; padding: 4px 6px;"
        )
        dup_value_lbl.setWordWrap(True)
        dup_value_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root_layout.addWidget(dup_value_lbl)

        # --- Sizes ---
        orig_size = _format_size(self.original_path)
        dup_size  = _format_size(self.duplicate_path)
        size_text = (
            f"Sizes: {orig_size} (original) / {dup_size} (duplicate)"
            if orig_size != dup_size
            else f"Size: {orig_size} each"
        )
        size_lbl = QLabel(size_text)
        size_lbl.setObjectName("sizeLabel")
        size_lbl.setStyleSheet("font-size: 11px; color: #6c757d; margin-top: 4px;")
        root_layout.addWidget(size_lbl)

        # --- Separator ---
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color: #dee2e6;")
        root_layout.addWidget(sep2)

        # --- Buttons ---
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        btn_keep   = QPushButton("Keep Existing")
        btn_keep.setObjectName("btnKeepExisting")
        btn_keep.setToolTip("Keep the original file, take no action on the duplicate.")
        btn_keep.clicked.connect(self._on_keep_existing)
        btn_layout.addWidget(btn_keep)

        btn_both   = QPushButton("Keep Both")
        btn_both.setObjectName("btnKeepBoth")
        btn_both.setToolTip("Keep both files (rename handled in Phase 2).")
        btn_both.clicked.connect(self._on_keep_both)
        btn_layout.addWidget(btn_both)

        btn_layout.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setObjectName("btnCancel")
        btn_cancel.setToolTip("Close without taking any action.")
        btn_cancel.clicked.connect(self._on_cancel)
        btn_layout.addWidget(btn_cancel)

        root_layout.addLayout(btn_layout)

    def _on_keep_existing(self) -> None:
        self.chosen_action = "keep_existing"
        logger.info("[TRAY] user chose keep_existing for duplicate: %s", self.duplicate_path)
        self.accept()

    def _on_keep_both(self) -> None:
        self.chosen_action = "keep_both"
        logger.info("[TRAY] user chose keep_both for duplicate: %s", self.duplicate_path)
        self.accept()

    def _on_cancel(self) -> None:
        self.chosen_action = "cancel"
        logger.info("[TRAY] user cancelled for duplicate: %s", self.duplicate_path)
        self.reject()


# ---------------------------------------------------------------------------
# Tray Application
# ---------------------------------------------------------------------------

_TRAY_MENU_STYLE = """
    QMenu {
        background-color: #ffffff;
        border: 1px solid #d0d0d0;
        border-radius: 6px;
        padding: 4px 0px;
    }
    QMenu::item {
        padding: 8px 28px 8px 14px;
        font-size: 13px;
        min-width: 160px;
    }
    QMenu::item:selected {
        background-color: #f0f0f0;
    }
    QMenu::item:disabled {
        color: #aaaaaa;
    }
    QMenu::separator {
        height: 1px;
        background: #e5e5e5;
        margin: 3px 0;
    }
"""

class TrayApplication(QObject):
    """
    Manages the QSystemTrayIcon and application lifecycle.
    """

    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self.app  = app
        self.tray: QSystemTrayIcon | None = None
        self._action_start  = None
        self._action_stop   = None
        self._action_status = None
        self._build_tray()
        self._connect_signals()
        self._start_monitoring()

    def _build_tray(self) -> None:
        """
        Create QSystemTrayIcon with menu.

        Menu structure:
          DDAS — Running          ← disabled status label
          ─────────────────────
          Start Monitoring
          Stop Monitoring
          ─────────────────────
          Settings...             ← disabled in Phase 1
          ─────────────────────
          Quit
        """
        icon = _make_colored_icon(QColor(70, 130, 180), size=16)
        self.tray = QSystemTrayIcon(icon, parent=None)
        self.tray.setToolTip("DDAS — Duplicate Detection and Analysis System")

        menu = QMenu()
        menu.setStyleSheet(_TRAY_MENU_STYLE)

        # Status label (disabled — informational only)
        self._action_status = menu.addAction("DDAS — Initializing…")
        self._action_status.setEnabled(False)
        menu.addSeparator()

        # Monitoring controls
        self._action_start = menu.addAction("Start Monitoring")
        self._action_start.triggered.connect(self._on_start_monitoring)

        self._action_stop = menu.addAction("Stop Monitoring")
        self._action_stop.triggered.connect(self._on_stop_monitoring)
        self._action_stop.setEnabled(False)

        menu.addSeparator()

        # Settings placeholder (Phase 3)
        action_settings = menu.addAction("Settings…")
        action_settings.setEnabled(False)

        menu.addSeparator()

        # Quit
        action_quit = menu.addAction("Quit")
        action_quit.triggered.connect(self._on_quit)

        self.tray.setContextMenu(menu)
        self.tray.show()
        logger.debug("[TRAY] system tray icon created.")

    def _connect_signals(self) -> None:
        """Connect AppSignals to local slots."""
        signals.duplicate_found.connect(self._on_duplicate_found)
        signals.monitoring_started.connect(self._on_monitoring_started)
        signals.monitoring_stopped.connect(self._on_monitoring_stopped)
        logger.debug("[TRAY] signals connected.")

    def _start_monitoring(self) -> None:
        """
        Start monitoring using directories from settings.
        If settings.watched_directories is empty, show a tray message.
        """
        if not settings.watched_directories:
            if self.tray:
                self.tray.showMessage(
                    "DDAS — No Directories",
                    "No watch directories configured. Edit user_prefs.json to add paths.",
                    QSystemTrayIcon.MessageIcon.Warning,
                    5000,
                )
            logger.warning("[TRAY] no watched_directories configured — monitoring not started.")
            return

        monitor.start(settings.watched_directories)

    @pyqtSlot(str, str)
    def _on_duplicate_found(self, original_path: str, duplicate_path: str) -> None:
        """
        Called on main thread when a duplicate is confirmed.

        1. Log the event.
        2. Show DuplicateAlertDialog.
        3. Log the user's chosen action.
        4. Show a tray balloon summary.
        """
        logger.info("[TRAY] duplicate alert: %s", duplicate_path)

        dlg = DuplicateAlertDialog(original_path, duplicate_path, parent=None)
        dlg.exec()

        logger.info("[TRAY] user action for %s: %s", duplicate_path, dlg.chosen_action)

        if self.tray:
            orig_name = os.path.basename(original_path)
            dup_name  = os.path.basename(duplicate_path)
            self.tray.showMessage(
                "DDAS — Duplicate Found",
                f"'{dup_name}' is a duplicate of '{orig_name}'.\nAction: {dlg.chosen_action}",
                QSystemTrayIcon.MessageIcon.Information,
                6000,
            )

    @pyqtSlot()
    def _on_monitoring_started(self) -> None:
        """Update tray tooltip and menu states when monitoring begins."""
        if self._action_status:
            self._action_status.setText("DDAS — Running")
        if self._action_start:
            self._action_start.setEnabled(False)
        if self._action_stop:
            self._action_stop.setEnabled(True)
        if self.tray:
            self.tray.setToolTip("DDAS — Monitoring active")
        logger.debug("[TRAY] monitoring started signal received.")

    @pyqtSlot()
    def _on_monitoring_stopped(self) -> None:
        """Update tray tooltip and menu states when monitoring stops."""
        if self._action_status:
            self._action_status.setText("DDAS — Stopped")
        if self._action_start:
            self._action_start.setEnabled(True)
        if self._action_stop:
            self._action_stop.setEnabled(False)
        if self.tray:
            self.tray.setToolTip("DDAS — Monitoring stopped")
        logger.debug("[TRAY] monitoring stopped signal received.")

    def _on_start_monitoring(self) -> None:
        """Called when 'Start Monitoring' is clicked in the tray menu."""
        monitor.start(settings.watched_directories)

    def _on_stop_monitoring(self) -> None:
        """Called when 'Stop Monitoring' is clicked in the tray menu."""
        monitor.stop()

    def _on_quit(self) -> None:
        """
        Clean shutdown sequence:
        1. monitor.stop()
        2. db.close()
        3. settings.save()
        4. self.app.quit()
        """
        logger.info("[TRAY] application shutting down.")
        from core.database import db as _db  # noqa: import inside method for shutdown safety
        monitor.stop()
        _db.close()
        settings.save()
        self.app.quit()
