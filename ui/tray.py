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
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QTextEdit,
    QWidget,
)
from PyQt6.QtGui  import QIcon, QPixmap, QColor, QPainter
from PyQt6.QtCore import Qt, QSize, pyqtSlot, QObject

from core.signals  import signals
from core.settings import settings
from services.monitoring_service import monitor
from resolution.executor   import executor
from services.preview_service import preview_service
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
    Modal dialog for duplicate resolution.

    Shows:
      - Original file path + size + modified date
      - Duplicate file path + size + modified date
      - Optional side-by-side preview (text diff or image thumbnails)
      - Action buttons: Keep Existing | Keep Both | Quarantine | Replace | Compare | Cancel

    After exec():
      .chosen_action : str — the action selected by the user
                       values: "keep_existing" | "keep_both" | "quarantine"
                                "replace" | "compare" | "cancel"

    Execution of the action is NOT done in this dialog.
    The dialog only captures the choice. TrayApplication._on_duplicate_found
    calls FileExecutor.execute() after the dialog closes.
    """

    def __init__(self, original_path: str, duplicate_path: str, parent=None) -> None:
        super().__init__(parent)
        self.original_path  = original_path
        self.duplicate_path = duplicate_path
        self.chosen_action  = "cancel"

        # Load preview data (fast — capped at 200KB/200 lines)
        self._preview_data = preview_service.compare(original_path, duplicate_path)

        self._build_ui()

    def _build_ui(self) -> None:
        self.setWindowTitle("DDAS — Duplicate Detected")
        self.setMinimumWidth(560)
        self.setMaximumWidth(720)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint)

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
            QPushButton {
                font-size: 12px;
                font-weight: 600;
                padding: 8px 18px;
                border-radius: 6px;
                border: none;
                min-width: 100px;
            }
            QPushButton#btnKeepExisting {
                background-color: #4682b4;
                color: white;
            }
            QPushButton#btnKeepExisting:hover { background-color: #3a6fa0; }
            QPushButton#btnKeepBoth {
                background-color: #28a745;
                color: white;
            }
            QPushButton#btnKeepBoth:hover { background-color: #218838; }
            QPushButton#btnCancel {
                background-color: #e9ecef;
                color: #495057;
            }
            QPushButton#btnCancel:hover { background-color: #dee2e6; }
            QPushButton#btnQuarantine {
                background-color: #e67e22;
                color: white;
            }
            QPushButton#btnQuarantine:hover { background-color: #cf6d17; }
            QPushButton#btnReplace {
                background-color: #8e44ad;
                color: white;
            }
            QPushButton#btnReplace:hover { background-color: #7d3c98; }
            QPushButton#btnCompare {
                background-color: transparent;
                color: #2980b9;
                border: 1px solid #2980b9;
            }
            QPushButton#btnCompare:hover { background-color: #eaf4fb; }
            QTextEdit {
                font-family: 'Consolas', monospace;
                font-size: 11px;
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
        """)

        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(20, 20, 20, 16)

        # --- Title ---
        title = QLabel("Duplicate File Detected")
        title.setObjectName("title")
        root.addWidget(title)

        subtitle = QLabel("Review both files before choosing an action.")
        subtitle.setObjectName("subtitle")
        root.addWidget(subtitle)

        root.addWidget(self._separator())

        # --- File info grid ---
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(4)

        def _info_label(text: str, bold: bool = False) -> QLabel:
            lbl = QLabel(text)
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if bold:
                lbl.setStyleSheet("font-weight: bold; font-size: 11px; color: #495057;")
            else:
                lbl.setStyleSheet(
                    "font-size: 11px; color: #212529; background-color: #e9ecef;"
                    " border-radius: 4px; padding: 4px 6px;"
                )
            return lbl

        fa = self._preview_data.get("file_a", {})
        fb = self._preview_data.get("file_b", {})

        grid.addWidget(_info_label("Original:", bold=True),   0, 0)
        grid.addWidget(_info_label(self.original_path),        0, 1)
        grid.addWidget(_info_label(
            f"{fa.get('size_human','?')} · Modified {fa.get('modified_at','?')}"
        ), 1, 1)

        dup_lbl = _info_label("Duplicate:", bold=True)
        dup_lbl.setStyleSheet("font-weight: bold; font-size: 11px; color: #c0392b;")
        grid.addWidget(dup_lbl, 2, 0)
        dup_path_lbl = _info_label(self.duplicate_path)
        dup_path_lbl.setStyleSheet(
            "font-size: 11px; color: #212529; background-color: #fdecea;"
            " border-radius: 4px; padding: 4px 6px;"
        )
        grid.addWidget(dup_path_lbl, 2, 1)
        grid.addWidget(_info_label(
            f"{fb.get('size_human','?')} · Modified {fb.get('modified_at','?')}"
        ), 3, 1)

        grid.setColumnStretch(1, 1)
        root.addWidget(grid_widget)

        # --- Preview panel (text diff or image thumbnails) ---
        self._add_preview_panel(root)

        root.addWidget(self._separator())

        # --- Buttons ---
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        def _btn(label: str, obj_name: str, slot) -> QPushButton:
            b = QPushButton(label)
            b.setObjectName(obj_name)
            b.clicked.connect(slot)
            return b

        btn_row.addWidget(_btn("Keep Existing",  "btnKeepExisting",  self._on_keep_existing))
        btn_row.addWidget(_btn("Keep Both",       "btnKeepBoth",      self._on_keep_both))
        btn_row.addWidget(_btn("Quarantine",      "btnQuarantine",    self._on_quarantine))
        btn_row.addWidget(_btn("Replace",         "btnReplace",       self._on_replace))
        btn_row.addStretch()
        btn_row.addWidget(_btn("Compare",         "btnCompare",       self._on_compare))
        btn_row.addWidget(_btn("Cancel",          "btnCancel",        self._on_cancel))

        root.addLayout(btn_row)

        # --- Tooltips ---
        self.findChild(QPushButton, "btnKeepExisting").setToolTip(
            "Delete the duplicate. Keep the original."
        )
        self.findChild(QPushButton, "btnKeepBoth").setToolTip(
            "Rename the duplicate so both files coexist."
        )
        self.findChild(QPushButton, "btnQuarantine").setToolTip(
            "Move the duplicate to the quarantine folder. Nothing is deleted."
        )
        self.findChild(QPushButton, "btnReplace").setToolTip(
            "Replace the original file with the duplicate's content."
        )
        self.findChild(QPushButton, "btnCompare").setToolTip(
            "View a side-by-side comparison without taking any action."
        )

    def _add_preview_panel(self, root: QVBoxLayout) -> None:
        """
        Add a preview panel if content is available.
        For text files: show unified diff in a QTextEdit.
        For images: show thumbnails side by side (if Pillow available).
        Skip if neither file has previewable content.
        """

        diff = self._preview_data.get("diff_lines")
        fa   = self._preview_data.get("file_a", {})
        fb   = self._preview_data.get("file_b", {})

        # Text diff
        if diff is not None:
            diff_header = QLabel(
                "No differences found." if not diff
                else f"Diff ({len(diff)} lines shown):"
            )
            diff_header.setStyleSheet("font-size: 11px; font-weight: bold; color: #495057;")
            root.addWidget(diff_header)

            if diff:
                diff_box = QTextEdit()
                diff_box.setReadOnly(True)
                diff_box.setMaximumHeight(140)
                diff_box.setPlainText("\n".join(diff))
                root.addWidget(diff_box)
            return

        # Image thumbnails
        if fa.get("preview_type") == "image" and fa.get("content") and fb.get("content"):
            from PyQt6.QtGui import QPixmap
            thumb_row = QHBoxLayout()

            for label_text, data in [("Original", fa), ("Duplicate", fb)]:
                col = QVBoxLayout()
                lbl = QLabel(label_text)
                lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #495057;")
                lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                col.addWidget(lbl)

                pixmap = QPixmap()
                try:
                    import base64 as _b64
                    pixmap.loadFromData(_b64.b64decode(data["content"]))
                    img_lbl = QLabel()
                    img_lbl.setPixmap(pixmap.scaled(
                        200, 160,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    ))
                    img_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    col.addWidget(img_lbl)
                except Exception:
                    col.addWidget(QLabel("(preview unavailable)"))

                thumb_row.addLayout(col)

            root.addLayout(thumb_row)

    def _separator(self) -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #dee2e6;")
        return sep

    def _on_keep_existing(self) -> None:
        self.chosen_action = "keep_existing"
        logger.info("[TRAY] user chose keep_existing: %s", self.duplicate_path)
        self.accept()

    def _on_keep_both(self) -> None:
        self.chosen_action = "keep_both"
        logger.info("[TRAY] user chose keep_both: %s", self.duplicate_path)
        self.accept()

    def _on_quarantine(self) -> None:
        self.chosen_action = "quarantine"
        logger.info("[TRAY] user chose quarantine: %s", self.duplicate_path)
        self.accept()

    def _on_replace(self) -> None:
        self.chosen_action = "replace"
        logger.info("[TRAY] user chose replace: %s", self.duplicate_path)
        self.accept()

    def _on_compare(self) -> None:
        self.chosen_action = "compare"
        logger.info("[TRAY] user chose compare: %s", self.duplicate_path)
        self.accept()

    def _on_cancel(self) -> None:
        self.chosen_action = "cancel"
        logger.info("[TRAY] user cancelled: %s", self.duplicate_path)
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
        self._main_window   = None
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

        # Open Dashboard
        action_dashboard = menu.addAction("Open Dashboard")
        action_dashboard.triggered.connect(self._on_open_dashboard)

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
        1. Show DuplicateAlertDialog to get user's chosen action.
        2. If action is not "cancel" or "compare": call FileExecutor.execute().
        3. Show tray balloon with result.
        """
        logger.info("[TRAY] duplicate alert: %s", duplicate_path)

        dlg = DuplicateAlertDialog(original_path, duplicate_path, parent=None)
        dlg.exec()

        action = dlg.chosen_action
        logger.info("[TRAY] user action for %s: %s", duplicate_path, action)

        if action in ("cancel", "compare"):
            # No file operation — user is just viewing or dismissed
            if self.tray and action == "compare":
                self.tray.showMessage(
                    "DDAS — Compare",
                    "No action taken. Files have been left unchanged.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )
            return

        # Execute the chosen action
        success = executor.execute(action, original_path, duplicate_path)

        if self.tray:
            orig_name = os.path.basename(original_path)
            dup_name  = os.path.basename(duplicate_path)
            if success:
                action_labels = {
                    "keep_existing": "Duplicate deleted",
                    "keep_both":     "Duplicate renamed — both files kept",
                    "quarantine":    "Duplicate moved to quarantine",
                    "replace":       "Original replaced with duplicate",
                }
                msg = action_labels.get(action, f"Action '{action}' completed")
                self.tray.showMessage(
                    "DDAS — Action Completed",
                    f"{msg}.\nFile: {dup_name}",
                    QSystemTrayIcon.MessageIcon.Information,
                    5000,
                )
            else:
                self.tray.showMessage(
                    "DDAS — Action Failed",
                    f"Could not complete '{action}' for '{dup_name}'.\nSee logs for details.",
                    QSystemTrayIcon.MessageIcon.Warning,
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

    def _on_open_dashboard(self) -> None:
        """Open the main dashboard window."""
        if self._main_window is not None:
            self._main_window.show_and_raise()
        logger.debug("[TRAY] dashboard opened.")

    def set_main_window(self, window) -> None:
        """Called from main.py after MainWindow is created."""
        self._main_window = window
