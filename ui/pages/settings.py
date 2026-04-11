"""
DDAS v2 — Settings page.

Controls:
  • Theme toggle (Dark / Light)
  • Watch directory management (add / remove)
  • Developer Mode toggle (shows/hides sidebar item)

Hashing algorithm is fixed to BLAKE3 and not user-configurable.
All changes are saved to user_prefs.json via config.settings immediately.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFileDialog, QListWidget,
    QFrame, QSizePolicy,
)

from config import settings as cfg


def _page_header(layout: QVBoxLayout, title: str, subtitle: str) -> None:
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    layout.addWidget(t)
    layout.addWidget(s)


def _section_header(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionHeader")
    return lbl


def _hline() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    return f


class SettingsPage(QWidget):
    """
    Settings page (index 3 in the main QStackedWidget).

    Signals:
        theme_changed(str):            "dark" or "light"
        watch_dirs_changed(list[str]): updated list of watch paths
        developer_mode_changed(bool):  toggle developer mode
    """

    theme_changed:          pyqtSignal = pyqtSignal(str)
    watch_dirs_changed:     pyqtSignal = pyqtSignal(list)
    developer_mode_changed: pyqtSignal = pyqtSignal(bool)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._prefs = cfg.load_user_prefs()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _page_header(root, "Settings", "Configure DDAS behaviour, appearance, and watch targets.")
        root.addSpacing(8)

        # Scrollable content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 12, 28, 28)
        content_layout.setSpacing(20)

        # ── Appearance ──────────────────────────────────────────────────────
        content_layout.addWidget(_section_header("Appearance"))

        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Colour Theme"))
        theme_row.addStretch()

        self._dark_btn  = QPushButton("Dark")
        self._light_btn = QPushButton("Light")
        for btn in (self._dark_btn, self._light_btn):
            btn.setObjectName("ToggleBtn")
            btn.setFixedWidth(90)
        theme_row.addWidget(self._dark_btn)
        theme_row.addWidget(self._light_btn)
        content_layout.addLayout(theme_row)

        self._dark_btn.clicked.connect(lambda: self._set_theme("dark"))
        self._light_btn.clicked.connect(lambda: self._set_theme("light"))
        self._refresh_theme_buttons()

        content_layout.addWidget(_hline())

        # ── Hashing ───────────────────────────────────────────────────────
        content_layout.addWidget(_section_header("Hashing"))
        algo_info_row = QHBoxLayout()
        algo_info_row.addWidget(QLabel("Algorithm"))
        algo_info_row.addStretch()
        algo_badge = QLabel("BLAKE3  (fixed)")
        algo_badge.setObjectName("BadgeSuccess")
        algo_info_row.addWidget(algo_badge)
        content_layout.addLayout(algo_info_row)
        algo_note = QLabel(
            "BLAKE3 is the canonical hashing algorithm for all deduplication operations. "
            "It is ~3× faster than SHA-256 and provides cryptographic-strength collision resistance. "
            "SHA-256 benchmarks are available in Developer Mode → Hash Performance Metrics."
        )
        algo_note.setObjectName("PageSubtitle")
        algo_note.setWordWrap(True)
        content_layout.addWidget(algo_note)

        content_layout.addWidget(_hline())

        # ── Watch Directories ───────────────────────────────────────────────
        content_layout.addWidget(_section_header("Watched Directories"))

        self._dir_list = QListWidget()
        self._dir_list.setMaximumHeight(180)
        for d in self._prefs.get("watch_dirs", []):
            self._dir_list.addItem(d)
        content_layout.addWidget(self._dir_list)

        dir_btn_row = QHBoxLayout()
        add_btn = QPushButton("Add Directory")
        add_btn.setFixedWidth(160)
        add_btn.clicked.connect(self._add_watch_dir)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.setObjectName("DangerBtn")
        remove_btn.setFixedWidth(160)
        remove_btn.clicked.connect(self._remove_watch_dir)
        dir_btn_row.addWidget(add_btn)
        dir_btn_row.addWidget(remove_btn)
        dir_btn_row.addStretch()
        content_layout.addLayout(dir_btn_row)

        content_layout.addWidget(_hline())

        # ── Developer Mode ──────────────────────────────────────────────────
        content_layout.addWidget(_section_header("Developer Mode"))

        dev_row = QHBoxLayout()
        dev_row.addWidget(QLabel("Show Developer Mode Tab"))
        dev_row.addStretch()
        self._dev_on_btn  = QPushButton("Enable")
        self._dev_off_btn = QPushButton("Disable")
        for btn in (self._dev_on_btn, self._dev_off_btn):
            btn.setObjectName("ToggleBtn")
            btn.setFixedWidth(90)
        dev_row.addWidget(self._dev_on_btn)
        dev_row.addWidget(self._dev_off_btn)
        content_layout.addLayout(dev_row)
        self._dev_on_btn.clicked.connect(lambda: self._set_dev_mode(True))
        self._dev_off_btn.clicked.connect(lambda: self._set_dev_mode(False))
        self._refresh_dev_buttons()

        dev_note = QLabel(
            "Developer Mode exposes raw BLAKE3 hash metrics, CPU/memory profiling, "
            "live event streams, and throughput benchmarks."
        )
        dev_note.setObjectName("PageSubtitle")
        dev_note.setWordWrap(True)
        content_layout.addWidget(dev_note)

        content_layout.addStretch()
        root.addWidget(content)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _save_prefs(self) -> None:
        cfg.save_user_prefs(self._prefs)

    def _set_theme(self, theme: str) -> None:
        self._prefs["theme"] = theme
        self._save_prefs()
        self._refresh_theme_buttons()
        self.theme_changed.emit(theme)

    def _refresh_theme_buttons(self) -> None:
        active = self._prefs.get("theme", "dark")
        self._dark_btn.setProperty("active", "true" if active == "dark" else "false")
        self._light_btn.setProperty("active", "true" if active == "light" else "false")
        for btn in (self._dark_btn, self._light_btn):
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _on_algo_changed(self, _: int) -> None:
        pass  # Algorithm is now fixed to BLAKE3 — method preserved for compatibility.

    def _add_watch_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Select Watch Directory", str(Path.home())
        )
        if not directory:
            return
        existing = [self._dir_list.item(i).text()
                    for i in range(self._dir_list.count())]
        if directory in existing:
            return
        self._dir_list.addItem(directory)
        self._update_watch_prefs()

    def _remove_watch_dir(self) -> None:
        for item in self._dir_list.selectedItems():
            self._dir_list.takeItem(self._dir_list.row(item))
        self._update_watch_prefs()

    def _update_watch_prefs(self) -> None:
        dirs = [self._dir_list.item(i).text() for i in range(self._dir_list.count())]
        self._prefs["watch_dirs"] = dirs
        self._save_prefs()
        self.watch_dirs_changed.emit(dirs)

    def _set_dev_mode(self, enabled: bool) -> None:
        self._prefs["developer_mode"] = enabled
        self._save_prefs()
        self._refresh_dev_buttons()
        self.developer_mode_changed.emit(enabled)

    def _refresh_dev_buttons(self) -> None:
        active = self._prefs.get("developer_mode", False)
        self._dev_on_btn.setProperty("active", "true" if active else "false")
        self._dev_off_btn.setProperty("active", "true" if not active else "false")
        for btn in (self._dev_on_btn, self._dev_off_btn):
            btn.style().unpolish(btn)
            btn.style().polish(btn)
