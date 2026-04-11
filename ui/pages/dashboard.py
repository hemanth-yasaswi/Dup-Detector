"""
DDAS v2 — Dashboard page.

Tabs:
  0 — Overview:        Stat cards (total files, duplicates, space saved).
  1 — Recent Activity: Table of recent file events.
  2 — Watch Status:    List of watched directories with status badges.

All data fields are placeholder-ready; they expose public update methods
that will be called from service-layer signals in Phase 5.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSizePolicy,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _page_header(parent_layout: QVBoxLayout, title: str, subtitle: str) -> None:
    """Append a title + subtitle block to parent_layout."""
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    parent_layout.addWidget(t)
    parent_layout.addWidget(s)


# ─── Stat Card ────────────────────────────────────────────────────────────────

class _StatCard(QWidget):
    """A value + label card used in the Overview tab."""

    def __init__(self, label: str, value: str = "—", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)

        self._value_lbl = QLabel(value)
        self._value_lbl.setObjectName("StatCardValue")
        self._label_lbl = QLabel(label.upper())
        self._label_lbl.setObjectName("StatCardLabel")

        layout.addWidget(self._value_lbl)
        layout.addWidget(self._label_lbl)

    def set_value(self, value: str) -> None:
        """Update the displayed value. Safe to call from any thread via signal."""
        self._value_lbl.setText(value)


# ─── Overview Tab ─────────────────────────────────────────────────────────────

class _OverviewTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Stat card row
        card_row = QHBoxLayout()
        card_row.setSpacing(16)

        self.card_total_files  = _StatCard("Total Indexed Files", "0")
        self.card_duplicates   = _StatCard("Duplicate Groups",     "0")
        self.card_space_saved  = _StatCard("Space Wasted",         "0 B")
        self.card_watched_dirs = _StatCard("Watched Directories",  "0")

        for card in (
            self.card_total_files, self.card_duplicates,
            self.card_space_saved, self.card_watched_dirs,
        ):
            card_row.addWidget(card)

        layout.addLayout(card_row)

        # System status row
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        status_hdr = QLabel("System Status")
        status_hdr.setObjectName("SectionHeader")
        layout.addWidget(status_hdr)

        self._status_val = QLabel("● Daemon running  ·  Idle — waiting for events")
        layout.addWidget(self._status_val)

        layout.addStretch()

    def set_status(self, text: str) -> None:
        self._status_val.setText(text)


# ─── Recent Activity Tab ──────────────────────────────────────────────────────

class _RecentActivityTab(QWidget):
    _HEADERS = ["Time", "Event", "File Path", "Size", "Status"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        self._table = QTableWidget(0, len(self._HEADERS))
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

        self._empty_lbl = QLabel(
            "No activity recorded yet.\n"
            "Duplicate detection events will appear here in real time."
        )
        self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_lbl.setObjectName("PageSubtitle")
        layout.addWidget(self._empty_lbl)

    def add_event(
        self,
        time: str,
        event: str,
        filepath: str,
        size: str,
        status: str,
    ) -> None:
        """Append a row. Called via signal connection from Phase 5 event handler."""
        self._empty_lbl.hide()
        row = self._table.rowCount()
        self._table.insertRow(row)
        for col, text in enumerate((time, event, filepath, size, status)):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, col, item)
        # Keep table scrolled to the latest event.
        self._table.scrollToBottom()

    def clear(self) -> None:
        self._table.setRowCount(0)
        self._empty_lbl.show()


# ─── Watch Status Tab ─────────────────────────────────────────────────────────

class _WatchStatusTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        hdr = QLabel("Monitored Directories")
        hdr.setObjectName("SectionHeader")
        layout.addWidget(hdr)

        self._dir_table = QTableWidget(0, 3)
        self._dir_table.setHorizontalHeaderLabels(["Directory", "Files", "Status"])
        self._dir_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._dir_table.verticalHeader().setVisible(False)
        self._dir_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._dir_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._dir_table)

        self._empty_lbl = QLabel(
            "No directories configured.\nAdd watch paths in Settings."
        )
        self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_lbl.setObjectName("PageSubtitle")
        layout.addWidget(self._empty_lbl)
        layout.addStretch()

    def refresh_dirs(self, dirs: list[tuple[str, int, str]]) -> None:
        """Repopulate the table. dirs = list of (path, file_count, status_str)."""
        self._dir_table.setRowCount(0)
        if dirs:
            self._empty_lbl.hide()
        for path, count, status in dirs:
            row = self._dir_table.rowCount()
            self._dir_table.insertRow(row)
            self._dir_table.setItem(row, 0, QTableWidgetItem(path))
            self._dir_table.setItem(row, 1, QTableWidgetItem(str(count)))
            self._dir_table.setItem(row, 2, QTableWidgetItem(status))


# ─── Dashboard Page ───────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    """
    Top-level Dashboard page (index 0 in the main QStackedWidget).

    Sub-widgets are exposed publicly so later phases can connect
    service signals directly to them without going through the page.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _page_header(root, "Dashboard",
                     "Real-time overview of your file system monitoring status.")
        root.addSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self.overview_tab     = _OverviewTab()
        self.activity_tab     = _RecentActivityTab()
        self.watchstatus_tab  = _WatchStatusTab()

        self._tabs.addTab(self.overview_tab,     "  Overview  ")
        self._tabs.addTab(self.activity_tab,     "  Recent Activity  ")
        self._tabs.addTab(self.watchstatus_tab,  "  Watch Status  ")

        root.addWidget(self._tabs)
