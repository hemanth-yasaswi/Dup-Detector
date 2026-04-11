"""
DDAS v2 — Duplicates page.

Tabs:
  0 — All Duplicates:   A QTreeWidget grouped by hash, showing all members.
  1 — By Size:          Sorted by wasted bytes (largest first).
  2 — By Directory:     Directory-hierarchy grouped view.
  3 — Quarantine:       Files moved to quarantine pending deletion.

All tabs are placeholder-ready. Data population methods are public
and will be connected to repository signals in Phase 5.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton,
)


def _page_header(layout: QVBoxLayout, title: str, subtitle: str) -> None:
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    layout.addWidget(t)
    layout.addWidget(s)


def _empty_state(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setObjectName("PageSubtitle")
    return lbl


# ─── All Duplicates Tab ───────────────────────────────────────────────────────

class _AllDuplicatesTab(QWidget):
    """
    Tree view: one top-level item per hash group, children = file paths.
    Shape: [hash_short]  [N files]  [total waste]
      └── /path/to/file1.ext  [size]  [modified]
      └── /path/to/file2.ext  [size]  [modified]
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        # Action bar
        action_bar = QHBoxLayout()
        self._count_lbl = QLabel("0 duplicate groups found")
        self._count_lbl.setObjectName("PageSubtitle")
        action_bar.addWidget(self._count_lbl)
        action_bar.addStretch()
        select_all_btn = QPushButton("Select All")
        select_all_btn.setObjectName("SecondaryBtn")
        select_all_btn.setFixedWidth(100)
        action_bar.addWidget(select_all_btn)
        layout.addLayout(action_bar)

        # Tree widget
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["File / Hash Group", "Size", "Modified", "Action"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self._tree.setUniformRowHeights(True)
        layout.addWidget(self._tree)

        self._empty = _empty_state(
            "No duplicates detected yet.\n"
            "Add watch directories in Settings and let the daemon scan."
        )
        layout.addWidget(self._empty)

    def populate(self, groups: list[dict]) -> None:
        """
        groups: list of {
          'hash': str,
          'files': [{'path': str, 'size': int, 'modified': str}]
        }
        """
        self._tree.clear()
        if not groups:
            self._empty.show()
            self._count_lbl.setText("0 duplicate groups found")
            return

        self._empty.hide()
        self._count_lbl.setText(f"{len(groups)} duplicate group(s) found")

        for group in groups:
            files = group["files"]
            waste = sum(f["size"] for f in files[1:])  # first copy is "original"
            root_item = QTreeWidgetItem([
                f"  {group['hash'][:12]}…",
                f"{len(files)} copies",
                f"Wastes {waste:,} B",
                "",
            ])
            root_item.setExpanded(True)
            for f in files:
                child = QTreeWidgetItem([
                    f"    {f['path']}",
                    f"{f['size']:,} B",
                    f.get("modified", ""),
                    "",
                ])
                root_item.addChild(child)
            self._tree.addTopLevelItem(root_item)


# ─── By Size Tab ──────────────────────────────────────────────────────────────

class _BySizeTab(QWidget):
    """
    Flat table of duplicate groups sorted by wasted bytes descending.
    """

    _HEADERS = ["Hash (first 16)", "# Copies", "File Size", "Total Waste", "Sample Path"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        self._table = QTableWidget(0, len(self._HEADERS))
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)
        layout.addWidget(_empty_state("Sorted duplicate groups will appear here."))


# ─── By Directory Tab ─────────────────────────────────────────────────────────

class _ByDirectoryTab(QWidget):
    """
    Tree view: one root per directory, children = duplicate files within it.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Directory / File", "Size", "Duplicates"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.setAlternatingRowColors(True)
        layout.addWidget(self._tree)
        layout.addWidget(_empty_state("Directory-grouped duplicate view will appear here."))


# ─── Quarantine Tab ───────────────────────────────────────────────────────────

class _QuarantineTab(QWidget):
    """
    Files that have been moved to quarantine pending permanent deletion.
    """

    _HEADERS = ["Original Path", "Quarantined At", "Size", "Restore", "Delete"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        warning = QLabel(
            "⚠  Files in quarantine are isolated but NOT yet deleted. "
            "Review carefully before permanent removal."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self._table = QTableWidget(0, len(self._HEADERS))
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)
        layout.addWidget(_empty_state("No files in quarantine."))


# ─── Duplicates Page ──────────────────────────────────────────────────────────

class DuplicatesPage(QWidget):
    """Top-level Duplicates page (index 1 in the main QStackedWidget)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _page_header(root, "Duplicates",
                     "Explore and manage content-identical files detected by the daemon.")
        root.addSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self.all_tab       = _AllDuplicatesTab()
        self.bysize_tab    = _BySizeTab()
        self.bydir_tab     = _ByDirectoryTab()
        self.quarantine_tab = _QuarantineTab()

        self._tabs.addTab(self.all_tab,         "  All Duplicates  ")
        self._tabs.addTab(self.bysize_tab,      "  By Size  ")
        self._tabs.addTab(self.bydir_tab,       "  By Directory  ")
        self._tabs.addTab(self.quarantine_tab,  "  Quarantine  ")

        root.addWidget(self._tabs)
