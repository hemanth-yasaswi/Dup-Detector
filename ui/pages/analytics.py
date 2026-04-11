"""
DDAS v2 — Analytics page.

Tabs:
  0 — Storage Saved:     Cumulative chart of space recovered.
  1 — Hash Performance:  Throughput and timing metrics per algo.
  2 — File Distribution: Breakdown by file type / extension.
  3 — Historical Trends: Duplicate rate over time.

Phase 1: All tabs display styled empty-state placeholders with
descriptive labels.  Chart widgets will be inserted in Phase 7
using PyQtGraph or a lightweight canvas widget, activated lazily
only when the tab becomes visible.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTabWidget,
    QFrame, QSizePolicy,
)


def _page_header(layout: QVBoxLayout, title: str, subtitle: str) -> None:
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    layout.addWidget(t)
    layout.addWidget(s)


def _chart_placeholder(description: str) -> QWidget:
    """A styled placeholder for a chart that will be wired in Phase 7."""
    container = QWidget()
    container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)

    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.Box)
    frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    inner = QVBoxLayout(frame)
    inner.setAlignment(Qt.AlignmentFlag.AlignCenter)

    icon_lbl = QLabel("▦")
    icon_lbl.setStyleSheet("font-size: 40px; color: #3d4275;")
    icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    inner.addWidget(icon_lbl)

    desc_lbl = QLabel(description)
    desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    desc_lbl.setObjectName("PageSubtitle")
    desc_lbl.setWordWrap(True)
    inner.addWidget(desc_lbl)

    phase_lbl = QLabel("Chart initialised in Phase 7")
    phase_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    phase_lbl.setStyleSheet("font-size: 10px; color: #4a5068;")
    inner.addWidget(phase_lbl)

    layout.addWidget(frame)
    return container


class _StorageSavedTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(_chart_placeholder(
            "Cumulative storage saved by removing duplicates.\n"
            "Updated after each scan cycle."
        ))


class _HashPerformanceTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(_chart_placeholder(
            "Hashing throughput (MB/s) for SHA-256 and BLAKE3.\n"
            "Data sourced from the benchmark and live indexer modules."
        ))


class _FileDistributionTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(_chart_placeholder(
            "File type distribution (images, video, audio, documents, binaries).\n"
            "Pie / donut chart rendered per indexed directory."
        ))


class _HistoricalTrendsTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(_chart_placeholder(
            "Duplicate detection rate and file growth over time.\n"
            "Plotted per day from the DDAS event log."
        ))


class AnalyticsPage(QWidget):
    """Top-level Analytics page (index 2 in the main QStackedWidget)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _page_header(root, "Analytics",
                     "Visualise storage savings, hashing performance, and file trends.")
        root.addSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self._tabs.addTab(_StorageSavedTab(),     "  Storage Saved  ")
        self._tabs.addTab(_HashPerformanceTab(),  "  Hash Performance  ")
        self._tabs.addTab(_FileDistributionTab(), "  File Distribution  ")
        self._tabs.addTab(_HistoricalTrendsTab(), "  Historical Trends  ")

        root.addWidget(self._tabs)
