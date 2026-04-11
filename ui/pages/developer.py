"""
DDAS v2 — Developer Mode page (BLAKE3 single-algorithm).

Tabs:
  0 — Hash Metrics:           Per-file BLAKE3 timing and throughput table.
  1 — CPU & Memory:           Live system resource usage (Phase 7 wiring).
  2 — Event Monitor:          Scrolling log of raw watchdog events.
  3 — DB Stats:               SQLite record counts, WAL size, page info.
  4 — Hash Performance:       BLAKE3 throughput, queue size, partial vs full counts.

Phase 1/Refactor: Placeholders. Phase 7: live signal wiring.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QPlainTextEdit, QPushButton,
    QSizePolicy, QFrame,
)


def _page_header(layout: QVBoxLayout, title: str, subtitle: str) -> None:
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    layout.addWidget(t)
    layout.addWidget(s)


def _placeholder(icon: str, text: str) -> QWidget:
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    lyt = QVBoxLayout(w)
    lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lyt.setSpacing(8)
    icon_lbl = QLabel(icon)
    icon_lbl.setStyleSheet("font-size: 36px; color: #3d4275;")
    icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lyt.addWidget(icon_lbl)
    txt_lbl = QLabel(text)
    txt_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    txt_lbl.setObjectName("PageSubtitle")
    txt_lbl.setWordWrap(True)
    lyt.addWidget(txt_lbl)
    return w


# ─── Hash Metrics Tab ─────────────────────────────────────────────────────────

class _HashMetricsTab(QWidget):
    # Algorithm column removed — BLAKE3 is implicit throughout.
    _HEADERS = ["File", "Stage", "Bytes", "Duration (ms)", "Throughput (MB/s)"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        action_row = QHBoxLayout()
        self._count_lbl = QLabel("0 hashing operations recorded")
        self._count_lbl.setObjectName("PageSubtitle")
        action_row.addWidget(self._count_lbl)
        action_row.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("SecondaryBtn")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self._clear)
        action_row.addWidget(clear_btn)
        layout.addLayout(action_row)

        self._table = QTableWidget(0, len(self._HEADERS))
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

    def record(
        self,
        file: str,
        stage: str,
        bytes_hashed: int,
        duration_ms: float,
    ) -> None:
        """Append one BLAKE3 hash record (Phase 7 signal entry point)."""
        throughput = (bytes_hashed / 1024 / 1024) / (duration_ms / 1000) if duration_ms else 0
        row = self._table.rowCount()
        self._table.insertRow(row)
        for col, text in enumerate((
            file, stage,
            f"{bytes_hashed:,}",
            f"{duration_ms:.2f}",
            f"{throughput:.1f}",
        )):
            self._table.setItem(row, col, QTableWidgetItem(text))
        self._count_lbl.setText(f"{row + 1} hashing operations recorded")

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._count_lbl.setText("0 hashing operations recorded")


# ─── CPU & Memory Tab ─────────────────────────────────────────────────────────

class _CpuMemTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # Summary row
        summary_row = QHBoxLayout()
        summary_row.setSpacing(16)
        for label, attr in (
            ("CPU %", "_cpu_lbl"),
            ("Memory (RSS)", "_mem_lbl"),
            ("Threads", "_thread_lbl"),
        ):
            card = QFrame()
            card.setObjectName("StatCard")
            card_lyt = QVBoxLayout(card)
            val = QLabel("—")
            val.setObjectName("StatCardValue")
            lbl = QLabel(label.upper())
            lbl.setObjectName("StatCardLabel")
            card_lyt.addWidget(val)
            card_lyt.addWidget(lbl)
            setattr(self, attr, val)
            summary_row.addWidget(card)
        layout.addLayout(summary_row)

        # Chart placeholder
        layout.addWidget(_placeholder(
            "▤",
            "CPU and memory usage chart will render here in Phase 7.\n"
            "Updates are triggered by psutil sampling on a low-frequency timer."
        ))

    def update_metrics(self, cpu: float, mem_mb: float, threads: int) -> None:
        """Slot for receiving live metrics (Phase 7)."""
        self._cpu_lbl.setText(f"{cpu:.1f}%")
        self._mem_lbl.setText(f"{mem_mb:.1f} MB")
        self._thread_lbl.setText(str(threads))


# ─── Event Monitor Tab ────────────────────────────────────────────────────────

class _EventMonitorTab(QWidget):
    """
    Rolling log of raw watchdog filesystem events.
    QPlainTextEdit is used because it handles large text more efficiently
    than QTextEdit (no HTML overhead, block-based storage).
    """

    _MAX_LINES = 2000  # Prevent unbounded memory growth.

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        action_row = QHBoxLayout()
        self._paused = False
        self._pause_btn = QPushButton("Pause")
        self._pause_btn.setObjectName("SecondaryBtn")
        self._pause_btn.setFixedWidth(80)
        self._pause_btn.clicked.connect(self._toggle_pause)
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("SecondaryBtn")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(lambda: self._log.clear())
        action_row.addStretch()
        action_row.addWidget(self._pause_btn)
        action_row.addWidget(clear_btn)
        layout.addLayout(action_row)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setPlaceholderText(
            "Waiting for filesystem events…\n"
            "Events appear here once the watchdog daemon is running."
        )
        self._log.setMaximumBlockCount(self._MAX_LINES)
        layout.addWidget(self._log)

    def append_event(self, text: str) -> None:
        """Append one event line (Phase 7 signal connection entry point)."""
        if not self._paused:
            self._log.appendPlainText(text)

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self._pause_btn.setText("Resume" if self._paused else "Pause")


# ─── DB Stats Tab ─────────────────────────────────────────────────────────────

class _DbStatsTab(QWidget):
    _HEADERS = ["Metric", "Value"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        action_row = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedWidth(100)
        action_row.addStretch()
        action_row.addWidget(refresh_btn)
        layout.addLayout(action_row)

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self._table)

        # Populate with placeholder rows
        placeholder_rows = [
            ("Total indexed files",   "—"),
            ("Duplicate groups",      "—"),
            ("DB file size",          "—"),
            ("WAL size",              "—"),
            ("Page size",             "4096 B"),
            ("Journal mode",          "WAL"),
            ("Last reconciliation",   "—"),
        ]
        self._table.setRowCount(len(placeholder_rows))
        for row, (metric, value) in enumerate(placeholder_rows):
            self._table.setItem(row, 0, QTableWidgetItem(metric))
            self._table.setItem(row, 1, QTableWidgetItem(value))

    def update_stats(self, stats: dict[str, str]) -> None:
        """Repopulate the table from a dict of metric → value pairs."""
        self._table.setRowCount(len(stats))
        for row, (k, v) in enumerate(stats.items()):
            self._table.setItem(row, 0, QTableWidgetItem(k))
            self._table.setItem(row, 1, QTableWidgetItem(v))


# ─── Hash Performance Tab ──────────────────────────────────────────────────────

class _HashPerformanceTab(QWidget):
    """
    Live BLAKE3 hashing performance metrics.

    Shows real-time throughput, queue depth, and partial vs full hash
    counts. All values are pushed by engine signals in Phase 7.
    In Phase 1/Refactor this tab displays stat cards + placeholder chart.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # ── Metric cards ────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(16)

        _card_defs = [
            ("Files / Second",       "_fps_lbl"),
            ("Avg Throughput",        "_throughput_lbl"),
            ("Partial Hashes",        "_partial_lbl"),
            ("Full Hashes",           "_full_lbl"),
            ("Queue Size",            "_queue_lbl"),
            ("CPU During Hash (%)",   "_cpu_lbl"),
        ]
        for label, attr in _card_defs:
            card = QFrame()
            card.setObjectName("StatCard")
            card_lyt = QVBoxLayout(card)
            card_lyt.setContentsMargins(14, 14, 14, 14)
            val = QLabel("—")
            val.setObjectName("StatCardValue")
            lbl = QLabel(label.upper())
            lbl.setObjectName("StatCardLabel")
            card_lyt.addWidget(val)
            card_lyt.addWidget(lbl)
            setattr(self, attr, val)
            cards_row.addWidget(card)

        layout.addLayout(cards_row)

        # ── Throughput chart placeholder ──────────────────────
        layout.addWidget(_placeholder(
            "⚡",
            "BLAKE3 throughput chart (MB/s over time) will render here in Phase 7.\n"
            "Driven by psutil + engine hash event signals — no polling."
        ))

    def update_performance(
        self,
        fps: float,
        throughput_mbps: float,
        partial_count: int,
        full_count: int,
        queue_size: int,
        cpu_pct: float,
    ) -> None:
        """Update all metric cards. Called from engine signals in Phase 7."""
        self._fps_lbl.setText(f"{fps:.1f}")
        self._throughput_lbl.setText(f"{throughput_mbps:.1f} MB/s")
        self._partial_lbl.setText(str(partial_count))
        self._full_lbl.setText(str(full_count))
        self._queue_lbl.setText(str(queue_size))
        self._cpu_lbl.setText(f"{cpu_pct:.1f}%")


# ─── Developer Page ───────────────────────────────────────────────────────────

class DeveloperPage(QWidget):
    """Top-level Developer Mode page (index 4 in the main QStackedWidget)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _page_header(root, "Developer Mode",
                     "Raw BLAKE3 engine metrics, live events, and performance tools.")
        root.addSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self.hash_metrics_tab      = _HashMetricsTab()
        self.cpu_mem_tab           = _CpuMemTab()
        self.event_monitor_tab     = _EventMonitorTab()
        self.db_stats_tab          = _DbStatsTab()
        self.hash_performance_tab  = _HashPerformanceTab()

        self._tabs.addTab(self.hash_metrics_tab,     "  Hash Metrics  ")
        self._tabs.addTab(self.cpu_mem_tab,          "  CPU & Memory  ")
        self._tabs.addTab(self.event_monitor_tab,    "  Event Monitor  ")
        self._tabs.addTab(self.db_stats_tab,         "  DB Stats  ")
        self._tabs.addTab(self.hash_performance_tab, "  Hash Performance  ")

        root.addWidget(self._tabs)
