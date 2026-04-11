"""
DDAS v2 — Sidebar navigation widget.

A vertically-stacked set of icon+text navigation buttons.
Emits `page_changed(index)` when a different item is selected.
Active state is managed by setting the "active" Qt property and
calling `style().polish()` — no manual colour changes needed.

Design notes:
  - Pure QWidget with QVBoxLayout — no QListWidget, which would bring
    unwanted selection highlight behaviour.
  - Each button stores its target page index as a custom attribute.
  - Developer Mode button is shown/hidden dynamically from Settings.
"""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QSpacerItem, QSizePolicy
from PyQt6.QtGui import QFont

from config.settings import APP_NAME, APP_VERSION, SIDEBAR_WIDTH


# ─── Navigation Items ──────────────────────────────────────────────────────────
# Each tuple: (label, icon_char, page_index)
_NAV_ITEMS: list[tuple[str, str, int]] = [
    ("Dashboard",     "⊞", 0),
    ("Duplicates",    "⧉", 1),
    ("Analytics",     "▦", 2),
    ("Settings",      "⚙", 3),
    ("Developer",     "⌥", 4),
]


class _NavButton(QPushButton):
    """A single sidebar navigation button."""

    def __init__(self, label: str, icon_char: str, page_index: int) -> None:
        super().__init__()
        self.page_index = page_index
        self._active = False

        self.setObjectName("SidebarBtn")
        self.setText(f"  {icon_char}  {label}")
        self.setCheckable(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(label)
        self.setMinimumHeight(42)

    @property
    def active(self) -> bool:
        return self._active

    @active.setter
    def active(self, value: bool) -> None:
        self._active = value
        # Setting Qt dynamic property — QSS selector [active="true"] picks this up.
        self.setProperty("active", "true" if value else "false")
        # Force QSS re-evaluation for this widget.
        self.style().unpolish(self)
        self.style().polish(self)


class SidebarWidget(QWidget):
    """
    Sidebar navigation panel.

    Signals:
        page_changed(int): Emitted with the target page index whenever
                           a nav button is clicked.
    """

    page_changed: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self.setObjectName("Sidebar")
        self.setFixedWidth(SIDEBAR_WIDTH)

        self._buttons: list[_NavButton] = []
        self._dev_button: _NavButton | None = None

        self._build_ui()
        # Select the first item (Dashboard) by default.
        self._select(0)

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_developer_mode_visible(self, visible: bool) -> None:
        """Show or hide the Developer Mode sidebar entry."""
        if self._dev_button is not None:
            self._dev_button.setVisible(visible)
            # If the dev page was selected and it's now hidden, go to Dashboard.
            if not visible and self._dev_button.active:
                self._select(0)
                self.page_changed.emit(0)

    # ── Private ────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # App logo / branding block
        logo_label = QLabel(APP_NAME)
        logo_label.setObjectName("SidebarLogo")
        layout.addWidget(logo_label)

        ver_label = QLabel(f"v{APP_VERSION}")
        ver_label.setObjectName("SidebarVersion")
        layout.addWidget(ver_label)

        layout.addSpacing(8)

        # Nav buttons
        for label, icon_char, idx in _NAV_ITEMS:
            btn = _NavButton(label, icon_char, idx)
            btn.clicked.connect(lambda _, b=btn: self._on_btn_clicked(b))
            layout.addWidget(btn)
            self._buttons.append(btn)

            if label == "Developer":
                self._dev_button = btn
                btn.setVisible(False)  # Hidden by default until enabled in Settings

        # Push everything to the top
        layout.addItem(
            QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

    def _on_btn_clicked(self, btn: _NavButton) -> None:
        if btn.page_index == self._current_index:
            return
        self._select(btn.page_index)
        self.page_changed.emit(btn.page_index)

    def _select(self, index: int) -> None:
        self._current_index = index
        for btn in self._buttons:
            btn.active = btn.page_index == index
