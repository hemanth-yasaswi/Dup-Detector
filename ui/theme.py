"""
DDAS v2 — Theme engine.

Provides two complete QSS stylesheets (dark / light) and a single
`apply_theme()` function that swaps the application-wide stylesheet
atomically. The current theme name is stored in user preferences.

Design rules:
  - All colours are defined as module-level constants so future
    theme additions only need to change the palette section.
  - No Qt imports at module top-level — this module is safe to import
    from tests without a running QApplication.
"""

from __future__ import annotations

# ─── Colour Palettes ──────────────────────────────────────────────────────────

DARK = {
    "bg_primary":    "#0f1117",
    "bg_secondary":  "#1a1d27",
    "bg_tertiary":   "#22263a",
    "bg_hover":      "#2a2f47",
    "bg_selected":   "#2d3250",
    "accent":        "#7c83fd",
    "accent_hover":  "#9da3ff",
    "accent_muted":  "#3d4275",
    "text_primary":  "#e8eaf0",
    "text_secondary":"#8b90a7",
    "text_disabled": "#4a5068",
    "border":        "#2a2f47",
    "border_light":  "#383d5c",
    "success":       "#4ade80",
    "warning":       "#fbbf24",
    "danger":        "#f87171",
    "tag_bg":        "#1e2236",
}

LIGHT = {
    "bg_primary":    "#f5f6fa",
    "bg_secondary":  "#ffffff",
    "bg_tertiary":   "#eef0f8",
    "bg_hover":      "#e4e7f5",
    "bg_selected":   "#dde1f5",
    "accent":        "#5c63d8",
    "accent_hover":  "#4a52cc",
    "accent_muted":  "#c5c8f0",
    "text_primary":  "#1a1d2e",
    "text_secondary":"#5a5f7a",
    "text_disabled": "#a0a4be",
    "border":        "#d8daea",
    "border_light":  "#eceef8",
    "success":       "#22c55e",
    "warning":       "#f59e0b",
    "danger":        "#ef4444",
    "tag_bg":        "#eef0f8",
}


def _build_qss(p: dict[str, str]) -> str:
    """Build a complete QSS stylesheet from a colour palette dict."""
    return f"""
/* ─── Global ─────────────────────────────────────────────────────────────── */
QWidget {{
    background-color: {p['bg_primary']};
    color: {p['text_primary']};
    font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    border: none;
    outline: none;
}}

QMainWindow, QDialog {{
    background-color: {p['bg_primary']};
}}

/* ─── Sidebar ─────────────────────────────────────────────────────────────── */
#Sidebar {{
    background-color: {p['bg_secondary']};
    border-right: 1px solid {p['border']};
}}

#SidebarLogo {{
    color: {p['accent']};
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 24px 20px 8px 20px;
}}

#SidebarVersion {{
    color: {p['text_disabled']};
    font-size: 10px;
    padding: 0px 20px 20px 20px;
}}

QPushButton#SidebarBtn {{
    background-color: transparent;
    color: {p['text_secondary']};
    text-align: left;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
    margin: 2px 10px;
    border: none;
}}

QPushButton#SidebarBtn:hover {{
    background-color: {p['bg_hover']};
    color: {p['text_primary']};
}}

QPushButton#SidebarBtn[active="true"] {{
    background-color: {p['bg_selected']};
    color: {p['accent']};
    font-weight: 600;
}}

/* ─── Content area ────────────────────────────────────────────────────────── */
#ContentArea {{
    background-color: {p['bg_primary']};
}}

#PageTitle {{
    color: {p['text_primary']};
    font-size: 22px;
    font-weight: 700;
    padding: 24px 28px 4px 28px;
}}

#PageSubtitle {{
    color: {p['text_secondary']};
    font-size: 12px;
    padding: 0px 28px 16px 28px;
}}

/* ─── Tab Widget ──────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    background-color: {p['bg_primary']};
    border: 1px solid {p['border']};
    border-radius: 10px;
    padding: 4px;
    margin: 0px 20px 20px 20px;
}}

QTabBar::tab {{
    background-color: transparent;
    color: {p['text_secondary']};
    padding: 8px 18px;
    margin-right: 4px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 500;
}}

QTabBar::tab:hover {{
    background-color: {p['bg_hover']};
    color: {p['text_primary']};
}}

QTabBar::tab:selected {{
    background-color: {p['bg_selected']};
    color: {p['accent']};
    font-weight: 600;
}}

QTabBar::tab:!selected {{
    margin-top: 2px;
}}

/* ─── Stat Cards ──────────────────────────────────────────────────────────── */
#StatCard {{
    background-color: {p['bg_secondary']};
    border: 1px solid {p['border']};
    border-radius: 12px;
    padding: 20px;
}}

#StatCardValue {{
    font-size: 28px;
    font-weight: 700;
    color: {p['accent']};
}}

#StatCardLabel {{
    font-size: 11px;
    color: {p['text_secondary']};
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

/* ─── Tables ──────────────────────────────────────────────────────────────── */
QTableWidget, QTreeWidget {{
    background-color: {p['bg_secondary']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    gridline-color: {p['border_light']};
    selection-background-color: {p['bg_selected']};
    selection-color: {p['text_primary']};
    alternate-background-color: {p['bg_tertiary']};
}}

QTableWidget::item, QTreeWidget::item {{
    padding: 6px 10px;
    border: none;
}}

QHeaderView::section {{
    background-color: {p['bg_tertiary']};
    color: {p['text_secondary']};
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid {p['border']};
}}

/* ─── Scroll Bars ─────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {p['border']};
    border-radius: 3px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background: {p['text_disabled']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 6px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background: {p['border']};
    border-radius: 3px;
    min-width: 20px;
}}

/* ─── Buttons ─────────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {p['accent']};
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {p['accent_hover']};
}}

QPushButton:pressed {{
    background-color: {p['accent_muted']};
}}

QPushButton:disabled {{
    background-color: {p['bg_tertiary']};
    color: {p['text_disabled']};
}}

QPushButton#SecondaryBtn {{
    background-color: transparent;
    color: {p['text_secondary']};
    border: 1px solid {p['border']};
}}

QPushButton#SecondaryBtn:hover {{
    background-color: {p['bg_hover']};
    color: {p['text_primary']};
    border-color: {p['border_light']};
}}

QPushButton#DangerBtn {{
    background-color: transparent;
    color: {p['danger']};
    border: 1px solid {p['danger']};
}}

QPushButton#DangerBtn:hover {{
    background-color: {p['danger']};
    color: #ffffff;
}}

/* ─── Line Edits / Combo Boxes ────────────────────────────────────────────── */
QLineEdit, QComboBox {{
    background-color: {p['bg_tertiary']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 7px 12px;
    color: {p['text_primary']};
    font-size: 13px;
}}

QLineEdit:focus, QComboBox:focus {{
    border-color: {p['accent']};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {p['text_secondary']};
    width: 0;
    height: 0;
    margin-right: 8px;
}}

QComboBox QAbstractItemView {{
    background-color: {p['bg_secondary']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    selection-background-color: {p['bg_selected']};
    selection-color: {p['text_primary']};
    padding: 4px;
}}

/* ─── Labels ──────────────────────────────────────────────────────────────── */
QLabel#SectionHeader {{
    font-size: 13px;
    font-weight: 600;
    color: {p['text_secondary']};
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 8px 0 4px 0;
}}

/* ─── CheckBox / Radio ────────────────────────────────────────────────────── */
QCheckBox, QRadioButton {{
    color: {p['text_primary']};
    spacing: 8px;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {p['border_light']};
    border-radius: 4px;
    background-color: {p['bg_tertiary']};
}}

QCheckBox::indicator:checked {{
    background-color: {p['accent']};
    border-color: {p['accent']};
}}

/* ─── Separators ──────────────────────────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="HLine"] {{
    color: {p['border']};
    max-height: 1px;
}}

/* ─── Plain Text Edit (Event Monitor) ────────────────────────────────────── */
QPlainTextEdit {{
    background-color: {p['bg_secondary']};
    color: {p['text_primary']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    padding: 8px;
    font-family: "Consolas", "JetBrains Mono", "Fira Code", monospace;
    font-size: 12px;
}}

/* ─── Badge labels ────────────────────────────────────────────────────────── */
QLabel#BadgeSuccess {{
    background-color: {p['success']};
    color: #000000;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 10px;
    font-weight: 700;
}}

QLabel#BadgeWarning {{
    background-color: {p['warning']};
    color: #000000;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 10px;
    font-weight: 700;
}}

QLabel#BadgeDanger {{
    background-color: {p['danger']};
    color: #ffffff;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 10px;
    font-weight: 700;
}}

/* ─── Tooltip ─────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {p['bg_tertiary']};
    color: {p['text_primary']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ─── Settings Toggle Button ──────────────────────────────────────────────── */
QPushButton#ToggleBtn {{
    background-color: {p['bg_tertiary']};
    color: {p['text_secondary']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 12px;
    font-weight: 500;
    min-width: 80px;
}}

QPushButton#ToggleBtn[active="true"] {{
    background-color: {p['accent']};
    color: #ffffff;
    border-color: {p['accent']};
}}

/* ─── List Widget ─────────────────────────────────────────────────────────── */
QListWidget {{
    background-color: {p['bg_secondary']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    outline: none;
}}

QListWidget::item {{
    padding: 8px 12px;
    border-radius: 4px;
    margin: 2px 4px;
}}

QListWidget::item:hover {{
    background-color: {p['bg_hover']};
}}

QListWidget::item:selected {{
    background-color: {p['bg_selected']};
    color: {p['text_primary']};
}}

/* ─── Splitter ────────────────────────────────────────────────────────────── */
QSplitter::handle {{
    background-color: {p['border']};
    width: 1px;
}}
"""


# Pre-built stylesheets — built once at module import time.
DARK_QSS: str = _build_qss(DARK)
LIGHT_QSS: str = _build_qss(LIGHT)

_THEME_MAP: dict[str, str] = {
    "dark": DARK_QSS,
    "light": LIGHT_QSS,
}


def apply_theme(app: "QApplication", theme: str) -> None:  # noqa: F821
    """
    Apply a named theme stylesheet to the entire QApplication.

    Args:
        app:   The running QApplication instance.
        theme: "dark" or "light". Unknown values default to "dark".
    """
    qss = _THEME_MAP.get(theme, DARK_QSS)
    app.setStyleSheet(qss)
