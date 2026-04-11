"""
DDAS v2 — Application-wide configuration and user preferences.

Design intent:
  - All magic strings/paths live here, never scattered across modules.
  - User preferences are persisted to a JSON file; defaults fall back gracefully.
  - This module has NO dependencies on Qt or any business-logic layer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# ─── Directory layout ─────────────────────────────────────────────────────────

# Absolute path to the project root (two levels up from this file).
ROOT_DIR: Path = Path(__file__).resolve().parent.parent

CONFIG_DIR: Path = ROOT_DIR / "config"
LOG_DIR: Path = ROOT_DIR / "logs"
DB_PATH: Path = ROOT_DIR / "db" / "ddas.db"
ASSETS_DIR: Path = ROOT_DIR / "assets"
BENCHMARKS_DIR: Path = ROOT_DIR / "benchmarks"

# Ensure runtime directories exist on import.
LOG_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ─── Application metadata ─────────────────────────────────────────────────────

APP_NAME: str = "DDAS"
APP_VERSION: str = "2.0.0"
APP_DISPLAY_NAME: str = "Data Duplication Alert System"
TRAY_TOOLTIP: str = f"{APP_NAME} v{APP_VERSION} — Running"

# ─── Engine constants ────────────────────────────────────────────────────────
# Hash algorithm is now fixed — BLAKE3 exclusively.
# These constants are imported by core/hasher/hash_utils.py for use in the engine.

HASH_ALGO: str = "blake3"                     # Canonical; not user-configurable
PARTIAL_CHUNK_SIZE: int  = 128 * 1024         # 128 KB: head chunk for partial hash
FULL_HASH_CHUNK_SIZE: int = 64 * 1024         # 64 KB: streaming read chunk for full hash
LARGE_FILE_THRESHOLD: int = 100 * 1024 * 1024 # 100 MB → also hash last 128 KB chunk
MAX_WORKER_THREADS: int = 4                   # ThreadPoolExecutor ceiling

# ─── UI defaults ──────────────────────────────────────────────────────────────

DEFAULT_THEME: str = "dark"                # "dark" | "light"
WINDOW_MIN_WIDTH: int = 1100
WINDOW_MIN_HEIGHT: int = 680
SIDEBAR_WIDTH: int = 210

# ─── User preferences (persisted) ─────────────────────────────────────────────

_PREFS_FILE: Path = CONFIG_DIR / "user_prefs.json"

_DEFAULT_PREFS: dict[str, Any] = {
    "theme": DEFAULT_THEME,
    "watch_dirs": [],
    "developer_mode": False,
}


def load_user_prefs() -> dict[str, Any]:
    """Load user preferences from disk, merging with defaults for missing keys."""
    if not _PREFS_FILE.exists():
        return dict(_DEFAULT_PREFS)
    try:
        with _PREFS_FILE.open("r", encoding="utf-8") as fh:
            stored = json.load(fh)
        # Merge: stored values take priority; missing keys fall back to defaults.
        return {**_DEFAULT_PREFS, **stored}
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT_PREFS)


def save_user_prefs(prefs: dict[str, Any]) -> None:
    """Persist user preferences to disk atomically."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = _PREFS_FILE.with_suffix(".tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(prefs, fh, indent=2)
        tmp_path.replace(_PREFS_FILE)
    except OSError as exc:
        # Non-fatal — app continues with in-memory prefs.
        print(f"[DDAS][WARN] Could not save user prefs: {exc}")
