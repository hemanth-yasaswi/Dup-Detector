"""
Settings manager. Loads from user_prefs.json on first import.
Access via the module-level singleton: from core.settings import settings
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List

from utils.logger import get_logger

PREFS_FILE = "user_prefs.json"
PREFS_TMP  = "user_prefs.json.tmp"

logger = get_logger(__name__)


@dataclass
class Settings:
    """
    All user-configurable settings with their defaults.

    Fields:
      watched_directories    : list of absolute directory paths to monitor
      min_file_size_bytes    : files smaller than this are skipped entirely (default: 1024)
      debounce_seconds       : seconds to wait before processing a burst of events (default: 0.5)
      stabilization_interval : seconds between file-size polls for stabilization (default: 0.5)
      stabilization_retries  : how many times to re-poll before giving up (default: 3)
      ignore_extensions      : list of lowercase extensions to skip e.g. [".tmp", ".lock"]
      ignore_directories     : list of directory name substrings to skip e.g. ["$RECYCLE.BIN"]
      quarantine_path        : absolute path to quarantine folder (default: ~/.ddas_quarantine)
      default_action         : one of "ask", "keep_existing", "keep_both", "quarantine"
      hash_algorithm         : internal only, always "blake3" — never shown in UI
      log_level              : "DEBUG" or "INFO" (default: "INFO")
      cpu_throttle_percent   : pause workers if CPU exceeds this (default: 15)
    """

    watched_directories:    List[str] = field(default_factory=list)
    min_file_size_bytes:    int       = 1024
    debounce_seconds:       float     = 0.5
    stabilization_interval: float     = 0.5
    stabilization_retries:  int       = 3
    ignore_extensions:      List[str] = field(default_factory=lambda: [
        ".tmp", ".lock", ".part", ".crdownload", ".ddas_tmp"
    ])
    ignore_directories:     List[str] = field(default_factory=lambda: [
        "$recycle.bin", "system volume information", ".git",
        "node_modules", "__pycache__", ".ddas_quarantine"
    ])
    quarantine_path: str = field(
        default_factory=lambda: os.path.join(os.path.expanduser("~"), ".ddas_quarantine")
    )
    default_action:       str = "ask"
    hash_algorithm:       str = "blake3"
    log_level:            str = "INFO"
    cpu_throttle_percent: int = 15

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> bool:
        """
        Write current settings to PREFS_FILE as formatted JSON.

        Uses an atomic write: write to PREFS_TMP then os.replace() to swap.
        Returns True on success, False on any IO error (logs the error).
        """
        try:
            data = asdict(self)
            content = json.dumps(data, indent=2, ensure_ascii=False)
            with open(PREFS_TMP, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.replace(PREFS_TMP, PREFS_FILE)
            logger.debug("[SETTINGS] preferences saved to %s", PREFS_FILE)
            return True
        except Exception as e:
            logger.error("[SETTINGS] failed to save preferences: %s", e)
            return False

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @staticmethod
    def load() -> "Settings":
        """
        Load settings from PREFS_FILE.

        Behaviour:
        - If file does not exist: return Settings() with all defaults, write defaults to file.
        - If file exists but is malformed JSON: log ERROR, return defaults (do NOT crash).
        - If file exists and is valid: merge with defaults — unknown keys are ignored,
          missing keys use defaults (forward-compatible).
        - After loading, populate watched_directories with existing default OS dirs
          (Desktop, Downloads, Documents) if watched_directories is empty.
        """
        defaults = Settings()

        if not os.path.isfile(PREFS_FILE):
            logger.info("[SETTINGS] no preferences file found — creating defaults at %s", PREFS_FILE)
            defaults._populate_default_dirs()
            defaults.save()
            return defaults

        try:
            with open(PREFS_FILE, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as e:
            logger.error("[SETTINGS] malformed JSON in %s — using defaults. Error: %s", PREFS_FILE, e)
            defaults._populate_default_dirs()
            return defaults
        except Exception as e:
            logger.error("[SETTINGS] could not read %s — using defaults. Error: %s", PREFS_FILE, e)
            defaults._populate_default_dirs()
            return defaults

        # Merge: start from defaults, overlay only known keys
        defaults_dict = asdict(defaults)
        for key, default_value in defaults_dict.items():
            if key in raw:
                defaults_dict[key] = raw[key]

        try:
            merged = Settings(**defaults_dict)
        except Exception as e:
            logger.error("[SETTINGS] could not construct Settings from file data: %s — using defaults", e)
            merged = Settings()

        if not merged.watched_directories:
            merged._populate_default_dirs()

        logger.debug("[SETTINGS] preferences loaded from %s", PREFS_FILE)
        return merged

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _populate_default_dirs(self) -> None:
        """
        If watched_directories is empty, add OS user directories that exist.
        Checks existence with os.path.isdir before adding.
        Candidates: ~/Desktop, ~/Downloads, ~/Documents
        """
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
        ]
        for candidate in candidates:
            if os.path.isdir(candidate):
                self.watched_directories.append(candidate)
                logger.debug("[SETTINGS] added default watch dir: %s", candidate)


# Module-level singleton
settings = Settings.load()
