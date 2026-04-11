"""
AppSignals — the application-wide Qt signal bus.

Import the singleton:
    from core.signals import signals

Never instantiate AppSignals directly anywhere else.
"""

from PyQt6.QtCore import QObject, pyqtSignal


class AppSignals(QObject):
    """
    All cross-module signals live here.

    Signal definitions:

    duplicate_found(str, str)
        Emitted by DetectionEngine when a full-hash duplicate is confirmed.
        arg0: path of the already-known original file
        arg1: path of the newly detected duplicate file

    monitoring_started()
        Emitted by MonitoringService after observers are running.

    monitoring_stopped()
        Emitted by MonitoringService after all observers have been stopped.

    file_processed(str, str)
        Emitted by DetectionEngine after processing any file (duplicate or not).
        arg0: absolute file path
        arg1: status string — one of: "normal", "duplicate", "error", "skipped"

    scan_stats_updated(int, int)
        Emitted periodically by DetectionEngine.
        arg0: total files processed since app start
        arg1: total duplicates found since app start

    error_occurred(str, str)
        Emitted when a non-fatal error occurs that the UI should know about.
        arg0: module name where error occurred
        arg1: error message string
    """

    duplicate_found    = pyqtSignal(str, str)
    monitoring_started = pyqtSignal()
    monitoring_stopped = pyqtSignal()
    file_processed     = pyqtSignal(str, str)
    scan_stats_updated = pyqtSignal(int, int)
    error_occurred     = pyqtSignal(str, str)


# Module-level singleton — import this object everywhere
signals = AppSignals()
