"""
MonitoringService — watches directories and routes file events to DetectionEngine.

Architecture:
  Watchdog observer threads → _FileEventHandler.on_* → debounce dict →
  _worker_loop (daemon thread) → DetectionEngine.process()

Debounce logic:
  Each incoming file path is stored in a dict: {path: timestamp_of_last_event}
  A background loop checks this dict every 100ms.
  A path is only dispatched to DetectionEngine when:
    current_time - timestamp >= settings.debounce_seconds
  This collapses rapid duplicate events (e.g. file copy triggers both
  on_created and multiple on_modified) into a single process() call.
"""

import os
import time
import threading
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler, FileSystemEvent

from services.detection_engine import engine
from core.signals  import signals
from core.settings import settings
from utils.logger  import get_logger

logger = get_logger(__name__)


class _FileEventHandler(FileSystemEventHandler):
    """
    Receives raw watchdog events and feeds them into the debounce buffer.
    One instance is shared across all observers.
    """

    def __init__(self, debounce_buffer: dict, buffer_lock: threading.Lock) -> None:
        """
        debounce_buffer : shared dict {abs_path: float (timestamp)}
        buffer_lock     : lock protecting debounce_buffer writes
        """
        super().__init__()
        self._debounce_buffer = debounce_buffer
        self._buffer_lock     = buffer_lock

    def on_created(self, event: FileSystemEvent) -> None:
        """
        Called when a file is created.
        Ignores directory events.
        Records event.src_path in debounce_buffer with current monotonic timestamp.
        """
        if event.is_directory:
            return
        path = str(event.src_path)
        logger.debug("[WATCHER] created: %s", path)
        with self._buffer_lock:
            self._debounce_buffer[path] = time.monotonic()

    def on_modified(self, event: FileSystemEvent) -> None:
        """
        Called when a file is modified.
        Ignores directory events.
        Records event.src_path in debounce_buffer.
        """
        if event.is_directory:
            return
        path = str(event.src_path)
        logger.debug("[WATCHER] modified: %s", path)
        with self._buffer_lock:
            self._debounce_buffer[path] = time.monotonic()

    def on_moved(self, event: FileSystemEvent) -> None:
        """
        Called when a file is moved/renamed.
        Ignores directory events.
        Records event.dest_path (new location) — NOT src_path (file no longer there).
        """
        if event.is_directory:
            return
        dest_path = str(event.dest_path)
        logger.debug("[WATCHER] moved: %s → %s", event.src_path, dest_path)
        with self._buffer_lock:
            self._debounce_buffer[dest_path] = time.monotonic()


class MonitoringService:
    """
    Manages watchdog observers and the debounce worker loop.
    """

    def __init__(self) -> None:
        self._observers:     list             = []
        self._debounce_buf:  dict             = {}
        self._buf_lock:      threading.Lock   = threading.Lock()
        self._worker_thread: threading.Thread | None = None
        self._stop_event:    threading.Event  = threading.Event()
        self._running:       bool             = False

    def start(self, directories: list) -> None:
        """
        Start monitoring all directories in the provided list.

        Steps:
        1. If already running: call self.stop() first, then proceed.
        2. Clear _debounce_buf.
        3. Reset _stop_event.
        4. For each directory in directories:
             - If not os.path.isdir: log WARNING and skip.
             - Create Observer, schedule handler (recursive=True), start it, append.
        5. If no valid directories: log ERROR, return without starting worker.
        6. Start _worker_thread as daemon=True.
        7. Set self._running = True.
        8. Emit signals.monitoring_started.
        9. Log INFO: [MONITOR] started watching N directories.
        """
        if self._running:
            logger.info("[MONITOR] already running — restarting.")
            self.stop()

        with self._buf_lock:
            self._debounce_buf.clear()

        self._stop_event.clear()

        handler = _FileEventHandler(self._debounce_buf, self._buf_lock)
        valid_count = 0

        for directory in directories:
            if not os.path.isdir(directory):
                logger.warning("[MONITOR] skipping invalid directory: %s", directory)
                continue

            try:
                observer = Observer()
                observer.schedule(handler, path=directory, recursive=True)
                observer.start()
                self._observers.append(observer)
                valid_count += 1
                logger.debug("[MONITOR] watching: %s", directory)
            except Exception as e:
                logger.error("[MONITOR] failed to start observer for %s: %s", directory, e)

        if valid_count == 0:
            logger.error("[MONITOR] no valid directories to watch — monitoring not started.")
            return

        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="ddas-worker",
            daemon=True,
        )
        self._worker_thread.start()

        self._running = True
        signals.monitoring_started.emit()
        logger.info("[MONITOR] started watching %d director%s.", valid_count, "y" if valid_count == 1 else "ies")

    def stop(self) -> None:
        """
        Stop all observers and the worker thread cleanly.

        Steps:
        1. If not running: return immediately.
        2. Set _stop_event.
        3. Stop and join each observer (timeout=5s).
        4. Clear _observers list.
        5. Join worker thread (timeout=5s).
        6. Set self._running = False.
        7. Emit signals.monitoring_stopped.
        8. Log INFO: [MONITOR] stopped.
        """
        if not self._running:
            return

        self._stop_event.set()

        for observer in self._observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as e:
                logger.error("[MONITOR] error stopping observer: %s", e)

        self._observers.clear()

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5)
            self._worker_thread = None

        self._running = False
        signals.monitoring_stopped.emit()
        logger.info("[MONITOR] stopped.")

    def is_running(self) -> bool:
        """Return self._running."""
        return self._running

    def _worker_loop(self) -> None:
        """
        Background daemon loop. Runs until _stop_event is set.

        Every 100ms:
        1. Sleep 0.1 s.
        2. Check if _stop_event is set — if so, break.
        3. Snapshot paths whose debounce window has elapsed and remove them from buffer.
        4. Call engine.process(path) for each ready path sequentially.

        Any exception in the loop body is caught, logged, and the loop continues.
        """
        logger.debug("[MONITOR] worker loop started.")
        while True:
            try:
                time.sleep(0.1)

                if self._stop_event.is_set():
                    break

                # Snapshot ready paths (debounce elapsed)
                now = time.monotonic()
                ready: dict = {}
                with self._buf_lock:
                    for path, ts in list(self._debounce_buf.items()):
                        if now - ts >= settings.debounce_seconds:
                            ready[path] = ts
                    for path in ready:
                        del self._debounce_buf[path]

                # Process each ready path sequentially (one file at a time)
                for path in ready:
                    if self._stop_event.is_set():
                        break
                    engine.process(path)

            except Exception as e:
                logger.error("[MONITOR] unexpected error in worker loop: %s", e)
                # Continue — never let the worker thread die silently

        logger.debug("[MONITOR] worker loop exited.")


# Module-level singleton
monitor = MonitoringService()
