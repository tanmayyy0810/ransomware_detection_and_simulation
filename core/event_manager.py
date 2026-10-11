"""
Filesystem Event Manager and Watchdog Adapter.
Captures real OS filesystem events, debounces duplicate OS callbacks,
and emits structured event objects for the behavioral detection engine.
"""

import time
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from watchdog.events import FileSystemEventHandler, FileSystemEvent as WatchdogEvent
from watchdog.observers import Observer

import config

@dataclass
class NormalizedEvent:
    """Standardized representation of a qualified filesystem event."""
    timestamp_monotonic: float
    timestamp_iso: str
    event_type: str                   # 'renamed', 'modified', 'created', 'deleted'
    src_path: str
    dest_path: Optional[str]
    src_filename: str
    dest_filename: Optional[str]
    is_directory: bool
    is_extension_changed: bool
    old_extension: str
    new_extension: str
    is_locked_extension: bool

    def to_dict(self) -> Dict:
        return {
            "timestamp_iso": self.timestamp_iso,
            "event_type": self.event_type,
            "src_filename": self.src_filename,
            "dest_filename": self.dest_filename,
            "is_extension_changed": self.is_extension_changed,
            "old_extension": self.old_extension,
            "new_extension": self.new_extension,
            "is_locked_extension": self.is_locked_extension
        }


class EventDebouncer:
    """
    Deduplicates rapid low-level OS notifications for identical file operations.
    Windows file systems often report multiple notifications for a single rename or edit.
    """
    def __init__(self, debounce_window: float = config.EVENT_DEBOUNCE_SECONDS):
        self.debounce_window = debounce_window
        self._history: Dict[Tuple[str, str, Optional[str]], float] = {}

    def is_duplicate(self, event_type: str, src_path: str, dest_path: Optional[str]) -> bool:
        now = time.monotonic()
        key = (event_type, src_path, dest_path)
        last_time = self._history.get(key)

        # Clean old keys periodically
        if len(self._history) > 200:
            self._history = {k: v for k, v in self._history.items() if now - v < self.debounce_window * 10}

        if last_time is not None and (now - last_time) < self.debounce_window:
            return True

        self._history[key] = now
        return False


class WatchdogHandler(FileSystemEventHandler):
    """
    Handles filesystem events specifically within the monitored sandbox directory.
    Filters out directories and debounces low-level OS duplicates.
    """
    def __init__(self, callback: Callable[[NormalizedEvent], None], debouncer: Optional[EventDebouncer] = None):
        super().__init__()
        self.callback = callback
        self.debouncer = debouncer or EventDebouncer()

    def _normalize_and_dispatch(self, raw_type: str, src_path: str, dest_path: Optional[str] = None, is_dir: bool = False):
        if is_dir:
            return

        # Deduplicate low-level identical callbacks
        if self.debouncer.is_duplicate(raw_type, src_path, dest_path):
            return

        now_mono = time.monotonic()
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        src_p = Path(src_path)
        dest_p = Path(dest_path) if dest_path else None

        src_filename = src_p.name
        dest_filename = dest_p.name if dest_p else None

        old_ext = src_p.suffix.lower()
        new_ext = dest_p.suffix.lower() if dest_p else old_ext

        is_ext_changed = (dest_p is not None) and (old_ext != new_ext)
        is_locked = (dest_p is not None) and (dest_filename.endswith(config.LOCKED_EXTENSION) if dest_filename else False)

        normalized = NormalizedEvent(
            timestamp_monotonic=now_mono,
            timestamp_iso=now_iso,
            event_type=raw_type,
            src_path=src_path,
            dest_path=dest_path,
            src_filename=src_filename,
            dest_filename=dest_filename,
            is_directory=is_dir,
            is_extension_changed=is_ext_changed,
            old_extension=old_ext,
            new_extension=new_ext,
            is_locked_extension=is_locked
        )

        try:
            self.callback(normalized)
        except Exception as e:
            # Prevent observer thread crash on callback exception
            print(f"Error in filesystem event callback: {e}")

    def on_moved(self, event: WatchdogEvent):
        # Watchdog moves correspond to file renames
        self._normalize_and_dispatch("renamed", event.src_path, getattr(event, "dest_path", None), event.is_directory)

    def on_modified(self, event: WatchdogEvent):
        self._normalize_and_dispatch("modified", event.src_path, None, event.is_directory)

    def on_created(self, event: WatchdogEvent):
        self._normalize_and_dispatch("created", event.src_path, None, event.is_directory)

    def on_deleted(self, event: WatchdogEvent):
        self._normalize_and_dispatch("deleted", event.src_path, None, event.is_directory)


class FileSystemObserverService:
    """Manages the lifecycle of the Watchdog Observer background thread."""
    def __init__(self, watch_directory: Path, on_event_callback: Callable[[NormalizedEvent], None]):
        self.watch_directory = watch_directory.resolve()
        self.on_event_callback = on_event_callback
        self.observer: Optional[Observer] = None
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running and self.observer is not None and self.observer.is_alive()

    def start(self) -> None:
        if self.is_running:
            return

        if not self.watch_directory.exists():
            self.watch_directory.mkdir(parents=True, exist_ok=True)

        handler = WatchdogHandler(self.on_event_callback)
        self.observer = Observer()
        # Strictly non-recursive observation as specified in prompt
        self.observer.schedule(handler, str(self.watch_directory), recursive=False)
        self.observer.daemon = True
        self.observer.start()
        self._is_running = True

    def stop(self) -> None:
        if self.observer is not None:
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
            except Exception:
                pass
            finally:
                self.observer = None
                self._is_running = False
