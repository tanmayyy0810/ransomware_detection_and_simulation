"""
Behavioral Detection Engine.
Implements a true sliding-window algorithm utilizing collections.deque and time.monotonic().
Detects high-frequency file modifications and bulk renames without signatures.
"""

import time
import threading
from collections import deque
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import config
from core.event_manager import FileSystemObserverService, NormalizedEvent
from core.alert_manager import AlertManager, SecurityAlert
from core.report_manager import ReportManager

class DetectionEngine:
    """
    Real-time behavioral filesystem anomaly detector.
    Analyzes velocity and pattern of filesystem events using a sliding time window.
    """
    def __init__(
        self,
        watch_directory: Optional[Path] = None,
        window_seconds: float = config.DEFAULT_WINDOW_SECONDS,
        threshold_events: int = config.DEFAULT_THRESHOLD_EVENTS,
        on_event_callback: Optional[Callable[[NormalizedEvent], None]] = None,
        on_alert_callback: Optional[Callable[[SecurityAlert], None]] = None,
        on_metrics_callback: Optional[Callable[[Dict], None]] = None,
        report_manager: Optional[ReportManager] = None
    ):
        self.watch_directory = (watch_directory or config.TEST_FOLDER_PATH).resolve()
        self.window_seconds = window_seconds
        self.threshold_events = threshold_events

        self.on_event_callback = on_event_callback
        self.on_alert_callback = on_alert_callback
        self.on_metrics_callback = on_metrics_callback

        self.report_manager = report_manager or ReportManager()
        self.alert_manager = AlertManager()

        # Sliding window deque storing tuples: (timestamp_monotonic, NormalizedEvent)
        self._window: deque = deque()
        self._lock = threading.Lock()

        # Operational metrics
        self.total_events_observed = 0
        self.total_alerts_generated = 0
        self.status = "IDLE"  # "IDLE", "MONITORING", "SUSPICIOUS"
        self.active_alert: Optional[SecurityAlert] = None

        # Underlying filesystem observer
        self.observer_service = FileSystemObserverService(
            self.watch_directory,
            self._handle_filesystem_event
        )

    @property
    def is_monitoring(self) -> bool:
        return self.observer_service.is_running

    def set_parameters(self, window_seconds: Optional[float] = None, threshold_events: Optional[int] = None) -> None:
        """Dynamically configure detection thresholds."""
        with self._lock:
            if window_seconds is not None and window_seconds > 0:
                self.window_seconds = float(window_seconds)
            if threshold_events is not None and threshold_events > 0:
                self.threshold_events = int(threshold_events)
        self._prune_and_notify_metrics(time.monotonic())

    def start_monitoring(self) -> None:
        """Start the background watchdog observer and set state to active."""
        if self.is_monitoring:
            return

        with self._lock:
            self._window.clear()
            self.active_alert = None
            self.status = "MONITORING"
            self.alert_manager.reset_cooldown()

        self.observer_service.start()
        self.report_manager.log_event(
            f"Monitoring started on directory '{self.watch_directory}' "
            f"(Threshold: >{self.threshold_events} events in {self.window_seconds:.1f}s)",
            level="INFO"
        )
        self._notify_metrics()

    def stop_monitoring(self) -> None:
        """Stop background observer cleanly."""
        if not self.is_monitoring:
            return

        self.observer_service.stop()
        with self._lock:
            self.status = "IDLE"

        self.report_manager.log_event(
            f"Monitoring stopped on directory '{self.watch_directory}'",
            level="INFO"
        )
        self._notify_metrics()

    def reset_detection_state(self) -> None:
        """Reset internal sliding window, alerts, and metrics without stopping observer."""
        with self._lock:
            self._window.clear()
            self.active_alert = None
            self.status = "MONITORING" if self.is_monitoring else "IDLE"
            self.alert_manager.reset_cooldown()
        self._notify_metrics()

    def _prune_window(self, now: float) -> None:
        """Remove events from the deque that fall outside the active sliding window."""
        cutoff = now - self.window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

    def _handle_filesystem_event(self, event: NormalizedEvent) -> None:
        """Process incoming qualified event through the sliding window algorithm."""
        now = time.monotonic()
        alert_to_dispatch: Optional[SecurityAlert] = None

        with self._lock:
            self.total_events_observed += 1

            # Only count modifying/renaming events towards ransomware velocity
            # Creation and deletion can be observed, but mass renames/modifications are primary qualifying events
            is_qualifying = event.event_type in ("renamed", "modified")

            if is_qualifying:
                self._window.append((now, event))

            # Prune sliding window to current window_seconds
            self._prune_window(now)

            qualifying_count = len(self._window)

            # Check if qualifying event count strictly exceeds the threshold (> threshold)
            if qualifying_count > self.threshold_events:
                if self.alert_manager.can_trigger_alert():
                    # Calculate true measured duration of the triggering burst
                    oldest_ts = self._window[0][0]
                    duration = max(0.01, now - oldest_ts)

                    # Gather affected files and observed extensions within the window
                    affected_files: List[str] = []
                    extensions: Set[str] = set()

                    for _, ev in self._window:
                        fname = ev.dest_filename or ev.src_filename
                        affected_files.append(fname)
                        if ev.is_extension_changed and ev.new_extension:
                            extensions.add(ev.new_extension)
                        elif ev.is_locked_extension:
                            extensions.add(config.LOCKED_EXTENSION)

                    new_alert = self.alert_manager.create_alert(
                        monitored_dir=str(self.watch_directory.name),
                        qualifying_events=qualifying_count,
                        threshold=self.threshold_events,
                        window_seconds=self.window_seconds,
                        duration_seconds=duration,
                        affected_files=affected_files,
                        changed_extensions=list(extensions)
                    )

                    self.active_alert = new_alert
                    self.total_alerts_generated += 1
                    self.status = "SUSPICIOUS"
                    alert_to_dispatch = new_alert

        # Dispatch callbacks and logging outside lock to prevent deadlock
        if is_qualifying:
            dest_info = f" -> {event.dest_filename}" if event.dest_filename else ""
            self.report_manager.log_event(
                f"Filesystem event: [{event.event_type}] {event.src_filename}{dest_info}",
                level="DEBUG"
            )

        if alert_to_dispatch:
            self.report_manager.log_alert(alert_to_dispatch)
            if self.on_alert_callback:
                try:
                    self.on_alert_callback(alert_to_dispatch)
                except Exception as e:
                    print(f"Error in on_alert_callback: {e}")

        if self.on_event_callback:
            try:
                self.on_event_callback(event)
            except Exception as e:
                print(f"Error in on_event_callback: {e}")

        self._notify_metrics()

    def _prune_and_notify_metrics(self, now: float) -> None:
        with self._lock:
            self._prune_window(now)
        self._notify_metrics()

    def _notify_metrics(self) -> None:
        """Compute snapshot metrics and notify consumer."""
        now = time.monotonic()
        with self._lock:
            self._prune_window(now)
            qualifying_in_window = len(self._window)

            distinct_files = set()
            locked_count = 0
            for _, ev in self._window:
                name = ev.dest_filename or ev.src_filename
                distinct_files.add(name)
                if ev.is_locked_extension:
                    locked_count += 1

            metrics = {
                "status": self.status,
                "is_monitoring": self.is_monitoring,
                "total_events_observed": self.total_events_observed,
                "qualifying_in_window": qualifying_in_window,
                "threshold_events": self.threshold_events,
                "window_seconds": self.window_seconds,
                "distinct_files_in_window": len(distinct_files),
                "locked_count_in_window": locked_count,
                "total_alerts": self.total_alerts_generated,
                "has_active_alert": self.active_alert is not None,
                "active_alert_id": self.active_alert.alert_id if self.active_alert else None
            }

        if self.on_metrics_callback:
            try:
                self.on_metrics_callback(metrics)
            except Exception as e:
                print(f"Error in on_metrics_callback: {e}")

    def get_current_metrics(self) -> Dict:
        now = time.monotonic()
        with self._lock:
            self._prune_window(now)
            distinct_files = {ev.dest_filename or ev.src_filename for _, ev in self._window}
            return {
                "status": self.status,
                "is_monitoring": self.is_monitoring,
                "total_events_observed": self.total_events_observed,
                "qualifying_in_window": len(self._window),
                "threshold_events": self.threshold_events,
                "window_seconds": self.window_seconds,
                "distinct_files_in_window": len(distinct_files),
                "total_alerts": self.total_alerts_generated,
                "has_active_alert": self.active_alert is not None,
                "active_alert_id": self.active_alert.alert_id if self.active_alert else None
            }
