"""
Automated Detection Engine Tests.
Verifies sliding-window algorithm, exact threshold edge cases (10 vs 11),
temporal window expiration, event deduplication, and alert cooldown.
"""

import time
import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import config
from core.detection_engine import DetectionEngine
from core.event_manager import EventDebouncer, NormalizedEvent
from core.alert_manager import AlertManager, SecurityAlert
from core.report_manager import ReportManager

def create_mock_event(filename: str, event_type: str = "renamed", is_locked: bool = True) -> NormalizedEvent:
    """Helper to generate a normalized event."""
    now_mono = time.monotonic()
    return NormalizedEvent(
        timestamp_monotonic=now_mono,
        timestamp_iso=time.strftime("%Y-%m-%d %H:%M:%S"),
        event_type=event_type,
        src_path=f"/fake/{filename}",
        dest_path=f"/fake/{filename}.locked" if is_locked else f"/fake/{filename}",
        src_filename=filename,
        dest_filename=f"{filename}.locked" if is_locked else filename,
        is_directory=False,
        is_extension_changed=is_locked,
        old_extension=".txt",
        new_extension=".locked" if is_locked else ".txt",
        is_locked_extension=is_locked
    )

class TestDetectionEngine(unittest.TestCase):
    """Test suite for the behavioral detection engine."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory(dir=config.PROJECT_ROOT)
        self.watch_dir = Path(self.test_dir.name) / "test_folder"
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = Path(self.test_dir.name) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.report_manager = ReportManager(
            log_path=self.reports_dir / "test_log.txt",
            alerts_json_path=self.reports_dir / "test_alerts.json"
        )

    def tearDown(self):
        try:
            self.test_dir.cleanup()
        except Exception:
            pass

    def test_threshold_edge_case_exactly_10_events_no_alert(self):
        """Exactly 10 qualifying events in 5.0 seconds must NOT trigger an alert (Threshold is >10)."""
        alerts_received = []
        detector = DetectionEngine(
            watch_directory=self.watch_dir,
            window_seconds=5.0,
            threshold_events=10,
            on_alert_callback=lambda a: alerts_received.append(a),
            report_manager=self.report_manager
        )

        # Inject exactly 10 rename events
        for i in range(10):
            ev = create_mock_event(f"file{i}.txt")
            detector._handle_filesystem_event(ev)

        self.assertEqual(len(alerts_received), 0, "10 events should not trigger alert when threshold is >10")
        metrics = detector.get_current_metrics()
        self.assertEqual(metrics["qualifying_in_window"], 10)
        self.assertEqual(metrics["status"], "IDLE")

    def test_threshold_edge_case_11_events_triggers_alert(self):
        """11 qualifying events in 5.0 seconds MUST trigger a security alert."""
        alerts_received = []
        detector = DetectionEngine(
            watch_directory=self.watch_dir,
            window_seconds=5.0,
            threshold_events=10,
            on_alert_callback=lambda a: alerts_received.append(a),
            report_manager=self.report_manager
        )

        # Inject 11 rename events
        for i in range(11):
            ev = create_mock_event(f"file{i}.txt")
            detector._handle_filesystem_event(ev)

        self.assertEqual(len(alerts_received), 1, "11 events must trigger an alert")
        alert = alerts_received[0]
        self.assertEqual(alert.qualifying_event_count, 11)
        self.assertEqual(alert.configured_threshold, 10)
        self.assertIn(".locked", alert.changed_extensions)

    def test_sliding_window_expiration(self):
        """Events older than window_seconds must be pruned so slow changes do not trigger alert."""
        alerts_received = []
        # Use a short 0.2s window
        detector = DetectionEngine(
            watch_directory=self.watch_dir,
            window_seconds=0.2,
            threshold_events=5,
            on_alert_callback=lambda a: alerts_received.append(a),
            report_manager=self.report_manager
        )

        # Inject 4 events
        for i in range(4):
            detector._handle_filesystem_event(create_mock_event(f"batch1_{i}.txt"))

        # Wait for the window to expire
        time.sleep(0.3)

        # Inject another 3 events (Total lifetime events = 7, but only 3 in active window)
        for i in range(3):
            detector._handle_filesystem_event(create_mock_event(f"batch2_{i}.txt"))

        self.assertEqual(len(alerts_received), 0, "Expired events should not count toward active window")
        metrics = detector.get_current_metrics()
        self.assertEqual(metrics["qualifying_in_window"], 3)

    def test_event_debouncer(self):
        """Debouncer must filter out identical duplicate OS notifications within debounce window."""
        debouncer = EventDebouncer(debounce_window=0.1)

        # First notification: valid
        is_dup1 = debouncer.is_duplicate("renamed", "/path/a.txt", "/path/a.txt.locked")
        self.assertFalse(is_dup1)

        # Immediate second callback for same operation: duplicate!
        is_dup2 = debouncer.is_duplicate("renamed", "/path/a.txt", "/path/a.txt.locked")
        self.assertTrue(is_dup2)

        # Different file: valid
        is_dup3 = debouncer.is_duplicate("renamed", "/path/b.txt", "/path/b.txt.locked")
        self.assertFalse(is_dup3)

    def test_alert_cooldown_prevents_flooding(self):
        """Alert cooldown must suppress duplicate alerts during one sustained burst."""
        alerts_received = []
        detector = DetectionEngine(
            watch_directory=self.watch_dir,
            window_seconds=5.0,
            threshold_events=5,
            on_alert_callback=lambda a: alerts_received.append(a),
            report_manager=self.report_manager
        )
        detector.alert_manager.cooldown_seconds = 2.0

        # Inject 20 rapid events (all within window)
        for i in range(20):
            detector._handle_filesystem_event(create_mock_event(f"burst_{i}.txt"))

        # Exactly 1 alert should be generated due to cooldown
        self.assertEqual(len(alerts_received), 1)

if __name__ == "__main__":
    unittest.main()
