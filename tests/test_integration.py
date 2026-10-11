"""
End-to-End Integration Tests.
Executes the full operational lifecycle:
Prepare -> Monitor -> Simulate -> Detect -> Alert -> Log -> Stop -> Reset -> Repeat.
"""

import time
import unittest
import tempfile
from pathlib import Path

import config
from core.sandbox_manager import SandboxManager
from core.simulation_engine import SimulationEngine
from core.detection_engine import DetectionEngine
from core.reset_manager import ResetManager
from core.report_manager import ReportManager

class TestEndToEndIntegration(unittest.TestCase):
    """Verifies complete end-to-end integration between detector, simulator, and filesystem."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory(dir=config.PROJECT_ROOT)
        self.sandbox_path = Path(self.test_dir.name) / "test_sandbox"
        self.sandbox_path.mkdir(parents=True, exist_ok=True)
        self.backup_path = Path(self.test_dir.name) / "backup"
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.reports_path = Path(self.test_dir.name) / "reports"
        self.reports_path.mkdir(parents=True, exist_ok=True)

        self.sandbox = SandboxManager(sandbox_path=self.sandbox_path, backup_path=self.backup_path)
        self.reports = ReportManager(
            log_path=self.reports_path / "security_log.txt",
            alerts_json_path=self.reports_path / "alerts.json"
        )
        self.resetter = ResetManager(sandbox_manager=self.sandbox)

    def tearDown(self):
        try:
            self.test_dir.cleanup()
        except Exception:
            pass

    def test_full_operational_lifecycle(self):
        """Execute complete lifecycle with real filesystem watchdog events."""
        # 1. Prepare 15 dummy files
        count, _ = self.sandbox.prepare_dummy_files(count=15, force_regenerate=True)
        self.assertEqual(count, 15)

        # 2. Start monitoring with threshold=10 in 5.0 seconds
        alerts_captured = []
        events_captured = []

        detector = DetectionEngine(
            watch_directory=self.sandbox_path,
            window_seconds=5.0,
            threshold_events=10,
            on_event_callback=lambda ev: events_captured.append(ev),
            on_alert_callback=lambda al: alerts_captured.append(al),
            report_manager=self.reports
        )
        detector.start_monitoring()
        time.sleep(0.3)  # Allow watchdog background observer thread to initialize

        try:
            # 3. Run simulation to rename all 15 files with fast 0.05s delay
            # 15 renames in ~0.8s will cross threshold of 10 within 5s!
            sim = SimulationEngine(sandbox_manager=self.sandbox, delay_seconds=0.05)
            processed, total, summary = sim.run_synchronous()

            self.assertEqual(processed, 15)

            # Allow watchdog observer to capture all queued events and process
            time.sleep(1.0)

            # 4. Verify detection and alert
            self.assertGreaterEqual(len(events_captured), 10, "Detector should observe file events")
            self.assertGreaterEqual(len(alerts_captured), 1, "Alert must be triggered for >10 events in window")

            first_alert = alerts_captured[0]
            self.assertEqual(first_alert.configured_threshold, 10)
            self.assertGreaterEqual(first_alert.qualifying_event_count, 11)

            # 5. Verify security log file persistence
            self.assertTrue(self.reports.log_path.exists())
            log_content = self.reports.read_latest_log_lines(100)
            self.assertIn("SECURITY ALERT", log_content)
            self.assertIn(first_alert.alert_id, log_content)

            # Verify structured JSON
            recent_alerts = self.reports.get_recent_alerts()
            self.assertGreaterEqual(len(recent_alerts), 1)

        finally:
            # 6. Stop monitoring
            detector.stop_monitoring()

        # 7. Reset sandbox back to baseline
        restored, errors, r_summary = self.resetter.reset_sandbox()
        self.assertEqual(restored, 15)
        self.assertEqual(errors, 0)

        # Verify all 15 files are restored to original extension on disk
        files_after_reset = self.sandbox.get_file_statuses()
        self.assertEqual(len(files_after_reset), 15)
        for f in files_after_reset:
            self.assertEqual(f["status"], "Original")

if __name__ == "__main__":
    unittest.main()
