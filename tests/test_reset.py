"""
Automated Reset and Sandbox Recovery Tests.
Verifies restoration of original names after full or partial simulations,
manifest alignment, content preservation, and demonstration repeatability.
"""

import unittest
import tempfile
import hashlib
from pathlib import Path

import config
from core.sandbox_manager import SandboxManager
from core.simulation_engine import SimulationEngine
from core.reset_manager import ResetManager

class TestResetManager(unittest.TestCase):
    """Test suite for sandbox reset and recovery mechanism."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory(dir=config.PROJECT_ROOT)
        self.sandbox_path = Path(self.test_dir.name) / "test_sandbox"
        self.sandbox_path.mkdir(parents=True, exist_ok=True)
        self.backup_path = Path(self.test_dir.name) / "backup"
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.sandbox = SandboxManager(sandbox_path=self.sandbox_path, backup_path=self.backup_path)
        self.resetter = ResetManager(sandbox_manager=self.sandbox)

    def tearDown(self):
        try:
            self.test_dir.cleanup()
        except Exception:
            pass

    def test_reset_after_full_simulation(self):
        """All files renamed to .locked must be restored to original names."""
        self.sandbox.prepare_dummy_files(count=10, force_regenerate=True)
        manifest_before = self.sandbox.load_manifest()

        # Run complete simulation
        sim = SimulationEngine(sandbox_manager=self.sandbox, delay_seconds=0.01)
        sim.run_synchronous()

        # Verify all files on disk are locked
        locked_files = list(self.sandbox_path.glob(f"*{config.LOCKED_EXTENSION}"))
        self.assertEqual(len(locked_files), 10)

        # Run reset
        restored, errors, summary = self.resetter.reset_sandbox()
        self.assertEqual(restored, 10)
        self.assertEqual(errors, 0)

        # Verify all files are restored to original names
        restored_locked = list(self.sandbox_path.glob(f"*{config.LOCKED_EXTENSION}"))
        self.assertEqual(len(restored_locked), 0)

        original_files = list(self.sandbox_path.glob("*.*"))
        self.assertEqual(len(original_files), 10)

        # Verify content integrity
        for fname, info in manifest_before["files"].items():
            fpath = self.sandbox_path / fname
            self.assertTrue(fpath.exists())
            self.assertEqual(hashlib.sha256(fpath.read_bytes()).hexdigest(), info["sha256"])

    def test_reset_after_partial_simulation(self):
        """Reset must correctly restore even if only a subset of files were renamed."""
        self.sandbox.prepare_dummy_files(count=10, force_regenerate=True)

        # Rename only first 4 files
        def on_prog(idx, total, o, n):
            if idx >= 4:
                sim.stop()

        sim = SimulationEngine(sandbox_manager=self.sandbox, delay_seconds=0.05, on_progress=on_prog)
        sim.run_synchronous()

        # Should have approximately 4 locked files and 6 original files
        locked_count = len(list(self.sandbox_path.glob(f"*{config.LOCKED_EXTENSION}")))
        self.assertGreaterEqual(locked_count, 1)

        # Reset
        restored, errors, summary = self.resetter.reset_sandbox()
        self.assertEqual(restored, locked_count)
        self.assertEqual(errors, 0)

        # All 10 must now be in original state
        locked_remaining = list(self.sandbox_path.glob(f"*{config.LOCKED_EXTENSION}"))
        self.assertEqual(len(locked_remaining), 0)
        original_count = len(list(self.sandbox_path.glob("*.*")))
        self.assertEqual(original_count, 10)

    def test_repeated_demonstration_cycle(self):
        """Sandbox must support consecutive simulate -> reset -> simulate -> reset cycles."""
        self.sandbox.prepare_dummy_files(count=5, force_regenerate=True)

        for cycle in range(2):
            sim = SimulationEngine(sandbox_manager=self.sandbox, delay_seconds=0.01)
            processed, total, _ = sim.run_synchronous()
            self.assertEqual(processed, 5)

            restored, errors, _ = self.resetter.reset_sandbox()
            self.assertEqual(restored, 5)
            self.assertEqual(errors, 0)

        # Final state check
        files = self.sandbox.get_file_statuses()
        self.assertEqual(len(files), 5)
        for f in files:
            self.assertEqual(f["status"], "Original")

if __name__ == "__main__":
    unittest.main()
