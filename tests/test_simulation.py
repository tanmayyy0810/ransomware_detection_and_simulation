"""
Automated Simulator Tests.
Verifies controlled renaming, manifest tracking, content preservation, and safe interruption.
"""

import unittest
import tempfile
import hashlib
from pathlib import Path

import config
from core.sandbox_manager import SandboxManager
from core.simulation_engine import SimulationEngine

class TestSimulationEngine(unittest.TestCase):
    """Test suite for the safe ransomware simulator."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory(dir=config.PROJECT_ROOT)
        self.sandbox_path = Path(self.test_dir.name) / "test_sandbox"
        self.sandbox_path.mkdir(parents=True, exist_ok=True)
        self.backup_path = Path(self.test_dir.name) / "backup"
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.manager = SandboxManager(sandbox_path=self.sandbox_path, backup_path=self.backup_path)

    def tearDown(self):
        try:
            self.test_dir.cleanup()
        except Exception:
            pass

    def test_dummy_file_generation_count(self):
        """Prepare demo must generate exactly requested number of files."""
        count, _ = self.manager.prepare_dummy_files(count=20, force_regenerate=True)
        self.assertEqual(count, 20)
        files_on_disk = list(self.sandbox_path.glob("*.*"))
        self.assertEqual(len(files_on_disk), 20)

    def test_manifest_integrity_and_hashes(self):
        """Manifest must contain sha256 checksums and file sizes for all generated files."""
        self.manager.prepare_dummy_files(count=10, force_regenerate=True)
        manifest = self.manager.load_manifest()
        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]), 10)

        for fname, info in manifest["files"].items():
            file_path = self.sandbox_path / fname
            self.assertTrue(file_path.exists())
            content = file_path.read_bytes()
            computed_hash = hashlib.sha256(content).hexdigest()
            self.assertEqual(info["sha256"], computed_hash)
            self.assertEqual(info["size_bytes"], len(content))

    def test_sequential_renaming_appends_locked(self):
        """Simulator must append .locked to dummy files and update state."""
        self.manager.prepare_dummy_files(count=5, force_regenerate=True)
        sim = SimulationEngine(sandbox_manager=self.manager, delay_seconds=0.01)

        processed, total, msg = sim.run_synchronous()
        self.assertEqual(processed, 5)
        self.assertEqual(total, 5)

        # Check all files on disk now end in .locked
        locked_files = list(self.sandbox_path.glob(f"*{config.LOCKED_EXTENSION}"))
        self.assertEqual(len(locked_files), 5)

    def test_file_contents_preserved_non_destructive(self):
        """Simulation must NOT encrypt or destroy file contents."""
        self.manager.prepare_dummy_files(count=5, force_regenerate=True)
        manifest_before = self.manager.load_manifest()

        sim = SimulationEngine(sandbox_manager=self.manager, delay_seconds=0.01)
        sim.run_synchronous()

        # Verify that contents of locked files are identical to original sha256
        for orig_name, info in manifest_before["files"].items():
            locked_name = f"{orig_name}{config.LOCKED_EXTENSION}"
            locked_path = self.sandbox_path / locked_name
            self.assertTrue(locked_path.exists(), f"Locked file {locked_name} should exist")

            content = locked_path.read_bytes()
            curr_hash = hashlib.sha256(content).hexdigest()
            self.assertEqual(info["sha256"], curr_hash, f"Contents of {locked_name} altered!")

    def test_simulation_interruption(self):
        """Simulation must stop cleanly when stop event is signaled."""
        self.manager.prepare_dummy_files(count=15, force_regenerate=True)

        call_count = [0]
        def on_progress(idx, total, old_name, new_name):
            call_count[0] += 1
            if idx >= 3:
                sim.stop()

        sim = SimulationEngine(sandbox_manager=self.manager, delay_seconds=0.05, on_progress=on_progress)
        processed, total, msg = sim.run_synchronous()

        self.assertLessEqual(processed, 4)
        self.assertIn("stopped by user", msg.lower())

if __name__ == "__main__":
    unittest.main()
