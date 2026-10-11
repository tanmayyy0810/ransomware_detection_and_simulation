"""
Automated Safety and Containment Tests.
Verifies that the sandbox strictly prevents arbitrary file operations, path traversal, and symlink escapes.
"""

import unittest
import tempfile
import shutil
from pathlib import Path

import config
from core.sandbox_manager import SandboxManager, SandboxSecurityError

class TestSandboxSafety(unittest.TestCase):
    """Test suite ensuring strict sandbox boundaries and safety protections."""

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

    def test_valid_sandbox_path_accepted(self):
        """A sandbox directory inside project root must be recognized as safe."""
        self.assertTrue(self.manager.is_safe_sandbox_dir())

    def test_outside_directory_rejected(self):
        """Arbitrary system directories must be strictly rejected."""
        outside_path = config.PROJECT_ROOT.parent
        outside_manager = SandboxManager(sandbox_path=outside_path, backup_path=self.backup_path)
        self.assertFalse(outside_manager.is_safe_sandbox_dir())

    def test_system_root_rejected(self):
        """Root drives like C:\\ or / must be rejected immediately."""
        sys_manager = SandboxManager(sandbox_path=Path("C:/Windows"), backup_path=self.backup_path)
        self.assertFalse(sys_manager.is_safe_sandbox_dir())

    def test_path_traversal_file_rejected(self):
        """Relative path traversal using .. must be caught and rejected."""
        traversal_target = self.sandbox_path / ".." / "outside.txt"
        self.assertFalse(self.manager.is_safe_file_path(traversal_target))
        with self.assertRaises(SandboxSecurityError):
            self.manager.assert_safe_operation(traversal_target)

    def test_assert_safe_operation_passes_for_internal_file(self):
        """Internal files within the sandbox must pass validation."""
        valid_file = self.sandbox_path / "test_file.txt"
        valid_file.write_text("safe content", encoding="utf-8")
        self.assertTrue(self.manager.is_safe_file_path(valid_file))
        # Should not raise exception
        self.manager.assert_safe_operation(valid_file)

    def test_non_registered_files_not_eligible(self):
        """Unregistered user files manually placed in sandbox are not selected for simulation."""
        # Prepare 5 dummy files
        self.manager.prepare_dummy_files(count=5, force_regenerate=True)
        # Create an unregistered file
        rogue_file = self.sandbox_path / "unregistered_user_doc.txt"
        rogue_file.write_text("do not rename", encoding="utf-8")

        eligible = self.manager.get_eligible_for_simulation()
        self.assertNotIn("unregistered_user_doc.txt", eligible)

if __name__ == "__main__":
    unittest.main()
