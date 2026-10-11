"""
Reset and Recovery Manager.
Restores locked dummy files back to their original names based on verified manifest records.
Ensures repeatable demonstrations without manual file cleanup.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config
from core.sandbox_manager import SandboxManager, SandboxSecurityError

class ResetManager:
    """Manages restoration of the sandbox to its pre-simulation baseline."""
    def __init__(self, sandbox_manager: Optional[SandboxManager] = None):
        self.sandbox_manager = sandbox_manager or SandboxManager()

    def reset_sandbox(self, regenerate_missing: bool = True) -> Tuple[int, int, str]:
        """
        Restore registered files in test_folder back to original names.
        Returns: (restored_count, errors_count, summary_message).
        """
        if not self.sandbox_manager.is_safe_sandbox_dir():
            raise SandboxSecurityError("Reset aborted: Sandbox path safety verification failed!")

        manifest = self.sandbox_manager.load_manifest()
        registered = manifest.get("files", {})

        if not registered:
            # If no manifest exists, prepare fresh demo files
            count, msg = self.sandbox_manager.prepare_dummy_files(count=config.DEFAULT_DUMMY_COUNT, force_regenerate=True)
            return count, 0, f"No previous manifest found. Prepared {count} fresh dummy files."

        restored_count = 0
        errors_count = 0
        error_details = []

        sandbox_dir = self.sandbox_manager.sandbox_path

        for orig_name, info in list(registered.items()):
            current_name = info.get("current_name", orig_name)
            expected_locked_name = f"{orig_name}{config.LOCKED_EXTENSION}"

            orig_path = sandbox_dir / orig_name
            locked_path = sandbox_dir / expected_locked_name
            current_path = sandbox_dir / current_name

            self.sandbox_manager.assert_safe_operation(orig_path)

            try:
                # Case 1: Locked file exists and original does not -> restore it
                if locked_path.exists() and not orig_path.exists():
                    self.sandbox_manager.assert_safe_operation(locked_path)
                    locked_path.rename(orig_path)
                    self.sandbox_manager.update_file_state_in_manifest(orig_name, orig_name, "original")
                    restored_count += 1
                elif current_path.exists() and current_name != orig_name and not orig_path.exists():
                    self.sandbox_manager.assert_safe_operation(current_path)
                    current_path.rename(orig_path)
                    self.sandbox_manager.update_file_state_in_manifest(orig_name, orig_name, "original")
                    restored_count += 1
                elif orig_path.exists():
                    # Already in original state; ensure manifest matches
                    self.sandbox_manager.update_file_state_in_manifest(orig_name, orig_name, "original")
                    # Clean leftover duplicate locked file if present
                    if locked_path.exists():
                        locked_path.unlink()
                else:
                    # File is missing
                    if regenerate_missing:
                        errors_count += 1
                        error_details.append(f"Missing file: {orig_name}")
            except Exception as e:
                errors_count += 1
                error_details.append(f"Failed restoring {orig_name}: {str(e)}")

        # If files were missing or corrupted, perform clean preparation to guarantee ready state
        if errors_count > 0 and regenerate_missing:
            prep_count, prep_msg = self.sandbox_manager.prepare_dummy_files(
                count=config.DEFAULT_DUMMY_COUNT,
                force_regenerate=True
            )
            return prep_count, 0, f"Restored and refreshed {prep_count} dummy files in sandbox."

        summary = f"Reset complete: {restored_count} files restored to original names."
        if error_details:
            summary += f" Encountered {len(error_details)} warnings: {'; '.join(error_details[:3])}"

        return restored_count, errors_count, summary
