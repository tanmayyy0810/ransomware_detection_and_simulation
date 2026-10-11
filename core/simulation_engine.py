"""
Safe Ransomware Behavior Simulator.
Renames registered dummy files to <filename>.locked sequentially with configurable delay.
Operates exclusively within the isolated sandbox environment.
"""

import time
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import config
from core.sandbox_manager import SandboxManager, SandboxSecurityError

class SimulationEngine:
    """
    Executes controlled, harmless ransomware-like bulk renaming.
    Emulates mass extension modification to test behavioral detection systems.
    """
    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        delay_seconds: float = config.DEFAULT_SIMULATION_DELAY,
        on_progress: Optional[Callable[[int, int, str, str], None]] = None,
        on_finished: Optional[Callable[[int, int, str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None
    ):
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.delay_seconds = delay_seconds
        self.on_progress = on_progress
        self.on_finished = on_finished
        self.on_error = on_error

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self.is_running = False
        self.files_processed = 0
        self.total_eligible = 0
        self.current_file = ""

    def set_delay(self, delay_seconds: float) -> None:
        """Update delay between consecutive file renames."""
        with self._lock:
            if delay_seconds >= 0:
                self.delay_seconds = float(delay_seconds)

    def stop(self) -> None:
        """Signal running simulation to halt immediately."""
        self._stop_event.set()

    def start_in_background(self) -> bool:
        """Launch simulation in a dedicated background worker thread."""
        with self._lock:
            if self.is_running:
                return False
            self.is_running = True
            self._stop_event.clear()

        self._thread = threading.Thread(target=self._run_simulation, daemon=True)
        self._thread.start()
        return True

    def run_synchronous(self) -> Tuple[int, int, str]:
        """Run simulation synchronously (used by CLI simulator script)."""
        with self._lock:
            if self.is_running:
                return 0, 0, "Simulation is already running."
            self.is_running = True
            self._stop_event.clear()

        return self._run_simulation()

    def _run_simulation(self) -> Tuple[int, int, str]:
        """Main simulation execution loop."""
        try:
            # 1. Enforce sandbox perimeter safety
            if not self.sandbox_manager.is_safe_sandbox_dir():
                raise SandboxSecurityError("Sandbox validation failed: Unauthorized target directory!")

            # 2. Query registered dummy files eligible for renaming
            eligible_files = self.sandbox_manager.get_eligible_for_simulation()
            self.total_eligible = len(eligible_files)
            self.files_processed = 0

            if self.total_eligible == 0:
                msg = "No eligible original dummy files found. Please prepare demo files first."
                if self.on_error:
                    self.on_error(msg)
                with self._lock:
                    self.is_running = False
                return 0, 0, msg

            # 3. Iterate over eligible dummy files sequentially
            for idx, orig_filename in enumerate(eligible_files, start=1):
                if self._stop_event.is_set():
                    msg = f"Simulation stopped by user after renaming {self.files_processed}/{self.total_eligible} files."
                    if self.on_finished:
                        self.on_finished(self.files_processed, self.total_eligible, msg)
                    with self._lock:
                        self.is_running = False
                    return self.files_processed, self.total_eligible, msg

                old_path = self.sandbox_manager.sandbox_path / orig_filename
                new_filename = f"{orig_filename}{config.LOCKED_EXTENSION}"
                new_path = self.sandbox_manager.sandbox_path / new_filename

                # Immediate safety assertions prior to operation
                self.sandbox_manager.assert_safe_operation(old_path)
                self.sandbox_manager.assert_safe_operation(new_path)

                if not old_path.exists():
                    continue

                if new_path.exists():
                    # Destination already exists; skip to avoid collision/overwriting
                    continue

                # Perform harmless atomic filesystem rename
                old_path.rename(new_path)

                # Update state in sandbox manifest
                self.sandbox_manager.update_file_state_in_manifest(
                    original_name=orig_filename,
                    new_name=new_filename,
                    status="locked"
                )

                self.files_processed = idx
                self.current_file = new_filename

                if self.on_progress:
                    try:
                        self.on_progress(idx, self.total_eligible, orig_filename, new_filename)
                    except Exception as e:
                        print(f"Error in on_progress callback: {e}")

                # Configurable pause between operations
                delay = self.delay_seconds
                if delay > 0 and idx < self.total_eligible:
                    # Sleep in small slices to remain immediately responsive to stop signals
                    slice_step = 0.05
                    elapsed = 0.0
                    while elapsed < delay:
                        if self._stop_event.is_set():
                            break
                        time.sleep(min(slice_step, delay - elapsed))
                        elapsed += slice_step

            final_msg = f"Simulation completed successfully: {self.files_processed}/{self.total_eligible} dummy files renamed."
            if self.on_finished:
                try:
                    self.on_finished(self.files_processed, self.total_eligible, final_msg)
                except Exception as e:
                    print(f"Error in on_finished callback: {e}")

            return self.files_processed, self.total_eligible, final_msg

        except Exception as e:
            err_msg = f"Simulation error: {str(e)}"
            if self.on_error:
                try:
                    self.on_error(err_msg)
                except Exception:
                    pass
            return self.files_processed, self.total_eligible, err_msg

        finally:
            with self._lock:
                self.is_running = False
