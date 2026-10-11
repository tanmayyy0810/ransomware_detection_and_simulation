"""
Strict Sandbox Safety and Dummy File Manager.
Enforces non-negotiable containment within the designated test_folder.
Prevents directory traversal, symlink escaping, and modification of arbitrary files.
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config

class SandboxSecurityError(Exception):
    """Raised when an operation violates sandbox containment boundaries."""
    pass


# Defined set of 20 realistic academic dummy files
DUMMY_FILE_TEMPLATES = [
    ("notes1.txt", "Operating Systems Lecture Notes\nTopic: Process Synchronization and Deadlocks\nSemester: Fall 2026"),
    ("notes2.txt", "Research Notes: Virtual Memory Management\nPaging algorithms: FIFO, LRU, Clock, and Working Set model."),
    ("report.txt", "Quarterly System Security Audit Report\nSummary: Behavioral detection layer operational with zero critical alerts."),
    ("sample_data.csv", "id,metric_name,baseline_value,observed_value\n1,cpu_util,42.5,45.1\n2,io_rate,120.0,131.4\n3,mem_used,68.2,70.5"),
    ("project_notes.md", "# Project Architecture\n\n- Detection Engine: Watchdog sliding window\n- Simulation Engine: Sandbox rename\n- Safety: Strict containment"),
    ("system_config.json", '{\n  "service_name": "os_monitor",\n  "version": "1.0.0",\n  "buffer_size_kb": 1024,\n  "log_level": "INFO"\n}'),
    ("audit_log.log", "[2026-10-10 08:00:01] Service initialized\n[2026-10-10 08:00:02] Sandbox perimeter verified\n[2026-10-10 08:00:05] Ready"),
    ("expenses.csv", "item_id,category,amount_usd,approved\n101,Lab Equipment,450.00,true\n102,Textbooks,120.50,true\n103,Software License,300.00,true"),
    ("presentation_outline.md", "# Ransomware Behavior Detection\n\n1. Background and Threat Model\n2. Behavior vs Signature Detection\n3. Sliding-window Algorithm\n4. Demonstration"),
    ("customer_records.csv", "client_id,account_tier,status,region\n901,Enterprise,Active,US-East\n902,Academic,Active,EU-Central\n903,Developer,Active,AP-South"),
    ("todo_list.txt", "Academic Milestone Tasks:\n- Verify file rename frequency\n- Run unit tests on sliding window\n- Document academic concepts"),
    ("readme_draft.md", "# Preliminary Research Draft\nBehavioral indicators of malicious encryption schemes in modern OS kernels."),
    ("server_metrics.json", '{\n  "uptime_hours": 720,\n  "load_average": [0.15, 0.22, 0.18],\n  "disk_free_gb": 128.4,\n  "active_daemons": 8\n}'),
    ("network_diag.log", "[2026-10-10 09:12:30] Interface eth0 up\n[2026-10-10 09:12:31] Ping gateway 192.168.1.1: 0.8ms\n[2026-10-10 09:12:32] All sockets healthy"),
    ("research_paper.txt", "Title: Dynamic File System Anomaly Detection\nAbstract: Analyzing entropy and velocity in localized I/O streams."),
    ("inventory.csv", "asset_tag,type,location,status\nLAB-01,Workstation,Room 304,In Use\nLAB-02,Server,Rack A,In Use\nLAB-03,Switch,Rack B,Active"),
    ("meeting_minutes.txt", "Advisory Committee Meeting\nDate: 2026-10-09\nAttendees: Research Team\nAgenda: Protection and Security module demo validation."),
    ("app_settings.json", '{\n  "window_width": 1100,\n  "window_height": 720,\n  "theme": "slate_dark",\n  "refresh_interval_ms": 100\n}'),
    ("changelog.md", "# System Changelog\n\n## v1.0.0 (2026-10-11)\n- Initial clean release of behavioral detector and simulation sandbox."),
    ("error_dump.log", "[2026-10-10 11:45:00] No critical failures detected. Routine self-test completed with exit code 0.")
]


class SandboxManager:
    """Manages the isolated sandbox test environment and enforces containment safety."""

    def __init__(self, sandbox_path: Optional[Path] = None, backup_path: Optional[Path] = None):
        self.sandbox_path = (sandbox_path or config.TEST_FOLDER_PATH).resolve()
        self.backup_path = (backup_path or config.BACKUP_PATH).resolve()
        self.manifest_file = self.backup_path / "manifest.json"
        self._ensure_sandbox_dirs()

    def _ensure_sandbox_dirs(self) -> None:
        """Ensure backup directory exists; test folder is validated."""
        self.backup_path.mkdir(parents=True, exist_ok=True)

    def is_safe_sandbox_dir(self) -> bool:
        """
        Verify that the sandbox directory is strictly inside the project root,
        is not a system directory, and is not a symlink.
        """
        try:
            resolved_sandbox = self.sandbox_path.resolve()
            resolved_root = config.PROJECT_ROOT.resolve()

            # Must be strictly a descendant of project root
            if not resolved_sandbox.is_relative_to(resolved_root):
                return False

            # Must not be the project root itself
            if resolved_sandbox == resolved_root:
                return False

            # Must not be a symlink
            if self.sandbox_path.is_symlink():
                return False

            # Explicit check against common forbidden system root directories
            forbidden_roots = ["C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Users", "/etc", "/usr", "/var", "/bin"]
            for forbidden in forbidden_roots:
                if str(resolved_sandbox).lower().startswith(forbidden.lower()) and len(str(resolved_sandbox)) <= len(forbidden) + 2:
                    return False

            return True
        except Exception:
            return False

    def is_safe_file_path(self, file_path: Path) -> bool:
        """
        Verify that an individual file target path is strictly inside the sandbox directory,
        has no symlinks, and does not perform directory traversal.
        """
        if not self.is_safe_sandbox_dir():
            return False

        try:
            resolved_file = file_path.resolve()
            resolved_sandbox = self.sandbox_path.resolve()

            # Target must be strictly inside the sandbox
            if not resolved_file.is_relative_to(resolved_sandbox):
                return False

            # Must not equal the sandbox folder itself
            if resolved_file == resolved_sandbox:
                return False

            # Must not be a symlink
            if file_path.is_symlink():
                return False

            return True
        except Exception:
            return False

    def assert_safe_operation(self, file_path: Path) -> None:
        """Raise SandboxSecurityError if file_path is not safely inside sandbox."""
        if not self.is_safe_file_path(file_path):
            raise SandboxSecurityError(f"Security violation: Target path '{file_path}' is outside authorized sandbox!")

    def load_manifest(self) -> Dict:
        """Load manifest from disk if it exists, otherwise return empty structure."""
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {"created_at": None, "sandbox_path": str(self.sandbox_path), "files": {}}
        return {"created_at": None, "sandbox_path": str(self.sandbox_path), "files": {}}

    def save_manifest(self, manifest_data: Dict) -> None:
        """Persist sandbox file manifest safely outside the watched test_folder."""
        self.backup_path.mkdir(parents=True, exist_ok=True)
        tmp_file = self.manifest_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        tmp_file.replace(self.manifest_file)

    def prepare_dummy_files(self, count: int = 20, force_regenerate: bool = False) -> Tuple[int, str]:
        """
        Generate specified number of realistic dummy files in test_folder and register them.
        Returns (number_of_files_prepared, message).
        """
        if not self.is_safe_sandbox_dir():
            raise SandboxSecurityError("Cannot prepare files: Sandbox directory failed safety validation!")

        self.sandbox_path.mkdir(parents=True, exist_ok=True)
        manifest = self.load_manifest()
        current_files = manifest.get("files", {})

        # If files already exist and force_regenerate is False, verify their status
        if current_files and not force_regenerate:
            existing_count = sum(1 for name, info in current_files.items() if (self.sandbox_path / info["current_name"]).exists())
            if existing_count >= count:
                return existing_count, f"Sandbox already prepared with {existing_count} verified dummy files."

        templates = DUMMY_FILE_TEMPLATES[:count]
        created_count = 0
        new_manifest_files = {}

        for filename, content in templates:
            target_path = self.sandbox_path / filename
            self.assert_safe_operation(target_path)

            # Prevent double-locked or collision
            locked_name = f"{filename}{config.LOCKED_EXTENSION}"
            locked_path = self.sandbox_path / locked_name
            if locked_path.exists():
                locked_path.unlink()

            content_bytes = content.encode("utf-8")
            sha256_hash = hashlib.sha256(content_bytes).hexdigest()

            with open(target_path, "wb") as f:
                f.write(content_bytes)

            new_manifest_files[filename] = {
                "original_name": filename,
                "current_name": filename,
                "extension": Path(filename).suffix,
                "size_bytes": len(content_bytes),
                "sha256": sha256_hash,
                "status": "original",
                "registered_at": datetime.now().isoformat()
            }
            created_count += 1

        manifest_data = {
            "created_at": datetime.now().isoformat(),
            "sandbox_path": str(self.sandbox_path),
            "total_files": created_count,
            "files": new_manifest_files
        }
        self.save_manifest(manifest_data)
        return created_count, f"Successfully generated {created_count} registered dummy files in sandbox."

    def get_registered_files(self) -> Dict[str, Dict]:
        """Return registered files from manifest."""
        manifest = self.load_manifest()
        return manifest.get("files", {})

    def get_eligible_for_simulation(self) -> List[str]:
        """
        Return list of filenames in sandbox that are currently in their original registered state,
        exist on disk, and are eligible to be renamed by the simulator.
        """
        registered = self.get_registered_files()
        eligible = []
        for orig_name, info in registered.items():
            curr_name = info.get("current_name", orig_name)
            curr_path = self.sandbox_path / curr_name
            # Eligible only if file exists on disk, current name equals original name (not already locked)
            if curr_path.exists() and not curr_name.endswith(config.LOCKED_EXTENSION):
                eligible.append(curr_name)
        eligible.sort()
        return eligible

    def get_file_statuses(self) -> List[Dict]:
        """
        Inspect physical filesystem in sandbox and correlate with manifest.
        Returns list of file status dictionaries for UI table presentation.
        """
        if not self.sandbox_path.exists():
            return []

        registered = self.get_registered_files()
        results = []

        try:
            for item in sorted(self.sandbox_path.iterdir()):
                if item.is_file():
                    fname = item.name
                    stat = item.stat()
                    mod_time = datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M:%S")
                    size_kb = f"{stat.st_size / 1024:.1f} KB" if stat.st_size >= 1024 else f"{stat.st_size} B"

                    is_locked = fname.endswith(config.LOCKED_EXTENSION)
                    status = "Renamed (.locked)" if is_locked else "Original"

                    # Check if file is registered in manifest
                    orig_lookup = fname[:-len(config.LOCKED_EXTENSION)] if is_locked else fname
                    is_registered = orig_lookup in registered

                    results.append({
                        "filename": fname,
                        "extension": item.suffix,
                        "status": status,
                        "size": size_kb,
                        "modified": mod_time,
                        "registered": is_registered,
                        "path": str(item)
                    })
        except Exception:
            pass

        return results

    def update_file_state_in_manifest(self, original_name: str, new_name: str, status: str) -> None:
        """Update individual file status in manifest after verified operation."""
        manifest = self.load_manifest()
        if "files" in manifest and original_name in manifest["files"]:
            manifest["files"][original_name]["current_name"] = new_name
            manifest["files"][original_name]["status"] = status
            self.save_manifest(manifest)
