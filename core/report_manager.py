"""
Report and Security Logging Manager.
Persists human-readable security logs and structured JSON alert histories outside the monitored directory.
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import config
from core.alert_manager import SecurityAlert

class ReportManager:
    """Thread-safe logging manager for operational events and security alerts."""
    def __init__(self, log_path: Optional[Path] = None, alerts_json_path: Optional[Path] = None):
        self.log_path = (log_path or config.SECURITY_LOG_FILE).resolve()
        self.alerts_json_path = (alerts_json_path or config.ALERTS_JSON_FILE).resolve()
        self._lock = threading.Lock()
        self._ensure_reports_dir()

    def _ensure_reports_dir(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.alerts_json_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, message: str, level: str = "INFO") -> None:
        """Write timestamped entry to security_log.txt."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}\n"
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(entry)
            except Exception as e:
                print(f"Failed writing to security log: {e}")

    def log_alert(self, alert: SecurityAlert) -> None:
        """Record critical security alert to both text log and structured JSON."""
        timestamp = alert.timestamp_iso
        text_entry = (
            f"\n{'='*70}\n"
            f"[{timestamp}] [SECURITY ALERT] Incident: {alert.alert_id}\n"
            f"[{timestamp}] [SECURITY ALERT] Reason: {alert.reason}\n"
            f"[{timestamp}] [SECURITY ALERT] Details: {alert.qualifying_event_count} changes within {alert.measured_duration_seconds:.2f}s "
            f"(threshold: >{alert.configured_threshold} in {alert.configured_window_seconds:.1f}s)\n"
            f"[{timestamp}] [SECURITY ALERT] Distinct Files Affected: {alert.distinct_affected_files_count}\n"
            f"[{timestamp}] [SECURITY ALERT] Extensions Observed: {', '.join(alert.changed_extensions)}\n"
            f"[{timestamp}] [SECURITY ALERT] Target Directory: {alert.monitored_directory}\n"
            f"{'='*70}\n"
        )
        with self._lock:
            # 1. Append to text log
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(text_entry)
            except Exception as e:
                print(f"Failed writing alert to security log: {e}")

            # 2. Append to structured alerts.json
            try:
                alerts_data = []
                if self.alerts_json_path.exists():
                    try:
                        with open(self.alerts_json_path, "r", encoding="utf-8") as jf:
                            alerts_data = json.load(jf)
                    except Exception:
                        alerts_data = []

                alerts_data.append(alert.to_dict())
                temp_json = self.alerts_json_path.with_suffix(".tmp")
                with open(temp_json, "w", encoding="utf-8") as jf:
                    json.dump(alerts_data, jf, indent=2)
                temp_json.replace(self.alerts_json_path)
            except Exception as e:
                print(f"Failed writing alert to alerts.json: {e}")

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Read recent alerts from JSON history."""
        if not self.alerts_json_path.exists():
            return []
        with self._lock:
            try:
                with open(self.alerts_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data[-limit:] if isinstance(data, list) else []
            except Exception:
                return []

    def read_latest_log_lines(self, num_lines: int = 50) -> str:
        """Read the tail of the security log for UI display."""
        if not self.log_path.exists():
            return "Security log is empty."
        with self._lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    return "".join(lines[-num_lines:])
            except Exception as e:
                return f"Error reading security log: {e}"
