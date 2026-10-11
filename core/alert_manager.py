"""
Security Alert Manager.
Constructs, classifies, and manages cooldown state for behavioral alerts.
Prevents duplicate alert flooding during sustained event bursts.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import time

import config

@dataclass
class SecurityAlert:
    alert_id: str
    timestamp_iso: str
    monitored_directory: str
    category: str
    severity: str
    reason: str
    qualifying_event_count: int
    configured_threshold: int
    configured_window_seconds: float
    measured_duration_seconds: float
    distinct_affected_files_count: int
    changed_extensions: List[str]
    sample_affected_files: List[str]
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp_iso,
            "directory": self.monitored_directory,
            "category": self.category,
            "severity": self.severity,
            "reason": self.reason,
            "qualifying_events": self.qualifying_event_count,
            "threshold": self.configured_threshold,
            "window_seconds": self.configured_window_seconds,
            "measured_duration": round(self.measured_duration_seconds, 2),
            "distinct_files_affected": self.distinct_affected_files_count,
            "changed_extensions": self.changed_extensions,
            "sample_files": self.sample_affected_files,
            "details": self.details
        }

    def format_terminal(self) -> str:
        """Format clean multiline string for terminal output (NO EMOJIS)."""
        separator = "=" * 64
        return (
            f"\n{separator}\n"
            f"SECURITY ALERT -- SUSPICIOUS FILE ACTIVITY DETECTED\n"
            f"{separator}\n"
            f"Alert ID:            {self.alert_id}\n"
            f"Timestamp:           {self.timestamp_iso}\n"
            f"Directory:           {self.monitored_directory}\n"
            f"Severity:            {self.severity}\n"
            f"Reason:              {self.reason}\n"
            f"Measured Velocity:   {self.qualifying_event_count} qualifying changes within {self.measured_duration_seconds:.2f}s\n"
            f"Configured Limit:    >{self.configured_threshold} events within {self.configured_window_seconds:.1f}s\n"
            f"Distinct Files:      {self.distinct_affected_files_count}\n"
            f"Extensions Observed: {', '.join(self.changed_extensions) if self.changed_extensions else 'None'}\n"
            f"Sample Files:        {', '.join(self.sample_affected_files[:4])}\n"
            f"Status:              Suspicious Activity (Ransomware-like mass renaming)\n"
            f"{separator}\n"
        )


class AlertManager:
    """Manages alert creation and suppresses duplicate floods with an active cooldown."""
    def __init__(self, cooldown_seconds: float = config.ALERT_COOLDOWN_SECONDS):
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time_mono: float = 0.0
        self.active_alert: Optional[SecurityAlert] = None
        self._alert_counter = 0

    def can_trigger_alert(self) -> bool:
        """True if the cooldown period has expired since the last alert."""
        return (time.monotonic() - self.last_alert_time_mono) >= self.cooldown_seconds

    def create_alert(
        self,
        monitored_dir: str,
        qualifying_events: int,
        threshold: int,
        window_seconds: float,
        duration_seconds: float,
        affected_files: List[str],
        changed_extensions: List[str],
        reason: Optional[str] = None
    ) -> SecurityAlert:
        self.last_alert_time_mono = time.monotonic()
        self._alert_counter += 1

        now = datetime.now()
        alert_id = f"ALERT-{now.strftime('%Y%m%d')}-{self._alert_counter:04d}"

        if not reason:
            if config.LOCKED_EXTENSION in changed_extensions:
                reason = "Rapid bulk file renaming with extension modification (.locked) exceeding security threshold"
            else:
                reason = "Rapid high-frequency filesystem modification burst exceeding threshold"

        severity = "CRITICAL" if config.LOCKED_EXTENSION in changed_extensions else "HIGH"

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp_iso=now.strftime("%Y-%m-%d %H:%M:%S"),
            monitored_directory=monitored_dir,
            category="Filesystem Behavioral Anomaly",
            severity=severity,
            reason=reason,
            qualifying_event_count=qualifying_events,
            configured_threshold=threshold,
            configured_window_seconds=window_seconds,
            measured_duration_seconds=duration_seconds,
            distinct_affected_files_count=len(set(affected_files)),
            changed_extensions=list(set(changed_extensions)),
            sample_affected_files=affected_files[:6]
        )
        self.active_alert = alert
        return alert

    def reset_cooldown(self) -> None:
        """Reset cooldown to allow immediate triggering if monitoring is restarted."""
        self.last_alert_time_mono = 0.0
        self.active_alert = None
