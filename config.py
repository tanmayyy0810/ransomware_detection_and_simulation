"""
Central configuration for Ransomware Behavior Detection and Simulation System.
All paths are resolved relative to the project root for cross-platform portability.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent

# Target sandbox directory (Must be strictly isolated inside project root)
TEST_FOLDER_NAME = "test_folder"
TEST_FOLDER_PATH = PROJECT_ROOT / TEST_FOLDER_NAME

# Backup & State Directory (outside monitored directory)
BACKUP_DIR_NAME = "backup"
BACKUP_PATH = PROJECT_ROOT / BACKUP_DIR_NAME
MANIFEST_FILE = BACKUP_PATH / "manifest.json"

# Reporting Directory (outside monitored directory)
REPORTS_DIR_NAME = "reports"
REPORTS_PATH = PROJECT_ROOT / REPORTS_DIR_NAME
SECURITY_LOG_FILE = REPORTS_PATH / "security_log.txt"
ALERTS_JSON_FILE = REPORTS_PATH / "alerts.json"

# Detection Engine Defaults
DEFAULT_WINDOW_SECONDS = 5.0         # Sliding observation window duration
DEFAULT_THRESHOLD_EVENTS = 10        # Trigger alert when qualifying events in window > 10 (i.e. >= 11)
ALERT_COOLDOWN_SECONDS = 4.0         # Cooldown window to avoid flooding redundant alerts during one wave

# Simulation Defaults
DEFAULT_DUMMY_COUNT = 20             # Standard academic demo file count
DEFAULT_SIMULATION_DELAY = 0.3       # Seconds between sequential renames (20 files * 0.3s = 6.0s total)
LOCKED_EXTENSION = ".locked"         # Harmless academic marker extension

# Debounce Window for Filesystem Events (seconds)
# Prevents duplicate Windows OS filesystem callbacks from artificially inflating event counts
EVENT_DEBOUNCE_SECONDS = 0.05

def ensure_directories():
    """Ensure system directories outside the monitored directory exist."""
    BACKUP_PATH.mkdir(parents=True, exist_ok=True)
    REPORTS_PATH.mkdir(parents=True, exist_ok=True)
