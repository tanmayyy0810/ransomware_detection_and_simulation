# Ransomware Behavior Detection and Simulation System

**An Operating Systems Protection and Security Module Project**  
*Behavior-Based Filesystem Anomaly Detection and Safe Simulation Environment*

---

## 1. Project Overview

The **Ransomware Behavior Detection and Simulation System** is an educational, production-grade cybersecurity software system demonstrating real-time behavioral detection of ransomware-like filesystem activity. 

Unlike traditional signature-based antivirus solutions that rely on known binary hashes, this system observes the **operational velocity and structural patterns** of filesystem modifications—specifically the high-frequency renaming of multiple files and extension alterations—to detect suspicious bursts of activity in real time.

The system is partitioned into two independent components:
1. **Safe Ransomware Behavior Simulator:** A harmless, non-destructive script that renames registered dummy files in an isolated sandbox directory (`test_folder`), appending `.locked` sequentially to emulate ransomware mass-renaming.
2. **Real-Time Behavioral Detector:** An independent service powered by Python's `watchdog` library that continuously observes the sandbox filesystem using a continuous sliding-window velocity algorithm. When the rate of qualifying modifications exceeds a configurable threshold (default: >10 events in 5.0 seconds), it raises a detailed security alert.

---

## 2. Problem Statement

Modern ransomware attacks typically execute at extreme velocity, rapidly encrypting and renaming hundreds of personal and system documents before user intervention is possible. Traditional antivirus scanners struggle against:
- **Zero-Day Variants:** Unseen malware strains with no registered signature in virus databases.
- **Polymorphic Malware:** Code that dynamically alters its binary representation to evade hash-based matching.

By focusing on the fundamental **operating system behavior** of ransomware—specifically the anomalous velocity of bulk file alterations and extension mutations across multiple distinct files within a compact time window—defense systems can detect malicious attacks without prior knowledge of the executable.

---

## 3. Project Objectives

- Implement an isolated, harmless test sandbox that never touches or endangers real user files.
- Emulate the filesystem behavioral footprint of ransomware safely (file renaming only, no encryption or payload destruction).
- Observe actual operating system filesystem events in real time using the `watchdog` engine.
- Implement an exact continuous **sliding time-window velocity algorithm** using monotonic time (`time.monotonic()`) and double-ended queues (`collections.deque`).
- Deliver both an interactive, presentation-ready native desktop GUI (`tkinter`/`ttk`) and standalone colored terminal CLI workflows.
- Provide automated reset and recovery to support repeatable live demonstrations.
- Document the underlying Operating Systems concepts for academic presentation.

---

## 4. Technology Stack

- **Language:** Python 3.11+ (Tested and verified on Python 3.12.8)
- **Filesystem Observation:** `watchdog` (v6.0.0+)
- **Desktop Graphical Interface:** `tkinter` & `ttk` (Native Windows/Linux desktop integration)
- **Terminal Styling:** `colorama` (v0.4.6+, Windows console ANSI support)
- **Timing & Mathematics:** Standard library `time.monotonic()` for drift-free temporal measurement
- **Concurrency & Data Structures:** `threading`, `queue.Queue`, `collections.deque`
- **Audit & Persistence:** Structured JSON (`reports/alerts.json`) and human-readable text logs (`reports/security_log.txt`)
- **Automated Testing:** Python `unittest` framework

*Zero external cloud services, web servers, or databases required. Runs 100% locally and offline.*

---

## 5. Installation Instructions

### Prerequisites
- Windows 10/11 (or modern Linux/macOS)
- Python 3.11 or later installed and added to your system `PATH`

### Setup via Windows PowerShell

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd "D:\Cat 1\os\Os_project"
   ```

2. (Optional but recommended) Create and activate a Python virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *Note: If script execution is restricted in PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first.*

3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 6. Required Dependencies

Declared in `requirements.txt`:
```text
watchdog>=6.0.0
colorama>=0.4.6
```

---

## 7. Project Structure

```
Os_project/
|-- app.py                     # Desktop GUI application launcher
|-- detector.py                # Standalone CLI behavioral detector
|-- simulator.py               # Standalone CLI safe ransomware simulator
|-- prepare_demo.py            # Sandbox initialization & dummy file generator
|-- reset.py                   # Demonstration reset & recovery script
|-- config.py                  # Global settings, paths, and thresholds
|-- requirements.txt           # Third-party dependencies declaration
|-- README.md                  # Comprehensive project documentation
|
|-- core/
|   |-- __init__.py
|   |-- sandbox_manager.py     # Sandbox containment safety & manifest tracking
|   |-- simulation_engine.py   # Safe sequential file renaming engine
|   |-- detection_engine.py    # Sliding-window behavioral analysis engine
|   |-- event_manager.py       # Watchdog filesystem adapter & event debouncer
|   |-- alert_manager.py       # Alert generation & cooldown flood control
|   |-- report_manager.py      # Thread-safe persistent security logging
|   |-- reset_manager.py       # Reversion of dummy files to original state
|
|-- ui/
|   |-- __init__.py
|   |-- main_window.py         # Main three-panel desktop application window
|   |-- components.py          # Custom metric cards, status badges, alert panels
|   |-- styles.py              # Technical dark slate design theme (No emojis)
|
|-- test_folder/               # Strictly isolated sandbox for dummy files
|-- backup/                    # Sandbox manifest and recovery state
|-- reports/                   # security_log.txt and alerts.json
|
|-- tests/                     # 20 automated unit and integration tests
|   |-- __init__.py
|   |-- test_safety.py         # Sandbox containment & directory traversal defense
|   |-- test_simulation.py     # File generation, hashes, and non-destructive rename
|   |-- test_detection.py      # Sliding window, 10 vs 11 boundary, debouncing
|   |-- test_reset.py          # Full & partial restoration, content preservation
|   |-- test_integration.py    # Complete end-to-end operational lifecycle
|
|-- docs/
    |-- DEMO_GUIDE.md          # Step-by-step presentation script for professors
    |-- PROJECT_EXPLANATION.md # Academic explanation of OS concepts
    |-- TEST_RESULTS.md        # Verified automated test results & report
```

---

## 8. How the Simulator Works

The simulator (`core/simulation_engine.py`) models mass file alteration safely:
1. Validates the sandbox path against strict containment rules.
2. Queries the sandbox manifest (`backup/manifest.json`) for eligible dummy files.
3. Iterates over registered files sequentially, renaming each from `<filename>` to `<filename>.locked`.
4. Enforces a configurable inter-file delay (default: 0.3 seconds per file).
5. Updates progress counters and notifies listeners.
6. Preserves the exact file content byte-for-byte (verified via SHA-256).

---

## 9. How the Detector Works

The detector (`core/detection_engine.py`) acts as a behavioral security monitor:
1. Launches a background `watchdog.observers.Observer` targeting `test_folder` non-recursively.
2. Receives low-level OS file events (`FileMovedEvent` and `FileModifiedEvent`).
3. Filters duplicate low-level OS callbacks using `EventDebouncer` (0.05s window).
4. Normalizes events to capture timestamps, source/destination names, and extension changes.
5. Feeds events into the continuous sliding-window velocity algorithm.
6. When the number of qualifying events in the rolling window exceeds the threshold, generates a structured `SecurityAlert`.
7. Enforces a cooldown period (default: 4.0 seconds) to prevent alert flooding during sustained activity.

---

## 10. Sliding-Window Algorithm Explanation

Rather than using fixed timer buckets (which fail when events straddle bucket borders), the detector uses a continuous sliding time-window deque:

```
[Oldest Event] <-------- 5.0 seconds --------> [Current Event]
   (t1, ev1)   (t2, ev2)   (t3, ev3) ... (t_n, ev_n)
```

1. On each event, the current monotonic timestamp is obtained using `time.monotonic()`.
2. The event is appended to the right of `collections.deque`.
3. The left of the deque is pruned: all entries with `timestamp < now - window_seconds` are popped.
4. The remaining entries represent the exact count of qualifying operations within the active window.
5. If `len(deque) > threshold`, an alert is immediately raised.

---

## 11. Detection Thresholds

- **Default Observation Window:** 5.0 seconds
- **Default Event Threshold:** 10 events (Alert triggers on the 11th qualifying event)
- **Default Dummy Files:** 20 files
- **Default Simulation Delay:** 0.30 seconds per file
- *Measured Timing:* 11 files * 0.3s = ~3.3 seconds elapsed (consistently within the 5.0s window).

---

## 12. CLI Operation

Run standalone tools from the project root:

1. **Prepare Demo Files:**
   ```powershell
   python prepare_demo.py
   ```
2. **Start Monitoring (Terminal 1):**
   ```powershell
   python detector.py
   ```
3. **Start Safe Simulation (Terminal 2):**
   ```powershell
   python simulator.py --delay 0.3
   ```
4. **Reset Demo Files:**
   ```powershell
   python reset.py
   ```

---

## 13. GUI Operation

Launch the native desktop application:
```powershell
python app.py
```

The application provides:
- **Header:** System status badge (`IDLE`, `MONITORING`, `SUSPICIOUS ACTIVITY`).
- **Control Bar:** Action buttons with state-aware availability.
- **Panel 1 (Live File Explorer):** Treeview table showing test_folder contents, file size, state (`Original` vs `Renamed (.locked)`), and last modified time.
- **Panel 2 (Simulation Activity):** Live progress bar, current file indicator, delay adjustment, and scrolling rename chronology.
- **Panel 3 (Detector Activity):** Real-time metric cards, threat assessment, threshold configuration, live event stream, and red Security Alert banner.

---

## 14. Real-Time Demonstration Procedure

Follow this 5-minute presentation sequence:
1. Launch `python app.py`.
2. Click **Prepare Demo Files** (generates 20 files).
3. Click **Open Test Folder** to show original files in Windows File Explorer.
4. Click **Start Monitoring** (Status badge turns green: `STATUS: MONITORING`).
5. Click **Start Simulation**.
6. Observe live updates across File Explorer, the GUI file list, and the simulation progress.
7. Upon the 11th rename, observe the detector trigger: Status badge switches to red `STATUS: SUSPICIOUS ACTIVITY` and the Security Alert card illuminates with velocity diagnostics.
8. Click **Reset Demo** to restore all files back to their original names.

*For complete speaking scripts and multi-window instructions, see `docs/DEMO_GUIDE.md`.*

---

## 15. How to Reset the Sandbox

- **Via GUI:** Click the **Reset Demo** button on the toolbar.
- **Via CLI:** Run `python reset.py`.
- **Restoration Guarantee:** Reversion is driven by `backup/manifest.json`. Files are verified before renaming back to their original extensions.

---

## 16. How to Examine Logs

- **Via GUI:** Click **View Security Log** to open the embedded audit viewer.
- **Via Text File:** Open `reports/security_log.txt` in any text editor.
- **Via Structured JSON:** Inspect `reports/alerts.json` for machine-readable records.

---

## 17. Strict Safety Boundaries

1. **Containment:** Operations are strictly constrained to `test_folder` inside the project root.
2. **No Arbitrary Targets:** System directories (`C:\Windows`, user directories, drives) are strictly rejected.
3. **No Traversal / Symlinks:** Path traversal (`..`) and symbolic link escapes are explicitly checked and blocked.
4. **No Destructive Payload:** Zero file encryption, zero content deletion, zero ransom notes, zero persistence mechanisms.
5. **Ownership Check:** The simulator only alters files explicitly created and registered in the sandbox manifest.
6. **Isolated Logs:** All audit logs and manifests reside outside `test_folder` so detector observation is not contaminated.

---

## 18. Testing Instructions

Execute the complete 20-test automated suite:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

All 20 tests verify safety containment, simulation integrity, detection boundary conditions, debouncing, reset recovery, and end-to-end lifecycle integration.

*For detailed test records, see `docs/TEST_RESULTS.md`.*

---

## 19. Limitations and False Positives

- **Educational Behavioral Heuristic:** Designed to demonstrate OS filesystem concepts; not intended as a replacement for commercial EDR solutions.
- **Filesystem Read Limitation:** `watchdog` observes metadata and modification events, but cannot track internal file read operations across all operating systems.
- **Legitimate Bulk Operations:** Legitimate software performing high-speed bulk renames (e.g. batch image converters, compilers, or git checkouts) may trigger the velocity threshold.

---

## 20. Troubleshooting

| Issue | Cause | Solution |
|:---|:---|:---|
| `No eligible dummy files found` | Files not yet generated or already locked. | Click **Prepare Demo Files** or run `python prepare_demo.py`. |
| `Detector did not trigger during simulation` | Simulation delay was too high or files < 11. | Ensure delay is $\le 0.4$s and file count is at least 15. Default 0.3s with 20 files triggers reliably. |
| `Permission denied` on file rename | A file is open in an external editor that holds an exclusive lock. | Close external text editors accessing files in `test_folder`. |
| PowerShell script activation blocked | Windows execution policy restriction. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the current terminal. |
