# Ransomware Behavior Detection System — Demonstration Guide

This guide details the step-by-step procedures for conducting an academic presentation or laboratory evaluation of the **Ransomware Behavior Detection and Simulation System**.

---

## 1. Demonstration Modes Overview

The project supports two distinct presentation workflows:
- **Mode A: Three-Window Native OS Demonstration** (Terminal + File Explorer)
- **Mode B: Integrated Desktop Application Demonstration** (Native Tkinter/ttk GUI)

Both modes utilize the exact same underlying behavioral detection engine, sandbox manager, and filesystem observation logic.

---

## 2. Mode A: Three-Window Native OS Demonstration

This setup mirrors the classic security demonstration format, demonstrating independent processes interacting with the Windows filesystem in real time.

### Window Arrangement

Arrange three windows on your monitor:

```
+------------------------------------+------------------------------------+
|                                    |                                    |
|       WINDOW 1: FILE EXPLORER      |     WINDOW 2: SIMULATOR TERMINAL   |
|         (test_folder View)         |        (python simulator.py)       |
|                                    |                                    |
+------------------------------------+------------------------------------+
|                                                                         |
|                       WINDOW 3: DETECTOR TERMINAL                       |
|                          (python detector.py)                           |
|                                                                         |
+-------------------------------------------------------------------------+
```

### Execution Steps

#### Step 1: Prepare Dummy Files
Open a PowerShell terminal and generate the sandbox files:
```powershell
python prepare_demo.py
```
*Verification:* Confirm that 20 dummy files (`notes1.txt`, `sample_data.csv`, `report.txt`, etc.) are generated.

#### Step 2: Open File Explorer (Window 1)
Open the physical directory in Windows File Explorer:
- Navigate to the `test_folder` inside the project folder.
- Keep this window visible on the left side of your screen.
- Verify all 20 dummy files exist with their normal extensions.

#### Step 3: Launch the Detector (Window 3)
In the bottom terminal window, start the detector:
```powershell
python detector.py
```
*Display observed:*
- Green status: `Status: MONITORING`
- Monitored directory: `test_folder`
- Threshold: `Velocity > 10 qualifying events in 5.0 seconds`
- Observer is listening for real OS filesystem events via `watchdog`.

#### Step 4: Launch the Simulator (Window 2)
In the top-right terminal window, start the safe simulator:
```powershell
python simulator.py --delay 0.3
```
*Live observation sequence:*
1. **Window 2 (Simulator):** Prints sequential progress:
   ```
   [01/20] Renamed notes1.txt -> notes1.txt.locked
   [02/20] Renamed notes2.txt -> notes2.txt.locked
   ...
   ```
2. **Window 1 (File Explorer):** The filenames dynamically change on disk from `.txt` to `.locked`.
3. **Window 3 (Detector):** As events arrive, individual live event logs appear.
4. **Trigger Point (Event 11):** At the 11th file rename (~3.3 seconds elapsed), the detector triggers:
   - Terminal prints a high-visibility Red Security Alert banner:
     ```
     ================================================================
     SECURITY ALERT -- SUSPICIOUS FILE ACTIVITY DETECTED
     ================================================================
     Alert ID:            ALERT-20261011-0001
     Timestamp:           2026-10-11 12:30:15
     Directory:           test_folder
     Severity:            CRITICAL
     Reason:              Rapid bulk file renaming with extension modification (.locked) exceeding security threshold
     Measured Velocity:   11 qualifying changes within 3.32s
     Configured Limit:    >10 events within 5.0s
     Distinct Files:      11
     Extensions Observed: .locked
     Status:              Suspicious Activity (Ransomware-like mass renaming)
     ================================================================
     ```
5. **Window 2 (Simulator):** Completes all 20 files and prints completion summary.

#### Step 5: Reset the Demonstration
In the terminal, run:
```powershell
python reset.py
```
- In File Explorer, observe all `.locked` files automatically restored to their original names and extensions.
- Both Window 1 and the manifest confirm 20/20 files restored.

---

## 3. Mode B: Integrated Desktop Application Demonstration

Mode B provides an integrated visualization suited for classroom projectors and comprehensive technical presentations.

### Execution Steps

#### Step 1: Launch the Application
```powershell
python app.py
```
The application opens in dark slate theme with a 3-panel layout:
- **Top Header:** Title, Subtitle, Status Badge (`STATUS: IDLE`).
- **Toolbar:** Control buttons with state-aware availability.
- **Panel 1 (Left):** Live File Explorer showing test_folder contents.
- **Panel 2 (Center):** Simulation Activity with progress bar and log.
- **Panel 3 (Right):** Detector metrics, threat assessment, alert banner, and event stream.

#### Step 2: Prepare Files
1. Click **Prepare Demo Files**.
2. Notice Panel 1 populates with 20 registered dummy files with statuses listed as `Original`.
3. Click **Open Test Folder** to open native Windows File Explorer to confirm disk synchronization.

#### Step 3: Activate Real-Time Monitoring
1. Click **Start Monitoring**.
2. The status badge switches to green: `STATUS: MONITORING`.
3. Panel 3 shows active metrics: `Window Events: 0 / 10`, `Window Limit: 5.0s`, `Threat Assessment: No suspicious burst detected`.

#### Step 4: Execute Safe Simulation
1. Ensure the simulation delay is set to `0.30s`.
2. Click **Start Simulation**.
3. Observe real-time synchronization across panels:
   - **Panel 2:** The progress bar advances smoothly, active filename updates, and chronological rename logs scroll.
   - **Panel 1:** Filenames update in the table in real time, with status changing to `Renamed (.locked)`.
   - **Panel 3:** Qualifying window events increment: `1 / 10`, `2 / 10`, ..., `10 / 10`.

#### Step 5: Observe Behavior Detection
1. As the 11th rename completes, the sliding window crosses the threshold (>10 events in 5.0s).
2. The status badge immediately turns red: `STATUS: SUSPICIOUS ACTIVITY`.
3. The threat assessment switches to: `Threat Assessment: Possible ransomware-like behavior`.
4. The **Security Alert Card** illuminates in red with full incident diagnostics:
   - Measured velocity (e.g. `11 changes observed in 3.34s`)
   - Distinct files affected
   - Extension changes observed (`.locked`)
5. The detector event log records the critical incident.

#### Step 6: Inspect Persistent Logs
1. Click **View Security Log**.
2. A viewer displays the persisted audit trail from `reports/security_log.txt` with exact timestamps and metrics.

#### Step 7: Demonstrate Safe Reset
1. Click **Reset Demo**.
2. The application restores every dummy file back to its original name.
3. Panel 1 immediately updates: all 20 files return to `Original`.
4. Panel 3 resets the alert banner to standby.
5. The system is ready to repeat the demonstration immediately.

---

## 4. Key Talking Points for Presentation

When demonstrating this project to a professor or evaluation panel, highlight these architectural points:

1. **Behavioral vs. Signature Detection:**
   Explain that signature-based antivirus cannot detect zero-day ransomware because hashes change. This detector monitors *velocity and patterns* of file operations rather than binary signatures.

2. **Sliding Time Window:**
   Explain why a sliding window using monotonic time (`time.monotonic()`) is superior to a simple interval counter. It measures continuous rolling velocity without artificial interval edge gaps.

3. **Strict Sandbox Containment:**
   Point out that safety is enforced at the core architectural level: path canonicalization, symlink rejection, explicit manifest validation, and zero destructive payload.

4. **Real Operating System Integration:**
   Emphasize that this is not a mock UI or timer simulation: native Windows File Explorer, Watchdog kernel notifications, and the Tkinter table all synchronize from actual disk operations.
