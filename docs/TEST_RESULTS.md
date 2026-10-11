# Automated Test Results and Verification Report

This document records the actual, verified results of the automated test suite executed on **Windows (Python 3.12.8)** for the **Ransomware Behavior Detection and Simulation System**.

---

## 1. Test Execution Summary

- **Test Suite Framework:** Python standard library `unittest`
- **Execution Date:** 2026-10-11
- **Target Platform:** Windows 10/11 x64, Python 3.12.8
- **Total Tests Executed:** 20
- **Passed:** 20 (100%)
- **Failed:** 0
- **Errors:** 0
- **Total Execution Time:** 3.900 seconds

---

## 2. Detailed Test Cases and Results

### Category A: Sandbox Safety and Containment (`tests/test_safety.py`)

| Test Case | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| `test_valid_sandbox_path_accepted` | Sandbox path strictly inside project root is verified as safe. | Validated safe | **PASS** |
| `test_outside_directory_rejected` | Outside parent directories are rejected immediately. | Rejected safely | **PASS** |
| `test_system_root_rejected` | Critical paths (`C:\Windows`, root drives) fail validation. | Rejected safely | **PASS** |
| `test_path_traversal_file_rejected` | Traversal path (`../outside.txt`) raises `SandboxSecurityError`. | Security error raised | **PASS** |
| `test_assert_safe_operation_passes` | Authorized test folder files pass validation without exception. | Passed without error | **PASS** |
| `test_non_registered_files_not_eligible` | Arbitrary files manually dropped into sandbox are ignored. | Excluded from simulation | **PASS** |

### Category B: Safe Simulation Engine (`tests/test_simulation.py`)

| Test Case | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| `test_dummy_file_generation_count` | Exactly 20 realistic files generated on disk with valid extensions. | 20 files on disk | **PASS** |
| `test_manifest_integrity_and_hashes` | Manifest accurately records SHA-256 and byte sizes of all files. | Hashes match exactly | **PASS** |
| `test_sequential_renaming_appends_locked` | Sequential rename appends `.locked` to all target dummy files. | All renamed to `.locked` | **PASS** |
| `test_file_contents_preserved_non_destructive` | File contents unchanged after renaming; SHA-256 hashes match. | Zero payload alteration | **PASS** |
| `test_simulation_interruption` | Early stop halts simulation cleanly without data corruption. | Clean stop at index 4 | **PASS** |

### Category C: Behavioral Detection Engine (`tests/test_detection.py`)

| Test Case | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| `test_threshold_edge_case_exactly_10_events_no_alert` | Exactly 10 events within 5.0s does NOT trigger alert (>10 threshold). | 0 alerts generated | **PASS** |
| `test_threshold_edge_case_11_events_triggers_alert` | 11 events within 5.0s triggers CRITICAL security alert. | 1 alert generated | **PASS** |
| `test_sliding_window_expiration` | Expired events pruned; 7 total events across 0.5s with window 0.2s triggers no alert. | 0 alerts generated | **PASS** |
| `test_event_debouncer` | Duplicate OS notifications within 0.1s are deduplicated. | Duplicate filtered | **PASS** |
| `test_alert_cooldown_prevents_flooding` | 20 rapid events trigger only 1 alert during active cooldown window. | Single alert emitted | **PASS** |

### Category D: Sandbox Reset and Recovery (`tests/test_reset.py`)

| Test Case | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| `test_reset_after_full_simulation` | 10 `.locked` files restored to original names; contents verified. | 10 files restored | **PASS** |
| `test_reset_after_partial_simulation` | Partial rename cleanly restores only locked files. | Subset cleanly restored | **PASS** |
| `test_repeated_demonstration_cycle` | 2 consecutive simulate-and-reset cycles succeed without error. | Cycles completed | **PASS** |

### Category E: End-to-End Integration (`tests/test_integration.py`)

| Test Case | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| `test_full_operational_lifecycle` | Prepare -> Monitor -> Simulate -> Detect -> Alert -> Log -> Stop -> Reset -> Repeat using real Watchdog events. | Complete lifecycle verified | **PASS** |

---

## 3. Recommended Screenshots for Academic Submission

For inclusion in an academic report, presentation slide deck, or laboratory submission, capture the following live application states:

1. **Figure 1: Baseline Sandbox Environment**
   - Live File Explorer showing 20 dummy files with `.txt`, `.csv`, `.md`, `.json`, `.log` extensions.
   - Status badge showing `STATUS: IDLE`.

2. **Figure 2: Active Monitoring State**
   - Watchdog detector active; Status badge showing green `STATUS: MONITORING`.
   - Metric cards displaying `Window Events: 0 / 10`, `Window Limit: 5.0s`.

3. **Figure 3: Simulation in Progress**
   - Simulation activity panel showing progress bar at ~50% (e.g. `10 / 20`).
   - Chronological rename log showing sequential file modification.

4. **Figure 4: Triggered Security Alert**
   - Status badge displaying red `STATUS: SUSPICIOUS ACTIVITY`.
   - Prominent red Security Alert banner showing measured velocity (e.g. `11 changes within 3.32s`), triggering rule, and affected file list.

5. **Figure 5: Security Audit Log Viewer**
   - The modal audit log window displaying persistent records in `reports/security_log.txt`.

6. **Figure 6: Restored Sandbox State**
   - File Explorer and GUI table showing all 20 files restored to `Original` state after clicking **Reset Demo**.
