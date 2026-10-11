# Ransomware Behavior Detection System — Academic and Operating Systems Concepts

This document provides a comprehensive academic explanation of the Operating Systems (OS) and cybersecurity principles implemented in the **Ransomware Behavior Detection and Simulation System**, tailored for the **Protection and Security** module.

---

## 1. Operating Systems Foundation

### 1.1 File Systems and File Metadata
A modern operating system manages persistent storage using a file system abstraction (such as NTFS on Windows or ext4 on Linux). 

- **File Identifier and Directory Entries:** Files are referenced via directory entries mapping human-readable names to underlying file indexes (MFT records on NTFS, inodes on Unix).
- **Metadata Attributes:** Each file maintains metadata including file size, creation timestamp, last modification timestamp (`st_mtime`), access rights, and file extension.
- **File Extensions:** In Windows, extensions (e.g. `.txt`, `.docx`, `.locked`) designate file association and indicate expected format. Ransomware alters these extensions after processing to signify encryption and prevent user access.

### 1.2 File Operations and Atomicity
The simulator performs file renames using standard operating system system calls:
- On Windows, file renames invoke kernel routines (`SetFileInformationByHandle` with `FileRenameInfo`).
- Renaming within the same filesystem directory is an **atomic metadata operation**: the data blocks on disk are not relocated; only the directory entry pointer and filename metadata are altered.
- The simulator updates the filename from `<name>.<ext>` to `<name>.<ext>.locked` without modifying or destroying file data blocks, demonstrating observable ransomware behavior safely.

---

## 2. Filesystem Event Monitoring Architecture

### 2.1 OS-Level Notification Mechanisms
Rather than continuously polling directory contents (which consumes high CPU and causes severe I/O degradation), modern operating systems provide event-driven kernel notifications:
- **Windows:** `ReadDirectoryChangesW` API delivers asynchronous notifications when directory entries or attributes are modified.
- **Linux:** `inotify` / `fanotify` kernel subsystem monitors filesystem events.
- **macOS:** `FSEvents` / `kqueue`.

The Python `watchdog` library provides an abstraction layer over these native platform APIs. In our system, an independent background `Observer` thread listens for:
1. `FileMovedEvent` (`renamed`): Captures `src_path` and `dest_path`.
2. `FileModifiedEvent` (`modified`): Captures content or attribute updates.

### 2.2 Event Debouncing and OS Noise
Operating systems frequently emit multiple low-level callbacks for a single logical file operation. For example, a rename or file write on Windows may trigger a modification event followed by a move event in rapid succession.
- If raw events were counted naively, detection statistics would be artificially inflated, causing premature false alarms.
- Our `EventDebouncer` module implements a short deduplication window (`EVENT_DEBOUNCE_SECONDS = 0.05s`). Low-level notifications sharing the same event type, source path, and destination path within this interval are merged into a single logical event.

---

## 3. Concurrency and Process Independence

### 3.1 Process Separation
In a realistic environment, malware and security monitors operate as separate, isolated OS processes.
- The **Simulator** runs as one process with its own execution context, virtual memory space, and scheduling thread.
- The **Detector** runs as an independent process. It has no internal memory access or shared variables with the simulator.
- Communication between the two processes occurs strictly through **filesystem side effects** mediated by the operating system kernel.

### 3.2 Threading Model in the Desktop Application
In the integrated desktop application (`app.py`), concurrent activities are partitioned across threads to prevent GUI freezing:
1. **Tkinter UI Thread:** Handles window rendering, user input, and widget updates.
2. **Watchdog Observer Thread:** Listens for OS filesystem notifications asynchronously.
3. **Simulation Worker Thread:** Performs sequential file renames with timed pauses.
4. **Thread-Safe Queue (`queue.Queue`):** Worker and observer threads marshal messages and metrics to the main thread, adhering to Tkinter's single-threaded UI constraints.

---

## 4. Protection and Security: Behavioral vs. Signature Detection

### 4.1 Limitations of Signature-Based Antivirus
Traditional Antivirus (AV) solutions rely on static signatures (e.g. SHA-256 hashes of known malicious binaries or distinct byte sequences):
- **Vulnerability to Polymorphism:** Attackers recompile or pack malware code, changing the binary hash while preserving malicious functionality.
- **Zero-Day Blindspot:** Novel ransomware strains have no existing signature database entry and bypass traditional scanners.

### 4.2 Behavioral Anomaly Detection
Behavioral detection analyzes *what a process does* rather than *what it looks like*:
- Real ransomware exhibits characteristic operational velocity: it alters hundreds or thousands of files in a short time frame.
- Behavioral detection looks for patterns such as:
  1. High frequency of file modifications/renames across multiple files.
  2. Mass extension changes (e.g., appending `.locked` or random hexadecimal extensions).
  3. Rapid deviation from normal user I/O velocity baselines.

---

## 5. The Sliding-Window Velocity Algorithm

### 5.1 Why Simple Fixed Timers Fail
A naive approach resets an event counter every 5 seconds (fixed time buckets). This approach suffers from boundary vulnerabilities:
- If 8 renames occur in the last second of Bucket 1, and 8 renames occur in the first second of Bucket 2, 16 renames occurred within a 2-second span.
- However, a fixed-interval counter evaluates each bucket independently as having only 8 events, failing to trigger a threshold of 10.

### 5.2 The Sliding-Window Deque Implementation
Our system implements a true continuous sliding time window using `collections.deque` and `time.monotonic()`:

```
Timeline: -----[ t - window_seconds .............. t ]----->
Events in Deque:    (t1, ev1)   (t2, ev2) ... (tn, evn)
```

1. As each qualified event arrives at timestamp $t_{\text{current}}$, it is appended to the right of the deque.
2. Older events satisfying $t_{\text{event}} < t_{\text{current}} - \text{window\_seconds}$ are pruned from the left (`popleft()`).
3. The remaining events in the deque represent the exact number of qualifying operations within the active window.
4. If $\text{count} > \text{threshold}$, a security alert is triggered immediately.
5. `time.monotonic()` ensures calculations are immune to system clock drift, daylight savings changes, or NTP adjustments.

---

## 6. False Positives and Academic Limitations

### 6.1 Understanding False Positives
In an operating system, legitimate software may also exhibit rapid file modification behavior:
- Batch photo editors resizing image collections.
- Software build tools (`make`, `compiler`) generating dozens of object files.
- Backup utilities encrypting or compressing user archives.
- Version control operations (`git checkout`, `git pull`).

Our system provides an educational behavioral heuristic. A commercial Endpoint Detection and Response (EDR) agent supplements velocity tracking with process provenance, entropy calculation, shadow copy inspection, and canary file traps.

### 6.2 Watchdog Observation Scope
`watchdog` reliably tracks directory-level events (`created`, `modified`, `deleted`, `moved`), but does not capture internal file read operations or raw disk sector writes. In academic discussions, this distinction must be clearly stated: the detector observes *filesystem event notifications*, not granular kernel I/O request packets (IRPs).
