"""
Main Desktop Application Window.
Three-panel technical monitoring workstation connecting real-time Watchdog detection,
sandboxed ransomware-like simulation, and live filesystem synchronization.
"""

import os
import sys
import time
import subprocess
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Optional

import config
from core.sandbox_manager import SandboxManager
from core.simulation_engine import SimulationEngine
from core.detection_engine import DetectionEngine
from core.reset_manager import ResetManager
from core.report_manager import ReportManager
from core.alert_manager import SecurityAlert
from core.event_manager import NormalizedEvent
from ui import styles
from ui.components import StatusBadge, MetricCard, AlertBanner, ScrollingLog

class MainWindow:
    """Integrated Desktop GUI orchestrating detection, simulation, and filesystem sync."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Ransomware Behavior Detection System")
        self.root.geometry("1200x780")
        self.root.minsize(1050, 680)
        self.root.configure(bg=styles.BG_MAIN)

        styles.setup_ttk_styles(self.root)

        # Thread-safe event queue
        self.ui_queue: queue.Queue = queue.Queue()

        # Core subsystems
        self.sandbox_manager = SandboxManager()
        self.report_manager = ReportManager()
        self.reset_manager = ResetManager(self.sandbox_manager)

        self.simulation_engine = SimulationEngine(
            sandbox_manager=self.sandbox_manager,
            delay_seconds=config.DEFAULT_SIMULATION_DELAY,
            on_progress=self._sim_on_progress,
            on_finished=self._sim_on_finished,
            on_error=self._sim_on_error
        )

        self.detection_engine = DetectionEngine(
            watch_directory=self.sandbox_manager.sandbox_path,
            window_seconds=config.DEFAULT_WINDOW_SECONDS,
            threshold_events=config.DEFAULT_THRESHOLD_EVENTS,
            on_event_callback=self._det_on_event,
            on_alert_callback=self._det_on_alert,
            on_metrics_callback=self._det_on_metrics,
            report_manager=self.report_manager
        )

        # UI State variables
        self.sim_delay_var = tk.DoubleVar(value=config.DEFAULT_SIMULATION_DELAY)
        self.threshold_var = tk.IntVar(value=config.DEFAULT_THRESHOLD_EVENTS)
        self.window_sec_var = tk.DoubleVar(value=config.DEFAULT_WINDOW_SECONDS)

        # Build UI Structure
        self._build_header()
        self._build_toolbar()
        self._build_panels()
        self._build_statusbar()

        # Bind close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start periodic queue processing loop
        self.root.after(50, self._process_queue)

        # Initial UI refresh
        self.refresh_file_explorer()
        self._update_button_states()

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================

    def _build_header(self):
        """Top application header displaying title, subtitle, and live status badge."""
        header_frame = tk.Frame(self.root, bg=styles.BG_MAIN, padx=16, pady=12)
        header_frame.pack(fill="x")

        title_box = tk.Frame(header_frame, bg=styles.BG_MAIN)
        title_box.pack(side="left")

        title_lbl = ttk.Label(title_box, text="Ransomware Behavior Detection System", style="HeaderTitle.TLabel")
        title_lbl.pack(anchor="w")

        sub_lbl = ttk.Label(
            title_box,
            text="Behavior-Based Filesystem Monitoring | Educational Simulation Environment",
            style="HeaderSub.TLabel"
        )
        sub_lbl.pack(anchor="w", pady=(2, 0))

        # Status Badge on right
        self.status_badge = StatusBadge(header_frame)
        self.status_badge.pack(side="right", pady=4)

    def _build_toolbar(self):
        """Action toolbar with prominent primary controls."""
        toolbar = tk.Frame(self.root, bg=styles.BG_PANEL, padx=16, pady=8, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        toolbar.pack(fill="x", padx=16, pady=(0, 10))

        # Left Action Buttons
        self.btn_prep = ttk.Button(toolbar, text="Prepare Demo Files", command=self.on_prepare_demo)
        self.btn_prep.pack(side="left", padx=(0, 6))

        self.btn_monitor_start = ttk.Button(toolbar, text="Start Monitoring", command=self.on_start_monitoring, style="Primary.TButton")
        self.btn_monitor_start.pack(side="left", padx=(0, 6))

        self.btn_monitor_stop = ttk.Button(toolbar, text="Stop Monitoring", command=self.on_stop_monitoring, state="disabled")
        self.btn_monitor_stop.pack(side="left", padx=(0, 6))

        # Separator
        sep1 = tk.Frame(toolbar, width=1, bg=styles.BORDER_COLOR, height=24)
        sep1.pack(side="left", padx=8, pady=2)

        self.btn_sim_start = ttk.Button(toolbar, text="Start Simulation", command=self.on_start_simulation)
        self.btn_sim_start.pack(side="left", padx=(0, 6))

        self.btn_sim_stop = ttk.Button(toolbar, text="Stop Simulation", command=self.on_stop_simulation, state="disabled")
        self.btn_sim_stop.pack(side="left", padx=(0, 6))

        # Separator
        sep2 = tk.Frame(toolbar, width=1, bg=styles.BORDER_COLOR, height=24)
        sep2.pack(side="left", padx=8, pady=2)

        self.btn_reset = ttk.Button(toolbar, text="Reset Demo", command=self.on_reset_demo)
        self.btn_reset.pack(side="left", padx=(0, 6))

        # Right Action Buttons
        self.btn_logs = ttk.Button(toolbar, text="View Security Log", command=self.on_view_logs)
        self.btn_logs.pack(side="right", padx=(6, 0))

        self.btn_open_folder = ttk.Button(toolbar, text="Open Test Folder", command=self.on_open_test_folder)
        self.btn_open_folder.pack(side="right", padx=(0, 6))

    def _build_panels(self):
        """Three-panel main content layout."""
        panes = tk.Frame(self.root, bg=styles.BG_MAIN)
        panes.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Grid layout with 3 equal/proportional columns
        panes.grid_columnconfigure(0, weight=4, uniform="panel_col")
        panes.grid_columnconfigure(1, weight=3, uniform="panel_col")
        panes.grid_columnconfigure(2, weight=4, uniform="panel_col")
        panes.grid_rowconfigure(0, weight=1)

        # Panel 1: Live File Explorer
        self._build_panel_file_explorer(panes)

        # Panel 2: Simulation Activity
        self._build_panel_simulation(panes)

        # Panel 3: Detector Activity & Alerts
        self._build_panel_detector(panes)

    def _build_panel_file_explorer(self, parent):
        """Panel 1: Live File Explorer showing real files in test_folder."""
        p1 = tk.Frame(parent, bg=styles.BG_PANEL, padx=12, pady=10, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        p1.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        # Header
        hdr = tk.Frame(p1, bg=styles.BG_PANEL)
        hdr.pack(fill="x", pady=(0, 8))
        ttk.Label(hdr, text="PANEL 1: LIVE FILE EXPLORER", style="PanelTitle.TLabel").pack(anchor="w")
        self.lbl_file_count = ttk.Label(hdr, text="Monitored Target: test_folder (0 files)", style="PanelSub.TLabel")
        self.lbl_file_count.pack(anchor="w")

        # Treeview Table
        cols = ("filename", "ext", "status", "size", "modified")
        self.tree_files = ttk.Treeview(p1, columns=cols, show="headings", selectmode="browse")

        self.tree_files.heading("filename", text="Filename")
        self.tree_files.heading("ext", text="Type")
        self.tree_files.heading("status", text="State")
        self.tree_files.heading("size", text="Size")
        self.tree_files.heading("modified", text="Modified")

        self.tree_files.column("filename", width=140, anchor="w")
        self.tree_files.column("ext", width=50, anchor="center")
        self.tree_files.column("status", width=105, anchor="w")
        self.tree_files.column("size", width=55, anchor="e")
        self.tree_files.column("modified", width=70, anchor="center")

        tree_scroll = ttk.Scrollbar(p1, orient="vertical", command=self.tree_files.yview)
        self.tree_files.configure(yscrollcommand=tree_scroll.set)

        self.tree_files.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

    def _build_panel_simulation(self, parent):
        """Panel 2: Simulation activity, controls, and sequential log."""
        p2 = tk.Frame(parent, bg=styles.BG_PANEL, padx=12, pady=10, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        p2.grid(row=0, column=1, sticky="nsew", padx=3)

        # Header
        hdr = tk.Frame(p2, bg=styles.BG_PANEL)
        hdr.pack(fill="x", pady=(0, 8))
        ttk.Label(hdr, text="PANEL 2: SIMULATION ACTIVITY", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(hdr, text="Safe sandboxed bulk rename engine", style="PanelSub.TLabel").pack(anchor="w")

        # Speed Configuration Row
        speed_box = tk.Frame(p2, bg=styles.BG_CARD, padx=8, pady=6, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        speed_box.pack(fill="x", pady=(0, 8))

        tk.Label(speed_box, text="Inter-file Delay (s):", font=styles.FONT_BODY, bg=styles.BG_CARD, fg=styles.TEXT_MAIN).pack(side="left")
        self.spin_delay = ttk.Spinbox(
            speed_box,
            from_=0.05,
            to=2.0,
            increment=0.05,
            width=6,
            textvariable=self.sim_delay_var,
            command=self._on_delay_changed
        )
        self.spin_delay.pack(side="left", padx=6)
        self.spin_delay.bind("<Return>", lambda e: self._on_delay_changed())

        # Progress Section
        prog_box = tk.Frame(p2, bg=styles.BG_CARD, padx=8, pady=8, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        prog_box.pack(fill="x", pady=(0, 8))

        prog_hdr = tk.Frame(prog_box, bg=styles.BG_CARD)
        prog_hdr.pack(fill="x")
        self.lbl_sim_status = tk.Label(prog_hdr, text="Operation: Idle", font=styles.FONT_BODY_BOLD, bg=styles.BG_CARD, fg=styles.TEXT_MAIN)
        self.lbl_sim_status.pack(side="left")

        self.lbl_sim_counter = tk.Label(prog_hdr, text="0 / 0 (0%)", font=styles.FONT_MONO_BOLD, bg=styles.BG_CARD, fg=styles.TEXT_MUTED)
        self.lbl_sim_counter.pack(side="right")

        self.progress_bar = ttk.Progressbar(prog_box, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", pady=(6, 4))

        self.lbl_current_file = tk.Label(
            prog_box,
            text="Active File: None",
            font=styles.FONT_MONO,
            bg=styles.BG_CARD,
            fg=styles.TEXT_MUTED,
            anchor="w"
        )
        self.lbl_current_file.pack(fill="x")

        # Scrolling Simulation Log
        tk.Label(p2, text="SIMULATION CHRONOLOGY", font=(styles.FONT_FAMILY, 8, "bold"), bg=styles.BG_PANEL, fg=styles.TEXT_MUTED).pack(anchor="w", pady=(2, 2))
        self.log_sim = ScrollingLog(p2, height=12)
        self.log_sim.pack(fill="both", expand=True)

    def _build_panel_detector(self, parent):
        """Panel 3: Real-time Detector Activity and Threat Assessment."""
        p3 = tk.Frame(parent, bg=styles.BG_PANEL, padx=12, pady=10, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        p3.grid(row=0, column=2, sticky="nsew", padx=(6, 0))

        # Header
        hdr = tk.Frame(p3, bg=styles.BG_PANEL)
        hdr.pack(fill="x", pady=(0, 8))
        ttk.Label(hdr, text="PANEL 3: DETECTOR ACTIVITY", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(hdr, text="Real-time Watchdog behavioral engine", style="PanelSub.TLabel").pack(anchor="w")

        # Threat Assessment Banner
        self.threat_box = tk.Frame(p3, bg=styles.BG_CARD, padx=10, pady=6, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        self.threat_box.pack(fill="x", pady=(0, 8))

        self.lbl_threat_state = tk.Label(
            self.threat_box,
            text="Threat Assessment: No suspicious burst detected",
            font=styles.FONT_BODY_BOLD,
            bg=styles.BG_CARD,
            fg=styles.ACCENT_GREEN
        )
        self.lbl_threat_state.pack(anchor="w")

        # Metric Cards Grid
        metrics_grid = tk.Frame(p3, bg=styles.BG_PANEL)
        metrics_grid.pack(fill="x", pady=(0, 8))
        metrics_grid.grid_columnconfigure(0, weight=1)
        metrics_grid.grid_columnconfigure(1, weight=1)

        self.card_window_events = MetricCard(metrics_grid, title="Window Events", initial_value="0 / 10")
        self.card_window_events.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=(0, 4))

        self.card_window_duration = MetricCard(metrics_grid, title="Window Limit", initial_value="5.0s")
        self.card_window_duration.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=(0, 4))

        self.card_distinct_files = MetricCard(metrics_grid, title="Distinct Files", initial_value="0")
        self.card_distinct_files.grid(row=1, column=0, sticky="nsew", padx=(0, 4), pady=(4, 0))

        self.card_total_observed = MetricCard(metrics_grid, title="Total Events", initial_value="0")
        self.card_total_observed.grid(row=1, column=1, sticky="nsew", padx=(4, 0), pady=(4, 0))

        # Security Alert Box (Visible when alert is triggered)
        self.alert_banner = AlertBanner(p3)
        self.alert_banner.pack(fill="x", pady=(0, 8))

        # Config Row
        cfg_box = tk.Frame(p3, bg=styles.BG_CARD, padx=8, pady=6, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        cfg_box.pack(fill="x", pady=(0, 8))

        tk.Label(cfg_box, text="Threshold:", font=styles.FONT_BODY, bg=styles.BG_CARD, fg=styles.TEXT_MAIN).pack(side="left")
        self.spin_thresh = ttk.Spinbox(
            cfg_box, from_=1, to=100, width=4, textvariable=self.threshold_var
        )
        self.spin_thresh.pack(side="left", padx=(4, 8))

        tk.Label(cfg_box, text="Window (s):", font=styles.FONT_BODY, bg=styles.BG_CARD, fg=styles.TEXT_MAIN).pack(side="left")
        self.spin_window = ttk.Spinbox(
            cfg_box, from_=1.0, to=60.0, increment=1.0, width=5, textvariable=self.window_sec_var
        )
        self.spin_window.pack(side="left", padx=(4, 8))

        btn_apply_cfg = ttk.Button(cfg_box, text="Apply", command=self.on_apply_detector_config)
        btn_apply_cfg.pack(side="right")

        # Live Event Log
        tk.Label(p3, text="RECENT DETECTOR EVENTS", font=(styles.FONT_FAMILY, 8, "bold"), bg=styles.BG_PANEL, fg=styles.TEXT_MUTED).pack(anchor="w", pady=(2, 2))
        self.log_det = ScrollingLog(p3, height=6)
        self.log_det.pack(fill="both", expand=True)

    def _build_statusbar(self):
        """Bottom application status bar."""
        statusbar = tk.Frame(self.root, bg=styles.BG_PANEL, padx=16, pady=4, highlightthickness=1, highlightbackground=styles.BORDER_COLOR)
        statusbar.pack(fill="x", side="bottom")

        self.lbl_status_msg = tk.Label(
            statusbar,
            text="System initialized. Ready for demonstration.",
            font=styles.FONT_BODY,
            bg=styles.BG_PANEL,
            fg=styles.TEXT_MUTED
        )
        self.lbl_status_msg.pack(side="left")

        lbl_engine_info = tk.Label(
            statusbar,
            text="OS Protection & Security Module | Offline Local Execution",
            font=styles.FONT_BODY,
            bg=styles.BG_PANEL,
            fg=styles.TEXT_MUTED
        )
        lbl_engine_info.pack(side="right")

    # =========================================================================
    # CORE CALLBACKS -> UI QUEUE (Thread-Safe Bridge)
    # =========================================================================

    def _sim_on_progress(self, idx: int, total: int, old_name: str, new_name: str):
        self.ui_queue.put(("sim_progress", (idx, total, old_name, new_name)))

    def _sim_on_finished(self, count: int, total: int, msg: str):
        self.ui_queue.put(("sim_finished", (count, total, msg)))

    def _sim_on_error(self, err_msg: str):
        self.ui_queue.put(("sim_error", err_msg))

    def _det_on_event(self, event: NormalizedEvent):
        self.ui_queue.put(("det_event", event))

    def _det_on_alert(self, alert: SecurityAlert):
        self.ui_queue.put(("det_alert", alert))

    def _det_on_metrics(self, metrics: dict):
        self.ui_queue.put(("det_metrics", metrics))

    # =========================================================================
    # QUEUE DISPATCHER
    # =========================================================================

    def _process_queue(self):
        """Poll and execute pending UI updates on the main Tkinter thread."""
        try:
            while not self.ui_queue.empty():
                msg_type, payload = self.ui_queue.get_nowait()

                if msg_type == "sim_progress":
                    idx, total, old_name, new_name = payload
                    pct = int((idx / total) * 100) if total > 0 else 0
                    self.progress_bar["value"] = pct
                    self.lbl_sim_counter.config(text=f"{idx} / {total} ({pct}%)")
                    self.lbl_current_file.config(text=f"Renamed: {new_name}")
                    self.lbl_sim_status.config(text="Operation: Bulk Renaming in Progress", fg=styles.ACCENT_AMBER)
                    ts = time.strftime("%H:%M:%S")
                    self.log_sim.append_line(f"[{ts}] {old_name} -> {new_name}", tag="warning")
                    self.refresh_file_explorer()

                elif msg_type == "sim_finished":
                    count, total, msg = payload
                    self.lbl_sim_status.config(text="Operation: Completed", fg=styles.ACCENT_GREEN)
                    self.lbl_status_msg.config(text=msg)
                    self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] {msg}", tag="success")
                    self._update_button_states()
                    self.refresh_file_explorer()

                elif msg_type == "sim_error":
                    self.lbl_sim_status.config(text="Operation: Error", fg=styles.ACCENT_RED)
                    self.lbl_status_msg.config(text=f"Error: {payload}")
                    self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] Error: {payload}", tag="danger")
                    self._update_button_states()

                elif msg_type == "det_event":
                    event: NormalizedEvent = payload
                    dest_str = f" -> {event.dest_filename}" if event.dest_filename else ""
                    ext_flag = " [.locked]" if event.is_locked_extension else ""
                    self.log_det.append_line(
                        f"[{event.timestamp_iso.split()[1]}] [{event.event_type.upper()}] {event.src_filename}{dest_str}{ext_flag}",
                        tag="danger" if event.is_locked_extension else "info"
                    )

                elif msg_type == "det_alert":
                    alert: SecurityAlert = payload
                    self.alert_banner.show_alert(alert)
                    self.status_badge.set_state("SUSPICIOUS ACTIVITY")
                    self.lbl_threat_state.config(
                        text="Threat Assessment: Possible ransomware-like behavior",
                        fg=styles.ACCENT_RED
                    )
                    self.log_det.append_line(
                        f"[{alert.timestamp_iso.split()[1]}] [CRITICAL ALERT] {alert.reason}",
                        tag="danger"
                    )
                    self.lbl_status_msg.config(text=f"Security Alert Triggered: {alert.alert_id}")

                elif msg_type == "det_metrics":
                    metrics = payload
                    q_in_w = metrics.get("qualifying_in_window", 0)
                    thresh = metrics.get("threshold_events", 10)
                    is_danger = q_in_w > thresh
                    self.card_window_events.update_value(f"{q_in_w} / {thresh}", is_danger=is_danger, is_highlight=(q_in_w > 0))
                    self.card_window_duration.update_value(f"{metrics.get('window_seconds', 5.0):.1f}s")
                    self.card_distinct_files.update_value(str(metrics.get("distinct_files_in_window", 0)))
                    self.card_total_observed.update_value(str(metrics.get("total_events_observed", 0)))

                    if not metrics.get("has_active_alert", False):
                        if metrics.get("is_monitoring", False):
                            self.status_badge.set_state("MONITORING")
                            self.lbl_threat_state.config(text="Threat Assessment: No suspicious burst detected", fg=styles.ACCENT_GREEN)
                        else:
                            self.status_badge.set_state("IDLE")
                            self.lbl_threat_state.config(text="Threat Assessment: Monitoring inactive", fg=styles.TEXT_MUTED)

        except Exception as e:
            print(f"Error processing UI queue: {e}")
        finally:
            self.root.after(50, self._process_queue)

    # =========================================================================
    # USER ACTION HANDLERS
    # =========================================================================

    def on_prepare_demo(self):
        """Prepare 20 realistic dummy files and refresh explorer."""
        try:
            count, msg = self.sandbox_manager.prepare_dummy_files(count=config.DEFAULT_DUMMY_COUNT, force_regenerate=True)
            self.refresh_file_explorer()
            self.lbl_status_msg.config(text=msg)
            self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] Prepared {count} dummy files in test_folder", tag="highlight")
            self._update_button_states()
        except Exception as e:
            messagebox.showerror("Sandbox Error", f"Failed to prepare dummy files: {e}")

    def on_start_monitoring(self):
        """Activate watchdog observation."""
        self.detection_engine.start_monitoring()
        self.status_badge.set_state("MONITORING")
        self.lbl_status_msg.config(text="Real-time filesystem monitoring active.")
        self.log_det.append_line(f"[{time.strftime('%H:%M:%S')}] Monitoring started on test_folder", tag="success")
        self._update_button_states()

    def on_stop_monitoring(self):
        """Deactivate watchdog observation."""
        self.detection_engine.stop_monitoring()
        self.status_badge.set_state("IDLE")
        self.lbl_status_msg.config(text="Filesystem monitoring stopped.")
        self.log_det.append_line(f"[{time.strftime('%H:%M:%S')}] Monitoring stopped", tag="info")
        self._update_button_states()

    def on_start_simulation(self):
        """Start background bulk rename simulation."""
        eligible = self.sandbox_manager.get_eligible_for_simulation()
        if not eligible:
            messagebox.showwarning("Simulation", "No eligible dummy files found. Click 'Prepare Demo Files' first.")
            return

        self._on_delay_changed()
        self.progress_bar["value"] = 0
        self.lbl_sim_counter.config(text=f"0 / {len(eligible)} (0%)")
        self.lbl_sim_status.config(text="Operation: Starting...", fg=styles.ACCENT_AMBER)
        self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] Simulation started ({len(eligible)} files, {self.sim_delay_var.get():.2f}s delay)", tag="highlight")

        started = self.simulation_engine.start_in_background()
        if started:
            self.lbl_status_msg.config(text="Simulation running in background thread...")
            self._update_button_states()

    def on_stop_simulation(self):
        """Request active simulation to halt."""
        self.simulation_engine.stop()
        self.lbl_status_msg.config(text="Stopping simulation...")
        self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] Stop requested by user", tag="warning")

    def on_reset_demo(self):
        """Safely restore renamed files back to original names."""
        if self.simulation_engine.is_running:
            messagebox.showwarning("Reset Demo", "Please stop active simulation before resetting.")
            return

        # Temporarily suspend / reset detection state so reset renames don't trigger detection
        was_monitoring = self.detection_engine.is_monitoring
        if was_monitoring:
            self.detection_engine.stop_monitoring()

        restored, errors, summary = self.reset_manager.reset_sandbox(regenerate_missing=True)
        self.detection_engine.reset_detection_state()

        if was_monitoring:
            self.detection_engine.start_monitoring()

        self.refresh_file_explorer()
        self.progress_bar["value"] = 0
        self.lbl_sim_counter.config(text="0 / 0 (0%)")
        self.lbl_current_file.config(text="Active File: None")
        self.lbl_sim_status.config(text="Operation: Reset Complete", fg=styles.ACCENT_GREEN)
        self.status_badge.set_state("MONITORING" if was_monitoring else "IDLE")
        self.lbl_threat_state.config(text="Threat Assessment: No suspicious burst detected", fg=styles.ACCENT_GREEN)
        self.alert_banner.title_lbl.config(text="SECURITY ALERT: STANDBY")
        self.alert_banner.reason_lbl.config(text="No active alert. System reset.")
        self.alert_banner.details_lbl.config(text="Waiting for behavioral activity.")
        self.alert_banner.files_lbl.config(text="")
        self.lbl_status_msg.config(text=summary)
        self.log_sim.append_line(f"[{time.strftime('%H:%M:%S')}] {summary}", tag="success")
        self._update_button_states()

    def on_open_test_folder(self):
        """Open real test_folder in Windows File Explorer or OS file manager."""
        target = self.sandbox_manager.sandbox_path
        target.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(target))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
        except Exception as e:
            messagebox.showerror("Explorer Error", f"Could not open directory: {e}")

    def on_view_logs(self):
        """Display recent security_log.txt entries in a modal viewer."""
        log_win = tk.Toplevel(self.root)
        log_win.title("Security Audit Log (security_log.txt)")
        log_win.geometry("750x500")
        log_win.configure(bg=styles.BG_MAIN)

        header = tk.Frame(log_win, bg=styles.BG_MAIN, padx=12, pady=8)
        header.pack(fill="x")
        tk.Label(
            header,
            text=f"Log File: {self.report_manager.log_path}",
            font=styles.FONT_BODY_BOLD,
            bg=styles.BG_MAIN,
            fg=styles.TEXT_BRIGHT
        ).pack(side="left")

        log_text = tk.Text(log_win, bg=styles.BG_INPUT, fg=styles.TEXT_MAIN, font=styles.FONT_MONO, wrap="word")
        scroll = ttk.Scrollbar(log_win, orient="vertical", command=log_text.yview)
        log_text.configure(yscrollcommand=scroll.set)

        log_text.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 12))
        scroll.pack(side="right", fill="y", padx=(0, 12), pady=(0, 12))

        content = self.report_manager.read_latest_log_lines(100)
        log_text.insert("1.0", content)
        log_text.see("end")
        log_text.config(state="disabled")

    def on_apply_detector_config(self):
        """Apply user-configured threshold and window seconds."""
        try:
            thresh = int(self.threshold_var.get())
            win = float(self.window_sec_var.get())
            if thresh <= 0 or win <= 0:
                raise ValueError("Values must be greater than zero.")
            self.detection_engine.set_parameters(window_seconds=win, threshold_events=thresh)
            self.card_window_duration.update_value(f"{win:.1f}s")
            self.lbl_status_msg.config(text=f"Detector settings updated: >{thresh} events in {win:.1f}s.")
            self.log_det.append_line(f"[{time.strftime('%H:%M:%S')}] Config updated: threshold={thresh}, window={win:.1f}s", tag="highlight")
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Invalid parameters: {e}")

    def _on_delay_changed(self):
        """Update simulation delay parameter."""
        try:
            val = float(self.sim_delay_var.get())
            if val < 0.01:
                val = 0.01
            self.simulation_engine.set_delay(val)
        except Exception:
            pass

    # =========================================================================
    # STATE & VIEW SYNCHRONIZATION
    # =========================================================================

    def refresh_file_explorer(self):
        """Scan real disk files in test_folder and populate Treeview table."""
        for item in self.tree_files.get_children():
            self.tree_files.delete(item)

        statuses = self.sandbox_manager.get_file_statuses()
        for s in statuses:
            item_id = self.tree_files.insert(
                "",
                "end",
                values=(s["filename"], s["extension"], s["status"], s["size"], s["modified"])
            )
            if s["status"].startswith("Renamed"):
                self.tree_files.item(item_id, tags=("locked",))

        self.tree_files.tag_configure("locked", foreground=styles.ACCENT_AMBER)
        total = len(statuses)
        self.lbl_file_count.config(text=f"Monitored Target: test_folder ({total} files on disk)")

    def _update_button_states(self):
        """Enable/disable controls based on current system state."""
        is_sim_running = self.simulation_engine.is_running
        is_monitoring = self.detection_engine.is_monitoring
        eligible_files = len(self.sandbox_manager.get_eligible_for_simulation())

        if is_sim_running:
            self.btn_prep.config(state="disabled")
            self.btn_sim_start.config(state="disabled")
            self.btn_sim_stop.config(state="normal")
            self.btn_reset.config(state="disabled")
        else:
            self.btn_prep.config(state="normal")
            self.btn_sim_start.config(state="normal" if eligible_files > 0 else "disabled")
            self.btn_sim_stop.config(state="disabled")
            self.btn_reset.config(state="normal")

        if is_monitoring:
            self.btn_monitor_start.config(state="disabled")
            self.btn_monitor_stop.config(state="normal")
        else:
            self.btn_monitor_start.config(state="normal")
            self.btn_monitor_stop.config(state="disabled")

    def on_closing(self):
        """Clean shutdown protocol on window close."""
        try:
            if self.simulation_engine.is_running:
                self.simulation_engine.stop()
            if self.detection_engine.is_monitoring:
                self.detection_engine.stop_monitoring()
        except Exception:
            pass
        finally:
            self.root.destroy()
