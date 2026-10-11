"""
Custom UI Components for the Ransomware Behavior Detection Desktop Application.
Engineered for clarity, contrast, and presentation-grade technical monitoring.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional

from ui import styles

class StatusBadge(tk.Frame):
    """Visual status badge indicating current operational state."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=styles.BG_MAIN, **kwargs)
        self.label = tk.Label(
            self,
            text="STATUS: IDLE",
            font=styles.FONT_BADGE,
            bg="#2c313a",
            fg=styles.TEXT_MAIN,
            padx=10,
            pady=3,
            relief="flat"
        )
        self.label.pack()

    def set_state(self, state: str):
        """Update badge appearance based on system state."""
        state_upper = state.upper()
        if "SUSPICIOUS" in state_upper or "ALERT" in state_upper:
            self.label.config(
                text=f"STATUS: {state_upper}",
                bg=styles.ACCENT_RED,
                fg="#ffffff"
            )
        elif "MONITORING" in state_upper or "ACTIVE" in state_upper:
            self.label.config(
                text=f"STATUS: {state_upper}",
                bg="#2e4033",
                fg=styles.ACCENT_GREEN
            )
        else:
            self.label.config(
                text=f"STATUS: {state_upper}",
                bg="#2c313a",
                fg=styles.TEXT_MAIN
            )


class MetricCard(tk.Frame):
    """Compact numeric display card for real-time monitoring indicators."""
    def __init__(self, parent, title: str, initial_value: str = "0", **kwargs):
        super().__init__(parent, bg=styles.BG_CARD, highlightthickness=1, highlightbackground=styles.BORDER_COLOR, padx=10, pady=8, **kwargs)
        self.title_lbl = tk.Label(
            self,
            text=title.upper(),
            font=(styles.FONT_FAMILY, 8, "bold"),
            bg=styles.BG_CARD,
            fg=styles.TEXT_MUTED
        )
        self.title_lbl.pack(anchor="w")

        self.val_lbl = tk.Label(
            self,
            text=initial_value,
            font=(styles.FONT_FAMILY, 15, "bold"),
            bg=styles.BG_CARD,
            fg=styles.TEXT_BRIGHT
        )
        self.val_lbl.pack(anchor="w", pady=(2, 0))

    def update_value(self, value: str, is_highlight: bool = False, is_danger: bool = False):
        color = styles.TEXT_BRIGHT
        if is_danger:
            color = styles.ACCENT_RED
        elif is_highlight:
            color = styles.ACCENT_BLUE

        self.val_lbl.config(text=value, fg=color)


class AlertBanner(tk.Frame):
    """Prominent, non-blocking alert card displayed upon detecting suspicious behavior."""
    def __init__(self, parent, on_dismiss=None, **kwargs):
        super().__init__(parent, bg=styles.BG_CARD, highlightthickness=2, highlightbackground=styles.ACCENT_RED, padx=12, pady=10, **kwargs)
        self.on_dismiss = on_dismiss

        # Header Row
        header_frame = tk.Frame(self, bg=styles.BG_CARD)
        header_frame.pack(fill="x", expand=True)

        self.title_lbl = tk.Label(
            header_frame,
            text="SECURITY ALERT: SUSPICIOUS ACTIVITY DETECTED",
            font=(styles.FONT_FAMILY, 10, "bold"),
            bg=styles.BG_CARD,
            fg=styles.ACCENT_RED
        )
        self.title_lbl.pack(side="left")

        self.time_lbl = tk.Label(
            header_frame,
            text="",
            font=(styles.FONT_FAMILY, 8, "normal"),
            bg=styles.BG_CARD,
            fg=styles.TEXT_MUTED
        )
        self.time_lbl.pack(side="right")

        # Content details
        self.reason_lbl = tk.Label(
            self,
            text="Sliding window velocity threshold exceeded.",
            font=(styles.FONT_FAMILY, 9, "bold"),
            bg=styles.BG_CARD,
            fg=styles.TEXT_BRIGHT,
            anchor="w",
            justify="left",
            wraplength=340
        )
        self.reason_lbl.pack(fill="x", pady=(4, 2))

        self.details_lbl = tk.Label(
            self,
            text="12 changes observed in 3.4 seconds (limit: >10 in 5.0s)",
            font=(styles.FONT_FAMILY, 8, "normal"),
            bg=styles.BG_CARD,
            fg=styles.TEXT_MAIN,
            anchor="w",
            justify="left",
            wraplength=340
        )
        self.details_lbl.pack(fill="x")

        # Affected files note
        self.files_lbl = tk.Label(
            self,
            text="Files affected: 12 distinct dummy files appended with .locked",
            font=styles.FONT_MONO,
            bg=styles.BG_CARD,
            fg=styles.ACCENT_AMBER,
            anchor="w",
            justify="left",
            wraplength=340
        )
        self.files_lbl.pack(fill="x", pady=(2, 0))

    def show_alert(self, alert):
        self.title_lbl.config(text=f"SECURITY ALERT [{alert.severity}]: {alert.alert_id}")
        self.time_lbl.config(text=alert.timestamp_iso.split()[1] if " " in alert.timestamp_iso else alert.timestamp_iso)
        self.reason_lbl.config(text=alert.reason)
        self.details_lbl.config(
            text=f"{alert.qualifying_event_count} changes observed in {alert.measured_duration_seconds:.2f}s "
                 f"(Limit: >{alert.configured_threshold} in {alert.configured_window_seconds:.1f}s)"
        )
        ext_str = ", ".join(alert.changed_extensions) if alert.changed_extensions else "none"
        self.files_lbl.config(
            text=f"Distinct files: {alert.distinct_affected_files_count} | Extensions: {ext_str}"
        )


class ScrollingLog(tk.Frame):
    """Text console for displaying live operation log entries."""
    def __init__(self, parent, height: int = 10, **kwargs):
        super().__init__(parent, bg=styles.BG_CARD, **kwargs)

        self.text = tk.Text(
            self,
            height=height,
            bg=styles.BG_INPUT,
            fg=styles.TEXT_MAIN,
            font=styles.FONT_MONO,
            relief="flat",
            wrap="word",
            state="disabled",
            borderwidth=0
        )
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=self.scrollbar.set)

        self.text.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Color tags
        self.text.tag_config("timestamp", foreground=styles.TEXT_MUTED)
        self.text.tag_config("info", foreground=styles.TEXT_MAIN)
        self.text.tag_config("success", foreground=styles.ACCENT_GREEN)
        self.text.tag_config("warning", foreground=styles.ACCENT_AMBER)
        self.text.tag_config("danger", foreground=styles.ACCENT_RED)
        self.text.tag_config("highlight", foreground=styles.ACCENT_BLUE)

    def append_line(self, line: str, tag: str = "info"):
        self.text.config(state="normal")
        self.text.insert("end", line + "\n", tag)
        self.text.see("end")
        self.text.config(state="disabled")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")
