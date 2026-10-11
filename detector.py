#!/usr/bin/env python3
"""
CLI Tool: Real-Time Ransomware Behavior Detector.
Monitors test_folder for real filesystem changes using Watchdog and a sliding-window algorithm.
"""

import argparse
import sys
import time
from pathlib import Path
from colorama import init, Fore, Style

import config
from core.detection_engine import DetectionEngine
from core.event_manager import NormalizedEvent
from core.alert_manager import SecurityAlert
from core.report_manager import ReportManager

init(autoreset=True)

def parse_args():
    parser = argparse.ArgumentParser(description="Real-Time Ransomware Behavior Detector (Watchdog)")
    parser.add_argument("--threshold", type=int, default=config.DEFAULT_THRESHOLD_EVENTS,
                        help=f"Event threshold triggering alert (default: {config.DEFAULT_THRESHOLD_EVENTS})")
    parser.add_argument("--window", type=float, default=config.DEFAULT_WINDOW_SECONDS,
                        help=f"Sliding observation window duration in seconds (default: {config.DEFAULT_WINDOW_SECONDS})")
    return parser.parse_args()

def main():
    args = parse_args()
    reports = ReportManager()

    def on_event(event: NormalizedEvent):
        # Format live event output
        dest_part = f" -> {event.dest_filename}" if event.dest_filename else ""
        ext_flag = f" [{Fore.YELLOW}EXT_CHANGE{Style.RESET_ALL}]" if event.is_extension_changed else ""
        locked_flag = f" [{Fore.RED}LOCKED{Style.RESET_ALL}]" if event.is_locked_extension else ""
        print(f"[{event.timestamp_iso}] [{event.event_type.upper()}] {event.src_filename}{dest_part}{ext_flag}{locked_flag}")

    def on_alert(alert: SecurityAlert):
        # Prominent red alert banner in terminal
        print(Fore.RED + Style.BRIGHT + alert.format_terminal() + Style.RESET_ALL)

    detector = DetectionEngine(
        watch_directory=config.TEST_FOLDER_PATH,
        window_seconds=args.window,
        threshold_events=args.threshold,
        on_event_callback=on_event,
        on_alert_callback=on_alert,
        report_manager=reports
    )

    print(f"\n{Style.BRIGHT}{Fore.CYAN}==================================================================")
    print(f"{Fore.CYAN}  RANSOMWARE BEHAVIOR DETECTOR -- REAL-TIME MONITORING")
    print(f"{Fore.CYAN}=================================================================={Style.RESET_ALL}\n")
    print(f"Status:             {Fore.GREEN}MONITORING{Style.RESET_ALL}")
    print(f"Monitored Target:   {config.TEST_FOLDER_PATH}")
    print(f"Detection Rule:     Velocity > {args.threshold} qualifying events in {args.window:.1f} seconds")
    print(f"Algorithm:          Sliding-window temporal measurement (monotonic time)")
    print(f"Safety Mode:        Sandbox contained (recursive=False)")
    print(f"\n{Fore.GREEN}Waiting for filesystem activity... (Press Ctrl+C to stop){Style.RESET_ALL}\n")

    try:
        detector.start_monitoring()
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopping detector service...{Style.RESET_ALL}")
    finally:
        detector.stop_monitoring()
        metrics = detector.get_current_metrics()
        print(f"\n{Fore.CYAN}Detector summary:{Style.RESET_ALL}")
        print(f"  Total filesystem events observed: {metrics['total_events_observed']}")
        print(f"  Total security alerts generated:  {metrics['total_alerts']}")
        print(f"{Fore.GREEN}Detector stopped cleanly.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
