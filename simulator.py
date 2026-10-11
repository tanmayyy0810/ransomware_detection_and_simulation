#!/usr/bin/env python3
"""
CLI Tool: Safe Ransomware Behavior Simulator.
Simulates ransomware-like mass file renaming inside the isolated test_folder.
"""

import argparse
import sys
from pathlib import Path
from colorama import init, Fore, Style

import config
from core.sandbox_manager import SandboxManager
from core.simulation_engine import SimulationEngine

init(autoreset=True)

def parse_args():
    parser = argparse.ArgumentParser(description="Safe Ransomware Behavior Simulator (Sandboxed)")
    parser.add_argument("--delay", type=float, default=config.DEFAULT_SIMULATION_DELAY,
                        help=f"Seconds between file renames (default: {config.DEFAULT_SIMULATION_DELAY}s)")
    return parser.parse_args()

def main():
    args = parse_args()
    sandbox = SandboxManager()

    print(f"\n{Style.BRIGHT}{Fore.YELLOW}==================================================================")
    print(f"{Fore.YELLOW}  SAFE RANSOMWARE BEHAVIOR SIMULATOR")
    print(f"{Fore.YELLOW}=================================================================={Style.RESET_ALL}\n")

    if not sandbox.is_safe_sandbox_dir():
        print(f"{Fore.RED}[ERROR] Sandbox perimeter safety check failed! Aborting.{Style.RESET_ALL}")
        sys.exit(1)

    eligible = sandbox.get_eligible_for_simulation()
    if not eligible:
        print(f"{Fore.RED}[ERROR] No eligible dummy files found in {sandbox.sandbox_path}.{Style.RESET_ALL}")
        print(f"Run 'python prepare_demo.py' to generate test files first.\n")
        sys.exit(1)

    print(f"Target Directory:    {sandbox.sandbox_path}")
    print(f"Total Dummy Files:   {len(eligible)}")
    print(f"Inter-file Delay:    {args.delay:.2f} seconds")
    print(f"Action:              Simulating bulk append of {config.LOCKED_EXTENSION}")
    print(f"{Fore.YELLOW}Starting safe simulation... (Press Ctrl+C to stop){Style.RESET_ALL}\n")

    def on_progress(idx, total, old_name, new_name):
        pct = int((idx / total) * 100)
        print(f"[{idx:02d}/{total:02d}] {Fore.CYAN}Renamed{Style.RESET_ALL} {old_name:<24} -> {Fore.YELLOW}{new_name:<30}{Style.RESET_ALL} (Progress: {pct}%)")

    sim = SimulationEngine(
        sandbox_manager=sandbox,
        delay_seconds=args.delay,
        on_progress=on_progress
    )

    try:
        processed, total, summary = sim.run_synchronous()
        print(f"\n{Fore.GREEN}[COMPLETE] {summary}{Style.RESET_ALL}\n")
    except KeyboardInterrupt:
        sim.stop()
        print(f"\n{Fore.YELLOW}Simulation interrupted by user.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
