#!/usr/bin/env python3
"""
CLI Tool: Prepare Demonstration Environment.
Generates 20 realistic dummy files and registers them in the sandbox manifest.
"""

import sys
from pathlib import Path
from colorama import init, Fore, Style

import config
from core.sandbox_manager import SandboxManager

init(autoreset=True)

def main():
    print(f"\n{Style.BRIGHT}{Fore.CYAN}==================================================================")
    print(f"{Fore.CYAN}  RANSOMWARE BEHAVIOR DETECTION SYSTEM -- DEMO PREPARATION")
    print(f"{Fore.CYAN}=================================================================={Style.RESET_ALL}\n")

    try:
        manager = SandboxManager()
        print(f"Target Sandbox Directory: {Fore.YELLOW}{manager.sandbox_path}{Style.RESET_ALL}")
        print(f"Verifying sandbox containment boundaries...")

        if not manager.is_safe_sandbox_dir():
            print(f"{Fore.RED}[ERROR] Sandbox path safety verification failed! Aborting.{Style.RESET_ALL}")
            sys.exit(1)

        print(f"Generating registered academic dummy files...")
        count, msg = manager.prepare_dummy_files(count=config.DEFAULT_DUMMY_COUNT, force_regenerate=True)

        print(f"\n{Fore.GREEN}[SUCCESS] {msg}{Style.RESET_ALL}")
        print(f"\nRegistered Files ({count} total):")

        files = manager.get_registered_files()
        for idx, (fname, info) in enumerate(files.items(), start=1):
            print(f"  [{idx:02d}/{count:02d}] {fname:<26} ({info.get('extension', '')}, {info.get('size_bytes', 0)} bytes)")

        print(f"\n{Fore.CYAN}Environment is ready for monitoring and simulation.{Style.RESET_ALL}")
        print(f"Next steps:")
        print(f"  1. Start detector:  python detector.py")
        print(f"  2. Start simulator: python simulator.py")
        print(f"  Or launch GUI:      python app.py\n")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Preparation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Failed to prepare demo files: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
