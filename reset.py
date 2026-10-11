#!/usr/bin/env python3
"""
CLI Tool: Demonstration Reset and Sandbox Recovery.
Restores locked test files back to their original names using verified manifest records.
"""

import sys
from pathlib import Path
from colorama import init, Fore, Style

import config
from core.sandbox_manager import SandboxManager
from core.reset_manager import ResetManager

init(autoreset=True)

def main():
    print(f"\n{Style.BRIGHT}{Fore.CYAN}==================================================================")
    print(f"{Fore.CYAN}  DEMO RESET AND SANDBOX RECOVERY")
    print(f"{Fore.CYAN}=================================================================={Style.RESET_ALL}\n")

    try:
        sandbox = SandboxManager()
        if not sandbox.is_safe_sandbox_dir():
            print(f"{Fore.RED}[ERROR] Sandbox path safety verification failed! Aborting.{Style.RESET_ALL}")
            sys.exit(1)

        print(f"Sandbox Target: {sandbox.sandbox_path}")
        print(f"Scanning manifest and restoring original file states...")

        resetter = ResetManager(sandbox)
        restored, errors, summary = resetter.reset_sandbox(regenerate_missing=True)

        if errors == 0:
            print(f"\n{Fore.GREEN}[SUCCESS] {summary}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[WARNING] {summary}{Style.RESET_ALL}")

        print(f"\nVerification:")
        statuses = sandbox.get_file_statuses()
        original_count = sum(1 for s in statuses if s["status"] == "Original")
        print(f"  Files currently in original state: {Fore.GREEN}{original_count}/{len(statuses)}{Style.RESET_ALL}")
        print(f"\nSandbox is restored and ready for another demonstration run.\n")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Reset operation cancelled by user.{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Reset failed: {e}{Style.RESET_ALL}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
