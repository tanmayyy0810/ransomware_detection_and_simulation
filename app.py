#!/usr/bin/env python3
"""
Desktop Application Entry Point.
Ransomware Behavior Detection and Simulation System.
Launches the native Tkinter/ttk desktop interface.
"""

import sys
import tkinter as tk
from ui.main_window import MainWindow

def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
