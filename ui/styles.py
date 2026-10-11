"""
UI Theme and Styles Configuration.
Provides a restrained, professional technical monitoring aesthetic (NO EMOJIS).
Uses Segoe UI typography and a dark slate palette appropriate for OS/Cybersecurity labs.
"""

import tkinter as tk
from tkinter import ttk

# Palette Constants
BG_MAIN = "#1e2227"          # Window canvas background
BG_PANEL = "#282c34"         # Panel surfaces
BG_CARD = "#21252b"          # Inner card surface
BG_INPUT = "#1b1d23"         # Input controls background
BORDER_COLOR = "#3e4451"     # Subtle component borders

TEXT_MAIN = "#abb2bf"        # Primary readable text
TEXT_BRIGHT = "#ffffff"      # High contrast headings
TEXT_MUTED = "#5c6370"       # Secondary labels

ACCENT_BLUE = "#61afef"      # Primary actions & selection
ACCENT_GREEN = "#98c379"     # Active monitoring / safe baseline
ACCENT_AMBER = "#e5c07b"     # Warnings / intermediate state
ACCENT_RED = "#e06c75"       # Security alert / suspicious activity
BTN_BG = "#353b45"           # Standard button background
BTN_HOVER = "#3e4451"
BTN_ACTIVE = "#4b5263"

# Fonts
FONT_FAMILY = "Segoe UI"
FONT_TITLE = (FONT_FAMILY, 14, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 9, "normal")
FONT_HEADING = (FONT_FAMILY, 11, "bold")
FONT_SUBHEADING = (FONT_FAMILY, 10, "bold")
FONT_BODY = (FONT_FAMILY, 9, "normal")
FONT_BODY_BOLD = (FONT_FAMILY, 9, "bold")
FONT_MONO = ("Consolas", 8, "normal")
FONT_MONO_BOLD = ("Consolas", 9, "bold")
FONT_BADGE = (FONT_FAMILY, 9, "bold")

def setup_ttk_styles(root: tk.Tk) -> ttk.Style:
    """Configure modern ttk styles matching the dark slate design system."""
    style = ttk.Style(root)
    style.theme_use("clam")

    # Base Frame styles
    style.configure("TFrame", background=BG_MAIN)
    style.configure("Panel.TFrame", background=BG_PANEL, relief="flat")
    style.configure("Card.TFrame", background=BG_CARD, relief="solid", borderwidth=1)

    # Label styles
    style.configure("TLabel", background=BG_MAIN, foreground=TEXT_MAIN, font=FONT_BODY)
    style.configure("Panel.TLabel", background=BG_PANEL, foreground=TEXT_MAIN, font=FONT_BODY)
    style.configure("Card.TLabel", background=BG_CARD, foreground=TEXT_MAIN, font=FONT_BODY)

    style.configure("HeaderTitle.TLabel", background=BG_MAIN, foreground=TEXT_BRIGHT, font=FONT_TITLE)
    style.configure("HeaderSub.TLabel", background=BG_MAIN, foreground=TEXT_MUTED, font=FONT_SUBTITLE)
    style.configure("PanelTitle.TLabel", background=BG_PANEL, foreground=TEXT_BRIGHT, font=FONT_HEADING)
    style.configure("PanelSub.TLabel", background=BG_PANEL, foreground=TEXT_MUTED, font=FONT_SUBTITLE)

    # Button styles
    style.configure(
        "TButton",
        background=BTN_BG,
        foreground=TEXT_BRIGHT,
        bordercolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        font=FONT_BODY_BOLD,
        padding=(8, 4)
    )
    style.map(
        "TButton",
        background=[("pressed", BTN_ACTIVE), ("active", BTN_HOVER), ("disabled", "#22252a")],
        foreground=[("disabled", TEXT_MUTED)]
    )

    style.configure("Primary.TButton", background=ACCENT_BLUE, foreground="#000000", font=FONT_BODY_BOLD)
    style.map("Primary.TButton", background=[("pressed", "#4fa1e2"), ("active", "#75bcfa")])

    style.configure("Danger.TButton", background=ACCENT_RED, foreground="#ffffff", font=FONT_BODY_BOLD)
    style.map("Danger.TButton", background=[("pressed", "#c9555e"), ("active", "#eb7983")])

    # Treeview (Live File Explorer table)
    style.configure(
        "Treeview",
        background=BG_CARD,
        foreground=TEXT_MAIN,
        fieldbackground=BG_CARD,
        rowheight=22,
        font=FONT_MONO,
        borderwidth=0
    )
    style.configure(
        "Treeview.Heading",
        background=BG_PANEL,
        foreground=TEXT_BRIGHT,
        font=FONT_SUBHEADING,
        relief="flat",
        padding=(4, 4)
    )
    style.map("Treeview", background=[("selected", "#2c313a")], foreground=[("selected", TEXT_BRIGHT)])
    style.map("Treeview.Heading", background=[("active", BORDER_COLOR)])

    # Progress bar
    style.configure("Horizontal.TProgressbar", background=ACCENT_BLUE, troughcolor=BG_CARD, borderwidth=0, thickness=6)

    # Entry and Spinbox
    style.configure(
        "TEntry",
        fieldbackground=BG_INPUT,
        foreground=TEXT_BRIGHT,
        bordercolor=BORDER_COLOR,
        padding=3
    )

    style.configure(
        "TSpinbox",
        fieldbackground=BG_INPUT,
        foreground=TEXT_BRIGHT,
        bordercolor=BORDER_COLOR,
        arrowcolor=TEXT_MAIN
    )

    return style
