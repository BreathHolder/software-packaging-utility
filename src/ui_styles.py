"""UI styling helpers for the application."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def apply_styles(app: tk.Tk) -> dict[str, str]:
    """Apply ttk styles and return shared color tokens.

    Troubleshooting: if styles do not apply, ensure a ttk theme is available
    on the host OS and that this runs before widgets are created.
    """
    style = ttk.Style(app)
    themes = style.theme_names()
    if "vista" in themes:
        style.theme_use("vista")
    elif "clam" in themes:
        style.theme_use("clam")
    else:
        style.theme_use(themes[0])
    style.configure("App.TFrame", background="#f7f3ee")
    style.configure("Ribbon.TFrame", background="#1f2a36")
    style.configure("RibbonTitle.TLabel", background="#1f2a36", foreground="#e8edf2")
    style.configure("Content.TFrame", background="#f7f3ee")
    style.configure("Header.TLabel", background="#f7f3ee", foreground="#1f2a36")
    style.configure("Body.TLabel", background="#f7f3ee", foreground="#4b5a6a")
    # Keep ttk frames/labelframes aligned with the content background.
    style.configure("TFrame", background="#f7f3ee")
    style.configure("TLabelframe", background="#f7f3ee")
    style.configure("TLabelframe.Label", background="#f7f3ee", foreground="#1f2a36")


    return {
        "ribbon_bg": "#1f2a36",
        "tab_bg": "#263445",
        "tab_fg": "#e8edf2",
        "tab_hover_bg": "#2c3d52",
        "tab_active_bg": "#f7f3ee",
        "tab_active_fg": "#1f2a36",
        "tab_border": "#263445",
        "tab_active_border": "#d9d2c9",
    }
