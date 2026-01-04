"""UI feedback helpers shared across the app."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont


def flash_label(label: ttk.Label, *, flashes: int = 10, interval_ms: int = 500) -> None:
    """Flash a label red/bold for a short duration."""
    normal_color = "#4b5a6a"
    alert_color = "#c0392b"
    style = ttk.Style(label)
    style_name = label.cget("style") or "TLabel"
    font_spec = label.cget("font") or style.lookup(style_name, "font") or "TkDefaultFont"
    try:
        normal_font = tkfont.nametofont(font_spec)
    except tk.TclError:
        normal_font = tkfont.Font(root=label, font=font_spec)
    alert_font = tkfont.Font(root=label, font=normal_font)
    alert_font.configure(weight="bold")

    def _toggle(count: int, is_alert: bool) -> None:
        if count <= 0:
            label.configure(foreground=normal_color)
            label.configure(font=font_spec)
            return
        if is_alert:
            label.configure(foreground=alert_color)
            label.configure(font=alert_font)
        else:
            label.configure(foreground=normal_color)
            label.configure(font=font_spec)
        label.after(interval_ms, _toggle, count - 1, not is_alert)

    _toggle(flashes, True)
