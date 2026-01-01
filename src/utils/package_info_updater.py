"""Package info file updater UI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from src.utils.package_info_creator import build_package_info_creator_frame


def build_package_info_updater_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Package Info File Updater UI frame."""
    return build_package_info_creator_frame(
        parent,
        allow_import=True,
        allow_installer=False,
        allow_prep=False,
        header_text="Package Info File Updater",
        subtext_text="Import an existing PackageInfo.txt, edit fields, and save updates.",
    )
