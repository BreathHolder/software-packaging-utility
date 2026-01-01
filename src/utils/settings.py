"""Settings UI and persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import (
    SETTINGS_DIR,
    SOFTWARE_PATHS_ARCHIVE,
    SOFTWARE_PATHS_MANUAL_INSTALLS,
    SOFTWARE_PATHS_PACKAGED,
    SOFTWARE_PATHS_SCAN_REQUESTS,
    SOFTWARE_PATHS_SOURCE,
    SOFTWARE_PATHS_STAGING,
)

SETTINGS_FILE = SETTINGS_DIR / "settings.json"


def build_settings_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Settings UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]

    settings = _load_settings()

    header = ttk.Label(
        frame,
        text="Settings",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Configure source and packaging paths.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    source_var = tk.StringVar(value=_get_setting(settings, "source_path", SOFTWARE_PATHS_SOURCE))
    scan_requests_var = tk.StringVar(
        value=_get_setting(settings, "scan_requests_path", SOFTWARE_PATHS_SCAN_REQUESTS)
    )
    manual_installs_var = tk.StringVar(
        value=_get_setting(settings, "manual_installs_path", SOFTWARE_PATHS_MANUAL_INSTALLS)
    )
    packaged_var = tk.StringVar(
        value=_get_setting(settings, "packaged_applications_path", SOFTWARE_PATHS_PACKAGED)
    )
    staging_var = tk.StringVar(
        value=_get_setting(settings, "packaged_staging_path", SOFTWARE_PATHS_STAGING)
    )
    archive_var = tk.StringVar(
        value=_get_setting(settings, "archive_path", SOFTWARE_PATHS_ARCHIVE)
    )

    def set_dirty(value: bool = True) -> None:
        frame.is_dirty = value  # type: ignore[attr-defined]

    def mark_dirty(_event=None) -> None:
        set_dirty(True)

    def update_source_children(*_args) -> None:
        source = Path(source_var.get().strip() or str(SOFTWARE_PATHS_SOURCE))
        scan_requests_var.set(str(source / "Scan_Requests"))
        manual_installs_var.set(str(source / "Manual_Installs"))
        set_dirty(True)

    source_var.trace_add("write", update_source_children)

    group = ttk.LabelFrame(frame, text="Paths", padding=16)
    group.pack(fill=tk.X, pady=(0, 20))
    group.columnconfigure(1, weight=1)

    _add_path_row(
        group,
        row=0,
        label="Source",
        variable=source_var,
        browse=True,
        on_change=mark_dirty,
    )
    _add_path_row(
        group,
        row=1,
        label="Scan_Requests (auto)",
        variable=scan_requests_var,
        browse=False,
        readonly=True,
    )
    _add_path_row(
        group,
        row=2,
        label="Manual_Installs (auto)",
        variable=manual_installs_var,
        browse=False,
        readonly=True,
    )
    _add_path_row(
        group,
        row=3,
        label="Packaged_Applications",
        variable=packaged_var,
        browse=True,
        on_change=mark_dirty,
    )
    _add_path_row(
        group,
        row=4,
        label="Packaged_Staging",
        variable=staging_var,
        browse=True,
        on_change=mark_dirty,
    )
    _add_path_row(
        group,
        row=5,
        label="Archive",
        variable=archive_var,
        browse=True,
        on_change=mark_dirty,
    )

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    save_button = ttk.Button(
        actions,
        text="Save Settings",
        command=lambda: _save_settings(
            settings,
            source_var.get(),
            scan_requests_var.get(),
            manual_installs_var.get(),
            packaged_var.get(),
            staging_var.get(),
            archive_var.get(),
            set_dirty,
        ),
    )
    save_button.pack(side=tk.RIGHT)

    return frame


def _add_path_row(
    parent: ttk.LabelFrame,
    row: int,
    label: str,
    variable: tk.StringVar,
    *,
    browse: bool,
    readonly: bool = False,
    on_change=None,
) -> None:
    ttk.Label(parent, text=label, style="Body.TLabel").grid(
        row=row, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    entry = ttk.Entry(parent, textvariable=variable, width=60)
    entry.grid(row=row, column=1, sticky="we", pady=4)
    if readonly:
        entry.configure(state="readonly")
    else:
        entry.bind("<KeyRelease>", on_change or (lambda _event: None))

    if browse:
        ttk.Button(
            parent,
            text="Browse",
            command=lambda: _browse_directory(variable, on_change),
        ).grid(row=row, column=2, padx=(12, 0), pady=4)


def _browse_directory(variable: tk.StringVar, on_change=None) -> None:
    directory = filedialog.askdirectory(title="Select Folder")
    if not directory:
        return
    variable.set(_normalize_path(directory))
    if on_change:
        on_change()


def _save_settings(
    existing: dict[str, Any],
    source_path: str,
    scan_requests_path: str,
    manual_installs_path: str,
    packaged_path: str,
    staging_path: str,
    archive_path: str,
    set_dirty,
) -> None:
    required = {
        "Source": source_path,
        "Packaged_Applications": packaged_path,
        "Packaged_Staging": staging_path,
        "Archive": archive_path,
    }
    missing = [label for label, value in required.items() if not value.strip()]
    if missing:
        messagebox.showerror(
            "Missing Settings",
            "Please provide values for:\n" + "\n".join(missing),
        )
        return

    updated = dict(existing)
    updated["source_path"] = _normalize_path(source_path)
    updated["scan_requests_path"] = _normalize_path(scan_requests_path)
    updated["manual_installs_path"] = _normalize_path(manual_installs_path)
    updated["packaged_applications_path"] = _normalize_path(packaged_path)
    updated["packaged_staging_path"] = _normalize_path(staging_path)
    updated["archive_path"] = _normalize_path(archive_path)

    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SETTINGS_FILE.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    except OSError as exc:
        messagebox.showerror("Save Failed", f"Could not save settings:\n{exc}")
        return

    messagebox.showinfo("Settings Saved", f"Saved:\n{SETTINGS_FILE}")
    set_dirty(False)


def _load_settings() -> dict[str, Any]:
    if not SETTINGS_FILE.exists():
        return {}
    try:
        raw = SETTINGS_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _get_setting(settings: dict[str, Any], key: str, fallback: Path) -> str:
    value = settings.get(key)
    if isinstance(value, str) and value.strip():
        return _normalize_path(value.strip())
    return _normalize_path(str(fallback))


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/")
