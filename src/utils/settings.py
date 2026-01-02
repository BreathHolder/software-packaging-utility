"""Settings UI and persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import (
    SETTINGS_DIR,
    FILE_PATHS_DEPENDENCY_NAMES,
    FILE_PATHS_SOFTWARE_NAMES,
    FILE_PATHS_VENDOR_NAMES,
    LOGGING_LEVEL,
    RETENTION_MANUAL_INSTALLS,
    RETENTION_PACKAGED_APPLICATIONS,
    RETENTION_SCAN_REQUESTs,
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
    settings_source_var = tk.StringVar(
        value=_get_string_setting(settings, "settings_source", "local")
    )
    vendor_names_local_var = tk.StringVar(
        value=_get_setting(settings, "vendor_names_path", FILE_PATHS_VENDOR_NAMES)
    )
    software_names_local_var = tk.StringVar(
        value=_get_setting(settings, "software_names_path", FILE_PATHS_SOFTWARE_NAMES)
    )
    dependency_names_local_var = tk.StringVar(
        value=_get_setting(settings, "dependency_names_path", FILE_PATHS_DEPENDENCY_NAMES)
    )
    vendor_names_repo_var = tk.StringVar(
        value=_get_string_setting(settings, "vendor_names_repo_url", "")
    )
    software_names_repo_var = tk.StringVar(
        value=_get_string_setting(settings, "software_names_repo_url", "")
    )
    dependency_names_repo_var = tk.StringVar(
        value=_get_string_setting(settings, "dependency_names_repo_url", "")
    )
    content_age_source_var = tk.StringVar(
        value=str(_get_int_setting(settings, "content_age_source_days", 0))
    )
    content_age_scan_requests_var = tk.StringVar(
        value=str(_get_int_setting(settings, "content_age_scan_requests_days", RETENTION_SCAN_REQUESTs))
    )
    content_age_manual_installs_var = tk.StringVar(
        value=str(_get_int_setting(settings, "content_age_manual_installs_days", RETENTION_MANUAL_INSTALLS))
    )
    content_age_packaged_applications_var = tk.StringVar(
        value=str(
            _get_int_setting(
                settings,
                "content_age_packaged_applications_days",
                RETENTION_PACKAGED_APPLICATIONS,
            )
        )
    )
    content_age_packaged_staging_var = tk.StringVar(
        value=str(_get_int_setting(settings, "content_age_packaged_staging_days", 0))
    )
    content_age_archive_var = tk.StringVar(
        value=str(_get_int_setting(settings, "content_age_archive_days", 0))
    )
    log_level_var = tk.StringVar(
        value=_get_string_setting(settings, "log_level", LOGGING_LEVEL).lower()
    )

    def set_dirty(value: bool = True) -> None:
        """Mark the settings page dirty so tab switching prompts the user."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    def mark_dirty(_event=None) -> None:
        """Event handler that marks the page dirty on edits."""
        set_dirty(True)

    def update_source_children(*_args) -> None:
        """Auto-derive Scan_Requests/Manual_Installs from Source."""
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

    files_group = ttk.LabelFrame(frame, text="Settings Files", padding=16)
    files_group.pack(fill=tk.X, pady=(0, 20))
    files_group.columnconfigure(1, weight=1)

    source_label = ttk.Label(files_group, text="Settings source", style="Body.TLabel")
    source_label.grid(row=0, column=0, sticky="w", pady=4, padx=(0, 12))
    source_frame = ttk.Frame(files_group)
    source_frame.grid(row=0, column=1, sticky="w", pady=4)
    ttk.Radiobutton(
        source_frame,
        text="Local files",
        value="local",
        variable=settings_source_var,
        command=mark_dirty,
    ).pack(side=tk.LEFT, padx=(0, 12))
    ttk.Radiobutton(
        source_frame,
        text="GitHub repo",
        value="github",
        variable=settings_source_var,
        command=mark_dirty,
    ).pack(side=tk.LEFT)

    _add_path_row(
        files_group,
        row=1,
        label="Vendor names (local)",
        variable=vendor_names_local_var,
        browse=True,
        on_change=mark_dirty,
    )
    _add_path_row(
        files_group,
        row=2,
        label="Software names (local)",
        variable=software_names_local_var,
        browse=True,
        on_change=mark_dirty,
    )
    _add_path_row(
        files_group,
        row=3,
        label="Dependency names (local)",
        variable=dependency_names_local_var,
        browse=True,
        on_change=mark_dirty,
    )

    _add_path_row(
        files_group,
        row=4,
        label="Vendor names (GitHub)",
        variable=vendor_names_repo_var,
        browse=False,
        on_change=mark_dirty,
    )
    _add_path_row(
        files_group,
        row=5,
        label="Software names (GitHub)",
        variable=software_names_repo_var,
        browse=False,
        on_change=mark_dirty,
    )
    _add_path_row(
        files_group,
        row=6,
        label="Dependency names (GitHub)",
        variable=dependency_names_repo_var,
        browse=False,
        on_change=mark_dirty,
    )

    content_group = ttk.LabelFrame(frame, text="Content Age (days)", padding=16)
    content_group.pack(fill=tk.X, pady=(0, 20))
    content_group.columnconfigure(1, weight=1)

    _add_text_row(
        content_group,
        row=0,
        label="Source",
        variable=content_age_source_var,
        on_change=mark_dirty,
    )
    _add_text_row(
        content_group,
        row=1,
        label="Scan_Requests",
        variable=content_age_scan_requests_var,
        on_change=mark_dirty,
    )
    _add_text_row(
        content_group,
        row=2,
        label="Manual_Installs",
        variable=content_age_manual_installs_var,
        on_change=mark_dirty,
    )
    _add_text_row(
        content_group,
        row=3,
        label="Packaged_Applications",
        variable=content_age_packaged_applications_var,
        on_change=mark_dirty,
    )
    _add_text_row(
        content_group,
        row=4,
        label="Packaged_Staging",
        variable=content_age_packaged_staging_var,
        on_change=mark_dirty,
    )
    _add_text_row(
        content_group,
        row=5,
        label="Archive",
        variable=content_age_archive_var,
        on_change=mark_dirty,
    )

    logging_group = ttk.LabelFrame(frame, text="Logging", padding=16)
    logging_group.pack(fill=tk.X, pady=(0, 20))
    logging_group.columnconfigure(1, weight=1)

    ttk.Label(logging_group, text="Log level", style="Body.TLabel").grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    log_level_combo = ttk.Combobox(
        logging_group,
        textvariable=log_level_var,
        values=["debug", "info", "warn", "error"],
        state="readonly",
        width=20,
    )
    log_level_combo.grid(row=0, column=1, sticky="w", pady=4)
    log_level_combo.bind("<<ComboboxSelected>>", mark_dirty)

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
            settings_source_var.get(),
            vendor_names_local_var.get(),
            software_names_local_var.get(),
            dependency_names_local_var.get(),
            vendor_names_repo_var.get(),
            software_names_repo_var.get(),
            dependency_names_repo_var.get(),
            content_age_source_var.get(),
            content_age_scan_requests_var.get(),
            content_age_manual_installs_var.get(),
            content_age_packaged_applications_var.get(),
            content_age_packaged_staging_var.get(),
            content_age_archive_var.get(),
            log_level_var.get(),
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
    """Render a labeled path input with an optional browse button."""
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


def _add_text_row(
    parent: ttk.LabelFrame,
    row: int,
    label: str,
    variable: tk.StringVar,
    on_change=None,
) -> None:
    """Render a simple labeled text input."""
    ttk.Label(parent, text=label, style="Body.TLabel").grid(
        row=row, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    entry = ttk.Entry(parent, textvariable=variable, width=20)
    entry.grid(row=row, column=1, sticky="w", pady=4)
    entry.bind("<KeyRelease>", on_change or (lambda _event: None))


def _browse_directory(variable: tk.StringVar, on_change=None) -> None:
    """Prompt for a folder and update the bound variable."""
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
    settings_source: str,
    vendor_names_path: str,
    software_names_path: str,
    dependency_names_path: str,
    vendor_names_repo_url: str,
    software_names_repo_url: str,
    dependency_names_repo_url: str,
    content_age_source_days: str,
    content_age_scan_requests_days: str,
    content_age_manual_installs_days: str,
    content_age_packaged_applications_days: str,
    content_age_packaged_staging_days: str,
    content_age_archive_days: str,
    log_level: str,
    set_dirty,
) -> None:
    """Validate inputs and persist settings to settings.json.

    Troubleshooting: if save fails, confirm file permissions on settings.json.
    """
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
    updated["settings_source"] = settings_source.strip() or "local"
    updated["vendor_names_path"] = _normalize_path(
        _relativize_path(vendor_names_path, SETTINGS_DIR)
    )
    updated["software_names_path"] = _normalize_path(
        _relativize_path(software_names_path, SETTINGS_DIR)
    )
    updated["dependency_names_path"] = _normalize_path(
        _relativize_path(dependency_names_path, SETTINGS_DIR)
    )
    updated["vendor_names_repo_url"] = vendor_names_repo_url.strip()
    updated["software_names_repo_url"] = software_names_repo_url.strip()
    updated["dependency_names_repo_url"] = dependency_names_repo_url.strip()

    age_fields = {
        "content_age_source_days": content_age_source_days,
        "content_age_scan_requests_days": content_age_scan_requests_days,
        "content_age_manual_installs_days": content_age_manual_installs_days,
        "content_age_packaged_applications_days": content_age_packaged_applications_days,
        "content_age_packaged_staging_days": content_age_packaged_staging_days,
        "content_age_archive_days": content_age_archive_days,
    }
    invalid = [key for key, value in age_fields.items() if not _is_valid_age(value)]
    if invalid:
        messagebox.showerror(
            "Invalid Content Age",
            "Enter whole numbers for:\n" + "\n".join(invalid),
        )
        return

    for key, value in age_fields.items():
        updated[key] = int(value.strip())

    normalized_level = log_level.strip().lower()
    valid_levels = {"debug", "info", "warn", "error"}
    if normalized_level not in valid_levels:
        messagebox.showerror(
            "Invalid Log Level",
            "Select one of: debug, info, warn, error.",
        )
        return
    updated["log_level"] = normalized_level

    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SETTINGS_FILE.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    except OSError as exc:
        messagebox.showerror("Save Failed", f"Could not save settings:\n{exc}")
        return

    messagebox.showinfo("Settings Saved", f"Saved:\n{SETTINGS_FILE}")
    set_dirty(False)


def _load_settings() -> dict[str, Any]:
    """Load settings.json into a dictionary."""
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
    """Return a normalized path setting, resolving relative paths."""
    value = settings.get(key)
    if isinstance(value, str) and value.strip():
        return _normalize_path(_resolve_path(value.strip(), SETTINGS_DIR))
    return _normalize_path(str(fallback))


def _get_string_setting(settings: dict[str, Any], key: str, fallback: str) -> str:
    """Return a string setting or fallback if missing."""
    value = settings.get(key)
    if isinstance(value, str):
        return value.strip()
    return fallback


def _get_int_setting(settings: dict[str, Any], key: str, fallback: int) -> int:
    """Return an integer setting or fallback if missing/invalid."""
    value = settings.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return fallback


def _is_valid_age(value: str) -> bool:
    """Return True when the content age field is a whole number string."""
    return bool(value.strip()) and value.strip().isdigit()


def _normalize_path(path: str) -> str:
    """Normalize a path to forward slashes for storage."""
    return path.replace("\\", "/")


def _relativize_path(path: str, base_dir: Path) -> str:
    """Return a path relative to base_dir when possible."""
    if not path:
        return path
    try:
        resolved = Path(path).expanduser().resolve()
        base = base_dir.expanduser().resolve()
        return str(resolved.relative_to(base))
    except (OSError, ValueError):
        return path


def _resolve_path(path: str, base_dir: Path) -> str:
    """Resolve a relative path against base_dir for display."""
    if not path:
        return path
    if "://" in path or Path(path).is_absolute():
        return path
    if path.replace("\\", "/").startswith("settings/"):
        return str((base_dir.parent / path).resolve())
    return str((base_dir / path).resolve())
