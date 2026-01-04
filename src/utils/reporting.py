"""Reporting utilities and UI."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import (
    REPORTS_DIR,
    SETTINGS_DIR,
    SOFTWARE_PATHS_ARCHIVE,
    SOFTWARE_PATHS_MANUAL_INSTALLS,
    SOFTWARE_PATHS_PACKAGE_PREP,
    SOFTWARE_PATHS_PACKAGED,
    SOFTWARE_PATHS_SCAN_REQUESTS,
    SOFTWARE_PATHS_SOURCE,
    SOFTWARE_PATHS_STAGING,
    RETENTION_MANUAL_INSTALLS,
    RETENTION_PACKAGED_APPLICATIONS,
    RETENTION_SCAN_REQUESTS,
)
from src.utils.metadata_extractor import parse_package_info_file


def build_reporting_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Reporting UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]

    def set_dirty(value: bool = True) -> None:
        """Mark the page dirty so tab switching warns about unsaved edits."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    header = ttk.Label(
        frame,
        text="Reporting",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Run reports based on current content thresholds and export to CSV.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    report_group = ttk.LabelFrame(frame, text="Content Age Scanning", padding=16)
    report_group.pack(fill=tk.X, pady=(0, 20))
    report_group.columnconfigure(1, weight=1)

    location_definitions = _load_location_definitions()
    location_vars: dict[str, tk.BooleanVar] = {}

    ttk.Label(
        report_group,
        text="Locations to scan",
        style="Body.TLabel",
    ).grid(row=0, column=0, sticky="w", pady=4, padx=(0, 12))

    locations_frame = ttk.Frame(report_group)
    locations_frame.grid(row=0, column=1, sticky="w")

    for index, (key, definition) in enumerate(location_definitions.items()):
        var = tk.BooleanVar(value=True)
        location_vars[key] = var
        checkbox = ttk.Checkbutton(
            locations_frame,
            text=definition["label"],
            variable=var,
            command=lambda: set_dirty(True),
        )
        checkbox.grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 16), pady=2)

    output_group = ttk.LabelFrame(frame, text="Content Age Output", padding=16)
    output_group.pack(fill=tk.X, pady=(0, 20))
    output_group.columnconfigure(1, weight=1)

    output_var = tk.StringVar(value=_default_report_path())

    ttk.Label(output_group, text="CSV path", style="Body.TLabel").grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    output_entry = ttk.Entry(output_group, textvariable=output_var, width=70)
    output_entry.grid(row=0, column=1, sticky="we", pady=4)

    browse_button = ttk.Button(
        output_group,
        text="Browse",
        command=lambda: _browse_output_path(output_var),
    )
    browse_button.grid(row=0, column=2, padx=(12, 0))

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    run_button = ttk.Button(
        actions,
        text="Run Content Age Scan",
        command=lambda: _run_content_age_scan(
            location_definitions,
            location_vars,
            output_var.get(),
            set_dirty,
        ),
    )
    run_button.pack(side=tk.RIGHT)

    compliance_group = ttk.LabelFrame(frame, text="Packaged Applications Compliance", padding=16)
    compliance_group.pack(fill=tk.X, pady=(0, 20))
    compliance_group.columnconfigure(1, weight=1)

    ttk.Label(
        compliance_group,
        text="Validates required files and naming standards in Packaged_Applications.",
        style="Body.TLabel",
    ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

    compliance_output_var = tk.StringVar(value=_default_compliance_report_path())

    ttk.Label(compliance_group, text="CSV path", style="Body.TLabel").grid(
        row=1, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    compliance_entry = ttk.Entry(compliance_group, textvariable=compliance_output_var, width=70)
    compliance_entry.grid(row=1, column=1, sticky="we", pady=4)

    compliance_browse = ttk.Button(
        compliance_group,
        text="Browse",
        command=lambda: _browse_output_path(
            compliance_output_var,
            "Save Compliance Report",
        ),
    )
    compliance_browse.grid(row=1, column=2, padx=(12, 0))

    compliance_actions = ttk.Frame(frame, style="Content.TFrame")
    compliance_actions.pack(fill=tk.X)
    compliance_button = ttk.Button(
        compliance_actions,
        text="Run Compliance Report",
        command=lambda: _run_packaged_compliance_report(
            compliance_output_var.get(),
            set_dirty,
        ),
    )
    compliance_button.pack(side=tk.RIGHT)

    return frame


def _default_report_path() -> str:
    """Generate a default CSV path for the report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = _get_reports_output_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    return str(reports_dir / f"content_age_scan_{timestamp}.csv")


def _default_compliance_report_path() -> str:
    """Generate a default CSV path for the compliance report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = _get_reports_output_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    return str(reports_dir / f"packaged_compliance_{timestamp}.csv")


def _browse_output_path(output_var: tk.StringVar, title: str = "Save Content Age Report") -> None:
    """Open a save dialog for the CSV report."""
    file_path = filedialog.asksaveasfilename(
        title=title,
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
    )
    if file_path:
        output_var.set(file_path)


def _run_content_age_scan(
    location_definitions: dict[str, dict[str, object]],
    location_vars: dict[str, tk.BooleanVar],
    output_path: str,
    set_dirty,
) -> None:
    """Run the content age scan and write the CSV output."""
    selected_keys = [key for key, var in location_vars.items() if var.get()]
    if not selected_keys:
        messagebox.showerror("Missing Selection", "Please select at least one location to scan.")
        return

    output_path_obj = Path(output_path).expanduser()
    output_path_obj.parent.mkdir(parents=True, exist_ok=True)
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows: list[list[str]] = []
    missing_locations: list[str] = []
    for key in selected_keys:
        definition = location_definitions[key]
        root = Path(str(definition["path"]))
        threshold = int(definition["threshold"])
        if not root.exists():
            missing_locations.append(str(root))
            continue
        for item in root.iterdir():
            try:
                mtime = item.stat().st_mtime
            except OSError:
                continue
            age_days = max(0, int((datetime.now().timestamp() - mtime) // 86400))
            days_past = max(0, age_days - threshold)
            rows.append(
                [
                    scan_timestamp,
                    str(definition["label"]),
                    str(item),
                    str(age_days),
                    str(days_past),
                ]
            )

    try:
        with output_path_obj.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "scan_date_time",
                    "general_location",
                    "specific_location",
                    "actual_age_days",
                    "days_past_expiration",
                ]
            )
            writer.writerows(rows)
    except OSError as exc:
        messagebox.showerror("Write Failed", f"Could not write report:\n{exc}")
        return

    if missing_locations:
        messagebox.showwarning(
            "Locations Not Found",
            "These locations were not found and were skipped:\n"
            + "\n".join(missing_locations),
        )

    messagebox.showinfo("Report Created", f"Saved:\n{output_path_obj}")
    set_dirty(False)


def _run_packaged_compliance_report(output_path: str, set_dirty) -> None:
    """Run a compliance report against Packaged_Applications."""
    packaged_root = _get_path_setting(_load_settings(), "packaged_applications_path", SOFTWARE_PATHS_PACKAGED)
    if not packaged_root.exists():
        messagebox.showerror(
            "Missing Packaged_Applications",
            f"Path not found:\n{packaged_root}",
        )
        return

    output_path_obj = Path(output_path).expanduser()
    output_path_obj.parent.mkdir(parents=True, exist_ok=True)
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows: list[list[str]] = []
    for package_info_path in packaged_root.rglob("PackageInfo.txt"):
        package_root = package_info_path.parent
        values = _safe_parse_package_info(package_info_path)
        missing_items = _collect_missing_compliance_items(package_root)
        packaged_name, naming_expected, naming_status, exception_note = _evaluate_packaged_naming(
            package_root,
            values,
        )
        rows.append(
            [
                scan_timestamp,
                "Packaged_Applications",
                str(package_root),
                "; ".join(missing_items),
                packaged_name,
                naming_expected,
                naming_status,
                exception_note,
            ]
        )

    try:
        with output_path_obj.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "scan_date_time",
                    "general_location",
                    "specific_location",
                    "missing_required_items",
                    "packaged_app_name",
                    "naming_expected",
                    "naming_status",
                    "exception_note",
                ]
            )
            writer.writerows(rows)
    except OSError as exc:
        messagebox.showerror("Write Failed", f"Could not write report:\n{exc}")
        return

    messagebox.showinfo("Report Created", f"Saved:\n{output_path_obj}")
    set_dirty(False)


def _load_location_definitions() -> dict[str, dict[str, object]]:
    """Build location definitions from settings or defaults."""
    settings = _load_settings()
    return {
        "source": {
            "label": "Source",
            "path": _get_path_setting(settings, "source_path", SOFTWARE_PATHS_SOURCE),
            "threshold": _get_int_setting(settings, "content_age_source_days", 0),
        },
        "scan_requests": {
            "label": "Scan_Requests",
            "path": _get_path_setting(settings, "scan_requests_path", SOFTWARE_PATHS_SCAN_REQUESTS),
            "threshold": _get_int_setting(
                settings,
                "content_age_scan_requests_days",
                RETENTION_SCAN_REQUESTS,
            ),
        },
        "manual_installs": {
            "label": "Manual_Installs",
            "path": _get_path_setting(settings, "manual_installs_path", SOFTWARE_PATHS_MANUAL_INSTALLS),
            "threshold": _get_int_setting(
                settings,
                "content_age_manual_installs_days",
                RETENTION_MANUAL_INSTALLS,
            ),
        },
        "packaged_apps": {
            "label": "Packaged_Applications",
            "path": _get_path_setting(
                settings,
                "packaged_applications_path",
                SOFTWARE_PATHS_PACKAGED,
            ),
            "threshold": _get_int_setting(
                settings,
                "content_age_packaged_applications_days",
                RETENTION_PACKAGED_APPLICATIONS,
            ),
        },
        "package_prep": {
            "label": "Package_Prep",
            "path": _get_path_setting(settings, "package_prep_path", SOFTWARE_PATHS_PACKAGE_PREP),
            "threshold": _get_int_setting(settings, "content_age_source_days", 0),
        },
        "package_staging": {
            "label": "Package_Staging",
            "path": _get_path_setting(settings, "package_staging_path", SOFTWARE_PATHS_STAGING),
            "threshold": _get_int_setting(settings, "content_age_packaged_staging_days", 0),
        },
        "archive": {
            "label": "Archive",
            "path": _get_path_setting(settings, "archive_path", SOFTWARE_PATHS_ARCHIVE),
            "threshold": _get_int_setting(settings, "content_age_archive_days", 0),
        },
    }


def _load_settings() -> dict[str, Any]:
    """Load settings.json into a dictionary."""
    settings_path = SETTINGS_DIR / "settings.json"
    if not settings_path.exists():
        return {}
    try:
        raw = settings_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _get_path_setting(settings: dict[str, Any], key: str, fallback: Path) -> Path:
    """Return a resolved path setting or fallback."""
    value = settings.get(key)
    if isinstance(value, str) and value.strip():
        return _resolve_path(value.strip(), SETTINGS_DIR)
    return fallback


def _get_int_setting(settings: dict[str, Any], key: str, fallback: int) -> int:
    """Return an integer setting or fallback."""
    value = settings.get(key)
    if isinstance(value, int):
        return value
    return fallback


def _resolve_path(path: str, base_dir: Path) -> Path:
    """Resolve relative paths against base_dir."""
    if "://" in path or Path(path).is_absolute():
        return Path(path)
    if path.replace("\\", "/").startswith("settings/"):
        return (base_dir.parent / path).resolve()
    return (base_dir / path).resolve()


def _get_reports_output_dir() -> Path:
    """Return the configured reports output directory."""
    settings = _load_settings()
    return _get_path_setting(settings, "reports_output_path", REPORTS_DIR)


def _safe_parse_package_info(package_info_path: Path) -> dict[str, str]:
    """Parse a PackageInfo.txt file into a dictionary."""
    try:
        return parse_package_info_file(package_info_path)
    except OSError:
        return {}


def _collect_missing_compliance_items(package_root: Path) -> list[str]:
    """Return missing required files/directories for a package."""
    missing: list[str] = []
    required_files = ["PackageInfo.txt", "README.txt", "prefetch.txt"]
    for name in required_files:
        if not (package_root / name).exists():
            missing.append(name)

    build_dir = package_root / "build_files"
    if not build_dir.exists():
        missing.append("build_files/")
    else:
        for name in ("binary_config.txt"):
            if not (build_dir / name).exists():
                missing.append(f"build_files/{name}")
        if not _has_installer_file(build_dir):
            missing.append("build_files/(installer file)")

    dependencies_dir = package_root / "dependencies"
    if not dependencies_dir.exists():
        missing.append("dependencies/")
    elif not (dependencies_dir / "dependencies.txt").exists():
        missing.append("dependencies/dependencies.txt")

    if not _has_packaged_app_file(package_root):
        missing.append("Packaged App (.exe)")

    return missing


def _evaluate_packaged_naming(
    package_root: Path,
    values: dict[str, str],
) -> tuple[str, str, str, str]:
    """Return package naming compliance status."""
    vendor = values.get("Software Vendor", "")
    software = values.get("Software Name", "")
    version = values.get("Software Version", "")
    architecture = values.get("Software Architecture", "")
    expected = _build_expected_packaged_name(vendor, software, version, architecture)

    packaged_name = _find_packaged_app_name(package_root)
    if packaged_name and packaged_name.lower() == expected.lower():
        return packaged_name, expected, "Compliant", "Not applicable"

    exception_note = values.get("Rename Skipped Reason", "").strip()
    if exception_note:
        return packaged_name, expected, "Exception", exception_note

    if not packaged_name:
        return "", expected, "Missing Packaged App", "Not authorized"

    return packaged_name, expected, "Noncompliant", "Not authorized"


def _find_packaged_app_name(package_root: Path) -> str:
    """Find the packaged app executable name in the package root."""
    for entry in sorted(package_root.glob("*.exe")):
        return entry.name
    return ""


def _has_packaged_app_file(package_root: Path) -> bool:
    """Return True if the package root has an EXE."""
    return any(package_root.glob("*.exe"))


def _has_installer_file(build_dir: Path) -> bool:
    """Return True if build_files contains an installer (EXE/MSI)."""
    return any(build_dir.glob("*.exe")) or any(build_dir.glob("*.msi"))


def _build_expected_packaged_name(
    vendor: str,
    software: str,
    version: str,
    architecture: str,
) -> str:
    """Build the expected packaged app filename."""
    vendor = _normalize_name_part(vendor)
    software = _normalize_name_part(software)
    version = _normalize_name_part(version)
    architecture = _normalize_name_part(architecture)
    return f"{vendor}.{software}_{version}_{architecture}.exe"


def _normalize_name_part(value: str) -> str:
    """Remove spaces and punctuation from a name part."""
    return re.sub(r"[^A-Za-z0-9]", "", value or "")
