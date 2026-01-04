"""Package info file creator UI."""

from __future__ import annotations

import json
import os
import socket
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from src.config import (
    FILE_PATHS_BUSINESS_AREAS,
    FILE_PATHS_DEPENDENCY_NAMES,
    FILE_PATHS_SOFTWARE_NAMES,
    FILE_PATHS_VENDOR_NAMES,
    LOGGING_DIR,
    SETTINGS_DIR,
    SOFTWARE_PATHS_PACKAGE_PREP,
)
from src.utils.logging_utils import append_text_log
from src.utils.metadata_extractor import (
    InstallerMetadata,
    UNKNOWN_VALUE,
    extract_installer_metadata,
    parse_package_info_file,
)


def build_package_info_creator_frame(
    parent: tk.Widget,
    *,
    allow_import: bool = False,
    allow_installer: bool = True,
    allow_prep: bool = True,
    header_text: str = "Package Info File Creator",
    subtext_text: str = "Load an installer, review metadata, and generate PackageInfo.txt.",
) -> ttk.Frame:
    """Create the Package Info File Creator UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]
    current_metadata: Optional[InstallerMetadata] = None
    existing_package_info_path: Optional[Path] = None
    vendor_options = _load_picklist(FILE_PATHS_VENDOR_NAMES)
    software_options = _load_picklist(FILE_PATHS_SOFTWARE_NAMES)
    dependency_options = _load_picklist(FILE_PATHS_DEPENDENCY_NAMES)
    business_area_options = _load_picklist(FILE_PATHS_BUSINESS_AREAS)

    header = ttk.Label(
        frame,
        text=header_text,
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text=subtext_text,
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    vendor_var = tk.StringVar(value=UNKNOWN_VALUE)
    software_var = tk.StringVar(value=UNKNOWN_VALUE)
    version_var = tk.StringVar(value=UNKNOWN_VALUE)
    architecture_var = tk.StringVar(value=UNKNOWN_VALUE)
    sha1_var = tk.StringVar(value=UNKNOWN_VALUE)
    sha256_var = tk.StringVar(value=UNKNOWN_VALUE)
    manual_labels: dict[str, ttk.Label] = {}
    auto_labels: dict[str, ttk.Label] = {}

    def set_dirty(value: bool = True) -> None:
        """Mark the page dirty so tab switching warns about unsaved edits."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    def mark_dirty(_event=None) -> None:
        """Event handler that marks the page dirty."""
        set_dirty(True)

    def set_existing_package_info(path: Path) -> None:
        """Track the existing PackageInfo.txt path for updates."""
        nonlocal existing_package_info_path
        existing_package_info_path = path

    def set_metadata(metadata: InstallerMetadata) -> None:
        """Populate automatic fields from extracted installer metadata."""
        nonlocal current_metadata
        current_metadata = metadata
        vendor_var.set(metadata.vendor_name)
        software_var.set(metadata.software_name)
        version_var.set(metadata.software_version)
        architecture_var.set(metadata.software_architecture)
        sha1_var.set(metadata.sha1)
        sha256_var.set(metadata.sha256)
        set_dirty(True)

    if allow_import:
        package_info_var = tk.StringVar()
        import_group = ttk.LabelFrame(frame, text="Existing PackageInfo.txt", padding=16)
        import_group.pack(fill=tk.X, pady=(0, 20))

        import_label = ttk.Label(import_group, text="PackageInfo path", style="Body.TLabel")
        import_label.grid(row=0, column=0, sticky="w", padx=(0, 12))
        import_entry = ttk.Entry(import_group, textvariable=package_info_var, width=70)
        import_entry.grid(row=0, column=1, sticky="we")
        import_button = ttk.Button(
            import_group,
            text="Browse",
            command=lambda: _browse_package_info_path(
                import_entry,
                vendor_var,
                software_var,
                version_var,
                architecture_var,
                sha1_var,
                sha256_var,
                manual_widgets,
                set_existing_package_info,
                set_dirty,
            ),
        )
        import_button.grid(row=0, column=2, padx=(12, 0))
        import_group.columnconfigure(1, weight=1)

    path_entry: Optional[ttk.Entry]
    if allow_installer:
        source_group = ttk.LabelFrame(frame, text="Source Installer", padding=16)
        source_group.pack(fill=tk.X, pady=(0, 20))

        path_label = ttk.Label(source_group, text="Installer path", style="Body.TLabel")
        path_label.grid(row=0, column=0, sticky="w", padx=(0, 12))
        path_entry = ttk.Entry(source_group, width=70)
        path_entry.grid(row=0, column=1, sticky="we")
        browse_button = ttk.Button(
            source_group,
            text="Browse",
            command=lambda: _browse_installer_path(
                path_entry,
                vendor_var,
                software_var,
                version_var,
                architecture_var,
                sha1_var,
                sha256_var,
                set_metadata,
            ),
        )
        browse_button.grid(row=0, column=2, padx=(12, 0))
        source_group.columnconfigure(1, weight=1)
    else:
        path_entry = None

    manual_group = ttk.LabelFrame(frame, text="Manual Fields", padding=16)
    manual_group.pack(fill=tk.X, pady=(0, 20))

    manual_fields = [
        "Request ID",
        "Requestor Name",
        "Software Reference ID",
        "Software Technology Owner ID",
        "Licensed Software Flag",
        "Business Areas",
        "Software Dependencies",
        "Software Vulnerability Scan Results",
    ]
    manual_widgets: dict[str, Any] = {}
    row = 0
    for label in manual_fields:
        field_label = ttk.Label(manual_group, text=label, style="Body.TLabel")
        field_label.grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        manual_labels[label] = field_label
        if label == "Licensed Software Flag":
            info_icon = ttk.Label(manual_group, text="ⓘ", style="Body.TLabel")
            info_icon.grid(row=row, column=0, sticky="e", padx=(0, 4))
            _attach_tooltip(
                info_icon,
                "No: This software is not licensed.\n"
                "Version Specific: Licensed for this specific version.\n"
                "Newest+ N-1: Licensed for only the latest 2 versions.",
            )
            entry = ttk.Combobox(
                manual_group,
                values=["No", "Version Specific", "Newest+ N-1"],
                state="readonly",
                width=47,
            )
            entry.grid(row=row, column=1, sticky="we", pady=4)
            entry.bind("<<ComboboxSelected>>", mark_dirty)
        elif label == "Software Vulnerability Scan Results":
            status_var = tk.StringVar(value="Scan results found. No vulnerabilities found")
            status_combo = ttk.Combobox(
                manual_group,
                textvariable=status_var,
                values=[
                    "Scan results found. No vulnerabilities found",
                    "Scan results found. Vulnerabilities found and accepted by technology owner",
                    "Scan results NOT found or vulnerabilities found NOT accepted",
                ],
                state="readonly",
                width=47,
            )
            status_combo.grid(row=row, column=1, sticky="we", pady=4)
            status_combo.bind("<<ComboboxSelected>>", mark_dirty)

            info_icon = ttk.Label(manual_group, text="ⓘ", style="Body.TLabel")
            info_icon.grid(row=row, column=0, sticky="e", padx=(0, 4))
            _attach_tooltip(
                info_icon,
                "Copy and paste the scan results evidence received from the requestor.",
            )

            details_label = ttk.Label(
                manual_group,
                text="Scan Results Details",
                style="Body.TLabel",
            )
            details_text = tk.Text(manual_group, height=4, width=48, wrap="word")
            details_text.bind("<<Modified>>", _track_text_modified(details_text, mark_dirty))

            scan_row = row
            manual_labels["Software Vulnerability Scan Results Details"] = details_label

            def _toggle_scan_details(_event=None) -> None:
                """Show or hide scan details based on status selection."""
                selection = status_var.get()
                if selection in {
                    "Scan results found. No vulnerabilities found",
                    "Scan results found. Vulnerabilities found and accepted by technology owner",
                }:
                    details_label.grid(
                        row=scan_row + 1,
                        column=0,
                        sticky="nw",
                        pady=4,
                        padx=(0, 12),
                    )
                    details_text.grid(row=scan_row + 1, column=1, sticky="we", pady=4)
                    details_text.configure(state="normal")
                else:
                    details_text.grid_remove()
                    details_label.grid_remove()
                    details_text.configure(state="disabled")

            status_combo.bind("<<ComboboxSelected>>", _toggle_scan_details)
            _toggle_scan_details()

            manual_widgets["Software Vulnerability Scan Results Status"] = status_combo
            manual_widgets["Software Vulnerability Scan Results Details"] = details_text
            manual_labels["Software Vulnerability Scan Results Status"] = field_label
            row += 2
            continue
        elif label == "Software Dependencies":
            dependencies_frame = ttk.Frame(manual_group)
            dependencies_frame.grid(row=row, column=1, sticky="we", pady=4)
            dependencies_frame.columnconfigure(0, weight=1)

            dependencies_list = tk.Listbox(
                dependencies_frame,
                selectmode=tk.MULTIPLE,
                height=6,
                exportselection=False,
            )
            for option in dependency_options:
                dependencies_list.insert(tk.END, option)
            dependencies_list.grid(row=0, column=0, sticky="we")
            dependencies_list.bind("<<ListboxSelect>>", mark_dirty)
            _bind_listbox_mousewheel(dependencies_list)

            other_var = tk.BooleanVar(value=False)
            other_check = ttk.Checkbutton(
                dependencies_frame,
                text="Other",
                variable=other_var,
                command=lambda: (_toggle_other_dependency(other_entry, other_var), mark_dirty()),
            )
            other_check.grid(row=1, column=0, sticky="w", pady=(6, 0))

            none_var = tk.BooleanVar(value=False)
            none_check = ttk.Checkbutton(
                dependencies_frame,
                text="No dependencies",
                variable=none_var,
            )
            none_check.configure(command=lambda: (_toggle_no_dependencies(
                dependencies_list,
                other_check,
                other_entry,
                other_var,
                none_var,
            ), mark_dirty()))
            none_check.grid(row=1, column=0, sticky="e", pady=(6, 0))

            other_entry = ttk.Entry(dependencies_frame, width=48, state="disabled")
            other_entry.grid(row=2, column=0, sticky="we", pady=(4, 0))
            other_entry.bind("<KeyRelease>", mark_dirty)

            entry = {
                "kind": "dependencies",
                "listbox": dependencies_list,
                "other_var": other_var,
                "other_entry": other_entry,
                "none_var": none_var,
                "other_check": other_check,
                "none_check": none_check,
            }
        elif label == "Business Areas":
            areas_frame = ttk.Frame(manual_group)
            areas_frame.grid(row=row, column=1, sticky="we", pady=4)
            areas_frame.columnconfigure(0, weight=1)

            areas_list = tk.Listbox(
                areas_frame,
                selectmode=tk.MULTIPLE,
                height=5,
                exportselection=False,
            )
            for option in business_area_options:
                areas_list.insert(tk.END, option)
            areas_list.grid(row=0, column=0, sticky="we")
            areas_list.bind("<<ListboxSelect>>", mark_dirty)
            _bind_listbox_mousewheel(areas_list)

            entry = {
                "kind": "multi_select",
                "listbox": areas_list,
            }
        else:
            entry = ttk.Entry(manual_group, width=50)
            entry.grid(row=row, column=1, sticky="we", pady=4)
            entry.bind("<KeyRelease>", mark_dirty)
        manual_widgets[label] = entry
        row += 1
    manual_group.columnconfigure(1, weight=1)

    metadata_group = ttk.LabelFrame(frame, text="Automated Metadata", padding=16)
    metadata_group.pack(fill=tk.X, pady=(0, 20))

    auto_fields = [
        ("Software Vendor", "vendor"),
        ("Software Name", "software"),
        ("Software Version", "version"),
        ("Software Architecture", "architecture"),
        ("Software SHA1 Hash", "sha1"),
        ("Software SHA256 Hash", "sha256"),
    ]
    for idx, (label, field_key) in enumerate(auto_fields):
        field_label = ttk.Label(metadata_group, text=label, style="Body.TLabel")
        field_label.grid(row=idx, column=0, sticky="w", pady=4, padx=(0, 12))
        auto_labels[label] = field_label
        if field_key == "vendor":
            vendor_combo = ttk.Combobox(
                metadata_group,
                textvariable=vendor_var,
                values=_with_add_option(vendor_options),
                state="readonly",
                width=47,
            )
            vendor_combo.grid(row=idx, column=1, sticky="we", pady=4)
            vendor_combo.bind(
                "<<ComboboxSelected>>",
                lambda event: _handle_add_option(
                    vendor_combo,
                    vendor_options,
                    "Vendor",
                    FILE_PATHS_VENDOR_NAMES,
                    current_metadata,
                    path_entry,
                ),
            )
            vendor_combo.bind("<<ComboboxSelected>>", mark_dirty, add="+")
        elif field_key == "software":
            software_combo = ttk.Combobox(
                metadata_group,
                textvariable=software_var,
                values=_with_add_option(software_options),
                state="readonly",
                width=47,
            )
            software_combo.grid(row=idx, column=1, sticky="we", pady=4)
            software_combo.bind(
                "<<ComboboxSelected>>",
                lambda event: _handle_add_option(
                    software_combo,
                    software_options,
                    "Software",
                    FILE_PATHS_SOFTWARE_NAMES,
                    current_metadata,
                    path_entry,
                ),
            )
            software_combo.bind("<<ComboboxSelected>>", mark_dirty, add="+")
        elif field_key == "architecture":
            architecture_combo = ttk.Combobox(
                metadata_group,
                textvariable=architecture_var,
                values=["x86", "x64"],
                state="readonly",
                width=47,
            )
            architecture_combo.grid(row=idx, column=1, sticky="we", pady=4)
            architecture_combo.bind("<<ComboboxSelected>>", mark_dirty)
        elif field_key == "version":
            entry = ttk.Entry(metadata_group, textvariable=version_var, width=50)
            entry.grid(row=idx, column=1, sticky="we", pady=4)
            entry.bind("<KeyRelease>", mark_dirty)
        elif field_key == "sha1":
            entry = ttk.Entry(metadata_group, textvariable=sha1_var, width=50, state="readonly")
            entry.grid(row=idx, column=1, sticky="we", pady=4)
        elif field_key == "sha256":
            entry = ttk.Entry(metadata_group, textvariable=sha256_var, width=50, state="readonly")
            entry.grid(row=idx, column=1, sticky="we", pady=4)
    metadata_group.columnconfigure(1, weight=1)

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    prep_var = tk.BooleanVar(value=True)
    if allow_prep:
        prep_check = ttk.Checkbutton(actions, text="Prep for packaging", variable=prep_var)
        prep_check.pack(side=tk.LEFT)
    generate_button = ttk.Button(
        actions,
        text="Generate PackageInfo.txt",
        command=lambda: _generate_package_info(
            path_entry.get() if path_entry is not None else "",
            vendor_var.get(),
            software_var.get(),
            version_var.get(),
            architecture_var.get(),
            sha1_var.get(),
            sha256_var.get(),
            manual_widgets,
            manual_labels,
            auto_labels,
            prep_var.get(),
            existing_package_info_path,
            allow_installer,
            set_dirty,
        ),
    )
    generate_button.pack(side=tk.RIGHT)

    return frame


def _browse_installer_path(
    path_entry: ttk.Entry,
    vendor_var: tk.StringVar,
    software_var: tk.StringVar,
    version_var: tk.StringVar,
    architecture_var: tk.StringVar,
    sha1_var: tk.StringVar,
    sha256_var: tk.StringVar,
    set_metadata,
) -> None:
    """Open a file dialog and populate the installer path entry."""
    file_path = filedialog.askopenfilename(
        title="Select Installer",
        filetypes=[("Installer files", "*.msi *.exe"), ("All files", "*.*")],
    )
    if not file_path:
        return
    path_entry.delete(0, tk.END)
    path_entry.insert(0, file_path)

    try:
        metadata = extract_installer_metadata(Path(file_path))
    except Exception as exc:
        messagebox.showerror(
            "Metadata Extraction Failed",
            f"Could not extract metadata:\n{exc}",
        )
        return

    set_metadata(metadata)


def _browse_package_info_path(
    path_entry: ttk.Entry,
    vendor_var: tk.StringVar,
    software_var: tk.StringVar,
    version_var: tk.StringVar,
    architecture_var: tk.StringVar,
    sha1_var: tk.StringVar,
    sha256_var: tk.StringVar,
    manual_widgets: dict[str, Any],
    set_existing_package_info: Callable[[Path], None],
    set_dirty: Callable[[bool], None],
) -> None:
    """Load an existing PackageInfo.txt and populate fields for editing."""
    file_path = filedialog.askopenfilename(
        title="Select PackageInfo.txt",
        filetypes=[("PackageInfo.txt", "PackageInfo.txt"), ("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not file_path:
        return

    path_entry.delete(0, tk.END)
    path_entry.insert(0, file_path)

    try:
        values = parse_package_info_file(Path(file_path))
    except Exception as exc:
        messagebox.showerror(
            "PackageInfo Load Failed",
            f"Could not read PackageInfo.txt:\n{exc}",
        )
        return

    _apply_package_info_values(
        values,
        vendor_var,
        software_var,
        version_var,
        architecture_var,
        sha1_var,
        sha256_var,
        manual_widgets,
    )
    set_existing_package_info(Path(file_path))
    set_dirty(True)


def _load_picklist(path: Path) -> list[str]:
    """Load a JSON array of strings as a picklist."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    options = []
    for item in data:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                options.append(name)
        else:
            value = str(item).strip()
            if value:
                options.append(value)
    return sorted(options, key=str.casefold)


def _with_add_option(options: list[str]) -> list[str]:
    """Append the add-new sentinel option for comboboxes."""
    return [*options, "Add new..."]


def _handle_add_option(
    combo: ttk.Combobox,
    options: list[str],
    label: str,
    picklist_path: Path,
    metadata: Optional[InstallerMetadata],
    path_entry: ttk.Entry,
) -> None:
    """Handle the add-new combobox selection and log the request."""
    if combo.get() != "Add new...":
        return
    new_value = simpledialog.askstring(
        f"Add {label}",
        f"Enter new {label} name:",
    )
    if not new_value:
        combo.set(_fallback_value(label, metadata))
        return
    new_value = new_value.strip()
    if not new_value:
        combo.set(_fallback_value(label, metadata))
        return
    if new_value not in options:
        options.append(new_value)
        options.sort(key=str.casefold)
    combo.configure(values=_with_add_option(options))
    combo.set(new_value)
    _log_picklist_addition_request(picklist_path, new_value, metadata, path_entry.get())
    _log_freeform_entry(label, new_value, metadata, path_entry.get())


def _fallback_value(label: str, metadata: Optional[InstallerMetadata]) -> str:
    """Fallback to metadata values when a picklist add is canceled."""
    if not metadata:
        return UNKNOWN_VALUE
    if label == "Vendor":
        return metadata.vendor_name
    if label == "Software":
        return metadata.software_name
    return UNKNOWN_VALUE


def _log_picklist_addition_request(
    picklist_path: Path,
    value: str,
    metadata: Optional[InstallerMetadata],
    source_path: str,
) -> None:
    """Log a request to add a value to a picklist JSON file."""
    log_path = LOGGING_DIR / "json_edit_requests.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vendor = metadata.vendor_name if metadata else UNKNOWN_VALUE
    software = metadata.software_name if metadata else UNKNOWN_VALUE
    version = metadata.software_version if metadata else UNKNOWN_VALUE
    arch = metadata.software_architecture if metadata else UNKNOWN_VALUE
    source = source_path or (str(metadata.source_path) if metadata else UNKNOWN_VALUE)
    line = (
        f"{timestamp} | file={picklist_path} | value={value} | "
        f"source={source} | vendor={vendor} | software={software} | "
        f"version={version} | arch={arch}"
    )
    append_text_log(log_path, line)


def _log_freeform_entry(
    field_name: str,
    value: str,
    metadata: Optional[InstallerMetadata],
    source_path: str,
    vendor_name: str = UNKNOWN_VALUE,
    software_name: str = UNKNOWN_VALUE,
    software_version: str = UNKNOWN_VALUE,
    software_architecture: str = UNKNOWN_VALUE,
) -> None:
    """Log any freeform field additions for downstream review."""
    log_path = LOGGING_DIR / "middleware_edit_requests.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vendor = metadata.vendor_name if metadata else vendor_name
    software = metadata.software_name if metadata else software_name
    version = metadata.software_version if metadata else software_version
    arch = metadata.software_architecture if metadata else software_architecture
    source = source_path or (str(metadata.source_path) if metadata else UNKNOWN_VALUE)
    line = (
        f"{timestamp} | field={field_name} | value={value} | "
        f"source={source} | vendor={vendor} | software={software} | "
        f"version={version} | arch={arch}"
    )
    append_text_log(log_path, line)


def _generate_package_info(
    installer_path_str: str,
    vendor_name: str,
    software_name: str,
    software_version: str,
    software_architecture: str,
    sha1_hash: str,
    sha256_hash: str,
    manual_widgets: dict[str, Any],
    manual_labels: dict[str, ttk.Label],
    auto_labels: dict[str, ttk.Label],
    prep_for_packaging: bool,
    existing_package_info_path: Optional[Path],
    allow_installer: bool,
    set_dirty: Callable[[bool], None],
) -> None:
    """Validate inputs and write PackageInfo.txt to disk.

    Troubleshooting: if saving fails, confirm file permissions and that
    the target folder exists and is writable.
    """
    installer_path: Optional[Path] = None
    if installer_path_str:
        installer_path = Path(installer_path_str).expanduser()
        if not installer_path.exists():
            messagebox.showerror("Missing Installer", "Please select a valid installer path.")
            return
    elif allow_installer and not existing_package_info_path:
        messagebox.showerror("Missing Installer", "Please select a valid installer path.")
        return
    elif not allow_installer and not existing_package_info_path:
        messagebox.showerror("Missing PackageInfo.txt", "Please select a valid PackageInfo.txt file.")
        return

    if not _validate_required_fields(
        installer_path is not None,
        vendor_name,
        software_name,
        software_version,
        software_architecture,
        sha1_hash,
        sha256_hash,
        manual_widgets,
        manual_labels,
        auto_labels,
    ):
        return

    if not vendor_name or vendor_name == UNKNOWN_VALUE:
        messagebox.showerror("Missing Vendor", "Please select a software vendor.")
        return
    if not software_name or software_name == UNKNOWN_VALUE:
        messagebox.showerror("Missing Software", "Please select a software name.")
        return

    if existing_package_info_path and prep_for_packaging:
        messagebox.showerror(
            "Prep Not Available",
            "Prep for packaging requires a new PackageInfo.txt file.",
        )
        return

    if existing_package_info_path:
        package_info_path = existing_package_info_path
        output_dir = package_info_path.parent
    else:
        if installer_path is None:
            messagebox.showerror("Missing Installer", "Please select a valid installer path.")
            return
        output_dir = installer_path.parent
        if prep_for_packaging:
            folder_name = _sanitize_folder_name(
                f"{vendor_name}_{software_name}_{software_version}-{software_architecture}"
            )
            output_dir = _get_package_prep_path() / folder_name
            output_dir.mkdir(parents=True, exist_ok=True)
        package_info_path = output_dir / "PackageInfo.txt"

    if package_info_path.exists():
        if not messagebox.askyesno(
            "Overwrite PackageInfo.txt",
            f"A PackageInfo.txt file already exists in:\n{output_dir}\n\nOverwrite?",
        ):
            return

    manual_values = _collect_manual_values(
        manual_widgets,
        installer_path_str,
        vendor_name,
        software_name,
        software_version,
        software_architecture,
    )
    change_date, change_analyst_id, change_analyst_name = _resolve_change_analyst_fields(
        existing_package_info_path
    )
    content = _build_package_info_content(
        manual_values=manual_values,
        vendor_name=vendor_name,
        software_name=software_name,
        software_version=software_version,
        software_architecture=software_architecture,
        sha1_hash=sha1_hash,
        sha256_hash=sha256_hash,
        change_date=change_date,
        change_analyst_id=change_analyst_id,
        change_analyst_name=change_analyst_name,
    )

    try:
        package_info_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        messagebox.showerror("Write Failed", f"Could not write PackageInfo.txt:\n{exc}")
        return

    if prep_for_packaging and installer_path is not None:
        target_path = output_dir / installer_path.name
        if installer_path.resolve() != target_path.resolve():
            try:
                shutil.move(str(installer_path), str(target_path))
            except OSError as exc:
                messagebox.showerror(
                    "Move Failed",
                    f"PackageInfo.txt was created, but the installer could not be moved:\n{exc}",
                )
                return

    messagebox.showinfo("Package Info Created", f"Saved:\n{package_info_path}")
    set_dirty(False)


def _collect_manual_values(
    manual_widgets: dict[str, Any],
    source_path: str,
    vendor_name: str,
    software_name: str,
    software_version: str,
    software_architecture: str,
) -> dict[str, str]:
    """Collect manual field values into a dictionary."""
    values: dict[str, str] = {}
    for label, widget in manual_widgets.items():
        if isinstance(widget, dict):
            kind = widget.get("kind")
            if kind == "dependencies":
                values[label] = _collect_dependency_values(
                    widget,
                    source_path,
                    vendor_name,
                    software_name,
                    software_version,
                    software_architecture,
                )
            elif kind == "multi_select":
                values[label] = _collect_multi_select_values(widget)
        elif isinstance(widget, tk.Text):
            values[label] = widget.get("1.0", tk.END).strip()
        else:
            values[label] = widget.get().strip()
    return values


def _build_package_info_content(
    manual_values: dict[str, str],
    vendor_name: str,
    software_name: str,
    software_version: str,
    software_architecture: str,
    sha1_hash: str,
    sha256_hash: str,
    change_date: str = "",
    change_analyst_id: str = "",
    change_analyst_name: str = "",
) -> str:
    """Build the PackageInfo.txt body, including a scan-details block."""
    scan_details = manual_values.get("Software Vulnerability Scan Results Details", "").strip()
    lines = [
        f"Request ID: {manual_values.get('Request ID', '')}",
        f"Requestor Name: {manual_values.get('Requestor Name', '')}",
    ]
    if change_date or change_analyst_id or change_analyst_name:
        lines.extend(
            [
                f"Change Date: {change_date}",
                f"Change Analyst ID: {change_analyst_id}",
                f"Change Analyst Name: {change_analyst_name}",
            ]
        )
    lines.extend(
        [
        f"Software Reference ID: {manual_values.get('Software Reference ID', '')}",
        f"Software Technology Owner ID: {manual_values.get('Software Technology Owner ID', '')}",
        f"Licensed Software Flag: {manual_values.get('Licensed Software Flag', '')}",
        f"Business Areas: {manual_values.get('Business Areas', '')}",
        f"Software Vendor: {vendor_name}",
        f"Software Name: {software_name}",
        f"Software Version: {software_version}",
        f"Software Architecture: {software_architecture}",
        f"Software SHA1 Hash: {sha1_hash}",
        f"Software SHA256 Hash: {sha256_hash}",
        f"Software Dependencies: {manual_values.get('Software Dependencies', '')}",
        f"Software Vulnerability Scan Results Status: {manual_values.get('Software Vulnerability Scan Results Status', '')}",
        ]
    )
    lines.append("##Software Vulnerability Scan Results Details Begin##")
    if scan_details:
        lines.extend(scan_details.splitlines())
    lines.append("##Software Vulnerability Scan Results Details End##")
    return "\n".join(lines)


def _apply_package_info_values(
    values: dict[str, str],
    vendor_var: tk.StringVar,
    software_var: tk.StringVar,
    version_var: tk.StringVar,
    architecture_var: tk.StringVar,
    sha1_var: tk.StringVar,
    sha256_var: tk.StringVar,
    manual_widgets: dict[str, Any],
) -> None:
    """Populate UI fields from a parsed PackageInfo.txt payload."""
    field_map = {
        "Software Vendor": vendor_var,
        "Software Name": software_var,
        "Software Version": version_var,
        "Software Architecture": architecture_var,
        "Software SHA1 Hash": sha1_var,
        "Software SHA256 Hash": sha256_var,
    }
    for key, var in field_map.items():
        value = values.get(key)
        if value:
            var.set(value)

    status_value = values.get("Software Vulnerability Scan Results Status")

    for label, widget in manual_widgets.items():
        value = values.get(label)
        if value is None:
            continue
        if label == "Software Vulnerability Scan Results Status" and isinstance(widget, ttk.Combobox):
            widget.set(value)
            continue
        if isinstance(widget, dict):
            kind = widget.get("kind")
            if kind == "dependencies":
                _populate_dependencies(widget, value)
            elif kind == "multi_select":
                _populate_multi_select(widget, value)
        elif isinstance(widget, tk.Text):
            widget.configure(state="normal")
            widget.delete("1.0", tk.END)
            widget.insert(tk.END, value)
            if not widget.winfo_ismapped():
                widget.configure(state="disabled")
        elif isinstance(widget, ttk.Combobox):
            widget.set(value)
        else:
            widget.delete(0, tk.END)
            widget.insert(0, value)

    status_widget = manual_widgets.get("Software Vulnerability Scan Results Status")
    if status_value and isinstance(status_widget, ttk.Combobox):
        status_widget.event_generate("<<ComboboxSelected>>")


def _sanitize_folder_name(value: str) -> str:
    """Sanitize a value for filesystem-safe folder names."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join("_" if ch in invalid_chars else ch for ch in value)
    return sanitized.strip() or "Package"


def _toggle_other_dependency(entry: ttk.Entry, other_var: tk.BooleanVar) -> None:
    """Enable/disable the Other dependency input based on the checkbox."""
    if other_var.get():
        entry.configure(state="normal")
        entry.focus_set()
    else:
        entry.delete(0, tk.END)
        entry.configure(state="disabled")


def _track_text_modified(widget: tk.Text, callback) -> callable:
    """Create a handler that fires when a Text widget is modified."""
    def _handler(_event=None) -> None:
        """Normalize Text change events into a single callback."""
        if widget.edit_modified():
            callback()
            widget.edit_modified(False)

    return _handler


def _collect_dependency_values(
    widget_parts: dict,
    source_path: str,
    vendor_name: str,
    software_name: str,
    software_version: str,
    software_architecture: str,
) -> str:
    """Collect dependency selections into a string for PackageInfo.txt."""
    listbox = widget_parts["listbox"]
    other_var = widget_parts["other_var"]
    other_entry = widget_parts["other_entry"]
    none_var = widget_parts.get("none_var")
    if none_var is not None and none_var.get():
        return "No dependencies"
    selections = [listbox.get(i) for i in listbox.curselection()]
    if other_var.get():
        other_value = other_entry.get().strip()
        if other_value:
            selections.append(other_value)
            _log_freeform_entry(
                "Software Dependencies (Other)",
                other_value,
                None,
                source_path,
                vendor_name,
                software_name,
                software_version,
                software_architecture,
            )
    return ", ".join(selections)


def _validate_required_fields(
    has_installer: bool,
    vendor_name: str,
    software_name: str,
    software_version: str,
    software_architecture: str,
    sha1_hash: str,
    sha256_hash: str,
    manual_widgets: dict[str, Any],
    manual_labels: dict[str, ttk.Label],
    auto_labels: dict[str, ttk.Label],
) -> bool:
    """Validate required fields and highlight any missing values."""
    missing_fields: list[str] = []

    _reset_label_states({**manual_labels, **auto_labels})

    auto_values = {
        "Software Vendor": vendor_name,
        "Software Name": software_name,
        "Software Version": software_version,
        "Software Architecture": software_architecture,
        "Software SHA1 Hash": sha1_hash,
        "Software SHA256 Hash": sha256_hash,
    }

    for label, value in auto_values.items():
        if label in {"Software SHA1 Hash", "Software SHA256 Hash"} and not has_installer:
            continue
        if not value or value.strip() == UNKNOWN_VALUE:
            missing_fields.append(label)
            _set_label_error(auto_labels.get(label))

    for label, widget in manual_widgets.items():
        label_widget = manual_labels.get(label)
        if isinstance(widget, dict):
            kind = widget.get("kind")
            if kind == "dependencies":
                if not _has_dependency_selection(widget):
                    missing_fields.append(label)
                    _set_label_error(label_widget)
            elif kind == "multi_select":
                if not _has_multi_select_selection(widget):
                    missing_fields.append(label)
                    _set_label_error(label_widget)
        elif isinstance(widget, tk.Text):
            if widget.winfo_ismapped() and not widget.get("1.0", tk.END).strip():
                missing_fields.append(label)
                _set_label_error(label_widget)
        else:
            if hasattr(widget, "winfo_ismapped") and not widget.winfo_ismapped():
                continue
            value = widget.get().strip()
            if not value:
                missing_fields.append(label)
                _set_label_error(label_widget)

    if not missing_fields:
        return True

    messagebox.showerror(
        "Missing Required Fields",
        "Please complete the following fields:\n" + "\n".join(missing_fields),
    )
    return False


def _has_dependency_selection(widget_parts: dict) -> bool:
    """Return True if a dependency selection is present."""
    listbox = widget_parts["listbox"]
    other_var = widget_parts["other_var"]
    other_entry = widget_parts["other_entry"]
    none_var = widget_parts.get("none_var")
    if none_var is not None and none_var.get():
        return True
    selections = listbox.curselection()
    if selections:
        return True
    if other_var.get() and other_entry.get().strip():
        return True
    return False


def _reset_label_states(labels: dict[str, ttk.Label]) -> None:
    """Clear error styling on all tracked labels."""
    for label in labels.values():
        _set_label_error(label, is_error=False)


def _set_label_error(label: Optional[ttk.Label], is_error: bool = True) -> None:
    """Apply or clear error styling on a label."""
    if label is None:
        return
    if is_error:
        label.configure(foreground="#c0392b", font=("Segoe UI", 11, "bold"))
    else:
        label.configure(foreground="#4b5a6a", font=("Segoe UI", 11))


def _populate_dependencies(widget_parts: dict, value: str) -> None:
    """Populate dependency widgets from a stored value string."""
    listbox = widget_parts["listbox"]
    other_var = widget_parts["other_var"]
    other_entry = widget_parts["other_entry"]
    none_var = widget_parts.get("none_var")
    other_check = widget_parts.get("other_check")
    none_check = widget_parts.get("none_check")

    listbox.selection_clear(0, tk.END)
    other_var.set(False)
    other_entry.configure(state="disabled")
    other_entry.delete(0, tk.END)
    if none_var is not None:
        none_var.set(False)
        if other_check is not None:
            other_check.configure(state="normal")
        if none_check is not None:
            none_check.configure(state="normal")
        listbox.configure(state="normal")

    selections = [item.strip() for item in value.split(",") if item.strip()]
    if not selections:
        return

    if selections == ["No dependencies"] and none_var is not None:
        none_var.set(True)
        _toggle_no_dependencies(
            listbox,
            other_check,
            other_entry,
            other_var,
            none_var,
        )
        return

    listbox_values = listbox.get(0, tk.END)
    unknown_values = []
    for item in selections:
        if item in listbox_values:
            listbox.selection_set(listbox_values.index(item))
        else:
            unknown_values.append(item)

    if unknown_values:
        other_var.set(True)
        other_entry.configure(state="normal")
        other_entry.insert(0, ", ".join(unknown_values))


def _collect_multi_select_values(widget_parts: dict) -> str:
    """Collect multi-select listbox values into a comma string."""
    listbox = widget_parts["listbox"]
    selections = [listbox.get(i) for i in listbox.curselection()]
    return ", ".join(selections)


def _has_multi_select_selection(widget_parts: dict) -> bool:
    """Return True if at least one multi-select item is chosen."""
    listbox = widget_parts["listbox"]
    return bool(listbox.curselection())


def _populate_multi_select(widget_parts: dict, value: str) -> None:
    """Populate multi-select listbox from a stored value string."""
    listbox = widget_parts["listbox"]
    listbox.selection_clear(0, tk.END)
    selections = [item.strip() for item in value.split(",") if item.strip()]
    if not selections:
        return
    listbox_values = listbox.get(0, tk.END)
    for item in selections:
        if item not in listbox_values:
            listbox.insert(tk.END, item)
            listbox_values = listbox.get(0, tk.END)
        listbox.selection_set(listbox_values.index(item))


def _toggle_no_dependencies(
    listbox: tk.Listbox,
    other_check: Optional[ttk.Checkbutton],
    other_entry: ttk.Entry,
    other_var: tk.BooleanVar,
    none_var: tk.BooleanVar,
) -> None:
    """Toggle the No dependencies mode and disable conflicting inputs."""
    if none_var.get():
        listbox.selection_clear(0, tk.END)
        listbox.configure(state="disabled")
        other_var.set(False)
        if other_check is not None:
            other_check.configure(state="disabled")
        other_entry.delete(0, tk.END)
        other_entry.configure(state="disabled")
    else:
        listbox.configure(state="normal")
        if other_check is not None:
            other_check.configure(state="normal")


def _resolve_change_analyst_fields(
    existing_package_info_path: Optional[Path],
) -> tuple[str, str, str]:
    """Return change analyst fields for new PackageInfo.txt creation."""
    if existing_package_info_path:
        try:
            values = parse_package_info_file(existing_package_info_path)
        except OSError:
            values = {}
        change_date = values.get("Change Date", "").strip()
        change_id = values.get("Change Analyst ID", "").strip()
        change_name = values.get("Change Analyst Name", "").strip()
        return change_date, change_id, change_name

    change_date = datetime.now().strftime("%m/%d/%Y")
    change_id = _get_netbios_name()
    change_name = _get_display_name(change_id)
    return change_date, change_id, change_name


def _get_netbios_name() -> str:
    """Return the user's NetBIOS/user name."""
    user_name = os.environ.get("USERNAME")
    if user_name:
        return user_name
    try:
        return os.getlogin()
    except OSError:
        return socket.gethostname() or UNKNOWN_VALUE


def _get_display_name(fallback: str) -> str:
    """Return a display name for the logged-in user."""
    for key in ("USERDISPLAYNAME", "DISPLAYNAME", "FULLNAME", "NAME"):
        value = os.environ.get(key)
        if value:
            return value
    return fallback


def _attach_tooltip(widget: tk.Widget, text: str) -> None:
    """Attach a simple hover tooltip to a widget."""
    tooltip = tk.Toplevel(widget)
    tooltip.withdraw()
    tooltip.overrideredirect(True)
    tooltip.attributes("-topmost", True)

    label = ttk.Label(
        tooltip,
        text=text,
        style="Body.TLabel",
        background="#fff7e6",
        foreground="#2b2b2b",
        padding=(8, 6),
        justify="left",
    )
    label.pack()

    def show_tooltip(event) -> None:
        """Display the tooltip near the hovered widget."""
        tooltip.update_idletasks()
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + 20
        tooltip.geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def hide_tooltip(_event) -> None:
        """Hide the tooltip when the cursor leaves."""
        tooltip.withdraw()

    widget.bind("<Enter>", show_tooltip)
    widget.bind("<Leave>", hide_tooltip)


def _resolve_path(path: str, base_dir: Path) -> Path:
    """Resolve relative paths against base_dir."""
    if "://" in path or Path(path).is_absolute():
        return Path(path)
    if path.replace("\\", "/").startswith("settings/"):
        return (base_dir.parent / path).resolve()
    return (base_dir / path).resolve()


def _get_package_prep_path() -> Path:
    """Resolve the Package_Prep path from settings.json."""
    settings_path = SETTINGS_DIR / "settings.json"
    try:
        raw = settings_path.read_text(encoding="utf-8")
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return SOFTWARE_PATHS_PACKAGE_PREP
    if not isinstance(settings, dict):
        return SOFTWARE_PATHS_PACKAGE_PREP
    value = settings.get("package_prep_path")
    if isinstance(value, str) and value.strip():
        return _resolve_path(value.strip(), SETTINGS_DIR)
    return SOFTWARE_PATHS_PACKAGE_PREP


def _bind_listbox_mousewheel(listbox: tk.Listbox) -> None:
    """Prevent listbox scrolling from bubbling to the main canvas."""
    def _on_mousewheel(event) -> str:
        listbox.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def _on_mousewheel_linux(event) -> str:
        if event.num == 4:
            listbox.yview_scroll(-1, "units")
        elif event.num == 5:
            listbox.yview_scroll(1, "units")
        return "break"

    listbox.bind("<MouseWheel>", _on_mousewheel)
    listbox.bind("<Button-4>", _on_mousewheel_linux)
    listbox.bind("<Button-5>", _on_mousewheel_linux)
