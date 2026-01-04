"""Package staging builder UI and filesystem actions."""

from __future__ import annotations

import json
import os
import shutil
import socket
import hashlib
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import (
    FILE_PATHS_BUSINESS_AREAS,
    FILE_PATHS_DEPENDENCY_NAMES,
    SETTINGS_DIR,
    SOFTWARE_PATHS_STAGING,
)
from src.utils.metadata_extractor import UNKNOWN_VALUE, parse_package_info_file


def build_package_staging_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Package Staging Builder UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]

    def set_dirty(value: bool = True) -> None:
        """Mark the page dirty so tab switching warns about unsaved edits."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    def mark_dirty(_event=None) -> None:
        """Event handler that marks the page dirty."""
        set_dirty(True)

    dependency_names_path = _get_dependency_names_path()
    dependency_options = _load_picklist(dependency_names_path)
    dependency_entries = _load_dependency_entries(dependency_names_path)
    business_area_options = _load_picklist(FILE_PATHS_BUSINESS_AREAS)
    package_info_values: dict[str, str] = {}

    header = ttk.Label(
        frame,
        text="Package Staging Builder",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Load a PackageInfo.txt and installer, review details, update dependencies, and build staging.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    source_group = ttk.LabelFrame(frame, text="Source Files", padding=16)
    source_group.pack(fill=tk.X, pady=(0, 20))
    source_group.columnconfigure(1, weight=1)

    package_info_var = tk.StringVar()
    installer_var = tk.StringVar()
    hash_status_var = tk.StringVar(value="SHA1/SHA256: Awaiting PackageInfo.txt + installer.")

    ttk.Label(source_group, text="PackageInfo path", style="Body.TLabel").grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    package_info_entry = ttk.Entry(source_group, textvariable=package_info_var, width=70)
    package_info_entry.grid(row=0, column=1, sticky="we", pady=4)

    ttk.Label(source_group, text="Installer path", style="Body.TLabel").grid(
        row=1, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    installer_entry = ttk.Entry(source_group, textvariable=installer_var, width=70)
    installer_entry.grid(row=1, column=1, sticky="we", pady=4)

    hash_status_label = ttk.Label(
        source_group,
        textvariable=hash_status_var,
        style="Body.TLabel",
        font=("Segoe UI", 11, "bold"),
        foreground="#4b5a6a",
        wraplength=680,
        justify="left",
    )
    hash_status_label.grid(row=2, column=1, sticky="w", pady=(8, 0))

    ttk.Button(
        source_group,
        text="Browse",
        command=lambda: (
            _browse_package_info(
                package_info_var,
                package_info_values,
                info_vars,
                dependencies_widget,
                business_list,
            ),
            _update_hash_status(
                installer_var.get(),
                package_info_values,
                hash_status_var,
                hash_status_label,
            ),
        ),
    ).grid(row=0, column=2, padx=(12, 0), pady=4)

    ttk.Button(
        source_group,
        text="Browse",
        command=lambda: (
            _browse_installer(installer_var),
            _update_hash_status(
                installer_var.get(),
                package_info_values,
                hash_status_var,
                hash_status_label,
            ),
        ),
    ).grid(row=1, column=2, padx=(12, 0), pady=4)

    info_group = ttk.LabelFrame(frame, text="Package Details (read-only)", padding=16)
    info_group.pack(fill=tk.X, pady=(0, 20))
    info_group.columnconfigure(1, weight=1)

    info_fields = [
        "Request ID",
        "Requestor Name",
        "Software Reference ID",
        "Software Technology Owner ID",
        "Licensed Software Flag",
        "Software Vendor",
        "Software Name",
        "Software Version",
        "Software Architecture",
        "Software SHA1 Hash",
        "Software SHA256 Hash",
        "Software Vulnerability Scan Results Status",
    ]
    info_vars: dict[str, tk.StringVar] = {}
    for row, label in enumerate(info_fields):
        ttk.Label(info_group, text=label, style="Body.TLabel").grid(
            row=row, column=0, sticky="w", pady=4, padx=(0, 12)
        )
        value_var = tk.StringVar(value="")
        entry = ttk.Entry(info_group, textvariable=value_var, width=60, state="readonly")
        entry.grid(row=row, column=1, sticky="we", pady=4)
        info_vars[label] = value_var

    packaging_group = ttk.LabelFrame(frame, text="Packaging Details", padding=16)
    packaging_group.pack(fill=tk.X, pady=(0, 20))
    packaging_group.columnconfigure(1, weight=1)

    ttk.Label(packaging_group, text="Business Areas", style="Body.TLabel").grid(
        row=0, column=0, sticky="nw", pady=4, padx=(0, 12)
    )
    business_list = tk.Listbox(
        packaging_group,
        selectmode=tk.MULTIPLE,
        height=4,
        exportselection=False,
        state="disabled",
    )
    for option in business_area_options:
        business_list.insert(tk.END, option)
    business_list.grid(row=0, column=1, sticky="we", pady=4)
    _bind_listbox_mousewheel(business_list)

    dependencies_group = ttk.LabelFrame(frame, text="Dependencies", padding=16)
    dependencies_group.pack(fill=tk.X, pady=(0, 20))
    dependencies_group.columnconfigure(0, weight=1)

    dependencies_frame = ttk.Frame(dependencies_group)
    dependencies_frame.grid(row=0, column=0, sticky="we")
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
    _bind_listbox_mousewheel(dependencies_list)

    other_var = tk.BooleanVar(value=False)
    other_entry = ttk.Entry(dependencies_frame, width=48, state="disabled")

    other_check = ttk.Checkbutton(
        dependencies_frame,
        text="Other",
        variable=other_var,
        command=lambda: (_toggle_other_dependency(other_entry, other_var), set_dirty()),
    )
    other_check.grid(row=1, column=0, sticky="w", pady=(6, 0))

    none_var = tk.BooleanVar(value=False)
    none_check = ttk.Checkbutton(
        dependencies_frame,
        text="No dependencies",
        variable=none_var,
    )
    none_check.configure(
        command=lambda: (
            _toggle_no_dependencies(
                dependencies_list,
                other_check,
                other_entry,
                other_var,
                none_var,
            ),
            set_dirty(),
        )
    )
    none_check.grid(row=1, column=0, sticky="e", pady=(6, 0))

    other_entry.grid(row=2, column=0, sticky="we", pady=(4, 0))

    dependencies_list.bind("<<ListboxSelect>>", mark_dirty)
    other_entry.bind("<KeyRelease>", mark_dirty)

    dependencies_widget = {
        "listbox": dependencies_list,
        "other_var": other_var,
        "other_entry": other_entry,
        "none_var": none_var,
        "other_check": other_check,
        "none_check": none_check,
    }

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    flat_build_var = tk.BooleanVar(value=False)
    flat_build_check = ttk.Checkbutton(
        actions,
        text="Flat Files for Build Package",
        variable=flat_build_var,
    )
    flat_build_check.pack(side=tk.LEFT)
    create_button = ttk.Button(
        actions,
        text="Create Package in Staging",
        command=lambda: _create_staging_package(
            installer_var.get(),
            package_info_var.get(),
            package_info_values,
            dependency_entries,
            dependencies_widget,
            flat_build_var.get(),
            set_dirty,
        ),
    )
    create_button.pack(side=tk.RIGHT)

    return frame


def _browse_package_info(
    package_info_var: tk.StringVar,
    package_info_values: dict[str, str],
    info_vars: dict[str, tk.StringVar],
    dependencies_widget: dict[str, Any],
    business_list: tk.Listbox,
) -> None:
    """Select and parse a PackageInfo.txt file."""
    file_path = filedialog.askopenfilename(
        title="Select PackageInfo.txt",
        filetypes=[("PackageInfo.txt", "PackageInfo.txt"), ("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not file_path:
        return
    package_info_var.set(file_path)
    try:
        values = parse_package_info_file(Path(file_path))
    except Exception as exc:
        messagebox.showerror(
            "PackageInfo Load Failed",
            f"Could not read PackageInfo.txt:\n{exc}",
        )
        return

    package_info_values.clear()
    package_info_values.update(values)

    for key, var in info_vars.items():
        var.set(values.get(key, ""))

    _populate_dependencies(dependencies_widget, values.get("Software Dependencies", ""))
    _populate_business_areas(business_list, values.get("Business Areas", ""))


def _browse_installer(installer_var: tk.StringVar) -> None:
    """Select an installer file."""
    file_path = filedialog.askopenfilename(
        title="Select Installer",
        filetypes=[("Installer files", "*.msi *.exe"), ("All files", "*.*")],
    )
    if not file_path:
        return
    installer_var.set(file_path)


def _update_hash_status(
    installer_path_str: str,
    package_info_values: dict[str, str],
    status_var: tk.StringVar,
    status_label: ttk.Label,
) -> None:
    """Compare installer hashes to PackageInfo.txt values and update status text."""
    if not installer_path_str or not package_info_values:
        status_var.set("SHA1/SHA256: Awaiting PackageInfo.txt + installer.")
        status_label.configure(foreground="#4b5a6a")
        return

    installer_path = Path(installer_path_str).expanduser()
    if not installer_path.exists():
        status_var.set("SHA1/SHA256: Installer not found.")
        status_label.configure(foreground="#c0392b")
        return

    expected_sha1 = package_info_values.get("Software SHA1 Hash", "").strip()
    expected_sha256 = package_info_values.get("Software SHA256 Hash", "").strip()
    if not expected_sha1 or not expected_sha256:
        status_var.set("SHA1/SHA256: PackageInfo.txt is missing hash values.")
        status_label.configure(foreground="#c0392b")
        return

    try:
        actual_sha1 = _hash_file(installer_path, "sha1")
        actual_sha256 = _hash_file(installer_path, "sha256")
    except OSError as exc:
        status_var.set(f"SHA1/SHA256: Could not read installer ({exc}).")
        status_label.configure(foreground="#c0392b")
        return

    if actual_sha1 == expected_sha1 and actual_sha256 == expected_sha256:
        status_var.set("SHA1/SHA256: Installer hashes match PackageInfo.txt.")
        status_label.configure(foreground="#2e7d32")
    else:
        status_var.set(
            "SHA1/SHA256 mismatch. New scan and rebuild of PackageInfo.txt required."
        )
        status_label.configure(foreground="#c0392b")


def _create_staging_package(
    installer_path_str: str,
    package_info_path_str: str,
    package_info_values: dict[str, str],
    dependency_entries: dict[str, str],
    dependencies_widget: dict[str, Any],
    flat_build: bool,
    set_dirty,
) -> None:
    """Build the staging directory structure with provided inputs."""
    installer_path = Path(installer_path_str).expanduser() if installer_path_str else None
    if installer_path is None or not installer_path.exists():
        messagebox.showerror("Missing Installer", "Please select a valid installer path.")
        return
    package_info_path = Path(package_info_path_str).expanduser() if package_info_path_str else None
    if package_info_path is None or not package_info_path.exists():
        messagebox.showerror("Missing PackageInfo", "Please select a valid PackageInfo.txt file.")
        return
    if not package_info_values:
        messagebox.showerror("Missing Package Info", "Please load PackageInfo.txt before continuing.")
        return

    dependencies_value = _collect_dependency_value(dependencies_widget)
    if dependencies_value is None:
        messagebox.showerror("Missing Dependencies", "Please select a dependency option.")
        return

    vendor_name = package_info_values.get("Software Vendor", "").strip()
    software_name = package_info_values.get("Software Name", "").strip()
    software_version = package_info_values.get("Software Version", "").strip()
    software_architecture = package_info_values.get("Software Architecture", "").strip()
    if not all([vendor_name, software_name, software_version, software_architecture]):
        messagebox.showerror("Missing Package Info", "PackageInfo.txt is missing required software details.")
        return

    business_areas = _split_business_areas(
        package_info_values.get("Business Areas", "")
    )
    if not business_areas:
        messagebox.showerror(
            "Missing Business Areas",
            "PackageInfo.txt is missing Business Areas.",
        )
        return

    staging_root = _get_package_staging_path()
    netbios_name = _sanitize_folder_name(_get_netbios_name())

    package_info_text = package_info_path.read_text(encoding="utf-8")
    updated_text = _update_dependencies_in_package_info(package_info_text, dependencies_value)

    base_root = (
        staging_root
        / netbios_name
        / _sanitize_folder_name(vendor_name)
        / _sanitize_folder_name(software_name)
    )

    missing_total: set[str] = set()
    for area in business_areas:
        version_arch_lob = _sanitize_folder_name(
            f"{software_version}_{software_architecture}_{area}"
        )
        target_root = base_root / version_arch_lob
        build_files_dir = target_root / "build_files"
        dependencies_dir = target_root / "dependencies"

        if target_root.exists() and any(target_root.iterdir()):
            if not messagebox.askyesno(
                "Overwrite Existing Package",
                f"The staging folder already has content:\n{target_root}\n\nOverwrite?",
            ):
                return

        try:
            target_root.mkdir(parents=True, exist_ok=True)
            if not flat_build:
                build_files_dir.mkdir(parents=True, exist_ok=True)
            dependencies_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("Create Failed", f"Could not create staging directories:\n{exc}")
            return

        try:
            install_target = target_root if flat_build else build_files_dir
            shutil.copy2(installer_path, install_target / installer_path.name)
        except OSError as exc:
            messagebox.showerror("Copy Failed", f"Could not copy installer:\n{exc}")
            return

        try:
            (target_root / "PackageInfo.txt").write_text(updated_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Write Failed", f"Could not write PackageInfo.txt:\n{exc}")
            return

        try:
            (dependencies_dir / "dependencies.txt").write_text(
                _format_dependencies_for_file(dependencies_value),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("Write Failed", f"Could not write dependencies.txt:\n{exc}")
            return

        missing = _copy_dependency_assets(
            dependencies_value,
            dependency_entries,
            dependencies_dir,
        )
        missing_total.update(missing)

    if missing_total:
        messagebox.showwarning(
            "Missing Dependency Files",
            "These dependencies do not have valid paths:\n"
            + "\n".join(sorted(missing_total)),
        )

    scan_status = package_info_values.get(
        "Software Vulnerability Scan Results Status",
        "",
    ).strip()
    if scan_status == "Scan results NOT found or vulnerabilities found NOT accepted":
        messagebox.showwarning(
            "Packaging Not Authorized",
            "Not authorized for packaging without a clean or accepted scan.",
        )
    messagebox.showinfo(
        "Package Staging Created",
        f"Created staging package:\n{target_root}",
    )
    set_dirty(False)


def _collect_dependency_value(widget_parts: dict[str, Any]) -> str | None:
    """Return a dependency string or None if nothing is selected."""
    if not _has_dependency_selection(widget_parts):
        return None

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

    return ", ".join(selections)


def _format_dependencies_for_file(dependencies_value: str) -> str:
    """Format dependencies for dependencies.txt."""
    if dependencies_value.strip() == "No dependencies":
        return "No dependencies"
    return "\n".join([item.strip() for item in dependencies_value.split(",") if item.strip()])


def _copy_dependency_assets(
    dependencies_value: str,
    dependency_entries: dict[str, str],
    dependencies_dir: Path,
) -> list[str]:
    """Copy dependency installer files into the dependencies folder."""
    if dependencies_value.strip() == "No dependencies":
        return []
    missing: list[str] = []
    for name in _split_dependency_names(dependencies_value):
        path_str = dependency_entries.get(name, "").strip()
        if not path_str:
            missing.append(name)
            continue
        dep_path = Path(path_str)
        if not dep_path.exists():
            missing.append(name)
            continue
        try:
            if dep_path.is_dir():
                shutil.copytree(
                    dep_path,
                    dependencies_dir / dep_path.name,
                    dirs_exist_ok=True,
                )
            else:
                shutil.copy2(dep_path, dependencies_dir / dep_path.name)
        except OSError:
            missing.append(name)
    return missing


def _split_dependency_names(value: str) -> list[str]:
    """Split dependency values into a normalized list."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_dependency_entries(path: Path) -> dict[str, str]:
    """Load dependency entries into a name -> path map."""
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, list):
        return {}
    entries: dict[str, str] = {}
    for item in data:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            path_value = str(item.get("path", "")).strip()
        else:
            name = str(item).strip()
            path_value = ""
        if name:
            entries[name] = path_value
    return entries


def _update_dependencies_in_package_info(contents: str, dependencies_value: str) -> str:
    """Update the Software Dependencies line in PackageInfo.txt content."""
    lines = contents.splitlines()
    updated = []
    replaced = False
    for line in lines:
        if line.strip().startswith("Software Dependencies:"):
            updated.append(f"Software Dependencies: {dependencies_value}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(f"Software Dependencies: {dependencies_value}")
    return "\n".join(updated)


def _populate_dependencies(widget_parts: dict[str, Any], value: str) -> None:
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


def _toggle_other_dependency(entry: ttk.Entry, other_var: tk.BooleanVar) -> None:
    """Enable/disable the Other dependency input based on the checkbox."""
    if other_var.get():
        entry.configure(state="normal")
        entry.focus_set()
    else:
        entry.delete(0, tk.END)
        entry.configure(state="disabled")


def _toggle_no_dependencies(
    listbox: tk.Listbox,
    other_check: ttk.Checkbutton | None,
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


def _has_dependency_selection(widget_parts: dict[str, Any]) -> bool:
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


def _get_dependency_names_path() -> Path:
    """Resolve the dependency_names.json path from settings.json."""
    settings_path = SETTINGS_DIR / "settings.json"
    try:
        raw = settings_path.read_text(encoding="utf-8")
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return FILE_PATHS_DEPENDENCY_NAMES
    if not isinstance(settings, dict):
        return FILE_PATHS_DEPENDENCY_NAMES
    value = settings.get("dependency_names_path")
    if isinstance(value, str) and value.strip():
        return _resolve_path(value.strip(), SETTINGS_DIR)
    return FILE_PATHS_DEPENDENCY_NAMES


def _get_package_staging_path() -> Path:
    """Resolve the Package_Staging path from settings.json."""
    settings_path = SETTINGS_DIR / "settings.json"
    try:
        raw = settings_path.read_text(encoding="utf-8")
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return SOFTWARE_PATHS_STAGING
    if not isinstance(settings, dict):
        return SOFTWARE_PATHS_STAGING
    value = settings.get("package_staging_path")
    if isinstance(value, str) and value.strip():
        return _resolve_path(value.strip(), SETTINGS_DIR)
    return SOFTWARE_PATHS_STAGING


def _resolve_path(path: str, base_dir: Path) -> Path:
    """Resolve relative paths against base_dir."""
    if "://" in path or Path(path).is_absolute():
        return Path(path)
    if path.replace("\\", "/").startswith("settings/"):
        return (base_dir.parent / path).resolve()
    return (base_dir / path).resolve()


def _get_netbios_name() -> str:
    """Return the packager NetBIOS/user name for staging folder creation."""
    user_name = os.environ.get("USERNAME")
    if user_name:
        return user_name
    try:
        return os.getlogin()
    except OSError:
        return socket.gethostname() or "UNKNOWN_HOST"


def _sanitize_folder_name(value: str) -> str:
    """Sanitize a value for filesystem-safe folder names."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join("_" if ch in invalid_chars else ch for ch in value)
    return sanitized.strip() or UNKNOWN_VALUE


def _split_business_areas(value: str) -> list[str]:
    """Split Business Areas into a normalized list."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _populate_business_areas(listbox: tk.Listbox, value: str) -> None:
    """Populate a read-only Business Areas listbox from stored values."""
    selections = [item.strip() for item in value.split(",") if item.strip()]
    listbox.configure(state="normal")
    listbox.selection_clear(0, tk.END)
    if selections:
        listbox_values = listbox.get(0, tk.END)
        for item in selections:
            if item not in listbox_values:
                listbox.insert(tk.END, item)
                listbox_values = listbox.get(0, tk.END)
            listbox.selection_set(listbox_values.index(item))
    listbox.configure(state="disabled")


def _hash_file(path: Path, algorithm: str) -> str:
    """Compute a hash for a file."""
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()




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
