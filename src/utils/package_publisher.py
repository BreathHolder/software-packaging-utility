"""Publish packaged applications into the final structure."""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import SETTINGS_DIR, SOFTWARE_PATHS_PACKAGED
from src.utils.metadata_extractor import parse_package_info_file
from src.utils.ui_feedback import flash_label


def build_package_publisher_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Publish Package UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]

    header = ttk.Label(
        frame,
        text="Publish Package",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Validate a staged package and publish it with packager details.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    path_group = ttk.LabelFrame(frame, text="Staged Package", padding=16)
    path_group.pack(fill=tk.X, pady=(0, 20))
    path_group.columnconfigure(1, weight=1)

    staged_path_var = tk.StringVar()
    staged_label = ttk.Label(path_group, text="Staged package path", style="Body.TLabel")
    staged_label.grid(row=0, column=0, sticky="w", pady=4, padx=(0, 12))
    staged_entry = ttk.Entry(path_group, textvariable=staged_path_var, width=70)
    staged_entry.grid(row=0, column=1, sticky="we", pady=4)
    ttk.Button(
        path_group,
        text="Browse",
        command=lambda: _browse_staged_path(
            staged_path_var,
            staged_label,
            update_state,
        ),
    ).grid(row=0, column=2, padx=(12, 0), pady=4)

    structure_var = tk.StringVar(value="Structure: Unknown")
    structure_label = ttk.Label(path_group, textvariable=structure_var, style="Body.TLabel")
    structure_label.grid(row=1, column=1, sticky="w", pady=(8, 0))

    checks_group = ttk.LabelFrame(frame, text="Package Checks", padding=16)
    checks_group.pack(fill=tk.X, pady=(0, 20))
    checks_group.columnconfigure(1, weight=1)

    status_vars: dict[str, tk.StringVar] = {}
    status_labels: dict[str, ttk.Label] = {}

    def _add_check_row(row: int, label: str) -> None:
        ttk.Label(checks_group, text=label, style="Body.TLabel").grid(
            row=row, column=0, sticky="w", pady=4, padx=(0, 12)
        )
        value_var = tk.StringVar(value="✖ Missing")
        value_label = ttk.Label(
            checks_group,
            textvariable=value_var,
            style="Body.TLabel",
            foreground="#c0392b",
        )
        value_label.grid(row=row, column=1, sticky="w", pady=4)
        status_vars[label] = value_var
        status_labels[label] = value_label

    _add_check_row(0, "PackageInfo.txt")
    _add_check_row(1, "README.txt")
    _add_check_row(2, "binary_config.txt")
    _add_check_row(3, "prefetch.txt")
    _add_check_row(4, "Packaged_App.exe")

    app_group = ttk.LabelFrame(frame, text="Packaged App", padding=16)
    app_group.pack(fill=tk.X, pady=(0, 20))
    app_group.columnconfigure(1, weight=1)

    app_label = ttk.Label(app_group, text="Packaged_App.exe", style="Body.TLabel")
    app_label.grid(row=0, column=0, sticky="w", pady=4, padx=(0, 12))
    app_var = tk.StringVar()
    app_combo = ttk.Combobox(app_group, textvariable=app_var, state="readonly", width=60)
    app_combo.grid(row=0, column=1, sticky="we", pady=4)
    ttk.Button(
        app_group,
        text="Browse",
        command=lambda: _browse_packaged_app(app_var, update_state),
    ).grid(row=0, column=2, padx=(12, 0), pady=4)

    rename_var = tk.BooleanVar(value=True)
    rename_check = ttk.Checkbutton(
        app_group,
        text="Rename Packaged_App.exe on publish",
        variable=rename_var,
        command=lambda: update_state(),
    )
    rename_check.grid(row=1, column=1, sticky="w", pady=4)

    rename_reason_label = ttk.Label(
        app_group,
        text="Why are you not renaming the file?",
        style="Body.TLabel",
    )
    rename_reason_entry = ttk.Entry(app_group, width=70)

    preview_group = ttk.LabelFrame(frame, text="Publish Preview", padding=16)
    preview_group.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
    preview_group.columnconfigure(0, weight=1)

    preview_text = tk.Text(preview_group, height=8, wrap="word", state="disabled")
    preview_text.grid(row=0, column=0, sticky="nsew")
    _bind_text_mousewheel(preview_text)

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    status_var = tk.StringVar(value="")
    status_label = ttk.Label(
        actions,
        textvariable=status_var,
        style="Body.TLabel",
        foreground="#2e7d32",
    )
    status_label.pack(side=tk.LEFT, pady=(6, 0))
    publish_button = ttk.Button(actions, text="Publish Package", state="disabled")
    publish_button.pack(side=tk.RIGHT)

    def update_state() -> None:
        """Refresh detection and UI state."""
        staged_path = Path(staged_path_var.get().strip()).expanduser()
        detection = _detect_package(staged_path)
        _apply_detection(
            detection,
            structure_var,
            status_vars,
            status_labels,
            app_combo,
            app_var,
        )
        rename_enabled = rename_var.get()
        if rename_enabled:
            rename_reason_label.grid_remove()
            rename_reason_entry.grid_remove()
        else:
            rename_reason_label.grid(row=2, column=0, sticky="w", pady=4, padx=(0, 12))
            rename_reason_entry.grid(row=2, column=1, sticky="we", pady=4)
        _update_preview(
            detection,
            app_var.get(),
            rename_enabled,
            rename_reason_entry.get(),
            preview_text,
        )
        can_publish = detection["all_present"] and bool(app_var.get().strip())
        if not rename_enabled and not rename_reason_entry.get().strip():
            can_publish = False
        publish_button.configure(
            state="normal" if can_publish else "disabled",
            command=lambda: _publish_package(
                detection,
                app_var.get(),
                rename_enabled,
                rename_reason_entry.get(),
                staged_label,
                app_label,
                rename_reason_label,
                preview_text,
                status_var,
                staged_path_var,
                app_var,
                rename_var,
                rename_reason_entry,
                structure_var,
                status_vars,
                status_labels,
                app_combo,
                update_state,
            ),
        )

    app_combo.bind("<<ComboboxSelected>>", lambda _event: update_state())
    rename_reason_entry.bind("<KeyRelease>", lambda _event: update_state())
    update_state()

    return frame


def _browse_staged_path(
    staged_path_var: tk.StringVar,
    staged_label: ttk.Label,
    update_state,
) -> None:
    """Select the staged package directory."""
    folder_path = filedialog.askdirectory(title="Select Staged Package Folder")
    if not folder_path:
        return
    staged_path_var.set(folder_path)
    if not Path(folder_path).exists():
        flash_label(staged_label)
    update_state()


def _browse_packaged_app(app_var: tk.StringVar, update_state) -> None:
    """Select the packaged app executable manually."""
    file_path = filedialog.askopenfilename(
        title="Select Packaged App",
        filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
    )
    if not file_path:
        return
    app_var.set(file_path)
    update_state()


def _detect_package(staged_path: Path) -> dict[str, object]:
    """Detect package file locations and candidates."""
    detection: dict[str, object] = {
        "root": staged_path,
        "has_build_files": False,
        "package_info": None,
        "readme": None,
        "binary_config": None,
        "prefetch": None,
        "packaged_app_candidates": [],
        "source_binary": None,
        "package_info_values": {},
        "all_present": False,
    }
    if not staged_path.exists():
        return detection

    build_dir = staged_path / "build_files"
    detection["has_build_files"] = build_dir.is_dir()

    package_info_path = staged_path / "PackageInfo.txt"
    detection["package_info"] = package_info_path if package_info_path.exists() else None
    readme_path = staged_path / "README.txt"
    detection["readme"] = readme_path if readme_path.exists() else None
    prefetch_path = staged_path / "prefetch.txt"
    detection["prefetch"] = prefetch_path if prefetch_path.exists() else None

    if build_dir.is_dir():
        binary_config_path = build_dir / "binary_config.txt"
    else:
        binary_config_path = staged_path / "binary_config.txt"
    detection["binary_config"] = binary_config_path if binary_config_path.exists() else None

    package_info_values = {}
    if package_info_path.exists():
        try:
            package_info_values = parse_package_info_file(package_info_path)
        except Exception:
            package_info_values = {}
    detection["package_info_values"] = package_info_values

    source_binary = _extract_source_binary_name(package_info_values)
    detection["source_binary"] = source_binary

    candidates = []
    for item in staged_path.glob("*.exe"):
        if item.name.lower() == (source_binary or "").lower():
            continue
        candidates.append(item)
    detection["packaged_app_candidates"] = candidates

    detection["all_present"] = all(
        detection[key] is not None
        for key in ("package_info", "readme", "binary_config", "prefetch")
    )
    return detection


def _extract_source_binary_name(values: dict[str, str]) -> Optional[str]:
    """Best-effort extraction of source binary name from PackageInfo values."""
    for key in ("Source", "Installer path", "Installer Path", "Installer"):
        raw = values.get(key, "").strip()
        if raw:
            return Path(raw).name
    return None


def _apply_detection(
    detection: dict[str, object],
    structure_var: tk.StringVar,
    status_vars: dict[str, tk.StringVar],
    status_labels: dict[str, ttk.Label],
    app_combo: ttk.Combobox,
    app_var: tk.StringVar,
) -> None:
    """Apply detection results to the UI."""
    if not detection["root"] or not Path(detection["root"]).exists():
        structure_var.set("Structure: Unknown")
    else:
        structure = "Flat" if not detection["has_build_files"] else "Standard"
        structure_var.set(f"Structure: {structure}")

    _set_status(status_vars, status_labels, "PackageInfo.txt", detection["package_info"] is not None)
    _set_status(status_vars, status_labels, "README.txt", detection["readme"] is not None)
    _set_status(status_vars, status_labels, "binary_config.txt", detection["binary_config"] is not None)
    _set_status(status_vars, status_labels, "prefetch.txt", detection["prefetch"] is not None)

    candidates: list[Path] = detection.get("packaged_app_candidates", [])  # type: ignore[assignment]
    app_combo.configure(values=[str(path) for path in candidates])
    if candidates and not app_var.get():
        app_var.set(str(candidates[0]))
    _set_status(status_vars, status_labels, "Packaged_App.exe", bool(app_var.get().strip()))


def _set_status(
    status_vars: dict[str, tk.StringVar],
    status_labels: dict[str, ttk.Label],
    key: str,
    ok: bool,
) -> None:
    """Update status row with check or x."""
    value_var = status_vars[key]
    label = status_labels[key]
    if ok:
        value_var.set("✔ Present")
        label.configure(foreground="#2e7d32")
    else:
        value_var.set("✖ Missing")
        label.configure(foreground="#c0392b")


def _update_preview(
    detection: dict[str, object],
    app_path_str: str,
    rename_enabled: bool,
    rename_reason: str,
    preview_text: tk.Text,
) -> None:
    """Render a preview of PackageInfo updates and renaming."""
    values: dict[str, str] = detection.get("package_info_values", {})  # type: ignore[assignment]
    vendor = values.get("Software Vendor", "Unknown")
    software = values.get("Software Name", "Unknown")
    version = values.get("Software Version", "Unknown")
    architecture = values.get("Software Architecture", "Unknown")

    packager_netbios = _get_netbios_name()
    packager_name = _get_display_name(packager_netbios)
    publish_date = datetime.now().strftime("%m/%d/%Y")
    info_lines = [
        "### Packager Information ###",
        f"Publish Date: {publish_date}",
        f"Packager Netbios Name: {packager_netbios}",
        f"Packager Name: {packager_name}",
    ]
    business_area = _extract_business_area(Path(detection.get("root", "")))
    if business_area:
        info_lines.append(f"Business Area: {business_area}")
    if not rename_enabled and rename_reason.strip():
        info_lines.append(f"Rename Skipped Reason: {rename_reason.strip()}")

    rename_target = _build_renamed_app_name(vendor, software, version, architecture)
    preview_lines = [
        "PackageInfo.txt append:",
        *info_lines,
        "",
        f"Packaged_App.exe selected: {Path(app_path_str).name if app_path_str else 'Not selected'}",
        f"Rename target: {rename_target if rename_enabled else 'Renaming disabled'}",
    ]

    preview_text.configure(state="normal")
    preview_text.delete("1.0", tk.END)
    preview_text.insert(tk.END, "\n".join(preview_lines))
    preview_text.configure(state="disabled")


def _publish_package(
    detection: dict[str, object],
    app_path_str: str,
    rename_enabled: bool,
    rename_reason: str,
    staged_label: ttk.Label,
    app_label: ttk.Label,
    rename_reason_label: ttk.Label,
    preview_text: tk.Text,
    status_var: tk.StringVar,
    staged_path_var: tk.StringVar,
    app_var: tk.StringVar,
    rename_var: tk.BooleanVar,
    rename_reason_entry: ttk.Entry,
    structure_var: tk.StringVar,
    status_vars: dict[str, tk.StringVar],
    status_labels: dict[str, ttk.Label],
    app_combo: ttk.Combobox,
    update_state,
) -> None:
    """Finalize PackageInfo updates and rename the packaged app."""
    staged_path = detection.get("root")
    if not staged_path or not Path(staged_path).exists():
        flash_label(staged_label)
        return
    if not app_path_str.strip():
        flash_label(app_label)
        return
    if not rename_enabled and not rename_reason.strip():
        flash_label(rename_reason_label)
        return

    package_info_path: Optional[Path] = detection.get("package_info")  # type: ignore[assignment]
    if package_info_path is None or not package_info_path.exists():
        flash_label(staged_label)
        return

    values: dict[str, str] = detection.get("package_info_values", {})  # type: ignore[assignment]
    vendor = values.get("Software Vendor", "Unknown")
    software = values.get("Software Name", "Unknown")
    version = values.get("Software Version", "Unknown")
    architecture = values.get("Software Architecture", "Unknown")

    packager_netbios = _get_netbios_name()
    packager_name = _get_display_name(packager_netbios)
    publish_date = datetime.now().strftime("%m/%d/%Y")

    append_lines = [
        "",
        "### Packager Information ###",
        f"Publish Date: {publish_date}",
        f"Packager Netbios Name: {packager_netbios}",
        f"Packager Name: {packager_name}",
    ]
    business_area = _extract_business_area(Path(staged_path))
    if business_area:
        append_lines.append(f"Business Area: {business_area}")
    if not rename_enabled and rename_reason.strip():
        append_lines.append(f"Rename Skipped Reason: {rename_reason.strip()}")

    try:
        package_info_path.write_text(
            package_info_path.read_text(encoding="utf-8").rstrip() + "\n" + "\n".join(append_lines) + "\n",
            encoding="utf-8",
        )
    except OSError:
        flash_label(staged_label)
        return

    if rename_enabled:
        target_name = _build_renamed_app_name(vendor, software, version, architecture)
        source_path = Path(app_path_str)
        if source_path.exists():
            try:
                source_path.rename(source_path.with_name(target_name))
            except OSError:
                flash_label(app_label)
                return

    target_root = _migrate_to_packaged_path(
        Path(staged_path),
        vendor,
        software,
        staged_label,
    )
    if target_root is None:
        return
    status_var.set("Package Successfully Published")
    try:
        os.startfile(str(target_root.parent))
    except OSError:
        pass
    _reset_publish_form(
        preview_text,
        status_var,
        staged_path_var,
        app_var,
        rename_var,
        rename_reason_entry,
        structure_var,
        status_vars,
        status_labels,
        app_combo,
    )


def _reset_publish_form(
    preview_text: tk.Text,
    status_var: tk.StringVar,
    staged_path_var: tk.StringVar,
    app_var: tk.StringVar,
    rename_var: tk.BooleanVar,
    rename_reason_entry: ttk.Entry,
    structure_var: tk.StringVar,
    status_vars: dict[str, tk.StringVar],
    status_labels: dict[str, ttk.Label],
    app_combo: ttk.Combobox,
) -> None:
    """Clear publish form state after a successful publish."""
    preview_text.configure(state="normal")
    preview_text.delete("1.0", tk.END)
    preview_text.configure(state="disabled")
    status_var.set("Package Successfully Published")
    staged_path_var.set("")
    app_var.set("")
    rename_var.set(True)
    rename_reason_entry.delete(0, tk.END)
    structure_var.set("Structure: Unknown")
    app_combo.configure(values=[])
    for key, var in status_vars.items():
        var.set("✖ Missing")
        status_labels[key].configure(foreground="#c0392b")


def _build_renamed_app_name(vendor: str, software: str, version: str, architecture: str) -> str:
    """Build a sanitized filename for the packaged app."""
    vendor = _normalize_name_part(vendor)
    software = _normalize_name_part(software)
    version = _normalize_name_part(version)
    architecture = _normalize_name_part(architecture)
    base = f"{vendor}.{software}_{version}_{architecture}.exe"
    return _sanitize_filename(base)


def _normalize_name_part(value: str) -> str:
    """Remove spaces and punctuation from a name part."""
    return re.sub(r"[^A-Za-z0-9]", "", value or "")


def _sanitize_filename(value: str) -> str:
    """Sanitize a value for filesystem-safe filenames."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join("_" if ch in invalid_chars else ch for ch in value)
    return sanitized.strip() or "Packaged_App.exe"


def _bind_text_mousewheel(widget: tk.Text) -> None:
    """Prevent text scrolling from bubbling to the main canvas."""
    def _on_mousewheel(event) -> str:
        widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def _on_mousewheel_linux(event) -> str:
        if event.num == 4:
            widget.yview_scroll(-1, "units")
        elif event.num == 5:
            widget.yview_scroll(1, "units")
        return "break"

    widget.bind("<MouseWheel>", _on_mousewheel)
    widget.bind("<Button-4>", _on_mousewheel_linux)
    widget.bind("<Button-5>", _on_mousewheel_linux)


def _extract_business_area(staged_path: Path) -> str:
    """Extract business area from the staged folder name."""
    parts = staged_path.name.split("_")
    if len(parts) < 3:
        return ""
    return parts[-1].strip()


def _migrate_to_packaged_path(
    staged_path: Path,
    vendor_name: str,
    software_name: str,
    staged_label: ttk.Label,
) -> Optional[Path]:
    """Move the staged business-area folder into Packaged_Applications."""
    packaged_root = _get_packaged_applications_path()
    if not packaged_root:
        flash_label(staged_label)
        return None

    vendor = _sanitize_folder_name(vendor_name) or staged_path.parent.parent.name
    software = _sanitize_folder_name(software_name) or staged_path.parent.name
    version_area = staged_path.name
    target_root = packaged_root / vendor / software / version_area

    if target_root.exists():
        if not messagebox.askyesno(
            "Overwrite Packaged Application",
            f"The packaged path already exists:\n{target_root}\n\nOverwrite?",
        ):
            return None
        try:
            shutil.rmtree(target_root)
        except OSError:
            flash_label(staged_label)
            return None

    try:
        target_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staged_path), str(target_root))
    except OSError:
        flash_label(staged_label)
        return None
    return target_root


def _get_packaged_applications_path() -> Path:
    """Resolve the Packaged_Applications path from settings.json."""
    settings_path = SETTINGS_DIR / "settings.json"
    try:
        raw = settings_path.read_text(encoding="utf-8")
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return SOFTWARE_PATHS_PACKAGED
    if not isinstance(settings, dict):
        return SOFTWARE_PATHS_PACKAGED
    value = settings.get("packaged_applications_path")
    if isinstance(value, str) and value.strip():
        return _resolve_path(value.strip(), SETTINGS_DIR)
    return SOFTWARE_PATHS_PACKAGED


def _resolve_path(path: str, base_dir: Path) -> Path:
    """Resolve relative paths against base_dir."""
    if "://" in path or Path(path).is_absolute():
        return Path(path)
    if path.replace("\\", "/").startswith("settings/"):
        return (base_dir.parent / path).resolve()
    return (base_dir / path).resolve()


def _sanitize_folder_name(value: str) -> str:
    """Sanitize a value for filesystem-safe folder names."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join("_" if ch in invalid_chars else ch for ch in value)
    return sanitized.strip()


def _get_netbios_name() -> str:
    """Return the packager NetBIOS/user name."""
    return os.environ.get("USERNAME") or os.getlogin()


def _get_display_name(fallback: str) -> str:
    """Return a display name for the logged-in user."""
    for key in ("USERDISPLAYNAME", "DISPLAYNAME", "FULLNAME", "NAME"):
        value = os.environ.get(key)
        if value:
            return value
    return fallback
