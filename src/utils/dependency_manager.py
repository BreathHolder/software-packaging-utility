"""Dependency list manager UI and persistence helpers."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.config import FILE_PATHS_DEPENDENCY_NAMES, LOGGING_DIR, SETTINGS_DIR
from src.utils.logging_utils import append_csv_log


def build_dependency_manager_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Dependency Manager UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]

    header = ttk.Label(
        frame,
        text="Dependency Manager",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Maintain dependency names and paths stored in dependency_names.json.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    dependency_path = _get_dependency_path()
    settings_source = _get_settings_source()
    if settings_source == "github":
        warning = ttk.Label(
            frame,
            text="Settings source is set to GitHub. Updates here change the local file only.",
            style="Body.TLabel",
            font=("Segoe UI", 10),
            foreground="#8a6d3b",
        )
        warning.pack(anchor="w", pady=(0, 16))

    name_var = tk.StringVar()
    path_var = tk.StringVar()
    status_var = tk.StringVar(value="")

    def set_dirty(value: bool = True) -> None:
        """Mark the page dirty so tab switching warns about unsaved edits."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    def mark_dirty(_event=None) -> None:
        """Event handler that marks the page dirty."""
        set_dirty(True)

    list_group = ttk.LabelFrame(frame, text="Dependencies", padding=16)
    list_group.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
    list_group.columnconfigure(0, weight=1)

    listbox = tk.Listbox(list_group, height=10, exportselection=False)
    listbox.grid(row=0, column=0, sticky="nsew")
    _bind_listbox_mousewheel(listbox)
    scrollbar = ttk.Scrollbar(list_group, orient=tk.VERTICAL, command=listbox.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    listbox.configure(yscrollcommand=scrollbar.set)

    form_group = ttk.LabelFrame(frame, text="Details", padding=16)
    form_group.pack(fill=tk.X, pady=(0, 20))
    form_group.columnconfigure(1, weight=1)

    ttk.Label(form_group, text="Name", style="Body.TLabel").grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    name_entry = ttk.Entry(form_group, textvariable=name_var, width=50)
    name_entry.grid(row=0, column=1, sticky="we", pady=4)
    name_entry.bind("<KeyRelease>", mark_dirty)

    ttk.Label(form_group, text="Path", style="Body.TLabel").grid(
        row=1, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    path_entry = ttk.Entry(form_group, textvariable=path_var, width=50)
    path_entry.grid(row=1, column=1, sticky="we", pady=4)
    path_entry.bind("<KeyRelease>", mark_dirty)

    browse_button = ttk.Button(
        form_group,
        text="Browse",
        command=lambda: _browse_dependency_path(path_var, mark_dirty),
    )
    browse_button.grid(row=1, column=2, padx=(12, 0))

    actions = ttk.Frame(frame, style="Content.TFrame")
    actions.pack(fill=tk.X)
    status_label = ttk.Label(
        actions,
        textvariable=status_var,
        style="Body.TLabel",
        font=("Segoe UI", 10),
        foreground="#2e7d32",
    )
    status_label.pack(side=tk.LEFT, pady=(6, 0))

    dependencies: list[dict[str, str]] = _load_dependencies(dependency_path)
    _refresh_listbox(listbox, dependencies)

    def select_item(_event=None) -> None:
        """Populate fields when a dependency is selected."""
        selection = listbox.curselection()
        if not selection:
            return
        name = listbox.get(selection[0])
        match = next(
            (item for item in dependencies if item.get("name", "") == name),
            None,
        )
        name_var.set(name)
        path_var.set(match.get("path", "") if match else "")

    listbox.bind("<<ListboxSelect>>", select_item)

    def add_dependency() -> None:
        """Add a new dependency entry."""
        name = name_var.get().strip()
        path_value = path_var.get().strip()
        if not name:
            messagebox.showerror("Missing Name", "Dependency name is required.")
            return
        if any(item["name"].casefold() == name.casefold() for item in dependencies):
            messagebox.showerror(
                "Duplicate Name",
                "A dependency with that name already exists.",
            )
            return
        dependencies.append({"name": name, "path": path_value})
        _save_dependencies(dependency_path, dependencies)
        _log_dependency_change("add", name, path_value, "", "")
        _refresh_listbox(listbox, dependencies)
        set_dirty(False)

    def update_dependency() -> None:
        """Update the selected dependency entry."""
        selection = listbox.curselection()
        if not selection:
            messagebox.showerror("No Selection", "Select a dependency to update.")
            return
        index = selection[0]
        name = name_var.get().strip()
        path_value = path_var.get().strip()
        if not name:
            messagebox.showerror("Missing Name", "Dependency name is required.")
            return
        existing = dependencies[index]
        previous_name = existing.get("name", "")
        previous_path = existing.get("path", "")
        if (
            name.casefold() != previous_name.casefold()
            and any(item["name"].casefold() == name.casefold() for item in dependencies)
        ):
            messagebox.showerror(
                "Duplicate Name",
                "A dependency with that name already exists.",
            )
            return
        dependencies[index] = {"name": name, "path": path_value}
        _save_dependencies(dependency_path, dependencies)
        _log_dependency_change("update", name, path_value, previous_name, previous_path)
        _refresh_listbox(listbox, dependencies)
        listbox.selection_set(index)
        status_var.set("Update successful")
        set_dirty(False)

    def delete_dependency() -> None:
        """Delete the selected dependency entry."""
        selection = listbox.curselection()
        if not selection:
            messagebox.showerror("No Selection", "Select a dependency to delete.")
            return
        index = selection[0]
        item = dependencies[index]
        if not messagebox.askyesno(
            "Delete Dependency",
            f"Remove '{item.get('name', '')}'?",
        ):
            return
        dependencies.pop(index)
        _save_dependencies(dependency_path, dependencies)
        _log_dependency_change(
            "delete",
            item.get("name", ""),
            item.get("path", ""),
            item.get("name", ""),
            item.get("path", ""),
        )
        _refresh_listbox(listbox, dependencies)
        name_var.set("")
        path_var.set("")
        set_dirty(False)

    ttk.Button(actions, text="Add", command=add_dependency).pack(side=tk.LEFT)
    ttk.Button(actions, text="Update", command=update_dependency).pack(side=tk.LEFT, padx=8)
    ttk.Button(actions, text="Delete", command=delete_dependency).pack(side=tk.LEFT)

    return frame


def _get_dependency_path() -> Path:
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


def _get_settings_source() -> str:
    """Return the configured settings source (local or github)."""
    settings_path = SETTINGS_DIR / "settings.json"
    try:
        raw = settings_path.read_text(encoding="utf-8")
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return "local"
    if isinstance(settings, dict):
        value = settings.get("settings_source")
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return "local"


def _load_dependencies(path: Path) -> list[dict[str, str]]:
    """Load dependency entries from JSON, normalizing legacy formats."""
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    dependencies = []
    for item in data:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            path_value = str(item.get("path", "")).strip()
        else:
            name = str(item).strip()
            path_value = ""
        if name:
            dependencies.append({"name": name, "path": path_value})
    return dependencies


def _save_dependencies(path: Path, dependencies: list[dict[str, str]]) -> None:
    """Persist dependency entries to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sorted(dependencies, key=lambda item: item["name"].casefold())
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _refresh_listbox(listbox: tk.Listbox, dependencies: list[dict[str, str]]) -> None:
    """Refresh the listbox contents from dependencies."""
    listbox.delete(0, tk.END)
    for item in dependencies:
        listbox.insert(tk.END, item["name"])


def _browse_dependency_path(path_var: tk.StringVar, on_change=None) -> None:
    """Open a file or folder picker for dependency paths."""
    file_path = filedialog.askopenfilename(
        title="Select Dependency File",
        filetypes=[("All files", "*.*")],
    )
    if file_path:
        path_var.set(file_path)
        if on_change:
            on_change()
        return
    folder_path = filedialog.askdirectory(title="Select Dependency Folder")
    if folder_path:
        path_var.set(folder_path)
        if on_change:
            on_change()


def _log_dependency_change(
    action: str,
    name: str,
    path_value: str,
    previous_name: str,
    previous_path: str,
) -> None:
    """Append dependency changes to a CSV log for review."""
    log_path = LOGGING_DIR / "dependency_changes.csv"
    append_csv_log(
        log_path,
        header=[
            "timestamp",
            "action",
            "name",
            "path",
            "previous_name",
            "previous_path",
        ],
        row=[
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            action,
            name,
            path_value,
            previous_name,
            previous_path,
        ],
    )


def _resolve_path(path: str, base_dir: Path) -> Path:
    """Resolve relative paths against base_dir."""
    if "://" in path or Path(path).is_absolute():
        return Path(path)
    if path.replace("\\", "/").startswith("settings/"):
        return (base_dir.parent / path).resolve()
    return (base_dir / path).resolve()


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
