"""Package documentation builder UI for binary_config.txt and README.txt."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.utils.metadata_extractor import parse_package_info_file
from src.utils.ui_feedback import flash_label


def build_package_documentation_frame(parent: tk.Widget) -> ttk.Frame:
    """Create the Package Doc Builder UI frame."""
    frame = ttk.Frame(parent, style="Content.TFrame")
    frame.is_dirty = False  # type: ignore[attr-defined]
    package_info_values: dict[str, str] = {}
    simple_install_var = tk.BooleanVar(value=False)
    packaged_app_var = tk.StringVar()

    def set_dirty(value: bool = True) -> None:
        """Mark the page dirty so tab switching warns about unsaved edits."""
        frame.is_dirty = value  # type: ignore[attr-defined]

    header = ttk.Label(
        frame,
        text="Package Doc Builder",
        style="Header.TLabel",
        font=("Segoe UI", 20, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    subtext = ttk.Label(
        frame,
        text="Build binary_config.txt and README.txt from PackageInfo.txt.",
        style="Body.TLabel",
        font=("Segoe UI", 11),
    )
    subtext.pack(anchor="w", pady=(0, 24))

    source_group = ttk.LabelFrame(frame, text="File Paths", padding=16)
    source_group.pack(fill=tk.X, pady=(0, 20))
    source_group.columnconfigure(1, weight=1)

    package_info_var = tk.StringVar()
    header_preview_var = tk.StringVar(value="")

    package_info_label = ttk.Label(
        source_group,
        text="PackageInfo path",
        style="Body.TLabel",
        font=("Segoe UI", 11, "bold"),
    )
    package_info_label.grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    package_info_entry = ttk.Entry(source_group, textvariable=package_info_var, width=70)
    package_info_entry.grid(row=0, column=1, sticky="we", pady=4)
    packaged_app_warning_var = tk.StringVar(value="")
    ttk.Button(
        source_group,
        text="Browse",
        command=lambda: _browse_package_info(
            package_info_var,
            package_info_values,
            header_preview_var,
            license_var,
            package_info_label,
            packaged_app_var,
            packaged_app_label,
            packaged_app_warning_var,
        ),
    ).grid(row=0, column=2, padx=(12, 0), pady=4)
    packaged_app_label = ttk.Label(
        source_group,
        text="Packaged_App.exe path",
        style="Body.TLabel",
        font=("Segoe UI", 11, "bold"),
    )
    packaged_app_label.grid(row=2, column=0, sticky="w", pady=(12, 4), padx=(0, 12))
    packaged_app_entry = ttk.Entry(source_group, textvariable=packaged_app_var, width=70)
    packaged_app_entry.grid(row=2, column=1, sticky="we", pady=(12, 4))
    packaged_app_warning = ttk.Label(
        source_group,
        textvariable=packaged_app_warning_var,
        style="Body.TLabel",
        foreground="#c0392b",
        wraplength=680,
        justify="left",
    )
    packaged_app_warning.grid(row=3, column=1, sticky="w", pady=(4, 0))
    ttk.Button(
        source_group,
        text="Browse",
        command=lambda: _browse_packaged_app(
            packaged_app_var,
            simple_install_var,
            additional_text,
            package_info_values,
            packaged_app_label,
            packaged_app_warning_var,
        ),
    ).grid(row=2, column=2, padx=(12, 0), pady=(12, 4))
    packaged_app_entry.bind(
        "<KeyRelease>",
        lambda _event: _update_packaged_app_warning(
            packaged_app_var.get(),
            package_info_values,
            packaged_app_label,
            packaged_app_warning_var,
        ),
    )

    header_preview = ttk.Label(
        source_group,
        textvariable=header_preview_var,
        style="Body.TLabel",
        justify="left",
    )
    header_preview.grid(row=4, column=1, sticky="w", pady=(8, 0))

    binary_group = ttk.LabelFrame(frame, text="binary_config.txt", padding=16)
    binary_group.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
    binary_group.columnconfigure(0, weight=1)

    binary_config_var = tk.StringVar(value="")
    binary_config_details_var = tk.StringVar(value="")
    binary_args_var = tk.StringVar(value="")
    binary_args_details_var = tk.StringVar(value="")

    binary_guidance = ttk.LabelFrame(binary_group, text="Guided Instructions", padding=12)
    binary_guidance.grid(row=0, column=0, sticky="we", pady=(0, 12))
    binary_guidance.columnconfigure(1, weight=1)

    ttk.Label(
        binary_guidance,
        text="Special configurations required?",
        style="Body.TLabel",
    ).grid(row=0, column=0, sticky="w", pady=4, padx=(0, 12))
    binary_config_frame = ttk.Frame(binary_guidance)
    binary_config_frame.grid(row=0, column=1, sticky="w")
    ttk.Radiobutton(
        binary_config_frame,
        text="Yes",
        value="Yes",
        variable=binary_config_var,
    ).pack(side=tk.LEFT)
    ttk.Radiobutton(
        binary_config_frame,
        text="No",
        value="No",
        variable=binary_config_var,
    ).pack(side=tk.LEFT, padx=(12, 0))

    binary_config_label = ttk.Label(
        binary_guidance,
        text="Provide the special configuration details",
        style="Body.TLabel",
    )
    binary_config_entry = ttk.Entry(
        binary_guidance,
        textvariable=binary_config_details_var,
        width=70,
    )

    ttk.Label(
        binary_guidance,
        text="Arguments required for install?",
        style="Body.TLabel",
    ).grid(row=2, column=0, sticky="w", pady=4, padx=(0, 12))
    binary_args_frame = ttk.Frame(binary_guidance)
    binary_args_frame.grid(row=2, column=1, sticky="w")
    ttk.Radiobutton(
        binary_args_frame,
        text="Yes",
        value="Yes",
        variable=binary_args_var,
    ).pack(side=tk.LEFT)
    ttk.Radiobutton(
        binary_args_frame,
        text="No",
        value="No",
        variable=binary_args_var,
    ).pack(side=tk.LEFT, padx=(12, 0))

    binary_args_label = ttk.Label(
        binary_guidance,
        text="Provide the argument details",
        style="Body.TLabel",
    )
    binary_args_entry = ttk.Entry(
        binary_guidance,
        textvariable=binary_args_details_var,
        width=70,
    )

    def refresh_binary_guidance(*_args) -> None:
        """Show/hide binary_config guided prompts."""
        if binary_config_var.get() == "Yes":
            binary_config_label.grid(row=1, column=0, sticky="w", pady=4, padx=(0, 12))
            binary_config_entry.grid(row=1, column=1, sticky="we", pady=4)
            binary_config_entry.configure(state="normal")
            binary_config_entry.focus_set()
        else:
            binary_config_details_var.set("")
            binary_config_label.grid_remove()
            binary_config_entry.grid_remove()
            binary_config_entry.configure(state="disabled")

        if binary_args_var.get() == "Yes":
            binary_args_label.grid(row=3, column=0, sticky="w", pady=4, padx=(0, 12))
            binary_args_entry.grid(row=3, column=1, sticky="we", pady=4)
            binary_args_entry.configure(state="normal")
            binary_args_entry.focus_set()
        else:
            binary_args_details_var.set("")
            binary_args_label.grid_remove()
            binary_args_entry.grid_remove()
            binary_args_entry.configure(state="disabled")

    binary_config_var.trace_add("write", lambda *_args: refresh_binary_guidance())
    binary_args_var.trace_add("write", lambda *_args: refresh_binary_guidance())
    refresh_binary_guidance()


    binary_actions = ttk.Frame(binary_group)
    binary_actions.grid(row=1, column=0, sticky="we", pady=(8, 0))
    ttk.Button(
        binary_actions,
        text="Open existing",
        command=lambda: _open_existing_binary_config(
            packaged_app_var,
            binary_config_var,
            binary_config_details_var,
            binary_args_var,
            binary_args_details_var,
            set_dirty,
            package_info_label,
        ),
    ).pack(side=tk.LEFT)
    ttk.Button(
        binary_actions,
        text="Save binary_config.txt",
        command=lambda: _save_document(
            "binary_config.txt",
            package_info_var.get(),
            package_info_values,
            packaged_app_var.get(),
            _build_binary_config_from_guidance(
                binary_config_var.get(),
                binary_config_details_var.get(),
                binary_args_var.get(),
                binary_args_details_var.get(),
            ),
            set_dirty,
            package_info_label,
            packaged_app_label,
        ),
    ).pack(side=tk.RIGHT)

    readme_group = ttk.LabelFrame(frame, text="README.txt", padding=16)
    readme_group.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
    readme_group.columnconfigure(0, weight=1)

    admin_var = tk.StringVar(value="Yes")
    user_scope_var = tk.StringVar(value="")
    user_scope_other_var = tk.StringVar(value="")
    license_var = tk.StringVar(value="")
    license_details_var = tk.StringVar(value="")
    config_change_var = tk.StringVar(value="")
    config_details_var = tk.StringVar(value="")
    event_id_var = tk.StringVar(value="")

    readme_controls = ttk.Frame(readme_group)
    readme_controls.grid(row=0, column=0, sticky="we")

    simple_install_check = ttk.Checkbutton(
        readme_controls,
        text="Simple Install Instructions",
        variable=simple_install_var,
        command=lambda: _toggle_readme_mode(
            simple_install_var.get(),
            packaged_app_var.get(),
            readme_text,
            additional_text,
            admin_var.get(),
            user_scope_var.get(),
            user_scope_other_var.get(),
            license_var.get(),
            license_details_var.get(),
            config_change_var.get(),
            config_details_var.get(),
            event_id_var.get(),
            additional_text.get("1.0", tk.END),
        ),
    )
    simple_install_check.grid(row=0, column=0, sticky="w", pady=4)

    guidance_frame = ttk.LabelFrame(readme_group, text="Guided Instructions", padding=12)
    guidance_frame.grid(row=1, column=0, sticky="we", pady=(8, 8))
    guidance_frame.columnconfigure(1, weight=1)

    ttk.Label(guidance_frame, text="Admin install required?", style="Body.TLabel").grid(
        row=0, column=0, sticky="w", pady=4, padx=(0, 12)
    )
    admin_frame = ttk.Frame(guidance_frame)
    admin_frame.grid(row=0, column=1, sticky="w")
    ttk.Radiobutton(admin_frame, text="Yes", value="Yes", variable=admin_var).pack(side=tk.LEFT)
    ttk.Radiobutton(admin_frame, text="No", value="No", variable=admin_var).pack(side=tk.LEFT, padx=(12, 0))

    install_scope_label = ttk.Label(
        guidance_frame,
        text="Install scope",
        style="Body.TLabel",
    )
    install_scope_label.grid(row=1, column=0, sticky="w", pady=4, padx=(0, 12))
    scope_frame = ttk.Frame(guidance_frame)
    scope_frame.grid(row=1, column=1, sticky="w")
    ttk.Radiobutton(scope_frame, text="All", value="All", variable=user_scope_var).pack(side=tk.LEFT)
    ttk.Radiobutton(
        scope_frame,
        text="Logged in user",
        value="Logged in user",
        variable=user_scope_var,
    ).pack(side=tk.LEFT, padx=(12, 0))
    ttk.Radiobutton(scope_frame, text="Other", value="Other", variable=user_scope_var).pack(
        side=tk.LEFT,
        padx=(12, 0),
    )

    user_scope_other_label = ttk.Label(
        guidance_frame,
        text="How does the installer choose which users to install for?",
        style="Body.TLabel",
    )
    user_scope_other_entry = ttk.Entry(
        guidance_frame,
        textvariable=user_scope_other_var,
        width=70,
    )

    license_label = ttk.Label(
        guidance_frame,
        text="License requirement",
        style="Body.TLabel",
    )
    license_label.grid(row=3, column=0, sticky="w", pady=4, padx=(0, 12))
    license_frame = ttk.Frame(guidance_frame)
    license_frame.grid(row=3, column=1, sticky="w")
    ttk.Radiobutton(license_frame, text="No", value="No", variable=license_var).pack(side=tk.LEFT)
    ttk.Radiobutton(license_frame, text="Manual", value="Manual", variable=license_var).pack(
        side=tk.LEFT,
        padx=(12, 0),
    )
    ttk.Radiobutton(license_frame, text="Automated", value="Automated", variable=license_var).pack(
        side=tk.LEFT,
        padx=(12, 0),
    )

    license_details_label = ttk.Label(
        guidance_frame,
        text="How does the installer or customer install the license?",
        style="Body.TLabel",
    )
    license_details_entry = ttk.Entry(
        guidance_frame,
        textvariable=license_details_var,
        width=70,
    )

    config_label = ttk.Label(
        guidance_frame,
        text="Configuration changes before install",
        style="Body.TLabel",
    )
    config_label.grid(row=5, column=0, sticky="w", pady=4, padx=(0, 12))
    config_frame = ttk.Frame(guidance_frame)
    config_frame.grid(row=5, column=1, sticky="w")
    ttk.Radiobutton(config_frame, text="Yes", value="Yes", variable=config_change_var).pack(side=tk.LEFT)
    ttk.Radiobutton(config_frame, text="No", value="No", variable=config_change_var).pack(
        side=tk.LEFT,
        padx=(12, 0),
    )

    config_details_label = ttk.Label(
        guidance_frame,
        text=(
            "What configuration does the installer need to review/change "
            "before installation and what do they need to review/change?"
        ),
        style="Body.TLabel",
        wraplength=520,
        justify="left",
    )
    config_details_entry = ttk.Entry(
        guidance_frame,
        textvariable=config_details_var,
        width=70,
    )

    event_id_label = ttk.Label(
        guidance_frame,
        text="Event ID generated when successfully installed",
        style="Body.TLabel",
    )
    event_id_label.grid(row=7, column=0, sticky="w", pady=4, padx=(0, 12))
    event_id_entry = ttk.Entry(
        guidance_frame,
        textvariable=event_id_var,
        width=30,
    )
    event_id_entry.grid(row=7, column=1, sticky="w", pady=4)

    readme_preview_frame = ttk.Frame(readme_group)
    readme_preview_frame.grid(row=2, column=0, sticky="nsew")
    readme_preview_frame.columnconfigure(0, weight=1)
    readme_preview_frame.rowconfigure(0, weight=1)
    readme_text = tk.Text(readme_preview_frame, height=8, wrap="word")
    readme_text.grid(row=0, column=0, sticky="nsew")
    readme_text.bind("<<Modified>>", _track_text_modified(readme_text, set_dirty))
    readme_text.configure(state="disabled")
    readme_scroll = ttk.Scrollbar(readme_preview_frame, orient=tk.VERTICAL, command=readme_text.yview)
    readme_scroll.grid(row=0, column=1, sticky="ns")
    readme_text.configure(yscrollcommand=readme_scroll.set)
    _bind_text_mousewheel(readme_text)

    additional_label = ttk.Label(
        readme_group,
        text="Additional instructions",
        style="Body.TLabel",
    )
    additional_label.grid(row=3, column=0, sticky="w", pady=(6, 2))
    additional_frame = ttk.Frame(readme_group)
    additional_frame.grid(row=4, column=0, sticky="we")
    additional_frame.columnconfigure(0, weight=1)
    additional_text = tk.Text(additional_frame, height=4, wrap="word")
    additional_text.grid(row=0, column=0, sticky="we")
    _bind_text_mousewheel(additional_text)
    additional_scroll = ttk.Scrollbar(additional_frame, orient=tk.VERTICAL, command=additional_text.yview)
    additional_scroll.grid(row=0, column=1, sticky="ns")
    additional_text.configure(yscrollcommand=additional_scroll.set)

    readme_actions = ttk.Frame(readme_group)
    readme_actions.grid(row=5, column=0, sticky="we", pady=(8, 0))
    ttk.Button(
        readme_actions,
        text="Open existing",
        command=lambda: _open_existing_readme(
            packaged_app_var,
            admin_var,
            user_scope_var,
            user_scope_other_var,
            license_var,
            license_details_var,
            config_change_var,
            config_details_var,
            event_id_var,
            additional_text,
            readme_text,
            set_dirty,
            package_info_label,
        ),
    ).pack(side=tk.LEFT)
    ttk.Button(
        readme_actions,
        text="Save README.txt",
        command=lambda: _save_document(
            "README.txt",
            package_info_var.get(),
            package_info_values,
            packaged_app_var.get(),
            readme_text.get("1.0", tk.END),
            set_dirty,
            package_info_label,
            packaged_app_label,
            simple_install_var.get(),
            _build_readme_from_form(
                admin_var.get(),
                user_scope_var.get(),
                user_scope_other_var.get(),
                license_var.get(),
                license_details_var.get(),
                config_change_var.get(),
                config_details_var.get(),
                event_id_var.get(),
                additional_text.get("1.0", tk.END),
                include_additional=True,
            ),
            admin_var.get(),
            user_scope_var.get(),
            user_scope_other_var.get(),
            license_var.get(),
            license_details_var.get(),
            config_change_var.get(),
            config_details_var.get(),
            event_id_var.get(),
            install_scope_label,
            user_scope_other_label,
            license_label,
            license_details_label,
            config_label,
            config_details_label,
            event_id_label,
        ),
    ).pack(side=tk.RIGHT)

    def refresh_guidance_visibility(*_args) -> None:
        """Refresh guided input visibility and preview content."""
        guidance_frame.grid()
        additional_label.grid()
        additional_frame.grid()
        _refresh_guided_prompts(
            user_scope_var.get(),
            user_scope_other_label,
            user_scope_other_entry,
            license_var.get(),
            license_details_label,
            license_details_entry,
            config_change_var.get(),
            config_details_label,
            config_details_entry,
        )
        _populate_guided_preview(
            readme_text,
            _build_readme_from_form(
                admin_var.get(),
                user_scope_var.get(),
                user_scope_other_var.get(),
                license_var.get(),
                license_details_var.get(),
                config_change_var.get(),
                config_details_var.get(),
                event_id_var.get(),
                additional_text.get("1.0", tk.END),
                include_additional=False,
            ),
        )

    def mark_guided_dirty(*_args) -> None:
        """Update preview text for guided instructions."""
        refresh_guidance_visibility()
        set_dirty(True)

    for var in (
        simple_install_var,
        admin_var,
        user_scope_var,
        user_scope_other_var,
        license_var,
        license_details_var,
        config_change_var,
        config_details_var,
        event_id_var,
    ):
        var.trace_add("write", lambda *_args: mark_guided_dirty())

    refresh_guidance_visibility()

    additional_text.bind("<<Modified>>", _track_text_modified(additional_text, set_dirty))

    return frame


def _browse_package_info(
    package_info_var: tk.StringVar,
    package_info_values: dict[str, str],
    header_preview_var: tk.StringVar,
    license_var: tk.StringVar,
    package_info_label: ttk.Label,
    packaged_app_var: tk.StringVar,
    packaged_app_label: ttk.Label,
    packaged_app_warning_var: tk.StringVar,
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
    except Exception:
        flash_label(package_info_label)
        return
    package_info_values.clear()
    package_info_values.update(values)
    header_preview_var.set(_build_header_preview(values))
    license_flag = values.get("Licensed Software Flag", "").strip()
    if license_flag.casefold() == "no":
        license_var.set("No")
    elif license_flag:
        license_var.set("")
    _update_packaged_app_warning(
        packaged_app_var.get(),
        package_info_values,
        packaged_app_label,
        packaged_app_warning_var,
    )


def _save_document(
    filename: str,
    package_info_path_str: str,
    package_info_values: dict[str, str],
    packaged_app_path_str: str,
    body_text: str,
    set_dirty,
    package_info_label: ttk.Label,
    packaged_app_label: ttk.Label,
    simple_install: bool = False,
    guided_text: str = "",
    admin_value: str | None = None,
    scope_value: str | None = None,
    scope_other: str | None = None,
    license_value: str | None = None,
    license_details: str | None = None,
    config_value: str | None = None,
    config_details: str | None = None,
    event_id_value: str | None = None,
    install_scope_label: ttk.Label | None = None,
    scope_other_label: ttk.Label | None = None,
    license_label: ttk.Label | None = None,
    license_details_label: ttk.Label | None = None,
    config_label: ttk.Label | None = None,
    config_details_label: ttk.Label | None = None,
    event_id_label: ttk.Label | None = None,
) -> None:
    """Save a documentation file with the PackageInfo header."""
    missing = False
    if not package_info_path_str:
        flash_label(package_info_label)
        missing = True
    if not packaged_app_path_str:
        flash_label(packaged_app_label)
        missing = True
    if missing:
        return
    if not package_info_values:
        flash_label(package_info_label)
        return
    if not Path(package_info_path_str).expanduser().exists():
        flash_label(package_info_label)
        return
    packaged_path = Path(packaged_app_path_str).expanduser()
    if packaged_path.exists() and packaged_path.is_dir():
        output_dir = packaged_path
    elif packaged_path.exists():
        output_dir = packaged_path.parent
    else:
        flash_label(packaged_app_label)
        return
    if filename == "binary_config.txt":
        build_dir = output_dir / "build_files"
        output_dir = build_dir if build_dir.exists() else output_dir
    output_path = output_dir / filename
    header = _build_header(package_info_values)
    if filename == "README.txt":
        if not _validate_guided_requirements(
            admin_value or "",
            scope_value or "",
            scope_other or "",
            license_value or "",
            license_details or "",
            config_value or "",
            config_details or "",
            event_id_value or "",
            install_scope_label,
            scope_other_label,
            license_label,
            license_details_label,
            config_label,
            config_details_label,
            event_id_label,
        ):
            return
    if filename == "README.txt" and guided_text:
        body = guided_text
    else:
        body = body_text.strip()
    content = header + "\n\n" + body + "\n"
    try:
        output_path.write_text(content, encoding="utf-8")
    except OSError:
        flash_label(packaged_app_label)
        return
    messagebox.showinfo("Saved", f"Saved:\n{output_path}")
    set_dirty(False)


def _build_header(values: dict[str, str]) -> str:
    """Build an ASCII header using PackageInfo values."""
    vendor = values.get("Software Vendor", "")
    software = values.get("Software Name", "")
    version = values.get("Software Version", "")
    architecture = values.get("Software Architecture", "")
    lines = [
        "=========================================",
        f"Vendor: {vendor}",
        f"Software: {software}",
        f"Version: {version}",
        f"Architecture: {architecture}",
        "=========================================",
    ]
    return "\n".join(lines)


def _build_header_preview(values: dict[str, str]) -> str:
    """Return a compact header preview."""
    vendor = values.get("Software Vendor", "")
    software = values.get("Software Name", "")
    version = values.get("Software Version", "")
    architecture = values.get("Software Architecture", "")
    return f"Vendor: {vendor}\nSoftware: {software}\nVersion: {version}\nArchitecture: {architecture}"


def _update_packaged_app_warning(
    packaged_app_path: str,
    package_info_values: dict[str, str],
    packaged_app_label: ttk.Label,
    warning_var: tk.StringVar,
) -> None:
    """Warn if the packaged app matches the original installer binary."""
    source_binary = _extract_source_binary_name(package_info_values)
    packaged_name = Path(packaged_app_path).name if packaged_app_path else ""
    if source_binary and packaged_name and packaged_name.lower() == source_binary.lower():
        warning_var.set(
            "Selected executable matches the original installer. "
            "Choose the packaged application instead."
        )
        packaged_app_label.configure(foreground="#c0392b")
        return

    expected_sha1 = package_info_values.get("Software SHA1 Hash", "").strip()
    expected_sha256 = package_info_values.get("Software SHA256 Hash", "").strip()
    if packaged_app_path and (expected_sha1 or expected_sha256):
        try:
            actual_sha1 = _hash_file(Path(packaged_app_path), "sha1") if expected_sha1 else ""
            actual_sha256 = _hash_file(Path(packaged_app_path), "sha256") if expected_sha256 else ""
        except OSError:
            actual_sha1 = ""
            actual_sha256 = ""
        if (
            (expected_sha1 and actual_sha1 == expected_sha1)
            or (expected_sha256 and actual_sha256 == expected_sha256)
        ):
            warning_var.set(
                "Selected executable matches the original installer hash. "
                "Choose the packaged application instead."
            )
            packaged_app_label.configure(foreground="#c0392b")
            return

    warning_var.set("")
    packaged_app_label.configure(foreground="#4b5a6a")


def _extract_source_binary_name(values: dict[str, str]) -> str:
    """Best-effort extraction of source binary name from PackageInfo values."""
    for key in ("Source", "Installer path", "Installer Path", "Installer"):
        raw = values.get(key, "").strip()
        if raw:
            return Path(raw).name
    return ""


def _hash_file(path: Path, algorithm: str) -> str:
    """Compute a hash for a file."""
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _browse_packaged_app(
    packaged_app_var: tk.StringVar,
    simple_install_var: tk.BooleanVar,
    additional_text: tk.Text,
    package_info_values: dict[str, str],
    packaged_app_label: ttk.Label,
    packaged_app_warning_var: tk.StringVar,
) -> None:
    """Select the packaged app executable for simple instructions."""
    file_path = filedialog.askopenfilename(
        title="Select Packaged App",
        filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
    )
    if not file_path:
        return
    packaged_app_var.set(file_path)
    _update_packaged_app_warning(
        file_path,
        package_info_values,
        packaged_app_label,
        packaged_app_warning_var,
    )
    if simple_install_var.get():
        _apply_simple_install(True, file_path, additional_text)


def _toggle_readme_mode(
    simple_install: bool,
    packaged_app_path: str,
    readme_text: tk.Text,
    additional_text: tk.Text,
    admin_value: str,
    user_scope_value: str,
    user_scope_other: str,
    license_value: str,
    license_details: str,
    config_change_value: str,
    config_details: str,
    event_id_value: str,
    additional_instructions: str,
) -> None:
    """Switch between simple and guided README content."""
    if simple_install:
        _apply_simple_install(True, packaged_app_path, additional_text)
        return
    _populate_guided_preview(
        readme_text,
        _build_readme_from_form(
            admin_value,
            user_scope_value,
            user_scope_other,
            license_value,
            license_details,
            config_change_value,
            config_details,
            event_id_value,
            additional_instructions,
            include_additional=False,
        ),
    )


def _open_existing_document(
    filename: str,
    packaged_app_var: tk.StringVar,
    target_text: tk.Text,
    set_dirty,
    update_packaged_app: bool,
    error_label: ttk.Label | None = None,
) -> None:
    """Open an existing documentation file into the editor."""
    file_path = filedialog.askopenfilename(
        title=f"Select {filename}",
        filetypes=[(filename, filename), ("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not file_path:
        return
    try:
        raw = Path(file_path).read_text(encoding="utf-8")
    except OSError:
        if error_label is not None:
            flash_label(error_label)
        return
    content = _strip_header(raw)
    target_text.delete("1.0", tk.END)
    target_text.insert(tk.END, content)
    set_dirty(True)

    if update_packaged_app:
        parent_dir = Path(file_path).parent
        packaged_app = parent_dir / "Packaged_App.exe"
        if packaged_app.exists():
            packaged_app_var.set(str(packaged_app))
        else:
            packaged_app_var.set(str(parent_dir))


def _open_existing_binary_config(
    packaged_app_var: tk.StringVar,
    config_var: tk.StringVar,
    config_details_var: tk.StringVar,
    args_var: tk.StringVar,
    args_details_var: tk.StringVar,
    set_dirty,
    error_label: ttk.Label,
) -> None:
    """Open an existing binary_config.txt and populate guided fields."""
    file_path = filedialog.askopenfilename(
        title="Select binary_config.txt",
        filetypes=[("binary_config.txt", "binary_config.txt"), ("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not file_path:
        return
    try:
        raw = Path(file_path).read_text(encoding="utf-8")
    except OSError:
        flash_label(error_label)
        return

    config_value, config_details, args_value, args_details = _parse_binary_config(raw)
    config_var.set(config_value)
    config_details_var.set(config_details)
    args_var.set(args_value)
    args_details_var.set(args_details)
    set_dirty(True)

    parent_dir = Path(file_path).parent
    packaged_app = parent_dir / "Packaged_App.exe"
    if packaged_app.exists():
        packaged_app_var.set(str(packaged_app))


def _parse_binary_config(contents: str) -> tuple[str, str, str, str]:
    """Parse binary_config.txt into guided fields."""
    config_value = "No"
    config_details = ""
    args_value = "No"
    args_details = ""
    for line in contents.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("- special configurations:"):
            value = stripped.split(":", 1)[1].strip()
            if value and value.lower() != "none":
                config_value = "Yes"
                config_details = value
            continue
        if stripped.lower().startswith("- installer arguments:"):
            value = stripped.split(":", 1)[1].strip()
            if value and value.lower() != "none":
                args_value = "Yes"
                args_details = value
            continue
    return config_value, config_details, args_value, args_details


def _open_existing_readme(
    packaged_app_var: tk.StringVar,
    admin_var: tk.StringVar,
    user_scope_var: tk.StringVar,
    user_scope_other_var: tk.StringVar,
    license_var: tk.StringVar,
    license_details_var: tk.StringVar,
    config_change_var: tk.StringVar,
    config_details_var: tk.StringVar,
    event_id_var: tk.StringVar,
    additional_text: tk.Text,
    readme_text: tk.Text,
    set_dirty,
    error_label: ttk.Label,
) -> None:
    """Open an existing README.txt and populate guided fields."""
    file_path = filedialog.askopenfilename(
        title="Select README.txt",
        filetypes=[("README.txt", "README.txt"), ("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not file_path:
        return
    try:
        raw = Path(file_path).read_text(encoding="utf-8")
    except OSError:
        flash_label(error_label)
        return

    content = _strip_header(raw)
    parsed = _parse_readme_guided(content)
    admin_var.set(parsed["admin"])
    user_scope_var.set(parsed["scope"])
    user_scope_other_var.set(parsed["scope_other"])
    license_var.set(parsed["license"])
    license_details_var.set(parsed["license_details"])
    config_change_var.set(parsed["config"])
    config_details_var.set(parsed["config_details"])
    event_id_var.set(parsed["event_id"])

    additional_text.configure(state="normal")
    additional_text.delete("1.0", tk.END)
    additional_text.insert(tk.END, parsed["additional"])
    additional_text.configure(state="normal")

    _populate_guided_preview(readme_text, _build_readme_from_form(
        admin_var.get(),
        user_scope_var.get(),
        user_scope_other_var.get(),
        license_var.get(),
        license_details_var.get(),
        config_change_var.get(),
        config_details_var.get(),
        event_id_var.get(),
        additional_text.get("1.0", tk.END),
        include_additional=False,
    ))

    set_dirty(True)

    parent_dir = Path(file_path).parent
    packaged_app = parent_dir / "Packaged_App.exe"
    if packaged_app.exists():
        packaged_app_var.set(str(packaged_app))


def _parse_readme_guided(contents: str) -> dict[str, str]:
    """Parse guided README content into field values."""
    parsed = {
        "admin": "Yes",
        "scope": "",
        "scope_other": "",
        "license": "",
        "license_details": "",
        "config": "",
        "config_details": "",
        "event_id": "",
        "additional": "",
    }
    lines = [line.rstrip() for line in contents.splitlines()]
    additional_lines: list[str] = []
    in_additional = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- Install as administrator:"):
            parsed["admin"] = stripped.split(":", 1)[1].strip() or "Yes"
            continue
        if stripped.startswith("- Install scope:"):
            value = stripped.split(":", 1)[1].strip()
            if value.startswith("Other (") and value.endswith(")"):
                parsed["scope"] = "Other"
                parsed["scope_other"] = value[len("Other (") : -1].strip()
            else:
                parsed["scope"] = value
            continue
        if stripped.startswith("- License requirement:"):
            value = stripped.split(":", 1)[1].strip()
            if value.startswith("Manual (") and value.endswith(")"):
                parsed["license"] = "Manual"
                parsed["license_details"] = value[len("Manual (") : -1].strip()
            else:
                parsed["license"] = value
            continue
        if stripped.startswith("- Configuration changes before install:"):
            value = stripped.split(":", 1)[1].strip()
            if value and value.lower() != "no" and value.lower() != "not specified":
                parsed["config"] = "Yes"
                parsed["config_details"] = value
            else:
                parsed["config"] = "No" if value.lower() == "no" else value
            continue
        if stripped.startswith("- Event ID generated when successfully installed:"):
            parsed["event_id"] = stripped.split(":", 1)[1].strip()
            continue
        if stripped == "Additional Instructions:":
            in_additional = True
            continue
        if in_additional:
            additional_lines.append(line)

    if additional_lines:
        parsed["additional"] = "\n".join(additional_lines).strip()
    else:
        parsed["additional"] = contents.strip()
    return parsed


def _apply_simple_install(enabled: bool, packaged_app_path: str, target_text: tk.Text) -> None:
    """Populate simple instructions in the target text widget."""
    if not enabled:
        return
    app_name = Path(packaged_app_path).name if packaged_app_path else "<Packaged_App.exe>"
    instructions = (
        "Installation Instructions:\n"
        f"1. Run {app_name}.\n"
        "2. Check Event Viewer > Windows Logs > System for event logging completed install."
    )
    target_text.delete("1.0", tk.END)
    target_text.insert(tk.END, instructions)


def _strip_header(content: str) -> str:
    """Remove the ASCII header block if present."""
    lines = content.splitlines()
    header_line = "========================================="
    if len(lines) < 6:
        return content
    if lines[0].strip() != header_line:
        return content
    try:
        end_index = lines.index(header_line, 1)
    except ValueError:
        return content
    return "\n".join(lines[end_index + 1 :]).lstrip()


def _refresh_guided_prompts(
    scope_value: str,
    scope_label: ttk.Label,
    scope_entry: ttk.Entry,
    license_value: str,
    license_label: ttk.Label,
    license_entry: ttk.Entry,
    config_value: str,
    config_label: ttk.Label,
    config_entry: ttk.Entry,
) -> None:
    """Show/hide conditional guided prompts."""
    if scope_value == "Other":
        scope_label.grid(row=2, column=0, sticky="w", pady=4, padx=(0, 12))
        scope_entry.grid(row=2, column=1, sticky="we", pady=4)
    else:
        scope_label.grid_remove()
        scope_entry.grid_remove()

    if license_value == "Manual":
        license_label.grid(row=4, column=0, sticky="w", pady=4, padx=(0, 12))
        license_entry.grid(row=4, column=1, sticky="we", pady=4)
    else:
        license_label.grid_remove()
        license_entry.grid_remove()

    if config_value == "Yes":
        config_label.grid(row=6, column=0, sticky="w", pady=4, padx=(0, 12))
        config_entry.grid(row=6, column=1, sticky="we", pady=4)
    else:
        config_label.grid_remove()
        config_entry.grid_remove()


def _build_readme_from_form(
    admin_value: str,
    user_scope_value: str,
    user_scope_other: str,
    license_value: str,
    license_details: str,
    config_change_value: str,
    config_details: str,
    event_id_value: str,
    additional_instructions: str,
    *,
    include_additional: bool = True,
) -> str:
    """Create README instructions from guided inputs."""
    lines = ["Installation Instructions:"]
    lines.append(f"- Install as administrator: {admin_value or 'Not specified'}")
    if user_scope_value == "Other" and user_scope_other.strip():
        scope_detail = f"Other ({user_scope_other.strip()})"
    else:
        scope_detail = user_scope_value or "Not specified"
    lines.append(f"- Install scope: {scope_detail}")
    if license_value == "Manual" and license_details.strip():
        license_detail = f"Manual ({license_details.strip()})"
    else:
        license_detail = license_value or "Not specified"
    lines.append(f"- License requirement: {license_detail}")
    if config_change_value == "Yes" and config_details.strip():
        config_detail = config_details.strip()
    else:
        config_detail = config_change_value or "Not specified"
    lines.append(f"- Configuration changes before install: {config_detail}")
    event_id = event_id_value.strip() or "Not specified"
    lines.append(f"- Event ID generated when successfully installed: {event_id}")
    if include_additional and additional_instructions.strip():
        lines.append("")
        lines.append("Additional Instructions:")
        lines.append(additional_instructions.strip())
    return "\n".join(lines)


def _build_binary_config_from_guidance(
    config_value: str,
    config_details: str,
    args_value: str,
    args_details: str,
) -> str:
    """Create binary_config content from guided inputs."""
    lines = ["Binary Config Instructions:"]
    if config_value == "Yes" and config_details.strip():
        lines.append(f"- Special configurations: {config_details.strip()}")
    else:
        lines.append("- Special configurations: None")
    if args_value == "Yes" and args_details.strip():
        lines.append(f"- Installer arguments: {args_details.strip()}")
    else:
        lines.append("- Installer arguments: None")
    return "\n".join(lines)


def _populate_guided_preview(readme_text: tk.Text, content: str) -> None:
    """Populate the README preview with guided content."""
    readme_text.configure(state="normal")
    readme_text.delete("1.0", tk.END)
    readme_text.insert(tk.END, content)
    readme_text.configure(state="disabled")


def _validate_guided_requirements(
    admin_value: str,
    scope_value: str,
    scope_other: str,
    license_value: str,
    license_details: str,
    config_value: str,
    config_details: str,
    event_id_value: str,
    install_scope_label: ttk.Label | None,
    scope_other_label: ttk.Label | None,
    license_label: ttk.Label | None,
    license_details_label: ttk.Label | None,
    config_label: ttk.Label | None,
    config_details_label: ttk.Label | None,
    event_id_label: ttk.Label | None,
) -> bool:
    """Validate guided fields and flash missing labels."""
    missing = False
    if not scope_value.strip():
        if install_scope_label is not None:
            flash_label(install_scope_label)
        missing = True
    if scope_value.strip() == "Other" and not scope_other.strip():
        if scope_other_label is not None:
            flash_label(scope_other_label)
        missing = True
    if not license_value.strip():
        if license_label is not None:
            flash_label(license_label)
        missing = True
    if license_value.strip() == "Manual" and not license_details.strip():
        if license_details_label is not None:
            flash_label(license_details_label)
        missing = True
    if not config_value.strip():
        if config_label is not None:
            flash_label(config_label)
        missing = True
    if config_value.strip() == "Yes" and not config_details.strip():
        if config_details_label is not None:
            flash_label(config_details_label)
        missing = True
    if not event_id_value.strip():
        if event_id_label is not None:
            flash_label(event_id_label)
        missing = True
    return not missing




def _track_text_modified(widget: tk.Text, callback) -> callable:
    """Create a handler that fires when a Text widget is modified."""
    def _handler(_event=None) -> None:
        """Normalize Text change events into a single callback."""
        if widget.edit_modified():
            callback()
            widget.edit_modified(False)

    return _handler


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
