"""
Interactive screening for installer metadata.

This module prompts a user to confirm or update extracted metadata, enforcing
updates when values are unknown. Vendor and software names are selected from
configured picklists.
"""

from __future__ import annotations

import json
from datetime import datetime
from dataclasses import replace
from pathlib import Path
from typing import Iterable, List, Optional

from src.config import (
    FILE_PATHS_SOFTWARE_NAMES,
    FILE_PATHS_VENDOR_NAMES,
    LOGGING_DIR,
)
from src.utils.metadata_extractor import InstallerMetadata, UNKNOWN_VALUE


class SourceInfoScreen:
    """Prompt a user to validate and update installer metadata."""

    def __init__(
        self,
        vendor_names_path: Path = FILE_PATHS_VENDOR_NAMES,
        software_names_path: Path = FILE_PATHS_SOFTWARE_NAMES,
    ) -> None:
        """Initialize picklist paths for interactive screening."""
        self._vendor_names_path = vendor_names_path
        self._software_names_path = software_names_path

    def screen(self, metadata: InstallerMetadata) -> InstallerMetadata:
        """Return metadata updated with user-supplied values."""
        vendor_options = _load_picklist(self._vendor_names_path)
        software_options = _load_picklist(self._software_names_path)

        vendor_name = _prompt_picklist(
            "Vendor name",
            vendor_options,
            current=metadata.vendor_name,
            require=_is_unknown(metadata.vendor_name),
            metadata=metadata,
            picklist_path=self._vendor_names_path,
        )
        software_name = _prompt_picklist(
            "Software name",
            software_options,
            current=metadata.software_name,
            require=_is_unknown(metadata.software_name),
            metadata=metadata,
            picklist_path=self._software_names_path,
        )
        software_version = _prompt_text(
            "Software version",
            current=metadata.software_version,
            require=_is_unknown(metadata.software_version),
        )
        software_architecture = _prompt_fixed_picklist(
            "Software architecture",
            ["x86", "x64"],
            current=metadata.software_architecture,
            require=_is_unknown(metadata.software_architecture),
        )

        return replace(
            metadata,
            vendor_name=vendor_name,
            software_name=software_name,
            software_version=software_version,
            software_architecture=software_architecture,
        )

    def browse_source_file(self) -> Path:
        """Prompt the user to select a source installer file path."""
        return _prompt_installer_path()


def _load_picklist(path: Path) -> List[str]:
    """Load a JSON array of strings as a picklist."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []

    options = [str(item).strip() for item in data if str(item).strip()]
    return options


def _prompt_installer_path() -> Path:
    """Prompt for a valid installer path (.msi or .exe)."""
    while True:
        response = input("Enter installer path (.msi or .exe): ").strip().strip('"')
        if not response:
            print("Installer path is required.")
            continue
        candidate = Path(response)
        if not candidate.exists():
            print("Path not found. Please enter a valid path.")
            continue
        if candidate.suffix.lower() not in {".msi", ".exe"}:
            print("Unsupported file type. Please select a .msi or .exe file.")
            continue
        return candidate


def _prompt_picklist(
    label: str,
    options: Iterable[str],
    current: str,
    require: bool,
    metadata: InstallerMetadata,
    picklist_path: Path,
) -> str:
    """Prompt for a selection from a list of options."""
    option_list = list(options)

    while True:
        print(f"{label}: {current or UNKNOWN_VALUE}")
        if option_list:
            for idx, option in enumerate(option_list, start=1):
                print(f"  {idx}. {option}")
            print("  A. Add a new value")
            default_index = _default_index(option_list, current)
            default_hint = f"[{default_index}]" if default_index is not None else ""
            response = input(f"Select {label} {default_hint}: ").strip()
            if not response:
                if not require and current:
                    return current
                if default_index is not None:
                    return option_list[default_index - 1]
            if response.lower() == "a":
                new_value = _prompt_text(f"New {label}", current="", require=True)
                _log_picklist_addition_request(picklist_path, new_value, metadata)
                return new_value
            if response.isdigit():
                selection = int(response)
                if 1 <= selection <= len(option_list):
                    return option_list[selection - 1]
        else:
            response = input(f"Enter {label}: ").strip()
            if response:
                return response

        if not require and current:
            return current
        print(f"{label} is required. Please select a value.")


def _prompt_fixed_picklist(
    label: str,
    options: Iterable[str],
    current: str,
    require: bool,
) -> str:
    """Prompt for a selection from a fixed list of options."""
    option_list = list(options)
    attempts = 0
    while True:
        print(f"{label}: {current or UNKNOWN_VALUE}")
        for idx, option in enumerate(option_list, start=1):
            print(f"  {idx}. {option}")
        default_index = _default_index(option_list, current)
        default_hint = f"[{default_index}]" if default_index is not None else ""
        response = input(f"Select {label} {default_hint}: ").strip()
        if not response:
            if not require and current:
                return current
            if default_index is not None:
                return option_list[default_index - 1]
        if response.isdigit():
            selection = int(response)
            if 1 <= selection <= len(option_list):
                selection_value = option_list[selection - 1]
                if _is_opposite_arch(current, selection_value):
                    if _confirm_override(
                        f"{label} differs from detected value '{current}'"
                    ):
                        return selection_value
                    if current in option_list:
                        return current
                return selection_value
        if not require and current:
            return current
        attempts += 1
        if attempts == 1:
            print(
                f"Invalid selection. Choose a listed option or press Enter for default."
            )
            continue
        default_value = current if current in option_list else option_list[0]
        print(f"Invalid selection. Defaulting to '{default_value}'.")
        return default_value


def _prompt_text(label: str, current: str, require: bool) -> str:
    """Prompt for a free-text field with optional default."""
    while True:
        default_hint = f"[{current}]" if current and not require else ""
        response = input(f"{label} {default_hint}: ").strip()
        if response:
            if current and response != current:
                if _confirm_override(
                    f"{label} differs from detected value '{current}'"
                ):
                    return response
                return current
            return response
        if not require and current:
            return current
        print(f"{label} is required. Please enter a value.")


def _default_index(options: List[str], current: str) -> Optional[int]:
    """Return the 1-based default index for the current value."""
    if current in options:
        return options.index(current) + 1
    return None


def _is_unknown(value: str) -> bool:
    """Return True when a value is empty or marked Unknown."""
    return not value or value.strip().lower() == UNKNOWN_VALUE.lower()


def _confirm_override(message: str) -> bool:
    """Require explicit confirmation before overriding detected values."""
    while True:
        response = input(f"{message}. Proceed? (y/n): ").strip().lower()
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False


def _is_opposite_arch(current: str, selection: str) -> bool:
    """Return True when the selection conflicts with detected architecture."""
    if not current:
        return False
    current_lower = current.strip().lower()
    selection_lower = selection.strip().lower()
    return {
        ("x86", "x64"),
        ("x64", "x86"),
    }.__contains__((current_lower, selection_lower))


def _log_picklist_addition_request(
    picklist_path: Path,
    value: str,
    metadata: InstallerMetadata,
) -> None:
    """Log a request to add a value to a picklist JSON file."""
    LOGGING_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGGING_DIR / "json_edit_requests.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"{timestamp} | file={picklist_path} | value={value} | "
        f"source={metadata.source_path} | vendor={metadata.vendor_name} | "
        f"software={metadata.software_name} | version={metadata.software_version} | "
        f"arch={metadata.software_architecture}"
    )
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")
