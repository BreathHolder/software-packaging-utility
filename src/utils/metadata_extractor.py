"""
Docstring for utils.metadata_extractor

When an executable (exe) or Microsoft installer (msi) file is selected as the source install file, this utility will extract the key metadata stored within the file for automated inclusion in the package build.
"""

# Imports
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Optional

# Aliases

UNKNOWN_VALUE = "Unknown"


@dataclass(frozen=True)
class InstallerMetadata:
    """Structured metadata extracted from installer binaries."""

    vendor_name: str
    software_name: str
    software_version: str
    software_architecture: str
    sha1: str
    sha256: str
    source_path: Path
    source_type: str


def parse_package_info_text(contents: str) -> dict[str, str]:
    """Parse a PackageInfo.txt payload into a key/value map."""
    values: dict[str, str] = {}
    current_key: Optional[str] = None
    in_scan_block = False
    scan_lines: list[str] = []
    scan_begin = "##Software Vulnerability Scan Results Details Begin##"
    scan_end = "##Software Vulnerability Scan Results Details End##"
    known_keys = {
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
        "Software Dependencies",
        "Software Vulnerability Scan Results Status",
        "Software Vulnerability Scan Results Details",
    }

    for line in contents.splitlines():
        stripped = line.strip()
        if in_scan_block:
            if stripped.startswith(scan_end):
                values["Software Vulnerability Scan Results Details"] = "\n".join(scan_lines).strip()
                scan_lines = []
                in_scan_block = False
                current_key = None
            else:
                scan_lines.append(line)
            continue

        if stripped.startswith(scan_begin):
            in_scan_block = True
            scan_lines = []
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            if not key:
                continue
            if (
                current_key == "Software Vulnerability Scan Results Details"
                and key not in known_keys
            ):
                existing = values.get(current_key, "")
                values[current_key] = f"{existing}\n{line}".strip()
                continue
            values[key] = value.strip()
            current_key = key
            continue

        if current_key is not None:
            existing = values.get(current_key, "")
            values[current_key] = f"{existing}\n{line}".strip()

    if in_scan_block:
        values["Software Vulnerability Scan Results Details"] = "\n".join(scan_lines).strip()
    return values


def parse_package_info_file(package_info_path: Path) -> dict[str, str]:
    """Load a PackageInfo.txt file and return parsed field values."""
    contents = package_info_path.read_text(encoding="utf-8")
    return parse_package_info_text(contents)


def extract_installer_metadata(installer_path: Path) -> InstallerMetadata:
    """Extract vendor, software, version, and architecture from an installer.

    Uses MSI properties for `.msi` files and Windows version info + PE headers
    for `.exe` files, falling back to safe defaults when fields are missing.
    """
    installer_path = Path(installer_path)
    suffix = installer_path.suffix.lower()

    if suffix == ".msi":
        metadata = _extract_from_msi(installer_path)
    elif suffix == ".exe":
        metadata = _extract_from_exe(installer_path)
    else:
        metadata = {}

    vendor_name = _clean_value(metadata.get("vendor_name"), UNKNOWN_VALUE)
    software_name = _clean_value(metadata.get("software_name"), UNKNOWN_VALUE)
    software_version = _clean_value(metadata.get("software_version"), UNKNOWN_VALUE)
    software_architecture = _clean_value(metadata.get("software_architecture"), UNKNOWN_VALUE)
    sha1 = _hash_file(installer_path, "sha1")
    sha256 = _hash_file(installer_path, "sha256")

    return InstallerMetadata(
        vendor_name=vendor_name,
        software_name=software_name,
        software_version=software_version,
        software_architecture=software_architecture,
        sha1=sha1,
        sha256=sha256,
        source_path=installer_path,
        source_type=suffix.lstrip(".") or UNKNOWN_VALUE,
    )


def build_package_directory_name(metadata: InstallerMetadata) -> str:
    """Format the directory name for package storage.

    Produces a path-like string using vendor, software name, and version/arch.
    """
    version_arch = f"{metadata.software_version}_{metadata.software_architecture}"
    return _safe_join(
        metadata.vendor_name,
        metadata.software_name,
        version_arch,
    )


def build_package_build_name(metadata: InstallerMetadata) -> str:
    """Format a build name suitable for package build folders or files.

    Uses vendor, software, version, and architecture in a stable order.
    """
    parts = [
        metadata.vendor_name,
        metadata.software_name,
        metadata.software_version,
        metadata.software_architecture,
    ]
    return _safe_join(*parts)


def build_package_info_text(metadata: InstallerMetadata) -> str:
    """Create the PackageInfo.txt content based on extracted metadata.

    Returns a newline-delimited string that can be written directly to disk.
    """
    return "\n".join(
        [
            f"Vendor: {metadata.vendor_name}",
            f"Software: {metadata.software_name}",
            f"Version: {metadata.software_version}",
            f"Architecture: {metadata.software_architecture}",
            f"SHA1: {metadata.sha1}",
            f"SHA256: {metadata.sha256}",
            f"Source: {metadata.source_path}",
            f"Installer Type: {metadata.source_type}",
        ]
    )


def _extract_from_exe(installer_path: Path) -> dict:
    """Extract metadata from an EXE via version info and PE headers."""
    vendor_name = None
    software_name = None
    software_version = None

    version_info = _get_windows_version_info(installer_path)
    if version_info:
        vendor_name = version_info.get("CompanyName")
        software_name = version_info.get("ProductName") or version_info.get("FileDescription")
        software_version = version_info.get("ProductVersion") or version_info.get("FileVersion")

    architecture = _get_pe_architecture(installer_path)

    return {
        "vendor_name": vendor_name,
        "software_name": software_name,
        "software_version": software_version,
        "software_architecture": architecture,
    }


def _extract_from_msi(installer_path: Path) -> dict:
    """Extract metadata from an MSI using Property and SummaryInformation."""
    try:
        import msilib  # type: ignore
    except Exception:
        return {}

    vendor_name = None
    software_name = None
    software_version = None
    architecture = None

    try:
        db = msilib.OpenDatabase(str(installer_path), msilib.MSIDBOPEN_READONLY)
        vendor_name = _msi_get_property(db, "Manufacturer")
        software_name = _msi_get_summary_info(db, 2) or _msi_get_property(db, "ProductName")
        software_version = _msi_get_property(db, "ProductVersion")
        architecture = _msi_get_architecture(db)
    except Exception:
        return {}

    return {
        "vendor_name": vendor_name,
        "software_name": software_name,
        "software_version": software_version,
        "software_architecture": architecture,
    }


def _msi_get_property(db, property_name: str) -> Optional[str]:
    """Read a single property value from an MSI Property table."""
    try:
        import msilib  # type: ignore
    except Exception:
        return None

    view = db.OpenView("SELECT `Value` FROM `Property` WHERE `Property`=?")
    record = msilib.CreateRecord(1)
    record.SetString(1, property_name)
    view.Execute(record)
    result = view.Fetch()
    view.Close()
    if not result:
        return None
    return result.GetString(1)


def _msi_get_summary_info(db, property_id: int) -> Optional[str]:
    """Read a SummaryInformation property by numeric ID."""
    try:
        summary = db.SummaryInformation(0)
        value = summary.GetProperty(property_id)
    except Exception:
        return None

    if not value:
        return None
    return str(value)


def _msi_get_architecture(db) -> Optional[str]:
    """Infer MSI architecture from the SummaryInformation template field."""
    try:
        summary = db.SummaryInformation(0)
        template = summary.GetProperty(7)
    except Exception:
        return None

    if not isinstance(template, str):
        return None

    template_lower = template.lower()
    if "x64" in template_lower or "intel64" in template_lower or "64" in template_lower:
        return "x64"
    if "x86" in template_lower or "intel" in template_lower or "32" in template_lower:
        return "x86"
    return None


def _get_windows_version_info(installer_path: Path) -> Optional[dict]:
    """Read Windows version info string fields from an EXE."""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return None

    path_str = str(installer_path)
    size = ctypes.windll.version.GetFileVersionInfoSizeW(path_str, None)
    if not size:
        return None

    buffer = ctypes.create_string_buffer(size)
    if not ctypes.windll.version.GetFileVersionInfoW(path_str, 0, size, buffer):
        return None

    translation_ptr = ctypes.c_void_p()
    translation_len = wintypes.UINT()
    if not ctypes.windll.version.VerQueryValueW(
        buffer, "\\VarFileInfo\\Translation", ctypes.byref(translation_ptr), ctypes.byref(translation_len)
    ):
        return None

    if translation_len.value < 4:
        return None

    lang, codepage = ctypes.cast(translation_ptr, ctypes.POINTER(wintypes.WORD))[0:2]
    lang_codepage = f"{lang:04x}{codepage:04x}"

    fields = [
        "CompanyName",
        "ProductName",
        "ProductVersion",
        "FileDescription",
        "FileVersion",
    ]
    results = {}
    for field in fields:
        value_ptr = ctypes.c_wchar_p()
        value_len = wintypes.UINT()
        sub_block = f"\\StringFileInfo\\{lang_codepage}\\{field}"
        if ctypes.windll.version.VerQueryValueW(
            buffer, sub_block, ctypes.byref(value_ptr), ctypes.byref(value_len)
        ):
            if value_ptr.value:
                results[field] = value_ptr.value
    return results or None


def _get_pe_architecture(installer_path: Path) -> Optional[str]:
    """Detect PE architecture (x86/x64) from the EXE header."""
    try:
        with open(installer_path, "rb") as handle:
            handle.seek(0x3C)
            pe_offset_bytes = handle.read(4)
            if len(pe_offset_bytes) != 4:
                return None
            pe_offset = int.from_bytes(pe_offset_bytes, "little")
            handle.seek(pe_offset)
            signature = handle.read(4)
            if signature != b"PE\x00\x00":
                return None
            machine_bytes = handle.read(2)
            if len(machine_bytes) != 2:
                return None
            machine = int.from_bytes(machine_bytes, "little")
    except OSError:
        return None

    if machine == 0x014C:
        return "x86"
    if machine == 0x8664:
        return "x64"
    return None


def _clean_value(value: Optional[str], fallback: str) -> str:
    """Normalize optional metadata values with trimming and fallback."""
    if not value:
        return fallback
    value = value.strip()
    return value or fallback


def _safe_join(*parts: str) -> str:
    """Join parts into a safe path-like string with sanitization."""
    safe_parts = []
    for part in parts:
        cleaned = (part or "").strip() or UNKNOWN_VALUE
        safe_parts.append(_sanitize_path_component(cleaned))
    return "/".join(safe_parts)


def _sanitize_path_component(value: str) -> str:
    """Strip invalid filesystem characters from a path component."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join("_" if ch in invalid_chars else ch for ch in value)
    return sanitized.strip() or UNKNOWN_VALUE


def _hash_file(file_path: Path, algorithm: str) -> str:
    """Hash a file using the named hashlib algorithm."""
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from None

    try:
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        raise

    return hasher.hexdigest()
