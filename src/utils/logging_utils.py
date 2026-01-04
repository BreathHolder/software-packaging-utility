"""Helpers for log file size management."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.config import LOGGING_DIR, SETTINGS_DIR

DEFAULT_LOG_SIZE_MB = 5


def append_text_log(path: Path, line: str) -> None:
    """Append a line to a log, rotating when size would exceed limit."""
    LOGGING_DIR.mkdir(parents=True, exist_ok=True)
    payload = f"{line}\n" if not line.endswith("\n") else line
    _rotate_if_needed(path, len(payload.encode("utf-8")))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(payload)


def append_csv_log(path: Path, header: list[str], row: list[str]) -> None:
    """Append a row to a CSV log, rotating when size would exceed limit."""
    LOGGING_DIR.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()
    row_payload = _format_csv_row(header if write_header else None, row)
    _rotate_if_needed(path, len(row_payload.encode("utf-8")))
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(header)
        writer.writerow(row)


def _format_csv_row(header: list[str] | None, row: list[str]) -> str:
    """Render a CSV header + row to a string for size estimation."""
    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer)
    if header is not None:
        writer.writerow(header)
    writer.writerow(row)
    return buffer.getvalue()


def _rotate_if_needed(path: Path, incoming_bytes: int) -> None:
    """Rotate a log file if the next write would exceed the size limit."""
    max_bytes = _get_log_size_limit_bytes()
    try:
        current_size = path.stat().st_size
    except OSError:
        current_size = 0
    if current_size + incoming_bytes <= max_bytes:
        return
    backup = path.with_suffix(path.suffix + ".1")
    try:
        if backup.exists():
            backup.unlink()
        if path.exists():
            path.rename(backup)
    except OSError:
        pass


def _get_log_size_limit_bytes() -> int:
    """Return the configured log size limit in bytes."""
    settings = _load_settings()
    value = settings.get("log_size_limit_mb")
    if isinstance(value, int) and value > 0:
        return value * 1024 * 1024
    return DEFAULT_LOG_SIZE_MB * 1024 * 1024


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
