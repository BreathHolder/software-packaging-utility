"""Manual test harness for SourceInfoScreen."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.metadata_extractor import extract_installer_metadata
from src.utils.screen_source_info import SourceInfoScreen


def main() -> None:
    screen = SourceInfoScreen()
    installer_path = screen.browse_source_file()
    metadata = extract_installer_metadata(installer_path)
    updated = screen.screen(metadata)
    print(updated)


if __name__ == "__main__":
    main()
