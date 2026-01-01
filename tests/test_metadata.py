# tests/test_metadata.py
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from src.utils.metadata_extractor import (
    extract_installer_metadata,
    build_package_directory_name,
    build_package_build_name,
    build_package_info_text,
)

def run(path_str: str) -> None:
    path = Path(path_str)
    metadata = extract_installer_metadata(path)
    print(metadata)
    print("Directory name:", build_package_directory_name(metadata))
    print("Build name:", build_package_build_name(metadata))
    print("PackageInfo.txt:\n", build_package_info_text(metadata))

if __name__ == "__main__":
    run(r"C:\Users\Matty\OneDrive\Projects\software-packaging-utilities\tests\files\Calibre.Calibre.x64_8_13_0.Matty.msi")
    run(r"C:\Users\Matty\OneDrive\Projects\software-packaging-utilities\tests\files\Microsoft.Visual_Studio_Code.x64_1_106_3.Matty.exe")
    run(r"C:\Users\Matty\OneDrive\Projects\software-packaging-utilities\tests\files\Piriform_Software.CCleaner.x64.7_1_1066.Matty.exe")
