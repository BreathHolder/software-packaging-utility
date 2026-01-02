# Software Packaging Utilities

![software packaging utility](./images/SPU-Logo-Square-256.png)

A Python application for package managing application source, standardize application storeage, and create reporting for standard adherence.

## Features

- **Configurable Settings**: Configure source/packaging paths, settings file sources, and content age from the Settings tab.
- **Robust Error Handling**: Comprehensive error handling and logging, with breakouts for distinct error logging and function execution results.
- **Type Safety**: Ensure type checking to prevent bottle-necked processes.
- **Testing**:

## Prerequisites

Before using Software Package Utilities, you'll need to set up the following:

### Python 3.9x

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/breathholder/software-package-utilities.git
cd software-package-utilities
```

### 2. Set Up Virtual Environment

Create and activate a virtual environment, then install dependencies from `requirements.txt`.

```bash
python -m venv .venv
.venv/Scripts/activate  # Windows
# or
source .venv/bin/activate  # macOS/Linux

python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Settings

Edit `settings/vendor_names.json` and add the vendor list with one vendor name, in quotes, per line. Add a comma after the quoted vendor name on every line execpt the last line:

```json
[
  "Adobe",
  "Cisco",
  "Google",
  "Microsoft",
  "Mozilla",
  "Piriform"
]
```

Edit `settings/software_names.json` and add the software list with one software name, in quotes, per line. Add a comma after the quoted software name on every line execpt the last line:

```json
[
  "Photoshop",
  "Premiere",
  "AnyConnect",
  "Windows 11",
  "Word",
  "Excel",
  "PowerPoint",
  "Firefox",
  "CCleaner"
]
```

## Usage

### Basic Usage

Run the utilities app from the project root:

```bash
python -m src.main
```

Or use the VS Code task:

- Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS)
- Type "Tasks: Run Task"
- Select "Run Software Packaging Utilities"

### What the Script Does

- **Package Info File Creator**: Load an installer, review metadata, and generate `PackageInfo.txt`.
- **Package Info File Updater**: Import an existing `PackageInfo.txt`, edit fields, and save updates.
- **Settings**: Configure base paths, content age (days), and the source for JSON settings files (local or GitHub).

## Configuration

The application uses multiple configuration files:

### Environment Variables (`.env`)

### Application Settings (`src/config.py`)

```python
# File and directory settings
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_DIR = PROJECT_ROOT / "settings"
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGGING_DIR = PROJECT_ROOT / "logs"
RETENTION_EXCEPTIONS_DIR = PROJECT_ROOT / "retention"

# Retention period settings (days)
RETENTION_SCAN_REQUESTS = 30
RETENTION_MANUAL_INSTALLS = 90
RETENTION_PACKAGED_APPLICATIONS = 366

# Configuration file paths
FILE_PATHS_VENDOR_NAMES = SETTINGS_DIR / "vendor_names.json"
FILE_PATHS_SOFTWARE_NAMES = SETTINGS_DIR / "software_names.json"
FILE_PATHS_DEPENDENCY_NAMES = SETTINGS_DIR / "dependency_names.json"

# Software paths (UNC-mapped to a local drive, e.g., D:\)
SOFTWARE_PATHS_SOURCE = Path("D:/Software_Packaging/Source")
SOFTWARE_PATHS_SCAN_REQUESTS = SOFTWARE_PATHS_SOURCE / "Scan_Requests"
SOFTWARE_PATHS_MANUAL_INSTALLS = SOFTWARE_PATHS_SOURCE / "Manual_Installs"
SOFTWARE_PATHS_PACKAGED = Path("D:/Software_Packaging/Packaged_Applications")
SOFTWARE_PATHS_STAGING = Path("D:/Software_Packaging/Packaged_Staging")
SOFTWARE_PATHS_PENDING_PROJECT_APPROVAL = Path(
    "D:/Software_Packaging/Pending_Project_Approval"
)
SOFTWARE_PATHS_ARCHIVE = Path("D:/Software_Packaging/Archive")

# Logging level settings
LOGGING_LEVEL = "INFO"

# Reporting output settings
REPORTING_OUTPUT_SCAN_REQUESTS = REPORTS_DIR / "scan_requests.csv"
REPORTING_OUTPUT_MANUAL_INSTALLS = REPORTS_DIR / "manual_installs.csv"
REPORTING_OUTPUT_PACKAGED_APPLICATIONS = REPORTS_DIR / "packaged_applications.csv"

# Retention exception lists (CSV per category)
RETENTION_EXCEPTIONS_MANUAL_INSTALLS = (
    RETENTION_EXCEPTIONS_DIR / "exception_manual_installs.csv"
)
RETENTION_EXCEPTIONS_PACKAGED_APPLICATIONS = (
    RETENTION_EXCEPTIONS_DIR / "exception_packaged_applications.csv"
)
RETENTION_EXCEPTIONS_PENDING_PROJECT_APPROVAL = (
    RETENTION_EXCEPTIONS_DIR / "exception_pending_project_approval.csv"
)
RETENTION_EXCEPTIONS_ARCHIVE = RETENTION_EXCEPTIONS_DIR / "exception_archive.csv"
```

## Project Structure

```text
software-packaging-utilities/
├── src/
│   ├── __init__.py
│   ├── main.py                          # Application entry point
│   ├── config.py                        # Configuration constants/paths
│   ├── ui_styles.py                     # Shared ttk styles/colors
│   └── utils/
│       ├── __init__,.py
│       ├── metadata_extractor.py
│       ├── package_builder.py
│       ├── package_info_creator.py
│       ├── package_info_updater.py
│       ├── package_renamer.py
│       ├── reporting.py
│       ├── screen_source_info.py
│       └── settings.py
├── images/
│   ├── SPU-Logo-Square-32.png
│   ├── SPU-Logo-Square-128.png
│   └── ...
├── settings/
│   ├── settings.json
│   ├── vendor_names.json
│   ├── software_names.json
│   └── dependency_names.json
├── tests/
│   ├── __init__.py
│   ├── harness.py
│   ├── test_metadata.py
│   ├── test_screen_source_info.py
│   └── files/                           # location for test files
├── docs/
│   └── app_requirements.md
├── logs/
│   └── json_edit_requests.log
├── build/                               # PyInstaller build artifacts
├── dist/                                # PyInstaller output
├── app.spec                             # PyInstaller spec
├── requirements.txt
├── rocket-gear.ico
├── LICENSE                              # MIT License
└── README.md                            # 👇 This is where you currently are
```

## Development

### Running Tests (not built yet)

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_main.py
```

### Code Quality (not built yet)

```bash
# Format code with Black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Lint with flake8
flake8 src/ tests/
```

## Troubleshooting (not built yet)

### Common Issues (not built yet)

## Prerequisites

- Python 3 installed (or use the packaged `app.exe` built with PyInstaller --not implemented yet).
- No network access required. Logs are written locally in `logs/`.

## Configure settings (not built yet)

### General (not built yet)

1. Logging Levels
2. Directory Path Defaults
3. JSON File Path Configuration (local vs. GH)

### Scanning (not built yet)

1. Scanning: Time-to-Live (days) by Path

## Utility 1: PackageInfo.txt File Builder

- **Purpose**: Streamlines the creation of `PackageInfo.txt` files, which are essential for standardizing software packaging. This tool provides a user-friendly interface to:
  - **Automate Metadata Extraction**: Automatically loads an installer file (`.msi`, `.exe`) and extracts key metadata such as software version, architecture, and cryptographic hashes (SHA1/SHA256).
  - **Standardize Data Entry**: Offers structured fields for manually entering required information, including request details, licensing, software dependencies, and vulnerability scan results.
  - **Prepare for Packaging**: Optionally creates a standardized folder structure for the package, moving the source installer and the newly generated `PackageInfo.txt` into a dedicated directory.

## Utility 2: Package Directory Builder

- **Purpose**:

## Utility 3: Settings Management

- **Purpose**: Provides a centralized UI to configure the application's core settings, which are persisted in `settings/settings.json`. This includes:
  - **Path Configuration**: Define the root paths for software source, packaging, staging, and archives.
  - **Logging Level**: Set the application's logging verbosity (Debug, Info, Warn, Error).
  - **Content Retention Policies**: Set the maximum age (in days) for content in different directories before it's flagged for review or cleanup.
  - **Picklist Source Management**: Choose whether to load picklists (for vendors, software names, etc.) from local `.json` files or from a remote GitHub repository, allowing for centralized management of these lists.

## Utility 4: Scan & Report Generation

### Standard Adherence

- **Purpose**:

### Picklist Deviations & Updates

- **Purpose**:

### Package Clean-Up

- **Purpose**:
