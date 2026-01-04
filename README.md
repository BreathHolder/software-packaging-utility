# Software Packaging Utilities

![software packaging utility](./images/SPU-Logo-Square-256.png)

A Python application for package managing application source, standardize application storeage, and create reporting for standard adherence.

## Features

- **Package Info File Creator**: Load an installer, review metadata, and generate `PackageInfo.txt`.
- **Package Info File Updater**: Import an existing `PackageInfo.txt`, edit fields, and save updates.
- **Package Staging Builder**: Prepares a standardized folder structure for packaging.
- **Package Documentation Builder**: Generates documentation for the package.
- **Dependency Manager**: Manages and tracks software dependencies.
- **Configurable Settings**: Configure source/packaging paths, settings file sources, and content age from the Settings tab.
- **Robust Error Handling**: Comprehensive error handling and logging, with breakouts for distinct error logging and function execution results.
- **Type Safety**: Ensure type checking to prevent bottle-necked processes.
- **Testing**: Includes a testing harness and tests for metadata extraction and screen source information.

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

### 3. Basic Usage

Run the utilities app from the project root:

```bash
python -m src.main
```

Or use the VS Code task:

- Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS)
- Type "Tasks: Run Task"
- Select "Run Software Packaging Utilities"

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
│       ├── dependency_manager.py
│       ├── metadata_extractor.py
│       ├── package_builder.py
│       ├── package_documentation_builder.py
│       ├── package_info_creator.py
│       ├── package_info_updater.py
│       ├── package_renamer.py
│       ├── package_staging_builder.py
│       ├── reporting.py
│       ├── screen_source_info.py
│       ├── settings.py
│       └── ui_feedback.py
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
├── .gitignore
├── README.md
├── requirements.txt
└── spu-logo.ico
```

## Configuration

The application's behavior can be customized by editing the JSON files in the `settings` directory.

### `settings.json`
Configures paths, logging levels, and other general settings.

### `vendor_names.json`, `software_names.json`, `dependency_names.json`
These files contain lists of vendors, software, and dependencies used throughout the application. Add or remove entries as needed, following the JSON array format.

**Example `vendor_names.json`:**
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

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_main.py
```

### Code Quality

```bash
# Format code with Black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Lint with flake8
flake8 src/ tests/
```
