"""
Configuration file for Software Packaging Utility

This file contains all configurable variables that are not sensitive credentials.

Config sections:
- File and directory settings: project roots and local app directories.
- Retention period settings: age thresholds (days) for retention logic.
- Configuration file paths: vendor/software name JSON inputs.
- Software paths: mapped storage locations for source, staging, packaging, approval, and archive.
- Logging level settings: application log verbosity.
- Reporting output settings: CSV output locations for reports.
- Retention exception lists: CSV files that exempt items from retention rules.
"""

# Imports
from pathlib import Path

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
FILE_PATHS_BUSINESS_AREAS = SETTINGS_DIR / "business_areas.json"

# Software paths (UNC-mapped to a local drive, e.g., D:\)
SOFTWARE_PATHS_SOURCE = Path("D:/Software_Packaging/Source")
SOFTWARE_PATHS_SCAN_REQUESTS = SOFTWARE_PATHS_SOURCE / "Scan_Requests"
SOFTWARE_PATHS_MANUAL_INSTALLS = SOFTWARE_PATHS_SOURCE / "Manual_Installs"
SOFTWARE_PATHS_PACKAGED = Path("D:/Software_Packaging/Packaged_Applications")
SOFTWARE_PATHS_STAGING = Path("D:/Software_Packaging/Packaged_Staging")
SOFTWARE_PATHS_PACKAGE_PREP = Path("D:/Software_Packaging/Package_Prep")
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
