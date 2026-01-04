# Software Packaging Utilities Requirements

The following are a set of features used to standardize software packaging and reporting processes.

## Features & Priorities

- [ ] Settings
  - [X] Retention Period Configurations (days)
    - [X] Scan Requests
    - [X] Manual Installs
    - [X] Packaged Applications
    - [X] Packaged Staging
    - [X] Archive
  - [X] Configuration File Paths
    - [X] Vendor Names
    - [X] Software Names
  - [X] Software Paths
    - [X] Source
    - [X] Packaged
    - [X] Staging
    - [X] Archive
  - [X] Logging Level
  - [ ] Log Management & Rolling
- [ ] Dependency Management
  - [ ] Dependency Picklist
  - [ ] Dependency Details: Name & Path Updates
- [ ] Source to Package Staging Buildout
  - [ ] Directory Structure Build
  - [ ] File Creations
  - [ ] Email Notification to Technology Owner and Requestor
- [ ] Package Staging to Packaged Applications Buildout
- [X] PackageInfo file Creator
  - [X] Request Info Inclusion
  - [X] Technology Owner Info Inclusion
  - [X] Binary Info Inclusion
  - [X] Vulnerability Scan Info Inclusion
  - [X] SHA Hash Info Inclusion
  - [X] Dependency Info Inclusion
- [X] PackageInfo file Updater
- [ ] Reporting
  - [ ] Scan Requests
  - [ ] Manual Installs
  - [ ] Packaged Applications

## Settings

- Retention Period Configuration: Scan Requests ➡️ Store an integer and take a range from 0 to 180 (days).
- Retention Period Configuration: Manual Installs ➡️ Store an integer and take a range from 0 to 365 (days).
- Retention Period Configuration: Packaged Applications ➡️ Store an integer and take a range from 0 to 365 (days).
- Configuration File Paths
  - Vendor Names ➡️ Provide a browse button and allow copy and paste of path to json file for vendor names.
  - Software Names ➡️ Provide a browse button and allow copy and paste of path to json file for software names.
- Software Paths
  - Source ➡️ Provide a browse button and allow copy and paste of path to directory for `Source`.
  - Scan_Requests ➡️ Should be derived from `Source` path as `Source/Scan_Requests`. While displayed, should not be editable.
  - Manual_Installs ➡️ Should be derived from `Source` path as `Source/Manual_Installs`. While displayed, should not be editable.
  - Packaged_Applications ➡️ Provide a browse button and allow copy and paste of path to directory for `Packaged_Applications`.
  - Staging ➡️ Provide a browse button and allow copy and paste of path to directory for `Staging`.
  - Archive ➡️ Provide a browse button and allow copy and paste of path to directory for `Archive`.
- Logging Level

## Source to Package Staging Buildout

- Directory Structure Build:
  - **Build Location Toggle**: One toggle switch which defaults to `Standard Build` but can be toggled to `Root Build`, removing the `Build` directory from the directory structure build.
  - **Current Build File Directory**: Provide a browse button and allow copy and paste of path to directory for `Current Build File Directory`. All content within this directory will be put in the `Build` directory or
- File Creations:
- Dependancies:

## Reporting

- Scan Requests
- Manual Installs
- Packaged Applications

## Desired Directory Paths

```text
package_root/
├── Source/                                     # Source content before packaging.
│   ├── Scan_Requests/                          # Requests to scan binaries.
│   │   └── request_id/                         # Directory name should match the RITM ID for the scan request.
│   │       ├── binary.exe                      # File to be scanned.
│   │       └── Request_Info.txt                # Text file containing basic request information.
│   └── Manual_Installs/                        # Binaries that are not packaged or too few installs to warrant packaging.
│       └── vendor_name/                        # Directory name should match the vendor name.
│           └── software_name/                  # Directory name should match the software name.
│               └── version_architecture_LOB/   # Directory name should match the software version, architecture, and LOB.
│                   ├── binary.exe              # File to be installed.
│                   ├── Readme.txt              # Text file containing instructions for install.
│                   └── Request_Info.txt        # Includes RITM or official scan results.
├── Packaged_Applications/                      # Official packaged applications.
│   └── dependency_management/                  # Parent directory for dependencies that will be copied into individual packaging folders.
│   └── vendor_name/                            # Directory name should match the vendor name.
│       └── software_name/                      # Directory name should match the software name.
│           └── version_architecture_LOB/       # Directory name should match the software version, architecture, and LOB.
│               ├── build_files/                # Supporting build inputs used to create the packaged app.
│               │   ├── binary.exe              # Source installer binary used for the build.
│               │   ├── binary_config.txt       # Config or transforms applied to the installer.
│               │   ├── vendor_docs.txt         # Vendor documentation for configurations needed in packaging.
│               │   └── Request_Info.txt        # Request metadata tied to the build.
│               ├── dependencies/               # Dependencies required by the packaged app.
│               │   ├── dependencies.txt        # Text manifest of required dependencies.
│               │   └── dependencies.exe        # Optional dependency installer binary.
│               ├── Packaged_App.exe            # Final packaged application.
│               ├── Package_Info.txt            # Packaging metadata and notes.
│               ├── Readme.txt                  # Notes for deployment or validation.
│               ├── prefetch.txt                # Prefetch data file generated from a script, denoting the Artifactory file path for the official package.
│               └── Request_Info.txt            # Request metadata for this packaged app.
├── Packaged_Staging/                           # Working area for building packages.
├── Archive/                                    # Archived content by source/type and retention policy.
│   ├── Manual_Installs/                        # Source apps older than $retention_manual_installs days.
│   ├── Scan_Requests/                          # Source scan requests older than $RETENTION_SCAN_REQUESTS days.
│   └── Packaged_Applications/                  # Packaged apps older than $retention_packaged_apps days.
```

## PackageInfo.txt Information

The following information is collected in the "Package Info File Creator" and "Updater" tabs. The data is gathered through a combination of automated extraction from the installer and manual user input via the UI.

### Manual Fields

These fields require direct user input.

- **Request ID**: Manual text entry.
- **Requestor Name**: Manual text entry.
- **Software Reference ID**: Manual text entry.
- **Software Technology Owner ID**: Manual text entry.
- **Licensed Software Flag**: Selected from a dropdown menu with options:
  - `No`
  - `Version Specific`
  - `Newest+ N-1`
- **Software Dependencies**: Selected from a predefined list. An "Other" option allows for manual entry of unlisted dependencies. A "No dependencies" checkbox is also available.
- **Software Vulnerability Scan Results**: The status is selected from a dropdown menu. If a scan was performed, a text box appears for pasting the detailed scan results.
  - `Scan results found. No vulnerabilities found`
  - `Scan results found. Vulnerabilities found and accepted by technology owner`
  - `Scan results NOT found. Binary scan required prior to packaging`

### Automated Metadata

These fields are automatically populated by analyzing the source installer file (`.msi`, `.exe`). Most can be manually overridden by the user if the extracted data is incorrect.

- **Software Vendor**: Automatically extracted. Can be manually changed by selecting a different vendor from a dropdown list or adding a new one.
- **Software Name**: Automatically extracted. Can be in manually changed by selecting a different name from a dropdown list or adding a new one.
- **Software Version**: Automatically extracted. The value can be manually edited in a text field.
- **Software Architecture**: Automatically extracted. Can be manually changed by selecting from a dropdown (`x86`, `x64`).
- **Software SHA1 Hash**: Automatically extracted. This field is read-only.
- **Software SHA256 Hash**: Automatically extracted. This field is read-only.

When a package is sent to the packagers, the PackageInfo.txt file should be created and sent with the request. If not, all required information must be documented within the packaging request for the packager.

## Feature Requests

### Packaging Communication

Prior to packaging, the PackageInfo.txt file must be used to generate templated communication to the requestor and the technology owner that the packaging has been requested and will commence via the request ID given.

When packaging, send email notification to Requestor & Technology Owner from a template, through the Software Packaging Utility, using the user's email client (assuming x86 architecture).

### Symbolic Links for Citrix Packages

For Citrix packages, there should be a symbolic link to the original package build with content included that is specific to Citrix itself.
