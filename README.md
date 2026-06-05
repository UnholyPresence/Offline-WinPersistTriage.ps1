# Offline-WinPersistTriage.ps1

Read-only PowerShell triage for common Windows persistence mechanisms and practical indicators of compromise on an offline Windows disk.

This script is intended for blue-team incident response, IR triage, malware persistence review, lab analysis, and post-compromise validation where the Windows installation is mounted as an offline volume on an analyst workstation.

> **Design goal:** report suspicious persistence and IOC artifacts without changing the target disk.

---

## Quick start

powershell
# Basic table output to console
.\Offline-WinPersistTriage.ps1 -TargetPath E:\ -Format Table

# JSON report written to analyst workstation
.\Offline-WinPersistTriage.ps1
  -TargetPath E:\Windows
  -Format Json
  -OutFile C:\Cases\host01_triage.json

# CSV report with event log parsing
.\Offline-WinPersistTriage.ps1
  -TargetPath E:\
  -Format Csv
  -OutFile C:\Cases\host01_triage.csv
  -ParseEvents

# Broader file IOC sweep
.\Offline-WinPersistTriage.ps1
  -TargetPath E:\
  -Format Json
  -OutFile C:\Cases\host01_deep_triage.json
  -ParseEvents
  -DeepFileScan

---

## Core features

* Inspects offline Windows registry hives without loading the original evidence hives.
* Copies registry hives to analyst temp storage before loading them.
* Checks common HKLM and HKCU persistence locations.
* Reviews services, drivers, scheduled tasks, Startup folders, PowerShell artifacts, WMI strings, Prefetch names, Amcache entries, hosts file entries, PortProxy, LSA packages, print monitors, and COM hijack indicators.
* Optional offline EVTX parsing.
* Optional deeper file IOC sweep.
* Outputs Table, Json, or Csv.
* Refuses to write reports under the target volume root.

---

## Important forensic note

The script is designed not to write to the target disk, but the safest workflow is still to mount the disk read-only or use a forensic write blocker. The script itself avoids target writes, but the storage layer should enforce read-only access whenever evidence handling matters.

---

## Parameters

| Parameter         | Required | Default  | Description                                                                             |
| ----------------- | -------: | -------- | --------------------------------------------------------------------------------------- |
| `-TargetPath`     |      Yes | None     | Mounted Windows volume root, such as `E:\`, or Windows directory, such as `E:\Windows`. |
| `-Format`         |       No | `Table`  | Output format: `Table`, `Json`, or `Csv`.                                               |
| `-OutFile`        |       No | None     | Optional report path. Must not be under the target volume.                              |
| `-ParseEvents`    |       No | Disabled | Parses selected offline EVTX logs for persistence-relevant events.                      |
| `-EventDaysBack`  |       No | `90`     | Number of days back for event log parsing.                                              |
| `-DeepFileScan`   |       No | Disabled | Recursively scans common writable/staging paths for suspicious files.                   |
| `-MaxFileResults` |       No | `5000`   | Maximum file findings returned by deep scan.                                            |
| `-KeepTemp`       |       No | Disabled | Keeps copied temp hives for debugging.                                                  |

---

## Output schema

Each finding contains:

| Field      | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `TimeUtc`  | Time the finding was generated.                                      |
| `Target`   | Resolved offline Windows path.                                       |
| `Severity` | `Info`, `Low`, `Medium`, `High`, or `Critical`.                      |
| `Category` | Finding category.                                                    |
| `Artifact` | Specific artifact name.                                              |
| `Location` | Registry path, file path, or event log path.                         |
| `Value`    | Relevant command, value, filename, event message, or IOC text.       |
| `Notes`    | Context, indicators, hashes, signatures, timestamps, or parse notes. |
| `Source`   | Source context, usually `Offline disk`.                              |

---

## Recommended workflow

1. Mount the target Windows disk read-only.
2. Run PowerShell as Administrator on the analyst workstation.
3. Save reports to an analyst-controlled case directory.
4. Start with JSON output for preservation and later parsing.
5. Review `High` and `Medium` findings first.
6. Validate suspicious items against timeline, user context, hashes, signatures, paths, and known-good baselines.

Suggested first-pass command:

powershell
.\Offline-WinPersistTriage.ps1 
  -TargetPath E:\ 
  -Format Json 
  -OutFile C:\Cases\host01\offline-persistence-triage.json 
  -ParseEvents

Suggested expanded command:

powershell
.\Offline-WinPersistTriage.ps1 
  -TargetPath E:\ 
  -Format Json 
  -OutFile C:\Cases\host01\offline-persistence-triage-deep.json 
  -ParseEvents 
  -EventDaysBack 180 
  -DeepFileScan 
  -MaxFileResults 10000


---

## Limitations

This is a triage collector, not a full forensic reconstruction tool.

Known limitations:

* WMI repository review is string-based only.
* Prefetch review is filename-based only.
* Amcache results vary by Windows version and artifact availability.
* Event log parsing depends on log retention and audit policy.
* PowerShell history may be absent, cleared, disabled, or user-specific.
* Severity is heuristic and should not be treated as a final verdict.
* Some mechanisms require deeper parsing with dedicated forensic tooling.

---

## Safety notes

* Do not run against original evidence unless the disk is mounted read-only or protected by a write blocker.
* Do not save output to the target disk.
* Treat findings as leads, not proof.
* Validate with additional tools before containment, eradication, or formal reporting decisions.
