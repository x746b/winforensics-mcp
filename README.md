<p align="center">
  <img src="icon.png" width="150" alt="WinForensics MCP">
</p>

# Windows Forensics MCP Server

A comprehensive **Model Context Protocol (MCP)** server for Windows digital forensics, enabling AI-assisted analysis of Windows artifacts directly from Claude CLI or any MCP-compatible client.

## Features

### Logs & Configuration (v0.1.0)
- **EVTX Parsing** - Windows Event Log analysis with filtering, search, and pre-built security queries
- **Registry Analysis** - Parse SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT hives
- **Remote Collection** - Collect artifacts via WinRM with password or pass-the-hash authentication
- **Forensic Reference** - Built-in knowledge of important Event IDs and registry keys

### Execution Artifacts (v0.2.0)
- **PE Analysis** - Static analysis of Windows executables with hash calculation, import/export extraction, packer detection, and suspicious API identification
- **Prefetch Parsing** - Execution evidence with run counts, timestamps, and loaded files
- **Amcache Analysis** - SHA1 hashes and first-seen timestamps from Amcache.hve
- **SRUM Analysis** - Application resource usage, CPU time, and network activity from SRUDB.dat
- **Execution Investigation** - Orchestrator that correlates Prefetch, Amcache, and SRUM to answer "Was this binary executed?"

### File System Artifacts (v0.2.0)
- **MFT Parsing** - Master File Table analysis with timestomping detection
- **USN Journal** - Change journal parsing for file operations and deleted file recovery
- **Timeline Builder** - Unified timeline from MFT, USN, Prefetch, Amcache, and EVTX

### User Activity (v0.2.0)
- **Browser History** - Edge, Chrome, and Firefox history/downloads parsing
- **LNK Files** - Windows shortcut analysis for recently accessed files
- **ShellBags** - Folder navigation history from UsrClass.dat with suspicious path detection

---

## Installation

### Prerequisites

```bash
# Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# Ensure Python 3.10+
python3 --version
```

### Install the Package

```bash
# Clone the repository
git clone https://github.com/x746b/winforensics-mcp.git
cd winforensics-mcp

# Create virtual environment and install
uv venv
source .venv/bin/activate
uv pip install -e .

# For remote collection support (WinRM, SSH, SMB):
uv pip install -e ".[remote]"
```

### Verify Installation

```bash
python -m winforensics_mcp.server
# Should start without errors (Ctrl+C to exit)
```

---

## Adding to Claude CLI

### Method 1: Using `claude mcp add` (Recommended)

```bash
claude mcp add winforensics-mcp \
  --scope user \
  -- uv run --directory /path/to/winforensics-mcp python -m winforensics_mcp.server
```

### Method 2: Manual JSON Configuration

Edit `~/.claude.json`:

```json
{
  "mcpServers": {
    "winforensics-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/winforensics-mcp",
        "python",
        "-m",
        "winforensics_mcp.server"
      ]
    }
  }
}
```

### Verify

```bash
claude mcp list
# Should show winforensics-mcp
```

---
## Adding to Gemini CLI

### Method 1: Using `gemini mcp add` (Recommended)

```bash
gemini mcp add winforensics-mcp "uv" --scope user -- run --directory /opt/winforensics-mcp python -m winforensics_mcp.server
```

---

## Tool Reference

### EVTX Tools

| Tool | Description |
|------|-------------|
| `evtx_list_files` | List EVTX files in a directory |
| `evtx_get_stats` | Get event counts, time range, Event ID distribution |
| `evtx_search` | Search with filters (time, Event ID, keywords) |
| `evtx_security_search` | Pre-built security event searches |
| `evtx_explain_event_id` | Get Event ID description |

### Registry Tools

| Tool | Description |
|------|-------------|
| `registry_get_key` | Get specific key and values |
| `registry_search` | Search values by pattern |
| `registry_get_persistence` | Get Run keys and services |
| `registry_get_users` | Get user accounts from SAM |
| `registry_get_usb_history` | Get USB device history |
| `registry_get_system_info` | Get OS version, hostname, timezone |
| `registry_get_network` | Get network configuration |

### Execution Artifact Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `file_analyze_pe` | Static PE analysis - hashes, imports, exports, packer detection |
| `disk_parse_prefetch` | Parse Prefetch files for execution evidence |
| `disk_parse_amcache` | Parse Amcache.hve for SHA1 hashes and timestamps |
| `disk_parse_srum` | Parse SRUDB.dat for app resource and network usage |
| `investigate_execution` | Correlate all execution artifacts for comprehensive analysis |

### File System Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `disk_parse_mft` | Parse $MFT for file metadata and timestomping detection |
| `disk_parse_usn_journal` | Parse $J for file operations and deleted files |
| `build_timeline` | Build unified timeline from multiple artifact sources |

### User Activity Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `browser_get_history` | Parse Edge/Chrome/Firefox history and downloads |
| `user_parse_lnk_files` | Parse Windows shortcuts for target paths and timestamps |
| `user_parse_shellbags` | Parse ShellBags for folder navigation history |

### Reference Tools

| Tool | Description |
|------|-------------|
| `forensics_list_important_events` | List important Event IDs by channel |
| `forensics_list_registry_keys` | List forensic registry keys by category |

### Remote Tools

| Tool | Description |
|------|-------------|
| `remote_collect_artifacts` | Collect artifacts via WinRM (password or pass-the-hash) |
| `remote_get_system_info` | Get remote system info |

---

## Usage Examples

### Execution Analysis (v0.2.0)

#### Investigate Binary Execution

**Request:**
```
Was mimikatz.exe ever executed? Check the artifacts in /mnt/evidence
```

**Output:**
```json
{
  "target": "mimikatz.exe",
  "execution_confirmed": true,
  "confidence": "HIGH",
  "evidence": [
    {
      "source": "Prefetch",
      "found": true,
      "finding": "Executed 3 times, last at 2024-03-15T14:23:45Z",
      "run_count": 3
    },
    {
      "source": "Amcache",
      "found": true,
      "finding": "SHA1: abc123..., First seen: 2024-03-14T09:00:00Z"
    },
    {
      "source": "SRUM",
      "found": true,
      "finding": "Network activity: 15.2 MB sent; Foreground time: 47 seconds"
    }
  ],
  "timeline": [
    {"time": "2024-03-14T09:00:00Z", "event": "First recorded in Amcache"},
    {"time": "2024-03-15T14:23:45Z", "event": "Last execution (Prefetch)"}
  ],
  "summary": "Execution of 'mimikatz.exe' confirmed (HIGH confidence)"
}
```

#### Analyze a Suspicious PE File

**Request:**
```
Analyze the PE file at /evidence/malware.exe
```

**Output:**
```json
{
  "filename": "malware.exe",
  "hashes": {
    "md5": "abc123...",
    "sha1": "def456...",
    "sha256": "ghi789...",
    "imphash": "jkl012..."
  },
  "pe_type": "PE32+ executable (GUI) x86-64",
  "compile_time": "2024-03-10T08:15:22Z",
  "sections": [
    {"name": ".text", "entropy": 6.2, "suspicious": false},
    {"name": "UPX0", "entropy": 0.0, "suspicious": true}
  ],
  "suspicious_indicators": [
    "UPX packed",
    "Process injection APIs detected (VirtualAllocEx, WriteProcessMemory)",
    "No version info"
  ],
  "imports_summary": {
    "kernel32.dll": ["VirtualAlloc", "CreateThread", "WriteProcessMemory"],
    "ntdll.dll": ["NtUnmapViewOfSection"]
  }
}
```

#### Parse Prefetch Files

**Request:**
```
Show me recent PowerShell executions from the Prefetch directory
```

**Output:**
```json
{
  "searched_executable": "powershell",
  "found": true,
  "total_run_count": 51,
  "execution_evidence": [
    {
      "executable": "POWERSHELL.EXE",
      "prefetch_hash": "913B4D98",
      "run_count": 51,
      "last_run_times": [
        "2025-01-21T01:59:35Z",
        "2025-01-20T18:30:12Z",
        "2025-01-20T15:45:00Z"
      ]
    }
  ]
}
```

#### Check Amcache for Suspicious Tools

**Request:**
```
Search Amcache for any hacking tools
```

**Output:**
```json
{
  "path": "/mnt/evidence/Windows/AppCompat/Programs/Amcache.hve",
  "entries": [
    {
      "name": "BloodHound.exe",
      "sha1": "204bc44c651e17f65c95314e0b6dfee586b72089",
      "path": "c:\\users\\admin\\downloads\\bloodhound.exe",
      "key_timestamp": "2024-12-21T02:25:24Z",
      "suspicious_reason": "Unusual execution path"
    },
    {
      "name": "mimikatz.exe",
      "sha1": "abc123def456...",
      "path": "c:\\temp\\mimikatz.exe",
      "suspicious_reason": "Unusual execution path"
    }
  ]
}
```

#### Analyze Application Resource Usage (SRUM)

**Request:**
```
Show me network activity for suspicious applications from SRUM
```

**Output:**
```json
{
  "table": "Network Data Usage",
  "entries": [
    {
      "executable": "powershell.exe",
      "bytes_sent": 15728640,
      "bytes_received": 52428800,
      "timestamp": "2025-01-20T18:30:00Z"
    },
    {
      "executable": "nc.exe",
      "bytes_sent": 1048576,
      "bytes_received": 2097152,
      "timestamp": "2025-01-20T19:15:00Z"
    }
  ]
}
```

---

### File System Analysis (v0.2.0)

#### Detect Timestomped Files

**Request:**
```
Find timestomped files in the MFT at /mnt/evidence/$MFT
```

**Output:**
```json
{
  "total_timestomped": 3,
  "timestomped_files": [
    {
      "path": "Users\\Alpha\\Downloads\\mimikatz.exe",
      "si_created": "2019-01-15T10:00:00Z",
      "fn_created": "2025-01-20T14:30:00Z",
      "detection_reason": "$SI created before $FN (impossible)"
    },
    {
      "path": "Windows\\Temp\\backdoor.dll",
      "si_created": "2020-06-01T00:00:00Z",
      "fn_created": "2025-01-21T08:15:00Z",
      "detection_reason": "$SI timestamp >1 year older than $FN"
    }
  ]
}
```

#### Find Deleted Files from USN Journal

**Request:**
```
Find deleted executable files from the USN journal
```

**Output:**
```json
{
  "output_mode": "deleted_files",
  "extension_filter": ".exe",
  "deleted_files": [
    {
      "filename": "SharpHound.exe",
      "timestamp": "2025-01-20T15:45:00Z",
      "mft_entry": 123456,
      "parent_entry": 78901
    },
    {
      "filename": "mimikatz.exe",
      "timestamp": "2025-01-20T16:00:00Z",
      "mft_entry": 234567
    }
  ]
}
```

#### Build Forensic Timeline

**Request:**
```
Build a timeline from all artifacts in /mnt/evidence for the keyword "mimikatz"
```

**Output:**
```json
{
  "keyword_filter": "mimikatz",
  "total_events": 8,
  "events": [
    {"time": "2025-01-20T14:30:00Z", "source": "MFT", "type": "file_created", "details": "mimikatz.exe"},
    {"time": "2025-01-20T14:31:00Z", "source": "Prefetch", "type": "program_executed", "details": "MIMIKATZ.EXE-ABC123.pf"},
    {"time": "2025-01-20T14:32:00Z", "source": "Amcache", "type": "program_first_seen", "details": "mimikatz.exe"},
    {"time": "2025-01-20T16:00:00Z", "source": "USN", "type": "file_deleted", "details": "mimikatz.exe"}
  ]
}
```

---

### User Activity Analysis (v0.2.0)

#### Parse Browser History

**Request:**
```
Get browser history from the Edge profile, filter for "mega.nz"
```

**Output:**
```json
{
  "browser": "edge",
  "url_filter": "mega.nz",
  "history_count": 2,
  "history": [
    {
      "url": "https://mega.nz/file/abc123",
      "title": "MEGA - Download",
      "visit_time": "2025-01-20T10:15:00Z",
      "visit_count": 1
    }
  ],
  "downloads": [
    {
      "url": "https://mega.nz/file/abc123",
      "target_path": "C:\\Users\\Alpha\\Downloads\\DC-Scan.ps1",
      "start_time": "2025-01-20T10:15:30Z",
      "total_bytes": 15420,
      "dangerous_type": "DANGEROUS_FILE"
    }
  ]
}
```

#### Analyze ShellBags for Suspicious Folder Access

**Request:**
```
Check ShellBags for suspicious folder access by user Alpha
```

**Output:**
```json
{
  "total_suspicious": 4,
  "suspicious_folders": [
    {
      "path": "My Computer\\C:\\Windows\\Temp",
      "last_viewed": "2025-01-20T14:30:00Z",
      "reason": "Suspicious path pattern: \\temp"
    },
    {
      "path": "My Computer\\Downloads\\mimikatz_trunk",
      "last_viewed": "2025-01-20T14:25:00Z",
      "reason": "Suspicious path pattern: mimikatz"
    },
    {
      "path": "My Computer\\C:\\Users\\Alpha\\AppData\\Roaming",
      "last_viewed": "2025-01-20T14:20:00Z",
      "reason": "Suspicious path pattern: appdata\\roaming"
    }
  ]
}
```

#### Parse LNK Files for Recent File Access

**Request:**
```
Show recently accessed files from user Alpha's Recent folder
```

**Output:**
```json
{
  "user_profile": "/mnt/evidence/Users/Alpha",
  "recent_folder": "/mnt/evidence/Users/Alpha/AppData/Roaming/Microsoft/Windows/Recent",
  "count": 5,
  "recent_files": [
    {
      "filename": "ntds.dit.lnk",
      "target_path": "C:\\Windows\\NTDS\\ntds.dit",
      "timestamps": {
        "creation_time": "2025-01-20T14:00:00Z",
        "modification_time": "2025-01-20T14:00:00Z"
      }
    },
    {
      "filename": "PowerView.ps1.lnk",
      "target_path": "C:\\Users\\Alpha\\Downloads\\PowerView.ps1",
      "timestamps": {
        "creation_time": "2025-01-20T13:45:00Z"
      }
    }
  ]
}
```

---

### Event Log Analysis

#### List Available Event Logs

**Request:**
```
List all EVTX files in /mnt/evidence/Windows/System32/winevt/Logs
```

**Output:**
```json
[
  {
    "name": "Security.evtx",
    "path": "/mnt/evidence/Windows/System32/winevt/Logs/Security.evtx",
    "size_bytes": 69206016,
    "modified": "2025-03-17T20:00:00"
  },
  {
    "name": "System.evtx",
    "path": "/mnt/evidence/Windows/System32/winevt/Logs/System.evtx",
    "size_bytes": 4194304,
    "modified": "2025-03-17T19:55:00"
  }
]
```

#### Search for Failed Logon Attempts

**Request:**
```
Find all failed logon events in Security.evtx
```

**Output:**
```json
{
  "event_type": "failed_logon",
  "count": 12,
  "events": [
    {
      "EventID": 4625,
      "TimeCreated": "2025-03-17T19:46:10Z",
      "TargetUserName": "svc_backup",
      "TargetDomainName": "CORP",
      "LogonType": 3,
      "IpAddress": "192.168.1.50",
      "ProcessName": "C:\\Windows\\Temp\\RunasCs.exe"
    }
  ]
}
```

---

### Registry Analysis

#### Check Persistence Mechanisms

**Request:**
```
Check for persistence in the SOFTWARE and SYSTEM registry hives
```

**Output:**
```json
{
  "run_keys": [
    {
      "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "name": "SecurityHealth",
      "value": "%ProgramFiles%\\Windows Defender\\MSASCuiL.exe",
      "suspicious": false
    }
  ],
  "services": [
    {
      "name": "malicious_svc",
      "image_path": "C:\\Windows\\Temp\\backdoor.exe",
      "start_type": 2,
      "suspicious": true
    }
  ]
}
```

#### Get User Accounts from SAM

**Request:**
```
List all user accounts from the SAM hive
```

**Output:**
```json
{
  "users": [
    {
      "username": "Administrator",
      "rid": 500,
      "last_login": "2025-03-17T19:44:14Z",
      "login_count": 42,
      "account_flags": ["Password Never Expires"]
    },
    {
      "username": "svc_deploy",
      "rid": 1002,
      "created": "2025-03-17T19:47:02Z",
      "login_count": 1
    }
  ]
}
```

---

## Typical Investigation Workflow

### 1. Collect or Mount Evidence

```bash
# Mount Windows image
mount -o ro /dev/sdb1 /mnt/evidence

# Or collect from remote system
"Collect artifacts from 192.168.1.50 user admin to /cases/incident001"
```

### 2. Quick Triage with Execution Investigation

```
"Was mimikatz.exe or powershell.exe executed? Check /mnt/evidence"
```

### 3. Deep Dive on Suspicious Binaries

```
"Analyze the PE file at /mnt/evidence/Windows/Temp/suspicious.exe"
"Search Amcache for files in the Temp folder"
```

### 4. Timeline Analysis

```
"Show me all Prefetch entries sorted by last run time"
"Find process creation events between 2025-01-15T10:00:00Z and 2025-01-15T12:00:00Z"
```

### 5. Persistence Check

```
"Check persistence mechanisms in the SOFTWARE and SYSTEM hives"
"Search registry for references to suspicious paths"
```

### 6. Lateral Movement Detection

```
"Find all logon events with LogonType 3 or 10"
"Show me service installations from the System event log"
```

---

## Important Event IDs Reference

### Security Log

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |
| 4697 | Service Installed |
| 4698-4702 | Scheduled Task Events |
| 4720 | User Account Created |
| 1102 | Audit Log Cleared |

### System Log

| Event ID | Description |
|----------|-------------|
| 7045 | New Service Installed |
| 7036 | Service Started/Stopped |
| 104 | Event Log Cleared |

### Sysmon

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 11 | File Created |
| 12-14 | Registry Events |
| 22 | DNS Query |

---

## Troubleshooting

### "Module not found" errors

```bash
source /path/to/winforensics-mcp/.venv/bin/activate
pip list | grep -E "evtx|registry|mcp|pefile|scca|esedb|mft|pylnk"
```

### "Permission denied" on registry hives

Registry hives may be locked. Either:
- Use offline/copied hives from a mounted image
- Use VSS (Volume Shadow Copy) collection via WinRM

### Missing v0.2.0 tools

Ensure dependencies are installed:
```bash
uv pip install pefile libscca-python libesedb-python mft pylnk3
```

### Remove MCP Server

```bash
claude mcp remove winforensics-mcp --scope user
```

---

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
ruff format .
```

---

## License

MIT License

---

## Credits

- [python-evtx](https://github.com/williballenthin/python-evtx) - EVTX parsing
- [python-registry](https://github.com/williballenthin/python-registry) - Registry parsing
- [pefile](https://github.com/erocarrera/pefile) - PE file analysis
- [libscca-python](https://github.com/libyal/libscca) - Prefetch parsing
- [libesedb-python](https://github.com/libyal/libesedb) - ESE database (SRUM) parsing
- [mft](https://github.com/omerbenamram/mft) - MFT parsing (Rust-based)
- [pylnk3](https://github.com/strayge/pylnk) - LNK file parsing
- [MCP](https://github.com/anthropics/mcp) - Model Context Protocol

__xtk__

