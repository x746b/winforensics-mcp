# Windows Forensics MCP Server

**Author:** xtk

A comprehensive **Model Context Protocol (MCP)** server for Windows digital forensics, enabling AI-assisted analysis of Windows artifacts directly from Claude CLI or any MCP-compatible client.

## Features

- **EVTX Parsing** - Windows Event Log analysis with filtering, search, and pre-built security queries
- **Registry Analysis** - Parse SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT hives
- **Remote Collection** - Collect artifacts via WinRM with password or pass-the-hash authentication
- **Forensic Reference** - Built-in knowledge of important Event IDs and registry keys

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
https://github.com/x746b/winforensics-mcp.git
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

## Usage Examples with Sample Output

### 1. List Available Event Logs

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

### 2. Get Event Log Statistics

**Request:**
```
Show me stats for Security.evtx
```

**Output:**
```json
{
  "file": "Security.evtx",
  "total_events": 15847,
  "time_range": {
    "earliest": "2025-01-15T08:00:00Z",
    "latest": "2025-03-17T19:51:24Z"
  },
  "top_event_ids": {
    "4624": 3521,
    "4625": 847,
    "4634": 3498,
    "4672": 1205,
    "4688": 4892
  }
}
```

### 3. Search for Failed Logon Attempts

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
      "Status": "0xC000006D",
      "SubStatus": "0xC000006A",
      "WorkstationName": "WKS001",
      "IpAddress": "192.168.1.50",
      "ProcessName": "C:\\Windows\\Temp\\RunasCs.exe"
    },
    {
      "EventID": 4625,
      "TimeCreated": "2025-03-17T19:46:14Z",
      "TargetUserName": "admin_ops",
      "TargetDomainName": "CORP",
      "LogonType": 3,
      "Status": "0xC000006D",
      "ProcessName": "C:\\Windows\\Temp\\RunasCs.exe"
    }
  ]
}
```

### 4. Analyze User Accounts from SAM

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
      "created": "2024-08-21T08:27:42Z",
      "last_login": "2025-03-17T19:44:14Z",
      "login_count": 42,
      "password_last_set": "2025-03-17T19:51:23Z",
      "account_flags": ["Password Never Expires"]
    },
    {
      "username": "Guest",
      "rid": 501,
      "created": "2024-08-21T08:27:42Z",
      "last_login": null,
      "login_count": 0,
      "account_flags": ["Account Disabled"]
    },
    {
      "username": "svc_deploy",
      "rid": 1002,
      "created": "2025-03-17T19:47:02Z",
      "last_login": "2025-03-17T19:51:24Z",
      "login_count": 1,
      "account_flags": []
    }
  ]
}
```

### 5. Check Persistence Mechanisms

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
    },
    {
      "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "name": "VMware User Process",
      "value": "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr",
      "suspicious": false
    }
  ],
  "services": [
    {
      "name": "WinDefend",
      "display_name": "Windows Defender Antivirus Service",
      "image_path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2302.7-0\\MsMpEng.exe\"",
      "start_type": 2,
      "suspicious": false
    }
  ],
  "suspicious_count": 0
}
```

### 6. Get System Information

**Request:**
```
What Windows version and computer name from the registry?
```

**Output:**
```json
{
  "computer_name": "WKS001",
  "domain": "corp.local",
  "os": {
    "product_name": "Windows 10 Pro",
    "build": "19041",
    "version": "2004",
    "install_date": "2024-08-21T08:25:00Z"
  },
  "timezone": "Pacific Standard Time",
  "last_shutdown": "2025-03-17T06:00:00Z"
}
```

### 7. Get Network Configuration

**Request:**
```
Show network configuration from SYSTEM hive
```

**Output:**
```json
{
  "interfaces": [
    {
      "name": "Ethernet0",
      "dhcp_enabled": false,
      "ip_address": "192.168.1.50",
      "subnet_mask": "255.255.255.0",
      "default_gateway": "192.168.1.1",
      "dns_servers": ["192.168.1.10", "192.168.1.11"]
    }
  ]
}
```

### 8. Search Registry for Suspicious Entries

**Request:**
```
Search the SOFTWARE hive for 'mimikatz'
```

**Output:**
```json
{
  "pattern": "mimikatz",
  "matches": [],
  "count": 0
}
```

### 9. Get USB Device History

**Request:**
```
Show USB device history from SYSTEM hive
```

**Output:**
```json
{
  "devices": [
    {
      "vendor": "SanDisk",
      "product": "Ultra USB 3.0",
      "serial": "4C530001234567890",
      "first_connected": "2025-02-10T14:30:00Z",
      "last_connected": "2025-03-15T09:00:00Z"
    }
  ]
}
```

### 10. Remote Artifact Collection

**Request with Password:**
```
Collect forensic artifacts from 192.168.1.100 with username 'admin' and save to /cases/case001
```

**Request with Pass-the-Hash:**
```
Collect artifacts from 192.168.1.100 as administrator using hash aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

**Output:**
```json
[
  {
    "artifact": "Security.evtx",
    "success": true,
    "local_path": "/cases/case001/evtx/Security.evtx",
    "size_bytes": 69206016,
    "error": null
  },
  {
    "artifact": "SAM",
    "success": true,
    "local_path": "/cases/case001/registry/SAM",
    "size_bytes": 65536,
    "error": null
  },
  {
    "artifact": "SYSTEM",
    "success": true,
    "local_path": "/cases/case001/registry/SYSTEM",
    "size_bytes": 17825792,
    "error": null
  }
]
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

## Typical Investigation Workflow

### 1. Mount or Collect Evidence

```bash
# Mount Windows image
mount -o ro /dev/sdb1 /mnt/evidence

# Or collect from remote system
"Collect artifacts from 192.168.1.50 user admin to /cases/incident001"
```

### 2. Discover Available Logs

```
"List all EVTX files in /mnt/evidence/Windows/System32/winevt/Logs"
```

### 3. Get Overview

```
"Show stats for Security.evtx - what events are most common?"
```

### 4. Hunt for Suspicious Activity

```
"Find all failed logon attempts in Security.evtx"
"Search for process creation events with powershell or cmd"
"Look for service installations in System.evtx"
```

### 5. Analyze Registry

```
"Check persistence mechanisms in the SOFTWARE and SYSTEM hives"
"Get user account details from SAM"
"Search registry for references to suspicious IP 10.10.10.10"
```

### 6. Correlate Findings

```
"Show me events between 2025-01-15T10:00:00Z and 2025-01-15T12:00:00Z"
```

---

## Troubleshooting

### "Module not found" errors

```bash
source /path/to/winforensics-mcp/.venv/bin/activate
pip list | grep -E "evtx|registry|mcp"
```

### "Permission denied" on registry hives

Registry hives may be locked. Either:
- Use offline/copied hives from a mounted image
- Use VSS (Volume Shadow Copy) collection via WinRM

### WinRM connection issues

```bash
# Test with password
python -c "import winrm; s=winrm.Session('http://HOST:5985/wsman', auth=('user','pass')); print(s.run_cmd('hostname'))"

# Test with pass-the-hash
python -c "import winrm; s=winrm.Session('http://HOST:5985/wsman', auth=('user','00000000000000000000000000000000:NTHASH'), transport='ntlm'); print(s.run_cmd('hostname'))"
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
- [MCP](https://github.com/anthropics/mcp) - Model Context Protocol
