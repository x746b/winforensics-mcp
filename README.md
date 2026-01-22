<img src="icon.png" width="150" alt="WinForensics MCP">

# Windows Forensics MCP Server

> **Windows DFIR from Linux** - A comprehensive forensics toolkit designed entirely for Linux environments with zero Windows tool dependencies. Parse Windows artifacts natively using pure Python libraries.

---

## Why This Matters

Traditional Windows forensics often requires:
- Running analysis tools on Windows
- Commercial forensic suites with expensive licenses
- Eric Zimmerman tools that only run on Windows/.NET

**WinForensics-MCP changes this.** Built from the ground up for Linux-based analysis:

- **No Windows Required** - Analyze Windows disk images directly from your Linux forensics workstation
- **No Wine/Mono Hacks** - Pure Python implementations using battle-tested open-source libraries
- **AI-Assisted Analysis** - Integrates with Claude CLI and any MCP-compatible client for intelligent artifact correlation
---

## Features

### Core Forensics
| Category | Capabilities |
|----------|--------------|
| **EVTX Logs** | Parse Windows Event Logs with filtering, search, and pre-built security queries |
| **Registry** | Analyze SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT hives |
| **Remote Collection** | Collect artifacts via WinRM (password or pass-the-hash) |

### Execution Artifacts
| Category | Capabilities |
|----------|--------------|
| **PE Analysis** | Static analysis with hashes (MD5/SHA1/SHA256/imphash), imports, exports, packer detection |
| **Prefetch** | Execution evidence with run counts, timestamps, loaded files |
| **Amcache** | SHA1 hashes and first-seen timestamps from Amcache.hve |
| **SRUM** | Application resource usage, CPU time, network activity from SRUDB.dat |

### File System Artifacts
| Category | Capabilities |
|----------|--------------|
| **MFT** | Master File Table parsing with timestomping detection |
| **USN Journal** | Change journal for file operations and deleted file recovery |
| **Timeline** | Unified timeline from MFT, USN, Prefetch, Amcache, EVTX |

### User Activity
| Category | Capabilities |
|----------|--------------|
| **Browser** | Edge, Chrome, Firefox history and downloads |
| **LNK Files** | Windows shortcut analysis for recently accessed files |
| **ShellBags** | Folder navigation history with suspicious path detection |
| **RecentDocs** | Registry-based recent document tracking |

### Orchestrators
| Tool | What It Does |
|------|--------------|
| `investigate_execution` | Correlates Prefetch + Amcache + SRUM to answer "Was this binary executed?" |
| `investigate_user_activity` | Correlates Browser + ShellBags + LNK + RecentDocs for user activity timeline |
| `hunt_ioc` | Searches for IOC (hash/filename/IP/domain) across ALL artifact sources |
| `build_timeline` | Builds unified forensic timeline from multiple sources |

### Utilities
| Tool | What It Does |
|------|--------------|
| `ingest_parsed_csv` | Import Eric Zimmerman tool CSV output (MFTECmd, PECmd, AmcacheParser) |

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

### Install

```bash
git clone https://github.com/x746b/winforensics-mcp.git
cd winforensics-mcp

# Install with uv (recommended)
uv sync

# Or traditional pip
uv venv && source .venv/bin/activate
uv pip install -e .

# For remote collection (WinRM, SSH, SMB):
uv pip install -e ".[remote]"
```

### Verify

```bash
uv run python -m winforensics_mcp.server
# Should start without errors (Ctrl+C to exit)
```

---

## Adding to Claude CLI

### Recommended: Using `claude mcp add`

```bash
claude mcp add winforensics-mcp \
  --scope user \
  -- uv run --directory /path/to/winforensics-mcp python -m winforensics_mcp.server
```

### Alternative: Manual JSON

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

## LLM Integration (CLAUDE.md)

For AI-assisted forensic analysis, include [`CLAUDE.md`](CLAUDE.md) in your case directory. It provides:

- **Orchestrator-first guidance** - Ensures LLMs use high-level tools before low-level parsers
- **Token efficiency** - Reduces API costs by 50%+ through proper tool selection
- **Investigation workflow** - Step-by-step methodology for consistent analysis

### Usage

Copy `CLAUDE.md` to your case directory:

```bash
cp /path/to/winforensics-mcp/CLAUDE.md /your/case/directory/
# Edit paths in CLAUDE.md to match your case
```

The LLM will automatically follow the orchestrator-first approach:

| Question | Orchestrator Used |
|----------|------------------|
| "Was malware.exe executed?" | `investigate_execution` |
| "What did the user do?" | `investigate_user_activity` |
| "Find this hash everywhere" | `hunt_ioc` |
| "Build incident timeline" | `build_timeline` |

---

## Quick Start Examples

### Was This Binary Executed?

```
Investigate if mimikatz.exe was executed on the system at /mnt/evidence
```

The `investigate_execution` orchestrator checks Prefetch, Amcache, and SRUM:

```json
{
  "target": "mimikatz.exe",
  "execution_confirmed": true,
  "confidence": "HIGH",
  "evidence": [
    {"source": "Prefetch", "finding": "Executed 3 times, last at 2024-03-15T14:23:45Z"},
    {"source": "Amcache", "finding": "SHA1: abc123..., First seen: 2024-03-14T09:00:00Z"},
    {"source": "SRUM", "finding": "Network: 15.2 MB sent; Foreground: 47 seconds"}
  ]
}
```

### Hunt for IOC Across All Artifacts

```
Hunt for the hash 204bc44c651e17f65c95314e0b6dfee586b72089 in /mnt/evidence
```

The `hunt_ioc` tool searches Prefetch, Amcache, SRUM, MFT, USN, Browser, and EVTX:

```json
{
  "ioc": "204bc44c651e17f65c95314e0b6dfee586b72089",
  "ioc_type": "sha1",
  "found": true,
  "confidence": "HIGH",
  "sources_with_hits": ["Amcache", "MFT"],
  "findings": [
    {"source": "Amcache", "matches": 1, "details": "bloodhound.exe"},
    {"source": "MFT", "matches": 1, "details": "Users\\Admin\\Downloads\\bloodhound.exe"}
  ]
}
```

### User Activity Investigation

```
What did the user 'Alpha' do on this system? Check /mnt/evidence/Users/Alpha
```

The `investigate_user_activity` orchestrator correlates browser, shellbags, LNK, and RecentDocs:

```json
{
  "activity_found": true,
  "confidence": "HIGH",
  "evidence": [
    {"source": "Browser", "finding": "15 visits, 3 downloads (PowerView.ps1, mimikatz.zip)"},
    {"source": "ShellBags", "finding": "42 folders navigated including \\Windows\\Temp"},
    {"source": "LNK Files", "finding": "8 executables, 12 documents accessed"}
  ],
  "timeline": [
    {"time": "2025-01-20T14:30:00Z", "source": "Browser", "event": "Downloaded: mimikatz.zip"},
    {"time": "2025-01-20T14:31:00Z", "source": "ShellBags", "event": "Navigated: Downloads\\mimikatz"}
  ]
}
```

### Detect Timestomping

```
Find timestomped files in the MFT at /mnt/evidence/$MFT
```

```json
{
  "total_timestomped": 2,
  "timestomped_files": [
    {
      "path": "Users\\Alpha\\Downloads\\backdoor.exe",
      "si_created": "2019-01-15T10:00:00Z",
      "fn_created": "2025-01-20T14:30:00Z",
      "detection_reason": "$SI created before $FN (impossible without manipulation)"
    }
  ]
}
```

### Import Eric Zimmerman CSV Output

Already ran MFTECmd on Windows? Import the CSV:

```
Ingest the MFTECmd CSV at /cases/MFTECmd_output.csv and search for .exe files
```

```json
{
  "csv_type": "mftecmd",
  "total_rows": 193008,
  "filter": {"field": "extension", "value": ".exe"},
  "total_matched": 4308,
  "entries": [...]
}
```

---

## Tool Reference

### Orchestrators (High-Level Investigation)

| Tool | Description |
|------|-------------|
| `investigate_execution` | Correlate Prefetch/Amcache/SRUM to prove binary execution |
| `investigate_user_activity` | Correlate Browser/ShellBags/LNK/RecentDocs for user activity |
| `hunt_ioc` | Hunt IOC (hash/filename/IP/domain) across all artifacts |
| `build_timeline` | Build unified timeline from multiple artifact sources |

### Execution Artifacts

| Tool | Description |
|------|-------------|
| `file_analyze_pe` | Static PE analysis - hashes, imports, exports, packer detection |
| `disk_parse_prefetch` | Parse Prefetch for execution evidence |
| `disk_parse_amcache` | Parse Amcache.hve for SHA1 hashes and timestamps |
| `disk_parse_srum` | Parse SRUDB.dat for app resource and network usage |

### File System

| Tool | Description |
|------|-------------|
| `disk_parse_mft` | Parse $MFT with timestomping detection |
| `disk_parse_usn_journal` | Parse $J for file operations and deleted files |

### User Activity

| Tool | Description |
|------|-------------|
| `browser_get_history` | Parse Edge/Chrome/Firefox history and downloads |
| `user_parse_lnk_files` | Parse Windows shortcuts for target paths |
| `user_parse_shellbags` | Parse ShellBags for folder navigation history |

### Event Logs

| Tool | Description |
|------|-------------|
| `evtx_list_files` | List EVTX files in a directory |
| `evtx_get_stats` | Get event counts, time range, Event ID distribution |
| `evtx_search` | Search with filters (time, Event ID, keywords) |
| `evtx_security_search` | Pre-built security event searches (logon, process creation, etc.) |
| `evtx_explain_event_id` | Get Event ID description |

### Registry

| Tool | Description |
|------|-------------|
| `registry_get_key` | Get specific key and values |
| `registry_search` | Search values by pattern |
| `registry_get_persistence` | Get Run keys and services |
| `registry_get_users` | Get user accounts from SAM |
| `registry_get_usb_history` | Get USB device history |
| `registry_get_system_info` | Get OS version, hostname, timezone |
| `registry_get_network` | Get network configuration |

### Utilities

| Tool | Description |
|------|-------------|
| `ingest_parsed_csv` | Import Eric Zimmerman CSV output (MFTECmd, PECmd, AmcacheParser, SrumECmd) |
| `forensics_list_important_events` | List important Event IDs by channel |
| `forensics_list_registry_keys` | List forensic registry keys by category |

### Remote Collection

| Tool | Description |
|------|-------------|
| `remote_collect_artifacts` | Collect artifacts via WinRM (password or pass-the-hash) |
| `remote_get_system_info` | Get remote system info |

---

## Typical Investigation Workflow

### 1. Mount Evidence

```bash
mount -o ro,loop /path/to/image.E01 /mnt/evidence
# Or use ewfmount for E01 files
```

### 2. Quick Triage

```
Investigate execution of mimikatz.exe and powershell.exe in /mnt/evidence
```

### 3. Hunt for Known IOCs

```
Hunt for these hashes in /mnt/evidence: abc123..., def456...
```

### 4. User Activity Deep Dive

```
Investigate user activity for 'Administrator' in /mnt/evidence
```

### 5. Timeline Analysis

```
Build a timeline for /mnt/evidence filtering for 'mimikatz'
```

### 6. Persistence Check

```
Check persistence mechanisms in the SYSTEM and SOFTWARE hives
```

---

## Configuration

### Adjusting Response Limits

Edit `winforensics_mcp/config.py`:

```python
MAX_EVTX_RESULTS = 50       # Event log search results
MAX_REGISTRY_RESULTS = 50   # Registry search results
MAX_PREFETCH_RESULTS = 20   # Prefetch entries
MAX_AMCACHE_RESULTS = 30    # Amcache entries
MAX_TIMELINE_RESULTS = 50   # Timeline events
MAX_MFT_RESULTS = 30        # MFT entries
MAX_USN_RESULTS = 30        # USN Journal records
```

---

## Troubleshooting

### Missing dependencies

```bash
uv pip install pefile libscca-python libesedb-python mft pylnk3
```

### Permission denied on registry hives

Registry hives may be locked. Use offline/copied hives from a mounted image.

### Remove MCP Server

```bash
claude mcp remove winforensics-mcp --scope user
```

---

## Dependencies

All parsing is done with pure Python libraries:

| Library | Purpose |
|---------|---------|
| [python-evtx](https://github.com/williballenthin/python-evtx) | EVTX parsing |
| [python-registry](https://github.com/williballenthin/python-registry) | Registry hive parsing |
| [pefile](https://github.com/erocarrera/pefile) | PE file analysis |
| [libscca-python](https://github.com/libyal/libscca) | Prefetch parsing |
| [libesedb-python](https://github.com/libyal/libesedb) | ESE database (SRUM) parsing |
| [mft](https://github.com/omerbenamram/mft) | MFT parsing (Rust-based, Python bindings) |
| [pylnk3](https://github.com/strayge/pylnk) | LNK file parsing |

---

## License

MIT License

---

## Author

**xtk**

Built for the DFIR community. No Windows required.
