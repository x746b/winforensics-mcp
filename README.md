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

## Related Projects

| Project | Focus | Link |
|---------|-------|------|
| **mem_forensics-mcp** | Unified Memory Forensics MCP Server - Multi-tier engine combining Rust speed with Vol3 coverage. | [GitHub](https://github.com/x746b/mem_forensics-mcp) |
| **mac_forensics-mcp** | macOS DFIR - Unified Logs, FSEvents, Spotlight, Plists, SQLite databases, Extended Attributes | [GitHub](https://github.com/x746b/mac_forensics-mcp) |

Use together for complete incident response across platforms.

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

### Network Forensics
| Category | Capabilities |
|----------|--------------|
| **PCAP Analysis** | Parse PCAP/PCAPNG files - conversations, DNS queries, HTTP requests, suspicious connections |

### API Monitor Capture Analysis
| Category | Capabilities |
|----------|--------------|
| **APMX Parsing** | Parse [API Monitor](http://www.rohitab.com/apimonitor) captures (.apmx64/.apmx86) - process metadata, API call extraction, parameter values |
| **Pattern Detection** | Detect injection, hollowing, credential dumping, and other attack patterns from captured API call sequences with MITRE ATT&CK mapping |
| **Handle Correlation** | Track handle values across calls to reconstruct attack chains (OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread) |
| **Injection Analysis** | Extract enriched injection chain details: target PID/process, shellcode size, allocation addresses, technique classification |
| **API Knowledge Base** | 26,944 Windows API definitions with parameter signatures, DLL mappings, and category browsing |

### Malware Detection
| Category | Capabilities |
|----------|--------------|
| **YARA Scanning** | 718 rules from [signature-base](https://github.com/Neo23x0/signature-base) - APT, ransomware, webshells, hacktools |
| **VirusTotal** | Hash/IP/domain reputation lookups with caching and rate limiting (free tier supported) |
| **DiE Integration** | Detect packers (UPX, Themida, VMProtect), compilers, .NET, installers via Detect It Easy |

### Orchestrators
| Tool | What It Does |
|------|--------------|
| `investigate_execution` | Correlates Prefetch + Amcache + SRUM to answer "Was this binary executed?" |
| `investigate_user_activity` | Correlates Browser + ShellBags + LNK + RecentDocs for user activity timeline |
| `hunt_ioc` | Searches for IOC (hash/filename/IP/domain) across ALL artifact sources + optional YARA scanning |
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

# For YARA malware scanning:
uv pip install -e ".[yara]"

# For VirusTotal threat intelligence:
uv pip install -e ".[virustotal]"

# For PCAP network analysis:
uv pip install -e ".[pcap]"

# Install everything:
uv pip install -e ".[all]"
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

The `hunt_ioc` tool searches Prefetch, Amcache, SRUM, MFT, USN, Browser, EVTX, and optionally YARA:

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

#### Hunt with YARA Scanning

For filename IOCs, enable YARA scanning to get threat intelligence in the same call:

```
Hunt for suspicious.exe in /mnt/evidence with YARA scanning enabled
```

```json
{
  "ioc": "suspicious.exe",
  "ioc_type": "filename",
  "found": true,
  "confidence": "HIGH",
  "sources_with_hits": ["Prefetch", "MFT", "YARA"],
  "findings": [
    {"source": "Prefetch", "matches": 1, "details": "Executed 5 times"},
    {"source": "MFT", "matches": 1, "details": "Users\\Admin\\Downloads\\suspicious.exe"},
    {"source": "YARA", "matches": 2, "details": ["Mimikatz_Memory_Rule", "HKTL_Mimikatz"]}
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

### Analyze Network Traffic

```
Analyze the PCAP file at /evidence/capture.pcap for suspicious activity
```

The `pcap_find_suspicious` tool detects C2 indicators, beaconing, and DNS tunneling:

```json
{
  "total_findings": 5,
  "findings": {
    "suspicious_ports": [
      {"src_ip": "192.168.1.100", "dst_ip": "185.220.101.1", "port": 4444, "reason": "Connection on suspicious port 4444"}
    ],
    "potential_beaconing": [
      {"src_ip": "192.168.1.100", "dst_ip": "10.10.10.10", "connection_count": 48, "avg_interval_seconds": 60.2}
    ],
    "dns_tunneling_indicators": [
      {"query": "aGVsbG8gd29ybGQ.evil.com", "reason": "Unusually long DNS label (45 chars)"}
    ]
  }
}
```

### Detect Packers with DiE

```
Check if malware.exe is packed using DiE
```

The `die_analyze_file` tool detects packers, compilers, and protectors:

```json
{
  "file": "/evidence/malware.exe",
  "file_type": "PE32",
  "arch": "x86",
  "detects": [
    {"type": "Packer", "name": "UPX", "version": "3.96"},
    {"type": "Compiler", "name": "MSVC", "version": "14.0"}
  ],
  "is_packed": true,
  "is_dotnet": false
}
```

### Look Up Hash on VirusTotal

```
Look up this hash on VirusTotal: d41d8cd98f00b204e9800998ecf8427e
```

```json
{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "hash_type": "md5",
  "found": true,
  "verdict": "malicious",
  "detection_ratio": "45/72",
  "popular_threat_names": ["Trojan.GenericKD", "Win32/Trojan"],
  "file_type": "Win32 EXE",
  "first_submission": "2024-01-15T10:00:00Z"
}
```

### Scan for Malware with YARA

```
Scan /mnt/evidence/Users/Admin/Downloads for malware
```

The `yara_scan_directory` tool uses 718 rules from signature-base:

```json
{
  "directory": "/mnt/evidence/Users/Admin/Downloads",
  "files_scanned": 47,
  "files_matched": 2,
  "matches": [
    {
      "file": "mimikatz.exe",
      "match_count": 3,
      "matches": [
        {"rule": "Mimikatz_Memory_Rule_1", "namespace": "gen_mimikatz"},
        {"rule": "mimikatz", "namespace": "gen_mimikatz"},
        {"rule": "HKTL_Mimikatz", "namespace": "thor-hacktools"}
      ]
    },
    {
      "file": "beacon.dll",
      "match_count": 1,
      "matches": [
        {"rule": "CobaltStrike_Beacon", "namespace": "apt_cobaltstrike"}
      ]
    }
  ]
}
```

### Analyze API Monitor Capture

```
Parse the API Monitor capture at /evidence/inject.apmx64 and detect attack patterns
```

The `apmx_detect_patterns` tool identifies injection chains and maps them to MITRE ATT&CK:

```json
{
  "total_records": 29230,
  "unique_apis_seen": 47,
  "patterns_detected": 2,
  "risk_level": "high",
  "details": [
    {
      "pattern_name": "Classic Process Injection",
      "pattern_id": "classic_injection",
      "mitre_id": "T1055.001",
      "apis_matched": ["CreateRemoteThread", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
      "risk": "high"
    }
  ],
  "suspicious_call_timeline": [
    {"record_index": 25664, "api": "OpenProcess"},
    {"record_index": 29109, "api": "VirtualAllocEx"},
    {"record_index": 29110, "api": "WriteProcessMemory"},
    {"record_index": 29111, "api": "CreateRemoteThread"}
  ]
}
```

For enriched injection chain details:

```
Get injection info from /evidence/inject.apmx64
```

```json
{
  "injection_chains": [
    {
      "handle_hex": "0x268",
      "target_pid": 16224,
      "target_process": "notepad.exe",
      "requested_alloc_size": 511,
      "shellcode_size": 511,
      "start_address_hex": "0x206583d0000",
      "injection_technique": "Classic Process Injection",
      "chain": [
        {"api": "OpenProcess", "record": 25664},
        {"api": "VirtualAllocEx", "record": 29109},
        {"api": "WriteProcessMemory", "record": 29110},
        {"api": "CreateRemoteThread", "record": 29111}
      ]
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
| `hunt_ioc` | Hunt IOC (hash/filename/IP/domain) across all artifacts; `yara_scan=True` adds YARA threat intel |
| `build_timeline` | Build unified timeline from multiple artifact sources |

### Execution Artifacts

| Tool | Description |
|------|-------------|
| `file_analyze_pe` | Static PE analysis - hashes, imports, exports, packer detection |
| `disk_parse_prefetch` | Parse Prefetch for execution evidence |
| `disk_parse_amcache` | Parse Amcache.hve for SHA1 hashes and timestamps |
| `disk_parse_srum` | Parse SRUDB.dat for app resource and network usage |

### Malware Detection (YARA)

| Tool | Description |
|------|-------------|
| `yara_scan_file` | Scan file with 718 YARA rules (Mimikatz, CobaltStrike, webshells, APT, ransomware) |
| `yara_scan_directory` | Batch scan directory for malware |
| `yara_list_rules` | List available/bundled YARA rules |

### Threat Intelligence (VirusTotal)

| Tool | Description |
|------|-------------|
| `vt_lookup_hash` | Look up file hash (MD5/SHA1/SHA256) on VirusTotal |
| `vt_lookup_ip` | Get IP address reputation and geolocation |
| `vt_lookup_domain` | Get domain reputation and categorization |
| `vt_lookup_file` | Calculate file hashes and look up on VirusTotal |

### Network Forensics (PCAP)

| Tool | Description |
|------|-------------|
| `pcap_get_stats` | Get PCAP statistics - packet counts, protocols, top talkers |
| `pcap_get_conversations` | Extract TCP/UDP conversations with byte counts |
| `pcap_get_dns` | Extract DNS queries and responses |
| `pcap_get_http` | Extract HTTP requests with URLs, methods, user-agents |
| `pcap_search` | Search packet payloads for strings or regex patterns |
| `pcap_find_suspicious` | Detect C2 indicators, beaconing, DNS tunneling |

### API Monitor Capture Analysis (APMX)

| Tool | Description |
|------|-------------|
| `apmx_parse` | Parse .apmx64/.apmx86 capture - process info, modules, call counts |
| `apmx_get_calls` | Extract API calls with filtering, pagination, and time range support |
| `apmx_get_call_details` | Detailed records with parameter values, return values, timestamps |
| `apmx_detect_patterns` | Detect attack patterns (injection, hollowing, credential dumping) with MITRE ATT&CK IDs |
| `apmx_correlate_handles` | Track handle producer/consumer chains across API calls |
| `apmx_get_injection_info` | Enriched injection chain extraction (target PID, shellcode size, technique) |
| `apmx_get_calls_around` | Context window of calls around a specific record |
| `apmx_search_params` | Search all records for a specific parameter value |
| `api_analyze_imports` | Full PE import analysis with pattern detection and MITRE ATT&CK mapping |
| `api_detect_patterns` | Detect attack patterns from PE import tables |
| `api_lookup` | Look up Windows API signature (26,944 APIs with params, DLL, category) |
| `api_search_category` | Browse APIs by category (e.g., "Process Injection", "File Management") |

### Packer Detection (DiE)

| Tool | Description |
|------|-------------|
| `die_analyze_file` | Analyze file for packers, compilers, protectors, .NET |
| `die_scan_directory` | Batch scan directory for packed executables |
| `die_get_packer_info` | Get info about packer (difficulty, unpack tools) |

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

### 7. Malware Analysis

```
Scan the Downloads folder for malware with YARA
```

### 8. Threat Intelligence

```
Look up suspicious hashes on VirusTotal
Check if this C2 IP is known malicious: 185.220.101.1
```

---

## Configuration

### VirusTotal API Key

For threat intelligence lookups, configure your VirusTotal API key:

```bash
# Option 1: Environment variable
export VIRUSTOTAL_API_KEY="your-api-key-here"

# Option 2: Config file
mkdir -p ~/.config/winforensics-mcp
echo "your-api-key-here" > ~/.config/winforensics-mcp/vt_api_key
```

Get your free API key at [virustotal.com](https://www.virustotal.com/gui/join-us).

**Note:** Free tier is rate-limited to 4 requests/minute. The client automatically handles rate limiting and caches results for 24 hours.

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

# For YARA scanning
uv pip install yara-python

# For VirusTotal lookups
uv pip install vt-py
```

### VirusTotal API errors

If you see "API key not configured":
```bash
# Check if key is set
echo $VIRUSTOTAL_API_KEY

# Or create config file
mkdir -p ~/.config/winforensics-mcp
echo "your-key" > ~/.config/winforensics-mcp/vt_api_key
```

If you see rate limit errors, wait 15 seconds between requests (automatic) or use cached results.

### DiE (Detect It Easy) not found

Install `diec` (command-line version):

```bash
# Debian/Ubuntu
sudo apt install detect-it-easy

# Or download from GitHub
# https://github.com/horsicq/DIE-engine/releases
# Extract and add to PATH
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
| [yara-python](https://github.com/VirusTotal/yara-python) | YARA rule scanning (optional) |
| [vt-py](https://github.com/VirusTotal/vt-py) | VirusTotal API client (optional) |
| [scapy](https://github.com/secdev/scapy) | PCAP/PCAPNG parsing (optional) |

### Bundled YARA Rules

718 rules from [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) are included:

| Category | Examples |
|----------|----------|
| APT | Lazarus, APT28, APT29, Turla, Sofacy, CobaltStrike |
| Crimeware | Emotet, TrickBot, Ransomware families |
| Generic | Mimikatz, webshells, PowerShell obfuscation |
| Exploits | Log4Shell, ProxyShell, PrintNightmare |
| Hacktools | BruteRatel, Empire, Metasploit payloads |

---

## Changelog

### v0.5.0 - API Monitor & Runtime Analysis Edition
- **API Monitor Integration**: Parse Rohitab API Monitor captures (.apmx64/.apmx86) with full call extraction, parameter decoding, and handle correlation
- **Runtime Pattern Detection**: Detect injection, hollowing, credential dumping, and 16+ attack patterns from captured API call sequences with MITRE ATT&CK mapping
- **Injection Chain Analysis**: Enriched extraction with target PID/process, shellcode size, allocation addresses, and technique classification
- **Windows API Knowledge Base**: 26,944 API definitions with parameter signatures, DLL mappings, and category browsing
- **PE Import Analysis**: Static import pattern detection with MITRE ATT&CK technique mapping
- **Flag/Enum Decoding**: Automatic symbolic decoding of process access rights, memory protection flags, and allocation types
- **New Tools**: `apmx_*`, `api_analyze_imports`, `api_detect_patterns`, `api_lookup`, `api_search_category`

### v0.4.0 - Threat Intel & Network Edition
- **YARA Scanning**: 718 bundled rules from signature-base (APT, ransomware, hacktools, webshells)
- **VirusTotal Integration**: Hash/IP/domain lookups with rate limiting and 24h caching
- **PCAP Analysis**: Network forensics with conversation extraction, DNS/HTTP parsing, C2 detection
- **DiE Integration**: Packer/compiler detection via Detect It Easy CLI
- **hunt_ioc Enhancement**: Optional `yara_scan=True` parameter to scan found files with YARA rules
- **New Tools**: `yara_scan_*`, `vt_lookup_*`, `pcap_*`, `die_*`
- **Total Tools**: 46 (base)

### v0.3.x
- Core forensics: EVTX, Registry, PE analysis, Prefetch, Amcache, SRUM
- File system: MFT parsing with timestomping detection, USN Journal
- User activity: Browser history, LNK files, ShellBags
- Orchestrators: `investigate_execution`, `investigate_user_activity`, `hunt_ioc`, `build_timeline`

---

## Credits

- **[Rohitab Batra](http://www.rohitab.com/apimonitor)** - Author of [API Monitor](http://www.rohitab.com/apimonitor), a powerful tool for spying on Windows API calls and COM interfaces. The APMX parser in this project was reverse-engineered from API Monitor capture files.
- **[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)** - YARA rule collection used for malware detection
- **[horsicq/DIE-engine](https://github.com/horsicq/DIE-engine)** - Detect It Easy packer/compiler identification engine

---

## License

MIT License

---

## Author

**xtk**

Built for the DFIR community. No Windows required.
