<img src="icon.png" width="150" alt="WinForensics MCP">

# Windows Forensics MCP Server

> **Windows DFIR from Linux** - A comprehensive forensics toolkit designed entirely for Linux environments with zero Windows tool dependencies. Parse Windows artifacts natively using pure Python libraries.

---

## Related Projects

- **[mem_forensics-mcp](https://github.com/x746b/mem_forensics-mcp)** - Unified Memory Forensics MCP Server - Multi-tier engine combining Rust speed with Vol3 coverage
- **[mac_forensics-mcp](https://github.com/x746b/mac_forensics-mcp)** - macOS DFIR - Unified Logs, FSEvents, Spotlight, Plists, SQLite databases, Extended Attributes

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

### Install from PyPI

```bash
uv tool install winforensics-mcp
```

### Install from source

```bash
git clone https://github.com/x746b/winforensics-mcp.git
cd winforensics-mcp

# Install with uv (recommended)
uv sync

# Or install with all optional extras
uv venv && source .venv/bin/activate
uv pip install -e ".[all]"
```

### Verify

```bash
uv run python -m winforensics_mcp.server
# Should start without errors (Ctrl+C to exit)
```

---

## Adding to Claude CLI

Installed from PyPI

```bash
claude mcp add winforensics-mcp --scope user -- uv run winforensics-mcp
```

Installed from sources

```bash
claude mcp add winforensics-mcp \
  --scope user \
  -- uv run --directory /path/to/winforensics-mcp python -m winforensics_mcp.server
```

Verify:

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
  "sources_with_hits": ["Amcache", "MFT"],
  "findings": [
    {"source": "Amcache", "matches": 1, "details": "bloodhound.exe"},
    {"source": "MFT", "matches": 1, "details": "Users\\Admin\\Downloads\\bloodhound.exe"}
  ]
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

## Configuration

### VirusTotal API Key

```bash
# Option 1: Environment variable
export VIRUSTOTAL_API_KEY="your-api-key-here"

# Option 2: Config file
mkdir -p ~/.config/winforensics-mcp
echo "your-api-key-here" > ~/.config/winforensics-mcp/vt_api_key
```

Get your free API key at [virustotal.com](https://www.virustotal.com/gui/join-us). Free tier is rate-limited to 4 requests/minute; the client handles rate limiting and caches results for 24 hours.

---

## Troubleshooting

### DiE (Detect It Easy) not found

```bash
# Debian/Ubuntu
sudo apt install detect-it-easy

# Or download from https://github.com/horsicq/DIE-engine/releases
```

### Remove MCP Server

```bash
claude mcp remove winforensics-mcp --scope user
```

---

## License

Credits: [Rohitab Batra](http://www.rohitab.com/apimonitor) (API Monitor), [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (YARA rules), [horsicq/DIE-engine](https://github.com/horsicq/DIE-engine) (Detect It Easy)

MIT License | xtk | Built for the DFIR community. No Windows required >)
