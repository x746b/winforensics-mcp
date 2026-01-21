# WinForensics-MCP v0.2.0 Development Progress

## Overview
Implementing v0.2.0 features per the implementation plan. Focus on expanding artifact coverage from "Logs & Config" to "Execution & File System" analysis.

---

## Completed Modules

### 1. PE Analyzer (`file_analyze_pe`) ✅
**Completed:** 2025-01-21

**Files:**
- `parsers/pe_analyzer.py` (new)
- `parsers/__init__.py` (updated)
- `server.py` (updated)
- `pyproject.toml` (added `pefile>=2023.2.7`)

**Features:**
- File hash calculation (MD5, SHA1, SHA256, Imphash)
- PE type detection (32/64-bit, EXE/DLL, subsystem)
- Section analysis with entropy calculation
- Import/export extraction
- Packer signature detection (UPX, MPRESS, ASPack, Themida, etc.)
- Suspicious API detection (injection, evasion, credential theft, keylogging)
- Version info extraction
- Optional string extraction

**Tool Parameters:**
- `file_path` (required)
- `calculate_hashes` (default: true)
- `extract_strings` (default: false)
- `check_signatures` (default: true)
- `detail_level` (minimal/standard/verbose)

**Test Status:** Passed - tested with EXE and DLL samples from HTB Sherlocks

---

### 2. Prefetch Parser (`disk_parse_prefetch`) ✅
**Completed:** 2025-01-21

**Files:**
- `parsers/prefetch_parser.py` (new)
- `parsers/__init__.py` (updated)
- `server.py` (updated)
- `pyproject.toml` (added `libscca-python>=20240427`)

**Features:**
- Parse single .pf file or entire Prefetch directory
- Extract executable name, prefetch hash, run count
- Last run times (up to 8 on Win8+)
- Volume information (device path, serial number, creation time)
- Loaded files/DLLs list
- Filter by executable name
- Graceful error handling for corrupted files

**Tool Parameters:**
- `path` (required) - .pf file or Prefetch directory
- `executable_filter` - Filter by executable name (case-insensitive)
- `include_loaded_files` (default: false)
- `limit` (default: 100)

**Test Status:** Passed - tested with 249 prefetch files from Whisper challenge
- Successfully parsed WSCRIPT.EXE showing BloodHound execution
- PowerShell.exe: 49 executions with 8 timestamps

---

### 3. Amcache Parser (`disk_parse_amcache`) ✅
**Completed:** 2025-01-21

**Files:**
- `parsers/amcache_parser.py` (new)
- `parsers/__init__.py` (updated)
- `server.py` (updated)

**Features:**
- Parse modern Windows 10/11 Amcache.hve format (InventoryApplicationFile)
- Support for legacy Windows 8.1 format (File key)
- Extract SHA1 hashes from FileId field
- File paths, names, publishers, versions
- Binary type (PE32/PE64, .NET CLR)
- Link/compile timestamps
- Filter by SHA1, path, name, time range
- Suspicious path detection for threat hunting

**Tool Parameters:**
- `amcache_path` (required) - Path to Amcache.hve
- `sha1_filter` - Filter by SHA1 hash
- `path_filter` - Filter by file path
- `name_filter` - Filter by file name
- `time_range_start/end` - Time range filter
- `limit` (default: 100)

**Test Status:** Passed
- Correctly extracts SHA1 hashes (e.g., BloodHound: `204bc44c651e17f65c95314e0b6dfee586b72089`)
- Found suspicious tools: BloodHound, BetterSafetyKatz, Certify, AmsiTrigger, John the Ripper
- Suspicious path filtering working correctly

---

### 4. SRUM Parser (`disk_parse_srum`) ✅
**Completed:** 2025-01-21

**Files:**
- `parsers/srum_parser.py` (new)
- `parsers/__init__.py` (updated)
- `server.py` (updated)
- `pyproject.toml` (added `libesedb-python>=20240420`)

**Features:**
- Parse SRUDB.dat ESE database using `libesedb-python`
- Application resource usage (CPU time, cycles, bytes read/written)
- Network data usage (bytes sent/received per application)
- Network connectivity tracking
- Push notification data
- Energy usage data
- Application timeline data
- Filter by application name or SID
- Time range filtering
- Summary function listing all tables with record counts

**Tool Parameters:**
- `srum_path` (required) - Path to SRUDB.dat
- `table` - Table to query (app_resource_usage, network_data_usage, etc.)
- `app_filter` - Filter by application name (case-insensitive)
- `sid_filter` - Filter by user SID
- `time_range_start/end` - ISO format time range filter
- `limit` (default: 100)

**SRUM Table GUIDs:**
- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` - App Resource Usage
- `{973F5D5C-1D90-4944-BE8E-24B94231A174}` - Network Data Usage
- `{DD6636C4-8929-4683-974E-22C046A43763}` - Network Connectivity
- `{5C8CF1C7-7257-4F13-B223-970EF5939312}` - App Timeline
- `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` - Energy Usage

**Test Status:** Passed
- App resource usage working (PowerShell with CPU time, bytes read/written)
- Network data usage working (bytes sent/received per app)
- Summary function lists all tables with record counts
- Note: SRUM uses ESE database format (not SQLite as initially documented)

---

### 5. Execution Investigation Orchestrator (`investigate_execution`) ✅
**Completed:** 2025-01-21

**Files:**
- `orchestrators/__init__.py` (new)
- `orchestrators/execution_tracker.py` (new)
- `__init__.py` (updated - version 0.2.0)
- `server.py` (updated)

**Features:**
- Correlates evidence from Prefetch, Amcache, and SRUM
- Answers "Was this binary executed?" with evidence from multiple sources
- Auto-detects artifact paths within a base directory
- Supports searching by executable name, file path, or SHA1 hash
- Confidence scoring (HIGH/MEDIUM/LOW/NONE) based on corroborating sources
- Unified timeline construction from all sources
- Human-readable summary generation
- Time range filtering

**Tool Parameters:**
- `target` (required) - Executable name, path, or SHA1 hash
- `artifacts_dir` (required) - Base directory with artifacts
- `time_range_start/end` - ISO format time range filter
- `prefetch_path/amcache_path/srum_path` - Override auto-detection

**Confidence Levels:**
- HIGH: 3+ sources confirm execution
- MEDIUM: 2 sources confirm execution
- LOW: 1 source confirms execution
- NONE: No evidence found

**Test Status:** Passed
- PowerShell.exe: MEDIUM confidence (Prefetch + Amcache)
- BloodHound: MEDIUM confidence (Prefetch + Amcache) with SHA1 extracted
- SHA1 search: LOW confidence (Amcache only - expected)
- Non-existent: NONE confidence (correct behavior)

---

## Phase 1 Complete ✅

All Phase 1 execution artifacts modules are now implemented:
- [x] `disk_parse_prefetch` - Execution evidence ✅
- [x] `disk_parse_amcache` - SHA1 hashes & execution times ✅
- [x] `disk_parse_srum` - Application resource usage ✅
- [x] `investigate_execution` - Orchestrator for execution analysis ✅

---

## Pending Modules

### Phase 2: File System Artifacts
- [ ] `disk_parse_mft` - MFT parsing with timestomping detection
- [ ] `disk_parse_usn_journal` - USN Journal parsing
- [ ] `build_timeline` - Unified timeline builder

### Phase 3: User Activity
- [ ] `browser_get_history` - Edge/Chrome/Firefox history
- [ ] `user_parse_shellbags` - Folder navigation history
- [ ] `user_parse_lnk_files` - LNK shortcut analysis

### Phase 4: Integration
- [ ] `hunt_ioc` - Cross-artifact IOC hunting
- [ ] `ingest_parsed_csv` - Eric Zimmerman CSV import

---

## Dependencies Added
```toml
dependencies = [
    "mcp>=1.0.0",
    "python-evtx>=0.7.0",
    "python-registry>=1.3.0",
    "python-dateutil>=2.8.2",
    "pefile>=2023.2.7",         # v0.2.0 - PE Analysis
    "libscca-python>=20240427", # v0.2.0 - Prefetch parsing
    "libesedb-python>=20240420", # v0.2.0 - SRUM ESE database parsing
]
```

---

## Test Samples Location
`/home/xtk/labs/HTB/_Sherlocks_/_mcp_/samples/C/`
- Prefetch: `Windows/prefetch/` (249 files)
- SRUM: `Windows/System32/sru/SRUDB.dat`
- Amcache: `Windows/appcompat/Programs/Amcache.hve`
- PE files: Various in Sherlocks challenges

---

## Notes
- Using `uv` for local dependency management
- All tools conditionally registered based on library availability
- Following existing parser patterns from evtx_parser.py
