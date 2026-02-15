# Phase 1 Implementation Plan: API Monitor MCP Tools

## Context

Adding API Monitor functionality to winforensics-mcp (v0.4.0 → v0.5.0). The user has Rohitab API Monitor's 2,121 XML definition files already downloaded at `/home/xtk/labs/AI/apimonitor/API/`. Phase 1 delivers three capabilities: PE import analysis, API knowledge base lookup, and API pattern detection.

## Files to Create

### 1. `winforensics_mcp/parsers/api_monitor/__init__.py`
- Export all public functions and `API_DB_AVAILABLE` flag

### 2. `winforensics_mcp/parsers/api_monitor/xml_parser.py`
**Purpose:** Parse the 2,121 API Monitor XML definition files into a SQLite database.

**Core logic:**
- Walk `API/` directory tree, parse each XML file with `xml.etree.ElementTree`
- Resolve `<Include Filename="...">` with cycle detection (convert `\` → `/` in paths)
- Track positional `<Category>` state within each `<Module>`/`<Interface>`
- Handle `<Condition Architecture="32|64">` by storing both variants
- Handle `BothCharset="True"` by expanding to both A/W suffixes

**SQLite schema (5 tables):**

```sql
-- Main API function table
CREATE TABLE apis (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,          -- e.g. "CreateFileW"
    module TEXT NOT NULL,        -- e.g. "Kernel32.dll"
    category TEXT,               -- e.g. "Data Access and Storage/Local File Systems/File Management"
    calling_convention TEXT,     -- STDCALL, CDECL
    return_type TEXT,            -- e.g. "HANDLE"
    error_func TEXT,             -- e.g. "GetLastError"
    charset TEXT DEFAULT 'W'     -- 'A', 'W', or NULL (no charset)
);
CREATE INDEX idx_apis_name ON apis(name);
CREATE INDEX idx_apis_module ON apis(module);
CREATE INDEX idx_apis_category ON apis(category);

-- Parameters for each API
CREATE TABLE params (
    id INTEGER PRIMARY KEY,
    api_id INTEGER REFERENCES apis(id),
    ordinal INTEGER,             -- parameter position (0-based)
    name TEXT,                   -- e.g. "lpFileName"
    type TEXT                    -- e.g. "LPCWSTR"
);

-- Type definitions (structs, enums, flags, aliases)
CREATE TABLE types (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,           -- 'struct', 'union', 'enum', 'flag', 'alias', 'integer', 'pointer'
    base_type TEXT,              -- for aliases/pointers
    size INTEGER,                -- for integers
    source_file TEXT             -- which XML file defined it
);
CREATE INDEX idx_types_name ON types(name);

-- Enum/Flag values
CREATE TABLE type_values (
    id INTEGER PRIMARY KEY,
    type_id INTEGER REFERENCES types(id),
    name TEXT NOT NULL,
    value TEXT NOT NULL
);

-- Structure/union fields
CREATE TABLE type_fields (
    id INTEGER PRIMARY KEY,
    type_id INTEGER REFERENCES types(id),
    ordinal INTEGER,
    name TEXT,
    field_type TEXT
);
```

**Key function:** `build_api_database(xml_dir: str | Path, db_path: str | Path) -> dict`
- Returns stats: `{"apis_parsed": N, "types_parsed": N, "modules_parsed": N, "db_path": "..."}`
- First-run generation: ~2,121 files → SQLite DB (one-time, <30 seconds)
- DB ships alongside the code or is generated on first `lookup_api` call

### 3. `winforensics_mcp/parsers/api_monitor/definitions_db.py`
**Purpose:** Query the SQLite knowledge base.

**Functions:**

```python
def lookup_api(db_path: str | Path, api_name: str) -> dict
```
- Case-insensitive search by exact name or LIKE pattern
- Returns: `{"name", "module", "category", "calling_convention", "return_type", "parameters": [{"name", "type", "ordinal"}], "charset"}`
- Supports wildcards: `lookup_api("Create*")` returns multiple matches

```python
def search_api_by_category(db_path: str | Path, category: str, limit: int = 50) -> dict
```
- Substring match on category path
- Returns list of APIs in that category with module info

```python
def get_api_stats(db_path: str | Path) -> dict
```
- Returns: total APIs, total types, module count, category tree summary

```python
def get_module_apis(db_path: str | Path, module_name: str, limit: int = 100) -> dict
```
- List all APIs exported by a specific DLL

### 4. `winforensics_mcp/parsers/api_monitor/patterns.py`
**Purpose:** Detect known malicious API call patterns from PE import tables.

**Functions:**

```python
def detect_api_patterns(imports: dict[str, list[str]]) -> dict
```
- Takes import table (output of pefile's `get_imports_summary`)
- Checks against pattern library
- Returns: `{"patterns_detected": [...], "risk_level": "high/medium/low", "details": [{"pattern_name", "apis_matched", "apis_missing", "description", "mitre_id"}]}`

**Pattern library (hardcoded dict):**
- `classic_injection`: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
- `apc_injection`: + QueueUserAPC
- `process_hollowing`: CreateProcess(SUSPENDED) + NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread
- `dll_injection`: + LoadLibrary via CreateRemoteThread
- `credential_dumping`: OpenProcess(lsass) + ReadProcessMemory / MiniDumpWriteDump
- `token_manipulation`: OpenProcessToken + DuplicateToken + ImpersonateLoggedOnUser
- `registry_persistence`: RegOpenKeyEx + RegSetValueEx (Run keys)
- `service_persistence`: CreateService + StartService
- `anti_debug`: IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess
- `shellcode_execution`: VirtualAlloc + VirtualProtect(PAGE_EXECUTE_*) + CreateThread
- `wmi_execution`: CoCreateInstance + IWbemLocator + IWbemServices
- `dns_exfiltration`: DnsQuery_A/W patterns
- Each pattern includes MITRE ATT&CK technique ID

```python
def analyze_pe_imports_detailed(file_path: str | Path, db_path: str | Path = None) -> dict
```
- Combines pefile import extraction + pattern detection + optional API DB enrichment
- Returns: full import list, pattern matches, per-DLL categorization, risk assessment

## Files to Modify

### 5. `winforensics_mcp/parsers/__init__.py`
Add imports:
```python
from .api_monitor import (
    build_api_database,
    lookup_api,
    search_api_by_category,
    get_api_stats,
    get_module_apis,
    detect_api_patterns,
    analyze_pe_imports_detailed,
    API_DB_AVAILABLE,
)
```
Add to `__all__`.

### 6. `winforensics_mcp/server.py`

**Imports section (~line 13-70):** Add imports for new functions.

**`list_tools()` (~line 244):** Register 4 new MCP tools:

| Tool Name | Description |
|---|---|
| `api_analyze_imports` | Detailed PE import analysis with pattern detection and API enrichment |
| `api_lookup` | Look up Windows API definition (signature, params, DLL, category) |
| `api_search_category` | Browse/search APIs by category |
| `api_detect_patterns` | Detect injection/evasion/persistence API patterns from PE imports |

**`_execute_tool()` (~line 2150):** Add 4 `elif` branches before the final `return json_response({"error": ...})`.

**Tool schemas:**

`api_analyze_imports`:
- `file_path` (required, string) — path to PE file
- `detect_patterns` (bool, default true) — run pattern detection
- `enrich_from_db` (bool, default false) — add API definitions from knowledge base

`api_lookup`:
- `api_name` (required, string) — API name or pattern (e.g., "CreateFileW", "Create*")
- `include_params` (bool, default true)

`api_search_category`:
- `category` (required, string) — category path or substring
- `limit` (int, default 50)

`api_detect_patterns`:
- `file_path` (required, string) — path to PE file

### 7. `pyproject.toml`
No changes needed — pefile is already a core dependency, xml.etree and sqlite3 are stdlib.

## Data Flow

```
API Monitor XML files (2,121 files)
        │
        ▼  [xml_parser.py - one-time build]
   api_definitions.db (SQLite)
        │
        ▼  [definitions_db.py - query layer]
   lookup_api / search_category / get_module_apis
        │
        ├──▶ api_lookup tool (standalone knowledge base queries)
        │
        └──▶ api_analyze_imports tool (enriches PE import analysis)
                    │
                    ├── pefile (import extraction)
                    └── patterns.py (pattern detection)
```

## DB Location Strategy

The SQLite DB will be stored at `winforensics_mcp/data/api_definitions.db`. The XML parser will:
1. Check if DB exists at that path
2. If not, check for XML source dir (configurable, default: look for `API/` in common locations)
3. Build DB on first use, or provide a `api_build_database` tool for explicit rebuild

For distribution: the pre-built DB (~5-10 MB) can ship with the package. The XML files are NOT required at runtime.

## Verification

1. **Unit test:** Parse a single XML file (e.g., Kernel32.xml) and verify API count, parameter extraction
2. **Integration test:** Build full DB from all 2,121 XMLs, query for known APIs
3. **MCP test:** Start server, call `api_lookup` with "CreateFileW", verify complete response
4. **Pattern test:** Run `api_detect_patterns` against a known malicious PE, verify injection patterns detected
5. **End-to-end:** `api_analyze_imports` on a sample PE — verify imports + patterns + enrichment

## Implementation Order

1. `xml_parser.py` — parse XMLs into SQLite (largest piece, ~300 lines)
2. `definitions_db.py` — query layer (~150 lines)
3. `patterns.py` — pattern detection (~200 lines)
4. `api_monitor/__init__.py` — exports
5. `parsers/__init__.py` — add new exports
6. `server.py` — register 4 new tools
7. Build the DB from the XML files in `apimonitor/API/`
8. Test all tools

---

## APMX64/APMX86 Capture File Format (Reverse-Engineered)

**Date:** February 12, 2026
**Source:** Reverse-engineered from `Ghost-Thread.apmx64` (3.4 MB, HTB Sherlock challenge)

### What APMX Files Are

APMX files are **save files from Rohitab API Monitor** — they capture every Win32 API call a monitored process made at runtime, with parameters, return values, timestamps, and call hierarchy. Think of them as the `.pcap` equivalent but for API calls instead of network packets.

- `.apmx64` — 64-bit capture
- `.apmx86` — 32-bit capture

### Container Format

The file is a **ZIP archive with a custom ASCII header prefix**:

```
[0x00 - 0xD4]  ASCII header block:
                "\r\n\r\n\r\n\tAPI Monitor 64-bit Capture\r\n"
                "\t(c) 2011-2013, Rohitab Batra <rohitab@rohitab.com>\r\n"
                "\thttp://www.rohitab.com/apimonitor/\r\n"
                (padded with \r\n to fixed size)

[0xD5 - 0xD9]  Marker: "RBAPMPK"
[0xDA - EOF]    Standard ZIP archive (starts with PK\x03\x04)
```

To open: skip to the first `PK\x03\x04` signature and pass to any ZIP library.

### ZIP Entry Structure

| Entry | Compressed | Uncompressed | Description |
|---|---|---|---|
| `info` | 84 B | 102 B | Binary metadata: version string (UTF-16LE), capture flags |
| `definitions` | 2.3 MB | 11 MB | API definitions active during capture (compressed XML knowledge base) |
| `log/monitoring.txt` | 811 B | 10 KB | UTF-16LE text log of module load/unload events |
| `process/0/info` | 678 B | 2.7 KB | Binary: process path, command line, loaded DLLs with base addresses, timestamps |
| `process/0/calls` | 80 KB | 240 KB | `uint64[]` offset table — one entry per captured API call |
| `process/0/data` | 1.2 MB | 14.2 MB | Binary blob of call records, indexed by `calls` offsets |
| `process/icons.bmp` | 428 B | 1 KB | Process icon bitmap |

Multi-process captures have `process/1/`, `process/2/`, etc.

### Call Record Structure (`process/N/data`)

The `calls` file is an array of little-endian `uint64` offsets into the `data` blob. Each offset points to a variable-length call record.

**Record layout (partially reverse-engineered):**

```
[0x00]       Flags/type byte
[0x04-0x07]  API index (uint32) — references the definitions blob
[0x08-0x0F]  Unknown (possibly parent call index for nesting)
[0x10-0x17]  Unknown
[0x28-0x2F]  Sequence number / call ordinal
[0x30-0x37]  Return address (uint64)
[0x38-0x3F]  Module base address (uint64)
[0x40-0x47]  Caller address (uint64)
[0x48-0x4F]  FILETIME timestamp (uint64 — Windows FILETIME)
...
[variable]   Embedded ASCII API function names (null-terminated)
[variable]   Parameter data (types vary per API)
[variable]   Nested/child call records (calls made within this call)
```

API names are stored as: `<length_byte> <0x00> <length_byte> <0x00> <ASCII name> <0x00>`

**Key finding:** Record boundaries are precisely known from the offset table, and each record contains one or more ASCII API names as plain strings. This makes extraction reliable even without fully decoding every binary field.

### Process Info Structure (`process/N/info`)

```
[0x00-0x03]  Process index (uint32)
[0x04-0x07]  Unknown
[0x08-0x0B]  PID (uint32)
[0x0C-0x13]  Image base address (uint64)
[0x14-0x17]  Path string length in chars (uint32)
[0x18-...]   Process path (UTF-16LE, null-terminated)
[...]        Command line (UTF-16LE, length-prefixed)
[...]        Timestamps (FILETIME pairs: creation, exit)
[...]        Module list: repeated entries of:
               [uint8 flags] [padding] [uint64 base_addr]
               [uint32 path_len] [UTF-16LE path]
```

### Monitoring Log (`log/monitoring.txt`)

UTF-16LE text file. Each line follows the pattern:
```
<process_name>: Monitoring Module 0x<base_address> -> <full_dll_path>.
<process_name>: Detaching Module 0x<base_address> -> <full_dll_path>.
```

### Test Data

- **File:** `/home/xtk/labs/AI/tests/Ghost-Thread.apmx64`
- **Process:** `inject.exe` from `C:\Users\karti\Downloads\inject.exe`
- **Call count:** 29,978 API calls captured
- **Context:** HTB Sherlock challenge — process injection technique identification
- **Loaded DLLs:** KERNEL32, ntdll, KERNELBASE, ADVAPI32, USER32, GDI32, etc.

### Implementation: `apmx_parser.py`

**New file:** `winforensics_mcp/parsers/api_monitor/apmx_parser.py`

**Functions:**

```python
def parse_apmx(file_path: str | Path) -> dict
```
- Opens APMX container, extracts metadata, process info, call summary
- Returns: process name/path/PID, module list, total call count, API frequency

```python
def get_apmx_calls(file_path: str | Path, process_index: int = 0,
                   api_filter: str = None, limit: int = 500, offset: int = 0) -> dict
```
- Extracts individual API call records with names, sequence, timestamps
- Supports filtering by API name pattern and pagination

```python
def detect_apmx_patterns(file_path: str | Path, process_index: int = 0) -> dict
```
- Runs the existing pattern detection engine against captured API calls
- Returns injection/evasion/persistence patterns with MITRE ATT&CK IDs

**MCP tools:**

| Tool | Description |
|---|---|
| `apmx_parse` | Parse APMX capture file — process info, modules, call statistics |
| `apmx_get_calls` | Extract API calls with filtering and pagination |
| `apmx_detect_patterns` | Detect attack patterns in captured API call sequences |

---

## Phase 2: APMX Parameter Value Extraction

**Date:** February 12-14, 2026
**Status:** IMPLEMENTED (core features complete)
**Priority:** HIGH — this is the single biggest gap preventing real forensic analysis

### Problem Statement

The current APMX parser extracts API **names** but NOT **parameter values**. When analyzing a capture like the Ghost-Thread challenge, we can see "OpenProcess was called" but NOT what PID was targeted, what access rights were requested, or what handle was returned. Every forensic question requires parameter values:

- "What PID was injected?" → needs OpenProcess `dwProcessId` param
- "What was the shellcode size?" → needs VirtualAllocEx `dwSize` param
- "What process was targeted?" → needs Process32NextW struct contents
- "What message was displayed?" → needs MessageBoxW string params

### Reverse Engineering Results

**API Monitor is NOT .NET** — it's native C++ (MSVC 16.00.40219, VS 2010, MFC static). RE was done via IDA Pro MCP integration on `apimonitor-x64.exe`.

#### Record Header (144 bytes, fully mapped via IDA RE + empirical analysis)

```
+0x00: uint16  marker (0x0101)
+0x04: uint32  format_version (0=Ghost-Thread, 7/8=Insider)
+0x08: uint32  record_index (sequential)
+0x0C: uint32  parent_index (0xFFFFFFFF = root/no parent)
+0x20: uint32  pre_params_size
+0x28: uint64  code_addr (offset into definitions blob)
+0x30: uint64  module_base_address
+0x48: uint64  timestamp (Windows FILETIME)
+0x58: uint32  post_params_size
+0x5C: uint32  section3_size (typically 8)
+0x6C: uint32  section4_size (API names + caller addresses)
+0x70: uint64  pre_params_ptr (absolute offset into data blob)
+0x78: uint64  post_params_ptr (0 = no post-call data)
+0x80: uint64  section3_ptr
+0x88: uint64  section4_ptr
```

#### Parameter Data Block Format

```
Byte 0: param_count
Byte 1: size_field (= param_count * 4 + 1)
Bytes 2..(size_field-1): descriptor entries (4 bytes each)
  Each entry: [b0] [b1] [b2] [b3]
  slot_count = b1 >> 4 = number of uint64 entries for this param
Byte size_field onward: uint64 values (LE), sequentially packed

CRITICAL: Last descriptor byte overlaps with first data byte at offset size_field.
```

#### Two Parameter Copies Per Record
1. **Pre-call block** (at pre_params_ptr): parameter values BEFORE the API was called
2. **Post-call block** (at post_params_ptr): parameter values AFTER the API returned
3. Comparing pre vs post reveals return values and output parameters

#### Value Extraction Heuristic (by slot count)
- **1 slot**: value = slot[0] (direct value: DWORD, BOOL, HANDLE)
- **2-4 slots**: check for [flag=0|1, address>0xFFFFFFFF, value] output pattern
- **5+ slots**: value = slot[0] (first slot is value, rest is type metadata)
- **94.8% match rate** across 998 verified records in Ghost-Thread

#### API Name Resolution (Two Sources)

1. **Embedded names** (sec4 of record): Higher-level Win32 API names (e.g., "OpenProcess"). Only present in some captures/records. Stored as `01 00 <len> 00 <ASCII> 00`.
2. **Definitions blob** resolution: `defs[code_addr + 0x18]` → uint64 name_ptr → null-terminated ASCII string. Always available. Returns lower-level native names (e.g., "NtOpenProcess").
3. **Priority**: Embedded names preferred (forensically relevant). Definitions name as fallback.
4. **100% resolution** across all 3 test files using combined approach.

#### Format Version Differences
- `+0x04 = 0x0` (Ghost-Thread): Param count includes return value, slot_count heuristic works well
- `+0x04 = 0x7` (Insider/wsl.exe): Proper param counts, reasonable slot counts
- `+0x04 = 0x8` (Insider/powershell.exe): Different descriptor encoding, slot counts 7-10, embedded string data in param blocks

### Implemented Functions

#### `get_apmx_call_details()` — Parameter values, return values, timestamps
```python
def get_apmx_call_details(
    file_path: str | Path,
    process_index: int = 0,
    call_indices: list[int] | None = None,
    api_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict
```
Returns calls with pre/post parameter values, return value detection, timestamps, parent-child relationships, embedded strings, and definitions-resolved native API names.

#### `correlate_apmx_handles()` — Handle chain reconstruction
```python
def correlate_apmx_handles(
    file_path: str | Path,
    process_index: int = 0,
    target_apis: list[str] | None = None,
    limit: int = 100,
) -> dict
```
Tracks handles from producers (OpenProcess, CreateFile, etc.) to consumers (VirtualAllocEx, WriteProcessMemory, etc.) including Nt* native API equivalents.

#### MCP Tools Registered

| Tool | Description |
|---|---|
| `apmx_get_call_details` | Detailed call records with pre/post parameter values |
| `apmx_correlate_handles` | Handle chain reconstruction (producer → consumer) |

### Verified Results (Ghost-Thread)

```
OpenProcess:        return=0x268, dwDesiredAccess=0x43A, bInheritHandle=1, dwProcessId=0x3F60
VirtualAllocEx:     hProcess=0x268, return=0x206583D0000, dwSize=0x1FF→0x1000, flProtect=PAGE_EXECUTE_READ(0x20)
WriteProcessMemory: hProcess=0x268, lpBaseAddress=0x206583D0000
Handle chain:       OpenProcess(0x268) → VirtualAllocEx → WriteProcessMemory(×4) → CreateRemoteThreadEx → CloseHandle
```

14 handle chains detected in Ghost-Thread capture.

### Test Coverage

76 tests total (67 core + 9 new dataset tests), all passing:
- `TestParseParamValues`: byte-overlap-aware param block parsing
- `TestParseCallRecord`: full record parsing with pre/post comparison
- `TestGetApmxCallDetails`: synthetic + real file call detail extraction
- `TestCorrelateHandles`: injection chain detection
- `TestGhostThreadCallDetails`: verified against known Ghost-Thread values
- `TestAttackerCapture`: definitions-only name resolution (no embedded names)
- `TestInsiderCapture`: multi-process, mixed names, pattern detection

### Remaining Work (Phase 2b)

1. **Named parameter mapping**: Use definitions blob to map positional params to names (e.g., param[1] → "dwDesiredAccess")
2. **Flag/enum decoding**: Decode `0x43A` → `PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|...` using type definitions
3. **Struct decoding**: Unpack PROCESSENTRY32W to show `th32ProcessID`, `szExeFile` fields
4. **String content extraction refinement**: Better UTF-16LE string detection in param blocks
5. **Format version 7/8 param parsing**: Full support for newer APMX format versions
6. **`search_apmx_params()`**: Search calls by parameter value across all records
