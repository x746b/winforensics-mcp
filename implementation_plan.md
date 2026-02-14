# API Monitor MCP Integration — Implementation Plan

**Project:** winforensics-mcp v0.5.0+
**Date:** February 12, 2026
**Base:** Research from `apimonitor.md`

---

## What Exists vs What Needs Building

### Existing Python Libraries (No Windows Dependency)

| Library | PyPI | What It Gives You | Status |
|---|---|---|---|
| **pefile** | `pip install pefile` | Static PE import/export analysis (already a dep in project) | Ready - just needs wrapper |
| **etl-parser** | `pip install etl-parser` | Parse Windows ETW trace files (.etl) on Linux | Needs install |
| **procmon-parser** | `pip install procmon-parser` | Parse Procmon PML captures on Linux | Needs install |
| **python-evtx** | already a dep | Sysmon events (DLL loads, injection, registry) = API-level telemetry | Already integrated |

### What Must Be Coded From Scratch

| Component | Effort | Why |
|---|---|---|
| **API Definition XML Parser** | Medium | 2,121 XML files in `API/` — parse into queryable SQLite DB |
| **API Pattern Detection** | Medium | Injection chains, evasion, persistence patterns — no library exists |
| **ETW-to-API Correlation** | Medium | Map raw ETW events to meaningful API call names |
| **APMX File Parser** | Very High | Proprietary undocumented binary format — **skip for v1** |

### The Gold Mine: `API/` Directory

2,121 XML definition files covering ~13,000 APIs across 200 DLLs already downloaded. This is the knowledge base that makes API Monitor valuable. Parsing these into a SQLite DB gives:

- `lookup_api("CreateFileW")` → full signature, params, DLL, category
- `api_category_search("injection")` → all relevant APIs
- Correlation enrichment for ETL/Procmon/Sysmon events

### Realistic Assessment

**~60% leverages existing libraries, ~40% custom code.** The hardest part (APMX binary format) should be deferred. Everything else is achievable with the libraries above + the XML definitions.

---

## Phase 1 — Quick Wins (v0.5.0)

### 1. `analyze_pe_imports` Tool

- **Backend:** pefile (already a dependency)
- **What it does:** Static analysis of PE binary imports/exports
- **Effort:** Low — thin wrapper around existing pefile functionality
- **Output:** List of imported DLLs, function names, addresses; exported functions
- **Example query:** "What APIs does malware.exe import?"

### 2. `lookup_api` / `api_category_search` Tools

- **Backend:** Custom XML parser → SQLite database
- **What it does:** Query the API Monitor knowledge base (13,000+ API definitions)
- **Effort:** Medium — parse 2,121 XML files, build SQLite schema
- **Data model:**
  - Functions: name, DLL, calling convention, return type, category
  - Parameters: name, type, direction (in/out)
  - Structures/Unions: fields, types, sizes
  - Enumerations and Flags: name, values
- **Example queries:**
  - `lookup_api("CreateFileW")` → full signature, params, DLL, category
  - `api_category_search("File Services")` → all file-related APIs
  - `api_category_search("injection")` → APIs commonly used in injection

### 3. `detect_api_patterns` Tool

- **Backend:** Custom pattern engine
- **What it does:** Detect known API call patterns from import tables or trace data
- **Effort:** Medium — hardcoded pattern signatures
- **Pre-built patterns:**
  ```
  classic_injection:    OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
  apc_injection:        OpenProcess → VirtualAllocEx → WriteProcessMemory → QueueUserAPC
  process_hollowing:    CreateProcess(SUSPENDED) → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread
  dll_injection:        OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibrary)
  credential_access:    OpenProcess(lsass) → ReadProcessMemory
  persistence:          RegOpenKeyEx(Run) → RegSetValueEx
  evasion:              NtQueryInformationProcess / IsDebuggerPresent / CheckRemoteDebuggerPresent
  ```
- **Example query:** "Was there process injection in this binary's imports?"

---

## Phase 2 — Trace Analysis (v0.6.0)

### 4. `parse_etl_trace` Tool

- **Backend:** etl-parser (Airbus CERT)
- **What it does:** Parse offline ETW trace files collected from target systems
- **Effort:** Medium — library handles parsing, need correlation layer
- **Capabilities:**
  - Parse ETW manifest-based providers
  - Parse TraceLogging format
  - Parse MOF kernel logs
  - Convert network traces (etl2pcap)
- **Example query:** "Show API activity from this ETW trace"

### 5. `parse_procmon_capture` Tool

- **Backend:** procmon-parser
- **What it does:** Analyze Process Monitor PML capture files
- **Effort:** Medium — library handles parsing, need forensic query layer
- **Capabilities:**
  - Process/operation/path extraction
  - Filter by process, operation type, path
  - Timeline reconstruction
- **Example query:** "Analyze this Procmon capture for suspicious behavior"

### 6. `correlate_api_activity` Orchestrator

- **Backend:** All sources combined
- **What it does:** Unified API activity timeline from PE imports + ETL + Procmon + Sysmon
- **Effort:** High — cross-source correlation logic
- **Example query:** "Build a complete API activity timeline for this investigation"

---

## Phase 3 — Intelligence (v0.7.0+)

### 7. Sysmon-to-API Mapping

- Map Sysmon EVTX events to API-level representation:
  - Event ID 7 (ImageLoaded) → LoadLibrary/LdrLoadDll
  - Event ID 8 (CreateRemoteThread) → CreateRemoteThread
  - Event ID 10 (ProcessAccess) → OpenProcess
  - Event ID 11 (FileCreate) → CreateFile
  - Event ID 12/13/14 (Registry) → RegOpenKey/RegSetValue
  - Event ID 22 (DNS) → DnsQuery

### 8. APMX File Format (Deferred)

- Proprietary binary format, completely undocumented
- Would require full reverse engineering effort
- **Recommendation:** Defer until Rohitab adds export capability or community RE effort emerges
- **Workaround:** Users should use Procmon (PML) or ETW (ETL) for capturable traces

---

## New Dependencies

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
apimonitor = [
    "etl-parser",
    "procmon-parser",
    # pefile already a core dependency
    # python-evtx already a core dependency
]
```

---

## Module Structure

```
winforensics_mcp/
├── parsers/
│   ├── pe_analyzer.py          # EXISTING — extend with analyze_pe_imports
│   ├── etl_analyzer.py         # NEW — Phase 2
│   ├── procmon_analyzer.py     # NEW — Phase 2
│   └── api_monitor/            # NEW — Phase 1
│       ├── __init__.py
│       ├── xml_parser.py       # Parse API Monitor XML definitions
│       ├── definitions_db.py   # SQLite knowledge base
│       └── patterns.py         # API call pattern detection
├── data/
│   └── api_definitions.db      # Pre-built SQLite DB from XML definitions
└── server.py                   # Register new MCP tools
```

---

## Effort Summary

| Component | Phase | Effort | Library | Custom Code |
|---|---|---|---|---|
| PE Import/Export Analysis | 1 | Low | pefile | Thin wrapper |
| API Definition Knowledge Base | 1 | Medium | None | XML parser + SQLite |
| API Pattern Detection | 1 | Medium | None | Pattern engine |
| ETL/ETW Trace Parsing | 2 | Medium | etl-parser | Correlation layer |
| Procmon PML Parsing | 2 | Medium | procmon-parser | Query layer |
| Cross-source Correlation | 2 | High | None | Orchestration |
| Sysmon-to-API Mapping | 3 | Medium | python-evtx | Mapping layer |
| APMX File Format Parser | Deferred | Very High | None | Full RE |
