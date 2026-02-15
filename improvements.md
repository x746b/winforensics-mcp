# APMX Toolset Improvements (Win-Forensics-MCP)

Scope: `winforensics_mcp.parsers.api_monitor.apmx_parser` + related APMX-facing functions.

This is a concrete backlog derived from solving the Ghost-Thread challenge with `Ghost-Thread.apmx64`.

## P0: Correctness / Footguns

- Fix `process_index` inconsistencies
  - Problem: `parse_apmx()` reports `process_index: 1` while the rest of the API surface uses `process_index: 0`.
  - Impact: Easy to query the wrong process or fail to query at all.
  - Acceptance:
    - `parse_apmx()` uses 0-based indices (or clearly labels and returns both 0-based and 1-based).
    - All APMX functions accept the same index convention and validate bounds.
    - Add a regression test that asserts `parse_apmx(...).processes[0].index == 0` for Ghost-Thread.

- Make call attribution “top API first”
  - Problem: `get_apmx_call_details` can show confusing combinations like `api_name=SetXStateFeaturesMask` but `nested_apis=[CreateToolhelp32Snapshot]`.
  - Impact: Users (and automation) answer “wrong API” even when the nested call is the one asked for.
  - Improvement:
    - Return fields:
      - `top_api`: first extracted API name in the record (what analysts want)
      - `nested_apis`: full embedded chain (already present, but ensure ordering)
      - `resolved_api`: optional name resolved from `definitions` (native API)
    - Do not overwrite `api_name` with a less-useful value.
  - Acceptance:
    - For Ghost-Thread, “snapshot” queries clearly show `top_api=CreateToolhelp32Snapshot` on the record users would inspect.

## P1: Better Evidence Extraction (Reduce Guesswork)

- Decode Toolhelp output structures
  - Problem: Process enumeration via `CreateToolhelp32Snapshot` + `Process32First/Next` is not decoded into `PROCESSENTRY32(W)` fields.
  - Impact: Target process name/PID cannot be reliably extracted from API evidence; users resort to string scraping.
  - Improvement:
    - For `Process32FirstW` / `Process32NextW`: parse `PROCESSENTRY32W` at the pointer argument and expose:
      - `th32ProcessID`
      - `szExeFile`
      - (optional) `cntThreads`, `th32ParentProcessID`
    - For ANSI variants: `PROCESSENTRY32A`.
    - If the pointer is into the APMX `data` blob, interpret it accordingly; otherwise keep raw pointer.
  - Acceptance:
    - For Ghost-Thread, the tool can return `{exe: "notepad.exe", pid: 16224}` from Toolhelp records without heuristics.

- Add parameter naming for common APIs
  - Problem: Parameters are currently positional indexes with heuristics; not stable enough for answering “which PID / which size / which start routine”.
  - Improvement:
    - Add a small mapping for common APIs (start with):
      - `CreateToolhelp32Snapshot(dwFlags, th32ProcessID)`
      - `Process32FirstW(hSnapshot, lppe)`
      - `Process32NextW(hSnapshot, lppe)`
      - `OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)`
      - `VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)`
      - `WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)`
      - `CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)`
      - `ExitProcess(uExitCode)`
    - Expose `parameters_named` alongside the raw positional list.
  - Acceptance:
    - A caller can read `dwProcessId` (OpenProcess) and `nSize` (WriteProcessMemory) without relying on index order.

- Robust “shellcode size” inference helper
  - Problem: `VirtualAllocEx(dwSize)` may be coerced to page size; `WriteProcessMemory(nSize)` is the best indicator but isn’t surfaced reliably.
  - Improvement:
    - Provide a helper that builds an injection chain and returns:
      - `requested_alloc_size` (from `VirtualAllocEx` pre-value)
      - `aligned_alloc_size` (from `VirtualAllocEx` post-value if present)
      - `write_size` (from `WriteProcessMemory.nSize` and/or bytes-written out param)
      - `shellcode_size` chosen by priority: `write_size` then `requested_alloc_size`
  - Acceptance:
    - Ghost-Thread “shellcode size” returns `511` (requested) and `4096` (aligned), with `shellcode_size=511` by default.

## P2: Higher-Level Analytic Outputs (User Value)

- Injection chain extraction (“tell me what happened”)
  - Improvement:
    - Add a function that correlates records into chains:
      - `OpenProcess(pid)` -> `VirtualAllocEx(size)` -> `WriteProcessMemory(size)` -> `CreateRemoteThread(start)`
    - Return a concise list of chains with timestamps and record indices.
  - Acceptance:
    - For Ghost-Thread, one chain is emitted with PID 16224 and sizes populated.

- TLS / pre-main execution detection (heuristic label)
  - Problem: Pattern detection flags classic injection but misses the pre-main characteristic.
  - Improvement:
    - Add a lightweight behavior pattern like `tls_callback_execution` that triggers on:
      - very early TLS/FLS activity (`FlsAlloc`/`FlsSetValue` or `TlsAlloc`/`TlsSetValue`) AND
      - injection chain present AND
      - self-termination (`ExitProcess`) soon after
    - Keep it explicitly labeled as “heuristic”.
  - Acceptance:
    - Ghost-Thread yields `tls_callback_execution` in `detect_apmx_patterns()` output.

## P3: Quality-of-Life / Performance

- Better string extraction from pointers into the `data` blob
  - Improvement:
    - When a param value looks like an offset/pointer into the APMX `data` blob range, attempt safe bounded reads for ASCII/UTF-16 strings.
  - Acceptance:
    - Common path strings and process names are extracted without manual `strings` scraping.

- Add “context window” query utilities
  - Improvement:
    - `get_apmx_calls_around(call_index, before, after)`
    - `get_apmx_calls(time_range_start, time_range_end)`
  - Acceptance:
    - Large captures are navigable without pulling huge call ranges.

## Tests To Add

- Add a dedicated regression test for Ghost-Thread (already added in `tests/data/test_ghost_thread_regression.py`).
- Extend it once Toolhelp parsing exists:
  - Assert the tool can extract `notepad.exe` and `16224` from `Process32First/Next`.
- Add a test for shellcode size resolver:
  - Asserts `requested_alloc_size=511`, `aligned_alloc_size=4096`, `shellcode_size=511`.

## Notes / Constraints

- APMX captures can embed nested APIs; do not assume the first embedded name always matches the analyst’s question.
- Some params are out-params; treat `[flag, addr, value]` patterns explicitly and surface them as such.

