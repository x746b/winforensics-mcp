"""Detect known malicious API call patterns from PE import tables.

Checks imported APIs against a library of attack patterns mapped to
MITRE ATT&CK techniques. Can optionally enrich results with API
definitions from the knowledge base.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Pattern library - each pattern defines required and optional API sets
# ---------------------------------------------------------------------------
PATTERNS: dict[str, dict[str, Any]] = {
    "classic_injection": {
        "name": "Classic Process Injection",
        "description": "Opens a remote process, allocates memory, writes shellcode, and creates a remote thread.",
        "mitre_id": "T1055.001",
        "required": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "optional": {"NtCreateThreadEx", "RtlCreateUserThread"},
        "min_match": 3,
        "risk": "high",
    },
    "apc_injection": {
        "name": "APC Queue Injection",
        "description": "Injects code via asynchronous procedure calls into a remote thread.",
        "mitre_id": "T1055.004",
        "required": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"},
        "optional": {"NtQueueApcThread", "OpenThread"},
        "min_match": 3,
        "risk": "high",
    },
    "process_hollowing": {
        "name": "Process Hollowing",
        "description": "Creates a suspended process, unmaps its memory, and replaces it with malicious code.",
        "mitre_id": "T1055.012",
        "required": {"CreateProcessW", "CreateProcessA", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"},
        "optional": {"ZwUnmapViewOfSection", "GetThreadContext", "Wow64SetThreadContext"},
        "min_match": 4,
        "risk": "high",
    },
    "dll_injection": {
        "name": "DLL Injection via CreateRemoteThread",
        "description": "Injects a DLL into a remote process using LoadLibrary as the thread start routine.",
        "mitre_id": "T1055.001",
        "required": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "GetProcAddress"},
        "optional": {"LoadLibraryA", "LoadLibraryW", "GetModuleHandleA", "GetModuleHandleW"},
        "min_match": 4,
        "risk": "high",
    },
    "credential_dumping": {
        "name": "Credential Dumping (LSASS)",
        "description": "Opens LSASS process and reads its memory or creates a minidump for credential extraction.",
        "mitre_id": "T1003.001",
        "required": {"OpenProcess", "ReadProcessMemory"},
        "optional": {"MiniDumpWriteDump", "NtReadVirtualMemory", "EnumProcesses", "CreateToolhelp32Snapshot"},
        "min_match": 2,
        "risk": "high",
    },
    "token_manipulation": {
        "name": "Token Manipulation",
        "description": "Opens process tokens and duplicates or impersonates them for privilege escalation.",
        "mitre_id": "T1134.001",
        "required": {"OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser"},
        "optional": {"DuplicateToken", "SetThreadToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW"},
        "min_match": 2,
        "risk": "high",
    },
    "registry_persistence": {
        "name": "Registry Run Key Persistence",
        "description": "Modifies registry Run keys to establish persistence across reboots.",
        "mitre_id": "T1547.001",
        "required": {"RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW"},
        "optional": {"RegCreateKeyExA", "RegCreateKeyExW"},
        "min_match": 2,
        "risk": "medium",
    },
    "service_persistence": {
        "name": "Service Persistence",
        "description": "Creates or modifies a Windows service for persistence or privilege escalation.",
        "mitre_id": "T1543.003",
        "required": {"OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"},
        "optional": {"ChangeServiceConfigA", "ChangeServiceConfigW", "ChangeServiceConfig2A", "ChangeServiceConfig2W"},
        "min_match": 2,
        "risk": "medium",
    },
    "anti_debug": {
        "name": "Anti-Debugging Techniques",
        "description": "Uses debugger detection APIs to evade analysis.",
        "mitre_id": "T1622",
        "required": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"},
        "optional": {"OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter", "NtSetInformationThread"},
        "min_match": 1,
        "risk": "medium",
    },
    "shellcode_execution": {
        "name": "Shellcode Execution",
        "description": "Allocates executable memory, copies shellcode, and executes it in a new thread.",
        "mitre_id": "T1055.012",
        "required": {"VirtualAlloc", "VirtualProtect", "CreateThread"},
        "optional": {"RtlMoveMemory", "memcpy", "VirtualProtectEx", "NtProtectVirtualMemory"},
        "min_match": 2,
        "risk": "high",
    },
    "wmi_execution": {
        "name": "WMI Execution",
        "description": "Uses WMI COM interfaces for remote or local command execution.",
        "mitre_id": "T1047",
        "required": {"CoCreateInstance", "CoInitializeEx", "CoInitializeSecurity"},
        "optional": {"CoInitialize", "CoUninitialize"},
        "min_match": 2,
        "risk": "medium",
    },
    "dns_exfiltration": {
        "name": "DNS Exfiltration / C2",
        "description": "Uses DNS query APIs that may indicate DNS tunneling or C2 communication.",
        "mitre_id": "T1071.004",
        "required": {"DnsQuery_A", "DnsQuery_W", "DnsQueryEx"},
        "optional": {"DnsRecordListFree", "DnsFree"},
        "min_match": 1,
        "risk": "medium",
    },
    "screen_capture": {
        "name": "Screen Capture",
        "description": "Captures screen contents using GDI APIs.",
        "mitre_id": "T1113",
        "required": {"BitBlt", "GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap"},
        "optional": {"GetWindowDC", "GetDesktopWindow", "SelectObject", "DeleteDC", "ReleaseDC"},
        "min_match": 3,
        "risk": "medium",
    },
    "keylogging": {
        "name": "Keylogging",
        "description": "Hooks keyboard input or polls key state for keystroke capture.",
        "mitre_id": "T1056.001",
        "required": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState"},
        "optional": {"CallNextHookEx", "UnhookWindowsHookEx", "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW"},
        "min_match": 2,
        "risk": "high",
    },
    "network_download": {
        "name": "Network Download / C2",
        "description": "Downloads files or communicates with remote servers using WinINet/WinHTTP.",
        "mitre_id": "T1105",
        "required": {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA", "URLDownloadToFileW"},
        "optional": {"HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW", "InternetReadFile", "InternetConnectA", "InternetConnectW", "WinHttpOpen", "WinHttpConnect"},
        "min_match": 2,
        "risk": "medium",
    },
    "process_creation": {
        "name": "Process Creation (Defense Evasion)",
        "description": "Creates child processes, potentially for living-off-the-land execution.",
        "mitre_id": "T1059",
        "required": {"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "WinExec"},
        "optional": {"CreateProcessAsUserA", "CreateProcessAsUserW", "CreateProcessWithLogonW", "CreateProcessWithTokenW"},
        "min_match": 1,
        "risk": "low",
    },
    "tls_callback_execution": {
        "name": "TLS Callback Execution (Heuristic)",
        "description": "Early TLS/FLS activity combined with injection chain and self-termination "
                       "suggests code execution via TLS callbacks before main().",
        "mitre_id": "T1055.001",
        "required": {"FlsAlloc", "FlsSetValue", "ExitProcess"},
        "optional": {"TlsAlloc", "TlsSetValue", "FlsFree", "TlsFree", "FlsGetValue", "TlsGetValue"},
        "min_match": 2,
        "risk": "high",
        # Custom flag: detect_apmx_patterns applies a temporal check for this pattern.
        "_requires_temporal_check": True,
    },
}


def detect_api_patterns(imports: dict[str, list[str]]) -> dict[str, Any]:
    """Detect known malicious API call patterns from a PE import table.

    Args:
        imports: Import table dict {dll_name: [function_names, ...]}

    Returns:
        Dict with "patterns_detected", "risk_level", "details"
    """
    # Flatten all imported function names into a set for O(1) lookup
    all_apis: set[str] = set()
    for funcs in imports.values():
        for f in funcs:
            if not f.startswith("..."):  # skip truncation markers
                all_apis.add(f)

    detected = []
    risk_levels: list[str] = []

    for pattern_id, pattern in PATTERNS.items():
        all_pattern_apis = pattern["required"] | pattern.get("optional", set())
        matched = all_apis & all_pattern_apis
        required_matched = all_apis & pattern["required"]

        if len(matched) >= pattern["min_match"]:
            missing_required = pattern["required"] - all_apis
            detected.append({
                "pattern_name": pattern["name"],
                "pattern_id": pattern_id,
                "apis_matched": sorted(matched),
                "apis_missing": sorted(missing_required) if missing_required else [],
                "match_count": len(matched),
                "min_required": pattern["min_match"],
                "description": pattern["description"],
                "mitre_id": pattern["mitre_id"],
                "risk": pattern["risk"],
            })
            risk_levels.append(pattern["risk"])

    # Overall risk is the highest detected
    if "high" in risk_levels:
        overall_risk = "high"
    elif "medium" in risk_levels:
        overall_risk = "medium"
    elif "low" in risk_levels:
        overall_risk = "low"
    else:
        overall_risk = "none"

    return {
        "patterns_detected": len(detected),
        "risk_level": overall_risk,
        "details": detected,
    }


def analyze_pe_imports_detailed(
    file_path: str | Path, db_path: str | Path | None = None
) -> dict[str, Any]:
    """Full PE import analysis with pattern detection and optional API DB enrichment.

    Args:
        file_path: Path to PE file
        db_path: Optional path to api_definitions.db for enrichment

    Returns:
        Dict with imports, patterns, per-DLL info, and risk assessment
    """
    try:
        import pefile
    except ImportError:
        return {"error": "pefile library not installed. Install with: pip install pefile"}

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"PE file not found: {file_path}")

    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError as e:
        return {"error": f"Invalid PE file: {e}"}

    try:
        # Extract full imports (no truncation)
        imports: dict[str, list[str]] = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                except Exception:
                    dll_name = str(entry.dll)

                functions = []
                for imp in entry.imports:
                    if imp.name:
                        try:
                            functions.append(imp.name.decode("utf-8", errors="ignore"))
                        except Exception:
                            functions.append(str(imp.name))
                    elif imp.ordinal:
                        functions.append(f"ordinal_{imp.ordinal}")
                imports[dll_name] = functions

        # Run pattern detection
        pattern_results = detect_api_patterns(imports)

        # Per-DLL summary
        dll_summary = []
        for dll_name, funcs in imports.items():
            dll_info: dict[str, Any] = {
                "dll": dll_name,
                "function_count": len(funcs),
                "functions": funcs,
            }
            dll_summary.append(dll_info)

        result: dict[str, Any] = {
            "file": str(file_path),
            "total_dlls": len(imports),
            "total_imports": sum(len(v) for v in imports.values()),
            "imports": dll_summary,
            "patterns": pattern_results,
        }

        # Optional enrichment from API knowledge base
        if db_path and Path(db_path).exists():
            from .definitions_db import lookup_api

            enriched_count = 0
            for dll_info in dll_summary:
                for func_name in dll_info["functions"]:
                    if func_name.startswith("ordinal_"):
                        continue
                    api_info = lookup_api(db_path, func_name, include_params=False)
                    if api_info["count"] > 0:
                        enriched_count += 1
            result["enrichment"] = {
                "db_path": str(db_path),
                "apis_found_in_db": enriched_count,
                "coverage_pct": round(
                    enriched_count / max(result["total_imports"], 1) * 100, 1
                ),
            }

        return result

    finally:
        pe.close()
