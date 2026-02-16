from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .parsers import (
    get_evtx_events,
    list_evtx_files,
    get_evtx_stats,
    search_security_events,
    get_event_id_description,
    get_registry_key,
    search_registry_values,
    get_run_keys,
    get_services,
    get_usb_devices,
    get_user_accounts,
    get_network_interfaces,
    get_system_info,
    analyze_pe,
    PEFILE_AVAILABLE,
    parse_prefetch_file,
    parse_prefetch_directory,
    PYSCCA_AVAILABLE,
    parse_amcache,
    parse_srum,
    PYESEDB_AVAILABLE,
    parse_mft,
    find_timestomped_files,
    MFT_AVAILABLE,
    parse_usn_journal,
    find_deleted_files,
    get_file_operations_summary,
    parse_browser_history,
    get_browser_downloads,
    parse_lnk_file,
    parse_lnk_directory,
    get_recent_files,
    PYLNK_AVAILABLE,
    parse_shellbags,
    find_suspicious_folders,
    ingest_csv,
    yara_scan_file,
    yara_scan_directory,
    yara_list_rules,
    YARA_AVAILABLE,
    vt_lookup_hash,
    vt_lookup_ip,
    vt_lookup_domain,
    vt_lookup_file,
    VT_AVAILABLE,
    get_pcap_stats,
    pcap_get_conversations,
    pcap_get_dns_queries,
    pcap_get_http_requests,
    search_pcap,
    pcap_find_suspicious,
    SCAPY_AVAILABLE,
    die_analyze_file,
    die_scan_directory,
    die_get_packer_info,
    DIE_AVAILABLE,
    build_api_database,
    lookup_api,
    search_api_by_category,
    get_api_stats,
    get_module_apis,
    detect_api_patterns,
    analyze_pe_imports_detailed,
    parse_apmx,
    get_apmx_calls,
    get_apmx_api_stats,
    detect_apmx_patterns,
    get_apmx_call_details,
    correlate_apmx_handles,
    get_apmx_injection_info,
    get_apmx_calls_around,
    search_apmx_params,
    API_DB_AVAILABLE,
)

from .orchestrators import investigate_execution, build_timeline, hunt_ioc, investigate_user_activity

from .collectors import (
    WinRMCollector,
    collect_triage_package,
    WINRM_AVAILABLE,
)

from .config import (
    IMPORTANT_EVENT_IDS,
    FORENSIC_REGISTRY_KEYS,
    MAX_EVTX_RESULTS,
    MAX_REGISTRY_RESULTS,
    MAX_PREFETCH_RESULTS,
    MAX_AMCACHE_RESULTS,
    MAX_TIMELINE_RESULTS,
    MAX_MFT_RESULTS,
    MAX_USN_RESULTS,
    MAX_RESPONSE_CHARS,
    TRUNCATE_KEEP_ITEMS,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("winforensics-mcp")

server = Server("winforensics-mcp")


def _truncate_array(arr: list, keep: int = TRUNCATE_KEEP_ITEMS) -> tuple[list, int]:
    """Truncate array keeping first N items, return (truncated_array, original_count)"""
    if len(arr) <= keep:
        return arr, len(arr)
    return arr[:keep], len(arr)


def _truncate_nested_arrays(item: dict, nested_keys: list[str], max_nested: int = 20) -> dict:
    """Truncate nested arrays within an item (e.g., loaded_files within prefetch entry)"""
    if not isinstance(item, dict):
        return item
    result = dict(item)
    for key in nested_keys:
        if key in result and isinstance(result[key], list) and len(result[key]) > max_nested:
            original_len = len(result[key])
            result[key] = result[key][:max_nested]
            result[f"{key}_truncated"] = True
            result[f"{key}_original_count"] = original_len
    return result


def _smart_truncate(data: Any, max_chars: int = MAX_RESPONSE_CHARS) -> tuple[Any, dict]:
    """
    Intelligently truncate response data to fit within max_chars.
    Returns (truncated_data, truncation_info).

    Strategy:
    1. First truncate nested arrays within items (e.g., loaded_files)
    2. Then reduce top-level array sizes progressively
    3. Add truncation metadata
    """
    # Known array keys that can be truncated (in priority order)
    ARRAY_KEYS = [
        "events", "entries", "prefetch_entries", "records", "files",
        "results", "timeline", "evidence", "matches", "history",
        "downloads", "shellbags", "lnk_files", "loaded_files",
        "run_keys", "services", "values", "subkeys"
    ]

    # Keys that contain nested arrays needing truncation
    NESTED_ARRAY_KEYS = ["loaded_files", "volumes", "files", "references"]

    truncation_info = {}

    # First, check if we're already under the limit
    initial_json = json.dumps(data, indent=2, default=str)
    if len(initial_json) <= max_chars:
        return data, truncation_info

    # If data is not a dict, we can't smart-truncate, just report the issue
    if not isinstance(data, dict):
        truncation_info["warning"] = f"Response too large ({len(initial_json)} chars), cannot auto-truncate non-dict"
        return data, truncation_info

    # Find and progressively truncate arrays
    modified = dict(data)  # Shallow copy

    # Step 1: Truncate nested arrays within items first
    for key in ARRAY_KEYS:
        if key not in modified:
            continue
        arr = modified[key]
        if not isinstance(arr, list) or len(arr) == 0:
            continue

        # Truncate nested arrays within each item
        modified[key] = [_truncate_nested_arrays(item, NESTED_ARRAY_KEYS) for item in arr]

    # Check if nested truncation was enough
    current_json = json.dumps(modified, indent=2, default=str)
    if len(current_json) <= max_chars:
        return modified, truncation_info

    # Step 2: Truncate top-level arrays
    for key in ARRAY_KEYS:
        if key not in modified:
            continue
        arr = modified[key]
        if not isinstance(arr, list) or len(arr) == 0:
            continue

        # Calculate how much we need to reduce
        current_json = json.dumps(modified, indent=2, default=str)
        if len(current_json) <= max_chars:
            break

        # Estimate items to keep based on average item size
        arr_json = json.dumps(arr, indent=2, default=str)
        if len(arr) > 0:
            avg_item_size = len(arr_json) / len(arr)
            excess_chars = len(current_json) - max_chars
            items_to_remove = int(excess_chars / avg_item_size) + 1
            keep_count = max(TRUNCATE_KEEP_ITEMS, len(arr) - items_to_remove)

            if keep_count < len(arr):
                truncation_info[key] = {
                    "original_count": len(arr),
                    "returned_count": keep_count,
                    "truncated": True
                }
                modified[key] = arr[:keep_count]

    # Final check - if still too large, do aggressive truncation
    final_json = json.dumps(modified, indent=2, default=str)
    if len(final_json) > max_chars:
        # Aggressive: reduce all arrays to minimum
        for key in ARRAY_KEYS:
            if key in modified and isinstance(modified[key], list) and len(modified[key]) > TRUNCATE_KEEP_ITEMS:
                original_len = truncation_info.get(key, {}).get("original_count", len(modified[key]))
                modified[key] = modified[key][:TRUNCATE_KEEP_ITEMS]
                truncation_info[key] = {
                    "original_count": original_len,
                    "returned_count": TRUNCATE_KEEP_ITEMS,
                    "truncated": True
                }

    return modified, truncation_info


def json_response(data: Any, max_chars: int = MAX_RESPONSE_CHARS) -> str:
    """Convert data to JSON string for response, with smart truncation if too large"""

    # Try without truncation first
    result = json.dumps(data, indent=2, default=str)

    if len(result) <= max_chars:
        return result

    # Apply smart truncation
    truncated_data, truncation_info = _smart_truncate(data, max_chars)

    # Add truncation metadata to response
    if isinstance(truncated_data, dict) and truncation_info:
        truncated_data["_truncation"] = {
            "warning": "Response was truncated to fit context limits. IMPORTANT: Oldest data was kept, newest may be missing!",
            "original_chars": len(result),
            "max_chars": max_chars,
            "truncated_arrays": truncation_info,
            "hint": "Use time_range_start/end to focus on incident window, or use offset parameter to paginate through all results"
        }

    return json.dumps(truncated_data, indent=2, default=str)


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available forensics tools"""
    tools = [
        Tool(
            name="evtx_list_files",
            description="List all EVTX (Windows Event Log) files in a directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory path to search"},
                    "recursive": {"type": "boolean", "default": True},
                },
                "required": ["directory"],
            },
        ),
        Tool(
            name="evtx_get_stats",
            description="Get statistics about an EVTX file: event counts, time range, Event ID distribution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {"type": "string", "description": "Path to EVTX file"},
                },
                "required": ["evtx_path"],
            },
        ),
        Tool(
            name="evtx_search",
            description="Search events from EVTX file. Filter by time, Event ID, keywords, provider. Supports pagination with offset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {"type": "string"},
                    "event_ids": {"type": "array", "items": {"type": "integer"}},
                    "start_time": {"type": "string", "description": "ISO format datetime"},
                    "end_time": {"type": "string"},
                    "contains": {"type": "array", "items": {"type": "string"}},
                    "not_contains": {"type": "array", "items": {"type": "string"}},
                    "provider": {"type": "string"},
                    "limit": {"type": "integer", "default": MAX_EVTX_RESULTS, "description": "Max results to return (default 50)"},
                    "offset": {"type": "integer", "default": 0, "description": "Skip first N matches for pagination"},
                },
                "required": ["evtx_path"],
            },
        ),
        Tool(
            name="evtx_security_search",
            description="Search for security events by type: logon, failed_logon, process_creation, etc. Supports pagination with offset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {"type": "string"},
                    "event_type": {
                        "type": "string",
                        "enum": ["logon", "failed_logon", "logoff", "process_creation",
                                "service_installed", "account_created", "account_modified",
                                "privilege_use", "log_cleared", "scheduled_task",
                                "kerberos", "lateral_movement", "credential_access"],
                    },
                    "limit": {"type": "integer", "default": MAX_EVTX_RESULTS, "description": "Max results to return (default 50)"},
                    "offset": {"type": "integer", "default": 0, "description": "Skip first N matches for pagination"},
                },
                "required": ["evtx_path", "event_type"],
            },
        ),
        Tool(
            name="evtx_explain_event_id",
            description="Get description of a Windows Event ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "integer"},
                    "channel": {"type": "string", "default": "Security"},
                },
                "required": ["event_id"],
            },
        ),
        Tool(
            name="registry_get_key",
            description="Get registry key and values from a hive file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string"},
                    "key_path": {"type": "string"},
                    "max_depth": {"type": "integer", "default": 3},
                },
                "required": ["hive_path", "key_path"],
            },
        ),
        Tool(
            name="registry_search",
            description="Search registry values by pattern.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string"},
                    "pattern": {"type": "string"},
                    "search_names": {"type": "boolean", "default": True},
                    "search_data": {"type": "boolean", "default": True},
                    "limit": {"type": "integer", "default": MAX_REGISTRY_RESULTS},
                },
                "required": ["hive_path", "pattern"],
            },
        ),
        Tool(
            name="registry_get_persistence",
            description="Get persistence mechanisms (Run keys, services) from registry.",
            inputSchema={
                "type": "object",
                "properties": {
                    "software_hive": {"type": "string"},
                    "system_hive": {"type": "string"},
                    "ntuser_hive": {"type": "string"},
                    "include_microsoft_services": {"type": "boolean", "default": False},
                },
            },
        ),
        Tool(
            name="registry_get_users",
            description="Get user accounts from SAM hive.",
            inputSchema={
                "type": "object",
                "properties": {"sam_path": {"type": "string"}},
                "required": ["sam_path"],
            },
        ),
        Tool(
            name="registry_get_usb_history",
            description="Get USB device history from SYSTEM hive.",
            inputSchema={
                "type": "object",
                "properties": {"system_hive": {"type": "string"}},
                "required": ["system_hive"],
            },
        ),
        Tool(
            name="registry_get_system_info",
            description="Get OS version, computer name, timezone from registry.",
            inputSchema={
                "type": "object",
                "properties": {
                    "software_hive": {"type": "string"},
                    "system_hive": {"type": "string"},
                },
                "required": ["software_hive", "system_hive"],
            },
        ),
        Tool(
            name="registry_get_network",
            description="Get network configuration from SYSTEM hive.",
            inputSchema={
                "type": "object",
                "properties": {"system_hive": {"type": "string"}},
                "required": ["system_hive"],
            },
        ),
        Tool(
            name="forensics_list_important_events",
            description="List important Event IDs for a log channel.",
            inputSchema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "enum": ["Security", "System", "PowerShell", "Sysmon"]},
                },
                "required": ["channel"],
            },
        ),
        Tool(
            name="forensics_list_registry_keys",
            description="List forensically important registry keys.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["persistence", "services", "network", "usb", "user_activity", "system_info"],
                    },
                },
            },
        ),
    ]

    # PE Analysis tools (if pefile available)
    if PEFILE_AVAILABLE:
        tools.append(
            Tool(
                name="file_analyze_pe",
                description="Perform static analysis on Windows PE files (EXE/DLL/SYS). Extracts headers, imports, exports, sections, calculates hashes (MD5/SHA1/SHA256/Imphash), and detects packers/suspicious indicators.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the PE file to analyze"},
                        "calculate_hashes": {
                            "type": "boolean",
                            "default": True,
                            "description": "Calculate MD5, SHA1, SHA256, Imphash",
                        },
                        "extract_strings": {
                            "type": "boolean",
                            "default": False,
                            "description": "Extract ASCII/Unicode strings (can be verbose)",
                        },
                        "check_signatures": {
                            "type": "boolean",
                            "default": True,
                            "description": "Check for known packer/crypter signatures",
                        },
                        "detail_level": {
                            "type": "string",
                            "enum": ["minimal", "standard", "verbose"],
                            "default": "standard",
                            "description": "Level of detail: minimal (hashes+type), standard (+ sections/imports), verbose (+ all data)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )

    # YARA scanning tools (if yara-python available)
    if YARA_AVAILABLE:
        tools.append(
            Tool(
                name="yara_scan_file",
                description="Scan a file with YARA rules for malware detection. Uses bundled signature-base rules by default (Mimikatz, CobaltStrike, webshells, ransomware, etc.).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file to scan",
                        },
                        "rule_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Custom YARA rule paths (files or directories). Uses bundled rules if not specified.",
                        },
                        "timeout": {
                            "type": "integer",
                            "default": 60,
                            "description": "Scan timeout in seconds",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="yara_scan_directory",
                description="Scan directory for malware with YARA rules. Returns only files with matches. Uses bundled signature-base rules by default.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Directory to scan",
                        },
                        "rule_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Custom YARA rule paths",
                        },
                        "file_pattern": {
                            "type": "string",
                            "default": "*",
                            "description": "Glob pattern for files (e.g., '*.exe', '*.dll')",
                        },
                        "recursive": {
                            "type": "boolean",
                            "default": True,
                            "description": "Search subdirectories",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum files to scan",
                        },
                    },
                    "required": ["directory"],
                },
            )
        )
        tools.append(
            Tool(
                name="yara_list_rules",
                description="List available YARA rules. Shows bundled rules or custom rules from specified paths.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "rule_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Custom rule paths to list. Lists bundled rules if not specified.",
                        },
                    },
                },
            )
        )

    # VirusTotal tools (if vt-py available)
    if VT_AVAILABLE:
        tools.append(
            Tool(
                name="vt_lookup_hash",
                description="Look up file hash (MD5/SHA1/SHA256) on VirusTotal for threat intelligence. "
                           "Returns AV detections, threat names, verdict, and file metadata. "
                           "Requires VIRUSTOTAL_API_KEY env var. Rate limited (15s between requests).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_hash": {
                            "type": "string",
                            "description": "MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hash",
                        },
                    },
                    "required": ["file_hash"],
                },
            )
        )
        tools.append(
            Tool(
                name="vt_lookup_ip",
                description="Look up IP address reputation on VirusTotal. "
                           "Returns AV verdicts, ASN info, country, and reputation score. "
                           "Requires VIRUSTOTAL_API_KEY env var.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ip_address": {
                            "type": "string",
                            "description": "IPv4 or IPv6 address",
                        },
                    },
                    "required": ["ip_address"],
                },
            )
        )
        tools.append(
            Tool(
                name="vt_lookup_domain",
                description="Look up domain reputation on VirusTotal. "
                           "Returns AV verdicts, registrar, creation date, and categorizations. "
                           "Requires VIRUSTOTAL_API_KEY env var.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain name (e.g., 'evil.com')",
                        },
                    },
                    "required": ["domain"],
                },
            )
        )
        tools.append(
            Tool(
                name="vt_lookup_file",
                description="Calculate file hash and look up on VirusTotal. "
                           "Combines local hashing + VT lookup in one call. "
                           "Requires VIRUSTOTAL_API_KEY env var.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file to hash and look up",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )

    # PCAP parsing tools (if scapy available)
    if SCAPY_AVAILABLE:
        tools.append(
            Tool(
                name="pcap_get_stats",
                description="Get statistics from a PCAP/PCAPNG file including packet counts, "
                           "time range, protocol distribution, top talkers, and top ports.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "max_packets": {
                            "type": "integer",
                            "default": 100000,
                            "description": "Maximum packets to analyze (for large files)",
                        },
                    },
                    "required": ["pcap_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="pcap_get_conversations",
                description="Extract network conversations (TCP/UDP flows) from PCAP. "
                           "Shows source/destination, ports, packet counts, bytes, and duration.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "protocol": {
                            "type": "string",
                            "enum": ["all", "tcp", "udp"],
                            "default": "all",
                            "description": "Filter by protocol",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum conversations to return",
                        },
                        "min_packets": {
                            "type": "integer",
                            "default": 1,
                            "description": "Minimum packets for a conversation to be included",
                        },
                    },
                    "required": ["pcap_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="pcap_get_dns",
                description="Extract DNS queries and responses from PCAP. "
                           "Shows query names, types, response IPs, and top queried domains.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum queries to return",
                        },
                        "query_filter": {
                            "type": "string",
                            "description": "Filter by domain name (substring match)",
                        },
                    },
                    "required": ["pcap_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="pcap_get_http",
                description="Extract HTTP requests from PCAP. "
                           "Shows method, host, URI, user-agent, and content-type.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum requests to return",
                        },
                        "url_filter": {
                            "type": "string",
                            "description": "Filter by URL (substring match)",
                        },
                        "method_filter": {
                            "type": "string",
                            "description": "Filter by HTTP method (GET, POST, etc.)",
                        },
                    },
                    "required": ["pcap_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="pcap_search",
                description="Search for pattern in packet payloads. "
                           "Supports string or regex search.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "pattern": {
                            "type": "string",
                            "description": "String or regex pattern to search for",
                        },
                        "regex": {
                            "type": "boolean",
                            "default": False,
                            "description": "Treat pattern as regex",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum matches to return",
                        },
                    },
                    "required": ["pcap_path", "pattern"],
                },
            )
        )
        tools.append(
            Tool(
                name="pcap_find_suspicious",
                description="Detect suspicious network activity in PCAP. "
                           "Finds: suspicious ports (4444, etc.), beaconing patterns, "
                           "DNS tunneling indicators, suspicious user-agents, large outbound transfers.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Path to PCAP or PCAPNG file",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum findings per category",
                        },
                    },
                    "required": ["pcap_path"],
                },
            )
        )

    # DiE (Detect It Easy) tools (if diec available)
    if DIE_AVAILABLE:
        tools.append(
            Tool(
                name="die_analyze_file",
                description="Analyze file with Detect It Easy (DiE). "
                           "Detects packers (UPX, Themida, VMProtect), compilers (MSVC, GCC), "
                           ".NET, installers, and file types. Requires diec CLI.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file to analyze",
                        },
                        "deep_scan": {
                            "type": "boolean",
                            "default": False,
                            "description": "Enable deep scan mode (slower but more thorough)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="die_scan_directory",
                description="Scan directory for executables and analyze with DiE. "
                           "Identifies packed files, compilers used, and provides summary statistics.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "dir_path": {
                            "type": "string",
                            "description": "Directory to scan",
                        },
                        "recursive": {
                            "type": "boolean",
                            "default": True,
                            "description": "Scan subdirectories",
                        },
                        "deep_scan": {
                            "type": "boolean",
                            "default": False,
                            "description": "Enable deep scan mode",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum files to scan",
                        },
                    },
                    "required": ["dir_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="die_get_packer_info",
                description="Get information about a packer/protector including "
                           "unpacking difficulty, tools, and common usage (legitimate vs malware).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "packer_name": {
                            "type": "string",
                            "description": "Packer name (e.g., 'UPX', 'Themida', 'VMProtect')",
                        },
                    },
                    "required": ["packer_name"],
                },
            )
        )

    # API Monitor tools (API knowledge base, import analysis, pattern detection)
    if API_DB_AVAILABLE:
        tools.append(
            Tool(
                name="api_analyze_imports",
                description="Detailed PE import analysis with pattern detection and API enrichment. "
                           "Extracts all imports, detects injection/evasion/persistence patterns with "
                           "MITRE ATT&CK mapping, and optionally enriches with API definitions.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to PE file to analyze",
                        },
                        "detect_patterns": {
                            "type": "boolean",
                            "default": True,
                            "description": "Run pattern detection against import table",
                        },
                        "enrich_from_db": {
                            "type": "boolean",
                            "default": False,
                            "description": "Add API definitions from knowledge base (requires built DB)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="api_lookup",
                description="Look up Windows API definition (signature, params, DLL, category) "
                           "from the API Monitor knowledge base. Supports wildcards (e.g., 'Create*').",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "api_name": {
                            "type": "string",
                            "description": "API name or pattern (e.g., 'CreateFileW', 'NtCreate*')",
                        },
                        "include_params": {
                            "type": "boolean",
                            "default": True,
                            "description": "Include parameter details in results",
                        },
                    },
                    "required": ["api_name"],
                },
            )
        )
        tools.append(
            Tool(
                name="api_search_category",
                description="Browse/search Windows APIs by category. Categories are hierarchical "
                           "(e.g., 'Data Access and Storage/Local File Systems/File Management').",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Category path or substring to search",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum results to return",
                        },
                    },
                    "required": ["category"],
                },
            )
        )
        tools.append(
            Tool(
                name="api_detect_patterns",
                description="Detect injection/evasion/persistence API patterns from PE imports. "
                           "Returns matched patterns with MITRE ATT&CK technique IDs and risk levels.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to PE file to analyze",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )

        # APMX capture file tools
        tools.append(
            Tool(
                name="apmx_parse",
                description="Parse Rohitab API Monitor capture file (.apmx64/.apmx86). "
                           "Returns process info (name, PID, path, command line), loaded modules, "
                           "and API call count. Use this first to understand what's in a capture.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="apmx_get_calls",
                description="Extract API call records from an APMX capture with filtering and pagination. "
                           "Each record shows the top-level API and any nested calls made within it.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to read (0 = first/only process)",
                        },
                        "api_filter": {
                            "type": "string",
                            "description": "Filter by API name substring (case-insensitive)",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 500,
                            "description": "Maximum number of call records to return",
                        },
                        "offset": {
                            "type": "integer",
                            "default": 0,
                            "description": "Skip first N matching records (for pagination)",
                        },
                        "time_range_start": {
                            "type": "string",
                            "description": "ISO 8601 datetime — only include calls at or after this time",
                        },
                        "time_range_end": {
                            "type": "string",
                            "description": "ISO 8601 datetime — only include calls at or before this time",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="apmx_detect_patterns",
                description="Detect injection/evasion/persistence patterns in APMX captured API calls. "
                           "Analyzes runtime behavior (actually-called APIs) against known attack patterns "
                           "with MITRE ATT&CK technique IDs. Returns risk level and suspicious call timeline.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to analyze (0 = first/only process)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )

        tools.append(
            Tool(
                name="apmx_get_call_details",
                description="Extract detailed API call records with parameter values, return values, "
                           "and timestamps from an APMX capture. Shows pre-call and post-call parameter "
                           "values, identifies return values by comparing pre/post state, and extracts "
                           "embedded strings. Use call_indices for specific records or api_filter to search.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to read (0 = first/only process)",
                        },
                        "call_indices": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Specific record indices to retrieve (overrides filter/pagination)",
                        },
                        "api_filter": {
                            "type": "string",
                            "description": "Filter by API name substring (case-insensitive)",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum number of detailed records to return",
                        },
                        "offset": {
                            "type": "integer",
                            "default": 0,
                            "description": "Skip first N matching records (for pagination)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="apmx_correlate_handles",
                description="Track handle values across API calls to reconstruct operation chains. "
                           "Identifies handle-producing APIs (OpenProcess, CreateFile, etc.) and traces "
                           "where those handles are consumed (VirtualAllocEx, WriteProcessMemory, etc.). "
                           "Reveals attack chains like: OpenProcess -> VirtualAllocEx -> WriteProcessMemory "
                           "-> CreateRemoteThread.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to analyze (0 = first/only process)",
                        },
                        "target_apis": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Limit to specific APIs (default: common injection/evasion APIs)",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum number of handle chains to return",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )

        tools.append(
            Tool(
                name="apmx_injection_info",
                description="Extract enriched injection chain details from an APMX capture. "
                           "Returns target PID, target process name, shellcode size (requested vs aligned), "
                           "start address, and injection technique label. Wraps handle correlation with "
                           "parameter decoding for a forensic-friendly summary.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to analyze (0 = first/only process)",
                        },
                    },
                    "required": ["file_path"],
                },
            )
        )
        tools.append(
            Tool(
                name="apmx_calls_around",
                description="Get a context window of API calls around a specific record index. "
                           "Returns detailed call records in the range [call_index-before, call_index+after]. "
                           "Useful for understanding what happened immediately before and after a suspicious call.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "call_index": {
                            "type": "integer",
                            "description": "The center record index to look around",
                        },
                        "before": {
                            "type": "integer",
                            "default": 10,
                            "description": "Number of records before the target to include",
                        },
                        "after": {
                            "type": "integer",
                            "default": 10,
                            "description": "Number of records after the target to include",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to read (0 = first/only process)",
                        },
                    },
                    "required": ["file_path", "call_index"],
                },
            )
        )
        tools.append(
            Tool(
                name="apmx_search_params",
                description="Search API calls by parameter value in an APMX capture. "
                           "Finds all calls where a specific integer (e.g., PID, handle, size) or "
                           "string appears as a parameter value. Returns matching calls with the "
                           "matched parameters highlighted.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to .apmx64 or .apmx86 capture file",
                        },
                        "value": {
                            "description": "Integer or string value to search for in parameters",
                        },
                        "process_index": {
                            "type": "integer",
                            "default": 0,
                            "description": "Which process to search (0 = first/only process)",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum number of matching calls to return",
                        },
                    },
                    "required": ["file_path", "value"],
                },
            )
        )

    # Prefetch parsing tools (if libscca available)
    if PYSCCA_AVAILABLE:
        tools.append(
            Tool(
                name="disk_parse_prefetch",
                description="Parse Windows Prefetch files to determine program execution history, run counts, and last execution times. Can parse a single .pf file or an entire Prefetch directory. Supports pagination.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to .pf file or Prefetch directory",
                        },
                        "executable_filter": {
                            "type": "string",
                            "description": "Filter by executable name (case-insensitive substring). Only applies to directory parsing.",
                        },
                        "include_loaded_files": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include list of files/DLLs loaded by the executable (WARNING: increases output size significantly)",
                        },
                        "limit": {
                            "type": "integer",
                            "default": MAX_PREFETCH_RESULTS,
                            "description": "Maximum number of prefetch entries to return (default 20)",
                        },
                        "offset": {
                            "type": "integer",
                            "default": 0,
                            "description": "Skip first N entries for pagination",
                        },
                    },
                    "required": ["path"],
                },
            )
        )

    # Amcache parsing tool (uses python-registry, always available)
    tools.append(
        Tool(
            name="disk_parse_amcache",
            description="Parse Amcache.hve to extract program execution evidence with SHA1 hashes, file paths, and timestamps. Proves a file existed and was prepared for execution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "amcache_path": {
                        "type": "string",
                        "description": "Path to Amcache.hve file",
                    },
                    "sha1_filter": {
                        "type": "string",
                        "description": "Filter by SHA1 hash (case-insensitive)",
                    },
                    "path_filter": {
                        "type": "string",
                        "description": "Filter by file path (case-insensitive substring)",
                    },
                    "name_filter": {
                        "type": "string",
                        "description": "Filter by file name (case-insensitive substring)",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter entries after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter entries before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": MAX_AMCACHE_RESULTS,
                        "description": "Maximum number of entries to return",
                    },
                },
                "required": ["amcache_path"],
            },
        )
    )

    # SRUM parsing tool (if libesedb available)
    if PYESEDB_AVAILABLE:
        tools.append(
            Tool(
                name="disk_parse_srum",
                description="Parse SRUDB.dat for application resource usage including CPU time, network bytes sent/received, and foreground time. Answers: How long did this program run? What was its network activity?",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "srum_path": {
                            "type": "string",
                            "description": "Path to SRUDB.dat file",
                        },
                        "table": {
                            "type": "string",
                            "enum": ["app_resource_usage", "network_data_usage", "all"],
                            "default": "app_resource_usage",
                            "description": "Which SRUM table to parse",
                        },
                        "app_filter": {
                            "type": "string",
                            "description": "Filter by application name (case-insensitive substring)",
                        },
                        "time_range_start": {
                            "type": "string",
                            "description": "ISO format datetime - filter entries after this time",
                        },
                        "time_range_end": {
                            "type": "string",
                            "description": "ISO format datetime - filter entries before this time",
                        },
                        "limit": {
                            "type": "integer",
                            "default": MAX_AMCACHE_RESULTS,
                            "description": "Maximum number of entries to return",
                        },
                    },
                    "required": ["srum_path"],
                },
            )
        )

    # Execution investigation orchestrator
    tools.append(
        Tool(
            name="investigate_execution",
            description="Comprehensive execution analysis. Correlates Prefetch, Amcache, and SRUM to prove or disprove binary execution. Answers: Was this binary executed? When? How long did it run? Provides confidence scoring and unified timeline.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Executable name (e.g., 'mimikatz.exe'), file path, or SHA1 hash to investigate",
                    },
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Base directory containing forensic artifacts (Prefetch, Amcache.hve, SRUDB.dat). Tool will auto-detect common paths.",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter events after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter events before this time",
                    },
                    "prefetch_path": {
                        "type": "string",
                        "description": "Override auto-detected Prefetch directory path",
                    },
                    "amcache_path": {
                        "type": "string",
                        "description": "Override auto-detected Amcache.hve path",
                    },
                    "srum_path": {
                        "type": "string",
                        "description": "Override auto-detected SRUDB.dat path",
                    },
                },
                "required": ["target", "artifacts_dir"],
            },
        )
    )

    # Timeline builder orchestrator
    tools.append(
        Tool(
            name="build_timeline",
            description="Build comprehensive forensic timeline from multiple artifact sources (MFT, USN Journal, Prefetch, Amcache, EVTX). Returns sorted, deduplicated events. Answers: What happened and when? Provides unified chronological view of system activity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Base directory containing forensic artifacts. Tool will auto-detect common paths for MFT, USN, Prefetch, etc.",
                    },
                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["mft", "usn", "prefetch", "amcache", "evtx"],
                        },
                        "default": ["mft", "usn", "prefetch", "amcache"],
                        "description": "List of sources to include in timeline",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - include events after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - include events before this time",
                    },
                    "keyword_filter": {
                        "type": "string",
                        "description": "Filter events containing this keyword (case-insensitive)",
                    },
                    "limit": {
                        "type": "integer",
                        "default": MAX_TIMELINE_RESULTS,
                        "description": "Maximum number of events to return",
                    },
                    "mft_path": {
                        "type": "string",
                        "description": "Override auto-detected $MFT path",
                    },
                    "usn_path": {
                        "type": "string",
                        "description": "Override auto-detected USN Journal path",
                    },
                    "prefetch_path": {
                        "type": "string",
                        "description": "Override auto-detected Prefetch directory path",
                    },
                    "amcache_path": {
                        "type": "string",
                        "description": "Override auto-detected Amcache.hve path",
                    },
                    "evtx_path": {
                        "type": "string",
                        "description": "Override auto-detected EVTX directory path",
                    },
                },
                "required": ["artifacts_dir"],
            },
        )
    )

    # IOC Hunter orchestrator
    tools.append(
        Tool(
            name="hunt_ioc",
            description="Hunt for IOC (hash, filename, IP, domain) across all forensic artifacts. Searches Prefetch, Amcache, SRUM, MFT, USN Journal, Browser History, EVTX logs, and optionally YARA rules. Answers: Where does this IOC appear? Was this file/hash/domain seen on the system? Is it known malware?",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "The indicator to search for: MD5/SHA1/SHA256 hash, filename, IP address, or domain",
                    },
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Base directory containing forensic artifacts. Tool will auto-detect common paths.",
                    },
                    "ioc_type": {
                        "type": "string",
                        "enum": ["auto", "md5", "sha1", "sha256", "ip", "domain", "filename"],
                        "default": "auto",
                        "description": "Type of IOC (auto-detected if not specified)",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter events after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter events before this time",
                    },
                    "yara_scan": {
                        "type": "boolean",
                        "default": False,
                        "description": "If True, scan the file with YARA rules when IOC is a filename and file is found. Provides threat intelligence (is it known malware?).",
                    },
                    "prefetch_path": {
                        "type": "string",
                        "description": "Override auto-detected Prefetch directory path",
                    },
                    "amcache_path": {
                        "type": "string",
                        "description": "Override auto-detected Amcache.hve path",
                    },
                    "srum_path": {
                        "type": "string",
                        "description": "Override auto-detected SRUDB.dat path",
                    },
                    "mft_path": {
                        "type": "string",
                        "description": "Override auto-detected $MFT path",
                    },
                    "usn_path": {
                        "type": "string",
                        "description": "Override auto-detected USN Journal path",
                    },
                    "evtx_path": {
                        "type": "string",
                        "description": "Override auto-detected EVTX directory path",
                    },
                },
                "required": ["ioc", "artifacts_dir"],
            },
        )
    )

    # User Activity Investigation orchestrator
    tools.append(
        Tool(
            name="investigate_user_activity",
            description="Comprehensive user activity investigation. Correlates Browser History, ShellBags, LNK files, and RecentDocs to build a complete picture of user activity. Answers: What did the user browse? What files did they access? What folders did they navigate?",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Base directory containing forensic artifacts or user profile",
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Optional keyword to search across all sources (URLs, filenames, paths)",
                    },
                    "username": {
                        "type": "string",
                        "description": "Optional username to narrow artifact search in multi-user images",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter events after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter events before this time",
                    },
                    "suspicious_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "For ShellBags, only return suspicious folder access (temp, AppData, network shares)",
                    },
                    "browser_path": {
                        "type": "string",
                        "description": "Override auto-detected browser History path",
                    },
                    "lnk_path": {
                        "type": "string",
                        "description": "Override auto-detected Recent LNK folder path",
                    },
                    "usrclass_path": {
                        "type": "string",
                        "description": "Override auto-detected UsrClass.dat path",
                    },
                    "ntuser_path": {
                        "type": "string",
                        "description": "Override auto-detected NTUSER.DAT path",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum results per source",
                    },
                },
                "required": ["artifacts_dir"],
            },
        )
    )

    # CSV Ingestor tool (for Eric Zimmerman tool outputs)
    tools.append(
        Tool(
            name="ingest_parsed_csv",
            description="Import pre-parsed CSV from Eric Zimmerman tools (MFTECmd, PECmd, AmcacheParser, SrumECmd) for querying. Auto-detects CSV type by column headers. Useful when you already have parsed output from EZ tools.",
            inputSchema={
                "type": "object",
                "properties": {
                    "csv_path": {
                        "type": "string",
                        "description": "Path to the CSV file",
                    },
                    "csv_type": {
                        "type": "string",
                        "enum": ["auto", "mftecmd", "pecmd", "amcache", "srumemd"],
                        "default": "auto",
                        "description": "Type of CSV (auto-detected if not specified)",
                    },
                    "filter_field": {
                        "type": "string",
                        "description": "Field name to filter on (e.g., 'filename', 'sha1', 'executable')",
                    },
                    "filter_value": {
                        "type": "string",
                        "description": "Value to filter for (case-insensitive substring match)",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter entries after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter entries before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum number of entries to return",
                    },
                },
                "required": ["csv_path"],
            },
        )
    )

    # MFT parsing tool (if mft library available)
    if MFT_AVAILABLE:
        tools.append(
            Tool(
                name="disk_parse_mft",
                description="Parse $MFT (Master File Table) for file metadata and timestomping detection. Compares $STANDARD_INFORMATION and $FILE_NAME timestamps to identify manipulation. Answers: When was this file actually created? Has it been timestomped?",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "mft_path": {
                            "type": "string",
                            "description": "Path to $MFT file",
                        },
                        "file_path_filter": {
                            "type": "string",
                            "description": "Filter by file path (case-insensitive substring)",
                        },
                        "entry_number": {
                            "type": "integer",
                            "description": "Get specific MFT entry by number",
                        },
                        "detect_timestomping": {
                            "type": "boolean",
                            "default": True,
                            "description": "Flag files where $SI timestamps are earlier than $FN timestamps",
                        },
                        "output_mode": {
                            "type": "string",
                            "enum": ["full", "summary", "timestomping_only"],
                            "default": "summary",
                            "description": "Output mode: full (all data), summary (basic info), timestomping_only (only flagged files)",
                        },
                        "allocated_only": {
                            "type": "boolean",
                            "default": True,
                            "description": "Only return allocated (not deleted) entries",
                        },
                        "files_only": {
                            "type": "boolean",
                            "default": False,
                            "description": "Only return files (exclude directories)",
                        },
                        "time_range_start": {
                            "type": "string",
                            "description": "ISO format datetime - filter entries modified after this time",
                        },
                        "time_range_end": {
                            "type": "string",
                            "description": "ISO format datetime - filter entries modified before this time",
                        },
                        "limit": {
                            "type": "integer",
                            "default": MAX_MFT_RESULTS,
                            "description": "Maximum number of entries to return",
                        },
                    },
                    "required": ["mft_path"],
                },
            )
        )

    # USN Journal parsing tool (pure Python, always available)
    tools.append(
        Tool(
            name="disk_parse_usn_journal",
            description="Parse $UsnJrnl:$J (USN Journal) for file system change history. Records file creation, deletion, modification, and rename operations. Answers: What files were created/deleted/renamed? When did file changes occur?",
            inputSchema={
                "type": "object",
                "properties": {
                    "usn_path": {
                        "type": "string",
                        "description": "Path to $J file (typically $Extend/$J)",
                    },
                    "filename_filter": {
                        "type": "string",
                        "description": "Filter by filename (case-insensitive substring)",
                    },
                    "reason_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by reason types (e.g., FILE_CREATE, FILE_DELETE, RENAME_NEW_NAME)",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter events after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter events before this time",
                    },
                    "interesting_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only return forensically interesting changes (create, delete, rename, modify)",
                    },
                    "files_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only return file events (exclude directories)",
                    },
                    "output_mode": {
                        "type": "string",
                        "enum": ["records", "summary", "deleted_files"],
                        "default": "records",
                        "description": "Output mode: records (individual changes), summary (statistics), deleted_files (only deletions)",
                    },
                    "extension_filter": {
                        "type": "string",
                        "description": "Filter by file extension (for deleted_files mode)",
                    },
                    "limit": {
                        "type": "integer",
                        "default": MAX_USN_RESULTS,
                        "description": "Maximum number of records to return",
                    },
                },
                "required": ["usn_path"],
            },
        )
    )

    # Browser history parsing (pure Python, always available)
    tools.append(
        Tool(
            name="browser_get_history",
            description="Parse browser history and downloads from Edge, Chrome, or Firefox. Answers: What URLs did the user visit? What files were downloaded? Where did downloads originate from?",
            inputSchema={
                "type": "object",
                "properties": {
                    "history_path": {
                        "type": "string",
                        "description": "Path to browser History SQLite file or profile directory",
                    },
                    "browser": {
                        "type": "string",
                        "enum": ["auto", "chrome", "edge", "firefox"],
                        "default": "auto",
                        "description": "Browser type (auto-detected if not specified)",
                    },
                    "include_downloads": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include download history",
                    },
                    "url_filter": {
                        "type": "string",
                        "description": "Filter by URL or title (case-insensitive substring)",
                    },
                    "dangerous_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only return downloads flagged as dangerous (Chrome/Edge only)",
                    },
                    "time_range_start": {
                        "type": "string",
                        "description": "ISO format datetime - filter visits after this time",
                    },
                    "time_range_end": {
                        "type": "string",
                        "description": "ISO format datetime - filter visits before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": MAX_EVTX_RESULTS,
                        "description": "Maximum number of results per category",
                    },
                },
                "required": ["history_path"],
            },
        )
    )

    # LNK file parsing (if pylnk3 available)
    if PYLNK_AVAILABLE:
        tools.append(
            Tool(
                name="user_parse_lnk_files",
                description="Parse Windows shortcut (.lnk) files to determine target paths, access times, and volume information. Answers: What files did the user access recently? What were the original file locations?",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to .lnk file, directory containing .lnk files, or user profile path",
                        },
                        "recursive": {
                            "type": "boolean",
                            "default": True,
                            "description": "Search recursively in subdirectories",
                        },
                        "target_filter": {
                            "type": "string",
                            "description": "Filter by target path (case-insensitive substring)",
                        },
                        "recent_only": {
                            "type": "boolean",
                            "default": False,
                            "description": "Only search the user's Recent folder (requires user profile path)",
                        },
                        "extension_filter": {
                            "type": "string",
                            "description": "Filter recent files by extension (e.g., '.exe', '.ps1')",
                        },
                        "limit": {
                            "type": "integer",
                            "default": MAX_PREFETCH_RESULTS,
                            "description": "Maximum number of results",
                        },
                    },
                    "required": ["path"],
                },
            )
        )

    # ShellBags parsing (uses python-registry, always available)
    tools.append(
        Tool(
            name="user_parse_shellbags",
            description="Parse ShellBags from UsrClass.dat to reveal folder navigation history. Shows which folders a user browsed in Windows Explorer with timestamps. Answers: Which folders did the user access? When did they browse suspicious paths?",
            inputSchema={
                "type": "object",
                "properties": {
                    "usrclass_path": {
                        "type": "string",
                        "description": "Path to UsrClass.dat (typically in Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat)",
                    },
                    "path_filter": {
                        "type": "string",
                        "description": "Filter results by path substring (case-insensitive)",
                    },
                    "suspicious_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only return suspicious folder accesses (temp, AppData, network shares, etc.)",
                    },
                    "limit": {
                        "type": "integer",
                        "default": MAX_REGISTRY_RESULTS,
                        "description": "Maximum number of results",
                    },
                },
                "required": ["usrclass_path"],
            },
        )
    )

    if WINRM_AVAILABLE:
        tools.extend([
            Tool(
                name="remote_collect_artifacts",
                description="Collect forensic artifacts from remote Windows system via WinRM. Supports password or pass-the-hash authentication.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Target hostname or IP address"},
                        "username": {"type": "string", "description": "Username (e.g., Administrator or DOMAIN\\user)"},
                        "password": {"type": "string", "description": "Password for authentication (use this OR ntlm_hash, not both)"},
                        "ntlm_hash": {"type": "string", "description": "NTLM hash for pass-the-hash (e.g., 'aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' or just NT hash)"},
                        "output_dir": {"type": "string", "description": "Local directory to save collected artifacts"},
                        "include_evtx": {"type": "boolean", "default": True, "description": "Collect Windows Event Logs"},
                        "include_registry": {"type": "boolean", "default": True, "description": "Collect registry hives (SAM, SYSTEM, SOFTWARE, etc.)"},
                    },
                    "required": ["host", "username", "output_dir"],
                },
            ),
            Tool(
                name="remote_get_system_info",
                description="Get system info from remote Windows via WinRM. Supports password or pass-the-hash authentication.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Target hostname or IP address"},
                        "username": {"type": "string", "description": "Username (e.g., Administrator or DOMAIN\\user)"},
                        "password": {"type": "string", "description": "Password for authentication (use this OR ntlm_hash, not both)"},
                        "ntlm_hash": {"type": "string", "description": "NTLM hash for pass-the-hash (e.g., 'aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' or just NT hash)"},
                    },
                    "required": ["host", "username"],
                },
            ),
        ])
    
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls"""
    try:
        result = await _execute_tool(name, arguments)
        return [TextContent(type="text", text=result)]
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def _execute_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a tool and return result"""
    
    if name == "evtx_list_files":
        result = list_evtx_files(args["directory"], recursive=args.get("recursive", True))
        return json_response(result)
    
    elif name == "evtx_get_stats":
        result = get_evtx_stats(args["evtx_path"])
        return json_response(result)
    
    elif name == "evtx_search":
        start_time = end_time = None
        if args.get("start_time"):
            start_time = datetime.fromisoformat(args["start_time"].replace("Z", "+00:00"))
        if args.get("end_time"):
            end_time = datetime.fromisoformat(args["end_time"].replace("Z", "+00:00"))

        result = get_evtx_events(
            args["evtx_path"],
            start_time=start_time,
            end_time=end_time,
            event_ids=args.get("event_ids"),
            contains=args.get("contains"),
            not_contains=args.get("not_contains"),
            provider=args.get("provider"),
            limit=args.get("limit", MAX_EVTX_RESULTS),
            offset=args.get("offset", 0),
        )
        return json_response(result)

    elif name == "evtx_security_search":
        result = search_security_events(
            args["evtx_path"],
            args["event_type"],
            limit=args.get("limit", MAX_EVTX_RESULTS),
            offset=args.get("offset", 0),
        )
        return json_response(result)
    
    elif name == "evtx_explain_event_id":
        desc = get_event_id_description(args["event_id"], args.get("channel", "Security"))
        return json_response({"event_id": args["event_id"], "description": desc})
    
    elif name == "registry_get_key":
        result = get_registry_key(args["hive_path"], args["key_path"], max_depth=args.get("max_depth", 3))
        return json_response(result)
    
    elif name == "registry_search":
        result = search_registry_values(
            args["hive_path"], args["pattern"],
            search_names=args.get("search_names", True),
            search_data=args.get("search_data", True),
            limit=args.get("limit", MAX_REGISTRY_RESULTS),
        )
        return json_response(result)
    
    elif name == "registry_get_persistence":
        result = {"run_keys": [], "services": []}
        if args.get("software_hive"):
            try:
                result["run_keys"].extend(get_run_keys(args["software_hive"]))
            except Exception as e:
                result["software_error"] = str(e)
        if args.get("ntuser_hive"):
            try:
                result["run_keys"].extend(get_run_keys(args["ntuser_hive"]))
            except Exception as e:
                result["ntuser_error"] = str(e)
        if args.get("system_hive"):
            try:
                result["services"] = get_services(args["system_hive"], args.get("include_microsoft_services", False))
            except Exception as e:
                result["system_error"] = str(e)
        return json_response(result)
    
    elif name == "registry_get_users":
        result = get_user_accounts(args["sam_path"])
        return json_response(result)
    
    elif name == "registry_get_usb_history":
        result = get_usb_devices(args["system_hive"])
        return json_response(result)
    
    elif name == "registry_get_system_info":
        result = get_system_info(args["software_hive"], args["system_hive"])
        return json_response(result)
    
    elif name == "registry_get_network":
        result = get_network_interfaces(args["system_hive"])
        return json_response(result)
    
    elif name == "forensics_list_important_events":
        events = IMPORTANT_EVENT_IDS.get(args["channel"], {})
        result = [{"event_id": eid, "description": desc} for eid, desc in sorted(events.items())]
        return json_response(result)
    
    elif name == "forensics_list_registry_keys":
        category = args.get("category")
        result = {category: FORENSIC_REGISTRY_KEYS.get(category, [])} if category else FORENSIC_REGISTRY_KEYS
        return json_response(result)

    elif name == "file_analyze_pe":
        if not PEFILE_AVAILABLE:
            return json_response({"error": "pefile library not installed. Install with: pip install pefile"})
        result = analyze_pe(
            args["file_path"],
            calculate_hashes=args.get("calculate_hashes", True),
            extract_strings_flag=args.get("extract_strings", False),
            check_signatures=args.get("check_signatures", True),
            detail_level=args.get("detail_level", "standard"),
        )
        return json_response(result)

    elif name == "yara_scan_file":
        if not YARA_AVAILABLE:
            return json_response({"error": "yara-python library not installed. Install with: pip install yara-python"})
        result = yara_scan_file(
            file_path=args["file_path"],
            rule_paths=args.get("rule_paths"),
            timeout=args.get("timeout", 60),
        )
        return json_response(result)

    elif name == "yara_scan_directory":
        if not YARA_AVAILABLE:
            return json_response({"error": "yara-python library not installed. Install with: pip install yara-python"})
        result = yara_scan_directory(
            directory=args["directory"],
            rule_paths=args.get("rule_paths"),
            file_pattern=args.get("file_pattern", "*"),
            recursive=args.get("recursive", True),
            limit=args.get("limit", 100),
        )
        return json_response(result)

    elif name == "yara_list_rules":
        if not YARA_AVAILABLE:
            return json_response({"error": "yara-python library not installed. Install with: pip install yara-python"})
        result = yara_list_rules(
            rule_paths=args.get("rule_paths"),
        )
        return json_response(result)

    elif name == "vt_lookup_hash":
        if not VT_AVAILABLE:
            return json_response({"error": "vt-py library not installed. Install with: pip install vt-py"})
        try:
            result = await asyncio.to_thread(vt_lookup_hash, args["file_hash"])
            return json_response(result)
        except ValueError as e:
            return json_response({"error": str(e)})
        except RuntimeError as e:
            return json_response({"error": str(e)})

    elif name == "vt_lookup_ip":
        if not VT_AVAILABLE:
            return json_response({"error": "vt-py library not installed. Install with: pip install vt-py"})
        try:
            result = await asyncio.to_thread(vt_lookup_ip, args["ip_address"])
            return json_response(result)
        except ValueError as e:
            return json_response({"error": str(e)})
        except RuntimeError as e:
            return json_response({"error": str(e)})

    elif name == "vt_lookup_domain":
        if not VT_AVAILABLE:
            return json_response({"error": "vt-py library not installed. Install with: pip install vt-py"})
        try:
            result = await asyncio.to_thread(vt_lookup_domain, args["domain"])
            return json_response(result)
        except ValueError as e:
            return json_response({"error": str(e)})
        except RuntimeError as e:
            return json_response({"error": str(e)})

    elif name == "vt_lookup_file":
        if not VT_AVAILABLE:
            return json_response({"error": "vt-py library not installed. Install with: pip install vt-py"})
        try:
            result = await asyncio.to_thread(vt_lookup_file, args["file_path"])
            return json_response(result)
        except ValueError as e:
            return json_response({"error": str(e)})
        except RuntimeError as e:
            return json_response({"error": str(e)})
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    # PCAP parsing tools
    elif name == "pcap_get_stats":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = get_pcap_stats(
                pcap_path=args["pcap_path"],
                max_packets=args.get("max_packets", 100000),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    elif name == "pcap_get_conversations":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = pcap_get_conversations(
                pcap_path=args["pcap_path"],
                protocol=args.get("protocol", "all"),
                limit=args.get("limit", 50),
                min_packets=args.get("min_packets", 1),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    elif name == "pcap_get_dns":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = pcap_get_dns_queries(
                pcap_path=args["pcap_path"],
                limit=args.get("limit", 100),
                query_filter=args.get("query_filter"),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    elif name == "pcap_get_http":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = pcap_get_http_requests(
                pcap_path=args["pcap_path"],
                limit=args.get("limit", 100),
                url_filter=args.get("url_filter"),
                method_filter=args.get("method_filter"),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    elif name == "pcap_search":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = search_pcap(
                pcap_path=args["pcap_path"],
                pattern=args["pattern"],
                regex=args.get("regex", False),
                limit=args.get("limit", 50),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    elif name == "pcap_find_suspicious":
        if not SCAPY_AVAILABLE:
            return json_response({"error": "scapy library not installed. Install with: pip install scapy"})
        try:
            result = pcap_find_suspicious(
                pcap_path=args["pcap_path"],
                limit=args.get("limit", 50),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})

    # DiE (Detect It Easy) tools
    elif name == "die_analyze_file":
        if not DIE_AVAILABLE:
            return json_response({
                "error": "diec (Detect It Easy CLI) not found. Install from: "
                        "https://github.com/horsicq/DIE-engine/releases"
            })
        try:
            result = die_analyze_file(
                file_path=args["file_path"],
                deep_scan=args.get("deep_scan", False),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"DiE analysis failed: {e}"})

    elif name == "die_scan_directory":
        if not DIE_AVAILABLE:
            return json_response({
                "error": "diec (Detect It Easy CLI) not found. Install from: "
                        "https://github.com/horsicq/DIE-engine/releases"
            })
        try:
            result = die_scan_directory(
                dir_path=args["dir_path"],
                recursive=args.get("recursive", True),
                deep_scan=args.get("deep_scan", False),
                limit=args.get("limit", 100),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except ValueError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"DiE scan failed: {e}"})

    elif name == "die_get_packer_info":
        # This doesn't require diec to be installed
        result = die_get_packer_info(args["packer_name"])
        return json_response(result)

    elif name == "api_analyze_imports":
        db_path = Path(__file__).parent / "data" / "api_definitions.db"
        enrich = args.get("enrich_from_db", False)
        try:
            result = analyze_pe_imports_detailed(
                file_path=args["file_path"],
                db_path=str(db_path) if enrich and db_path.exists() else None,
            )
            if not args.get("detect_patterns", True) and "patterns" in result:
                del result["patterns"]
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"Import analysis failed: {e}"})

    elif name == "api_lookup":
        db_path = Path(__file__).parent / "data" / "api_definitions.db"
        if not db_path.exists():
            return json_response({
                "error": f"API database not found at {db_path}. "
                        "Build it first by providing XML dir path to build_api_database()."
            })
        try:
            result = lookup_api(
                db_path=str(db_path),
                api_name=args["api_name"],
                include_params=args.get("include_params", True),
            )
            return json_response(result)
        except Exception as e:
            return json_response({"error": f"API lookup failed: {e}"})

    elif name == "api_search_category":
        db_path = Path(__file__).parent / "data" / "api_definitions.db"
        if not db_path.exists():
            return json_response({
                "error": f"API database not found at {db_path}. "
                        "Build it first by providing XML dir path to build_api_database()."
            })
        try:
            result = search_api_by_category(
                db_path=str(db_path),
                category=args["category"],
                limit=args.get("limit", 50),
            )
            return json_response(result)
        except Exception as e:
            return json_response({"error": f"Category search failed: {e}"})

    elif name == "api_detect_patterns":
        try:
            result = analyze_pe_imports_detailed(file_path=args["file_path"])
            # Return only the patterns portion
            if "patterns" in result:
                return json_response(result["patterns"])
            elif "error" in result:
                return json_response(result)
            return json_response({"patterns_detected": 0, "risk_level": "none", "details": []})
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"Pattern detection failed: {e}"})

    elif name == "apmx_parse":
        try:
            result = parse_apmx(file_path=args["file_path"])
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX parse failed: {e}"})

    elif name == "apmx_get_calls":
        try:
            result = get_apmx_calls(
                file_path=args["file_path"],
                process_index=args.get("process_index", 0),
                api_filter=args.get("api_filter"),
                limit=args.get("limit", 500),
                offset=args.get("offset", 0),
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX call extraction failed: {e}"})

    elif name == "apmx_detect_patterns":
        try:
            result = detect_apmx_patterns(
                file_path=args["file_path"],
                process_index=args.get("process_index", 0),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX pattern detection failed: {e}"})

    elif name == "apmx_get_call_details":
        try:
            result = get_apmx_call_details(
                file_path=args["file_path"],
                process_index=args.get("process_index", 0),
                call_indices=args.get("call_indices"),
                api_filter=args.get("api_filter"),
                limit=args.get("limit", 50),
                offset=args.get("offset", 0),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX call details failed: {e}"})

    elif name == "apmx_correlate_handles":
        try:
            result = correlate_apmx_handles(
                file_path=args["file_path"],
                process_index=args.get("process_index", 0),
                target_apis=args.get("target_apis"),
                limit=args.get("limit", 100),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX handle correlation failed: {e}"})

    elif name == "apmx_injection_info":
        try:
            result = get_apmx_injection_info(
                file_path=args["file_path"],
                process_index=args.get("process_index", 0),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX injection info failed: {e}"})

    elif name == "apmx_calls_around":
        try:
            result = get_apmx_calls_around(
                file_path=args["file_path"],
                call_index=args["call_index"],
                before=args.get("before", 10),
                after=args.get("after", 10),
                process_index=args.get("process_index", 0),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX calls around failed: {e}"})

    elif name == "apmx_search_params":
        try:
            value = args["value"]
            # Try to convert to int if it looks numeric
            if isinstance(value, str):
                try:
                    if value.startswith("0x"):
                        value = int(value, 16)
                    elif value.isdigit():
                        value = int(value)
                except (ValueError, OverflowError):
                    pass
            result = search_apmx_params(
                file_path=args["file_path"],
                value=value,
                process_index=args.get("process_index", 0),
                limit=args.get("limit", 50),
            )
            return json_response(result)
        except FileNotFoundError as e:
            return json_response({"error": str(e)})
        except Exception as e:
            return json_response({"error": f"APMX param search failed: {e}"})

    elif name == "disk_parse_prefetch":
        if not PYSCCA_AVAILABLE:
            return json_response({"error": "libscca-python library not installed. Install with: pip install libscca-python"})

        path = Path(args["path"])
        include_loaded = args.get("include_loaded_files", False)

        if path.is_file():
            # Parse single prefetch file
            result = parse_prefetch_file(
                path,
                include_loaded_files=include_loaded,
            )
        elif path.is_dir():
            # Parse directory of prefetch files
            result = parse_prefetch_directory(
                path,
                executable_filter=args.get("executable_filter"),
                include_loaded_files=include_loaded,
                limit=args.get("limit", MAX_PREFETCH_RESULTS),
                offset=args.get("offset", 0),
            )
        else:
            return json_response({"error": f"Path not found: {path}"})

        return json_response(result)

    elif name == "disk_parse_amcache":
        result = parse_amcache(
            args["amcache_path"],
            sha1_filter=args.get("sha1_filter"),
            path_filter=args.get("path_filter"),
            name_filter=args.get("name_filter"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            limit=args.get("limit", MAX_AMCACHE_RESULTS),
        )
        return json_response(result)

    elif name == "disk_parse_srum":
        if not PYESEDB_AVAILABLE:
            return json_response({"error": "libesedb-python library not installed. Install with: pip install libesedb-python"})
        result = parse_srum(
            args["srum_path"],
            table=args.get("table", "app_resource_usage"),
            app_filter=args.get("app_filter"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            limit=args.get("limit", MAX_AMCACHE_RESULTS),
        )
        return json_response(result)

    elif name == "investigate_execution":
        result = investigate_execution(
            target=args["target"],
            artifacts_dir=args["artifacts_dir"],
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            prefetch_path=args.get("prefetch_path"),
            amcache_path=args.get("amcache_path"),
            srum_path=args.get("srum_path"),
        )
        return json_response(result)

    elif name == "build_timeline":
        result = build_timeline(
            artifacts_dir=args["artifacts_dir"],
            sources=args.get("sources"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            keyword_filter=args.get("keyword_filter"),
            limit=args.get("limit", MAX_TIMELINE_RESULTS),
            mft_path=args.get("mft_path"),
            usn_path=args.get("usn_path"),
            prefetch_path=args.get("prefetch_path"),
            amcache_path=args.get("amcache_path"),
            evtx_path=args.get("evtx_path"),
        )
        return json_response(result)

    elif name == "hunt_ioc":
        result = hunt_ioc(
            ioc=args["ioc"],
            artifacts_dir=args["artifacts_dir"],
            ioc_type=args.get("ioc_type", "auto"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            yara_scan=args.get("yara_scan", False),
            prefetch_path=args.get("prefetch_path"),
            amcache_path=args.get("amcache_path"),
            srum_path=args.get("srum_path"),
            mft_path=args.get("mft_path"),
            usn_path=args.get("usn_path"),
            evtx_path=args.get("evtx_path"),
        )
        return json_response(result)

    elif name == "investigate_user_activity":
        result = investigate_user_activity(
            artifacts_dir=args["artifacts_dir"],
            keyword=args.get("keyword"),
            username=args.get("username"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            suspicious_only=args.get("suspicious_only", False),
            browser_path=args.get("browser_path"),
            lnk_path=args.get("lnk_path"),
            usrclass_path=args.get("usrclass_path"),
            ntuser_path=args.get("ntuser_path"),
            limit=args.get("limit", 50),
        )
        return json_response(result)

    elif name == "ingest_parsed_csv":
        result = ingest_csv(
            csv_path=args["csv_path"],
            csv_type=args.get("csv_type", "auto"),
            filter_field=args.get("filter_field"),
            filter_value=args.get("filter_value"),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            limit=args.get("limit", 100),
        )
        return json_response(result)

    elif name == "disk_parse_mft":
        if not MFT_AVAILABLE:
            return json_response({"error": "mft library not installed. Install with: pip install mft"})
        result = parse_mft(
            mft_path=args["mft_path"],
            file_path_filter=args.get("file_path_filter"),
            entry_number=args.get("entry_number"),
            detect_timestomping=args.get("detect_timestomping", True),
            output_mode=args.get("output_mode", "summary"),
            allocated_only=args.get("allocated_only", True),
            files_only=args.get("files_only", False),
            time_range_start=args.get("time_range_start"),
            time_range_end=args.get("time_range_end"),
            limit=args.get("limit", MAX_MFT_RESULTS),
        )
        return json_response(result)

    elif name == "disk_parse_usn_journal":
        output_mode = args.get("output_mode", "records")

        if output_mode == "summary":
            result = get_file_operations_summary(
                usn_path=args["usn_path"],
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
            )
        elif output_mode == "deleted_files":
            result = find_deleted_files(
                usn_path=args["usn_path"],
                extension_filter=args.get("extension_filter"),
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
                limit=args.get("limit", MAX_USN_RESULTS),
            )
        else:
            result = parse_usn_journal(
                usn_path=args["usn_path"],
                filename_filter=args.get("filename_filter"),
                reason_filter=args.get("reason_filter"),
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
                interesting_only=args.get("interesting_only", False),
                files_only=args.get("files_only", False),
                limit=args.get("limit", MAX_USN_RESULTS),
            )
        return json_response(result)

    elif name == "browser_get_history":
        dangerous_only = args.get("dangerous_only", False)
        if dangerous_only:
            result = get_browser_downloads(
                history_path=args["history_path"],
                browser=args.get("browser", "auto"),
                dangerous_only=True,
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
                limit=args.get("limit", MAX_EVTX_RESULTS),
            )
        else:
            result = parse_browser_history(
                history_path=args["history_path"],
                browser=args.get("browser", "auto"),
                include_downloads=args.get("include_downloads", True),
                url_filter=args.get("url_filter"),
                time_range_start=args.get("time_range_start"),
                time_range_end=args.get("time_range_end"),
                limit=args.get("limit", MAX_EVTX_RESULTS),
            )
        return json_response(result)

    elif name == "user_parse_lnk_files":
        if not PYLNK_AVAILABLE:
            return json_response({"error": "pylnk3 library not installed. Install with: pip install pylnk3"})

        path = Path(args["path"])
        recent_only = args.get("recent_only", False)

        if path.is_file() and path.suffix.lower() == '.lnk':
            # Parse single LNK file
            result = parse_lnk_file(path)
        elif recent_only or (path.is_dir() and (path / "AppData").exists()):
            # Parse Recent folder from user profile
            result = get_recent_files(
                user_profile_path=path,
                extension_filter=args.get("extension_filter"),
                limit=args.get("limit", MAX_PREFETCH_RESULTS),
            )
        else:
            # Parse directory of LNK files
            result = parse_lnk_directory(
                directory=path,
                recursive=args.get("recursive", True),
                target_filter=args.get("target_filter"),
                limit=args.get("limit", MAX_PREFETCH_RESULTS),
            )
        return json_response(result)

    elif name == "user_parse_shellbags":
        usrclass_path = args["usrclass_path"]
        suspicious_only = args.get("suspicious_only", False)

        if suspicious_only:
            result = find_suspicious_folders(
                usrclass_path=usrclass_path,
                limit=args.get("limit", MAX_REGISTRY_RESULTS),
            )
        else:
            result = parse_shellbags(
                usrclass_path=usrclass_path,
                path_filter=args.get("path_filter"),
                include_timestamps=True,
                limit=args.get("limit", MAX_REGISTRY_RESULTS),
            )
        return json_response(result)

    elif name == "remote_collect_artifacts":
        if not WINRM_AVAILABLE:
            return json_response({"error": "pywinrm not installed"})
        password = args.get("password")
        ntlm_hash = args.get("ntlm_hash")
        if not password and not ntlm_hash:
            return json_response({"error": "Either password or ntlm_hash must be provided"})
        collector = WinRMCollector(
            host=args["host"],
            username=args["username"],
            password=password,
            ntlm_hash=ntlm_hash,
        )
        results = collect_triage_package(
            collector, Path(args["output_dir"]),
            include_evtx=args.get("include_evtx", True),
            include_registry=args.get("include_registry", True),
        )
        return json_response([{
            "artifact": r.artifact_name, "success": r.success,
            "local_path": str(r.local_path) if r.local_path else None,
            "size_bytes": r.size_bytes, "error": r.error,
        } for r in results])

    elif name == "remote_get_system_info":
        if not WINRM_AVAILABLE:
            return json_response({"error": "pywinrm not installed"})
        password = args.get("password")
        ntlm_hash = args.get("ntlm_hash")
        if not password and not ntlm_hash:
            return json_response({"error": "Either password or ntlm_hash must be provided"})
        collector = WinRMCollector(
            host=args["host"],
            username=args["username"],
            password=password,
            ntlm_hash=ntlm_hash,
        )
        return json_response(collector.get_system_info())
    
    return json_response({"error": f"Unknown tool: {name}"})


def main():
    """Main entry point"""
    import asyncio
    
    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    
    asyncio.run(run())


if __name__ == "__main__":
    main()
