from __future__ import annotations

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
)

from .orchestrators import investigate_execution, build_timeline, hunt_ioc

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
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("winforensics-mcp")

server = Server("winforensics-mcp")


def json_response(data: Any) -> str:
    """Convert data to JSON string for response"""
    return json.dumps(data, indent=2, default=str)


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
            description="Search events from EVTX file. Filter by time, Event ID, keywords, provider.",
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
                    "limit": {"type": "integer", "default": MAX_EVTX_RESULTS},
                },
                "required": ["evtx_path"],
            },
        ),
        Tool(
            name="evtx_security_search",
            description="Search for security events by type: logon, failed_logon, process_creation, etc.",
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
                    "limit": {"type": "integer", "default": MAX_EVTX_RESULTS},
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

    # Prefetch parsing tools (if libscca available)
    if PYSCCA_AVAILABLE:
        tools.append(
            Tool(
                name="disk_parse_prefetch",
                description="Parse Windows Prefetch files to determine program execution history, run counts, and last execution times. Can parse a single .pf file or an entire Prefetch directory.",
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
                            "description": "Include list of files/DLLs loaded by the executable",
                        },
                        "limit": {
                            "type": "integer",
                            "default": MAX_PREFETCH_RESULTS,
                            "description": "Maximum number of prefetch entries to return (for directory parsing)",
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
            description="Hunt for IOC (hash, filename, IP, domain) across all forensic artifacts. Searches Prefetch, Amcache, SRUM, MFT, USN Journal, Browser History, and EVTX logs. Answers: Where does this IOC appear? Was this file/hash/domain seen on the system?",
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
        )
        return json_response(result)

    elif name == "evtx_security_search":
        result = search_security_events(args["evtx_path"], args["event_type"], limit=args.get("limit", MAX_EVTX_RESULTS))
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
            prefetch_path=args.get("prefetch_path"),
            amcache_path=args.get("amcache_path"),
            srum_path=args.get("srum_path"),
            mft_path=args.get("mft_path"),
            usn_path=args.get("usn_path"),
            evtx_path=args.get("evtx_path"),
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
