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
)

from .collectors import (
    WinRMCollector,
    collect_triage_package,
    WINRM_AVAILABLE,
)

from .config import IMPORTANT_EVENT_IDS, FORENSIC_REGISTRY_KEYS

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
                    "limit": {"type": "integer", "default": 100},
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
                    "limit": {"type": "integer", "default": 100},
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
                    "limit": {"type": "integer", "default": 100},
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
            limit=args.get("limit", 100),
        )
        return json_response(result)
    
    elif name == "evtx_security_search":
        result = search_security_events(args["evtx_path"], args["event_type"], limit=args.get("limit", 100))
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
            limit=args.get("limit", 100),
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
