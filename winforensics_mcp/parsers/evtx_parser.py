from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional, Sequence

# Rust-backed EVTX parser (preferred — 200x faster)
try:
    import evtx as _evtx_rust
    EVTX_RUST_AVAILABLE = True
except ImportError:
    EVTX_RUST_AVAILABLE = False

# Pure-Python fallback
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    from xml.etree import ElementTree as ET
    EVTX_PYTHON_AVAILABLE = True
except ImportError:
    EVTX_PYTHON_AVAILABLE = False

EVTX_AVAILABLE = EVTX_RUST_AVAILABLE or EVTX_PYTHON_AVAILABLE

from ..config import (
    MAX_EVTX_RESULTS,
    MAX_SCAN_EVENTS,
    IMPORTANT_EVENT_IDS,
)


def check_evtx_available() -> None:
    """Raise error if evtx library not available"""
    if not EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx library not installed. Install with: pip install evtx"
        )


def parse_evtx_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse Windows Event Log timestamp to datetime"""
    if not timestamp_str:
        return None

    # Handle various timestamp formats
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
    ]

    # Clean up the timestamp
    timestamp_str = timestamp_str.strip()
    # Rust evtx record-level timestamps have " UTC" suffix
    if timestamp_str.endswith(" UTC"):
        timestamp_str = timestamp_str[:-4]
    # Python %f only handles 6 digits — truncate excess (e.g., 7-digit .2523953Z)
    m = re.search(r"(\.\d{7,})", timestamp_str)
    if m:
        timestamp_str = timestamp_str[:m.start()] + m.group()[:7] + timestamp_str[m.end():]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    
    return None


def xml_to_dict(element: ET.Element, strip_ns: bool = True) -> dict[str, Any]:
    """Convert XML element to dictionary"""
    result: dict[str, Any] = {}

    # Handle tag name (strip namespace if requested)
    tag = element.tag
    if strip_ns and "}" in tag:
        tag = tag.split("}", 1)[1]

    # Handle attributes
    if element.attrib:
        result["@attributes"] = dict(element.attrib)

    # Handle text content
    if element.text and element.text.strip():
        text_content = element.text.strip()
        if len(element) == 0:  # No children
            # If no attributes, return just the text
            # If has attributes, return dict with both
            if not element.attrib:
                return text_content
            else:
                result["#text"] = text_content
                return result
        result["#text"] = text_content

    # Handle children
    for child in element:
        child_tag = child.tag
        if strip_ns and "}" in child_tag:
            child_tag = child_tag.split("}", 1)[1]

        child_data = xml_to_dict(child, strip_ns)

        if child_tag in result:
            # Convert to list if multiple children with same tag
            if not isinstance(result[child_tag], list):
                result[child_tag] = [result[child_tag]]
            result[child_tag].append(child_data)
        else:
            result[child_tag] = child_data

    return result


def extract_event_data(event_dict: dict) -> dict[str, Any]:
    """Extract and flatten event data for easier querying"""
    result = {
        "EventID": None,
        "TimeCreated": None,
        "Computer": None,
        "Channel": None,
        "Provider": None,
        "EventData": {},
        "UserData": {},
    }

    # Navigate the event structure
    event = event_dict.get("Event", event_dict)
    system = event.get("System", {})

    # Extract system fields
    event_id = system.get("EventID", {})
    if isinstance(event_id, dict):
        result["EventID"] = event_id.get("#text") or event_id.get("@attributes", {}).get("Qualifiers")
    else:
        result["EventID"] = event_id

    # Try to convert EventID to int
    if result["EventID"]:
        try:
            result["EventID"] = int(result["EventID"])
        except (ValueError, TypeError):
            pass

    # TimeCreated
    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        result["TimeCreated"] = time_created.get("@attributes", {}).get("SystemTime")
    else:
        result["TimeCreated"] = time_created

    # Other system fields
    result["Computer"] = system.get("Computer")
    result["Channel"] = system.get("Channel")

    provider = system.get("Provider", {})
    if isinstance(provider, dict):
        result["Provider"] = provider.get("@attributes", {}).get("Name")
    else:
        result["Provider"] = provider

    # Extract EventData - handles named Data elements like <Data Name="TargetUserName">value</Data>
    event_data = event.get("EventData", {})
    if isinstance(event_data, dict):
        data_items = event_data.get("Data", [])
        if not isinstance(data_items, list):
            data_items = [data_items]

        unnamed_index = 0
        for item in data_items:
            if isinstance(item, dict):
                # Named data element: <Data Name="foo">bar</Data>
                name = item.get("@attributes", {}).get("Name", "")
                value = item.get("#text", "")
                if name:
                    result["EventData"][name] = value
                elif value:
                    # Unnamed data element with value
                    result["EventData"][f"Data_{unnamed_index}"] = value
                    unnamed_index += 1
            elif isinstance(item, str):
                # Plain text data element: <Data>value</Data>
                if item.strip():
                    result["EventData"][f"Data_{unnamed_index}"] = item
                    unnamed_index += 1

    # Extract UserData (if present) - flatten nested structure
    user_data = event.get("UserData", {})
    if isinstance(user_data, dict):
        # Flatten UserData for easier access
        flattened = {}
        _flatten_dict(user_data, flattened, "")
        result["UserData"] = flattened if flattened else user_data

    return result


def _flatten_dict(d: dict, result: dict, prefix: str) -> None:
    """Flatten nested dictionary for easier querying"""
    for key, value in d.items():
        if key.startswith("@") or key.startswith("#"):  # Skip attributes marker
            continue
        new_key = f"{prefix}{key}" if prefix else key
        if isinstance(value, dict):
            # Check if it's a simple value dict with just #text
            if "#text" in value and len([k for k in value.keys() if not k.startswith("@") and not k.startswith("#")]) == 1:
                result[new_key] = value["#text"]
            else:
                _flatten_dict(value, result, f"{new_key}.")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    _flatten_dict(item, result, f"{new_key}[{i}].")
                else:
                    result[f"{new_key}[{i}]"] = item
        else:
            result[new_key] = value


def extract_event_data_json(event_dict: dict) -> dict[str, Any]:
    """Extract and flatten event data from Rust evtx JSON output.

    The Rust parser produces JSON with ``#attributes`` keys and flat
    EventData (no nested ``<Data Name="...">`` elements), so this is
    simpler and faster than the XML-based ``extract_event_data()``.
    """
    result: dict[str, Any] = {
        "EventID": None,
        "TimeCreated": None,
        "Computer": None,
        "Channel": None,
        "Provider": None,
        "EventData": {},
        "UserData": {},
    }

    event = event_dict.get("Event", event_dict)
    system = event.get("System", {})

    # EventID — Rust parser gives int directly
    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    if event_id is not None:
        try:
            result["EventID"] = int(event_id)
        except (ValueError, TypeError):
            result["EventID"] = event_id
    else:
        result["EventID"] = event_id

    # TimeCreated
    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        result["TimeCreated"] = (
            time_created.get("#attributes", {}).get("SystemTime")
            or time_created.get("@attributes", {}).get("SystemTime")
        )
    else:
        result["TimeCreated"] = time_created

    # Other system fields
    result["Computer"] = system.get("Computer")
    result["Channel"] = system.get("Channel")

    provider = system.get("Provider", {})
    if isinstance(provider, dict):
        result["Provider"] = (
            provider.get("#attributes", {}).get("Name")
            or provider.get("@attributes", {}).get("Name")
        )
    else:
        result["Provider"] = provider

    # EventData — Rust JSON already has flat key-value pairs
    event_data = event.get("EventData", {})
    if isinstance(event_data, dict):
        for k, v in event_data.items():
            if k.startswith("#") or k.startswith("@"):
                continue
            if v is None:
                v = ""
            result["EventData"][k] = str(v) if not isinstance(v, str) else v

    # UserData
    user_data = event.get("UserData", {})
    if isinstance(user_data, dict):
        flattened: dict[str, Any] = {}
        _flatten_dict(user_data, flattened, "")
        result["UserData"] = flattened if flattened else user_data

    return result


def iter_evtx_events(
    evtx_path: str | Path,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_ids: Optional[Sequence[int]] = None,
    contains: Optional[Sequence[str]] = None,
    not_contains: Optional[Sequence[str]] = None,
    provider: Optional[str] = None,
    max_scan: int = MAX_SCAN_EVENTS,
) -> Generator[dict[str, Any], None, None]:
    """
    Iterate over events in an EVTX file with filtering.

    Uses the Rust-backed evtx library when available (200x+ faster).
    Falls back to python-evtx if the Rust library is not installed.
    """
    check_evtx_available()

    evtx_path = Path(evtx_path)
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX file not found: {evtx_path}")

    if EVTX_RUST_AVAILABLE:
        yield from _iter_evtx_rust(
            evtx_path, start_time, end_time, event_ids,
            contains, not_contains, provider, max_scan,
        )
    else:
        yield from _iter_evtx_python(
            evtx_path, start_time, end_time, event_ids,
            contains, not_contains, provider, max_scan,
        )


def _iter_evtx_rust(
    evtx_path: Path,
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    event_ids: Optional[Sequence[int]],
    contains: Optional[Sequence[str]],
    not_contains: Optional[Sequence[str]],
    provider: Optional[str],
    max_scan: int,
) -> Generator[dict[str, Any], None, None]:
    """Fast path using Rust evtx library with JSON output."""

    event_ids_set = set(event_ids) if event_ids else None

    # Pre-compile case-insensitive regex for contains/not_contains
    contains_pat = None
    if contains:
        # All terms must match — we check each individually
        contains_pat = [re.compile(re.escape(t), re.IGNORECASE) for t in contains]
    not_contains_pat = None
    if not_contains:
        # Any term matching → exclude
        not_contains_pat = re.compile(
            "|".join(re.escape(t) for t in not_contains), re.IGNORECASE,
        )

    scanned = 0
    parser = _evtx_rust.PyEvtxParser(str(evtx_path))

    for record in parser.records_json():
        if isinstance(record, Exception):
            continue

        scanned += 1
        if scanned > max_scan:
            break

        data_str = record["data"]

        # --- Fast pre-filters on the raw JSON string (no parsing yet) ---

        # Event ID pre-filter: check for the number in the raw string
        # (avoids json.loads for non-matching events)
        if event_ids_set:
            # Quick string check before full parse
            if not any(f'"EventID":{eid}' in data_str or f'"EventID": {eid}' in data_str for eid in event_ids_set):
                continue

        # Contains filter on raw JSON string
        if contains_pat:
            if not all(p.search(data_str) for p in contains_pat):
                continue

        # Not-contains filter on raw JSON string
        if not_contains_pat:
            if not_contains_pat.search(data_str):
                continue

        # --- Parse JSON and extract structured data ---
        try:
            event_dict = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            continue

        event_data = extract_event_data_json(event_dict)

        # Precise Event ID filter (the string pre-filter may have false positives)
        if event_ids_set and event_data["EventID"] not in event_ids_set:
            continue

        # Provider filter
        if provider and event_data["Provider"] != provider:
            continue

        # Time filters
        if start_time or end_time:
            event_time = parse_evtx_timestamp(event_data["TimeCreated"])
            if event_time:
                if start_time and event_time < start_time:
                    continue
                if end_time and event_time > end_time:
                    continue

        # Store raw JSON for reference (smaller than XML)
        event_data["_raw_xml"] = data_str

        yield event_data


def _iter_evtx_python(
    evtx_path: Path,
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    event_ids: Optional[Sequence[int]],
    contains: Optional[Sequence[str]],
    not_contains: Optional[Sequence[str]],
    provider: Optional[str],
    max_scan: int,
) -> Generator[dict[str, Any], None, None]:
    """Fallback path using pure-Python python-evtx library."""

    event_ids_set = set(event_ids) if event_ids else None

    # Pre-compile regex for contains/not_contains
    contains_pat = None
    if contains:
        contains_pat = [re.compile(re.escape(t), re.IGNORECASE) for t in contains]
    not_contains_pat = None
    if not_contains:
        not_contains_pat = re.compile(
            "|".join(re.escape(t) for t in not_contains), re.IGNORECASE,
        )

    scanned = 0

    with Evtx(str(evtx_path)) as evtx:
        for xml_str, record in evtx_file_xml_view(evtx.get_file_header()):
            scanned += 1
            if scanned > max_scan:
                break

            try:
                # Content filters on raw string (before expensive XML parse)
                if contains_pat:
                    if not all(p.search(xml_str) for p in contains_pat):
                        continue

                if not_contains_pat:
                    if not_contains_pat.search(xml_str):
                        continue

                # Parse XML
                root = ET.fromstring(xml_str)
                event_dict = xml_to_dict(root)
                event_data = extract_event_data(event_dict)

                # Event ID filter
                if event_ids_set and event_data["EventID"] not in event_ids_set:
                    continue

                # Provider filter
                if provider and event_data["Provider"] != provider:
                    continue

                # Time filters
                if start_time or end_time:
                    event_time = parse_evtx_timestamp(event_data["TimeCreated"])
                    if event_time:
                        if start_time and event_time < start_time:
                            continue
                        if end_time and event_time > end_time:
                            continue

                # Add raw XML for reference
                event_data["_raw_xml"] = xml_str

                yield event_data

            except ET.ParseError:
                continue


def get_evtx_events(
    evtx_path: str | Path,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_ids: Optional[Sequence[int]] = None,
    contains: Optional[Sequence[str]] = None,
    not_contains: Optional[Sequence[str]] = None,
    provider: Optional[str] = None,
    limit: int = MAX_EVTX_RESULTS,
    offset: int = 0,
    fields: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    """
    Get events from an EVTX file with filtering.

    Args:
        evtx_path: Path to the .evtx file
        start_time: Only return events after this time
        end_time: Only return events before this time
        event_ids: Only return events with these Event IDs
        contains: Only return events containing ALL of these strings
        not_contains: Exclude events containing ANY of these strings
        provider: Only return events from this provider
        limit: Maximum number of results to return
        offset: Number of matching events to skip (for pagination)
        fields: Only include these fields in output (for smaller responses)

    Returns:
        Dict with events list and metadata (total_matched, returned, truncated)
    """
    results = []
    total_matched = 0
    skipped = 0
    truncated = False

    for event in iter_evtx_events(
        evtx_path,
        start_time=start_time,
        end_time=end_time,
        event_ids=event_ids,
        contains=contains,
        not_contains=not_contains,
        provider=provider,
    ):
        total_matched += 1

        # Skip events for pagination offset
        if skipped < offset:
            skipped += 1
            continue

        # Skip if we've hit the limit (but keep counting total)
        if len(results) >= limit:
            truncated = True
            continue

        # Field projection
        if fields:
            projected = {}
            for field in fields:
                if field in event:
                    projected[field] = event[field]
                elif "." in field:
                    # Handle nested fields like "EventData.TargetUserName"
                    parts = field.split(".")
                    value = event
                    for part in parts:
                        if isinstance(value, dict):
                            value = value.get(part)
                        else:
                            value = None
                            break
                    if value is not None:
                        projected[field] = value
            event = projected
        else:
            # Remove raw XML by default to save space
            event.pop("_raw_xml", None)

        results.append(event)

    return {
        "events": results,
        "total_matched": total_matched,
        "returned": len(results),
        "offset": offset,
        "truncated": truncated,
        "limit": limit,
        "next_offset": offset + len(results) if truncated else None,
    }


def list_evtx_files(
    directory: str | Path,
    recursive: bool = True,
) -> list[dict[str, Any]]:
    """
    List all EVTX files in a directory.
    
    Args:
        directory: Directory to search
        recursive: Search subdirectories
        
    Returns:
        List of file info dictionaries
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    
    pattern = "**/*.evtx" if recursive else "*.evtx"
    files = []
    
    for evtx_path in directory.glob(pattern):
        try:
            stat = evtx_path.stat()
            files.append({
                "path": str(evtx_path),
                "name": evtx_path.name,
                "size_bytes": stat.st_size,
                "size_human": _human_readable_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
        except OSError:
            continue
    
    return sorted(files, key=lambda x: x["name"])


def get_evtx_stats(evtx_path: str | Path) -> dict[str, Any]:
    """
    Get statistics about an EVTX file.
    
    Args:
        evtx_path: Path to the .evtx file
        
    Returns:
        Statistics dictionary
    """
    check_evtx_available()
    
    evtx_path = Path(evtx_path)
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX file not found: {evtx_path}")
    
    stats = {
        "path": str(evtx_path),
        "name": evtx_path.name,
        "size_bytes": evtx_path.stat().st_size,
        "total_events": 0,
        "event_id_counts": {},
        "time_range": {"earliest": None, "latest": None},
        "providers": set(),
    }
    
    earliest = None
    latest = None
    
    for event in iter_evtx_events(evtx_path, max_scan=MAX_SCAN_EVENTS):
        stats["total_events"] += 1
        
        # Count event IDs
        event_id = event.get("EventID")
        if event_id:
            stats["event_id_counts"][event_id] = stats["event_id_counts"].get(event_id, 0) + 1
        
        # Track providers
        provider = event.get("Provider")
        if provider:
            stats["providers"].add(provider)
        
        # Track time range
        time_created = parse_evtx_timestamp(event.get("TimeCreated", ""))
        if time_created:
            if earliest is None or time_created < earliest:
                earliest = time_created
            if latest is None or time_created > latest:
                latest = time_created
    
    # Convert sets to lists for JSON serialization
    stats["providers"] = sorted(stats["providers"])
    
    # Sort event ID counts by count descending
    stats["event_id_counts"] = dict(
        sorted(stats["event_id_counts"].items(), key=lambda x: x[1], reverse=True)
    )
    
    if earliest:
        stats["time_range"]["earliest"] = earliest.isoformat()
    if latest:
        stats["time_range"]["latest"] = latest.isoformat()
    
    return stats


def search_security_events(
    evtx_path: str | Path,
    event_type: str,
    limit: int = MAX_EVTX_RESULTS,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Search for specific security event types.

    Args:
        evtx_path: Path to Security.evtx file
        event_type: Type of events to search for:
            - "logon": Successful logons (4624)
            - "failed_logon": Failed logons (4625)
            - "logoff": Logoffs (4634)
            - "process_creation": Process creation (4688)
            - "service_installed": Service installations (4697, 7045)
            - "account_created": Account creation (4720)
            - "account_modified": Account modifications (4738)
            - "privilege_use": Special privilege use (4672)
            - "log_cleared": Audit log cleared (1102, 104)
            - "scheduled_task": Scheduled task events (4698-4702)
            - "kerberos": Kerberos events (4768-4771)
        limit: Maximum results
        offset: Number of matching events to skip (for pagination)

    Returns:
        Dict with events list and metadata (total_matched, returned, truncated)
    """
    event_type_map = {
        "logon": [4624],
        "failed_logon": [4625],
        "logoff": [4634],
        "process_creation": [4688],
        "service_installed": [4697, 7045],
        "account_created": [4720],
        "account_modified": [4738],
        "privilege_use": [4672],
        "log_cleared": [1102, 104],
        "scheduled_task": [4698, 4699, 4700, 4701, 4702],
        "kerberos": [4768, 4769, 4770, 4771],
        "lateral_movement": [4624, 4648, 4778, 4779],
        "credential_access": [4768, 4769, 4771, 4776],
    }

    event_ids = event_type_map.get(event_type.lower())
    if not event_ids:
        available = ", ".join(event_type_map.keys())
        raise ValueError(f"Unknown event type: {event_type}. Available: {available}")

    return get_evtx_events(evtx_path, event_ids=event_ids, limit=limit, offset=offset)


def evtx_attack_summary(
    evtx_path: str | Path,
    event_type: str = "process_creation",
    contains: Optional[Sequence[str]] = None,
    not_contains: Optional[Sequence[str]] = None,
    limit: int = 500,
) -> dict[str, Any]:
    """
    Return a compact, TSV-formatted summary of security events.

    Unlike evtx_security_search which returns full JSON per event, this returns
    one tab-separated line per event with only the attack-relevant columns.
    Designed for rapid triage — fits an entire attack chain in a single call.

    Supported event_type values and their columns:
        process_creation: Timestamp | User | ParentProcess | CommandLine
        logon:            Timestamp | User | SourceIP | LogonType
        account_created:  Timestamp | NewUser | CreatedBy
        scheduled_task:   Timestamp | TaskName | Action | EventID
        service_installed: Timestamp | ServiceName | ImagePath | ServiceType
    """
    # Map event types to Event IDs and field extractors
    type_config: dict[str, dict[str, Any]] = {
        "process_creation": {
            "event_ids": [4688],
            "header": "Timestamp\tUser\tParentProcess\tCommandLine",
            "fields": lambda ed: (
                ed.get("TargetUserName") or ed.get("SubjectUserName", "?"),
                _basename(ed.get("ParentProcessName", "?")),
                ed.get("CommandLine", "?"),
            ),
        },
        "logon": {
            "event_ids": [4624],
            "header": "Timestamp\tUser\tSourceIP\tLogonType",
            "fields": lambda ed: (
                ed.get("TargetUserName", "?"),
                ed.get("IpAddress", "?"),
                ed.get("LogonType", "?"),
            ),
        },
        "account_created": {
            "event_ids": [4720],
            "header": "Timestamp\tNewUser\tCreatedBy",
            "fields": lambda ed: (
                ed.get("TargetUserName", "?"),
                ed.get("SubjectUserName", "?"),
            ),
        },
        "scheduled_task": {
            "event_ids": [4698, 4699, 4700, 4701, 4702],
            "header": "Timestamp\tTaskName\tAction\tEventID",
            "fields": lambda ed: (
                ed.get("TaskName", "?"),
                ed.get("TaskContent", ed.get("Data_0", "?"))[:120],
            ),
            "include_event_id": True,
        },
        "service_installed": {
            "event_ids": [4697, 7045],
            "header": "Timestamp\tServiceName\tImagePath\tServiceType",
            "fields": lambda ed: (
                ed.get("ServiceName", "?"),
                ed.get("ImagePath", ed.get("ServiceFileName", "?")),
                ed.get("ServiceType", "?"),
            ),
        },
    }

    config = type_config.get(event_type.lower())
    if not config:
        available = ", ".join(type_config.keys())
        raise ValueError(f"Unknown event type: {event_type}. Available: {available}")

    lines = [config["header"]]
    total = 0

    for event in iter_evtx_events(
        evtx_path,
        event_ids=config["event_ids"],
        contains=contains,
        not_contains=not_contains,
    ):
        total += 1
        if total > limit:
            break

        ts = event.get("TimeCreated", "?")
        ed = event.get("EventData", {})
        cols = config["fields"](ed)

        if config.get("include_event_id"):
            cols = (*cols, str(event.get("EventID", "?")))

        lines.append(f"{ts}\t" + "\t".join(str(c) for c in cols))

    return {
        "format": "tsv",
        "event_type": event_type,
        "total_events": min(total, limit),
        "truncated": total > limit,
        "data": "\n".join(lines),
    }


def _basename(path: str) -> str:
    """Extract filename from a Windows path."""
    if not path or path == "?":
        return path
    return path.rsplit("\\", 1)[-1]


def get_event_id_description(event_id: int, channel: str = "Security") -> str:
    """Get human-readable description for an Event ID"""
    channel_events = IMPORTANT_EVENT_IDS.get(channel, {})
    return channel_events.get(event_id, f"Event ID {event_id}")


def _human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human readable string"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
