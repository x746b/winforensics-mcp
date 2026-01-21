from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional, Sequence
from xml.etree import ElementTree as ET

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

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
        if key.startswith("@"):  # Skip attributes marker
            continue
        new_key = f"{prefix}{key}" if prefix else key
        if isinstance(value, dict):
            # Check if it's a simple value dict with just #text
            if "#text" in value and len([k for k in value.keys() if not k.startswith("@")]) == 1:
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
    
    Args:
        evtx_path: Path to the .evtx file
        start_time: Only return events after this time
        end_time: Only return events before this time
        event_ids: Only return events with these Event IDs
        contains: Only return events containing ALL of these strings (case-insensitive)
        not_contains: Exclude events containing ANY of these strings
        provider: Only return events from this provider
        max_scan: Maximum number of events to scan
        
    Yields:
        Parsed event dictionaries
    """
    check_evtx_available()
    
    evtx_path = Path(evtx_path)
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX file not found: {evtx_path}")
    
    # Normalize filters
    event_ids_set = set(event_ids) if event_ids else None
    contains_lower = [s.lower() for s in contains] if contains else None
    not_contains_lower = [s.lower() for s in not_contains] if not_contains else None
    
    scanned = 0
    
    with Evtx(str(evtx_path)) as evtx:
        for xml_str, record in evtx_file_xml_view(evtx.get_file_header()):
            scanned += 1
            if scanned > max_scan:
                break
            
            try:
                # Parse XML
                root = ET.fromstring(xml_str)
                event_dict = xml_to_dict(root)
                event_data = extract_event_data(event_dict)
                
                # Apply filters
                
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
                
                # Content filters
                xml_lower = xml_str.lower()
                
                if contains_lower:
                    if not all(term in xml_lower for term in contains_lower):
                        continue
                
                if not_contains_lower:
                    if any(term in xml_lower for term in not_contains_lower):
                        continue
                
                # Add raw XML for reference
                event_data["_raw_xml"] = xml_str
                
                yield event_data
                
            except ET.ParseError:
                # Skip malformed events
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
        fields: Only include these fields in output (for smaller responses)

    Returns:
        Dict with events list and metadata (total_matched, returned, truncated)
    """
    results = []
    total_matched = 0
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
        "truncated": truncated,
        "limit": limit,
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
    
    return get_evtx_events(evtx_path, event_ids=event_ids, limit=limit)


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
