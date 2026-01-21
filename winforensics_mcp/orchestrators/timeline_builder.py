"""
Timeline Builder Orchestrator

Builds a comprehensive forensic timeline from multiple artifact sources:
- MFT (file create/modify/access timestamps)
- USN Journal (file operations history)
- Prefetch (program executions)
- Amcache (first seen timestamps)
- EVTX (Windows event logs)

Returns sorted, deduplicated timeline events.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Iterator
import hashlib

from .execution_tracker import find_artifact_paths, ARTIFACT_PATHS

# Extend artifact paths for timeline building
TIMELINE_ARTIFACT_PATHS = {
    **ARTIFACT_PATHS,
    "mft": [
        "$MFT",
        "C/$MFT",
        "MFT",
        "Windows/$MFT",
    ],
    "usn": [
        "$Extend/$J",
        "$Extend/$UsnJrnl/$J",
        "C/$Extend/$J",
        "C/$Extend/$UsnJrnl/$J",
        "$J",
        "UsnJrnl",
    ],
    "evtx": [
        "Windows/System32/winevt/Logs",
        "Windows/system32/winevt/logs",
        "C/Windows/System32/winevt/Logs",
        "winevt/Logs",
        "Logs",
    ],
}


def find_timeline_artifacts(
    artifacts_dir: str | Path,
) -> dict[str, Optional[Path]]:
    """
    Find all timeline-relevant artifacts within a directory structure.

    Args:
        artifacts_dir: Base directory containing forensic artifacts

    Returns:
        Dictionary mapping artifact type to found path (or None if not found)
    """
    artifacts_dir = Path(artifacts_dir)
    found = {
        "mft": None,
        "usn": None,
        "prefetch": None,
        "amcache": None,
        "evtx": None,
    }

    if not artifacts_dir.exists():
        return found

    # Search for each artifact type
    for artifact_type, patterns in TIMELINE_ARTIFACT_PATHS.items():
        if artifact_type not in found:
            continue
        for pattern in patterns:
            candidate = artifacts_dir / pattern
            if candidate.exists():
                found[artifact_type] = candidate
                break

    return found


def _parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    """Parse ISO datetime string to datetime object"""
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _normalize_timestamp(ts) -> Optional[str]:
    """Normalize various timestamp formats to ISO string"""
    if ts is None:
        return None
    if isinstance(ts, str):
        dt = _parse_iso_datetime(ts)
        return dt.isoformat() if dt else None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    return str(ts)


def _event_hash(event: dict) -> str:
    """Generate hash for deduplication"""
    key = f"{event.get('timestamp')}|{event.get('source')}|{event.get('event_type')}|{event.get('path', '')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def _iter_mft_events(
    mft_path: Path,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    keyword_filter: Optional[str],
    limit: int,
) -> Iterator[dict[str, Any]]:
    """Iterate MFT entries as timeline events"""
    from ..parsers.mft_parser import iter_mft_entries, MFT_AVAILABLE

    if not MFT_AVAILABLE:
        return

    filter_lower = keyword_filter.lower() if keyword_filter else None
    count = 0

    for entry in iter_mft_entries(mft_path, allocated_only=True, files_only=True):
        if count >= limit:
            break

        path = entry.get("path", "")
        if filter_lower and filter_lower not in path.lower():
            continue

        # Get timestamps
        si_ts = entry.get("timestamps", {}).get("si", {})

        # SI Modified timestamp (most commonly used)
        modified = si_ts.get("modified")
        if modified:
            modified_dt = _parse_iso_datetime(modified)
            if modified_dt:
                if time_range_start and modified_dt < time_range_start:
                    continue
                if time_range_end and modified_dt > time_range_end:
                    continue

                # Handle timestomping field which can be None
                timestomping = entry.get("timestomping")
                timestomping_detected = timestomping.get("detected", False) if timestomping else False

                count += 1
                yield {
                    "timestamp": modified,
                    "source": "MFT",
                    "event_type": "file_modified",
                    "description": f"File modified: {path}",
                    "path": path,
                    "details": {
                        "entry_id": entry.get("entry_id"),
                        "file_size": entry.get("file_size"),
                        "timestomping": timestomping_detected,
                    },
                }

        # SI Created timestamp
        created = si_ts.get("created")
        if created and created != modified:
            created_dt = _parse_iso_datetime(created)
            if created_dt:
                if time_range_start and created_dt < time_range_start:
                    continue
                if time_range_end and created_dt > time_range_end:
                    continue

                count += 1
                yield {
                    "timestamp": created,
                    "source": "MFT",
                    "event_type": "file_created",
                    "description": f"File created: {path}",
                    "path": path,
                    "details": {
                        "entry_id": entry.get("entry_id"),
                        "file_size": entry.get("file_size"),
                    },
                }


def _iter_usn_events(
    usn_path: Path,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    keyword_filter: Optional[str],
    limit: int,
) -> Iterator[dict[str, Any]]:
    """Iterate USN Journal entries as timeline events"""
    from ..parsers.usn_parser import iter_usn_records

    filter_lower = keyword_filter.lower() if keyword_filter else None
    count = 0

    # Focus on interesting operations
    interesting_reasons = {
        "FILE_CREATE",
        "FILE_DELETE",
        "RENAME_NEW_NAME",
        "DATA_OVERWRITE",
        "SECURITY_CHANGE",
    }

    for record in iter_usn_records(usn_path):
        if count >= limit:
            break

        reasons = record.get("reasons", [])

        # Only include interesting events
        if not any(r in interesting_reasons for r in reasons):
            continue

        filename = record.get("filename", "")
        if filter_lower and filter_lower not in filename.lower():
            continue

        timestamp = record.get("timestamp")
        if not timestamp:
            continue

        timestamp_dt = _parse_iso_datetime(timestamp)
        if timestamp_dt:
            if time_range_start and timestamp_dt < time_range_start:
                continue
            if time_range_end and timestamp_dt > time_range_end:
                continue

        # Determine event type based on reason flags
        event_type = "file_change"
        if "FILE_CREATE" in reasons:
            event_type = "file_created"
        elif "FILE_DELETE" in reasons:
            event_type = "file_deleted"
        elif "RENAME_NEW_NAME" in reasons:
            event_type = "file_renamed"
        elif "DATA_OVERWRITE" in reasons:
            event_type = "file_modified"

        count += 1
        yield {
            "timestamp": timestamp,
            "source": "USN",
            "event_type": event_type,
            "description": f"{event_type.replace('_', ' ').title()}: {filename}",
            "path": filename,
            "details": {
                "reasons": reasons,
                "mft_entry": record.get("mft_entry_number"),
                "parent_mft_entry": record.get("parent_mft_entry_number"),
            },
        }


def _iter_prefetch_events(
    prefetch_dir: Path,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    keyword_filter: Optional[str],
    limit: int,
) -> Iterator[dict[str, Any]]:
    """Iterate Prefetch entries as timeline events"""
    from ..parsers.prefetch_parser import parse_prefetch_directory, PYSCCA_AVAILABLE

    if not PYSCCA_AVAILABLE:
        return

    filter_lower = keyword_filter.lower() if keyword_filter else None
    count = 0

    result = parse_prefetch_directory(prefetch_dir, include_loaded_files=False)
    entries = result.get("prefetch_entries", [])

    for entry in entries:
        executable = entry.get("executable", "")
        if filter_lower and filter_lower not in executable.lower():
            continue

        # Each execution time becomes a timeline event
        run_times = entry.get("last_run_times", [])
        for run_time in run_times:
            if count >= limit:
                break

            run_dt = _parse_iso_datetime(run_time)
            if run_dt:
                if time_range_start and run_dt < time_range_start:
                    continue
                if time_range_end and run_dt > time_range_end:
                    continue

            count += 1
            yield {
                "timestamp": run_time,
                "source": "Prefetch",
                "event_type": "program_executed",
                "description": f"Program executed: {executable}",
                "path": executable,
                "details": {
                    "run_count": entry.get("run_count"),
                    "prefetch_hash": entry.get("hash"),
                    "prefetch_file": entry.get("filename"),
                },
            }


def _iter_amcache_events(
    amcache_path: Path,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    keyword_filter: Optional[str],
    limit: int,
) -> Iterator[dict[str, Any]]:
    """Iterate Amcache entries as timeline events"""
    from ..parsers.amcache_parser import parse_amcache

    filter_lower = keyword_filter.lower() if keyword_filter else None
    count = 0

    result = parse_amcache(
        amcache_path,
        name_filter=keyword_filter,
        time_range_start=time_range_start.isoformat() if time_range_start else None,
        time_range_end=time_range_end.isoformat() if time_range_end else None,
        limit=limit * 2,  # Get more to allow filtering
    )

    entries = result.get("entries", [])

    for entry in entries:
        if count >= limit:
            break

        name = entry.get("name", "")
        path = entry.get("path", "")
        if filter_lower:
            if filter_lower not in name.lower() and filter_lower not in path.lower():
                continue

        timestamp = entry.get("key_timestamp")
        if not timestamp:
            continue

        count += 1
        yield {
            "timestamp": timestamp,
            "source": "Amcache",
            "event_type": "program_first_seen",
            "description": f"First seen in Amcache: {name or path}",
            "path": path or name,
            "details": {
                "sha1": entry.get("sha1"),
                "publisher": entry.get("publisher"),
                "version": entry.get("version"),
                "product_name": entry.get("product_name"),
            },
        }


def _iter_evtx_events(
    evtx_dir: Path,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    keyword_filter: Optional[str],
    limit: int,
) -> Iterator[dict[str, Any]]:
    """Iterate EVTX entries as timeline events"""
    from ..parsers.evtx_parser import iter_evtx_events, EVTX_AVAILABLE

    if not EVTX_AVAILABLE:
        return

    count = 0
    filter_lower = keyword_filter.lower() if keyword_filter else None

    # Look for Security.evtx primarily (most forensically relevant)
    evtx_files = []
    if evtx_dir.is_file():
        evtx_files = [evtx_dir]
    else:
        for evtx_file in evtx_dir.glob("*.evtx"):
            # Prioritize security log
            if "security" in evtx_file.name.lower():
                evtx_files.insert(0, evtx_file)
            else:
                evtx_files.append(evtx_file)

    # Important event IDs for timeline
    important_event_ids = {
        # Security events
        4624, 4625, 4648, 4672,  # Logon events
        4688, 4689,              # Process creation/termination
        4697,                    # Service installed
        4698, 4699, 4700, 4701, 4702,  # Scheduled tasks
        4720, 4722, 4724, 4728, 4732,  # Account management
        1102,                    # Log cleared
        # System events
        7045,                    # Service installed (System log)
        # Sysmon events (if present)
        1, 3, 11, 12, 13,       # Process create, network, file create, registry
    }

    for evtx_file in evtx_files[:5]:  # Limit files to process
        if count >= limit:
            break

        try:
            for event in iter_evtx_events(
                str(evtx_file),
                start_time=time_range_start.isoformat() if time_range_start else None,
                end_time=time_range_end.isoformat() if time_range_end else None,
            ):
                if count >= limit:
                    break

                event_id = event.get("event_id")
                if event_id not in important_event_ids:
                    continue

                # Apply keyword filter to event data
                if filter_lower:
                    event_str = str(event.get("event_data", {})).lower()
                    if filter_lower not in event_str:
                        continue

                timestamp = event.get("timestamp")
                if not timestamp:
                    continue

                # Generate description based on event ID
                description = _get_event_description(event)

                count += 1
                yield {
                    "timestamp": timestamp,
                    "source": "EVTX",
                    "event_type": f"event_{event_id}",
                    "description": description,
                    "path": str(evtx_file.name),
                    "details": {
                        "event_id": event_id,
                        "provider": event.get("provider"),
                        "computer": event.get("computer"),
                        "event_data": _summarize_event_data(event.get("event_data", {})),
                    },
                }

        except Exception:
            continue


def _get_event_description(event: dict) -> str:
    """Generate human-readable description for EVTX event"""
    event_id = event.get("event_id")
    event_data = event.get("event_data", {})

    descriptions = {
        4624: lambda: f"Logon: {event_data.get('TargetUserName', 'unknown')}@{event_data.get('TargetDomainName', '')} (Type {event_data.get('LogonType', '?')})",
        4625: lambda: f"Failed logon: {event_data.get('TargetUserName', 'unknown')}@{event_data.get('TargetDomainName', '')}",
        4648: lambda: f"Explicit credential use: {event_data.get('TargetUserName', 'unknown')}",
        4672: lambda: f"Special privileges: {event_data.get('SubjectUserName', 'unknown')}",
        4688: lambda: f"Process created: {event_data.get('NewProcessName', event_data.get('CommandLine', 'unknown'))}",
        4689: lambda: f"Process terminated: {event_data.get('ProcessName', 'unknown')}",
        4697: lambda: f"Service installed: {event_data.get('ServiceName', 'unknown')}",
        4720: lambda: f"Account created: {event_data.get('TargetUserName', 'unknown')}",
        1102: lambda: "Security log cleared",
        7045: lambda: f"Service installed: {event_data.get('ServiceName', 'unknown')}",
        1: lambda: f"Sysmon: Process created: {event_data.get('Image', event_data.get('CommandLine', 'unknown'))}",
        3: lambda: f"Sysmon: Network connection: {event_data.get('DestinationIp', '')}:{event_data.get('DestinationPort', '')}",
        11: lambda: f"Sysmon: File created: {event_data.get('TargetFilename', 'unknown')}",
    }

    if event_id in descriptions:
        try:
            return descriptions[event_id]()
        except Exception:
            pass

    return f"Event ID {event_id}"


def _summarize_event_data(event_data: dict, max_fields: int = 5) -> dict:
    """Summarize event data to essential fields"""
    important_fields = [
        "TargetUserName", "SubjectUserName", "TargetDomainName",
        "LogonType", "IpAddress", "WorkstationName",
        "ProcessName", "NewProcessName", "CommandLine", "ParentProcessName",
        "ServiceName", "ImagePath",
        "Image", "DestinationIp", "DestinationPort", "TargetFilename",
    ]

    result = {}
    for field in important_fields:
        if field in event_data and event_data[field]:
            result[field] = event_data[field]
            if len(result) >= max_fields:
                break

    return result


def build_timeline(
    artifacts_dir: str | Path,
    sources: Optional[list[str]] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    keyword_filter: Optional[str] = None,
    limit: int = 1000,
    mft_path: Optional[str] = None,
    usn_path: Optional[str] = None,
    prefetch_path: Optional[str] = None,
    amcache_path: Optional[str] = None,
    evtx_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build comprehensive forensic timeline from multiple artifact sources.

    Args:
        artifacts_dir: Base directory containing forensic artifacts
        sources: List of sources to include: "mft", "usn", "prefetch", "amcache", "evtx"
                 Default: ["mft", "usn", "prefetch", "amcache"]
        time_range_start: ISO datetime, include events after this time
        time_range_end: ISO datetime, include events before this time
        keyword_filter: Filter events containing this keyword (case-insensitive)
        limit: Maximum number of events to return
        mft_path: Override auto-detected $MFT path
        usn_path: Override auto-detected USN Journal path
        prefetch_path: Override auto-detected Prefetch directory path
        amcache_path: Override auto-detected Amcache.hve path
        evtx_path: Override auto-detected EVTX directory path

    Returns:
        Timeline with sorted, deduplicated events
    """
    artifacts_dir = Path(artifacts_dir)

    # Default sources
    if sources is None:
        sources = ["mft", "usn", "prefetch", "amcache"]

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = _parse_iso_datetime(time_range_start)
    if time_range_end:
        end_dt = _parse_iso_datetime(time_range_end)

    # Find artifact paths
    found_paths = find_timeline_artifacts(artifacts_dir)

    # Apply overrides
    if mft_path:
        found_paths["mft"] = Path(mft_path)
    if usn_path:
        found_paths["usn"] = Path(usn_path)
    if prefetch_path:
        found_paths["prefetch"] = Path(prefetch_path)
    if amcache_path:
        found_paths["amcache"] = Path(amcache_path)
    if evtx_path:
        found_paths["evtx"] = Path(evtx_path)

    # Track sources processed
    sources_info = {}
    all_events = []
    seen_hashes = set()

    # Per-source limit to balance timeline
    per_source_limit = max(limit // len(sources), 100) if sources else limit

    # Collect events from each source
    if "mft" in sources and found_paths.get("mft"):
        mft_file = found_paths["mft"]
        if mft_file.exists():
            sources_info["mft"] = {"path": str(mft_file), "status": "processed"}
            try:
                for event in _iter_mft_events(mft_file, start_dt, end_dt, keyword_filter, per_source_limit):
                    event_hash = _event_hash(event)
                    if event_hash not in seen_hashes:
                        seen_hashes.add(event_hash)
                        all_events.append(event)
            except Exception as e:
                sources_info["mft"]["status"] = f"error: {str(e)}"
        else:
            sources_info["mft"] = {"path": str(mft_file), "status": "not found"}
    elif "mft" in sources:
        sources_info["mft"] = {"status": "not found"}

    if "usn" in sources and found_paths.get("usn"):
        usn_file = found_paths["usn"]
        if usn_file.exists():
            sources_info["usn"] = {"path": str(usn_file), "status": "processed"}
            try:
                for event in _iter_usn_events(usn_file, start_dt, end_dt, keyword_filter, per_source_limit):
                    event_hash = _event_hash(event)
                    if event_hash not in seen_hashes:
                        seen_hashes.add(event_hash)
                        all_events.append(event)
            except Exception as e:
                sources_info["usn"]["status"] = f"error: {str(e)}"
        else:
            sources_info["usn"] = {"path": str(usn_file), "status": "not found"}
    elif "usn" in sources:
        sources_info["usn"] = {"status": "not found"}

    if "prefetch" in sources and found_paths.get("prefetch"):
        prefetch_dir = found_paths["prefetch"]
        if prefetch_dir.exists():
            sources_info["prefetch"] = {"path": str(prefetch_dir), "status": "processed"}
            try:
                for event in _iter_prefetch_events(prefetch_dir, start_dt, end_dt, keyword_filter, per_source_limit):
                    event_hash = _event_hash(event)
                    if event_hash not in seen_hashes:
                        seen_hashes.add(event_hash)
                        all_events.append(event)
            except Exception as e:
                sources_info["prefetch"]["status"] = f"error: {str(e)}"
        else:
            sources_info["prefetch"] = {"path": str(prefetch_dir), "status": "not found"}
    elif "prefetch" in sources:
        sources_info["prefetch"] = {"status": "not found"}

    if "amcache" in sources and found_paths.get("amcache"):
        amcache_file = found_paths["amcache"]
        if amcache_file.exists():
            sources_info["amcache"] = {"path": str(amcache_file), "status": "processed"}
            try:
                for event in _iter_amcache_events(amcache_file, start_dt, end_dt, keyword_filter, per_source_limit):
                    event_hash = _event_hash(event)
                    if event_hash not in seen_hashes:
                        seen_hashes.add(event_hash)
                        all_events.append(event)
            except Exception as e:
                sources_info["amcache"]["status"] = f"error: {str(e)}"
        else:
            sources_info["amcache"] = {"path": str(amcache_file), "status": "not found"}
    elif "amcache" in sources:
        sources_info["amcache"] = {"status": "not found"}

    if "evtx" in sources and found_paths.get("evtx"):
        evtx_dir = found_paths["evtx"]
        if evtx_dir.exists():
            sources_info["evtx"] = {"path": str(evtx_dir), "status": "processed"}
            try:
                for event in _iter_evtx_events(evtx_dir, start_dt, end_dt, keyword_filter, per_source_limit):
                    event_hash = _event_hash(event)
                    if event_hash not in seen_hashes:
                        seen_hashes.add(event_hash)
                        all_events.append(event)
            except Exception as e:
                sources_info["evtx"]["status"] = f"error: {str(e)}"
        else:
            sources_info["evtx"] = {"path": str(evtx_dir), "status": "not found"}
    elif "evtx" in sources:
        sources_info["evtx"] = {"status": "not found"}

    # Sort events by timestamp (most recent first)
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Apply overall limit
    all_events = all_events[:limit]

    # Generate statistics
    source_counts = {}
    event_type_counts = {}
    for event in all_events:
        source = event.get("source", "unknown")
        event_type = event.get("event_type", "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

    # Get time range of results
    time_range_result = None
    if all_events:
        timestamps = [e.get("timestamp") for e in all_events if e.get("timestamp")]
        if timestamps:
            time_range_result = {
                "earliest": min(timestamps),
                "latest": max(timestamps),
            }

    return {
        "artifacts_dir": str(artifacts_dir),
        "sources_requested": sources,
        "sources_info": sources_info,
        "filters": {
            "time_range_start": time_range_start,
            "time_range_end": time_range_end,
            "keyword_filter": keyword_filter,
        },
        "statistics": {
            "total_events": len(all_events),
            "by_source": source_counts,
            "by_event_type": event_type_counts,
            "time_range": time_range_result,
        },
        "events": all_events,
    }
