"""
MFT Parser Module

Parses Windows $MFT (Master File Table) for file metadata and timestomping detection.
Compares $STANDARD_INFORMATION and $FILE_NAME timestamps to identify manipulation.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional, Iterator

try:
    import mft
    MFT_AVAILABLE = True
except ImportError:
    MFT_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS


def check_mft_available() -> None:
    """Raise error if mft library not available"""
    if not MFT_AVAILABLE:
        raise ImportError(
            "mft library not installed. Install with: pip install mft"
        )


def _parse_timestamp(ts) -> Optional[str]:
    """Convert MFT timestamp to ISO format string"""
    if ts is None:
        return None
    try:
        # mft library returns datetime objects
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.isoformat()
        return str(ts)
    except Exception:
        return None


def _decode_resident_stream(data: bytes, max_chars: int = 4096) -> dict[str, Any]:
    """Decode small resident stream data for analyst-friendly output."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        encodings = ("utf-16", "utf-8")
    elif data.startswith(b"\x00\x00"):
        # Some parsers expose Zone.Identifier with leading NULs; strip them
        # before trying normal text decoding.
        data = data.lstrip(b"\x00")
        encodings = ("utf-8", "utf-16-le")
    else:
        encodings = ("utf-8", "utf-16-le")

    for encoding in encodings:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue

        printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
        if text and printable / len(text) >= 0.85:
            return {
                "content_encoding": encoding,
                "content_preview": text[:max_chars],
                "content_truncated": len(text) > max_chars,
            }

    hex_preview = data[: max_chars // 2].hex()
    return {
        "content_encoding": "hex",
        "content_preview": hex_preview,
        "content_truncated": len(data) > max_chars // 2,
    }


def _parse_data_stream(attr, entry_file_size: Optional[int]) -> dict[str, Any]:
    """Parse a $DATA attribute, including named NTFS alternate data streams."""
    name = getattr(attr, "name", "") or ""
    is_ads = bool(name)
    is_resident = getattr(attr, "is_resident", None)
    content = getattr(attr, "attribute_content", None)
    data = getattr(content, "data", None) if content is not None else None

    if data is not None:
        stream_size = len(data)
    elif not is_ads:
        stream_size = entry_file_size
    else:
        stream_size = None

    stream = {
        "name": name,
        "type": "$DATA",
        "is_ads": is_ads,
        "is_resident": is_resident,
        "size": stream_size,
        "metadata_size": getattr(attr, "data_size", None),
    }

    # Only include resident content for named streams; unnamed default streams
    # can be huge and are not what ADS hunting needs.
    if is_ads and data:
        stream.update(_decode_resident_stream(data))

    return stream


def _stream_filter_values(entry: dict[str, Any]) -> list[str]:
    """Build searchable strings for path filters, including ADS paths/content."""
    path = entry.get("path") or ""
    values = [path]

    for stream in entry.get("data_streams", []):
        name = stream.get("name") or ""
        if not name:
            continue
        values.extend([
            name,
            f"{path}:{name}" if path else name,
            stream.get("content_preview") or "",
        ])

    return values


def _entry_matches_filter(entry: dict[str, Any], filter_lower: Optional[str]) -> bool:
    """Return True when the path filter matches path or ADS metadata."""
    if not filter_lower:
        return True
    return any(filter_lower in value.lower() for value in _stream_filter_values(entry) if value)


def _detect_timestomping(
    si_created: Optional[datetime],
    fn_created: Optional[datetime],
    threshold_days: int = 365,
) -> dict[str, Any]:
    """
    Detect potential timestomping by comparing $SI and $FN timestamps.

    Timestomping indicators:
    1. $SI.Created < $FN.Created (impossible in normal operation)
    2. $SI.Created significantly older than $FN.Created (suspicious)
    3. Timestamps are rounded/suspicious patterns

    Args:
        si_created: $STANDARD_INFORMATION created timestamp
        fn_created: $FILE_NAME created timestamp
        threshold_days: Days difference to flag as suspicious

    Returns:
        Detection result with indicators
    """
    if si_created is None or fn_created is None:
        return {"detected": False, "reason": "Missing timestamps"}

    # Ensure both have timezone info
    if si_created.tzinfo is None:
        si_created = si_created.replace(tzinfo=timezone.utc)
    if fn_created.tzinfo is None:
        fn_created = fn_created.replace(tzinfo=timezone.utc)

    indicators = []

    # Check if SI created is before FN created (definite timestomping)
    if si_created < fn_created:
        indicators.append("$SI.Created before $FN.Created (impossible normally)")

    # Check if SI is significantly older than FN
    diff = fn_created - si_created
    if diff.days > threshold_days:
        indicators.append(f"$SI.Created is {diff.days} days older than $FN.Created")

    # Check for suspicious patterns (all zeros in time portion)
    if si_created.hour == 0 and si_created.minute == 0 and si_created.second == 0:
        if si_created.microsecond == 0:
            indicators.append("$SI.Created has zeroed time components (suspicious)")

    return {
        "detected": len(indicators) > 0,
        "indicators": indicators if indicators else None,
        "si_created": si_created.isoformat(),
        "fn_created": fn_created.isoformat(),
        "difference_days": diff.days if diff.days != 0 else None,
    }


def _parse_mft_entry(entry, include_all_attributes: bool = False) -> dict[str, Any]:
    """Parse a single MFT entry"""
    flags_str = str(entry.flags)
    # Directories have INDEX_PRESENT flag or DIRECTORY flag
    is_dir = "DIRECTORY" in flags_str or "INDEX_PRESENT" in flags_str

    result = {
        "entry_id": entry.entry_id,
        "sequence": entry.sequence,
        "path": entry.full_path,
        "file_size": entry.file_size,
        "size_semantics": "unknown",
        "host_file_size": None,
        "flags": flags_str,
        "is_allocated": "ALLOCATED" in flags_str,
        "is_directory": is_dir,
        "hard_link_count": entry.hard_link_count,
        "has_ads": False,
        "is_ads_entry": False,
        "ads_count": 0,
        "data_streams": [],
        "timestamps": {
            "si": None,  # $STANDARD_INFORMATION
            "fn": None,  # $FILE_NAME (first one)
        },
        "timestomping": None,
    }

    si_timestamps = None
    fn_timestamps = None
    fn_name = None

    for attr in entry.attributes():
        content = attr.attribute_content

        # $DATA (type 128 / 0x80) - unnamed default stream or named ADS.
        # Non-resident streams often have no parsed content object, so handle
        # these before skipping attributes without content.
        if attr.type_code == 128:
            result["data_streams"].append(_parse_data_stream(attr, entry.file_size))
            continue

        if content is None:
            continue

        # $STANDARD_INFORMATION (type 16 / 0x10)
        if attr.type_code == 16:
            si_timestamps = {
                "created": content.created,
                "modified": content.modified,
                "accessed": content.accessed,
                "mft_modified": content.mft_modified,
            }
            result["timestamps"]["si"] = {
                "created": _parse_timestamp(content.created),
                "modified": _parse_timestamp(content.modified),
                "accessed": _parse_timestamp(content.accessed),
                "mft_modified": _parse_timestamp(content.mft_modified),
            }

        # $FILE_NAME (type 48 / 0x30) - take the first one
        elif attr.type_code == 48 and fn_timestamps is None:
            fn_timestamps = {
                "created": content.created,
                "modified": content.modified,
                "accessed": content.accessed,
                "mft_modified": content.mft_modified,
            }
            fn_name = content.name
            result["timestamps"]["fn"] = {
                "created": _parse_timestamp(content.created),
                "modified": _parse_timestamp(content.modified),
                "accessed": _parse_timestamp(content.accessed),
                "mft_modified": _parse_timestamp(content.mft_modified),
                "name": fn_name,
            }

    ads_streams = [stream for stream in result["data_streams"] if stream.get("is_ads")]
    unnamed_streams = [stream for stream in result["data_streams"] if not stream.get("is_ads")]
    result["has_ads"] = bool(ads_streams)
    result["ads_count"] = len(ads_streams)
    result["host_file_size"] = unnamed_streams[0].get("size") if unnamed_streams else None

    if unnamed_streams:
        result["size_semantics"] = "unnamed_data"
    elif len(ads_streams) == 1:
        result["size_semantics"] = "ads_stream"
        result["is_ads_entry"] = True
        result["stream_name"] = ads_streams[0].get("name")
        result["stream_path"] = (
            f"{result['path']}:{ads_streams[0].get('name')}"
            if result.get("path")
            else ads_streams[0].get("name")
        )
    elif ads_streams:
        result["size_semantics"] = "multiple_ads_streams"

    # Detect timestomping
    if si_timestamps and fn_timestamps:
        result["timestomping"] = _detect_timestomping(
            si_timestamps.get("created"),
            fn_timestamps.get("created"),
        )

    return result


def iter_mft_entries(
    mft_path: str | Path,
    file_path_filter: Optional[str] = None,
    allocated_only: bool = True,
    files_only: bool = False,
) -> Iterator[dict[str, Any]]:
    """
    Iterate over MFT entries with optional filtering.

    Args:
        mft_path: Path to $MFT file
        file_path_filter: Filter by path (case-insensitive substring)
        allocated_only: Only return allocated entries
        files_only: Only return files (not directories)

    Yields:
        Parsed MFT entry dictionaries
    """
    check_mft_available()

    mft_path = Path(mft_path)
    if not mft_path.exists():
        raise FileNotFoundError(f"MFT file not found: {mft_path}")

    parser = mft.PyMftParser(str(mft_path))
    filter_lower = file_path_filter.lower() if file_path_filter else None

    for entry in parser.entries():
        flags_str = str(entry.flags)
        # Apply filters
        if allocated_only and "ALLOCATED" not in flags_str:
            continue

        # Directories have INDEX_PRESENT or DIRECTORY flag
        is_dir = "DIRECTORY" in flags_str or "INDEX_PRESENT" in flags_str
        if files_only and is_dir:
            continue

        parsed = _parse_mft_entry(entry)
        if not _entry_matches_filter(parsed, filter_lower):
            continue

        yield parsed


def parse_mft(
    mft_path: str | Path,
    file_path_filter: Optional[str] = None,
    entry_number: Optional[int] = None,
    detect_timestomping: bool = True,
    output_mode: str = "summary",
    allocated_only: bool = True,
    files_only: bool = False,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse $MFT for file metadata and timestomping detection.

    Args:
        mft_path: Path to $MFT file
        file_path_filter: Filter by file path (case-insensitive substring)
        entry_number: Get specific MFT entry by number
        detect_timestomping: Flag files where SI timestamps are earlier than FN timestamps
        output_mode: "full" (all entries), "summary" (basic info), "timestomping_only" (only flagged)
        allocated_only: Only return allocated entries
        files_only: Only return files (not directories)
        time_range_start: ISO datetime, filter entries modified after this time
        time_range_end: ISO datetime, filter entries modified before this time
        limit: Maximum number of entries to return

    Returns:
        Dictionary with MFT parsing results
    """
    check_mft_available()

    mft_path = Path(mft_path)
    if not mft_path.exists():
        raise FileNotFoundError(f"MFT file not found: {mft_path}")

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    parser = mft.PyMftParser(str(mft_path))

    # If requesting specific entry
    if entry_number is not None:
        for entry in parser.entries():
            if entry.entry_id == entry_number:
                parsed = _parse_mft_entry(entry)
                return {
                    "path": str(mft_path),
                    "entry": parsed,
                }
        return {
            "path": str(mft_path),
            "error": f"Entry {entry_number} not found",
        }

    entries = []
    timestomped_count = 0
    total_scanned = 0
    filter_lower = file_path_filter.lower() if file_path_filter else None

    for entry in parser.entries():
        total_scanned += 1
        flags_str = str(entry.flags)

        # Apply filters
        if allocated_only and "ALLOCATED" not in flags_str:
            continue

        # Directories have INDEX_PRESENT or DIRECTORY flag
        is_dir = "DIRECTORY" in flags_str or "INDEX_PRESENT" in flags_str
        if files_only and is_dir:
            continue

        parsed = _parse_mft_entry(entry)
        if not _entry_matches_filter(parsed, filter_lower):
            continue

        # Time range filter (using SI modified time)
        if start_dt or end_dt:
            si_modified = parsed.get("timestamps", {}).get("si", {}).get("modified")
            if si_modified:
                try:
                    entry_dt = datetime.fromisoformat(si_modified.replace("Z", "+00:00"))
                    if start_dt and entry_dt < start_dt:
                        continue
                    if end_dt and entry_dt > end_dt:
                        continue
                except ValueError:
                    pass

        # Track timestomping
        timestomping = parsed.get("timestomping")
        if timestomping and timestomping.get("detected"):
            timestomped_count += 1

        # Output mode filtering
        if output_mode == "timestomping_only":
            if not (timestomping and timestomping.get("detected")):
                continue

        entries.append(parsed)

        if len(entries) >= limit:
            break

    # Sort by modified time (most recent first)
    entries.sort(
        key=lambda x: x.get("timestamps", {}).get("si", {}).get("modified") or "",
        reverse=True,
    )

    return {
        "path": str(mft_path),
        "total_scanned": total_scanned,
        "returned_entries": len(entries),
        "timestomped_count": timestomped_count,
        "output_mode": output_mode,
        "entries": entries,
    }


def find_timestomped_files(
    mft_path: str | Path,
    threshold_days: int = 365,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Find files with potential timestomping.

    Args:
        mft_path: Path to $MFT file
        threshold_days: Days difference threshold to flag as suspicious
        limit: Maximum results

    Returns:
        List of potentially timestomped files
    """
    check_mft_available()

    mft_path = Path(mft_path)
    if not mft_path.exists():
        raise FileNotFoundError(f"MFT file not found: {mft_path}")

    parser = mft.PyMftParser(str(mft_path))

    timestomped = []
    total_files = 0

    for entry in parser.entries():
        flags_str = str(entry.flags)
        # Only check allocated files (not directories)
        if "ALLOCATED" not in flags_str:
            continue
        # Directories have INDEX_PRESENT or DIRECTORY flag
        is_dir = "DIRECTORY" in flags_str or "INDEX_PRESENT" in flags_str
        if is_dir:
            continue

        total_files += 1
        parsed = _parse_mft_entry(entry)

        timestomping = parsed.get("timestomping")
        if timestomping and timestomping.get("detected"):
            timestomped.append(parsed)

            if len(timestomped) >= limit:
                break

    # Sort by severity (SI before FN is most severe)
    def severity_key(x):
        indicators = x.get("timestomping", {}).get("indicators", [])
        if any("impossible" in i for i in indicators):
            return 0
        return 1

    timestomped.sort(key=severity_key)

    return {
        "path": str(mft_path),
        "total_files_scanned": total_files,
        "timestomped_count": len(timestomped),
        "threshold_days": threshold_days,
        "timestomped_files": timestomped,
    }


def get_mft_entry(
    mft_path: str | Path,
    entry_number: int,
) -> dict[str, Any]:
    """
    Get a specific MFT entry by entry number.

    Args:
        mft_path: Path to $MFT file
        entry_number: MFT entry number

    Returns:
        Parsed MFT entry
    """
    return parse_mft(mft_path, entry_number=entry_number)


def search_mft_by_extension(
    mft_path: str | Path,
    extension: str,
    allocated_only: bool = True,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Search MFT for files by extension.

    Args:
        mft_path: Path to $MFT file
        extension: File extension to search (e.g., "exe", ".exe")
        allocated_only: Only search allocated files
        limit: Maximum results

    Returns:
        Matching files
    """
    check_mft_available()

    # Normalize extension
    ext = extension.lower()
    if not ext.startswith("."):
        ext = "." + ext

    mft_path = Path(mft_path)
    if not mft_path.exists():
        raise FileNotFoundError(f"MFT file not found: {mft_path}")

    parser = mft.PyMftParser(str(mft_path))

    matches = []

    for entry in parser.entries():
        if allocated_only and "ALLOCATED" not in str(entry.flags):
            continue
        if "DIRECTORY" in str(entry.flags):
            continue

        path = entry.full_path
        if path and path.lower().endswith(ext):
            parsed = _parse_mft_entry(entry)
            matches.append(parsed)

            if len(matches) >= limit:
                break

    return {
        "path": str(mft_path),
        "extension": ext,
        "match_count": len(matches),
        "matches": matches,
    }
