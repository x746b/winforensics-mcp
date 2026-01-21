"""
USN Journal Parser Module

Parses Windows $UsnJrnl:$J (Update Sequence Number Journal) for file system change history.
Records file creation, deletion, modification, and rename operations.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Iterator

from ..config import MAX_REGISTRY_RESULTS


# USN_REASON flags
USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}

# File attributes
FILE_ATTRIBUTES = {
    0x0001: "READONLY",
    0x0002: "HIDDEN",
    0x0004: "SYSTEM",
    0x0010: "DIRECTORY",
    0x0020: "ARCHIVE",
    0x0040: "DEVICE",
    0x0080: "NORMAL",
    0x0100: "TEMPORARY",
    0x0200: "SPARSE_FILE",
    0x0400: "REPARSE_POINT",
    0x0800: "COMPRESSED",
    0x1000: "OFFLINE",
    0x2000: "NOT_CONTENT_INDEXED",
    0x4000: "ENCRYPTED",
}


def _filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to datetime"""
    if filetime == 0 or filetime < 0:
        return None
    try:
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        unix_ts = (filetime - EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _parse_reasons(reason: int) -> list[str]:
    """Parse USN reason flags into list of strings"""
    reasons = []
    for flag, name in USN_REASONS.items():
        if reason & flag:
            reasons.append(name)
    return reasons


def _parse_attributes(attrs: int) -> list[str]:
    """Parse file attributes into list of strings"""
    attributes = []
    for flag, name in FILE_ATTRIBUTES.items():
        if attrs & flag:
            attributes.append(name)
    return attributes


def _is_interesting_change(reasons: list[str]) -> bool:
    """Check if the change is forensically interesting"""
    interesting = {
        "FILE_CREATE", "FILE_DELETE", "RENAME_OLD_NAME", "RENAME_NEW_NAME",
        "DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION",
        "SECURITY_CHANGE", "ENCRYPTION_CHANGE", "HARD_LINK_CHANGE",
    }
    return bool(set(reasons) & interesting)


def iter_usn_records(
    usn_path: str | Path,
    skip_sparse: bool = True,
) -> Iterator[dict[str, Any]]:
    """
    Iterate over USN Journal records.

    Args:
        usn_path: Path to $J file
        skip_sparse: Skip sparse/empty regions in the journal

    Yields:
        Parsed USN record dictionaries
    """
    usn_path = Path(usn_path)
    if not usn_path.exists():
        raise FileNotFoundError(f"USN Journal not found: {usn_path}")

    with open(usn_path, 'rb') as f:
        data = f.read()

    offset = 0
    data_len = len(data)

    while offset < data_len - 8:
        # Skip sparse regions (filled with zeros)
        if skip_sparse:
            # Check for zero-filled region
            if data[offset:offset + 8] == b'\x00' * 8:
                # Skip to next page boundary (4096 bytes typically)
                next_page = (offset + 4096) & ~0xFFF
                if next_page <= offset:
                    next_page = offset + 4096
                offset = next_page
                continue

        # Read record length
        if offset + 4 > data_len:
            break

        record_len = struct.unpack('<I', data[offset:offset + 4])[0]

        # Validate record length
        if record_len < 60 or record_len > 65536:
            # Invalid record, try to skip
            offset += 8
            continue

        if offset + record_len > data_len:
            break

        record_data = data[offset:offset + record_len]

        try:
            # Parse USN record (V2 format - most common)
            major_ver = struct.unpack('<H', record_data[4:6])[0]
            minor_ver = struct.unpack('<H', record_data[6:8])[0]

            if major_ver == 2:
                # USN_RECORD_V2
                file_ref = struct.unpack('<Q', record_data[8:16])[0]
                parent_ref = struct.unpack('<Q', record_data[16:24])[0]
                usn = struct.unpack('<Q', record_data[24:32])[0]
                timestamp = struct.unpack('<Q', record_data[32:40])[0]
                reason = struct.unpack('<I', record_data[40:44])[0]
                source_info = struct.unpack('<I', record_data[44:48])[0]
                security_id = struct.unpack('<I', record_data[48:52])[0]
                file_attrs = struct.unpack('<I', record_data[52:56])[0]
                filename_len = struct.unpack('<H', record_data[56:58])[0]
                filename_offset = struct.unpack('<H', record_data[58:60])[0]

                # Extract filename
                filename = ""
                if filename_offset + filename_len <= record_len:
                    try:
                        filename = record_data[filename_offset:filename_offset + filename_len].decode('utf-16-le')
                    except UnicodeDecodeError:
                        filename = "<decode error>"

                dt = _filetime_to_datetime(timestamp)

                yield {
                    "version": f"{major_ver}.{minor_ver}",
                    "usn": usn,
                    "timestamp": dt.isoformat() if dt else None,
                    "file_reference": file_ref,
                    "file_reference_mft_entry": file_ref & 0xFFFFFFFFFFFF,
                    "file_reference_sequence": (file_ref >> 48) & 0xFFFF,
                    "parent_reference": parent_ref,
                    "parent_mft_entry": parent_ref & 0xFFFFFFFFFFFF,
                    "filename": filename,
                    "reason": reason,
                    "reasons": _parse_reasons(reason),
                    "file_attributes": file_attrs,
                    "attributes": _parse_attributes(file_attrs),
                    "is_directory": bool(file_attrs & 0x10),
                    "source_info": source_info,
                    "security_id": security_id,
                }

            elif major_ver == 3:
                # USN_RECORD_V3 (128-bit file references)
                file_ref_low = struct.unpack('<Q', record_data[8:16])[0]
                file_ref_high = struct.unpack('<Q', record_data[16:24])[0]
                parent_ref_low = struct.unpack('<Q', record_data[24:32])[0]
                parent_ref_high = struct.unpack('<Q', record_data[32:40])[0]
                usn = struct.unpack('<Q', record_data[40:48])[0]
                timestamp = struct.unpack('<Q', record_data[48:56])[0]
                reason = struct.unpack('<I', record_data[56:60])[0]
                source_info = struct.unpack('<I', record_data[60:64])[0]
                security_id = struct.unpack('<I', record_data[64:68])[0]
                file_attrs = struct.unpack('<I', record_data[68:72])[0]
                filename_len = struct.unpack('<H', record_data[72:74])[0]
                filename_offset = struct.unpack('<H', record_data[74:76])[0]

                filename = ""
                if filename_offset + filename_len <= record_len:
                    try:
                        filename = record_data[filename_offset:filename_offset + filename_len].decode('utf-16-le')
                    except UnicodeDecodeError:
                        filename = "<decode error>"

                dt = _filetime_to_datetime(timestamp)

                yield {
                    "version": f"{major_ver}.{minor_ver}",
                    "usn": usn,
                    "timestamp": dt.isoformat() if dt else None,
                    "file_reference": file_ref_low,
                    "file_reference_mft_entry": file_ref_low & 0xFFFFFFFFFFFF,
                    "file_reference_sequence": (file_ref_low >> 48) & 0xFFFF,
                    "parent_reference": parent_ref_low,
                    "parent_mft_entry": parent_ref_low & 0xFFFFFFFFFFFF,
                    "filename": filename,
                    "reason": reason,
                    "reasons": _parse_reasons(reason),
                    "file_attributes": file_attrs,
                    "attributes": _parse_attributes(file_attrs),
                    "is_directory": bool(file_attrs & 0x10),
                    "source_info": source_info,
                    "security_id": security_id,
                }

        except (struct.error, IndexError):
            pass

        offset += record_len


def parse_usn_journal(
    usn_path: str | Path,
    filename_filter: Optional[str] = None,
    reason_filter: Optional[list[str]] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    interesting_only: bool = False,
    files_only: bool = False,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse USN Journal for file system changes.

    Args:
        usn_path: Path to $J file
        filename_filter: Filter by filename (case-insensitive substring)
        reason_filter: Filter by reason types (e.g., ["FILE_CREATE", "FILE_DELETE"])
        time_range_start: ISO datetime, filter events after this time
        time_range_end: ISO datetime, filter events before this time
        interesting_only: Only return forensically interesting changes
        files_only: Only return file events (not directories)
        limit: Maximum number of records to return

    Returns:
        Dictionary with USN Journal parsing results
    """
    usn_path = Path(usn_path)
    if not usn_path.exists():
        raise FileNotFoundError(f"USN Journal not found: {usn_path}")

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    filename_lower = filename_filter.lower() if filename_filter else None
    reason_set = set(r.upper() for r in reason_filter) if reason_filter else None

    records = []
    total_scanned = 0
    reason_counts = {}

    for record in iter_usn_records(usn_path):
        total_scanned += 1

        # Track reason counts
        for r in record.get("reasons", []):
            reason_counts[r] = reason_counts.get(r, 0) + 1

        # Apply filters
        if filename_lower:
            fn = record.get("filename", "").lower()
            if filename_lower not in fn:
                continue

        if reason_set:
            record_reasons = set(record.get("reasons", []))
            if not (record_reasons & reason_set):
                continue

        if interesting_only:
            if not _is_interesting_change(record.get("reasons", [])):
                continue

        if files_only and record.get("is_directory"):
            continue

        # Time filter
        if start_dt or end_dt:
            ts = record.get("timestamp")
            if ts:
                try:
                    record_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if start_dt and record_dt < start_dt:
                        continue
                    if end_dt and record_dt > end_dt:
                        continue
                except ValueError:
                    pass

        records.append(record)

        if len(records) >= limit:
            break

    # Sort by timestamp (most recent first)
    records.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    return {
        "path": str(usn_path),
        "total_scanned": total_scanned,
        "returned_records": len(records),
        "reason_distribution": dict(sorted(reason_counts.items(), key=lambda x: -x[1])[:15]),
        "records": records,
    }


def search_usn_for_file(
    usn_path: str | Path,
    filename: str,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Search USN Journal for all changes to a specific file.

    Args:
        usn_path: Path to $J file
        filename: Filename to search for (case-insensitive)
        limit: Maximum results

    Returns:
        All USN records for the specified file
    """
    return parse_usn_journal(
        usn_path,
        filename_filter=filename,
        limit=limit,
    )


def get_file_operations_summary(
    usn_path: str | Path,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
) -> dict[str, Any]:
    """
    Get summary of file operations in the USN Journal.

    Args:
        usn_path: Path to $J file
        time_range_start: ISO datetime filter
        time_range_end: ISO datetime filter

    Returns:
        Summary statistics of file operations
    """
    usn_path = Path(usn_path)
    if not usn_path.exists():
        raise FileNotFoundError(f"USN Journal not found: {usn_path}")

    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    stats = {
        "total_records": 0,
        "files_created": 0,
        "files_deleted": 0,
        "files_renamed": 0,
        "files_modified": 0,
        "directories_created": 0,
        "directories_deleted": 0,
        "earliest_timestamp": None,
        "latest_timestamp": None,
        "reason_distribution": {},
        "extension_distribution": {},
    }

    for record in iter_usn_records(usn_path):
        # Time filter
        if start_dt or end_dt:
            ts = record.get("timestamp")
            if ts:
                try:
                    record_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if start_dt and record_dt < start_dt:
                        continue
                    if end_dt and record_dt > end_dt:
                        continue
                except ValueError:
                    pass

        stats["total_records"] += 1

        # Track timestamps
        ts = record.get("timestamp")
        if ts:
            if stats["earliest_timestamp"] is None or ts < stats["earliest_timestamp"]:
                stats["earliest_timestamp"] = ts
            if stats["latest_timestamp"] is None or ts > stats["latest_timestamp"]:
                stats["latest_timestamp"] = ts

        reasons = record.get("reasons", [])
        is_dir = record.get("is_directory", False)

        # Count by reason
        for r in reasons:
            stats["reason_distribution"][r] = stats["reason_distribution"].get(r, 0) + 1

        # Count operations
        if "FILE_CREATE" in reasons:
            if is_dir:
                stats["directories_created"] += 1
            else:
                stats["files_created"] += 1
        if "FILE_DELETE" in reasons:
            if is_dir:
                stats["directories_deleted"] += 1
            else:
                stats["files_deleted"] += 1
        if "RENAME_NEW_NAME" in reasons:
            stats["files_renamed"] += 1
        if any(r in reasons for r in ["DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION"]):
            stats["files_modified"] += 1

        # Track file extensions
        filename = record.get("filename", "")
        if "." in filename and not is_dir:
            ext = filename.rsplit(".", 1)[-1].lower()
            if len(ext) <= 10:  # Reasonable extension length
                stats["extension_distribution"][ext] = stats["extension_distribution"].get(ext, 0) + 1

    # Sort distributions
    stats["reason_distribution"] = dict(
        sorted(stats["reason_distribution"].items(), key=lambda x: -x[1])[:20]
    )
    stats["extension_distribution"] = dict(
        sorted(stats["extension_distribution"].items(), key=lambda x: -x[1])[:20]
    )

    return {
        "path": str(usn_path),
        "summary": stats,
    }


def find_deleted_files(
    usn_path: str | Path,
    extension_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Find deleted files from USN Journal.

    Args:
        usn_path: Path to $J file
        extension_filter: Filter by file extension (e.g., "exe", "docx")
        time_range_start: ISO datetime filter
        time_range_end: ISO datetime filter
        limit: Maximum results

    Returns:
        List of deleted files
    """
    usn_path = Path(usn_path)
    if not usn_path.exists():
        raise FileNotFoundError(f"USN Journal not found: {usn_path}")

    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    ext = None
    if extension_filter:
        ext = extension_filter.lower()
        if not ext.startswith("."):
            ext = "." + ext

    deleted = []

    for record in iter_usn_records(usn_path):
        if "FILE_DELETE" not in record.get("reasons", []):
            continue

        if record.get("is_directory"):
            continue

        filename = record.get("filename", "")

        # Extension filter
        if ext and not filename.lower().endswith(ext):
            continue

        # Time filter
        if start_dt or end_dt:
            ts = record.get("timestamp")
            if ts:
                try:
                    record_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if start_dt and record_dt < start_dt:
                        continue
                    if end_dt and record_dt > end_dt:
                        continue
                except ValueError:
                    pass

        deleted.append(record)

        if len(deleted) >= limit:
            break

    # Sort by timestamp (most recent first)
    deleted.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    return {
        "path": str(usn_path),
        "deleted_count": len(deleted),
        "deleted_files": deleted,
    }
