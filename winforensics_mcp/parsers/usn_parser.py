"""
USN Journal Parser Module

Parses Windows $UsnJrnl:$J (Update Sequence Number Journal) for file system change history.
Records file creation, deletion, modification, and rename operations.
"""
from __future__ import annotations

import mmap
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


def _build_record(major_ver: int, minor_ver: int, file_ref: int, parent_ref: int,
                   usn: int, timestamp_ft: int, reason: int, source_info: int,
                   security_id: int, file_attrs: int, filename: str) -> dict[str, Any]:
    """Build a full USN record dict from raw fields."""
    dt = _filetime_to_datetime(timestamp_ft)
    return {
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


def iter_usn_records(
    usn_path: str | Path,
    skip_sparse: bool = True,
) -> Iterator[dict[str, Any]]:
    """
    Iterate over USN Journal records as dicts.

    Args:
        usn_path: Path to $J file
        skip_sparse: Skip sparse/empty regions in the journal

    Yields:
        Parsed USN record dictionaries
    """
    for (maj, minor, file_ref, parent_ref, usn, ts_ft,
         reason, src_info, sec_id, file_attrs, filename) in iter_usn_raw(usn_path, skip_sparse):
        yield _build_record(maj, minor, file_ref, parent_ref, usn, ts_ft,
                            reason, src_info, sec_id, file_attrs, filename)


def iter_usn_raw(
    usn_path: str | Path,
    skip_sparse: bool = True,
) -> Iterator[tuple]:
    """
    Fast iterator yielding raw USN field tuples (no dict/list allocation per record).

    Yields:
        (major_ver, minor_ver, file_ref, parent_ref, usn, timestamp_filetime,
         reason, source_info, security_id, file_attrs, filename)
    """
    usn_path = Path(usn_path)
    if not usn_path.exists():
        raise FileNotFoundError(f"USN Journal not found: {usn_path}")

    import os

    with open(usn_path, 'rb') as f:
        file_size = os.fstat(f.fileno()).st_size
        if file_size == 0:
            return

        # Use mmap instead of f.read() — avoids loading multi-GB journals into Python heap
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    try:
        data = mm
        data_len = file_size
        offset = 0

        # Pre-allocated buffer for sparse region checks
        _ZEROS_8 = b'\x00' * 8

        # Struct formats for batch unpacking (avoid per-field unpack overhead)
        _V2_HEADER = struct.Struct('<IHHQQQQIIIIHH')  # 60 bytes: record_len..filename_offset
        _V3_HEADER = struct.Struct('<IHHQQQQQQIIIIHH')  # 76 bytes

        while offset < data_len - 8:
            # Skip sparse regions (filled with zeros)
            if skip_sparse:
                if data[offset:offset + 8] == _ZEROS_8:
                    next_page = (offset + 4096) & ~0xFFF
                    if next_page <= offset:
                        next_page = offset + 4096
                    offset = next_page
                    continue

            # Read record length
            if offset + 4 > data_len:
                break

            record_len = struct.unpack_from('<I', data, offset)[0]

            # Validate record length
            if record_len < 60 or record_len > 65536:
                offset += 8
                continue

            if offset + record_len > data_len:
                break

            try:
                major_ver = struct.unpack_from('<H', data, offset + 4)[0]

                if major_ver == 2 and record_len >= 60:
                    # USN_RECORD_V2 — batch unpack all fixed fields at once
                    (_, _maj, _min, file_ref, parent_ref, usn, timestamp,
                     reason, source_info, security_id, file_attrs,
                     filename_len, filename_offset) = _V2_HEADER.unpack_from(data, offset)

                    # Extract filename
                    filename = ""
                    abs_fn_start = offset + filename_offset
                    if filename_offset + filename_len <= record_len and abs_fn_start + filename_len <= data_len:
                        try:
                            filename = data[abs_fn_start:abs_fn_start + filename_len].decode('utf-16-le')
                        except UnicodeDecodeError:
                            filename = "<decode error>"

                    yield (2, _min, file_ref, parent_ref, usn, timestamp,
                           reason, source_info, security_id, file_attrs, filename)

                elif major_ver == 3 and record_len >= 76:
                    # USN_RECORD_V3 (128-bit file references) — batch unpack
                    (_, _maj, _min, file_ref_low, file_ref_high,
                     parent_ref_low, parent_ref_high, usn, timestamp,
                     reason, source_info, security_id, file_attrs,
                     filename_len, filename_offset) = _V3_HEADER.unpack_from(data, offset)

                    filename = ""
                    abs_fn_start = offset + filename_offset
                    if filename_offset + filename_len <= record_len and abs_fn_start + filename_len <= data_len:
                        try:
                            filename = data[abs_fn_start:abs_fn_start + filename_len].decode('utf-16-le')
                        except UnicodeDecodeError:
                            filename = "<decode error>"

                    yield (3, _min, file_ref_low, parent_ref_low, usn, timestamp,
                           reason, source_info, security_id, file_attrs, filename)

            except (struct.error, IndexError):
                pass

            offset += record_len

    finally:
        mm.close()


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
    reason_set = None
    if reason_filter:
        # Convert reason names to bitmask for fast comparison
        reason_name_to_flag = {v: k for k, v in USN_REASONS.items()}
        reason_set = 0
        for r in reason_filter:
            flag = reason_name_to_flag.get(r.upper(), 0)
            reason_set |= flag

    records = []
    total_scanned = 0
    reason_counts = {}

    # Pre-build sorted flag list for reason counting
    _reason_flags = sorted(USN_REASONS.items())

    # Use raw iterator — avoids dict/list creation for non-matching records
    for (maj, minor, file_ref, parent_ref, usn_val, ts_ft,
         reason, src_info, sec_id, file_attrs, filename) in iter_usn_raw(usn_path):
        total_scanned += 1

        # Track reason counts (bitmask check, skip if reason == CLOSE only)
        if reason:
            for flag, name in _reason_flags:
                if reason & flag:
                    reason_counts[name] = reason_counts.get(name, 0) + 1

        # Apply filters on raw fields (no dict/list allocation)
        if filename_lower:
            if filename_lower not in filename.lower():
                continue

        if reason_set is not None:
            if not (reason & reason_set):
                continue

        if interesting_only:
            # Check interesting flags directly via bitmask
            INTERESTING_MASK = (0x1 | 0x2 | 0x4 | 0x100 | 0x200 |
                                0x1000 | 0x2000 | 0x800 | 0x40000 | 0x10000)
            if not (reason & INTERESTING_MASK):
                continue

        if files_only and (file_attrs & 0x10):
            continue

        # Time filter
        if start_dt or end_dt:
            dt = _filetime_to_datetime(ts_ft)
            if dt:
                if start_dt and dt < start_dt:
                    continue
                if end_dt and dt > end_dt:
                    continue

        # Only build full record dict for matched records
        records.append(_build_record(maj, minor, file_ref, parent_ref, usn_val, ts_ft,
                                     reason, src_info, sec_id, file_attrs, filename))

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

    # Track min/max filetime as ints for speed, convert at end
    earliest_ft: Optional[int] = None
    latest_ft: Optional[int] = None

    for (maj, minor, file_ref, parent_ref, usn_val, ts_ft,
         reason, src_info, sec_id, file_attrs, filename) in iter_usn_raw(usn_path):
        # Time filter
        if start_dt or end_dt:
            dt = _filetime_to_datetime(ts_ft)
            if dt:
                if start_dt and dt < start_dt:
                    continue
                if end_dt and dt > end_dt:
                    continue

        stats["total_records"] += 1

        # Track timestamps (compare raw filetimes — no datetime conversion)
        if ts_ft > 0:
            if earliest_ft is None or ts_ft < earliest_ft:
                earliest_ft = ts_ft
            if latest_ft is None or ts_ft > latest_ft:
                latest_ft = ts_ft

        is_dir = bool(file_attrs & 0x10)

        # Count by reason (bitmask check, no list creation)
        for flag, name in USN_REASONS.items():
            if reason & flag:
                stats["reason_distribution"][name] = stats["reason_distribution"].get(name, 0) + 1

        # Count operations (bitmask checks)
        if reason & 0x100:  # FILE_CREATE
            if is_dir:
                stats["directories_created"] += 1
            else:
                stats["files_created"] += 1
        if reason & 0x200:  # FILE_DELETE
            if is_dir:
                stats["directories_deleted"] += 1
            else:
                stats["files_deleted"] += 1
        if reason & 0x2000:  # RENAME_NEW_NAME
            stats["files_renamed"] += 1
        if reason & 0x7:  # DATA_OVERWRITE | DATA_EXTEND | DATA_TRUNCATION
            stats["files_modified"] += 1

        # Track file extensions
        if "." in filename and not is_dir:
            ext = filename.rsplit(".", 1)[-1].lower()
            if len(ext) <= 10:
                stats["extension_distribution"][ext] = stats["extension_distribution"].get(ext, 0) + 1

    # Convert tracked filetimes to ISO strings
    if earliest_ft:
        dt = _filetime_to_datetime(earliest_ft)
        stats["earliest_timestamp"] = dt.isoformat() if dt else None
    if latest_ft:
        dt = _filetime_to_datetime(latest_ft)
        stats["latest_timestamp"] = dt.isoformat() if dt else None

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

    for (maj, minor, file_ref, parent_ref, usn_val, ts_ft,
         reason, src_info, sec_id, file_attrs, filename) in iter_usn_raw(usn_path):
        if not (reason & 0x200):  # FILE_DELETE
            continue

        if file_attrs & 0x10:  # DIRECTORY
            continue

        # Extension filter
        if ext and not filename.lower().endswith(ext):
            continue

        # Time filter
        if start_dt or end_dt:
            dt = _filetime_to_datetime(ts_ft)
            if dt:
                if start_dt and dt < start_dt:
                    continue
                if end_dt and dt > end_dt:
                    continue

        deleted.append(_build_record(maj, minor, file_ref, parent_ref, usn_val, ts_ft,
                                     reason, src_info, sec_id, file_attrs, filename))

        if len(deleted) >= limit:
            break

    # Sort by timestamp (most recent first)
    deleted.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    return {
        "path": str(usn_path),
        "deleted_count": len(deleted),
        "deleted_files": deleted,
    }
