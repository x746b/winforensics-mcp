"""
CSV Ingestor for Eric Zimmerman Tool Outputs

Supports importing pre-parsed CSV files from:
- MFTECmd (MFT parsing)
- PECmd (Prefetch parsing)
- AmcacheParser (Amcache parsing)
- SrumECmd (SRUM parsing)

Auto-detects CSV type by column signatures.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# Column signatures for auto-detection
CSV_SIGNATURES = {
    "mftecmd": {
        "required": ["EntryNumber", "FileName"],
        "optional": ["SequenceNumber", "ParentPath", "FileSize", "Created0x10"],
    },
    "pecmd": {
        "required": ["ExecutableName", "RunCount"],
        "optional": ["LastRun", "SourceFilename", "Hash", "Size"],
    },
    "amcache": {
        "required": ["SHA1", "FullPath"],
        "optional": ["Name", "Publisher", "Version", "FileKeyLastWriteTimestamp"],
    },
    "amcache_alt": {
        # Alternative Amcache format
        "required": ["Sha1", "Path"],
        "optional": ["Name", "Publisher", "Version"],
    },
    "srumemd": {
        "required": ["ExeInfo"],
        "optional": ["Timestamp", "UserSid", "BytesSent", "BytesReceived"],
    },
    "srumemd_network": {
        "required": ["InterfaceLuid"],
        "optional": ["BytesSent", "BytesReceived", "Timestamp"],
    },
}

# Field mappings to normalize different CSV formats
FIELD_MAPPINGS = {
    "mftecmd": {
        "entry_number": ["EntryNumber"],
        "sequence_number": ["SequenceNumber"],
        "parent_path": ["ParentPath"],
        "filename": ["FileName"],
        "extension": ["Extension"],
        "file_size": ["FileSize"],
        "is_directory": ["IsDirectory"],
        "in_use": ["InUse"],
        "created": ["Created0x10", "Created0x30"],
        "modified": ["LastModified0x10", "LastModified0x30"],
        "accessed": ["LastAccess0x10", "LastAccess0x30"],
        "record_changed": ["LastRecordChange0x10", "LastRecordChange0x30"],
        "si_flags": ["SiFlags"],
        "is_timestomped": ["SI<FN"],
    },
    "pecmd": {
        "executable": ["ExecutableName"],
        "run_count": ["RunCount"],
        "last_run": ["LastRun"],
        "source_file": ["SourceFilename", "SourceFile"],
        "hash": ["Hash"],
        "size": ["Size"],
        "version": ["Version"],
        "source_created": ["SourceCreated"],
        "source_modified": ["SourceModified"],
        "volume_name": ["Volume0Name"],
        "volume_serial": ["Volume0Serial"],
    },
    "amcache": {
        "sha1": ["SHA1", "Sha1"],
        "path": ["FullPath", "Path"],
        "name": ["Name"],
        "publisher": ["Publisher"],
        "version": ["Version"],
        "file_size": ["FileSize", "Size"],
        "key_timestamp": ["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp"],
        "program_id": ["ProgramId"],
        "language": ["Language"],
        "product_name": ["ProductName"],
    },
    "srumemd": {
        "timestamp": ["Timestamp", "TimeStamp"],
        "exe_info": ["ExeInfo"],
        "user_sid": ["UserSid"],
        "bytes_sent": ["BytesSent"],
        "bytes_received": ["BytesReceived"],
        "foreground_bytes_read": ["ForegroundBytesRead"],
        "foreground_bytes_written": ["ForegroundBytesWritten"],
        "foreground_cycle_time": ["ForegroundCycleTime"],
        "background_cycle_time": ["BackgroundCycleTime"],
    },
}


def _detect_csv_type(headers: list[str]) -> Optional[str]:
    """
    Detect CSV type based on column headers.

    Returns the detected type or None if unknown.
    """
    headers_lower = [h.lower() for h in headers]
    headers_set = set(headers)

    for csv_type, signature in CSV_SIGNATURES.items():
        required = signature["required"]
        # Check if all required columns are present (case-insensitive)
        if all(any(r.lower() == h for h in headers_lower) for r in required):
            # For amcache_alt, map to amcache
            if csv_type == "amcache_alt":
                return "amcache"
            if csv_type == "srumemd_network":
                return "srumemd"
            return csv_type

    return None


def _get_field_value(row: dict, field_mappings: list[str]) -> Optional[str]:
    """Get field value using multiple possible column names."""
    for field in field_mappings:
        if field in row and row[field]:
            return row[field]
    return None


def _parse_timestamp(value: str) -> Optional[str]:
    """Parse various timestamp formats to ISO format."""
    if not value or value.strip() == "":
        return None

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value.strip(), fmt)
            return dt.isoformat()
        except ValueError:
            continue

    # Return as-is if no format matches
    return value.strip()


def _parse_int(value: str) -> Optional[int]:
    """Parse string to integer, handling empty values."""
    if not value or value.strip() == "":
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _parse_bool(value: str) -> Optional[bool]:
    """Parse string to boolean."""
    if not value:
        return None
    v = value.strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    return None


def _normalize_mftecmd_row(row: dict) -> dict:
    """Normalize MFTECmd CSV row to standard format."""
    mappings = FIELD_MAPPINGS["mftecmd"]

    return {
        "entry_number": _parse_int(_get_field_value(row, mappings["entry_number"]) or ""),
        "sequence_number": _parse_int(_get_field_value(row, mappings["sequence_number"]) or ""),
        "parent_path": _get_field_value(row, mappings["parent_path"]),
        "filename": _get_field_value(row, mappings["filename"]),
        "extension": _get_field_value(row, mappings["extension"]),
        "file_size": _parse_int(_get_field_value(row, mappings["file_size"]) or ""),
        "is_directory": _parse_bool(_get_field_value(row, mappings["is_directory"]) or ""),
        "in_use": _parse_bool(_get_field_value(row, mappings["in_use"]) or ""),
        "created": _parse_timestamp(_get_field_value(row, mappings["created"]) or ""),
        "modified": _parse_timestamp(_get_field_value(row, mappings["modified"]) or ""),
        "accessed": _parse_timestamp(_get_field_value(row, mappings["accessed"]) or ""),
        "is_timestomped": _parse_bool(_get_field_value(row, mappings["is_timestomped"]) or ""),
        "full_path": f"{_get_field_value(row, mappings['parent_path']) or ''}/{_get_field_value(row, mappings['filename']) or ''}".replace("//", "/"),
    }


def _normalize_pecmd_row(row: dict) -> dict:
    """Normalize PECmd CSV row to standard format."""
    mappings = FIELD_MAPPINGS["pecmd"]

    return {
        "executable": _get_field_value(row, mappings["executable"]),
        "run_count": _parse_int(_get_field_value(row, mappings["run_count"]) or ""),
        "last_run": _parse_timestamp(_get_field_value(row, mappings["last_run"]) or ""),
        "source_file": _get_field_value(row, mappings["source_file"]),
        "hash": _get_field_value(row, mappings["hash"]),
        "size": _parse_int(_get_field_value(row, mappings["size"]) or ""),
        "version": _get_field_value(row, mappings["version"]),
        "volume_name": _get_field_value(row, mappings["volume_name"]),
        "volume_serial": _get_field_value(row, mappings["volume_serial"]),
    }


def _normalize_amcache_row(row: dict) -> dict:
    """Normalize AmcacheParser CSV row to standard format."""
    mappings = FIELD_MAPPINGS["amcache"]

    return {
        "sha1": _get_field_value(row, mappings["sha1"]),
        "path": _get_field_value(row, mappings["path"]),
        "name": _get_field_value(row, mappings["name"]),
        "publisher": _get_field_value(row, mappings["publisher"]),
        "version": _get_field_value(row, mappings["version"]),
        "file_size": _parse_int(_get_field_value(row, mappings["file_size"]) or ""),
        "key_timestamp": _parse_timestamp(_get_field_value(row, mappings["key_timestamp"]) or ""),
        "program_id": _get_field_value(row, mappings["program_id"]),
        "product_name": _get_field_value(row, mappings["product_name"]),
    }


def _normalize_srumemd_row(row: dict) -> dict:
    """Normalize SrumECmd CSV row to standard format."""
    mappings = FIELD_MAPPINGS["srumemd"]

    return {
        "timestamp": _parse_timestamp(_get_field_value(row, mappings["timestamp"]) or ""),
        "exe_info": _get_field_value(row, mappings["exe_info"]),
        "user_sid": _get_field_value(row, mappings["user_sid"]),
        "bytes_sent": _parse_int(_get_field_value(row, mappings["bytes_sent"]) or ""),
        "bytes_received": _parse_int(_get_field_value(row, mappings["bytes_received"]) or ""),
        "foreground_bytes_read": _parse_int(_get_field_value(row, mappings["foreground_bytes_read"]) or ""),
        "foreground_bytes_written": _parse_int(_get_field_value(row, mappings["foreground_bytes_written"]) or ""),
        "foreground_cycle_time": _parse_int(_get_field_value(row, mappings["foreground_cycle_time"]) or ""),
        "background_cycle_time": _parse_int(_get_field_value(row, mappings["background_cycle_time"]) or ""),
    }


def ingest_csv(
    csv_path: str | Path,
    csv_type: Optional[str] = None,
    filter_field: Optional[str] = None,
    filter_value: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Ingest a pre-parsed CSV from Eric Zimmerman tools.

    Args:
        csv_path: Path to the CSV file
        csv_type: Type of CSV (mftecmd, pecmd, amcache, srumemd) or "auto"
        filter_field: Field name to filter on
        filter_value: Value to filter for (case-insensitive substring)
        time_range_start: ISO format datetime - filter entries after this time
        time_range_end: ISO format datetime - filter entries before this time
        limit: Maximum number of entries to return

    Returns:
        Dictionary with parsed entries and metadata
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        return {"error": f"CSV file not found: {csv_path}"}

    if not csv_path.is_file():
        return {"error": f"Path is not a file: {csv_path}"}

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        try:
            start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
        except ValueError:
            pass
    if time_range_end:
        try:
            end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))
        except ValueError:
            pass

    try:
        # Read CSV with UTF-8 BOM handling
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []

            # Auto-detect CSV type if not specified
            detected_type = _detect_csv_type(headers)

            if csv_type and csv_type != "auto":
                final_type = csv_type
            elif detected_type:
                final_type = detected_type
            else:
                return {
                    "error": "Could not detect CSV type. Please specify csv_type.",
                    "headers_found": headers[:20],
                    "supported_types": list(CSV_SIGNATURES.keys()),
                }

            # Select normalizer based on type
            normalizers = {
                "mftecmd": _normalize_mftecmd_row,
                "pecmd": _normalize_pecmd_row,
                "amcache": _normalize_amcache_row,
                "srumemd": _normalize_srumemd_row,
            }

            normalizer = normalizers.get(final_type)
            if not normalizer:
                return {"error": f"Unsupported CSV type: {final_type}"}

            # Time field for filtering
            time_fields = {
                "mftecmd": "created",
                "pecmd": "last_run",
                "amcache": "key_timestamp",
                "srumemd": "timestamp",
            }
            time_field = time_fields.get(final_type, "timestamp")

            entries = []
            total_rows = 0
            total_matched = 0

            for row in reader:
                total_rows += 1

                # Normalize the row
                normalized = normalizer(row)

                # Apply field filter
                if filter_field and filter_value:
                    field_val = normalized.get(filter_field)
                    if not field_val:
                        continue
                    if filter_value.lower() not in str(field_val).lower():
                        continue

                # Apply time filter
                time_val = normalized.get(time_field)
                if time_val and (start_dt or end_dt):
                    try:
                        entry_dt = datetime.fromisoformat(time_val.replace("Z", "+00:00"))
                        if start_dt and entry_dt < start_dt:
                            continue
                        if end_dt and entry_dt > end_dt:
                            continue
                    except ValueError:
                        pass

                total_matched += 1

                if len(entries) < limit:
                    entries.append(normalized)

            return {
                "path": str(csv_path),
                "csv_type": final_type,
                "csv_type_detected": detected_type,
                "headers": headers[:20],
                "total_rows": total_rows,
                "total_matched": total_matched,
                "returned": len(entries),
                "truncated": total_matched > len(entries),
                "filter": {
                    "field": filter_field,
                    "value": filter_value,
                } if filter_field else None,
                "time_range": {
                    "start": time_range_start,
                    "end": time_range_end,
                } if time_range_start or time_range_end else None,
                "entries": entries,
            }

    except csv.Error as e:
        return {"error": f"CSV parsing error: {e}"}
    except Exception as e:
        return {"error": f"Error reading CSV: {e}"}


def query_mftecmd_csv(
    csv_path: str | Path,
    filename_filter: Optional[str] = None,
    path_filter: Optional[str] = None,
    extension_filter: Optional[str] = None,
    directories_only: bool = False,
    files_only: bool = False,
    deleted_only: bool = False,
    timestomped_only: bool = False,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Query MFTECmd CSV with specific filters.

    Provides more targeted querying than generic ingest_csv.
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        return {"error": f"CSV file not found: {csv_path}"}

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        try:
            start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
        except ValueError:
            pass
    if time_range_end:
        try:
            end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))
        except ValueError:
            pass

    try:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)

            entries = []
            total_rows = 0
            total_matched = 0

            for row in reader:
                total_rows += 1
                normalized = _normalize_mftecmd_row(row)

                # Apply filters
                if filename_filter:
                    fn = normalized.get("filename") or ""
                    if filename_filter.lower() not in fn.lower():
                        continue

                if path_filter:
                    fp = normalized.get("full_path") or ""
                    if path_filter.lower() not in fp.lower():
                        continue

                if extension_filter:
                    ext = normalized.get("extension") or ""
                    if extension_filter.lower().lstrip(".") != ext.lower().lstrip("."):
                        continue

                if directories_only and not normalized.get("is_directory"):
                    continue

                if files_only and normalized.get("is_directory"):
                    continue

                if deleted_only and normalized.get("in_use"):
                    continue

                if timestomped_only and not normalized.get("is_timestomped"):
                    continue

                # Time filter
                created = normalized.get("created")
                if created and (start_dt or end_dt):
                    try:
                        entry_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        if start_dt and entry_dt < start_dt:
                            continue
                        if end_dt and entry_dt > end_dt:
                            continue
                    except ValueError:
                        pass

                total_matched += 1

                if len(entries) < limit:
                    entries.append(normalized)

            return {
                "path": str(csv_path),
                "csv_type": "mftecmd",
                "total_rows": total_rows,
                "total_matched": total_matched,
                "returned": len(entries),
                "truncated": total_matched > len(entries),
                "filters_applied": {
                    "filename": filename_filter,
                    "path": path_filter,
                    "extension": extension_filter,
                    "directories_only": directories_only,
                    "files_only": files_only,
                    "deleted_only": deleted_only,
                    "timestomped_only": timestomped_only,
                },
                "entries": entries,
            }

    except Exception as e:
        return {"error": f"Error reading CSV: {e}"}


def query_pecmd_csv(
    csv_path: str | Path,
    executable_filter: Optional[str] = None,
    min_run_count: Optional[int] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Query PECmd CSV with specific filters.
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        return {"error": f"CSV file not found: {csv_path}"}

    start_dt = None
    end_dt = None
    if time_range_start:
        try:
            start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
        except ValueError:
            pass
    if time_range_end:
        try:
            end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))
        except ValueError:
            pass

    try:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)

            entries = []
            total_rows = 0
            total_matched = 0

            for row in reader:
                total_rows += 1
                normalized = _normalize_pecmd_row(row)

                if executable_filter:
                    exe = normalized.get("executable") or ""
                    if executable_filter.lower() not in exe.lower():
                        continue

                if min_run_count is not None:
                    run_count = normalized.get("run_count") or 0
                    if run_count < min_run_count:
                        continue

                last_run = normalized.get("last_run")
                if last_run and (start_dt or end_dt):
                    try:
                        entry_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                        if start_dt and entry_dt < start_dt:
                            continue
                        if end_dt and entry_dt > end_dt:
                            continue
                    except ValueError:
                        pass

                total_matched += 1

                if len(entries) < limit:
                    entries.append(normalized)

            return {
                "path": str(csv_path),
                "csv_type": "pecmd",
                "total_rows": total_rows,
                "total_matched": total_matched,
                "returned": len(entries),
                "truncated": total_matched > len(entries),
                "entries": entries,
            }

    except Exception as e:
        return {"error": f"Error reading CSV: {e}"}


def query_amcache_csv(
    csv_path: str | Path,
    sha1_filter: Optional[str] = None,
    name_filter: Optional[str] = None,
    path_filter: Optional[str] = None,
    publisher_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Query AmcacheParser CSV with specific filters.
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        return {"error": f"CSV file not found: {csv_path}"}

    start_dt = None
    end_dt = None
    if time_range_start:
        try:
            start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
        except ValueError:
            pass
    if time_range_end:
        try:
            end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))
        except ValueError:
            pass

    try:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)

            entries = []
            total_rows = 0
            total_matched = 0

            for row in reader:
                total_rows += 1
                normalized = _normalize_amcache_row(row)

                if sha1_filter:
                    sha1 = normalized.get("sha1") or ""
                    if sha1_filter.lower() != sha1.lower():
                        continue

                if name_filter:
                    name = normalized.get("name") or ""
                    if name_filter.lower() not in name.lower():
                        continue

                if path_filter:
                    path = normalized.get("path") or ""
                    if path_filter.lower() not in path.lower():
                        continue

                if publisher_filter:
                    pub = normalized.get("publisher") or ""
                    if publisher_filter.lower() not in pub.lower():
                        continue

                ts = normalized.get("key_timestamp")
                if ts and (start_dt or end_dt):
                    try:
                        entry_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if start_dt and entry_dt < start_dt:
                            continue
                        if end_dt and entry_dt > end_dt:
                            continue
                    except ValueError:
                        pass

                total_matched += 1

                if len(entries) < limit:
                    entries.append(normalized)

            return {
                "path": str(csv_path),
                "csv_type": "amcache",
                "total_rows": total_rows,
                "total_matched": total_matched,
                "returned": len(entries),
                "truncated": total_matched > len(entries),
                "entries": entries,
            }

    except Exception as e:
        return {"error": f"Error reading CSV: {e}"}
