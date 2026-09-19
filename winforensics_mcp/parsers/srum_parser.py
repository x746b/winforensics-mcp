from __future__ import annotations

import math
import re
import struct
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path
from typing import Any
from uuid import UUID

try:
    import pyesedb
    PYESEDB_AVAILABLE = True
except ImportError:
    PYESEDB_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS

# SRUM table GUIDs
SRUM_TABLES = {
    "app_resource_usage": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
    "network_data_usage": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
    "network_connectivity": "{DD6636C4-8929-4683-974E-22C046A43763}",
    "app_timeline": "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
    "energy_usage": "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
    "push_notifications": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}",
}


def check_pyesedb_available() -> None:
    """Raise error if pyesedb library not available"""
    if not PYESEDB_AVAILABLE:
        raise ImportError(
            "libesedb-python library not installed. Install with: pip install libesedb-python"
        )


def _ole_timestamp_to_datetime(ole_bytes: bytes) -> datetime | None:
    """Convert OLE/Variant timestamp (8 bytes, float64) to datetime"""
    if not ole_bytes or len(ole_bytes) != 8:
        return None
    try:
        ole_time = struct.unpack('<d', ole_bytes)[0]
        if not math.isfinite(ole_time):
            return None
        # OLE DATE uses the absolute fractional part as the time of day,
        # including for dates before the epoch.
        days = math.trunc(ole_time)
        return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(
            days=days, seconds=abs(ole_time - days) * 86400
        )
    except (struct.error, ValueError, OSError, OverflowError):
        return None


def _filetime_to_datetime(filetime_bytes: bytes) -> datetime | None:
    """Convert Windows FILETIME (8 bytes) to datetime"""
    if not filetime_bytes or len(filetime_bytes) != 8:
        return None
    try:
        filetime = struct.unpack('<Q', filetime_bytes)[0]
        if filetime == 0:
            return None
        epoch_diff = 116444736000000000
        if filetime < epoch_diff:
            return None
        unix_ts = (filetime - epoch_diff) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (struct.error, ValueError, OSError, OverflowError):
        return None


def _get_int_value(data: bytes, size: int = 4) -> int | None:
    """Extract integer from bytes"""
    if not data:
        return None
    try:
        if size == 4:
            return struct.unpack('<I', data[:4])[0]
        elif size == 8:
            return struct.unpack('<Q', data[:8])[0]
        elif size == 2:
            return struct.unpack('<H', data[:2])[0]
        elif size == 1:
            return data[0]
        return None
    except (struct.error, IndexError):
        return None


def _get_record_value(record, column_index: int, column_type: int) -> Any:
    """Decode JET_COLTYP without scaling or losing integer precision.

    Type definitions: Microsoft's ESE published/inc/jethdr.w. Currency is
    retained as its signed 64-bit integer because SRUM uses raw counters.
    Invalid typed values raise so the caller can report a field error.
    """
    data = record.get_value_data(column_index)
    if data is None:
        return None

    formats = {
        1: "B",  # Bit (one byte, nullable)
        2: "B",  # UnsignedByte
        3: "h",  # Short
        4: "i",  # Long
        5: "q",  # Currency / native signed 64-bit integer
        6: "f",  # IEEESingle
        7: "d",  # IEEEDouble
        14: "I",  # UnsignedLong
        15: "q",  # LongLong
        17: "H",  # UnsignedShort
        18: "Q",  # UnsignedLongLong (Windows 10+)
    }
    if column_type in formats:
        value = struct.unpack("<" + formats[column_type], data)[0]
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite ESE floating point value")
        return bool(value) if column_type == 1 else value
    if column_type == 8:  # DateTime (OLE)
        dt = _ole_timestamp_to_datetime(data)
        if dt is None:
            raise ValueError("Invalid ESE OLE timestamp")
        return dt.isoformat()
    if column_type in (10, 12):  # Text / LongText; let libesedb honor the code page.
        return record.get_value_data_as_string(column_index)
    if column_type == 16:
        return str(UUID(bytes_le=data))
    # Binary/LongBinary and unknown types retain all bytes, not a preview.
    return data.hex()


def _build_id_map(db, diagnostics=None) -> dict[int, dict[str, Any]]:
    """Build mapping of AppId/UserId to names from SruDbIdMapTable"""
    id_map = {}

    try:
        # Find SruDbIdMapTable
        for i in range(db.number_of_tables):
            table = db.get_table(i)
            if table.name == "SruDbIdMapTable":
                for j in range(table.number_of_records):
                    record = table.get_record(j)

                    id_type_data = record.get_value_data(0)
                    id_index_data = record.get_value_data(1)
                    id_blob_data = record.get_value_data(2)

                    if not id_index_data:
                        continue

                    id_type = _get_int_value(id_type_data, 1) if id_type_data else 0
                    id_index = _get_int_value(id_index_data, 4)

                    if id_index is None:
                        continue

                    # Parse blob based on type
                    name = None
                    if id_blob_data:
                        try:
                            # Try to decode as UTF-16-LE string
                            decoded = id_blob_data.decode('utf-16-le').rstrip('\x00')
                            if decoded:
                                name = decoded
                        except (UnicodeDecodeError, AttributeError):
                            pass

                    id_map[id_index] = {
                        "type": (
                            "app" if id_type == 0 else "user" if id_type == 3 else f"type_{id_type}"
                        ),
                        "name": name,
                    }
                break
    except Exception as exc:
        if diagnostics is not None:
            _add_error(diagnostics, "id_map_errors", None, exc)

    return id_map


def _parse_app_name(raw_name: str) -> dict[str, str]:
    """Parse application name from SRUM format: !!exe.exe!timestamp!hex!description"""
    result = {"raw": raw_name, "executable": None, "description": None}

    if not raw_name:
        return result

    if raw_name.startswith("!!"):
        # Format: !!executable.exe!timestamp!hex!description
        parts = raw_name[2:].split("!")
        if parts:
            result["executable"] = parts[0]
        if len(parts) >= 4:
            # Last part might be description in brackets
            desc = parts[-1] if parts[-1] else None
            if desc:
                result["description"] = desc.strip("[] ")
    else:
        # Might be a SID or other format
        result["executable"] = raw_name

    return result


def _find_table_by_guid(db, guid: str):
    """Find table by GUID"""
    for i in range(db.number_of_tables):
        table = db.get_table(i)
        if table.name == guid:
            return table
    return None


APP_MATCH_MODES = ("substring", "exact_basename", "exact_path", "regex")
AGGREGATE_BY = (
    "none", "application", "user", "interface", "application_user", "application_interface",
)
_COMMON_COLUMNS = {
    "TimeStamp": "timestamp", "AppId": "app_id", "UserId": "user_id",
}
_APP_COLUMNS = {
    **_COMMON_COLUMNS,
    "ForegroundCycleTime": "foreground_cycle_time",
    "BackgroundCycleTime": "background_cycle_time",
    "FaceTime": "face_time",
    "ForegroundBytesRead": "foreground_bytes_read",
    "ForegroundBytesWritten": "foreground_bytes_written",
    "BackgroundBytesRead": "background_bytes_read",
    "BackgroundBytesWritten": "background_bytes_written",
}
_NETWORK_COLUMNS = {
    **_COMMON_COLUMNS,
    "BytesSent": "bytes_sent", "BytesRecvd": "bytes_received", "InterfaceLuid": "interface_luid",
}


def _utc_datetime(value: str) -> datetime:
    """Interpret naive ISO timestamps as UTC, and normalize offsets to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Expected a non-empty ISO datetime string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_filters(app_filter, app_match_mode, time_range_start, time_range_end, limit):
    if app_match_mode not in APP_MATCH_MODES:
        raise ValueError(f"app_match_mode must be one of: {', '.join(APP_MATCH_MODES)}")
    if app_filter is not None and not isinstance(app_filter, str):
        raise ValueError("app_filter must be a string")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    pattern = None
    if app_match_mode == "regex" and app_filter:
        try:
            pattern = re.compile(app_filter, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid app_filter regex: {exc}") from exc
    bounds = []
    for name, value in (("time_range_start", time_range_start), ("time_range_end", time_range_end)):
        try:
            bounds.append(_utc_datetime(value) if value is not None else None)
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"{name} must be a valid ISO datetime") from exc
    start_dt, end_dt = bounds
    if start_dt and end_dt and start_dt > end_dt:
        raise ValueError("time_range_start must not be after time_range_end")
    return start_dt, end_dt, pattern


def _normalize_app_path(value: str) -> str:
    # Do not resolve relative segments, strip prefixes, or expand environment variables.
    return value.replace("/", "\\").lower()


def _app_matches(entry, app_filter, mode, pattern) -> bool:
    if not app_filter:
        return True
    raw = entry.get("app_name") or ""
    executable = entry.get("executable") or ""
    if mode == "substring":
        return app_filter.lower() in raw.lower() or app_filter.lower() in executable.lower()
    if mode == "regex":
        return bool(pattern.search(raw) or pattern.search(executable))
    expected = _normalize_app_path(app_filter)
    candidate = _normalize_app_path(executable)
    if mode == "exact_basename":
        return candidate.rsplit("\\", 1)[-1] == expected
    return candidate == expected


def _traffic_units(entry: dict[str, Any]) -> None:
    """Add decimal MB and binary MiB; raw integer counters remain authoritative."""
    for field in ("bytes_sent", "bytes_received"):
        value = entry.get(field)
        for unit, divisor in (("decimal_mb", 1_000_000), ("binary_mib", 1_048_576)):
            converted = None
            if type(value) is int:
                with localcontext() as context:
                    context.prec = max(28, len(str(abs(value))) + 12)
                    converted = float((Decimal(value) / divisor).quantize(
                        Decimal("0.000001"), rounding=ROUND_HALF_EVEN,
                    ))
            entry[f"{field}_{unit}"] = converted


def _diagnostics() -> dict[str, Any]:
    return {
        "record_errors": 0, "field_errors": 0, "id_map_errors": 0,
        "invalid_timestamps": 0, "skipped_invalid_timestamps": 0,
        "skipped_record_errors": 0, "error_count": 0, "errors": [],
    }


def _add_error(diagnostics, kind, record_index, error, column=None):
    diagnostics[kind] += 1
    diagnostics["error_count"] += 1
    if len(diagnostics["errors"]) < 25:
        item = {"kind": kind, "record_index": record_index, "message": str(error)[:300]}
        if column is not None:
            item["column"] = column
        diagnostics["errors"].append(item)


def _aggregate_network(groups, entry, timestamp, aggregate_by):
    dimensions = {}
    if "application" in aggregate_by:
        application = entry.get("executable") or entry.get("app_name")
        dimensions["application"] = _normalize_app_path(application) if application else None
        # Keep unresolved IDs distinct; known names group across ID-map aliases.
        dimensions["app_id"] = entry.get("app_id") if not application else None
    if "user" in aggregate_by:
        dimensions["user_id"] = entry.get("user_id")
    if "interface" in aggregate_by:
        dimensions["interface_luid"] = entry.get("interface_luid")
    key = tuple(dimensions.values())
    if key not in groups:
        groups[key] = {
            **dimensions, "record_count": 0, "bytes_sent": None, "bytes_received": None,
            "first_timestamp": None, "last_timestamp": None,
            "missing_bytes_sent_records": 0, "missing_bytes_received_records": 0,
            "missing_timestamp_records": 0,
        }
    group = groups[key]
    group["record_count"] += 1
    for field in ("bytes_sent", "bytes_received"):
        value = entry.get(field)
        if type(value) is int:
            group[field] = (group[field] or 0) + value
        else:
            group[f"missing_{field}_records"] += 1
    if timestamp is None:
        group["missing_timestamp_records"] += 1
    else:
        iso = timestamp.isoformat()
        if group["first_timestamp"] is None or iso < group["first_timestamp"]:
            group["first_timestamp"] = iso
        if group["last_timestamp"] is None or iso > group["last_timestamp"]:
            group["last_timestamp"] = iso


def _parse_usage_table(
    srum_path, table_key, app_filter, time_range_start, time_range_end, limit,
    app_match_mode, aggregate_by="none",
):
    start_dt, end_dt, pattern = _validate_filters(
        app_filter, app_match_mode, time_range_start, time_range_end, limit,
    )
    if aggregate_by not in AGGREGATE_BY:
        raise ValueError(f"aggregate_by must be one of: {', '.join(AGGREGATE_BY)}")
    check_pyesedb_available()
    srum_path = Path(srum_path)
    if not srum_path.exists():
        raise FileNotFoundError(f"SRUM database not found: {srum_path}")
    network = table_key == "network_data_usage"
    title = "Network Data Usage" if network else "Application Resource Usage"
    fields = _NETWORK_COLUMNS if network else _APP_COLUMNS
    diagnostics = _diagnostics()
    db = pyesedb.file()
    db.open(str(srum_path))
    try:
        id_map = _build_id_map(db, diagnostics)
        table = _find_table_by_guid(db, SRUM_TABLES[table_key])
        if table is None:
            return {"error": f"{title} table not found", "entries": [], "diagnostics": diagnostics}
        columns = {}
        for i in range(table.number_of_columns):
            column = table.get_column(i)
            columns[column.name] = (i, column.type)
        entries = []
        groups = {}
        scanned = matched = 0
        for i in range(table.number_of_records):
            # Retain legacy record selection; aggregation explicitly scans all matches.
            if len(entries) >= limit and aggregate_by == "none":
                break
            scanned += 1
            try:
                record = table.get_record(i)
            except Exception as exc:
                _add_error(diagnostics, "record_errors", i, exc)
                diagnostics["skipped_record_errors"] += 1
                continue
            entry = dict.fromkeys(fields.values())
            entry.update(app_name=None, executable=None)
            for column_name, field in fields.items():
                if column_name in columns:
                    index, column_type = columns[column_name]
                    try:
                        entry[field] = _get_record_value(record, index, column_type)
                    except Exception as exc:
                        _add_error(diagnostics, "field_errors", i, exc, column_name)
            app_info = id_map.get(entry["app_id"], {})
            entry["app_name"] = app_info.get("name")
            entry["executable"] = _parse_app_name(entry["app_name"])["executable"]
            if not _app_matches(entry, app_filter, app_match_mode, pattern):
                continue
            timestamp = None
            try:
                timestamp = _utc_datetime(entry["timestamp"])
            except (ValueError, OverflowError):
                diagnostics["invalid_timestamps"] += 1
                if start_dt is not None or end_dt is not None:
                    diagnostics["skipped_invalid_timestamps"] += 1
                    continue
            if timestamp is not None:
                if start_dt is not None and timestamp < start_dt:
                    continue
                if end_dt is not None and timestamp > end_dt:
                    continue
            matched += 1
            if network:
                _traffic_units(entry)
                if aggregate_by != "none":
                    _aggregate_network(groups, entry, timestamp, aggregate_by)
            if len(entries) < limit:
                entries.append(entry)
        # Existing output is newest-first within the limited record selection.
        entries.sort(key=lambda entry: entry.get("timestamp") or "", reverse=True)
        scan_complete = scanned == table.number_of_records
        diagnostics["errors_truncated"] = diagnostics["error_count"] > len(diagnostics["errors"])
        result = {
            "path": str(srum_path), "table": title, "total_records": table.number_of_records,
            "returned_entries": len(entries), "entries": entries,
            "scanned_records": scanned, "scan_complete": scan_complete,
            "matched_records": matched, "matched_records_complete": scan_complete,
            "entries_truncated": not scan_complete or matched > len(entries),
            "diagnostics": diagnostics,
        }
        if aggregate_by != "none":
            aggregates = list(groups.values())
            for aggregate in aggregates:
                _traffic_units(aggregate)
            result["aggregates"] = aggregates
            result["aggregation"] = {
                "aggregate_by": aggregate_by, "scope": "all_matching_records",
                "record_count": matched, "group_count": len(aggregates),
                "scan_complete": scan_complete,
                "complete": (
                    not diagnostics["error_count"] and not diagnostics["invalid_timestamps"]
                    and not any(
                        group["missing_bytes_sent_records"]
                        or group["missing_bytes_received_records"]
                        for group in aggregates
                    )
                ),
                "application_key": "normalized executable path, with app_id for unresolved names",
                "missing_key_policy": "null bucket; unresolved application IDs remain distinct",
                "counter_policy": "sum known integers; missing values counted separately",
            }
        return result
    finally:
        db.close()


def parse_srum_app_resource_usage(
    srum_path: str | Path,
    app_filter: str | None = None,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
    limit: int = MAX_REGISTRY_RESULTS,
    *,
    app_match_mode: str = "substring",
) -> dict[str, Any]:
    """Read raw SRUM application counters with inclusive UTC time boundaries.

    Cycle and FaceTime counters are preserved without interpreting runtime units.
    Naive ISO boundaries are UTC. Exact basename matches only the executable
    basename; exact path normalizes case and slash direction only.
    """
    return _parse_usage_table(
        srum_path, "app_resource_usage", app_filter, time_range_start, time_range_end,
        limit, app_match_mode,
    )


def parse_srum_network_usage(
    srum_path: str | Path,
    app_filter: str | None = None,
    limit: int = MAX_REGISTRY_RESULTS,
    *,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
    app_match_mode: str = "substring",
    aggregate_by: str = "none",
) -> dict[str, Any]:
    """Read network counters and derived MB/MiB with optional full-match aggregation.

    Aggregation scans all matching rows, independently of the entries limit.
    Missing counters remain null when no group member supplies a value.
    """
    return _parse_usage_table(
        srum_path, "network_data_usage", app_filter, time_range_start, time_range_end,
        limit, app_match_mode, aggregate_by,
    )


def parse_srum(
    srum_path: str | Path,
    table: str = "app_resource_usage",
    app_filter: str | None = None,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
    limit: int = MAX_REGISTRY_RESULTS,
    *,
    app_match_mode: str = "substring",
    aggregate_by: str = "none",
) -> dict[str, Any]:
    """Parse SRUM; table='all' retains the legacy per-table limit of limit // 2."""
    # Validate before table='all' catches per-table I/O errors.
    _validate_filters(app_filter, app_match_mode, time_range_start, time_range_end, limit)
    if aggregate_by not in AGGREGATE_BY:
        raise ValueError(f"aggregate_by must be one of: {', '.join(AGGREGATE_BY)}")
    if aggregate_by != "none" and table == "app_resource_usage":
        raise ValueError("aggregate_by is only supported for network_data_usage or all")
    kwargs = {
        "app_filter": app_filter, "time_range_start": time_range_start,
        "time_range_end": time_range_end, "limit": limit, "app_match_mode": app_match_mode,
    }
    if table == "app_resource_usage":
        return parse_srum_app_resource_usage(srum_path, **kwargs)
    if table == "network_data_usage":
        return parse_srum_network_usage(srum_path, **kwargs, aggregate_by=aggregate_by)
    if table == "all":
        result = {"path": str(srum_path), "tables": {}}
        kwargs["limit"] = limit // 2
        for name, parser in (
            ("app_resource_usage", parse_srum_app_resource_usage),
            ("network_data_usage", parse_srum_network_usage),
        ):
            try:
                options = {"aggregate_by": aggregate_by} if name == "network_data_usage" else {}
                result["tables"][name] = parser(srum_path, **kwargs, **options)
            except Exception as exc:
                result["tables"][name] = {"error": str(exc)}
        return result
    return {
        "error": f"Unknown table: {table}. Available: app_resource_usage, network_data_usage, all"
    }


def get_srum_summary(srum_path: str | Path) -> dict[str, Any]:
    """
    Get summary of SRUM database contents.

    Args:
        srum_path: Path to SRUDB.dat

    Returns:
        Summary of available tables and record counts
    """
    check_pyesedb_available()

    srum_path = Path(srum_path)
    if not srum_path.exists():
        raise FileNotFoundError(f"SRUM database not found: {srum_path}")

    db = pyesedb.file()
    db.open(str(srum_path))

    try:
        summary = {
            "path": str(srum_path),
            "total_tables": db.number_of_tables,
            "tables": [],
        }

        # Map GUIDs to friendly names
        guid_names = {v: k for k, v in SRUM_TABLES.items()}

        for i in range(db.number_of_tables):
            table = db.get_table(i)

            table_info = {
                "name": table.name,
                "friendly_name": guid_names.get(table.name),
                "records": table.number_of_records,
                "columns": table.number_of_columns,
            }

            # Only include non-system tables with records
            if not table.name.startswith("MSys") and table.number_of_records > 0:
                summary["tables"].append(table_info)

        return summary

    finally:
        db.close()
