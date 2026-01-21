from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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


def _ole_timestamp_to_datetime(ole_bytes: bytes) -> Optional[datetime]:
    """Convert OLE/Variant timestamp (8 bytes, float64) to datetime"""
    if not ole_bytes or len(ole_bytes) != 8:
        return None
    try:
        ole_time = struct.unpack('<d', ole_bytes)[0]
        if ole_time == 0 or ole_time < 0:
            return None
        # OLE timestamp: days since Dec 30, 1899
        unix_ts = (ole_time - 25569) * 86400
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (struct.error, ValueError, OSError, OverflowError):
        return None


def _filetime_to_datetime(filetime_bytes: bytes) -> Optional[datetime]:
    """Convert Windows FILETIME (8 bytes) to datetime"""
    if not filetime_bytes or len(filetime_bytes) != 8:
        return None
    try:
        filetime = struct.unpack('<Q', filetime_bytes)[0]
        if filetime == 0:
            return None
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        unix_ts = (filetime - EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (struct.error, ValueError, OSError, OverflowError):
        return None


def _get_int_value(data: bytes, size: int = 4) -> Optional[int]:
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
    """Get typed value from ESE record"""
    data = record.get_value_data(column_index)
    if data is None:
        return None

    # ESE column types
    # 4 = Long (4 bytes)
    # 8 = DateTime (8 bytes, OLE)
    # 11 = LongBinary
    # 14 = GUID
    # 15 = UnsignedLongLong (8 bytes)
    # 2 = Short

    if column_type == 4:  # Long integer
        return _get_int_value(data, 4)
    elif column_type == 15:  # Unsigned long long
        return _get_int_value(data, 8)
    elif column_type == 8:  # DateTime (OLE)
        dt = _ole_timestamp_to_datetime(data)
        return dt.isoformat() if dt else None
    elif column_type == 2:  # Short
        return _get_int_value(data, 2)
    elif column_type == 11:  # Binary
        return data.hex() if len(data) <= 32 else f"{data[:16].hex()}..."
    else:
        return data.hex() if isinstance(data, bytes) else data


def _build_id_map(db) -> dict[int, dict[str, Any]]:
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
                        "type": "app" if id_type == 0 else "user" if id_type == 3 else f"type_{id_type}",
                        "name": name,
                    }
                break
    except Exception:
        pass

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


def parse_srum_app_resource_usage(
    srum_path: str | Path,
    app_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse SRUM Application Resource Usage table.

    Returns CPU cycles, foreground time, bytes read/written per application.

    Args:
        srum_path: Path to SRUDB.dat
        app_filter: Filter by application name (case-insensitive substring)
        time_range_start: ISO datetime, filter after this time
        time_range_end: ISO datetime, filter before this time
        limit: Maximum results

    Returns:
        Dictionary with application resource usage entries
    """
    check_pyesedb_available()

    srum_path = Path(srum_path)
    if not srum_path.exists():
        raise FileNotFoundError(f"SRUM database not found: {srum_path}")

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    app_filter_lower = app_filter.lower() if app_filter else None

    db = pyesedb.file()
    db.open(str(srum_path))

    try:
        # Build ID map
        id_map = _build_id_map(db)

        # Find app resource usage table
        table = _find_table_by_guid(db, SRUM_TABLES["app_resource_usage"])
        if not table:
            return {"error": "Application Resource Usage table not found", "entries": []}

        # Build column map
        columns = {}
        for i in range(table.number_of_columns):
            col = table.get_column(i)
            columns[col.name] = (i, col.type)

        entries = []
        for i in range(table.number_of_records):
            if len(entries) >= limit:
                break

            try:
                record = table.get_record(i)

                entry = {
                    "timestamp": None,
                    "app_id": None,
                    "app_name": None,
                    "executable": None,
                    "user_id": None,
                    "foreground_cycle_time": None,
                    "background_cycle_time": None,
                    "face_time": None,
                    "foreground_bytes_read": None,
                    "foreground_bytes_written": None,
                    "background_bytes_read": None,
                    "background_bytes_written": None,
                }

                # Extract values
                if "TimeStamp" in columns:
                    idx, ctype = columns["TimeStamp"]
                    entry["timestamp"] = _get_record_value(record, idx, ctype)

                if "AppId" in columns:
                    idx, ctype = columns["AppId"]
                    app_id = _get_record_value(record, idx, ctype)
                    entry["app_id"] = app_id
                    if app_id and app_id in id_map:
                        app_info = id_map[app_id]
                        entry["app_name"] = app_info.get("name")
                        parsed = _parse_app_name(app_info.get("name"))
                        entry["executable"] = parsed.get("executable")

                if "UserId" in columns:
                    idx, ctype = columns["UserId"]
                    user_id = _get_record_value(record, idx, ctype)
                    entry["user_id"] = user_id

                # Cycle times (in 100-nanosecond intervals)
                if "ForegroundCycleTime" in columns:
                    idx, ctype = columns["ForegroundCycleTime"]
                    entry["foreground_cycle_time"] = _get_record_value(record, idx, ctype)

                if "BackgroundCycleTime" in columns:
                    idx, ctype = columns["BackgroundCycleTime"]
                    entry["background_cycle_time"] = _get_record_value(record, idx, ctype)

                if "FaceTime" in columns:
                    idx, ctype = columns["FaceTime"]
                    entry["face_time"] = _get_record_value(record, idx, ctype)

                # Bytes read/written
                if "ForegroundBytesRead" in columns:
                    idx, ctype = columns["ForegroundBytesRead"]
                    entry["foreground_bytes_read"] = _get_record_value(record, idx, ctype)

                if "ForegroundBytesWritten" in columns:
                    idx, ctype = columns["ForegroundBytesWritten"]
                    entry["foreground_bytes_written"] = _get_record_value(record, idx, ctype)

                if "BackgroundBytesRead" in columns:
                    idx, ctype = columns["BackgroundBytesRead"]
                    entry["background_bytes_read"] = _get_record_value(record, idx, ctype)

                if "BackgroundBytesWritten" in columns:
                    idx, ctype = columns["BackgroundBytesWritten"]
                    entry["background_bytes_written"] = _get_record_value(record, idx, ctype)

                # Apply filters
                if app_filter_lower:
                    app_name = (entry.get("app_name") or "").lower()
                    exe_name = (entry.get("executable") or "").lower()
                    if app_filter_lower not in app_name and app_filter_lower not in exe_name:
                        continue

                if start_dt or end_dt:
                    ts = entry.get("timestamp")
                    if ts:
                        try:
                            entry_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            if start_dt and entry_dt < start_dt:
                                continue
                            if end_dt and entry_dt > end_dt:
                                continue
                        except ValueError:
                            pass

                entries.append(entry)

            except Exception:
                continue

        # Sort by timestamp (most recent first)
        entries.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        return {
            "path": str(srum_path),
            "table": "Application Resource Usage",
            "total_records": table.number_of_records,
            "returned_entries": len(entries),
            "entries": entries,
        }

    finally:
        db.close()


def parse_srum_network_usage(
    srum_path: str | Path,
    app_filter: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse SRUM Network Data Usage table.

    Returns bytes sent/received per application.

    Args:
        srum_path: Path to SRUDB.dat
        app_filter: Filter by application name
        limit: Maximum results

    Returns:
        Dictionary with network usage entries
    """
    check_pyesedb_available()

    srum_path = Path(srum_path)
    if not srum_path.exists():
        raise FileNotFoundError(f"SRUM database not found: {srum_path}")

    app_filter_lower = app_filter.lower() if app_filter else None

    db = pyesedb.file()
    db.open(str(srum_path))

    try:
        id_map = _build_id_map(db)

        table = _find_table_by_guid(db, SRUM_TABLES["network_data_usage"])
        if not table:
            return {"error": "Network Data Usage table not found", "entries": []}

        columns = {}
        for i in range(table.number_of_columns):
            col = table.get_column(i)
            columns[col.name] = (i, col.type)

        entries = []
        for i in range(table.number_of_records):
            if len(entries) >= limit:
                break

            try:
                record = table.get_record(i)

                entry = {
                    "timestamp": None,
                    "app_id": None,
                    "app_name": None,
                    "executable": None,
                    "bytes_sent": None,
                    "bytes_received": None,
                    "interface_luid": None,
                }

                if "TimeStamp" in columns:
                    idx, ctype = columns["TimeStamp"]
                    entry["timestamp"] = _get_record_value(record, idx, ctype)

                if "AppId" in columns:
                    idx, ctype = columns["AppId"]
                    app_id = _get_record_value(record, idx, ctype)
                    entry["app_id"] = app_id
                    if app_id and app_id in id_map:
                        app_info = id_map[app_id]
                        entry["app_name"] = app_info.get("name")
                        parsed = _parse_app_name(app_info.get("name"))
                        entry["executable"] = parsed.get("executable")

                if "BytesSent" in columns:
                    idx, ctype = columns["BytesSent"]
                    entry["bytes_sent"] = _get_record_value(record, idx, ctype)

                if "BytesRecvd" in columns:
                    idx, ctype = columns["BytesRecvd"]
                    entry["bytes_received"] = _get_record_value(record, idx, ctype)

                if "InterfaceLuid" in columns:
                    idx, ctype = columns["InterfaceLuid"]
                    entry["interface_luid"] = _get_record_value(record, idx, ctype)

                # Apply filter
                if app_filter_lower:
                    app_name = (entry.get("app_name") or "").lower()
                    exe_name = (entry.get("executable") or "").lower()
                    if app_filter_lower not in app_name and app_filter_lower not in exe_name:
                        continue

                entries.append(entry)

            except Exception:
                continue

        entries.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        return {
            "path": str(srum_path),
            "table": "Network Data Usage",
            "total_records": table.number_of_records,
            "returned_entries": len(entries),
            "entries": entries,
        }

    finally:
        db.close()


def parse_srum(
    srum_path: str | Path,
    table: str = "app_resource_usage",
    app_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse SRUM database.

    Args:
        srum_path: Path to SRUDB.dat
        table: Table to parse - "app_resource_usage", "network_data_usage", "network_connectivity", "all"
        app_filter: Filter by application name
        time_range_start: ISO datetime filter
        time_range_end: ISO datetime filter
        limit: Maximum results

    Returns:
        Dictionary with SRUM entries
    """
    if table == "app_resource_usage":
        return parse_srum_app_resource_usage(
            srum_path, app_filter, time_range_start, time_range_end, limit
        )
    elif table == "network_data_usage":
        return parse_srum_network_usage(srum_path, app_filter, limit)
    elif table == "all":
        result = {
            "path": str(srum_path),
            "tables": {},
        }

        # Get app resource usage
        try:
            app_result = parse_srum_app_resource_usage(
                srum_path, app_filter, time_range_start, time_range_end, limit // 2
            )
            result["tables"]["app_resource_usage"] = app_result
        except Exception as e:
            result["tables"]["app_resource_usage"] = {"error": str(e)}

        # Get network usage
        try:
            net_result = parse_srum_network_usage(srum_path, app_filter, limit // 2)
            result["tables"]["network_data_usage"] = net_result
        except Exception as e:
            result["tables"]["network_data_usage"] = {"error": str(e)}

        return result
    else:
        return {"error": f"Unknown table: {table}. Available: app_resource_usage, network_data_usage, all"}


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
