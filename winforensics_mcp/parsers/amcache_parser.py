from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS


def check_registry_available() -> None:
    """Raise error if python-registry library not available"""
    if not REGISTRY_AVAILABLE:
        raise ImportError(
            "python-registry library not installed. Install with: pip install python-registry"
        )


def _extract_sha1_from_file_id(file_id: str) -> Optional[str]:
    """
    Extract SHA1 hash from Amcache FileId.

    FileId format: 0000 (4 hex chars prefix) + SHA1 (40 hex chars)
    Example: 0000fdd94dae151e87b68df9feb47ed9ba266c6c99be (44 chars total)
    """
    if not file_id or len(file_id) < 44:
        return None

    # Skip first 4 hex chars (2 bytes of zeros prefix)
    # SHA1 is the remaining 40 hex chars
    sha1 = file_id[4:44] if file_id.startswith("0000") else file_id[:40]

    # Validate it looks like a SHA1
    if len(sha1) == 40 and all(c in "0123456789abcdef" for c in sha1.lower()):
        return sha1.lower()

    return None


def _parse_link_date(link_date_str: str) -> Optional[str]:
    """Parse LinkDate string to ISO format"""
    if not link_date_str:
        return None

    # Format: "MM/DD/YYYY HH:MM:SS"
    try:
        dt = datetime.strptime(link_date_str, "%m/%d/%Y %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return link_date_str


def _get_value_safe(key, value_name: str, default=None):
    """Safely get a registry value"""
    try:
        for value in key.values():
            if value.name() == value_name:
                return value.value()
    except Exception:
        pass
    return default


def parse_amcache_entry(entry_key) -> dict[str, Any]:
    """Parse a single Amcache InventoryApplicationFile entry"""
    result = {
        "name": _get_value_safe(entry_key, "Name"),
        "path": _get_value_safe(entry_key, "LowerCaseLongPath"),
        "sha1": None,
        "file_id": _get_value_safe(entry_key, "FileId"),
        "program_id": _get_value_safe(entry_key, "ProgramId"),
        "publisher": _get_value_safe(entry_key, "Publisher"),
        "version": _get_value_safe(entry_key, "Version"),
        "bin_file_version": _get_value_safe(entry_key, "BinFileVersion"),
        "binary_type": _get_value_safe(entry_key, "BinaryType"),
        "product_name": _get_value_safe(entry_key, "ProductName"),
        "product_version": _get_value_safe(entry_key, "ProductVersion"),
        "original_filename": _get_value_safe(entry_key, "OriginalFileName"),
        "link_date": None,
        "size": _get_value_safe(entry_key, "Size"),
        "language": _get_value_safe(entry_key, "Language"),
        "usn": _get_value_safe(entry_key, "Usn"),
        "key_timestamp": None,
    }

    # Extract SHA1 from FileId
    if result["file_id"]:
        result["sha1"] = _extract_sha1_from_file_id(result["file_id"])

    # Parse link date
    link_date_raw = _get_value_safe(entry_key, "LinkDate")
    if link_date_raw:
        result["link_date"] = _parse_link_date(link_date_raw)

    # Key timestamp (first seen in Amcache)
    try:
        ts = entry_key.timestamp()
        if ts:
            result["key_timestamp"] = ts.isoformat()
    except Exception:
        pass

    return result


def parse_amcache(
    amcache_path: str | Path,
    sha1_filter: Optional[str] = None,
    path_filter: Optional[str] = None,
    name_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse Amcache.hve to extract program execution evidence with SHA1 hashes.

    Args:
        amcache_path: Path to Amcache.hve file
        sha1_filter: Filter by SHA1 hash (case-insensitive)
        path_filter: Filter by file path (case-insensitive substring)
        name_filter: Filter by file name (case-insensitive substring)
        time_range_start: ISO format datetime, filter entries after this time
        time_range_end: ISO format datetime, filter entries before this time
        limit: Maximum number of results

    Returns:
        Dictionary with parsed Amcache entries
    """
    check_registry_available()

    amcache_path = Path(amcache_path)
    if not amcache_path.exists():
        raise FileNotFoundError(f"Amcache file not found: {amcache_path}")

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    # Normalize filters
    sha1_filter = sha1_filter.lower() if sha1_filter else None
    path_filter = path_filter.lower() if path_filter else None
    name_filter = name_filter.lower() if name_filter else None

    reg = Registry.Registry(str(amcache_path))
    root = reg.root()

    # Find the InventoryApplicationFile key
    # Structure: {GUID}\Root\InventoryApplicationFile
    inv_app_file_key = None
    for sk1 in root.subkeys():
        if sk1.name() == "Root":
            for sk2 in sk1.subkeys():
                if sk2.name() == "InventoryApplicationFile":
                    inv_app_file_key = sk2
                    break
        break

    if not inv_app_file_key:
        # Try older format: Root\File\{Volume GUID}
        for sk1 in root.subkeys():
            if sk1.name() == "Root":
                for sk2 in sk1.subkeys():
                    if sk2.name() == "File":
                        # Handle older Amcache format
                        return _parse_amcache_legacy(sk2, sha1_filter, path_filter, name_filter, start_dt, end_dt, limit)

        return {
            "path": str(amcache_path),
            "error": "Could not find InventoryApplicationFile or File key in Amcache",
            "entries": [],
        }

    entries = []
    total_scanned = 0

    for entry_key in inv_app_file_key.subkeys():
        total_scanned += 1

        try:
            entry = parse_amcache_entry(entry_key)

            # Apply filters
            if sha1_filter and entry.get("sha1"):
                if sha1_filter not in entry["sha1"].lower():
                    continue

            if path_filter and entry.get("path"):
                if path_filter not in entry["path"].lower():
                    continue

            if name_filter and entry.get("name"):
                if name_filter not in entry["name"].lower():
                    continue

            # Time filter
            if start_dt or end_dt:
                key_ts = entry.get("key_timestamp")
                if key_ts:
                    try:
                        entry_dt = datetime.fromisoformat(key_ts.replace("Z", "+00:00"))
                        if start_dt and entry_dt < start_dt:
                            continue
                        if end_dt and entry_dt > end_dt:
                            continue
                    except ValueError:
                        pass

            entries.append(entry)

            if len(entries) >= limit:
                break

        except Exception:
            continue

    # Sort by timestamp (most recent first)
    entries.sort(key=lambda x: x.get("key_timestamp") or "", reverse=True)

    return {
        "path": str(amcache_path),
        "total_entries": total_scanned,
        "returned_entries": len(entries),
        "entries": entries,
    }


def _parse_amcache_legacy(
    file_key,
    sha1_filter: Optional[str],
    path_filter: Optional[str],
    name_filter: Optional[str],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    limit: int,
) -> dict[str, Any]:
    """Parse older Amcache format (Windows 8.1/early Win10)"""
    entries = []
    total_scanned = 0

    # Older format: Root\File\{Volume GUID}\{Entry}
    for volume_key in file_key.subkeys():
        for entry_key in volume_key.subkeys():
            total_scanned += 1

            try:
                entry = {
                    "name": None,
                    "path": None,
                    "sha1": None,
                    "key_timestamp": None,
                }

                # In legacy format, entry name often contains the path
                entry["path"] = _get_value_safe(entry_key, "15")  # FullPath
                entry["name"] = _get_value_safe(entry_key, "0")   # ProductName

                # SHA1 in legacy format
                sha1_raw = _get_value_safe(entry_key, "101")
                if sha1_raw:
                    if isinstance(sha1_raw, str) and len(sha1_raw) >= 40:
                        entry["sha1"] = sha1_raw[:40].lower()

                # Key timestamp
                try:
                    ts = entry_key.timestamp()
                    if ts:
                        entry["key_timestamp"] = ts.isoformat()
                except Exception:
                    pass

                # Apply filters
                if sha1_filter and entry.get("sha1"):
                    if sha1_filter not in entry["sha1"].lower():
                        continue

                if path_filter and entry.get("path"):
                    if path_filter not in str(entry["path"]).lower():
                        continue

                if name_filter and entry.get("name"):
                    if name_filter not in str(entry["name"]).lower():
                        continue

                entries.append(entry)

                if len(entries) >= limit:
                    break

            except Exception:
                continue

        if len(entries) >= limit:
            break

    return {
        "format": "legacy",
        "total_entries": total_scanned,
        "returned_entries": len(entries),
        "entries": entries,
    }


def search_amcache_by_sha1(
    amcache_path: str | Path,
    sha1_hash: str,
) -> dict[str, Any]:
    """
    Search Amcache for a specific SHA1 hash.

    Args:
        amcache_path: Path to Amcache.hve
        sha1_hash: SHA1 hash to search for

    Returns:
        Search results with matching entries
    """
    sha1_hash = sha1_hash.lower().strip()

    result = parse_amcache(
        amcache_path,
        sha1_filter=sha1_hash,
        limit=50,
    )

    # Check for exact matches
    exact_matches = [
        e for e in result.get("entries", [])
        if e.get("sha1") == sha1_hash
    ]

    return {
        "searched_sha1": sha1_hash,
        "found": len(exact_matches) > 0,
        "matches": exact_matches,
        "partial_matches": [
            e for e in result.get("entries", [])
            if e.get("sha1") != sha1_hash
        ],
    }


def get_amcache_executables(
    amcache_path: str | Path,
    suspicious_only: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Get list of executables from Amcache.

    Args:
        amcache_path: Path to Amcache.hve
        suspicious_only: Only return entries from unusual paths
        limit: Maximum results

    Returns:
        List of executables with metadata
    """
    result = parse_amcache(amcache_path, limit=limit * 2 if suspicious_only else limit)

    entries = result.get("entries", [])

    if suspicious_only:
        # Filter for executables from unusual locations
        suspicious_paths = [
            "\\users\\",
            "\\temp\\",
            "\\appdata\\local\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\public\\",
            "programdata\\",
        ]

        system_paths = [
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\windows\\winsxs\\",
        ]

        filtered = []
        for entry in entries:
            path = (entry.get("path") or "").lower()

            # Skip common system paths
            if any(sp in path for sp in system_paths):
                continue

            # Include if in suspicious path or not in any known path
            if any(sp in path for sp in suspicious_paths):
                entry["suspicious_reason"] = "Unusual execution path"
                filtered.append(entry)
            elif path and not any(sp in path for sp in system_paths):
                entry["suspicious_reason"] = "Non-standard path"
                filtered.append(entry)

            if len(filtered) >= limit:
                break

        entries = filtered

    return {
        "path": str(amcache_path),
        "total_entries": result.get("total_entries", 0),
        "returned_entries": len(entries),
        "executables": entries[:limit],
    }
