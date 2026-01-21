"""
ShellBags Parser Module

Parses Windows ShellBags from UsrClass.dat to extract folder navigation history.
ShellBags reveal which folders a user has browsed in Windows Explorer.
"""
from __future__ import annotations

import struct
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


# Known root folder GUIDs
KNOWN_GUIDS = {
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "My Computer",
    "{450D8FBA-AD25-11D0-98A8-0800361B1103}": "My Documents",
    "{59031A47-3F72-44A7-89C5-5595FE6B30EE}": "User Profile",
    "{031E4825-7B94-4DC3-B131-E946B44C8DD5}": "Libraries",
    "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}": "Music",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "Pictures",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "Videos",
    "{208D2C60-3AEA-1069-A2D7-08002B30309D}": "Network",
    "{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
    "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Local Folder",
    "{679F85CB-0220-4080-B29B-5540CC05AAB6}": "Quick Access",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{D3162B92-9365-467A-956B-92703ACA08AF}": "Documents",
    "{088E3905-0323-4B02-9826-5D99428E115F}": "Downloads",
    "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}": "Pictures",
    "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}": "Pictures",
    "{A0953C92-50DC-43BF-BE83-3742FED03C9C}": "Videos",
    "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}": "Videos",
}


def _parse_guid(data: bytes) -> Optional[str]:
    """Parse a 16-byte GUID from binary data"""
    if len(data) < 16:
        return None
    d1, d2, d3 = struct.unpack("<IHH", data[:8])
    d4 = data[8:16]
    guid = "{%08X-%04X-%04X-%s-%s}" % (
        d1, d2, d3,
        d4[:2].hex().upper(),
        d4[2:].hex().upper()
    )
    return guid


def _parse_dos_datetime(date_val: int, time_val: int) -> Optional[datetime]:
    """Parse DOS date/time values to datetime"""
    try:
        if date_val == 0 and time_val == 0:
            return None
        day = date_val & 0x1F
        month = (date_val >> 5) & 0x0F
        year = ((date_val >> 9) & 0x7F) + 1980
        second = (time_val & 0x1F) * 2
        minute = (time_val >> 5) & 0x3F
        hour = (time_val >> 11) & 0x1F

        if 1 <= month <= 12 and 1 <= day <= 31:
            return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime to ISO string"""
    if dt is None:
        return None
    return dt.isoformat()


def _extract_unicode_string(data: bytes, start: int) -> Optional[str]:
    """Extract a null-terminated Unicode string from data"""
    try:
        for i in range(start, len(data) - 1, 2):
            if data[i:i+2] == b"\x00\x00":
                s = data[start:i].decode("utf-16-le", errors="ignore")
                if s and s.isprintable():
                    return s
                return None
    except Exception:
        pass
    return None


def _find_extension_block_name(data: bytes, after_short_name: int) -> Optional[str]:
    """
    Find the long filename in extension blocks after the short name.

    Extension blocks have format:
    - 2 bytes: size
    - 2 bytes: version
    - 4 bytes: signature (BEEF0004 for file entry extension)
    - Variable: data including long name
    """
    remaining = data[after_short_name:]

    # Look for BEEF0004 signature which marks file entry extension block
    for offset in range(0, len(remaining) - 20):
        # Check for extension block signature
        if remaining[offset:offset+4] == b"\x04\x00\xef\xbe":
            # This is a file entry extension block
            # Long name is Unicode string at variable offset
            # Skip the header and look for Unicode string
            ext_data = remaining[offset+8:]

            # The long name often appears after some fixed fields
            # Try to find it by looking for printable Unicode sequences
            for name_offset in [0, 4, 8, 12, 16, 20, 24]:
                if name_offset < len(ext_data):
                    name = _extract_unicode_string(ext_data, name_offset)
                    if name and len(name) > 1 and name[0].isalnum():
                        return name

    return None


def _is_valid_folder_name(name: str) -> bool:
    """Check if string looks like a valid folder/file name"""
    if not name or len(name) < 1:
        return False
    # Must start with alphanumeric or common special chars
    if not (name[0].isalnum() or name[0] in "._-$~"):
        return False
    # Should be mostly printable ASCII
    ascii_count = sum(1 for c in name if ord(c) < 128 and c.isprintable())
    return ascii_count >= len(name) * 0.7


def _parse_shell_item(data: bytes) -> Optional[dict[str, Any]]:
    """Parse a shell item and return folder/file info"""
    if len(data) < 4:
        return None

    size = struct.unpack("<H", data[:2])[0]
    if size < 4 or size > len(data):
        return None

    item_type = data[2]
    result = {
        "size": size,
        "type": hex(item_type),
    }

    # Root folder with GUID (type 0x1F)
    if item_type == 0x1F:
        if size >= 18:
            guid = _parse_guid(data[4:20])
            result["guid"] = guid
            name = KNOWN_GUIDS.get(guid, f"Unknown GUID")
            result["name"] = name
            result["folder_type"] = "root"

    # Drive entry (type 0x2F)
    elif item_type == 0x2F:
        if size >= 4:
            try:
                # Drive letter at offset 3
                drive = data[3:].split(b"\x00")[0].decode("ascii", errors="ignore")
                result["name"] = drive.rstrip("\\")
                result["folder_type"] = "drive"
            except Exception:
                pass

    # Delegate/extension item (type 0x2E) - often contains GUIDs
    elif item_type == 0x2E:
        if size >= 18:
            guid = _parse_guid(data[4:20])
            result["guid"] = guid
            name = KNOWN_GUIDS.get(guid, None)
            if name:
                result["name"] = name
            result["folder_type"] = "delegate"

    # File/folder entry (type 0x31, 0x32, 0x35, etc.)
    elif (item_type & 0xF0) == 0x30:
        result["folder_type"] = "folder" if (item_type & 0x01) else "file"

        if size >= 14:
            # Parse DOS timestamp
            try:
                mod_date, mod_time = struct.unpack("<HH", data[8:12])
                mod_dt = _parse_dos_datetime(mod_date, mod_time)
                if mod_dt:
                    result["modified_time"] = _format_datetime(mod_dt)
            except Exception:
                pass

            # Short name at offset 14
            name_offset = 14
            try:
                name_end = data.index(b"\x00", name_offset)
                short_name = data[name_offset:name_end].decode("ascii", errors="ignore")
                result["short_name"] = short_name

                # Look for long name in extension block
                long_name = _find_extension_block_name(data, name_end + 1)

                if long_name and _is_valid_folder_name(long_name):
                    result["name"] = long_name
                else:
                    # Fall back to short name
                    result["name"] = short_name
            except Exception:
                pass

    # Network location (type 0x40-0x4F)
    elif (item_type & 0xF0) == 0x40 or item_type == 0xC3:
        result["folder_type"] = "network"
        try:
            # Network path usually at variable offset
            for offset in [3, 5, 7]:
                if offset < size:
                    path = data[offset:].split(b"\x00")[0].decode("ascii", errors="ignore")
                    if path.startswith("\\\\"):
                        result["name"] = path
                        break
        except Exception:
            pass

    # ZIP folder (type 0x52)
    elif item_type == 0x52:
        result["folder_type"] = "zip"
        if size >= 14:
            try:
                name_offset = 14
                name_end = data.index(b"\x00", name_offset)
                short_name = data[name_offset:name_end].decode("ascii", errors="ignore")
                result["name"] = short_name
            except Exception:
                pass

    return result


def _traverse_bagmru(
    key,
    parent_path: str,
    results: list,
    bag_timestamps: dict,
    path_filter: Optional[str],
    limit: int,
) -> None:
    """Recursively traverse BagMRU to build folder paths"""
    if len(results) >= limit:
        return

    # Get current folder's shell item data
    for val in key.values():
        if not val.name().isdigit():
            continue

        raw = val.raw_data()
        item = _parse_shell_item(raw)

        if not item or "name" not in item:
            continue

        name = item["name"]

        # Build full path
        if parent_path:
            if parent_path.endswith("\\") or name.startswith("\\"):
                full_path = parent_path + name
            elif ":" in parent_path and not parent_path.endswith("\\"):
                full_path = parent_path + "\\" + name
            else:
                full_path = parent_path + "\\" + name
        else:
            full_path = name

        # Get bag info (timestamps) if available
        entry = {
            "path": full_path,
            "folder_type": item.get("folder_type"),
            "short_name": item.get("short_name"),
            "modified_time": item.get("modified_time"),
        }

        # Look up bag timestamp for this slot
        try:
            slot_key = key.subkey(val.name())
            node_slot = slot_key.value("NodeSlot").value()
            if node_slot in bag_timestamps:
                entry["last_viewed"] = bag_timestamps[node_slot]
        except Exception:
            pass

        # Apply filter
        if path_filter:
            if path_filter.lower() not in full_path.lower():
                pass  # Don't add to results, but continue traversing
            else:
                results.append(entry)
        else:
            results.append(entry)

        if len(results) >= limit:
            return

        # Recurse into subkey
        try:
            subkey = key.subkey(val.name())
            _traverse_bagmru(subkey, full_path, results, bag_timestamps, path_filter, limit)
        except Exception:
            pass


def _get_bag_timestamps(reg) -> dict[int, str]:
    """Get last view timestamps from Bags keys"""
    timestamps = {}

    try:
        bags = reg.open("Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags")

        for bag_key in bags.subkeys():
            try:
                bag_num = int(bag_key.name())
                # The bag key's last write time indicates when folder was last viewed
                last_write = bag_key.timestamp()
                if last_write:
                    timestamps[bag_num] = last_write.isoformat()
            except (ValueError, Exception):
                pass
    except Exception:
        pass

    return timestamps


def parse_shellbags(
    usrclass_path: str | Path,
    path_filter: Optional[str] = None,
    include_timestamps: bool = True,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse ShellBags from UsrClass.dat to reveal folder navigation history.

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        path_filter: Filter results by path substring (case-insensitive)
        include_timestamps: Include last viewed timestamps from Bags
        limit: Maximum number of results

    Returns:
        Dictionary with list of visited folders
    """
    check_registry_available()

    usrclass_path = Path(usrclass_path)
    if not usrclass_path.exists():
        raise FileNotFoundError(f"UsrClass.dat not found: {usrclass_path}")

    try:
        reg = Registry.Registry(str(usrclass_path))
    except Exception as e:
        raise ValueError(f"Failed to open registry hive: {e}")

    # Get bag timestamps if requested
    bag_timestamps = {}
    if include_timestamps:
        bag_timestamps = _get_bag_timestamps(reg)

    # Find BagMRU key
    try:
        bagmru = reg.open("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
    except Exception:
        return {
            "usrclass_path": str(usrclass_path),
            "error": "BagMRU key not found - no ShellBag data available",
            "folders": [],
        }

    results = []

    # Traverse BagMRU tree
    _traverse_bagmru(bagmru, "", results, bag_timestamps, path_filter, limit)

    # Sort by last viewed (most recent first) if timestamps available
    results_with_timestamps = [r for r in results if r.get("last_viewed")]
    results_without_timestamps = [r for r in results if not r.get("last_viewed")]

    results_with_timestamps.sort(key=lambda x: x["last_viewed"], reverse=True)

    sorted_results = results_with_timestamps + results_without_timestamps

    return {
        "usrclass_path": str(usrclass_path),
        "total_folders": len(sorted_results),
        "folders": sorted_results,
    }


def search_shellbags(
    usrclass_path: str | Path,
    search_term: str,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Search ShellBags for folders matching a search term.

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        search_term: Search term (case-insensitive substring match)
        limit: Maximum number of results

    Returns:
        Matching folders
    """
    return parse_shellbags(
        usrclass_path,
        path_filter=search_term,
        include_timestamps=True,
        limit=limit,
    )


def get_recently_viewed_folders(
    usrclass_path: str | Path,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Get recently viewed folders from ShellBags.

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        limit: Maximum number of results

    Returns:
        Recently viewed folders sorted by last access time
    """
    result = parse_shellbags(usrclass_path, include_timestamps=True, limit=limit * 2)

    # Filter to only include folders with timestamps
    folders_with_timestamps = [
        f for f in result.get("folders", [])
        if f.get("last_viewed")
    ][:limit]

    return {
        "usrclass_path": str(usrclass_path),
        "total_folders": len(folders_with_timestamps),
        "recently_viewed": folders_with_timestamps,
    }


def find_suspicious_folders(
    usrclass_path: str | Path,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Find potentially suspicious folder access patterns.

    Looks for:
    - Temp folders
    - AppData folders
    - System folders (Windows, System32)
    - Network shares
    - Removable drives
    - Known tool/malware paths

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        limit: Maximum number of results

    Returns:
        Suspicious folder accesses
    """
    suspicious_patterns = [
        "\\temp",
        "\\tmp",
        "appdata\\local\\temp",
        "appdata\\roaming",
        "\\system32",
        "\\syswow64",
        "\\programdata",
        "\\$recycle.bin",
        "\\tools",
        "\\hack",
        "mimikatz",
        "bloodhound",
        "sharphound",
        "rubeus",
        "cobalt",
        "empire",
        "metasploit",
        "\\public\\",
        "c:\\users\\public",
    ]

    result = parse_shellbags(usrclass_path, include_timestamps=True, limit=limit * 10)

    suspicious = []
    for folder in result.get("folders", []):
        path_lower = folder["path"].lower()

        # Check for network paths
        if path_lower.startswith("\\\\"):
            folder["reason"] = "Network share access"
            suspicious.append(folder)
            continue

        # Check for removable drives (D:, E:, etc. but not C:)
        if len(path_lower) >= 2 and path_lower[1] == ":" and path_lower[0] not in "c":
            if path_lower[0] in "defghijklmnopqrstuvwxyz":
                folder["reason"] = f"Removable/secondary drive access"
                suspicious.append(folder)
                continue

        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern in path_lower:
                folder["reason"] = f"Suspicious path pattern: {pattern}"
                suspicious.append(folder)
                break

        if len(suspicious) >= limit:
            break

    return {
        "usrclass_path": str(usrclass_path),
        "total_suspicious": len(suspicious),
        "suspicious_folders": suspicious[:limit],
    }
