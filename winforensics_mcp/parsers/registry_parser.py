from __future__ import annotations

import re
import struct
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# QWORDs with these documented meanings are timestamps, unlike arbitrary counters.
FILETIME_VALUE_NAMES = frozenset({
    "lastusedtimestart", "lastusedtimestop", "lastarrivaldate", "lastremovaldate",
    "installdate", "firstinstalldate", "lastarrivaltime", "lastremovaltime",
    "installtime", "firstinstalltime", "devpkey_device_lastarrivaldate",
    "devpkey_device_lastremovaldate", "devpkey_device_installdate",
    "devpkey_device_firstinstalldate",
})
REGISTRY_QUERY_FIELDS = (
    "name", "type", "data", "data_raw", "data_utc", "key_path",
)


def check_registry_available() -> None:
    """Raise error if python-registry library not available"""
    if not REGISTRY_AVAILABLE:
        raise ImportError(
            "python-registry library not installed. Install with: pip install python-registry"
        )


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to datetime"""
    if filetime <= 0:
        return None
    try:
        # Integer arithmetic avoids loss of precision from a float Unix timestamp.
        return FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (ValueError, OverflowError):
        return None


def filetime_to_utc(filetime: int) -> str | None:
    """Render FILETIME in UTC, retaining its full 100-nanosecond precision."""
    timestamp = filetime_to_datetime(filetime)
    if timestamp is None:
        return None
    whole_seconds = timestamp.replace(microsecond=0).isoformat().removesuffix("+00:00")
    return f"{whole_seconds}.{filetime % 10_000_000:07d}+00:00"


def parse_registry_key(key, max_depth: int = 10, current_depth: int = 0) -> dict[str, Any]:
    """
    Parse a registry key and its values.
    
    Args:
        key: Registry key object
        max_depth: Maximum recursion depth for subkeys
        current_depth: Current recursion depth
        
    Returns:
        Dictionary with key information
    """
    result = {
        "name": key.name(),
        "path": key.path(),
        "timestamp": None,
        "values": [],
        "subkeys": [],
    }
    
    # Get key timestamp
    try:
        timestamp = key.timestamp()
        if timestamp:
            result["timestamp"] = timestamp.isoformat()
    except Exception:
        pass
    
    # Get values
    try:
        for value in key.values():
            value_data = parse_registry_value(value)
            result["values"].append(value_data)
    except Exception:
        pass
    
    # Get subkeys (with depth limit)
    if current_depth < max_depth:
        try:
            for subkey in key.subkeys():
                subkey_data = parse_registry_key(subkey, max_depth, current_depth + 1)
                result["subkeys"].append(subkey_data)
        except Exception:
            pass
    
    return result


def parse_registry_value(value) -> dict[str, Any]:
    """
    Parse a registry value.
    
    Args:
        value: Registry value object
        
    Returns:
        Dictionary with value information
    """
    result = {
        "name": value.name(),
        "type": str(value.value_type()),
        "data": None,
        "data_raw": None,
    }
    
    try:
        data = value.value()
        
        # Handle different value types
        if isinstance(data, bytes):
            # Try to decode as string, otherwise hex encode
            try:
                result["data"] = data.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                try:
                    result["data"] = data.decode("utf-8").rstrip("\x00")
                except UnicodeDecodeError:
                    result["data"] = data.hex()
                    result["data_raw"] = True
        elif isinstance(data, int):
            result["data"] = data
            if value.value_type() == 11 and value.name().casefold() in FILETIME_VALUE_NAMES:
                result["data_utc"] = filetime_to_utc(data)
        elif isinstance(data, list):
            # Multi-string values
            result["data"] = [s.rstrip("\x00") if isinstance(s, str) else s for s in data]
        else:
            result["data"] = str(data)
            
    except Exception as e:
        result["data"] = f"<Error reading value: {e}>"
    
    return result


def open_registry_hive(hive_path: str | Path) -> Any:
    """
    Open a registry hive file.
    
    Args:
        hive_path: Path to the registry hive file
        
    Returns:
        Registry object
    """
    check_registry_available()
    
    hive_path = Path(hive_path)
    if not hive_path.exists():
        raise FileNotFoundError(f"Registry hive not found: {hive_path}")
    
    return Registry.Registry(str(hive_path))


def get_registry_key(
    hive_path: str | Path,
    key_path: str,
    max_depth: int = 3,
) -> dict[str, Any]:
    """
    Get a specific registry key and its contents.
    
    Args:
        hive_path: Path to the registry hive file
        key_path: Path to the key within the hive (e.g., "SOFTWARE\\Microsoft\\Windows")
        max_depth: Maximum depth for subkey enumeration
        
    Returns:
        Dictionary with key information
    """
    reg = open_registry_hive(hive_path)
    
    try:
        # Navigate to the key
        key = reg.open(key_path)
        return parse_registry_key(key, max_depth=max_depth)
    except Registry.RegistryKeyNotFoundException:
        raise KeyError(f"Registry key not found: {key_path}")


def search_registry_values(
    hive_path: str | Path,
    pattern: str,
    search_names: bool = True,
    search_data: bool = True,
    case_sensitive: bool = False,
    limit: int = MAX_REGISTRY_RESULTS,
) -> list[dict[str, Any]]:
    """
    Search for registry values matching a pattern.
    
    Args:
        hive_path: Path to the registry hive file
        pattern: Search pattern (substring match)
        search_names: Search in value names
        search_data: Search in value data
        case_sensitive: Case-sensitive search
        limit: Maximum results
        
    Returns:
        List of matching values with their key paths
    """
    reg = open_registry_hive(hive_path)
    results = []
    
    if not case_sensitive:
        pattern = pattern.lower()
    
    def search_key(key, path=""):
        nonlocal results
        
        if len(results) >= limit:
            return
        
        current_path = f"{path}\\{key.name()}" if path else key.name()
        
        # Search values
        try:
            for value in key.values():
                if len(results) >= limit:
                    return
                
                match_found = False
                value_name = value.name()
                
                # Search in name
                if search_names:
                    check_name = value_name if case_sensitive else value_name.lower()
                    if pattern in check_name:
                        match_found = True
                
                # Search in data
                if search_data and not match_found:
                    try:
                        data = value.value()
                        if isinstance(data, str):
                            check_data = data if case_sensitive else data.lower()
                            if pattern in check_data:
                                match_found = True
                        elif isinstance(data, bytes):
                            try:
                                decoded = data.decode("utf-16-le")
                                check_data = decoded if case_sensitive else decoded.lower()
                                if pattern in check_data:
                                    match_found = True
                            except UnicodeDecodeError:
                                pass
                    except Exception:
                        pass
                
                if match_found:
                    value_data = parse_registry_value(value)
                    value_data["key_path"] = current_path
                    results.append(value_data)
        except Exception:
            pass
        
        # Recurse into subkeys
        try:
            for subkey in key.subkeys():
                if len(results) >= limit:
                    return
                search_key(subkey, current_path)
        except Exception:
            pass
    
    search_key(reg.root())
    return results


def query_registry_values(
    hive_path: str | Path,
    pattern: str,
    search_names: bool = True,
    search_data: bool = True,
    case_sensitive: bool = False,
    match_mode: str = "substring",
    key_path_prefix: str | None = None,
    offset: int = 0,
    limit: int = MAX_REGISTRY_RESULTS,
    fields: list[str] | None = None,
    diagnostic_limit: int = 5,
) -> dict[str, Any]:
    """Query a registry subtree with pagination and totals over readable values.

    The prefix selects a whole key and its descendants, never similarly named
    sibling keys. Paths may be hive-relative or include the root key name.
    Exact matching compares entire value names or individual data strings;
    regex matching uses ``re.search``. Multi-string entries are matched separately.
    Traversal follows the immutable hive's key/value order. Read failures are
    reported separately so a partial scan cannot appear to have complete totals.
    """
    if not isinstance(pattern, str):
        raise ValueError("pattern must be a string")
    if match_mode not in ("substring", "exact", "regex"):
        raise ValueError("match_mode must be substring, exact, or regex")
    for name, value in (
        ("search_names", search_names), ("search_data", search_data),
        ("case_sensitive", case_sensitive),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean")
    if not search_names and not search_data:
        raise ValueError("At least one of search_names or search_data must be true")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")
    if type(diagnostic_limit) is not int or not 0 <= diagnostic_limit <= 20:
        raise ValueError("diagnostic_limit must be an integer between 0 and 20")
    if key_path_prefix is not None and not isinstance(key_path_prefix, str):
        raise ValueError("key_path_prefix must be a string")
    if fields is not None and (
        not isinstance(fields, list) or not fields
        or any(not isinstance(field, str) or field not in REGISTRY_QUERY_FIELDS for field in fields)
    ):
        raise ValueError(f"fields must be a non-empty list containing {REGISTRY_QUERY_FIELDS}")

    regex = None
    if match_mode == "regex":
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regular expression: {exc}") from exc
    needle = pattern if case_sensitive else pattern.casefold()

    def matches(text: str) -> bool:
        if regex is not None:
            return regex.search(text) is not None
        candidate = text if case_sensitive else text.casefold()
        return needle == candidate if match_mode == "exact" else needle in candidate

    def data_strings(data: Any) -> list[str]:
        if isinstance(data, bytes):
            try:
                return [data.decode("utf-16-le").rstrip("\x00")]
            except UnicodeDecodeError:
                try:
                    return [data.decode("utf-8").rstrip("\x00")]
                except UnicodeDecodeError:
                    return []
        if isinstance(data, list):
            return [item.rstrip("\x00") for item in data if isinstance(item, str)]
        if isinstance(data, str):
            return [data.rstrip("\x00")]
        if isinstance(data, int):
            return [str(data)]
        return []

    reg = open_registry_hive(hive_path)
    root = reg.root()
    prefix = (key_path_prefix or "").replace("/", "\\").strip("\\")
    root_name = root.name()
    if prefix.casefold() == root_name.casefold():
        prefix = ""
    elif prefix.casefold().startswith(root_name.casefold() + "\\"):
        prefix = prefix[len(root_name) + 1:]
    try:
        start = reg.open(prefix) if prefix else root
    except Registry.RegistryKeyNotFoundException as exc:
        raise KeyError(f"Registry key prefix not found: {key_path_prefix}") from exc

    results = []
    total_matched = 0
    read_errors = 0
    diagnostics = []

    def record_error(path: str, operation: str, exc: Exception) -> None:
        nonlocal read_errors
        read_errors += 1
        if len(diagnostics) < diagnostic_limit:
            diagnostics.append({"key_path": path, "operation": operation, "error": str(exc)})

    start_path = f"{root_name}\\{prefix}" if prefix else root_name
    stack = [(start, start_path)]
    while stack:
        key, current_path = stack.pop()
        try:
            for value in key.values():
                try:
                    found = search_names and matches(value.name())
                    if search_data and not found:
                        found = any(matches(text) for text in data_strings(value.value()))
                    if not found:
                        continue
                    total_matched += 1
                    if offset < total_matched <= offset + limit:
                        row = parse_registry_value(value)
                        row["key_path"] = current_path
                        results.append(
                            {field: row[field] for field in fields if field in row}
                            if fields is not None else row
                        )
                except Exception as exc:
                    record_error(current_path, "read_value", exc)
        except Exception as exc:
            record_error(current_path, "enumerate_values", exc)
        children = []
        try:
            for subkey in key.subkeys():
                children.append((subkey, f"{current_path}\\{subkey.name()}"))
        except Exception as exc:
            record_error(current_path, "enumerate_subkeys", exc)
        stack.extend(reversed(children))

    returned = len(results)
    has_more = offset + returned < total_matched
    return {
        "results": results,
        "total_matched": total_matched,
        "returned": returned,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + returned if has_more else None,
        "truncated": has_more,
        "total_matched_complete": read_errors == 0,
        "read_errors": read_errors,
        "diagnostics": diagnostics,
        "diagnostics_truncated": read_errors > len(diagnostics),
    }


def get_run_keys(hive_path: str | Path) -> list[dict[str, Any]]:
    """
    Get persistence mechanisms from Run keys.
    
    Args:
        hive_path: Path to SOFTWARE or NTUSER.DAT hive
        
    Returns:
        List of autorun entries
    """
    run_key_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",  # For NTUSER.DAT
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]
    
    reg = open_registry_hive(hive_path)
    results = []
    
    for key_path in run_key_paths:
        try:
            key = reg.open(key_path)
            for value in key.values():
                results.append({
                    "key": key_path,
                    "name": value.name(),
                    "command": parse_registry_value(value)["data"],
                    "timestamp": key.timestamp().isoformat() if key.timestamp() else None,
                })
        except (Registry.RegistryKeyNotFoundException, Exception):
            continue
    
    return results


def get_winlogon_persistence(hive_path: str | Path) -> dict[str, Any]:
    """Inspect Winlogon values that can execute content at interactive logon."""
    key_path = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    expected_defaults = {
        "Userinit": "A single userinit.exe entry (optionally fully qualified)",
        "Shell": "explorer.exe",
        "AppSetup": "empty or absent",
        "Taskman": "empty or absent",
    }
    result = {
        "key": key_path,
        "present": False,
        "last_write_time": None,
        "timestamp": None,
        "values": {name: None for name in expected_defaults},
        "value_details": {},
        "expected_defaults": expected_defaults,
        "deviations": [],
        "suspicious": False,
    }

    reg = open_registry_hive(hive_path)
    try:
        key = reg.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        return result

    result["present"] = True
    try:
        timestamp = key.timestamp()
        if timestamp:
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            result["last_write_time"] = timestamp.isoformat()
            result["timestamp"] = timestamp.isoformat()
    except Exception:
        pass

    canonical_names = {name.lower(): name for name in expected_defaults}
    try:
        for value in key.values():
            canonical = canonical_names.get(value.name().lower())
            if not canonical:
                continue
            parsed = parse_registry_value(value)
            result["values"][canonical] = parsed["data"]
            result["value_details"][canonical] = parsed
    except Exception:
        pass

    userinit = str(result["values"].get("Userinit") or "")
    userinit_entries = [entry.strip() for entry in userinit.split(",") if entry.strip()]
    userinit_basenames = [
        entry.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        for entry in userinit_entries
    ]
    if userinit and not (len(userinit_basenames) == 1 and userinit_basenames[0] == "userinit.exe"):
        result["deviations"].append({
            "value_name": "Userinit",
            "value": userinit,
            "reason": "Expected only userinit.exe; additional executables run at logon",
        })

    shell = str(result["values"].get("Shell") or "")
    shell_basename = shell.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if shell and shell_basename != "explorer.exe":
        result["deviations"].append({
            "value_name": "Shell",
            "value": shell,
            "reason": "Expected explorer.exe as the interactive shell",
        })

    for value_name in ("AppSetup", "Taskman"):
        value_data = result["values"].get(value_name)
        if value_data not in (None, "", []):
            result["deviations"].append({
                "value_name": value_name,
                "value": value_data,
                "reason": f"{value_name} is normally empty or absent",
            })

    result["suspicious"] = bool(result["deviations"])
    return result


def get_services(hive_path: str | Path, include_microsoft: bool = False) -> list[dict[str, Any]]:
    """
    Get Windows services from SYSTEM hive.
    
    Args:
        hive_path: Path to SYSTEM hive
        include_microsoft: Include Microsoft services (usually many)
        
    Returns:
        List of service information
    """
    reg = open_registry_hive(hive_path)
    results = []
    
    # Need to find current control set
    try:
        select_key = reg.open("Select")
        current = None
        for value in select_key.values():
            if value.name() == "Current":
                current = value.value()
                break
        
        if current is None:
            current = 1
        
        services_path = f"ControlSet{current:03d}\\Services"
    except Exception:
        services_path = "ControlSet001\\Services"
    
    try:
        services_key = reg.open(services_path)
        
        for service_key in services_key.subkeys():
            service_info = {
                "name": service_key.name(),
                "display_name": None,
                "image_path": None,
                "start_type": None,
                "type": None,
                "description": None,
                "timestamp": service_key.timestamp().isoformat() if service_key.timestamp() else None,
            }
            
            for value in service_key.values():
                vname = value.name().lower()
                vdata = parse_registry_value(value)["data"]
                
                if vname == "displayname":
                    service_info["display_name"] = vdata
                elif vname == "imagepath":
                    service_info["image_path"] = vdata
                elif vname == "start":
                    start_types = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
                    service_info["start_type"] = start_types.get(vdata, str(vdata))
                elif vname == "type":
                    service_info["type"] = vdata
                elif vname == "description":
                    service_info["description"] = vdata
            
            # Filter Microsoft services if requested
            if not include_microsoft:
                image_path = (service_info.get("image_path") or "").lower()
                if "microsoft" in image_path or "windows" in image_path.split("\\")[0:2]:
                    if not service_info["image_path"] or "system32" in image_path:
                        continue
            
            results.append(service_info)
            
    except Exception as e:
        raise RuntimeError(f"Error reading services: {e}")
    
    return results


def get_usb_devices(hive_path: str | Path) -> list[dict[str, Any]]:
    """
    Get USB device history from SYSTEM hive.
    
    Args:
        hive_path: Path to SYSTEM hive
        
    Returns:
        List of USB device information
    """
    reg = open_registry_hive(hive_path)
    results = []
    
    # Find current control set
    try:
        select_key = reg.open("Select")
        current = 1
        for value in select_key.values():
            if value.name() == "Current":
                current = value.value()
                break
        control_set = f"ControlSet{current:03d}"
    except Exception:
        control_set = "ControlSet001"

    def device_values(key) -> dict[str, Any]:
        values = {}
        for value in key.values():
            name = value.name().casefold()
            try:
                raw = value.value()
                if name == "containerid" and isinstance(raw, bytes) and len(raw) == 16:
                    values[name] = "{" + str(uuid.UUID(bytes_le=raw)) + "}"
                else:
                    values[name] = parse_registry_value(value)["data"]
            except Exception:
                continue
        return values

    def container_identity(value) -> str | None:
        try:
            identifier = uuid.UUID(str(value))
            return str(identifier) if identifier.int else None
        except (ValueError, AttributeError):
            return None

    def instance_path_matches(wpd_id: str, device_class: str, instance_id: str) -> bool:
        # WPD physical entries encode the complete USBSTOR device path, with
        # '#' separators. Comparing components avoids serial-prefix collisions.
        parts = re.split(r"[\\#]", wpd_id.casefold())
        target = [device_class.casefold(), instance_id.casefold()]
        return any(
            part.removeprefix("_??_") == "usbstor" and parts[index + 1:index + 3] == target
            for index, part in enumerate(parts)
        )

    wpd_devices = []
    try:
        wpd_key = reg.open(f"{control_set}\\Enum\\SWD\\WPDBUSENUM")
        for device in wpd_key.subkeys():
            try:
                values = device_values(device)
                wpd_devices.append({
                    "instance_id": device.name(),
                    "key_path": device.path(),
                    "friendly_name": values.get("friendlyname"),
                    "manufacturer": values.get("mfg"),
                    "device_desc": values.get("devicedesc"),
                    "container_id": values.get("containerid"),
                })
            except Exception:
                continue
    except Exception:
        pass

    # USBSTOR devices
    try:
        usbstor_path = f"{control_set}\\Enum\\USBSTOR"
        usbstor_key = reg.open(usbstor_path)
        
        for device_class in usbstor_key.subkeys():
            for device in device_class.subkeys():
                instance_id = device.name()
                device_info = {
                    "type": "USBSTOR",
                    "class": device_class.name(),
                    "serial": instance_id,
                    "friendly_name": None,
                    "first_connected": device.timestamp().isoformat() if device.timestamp() else None,
                    "first_connected_source": "usb_stor_key_last_write",
                    "instance_id": instance_id,
                    "physical_serial": re.sub(r"&[0-9]+$", "", instance_id),
                    "device_instance_path": f"USBSTOR\\{device_class.name()}\\{instance_id}",
                }
                values = device_values(device)
                device_info.update({
                    "friendly_name": values.get("friendlyname"),
                    "manufacturer": values.get("mfg"),
                    "device_desc": values.get("devicedesc"),
                    "usb_stor_manufacturer": values.get("mfg"),
                    "usb_stor_device_desc": values.get("devicedesc"),
                    "container_id": values.get("containerid"),
                })
                container_id = container_identity(device_info["container_id"])
                correlated = []
                for wpd in wpd_devices:
                    match_sources = []
                    if instance_path_matches(wpd["instance_id"], device_class.name(), instance_id):
                        match_sources.append("instance_path")
                    if container_id and container_identity(wpd["container_id"]) == container_id:
                        match_sources.append("container_id")
                    if match_sources:
                        correlated.append({**wpd, "match_sources": match_sources})
                correlated.sort(key=lambda item: (
                    "instance_path" not in item["match_sources"],
                    not bool(item["friendly_name"]),
                    item["instance_id"].casefold(),
                ))
                device_info["wpd_devices"] = correlated
                device_info["wpd_friendly_names"] = list(dict.fromkeys(
                    item["friendly_name"] for item in correlated
                    if isinstance(item["friendly_name"], str) and item["friendly_name"]
                ))
                device_info["device_name"] = next(iter(device_info["wpd_friendly_names"]), None)
                if device_info["device_name"] is None:
                    device_info["device_name"] = device_info["friendly_name"]
                for field in ("manufacturer", "device_desc"):
                    current_value = device_info[field]
                    if current_value is None or (
                        isinstance(current_value, str) and current_value.startswith("@")
                    ):
                        readable_wpd_value = next((
                            item[field] for item in correlated
                            if "instance_path" in item["match_sources"]
                            and isinstance(item[field], str) and item[field]
                            and not item[field].startswith("@")
                        ), None)
                        if readable_wpd_value is not None:
                            device_info[field] = readable_wpd_value
                for field in ("manufacturer", "device_desc", "container_id"):
                    if device_info[field] is None:
                        device_info[field] = next(
                            (item[field] for item in correlated if item[field] is not None), None,
                        )
                results.append(device_info)
                
    except Exception:
        pass
    
    return results


def get_user_accounts(sam_path: str | Path) -> list[dict[str, Any]]:
    """
    Get user accounts from SAM hive.
    
    Args:
        sam_path: Path to SAM hive
        
    Returns:
        List of user account information
    """
    reg = open_registry_hive(sam_path)
    results = []
    
    try:
        users_path = "SAM\\Domains\\Account\\Users"
        users_key = reg.open(users_path)
        
        # Get user names from Names subkey
        names_key = reg.open(f"{users_path}\\Names")
        rid_to_name = {}
        
        for name_key in names_key.subkeys():
            # The default value type contains the RID
            try:
                for value in name_key.values():
                    if value.name() == "":
                        rid = value.value_type()
                        rid_to_name[rid] = name_key.name()
            except Exception:
                pass
        
        # Get user details from RID subkeys
        for subkey in users_key.subkeys():
            if subkey.name() == "Names":
                continue
            
            try:
                rid = int(subkey.name(), 16)
                user_info = {
                    "rid": rid,
                    "name": rid_to_name.get(rid, f"Unknown-{rid}"),
                    "last_login": None,
                    "last_password_change": None,
                    "account_created": None,
                    "login_count": None,
                    "flags": [],
                }
                
                # Parse F value for account metadata
                for value in subkey.values():
                    if value.name() == "F":
                        try:
                            f_data = value.value()
                            if len(f_data) >= 72:
                                # Last login time
                                last_login = struct.unpack("<Q", f_data[8:16])[0]
                                if last_login:
                                    user_info["last_login"] = filetime_to_datetime(last_login)
                                    if user_info["last_login"]:
                                        user_info["last_login"] = user_info["last_login"].isoformat()
                                
                                # Password change time
                                pwd_change = struct.unpack("<Q", f_data[24:32])[0]
                                if pwd_change:
                                    user_info["last_password_change"] = filetime_to_datetime(pwd_change)
                                    if user_info["last_password_change"]:
                                        user_info["last_password_change"] = user_info["last_password_change"].isoformat()
                                
                                # Account created time
                                created = struct.unpack("<Q", f_data[32:40])[0]
                                if created:
                                    user_info["account_created"] = filetime_to_datetime(created)
                                    if user_info["account_created"]:
                                        user_info["account_created"] = user_info["account_created"].isoformat()
                                
                                # Login count
                                if len(f_data) >= 68:
                                    user_info["login_count"] = struct.unpack("<H", f_data[66:68])[0]
                                
                                # Account flags
                                if len(f_data) >= 58:
                                    flags = struct.unpack("<H", f_data[56:58])[0]
                                    if flags & 0x0001:
                                        user_info["flags"].append("Disabled")
                                    if flags & 0x0004:
                                        user_info["flags"].append("PasswordNotRequired")
                                    if flags & 0x0200:
                                        user_info["flags"].append("NormalAccount")
                                        
                        except Exception:
                            pass
                
                results.append(user_info)
                
            except ValueError:
                continue
                
    except Exception as e:
        raise RuntimeError(f"Error reading SAM hive: {e}")
    
    return results


def get_network_interfaces(hive_path: str | Path) -> list[dict[str, Any]]:
    """
    Get network interface configuration from SYSTEM hive.
    
    Args:
        hive_path: Path to SYSTEM hive
        
    Returns:
        List of network interface information
    """
    reg = open_registry_hive(hive_path)
    results = []
    
    # Find current control set
    try:
        select_key = reg.open("Select")
        current = 1
        for value in select_key.values():
            if value.name() == "Current":
                current = value.value()
                break
        control_set = f"ControlSet{current:03d}"
    except Exception:
        control_set = "ControlSet001"
    
    try:
        interfaces_path = f"{control_set}\\Services\\Tcpip\\Parameters\\Interfaces"
        interfaces_key = reg.open(interfaces_path)
        
        for interface_key in interfaces_key.subkeys():
            interface_info = {
                "guid": interface_key.name(),
                "ip_address": None,
                "subnet_mask": None,
                "default_gateway": None,
                "dhcp_enabled": None,
                "dhcp_server": None,
                "dns_servers": None,
            }
            
            for value in interface_key.values():
                vname = value.name()
                vdata = parse_registry_value(value)["data"]
                
                if vname == "IPAddress":
                    interface_info["ip_address"] = vdata
                elif vname == "SubnetMask":
                    interface_info["subnet_mask"] = vdata
                elif vname == "DefaultGateway":
                    interface_info["default_gateway"] = vdata
                elif vname == "EnableDHCP":
                    interface_info["dhcp_enabled"] = bool(vdata)
                elif vname == "DhcpServer":
                    interface_info["dhcp_server"] = vdata
                elif vname == "NameServer":
                    interface_info["dns_servers"] = vdata
                elif vname == "DhcpIPAddress":
                    if not interface_info["ip_address"]:
                        interface_info["ip_address"] = vdata
            
            results.append(interface_info)
            
    except Exception:
        pass
    
    return results


def get_system_info(software_path: str | Path, system_path: str | Path) -> dict[str, Any]:
    """
    Get system information from SOFTWARE and SYSTEM hives.
    
    Args:
        software_path: Path to SOFTWARE hive
        system_path: Path to SYSTEM hive
        
    Returns:
        System information dictionary
    """
    info = {
        "product_name": None,
        "version": None,
        "build": None,
        "install_date": None,
        "registered_owner": None,
        "registered_org": None,
        "computer_name": None,
        "timezone": None,
    }
    
    # Get info from SOFTWARE hive
    try:
        software_reg = open_registry_hive(software_path)
        nt_key = software_reg.open("Microsoft\\Windows NT\\CurrentVersion")
        
        for value in nt_key.values():
            vname = value.name()
            vdata = parse_registry_value(value)["data"]
            
            if vname == "ProductName":
                info["product_name"] = vdata
            elif vname == "CurrentVersion":
                info["version"] = vdata
            elif vname == "CurrentBuild" or vname == "CurrentBuildNumber":
                info["build"] = vdata
            elif vname == "InstallDate":
                if isinstance(vdata, int):
                    info["install_date"] = datetime.fromtimestamp(vdata, tz=timezone.utc).isoformat()
            elif vname == "RegisteredOwner":
                info["registered_owner"] = vdata
            elif vname == "RegisteredOrganization":
                info["registered_org"] = vdata
                
    except Exception:
        pass
    
    # Get info from SYSTEM hive
    try:
        system_reg = open_registry_hive(system_path)
        
        # Computer name
        try:
            name_key = system_reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")
            for value in name_key.values():
                if value.name() == "ComputerName":
                    info["computer_name"] = parse_registry_value(value)["data"]
        except Exception:
            pass
        
        # Timezone
        try:
            tz_key = system_reg.open("ControlSet001\\Control\\TimeZoneInformation")
            for value in tz_key.values():
                if value.name() == "TimeZoneKeyName":
                    info["timezone"] = parse_registry_value(value)["data"]
        except Exception:
            pass
            
    except Exception:
        pass
    
    return info
