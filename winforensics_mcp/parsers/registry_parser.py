from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional, Sequence

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

from ..config import (
    MAX_REGISTRY_RESULTS,
    FORENSIC_REGISTRY_KEYS,
)


def check_registry_available() -> None:
    """Raise error if python-registry library not available"""
    if not REGISTRY_AVAILABLE:
        raise ImportError(
            "python-registry library not installed. Install with: pip install python-registry"
        )


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to datetime"""
    if filetime == 0:
        return None
    try:
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        EPOCH_DIFF = 116444736000000000  # Difference between 1601 and 1970 in 100ns
        timestamp = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (ValueError, OSError):
        return None


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
    
    # USBSTOR devices
    try:
        usbstor_path = f"{control_set}\\Enum\\USBSTOR"
        usbstor_key = reg.open(usbstor_path)
        
        for device_class in usbstor_key.subkeys():
            for device in device_class.subkeys():
                device_info = {
                    "type": "USBSTOR",
                    "class": device_class.name(),
                    "serial": device.name(),
                    "friendly_name": None,
                    "first_connected": device.timestamp().isoformat() if device.timestamp() else None,
                }
                
                for value in device.values():
                    if value.name() == "FriendlyName":
                        device_info["friendly_name"] = parse_registry_value(value)["data"]
                
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
