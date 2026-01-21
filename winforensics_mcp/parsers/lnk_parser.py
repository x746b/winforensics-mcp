"""
LNK File Parser Module

Parses Windows shortcut (.lnk) files to extract target paths, timestamps,
and volume information for forensic analysis.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import pylnk3
    PYLNK_AVAILABLE = True
except ImportError:
    PYLNK_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS


def check_pylnk_available() -> None:
    """Raise error if pylnk3 library not available"""
    if not PYLNK_AVAILABLE:
        raise ImportError(
            "pylnk3 library not installed. Install with: pip install pylnk3"
        )


def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime to ISO string"""
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _extract_local_path(lnk) -> Optional[str]:
    """Extract local path from link info"""
    try:
        link_info = lnk.link_info
        if link_info:
            # link_info string contains the local path
            info_str = str(link_info)
            if 'Path:' in info_str:
                # Extract path from "Path: C:\..." line
                for line in info_str.split('\n'):
                    if 'Path:' in line:
                        path = line.split('Path:')[-1].strip()
                        if path:
                            return path
    except Exception:
        pass
    return None


def _extract_volume_info(lnk) -> Optional[dict[str, Any]]:
    """Extract volume information from link info"""
    try:
        link_info = lnk.link_info
        if link_info:
            info_str = str(link_info)
            volume_info = {}

            if 'Volume Serial Number:' in info_str:
                for line in info_str.split('\n'):
                    line = line.strip()
                    if 'Volume Serial Number:' in line:
                        serial = line.split(':')[-1].strip()
                        volume_info['serial_number'] = serial
                    elif 'Volume Type:' in line:
                        vol_type = line.split(':')[-1].strip()
                        volume_info['volume_type'] = vol_type
                    elif 'Volume Label:' in line:
                        label = line.split(':')[-1].strip()
                        if label:
                            volume_info['volume_label'] = label

            if volume_info:
                return volume_info
    except Exception:
        pass
    return None


def _parse_single_lnk(lnk_path: Path) -> dict[str, Any]:
    """Parse a single LNK file"""
    check_pylnk_available()

    if not lnk_path.exists():
        raise FileNotFoundError(f"LNK file not found: {lnk_path}")

    try:
        lnk = pylnk3.parse(str(lnk_path))
    except Exception as e:
        raise ValueError(f"Failed to parse LNK file: {e}")

    # Extract target path (try local path first, then general path)
    target_path = _extract_local_path(lnk)
    if not target_path:
        target_path = lnk.path

    # Extract file flags as list
    file_flags = []
    if hasattr(lnk, 'file_flags') and lnk.file_flags:
        try:
            flags_dict = lnk.file_flags
            if isinstance(flags_dict, dict):
                file_flags = [k for k, v in flags_dict.items() if v]
        except Exception:
            pass

    result = {
        "filename": lnk_path.name,
        "path": str(lnk_path),
        "target_path": target_path,
        "local_path": _extract_local_path(lnk),
        "working_dir": lnk.working_dir,
        "arguments": lnk.arguments,
        "description": lnk.description,
        "timestamps": {
            "creation_time": _format_datetime(lnk.creation_time),
            "modification_time": _format_datetime(lnk.modification_time),
            "access_time": _format_datetime(lnk.access_time),
        },
        "target_file_size": lnk.file_size,
        "file_flags": file_flags if file_flags else None,
        "volume_info": _extract_volume_info(lnk),
        "relative_path": lnk.relative_path if hasattr(lnk, 'relative_path') else None,
        "icon_location": lnk.icon if hasattr(lnk, 'icon') else None,
    }

    return result


def parse_lnk_file(
    lnk_path: str | Path,
) -> dict[str, Any]:
    """
    Parse a single LNK shortcut file.

    Args:
        lnk_path: Path to .lnk file

    Returns:
        Dictionary with LNK file details
    """
    return _parse_single_lnk(Path(lnk_path))


def parse_lnk_directory(
    directory: str | Path,
    recursive: bool = True,
    target_filter: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse all LNK files in a directory.

    Args:
        directory: Path to directory containing .lnk files
        recursive: Search recursively in subdirectories
        target_filter: Filter by target path (case-insensitive substring)
        limit: Maximum number of results

    Returns:
        Dictionary with list of parsed LNK files
    """
    check_pylnk_available()

    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    results = []
    errors = []
    filter_lower = target_filter.lower() if target_filter else None

    # Find all .lnk files
    pattern = "**/*.lnk" if recursive else "*.lnk"
    lnk_files = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)

    for lnk_path in lnk_files:
        if len(results) >= limit:
            break

        try:
            parsed = _parse_single_lnk(lnk_path)

            # Apply filter
            if filter_lower:
                target = parsed.get("target_path") or parsed.get("local_path") or ""
                if filter_lower not in target.lower():
                    continue

            results.append(parsed)

        except Exception as e:
            errors.append({
                "file": str(lnk_path),
                "error": str(e),
            })

    return {
        "directory": str(directory),
        "recursive": recursive,
        "total_files": len(lnk_files),
        "parsed_count": len(results),
        "lnk_files": results,
        "errors": errors if errors else None,
    }


def get_recent_files(
    user_profile_path: str | Path,
    extension_filter: Optional[str] = None,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Get recently accessed files from user's Recent folder.

    Args:
        user_profile_path: Path to user profile (e.g., C:\\Users\\victim)
        extension_filter: Filter by original file extension (e.g., ".exe", ".ps1")
        limit: Maximum results

    Returns:
        List of recently accessed files
    """
    check_pylnk_available()

    user_profile = Path(user_profile_path)
    recent_dir = user_profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"

    if not recent_dir.exists():
        raise FileNotFoundError(f"Recent folder not found: {recent_dir}")

    results = []
    filter_ext = extension_filter.lower() if extension_filter else None

    lnk_files = sorted(recent_dir.glob("*.lnk"), key=lambda p: p.stat().st_mtime, reverse=True)

    for lnk_path in lnk_files:
        if len(results) >= limit:
            break

        try:
            parsed = _parse_single_lnk(lnk_path)

            # Apply extension filter
            if filter_ext:
                target = parsed.get("local_path") or parsed.get("target_path") or ""
                if not target.lower().endswith(filter_ext):
                    continue

            results.append(parsed)

        except Exception:
            continue

    return {
        "user_profile": str(user_profile),
        "recent_folder": str(recent_dir),
        "count": len(results),
        "recent_files": results,
    }


def search_lnk_for_target(
    directory: str | Path,
    target_name: str,
    recursive: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Search for LNK files pointing to a specific target.

    Args:
        directory: Directory to search
        target_name: Name or path substring to search for
        recursive: Search recursively
        limit: Maximum results

    Returns:
        Matching LNK files
    """
    return parse_lnk_directory(
        directory,
        recursive=recursive,
        target_filter=target_name,
        limit=limit,
    )
