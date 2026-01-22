from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import pyscca
    PYSCCA_AVAILABLE = True
except ImportError:
    PYSCCA_AVAILABLE = False

from ..config import MAX_EVTX_RESULTS


def check_pyscca_available() -> None:
    """Raise error if pyscca library not available"""
    if not PYSCCA_AVAILABLE:
        raise ImportError(
            "libscca-python library not installed. Install with: pip install libscca-python"
        )


def _filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to datetime"""
    if not filetime or filetime == 0:
        return None
    try:
        # FILETIME is 100-nanosecond intervals since Jan 1, 1601
        # Convert to Unix timestamp
        EPOCH_DIFF = 116444736000000000  # Difference between 1601 and 1970 in 100-ns
        if filetime < EPOCH_DIFF:
            return None
        unix_ts = (filetime - EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def parse_prefetch_file(
    file_path: str | Path,
    include_loaded_files: bool = False,
    include_volumes: bool = True,
    max_loaded_files: int = 100,
) -> dict[str, Any]:
    """
    Parse a single Windows Prefetch file.

    Args:
        file_path: Path to the .pf file
        include_loaded_files: Include list of files/DLLs loaded by the executable
        include_volumes: Include volume information
        max_loaded_files: Maximum number of loaded files to return

    Returns:
        Parsed prefetch data dictionary
    """
    check_pyscca_available()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Prefetch file not found: {file_path}")

    if not file_path.suffix.lower() == ".pf":
        raise ValueError(f"Not a prefetch file (expected .pf extension): {file_path}")

    result: dict[str, Any] = {
        "filename": file_path.name,
        "path": str(file_path),
    }

    pf = pyscca.file()
    try:
        pf.open(str(file_path))

        # Basic info
        result["executable"] = pf.executable_filename
        result["prefetch_hash"] = f"{pf.prefetch_hash:08X}" if pf.prefetch_hash else None
        result["run_count"] = pf.run_count
        result["format_version"] = pf.format_version

        # Last run times (Windows 8+ can have up to 8)
        last_run_times = []
        for i in range(8):  # Max 8 last run times in Win8+
            try:
                run_time_int = pf.get_last_run_time_as_integer(i)
                if run_time_int and run_time_int > 0:
                    dt = _filetime_to_datetime(run_time_int)
                    if dt:
                        last_run_times.append(dt.isoformat())
            except Exception:
                break

        result["last_run_times"] = last_run_times
        if last_run_times:
            result["last_run"] = last_run_times[0]

        # Volume information
        if include_volumes and pf.number_of_volumes > 0:
            volumes = []
            for i in range(pf.number_of_volumes):
                try:
                    vol = pf.get_volume_information(i)
                    vol_info = {
                        "device_path": vol.device_path,
                        "serial_number": f"{vol.serial_number:08X}" if vol.serial_number else None,
                    }
                    # Get creation time
                    try:
                        creation_time_int = vol.get_creation_time_as_integer()
                        if creation_time_int:
                            dt = _filetime_to_datetime(creation_time_int)
                            if dt:
                                vol_info["creation_time"] = dt.isoformat()
                    except Exception:
                        pass

                    volumes.append(vol_info)
                except Exception:
                    continue

            if volumes:
                result["volumes"] = volumes

        # Loaded files/resources
        if include_loaded_files:
            loaded_files = []
            num_files = min(pf.number_of_filenames, max_loaded_files)
            for i in range(num_files):
                try:
                    filename = pf.get_filename(i)
                    if filename:
                        loaded_files.append(filename)
                except Exception:
                    continue

            result["loaded_files"] = loaded_files
            result["loaded_files_count"] = pf.number_of_filenames
            if pf.number_of_filenames > max_loaded_files:
                result["loaded_files_truncated"] = True

    finally:
        pf.close()

    return result


def parse_prefetch_directory(
    directory: str | Path,
    executable_filter: Optional[str] = None,
    include_loaded_files: bool = False,
    limit: int = MAX_EVTX_RESULTS,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Parse all Prefetch files in a directory.

    Args:
        directory: Path to Prefetch directory
        executable_filter: Filter by executable name (case-insensitive substring)
        include_loaded_files: Include loaded files for each prefetch entry
        limit: Maximum number of results
        offset: Number of results to skip (for pagination)

    Returns:
        Dictionary with list of parsed prefetch files
    """
    check_pyscca_available()

    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Prefetch directory not found: {directory}")

    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    results = []
    errors = []
    matched_count = 0
    skipped = 0
    truncated = False
    filter_lower = executable_filter.lower() if executable_filter else None

    # Find all .pf files
    pf_files = sorted(directory.glob("*.pf"), key=lambda p: p.stat().st_mtime, reverse=True)

    for pf_path in pf_files:
        try:
            parsed = parse_prefetch_file(
                pf_path,
                include_loaded_files=include_loaded_files,
                include_volumes=False,  # Skip volumes for directory parsing to reduce output
            )

            # Apply filter
            if filter_lower:
                exe_name = parsed.get("executable", "").lower()
                if filter_lower not in exe_name:
                    continue

            matched_count += 1

            # Skip for pagination offset
            if skipped < offset:
                skipped += 1
                continue

            # Check limit
            if len(results) >= limit:
                truncated = True
                continue  # Keep counting matches

            results.append(parsed)

        except Exception as e:
            errors.append({
                "file": str(pf_path),
                "error": str(e),
            })

    return {
        "directory": str(directory),
        "total_files": len(pf_files),
        "total_matched": matched_count,
        "parsed_count": len(results),
        "offset": offset,
        "truncated": truncated,
        "next_offset": offset + len(results) if truncated else None,
        "prefetch_entries": results,
        "errors": errors if errors else None,
    }


def search_prefetch_for_executable(
    directory: str | Path,
    executable_name: str,
    include_loaded_files: bool = True,
) -> dict[str, Any]:
    """
    Search for a specific executable in Prefetch files.

    Args:
        directory: Path to Prefetch directory
        executable_name: Name of executable to search for (case-insensitive)
        include_loaded_files: Include loaded files in results

    Returns:
        Search results with execution evidence
    """
    check_pyscca_available()

    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Prefetch directory not found: {directory}")

    exe_lower = executable_name.lower()
    matches = []

    for pf_path in directory.glob("*.pf"):
        try:
            # Quick check: prefetch filename starts with executable name
            pf_name_lower = pf_path.stem.lower()
            if not pf_name_lower.startswith(exe_lower.replace(".exe", "")):
                continue

            parsed = parse_prefetch_file(
                pf_path,
                include_loaded_files=include_loaded_files,
            )
            matches.append(parsed)

        except Exception:
            continue

    # Sort by last run time (most recent first)
    matches.sort(
        key=lambda x: x.get("last_run", ""),
        reverse=True,
    )

    return {
        "searched_executable": executable_name,
        "found": len(matches) > 0,
        "execution_evidence": matches,
        "total_run_count": sum(m.get("run_count", 0) for m in matches),
    }


def get_recent_executions(
    directory: str | Path,
    hours: int = 24,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Get recently executed programs from Prefetch.

    Args:
        directory: Path to Prefetch directory
        hours: Look back this many hours
        limit: Maximum results

    Returns:
        Recently executed programs
    """
    check_pyscca_available()

    from datetime import timedelta

    directory = Path(directory)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    recent = []
    for pf_path in directory.glob("*.pf"):
        try:
            parsed = parse_prefetch_file(pf_path, include_loaded_files=False)

            last_run = parsed.get("last_run")
            if last_run:
                last_run_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                if last_run_dt >= cutoff:
                    recent.append(parsed)

        except Exception:
            continue

        if len(recent) >= limit:
            break

    # Sort by last run time
    recent.sort(key=lambda x: x.get("last_run", ""), reverse=True)

    return {
        "directory": str(directory),
        "hours_lookback": hours,
        "cutoff_time": cutoff.isoformat(),
        "recent_executions": recent[:limit],
    }
