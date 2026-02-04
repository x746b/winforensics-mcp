"""
Detect It Easy (DiE) integration for packer/compiler detection.

DiE is a program for determining types of files and detecting:
- Packers (UPX, ASPack, Themida, VMProtect, etc.)
- Cryptors and protectors
- Compilers (MSVC, GCC, Delphi, etc.)
- Linkers
- Installers (NSIS, InnoSetup, etc.)
- .NET/Java detection
- File type identification

Requires `diec` (DiE command-line) to be installed and in PATH.
Install from: https://github.com/horsicq/DIE-engine/releases
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


def _find_diec() -> Optional[str]:
    """Find diec executable in PATH or common locations."""
    # Check PATH first
    diec_path = shutil.which("diec")
    if diec_path:
        return diec_path

    # Check common installation locations
    common_paths = [
        "/usr/bin/diec",
        "/usr/local/bin/diec",
        "/opt/die/diec",
        "/opt/detect-it-easy/diec",
        os.path.expanduser("~/.local/bin/diec"),
        os.path.expanduser("~/DIE/diec"),
    ]

    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


# Check if diec is available
_DIEC_PATH = _find_diec()
DIE_AVAILABLE = _DIEC_PATH is not None


def check_die_available() -> None:
    """Raise error if diec not available."""
    if not DIE_AVAILABLE:
        raise RuntimeError(
            "diec (Detect It Easy CLI) not found. Install from:\n"
            "https://github.com/horsicq/DIE-engine/releases\n"
            "Or on Debian/Ubuntu: apt install detect-it-easy"
        )


def get_die_version() -> Optional[str]:
    """Get DiE version string."""
    if not DIE_AVAILABLE:
        return None

    try:
        result = subprocess.run(
            [_DIEC_PATH, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return None


def analyze_file(
    file_path: str | Path,
    deep_scan: bool = False,
    show_version: bool = True,
    show_options: bool = False,
) -> dict[str, Any]:
    """
    Analyze a file with Detect It Easy.

    Args:
        file_path: Path to file to analyze
        deep_scan: Enable deep scan mode (slower but more thorough)
        show_version: Include version info in results
        show_options: Include compiler/linker options

    Returns:
        {
            "file": str,
            "file_size": int,
            "file_type": str,
            "arch": str,
            "mode": str,
            "endianness": str,
            "detects": [
                {
                    "type": str,  # "Packer", "Compiler", "Linker", "Protector", etc.
                    "name": str,  # "UPX", "MSVC", etc.
                    "version": str,
                    "options": str,
                    "string": str,  # Full detection string
                }
            ],
            "is_packed": bool,
            "is_dotnet": bool,
            "is_installer": bool,
            "entropy": float,
            "strings_count": int,
        }
    """
    check_die_available()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Build command
    cmd = [_DIEC_PATH, "-j"]  # JSON output

    if deep_scan:
        cmd.append("-d")  # Deep scan

    cmd.append(str(file_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,  # 1 minute timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "file": str(file_path),
            "error": "Analysis timed out (>60 seconds)",
        }
    except Exception as e:
        return {
            "file": str(file_path),
            "error": f"Failed to run diec: {e}",
        }

    # Parse JSON output
    try:
        # diec outputs a JSON object, but may have warnings before it
        stdout = result.stdout

        # Find JSON start (first '{')
        json_start = stdout.find('{')
        if json_start > 0:
            stdout = stdout[json_start:]

        # Find JSON end (last '}')
        json_end = stdout.rfind('}')
        if json_end > 0:
            stdout = stdout[:json_end + 1]

        data = json.loads(stdout)
    except json.JSONDecodeError:
        # If JSON parsing fails, return raw output
        return {
            "file": str(file_path),
            "raw_output": result.stdout,
            "error": "Failed to parse diec JSON output",
        }

    # Process the response
    return _process_die_result(file_path, data, show_version, show_options)


def _process_die_result(
    file_path: Path,
    data: dict,
    show_version: bool,
    show_options: bool,
) -> dict[str, Any]:
    """Process DiE JSON output into standardized format."""

    # Handle different JSON structures from diec
    # The structure can vary between versions

    detects = []
    file_type = None
    arch = None
    mode = None
    endianness = None

    # Extract detections
    if "detects" in data:
        raw_detects = data["detects"]
        if isinstance(raw_detects, list):
            for item in raw_detects:
                if isinstance(item, dict):
                    # Handle nested values structure
                    if "values" in item:
                        for val in item.get("values", []):
                            detect_entry = _parse_detect_entry(val, show_version, show_options)
                            if detect_entry:
                                detects.append(detect_entry)
                    else:
                        detect_entry = _parse_detect_entry(item, show_version, show_options)
                        if detect_entry:
                            detects.append(detect_entry)
                elif isinstance(item, str):
                    detects.append({"string": item, "type": "Unknown", "name": item})

    # Try to extract file info
    if "filetype" in data:
        file_type = data["filetype"]
    elif "type" in data:
        file_type = data["type"]

    if "arch" in data:
        arch = data["arch"]
    if "mode" in data:
        mode = data["mode"]
    if "endianess" in data or "endianness" in data:
        endianness = data.get("endianess") or data.get("endianness")

    # Analyze detections for flags
    detect_types = {d.get("type", "").lower() for d in detects}
    detect_names = {d.get("name", "").lower() for d in detects}

    is_packed = any(t in detect_types for t in ["packer", "protector", "cryptor"])
    is_dotnet = any(".net" in n or "msil" in n for n in detect_names)
    is_installer = any(t == "installer" for t in detect_types) or any(
        n in detect_names for n in ["nsis", "innosetup", "installshield", "wix"]
    )

    # Get file stats
    try:
        file_size = file_path.stat().st_size
    except Exception:
        file_size = None

    return {
        "file": str(file_path),
        "file_size": file_size,
        "file_type": file_type,
        "arch": arch,
        "mode": mode,
        "endianness": endianness,
        "detects": detects,
        "detect_count": len(detects),
        "is_packed": is_packed,
        "is_dotnet": is_dotnet,
        "is_installer": is_installer,
    }


def _parse_detect_entry(
    item: dict,
    show_version: bool,
    show_options: bool,
) -> Optional[dict]:
    """Parse a single detection entry."""
    if not isinstance(item, dict):
        return None

    entry = {}

    # Type (Packer, Compiler, Linker, etc.)
    entry["type"] = item.get("type", item.get("parentname", "Unknown"))

    # Name
    entry["name"] = item.get("name", item.get("string", "Unknown"))

    # Version
    if show_version and "version" in item:
        entry["version"] = item["version"]

    # Options
    if show_options and "options" in item:
        entry["options"] = item["options"]

    # Full string representation
    if "string" in item:
        entry["string"] = item["string"]
    else:
        # Build string from components
        parts = [entry["type"], entry["name"]]
        if show_version and entry.get("version"):
            parts.append(entry["version"])
        entry["string"] = ": ".join(filter(None, parts))

    return entry


def scan_directory(
    dir_path: str | Path,
    recursive: bool = True,
    extensions: Optional[list[str]] = None,
    deep_scan: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Scan directory for executables and analyze with DiE.

    Args:
        dir_path: Directory to scan
        recursive: Scan subdirectories
        extensions: File extensions to scan (default: .exe, .dll, .sys, .ocx, .scr)
        deep_scan: Enable deep scan mode
        limit: Maximum files to scan

    Returns:
        {
            "directory": str,
            "files_scanned": int,
            "files_with_detections": int,
            "packed_files": [...],
            "results": [
                {
                    "file": str,
                    "detects": [...],
                    "is_packed": bool,
                    ...
                }
            ],
            "summary": {
                "by_compiler": {"MSVC": 5, "GCC": 2, ...},
                "by_packer": {"UPX": 3, ...},
                "file_types": {"PE32": 10, "PE64": 5, ...},
            }
        }
    """
    check_die_available()

    dir_path = Path(dir_path)
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise ValueError(f"Not a directory: {dir_path}")

    # Default extensions for Windows executables
    if extensions is None:
        extensions = [".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".cpl"]

    extensions = [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions]

    # Find files
    if recursive:
        files = [f for f in dir_path.rglob("*") if f.is_file() and f.suffix.lower() in extensions]
    else:
        files = [f for f in dir_path.glob("*") if f.is_file() and f.suffix.lower() in extensions]

    # Limit files
    files = files[:limit]

    results = []
    packed_files = []
    compiler_counts: dict[str, int] = {}
    packer_counts: dict[str, int] = {}
    file_type_counts: dict[str, int] = {}

    for file_path in files:
        try:
            result = analyze_file(file_path, deep_scan=deep_scan)
            results.append(result)

            # Track packed files
            if result.get("is_packed"):
                packed_files.append(str(file_path))

            # Aggregate statistics
            if result.get("file_type"):
                ft = result["file_type"]
                file_type_counts[ft] = file_type_counts.get(ft, 0) + 1

            for detect in result.get("detects", []):
                dtype = detect.get("type", "").lower()
                dname = detect.get("name", "Unknown")

                if dtype in ("compiler", "linker"):
                    compiler_counts[dname] = compiler_counts.get(dname, 0) + 1
                elif dtype in ("packer", "protector", "cryptor"):
                    packer_counts[dname] = packer_counts.get(dname, 0) + 1

        except Exception as e:
            results.append({
                "file": str(file_path),
                "error": str(e),
            })

    files_with_detections = sum(1 for r in results if r.get("detect_count", 0) > 0)

    return {
        "directory": str(dir_path),
        "files_found": len(files),
        "files_scanned": len(results),
        "files_with_detections": files_with_detections,
        "packed_files_count": len(packed_files),
        "packed_files": packed_files[:20],  # Limit packed files list
        "results": results,
        "summary": {
            "by_compiler": dict(sorted(compiler_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "by_packer": dict(sorted(packer_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "file_types": dict(sorted(file_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        },
    }


def get_packer_info(packer_name: str) -> dict[str, Any]:
    """
    Get information about a known packer/protector.

    Args:
        packer_name: Name of packer (e.g., "UPX", "Themida")

    Returns:
        Information about the packer including unpacking difficulty and tools.
    """
    # Common packers/protectors database
    packer_db = {
        "upx": {
            "name": "UPX (Ultimate Packer for eXecutables)",
            "type": "Packer",
            "difficulty": "Easy",
            "description": "Open-source executable packer, easily unpacked",
            "unpack_tool": "upx -d <file>",
            "legitimate_use": "Often used legitimately to reduce file size",
        },
        "aspack": {
            "name": "ASPack",
            "type": "Packer",
            "difficulty": "Medium",
            "description": "Commercial packer for Win32 executables",
            "unpack_tool": "AspackDie, manual unpacking",
            "legitimate_use": "Sometimes used legitimately",
        },
        "themida": {
            "name": "Themida/WinLicense",
            "type": "Protector",
            "difficulty": "Hard",
            "description": "Advanced software protection with VM, anti-debug, anti-dump",
            "unpack_tool": "Manual analysis, specialized tools",
            "legitimate_use": "Common in commercial software protection",
            "malware_use": "Frequently used by malware to evade analysis",
        },
        "vmprotect": {
            "name": "VMProtect",
            "type": "Protector",
            "difficulty": "Very Hard",
            "description": "Code virtualization protection",
            "unpack_tool": "Manual VM analysis, devirtualization tools",
            "legitimate_use": "Used in commercial software",
            "malware_use": "Increasingly used by sophisticated malware",
        },
        "enigma": {
            "name": "Enigma Protector",
            "type": "Protector",
            "difficulty": "Hard",
            "description": "Software protection with licensing",
            "unpack_tool": "Manual unpacking, Enigma VirtualBox tools",
            "legitimate_use": "Commercial software protection",
        },
        "mpress": {
            "name": "MPRESS",
            "type": "Packer",
            "difficulty": "Easy",
            "description": "Free PE packer",
            "unpack_tool": "Manual OEP finding, generic unpackers",
            "legitimate_use": "Legitimate use for size reduction",
        },
        "pecompact": {
            "name": "PECompact",
            "type": "Packer",
            "difficulty": "Medium",
            "description": "PE executable compressor",
            "unpack_tool": "PECompact unpack plugins",
            "legitimate_use": "Legitimate compression tool",
        },
        "petite": {
            "name": "Petite",
            "type": "Packer",
            "difficulty": "Easy",
            "description": "Free Win32 executable compressor",
            "unpack_tool": "un-petite, manual unpacking",
            "legitimate_use": "Size reduction",
        },
        "nspack": {
            "name": "NSPack/NsPack",
            "type": "Packer",
            "difficulty": "Easy",
            "description": "Simple PE packer",
            "unpack_tool": "NSPack unpackers available",
            "legitimate_use": "Rarely used legitimately",
            "malware_use": "Common in older malware",
        },
        "confuser": {
            "name": "ConfuserEx",
            "type": "Obfuscator",
            "difficulty": "Medium-Hard",
            "description": ".NET obfuscator/protector",
            "unpack_tool": "de4dot, dnSpy",
            "legitimate_use": ".NET code protection",
            "malware_use": "Very common in .NET malware",
        },
    }

    key = packer_name.lower().replace(" ", "").replace("-", "")

    # Try exact match first
    if key in packer_db:
        return packer_db[key]

    # Try partial match
    for pk, info in packer_db.items():
        if pk in key or key in pk:
            return info

    return {
        "name": packer_name,
        "type": "Unknown",
        "difficulty": "Unknown",
        "description": "No information available for this packer",
        "note": "Consider searching online for unpacking resources",
    }
