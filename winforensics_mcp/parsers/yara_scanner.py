"""
YARA rule scanning for malware detection.

Features:
- Compile rules from files/directories with caching
- Scan files, directories, or raw bytes
- Rule namespace organization
- Skip rules with external variables (incompatible without THOR)
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# Rule cache: cache_key -> (compiled_rules, timestamp)
_rule_cache: dict[str, tuple[Any, float]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


# Files known to use external variables (incompatible without THOR/LOKI)
# These rules reference undefined identifiers like 'filename', 'filepath', 'extension'
EXTERNAL_VAR_FILES = {
    "configured_vulns_ext_vars.yar",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "expl_connectwise_screenconnect_vuln_feb24.yar",
    "gen_anomalies_keyword.yar",
    "gen_case_anomalies.yar",
    "gen_fake_amsi_dll.yar",
    "gen_mal_3cx_compromise_mar23.yar",
    "gen_susp_obfuscation.yar",
    "gen_vcruntime140_dll_sideloading.yar",
    "gen_webshells_ext_vars.yar",
    "general_cloaking.yar",
    "generic_anomalies.yar",
    "thor_inverse_matches.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
    "yara_mixed_ext_vars.yar",
}


def check_yara_available() -> None:
    """Raise error if yara-python library not available."""
    if not YARA_AVAILABLE:
        raise ImportError(
            "yara-python library not installed. Install with: pip install yara-python"
        )


def _uses_external_vars(yar_file: Path) -> bool:
    """Check if rule file uses external variables (incompatible)."""
    return yar_file.name in EXTERNAL_VAR_FILES


def _get_cache_key(yar_files: dict[str, str]) -> str:
    """Generate cache key from rule file paths."""
    content = str(sorted(yar_files.items()))
    return hashlib.md5(content.encode()).hexdigest()


def compile_rules(
    rule_paths: list[str | Path],
    use_cache: bool = True,
) -> Any:  # Returns yara.Rules
    """
    Compile YARA rules from files or directories.

    Args:
        rule_paths: List of .yar files or directories containing .yar files
        use_cache: Use cached compiled rules if available and not expired

    Returns:
        Compiled yara.Rules object

    Raises:
        ImportError: If yara-python not installed
        ValueError: If no valid rules found
        yara.SyntaxError: If rules have syntax errors
    """
    check_yara_available()

    # Collect all .yar files with namespaces
    yar_files: dict[str, str] = {}

    for path in rule_paths:
        path = Path(path)

        if path.is_file() and path.suffix in (".yar", ".yara"):
            if not _uses_external_vars(path):
                namespace = path.stem
                yar_files[namespace] = str(path)

        elif path.is_dir():
            for yar_file in path.rglob("*.yar"):
                if _uses_external_vars(yar_file):
                    continue
                # Create namespace from directory + filename
                rel_path = yar_file.relative_to(path)
                namespace = str(rel_path.with_suffix("")).replace("/", "_").replace("\\", "_")
                yar_files[namespace] = str(yar_file)

            # Also check .yara extension
            for yar_file in path.rglob("*.yara"):
                if _uses_external_vars(yar_file):
                    continue
                rel_path = yar_file.relative_to(path)
                namespace = str(rel_path.with_suffix("")).replace("/", "_").replace("\\", "_")
                yar_files[namespace] = str(yar_file)

    if not yar_files:
        raise ValueError(f"No valid YARA rules found in: {rule_paths}")

    # Check cache
    cache_key = _get_cache_key(yar_files)
    if use_cache and cache_key in _rule_cache:
        rules, timestamp = _rule_cache[cache_key]
        if time.time() - timestamp < CACHE_TTL_SECONDS:
            return rules

    # Compile rules
    rules = yara.compile(filepaths=yar_files)

    # Update cache
    if use_cache:
        _rule_cache[cache_key] = (rules, time.time())

    return rules


def get_default_rules_path() -> Optional[Path]:
    """Get path to bundled YARA rules if available."""
    # Check for bundled rules in package
    package_dir = Path(__file__).parent.parent
    rules_dir = package_dir / "rules"

    if rules_dir.exists() and any(rules_dir.glob("*.yar")):
        return rules_dir

    return None


def scan_file(
    file_path: str | Path,
    rules: Optional[Any] = None,
    rule_paths: Optional[list[str | Path]] = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Scan a file with YARA rules.

    Args:
        file_path: Path to file to scan
        rules: Pre-compiled rules (preferred for batch scanning)
        rule_paths: Paths to compile rules from (if rules not provided)
        timeout: Scan timeout in seconds

    Returns:
        {
            "file": str,
            "file_size": int,
            "matches": [
                {
                    "rule": str,
                    "namespace": str,
                    "tags": list[str],
                    "meta": dict,
                    "strings": list[dict]  # matched strings with offsets
                }
            ],
            "match_count": int,
            "scan_time_ms": float
        }

    Raises:
        ImportError: If yara-python not installed
        FileNotFoundError: If file not found
        ValueError: If neither rules nor rule_paths provided
    """
    check_yara_available()

    start_time = time.perf_counter()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Get or compile rules
    if rules is None:
        if rule_paths is None:
            # Try bundled rules
            default_path = get_default_rules_path()
            if default_path:
                rule_paths = [default_path]
            else:
                raise ValueError(
                    "Must provide either 'rules' or 'rule_paths'. "
                    "No bundled rules found."
                )
        rules = compile_rules(rule_paths)

    # Scan file
    try:
        matches = rules.match(str(file_path), timeout=timeout)
    except yara.TimeoutError:
        elapsed = (time.perf_counter() - start_time) * 1000
        return {
            "file": str(file_path),
            "file_size": file_path.stat().st_size,
            "matches": [],
            "match_count": 0,
            "scan_time_ms": round(elapsed, 2),
            "error": f"Scan timed out after {timeout}s",
        }
    except yara.Error as e:
        elapsed = (time.perf_counter() - start_time) * 1000
        return {
            "file": str(file_path),
            "file_size": file_path.stat().st_size,
            "matches": [],
            "match_count": 0,
            "scan_time_ms": round(elapsed, 2),
            "error": f"YARA scan error: {e}",
        }

    # Format matches
    result_matches = []
    for match in matches:
        match_info = {
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
        }

        # Extract matched strings (limit to prevent huge output)
        strings_info = []
        if hasattr(match, "strings") and match.strings:
            for string_match in match.strings[:10]:
                string_info = {
                    "identifier": string_match.identifier,
                }
                # Get first instance offset and data
                if hasattr(string_match, "instances") and string_match.instances:
                    inst = string_match.instances[0]
                    string_info["offset"] = inst.offset
                    # Truncate matched data to prevent huge output
                    if hasattr(inst, "matched_data"):
                        data = inst.matched_data[:64]
                        # Try to decode as string, otherwise hex
                        try:
                            string_info["data"] = data.decode("utf-8", errors="replace")
                        except Exception:
                            string_info["data"] = data.hex()
                strings_info.append(string_info)

        if strings_info:
            match_info["strings"] = strings_info

        result_matches.append(match_info)

    elapsed = (time.perf_counter() - start_time) * 1000

    return {
        "file": str(file_path),
        "file_size": file_path.stat().st_size,
        "matches": result_matches,
        "match_count": len(result_matches),
        "scan_time_ms": round(elapsed, 2),
    }


def scan_directory(
    directory: str | Path,
    rules: Optional[Any] = None,
    rule_paths: Optional[list[str | Path]] = None,
    file_pattern: str = "*",
    recursive: bool = True,
    limit: int = 100,
    timeout_per_file: int = 30,
) -> dict[str, Any]:
    """
    Scan directory for malware with YARA rules.

    Args:
        directory: Directory to scan
        rules: Pre-compiled rules
        rule_paths: Paths to compile rules from
        file_pattern: Glob pattern for files (e.g., "*.exe", "*.dll")
        recursive: Search subdirectories
        limit: Maximum files to scan
        timeout_per_file: Timeout per file in seconds

    Returns:
        {
            "directory": str,
            "files_scanned": int,
            "files_matched": int,
            "matches": [...],  # Only files with matches
            "errors": [...],   # Files that failed to scan
            "truncated": bool,
        }
    """
    check_yara_available()

    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    # Compile rules once for batch scanning
    if rules is None:
        if rule_paths is None:
            default_path = get_default_rules_path()
            if default_path:
                rule_paths = [default_path]
            else:
                raise ValueError(
                    "Must provide either 'rules' or 'rule_paths'. "
                    "No bundled rules found."
                )
        rules = compile_rules(rule_paths)

    glob_func = directory.rglob if recursive else directory.glob

    results = []
    errors = []
    scanned = 0

    for file_path in glob_func(file_pattern):
        if not file_path.is_file():
            continue

        # Skip very large files (>100MB) to avoid memory issues
        try:
            if file_path.stat().st_size > 100 * 1024 * 1024:
                continue
        except OSError:
            continue

        if scanned >= limit:
            break

        try:
            result = scan_file(file_path, rules=rules, timeout=timeout_per_file)
            scanned += 1

            # Only include files with matches
            if result["match_count"] > 0:
                results.append(result)

        except Exception as e:
            errors.append({
                "file": str(file_path),
                "error": str(e),
            })

    return {
        "directory": str(directory),
        "pattern": file_pattern,
        "recursive": recursive,
        "files_scanned": scanned,
        "files_matched": len(results),
        "matches": results,
        "errors": errors[:10],  # Limit error output
        "truncated": scanned >= limit,
    }


def scan_bytes(
    data: bytes,
    rules: Optional[Any] = None,
    rule_paths: Optional[list[str | Path]] = None,
    identifier: str = "memory",
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Scan raw bytes with YARA rules.

    Args:
        data: Bytes to scan
        rules: Pre-compiled rules
        rule_paths: Paths to compile rules from
        identifier: Name to identify the scanned data
        timeout: Scan timeout in seconds

    Returns:
        {
            "identifier": str,
            "size": int,
            "matches": [...],
            "match_count": int,
            "scan_time_ms": float,
        }
    """
    check_yara_available()

    start_time = time.perf_counter()

    # Get or compile rules
    if rules is None:
        if rule_paths is None:
            default_path = get_default_rules_path()
            if default_path:
                rule_paths = [default_path]
            else:
                raise ValueError(
                    "Must provide either 'rules' or 'rule_paths'. "
                    "No bundled rules found."
                )
        rules = compile_rules(rule_paths)

    # Scan data
    try:
        matches = rules.match(data=data, timeout=timeout)
    except yara.TimeoutError:
        elapsed = (time.perf_counter() - start_time) * 1000
        return {
            "identifier": identifier,
            "size": len(data),
            "matches": [],
            "match_count": 0,
            "scan_time_ms": round(elapsed, 2),
            "error": f"Scan timed out after {timeout}s",
        }
    except yara.Error as e:
        elapsed = (time.perf_counter() - start_time) * 1000
        return {
            "identifier": identifier,
            "size": len(data),
            "matches": [],
            "match_count": 0,
            "scan_time_ms": round(elapsed, 2),
            "error": f"YARA scan error: {e}",
        }

    # Format matches (simplified for bytes scan)
    result_matches = []
    for match in matches:
        result_matches.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
        })

    elapsed = (time.perf_counter() - start_time) * 1000

    return {
        "identifier": identifier,
        "size": len(data),
        "matches": result_matches,
        "match_count": len(result_matches),
        "scan_time_ms": round(elapsed, 2),
    }


def list_rules(
    rule_paths: Optional[list[str | Path]] = None,
) -> dict[str, Any]:
    """
    List available YARA rules.

    Args:
        rule_paths: Paths to list rules from (uses bundled if not specified)

    Returns:
        {
            "rule_files": [{"path": str, "namespace": str}],
            "total_files": int,
            "source": str,
        }
    """
    if rule_paths is None:
        default_path = get_default_rules_path()
        if default_path:
            rule_paths = [default_path]
            source = "bundled"
        else:
            return {
                "rule_files": [],
                "total_files": 0,
                "source": "none",
                "error": "No bundled rules found and no rule_paths provided",
            }
    else:
        source = "custom"

    rule_files = []

    for path in rule_paths:
        path = Path(path)

        if path.is_file() and path.suffix in (".yar", ".yara"):
            if not _uses_external_vars(path):
                rule_files.append({
                    "path": str(path),
                    "namespace": path.stem,
                    "skipped": False,
                })
            else:
                rule_files.append({
                    "path": str(path),
                    "namespace": path.stem,
                    "skipped": True,
                    "skip_reason": "Uses external variables",
                })

        elif path.is_dir():
            for yar_file in sorted(path.rglob("*.yar")):
                rel_path = yar_file.relative_to(path)
                namespace = str(rel_path.with_suffix("")).replace("/", "_").replace("\\", "_")

                if _uses_external_vars(yar_file):
                    rule_files.append({
                        "path": str(yar_file),
                        "namespace": namespace,
                        "skipped": True,
                        "skip_reason": "Uses external variables",
                    })
                else:
                    rule_files.append({
                        "path": str(yar_file),
                        "namespace": namespace,
                        "skipped": False,
                    })

    return {
        "rule_files": rule_files,
        "total_files": len(rule_files),
        "usable_files": len([r for r in rule_files if not r.get("skipped")]),
        "source": source,
    }
