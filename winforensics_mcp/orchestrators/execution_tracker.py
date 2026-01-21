"""
Execution Tracker Orchestrator

Correlates evidence from Prefetch, Amcache, and SRUM to answer:
"Was this binary executed?"

Provides a unified view with confidence scoring and timeline reconstruction.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..parsers.prefetch_parser import (
    search_prefetch_for_executable,
    PYSCCA_AVAILABLE,
)
from ..parsers.amcache_parser import (
    parse_amcache,
    search_amcache_by_sha1,
    REGISTRY_AVAILABLE,
)
from ..parsers.srum_parser import (
    parse_srum_app_resource_usage,
    parse_srum_network_usage,
    PYESEDB_AVAILABLE,
)


# Common artifact path patterns (relative to artifacts_dir)
ARTIFACT_PATHS = {
    "prefetch": [
        "Windows/prefetch",
        "Windows/Prefetch",
        "prefetch",
        "Prefetch",
        "C/Windows/prefetch",
        "C/Windows/Prefetch",
    ],
    "amcache": [
        "Windows/appcompat/Programs/Amcache.hve",
        "Windows/AppCompat/Programs/Amcache.hve",
        "Amcache.hve",
        "C/Windows/appcompat/Programs/Amcache.hve",
        "C/Windows/AppCompat/Programs/Amcache.hve",
    ],
    "srum": [
        "Windows/System32/sru/SRUDB.dat",
        "Windows/system32/sru/SRUDB.dat",
        "SRUDB.dat",
        "sru/SRUDB.dat",
        "C/Windows/System32/sru/SRUDB.dat",
    ],
}


def _is_sha1(value: str) -> bool:
    """Check if string looks like a SHA1 hash"""
    return bool(re.match(r'^[a-fA-F0-9]{40}$', value))


def _is_sha256(value: str) -> bool:
    """Check if string looks like a SHA256 hash"""
    return bool(re.match(r'^[a-fA-F0-9]{64}$', value))


def _extract_executable_name(target: str) -> str:
    """Extract executable name from path or target string"""
    # If it's a hash, return as-is
    if _is_sha1(target) or _is_sha256(target):
        return target

    # Extract filename from path
    if '\\' in target:
        target = target.split('\\')[-1]
    if '/' in target:
        target = target.split('/')[-1]

    return target


def find_artifact_paths(
    artifacts_dir: str | Path,
) -> dict[str, Optional[Path]]:
    """
    Find artifact files within a directory structure.

    Searches common Windows artifact path patterns.

    Args:
        artifacts_dir: Base directory containing forensic artifacts

    Returns:
        Dictionary mapping artifact type to found path (or None if not found)
    """
    artifacts_dir = Path(artifacts_dir)
    found = {
        "prefetch": None,
        "amcache": None,
        "srum": None,
    }

    if not artifacts_dir.exists():
        return found

    # Search for each artifact type
    for artifact_type, patterns in ARTIFACT_PATHS.items():
        for pattern in patterns:
            candidate = artifacts_dir / pattern
            if candidate.exists():
                found[artifact_type] = candidate
                break

    return found


def _search_prefetch(
    prefetch_dir: Path,
    target: str,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
) -> dict[str, Any]:
    """Search Prefetch for execution evidence"""
    if not PYSCCA_AVAILABLE:
        return {
            "source": "Prefetch",
            "available": False,
            "error": "libscca-python not installed",
        }

    try:
        exe_name = _extract_executable_name(target)

        # Search by executable name
        result = search_prefetch_for_executable(
            prefetch_dir,
            exe_name,
            include_loaded_files=False,
        )

        if not result.get("found"):
            return {
                "source": "Prefetch",
                "available": True,
                "found": False,
                "path": str(prefetch_dir),
            }

        # Extract evidence
        evidence = result.get("execution_evidence", [])

        # Filter by time range if specified
        if time_range_start or time_range_end:
            filtered_evidence = []
            for entry in evidence:
                run_times = entry.get("last_run_times", [])
                filtered_times = []
                for rt in run_times:
                    try:
                        rt_dt = datetime.fromisoformat(rt.replace("Z", "+00:00"))
                        if time_range_start and rt_dt < time_range_start:
                            continue
                        if time_range_end and rt_dt > time_range_end:
                            continue
                        filtered_times.append(rt)
                    except ValueError:
                        filtered_times.append(rt)

                if filtered_times:
                    entry = entry.copy()
                    entry["last_run_times"] = filtered_times
                    entry["last_run"] = filtered_times[0] if filtered_times else None
                    filtered_evidence.append(entry)

            evidence = filtered_evidence

        if not evidence:
            return {
                "source": "Prefetch",
                "available": True,
                "found": False,
                "path": str(prefetch_dir),
                "note": "No executions in specified time range",
            }

        # Aggregate findings
        total_run_count = sum(e.get("run_count", 0) for e in evidence)
        all_run_times = []
        for entry in evidence:
            all_run_times.extend(entry.get("last_run_times", []))

        all_run_times = sorted(set(all_run_times), reverse=True)

        return {
            "source": "Prefetch",
            "available": True,
            "found": True,
            "path": str(prefetch_dir),
            "finding": f"Executed {total_run_count} times, last at {all_run_times[0]}" if all_run_times else f"Executed {total_run_count} times",
            "run_count": total_run_count,
            "last_run": all_run_times[0] if all_run_times else None,
            "run_times": all_run_times[:8],  # Limit to 8 most recent
            "prefetch_files": [e.get("filename") for e in evidence],
        }

    except Exception as e:
        return {
            "source": "Prefetch",
            "available": True,
            "found": False,
            "error": str(e),
        }


def _search_amcache(
    amcache_path: Path,
    target: str,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
) -> dict[str, Any]:
    """Search Amcache for execution evidence"""
    if not REGISTRY_AVAILABLE:
        return {
            "source": "Amcache",
            "available": False,
            "error": "python-registry not installed",
        }

    try:
        # Determine search method based on target type
        if _is_sha1(target):
            result = search_amcache_by_sha1(amcache_path, target)
            matches = result.get("matches", [])
        else:
            exe_name = _extract_executable_name(target)
            result = parse_amcache(
                amcache_path,
                name_filter=exe_name.replace(".exe", ""),  # Match without extension
                time_range_start=time_range_start.isoformat() if time_range_start else None,
                time_range_end=time_range_end.isoformat() if time_range_end else None,
                limit=50,
            )
            matches = result.get("entries", [])

        if not matches:
            return {
                "source": "Amcache",
                "available": True,
                "found": False,
                "path": str(amcache_path),
            }

        # Extract key findings
        first_match = matches[0]
        sha1 = first_match.get("sha1")
        first_seen = first_match.get("key_timestamp")
        file_path = first_match.get("path")

        finding_parts = []
        if sha1:
            finding_parts.append(f"SHA1: {sha1}")
        if first_seen:
            finding_parts.append(f"First seen: {first_seen}")

        return {
            "source": "Amcache",
            "available": True,
            "found": True,
            "path": str(amcache_path),
            "finding": ", ".join(finding_parts) if finding_parts else "Entry found",
            "sha1": sha1,
            "first_seen": first_seen,
            "file_path": file_path,
            "product_name": first_match.get("product_name"),
            "publisher": first_match.get("publisher"),
            "version": first_match.get("version"),
            "match_count": len(matches),
        }

    except Exception as e:
        return {
            "source": "Amcache",
            "available": True,
            "found": False,
            "error": str(e),
        }


def _search_srum(
    srum_path: Path,
    target: str,
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
) -> dict[str, Any]:
    """Search SRUM for execution evidence"""
    if not PYESEDB_AVAILABLE:
        return {
            "source": "SRUM",
            "available": False,
            "error": "libesedb-python not installed",
        }

    try:
        exe_name = _extract_executable_name(target)

        # Search app resource usage
        app_result = parse_srum_app_resource_usage(
            srum_path,
            app_filter=exe_name.replace(".exe", ""),
            time_range_start=time_range_start.isoformat() if time_range_start else None,
            time_range_end=time_range_end.isoformat() if time_range_end else None,
            limit=100,
        )

        # Search network usage
        net_result = parse_srum_network_usage(
            srum_path,
            app_filter=exe_name.replace(".exe", ""),
            limit=100,
        )

        app_entries = app_result.get("entries", [])
        net_entries = net_result.get("entries", [])

        if not app_entries and not net_entries:
            return {
                "source": "SRUM",
                "available": True,
                "found": False,
                "path": str(srum_path),
            }

        # Calculate totals from app resource usage
        total_foreground_time = 0
        total_background_time = 0
        total_bytes_read = 0
        total_bytes_written = 0

        for entry in app_entries:
            fg_time = entry.get("foreground_cycle_time") or 0
            bg_time = entry.get("background_cycle_time") or 0
            total_foreground_time += fg_time
            total_background_time += bg_time

            total_bytes_read += (entry.get("foreground_bytes_read") or 0) + (entry.get("background_bytes_read") or 0)
            total_bytes_written += (entry.get("foreground_bytes_written") or 0) + (entry.get("background_bytes_written") or 0)

        # Calculate network totals
        total_bytes_sent = sum(e.get("bytes_sent") or 0 for e in net_entries)
        total_bytes_recv = sum(e.get("bytes_received") or 0 for e in net_entries)

        # Build finding string
        finding_parts = []
        if total_bytes_sent or total_bytes_recv:
            sent_mb = total_bytes_sent / (1024 * 1024)
            recv_mb = total_bytes_recv / (1024 * 1024)
            finding_parts.append(f"Network activity: {sent_mb:.1f} MB sent, {recv_mb:.1f} MB received")

        # Convert cycle time to approximate seconds (very rough estimate)
        # Cycle time is in 100-nanosecond intervals
        if total_foreground_time:
            runtime_sec = total_foreground_time / 10_000_000
            if runtime_sec > 3600:
                finding_parts.append(f"Foreground time: {runtime_sec/3600:.1f} hours")
            elif runtime_sec > 60:
                finding_parts.append(f"Foreground time: {runtime_sec/60:.1f} minutes")
            else:
                finding_parts.append(f"Foreground time: {runtime_sec:.0f} seconds")

        if total_bytes_read or total_bytes_written:
            read_mb = total_bytes_read / (1024 * 1024)
            write_mb = total_bytes_written / (1024 * 1024)
            finding_parts.append(f"Disk I/O: {read_mb:.1f} MB read, {write_mb:.1f} MB written")

        return {
            "source": "SRUM",
            "available": True,
            "found": True,
            "path": str(srum_path),
            "finding": "; ".join(finding_parts) if finding_parts else "Activity recorded",
            "record_count": len(app_entries) + len(net_entries),
            "network": {
                "bytes_sent": total_bytes_sent,
                "bytes_received": total_bytes_recv,
            } if total_bytes_sent or total_bytes_recv else None,
            "resource_usage": {
                "foreground_cycle_time": total_foreground_time,
                "background_cycle_time": total_background_time,
                "bytes_read": total_bytes_read,
                "bytes_written": total_bytes_written,
            } if total_foreground_time or total_bytes_read else None,
        }

    except Exception as e:
        return {
            "source": "SRUM",
            "available": True,
            "found": False,
            "error": str(e),
        }


def _build_timeline(evidence_results: list[dict]) -> list[dict]:
    """Build unified timeline from evidence"""
    timeline = []

    for result in evidence_results:
        if not result.get("found"):
            continue

        source = result.get("source")

        if source == "Prefetch":
            run_times = result.get("run_times", [])
            for i, rt in enumerate(run_times):
                event_type = "Last execution" if i == 0 else f"Execution #{len(run_times) - i}"
                timeline.append({
                    "time": rt,
                    "source": "Prefetch",
                    "event": f"{event_type} (Prefetch)",
                })

        elif source == "Amcache":
            first_seen = result.get("first_seen")
            if first_seen:
                timeline.append({
                    "time": first_seen,
                    "source": "Amcache",
                    "event": "First recorded in Amcache (execution/installation)",
                })

        # SRUM doesn't provide precise timestamps suitable for timeline

    # Sort by time (most recent first)
    timeline.sort(key=lambda x: x.get("time", ""), reverse=True)

    return timeline


def _calculate_confidence(evidence_results: list[dict]) -> str:
    """Calculate confidence level based on evidence"""
    sources_found = sum(1 for r in evidence_results if r.get("found"))
    sources_available = sum(1 for r in evidence_results if r.get("available", True))

    if sources_found == 0:
        return "NONE"
    elif sources_found >= 3:
        return "HIGH"
    elif sources_found >= 2:
        return "MEDIUM"
    elif sources_found == 1 and sources_available >= 2:
        return "LOW"
    else:
        return "LOW"


def investigate_execution(
    target: str,
    artifacts_dir: str | Path,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    prefetch_path: Optional[str] = None,
    amcache_path: Optional[str] = None,
    srum_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Comprehensive execution analysis.

    Correlates Prefetch, Amcache, and SRUM to prove or disprove binary execution.

    Args:
        target: Executable name, path, or SHA1 hash to investigate
        artifacts_dir: Base directory containing forensic artifacts
        time_range_start: ISO format datetime, filter events after this time
        time_range_end: ISO format datetime, filter events before this time
        prefetch_path: Override auto-detected Prefetch directory path
        amcache_path: Override auto-detected Amcache.hve path
        srum_path: Override auto-detected SRUDB.dat path

    Returns:
        Comprehensive execution evidence with confidence scoring and timeline
    """
    artifacts_dir = Path(artifacts_dir)

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    # Find artifact paths (auto-detect or use overrides)
    found_paths = find_artifact_paths(artifacts_dir)

    prefetch_dir = Path(prefetch_path) if prefetch_path else found_paths.get("prefetch")
    amcache_file = Path(amcache_path) if amcache_path else found_paths.get("amcache")
    srum_file = Path(srum_path) if srum_path else found_paths.get("srum")

    # Track which artifacts were searched
    artifacts_searched = {
        "prefetch": prefetch_dir is not None and prefetch_dir.exists(),
        "amcache": amcache_file is not None and amcache_file.exists(),
        "srum": srum_file is not None and srum_file.exists(),
    }

    evidence_results = []

    # Search each artifact source
    if prefetch_dir and prefetch_dir.exists():
        prefetch_result = _search_prefetch(prefetch_dir, target, start_dt, end_dt)
        evidence_results.append(prefetch_result)
    else:
        evidence_results.append({
            "source": "Prefetch",
            "available": False,
            "error": "Prefetch directory not found",
        })

    if amcache_file and amcache_file.exists():
        amcache_result = _search_amcache(amcache_file, target, start_dt, end_dt)
        evidence_results.append(amcache_result)
    else:
        evidence_results.append({
            "source": "Amcache",
            "available": False,
            "error": "Amcache.hve not found",
        })

    if srum_file and srum_file.exists():
        srum_result = _search_srum(srum_file, target, start_dt, end_dt)
        evidence_results.append(srum_result)
    else:
        evidence_results.append({
            "source": "SRUM",
            "available": False,
            "error": "SRUDB.dat not found",
        })

    # Determine if execution was confirmed
    execution_confirmed = any(r.get("found") for r in evidence_results)

    # Calculate confidence
    confidence = _calculate_confidence(evidence_results)

    # Build timeline
    timeline = _build_timeline(evidence_results)

    # Extract SHA1 if found in Amcache
    sha1_hash = None
    for result in evidence_results:
        if result.get("source") == "Amcache" and result.get("sha1"):
            sha1_hash = result["sha1"]
            break

    return {
        "target": target,
        "target_type": "sha1" if _is_sha1(target) else "sha256" if _is_sha256(target) else "executable",
        "artifacts_dir": str(artifacts_dir),
        "execution_confirmed": execution_confirmed,
        "confidence": confidence,
        "sha1": sha1_hash,
        "time_range": {
            "start": time_range_start,
            "end": time_range_end,
        } if time_range_start or time_range_end else None,
        "artifacts_searched": artifacts_searched,
        "evidence": evidence_results,
        "timeline": timeline if timeline else None,
        "summary": _generate_summary(target, execution_confirmed, confidence, evidence_results),
    }


def _generate_summary(
    target: str,
    execution_confirmed: bool,
    confidence: str,
    evidence_results: list[dict],
) -> str:
    """Generate human-readable summary"""
    if not execution_confirmed:
        sources_searched = [r["source"] for r in evidence_results if r.get("available", True)]
        return f"No execution evidence found for '{target}' in {', '.join(sources_searched)}"

    findings = []
    for result in evidence_results:
        if result.get("found") and result.get("finding"):
            findings.append(f"- {result['source']}: {result['finding']}")

    summary = f"Execution of '{target}' confirmed ({confidence} confidence):\n"
    summary += "\n".join(findings)

    return summary
