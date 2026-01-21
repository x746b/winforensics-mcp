"""
IOC Hunter Orchestrator

Searches for Indicators of Compromise across all forensic artifacts.
Supports hashes (MD5/SHA1/SHA256), filenames, IPs, and domains.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .execution_tracker import find_artifact_paths, ARTIFACT_PATHS

# Import parsers with availability checks
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
    PYESEDB_AVAILABLE,
)
from ..parsers.mft_parser import (
    parse_mft,
    MFT_AVAILABLE,
)
from ..parsers.usn_parser import (
    parse_usn_journal,
)
from ..parsers.browser_parser import (
    parse_browser_history,
)
from ..parsers.evtx_parser import (
    get_evtx_events,
    EVTX_AVAILABLE,
)

# Extended artifact paths for IOC hunting
IOC_ARTIFACT_PATHS = {
    **ARTIFACT_PATHS,
    "mft": [
        "$MFT",
        "C/$MFT",
        "Windows/$MFT",
    ],
    "usn": [
        "$Extend/$UsnJrnl_$J",
        "$UsnJrnl_$J",
        "$J",
        "C/$Extend/$UsnJrnl_$J",
    ],
    "browser": [
        # Edge
        "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
        # Chrome
        "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
        # Firefox
        "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    ],
    "evtx": [
        "Windows/System32/winevt/Logs",
        "Windows/System32/winevt/logs",
        "C/Windows/System32/winevt/Logs",
        "C/Windows/System32/winevt/logs",
        "winevt/Logs",
        "winevt/logs",
    ],
}


def _detect_ioc_type(ioc: str) -> str:
    """
    Auto-detect IOC type from the value.

    Returns one of: md5, sha1, sha256, ip, domain, filename
    """
    ioc = ioc.strip()

    # Hash patterns
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return "md5"
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return "sha1"
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "sha256"

    # IP address (IPv4)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return "ip"

    # IPv6 (simplified check)
    if re.match(r'^[a-fA-F0-9:]+$', ioc) and ':' in ioc:
        return "ip"

    # Domain (contains dots, no spaces, no path separators)
    if '.' in ioc and ' ' not in ioc and '\\' not in ioc and '/' not in ioc:
        # Check if it looks like a domain (not just a filename with extension)
        parts = ioc.split('.')
        if len(parts) >= 2:
            tld = parts[-1].lower()
            # Common TLDs
            if tld in ('com', 'net', 'org', 'io', 'co', 'gov', 'edu', 'ru', 'cn',
                       'uk', 'de', 'fr', 'jp', 'br', 'au', 'in', 'it', 'es', 'nl',
                       'xyz', 'top', 'info', 'biz', 'online', 'site', 'club'):
                return "domain"

    # Default to filename
    return "filename"


def _find_extended_artifact_paths(
    artifacts_dir: Path,
) -> dict[str, Optional[Path]]:
    """
    Find artifact files within a directory structure.
    Extended version that includes MFT, USN, browser, and EVTX paths.
    """
    found = {
        "prefetch": None,
        "amcache": None,
        "srum": None,
        "mft": None,
        "usn": None,
        "browser": [],
        "evtx": None,
    }

    if not artifacts_dir.exists():
        return found

    # Search for each artifact type
    for artifact_type, patterns in IOC_ARTIFACT_PATHS.items():
        if artifact_type == "browser":
            # Browser paths can have wildcards, handle specially
            for pattern in patterns:
                if '*' in pattern:
                    # Glob for user directories
                    base_pattern = pattern.split('*')[0]
                    base_path = artifacts_dir / base_pattern.rstrip('/')
                    if base_path.parent.exists():
                        for user_dir in base_path.parent.iterdir():
                            if user_dir.is_dir():
                                rest_pattern = pattern.split('*', 1)[1]
                                full_path = user_dir / rest_pattern.lstrip('/')
                                if full_path.exists():
                                    found["browser"].append(full_path)
                else:
                    candidate = artifacts_dir / pattern
                    if candidate.exists():
                        found["browser"].append(candidate)
        else:
            for pattern in patterns:
                candidate = artifacts_dir / pattern
                if candidate.exists():
                    found[artifact_type] = candidate
                    break

    return found


def _search_prefetch_ioc(
    prefetch_dir: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search Prefetch for IOC (only supports filename search)"""
    if not PYSCCA_AVAILABLE:
        return {
            "source": "Prefetch",
            "available": False,
            "error": "libscca-python not installed",
        }

    # Prefetch only supports filename search
    if ioc_type not in ("filename", "md5", "sha1", "sha256"):
        return {
            "source": "Prefetch",
            "available": True,
            "searched": False,
            "note": f"Prefetch does not support {ioc_type} search",
        }

    # For hashes, we can't search Prefetch directly
    if ioc_type in ("md5", "sha1", "sha256"):
        return {
            "source": "Prefetch",
            "available": True,
            "searched": False,
            "note": "Prefetch does not contain file hashes",
        }

    try:
        # Extract just the filename part
        search_term = ioc
        if '\\' in search_term:
            search_term = search_term.split('\\')[-1]
        if '/' in search_term:
            search_term = search_term.split('/')[-1]

        result = search_prefetch_for_executable(
            prefetch_dir,
            search_term,
            include_loaded_files=False,
        )

        if not result.get("found"):
            return {
                "source": "Prefetch",
                "available": True,
                "searched": True,
                "found": False,
                "path": str(prefetch_dir),
            }

        evidence = result.get("execution_evidence", [])
        matches = []
        for entry in evidence:
            matches.append({
                "executable": entry.get("executable"),
                "run_count": entry.get("run_count"),
                "last_run": entry.get("last_run"),
                "prefetch_file": entry.get("filename"),
            })

        return {
            "source": "Prefetch",
            "available": True,
            "searched": True,
            "found": True,
            "path": str(prefetch_dir),
            "matches": matches,
            "match_count": len(matches),
        }

    except Exception as e:
        return {
            "source": "Prefetch",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_amcache_ioc(
    amcache_path: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search Amcache for IOC"""
    if not REGISTRY_AVAILABLE:
        return {
            "source": "Amcache",
            "available": False,
            "error": "python-registry not installed",
        }

    try:
        if ioc_type == "sha1":
            result = search_amcache_by_sha1(amcache_path, ioc)
            matches = result.get("matches", [])
        elif ioc_type in ("filename", "md5", "sha256"):
            # Search by name/path
            search_term = ioc
            if '\\' in search_term:
                search_term = search_term.split('\\')[-1]
            if '/' in search_term:
                search_term = search_term.split('/')[-1]

            result = parse_amcache(
                amcache_path,
                name_filter=search_term.replace('.exe', '').replace('.dll', ''),
                limit=30,
            )
            matches = result.get("entries", [])
        else:
            # IP/domain not searchable in Amcache
            return {
                "source": "Amcache",
                "available": True,
                "searched": False,
                "note": f"Amcache does not support {ioc_type} search",
            }

        if not matches:
            return {
                "source": "Amcache",
                "available": True,
                "searched": True,
                "found": False,
                "path": str(amcache_path),
            }

        formatted_matches = []
        for entry in matches[:10]:  # Limit matches
            formatted_matches.append({
                "name": entry.get("name"),
                "path": entry.get("path"),
                "sha1": entry.get("sha1"),
                "first_seen": entry.get("key_timestamp"),
                "publisher": entry.get("publisher"),
            })

        return {
            "source": "Amcache",
            "available": True,
            "searched": True,
            "found": True,
            "path": str(amcache_path),
            "matches": formatted_matches,
            "match_count": len(matches),
        }

    except Exception as e:
        return {
            "source": "Amcache",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_srum_ioc(
    srum_path: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search SRUM for IOC (filename only)"""
    if not PYESEDB_AVAILABLE:
        return {
            "source": "SRUM",
            "available": False,
            "error": "libesedb-python not installed",
        }

    if ioc_type not in ("filename",):
        return {
            "source": "SRUM",
            "available": True,
            "searched": False,
            "note": f"SRUM does not support {ioc_type} search",
        }

    try:
        search_term = ioc
        if '\\' in search_term:
            search_term = search_term.split('\\')[-1]
        if '/' in search_term:
            search_term = search_term.split('/')[-1]

        result = parse_srum_app_resource_usage(
            srum_path,
            app_filter=search_term.replace('.exe', ''),
            limit=30,
        )

        entries = result.get("entries", [])

        if not entries:
            return {
                "source": "SRUM",
                "available": True,
                "searched": True,
                "found": False,
                "path": str(srum_path),
            }

        # Aggregate SRUM data
        total_foreground = sum(e.get("foreground_cycle_time") or 0 for e in entries)

        return {
            "source": "SRUM",
            "available": True,
            "searched": True,
            "found": True,
            "path": str(srum_path),
            "match_count": len(entries),
            "summary": {
                "total_records": len(entries),
                "total_foreground_time": total_foreground,
            },
        }

    except Exception as e:
        return {
            "source": "SRUM",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_mft_ioc(
    mft_path: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search MFT for IOC (filename/path only)"""
    if not MFT_AVAILABLE:
        return {
            "source": "MFT",
            "available": False,
            "error": "mft library not installed",
        }

    if ioc_type not in ("filename",):
        return {
            "source": "MFT",
            "available": True,
            "searched": False,
            "note": f"MFT does not support {ioc_type} search",
        }

    try:
        search_term = ioc
        # Extract just filename for search
        if '\\' in search_term:
            search_term = search_term.split('\\')[-1]
        if '/' in search_term:
            search_term = search_term.split('/')[-1]

        result = parse_mft(
            mft_path,
            file_path_filter=search_term,
            output_mode="summary",
            limit=20,
        )

        entries = result.get("entries", [])

        if not entries:
            return {
                "source": "MFT",
                "available": True,
                "searched": True,
                "found": False,
                "path": str(mft_path),
            }

        matches = []
        for entry in entries[:10]:
            matches.append({
                "filename": entry.get("filename"),
                "path": entry.get("path"),
                "size": entry.get("size"),
                "created": entry.get("si_created"),
                "modified": entry.get("si_modified"),
                "is_timestomped": entry.get("is_timestomped"),
            })

        return {
            "source": "MFT",
            "available": True,
            "searched": True,
            "found": True,
            "path": str(mft_path),
            "matches": matches,
            "match_count": result.get("total_matched", len(entries)),
        }

    except Exception as e:
        return {
            "source": "MFT",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_usn_ioc(
    usn_path: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search USN Journal for IOC (filename only)"""
    if ioc_type not in ("filename",):
        return {
            "source": "USN Journal",
            "available": True,
            "searched": False,
            "note": f"USN Journal does not support {ioc_type} search",
        }

    try:
        search_term = ioc
        if '\\' in search_term:
            search_term = search_term.split('\\')[-1]
        if '/' in search_term:
            search_term = search_term.split('/')[-1]

        result = parse_usn_journal(
            usn_path,
            filename_filter=search_term,
            interesting_only=True,
            limit=20,
        )

        entries = result.get("records", [])

        if not entries:
            return {
                "source": "USN Journal",
                "available": True,
                "searched": True,
                "found": False,
                "path": str(usn_path),
            }

        matches = []
        for entry in entries[:10]:
            matches.append({
                "filename": entry.get("filename"),
                "timestamp": entry.get("timestamp"),
                "reason": entry.get("reason"),
            })

        return {
            "source": "USN Journal",
            "available": True,
            "searched": True,
            "found": True,
            "path": str(usn_path),
            "matches": matches,
            "match_count": result.get("total_matched", len(entries)),
        }

    except Exception as e:
        return {
            "source": "USN Journal",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_browser_ioc(
    browser_paths: list[Path],
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search browser history for IOC (domain, IP, URL, filename)"""
    if not browser_paths:
        return {
            "source": "Browser History",
            "available": False,
            "error": "No browser history files found",
        }

    # Browser can search URLs, domains, IPs, and downloaded filenames
    if ioc_type not in ("domain", "ip", "filename"):
        return {
            "source": "Browser History",
            "available": True,
            "searched": False,
            "note": f"Browser history search not useful for {ioc_type}",
        }

    try:
        all_matches = []
        searched_browsers = []

        for browser_path in browser_paths:
            try:
                result = parse_browser_history(
                    browser_path,
                    browser="auto",
                    include_downloads=True,
                    url_filter=ioc,
                    limit=20,
                )

                browser_type = result.get("browser", "unknown")
                searched_browsers.append(browser_type)

                # Check history
                history = result.get("history", [])
                for entry in history:
                    all_matches.append({
                        "type": "visit",
                        "browser": browser_type,
                        "url": entry.get("url"),
                        "title": entry.get("title"),
                        "visit_time": entry.get("visit_time"),
                    })

                # Check downloads
                downloads = result.get("downloads", [])
                for entry in downloads:
                    url = entry.get("url", "")
                    target = entry.get("target_path", "")
                    # Match IOC in URL or downloaded filename
                    if ioc.lower() in url.lower() or ioc.lower() in target.lower():
                        all_matches.append({
                            "type": "download",
                            "browser": browser_type,
                            "url": url,
                            "target_path": target,
                            "start_time": entry.get("start_time"),
                            "total_bytes": entry.get("total_bytes"),
                        })

            except Exception:
                continue

        if not all_matches:
            return {
                "source": "Browser History",
                "available": True,
                "searched": True,
                "found": False,
                "browsers_searched": searched_browsers,
            }

        return {
            "source": "Browser History",
            "available": True,
            "searched": True,
            "found": True,
            "browsers_searched": searched_browsers,
            "matches": all_matches[:15],  # Limit output
            "match_count": len(all_matches),
        }

    except Exception as e:
        return {
            "source": "Browser History",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _search_evtx_ioc(
    evtx_dir: Path,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    """Search EVTX logs for IOC"""
    if not EVTX_AVAILABLE:
        return {
            "source": "EVTX",
            "available": False,
            "error": "python-evtx not installed",
        }

    if not evtx_dir.exists():
        return {
            "source": "EVTX",
            "available": False,
            "error": "EVTX directory not found",
        }

    try:
        all_matches = []
        searched_files = []

        # Priority EVTX files for IOC hunting
        priority_logs = [
            "Security.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-DNS-Client%4Operational.evtx",
        ]

        # Find EVTX files
        evtx_files = []
        for log in priority_logs:
            log_path = evtx_dir / log
            if log_path.exists():
                evtx_files.append(log_path)

        # Also check for any .evtx files if priority logs not found
        if not evtx_files:
            evtx_files = list(evtx_dir.glob("*.evtx"))[:5]  # Limit to 5 files

        for evtx_file in evtx_files:
            try:
                result = get_evtx_events(
                    str(evtx_file),
                    contains=[ioc],
                    limit=10,
                )

                searched_files.append(evtx_file.name)
                events = result.get("events", [])

                for event in events:
                    all_matches.append({
                        "log_file": evtx_file.name,
                        "event_id": event.get("event_id"),
                        "timestamp": event.get("timestamp"),
                        "provider": event.get("provider"),
                    })

            except Exception:
                continue

        if not all_matches:
            return {
                "source": "EVTX",
                "available": True,
                "searched": True,
                "found": False,
                "logs_searched": searched_files,
            }

        return {
            "source": "EVTX",
            "available": True,
            "searched": True,
            "found": True,
            "logs_searched": searched_files,
            "matches": all_matches[:15],
            "match_count": len(all_matches),
        }

    except Exception as e:
        return {
            "source": "EVTX",
            "available": True,
            "searched": True,
            "found": False,
            "error": str(e),
        }


def _calculate_hunt_confidence(results: list[dict]) -> str:
    """Calculate confidence based on number of sources with matches"""
    sources_found = sum(1 for r in results if r.get("found"))
    sources_searched = sum(1 for r in results if r.get("searched"))

    if sources_found == 0:
        return "NONE"
    elif sources_found >= 4:
        return "HIGH"
    elif sources_found >= 2:
        return "MEDIUM"
    else:
        return "LOW"


def hunt_ioc(
    ioc: str,
    artifacts_dir: str | Path,
    ioc_type: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    prefetch_path: Optional[str] = None,
    amcache_path: Optional[str] = None,
    srum_path: Optional[str] = None,
    mft_path: Optional[str] = None,
    usn_path: Optional[str] = None,
    evtx_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Hunt for IOC across all forensic artifacts.

    Args:
        ioc: The indicator to search for (hash, filename, IP, domain)
        artifacts_dir: Base directory containing forensic artifacts
        ioc_type: Type of IOC (auto-detected if not specified):
                  md5, sha1, sha256, ip, domain, filename
        time_range_start: ISO format datetime, filter events after this time
        time_range_end: ISO format datetime, filter events before this time
        prefetch_path: Override auto-detected Prefetch directory
        amcache_path: Override auto-detected Amcache.hve path
        srum_path: Override auto-detected SRUDB.dat path
        mft_path: Override auto-detected $MFT path
        usn_path: Override auto-detected USN Journal path
        evtx_path: Override auto-detected EVTX directory

    Returns:
        Comprehensive IOC hunt results with matches from all sources
    """
    artifacts_dir = Path(artifacts_dir)
    ioc = ioc.strip()

    # Auto-detect IOC type if not specified
    detected_type = _detect_ioc_type(ioc)
    final_type = ioc_type if ioc_type and ioc_type != "auto" else detected_type

    # Find artifact paths
    found_paths = _find_extended_artifact_paths(artifacts_dir)

    # Apply overrides
    prefetch_dir = Path(prefetch_path) if prefetch_path else found_paths.get("prefetch")
    amcache_file = Path(amcache_path) if amcache_path else found_paths.get("amcache")
    srum_file = Path(srum_path) if srum_path else found_paths.get("srum")
    mft_file = Path(mft_path) if mft_path else found_paths.get("mft")
    usn_file = Path(usn_path) if usn_path else found_paths.get("usn")
    evtx_dir = Path(evtx_path) if evtx_path else found_paths.get("evtx")
    browser_paths = found_paths.get("browser", [])

    # Track artifacts searched
    artifacts_searched = {
        "prefetch": prefetch_dir is not None and prefetch_dir.exists(),
        "amcache": amcache_file is not None and amcache_file.exists(),
        "srum": srum_file is not None and srum_file.exists(),
        "mft": mft_file is not None and mft_file.exists(),
        "usn": usn_file is not None and usn_file.exists(),
        "browser": len(browser_paths) > 0,
        "evtx": evtx_dir is not None and evtx_dir.exists(),
    }

    results = []

    # Search each artifact source
    if prefetch_dir and prefetch_dir.exists():
        results.append(_search_prefetch_ioc(prefetch_dir, ioc, final_type))
    else:
        results.append({
            "source": "Prefetch",
            "available": False,
            "error": "Prefetch directory not found",
        })

    if amcache_file and amcache_file.exists():
        results.append(_search_amcache_ioc(amcache_file, ioc, final_type))
    else:
        results.append({
            "source": "Amcache",
            "available": False,
            "error": "Amcache.hve not found",
        })

    if srum_file and srum_file.exists():
        results.append(_search_srum_ioc(srum_file, ioc, final_type))
    else:
        results.append({
            "source": "SRUM",
            "available": False,
            "error": "SRUDB.dat not found",
        })

    if mft_file and mft_file.exists():
        results.append(_search_mft_ioc(mft_file, ioc, final_type))
    else:
        results.append({
            "source": "MFT",
            "available": False,
            "error": "$MFT not found",
        })

    if usn_file and usn_file.exists():
        results.append(_search_usn_ioc(usn_file, ioc, final_type))
    else:
        results.append({
            "source": "USN Journal",
            "available": False,
            "error": "USN Journal not found",
        })

    if browser_paths:
        results.append(_search_browser_ioc(browser_paths, ioc, final_type))
    else:
        results.append({
            "source": "Browser History",
            "available": False,
            "error": "No browser history found",
        })

    if evtx_dir and evtx_dir.exists():
        results.append(_search_evtx_ioc(evtx_dir, ioc, final_type))
    else:
        results.append({
            "source": "EVTX",
            "available": False,
            "error": "EVTX directory not found",
        })

    # Calculate overall confidence
    confidence = _calculate_hunt_confidence(results)

    # Count total matches
    total_matches = sum(
        r.get("match_count", 0) for r in results if r.get("found")
    )

    # Generate summary
    found_sources = [r["source"] for r in results if r.get("found")]
    not_found_sources = [r["source"] for r in results if r.get("searched") and not r.get("found")]
    unavailable_sources = [r["source"] for r in results if not r.get("available", True)]

    if found_sources:
        summary = f"IOC '{ioc}' ({final_type}) found in {len(found_sources)} source(s): {', '.join(found_sources)}"
    else:
        searched = [r["source"] for r in results if r.get("searched")]
        summary = f"IOC '{ioc}' ({final_type}) not found in any of the {len(searched)} sources searched"

    return {
        "ioc": ioc,
        "ioc_type": final_type,
        "ioc_type_detected": detected_type,
        "artifacts_dir": str(artifacts_dir),
        "found": len(found_sources) > 0,
        "confidence": confidence,
        "total_matches": total_matches,
        "sources_with_matches": found_sources,
        "sources_searched_no_match": not_found_sources,
        "sources_unavailable": unavailable_sources,
        "artifacts_searched": artifacts_searched,
        "results": results,
        "summary": summary,
    }
