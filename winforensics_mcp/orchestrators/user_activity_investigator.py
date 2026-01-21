"""
User Activity Investigator Orchestrator

Correlates evidence from Browser History, ShellBags, LNK files, and RecentDocs
to build a comprehensive view of user activity on a Windows system.

Answers questions like:
- What did the user browse to?
- What files did they access?
- What folders did they navigate?
- What did they download?
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..parsers.browser_parser import (
    parse_browser_history,
    search_browser_history,
    get_browser_downloads,
)
from ..parsers.shellbags_parser import (
    parse_shellbags,
    search_shellbags,
    find_suspicious_folders,
)
from ..parsers.lnk_parser import (
    parse_lnk_directory,
    get_recent_files,
    search_lnk_for_target,
    PYLNK_AVAILABLE,
)
from ..parsers.registry_parser import (
    get_registry_key,
    REGISTRY_AVAILABLE,
)


# Common artifact path patterns (relative to artifacts_dir or user profile)
USER_ARTIFACT_PATHS = {
    "browser_chrome": [
        "Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History",
        "AppData/Local/Google/Chrome/User Data/Default/History",
        "Google/Chrome/User Data/Default/History",
    ],
    "browser_edge": [
        "Users/{user}/AppData/Local/Microsoft/Edge/User Data/Default/History",
        "AppData/Local/Microsoft/Edge/User Data/Default/History",
        "Microsoft/Edge/User Data/Default/History",
    ],
    "browser_firefox": [
        "Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
        "AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
        "Mozilla/Firefox/Profiles/*/places.sqlite",
    ],
    "recent_lnk": [
        "Users/{user}/AppData/Roaming/Microsoft/Windows/Recent",
        "AppData/Roaming/Microsoft/Windows/Recent",
        "Recent",
    ],
    "usrclass": [
        "Users/{user}/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "AppData/Local/Microsoft/Windows/UsrClass.dat",
        "UsrClass.dat",
    ],
    "ntuser": [
        "Users/{user}/NTUSER.DAT",
        "NTUSER.DAT",
    ],
}


def _find_user_artifacts(
    artifacts_dir: Path,
    username: Optional[str] = None,
) -> dict[str, Optional[Path]]:
    """
    Find user activity artifacts within a directory structure.

    Args:
        artifacts_dir: Base directory containing forensic artifacts
        username: Optional username to narrow search

    Returns:
        Dictionary mapping artifact type to found path (or None)
    """
    found = {
        "browser_history": None,
        "browser_type": None,
        "recent_lnk": None,
        "usrclass": None,
        "ntuser": None,
    }

    if not artifacts_dir.exists():
        return found

    # Try to find browser history (check multiple browsers)
    for browser_type, paths in [
        ("edge", USER_ARTIFACT_PATHS["browser_edge"]),
        ("chrome", USER_ARTIFACT_PATHS["browser_chrome"]),
    ]:
        for pattern in paths:
            if username:
                pattern = pattern.replace("{user}", username)
            else:
                pattern = pattern.replace("{user}/", "*/")

            # Handle glob patterns
            if "*" in pattern:
                matches = list(artifacts_dir.glob(pattern))
                if matches:
                    found["browser_history"] = matches[0]
                    found["browser_type"] = browser_type
                    break
            else:
                candidate = artifacts_dir / pattern
                if candidate.exists():
                    found["browser_history"] = candidate
                    found["browser_type"] = browser_type
                    break

        if found["browser_history"]:
            break

    # Try Firefox separately (different file name)
    if not found["browser_history"]:
        for pattern in USER_ARTIFACT_PATHS["browser_firefox"]:
            if username:
                pattern = pattern.replace("{user}", username)
            else:
                pattern = pattern.replace("{user}/", "*/")

            matches = list(artifacts_dir.glob(pattern))
            if matches:
                found["browser_history"] = matches[0]
                found["browser_type"] = "firefox"
                break

    # Find Recent LNK folder
    for pattern in USER_ARTIFACT_PATHS["recent_lnk"]:
        if username:
            pattern = pattern.replace("{user}", username)
        else:
            pattern = pattern.replace("{user}/", "*/")

        if "*" in pattern:
            matches = list(artifacts_dir.glob(pattern))
            if matches and matches[0].is_dir():
                found["recent_lnk"] = matches[0]
                break
        else:
            candidate = artifacts_dir / pattern
            if candidate.exists() and candidate.is_dir():
                found["recent_lnk"] = candidate
                break

    # Find UsrClass.dat
    for pattern in USER_ARTIFACT_PATHS["usrclass"]:
        if username:
            pattern = pattern.replace("{user}", username)
        else:
            pattern = pattern.replace("{user}/", "*/")

        if "*" in pattern:
            matches = list(artifacts_dir.glob(pattern))
            if matches:
                found["usrclass"] = matches[0]
                break
        else:
            candidate = artifacts_dir / pattern
            if candidate.exists():
                found["usrclass"] = candidate
                break

    # Find NTUSER.DAT
    for pattern in USER_ARTIFACT_PATHS["ntuser"]:
        if username:
            pattern = pattern.replace("{user}", username)
        else:
            pattern = pattern.replace("{user}/", "*/")

        if "*" in pattern:
            matches = list(artifacts_dir.glob(pattern))
            if matches:
                found["ntuser"] = matches[0]
                break
        else:
            candidate = artifacts_dir / pattern
            if candidate.exists():
                found["ntuser"] = candidate
                break

    return found


def _search_browser(
    history_path: Path,
    browser_type: str,
    keyword: Optional[str],
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    limit: int = 50,
) -> dict[str, Any]:
    """Search browser history for activity"""
    try:
        if keyword:
            result = search_browser_history(
                history_path,
                keyword=keyword,
                browser=browser_type,
                include_downloads=True,
                limit=limit,
            )
        else:
            result = parse_browser_history(
                history_path,
                browser=browser_type,
                include_downloads=True,
                time_range_start=time_range_start.isoformat() if time_range_start else None,
                time_range_end=time_range_end.isoformat() if time_range_end else None,
                limit=limit,
            )

        visits = result.get("visits", [])
        downloads = result.get("downloads", [])

        if not visits and not downloads:
            return {
                "source": "Browser",
                "available": True,
                "found": False,
                "path": str(history_path),
                "browser": browser_type,
            }

        # Build summary
        finding_parts = []
        if visits:
            finding_parts.append(f"{len(visits)} visits")
        if downloads:
            finding_parts.append(f"{len(downloads)} downloads")

        # Extract domains from visits
        domains = set()
        for v in visits[:20]:
            url = v.get("url", "")
            if "://" in url:
                domain = url.split("://")[1].split("/")[0]
                domains.add(domain)

        return {
            "source": "Browser",
            "available": True,
            "found": True,
            "path": str(history_path),
            "browser": browser_type,
            "finding": ", ".join(finding_parts),
            "total_visits": result.get("total_visits", len(visits)),
            "total_downloads": result.get("total_downloads", len(downloads)),
            "visits": visits[:20],
            "downloads": downloads[:10],
            "top_domains": list(domains)[:10],
        }

    except Exception as e:
        return {
            "source": "Browser",
            "available": True,
            "found": False,
            "error": str(e),
            "path": str(history_path),
        }


def _search_shellbags(
    usrclass_path: Path,
    keyword: Optional[str],
    suspicious_only: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    """Search ShellBags for folder navigation"""
    if not REGISTRY_AVAILABLE:
        return {
            "source": "ShellBags",
            "available": False,
            "error": "python-registry not installed",
        }

    try:
        if suspicious_only:
            result = find_suspicious_folders(usrclass_path, limit=limit)
        elif keyword:
            result = search_shellbags(usrclass_path, keyword, limit=limit)
        else:
            result = parse_shellbags(usrclass_path, limit=limit)

        folders = result.get("folders", [])
        if suspicious_only:
            folders = result.get("suspicious_folders", [])

        if not folders:
            return {
                "source": "ShellBags",
                "available": True,
                "found": False,
                "path": str(usrclass_path),
            }

        # Identify interesting patterns
        network_shares = [f for f in folders if f.get("path", "").startswith("\\\\")]
        removable = [f for f in folders if any(
            x in f.get("path", "").lower() for x in ["removable", "usb", ":\\"]
            if len(f.get("path", "").split(":")[0]) == 1
        )]

        return {
            "source": "ShellBags",
            "available": True,
            "found": True,
            "path": str(usrclass_path),
            "finding": f"{len(folders)} folders navigated",
            "total_folders": result.get("total_found", len(folders)),
            "folders": folders[:30],
            "network_shares": [f.get("path") for f in network_shares][:10] if network_shares else None,
            "has_removable_access": len(removable) > 0,
        }

    except Exception as e:
        return {
            "source": "ShellBags",
            "available": True,
            "found": False,
            "error": str(e),
            "path": str(usrclass_path),
        }


def _search_lnk_files(
    recent_dir: Path,
    keyword: Optional[str],
    limit: int = 50,
) -> dict[str, Any]:
    """Search LNK files for recent file access"""
    if not PYLNK_AVAILABLE:
        return {
            "source": "LNK Files",
            "available": False,
            "error": "pylnk3 not installed",
        }

    try:
        if keyword:
            result = search_lnk_for_target(recent_dir, keyword, recursive=True, limit=limit)
        else:
            result = parse_lnk_directory(recent_dir, recursive=True, limit=limit)

        lnk_files = result.get("lnk_files", [])

        if not lnk_files:
            return {
                "source": "LNK Files",
                "available": True,
                "found": False,
                "path": str(recent_dir),
            }

        # Categorize by file type
        exe_targets = []
        doc_targets = []
        other_targets = []

        for lnk in lnk_files:
            target = lnk.get("target_path", "").lower()
            if target.endswith((".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs")):
                exe_targets.append(lnk)
            elif target.endswith((".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".csv")):
                doc_targets.append(lnk)
            else:
                other_targets.append(lnk)

        finding_parts = []
        if exe_targets:
            finding_parts.append(f"{len(exe_targets)} executables")
        if doc_targets:
            finding_parts.append(f"{len(doc_targets)} documents")
        if other_targets:
            finding_parts.append(f"{len(other_targets)} other files")

        return {
            "source": "LNK Files",
            "available": True,
            "found": True,
            "path": str(recent_dir),
            "finding": ", ".join(finding_parts) if finding_parts else f"{len(lnk_files)} files",
            "total_files": result.get("total_found", len(lnk_files)),
            "lnk_files": lnk_files[:30],
            "executables_accessed": [l.get("target_path") for l in exe_targets][:10] if exe_targets else None,
            "documents_accessed": [l.get("target_path") for l in doc_targets][:10] if doc_targets else None,
        }

    except Exception as e:
        return {
            "source": "LNK Files",
            "available": True,
            "found": False,
            "error": str(e),
            "path": str(recent_dir),
        }


def _search_recentdocs(
    ntuser_path: Path,
    keyword: Optional[str],
    limit: int = 50,
) -> dict[str, Any]:
    """Search RecentDocs registry for recent file access"""
    if not REGISTRY_AVAILABLE:
        return {
            "source": "RecentDocs",
            "available": False,
            "error": "python-registry not installed",
        }

    try:
        # RecentDocs is under Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        result = get_registry_key(
            ntuser_path,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            max_depth=2,
        )

        if result.get("error"):
            return {
                "source": "RecentDocs",
                "available": True,
                "found": False,
                "path": str(ntuser_path),
                "error": result.get("error"),
            }

        # Parse RecentDocs entries
        recent_files = []
        subkeys = result.get("subkeys", [])

        # Main RecentDocs key has MRU list, subkeys are by extension
        values = result.get("values", [])
        for val in values:
            if val.get("name", "").isdigit():
                # Binary value containing filename
                data = val.get("data")
                if data and isinstance(data, bytes):
                    try:
                        # RecentDocs format: null-terminated Unicode string
                        filename = data.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
                        if filename and not filename.startswith(('.', '$')):
                            recent_files.append({
                                "filename": filename.rstrip('\x00'),
                                "extension": None,
                                "mru_position": int(val.get("name")),
                            })
                    except Exception:
                        pass

        # Check extension subkeys
        for subkey in subkeys:
            ext = subkey.get("name", "")
            if ext.startswith("."):
                subkey_values = subkey.get("values", [])
                for val in subkey_values:
                    if val.get("name", "").isdigit():
                        data = val.get("data")
                        if data and isinstance(data, bytes):
                            try:
                                filename = data.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
                                if filename:
                                    recent_files.append({
                                        "filename": filename.rstrip('\x00'),
                                        "extension": ext,
                                        "mru_position": int(val.get("name")),
                                    })
                            except Exception:
                                pass

        # Filter by keyword if specified
        if keyword:
            keyword_lower = keyword.lower()
            recent_files = [f for f in recent_files if keyword_lower in f.get("filename", "").lower()]

        if not recent_files:
            return {
                "source": "RecentDocs",
                "available": True,
                "found": False,
                "path": str(ntuser_path),
            }

        # Sort by MRU position (lower = more recent)
        recent_files.sort(key=lambda x: x.get("mru_position", 999))

        # Categorize
        extensions = {}
        for f in recent_files:
            ext = f.get("extension") or "unknown"
            extensions[ext] = extensions.get(ext, 0) + 1

        return {
            "source": "RecentDocs",
            "available": True,
            "found": True,
            "path": str(ntuser_path),
            "finding": f"{len(recent_files)} recently accessed files",
            "total_files": len(recent_files),
            "recent_files": recent_files[:limit],
            "extensions_accessed": extensions,
        }

    except Exception as e:
        return {
            "source": "RecentDocs",
            "available": True,
            "found": False,
            "error": str(e),
            "path": str(ntuser_path),
        }


def _build_activity_timeline(evidence_results: list[dict]) -> list[dict]:
    """Build unified timeline from user activity evidence"""
    timeline = []

    for result in evidence_results:
        if not result.get("found"):
            continue

        source = result.get("source")

        if source == "Browser":
            # Add recent visits with timestamps
            for visit in result.get("visits", [])[:10]:
                visit_time = visit.get("visit_time") or visit.get("last_visit_time")
                if visit_time:
                    timeline.append({
                        "time": visit_time,
                        "source": "Browser",
                        "event": f"Visited: {visit.get('url', 'unknown')[:80]}",
                        "details": visit.get("title"),
                    })

            # Add downloads
            for dl in result.get("downloads", [])[:5]:
                dl_time = dl.get("start_time") or dl.get("end_time")
                if dl_time:
                    timeline.append({
                        "time": dl_time,
                        "source": "Browser",
                        "event": f"Downloaded: {dl.get('filename', 'unknown')}",
                        "details": dl.get("url"),
                    })

        elif source == "LNK Files":
            # Add LNK files with access times
            for lnk in result.get("lnk_files", [])[:10]:
                access_time = lnk.get("access_time") or lnk.get("creation_time")
                if access_time:
                    timeline.append({
                        "time": access_time,
                        "source": "LNK",
                        "event": f"Accessed: {lnk.get('target_path', 'unknown')}",
                    })

        elif source == "ShellBags":
            # ShellBags have less precise timestamps but still useful
            for folder in result.get("folders", [])[:10]:
                mod_time = folder.get("last_modified") or folder.get("modified_time")
                if mod_time:
                    timeline.append({
                        "time": mod_time,
                        "source": "ShellBags",
                        "event": f"Navigated: {folder.get('path', 'unknown')}",
                    })

    # Sort by time (most recent first)
    def parse_time(t):
        if not t:
            return ""
        if isinstance(t, str):
            return t
        return str(t)

    timeline.sort(key=lambda x: parse_time(x.get("time", "")), reverse=True)

    return timeline[:50]  # Limit timeline entries


def _calculate_confidence(evidence_results: list[dict]) -> str:
    """Calculate confidence level based on evidence"""
    sources_found = sum(1 for r in evidence_results if r.get("found"))
    sources_available = sum(1 for r in evidence_results if r.get("available", True))

    if sources_found == 0:
        return "NONE"
    elif sources_found >= 4:
        return "HIGH"
    elif sources_found >= 2:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_activity_summary(
    keyword: Optional[str],
    evidence_results: list[dict],
    confidence: str,
) -> str:
    """Generate human-readable activity summary"""
    found_sources = [r for r in evidence_results if r.get("found")]

    if not found_sources:
        searched = [r["source"] for r in evidence_results if r.get("available", True)]
        if keyword:
            return f"No activity found matching '{keyword}' in {', '.join(searched)}"
        return f"No user activity found in {', '.join(searched)}"

    summary_parts = []
    if keyword:
        summary_parts.append(f"Activity matching '{keyword}' found ({confidence} confidence):")
    else:
        summary_parts.append(f"User activity found ({confidence} confidence):")

    for result in found_sources:
        finding = result.get("finding", "Activity detected")
        summary_parts.append(f"- {result['source']}: {finding}")

    return "\n".join(summary_parts)


def investigate_user_activity(
    artifacts_dir: str | Path,
    keyword: Optional[str] = None,
    username: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    suspicious_only: bool = False,
    browser_path: Optional[str] = None,
    lnk_path: Optional[str] = None,
    usrclass_path: Optional[str] = None,
    ntuser_path: Optional[str] = None,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Comprehensive user activity investigation.

    Correlates Browser History, ShellBags, LNK files, and RecentDocs
    to build a complete picture of user activity.

    Args:
        artifacts_dir: Base directory containing forensic artifacts or user profile
        keyword: Optional keyword to search across all sources
        username: Optional username to narrow artifact search
        time_range_start: ISO format datetime, filter events after this time
        time_range_end: ISO format datetime, filter events before this time
        suspicious_only: For ShellBags, only return suspicious folder access
        browser_path: Override auto-detected browser History path
        lnk_path: Override auto-detected Recent LNK folder path
        usrclass_path: Override auto-detected UsrClass.dat path
        ntuser_path: Override auto-detected NTUSER.DAT path
        limit: Maximum results per source

    Returns:
        Comprehensive user activity evidence with confidence scoring and timeline
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
    found_paths = _find_user_artifacts(artifacts_dir, username)

    browser_file = Path(browser_path) if browser_path else found_paths.get("browser_history")
    browser_type = found_paths.get("browser_type", "auto")
    recent_dir = Path(lnk_path) if lnk_path else found_paths.get("recent_lnk")
    usrclass_file = Path(usrclass_path) if usrclass_path else found_paths.get("usrclass")
    ntuser_file = Path(ntuser_path) if ntuser_path else found_paths.get("ntuser")

    # Track which artifacts were searched
    artifacts_searched = {
        "browser": browser_file is not None and browser_file.exists(),
        "lnk_files": recent_dir is not None and recent_dir.exists(),
        "shellbags": usrclass_file is not None and usrclass_file.exists(),
        "recentdocs": ntuser_file is not None and ntuser_file.exists(),
    }

    evidence_results = []

    # Search each artifact source
    if browser_file and browser_file.exists():
        browser_result = _search_browser(
            browser_file, browser_type, keyword, start_dt, end_dt, limit
        )
        evidence_results.append(browser_result)
    else:
        evidence_results.append({
            "source": "Browser",
            "available": False,
            "error": "Browser history not found",
        })

    if usrclass_file and usrclass_file.exists():
        shellbags_result = _search_shellbags(
            usrclass_file, keyword, suspicious_only, limit
        )
        evidence_results.append(shellbags_result)
    else:
        evidence_results.append({
            "source": "ShellBags",
            "available": False,
            "error": "UsrClass.dat not found",
        })

    if recent_dir and recent_dir.exists():
        lnk_result = _search_lnk_files(recent_dir, keyword, limit)
        evidence_results.append(lnk_result)
    else:
        evidence_results.append({
            "source": "LNK Files",
            "available": False,
            "error": "Recent folder not found",
        })

    if ntuser_file and ntuser_file.exists():
        recentdocs_result = _search_recentdocs(ntuser_file, keyword, limit)
        evidence_results.append(recentdocs_result)
    else:
        evidence_results.append({
            "source": "RecentDocs",
            "available": False,
            "error": "NTUSER.DAT not found",
        })

    # Determine if activity was found
    activity_found = any(r.get("found") for r in evidence_results)

    # Calculate confidence
    confidence = _calculate_confidence(evidence_results)

    # Build timeline
    timeline = _build_activity_timeline(evidence_results)

    # Generate summary
    summary = _generate_activity_summary(keyword, evidence_results, confidence)

    return {
        "artifacts_dir": str(artifacts_dir),
        "username": username,
        "keyword": keyword,
        "activity_found": activity_found,
        "confidence": confidence,
        "time_range": {
            "start": time_range_start,
            "end": time_range_end,
        } if time_range_start or time_range_end else None,
        "artifacts_searched": artifacts_searched,
        "evidence": evidence_results,
        "timeline": timeline if timeline else None,
        "summary": summary,
    }
