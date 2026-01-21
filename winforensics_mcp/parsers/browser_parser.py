"""
Browser History Parser Module

Parses browser history and downloads from Edge, Chrome, and Firefox.
Uses built-in sqlite3 - no external dependencies required.
"""
from __future__ import annotations

import sqlite3
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..config import MAX_REGISTRY_RESULTS


# Chromium timestamp epoch: January 1, 1601 UTC (Windows FILETIME)
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Firefox timestamp: microseconds since Unix epoch
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _chromium_time_to_datetime(timestamp: int) -> Optional[datetime]:
    """Convert Chromium timestamp (microseconds since 1601) to datetime"""
    if not timestamp or timestamp <= 0:
        return None
    try:
        # Chromium uses microseconds since January 1, 1601
        seconds = timestamp / 1_000_000
        dt = CHROMIUM_EPOCH.replace(tzinfo=timezone.utc)
        from datetime import timedelta
        return dt + timedelta(seconds=seconds)
    except (ValueError, OverflowError, OSError):
        return None


def _firefox_time_to_datetime(timestamp: int) -> Optional[datetime]:
    """Convert Firefox timestamp (microseconds since Unix epoch) to datetime"""
    if not timestamp or timestamp <= 0:
        return None
    try:
        # Firefox uses microseconds since Unix epoch
        seconds = timestamp / 1_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime to ISO string"""
    if dt is None:
        return None
    return dt.isoformat()


def _detect_browser_type(db_path: Path) -> str:
    """Detect browser type from database schema"""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Check for Chromium-specific tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        # Firefox has 'moz_places' and 'moz_historyvisits'
        if 'moz_places' in tables:
            return 'firefox'
        # Chromium has 'urls' and 'visits'
        elif 'urls' in tables and 'visits' in tables:
            # Check if Edge-specific tables exist
            if 'edge_urls' in tables:
                return 'edge'
            return 'chrome'

        return 'unknown'
    except Exception:
        return 'unknown'


def _copy_to_temp(db_path: Path) -> Path:
    """
    Copy database to temp location to avoid SQLite locking issues.
    Browser databases are often locked when the browser is running.
    """
    temp_dir = tempfile.mkdtemp(prefix="browser_history_")
    temp_path = Path(temp_dir) / db_path.name
    shutil.copy2(db_path, temp_path)

    # Also copy any WAL/SHM files if present
    for suffix in ['-wal', '-shm', '-journal']:
        wal_path = db_path.parent / (db_path.name + suffix)
        if wal_path.exists():
            shutil.copy2(wal_path, temp_path.parent / (temp_path.name + suffix))

    return temp_path


def _parse_chromium_history(
    db_path: Path,
    url_filter: Optional[str],
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    limit: int,
) -> dict[str, Any]:
    """Parse Chromium-based browser history (Chrome/Edge)"""
    results = []
    total_matched = 0
    filter_lower = url_filter.lower() if url_filter else None

    # Copy to temp to avoid locking
    temp_path = _copy_to_temp(db_path)

    try:
        conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Query URLs with visit information
        query = """
            SELECT
                u.id,
                u.url,
                u.title,
                u.visit_count,
                u.typed_count,
                u.last_visit_time,
                u.hidden
            FROM urls u
            ORDER BY u.last_visit_time DESC
        """

        cursor.execute(query)

        for row in cursor.fetchall():
            url = row['url']
            title = row['title']
            last_visit_time = _chromium_time_to_datetime(row['last_visit_time'])

            # Apply filters
            if filter_lower:
                if filter_lower not in url.lower() and (not title or filter_lower not in title.lower()):
                    continue

            if time_range_start and last_visit_time and last_visit_time < time_range_start:
                continue
            if time_range_end and last_visit_time and last_visit_time > time_range_end:
                continue

            total_matched += 1

            # Only add to results if under limit
            if len(results) < limit:
                results.append({
                    'url': url,
                    'title': title,
                    'visit_count': row['visit_count'],
                    'typed_count': row['typed_count'],
                    'last_visit_time': _format_datetime(last_visit_time),
                    'hidden': bool(row['hidden']),
                })

        conn.close()
    finally:
        # Cleanup temp files
        shutil.rmtree(temp_path.parent, ignore_errors=True)

    return {
        "entries": results,
        "total_matched": total_matched,
        "returned": len(results),
        "truncated": total_matched > len(results),
    }


def _parse_chromium_downloads(
    db_path: Path,
    url_filter: Optional[str],
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    limit: int,
) -> dict[str, Any]:
    """Parse Chromium-based browser downloads (Chrome/Edge)"""
    results = []
    total_matched = 0
    filter_lower = url_filter.lower() if url_filter else None

    # Download states
    STATE_MAP = {
        0: 'in_progress',
        1: 'complete',
        2: 'cancelled',
        3: 'interrupted',
    }

    # Danger types
    DANGER_MAP = {
        0: 'not_dangerous',
        1: 'dangerous_file',
        2: 'dangerous_url',
        3: 'dangerous_content',
        4: 'maybe_dangerous_content',
        5: 'uncommon_content',
        6: 'user_validated',
        7: 'dangerous_host',
        8: 'potentially_unwanted',
        9: 'allowlisted_by_policy',
        10: 'async_scanning',
        11: 'blocked_password_protected',
        12: 'blocked_too_large',
        13: 'sensitive_content_warning',
        14: 'sensitive_content_block',
        15: 'deep_scanned_failed',
        16: 'deep_scanned_safe',
        17: 'deep_scanned_opened_dangerous',
        18: 'prompt_for_scanning',
        19: 'blocked_unsupported_filetype',
        20: 'dangerous_account_compromise',
    }

    temp_path = _copy_to_temp(db_path)

    try:
        conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT
                id,
                target_path,
                start_time,
                end_time,
                received_bytes,
                total_bytes,
                state,
                danger_type,
                referrer,
                tab_url,
                mime_type,
                original_mime_type
            FROM downloads
            ORDER BY start_time DESC
        """

        cursor.execute(query)

        for row in cursor.fetchall():
            target_path = row['target_path']
            tab_url = row['tab_url']
            referrer = row['referrer']
            start_time = _chromium_time_to_datetime(row['start_time'])
            end_time = _chromium_time_to_datetime(row['end_time'])

            # Apply filters
            if filter_lower:
                match = False
                if target_path and filter_lower in target_path.lower():
                    match = True
                if tab_url and filter_lower in tab_url.lower():
                    match = True
                if referrer and filter_lower in referrer.lower():
                    match = True
                if not match:
                    continue

            if time_range_start and start_time and start_time < time_range_start:
                continue
            if time_range_end and start_time and start_time > time_range_end:
                continue

            total_matched += 1

            if len(results) < limit:
                results.append({
                    'target_path': target_path,
                    'url': tab_url,
                    'referrer': referrer if referrer else None,
                    'start_time': _format_datetime(start_time),
                    'end_time': _format_datetime(end_time),
                    'received_bytes': row['received_bytes'],
                    'total_bytes': row['total_bytes'],
                    'state': STATE_MAP.get(row['state'], f"unknown_{row['state']}"),
                    'danger_type': DANGER_MAP.get(row['danger_type'], f"unknown_{row['danger_type']}"),
                    'mime_type': row['mime_type'],
                })

        conn.close()
    finally:
        shutil.rmtree(temp_path.parent, ignore_errors=True)

    return {
        "entries": results,
        "total_matched": total_matched,
        "returned": len(results),
        "truncated": total_matched > len(results),
    }


def _parse_firefox_history(
    db_path: Path,
    url_filter: Optional[str],
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    limit: int,
) -> dict[str, Any]:
    """Parse Firefox browser history"""
    results = []
    total_matched = 0
    filter_lower = url_filter.lower() if url_filter else None

    temp_path = _copy_to_temp(db_path)

    try:
        conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT
                p.id,
                p.url,
                p.title,
                p.visit_count,
                p.last_visit_date,
                p.hidden,
                p.typed
            FROM moz_places p
            WHERE p.visit_count > 0
            ORDER BY p.last_visit_date DESC
        """

        cursor.execute(query)

        for row in cursor.fetchall():
            url = row['url']
            title = row['title']
            last_visit_time = _firefox_time_to_datetime(row['last_visit_date'])

            # Apply filters
            if filter_lower:
                if filter_lower not in url.lower() and (not title or filter_lower not in title.lower()):
                    continue

            if time_range_start and last_visit_time and last_visit_time < time_range_start:
                continue
            if time_range_end and last_visit_time and last_visit_time > time_range_end:
                continue

            total_matched += 1

            if len(results) < limit:
                results.append({
                    'url': url,
                    'title': title,
                    'visit_count': row['visit_count'],
                    'typed_count': row['typed'],
                    'last_visit_time': _format_datetime(last_visit_time),
                    'hidden': bool(row['hidden']),
                })

        conn.close()
    finally:
        shutil.rmtree(temp_path.parent, ignore_errors=True)

    return {
        "entries": results,
        "total_matched": total_matched,
        "returned": len(results),
        "truncated": total_matched > len(results),
    }


def _parse_firefox_downloads(
    db_path: Path,
    url_filter: Optional[str],
    time_range_start: Optional[datetime],
    time_range_end: Optional[datetime],
    limit: int,
) -> dict[str, Any]:
    """Parse Firefox downloads from moz_annos table"""
    results = []
    total_matched = 0
    filter_lower = url_filter.lower() if url_filter else None

    temp_path = _copy_to_temp(db_path)

    try:
        conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Firefox stores downloads in moz_annos with specific annotation names
        query = """
            SELECT
                p.url,
                a.content,
                a.dateAdded
            FROM moz_annos a
            JOIN moz_places p ON a.place_id = p.id
            JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
            WHERE aa.name = 'downloads/destinationFileURI'
            ORDER BY a.dateAdded DESC
        """

        try:
            cursor.execute(query)

            for row in cursor.fetchall():
                url = row['url']
                target_path = row['content']
                download_time = _firefox_time_to_datetime(row['dateAdded'])

                # Apply filters
                if filter_lower:
                    if filter_lower not in url.lower() and filter_lower not in target_path.lower():
                        continue

                if time_range_start and download_time and download_time < time_range_start:
                    continue
                if time_range_end and download_time and download_time > time_range_end:
                    continue

                total_matched += 1

                # Clean up file:// prefix
                if target_path and target_path.startswith('file:///'):
                    target_path = target_path[8:]  # Remove file:///

                if len(results) < limit:
                    results.append({
                        'target_path': target_path,
                        'url': url,
                        'start_time': _format_datetime(download_time),
                    })

        except sqlite3.OperationalError:
            # moz_annos table might not exist in newer Firefox versions
            pass

        conn.close()
    finally:
        shutil.rmtree(temp_path.parent, ignore_errors=True)

    return {
        "entries": results,
        "total_matched": total_matched,
        "returned": len(results),
        "truncated": total_matched > len(results),
    }


def parse_browser_history(
    history_path: str | Path,
    browser: str = "auto",
    include_downloads: bool = True,
    url_filter: Optional[str] = None,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Parse browser history and downloads from Edge, Chrome, or Firefox.

    Args:
        history_path: Path to History SQLite file or browser profile directory
        browser: Browser type (auto, chrome, edge, firefox)
        include_downloads: Include download history
        url_filter: Filter by URL or title (case-insensitive substring)
        time_range_start: ISO datetime, filter visits after this time
        time_range_end: ISO datetime, filter visits before this time
        limit: Maximum number of results per category

    Returns:
        Dictionary with history and downloads
    """
    history_path = Path(history_path)

    if not history_path.exists():
        raise FileNotFoundError(f"History file not found: {history_path}")

    # If directory provided, look for History file
    if history_path.is_dir():
        # Check for Chromium-based browsers
        chromium_history = history_path / "History"
        firefox_history = history_path / "places.sqlite"

        if chromium_history.exists():
            history_path = chromium_history
        elif firefox_history.exists():
            history_path = firefox_history
        else:
            raise FileNotFoundError(
                f"No browser history found in {history_path}. "
                "Expected 'History' (Chrome/Edge) or 'places.sqlite' (Firefox)"
            )

    # Parse time filters
    start_dt = None
    end_dt = None
    if time_range_start:
        start_dt = datetime.fromisoformat(time_range_start.replace("Z", "+00:00"))
    if time_range_end:
        end_dt = datetime.fromisoformat(time_range_end.replace("Z", "+00:00"))

    # Detect browser type
    if browser == "auto":
        browser = _detect_browser_type(history_path)

    result = {
        "path": str(history_path),
        "browser": browser,
        "history": [],
        "downloads": [] if include_downloads else None,
        "history_count": 0,
        "history_total": 0,
        "history_truncated": False,
        "downloads_count": 0 if include_downloads else None,
        "downloads_total": 0 if include_downloads else None,
        "downloads_truncated": False if include_downloads else None,
    }

    # Parse based on browser type
    if browser in ('chrome', 'edge'):
        history_result = _parse_chromium_history(
            history_path, url_filter, start_dt, end_dt, limit
        )
        result['history'] = history_result['entries']
        result['history_total'] = history_result['total_matched']
        result['history_truncated'] = history_result['truncated']

        if include_downloads:
            downloads_result = _parse_chromium_downloads(
                history_path, url_filter, start_dt, end_dt, limit
            )
            result['downloads'] = downloads_result['entries']
            result['downloads_total'] = downloads_result['total_matched']
            result['downloads_truncated'] = downloads_result['truncated']
    elif browser == 'firefox':
        history_result = _parse_firefox_history(
            history_path, url_filter, start_dt, end_dt, limit
        )
        result['history'] = history_result['entries']
        result['history_total'] = history_result['total_matched']
        result['history_truncated'] = history_result['truncated']
        if include_downloads:
            downloads_result = _parse_firefox_downloads(
                history_path, url_filter, start_dt, end_dt, limit
            )
            result['downloads'] = downloads_result['entries']
            result['downloads_total'] = downloads_result['total_matched']
            result['downloads_truncated'] = downloads_result['truncated']
    else:
        raise ValueError(f"Unknown or unsupported browser type: {browser}")

    result['history_count'] = len(result['history'])
    if include_downloads and result['downloads'] is not None:
        result['downloads_count'] = len(result['downloads'])

    return result


def search_browser_history(
    history_path: str | Path,
    keyword: str,
    browser: str = "auto",
    include_downloads: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Search browser history for a keyword.

    Args:
        history_path: Path to History SQLite file
        keyword: Keyword to search for in URLs and titles
        browser: Browser type (auto, chrome, edge, firefox)
        include_downloads: Include download history
        limit: Maximum results

    Returns:
        Matching history entries
    """
    return parse_browser_history(
        history_path,
        browser=browser,
        include_downloads=include_downloads,
        url_filter=keyword,
        limit=limit,
    )


def get_browser_downloads(
    history_path: str | Path,
    browser: str = "auto",
    dangerous_only: bool = False,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Get browser downloads with optional filtering for dangerous files.

    Args:
        history_path: Path to History SQLite file
        browser: Browser type (auto, chrome, edge, firefox)
        dangerous_only: Only return downloads flagged as dangerous
        time_range_start: ISO datetime filter
        time_range_end: ISO datetime filter
        limit: Maximum results

    Returns:
        Download history
    """
    result = parse_browser_history(
        history_path,
        browser=browser,
        include_downloads=True,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        limit=limit * 2 if dangerous_only else limit,
    )

    downloads = result.get('downloads', [])
    total_matched = result.get('downloads_total', len(downloads))

    if dangerous_only:
        # Filter for dangerous downloads
        dangerous_downloads = [
            d for d in downloads
            if d.get('danger_type') and d['danger_type'] != 'not_dangerous'
        ]
        total_matched = len(dangerous_downloads)
        downloads = dangerous_downloads[:limit]

    return {
        "path": result['path'],
        "browser": result['browser'],
        "downloads": downloads,
        "downloads_count": len(downloads),
        "downloads_total": total_matched,
        "truncated": total_matched > len(downloads),
        "filter": "dangerous_only" if dangerous_only else None,
    }
