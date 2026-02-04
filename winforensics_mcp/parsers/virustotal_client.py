"""
VirusTotal API client for threat intelligence lookups.

Features:
- Hash lookups (MD5/SHA1/SHA256)
- IP reputation
- Domain reputation
- File hash + lookup
- Rate limiting with backoff (free tier: 4 req/min)
- Caching to reduce API calls (24h TTL)
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False


# Cache: key -> (result, timestamp)
_cache: dict[str, tuple[dict, datetime]] = {}
CACHE_TTL = timedelta(hours=24)

# Rate limiting for free tier (4 requests/minute = 15 seconds between requests)
_last_request_time: float = 0
MIN_REQUEST_INTERVAL: float = 15.0  # seconds


def check_vt_available() -> None:
    """Raise error if vt-py library not available."""
    if not VT_AVAILABLE:
        raise ImportError(
            "vt-py library not installed. Install with: pip install vt-py"
        )


def get_api_key() -> Optional[str]:
    """
    Get VirusTotal API key from (in order):
    1. Environment variable: VIRUSTOTAL_API_KEY
    2. Config file: ~/.config/winforensics-mcp/vt_api_key
    3. None (functions will raise error)
    """
    # Environment variable
    if key := os.environ.get("VIRUSTOTAL_API_KEY"):
        return key.strip()

    # Config file
    config_file = Path.home() / ".config" / "winforensics-mcp" / "vt_api_key"
    if config_file.exists():
        return config_file.read_text().strip()

    return None


def check_api_key() -> str:
    """Get API key or raise error if not configured."""
    key = get_api_key()
    if not key:
        raise ValueError(
            "VirusTotal API key not configured. Either:\n"
            "1. Set VIRUSTOTAL_API_KEY environment variable\n"
            "2. Create ~/.config/winforensics-mcp/vt_api_key with your key"
        )
    return key


def _rate_limit() -> None:
    """Enforce rate limiting between requests."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < MIN_REQUEST_INTERVAL:
        sleep_time = MIN_REQUEST_INTERVAL - elapsed
        time.sleep(sleep_time)
    _last_request_time = time.time()


def _get_cached(key: str) -> Optional[dict]:
    """Get cached result if not expired."""
    if key in _cache:
        result, timestamp = _cache[key]
        if datetime.now() - timestamp < CACHE_TTL:
            result = dict(result)  # Copy to avoid mutation
            result["_cached"] = True
            result["_cache_age_hours"] = round(
                (datetime.now() - timestamp).total_seconds() / 3600, 1
            )
            return result
        else:
            # Expired, remove from cache
            del _cache[key]
    return None


def _set_cached(key: str, result: dict) -> None:
    """Cache result."""
    _cache[key] = (dict(result), datetime.now())


def _normalize_hash(file_hash: str) -> tuple[str, str]:
    """Normalize hash and determine type."""
    file_hash = file_hash.lower().strip()
    hash_types = {32: "md5", 40: "sha1", 64: "sha256"}
    hash_type = hash_types.get(len(file_hash), "unknown")
    return file_hash, hash_type


def lookup_hash(file_hash: str) -> dict[str, Any]:
    """
    Look up file hash on VirusTotal.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash

    Returns:
        {
            "hash": str,
            "hash_type": str,  # md5, sha1, sha256
            "found": bool,
            "malicious": int,  # AV detections
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "total_engines": int,
            "detection_ratio": str,  # "45/72"
            "verdict": str,  # "malicious", "suspicious", "clean", "unknown"
            "popular_threat_names": list[str],
            "first_submission": str,  # ISO timestamp
            "last_analysis": str,
            "file_type": str,
            "file_size": int,
            "names": list[str],  # Known file names
            "tags": list[str],
        }
    """
    check_vt_available()
    api_key = check_api_key()

    file_hash, hash_type = _normalize_hash(file_hash)

    if hash_type == "unknown":
        return {
            "hash": file_hash,
            "hash_type": "unknown",
            "found": False,
            "error": f"Invalid hash length ({len(file_hash)}). Expected 32 (MD5), 40 (SHA1), or 64 (SHA256).",
        }

    # Check cache
    cache_key = f"hash:{file_hash}"
    if cached := _get_cached(cache_key):
        return cached

    _rate_limit()

    try:
        with vt.Client(api_key) as client:
            file_obj = client.get_object(f"/files/{file_hash}")
    except vt.error.APIError as e:
        if "NotFoundError" in str(e) or "not found" in str(e).lower():
            result = {
                "hash": file_hash,
                "hash_type": hash_type,
                "found": False,
                "verdict": "unknown",
                "message": "Hash not found in VirusTotal database",
            }
            _set_cached(cache_key, result)
            return result
        raise RuntimeError(f"VirusTotal API error: {e}")

    # Parse response
    stats = getattr(file_obj, "last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    # Determine verdict
    if malicious >= 5:
        verdict = "malicious"
    elif malicious > 0 or suspicious >= 3:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    # Extract threat names from detections
    threat_names = []
    if hasattr(file_obj, "last_analysis_results"):
        for av_name, av_result in file_obj.last_analysis_results.items():
            if isinstance(av_result, dict):
                if av_result.get("category") == "malicious" and av_result.get("result"):
                    threat_names.append(av_result["result"])

    # Get most common threat names
    popular_threats = [name for name, _ in Counter(threat_names).most_common(5)]

    # Format timestamps
    first_submission = None
    if hasattr(file_obj, "first_submission_date"):
        ts = file_obj.first_submission_date
        if isinstance(ts, (int, float)):
            first_submission = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        elif isinstance(ts, datetime):
            first_submission = ts.isoformat()

    last_analysis = None
    if hasattr(file_obj, "last_analysis_date"):
        ts = file_obj.last_analysis_date
        if isinstance(ts, (int, float)):
            last_analysis = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        elif isinstance(ts, datetime):
            last_analysis = ts.isoformat()

    result = {
        "hash": file_hash,
        "hash_type": hash_type,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
        "verdict": verdict,
        "popular_threat_names": popular_threats,
        "first_submission": first_submission,
        "last_analysis": last_analysis,
        "file_type": getattr(file_obj, "type_description", None),
        "file_size": getattr(file_obj, "size", None),
        "names": list(getattr(file_obj, "names", []))[:10],
        "tags": list(getattr(file_obj, "tags", []))[:10],
        "sha256": getattr(file_obj, "sha256", None),
        "sha1": getattr(file_obj, "sha1", None),
        "md5": getattr(file_obj, "md5", None),
    }

    _set_cached(cache_key, result)
    return result


def lookup_ip(ip_address: str) -> dict[str, Any]:
    """
    Look up IP address reputation on VirusTotal.

    Args:
        ip_address: IPv4 or IPv6 address

    Returns:
        {
            "ip": str,
            "found": bool,
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "verdict": str,
            "as_owner": str,
            "asn": int,
            "country": str,
            "continent": str,
            "last_analysis_date": str,
            "reputation": int,  # Community score
            "tags": list[str],
        }
    """
    check_vt_available()
    api_key = check_api_key()

    ip_address = ip_address.strip()

    # Check cache
    cache_key = f"ip:{ip_address}"
    if cached := _get_cached(cache_key):
        return cached

    _rate_limit()

    try:
        with vt.Client(api_key) as client:
            ip_obj = client.get_object(f"/ip_addresses/{ip_address}")
    except vt.error.APIError as e:
        if "NotFoundError" in str(e) or "not found" in str(e).lower():
            return {
                "ip": ip_address,
                "found": False,
                "verdict": "unknown",
                "message": "IP not found in VirusTotal database",
            }
        raise RuntimeError(f"VirusTotal API error: {e}")

    stats = getattr(ip_obj, "last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    # Determine verdict
    if malicious >= 3:
        verdict = "malicious"
    elif malicious > 0 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    # Format timestamp
    last_analysis = None
    if hasattr(ip_obj, "last_analysis_date"):
        ts = ip_obj.last_analysis_date
        if isinstance(ts, (int, float)):
            last_analysis = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        elif isinstance(ts, datetime):
            last_analysis = ts.isoformat()

    result = {
        "ip": ip_address,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "verdict": verdict,
        "as_owner": getattr(ip_obj, "as_owner", None),
        "asn": getattr(ip_obj, "asn", None),
        "country": getattr(ip_obj, "country", None),
        "continent": getattr(ip_obj, "continent", None),
        "last_analysis_date": last_analysis,
        "reputation": getattr(ip_obj, "reputation", 0),
        "tags": list(getattr(ip_obj, "tags", []))[:10],
        "network": getattr(ip_obj, "network", None),
    }

    _set_cached(cache_key, result)
    return result


def lookup_domain(domain: str) -> dict[str, Any]:
    """
    Look up domain reputation on VirusTotal.

    Args:
        domain: Domain name (e.g., 'evil.com')

    Returns:
        {
            "domain": str,
            "found": bool,
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "verdict": str,
            "registrar": str,
            "creation_date": str,
            "last_analysis_date": str,
            "reputation": int,
            "categories": dict,  # AV categorizations
            "tags": list[str],
        }
    """
    check_vt_available()
    api_key = check_api_key()

    domain = domain.strip().lower()

    # Check cache
    cache_key = f"domain:{domain}"
    if cached := _get_cached(cache_key):
        return cached

    _rate_limit()

    try:
        with vt.Client(api_key) as client:
            domain_obj = client.get_object(f"/domains/{domain}")
    except vt.error.APIError as e:
        if "NotFoundError" in str(e) or "not found" in str(e).lower():
            return {
                "domain": domain,
                "found": False,
                "verdict": "unknown",
                "message": "Domain not found in VirusTotal database",
            }
        raise RuntimeError(f"VirusTotal API error: {e}")

    stats = getattr(domain_obj, "last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    # Determine verdict
    if malicious >= 3:
        verdict = "malicious"
    elif malicious > 0 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    # Format timestamps
    creation_date = None
    if hasattr(domain_obj, "creation_date"):
        ts = domain_obj.creation_date
        if isinstance(ts, (int, float)):
            creation_date = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        elif isinstance(ts, datetime):
            creation_date = ts.isoformat()

    last_analysis = None
    if hasattr(domain_obj, "last_analysis_date"):
        ts = domain_obj.last_analysis_date
        if isinstance(ts, (int, float)):
            last_analysis = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        elif isinstance(ts, datetime):
            last_analysis = ts.isoformat()

    result = {
        "domain": domain,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "verdict": verdict,
        "registrar": getattr(domain_obj, "registrar", None),
        "creation_date": creation_date,
        "last_analysis_date": last_analysis,
        "reputation": getattr(domain_obj, "reputation", 0),
        "categories": dict(getattr(domain_obj, "categories", {})),
        "tags": list(getattr(domain_obj, "tags", []))[:10],
        "whois": getattr(domain_obj, "whois", None)[:500] if hasattr(domain_obj, "whois") and domain_obj.whois else None,
    }

    _set_cached(cache_key, result)
    return result


def lookup_file(file_path: str | Path) -> dict[str, Any]:
    """
    Calculate file hashes and look up on VirusTotal.
    Convenience function that hashes the file first.

    Args:
        file_path: Path to file

    Returns:
        Same as lookup_hash() plus:
        - file_path: str
        - local_hashes: dict with md5, sha1, sha256
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Calculate all hashes
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    local_hashes = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

    # Look up using SHA256 (most reliable)
    result = lookup_hash(local_hashes["sha256"])
    result["file_path"] = str(file_path)
    result["local_hashes"] = local_hashes
    result["file_size_local"] = file_path.stat().st_size

    return result


def clear_cache() -> int:
    """Clear the cache. Returns number of items cleared."""
    count = len(_cache)
    _cache.clear()
    return count


def get_cache_stats() -> dict[str, Any]:
    """Get cache statistics."""
    now = datetime.now()
    valid = sum(1 for _, (_, ts) in _cache.items() if now - ts < CACHE_TTL)
    expired = len(_cache) - valid

    return {
        "total_entries": len(_cache),
        "valid_entries": valid,
        "expired_entries": expired,
        "ttl_hours": CACHE_TTL.total_seconds() / 3600,
    }
