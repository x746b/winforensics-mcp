"""Parse Rohitab API Monitor capture files (.apmx64 / .apmx86).

APMX files are ZIP archives with a custom header that contain captured
Win32 API call sequences from monitored processes. This parser extracts
process metadata, API call records, parameter values, return values,
and runs pattern detection against the captured call sequence.

Format reverse-engineered from real captures and IDA Pro analysis of
apimonitor-x64.exe (February 2026).

Record layout (144-byte header):
  +0x08: record_index (uint32)
  +0x0C: parent_index (uint32, 0xFFFFFFFF = root)
  +0x20: pre_params_size (uint32)
  +0x48: timestamp (FILETIME, uint64)
  +0x58: post_params_size (uint32)
  +0x5C: section3_size (uint32)
  +0x6C: section4_size (uint32, contains API names + caller addresses)
  +0x70: pre_params_ptr (uint64, offset into data blob)
  +0x78: post_params_ptr (uint64, 0 = no post-call data)
  +0x80: section3_ptr (uint64)
  +0x88: section4_ptr (uint64)

Parameter data block:
  Byte 0: param_count
  Byte 1: size_field (= param_count * 4 + 1)
  Bytes 2..(size_field-1): descriptor entries (4 bytes each)
    Each entry: [flags_lo] [slot_count_hi | type_lo] [0x00] [def_ref]
    slot_count = entry[1] >> 4 = number of uint64 entries for this param
  Byte size_field onward: uint64 values (LE), sequentially packed
"""
from __future__ import annotations

import io
import struct
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _open_apmx_zip(file_path: str | Path) -> zipfile.ZipFile:
    """Open an APMX file, skipping past the custom header to the ZIP data."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"APMX file not found: {file_path}")

    data = file_path.read_bytes()
    pk_offset = data.find(b"PK\x03\x04")
    if pk_offset == -1:
        raise ValueError(f"Not a valid APMX file (no ZIP signature found): {file_path}")

    return zipfile.ZipFile(io.BytesIO(data[pk_offset:]))


def _read_utf16le_string(data: bytes, offset: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-16LE string. Returns (string, new_offset)."""
    if offset + 4 > len(data):
        return "", offset
    char_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    byte_count = char_count * 2
    if offset + byte_count > len(data):
        return "", offset
    text = data[offset : offset + byte_count].decode("utf-16-le", errors="replace").rstrip("\x00")
    return text, offset + byte_count


def _extract_api_names(record: bytes) -> list[str]:
    """Extract API function names from a binary call record.

    Names are encoded as: 01 00 <length_byte> 00 <ascii_name> 00
    The first name is the top-level API, subsequent names are nested calls.
    """
    names: list[str] = []
    i = 0
    end = len(record) - 4
    while i < end:
        if record[i] == 0x01 and record[i + 1] == 0x00 and record[i + 3] == 0x00:
            name_len = record[i + 2]
            if 3 <= name_len <= 80:
                start = i + 4
                name_end = start + name_len - 1  # exclude null terminator
                if name_end <= len(record):
                    candidate = record[start:name_end]
                    try:
                        name = candidate.decode("ascii")
                        if all(c.isalnum() or c in "_" for c in name) and len(name) >= 3:
                            names.append(name)
                            i = name_end + 1
                            continue
                    except (UnicodeDecodeError, ValueError):
                        pass
        i += 1
    return names


def _resolve_name_from_defs(defs_blob: bytes, code_addr: int) -> str | None:
    """Resolve an API name from the definitions blob using code_addr.

    Each definition entry has a name pointer at offset +0x18 (uint64) that
    points to a null-terminated ASCII string in the definitions string pool.
    """
    if code_addr + 0x20 > len(defs_blob):
        return None
    name_ptr = struct.unpack_from("<Q", defs_blob, code_addr + 0x18)[0]
    if name_ptr >= len(defs_blob):
        return None
    end = defs_blob.find(b"\x00", name_ptr, name_ptr + 300)
    if end <= name_ptr:
        return None
    try:
        name = defs_blob[name_ptr:end].decode("ascii")
        if name.isprintable() and len(name) >= 2:
            return name
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def _get_record_api_name(
    rec: bytes,
    data_blob: bytes,
    rec_offset: int,
    defs_blob: bytes | None,
) -> str:
    """Get the API name for a record.

    Prefers embedded names (higher-level Win32 APIs like OpenProcess) when
    available, falls back to definitions-resolved names (lower-level native
    APIs like NtOpenProcess).
    """
    # Primary: embedded names from sec4 (higher-level, more forensically useful)
    names = _extract_api_names(rec)
    if names:
        return names[0]

    # Fallback: resolve from definitions blob via code_addr at +0x28
    if defs_blob is not None and len(rec) >= 0x30:
        code_addr = struct.unpack_from("<Q", rec, 0x28)[0]
        name = _resolve_name_from_defs(defs_blob, code_addr)
        if name:
            return name

    return ""


# Windows FILETIME epoch: Jan 1, 1601
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_TICKS_PER_SEC = 10_000_000


def _filetime_to_iso(filetime: int) -> str | None:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO string."""
    if filetime == 0:
        return None
    try:
        seconds = filetime / _FILETIME_TICKS_PER_SEC
        dt = _FILETIME_EPOCH + __import__("datetime").timedelta(seconds=seconds)
        return dt.isoformat(timespec="microseconds")
    except (ValueError, OverflowError, OSError):
        return None


def _parse_param_values(
    param_block: bytes, count: int, size_field: int
) -> list[dict[str, Any]]:
    """Parse parameter values from a pre-call or post-call data block.

    Returns a list of dicts, one per parameter, containing:
      - slot_count: number of uint64 entries used by this param
      - values: list of uint64 values (raw)
      - value: the "primary" value (last entry for multi-slot, only for single)
    """
    params: list[dict[str, Any]] = []
    data_offset = size_field  # values start after descriptor
    available = len(param_block) - data_offset

    pos = 0  # byte position within the value data
    for p in range(count):
        desc_off = 2 + p * 4
        if desc_off + 4 > len(param_block):
            break
        b1 = param_block[desc_off + 1]
        slot_count = b1 >> 4
        if slot_count == 0:
            slot_count = 1  # safety

        slots: list[int] = []
        for s in range(slot_count):
            byte_pos = data_offset + pos + s * 8
            if byte_pos + 8 <= len(param_block):
                slots.append(struct.unpack_from("<Q", param_block, byte_pos)[0])

        pos += slot_count * 8

        entry: dict[str, Any] = {
            "slot_count": slot_count,
            "values": slots,
        }

        # Determine primary value using heuristics based on slot count:
        # - 1 slot: direct value
        # - 2-4 slots: check for [flag, address, value] output pattern
        # - 5+ slots: first slot is value, rest is type metadata
        if not slots:
            entry["value"] = None
        elif slot_count == 1:
            entry["value"] = slots[0]
        elif slot_count >= 5:
            # Large slot counts = value + type/definition metadata
            entry["value"] = slots[0]
        elif slot_count >= 2:
            s0, s1 = slots[0], slots[1]
            is_flag_addr_pattern = (
                s0 in (0, 1)
                and s1 > 0xFFFFFFFF  # > 32-bit = likely 64-bit pointer
            )
            if is_flag_addr_pattern and len(slots) >= 3:
                # Output/reference: [flag, addr, value] or [flag, addr, flag2, value]
                if slot_count == 4 and len(slots) >= 4 and slots[2] in (0, 1):
                    entry["value"] = slots[3]
                else:
                    entry["value"] = slots[2]
                entry["address"] = s1
            elif is_flag_addr_pattern and len(slots) == 2:
                entry["value"] = s1
            else:
                # First slot is the actual value (e.g., handle, DWORD)
                entry["value"] = s0
        else:
            entry["value"] = slots[0] if slots else None

        params.append(entry)

    return params


def _extract_strings_from_values(values: list[int]) -> list[str]:
    """Try to decode UTF-16LE strings from uint64 value sequences."""
    strings: list[str] = []
    # Pack values into bytes
    raw = b""
    for v in values:
        raw += struct.pack("<Q", v)
    # Scan for UTF-16LE strings (at least 3 chars)
    i = 0
    while i < len(raw) - 5:
        # Check if this looks like start of UTF-16LE text
        if raw[i + 1] == 0 and 0x20 <= raw[i] <= 0x7E:
            end = i
            while end + 1 < len(raw) and (raw[end] != 0 or raw[end + 1] != 0):
                end += 2
            if end - i >= 10:  # at least 5 wide chars
                try:
                    s = raw[i:end].decode("utf-16-le", errors="strict")
                    if all(c.isprintable() or c in "\t\n\r" for c in s):
                        strings.append(s)
                        i = end + 2
                        continue
                except (UnicodeDecodeError, ValueError):
                    pass
        i += 1
    return strings


def _parse_call_record(
    rec: bytes, record_index: int, defs_blob: bytes | None = None
) -> dict[str, Any]:
    """Parse a single call record into structured data.

    Extracts: record index, parent, timestamp, parameter values (pre/post),
    return value, API names, and embedded strings.
    """
    if len(rec) < 0x92:
        return {"call_index": record_index, "error": "record too short"}

    result: dict[str, Any] = {"call_index": record_index}

    # Header fields
    result["record_index"] = struct.unpack_from("<I", rec, 0x08)[0]
    parent = struct.unpack_from("<I", rec, 0x0C)[0]
    result["parent_index"] = parent if parent != 0xFFFFFFFF else None

    # Timestamp
    filetime = struct.unpack_from("<Q", rec, 0x48)[0]
    ts = _filetime_to_iso(filetime)
    if ts:
        result["timestamp"] = ts

    # Sizes and pointers
    pre_size = struct.unpack_from("<I", rec, 0x20)[0]
    post_size = struct.unpack_from("<I", rec, 0x58)[0]
    ptr_78 = struct.unpack_from("<Q", rec, 0x78)[0]
    has_post = ptr_78 != 0

    # API name: prefer embedded name (higher-level Win32 API), fall back to defs
    defs_name = None
    if defs_blob is not None and len(rec) >= 0x30:
        code_addr = struct.unpack_from("<Q", rec, 0x28)[0]
        defs_name = _resolve_name_from_defs(defs_blob, code_addr)

    embedded_names = _extract_api_names(rec)
    result["api_name"] = (embedded_names[0] if embedded_names else None) or defs_name
    if defs_name and defs_name != result.get("api_name"):
        result["native_api"] = defs_name
    if len(embedded_names) > 1:
        result["nested_apis"] = embedded_names[1:]

    # Parameter descriptor
    if 0x90 + 2 <= len(rec):
        count = rec[0x90]
        size_field = rec[0x91]
        expected_sf = count * 4 + 1
        if size_field != expected_sf or count == 0:
            result["param_count"] = count
            return result

        result["param_count"] = count

        # Parse pre-call values
        pre_block = rec[0x90 : 0x90 + pre_size]
        pre_params = _parse_param_values(pre_block, count, size_field)

        # Parse post-call values (if available)
        post_params: list[dict[str, Any]] | None = None
        if has_post and 0x90 + pre_size + size_field < len(rec):
            post_start = 0x90 + pre_size
            post_block = rec[post_start : post_start + post_size]
            # Verify post block has same descriptor
            if len(post_block) >= 2 and post_block[0] == count and post_block[1] == size_field:
                post_params = _parse_param_values(post_block, count, size_field)

        # Build parameter list with pre/post comparison
        params_out: list[dict[str, Any]] = []
        return_value = None

        for p_idx in range(count):
            if p_idx >= len(pre_params):
                break
            pre = pre_params[p_idx]
            pinfo: dict[str, Any] = {
                "index": p_idx,
                "pre_value": pre["value"],
            }
            if pre.get("address") is not None:
                pinfo["address"] = f"0x{pre['address']:x}"

            # Format hex for handle-like values
            val = pre["value"]
            if isinstance(val, int) and val != 0:
                pinfo["pre_value_hex"] = f"0x{val:x}"

            # Check for post-call value changes
            if post_params and p_idx < len(post_params):
                post = post_params[p_idx]
                pinfo["post_value"] = post["value"]
                if isinstance(post["value"], int) and post["value"] != 0:
                    pinfo["post_value_hex"] = f"0x{post['value']:x}"
                if pre["value"] != post["value"]:
                    pinfo["changed"] = True
                    # Heuristic: return value is typically the first changed
                    # param that has the flag+addr+value pattern (output param)
                    if return_value is None:
                        has_output_pattern = pre.get("address") is not None
                        is_zero_to_nonzero = pre["value"] == 0 and post["value"] != 0
                        if has_output_pattern or is_zero_to_nonzero:
                            return_value = post["value"]
                            pinfo["is_return"] = True

            # Extract embedded strings from multi-slot params
            if pre["slot_count"] >= 6 and pre["values"]:
                # Skip the first few header slots (flag, addr, value)
                # and scan remaining for UTF-16LE strings
                string_slots = pre["values"][2:] if pre["slot_count"] < 5 else pre["values"][1:]
                strings = _extract_strings_from_values(string_slots)
                if strings:
                    pinfo["strings"] = strings

            params_out.append(pinfo)

        result["parameters"] = params_out
        if return_value is not None:
            result["return_value"] = return_value
            result["return_hex"] = f"0x{return_value:x}"

    return result


def _parse_process_info(data: bytes) -> dict[str, Any]:
    """Parse the process/N/info binary blob."""
    info: dict[str, Any] = {}
    offset = 0

    if len(data) < 20:
        return info

    # First 4 bytes: process index
    info["process_index"] = struct.unpack_from("<I", data, 0)[0]
    offset = 8

    # PID
    if offset + 4 <= len(data):
        pid = struct.unpack_from("<I", data, offset)[0]
        info["pid"] = pid
        offset += 4

    # Image base (uint64)
    if offset + 8 <= len(data):
        base = struct.unpack_from("<Q", data, offset)[0]
        info["image_base"] = f"0x{base:016x}"
        offset += 8

    # Process path
    path, offset = _read_utf16le_string(data, offset)
    if path:
        info["process_path"] = path
        info["process_name"] = path.rsplit("\\", 1)[-1] if "\\" in path else path

    # Command line
    cmdline, offset = _read_utf16le_string(data, offset)
    if cmdline:
        info["command_line"] = cmdline

    # Scan remainder for module paths (DLL list)
    modules = []
    scan_offset = offset
    while scan_offset < len(data) - 10:
        # Look for path strings starting with drive letter patterns
        path_str, new_offset = _read_utf16le_string(data, scan_offset)
        if path_str and ("\\" in path_str or "/" in path_str):
            # Filter out garbled strings — valid paths start with a drive letter or UNC
            if len(path_str) >= 4 and (path_str[1] == ":" or path_str.startswith("\\\\")):
                dll_name = path_str.rsplit("\\", 1)[-1] if "\\" in path_str else path_str
                modules.append({"path": path_str, "name": dll_name})
            scan_offset = new_offset
        else:
            scan_offset += 1

    if modules:
        info["modules"] = modules

    return info


def _parse_monitoring_log(data: bytes) -> list[dict[str, str]]:
    """Parse the monitoring log (UTF-16LE text)."""
    try:
        text = data.decode("utf-16-le", errors="replace")
    except Exception:
        return []

    entries = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ": Monitoring Module " in line:
            parts = line.split(": Monitoring Module ", 1)
            process = parts[0].strip()
            rest = parts[1].strip().rstrip(".")
            addr, path = "", ""
            if " -> " in rest:
                addr, path = rest.split(" -> ", 1)
            entries.append({"action": "load", "process": process, "address": addr, "module": path})
        elif ": Detaching Module " in line:
            parts = line.split(": Detaching Module ", 1)
            process = parts[0].strip()
            rest = parts[1].strip().rstrip(".")
            addr, path = "", ""
            if " -> " in rest:
                addr, path = rest.split(" -> ", 1)
            entries.append({"action": "unload", "process": process, "address": addr, "module": path})
    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_apmx(file_path: str | Path) -> dict[str, Any]:
    """Parse an APMX capture file and return summary metadata.

    Args:
        file_path: Path to .apmx64 or .apmx86 file

    Returns:
        Dict with capture info, process details, module list, call statistics
    """
    zf = _open_apmx_zip(file_path)
    result: dict[str, Any] = {"file": str(file_path)}

    # List available entries
    entry_names = [info.filename for info in zf.infolist()]

    # Capture info
    if "info" in entry_names:
        info_data = zf.read("info")
        # Version string is UTF-16LE at a small offset
        try:
            # Skip first 4 bytes (flags), then read length-prefixed UTF-16LE
            version, _ = _read_utf16le_string(info_data, 4)
            result["version"] = version
        except Exception:
            pass

    # Determine bitness from filename or version
    file_path = Path(file_path)
    if file_path.suffix.lower() == ".apmx64":
        result["architecture"] = "64-bit"
    elif file_path.suffix.lower() == ".apmx86":
        result["architecture"] = "32-bit"

    # Count processes
    process_indices = set()
    for name in entry_names:
        if name.startswith("process/") and "/info" in name:
            parts = name.split("/")
            if len(parts) >= 3 and parts[1].isdigit():
                process_indices.add(int(parts[1]))

    result["process_count"] = len(process_indices)
    result["processes"] = []

    for idx in sorted(process_indices):
        # Process info
        info_key = f"process/{idx}/info"
        if info_key in entry_names:
            pinfo = _parse_process_info(zf.read(info_key))
            pinfo["index"] = idx

            # Call count
            calls_key = f"process/{idx}/calls"
            if calls_key in entry_names:
                calls_data = zf.read(calls_key)
                pinfo["total_calls"] = len(calls_data) // 8

            result["processes"].append(pinfo)

    # Monitoring log
    if "log/monitoring.txt" in entry_names:
        log_entries = _parse_monitoring_log(zf.read("log/monitoring.txt"))
        loaded = [e for e in log_entries if e["action"] == "load"]
        result["modules_loaded"] = len(loaded)
        result["module_list"] = [e["module"] for e in loaded]

    zf.close()
    return result


def get_apmx_calls(
    file_path: str | Path,
    process_index: int = 0,
    api_filter: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    """Extract API call records from an APMX capture.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to read (0 = first/only)
        api_filter: Optional API name substring filter (case-insensitive)
        limit: Max records to return
        offset: Skip first N matching records (pagination)

    Returns:
        Dict with call records, each containing api_names and call index
    """
    zf = _open_apmx_zip(file_path)

    calls_key = f"process/{process_index}/calls"
    data_key = f"process/{process_index}/data"

    entry_names = [info.filename for info in zf.infolist()]
    if calls_key not in entry_names or data_key not in entry_names:
        zf.close()
        return {"error": f"Process {process_index} not found in capture"}

    calls_data = zf.read(calls_key)
    api_data = zf.read(data_key)
    defs_blob = zf.read("definitions") if "definitions" in entry_names else None
    zf.close()

    num_records = len(calls_data) // 8
    offsets_arr = struct.unpack(f"<{num_records}Q", calls_data)

    records = []
    skipped = 0
    filter_lower = api_filter.lower() if api_filter else None

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        api_name = _get_record_api_name(rec, api_data, off, defs_blob)
        embedded_names = _extract_api_names(rec)

        if not api_name and not embedded_names:
            continue

        all_names = [api_name] if api_name else []
        for n in embedded_names:
            if n not in all_names:
                all_names.append(n)

        top_api = api_name or embedded_names[0]

        # Apply filter
        if filter_lower:
            if not any(filter_lower in n.lower() for n in all_names):
                continue

        # Apply pagination
        if skipped < offset:
            skipped += 1
            continue

        records.append({
            "call_index": i,
            "top_api": top_api,
            "all_apis": all_names,
            "nested_count": len(all_names) - 1,
        })

        if len(records) >= limit:
            break

    return {
        "total_records": num_records,
        "returned": len(records),
        "offset": offset,
        "filter": api_filter,
        "calls": records,
    }


def get_apmx_api_stats(
    file_path: str | Path, process_index: int = 0
) -> dict[str, Any]:
    """Get API call frequency statistics from an APMX capture.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to analyze

    Returns:
        Dict with top-level API counts, all API counts, total calls
    """
    zf = _open_apmx_zip(file_path)

    calls_key = f"process/{process_index}/calls"
    data_key = f"process/{process_index}/data"

    entry_names = [info.filename for info in zf.infolist()]
    if calls_key not in entry_names or data_key not in entry_names:
        zf.close()
        return {"error": f"Process {process_index} not found in capture"}

    calls_data = zf.read(calls_key)
    api_data = zf.read(data_key)
    defs_blob = zf.read("definitions") if "definitions" in entry_names else None
    zf.close()

    num_records = len(calls_data) // 8
    offsets_arr = struct.unpack(f"<{num_records}Q", calls_data)

    top_level_counts: Counter[str] = Counter()
    all_api_counts: Counter[str] = Counter()

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        api_name = _get_record_api_name(rec, api_data, off, defs_blob)
        embedded_names = _extract_api_names(rec)

        if api_name:
            top_level_counts[api_name] += 1
            all_api_counts[api_name] += 1
        elif embedded_names:
            top_level_counts[embedded_names[0]] += 1

        for n in embedded_names:
            all_api_counts[n] += 1

    return {
        "total_records": num_records,
        "unique_top_level_apis": len(top_level_counts),
        "unique_all_apis": len(all_api_counts),
        "top_apis_by_frequency": [
            {"api": name, "count": count}
            for name, count in top_level_counts.most_common(50)
        ],
        "all_apis_by_frequency": [
            {"api": name, "count": count}
            for name, count in all_api_counts.most_common(50)
        ],
    }


def detect_apmx_patterns(
    file_path: str | Path, process_index: int = 0
) -> dict[str, Any]:
    """Detect injection/evasion/persistence patterns in APMX captured API calls.

    Uses the same pattern library as PE import analysis but checks against
    actually-called APIs (runtime behavior, not just static imports).

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to analyze

    Returns:
        Dict with detected patterns, risk level, and timeline of suspicious calls
    """
    from .patterns import PATTERNS

    zf = _open_apmx_zip(file_path)

    calls_key = f"process/{process_index}/calls"
    data_key = f"process/{process_index}/data"

    entry_names = [info.filename for info in zf.infolist()]
    if calls_key not in entry_names or data_key not in entry_names:
        zf.close()
        return {"error": f"Process {process_index} not found in capture"}

    calls_data = zf.read(calls_key)
    api_data = zf.read(data_key)
    defs_blob = zf.read("definitions") if "definitions" in entry_names else None
    zf.close()

    num_records = len(calls_data) // 8
    offsets_arr = struct.unpack(f"<{num_records}Q", calls_data)

    # Collect ALL unique API names seen in the capture (top-level only for pattern matching)
    all_apis: set[str] = set()
    # Track where each API appears for timeline reconstruction
    api_first_seen: dict[str, int] = {}

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        api_name = _get_record_api_name(rec, api_data, off, defs_blob)
        embedded_names = _extract_api_names(rec)

        names = set()
        if api_name:
            names.add(api_name)
        names.update(embedded_names)

        for name in names:
            all_apis.add(name)
            if name not in api_first_seen:
                api_first_seen[name] = i

    # Run pattern detection
    detected = []
    risk_levels: list[str] = []

    for pattern_id, pattern in PATTERNS.items():
        all_pattern_apis = pattern["required"] | pattern.get("optional", set())
        matched = all_apis & all_pattern_apis
        required_matched = all_apis & pattern["required"]

        if len(matched) >= pattern["min_match"]:
            missing_required = pattern["required"] - all_apis

            # Build timeline of matched APIs
            timeline = []
            for api in sorted(matched, key=lambda a: api_first_seen.get(a, 0)):
                timeline.append({
                    "api": api,
                    "first_seen_at_record": api_first_seen.get(api, -1),
                })

            detected.append({
                "pattern_name": pattern["name"],
                "pattern_id": pattern_id,
                "apis_matched": sorted(matched),
                "apis_missing": sorted(missing_required) if missing_required else [],
                "match_count": len(matched),
                "min_required": pattern["min_match"],
                "description": pattern["description"],
                "mitre_id": pattern["mitre_id"],
                "risk": pattern["risk"],
                "timeline": timeline,
            })
            risk_levels.append(pattern["risk"])

    # Overall risk
    if "high" in risk_levels:
        overall_risk = "high"
    elif "medium" in risk_levels:
        overall_risk = "medium"
    elif "low" in risk_levels:
        overall_risk = "low"
    else:
        overall_risk = "none"

    # Build suspicious call timeline (ordered by record index)
    suspicious_timeline = []
    suspicious_api_set = set()
    for det in detected:
        for api in det["apis_matched"]:
            suspicious_api_set.add(api)

    for api in sorted(suspicious_api_set, key=lambda a: api_first_seen.get(a, 0)):
        suspicious_timeline.append({
            "record_index": api_first_seen[api],
            "api": api,
        })

    return {
        "total_records": num_records,
        "unique_apis_seen": len(all_apis),
        "patterns_detected": len(detected),
        "risk_level": overall_risk,
        "details": detected,
        "suspicious_call_timeline": suspicious_timeline,
    }


def get_apmx_call_details(
    file_path: str | Path,
    process_index: int = 0,
    call_indices: list[int] | None = None,
    api_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Extract detailed API call records with parameter values and return values.

    Each record includes pre-call and post-call parameter values, timestamps,
    parent-child relationships, and embedded strings.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to read (0 = first/only)
        call_indices: Specific record indices to retrieve (overrides filter/pagination)
        api_filter: Filter by API name substring (case-insensitive)
        limit: Max records to return (default 50)
        offset: Skip first N matching records (pagination)

    Returns:
        Dict with detailed call records including parameter values
    """
    zf = _open_apmx_zip(file_path)

    calls_key = f"process/{process_index}/calls"
    data_key = f"process/{process_index}/data"

    entry_names = [info.filename for info in zf.infolist()]
    if calls_key not in entry_names or data_key not in entry_names:
        zf.close()
        return {"error": f"Process {process_index} not found in capture"}

    calls_data = zf.read(calls_key)
    api_data = zf.read(data_key)
    defs_blob = zf.read("definitions") if "definitions" in entry_names else None
    zf.close()

    num_records = len(calls_data) // 8
    offsets_arr = struct.unpack(f"<{num_records}Q", calls_data)

    records: list[dict[str, Any]] = []

    if call_indices is not None:
        # Direct index lookup
        for idx in call_indices:
            if 0 <= idx < num_records:
                off = offsets_arr[idx]
                next_off = offsets_arr[idx + 1] if idx + 1 < num_records else len(api_data)
                rec = api_data[off:next_off]
                parsed = _parse_call_record(rec, idx, defs_blob=defs_blob)
                records.append(parsed)
    else:
        # Filtered iteration
        filter_lower = api_filter.lower() if api_filter else None
        skipped = 0

        for i in range(num_records):
            off = offsets_arr[i]
            next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
            rec = api_data[off:next_off]

            api_name = _get_record_api_name(rec, api_data, off, defs_blob)
            embedded_names = _extract_api_names(rec)

            if not api_name and not embedded_names:
                continue

            all_names = [api_name] if api_name else []
            all_names.extend(embedded_names)

            if filter_lower and not any(filter_lower in n.lower() for n in all_names):
                continue

            if skipped < offset:
                skipped += 1
                continue

            parsed = _parse_call_record(rec, i, defs_blob=defs_blob)
            records.append(parsed)

            if len(records) >= limit:
                break

    return {
        "total_records": num_records,
        "returned": len(records),
        "calls": records,
    }


def correlate_apmx_handles(
    file_path: str | Path,
    process_index: int = 0,
    target_apis: list[str] | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Track handle values across API calls to reconstruct operation chains.

    Identifies handle-producing APIs (OpenProcess, CreateFile, etc.) and traces
    where those handles are subsequently used. This reveals attack chains like:
    OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to analyze
        target_apis: Limit to specific APIs (default: common injection APIs)
        limit: Max chains to return

    Returns:
        Dict with handle chains showing producer→consumer relationships
    """
    # APIs that produce handles (return value is a handle)
    # Includes both Win32 and native (Nt/Rtl) variants
    HANDLE_PRODUCERS = {
        "OpenProcess", "NtOpenProcess", "OpenThread", "NtOpenThread",
        "CreateToolhelp32Snapshot",
        "CreateFileA", "CreateFileW", "NtCreateFile", "NtOpenFile",
        "CreateFileMappingA", "CreateFileMappingW", "NtCreateSection",
        "OpenFileMappingA", "OpenFileMappingW",
        "CreateMutexA", "CreateMutexW", "CreateEventA", "CreateEventW",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
        "OpenProcessToken", "NtOpenProcessToken",
        "DuplicateTokenEx", "NtDuplicateToken",
        "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExInternalW", "RegOpenKeyExInternalA",
        "NtOpenKey", "NtCreateKey",
        "CreateNamedPipeA", "CreateNamedPipeW",
        "WSASocketA", "WSASocketW", "socket",
    }

    # APIs that consume handles (first or second param is typically a handle)
    HANDLE_CONSUMERS = {
        "VirtualAllocEx", "VirtualProtectEx", "VirtualFreeEx",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "WriteProcessMemory", "ReadProcessMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "GetThreadContext",
        "NtSetContextThread", "NtGetContextThread",
        "ResumeThread", "SuspendThread", "TerminateThread",
        "NtResumeThread", "NtSuspendThread", "NtTerminateThread",
        "MapViewOfFile", "UnmapViewOfFile",
        "CloseHandle", "NtClose", "DuplicateHandle",
        "NtMapViewOfSection", "NtUnmapViewOfSection",
        "SetInformationJobObject", "AssignProcessToJobObject",
    }

    if target_apis:
        target_set = set(target_apis)
    else:
        target_set = HANDLE_PRODUCERS | HANDLE_CONSUMERS

    zf = _open_apmx_zip(file_path)
    calls_key = f"process/{process_index}/calls"
    data_key = f"process/{process_index}/data"

    entry_names = [info.filename for info in zf.infolist()]
    if calls_key not in entry_names or data_key not in entry_names:
        zf.close()
        return {"error": f"Process {process_index} not found in capture"}

    calls_data = zf.read(calls_key)
    api_data = zf.read(data_key)
    defs_blob = zf.read("definitions") if "definitions" in entry_names else None
    zf.close()

    num_records = len(calls_data) // 8
    offsets_arr = struct.unpack(f"<{num_records}Q", calls_data)

    # First pass: collect handle-producing records and their return values
    handle_sources: dict[int, dict[str, Any]] = {}  # handle_value → record info
    all_records: list[dict[str, Any]] = []

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        # Check both embedded and definitions-resolved names against target set
        embedded = _extract_api_names(rec)
        defs_name = None
        if defs_blob is not None and len(rec) >= 0x30:
            code_addr = struct.unpack_from("<Q", rec, 0x28)[0]
            defs_name = _resolve_name_from_defs(defs_blob, code_addr)

        all_names = set()
        if embedded:
            all_names.update(embedded)
        if defs_name:
            all_names.add(defs_name)

        if not all_names & target_set:
            continue

        parsed = _parse_call_record(rec, i, defs_blob=defs_blob)
        all_records.append(parsed)

        api_name = parsed.get("api_name", "")
        ret_val = parsed.get("return_value")

        # Record as handle producer if it has a non-zero/non-error return
        if api_name in HANDLE_PRODUCERS and ret_val is not None:
            if ret_val != 0 and ret_val != 0xFFFFFFFF and ret_val != 0xFFFFFFFFFFFFFFFF:
                handle_sources[ret_val] = {
                    "handle": ret_val,
                    "handle_hex": f"0x{ret_val:x}",
                    "producer_api": api_name,
                    "producer_record": i,
                    "timestamp": parsed.get("timestamp"),
                    "consumers": [],
                }

    # Second pass: match handle consumers
    for parsed in all_records:
        api_name = parsed.get("api_name", "")
        if api_name not in HANDLE_CONSUMERS:
            continue

        params = parsed.get("parameters", [])
        # Check first few parameter values for known handles
        for p in params[:3]:
            val = p.get("pre_value")
            if val is not None and val in handle_sources:
                handle_sources[val]["consumers"].append({
                    "api": api_name,
                    "record": parsed["call_index"],
                    "timestamp": parsed.get("timestamp"),
                })
                break

    # Build chains (only include handles that have both producer and consumer)
    chains = []
    for handle_val, info in sorted(handle_sources.items(), key=lambda x: x[1]["producer_record"]):
        if info["consumers"]:
            chains.append(info)
        if len(chains) >= limit:
            break

    # Also include orphan producers (handles created but not tracked as consumed)
    orphans = []
    for handle_val, info in sorted(handle_sources.items(), key=lambda x: x[1]["producer_record"]):
        if not info["consumers"]:
            orphans.append({
                "handle": info["handle"],
                "handle_hex": info["handle_hex"],
                "producer_api": info["producer_api"],
                "producer_record": info["producer_record"],
            })

    return {
        "total_records": num_records,
        "handle_chains": chains,
        "chain_count": len(chains),
        "orphan_handles": orphans[:20],  # limit orphans shown
    }
