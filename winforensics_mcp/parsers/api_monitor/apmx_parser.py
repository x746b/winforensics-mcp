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
    # Names encoded as: 01 00 <len> 00 <ascii> 00
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
    """Resolve an API name from the definitions blob using code_addr."""
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
    """Get the API name for a record, preferring embedded over definitions-resolved names."""
    # Prefer embedded names
    names = _extract_api_names(rec)
    if names:
        return names[0]

    # Fall back to definitions
    if defs_blob is not None and len(rec) >= 0x30:
        code_addr = struct.unpack_from("<Q", rec, 0x28)[0]
        name = _resolve_name_from_defs(defs_blob, code_addr)
        if name:
            return name

    return ""


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


# ---------------------------------------------------------------------------
# Named parameter mappings for common APIs
# ---------------------------------------------------------------------------

COMMON_API_PARAMS: dict[str, list[str]] = {
    "CreateToolhelp32Snapshot": ["dwFlags", "th32ProcessID"],
    "Process32FirstW": ["hSnapshot", "lppe"],
    "Process32NextW": ["hSnapshot", "lppe"],
    "Process32First": ["hSnapshot", "lppe"],
    "Process32Next": ["hSnapshot", "lppe"],
    "OpenProcess": ["dwDesiredAccess", "bInheritHandle", "dwProcessId"],
    "VirtualAllocEx": ["hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"],
    "WriteProcessMemory": ["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"],
    "CreateRemoteThread": ["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"],
    "CreateRemoteThreadEx": ["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId", "lpAttributeList"],
    "ExitProcess": ["uExitCode"],
    "CloseHandle": ["hObject"],
    "VirtualProtectEx": ["hProcess", "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"],
    "ReadProcessMemory": ["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesRead"],
    "NtAllocateVirtualMemory": ["ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"],
    "VirtualAlloc": ["lpAddress", "dwSize", "flAllocationType", "flProtect"],
    "VirtualProtect": ["lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"],
    "CreateThread": ["lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"],
    "NtWriteVirtualMemory": ["ProcessHandle", "BaseAddress", "Buffer", "BufferSize", "NumberOfBytesWritten"],
    "NtReadVirtualMemory": ["ProcessHandle", "BaseAddress", "Buffer", "BufferSize", "NumberOfBytesRead"],
}


# ---------------------------------------------------------------------------
# Flag/enum decoding for common API parameters
# ---------------------------------------------------------------------------

# Process access rights (OpenProcess dwDesiredAccess)
_PROCESS_ACCESS_FLAGS: dict[int, str] = {
    0x0001: "PROCESS_TERMINATE",
    0x0002: "PROCESS_CREATE_THREAD",
    0x0004: "PROCESS_SET_SESSIONID",
    0x0008: "PROCESS_VM_OPERATION",
    0x0010: "PROCESS_VM_READ",
    0x0020: "PROCESS_VM_WRITE",
    0x0040: "PROCESS_DUP_HANDLE",
    0x0080: "PROCESS_CREATE_PROCESS",
    0x0100: "PROCESS_SET_QUOTA",
    0x0200: "PROCESS_SET_INFORMATION",
    0x0400: "PROCESS_QUERY_INFORMATION",
    0x0800: "PROCESS_SUSPEND_RESUME",
    0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
    0x2000: "PROCESS_SET_LIMITED_INFORMATION",
    0x001F_0FFF: "PROCESS_ALL_ACCESS",
    0x0010_0000: "SYNCHRONIZE",
}

# Memory allocation type (VirtualAllocEx flAllocationType)
_MEM_ALLOC_FLAGS: dict[int, str] = {
    0x0000_1000: "MEM_COMMIT",
    0x0000_2000: "MEM_RESERVE",
    0x0000_4000: "MEM_DECOMMIT",
    0x0000_8000: "MEM_RELEASE",
    0x0008_0000: "MEM_RESET",
    0x0010_0000: "MEM_TOP_DOWN",
    0x0020_0000: "MEM_WRITE_WATCH",
    0x0040_0000: "MEM_PHYSICAL",
    0x0100_0000: "MEM_RESET_UNDO",
    0x2000_0000: "MEM_LARGE_PAGES",
}

# Memory protection (VirtualAllocEx/VirtualProtectEx flProtect/flNewProtect)
_MEM_PROTECT_FLAGS: dict[int, str] = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}

# CreateToolhelp32Snapshot dwFlags
_TH32CS_FLAGS: dict[int, str] = {
    0x01: "TH32CS_SNAPHEAPLIST",
    0x02: "TH32CS_SNAPPROCESS",
    0x04: "TH32CS_SNAPTHREAD",
    0x08: "TH32CS_SNAPMODULE",
    0x10: "TH32CS_SNAPMODULE32",
    0x80000000: "TH32CS_INHERIT",
}

# Thread creation flags (CreateRemoteThread dwCreationFlags)
_THREAD_CREATION_FLAGS: dict[int, str] = {
    0x00: "0",
    0x04: "CREATE_SUSPENDED",
    0x00010000: "STACK_SIZE_PARAM_IS_A_RESERVATION",
}

# Maps (api_name, param_name) to the flag lookup table
_PARAM_FLAG_MAP: dict[tuple[str, str], dict[int, str]] = {
    ("OpenProcess", "dwDesiredAccess"): _PROCESS_ACCESS_FLAGS,
    ("VirtualAllocEx", "flAllocationType"): _MEM_ALLOC_FLAGS,
    ("VirtualAllocEx", "flProtect"): _MEM_PROTECT_FLAGS,
    ("VirtualAlloc", "flAllocationType"): _MEM_ALLOC_FLAGS,
    ("VirtualAlloc", "flProtect"): _MEM_PROTECT_FLAGS,
    ("VirtualProtectEx", "flNewProtect"): _MEM_PROTECT_FLAGS,
    ("VirtualProtect", "flNewProtect"): _MEM_PROTECT_FLAGS,
    ("NtAllocateVirtualMemory", "AllocationType"): _MEM_ALLOC_FLAGS,
    ("NtAllocateVirtualMemory", "Protect"): _MEM_PROTECT_FLAGS,
    ("CreateToolhelp32Snapshot", "dwFlags"): _TH32CS_FLAGS,
    ("CreateRemoteThread", "dwCreationFlags"): _THREAD_CREATION_FLAGS,
    ("CreateRemoteThreadEx", "dwCreationFlags"): _THREAD_CREATION_FLAGS,
    ("CreateThread", "dwCreationFlags"): _THREAD_CREATION_FLAGS,
}


def _decode_flags(value: int, flag_table: dict[int, str]) -> str:
    """Decode a bitmask value into symbolic flag names."""
    if not isinstance(value, int) or value < 0:
        return ""
    if value in flag_table:
        return flag_table[value]
    parts = []
    remaining = value
    # Sort by value descending to match largest flags first
    for flag_val, flag_name in sorted(flag_table.items(), reverse=True):
        if flag_val == 0:
            continue
        if remaining & flag_val == flag_val:
            parts.append(flag_name)
            remaining &= ~flag_val
    if remaining:
        parts.append(f"0x{remaining:x}")
    return " | ".join(reversed(parts)) if parts else f"0x{value:x}"


# ---------------------------------------------------------------------------
# Toolhelp structure decoding
# ---------------------------------------------------------------------------

def _decode_processentry32w(param_data: dict) -> dict[str, Any] | None:
    """Decode PROCESSENTRY32W from uint64 slot values."""
    slots = param_data.get("values", [])
    if len(slots) < 8:
        return None

    # Reconstruct raw bytes from uint64 slots
    raw = b""
    for v in slots:
        raw += struct.pack("<Q", v)

    if len(raw) < 44:
        return None

    dw_size = struct.unpack_from("<I", raw, 0)[0]
    # PROCESSENTRY32W.dwSize should be 568
    if dw_size != 568 and dw_size != 556:
        # 568 = sizeof(PROCESSENTRY32W), 556 = sizeof(PROCESSENTRY32A)
        return None

    th32_process_id = struct.unpack_from("<I", raw, 8)[0]
    cnt_threads = struct.unpack_from("<I", raw, 24)[0]
    th32_parent_process_id = struct.unpack_from("<I", raw, 28)[0]

    # Extract szExeFile (starts at offset 40)
    exe_name = ""
    if dw_size == 568 and len(raw) >= 44 + 10:
        # Wide string (UTF-16LE)
        exe_bytes = raw[40:40 + 520]
        try:
            exe_name = exe_bytes.decode("utf-16-le", errors="replace").split("\x00")[0]
        except Exception:
            pass
    elif dw_size == 556 and len(raw) >= 44 + 10:
        # ANSI string
        exe_bytes = raw[40:40 + 260]
        try:
            exe_name = exe_bytes.decode("ascii", errors="replace").split("\x00")[0]
        except Exception:
            pass

    if not exe_name and th32_process_id == 0:
        return None

    result: dict[str, Any] = {
        "th32ProcessID": th32_process_id,
        "th32ParentProcessID": th32_parent_process_id,
        "cntThreads": cnt_threads,
    }
    if exe_name:
        result["szExeFile"] = exe_name

    return result


def _parse_param_values(
    param_block: bytes, count: int, size_field: int
) -> list[dict[str, Any]]:
    """Parse parameter values from a pre-call or post-call data block."""
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
    """Try to decode UTF-16LE and ASCII strings from uint64 value sequences."""
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

    # Also scan for ASCII strings (at least 4 printable chars)
    if not strings:
        i = 0
        while i < len(raw) - 3:
            if 0x20 <= raw[i] <= 0x7E:
                end = i
                while end < len(raw) and 0x20 <= raw[end] <= 0x7E:
                    end += 1
                if end - i >= 4:
                    try:
                        s = raw[i:end].decode("ascii")
                        if all(c.isprintable() for c in s):
                            strings.append(s)
                    except (UnicodeDecodeError, ValueError):
                        pass
                    i = end
                else:
                    i += 1
            else:
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
    fmt_version = struct.unpack_from("<I", rec, 0x04)[0]
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
    top_api = (embedded_names[0] if embedded_names else None) or defs_name
    result["api_name"] = top_api
    result["top_api"] = top_api  # explicit alias — what analysts usually want
    if defs_name and defs_name != top_api:
        result["resolved_api"] = defs_name
        result["native_api"] = defs_name  # backward compat alias
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

        # Format v8 packs params into 2 large groups; flag as "grouped"
        if fmt_version >= 8 and count <= 2:
            total_slots = 0
            for p in range(count):
                do = 0x92 + p * 4
                if do + 4 <= len(rec):
                    total_slots += rec[do + 1] >> 4
            if total_slots > 10:
                result["param_format"] = "grouped"

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
            if pre["slot_count"] >= 4 and pre["values"]:
                # Skip the first few header slots (flag, addr, value)
                # and scan remaining for UTF-16LE strings
                string_slots = pre["values"][2:] if pre["slot_count"] < 5 else pre["values"][1:]
                strings = _extract_strings_from_values(string_slots)
                if strings:
                    pinfo["strings"] = strings

            params_out.append(pinfo)

        # Skip return-value slots when assigning names
        api_for_naming = result.get("api_name") or ""
        param_names = COMMON_API_PARAMS.get(api_for_naming)
        if param_names:
            name_idx = 0
            for p in params_out:
                if name_idx >= len(param_names):
                    break
                # Skip the return-value slot (detected by pre/post comparison)
                if p.get("is_return"):
                    continue
                p["name"] = param_names[name_idx]
                name_idx += 1

        # Decode flag/enum values for named parameters
        if api_for_naming:
            for p in params_out:
                pname = p.get("name")
                if not pname:
                    continue
                flag_table = _PARAM_FLAG_MAP.get((api_for_naming, pname))
                if flag_table is None:
                    continue
                val = p.get("pre_value")
                if isinstance(val, int):
                    decoded_str = _decode_flags(val, flag_table)
                    if decoded_str:
                        p["decoded_value"] = decoded_str

        if api_for_naming in ("Process32FirstW", "Process32NextW", "Process32First", "Process32Next"):
            # The second actual parameter (lppe) contains the PROCESSENTRY32W struct.
            # In the param block it's typically at index 1 or 2 depending on return slot.
            for p in params_out:
                if p.get("name") == "lppe" and post_params:
                    # Use post-call values since the struct is filled after the call
                    p_idx_val = p["index"]
                    if p_idx_val < len(post_params):
                        decoded = _decode_processentry32w(post_params[p_idx_val])
                        if decoded:
                            p["decoded_struct"] = decoded

        result["parameters"] = params_out
        if return_value is not None:
            result["return_value"] = return_value
            result["return_hex"] = f"0x{return_value:x}"

    return result


def _parse_process_info(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {}
    offset = 0

    if len(data) < 20:
        return info

    # First 4 bytes: 1-based process index from the binary (internal use only).
    # We intentionally do NOT expose this as "process_index" since the public
    # API uses 0-based indices derived from ZIP path names (see parse_apmx).
    info["_raw_process_index"] = struct.unpack_from("<I", data, 0)[0]
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
            pinfo["index"] = idx  # canonical 0-based index from ZIP path
            # Remove internal raw field — only expose the 0-based index
            pinfo.pop("_raw_process_index", None)

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


def _iso_to_filetime(iso_str: str) -> int | None:
    """Convert an ISO 8601 datetime string to Windows FILETIME ticks."""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - _FILETIME_EPOCH
        return int(delta.total_seconds() * _FILETIME_TICKS_PER_SEC)
    except (ValueError, OverflowError):
        return None


def get_apmx_calls(
    file_path: str | Path,
    process_index: int = 0,
    api_filter: str | None = None,
    limit: int = 500,
    offset: int = 0,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
) -> dict[str, Any]:
    """Extract API call records from an APMX capture.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to read (0 = first/only)
        api_filter: Optional API name substring filter (case-insensitive)
        limit: Max records to return
        offset: Skip first N matching records (pagination)
        time_range_start: ISO 8601 datetime — only include calls at or after this time
        time_range_end: ISO 8601 datetime — only include calls at or before this time

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

    # Convert time range to FILETIME for fast comparison
    ft_start = _iso_to_filetime(time_range_start) if time_range_start else None
    ft_end = _iso_to_filetime(time_range_end) if time_range_end else None

    records = []
    skipped = 0
    filter_lower = api_filter.lower() if api_filter else None

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        # Time range filter (timestamp at offset 0x48)
        if (ft_start is not None or ft_end is not None) and len(rec) >= 0x50:
            filetime = struct.unpack_from("<Q", rec, 0x48)[0]
            if ft_start is not None and filetime < ft_start:
                continue
            if ft_end is not None and filetime > ft_end:
                continue

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
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
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

            # Temporal check for tls_callback_execution:
            # Only flag if FLS/TLS APIs appear in the first 200 records AND
            # an injection chain pattern is also present.
            if pattern.get("_requires_temporal_check") and pattern_id == "tls_callback_execution":
                fls_tls_apis = {"FlsAlloc", "FlsSetValue", "TlsAlloc", "TlsSetValue",
                                "FlsFree", "TlsFree", "FlsGetValue", "TlsGetValue"}
                early_fls = any(
                    api_first_seen.get(api, 999999) < 200
                    for api in (matched & fls_tls_apis)
                )
                has_injection = any(
                    api in all_apis
                    for api in ("VirtualAllocEx", "WriteProcessMemory",
                                "NtAllocateVirtualMemory", "NtWriteVirtualMemory")
                )
                if not (early_fls and has_injection):
                    continue

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


# ---------------------------------------------------------------------------
# Injection chain extraction
# ---------------------------------------------------------------------------

def get_apmx_injection_info(
    file_path: str | Path,
    process_index: int = 0,
) -> dict[str, Any]:
    """Extract enriched injection chain details from an APMX capture.

    Wraps correlate_apmx_handles() and enriches each chain with:
    - target_pid: from OpenProcess dwProcessId parameter
    - target_process: from Process32FirstW/NextW decoded structs
    - requested_alloc_size: from VirtualAllocEx dwSize pre-value
    - aligned_alloc_size: from VirtualAllocEx dwSize post-value
    - write_size: from WriteProcessMemory nSize
    - shellcode_size: best estimate (write_size or requested_alloc_size)
    - start_address: from CreateRemoteThread lpStartAddress
    - injection_technique: detected technique label

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        process_index: Which process to analyze

    Returns:
        Dict with enriched injection chains
    """
    file_path = Path(file_path)

    # Get handle chains
    handle_result = correlate_apmx_handles(file_path, process_index=process_index)
    if "error" in handle_result:
        return handle_result

    # Get pattern detection for technique labeling
    pattern_result = detect_apmx_patterns(file_path, process_index=process_index)
    pattern_ids = {d["pattern_id"] for d in pattern_result.get("details", [])}

    # Collect Process32 results for target process lookup
    toolhelp_entries: list[dict[str, Any]] = []
    toolhelp_exe_strings: Counter[str] = Counter()
    p32_calls = get_apmx_calls(file_path, process_index=process_index, api_filter="Process32", limit=200)
    p32_range: tuple[int, int] | None = None
    if p32_calls.get("returned", 0) > 0:
        p32_indices = [c["call_index"] for c in p32_calls["calls"]]
        p32_range = (min(p32_indices), max(p32_indices))
        p32_details = get_apmx_call_details(file_path, process_index=process_index, call_indices=p32_indices)
        for c in p32_details.get("calls", []):
            for p in c.get("parameters", []):
                ds = p.get("decoded_struct")
                if ds and ds.get("szExeFile"):
                    toolhelp_entries.append(ds)

    # Fallback: scan for .exe strings near Process32 calls
    if not toolhelp_entries and p32_range:
        ctx_start = max(0, p32_range[0] - 5)
        ctx_end = p32_range[1] + 10
        ctx_indices = list(range(ctx_start, ctx_end + 1))
        ctx_details = get_apmx_call_details(
            file_path, process_index=process_index,
            call_indices=ctx_indices, limit=len(ctx_indices),
        )
        for c in ctx_details.get("calls", []):
            for p in c.get("parameters", []):
                for s in p.get("strings", []):
                    low = s.strip().lower()
                    if low.endswith(".exe") and len(s) < 50:
                        toolhelp_exe_strings[s.strip()] += 1

    # Build injection chains
    injection_chains: list[dict[str, Any]] = []

    for chain in handle_result.get("handle_chains", []):
        if chain["producer_api"] != "OpenProcess":
            continue

        consumer_apis = {c["api"] for c in chain["consumers"]}
        # Must have at least VirtualAllocEx or WriteProcessMemory
        if not (consumer_apis & {"VirtualAllocEx", "WriteProcessMemory", "NtAllocateVirtualMemory"}):
            continue

        chain_info: dict[str, Any] = {
            "handle": chain["handle"],
            "handle_hex": chain["handle_hex"],
            "producer_record": chain["producer_record"],
        }

        # Get OpenProcess details for target PID
        op_details = get_apmx_call_details(
            file_path, process_index=process_index,
            call_indices=[chain["producer_record"]],
        )
        if op_details.get("calls"):
            op_call = op_details["calls"][0]
            for p in op_call.get("parameters", []):
                if p.get("name") == "dwProcessId":
                    chain_info["target_pid"] = p.get("pre_value")
                    break

        # Look up target process name from Toolhelp entries
        target_pid = chain_info.get("target_pid")
        if target_pid and toolhelp_entries:
            for te in toolhelp_entries:
                if te.get("th32ProcessID") == target_pid:
                    chain_info["target_process"] = te.get("szExeFile")
                    break

        # Fallback: most-common .exe string near Process32 calls
        if "target_process" not in chain_info and toolhelp_exe_strings:
            most_common = toolhelp_exe_strings.most_common(1)[0][0]
            chain_info["target_process"] = most_common

        # Get VirtualAllocEx details
        for consumer in chain["consumers"]:
            if consumer["api"] in ("VirtualAllocEx", "NtAllocateVirtualMemory"):
                va_details = get_apmx_call_details(
                    file_path, process_index=process_index,
                    call_indices=[consumer["record"]],
                )
                if va_details.get("calls"):
                    va_call = va_details["calls"][0]
                    for p in va_call.get("parameters", []):
                        if p.get("name") == "dwSize":
                            chain_info["requested_alloc_size"] = p.get("pre_value")
                            if p.get("post_value") is not None and p.get("changed"):
                                chain_info["aligned_alloc_size"] = p["post_value"]
                            elif p.get("post_value") is not None:
                                chain_info["aligned_alloc_size"] = p["post_value"]
                            break
                    chain_info["alloc_return"] = va_call.get("return_value")
                    if va_call.get("return_hex"):
                        chain_info["alloc_return_hex"] = va_call["return_hex"]
                break

        # Get WriteProcessMemory details
        for consumer in chain["consumers"]:
            if consumer["api"] in ("WriteProcessMemory", "NtWriteVirtualMemory"):
                wpm_details = get_apmx_call_details(
                    file_path, process_index=process_index,
                    call_indices=[consumer["record"]],
                )
                if wpm_details.get("calls"):
                    wpm_call = wpm_details["calls"][0]
                    for p in wpm_call.get("parameters", []):
                        if p.get("name") in ("nSize", "BufferSize"):
                            chain_info["write_size"] = p.get("pre_value")
                            break
                break

        # Get CreateRemoteThread details
        for consumer in chain["consumers"]:
            if consumer["api"] in ("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx"):
                crt_details = get_apmx_call_details(
                    file_path, process_index=process_index,
                    call_indices=[consumer["record"]],
                )
                if crt_details.get("calls"):
                    crt_call = crt_details["calls"][0]
                    for p in crt_call.get("parameters", []):
                        if p.get("name") == "lpStartAddress":
                            sa = p.get("pre_value")
                            if sa:
                                chain_info["start_address"] = sa
                                chain_info["start_address_hex"] = f"0x{sa:x}"
                            break
                break

        # Shellcode size: prefer requested_alloc_size from VirtualAllocEx (most
        # reliable).  Only use write_size if it's smaller (partial write).
        # WriteProcessMemory nSize can be unreliable due to multi-slot parsing
        # artifacts in the APMX format.
        write_sz = chain_info.get("write_size")
        req_sz = chain_info.get("requested_alloc_size")
        if req_sz:
            if write_sz and 0 < write_sz <= req_sz:
                chain_info["shellcode_size"] = write_sz
            else:
                chain_info["shellcode_size"] = req_sz
        else:
            chain_info["shellcode_size"] = write_sz

        # Injection technique label
        if "tls_callback_execution" in pattern_ids:
            chain_info["injection_technique"] = "Thread Local Storage (TLS Callback)"
        elif "classic_injection" in pattern_ids:
            chain_info["injection_technique"] = "Classic Process Injection"
        elif "apc_injection" in pattern_ids:
            chain_info["injection_technique"] = "APC Queue Injection"
        elif "process_hollowing" in pattern_ids:
            chain_info["injection_technique"] = "Process Hollowing"
        else:
            chain_info["injection_technique"] = "Unknown"

        # Consumer summary
        chain_info["chain"] = [
            {"api": chain["producer_api"], "record": chain["producer_record"]},
        ] + [
            {"api": c["api"], "record": c["record"]} for c in chain["consumers"]
        ]

        injection_chains.append(chain_info)

    return {
        "total_records": handle_result.get("total_records", 0),
        "injection_chains": injection_chains,
        "chain_count": len(injection_chains),
        "patterns_detected": [d["pattern_id"] for d in pattern_result.get("details", [])],
    }


# ---------------------------------------------------------------------------
# Context window query utilities
# ---------------------------------------------------------------------------

def get_apmx_calls_around(
    file_path: str | Path,
    call_index: int,
    before: int = 10,
    after: int = 10,
    process_index: int = 0,
) -> dict[str, Any]:
    """Get context window of calls around a specific record index.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        call_index: The center record index
        before: Number of records before the target to include
        after: Number of records after the target to include
        process_index: Which process to read

    Returns:
        Dict with call records in the range [call_index-before, call_index+after]
    """
    start = max(0, call_index - before)
    end = call_index + after
    indices = list(range(start, end + 1))

    result = get_apmx_call_details(
        file_path, process_index=process_index,
        call_indices=indices,
    )

    if "error" in result:
        return result

    return {
        "center_index": call_index,
        "range_start": start,
        "range_end": end,
        "total_records": result.get("total_records", 0),
        "returned": result.get("returned", 0),
        "calls": result.get("calls", []),
    }


def search_apmx_params(
    file_path: str | Path,
    value: int | str,
    process_index: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Search all call records for a specific parameter value.

    Searches pre-call and post-call parameter values for exact integer matches,
    or string containment for string values.

    Args:
        file_path: Path to .apmx64 or .apmx86 file
        value: Integer value or string to search for
        process_index: Which process to search
        limit: Maximum number of matching calls to return

    Returns:
        Dict with matching calls and the matched parameters highlighted
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

    is_int_search = isinstance(value, int)
    str_lower = str(value).lower() if not is_int_search else None

    matches: list[dict[str, Any]] = []

    for i in range(num_records):
        off = offsets_arr[i]
        next_off = offsets_arr[i + 1] if i + 1 < num_records else len(api_data)
        rec = api_data[off:next_off]

        if len(rec) < 0x92:
            continue

        parsed = _parse_call_record(rec, i, defs_blob=defs_blob)
        params = parsed.get("parameters", [])
        matched_params: list[dict[str, Any]] = []

        for p in params:
            if is_int_search:
                if p.get("pre_value") == value or p.get("post_value") == value:
                    matched_params.append(p)
            else:
                # String search in parameter strings and hex values
                for field in ("pre_value_hex", "post_value_hex"):
                    fv = p.get(field, "")
                    if str_lower and str_lower in str(fv).lower():
                        matched_params.append(p)
                        break
                else:
                    for s in p.get("strings", []):
                        if str_lower and str_lower in s.lower():
                            matched_params.append(p)
                            break

        if matched_params:
            matches.append({
                "call_index": i,
                "api_name": parsed.get("api_name"),
                "top_api": parsed.get("top_api"),
                "timestamp": parsed.get("timestamp"),
                "matched_params": matched_params,
            })

        if len(matches) >= limit:
            break

    return {
        "total_records": num_records,
        "search_value": value,
        "matches": matches,
        "match_count": len(matches),
    }
