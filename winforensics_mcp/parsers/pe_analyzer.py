from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


def check_pefile_available() -> None:
    """Raise error if pefile library not available"""
    if not PEFILE_AVAILABLE:
        raise ImportError(
            "pefile library not installed. Install with: pip install pefile"
        )


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0

    entropy = 0.0
    data_len = len(data)

    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    # Calculate entropy
    for count in freq:
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)

    return round(entropy, 2)


def get_file_hashes(file_path: Path) -> dict[str, str]:
    """Calculate MD5, SHA1, SHA256 hashes of a file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def get_pe_type(pe: "pefile.PE") -> str:
    """Determine PE file type from characteristics"""
    machine_types = {
        0x14c: "x86",
        0x8664: "x86-64",
        0x1c0: "ARM",
        0xaa64: "ARM64",
    }

    arch = machine_types.get(pe.FILE_HEADER.Machine, "Unknown")

    # Determine subsystem
    if hasattr(pe, "OPTIONAL_HEADER"):
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        subsystem_names = {
            1: "Native",
            2: "GUI",
            3: "Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Driver",
            12: "EFI Runtime Driver",
            14: "Xbox",
        }
        subsys_name = subsystem_names.get(subsystem, "Unknown")
    else:
        subsys_name = "Unknown"

    # Check if DLL
    is_dll = pe.FILE_HEADER.Characteristics & 0x2000
    file_type = "DLL" if is_dll else "executable"

    # Check PE32 vs PE32+
    pe_format = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20b else "PE32"

    return f"{pe_format} {file_type} ({subsys_name}) {arch}"


def get_compile_timestamp(pe: "pefile.PE") -> Optional[str]:
    """Extract compile timestamp from PE header"""
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp and timestamp > 0:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat()
    except (OSError, ValueError):
        pass
    return None


def get_sections_info(pe: "pefile.PE") -> list[dict[str, Any]]:
    """Extract section information with entropy analysis"""
    sections = []

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        except Exception:
            name = str(section.Name)

        section_data = section.get_data()
        entropy = calculate_entropy(section_data)

        section_info = {
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
        }

        # Flag suspicious characteristics
        suspicious = []

        # High entropy (>7.0) suggests encryption/packing
        if entropy > 7.0:
            suspicious.append("high_entropy")

        # Executable + Writable is suspicious
        if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
            suspicious.append("exec_writable")

        # Raw size is 0 but virtual size is not (unpacking stub)
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            suspicious.append("empty_raw_section")

        # Common packer section names
        packer_sections = ["UPX", ".packed", ".MPRESS", "ASPack", ".nsp", ".enigma"]
        if any(ps.lower() in name.lower() for ps in packer_sections):
            suspicious.append("packer_section_name")

        if suspicious:
            section_info["suspicious"] = suspicious

        sections.append(section_info)

    return sections


def get_imports_summary(pe: "pefile.PE", max_per_dll: int = 20) -> dict[str, list[str]]:
    """Extract import summary (DLL -> functions)"""
    imports: dict[str, list[str]] = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
        except Exception:
            dll_name = str(entry.dll)

        functions = []
        for imp in entry.imports:
            if imp.name:
                try:
                    func_name = imp.name.decode("utf-8", errors="ignore")
                except Exception:
                    func_name = str(imp.name)
                functions.append(func_name)
            elif imp.ordinal:
                functions.append(f"ordinal_{imp.ordinal}")

        # Limit functions per DLL to avoid huge output
        if len(functions) > max_per_dll:
            imports[dll_name] = functions[:max_per_dll] + [f"... and {len(functions) - max_per_dll} more"]
        else:
            imports[dll_name] = functions

    return imports


def get_exports_summary(pe: "pefile.PE", max_exports: int = 50) -> list[str]:
    """Extract export function names"""
    exports = []

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            try:
                exports.append(exp.name.decode("utf-8", errors="ignore"))
            except Exception:
                exports.append(str(exp.name))
        elif exp.ordinal:
            exports.append(f"ordinal_{exp.ordinal}")

        if len(exports) >= max_exports:
            break

    return exports


def detect_suspicious_imports(imports: dict[str, list[str]]) -> list[str]:
    """Detect suspicious API usage patterns"""
    suspicious = []

    # Suspicious APIs by category
    suspicious_apis = {
        "process_injection": [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
            "NtCreateThreadEx", "RtlCreateUserThread", "NtQueueApcThread",
        ],
        "code_injection": [
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        ],
        "credential_theft": [
            "CredEnumerateA", "CredEnumerateW", "LsaRetrievePrivateData",
            "SamQueryInformationUser", "SamGetPrivateData",
        ],
        "evasion": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
        ],
        "persistence": [
            "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
            "CreateServiceA", "CreateServiceW",
        ],
        "network": [
            "InternetOpenA", "InternetOpenW", "URLDownloadToFileA",
            "HttpSendRequestA", "WSAStartup", "connect", "send", "recv",
        ],
        "keylogging": [
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
            "GetKeyState", "GetKeyboardState",
        ],
        "screen_capture": [
            "BitBlt", "GetDC", "GetWindowDC", "CreateCompatibleDC",
        ],
    }

    # Flatten all imports
    all_imports = []
    for dll_funcs in imports.values():
        all_imports.extend(dll_funcs)

    # Check for suspicious patterns
    for category, apis in suspicious_apis.items():
        found = [api for api in apis if api in all_imports]
        if found:
            if category == "process_injection" and len(found) >= 2:
                suspicious.append(f"Process injection APIs detected: {', '.join(found[:3])}")
            elif category == "code_injection" and len(found) >= 2:
                suspicious.append(f"Code injection APIs detected: {', '.join(found[:3])}")
            elif category == "credential_theft":
                suspicious.append(f"Credential access APIs detected: {', '.join(found[:3])}")
            elif category == "evasion":
                suspicious.append(f"Anti-debugging/evasion APIs detected: {', '.join(found[:3])}")
            elif category == "keylogging" and len(found) >= 2:
                suspicious.append(f"Keylogging APIs detected: {', '.join(found[:3])}")

    return suspicious


def detect_packer_signatures(pe: "pefile.PE") -> list[str]:
    """Detect common packer/crypter signatures"""
    packers = []

    # Check section names for known packers
    packer_sections = {
        "UPX0": "UPX",
        "UPX1": "UPX",
        "UPX2": "UPX",
        ".MPRESS1": "MPRESS",
        ".MPRESS2": "MPRESS",
        "ASPack": "ASPack",
        ".aspack": "ASPack",
        ".adata": "ASPack",
        "PECompact2": "PECompact",
        ".petite": "Petite",
        ".yP": "Y0da Protector",
        "nsp0": "NsPack",
        "nsp1": "NsPack",
        ".nsp0": "NsPack",
        ".enigma1": "Enigma Protector",
        ".enigma2": "Enigma Protector",
        "VProtect": "VMProtect",
        ".themida": "Themida",
    }

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        except Exception:
            continue

        for packer_name, packer_id in packer_sections.items():
            if packer_name.lower() in name.lower():
                if f"{packer_id} packed" not in packers:
                    packers.append(f"{packer_id} packed")

    # Check for high overall entropy (suggesting packing)
    total_size = 0
    weighted_entropy = 0.0
    for section in pe.sections:
        data = section.get_data()
        if data:
            size = len(data)
            total_size += size
            weighted_entropy += calculate_entropy(data) * size

    if total_size > 0:
        avg_entropy = weighted_entropy / total_size
        if avg_entropy > 7.2:
            packers.append("High entropy (likely packed/encrypted)")

    return packers


def get_version_info(pe: "pefile.PE") -> Optional[dict[str, str]]:
    """Extract version information from PE resources"""
    version_info = {}

    if not hasattr(pe, "FileInfo"):
        return None

    try:
        for file_info in pe.FileInfo:
            for info in file_info:
                if hasattr(info, "StringTable"):
                    for st in info.StringTable:
                        for entry in st.entries.items():
                            key = entry[0].decode("utf-8", errors="ignore") if isinstance(entry[0], bytes) else str(entry[0])
                            val = entry[1].decode("utf-8", errors="ignore") if isinstance(entry[1], bytes) else str(entry[1])
                            if val and val.strip():
                                version_info[key] = val.strip()
    except Exception:
        pass

    return version_info if version_info else None


def extract_strings(pe: "pefile.PE", min_length: int = 6, max_strings: int = 200) -> dict[str, list[str]]:
    """Extract ASCII and Unicode strings from PE"""
    ascii_strings = []
    unicode_strings = []

    # Get raw data
    try:
        data = pe.__data__
    except Exception:
        return {"ascii": [], "unicode": []}

    # Extract ASCII strings
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                ascii_strings.append("".join(current))
                if len(ascii_strings) >= max_strings:
                    break
            current = []

    # Extract Unicode strings (UTF-16LE)
    current = []
    i = 0
    while i < len(data) - 1 and len(unicode_strings) < max_strings:
        char = data[i] | (data[i + 1] << 8)
        if 32 <= char < 127 and data[i + 1] == 0:
            current.append(chr(char))
        else:
            if len(current) >= min_length:
                s = "".join(current)
                if s not in ascii_strings:  # Avoid duplicates
                    unicode_strings.append(s)
            current = []
        i += 2

    return {
        "ascii": ascii_strings[:max_strings],
        "unicode": unicode_strings[:max_strings],
    }


def analyze_pe(
    file_path: str | Path,
    calculate_hashes: bool = True,
    extract_strings_flag: bool = False,
    check_signatures: bool = True,
    detail_level: str = "standard",
) -> dict[str, Any]:
    """
    Analyze a Windows PE file (EXE/DLL/SYS).

    Args:
        file_path: Path to the PE file
        calculate_hashes: Calculate MD5, SHA1, SHA256, Imphash
        extract_strings_flag: Extract ASCII/Unicode strings
        check_signatures: Check for packer/crypter signatures
        detail_level: "minimal", "standard", or "verbose"

    Returns:
        Analysis results dictionary
    """
    check_pefile_available()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"PE file not found: {file_path}")

    result: dict[str, Any] = {
        "filename": file_path.name,
        "file_size": file_path.stat().st_size,
    }

    # Calculate file hashes
    if calculate_hashes:
        result["hashes"] = get_file_hashes(file_path)

    # Parse PE
    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError as e:
        result["error"] = f"Invalid PE file: {e}"
        return result

    try:
        # Basic info
        result["pe_type"] = get_pe_type(pe)
        result["compile_time"] = get_compile_timestamp(pe)

        if hasattr(pe, "OPTIONAL_HEADER"):
            result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

        # Imphash
        if calculate_hashes:
            try:
                imphash = pe.get_imphash()
                if imphash:
                    result["hashes"]["imphash"] = imphash
            except Exception:
                pass

        # Sections
        if detail_level in ["standard", "verbose"]:
            result["sections"] = get_sections_info(pe)

        # Imports
        imports = get_imports_summary(pe)
        if detail_level == "minimal":
            result["imports_count"] = sum(len(v) for v in imports.values())
            result["imported_dlls"] = list(imports.keys())
        elif detail_level == "standard":
            # Summarize imports - show suspicious DLLs and key APIs
            result["imports_summary"] = imports
        else:  # verbose
            result["imports"] = imports

        # Exports
        if detail_level in ["standard", "verbose"]:
            exports = get_exports_summary(pe)
            if exports:
                result["exports"] = exports

        # Version info
        version_info = get_version_info(pe)
        if version_info:
            result["version_info"] = version_info
        else:
            result["version_info"] = None

        # Suspicious indicators
        suspicious = []

        if check_signatures:
            packers = detect_packer_signatures(pe)
            suspicious.extend(packers)

        if detail_level in ["standard", "verbose"]:
            api_suspicious = detect_suspicious_imports(imports)
            suspicious.extend(api_suspicious)

        # Check for no version info (common in malware)
        if not version_info:
            suspicious.append("No version info")

        # Check for suspicious compile time
        compile_time = get_compile_timestamp(pe)
        if compile_time:
            try:
                ct = datetime.fromisoformat(compile_time.replace("Z", "+00:00"))
                if ct.year < 2000 or ct > datetime.now(timezone.utc):
                    suspicious.append(f"Suspicious compile time: {compile_time}")
            except Exception:
                pass

        if suspicious:
            result["suspicious_indicators"] = suspicious

        # Strings extraction
        if extract_strings_flag:
            result["strings"] = extract_strings(pe)

    finally:
        pe.close()

    return result
