"""Tests for API Monitor module: patterns, APMX parser, and definitions DB."""

import io
import struct
import zipfile
from pathlib import Path

import pytest

from winforensics_mcp.parsers.api_monitor import API_DB_AVAILABLE
from winforensics_mcp.parsers.api_monitor.patterns import PATTERNS, detect_api_patterns
from winforensics_mcp.parsers.api_monitor.apmx_parser import (
    _extract_api_names,
    _read_utf16le_string,
    _parse_monitoring_log,
    _parse_param_values,
    _parse_call_record,
    _filetime_to_iso,
    parse_apmx,
    get_apmx_calls,
    get_apmx_api_stats,
    detect_apmx_patterns,
    get_apmx_call_details,
    correlate_apmx_handles,
)


# Path to the real APMX test capture (may not exist on all systems)
APMX_TEST_FILE = Path("/home/xtk/labs/AI/tests/Ghost-Thread.apmx64")
# Path to the pre-built API definitions DB
API_DB_PATH = Path(__file__).resolve().parent.parent / "winforensics_mcp" / "data" / "api_definitions.db"


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------

class TestApiMonitorImports:
    """Test that all API Monitor functions are importable."""

    def test_api_db_available_flag(self):
        assert isinstance(API_DB_AVAILABLE, bool)
        assert API_DB_AVAILABLE is True

    def test_parser_level_imports(self):
        from winforensics_mcp.parsers import (
            build_api_database,
            lookup_api,
            search_api_by_category,
            get_api_stats,
            get_module_apis,
            detect_api_patterns,
            analyze_pe_imports_detailed,
            parse_apmx,
            get_apmx_calls,
            get_apmx_api_stats,
            detect_apmx_patterns,
        )
        assert callable(parse_apmx)
        assert callable(get_apmx_calls)
        assert callable(get_apmx_api_stats)
        assert callable(detect_apmx_patterns)
        assert callable(lookup_api)
        assert callable(build_api_database)

    def test_server_imports_apmx(self):
        """Verify server module can import APMX functions."""
        import winforensics_mcp.server  # noqa: F401


# ---------------------------------------------------------------------------
# Pattern library tests
# ---------------------------------------------------------------------------

class TestPatternLibrary:
    """Test the attack pattern definitions."""

    def test_pattern_count(self):
        """Should have at least 10 patterns."""
        assert len(PATTERNS) >= 10

    def test_pattern_structure(self):
        """Every pattern must have required fields."""
        for pid, p in PATTERNS.items():
            assert "name" in p, f"{pid} missing name"
            assert "description" in p, f"{pid} missing description"
            assert "mitre_id" in p, f"{pid} missing mitre_id"
            assert "required" in p, f"{pid} missing required"
            assert "min_match" in p, f"{pid} missing min_match"
            assert "risk" in p, f"{pid} missing risk"
            assert isinstance(p["required"], set), f"{pid} required should be set"
            assert p["risk"] in ("high", "medium", "low"), f"{pid} invalid risk"
            assert p["min_match"] > 0, f"{pid} min_match must be positive"
            assert p["mitre_id"].startswith("T"), f"{pid} mitre_id should start with T"

    def test_classic_injection_pattern(self):
        p = PATTERNS["classic_injection"]
        assert "OpenProcess" in p["required"]
        assert "VirtualAllocEx" in p["required"]
        assert "WriteProcessMemory" in p["required"]
        assert "CreateRemoteThread" in p["required"]
        assert p["risk"] == "high"
        assert p["mitre_id"] == "T1055.001"


class TestDetectApiPatterns:
    """Test pattern detection against synthetic import tables."""

    def test_classic_injection_detected(self):
        imports = {
            "KERNEL32.dll": [
                "OpenProcess", "VirtualAllocEx",
                "WriteProcessMemory", "CreateRemoteThread",
            ],
        }
        result = detect_api_patterns(imports)
        assert result["patterns_detected"] > 0
        assert result["risk_level"] == "high"
        ids = [d["pattern_id"] for d in result["details"]]
        assert "classic_injection" in ids

    def test_no_patterns_for_benign_imports(self):
        imports = {
            "KERNEL32.dll": ["GetModuleFileNameW", "ExitProcess", "Sleep"],
            "USER32.dll": ["MessageBoxW"],
        }
        result = detect_api_patterns(imports)
        assert result["patterns_detected"] == 0
        assert result["risk_level"] == "none"

    def test_partial_match_under_threshold(self):
        """One API from a 4-required pattern shouldn't trigger it."""
        imports = {"KERNEL32.dll": ["OpenProcess"]}
        result = detect_api_patterns(imports)
        ids = [d["pattern_id"] for d in result["details"]]
        assert "classic_injection" not in ids

    def test_empty_imports(self):
        result = detect_api_patterns({})
        assert result["patterns_detected"] == 0
        assert result["risk_level"] == "none"

    def test_anti_debug_detected(self):
        imports = {
            "KERNEL32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
        }
        result = detect_api_patterns(imports)
        ids = [d["pattern_id"] for d in result["details"]]
        assert "anti_debug" in ids

    def test_multiple_patterns_detected(self):
        """Imports matching several patterns should all appear."""
        imports = {
            "KERNEL32.dll": [
                "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                "CreateRemoteThread", "GetProcAddress",
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            ],
        }
        result = detect_api_patterns(imports)
        ids = [d["pattern_id"] for d in result["details"]]
        assert "classic_injection" in ids
        assert "anti_debug" in ids

    def test_risk_level_ordering(self):
        """High risk should dominate when mixed."""
        imports = {
            "KERNEL32.dll": [
                "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                "CreateRemoteThread",  # high risk
            ],
            "ADVAPI32.dll": [
                "RegOpenKeyExA", "RegSetValueExA",  # medium risk
            ],
        }
        result = detect_api_patterns(imports)
        assert result["risk_level"] == "high"


# ---------------------------------------------------------------------------
# APMX low-level helper tests
# ---------------------------------------------------------------------------

class TestReadUtf16leString:
    """Test the length-prefixed UTF-16LE string reader."""

    def test_basic_string(self):
        text = "hello"
        encoded = text.encode("utf-16-le")
        data = struct.pack("<I", len(text)) + encoded
        result, new_offset = _read_utf16le_string(data, 0)
        assert result == "hello"
        assert new_offset == 4 + len(encoded)

    def test_empty_string(self):
        data = struct.pack("<I", 0)
        result, new_offset = _read_utf16le_string(data, 0)
        assert result == ""
        assert new_offset == 4

    def test_with_offset(self):
        padding = b"\x00" * 8
        text = "test"
        encoded = text.encode("utf-16-le")
        data = padding + struct.pack("<I", len(text)) + encoded
        result, new_offset = _read_utf16le_string(data, 8)
        assert result == "test"

    def test_truncated_data(self):
        """If data is too short, should return empty."""
        result, offset = _read_utf16le_string(b"\x00\x00", 0)
        assert result == ""


class TestExtractApiNames:
    """Test API name extraction from binary records."""

    def _make_api_name(self, name: str) -> bytes:
        """Build the binary encoding for an API name: 01 00 <len> 00 <ascii> 00"""
        encoded = name.encode("ascii") + b"\x00"
        return b"\x01\x00" + bytes([len(encoded)]) + b"\x00" + encoded

    def test_single_api(self):
        record = b"\x00" * 16 + self._make_api_name("CreateFileW") + b"\x00" * 4
        names = _extract_api_names(record)
        assert "CreateFileW" in names

    def test_multiple_apis(self):
        record = (
            b"\x00" * 8
            + self._make_api_name("OpenProcess")
            + b"\x00" * 4
            + self._make_api_name("VirtualAllocEx")
            + b"\x00" * 4
        )
        names = _extract_api_names(record)
        assert "OpenProcess" in names
        assert "VirtualAllocEx" in names

    def test_empty_record(self):
        names = _extract_api_names(b"\x00" * 10)
        assert names == []

    def test_short_names_filtered(self):
        """Names shorter than 3 chars should be skipped."""
        record = b"\x00" * 4 + self._make_api_name("AB") + b"\x00" * 4
        names = _extract_api_names(record)
        assert "AB" not in names

    def test_non_ascii_filtered(self):
        """Non-ASCII bytes in name position should not produce results."""
        record = b"\x00" * 4 + b"\x01\x00\x08\x00\xff\xfe\xfd\xfc\xfb\xfa\xf9\x00" + b"\x00" * 4
        names = _extract_api_names(record)
        assert len(names) == 0


class TestParseMonitoringLog:
    """Test the UTF-16LE monitoring log parser."""

    def test_load_entries(self):
        text = "inject.exe: Monitoring Module 0x7FF800000000 -> C:\\WINDOWS\\System32\\ntdll.dll.\r\n"
        data = text.encode("utf-16-le")
        entries = _parse_monitoring_log(data)
        assert len(entries) == 1
        assert entries[0]["action"] == "load"
        assert entries[0]["process"] == "inject.exe"
        assert "ntdll.dll" in entries[0]["module"]

    def test_detach_entries(self):
        text = "test.exe: Detaching Module 0x1234 -> C:\\test.dll.\r\n"
        data = text.encode("utf-16-le")
        entries = _parse_monitoring_log(data)
        assert len(entries) == 1
        assert entries[0]["action"] == "unload"

    def test_mixed_entries(self):
        text = (
            "p.exe: Monitoring Module 0xA -> C:\\a.dll.\r\n"
            "p.exe: Detaching Module 0xB -> C:\\b.dll.\r\n"
            "p.exe: Monitoring Module 0xC -> C:\\c.dll.\r\n"
        )
        data = text.encode("utf-16-le")
        entries = _parse_monitoring_log(data)
        assert len(entries) == 3
        assert entries[0]["action"] == "load"
        assert entries[1]["action"] == "unload"
        assert entries[2]["action"] == "load"

    def test_empty_data(self):
        entries = _parse_monitoring_log(b"")
        assert entries == []


# ---------------------------------------------------------------------------
# Synthetic APMX file tests
# ---------------------------------------------------------------------------

def _build_synthetic_apmx(
    process_name: str = "test.exe",
    api_names: list[str] | None = None,
    architecture: str = "64",
) -> bytes:
    """Build a minimal synthetic APMX file in memory.

    Returns bytes that can be written to a temp file for testing.
    """
    if api_names is None:
        api_names = ["CreateFileW", "ReadFile", "CloseHandle"]

    # Build inner ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # info entry: 4 bytes flags + length-prefixed UTF-16LE version string
        version = f"API Monitor v2 Test {architecture}-bit"
        version_encoded = version.encode("utf-16-le")
        info_data = struct.pack("<I", 0) + struct.pack("<I", len(version)) + version_encoded
        zf.writestr("info", info_data)

        # process/0/info: minimal process info
        path = f"C:\\test\\{process_name}"
        path_encoded = path.encode("utf-16-le")
        cmdline = f'"{path}"'
        cmdline_encoded = cmdline.encode("utf-16-le")
        pinfo = (
            struct.pack("<I", 0)           # process_index
            + struct.pack("<I", 0)         # unknown
            + struct.pack("<I", 1234)      # PID
            + struct.pack("<Q", 0x7FF700000000)  # image base
            + struct.pack("<I", len(path)) + path_encoded
            + struct.pack("<I", len(cmdline)) + cmdline_encoded
        )
        zf.writestr("process/0/info", pinfo)

        # Build call records with embedded API names
        data_blob = bytearray()
        offsets = []
        for name in api_names:
            offsets.append(len(data_blob))
            # Build a minimal record with the API name embedded
            encoded_name = name.encode("ascii") + b"\x00"
            name_block = b"\x01\x00" + bytes([len(encoded_name)]) + b"\x00" + encoded_name
            record = b"\x00" * 16 + name_block + b"\x00" * 8
            data_blob.extend(record)

        # calls: uint64 array of offsets
        calls_data = struct.pack(f"<{len(offsets)}Q", *offsets)
        zf.writestr("process/0/calls", calls_data)
        zf.writestr("process/0/data", bytes(data_blob))

        # monitoring log
        log_text = f"{process_name}: Monitoring Module 0x7FF800000000 -> C:\\WINDOWS\\System32\\ntdll.dll.\r\n"
        zf.writestr("log/monitoring.txt", log_text.encode("utf-16-le"))

    zip_bytes = buf.getvalue()

    # Prepend APMX header
    header = b"\r\n\r\n\r\n\tAPI Monitor Test Capture\r\n"
    header += b"\t(c) Test\r\n"
    header = header.ljust(0xD5, b"\r")
    header += b"RBAPMPK"

    return header + zip_bytes


class TestSyntheticApmxParse:
    """Test parse_apmx against synthetic captures."""

    def test_basic_parse(self, tmp_path):
        apmx = _build_synthetic_apmx(process_name="malware.exe", api_names=["CreateFileW", "ReadFile"])
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = parse_apmx(str(f))
        assert result["architecture"] == "64-bit"
        assert result["process_count"] == 1
        assert result["processes"][0]["pid"] == 1234
        assert result["processes"][0]["process_name"] == "malware.exe"
        assert result["processes"][0]["total_calls"] == 2

    def test_module_list(self, tmp_path):
        apmx = _build_synthetic_apmx()
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = parse_apmx(str(f))
        assert result["modules_loaded"] == 1
        assert "ntdll.dll" in result["module_list"][0]

    def test_32bit_architecture(self, tmp_path):
        apmx = _build_synthetic_apmx(architecture="32")
        f = tmp_path / "test.apmx86"
        f.write_bytes(apmx)

        result = parse_apmx(str(f))
        assert result["architecture"] == "32-bit"

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_apmx("/nonexistent/file.apmx64")

    def test_invalid_file(self, tmp_path):
        f = tmp_path / "bad.apmx64"
        f.write_bytes(b"this is not an apmx file at all")
        with pytest.raises(ValueError, match="no ZIP signature"):
            parse_apmx(str(f))


class TestSyntheticApmxCalls:
    """Test get_apmx_calls against synthetic captures."""

    def test_extract_all_calls(self, tmp_path):
        apis = ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_calls(str(f))
        assert result["total_records"] == 4
        assert result["returned"] == 4
        top_apis = [c["top_api"] for c in result["calls"]]
        assert "CreateFileW" in top_apis
        assert "CloseHandle" in top_apis

    def test_api_filter(self, tmp_path):
        apis = ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_calls(str(f), api_filter="File")
        assert result["returned"] == 3  # CreateFileW, ReadFile, WriteFile
        assert result["filter"] == "File"

    def test_limit(self, tmp_path):
        apis = ["A" * 5 + str(i) for i in range(20)]  # AAAAA0 .. AAAAA19
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_calls(str(f), limit=5)
        assert result["returned"] == 5
        assert result["total_records"] == 20

    def test_offset(self, tmp_path):
        apis = ["CreateFileW", "ReadFile", "WriteFile"]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_calls(str(f), offset=1)
        assert result["returned"] == 2
        assert result["offset"] == 1

    def test_invalid_process_index(self, tmp_path):
        apmx = _build_synthetic_apmx()
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_calls(str(f), process_index=99)
        assert "error" in result


class TestSyntheticApmxStats:
    """Test get_apmx_api_stats against synthetic captures."""

    def test_basic_stats(self, tmp_path):
        apis = ["CreateFileW", "ReadFile", "ReadFile", "CloseHandle"]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_api_stats(str(f))
        assert result["total_records"] == 4
        assert result["unique_top_level_apis"] == 3
        # ReadFile should appear twice
        freq = {e["api"]: e["count"] for e in result["top_apis_by_frequency"]}
        assert freq["ReadFile"] == 2
        assert freq["CreateFileW"] == 1


class TestSyntheticApmxPatterns:
    """Test detect_apmx_patterns against synthetic captures."""

    def test_injection_pattern_detected(self, tmp_path):
        apis = [
            "GetModuleFileNameW",  # benign
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = detect_apmx_patterns(str(f))
        assert result["risk_level"] == "high"
        assert result["patterns_detected"] >= 1
        ids = [d["pattern_id"] for d in result["details"]]
        assert "classic_injection" in ids

    def test_no_patterns_for_benign(self, tmp_path):
        apis = ["GetModuleFileNameW", "ExitProcess", "Sleep"]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = detect_apmx_patterns(str(f))
        assert result["risk_level"] == "none"
        assert result["patterns_detected"] == 0

    def test_timeline_ordering(self, tmp_path):
        apis = [
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]
        apmx = _build_synthetic_apmx(api_names=apis)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = detect_apmx_patterns(str(f))
        timeline = result["suspicious_call_timeline"]
        indices = [e["record_index"] for e in timeline]
        assert indices == sorted(indices), "Timeline should be ordered by record index"


# ---------------------------------------------------------------------------
# Integration tests with real capture file
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not APMX_TEST_FILE.exists(), reason="Test APMX capture not available")
class TestRealApmxCapture:
    """Integration tests against the real APMX capture file."""

    def test_parse_metadata(self):
        result = parse_apmx(str(APMX_TEST_FILE))
        assert result["architecture"] == "64-bit"
        assert result["process_count"] == 1
        proc = result["processes"][0]
        assert proc["pid"] > 0
        assert proc["total_calls"] > 1000
        assert "process_name" in proc
        assert "process_path" in proc

    def test_module_list_populated(self):
        result = parse_apmx(str(APMX_TEST_FILE))
        assert result["modules_loaded"] > 10
        dll_names = [m.rsplit("\\", 1)[-1].lower() for m in result["module_list"]]
        assert any("kernel32" in d for d in dll_names)
        assert any("ntdll" in d for d in dll_names)

    def test_call_extraction(self):
        result = get_apmx_calls(str(APMX_TEST_FILE), limit=20)
        assert result["total_records"] > 1000
        assert result["returned"] == 20
        for call in result["calls"]:
            assert "top_api" in call
            assert "call_index" in call
            assert len(call["top_api"]) >= 3

    def test_call_filter(self):
        result = get_apmx_calls(str(APMX_TEST_FILE), api_filter="OpenProcess", limit=50)
        for call in result["calls"]:
            assert any("openprocess" in a.lower() for a in call["all_apis"])

    def test_api_stats(self):
        result = get_apmx_api_stats(str(APMX_TEST_FILE))
        assert result["total_records"] > 1000
        assert result["unique_top_level_apis"] > 50
        assert result["unique_all_apis"] >= result["unique_top_level_apis"]
        assert len(result["top_apis_by_frequency"]) > 0

    def test_pattern_detection_finds_injection(self):
        result = detect_apmx_patterns(str(APMX_TEST_FILE))
        assert result["risk_level"] == "high"
        assert result["patterns_detected"] >= 1
        ids = [d["pattern_id"] for d in result["details"]]
        assert "classic_injection" in ids

        # Should have a timeline
        assert len(result["suspicious_call_timeline"]) > 0

    def test_injection_timeline_order(self):
        """The injection chain should appear in the expected order."""
        result = detect_apmx_patterns(str(APMX_TEST_FILE))
        for det in result["details"]:
            if det["pattern_id"] == "classic_injection":
                tl = det["timeline"]
                api_order = [e["api"] for e in tl]
                # OpenProcess should come before VirtualAllocEx
                assert api_order.index("OpenProcess") < api_order.index("VirtualAllocEx")
                assert api_order.index("VirtualAllocEx") < api_order.index("WriteProcessMemory")
                break
        else:
            pytest.fail("classic_injection pattern not found")


# ---------------------------------------------------------------------------
# API Definitions DB tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not API_DB_PATH.exists(), reason="API definitions DB not built")
class TestApiDefinitionsDB:
    """Tests for the API knowledge base queries."""

    def test_lookup_exact(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import lookup_api
        result = lookup_api(API_DB_PATH, "CreateFileW")
        assert result["count"] >= 1
        api = result["results"][0]
        assert api["name"] == "CreateFileW"
        assert "kernel32" in api["module"].lower()
        assert len(api["parameters"]) > 0

    def test_lookup_wildcard(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import lookup_api
        result = lookup_api(API_DB_PATH, "VirtualAlloc*")
        assert result["count"] >= 2
        names = [r["name"] for r in result["results"]]
        assert any("VirtualAlloc" in n for n in names)

    def test_lookup_case_insensitive(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import lookup_api
        r1 = lookup_api(API_DB_PATH, "createfilew")
        r2 = lookup_api(API_DB_PATH, "CREATEFILEW")
        assert r1["count"] == r2["count"]

    def test_lookup_not_found(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import lookup_api
        result = lookup_api(API_DB_PATH, "ThisApiDoesNotExist12345")
        assert result["count"] == 0

    def test_search_category(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import search_api_by_category
        result = search_api_by_category(API_DB_PATH, "File Management")
        assert result["count"] > 0

    def test_get_stats(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import get_api_stats
        result = get_api_stats(API_DB_PATH)
        assert result["total_apis"] > 20000
        assert result["total_types"] > 5000
        assert result["module_count"] > 500

    def test_get_module_apis(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import get_module_apis
        result = get_module_apis(API_DB_PATH, "Kernel32.dll", limit=500)
        assert result["count"] > 100
        names = [r["name"] for r in result["results"]]
        assert "CreateFileW" in names

    def test_db_not_found(self):
        from winforensics_mcp.parsers.api_monitor.definitions_db import lookup_api
        with pytest.raises(FileNotFoundError):
            lookup_api("/nonexistent/db.sqlite", "CreateFileW")


# ---------------------------------------------------------------------------
# Parameter value extraction tests
# ---------------------------------------------------------------------------

def _build_call_record(
    record_index: int = 0,
    parent_index: int = 0xFFFFFFFF,
    api_name: str = "TestApi",
    pre_params: list[tuple[int, list[int]]] | None = None,
    post_params: list[tuple[int, list[int]]] | None = None,
    timestamp: int = 133892988507053179,  # 2025-04-16T17:40:50 UTC
) -> bytes:
    """Build a synthetic call record with proper header and param data.

    Args:
        pre_params: List of (b1_byte, values_list) per parameter.
            b1_byte encodes slot_count in upper nibble: (slot_count << 4) | lower_nibble.
            values_list contains the uint64 values for that parameter.
        post_params: Same format for post-call values (None = no post-call data).
    """
    if pre_params is None:
        pre_params = [(0x10, [42])]  # single param, 1 slot, value=42

    # Build param data block.
    # APMX format quirk: the last descriptor byte is shared with the first
    # data byte (they overlap at offset size_field). We handle this by
    # making the descriptor's last byte equal the low byte of the first value.
    def _build_param_block(params):
        count = len(params)
        size_field = count * 4 + 1
        block = bytearray()
        block.append(count)
        block.append(size_field)
        # Descriptor entries: [0x00, b1, 0x00, b3] per param
        for i, (b1, _vals) in enumerate(params):
            block.extend(b"\x00")
            block.append(b1)
            block.extend(b"\x00")
            # Last byte of last entry must be low byte of first data value
            if i == count - 1:
                first_val = params[0][1][0] if params[0][1] else 0
                block.append(first_val & 0xFF)
            else:
                block.append(0x01)
        # Value data (skip first byte since it's shared with descriptor)
        first = True
        for _b1, vals in params:
            for v in vals:
                packed = struct.pack("<Q", v)
                if first:
                    block.extend(packed[1:])  # skip first byte (shared)
                    first = False
                else:
                    block.extend(packed)
        return bytes(block)

    pre_block = _build_param_block(pre_params)
    pre_size = len(pre_block)

    has_post = post_params is not None
    if has_post:
        post_block = _build_param_block(post_params)
        post_size = len(post_block)
    else:
        post_block = b""
        post_size = 0

    # API name block (goes in section4 area)
    name_bytes = api_name.encode("ascii") + b"\x00"
    name_block = b"\x01\x00" + bytes([len(name_bytes)]) + b"\x00" + name_bytes

    # Section 3: 8 bytes of zeros (error code)
    section3 = b"\x00" * 8
    section3_size = 8

    # Section 4: caller addresses + name
    section4 = b"\x00" * 16 + name_block + b"\x00" * 4
    section4_size = len(section4)

    # Calculate absolute offsets within record (base pointer is record start)
    # We'll use relative layout, pointers will be absolute in data blob
    header_size = 0x90
    pre_offset = header_size
    post_offset = pre_offset + pre_size if has_post else 0
    sec3_offset = pre_offset + pre_size + (post_size if has_post else 0)
    sec4_offset = sec3_offset + section3_size

    # Build 144-byte header
    header = bytearray(header_size)
    # Magic
    header[0] = 0x01
    header[1] = 0x01
    header[2] = 0x00
    header[3] = 0x02
    # Record index
    struct.pack_into("<I", header, 0x08, record_index)
    # Parent index
    struct.pack_into("<I", header, 0x0C, parent_index)
    # Pre params size
    struct.pack_into("<I", header, 0x20, pre_size)
    # Timestamp
    struct.pack_into("<Q", header, 0x48, timestamp)
    # Post params size
    struct.pack_into("<I", header, 0x58, post_size)
    # Section 3 size
    struct.pack_into("<I", header, 0x5C, section3_size)
    # Section 4 size
    struct.pack_into("<I", header, 0x6C, section4_size)
    # Pointers (absolute offsets; will be adjusted during APMX assembly)
    # Set to placeholder - will be filled by _build_detailed_apmx
    struct.pack_into("<Q", header, 0x70, pre_offset)  # pre_params_ptr
    struct.pack_into("<Q", header, 0x78, post_offset if has_post else 0)  # post_params_ptr
    struct.pack_into("<Q", header, 0x80, sec3_offset)  # section3_ptr
    struct.pack_into("<Q", header, 0x88, sec4_offset)  # section4_ptr

    record = bytes(header) + pre_block + post_block + section3 + section4
    return record


def _build_detailed_apmx(
    records: list[bytes],
    process_name: str = "test.exe",
) -> bytes:
    """Build a synthetic APMX file with detailed call records.

    Args:
        records: List of binary records (from _build_call_record)
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # info entry
        version = "API Monitor v2 Test 64-bit"
        version_encoded = version.encode("utf-16-le")
        info_data = struct.pack("<I", 0) + struct.pack("<I", len(version)) + version_encoded
        zf.writestr("info", info_data)

        # process/0/info
        path = f"C:\\test\\{process_name}"
        path_encoded = path.encode("utf-16-le")
        cmdline = f'"{path}"'
        cmdline_encoded = cmdline.encode("utf-16-le")
        pinfo = (
            struct.pack("<I", 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 1234)
            + struct.pack("<Q", 0x7FF700000000)
            + struct.pack("<I", len(path)) + path_encoded
            + struct.pack("<I", len(cmdline)) + cmdline_encoded
        )
        zf.writestr("process/0/info", pinfo)

        # Build data blob and offset table
        data_blob = bytearray()
        offsets = []
        for rec in records:
            base_offset = len(data_blob)
            offsets.append(base_offset)

            # Adjust pointers in header to be absolute offsets in data blob
            rec_arr = bytearray(rec)
            for ptr_off in (0x70, 0x78, 0x80, 0x88):
                relative = struct.unpack_from("<Q", rec_arr, ptr_off)[0]
                if relative != 0:
                    struct.pack_into("<Q", rec_arr, ptr_off, base_offset + relative)
            data_blob.extend(rec_arr)

        calls_data = struct.pack(f"<{len(offsets)}Q", *offsets)
        zf.writestr("process/0/calls", calls_data)
        zf.writestr("process/0/data", bytes(data_blob))

        log_text = f"{process_name}: Monitoring Module 0x7FF800000000 -> C:\\WINDOWS\\System32\\ntdll.dll.\r\n"
        zf.writestr("log/monitoring.txt", log_text.encode("utf-16-le"))

    zip_bytes = buf.getvalue()
    header = b"\r\n\r\n\r\n\tAPI Monitor Test Capture\r\n\t(c) Test\r\n"
    header = header.ljust(0xD5, b"\r")
    header += b"RBAPMPK"
    return header + zip_bytes


class TestFiletimeConversion:
    """Test FILETIME to ISO conversion."""

    def test_known_timestamp(self):
        # 2025-04-16T17:40:50.705317 UTC
        ts = _filetime_to_iso(133892988507053179)
        assert ts is not None
        assert "2025-04-16" in ts
        assert "17:40:50" in ts

    def test_zero_timestamp(self):
        assert _filetime_to_iso(0) is None


class TestParseParamValues:
    """Test parameter value extraction from binary data."""

    def _build_overlapping_block(self, count, descriptors, all_values):
        """Build a param block matching the real APMX overlap format.

        In the APMX format, the last descriptor byte is shared with the
        first data byte (they overlap at offset size_field).

        Args:
            count: number of parameters
            descriptors: list of (b1,) per param - the descriptor byte encoding slot_count
            all_values: flat list of all uint64 values across all params
        """
        size_field = count * 4 + 1
        block = bytearray()
        block.append(count)
        block.append(size_field)
        first_val_low = (all_values[0] & 0xFF) if all_values else 0
        for i, (b1,) in enumerate(descriptors):
            block.extend(b"\x00")
            block.append(b1)
            block.extend(b"\x00")
            if i == count - 1:
                block.append(first_val_low)  # shared with first data byte
            else:
                block.append(0x01)
        # Write values, skipping first byte of first value (already in descriptor)
        for j, v in enumerate(all_values):
            packed = struct.pack("<Q", v)
            if j == 0:
                block.extend(packed[1:])  # skip first byte (shared)
            else:
                block.extend(packed)
        return bytes(block)

    def test_single_slot_param(self):
        """Single-slot param: value is the uint64 directly."""
        block = self._build_overlapping_block(1, [(0x10,)], [0x43A])
        params = _parse_param_values(block, count=1, size_field=5)
        assert len(params) == 1
        assert params[0]["value"] == 0x43A
        assert params[0]["slot_count"] == 1

    def test_three_slot_output_param(self):
        """3-slot output param: [flag=1, address, value]."""
        block = self._build_overlapping_block(1, [(0x30,)], [1, 0xCEE76FED68, 0x268])
        params = _parse_param_values(block, count=1, size_field=5)
        assert len(params) == 1
        assert params[0]["value"] == 0x268
        assert params[0]["slot_count"] == 3
        assert params[0]["address"] == 0xCEE76FED68

    def test_multi_slot_value_param(self):
        """5+ slot param: first slot is the value."""
        block = self._build_overlapping_block(1, [(0x60,)], [42, 0xABCD, 0, 0, 0, 0])
        params = _parse_param_values(block, count=1, size_field=5)
        assert len(params) == 1
        assert params[0]["value"] == 42
        assert params[0]["slot_count"] == 6

    def test_multiple_params(self):
        """Multiple params with different slot counts."""
        # OpenProcess-like: return(3 slots) + dwDesiredAccess(1 slot)
        block = self._build_overlapping_block(
            2,
            [(0x30,), (0x10,)],
            [1, 0xCEE76FED68, 0, 0x43A],  # param0: flag, addr, value=0; param1: 0x43A
        )
        params = _parse_param_values(block, count=2, size_field=9)
        assert len(params) == 2
        assert params[0]["value"] == 0           # return pre-call
        assert params[0]["slot_count"] == 3
        assert params[1]["value"] == 0x43A       # dwDesiredAccess
        assert params[1]["slot_count"] == 1


class TestParseCallRecord:
    """Test full call record parsing."""

    def test_basic_record(self):
        rec = _build_call_record(
            record_index=100,
            api_name="TestApi",
            pre_params=[(0x10, [42])],
        )
        result = _parse_call_record(rec, 100)
        assert result["call_index"] == 100
        assert result["record_index"] == 100
        assert result["api_name"] == "TestApi"
        assert result["parent_index"] is None
        assert result["param_count"] == 1
        assert len(result["parameters"]) == 1
        assert result["parameters"][0]["pre_value"] == 42

    def test_return_value_detection(self):
        """Return value detected from pre/post comparison."""
        rec = _build_call_record(
            api_name="OpenProcess",
            pre_params=[
                (0x30, [1, 0xCEE76FED68, 0]),      # return: 3 slots, pre=0
                (0x10, [0x43A]),                     # dwDesiredAccess
            ],
            post_params=[
                (0x30, [1, 0xCEE76FED68, 0x268]),   # return: post=0x268
                (0x10, [0x43A]),                     # same
            ],
        )
        result = _parse_call_record(rec, 0)
        assert result["api_name"] == "OpenProcess"
        assert result["return_value"] == 0x268
        assert result["return_hex"] == "0x268"
        # First param should be marked as changed
        p0 = result["parameters"][0]
        assert p0["changed"] is True
        assert p0["is_return"] is True
        assert p0["post_value"] == 0x268

    def test_timestamp_extraction(self):
        rec = _build_call_record(
            api_name="TestApi",
            timestamp=133892988507053179,
        )
        result = _parse_call_record(rec, 0)
        assert "timestamp" in result
        assert "2025-04-16" in result["timestamp"]

    def test_parent_record(self):
        rec = _build_call_record(parent_index=42, api_name="ChildApi")
        result = _parse_call_record(rec, 1)
        assert result["parent_index"] == 42


class TestGetApmxCallDetails:
    """Test the get_apmx_call_details public API."""

    def test_call_details_by_index(self, tmp_path):
        records = [
            _build_call_record(record_index=0, api_name="OpenProcess",
                               pre_params=[(0x10, [0x268])]),
            _build_call_record(record_index=1, api_name="VirtualAllocEx",
                               pre_params=[(0x10, [0x268]), (0x10, [0x1000])]),
        ]
        apmx = _build_detailed_apmx(records)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_call_details(str(f), call_indices=[0, 1])
        assert result["returned"] == 2
        assert result["calls"][0]["api_name"] == "OpenProcess"
        assert result["calls"][1]["api_name"] == "VirtualAllocEx"

    def test_call_details_with_filter(self, tmp_path):
        records = [
            _build_call_record(record_index=0, api_name="OpenProcess"),
            _build_call_record(record_index=1, api_name="CloseHandle"),
            _build_call_record(record_index=2, api_name="OpenThread"),
        ]
        apmx = _build_detailed_apmx(records)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = get_apmx_call_details(str(f), api_filter="Open")
        assert result["returned"] == 2
        apis = [c["api_name"] for c in result["calls"]]
        assert "OpenProcess" in apis
        assert "OpenThread" in apis
        assert "CloseHandle" not in apis

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            get_apmx_call_details("/nonexistent/file.apmx64")


class TestCorrelateHandles:
    """Test handle correlation across API calls."""

    def test_injection_chain(self, tmp_path):
        """Detect OpenProcess → VirtualAllocEx → WriteProcessMemory chain."""
        records = [
            # OpenProcess returns handle 0x268
            _build_call_record(
                record_index=0, api_name="OpenProcess",
                pre_params=[(0x30, [1, 0xCEE76FED68, 0])],
                post_params=[(0x30, [1, 0xCEE76FED68, 0x268])],
            ),
            # VirtualAllocEx uses handle 0x268
            _build_call_record(
                record_index=1, api_name="VirtualAllocEx",
                pre_params=[
                    (0x10, [0x268]),    # hProcess
                    (0x30, [1, 0xCEE76FED08, 0]),  # return
                ],
                post_params=[
                    (0x10, [0x268]),
                    (0x30, [1, 0xCEE76FED08, 0x206583D0000]),
                ],
            ),
            # WriteProcessMemory uses handle 0x268
            _build_call_record(
                record_index=2, api_name="WriteProcessMemory",
                pre_params=[
                    (0x10, [0x268]),         # hProcess
                    (0x10, [0x206583D0000]), # lpBaseAddress
                ],
            ),
            # CloseHandle uses handle 0x268
            _build_call_record(
                record_index=3, api_name="CloseHandle",
                pre_params=[(0x10, [0x268])],
            ),
        ]
        apmx = _build_detailed_apmx(records)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = correlate_apmx_handles(str(f))
        assert result["chain_count"] >= 1

        # Find the 0x268 chain
        chain = None
        for c in result["handle_chains"]:
            if c["handle"] == 0x268:
                chain = c
                break
        assert chain is not None, "Handle 0x268 chain not found"
        assert chain["producer_api"] == "OpenProcess"
        consumer_apis = [c["api"] for c in chain["consumers"]]
        assert "VirtualAllocEx" in consumer_apis
        assert "WriteProcessMemory" in consumer_apis
        assert "CloseHandle" in consumer_apis

    def test_no_chains_for_benign(self, tmp_path):
        """No handle chains for non-handle APIs."""
        records = [
            _build_call_record(record_index=0, api_name="Sleep",
                               pre_params=[(0x10, [1000])]),
            _build_call_record(record_index=1, api_name="GetTickCount",
                               pre_params=[(0x10, [0])]),
        ]
        apmx = _build_detailed_apmx(records)
        f = tmp_path / "test.apmx64"
        f.write_bytes(apmx)

        result = correlate_apmx_handles(str(f))
        assert result["chain_count"] == 0


# ---------------------------------------------------------------------------
# Tests against real Ghost-Thread capture (skipped if file not present)
# ---------------------------------------------------------------------------

GHOST_THREAD_FILE = Path("tests/data/Ghost-Thread.apmx64")


@pytest.mark.skipif(not GHOST_THREAD_FILE.exists(), reason="Ghost-Thread.apmx64 not found")
class TestGhostThreadCallDetails:
    """Test parameter extraction against real Ghost-Thread capture."""

    def test_openprocess_return_value(self):
        result = get_apmx_call_details(str(GHOST_THREAD_FILE), call_indices=[25664])
        call = result["calls"][0]
        assert call["api_name"] == "OpenProcess"
        assert call["return_value"] == 0x268
        # Check dwDesiredAccess param
        p1 = call["parameters"][1]
        assert p1["pre_value"] == 0x43A

    def test_virtualallocex_params(self):
        result = get_apmx_call_details(str(GHOST_THREAD_FILE), call_indices=[29109])
        call = result["calls"][0]
        assert call["api_name"] == "VirtualAllocEx"
        assert call["return_value"] == 0x206583D0000
        # hProcess should be 0x268
        p0 = call["parameters"][0]
        assert p0["pre_value"] == 0x268
        # flProtect should be PAGE_EXECUTE_READ
        p5 = call["parameters"][5]
        assert p5["pre_value"] == 0x20

    def test_injection_handle_chain(self):
        result = correlate_apmx_handles(str(GHOST_THREAD_FILE))
        # Find the 0x268 chain
        chain = None
        for c in result["handle_chains"]:
            if c["handle"] == 0x268:
                chain = c
                break
        assert chain is not None
        assert chain["producer_api"] == "OpenProcess"
        consumer_apis = [c["api"] for c in chain["consumers"]]
        assert "VirtualAllocEx" in consumer_apis
        assert "WriteProcessMemory" in consumer_apis

    def test_timestamps_present(self):
        result = get_apmx_call_details(str(GHOST_THREAD_FILE), call_indices=[25664])
        call = result["calls"][0]
        assert "timestamp" in call
        assert "2025-04-16" in call["timestamp"]


# ---------------------------------------------------------------------------
# Tests against Attacker capture (definitions-only name resolution)
# ---------------------------------------------------------------------------

ATTACKER_FILE = Path("tests/data/Attacker.apmx64")


@pytest.mark.skipif(not ATTACKER_FILE.exists(), reason="Attacker.apmx64 not found")
class TestAttackerCapture:
    """Test definitions-based name resolution for captures without embedded names."""

    def test_all_records_resolved(self):
        """All records should have API names via definitions blob."""
        result = get_apmx_calls(str(ATTACKER_FILE), process_index=0, limit=100)
        assert result["returned"] == 100
        for call in result["calls"]:
            assert call["top_api"], f"Record {call['call_index']} has no API name"

    def test_api_stats_complete(self):
        stats = get_apmx_api_stats(str(ATTACKER_FILE), process_index=0)
        assert stats["total_records"] == 6367
        assert stats["unique_top_level_apis"] >= 5

    def test_known_apis_present(self):
        """Attacker file should contain file I/O APIs."""
        stats = get_apmx_api_stats(str(ATTACKER_FILE), process_index=0)
        api_names = {s["api"] for s in stats["top_apis_by_frequency"]}
        assert "ReadFile" in api_names
        assert "WriteFile" in api_names

    def test_call_details_with_defs_name(self):
        result = get_apmx_call_details(str(ATTACKER_FILE), process_index=0, limit=3)
        assert result["returned"] == 3
        call = result["calls"][0]
        assert call["api_name"] == "GetCurrentDirectoryW"
        assert call["param_count"] >= 1

    def test_multi_process(self):
        """Both processes should be parseable."""
        result0 = get_apmx_calls(str(ATTACKER_FILE), process_index=0, limit=1)
        result1 = get_apmx_calls(str(ATTACKER_FILE), process_index=1, limit=1)
        assert result0["returned"] >= 1
        assert result1["returned"] >= 1


# ---------------------------------------------------------------------------
# Tests against Insider capture (mixed embedded + definitions names)
# ---------------------------------------------------------------------------

INSIDER_FILE = Path("tests/data/Insider.apmx64")


@pytest.mark.skipif(not INSIDER_FILE.exists(), reason="Insider.apmx64 not found")
class TestInsiderCapture:
    """Test mixed name resolution and pattern detection on Insider capture."""

    def test_multi_process_metadata(self):
        from winforensics_mcp.parsers.api_monitor.apmx_parser import parse_apmx
        meta = parse_apmx(str(INSIDER_FILE))
        assert meta["process_count"] == 2
        names = [p["process_name"] for p in meta["processes"]]
        assert "wsl.exe" in names
        assert "powershell.exe" in names

    def test_powershell_api_stats(self):
        stats = get_apmx_api_stats(str(INSIDER_FILE), process_index=1)
        assert stats["total_records"] == 22989
        # With definitions resolution, should have many more unique APIs
        assert stats["unique_top_level_apis"] > 100

    def test_pattern_detection_finds_threats(self):
        patterns = detect_apmx_patterns(str(INSIDER_FILE), process_index=1)
        assert patterns["patterns_detected"] >= 3
        assert patterns["risk_level"] in ("high", "critical")
        pattern_names = {p["pattern_name"] for p in patterns["details"]}
        # Should detect injection and persistence patterns
        assert any("Injection" in n or "Persistence" in n or "Token" in n for n in pattern_names)

    def test_call_filter_accuracy(self):
        """Filter by RegCreateKey should return registry operations."""
        result = get_apmx_calls(str(INSIDER_FILE), process_index=1, api_filter="RegCreateKey", limit=10)
        assert result["returned"] >= 1
        for call in result["calls"]:
            all_names = " ".join(call["all_apis"])
            assert "RegCreateKey" in all_names
