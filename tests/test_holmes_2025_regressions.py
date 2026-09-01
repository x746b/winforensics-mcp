import asyncio
import json
import os
import struct
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from winforensics_mcp import server as server_module
from winforensics_mcp.parsers import lnk_parser, registry_parser
from winforensics_mcp.parsers.api_monitor.patterns import detect_api_patterns


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(value):
    delta = value - FILETIME_EPOCH
    seconds = (delta.days * 86400) + delta.seconds
    return (seconds * 10_000_000) + (delta.microseconds * 10)


def write_lnk_header(path, creation, access, modification):
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    struct.pack_into(
        "<QQQ",
        header,
        0x1C,
        to_filetime(creation),
        to_filetime(access),
        to_filetime(modification),
    )
    path.write_bytes(header)


def dummy_lnk():
    return SimpleNamespace(
        path=r"C:\Evidence\dump.bin",
        link_info=None,
        file_flags=None,
        working_dir=r"C:\Evidence",
        arguments=None,
        description="dump",
        creation_time=datetime(2025, 8, 20, 12, 8, 6),
        access_time=datetime(2025, 8, 20, 12, 8, 7),
        modification_time=datetime(2025, 8, 20, 12, 8, 8),
        file_size=123,
        relative_path=None,
        icon=None,
    )


@pytest.mark.parametrize("host_timezone", ["UTC", "Europe/Prague"])
def test_lnk_header_filetimes_are_host_timezone_independent(tmp_path, host_timezone):
    creation = datetime(2025, 8, 20, 10, 8, 6, tzinfo=timezone.utc)
    access = datetime(2025, 8, 20, 10, 8, 7, tzinfo=timezone.utc)
    modification = datetime(2025, 8, 20, 10, 8, 8, tzinfo=timezone.utc)
    lnk_path = tmp_path / "dump.lnk"
    write_lnk_header(lnk_path, creation, access, modification)

    old_timezone = os.environ.get("TZ")
    os.environ["TZ"] = host_timezone
    if hasattr(time, "tzset"):
        time.tzset()
    try:
        with patch.object(lnk_parser.pylnk3, "parse", return_value=dummy_lnk()):
            result = lnk_parser.parse_lnk_file(lnk_path)
    finally:
        if old_timezone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_timezone
        if hasattr(time, "tzset"):
            time.tzset()

    assert result["timestamp_source"] == "LNK header FILETIME"
    assert result["timestamps"]["creation_time"] == "2025-08-20T10:08:06+00:00"
    assert result["target_timestamps"] == {
        "creation_time_utc": "2025-08-20T10:08:06+00:00",
        "access_time_utc": "2025-08-20T10:08:07+00:00",
        "modification_time_utc": "2025-08-20T10:08:08+00:00",
    }


class FakeValue:
    def __init__(self, name, value):
        self._name = name
        self._value = value

    def name(self):
        return self._name

    def value(self):
        return self._value

    def value_type(self):
        return 1


class FakeKey:
    def __init__(self, values):
        self._values = values

    def values(self):
        return self._values

    def timestamp(self):
        return datetime(2025, 8, 20, 10, 13, 57, tzinfo=timezone.utc)


class FakeHive:
    def __init__(self, values):
        self._key = FakeKey(values)

    def open(self, key_path):
        assert key_path == r"Microsoft\Windows NT\CurrentVersion\Winlogon"
        return self._key


def test_winlogon_persistence_surfaces_userinit_deviation():
    values = [
        FakeValue("Userinit", "Userinit.exe, JM.exe"),
        FakeValue("Shell", "explorer.exe"),
    ]
    with patch.object(registry_parser, "open_registry_hive", return_value=FakeHive(values)):
        result = registry_parser.get_winlogon_persistence("SOFTWARE")

    assert result["present"] is True
    assert result["last_write_time"] == "2025-08-20T10:13:57+00:00"
    assert result["values"]["Userinit"] == "Userinit.exe, JM.exe"
    assert result["suspicious"] is True
    assert result["deviations"][0]["value_name"] == "Userinit"


def test_default_winlogon_values_are_not_flagged():
    values = [
        FakeValue("Userinit", r"C:\Windows\System32\userinit.exe,"),
        FakeValue("Shell", "explorer.exe"),
    ]
    with patch.object(registry_parser, "open_registry_hive", return_value=FakeHive(values)):
        result = registry_parser.get_winlogon_persistence("SOFTWARE")

    assert result["suspicious"] is False
    assert result["deviations"] == []


def test_registry_persistence_response_keeps_existing_fields_and_adds_winlogon():
    winlogon = {"values": {"Userinit": "Userinit.exe, JM.exe"}, "suspicious": True}
    with (
        patch.object(server_module, "get_run_keys", return_value=[{"name": "Updater"}]),
        patch.object(server_module, "get_winlogon_persistence", return_value=winlogon),
    ):
        result = json.loads(asyncio.run(server_module._execute_tool(
            "registry_get_persistence",
            {"software_hive": "SOFTWARE"},
        )))

    assert result["run_keys"] == [{"name": "Updater"}]
    assert result["services"] == []
    assert result["winlogon"] == winlogon


def test_optional_com_apis_do_not_satisfy_wmi_threshold():
    result = detect_api_patterns({
        "ole32.dll": ["CoCreateInstance", "CoInitialize", "CoUninitialize"],
    })

    ids = {detail["pattern_id"] for detail in result["details"]}
    assert "wmi_execution" not in ids


def test_real_wmi_required_apis_still_match_and_report_optional_evidence():
    result = detect_api_patterns({
        "ole32.dll": ["CoCreateInstance", "CoInitializeEx", "CoUninitialize"],
    })

    wmi = next(detail for detail in result["details"] if detail["pattern_id"] == "wmi_execution")
    assert wmi["required_match_count"] == 2
    assert wmi["required_apis_matched"] == ["CoCreateInstance", "CoInitializeEx"]
    assert wmi["optional_apis_matched"] == ["CoUninitialize"]


def test_anti_debug_detection_is_preserved():
    result = detect_api_patterns({"kernel32.dll": ["IsDebuggerPresent"]})
    ids = {detail["pattern_id"] for detail in result["details"]}
    assert "anti_debug" in ids
