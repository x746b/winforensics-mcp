"""Sanitized registry regressions for querying, FILETIME and USB/WPD correlation."""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from winforensics_mcp import server
from winforensics_mcp.parsers import registry_parser as registry


class FakeValue:
    def __init__(self, name, data, value_type=1):
        self._name, self._data, self._type = name, data, value_type

    def name(self):
        return self._name

    def value(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data

    def value_type(self):
        return self._type


class FakeKey:
    def __init__(self, name, values=(), subkeys=()):
        self._name = name
        self._values = list(values)
        self._subkeys = list(subkeys)
        self._path = name
        self.set_path(name)

    def set_path(self, path):
        self._path = path
        for child in self._subkeys:
            child.set_path(path + "\\" + child.name())

    def name(self):
        return self._name

    def path(self):
        return self._path

    def values(self):
        return self._values

    def subkeys(self):
        return self._subkeys

    def timestamp(self):
        return datetime(2024, 1, 2, tzinfo=timezone.utc)


class FakeHive:
    def __init__(self, root):
        self._root = root

    def root(self):
        return self._root

    def open(self, path):
        key = self._root
        for name in path.split("\\"):
            key = next(
                (child for child in key.subkeys() if child.name().lower() == name.lower()), None,
            )
            if key is None:
                raise registry.Registry.RegistryKeyNotFoundException(path)
        return key


@pytest.fixture
def query_hive():
    root = FakeKey("ROOT", subkeys=[
        FakeKey("Apps", values=[
            FakeValue("Updater", "update.exe"),
            FakeValue("Vendor", "VendorUpdate.exe"),
            FakeValue("UPPER", "UPDATE.EXE"),
            FakeValue("Multi", ["editor.exe", "update.exe"], 7),
            FakeValue("Bytes", b"update.exe\x00", 3),
        ], subkeys=[FakeKey("Child", values=[FakeValue("ChildApp", "update.exe")])]),
        FakeKey("AppsBackup", values=[FakeValue("Backup", "update.exe")]),
    ])
    with patch.object(registry, "open_registry_hive", return_value=FakeHive(root)):
        yield


def test_query_default_retains_legacy_match_rows(query_hive):
    legacy = registry.search_registry_values("hive", "VendorUpdate.exe")
    result = registry.query_registry_values("hive", "VendorUpdate.exe")
    assert result["results"] == legacy
    assert isinstance(legacy, list)
    assert set(legacy[0]) == {"name", "type", "data", "data_raw", "key_path"}


@pytest.mark.parametrize("prefix", ["Apps", "ROOT\\Apps", "root\\apps", "Apps\\"])
def test_exact_query_scope_pagination_and_projection(query_hive, prefix):
    result = registry.query_registry_values(
        "hive", "update.exe", match_mode="exact", search_names=False,
        key_path_prefix=prefix, offset=1, limit=2, fields=["name", "data"],
    )
    assert result["total_matched"] == 5
    assert [item["name"] for item in result["results"]] == ["UPPER", "Multi"]
    assert all(set(item) == {"name", "data"} for item in result["results"])
    assert result["returned"] == 2
    assert result["next_offset"] == 3
    assert result["truncated"] is True
    assert result["total_matched_complete"] is True
    assert result["diagnostics"] == []


def test_case_sensitive_regex_and_name_only(query_hive):
    result = registry.query_registry_values(
        "hive", "^UP", match_mode="regex", case_sensitive=True, search_data=False,
    )
    assert [item["name"] for item in result["results"]] == ["UPPER"]
    exact = registry.query_registry_values(
        "hive", "update.exe", match_mode="exact", case_sensitive=True,
        search_names=False, key_path_prefix="Apps",
    )
    assert exact["total_matched"] == 4


@pytest.mark.parametrize("offset", [7, 50])
def test_offset_past_end_has_no_next_page(query_hive, offset):
    result = registry.query_registry_values("hive", "update.exe", offset=offset)
    assert result["results"] == []
    assert result["returned"] == 0
    assert result["total_matched"] == 7
    assert result["next_offset"] is None
    assert result["truncated"] is False


@pytest.mark.parametrize("kwargs", [
    {"pattern": None}, {"pattern": "[", "match_mode": "regex"},
    {"match_mode": "glob"}, {"offset": -1}, {"offset": True},
    {"limit": 0}, {"limit": 1001}, {"limit": 1.5},
    {"search_names": False, "search_data": False}, {"case_sensitive": "yes"},
    {"key_path_prefix": []}, {"fields": "name"}, {"fields": []}, {"fields": ["unknown"]},
    {"diagnostic_limit": -1}, {"diagnostic_limit": 21}, {"diagnostic_limit": True},
    {"diagnostic_limit": 1.5},
])
def test_invalid_queries_fail_before_opening_hive(kwargs):
    arguments = {"pattern": "test", **kwargs}
    with patch.object(registry, "open_registry_hive") as opener:
        with pytest.raises(ValueError):
            registry.query_registry_values("hive", **arguments)
        opener.assert_not_called()


def test_missing_prefix_is_an_error(query_hive):
    with pytest.raises(KeyError, match="prefix not found"):
        registry.query_registry_values("hive", "test", key_path_prefix="Missing")


def test_corrupt_value_reports_incomplete_totals():
    root = FakeKey("ROOT", values=[
        FakeValue("broken", ValueError("invalid cell")), FakeValue("ok", "needle"),
    ])
    with patch.object(registry, "open_registry_hive", return_value=FakeHive(root)):
        result = registry.query_registry_values("hive", "needle", search_names=False)
    assert result["total_matched"] == 1
    assert result["total_matched_complete"] is False
    assert result["read_errors"] == 1
    assert result["diagnostics"][0]["operation"] == "read_value"
    assert result["diagnostics_truncated"] is False


@pytest.mark.parametrize("limit, expected", [(None, 5), (0, 0), (2, 2), (20, 8)])
def test_query_diagnostics_are_bounded_without_losing_error_totals(limit, expected):
    root = FakeKey("ROOT", values=[
        FakeValue(f"broken-{index}", ValueError("invalid cell")) for index in range(8)
    ])
    options = {"diagnostic_limit": limit} if limit is not None else {}
    with patch.object(registry, "open_registry_hive", return_value=FakeHive(root)):
        result = registry.query_registry_values("hive", "needle", search_names=False, **options)
    assert result["read_errors"] == 8
    assert result["total_matched_complete"] is False
    assert len(result["diagnostics"]) == expected
    assert result["diagnostics_truncated"] is (expected < 8)


def test_server_forwards_diagnostic_limit():
    root = FakeKey("ROOT", values=[FakeValue("broken", ValueError("invalid cell"))])
    with patch.object(registry, "open_registry_hive", return_value=FakeHive(root)):
        result = json.loads(asyncio.run(server._execute_tool("registry_query", {
            "hive_path": "hive", "pattern": "needle", "diagnostic_limit": 0,
        })))
    assert result["read_errors"] == 1
    assert result["diagnostics"] == []
    assert result["diagnostics_truncated"] is True


@pytest.mark.parametrize("name", [
    "LastUsedTimeStart", "LastUsedTimeStop", "LastArrivalDate", "LastRemovalDate",
    "InstallDate", "FirstInstallDate", "DEVPKEY_Device_LastArrivalDate",
])
def test_named_qword_filetime_preserves_100ns_and_raw(name):
    ticks = 133486272001234567
    result = registry.parse_registry_value(FakeValue(name, ticks, 11))
    assert result["data"] == ticks
    assert result["data_utc"] == "2024-01-02T00:00:00.1234567+00:00"
    assert result["type"] == "11"


@pytest.mark.parametrize("ticks", [0, -1, 2**64 - 1])
def test_unset_or_invalid_filetime_stays_raw(ticks):
    result = registry.parse_registry_value(FakeValue("LastUsedTimeStop", ticks, 11))
    assert result["data"] == ticks
    assert result["data_utc"] is None


@pytest.mark.parametrize("name, value_type", [("Counter", 11), ("InstallDate", 4)])
def test_arbitrary_counters_and_dword_install_dates_are_not_normalized(name, value_type):
    result = registry.parse_registry_value(FakeValue(name, 133486272001234567, value_type))
    assert "data_utc" not in result


def usb_hive(
    include_wpd=True, serial="TEST123&0", container="{11111111-2222-3333-4444-555555555555}",
):
    device_class = "Disk&Ven_Example&Prod_Flash&Rev_1.00"
    usb = FakeKey("USBSTOR", subkeys=[FakeKey(device_class, subkeys=[
        FakeKey(serial, values=[
            FakeValue("FriendlyName", "Example Flash USB Device"),
            FakeValue("Mfg", "@usbstor.inf,%manufacturer%;Example"),
            FakeValue("DeviceDesc", "@usbstor.inf,%disk%;USB Mass Storage Device"),
            FakeValue("ContainerID", container),
        ]),
    ])])
    enum_children = [usb]
    if include_wpd:
        wpd = FakeKey("WPDBUSENUM", subkeys=[
            FakeKey("{PARTITION}#0000001000", values=[
                FakeValue("FriendlyName", "EFI-PARTITION"), FakeValue("ContainerID", container),
            ]),
            FakeKey(f"_??_USBSTOR#{device_class}#{serial}#{{INTERFACE}}", values=[
                FakeValue("FriendlyName", "CASE-USB-0042"),
                FakeValue("Mfg", "Example"), FakeValue("DeviceDesc", "Flash Drive"),
                FakeValue("ContainerID", container.upper()),
            ]),
            FakeKey(f"_??_USBSTOR#{device_class}#{serial}EXTRA#{{INTERFACE}}", values=[
                FakeValue("FriendlyName", "Unrelated Device"),
                FakeValue("ContainerID", "{99999999-2222-3333-4444-555555555555}"),
            ]),
        ])
        enum_children.append(FakeKey("SWD", subkeys=[wpd]))
    return FakeHive(FakeKey("ROOT", subkeys=[
        FakeKey("Select", values=[FakeValue("Current", 2, 4)]),
        FakeKey("ControlSet002", subkeys=[FakeKey("Enum", subkeys=enum_children)]),
    ]))


def test_usb_physical_wpd_preferred_secondary_preserved():
    with patch.object(registry, "open_registry_hive", return_value=usb_hive()):
        result = registry.get_usb_devices("SYSTEM")[0]
    assert result["serial"] == result["instance_id"] == "TEST123&0"
    assert result["physical_serial"] == "TEST123"
    assert result["friendly_name"] == "Example Flash USB Device"
    assert result["device_name"] == "CASE-USB-0042"
    assert result["wpd_friendly_names"] == ["CASE-USB-0042", "EFI-PARTITION"]
    assert result["wpd_devices"][0]["match_sources"] == ["instance_path", "container_id"]
    assert result["wpd_devices"][1]["match_sources"] == ["container_id"]
    assert result["manufacturer"] == "Example"
    assert result["device_desc"] == "Flash Drive"
    assert result["usb_stor_manufacturer"] == "@usbstor.inf,%manufacturer%;Example"
    assert result["usb_stor_device_desc"] == "@usbstor.inf,%disk%;USB Mass Storage Device"
    assert result["first_connected_source"] == "usb_stor_key_last_write"
    assert result["first_connected"] == "2024-01-02T00:00:00+00:00"
    assert result["device_instance_path"].endswith("\\TEST123&0")


@pytest.mark.parametrize("serial, physical", [
    ("TEST&ABC", "TEST&ABC"), ("TEST&1&23", "TEST&1"), ("TEST", "TEST"),
])
def test_usb_without_wpd_keeps_legacy_data_and_only_strips_terminal_digits(serial, physical):
    with patch.object(registry, "open_registry_hive", return_value=usb_hive(False, serial)):
        result = registry.get_usb_devices("SYSTEM")[0]
    assert result["physical_serial"] == physical
    assert result["serial"] == serial
    assert result["device_name"] == result["friendly_name"]
    assert result["wpd_devices"] == []
    assert result["manufacturer"] == result["usb_stor_manufacturer"]
    assert result["device_desc"] == result["usb_stor_device_desc"]


def test_null_container_does_not_correlate_unrelated_partitions():
    hive = usb_hive(container="{00000000-0000-0000-0000-000000000000}")
    with patch.object(registry, "open_registry_hive", return_value=hive):
        result = registry.get_usb_devices("SYSTEM")[0]
    assert result["wpd_friendly_names"] == ["CASE-USB-0042"]
    assert result["wpd_devices"][0]["match_sources"] == ["instance_path"]


def test_server_schema_and_dispatch_are_additive(query_hive):
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert "registry_search" in tools
    schema = tools["registry_query"].inputSchema
    assert schema["properties"]["match_mode"]["enum"] == ["substring", "exact", "regex"]
    assert schema["properties"]["limit"]["maximum"] == 1000
    assert schema["properties"]["diagnostic_limit"]["default"] == 5
    assert schema["properties"]["diagnostic_limit"]["minimum"] == 0
    assert schema["properties"]["diagnostic_limit"]["maximum"] == 20
    result = json.loads(asyncio.run(server._execute_tool("registry_query", {
        "hive_path": "hive", "pattern": "UPPER", "match_mode": "exact",
        "case_sensitive": True, "search_data": False, "key_path_prefix": "Apps",
        "offset": 0, "limit": 1, "fields": ["name"],
    })))
    assert result["results"] == [{"name": "UPPER"}]
    legacy = json.loads(asyncio.run(server._execute_tool("registry_search", {
        "hive_path": "hive", "pattern": "VendorUpdate.exe",
    })))
    assert isinstance(legacy, list)


def test_server_query_truncation_keeps_offsets_honest():
    page = {
        "results": [{"name": str(index), "data": "x" * 500} for index in range(8)],
        "total_matched": 20, "returned": 8, "offset": 4, "limit": 8,
        "next_offset": 12, "truncated": True,
    }
    result = json.loads(server.registry_query_response(page, max_chars=1500))
    assert result["returned"] == len(result["results"]) == 2
    assert result["next_offset"] == 6
    assert result["response_size_limited"] is True
    assert len(page["results"]) == 8


def test_oversized_single_row_gives_projection_guidance():
    with pytest.raises(ValueError, match="use fields"):
        server.registry_query_response({"results": [{"data": "x" * 5000}]}, max_chars=100)
