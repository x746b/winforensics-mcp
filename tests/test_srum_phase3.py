"""Sanitized SRUM decoding, filtering, aggregation, and MCP regressions."""

import asyncio
import json
import struct
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from winforensics_mcp import server
from winforensics_mcp.parsers import srum_parser as srum


class FakeRecord:
    def __init__(self, values, strings=None):
        self.values = values
        self.strings = strings or {}

    def get_value_data(self, index):
        value = self.values[index]
        if isinstance(value, Exception):
            raise value
        return value

    def get_value_data_as_string(self, index):
        return self.strings.get(index, self.values[index].decode("utf-16-le"))


class FakeTable:
    def __init__(self, name, columns, records):
        self.name = name
        self.columns = [SimpleNamespace(name=name, type=ctype) for name, ctype in columns]
        self.records = records
        self.number_of_columns = len(columns)
        self.number_of_records = len(records)

    def get_column(self, index):
        return self.columns[index]

    def get_record(self, index):
        record = self.records[index]
        if isinstance(record, Exception):
            raise record
        return record


class FakeDatabase:
    def __init__(self, tables):
        self.tables = tables
        self.number_of_tables = len(tables)
        self.closed = False

    def open(self, path):
        self.path = path

    def close(self):
        self.closed = True

    def get_table(self, index):
        return self.tables[index]


def ole(value):
    if value is None or isinstance(value, bytes):
        return value
    dt = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    epoch = datetime(1899, 12, 30, tzinfo=timezone.utc)
    return struct.pack("<d", (dt - epoch).total_seconds() / 86400)


def integer(value, fmt="q"):
    return struct.pack("<" + fmt, value) if value is not None else None


def network_record(timestamp="2024-01-02T12:00:00", app=1, sent=172064531,
                   received=1048576, user=10, interface=20):
    return FakeRecord([
        ole(timestamp), integer(app, "i"), integer(user, "i"),
        integer(sent), integer(received), integer(interface),
    ])


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "SRUDB.dat"
    path.touch()
    instances = []

    def install(network_rows=None, app_rows=None, names=None):
        names = names if names is not None else {
            1: r"C:\Apps\update.exe", 2: r"C:\Apps\MicrosoftEdgeUpdate.exe",
            3: "!!UPDATE.EXE!stamp!hash![Updater]", 4: r"D:\Tools\update.exe",
        }
        id_map = FakeTable("SruDbIdMapTable", [("IdType", 2), ("IdIndex", 4), ("IdBlob", 11)], [
            FakeRecord([b"\x00", integer(index, "i"), name.encode("utf-16-le")])
            for index, name in names.items()
        ])
        network = FakeTable(srum.SRUM_TABLES["network_data_usage"], [
            ("TimeStamp", 8), ("AppId", 4), ("UserId", 4),
            ("BytesSent", 15), ("BytesRecvd", 15), ("InterfaceLuid", 15),
        ], network_rows if network_rows is not None else [network_record()])
        app = FakeTable(srum.SRUM_TABLES["app_resource_usage"], [
            ("TimeStamp", 8), ("AppId", 4), ("UserId", 4),
            ("ForegroundCycleTime", 15), ("BackgroundCycleTime", 15), ("FaceTime", 4),
        ], app_rows if app_rows is not None else [FakeRecord([
            ole("2024-01-02T12:00:00"), integer(1, "i"), integer(10, "i"),
            integer(2**60 + 3), integer(555), integer(27, "i"),
        ])])

        def factory():
            db = FakeDatabase([id_map, app, network])
            instances.append(db)
            return db

        monkeypatch.setattr(srum, "PYESEDB_AVAILABLE", True)
        monkeypatch.setattr(srum, "pyesedb", SimpleNamespace(file=factory), raising=False)
        return path, app, network

    install.instances = instances
    return install


@pytest.mark.parametrize(("ctype", "fmt", "value"), [
    (1, "B", 0), (1, "B", 255), (2, "B", 255), (3, "h", -32768),
    (4, "i", -2147483648), (5, "q", -(2**63)), (6, "f", 1.25), (7, "d", -9.5),
    (14, "I", 2**32 - 1), (15, "q", 2**60 + 123), (15, "q", -9),
    (17, "H", 65535), (18, "Q", 2**64 - 1),
])
def test_jet_numeric_types(ctype, fmt, value):
    decoded = srum._get_record_value(FakeRecord([struct.pack("<" + fmt, value)]), 0, ctype)
    assert decoded == (bool(value) if ctype == 1 else value)
    assert type(decoded) is (bool if ctype == 1 else float if ctype in (6, 7) else int)


@pytest.mark.parametrize("ctype", [1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18])
def test_malformed_fixed_width_value_rejected(ctype):
    with pytest.raises((ValueError, struct.error)):
        srum._get_record_value(FakeRecord([b"not a fixed width value"]), 0, ctype)
    assert srum._get_record_value(FakeRecord([None]), 0, ctype) is None


@pytest.mark.parametrize("ctype,fmt", [(6, "f"), (7, "d"), (8, "d")])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numeric_values_rejected(ctype, fmt, value):
    with pytest.raises(ValueError):
        srum._get_record_value(FakeRecord([struct.pack("<" + fmt, value)]), 0, ctype)


@pytest.mark.parametrize("ctype", [9, 11, 0, 13, 99])
def test_binary_and_unknown_types_preserve_all_bytes(ctype):
    raw = bytes(range(100))
    assert srum._get_record_value(FakeRecord([raw]), 0, ctype) == raw.hex()


@pytest.mark.parametrize("ctype", [10, 12])
def test_text_uses_library_codepage_decoder_and_preserves_embedded_nuls(ctype):
    class AnsiRecord(FakeRecord):
        def get_value_data_as_string(self, index):
            return self.values[index].decode("cp1252")

    assert srum._get_record_value(AnsiRecord([b"caf\xe9\x00value"]), 0, ctype) == "café\0value"
    assert srum._get_record_value(FakeRecord(["aé\0b".encode("utf-16-le")]), 0, ctype) == "aé\0b"


def test_guid_decodes_windows_byte_order():
    guid = UUID("01234567-89ab-cdef-0123-456789abcdef")
    assert srum._get_record_value(FakeRecord([guid.bytes_le]), 0, 16) == str(guid)


@pytest.mark.parametrize("days,expected", [
    (0, "1899-12-30T00:00:00+00:00"), (-1.5, "1899-12-29T12:00:00+00:00"),
    (45293.5, "2024-01-02T12:00:00+00:00"),
])
def test_ole_date_types(days, expected):
    assert srum._get_record_value(FakeRecord([struct.pack("<d", days)]), 0, 8) == expected


def test_default_shapes_and_raw_counters(database):
    path, _, _ = database()
    app = srum.parse_srum(path)
    assert app["table"] == "Application Resource Usage"
    assert app["entries"][0]["foreground_cycle_time"] == 2**60 + 3
    assert app["entries"][0]["face_time"] == 27
    net = srum.parse_srum_network_usage(path, None, 1)  # Legacy positional signature.
    assert "aggregates" not in net
    assert "aggregation" not in net
    assert net["entries"][0]["bytes_sent"] == 172064531
    assert net["entries"][0]["bytes_sent_decimal_mb"] == 172.064531
    assert net["entries"][0]["bytes_sent_binary_mib"] == 164.093524
    assert net["entries"][0]["bytes_received_decimal_mb"] == 1.048576
    assert net["entries"][0]["bytes_received_binary_mib"] == 1.0
    assert all(db.closed for db in database.instances)


def test_exact_basename_excludes_collision_but_default_keeps_substring(database):
    path, _, _ = database(network_rows=[network_record(app=index) for index in (1, 2, 3, 4)])
    legacy = srum.parse_srum_network_usage(path, "update.exe")
    assert len(legacy["entries"]) == 4
    exact = srum.parse_srum_network_usage(path, "UPDATE.EXE", app_match_mode="exact_basename")
    assert [entry["app_id"] for entry in exact["entries"]] == [1, 3, 4]
    description = srum.parse_srum_network_usage(path, "Updater", app_match_mode="exact_basename")
    assert description["entries"] == []


@pytest.mark.parametrize("pattern,expected", [
    ("c:/apps/UPDATE.exe", [1]), ("update.exe", []), ("apps/update.exe", []),
    ("c:/apps/../apps/update.exe", []), ("d:/tools/update.exe", [4]),
])
def test_exact_path_requires_whole_normalized_path(database, pattern, expected):
    path, _, _ = database(network_rows=[network_record(app=index) for index in (1, 2, 4)])
    result = srum.parse_srum_network_usage(path, pattern, app_match_mode="exact_path")
    assert [entry["app_id"] for entry in result["entries"]] == expected


def test_regex_application_filter(database):
    path, _, _ = database(network_rows=[network_record(app=index) for index in (1, 2, 4)])
    result = srum.parse_srum_network_usage(path, r"(?i)\\update\.exe$", app_match_mode="regex")
    assert [entry["app_id"] for entry in result["entries"]] == [1, 4]


@pytest.mark.parametrize("table", ["app_resource_usage", "network_data_usage", "all"])
@pytest.mark.parametrize("start,end,expected", [
    ("2024-01-02T12:00:00", "2024-01-02T12:00:00", 1),
    ("2024-01-02T13:00:00+01:00", "2024-01-02T07:00:00-05:00", 1),
    ("2024-01-02T12:00:00Z", None, 1),
    (None, "2024-01-02T12:00:00Z", 1),
    ("2024-01-02T12:00:01", None, 0),
    (None, "2024-01-02T11:59:59", 0),
])
def test_inclusive_utc_filters_on_every_table(database, table, start, end, expected):
    path, _, _ = database()
    result = srum.parse_srum(path, table, time_range_start=start, time_range_end=end)
    results = result["tables"].values() if table == "all" else [result]
    assert all(result["returned_entries"] == expected for result in results)


@pytest.mark.parametrize("table", ["app_resource_usage", "network_data_usage", "all"])
@pytest.mark.parametrize("options", [
    {"time_range_start": "not-a-date"}, {"time_range_end": ""},
    {"time_range_start": "2024-01-03", "time_range_end": "2024-01-02"},
    {"time_range_start": "2024-01-02T12:00:00-03:00", "time_range_end": "2024-01-02T12:00:00Z"},
    {"app_filter": "[", "app_match_mode": "regex"}, {"app_match_mode": "unknown"},
    {"aggregate_by": "bad"}, {"limit": -1}, {"limit": True},
])
def test_bad_inputs_rejected_before_database_open(table, options):
    with pytest.raises(ValueError):
        srum.parse_srum("does-not-exist.dat", table=table, **options)


def test_resource_table_rejects_network_aggregation():
    with pytest.raises(ValueError, match="only supported"):
        srum.parse_srum("does-not-exist.dat", aggregate_by="application")


def test_invalid_timestamps_excluded_with_filter_and_reported(database):
    rows = [network_record(timestamp=None), network_record(timestamp=b"bad"), network_record()]
    path, _, _ = database(network_rows=rows)
    result = srum.parse_srum_network_usage(path, time_range_start="2024-01-02")
    assert result["returned_entries"] == 1
    assert result["diagnostics"]["invalid_timestamps"] == 2
    assert result["diagnostics"]["skipped_invalid_timestamps"] == 2
    assert result["diagnostics"]["field_errors"] == 1
    assert srum.parse_srum_network_usage(path)["returned_entries"] == 3


def test_errors_are_bounded_without_losing_counts(database):
    path, _, _ = database(network_rows=[OSError("unreadable record")] * 30 + [network_record()])
    result = srum.parse_srum_network_usage(path)
    assert result["returned_entries"] == 1
    assert result["diagnostics"]["record_errors"] == 30
    assert result["diagnostics"]["skipped_record_errors"] == 30
    assert result["diagnostics"]["error_count"] == 30
    assert len(result["diagnostics"]["errors"]) == 25
    assert result["diagnostics"]["errors_truncated"] is True
    assert result["scan_complete"] is True


def test_missing_or_malformed_counters_stay_null(database):
    row = network_record(sent=None, received=None)
    row.values[4] = b"bad"
    path, _, _ = database(network_rows=[row])
    result = srum.parse_srum_network_usage(path, aggregate_by="application")
    assert result["entries"][0]["bytes_sent"] is None
    assert result["entries"][0]["bytes_sent_decimal_mb"] is None
    aggregate = result["aggregates"][0]
    assert aggregate["bytes_sent"] is None and aggregate["bytes_received"] is None
    assert aggregate["missing_bytes_sent_records"] == 1
    assert aggregate["missing_bytes_received_records"] == 1
    assert result["aggregation"]["complete"] is False


@pytest.mark.parametrize("mode,count", [
    ("application", 2), ("user", 2), ("interface", 2),
    ("application_user", 3), ("application_interface", 3),
])
def test_all_aggregate_modes_preserve_totals_and_entries(database, mode, count):
    path, _, _ = database(network_rows=[
        network_record(sent=1, received=10, user=10, interface=20),
        network_record(sent=2, received=20, user=11, interface=21),
        network_record(app=4, sent=3, received=30, user=10, interface=20),
    ])
    result = srum.parse_srum_network_usage(path, limit=1, aggregate_by=mode)
    assert result["returned_entries"] == 1
    assert len(result["aggregates"]) == count
    assert sum(group["bytes_sent"] for group in result["aggregates"]) == 6
    assert sum(group["bytes_received"] for group in result["aggregates"]) == 60
    assert sum(group["record_count"] for group in result["aggregates"]) == 3
    assert result["aggregation"]["scope"] == "all_matching_records"
    assert result["aggregation"]["record_count"] == 3
    assert result["aggregation"]["scan_complete"] is True
    assert result["entries_truncated"] is True


def test_aggregate_filters_units_and_first_last_timestamps(database):
    path, _, _ = database(network_rows=[
        network_record("2024-01-01T12:00:00", sent=100),
        network_record("2024-01-02T12:00:00", sent=1000000),
        network_record("2024-01-03T12:00:00", sent=2000000),
        network_record("2024-01-02T12:00:00", app=2, sent=999),
    ])
    result = srum.parse_srum_network_usage(
        path, "update.exe", 1, app_match_mode="exact_basename", aggregate_by="application",
        time_range_start="2024-01-02", time_range_end="2024-01-03T12:00:00",
    )
    aggregate = result["aggregates"][0]
    assert aggregate["bytes_sent"] == 3000000
    assert aggregate["bytes_sent_decimal_mb"] == 3
    assert aggregate["bytes_sent_binary_mib"] == 2.861023
    assert aggregate["first_timestamp"] == "2024-01-02T12:00:00+00:00"
    assert aggregate["last_timestamp"] == "2024-01-03T12:00:00+00:00"
    assert aggregate["record_count"] == 2
    assert result["entries"][0]["bytes_sent"] == 1000000


def test_aggregation_normalizes_applications_but_separates_unknown_ids(database):
    path, _, _ = database(
        names={1: r"C:\Apps\update.exe", 2: "c:/apps/UPDATE.EXE"},
        network_rows=[network_record(app=app) for app in (1, 2, 50, 51, None, None)],
    )
    result = srum.parse_srum_network_usage(path, aggregate_by="application")
    assert [group["record_count"] for group in result["aggregates"]] == [2, 1, 1, 2]
    assert [group["app_id"] for group in result["aggregates"]] == [None, 50, 51, None]


def test_missing_group_keys_and_timestamps_are_deterministic(database):
    path, _, _ = database(network_rows=[network_record(timestamp=None, user=None)] * 2)
    result = srum.parse_srum_network_usage(path, aggregate_by="user")
    assert len(result["aggregates"]) == 1
    assert result["aggregates"][0]["user_id"] is None
    assert result["aggregates"][0]["missing_timestamp_records"] == 2
    assert result["aggregates"][0]["first_timestamp"] is None
    assert result["aggregation"]["complete"] is False


def test_aggregation_sums_raw_large_integers_before_rounding(database):
    path, _, _ = database(network_rows=[network_record(sent=2**60 + 1)] * 2)
    result = srum.parse_srum_network_usage(path, aggregate_by="application")
    assert result["aggregates"][0]["bytes_sent"] == 2**61 + 2


def test_all_propagates_matching_aggregation_and_legacy_limit(database):
    path, _, _ = database(network_rows=[network_record(), network_record(app=2)])
    result = srum.parse_srum(path, "all", "update.exe", limit=2,
                             app_match_mode="exact_basename", aggregate_by="user")
    app = result["tables"]["app_resource_usage"]
    net = result["tables"]["network_data_usage"]
    assert app["returned_entries"] == net["returned_entries"] == 1
    assert "aggregates" not in app
    assert net["aggregates"][0]["record_count"] == 1
    assert net["scanned_records"] == 2


def test_zero_limit_with_and_without_aggregation(database):
    path, _, _ = database()
    plain = srum.parse_srum_network_usage(path, limit=0)
    assert plain["entries"] == [] and plain["scanned_records"] == 0
    grouped = srum.parse_srum_network_usage(path, limit=0, aggregate_by="user")
    assert grouped["entries"] == [] and grouped["aggregates"][0]["record_count"] == 1


def test_empty_filtered_aggregate(database):
    path, _, _ = database()
    result = srum.parse_srum_network_usage(
        path, time_range_start="2025-01-01", aggregate_by="application",
    )
    assert result["entries"] == [] and result["aggregates"] == []
    assert result["aggregation"]["record_count"] == 0


def test_mcp_schema_and_dispatch(database, monkeypatch):
    path, _, _ = database(network_rows=[network_record(), network_record(app=2)])
    monkeypatch.setattr(server, "PYESEDB_AVAILABLE", True)
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    properties = tools["disk_parse_srum"].inputSchema["properties"]
    assert properties["app_match_mode"]["default"] == "substring"
    assert properties["aggregate_by"]["default"] == "none"
    assert properties["table"]["default"] == "app_resource_usage"
    response = asyncio.run(server._execute_tool("disk_parse_srum", {
        "srum_path": str(path), "table": "all", "app_filter": "update.exe",
        "app_match_mode": "exact_basename", "aggregate_by": "application_user",
        "time_range_start": "2024-01-02T13:00:00+01:00", "limit": 2,
    }))
    result = json.loads(response)
    assert result["tables"]["network_data_usage"]["aggregates"][0]["record_count"] == 1
