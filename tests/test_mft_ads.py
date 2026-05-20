from datetime import datetime, timezone
from pathlib import Path

from winforensics_mcp.parsers.mft_parser import _entry_matches_filter, _parse_mft_entry


class FakeFlags:
    def __str__(self):
        return "EntryFlags(ALLOCATED)"


class FakeStandardInformation:
    created = datetime(2023, 5, 5, 10, 19, 46, tzinfo=timezone.utc)
    modified = datetime(2023, 5, 5, 10, 20, 48, tzinfo=timezone.utc)
    accessed = datetime(2023, 5, 5, 10, 22, 37, tzinfo=timezone.utc)
    mft_modified = datetime(2023, 5, 5, 10, 22, 23, tzinfo=timezone.utc)


class FakeFileName(FakeStandardInformation):
    name = "OBSSTR~1.ZIP"


class FakeDataContent:
    def __init__(self, data: bytes):
        self.data = data


class FakeAttribute:
    def __init__(self, type_code, content=None, name="", data_size=0, is_resident=True):
        self.type_code = type_code
        self.attribute_content = content
        self.name = name
        self.data_size = data_size
        self.is_resident = is_resident


class FakeEntry:
    entry_id = 129184
    sequence = 8
    full_path = "Users/Simon.stark/Documents/Streaming Software/Obs Streaming Software.zip"
    file_size = 166
    flags = FakeFlags()
    hard_link_count = 1

    def __init__(self, attrs):
        self._attrs = attrs

    def attributes(self):
        return self._attrs


def test_parse_mft_entry_surfaces_ads_stream_name_and_content():
    entry = FakeEntry([
        FakeAttribute(16, FakeStandardInformation()),
        FakeAttribute(48, FakeFileName()),
        FakeAttribute(
            128,
            FakeDataContent(
                b"\x00\x00[ZoneTransfer]\r\n"
                b"ZoneId=3\r\n"
                b"HostUrl=http://obsproicet.net/download.zip"
            ),
            name="Zone.Identifier",
            data_size=224,
        ),
    ])

    parsed = _parse_mft_entry(entry)

    assert parsed["has_ads"] is True
    assert parsed["is_ads_entry"] is True
    assert parsed["size_semantics"] == "ads_stream"
    assert parsed["host_file_size"] is None
    assert parsed["stream_name"] == "Zone.Identifier"
    assert parsed["stream_path"].endswith("Obs Streaming Software.zip:Zone.Identifier")
    assert parsed["data_streams"][0]["size"] == 70
    assert parsed["data_streams"][0]["content_encoding"] == "utf-8"
    assert "HostUrl=http://obsproicet.net/download.zip" in parsed["data_streams"][0]["content_preview"]


def test_parse_mft_entry_distinguishes_host_size_from_ads_size():
    entry = FakeEntry([
        FakeAttribute(16, FakeStandardInformation()),
        FakeAttribute(48, FakeFileName()),
        FakeAttribute(128, None, name="", data_size=80, is_resident=False),
        FakeAttribute(
            128,
            FakeDataContent(b"[ZoneTransfer]\r\nZoneId=3"),
            name="Zone.Identifier",
            data_size=112,
        ),
    ])
    entry.file_size = 3_644_961

    parsed = _parse_mft_entry(entry)

    assert parsed["has_ads"] is True
    assert parsed["is_ads_entry"] is False
    assert parsed["size_semantics"] == "unnamed_data"
    assert parsed["host_file_size"] == 3_644_961
    assert parsed["ads_count"] == 1
    assert parsed["data_streams"][0]["name"] == ""
    assert parsed["data_streams"][1]["name"] == "Zone.Identifier"
    assert parsed["data_streams"][1]["size"] == 24


def test_mft_filter_matches_ads_name_and_resident_content():
    entry = FakeEntry([
        FakeAttribute(
            128,
            FakeDataContent(b"[ZoneTransfer]\r\nHostUrl=http://obsproicet.net/file.zip"),
            name="Zone.Identifier",
        ),
    ])

    parsed = _parse_mft_entry(entry)

    assert _entry_matches_filter(parsed, "zone.identifier")
    assert _entry_matches_filter(parsed, "obsproicet.net")
    assert _entry_matches_filter(parsed, "streaming software.zip:zone.identifier")


def test_hunt_ioc_mft_mapping_includes_ads_metadata(monkeypatch):
    from winforensics_mcp.orchestrators import ioc_hunter

    def fake_parse_mft(*args, **kwargs):
        return {
            "entries": [{
                "path": "ProjectArk/diagram.png",
                "file_size": 286_347,
                "host_file_size": 286_347,
                "size_semantics": "unnamed_data",
                "has_ads": True,
                "ads_count": 1,
                "data_streams": [{
                    "name": "Zone.Identifier",
                    "is_ads": True,
                    "is_resident": True,
                    "size": 319,
                    "content_preview": "[ZoneTransfer]\r\nZoneId=3",
                }],
                "timestamps": {
                    "si": {
                        "created": "2025-06-07T15:09:40+00:00",
                        "modified": "2025-06-07T15:09:42+00:00",
                    },
                },
                "timestomping": {"detected": False},
            }],
        }

    monkeypatch.setattr(ioc_hunter, "MFT_AVAILABLE", True)
    monkeypatch.setattr(ioc_hunter, "parse_mft", fake_parse_mft)

    result = ioc_hunter._search_mft_ioc(Path("/tmp/$MFT"), "Zone.Identifier", "filename")

    match = result["matches"][0]
    assert match["filename"] == "diagram.png"
    assert match["size"] == 286_347
    assert match["created"] == "2025-06-07T15:09:40+00:00"
    assert match["has_ads"] is True
    assert match["ads_streams"][0]["name"] == "Zone.Identifier"


def test_timeline_mft_keyword_filter_reaches_ads_metadata(monkeypatch):
    from winforensics_mcp.orchestrators import timeline_builder
    from winforensics_mcp.parsers import mft_parser

    def fake_iter_mft_entries(mft_path, file_path_filter=None, **kwargs):
        assert file_path_filter == "Zone.Identifier"
        yield {
            "entry_id": 42,
            "path": "download.zip",
            "file_size": 21,
            "host_file_size": 21,
            "size_semantics": "unnamed_data",
            "has_ads": True,
            "ads_count": 1,
            "data_streams": [{
                "name": "Zone.Identifier",
                "is_ads": True,
                "size": 65,
            }],
            "timestamps": {
                "si": {
                    "created": "2026-05-20T18:59:11+00:00",
                    "modified": "2026-05-20T18:59:12+00:00",
                },
            },
            "timestomping": {"detected": False},
        }

    monkeypatch.setattr(mft_parser, "MFT_AVAILABLE", True)
    monkeypatch.setattr(mft_parser, "iter_mft_entries", fake_iter_mft_entries)

    events = list(
        timeline_builder._iter_mft_events(
            Path("/tmp/$MFT"),
            time_range_start=None,
            time_range_end=None,
            keyword_filter="Zone.Identifier",
            limit=5,
        )
    )

    assert len(events) == 2
    assert events[0]["details"]["has_ads"] is True
    assert events[0]["details"]["ads_streams"][0]["name"] == "Zone.Identifier"
