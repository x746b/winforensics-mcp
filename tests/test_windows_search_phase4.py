"""Sanitized Windows Search adapter tests; no case evidence is committed."""

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from winforensics_mcp.parsers import windows_search_parser as parser


@pytest.fixture
def evidence(tmp_path):
    source = tmp_path / "renamed evidence.edb"
    source.write_bytes(b"sanitized evidence")
    return source


@pytest.fixture
def sidecar(tmp_path, monkeypatch):
    binary = tmp_path / "sidr"
    binary.write_bytes(b"sanitized binary")
    binary.chmod(0o755)
    state = {
        "rows": {
            "file": [
                {
                    "WorkId": 1,
                    "System_ItemPathDisplay": r"C:\docs\alpha.txt",
                    "System_Search_AutoSummary": "Secret report",
                    "System_DateModified": "2024-01-01T12:00:00",
                },
                {
                    "WorkId": 2,
                    "System_ItemPathDisplay": r"C:\docs\beta.txt",
                    "System_Search_AutoSummary": "Another secret",
                    "System_DateModified": "2024-01-02T12:00:00Z",
                },
            ],
            "internet_history": [
                {
                    "WorkId": 3,
                    "System_ItemUrl": "https://example.invalid",
                    "System_Link_DateVisited": "2024-01-03T00:00:00",
                }
            ],
            "activity_history": [],
        },
        "log": b"Found 1 Windows Search database(s)\n",
        "dirty": False,
        "exit": 0,
        "missing": set(),
        "version": b"sidr 0.9.2",
        "mutate": False,
    }

    def run(argv, **kwargs):
        assert isinstance(argv, list)
        assert "shell" not in kwargs
        if argv[-1] == "--version":
            kwargs["stdout"].write(state["version"])
            return SimpleNamespace(returncode=0)
        if state.get("timeout"):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        copied = Path(argv[-1]) / "Windows.edb"
        assert copied.read_bytes() == b"sanitized evidence"
        if state["mutate"]:
            copied.write_bytes(b"mutated copy")
        output = Path(argv[argv.index("-o") + 1])
        for kind, suffix in parser.REPORTS.items():
            if kind in state["missing"]:
                continue
            path = output / f"HOST_{suffix}_20240101{'_dirty' if state['dirty'] else ''}.json"
            path.write_text("".join(json.dumps(row) + "\n" for row in state["rows"][kind]))
            if state.get("malformed"):
                with path.open("a") as stream:
                    stream.write("invalid json\n")
        kwargs["stdout"].write(state["log"])
        return SimpleNamespace(returncode=state["exit"])

    monkeypatch.setattr(parser.subprocess, "run", run)
    monkeypatch.setattr(parser, "_resolve_sidr", lambda path: (binary, [str(binary)]))
    return state


def test_filter_paging_projection_and_hashes(evidence, sidecar):
    result = parser.parse_windows_search(
        str(evidence), content_filter="SECRET", offset=1, limit=1, fields=["WorkId"]
    )
    assert result["records"] == [{"WorkId": 2}]
    assert result["matched_records"] == 2
    assert result["total_records"] == 3
    assert result["report_counts"]["file"] == {"total": 2, "matched": 2}
    assert result["complete"]
    assert result["evidence_unchanged"]
    assert result["backend_metadata"]["version"] == "sidr 0.9.2"
    assert len(result["backend_metadata"]["sha256"]) == 64


@pytest.mark.parametrize(
    "filters,ids",
    [
        ({"path_filter": "DOCS", "filename_filter": "ALPHA"}, [1]),
        ({"query": "another"}, [2]),
        ({"work_id": 2}, [2]),
        ({"report_type": "internet_history"}, [3]),
        ({"time_start": "2024-01-01T13:00:00+01:00", "time_end": "2024-01-01T12:00:00Z"}, [1]),
        ({"time_start": "2025-01-01"}, []),
    ],
)
def test_filters(evidence, sidecar, filters, ids):
    result = parser.parse_windows_search(str(evidence), **filters)
    assert [r["WorkId"] for r in result["records"]] == ids


def test_pagination(evidence, sidecar):
    result = parser.parse_windows_search(str(evidence), limit=1)
    assert result["matched_records"] == 3
    assert result["next_offset"] == 1
    assert result["has_more"]


def test_dirty_preserves_rows(evidence, sidecar):
    sidecar["dirty"] = True
    sidecar["log"] = b"WARNING: The database state is not clean.\n"
    result = parser.parse_windows_search(str(evidence))
    assert not result["complete"]
    assert result["database_state"] == "dirty"
    assert result["returned_records"] == 3
    assert not result["content_filter_complete"]


@pytest.mark.parametrize("failure", ["missing", "error_log", "nonzero", "malformed"])
def test_sidecar_failure_is_not_success(evidence, sidecar, failure):
    if failure == "missing":
        sidecar["missing"] = set(parser.REPORTS)
    elif failure == "error_log":
        sidecar["log"] = b"ese_generate_report failed with error: broken\n"
    elif failure == "nonzero":
        sidecar["exit"] = 1
    else:
        sidecar["malformed"] = True
    result = parser.parse_windows_search(str(evidence))
    assert not result["complete"]
    assert result["diagnostic_count"]
    assert result["evidence_unchanged"]


def test_timeout_and_cleanup(evidence, sidecar):
    sidecar["timeout"] = True
    result = parser.parse_windows_search(str(evidence))
    assert "timed out" in result["error"]
    assert result["evidence_unchanged"]


def test_copy_isolation(evidence, sidecar):
    sidecar["mutate"] = True
    result = parser.parse_windows_search(str(evidence))
    assert evidence.read_bytes() == b"sanitized evidence"
    assert result["evidence_unchanged"]


def test_version_mismatch(evidence, sidecar):
    sidecar["version"] = b"sidr 0.8.0"
    result = parser.parse_windows_search(str(evidence))
    assert "0.9.2 is required" in result["error"]


def test_bounded_output_preserves_next_offset(evidence, sidecar):
    sidecar["rows"]["file"] = [
        {"WorkId": i, "System_Search_AutoSummary": "x" * 10000} for i in range(40)
    ]
    result = parser.parse_windows_search(str(evidence), report_type="file", limit=40)
    assert 0 < result["returned_records"] < 40
    assert result["matched_records"] == 40
    assert result["next_offset"] == result["returned_records"]
    assert result["values_truncated"] > 0
    assert len(json.dumps(result["records"])) < 25000


def test_diagnostics_bounded(evidence, sidecar):
    sidecar["log"] = b"Error: malformed field\n" * 50
    result = parser.parse_windows_search(str(evidence))
    assert result["diagnostic_count"] == 50
    assert len(result["diagnostics"]) == parser.MAX_DIAGNOSTICS


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"offset": -1},
        {"timeout": 0},
        {"report_type": "bad"},
        {"fields": "WorkId"},
        {"work_id": True},
        {"query": 1},
        {"time_start": "bad"},
        {"time_start": "2025-01-01", "time_end": "2024-01-01"},
    ],
)
def test_invalid_options(evidence, kwargs):
    result = parser.parse_windows_search(str(evidence), **kwargs)
    assert result["error"]
    assert not result["complete"]


def test_discovery_precedence(tmp_path, monkeypatch):
    explicit, env, local, path = [
        tmp_path / name for name in ("explicit", "env", ".tools/sidr", "path")
    ]
    local.parent.mkdir()
    for binary in (explicit, env, local, path):
        binary.write_text("binary")
        binary.chmod(0o755)
    monkeypatch.setattr(parser, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("WINFORENSICS_SIDR_PATH", str(env))
    monkeypatch.setattr(parser.shutil, "which", lambda name: str(path))
    assert parser._resolve_sidr(str(explicit))[0] == explicit
    assert parser._resolve_sidr(None)[0] == env
    env.unlink()
    assert parser._resolve_sidr(None)[0] == local
    local.unlink()
    assert parser._resolve_sidr(None)[0] == path
    assert parser._resolve_sidr(str(tmp_path / "absent"))[0] is None


def test_bundled_sidecar_selection_is_architecture_aware(tmp_path, monkeypatch):
    tools = tmp_path / ".tools"
    tools.mkdir()
    arm = tools / "sidr"
    x86 = tools / "sidr_x86"
    for binary in (arm, x86):
        binary.write_text("binary")
        binary.chmod(0o755)
    monkeypatch.setattr(parser, "REPO_ROOT", tmp_path)
    monkeypatch.delenv("WINFORENSICS_SIDR_PATH", raising=False)
    monkeypatch.setattr(parser.shutil, "which", lambda name: None)
    monkeypatch.setattr(parser.platform, "machine", lambda: "aarch64")
    assert parser._resolve_sidr(None)[0] == arm
    monkeypatch.setattr(parser.platform, "machine", lambda: "x86_64")
    assert parser._resolve_sidr(None)[0] == x86


def test_no_backend_actionable(evidence, monkeypatch):
    monkeypatch.setattr(parser, "_resolve_sidr", lambda path: (None, ["/missing/sidr"]))
    monkeypatch.setattr(parser, "pyesedb", None)
    result = parser.parse_windows_search(str(evidence))
    assert "scripts/build_sidr.sh" in result["error"]
    assert "/missing/sidr" in result["error"]


def test_explicit_missing_sidr_does_not_fallback(evidence, monkeypatch):
    monkeypatch.setattr(parser, "_resolve_sidr", lambda path: (None, [path]))
    result = parser.parse_windows_search(str(evidence), sidr_path="/missing/sidr")
    assert result["backend"] is None
    assert "error" in result


def test_fallback_incomplete_content(evidence, monkeypatch):
    monkeypatch.setattr(parser, "_resolve_sidr", lambda path: (None, []))
    library = MagicMock()
    table = library.file.return_value.get_table.return_value
    library.file.return_value.get_number_of_tables.return_value = 1
    table.get_name.return_value = "SystemIndex_0A_PropertyStore"
    table.get_number_of_columns.return_value = 3
    columns = [
        ("DocID", 4),
        ("42-System_ItemPathDisplay", 10),
        ("43-System_Search_AutoSummary", 12),
    ]
    table.get_column.side_effect = lambda i: SimpleNamespace(
        get_name=lambda: columns[i][0], get_type=lambda: columns[i][1]
    )
    table.get_number_of_records.return_value = 1
    record = table.get_record.return_value
    record.is_long_value.side_effect = lambda i: i == 2
    record.is_multi_value.return_value = False
    record.get_value_data_as_integer.return_value = 7
    record.get_value_data_as_string.return_value = r"C:\docs\note.txt"
    monkeypatch.setattr(parser, "pyesedb", library)
    result = parser.parse_windows_search(str(evidence), content_filter="secret")
    assert not result["complete"]
    assert not result["content_filter_complete"]
    assert result["unsupported_long_values"] == 1
    assert result["matched_records"] == 0
    assert "not conclusive" in result["diagnostics"][0]
    result = parser.parse_windows_search(str(evidence), work_id=7)
    assert result["records"][0]["WorkId"] == 7
    assert library.file.return_value.close.called


def test_tool_registration_and_dispatch(evidence, sidecar):
    from winforensics_mcp import server

    tools = asyncio.run(server.list_tools())
    tool = next(tool for tool in tools if tool.name == "windows_search_parse")
    assert tool.inputSchema["required"] == ["edb_path"]
    response = asyncio.run(
        server.call_tool("windows_search_parse", {"edb_path": str(evidence), "limit": 1})
    )
    result = json.loads(response[0].text)
    assert result["returned_records"] == 1
    assert result["next_offset"] == 1
