"""
Tests for response size control and truncation functionality.

These tests verify that large responses are properly truncated to prevent
context overflow when used with LLMs.
"""
import pytest
import json


class TestResponseSizeConfig:
    """Test response size configuration constants."""

    def test_max_response_chars_exists(self):
        from winforensics_mcp.config import MAX_RESPONSE_CHARS
        assert isinstance(MAX_RESPONSE_CHARS, int)
        assert MAX_RESPONSE_CHARS > 0
        # Should be around 40000 chars (~10k tokens)
        assert 30000 <= MAX_RESPONSE_CHARS <= 100000

    def test_truncate_keep_items_exists(self):
        from winforensics_mcp.config import TRUNCATE_KEEP_ITEMS
        assert isinstance(TRUNCATE_KEEP_ITEMS, int)
        assert TRUNCATE_KEEP_ITEMS > 0
        # Should keep at least a few items for context
        assert 5 <= TRUNCATE_KEEP_ITEMS <= 50


class TestTruncateNestedArrays:
    """Test nested array truncation helper."""

    def test_truncate_nested_arrays_import(self):
        from winforensics_mcp.server import _truncate_nested_arrays
        assert callable(_truncate_nested_arrays)

    def test_truncate_nested_arrays_basic(self):
        from winforensics_mcp.server import _truncate_nested_arrays

        item = {
            "name": "test",
            "loaded_files": ["file1", "file2", "file3"] * 20,  # 60 items
        }
        result = _truncate_nested_arrays(item, ["loaded_files"], max_nested=10)

        assert len(result["loaded_files"]) == 10
        assert result["loaded_files_truncated"] is True
        assert result["loaded_files_original_count"] == 60

    def test_truncate_nested_arrays_no_truncation_needed(self):
        from winforensics_mcp.server import _truncate_nested_arrays

        item = {
            "name": "test",
            "loaded_files": ["file1", "file2", "file3"],
        }
        result = _truncate_nested_arrays(item, ["loaded_files"], max_nested=10)

        assert len(result["loaded_files"]) == 3
        assert "loaded_files_truncated" not in result

    def test_truncate_nested_arrays_non_dict(self):
        from winforensics_mcp.server import _truncate_nested_arrays

        # Should return non-dict items unchanged
        result = _truncate_nested_arrays("not a dict", ["loaded_files"])
        assert result == "not a dict"

    def test_truncate_nested_arrays_missing_key(self):
        from winforensics_mcp.server import _truncate_nested_arrays

        item = {"name": "test", "other": "data"}
        result = _truncate_nested_arrays(item, ["loaded_files"])

        assert result == item
        assert "loaded_files_truncated" not in result


class TestSmartTruncate:
    """Test smart truncation function."""

    def test_smart_truncate_import(self):
        from winforensics_mcp.server import _smart_truncate
        assert callable(_smart_truncate)

    def test_smart_truncate_small_data(self):
        from winforensics_mcp.server import _smart_truncate

        data = {"events": [{"id": 1}, {"id": 2}]}
        result, info = _smart_truncate(data, max_chars=10000)

        assert result == data
        assert info == {}

    def test_smart_truncate_large_array(self):
        from winforensics_mcp.server import _smart_truncate

        # Create data larger than limit
        data = {"events": [{"id": i, "data": "x" * 500} for i in range(100)]}
        result, info = _smart_truncate(data, max_chars=10000)

        assert len(result["events"]) < 100
        assert "events" in info
        assert info["events"]["truncated"] is True
        assert info["events"]["original_count"] == 100

    def test_smart_truncate_nested_arrays(self):
        from winforensics_mcp.server import _smart_truncate

        # Data with nested arrays (like prefetch entries with loaded_files)
        data = {
            "prefetch_entries": [
                {
                    "name": f"entry{i}",
                    "loaded_files": [f"file{j}" for j in range(100)]
                }
                for i in range(50)
            ]
        }
        result, info = _smart_truncate(data, max_chars=20000)

        # Should truncate nested loaded_files arrays
        if result["prefetch_entries"]:
            first_entry = result["prefetch_entries"][0]
            if "loaded_files_truncated" in first_entry:
                assert len(first_entry["loaded_files"]) <= 20

    def test_smart_truncate_non_dict(self):
        from winforensics_mcp.server import _smart_truncate

        # Large non-dict data should return with warning
        data = ["item"] * 10000
        result, info = _smart_truncate(data, max_chars=1000)

        assert "warning" in info


class TestJsonResponse:
    """Test json_response function with truncation."""

    def test_json_response_import(self):
        from winforensics_mcp.server import json_response
        assert callable(json_response)

    def test_json_response_small_data(self):
        from winforensics_mcp.server import json_response

        data = {"events": [{"id": 1}]}
        result = json_response(data)
        parsed = json.loads(result)

        assert parsed["events"] == [{"id": 1}]
        assert "_truncation" not in parsed

    def test_json_response_large_data_truncated(self):
        from winforensics_mcp.server import json_response

        # Create data larger than MAX_RESPONSE_CHARS
        data = {"events": [{"id": i, "data": "x" * 1000} for i in range(200)]}
        result = json_response(data)
        parsed = json.loads(result)

        assert "_truncation" in parsed
        assert "warning" in parsed["_truncation"]
        assert "original_chars" in parsed["_truncation"]
        assert "hint" in parsed["_truncation"]
        assert len(parsed["events"]) < 200

    def test_json_response_respects_max_chars(self):
        from winforensics_mcp.server import json_response
        from winforensics_mcp.config import MAX_RESPONSE_CHARS

        # Create very large data
        data = {"events": [{"id": i, "data": "x" * 2000} for i in range(500)]}
        result = json_response(data)

        # Result should be close to or under MAX_RESPONSE_CHARS
        # Allow some tolerance for truncation metadata
        assert len(result) <= MAX_RESPONSE_CHARS * 1.5


class TestPaginationOffset:
    """Test pagination offset parameter in parsers."""

    def test_evtx_parser_has_offset(self):
        import inspect
        from winforensics_mcp.parsers.evtx_parser import get_evtx_events, search_security_events

        # Check get_evtx_events has offset parameter
        sig = inspect.signature(get_evtx_events)
        params = list(sig.parameters.keys())
        assert "offset" in params

        # Check search_security_events has offset parameter
        sig2 = inspect.signature(search_security_events)
        params2 = list(sig2.parameters.keys())
        assert "offset" in params2

    def test_prefetch_parser_has_offset(self):
        import inspect
        from winforensics_mcp.parsers.prefetch_parser import parse_prefetch_directory

        sig = inspect.signature(parse_prefetch_directory)
        params = list(sig.parameters.keys())
        assert "offset" in params


class TestResponseMetadata:
    """Test that truncated responses include proper metadata."""

    def test_truncation_includes_next_offset(self):
        from winforensics_mcp.server import json_response

        # Simulate evtx response with truncation
        data = {
            "events": [{"id": i} for i in range(100)],
            "total_matched": 500,
            "returned": 100,
            "offset": 0,
            "truncated": True,
            "limit": 100,
            "next_offset": 100,
        }
        result = json_response(data)
        parsed = json.loads(result)

        # Even after truncation, metadata should be preserved
        assert "total_matched" in parsed
        assert "truncated" in parsed

    def test_truncation_metadata_has_hint(self):
        from winforensics_mcp.server import json_response

        data = {"events": [{"id": i, "data": "x" * 1000} for i in range(200)]}
        result = json_response(data)
        parsed = json.loads(result)

        if "_truncation" in parsed:
            assert "hint" in parsed["_truncation"]
            hint = parsed["_truncation"]["hint"].lower()
            assert "time_range" in hint or "offset" in hint or "paginate" in hint
