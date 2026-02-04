"""Tests for PCAP parser module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winforensics_mcp.parsers.pcap_parser import SCAPY_AVAILABLE


class TestScapyAvailability:
    """Test scapy availability flag."""

    def test_scapy_available_flag_exists(self):
        """Test SCAPY_AVAILABLE flag is defined."""
        assert isinstance(SCAPY_AVAILABLE, bool)

    def test_scapy_available_is_true(self):
        """Test scapy is actually available in test environment."""
        assert SCAPY_AVAILABLE is True


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapImports:
    """Test that PCAP parser functions can be imported."""

    def test_pcap_parser_imports(self):
        """Test all PCAP parser functions are importable."""
        from winforensics_mcp.parsers import (
            get_pcap_stats,
            pcap_get_conversations,
            pcap_get_dns_queries,
            pcap_get_http_requests,
            search_pcap,
            pcap_find_suspicious,
            SCAPY_AVAILABLE,
        )
        assert callable(get_pcap_stats)
        assert callable(pcap_get_conversations)
        assert callable(pcap_get_dns_queries)
        assert callable(pcap_get_http_requests)
        assert callable(search_pcap)
        assert callable(pcap_find_suspicious)

    def test_pcap_parser_direct_imports(self):
        """Test direct imports from pcap_parser module."""
        from winforensics_mcp.parsers.pcap_parser import (
            get_pcap_stats,
            get_conversations,
            get_dns_queries,
            get_http_requests,
            search_pcap,
            find_suspicious_connections,
            iter_packets,
        )
        assert callable(get_pcap_stats)
        assert callable(get_conversations)
        assert callable(get_dns_queries)
        assert callable(get_http_requests)
        assert callable(search_pcap)
        assert callable(find_suspicious_connections)
        assert callable(iter_packets)


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapFileNotFound:
    """Test error handling for missing files."""

    def test_get_stats_file_not_found(self):
        """Test get_pcap_stats with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import get_pcap_stats

        with pytest.raises(FileNotFoundError):
            get_pcap_stats("/nonexistent/file.pcap")

    def test_get_conversations_file_not_found(self):
        """Test get_conversations with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import get_conversations

        with pytest.raises(FileNotFoundError):
            get_conversations("/nonexistent/file.pcap")

    def test_get_dns_queries_file_not_found(self):
        """Test get_dns_queries with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import get_dns_queries

        with pytest.raises(FileNotFoundError):
            get_dns_queries("/nonexistent/file.pcap")

    def test_get_http_requests_file_not_found(self):
        """Test get_http_requests with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import get_http_requests

        with pytest.raises(FileNotFoundError):
            get_http_requests("/nonexistent/file.pcap")

    def test_search_pcap_file_not_found(self):
        """Test search_pcap with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import search_pcap

        with pytest.raises(FileNotFoundError):
            search_pcap("/nonexistent/file.pcap", "test")

    def test_find_suspicious_file_not_found(self):
        """Test find_suspicious_connections with non-existent file."""
        from winforensics_mcp.parsers.pcap_parser import find_suspicious_connections

        with pytest.raises(FileNotFoundError):
            find_suspicious_connections("/nonexistent/file.pcap")


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapHelpers:
    """Test helper functions."""

    def test_format_timestamp(self):
        """Test timestamp formatting."""
        from winforensics_mcp.parsers.pcap_parser import _format_timestamp

        # Test with known timestamp (2024-01-15 12:00:00 UTC)
        ts = 1705320000.0
        result = _format_timestamp(ts)
        assert result.endswith("Z")
        assert "2024-01-15" in result

    def test_normalize_hash_preserved_from_other_tests(self):
        """Ensure pcap module doesn't break other imports."""
        # This just ensures the parsers package still works after adding pcap
        from winforensics_mcp.parsers import YARA_AVAILABLE, VT_AVAILABLE
        assert isinstance(YARA_AVAILABLE, bool)
        assert isinstance(VT_AVAILABLE, bool)


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapWithMockedPackets:
    """Tests using mocked packet data."""

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_get_stats_empty_pcap(self, mock_iter):
        """Test get_pcap_stats with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import get_pcap_stats

        mock_iter.return_value = iter([])

        # Create a temporary empty file
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_pcap_stats(temp_path)
            assert result["packet_count"] == 0
            assert result["protocols"] == {}
            assert result["top_talkers"] == []
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_get_conversations_empty(self, mock_iter):
        """Test get_conversations with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import get_conversations

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_conversations(temp_path)
            assert result["total_conversations"] == 0
            assert result["conversations"] == []
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_get_dns_empty(self, mock_iter):
        """Test get_dns_queries with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import get_dns_queries

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_dns_queries(temp_path)
            assert result["total_queries"] == 0
            assert result["queries"] == []
            assert result["unique_domains"] == 0
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_get_http_empty(self, mock_iter):
        """Test get_http_requests with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import get_http_requests

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_http_requests(temp_path)
            assert result["total_requests"] == 0
            assert result["requests"] == []
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_search_pcap_empty(self, mock_iter):
        """Test search_pcap with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import search_pcap

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = search_pcap(temp_path, "test")
            assert result["total_matches"] == 0
            assert result["matches"] == []
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_find_suspicious_empty(self, mock_iter):
        """Test find_suspicious_connections with empty packet list."""
        from winforensics_mcp.parsers.pcap_parser import find_suspicious_connections

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = find_suspicious_connections(temp_path)
            assert result["total_findings"] == 0
            assert "findings" in result
        finally:
            os.unlink(temp_path)


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapResultStructure:
    """Test result structure validation."""

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_stats_result_structure(self, mock_iter):
        """Test get_pcap_stats returns expected structure."""
        from winforensics_mcp.parsers.pcap_parser import get_pcap_stats

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_pcap_stats(temp_path)
            expected_keys = {
                "file", "file_size_bytes", "packet_count", "packets_analyzed",
                "truncated", "total_bytes", "time_range", "protocols",
                "top_talkers", "top_ports", "dns_query_count", "http_request_count"
            }
            assert set(result.keys()) == expected_keys
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_conversations_result_structure(self, mock_iter):
        """Test get_conversations returns expected structure."""
        from winforensics_mcp.parsers.pcap_parser import get_conversations

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_conversations(temp_path)
            expected_keys = {"total_conversations", "returned", "protocol_filter", "conversations"}
            assert set(result.keys()) == expected_keys
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_dns_result_structure(self, mock_iter):
        """Test get_dns_queries returns expected structure."""
        from winforensics_mcp.parsers.pcap_parser import get_dns_queries

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_dns_queries(temp_path)
            expected_keys = {
                "total_queries", "returned", "filter", "queries",
                "top_queried_domains", "unique_domains"
            }
            assert set(result.keys()) == expected_keys
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_suspicious_result_structure(self, mock_iter):
        """Test find_suspicious_connections returns expected structure."""
        from winforensics_mcp.parsers.pcap_parser import find_suspicious_connections

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = find_suspicious_connections(temp_path)
            assert "total_findings" in result
            assert "findings" in result
            findings = result["findings"]
            expected_categories = {
                "suspicious_ports", "potential_beaconing",
                "dns_tunneling_indicators", "suspicious_user_agents",
                "large_outbound_transfers"
            }
            assert set(findings.keys()) == expected_categories
        finally:
            os.unlink(temp_path)


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapFilters:
    """Test filter parameters."""

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_conversations_protocol_filter(self, mock_iter):
        """Test get_conversations protocol filter."""
        from winforensics_mcp.parsers.pcap_parser import get_conversations

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = get_conversations(temp_path, protocol="tcp")
            assert result["protocol_filter"] == "tcp"

            result = get_conversations(temp_path, protocol="udp")
            assert result["protocol_filter"] == "udp"
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.pcap_parser.iter_packets")
    def test_search_pcap_regex_flag(self, mock_iter):
        """Test search_pcap regex flag."""
        from winforensics_mcp.parsers.pcap_parser import search_pcap

        mock_iter.return_value = iter([])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name

        try:
            result = search_pcap(temp_path, "test.*pattern", regex=True)
            assert result["regex"] is True
            assert result["pattern"] == "test.*pattern"

            result = search_pcap(temp_path, "simple", regex=False)
            assert result["regex"] is False
        finally:
            os.unlink(temp_path)
